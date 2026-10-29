use super::*;

fn queue_operation_publication_probe(probe: OperationPublicationProbe) {
    OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .push_back(probe);
    super::super::super::intercept::wake_operation_publication_worker();
}

pub(in crate::hook) fn next_operation_publication_probe_deadline() -> Option<Instant> {
    OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .iter()
        .map(|probe| probe.not_before)
        .min()
}

pub(super) fn register_operation_publication(target: LocalBinderTarget) -> anyhow::Result<u64> {
    let mut publications =
        OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned");
    if publications.len() >= MAX_PENDING_OPERATION_PUBLICATIONS {
        anyhow::bail!(
            "pending native operation publication limit reached ({MAX_PENDING_OPERATION_PUBLICATIONS})"
        );
    }
    let generation = NEXT_OPERATION_PUBLICATION_GENERATION.fetch_add(1, Ordering::Relaxed);
    publications.insert(
        target,
        OperationPublication {
            generation,
            acquire_pending: false,
            acquire_owned: false,
            connection: None,
            binder: None,
        },
    );
    Ok(generation)
}

fn finish_operation_publication(
    publications: &mut HashMap<LocalBinderTarget, OperationPublication>,
    retirement: NativeBinderRetirement,
) -> bool {
    let Some(publication) = publications.get(&retirement.target) else {
        return false;
    };
    if publication.generation != retirement.generation
        || !publication.acquire_owned
        || publication.binder.is_none()
    {
        return false;
    }
    publications.remove(&retirement.target);
    true
}

pub(in crate::hook) fn mark_operation_publication_acquire_pending(
    target: LocalBinderTarget,
    connection: BinderStateKey,
) -> Option<NativeBinderRetirement> {
    let mut publications =
        OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned");
    let publication = publications.get_mut(&target)?;
    if publication.connection != Some(connection)
        || publication.acquire_pending
        || publication.acquire_owned
    {
        return None;
    }
    publication.acquire_pending = true;
    Some(NativeBinderRetirement { target, generation: publication.generation })
}

pub(in crate::hook) fn mark_operation_publication_acquire_committed(
    retirement: NativeBinderRetirement,
) {
    let finished = {
        let mut publications =
            OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned");
        let Some(publication) = publications.get_mut(&retirement.target) else {
            return;
        };
        if publication.generation != retirement.generation || !publication.acquire_pending {
            return;
        }
        publication.acquire_pending = false;
        publication.acquire_owned = true;
        finish_operation_publication(&mut publications, retirement)
    };
    if finished {
        release_native_operation_initial_strong(retirement);
    }
}

pub(in crate::hook) fn cancel_operation_publication_acquire_pending(
    retirement: NativeBinderRetirement,
) {
    if let Some(publication) = OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .get_mut(&retirement.target)
        .filter(|publication| publication.generation == retirement.generation)
    {
        publication.acquire_pending = false;
    }
}

pub(in crate::hook) fn operation_publication_acquire_is_pending(
    probe: OperationPublicationProbe,
) -> bool {
    OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .get(&probe.target)
        .is_some_and(|publication| {
            publication.generation == probe.generation
                && publication.binder == Some(probe.binder)
                && publication.acquire_pending
        })
}

pub(in crate::hook) fn operation_publication_pending_acquire(
    target: LocalBinderTarget,
    connection: BinderStateKey,
) -> Option<NativeBinderRetirement> {
    let publications = OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned");
    let publication = publications.get(&target)?;
    (publication.connection == Some(connection) && publication.acquire_pending)
        .then_some(NativeBinderRetirement { target, generation: publication.generation })
}

pub(in crate::hook) fn mark_operation_publication_completed(
    retirement: NativeBinderRetirement,
    binder: BinderFdToken,
) {
    let (finished, probe) = {
        let mut publications =
            OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned");
        let Some(publication) = publications.get_mut(&retirement.target) else {
            return;
        };
        if publication.generation != retirement.generation
            || publication.connection.is_some_and(|connection| connection != binder.connection)
        {
            return;
        }
        publication.connection = Some(binder.connection);
        publication.binder = Some(binder);
        let finished = finish_operation_publication(&mut publications, retirement);
        let probe =
            publications.get(&retirement.target).map(|publication| OperationPublicationProbe {
                target: retirement.target,
                binder,
                generation: publication.generation,
                not_before: Instant::now() + OPERATION_PUBLICATION_PROBE_GRACE,
                query_failures: 0,
            });
        (finished, probe)
    };
    if finished {
        release_native_operation_initial_strong(retirement);
    }
    if let Some(probe) = probe {
        queue_operation_publication_probe(probe);
    }
}

pub(in crate::hook) fn bind_operation_publication_connection(
    retirement: NativeBinderRetirement,
    connection: BinderStateKey,
) {
    if let Some(publication) = OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .get_mut(&retirement.target)
        .filter(|publication| {
            publication.generation == retirement.generation
                && publication.connection.is_none_or(|bound| bound == connection)
        })
    {
        publication.connection = Some(connection);
    }
}

pub(in crate::hook) fn retire_binder_connection_publications(connection: BinderStateKey) {
    let (targets, retired_targets) = {
        let mut publications =
            OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned");
        let targets = publications
            .iter()
            .filter_map(|(target, publication)| {
                (publication.connection == Some(connection)).then_some(NativeBinderRetirement {
                    target: *target,
                    generation: publication.generation,
                })
            })
            .collect::<Vec<_>>();
        let retired_targets = targets
            .iter()
            .copied()
            .filter(|retirement| {
                publications
                    .get(&retirement.target)
                    .is_some_and(|publication| !publication.acquire_pending)
            })
            .collect::<Vec<_>>();
        publications.retain(|_, publication| {
            publication.connection != Some(connection) || publication.acquire_pending
        });
        (targets, retired_targets)
    };
    if targets.is_empty() {
        return;
    }
    OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .retain(|probe| {
            !targets.iter().any(|retirement| {
                probe.target == retirement.target && probe.generation == retirement.generation
            })
        });
    for retirement in retired_targets {
        drop_synthetic_operation_retirement(retirement);
    }
}

pub(in crate::hook) fn finish_local_operation_publication(retirement: NativeBinderRetirement) {
    let removed = {
        let mut publications =
            OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned");
        publications
            .get(&retirement.target)
            .is_some_and(|publication| publication.generation == retirement.generation)
            .then(|| publications.remove(&retirement.target))
            .flatten()
            .is_some()
    };
    if removed {
        release_native_operation_initial_strong(retirement);
    }
}

pub(in crate::hook) fn take_operation_publication_probe(
    now: Instant,
) -> Option<OperationPublicationProbe> {
    loop {
        let probe = {
            let mut probes = OPERATION_PUBLICATION_PROBES
                .lock()
                .expect("operation publication probe queue poisoned");
            let ready = probes.iter().position(|probe| probe.not_before <= now)?;
            probes.remove(ready)?
        };
        let eligible = {
            let publications =
                OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned");
            publications.get(&probe.target).is_some_and(|publication| {
                publication.generation == probe.generation
                    && publication.binder == Some(probe.binder)
                    && !publication.acquire_owned
            })
        };
        if eligible {
            return Some(probe);
        }
    }
}

pub(in crate::hook) fn finish_operation_publication_probe(
    mut probe: OperationPublicationProbe,
    node_exists: Result<bool, i32>,
    now: Instant,
) -> Option<NativeBinderRetirement> {
    {
        let mut publications =
            OPERATION_PUBLICATIONS.lock().expect("operation publication map poisoned");
        let publication = publications.get(&probe.target)?;
        if publication.generation != probe.generation
            || publication.binder != Some(probe.binder)
            || publication.acquire_owned
        {
            return None;
        }
        if !publication.acquire_pending && matches!(node_exists, Ok(false)) {
            publications.remove(&probe.target);
            return Some(NativeBinderRetirement {
                target: probe.target,
                generation: probe.generation,
            });
        }
    }
    let reached_max_backoff = if node_exists.is_err() {
        let previous_failures = probe.query_failures;
        probe.query_failures = probe
            .query_failures
            .saturating_add(1)
            .min(OPERATION_PUBLICATION_MAX_QUERY_BACKOFF_SHIFT);
        previous_failures < OPERATION_PUBLICATION_MAX_QUERY_BACKOFF_SHIFT
            && probe.query_failures == OPERATION_PUBLICATION_MAX_QUERY_BACKOFF_SHIFT
    } else {
        probe.query_failures = 0;
        false
    };
    if reached_max_backoff {
        warn!(
            "event=synthetic operation publication node query failed repeatedly; retaining the operation and native Binder until driver reference state is known ptr=0x{:x} cookie=0x{:x} fd={} failures={}",
            probe.target.ptr, probe.target.cookie, probe.binder.fd, probe.query_failures
        );
    }
    probe.not_before = now
        + OPERATION_PUBLICATION_REPROBE_DELAY
            .saturating_mul(1u32 << u32::from(probe.query_failures));
    queue_operation_publication_probe(probe);
    None
}
