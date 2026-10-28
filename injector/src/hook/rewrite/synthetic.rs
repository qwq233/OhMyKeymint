use super::*;

use publication::register_operation_publication;
pub(in crate::hook) use publication::{
    bind_operation_publication_connection, cancel_operation_publication_acquire_pending,
    finish_local_operation_publication, finish_operation_publication_probe,
    mark_operation_publication_acquire_committed, mark_operation_publication_acquire_pending,
    mark_operation_publication_completed, next_operation_publication_probe_deadline,
    operation_publication_acquire_is_pending, operation_publication_pending_acquire,
    retire_binder_connection_publications, take_operation_publication_probe,
};

mod publication;
#[cfg(test)]
pub(super) mod tests;

#[derive(Clone)]
pub(super) struct OperationTargetInfo {
    pub(super) route: RouteTarget,
    pub(super) aad_allowed: bool,
    pub(super) backend: Option<Arc<AospOperationBinder>>,
    pub(super) finalized: bool,
}

pub(in crate::hook) struct NativeOperationState {
    pub(super) backend: AospOperationBinder,
    pub(super) aad_allowed: bool,
    pub(super) caller: CallerInfo,
    pub(super) finalized: AtomicBool,
}

impl NativeOperationState {
    pub(super) fn is_finalized(&self) -> bool {
        self.finalized.load(Ordering::Acquire)
    }

    pub(super) fn retire(&self) {
        if self.finalized.swap(true, Ordering::AcqRel) {
            return;
        }
        let _guard = BypassGuard::enter();
        if let Err(status) = self.backend.r#abort() {
            debug!("event=synthetic retired OMK operation abort failed: {status}");
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OperationPublication {
    generation: u64,
    acquire_pending: bool,
    acquire_owned: bool,
    connection: Option<BinderStateKey>,
    binder: Option<BinderFdToken>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::hook) struct OperationPublicationProbe {
    pub(in crate::hook) target: LocalBinderTarget,
    pub(in crate::hook) binder: BinderFdToken,
    pub(in crate::hook) generation: u64,
    pub(in crate::hook) not_before: Instant,
    pub(in crate::hook) query_failures: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::hook) enum SyntheticTargetKind {
    SecurityLevel,
    Operation,
}

pub(in crate::hook) enum SyntheticReply {
    Parcel(Box<parcel::OwnedReply>),
    Status(i32),
    NoReply,
}

#[derive(Clone, Debug)]
pub(super) struct SyntheticTargetInfo {
    pub(super) kind: SyntheticTargetKind,
    #[cfg(test)]
    pub(super) caller: Option<CallerInfo>,
    pub(super) native_generation: Option<u64>,
    pub(super) operation: Option<Weak<NativeOperationState>>,
}

static OPERATION_TARGETS: LazyLock<Mutex<HashMap<LocalBinderTarget, OperationTargetInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static SYNTHETIC_SECURITY_LEVEL_TARGETS: LazyLock<
    Mutex<
        HashMap<
            crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
            LocalBinderTarget,
        >,
    >,
> = LazyLock::new(|| Mutex::new(HashMap::new()));
static SYNTHETIC_TARGETS: LazyLock<Mutex<HashMap<LocalBinderTarget, SyntheticTargetInfo>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NATIVE_BINDERS: LazyLock<Mutex<HashMap<LocalBinderTarget, Arc<NativeBinder>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static OPERATION_PUBLICATIONS: LazyLock<Mutex<HashMap<LocalBinderTarget, OperationPublication>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static OPERATION_PUBLICATION_PROBES: LazyLock<Mutex<VecDeque<OperationPublicationProbe>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

static NEXT_OPERATION_PUBLICATION_GENERATION: AtomicU64 = AtomicU64::new(1);

const OPERATION_PUBLICATION_PROBE_GRACE: Duration = Duration::from_millis(250);
const OPERATION_PUBLICATION_REPROBE_DELAY: Duration = Duration::from_secs(1);
const OPERATION_PUBLICATION_MAX_QUERY_BACKOFF_SHIFT: u8 = 5;
const MAX_PENDING_OPERATION_PUBLICATIONS: usize = 64;

pub(in crate::hook) fn lookup_synthetic_target(
    target: LocalBinderTarget,
) -> Option<SyntheticTargetKind> {
    SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned")
        .get(&target)
        .map(|info| info.kind)
}

pub(in crate::hook::rewrite) fn remember_operation_target(
    target: LocalBinderTarget,
    info: OperationTargetInfo,
) {
    let previous = OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .insert(target, info);
    if let Some(previous) = previous {
        if let Some(backend) = previous.backend {
            let _guard = BypassGuard::enter();
            if let Err(status) = backend.r#abort() {
                debug!(
                    "event=route previous OMK operation for carrier ptr=0x{:x} cookie=0x{:x} could not be aborted while replacing mapping: {}",
                    target.ptr, target.cookie, status
                );
            }
        }
    }
}

pub(in crate::hook::rewrite) fn lookup_operation_target(
    target: LocalBinderTarget,
) -> Option<OperationTargetInfo> {
    OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .get(&target)
        .cloned()
}

pub(in crate::hook::rewrite) fn forget_operation_target(target: LocalBinderTarget) {
    let retired = OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned")
        .remove(&target);
    drop(retired);
}

pub(crate) fn drop_synthetic_operation_retirement(retirement: NativeBinderRetirement) {
    let (info, state, native) = {
        let mut binders = NATIVE_BINDERS.lock().expect("native binder map poisoned");
        let mut operations = OPERATION_TARGETS
            .lock()
            .expect("operation target map poisoned");
        let mut synthetic = SYNTHETIC_TARGETS
            .lock()
            .expect("synthetic target map poisoned");
        let matches_generation = binders
            .get(&retirement.target)
            .is_some_and(|native| native.retirement_generation() == retirement.generation)
            || synthetic.get(&retirement.target).is_some_and(|info| {
                info.kind == SyntheticTargetKind::Operation
                    && info.native_generation == Some(retirement.generation)
            });
        if !matches_generation {
            return;
        }
        let info = operations.remove(&retirement.target);
        let state = synthetic
            .remove(&retirement.target)
            .and_then(|info| info.operation)
            .and_then(|state| state.upgrade());
        let native = binders.remove(&retirement.target);
        (info, state, native)
    };

    {
        let mut publications = OPERATION_PUBLICATIONS
            .lock()
            .expect("operation publication map poisoned");
        if publications
            .get(&retirement.target)
            .is_some_and(|publication| publication.generation == retirement.generation)
        {
            publications.remove(&retirement.target);
        }
    }
    OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .retain(|probe| {
            probe.target != retirement.target || probe.generation != retirement.generation
        });
    if let Some(native) = native.as_ref() {
        native.disarm_retirement();
    }
    if let Some(state) = state {
        state.retire();
    }
    abort_operation_target_info(retirement.target, info);
    drop(native);
}

fn release_native_operation_initial_strong(retirement: NativeBinderRetirement) {
    let native = {
        let mut binders = NATIVE_BINDERS.lock().expect("native binder map poisoned");
        binders
            .get(&retirement.target)
            .is_some_and(|native| native.retirement_generation() == retirement.generation)
            .then(|| binders.remove(&retirement.target))
            .flatten()
    };
    drop(native);
}

fn abort_operation_target_info(target: LocalBinderTarget, info: Option<OperationTargetInfo>) {
    let Some(info) = info else {
        debug!(
            "event=synthetic release for stale operation target ptr=0x{:x} cookie=0x{:x}",
            target.ptr, target.cookie
        );
        return;
    };
    if info.finalized {
        debug!(
            "event=synthetic release for finalized operation target ptr=0x{:x} cookie=0x{:x}",
            target.ptr, target.cookie
        );
        return;
    }
    let Some(backend) = info.backend else {
        return;
    };
    let _guard = BypassGuard::enter();
    if let Err(status) = backend.r#abort() {
        debug!(
            "event=synthetic drop abort for operation target ptr=0x{:x} cookie=0x{:x} failed: {}",
            target.ptr, target.cookie, status
        );
    }
}

pub(in crate::hook) fn retire_synthetic_operation_retirement(retirement: NativeBinderRetirement) {
    let (info, state) = {
        let mut operations = OPERATION_TARGETS
            .lock()
            .expect("operation target map poisoned");
        let mut synthetic = SYNTHETIC_TARGETS
            .lock()
            .expect("synthetic target map poisoned");
        let matches_generation = synthetic.get(&retirement.target).is_some_and(|info| {
            info.kind == SyntheticTargetKind::Operation
                && info.native_generation == Some(retirement.generation)
        });
        if !matches_generation {
            return;
        }
        let state = synthetic
            .remove(&retirement.target)
            .and_then(|info| info.operation)
            .and_then(|state| state.upgrade());
        (operations.remove(&retirement.target), state)
    };
    if OPERATION_PUBLICATIONS
        .lock()
        .expect("operation publication map poisoned")
        .get(&retirement.target)
        .is_some_and(|publication| publication.generation == retirement.generation)
    {
        let now = Instant::now();
        for probe in OPERATION_PUBLICATION_PROBES
            .lock()
            .expect("operation publication probe queue poisoned")
            .iter_mut()
            .filter(|probe| {
                probe.target == retirement.target && probe.generation == retirement.generation
            })
        {
            probe.not_before = now;
        }
        super::super::intercept::wake_operation_publication_worker();
    }
    if let Some(state) = state {
        state.retire();
    }
    abort_operation_target_info(retirement.target, info);
}

pub(crate) fn retire_native_operation_target(retirement: NativeBinderRetirement) {
    let info = {
        let mut operations = OPERATION_TARGETS
            .lock()
            .expect("operation target map poisoned");
        let mut synthetic = SYNTHETIC_TARGETS
            .lock()
            .expect("synthetic target map poisoned");
        let matches_generation = synthetic.get(&retirement.target).is_some_and(|info| {
            info.kind == SyntheticTargetKind::Operation
                && info.native_generation == Some(retirement.generation)
        });
        if !matches_generation {
            debug!(
                "event=synthetic ignored stale native operation retirement ptr=0x{:x} cookie=0x{:x} generation={}",
                retirement.target.ptr, retirement.target.cookie, retirement.generation
            );
            return;
        }
        synthetic.remove(&retirement.target);
        operations.remove(&retirement.target)
    };

    {
        let mut publications = OPERATION_PUBLICATIONS
            .lock()
            .expect("operation publication map poisoned");
        if publications
            .get(&retirement.target)
            .is_some_and(|publication| publication.generation == retirement.generation)
        {
            publications.remove(&retirement.target);
        }
    }
    OPERATION_PUBLICATION_PROBES
        .lock()
        .expect("operation publication probe queue poisoned")
        .retain(|probe| {
            probe.target != retirement.target || probe.generation != retirement.generation
        });

    drop(info);
}

pub(in crate::hook::rewrite) fn mark_operation_target_finalized(target: LocalBinderTarget) {
    let retired = {
        let mut operations = OPERATION_TARGETS
            .lock()
            .expect("operation target map poisoned");
        operations.get_mut(&target).and_then(|info| {
            info.finalized = true;
            info.backend.take()
        })
    };
    drop(retired);
}

fn native_binder_carrier(native: &NativeBinder) -> parcel::ReplyBinderCarrier {
    parcel::ReplyBinderCarrier {
        bytes: native.carrier().to_vec(),
        is_object: true,
    }
}

pub(in crate::hook) fn lookup_native_binder(
    target: LocalBinderTarget,
) -> Option<Arc<NativeBinder>> {
    NATIVE_BINDERS
        .lock()
        .expect("native binder map poisoned")
        .get(&target)
        .cloned()
}

pub(in crate::hook) fn lookup_native_binder_for(
    retirement: NativeBinderRetirement,
) -> Option<Arc<NativeBinder>> {
    let binders = NATIVE_BINDERS.lock().expect("native binder map poisoned");
    binders
        .get(&retirement.target)
        .filter(|native| native.retirement_generation() == retirement.generation)
        .cloned()
}

pub(in crate::hook::rewrite) fn register_synthetic_operation_carrier(
    backend: AospOperationBinder,
    aad_allowed: bool,
    caller: &CallerInfo,
) -> anyhow::Result<(parcel::ReplyBinderCarrier, NativeBinderRetirement)> {
    let native = Arc::new(create_native_operation_binder()?);
    let state = Arc::new(NativeOperationState {
        backend,
        aad_allowed,
        caller: caller.clone(),
        finalized: AtomicBool::new(false),
    });
    native.set_operation_state(Arc::clone(&state))?;
    let target = native.target();
    let carrier = native_binder_carrier(&native);
    let generation = register_operation_publication(target)?;
    let mut binders = NATIVE_BINDERS.lock().expect("native binder map poisoned");
    let mut operations = OPERATION_TARGETS
        .lock()
        .expect("operation target map poisoned");
    let mut synthetic = SYNTHETIC_TARGETS
        .lock()
        .expect("synthetic target map poisoned");
    let replaced_stale_system = if !synthetic.contains_key(&target)
        && !binders.contains_key(&target)
        && operations
            .get(&target)
            .is_some_and(|info| info.route == RouteTarget::System)
    {
        operations.remove(&target);
        true
    } else {
        false
    };
    if operations.contains_key(&target)
        || synthetic.contains_key(&target)
        || binders.contains_key(&target)
    {
        drop(synthetic);
        drop(operations);
        drop(binders);
        OPERATION_PUBLICATIONS
            .lock()
            .expect("operation publication map poisoned")
            .remove(&target);
        anyhow::bail!(
            "native operation target collision for ptr=0x{:x} cookie=0x{:x}",
            target.ptr,
            target.cookie
        );
    }
    synthetic.insert(
        target,
        SyntheticTargetInfo {
            kind: SyntheticTargetKind::Operation,
            #[cfg(test)]
            caller: Some(caller.clone()),
            native_generation: Some(generation),
            operation: Some(Arc::downgrade(&state)),
        },
    );
    binders.insert(target, native.clone());
    native.arm_retirement(generation);
    drop(binders);
    drop(synthetic);
    drop(operations);
    if replaced_stale_system {
        debug!(
            "event=synthetic replaced stale system operation mapping for reused target ptr=0x{:x} cookie=0x{:x}",
            target.ptr, target.cookie
        );
    }
    info!(
        "event=synthetic registered operation target ptr=0x{:x} cookie=0x{:x} aad_allowed={} uid={} pid={} sid='{}'",
        target.ptr, target.cookie, aad_allowed, caller.uid, caller.pid, caller.sid
    );
    Ok((carrier, NativeBinderRetirement { target, generation }))
}

pub(in crate::hook::rewrite) fn register_synthetic_security_level_carrier(
    security_level: crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel,
    source_method: ServiceMethod,
    caller: &CallerInfo,
) -> anyhow::Result<parcel::ReplyBinderCarrier> {
    let (target, carrier) = {
        let mut targets = SYNTHETIC_SECURITY_LEVEL_TARGETS
            .lock()
            .expect("synthetic security-level target map poisoned");
        if let Some(target) = targets.get(&security_level) {
            let native = NATIVE_BINDERS
                .lock()
                .expect("native binder map poisoned")
                .get(target)
                .cloned();
            let carrier = if let Some(native) = native {
                native_binder_carrier(&native)
            } else {
                return Err(anyhow::anyhow!(
                    "missing cached security-level binder for ptr=0x{:x} cookie=0x{:x}",
                    target.ptr,
                    target.cookie
                ));
            };
            (*target, carrier)
        } else {
            let native = Arc::new(create_native_security_level_binder()?);
            let target = native.target();
            let carrier = native_binder_carrier(&native);
            let mut binders = NATIVE_BINDERS.lock().expect("native binder map poisoned");
            let mut synthetic = SYNTHETIC_TARGETS
                .lock()
                .expect("synthetic target map poisoned");
            if binders.contains_key(&target) || synthetic.contains_key(&target) {
                anyhow::bail!(
                    "native security-level binder collision for ptr=0x{:x} cookie=0x{:x}",
                    target.ptr,
                    target.cookie
                );
            }
            binders.insert(target, native);
            synthetic.insert(
                target,
                SyntheticTargetInfo {
                    kind: SyntheticTargetKind::SecurityLevel,
                    #[cfg(test)]
                    caller: None,
                    native_generation: None,
                    operation: None,
                },
            );
            targets.insert(security_level, target);
            (target, carrier)
        }
    };
    tracker::remember_security_level_target(target, SecurityLevelTargetInfo { security_level });
    info!(
        "event=synthetic registered/reused security-level target ptr=0x{:x} cookie=0x{:x} security_level={:?} source_method={:?} uid={} pid={} sid='{}'",
        target.ptr, target.cookie, security_level, source_method, caller.uid, caller.pid, caller.sid
    );
    Ok(carrier)
}
