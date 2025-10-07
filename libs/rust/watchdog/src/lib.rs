// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Can be removed when instrumentations are added to keystore.
#![allow(dead_code)]

//! This module implements a watchdog thread.

use std::{
    cmp::min,
    collections::HashMap,
    sync::Arc,
    sync::{Condvar, Mutex, MutexGuard},
    thread,
};
use std::{
    marker::PhantomData,
    time::{Duration, Instant},
};

/// Represents a Watchdog record. It can be created with `Watchdog::watch` or
/// `Watchdog::watch_with`. It disarms the record when dropped.
pub struct WatchPoint {
    id: &'static str,
    wd: Arc<Watchdog>,
    not_send: PhantomData<*mut ()>, // WatchPoint must not be Send.
}

impl Drop for WatchPoint {
    fn drop(&mut self) {
        self.wd.disarm(self.id)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    NotRunning,
    Running,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct Index {
    tid: thread::ThreadId,
    id: &'static str,
}

struct Record {
    started: Instant,
    deadline: Instant,
    context: Option<Box<dyn std::fmt::Debug + Send + 'static>>,
}

impl Record {
    // Return a string representation of the start time of the record.
    //
    // Times are hard. This may not be accurate (e.g. if the system clock has been modified since
    // the watchdog started), but it's _really_ useful to get a starting wall time for overrunning
    // watchdogs.
    fn started_utc(&self) -> String {
        let started_utc = chrono::Utc::now() - self.started.elapsed();
        format!("{}", started_utc.format("%m-%d %H:%M:%S%.3f UTC"))
    }
}

struct WatchdogState {
    state: State,
    thread: Option<thread::JoinHandle<()>>,
    /// How long to wait before dropping the watchdog thread when idle.
    idle_timeout: Duration,
    records: HashMap<Index, Record>,
    last_report: Option<Instant>,
    noisy_timeout: Duration,
}

impl WatchdogState {
    /// If we have overdue records, we want to log them but slowly backoff
    /// so that we do not clog the logs. We start with logs every
    /// `MIN_REPORT_TIMEOUT` sec then increment the timeout by 5 up
    /// to a maximum of `MAX_REPORT_TIMEOUT`.
    const MIN_REPORT_TIMEOUT: Duration = Duration::from_secs(1);
    const MAX_REPORT_TIMEOUT: Duration = Duration::from_secs(30);

    fn reset_noisy_timeout(&mut self) {
        self.noisy_timeout = Self::MIN_REPORT_TIMEOUT;
    }

    fn update_noisy_timeout(&mut self) {
        let noisy_update = self.noisy_timeout + Duration::from_secs(5);
        self.noisy_timeout = min(Self::MAX_REPORT_TIMEOUT, noisy_update);
    }

    fn overdue_and_next_timeout(&self) -> (bool, Option<Duration>) {
        let now = Instant::now();
        let mut next_timeout: Option<Duration> = None;
        let mut has_overdue = false;
        for (_, r) in self.records.iter() {
            let timeout = r.deadline.saturating_duration_since(now);
            if timeout == Duration::new(0, 0) {
                // This timeout has passed.
                has_overdue = true;
            } else {
                // This timeout is still to come; see if it's the closest one to now.
                next_timeout = match next_timeout {
                    Some(nt) if timeout < nt => Some(timeout),
                    Some(nt) => Some(nt),
                    None => Some(timeout),
                };
            }
        }
        (has_overdue, next_timeout)
    }

    fn log_report(&mut self, has_overdue: bool) {
        if !has_overdue {
            // Nothing to report.
            self.last_report = None;
            return;
        }
        // Something to report...
        if let Some(reported_at) = self.last_report {
            if reported_at.elapsed() < self.noisy_timeout {
                // .. but it's too soon since the last report.
                self.last_report = None;
                return;
            }
        }
        self.update_noisy_timeout();
        self.last_report = Some(Instant::now());
        log::warn!("### Keystore Watchdog report - BEGIN ###");

        let now = Instant::now();
        let mut overdue_records: Vec<(&Index, &Record)> = self
            .records
            .iter()
            .filter(|(_, r)| r.deadline.saturating_duration_since(now) == Duration::new(0, 0))
            .collect();

        log::warn!(
            concat!(
                "When extracting from a bug report, please include this header ",
                "and all {} records below (to footer)"
            ),
            overdue_records.len()
        );

        // Watch points can be nested, i.e., a single thread may have multiple armed
        // watch points. And the most recent on each thread (thread recent) is closest to the point
        // where something is blocked. Furthermore, keystore2 has various critical section
        // and common backend resources KeyMint that can only be entered serialized. So if one
        // thread hangs, the others will soon follow suite. Thus the oldest "thread recent" watch
        // point is most likely pointing toward the culprit.
        // Thus, sort by start time first.
        overdue_records.sort_unstable_by(|(_, r1), (_, r2)| r1.started.cmp(&r2.started));
        // Then we groups all of the watch points per thread preserving the order within
        // groups.
        let groups = overdue_records.iter().fold(
            HashMap::<thread::ThreadId, Vec<(&Index, &Record)>>::new(),
            |mut acc, (i, r)| {
                acc.entry(i.tid).or_default().push((i, r));
                acc
            },
        );
        // Put the groups back into a vector.
        let mut groups: Vec<Vec<(&Index, &Record)>> = groups.into_values().collect();
        // Sort the groups by start time of the most recent (.last()) of each group.
        // It is panic safe to use unwrap() here because we never add empty vectors to
        // the map.
        groups.sort_by(|v1, v2| {
            v1.last()
                .unwrap()
                .1
                .started
                .cmp(&v2.last().unwrap().1.started)
        });

        for g in groups.iter() {
            for (i, r) in g.iter() {
                match &r.context {
                    Some(ctx) => {
                        log::warn!(
                            "{:?} {} Started: {} Pending: {:?} Overdue {:?} for {:?}",
                            i.tid,
                            i.id,
                            r.started_utc(),
                            r.started.elapsed(),
                            r.deadline.elapsed(),
                            ctx
                        );
                    }
                    None => {
                        log::warn!(
                            "{:?} {} Started: {} Pending: {:?} Overdue {:?}",
                            i.tid,
                            i.id,
                            r.started_utc(),
                            r.started.elapsed(),
                            r.deadline.elapsed()
                        );
                    }
                }
            }
        }
        log::warn!("### Keystore Watchdog report - END ###");
    }

    fn disarm(&mut self, index: Index) {
        let result = self.records.remove(&index);
        if let Some(record) = result {
            let now = Instant::now();
            let timeout_left = record.deadline.saturating_duration_since(now);
            if timeout_left == Duration::new(0, 0) {
                match &record.context {
                    Some(ctx) => log::info!(
                        "Watchdog complete for: {:?} {} Started: {} Pending: {:?} Overdue {:?} for {:?}",
                        index.tid,
                        index.id,
                        record.started_utc(),
                        record.started.elapsed(),
                        record.deadline.elapsed(),
                        ctx
                    ),
                    None => log::info!(
                        "Watchdog complete for: {:?} {} Started: {} Pending: {:?} Overdue {:?}",
                        index.tid,
                        index.id,
                        record.started_utc(),
                        record.started.elapsed(),
                        record.deadline.elapsed()
                    ),
                }
            }
        }
    }

    fn arm(&mut self, index: Index, record: Record) {
        if self.records.insert(index.clone(), record).is_some() {
            log::warn!(
                "Recursive watchdog record at \"{:?}\" replaces previous record.",
                index
            );
        }
    }
}

/// Watchdog spawns a thread that logs records of all overdue watch points when a deadline
/// is missed and at least every second as long as overdue watch points exist.
/// The thread terminates when idle for a given period of time.
pub struct Watchdog {
    state: Arc<(Condvar, Mutex<WatchdogState>)>,
}

impl Watchdog {
    /// Construct a [`Watchdog`]. When `idle_timeout` has elapsed since the watchdog thread became
    /// idle, i.e., there are no more active or overdue watch points, the watchdog thread
    /// terminates.
    pub fn new(idle_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new((
                Condvar::new(),
                Mutex::new(WatchdogState {
                    state: State::NotRunning,
                    thread: None,
                    idle_timeout,
                    records: HashMap::new(),
                    last_report: None,
                    noisy_timeout: WatchdogState::MIN_REPORT_TIMEOUT,
                }),
            )),
        })
    }

    fn watch_with_optional(
        wd: Arc<Self>,
        context: Option<Box<dyn std::fmt::Debug + Send + 'static>>,
        id: &'static str,
        timeout: Duration,
    ) -> Option<WatchPoint> {
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            log::warn!("Deadline computation failed for WatchPoint \"{}\"", id);
            log::warn!("WatchPoint not armed.");
            return None;
        };
        wd.arm(context, id, deadline);
        Some(WatchPoint {
            id,
            wd,
            not_send: Default::default(),
        })
    }

    /// Create a new watch point. If the WatchPoint is not dropped before the timeout
    /// expires, a report is logged at least every second, which includes the id string
    /// and any provided context.
    pub fn watch_with(
        wd: &Arc<Self>,
        id: &'static str,
        timeout: Duration,
        context: impl std::fmt::Debug + Send + 'static,
    ) -> Option<WatchPoint> {
        Self::watch_with_optional(wd.clone(), Some(Box::new(context)), id, timeout)
    }

    /// Like `watch_with`, but without context.
    pub fn watch(wd: &Arc<Self>, id: &'static str, timeout: Duration) -> Option<WatchPoint> {
        Self::watch_with_optional(wd.clone(), None, id, timeout)
    }

    fn arm(
        &self,
        context: Option<Box<dyn std::fmt::Debug + Send + 'static>>,
        id: &'static str,
        deadline: Instant,
    ) {
        let tid = thread::current().id();
        let index = Index { tid, id };
        let record = Record {
            started: Instant::now(),
            deadline,
            context,
        };

        let (ref condvar, ref state) = *self.state;

        let mut state = state.lock().unwrap();
        state.arm(index, record);

        if state.state != State::Running {
            self.spawn_thread(&mut state);
        }
        drop(state);
        condvar.notify_all();
    }

    fn disarm(&self, id: &'static str) {
        let tid = thread::current().id();
        let index = Index { tid, id };
        let (_, ref state) = *self.state;

        let mut state = state.lock().unwrap();
        state.disarm(index);
        // There is no need to notify condvar. There is no action required for the
        // watchdog thread before the next deadline.
    }

    fn spawn_thread(&self, state: &mut MutexGuard<WatchdogState>) {
        if let Some(t) = state.thread.take() {
            t.join().expect("Watchdog thread panicked.");
        }

        let cloned_state = self.state.clone();

        state.thread = Some(thread::spawn(move || {
            let (ref condvar, ref state) = *cloned_state;

            let mut state = state.lock().unwrap();

            loop {
                let (has_overdue, next_timeout) = state.overdue_and_next_timeout();
                state.log_report(has_overdue);

                let (next_timeout, idle) = match (has_overdue, next_timeout) {
                    (true, Some(next_timeout)) => (min(next_timeout, state.noisy_timeout), false),
                    (true, None) => (state.noisy_timeout, false),
                    (false, Some(next_timeout)) => (next_timeout, false),
                    (false, None) => (state.idle_timeout, true),
                };

                // Wait until the closest timeout pops, but use a condition variable so that if a
                // new watchpoint is started in the meanwhile it will interrupt the wait so we can
                // recalculate.
                let (s, timeout) = condvar.wait_timeout(state, next_timeout).unwrap();
                state = s;

                if idle && timeout.timed_out() && state.records.is_empty() {
                    state.reset_noisy_timeout();
                    state.state = State::NotRunning;
                    break;
                }
            }
            log::info!("Watchdog thread idle -> terminating. Have a great day.");
        }));
        state.state = State::Running;
    }
}
