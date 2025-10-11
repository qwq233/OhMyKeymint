// Copyright 2020, The Android Open Source Project
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

//! This crate implements the `IKeystoreOperation` AIDL interface, which represents
//! an ongoing key operation, as well as the operation database, which is mainly
//! required for tracking operations for the purpose of pruning.
//! This crate also implements an operation pruning strategy.
//!
//! Operations implement the API calls update, finish, and abort.
//! Additionally, an operation can be dropped and pruned. The former
//! happens if the client deletes a binder to the operation object.
//! An existing operation may get pruned when running out of operation
//! slots and a new operation takes precedence.
//!
//! ## Operation Lifecycle
//! An operation gets created when the client calls `IKeystoreSecurityLevel::create`.
//! It may receive zero or more update request. The lifecycle ends when:
//!  * `update` yields an error.
//!  * `finish` is called.
//!  * `abort` is called.
//!  * The operation gets dropped.
//!  * The operation gets pruned.
//!
//! `Operation` has an `Outcome` member. While the outcome is `Outcome::Unknown`,
//! the operation is active and in a good state. Any of the above conditions may
//! change the outcome to one of the defined outcomes Success, Abort, Dropped,
//! Pruned, or ErrorCode. The latter is chosen in the case of an unexpected error, during
//! `update` or `finish`. `Success` is chosen iff `finish` completes without error.
//! Note that all operations get dropped eventually in the sense that they lose
//! their last reference and get destroyed. At that point, the fate of the operation
//! gets logged. However, an operation will transition to `Outcome::Dropped` iff
//! the operation was still active (`Outcome::Unknown`) at that time.
//!
//! ## Operation Dropping
//! To observe the dropping of an operation, we have to make sure that there
//! are no strong references to the IBinder representing this operation.
//! This would be simple enough if the operation object would need to be accessed
//! only by transactions. But to perform pruning, we have to retain a reference to the
//! original operation object.
//!
//! ## Operation Pruning
//! Pruning an operation happens during the creation of a new operation.
//! We have to iterate through the operation database to find a suitable
//! candidate. Then we abort and finalize this operation setting its outcome to
//! `Outcome::Pruned`. The corresponding KeyMint operation slot will have been freed
//! up at this point, but the `Operation` object lingers. When the client
//! attempts to use the operation again they will receive
//! ErrorCode::INVALID_OPERATION_HANDLE indicating that the operation no longer
//! exits. This should be the cue for the client to destroy its binder.
//! At that point the operation gets dropped.
//!
//! ## Architecture
//! The `IKeystoreOperation` trait is implemented by `KeystoreOperation`.
//! This acts as a proxy object holding a strong reference to actual operation
//! implementation `Operation`.
//!
//! ```
//! struct KeystoreOperation {
//!     operation: Mutex<Option<Arc<Operation>>>,
//! }
//! ```
//!
//! The `Mutex` serves two purposes. It provides interior mutability allowing
//! us to set the Option to None. We do this when the life cycle ends during
//! a call to `update`, `finish`, or `abort`. As a result most of the Operation
//! related resources are freed. The `KeystoreOperation` proxy object still
//! lingers until dropped by the client.
//! The second purpose is to protect operations against concurrent usage.
//! Failing to lock this mutex yields `ResponseCode::OPERATION_BUSY` and indicates
//! a programming error in the client.
//!
//! Note that the Mutex only protects the operation against concurrent client calls.
//! We still retain weak references to the operation in the operation database:
//!
//! ```
//! struct OperationDb {
//!     operations: Mutex<Vec<Weak<Operation>>>
//! }
//! ```
//!
//! This allows us to access the operations for the purpose of pruning.
//! We do this in three phases.
//!  1. We gather the pruning information. Besides non mutable information,
//!     we access `last_usage` which is protected by a mutex.
//!     We only lock this mutex for single statements at a time. During
//!     this phase we hold the operation db lock.
//!  2. We choose a pruning candidate by computing the pruning resistance
//!     of each operation. We do this entirely with information we now
//!     have on the stack without holding any locks.
//!     (See `OperationDb::prune` for more details on the pruning strategy.)
//!  3. During pruning we briefly lock the operation database again to get the
//!     the pruning candidate by index. We then attempt to abort the candidate.
//!     If the candidate was touched in the meantime or is currently fulfilling
//!     a request (i.e., the client calls update, finish, or abort),
//!     we go back to 1 and try again.
//!
//! So the outer Mutex in `KeystoreOperation::operation` only protects
//! operations against concurrent client calls but not against concurrent
//! pruning attempts. This is what the `Operation::outcome` mutex is used for.
//!
//! ```
//! struct Operation {
//!     ...
//!     outcome: Mutex<Outcome>,
//!     ...
//! }
//! ```
//!
//! Any request that can change the outcome, i.e., `update`, `finish`, `abort`,
//! `drop`, and `prune` has to take the outcome lock and check if the outcome
//! is still `Outcome::Unknown` before entering. `prune` is special in that
//! it will `try_lock`, because we don't want to be blocked on a potentially
//! long running request at another operation. If it fails to get the lock
//! the operation is either being touched, which changes its pruning resistance,
//! or it transitions to its end-of-life, which means we may get a free slot.
//! Either way, we have to revaluate the pruning scores.

use crate::android::hardware::security::keymint::ErrorCode::ErrorCode;
use crate::android::system::keystore2::ResponseCode::ResponseCode;
use crate::keymaster::enforcements::AuthInfo;

use crate::keymaster::error::{
    error_to_serialized_error, into_binder, into_logged_binder, map_binder_status,
    KsError as Error, SerializedError,
};

use crate::android::hardware::security::keymint::{
    IKeyMintOperation::IKeyMintOperation, KeyParameter::KeyParameter, KeyPurpose::KeyPurpose,
    SecurityLevel::SecurityLevel,
};
use crate::android::system::keystore2::{
    IKeystoreOperation::BnKeystoreOperation, IKeystoreOperation::IKeystoreOperation,
};
use crate::err;
use crate::keymaster::metrics_store::log_key_operation_event_stats;
use crate::watchdog as wd;
use anyhow::{anyhow, Context, Result};
use rsbinder::{Status, Strong};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Duration,
    time::Instant,
};

/// Operations have `Outcome::Unknown` as long as they are active. They transition
/// to one of the other variants exactly once. The distinction in outcome is mainly
/// for the statistic.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Outcome {
    /// Operations have `Outcome::Unknown` as long as they are active.
    Unknown,
    /// Operation is successful.
    Success,
    /// Operation is aborted.
    Abort,
    /// Operation is dropped.
    Dropped,
    /// Operation is pruned.
    Pruned,
    /// Operation is failed with the error code.
    ErrorCode(SerializedError),
}

/// Operation bundles all of the operation related resources and tracks the operation's
/// outcome.
#[derive(Debug)]
pub struct Operation {
    // The index of this operation in the OperationDb.
    index: usize,
    km_op: Strong<dyn IKeyMintOperation>,
    last_usage: Mutex<Instant>,
    outcome: Mutex<Outcome>,
    owner: u32, // Uid of the operation's owner.
    auth_info: Mutex<AuthInfo>,
    forced: bool,
    logging_info: LoggingInfo,
}

/// Keeps track of the information required for logging operations.
#[derive(Debug)]
pub struct LoggingInfo {
    sec_level: SecurityLevel,
    purpose: KeyPurpose,
    op_params: Vec<KeyParameter>,
    key_upgraded: bool,
}

impl LoggingInfo {
    /// Constructor
    pub fn new(
        sec_level: SecurityLevel,
        purpose: KeyPurpose,
        op_params: Vec<KeyParameter>,
        key_upgraded: bool,
    ) -> LoggingInfo {
        Self {
            sec_level,
            purpose,
            op_params,
            key_upgraded,
        }
    }
}

struct PruningInfo {
    last_usage: Instant,
    owner: u32,
    index: usize,
    forced: bool,
}

// We don't except more than 32KiB of data in `update`, `updateAad`, and `finish`.
const MAX_RECEIVE_DATA: usize = 0x8000;

impl Operation {
    /// Constructor
    pub fn new(
        index: usize,
        km_op: rsbinder::Strong<dyn IKeyMintOperation>,
        owner: u32,
        auth_info: AuthInfo,
        forced: bool,
        logging_info: LoggingInfo,
    ) -> Self {
        Self {
            index,
            km_op,
            last_usage: Mutex::new(Instant::now()),
            outcome: Mutex::new(Outcome::Unknown),
            owner,
            auth_info: Mutex::new(auth_info),
            forced,
            logging_info,
        }
    }

    fn get_pruning_info(&self) -> Option<PruningInfo> {
        // An operation may be finalized.
        if let Ok(guard) = self.outcome.try_lock() {
            match *guard {
                Outcome::Unknown => {}
                // If the outcome is any other than unknown, it has been finalized,
                // and we can no longer consider it for pruning.
                _ => return None,
            }
        }
        // Else: If we could not grab the lock, this means that the operation is currently
        //       being used and it may be transitioning to finalized or it was simply updated.
        //       In any case it is fair game to consider it for pruning. If the operation
        //       transitioned to a final state, we will notice when we attempt to prune, and
        //       a subsequent attempt to create a new operation will succeed.
        Some(PruningInfo {
            // Expect safety:
            // `last_usage` is locked only for primitive single line statements.
            // There is no chance to panic and poison the mutex.
            last_usage: *self.last_usage.lock().expect("In get_pruning_info."),
            owner: self.owner,
            index: self.index,
            forced: self.forced,
        })
    }

    fn prune(&self, last_usage: Instant) -> Result<(), Error> {
        let mut locked_outcome = match self.outcome.try_lock() {
            Ok(guard) => match *guard {
                Outcome::Unknown => guard,
                _ => return Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)),
            },
            Err(_) => return Err(Error::Rc(ResponseCode::OPERATION_BUSY)),
        };

        // In `OperationDb::prune`, which is our caller, we first gather the pruning
        // information including the last usage. When we select a candidate
        // we call `prune` on that candidate passing the last_usage
        // that we gathered earlier. If the actual last usage
        // has changed since than, it means the operation was busy in the
        // meantime, which means that we have to reevaluate the pruning score.
        //
        // Expect safety:
        // `last_usage` is locked only for primitive single line statements.
        // There is no chance to panic and poison the mutex.
        if *self.last_usage.lock().expect("In Operation::prune()") != last_usage {
            return Err(Error::Rc(ResponseCode::OPERATION_BUSY));
        }
        *locked_outcome = Outcome::Pruned;

        let _wp = wd::watch("Operation::prune: calling IKeyMintOperation::abort()");

        // We abort the operation. If there was an error we log it but ignore it.
        if let Err(e) = map_binder_status(self.km_op.abort()) {
            log::warn!("In prune: KeyMint::abort failed with {:?}.", e);
        }

        Ok(())
    }

    // This function takes a Result from a KeyMint call and inspects it for errors.
    // If an error was found it updates the given `locked_outcome` accordingly.
    // It forwards the Result unmodified.
    // The precondition to this call must be *locked_outcome == Outcome::Unknown.
    // Ideally the `locked_outcome` came from a successful call to `check_active`
    // see below.
    fn update_outcome<T>(
        &self,
        locked_outcome: &mut Outcome,
        err: Result<T, Error>,
    ) -> Result<T, Error> {
        if let Err(e) = &err {
            *locked_outcome = Outcome::ErrorCode(error_to_serialized_error(e))
        }
        err
    }

    // This function grabs the outcome lock and checks the current outcome state.
    // If the outcome is still `Outcome::Unknown`, this function returns
    // the locked outcome for further updates. In any other case it returns
    // ErrorCode::INVALID_OPERATION_HANDLE indicating that this operation has
    // been finalized and is no longer active.
    fn check_active(&self) -> Result<MutexGuard<Outcome>> {
        let guard = self.outcome.lock().expect("In check_active.");
        match *guard {
            Outcome::Unknown => Ok(guard),
            _ => Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)).context(err!(
                "Call on finalized operation with outcome: {:?}.",
                *guard
            )),
        }
    }

    // This function checks the amount of input data sent to us. We reject any buffer
    // exceeding MAX_RECEIVE_DATA bytes as input to `update`, `update_aad`, and `finish`
    // in order to force clients into using reasonable limits.
    fn check_input_length(data: &[u8]) -> Result<()> {
        if data.len() > MAX_RECEIVE_DATA {
            // This error code is unique, no context required here.
            return Err(anyhow!(Error::Rc(ResponseCode::TOO_MUCH_DATA)));
        }
        Ok(())
    }

    // Update the last usage to now.
    fn touch(&self) {
        // Expect safety:
        // `last_usage` is locked only for primitive single line statements.
        // There is no chance to panic and poison the mutex.
        *self.last_usage.lock().expect("In touch.") = Instant::now();
    }

    /// Implementation of `IKeystoreOperation::updateAad`.
    /// Refer to the AIDL spec at system/hardware/interfaces/keystore2 for details.
    fn update_aad(&self, aad_input: &[u8]) -> Result<()> {
        let mut outcome = self.check_active().context("In update_aad")?;
        Self::check_input_length(aad_input).context("In update_aad")?;
        self.touch();

        let (hat, tst) = self
            .auth_info
            .lock()
            .unwrap()
            .before_update()
            .context(err!("Trying to get auth tokens."))?;

        self.update_outcome(&mut outcome, {
            let _wp = wd::watch("Operation::update_aad: calling IKeyMintOperation::updateAad");
            map_binder_status(self.km_op.updateAad(aad_input, hat.as_ref(), tst.as_ref()))
        })
        .context(err!("Update failed."))?;

        Ok(())
    }

    /// Implementation of `IKeystoreOperation::update`.
    /// Refer to the AIDL spec at system/hardware/interfaces/keystore2 for details.
    fn update(&self, input: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut outcome = self.check_active().context("In update")?;
        Self::check_input_length(input).context("In update")?;
        self.touch();

        let (hat, tst) = self
            .auth_info
            .lock()
            .unwrap()
            .before_update()
            .context(err!("Trying to get auth tokens."))?;

        let output = self
            .update_outcome(&mut outcome, {
                let _wp = wd::watch("Operation::update: calling IKeyMintOperation::update");
                map_binder_status(self.km_op.update(input, hat.as_ref(), tst.as_ref()))
            })
            .context(err!("Update failed."))?;

        if output.is_empty() {
            Ok(None)
        } else {
            Ok(Some(output))
        }
    }

    /// Implementation of `IKeystoreOperation::finish`.
    /// Refer to the AIDL spec at system/hardware/interfaces/keystore2 for details.
    fn finish(&self, input: Option<&[u8]>, signature: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        let mut outcome = self.check_active().context("In finish")?;
        if let Some(input) = input {
            Self::check_input_length(input).context("In finish")?;
        }
        self.touch();

        let (hat, tst, confirmation_token) = self
            .auth_info
            .lock()
            .unwrap()
            .before_finish()
            .context(err!("Trying to get auth tokens."))?;

        let output = self
            .update_outcome(&mut outcome, {
                let _wp = wd::watch("Operation::finish: calling IKeyMintOperation::finish");
                map_binder_status(self.km_op.finish(
                    input,
                    signature,
                    hat.as_ref(),
                    tst.as_ref(),
                    confirmation_token.as_deref(),
                ))
            })
            .context(err!("Finish failed."))?;

        self.auth_info
            .lock()
            .unwrap()
            .after_finish()
            .context("In finish.")?;

        // At this point the operation concluded successfully.
        *outcome = Outcome::Success;

        if output.is_empty() {
            Ok(None)
        } else {
            Ok(Some(output))
        }
    }

    /// Aborts the operation if it is active. IFF the operation is aborted the outcome is
    /// set to `outcome`. `outcome` must reflect the reason for the abort. Since the operation
    /// gets aborted `outcome` must not be `Operation::Success` or `Operation::Unknown`.
    fn abort(&self, outcome: Outcome) -> Result<()> {
        let mut locked_outcome = self.check_active().context("In abort")?;
        *locked_outcome = outcome;

        {
            let _wp = wd::watch("Operation::abort: calling IKeyMintOperation::abort");
            map_binder_status(self.km_op.abort()).context(err!("KeyMint::abort failed."))
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        let guard = self.outcome.lock().expect("In drop.");
        log_key_operation_event_stats(
            self.logging_info.sec_level,
            self.logging_info.purpose,
            &(self.logging_info.op_params),
            &guard,
            self.logging_info.key_upgraded,
        );
        if let Outcome::Unknown = *guard {
            drop(guard);
            // If the operation was still active we call abort, setting
            // the outcome to `Outcome::Dropped`
            if let Err(e) = self.abort(Outcome::Dropped) {
                log::error!("While dropping Operation: abort failed:\n    {:?}", e);
            }
        }
    }
}

/// The OperationDb holds weak references to all ongoing operations.
/// Its main purpose is to facilitate operation pruning.
#[derive(Debug, Default)]
pub struct OperationDb {
    // TODO replace Vec with WeakTable when the weak_table crate becomes
    // available.
    operations: Mutex<Vec<Weak<Operation>>>,
}

impl OperationDb {
    /// Creates a new OperationDb.
    pub fn new() -> Self {
        Self {
            operations: Mutex::new(Vec::new()),
        }
    }

    /// Creates a new operation.
    /// This function takes a KeyMint operation and an associated
    /// owner uid and returns a new Operation wrapped in a `std::sync::Arc`.
    pub fn create_operation(
        &self,
        km_op: rsbinder::Strong<dyn IKeyMintOperation>,
        owner: u32,
        auth_info: AuthInfo,
        forced: bool,
        logging_info: LoggingInfo,
    ) -> Arc<Operation> {
        // We use unwrap because we don't allow code that can panic while locked.
        let mut operations = self.operations.lock().expect("In create_operation.");

        let mut index: usize = 0;
        // First we iterate through the operation slots to try and find an unused
        // slot. If we don't find one, we append the new entry instead.
        match (*operations).iter_mut().find(|s| {
            index += 1;
            s.upgrade().is_none()
        }) {
            Some(free_slot) => {
                let new_op = Arc::new(Operation::new(
                    index - 1,
                    km_op,
                    owner,
                    auth_info,
                    forced,
                    logging_info,
                ));
                *free_slot = Arc::downgrade(&new_op);
                new_op
            }
            None => {
                let new_op = Arc::new(Operation::new(
                    operations.len(),
                    km_op,
                    owner,
                    auth_info,
                    forced,
                    logging_info,
                ));
                operations.push(Arc::downgrade(&new_op));
                new_op
            }
        }
    }

    fn get(&self, index: usize) -> Option<Arc<Operation>> {
        self.operations
            .lock()
            .expect("In OperationDb::get.")
            .get(index)
            .and_then(|op| op.upgrade())
    }

    /// Attempts to prune an operation.
    ///
    /// This function is used during operation creation, i.e., by
    /// `KeystoreSecurityLevel::create_operation`, to try and free up an operation slot
    /// if it got `ErrorCode::TOO_MANY_OPERATIONS` from the KeyMint backend. It is not
    /// guaranteed that an operation slot is available after this call successfully
    /// returned for various reasons. E.g., another thread may have snatched up the newly
    /// available slot. Callers may have to call prune multiple times before they get a
    /// free operation slot. Prune may also return `Err(Error::Rc(ResponseCode::BACKEND_BUSY))`
    /// which indicates that no prunable operation was found.
    ///
    /// To find a suitable candidate we compute the malus for the caller and each existing
    /// operation. The malus is the inverse of the pruning power (caller) or pruning
    /// resistance (existing operation).
    ///
    /// The malus is based on the number of sibling operations and age. Sibling
    /// operations are operations that have the same owner (UID).
    ///
    /// Every operation, existing or new, starts with a malus of 1. Every sibling
    /// increases the malus by one. The age is the time since an operation was last touched.
    /// It increases the malus by log6(<age in seconds> + 1) rounded down to the next
    /// integer. So the malus increases stepwise after 5s, 35s, 215s, ...
    /// Of two operations with the same malus the least recently used one is considered
    /// weaker.
    ///
    /// For the caller to be able to prune an operation it must find an operation
    /// with a malus higher than its own.
    ///
    /// The malus can be expressed as
    /// ```
    /// malus = 1 + no_of_siblings + floor(log6(age_in_seconds + 1))
    /// ```
    /// where the constant `1` accounts for the operation under consideration.
    /// In reality we compute it as
    /// ```
    /// caller_malus = 1 + running_siblings
    /// ```
    /// because the new operation has no age and is not included in the `running_siblings`,
    /// and
    /// ```
    /// running_malus = running_siblings + floor(log6(age_in_seconds + 1))
    /// ```
    /// because a running operation is included in the `running_siblings` and it has
    /// an age.
    ///
    /// ## Example
    /// A caller with no running operations has a malus of 1. Young (age < 5s) operations
    /// also with no siblings have a malus of one and cannot be pruned by the caller.
    /// We have to find an operation that has at least one sibling or is older than 5s.
    ///
    /// A caller with one running operation has a malus of 2. Now even young siblings
    /// or single child aging (5s <= age < 35s) operations are off limit. An aging
    /// sibling of two, however, would have a malus of 3 and would be fair game.
    ///
    /// ## Rationale
    /// Due to the limitation of KeyMint operation slots, we cannot get around pruning or
    /// a single app could easily DoS KeyMint.
    /// Keystore 1.0 used to always prune the least recently used operation. This at least
    /// guaranteed that new operations can always be started. With the increased usage
    /// of Keystore we saw increased pruning activity which can lead to a livelock
    /// situation in the worst case.
    ///
    /// With the new pruning strategy we want to provide well behaved clients with
    /// progress assurances while punishing DoS attempts. As a result of this
    /// strategy we can be in the situation where no operation can be pruned and the
    /// creation of a new operation fails. This allows single child operations which
    /// are frequently updated to complete, thereby breaking up livelock situations
    /// and facilitating system wide progress.
    ///
    /// ## Update
    /// We also allow callers to cannibalize their own sibling operations if no other
    /// slot can be found. In this case the least recently used sibling is pruned.
    pub fn prune(&self, caller: u32, forced: bool) -> Result<(), Error> {
        loop {
            // Maps the uid of the owner to the number of operations that owner has
            // (running_siblings). More operations per owner lowers the pruning
            // resistance of the operations of that owner. Whereas the number of
            // ongoing operations of the caller lowers the pruning power of the caller.
            let mut owners: HashMap<u32, u64> = HashMap::new();
            let mut pruning_info: Vec<PruningInfo> = Vec::new();

            let now = Instant::now();
            self.operations
                .lock()
                .expect("In OperationDb::prune: Trying to lock self.operations.")
                .iter()
                .for_each(|op| {
                    if let Some(op) = op.upgrade() {
                        if let Some(p_info) = op.get_pruning_info() {
                            let owner = p_info.owner;
                            pruning_info.push(p_info);
                            // Count operations per owner.
                            *owners.entry(owner).or_insert(0) += 1;
                        }
                    }
                });

            // If the operation is forced, the caller has a malus of 0.
            let caller_malus = if forced {
                0
            } else {
                1u64 + *owners.entry(caller).or_default()
            };

            // We iterate through all operations computing the malus and finding
            // the candidate with the highest malus which must also be higher
            // than the caller_malus.
            struct CandidateInfo {
                index: usize,
                malus: u64,
                last_usage: Instant,
                age: Duration,
            }
            let mut oldest_caller_op: Option<CandidateInfo> = None;
            let candidate = pruning_info.iter().fold(
                None,
                |acc: Option<CandidateInfo>,
                 &PruningInfo {
                     last_usage,
                     owner,
                     index,
                     forced,
                 }| {
                    // Compute the age of the current operation.
                    let age = now
                        .checked_duration_since(last_usage)
                        .unwrap_or_else(|| Duration::new(0, 0));

                    // Find the least recently used sibling as an alternative pruning candidate.
                    if owner == caller {
                        if let Some(CandidateInfo { age: a, .. }) = oldest_caller_op {
                            if age > a {
                                oldest_caller_op = Some(CandidateInfo {
                                    index,
                                    malus: 0,
                                    last_usage,
                                    age,
                                });
                            }
                        } else {
                            oldest_caller_op = Some(CandidateInfo {
                                index,
                                malus: 0,
                                last_usage,
                                age,
                            });
                        }
                    }

                    // Compute the malus of the current operation.
                    let malus = if forced {
                        // Forced operations have a malus of 0. And cannot even be pruned
                        // by other forced operations.
                        0
                    } else {
                        // Expect safety: Every owner in pruning_info was counted in
                        // the owners map. So this unwrap cannot panic.
                        *owners.get(&owner).expect(
                            "This is odd. We should have counted every owner in pruning_info.",
                        ) + ((age.as_secs() + 1) as f64).log(6.0).floor() as u64
                    };

                    // Now check if the current operation is a viable/better candidate
                    // the one currently stored in the accumulator.
                    match acc {
                        // First we have to find any operation that is prunable by the caller.
                        None => {
                            if caller_malus < malus {
                                Some(CandidateInfo {
                                    index,
                                    malus,
                                    last_usage,
                                    age,
                                })
                            } else {
                                None
                            }
                        }
                        // If we have found one we look for the operation with the worst score.
                        // If there is a tie, the older operation is considered weaker.
                        Some(CandidateInfo {
                            index: i,
                            malus: m,
                            last_usage: l,
                            age: a,
                        }) => {
                            if malus > m || (malus == m && age > a) {
                                Some(CandidateInfo {
                                    index,
                                    malus,
                                    last_usage,
                                    age,
                                })
                            } else {
                                Some(CandidateInfo {
                                    index: i,
                                    malus: m,
                                    last_usage: l,
                                    age: a,
                                })
                            }
                        }
                    }
                },
            );

            // If we did not find a suitable candidate we may cannibalize our oldest sibling.
            let candidate = candidate.or(oldest_caller_op);

            match candidate {
                Some(CandidateInfo {
                    index,
                    malus: _,
                    last_usage,
                    age: _,
                }) => {
                    match self.get(index) {
                        Some(op) => {
                            match op.prune(last_usage) {
                                // We successfully freed up a slot.
                                Ok(()) => break Ok(()),
                                // This means the operation we tried to prune was on its way
                                // out. It also means that the slot it had occupied was freed up.
                                Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)) => break Ok(()),
                                // This means the operation we tried to prune was currently
                                // servicing a request. There are two options.
                                // * Assume that it was touched, which means that its
                                //   pruning resistance increased. In that case we have
                                //   to start over and find another candidate.
                                // * Assume that the operation is transitioning to end-of-life.
                                //   which means that we got a free slot for free.
                                // If we assume the first but the second is true, we prune
                                // a good operation without need (aggressive approach).
                                // If we assume the second but the first is true, our
                                // caller will attempt to create a new KeyMint operation,
                                // fail with `ErrorCode::TOO_MANY_OPERATIONS`, and call
                                // us again (conservative approach).
                                Err(Error::Rc(ResponseCode::OPERATION_BUSY)) => {
                                    // We choose the conservative approach, because
                                    // every needlessly pruned operation can impact
                                    // the user experience.
                                    // To switch to the aggressive approach replace
                                    // the following line with `continue`.
                                    break Ok(());
                                }

                                // The candidate may have been touched so the score
                                // has changed since our evaluation.
                                _ => continue,
                            }
                        }
                        // This index does not exist any more. The operation
                        // in this slot was dropped. Good news, a slot
                        // has freed up.
                        None => break Ok(()),
                    }
                }
                // We did not get a pruning candidate.
                None => break Err(Error::Rc(ResponseCode::BACKEND_BUSY)),
            }
        }
    }
}

/// Implementation of IKeystoreOperation.
pub struct KeystoreOperation {
    operation: Mutex<Option<Arc<Operation>>>,
}

impl KeystoreOperation {
    /// Creates a new operation instance wrapped in a
    /// BnKeystoreOperation proxy object. It also enables
    /// `BinderFeatures::set_requesting_sid` on the new interface, because
    /// we need it for checking Keystore permissions.
    pub fn new_native_binder(
        operation: Arc<Operation>,
    ) -> rsbinder::Strong<dyn IKeystoreOperation> {
        BnKeystoreOperation::new_binder(Self {
            operation: Mutex::new(Some(operation)),
        })
    }

    /// Grabs the outer operation mutex and calls `f` on the locked operation.
    /// The function also deletes the operation if it returns with an error or if
    /// `delete_op` is true.
    fn with_locked_operation<T, F>(&self, f: F, delete_op: bool) -> Result<T>
    where
        for<'a> F: FnOnce(&'a Operation) -> Result<T>,
    {
        let mut delete_op: bool = delete_op;
        match self.operation.try_lock() {
            Ok(mut mutex_guard) => {
                let result = match &*mutex_guard {
                    Some(op) => {
                        let result = f(op);
                        // Any error here means we can discard the operation.
                        if result.is_err() {
                            delete_op = true;
                        }
                        result
                    }
                    None => Err(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE))
                        .context(err!("KeystoreOperation::with_locked_operation")),
                };

                if delete_op {
                    // We give up our reference to the Operation, thereby freeing up our
                    // internal resources and ending the wrapped KeyMint operation.
                    // This KeystoreOperation object will still be owned by an SpIBinder
                    // until the client drops its remote reference.
                    *mutex_guard = None;
                }
                result
            }
            Err(_) => Err(Error::Rc(ResponseCode::OPERATION_BUSY))
                .context(err!("KeystoreOperation::with_locked_operation")),
        }
    }
}

impl rsbinder::Interface for KeystoreOperation {}

#[allow(non_snake_case)]
impl IKeystoreOperation for KeystoreOperation {
    fn updateAad(&self, aad_input: &[u8]) -> Result<(), Status> {
        let _wp = wd::watch("IKeystoreOperation::updateAad");
        self.with_locked_operation(
            |op| {
                op.update_aad(aad_input)
                    .context(err!("KeystoreOperation::updateAad"))
            },
            false,
        )
        .map_err(into_logged_binder)
    }

    fn update(&self, input: &[u8]) -> Result<std::option::Option<Vec<u8>>, Status> {
        let _wp = wd::watch("IKeystoreOperation::update");
        self.with_locked_operation(
            |op| op.update(input).context(err!("KeystoreOperation::update")),
            false,
        )
        .map_err(into_logged_binder)
    }
    fn finish(
        &self,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
    ) -> Result<std::option::Option<Vec<u8>>, Status> {
        let _wp = wd::watch("IKeystoreOperation::finish");
        self.with_locked_operation(
            |op| {
                op.finish(input, signature)
                    .context(err!("KeystoreOperation::finish"))
            },
            true,
        )
        .map_err(into_logged_binder)
    }

    fn abort(&self) -> Result<(), Status> {
        let _wp = wd::watch("IKeystoreOperation::abort");
        let result = self.with_locked_operation(
            |op| {
                op.abort(Outcome::Abort)
                    .context(err!("KeystoreOperation::abort"))
            },
            true,
        );
        result.map_err(|e| {
            match e.root_cause().downcast_ref::<Error>() {
                // Calling abort on expired operations is something very common.
                // There is no reason to clutter the log with it. It is never the cause
                // for a true problem.
                Some(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)) => {}
                _ => log::error!("{:?}", e),
            };
            into_binder(e)
        })
    }
}
