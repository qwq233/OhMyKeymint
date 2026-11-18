use crate::hook::binder::LocalBinderTarget;
use crate::hook::BinderStateKey;
use binder::SpIBinder;
use std::cell::{Cell, RefCell};

struct PendingCall {
    id: u64,
    connection: Option<BinderStateKey>,
    target: LocalBinderTarget,
    input: usize,
    flags: u32,
    delivered: bool,
    pin: Option<SpIBinder>,
}

thread_local! {
    static NEXT_FRAME: Cell<u64> = Cell::default();
    static FRAMES: RefCell<Vec<PendingCall>> = RefCell::default();
}

pub(in crate::hook) fn available() -> bool {
    FRAMES.try_with(|_| ()).is_ok() && NEXT_FRAME.try_with(|_| ()).is_ok()
}

pub(in crate::hook) struct ReceivedCall {
    pub target: LocalBinderTarget,
    pub flags: u32,
    _pin: Option<SpIBinder>,
}

pub(in crate::hook) fn push_received_frame(
    connection: Option<BinderStateKey>,
    target: LocalBinderTarget,
    input: usize,
    flags: u32,
    pin: Option<SpIBinder>,
) -> Option<u64> {
    let id = NEXT_FRAME
        .try_with(|next| {
            let id = next.get().checked_add(1).expect("thread frame IDs exhausted");
            next.set(id);
            id
        })
        .ok()?;
    FRAMES
        .try_with(|slot| {
            slot.borrow_mut().push(PendingCall {
                id,
                connection,
                target,
                input,
                flags,
                pin,
                delivered: connection.is_none(),
            });
        })
        .ok()?;
    Some(id)
}

pub(in crate::hook) fn claim_callback(target: LocalBinderTarget, input: usize) -> ReceivedCall {
    let frame = FRAMES
        .try_with(|slot| {
            let mut frames = slot.borrow_mut();
            let position = frames.iter().rposition(|frame| {
                frame.delivered && frame.target == target && frame.input == input
            })?;
            Some(frames.remove(position))
        })
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            panic!("missing delivered Binder receipt: target={target:?} input={input:#x}")
        });
    ReceivedCall { target: frame.target, flags: frame.flags, _pin: frame.pin }
}

pub(in crate::hook) fn mark_delivered(id: u64) {
    FRAMES
        .try_with(|slot| {
            let mut frames = slot.borrow_mut();
            let frame = frames
                .iter_mut()
                .find(|frame| frame.id == id)
                .unwrap_or_else(|| panic!("missing Binder delivery receipt: frame={id}"));
            frame.delivered = true;
        })
        .expect("Binder receipt TLS destroyed before delivery");
}

pub(in crate::hook) fn discard_received_frame(id: u64) {
    let removed = FRAMES.try_with(|slot| {
        let mut frames = slot.borrow_mut();
        let position = frames.iter().position(|frame| frame.id == id)?;
        Some(frames.remove(position))
    });
    drop(removed);
}

pub(in crate::hook) fn commit_free_buffer(connection: BinderStateKey, input: usize) {
    let removed = FRAMES.try_with(|slot| {
        let mut frames = slot.borrow_mut();
        let position = frames
            .iter()
            .rposition(|frame| frame.connection == Some(connection) && frame.input == input)?;
        Some(frames.remove(position))
    });
    drop(removed);
}

pub(in crate::hook) fn clear_binder_fd_thread_state(connection: BinderStateKey) {
    let removed = FRAMES.try_with(|slot| {
        slot.borrow_mut()
            .extract_if(.., |frame| frame.connection == Some(connection) && !frame.delivered)
            .collect::<Vec<_>>()
    });
    // Delivered callbacks retain their pin until callback, buffer release or TLS teardown.
    drop(removed);
}

#[cfg(test)]
pub(in crate::hook) mod tests {
    use super::*;
    use binder::binder_impl::{Binder, BorrowedParcel, Remotable};
    use binder::{binder_fn_get_class, Interface, StatusCode};
    use std::ffi::CStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    pub(in crate::hook) fn reset_received_frames_for_test(
        connection: BinderStateKey,
        count: usize,
    ) {
        let removed = FRAMES.replace(Vec::new());
        drop(removed);
        for index in 0..count {
            push_received_frame(
                Some(connection),
                LocalBinderTarget { ptr: 0, cookie: 0 },
                index,
                0,
                None,
            )
            .unwrap();
        }
    }

    pub(in crate::hook) fn received_frame_count_for_test(connection: BinderStateKey) -> usize {
        FRAMES.with_borrow(|frames| {
            frames.iter().filter(|frame| frame.connection == Some(connection)).count()
        })
    }

    pub(in crate::hook) fn pin(drops: Arc<AtomicUsize>) -> SpIBinder {
        struct Pin {
            drops: Arc<AtomicUsize>,
        }
        impl Drop for Pin {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        impl Remotable for Pin {
            fn get_descriptor() -> &'static str {
                "test.DeliveryPin"
            }
            fn on_transact(
                &self,
                _: u32,
                _: &BorrowedParcel<'_>,
                _: &mut BorrowedParcel<'_>,
            ) -> Result<(), StatusCode> {
                Err(StatusCode::UNKNOWN_TRANSACTION)
            }
            fn on_dump(&self, _: &mut dyn std::io::Write, _: &[&CStr]) -> Result<(), StatusCode> {
                Ok(())
            }
            fn on_shell_command(
                &self,
                _: &mut dyn std::io::Read,
                _: &mut dyn std::io::Write,
                _: &mut dyn std::io::Write,
                _: &[&CStr],
            ) -> Result<(), StatusCode> {
                Ok(())
            }
            binder_fn_get_class!(Binder<Self>);
        }
        Binder::new(Pin { drops }).as_binder()
    }

    #[test]
    fn retirement_keeps_delivered_existing_carrier_without_a_rewrite_pin() {
        reset_received_frames_for_test(507, 0);
        let target = LocalBinderTarget { ptr: 71, cookie: 72 };
        let id = push_received_frame(Some(507), target, 73, 0, None).unwrap();
        mark_delivered(id);
        clear_binder_fd_thread_state(507);
        let call = claim_callback(target, 73);
        assert_eq!(call.flags, 0);
        clear_binder_fd_thread_state(507);
        assert_eq!(received_frame_count_for_test(507), 0);
    }
}
