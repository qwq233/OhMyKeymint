use super::*;
use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::hook::rewrite::tests::*;

mod queue;
mod rewrite_failure;

pub(in crate::hook::rewrite) fn take_top_pending(
    connection: BinderStateKey,
) -> Option<Option<PendingCall>> {
    PENDING_REPLY_QUEUE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let position = slot
            .iter()
            .rposition(|frame| frame.connection == connection)?;
        Some(slot.remove(position).pending)
    })
}

pub(in crate::hook) fn reset_pending_reply_frames_for_test(
    connection: BinderStateKey,
    count: usize,
) {
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
    for _ in 0..count {
        push_pending_frame(connection);
    }
}

pub(in crate::hook) fn pending_reply_frame_count_for_test(connection: BinderStateKey) -> usize {
    PENDING_REPLY_QUEUE.with(|slot| {
        slot.borrow()
            .iter()
            .filter(|frame| frame.connection == connection)
            .count()
    })
}

pub(in crate::hook) fn pending_reply_frame_claims_for_test(
    connection: BinderStateKey,
) -> Vec<bool> {
    PENDING_REPLY_QUEUE.with(|slot| {
        slot.borrow()
            .iter()
            .filter(|frame| frame.connection == connection)
            .map(|frame| frame.claimed)
            .collect()
    })
}

pub(in crate::hook::rewrite) fn reset_pending_state_for_tests() {
    PENDING_REPLY_QUEUE.with(|slot| slot.borrow_mut().clear());
    OUTBOUND_REPLY_BUFFERS.with(|slot| slot.borrow_mut().clear());
}
