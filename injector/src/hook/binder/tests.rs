use super::{
    binder_transaction_data, BC_FREE_BUFFER_NR, BC_REPLY_NR, BR_TRANSACTION_NR, IOC_NONE, IOC_READ,
    IOC_WRITE,
};
use std::mem;

const BR_NOOP_NR: u32 = 12;

pub(in crate::hook) const BR_NOOP_CMD: u32 = super::ioc(IOC_NONE, b'r' as u32, BR_NOOP_NR, 0);

pub(in crate::hook) const BR_TRANSACTION_CMD: u32 =
    super::ioc(IOC_READ, b'r' as u32, BR_TRANSACTION_NR, mem::size_of::<binder_transaction_data>());

pub(in crate::hook) const BC_FREE_BUFFER_CMD: u32 =
    super::ioc(IOC_WRITE, b'c' as u32, BC_FREE_BUFFER_NR, mem::size_of::<libc::c_ulong>());

pub(in crate::hook) const BC_REPLY_CMD: u32 =
    super::ioc(IOC_WRITE, b'c' as u32, BC_REPLY_NR, mem::size_of::<binder_transaction_data>());
