use rsbinder::{thread_state::CallingContext, Strong};

use crate::android::system::keystore2::IKeystoreOperation::IKeystoreOperation as AospKeystoreOperation;
use crate::android::system::keystore2::IKeystoreSecurityLevel::IKeystoreSecurityLevel as AospKeystoreSecurityLevel;
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTarget {
    System,
    Omk,
}

#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub uid: u32,
    pub pid: i32,
    pub sid: String,
}

impl CallerIdentity {
    pub fn new(uid: u32, pid: i32) -> Self {
        Self {
            uid,
            pid,
            sid: String::new(),
        }
    }

    pub fn with_sid(mut self, sid: impl Into<String>) -> Self {
        self.sid = sid.into();
        self
    }

    pub fn to_caller_info(&self) -> CallerInfo {
        CallerInfo {
            callingUid: self.uid as i64,
            callingSid: self.sid.clone(),
            callingPid: self.pid as i64,
        }
    }

    pub fn from_calling_context(context: &CallingContext) -> Self {
        Self {
            uid: context.uid,
            pid: context.pid,
            sid: context
                .sid
                .as_ref()
                .map(|sid| sid.to_string_lossy().into_owned())
                .unwrap_or_default(),
        }
    }
}

pub type AospSecurityLevelBinder = Strong<dyn AospKeystoreSecurityLevel>;
pub type AospOperationBinder = Strong<dyn AospKeystoreOperation>;
