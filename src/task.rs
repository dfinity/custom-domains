use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use strum::{self, Display, EnumIter, EnumString};

use crate::time::UtcTimestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumIter, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum TaskKind {
    Issue,
    Renew,
    Update,
    Delete,
}

/// A task submitted by user for further scheduling and execution.
#[derive(Debug, Clone, PartialEq, Eq, new)]
pub struct InputTask {
    pub kind: TaskKind,
    pub domain: FQDN,
}

#[derive(Debug, Clone, PartialEq, Eq, new)]
pub struct ScheduledTask {
    pub kind: TaskKind,
    pub domain: FQDN,
    pub id: UtcTimestamp,
    pub certificate: Option<Vec<u8>>,
}

/// Represents the result of a task execution submitted by a worker to the repository.
///
/// Contains all relevant information about task completion:
/// - If `output` is `Some`, the task succeeded.
/// - If `failure` is `Some`, the task failed.
///   Only one of these can be `Some`.
#[derive(Debug, Clone)]
pub struct TaskResult {
    pub domain: FQDN,
    pub output: Option<TaskOutput>,
    pub failure: Option<TaskFailReason>,
    pub task_id: UtcTimestamp,
}

impl TaskResult {
    pub fn success(domain: FQDN, output: TaskOutput, task_id: UtcTimestamp) -> Self {
        Self {
            domain,
            output: Some(output),
            failure: None,
            task_id,
        }
    }

    pub fn failure(domain: FQDN, failure: TaskFailReason, task_id: UtcTimestamp) -> Self {
        Self {
            domain,
            output: None,
            failure: Some(failure),
            task_id,
        }
    }
}

#[derive(Debug, Clone)]
pub enum TaskOutput {
    Issue(IssueCertificateOutput),
    Update(Principal),
    Delete,
}

// The `to_string()` output is user-facing.
// Only validation failures are actionable by the user.
// All other errors suggest retrying or contacting support.
// TODO: add request_id to the body? (should be already in the header once intergrated into ic-gateway)
#[derive(Debug, Clone, Display, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
pub enum TaskFailReason {
    #[strum(to_string = "Validation failed: {0}. Please review your settings and try again.")]
    ValidationFailed(String),
    #[strum(to_string = "An unexpected error occurred. Please try again later or contact support")]
    Timeout { duration_secs: u64 },
    #[strum(to_string = "An unexpected error occurred. Please try again later or contact support")]
    GenericFailure(String),
}

#[derive(Debug, Clone, new)]
pub struct IssueCertificateOutput {
    pub canister_id: Principal,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub not_before: UtcTimestamp,
    pub not_after: UtcTimestamp,
}
