use anyhow::anyhow;
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
    pub fn new(
        domain: FQDN,
        output: Option<TaskOutput>,
        failure: Option<TaskFailReason>,
        task_id: UtcTimestamp,
    ) -> anyhow::Result<Self> {
        if output.is_some() && failure.is_some() || output.is_none() && failure.is_none() {
            return Err(anyhow!("Task should be either failed or succeeded"));
        }

        Ok(Self {
            domain,
            output,
            failure,
            task_id,
        })
    }
}

#[derive(Debug, Clone)]
pub enum TaskOutput {
    Issue(IssueCertificateOutput),
    Update(Principal),
    Delete,
}

#[derive(Debug, Clone, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TaskFailReason {
    #[strum(to_string = "validation_failed: {0}")]
    ValidationFailed(String),
}

#[derive(Debug, Clone, new)]
pub struct IssueCertificateOutput {
    pub canister_id: Principal,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub not_before: UtcTimestamp,
    pub not_after: UtcTimestamp,
}
