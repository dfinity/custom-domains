use std::{str::FromStr, time::Duration};

use candid::Principal;
use canister_api::{
    InputTask as ApiInputTask, IssueCertificateOutput as ApiIssueCertificateOutput,
    ScheduledTask as ApiScheduledTask, TaskFailReason as ApiTaskFailReason,
    TaskKind as ApiTaskKind, TaskOutput as ApiTaskOutput, TaskResult as ApiTaskResult,
};
use derive_new::new;
use fqdn::FQDN;
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display, IntoStaticStr};

use crate::traits::time::UtcTimestamp;

/// Represents different types of domain certificate tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum TaskKind {
    /// Initial certificate issuance for a new domain
    Issue,
    /// Certificate renewal for an existing domain
    Renew,
    /// Update domain configuration if canister ID changes
    Update,
    /// Delete domain and revoke its certificate
    Delete,
}

/// A task submitted by user for further scheduling and execution.
#[derive(Debug, Clone, PartialEq, Eq, new)]
pub struct InputTask {
    /// The type of task to perform
    pub kind: TaskKind,
    /// The domain to process
    pub domain: FQDN,
}

/// Scheduled task that is ready for execution by a worker.
#[derive(Debug, Clone, PartialEq, Eq, new)]
pub struct ScheduledTask {
    /// The type of task to perform
    pub kind: TaskKind,
    /// The domain to process
    pub domain: FQDN,
    /// Unique task identifier (timestamp)
    pub task_id: UtcTimestamp,
    /// Existing certificate data (for renewal/deletion tasks)
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
    /// The domain that was processed
    pub domain: FQDN,
    /// Task output if successful
    pub output: Option<TaskOutput>,
    /// Failure reason if unsuccessful
    pub failure: Option<TaskFailReason>,
    /// Unique task identifier
    pub task_id: UtcTimestamp,
    /// Time taken to execute the task
    pub duration: Duration,
}

impl TaskResult {
    /// Creates a successful task result.
    pub fn success(domain: FQDN, output: TaskOutput, task_id: UtcTimestamp) -> Self {
        Self {
            domain,
            output: Some(output),
            failure: None,
            task_id,
            duration: Duration::ZERO,
        }
    }

    /// Creates a failed task result.
    pub fn failure(domain: FQDN, failure: TaskFailReason, task_id: UtcTimestamp) -> Self {
        Self {
            domain,
            output: None,
            failure: Some(failure),
            task_id,
            duration: Duration::ZERO,
        }
    }
}

impl TaskResult {
    /// Sets the duration for this task result.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }
}

/// Output data from successful task execution.
#[derive(Debug, Clone)]
pub enum TaskOutput {
    /// Certificate issuance output containing cert, key, and validity info
    Issue(IssueCertificateOutput),
    /// Domain update output containing the new canister ID
    Update(Principal),
    /// Domain deletion output (no additional data)
    Delete,
}

// The `to_string()` output is user-facing.
// Only validation failures are actionable by the user.
// All other errors suggest retrying or contacting support.
// TODO: add request_id to the body? (should be already in the header once intergrated into ic-gateway)
#[derive(Debug, Serialize, Deserialize, Clone, Display, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum TaskFailReason {
    /// Domain validation failed with a specific error message
    #[strum(to_string = "Validation failed: {0}. Please review your settings and try again.")]
    ValidationFailed(String),
    /// Task execution exceeded the allowed time limit
    #[strum(to_string = "An unexpected error occurred. Please try again later or contact support")]
    Timeout { duration_secs: u64 },
    /// Generic failure with error details
    #[strum(to_string = "An unexpected error occurred. Please try again later or contact support")]
    GenericFailure(String),
}

/// Output from successful certificate issuance containing all certificate data.
#[derive(Debug, Clone, new)]
pub struct IssueCertificateOutput {
    /// The canister ID this certificate is issued for
    pub canister_id: Principal,
    /// The PEM-encoded certificate chain
    pub certificate: Vec<u8>,
    /// The PEM-encoded private key
    pub private_key: Vec<u8>,
    /// Certificate validity start time (Unix timestamp)
    pub not_before: UtcTimestamp,
    /// Certificate validity end time (Unix timestamp)
    pub not_after: UtcTimestamp,
}

impl From<ApiTaskKind> for TaskKind {
    fn from(task_kind: ApiTaskKind) -> Self {
        match task_kind {
            ApiTaskKind::Issue => TaskKind::Issue,
            ApiTaskKind::Renew => TaskKind::Renew,
            ApiTaskKind::Update => TaskKind::Update,
            ApiTaskKind::Delete => TaskKind::Delete,
        }
    }
}

impl TryFrom<ApiScheduledTask> for ScheduledTask {
    type Error = anyhow::Error;

    fn try_from(api_task: ApiScheduledTask) -> Result<Self, Self::Error> {
        Ok(ScheduledTask {
            kind: api_task.kind.into(),
            domain: FQDN::from_str(&api_task.domain)?,
            task_id: api_task.id,
            certificate: api_task.certificate,
        })
    }
}

impl From<InputTask> for ApiInputTask {
    fn from(task: InputTask) -> Self {
        ApiInputTask {
            kind: task.kind.into(),
            domain: task.domain.to_string(),
        }
    }
}

impl From<TaskKind> for ApiTaskKind {
    fn from(task_kind: TaskKind) -> Self {
        match task_kind {
            TaskKind::Issue => ApiTaskKind::Issue,
            TaskKind::Renew => ApiTaskKind::Renew,
            TaskKind::Update => ApiTaskKind::Update,
            TaskKind::Delete => ApiTaskKind::Delete,
        }
    }
}

impl From<TaskOutput> for ApiTaskOutput {
    fn from(output: TaskOutput) -> Self {
        match output {
            TaskOutput::Issue(issue_output) => ApiTaskOutput::Issue(issue_output.into()),
            TaskOutput::Update(principal) => ApiTaskOutput::Update(principal),
            TaskOutput::Delete => ApiTaskOutput::Delete,
        }
    }
}

impl From<IssueCertificateOutput> for ApiIssueCertificateOutput {
    fn from(output: IssueCertificateOutput) -> Self {
        ApiIssueCertificateOutput {
            canister_id: output.canister_id,
            certificate: output.certificate,
            private_key: output.private_key,
            not_before: output.not_before,
            not_after: output.not_after,
        }
    }
}

impl From<TaskResult> for ApiTaskResult {
    fn from(task_result: TaskResult) -> Self {
        ApiTaskResult {
            domain: task_result.domain.to_string(),
            output: task_result.output.map(ApiTaskOutput::from),
            failure: task_result.failure.map(ApiTaskFailReason::from),
            task_id: task_result.task_id,
            duration_secs: task_result.duration.as_secs(),
        }
    }
}

impl From<TaskFailReason> for ApiTaskFailReason {
    fn from(failure: TaskFailReason) -> Self {
        match failure {
            TaskFailReason::ValidationFailed(reason) => ApiTaskFailReason::ValidationFailed(reason),
            TaskFailReason::Timeout { duration_secs } => {
                ApiTaskFailReason::Timeout { duration_secs }
            }
            TaskFailReason::GenericFailure(reason) => ApiTaskFailReason::GenericFailure(reason),
        }
    }
}
