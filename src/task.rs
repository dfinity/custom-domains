use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use strum::{self, Display, EnumIter, EnumString};

use crate::time::Timestamp;

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
    pub id: Timestamp,
    pub certificate: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskStatus {
    Succeeded,
    Failed,
}

/// The result of task execution submitted by a worker back to the repository.
///
/// Contains all necessary information about task completion: status, outputs, etc.
#[derive(Debug, Clone, new)]
pub struct TaskResult {
    pub domain: FQDN,
    pub status: TaskStatus,
    pub output: TaskOutput,
    pub task_id: Timestamp,
}

#[derive(Debug, Clone)]
pub enum TaskOutput {
    Issue(IssueCertificateOutput),
    Update(Principal),
    Delete,
}

#[derive(Debug, Clone, new)]
pub struct IssueCertificateOutput {
    pub canister_id: Principal,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}
