//! # Custom Domains Canister API
//!
//! This module defines the public API types and interfaces for the custom domains management canister.
//! All types implement [`CandidType`] for integration with candid interface.

use candid::{CandidType, Principal};
use derive_new::new;
use serde::{Deserialize, Serialize};

type TaskId = u64;
type Timestamp = u64;

pub type FetchTaskResult = Result<Option<ScheduledTask>, FetchTaskError>;
pub type SubmitTaskResult = Result<(), SubmitTaskError>;
pub type TryAddTaskResult = Result<(), TryAddTaskError>;
pub type GetDomainStatusResult = Result<Option<DomainStatus>, GetDomainStatusError>;

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    Issue,
    Renew,
    Update,
    Delete,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct InputTask {
    pub kind: TaskKind,
    pub domain: String,
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, new)]
pub struct ScheduledTask {
    pub kind: TaskKind,
    pub domain: String,
    pub id: TaskId,
    pub certificate: Option<Vec<u8>>,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct TaskResult {
    pub domain: String,
    pub output: Option<TaskOutput>,
    pub failure: Option<TaskFailReason>,
    pub task_id: TaskId,
    pub duration_secs: Timestamp,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub enum TaskOutput {
    Issue(IssueCertificateOutput),
    Update(Principal),
    Delete,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct IssueCertificateOutput {
    pub canister_id: Principal,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub enum TaskFailReason {
    ValidationFailed(String),
    Timeout { duration_secs: Timestamp },
    GenericFailure(String),
}

#[derive(CandidType, Clone, Deserialize, Serialize, Debug)]
pub struct DomainStatus {
    pub domain: String,
    pub canister_id: Option<Principal>,
    pub status: RegistrationStatus,
}

#[derive(CandidType, Clone, Deserialize, Serialize, Debug)]
pub enum RegistrationStatus {
    Processing,
    Registered,
    Failure(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub enum FetchTaskError {
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub enum GetDomainStatusError {
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub enum SubmitTaskError {
    DomainNotFound(String),
    NonExistingTaskSubmitted(TaskId),
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub enum TryAddTaskError {
    DomainNotFound(String),
    AnotherTaskInProgress(String),
    CertificateAlreadyIssued(String),
    MissingCertificateForUpdate(String),
    InternalError(String),
}
