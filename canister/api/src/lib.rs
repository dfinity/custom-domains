//! # Custom Domains Canister API
//!
//! This module defines the public API types and interfaces for the custom domains management canister.
//! All types implement [`CandidType`] for integration with candid interface.

use candid::{CandidType, Principal};
use derive_new::new;
use serde::{Deserialize, Serialize};
use strum::IntoStaticStr;

type TaskId = u64;
type Timestamp = u64;

pub type FetchTaskResult = Result<Option<ScheduledTask>, FetchTaskError>;
pub type SubmitTaskResult = Result<(), SubmitTaskError>;
pub type TryAddTaskResult = Result<(), TryAddTaskError>;
pub type GetDomainStatusResult = Result<Option<DomainStatus>, GetDomainStatusError>;
pub type GetLastChangeTimeResult = Result<Timestamp, GetLastChangeTimeError>;
pub type ListCertificatesPageResult = Result<CertificatesPage, ListCertificatesPageError>;
pub type HasNextTaskResult = Result<bool, HasNextTaskError>;

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct InitArg {
    pub authorized_principal: Option<Principal>,
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
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
    pub task_kind: TaskKind,
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

#[derive(CandidType, Clone, Deserialize, Serialize, Debug)]
pub struct CertificatesPage {
    pub items: Vec<RegisteredDomain>,
    pub next_key: Option<String>,
}

impl CertificatesPage {
    pub fn new(items: Vec<RegisteredDomain>, next_key: Option<String>) -> Self {
        Self { items, next_key }
    }
}

#[derive(CandidType, Clone, Deserialize, Serialize, Debug)]
pub struct ListCertificatesPageInput {
    /// Optional starting point for pagination (domain name to start from)
    pub start_key: Option<String>,
    /// Maximum number of items to return per page
    pub limit: Option<u32>,
}

impl ListCertificatesPageInput {
    pub fn new() -> Self {
        Self {
            start_key: None,
            limit: None,
        }
    }
}

impl Default for ListCertificatesPageInput {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(CandidType, Clone, Deserialize, Serialize, Debug)]
pub struct RegisteredDomain {
    pub domain: String,
    pub canister_id: Principal,
    pub cert_encrypted: Vec<u8>,
    pub priv_key_encrypted: Vec<u8>,
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub enum GetLastChangeTimeError {
    Unauthorized,
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum FetchTaskError {
    Unauthorized,
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub enum GetDomainStatusError {
    Unauthorized,
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub enum ListCertificatesPageError {
    Unauthorized,
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum SubmitTaskError {
    Unauthorized,
    DomainNotFound(String),
    NonExistingTaskSubmitted(TaskId),
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub enum HasNextTaskError {
    Unauthorized,
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum TryAddTaskError {
    Unauthorized,
    DomainNotFound(String),
    AnotherTaskInProgress(String),
    CertificateAlreadyIssued(String),
    MissingCertificateForUpdate(String),
    InternalError(String),
}
