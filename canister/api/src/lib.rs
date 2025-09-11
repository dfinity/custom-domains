//! # Custom Domains Canister API
//!
//! This module defines the public API types and interfaces for the custom domains management canister.
//! All types implement [`CandidType`] for integration with candid interface.

use std::time::Duration;

use candid::{CandidType, Principal};
use derive_new::new;
use serde::{Deserialize, Serialize};
use strum::{EnumIter, IntoStaticStr};
use thiserror::Error;

type TaskId = u64;
type Timestamp = u64;

// Declare constants related to the canister here, enabling usage in other modules and tests.

// Certificate renewal should be attempted when this fraction of the validity period has elapsed
pub const CERTIFICATE_VALIDITY_FRACTION: f64 = 0.66;

// A domain is considered close to certificate expiration if less than this fraction of its validity period remains
pub const CERT_EXPIRATION_ALERT_THRESHOLD: f64 = 0.2;

// Task is considered timed out, if its result isn't submitted within this time window.
// This allows the task to be rescheduled if a worker fails.
// Submitting results for timed out tasks results in a NonExistingTaskSubmitted error.
pub const TASK_TIMEOUT: Duration = Duration::from_secs(10 * 60);

// If no certificate has been issued, the domain entry is removed after this duration.
pub const UNREGISTERED_DOMAIN_EXPIRATION_TIME: Duration = Duration::from_secs(24 * 60 * 60);

// If a task fails this many times with a recoverable error, it is no longer rescheduled.
// User is expected to resubmit the task.
pub const MAX_TASK_FAILURES: u32 = 20;

// If a task fails, it will not be rescheduled earlier than this interval.
pub const MIN_TASK_RETRY_DELAY: Duration = Duration::from_secs(30);

// Default number of domains returned per page when no limit is specified or limit is zero
pub const DEFAULT_PAGE_LIMIT: u32 = 100;

// Maximum number of domains that can be returned in a single page to safely stay lower than 2MB response
pub const MAX_PAGE_LIMIT: u32 = 400;

// Interval for purging stale, unregistered domains
pub const STALE_DOMAINS_CLEANUP_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);

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

#[derive(
    CandidType, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash, IntoStaticStr,
)]
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
    pub enc_cert: Option<Vec<u8>>,
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
    pub enc_cert: Vec<u8>,
    pub enc_priv_key: Vec<u8>,
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq, Error, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum TaskFailReason {
    #[error("validation_failed: {0}")]
    ValidationFailed(String),
    #[error("timeout after {duration_secs}s")]
    Timeout { duration_secs: Timestamp },
    #[error("rate_limited")]
    RateLimited,
    #[error("generic_failure: {0}")]
    GenericFailure(String),
}

#[derive(CandidType, Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct DomainStatus {
    pub domain: String,
    pub canister_id: Option<Principal>,
    pub status: RegistrationStatus,
}

#[derive(
    CandidType, Clone, Deserialize, Serialize, Debug, EnumIter, IntoStaticStr, PartialEq, Eq,
)]
#[strum(serialize_all = "snake_case")]
pub enum RegistrationStatus {
    /// The registration is currently being processed
    Registering,
    /// The domain has been successfully registered and has a valid certificate
    Registered,
    /// The domain registration has expired
    Expired,
    /// The registration failed with an error message
    Failed(String),
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
    pub enc_cert: Vec<u8>,
    pub enc_priv_key: Vec<u8>,
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub enum GetLastChangeTimeError {
    Unauthorized,
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, IntoStaticStr, Error)]
#[strum(serialize_all = "snake_case")]
pub enum FetchTaskError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, Error)]
pub enum GetDomainStatusError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone)]
pub enum ListCertificatesPageError {
    Unauthorized,
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, IntoStaticStr, Error, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
pub enum SubmitTaskError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Domain not found: {0}")]
    DomainNotFound(String),
    #[error("A non-existing task was submitted: {0}")]
    NonExistingTaskSubmitted(TaskId),
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Error)]
pub enum HasNextTaskError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, IntoStaticStr, Error)]
#[strum(serialize_all = "snake_case")]
pub enum TryAddTaskError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Domain not found: {0}")]
    DomainNotFound(String),
    #[error("Another task is already in progress for domain: {0}")]
    AnotherTaskInProgress(String),
    #[error("Certificate already issued for domain: {0}")]
    CertificateAlreadyIssued(String),
    #[error("Update requires an exisiting certificate: {0}")]
    MissingCertificateForUpdate(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}
