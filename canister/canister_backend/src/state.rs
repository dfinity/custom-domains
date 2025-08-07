use std::{borrow::Cow, time::Duration};

use candid::Principal;
use canister_api::{
    FetchTaskResult, InputTask, ScheduledTask, SubmitTaskError, SubmitTaskResult, TaskFailReason,
    TaskKind, TaskOutput, TaskResult, TryAddTaskError, TryAddTaskResult,
};
use ic_cdk::api::time;
use ic_stable_structures::{
    memory_manager::VirtualMemory, storable::Bound, DefaultMemoryImpl, StableBTreeMap, StableCell,
    Storable,
};
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};

use crate::storage::STATE;

type UtcTimestamp = u64;

// The certificate renewal task is initiated this far ahead of the expiration
const CERT_RENEWAL_BEFORE_EXPIRY: Duration = Duration::from_secs(30 * 24 * 60 * 60);

// The task expires (times out) after this time window if its result isn't submitted.
// This allows the task to be rescheduled if a worker fails.
// Submitting results for expired tasks results in a NonExistingTaskSubmitted error.
const TASK_EXPIRATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

// If no certificate has been issued, the domain entry is removed after this duration.
const UNREGISTERED_DOMAIN_EXPIRATION_TIME: Duration = Duration::from_secs(24 * 60 * 60);

// If a task fails this many times with a recoverable error, it is no longer rescheduled.
// User is expected to resubmit the task.
const MAX_TASK_FAILURES: u32 = 20;

// If a task fails, it will not be rescheduled earlier than this interval.
const MIN_TASK_RETRY_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainEntry {
    pub task: Option<TaskKind>,
    pub last_fail_time: Option<UtcTimestamp>,
    pub last_failure_reason: Option<TaskFailReason>,
    pub failures_count: u32,
    pub canister_id: Option<Principal>,
    pub created_at: UtcTimestamp,
    pub taken_at: Option<UtcTimestamp>,
    pub certificate: Option<Vec<u8>>,
    pub private_key: Option<Vec<u8>>,
    pub not_before: Option<UtcTimestamp>,
    pub not_after: Option<UtcTimestamp>,
}

impl DomainEntry {
    pub fn new(task: Option<TaskKind>, created_at: UtcTimestamp) -> Self {
        Self {
            task,
            created_at,
            ..Default::default()
        }
    }
}

impl Storable for DomainEntry {
    fn to_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("DomainEntry serialization failed"))
    }

    fn into_bytes(self) -> Vec<u8> {
        to_vec(&self).expect("DomainEntry serialization failed")
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("DomainEntry deserialization failed")
    }

    const BOUND: Bound = Bound::Unbounded;
}

pub struct CanisterState {
    pub domains: StableBTreeMap<String, DomainEntry, VirtualMemory<DefaultMemoryImpl>>,
    pub last_change: StableCell<UtcTimestamp, VirtualMemory<DefaultMemoryImpl>>,
}

fn get_time() -> UtcTimestamp {
    time() / 1_000_000_000
}

impl CanisterState {
    pub fn fetch_next_task(&mut self) -> FetchTaskResult {
        let now = get_time();
        let mut domains_to_remove = Vec::new();

        let domains: Vec<_> = self.domains.iter().map(|e| e.key().clone()).collect();

        for domain in domains.iter() {
            let mut entry = self.domains.get(domain).unwrap();
            // Reclaim tasks that have exceeded the timeout period.
            if let Some(taken_at) = entry.taken_at {
                let expiry_time = taken_at.saturating_add(TASK_EXPIRATION_TIMEOUT.as_secs());
                if now >= expiry_time {
                    entry.taken_at = None;
                }
            }

            // Create a renewal task if the certificate is approaching expiration and no task is active.
            if entry.task.is_none() {
                if let Some(not_after) = entry.not_after {
                    if now >= not_after.saturating_sub(CERT_RENEWAL_BEFORE_EXPIRY.as_secs()) {
                        entry.task = Some(TaskKind::Renew);
                    }
                }
            }

            // Remove domains without certificates that have exceeded the retention period,
            // unless a task is currently active
            if entry.taken_at.is_none() && entry.certificate.is_none() {
                let expiry_time = entry
                    .created_at
                    .saturating_add(UNREGISTERED_DOMAIN_EXPIRATION_TIME.as_secs());
                if now >= expiry_time {
                    domains_to_remove.push(domain.clone());
                }
            }
        }

        let mut scheduled_task = None;

        for domain in domains.iter() {
            let mut entry = self.domains.get(domain).unwrap();

            // Skip if there's no task or it is already taken.
            let task_kind = match &entry.task {
                Some(task) if entry.taken_at.is_none() => task,
                _ => continue,
            };

            // Skip if the task can't be retried now.
            if let Some(last_fail) = entry.last_fail_time {
                let next_allowed = last_fail.saturating_add(MIN_TASK_RETRY_DELAY.as_secs());
                if now < next_allowed {
                    continue;
                }
            }

            // mark the task as taken
            entry.taken_at = Some(now);
            self.domains.insert(domain.clone(), entry.clone());

            let certificate = match task_kind {
                TaskKind::Delete => entry.certificate.clone(),
                _ => None,
            };

            scheduled_task = Some(ScheduledTask::new(
                *task_kind,
                domain.clone(),
                now,
                certificate,
            ));
        }

        // Remove expired domains
        for domain in domains_to_remove {
            self.domains.remove(&domain);
        }

        Ok(scheduled_task)
    }

    pub fn try_add_task(&mut self, task: InputTask) -> TryAddTaskResult {
        let now = get_time();

        let domain = task.domain;
        let domain_entry = match self.domains.get(&domain) {
            Some(mut entry) => {
                // Prevent scheduling concurrent tasks for domain
                if entry.task.is_some() {
                    return Err(TryAddTaskError::AnotherTaskInProgress(domain));
                }

                // Prevent explicit certificate re-issuance
                // TODO: maybe useful functionality for the admin?
                if task.kind == TaskKind::Issue && entry.certificate.is_some() {
                    return Err(TryAddTaskError::CertificateAlreadyIssued(domain));
                }

                // Require an existing certificate for `Update` task
                if task.kind == TaskKind::Update && entry.certificate.is_none() {
                    return Err(TryAddTaskError::MissingCertificateForUpdate(domain));
                }

                // Set the task field
                entry.task = Some(task.kind);

                entry
            }
            None => {
                // Only `Issue` task can create new domain entry
                if task.kind != TaskKind::Issue {
                    return Err(TryAddTaskError::DomainNotFound(domain));
                }

                DomainEntry::new(Some(task.kind), now)
            }
        };

        // Insert new domain entry
        self.domains.insert(domain, domain_entry);

        Ok(())
    }

    pub fn submit_task_result(&mut self, task_result: TaskResult) -> SubmitTaskResult {
        let now = get_time();
        let domain = task_result.domain.clone();
        let task_id = task_result.task_id;

        let mut entry = self
            .domains
            .get(&domain)
            .ok_or_else(|| SubmitTaskError::DomainNotFound(domain.clone()))?;

        // Validate task ID matches `taken_at` (checking `task_kind` is optional)
        if entry.taken_at != Some(task_id) {
            return Err(SubmitTaskError::NonExistingTaskSubmitted(task_id));
        }

        // Handle task result based on the output or failure
        if let Some(output) = task_result.output {
            // Unset fields in case of task success
            entry.task = None;
            entry.taken_at = None;
            entry.last_failure_reason = None;
            entry.failures_count = 0;
            entry.last_fail_time = None;
            self.last_change.set(now);

            match output {
                TaskOutput::Issue(output) => {
                    entry.canister_id = Some(output.canister_id);
                    entry.certificate = Some(output.certificate);
                    entry.private_key = Some(output.private_key);
                    entry.not_before = Some(output.not_before);
                    entry.not_after = Some(output.not_after);
                }
                TaskOutput::Delete => {
                    self.domains.remove(&domain);
                    return Ok(());
                }
                TaskOutput::Update(canister_id) => {
                    entry.canister_id = Some(canister_id);
                }
            }
        } else if let Some(failure) = task_result.failure {
            entry.failures_count += 1;
            entry.last_failure_reason = Some(failure);
            entry.taken_at = None;
            entry.last_fail_time = Some(now);
            // delete the task if the retry limit is reached
            if entry.failures_count >= MAX_TASK_FAILURES {
                entry.task = None;
            }
        }

        self.domains.insert(domain.to_string(), entry);

        Ok(())
    }
}

pub fn with_state<R>(f: impl FnOnce(&CanisterState) -> R) -> R {
    STATE.with(|s| f(&s.borrow()))
}

pub fn with_state_mut<R>(f: impl FnOnce(&mut CanisterState) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}
