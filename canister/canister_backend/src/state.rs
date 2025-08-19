use candid::Principal;
use canister_api::{
    CertificatesPage, DomainStatus, FetchTaskResult, GetDomainStatusResult,
    GetLastChangeTimeResult, HasNextTaskResult, InputTask, ListCertificatesPageInput,
    ListCertificatesPageResult, RegisteredDomain, RegistrationStatus, ScheduledTask,
    SubmitTaskError, SubmitTaskResult, TaskFailReason, TaskKind, TaskOutput, TaskResult,
    TryAddTaskError, TryAddTaskResult,
};
use ic_stable_structures::{
    memory_manager::VirtualMemory, storable::Bound, DefaultMemoryImpl, StableBTreeMap, StableCell,
    Storable,
};
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};
use std::{borrow::Cow, ops::Bound as RangeBound, time::Duration};

use crate::{
    get_time_secs,
    metrics::{
        update_metrics, MetricsName, FAILURE_STATUS, FETCH_NEXT_TASK_FUNC, SUBMIT_TASK_RESULT_FUNC,
        SUCCESS_STATUS, TRY_ADD_TASK_FUNC,
    },
    storage::STATE,
};

pub type UtcTimestamp = u64;

// The certificate renewal task is initiated this far ahead of the expiration
const CERT_RENEWAL_BEFORE_EXPIRY: Duration = Duration::from_secs(30 * 24 * 60 * 60);

// Task is considered timed out, if its result isn't submitted within this time window.
// This allows the task to be rescheduled if a worker fails.
// Submitting results for timed out tasks results in a NonExistingTaskSubmitted error.
const TASK_TIMEOUT: Duration = Duration::from_secs(10 * 60);

// If no certificate has been issued, the domain entry is removed after this duration.
const UNREGISTERED_DOMAIN_EXPIRATION_TIME: Duration = Duration::from_secs(24 * 60 * 60);

// If a task fails this many times with a recoverable error, it is no longer rescheduled.
// User is expected to resubmit the task.
const MAX_TASK_FAILURES: u32 = 20;

// If a task fails, it will not be rescheduled earlier than this interval.
const MIN_TASK_RETRY_DELAY: Duration = Duration::from_secs(30);

// Default number of domains returned per page when no limit is specified or limit is zero
const DEFAULT_PAGE_LIMIT: u32 = 100;
// Maximum number of domains that can be returned in a single page to safely stay lower than 2MB response
const MAX_PAGE_LIMIT: u32 = 400;

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

impl CanisterState {
    // Processes all domains and returns true if next task exists.
    pub fn has_next_task(&self, now: UtcTimestamp) -> HasNextTaskResult {
        let has_task = self
            .domains
            .values()
            .any(|entry| has_pending_task(&entry, now).is_some());

        Ok(has_task)
    }

    pub fn fetch_next_task_with_metrics(&mut self, now: UtcTimestamp) -> FetchTaskResult {
        let result = self.fetch_next_task(now);

        // Update metrics based on result
        let (status, error, task_kind) = match &result {
            Ok(Some(task)) => (SUCCESS_STATUS, "", task.kind.into()),
            Ok(None) => (SUCCESS_STATUS, "", ""),
            Err(err) => (FAILURE_STATUS, err.into(), ""),
        };

        update_metrics(
            MetricsName::CanisterApiCalls,
            &[FETCH_NEXT_TASK_FUNC, status, task_kind, error],
            None,
        );

        result
    }

    pub fn fetch_next_task(&mut self, now: UtcTimestamp) -> FetchTaskResult {
        // TODO: consider adding randomization to task selection
        // Iterate through domains and find the first one with a pending task
        for entry in self.domains.iter() {
            let domain = entry.key().clone();
            let mut domain_entry = entry.value();

            // Schedule only the first available pending task
            if let Some(task_kind) = has_pending_task(&domain_entry, now) {
                domain_entry.taken_at = Some(now);
                domain_entry.task = Some(task_kind);
                let scheduled_task = Some(ScheduledTask::new(
                    task_kind,
                    domain.clone(),
                    now,
                    domain_entry.certificate.clone(),
                ));
                // Update the domain entry
                self.domains.insert(domain, domain_entry);
                return Ok(scheduled_task);
            }
        }

        Ok(None)
    }

    pub fn get_domain_status(&self, domain: String) -> GetDomainStatusResult {
        let entry = match self.domains.get(&domain) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let status = if entry.task.is_none() && entry.certificate.is_some() {
            RegistrationStatus::Registered
        } else if entry.task.is_some() {
            RegistrationStatus::Processing
        } else {
            RegistrationStatus::Failure(
                entry
                    .last_failure_reason
                    .clone()
                    .map_or("".to_string(), |err| format!("{err:?}")),
            )
        };

        let domain_status = DomainStatus {
            domain: domain.clone(),
            canister_id: entry.canister_id,
            status,
        };

        Ok(Some(domain_status))
    }

    // Removes unregistered domains that have been in the system for too long
    pub fn cleanup_stale_domains(&mut self, now: UtcTimestamp) {
        let mut domains_to_remove = Vec::new();

        for entry in self.domains.iter() {
            let domain = entry.key().clone();
            let domain_entry = entry.value();

            // Remove domain if unregistered too long
            if should_remove_unregistered_domain(&domain_entry, now) {
                domains_to_remove.push(domain);
            }
        }

        // Remove expired/unregistered domains
        for domain in domains_to_remove {
            self.domains.remove(&domain);
        }
    }

    pub fn try_add_task_with_metrics(
        &mut self,
        task: InputTask,
        now: UtcTimestamp,
    ) -> TryAddTaskResult {
        let task_kind: &'static str = task.kind.into();
        let result = self.try_add_task(task, now);

        // Update metrics based on result
        let (status, error) = match &result {
            Ok(()) => (SUCCESS_STATUS, ""),
            Err(err) => (FAILURE_STATUS, err.into()),
        };

        update_metrics(
            MetricsName::CanisterApiCalls,
            &[TRY_ADD_TASK_FUNC, status, task_kind, error],
            None,
        );

        result
    }

    fn try_add_task(&mut self, task: InputTask, now: UtcTimestamp) -> TryAddTaskResult {
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

        // Upsert the domain entry
        self.domains.insert(domain, domain_entry);

        Ok(())
    }

    pub fn submit_task_result_with_metrics(
        &mut self,
        task_result: TaskResult,
        now: UtcTimestamp,
    ) -> SubmitTaskResult {
        let task_kind: &'static str = task_result.task_kind.into();
        let result = self.submit_task_result(task_result, now);

        // Update metrics based on result
        let (status, error, task_kind) = match &result {
            Ok(()) => (SUCCESS_STATUS, "", task_kind),
            Err(err) => (FAILURE_STATUS, err.into(), task_kind),
        };

        update_metrics(
            MetricsName::CanisterApiCalls,
            &[SUBMIT_TASK_RESULT_FUNC, status, task_kind, error],
            None,
        );

        result
    }

    pub fn submit_task_result(
        &mut self,
        task_result: TaskResult,
        now: UtcTimestamp,
    ) -> SubmitTaskResult {
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

            // Delete the task if the retry limit is reached
            if entry.failures_count >= MAX_TASK_FAILURES {
                entry.task = None;
            }
        }

        // Update the domain entry
        self.domains.insert(domain.to_string(), entry);

        Ok(())
    }

    pub fn get_last_change_time(&self) -> GetLastChangeTimeResult {
        Ok(*self.last_change.get())
    }

    pub fn list_certificates_page(
        &self,
        input: ListCertificatesPageInput,
    ) -> ListCertificatesPageResult {
        let limit = input
            .limit
            .filter(|&lim| lim > 0)
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .min(MAX_PAGE_LIMIT) as usize;

        let mut registered_domains = Vec::with_capacity(limit);
        let mut next_key = None;

        let domains_iter = match &input.start_key {
            Some(start_key) => self
                .domains
                .range((RangeBound::Included(start_key), RangeBound::Unbounded)),
            None => self.domains.range(..),
        };

        let mut count = 0;

        for entry in domains_iter {
            let domain = entry.key();
            let domain_entry = entry.value();

            // Only include domains with issued certificates and existing canister_id
            if let (Some(cert), Some(private_key), Some(canister_id)) = (
                &domain_entry.certificate,
                &domain_entry.private_key,
                &domain_entry.canister_id,
            ) {
                if count >= limit {
                    next_key = Some(domain.clone());
                    break;
                }

                registered_domains.push(RegisteredDomain {
                    domain: domain.clone(),
                    canister_id: *canister_id,
                    cert_encrypted: cert.clone(),
                    priv_key_encrypted: private_key.clone(),
                });

                count += 1;
            }
        }

        let page = CertificatesPage::new(registered_domains, next_key);

        Ok(page)
    }
}

impl CanisterState {
    /// Creates a new CanisterState with optionally pre-populated domains for testing
    pub fn new_with_sample_domains(num_domains: usize, cert_size_bytes: usize) -> Self {
        use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};

        let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
        let domains_memory = memory_manager.get(MemoryId::new(0));
        let last_change_memory = memory_manager.get(MemoryId::new(1));

        let domains = StableBTreeMap::init(domains_memory);
        let last_change = StableCell::init(last_change_memory, 1);

        let mut state = Self {
            domains,
            last_change,
        };

        // Some sample canister IDs
        let sample_canister_ids = [
            Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap(),
            Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap(),
            Principal::from_text("rno2w-sqaaa-aaaaa-aaacq-cai").unwrap(),
            Principal::from_text("renrk-eyaaa-aaaaa-aaada-cai").unwrap(),
            Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap(),
        ];

        for i in 0..num_domains {
            let domain = format!("domain_{i}.example.com");
            let canister_id = sample_canister_ids[i % sample_canister_ids.len()];

            let mut domain_entry = DomainEntry::new(None, i as u64);
            domain_entry.canister_id = Some(canister_id);

            // Generate certificate data of specified size
            let cert_data = {
                let base_cert = format!("-----BEGIN CERTIFICATE-----\ncert_data_{}\n", i + 1);
                let padding = "X".repeat(cert_size_bytes);
                format!("{base_cert}{padding}-----END CERTIFICATE-----")
            };

            // Generate private key data
            let key_data = format!("key_data_{}", i + 1);

            let now = get_time_secs();
            domain_entry.certificate = Some(cert_data.into_bytes());
            domain_entry.private_key = Some(key_data.into_bytes());
            domain_entry.not_before = Some(now);
            domain_entry.not_after = Some(now + 30 * 24 * 60 * 60);

            state.domains.insert(domain, domain_entry);
        }

        state
    }
}

/// Check if the domain has remained unregistered too long since creation
fn should_remove_unregistered_domain(entry: &DomainEntry, now: UtcTimestamp) -> bool {
    // If the domain has a certificate or a pending task, it should not be removed
    if entry.certificate.is_some() || entry.task.is_some() {
        return false;
    }

    let expiry_time = entry
        .created_at
        .saturating_add(UNREGISTERED_DOMAIN_EXPIRATION_TIME.as_secs());

    now >= expiry_time
}

fn has_pending_task(entry: &DomainEntry, now: UtcTimestamp) -> Option<TaskKind> {
    if let Some(task) = entry.task {
        if let Some(taken_at) = entry.taken_at {
            // Reclaim task if it has been running longer than timeout
            let expiry_time = taken_at.saturating_add(TASK_TIMEOUT.as_secs());
            if now >= expiry_time {
                return Some(task);
            }
        } else if let Some(last_fail_time) = entry.last_fail_time {
            // Retry a previously failed task after delay has elapsed
            let next_allowed = last_fail_time.saturating_add(MIN_TASK_RETRY_DELAY.as_secs());
            if now >= next_allowed {
                return Some(task);
            }
        } else {
            // Task is new and has not been taken or failed, schedule it
            return Some(task);
        }
    } else if let Some(not_after) = entry.not_after {
        // Schedule certificate renewal if time has come
        let renewal_time = not_after.saturating_sub(CERT_RENEWAL_BEFORE_EXPIRY.as_secs());
        if now >= renewal_time {
            return Some(TaskKind::Renew);
        }
    }

    None
}

pub fn with_state<R>(f: impl FnOnce(&CanisterState) -> R) -> R {
    STATE.with(|s| f(&s.borrow()))
}

pub fn with_state_mut<R>(f: impl FnOnce(&mut CanisterState) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Principal;
    use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};

    /// Create a test CanisterState with sample data
    fn create_test_state() -> CanisterState {
        let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
        let domains_memory = memory_manager.get(MemoryId::new(0));
        let last_change_memory = memory_manager.get(MemoryId::new(1));

        let domains = StableBTreeMap::init(domains_memory);
        let last_change = StableCell::init(last_change_memory, 0);

        let mut state = CanisterState {
            domains,
            last_change,
        };

        let canister_id_1 = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
        let canister_id_2 = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
        let canister_id_3 = Principal::from_text("rno2w-sqaaa-aaaaa-aaacq-cai").unwrap();

        // Domain with certificate
        let mut domain1 = DomainEntry::new(None, 1000);
        domain1.canister_id = Some(canister_id_1);
        domain1.certificate = Some(b"cert1_data".to_vec());
        domain1.private_key = Some(b"key1_data".to_vec());
        domain1.not_before = Some(1500);
        domain1.not_after = Some(2500);
        state.domains.insert("example.com".to_string(), domain1);

        // Another domain with certificate
        let mut domain2 = DomainEntry::new(None, 1100);
        domain2.canister_id = Some(canister_id_2);
        domain2.certificate = Some(b"cert2_data".to_vec());
        domain2.private_key = Some(b"key2_data".to_vec());
        domain2.not_before = Some(1600);
        domain2.not_after = Some(2600);
        state.domains.insert("test.org".to_string(), domain2);

        // Domain without certificate (should be excluded)
        let domain3 = DomainEntry::new(Some(TaskKind::Issue), 1200);
        state.domains.insert("pending.net".to_string(), domain3);

        // Another domain with certificate
        let mut domain4 = DomainEntry::new(None, 1300);
        domain4.canister_id = Some(canister_id_3);
        domain4.certificate = Some(b"cert3_data".to_vec());
        domain4.private_key = Some(b"key3_data".to_vec());
        domain4.not_before = Some(1700);
        domain4.not_after = Some(2700);
        state.domains.insert("website.io".to_string(), domain4);

        // Domain without certificate (should be excluded)
        let mut domain5 = DomainEntry::new(None, 1400);
        domain5.canister_id = Some(canister_id_1);
        domain5.certificate = None;
        state.domains.insert("incomplete.dev".to_string(), domain5);

        // Another domain with certificate
        let mut domain6 = DomainEntry::new(None, 1300);
        domain6.canister_id = Some(canister_id_2);
        domain6.certificate = Some(b"cert6_data".to_vec());
        domain6.private_key = Some(b"key6_data".to_vec());
        domain6.not_before = Some(1700);
        domain6.not_after = Some(2700);
        state.domains.insert("dfinity.org".to_string(), domain6);

        state
    }

    #[test]
    fn test_list_certificates_page_basic_functionality() {
        let state = create_test_state();

        let input = ListCertificatesPageInput {
            start_key: None,
            limit: None,
        };
        let result = state.list_certificates_page(input).unwrap();

        // Should return only domains with certificates
        assert_eq!(result.items.len(), 4);

        // Verify the domains are sorted alphabetically
        let domains: Vec<&str> = result.items.iter().map(|d| d.domain.as_str()).collect();
        assert_eq!(
            domains,
            vec!["dfinity.org", "example.com", "test.org", "website.io"]
        );

        let first_domain = &result.items[1];
        assert_eq!(first_domain.domain, "example.com");
        assert_eq!(first_domain.cert_encrypted, b"cert1_data");
        assert_eq!(first_domain.priv_key_encrypted, b"key1_data");
        assert_eq!(
            first_domain.canister_id,
            Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap()
        );
    }

    #[test]
    fn test_list_certificates_page_with_limit() {
        let state = create_test_state();

        let input = ListCertificatesPageInput {
            start_key: None,
            limit: Some(2),
        };
        let result = state.list_certificates_page(input).unwrap();

        // Should return only 2 domains due to limit
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].domain, "dfinity.org");
        assert_eq!(result.items[1].domain, "example.com");

        // Should have next_key for pagination
        assert_eq!(result.next_key, Some("test.org".to_string()));
    }

    #[test]
    fn test_list_certificates_page_pagination_with_start_key() {
        let state = create_test_state();

        let input = ListCertificatesPageInput {
            start_key: Some("test.org".to_string()),
            limit: None,
        };
        let result = state.list_certificates_page(input).unwrap();

        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].domain, "test.org");
        assert_eq!(result.items[1].domain, "website.io");

        // No next key since we've reached the end
        assert_eq!(result.next_key, None);
    }

    #[test]
    fn test_list_certificates_page_pagination_continuation() {
        let state = create_test_state();

        // First page with limit 1
        let input1 = ListCertificatesPageInput {
            start_key: None,
            limit: Some(1),
        };
        let result1 = state.list_certificates_page(input1).unwrap();

        assert_eq!(result1.items.len(), 1);
        assert_eq!(result1.items[0].domain, "dfinity.org");
        assert_eq!(result1.next_key, Some("example.com".to_string()));

        // Second page using next_key and limit 2
        let input2 = ListCertificatesPageInput {
            start_key: result1.next_key,
            limit: Some(2),
        };
        let result2 = state.list_certificates_page(input2).unwrap();

        assert_eq!(result2.items.len(), 2);
        assert_eq!(result2.items[0].domain, "example.com");
        assert_eq!(result2.items[1].domain, "test.org");
        assert_eq!(result2.next_key, Some("website.io".to_string()));

        // Third page using next_key and limit 3
        let input3 = ListCertificatesPageInput {
            start_key: result2.next_key,
            limit: Some(3),
        };
        let result3 = state.list_certificates_page(input3).unwrap();

        assert_eq!(result3.items.len(), 1);
        assert_eq!(result3.items[0].domain, "website.io");
        assert_eq!(result3.next_key, None);
    }

    #[test]
    fn test_list_certificates_page_nonexistent_start_key() {
        let state = create_test_state();

        // Use a start_key that doesn't exist but is lexicographically between domains
        let input = ListCertificatesPageInput {
            start_key: Some("middle.com".to_string()), // Between "example.com" and "test.org"
            limit: None,
        };
        let result = state.list_certificates_page(input).unwrap();

        // Should return domains that come after "middle.com" lexicographically
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].domain, "test.org");
        assert_eq!(result.items[1].domain, "website.io");
    }

    #[test]
    fn test_list_certificates_page_empty_state() {
        let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
        let domains_memory = memory_manager.get(MemoryId::new(0));
        let last_change_memory = memory_manager.get(MemoryId::new(1));

        let domains = StableBTreeMap::init(domains_memory);
        let last_change = StableCell::init(last_change_memory, 0);

        let state = CanisterState {
            domains,
            last_change,
        };

        let input = ListCertificatesPageInput {
            start_key: None,
            limit: None,
        };
        let result = state.list_certificates_page(input).unwrap();

        assert_eq!(result.items.len(), 0);
        assert_eq!(result.next_key, None);
    }

    #[test]
    fn test_list_certificates_page_start_key_at_end() {
        let state = create_test_state();

        // Use the last domain as start_key
        let input = ListCertificatesPageInput {
            start_key: Some("website.io".to_string()),
            limit: None,
        };
        let result = state.list_certificates_page(input).unwrap();

        // Should return this domain only
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.next_key, None);
        assert_eq!(result.items[0].domain, "website.io");
    }
}
