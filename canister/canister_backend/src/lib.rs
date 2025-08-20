use std::time::Duration;

use canister_api::{
    FetchTaskError, FetchTaskResult, GetDomainStatusError, GetDomainStatusResult,
    GetLastChangeTimeError, GetLastChangeTimeResult, HasNextTaskError, HasNextTaskResult, InitArg,
    InputTask, ListCertificatesPageError, ListCertificatesPageInput, ListCertificatesPageResult,
    SubmitTaskError, SubmitTaskResult, TaskResult, TryAddTaskError, TryAddTaskResult,
};
use ic_cdk::{
    api::{call::accept_message, time},
    caller, init, inspect_message, post_upgrade, query, trap, update,
};
use ic_cdk_timers::set_timer_interval;
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};

use crate::{
    metrics::{export_metrics_as_http_response, METRICS},
    state::{with_state, with_state_mut, UtcTimestamp},
    storage::AUTHORIZED_PRINCIPAL,
};

pub mod metrics;
pub mod state;
pub mod storage;

// Interval for purging stale, unregistered domains
const STALE_DOMAINS_CLEANUP_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);

// Inspect ingress messages in the pre-consensus phase and reject early, if the caller is unauthorized
#[inspect_message]
fn inspect_message() {
    if let Some(authorized_principal) = AUTHORIZED_PRINCIPAL.with(|p| *p.borrow()) {
        if authorized_principal != caller() {
            trap("message_inspection_failed: unauthorized call");
        }
    }
    accept_message()
}

pub fn get_time_secs() -> UtcTimestamp {
    time() / 1_000_000_000
}

fn validate_caller<T>(unauthorized_error: T) -> Result<(), T> {
    if let Some(authorized_principal) = AUTHORIZED_PRINCIPAL.with(|p| *p.borrow()) {
        if authorized_principal != caller() {
            return Err(unauthorized_error);
        }
    }
    Ok(())
}

#[init]
fn init(init_arg: InitArg) {
    // Initialize the authorized principal
    AUTHORIZED_PRINCIPAL.with(|p| *p.borrow_mut() = init_arg.authorized_principal);

    set_timer_interval(STALE_DOMAINS_CLEANUP_INTERVAL, move || {
        let now = get_time_secs();
        with_state_mut(|state| state.cleanup_stale_domains(now));
    });

    METRICS.with(|cell| {
        let metrics = cell.borrow();
        metrics.last_upgrade_time.set(get_time_secs() as i64);
    });
}

// Run every time a canister is upgraded
#[post_upgrade]
fn post_upgrade(init_arg: InitArg) {
    // Run the same initialization logic
    init(init_arg);
}

#[query]
async fn get_domain_status(domain: String) -> GetDomainStatusResult {
    validate_caller(GetDomainStatusError::Unauthorized)?;
    let now = get_time_secs();
    with_state(|state| state.get_domain_status(domain, now))
}

#[query]
async fn has_next_task() -> HasNextTaskResult {
    validate_caller(HasNextTaskError::Unauthorized)?;
    let now = get_time_secs();
    with_state(|state| state.has_next_task(now))
}

#[update]
async fn fetch_next_task() -> FetchTaskResult {
    validate_caller(FetchTaskError::Unauthorized)?;
    let now = get_time_secs();
    with_state_mut(|state| state.fetch_next_task_with_metrics(now))
}

#[update]
async fn submit_task_result(result: TaskResult) -> SubmitTaskResult {
    validate_caller(SubmitTaskError::Unauthorized)?;
    let now = get_time_secs();
    with_state_mut(|state| state.submit_task_result_with_metrics(result, now))
}

#[update]
async fn try_add_task(task: InputTask) -> TryAddTaskResult {
    validate_caller(TryAddTaskError::Unauthorized)?;
    let now = get_time_secs();
    with_state_mut(|state| state.try_add_task_with_metrics(task, now))
}

#[query]
async fn get_last_change_time() -> GetLastChangeTimeResult {
    validate_caller(GetLastChangeTimeError::Unauthorized)?;
    with_state(|state| state.get_last_change_time())
}

#[query]
async fn list_certificates_page(input: ListCertificatesPageInput) -> ListCertificatesPageResult {
    validate_caller(ListCertificatesPageError::Unauthorized)?;
    with_state(|state| state.list_certificates_page(input))
}

#[query(decoding_quota = 10000)]
fn http_request(request: HttpRequest) -> HttpResponse {
    let now = get_time_secs();
    match request.path() {
        "/metrics" => export_metrics_as_http_response(now),
        _ => HttpResponseBuilder::not_found().build(),
    }
}
