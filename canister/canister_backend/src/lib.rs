use std::time::Duration;

use canister_api::{
    FetchTaskError, FetchTaskResult, GetDomainStatusError, GetDomainStatusResult,
    GetLastChangeTimeError, GetLastChangeTimeResult, InitArg, InputTask, ListCertificatesPageError,
    ListCertificatesPageInput, ListCertificatesPageResult, SubmitTaskError, SubmitTaskResult,
    TaskResult, TryAddTaskError, TryAddTaskResult,
};
use ic_cdk::{caller, init, inspect_message, post_upgrade, query, trap, update};
use ic_cdk_timers::set_timer_interval;

use crate::{
    state::{get_time_secs, with_state, with_state_mut},
    storage::AUTHORIZED_PRINCIPAL,
};

pub mod state;
pub mod storage;

const ENQUEUE_TASKS_INTERVAL: Duration = Duration::from_secs(30);

// Inspect ingress messages in the pre-consensus phase and reject early, if the caller is unauthorized
#[inspect_message]
fn inspect_message() {
    if let Some(authorized_principal) = AUTHORIZED_PRINCIPAL.with(|p| *p.borrow()) {
        if authorized_principal != caller() {
            trap("message_inspection_failed: unauthorized call");
        }
    }
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

    set_timer_interval(ENQUEUE_TASKS_INTERVAL, move || {
        let now = get_time_secs();
        with_state_mut(|state| state.maybe_enqueue_tasks(now));
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
    with_state(|state| state.get_domain_status(domain))
}

#[update]
async fn fetch_next_task() -> FetchTaskResult {
    validate_caller(FetchTaskError::Unauthorized)?;
    with_state_mut(|state| state.fetch_next_task())
}

#[update]
async fn submit_task_result(result: TaskResult) -> SubmitTaskResult {
    validate_caller(SubmitTaskError::Unauthorized)?;
    with_state_mut(|state| state.submit_task_result(result))
}

#[update]
async fn try_add_task(task: InputTask) -> TryAddTaskResult {
    validate_caller(TryAddTaskError::Unauthorized)?;
    with_state_mut(|state| state.try_add_task(task))
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
