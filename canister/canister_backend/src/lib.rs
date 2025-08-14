use std::time::Duration;

use canister_api::{
    FetchTaskResult, GetDomainStatusResult, GetLastChangeTimeResult, InputTask,
    ListCertificatesPageInput, ListCertificatesPageResult, SubmitTaskResult, TaskResult,
    TryAddTaskResult,
};
use ic_cdk::{init, query, update};
use ic_cdk_timers::set_timer_interval;

use crate::state::{get_time_secs, with_state, with_state_mut};

pub mod state;
pub mod storage;

const ENQUEUE_TASKS_INTERVAL: Duration = Duration::from_secs(5);

#[init]
fn init() {
    set_timer_interval(ENQUEUE_TASKS_INTERVAL, move || {
        let now = get_time_secs();
        with_state_mut(|state| state.maybe_enqueue_tasks(now));
    });
}

#[query]
async fn get_domain_status(domain: String) -> GetDomainStatusResult {
    with_state(|state| state.get_domain_status(domain))
}

#[update]
async fn fetch_next_task() -> FetchTaskResult {
    with_state_mut(|state| state.fetch_next_task())
}

#[update]
async fn submit_task_result(result: TaskResult) -> SubmitTaskResult {
    with_state_mut(|state| state.submit_task_result(result))
}

#[update]
async fn try_add_task(task: InputTask) -> TryAddTaskResult {
    with_state_mut(|state| state.try_add_task(task))
}

#[query]
async fn get_last_change_time() -> GetLastChangeTimeResult {
    with_state(|state| state.get_last_change_time())
}

#[query]
async fn list_certificates_page(input: ListCertificatesPageInput) -> ListCertificatesPageResult {
    with_state(|state| state.list_certificates_page(input))
}
