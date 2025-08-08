use canister_api::{
    FetchTaskResult, GetDomainStatusResult, InputTask, SubmitTaskResult, TaskResult,
    TryAddTaskResult,
};
use ic_cdk::{query, update};

use crate::state::{with_state, with_state_mut};

pub mod state;
pub mod storage;

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
