use canister_api::{FetchTaskResult, InputTask, SubmitTaskResult, TaskResult, TryAddTaskResult};
use ic_cdk::update;

use crate::state::with_state_mut;

pub mod state;
pub mod storage;

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
