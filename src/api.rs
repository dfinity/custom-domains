use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{task::Domain, task_manager::ManagesTasks};

#[derive(Clone)]
pub struct AppState {
    pub task_manager: Arc<dyn ManagesTasks>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PostPayload {
    domain: Domain,
}

pub async fn post_handler(
    _state: State<AppState>,
    Json(_body): Json<PostPayload>,
) -> impl IntoResponse {
    StatusCode::ACCEPTED
}
