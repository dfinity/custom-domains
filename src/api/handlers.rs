use axum::{
    Json,
    extract::{Path, State},
};
use reqwest::StatusCode;

use crate::{
    api::{backend_service::BackendService, models::{ApiError, ApiResponse, AppState, PostPayload, StatusResponse}}, task::TaskKind
};

// POST /domains
pub async fn post_handler(
    State(AppState { state }): State<AppState>,
    Json(PostPayload { domain }): Json<PostPayload>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), ApiError> {
    let service = BackendService::new(state);
    service.add_task(&domain, TaskKind::Issue).await?;
    Ok((StatusCode::ACCEPTED, Json(ApiResponse::success(()))))
}

// POST /domains/{:id}/update
pub async fn update_handler(
    Path(domain): Path<String>,
    State(AppState { state }): State<AppState>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), ApiError> {
    let service = BackendService::new(state);
    service.add_task(&domain, TaskKind::Update).await?;
    Ok((StatusCode::ACCEPTED, Json(ApiResponse::success(()))))
}

// GET /domains/{:id}/status
pub async fn get_handler(
    Path(domain): Path<String>,
    State(AppState { state }): State<AppState>,
) -> Result<(StatusCode, Json<ApiResponse<StatusResponse>>), ApiError> {
    let service = BackendService::new(state);
    let status = service.get_domain_status(&domain).await?;
    Ok((StatusCode::OK, Json(ApiResponse::success(status))))
}

// DELETE /domains/{:id}
pub async fn delete_handler(
    Path(domain): Path<String>,
    State(AppState { state }): State<AppState>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), ApiError> {
    let service = BackendService::new(state);
    service.add_task(&domain, TaskKind::Delete).await?;
    Ok((StatusCode::ACCEPTED, Json(ApiResponse::success(()))))
}
