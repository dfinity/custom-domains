use axum::{
    Json,
    extract::{Path, State},
};
use reqwest::StatusCode;
use tracing::info;

use crate::{
    api::{
        backend_service::BackendService,
        models::{ApiError, ApiResponse, PostPayload, RegistrationStatus, ValidationStatus},
    },
    task::TaskKind,
};

/// Genetic yype for all HTTP handlers.
pub type HandlerResult<T> = Result<(StatusCode, Json<ApiResponse<T>>), ApiError>;

/// POST /domains
///
/// Registers a new domain by triggering a certificate issuance task.
/// Responds with 202 Accepted to indicate async processing.
pub async fn create_handler(
    State(backend_service): State<BackendService>,
    Json(PostPayload { domain }): Json<PostPayload>,
) -> HandlerResult<()> {
    info!("Received request to create domain: {}", domain);
    backend_service
        .try_add_task(&domain, TaskKind::Issue)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(ApiResponse::success(()))))
}

/// POST /domains/{id}/update
///
/// Triggers an update task for an existing domain registration, updates domain -> canister_id mapping.
/// Responds with 202 Accepted to indicate async processing.
pub async fn update_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> HandlerResult<()> {
    info!("Received request to update domain: {}", domain);
    backend_service
        .try_add_task(&domain, TaskKind::Update)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(ApiResponse::success(()))))
}

/// GET /domains/{id}/status
///
/// Retrieves the current registration status of the given domain.
/// Returns 200 OK with the status payload.
pub async fn get_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> HandlerResult<RegistrationStatus> {
    info!("Received request for domain status: {}", domain);
    let status = backend_service.get_registration_status(&domain).await?;
    Ok((StatusCode::OK, Json(ApiResponse::success(status))))
}

/// GET /domains/{id}/validate
///
/// Validates if the specified domain is eligible for registration.
///
/// This endpoint checks whether all DNS records for the given domain are correctly configured by the owner,
/// and whether canister ownership is confirmed.
/// Always returns 200 OK with the validation result in the response body.
pub async fn validate_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> HandlerResult<ValidationStatus> {
    info!("Received request for domain validation: {}", domain);
    let validation_status = backend_service.validate_domain(&domain).await?;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::success(validation_status)),
    ))
}

/// DELETE /domains/{id}
///
/// Deletes an existing domain registration and revokes its certificate.
/// Responds with 202 Accepted to indicate async revocation.
pub async fn delete_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> HandlerResult<()> {
    info!("Received request to delete domain: {}", domain);
    backend_service
        .try_add_task(&domain, TaskKind::Delete)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(ApiResponse::success(()))))
}
