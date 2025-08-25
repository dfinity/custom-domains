use base::types::task::TaskKind;

use crate::{
    backend_service::BackendService,
    models::{error_response, success_response, ApiError, DomainData, PostPayload},
};
use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    Json,
};
use tracing::{error, info};

/// Logging middleware that logs incoming requests and their responses
pub async fn logging_middleware(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let uri = request.uri().path().to_string();
    let start = std::time::Instant::now();

    let response = next.run(request).await;
    let duration = start.elapsed();
    let status_code = response.status().as_u16();

    info!(
        method,
        uri,
        status_code,
        duration_ms = duration.as_millis(),
        "http_request"
    );

    response
}

fn log_error(err: &ApiError, domain: &str, operation: &str) {
    error!(
        domain = %domain,
        operation = %operation,
        error = %err,
    );
}

/// POST /domains
///
/// Registers a new domain by triggering a certificate issuance task.
/// Responds with 202 Accepted to indicate async processing.
///
/// Example responses:
///
/// 202 Accepted:
/// {
///   "status": "success",
///   "code": 202,
///   "message": "Domain registration request accepted and may take a few minutes to process",
///   "data": {
///     "domain": "example.org",
///     "canister_id": "laqa6-raaaa-aaaam-aehzq-cai",
///   }
/// }
///
/// 400 Bad Request:
/// {
///   "status": "error",
///   "code": 400,
///   "message": "Domain registration request failed",
///   "data": {
///     "domain": "example.org"
///   },
///   "errors": "bad_request: missing DNS CNAME record from _acme-challenge.example.org. to _acme-challenge.example.org.icp2.io."
/// }
///
/// 409 Conflict (submitted after issue finishes):
/// {
///   "status": "error",
///   "code": 409,
///   "message": "Domain registration request failed",
///   "data": {
///     "domain": "example.org"
///   },
///   "errors": "conflict: Certificate for example.org already exists; reissuance is not permitted."
/// }
///
/// 409 Conflict (submitted before issue finishes):
/// {
///   "status": "error",
///   "code": 409,
///   "message": "Domain registration request failed",
///   "data": {
///     "domain": "example.org"
///   },
///   "errors": "conflict: A task for example.org is already in progress. Please retry after it completes."
/// }
pub async fn create_handler(
    State(backend_service): State<BackendService>,
    Json(PostPayload { domain }): Json<PostPayload>,
) -> axum::response::Response {
    match backend_service.submit_task(&domain, TaskKind::Issue).await {
        Ok(canister_id) => success_response(
            StatusCode::ACCEPTED,
            DomainData {
                domain: domain.clone(),
                canister_id: Some(canister_id),
                validation_status: None,
                registration_status: None,
            },
            Some(
                "Domain registration request accepted and may take a few minutes to process"
                    .to_string(),
            ),
        ),
        Err(err) => {
            log_error(&err, &domain, "create_registration");
            error_response(
                err,
                DomainData {
                    domain,
                    canister_id: None,
                    validation_status: None,
                    registration_status: None,
                },
                Some("Domain registration request failed".to_string()),
            )
        }
    }
}

/// POST /domains/{id}/update
///
/// Triggers an update task for an existing domain registration, updates domain -> canister_id mapping.
/// Responds with 202 Accepted to indicate async processing.
///
/// Example responses:
///
/// 202 Accepted:
/// {
///   "status": "success",
///   "code": 202,
///   "message": "Update domain registration request accepted and may take a few minutes to process",
///   "data": {
///     "domain": "example.org",
///     "canister_id": "laqa6-raaaa-aaaam-aehzq-cai"
///   }
/// }
///
/// Error responses:
/// {
///   "status": "error",
///   "code": xxx,
///   "message": "Update domain registration request failed",
///   "data": {
///     "domain": "example.org"
///   },
///   "errors": "error details..."
/// }
pub async fn update_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    match backend_service.submit_task(&domain, TaskKind::Update).await {
        Ok(canister_id) => success_response(
            StatusCode::ACCEPTED,
            DomainData {
                domain: domain.clone(),
                canister_id: Some(canister_id),
                validation_status: None,
                registration_status: None,
            },
            Some(
                "Update domain registration request accepted and may take a few minutes to process"
                    .to_string(),
            ),
        ),
        Err(err) => {
            log_error(&err, &domain, "update_registration");
            error_response(
                err,
                DomainData {
                    domain,
                    canister_id: None,
                    validation_status: None,
                    registration_status: None,
                },
                Some("Update domain registration request failed".to_string()),
            )
        }
    }
}

/// GET /domains/{id}/status
///
/// Retrieves the current registration status of the given domain.
/// Returns 200 OK with the status payload.
///
/// Example responses:
///
/// 200 OK:
/// {
///   "status": "success",
///   "code": 200,
///   "message": "Registration status of the domain",
///   "data": {
///     "domain": "example.org",
///     "canister_id": "laqa6-raaaa-aaaam-aehzq-cai",
///     "registration_status": "registered" | "processing"
///   }
/// }
///
/// 200 OK (failure case):
/// {
///   "status": "success",
///   "code": 200,
///   "message": "Registration status of the domain",
///   "data": {
///     "domain": "example.org",
///     "registration_status": {
///       "failed": "An unexpected error occurred during registration. Please try again later or contact support."
///     }
///   }
/// }
///
/// Error responses:
/// {
///   "status": "error",
///   "code": xxx,
///   "message": "Registration status request failed",
///   "data": {
///     "domain": "example.org"
///   },
///   "errors": "error details..."
/// }
pub async fn get_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    match backend_service.get_domain_status(&domain).await {
        Ok(domains_status) => success_response(
            StatusCode::OK,
            DomainData {
                domain: domain.clone(),
                canister_id: domains_status.canister_id,
                validation_status: None,
                registration_status: Some(domains_status.status),
            },
            Some("Registration status of the domain".to_string()),
        ),
        Err(err) => {
            log_error(&err, &domain, "registration_status");
            error_response(
                err,
                DomainData {
                    domain,
                    canister_id: None,
                    validation_status: None,
                    registration_status: None,
                },
                Some("Registration status request failed".to_string()),
            )
        }
    }
}

/// GET /domains/{id}/validate
///
/// Validates if the specified domain is eligible for registration.
///
/// This endpoint checks whether all DNS records for the given domain are correctly configured by the owner,
/// and whether canister ownership is confirmed.
///
/// Example responses:
///
/// 200 OK:
/// {
///   "status": "success",
///   "code": 200,
///   "message": "Domain is eligible for registration: DNS records are valid and canister ownership is verified",
///   "data": {
///     "domain": "example.org",
///     "canister_id": "laqa6-raaaa-aaaam-aehzq-cai",
///     "validation_status": "valid"
///   }
/// }
///
/// 422 Unprocessable Entity:
/// {
///   "status": "error",
///   "code": 422,
///   "message": "Failed to validate DNS records or verify canister ownership",
///   "data": {
///     "domain": "example.org"
///   },
///   "errors": "unprocessable_entity: missing DNS CNAME record from _acme-challenge.example.org. to _acme-challenge.example.org.icp2.io."
/// }
pub async fn validate_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    match backend_service.validate(&domain).await {
        Ok((canister_id, validation_status)) => success_response(
            StatusCode::OK,
            DomainData {
                domain: domain.clone(),
                canister_id: Some(canister_id),
                validation_status: Some(validation_status),
                registration_status: None,
            },
            Some("Domain is eligible for registration: DNS records are valid and canister ownership is verified".to_string()),
        ),
        Err(err) => {
            log_error(&err, &domain, "validate_domain");
            error_response(
                err,
                DomainData {
                    domain,
                    canister_id: None,
                    validation_status: None,
                    registration_status: None,
                },
                Some("Failed to validate DNS records or verify canister ownership".to_string()),
            )
        }
    }
}

/// DELETE /domains/{id}
///
/// Deletes an existing domain registration and revokes its certificate.
/// Responds with 202 Accepted to indicate async revocation.
///
/// Example responses:
///
/// 202 Accepted:
/// {
///   "status": "success",
///   "code": 202,
///   "message": "Delete domain registration request accepted and may take a few minutes to process",
///   "data": {
///     "domain": "example.org"
///   }
/// }
///
/// Error responses:
/// {
///   "status": "error",
///   "code": xxx,
///   "message": "Delete domain registration request failed",
///   "data": {
///     "domain": "example.org"
///   },
///   "errors": "error details..."
/// }
pub async fn delete_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    match backend_service.submit_delete_task(&domain).await {
        Ok(()) => success_response(
            StatusCode::ACCEPTED,
            DomainData {
                domain: domain.clone(),
                canister_id: None,
                validation_status: None,
                registration_status: None,
            },
            Some(
                "Delete domain registration request accepted and may take a few minutes to process"
                    .to_string(),
            ),
        ),
        Err(err) => {
            log_error(&err, &domain, "delete_registration");
            error_response(
                err,
                DomainData {
                    domain,
                    canister_id: None,
                    validation_status: None,
                    registration_status: None,
                },
                Some("Delete domain registration request failed".to_string()),
            )
        }
    }
}
