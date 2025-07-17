use axum::{
    Json,
    extract::{Path, State},
};
use reqwest::StatusCode;
use tracing::info;

use crate::{
    api::{
        backend_service::BackendService,
        models::{DomainData, PostPayload, error_response, success_response},
    },
    task::TaskKind,
};

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
///     "status_endpoint": "/domains/example.org/status"
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
///   "errors": "conflict: Certificate for example.org already issued"
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
///   "errors": "conflict: Another task for example.org is currently in progress"
/// }
pub async fn create_handler(
    State(backend_service): State<BackendService>,
    Json(PostPayload { domain }): Json<PostPayload>,
) -> axum::response::Response {
    info!("Received request to create domain: {domain}");

    match backend_service.submit_task(&domain, TaskKind::Issue).await {
        Ok(canister_id) => success_response(
            StatusCode::ACCEPTED,
            DomainData {
                domain: domain.clone(),
                canister_id: Some(canister_id),
                status_endpoint: Some(format!("/domains/{domain}/status")),
                validation_status: None,
                registration_status: None,
            },
            Some(
                "Domain registration request accepted and may take a few minutes to process"
                    .to_string(),
            ),
        ),
        Err(err) => error_response(
            err,
            DomainData {
                domain,
                canister_id: None,
                status_endpoint: None,
                validation_status: None,
                registration_status: None,
            },
            Some("Domain registration request failed".to_string()),
        ),
    }
}

/// POST /domains/{id}/update
///
/// Triggers an update task for an existing domain registration, updates domain -> canister_id mapping.
/// Responds with 202 Accepted to indicate async processing.
///
/// Example responses (similar to create_handler):
///
/// 202 Accepted:
/// {
///   "status": "success",
///   "code": 202,
///   "message": "Update domain registration request accepted and may take a few minutes to process",
///   "data": {
///     "domain": "example.org",
///     "canister_id": "laqa6-raaaa-aaaam-aehzq-cai",
///     "status_endpoint": "/domains/example.org/status"
///   }
/// }
pub async fn update_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    info!("Received request to update domain: {}", domain);

    match backend_service.submit_task(&domain, TaskKind::Update).await {
        Ok(canister_id) => success_response(
            StatusCode::ACCEPTED,
            DomainData {
                domain: domain.clone(),
                canister_id: Some(canister_id),
                status_endpoint: Some(format!("/domains/{domain}/status")),
                validation_status: None,
                registration_status: None,
            },
            Some(
                "Update domain registration request accepted and may take a few minutes to process"
                    .to_string(),
            ),
        ),
        Err(err) => error_response(
            err,
            DomainData {
                domain,
                canister_id: None,
                status_endpoint: None,
                validation_status: None,
                registration_status: None,
            },
            Some("Update domain registration request failed".to_string()),
        ),
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
/// 200 OK:
/// {
///   "status": "success",
///   "code": 200,
///   "message": "Registration status of the domain",
///   "data": {
///     "domain": "example.org",
///     "registration_status": {
///       "failure": "validation_failed: invalid DNS TXT record from _canister-id.example.org to laqa6-raaaa-aaaam-aehzq-caii"
///     }
///   }
/// }
pub async fn get_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    info!("Received request for domain status: {}", domain);
    match backend_service.get_domain_status(&domain).await {
        Ok(domains_status) => success_response(
            StatusCode::OK,
            DomainData {
                domain: domain.clone(),
                canister_id: domains_status.canister_id,
                status_endpoint: None,
                validation_status: None,
                registration_status: Some(domains_status.status),
            },
            Some("Registration status of the domain".to_string()),
        ),
        Err(err) => error_response(
            err,
            DomainData {
                domain,
                canister_id: None,
                status_endpoint: None,
                validation_status: None,
                registration_status: None,
            },
            Some("Registration status request failed".to_string()),
        ),
    }
}

/// GET /domains/{id}/validate
///
/// Validates if the specified domain is eligible for registration.
///
/// This endpoint checks whether all DNS records for the given domain are correctly configured by the owner,
/// and whether canister ownership is confirmed.
/// Always returns 200 OK with the validation result in the response body.
///
/// 200 Ok:
/// {
///   "status": "success",
///   "code": 200,
///   "message": "Verifies all DNS records and canister ownership (domain name in ./well-known/ic-domains)",
///   "data": {
///     "domain": "example.org",
///     "canister_id": "laqa6-raaaa-aaaam-aehzq-cai",
///     "validation_status": "valid"
///   }
/// }
///
/// 422 Unprocessable Entity
/// {
///   "status": "error",
///   "code": 422,
///   "message": "Verifies all DNS records and canister ownership (domain name in ./well-known/ic-domains)",
///   "data": {
///     "domain": "example.org"
///   },
///   "errors": "unprocessable_entity: invalid DNS TXT record from _canister-id.example.org to laqa6-raaaa-aaaam-aehzq-caii"
/// }
pub async fn validate_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    info!("Received request for domain validation: {}", domain);

    let message =
        "Verifies all DNS records and canister ownership (domain name in ./well-known/ic-domains)"
            .to_string();
    match backend_service.validate(&domain).await {
        Ok((canister_id, validation_status)) => success_response(
            StatusCode::OK,
            DomainData {
                domain: domain.clone(),
                canister_id: Some(canister_id),
                status_endpoint: None,
                validation_status: Some(validation_status),
                registration_status: None,
            },
            Some(message),
        ),
        Err(err) => error_response(
            err,
            DomainData {
                domain,
                canister_id: None,
                status_endpoint: None,
                validation_status: None,
                registration_status: None,
            },
            Some(message),
        ),
    }
}

//  DELETE /domains/{id}
//
//  Deletes an existing domain registration and revokes its certificate.
//  Responds with 202 Accepted to indicate async revocation.
//
//  202 Accepted:
/// {
///   "status": "success",
///   "code": 202,
///   "message": "Delete domain registration request accepted and may take a few minutes to process",
///   "data": {
///     "domain": "example.org",
///     "canister_id": "laqa6-raaaa-aaaam-aehzq-cai",
///     "status_endpoint": "/domains/example.org/status"
///   }
/// }
pub async fn delete_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    info!("Received request to delete domain: {}", domain);

    match backend_service.submit_delete_task(&domain).await {
        Ok(()) => success_response(
            StatusCode::ACCEPTED,
            DomainData {
                domain: domain.clone(),
                canister_id: None,
                status_endpoint: Some(format!("/domains/{domain}/status")),
                validation_status: None,
                registration_status: None,
            },
            Some(
                "Delete domain registration request accepted and may take a few minutes to process"
                    .to_string(),
            ),
        ),
        Err(err) => error_response(
            err,
            DomainData {
                domain,
                canister_id: None,
                status_endpoint: None,
                validation_status: None,
                registration_status: None,
            },
            Some("Delete domain registration request failed".to_string()),
        ),
    }
}
