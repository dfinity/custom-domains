use base::{
    traits::{repository::RepositoryError, validation::ValidationError},
    types::domain::RegistrationStatus,
};

use axum::{http::StatusCode, response::IntoResponse, Json};
use candid::Principal;
use serde::{Deserialize, Serialize};

/// Generic API response structure for all endpoints.
#[derive(Serialize)]
pub struct ApiResponse<T> {
    /// Status of the response ("success" or "error")
    status: String,
    /// HTTP status code
    code: u16,
    /// Optional human-readable message
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Optional response data payload
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    /// Optional error details
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<String>,
}

/// API error types with associated details.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ApiError {
    /// Invalid request data (400)
    BadRequest { details: String },
    /// Resource not found (404)
    NotFound { details: String },
    /// Resource conflict (409)
    Conflict { details: String },
    /// Request validation failed (422)
    UnprocessableEntity { details: String },
    /// Server error (500)
    InternalServerError { details: String },
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::BadRequest { details } => write!(f, "bad_request: {details}"),
            ApiError::NotFound { details } => write!(f, "not_found: {details}"),
            ApiError::Conflict { details } => write!(f, "conflict: {details}"),
            ApiError::UnprocessableEntity { details } => {
                write!(f, "unprocessable_entity: {details}")
            }
            ApiError::InternalServerError { .. } => write!(f, ""),
        }
    }
}

/// Response data payload for domain-related endpoints.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct DomainData {
    /// The domain name
    pub domain: String,
    /// Associated canister ID (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canister_id: Option<Principal>,
    /// Domain validation status (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<ValidationStatus>,
    /// Domain registration status (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_status: Option<RegistrationStatus>,
}

impl From<RepositoryError> for ApiError {
    fn from(err: RepositoryError) -> Self {
        match err {
            RepositoryError::CertificateAlreadyIssued(domain) => ApiError::Conflict {
                details: format!("Certificate for {domain} already issued"),
            },
            RepositoryError::AnotherTaskInProgress(domain) => ApiError::Conflict {
                details: format!("Another task for {domain} is currently in progress"),
            },
            RepositoryError::DomainNotFound(domain) => ApiError::NotFound {
                details: format!("Domain {domain} not found"),
            },
            _ => ApiError::InternalServerError {
                details: "".to_string(),
            },
        }
    }
}

// All validation errors should be converted to BadRequest
impl From<ValidationError> for ApiError {
    fn from(value: ValidationError) -> Self {
        Self::BadRequest {
            details: value.to_string(),
        }
    }
}

/// Creates a success response with the given data and message.
pub fn success_response<T: Serialize>(
    code: StatusCode,
    data: T,
    message: Option<String>,
) -> axum::response::Response {
    let json: Json<ApiResponse<T>> = Json(ApiResponse {
        status: "success".to_string(),
        code: code.as_u16(),
        message,
        data: Some(data),
        errors: None,
    });

    (code, json).into_response()
}

/// Creates an error response with the given error, data, and message.
pub fn error_response<T: Serialize>(
    error: ApiError,
    data: T,
    message: Option<String>,
) -> axum::response::Response {
    let code = match error {
        ApiError::BadRequest { .. } => StatusCode::BAD_REQUEST,
        ApiError::NotFound { .. } => StatusCode::NOT_FOUND,
        ApiError::Conflict { .. } => StatusCode::CONFLICT,
        ApiError::UnprocessableEntity { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        ApiError::InternalServerError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    };

    let json: Json<ApiResponse<T>> = Json(ApiResponse {
        status: "error".to_string(),
        code: code.as_u16(),
        message,
        data: Some(data),
        errors: Some(error.to_string()),
    });

    (code, json).into_response()
}

/// Domain validation status for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    /// Domain validation passed
    Valid,
    /// Domain validation failed with error details
    Invalid(String),
}

/// Request payload for domain registration endpoints.
#[derive(Debug, Deserialize, Serialize)]
pub struct PostPayload {
    pub domain: String,
}
