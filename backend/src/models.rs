use base::{
    traits::{repository::RepositoryError, validation::ValidationError},
    types::domain::RegistrationStatus,
};

use axum::{http::StatusCode, response::IntoResponse, Json};
use candid::Principal;
use serde::{Deserialize, Serialize};

// Generic API response
#[derive(Serialize)]
pub struct ApiResponse<T> {
    status: String,
    code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ApiError {
    BadRequest { details: String },
    NotFound { details: String },
    Conflict { details: String },
    UnprocessableEntity { details: String },
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

// Response data for all handlers
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct DomainData {
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canister_id: Option<Principal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<ValidationStatus>,
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

// Domain validation status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Valid,
    Invalid(String),
}

// Payload for registering a new domain
#[derive(Debug, Deserialize, Serialize)]
pub struct PostPayload {
    pub domain: String,
}
