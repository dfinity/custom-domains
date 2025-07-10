use std::sync::Arc;

use axum::{Json, response::IntoResponse};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::repository::Repository;

#[derive(Serialize)]
pub struct StatusResponse {
    pub status: RegistrationStatus,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PostPayload {
    pub domain: String,
}

#[derive(Serialize)]
pub enum RegistrationStatus {
    Processing,
    Registered,
}

#[derive(Clone)]
pub struct AppState {
    pub state: Arc<dyn Repository>,
}

#[derive(Serialize)]
pub struct ApiResponse<T> {
    data: Option<T>,
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            data: Some(data),
            error: None,
        }
    }

    pub fn error(error: impl Into<String>) -> Self {
        Self {
            data: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Conflict(String),
    NotFound(String),
    InternalServerError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (status, Json(ApiResponse::<()>::error(message))).into_response()
    }
}
