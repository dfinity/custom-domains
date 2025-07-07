use std::{str::FromStr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use fqdn::FQDN;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    repository::{Repository, RepositoryError},
    task::{InputTask, TaskKind},
};

#[derive(Serialize)]
pub enum RegistrationStatus {
    Processing,
    Registered,
}

#[derive(Clone)]
pub struct AppState {
    pub state: Arc<dyn Repository>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PostPayload {
    domain: String,
}

pub async fn post_handler(
    State(AppState { state }): State<AppState>,
    Json(PostPayload { domain }): Json<PostPayload>,
) -> impl IntoResponse {
    let domain = FQDN::from_str(&domain).expect("TODO 400");
    let task = InputTask::new(TaskKind::Issue, domain);

    match state.try_add_task(task).await {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({}))).into_response(),
        Err(err) => match err {
            RepositoryError::CertificateAlreadyIssued(_) => {
                let body = json!({"error": "certificate for domain {domain} was already issued"});
                (StatusCode::CONFLICT, Json(body)).into_response()
            }
            _ => todo!(),
        },
    }
}

pub async fn get_handler(
    Path(domain): Path<String>,
    State(AppState { state }): State<AppState>,
) -> impl IntoResponse {
    let domain = FQDN::from_str(&domain).expect("TODO 400");

    match state.get_domain(&domain).await {
        Ok(Some(entry)) => {
            let status = entry.task.map_or(RegistrationStatus::Registered, |_| {
                RegistrationStatus::Processing
            });
            let body = json!({"status": status});
            (StatusCode::OK, Json(body)).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_err) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn delete_handler(
    Path(domain): Path<String>,
    State(AppState { state }): State<AppState>,
) -> impl IntoResponse {
    let domain = FQDN::from_str(&domain).expect("TODO 400");
    let task = InputTask::new(TaskKind::Delete, domain);

    match state.try_add_task(task).await {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({}))).into_response(),
        Err(err) => match err {
            RepositoryError::DomainNotFound(_) => {
                let body = json!({"error": "resource was not found"});
                (StatusCode::NOT_FOUND, Json(body)).into_response()
            }
            _ => todo!(),
        },
    }
}

pub fn create_router(repository: Arc<dyn Repository>) -> Router {
    let app_state = AppState { state: repository };
    Router::new()
        .route("/domains", post(post_handler))
        .route("/domains/{:id}/status", get(get_handler))
        .route("/domains/{:id}", delete(delete_handler))
        .with_state(app_state)
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use fqdn::FQDN;
    use serde_json::json;
    use tower::util::ServiceExt;

    use crate::{
        api::create_router,
        repository::{MockRepository, RepositoryError},
        task::{InputTask, TaskKind},
    };

    const BODY_LIMIT: usize = 5000;

    #[tokio::test]
    async fn test_post_accepted_and_conflict() {
        let mut mock_repository = MockRepository::new();
        let domain = FQDN::from_str("example.org").unwrap();
        let expected_task = InputTask::new(TaskKind::Issue, domain.clone());

        // First expectation: successful task addition
        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        // Second expectation: certificate already issued
        mock_repository.expect_try_add_task().returning(|_| {
            let domain = FQDN::from_str("example.org").unwrap();
            Box::pin(async { Err(RepositoryError::CertificateAlreadyIssued(domain)) })
        });

        let router = create_router(Arc::new(mock_repository));

        // Status 202, accepted
        let body = json!({"domain":"example.org"});

        let request = Request::builder()
            .method("POST")
            .uri("/domains")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        // Status 409, conflict
        let body = json!({"domain":"example_1.org"});

        let request = Request::builder()
            .method("POST")
            .uri("/domains")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body_bytes = to_bytes(response.into_body(), BODY_LIMIT).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        assert!(body_str.contains("already issued"));
    }
}
