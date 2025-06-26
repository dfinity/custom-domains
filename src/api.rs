use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    repository::{Repository, RepositoryError},
    task::{Domain, Task, TaskName},
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
    domain: Domain,
}

pub async fn post_handler(
    State(AppState { state }): State<AppState>,
    Json(PostPayload { domain }): Json<PostPayload>,
) -> impl IntoResponse {
    let task = Task::new(TaskName::Create, domain);

    match state.try_add_task(task).await {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({}))).into_response(),
        Err(err) => match err {
            RepositoryError::TaskAlreadyExists => {
                let body = json!({"error": "resource was already created"});
                (StatusCode::CONFLICT, Json(body)).into_response()
            }
            _ => todo!(),
        },
    }
}

pub async fn get_handler(
    Path(domain): Path<Domain>,
    State(AppState { state }): State<AppState>,
) -> impl IntoResponse {
    match state.get_domain(domain).await {
        Ok(Some(entry)) => {
            let status = entry.task.map_or(RegistrationStatus::Registered, |_| {
                RegistrationStatus::Processing
            });
            let body = json!({ "status": status, "certificate": entry.certificate });
            (StatusCode::OK, Json(body)).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_err) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn delete_handler(
    Path(domain): Path<Domain>,
    State(AppState { state }): State<AppState>,
) -> impl IntoResponse {
    let task = Task::new(TaskName::Delete, domain);

    match state.try_add_task(task).await {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({}))).into_response(),
        Err(err) => match err {
            RepositoryError::DomainNotFound => {
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
    use std::sync::Arc;

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use serde_json::json;
    use tower::util::ServiceExt;

    use crate::{
        api::create_router,
        repository::{MockRepository, RepositoryError},
        task::{Domain, Task, TaskName},
    };

    #[tokio::test]
    async fn test_post_accepted_and_conflict() {
        let mut mock_repository = MockRepository::new();
        let expected_task = Task::new(TaskName::Create, Domain("example.org".to_string()));
        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task)
            .returning(|_| Box::pin(async { Ok(()) }));
        mock_repository
            .expect_try_add_task()
            .returning(|_| Box::pin(async { Err(RepositoryError::TaskAlreadyExists) }));

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
        let body_bytes = to_bytes(response.into_body(), 1000).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        assert!(body_str.contains("resource was already created"));
    }
}
