use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    task::{Domain, Task, TaskError, TaskName},
    task_manager::ManagesTasks,
};

#[derive(Clone)]
pub struct AppState {
    pub task_manager: Arc<dyn ManagesTasks>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PostPayload {
    domain: Domain,
}

pub async fn post_handler(
    state: State<AppState>,
    Json(PostPayload { domain }): Json<PostPayload>,
) -> impl IntoResponse {
    let task = Task::new(TaskName::Create, domain, 0);

    match state.task_manager.try_add(task).await {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({}))),
        Err(err) => match err {
            TaskError::AlreadyCreated => {
                let body = json!({"error": "resource was already created"});
                (StatusCode::CONFLICT, Json(body))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode},
        routing::post,
    };
    use serde_json::json;
    use tower::util::ServiceExt;

    use crate::{
        api::{AppState, post_handler},
        task::{Domain, Task, TaskError, TaskName},
        task_manager::{ManagesTasks, MockManagesTasks},
    };

    fn create_test_router(task_manager: Arc<dyn ManagesTasks>) -> Router {
        let app_state = AppState { task_manager };
        Router::new()
            .route("/domains", post(post_handler))
            .with_state(app_state)
    }

    #[tokio::test]
    async fn test_post_accepted_and_conflict() {
        let mut mock_task_manager = MockManagesTasks::new();
        let expected_task = Task::new(TaskName::Create, Domain("example.org".to_string()), 0);
        mock_task_manager
            .expect_try_add()
            .withf(move |task| *task == expected_task)
            .returning(|_| Box::pin(async { Ok(()) }));
        mock_task_manager
            .expect_try_add()
            .returning(|_| Box::pin(async { Err(TaskError::AlreadyCreated) }));

        let router = create_test_router(Arc::new(mock_task_manager));

        // Status accepted 202
        let body = json!({"domain":"example.org"});

        let request = Request::builder()
            .method("POST")
            .uri("/domains")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        // Status conflict 409
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
