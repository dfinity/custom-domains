use std::sync::Arc;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::{
    api::{
        backend_service::BackendService,
        handlers::{create_handler, delete_handler, get_handler, update_handler},
    },
    repository::Repository,
};

pub fn create_router(repository: Arc<dyn Repository>) -> Router {
    let backend_service = BackendService::new(repository);
    Router::new()
        .route("/domains", post(create_handler))
        .route("/domains/{:id}/status", get(get_handler))
        .route("/domains/{:id}/update", post(update_handler))
        .route("/domains/{:id}", delete(delete_handler))
        .with_state(backend_service)
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
        api::routes::create_router,
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
