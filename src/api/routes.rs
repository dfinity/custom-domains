use std::sync::Arc;

use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{delete, get, post},
};

use crate::{
    api::{
        backend_service::BackendService,
        handlers::{create_handler, delete_handler, get_handler, update_handler, validate_handler},
        metrics::{HttpMetrics, metrics_handler, metrics_middleware},
    },
    repository::Repository,
    validation::ValidatesDomains,
};

use prometheus::Registry;

pub fn create_router(
    repository: Arc<dyn Repository>,
    validator: Arc<dyn ValidatesDomains>,
    registry: Registry,
    with_metrics_endpoint: bool,
) -> Router {
    let backend_service = BackendService::new(repository, validator);

    let api_router = Router::new()
        .route("/v1/domains", post(create_handler))
        .route("/v1/domains/{:id}/status", get(get_handler))
        .route("/v1/domains/{:id}/update", post(update_handler))
        .route("/v1/domains/{:id}", delete(delete_handler))
        .route("/v1/domains/{:id}/validate", get(validate_handler))
        .layer(from_fn_with_state(
            Arc::new(HttpMetrics::new(registry.clone())),
            metrics_middleware,
        ))
        .with_state(backend_service);

    let metrics_router = if with_metrics_endpoint {
        Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(registry)
    } else {
        Router::new()
    };

    api_router.merge(metrics_router)
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use candid::Principal;
    use fqdn::FQDN;
    use prometheus::Registry;
    use serde_json::json;
    use tower::util::ServiceExt;

    use crate::{
        api::routes::create_router,
        repository::{MockRepository, RepositoryError},
        task::{InputTask, TaskKind},
        validation::MockValidatesDomains,
    };

    const BODY_LIMIT: usize = 5000;

    #[tokio::test]
    async fn test_post_accepted_and_conflict() {
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async { Ok(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap()) })
        });

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

        let registry = Registry::new_custom(Some("custom_domains".into()), None).unwrap();
        let router = create_router(
            Arc::new(mock_repository),
            Arc::new(mock_validator),
            registry,
            true,
        );

        // Status 202, accepted
        let body = json!({"domain":"example.org"});

        let request = Request::builder()
            .method("POST")
            .uri("/v1/domains")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = router.clone().oneshot(request).await.unwrap();
        println!("response {response:?}");
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        // // Status 409, conflict
        let body = json!({"domain":"example_1.org"});

        let request = Request::builder()
            .method("POST")
            .uri("/v1/domains")
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
