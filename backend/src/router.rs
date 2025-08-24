use base::traits::{repository::Repository, validation::ValidatesDomains};
use std::sync::Arc;

use axum::{
    middleware::from_fn_with_state,
    routing::{delete, get, post},
    Router,
};
use prometheus::Registry;

use crate::{
    backend_service::BackendService,
    handlers::{create_handler, delete_handler, get_handler, update_handler, validate_handler},
    metrics::{metrics_handler, metrics_middleware, HttpMetrics},
};

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
    use base::{
        traits::{
            repository::{MockRepository, RepositoryError},
            validation::{MockValidatesDomains, ValidationError},
        },
        types::task::{InputTask, TaskKind},
    };
    use std::{str::FromStr, sync::Arc};

    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use candid::Principal;
    use fqdn::FQDN;
    use prometheus::Registry;
    use serde_json::{json, Value};
    use tower::util::ServiceExt;

    use crate::router::create_router;

    const BODY_LIMIT: usize = 5000;

    /// Helper function to create a router with mocked dependencies
    fn create_test_router(
        mock_repository: MockRepository,
        mock_validator: MockValidatesDomains,
    ) -> axum::Router {
        let registry = Registry::new_custom(Some("custom_domains".into()), None).unwrap();
        create_router(
            Arc::new(mock_repository),
            Arc::new(mock_validator),
            registry,
            true,
        )
    }

    /// Helper function to make a POST request to /v1/domains
    async fn post_domain_request(router: axum::Router, domain: &str) -> (StatusCode, Value) {
        let body = json!({"domain": domain});
        let request = Request::builder()
            .method("POST")
            .uri("/v1/domains")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), BODY_LIMIT).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        (status, body_json)
    }

    #[tokio::test]
    async fn test_post_domain_success_accepted() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        let expected_canister_id = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
        mock_validator
            .expect_validate()
            .returning(move |_| Box::pin(async move { Ok(expected_canister_id) }));

        let mut mock_repository = MockRepository::new();
        let domain_normal = "example.org";
        let subdomain_unicode = "тест.unicode.org";

        let expected_task_normal =
            InputTask::new(TaskKind::Issue, FQDN::from_str(domain_normal).unwrap());
        let expected_task_unicode =
            InputTask::new(TaskKind::Issue, FQDN::from_str(subdomain_unicode).unwrap());
        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task_normal)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task_unicode)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router.clone(), domain_normal).await;
        let (status_unicode, response_json_unicode) =
            post_domain_request(router, subdomain_unicode).await;

        // Assert
        for (status, response_json, domain) in [
            (status, response_json, domain_normal),
            (status_unicode, response_json_unicode, subdomain_unicode),
        ] {
            assert_eq!(status, StatusCode::ACCEPTED);
            assert_eq!(response_json["status"], "success");
            assert_eq!(response_json["code"], 202);
            assert_eq!(response_json["data"]["domain"], domain);
            assert_eq!(
                response_json["data"]["canister_id"],
                "rrkah-fqaaa-aaaaa-aaaaq-cai"
            );
            assert_eq!(
                response_json["message"].as_str().unwrap(),
                "Domain registration request accepted and may take a few minutes to process"
            );
        }
    }

    #[tokio::test]
    async fn test_post_domain_conflict_certificate_already_issued() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async { Ok(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap()) })
        });

        let mut mock_repository = MockRepository::new();
        mock_repository.expect_try_add_task().returning(|_| {
            let domain = FQDN::from_str("example.org").unwrap();
            Box::pin(async { Err(RepositoryError::CertificateAlreadyIssued(domain)) })
        });

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["code"], 409);
        assert_eq!(
            response_json["message"],
            "Domain registration request failed"
        );
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert!(response_json["errors"]
            .as_str()
            .unwrap()
            .contains("already issued"));
    }

    #[tokio::test]
    async fn test_post_domain_conflict_another_task_in_progress() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async { Ok(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap()) })
        });

        let mut mock_repository = MockRepository::new();
        mock_repository.expect_try_add_task().returning(|_| {
            let domain = FQDN::from_str("example.org").unwrap();
            Box::pin(async { Err(RepositoryError::AnotherTaskInProgress(domain)) })
        });

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["code"], 409);
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert!(response_json["errors"]
            .as_str()
            .unwrap()
            .contains("in progress"));
    }

    #[tokio::test]
    async fn test_post_domain_bad_request_invalid_domain() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router, "invalid..domain").await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["code"], 400);
        assert_eq!(response_json["data"]["domain"], "invalid..domain");
        assert!(response_json["errors"]
            .as_str()
            .unwrap()
            .contains("Invalid domain"));
    }

    #[tokio::test]
    async fn test_post_domain_bad_request_with_validation_error() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async {
                Err(ValidationError::MissingDnsCname {
                    src: "_acme-challenge.example.org.".to_string(),
                    dst: "_acme-challenge.example.org.icp2.io.".to_string(),
                })
            })
        });

        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["code"], 400);
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            "bad_request: missing DNS CNAME record from _acme-challenge.example.org. to _acme-challenge.example.org.icp2.io."
        )
    }

    #[tokio::test]
    async fn test_post_domain_internal_server_error_repository_failure() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async { Ok(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap()) })
        });

        let mut mock_repository = MockRepository::new();
        mock_repository.expect_try_add_task().returning(|_| {
            Box::pin(async {
                Err(RepositoryError::InternalError(anyhow::anyhow!(
                    "Some internal error"
                )))
            })
        });

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["code"], 500);
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert_eq!(response_json["errors"], "internal_server_error: An unexpected error occurred. Please try again later or contact support");
    }

    #[tokio::test]
    async fn test_post_domain_malformed_json() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let request = Request::builder()
            .method("POST")
            .uri("/v1/domains")
            .header("content-type", "application/json")
            .body(Body::from("{invalid json"))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_post_domain_missing_content_type() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let body = json!({"domain": "example.org"});
        let request = Request::builder()
            .method("POST")
            .uri("/v1/domains")
            // No content-type header
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_post_domain_missing_domain_field() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let body = json!({"not_domain": "example.org"});
        let request = Request::builder()
            .method("POST")
            .uri("/v1/domains")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        // Assert: returns UnprocessableEntity for missing required "domain" field
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_post_domain_very_long_domain() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let long_domain = "a".repeat(250) + ".example.org";
        let (status, response_json) = post_domain_request(router, &long_domain).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["code"], 400);
        assert_eq!(response_json["errors"], "bad_request: Domain is too long");
    }

    #[tokio::test]
    async fn test_post_domain_wrong_http_method() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act: use GET instead of POST
        let request = Request::builder()
            .method("GET")
            .uri("/v1/domains")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
