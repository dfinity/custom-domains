use std::{
    env,
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};

use anyhow::{anyhow, bail};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode},
};
use custom_domains::{
    acme::AcmeClientConfig,
    api::routes::create_router,
    helpers::retry_async,
    metrics::WorkerMetrics,
    state::State,
    time::MockTime,
    validation::Validator,
    work::{Worker, WorkerConfig},
};
use prometheus::Registry;
use serde_json::json;
use tokio::spawn;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

const LIMIT: usize = 20000;
const AWAIT_TIMEOUT: Duration = Duration::from_secs(120);
const RETRY_INTERVAL: Duration = Duration::from_secs(15);

pub async fn submit_registration(router: &Router, domain: &str) -> Response<Body> {
    let body = json!({ "domain": domain });

    let request = Request::builder()
        .method("POST")
        .uri("/v1/domains")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();

    router.clone().oneshot(request).await.unwrap()
}

async fn get_status(router: &Router, domain: &str) -> Response<Body> {
    let uri = format!("/v1/domains/{domain}/status");

    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap();

    router.clone().oneshot(request).await.unwrap()
}

async fn delete_domain(router: &Router, domain: &str) -> Response<Body> {
    let uri = format!("/v1/domains/{domain}");

    let request = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap();

    router.clone().oneshot(request).await.unwrap()
}

async fn await_registration_ready(router: &Router, domain: &str) {
    let msg = &format!("awaiting registration for domain {domain}");
    let closure = || async {
        let response = get_status(router, domain).await;
        let body_bytes = to_bytes(response.into_body(), LIMIT).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        if body_str.contains("registered") {
            info!("registration is ready: {body_str}");
            return Ok(());
        }
        bail!("certificate is not ready yet");
    };

    retry_async(
        Some(msg),
        Some(Level::INFO),
        AWAIT_TIMEOUT,
        RETRY_INTERVAL,
        closure,
    )
    .await
    .map_err(|err| anyhow!("failed to await for registration: {err:?}"))
    .unwrap();
}

async fn await_registration_deletion(router: Router, domain: &str) {
    let msg = &format!("awaiting deletion of domain {domain}");
    let closure = || async {
        let response = get_status(&router, domain).await;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        bail!("domain is not deleted yet");
    };

    retry_async(
        Some(msg),
        Some(Level::INFO),
        AWAIT_TIMEOUT,
        RETRY_INTERVAL,
        closure,
    )
    .await
    .map_err(|err| anyhow!("failed to await for registration: {err:?}"))
    .unwrap();
}

fn setup_tracing() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");
}

#[tokio::test]
#[ignore]
async fn basic_registration_scenario() -> anyhow::Result<()> {
    // For this domain a certificate will be obtained
    let domain = &env::var("DOMAIN_NAME").expect("DOMAIN_NAME var is not set");
    // API cloudflare token is required to perform an acme dns-01 challenge
    let cloudflare_api_token =
        env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN var is not set");
    setup_tracing();
    // Initialize router
    let mock_time = Arc::new(MockTime::new(1));
    let state = Arc::new(State::new(mock_time));
    let validator = Arc::new(Validator::default());
    let registry = Registry::new_custom(Some("custom_domains".into()), None).unwrap();
    let router = create_router(state.clone(), validator.clone(), registry.clone(), true);

    info!("user submits domain={domain} for registration");
    let response = submit_registration(&router, domain).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    info!("user verifies domain is being processed");
    let response = get_status(&router, domain).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), LIMIT).await.unwrap();
    let body_str = std::str::from_utf8(&body_bytes).unwrap();
    assert!(body_str.contains("processing"));

    info!("starting worker, which peforms all tasks ...");
    let token = CancellationToken::new();
    let acme_client = Arc::new(AcmeClientConfig::new(cloudflare_api_token).build().await?);

    let worker = Worker::new(
        "hard_worker".to_string(),
        state,
        validator,
        acme_client,
        WorkerConfig::default(),
        registry,
        token.clone(),
    );
    spawn(async move { worker.run().await });

    info!("awaiting the worker to obtain a certificate ...");
    await_registration_ready(&router, domain).await;

    info!("user deletes the registration of domain={domain}");
    let response = delete_domain(&router, domain).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    info!("awaiting the worker to delete the registration ...");
    await_registration_deletion(router, domain).await;

    token.cancel();

    Ok(())
}
