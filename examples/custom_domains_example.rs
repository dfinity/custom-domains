use std::{env, net::SocketAddr, sync::Arc};

use backend::router::create_router;
use base::types::{
    acme::AcmeClientConfig,
    cipher::CertificateCipher,
    validator::Validator,
    worker::{Worker, WorkerConfig},
};
use canister_client::canister_client::CanisterClient;
use chacha20poly1305::{aead::OsRng, KeyInit, XChaCha20Poly1305};
use ic_agent::Agent;
use prometheus::Registry;
use tokio::spawn;
use tokio_util::sync::CancellationToken;
use tracing::info;

// This example demonstrates how to run custom domains service with the backend server, worker and canister.
// 1. Deploy the canister with `dfx deploy` and set the environment variable `CANISTER_ID` to the canister ID.
// 2. Set the CLOUDFLARE_API_TOKEN environment variable
// 3. Run the example with `cargo run --example custom_domains_example`
// 4. Submit a domain registration request via the API:
// curl -v -X POST http://127.0.0.1:3000/v1/domains \
// -H "Content-Type: application/json" \
// -d '{"domain": "custom_domain.com"}' | jq

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let canister_id = env::var("CANISTER_ID").expect("CANISTER_ID var is not set");
    let cloudflare_api_token =
        env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN var is not set");
    let cipher = {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = CertificateCipher::new_with_key(&key);
        Arc::new(cipher)
    };
    let agent = Agent::builder().with_url("https://ic0.app").build()?;
    let canister_id = canister_id.parse().expect("Invalid CANISTER_ID format");
    let repository = Arc::new(CanisterClient::new(agent, canister_id, cipher));
    let validator = Arc::new(Validator::default());

    info!("starting worker, which peforms all tasks ...");
    let token = CancellationToken::new();
    let acme_client = Arc::new(AcmeClientConfig::new(cloudflare_api_token).build().await?);
    let registry = Registry::new_custom(Some("custom_domains".into()), None).unwrap();
    let worker = Worker::new(
        "worker_1".to_string(),
        repository.clone(),
        validator.clone(),
        acme_client,
        WorkerConfig::default(),
        registry.clone(),
        token.clone(),
    );

    spawn(async move { worker.run().await });

    let app = create_router(repository.clone(), validator, registry, true);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    info!("Starting server on http://{}", addr);
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
