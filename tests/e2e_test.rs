use std::collections::HashSet;
use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use async_trait::async_trait;
use backend::router::create_router;
use base::traits::repository::Repository;
use base::types::domain::RegistrationStatus;
use base::{
    traits::validation::{ValidatesDomains, ValidationError},
    types::{
        cipher::CertificateCipher,
        worker::{Worker, WorkerConfig, WorkerMetrics},
    },
};
use candid::Principal;
use canister_client::canister_client::CanisterClient;
use chacha20poly1305::{aead::OsRng, KeyInit, XChaCha20Poly1305};
use fqdn::FQDN;
use ic_agent::Agent;
use ic_bn_lib::reqwest;
use ic_bn_lib::{
    tests::pebble::{dns::TokenManagerPebble, Env},
    tls::acme::{
        client::{AcmeCertificateClient, ClientBuilder},
        AcmeUrl, TokenManager,
    },
};
use pem::parse_many;
use prometheus::Registry;
use serde_json::json;
use tokio::{spawn, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::info;
use x509_parser::{parse_x509_certificate, prelude::GeneralName};

mod helpers;
use helpers::init_logging;

use crate::helpers::TestEnv;

const DOMAINS_COUNT: usize = 100;
const WORKERS_COUNT: usize = 10;

struct MockValidator;

#[async_trait]
impl ValidatesDomains for MockValidator {
    async fn validate(&self, _domain: &FQDN) -> Result<Principal, ValidationError> {
        Ok("laqa6-raaaa-aaaam-aehzq-cai".parse().unwrap())
    }

    async fn validate_deletion(&self, _domain: &FQDN) -> Result<(), ValidationError> {
        Ok(())
    }
}

// Title: Custom Domains with Pebble ACME test server and multiple workers processing registration requests in parallel
// Setup:
// - Start Pocket IC and install the Custom Domains canister
// - Start HTTP Gateway server on top of Pocket IC to acc
// - Start pebble ACME test server issuing certificates
// - Start one backend API server accepting domain registration requests
// - Start N=30 workers polling the canister for tasks, executing them and submitting results back to the canister
// Steps:
// 1. Submit N=500 domains for registration via the API
//    Each worker should pick up tasks and obtain certificates in parallel
// 2. Verify that all domains have been registered and certificates obtained
// 3. Verify all certificates are valid and match the requested domains
// 4. Delete half of the domains via the API and verify they are removed from the canister
// 5. Get canister metrics and verify the the expected of registered domains is correct

async fn create_acme_client(
    addr_acme: String,
    token_manager: Arc<dyn TokenManager>,
) -> anyhow::Result<Arc<dyn AcmeCertificateClient>> {
    let builder = ClientBuilder::new(true)
        .with_acme_url(AcmeUrl::Custom(format!("https://{addr_acme}/dir").parse()?))
        .with_token_manager(token_manager);

    let (builder, _contract) = builder.create_account("mailto:foo@bar.com").await?;

    let acme_client = builder
        .build()
        .await
        .with_context(|| "failed to build ACME client")?;

    Ok(Arc::new(acme_client))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_pebble_test() -> anyhow::Result<()> {
    init_logging();

    info!("Starting Pocket IC and installing custom domains canister ...");
    let sender = Principal::anonymous();
    let authorized_principal = Some(sender);
    let mut env = TestEnv::new(authorized_principal, sender).await?;
    let ic_url = env.pic.make_live_with_params(None, None, None, None).await;
    info!("Pocket IC HTTP Gateway running at {ic_url}");

    info!("Starting Pebble ACME server and DNS challenge test server ...");
    let pebble_env = Env::new().await;
    info!(
        "Pebble test environment started: ACME server at {}, DNS management server at {}",
        pebble_env.addr_acme(),
        pebble_env.addr_dns_management()
    );

    // Create DNS token manager pointing to Pebble DNS server
    let token_manager = Arc::new(TokenManagerPebble::new(
        format!("http://{}", pebble_env.addr_dns_management()).parse()?,
    ));

    // Create ACME client pointing to Pebble ACME server
    info!("Creating ACME client for Pebble server ...");
    let acme_client = create_acme_client(pebble_env.addr_acme(), token_manager.clone()).await?;

    // Domains for registration
    let domains = (1..=DOMAINS_COUNT)
        .map(|i| format!("custom-domain-{i}.example.com"))
        .collect::<Vec<_>>();

    // Setup workers
    let cancellation_token = CancellationToken::new();
    let agent = Agent::builder().with_url(ic_url).build()?;
    let root_key = env.pic.root_key().await.expect("failed to get root key");
    agent.set_root_key(root_key);
    let cipher = {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = CertificateCipher::new_with_key(&key);
        Arc::new(cipher)
    };
    let repository = Arc::new(CanisterClient::new(agent, env.canister_id, cipher));
    let prometheus_registry = Registry::new_custom(Some("custom_domains".into()), None).unwrap();
    let metrics = Arc::new(WorkerMetrics::new(prometheus_registry.clone()));
    let validator = Arc::new(MockValidator);

    info!("Spawning {WORKERS_COUNT} workers ...");
    for i in 0..WORKERS_COUNT {
        let worker = Worker::new(
            format!("worker_{}", i + 1),
            repository.clone(),
            validator.clone(),
            acme_client.clone(),
            WorkerConfig::default(),
            metrics.clone(),
            cancellation_token.clone(),
        );

        spawn(async move { worker.run().await });
    }

    // Spawn the API server
    let api_addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let repository_cloned = repository.clone();
    let _handle = spawn(async move {
        let router = create_router(repository_cloned, validator, prometheus_registry, true);
        info!("Starting API server at http://{}", api_addr);
        axum_server::bind(api_addr)
            .serve(router.into_make_service())
            .await
    });

    sleep(Duration::from_secs(5)).await;

    info!("Step 1: Submitting {DOMAINS_COUNT} domains for registration via API ...");
    let client = reqwest::Client::new();
    let mut task_handles = vec![];
    for domain in domains.clone() {
        let client_cloned = client.clone();
        let handle = spawn(async move {
            client_cloned
                .post(format!(
                    "http://{}:{}/v1/domains",
                    api_addr.ip(),
                    api_addr.port()
                ))
                .header("Content-Type", "application/json")
                .json(&json!({"domain": domain}))
                .send()
                .await
                .unwrap()
        });
        task_handles.push(handle);
    }

    for handle in task_handles {
        let response = handle.await?;
        assert!(response.status().is_success());
    }

    while repository.has_next_task().await? {
        let duration = Duration::from_secs(10);
        info!("Waiting for workers to process remaining tasks, sleeping {duration:?} ...");
        sleep(duration).await;
    }

    info!("Step 2: Verifying that all domains have been registered and certificates obtained ...");
    for domain in &domains {
        loop {
            let status = repository
                .get_domain_status(&domain.parse()?)
                .await?
                .context("Domain not found")?;
            if status.status == RegistrationStatus::Registered {
                break;
            }
        }
    }

    info!("Step 3: Verifying all certificates are valid and match the requested domains ...");
    let registered_domains = repository.all_registrations().await?;
    let mut domains_set: HashSet<String> = HashSet::from_iter(domains.clone());
    for registered_domain in registered_domains {
        let domain = extract_domain_from_cert(registered_domain.cert)?;
        assert!(domains_set.remove(&domain));
    }
    assert!(domains_set.is_empty());
    info!("All {DOMAINS_COUNT} certificates were issued successfully by Pebble ACME server");

    info!("Step 4: Deleting half of the domains via API and verifying they are removed from the canister ...");
    let domains_to_delete = &domains[..(DOMAINS_COUNT / 2)];
    for domain in domains_to_delete {
        let response = client
            .delete(format!(
                "http://{}:{}/v1/domains/{}",
                api_addr.ip(),
                api_addr.port(),
                domain
            ))
            .send()
            .await?;
        assert!(response.status().is_success());
    }

    for domain in domains_to_delete {
        while let Some(_domain_status) = repository.get_domain_status(&domain.parse()?).await? {
            sleep(Duration::from_millis(50)).await;
        }
    }
    info!("Half of the domains ({DOMAINS_COUNT}/2) were deleted successfully");

    info!("Step 5: Getting canister metrics and verifying they are reasonable ...");
    let metrics_text = client
        .get(format!(
            "http://{}.raw.{}:{}/metrics",
            env.canister_id,
            api_addr.ip(),
            api_addr.port()
        ))
        .send()
        .await?
        .text()
        .await?;
    assert!(metrics_text.contains(
        &format!(
            "domains_total{{registration_status=\"registered\"}} {}",
            DOMAINS_COUNT / 2
        )
    ));
    assert!(metrics_text.contains("domains_total{registration_status=\"expired\"} 0"));
    assert!(metrics_text.contains("domains_total{registration_status=\"failed\"} 0"));
    assert!(metrics_text.contains("domains_total{registration_status=\"registering\"} 0"));

    Ok(())
}

fn extract_domain_from_cert(cert: Vec<u8>) -> anyhow::Result<String> {
    // Parse certificate chain
    let pem_str =
        std::str::from_utf8(&cert).with_context(|| "Certificate contains invalid UTF-8")?;

    let pems = parse_many(pem_str).with_context(|| "Failed to parse PEM certificates")?;

    let Some(first_cert) = pems.first() else {
        bail!("No certificates found in PEM chain");
    };

    // Extract validity period
    let (_, cert) = parse_x509_certificate(first_cert.contents())
        .with_context(|| "Failed to parse X509 certificate")?;

    // Validate that issued certificate is for the requested domain
    let subject_alt_names = cert
        .subject_alternative_name()?
        .map(|ext| &ext.value.general_names)
        .with_context(|| "Certificate has no Subject Alternative Name")?;

    let cert_domains: Vec<String> = subject_alt_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect();

    Ok(cert_domains[0].clone())
}
