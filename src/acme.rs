use std::{sync::Arc, time::Duration};

use anyhow::Context;
use ic_bn_lib::{
    http::dns::{Options, Resolver},
    tls::acme::{
        AcmeUrl,
        client::{Client, ClientBuilder},
        dns::TokenManagerDns,
        instant_acme::AccountCredentials,
    },
};

use ic_bn_lib::tls::acme::dns::cloudflare::Cloudflare;
use reqwest::Url;

const DEFAULT_POLL_ORDER_TIMEOUT: Duration = Duration::from_secs(140);
const DEFAULT_POLL_TOKEN_TIMEOUT: Duration = Duration::from_secs(140);
const DEFAULT_CLOUDFLARE_URL: &str = "https://api.cloudflare.com/client/v4/";

pub struct AcmeClientConfig {
    /// Cloudflare API token for authentication
    pub cloudflare_api_token: String,
    /// Base URL for Cloudflare API requests
    pub cloudflare_url: Url,
    /// ACME provider URL, e.g. staging letsencrypt https://acme-staging-v02.api.letsencrypt.org/directory
    pub acme_url: AcmeUrl,
    /// ACME account credentials
    pub acme_credentials: Option<AccountCredentials>,
    /// Whether to allow insecure TLS connections
    pub insecure_tls: bool,
    /// Timeout for polling ACME order status
    pub poll_order_timeout: Duration,
    /// Timeout for token polling, which verifies the dns record is correct
    pub poll_token_timeout: Duration,
}

impl AcmeClientConfig {
    pub fn new(cloudflare_api_token: String) -> Self {
        AcmeClientConfig {
            cloudflare_api_token,
            cloudflare_url: Url::parse(DEFAULT_CLOUDFLARE_URL).unwrap(),
            acme_url: AcmeUrl::LetsEncryptStaging,
            acme_credentials: None,
            insecure_tls: false,
            poll_order_timeout: DEFAULT_POLL_ORDER_TIMEOUT,
            poll_token_timeout: DEFAULT_POLL_TOKEN_TIMEOUT,
        }
    }

    pub fn with_cloudflare_url(mut self, url: Url) -> Self {
        self.cloudflare_url = url;
        self
    }

    pub fn with_acme_url(mut self, acme_url: AcmeUrl) -> Self {
        self.acme_url = acme_url;
        self
    }

    pub fn with_credentials(mut self, credentials: AccountCredentials) -> Self {
        self.acme_credentials = Some(credentials);
        self
    }

    pub fn with_insecure_tls(mut self, insecure: bool) -> Self {
        self.insecure_tls = insecure;
        self
    }

    pub fn with_poll_order_timeout(mut self, timeout: Duration) -> Self {
        self.poll_order_timeout = timeout;
        self
    }

    pub fn with_poll_token_timeout(mut self, timeout: Duration) -> Self {
        self.poll_token_timeout = timeout;
        self
    }
}

impl AcmeClientConfig {
    pub async fn build(self) -> anyhow::Result<Client> {
        let cloudflare = Arc::new(Cloudflare::new(
            self.cloudflare_url,
            self.cloudflare_api_token,
        )?);

        // DNS resolver
        let resolver_opts = Options::default();
        let dns_resolver = Resolver::new(resolver_opts);
        let token_manager = Arc::new(TokenManagerDns::new(Arc::new(dns_resolver), cloudflare));

        let builder = ClientBuilder::new(self.insecure_tls)
            .with_acme_url(self.acme_url.clone())
            .with_token_manager(token_manager);

        let builder = if let Some(credentials) = self.acme_credentials {
            builder
                .load_account(credentials)
                .await
                .with_context(|| "unable to load ACME account")?
        } else {
            let (builder, _) = builder
                .create_account("mailto:test_account@testing.org")
                .await?;
            builder
        };

        let client = builder
            .with_order_timeout(self.poll_order_timeout)
            .with_token_timeout(self.poll_token_timeout)
            .build()
            .await?;

        Ok(client)
    }
}
