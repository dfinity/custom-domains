use anyhow::Result;
use ic_bn_lib::{
    http::dns::{Options, Resolver},
    tls::acme::{
        AcmeUrl,
        client::{Client, ClientBuilder},
        dns::{TokenManagerDns, cloudflare::Cloudflare},
    },
};
use reqwest::Url;
use std::{env, sync::Arc};

const CLOUDFLARE_URL: &str = "https://api.cloudflare.com/client/v4/";
const INSECURE_TLS: bool = false;

pub async fn create_acme_client() -> Result<Client> {
    let api_token = env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN var is not set");
    let cloudflare_url = Url::parse(CLOUDFLARE_URL)?;
    let cloudflare = Arc::new(Cloudflare::new(cloudflare_url, api_token)?);
    let resolver_opts = Options::default();
    let resolver = Resolver::new(resolver_opts);
    let token_manager = Arc::new(TokenManagerDns::new(Arc::new(resolver), cloudflare));
    // TODO: make configurable
    let acme_url = AcmeUrl::LetsEncryptStaging;

    let builder = ClientBuilder::new(INSECURE_TLS)
        .with_acme_url(acme_url)
        .with_token_manager(token_manager);

    // TODO: save/load account
    let (builder, _) = builder
        .create_account("mailto:test_account@testing.org")
        .await?;

    let client = builder.build().await?;

    Ok(client)
}
