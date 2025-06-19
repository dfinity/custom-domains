use thiserror::Error;
use trait_async::trait_async;

use crate::task::Domain;

pub struct DomainEntry {}

#[derive(Debug, Error)]
pub enum RepositoryError {}

#[trait_async]
pub trait DomainRepository: Send + Sync {
    async fn get(&self, domain: Domain) -> Result<Option<DomainEntry>, RepositoryError>;
}
