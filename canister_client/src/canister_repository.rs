use std::sync::Arc;

use anyhow::anyhow;
use base::{
    traits::{
        cipher::CiphersCertificates,
        repository::{Repository, RepositoryError},
        time::UtcTimestamp,
    },
    types::{
        domain::{CustomDomain, DomainStatus, RegisteredDomain},
        task::{InputTask, ScheduledTask, TaskOutput, TaskResult},
    },
};
use candid::{Decode, Encode, Principal};
use canister_api::{
    FetchTaskResult as ApiFetchTaskResult, GetDomainStatusResult as ApiGetDomainStatusResult,
    InputTask as ApiInputTask, SubmitTaskResult as ApiSubmitTaskResult,
    TaskResult as ApiTaskResult, TryAddTaskResult as ApiTryAddTaskResult,
};
use derive_new::new;
use fqdn::FQDN;
use ic_agent::Agent;
use trait_async::trait_async;

#[derive(Debug, new)]
pub struct CanisterClient {
    agent: Agent,
    canister_id: Principal,
    certificate_cipher: Arc<dyn CiphersCertificates>,
}

impl CanisterClient {
    fn encrypt_field(&self, field_name: &str, data: &[u8]) -> Result<Vec<u8>, RepositoryError> {
        self.certificate_cipher.encrypt(data).map_err(|err| {
            RepositoryError::InternalError(anyhow!("failed to encrypt {field_name}: {err}"))
        })
    }
}

#[trait_async]
impl Repository for CanisterClient {
    async fn get_domain_status(
        &self,
        domain: &FQDN,
    ) -> Result<Option<DomainStatus>, RepositoryError> {
        let arg = Encode!(&domain.to_string()).unwrap();

        let result = self
            .agent
            .query(&self.canister_id, "get_domain_status")
            .with_arg(arg)
            .call()
            .await
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!("Canister query call failed: {err}"))
            })?;

        let response = Decode!(&result, ApiGetDomainStatusResult).map_err(|err| {
            RepositoryError::InternalError(anyhow!("Failed to decode canister response: {err}"))
        })?;

        let domain_status = response
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!(
                    "Failed to get domain status from canister: {err:?}"
                ))
            })?
            .map(DomainStatus::from);

        Ok(domain_status)
    }

    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError> {
        let arg = Encode!().unwrap();

        let result = self
            .agent
            .update(&self.canister_id, "fetch_next_task")
            .with_arg(arg)
            .call_and_wait()
            .await
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!("Canister update call failed: {err}"))
            })?;

        let response = Decode!(&result, ApiFetchTaskResult).map_err(|err| {
            RepositoryError::InternalError(anyhow!("Failed to decode canister response: {err}"))
        })?;

        let scheduled_task = response
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!(
                    "Failed to fetch task from canister: {err:?}"
                ))
            })?
            .map(ScheduledTask::from);

        Ok(scheduled_task)
    }

    async fn submit_task_result(&self, mut task_result: TaskResult) -> Result<(), RepositoryError> {
        // We encrypt certificate and private_key and pass the result further to the canister.
        if let Some(TaskOutput::Issue(issued_certificate)) = &mut task_result.output {
            issued_certificate.certificate =
                self.encrypt_field("certificate", &issued_certificate.certificate)?;

            issued_certificate.private_key =
                self.encrypt_field("private key", &issued_certificate.private_key)?;
        }

        let arg = Encode!(&ApiTaskResult::from(task_result)).map_err(|err| {
            RepositoryError::InternalError(anyhow!("Failed to encode task result: {err}"))
        })?;

        let result = self
            .agent
            .update(&self.canister_id, "submit_task_result")
            .with_arg(arg)
            .call_and_wait()
            .await
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!("Canister update call failed: {err}"))
            })?;

        Decode!(&result, ApiSubmitTaskResult)
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!("Failed to decode canister response: {err}"))
            })?
            .map_err(RepositoryError::from)?;

        Ok(())
    }

    async fn try_add_task(&self, input_task: InputTask) -> Result<(), RepositoryError> {
        let arg = Encode!(&ApiInputTask::from(input_task)).map_err(|err| {
            RepositoryError::InternalError(anyhow!("Failed to encode input task: {err}"))
        })?;

        let result = self
            .agent
            .update(&self.canister_id, "try_add_task")
            .with_arg(arg)
            .call_and_wait()
            .await
            .unwrap();

        Decode!(&result, ApiTryAddTaskResult)
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!("Failed to decode canister response: {err}"))
            })?
            .map_err(RepositoryError::from)?;

        Ok(())
    }

    async fn get_last_change_time(&self) -> Result<UtcTimestamp, RepositoryError> {
        todo!()
    }

    async fn all_registrations(&self) -> Result<Vec<RegisteredDomain>, RepositoryError> {
        todo!()
    }

    async fn all_registered_domains(&self) -> Result<Vec<CustomDomain>, RepositoryError> {
        todo!()
    }
}
