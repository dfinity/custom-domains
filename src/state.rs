use anyhow::anyhow;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use trait_async::trait_async;

use crate::{
    repository::{DomainEntry, Repository, RepositoryError},
    task::{Domain, Task, TaskName, TaskResult, TaskStatus},
};

#[derive(Default)]
pub struct State {
    storage: Arc<Mutex<HashMap<Domain, DomainEntry>>>,
}

#[trait_async]
impl Repository for State {
    async fn get_domain(&self, domain: Domain) -> Result<Option<DomainEntry>, RepositoryError> {
        let mutex = self.storage.lock().unwrap();
        let entry = mutex.get(&domain).cloned();
        Ok(entry)
    }

    async fn fetch_next_task(&self) -> Result<Option<Task>, RepositoryError> {
        let mutex = self.storage.lock().unwrap();
        if let Some((domain, entry)) = mutex.iter().next() {
            if let Some(task_name) = entry.task {
                let task = Task::new(task_name, domain.clone());
                return Ok(Some(task));
            }
        }
        Ok(None)
    }

    async fn submit_task_result(&self, task_result: TaskResult) -> Result<(), RepositoryError> {
        let mut mutex = self.storage.lock().unwrap();

        match task_result.task.name {
            TaskName::Create => {
                if task_result.status == TaskStatus::Succeeded {
                    if let Some(entry) = mutex.get_mut(&task_result.task.domain_name) {
                        entry.certificate = task_result.certificate;
                        entry.task = None;
                    }
                }
            }
            TaskName::Delete => {
                if task_result.status == TaskStatus::Succeeded {
                    let domain = task_result.task.domain_name;
                    if mutex.remove(&domain).is_none() {
                        return Err(RepositoryError::DomainNotFound);
                    }
                }
            }
            _ => todo!(),
        }
        Err(anyhow!("TODO").into())
    }

    async fn try_add_task(&self, task: Task) -> Result<(), RepositoryError> {
        let mut mutex = self.storage.lock().unwrap();
        let domain = task.domain_name;
        let entry = DomainEntry::new(Some(task.name), None);
        mutex.insert(domain, entry);
        Ok(())
    }
}
