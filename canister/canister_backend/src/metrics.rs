use std::{borrow::BorrowMut, cell::RefCell};

use ic_cdk::api::{
    canister_balance,
    stable::{stable_size, WASM_PAGE_SIZE_IN_BYTES},
};
use ic_http_types::{HttpResponse, HttpResponseBuilder};
use prometheus::{
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    register_gauge_with_registry, register_int_gauge_with_registry, CounterVec, Encoder, Gauge,
    GaugeVec, IntGauge, Registry, Result as PrometheusResult, TextEncoder,
};

use crate::state::with_state;

pub const TRY_ADD_TASK_FUNC: &str = "try_add_task";
pub const FETCH_NEXT_TASK_FUNC: &str = "fetch_next_task";
pub const SUBMIT_TASK_RESULT_FUNC: &str = "submit_task_result";
pub const SUCCESS_STATUS: &str = "success";
pub const FAILURE_STATUS: &str = "failure";

thread_local! {
    pub static METRICS: RefCell<CanisterMetrics> = RefCell::new(CanisterMetrics::new().expect("failed to create Prometheus metrics"));
}

pub enum MetricsName {
    CanisterApiCalls,
    DomainsTotal,
}

pub fn update_metrics(name: MetricsName, labels: &[&str], value: Option<f64>) {
    METRICS.with(|cell| {
        let metrics = cell.borrow();
        match name {
            MetricsName::CanisterApiCalls => {
                metrics.canister_api_calls.with_label_values(labels).inc();
            }
            MetricsName::DomainsTotal => {
                let v = value.unwrap_or(0.0);
                metrics.domains_total.with_label_values(labels).set(v);
            }
        }
    });
}

/// Represents all metrics collected in the canister
pub struct CanisterMetrics {
    pub registry: Registry, // Prometheus registry
    pub cycle_balance: Gauge,
    pub canister_api_calls: CounterVec,
    pub domains_total: GaugeVec,
    pub tasks_total: GaugeVec,
    pub stable_memory_size: Gauge,
    pub last_upgrade_time: IntGauge,
    pub last_stale_domains_cleanup: IntGauge,
}

impl CanisterMetrics {
    pub fn new() -> PrometheusResult<Self> {
        let registry = Registry::new();

        let cycle_balance = register_gauge_with_registry!(
            "cycle_balance",
            "Amount of funds available in the canister.",
            &registry
        )?;

        let canister_api_calls = register_counter_vec_with_registry!(
            "canister_api_calls",
            "Total number of API calls made to the canister by status, task_kind, and error (in case of failure).",
            &["method", "status", "task_kind", "error"],
            &registry,
        )?;

        let domains_total = register_gauge_vec_with_registry!(
            "domains_total",
            "Total number of domains by status.",
            // status:
            //  - processing: domain is being processed, has a task
            //  - registered: domain has valid certificate
            //  - expired: has an expired certificate (TODO)
            //  - failed: has no certificate and no task
            &["registration_status"],
            &registry,
        )?;

        let tasks_total = register_gauge_vec_with_registry!(
            "tasks_total",
            "Total number of tasks by: kind, status, attempt and last_fail_reason (e.g. timeout, rate-limit).",
            // status:
            //  - pending: task is Some, taken_at is None
            //  - in_progress: task is Some, taken_at is Some
            //  - completed: last_task (to be added to DomainEntry) is Some, task is None
            //  - failed: last_task is Some, task is None and last_failure_reason is Some
            &["task_kind", "status", "attempt", "last_fail_reason"],
            &registry,
        )?;

        let stable_memory_size = register_gauge_with_registry!(
            "stable_memory_bytes",
            "Size of the stable memory allocated by this canister in bytes.",
            &registry,
        )?;

        let last_upgrade_time = register_int_gauge_with_registry!(
            "last_upgrade_time",
            "The Unix timestamp of the last successful canister upgrade",
            &registry,
        )?;

        let last_stale_domains_cleanup = register_int_gauge_with_registry!(
            "last_stale_domains_cleanup",
            "The Unix timestamp of the last stale domains cleanup",
            &registry,
        )?;

        Ok(Self {
            registry,
            cycle_balance,
            canister_api_calls,
            domains_total,
            tasks_total,
            stable_memory_size,
            last_upgrade_time,
            last_stale_domains_cleanup,
        })
    }
}

pub fn export_metrics_as_http_response() -> HttpResponse {
    // Certain metrics need to be recomputed
    recompute_metrics();

    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let registry = METRICS.with(|cell| cell.borrow().registry.clone());
    let metrics_family = registry.gather();

    match encoder.encode(&metrics_family, &mut buffer) {
        Ok(()) => HttpResponseBuilder::ok()
            .header("Content-Type", "text/plain")
            .with_body_and_content_length(buffer)
            .build(),
        Err(err) => {
            // Return an HTTP 500 error with detailed error information
            HttpResponseBuilder::server_error(format!("Failed to encode metrics: {err:?}")).build()
        }
    }
}

pub fn recompute_metrics() {
    METRICS.with(|cell| {
        let memory = (stable_size() * WASM_PAGE_SIZE_IN_BYTES) as f64;

        let mut cell = cell.borrow_mut();
        cell.stable_memory_size.borrow_mut().set(memory);
        cell.cycle_balance.set(canister_balance() as f64);

        let statuses = with_state(|state| state.domain_statuses());
        for (domain_status, count) in statuses.iter() {
            cell.domains_total
                .with_label_values(&[domain_status])
                .set(*count as f64);
        }
    });
}
