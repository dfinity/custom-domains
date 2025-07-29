use prometheus::{
    GaugeVec, HistogramVec, IntCounterVec, Registry, register_gauge_vec_with_registry,
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
};

#[derive(Clone)]
pub struct WorkerMetrics {
    pub task_executions: HistogramVec,
    pub task_submissions: IntCounterVec,
    pub task_fetches: IntCounterVec,
    pub worker_utilization: GaugeVec,
}

pub const TASK_DURATION_BUCKETS: &[f64] = &[5.0, 30.0, 60.0, 90.0, 120.0, 180.0, 300.0, 400.0];

impl WorkerMetrics {
    pub fn new(registry: Registry) -> Self {
        Self {
            task_executions: register_histogram_vec_with_registry!(
                "task_execution_duration_seconds",
                "Task execution durations in seconds",
                &["worker_name", "task_kind", "status", "failure"],
                TASK_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
            task_submissions: register_int_counter_vec_with_registry!(
                "task_submission_with_retries",
                "Total number of task submission (with retries)",
                &[
                    "worker_name",
                    "task_kind",
                    "status",
                    "attempts",
                    "last_failure"
                ],
                registry
            )
            .unwrap(),
            task_fetches: register_int_counter_vec_with_registry!(
                format!("task_fetch"),
                format!("Total number of task fetching attempts"),
                &["worker_name", "status", "failure"],
                registry
            )
            .unwrap(),
            worker_utilization: register_gauge_vec_with_registry!(
                "worker_utilization_percent",
                "Worker utilization percentage",
                &["worker_name"],
                registry
            )
            .unwrap(),
        }
    }
}
