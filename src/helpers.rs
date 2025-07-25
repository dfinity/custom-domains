use std::{
    fmt::Display,
    time::{Duration, Instant},
};

use anyhow::Result;
use tokio::time::sleep;
use tracing::{Level, debug, error, info, trace, warn};

#[derive(Debug)]
pub struct RetryTimeoutError<E> {
    pub attempts: usize,
    pub last_error: E,
}

pub async fn retry_async<F, Fut, R, E>(
    operation: Option<&str>,
    log_level: Option<Level>,
    timeout: Duration,
    backoff: Duration,
    f: F,
) -> Result<(usize, R), RetryTimeoutError<E>>
where
    Fut: Future<Output = Result<R, E>>,
    F: Fn() -> Fut,
    E: std::fmt::Debug,
{
    let log_level = log_level.unwrap_or(Level::INFO);
    let start_time = Instant::now();
    let mut attempt = 1;

    if let Some(op) = operation {
        trace_msg(
            log_level,
            format!("Retrying operation \"{op}\" for up to {timeout:?} with {backoff:?} backoff"),
        );
    }

    loop {
        match f().await {
            Ok(v) => {
                if let Some(op_name) = operation {
                    trace_msg(
                        log_level,
                        format!(
                            "Operation \"{op_name}\" succeeded after {:?} on attempt {attempt}",
                            start_time.elapsed()
                        ),
                    );
                }
                return Ok((attempt, v));
            }
            Err(err) => {
                if start_time.elapsed() > timeout {
                    return Err(RetryTimeoutError {
                        attempts: attempt,
                        last_error: err,
                    });
                }

                if let Some(op_name) = operation {
                    trace_msg(
                        log_level,
                        format!(
                            "Operation \"{op_name}\" failed on attempt {attempt}. Error: {err:?}"
                        ),
                    );
                }

                sleep(backoff).await;
                attempt += 1;
            }
        }
    }
}

pub fn trace_msg<M: Display>(level: Level, message: M) {
    match level {
        Level::ERROR => error!(message = %message),
        Level::WARN => warn!(message = %message),
        Level::INFO => info!(message = %message),
        Level::DEBUG => debug!(message = %message),
        Level::TRACE => trace!(message = %message),
    }
}

pub fn format_error_chain(err: &anyhow::Error) -> String {
    let mut s = format!("{err}");
    for cause in err.chain().skip(1) {
        s.push_str(&format!("\nCaused by: {cause}"));
    }
    s
}
