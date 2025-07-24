use std::{
    fmt::Display,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use tokio::time::sleep;
use tracing::{Level, debug, error, info, trace, warn};

pub async fn retry_async<F, Fut, R>(
    operation: Option<&str>,
    log_level: Option<Level>,
    timeout: Duration,
    backoff: Duration,
    f: F,
) -> Result<(usize, R), (usize, anyhow::Error)>
where
    Fut: Future<Output = anyhow::Result<R>>,
    F: Fn() -> Fut,
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
                    let op_name = operation.map(|op| format!(" \"{op}\"")).unwrap_or_default();
                    let err = anyhow!(
                        "Operation{op_name} timed out after {:?} on attempt {attempt}. Last error: {}",
                        start_time.elapsed(),
                        truncate_error_msg(&err)
                    );
                    return Err((attempt, err));
                }

                if let Some(op_name) = operation {
                    trace_msg(
                        log_level,
                        format!(
                            "Operation \"{op_name}\" failed on attempt {attempt}. Error: {}",
                            truncate_error_msg(&err)
                        ),
                    );
                }

                sleep(backoff).await;
                attempt += 1;
            }
        }
    }
}

fn truncate_error_msg(err: &anyhow::Error) -> String {
    let mut short_msg = err.to_string().replace('\n', "\\n ");
    short_msg.truncate(500);
    short_msg.push_str("...");
    short_msg
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
