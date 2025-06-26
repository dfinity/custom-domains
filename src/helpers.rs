use std::time::{Duration, Instant};

use tokio::time::sleep;
use tracing::info;

pub async fn retry_async<S: AsRef<str>, F, Fut, R>(
    msg: S,
    timeout: Duration,
    backoff: Duration,
    f: F,
) -> anyhow::Result<R>
where
    Fut: Future<Output = anyhow::Result<R>>,
    F: Fn() -> Fut,
{
    let msg = msg.as_ref();
    let mut attempt = 1;
    let start = Instant::now();
    info!(
        "Call \"{msg}\" is being retried for the maximum of {timeout:?} with a constant backoff of {backoff:?}"
    );
    loop {
        match f().await {
            Ok(v) => {
                info!(
                    "Call \"{msg}\" succeeded after {:?} on attempt {attempt}",
                    start.elapsed()
                );
                break Ok(v);
            }
            Err(err) => {
                let err_msg = err.to_string();
                if start.elapsed() > timeout {
                    break Err(err.context(format!(
                        "Call \"{msg}\" timed out after {:?} on attempt {attempt}. Last error: {err_msg}",
                        start.elapsed(),
                    )));
                }
                info!(
                    "Call \"{msg}\" failed on attempt {attempt}. Error: {}",
                    truncate_error_msg(err_msg)
                );
                sleep(backoff).await;
                attempt += 1;
            }
        }
    }
}

fn truncate_error_msg(err_str: String) -> String {
    let mut short_e = err_str.replace('\n', "\\n ");
    short_e.truncate(500);
    short_e.push_str("...");
    short_e
}
