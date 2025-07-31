use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use derive_new::new;

use crate::traits::time::{UtcTimestamp, UtcTimestampProvider};

#[derive(Debug)]
pub struct MockTime {
    timestamp: AtomicU64,
}

#[derive(Debug, new)]
pub struct SystemTime {}

impl UtcTimestampProvider for SystemTime {
    fn unix_timestamp(&self) -> UtcTimestamp {
        Utc::now().timestamp() as UtcTimestamp
    }
}

impl MockTime {
    pub fn new(time: UtcTimestamp) -> Self {
        Self {
            timestamp: AtomicU64::new(time),
        }
    }
}

impl UtcTimestampProvider for MockTime {
    fn unix_timestamp(&self) -> UtcTimestamp {
        self.timestamp.load(Ordering::SeqCst)
    }
}

impl MockTime {
    pub fn set_time(&self, timestamp: UtcTimestamp) {
        self.timestamp.store(timestamp, Ordering::SeqCst);
    }
}
