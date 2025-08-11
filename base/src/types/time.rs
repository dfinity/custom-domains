use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;

use crate::traits::time::{UtcTimestamp, UtcTimestampProvider};

/// Mock time provider for testing that allows setting a specific timestamp.
#[derive(Debug)]
pub struct MockTime {
    timestamp: AtomicU64,
}

/// System time provider that returns the actual current UTC timestamp.
#[derive(Debug)]
pub struct SystemTime;

impl UtcTimestampProvider for SystemTime {
    fn unix_timestamp(&self) -> UtcTimestamp {
        Utc::now().timestamp() as UtcTimestamp
    }
}

impl MockTime {
    /// Creates a new mock time provider with the given timestamp.
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
    /// Updates the mock time to a new timestamp.
    pub fn set_time(&self, timestamp: UtcTimestamp) {
        self.timestamp.store(timestamp, Ordering::SeqCst);
    }
}
