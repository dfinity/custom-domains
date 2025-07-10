use std::sync::atomic::{AtomicU64, Ordering};

// Timestamp representing seconds in UTC since the UNIX epoch (January 1, 1970).
pub type UtcTimestamp = u64;

/// Trait for getting the current timestamp in UTC seconds since UNIX epoch.
pub trait UtcTimestampProvider: Send + Sync {
    fn unix_timestamp(&self) -> UtcTimestamp;
}

pub struct MockTime {
    timestamp: AtomicU64,
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
