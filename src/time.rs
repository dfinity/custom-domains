use std::sync::atomic::{AtomicU64, Ordering};

pub type Timestamp = u64;

/// Trait for getting the current timestamp in UTC seconds since UNIX epoch.
pub trait UnixTimestamp: Send + Sync {
    fn unix_timestamp(&self) -> Timestamp;
}

pub struct MockTime {
    timestamp: AtomicU64,
}

impl MockTime {
    pub fn new(time: Timestamp) -> Self {
        Self {
            timestamp: AtomicU64::new(time),
        }
    }
}

impl UnixTimestamp for MockTime {
    fn unix_timestamp(&self) -> Timestamp {
        self.timestamp.load(Ordering::SeqCst)
    }
}

impl MockTime {
    pub fn set_time(&self, timestamp: Timestamp) {
        self.timestamp.store(timestamp, Ordering::SeqCst);
    }
}
