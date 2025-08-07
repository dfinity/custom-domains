// Timestamp representing seconds in UTC since the UNIX epoch (January 1, 1970).
pub type UtcTimestamp = u64;

/// Trait for getting the current timestamp in UTC seconds since UNIX epoch.
pub trait UtcTimestampProvider: Send + Sync + std::fmt::Debug {
    fn unix_timestamp(&self) -> UtcTimestamp;
}
