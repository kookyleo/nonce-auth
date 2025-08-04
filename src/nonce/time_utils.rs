//! Time utilities for safe timestamp handling.
//!
//! This module provides safe alternatives to direct SystemTime operations
//! that could potentially panic.

use crate::nonce::error::NonceError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Get current timestamp in seconds since Unix epoch.
///
/// This function handles potential system time errors gracefully.
/// In the extremely rare case where system time is before Unix epoch,
/// it returns an error instead of panicking.
pub(crate) fn current_timestamp() -> Result<i64, NonceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| NonceError::CryptoError("System time is before Unix epoch".to_string()))
}

/// Check if a timestamp is expired based on TTL.
#[allow(dead_code)]
pub(crate) fn is_expired(created_at: i64, ttl_seconds: u64) -> bool {
    let now = current_timestamp().unwrap_or(0);
    now - created_at > ttl_seconds as i64
}

/// Check if a timestamp is outside the allowed time window.
pub(crate) fn is_outside_window(timestamp: u64, current_time: i64, time_window: Duration) -> bool {
    let timestamp_i64 = timestamp as i64;
    let window_seconds = time_window.as_secs() as i64;

    // Check if timestamp is too old or too far in the future
    (current_time - timestamp_i64) > window_seconds
        || (timestamp_i64 - current_time) > window_seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp().unwrap();
        // Should be a reasonable timestamp (after year 2020)
        assert!(ts > 1577836800); // 2020-01-01 00:00:00 UTC
    }

    #[test]
    fn test_is_expired() {
        let now = current_timestamp().unwrap();

        // Not expired
        assert!(!is_expired(now - 10, 60)); // Created 10 seconds ago, TTL 60s

        // Expired
        assert!(is_expired(now - 120, 60)); // Created 120 seconds ago, TTL 60s
    }

    #[test]
    fn test_is_outside_window() {
        let now = current_timestamp().unwrap();
        let window = Duration::from_secs(60);

        // Within window
        assert!(!is_outside_window((now - 30) as u64, now, window));

        // Outside window (too old)
        assert!(is_outside_window((now - 120) as u64, now, window));

        // Outside window (too far in future)
        assert!(is_outside_window((now + 120) as u64, now, window));
    }
}
