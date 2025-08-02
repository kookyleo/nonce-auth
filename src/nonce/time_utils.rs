//! Time utilities for safe timestamp handling.
//!
//! This module provides safe alternatives to direct SystemTime operations
//! that could potentially panic.

use std::time::{SystemTime, UNIX_EPOCH};

/// Get current timestamp in seconds since Unix epoch.
///
/// This function handles potential system time errors gracefully.
/// In the extremely rare case where system time is before Unix epoch,
/// it returns 0 instead of panicking.
pub(crate) fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_else(|_| {
            // This should never happen in practice, but handle it gracefully
            // by returning 0 (Unix epoch)
            0
        })
}

/// Check if a timestamp is expired based on TTL.
pub(crate) fn is_expired(created_at: i64, ttl_seconds: u64) -> bool {
    let now = current_timestamp();
    now - created_at > ttl_seconds as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        // Should be a reasonable timestamp (after year 2020)
        assert!(ts > 1577836800); // 2020-01-01 00:00:00 UTC
    }

    #[test]
    fn test_is_expired() {
        let now = current_timestamp();

        // Not expired
        assert!(!is_expired(now - 10, 60)); // Created 10 seconds ago, TTL 60s

        // Expired
        assert!(is_expired(now - 120, 60)); // Created 120 seconds ago, TTL 60s
    }
}
