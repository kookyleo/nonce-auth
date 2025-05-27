use std::time::{Duration, SystemTime, UNIX_EPOCH};
use turbosql::Turbosql;

/// A database record representing a used nonce with its metadata.
///
/// This struct represents a nonce that has been consumed by the server
/// to prevent replay attacks. Each record contains:
/// - The nonce value itself (typically a UUID)
/// - When it was created/consumed
/// - An optional context for business logic isolation
///
/// # Database Schema
///
/// This struct maps to the `noncerecord` table with the following schema:
/// ```sql
/// CREATE TABLE noncerecord (
///     rowid INTEGER PRIMARY KEY,
///     nonce TEXT NOT NULL,
///     created_at INTEGER NOT NULL,
///     context TEXT,
///     UNIQUE(nonce, context)
/// );
/// ```
///
/// The `UNIQUE(nonce, context)` constraint ensures that the same nonce
/// can be used in different contexts but only once per context.
///
/// # Context Isolation
///
/// The `context` field allows for logical separation of nonces across
/// different business scenarios. For example:
/// - API endpoints: `"api_v1"`, `"api_v2"`
/// - User actions: `"login"`, `"password_reset"`
/// - Form submissions: `"contact_form"`, `"payment_form"`
///
/// # Note
///
/// `NonceRecord` is an internal structure and is not exposed in the public API.
/// It is used internally by `NonceServer` for database operations.
#[derive(Turbosql, Default, Debug)]
pub(crate) struct NonceRecord {
    /// Primary key for the database record.
    /// This is automatically assigned by SQLite when the record is inserted.
    pub(crate) rowid: Option<i64>,

    /// The nonce value, typically a UUID string.
    /// This must be unique within the same context.
    pub(crate) nonce: String,

    /// Unix timestamp (seconds since epoch) when this nonce was created/consumed.
    /// Used for TTL calculations and cleanup operations.
    pub(crate) created_at: i64,

    /// Optional context string for logical separation of nonces.
    /// Allows the same nonce value to be used in different business contexts.
    /// If `None`, the nonce is considered to be in the global/default context.
    pub(crate) context: Option<String>,
}

impl NonceRecord {
    /// Creates a new `NonceRecord` instance.
    ///
    /// This constructor creates a new nonce record that can be inserted
    /// into the database. The `rowid` is set to `None` and will be
    /// automatically assigned by SQLite upon insertion.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce value, typically a UUID string
    /// * `created_at` - Unix timestamp when this nonce was created/consumed
    /// * `context` - Optional context string for logical separation
    ///
    /// # Returns
    ///
    /// A new `NonceRecord` instance ready for database insertion.
    ///
    /// # Note
    ///
    /// This is an internal method used by `NonceServer` and is not exposed in the public API.
    pub(crate) fn create(nonce: String, created_at: i64, context: Option<String>) -> Self {
        Self {
            rowid: None,
            nonce,
            created_at,
            context,
        }
    }

    /// Checks if this nonce record has expired based on the given TTL.
    ///
    /// A nonce is considered expired if the current time is greater than
    /// the creation time plus the TTL duration. Expired nonces should be
    /// cleaned up from the database and are no longer valid for use.
    ///
    /// # Arguments
    ///
    /// * `ttl` - The time-to-live duration for nonces
    ///
    /// # Returns
    ///
    /// * `true` - If the nonce has expired and should be cleaned up
    /// * `false` - If the nonce is still valid
    ///
    /// # Note
    ///
    /// This is an internal method used by `NonceServer` and is not exposed in the public API.
    pub(crate) fn is_expired(&self, ttl: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        now > self.created_at + ttl.as_secs() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_creation() {
        let nonce = "test-nonce-123".to_string();
        let created_at = 1234567890;
        let context = Some("test-context".to_string());

        let record = NonceRecord::create(nonce.clone(), created_at, context.clone());

        assert_eq!(record.nonce, nonce);
        assert_eq!(record.created_at, created_at);
        assert_eq!(record.context, context);
        assert_eq!(record.rowid, None);
    }

    #[test]
    fn test_record_creation_without_context() {
        let nonce = "test-nonce-456".to_string();
        let created_at = 1234567890;

        let record = NonceRecord::create(nonce.clone(), created_at, None);

        assert_eq!(record.nonce, nonce);
        assert_eq!(record.created_at, created_at);
        assert_eq!(record.context, None);
    }

    #[test]
    fn test_is_expired_not_expired() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let record = NonceRecord::create(
            "test-nonce".to_string(),
            now - 100, // Created 100 seconds ago
            None,
        );

        let ttl = Duration::from_secs(300); // 5 minutes TTL
        assert!(!record.is_expired(ttl));
    }

    #[test]
    fn test_is_expired_expired() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let record = NonceRecord::create(
            "test-nonce".to_string(),
            now - 400, // Created 400 seconds ago
            None,
        );

        let ttl = Duration::from_secs(300); // 5 minutes TTL
        assert!(record.is_expired(ttl));
    }

    #[test]
    fn test_is_expired_edge_case() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let record = NonceRecord::create(
            "test-nonce".to_string(),
            now - 301, // Created 301 seconds ago (1 second past TTL)
            None,
        );

        let ttl = Duration::from_secs(300);
        // Should be expired (now > created_at + ttl)
        assert!(record.is_expired(ttl));
    }

    #[test]
    fn test_is_expired_future_created_at() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let record = NonceRecord::create(
            "test-nonce".to_string(),
            now + 100, // Created in the future (shouldn't happen in practice)
            None,
        );

        let ttl = Duration::from_secs(300);
        assert!(!record.is_expired(ttl));
    }

    #[test]
    fn test_default_record() {
        let record = NonceRecord::default();

        assert_eq!(record.rowid, None);
        assert_eq!(record.nonce, "");
        assert_eq!(record.created_at, 0);
        assert_eq!(record.context, None);
    }
}
