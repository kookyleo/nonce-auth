//! Pluggable storage backends for nonce persistence.
//!
//! This module provides a trait-based storage system that allows different
//! backends to be used for nonce persistence. The available backends depend
//! on the enabled features.

use crate::NonceError;
use async_trait::async_trait;
use std::time::Duration;

// Always available
mod memory;
pub use memory::MemoryStorage;

// Feature-gated storage backends
#[cfg(feature = "sqlite-storage")]
mod sqlite;
#[cfg(feature = "sqlite-storage")]
pub use sqlite::SqliteStorage;

#[cfg(feature = "redis-storage")]
mod redis;
#[cfg(feature = "redis-storage")]
pub use redis::RedisStorage;

/// Represents a stored nonce entry with its metadata.
#[derive(Debug, Clone)]
pub struct NonceEntry {
    /// The unique nonce value
    pub nonce: String,
    /// Unix timestamp when the nonce was created
    pub created_at: i64,
    /// Optional context for nonce scoping
    pub context: Option<String>,
}

/// Statistics about the nonce storage backend.
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// Total number of nonce records in storage
    pub total_records: usize,
    /// Additional backend-specific information
    pub backend_info: String,
}

/// Abstract storage backend for nonce persistence.
///
/// This trait defines the interface that all storage backends must implement
/// to work with the nonce authentication system. It provides operations for
/// storing, retrieving, and managing nonces with expiration support.
///
/// # Available Implementations
///
/// - [`MemoryStorage`] - Always available, in-memory HashMap-based storage
/// - `SqliteStorage` - Available with `sqlite-storage` feature, persistent SQLite storage
/// - `RedisStorage` - Available with `redis-storage` feature, distributed Redis storage
///
/// # Thread Safety
///
/// All methods are async and must be thread-safe. Implementations should
/// handle concurrent access properly.
///
/// # Error Handling
///
/// All methods return `Result<T, NonceError>` and should map backend-specific
/// errors to appropriate `NonceError` variants.
///
/// # Example Implementation
///
/// ```rust
/// use nonce_auth::storage::{NonceStorage, NonceEntry, StorageStats};
/// use nonce_auth::NonceError;
/// use async_trait::async_trait;
/// use std::collections::HashMap;
/// use std::sync::Arc;
/// use std::time::Duration;
/// use tokio::sync::RwLock;
///
/// #[derive(Default)]
/// pub struct CustomStorage {
///     data: Arc<RwLock<HashMap<String, NonceEntry>>>,
/// }
///
/// #[async_trait]
/// impl NonceStorage for CustomStorage {
///     async fn init(&self) -> Result<(), NonceError> {
///         // Initialize storage (create tables, connections, etc.)
///         Ok(())
///     }
///
///     async fn get(&self, nonce: &str, context: Option<&str>) -> Result<Option<NonceEntry>, NonceError> {
///         let key = format!("{}:{}", nonce, context.unwrap_or(""));
///         let data = self.data.read().await;
///         Ok(data.get(&key).cloned())
///     }
///
///     async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> {
///         let key = format!("{}:{}", nonce, context.unwrap_or(""));
///         let entry = NonceEntry {
///             nonce: nonce.to_string(),
///             created_at: std::time::SystemTime::now()
///                 .duration_since(std::time::UNIX_EPOCH)
///                 .unwrap()
///                 .as_secs() as i64,
///             context: context.map(|s| s.to_string()),
///         };
///         let mut data = self.data.write().await;
///         if data.contains_key(&key) {
///             return Err(NonceError::DuplicateNonce);
///         }
///         data.insert(key, entry);
///         Ok(())
///     }
///
///     async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
///         let key = format!("{}:{}", nonce, context.unwrap_or(""));
///         let data = self.data.read().await;
///         Ok(data.contains_key(&key))
///     }
///
///     async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
///         let mut data = self.data.write().await;
///         let initial_count = data.len();
///         data.retain(|_, entry| entry.created_at > cutoff_time);
///         Ok(initial_count - data.len())
///     }
///
///     async fn get_stats(&self) -> Result<StorageStats, NonceError> {
///         let data = self.data.read().await;
///         Ok(StorageStats {
///             total_records: data.len(),
///             backend_info: "Custom storage implementation".to_string(),
///         })
///     }
/// }
/// ```
#[async_trait]
pub trait NonceStorage: Send + Sync {
    /// Optional method for storage backend initialization.
    ///
    /// This method is called once when the storage backend is first used.
    /// Implementations can use this for tasks like schema creation,
    /// connection setup, etc.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If initialization succeeded
    /// * `Err(NonceError)` - If initialization failed
    async fn init(&self) -> Result<(), NonceError> {
        // Default implementation does nothing
        Ok(())
    }

    /// Retrieves a nonce entry if it exists.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce value to retrieve
    /// * `context` - Optional context for scoping the nonce
    ///
    /// # Returns
    ///
    /// * `Ok(Some(NonceEntry))` - If the nonce exists and is not expired
    /// * `Ok(None)` - If the nonce doesn't exist or has expired
    /// * `Err(NonceError)` - If there was an error accessing storage
    async fn get(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<Option<NonceEntry>, NonceError>;

    /// Stores a new nonce with expiration time.
    ///
    /// This method should atomically check for duplicates and insert the nonce.
    /// If the nonce already exists (considering context), it should return
    /// `NonceError::DuplicateNonce`.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce value to store
    /// * `context` - Optional context for scoping the nonce
    /// * `ttl` - Time-to-live duration for the nonce
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the nonce was successfully stored
    /// * `Err(NonceError::DuplicateNonce)` - If the nonce already exists
    /// * `Err(NonceError)` - If there was an error accessing storage
    async fn set(
        &self,
        nonce: &str,
        context: Option<&str>,
        ttl: Duration,
    ) -> Result<(), NonceError>;

    /// Checks if a nonce exists without retrieving it.
    ///
    /// This is an optimization method for cases where only existence
    /// checking is needed without the full entry data.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce value to check
    /// * `context` - Optional context for scoping the nonce
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If the nonce exists and is not expired
    /// * `Ok(false)` - If the nonce doesn't exist or has expired
    /// * `Err(NonceError)` - If there was an error accessing storage
    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError>;

    /// Removes all expired nonces from storage.
    ///
    /// This method should remove all nonces that were created before
    /// the specified cutoff time.
    ///
    /// # Arguments
    ///
    /// * `cutoff_time` - Unix timestamp; nonces created before this time should be removed
    ///
    /// # Returns
    ///
    /// * `Ok(count)` - Number of nonces that were removed
    /// * `Err(NonceError)` - If there was an error accessing storage
    async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError>;

    /// Returns statistics about the storage backend.
    ///
    /// This method provides insight into the current state of the storage
    /// backend, which can be useful for monitoring and debugging.
    ///
    /// # Returns
    ///
    /// * `Ok(StorageStats)` - Current storage statistics
    /// * `Err(NonceError)` - If there was an error accessing storage
    async fn get_stats(&self) -> Result<StorageStats, NonceError>;
}
