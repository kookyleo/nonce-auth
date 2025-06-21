use async_trait::async_trait;
use std::time::Duration;

use crate::NonceError;

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
/// pub struct MemoryStorage {
///     data: Arc<RwLock<HashMap<String, NonceEntry>>>,
/// }
///
/// #[async_trait]
/// impl NonceStorage for MemoryStorage {
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
///             backend_info: "In-memory HashMap storage".to_string(),
///         })
///     }
/// }
/// ```
#[async_trait]
pub trait NonceStorage: Send + Sync {
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
}

/// A simple in-memory storage implementation for testing and demonstration.
///
/// This implementation uses a `HashMap` wrapped in `Arc<RwLock<>>` for
/// thread-safe access. It doesn't persist data across restarts and doesn't
/// implement automatic expiration (expired entries are only removed during
/// cleanup operations).
///
/// # Thread Safety
///
/// This implementation is fully thread-safe and can handle concurrent
/// operations from multiple threads.
///
/// # Usage
///
/// ```rust
/// use nonce_auth::storage::{MemoryStorage, NonceStorage};
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), nonce_auth::NonceError> {
/// let storage = MemoryStorage::new();
///
/// // Store a nonce
/// storage.set("test-nonce", None, Duration::from_secs(300)).await?;
///
/// // Check if it exists
/// let exists = storage.exists("test-nonce", None).await?;
/// assert!(exists);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct MemoryStorage {
    data: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, NonceEntry>>>,
}

impl MemoryStorage {
    /// Creates a new in-memory storage instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a storage key from nonce and context.
    fn make_key(nonce: &str, context: Option<&str>) -> String {
        format!("{}:{}", nonce, context.unwrap_or(""))
    }
}

#[async_trait]
impl NonceStorage for MemoryStorage {
    async fn get(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<Option<NonceEntry>, NonceError> {
        let key = Self::make_key(nonce, context);
        let data = self.data.read().await;
        Ok(data.get(&key).cloned())
    }

    async fn set(
        &self,
        nonce: &str,
        context: Option<&str>,
        _ttl: Duration,
    ) -> Result<(), NonceError> {
        let key = Self::make_key(nonce, context);
        let entry = NonceEntry {
            nonce: nonce.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            context: context.map(|s| s.to_string()),
        };

        let mut data = self.data.write().await;
        if data.contains_key(&key) {
            return Err(NonceError::DuplicateNonce);
        }
        data.insert(key, entry);
        Ok(())
    }

    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
        let key = Self::make_key(nonce, context);
        let data = self.data.read().await;
        Ok(data.contains_key(&key))
    }

    async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
        let mut data = self.data.write().await;
        let initial_count = data.len();
        data.retain(|_, entry| entry.created_at > cutoff_time);
        Ok(initial_count - data.len())
    }

    async fn get_stats(&self) -> Result<StorageStats, NonceError> {
        let data = self.data.read().await;
        Ok(StorageStats {
            total_records: data.len(),
            backend_info: "In-memory HashMap storage".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn test_memory_storage_basic_operations() -> Result<(), NonceError> {
        let storage = MemoryStorage::new();

        // Test set and exists
        storage
            .set("test-nonce", None, Duration::from_secs(300))
            .await?;
        assert!(storage.exists("test-nonce", None).await?);

        // Test get
        let entry = storage.get("test-nonce", None).await?;
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.nonce, "test-nonce");
        assert!(entry.context.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_memory_storage_duplicate_nonce() -> Result<(), NonceError> {
        let storage = MemoryStorage::new();

        // First set should succeed
        storage
            .set("test-nonce", None, Duration::from_secs(300))
            .await?;

        // Second set should fail
        let result = storage
            .set("test-nonce", None, Duration::from_secs(300))
            .await;
        assert!(matches!(result, Err(NonceError::DuplicateNonce)));

        Ok(())
    }

    #[tokio::test]
    async fn test_memory_storage_context_isolation() -> Result<(), NonceError> {
        let storage = MemoryStorage::new();

        // Same nonce, different contexts should work
        storage
            .set("test-nonce", Some("context1"), Duration::from_secs(300))
            .await?;
        storage
            .set("test-nonce", Some("context2"), Duration::from_secs(300))
            .await?;

        // Both should exist
        assert!(storage.exists("test-nonce", Some("context1")).await?);
        assert!(storage.exists("test-nonce", Some("context2")).await?);

        // But not in wrong context
        assert!(!storage.exists("test-nonce", Some("context3")).await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_memory_storage_cleanup() -> Result<(), NonceError> {
        let storage = MemoryStorage::new();

        // Add some nonces
        storage
            .set("old-nonce", None, Duration::from_secs(300))
            .await?;
        storage
            .set("new-nonce", None, Duration::from_secs(300))
            .await?;

        // Cleanup with cutoff time in the future should remove all
        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600;

        let removed = storage.cleanup_expired(future_time).await?;
        assert_eq!(removed, 2);

        // Both should be gone
        assert!(!storage.exists("old-nonce", None).await?);
        assert!(!storage.exists("new-nonce", None).await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_memory_storage_stats() -> Result<(), NonceError> {
        let storage = MemoryStorage::new();

        // Initial stats
        let stats = storage.get_stats().await?;
        assert_eq!(stats.total_records, 0);

        // Add some nonces
        storage
            .set("nonce1", None, Duration::from_secs(300))
            .await?;
        storage
            .set("nonce2", Some("context"), Duration::from_secs(300))
            .await?;

        // Updated stats
        let stats = storage.get_stats().await?;
        assert_eq!(stats.total_records, 2);
        assert!(stats.backend_info.contains("In-memory"));

        Ok(())
    }
}
