//! In-memory storage backend implementation.
//!
//! This module provides a simple in-memory storage backend that uses a HashMap
//! for nonce persistence. It's ideal for testing, development, and single-instance
//! applications where persistence across restarts is not required.

use super::{NonceEntry, NonceStorage, StorageStats};
use crate::NonceError;
use crate::nonce::time_utils;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::Duration;

/// A simple in-memory storage implementation for testing and single-instance applications.
///
/// This implementation uses a `HashMap` wrapped in `Arc<RwLock<>>` for
/// thread-safe access. It doesn't persist data across restarts and doesn't
/// implement automatic expiration (expired entries are only removed during
/// cleanup operations).
///
/// # Features
///
/// - **Zero dependencies**: No external storage dependencies required
/// - **Thread-safe**: Uses tokio's RwLock for concurrent access
/// - **Fast operations**: All operations are in-memory and very fast
/// - **Context isolation**: Supports nonce namespacing via contexts
/// - **No persistence**: Data is lost when the application restarts
/// - **Pre-allocated capacity**: Optional capacity hint for better performance
/// - **Batch operations**: Support for bulk operations
///
/// # Use Cases
///
/// - Development and testing environments
/// - Single-instance applications with short-lived nonces
/// - Applications that don't require persistence across restarts
/// - Proof-of-concept implementations
///
/// # Example
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
///
/// // Get the entry
/// let entry = storage.get("test-nonce", None).await?;
/// assert!(entry.is_some());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct MemoryStorage {
    data: std::sync::Arc<tokio::sync::RwLock<HashMap<String, NonceEntry>>>,
}

impl MemoryStorage {
    /// Creates a new in-memory storage instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::storage::MemoryStorage;
    ///
    /// let storage = MemoryStorage::new();
    /// ```
    pub fn new() -> Self {
        Self {
            data: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Creates a new in-memory storage instance with pre-allocated capacity.
    ///
    /// This can improve performance when you know approximately how many nonces
    /// you'll be storing, as it avoids HashMap reallocations.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Initial capacity hint for the internal HashMap
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::storage::MemoryStorage;
    ///
    /// // Pre-allocate for ~1000 nonces
    /// let storage = MemoryStorage::with_capacity(1000);
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::with_capacity(capacity))),
        }
    }

    /// Creates a storage key from nonce and context.
    ///
    /// The key format is "nonce:context" where context defaults to empty string.
    /// This ensures that the same nonce can exist in different contexts.
    fn make_key(nonce: &str, context: Option<&str>) -> String {
        match context {
            Some(ctx) => {
                let mut key = String::with_capacity(nonce.len() + ctx.len() + 1);
                key.push_str(nonce);
                key.push(':');
                key.push_str(ctx);
                key
            }
            None => {
                let mut key = String::with_capacity(nonce.len() + 1);
                key.push_str(nonce);
                key.push(':');
                key
            }
        }
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
            created_at: time_utils::current_timestamp()?,
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

        // More accurate memory usage calculation
        let base_entry_size = std::mem::size_of::<NonceEntry>();
        let mut total_memory = data.len() * base_entry_size;

        // Add string storage overhead
        for (key, entry) in data.iter() {
            total_memory += key.len(); // Key string
            total_memory += entry.nonce.len(); // Nonce string
            if let Some(ctx) = &entry.context {
                total_memory += ctx.len(); // Context string
            }
        }

        // Add HashMap overhead (approximate)
        total_memory += data.capacity() * std::mem::size_of::<(String, NonceEntry)>();

        Ok(StorageStats {
            total_records: data.len(),
            backend_info: format!(
                "In-memory HashMap storage (~{} bytes, capacity: {})",
                total_memory,
                data.capacity()
            ),
        })
    }
}

/// Batch operations support for better performance
impl MemoryStorage {
    /// Insert multiple nonces in a batch operation.
    ///
    /// This method acquires the write lock once and performs all insertions,
    /// which can be more efficient than individual set operations.
    ///
    /// # Arguments
    ///
    /// * `nonces` - Vector of (nonce, context) tuples to insert
    /// * `_ttl` - Time-to-live (not used in memory storage but kept for consistency)
    ///
    /// # Returns
    ///
    /// Number of successfully inserted nonces (duplicates are skipped)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::storage::MemoryStorage;
    /// use std::time::Duration;
    ///
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let storage = MemoryStorage::new();
    /// let nonces = vec![
    ///     ("nonce1", None),
    ///     ("nonce2", Some("ctx1")),
    ///     ("nonce3", Some("ctx2")),
    /// ];
    ///
    /// let inserted = storage.batch_set(nonces, Duration::from_secs(300)).await?;
    /// assert_eq!(inserted, 3);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn batch_set(
        &self,
        nonces: Vec<(&str, Option<&str>)>,
        _ttl: Duration,
    ) -> Result<usize, NonceError> {
        let created_at = time_utils::current_timestamp()?;
        let mut data = self.data.write().await;
        let mut success_count = 0;

        for (nonce, context) in nonces {
            let key = Self::make_key(nonce, context);

            if let std::collections::hash_map::Entry::Vacant(e) = data.entry(key) {
                let entry = NonceEntry {
                    nonce: nonce.to_string(),
                    created_at,
                    context: context.map(|s| s.to_string()),
                };
                e.insert(entry);
                success_count += 1;
            }
            // Skip duplicates silently in batch operation
        }

        Ok(success_count)
    }

    /// Check existence of multiple nonces in a batch operation.
    ///
    /// This method acquires the read lock once and checks all nonces,
    /// which can be more efficient than individual exists operations.
    ///
    /// # Arguments
    ///
    /// * `nonces` - Vector of (nonce, context) tuples to check
    ///
    /// # Returns
    ///
    /// Vector of boolean values indicating existence for each nonce
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::storage::MemoryStorage;
    ///
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let storage = MemoryStorage::new();
    /// let check_nonces = vec![
    ///     ("nonce1", None),
    ///     ("nonce2", Some("ctx1")),
    /// ];
    ///
    /// let results = storage.batch_exists(check_nonces).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn batch_exists(
        &self,
        nonces: Vec<(&str, Option<&str>)>,
    ) -> Result<Vec<bool>, NonceError> {
        let data = self.data.read().await;
        let mut results = Vec::with_capacity(nonces.len());

        for (nonce, context) in nonces {
            let key = Self::make_key(nonce, context);
            results.push(data.contains_key(&key));
        }

        Ok(results)
    }

    /// Get multiple nonces in a batch operation.
    ///
    /// This method acquires the read lock once and retrieves all nonces,
    /// which can be more efficient than individual get operations.
    ///
    /// # Arguments
    ///
    /// * `nonces` - Vector of (nonce, context) tuples to retrieve
    ///
    /// # Returns
    ///
    /// Vector of optional NonceEntry values
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::storage::MemoryStorage;
    ///
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let storage = MemoryStorage::new();
    /// let get_nonces = vec![
    ///     ("nonce1", None),
    ///     ("nonce2", Some("ctx1")),
    /// ];
    ///
    /// let results = storage.batch_get(get_nonces).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn batch_get(
        &self,
        nonces: Vec<(&str, Option<&str>)>,
    ) -> Result<Vec<Option<NonceEntry>>, NonceError> {
        let data = self.data.read().await;
        let mut results = Vec::with_capacity(nonces.len());

        for (nonce, context) in nonces {
            let key = Self::make_key(nonce, context);
            results.push(data.get(&key).cloned());
        }

        Ok(results)
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
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
        assert!(stats.backend_info.contains("In-memory"));

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
        assert!(stats.backend_info.contains("bytes"));
        assert!(stats.backend_info.contains("capacity"));

        Ok(())
    }

    #[tokio::test]
    async fn test_memory_storage_with_capacity() -> Result<(), NonceError> {
        let storage = MemoryStorage::with_capacity(100);

        // Add some nonces
        storage.set("test1", None, Duration::from_secs(300)).await?;
        storage
            .set("test2", Some("ctx"), Duration::from_secs(300))
            .await?;

        let stats = storage.get_stats().await?;
        assert_eq!(stats.total_records, 2);
        // Should have pre-allocated capacity
        assert!(stats.backend_info.contains("capacity"));

        Ok(())
    }

    #[tokio::test]
    async fn test_batch_operations() -> Result<(), NonceError> {
        let storage = MemoryStorage::new();

        // Test batch_set
        let nonces = vec![
            ("batch1", None),
            ("batch2", Some("ctx1")),
            ("batch3", Some("ctx2")),
            ("batch1", None), // Duplicate, should be skipped
        ];

        let inserted = storage.batch_set(nonces, Duration::from_secs(300)).await?;
        assert_eq!(inserted, 3); // Only 3 unique nonces inserted

        // Test batch_exists
        let check_nonces = vec![
            ("batch1", None),
            ("batch2", Some("ctx1")),
            ("batch3", Some("ctx2")),
            ("batch4", None), // Doesn't exist
        ];

        let exists_results = storage.batch_exists(check_nonces).await?;
        assert_eq!(exists_results, vec![true, true, true, false]);

        // Test batch_get
        let get_nonces = vec![
            ("batch1", None),
            ("batch4", None), // Doesn't exist
        ];

        let get_results = storage.batch_get(get_nonces).await?;
        assert!(get_results[0].is_some());
        assert!(get_results[1].is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_memory_storage_key_generation() {
        // Test key generation logic
        assert_eq!(MemoryStorage::make_key("nonce1", None), "nonce1:");
        assert_eq!(MemoryStorage::make_key("nonce1", Some("ctx")), "nonce1:ctx");
        assert_eq!(MemoryStorage::make_key("nonce1", Some("")), "nonce1:");
    }

    #[tokio::test]
    async fn test_memory_storage_concurrent_access() -> Result<(), NonceError> {
        let storage = std::sync::Arc::new(MemoryStorage::new());
        let mut handles = vec![];

        // Spawn multiple tasks that try to insert the same nonce
        for i in 0..10 {
            let storage_clone = std::sync::Arc::clone(&storage);
            let handle = tokio::spawn(async move {
                storage_clone
                    .set(&format!("nonce-{}", i), None, Duration::from_secs(300))
                    .await
            });
            handles.push(handle);
        }

        // All should succeed since they have different nonce values
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        // Verify all nonces were stored
        let stats = storage.get_stats().await?;
        assert_eq!(stats.total_records, 10);

        Ok(())
    }

    #[tokio::test]
    async fn test_memory_usage_calculation() -> Result<(), NonceError> {
        let storage = MemoryStorage::new();

        // Add nonces with various sizes
        storage.set("short", None, Duration::from_secs(300)).await?;
        storage
            .set(
                "very_long_nonce_name_for_testing",
                Some("long_context_name"),
                Duration::from_secs(300),
            )
            .await?;

        let stats = storage.get_stats().await?;
        assert_eq!(stats.total_records, 2);

        // Memory usage should account for string lengths
        assert!(stats.backend_info.contains("bytes"));
        assert!(stats.backend_info.contains("capacity"));

        Ok(())
    }
}
