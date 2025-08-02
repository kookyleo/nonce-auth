//! Redis storage backend implementation.
//!
//! This module provides a Redis-based storage backend for nonce persistence.
//! It's ideal for distributed applications that need shared state across multiple instances.

use super::{NonceEntry, NonceStorage, StorageStats};
use crate::NonceError;
use crate::nonce::time_utils;
use async_trait::async_trait;
use redis::{AsyncCommands, Client};
use std::time::Duration;

/// Redis-based storage backend for nonce persistence.
///
/// This implementation provides distributed storage using Redis, making it suitable
/// for multi-instance applications that need shared nonce state.
///
/// # Features
///
/// - **Distributed storage**: Shared state across multiple application instances
/// - **TTL support**: Automatic expiration using Redis TTL
/// - **Context isolation**: Supports nonce namespacing via key prefixes
/// - **High performance**: Leverages Redis's in-memory architecture
/// - **Atomic operations**: Uses Redis commands for thread-safe operations
///
/// # Example
///
/// ```rust
/// use nonce_auth::storage::RedisStorage;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), nonce_auth::NonceError> {
/// // Create Redis storage with default settings
/// let storage = Arc::new(RedisStorage::new("redis://localhost:6379", "nonce_auth")?);
///
/// // Or with custom configuration
/// let custom_storage = Arc::new(RedisStorage::new("redis://user:pass@server:6379/0", "myapp_nonces")?);
/// # Ok(())
/// # }
/// ```
pub struct RedisStorage {
    client: Client,
    key_prefix: String,
}

impl RedisStorage {
    /// Create a new Redis storage backend.
    ///
    /// # Arguments
    ///
    /// * `redis_url` - Redis connection URL (e.g., "redis://localhost:6379")
    /// * `key_prefix` - Prefix for all nonce keys to avoid collisions
    ///
    /// # Returns
    ///
    /// * `Ok(RedisStorage)` - Successfully created storage instance
    /// * `Err(NonceError)` - Failed to create Redis client
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::storage::RedisStorage;
    ///
    /// # fn example() -> Result<(), nonce_auth::NonceError> {
    /// // Local Redis
    /// let storage = RedisStorage::new("redis://localhost:6379", "nonce_auth")?;
    ///
    /// // Remote Redis with auth
    /// let remote_storage = RedisStorage::new(
    ///     "redis://user:password@redis.example.com:6379/0",
    ///     "myapp_nonces"
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(redis_url: &str, key_prefix: &str) -> Result<Self, NonceError> {
        let client = Client::open(redis_url)
            .map_err(|e| NonceError::from_database_message(format!("Redis client error: {}", e)))?;

        Ok(Self {
            client,
            key_prefix: key_prefix.to_string(),
        })
    }

    /// Create a Redis key for the given nonce and context.
    fn make_key(&self, nonce: &str, context: Option<&str>) -> String {
        match context {
            Some(ctx) => {
                let mut key =
                    String::with_capacity(self.key_prefix.len() + ctx.len() + nonce.len() + 2);
                key.push_str(&self.key_prefix);
                key.push(':');
                key.push_str(ctx);
                key.push(':');
                key.push_str(nonce);
                key
            }
            None => {
                let mut key = String::with_capacity(self.key_prefix.len() + nonce.len() + 1);
                key.push_str(&self.key_prefix);
                key.push(':');
                key.push_str(nonce);
                key
            }
        }
    }

    /// Parse nonce data from Redis value.
    fn parse_entry(&self, key: &str, value: String) -> Result<NonceEntry, NonceError> {
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 2 {
            return Err(NonceError::from_database_message(
                "Invalid Redis value format",
            ));
        }

        let created_at: i64 = parts[1]
            .parse()
            .map_err(|_| NonceError::from_database_message("Invalid timestamp in Redis value"))?;

        // Extract nonce and context from key
        let key_parts: Vec<&str> = key.split(':').collect();
        let (nonce, context) = if key_parts.len() == 3 {
            // Format: prefix:context:nonce
            (key_parts[2].to_string(), Some(key_parts[1].to_string()))
        } else if key_parts.len() == 2 {
            // Format: prefix:nonce
            (key_parts[1].to_string(), None)
        } else {
            return Err(NonceError::from_database_message(
                "Invalid Redis key format",
            ));
        };

        Ok(NonceEntry {
            nonce,
            created_at,
            context,
        })
    }
}

#[async_trait]
impl NonceStorage for RedisStorage {
    async fn init(&self) -> Result<(), NonceError> {
        // Test Redis connection
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| {
                NonceError::from_database_message(format!("Redis connection failed: {}", e))
            })?;

        // Verify Redis is accessible with a ping
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| NonceError::from_database_message(format!("Redis ping failed: {}", e)))?;

        Ok(())
    }

    async fn get(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<Option<NonceEntry>, NonceError> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        let key = self.make_key(nonce, context);

        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        match value {
            Some(val) => Ok(Some(self.parse_entry(&key, val)?)),
            None => Ok(None),
        }
    }

    async fn set(
        &self,
        nonce: &str,
        context: Option<&str>,
        ttl: Duration,
    ) -> Result<(), NonceError> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        let key = self.make_key(nonce, context);
        let created_at = time_utils::current_timestamp();

        // Optimize value string allocation
        let created_at_str = created_at.to_string();
        let mut value = String::with_capacity(nonce.len() + created_at_str.len() + 1);
        value.push_str(nonce);
        value.push(':');
        value.push_str(&created_at_str);
        let ttl_secs = ttl.as_secs() as usize;

        // Use SET with EX and NX (set if not exists)
        let result: Result<Option<String>, _> = conn
            .set_options(
                &key,
                &value,
                redis::SetOptions::default()
                    .conditional_set(redis::ExistenceCheck::NX)
                    .with_expiration(redis::SetExpiry::EX(ttl_secs)),
            )
            .await;

        match result {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(NonceError::DuplicateNonce), // Key already exists
            Err(e) => Err(NonceError::from_database_message(e.to_string())),
        }
    }

    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        let key = self.make_key(nonce, context);

        let exists: bool = conn
            .exists(&key)
            .await
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        Ok(exists)
    }

    async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        // Get all keys matching our prefix
        let pattern = format!("{}:*", self.key_prefix);
        let keys: Vec<String> = conn
            .keys(&pattern)
            .await
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        let mut deleted_count = 0;

        // Check each key and delete if expired
        for key in &keys {
            let value: Option<String> = conn
                .get(key)
                .await
                .map_err(|e| NonceError::from_database_message(e.to_string()))?;

            if let Some(val) = value {
                if let Ok(entry) = self.parse_entry(key, val) {
                    if entry.created_at <= cutoff_time {
                        let deleted: usize = conn
                            .del(key)
                            .await
                            .map_err(|e| NonceError::from_database_message(e.to_string()))?;
                        deleted_count += deleted;
                    }
                }
            }
        }

        Ok(deleted_count)
    }

    async fn get_stats(&self) -> Result<StorageStats, NonceError> {
        let mut conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        // Count keys matching our prefix
        let pattern = format!("{}:*", self.key_prefix);
        let keys: Vec<String> = conn
            .keys(&pattern)
            .await
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        // Get Redis server info for additional stats
        let info: String = redis::cmd("INFO")
            .arg("memory")
            .query_async(&mut conn)
            .await
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        // Extract memory usage from info string
        let memory_usage = info
            .lines()
            .find(|line| line.starts_with("used_memory_human:"))
            .map(|line| line.split(':').nth(1).unwrap_or("unknown").trim())
            .unwrap_or("unknown");

        Ok(StorageStats {
            total_records: keys.len(),
            backend_info: format!(
                "Redis storage (memory: {}, prefix: {})",
                memory_usage, self.key_prefix
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running Redis instance
    // Skip them if Redis is not available
    async fn get_test_storage() -> Result<RedisStorage, NonceError> {
        let storage = RedisStorage::new("redis://localhost:6379", "test_nonce_auth")?;

        // Try to initialize - if it fails, skip the test
        match storage.init().await {
            Ok(()) => Ok(storage),
            Err(_) => {
                println!("Skipping Redis tests - no Redis server available");
                Err(NonceError::from_database_message("Redis not available"))
            }
        }
    }

    #[tokio::test]
    async fn test_redis_storage_basic_operations() {
        let storage = match get_test_storage().await {
            Ok(s) => s,
            Err(_) => return, // Skip test if Redis not available
        };

        // Clean up any existing test data
        let _ = storage.cleanup_expired(9999999999).await;

        // Test set and exists
        storage
            .set("test-nonce", None, Duration::from_secs(300))
            .await
            .unwrap();
        assert!(storage.exists("test-nonce", None).await.unwrap());

        // Test get
        let entry = storage.get("test-nonce", None).await.unwrap();
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.nonce, "test-nonce");
        assert!(entry.context.is_none());

        // Cleanup
        let _ = storage.cleanup_expired(9999999999).await;
    }

    #[tokio::test]
    async fn test_redis_storage_duplicate_nonce() {
        let storage = match get_test_storage().await {
            Ok(s) => s,
            Err(_) => return, // Skip test if Redis not available
        };

        // Clean up any existing test data
        let _ = storage.cleanup_expired(9999999999).await;

        // First set should succeed
        storage
            .set("dup-test-nonce", None, Duration::from_secs(300))
            .await
            .unwrap();

        // Second set should fail
        let result = storage
            .set("dup-test-nonce", None, Duration::from_secs(300))
            .await;
        assert!(matches!(result, Err(NonceError::DuplicateNonce)));

        // Cleanup
        let _ = storage.cleanup_expired(9999999999).await;
    }

    #[tokio::test]
    async fn test_redis_storage_context_isolation() {
        let storage = match get_test_storage().await {
            Ok(s) => s,
            Err(_) => return, // Skip test if Redis not available
        };

        // Clean up any existing test data
        let _ = storage.cleanup_expired(9999999999).await;

        // Same nonce, different contexts should work
        storage
            .set("ctx-test-nonce", Some("context1"), Duration::from_secs(300))
            .await
            .unwrap();
        storage
            .set("ctx-test-nonce", Some("context2"), Duration::from_secs(300))
            .await
            .unwrap();

        // Both should exist
        assert!(
            storage
                .exists("ctx-test-nonce", Some("context1"))
                .await
                .unwrap()
        );
        assert!(
            storage
                .exists("ctx-test-nonce", Some("context2"))
                .await
                .unwrap()
        );

        // But not in wrong context
        assert!(
            !storage
                .exists("ctx-test-nonce", Some("context3"))
                .await
                .unwrap()
        );

        // Cleanup
        let _ = storage.cleanup_expired(9999999999).await;
    }

    #[tokio::test]
    async fn test_redis_storage_ttl() {
        let storage = match get_test_storage().await {
            Ok(s) => s,
            Err(_) => return, // Skip test if Redis not available
        };

        // Clean up any existing test data
        let _ = storage.cleanup_expired(9999999999).await;

        // Set with very short TTL
        storage
            .set("ttl-test-nonce", None, Duration::from_millis(100))
            .await
            .unwrap();

        // Should exist initially
        assert!(storage.exists("ttl-test-nonce", None).await.unwrap());

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Should be automatically expired by Redis
        assert!(!storage.exists("ttl-test-nonce", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_redis_storage_stats() {
        let storage = match get_test_storage().await {
            Ok(s) => s,
            Err(_) => return, // Skip test if Redis not available
        };

        // Clean up any existing test data
        let _ = storage.cleanup_expired(9999999999).await;

        // Add some nonces
        storage
            .set("stats-nonce1", None, Duration::from_secs(300))
            .await
            .unwrap();
        storage
            .set("stats-nonce2", Some("context"), Duration::from_secs(300))
            .await
            .unwrap();

        // Get stats
        let stats = storage.get_stats().await.unwrap();
        assert_eq!(stats.total_records, 2);
        assert!(stats.backend_info.contains("Redis"));
        assert!(stats.backend_info.contains("test_nonce_auth"));

        // Cleanup
        let _ = storage.cleanup_expired(9999999999).await;
    }
}
