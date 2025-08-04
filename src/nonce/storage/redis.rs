//! Redis storage backend implementation.
//!
//! This module provides a Redis-based storage backend for nonce persistence.
//! It's ideal for distributed applications that need shared state across multiple instances.

use super::{NonceEntry, NonceStorage, StorageStats};
use crate::NonceError;
use crate::nonce::time_utils;
use async_trait::async_trait;
use redis::{AsyncCommands, Client, aio::MultiplexedConnection};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

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
/// - **High performance**: Leverages Redis's in-memory architecture with connection pooling
/// - **Atomic operations**: Uses Redis commands for thread-safe operations
/// - **Connection pooling**: Reuses connections for better performance
/// - **Production-safe**: Uses SCAN instead of KEYS for better performance
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
    /// Shared persistent connection for better performance
    conn: Arc<Mutex<Option<MultiplexedConnection>>>,
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
            .map_err(|e| NonceError::from_storage_message(format!("Redis client error: {}", e)))?;

        Ok(Self {
            client,
            key_prefix: key_prefix.to_string(),
            conn: Arc::new(Mutex::new(None)),
        })
    }

    /// Get or create a persistent connection
    async fn get_connection(&self) -> Result<MultiplexedConnection, NonceError> {
        let mut conn_guard = self.conn.lock().await;

        // Check if we have an existing connection
        if let Some(conn) = conn_guard.as_ref() {
            // Test if connection is still alive
            let mut test_conn = conn.clone();
            match redis::cmd("PING")
                .query_async::<_, String>(&mut test_conn)
                .await
            {
                Ok(_) => return Ok(conn.clone()),
                Err(_) => {
                    // Connection is dead, remove it
                    *conn_guard = None;
                }
            }
        }

        // Create new connection
        let new_conn = self
            .client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| {
                NonceError::from_storage_message(format!("Redis connection failed: {}", e))
            })?;

        *conn_guard = Some(new_conn.clone());
        Ok(new_conn)
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
            return Err(NonceError::from_storage_message(
                "Invalid Redis value format",
            ));
        }

        let created_at: i64 = parts[1]
            .parse()
            .map_err(|_| NonceError::from_storage_message("Invalid timestamp in Redis value"))?;

        // Extract nonce and context from key
        let key_parts: Vec<&str> = key.split(':').collect();
        let (nonce, context) = if key_parts.len() == 3 {
            // Format: prefix:context:nonce
            (key_parts[2].to_string(), Some(key_parts[1].to_string()))
        } else if key_parts.len() == 2 {
            // Format: prefix:nonce
            (key_parts[1].to_string(), None)
        } else {
            return Err(NonceError::from_storage_message("Invalid Redis key format"));
        };

        Ok(NonceEntry {
            nonce,
            created_at,
            context,
        })
    }

    /// Scan keys with pattern using SCAN instead of KEYS for production safety
    async fn scan_keys(&self, pattern: &str) -> Result<Vec<String>, NonceError> {
        let mut conn = self.get_connection().await?;
        let mut keys = Vec::new();
        let mut cursor = 0u64;

        loop {
            let (new_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(100) // Process 100 keys at a time
                .query_async(&mut conn)
                .await
                .map_err(|e| NonceError::from_storage_message(e.to_string()))?;

            keys.extend(batch);
            cursor = new_cursor;

            if cursor == 0 {
                break;
            }
        }

        Ok(keys)
    }
}

#[async_trait]
impl NonceStorage for RedisStorage {
    async fn init(&self) -> Result<(), NonceError> {
        // Initialize connection and test Redis
        let mut conn = self.get_connection().await?;

        // Verify Redis is accessible with a ping
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| NonceError::from_storage_message(format!("Redis ping failed: {}", e)))?;

        Ok(())
    }

    async fn get(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<Option<NonceEntry>, NonceError> {
        let mut conn = self.get_connection().await?;
        let key = self.make_key(nonce, context);

        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| NonceError::from_storage_message(e.to_string()))?;

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
        let mut conn = self.get_connection().await?;
        let key = self.make_key(nonce, context);
        let created_at = time_utils::current_timestamp()?;

        // Optimize value string allocation
        let created_at_str = created_at.to_string();
        let mut value = String::with_capacity(nonce.len() + created_at_str.len() + 1);
        value.push_str(nonce);
        value.push(':');
        value.push_str(&created_at_str);
        // Redis requires TTL in seconds, minimum 1 second
        let ttl_secs = ttl.as_secs().max(1) as usize;

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
            Err(e) => Err(NonceError::from_storage_message(e.to_string())),
        }
    }

    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
        let mut conn = self.get_connection().await?;
        let key = self.make_key(nonce, context);

        let exists: bool = conn
            .exists(&key)
            .await
            .map_err(|e| NonceError::from_storage_message(e.to_string()))?;

        Ok(exists)
    }

    async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
        let mut conn = self.get_connection().await?;

        // Use SCAN instead of KEYS for production safety
        let pattern = format!("{}:*", self.key_prefix);
        let keys = self.scan_keys(&pattern).await?;

        let mut deleted_count = 0;
        let mut to_delete = Vec::new();

        // Batch get values to check expiration
        for chunk in keys.chunks(100) {
            let values: Vec<Option<String>> = redis::cmd("MGET")
                .arg(chunk)
                .query_async(&mut conn)
                .await
                .map_err(|e| NonceError::from_storage_message(e.to_string()))?;

            for (key, value) in chunk.iter().zip(values.iter()) {
                if let Some(val) = value {
                    if let Ok(entry) = self.parse_entry(key, val.clone()) {
                        if entry.created_at <= cutoff_time {
                            to_delete.push(key.clone());
                        }
                    }
                }
            }
        }

        // Batch delete expired keys
        for chunk in to_delete.chunks(100) {
            if !chunk.is_empty() {
                let deleted: usize = conn
                    .del(chunk)
                    .await
                    .map_err(|e| NonceError::from_storage_message(e.to_string()))?;
                deleted_count += deleted;
            }
        }

        Ok(deleted_count)
    }

    async fn get_stats(&self) -> Result<StorageStats, NonceError> {
        let mut conn = self.get_connection().await?;

        // Count keys using SCAN instead of KEYS
        let pattern = format!("{}:*", self.key_prefix);
        let keys = self.scan_keys(&pattern).await?;
        let total_records = keys.len();

        // Get Redis server info for additional stats
        let info: String = redis::cmd("INFO")
            .arg("memory")
            .query_async(&mut conn)
            .await
            .map_err(|e| NonceError::from_storage_message(e.to_string()))?;

        // Extract memory usage from info string
        let memory_usage = info
            .lines()
            .find(|line| line.starts_with("used_memory_human:"))
            .map(|line| line.split(':').nth(1).unwrap_or("unknown").trim())
            .unwrap_or("unknown");

        Ok(StorageStats {
            total_records,
            backend_info: format!(
                "Redis storage (memory: {}, prefix: {}, persistent conn)",
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
                Err(NonceError::from_storage_message("Redis not available"))
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
        assert!(stats.backend_info.contains("persistent conn"));

        // Cleanup
        let _ = storage.cleanup_expired(9999999999).await;
    }

    #[tokio::test]
    async fn test_redis_connection_reuse() {
        let storage = match get_test_storage().await {
            Ok(s) => s,
            Err(_) => return, // Skip test if Redis not available
        };

        // Clean up any existing test data
        let _ = storage.cleanup_expired(9999999999).await;

        // Multiple operations should reuse the same connection
        for i in 0..10 {
            let nonce = format!("conn-test-{}", i);
            storage
                .set(&nonce, None, Duration::from_secs(60))
                .await
                .unwrap();

            assert!(storage.exists(&nonce, None).await.unwrap());
        }

        // Cleanup
        let _ = storage.cleanup_expired(9999999999).await;
    }

    #[tokio::test]
    async fn test_redis_scan_performance() {
        let storage = match get_test_storage().await {
            Ok(s) => s,
            Err(_) => return, // Skip test if Redis not available
        };

        // Clean up any existing test data
        let _ = storage.cleanup_expired(9999999999).await;

        // Add many nonces
        for i in 0..100 {
            let nonce = format!("scan-test-{}", i);
            storage
                .set(&nonce, None, Duration::from_secs(300))
                .await
                .unwrap();
        }

        // Test stats (uses SCAN)
        let stats = storage.get_stats().await.unwrap();
        assert!(stats.total_records >= 100);

        // Cleanup (uses SCAN and batch delete)
        let deleted = storage.cleanup_expired(9999999999).await.unwrap();
        assert!(deleted >= 100);
    }
}
