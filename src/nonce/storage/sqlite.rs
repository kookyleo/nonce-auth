//! SQLite storage backend implementation.
//!
//! This module provides a production-ready SQLite storage backend for nonce persistence.
//! It's ideal for single-instance applications that need persistent storage.

use super::{NonceEntry, NonceStorage, StorageStats};
use crate::NonceError;
use async_trait::async_trait;
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// SQLite-based storage backend for nonce persistence.
///
/// This implementation provides persistent storage using SQLite, making it suitable
/// for production use where data needs to survive application restarts.
///
/// # Features
///
/// - **Persistent storage**: Data survives application restarts
/// - **Context isolation**: Supports nonce namespacing via contexts
/// - **Automatic indexing**: Optimized queries for nonce lookup and cleanup
/// - **Thread-safe**: Uses Arc<Mutex<Connection>> for concurrent access
/// - **ACID compliance**: Leverages SQLite's transactional guarantees
///
/// # Example
///
/// ```rust
/// use nonce_auth::storage::SqliteStorage;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), nonce_auth::NonceError> {
/// // Create SQLite storage (file-based)
/// let storage = Arc::new(SqliteStorage::new("nonce_auth.db")?);
///
/// // Or use in-memory SQLite (for testing)
/// let memory_storage = Arc::new(SqliteStorage::new(":memory:")?);
/// # Ok(())
/// # }
/// ```
pub struct SqliteStorage {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    /// Create a new SQLite storage backend.
    ///
    /// # Arguments
    ///
    /// * `db_path` - Path to the SQLite database file, or ":memory:" for in-memory database
    ///
    /// # Returns
    ///
    /// * `Ok(SqliteStorage)` - Successfully created storage instance
    /// * `Err(NonceError)` - Failed to open database connection
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::storage::SqliteStorage;
    ///
    /// # fn example() -> Result<(), nonce_auth::NonceError> {
    /// // File-based storage
    /// let storage = SqliteStorage::new("./data/nonce_auth.db")?;
    ///
    /// // In-memory storage (for testing)
    /// let memory_storage = SqliteStorage::new(":memory:")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(db_path: &str) -> Result<Self, NonceError> {
        let connection = if db_path == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open(db_path)
        };

        let connection = connection.map_err(NonceError::from_database_error)?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Create the database schema if it doesn't exist.
    fn init_schema(&self) -> Result<(), NonceError> {
        let conn = self.connection.lock().unwrap();

        // Create main table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS nonce_record (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nonce TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                context TEXT DEFAULT '',
                UNIQUE(nonce, context)
            )
            "#,
            [],
        )
        .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        // Create performance indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nonce_context ON nonce_record (nonce, context)",
            [],
        )
        .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_created_at ON nonce_record (created_at)",
            [],
        )
        .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl NonceStorage for SqliteStorage {
    async fn init(&self) -> Result<(), NonceError> {
        self.init_schema()
    }

    async fn get(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<Option<NonceEntry>, NonceError> {
        let context = context.unwrap_or("");
        let conn = self.connection.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT nonce, created_at, context FROM nonce_record WHERE nonce = ?1 AND context = ?2")
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        let result = stmt.query_row(params![nonce, context], |row| {
            Ok(NonceEntry {
                nonce: row.get(0)?,
                created_at: row.get(1)?,
                context: {
                    let ctx: String = row.get(2)?;
                    if ctx.is_empty() { None } else { Some(ctx) }
                },
            })
        });

        match result {
            Ok(entry) => Ok(Some(entry)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(NonceError::from_database_message(e.to_string())),
        }
    }

    async fn set(
        &self,
        nonce: &str,
        context: Option<&str>,
        _ttl: Duration,
    ) -> Result<(), NonceError> {
        let context = context.unwrap_or("");
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let conn = self.connection.lock().unwrap();

        conn.execute(
            "INSERT INTO nonce_record (nonce, created_at, context) VALUES (?1, ?2, ?3)",
            params![nonce, created_at, context],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(sqlite_err, _)
                if sqlite_err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                NonceError::DuplicateNonce
            }
            _ => NonceError::from_database_message(e.to_string()),
        })?;

        Ok(())
    }

    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
        let context = context.unwrap_or("");
        let conn = self.connection.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT 1 FROM nonce_record WHERE nonce = ?1 AND context = ?2")
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        let exists = stmt
            .exists(params![nonce, context])
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        Ok(exists)
    }

    async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
        let conn = self.connection.lock().unwrap();

        let changes = conn
            .execute(
                "DELETE FROM nonce_record WHERE created_at <= ?1",
                params![cutoff_time],
            )
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        Ok(changes)
    }

    async fn get_stats(&self) -> Result<StorageStats, NonceError> {
        let conn = self.connection.lock().unwrap();

        let count: usize = conn
            .query_row("SELECT COUNT(*) FROM nonce_record", [], |row| row.get(0))
            .map_err(|e| NonceError::from_database_message(e.to_string()))?;

        // Get additional SQLite-specific stats
        let db_size: i64 = conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap_or(0);

        let page_size: i64 = conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .unwrap_or(4096);

        let size_bytes = db_size * page_size;

        Ok(StorageStats {
            total_records: count,
            backend_info: format!("SQLite storage ({} bytes, {} pages)", size_bytes, db_size),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn test_sqlite_storage_basic_operations() -> Result<(), NonceError> {
        let storage = SqliteStorage::new(":memory:")?;
        storage.init().await?;

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
    async fn test_sqlite_storage_duplicate_nonce() -> Result<(), NonceError> {
        let storage = SqliteStorage::new(":memory:")?;
        storage.init().await?;

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
    async fn test_sqlite_storage_context_isolation() -> Result<(), NonceError> {
        let storage = SqliteStorage::new(":memory:")?;
        storage.init().await?;

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
    async fn test_sqlite_storage_cleanup() -> Result<(), NonceError> {
        let storage = SqliteStorage::new(":memory:")?;
        storage.init().await?;

        // Add some nonces
        storage
            .set("old-nonce", None, Duration::from_secs(300))
            .await?;
        storage
            .set("new-nonce", None, Duration::from_secs(300))
            .await?;

        // Verify they exist
        assert!(storage.exists("old-nonce", None).await?);
        assert!(storage.exists("new-nonce", None).await?);

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
    async fn test_sqlite_storage_stats() -> Result<(), NonceError> {
        let storage = SqliteStorage::new(":memory:")?;
        storage.init().await?;

        // Initial stats
        let stats = storage.get_stats().await?;
        assert_eq!(stats.total_records, 0);
        assert!(stats.backend_info.contains("SQLite"));

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
        assert!(stats.backend_info.contains("SQLite"));
        assert!(stats.backend_info.contains("bytes"));

        Ok(())
    }

    #[tokio::test]
    async fn test_sqlite_storage_persistence() -> Result<(), NonceError> {
        // Create a temporary file for testing persistence
        let temp_path = format!("/tmp/test_nonce_{}.db", std::process::id());

        // Create storage and add data
        {
            let storage = SqliteStorage::new(&temp_path)?;
            storage.init().await?;

            storage
                .set("persistent-nonce", None, Duration::from_secs(300))
                .await?;
        }

        // Reopen storage and verify data persists
        {
            let storage = SqliteStorage::new(&temp_path)?;
            storage.init().await?;

            assert!(storage.exists("persistent-nonce", None).await?);

            let entry = storage.get("persistent-nonce", None).await?;
            assert!(entry.is_some());
            assert_eq!(entry.unwrap().nonce, "persistent-nonce");
        }

        // Cleanup
        std::fs::remove_file(&temp_path).ok();

        Ok(())
    }
}
