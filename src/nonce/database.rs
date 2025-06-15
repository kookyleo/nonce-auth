use crate::NonceError;
use crate::nonce::NonceConfig;
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};

/// Database connection manager for nonce storage.
///
/// This module provides a thread-safe database abstraction layer for managing
/// nonce records in SQLite. It handles connection management, schema initialization,
/// and all database operations required for nonce-based authentication.
///
/// # Thread Safety
///
/// The database connection is wrapped in `Arc<Mutex<Connection>>` to enable
/// safe concurrent access from multiple threads. All operations acquire
/// the mutex lock before executing SQL statements.
///
/// # Performance Optimizations
///
/// - **WAL Mode**: Enables Write-Ahead Logging for better concurrency
/// - **Cache Tuning**: Configurable cache size for better memory usage
/// - **Optimized Indexes**: Composite indexes for efficient queries
/// - **Prepared Statements**: Reused for better performance
///
/// # Database Schema
///
/// The database uses a single table `nonce_record` with the following structure:
/// ```sql
/// CREATE TABLE nonce_record (
///     id INTEGER PRIMARY KEY AUTOINCREMENT,
///     nonce TEXT NOT NULL,
///     created_at INTEGER NOT NULL,
///     context TEXT DEFAULT '',
///     UNIQUE(nonce, context)
/// );
///
/// -- Optimized indexes
/// CREATE INDEX idx_nonce_context ON nonce_record (nonce, context);
/// CREATE INDEX idx_created_at ON nonce_record (created_at);
/// CREATE INDEX idx_context_created_at ON nonce_record (context, created_at);
/// ```
///
/// # Configuration
///
/// The database path can be configured using the `NONCE_AUTH_DB_PATH` environment variable:
/// - `:memory:` for in-memory database (testing)
/// - File path for persistent storage
/// - Defaults to `nonce_auth.db` in current directory
///
/// Performance can be tuned via environment variables:
/// - `NONCE_AUTH_CACHE_SIZE`: Cache size in KB (default: 2048)
/// - `NONCE_AUTH_WAL_MODE`: Enable WAL mode (default: true)
/// - `NONCE_AUTH_SYNC_MODE`: Sync mode NORMAL/FULL/OFF (default: NORMAL)
/// - `NONCE_AUTH_TEMP_STORE`: Temp storage MEMORY/FILE (default: MEMORY)
pub(crate) struct Database {
    /// Thread-safe database connection
    connection: Arc<Mutex<Connection>>,
    /// Database configuration
    config: NonceConfig,
}

impl Database {
    /// Creates a new database connection with optimized settings.
    ///
    /// The database location is determined by the `NONCE_AUTH_DB_PATH` environment
    /// variable. If not set, defaults to `nonce_auth.db` in the current directory.
    ///
    /// # Performance Configuration
    ///
    /// The database is automatically configured with performance optimizations:
    /// - WAL mode for better concurrency
    /// - Optimized cache size
    /// - Memory-based temporary storage
    /// - Proper synchronization mode
    ///
    /// # Returns
    ///
    /// * `Ok(Database)` - Successfully created database instance
    /// * `Err(NonceError::DatabaseError)` - Failed to open database connection
    ///
    /// # Example
    ///
    /// ```ignore
    /// // This is an internal API, not exposed publicly
    /// use nonce_auth::nonce::database::Database;
    /// let db = Database::new(NonceConfig::production())?;
    /// # Ok::<(), nonce_auth::NonceError>(())
    /// ```
    pub(crate) fn new(config: NonceConfig) -> Result<Self, NonceError> {
        let connection = if config.db_path == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open(&config.db_path)
        };

        let connection = connection.map_err(|e| NonceError::DatabaseError(e.to_string()))?;

        let db = Self {
            connection: Arc::new(Mutex::new(connection)),
            config,
        };

        // Apply performance optimizations
        db.configure_performance()?;

        Ok(db)
    }

    /// Configures SQLite performance settings.
    ///
    /// This method applies various PRAGMA settings to optimize SQLite performance
    /// for the nonce authentication use case.
    fn configure_performance(&self) -> Result<(), NonceError> {
        let conn = self.connection.lock().unwrap();

        // Set cache size (negative value means KB, positive means pages)
        conn.pragma_update(None, "cache_size", -self.config.cache_size_kb)
            .map_err(|e| NonceError::DatabaseError(format!("Failed to set cache_size: {e}")))?;

        // Enable WAL mode for better concurrency (only for file databases)
        if self.config.wal_mode && self.config.db_path != ":memory:" {
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(|e| {
                    NonceError::DatabaseError(format!("Failed to enable WAL mode: {e}"))
                })?;
        }

        // Set synchronous mode
        conn.pragma_update(None, "synchronous", &self.config.sync_mode)
            .map_err(|e| {
                NonceError::DatabaseError(format!("Failed to set synchronous mode: {e}"))
            })?;

        // Set temporary storage mode
        conn.pragma_update(None, "temp_store", &self.config.temp_store)
            .map_err(|e| NonceError::DatabaseError(format!("Failed to set temp_store: {e}")))?;

        // Enable foreign key constraints
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(|e| {
                NonceError::DatabaseError(format!("Failed to enable foreign keys: {e}"))
            })?;

        // Optimize for faster writes (trade-off with durability)
        if self.config.wal_mode && self.config.sync_mode == "NORMAL" {
            conn.pragma_update(None, "wal_autocheckpoint", 1000)
                .map_err(|e| {
                    NonceError::DatabaseError(format!("Failed to set WAL autocheckpoint: {e}"))
                })?;
        }

        Ok(())
    }

    /// Initializes the database schema with optimized indexes.
    ///
    /// Creates the `nonce_record` table and associated indexes if they don't exist.
    /// This method is idempotent and safe to call multiple times.
    ///
    /// # Schema Created
    ///
    /// - Table: `nonce_record` with fields for nonce, timestamp, and context
    /// - Index: `idx_nonce_context` for fast nonce existence checks
    /// - Index: `idx_created_at` for efficient cleanup operations
    /// - Index: `idx_context_created_at` for context-specific cleanup
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Schema initialized successfully
    /// * `Err(NonceError::DatabaseError)` - Failed to create schema
    ///
    /// # Example
    ///
    /// ```ignore
    /// // This is an internal API, not exposed publicly
    /// use nonce_auth::nonce::database::Database;
    /// let db = Database::new()?;
    /// db.init_schema()?;
    /// # Ok::<(), nonce_auth::NonceError>(())
    /// ```
    pub(crate) fn init_schema(&self) -> Result<(), NonceError> {
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
        .map_err(|e| NonceError::DatabaseError(e.to_string()))?;

        // Create optimized indexes
        // Primary index for nonce existence checks
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nonce_context ON nonce_record (nonce, context)",
            [],
        )
        .map_err(|e| NonceError::DatabaseError(e.to_string()))?;

        // Index for cleanup operations
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_created_at ON nonce_record (created_at)",
            [],
        )
        .map_err(|e| NonceError::DatabaseError(e.to_string()))?;

        // Composite index for context-specific operations
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_context_created_at ON nonce_record (context, created_at)",
            [],
        ).map_err(|e| NonceError::DatabaseError(e.to_string()))?;

        // Analyze tables for query optimizer
        conn.execute("ANALYZE", [])
            .map_err(|e| NonceError::DatabaseError(format!("Failed to analyze tables: {e}")))?;

        Ok(())
    }

    /// Checks if a nonce exists in the database.
    ///
    /// Searches for a nonce within the specified context. The context isolation
    /// allows the same nonce value to be used in different business scenarios.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce string to search for
    /// * `context` - Optional context for nonce scoping. `None` means global context.
    ///
    /// # Returns
    ///
    /// * `Ok(Some((id, created_at)))` - Nonce exists, returns record ID and creation time
    /// * `Ok(None)` - Nonce does not exist
    /// * `Err(NonceError::DatabaseError)` - Database operation failed
    ///
    /// # Example
    ///
    /// ```ignore
    /// // This is an internal API, not exposed publicly
    /// use nonce_auth::nonce::database::Database;
    /// let db = Database::new()?;
    ///
    /// // Check if nonce exists in global context
    /// if let Some((id, created_at)) = db.nonce_exists("my-nonce", None)? {
    ///     println!("Nonce {} exists, created at {}", id, created_at);
    /// }
    ///
    /// // Check if nonce exists in specific context
    /// if db.nonce_exists("my-nonce", Some("api_v1"))?.is_none() {
    ///     println!("Nonce available in api_v1 context");
    /// }
    /// # Ok::<(), nonce_auth::NonceError>(())
    /// ```
    pub(crate) fn nonce_exists(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<Option<(i64, i64)>, NonceError> {
        let conn = self.connection.lock().unwrap();
        let context_value = context.unwrap_or("");

        let mut stmt = conn
            .prepare("SELECT id, created_at FROM nonce_record WHERE nonce = ? AND context = ?")
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;

        let result = stmt.query_row(params![nonce, context_value], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        });

        match result {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(NonceError::DatabaseError(e.to_string())),
        }
    }

    /// Inserts a new nonce record into the database.
    ///
    /// Attempts to insert a nonce with the given creation timestamp and context.
    /// If a nonce with the same value and context already exists, returns a
    /// `DuplicateNonce` error due to the UNIQUE constraint.
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce string to insert
    /// * `created_at` - Unix timestamp when the nonce was created
    /// * `context` - Optional context for nonce scoping. `None` means global context.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Nonce inserted successfully
    /// * `Err(NonceError::DuplicateNonce)` - Nonce already exists in the same context
    /// * `Err(NonceError::DatabaseError)` - Other database operation failed
    ///
    /// # Example
    ///
    /// ```ignore
    /// // This is an internal API, not exposed publicly
    /// use nonce_auth::nonce::database::Database;
    /// use std::time::{SystemTime, UNIX_EPOCH};
    ///
    /// let db = Database::new()?;
    /// let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    ///
    /// // Insert nonce in global context
    /// db.insert_nonce("unique-nonce", now, None)?;
    ///
    /// // Insert same nonce in different context (allowed)
    /// db.insert_nonce("unique-nonce", now, Some("api_v1"))?;
    ///
    /// // This would fail with DuplicateNonce error
    /// // db.insert_nonce("unique-nonce", now, None)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub(crate) fn insert_nonce(
        &self,
        nonce: &str,
        created_at: i64,
        context: Option<&str>,
    ) -> Result<(), NonceError> {
        let conn = self.connection.lock().unwrap();
        let context_value = context.unwrap_or("");

        let result = conn.execute(
            "INSERT INTO nonce_record (nonce, created_at, context) VALUES (?, ?, ?)",
            params![nonce, created_at, context_value],
        );

        match result {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(sqlite_err, _))
                if sqlite_err.code == rusqlite::ErrorCode::ConstraintViolation
                    && sqlite_err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
            {
                Err(NonceError::DuplicateNonce)
            }
            Err(e) => Err(NonceError::DatabaseError(e.to_string())),
        }
    }

    /// Cleans up expired nonce records from the database.
    ///
    /// Removes all nonce records that were created before the specified cutoff time.
    /// This is typically called with `current_time - ttl` to remove expired nonces.
    /// Uses optimized batch deletion for better performance.
    ///
    /// # Arguments
    ///
    /// * `cutoff_time` - Unix timestamp. Records created before this time will be deleted.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of records deleted
    /// * `Err(NonceError::DatabaseError)` - Database operation failed
    ///
    /// # Example
    ///
    /// ```ignore
    /// // This is an internal API, not exposed publicly
    /// use nonce_auth::nonce::database::Database;
    /// use std::time::{SystemTime, UNIX_EPOCH, Duration};
    ///
    /// let db = Database::new()?;
    /// let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    /// let five_minutes_ago = now - 300; // 5 minutes TTL
    ///
    /// // Remove all nonces older than 5 minutes
    /// let deleted_count = db.cleanup_expired(five_minutes_ago)?;
    /// println!("Deleted {} expired nonces", deleted_count);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub(crate) fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
        let conn = self.connection.lock().unwrap();

        // Use a transaction for better performance and consistency
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| NonceError::DatabaseError(format!("Failed to start transaction: {e}")))?;

        // Delete in batches to avoid long-running transactions
        let batch_size = self.config.cleanup_batch_size;
        let mut total_deleted = 0;

        loop {
            let deleted = tx
                .execute(
                    "DELETE FROM nonce_record WHERE id IN (
                    SELECT id FROM nonce_record 
                    WHERE created_at <= ? 
                    LIMIT ?
                )",
                    params![cutoff_time, batch_size],
                )
                .map_err(|e| NonceError::DatabaseError(e.to_string()))?;

            total_deleted += deleted;

            // If we deleted fewer than batch_size, we're done
            if deleted < batch_size {
                break;
            }
        }

        tx.commit().map_err(|e| {
            NonceError::DatabaseError(format!("Failed to commit cleanup transaction: {e}"))
        })?;

        // Optimize database after cleanup if significant deletions occurred
        if total_deleted > 100 {
            conn.execute("PRAGMA optimize", []).map_err(|e| {
                NonceError::DatabaseError(format!("Failed to optimize database: {e}"))
            })?;
        }

        Ok(total_deleted)
    }

    /// Batch insert multiple nonces in a single transaction.
    ///
    /// This method is more efficient than multiple individual inserts
    /// when you need to store multiple nonces at once.
    ///
    /// # Arguments
    ///
    /// * `nonces` - Vector of (nonce, created_at, context) tuples to insert
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All nonces inserted successfully
    /// * `Err(NonceError::DuplicateNonce)` - One or more nonces already exist
    /// * `Err(NonceError::DatabaseError)` - Other database operation failed
    ///
    /// # Example
    ///
    /// ```ignore
    /// // This is an internal API, not exposed publicly
    /// use nonce_auth::nonce::database::Database;
    /// use std::time::{SystemTime, UNIX_EPOCH};
    ///
    /// let db = Database::new()?;
    /// let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    ///
    /// let nonces = vec![
    ///     ("nonce1".to_string(), now, None),
    ///     ("nonce2".to_string(), now, Some("api_v1")),
    ///     ("nonce3".to_string(), now, None),
    /// ];
    ///
    /// db.batch_insert_nonces(nonces)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[allow(dead_code)]
    pub(crate) fn batch_insert_nonces(
        &self,
        nonces: Vec<(String, i64, Option<&str>)>,
    ) -> Result<(), NonceError> {
        if nonces.is_empty() {
            return Ok(());
        }

        let conn = self.connection.lock().unwrap();

        let tx = conn.unchecked_transaction().map_err(|e| {
            NonceError::DatabaseError(format!("Failed to start batch insert transaction: {e}"))
        })?;

        {
            let mut stmt = tx
                .prepare("INSERT INTO nonce_record (nonce, created_at, context) VALUES (?, ?, ?)")
                .map_err(|e| {
                    NonceError::DatabaseError(format!(
                        "Failed to prepare batch insert statement: {e}"
                    ))
                })?;

            for (nonce, created_at, context) in nonces {
                let context_value = context.unwrap_or("");

                let result = stmt.execute(params![nonce, created_at, context_value]);

                match result {
                    Ok(_) => {}
                    Err(rusqlite::Error::SqliteFailure(sqlite_err, _))
                        if sqlite_err.code == rusqlite::ErrorCode::ConstraintViolation
                            && sqlite_err.extended_code
                                == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
                    {
                        return Err(NonceError::DuplicateNonce);
                    }
                    Err(e) => return Err(NonceError::DatabaseError(e.to_string())),
                }
            }
        }

        tx.commit().map_err(|e| {
            NonceError::DatabaseError(format!("Failed to commit batch insert transaction: {e}"))
        })?;

        Ok(())
    }

    /// Gets database statistics for monitoring and optimization.
    ///
    /// Returns information about database size, cache usage, and performance metrics.
    ///
    /// # Returns
    ///
    /// * `Ok(DatabaseStats)` - Database statistics
    /// * `Err(NonceError::DatabaseError)` - Failed to retrieve statistics
    #[allow(dead_code)]
    pub(crate) fn get_stats(&self) -> Result<DatabaseStats, NonceError> {
        let conn = self.connection.lock().unwrap();

        // Get table info
        let mut stmt = conn
            .prepare("SELECT COUNT(*) FROM nonce_record")
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;
        let total_records: i64 = stmt
            .query_row([], |row| row.get(0))
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;

        // Get database size
        let mut stmt = conn
            .prepare("PRAGMA page_count")
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;
        let page_count: i64 = stmt
            .query_row([], |row| row.get(0))
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;

        let mut stmt = conn
            .prepare("PRAGMA page_size")
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;
        let page_size: i64 = stmt
            .query_row([], |row| row.get(0))
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;

        // Get cache stats
        let mut stmt = conn
            .prepare("PRAGMA cache_size")
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;
        let cache_size: i64 = stmt
            .query_row([], |row| row.get(0))
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;

        Ok(DatabaseStats {
            total_records: total_records as usize,
            database_size_bytes: (page_count * page_size) as usize,
            cache_size_kb: cache_size.unsigned_abs() as usize, // abs() because negative means KB
            config: self.config.clone(),
        })
    }
}

/// Database performance statistics.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct DatabaseStats {
    /// Total number of nonce records
    pub total_records: usize,
    /// Database file size in bytes
    pub database_size_bytes: usize,
    /// Cache size in KB
    pub cache_size_kb: usize,
    /// Current database configuration
    pub config: NonceConfig,
}

// Global database instance management
lazy_static::lazy_static! {
    /// Global database instance for the application.
    ///
    /// This static instance ensures that all parts of the application
    /// use the same database connection and schema.
    static ref DATABASE: Mutex<Option<Database>> = Mutex::new(None);
}

/// Gets the global database instance.
///
/// This function implements a singleton pattern for database access.
/// On first call, it creates and initializes the database. Subsequent
/// calls return a clone of the existing database handle.
///
/// # Returns
///
/// * `Ok(Database)` - Successfully obtained database instance
/// * `Err(NonceError)` - Failed to create or initialize database
///
/// # Thread Safety
///
/// This function is thread-safe. Multiple threads can call it concurrently,
/// and the database will only be initialized once.
///
/// # Example
///
/// ```ignore
/// // This is an internal API, not exposed publicly
/// use nonce_auth::nonce::database::get_database;
/// let db = get_database()?;
/// db.init_schema()?;
/// # Ok::<(), nonce_auth::NonceError>(())
/// ```
pub(crate) fn get_database() -> Result<Database, NonceError> {
    let mut db_guard = DATABASE.lock().unwrap();

    if db_guard.is_none() {
        // Create configuration from environment variables (preset + overrides)
        let config = NonceConfig::from_env();
        let db = Database::new(config)?;
        db.init_schema()?;
        *db_guard = Some(db);
    }

    // Clone the database instance (Arc<Mutex<Connection>> is cheap to clone)
    Ok(Database {
        connection: db_guard.as_ref().unwrap().connection.clone(),
        config: db_guard.as_ref().unwrap().config.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Helper function to create a test database with in-memory storage
    fn create_test_db() -> Database {
        let config = NonceConfig::development(); // Use in-memory config
        let db = Database::new(config).expect("Failed to create test database");
        db.init_schema().expect("Failed to initialize test schema");
        db
    }

    #[test]
    fn test_database_creation() {
        let _db = create_test_db();
        // If we reach here, database creation succeeded
    }

    #[test]
    fn test_schema_initialization() {
        let db = create_test_db();

        // Test that we can initialize schema multiple times (idempotent)
        assert!(db.init_schema().is_ok());
        assert!(db.init_schema().is_ok());
    }

    #[test]
    fn test_nonce_insertion_and_existence_check() {
        let db = create_test_db();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Test nonce doesn't exist initially
        assert!(db.nonce_exists("test-nonce", None).unwrap().is_none());

        // Insert nonce
        assert!(db.insert_nonce("test-nonce", now, None).is_ok());

        // Test nonce now exists
        let result = db.nonce_exists("test-nonce", None).unwrap();
        assert!(result.is_some());
        let (id, created_at) = result.unwrap();
        assert!(id > 0);
        assert_eq!(created_at, now);
    }

    #[test]
    fn test_duplicate_nonce_error() {
        let db = create_test_db();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Insert nonce first time - should succeed
        assert!(db.insert_nonce("duplicate-nonce", now, None).is_ok());

        // Insert same nonce again - should fail
        let result = db.insert_nonce("duplicate-nonce", now, None);
        assert!(matches!(result, Err(NonceError::DuplicateNonce)));
    }

    #[test]
    fn test_context_isolation() {
        let db = create_test_db();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Insert same nonce in different contexts - should all succeed
        assert!(db.insert_nonce("context-nonce", now, None).is_ok());
        assert!(
            db.insert_nonce("context-nonce", now, Some("api_v1"))
                .is_ok()
        );
        assert!(
            db.insert_nonce("context-nonce", now, Some("api_v2"))
                .is_ok()
        );

        // Check existence in each context
        assert!(db.nonce_exists("context-nonce", None).unwrap().is_some());
        assert!(
            db.nonce_exists("context-nonce", Some("api_v1"))
                .unwrap()
                .is_some()
        );
        assert!(
            db.nonce_exists("context-nonce", Some("api_v2"))
                .unwrap()
                .is_some()
        );

        // Check non-existence in different context
        assert!(
            db.nonce_exists("context-nonce", Some("api_v3"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_cleanup_expired() {
        let db = create_test_db();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Insert old and new nonces
        let old_time = now - 3600; // 1 hour ago
        let new_time = now - 60; // 1 minute ago

        assert!(db.insert_nonce("old-nonce", old_time, None).is_ok());
        assert!(db.insert_nonce("new-nonce", new_time, None).is_ok());

        // Verify both exist
        assert!(db.nonce_exists("old-nonce", None).unwrap().is_some());
        assert!(db.nonce_exists("new-nonce", None).unwrap().is_some());

        // Clean up nonces older than 30 minutes
        let cutoff = now - 1800; // 30 minutes ago
        assert!(db.cleanup_expired(cutoff).is_ok());

        // Old nonce should be gone, new nonce should remain
        assert!(db.nonce_exists("old-nonce", None).unwrap().is_none());
        assert!(db.nonce_exists("new-nonce", None).unwrap().is_some());
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let db = Arc::new(create_test_db());
        let db1 = Arc::clone(&db);
        let db2 = Arc::clone(&db);

        let handle1 = thread::spawn(move || {
            for i in 0..10 {
                let nonce = format!("thread1-nonce-{i}");
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                db1.insert_nonce(&nonce, now, Some("thread1")).unwrap();
            }
        });

        let handle2 = thread::spawn(move || {
            for i in 0..10 {
                let nonce = format!("thread2-nonce-{i}");
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                db2.insert_nonce(&nonce, now, Some("thread2")).unwrap();
            }
        });

        // Wait for both threads to complete
        handle1.join().unwrap();
        handle2.join().unwrap();

        // Verify that all nonces were inserted
        for i in 0..10 {
            let nonce1 = format!("thread1-nonce-{i}");
            let nonce2 = format!("thread2-nonce-{i}");
            assert!(db.nonce_exists(&nonce1, Some("thread1")).unwrap().is_some());
            assert!(db.nonce_exists(&nonce2, Some("thread2")).unwrap().is_some());
        }
    }

    #[test]
    fn test_get_database_singleton() {
        unsafe {
            std::env::set_var("NONCE_AUTH_DB_PATH", ":memory:");
        }

        // Reset the global database for this test
        {
            let mut db_guard = DATABASE.lock().unwrap();
            *db_guard = None;
        }

        // Get database instances - should be the same
        let db1 = get_database().unwrap();
        let db2 = get_database().unwrap();

        // Both should work with the same underlying database
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        db1.insert_nonce("singleton-test", now, None).unwrap();
        assert!(db2.nonce_exists("singleton-test", None).unwrap().is_some());
    }

    #[test]
    fn test_database_error_handling() {
        // Test invalid database path (should still work with SQLite)
        unsafe {
            std::env::set_var("NONCE_AUTH_DB_PATH", "/invalid/path/test.db");
        }

        // This might fail depending on permissions
        let config = NonceConfig::from_env();
        let result = Database::new(config);
        match result {
            Ok(_) => {
                // If it succeeds, that's fine too (SQLite might create directories)
            }
            Err(NonceError::DatabaseError(_)) => {
                // Expected error for invalid path
            }
            Err(e) => panic!("Unexpected error type: {:?}", e),
        }
    }
}
