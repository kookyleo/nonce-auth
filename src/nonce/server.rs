use hmac::Mac;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(not(docsrs))]
use turbosql::{Turbosql, execute, select};

use super::{NonceError, record::NonceRecord};
use crate::AuthData;
use crate::HmacSha256;

/// Server-side nonce manager for verifying signed requests and managing nonce storage.
///
/// The `NonceServer` is responsible for:
/// - Verifying the integrity of signed requests from clients
/// - Managing nonce storage and preventing replay attacks
/// - Cleaning up expired nonce records automatically
/// - Providing configurable TTL and time window settings
///
/// # Security Features
///
/// - **Replay Attack Prevention**: Each nonce can only be used once
/// - **Time Window Validation**: Requests outside the time window are rejected
/// - **Context Isolation**: Nonces can be scoped to different business contexts
/// - **Automatic Cleanup**: Expired nonces are cleaned up in the background
///
/// # Database Storage
///
/// The server uses SQLite for persistent nonce storage. The database location
/// can be configured using the `TURBOSQL_DB_PATH` environment variable.
/// If not set, it defaults to `nonce_auth.db` in the current directory.
///
/// # Example
///
/// ```rust
/// use nonce_auth::NonceServer;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Initialize the database
/// NonceServer::init().await?;
///
/// // Create a server with custom settings
/// let server = NonceServer::new(
///     b"my_secret_key",
///     Some(Duration::from_secs(300)), // 5 minutes TTL
///     Some(Duration::from_secs(60)),  // 1 minute time window
/// );
/// # Ok(())
/// # }
/// ```
pub struct NonceServer {
    /// Default time-to-live for nonce records. After this duration,
    /// nonces are considered expired and will be cleaned up.
    default_ttl: Duration,

    /// Time window for timestamp validation. Requests with timestamps
    /// outside this window (past or future) will be rejected.
    time_window: Duration,

    /// Secret key used for HMAC signature verification.
    /// This should match the secret used by the client.
    secret: Vec<u8>,
}

impl NonceServer {
    /// Creates a new `NonceServer` instance with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret key used for HMAC signature verification.
    ///   This must match the secret used by the client.
    /// * `default_ttl` - Optional TTL for nonce records. If `None`, defaults to 5 minutes.
    ///   This controls how long nonces remain valid in the database.
    /// * `time_window` - Optional time window for timestamp validation. If `None`, defaults to 1 minute.
    ///   This controls how much clock skew is allowed between client and server.
    ///
    /// # Returns
    ///
    /// A new `NonceServer` instance ready to verify signed requests.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceServer;
    /// use std::time::Duration;
    ///
    /// // Create server with default settings
    /// let server = NonceServer::new(b"my_secret", None, None);
    ///
    /// // Create server with custom settings
    /// let server = NonceServer::new(
    ///     b"my_secret",
    ///     Some(Duration::from_secs(600)), // 10 minutes TTL
    ///     Some(Duration::from_secs(120)), // 2 minutes time window
    /// );
    /// ```
    pub fn new(
        secret: &[u8],
        default_ttl: Option<Duration>,
        time_window: Option<Duration>,
    ) -> Self {
        let default_ttl = default_ttl.unwrap_or(Duration::from_secs(300));
        let time_window = time_window.unwrap_or(Duration::from_secs(60));
        Self {
            default_ttl,
            time_window,
            secret: secret.to_vec(),
        }
    }

    /// Verifies authentication data with custom signature data construction.
    ///
    /// This is the primary verification method that provides maximum flexibility
    /// by allowing applications to define how the signature data should be
    /// constructed through a closure.
    ///
    /// # Arguments
    ///
    /// * `auth_data` - The authentication data containing timestamp, nonce, and signature
    /// * `context` - Optional context for nonce scoping
    /// * `signature_builder` - A closure that defines how to build the signature data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the authentication data is valid and has been processed
    /// * `Err(NonceError)` - If validation fails for any reason
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::{NonceServer, AuthData};
    /// use std::time::Duration;
    /// use hmac::Mac;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # NonceServer::init().await?;
    /// let server = NonceServer::new(b"secret", None, None);
    /// let auth_data = AuthData {
    ///     timestamp: 1234567890,
    ///     nonce: "unique-nonce".to_string(),
    ///     signature: "expected-signature".to_string(),
    /// };
    ///
    /// // Custom signature including payload and method
    /// let payload = "request body";
    /// let method = "POST";
    ///
    /// server.verify_auth_data(&auth_data, None, |mac| {
    ///     mac.update(auth_data.timestamp.to_string().as_bytes());
    ///     mac.update(auth_data.nonce.as_bytes());
    ///     mac.update(payload.as_bytes());
    ///     mac.update(method.as_bytes());
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_auth_data<F>(
        &self,
        auth_data: &AuthData,
        context: Option<&str>,
        signature_builder: F,
    ) -> Result<(), NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        // 1. Verify timestamp is within allowed window
        self.verify_timestamp(auth_data.timestamp)?;

        // 2. Verify signature with custom builder
        self.verify_signature(&auth_data.signature, signature_builder)?;

        // 3. Verify nonce is valid and not used
        self.verify_and_consume_nonce(&auth_data.nonce, context)
            .await?;

        Ok(())
    }

    /// Initializes the database schema for nonce storage.
    ///
    /// This method creates the necessary tables and indexes if they don't already exist.
    /// It should be called once before using any `NonceServer` instances.
    ///
    /// # Database Configuration
    ///
    /// The database location can be configured using the `TURBOSQL_DB_PATH` environment variable:
    /// - If set to `:memory:`, uses an in-memory database (useful for testing)
    /// - If set to a file path, uses that file for persistent storage
    /// - If not set, defaults to `nonce_auth.db` in the current directory
    ///
    /// # Schema
    ///
    /// Creates the following table:
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
    /// And the following indexes for performance:
    /// - `idx_nonce_context` on `(nonce, context)` for fast nonce lookups
    /// - `idx_created_at` on `created_at` for efficient cleanup operations
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If initialization completed successfully
    /// * `Err(NonceError::DatabaseError)` - If there was a database error during initialization
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceServer;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Initialize with default database location
    /// NonceServer::init().await?;
    ///
    /// // Or configure database location via environment variable
    /// unsafe { std::env::set_var("TURBOSQL_DB_PATH", "/path/to/nonce_auth.db"); }
    /// NonceServer::init().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn init() -> Result<(), NonceError> {
        #[cfg(not(docsrs))]
        {
            // This will create the table if it doesn't exist
            execute!(
                r#"
                CREATE TABLE IF NOT EXISTS noncerecord (
                    rowid INTEGER PRIMARY KEY,
                    nonce TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    context TEXT,
                    UNIQUE(nonce, context)
                )
                "#
            )?;

            // Create index for faster lookups
            execute!("CREATE INDEX IF NOT EXISTS idx_nonce_context ON noncerecord (nonce, context)")?;
            execute!("CREATE INDEX IF NOT EXISTS idx_created_at ON noncerecord (created_at)")?;
        }

        Ok(())
    }

    /// Verifies timestamp is within the allowed window.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The timestamp to verify (seconds since Unix epoch)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the timestamp is within the allowed window
    /// * `Err(NonceError::TimestampOutOfWindow)` - If the timestamp is too old or too far in the future
    pub(crate) fn verify_timestamp(&self, timestamp: u64) -> Result<(), NonceError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let time_diff = (now - timestamp as i64).unsigned_abs();
        if time_diff > self.time_window.as_secs() {
            return Err(NonceError::TimestampOutOfWindow);
        }
        Ok(())
    }

    /// Verifies HMAC signature with custom data builder.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify (hex-encoded)
    /// * `data_builder` - A closure that adds data to the HMAC instance
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the signature is valid
    /// * `Err(NonceError::InvalidSignature)` - If the signature is invalid
    /// * `Err(NonceError::CryptoError)` - If there's an error in the crypto operations
    pub(crate) fn verify_signature<F>(
        &self,
        signature: &str,
        data_builder: F,
    ) -> Result<(), NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        let expected_signature = self.generate_signature(data_builder)?;
        if expected_signature != signature {
            return Err(NonceError::InvalidSignature);
        }
        Ok(())
    }

    /// Generates HMAC signature with custom data builder.
    ///
    /// # Arguments
    ///
    /// * `data_builder` - A closure that adds data to the HMAC instance
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The hex-encoded HMAC signature
    /// * `Err(NonceError::CryptoError)` - If there's an error in the crypto operations
    fn generate_signature<F>(&self, data_builder: F) -> Result<String, NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|e| NonceError::CryptoError(e.to_string()))?;

        data_builder(&mut mac);

        let result = mac.finalize();
        let signature = hex::encode(result.into_bytes());
        Ok(signature)
    }

    /// Verifies that a nonce is valid and hasn't been used, then marks it as consumed.
    ///
    /// This method implements the core replay attack prevention logic:
    /// 1. Checks if the nonce already exists in the database
    /// 2. If it exists, determines if it's expired or duplicate
    /// 3. If it doesn't exist, stores it to prevent future reuse
    /// 4. Triggers background cleanup of expired nonces
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce string to verify and consume
    /// * `context` - Optional context for nonce scoping
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the nonce is valid and has been consumed
    /// * `Err(NonceError)` - If the nonce is invalid, expired, or already used
    async fn verify_and_consume_nonce(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<(), NonceError> {
        #[cfg(not(docsrs))]
        {
            // Check if nonce already exists (has been used)
            let existing_records: Vec<NonceRecord> = if let Some(ctx) = context {
                select!(
                    Vec<NonceRecord>
                    "WHERE nonce = ? AND context = ?",
                    nonce, ctx
                )?
            } else {
                select!(
                    Vec<NonceRecord>
                    "WHERE nonce = ? AND context IS NULL",
                    nonce
                )?
            };

            if !existing_records.is_empty() {
                // Check if it's expired
                if existing_records[0].is_expired(self.default_ttl) {
                    return Err(NonceError::ExpiredNonce);
                }
                return Err(NonceError::DuplicateNonce);
            }

            // Store the nonce to mark it as used
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let record = NonceRecord::create(nonce.to_string(), now, context.map(|s| s.to_string()));
            record.insert()?;

            // Clean up expired nonces in the background
            let ttl = self.default_ttl;
            tokio::spawn(async move {
                if let Err(e) = Self::cleanup_expired_nonces(ttl).await {
                    eprintln!("Failed to clean up expired nonces: {e}");
                }
            });
        }

        Ok(())
    }

    /// Cleans up expired nonce records from the database.
    ///
    /// This method removes all nonce records that are older than the specified TTL.
    /// It's called automatically in the background after each nonce verification,
    /// but can also be called manually for maintenance purposes.
    ///
    /// # Arguments
    ///
    /// * `ttl` - The time-to-live duration. Records older than this will be deleted.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If cleanup completed successfully
    /// * `Err(NonceError::DatabaseError)` - If there was a database error during cleanup
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceServer;
    /// use std::time::Duration;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # NonceServer::init().await?;
    /// // Manual cleanup of nonces older than 1 hour
    /// NonceServer::cleanup_expired_nonces(Duration::from_secs(3600)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn cleanup_expired_nonces(ttl: Duration) -> Result<(), NonceError> {
        #[cfg(not(docsrs))]
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let cutoff_time = now - ttl.as_secs() as i64;

            execute!("DELETE FROM noncerecord WHERE created_at <= ?", cutoff_time)?;
        }

        Ok(())
    }

    /// Returns the default TTL (time-to-live) duration for nonce records.
    ///
    /// This is the duration after which nonces are considered expired
    /// and will be cleaned up from the database.
    ///
    /// # Returns
    ///
    /// The default TTL duration configured for this server instance.
    pub fn ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Returns the time window duration for timestamp validation.
    ///
    /// This is the maximum allowed difference between the request timestamp
    /// and the current server time. Requests outside this window are rejected.
    ///
    /// # Returns
    ///
    /// The time window duration configured for this server instance.
    pub fn time_window(&self) -> Duration {
        self.time_window
    }
}
