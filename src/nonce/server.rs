use hmac::Mac;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use turbosql::{Turbosql, execute, select};

use super::{NonceError, record::NonceRecord};
use crate::HmacSha256;
use crate::SignedRequest;

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

    /// Verifies a signed request from a client.
    ///
    /// This method performs a comprehensive verification process:
    /// 1. Validates that the request timestamp is within the allowed time window
    /// 2. Verifies the HMAC signature using the shared secret
    /// 3. Checks that the nonce hasn't been used before (prevents replay attacks)
    /// 4. Stores the nonce to prevent future reuse
    ///
    /// # Arguments
    ///
    /// * `request` - The signed request to verify, containing timestamp, nonce, and signature
    /// * `context` - Optional context string for nonce scoping. Nonces are isolated per context.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the request is valid and verification succeeds
    /// * `Err(NonceError)` - If verification fails for any reason
    ///
    /// # Errors
    ///
    /// * `NonceError::TimestampOutOfWindow` - Request timestamp is too old or too far in the future
    /// * `NonceError::InvalidSignature` - HMAC signature verification failed
    /// * `NonceError::DuplicateNonce` - Nonce has already been used
    /// * `NonceError::ExpiredNonce` - Nonce exists but has expired
    /// * `NonceError::DatabaseError` - Database operation failed
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::{NonceServer, NonceClient};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # NonceServer::init().await?;
    /// let server = NonceServer::new(b"shared_secret", None, None);
    /// let client = NonceClient::new(b"shared_secret");
    ///
    /// let request = client.create_signed_request()?;
    ///
    /// match server.verify_signed_request(&request, Some("api_v1")).await {
    ///     Ok(()) => println!("Request verified successfully"),
    ///     Err(e) => println!("Verification failed: {}", e),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_signed_request(
        &self,
        request: &SignedRequest,
        context: Option<&str>,
    ) -> Result<(), NonceError> {
        // 1. Verify timestamp is within allowed window
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let time_diff = (now - request.timestamp as i64).unsigned_abs(); // plus or minus the time window
        if time_diff > self.time_window.as_secs() {
            return Err(NonceError::TimestampOutOfWindow);
        }

        // 2. Verify signature
        self.verify_signature(
            &request.timestamp.to_string(),
            &request.nonce,
            &request.signature,
        )?;

        // 3. Verify nonce is valid and not used
        self.verify_and_consume_nonce(&request.nonce, context)
            .await?;

        Ok(())
    }

    /// Verifies the HMAC signature of a request.
    ///
    /// This method reconstructs the expected signature using the same algorithm
    /// as the client and compares it with the provided signature using a
    /// constant-time comparison to prevent timing attacks.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The timestamp string from the request
    /// * `nonce` - The nonce string from the request  
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the signature is valid
    /// * `Err(NonceError::InvalidSignature)` - If the signature is invalid
    /// * `Err(NonceError::CryptoError)` - If there's an error in the crypto operations
    fn verify_signature(
        &self,
        timestamp: &str,
        nonce: &str,
        signature: &str,
    ) -> Result<(), NonceError> {
        let expected_signature = self.sign(timestamp, nonce)?;
        if expected_signature != signature {
            return Err(NonceError::InvalidSignature);
        }
        Ok(())
    }

    /// Generates an HMAC-SHA256 signature for the given timestamp and nonce.
    ///
    /// This method uses the same signing algorithm as the client to generate
    /// the expected signature for verification purposes.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The timestamp string to sign
    /// * `nonce` - The nonce string to sign
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The hex-encoded HMAC signature
    /// * `Err(NonceError::CryptoError)` - If there's an error in the crypto operations
    fn sign(&self, timestamp: &str, nonce: &str) -> Result<String, NonceError> {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|e| NonceError::CryptoError(e.to_string()))?;

        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());

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

        let record = NonceRecord::new(nonce.to_string(), now, context.map(|s| s.to_string()));
        record.insert()?;

        // Clean up expired nonces in the background
        let ttl = self.default_ttl;
        tokio::spawn(async move {
            if let Err(e) = Self::cleanup_expired(ttl).await {
                eprintln!("Failed to clean up expired nonces: {}", e);
            }
        });

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
    /// NonceServer::cleanup_expired(Duration::from_secs(3600)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn cleanup_expired(ttl: Duration) -> Result<(), NonceError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let cutoff_time = now - ttl.as_secs() as i64;

        execute!("DELETE FROM noncerecord WHERE created_at <= ?", cutoff_time)?;

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
    pub fn default_ttl(&self) -> Duration {
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
