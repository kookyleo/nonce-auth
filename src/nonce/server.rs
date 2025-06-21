use hmac::Mac;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{NonceError, NonceStorage};
use crate::HmacSha256;
use crate::ProtectionData;

/// Server-side nonce manager for verifying signed requests with pluggable storage backends.
///
/// The `NonceServer` is responsible for:
/// - Verifying the integrity of signed requests from clients
/// - Managing nonce storage through pluggable storage backends
/// - Preventing replay attacks by ensuring each nonce is used only once
/// - Providing configurable TTL and time window settings
///
/// # Storage Backend
///
/// The server requires a storage backend that implements the `NonceStorage` trait.
/// This allows for flexible storage solutions including in-memory, database,
/// Redis, or any custom implementation.
///
/// # Security Features
///
/// - **Replay Attack Prevention**: Each nonce can only be used once
/// - **Time Window Validation**: Requests outside the time window are rejected
/// - **Context Isolation**: Nonces can be scoped to different business contexts
/// - **Automatic Cleanup**: Expired nonces can be cleaned up through the storage backend
///
/// # Example
///
/// ```rust
/// use nonce_auth::{NonceServer, storage::MemoryStorage};
/// use std::time::Duration;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create a storage backend
/// let storage = Arc::new(MemoryStorage::new());
///
/// // Create a server with the storage backend
/// let server = NonceServer::new(
///     b"my_secret_key",
///     storage,
///     Some(Duration::from_secs(300)), // 5 minutes TTL
///     Some(Duration::from_secs(60)),  // 1 minute time window
/// );
/// # Ok(())
/// # }
/// ```
pub struct NonceServer<S: NonceStorage> {
    /// Default time-to-live for nonce records. After this duration,
    /// nonces are considered expired and will be cleaned up.
    default_ttl: Duration,

    /// Time window for timestamp validation. Requests with timestamps
    /// outside this window (past or future) will be rejected.
    time_window: Duration,

    /// Secret key used for HMAC signature verification.
    /// This should match the secret used by the client.
    secret: Vec<u8>,

    /// Storage backend for nonce persistence.
    storage: Arc<S>,
}

impl<S: NonceStorage> NonceServer<S> {
    /// Creates a new `NonceServer` instance with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret key used for HMAC signature verification.
    ///   This must match the secret used by the client.
    /// * `storage` - The storage backend implementation for nonce persistence.
    /// * `default_ttl` - Optional TTL for nonce records. If `None`, defaults to 5 minutes.
    ///   This controls how long nonces remain valid in the storage backend.
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
    /// use nonce_auth::{NonceServer, storage::MemoryStorage};
    /// use std::time::Duration;
    /// use std::sync::Arc;
    ///
    /// // Create server with default settings
    /// let storage = Arc::new(MemoryStorage::new());
    /// let server = NonceServer::new(b"my_secret", storage, None, None);
    ///
    /// // Create server with custom settings
    /// let storage = Arc::new(MemoryStorage::new());
    /// let server = NonceServer::new(
    ///     b"my_secret",
    ///     storage,
    ///     Some(Duration::from_secs(600)), // 10 minutes TTL
    ///     Some(Duration::from_secs(120)), // 2 minutes time window
    /// );
    /// ```
    pub fn new(
        secret: &[u8],
        storage: Arc<S>,
        default_ttl: Option<Duration>,
        time_window: Option<Duration>,
    ) -> Self {
        let default_ttl = default_ttl.unwrap_or(Duration::from_secs(300));
        let time_window = time_window.unwrap_or(Duration::from_secs(60));
        Self {
            default_ttl,
            time_window,
            secret: secret.to_vec(),
            storage,
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
    /// * `protection_data` - The authentication data containing timestamp, nonce, and signature
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
    /// use nonce_auth::{NonceServer, ProtectionData, storage::MemoryStorage};
    /// use std::time::Duration;
    /// use std::sync::Arc;
    /// use hmac::Mac;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let storage = Arc::new(MemoryStorage::new());
    /// let server = NonceServer::new(b"secret", storage, None, None);
    /// let protection_data = ProtectionData {
    ///     timestamp: 1234567890,
    ///     nonce: "unique-nonce".to_string(),
    ///     signature: "expected-signature".to_string(),
    /// };
    ///
    /// // Custom signature including payload and method
    /// let payload = "request body";
    /// let method = "POST";
    ///
    /// server.verify_protection_data(&protection_data, None, |mac| {
    ///     mac.update(protection_data.timestamp.to_string().as_bytes());
    ///     mac.update(protection_data.nonce.as_bytes());
    ///     mac.update(payload.as_bytes());
    ///     mac.update(method.as_bytes());
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_protection_data<F>(
        &self,
        protection_data: &ProtectionData,
        context: Option<&str>,
        signature_builder: F,
    ) -> Result<(), NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        // 1. Verify timestamp is within allowed window
        self.verify_timestamp(protection_data.timestamp)?;

        // 2. Verify signature with custom builder
        self.verify_signature(&protection_data.signature, signature_builder)?;

        // 3. Verify nonce is valid and not used, then consume it
        self.verify_and_consume_nonce(&protection_data.nonce, context)
            .await?;

        Ok(())
    }

    /// Initializes the storage backend.
    ///
    /// This method calls the storage backend's `init()` method, which can be used
    /// for tasks like schema creation, connection setup, etc.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If initialization succeeded
    /// * `Err(NonceError)` - If initialization failed
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::{NonceServer, storage::MemoryStorage};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let storage = Arc::new(MemoryStorage::new());
    /// let server = NonceServer::new(b"secret", storage, None, None);
    ///
    /// // Initialize the storage backend
    /// server.init().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn init(&self) -> Result<(), NonceError> {
        self.storage.init().await
    }

    /// Verifies that the timestamp is within the allowed time window.
    ///
    /// This method checks that the timestamp is not too old or too far in the future
    /// compared to the server's current time.
    pub(crate) fn verify_timestamp(&self, timestamp: u64) -> Result<(), NonceError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let time_diff = now.abs_diff(timestamp);

        if time_diff > self.time_window.as_secs() {
            return Err(NonceError::TimestampOutOfWindow);
        }

        Ok(())
    }

    /// Verifies the HMAC signature using the provided data builder.
    pub(crate) fn verify_signature<F>(
        &self,
        signature: &str,
        data_builder: F,
    ) -> Result<(), NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        let expected_signature = self.generate_signature(data_builder)?;
        if signature != expected_signature {
            return Err(NonceError::InvalidSignature);
        }
        Ok(())
    }

    /// Generates an HMAC signature using the provided data builder.
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

    /// Verifies that a nonce is valid and hasn't been used, then stores it.
    ///
    /// This method atomically checks for nonce existence and stores it if it's new.
    /// The storage backend is responsible for ensuring atomicity of this operation.
    async fn verify_and_consume_nonce(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<(), NonceError> {
        // Check if nonce already exists and retrieve entry for expiration check
        if let Some(entry) = self.storage.get(nonce, context).await? {
            // Check if the existing nonce has expired
            if Self::is_time_expired(entry.created_at, self.default_ttl) {
                // Nonce exists but is expired
                return Err(NonceError::ExpiredNonce);
            } else {
                // Nonce exists and is still valid - this is a duplicate
                return Err(NonceError::DuplicateNonce);
            }
        }

        // Nonce doesn't exist, store it
        self.storage.set(nonce, context, self.default_ttl).await?;

        Ok(())
    }

    /// Cleans up expired nonces from the storage backend.
    ///
    /// This method removes all nonces that have exceeded the specified TTL duration.
    /// It can be called periodically to maintain storage efficiency.
    ///
    /// # Arguments
    ///
    /// * `ttl` - Time-to-live duration; nonces older than this will be removed
    ///
    /// # Returns
    ///
    /// * `Ok(count)` - Number of nonces that were removed
    /// * `Err(NonceError)` - If cleanup failed
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::{NonceServer, storage::MemoryStorage};
    /// use std::time::Duration;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let storage = Arc::new(MemoryStorage::new());
    /// let server = NonceServer::new(b"secret", storage, None, None);
    ///
    /// // Clean up nonces older than 1 hour
    /// let removed = server.cleanup_expired_nonces(Duration::from_secs(3600)).await?;
    /// println!("Removed {} expired nonces", removed);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn cleanup_expired_nonces(&self, ttl: Duration) -> Result<usize, NonceError> {
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - ttl.as_secs() as i64;

        self.storage.cleanup_expired(cutoff_time).await
    }

    /// Returns the default TTL for nonce records.
    ///
    /// # Returns
    ///
    /// The default time-to-live duration for nonce records.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::{NonceServer, storage::MemoryStorage};
    /// use std::sync::Arc;
    ///
    /// let storage = Arc::new(MemoryStorage::new());
    /// let server = NonceServer::new(b"secret", storage, None, None);
    /// let ttl = server.ttl();
    /// println!("Default TTL: {:?}", ttl);
    /// ```
    pub fn ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Returns the time window for timestamp validation.
    ///
    /// # Returns
    ///
    /// The time window duration for timestamp validation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::{NonceServer, storage::MemoryStorage};
    /// use std::sync::Arc;
    ///
    /// let storage = Arc::new(MemoryStorage::new());
    /// let server = NonceServer::new(b"secret", storage, None, None);
    /// let window = server.time_window();
    /// println!("Time window: {:?}", window);
    /// ```
    pub fn time_window(&self) -> Duration {
        self.time_window
    }

    /// Returns a reference to the storage backend.
    ///
    /// This can be useful for accessing storage-specific functionality
    /// or getting storage statistics.
    ///
    /// # Returns
    ///
    /// A reference to the storage backend.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::{NonceServer, storage::MemoryStorage};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let storage = Arc::new(MemoryStorage::new());
    /// let server = NonceServer::new(b"secret", storage, None, None);
    /// use nonce_auth::storage::NonceStorage;
    /// let stats = server.storage().get_stats().await?;
    /// println!("Storage stats: {stats:?}");
    /// # Ok(())
    /// # }
    /// ```
    pub fn storage(&self) -> &Arc<S> {
        &self.storage
    }

    /// Checks if a time is expired based on TTL.
    fn is_time_expired(created_at: i64, ttl: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        now - created_at > ttl.as_secs() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::storage::MemoryStorage;

    #[test]
    fn test_is_time_expired_not_expired() {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ttl = Duration::from_secs(300);

        assert!(!NonceServer::<MemoryStorage>::is_time_expired(
            created_at, ttl
        ));
    }

    #[test]
    fn test_is_time_expired_expired() {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 400; // 400 seconds ago
        let ttl = Duration::from_secs(300); // 300 seconds TTL

        assert!(NonceServer::<MemoryStorage>::is_time_expired(
            created_at, ttl
        ));
    }

    #[test]
    fn test_is_time_expired_edge_case() {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 301; // Just over TTL seconds ago
        let ttl = Duration::from_secs(300);

        // Should be expired (> TTL is expired)
        assert!(NonceServer::<MemoryStorage>::is_time_expired(
            created_at, ttl
        ));
    }

    #[test]
    fn test_is_time_expired_future_created_at() {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 100; // 100 seconds in the future
        let ttl = Duration::from_secs(300);

        // Future timestamps should not be expired
        assert!(!NonceServer::<MemoryStorage>::is_time_expired(
            created_at, ttl
        ));
    }
}
