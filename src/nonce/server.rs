use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::Mac;
use tokio;

use super::cleanup::BoxedCleanupStrategy;
use super::{CredentialVerifier, NonceError, NonceServerBuilder, NonceStorage};
use crate::storage::MemoryStorage;
use crate::{HmacSha256, NonceCredential};

/// A server that verifies `NonceCredential`s and manages nonce storage.
///
/// The server includes automatic nonce cleanup functionality that triggers
/// based on configurable strategies. By default, it uses a hybrid approach
/// that performs cleanup after a certain number of requests or elapsed time.
///
/// To create an instance, use the `NonceServer::builder()` method.
pub struct NonceServer<S: NonceStorage> {
    pub(crate) default_ttl: Duration,
    pub(crate) time_window: Duration,
    pub(crate) storage: Arc<S>,
    pub(crate) cleanup_strategy: BoxedCleanupStrategy,
}

impl NonceServer<MemoryStorage> {
    /// Creates a new `NonceServerBuilder` to construct a `NonceServer`.
    ///
    /// The builder defaults to using `MemoryStorage`. Provide a custom storage
    /// backend using the `.with_storage()` method on the builder.
    pub fn builder() -> NonceServerBuilder<MemoryStorage> {
        NonceServerBuilder::new()
    }
}

impl<S: NonceStorage + 'static> NonceServer<S> {
    /// Internal constructor used by the builder.
    pub(crate) fn new(
        storage: Arc<S>,
        default_ttl: Option<Duration>,
        time_window: Option<Duration>,
        cleanup_strategy: BoxedCleanupStrategy,
    ) -> Self {
        let default_ttl = default_ttl.unwrap_or(Duration::from_secs(300));
        let time_window = time_window.unwrap_or(Duration::from_secs(60));
        Self {
            default_ttl,
            time_window,
            storage,
            cleanup_strategy,
        }
    }

    /// Returns a builder-like verifier to check the validity of a `NonceCredential`.
    pub fn credential_verifier<'a>(
        &'a self,
        credential: &'a NonceCredential,
    ) -> CredentialVerifier<'a, S> {
        CredentialVerifier::new(self, credential)
    }

    /// Initializes the storage backend (e.g., creates database tables).
    pub(crate) async fn init(&self) -> Result<(), NonceError> {
        self.storage.init().await
    }

    /// Verifies that the timestamp is within the allowed time window.
    pub(crate) fn verify_timestamp(&self, timestamp: u64) -> Result<(), NonceError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| NonceError::CryptoError(format!("System clock error: {e}")))?
            .as_secs();
        let time_diff = now.abs_diff(timestamp);
        if time_diff > self.time_window.as_secs() {
            return Err(NonceError::TimestampOutOfWindow);
        }
        Ok(())
    }

    /// Verifies the HMAC signature using the provided data builder.
    pub(crate) fn verify_signature<F>(
        secret: &[u8],
        signature: &str,
        data_builder: F,
    ) -> Result<(), NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| NonceError::CryptoError(e.to_string()))?;
        data_builder(&mut mac);
        let expected_signature = hex::encode(mac.finalize().into_bytes());
        if signature != expected_signature {
            return Err(NonceError::InvalidSignature);
        }
        Ok(())
    }

    /// Verifies that a nonce is valid and hasn't been used, then stores it.
    ///
    /// After successful verification and storage, this method checks the cleanup
    /// strategy to determine if automatic cleanup should be triggered. If so,
    /// cleanup is performed asynchronously in the background.
    pub(crate) async fn verify_and_consume_nonce(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<(), NonceError> {
        if let Some(entry) = self.storage.get(nonce, context).await? {
            return if Self::is_time_expired(entry.created_at, self.default_ttl) {
                Err(NonceError::ExpiredNonce)
            } else {
                Err(NonceError::DuplicateNonce)
            };
        }

        // Store the nonce
        self.storage.set(nonce, context, self.default_ttl).await?;

        // Check if cleanup should be triggered
        if self.cleanup_strategy.should_cleanup().await {
            // Create a clone of storage and ttl for the background task
            let storage_clone = Arc::clone(&self.storage);
            let ttl = self.default_ttl;

            // Spawn cleanup in background to avoid blocking the verification
            tokio::spawn(async move {
                if let Err(e) = Self::cleanup_expired_nonces_static(&storage_clone, ttl).await {
                    tracing::warn!("Background cleanup failed: {}", e);
                }
            });

            // Mark cleanup as performed
            self.cleanup_strategy.mark_as_cleaned().await;
        }

        Ok(())
    }

    /// Cleans up expired nonces from the storage backend.
    pub async fn cleanup_expired_nonces(&self, ttl: Duration) -> Result<usize, NonceError> {
        Self::cleanup_expired_nonces_static(&self.storage, ttl).await
    }

    /// Static version of cleanup_expired_nonces for use in background tasks.
    async fn cleanup_expired_nonces_static<T: NonceStorage>(
        storage: &Arc<T>,
        ttl: Duration,
    ) -> Result<usize, NonceError> {
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| NonceError::CryptoError(format!("System clock error: {e}")))?
            .as_secs() as i64
            - ttl.as_secs() as i64;
        storage.cleanup_expired(cutoff_time).await
    }

    /// Returns the configured default TTL for nonce records.
    pub fn ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Returns the configured time window for timestamp validation.
    pub fn time_window(&self) -> Duration {
        self.time_window
    }

    /// Returns a reference to the storage backend.
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
            - 400;
        let ttl = Duration::from_secs(300);
        assert!(NonceServer::<MemoryStorage>::is_time_expired(
            created_at, ttl
        ));
    }
}
