use hmac::Mac;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{CredentialVerifier, NonceError, NonceStorage, NonceServerBuilder};
use crate::{HmacSha256, NonceCredential};

/// A server that verifies `NonceCredential`s and manages nonce storage.
///
/// This server is responsible for the core security logic:
/// - Verifying credential signatures.
/// - Validating timestamps.
/// - Preventing nonce reuse (replay attacks).
///
/// To create an instance, use the `NonceServer::builder()` method.
pub struct NonceServer<S: NonceStorage> {
    pub(crate) default_ttl: Duration,
    pub(crate) time_window: Duration,
    pub(crate) secret: Vec<u8>,
    pub(crate) storage: Arc<S>,
}

impl<S: NonceStorage> NonceServer<S> {
    /// Creates a new `NonceServerBuilder` to construct a `NonceServer`.
    pub fn builder(secret: &[u8], storage: Arc<S>) -> NonceServerBuilder<S> {
        NonceServerBuilder::new(secret, storage)
    }

    /// Internal constructor used by the builder.
    pub(crate) fn new(
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
            .unwrap()
            .as_secs();
        let time_diff = now.abs_diff(timestamp);
        if time_diff > self.time_window.as_secs() {
            return Err(NonceError::TimestampOutOfWindow);
        }
        Ok(())
    }

    /// Verifies the HMAC signature using the provided data builder.
    pub(crate) fn verify_signature<F>(&self, signature: &str, data_builder: F) -> Result<(), NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|e| NonceError::CryptoError(e.to_string()))?;
        data_builder(&mut mac);
        let expected_signature = hex::encode(mac.finalize().into_bytes());
        if signature != expected_signature {
            return Err(NonceError::InvalidSignature);
        }
        Ok(())
    }

    /// Verifies that a nonce is valid and hasn't been used, then stores it.
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
        self.storage.set(nonce, context, self.default_ttl).await
    }

    /// Cleans up expired nonces from the storage backend.
    pub async fn cleanup_expired_nonces(&self, ttl: Duration) -> Result<usize, NonceError> {
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - ttl.as_secs() as i64;
        self.storage.cleanup_expired(cutoff_time).await
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