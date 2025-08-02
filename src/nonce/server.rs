use std::sync::Arc;
#[cfg(feature = "metrics")]
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::Mac;
use tokio;

use super::cleanup::BoxedCleanupStrategy;
use super::time_utils;
use super::{CredentialVerifier, NonceError, NonceServerBuilder, NonceStorage};
use crate::storage::MemoryStorage;
use crate::{HmacSha256, NonceCredential};

#[cfg(feature = "metrics")]
use super::metrics::{MetricEvent, MetricsCollector, NoOpMetricsCollector};

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
    #[cfg(feature = "metrics")]
    pub(crate) metrics_collector: Arc<dyn MetricsCollector>,
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
    #[cfg(feature = "metrics")]
    pub(crate) fn new(
        storage: Arc<S>,
        default_ttl: Option<Duration>,
        time_window: Option<Duration>,
        cleanup_strategy: BoxedCleanupStrategy,
        metrics_collector: Option<Arc<dyn MetricsCollector>>,
    ) -> Self {
        let default_ttl = default_ttl.unwrap_or(Duration::from_secs(300));
        let time_window = time_window.unwrap_or(Duration::from_secs(60));
        let metrics_collector =
            metrics_collector.unwrap_or_else(|| Arc::new(NoOpMetricsCollector::new()));
        Self {
            default_ttl,
            time_window,
            storage,
            cleanup_strategy,
            metrics_collector,
        }
    }

    /// Internal constructor used by the builder (non-metrics version).
    #[cfg(not(feature = "metrics"))]
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
        // Check if nonce already exists
        self.check_nonce_existence(nonce, context).await?;

        // Store the nonce
        self.store_nonce(nonce, context).await?;

        // Trigger cleanup if needed
        self.maybe_trigger_cleanup().await;

        Ok(())
    }

    /// Check if nonce already exists and handle accordingly.
    async fn check_nonce_existence(
        &self,
        nonce: &str,
        context: Option<&str>,
    ) -> Result<(), NonceError> {
        #[cfg(feature = "metrics")]
        let start_time = Instant::now();

        let get_result = self.storage.get(nonce, context).await;

        #[cfg(feature = "metrics")]
        self.record_storage_operation("get", start_time.elapsed(), get_result.is_ok())
            .await;

        if let Some(entry) = get_result? {
            return if Self::is_time_expired(entry.created_at, self.default_ttl) {
                Err(NonceError::ExpiredNonce)
            } else {
                Err(NonceError::DuplicateNonce)
            };
        }

        Ok(())
    }

    /// Store the nonce in the storage backend.
    async fn store_nonce(&self, nonce: &str, context: Option<&str>) -> Result<(), NonceError> {
        #[cfg(feature = "metrics")]
        let start_time = Instant::now();

        let set_result = self.storage.set(nonce, context, self.default_ttl).await;

        #[cfg(feature = "metrics")]
        self.record_storage_operation("set", start_time.elapsed(), set_result.is_ok())
            .await;

        set_result
    }

    /// Record storage operation metrics if enabled.
    #[cfg(feature = "metrics")]
    async fn record_storage_operation(
        &self,
        operation: &str,
        duration: std::time::Duration,
        success: bool,
    ) {
        let event = MetricEvent::StorageOperation {
            operation: operation.to_string(),
            duration,
            success,
        };
        self.metrics_collector.record_event(event).await;
    }

    /// Check cleanup strategy and trigger background cleanup if needed.
    async fn maybe_trigger_cleanup(&self) {
        if self.cleanup_strategy.should_cleanup().await {
            self.spawn_background_cleanup().await;
            self.cleanup_strategy.mark_as_cleaned().await;
        }
    }

    /// Spawn background cleanup task.
    async fn spawn_background_cleanup(&self) {
        let storage_clone = Arc::clone(&self.storage);
        let ttl = self.default_ttl;

        #[cfg(feature = "metrics")]
        let metrics_clone = Arc::clone(&self.metrics_collector);

        tokio::spawn(async move {
            #[cfg(feature = "metrics")]
            let cleanup_start_time = Instant::now();

            let cleanup_result = Self::cleanup_expired_nonces_static(&storage_clone, ttl).await;

            #[cfg(feature = "metrics")]
            {
                let duration = cleanup_start_time.elapsed();
                if let Ok(items_cleaned) = cleanup_result {
                    let event = MetricEvent::CleanupOperation {
                        items_cleaned,
                        duration,
                    };
                    metrics_clone.record_event(event).await;
                }
            }

            if let Err(e) = cleanup_result {
                tracing::warn!("Background cleanup failed: {}", e);
            }
        });
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
        time_utils::is_expired(created_at, ttl.as_secs())
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
