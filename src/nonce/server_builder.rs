use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::nonce::cleanup::{BoxedCleanupStrategy, CustomCleanupStrategy, HybridCleanupStrategy};
use crate::nonce::{NonceError, NonceServer};
use crate::storage::{MemoryStorage, NonceStorage};

/// A builder for creating a `NonceServer` instance.
///
/// This builder defaults to using `MemoryStorage` and allows for ergonomic
/// configuration of all server parameters.
#[must_use = "The builder does nothing unless `.build_and_init()` is called."]
pub struct NonceServerBuilder<S: NonceStorage> {
    storage: Arc<S>,
    ttl: Option<Duration>,
    time_window: Option<Duration>,
    cleanup_strategy: Option<BoxedCleanupStrategy>,
}

impl NonceServerBuilder<MemoryStorage> {
    /// Creates a new builder.
    ///
    /// By default, this builder uses `MemoryStorage`. Use `.with_storage()` to
    /// provide a different storage backend.
    pub(crate) fn new() -> Self {
        Self {
            storage: Arc::new(MemoryStorage::new()),
            ttl: None,
            time_window: None,
            cleanup_strategy: None, // Will default to HybridCleanupStrategy in build_and_init
        }
    }
}

impl<S: NonceStorage + 'static> NonceServerBuilder<S> {
    /// Specifies a custom storage backend to use instead of the default `MemoryStorage`.
    pub fn with_storage<T: NonceStorage + 'static>(self, storage: Arc<T>) -> NonceServerBuilder<T> {
        NonceServerBuilder {
            storage,
            ttl: self.ttl,
            time_window: self.time_window,
            cleanup_strategy: self.cleanup_strategy,
        }
    }

    /// Sets a custom time-to-live (TTL) for nonces.
    ///
    /// If not set, defaults to 5 minutes.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sets a custom time window for timestamp validation.
    ///
    /// If not set, defaults to 1 minute.
    pub fn with_time_window(mut self, time_window: Duration) -> Self {
        self.time_window = Some(time_window);
        self
    }

    /// Configures the automatic cleanup strategy with custom hybrid thresholds.
    ///
    /// By default, the server uses a hybrid cleanup strategy that triggers cleanup
    /// based on either request count (100 requests) or elapsed time (5 minutes).
    /// This method allows you to customize these thresholds.
    ///
    /// # Arguments
    ///
    /// * `count_threshold` - Number of successful nonce verifications before triggering cleanup
    /// * `time_threshold` - Maximum duration between cleanup operations
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Duration;
    /// # use nonce_auth::NonceServer;
    /// #
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// // Cleanup every 50 requests or every 2 minutes
    /// let server = NonceServer::builder()
    ///     .with_hybrid_cleanup_thresholds(50, Duration::from_secs(120))
    ///     .build_and_init()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_hybrid_cleanup_thresholds(
        mut self,
        count_threshold: u32,
        time_threshold: Duration,
    ) -> Self {
        let strategy = HybridCleanupStrategy::new(count_threshold, time_threshold);
        self.cleanup_strategy = Some(Box::new(strategy));
        self
    }

    /// Configures a custom cleanup strategy using a user-provided closure.
    ///
    /// This method allows you to completely replace the default cleanup logic
    /// with your own custom strategy. The provided closure will be called after
    /// each successful nonce verification to determine if cleanup should be triggered.
    ///
    /// # Arguments
    ///
    /// * `strategy_fn` - A closure that returns a Future<Output = bool> indicating
    ///   whether cleanup should be performed
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::sync::atomic::{AtomicU32, Ordering};
    /// # use std::sync::Arc;
    /// # use nonce_auth::NonceServer;
    /// #
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let counter = Arc::new(AtomicU32::new(0));
    /// let counter_clone = Arc::clone(&counter);
    ///
    /// // Cleanup every 10th request
    /// let server = NonceServer::builder()
    ///     .with_custom_cleanup_strategy(move || {
    ///         let counter = Arc::clone(&counter_clone);
    ///         async move {
    ///             let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
    ///             count % 10 == 0
    ///         }
    ///     })
    ///     .build_and_init()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_custom_cleanup_strategy<F, Fut>(mut self, strategy_fn: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        let strategy = CustomCleanupStrategy::new(strategy_fn);
        self.cleanup_strategy = Some(Box::new(strategy));
        self
    }

    /// Builds and initializes the `NonceServer`.
    ///
    /// This method consumes the builder and returns a fully configured and initialized server.
    /// It automatically calls the storage backend's `init()` method and sets up automatic
    /// nonce cleanup with the configured strategy (defaults to hybrid strategy with 100
    /// request count and 5-minute time thresholds).
    pub async fn build_and_init(self) -> Result<NonceServer<S>, NonceError> {
        // Use the configured cleanup strategy or default to HybridCleanupStrategy
        let cleanup_strategy = self
            .cleanup_strategy
            .unwrap_or_else(|| Box::new(HybridCleanupStrategy::default()));

        let server = NonceServer::new(self.storage, self.ttl, self.time_window, cleanup_strategy);
        server.init().await?;
        Ok(server)
    }
}
