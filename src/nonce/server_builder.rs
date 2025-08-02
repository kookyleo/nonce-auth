use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::nonce::cleanup::{BoxedCleanupStrategy, CustomCleanupStrategy, HybridCleanupStrategy};
use crate::nonce::{NonceError, NonceServer};
use crate::storage::{MemoryStorage, NonceStorage};

#[cfg(feature = "metrics")]
use crate::nonce::metrics::{InMemoryMetricsCollector, MetricsCollector};

/// Predefined configuration presets for common use cases.
///
/// These presets provide sensible defaults for different deployment scenarios,
/// balancing security, usability, and performance requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPreset {
    /// Production-ready configuration.
    ///
    /// Balanced security and usability:
    /// - TTL: 5 minutes (reasonable balance between security and usability)
    /// - Time window: 1 minute (accounts for network delays and clock skew)
    Production,

    /// Development-friendly configuration.
    ///
    /// Relaxed settings for easier testing and debugging:
    /// - TTL: 10 minutes (longer window for testing)
    /// - Time window: 2 minutes (more forgiving for local development)
    Development,

    /// High-security configuration.
    ///
    /// Maximum security with strict timing requirements:
    /// - TTL: 2 minutes (very short window to minimize exposure)
    /// - Time window: 30 seconds (strict timing requirements)
    HighSecurity,

    /// Load configuration from environment variables.
    ///
    /// Reads configuration from:
    /// - `NONCE_AUTH_DEFAULT_TTL`: Default TTL in seconds (default: 300)
    /// - `NONCE_AUTH_DEFAULT_TIME_WINDOW`: Time window in seconds (default: 60)
    FromEnv,
}

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
    #[cfg(feature = "metrics")]
    metrics_collector: Option<Arc<dyn MetricsCollector>>,
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
            #[cfg(feature = "metrics")]
            metrics_collector: None, // Will default to NoOpMetricsCollector in build_and_init
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
            #[cfg(feature = "metrics")]
            metrics_collector: self.metrics_collector,
        }
    }

    /// Sets a custom time-to-live (TTL) for nonces.
    ///
    /// If not set, defaults to 5 minutes.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sets the time-to-live (TTL) for nonces (simplified API).
    ///
    /// This is a convenience method identical to `with_ttl` but with a shorter name
    /// for more ergonomic builder usage.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Duration;
    /// # use nonce_auth::NonceServer;
    /// #
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let server = NonceServer::builder()
    ///     .ttl(Duration::from_secs(300))
    ///     .time_window(Duration::from_secs(60))
    ///     .build_and_init()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn ttl(self, ttl: Duration) -> Self {
        self.with_ttl(ttl)
    }

    /// Sets a custom time window for timestamp validation.
    ///
    /// If not set, defaults to 1 minute.
    pub fn with_time_window(mut self, time_window: Duration) -> Self {
        self.time_window = Some(time_window);
        self
    }

    /// Sets the time window for timestamp validation (simplified API).
    ///
    /// This is a convenience method identical to `with_time_window` but with a shorter name
    /// for more ergonomic builder usage.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::time::Duration;
    /// # use nonce_auth::NonceServer;
    /// #
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let server = NonceServer::builder()
    ///     .ttl(Duration::from_secs(300))
    ///     .time_window(Duration::from_secs(60))
    ///     .build_and_init()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn time_window(self, time_window: Duration) -> Self {
        self.with_time_window(time_window)
    }

    /// Applies a predefined configuration preset.
    ///
    /// This method provides common configuration patterns for different use cases:
    ///
    /// - `ConfigPreset::Production`: Balanced security and usability (TTL: 5min, window: 1min)
    /// - `ConfigPreset::Development`: Relaxed for testing (TTL: 10min, window: 2min)  
    /// - `ConfigPreset::HighSecurity`: Maximum security (TTL: 2min, window: 30s)
    /// - `ConfigPreset::FromEnv`: Load from environment variables
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::{NonceServer, ConfigPreset};
    /// #
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// // Production configuration
    /// let server = NonceServer::builder()
    ///     .with_preset(ConfigPreset::Production)
    ///     .build_and_init()
    ///     .await?;
    ///
    /// // Development configuration  
    /// let dev_server = NonceServer::builder()
    ///     .with_preset(ConfigPreset::Development)
    ///     .build_and_init()
    ///     .await?;
    ///
    /// // High security configuration
    /// let secure_server = NonceServer::builder()
    ///     .with_preset(ConfigPreset::HighSecurity)
    ///     .build_and_init()
    ///     .await?;
    ///
    /// // Load from environment variables
    /// let env_server = NonceServer::builder()
    ///     .with_preset(ConfigPreset::FromEnv)
    ///     .build_and_init()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_preset(self, preset: ConfigPreset) -> Self {
        match preset {
            ConfigPreset::Production => self
                .ttl(Duration::from_secs(300))
                .time_window(Duration::from_secs(60)),
            ConfigPreset::Development => self
                .ttl(Duration::from_secs(600))
                .time_window(Duration::from_secs(120)),
            ConfigPreset::HighSecurity => self
                .ttl(Duration::from_secs(120))
                .time_window(Duration::from_secs(30)),
            ConfigPreset::FromEnv => {
                let ttl = Duration::from_secs(
                    std::env::var("NONCE_AUTH_DEFAULT_TTL")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(300),
                );

                let time_window = Duration::from_secs(
                    std::env::var("NONCE_AUTH_DEFAULT_TIME_WINDOW")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(60),
                );

                self.ttl(ttl).time_window(time_window)
            }
        }
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

    /// Configures a custom metrics collector for monitoring nonce operations.
    ///
    /// By default, metrics collection is disabled (uses `NoOpMetricsCollector`).
    /// This method allows you to enable metrics collection with a custom collector.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::sync::Arc;
    /// # use nonce_auth::NonceServer;
    /// # use nonce_auth::nonce::{InMemoryMetricsCollector, MetricsCollector};
    /// #
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let metrics_collector = Arc::new(InMemoryMetricsCollector::new());
    ///
    /// let server = NonceServer::builder()
    ///     .with_metrics_collector(Arc::clone(&metrics_collector) as Arc<dyn MetricsCollector>)
    ///     .build_and_init()
    ///     .await?;
    ///
    /// // Later, you can retrieve metrics
    /// let metrics = metrics_collector.get_metrics().await?;
    /// println!("Nonces generated: {}", metrics.nonces_generated);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "metrics")]
    pub fn with_metrics_collector(mut self, collector: Arc<dyn MetricsCollector>) -> Self {
        self.metrics_collector = Some(collector);
        self
    }

    /// Enables basic in-memory metrics collection.
    ///
    /// This is a convenience method that creates and configures an `InMemoryMetricsCollector`
    /// for you. The collector tracks basic metrics like nonce generation count, verification
    /// attempts, success/failure rates, and performance timings.
    ///
    /// Returns the configured builder and a reference to the metrics collector that you
    /// can use to retrieve metrics later.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::NonceServer;
    /// # use nonce_auth::nonce::MetricsCollector;
    /// #
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let (server_builder, metrics_collector) = NonceServer::builder()
    ///     .enable_basic_metrics();
    ///
    /// let server = server_builder.build_and_init().await?;
    ///
    /// // Use server for authentication...
    ///
    /// // Later, retrieve metrics
    /// let metrics = metrics_collector.get_metrics().await?;
    /// println!("Total verifications: {}", metrics.verification_attempts);
    /// println!("Success rate: {:.1}%",
    ///     (metrics.verification_successes as f64 / metrics.verification_attempts as f64) * 100.0);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "metrics")]
    pub fn enable_basic_metrics(mut self) -> (Self, Arc<InMemoryMetricsCollector>) {
        let collector = Arc::new(InMemoryMetricsCollector::new());
        self.metrics_collector = Some(Arc::clone(&collector) as Arc<dyn MetricsCollector>);
        (self, collector)
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

        #[cfg(feature = "metrics")]
        let server = NonceServer::new(
            self.storage,
            self.ttl,
            self.time_window,
            cleanup_strategy,
            self.metrics_collector,
        );

        #[cfg(not(feature = "metrics"))]
        let server = NonceServer::new(self.storage, self.ttl, self.time_window, cleanup_strategy);

        server.init().await?;
        Ok(server)
    }
}
