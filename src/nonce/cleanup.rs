use std::future::Future;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

/// Strategy for determining when to perform automatic nonce cleanup.
///
/// Cleanup strategies are used by `NonceServer` to automatically trigger
/// expired nonce cleanup based on various criteria such as request count,
/// elapsed time, or custom logic.
#[async_trait]
pub trait CleanupStrategy: Send + Sync {
    /// Determines whether cleanup should be triggered.
    ///
    /// This method is called after each successful nonce verification to check
    /// if it's time to perform cleanup.
    async fn should_cleanup(&self) -> bool;

    /// Marks that cleanup has been performed and resets internal state.
    ///
    /// This method is called after cleanup has been triggered to reset
    /// counters, timestamps, or other internal state tracking.
    async fn mark_as_cleaned(&self);
}

/// Default hybrid cleanup strategy that triggers cleanup based on both
/// request count and elapsed time since the last cleanup.
///
/// This strategy maintains an internal counter of verification requests
/// and tracks the time since the last cleanup. Cleanup is triggered when
/// either threshold is exceeded.
pub struct HybridCleanupStrategy {
    count_threshold: u32,
    time_threshold: Duration,
    request_count: AtomicU32,
    last_cleanup_time: AtomicU64,
}

impl HybridCleanupStrategy {
    /// Creates a new hybrid cleanup strategy with the specified thresholds.
    ///
    /// # Arguments
    ///
    /// * `count_threshold` - Number of verification requests before triggering cleanup
    /// * `time_threshold` - Maximum time duration between cleanups
    ///
    /// # Example
    ///
    /// ```
    /// use std::time::Duration;
    /// use nonce_auth::nonce::cleanup::HybridCleanupStrategy;
    ///
    /// // Cleanup every 100 requests or every 5 minutes
    /// let strategy = HybridCleanupStrategy::new(100, Duration::from_secs(300));
    /// ```
    pub fn new(count_threshold: u32, time_threshold: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            count_threshold,
            time_threshold,
            request_count: AtomicU32::new(0),
            last_cleanup_time: AtomicU64::new(now),
        }
    }

    /// Updates the thresholds for this strategy.
    ///
    /// This method allows modifying the cleanup triggers after creation.
    pub fn set_thresholds(&mut self, count_threshold: u32, time_threshold: Duration) {
        self.count_threshold = count_threshold;
        self.time_threshold = time_threshold;
    }
}

#[async_trait]
impl CleanupStrategy for HybridCleanupStrategy {
    async fn should_cleanup(&self) -> bool {
        // Increment request count
        let count = self.request_count.fetch_add(1, Ordering::SeqCst) + 1;

        // Check count threshold
        if count >= self.count_threshold {
            return true;
        }

        // Check time threshold
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last_cleanup = self.last_cleanup_time.load(Ordering::SeqCst);
        let elapsed = now.saturating_sub(last_cleanup);

        elapsed >= self.time_threshold.as_secs()
    }

    async fn mark_as_cleaned(&self) {
        self.request_count.store(0, Ordering::SeqCst);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_cleanup_time.store(now, Ordering::SeqCst);
    }
}

impl Default for HybridCleanupStrategy {
    /// Creates a new hybrid cleanup strategy with default thresholds.
    ///
    /// Uses a count threshold of 100 requests and a time threshold of 5 minutes.
    fn default() -> Self {
        Self::new(100, Duration::from_secs(300))
    }
}

/// Wrapper for custom cleanup strategies provided via closures.
///
/// This allows users to provide their own cleanup logic as a closure
/// that returns a Future<Output = bool>.
pub struct CustomCleanupStrategy<F, Fut>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    strategy_fn: F,
}

impl<F, Fut> CustomCleanupStrategy<F, Fut>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    /// Creates a new custom cleanup strategy from a closure.
    ///
    /// # Arguments
    ///
    /// * `strategy_fn` - A closure that returns a Future<Output = bool>
    ///   indicating whether cleanup should be triggered
    ///
    /// # Example
    ///
    /// ```
    /// use nonce_auth::nonce::cleanup::CustomCleanupStrategy;
    ///
    /// let strategy = CustomCleanupStrategy::new(|| async {
    ///     // Custom cleanup logic - e.g., cleanup every other call
    ///     static mut COUNTER: u32 = 0;
    ///     unsafe {
    ///         COUNTER += 1;
    ///         COUNTER % 2 == 0
    ///     }
    /// });
    /// ```
    pub fn new(strategy_fn: F) -> Self {
        Self { strategy_fn }
    }
}

#[async_trait]
impl<F, Fut> CleanupStrategy for CustomCleanupStrategy<F, Fut>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send + 'static,
{
    async fn should_cleanup(&self) -> bool {
        (self.strategy_fn)().await
    }

    async fn mark_as_cleaned(&self) {
        // For custom strategies, state management is left to the closure
        // so we don't need to do anything here
    }
}

/// Type alias for boxed cleanup strategies to reduce verbosity.
pub type BoxedCleanupStrategy = Box<dyn CleanupStrategy>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32};
    use tokio::time::{Duration as TokioDuration, sleep};

    #[tokio::test]
    async fn test_hybrid_strategy_count_threshold() {
        let strategy = HybridCleanupStrategy::new(3, Duration::from_secs(3600)); // Long time threshold

        // First two requests should not trigger cleanup
        assert!(!strategy.should_cleanup().await);
        assert!(!strategy.should_cleanup().await);

        // Third request should trigger cleanup
        assert!(strategy.should_cleanup().await);
    }

    #[tokio::test]
    async fn test_hybrid_strategy_time_threshold() {
        let strategy = HybridCleanupStrategy::new(100, Duration::from_secs(1)); // 1 second threshold

        // First request should not trigger cleanup (count is 1, time is fresh)
        let result1 = strategy.should_cleanup().await;
        assert!(!result1, "First request should not trigger cleanup");

        // Wait for time threshold to pass
        sleep(TokioDuration::from_millis(1100)).await;

        // Next request should trigger cleanup due to time
        let result2 = strategy.should_cleanup().await;
        assert!(
            result2,
            "Second request after time threshold should trigger cleanup"
        );
    }

    #[tokio::test]
    async fn test_hybrid_strategy_reset_after_cleanup() {
        let strategy = HybridCleanupStrategy::new(2, Duration::from_secs(3600));

        // Trigger cleanup with count
        assert!(!strategy.should_cleanup().await);
        assert!(strategy.should_cleanup().await);

        // Mark as cleaned
        strategy.mark_as_cleaned().await;

        // Should reset and not trigger immediately
        assert!(!strategy.should_cleanup().await);
    }

    #[tokio::test]
    async fn test_custom_strategy() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let strategy = CustomCleanupStrategy::new(move || {
            let counter = Arc::clone(&counter_clone);
            async move {
                let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
                count.is_multiple_of(2) // Cleanup every second call
            }
        });

        // First call should not trigger cleanup
        assert!(!strategy.should_cleanup().await);

        // Second call should trigger cleanup
        assert!(strategy.should_cleanup().await);

        // Third call should not trigger cleanup
        assert!(!strategy.should_cleanup().await);
    }

    #[tokio::test]
    async fn test_custom_strategy_mark_as_cleaned_noop() {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);

        let strategy = CustomCleanupStrategy::new(move || {
            let flag = Arc::clone(&flag_clone);
            async move { flag.load(Ordering::SeqCst) }
        });

        // Should not trigger cleanup initially
        assert!(!strategy.should_cleanup().await);

        // mark_as_cleaned should be a no-op for custom strategies
        strategy.mark_as_cleaned().await;

        // Still should not trigger cleanup
        assert!(!strategy.should_cleanup().await);

        // Set flag externally
        flag.store(true, Ordering::SeqCst);

        // Now should trigger cleanup
        assert!(strategy.should_cleanup().await);
    }
}
