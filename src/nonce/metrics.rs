//! Monitoring and metrics collection for nonce authentication operations.
//!
//! This module provides a pluggable metrics system for tracking authentication
//! performance, usage patterns, and error rates. Metrics collection is optional
//! and can be enabled via the `metrics` feature.

use crate::NonceError;
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Core metrics tracked by the nonce authentication system.
#[derive(Debug, Clone, Default)]
pub struct NonceMetrics {
    /// Total number of nonces generated
    pub nonces_generated: u64,
    /// Total number of verification attempts
    pub verification_attempts: u64,
    /// Number of successful verifications
    pub verification_successes: u64,
    /// Number of failed verifications
    pub verification_failures: u64,
    /// Total number of storage operations
    pub storage_operations: u64,
    /// Number of cleanup operations performed
    pub cleanup_operations: u64,
    /// Total number of errors by category
    pub error_counts: ErrorMetrics,
    /// Performance metrics
    pub performance: PerformanceMetrics,
}

/// Error count metrics by category.
#[derive(Debug, Clone, Default)]
pub struct ErrorMetrics {
    /// Duplicate nonce errors
    pub duplicate_nonce: u64,
    /// Timestamp out of window errors
    pub timestamp_out_of_window: u64,
    /// Invalid signature errors
    pub invalid_signature: u64,
    /// Storage backend errors
    pub storage_errors: u64,
    /// Cryptographic errors
    pub crypto_errors: u64,
    /// Other errors
    pub other_errors: u64,
}

/// Performance timing metrics.
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    /// Average time for nonce generation (microseconds)
    pub avg_generation_time_us: u64,
    /// Average time for verification (microseconds)
    pub avg_verification_time_us: u64,
    /// Average time for storage operations (microseconds)
    pub avg_storage_time_us: u64,
    /// Number of samples used for averages
    pub sample_count: u64,
}

/// Events that can be tracked by the metrics system.
#[derive(Debug, Clone)]
pub enum MetricEvent {
    /// A nonce was generated
    NonceGenerated {
        /// Time taken to generate
        duration: Duration,
        /// Optional context
        context: Option<String>,
    },
    /// A verification attempt was made
    VerificationAttempt {
        /// Time taken to verify
        duration: Duration,
        /// Whether verification succeeded
        success: bool,
        /// Optional context
        context: Option<String>,
    },
    /// A storage operation was performed
    StorageOperation {
        /// Type of operation (get, set, exists, cleanup)
        operation: String,
        /// Time taken
        duration: Duration,
        /// Whether operation succeeded
        success: bool,
    },
    /// A cleanup operation was performed
    CleanupOperation {
        /// Number of items cleaned up
        items_cleaned: usize,
        /// Time taken
        duration: Duration,
    },
    /// An error occurred
    Error {
        /// The error code that occurred
        error_code: &'static str,
        /// Error message
        error_message: String,
        /// Optional context
        context: Option<String>,
    },
}

/// Trait for metrics collection backends.
///
/// This trait allows different metrics collection strategies to be plugged in,
/// from simple in-memory counters to external monitoring systems like Prometheus
/// or StatsD.
///
/// # Thread Safety
///
/// All methods must be thread-safe as they may be called concurrently from
/// multiple threads.
///
/// # Example Implementation
///
/// ```rust
/// use nonce_auth::nonce::{MetricsCollector, MetricEvent, NonceMetrics};
/// use async_trait::async_trait;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// #[derive(Default)]
/// pub struct SimpleMetricsCollector {
///     metrics: Arc<RwLock<NonceMetrics>>,
/// }
///
/// #[async_trait]
/// impl MetricsCollector for SimpleMetricsCollector {
///     async fn record_event(&self, event: MetricEvent) {
///         // Implementation here
///     }
///
///     async fn get_metrics(&self) -> Result<NonceMetrics, nonce_auth::NonceError> {
///         Ok(self.metrics.read().await.clone())
///     }
///
///     async fn reset_metrics(&self) -> Result<(), nonce_auth::NonceError> {
///         *self.metrics.write().await = NonceMetrics::default();
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait MetricsCollector: Send + Sync {
    /// Record a metric event.
    ///
    /// This method should be fast and non-blocking as it may be called
    /// frequently during normal operation.
    async fn record_event(&self, event: MetricEvent);

    /// Get current metrics snapshot.
    ///
    /// Returns a point-in-time snapshot of all collected metrics.
    async fn get_metrics(&self) -> Result<NonceMetrics, NonceError>;

    /// Reset all metrics to zero.
    ///
    /// This can be useful for periodic reporting or testing.
    async fn reset_metrics(&self) -> Result<(), NonceError>;

    /// Flush any buffered metrics.
    ///
    /// Some implementations may buffer metrics for performance. This method
    /// ensures all metrics are persisted or sent to external systems.
    async fn flush(&self) -> Result<(), NonceError> {
        // Default implementation does nothing
        Ok(())
    }
}

/// Simple in-memory metrics collector.
///
/// This is the default metrics collector that keeps all metrics in memory
/// using atomic counters. It's suitable for single-instance applications
/// and provides good performance with minimal overhead.
///
/// # Features
///
/// - **Thread-safe**: Uses atomic operations for concurrent access
/// - **Low overhead**: Minimal performance impact on normal operations  
/// - **Real-time**: Metrics are immediately available
/// - **No persistence**: Metrics are lost when the application restarts
///
/// # Example
///
/// ```rust
/// use nonce_auth::nonce::{InMemoryMetricsCollector, MetricsCollector, MetricEvent};
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), nonce_auth::NonceError> {
/// let collector = InMemoryMetricsCollector::new();
///
/// // Record some events
/// collector.record_event(MetricEvent::NonceGenerated {
///     duration: Duration::from_micros(100),
///     context: Some("user123".to_string()),
/// }).await;
///
/// // Get current metrics
/// let metrics = collector.get_metrics().await?;
/// println!("Nonces generated: {}", metrics.nonces_generated);
///
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct InMemoryMetricsCollector {
    nonces_generated: AtomicU64,
    verification_attempts: AtomicU64,
    verification_successes: AtomicU64,
    verification_failures: AtomicU64,
    storage_operations: AtomicU64,
    cleanup_operations: AtomicU64,

    // Error counts
    duplicate_nonce_errors: AtomicU64,
    timestamp_out_of_window_errors: AtomicU64,
    invalid_signature_errors: AtomicU64,
    storage_errors: AtomicU64,
    crypto_errors: AtomicU64,
    other_errors: AtomicU64,

    // Performance tracking
    generation_time_total: AtomicU64,
    verification_time_total: AtomicU64,
    storage_time_total: AtomicU64,
    generation_samples: AtomicU64,
    verification_samples: AtomicU64,
    storage_samples: AtomicU64,
}

impl InMemoryMetricsCollector {
    /// Create a new in-memory metrics collector.
    pub fn new() -> Self {
        Self {
            nonces_generated: AtomicU64::new(0),
            verification_attempts: AtomicU64::new(0),
            verification_successes: AtomicU64::new(0),
            verification_failures: AtomicU64::new(0),
            storage_operations: AtomicU64::new(0),
            cleanup_operations: AtomicU64::new(0),
            duplicate_nonce_errors: AtomicU64::new(0),
            timestamp_out_of_window_errors: AtomicU64::new(0),
            invalid_signature_errors: AtomicU64::new(0),
            storage_errors: AtomicU64::new(0),
            crypto_errors: AtomicU64::new(0),
            other_errors: AtomicU64::new(0),
            generation_time_total: AtomicU64::new(0),
            verification_time_total: AtomicU64::new(0),
            storage_time_total: AtomicU64::new(0),
            generation_samples: AtomicU64::new(0),
            verification_samples: AtomicU64::new(0),
            storage_samples: AtomicU64::new(0),
        }
    }
}

impl Default for InMemoryMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MetricsCollector for InMemoryMetricsCollector {
    async fn record_event(&self, event: MetricEvent) {
        match event {
            MetricEvent::NonceGenerated { duration, .. } => {
                self.nonces_generated.fetch_add(1, Ordering::Relaxed);
                self.generation_time_total
                    .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
                self.generation_samples.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::VerificationAttempt {
                duration, success, ..
            } => {
                self.verification_attempts.fetch_add(1, Ordering::Relaxed);
                if success {
                    self.verification_successes.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.verification_failures.fetch_add(1, Ordering::Relaxed);
                }
                self.verification_time_total
                    .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
                self.verification_samples.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::StorageOperation {
                duration, success, ..
            } => {
                if success {
                    self.storage_operations.fetch_add(1, Ordering::Relaxed);
                }
                self.storage_time_total
                    .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
                self.storage_samples.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::CleanupOperation { .. } => {
                self.cleanup_operations.fetch_add(1, Ordering::Relaxed);
            }
            MetricEvent::Error { error_code, .. } => match error_code {
                "duplicate_nonce" => {
                    self.duplicate_nonce_errors.fetch_add(1, Ordering::Relaxed);
                }
                "timestamp_out_of_window" => {
                    self.timestamp_out_of_window_errors
                        .fetch_add(1, Ordering::Relaxed);
                }
                "invalid_signature" => {
                    self.invalid_signature_errors
                        .fetch_add(1, Ordering::Relaxed);
                }
                "storage_error" => {
                    self.storage_errors.fetch_add(1, Ordering::Relaxed);
                }
                "crypto_error" => {
                    self.crypto_errors.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    self.other_errors.fetch_add(1, Ordering::Relaxed);
                }
            },
        }
    }

    async fn get_metrics(&self) -> Result<NonceMetrics, NonceError> {
        let generation_samples = self.generation_samples.load(Ordering::Relaxed);
        let verification_samples = self.verification_samples.load(Ordering::Relaxed);
        let storage_samples = self.storage_samples.load(Ordering::Relaxed);

        Ok(NonceMetrics {
            nonces_generated: self.nonces_generated.load(Ordering::Relaxed),
            verification_attempts: self.verification_attempts.load(Ordering::Relaxed),
            verification_successes: self.verification_successes.load(Ordering::Relaxed),
            verification_failures: self.verification_failures.load(Ordering::Relaxed),
            storage_operations: self.storage_operations.load(Ordering::Relaxed),
            cleanup_operations: self.cleanup_operations.load(Ordering::Relaxed),
            error_counts: ErrorMetrics {
                duplicate_nonce: self.duplicate_nonce_errors.load(Ordering::Relaxed),
                timestamp_out_of_window: self
                    .timestamp_out_of_window_errors
                    .load(Ordering::Relaxed),
                invalid_signature: self.invalid_signature_errors.load(Ordering::Relaxed),
                storage_errors: self.storage_errors.load(Ordering::Relaxed),
                crypto_errors: self.crypto_errors.load(Ordering::Relaxed),
                other_errors: self.other_errors.load(Ordering::Relaxed),
            },
            performance: PerformanceMetrics {
                avg_generation_time_us: if generation_samples > 0 {
                    self.generation_time_total.load(Ordering::Relaxed) / generation_samples
                } else {
                    0
                },
                avg_verification_time_us: if verification_samples > 0 {
                    self.verification_time_total.load(Ordering::Relaxed) / verification_samples
                } else {
                    0
                },
                avg_storage_time_us: if storage_samples > 0 {
                    self.storage_time_total.load(Ordering::Relaxed) / storage_samples
                } else {
                    0
                },
                sample_count: generation_samples + verification_samples + storage_samples,
            },
        })
    }

    async fn reset_metrics(&self) -> Result<(), NonceError> {
        // Reset all atomic counters to zero
        self.nonces_generated.store(0, Ordering::Relaxed);
        self.verification_attempts.store(0, Ordering::Relaxed);
        self.verification_successes.store(0, Ordering::Relaxed);
        self.verification_failures.store(0, Ordering::Relaxed);
        self.storage_operations.store(0, Ordering::Relaxed);
        self.cleanup_operations.store(0, Ordering::Relaxed);
        self.duplicate_nonce_errors.store(0, Ordering::Relaxed);
        self.timestamp_out_of_window_errors
            .store(0, Ordering::Relaxed);
        self.invalid_signature_errors.store(0, Ordering::Relaxed);
        self.storage_errors.store(0, Ordering::Relaxed);
        self.crypto_errors.store(0, Ordering::Relaxed);
        self.other_errors.store(0, Ordering::Relaxed);
        self.generation_time_total.store(0, Ordering::Relaxed);
        self.verification_time_total.store(0, Ordering::Relaxed);
        self.storage_time_total.store(0, Ordering::Relaxed);
        self.generation_samples.store(0, Ordering::Relaxed);
        self.verification_samples.store(0, Ordering::Relaxed);
        self.storage_samples.store(0, Ordering::Relaxed);
        Ok(())
    }
}

/// No-op metrics collector that discards all metrics.
///
/// This collector can be used when metrics collection is disabled or
/// not desired. All operations are no-ops and have minimal performance impact.
#[derive(Debug, Default)]
pub struct NoOpMetricsCollector;

impl NoOpMetricsCollector {
    /// Create a new no-op metrics collector.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl MetricsCollector for NoOpMetricsCollector {
    async fn record_event(&self, _event: MetricEvent) {
        // Do nothing
    }

    async fn get_metrics(&self) -> Result<NonceMetrics, NonceError> {
        Ok(NonceMetrics::default())
    }

    async fn reset_metrics(&self) -> Result<(), NonceError> {
        Ok(())
    }
}

/// Helper for timing operations and recording metrics.
///
/// This utility makes it easy to time operations and automatically
/// record the results to a metrics collector.
///
/// # Example
///
/// ```rust
/// use nonce_auth::nonce::{MetricsTimer, InMemoryMetricsCollector, MetricEvent};
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), nonce_auth::NonceError> {
/// let collector = Arc::new(InMemoryMetricsCollector::new());
/// let mut timer = MetricsTimer::new(Arc::clone(&collector) as Arc<dyn nonce_auth::nonce::MetricsCollector>);
///
/// // Time an operation
/// let result = timer.time_async(async {
///     // Some async operation
///     tokio::time::sleep(std::time::Duration::from_millis(10)).await;
///     Ok::<_, nonce_auth::NonceError>(42)
/// }).await;
///
/// // Record the timing
/// timer.record(MetricEvent::NonceGenerated {
///     duration: timer.elapsed(),
///     context: None,
/// }).await;
///
/// # Ok(())
/// # }
/// ```
pub struct MetricsTimer {
    collector: Arc<dyn MetricsCollector>,
    start_time: Instant,
}

impl MetricsTimer {
    /// Create a new metrics timer.
    pub fn new(collector: Arc<dyn MetricsCollector>) -> Self {
        Self {
            collector,
            start_time: Instant::now(),
        }
    }

    /// Get the elapsed time since the timer was created.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Reset the timer to the current time.
    pub fn reset(&mut self) {
        self.start_time = Instant::now();
    }

    /// Record a metric event with timing information.
    pub async fn record(&self, event: MetricEvent) {
        self.collector.record_event(event).await;
    }

    /// Time an async operation and return its result.
    pub async fn time_async<F, T, E>(&mut self, operation: F) -> Result<T, E>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        self.reset();
        operation.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration as TokioDuration, sleep};

    #[tokio::test]
    async fn test_in_memory_metrics_collector() -> Result<(), NonceError> {
        let collector = InMemoryMetricsCollector::new();

        // Record some events
        collector
            .record_event(MetricEvent::NonceGenerated {
                duration: Duration::from_micros(100),
                context: None,
            })
            .await;

        collector
            .record_event(MetricEvent::VerificationAttempt {
                duration: Duration::from_micros(200),
                success: true,
                context: None,
            })
            .await;

        collector
            .record_event(MetricEvent::VerificationAttempt {
                duration: Duration::from_micros(150),
                success: false,
                context: None,
            })
            .await;

        collector
            .record_event(MetricEvent::Error {
                error_code: "duplicate_nonce",
                error_message: "Duplicate nonce error".to_string(),
                context: None,
            })
            .await;

        // Get metrics
        let metrics = collector.get_metrics().await?;

        assert_eq!(metrics.nonces_generated, 1);
        assert_eq!(metrics.verification_attempts, 2);
        assert_eq!(metrics.verification_successes, 1);
        assert_eq!(metrics.verification_failures, 1);
        assert_eq!(metrics.error_counts.duplicate_nonce, 1);
        assert_eq!(metrics.performance.avg_generation_time_us, 100);
        assert_eq!(metrics.performance.avg_verification_time_us, 175); // (200 + 150) / 2

        // Reset metrics
        collector.reset_metrics().await?;
        let reset_metrics = collector.get_metrics().await?;
        assert_eq!(reset_metrics.nonces_generated, 0);
        assert_eq!(reset_metrics.verification_attempts, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_no_op_metrics_collector() -> Result<(), NonceError> {
        let collector = NoOpMetricsCollector::new();

        // Record events (should be ignored)
        collector
            .record_event(MetricEvent::NonceGenerated {
                duration: Duration::from_micros(100),
                context: None,
            })
            .await;

        // Metrics should always be zero
        let metrics = collector.get_metrics().await?;
        assert_eq!(metrics.nonces_generated, 0);
        assert_eq!(metrics.verification_attempts, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_metrics_timer() -> Result<(), NonceError> {
        let collector = Arc::new(InMemoryMetricsCollector::new());
        let mut timer = MetricsTimer::new(Arc::clone(&collector) as Arc<dyn MetricsCollector>);

        // Time an operation
        let result = timer
            .time_async(async {
                sleep(TokioDuration::from_millis(10)).await;
                Ok::<i32, NonceError>(42)
            })
            .await?;

        assert_eq!(result, 42);
        assert!(timer.elapsed() >= Duration::from_millis(10));

        // Record the timing
        timer
            .record(MetricEvent::NonceGenerated {
                duration: timer.elapsed(),
                context: None,
            })
            .await;

        let metrics = collector.get_metrics().await?;
        assert_eq!(metrics.nonces_generated, 1);
        assert!(metrics.performance.avg_generation_time_us >= 10000); // At least 10ms in microseconds

        Ok(())
    }

    #[tokio::test]
    async fn test_error_categorization() -> Result<(), NonceError> {
        let collector = InMemoryMetricsCollector::new();

        // Test different error types using error codes
        let error_codes = vec![
            "duplicate_nonce",
            "timestamp_out_of_window",
            "invalid_signature",
            "storage_error",
            "crypto_error",
            "invalid_input",
        ];

        for error_code in error_codes {
            collector
                .record_event(MetricEvent::Error {
                    error_code,
                    error_message: format!("Test error: {error_code}"),
                    context: None,
                })
                .await;
        }

        let metrics = collector.get_metrics().await?;
        assert_eq!(metrics.error_counts.duplicate_nonce, 1);
        assert_eq!(metrics.error_counts.timestamp_out_of_window, 1);
        assert_eq!(metrics.error_counts.invalid_signature, 1);
        assert_eq!(metrics.error_counts.storage_errors, 1);
        assert_eq!(metrics.error_counts.crypto_errors, 1);
        assert_eq!(metrics.error_counts.other_errors, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_metrics_collection() -> Result<(), NonceError> {
        let collector = Arc::new(InMemoryMetricsCollector::new());
        let mut handles = vec![];

        // Spawn multiple tasks recording metrics concurrently
        for i in 0..100 {
            let collector_clone = Arc::clone(&collector);
            let handle = tokio::spawn(async move {
                collector_clone
                    .record_event(MetricEvent::NonceGenerated {
                        duration: Duration::from_micros(i),
                        context: None,
                    })
                    .await;
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        let metrics = collector.get_metrics().await?;
        assert_eq!(metrics.nonces_generated, 100);
        assert!(metrics.performance.sample_count >= 100);

        Ok(())
    }

    #[tokio::test]
    async fn test_performance_averages_calculation() -> Result<(), NonceError> {
        let collector = InMemoryMetricsCollector::new();

        // Record generation events with known durations
        collector
            .record_event(MetricEvent::NonceGenerated {
                duration: Duration::from_micros(100),
                context: None,
            })
            .await;
        collector
            .record_event(MetricEvent::NonceGenerated {
                duration: Duration::from_micros(200),
                context: None,
            })
            .await;
        collector
            .record_event(MetricEvent::NonceGenerated {
                duration: Duration::from_micros(300),
                context: None,
            })
            .await;

        // Record verification events
        collector
            .record_event(MetricEvent::VerificationAttempt {
                duration: Duration::from_micros(500),
                success: true,
                context: None,
            })
            .await;
        collector
            .record_event(MetricEvent::VerificationAttempt {
                duration: Duration::from_micros(700),
                success: false,
                context: None,
            })
            .await;

        // Record storage events
        collector
            .record_event(MetricEvent::StorageOperation {
                operation: "set".to_string(),
                duration: Duration::from_micros(150),
                success: true,
            })
            .await;
        collector
            .record_event(MetricEvent::StorageOperation {
                operation: "get".to_string(),
                duration: Duration::from_micros(50),
                success: true,
            })
            .await;

        let metrics = collector.get_metrics().await?;

        // Test average calculations
        assert_eq!(metrics.performance.avg_generation_time_us, 200); // (100+200+300)/3
        assert_eq!(metrics.performance.avg_verification_time_us, 600); // (500+700)/2
        assert_eq!(metrics.performance.avg_storage_time_us, 100); // (150+50)/2
        assert_eq!(metrics.performance.sample_count, 7); // 3+2+2

        Ok(())
    }

    #[tokio::test]
    async fn test_storage_operation_success_tracking() -> Result<(), NonceError> {
        let collector = InMemoryMetricsCollector::new();

        // Record successful storage operations
        collector
            .record_event(MetricEvent::StorageOperation {
                operation: "set".to_string(),
                duration: Duration::from_micros(100),
                success: true,
            })
            .await;
        collector
            .record_event(MetricEvent::StorageOperation {
                operation: "get".to_string(),
                duration: Duration::from_micros(50),
                success: true,
            })
            .await;

        // Record failed storage operation
        collector
            .record_event(MetricEvent::StorageOperation {
                operation: "cleanup".to_string(),
                duration: Duration::from_micros(200),
                success: false,
            })
            .await;

        let metrics = collector.get_metrics().await?;

        // Only successful operations should be counted in storage_operations
        assert_eq!(metrics.storage_operations, 2);
        // But all operations should contribute to timing averages
        assert_eq!(metrics.performance.avg_storage_time_us, 116); // (100+50+200)/3
        assert_eq!(metrics.performance.sample_count, 3);

        Ok(())
    }

    #[tokio::test]
    async fn test_cleanup_operations_tracking() -> Result<(), NonceError> {
        let collector = InMemoryMetricsCollector::new();

        // Record cleanup operations
        collector
            .record_event(MetricEvent::CleanupOperation {
                items_cleaned: 100,
                duration: Duration::from_millis(5),
            })
            .await;
        collector
            .record_event(MetricEvent::CleanupOperation {
                items_cleaned: 50,
                duration: Duration::from_millis(2),
            })
            .await;

        let metrics = collector.get_metrics().await?;
        assert_eq!(metrics.cleanup_operations, 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_metrics_reset_comprehensive() -> Result<(), NonceError> {
        let collector = InMemoryMetricsCollector::new();

        // Fill up all metrics
        collector
            .record_event(MetricEvent::NonceGenerated {
                duration: Duration::from_micros(100),
                context: Some("test".to_string()),
            })
            .await;
        collector
            .record_event(MetricEvent::VerificationAttempt {
                duration: Duration::from_micros(200),
                success: true,
                context: None,
            })
            .await;
        collector
            .record_event(MetricEvent::StorageOperation {
                operation: "set".to_string(),
                duration: Duration::from_micros(50),
                success: true,
            })
            .await;
        collector
            .record_event(MetricEvent::CleanupOperation {
                items_cleaned: 10,
                duration: Duration::from_millis(1),
            })
            .await;
        collector
            .record_event(MetricEvent::Error {
                error_code: "invalid_signature",
                error_message: "Test error".to_string(),
                context: None,
            })
            .await;

        // Verify metrics were recorded
        let before_reset = collector.get_metrics().await?;
        assert!(before_reset.nonces_generated > 0);
        assert!(before_reset.verification_attempts > 0);
        assert!(before_reset.storage_operations > 0);
        assert!(before_reset.cleanup_operations > 0);
        assert!(before_reset.error_counts.invalid_signature > 0);
        assert!(before_reset.performance.sample_count > 0);

        // Reset metrics
        collector.reset_metrics().await?;

        // Verify all metrics are zero
        let after_reset = collector.get_metrics().await?;
        assert_eq!(after_reset.nonces_generated, 0);
        assert_eq!(after_reset.verification_attempts, 0);
        assert_eq!(after_reset.verification_successes, 0);
        assert_eq!(after_reset.verification_failures, 0);
        assert_eq!(after_reset.storage_operations, 0);
        assert_eq!(after_reset.cleanup_operations, 0);
        assert_eq!(after_reset.error_counts.duplicate_nonce, 0);
        assert_eq!(after_reset.error_counts.timestamp_out_of_window, 0);
        assert_eq!(after_reset.error_counts.invalid_signature, 0);
        assert_eq!(after_reset.error_counts.storage_errors, 0);
        assert_eq!(after_reset.error_counts.crypto_errors, 0);
        assert_eq!(after_reset.error_counts.other_errors, 0);
        assert_eq!(after_reset.performance.avg_generation_time_us, 0);
        assert_eq!(after_reset.performance.avg_verification_time_us, 0);
        assert_eq!(after_reset.performance.avg_storage_time_us, 0);
        assert_eq!(after_reset.performance.sample_count, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_metrics_timer_reset_and_reuse() -> Result<(), NonceError> {
        let collector = Arc::new(InMemoryMetricsCollector::new());
        let mut timer = MetricsTimer::new(Arc::clone(&collector) as Arc<dyn MetricsCollector>);

        // First timing
        let result1 = timer
            .time_async(async {
                sleep(TokioDuration::from_millis(10)).await;
                Ok::<i32, NonceError>(1)
            })
            .await?;

        let first_elapsed = timer.elapsed();
        timer
            .record(MetricEvent::NonceGenerated {
                duration: first_elapsed,
                context: None,
            })
            .await;

        // Reset and reuse timer
        timer.reset();
        let result2 = timer
            .time_async(async {
                sleep(TokioDuration::from_millis(5)).await;
                Ok::<i32, NonceError>(2)
            })
            .await?;

        let second_elapsed = timer.elapsed();
        timer
            .record(MetricEvent::VerificationAttempt {
                duration: second_elapsed,
                success: true,
                context: None,
            })
            .await;

        assert_eq!(result1, 1);
        assert_eq!(result2, 2);
        assert!(first_elapsed >= Duration::from_millis(10));
        assert!(second_elapsed >= Duration::from_millis(5));
        assert!(second_elapsed < first_elapsed); // Second timing should be shorter

        let metrics = collector.get_metrics().await?;
        assert_eq!(metrics.nonces_generated, 1);
        assert_eq!(metrics.verification_attempts, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_edge_cases_zero_samples() -> Result<(), NonceError> {
        let collector = InMemoryMetricsCollector::new();

        // Get metrics without any events - should not panic and return zeros
        let metrics = collector.get_metrics().await?;
        assert_eq!(metrics.performance.avg_generation_time_us, 0);
        assert_eq!(metrics.performance.avg_verification_time_us, 0);
        assert_eq!(metrics.performance.avg_storage_time_us, 0);
        assert_eq!(metrics.performance.sample_count, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_context_information_preservation() -> Result<(), NonceError> {
        let collector = InMemoryMetricsCollector::new();

        // Record events with different contexts
        collector
            .record_event(MetricEvent::NonceGenerated {
                duration: Duration::from_micros(100),
                context: Some("user123".to_string()),
            })
            .await;
        collector
            .record_event(MetricEvent::VerificationAttempt {
                duration: Duration::from_micros(200),
                success: true,
                context: Some("api_key_auth".to_string()),
            })
            .await;
        collector
            .record_event(MetricEvent::Error {
                error_code: "duplicate_nonce",
                error_message: "Nonce already used".to_string(),
                context: Some("mobile_app".to_string()),
            })
            .await;

        // Even though contexts are passed, the counts should still be correct
        let metrics = collector.get_metrics().await?;
        assert_eq!(metrics.nonces_generated, 1);
        assert_eq!(metrics.verification_attempts, 1);
        assert_eq!(metrics.verification_successes, 1);
        assert_eq!(metrics.error_counts.duplicate_nonce, 1);

        Ok(())
    }
}
