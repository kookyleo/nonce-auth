//! Performance test suite for nonce-auth storage backends
//!
//! This module contains comprehensive performance tests for all storage backends
//! to ensure optimizations provide expected improvements and meet performance targets.
//!
//! ## Running Performance Tests
//!
//! Run all performance tests:
//! ```bash
//! cargo test --test performance
//! ```
//!
//! Run specific backend tests:
//! ```bash
//! cargo test --test performance memory
//! cargo test --test performance --features sqlite-storage sqlite
//! cargo test --test performance --features redis-storage redis
//! ```
//!
//! Run with all features:
//! ```bash
//! cargo test --test performance --all-features
//! ```

pub mod memory_storage;

#[cfg(feature = "sqlite-storage")]
pub mod sqlite_storage;

#[cfg(feature = "redis-storage")]
pub mod redis_storage;

/// Common performance test utilities and benchmarks
pub mod utils {
    use std::time::{Duration, Instant};
    
    /// Performance benchmark result
    #[derive(Debug)]
    pub struct BenchmarkResult {
        pub operation: String,
        pub duration: Duration,
        pub operations: usize,
        pub ops_per_sec: f64,
    }
    
    impl BenchmarkResult {
        pub fn new(operation: &str, duration: Duration, operations: usize) -> Self {
            let ops_per_sec = operations as f64 / duration.as_secs_f64();
            Self {
                operation: operation.to_string(),
                duration,
                operations,
                ops_per_sec,
            }
        }
        
        pub fn print(&self) {
            println!("  {}: {:?} ({:.0} ops/sec, {} ops)", 
                self.operation, self.duration, self.ops_per_sec, self.operations);
        }
        
        pub fn assert_min_ops_per_sec(&self, min_ops: f64) {
            assert!(self.ops_per_sec >= min_ops, 
                "{} should achieve at least {:.0} ops/sec, got {:.0}", 
                self.operation, min_ops, self.ops_per_sec);
        }
        
        pub fn improvement_over(&self, other: &BenchmarkResult) -> f64 {
            other.duration.as_secs_f64() / self.duration.as_secs_f64()
        }
    }
    
    /// Benchmark a closure and return the result
    pub async fn benchmark<F, Fut, R>(operation: &str, operations: usize, f: F) -> BenchmarkResult
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        let start = Instant::now();
        let _ = f().await;
        let duration = start.elapsed();
        BenchmarkResult::new(operation, duration, operations)
    }
    
    /// Standard dataset sizes for consistent testing
    pub const TINY_DATASET: usize = 100;
    pub const SMALL_DATASET: usize = 1_000;
    pub const MEDIUM_DATASET: usize = 5_000;
    pub const LARGE_DATASET: usize = 10_000;
    pub const XLARGE_DATASET: usize = 50_000;
    
    /// Standard performance thresholds
    pub mod thresholds {
        /// Memory storage thresholds (very high performance expected)
        pub mod memory {
            pub const SEQUENTIAL_WRITES: f64 = 200_000.0;
            pub const BATCH_WRITES: f64 = 500_000.0;
            pub const BATCH_READS: f64 = 1_000_000.0;
            pub const CONCURRENT_WRITES: f64 = 100_000.0;
            pub const CONCURRENT_READS: f64 = 500_000.0;
            pub const CLEANUP_RATE: f64 = 1_000_000.0;
        }
        
        /// SQLite storage thresholds (good performance expected)
        pub mod sqlite {
            pub const SEQUENTIAL_WRITES: f64 = 10_000.0;
            pub const BATCH_WRITES: f64 = 50_000.0;
            pub const CACHED_READS: f64 = 50_000.0;
            pub const CONCURRENT_WRITES: f64 = 1_000.0;
            pub const CONCURRENT_READS: f64 = 10_000.0;
            pub const CLEANUP_RATE: f64 = 100_000.0;
        }
        
        /// Redis storage thresholds (network-bound but optimized)
        pub mod redis {
            pub const SEQUENTIAL_WRITES: f64 = 1_000.0;
            pub const CONCURRENT_WRITES: f64 = 1_000.0;
            pub const CONCURRENT_READS: f64 = 3_000.0;
            pub const SCAN_RATE: f64 = 50_000.0;
            pub const CLEANUP_RATE: f64 = 10_000.0;
        }
    }
}