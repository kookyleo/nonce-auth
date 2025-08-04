// Core architecture components
mod config;
mod credential_builder;
mod credential_verifier;
mod error;
mod time_utils;

// Storage and cleanup systems
pub mod cleanup;
pub mod storage;

// Signature algorithms
pub mod signature;

// Metrics (optional feature)
#[cfg(feature = "metrics")]
pub mod metrics;

// Core components exports
pub use config::{ConfigPreset, NonceConfig};
pub use credential_builder::{CredentialBuilder, NonceGeneratorFn, TimeProviderFn};
pub use credential_verifier::CredentialVerifier;
pub use error::NonceError;

// Storage and cleanup exports
pub use cleanup::{
    BoxedCleanupStrategy, CleanupStrategy, CustomCleanupStrategy, HybridCleanupStrategy,
};
pub use storage::{MemoryStorage, NonceEntry, NonceStorage, StorageStats};

// Signature algorithm exports
#[cfg(feature = "algo-hmac-sha256")]
pub use signature::{DefaultSignatureAlgorithm, create_default_algorithm};
pub use signature::{MacLike, SignatureAlgorithm};

// Metrics exports (optional feature)
#[cfg(feature = "metrics")]
pub use metrics::{
    ErrorMetrics, InMemoryMetricsCollector, MetricEvent, MetricsCollector, MetricsTimer,
    NoOpMetricsCollector, NonceMetrics, PerformanceMetrics,
};
