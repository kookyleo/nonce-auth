# Configuration Guide

This document provides a reference for all configuration options available in `nonce-auth`.

## Server Configuration

Configuration for the `NonceServer` is done via the builder pattern, which allows customization of TTL and time window.

```rust
use nonce_auth::NonceServer;
use std::time::Duration;

// Example: Custom TTL of 10 minutes and a time window of 2 minutes.
let server = NonceServer::builder(b"your-secret-key")
    .with_ttl(Duration::from_secs(600))         // Custom TTL
    .with_time_window(Duration::from_secs(120)) // Custom time window
    .build_and_init()
    .await?;
```

- **`default_ttl`**: `Option<Duration>`
  - **Default**: `Some(Duration::from_secs(300))` (5 minutes)
  - **Description**: The default time-to-live for nonce records in the storage backend. After this duration, nonces are considered expired.

- **`time_window`**: `Option<Duration>`
  - **Default**: `Some(Duration::from_secs(60))` (1 minute)
  - **Description**: The allowed time difference between the server's clock and the timestamp on an incoming credential.

### Configuration Presets

The library provides built-in configuration presets for common use cases:

```rust
use nonce_auth::NonceConfig;

// Production: 5min TTL, 1min window - balanced security/usability
let config = NonceConfig::production();

// Development: 10min TTL, 2min window - developer-friendly  
let config = NonceConfig::development();

// High Security: 2min TTL, 30sec window - maximum security
let config = NonceConfig::high_security();

// Apply configuration to server
let server = NonceServer::builder(b"your-secret-key")
    .with_ttl(config.default_ttl)
    .with_time_window(config.time_window)
    .build_and_init()
    .await?;
```

### Environment Variables

These parameters can also be configured via environment variables, which will be used as defaults for the builder:

- `NONCE_AUTH_DEFAULT_TTL`: Overrides the default TTL in seconds.
- `NONCE_AUTH_DEFAULT_TIME_WINDOW`: Overrides the default time window in seconds.

```bash
# Example: Set a 10-minute TTL and a 2-minute time window.
export NONCE_AUTH_DEFAULT_TTL=600
export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
```

## Storage Backend Configuration

The library uses a trait-based storage system. You can use the built-in `MemoryStorage` or create your own.

### Memory Storage (Default)

The default storage backend is `MemoryStorage`, which is automatically used when you create a server with `NonceServer::builder()`. This is ideal for testing, examples, or single-instance applications where persistence is not required.

```rust
use nonce_auth::NonceServer;

// Uses MemoryStorage by default
let server = NonceServer::builder(b"your-secret-key")
    .build_and_init()
    .await?;
```

### Custom Storage (e.g., SQLite, Redis)

You can implement the `NonceStorage` trait to create a custom backend. This is necessary for applications that require persistent storage or are distributed across multiple instances.

See the [SQLite example](examples/sqlite_storage.rs) for a complete reference implementation.

```rust
use async_trait::async_trait;
use nonce_auth::storage::{NonceStorage, NonceEntry, StorageStats};
use nonce_auth::NonceError;
use std::time::Duration;

pub struct MyCustomStorage; // Your implementation details here

#[async_trait]
impl NonceStorage for MyCustomStorage {
    // ... implement required methods ...
    # async fn get(&self, nonce: &str, context: Option<&str>) -> Result<Option<NonceEntry>, NonceError> { todo!() }
    # async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> { todo!() }
    # async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> { todo!() }
    # async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> { todo!() }
    # async fn get_stats(&self) -> Result<StorageStats, NonceError> { todo!() }
}

// Use the custom storage with the builder
let server = NonceServer::builder(b"your-secret-key")
    .with_storage(Arc::new(MyCustomStorage))
    .build_and_init()
    .await?;
```