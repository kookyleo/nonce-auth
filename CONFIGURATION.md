# Configuration Guide

This document provides a reference for all configuration options available in `nonce-auth`.

## Server Configuration

Configuration for the `NonceServer` is done via the `NonceServer::new` function, which accepts optional `Duration` values for TTL and time window.

```rust
use nonce_auth::{NonceServer, storage::MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

let storage = Arc::new(MemoryStorage::new());

// Example: Custom TTL of 10 minutes and a time window of 2 minutes.
let server = NonceServer::new(
    b"your-secret-key",
    storage,
    Some(Duration::from_secs(600)),  // Custom TTL
    Some(Duration::from_secs(120)),  // Custom time window
);
```

- **`default_ttl`**: `Option<Duration>`
  - **Default**: `Some(Duration::from_secs(300))` (5 minutes)
  - **Description**: The default time-to-live for nonce records in the storage backend. After this duration, nonces are considered expired.

- **`time_window`**: `Option<Duration>`
  - **Default**: `Some(Duration::from_secs(60))` (1 minute)
  - **Description**: The allowed time difference between the server's clock and the timestamp on an incoming credential.

### Environment Variables

These parameters can also be configured via environment variables, which will be used if no value is provided to `NonceServer::new`.

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

Ideal for testing, examples, or single-instance applications where persistence is not required.

```rust
use nonce_auth::storage::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
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
```