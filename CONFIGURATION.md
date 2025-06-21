# Nonce-Auth Configuration Guide

This document provides detailed information about configuring the nonce-auth library with pluggable storage backends.

## Overview

nonce-auth provides a flexible configuration system that supports adjusting security parameters through environment variables and programmatic configuration. The library uses a trait-based storage abstraction, allowing you to plug in different storage backends (memory, SQLite, Redis, etc.) as needed.

## Configuration Methods

### 1. Environment Variable Configuration

The library supports environment variables for security parameters:

```bash
# Security Configuration
export NONCE_AUTH_DEFAULT_TTL=300                  # Default TTL (seconds)
export NONCE_AUTH_DEFAULT_TIME_WINDOW=60           # Time window (seconds)
```

### 2. Programmatic Configuration

Create custom configurations programmatically:

```rust
use nonce_auth::{NonceServer, storage::MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

// Create storage backend
let storage = Arc::new(MemoryStorage::new());

// Create server with custom configuration
let server = NonceServer::new(
    b"your-secret-key",
    storage,
    Some(Duration::from_secs(600)),  // Custom TTL
    Some(Duration::from_secs(120)),  // Custom time window
);

// Initialize the server
server.init().await?;
```

## Configuration Parameters

### Security Configuration

#### `NONCE_AUTH_DEFAULT_TTL`
- **Type**: Integer (seconds)
- **Default**: `300` (5 minutes)
- **Range**: 30 - 86400 (30 seconds - 24 hours)
- **Description**: Default time-to-live for nonce records

**Recommended Values:**
- High security scenarios: 60-300 seconds
- General scenarios: 300-600 seconds
- Relaxed scenarios: 600-1800 seconds

```bash
# High security: 1 minute
export NONCE_AUTH_DEFAULT_TTL=60

# Standard: 5 minutes
export NONCE_AUTH_DEFAULT_TTL=300

# Relaxed: 10 minutes
export NONCE_AUTH_DEFAULT_TTL=600
```

#### `NONCE_AUTH_DEFAULT_TIME_WINDOW`
- **Type**: Integer (seconds)
- **Default**: `60` (1 minute)
- **Range**: 10 - 3600 (10 seconds - 1 hour)
- **Description**: Allowed deviation for timestamp validation

**Considerations:**
- Network latency
- Clock synchronization accuracy
- Security requirements

```bash
# Strict: 30 seconds
export NONCE_AUTH_DEFAULT_TIME_WINDOW=30

# Standard: 1 minute
export NONCE_AUTH_DEFAULT_TIME_WINDOW=60

# Relaxed: 2 minutes
export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
```

## Storage Backend Configuration

### Built-in Storage Backends

#### Memory Storage (Default)
```rust
use nonce_auth::storage::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
```

**Features:**
- Fast in-memory storage using HashMap
- Suitable for single-instance applications
- No persistence across restarts
- Thread-safe with Arc<Mutex<HashMap>>

#### Custom Storage Backends

You can implement your own storage backend by implementing the `NonceStorage` trait:

```rust
use async_trait::async_trait;
use nonce_auth::storage::{NonceStorage, NonceEntry, StorageStats};
use nonce_auth::NonceError;
use std::time::Duration;

pub struct MyCustomStorage {
    // Your storage implementation
}

#[async_trait]
impl NonceStorage for MyCustomStorage {
    async fn init(&self) -> Result<(), NonceError> {
        // Initialize your storage
        Ok(())
    }

    async fn get(&self, nonce: &str, context: Option<&str>) -> Result<Option<NonceEntry>, NonceError> {
        // Implement get logic
        unimplemented!()
    }

    async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> {
        // Implement set logic
        unimplemented!()
    }

    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
        // Implement exists logic
        unimplemented!()
    }

    async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
        // Implement cleanup logic
        unimplemented!()
    }

    async fn get_stats(&self) -> Result<StorageStats, NonceError> {
        // Implement stats logic
        unimplemented!()
    }
}
```

### Example Storage Implementations

The library includes example implementations for different storage backends:

- **SQLite Storage**: See `examples/sqlite_storage.rs` for a complete SQLite implementation
- **Memory Storage**: Built-in implementation for testing and single-instance use
- **Redis Storage**: Can be implemented using similar patterns

## Configuration Examples

### High-Concurrency Web Service
```rust
use nonce_auth::{NonceServer, storage::MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

// For single-instance high-concurrency scenarios
let storage = Arc::new(MemoryStorage::new());
let server = NonceServer::new(
    b"your-secret-key",
    storage,
    Some(Duration::from_secs(300)),  // 5 minutes TTL
    Some(Duration::from_secs(60)),   // 1 minute time window
);
```

### Microservice Architecture
```rust
// Use custom storage backend for distributed scenarios
let storage = Arc::new(MyDistributedStorage::new());
let server = NonceServer::new(
    b"your-secret-key",
    storage,
    Some(Duration::from_secs(180)),  // 3 minutes TTL
    Some(Duration::from_secs(30)),   // 30 seconds time window
);
```

### Development and Testing
```bash
# Relaxed settings for development
export NONCE_AUTH_DEFAULT_TTL=60
export NONCE_AUTH_DEFAULT_TIME_WINDOW=300
```

```rust
// Use memory storage for testing
let storage = Arc::new(MemoryStorage::new());
let server = NonceServer::new(b"test-key", storage, None, None);
```

## Best Practices

### 1. Choose Appropriate Storage Backend
- **Memory Storage**: Single-instance applications, testing
- **SQLite Storage**: Single-instance with persistence needs
- **Redis/Database Storage**: Multi-instance, distributed applications

### 2. Security Parameter Tuning
- **TTL**: Balance between security and usability
- **Time Window**: Consider network latency and clock sync
- **Context Isolation**: Use contexts for different business scenarios

### 3. Error Handling
```rust
match server.verify_protection_data(&data, None, |mac| {
    mac.update(data.timestamp.to_string().as_bytes());
    mac.update(data.nonce.as_bytes());
}).await {
    Ok(()) => println!("✅ Authentication successful"),
    Err(NonceError::DuplicateNonce) => println!("❌ Nonce already used"),
    Err(NonceError::ExpiredNonce) => println!("❌ Nonce expired"),
    Err(NonceError::TimestampOutOfWindow) => println!("❌ Timestamp out of window"),
    Err(e) => println!("❌ Other error: {e}"),
}
```

### 4. Performance Considerations
- Use appropriate TTL values to balance security and storage growth
- Implement efficient cleanup strategies in custom storage backends
- Consider using connection pooling for database-backed storage

## Summary

The nonce-auth library provides a flexible configuration system focused on security parameters:

- ✅ **Pluggable Storage**: Choose the right storage backend for your needs
- ✅ **Environment Variables**: Easy configuration through environment variables
- ✅ **Programmatic Configuration**: Full control over security parameters
- ✅ **Context Isolation**: Support for different business scenarios
- ✅ **Async Support**: Fully asynchronous API design

For more information, please refer to:
- [API Documentation](https://docs.rs/nonce-auth)
- [Example Code](examples/)
- [GitHub Repository](https://github.com/kookyleo/nonce-auth) 