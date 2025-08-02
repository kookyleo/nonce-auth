# Configuration Guide

This document provides a comprehensive reference for all configuration options available in `nonce-auth`.

## Server Configuration

### Server Builder Pattern

The `NonceServer` is configured using the builder pattern with the following methods:

```rust
use nonce_auth::{NonceServer, NonceConfig};
use std::time::Duration;
use std::sync::Arc;

// Complete server configuration example
let server = NonceServer::builder()
    .with_ttl(Duration::from_secs(600))         // Custom TTL (default: 300s)
    .with_time_window(Duration::from_secs(120)) // Custom time window (default: 60s)
    .with_storage(Arc::new(custom_storage))     // Custom storage backend
    .build_and_init()                           // Initialize storage and return server
    .await?;
```

#### Available Builder Methods

| Method | Description | Default |
|--------|-------------|---------|
| `with_preset(ConfigPreset)` | Apply configuration preset | - |
| `with_ttl(Duration)` | Set nonce time-to-live duration | 5 minutes |
| `with_time_window(Duration)` | Set timestamp validation window | 1 minute |
| `with_storage(Arc<T>)` | Set custom storage backend | `MemoryStorage` |
| `build_and_init()` | Build and initialize server | - |

### Configuration Presets

Built-in configuration presets for common scenarios:

```rust
use nonce_auth::{NonceServer, ConfigPreset};

// Production: Balanced security and usability (TTL: 5min, Window: 1min)
let server = NonceServer::builder()
    .with_preset(ConfigPreset::Production)
    .build_and_init()
    .await?;

// Development: Developer-friendly settings (TTL: 10min, Window: 2min)
let dev_server = NonceServer::builder()
    .with_preset(ConfigPreset::Development)
    .build_and_init()
    .await?;

// High Security: Maximum security (TTL: 2min, Window: 30s)
let secure_server = NonceServer::builder()
    .with_preset(ConfigPreset::HighSecurity)
    .build_and_init()
    .await?;

// Load from environment variables
// Reads NONCE_AUTH_DEFAULT_TTL and NONCE_AUTH_DEFAULT_TIME_WINDOW
let env_server = NonceServer::builder()
    .with_preset(ConfigPreset::FromEnv)
    .build_and_init()
    .await?;

// Override preset values
let custom_server = NonceServer::builder()
    .with_preset(ConfigPreset::Production)
    .with_ttl(Duration::from_secs(600))  // Override production TTL
    .build_and_init()
    .await?;
```

### Configuration Validation and Monitoring

```rust
use nonce_auth::NonceConfig;

let config = NonceConfig::production();

// Get human-readable summary
println!("{}", config.summary());
// Output: "NonceConfig { TTL: 300s, Time Window: 60s }"

// Validate configuration and get warnings
let issues = config.validate();
if issues.is_empty() {
    println!("✓ Configuration is valid");
} else {
    println!("⚠ Configuration issues:");
    for issue in issues {
        println!("  - {}", issue);
    }
}
```

### Environment Variables

Configure defaults via environment variables:

```bash
# Set default TTL (in seconds)
export NONCE_AUTH_DEFAULT_TTL=600

# Set default time window (in seconds)  
export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
```

```rust
// Use environment variables as defaults
let config = NonceConfig::from_env();
let server = NonceServer::builder()
    .with_ttl(config.default_ttl)
    .with_time_window(config.time_window)
    .build_and_init()
    .await?;
```

### Server Inspection and Management

Once created, the server provides methods for inspection and management:

```rust
// Inspect server configuration
println!("Server TTL: {:?}", server.ttl());
println!("Server time window: {:?}", server.time_window());

// Access storage backend for statistics
let stats = server.storage().get_stats().await?;
println!("Total nonce records: {}", stats.total_records);
println!("Storage backend: {}", stats.backend_info);
```

### Automatic Cleanup Configuration

The server includes automatic cleanup functionality that runs in the background:

#### Default Automatic Cleanup

By default, the server uses a hybrid cleanup strategy that triggers cleanup when:
- 100 requests have been processed, OR
- 5 minutes have elapsed since the last cleanup

```rust
// Server with default automatic cleanup
let server = NonceServer::builder()
    .build_and_init()
    .await?;
// Cleanup happens automatically in the background
```

#### Custom Cleanup Thresholds

Customize the hybrid cleanup strategy thresholds:

```rust
use std::time::Duration;

let server = NonceServer::builder()
    .with_hybrid_cleanup_thresholds(
        50,                       // Cleanup every 50 requests
        Duration::from_secs(120)  // OR every 2 minutes
    )
    .build_and_init()
    .await?;
```

#### Custom Cleanup Strategy

Provide completely custom cleanup logic:

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

// Example: Cleanup based on memory usage
let server = NonceServer::builder()
    .with_custom_cleanup_strategy(|| async {
        // Your custom logic here
        let memory_usage = get_current_memory_usage();
        memory_usage > 80 // Cleanup when memory usage exceeds 80%
    })
    .build_and_init()
    .await?;

// Example: Progressive cleanup frequency
let request_count = Arc::new(AtomicU32::new(0));
let count_clone = Arc::clone(&request_count);

let server = NonceServer::builder()
    .with_custom_cleanup_strategy(move || {
        let count = count_clone.fetch_add(1, Ordering::SeqCst);
        async move {
            // Cleanup more frequently as load increases
            match count {
                0..=100 => count % 100 == 0,    // Every 100 requests
                101..=500 => count % 50 == 0,   // Every 50 requests
                _ => count % 25 == 0,            // Every 25 requests
            }
        }
    })
    .build_and_init()
    .await?;
```

#### Manual Cleanup

While automatic cleanup is recommended, you can still trigger cleanup manually if needed:

```rust
// Manual cleanup (rarely needed due to automatic cleanup)
let deleted_count = server.cleanup_expired_nonces(Duration::from_secs(300)).await?;
println!("Manually cleaned up {} expired nonces", deleted_count);
```

## Storage Backend Configuration

### Built-in Storage Backends

#### Memory Storage (Default)

```rust
use nonce_auth::NonceServer;

// Uses MemoryStorage by default - ideal for testing and single-instance apps
let server = NonceServer::builder()
    .build_and_init()
    .await?;
```

#### Custom Storage Implementation

Implement the `NonceStorage` trait for custom backends:

```rust
use async_trait::async_trait;
use nonce_auth::storage::{NonceStorage, NonceEntry, StorageStats};
use nonce_auth::NonceError;
use std::time::Duration;

pub struct MyCustomStorage {
    // Your storage implementation details
}

#[async_trait]
impl NonceStorage for MyCustomStorage {
    async fn init(&self) -> Result<(), NonceError> {
        // Initialize storage (create tables, connections, etc.)
        Ok(())
    }

    async fn get(&self, nonce: &str, context: Option<&str>) -> Result<Option<NonceEntry>, NonceError> {
        // Retrieve nonce entry
        todo!()
    }

    async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> {
        // Store nonce with TTL
        todo!()
    }

    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
        // Check if nonce exists (optimized version of get)
        todo!()
    }

    async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
        // Remove expired nonces, return count of deleted records
        todo!()
    }

    async fn get_stats(&self) -> Result<StorageStats, NonceError> {
        // Return storage statistics
        Ok(StorageStats {
            total_records: 0,
            backend_info: "Custom storage backend".to_string(),
        })
    }
}

// Use custom storage
let custom_storage = Arc::new(MyCustomStorage {});
let server = NonceServer::builder()
    .with_storage(custom_storage)
    .build_and_init()
    .await?;
```

See [SQLite example](../examples/sqlite_storage.rs) for a complete implementation.

#### Storage Backend Lifecycle

```rust
// Understanding the init() method
#[async_trait]
impl NonceStorage for MyCustomStorage {
    async fn init(&self) -> Result<(), NonceError> {
        // Called automatically by build_and_init()
        // Use this to:
        // - Create database tables
        // - Establish connections
        // - Run migrations
        // - Validate configuration
        Ok(())
    }
    
    // ... other methods
}

// Manual initialization (if needed)
let storage = Arc::new(MyCustomStorage::new());
storage.init().await?; // Usually not needed - build_and_init() calls this

let server = NonceServer::builder()
    .with_storage(storage)
    .build_and_init() // This calls storage.init() automatically
    .await?;
```

#### Advanced Storage Examples

**Redis-like Storage Implementation:**
```rust
use async_trait::async_trait;
use nonce_auth::storage::{NonceStorage, NonceEntry, StorageStats};

pub struct RedisStorage {
    client: redis::Client,
    key_prefix: String,
}

#[async_trait]
impl NonceStorage for RedisStorage {
    async fn init(&self) -> Result<(), NonceError> {
        // Test connection and setup
        let mut conn = self.client.get_async_connection().await
            .map_err(|e| NonceError::DatabaseError(format!("Redis connection failed: {e}")))?;
        
        // Verify Redis is accessible
        redis::cmd("PING").query_async(&mut conn).await
            .map_err(|e| NonceError::DatabaseError(format!("Redis ping failed: {e}")))?;
        
        Ok(())
    }

    async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> {
        let mut conn = self.client.get_async_connection().await
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;
        
        let key = format!("{}:{}:{}", self.key_prefix, nonce, context.unwrap_or(""));
        let ttl_secs = ttl.as_secs() as usize;
        
        redis::cmd("SETEX")
            .arg(&key)
            .arg(ttl_secs)
            .arg("1")
            .query_async(&mut conn)
            .await
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;
        
        Ok(())
    }

    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
        let mut conn = self.client.get_async_connection().await
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;
        
        let key = format!("{}:{}:{}", self.key_prefix, nonce, context.unwrap_or(""));
        
        let exists: bool = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| NonceError::DatabaseError(e.to_string()))?;
        
        Ok(exists)
    }

    // ... implement other required methods
}
```

**Encrypted Storage Wrapper:**
```rust
pub struct EncryptedStorage<T: NonceStorage> {
    inner: T,
    encryption_key: [u8; 32],
}

#[async_trait]
impl<T: NonceStorage + Send + Sync> NonceStorage for EncryptedStorage<T> {
    async fn init(&self) -> Result<(), NonceError> {
        self.inner.init().await
    }

    async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> {
        let encrypted_nonce = self.encrypt(nonce)?;
        let encrypted_context = context.map(|c| self.encrypt(c)).transpose()?;
        
        self.inner.set(&encrypted_nonce, encrypted_context.as_deref(), ttl).await
    }

    // ... implement encryption/decryption for other methods
}
```

## Client Configuration

### Basic Client Usage

```rust
use nonce_auth::NonceClient;

// Simple client with defaults (UUID v4 nonces, system time)
let client = NonceClient::new(b"my_secret");
let credential = client.credential_builder().sign(b"payload")?;
```

### Advanced Client Configuration

Use the builder pattern for full customization:

```rust
use nonce_auth::NonceClient;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

let client = NonceClient::builder()
    .with_secret(b"my_secret")
    .with_nonce_generator(|| {
        // Custom nonce generation strategy
        format!("api-req-{}", uuid::Uuid::new_v4())
    })
    .with_time_provider(|| {
        // Custom time source (e.g., NTP-synchronized)
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| nonce_auth::NonceError::CryptoError(format!("Time error: {}", e)))
    })
    .build();
```

#### Available Client Builder Methods

| Method | Parameters | Description |
|--------|-----------|-------------|
| `with_secret(&[u8])` | Secret key bytes | Set shared secret (required) |
| `with_nonce_generator(F)` | `F: Fn() -> String` | Custom nonce generation function |
| `with_time_provider(F)` | `F: Fn() -> Result<u64, NonceError>` | Custom timestamp provider |
| `build()` | - | Build client (panics if no secret) |

#### Builder Pattern Advanced Usage

```rust
// Using Default trait
let client = NonceClientBuilder::default()
    .with_secret(b"my_secret")
    .build();

// Conditional builder configuration
fn create_client_for_environment(env: &str) -> NonceClient {
    let mut builder = NonceClient::builder()
        .with_secret(get_secret_for_env(env));
    
    if env == "development" {
        builder = builder.with_nonce_generator(|| {
            format!("dev-{}-{}", std::process::id(), uuid::Uuid::new_v4())
        });
    } else if env == "testing" {
        builder = builder
            .with_nonce_generator(|| "test-nonce".to_string())
            .with_time_provider(|| Ok(1234567890));
    }
    
    builder.build()
}

// Builder with error handling
fn try_build_client(secret: Option<&[u8]>) -> Result<NonceClient, &'static str> {
    let Some(secret) = secret else {
        return Err("Secret is required");
    };
    
    Ok(NonceClient::builder()
        .with_secret(secret)
        .build())
}
```

### Client Configuration Examples

#### Testing with Fixed Values

```rust
// Deterministic values for testing
let test_client = NonceClient::builder()
    .with_secret(b"test_secret")
    .with_nonce_generator(|| "fixed-test-nonce".to_string())
    .with_time_provider(|| Ok(1234567890))
    .build();

let credential = test_client.credential_builder().sign(b"test")?;
assert_eq!(credential.nonce, "fixed-test-nonce");
assert_eq!(credential.timestamp, 1234567890);
```

#### Sequential Nonces

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

let counter = Arc::new(AtomicU64::new(0));
let counter_clone = counter.clone();

let client = NonceClient::builder()
    .with_secret(b"secret")
    .with_nonce_generator(move || {
        let id = counter_clone.fetch_add(1, Ordering::SeqCst);
        format!("seq-{:010}", id)
    })
    .build();

// Generates: seq-0000000000, seq-0000000001, seq-0000000002, ...
```

#### Custom Time Sources

```rust
// NTP-synchronized time or custom time source
let client = NonceClient::builder()
    .with_secret(b"secret")
    .with_time_provider(|| {
        // Your custom time implementation
        get_ntp_synchronized_time()
            .map_err(|e| nonce_auth::NonceError::CryptoError(format!("NTP error: {}", e)))
    })
    .build();
```

### Custom Signature Logic

#### Client-Side Custom Signing

```rust
let client = NonceClient::new(b"secret");

// Standard signing (recommended)
let credential = client.credential_builder().sign(b"payload")?;

// Custom signing with additional data
let credential = client.credential_builder()
    .sign_with(|mac, timestamp, nonce| {
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(b"payload");
        mac.update(b"extra_context_data");  // Additional authenticated data
    })?;

// Complex signing with structured data
let credential = client.credential_builder()
    .sign_with(|mac, timestamp, nonce| {
        mac.update(b"prefix:");
        mac.update(timestamp.as_bytes());
        mac.update(b":nonce:");
        mac.update(nonce.as_bytes());
        mac.update(b":user_id:");
        mac.update(b"12345");
        mac.update(b":payload:");
        mac.update(payload);
        mac.update(b":suffix");
    })?;

// Binary data signing
let binary_data = vec![0x01, 0x02, 0x03, 0x04];
let credential = client.credential_builder()
    .sign_with(|mac, timestamp, nonce| {
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(&binary_data);  // Binary payload
        mac.update(b"metadata");   // Additional metadata
    })?;
```

## Credential Verification

### Basic Verification

```rust
// Standard verification
let result = server
    .credential_verifier(&credential)
    .with_secret(b"shared_secret")
    .verify(b"payload")
    .await;

// Structured verification with multiple components
let user_id = b"user123";
let payload = b"data";
let api_version = b"v1";

let credential = client.credential_builder()
    .sign_structured(&[user_id, payload, api_version])?;

let result = server
    .credential_verifier(&credential)
    .with_secret(b"shared_secret")
    .verify_structured(&[user_id, payload, api_version])
    .await;

match result {
    Ok(()) => println!("✓ Credential verified"),
    Err(e) => println!("✗ Verification failed: {}", e),
}
```

### Advanced Verification Options

```rust
// Verification with context isolation
let result = server
    .credential_verifier(&credential)
    .with_secret(user_secret)
    .with_context(Some("api_v1"))  // Context-specific nonce isolation
    .verify(payload)
    .await;

// Dynamic secret verification with context
async fn fetch_user_secret(user_id: &str) -> Result<Vec<u8>, NonceError> {
    // Fetch secret from database/cache based on user_id
    Ok(format!("secret_for_{}", user_id).into_bytes())
}

let user_id = "user123";
let result = server
    .credential_verifier(&credential)
    .with_context(Some(user_id))
    .verify_with_secret_provider(payload, |context| async move {
        match context {
            Some(user_id) => fetch_user_secret(&user_id).await,
            None => Err(NonceError::CryptoError("Context required".to_string())),
        }
    })
    .await;

// Structured verification with dynamic secret
let credential = client.credential_builder()
    .sign_structured(&[user_id.as_bytes(), payload])?;

let result = server
    .credential_verifier(&credential)
    .with_context(Some(user_id))
    .verify_structured_with_secret_provider(
        &[user_id.as_bytes(), payload],
        |context| async move {
            match context {
                Some(user_id) => fetch_user_secret(&user_id).await,
                None => Err(NonceError::CryptoError("Context required".to_string())),
            }
        }
    )
    .await;

// Custom verification logic matching custom signing
let result = server
    .credential_verifier(&credential)
    .with_secret(shared_secret)
    .with_context(Some("special_context"))
    .verify_with(|mac| {
        mac.update(credential.timestamp.to_string().as_bytes());
        mac.update(credential.nonce.as_bytes());
        mac.update(payload);
        mac.update(b"extra_context_data");  // Must match client-side logic
    })
    .await;

// Complex verification matching structured signing
let result = server
    .credential_verifier(&credential)
    .with_secret(shared_secret)
    .verify_with(|mac| {
        mac.update(b"prefix:");
        mac.update(credential.timestamp.to_string().as_bytes());
        mac.update(b":nonce:");
        mac.update(credential.nonce.as_bytes());
        mac.update(b":user_id:");
        mac.update(b"12345");  // Must match exact user_id from signing
        mac.update(b":payload:");
        mac.update(payload);
        mac.update(b":suffix");
    })
    .await;

// Binary data verification
let binary_data = vec![0x01, 0x02, 0x03, 0x04];
let result = server
    .credential_verifier(&credential)
    .with_secret(shared_secret)
    .verify_with(|mac| {
        mac.update(credential.timestamp.to_string().as_bytes());
        mac.update(credential.nonce.as_bytes());
        mac.update(&binary_data);  // Same binary data as signing
        mac.update(b"metadata");   // Same metadata as signing
    })
    .await;

// Conditional verification based on credential data
let result = server
    .credential_verifier(&credential)
    .with_secret(shared_secret)
    .verify_with(|mac| {
        mac.update(credential.timestamp.to_string().as_bytes());
        mac.update(credential.nonce.as_bytes());
        mac.update(payload);
        
        // Add conditional data based on timestamp
        if credential.timestamp > 1640995200 {  // After 2022-01-01
            mac.update(b"new_format");
        } else {
            mac.update(b"legacy_format");
        }
    })
    .await;
```

#### Available Verification Methods

| Method | Parameters | Description |
|--------|-----------|-------------|
| `with_secret(&[u8])` | Secret key bytes | Set verification secret (required) |
| `with_context(Option<&str>)` | Context string | Set nonce isolation context |
| `verify(&[u8])` | Payload bytes | Standard verification |
| `verify_structured(&[&[u8]])` | Data components | Structured data verification |
| `verify_with<F>(F)` | MAC builder closure | Custom verification logic |
| `verify_with_secret_provider<F>(payload, F)` | Payload, async secret provider | Dynamic secret verification |
| `verify_structured_with_secret_provider<F>(components, F)` | Components, async secret provider | Structured + dynamic secret |

## Multi-Secret and Context Support

### Multi-User Authentication

```rust
let server = NonceServer::builder().build_and_init().await?;

// Different users with different secrets
let user1_secret = b"user1_key_12345";
let user2_secret = b"user2_key_67890";

// User 1 verification
server.credential_verifier(&user1_credential)
    .with_secret(user1_secret)
    .verify(payload)
    .await?;

// User 2 verification with same server instance
server.credential_verifier(&user2_credential)
    .with_secret(user2_secret)
    .verify(payload)
    .await?;
```

### Context Isolation

```rust
// Same nonce can be used across different contexts
let credential = client.credential_builder().sign(b"data")?;

// API v1 context
server.credential_verifier(&credential)
    .with_secret(secret)
    .with_context(Some("api_v1"))
    .verify(b"data")
    .await?;  // ✓ Success

// API v2 context (same nonce, different context)
server.credential_verifier(&credential)
    .with_secret(secret)
    .with_context(Some("api_v2"))
    .verify(b"data")
    .await?;  // ✓ Success

// Reuse in same context fails
server.credential_verifier(&credential)
    .with_secret(secret)
    .with_context(Some("api_v1"))
    .verify(b"data")
    .await?;  // ✗ DuplicateNonce error
```

## Error Handling

### Error Types and Handling

```rust
use nonce_auth::NonceError;
use std::error::Error;

match server.credential_verifier(&credential)
    .with_secret(secret)
    .verify(payload)
    .await
{
    Ok(()) => println!("✓ Verification successful"),
    
    Err(NonceError::DuplicateNonce) => {
        // Nonce already used - replay attack prevention
        println!("⚠ Nonce reuse detected - possible replay attack");
    },
    
    Err(NonceError::ExpiredNonce) => {
        // Nonce exceeded TTL
        println!("⚠ Nonce expired - client should generate new request");
    },
    
    Err(NonceError::InvalidSignature) => {
        // Signature verification failed
        println!("⚠ Invalid signature - check shared secret or request integrity");
    },
    
    Err(NonceError::TimestampOutOfWindow) => {
        // Timestamp outside allowed window
        println!("⚠ Request timestamp out of range - check clock synchronization");
    },
    
    Err(NonceError::DatabaseError(err)) => {
        // Storage backend error - can access original error
        println!("⚠ Storage error: {}", err);
        if let Some(source) = err.source() {
            println!("  Caused by: {}", source);
        }
    },
    
    Err(NonceError::CryptoError(msg)) => {
        // Cryptographic operation error
        println!("⚠ Crypto error: {}", msg);
    },
}

// Using error utility methods
let error = NonceError::DuplicateNonce;
println!("Error code: {}", error.code());                      // "duplicate_nonce"
println!("Is temporary: {}", error.is_temporary());           // false
println!("Is auth error: {}", error.is_authentication_error()); // true

let db_error = NonceError::from_database_message("Connection timeout");
println!("Error code: {}", db_error.code());                 // "database_error"
println!("Is temporary: {}", db_error.is_temporary());       // true
println!("Is auth error: {}", db_error.is_authentication_error()); // false

// Error classification methods
println!("Is client error: {}", error.is_client_error());   // true for auth errors
println!("Is server error: {}", db_error.is_server_error()); // true for system errors
```

### Advanced Error Handling Patterns

```rust
use nonce_auth::NonceError;
use std::time::Duration;

// Retry logic for transient database errors
async fn verify_with_retry(
    server: &NonceServer<impl NonceStorage>,
    credential: &NonceCredential,
    secret: &[u8],
    payload: &[u8],
    max_retries: u32,
) -> Result<(), NonceError> {
    let mut attempts = 0;
    
    loop {
        match server
            .credential_verifier(credential)
            .with_secret(secret)
            .verify(payload)
            .await
        {
            Ok(()) => return Ok(()),
            
            Err(NonceError::DatabaseError(_)) if attempts < max_retries => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                continue;
            },
            
            Err(e) => return Err(e),
        }
    }
}

// Graceful error handling for production
async fn handle_verification_error(error: NonceError) -> (u16, String) {
    match error {
        NonceError::DuplicateNonce => {
            (409, "Request already processed".to_string())
        },
        
        NonceError::ExpiredNonce => {
            (401, "Request expired, please generate a new one".to_string())
        },
        
        NonceError::InvalidSignature => {
            (401, "Invalid authentication credentials".to_string())
        },
        
        NonceError::TimestampOutOfWindow => {
            (400, "Request timestamp out of acceptable range".to_string())
        },
        
        NonceError::DatabaseError(_) => {
            // Log the actual error internally but don't expose details
            eprintln!("Database error: {}", error);
            (503, "Service temporarily unavailable".to_string())
        },
        
        NonceError::CryptoError(_) => {
            // Log the actual error internally
            eprintln!("Crypto error: {}", error);
            (500, "Internal server error".to_string())
        },
    }
}

// Custom error handling for verify_with
async fn verify_with_detailed_error(
    server: &NonceServer<impl NonceStorage>,
    credential: &NonceCredential,
    secret: &[u8],
    payload: &[u8],
) -> Result<(), String> {
    server
        .credential_verifier(credential)
        .with_secret(secret)
        .verify_with(|mac| {
            mac.update(credential.timestamp.to_string().as_bytes());
            mac.update(credential.nonce.as_bytes());
            mac.update(payload);
        })
        .await
        .map_err(|e| match e {
            NonceError::InvalidSignature => {
                "Signature mismatch: Check MAC construction order and data".to_string()
            },
            other => format!("Verification failed: {}", other),
        })
}
```

## Performance and Security Considerations

### TTL Configuration Guidelines

| Use Case | Recommended TTL | Trade-offs |
|----------|----------------|------------|
| High-security APIs | 2-5 minutes | Better security, may impact UX |
| Standard web APIs | 5-10 minutes | Balanced security/usability |
| Development/testing | 10-30 minutes | Developer-friendly |
| Batch processing | 30-60 minutes | Accommodates longer processing |

### Time Window Guidelines

| Network Conditions | Recommended Window | Notes |
|-------------------|------------------|-------|
| Local/LAN | 30-60 seconds | Tight synchronization |
| Internet/WAN | 60-120 seconds | Account for network latency |
| Mobile/unstable | 120-300 seconds | Higher tolerance needed |

### Storage Backend Selection

| Backend | Use Case | Pros | Cons |
|---------|----------|------|------|
| MemoryStorage | Testing, single instance | Fast, simple | No persistence, no scaling |
| SQLite | Single instance, persistence needed | Persistent, reliable | No horizontal scaling |
| Redis | Multi-instance, high scale | Distributed, fast | Additional infrastructure |

### Security Best Practices

```rust
// Production-ready server configuration
let server = NonceServer::builder()
    .with_ttl(Duration::from_secs(300))     // 5-minute TTL
    .with_time_window(Duration::from_secs(60))  // 1-minute window
    .with_storage(Arc::new(persistent_storage)) // Use persistent storage
    .build_and_init()
    .await?;

// Automatic cleanup is enabled by default
// No need for manual cleanup tasks - the server handles it automatically
```

## Complete Example: Production Setup

```rust
use nonce_auth::{NonceServer, NonceClient, NonceConfig};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure server with production settings
    let server = NonceServer::builder()
        .with_preset(ConfigPreset::Production)
        .with_storage(Arc::new(setup_persistent_storage().await?))
        .build_and_init()
        .await?;

    // 2. Configure client with custom nonce strategy
    let client = NonceClient::builder()
        .with_secret(b"production_secret_key")
        .with_nonce_generator(|| {
            format!("prod-{}-{}", 
                std::process::id(), 
                uuid::Uuid::new_v4())
        })
        .build();

    // 3. Automatic cleanup is enabled by default
    // The server will automatically clean up expired nonces based on the
    // default hybrid strategy (every 100 requests OR every 5 minutes)

    // 4. Handle requests
    let payload = b"important_request_data";
    let credential = client.credential_builder().sign(payload)?;

    match server
        .credential_verifier(&credential)
        .with_secret(b"production_secret_key")
        .with_context(Some("api_v1"))
        .verify(payload)
        .await
    {
        Ok(()) => println!("✅ Request authenticated successfully"),
        Err(e) => eprintln!("❌ Authentication failed: {}", e),
    }

    Ok(())
}
```

This comprehensive configuration guide covers all available options in the nonce-auth library. For more examples, see the [examples directory](../examples/).