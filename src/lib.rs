//! # Nonce Auth
//!
//! A Rust library for secure nonce-based authentication with pluggable storage backends.
//!
//! This library provides a complete solution for implementing nonce-based authentication
//! in client-server applications. It uses HMAC-SHA256 signatures and pluggable storage
//! backends for persistent nonce storage to ensure that each request can only be used once.
//!
//! ## Features
//!
//! - **HMAC-SHA256 Signing**: Cryptographic signing of requests using shared secrets
//! - **Replay Attack Prevention**: Each nonce can only be used once
//! - **Time Window Validation**: Requests outside the time window are rejected
//! - **Context Isolation**: Nonces can be scoped to different business contexts
//! - **Pluggable Storage**: Flexible storage backends (memory, database, Redis, etc.)
//! - **Async Support**: Fully asynchronous API design
//! - **Client-Server Separation**: Clean separation of client and server responsibilities
//!
//! ## Quick Start
//!
//! ### Basic Usage
//!
//! ```rust
//! use nonce_auth::{NonceClient, NonceServer, storage::MemoryStorage};
//! use std::time::Duration;
//! use std::sync::Arc;
//! use hmac::Mac;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a storage backend
//! let storage = Arc::new(MemoryStorage::new());
//!
//! // Create client and server with shared secret
//! let secret = b"shared_secret_key";
//! let client = NonceClient::new(secret);
//! let server = NonceServer::new(secret, storage, None, None);
//!
//! // Initialize the storage backend
//! server.init().await?;
//!
//! // Client generates authentication data with custom signature
//! let protection_data = client.create_protection_data(|mac, timestamp, nonce| {
//!     mac.update(timestamp.as_bytes());
//!     mac.update(nonce.as_bytes());
//! })?;
//!
//! // Server verifies the authentication data with matching signature algorithm
//! match server.verify_protection_data(&protection_data, None, |mac| {
//!     mac.update(protection_data.timestamp.to_string().as_bytes());
//!     mac.update(protection_data.nonce.as_bytes());
//! }).await {
//!     Ok(()) => println!("Authentication verified successfully"),
//!     Err(e) => println!("Verification failed: {e}"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### With Context Isolation
//!
//! ```rust
//! use nonce_auth::{NonceClient, NonceServer, storage::MemoryStorage};
//! use std::sync::Arc;
//! use hmac::Mac;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = Arc::new(MemoryStorage::new());
//! let client = NonceClient::new(b"secret");
//! let server = NonceServer::new(b"secret", storage, None, None);
//!
//! let protection_data = client.create_protection_data(|mac, timestamp, nonce| {
//!     mac.update(timestamp.as_bytes());
//!     mac.update(nonce.as_bytes());
//! })?;
//!
//! // Same nonce can be used in different contexts
//! server.verify_protection_data(&protection_data, Some("api_v1"), |mac| {
//!     mac.update(protection_data.timestamp.to_string().as_bytes());
//!     mac.update(protection_data.nonce.as_bytes());
//! }).await?;
//! server.verify_protection_data(&protection_data, Some("api_v2"), |mac| {
//!     mac.update(protection_data.timestamp.to_string().as_bytes());
//!     mac.update(protection_data.nonce.as_bytes());
//! }).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Storage Backends
//!
//! The library supports pluggable storage backends through the `NonceStorage` trait:
//!
//! ### In-Memory Storage (for testing/development)
//!
//! ```rust
//! use nonce_auth::storage::MemoryStorage;
//! use std::sync::Arc;
//!
//! let storage = Arc::new(MemoryStorage::new());
//! ```
//!
//! ### Custom Storage Implementation
//!
//! ```rust
//! use nonce_auth::storage::{NonceStorage, NonceEntry, StorageStats};
//! use nonce_auth::NonceError;
//! use async_trait::async_trait;
//! use std::time::Duration;
//!
//! pub struct CustomStorage {
//!     // Your storage implementation
//! }
//!
//! #[async_trait]
//! impl NonceStorage for CustomStorage {
//!     async fn get(&self, nonce: &str, context: Option<&str>) -> Result<Option<NonceEntry>, NonceError> {
//!         // Implementation
//!         todo!()
//!     }
//!
//!     async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> {
//!         // Implementation
//!         todo!()
//!     }
//!
//!     async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
//!         // Implementation
//!         todo!()
//!     }
//!
//!     async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
//!         // Implementation
//!         todo!()
//!     }
//!
//!     async fn get_stats(&self) -> Result<StorageStats, NonceError> {
//!         // Implementation
//!         todo!()
//!     }
//! }
//! ```
//!
//! ## Architecture
//!
//! The library is designed with clear separation between client and server responsibilities:
//!
//! - **[`NonceClient`]**: Lightweight client for generating signed requests
//! - **[`NonceServer`]**: Server-side verification and nonce management with pluggable storage
//! - **[`NonceStorage`]**: Abstract storage trait for implementing custom backends
//! - **[`ProtectionData`]**: The data structure exchanged between client and server
//! - **[`NonceError`]**: Comprehensive error handling for all failure modes

use hmac::Hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub mod nonce;
pub mod storage {
    //! Storage backend abstractions and implementations.
    //!
    //! This module provides the storage abstraction layer for nonce persistence.
    //! It includes the `NonceStorage` trait and basic implementations.

    pub use crate::nonce::storage::*;
}

// Re-export commonly used types
pub use nonce::{NonceClient, NonceConfig, NonceError, NonceServer};

/// Internal type alias for HMAC-SHA256 operations.
type HmacSha256 = Hmac<Sha256>;

/// Authentication data for nonce-based request verification.
///
/// This structure contains the cryptographic authentication information
/// that is embedded within or sent alongside application requests. It is
/// specifically designed for nonce-based authentication and replay attack
/// prevention, not as a complete request structure.
///
/// # Purpose
///
/// `ProtectionData` represents only the authentication portion of a request:
/// - It does not contain application payload or business logic data
/// - It focuses solely on cryptographic verification and replay prevention
/// - It can be embedded in larger request structures or sent as headers
///
/// # Fields
///
/// - `timestamp`: Unix timestamp (seconds since epoch) when the auth data was created
/// - `nonce`: A unique identifier (typically UUID) that prevents request reuse
/// - `signature`: HMAC-SHA256 signature that can include various data fields
///
/// # Serialization
///
/// This struct implements `Serialize` and `Deserialize` for easy JSON/binary
/// serialization when sending authentication data over the network.
///
/// # Example
///
/// ```rust
/// use nonce_auth::{NonceClient, ProtectionData};
/// use hmac::Mac;
///
/// let client = NonceClient::new(b"secret");
/// let protection_data: ProtectionData = client.create_protection_data(|mac, timestamp, nonce| {
///     mac.update(timestamp.as_bytes());
///     mac.update(nonce.as_bytes());
/// }).unwrap();
///
/// // Embed in a larger request structure
/// #[derive(serde::Serialize)]
/// struct ApiRequest {
///     payload: String,
///     auth: ProtectionData,
/// }
///
/// let request = ApiRequest {
///     payload: "application data".to_string(),
///     auth: protection_data,
/// };
/// ```
///
/// # Security Notes
///
/// - The timestamp prevents very old authentication attempts from being replayed
/// - The nonce ensures each authentication attempt is unique and can only be used once
/// - The signature proves the authentication data hasn't been tampered with
/// - The signature algorithm is flexible and can include additional request data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionData {
    /// Unix timestamp (seconds since epoch) when this authentication data was created.
    ///
    /// Used by the server to validate that the authentication attempt is within the
    /// acceptable time window and not too old.
    pub timestamp: u64,

    /// A unique nonce value, typically a UUID string.
    ///
    /// This value must be unique and is used to prevent the same
    /// authentication data from being processed multiple times.
    pub nonce: String,

    /// HMAC-SHA256 signature that can include various data fields.
    ///
    /// The signature algorithm is flexible and can be customized to include
    /// timestamp, nonce, payload, HTTP method, path, or any other relevant data.
    /// This proves that the authentication data was created by someone who knows
    /// the shared secret and that the included data hasn't been tampered with.
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use crate::nonce::storage::MemoryStorage;
    use crate::nonce::{NonceClient, NonceError, NonceServer};
    use hmac::Mac;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_client_server_separation() {
        let storage = Arc::new(MemoryStorage::new());
        let client = NonceClient::new(b"test_secret");
        let server = NonceServer::new(b"test_secret", storage, None, None);

        server.init().await.unwrap();

        // Client creates protection data
        let protection_data = client
            .create_protection_data(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
            })
            .unwrap();

        // Server verifies protection data
        let result = server
            .verify_protection_data(&protection_data, None, |mac| {
                mac.update(protection_data.timestamp.to_string().as_bytes());
                mac.update(protection_data.nonce.as_bytes());
            })
            .await;

        assert!(result.is_ok());

        // Same nonce should be rejected
        let result = server
            .verify_protection_data(&protection_data, None, |mac| {
                mac.update(protection_data.timestamp.to_string().as_bytes());
                mac.update(protection_data.nonce.as_bytes());
            })
            .await;

        assert!(matches!(result, Err(NonceError::DuplicateNonce)));
    }

    #[tokio::test]
    async fn test_context_isolation() {
        let storage = Arc::new(MemoryStorage::new());
        let client = NonceClient::new(b"test_secret");
        let server = NonceServer::new(b"test_secret", storage, None, None);

        server.init().await.unwrap();

        let protection_data = client
            .create_protection_data(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
            })
            .unwrap();

        // Same nonce should work in different contexts
        server
            .verify_protection_data(&protection_data, Some("context1"), |mac| {
                mac.update(protection_data.timestamp.to_string().as_bytes());
                mac.update(protection_data.nonce.as_bytes());
            })
            .await
            .unwrap();

        server
            .verify_protection_data(&protection_data, Some("context2"), |mac| {
                mac.update(protection_data.timestamp.to_string().as_bytes());
                mac.update(protection_data.nonce.as_bytes());
            })
            .await
            .unwrap();

        // But should fail if used twice in same context
        let result = server
            .verify_protection_data(&protection_data, Some("context1"), |mac| {
                mac.update(protection_data.timestamp.to_string().as_bytes());
                mac.update(protection_data.nonce.as_bytes());
            })
            .await;

        assert!(matches!(result, Err(NonceError::DuplicateNonce)));
    }

    #[tokio::test]
    async fn test_timestamp_validation() {
        let storage = Arc::new(MemoryStorage::new());
        let client = NonceClient::new(b"test_secret");
        let server = NonceServer::new(
            b"test_secret",
            storage,
            None,
            Some(std::time::Duration::from_secs(1)),
        );

        server.init().await.unwrap();

        // Create protection data with old timestamp
        let mut protection_data = client
            .create_protection_data(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
            })
            .unwrap();

        // Simulate old timestamp (2 seconds ago, but time window is 1 second)
        protection_data.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 2;

        let result = server
            .verify_protection_data(&protection_data, None, |mac| {
                mac.update(protection_data.timestamp.to_string().as_bytes());
                mac.update(protection_data.nonce.as_bytes());
            })
            .await;

        assert!(matches!(result, Err(NonceError::TimestampOutOfWindow)));
    }

    #[tokio::test]
    async fn test_signature_verification() {
        let storage = Arc::new(MemoryStorage::new());
        let client = NonceClient::new(b"test_secret");
        let server = NonceServer::new(b"different_secret", storage, None, None);

        server.init().await.unwrap();

        let protection_data = client
            .create_protection_data(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
            })
            .unwrap();

        let result = server
            .verify_protection_data(&protection_data, None, |mac| {
                mac.update(protection_data.timestamp.to_string().as_bytes());
                mac.update(protection_data.nonce.as_bytes());
            })
            .await;

        assert!(matches!(result, Err(NonceError::InvalidSignature)));
    }

    #[tokio::test]
    async fn test_serialization() {
        let client = NonceClient::new(b"test_secret");
        let protection_data = client
            .create_protection_data(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
            })
            .unwrap();

        // Test JSON serialization
        let json = serde_json::to_string(&protection_data).unwrap();
        let deserialized: super::ProtectionData = serde_json::from_str(&json).unwrap();

        assert_eq!(protection_data.timestamp, deserialized.timestamp);
        assert_eq!(protection_data.nonce, deserialized.nonce);
        assert_eq!(protection_data.signature, deserialized.signature);
    }
}
