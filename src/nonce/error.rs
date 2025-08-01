use thiserror::Error;

/// Error types that can occur during nonce authentication operations.
///
/// This enum represents all possible errors that can occur when using
/// the nonce authentication library. Each variant corresponds to a
/// specific failure mode in the authentication process.
///
/// # Error Categories
///
/// - **Authentication Errors**: `DuplicateNonce`, `ExpiredNonce`, `InvalidSignature`, `TimestampOutOfWindow`
/// - **System Errors**: `DatabaseError`, `CryptoError`
///
/// # Example
///
/// ```rust
/// use nonce_auth::{NonceServer, NonceError, NonceClient, storage::MemoryStorage};
/// use hmac::Mac;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let storage = Arc::new(MemoryStorage::new());
/// let server = NonceServer::builder(b"secret", storage).build_and_init().await?;
/// let client = NonceClient::new(b"secret");
/// let payload = b"test payload";
/// let credential = client.credential_builder().sign(payload)?;
///
/// // Handle different error types
/// match server
///     .credential_verifier(&credential)
///     .verify_with(|mac| {
///         mac.update(credential.timestamp.to_string().as_bytes());
///         mac.update(credential.nonce.as_bytes());
///         mac.update(payload);
///     })
///     .await
/// {
///     Ok(()) => println!("Request verified"),
///     Err(NonceError::DuplicateNonce) => println!("Nonce already used"),
///     Err(NonceError::InvalidSignature) => println!("Invalid signature"),
///     Err(NonceError::TimestampOutOfWindow) => println!("Request too old"),
///     Err(e) => println!("Other error: {e}"),
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Error, Debug)]
pub enum NonceError {
    /// The nonce has already been used and cannot be reused.
    ///
    /// This error occurs when a client attempts to use a nonce that has
    /// already been consumed by the server. This is the primary mechanism
    /// for preventing replay attacks.
    ///
    /// # When This Occurs
    ///
    /// - A client sends the same signed request twice
    /// - A malicious actor attempts to replay a captured request
    /// - Network issues cause duplicate request delivery
    ///
    /// # Resolution
    ///
    /// The client should generate a new signed request with a fresh nonce.
    #[error("Nonce already exists")]
    DuplicateNonce,

    /// The nonce has expired and is no longer valid.
    ///
    /// This error occurs when a nonce exists in the database but has
    /// exceeded its time-to-live (TTL) duration. Expired nonces are
    /// considered invalid and should be cleaned up.
    ///
    /// # When This Occurs
    ///
    /// - A client uses a very old signed request
    /// - The server's TTL is set too short for the use case
    /// - There are significant delays in request processing
    ///
    /// # Resolution
    ///
    /// The client should generate a new signed request with a fresh nonce.
    #[error("Nonce expired")]
    ExpiredNonce,

    /// The HMAC signature verification failed.
    ///
    /// This error occurs when the provided signature doesn't match the
    /// expected signature calculated by the server. This indicates either
    /// a tampered request or mismatched secrets.
    ///
    /// # When This Occurs
    ///
    /// - Client and server are using different secret keys
    /// - The request has been tampered with in transit
    /// - There's a bug in the signature generation/verification logic
    /// - The timestamp or nonce values have been modified
    ///
    /// # Resolution
    ///
    /// - Verify that client and server use the same secret key
    /// - Check for request tampering or transmission errors
    /// - Ensure proper signature generation on the client side
    #[error("Invalid signature")]
    InvalidSignature,

    /// The request timestamp is outside the allowed time window.
    ///
    /// This error occurs when the timestamp in the signed request is
    /// either too old or too far in the future compared to the server's
    /// current time, exceeding the configured time window.
    ///
    /// # When This Occurs
    ///
    /// - Client and server clocks are significantly out of sync
    /// - Network delays cause old requests to arrive late
    /// - The time window is configured too strictly
    /// - A malicious actor attempts to use very old captured requests
    ///
    /// # Resolution
    ///
    /// - Synchronize client and server clocks (e.g., using NTP)
    /// - Increase the time window if appropriate for your use case
    /// - Generate fresh requests closer to when they'll be sent
    #[error("Timestamp out of window")]
    TimestampOutOfWindow,

    /// A database operation failed.
    ///
    /// This error occurs when there's a problem with the underlying
    /// SQLite database operations, such as connection issues, disk
    /// space problems, or corruption.
    ///
    /// # When This Occurs
    ///
    /// - Database file is corrupted or inaccessible
    /// - Insufficient disk space for database operations
    /// - Database is locked by another process
    /// - File permission issues
    ///
    /// # Resolution
    ///
    /// - Check database file permissions and disk space
    /// - Verify database file integrity
    /// - Ensure proper database initialization
    /// - Check for competing database access
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// A cryptographic operation failed.
    ///
    /// This error occurs when there's a problem with the HMAC signature
    /// generation or verification process, typically due to invalid
    /// key material or system-level crypto issues.
    ///
    /// # When This Occurs
    ///
    /// - Invalid or corrupted secret key
    /// - System-level cryptographic library issues
    /// - Memory allocation failures during crypto operations
    ///
    /// # Resolution
    ///
    /// - Verify the secret key is valid and properly formatted
    /// - Check system cryptographic library installation
    /// - Ensure sufficient system resources
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

// SQLite error conversion is now provided in examples/sqlite_storage.rs
// since rusqlite is no longer a core dependency

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(
            NonceError::DuplicateNonce.to_string(),
            "Nonce already exists"
        );
        assert_eq!(NonceError::ExpiredNonce.to_string(), "Nonce expired");
        assert_eq!(
            NonceError::InvalidSignature.to_string(),
            "Invalid signature"
        );
        assert_eq!(
            NonceError::TimestampOutOfWindow.to_string(),
            "Timestamp out of window"
        );

        let db_error = NonceError::DatabaseError("test error".to_string());
        assert_eq!(db_error.to_string(), "Database error: test error");

        let crypto_error = NonceError::CryptoError("crypto test error".to_string());
        assert_eq!(crypto_error.to_string(), "Crypto error: crypto test error");
    }

    #[test]
    fn test_error_debug() {
        let error = NonceError::DuplicateNonce;
        let debug_str = format!("{error:?}");
        assert_eq!(debug_str, "DuplicateNonce");
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NonceError>();
    }

    #[test]
    fn test_error_types() {
        // Test that all error variants can be created and displayed
        let errors = vec![
            NonceError::DuplicateNonce,
            NonceError::ExpiredNonce,
            NonceError::InvalidSignature,
            NonceError::TimestampOutOfWindow,
            NonceError::DatabaseError("test".to_string()),
            NonceError::CryptoError("test".to_string()),
        ];

        for error in errors {
            // Each error should have a non-empty string representation
            assert!(!error.to_string().is_empty());
            // Each error should be debug-printable
            assert!(!format!("{error:?}").is_empty());
        }
    }
}
