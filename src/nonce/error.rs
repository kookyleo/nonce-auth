use thiserror::Error;

/// Error types that can occur during nonce authentication operations.
///
/// This enum represents all possible errors that can occur when using
/// the nonce authentication library. Each variant corresponds to a
/// specific failure mode in the authentication process.
///
/// # Error Categories
///
/// - **Authentication Errors**: `DuplicateNonce`, `InvalidSignature`, `TimestampOutOfWindow`
/// - **System Errors**: `StorageError`, `CryptoError`
///
/// # Error Codes
///
/// Each error variant has a stable string code that can be used for programmatic error handling:
///
/// ```rust
/// use nonce_auth::NonceError;
///
/// let error = NonceError::DuplicateNonce;
/// assert_eq!(error.code(), "duplicate_nonce");
/// ```
///
/// # Example
///
/// ```rust
/// use nonce_auth::{CredentialBuilder, CredentialVerifier, NonceError, storage::MemoryStorage};
/// use hmac::Mac;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let storage = Arc::new(MemoryStorage::new());
/// let payload = b"test payload";
/// let credential = CredentialBuilder::new(b"secret").sign(payload)?;
///
/// // Handle different error types
/// match CredentialVerifier::new(storage)
///     .with_secret(b"secret")
///     .verify_with(&credential, |mac| {
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
    /// This error occurs when attempting to use a nonce that has
    /// already been consumed. This is the primary mechanism
    /// for preventing replay attacks.
    ///
    /// # When This Occurs
    ///
    /// - The same signed request is sent twice
    /// - A malicious actor attempts to replay a captured request
    /// - Network issues cause duplicate request delivery
    ///
    /// # Resolution
    ///
    /// A new signed request should be generated with a fresh nonce.
    #[error("Nonce already exists")]
    DuplicateNonce,

    /// The HMAC signature verification failed.
    ///
    /// This error occurs when the provided signature doesn't match the
    /// expected signature calculated during verification. This indicates either
    /// a tampered request or mismatched secrets.
    ///
    /// # When This Occurs
    ///
    /// - Different secret keys are being used for signing and verification
    /// - The request has been tampered with in transit
    /// - There's a bug in the signature generation/verification logic
    /// - The timestamp or nonce values have been modified
    ///
    /// # Resolution
    ///
    /// - Verify that the same secret key is used for signing and verification
    /// - Check for request tampering or transmission errors
    /// - Ensure proper signature generation during credential creation
    #[error("Invalid signature")]
    InvalidSignature,

    /// The request timestamp is outside the allowed time window.
    ///
    /// This error occurs when the timestamp in the signed request is
    /// either too old or too far in the future compared to the current
    /// current time, exceeding the configured time window.
    ///
    /// # When This Occurs
    ///
    /// - System clocks are significantly out of sync
    /// - Network delays cause old requests to arrive late
    /// - The time window is configured too strictly
    /// - A malicious actor attempts to use very old captured requests
    ///
    /// # Resolution
    ///
    /// - Synchronize system clocks (e.g., using NTP)
    /// - Increase the time window if appropriate for your use case
    /// - Generate fresh requests closer to when they'll be sent
    #[error("Timestamp out of window")]
    TimestampOutOfWindow,

    /// A storage operation failed.
    ///
    /// This error occurs when there's a problem with the underlying
    /// storage backend operations, such as connection issues, disk space
    /// problems, or corruption. This applies to all storage backends
    /// including memory, SQLite, Redis, and others.
    ///
    /// # When This Occurs
    ///
    /// - Storage backend is unavailable or unreachable
    /// - Database file is corrupted or inaccessible (SQLite)
    /// - Redis server connection issues (Redis)
    /// - Insufficient disk space for storage operations
    /// - Storage backend is locked by another process
    /// - File permission issues (file-based storage)
    ///
    /// # Resolution
    ///
    /// - Check storage backend availability and connectivity
    /// - Verify storage permissions and disk space
    /// - Ensure proper storage initialization
    /// - Check for competing storage access
    #[error("Storage error: {0}")]
    StorageError(#[source] Box<dyn std::error::Error + Send + Sync>),

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

impl NonceError {
    /// Returns a stable string code for this error that can be used for programmatic error handling.
    ///
    /// The error codes are guaranteed to remain stable across versions, making them
    /// suitable for use in error handling logic, logging, monitoring, and API responses.
    ///
    /// # Error Codes
    ///
    /// - `duplicate_nonce`: Nonce has already been used
    /// - `invalid_signature`: HMAC signature verification failed
    /// - `timestamp_out_of_window`: Request timestamp is outside allowed window
    /// - `storage_error`: Storage backend operation failed
    /// - `crypto_error`: Cryptographic operation failed
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceError;
    ///
    /// let error = NonceError::DuplicateNonce;
    /// assert_eq!(error.code(), "duplicate_nonce");
    ///
    /// match error.code() {
    ///     "duplicate_nonce" => println!("Replay attack detected"),
    ///     "invalid_signature" => println!("Authentication failed"),
    ///     "storage_error" => println!("Storage backend issue"),
    ///     _ => println!("Other error"),
    /// }
    /// ```
    pub fn code(&self) -> &'static str {
        match self {
            NonceError::DuplicateNonce => "duplicate_nonce",
            NonceError::InvalidSignature => "invalid_signature",
            NonceError::TimestampOutOfWindow => "timestamp_out_of_window",
            NonceError::StorageError(_) => "storage_error",
            NonceError::CryptoError(_) => "crypto_error",
        }
    }

    /// Creates a new `StorageError` from any error that implements the standard library's `Error` trait.
    ///
    /// This is a convenience method for creating storage errors while preserving the original
    /// error information. The original error will be available through the `source()` method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceError;
    /// use std::io;
    /// use std::error::Error;
    ///
    /// let io_error = io::Error::new(io::ErrorKind::PermissionDenied, "File access denied");
    /// let nonce_error = NonceError::from_storage_error(io_error);
    ///
    /// assert_eq!(nonce_error.code(), "storage_error");
    /// assert!(nonce_error.source().is_some());
    /// ```
    pub fn from_storage_error<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        NonceError::StorageError(Box::new(error))
    }

    /// Creates a new `StorageError` from a string message.
    ///
    /// This method is useful when you need to create a storage error from a string
    /// without an underlying error type.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceError;
    ///
    /// let error = NonceError::from_storage_message("Connection timeout");
    /// assert_eq!(error.code(), "storage_error");
    /// ```
    pub fn from_storage_message<S: Into<String>>(message: S) -> Self {
        #[derive(Debug)]
        struct SimpleError(String);

        impl std::fmt::Display for SimpleError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::error::Error for SimpleError {}

        NonceError::StorageError(Box::new(SimpleError(message.into())))
    }

    /// Returns true if this is a temporary error that might succeed if retried.
    ///
    /// Temporary errors are typically system-level issues like database connectivity
    /// problems or transient resource constraints. Authentication errors like
    /// `InvalidSignature` or `DuplicateNonce` are not considered temporary.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceError;
    ///
    /// let auth_error = NonceError::InvalidSignature;
    /// let db_error = NonceError::from_storage_message("Connection timeout");
    ///
    /// assert!(!auth_error.is_temporary());
    /// assert!(db_error.is_temporary());
    /// ```
    pub fn is_temporary(&self) -> bool {
        matches!(
            self,
            NonceError::StorageError(_) | NonceError::CryptoError(_)
        )
    }

    /// Returns true if this is an authentication-related error.
    ///
    /// Authentication errors indicate issues with the credential verification
    /// process, as opposed to system-level errors.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceError;
    ///
    /// let auth_error = NonceError::InvalidSignature;
    /// let system_error = NonceError::from_storage_message("Connection timeout");
    ///
    /// assert!(auth_error.is_authentication_error());
    /// assert!(!system_error.is_authentication_error());
    /// ```
    pub fn is_authentication_error(&self) -> bool {
        matches!(
            self,
            NonceError::DuplicateNonce
                | NonceError::InvalidSignature
                | NonceError::TimestampOutOfWindow
        )
    }

    /// Returns true if this error represents a request-side issue.
    ///
    /// Request errors indicate problems with the request that should
    /// be fixed before retrying.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceError;
    ///
    /// let request_error = NonceError::InvalidSignature;
    /// let system_error = NonceError::from_storage_message("Connection failed");
    ///
    /// assert!(request_error.is_client_error());
    /// assert!(!system_error.is_client_error());
    /// ```
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            NonceError::DuplicateNonce
                | NonceError::InvalidSignature
                | NonceError::TimestampOutOfWindow
        )
    }

    /// Returns true if this error represents a system-side issue.
    ///
    /// System errors indicate problems with the system that are
    /// not the request's fault and may be temporary.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceError;
    ///
    /// let system_error = NonceError::from_storage_message("Connection failed");
    /// let request_error = NonceError::InvalidSignature;
    ///
    /// assert!(system_error.is_server_error());
    /// assert!(!request_error.is_server_error());
    /// ```
    pub fn is_server_error(&self) -> bool {
        matches!(
            self,
            NonceError::StorageError(_) | NonceError::CryptoError(_)
        )
    }
}

// SQLite error conversion is now provided in examples/sqlite_storage.rs
// since rusqlite is no longer a core dependency

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_error_types() {
        // Test error display messages
        assert_eq!(
            NonceError::DuplicateNonce.to_string(),
            "Nonce already exists"
        );
        assert_eq!(
            NonceError::InvalidSignature.to_string(),
            "Invalid signature"
        );
        assert_eq!(
            NonceError::TimestampOutOfWindow.to_string(),
            "Timestamp out of window"
        );

        let storage_error = NonceError::from_storage_message("test error");
        assert_eq!(storage_error.to_string(), "Storage error: test error");

        let crypto_error = NonceError::CryptoError("crypto test error".to_string());
        assert_eq!(crypto_error.to_string(), "Crypto error: crypto test error");
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(NonceError::DuplicateNonce.code(), "duplicate_nonce");
        assert_eq!(NonceError::InvalidSignature.code(), "invalid_signature");
        assert_eq!(
            NonceError::TimestampOutOfWindow.code(),
            "timestamp_out_of_window"
        );
        assert_eq!(
            NonceError::from_storage_message("test").code(),
            "storage_error"
        );
        assert_eq!(
            NonceError::CryptoError("test".to_string()).code(),
            "crypto_error"
        );
    }

    #[test]
    fn test_storage_error_from_error() {
        use std::io;

        let io_error = io::Error::new(io::ErrorKind::PermissionDenied, "Permission denied");
        let nonce_error = NonceError::from_storage_error(io_error);

        assert_eq!(nonce_error.code(), "storage_error");
        assert!(nonce_error.source().is_some());
        assert!(nonce_error.to_string().contains("Permission denied"));
    }

    #[test]
    fn test_storage_error_from_message() {
        let error = NonceError::from_storage_message("Connection timeout");

        assert_eq!(error.code(), "storage_error");
        assert!(error.to_string().contains("Connection timeout"));
    }

    #[test]
    fn test_error_classification() {
        // Authentication errors (client errors, not temporary)
        let auth_errors = [
            NonceError::DuplicateNonce,
            NonceError::InvalidSignature,
            NonceError::TimestampOutOfWindow,
        ];
        for error in &auth_errors {
            assert!(error.is_authentication_error());
            assert!(error.is_client_error());
            assert!(!error.is_server_error());
            assert!(!error.is_temporary());
        }

        // System errors (server errors, temporary)
        let system_errors = [
            NonceError::from_storage_message("test"),
            NonceError::CryptoError("test".to_string()),
        ];
        for error in &system_errors {
            assert!(!error.is_authentication_error());
            assert!(!error.is_client_error());
            assert!(error.is_server_error());
            assert!(error.is_temporary());
        }
    }
}
