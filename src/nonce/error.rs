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
/// use nonce_auth::{NonceServer, NonceError, NonceClient};
/// use hmac::Mac;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let server = NonceServer::builder().build_and_init().await?;
/// let client = NonceClient::new(b"secret");
/// let payload = b"test payload";
/// let credential = client.credential_builder().sign(payload)?;
///
/// // Handle different error types
/// match server
///     .credential_verifier(&credential)
///     .with_secret(b"secret")
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
    /// database operations, such as connection issues, disk space
    /// problems, or corruption.
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
    DatabaseError(#[source] Box<dyn std::error::Error + Send + Sync>),

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
    ///     _ => println!("Other error"),
    /// }
    /// ```
    pub fn code(&self) -> &'static str {
        match self {
            NonceError::DuplicateNonce => "duplicate_nonce",
            NonceError::ExpiredNonce => "expired_nonce",
            NonceError::InvalidSignature => "invalid_signature",
            NonceError::TimestampOutOfWindow => "timestamp_out_of_window",
            NonceError::DatabaseError(_) => "database_error",
            NonceError::CryptoError(_) => "crypto_error",
        }
    }

    /// Creates a new `DatabaseError` from any error that implements the standard library's `Error` trait.
    ///
    /// This is a convenience method for creating database errors while preserving the original
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
    /// let nonce_error = NonceError::from_database_error(io_error);
    ///
    /// assert_eq!(nonce_error.code(), "database_error");
    /// assert!(nonce_error.source().is_some());
    /// ```
    pub fn from_database_error<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        NonceError::DatabaseError(Box::new(error))
    }

    /// Creates a new `DatabaseError` from a string message.
    ///
    /// This method is useful when you need to create a database error from a string
    /// without an underlying error type.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceError;
    ///
    /// let error = NonceError::from_database_message("Connection timeout");
    /// assert_eq!(error.code(), "database_error");
    /// ```
    pub fn from_database_message<S: Into<String>>(message: S) -> Self {
        #[derive(Debug)]
        struct SimpleError(String);

        impl std::fmt::Display for SimpleError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::error::Error for SimpleError {}

        NonceError::DatabaseError(Box::new(SimpleError(message.into())))
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
    /// let db_error = NonceError::from_database_message("Connection timeout");
    ///
    /// assert!(!auth_error.is_temporary());
    /// assert!(db_error.is_temporary());
    /// ```
    pub fn is_temporary(&self) -> bool {
        matches!(
            self,
            NonceError::DatabaseError(_) | NonceError::CryptoError(_)
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
    /// let system_error = NonceError::from_database_message("Connection timeout");
    ///
    /// assert!(auth_error.is_authentication_error());
    /// assert!(!system_error.is_authentication_error());
    /// ```
    pub fn is_authentication_error(&self) -> bool {
        matches!(
            self,
            NonceError::DuplicateNonce
                | NonceError::ExpiredNonce
                | NonceError::InvalidSignature
                | NonceError::TimestampOutOfWindow
        )
    }

    /// Returns true if this error represents a client-side issue.
    ///
    /// Client errors indicate problems with the request that should
    /// be fixed by the client before retrying.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceError;
    ///
    /// let client_error = NonceError::InvalidSignature;
    /// let server_error = NonceError::from_database_message("Connection failed");
    ///
    /// assert!(client_error.is_client_error());
    /// assert!(!server_error.is_client_error());
    /// ```
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            NonceError::DuplicateNonce
                | NonceError::ExpiredNonce
                | NonceError::InvalidSignature
                | NonceError::TimestampOutOfWindow
        )
    }

    /// Returns true if this error represents a server-side issue.
    ///
    /// Server errors indicate problems with the system that are
    /// not the client's fault and may be temporary.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::NonceError;
    ///
    /// let server_error = NonceError::from_database_message("Connection failed");
    /// let client_error = NonceError::InvalidSignature;
    ///
    /// assert!(server_error.is_server_error());
    /// assert!(!client_error.is_server_error());
    /// ```
    pub fn is_server_error(&self) -> bool {
        matches!(
            self,
            NonceError::DatabaseError(_) | NonceError::CryptoError(_)
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

        let db_error = NonceError::from_database_message("test error");
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
            NonceError::from_database_message("test"),
            NonceError::CryptoError("test".to_string()),
        ];

        for error in errors {
            // Each error should have a non-empty string representation
            assert!(!error.to_string().is_empty());
            // Each error should be debug-printable
            assert!(!format!("{error:?}").is_empty());
        }
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(NonceError::DuplicateNonce.code(), "duplicate_nonce");
        assert_eq!(NonceError::ExpiredNonce.code(), "expired_nonce");
        assert_eq!(NonceError::InvalidSignature.code(), "invalid_signature");
        assert_eq!(
            NonceError::TimestampOutOfWindow.code(),
            "timestamp_out_of_window"
        );
        assert_eq!(
            NonceError::from_database_message("test").code(),
            "database_error"
        );
        assert_eq!(
            NonceError::CryptoError("test".to_string()).code(),
            "crypto_error"
        );
    }

    #[test]
    fn test_database_error_from_error() {
        use std::io;

        let io_error = io::Error::new(io::ErrorKind::PermissionDenied, "Permission denied");
        let nonce_error = NonceError::from_database_error(io_error);

        assert_eq!(nonce_error.code(), "database_error");
        assert!(nonce_error.source().is_some());
        assert!(nonce_error.to_string().contains("Permission denied"));
    }

    #[test]
    fn test_database_error_from_message() {
        let error = NonceError::from_database_message("Connection timeout");

        assert_eq!(error.code(), "database_error");
        assert!(error.to_string().contains("Connection timeout"));
    }

    #[test]
    fn test_is_temporary() {
        // Not temporary errors
        assert!(!NonceError::DuplicateNonce.is_temporary());
        assert!(!NonceError::ExpiredNonce.is_temporary());
        assert!(!NonceError::InvalidSignature.is_temporary());
        assert!(!NonceError::TimestampOutOfWindow.is_temporary());

        // Temporary errors
        assert!(NonceError::from_database_message("test").is_temporary());
        assert!(NonceError::CryptoError("test".to_string()).is_temporary());
    }

    #[test]
    fn test_is_client_error() {
        // Client errors
        assert!(NonceError::DuplicateNonce.is_client_error());
        assert!(NonceError::ExpiredNonce.is_client_error());
        assert!(NonceError::InvalidSignature.is_client_error());
        assert!(NonceError::TimestampOutOfWindow.is_client_error());

        // Not client errors
        assert!(!NonceError::from_database_message("test").is_client_error());
        assert!(!NonceError::CryptoError("test".to_string()).is_client_error());
    }

    #[test]
    fn test_is_server_error() {
        // Server errors
        assert!(NonceError::from_database_message("test").is_server_error());
        assert!(NonceError::CryptoError("test".to_string()).is_server_error());

        // Not server errors
        assert!(!NonceError::DuplicateNonce.is_server_error());
        assert!(!NonceError::InvalidSignature.is_server_error());
        assert!(!NonceError::ExpiredNonce.is_server_error());
        assert!(!NonceError::TimestampOutOfWindow.is_server_error());
    }

    #[test]
    fn test_is_authentication_error() {
        // Authentication errors
        assert!(NonceError::DuplicateNonce.is_authentication_error());
        assert!(NonceError::ExpiredNonce.is_authentication_error());
        assert!(NonceError::InvalidSignature.is_authentication_error());
        assert!(NonceError::TimestampOutOfWindow.is_authentication_error());

        // Not authentication errors
        assert!(!NonceError::from_database_message("test").is_authentication_error());
        assert!(!NonceError::CryptoError("test".to_string()).is_authentication_error());
    }
}
