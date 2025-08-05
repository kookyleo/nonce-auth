use crate::NonceCredential;
use crate::nonce::error::NonceError;
use crate::nonce::storage::NonceStorage;
use crate::nonce::time_utils::{current_timestamp, is_outside_window};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

/// A function that provides secrets dynamically based on context.
type SecretProviderFn = Box<
    dyn for<'a> Fn(
            Option<&'a str>,
        )
            -> Pin<Box<dyn Future<Output = Result<Vec<u8>, NonceError>> + Send + 'a>>
        + Send
        + Sync,
>;

/// Verifier for cryptographic credentials.
///
/// `CredentialVerifier` provides a fluent interface for configuring and verifying
/// `NonceCredential` instances. It supports various verification methods including
/// dynamic secret resolution and context isolation.
///
/// This verifier is `Send + Sync` and can be safely shared across threads using
/// `Arc<CredentialVerifier>`, making it suitable for server environments with
/// high concurrency requirements.
pub struct CredentialVerifier {
    storage: Arc<dyn NonceStorage>,
    secret: Option<Vec<u8>>,
    secret_provider: Option<SecretProviderFn>,
    context: Option<String>,
    storage_ttl: Duration,
    time_window: Duration,
}

impl CredentialVerifier {
    /// Creates a new `CredentialVerifier` with default settings.
    ///
    /// # Arguments
    ///
    /// * `storage` - The storage backend for nonce tracking
    ///
    /// # Default Settings
    ///
    /// - Storage TTL: 5 minutes
    /// - Time window: 1 minute
    /// - Signature algorithm: HMAC-SHA256
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::{CredentialVerifier, storage::MemoryStorage};
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let storage = Arc::new(MemoryStorage::new());
    /// let verifier = CredentialVerifier::new(storage);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(storage: Arc<dyn NonceStorage>) -> Self {
        Self {
            storage,
            secret: None,
            secret_provider: None,
            context: None,
            storage_ttl: Duration::from_secs(300), // 5 minutes
            time_window: Duration::from_secs(60),  // 1 minute
        }
    }

    /// Sets the shared secret for verification.
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        self.secret = Some(secret.to_vec());
        self
    }

    /// Sets the context for nonce isolation.
    ///
    /// Contexts allow the same nonce to be used across different scopes
    /// while still preventing replay attacks within each scope.
    pub fn with_context(mut self, context: Option<&str>) -> Self {
        self.context = context.map(|s| s.to_string());
        self
    }

    /// Sets the storage TTL (time-to-live) for nonce records.
    ///
    /// This determines how long nonces are kept in storage before
    /// they can be cleaned up. This should be longer than the
    /// time window to ensure nonces aren't reused.
    ///
    /// # Arguments
    ///
    /// * `storage_ttl` - Duration for which nonces should be stored
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::{CredentialVerifier, storage::MemoryStorage};
    /// # use std::sync::Arc;
    /// # use std::time::Duration;
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// # let storage = Arc::new(MemoryStorage::new());
    /// # let credential = nonce_auth::CredentialBuilder::new(b"secret").sign(b"payload")?;
    /// let verifier = CredentialVerifier::new(storage)
    ///     .with_storage_ttl(Duration::from_secs(600)); // 10 minutes
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_storage_ttl(mut self, storage_ttl: Duration) -> Self {
        self.storage_ttl = storage_ttl;
        self
    }

    /// Sets the time window for timestamp validation.
    pub fn with_time_window(mut self, time_window: Duration) -> Self {
        self.time_window = time_window;
        self
    }

    /// Sets a dynamic secret provider for verification.
    ///
    /// This allows secrets to be resolved dynamically based on the context,
    /// enabling multi-user scenarios where each user has a different secret.
    ///
    /// # Arguments
    ///
    /// * `provider` - Function that resolves the secret based on context
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::{CredentialVerifier, storage::MemoryStorage, NonceError};
    /// # use std::sync::Arc;
    /// # async fn example() -> Result<(), NonceError> {
    /// # let storage = Arc::new(MemoryStorage::new());
    /// # let credential = nonce_auth::CredentialBuilder::new(b"user123_secret").sign(b"payload")?;
    /// let verifier = CredentialVerifier::new(storage)
    ///     .with_context(Some("user123"))
    ///     .with_secret_provider(|context| {
    ///         let owned_context = context.map(|s| s.to_owned());
    ///         async move {
    ///             match owned_context.as_deref() {
    ///                 Some("user123") => Ok(b"user123_secret".to_vec()),
    ///                 Some("user456") => Ok(b"user456_secret".to_vec()),
    ///                 _ => Err(NonceError::CryptoError("Unknown user".to_string())),
    ///             }
    ///         }
    ///     });
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_secret_provider<P, F>(mut self, provider: P) -> Self
    where
        P: for<'a> Fn(Option<&'a str>) -> F + Send + Sync + 'static,
        F: Future<Output = Result<Vec<u8>, NonceError>> + Send + 'static,
    {
        self.secret_provider = Some(Box::new(move |context| Box::pin(provider(context))));
        self
    }

    /// Verifies a credential with a standard payload.
    ///
    /// This method performs the complete verification process:
    /// 1. Validates the timestamp is within the time window
    /// 2. Checks that the nonce hasn't been used before
    /// 3. Verifies the HMAC signature
    /// 4. Stores the nonce to prevent replay attacks
    ///
    /// # Arguments
    ///
    /// * `credential` - The credential to verify
    /// * `payload` - The data that was signed
    ///
    /// # Returns
    ///
    /// `Ok(())` if verification succeeds, or a `NonceError` if verification fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::{CredentialVerifier, storage::MemoryStorage};
    /// # use std::sync::Arc;
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// # let storage = Arc::new(MemoryStorage::new());
    /// # let credential = nonce_auth::CredentialBuilder::new(b"secret").sign(b"payload")?;
    /// let result = CredentialVerifier::new(storage)
    ///     .with_secret(b"shared_secret")
    ///     .verify(&credential, b"payload")
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify(
        self,
        credential: &NonceCredential,
        payload: &[u8],
    ) -> Result<(), NonceError> {
        let secret = if let Some(ref provider) = self.secret_provider {
            provider(self.context.as_deref()).await?
        } else if let Some(ref secret) = self.secret {
            secret.clone()
        } else {
            return Err(NonceError::CryptoError(
                "Either secret or secret_provider must be set before verification".to_string(),
            ));
        };

        self.verify_internal(credential, &secret, |secret| {
            self.verify_signature(
                secret,
                credential.timestamp,
                &credential.nonce,
                payload,
                &credential.signature,
            )
        })
        .await
    }

    /// Verifies a credential with structured data components.
    ///
    /// This method verifies credentials that were created using `sign_structured()`.
    /// The components must be provided in the same order as during signing.
    ///
    /// # Arguments
    ///
    /// * `credential` - The credential to verify
    /// * `components` - Array of data components in the same order as signing
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::{CredentialVerifier, storage::MemoryStorage};
    /// # use std::sync::Arc;
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// # let storage = Arc::new(MemoryStorage::new());
    /// # let credential = nonce_auth::CredentialBuilder::new(b"secret")
    /// #     .sign_structured(&[b"user123", b"action", b"data"])?;
    /// let result = CredentialVerifier::new(storage)
    ///     .with_secret(b"shared_secret")
    ///     .verify_structured(&credential, &[b"user123", b"action", b"data"])
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_structured(
        self,
        credential: &NonceCredential,
        components: &[&[u8]],
    ) -> Result<(), NonceError> {
        let secret = if let Some(ref provider) = self.secret_provider {
            provider(self.context.as_deref()).await?
        } else if let Some(ref secret) = self.secret {
            secret.clone()
        } else {
            return Err(NonceError::CryptoError(
                "Either secret or secret_provider must be set before verification".to_string(),
            ));
        };

        self.verify_internal(credential, &secret, |secret| {
            self.verify_structured_signature(
                secret,
                credential.timestamp,
                &credential.nonce,
                components,
                &credential.signature,
            )
        })
        .await
    }

    /// Verifies a credential using a custom MAC construction function.
    ///
    /// This method provides maximum flexibility by allowing custom MAC verification
    /// that matches the signing process used with `sign_with()`.
    ///
    /// # Arguments
    ///
    /// * `credential` - The credential to verify
    /// * `mac_fn` - Function that constructs the MAC for verification
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::{CredentialVerifier, storage::MemoryStorage};
    /// # use std::sync::Arc;
    /// # use hmac::Mac;
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// # let storage = Arc::new(MemoryStorage::new());
    /// # let credential = nonce_auth::CredentialBuilder::new(b"secret")
    /// #     .sign_with(|mac, timestamp, nonce| {
    /// #         mac.update(b"prefix:");
    /// #         mac.update(timestamp.as_bytes());
    /// #         mac.update(b":nonce:");
    /// #         mac.update(nonce.as_bytes());
    /// #         mac.update(b":custom_data");
    /// #     })?;
    /// let result = CredentialVerifier::new(storage)
    ///     .with_secret(b"shared_secret")
    ///     .verify_with(&credential, |mac| {
    ///         mac.update(b"prefix:");
    ///         mac.update(credential.timestamp.to_string().as_bytes());
    ///         mac.update(b":nonce:");
    ///         mac.update(credential.nonce.as_bytes());
    ///         mac.update(b":custom_data");
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_with<F>(
        self,
        credential: &NonceCredential,
        mac_fn: F,
    ) -> Result<(), NonceError>
    where
        F: FnOnce(&mut HmacSha256),
    {
        let secret = if let Some(ref provider) = self.secret_provider {
            provider(self.context.as_deref()).await?
        } else if let Some(ref secret) = self.secret {
            secret.clone()
        } else {
            return Err(NonceError::CryptoError(
                "Either secret or secret_provider must be set before verification".to_string(),
            ));
        };

        self.verify_internal(credential, &secret, |secret| {
            self.verify_custom_signature(
                secret,
                credential.timestamp,
                &credential.nonce,
                &credential.signature,
                mac_fn,
            )
        })
        .await
    }

    /// Verifies a standard HMAC signature for timestamp, nonce, and payload.
    fn verify_signature(
        &self,
        secret: &[u8],
        timestamp: u64,
        nonce: &str,
        payload: &[u8],
        signature: &str,
    ) -> Result<bool, NonceError> {
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| NonceError::CryptoError(format!("Invalid secret key: {e}")))?;

        mac.update(timestamp.to_string().as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(payload);

        let expected_signature =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        Ok(expected_signature == signature)
    }

    /// Verifies a structured signature for multiple data components.
    fn verify_structured_signature(
        &self,
        secret: &[u8],
        timestamp: u64,
        nonce: &str,
        components: &[&[u8]],
        signature: &str,
    ) -> Result<bool, NonceError> {
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| NonceError::CryptoError(format!("Invalid secret key: {e}")))?;

        mac.update(timestamp.to_string().as_bytes());
        mac.update(nonce.as_bytes());
        for component in components {
            mac.update(component);
        }

        let expected_signature =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        Ok(expected_signature == signature)
    }

    /// Verifies a custom signature using a user-provided MAC construction function.
    fn verify_custom_signature<F>(
        &self,
        secret: &[u8],
        _timestamp: u64,
        _nonce: &str,
        signature: &str,
        mac_fn: F,
    ) -> Result<bool, NonceError>
    where
        F: FnOnce(&mut HmacSha256),
    {
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| NonceError::CryptoError(format!("Invalid secret key: {e}")))?;

        mac_fn(&mut mac);

        let expected_signature =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        Ok(expected_signature == signature)
    }

    /// Internal verification logic shared by all verification methods.
    async fn verify_internal<F>(
        &self,
        credential: &NonceCredential,
        secret: &[u8],
        verify_signature: F,
    ) -> Result<(), NonceError>
    where
        F: FnOnce(&[u8]) -> Result<bool, NonceError>,
    {
        // 1. Validate timestamp is within time window
        let current_time = current_timestamp()?;
        if is_outside_window(credential.timestamp, current_time, self.time_window) {
            return Err(NonceError::TimestampOutOfWindow);
        }

        // 2. Verify signature FIRST (before consuming the nonce)
        let signature_valid = verify_signature(secret)?;
        if !signature_valid {
            return Err(NonceError::InvalidSignature);
        }

        // 3. Check nonce uniqueness and store if unique (only after signature is verified)
        let context_str = self.context.as_deref();

        // Check if nonce already exists - if it does, it's a duplicate regardless of TTL
        if self.storage.exists(&credential.nonce, context_str).await? {
            return Err(NonceError::DuplicateNonce);
        }

        // Store the nonce (only if it doesn't exist)
        self.storage
            .set(&credential.nonce, context_str, self.storage_ttl)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CredentialBuilder;
    use crate::nonce::storage::MemoryStorage;
    use std::time::Duration;

    #[tokio::test]
    async fn test_basic_verification() {
        let storage = Arc::new(MemoryStorage::new());
        let secret = b"test_secret";
        let payload = b"test_payload";

        let credential = CredentialBuilder::new(secret).sign(payload).unwrap();

        let result = CredentialVerifier::new(storage)
            .with_secret(secret)
            .verify(&credential, payload)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_duplicate_nonce_rejection() {
        let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
        let secret = b"test_secret";
        let payload = b"test_payload";

        let credential = CredentialBuilder::new(secret).sign(payload).unwrap();

        // First verification should succeed
        CredentialVerifier::new(Arc::clone(&storage))
            .with_secret(secret)
            .verify(&credential, payload)
            .await
            .unwrap();

        // Second verification should fail
        let result = CredentialVerifier::new(storage)
            .with_secret(secret)
            .verify(&credential, payload)
            .await;

        assert!(matches!(result, Err(NonceError::DuplicateNonce)));
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
        let payload = b"test_payload";

        let credential = CredentialBuilder::new(b"secret1").sign(payload).unwrap();

        let result = CredentialVerifier::new(storage)
            .with_secret(b"secret2") // Different secret
            .verify(&credential, payload)
            .await;

        assert!(matches!(result, Err(NonceError::InvalidSignature)));
    }

    #[tokio::test]
    async fn test_timestamp_out_of_window() {
        let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
        let secret = b"test_secret";
        let payload = b"test_payload";

        // Create credential with old timestamp
        let old_timestamp = (current_timestamp().unwrap() - 3600) as u64; // 1 hour ago
        let credential = CredentialBuilder::new(secret)
            .with_time_provider(move || Ok(old_timestamp))
            .sign(payload)
            .unwrap();

        let result = CredentialVerifier::new(storage)
            .with_secret(secret)
            .with_time_window(Duration::from_secs(60)) // 1 minute window
            .verify(&credential, payload)
            .await;

        assert!(matches!(result, Err(NonceError::TimestampOutOfWindow)));
    }

    #[tokio::test]
    async fn test_context_isolation() {
        let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
        let secret = b"test_secret";
        let payload = b"test_payload";

        let credential = CredentialBuilder::new(secret).sign(payload).unwrap();

        // Use in context1
        CredentialVerifier::new(Arc::clone(&storage))
            .with_secret(secret)
            .with_context(Some("context1"))
            .verify(&credential, payload)
            .await
            .unwrap();

        // Should work in context2 (different context)
        let result = CredentialVerifier::new(Arc::clone(&storage))
            .with_secret(secret)
            .with_context(Some("context2"))
            .verify(&credential, payload)
            .await;

        assert!(result.is_ok());

        // Should fail in context1 again (same context)
        let result = CredentialVerifier::new(storage)
            .with_secret(secret)
            .with_context(Some("context1"))
            .verify(&credential, payload)
            .await;

        assert!(matches!(result, Err(NonceError::DuplicateNonce)));
    }

    #[tokio::test]
    async fn test_structured_verification() {
        let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
        let secret = b"test_secret";
        let components = [b"part1".as_slice(), b"part2", b"part3"];

        let credential = CredentialBuilder::new(secret)
            .sign_structured(&components)
            .unwrap();

        let result = CredentialVerifier::new(storage)
            .with_secret(secret)
            .verify_structured(&credential, &components)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_custom_verification() {
        let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
        let secret = b"test_secret";

        let credential = CredentialBuilder::new(secret)
            .sign_with(|mac, timestamp, nonce| {
                mac.update(b"prefix:");
                mac.update(timestamp.as_bytes());
                mac.update(b":nonce:");
                mac.update(nonce.as_bytes());
                mac.update(b":custom");
            })
            .unwrap();

        let result = CredentialVerifier::new(storage)
            .with_secret(secret)
            .verify_with(&credential, |mac| {
                mac.update(b"prefix:");
                mac.update(credential.timestamp.to_string().as_bytes());
                mac.update(b":nonce:");
                mac.update(credential.nonce.as_bytes());
                mac.update(b":custom");
            })
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_secret_provider() {
        let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
        let payload = b"test_payload";

        let credential = CredentialBuilder::new(b"user123_secret")
            .sign(payload)
            .unwrap();

        let result = CredentialVerifier::new(storage)
            .with_context(Some("user123"))
            .with_secret_provider(|context| {
                let owned_context = context.map(|s| s.to_owned());
                async move {
                    match owned_context.as_deref() {
                        Some("user123") => Ok(b"user123_secret".to_vec()),
                        Some("user456") => Ok(b"user456_secret".to_vec()),
                        _ => Err(NonceError::CryptoError("Unknown user".to_string())),
                    }
                }
            })
            .verify(&credential, payload)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_secret_provider_error() {
        let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
        let payload = b"test_payload";

        let credential = CredentialBuilder::new(b"secret").sign(payload).unwrap();

        let result = CredentialVerifier::new(storage)
            .with_context(Some("unknown_user"))
            .with_secret_provider(|_context| async {
                Err(NonceError::from_storage_message("User not found"))
            })
            .verify(&credential, payload)
            .await;

        assert!(matches!(result, Err(NonceError::StorageError(_))));
    }

    #[tokio::test]
    async fn test_verification_without_secret() {
        let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
        let payload = b"test_payload";

        let credential = CredentialBuilder::new(b"secret").sign(payload).unwrap();

        let result = CredentialVerifier::new(storage)
            .verify(&credential, payload) // No secret set
            .await;

        assert!(matches!(result, Err(NonceError::CryptoError(_))));
    }

    #[test]
    fn test_credential_verifier_implements_sync() {
        // This test will only compile if CredentialVerifier implements Sync
        fn assert_sync<T: Sync>() {}
        assert_sync::<CredentialVerifier>();

        // Test that it can actually be shared across threads
        let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());
        let verifier = Arc::new(CredentialVerifier::new(storage).with_secret(b"test"));

        let verifier_clone = Arc::clone(&verifier);
        let handle = std::thread::spawn(move || {
            // This verifies the verifier can be moved to another thread
            drop(verifier_clone);
        });

        handle.join().unwrap();
        println!("CredentialVerifier successfully implements Sync!");
    }
}
