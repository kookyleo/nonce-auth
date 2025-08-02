use hmac::Mac;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};

use super::NonceError;
use crate::{HmacSha256, NonceCredential};

/// A function type for generating nonces.
pub type NonceGenerator = Box<dyn Fn() -> String + Send + Sync>;

/// A function type for providing timestamps.
pub type TimeProvider = Box<dyn Fn() -> Result<u64, NonceError> + Send + Sync>;

/// A client for generating cryptographically signed `NonceCredential`s.
///
/// This client is stateless and responsible for creating credentials that can be
/// verified by a `NonceServer`.
///
/// # Example
///
/// ```rust
/// use nonce_auth::NonceClient;
/// use hmac::Mac; // Trait for `mac.update()`
///
/// let client = NonceClient::new(b"my_secret");
/// let payload = b"some_data_to_protect";
///
/// // Standard usage:
/// let credential = client.credential_builder().sign(payload).unwrap();
///
/// // Advanced usage:
/// let custom_credential = client.credential_builder().sign_with(|mac, ts, nonce| {
///     mac.update(ts.as_bytes());
///     mac.update(nonce.as_bytes());
///     mac.update(payload);
/// }).unwrap();
/// ```
pub struct NonceClient {
    secret: Vec<u8>,
    nonce_generator: NonceGenerator,
    time_provider: TimeProvider,
}

impl NonceClient {
    /// Creates a new `NonceClient` with the specified shared secret and default generators.
    /// 
    /// Uses UUID v4 for nonce generation and system time for timestamps.
    /// For more customization options, use `NonceClient::builder()`.
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            nonce_generator: Box::new(|| uuid::Uuid::new_v4().to_string()),
            time_provider: Box::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| NonceError::CryptoError(format!("System clock error: {}", e)))
                    .map(|d| d.as_secs())
            }),
        }
    }

    /// Creates a new `NonceClientBuilder` for advanced configuration.
    pub fn builder() -> NonceClientBuilder {
        NonceClientBuilder::new()
    }

    /// Returns a builder to construct and sign a `NonceCredential`.
    ///
    /// This is the recommended entry point for creating credentials.
    pub fn credential_builder(&self) -> NonceCredentialBuilder {
        NonceCredentialBuilder::new(self)
    }

    /// Low-level function to generate a signature. Used internally by the builder.
    fn generate_signature<F>(&self, data_builder: F) -> Result<String, NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|e| NonceError::CryptoError(e.to_string()))?;
        data_builder(&mut mac);
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }
}

/// A builder for creating a `NonceCredential`.
///
/// This builder provides a safe and ergonomic API for signing data.
pub struct NonceCredentialBuilder<'a> {
    client: &'a NonceClient,
    _phantom: PhantomData<()>,
}

impl<'a> NonceCredentialBuilder<'a> {
    fn new(client: &'a NonceClient) -> Self {
        Self {
            client,
            _phantom: PhantomData,
        }
    }

    /// Signs the standard components (`timestamp`, `nonce`) plus a payload.
    ///
    /// This is the recommended method for most use cases, as it ensures the payload
    /// is always included in the signature.
    ///
    /// # Arguments
    ///
    /// * `payload`: The business data to include in the signature.
    pub fn sign(self, payload: &[u8]) -> Result<NonceCredential, NonceError> {
        self.sign_with(|mac, timestamp, nonce| {
            mac.update(timestamp.as_bytes());
            mac.update(nonce.as_bytes());
            mac.update(payload);
        })
    }

    /// Signs the credential using custom logic defined in a closure for advanced use cases.
    ///
    /// # Warning
    ///
    /// You are responsible for including all relevant data in the signature
    /// within the closure. Forgetting to include the payload can lead to security vulnerabilities.
    ///
    /// # Arguments
    ///
    /// * `signature_builder`: A closure that defines the exact data to be signed.
    pub fn sign_with<F>(self, signature_builder: F) -> Result<NonceCredential, NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>, &str, &str),
    {
        let timestamp = (self.client.time_provider)()?;
        let nonce = (self.client.nonce_generator)();

        let signature = self.client.generate_signature(|mac| {
            signature_builder(mac, &timestamp.to_string(), &nonce);
        })?;

        Ok(NonceCredential {
            timestamp,
            nonce,
            signature,
        })
    }
}

/// A builder for creating customized `NonceClient` instances.
///
/// This builder allows you to customize nonce generation, timestamp providers,
/// and other aspects of the client behavior.
///
/// # Example
///
/// ```rust
/// use nonce_auth::NonceClient;
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// // Create a client with custom nonce generator
/// let client = NonceClient::builder()
///     .with_secret(b"my_secret")
///     .with_nonce_generator(|| format!("custom-{}", rand::random::<u32>()))
///     .with_time_provider(|| {
///         SystemTime::now()
///             .duration_since(UNIX_EPOCH)
///             .map(|d| d.as_secs())
///             .map_err(|e| nonce_auth::NonceError::CryptoError(format!("Time error: {}", e)))
///     })
///     .build();
/// ```
pub struct NonceClientBuilder {
    secret: Option<Vec<u8>>,
    nonce_generator: Option<NonceGenerator>,
    time_provider: Option<TimeProvider>,
}

impl NonceClientBuilder {
    /// Creates a new `NonceClientBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            secret: None,
            nonce_generator: None,
            time_provider: None,
        }
    }

    /// Sets the shared secret for cryptographic operations.
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        self.secret = Some(secret.to_vec());
        self
    }

    /// Sets a custom nonce generator function.
    ///
    /// The function should return a unique string each time it's called.
    /// The default uses UUID v4.
    pub fn with_nonce_generator<F>(mut self, generator: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.nonce_generator = Some(Box::new(generator));
        self
    }

    /// Sets a custom time provider function for generating timestamps.
    ///
    /// The function should return the current time as seconds since UNIX epoch.
    /// The default uses `SystemTime::now()`.
    pub fn with_time_provider<F>(mut self, provider: F) -> Self
    where
        F: Fn() -> Result<u64, NonceError> + Send + Sync + 'static,
    {
        self.time_provider = Some(Box::new(provider));
        self
    }

    /// Builds the `NonceClient` with the configured options.
    ///
    /// # Panics
    ///
    /// Panics if no secret was provided via `with_secret()`.
    pub fn build(self) -> NonceClient {
        let secret = self.secret.expect("Secret is required. Use with_secret() to provide one.");
        
        let nonce_generator = self.nonce_generator.unwrap_or_else(|| {
            Box::new(|| uuid::Uuid::new_v4().to_string())
        });

        let time_provider = self.time_provider.unwrap_or_else(|| {
            Box::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| NonceError::CryptoError(format!("System clock error: {}", e)))
                    .map(|d| d.as_secs())
            })
        });

        NonceClient {
            secret,
            nonce_generator,
            time_provider,
        }
    }
}

impl Default for NonceClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test_secret_key_123";

    #[test]
    fn test_client_creation() {
        let client = NonceClient::new(TEST_SECRET);
        assert_eq!(client.secret, TEST_SECRET);
    }

    #[test]
    fn test_builder_sign_standard() {
        let client = NonceClient::new(TEST_SECRET);
        let payload = b"test payload";

        let credential = client.credential_builder().sign(payload).unwrap();

        assert!(credential.timestamp > 0);
        assert!(!credential.nonce.is_empty());
        assert!(!credential.signature.is_empty());
        assert_eq!(credential.signature.len(), 64);

        // Verify the signature matches the expected components
        let expected_signature = client
            .generate_signature(|mac| {
                mac.update(credential.timestamp.to_string().as_bytes());
                mac.update(credential.nonce.as_bytes());
                mac.update(payload);
            })
            .unwrap();
        assert_eq!(credential.signature, expected_signature);
    }

    #[test]
    fn test_builder_sign_with_custom_logic() {
        let client = NonceClient::new(TEST_SECRET);
        let payload = "test payload";
        let extra = "extra_context";

        let credential = client
            .credential_builder()
            .sign_with(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
                mac.update(payload.as_bytes());
                mac.update(extra.as_bytes());
            })
            .unwrap();

        // Verify the signature includes all custom parts
        let expected_signature = client
            .generate_signature(|mac| {
                mac.update(credential.timestamp.to_string().as_bytes());
                mac.update(credential.nonce.as_bytes());
                mac.update(payload.as_bytes());
                mac.update(extra.as_bytes());
            })
            .unwrap();
        assert_eq!(credential.signature, expected_signature);
    }

    #[test]
    fn test_multiple_credentials_different_nonces() {
        let client = NonceClient::new(TEST_SECRET);

        let credential1 = client.credential_builder().sign(b"payload1").unwrap();
        let credential2 = client.credential_builder().sign(b"payload2").unwrap();

        assert_ne!(credential1.nonce, credential2.nonce);
        assert_ne!(credential1.signature, credential2.signature);
    }

    #[test]
    fn test_builder_with_secret() {
        let client = NonceClient::builder()
            .with_secret(TEST_SECRET)
            .build();
        
        assert_eq!(client.secret, TEST_SECRET);
    }

    #[test]
    fn test_builder_with_custom_nonce_generator() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter_clone = counter.clone();
        
        let client = NonceClient::builder()
            .with_secret(TEST_SECRET)
            .with_nonce_generator(move || {
                let val = counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                format!("custom-nonce-{}", val)
            })
            .build();

        let credential1 = client.credential_builder().sign(b"test").unwrap();
        let credential2 = client.credential_builder().sign(b"test").unwrap();

        assert_eq!(credential1.nonce, "custom-nonce-0");
        assert_eq!(credential2.nonce, "custom-nonce-1");
    }

    #[test]
    fn test_builder_with_custom_time_provider() {
        let fixed_time = 1234567890u64;
        
        let client = NonceClient::builder()
            .with_secret(TEST_SECRET)
            .with_time_provider(move || Ok(fixed_time))
            .build();

        let credential = client.credential_builder().sign(b"test").unwrap();
        assert_eq!(credential.timestamp, fixed_time);
    }

    #[test]
    fn test_builder_with_all_custom_options() {
        let client = NonceClient::builder()
            .with_secret(TEST_SECRET)
            .with_nonce_generator(|| "fixed-nonce".to_string())
            .with_time_provider(|| Ok(9999999999))
            .build();

        let credential = client.credential_builder().sign(b"test payload").unwrap();
        
        assert_eq!(credential.nonce, "fixed-nonce");
        assert_eq!(credential.timestamp, 9999999999);
        
        // Verify signature is computed correctly with fixed values
        let expected_signature = client
            .generate_signature(|mac| {
                mac.update(b"9999999999");
                mac.update(b"fixed-nonce");
                mac.update(b"test payload");
            })
            .unwrap();
        assert_eq!(credential.signature, expected_signature);
    }

    #[test]
    #[should_panic(expected = "Secret is required")]
    fn test_builder_without_secret_panics() {
        NonceClient::builder().build();
    }

    #[test]
    fn test_builder_default() {
        let builder1 = NonceClientBuilder::new();
        let builder2 = NonceClientBuilder::default();
        
        // Both should have the same initial state (all None)
        assert!(builder1.secret.is_none());
        assert!(builder1.nonce_generator.is_none());
        assert!(builder1.time_provider.is_none());
        
        assert!(builder2.secret.is_none());
        assert!(builder2.nonce_generator.is_none());
        assert!(builder2.time_provider.is_none());
    }
}
