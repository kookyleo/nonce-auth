//! Asynchronous nonce client implementation.
//!
//! This module provides an async version of the nonce client that supports
//! async operations like fetching secrets from databases, making network calls
//! to get nonces, or synchronizing time with NTP servers.

use crate::nonce::signature::{MacLike, SignatureAlgorithm, create_default_algorithm};
use crate::{NonceCredential, NonceError};
use std::future::Future;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

/// Type alias for async secret provider functions
pub type AsyncSecretProvider = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<Vec<u8>, NonceError>> + Send>> + Send + Sync,
>;

/// Type alias for async nonce generator functions  
pub type AsyncNonceGenerator =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<String, NonceError>> + Send>> + Send + Sync>;

/// Type alias for async time provider functions
pub type AsyncTimeProvider =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<u64, NonceError>> + Send>> + Send + Sync>;

// Helper functions to create common async providers with better ergonomics

/// Creates an async secret provider from a static secret
pub fn static_secret_provider(secret: Vec<u8>) -> AsyncSecretProvider {
    Box::new(move || {
        let secret = secret.clone();
        Box::pin(async move { Ok(secret) })
    })
}

/// Creates an async secret provider from an async function
pub fn async_secret_provider<F, Fut>(f: F) -> AsyncSecretProvider
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Vec<u8>, NonceError>> + Send + 'static,
{
    Box::new(move || Box::pin(f()))
}

/// Creates an async nonce generator from a synchronous function
pub fn sync_nonce_generator<F>(f: F) -> AsyncNonceGenerator
where
    F: Fn() -> String + Send + Sync + 'static,
{
    Box::new(move || {
        let result = f();
        Box::pin(async move { Ok(result) })
    })
}

/// Creates an async nonce generator from an async function
pub fn async_nonce_generator<F, Fut>(f: F) -> AsyncNonceGenerator
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<String, NonceError>> + Send + 'static,
{
    Box::new(move || Box::pin(f()))
}

/// Creates an async time provider from a synchronous function
pub fn sync_time_provider<F>(f: F) -> AsyncTimeProvider
where
    F: Fn() -> Result<u64, NonceError> + Send + Sync + 'static,
{
    Box::new(move || {
        let result = f();
        Box::pin(async move { result })
    })
}

/// Creates an async time provider from an async function  
pub fn async_time_provider<F, Fut>(f: F) -> AsyncTimeProvider
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<u64, NonceError>> + Send + 'static,
{
    Box::new(move || Box::pin(f()))
}

/// An async nonce client that can generate signed credentials with async operations.
///
/// This client supports async secret providers, nonce generators, and time providers,
/// making it suitable for scenarios where credential generation requires network calls,
/// database queries, or other async operations.
///
/// # Example
///
/// ```rust
/// use nonce_auth::AsyncNonceClient;
///
/// # async fn example() -> Result<(), nonce_auth::NonceError> {
/// // Simple async client with static secret
/// let client = AsyncNonceClient::builder()
///     .with_secret_provider(|| async { Ok(b"my_secret".to_vec()) })
///     .build();
///
/// let payload = b"important_data";
/// let credential = client.credential_builder().sign(payload).await?;
/// # Ok(())
/// # }
/// ```
pub struct AsyncNonceClient {
    secret_provider: AsyncSecretProvider,
    nonce_generator: AsyncNonceGenerator,
    time_provider: AsyncTimeProvider,
}

impl AsyncNonceClient {
    /// Create a new async client builder.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::AsyncNonceClient;
    ///
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_secret_provider(|| async { Ok(b"secret".to_vec()) })
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> AsyncNonceClientBuilder {
        AsyncNonceClientBuilder::new()
    }

    /// Create a credential builder for generating signed credentials.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::AsyncNonceClient;
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_secret_provider(|| async { Ok(b"secret".to_vec()) })
    ///     .build();
    ///
    /// let credential = client.credential_builder().sign(b"payload").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn credential_builder(&self) -> AsyncCredentialBuilder {
        AsyncCredentialBuilder::new(self)
    }
}

/// Builder for creating `AsyncNonceClient` instances.
///
/// This builder allows you to configure async providers for secrets, nonces, and time.
/// A secret provider is required - all other providers have sensible defaults.
pub struct AsyncNonceClientBuilder {
    secret_provider: Option<AsyncSecretProvider>,
    nonce_generator: Option<AsyncNonceGenerator>,
    time_provider: Option<AsyncTimeProvider>,
}

impl AsyncNonceClientBuilder {
    /// Create a new builder.
    fn new() -> Self {
        Self {
            secret_provider: None,
            nonce_generator: None,
            time_provider: None,
        }
    }

    /// Set an async secret provider.
    ///
    /// The secret provider is called each time a credential is generated,
    /// allowing for dynamic secret rotation or context-dependent secrets.
    ///
    /// # Arguments
    ///
    /// * `provider` - An async function that returns the secret key bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::AsyncNonceClient;
    ///
    /// # async fn fetch_secret_from_vault() -> Result<Vec<u8>, nonce_auth::NonceError> {
    /// #     Ok(b"vault_secret".to_vec())
    /// # }
    /// #
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_secret_provider(|| async {
    ///         // Fetch secret from external vault/database
    ///         fetch_secret_from_vault().await
    ///     })
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_secret_provider<F, Fut>(mut self, provider: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<u8>, NonceError>> + Send + 'static,
    {
        self.secret_provider = Some(async_secret_provider(provider));
        self
    }

    /// Set a static secret (for simple use cases).
    ///
    /// This is a convenience method for cases where you have a static secret
    /// that doesn't need to be fetched asynchronously.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::AsyncNonceClient;
    ///
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_static_secret(b"my_secret".to_vec())
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_static_secret(mut self, secret: Vec<u8>) -> Self {
        self.secret_provider = Some(static_secret_provider(secret));
        self
    }

    /// Set an async nonce generator.
    ///
    /// If not set, defaults to generating UUID v4 nonces.
    ///
    /// # Arguments
    ///
    /// * `generator` - An async function that returns a unique nonce string
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::AsyncNonceClient;
    ///
    /// # async fn fetch_nonce_from_service() -> Result<String, nonce_auth::NonceError> {
    /// #     Ok("service_nonce_123".to_string())
    /// # }
    /// #
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_secret_provider(|| async { Ok(b"secret".to_vec()) })
    ///     .with_nonce_generator(|| async {
    ///         // Fetch nonce from external service to ensure global uniqueness
    ///         fetch_nonce_from_service().await
    ///     })
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_nonce_generator<F, Fut>(mut self, generator: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, NonceError>> + Send + 'static,
    {
        self.nonce_generator = Some(async_nonce_generator(generator));
        self
    }

    /// Set a synchronous nonce generator.
    ///
    /// This is a convenience method for cases where nonce generation
    /// is synchronous (like UUID generation).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::AsyncNonceClient;
    ///
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_static_secret(b"secret".to_vec())
    ///     .with_sync_nonce_generator(|| format!("custom-{}", rand::random::<u32>()))
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_sync_nonce_generator<F>(mut self, generator: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.nonce_generator = Some(sync_nonce_generator(generator));
        self
    }

    /// Set an async time provider.
    ///
    /// If not set, defaults to using system time.
    ///
    /// # Arguments
    ///
    /// * `provider` - An async function that returns the current Unix timestamp
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::AsyncNonceClient;
    ///
    /// # async fn fetch_ntp_time() -> Result<u64, nonce_auth::NonceError> {
    /// #     Ok(1234567890)
    /// # }
    /// #
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_secret_provider(|| async { Ok(b"secret".to_vec()) })
    ///     .with_time_provider(|| async {
    ///         // Use NTP for more accurate time synchronization
    ///         fetch_ntp_time().await
    ///     })
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_time_provider<F, Fut>(mut self, provider: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<u64, NonceError>> + Send + 'static,
    {
        self.time_provider = Some(async_time_provider(provider));
        self
    }

    /// Set a synchronous time provider.
    ///
    /// This is a convenience method for cases where time generation
    /// is synchronous (like system time).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::AsyncNonceClient;
    /// use std::time::{SystemTime, UNIX_EPOCH};
    ///
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_static_secret(b"secret".to_vec())
    ///     .with_sync_time_provider(|| {
    ///         SystemTime::now()
    ///             .duration_since(UNIX_EPOCH)
    ///             .map(|d| d.as_secs())
    ///             .map_err(|e| nonce_auth::NonceError::CryptoError(format!("Time error: {}", e)))
    ///     })
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_sync_time_provider<F>(mut self, provider: F) -> Self
    where
        F: Fn() -> Result<u64, NonceError> + Send + Sync + 'static,
    {
        self.time_provider = Some(sync_time_provider(provider));
        self
    }

    /// Build the async client.
    ///
    /// # Panics
    ///
    /// Panics if no secret provider was set using `with_secret_provider()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::AsyncNonceClient;
    ///
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_secret_provider(|| async { Ok(b"secret".to_vec()) })
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self) -> AsyncNonceClient {
        let secret_provider = self
            .secret_provider
            .expect("Secret provider is required. Use with_secret_provider() to set one.");

        let nonce_generator = self.nonce_generator.unwrap_or_else(|| {
            #[cfg(feature = "default-generators")]
            {
                sync_nonce_generator(|| uuid::Uuid::new_v4().to_string())
            }
            #[cfg(not(feature = "default-generators"))]
            {
                Box::new(|| {
                    Box::pin(async {
                        Err(NonceError::CryptoError(
                            "No nonce generator available. Enable 'default-generators' feature or provide a custom generator.".to_string()
                        ))
                    })
                })
            }
        });

        let time_provider = self.time_provider.unwrap_or_else(|| {
            sync_time_provider(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .map_err(|e| NonceError::CryptoError(format!("System time error: {}", e)))
            })
        });

        AsyncNonceClient {
            secret_provider,
            nonce_generator,
            time_provider,
        }
    }
}

/// Builder for creating signed credentials using an async nonce client.
///
/// This builder provides methods for signing payloads with different strategies,
/// all supporting async operations for secret fetching and other dynamic operations.
pub struct AsyncCredentialBuilder<'a> {
    client: &'a AsyncNonceClient,
}

impl<'a> AsyncCredentialBuilder<'a> {
    /// Create a new credential builder.
    fn new(client: &'a AsyncNonceClient) -> Self {
        Self { client }
    }

    /// Sign a payload using the standard signing method.
    ///
    /// This is the recommended method for most use cases. It signs the
    /// timestamp, nonce, and payload in a standard format.
    ///
    /// # Arguments
    ///
    /// * `payload` - The data to sign
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::AsyncNonceClient;
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_secret_provider(|| async { Ok(b"secret".to_vec()) })
    ///     .build();
    ///
    /// let payload = b"important_data";
    /// let credential = client.credential_builder().sign(payload).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign(self, payload: &[u8]) -> Result<NonceCredential, NonceError> {
        let secret = (self.client.secret_provider)().await?;
        let timestamp = (self.client.time_provider)().await?;
        let nonce = (self.client.nonce_generator)().await?;

        let algorithm = create_default_algorithm(&secret);
        let signature = algorithm.sign(timestamp, &nonce, payload)?;

        Ok(NonceCredential {
            timestamp,
            nonce,
            signature,
        })
    }

    /// Sign structured data components.
    ///
    /// This method provides a safer alternative to `sign_with` by handling
    /// the MAC update order automatically. The components are processed in
    /// the exact order they appear in the slice.
    ///
    /// # Arguments
    ///
    /// * `components` - An ordered slice of data components to sign
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::AsyncNonceClient;
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_secret_provider(|| async { Ok(b"secret".to_vec()) })
    ///     .build();
    ///
    /// let user_id = b"user123";
    /// let payload = b"data";
    /// let api_version = b"v1";
    ///
    /// let credential = client.credential_builder()
    ///     .sign_structured(&[user_id, payload, api_version])
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign_structured(
        self,
        components: &[&[u8]],
    ) -> Result<NonceCredential, NonceError> {
        let secret = (self.client.secret_provider)().await?;
        let timestamp = (self.client.time_provider)().await?;
        let nonce = (self.client.nonce_generator)().await?;

        let algorithm = create_default_algorithm(&secret);
        let signature = algorithm.sign_with(timestamp, &nonce, |mac| {
            for component in components {
                mac.update(component);
            }
        })?;

        Ok(NonceCredential {
            timestamp,
            nonce,
            signature,
        })
    }

    /// Sign using custom signature construction logic.
    ///
    /// This method provides maximum flexibility for advanced use cases but
    /// requires careful implementation to ensure security.
    ///
    /// # Arguments
    ///
    /// * `builder` - A closure that receives MAC, timestamp, and nonce for signature construction
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::AsyncNonceClient;
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let client = AsyncNonceClient::builder()
    ///     .with_secret_provider(|| async { Ok(b"secret".to_vec()) })
    ///     .build();
    ///
    /// let credential = client.credential_builder()
    ///     .sign_with(|mac, timestamp, nonce| {
    ///         mac.update(timestamp.as_bytes());
    ///         mac.update(nonce.as_bytes());
    ///         mac.update(b"custom_data");
    ///         mac.update(b"more_context");
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn sign_with<F>(self, builder: F) -> Result<NonceCredential, NonceError>
    where
        F: FnOnce(&mut dyn MacLike, &str, &str),
    {
        let secret = (self.client.secret_provider)().await?;
        let timestamp = (self.client.time_provider)().await?;
        let nonce = (self.client.nonce_generator)().await?;

        let algorithm = create_default_algorithm(&secret);
        let timestamp_str = timestamp.to_string();
        let signature = algorithm.sign_with(timestamp, &nonce, |mac| {
            builder(mac, &timestamp_str, &nonce);
        })?;

        Ok(NonceCredential {
            timestamp,
            nonce,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[tokio::test]
    async fn test_async_client_basic_functionality() {
        let client = AsyncNonceClient::builder()
            .with_secret_provider(|| async { Ok(b"test_secret".to_vec()) })
            .build();

        let payload = b"test_payload";
        let credential = client.credential_builder().sign(payload).await.unwrap();

        assert!(!credential.nonce.is_empty());
        assert!(!credential.signature.is_empty());
        assert!(credential.timestamp > 0);
    }

    #[tokio::test]
    async fn test_async_client_with_custom_providers() {
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = Arc::clone(&counter);

        let client = AsyncNonceClient::builder()
            .with_secret_provider(|| async { Ok(b"custom_secret".to_vec()) })
            .with_nonce_generator(move || {
                let counter = Arc::clone(&counter_clone);
                async move {
                    let id = counter.fetch_add(1, Ordering::SeqCst);
                    Ok(format!("async_nonce_{}", id))
                }
            })
            .with_time_provider(|| async { Ok(1234567890) })
            .build();

        let credential1 = client.credential_builder().sign(b"payload1").await.unwrap();
        let credential2 = client.credential_builder().sign(b"payload2").await.unwrap();

        // Check that nonces are sequential
        assert_eq!(credential1.nonce, "async_nonce_0");
        assert_eq!(credential2.nonce, "async_nonce_1");

        // Check that timestamps are fixed
        assert_eq!(credential1.timestamp, 1234567890);
        assert_eq!(credential2.timestamp, 1234567890);

        // Check that signatures are different (different nonces)
        assert_ne!(credential1.signature, credential2.signature);
    }

    #[tokio::test]
    async fn test_async_client_structured_signing() {
        let client = AsyncNonceClient::builder()
            .with_secret_provider(|| async { Ok(b"test_secret".to_vec()) })
            .build();

        let user_id = b"user123";
        let payload = b"important_data";
        let context = b"api_v1";

        let credential = client
            .credential_builder()
            .sign_structured(&[user_id, payload, context])
            .await
            .unwrap();

        assert!(!credential.nonce.is_empty());
        assert!(!credential.signature.is_empty());
        assert!(credential.timestamp > 0);
    }

    #[tokio::test]
    async fn test_async_client_custom_signing() {
        let client = AsyncNonceClient::builder()
            .with_secret_provider(|| async { Ok(b"test_secret".to_vec()) })
            .build();

        let credential = client
            .credential_builder()
            .sign_with(|mac, timestamp, nonce| {
                mac.update(timestamp.as_bytes());
                mac.update(nonce.as_bytes());
                mac.update(b"custom_payload");
                mac.update(b"extra_context");
            })
            .await
            .unwrap();

        assert!(!credential.nonce.is_empty());
        assert!(!credential.signature.is_empty());
        assert!(credential.timestamp > 0);
    }

    #[tokio::test]
    async fn test_async_client_secret_provider_error() {
        let client = AsyncNonceClient::builder()
            .with_secret_provider(|| async {
                Err(NonceError::CryptoError("Secret fetch failed".to_string()))
            })
            .build();

        let result = client.credential_builder().sign(b"payload").await;
        assert!(matches!(result, Err(NonceError::CryptoError(_))));
    }

    #[tokio::test]
    async fn test_async_client_nonce_generator_error() {
        let client = AsyncNonceClient::builder()
            .with_secret_provider(|| async { Ok(b"secret".to_vec()) })
            .with_nonce_generator(|| async {
                Err(NonceError::CryptoError(
                    "Nonce generation failed".to_string(),
                ))
            })
            .build();

        let result = client.credential_builder().sign(b"payload").await;
        assert!(matches!(result, Err(NonceError::CryptoError(_))));
    }

    #[tokio::test]
    async fn test_async_client_time_provider_error() {
        let client = AsyncNonceClient::builder()
            .with_secret_provider(|| async { Ok(b"secret".to_vec()) })
            .with_time_provider(|| async {
                Err(NonceError::CryptoError("Time fetch failed".to_string()))
            })
            .build();

        let result = client.credential_builder().sign(b"payload").await;
        assert!(matches!(result, Err(NonceError::CryptoError(_))));
    }

    #[tokio::test]
    #[should_panic(expected = "Secret provider is required")]
    async fn test_async_client_builder_without_secret_panics() {
        let _client = AsyncNonceClient::builder().build();
    }
}
