use hmac::Mac;
use std::future::Future;

#[cfg(feature = "metrics")]
use std::time::Instant;

use crate::NonceCredential;
use crate::nonce::{NonceError, NonceServer};
use crate::storage::NonceStorage;

#[cfg(feature = "metrics")]
use crate::nonce::metrics::MetricEvent;

/// A verifier for `NonceCredential`s, created by `NonceServer::credential_verifier`.
///
/// This builder-like struct provides a safe and ergonomic API for verifying credentials.
/// Methods can be chained to configure context, secrets, and secret providers before verification.
#[must_use = "The verifier does nothing unless one of the `verify` methods is called."]
pub struct CredentialVerifier<'a, S: NonceStorage> {
    server: &'a NonceServer<S>,
    credential: &'a NonceCredential,
    context: Option<&'a str>,
    secret: Option<&'a [u8]>,
}

impl<'a, S: NonceStorage + 'static> CredentialVerifier<'a, S> {
    /// Creates a new verifier.
    pub(crate) fn new(server: &'a NonceServer<S>, credential: &'a NonceCredential) -> Self {
        Self {
            server,
            credential,
            context: None,
            secret: None,
        }
    }

    /// Sets the context for this verification operation.
    ///
    /// The context provides an additional layer of isolation for nonces.
    pub fn with_context(mut self, context: Option<&'a str>) -> Self {
        self.context = context;
        self
    }

    /// Sets the secret key for this verification operation.
    ///
    /// This is required for signature verification. Each user/client may have a different secret.
    pub fn with_secret(mut self, secret: &'a [u8]) -> Self {
        self.secret = Some(secret);
        self
    }

    /// Fetches the secret dynamically and verifies the credential against a standard payload.
    ///
    /// This method combines secret fetching and verification in one step to avoid lifetime issues.
    /// The secret provider receives the current context (if set) and should return the appropriate secret.
    ///
    /// # Arguments
    ///
    /// * `payload`: The payload that was signed on the client side.
    /// * `secret_provider`: An async closure that takes the current context and returns the secret key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::{NonceServer, NonceClient, NonceError};
    /// # async fn get_secret_for_user(user_id: &str) -> Result<Vec<u8>, NonceError> {
    /// #     Ok(b"user_secret".to_vec())
    /// # }
    /// # async fn example() -> Result<(), NonceError> {
    /// let server = NonceServer::builder().build_and_init().await?;
    /// let client = NonceClient::new(b"user_secret");
    /// let payload = b"important_data";
    /// let user_id = "user123";
    ///
    /// let credential = client.credential_builder().sign(payload)?;
    ///
    /// // Chain context then verify with secret provider
    /// server.credential_verifier(&credential)
    ///     .with_context(Some(user_id))
    ///     .verify_with_secret_provider(payload, |context| async move {
    ///         match context {
    ///             Some(user_id) => get_secret_for_user(&user_id).await,
    ///             None => Err(NonceError::CryptoError("Context required for secret lookup".to_string())),
    ///         }
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_with_secret_provider<F, Fut>(
        self,
        payload: &[u8],
        secret_provider: F,
    ) -> Result<(), NonceError>
    where
        F: FnOnce(Option<String>) -> Fut,
        Fut: Future<Output = Result<Vec<u8>, NonceError>>,
    {
        let secret = secret_provider(self.context.map(|s| s.to_string())).await?;

        // Create new verifier with the fetched secret
        CredentialVerifier {
            server: self.server,
            credential: self.credential,
            context: self.context,
            secret: Some(&secret),
        }
        .verify(payload)
        .await
    }

    /// Fetches the secret dynamically and verifies using structured data components.
    ///
    /// This method combines secret fetching and structured verification in one step.
    ///
    /// # Arguments
    ///
    /// * `data_components`: An ordered slice of byte slices to be included in the signature.
    /// * `secret_provider`: An async closure that takes the current context and returns the secret key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::{NonceServer, NonceClient, NonceError};
    /// # async fn get_secret_for_user(user_id: &str) -> Result<Vec<u8>, NonceError> {
    /// #     Ok(b"user_secret".to_vec())
    /// # }
    /// # async fn example() -> Result<(), NonceError> {
    /// let server = NonceServer::builder().build_and_init().await?;
    /// let client = NonceClient::new(b"user_secret");
    /// let user_id = "user123";
    /// let payload = b"important_data";
    ///
    /// let credential = client.credential_builder()
    ///     .sign_structured(&[user_id.as_bytes(), payload])?;
    ///
    /// server.credential_verifier(&credential)
    ///     .with_context(Some(user_id))
    ///     .verify_structured_with_secret_provider(&[user_id.as_bytes(), payload], |context| async move {
    ///         match context {
    ///             Some(user_id) => get_secret_for_user(&user_id).await,
    ///             None => Err(NonceError::CryptoError("Context required".to_string())),
    ///         }
    ///     })
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_structured_with_secret_provider<F, Fut>(
        self,
        data_components: &[&[u8]],
        secret_provider: F,
    ) -> Result<(), NonceError>
    where
        F: FnOnce(Option<String>) -> Fut,
        Fut: Future<Output = Result<Vec<u8>, NonceError>>,
    {
        let secret = secret_provider(self.context.map(|s| s.to_string())).await?;

        // Create new verifier with the fetched secret
        CredentialVerifier {
            server: self.server,
            credential: self.credential,
            context: self.context,
            secret: Some(&secret),
        }
        .verify_structured(data_components)
        .await
    }

    /// Verifies the credential against a standard payload.
    ///
    /// This is the recommended verification method for most use cases. It assumes the
    /// signature was created on the client using `sign(payload)`.
    ///
    /// # Arguments
    ///
    /// * `payload`: The payload that was signed on the client side.
    pub async fn verify(self, payload: &[u8]) -> Result<(), NonceError> {
        let timestamp_str = self.credential.timestamp.to_string();
        let nonce_str = &self.credential.nonce;

        self.verify_with(|mac| {
            mac.update(timestamp_str.as_bytes());
            mac.update(nonce_str.as_bytes());
            mac.update(payload);
        })
        .await
    }

    /// Verifies the credential using a structured list of data components.
    ///
    /// This is a safer alternative to `verify_with` that eliminates the possibility of
    /// MAC update order mistakes. The provided data components will be processed in
    /// the exact order they appear in the slice.
    ///
    /// # Arguments
    ///
    /// * `data_components`: An ordered slice of byte slices to be included in the signature.
    ///   The order must exactly match the order used in `sign_structured` on the client side.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use nonce_auth::{NonceServer, NonceClient};
    /// # async fn example() -> Result<(), nonce_auth::NonceError> {
    /// let server = NonceServer::builder().build_and_init().await?;
    /// let client = NonceClient::new(b"secret");
    ///
    /// let user_id = b"user123";
    /// let payload = b"important_data";
    /// let context = b"api_v2";
    ///
    /// // Client side
    /// let credential = client.credential_builder()
    ///     .sign_structured(&[user_id, payload, context])?;
    ///
    /// // Server side
    /// server.credential_verifier(&credential)
    ///     .with_secret(b"secret")
    ///     .verify_structured(&[user_id, payload, context])
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_structured(self, data_components: &[&[u8]]) -> Result<(), NonceError> {
        let timestamp_str = self.credential.timestamp.to_string();
        let nonce_str = &self.credential.nonce;

        self.verify_with(|mac| {
            // Always include timestamp and nonce first
            mac.update(timestamp_str.as_bytes());
            mac.update(nonce_str.as_bytes());

            // Then include all data components in order
            for component in data_components {
                mac.update(component);
            }
        })
        .await
    }

    /// Verifies the credential using custom signature-reconstruction logic.
    ///
    /// This method is for advanced scenarios where the signature includes more than
    /// just the standard payload.
    ///
    /// # Warning
    ///
    /// The logic in the `signature_builder` closure must exactly match the logic
    /// used on the client side in `sign_with`, otherwise verification will fail.
    /// Consider using `verify_structured` for safer, more maintainable code.
    ///
    /// # Arguments
    ///
    /// * `signature_builder`: A closure to reconstruct the signed data.
    pub async fn verify_with<F>(self, signature_builder: F) -> Result<(), NonceError>
    where
        F: FnOnce(&mut hmac::Hmac<sha2::Sha256>),
    {
        #[cfg(feature = "metrics")]
        let start_time = Instant::now();

        let secret = self.secret.ok_or_else(|| {
            NonceError::CryptoError("Secret key must be provided using with_secret()".to_string())
        })?;

        let result = async {
            self.server.verify_timestamp(self.credential.timestamp)?;
            NonceServer::<S>::verify_signature(
                secret,
                &self.credential.signature,
                signature_builder,
            )?;
            self.server
                .verify_and_consume_nonce(&self.credential.nonce, self.context)
                .await
        }
        .await;

        // Record metrics if enabled
        #[cfg(feature = "metrics")]
        {
            let duration = start_time.elapsed();
            let success = result.is_ok();
            let context = self.context.map(|s| s.to_string());

            let event = MetricEvent::VerificationAttempt {
                duration,
                success,
                context,
            };

            self.server.metrics_collector.record_event(event).await;

            // Record error if verification failed
            if let Err(ref error) = result {
                let error_event = MetricEvent::Error {
                    error_code: error.code(),
                    error_message: error.to_string(),
                    context: self.context.map(|s| s.to_string()),
                };
                self.server
                    .metrics_collector
                    .record_event(error_event)
                    .await;
            }
        }

        result
    }
}
