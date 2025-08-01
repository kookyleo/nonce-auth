use std::sync::Arc;
use std::time::Duration;

use crate::nonce::{NonceError, NonceServer};
use crate::storage::{MemoryStorage, NonceStorage};

/// A builder for creating a `NonceServer` instance.
///
/// This builder defaults to using `MemoryStorage` and allows for ergonomic
/// configuration of all server parameters.
#[must_use = "The builder does nothing unless `.build_and_init()` is called."]
pub struct NonceServerBuilder<S: NonceStorage> {
    secret: Vec<u8>,
    storage: Arc<S>,
    ttl: Option<Duration>,
    time_window: Option<Duration>,
}

impl NonceServerBuilder<MemoryStorage> {
    /// Creates a new builder with the required secret key.
    ///
    /// By default, this builder uses `MemoryStorage`. Use `.with_storage()` to
    /// provide a different storage backend.
    pub(crate) fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            storage: Arc::new(MemoryStorage::new()),
            ttl: None,
            time_window: None,
        }
    }
}

impl<S: NonceStorage> NonceServerBuilder<S> {
    /// Specifies a custom storage backend to use instead of the default `MemoryStorage`.
    pub fn with_storage<T: NonceStorage>(self, storage: Arc<T>) -> NonceServerBuilder<T> {
        NonceServerBuilder {
            secret: self.secret,
            storage,
            ttl: self.ttl,
            time_window: self.time_window,
        }
    }

    /// Sets a custom time-to-live (TTL) for nonces.
    ///
    /// If not set, defaults to 5 minutes.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sets a custom time window for timestamp validation.
    ///
    /// If not set, defaults to 1 minute.
    pub fn with_time_window(mut self, time_window: Duration) -> Self {
        self.time_window = Some(time_window);
        self
    }

    /// Builds and initializes the `NonceServer`.
    ///
    /// This method consumes the builder and returns a fully configured and initialized server.
    /// It automatically calls the storage backend's `init()` method.
    pub async fn build_and_init(self) -> Result<NonceServer<S>, NonceError> {
        let server = NonceServer::new(&self.secret, self.storage, self.ttl, self.time_window);
        server.init().await?;
        Ok(server)
    }
}
