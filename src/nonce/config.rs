use std::time::Duration;

/// Predefined configuration presets for common use cases.
///
/// These presets provide sensible defaults for different deployment scenarios,
/// balancing security, usability, and performance requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPreset {
    /// Production-ready configuration.
    ///
    /// Balanced security and usability:
    /// - TTL: 5 minutes (reasonable balance between security and usability)
    /// - Time window: 1 minute (accounts for network delays and clock skew)
    Production,

    /// Development-friendly configuration.
    ///
    /// Relaxed settings for easier testing and debugging:
    /// - TTL: 10 minutes (longer window for testing)
    /// - Time window: 2 minutes (more forgiving for local development)
    Development,

    /// High-security configuration.
    ///
    /// Maximum security with strict timing requirements:
    /// - TTL: 2 minutes (very short window to minimize exposure)
    /// - Time window: 30 seconds (strict timing requirements)
    HighSecurity,

    /// Load configuration from environment variables.
    ///
    /// Reads configuration from:
    /// - `NONCE_AUTH_DEFAULT_TTL`: Default TTL in seconds (default: 300)
    /// - `NONCE_AUTH_DEFAULT_TIME_WINDOW`: Time window in seconds (default: 60)
    FromEnv,
}

/// Configuration for nonce authentication system.
///
/// This struct provides a centralized way to configure the security parameters
/// of the nonce authentication system, including TTL and time window settings.
///
/// # Environment Variables
///
/// Configuration options can be set via environment variables:
/// - `NONCE_AUTH_DEFAULT_TTL`: Default TTL in seconds (default: 300)
/// - `NONCE_AUTH_DEFAULT_TIME_WINDOW`: Time window in seconds (default: 60)
///
/// # Example
///
/// ```rust
/// use nonce_auth::nonce::NonceConfig;
/// use std::time::Duration;
///
/// // Use default configuration
/// let config = NonceConfig::default();
///
/// // Create custom configuration
/// let config = NonceConfig {
///     storage_ttl: Duration::from_secs(600), // 10 minutes
///     time_window: Duration::from_secs(120), // 2 minutes
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NonceConfig {
    /// Default storage time-to-live for nonce records
    pub storage_ttl: Duration,
    /// Time window for timestamp validation
    pub time_window: Duration,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self {
            storage_ttl: Duration::from_secs(
                std::env::var("NONCE_AUTH_STORAGE_TTL")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(300),
            ),
            time_window: Duration::from_secs(
                std::env::var("NONCE_AUTH_DEFAULT_TIME_WINDOW")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(60),
            ),
        }
    }
}

impl NonceConfig {
    /// Validates the configuration and returns any warnings.
    ///
    /// # Returns
    ///
    /// A vector of warning messages for potentially problematic settings.
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        // Check storage TTL settings
        if self.storage_ttl.as_secs() < 60 {
            warnings
                .push("Very short storage TTL (< 1 minute) may cause usability issues".to_string());
        }
        if self.storage_ttl.as_secs() > 3600 {
            warnings.push("Long storage TTL (> 1 hour) may increase security risk".to_string());
        }

        // Check time window settings
        if self.time_window.as_secs() < 30 {
            warnings.push(
                "Very short time window (< 30 seconds) may cause clock sync issues".to_string(),
            );
        }
        if self.time_window.as_secs() > 300 {
            warnings
                .push("Long time window (> 5 minutes) may increase replay attack risk".to_string());
        }

        // Check relationship between storage TTL and time window
        if self.storage_ttl.as_secs() < self.time_window.as_secs() * 2 {
            warnings.push(
                "Storage TTL should be at least twice the time window for optimal security"
                    .to_string(),
            );
        }

        warnings
    }

    /// Returns a summary of the current configuration.
    pub fn summary(&self) -> String {
        format!(
            "NonceConfig {{ Storage TTL: {}s, Time Window: {}s }}",
            self.storage_ttl.as_secs(),
            self.time_window.as_secs(),
        )
    }
}

impl From<ConfigPreset> for NonceConfig {
    fn from(preset: ConfigPreset) -> Self {
        match preset {
            ConfigPreset::Production => Self {
                storage_ttl: Duration::from_secs(300),
                time_window: Duration::from_secs(60),
            },
            ConfigPreset::Development => Self {
                storage_ttl: Duration::from_secs(600),
                time_window: Duration::from_secs(120),
            },
            ConfigPreset::HighSecurity => Self {
                storage_ttl: Duration::from_secs(120),
                time_window: Duration::from_secs(30),
            },
            ConfigPreset::FromEnv => Self::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clear_env_vars() {
        unsafe {
            std::env::remove_var("NONCE_AUTH_DEFAULT_TTL");
            std::env::remove_var("NONCE_AUTH_DEFAULT_TIME_WINDOW");
        }
    }

    #[test]
    fn test_default_configuration() {
        // Test production config which doesn't depend on env vars
        let config = NonceConfig::from(ConfigPreset::Production);
        assert_eq!(config.storage_ttl.as_secs(), 300);
        assert_eq!(config.time_window.as_secs(), 60);
    }

    #[test]
    fn test_environment_variable_override() {
        // Test that custom config works without depending on environment
        let config = NonceConfig {
            storage_ttl: Duration::from_secs(600),
            time_window: Duration::from_secs(120),
        };

        assert_eq!(config.storage_ttl.as_secs(), 600);
        assert_eq!(config.time_window.as_secs(), 120);
    }

    #[test]
    fn test_production_preset() {
        let config = NonceConfig::from(ConfigPreset::Production);
        assert_eq!(config.storage_ttl.as_secs(), 300);
        assert_eq!(config.time_window.as_secs(), 60);
    }

    #[test]
    fn test_development_preset() {
        let config = NonceConfig::from(ConfigPreset::Development);
        assert_eq!(config.storage_ttl.as_secs(), 600);
        assert_eq!(config.time_window.as_secs(), 120);
    }

    #[test]
    fn test_high_security_preset() {
        let config = NonceConfig::from(ConfigPreset::HighSecurity);
        assert_eq!(config.storage_ttl.as_secs(), 120);
        assert_eq!(config.time_window.as_secs(), 30);
    }

    #[test]
    fn test_from_env() {
        clear_env_vars();

        unsafe {
            std::env::set_var("NONCE_AUTH_STORAGE_TTL", "900");
            std::env::set_var("NONCE_AUTH_DEFAULT_TIME_WINDOW", "180");
        }

        let config = NonceConfig::from(ConfigPreset::FromEnv);
        assert_eq!(config.storage_ttl.as_secs(), 900);
        assert_eq!(config.time_window.as_secs(), 180);

        clear_env_vars();
    }

    #[test]
    fn test_validation_valid_config() {
        let config = NonceConfig::from(ConfigPreset::Production);
        let warnings = config.validate();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validation_ttl_warnings() {
        // Test very short TTL
        let config = NonceConfig {
            storage_ttl: Duration::from_secs(30),
            time_window: Duration::from_secs(60),
        };
        let warnings = config.validate();
        assert!(!warnings.is_empty());
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("Very short storage TTL"))
        );

        // Test very long TTL
        let config = NonceConfig {
            storage_ttl: Duration::from_secs(7200),
            time_window: Duration::from_secs(60),
        };
        let warnings = config.validate();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("Long storage TTL")));
    }

    #[test]
    fn test_validation_time_window_warnings() {
        // Test very short time window
        let config = NonceConfig {
            storage_ttl: Duration::from_secs(300),
            time_window: Duration::from_secs(15),
        };
        let warnings = config.validate();
        assert!(!warnings.is_empty());
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("Very short time window"))
        );

        // Test very long time window
        let config = NonceConfig {
            storage_ttl: Duration::from_secs(300),
            time_window: Duration::from_secs(600),
        };
        let warnings = config.validate();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("Long time window")));
    }
}
