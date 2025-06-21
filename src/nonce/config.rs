use std::time::Duration;

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
///     default_ttl: Duration::from_secs(600), // 10 minutes
///     time_window: Duration::from_secs(120), // 2 minutes
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NonceConfig {
    /// Default time-to-live for nonce records
    pub default_ttl: Duration,
    /// Time window for timestamp validation
    pub time_window: Duration,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(
                std::env::var("NONCE_AUTH_DEFAULT_TTL")
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
    /// Creates a new configuration from environment variables.
    ///
    /// # Returns
    ///
    /// A `NonceConfig` instance with environment variable values.
    ///
    /// # Example
    ///
    /// ```bash
    /// export NONCE_AUTH_DEFAULT_TTL=600
    /// export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
    /// ```
    pub fn from_env() -> Self {
        Self::default()
    }

    /// Creates a production-ready configuration.
    ///
    /// Production settings prioritize security and stability:
    /// - 5 minutes TTL (reasonable balance between security and usability)
    /// - 1 minute time window (accounts for network delays and clock skew)
    pub fn production() -> Self {
        Self {
            default_ttl: Duration::from_secs(300),
            time_window: Duration::from_secs(60),
        }
    }

    /// Creates a development configuration.
    ///
    /// Development settings prioritize convenience:
    /// - 10 minutes TTL (longer window for testing)
    /// - 2 minutes time window (more forgiving for local development)
    pub fn development() -> Self {
        Self {
            default_ttl: Duration::from_secs(600),
            time_window: Duration::from_secs(120),
        }
    }

    /// Creates a high-security configuration.
    ///
    /// High-security settings prioritize maximum security:
    /// - 2 minutes TTL (very short window to minimize exposure)
    /// - 30 seconds time window (strict timing requirements)
    pub fn high_security() -> Self {
        Self {
            default_ttl: Duration::from_secs(120),
            time_window: Duration::from_secs(30),
        }
    }

    /// Validates the configuration and returns any warnings.
    ///
    /// # Returns
    ///
    /// A vector of warning messages for potentially problematic settings.
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        // Check TTL settings
        if self.default_ttl.as_secs() < 60 {
            warnings.push("Very short TTL (< 1 minute) may cause usability issues".to_string());
        }
        if self.default_ttl.as_secs() > 3600 {
            warnings.push("Long TTL (> 1 hour) may increase security risk".to_string());
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

        // Check relationship between TTL and time window
        if self.default_ttl.as_secs() < self.time_window.as_secs() * 2 {
            warnings.push(
                "TTL should be at least twice the time window for optimal security".to_string(),
            );
        }

        warnings
    }

    /// Returns a summary of the current configuration.
    pub fn summary(&self) -> String {
        format!(
            "NonceConfig {{ TTL: {}s, Time Window: {}s }}",
            self.default_ttl.as_secs(),
            self.time_window.as_secs(),
        )
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
        let config = NonceConfig::production();
        assert_eq!(config.default_ttl.as_secs(), 300);
        assert_eq!(config.time_window.as_secs(), 60);
    }

    #[test]
    fn test_environment_variable_override() {
        // Test that custom config works without depending on environment
        let config = NonceConfig {
            default_ttl: Duration::from_secs(600),
            time_window: Duration::from_secs(120),
        };

        assert_eq!(config.default_ttl.as_secs(), 600);
        assert_eq!(config.time_window.as_secs(), 120);
    }

    #[test]
    fn test_production_preset() {
        let config = NonceConfig::production();
        assert_eq!(config.default_ttl.as_secs(), 300);
        assert_eq!(config.time_window.as_secs(), 60);
    }

    #[test]
    fn test_development_preset() {
        let config = NonceConfig::development();
        assert_eq!(config.default_ttl.as_secs(), 600);
        assert_eq!(config.time_window.as_secs(), 120);
    }

    #[test]
    fn test_high_security_preset() {
        let config = NonceConfig::high_security();
        assert_eq!(config.default_ttl.as_secs(), 120);
        assert_eq!(config.time_window.as_secs(), 30);
    }

    #[test]
    fn test_from_env() {
        clear_env_vars();

        unsafe {
            std::env::set_var("NONCE_AUTH_DEFAULT_TTL", "900");
            std::env::set_var("NONCE_AUTH_DEFAULT_TIME_WINDOW", "180");
        }

        let config = NonceConfig::from_env();
        assert_eq!(config.default_ttl.as_secs(), 900);
        assert_eq!(config.time_window.as_secs(), 180);

        clear_env_vars();
    }

    #[test]
    fn test_validation_valid_config() {
        let config = NonceConfig::production();
        let warnings = config.validate();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validation_ttl_warnings() {
        // Test very short TTL
        let config = NonceConfig {
            default_ttl: Duration::from_secs(30),
            time_window: Duration::from_secs(60),
        };
        let warnings = config.validate();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("Very short TTL")));

        // Test very long TTL
        let config = NonceConfig {
            default_ttl: Duration::from_secs(7200),
            time_window: Duration::from_secs(60),
        };
        let warnings = config.validate();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("Long TTL")));
    }

    #[test]
    fn test_validation_time_window_warnings() {
        // Test very short time window
        let config = NonceConfig {
            default_ttl: Duration::from_secs(300),
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
            default_ttl: Duration::from_secs(300),
            time_window: Duration::from_secs(600),
        };
        let warnings = config.validate();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("Long time window")));
    }

    #[test]
    fn test_validation_ttl_window_relationship() {
        let config = NonceConfig {
            default_ttl: Duration::from_secs(60),
            time_window: Duration::from_secs(60),
        };
        let warnings = config.validate();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("at least twice")));
    }

    #[test]
    fn test_summary_format() {
        let config = NonceConfig::production();
        let summary = config.summary();
        assert!(summary.contains("TTL: 300s"));
        assert!(summary.contains("Time Window: 60s"));
    }

    #[test]
    fn test_config_clone_and_debug() {
        let config = NonceConfig::production();
        let cloned = config.clone();
        assert_eq!(config.default_ttl, cloned.default_ttl);
        assert_eq!(config.time_window, cloned.time_window);

        // Test Debug implementation
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("NonceConfig"));
    }
}
