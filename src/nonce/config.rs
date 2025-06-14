use std::time::Duration;

/// Comprehensive configuration for nonce authentication system.
///
/// This struct provides a centralized way to configure all aspects of the
/// nonce authentication system, including database settings, performance
/// tuning, and security parameters.
///
/// # Environment Variables
///
/// All configuration options can be set via environment variables:
///
/// ## Database Configuration
/// - `NONCE_AUTH_DB_PATH`: Database file path (default: "nonce_auth.db")
/// - `NONCE_AUTH_CACHE_SIZE`: SQLite cache size in KB (default: 2048)
/// - `NONCE_AUTH_WAL_MODE`: Enable WAL mode (default: true)
/// - `NONCE_AUTH_SYNC_MODE`: Synchronous mode NORMAL/FULL/OFF (default: NORMAL)
/// - `NONCE_AUTH_TEMP_STORE`: Temp storage MEMORY/FILE (default: MEMORY)
///
/// ## Performance Configuration
/// - `NONCE_AUTH_CLEANUP_BATCH_SIZE`: Cleanup batch size (default: 1000)
/// - `NONCE_AUTH_CLEANUP_THRESHOLD`: Auto-optimize threshold (default: 100)
///
/// ## Security Configuration
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
///     db_path: "custom_nonce.db".to_string(),
///     cache_size_kb: 4096, // 4MB cache
///     default_ttl: Duration::from_secs(600), // 10 minutes
///     time_window: Duration::from_secs(120), // 2 minutes
///     ..Default::default()
/// };
///
/// // Use config directly with Database::new(config)
/// ```
#[derive(Debug, Clone)]
pub struct NonceConfig {
    // Database configuration
    /// SQLite database file path
    pub db_path: String,
    /// SQLite cache size in KB
    pub cache_size_kb: i32,
    /// Enable WAL (Write-Ahead Logging) mode
    pub wal_mode: bool,
    /// Synchronous mode: OFF, NORMAL, FULL
    pub sync_mode: String,
    /// Temporary storage: MEMORY, FILE
    pub temp_store: String,
    
    // Performance configuration
    /// Batch size for cleanup operations
    pub cleanup_batch_size: usize,
    /// Threshold for triggering database optimization
    pub cleanup_optimize_threshold: usize,
    
    // Security configuration
    /// Default time-to-live for nonce records
    pub default_ttl: Duration,
    /// Time window for timestamp validation
    pub time_window: Duration,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self {
            // Database defaults
            db_path: std::env::var("NONCE_AUTH_DB_PATH")
                .unwrap_or_else(|_| "nonce_auth.db".to_string()),
            cache_size_kb: std::env::var("NONCE_AUTH_CACHE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2048),
            wal_mode: std::env::var("NONCE_AUTH_WAL_MODE")
                .map(|s| s.to_lowercase() != "false")
                .unwrap_or(true),
            sync_mode: std::env::var("NONCE_AUTH_SYNC_MODE")
                .unwrap_or_else(|_| "NORMAL".to_string()),
            temp_store: std::env::var("NONCE_AUTH_TEMP_STORE")
                .unwrap_or_else(|_| "MEMORY".to_string()),
            
            // Performance defaults
            cleanup_batch_size: std::env::var("NONCE_AUTH_CLEANUP_BATCH_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1000),
            cleanup_optimize_threshold: std::env::var("NONCE_AUTH_CLEANUP_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            
            // Security defaults
            default_ttl: Duration::from_secs(
                std::env::var("NONCE_AUTH_DEFAULT_TTL")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(300)
            ),
            time_window: Duration::from_secs(
                std::env::var("NONCE_AUTH_DEFAULT_TIME_WINDOW")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(60)
            ),
        }
    }
}

impl NonceConfig {
    /// Creates a new configuration from environment variables.
    ///
    /// This method first determines the preset configuration based on the
    /// `NONCE_AUTH_PRESET` environment variable, then applies individual
    /// environment variable overrides.
    ///
    /// # Environment Variables
    ///
    /// - `NONCE_AUTH_PRESET`: Preset configuration (`production`, `development`, `high_performance`)
    /// - Individual configuration variables override preset values
    ///
    /// # Returns
    ///
    /// A `NonceConfig` instance with preset and environment variable values.
    ///
    /// # Example
    ///
    /// ```bash
    /// # Use production preset with custom cache size
    /// export NONCE_AUTH_PRESET=production
    /// export NONCE_AUTH_CACHE_SIZE=16384
    /// ```
    pub fn from_env() -> Self {
        // Start with preset configuration based on NONCE_AUTH_PRESET
        let preset = std::env::var("NONCE_AUTH_PRESET")
            .unwrap_or_else(|_| "production".to_string());
        
        let mut config = match preset.to_lowercase().as_str() {
            "development" => Self::development(),
            "high_performance" => Self::high_performance(),
            _ => Self::production(), // Default to production
        };
        
        // Apply individual environment variable overrides
        if let Ok(db_path) = std::env::var("NONCE_AUTH_DB_PATH") {
            config.db_path = db_path;
        }
        
        if let Ok(cache_size) = std::env::var("NONCE_AUTH_CACHE_SIZE") {
            if let Ok(size) = cache_size.parse() {
                config.cache_size_kb = size;
            }
        }
        
        if let Ok(wal_mode) = std::env::var("NONCE_AUTH_WAL_MODE") {
            config.wal_mode = wal_mode.to_lowercase() != "false";
        }
        
        if let Ok(sync_mode) = std::env::var("NONCE_AUTH_SYNC_MODE") {
            config.sync_mode = sync_mode;
        }
        
        if let Ok(temp_store) = std::env::var("NONCE_AUTH_TEMP_STORE") {
            config.temp_store = temp_store;
        }
        
        if let Ok(batch_size) = std::env::var("NONCE_AUTH_CLEANUP_BATCH_SIZE") {
            if let Ok(size) = batch_size.parse() {
                config.cleanup_batch_size = size;
            }
        }
        
        if let Ok(threshold) = std::env::var("NONCE_AUTH_CLEANUP_THRESHOLD") {
            if let Ok(thresh) = threshold.parse() {
                config.cleanup_optimize_threshold = thresh;
            }
        }
        
        if let Ok(ttl) = std::env::var("NONCE_AUTH_DEFAULT_TTL") {
            if let Ok(secs) = ttl.parse() {
                config.default_ttl = Duration::from_secs(secs);
            }
        }
        
        if let Ok(window) = std::env::var("NONCE_AUTH_DEFAULT_TIME_WINDOW") {
            if let Ok(secs) = window.parse() {
                config.time_window = Duration::from_secs(secs);
            }
        }
        
        config
    }

    /// Updates this configuration with values from environment variables.
    ///
    /// Only updates fields where environment variables are set.
    /// This allows combining preset configurations with environment overrides.
    ///
    /// # Returns
    ///
    /// A new `NonceConfig` instance with environment variable overrides applied.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::nonce::NonceConfig;
    ///
    /// // Start with production preset, then apply environment overrides
    /// let config = NonceConfig::production().update_from_env();
    /// ```
    pub fn update_from_env(mut self) -> Self {
        // Only update if environment variable is set
        if let Ok(db_path) = std::env::var("NONCE_AUTH_DB_PATH") {
            self.db_path = db_path;
        }
        
        if let Ok(cache_size) = std::env::var("NONCE_AUTH_CACHE_SIZE") {
            if let Ok(size) = cache_size.parse() {
                self.cache_size_kb = size;
            }
        }
        
        if let Ok(wal_mode) = std::env::var("NONCE_AUTH_WAL_MODE") {
            self.wal_mode = wal_mode.to_lowercase() != "false";
        }
        
        if let Ok(sync_mode) = std::env::var("NONCE_AUTH_SYNC_MODE") {
            self.sync_mode = sync_mode;
        }
        
        if let Ok(temp_store) = std::env::var("NONCE_AUTH_TEMP_STORE") {
            self.temp_store = temp_store;
        }
        
        if let Ok(batch_size) = std::env::var("NONCE_AUTH_CLEANUP_BATCH_SIZE") {
            if let Ok(size) = batch_size.parse() {
                self.cleanup_batch_size = size;
            }
        }
        
        if let Ok(threshold) = std::env::var("NONCE_AUTH_CLEANUP_THRESHOLD") {
            if let Ok(thresh) = threshold.parse() {
                self.cleanup_optimize_threshold = thresh;
            }
        }
        
        if let Ok(ttl) = std::env::var("NONCE_AUTH_DEFAULT_TTL") {
            if let Ok(secs) = ttl.parse() {
                self.default_ttl = Duration::from_secs(secs);
            }
        }
        
        if let Ok(window) = std::env::var("NONCE_AUTH_DEFAULT_TIME_WINDOW") {
            if let Ok(secs) = window.parse() {
                self.time_window = Duration::from_secs(secs);
            }
        }
        
        self
    }

    /// Creates a new configuration with recommended production settings.
    ///
    /// This preset is optimized for production environments with:
    /// - Larger cache size for better performance
    /// - WAL mode enabled for concurrency
    /// - Balanced security settings
    /// - Optimized cleanup parameters
    ///
    /// # Returns
    ///
    /// A `NonceConfig` instance with production-optimized settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::nonce::NonceConfig;
    ///
    /// let config = NonceConfig::production();
    /// // Use config directly with Database::new(config)
    /// ```
    pub fn production() -> Self {
        Self {
            db_path: "nonce_auth.db".to_string(),
            cache_size_kb: 8192, // 8MB cache
            wal_mode: true,
            sync_mode: "NORMAL".to_string(),
            temp_store: "MEMORY".to_string(),
            cleanup_batch_size: 2000,
            cleanup_optimize_threshold: 500,
            default_ttl: Duration::from_secs(300), // 5 minutes
            time_window: Duration::from_secs(60),  // 1 minute
        }
    }
    
    /// Creates a new configuration optimized for development and testing.
    ///
    /// This preset uses:
    /// - In-memory database for faster tests
    /// - Smaller cache size to save memory
    /// - Shorter TTL for faster test cycles
    /// - Relaxed time window for development
    ///
    /// # Returns
    ///
    /// A `NonceConfig` instance with development-optimized settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::nonce::NonceConfig;
    ///
    /// let config = NonceConfig::development();
    /// // Use config directly with Database::new(config)
    /// ```
    pub fn development() -> Self {
        Self {
            db_path: ":memory:".to_string(),
            cache_size_kb: 512, // 512KB cache
            wal_mode: false, // Not needed for in-memory
            sync_mode: "OFF".to_string(), // Faster for development
            temp_store: "MEMORY".to_string(),
            cleanup_batch_size: 100,
            cleanup_optimize_threshold: 50,
            default_ttl: Duration::from_secs(60),  // 1 minute
            time_window: Duration::from_secs(300), // 5 minutes (relaxed)
        }
    }
    
    /// Creates a new configuration optimized for high-performance scenarios.
    ///
    /// This preset maximizes performance with:
    /// - Large cache size
    /// - Aggressive optimization settings
    /// - Larger batch sizes
    /// - Minimal synchronization overhead
    ///
    /// # Returns
    ///
    /// A `NonceConfig` instance with high-performance settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::nonce::NonceConfig;
    ///
    /// let config = NonceConfig::high_performance();
    /// // Use config directly with Database::new(config)
    /// ```
    pub fn high_performance() -> Self {
        Self {
            db_path: "nonce_auth.db".to_string(),
            cache_size_kb: 16384, // 16MB cache
            wal_mode: true,
            sync_mode: "NORMAL".to_string(),
            temp_store: "MEMORY".to_string(),
            cleanup_batch_size: 5000,
            cleanup_optimize_threshold: 1000,
            default_ttl: Duration::from_secs(300),
            time_window: Duration::from_secs(60),
        }
    }
    

    
    /// Validates the configuration and returns any issues found.
    ///
    /// This method checks for common configuration problems and
    /// returns a list of validation errors or warnings.
    ///
    /// # Returns
    ///
    /// A vector of validation messages. Empty if configuration is valid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::nonce::NonceConfig;
    ///
    /// let config = NonceConfig::default();
    /// let issues = config.validate();
    /// if !issues.is_empty() {
    ///     for issue in issues {
    ///         println!("Config issue: {}", issue);
    ///     }
    /// }
    /// ```
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        
        // Validate cache size
        if self.cache_size_kb < 64 {
            issues.push("Cache size is very small, consider increasing for better performance".to_string());
        }
        if self.cache_size_kb > 32768 {
            issues.push("Cache size is very large, may consume excessive memory".to_string());
        }
        
        // Validate sync mode
        if !["OFF", "NORMAL", "FULL"].contains(&self.sync_mode.as_str()) {
            issues.push(format!("Invalid sync_mode '{}', must be OFF, NORMAL, or FULL", self.sync_mode));
        }
        
        // Validate temp store
        if !["MEMORY", "FILE"].contains(&self.temp_store.as_str()) {
            issues.push(format!("Invalid temp_store '{}', must be MEMORY or FILE", self.temp_store));
        }
        
        // Validate TTL
        if self.default_ttl.as_secs() < 30 {
            issues.push("Default TTL is very short, may cause frequent cleanup overhead".to_string());
        }
        if self.default_ttl.as_secs() > 86400 {
            issues.push("Default TTL is very long, may cause database bloat".to_string());
        }
        
        // Validate time window
        if self.time_window.as_secs() < 10 {
            issues.push("Time window is very short, may cause legitimate requests to be rejected".to_string());
        }
        if self.time_window.as_secs() > 3600 {
            issues.push("Time window is very long, may reduce security against replay attacks".to_string());
        }
        
        // Validate batch sizes
        if self.cleanup_batch_size < 10 {
            issues.push("Cleanup batch size is very small, may cause performance issues".to_string());
        }
        if self.cleanup_batch_size > 10000 {
            issues.push("Cleanup batch size is very large, may cause long-running transactions".to_string());
        }
        
        issues
    }
    
    /// Returns a summary of the current configuration.
    ///
    /// This method provides a human-readable summary of all configuration
    /// settings, useful for logging and debugging.
    ///
    /// # Returns
    ///
    /// A formatted string describing the configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nonce_auth::nonce::NonceConfig;
    ///
    /// let config = NonceConfig::default();
    /// println!("Configuration:\n{}", config.summary());
    /// ```
    pub fn summary(&self) -> String {
        format!(
            "Nonce Authentication Configuration:
Database:
  Path: {}
  Cache Size: {} KB
  WAL Mode: {}
  Sync Mode: {}
  Temp Store: {}

Performance:
  Cleanup Batch Size: {}
  Optimize Threshold: {}

Security:
  Default TTL: {} seconds
  Time Window: {} seconds",
            self.db_path,
            self.cache_size_kb,
            self.wal_mode,
            self.sync_mode,
            self.temp_store,
            self.cleanup_batch_size,
            self.cleanup_optimize_threshold,
            self.default_ttl.as_secs(),
            self.time_window.as_secs()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use serial_test::serial;

    /// Helper function to clear all nonce auth environment variables
    fn clear_env_vars() {
        let vars = [
            "NONCE_AUTH_DB_PATH",
            "NONCE_AUTH_CACHE_SIZE",
            "NONCE_AUTH_WAL_MODE",
            "NONCE_AUTH_SYNC_MODE",
            "NONCE_AUTH_TEMP_STORE",
            "NONCE_AUTH_CLEANUP_BATCH_SIZE",
            "NONCE_AUTH_CLEANUP_THRESHOLD",
            "NONCE_AUTH_DEFAULT_TTL",
            "NONCE_AUTH_DEFAULT_TIME_WINDOW",
        ];
        
        for var in &vars {
            unsafe {
                env::remove_var(var);
            }
        }
    }

    #[test]
    #[serial]
    fn test_default_configuration() {
        // Save current environment
        let saved_vars: Vec<_> = [
            "NONCE_AUTH_DB_PATH",
            "NONCE_AUTH_CACHE_SIZE",
            "NONCE_AUTH_WAL_MODE",
            "NONCE_AUTH_SYNC_MODE",
            "NONCE_AUTH_TEMP_STORE",
            "NONCE_AUTH_CLEANUP_BATCH_SIZE",
            "NONCE_AUTH_CLEANUP_THRESHOLD",
            "NONCE_AUTH_DEFAULT_TTL",
            "NONCE_AUTH_DEFAULT_TIME_WINDOW",
        ].iter().map(|var| (*var, env::var(var).ok())).collect();
        
        clear_env_vars();
        
        let config = NonceConfig::default();
        
        // Test default values
        assert_eq!(config.db_path, "nonce_auth.db");
        assert_eq!(config.cache_size_kb, 2048);
        assert_eq!(config.wal_mode, true);
        assert_eq!(config.sync_mode, "NORMAL");
        assert_eq!(config.temp_store, "MEMORY");
        assert_eq!(config.cleanup_batch_size, 1000);
        assert_eq!(config.cleanup_optimize_threshold, 100);
        assert_eq!(config.default_ttl, Duration::from_secs(300));
        assert_eq!(config.time_window, Duration::from_secs(60));
        
        // Restore environment
        for (var, value) in saved_vars {
            match value {
                Some(val) => unsafe { env::set_var(var, val); },
                None => unsafe { env::remove_var(var); },
            }
        }
    }

    #[test]
    #[serial]
    fn test_environment_variable_override() {
        // Save current environment
        let saved_vars: Vec<_> = [
            "NONCE_AUTH_DB_PATH",
            "NONCE_AUTH_CACHE_SIZE",
            "NONCE_AUTH_WAL_MODE",
            "NONCE_AUTH_SYNC_MODE",
            "NONCE_AUTH_TEMP_STORE",
            "NONCE_AUTH_CLEANUP_BATCH_SIZE",
            "NONCE_AUTH_CLEANUP_THRESHOLD",
            "NONCE_AUTH_DEFAULT_TTL",
            "NONCE_AUTH_DEFAULT_TIME_WINDOW",
        ].iter().map(|var| (*var, env::var(var).ok())).collect();
        
        clear_env_vars();
        
        // Set environment variables
        unsafe {
            env::set_var("NONCE_AUTH_DB_PATH", "test.db");
            env::set_var("NONCE_AUTH_CACHE_SIZE", "4096");
            env::set_var("NONCE_AUTH_WAL_MODE", "false");
            env::set_var("NONCE_AUTH_SYNC_MODE", "FULL");
            env::set_var("NONCE_AUTH_TEMP_STORE", "FILE");
            env::set_var("NONCE_AUTH_CLEANUP_BATCH_SIZE", "2000");
            env::set_var("NONCE_AUTH_CLEANUP_THRESHOLD", "200");
            env::set_var("NONCE_AUTH_DEFAULT_TTL", "600");
            env::set_var("NONCE_AUTH_DEFAULT_TIME_WINDOW", "120");
        }
        
        let config = NonceConfig::default();
        
        // Test environment variable overrides
        assert_eq!(config.db_path, "test.db");
        assert_eq!(config.cache_size_kb, 4096);
        assert_eq!(config.wal_mode, false);
        assert_eq!(config.sync_mode, "FULL");
        assert_eq!(config.temp_store, "FILE");
        assert_eq!(config.cleanup_batch_size, 2000);
        assert_eq!(config.cleanup_optimize_threshold, 200);
        assert_eq!(config.default_ttl, Duration::from_secs(600));
        assert_eq!(config.time_window, Duration::from_secs(120));
        
        // Restore environment
        for (var, value) in saved_vars {
            match value {
                Some(val) => unsafe { env::set_var(var, val); },
                None => unsafe { env::remove_var(var); },
            }
        }
    }

    #[test]
    #[serial]
    fn test_wal_mode_parsing() {
        // Save current environment
        let saved_vars: Vec<_> = [
            "NONCE_AUTH_DB_PATH",
            "NONCE_AUTH_CACHE_SIZE",
            "NONCE_AUTH_WAL_MODE",
            "NONCE_AUTH_SYNC_MODE",
            "NONCE_AUTH_TEMP_STORE",
            "NONCE_AUTH_CLEANUP_BATCH_SIZE",
            "NONCE_AUTH_CLEANUP_THRESHOLD",
            "NONCE_AUTH_DEFAULT_TTL",
            "NONCE_AUTH_DEFAULT_TIME_WINDOW",
        ].iter().map(|var| (*var, env::var(var).ok())).collect();
        
        clear_env_vars();
        
        // Test various WAL mode values
        let test_cases = [
            ("true", true),
            ("TRUE", true),
            ("True", true),
            ("false", false),
            ("FALSE", false),
            ("False", false),
            ("0", true), // Non-"false" values should be true
            ("1", true),
            ("", true),
        ];
        
        for (env_value, expected) in &test_cases {
            unsafe {
                env::set_var("NONCE_AUTH_WAL_MODE", env_value);
            }
            let config = NonceConfig::default();
            assert_eq!(config.wal_mode, *expected, "Failed for WAL_MODE='{}'", env_value);
        }
        
        // Restore environment
        for (var, value) in saved_vars {
            match value {
                Some(val) => unsafe { env::set_var(var, val); },
                None => unsafe { env::remove_var(var); },
            }
        }
    }

    #[test]
    #[serial]
    fn test_invalid_numeric_env_vars() {
        // Save current environment
        let saved_vars: Vec<_> = [
            "NONCE_AUTH_DB_PATH",
            "NONCE_AUTH_CACHE_SIZE",
            "NONCE_AUTH_WAL_MODE",
            "NONCE_AUTH_SYNC_MODE",
            "NONCE_AUTH_TEMP_STORE",
            "NONCE_AUTH_CLEANUP_BATCH_SIZE",
            "NONCE_AUTH_CLEANUP_THRESHOLD",
            "NONCE_AUTH_DEFAULT_TTL",
            "NONCE_AUTH_DEFAULT_TIME_WINDOW",
        ].iter().map(|var| (*var, env::var(var).ok())).collect();
        
        clear_env_vars();
        
        // Test invalid numeric values fall back to defaults
        unsafe {
            env::set_var("NONCE_AUTH_CACHE_SIZE", "invalid");
            env::set_var("NONCE_AUTH_CLEANUP_BATCH_SIZE", "not_a_number");
            env::set_var("NONCE_AUTH_CLEANUP_THRESHOLD", "");
            env::set_var("NONCE_AUTH_DEFAULT_TTL", "abc");
            env::set_var("NONCE_AUTH_DEFAULT_TIME_WINDOW", "-1");
        }
        
        let config = NonceConfig::default();
        
        // Should fall back to defaults
        assert_eq!(config.cache_size_kb, 2048);
        assert_eq!(config.cleanup_batch_size, 1000);
        assert_eq!(config.cleanup_optimize_threshold, 100);
        assert_eq!(config.default_ttl, Duration::from_secs(300));
        assert_eq!(config.time_window, Duration::from_secs(60));
        
        // Restore environment
        for (var, value) in saved_vars {
            match value {
                Some(val) => unsafe { env::set_var(var, val); },
                None => unsafe { env::remove_var(var); },
            }
        }
    }

    #[test]
    fn test_production_preset() {
        let config = NonceConfig::production();
        
        assert_eq!(config.cache_size_kb, 8192);
        assert_eq!(config.wal_mode, true);
        assert_eq!(config.sync_mode, "NORMAL");
        assert_eq!(config.temp_store, "MEMORY");
        assert_eq!(config.cleanup_batch_size, 2000);
        assert_eq!(config.cleanup_optimize_threshold, 500);
        assert_eq!(config.default_ttl, Duration::from_secs(300));
        assert_eq!(config.time_window, Duration::from_secs(60));
    }

    #[test]
    fn test_development_preset() {
        let config = NonceConfig::development();
        
        assert_eq!(config.db_path, ":memory:");
        assert_eq!(config.cache_size_kb, 512);
        assert_eq!(config.wal_mode, false);
        assert_eq!(config.sync_mode, "OFF");
        assert_eq!(config.temp_store, "MEMORY");
        assert_eq!(config.cleanup_batch_size, 100);
        assert_eq!(config.cleanup_optimize_threshold, 50);
        assert_eq!(config.default_ttl, Duration::from_secs(60));
        assert_eq!(config.time_window, Duration::from_secs(300));
    }

    #[test]
    fn test_high_performance_preset() {
        let config = NonceConfig::high_performance();
        
        assert_eq!(config.cache_size_kb, 16384);
        assert_eq!(config.wal_mode, true);
        assert_eq!(config.sync_mode, "NORMAL");
        assert_eq!(config.temp_store, "MEMORY");
        assert_eq!(config.cleanup_batch_size, 5000);
        assert_eq!(config.cleanup_optimize_threshold, 1000);
        assert_eq!(config.default_ttl, Duration::from_secs(300));
        assert_eq!(config.time_window, Duration::from_secs(60));
    }

    #[test]
    #[serial]
    fn test_from_env() {
        // Save current environment
        let saved_vars: Vec<_> = [
            "NONCE_AUTH_DB_PATH",
            "NONCE_AUTH_CACHE_SIZE",
            "NONCE_AUTH_WAL_MODE",
            "NONCE_AUTH_SYNC_MODE",
            "NONCE_AUTH_TEMP_STORE",
            "NONCE_AUTH_CLEANUP_BATCH_SIZE",
            "NONCE_AUTH_CLEANUP_THRESHOLD",
            "NONCE_AUTH_DEFAULT_TTL",
            "NONCE_AUTH_DEFAULT_TIME_WINDOW",
        ].iter().map(|var| (*var, env::var(var).ok())).collect();
        
        clear_env_vars();
        
        // Set test environment variables
        unsafe {
            env::set_var("NONCE_AUTH_DB_PATH", "custom.db");
            env::set_var("NONCE_AUTH_CACHE_SIZE", "1024");
            env::set_var("NONCE_AUTH_WAL_MODE", "false");
            env::set_var("NONCE_AUTH_SYNC_MODE", "OFF");
            env::set_var("NONCE_AUTH_TEMP_STORE", "FILE");
            env::set_var("NONCE_AUTH_CLEANUP_BATCH_SIZE", "500");
            env::set_var("NONCE_AUTH_CLEANUP_THRESHOLD", "250");
            env::set_var("NONCE_AUTH_DEFAULT_TTL", "120");
            env::set_var("NONCE_AUTH_DEFAULT_TIME_WINDOW", "30");
        }
        
        let config = NonceConfig::from_env();
        
        // Verify configuration was read from environment
        assert_eq!(config.db_path, "custom.db");
        assert_eq!(config.cache_size_kb, 1024);
        assert_eq!(config.wal_mode, false);
        assert_eq!(config.sync_mode, "OFF");
        assert_eq!(config.temp_store, "FILE");
        assert_eq!(config.cleanup_batch_size, 500);
        assert_eq!(config.cleanup_optimize_threshold, 250);
        assert_eq!(config.default_ttl, Duration::from_secs(120));
        assert_eq!(config.time_window, Duration::from_secs(30));
        
        // Restore environment
        for (var, value) in saved_vars {
            match value {
                Some(val) => unsafe { env::set_var(var, val); },
                None => unsafe { env::remove_var(var); },
            }
        }
    }

    #[test]
    fn test_validation_valid_config() {
        let config = NonceConfig::production();
        let issues = config.validate();
        assert!(issues.is_empty(), "Production config should be valid");
    }

    #[test]
    fn test_validation_cache_size_warnings() {
        // Test very small cache size
        let config = NonceConfig {
            cache_size_kb: 32,
            ..NonceConfig::default()
        };
        let issues = config.validate();
        assert!(issues.iter().any(|issue| issue.contains("Cache size is very small")));
        
        // Test very large cache size
        let config = NonceConfig {
            cache_size_kb: 50000,
            ..NonceConfig::default()
        };
        let issues = config.validate();
        assert!(issues.iter().any(|issue| issue.contains("Cache size is very large")));
    }

    #[test]
    fn test_validation_invalid_sync_mode() {
        let config = NonceConfig {
            sync_mode: "INVALID".to_string(),
            ..NonceConfig::default()
        };
        let issues = config.validate();
        assert!(issues.iter().any(|issue| issue.contains("Invalid sync_mode")));
    }

    #[test]
    fn test_validation_invalid_temp_store() {
        let config = NonceConfig {
            temp_store: "INVALID".to_string(),
            ..NonceConfig::default()
        };
        let issues = config.validate();
        assert!(issues.iter().any(|issue| issue.contains("Invalid temp_store")));
    }

    #[test]
    fn test_validation_ttl_warnings() {
        // Test very short TTL
        let config = NonceConfig {
            default_ttl: Duration::from_secs(10),
            ..NonceConfig::default()
        };
        let issues = config.validate();
        assert!(issues.iter().any(|issue| issue.contains("Default TTL is very short")));
        
        // Test very long TTL
        let config = NonceConfig {
            default_ttl: Duration::from_secs(100000),
            ..NonceConfig::default()
        };
        let issues = config.validate();
        assert!(issues.iter().any(|issue| issue.contains("Default TTL is very long")));
    }

    #[test]
    fn test_validation_time_window_warnings() {
        // Test very short time window
        let config = NonceConfig {
            time_window: Duration::from_secs(5),
            ..NonceConfig::default()
        };
        let issues = config.validate();
        assert!(issues.iter().any(|issue| issue.contains("Time window is very short")));
        
        // Test very long time window
        let config = NonceConfig {
            time_window: Duration::from_secs(5000),
            ..NonceConfig::default()
        };
        let issues = config.validate();
        assert!(issues.iter().any(|issue| issue.contains("Time window is very long")));
    }

    #[test]
    fn test_validation_batch_size_warnings() {
        // Test very small batch size
        let config = NonceConfig {
            cleanup_batch_size: 5,
            ..NonceConfig::default()
        };
        let issues = config.validate();
        assert!(issues.iter().any(|issue| issue.contains("Cleanup batch size is very small")));
        
        // Test very large batch size
        let config = NonceConfig {
            cleanup_batch_size: 20000,
            ..NonceConfig::default()
        };
        let issues = config.validate();
        assert!(issues.iter().any(|issue| issue.contains("Cleanup batch size is very large")));
    }

    #[test]
    fn test_summary_format() {
        let config = NonceConfig::default();
        let summary = config.summary();
        
        // Check that summary contains key information
        assert!(summary.contains("Nonce Authentication Configuration"));
        assert!(summary.contains("Database:"));
        assert!(summary.contains("Performance:"));
        assert!(summary.contains("Security:"));
        assert!(summary.contains(&config.db_path));
        assert!(summary.contains(&config.cache_size_kb.to_string()));
        assert!(summary.contains(&config.sync_mode));
        assert!(summary.contains(&config.cleanup_batch_size.to_string()));
        assert!(summary.contains(&config.default_ttl.as_secs().to_string()));
    }

    #[test]
    fn test_config_clone_and_debug() {
        let config = NonceConfig::default();
        
        // Test Clone trait
        let cloned_config = config.clone();
        assert_eq!(config.db_path, cloned_config.db_path);
        assert_eq!(config.cache_size_kb, cloned_config.cache_size_kb);
        
        // Test Debug trait
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("NonceConfig"));
        assert!(debug_str.contains("db_path"));
    }

    #[test]
    fn test_custom_configuration() {
        let config = NonceConfig {
            db_path: "custom_path.db".to_string(),
            cache_size_kb: 4096,
            wal_mode: false,
            sync_mode: "FULL".to_string(),
            temp_store: "FILE".to_string(),
            cleanup_batch_size: 1500,
            cleanup_optimize_threshold: 300,
            default_ttl: Duration::from_secs(600),
            time_window: Duration::from_secs(120),
        };
        
        assert_eq!(config.db_path, "custom_path.db");
        assert_eq!(config.cache_size_kb, 4096);
        assert_eq!(config.wal_mode, false);
        assert_eq!(config.sync_mode, "FULL");
        assert_eq!(config.temp_store, "FILE");
        assert_eq!(config.cleanup_batch_size, 1500);
        assert_eq!(config.cleanup_optimize_threshold, 300);
        assert_eq!(config.default_ttl, Duration::from_secs(600));
        assert_eq!(config.time_window, Duration::from_secs(120));
    }

    #[test]
    #[serial]
    fn test_preset_independence() {
        // Save current environment
        let saved_vars: Vec<_> = [
            "NONCE_AUTH_DB_PATH",
            "NONCE_AUTH_CACHE_SIZE",
            "NONCE_AUTH_WAL_MODE",
            "NONCE_AUTH_SYNC_MODE",
            "NONCE_AUTH_TEMP_STORE",
            "NONCE_AUTH_CLEANUP_BATCH_SIZE",
            "NONCE_AUTH_CLEANUP_THRESHOLD",
            "NONCE_AUTH_DEFAULT_TTL",
            "NONCE_AUTH_DEFAULT_TIME_WINDOW",
        ].iter().map(|var| (*var, env::var(var).ok())).collect();
        
        clear_env_vars();
        
        // Set environment variables that would affect Default::default()
        unsafe {
            env::set_var("NONCE_AUTH_DB_PATH", "env_override.db");
            env::set_var("NONCE_AUTH_CACHE_SIZE", "1024");
        }
        
        // Preset configurations should NOT be affected by environment variables
        let production_config = NonceConfig::production();
        assert_eq!(production_config.db_path, "nonce_auth.db"); // Not env_override.db
        assert_eq!(production_config.cache_size_kb, 8192); // Not 1024
        assert_eq!(production_config.cleanup_batch_size, 2000);
        
        let dev_config = NonceConfig::development();
        assert_eq!(dev_config.db_path, ":memory:"); // Not env_override.db
        assert_eq!(dev_config.cache_size_kb, 512); // Not 1024
        
        let perf_config = NonceConfig::high_performance();
        assert_eq!(perf_config.db_path, "nonce_auth.db"); // Not env_override.db
        assert_eq!(perf_config.cache_size_kb, 16384); // Not 1024
        
        // But from_env() should use environment variables
        let env_config = NonceConfig::from_env();
        assert_eq!(env_config.db_path, "env_override.db");
        assert_eq!(env_config.cache_size_kb, 1024);
        
        // Restore environment
        for (var, value) in saved_vars {
            match value {
                Some(val) => unsafe { env::set_var(var, val); },
                None => unsafe { env::remove_var(var); },
            }
        }
    }

    #[test]
    #[serial]
    fn test_env_preset_selection() {
        // Save current environment
        let saved_env = env::var("NONCE_AUTH_PRESET").ok();
        
        // Test production preset (default)
        unsafe {
            env::remove_var("NONCE_AUTH_PRESET");
        }
        let config = NonceConfig::from_env();
        let prod_config = NonceConfig::production();
        assert_eq!(config.cache_size_kb, prod_config.cache_size_kb);
        assert_eq!(config.cleanup_batch_size, prod_config.cleanup_batch_size);
        
        // Test development preset
        unsafe {
            env::set_var("NONCE_AUTH_PRESET", "development");
        }
        let config = NonceConfig::from_env();
        let dev_config = NonceConfig::development();
        assert_eq!(config.cache_size_kb, dev_config.cache_size_kb);
        assert_eq!(config.db_path, dev_config.db_path);
        
        // Test high_performance preset
        unsafe {
            env::set_var("NONCE_AUTH_PRESET", "high_performance");
        }
        let config = NonceConfig::from_env();
        let hp_config = NonceConfig::high_performance();
        assert_eq!(config.cache_size_kb, hp_config.cache_size_kb);
        assert_eq!(config.cleanup_batch_size, hp_config.cleanup_batch_size);
        
        // Test invalid preset defaults to production
        unsafe {
            env::set_var("NONCE_AUTH_PRESET", "invalid");
        }
        let config = NonceConfig::from_env();
        let prod_config = NonceConfig::production();
        assert_eq!(config.cache_size_kb, prod_config.cache_size_kb);
        
        // Restore environment
        match saved_env {
            Some(val) => unsafe { env::set_var("NONCE_AUTH_PRESET", val); },
            None => unsafe { env::remove_var("NONCE_AUTH_PRESET"); },
        }
    }

    #[test]
    #[serial]
    fn test_env_override_preset() {
        // Save current environment
        let saved_vars: Vec<_> = [
            "NONCE_AUTH_PRESET",
            "NONCE_AUTH_CACHE_SIZE",
            "NONCE_AUTH_DB_PATH",
        ].iter().map(|var| (*var, env::var(var).ok())).collect();
        
        // Test that individual environment variables override preset values
        unsafe {
            env::set_var("NONCE_AUTH_PRESET", "production");
            env::set_var("NONCE_AUTH_CACHE_SIZE", "12345");
            env::set_var("NONCE_AUTH_DB_PATH", "custom_test.db");
        }
        
        let config = NonceConfig::from_env();
        let prod_config = NonceConfig::production();
        
        // Overridden values should be different from preset
        assert_eq!(config.cache_size_kb, 12345);
        assert_eq!(config.db_path, "custom_test.db");
        
        // Non-overridden values should match preset
        assert_eq!(config.cleanup_batch_size, prod_config.cleanup_batch_size);
        assert_eq!(config.wal_mode, prod_config.wal_mode);
        
        // Restore environment
        for (var, value) in saved_vars {
            match value {
                Some(val) => unsafe { env::set_var(var, val); },
                None => unsafe { env::remove_var(var); },
            }
        }
    }
} 