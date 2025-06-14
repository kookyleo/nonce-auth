# Nonce-Auth Configuration and Optimization Guide

This document provides detailed information about all configuration options, SQLite optimization measures, and performance tuning methods for the nonce-auth library.

## Overview

nonce-auth provides a flexible configuration system that supports adjusting database performance, security parameters, and system behavior through environment variables, preset configurations, and programmatic configuration. With proper configuration and optimization, it can provide stable and efficient nonce authentication services under various load scenarios.

## Configuration Methods

### 1. Environment Variable Configuration

#### Preset Configuration Selection

Use `NONCE_AUTH_PRESET` to select a preset configuration:

```bash
# Select preset configuration (defaults to 'production')
export NONCE_AUTH_PRESET=production        # or 'development' or 'high_performance'
```

#### Individual Configuration Overrides

Individual environment variables override preset values:

```bash
# Database Configuration
export NONCE_AUTH_DB_PATH="nonce_auth.db"          # Database file path
export NONCE_AUTH_CACHE_SIZE=8192                  # Cache size (KB)
export NONCE_AUTH_WAL_MODE=true                    # WAL mode
export NONCE_AUTH_SYNC_MODE=NORMAL                 # Synchronization mode
export NONCE_AUTH_TEMP_STORE=MEMORY                # Temporary storage

# Performance Configuration
export NONCE_AUTH_CLEANUP_BATCH_SIZE=2000          # Cleanup batch size
export NONCE_AUTH_CLEANUP_THRESHOLD=500            # Optimization threshold

# Security Configuration
export NONCE_AUTH_DEFAULT_TTL=300                  # Default TTL (seconds)
export NONCE_AUTH_DEFAULT_TIME_WINDOW=60           # Time window (seconds)
```

#### Configuration Priority

The final configuration follows this priority order:
1. **Individual environment variables** (highest priority)
2. **Preset configuration** (selected by `NONCE_AUTH_PRESET`)
3. **Default values** (lowest priority)

**Example:**
```bash
# Use production preset with custom cache size
export NONCE_AUTH_PRESET=production
export NONCE_AUTH_CACHE_SIZE=16384      # Override preset cache size
```

### 2. Preset Configurations

#### Production Configuration
```bash
# Set environment for production preset
export NONCE_AUTH_PRESET=production

# Optional: Override specific settings
export NONCE_AUTH_CACHE_SIZE=16384  # 16MB cache for high load
```

```rust
use nonce_auth::NonceServer;

// Configuration is automatically loaded from environment
let server = NonceServer::new(b"your-secret-key", None, None);
```

**Features:**
- 8MB cache, balancing performance and memory usage
- WAL mode enabled for improved concurrent performance
- 2000 batch size for optimized cleanup performance
- 5-minute TTL, 1-minute time window

#### Development Configuration
```bash
# Set environment for development preset
export NONCE_AUTH_PRESET=development

# Optional: Override specific settings
export NONCE_AUTH_DB_PATH="test_nonce.db"  # Use file instead of memory
```

```rust
use nonce_auth::NonceServer;

// Configuration is automatically loaded from environment
let server = NonceServer::new(b"your-secret-key", None, None);
```

**Features:**
- In-memory database for fast testing
- 512KB cache to save memory
- WAL mode disabled for simplified debugging
- 1-minute TTL, 5-minute time window (relaxed)

#### High-Performance Configuration
```bash
# Set environment for high-performance preset
export NONCE_AUTH_PRESET=high_performance

# Optional: Override specific settings
export NONCE_AUTH_CACHE_SIZE=32768  # 32MB cache for maximum performance
```

```rust
use nonce_auth::NonceServer;

// Configuration is automatically loaded from environment
let server = NonceServer::new(b"your-secret-key", None, None);
```

**Features:**
- 16MB cache for maximum performance
- 5000 batch size to reduce transaction overhead
- 1000 optimization threshold for aggressive optimization

### 3. Programmatic Configuration

For advanced use cases, you can still create custom configurations:

```rust
use nonce_auth::NonceConfig;
use std::time::Duration;

// Create a custom configuration
let config = NonceConfig {
    db_path: "custom_nonce.db".to_string(),
    cache_size_kb: 4096,
    wal_mode: true,
    sync_mode: "NORMAL".to_string(),
    temp_store: "MEMORY".to_string(),
    cleanup_batch_size: 1500,
    cleanup_optimize_threshold: 300,
    default_ttl: Duration::from_secs(600),
    time_window: Duration::from_secs(120),
};

// Apply environment variable overrides if needed
let config = config.update_from_env();

// Use the configuration for inspection or validation
println!("Configuration: {}", config.summary());
let issues = config.validate();
if !issues.is_empty() {
    println!("Configuration issues: {:?}", issues);
}
```

**Note:** The library automatically uses `NonceConfig::from_env()` for database initialization, so programmatic configuration is mainly useful for inspection, validation, or testing purposes.

## Configuration Parameters

### Preset Configuration

#### `NONCE_AUTH_PRESET`
- **Type**: String
- **Default**: `"production"`
- **Options**: `production`, `development`, `high_performance`
- **Description**: Selects the preset configuration to use as a base

**Preset Comparison:**

| Setting | Production | Development | High Performance |
|---------|------------|-------------|------------------|
| Cache Size | 8MB | 512KB | 16MB |
| Database | File | Memory | File |
| WAL Mode | Enabled | Disabled | Enabled |
| Sync Mode | NORMAL | OFF | NORMAL |
| Batch Size | 2000 | 100 | 5000 |
| TTL | 5 min | 1 min | 5 min |
| Time Window | 1 min | 5 min | 1 min |

```bash
# Use development preset for testing
export NONCE_AUTH_PRESET=development

# Use high-performance preset for production with high load
export NONCE_AUTH_PRESET=high_performance
```

### Database Configuration

#### `NONCE_AUTH_DB_PATH`
- **Type**: String
- **Default**: `"nonce_auth.db"`
- **Description**: SQLite database file path
- **Special Values**: 
  - `:memory:` - In-memory database (for testing)
  - File path - Persistent storage

```bash
# Use in-memory database
export NONCE_AUTH_DB_PATH=":memory:"

# Use custom path
export NONCE_AUTH_DB_PATH="/var/lib/nonce_auth/nonce.db"
```

#### `NONCE_AUTH_CACHE_SIZE`
- **Type**: Integer (KB)
- **Default**: `2048` (2MB)
- **Range**: 64 - 32768 (64KB - 32MB)
- **Description**: SQLite page cache size

**Recommended Values:**
- Development: 512KB
- Production: 8MB
- High Load: 16MB

```bash
# Set 4MB cache
export NONCE_AUTH_CACHE_SIZE=4096
```

**Implementation Details:**
```rust
// Set cache size to 8MB
conn.pragma_update(None, "cache_size", -8192)?;
```

#### `NONCE_AUTH_WAL_MODE`
- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable Write-Ahead Logging mode

**Advantages:**
- Improved concurrent read/write performance
- Reduced lock contention
- Better crash recovery

**Notes:**
- Only applicable to file databases
- Automatically disabled for in-memory databases

```bash
# Enable WAL mode
export NONCE_AUTH_WAL_MODE=true

# Disable WAL mode
export NONCE_AUTH_WAL_MODE=false
```

**Implementation Details:**
```rust
// Enable WAL mode
conn.pragma_update(None, "journal_mode", "WAL")?;
```

#### `NONCE_AUTH_SYNC_MODE`
- **Type**: String
- **Default**: `"NORMAL"`
- **Options**: `OFF`, `NORMAL`, `FULL`
- **Description**: Data synchronization mode

**Mode Comparison:**
| Mode | Performance | Safety | Description |
|------|-------------|--------|-------------|
| OFF | Fastest | Lowest | May lose data |
| NORMAL | Balanced | Medium | Recommended for production |
| FULL | Slowest | Highest | Maximum data safety |

```bash
# Balanced mode (recommended)
export NONCE_AUTH_SYNC_MODE=NORMAL

# High-performance mode (higher risk)
export NONCE_AUTH_SYNC_MODE=OFF

# High-security mode (lower performance)
export NONCE_AUTH_SYNC_MODE=FULL
```

**Implementation Details:**
```rust
// Set synchronization mode
conn.pragma_update(None, "synchronous", "NORMAL")?;
```

#### `NONCE_AUTH_TEMP_STORE`
- **Type**: String
- **Default**: `"MEMORY"`
- **Options**: `MEMORY`, `FILE`
- **Description**: Temporary table and index storage location

```bash
# Memory storage (recommended)
export NONCE_AUTH_TEMP_STORE=MEMORY

# File storage
export NONCE_AUTH_TEMP_STORE=FILE
```

**Implementation Details:**
```rust
// Use memory temporary storage
conn.pragma_update(None, "temp_store", "MEMORY")?;
```

### Performance Configuration

#### `NONCE_AUTH_CLEANUP_BATCH_SIZE`
- **Type**: Integer
- **Default**: `1000`
- **Range**: 10 - 10000
- **Description**: Batch size for cleanup operations

**Impact:**
- Too small: Frequent transactions, poor performance
- Too large: Long transactions, may block

```bash
# High-performance setting
export NONCE_AUTH_CLEANUP_BATCH_SIZE=5000

# Conservative setting
export NONCE_AUTH_CLEANUP_BATCH_SIZE=500
```

**Implementation Details:**
```rust
// Batch deletion to avoid long transactions
let batch_size = 1000;
loop {
    let deleted = tx.execute(
        "DELETE FROM nonce_record WHERE id IN (
            SELECT id FROM nonce_record 
            WHERE created_at <= ? 
            LIMIT ?
        )",
        params![cutoff_time, batch_size],
    )?;
    
    if deleted < batch_size { break; }
}
```

#### `NONCE_AUTH_CLEANUP_THRESHOLD`
- **Type**: Integer
- **Default**: `100`
- **Description**: Threshold for triggering database optimization after deletions

```bash
# Aggressive optimization
export NONCE_AUTH_CLEANUP_THRESHOLD=50

# Conservative optimization
export NONCE_AUTH_CLEANUP_THRESHOLD=1000
```

### Security Configuration

#### `NONCE_AUTH_DEFAULT_TTL`
- **Type**: Integer (seconds)
- **Default**: `300` (5 minutes)
- **Range**: 30 - 86400 (30 seconds - 24 hours)
- **Description**: Default time-to-live for nonce records

**Recommended Values:**
- High security scenarios: 60-300 seconds
- General scenarios: 300-600 seconds
- Relaxed scenarios: 600-1800 seconds

```bash
# High security: 1 minute
export NONCE_AUTH_DEFAULT_TTL=60

# Standard: 5 minutes
export NONCE_AUTH_DEFAULT_TTL=300

# Relaxed: 10 minutes
export NONCE_AUTH_DEFAULT_TTL=600
```

#### `NONCE_AUTH_DEFAULT_TIME_WINDOW`
- **Type**: Integer (seconds)
- **Default**: `60` (1 minute)
- **Range**: 10 - 3600 (10 seconds - 1 hour)
- **Description**: Allowed deviation for timestamp validation

**Considerations:**
- Network latency
- Clock synchronization accuracy
- Security requirements

```bash
# Strict: 30 seconds
export NONCE_AUTH_DEFAULT_TIME_WINDOW=30

# Standard: 1 minute
export NONCE_AUTH_DEFAULT_TIME_WINDOW=60

# Relaxed: 2 minutes
export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
```

## SQLite Optimization Measures

### 1. Index Optimization

#### Composite Index Design
```sql
-- Primary query index (nonce existence check)
CREATE INDEX idx_nonce_context ON nonce_record (nonce, context);

-- Cleanup operation index
CREATE INDEX idx_created_at ON nonce_record (created_at);

-- Context-specific operation index
CREATE INDEX idx_context_created_at ON nonce_record (context, created_at);
```

#### Query Optimizer
```rust
// Analyze table structure to optimize query plans
conn.execute("ANALYZE", [])?;
```

### 2. Transactions and Batch Operations

#### Batch Insert
```rust
// Batch insert within transaction
let tx = conn.unchecked_transaction()?;
let mut stmt = tx.prepare("INSERT INTO nonce_record (nonce, created_at, context) VALUES (?, ?, ?)")?;

for (nonce, created_at, context) in nonces {
    stmt.execute(params![nonce, created_at, context])?;
}

tx.commit()?;
```

### 3. Connection Management

#### Singleton Pattern
```rust
// Global database instance to avoid frequent connections
lazy_static! {
    static ref DATABASE: Mutex<Option<Database>> = Mutex::new(None);
}
```

#### Thread Safety
```rust
// Arc<Mutex<Connection>> supports multi-threaded access
pub struct Database {
    connection: Arc<Mutex<Connection>>,
    config: DatabaseConfig,
}
```

## Configuration Validation

Use built-in validation to check configuration reasonableness:

```rust
use nonce_auth::nonce::NonceConfig;

let config = NonceConfig::default();
let issues = config.validate();

if !issues.is_empty() {
    for issue in issues {
        println!("Configuration issue: {}", issue);
    }
}
```

**Common Warnings:**
- Cache size too small/large
- TTL time too short/long
- Time window too strict/loose
- Unreasonable batch size

## Configuration Summary

View current configuration summary:

```rust
let config = NonceConfig::default();
println!("Current configuration:\n{}", config.summary());
```

Example output:
```
Nonce Authentication Configuration:
Database:
  Path: nonce_auth.db
  Cache Size: 8192 KB
  WAL Mode: true
  Sync Mode: NORMAL
  Temp Store: MEMORY

Performance:
  Cleanup Batch Size: 2000
  Optimize Threshold: 500

Security:
  Default TTL: 300 seconds
  Time Window: 60 seconds
```

## Scenario-Based Configuration Recommendations

### High-Concurrency Web Service
```bash
export NONCE_AUTH_CACHE_SIZE=16384
export NONCE_AUTH_WAL_MODE=true
export NONCE_AUTH_SYNC_MODE=NORMAL
export NONCE_AUTH_CLEANUP_BATCH_SIZE=5000
export NONCE_AUTH_DEFAULT_TTL=300
export NONCE_AUTH_DEFAULT_TIME_WINDOW=60
```

### Microservice Architecture
```bash
export NONCE_AUTH_CACHE_SIZE=4096
export NONCE_AUTH_WAL_MODE=true
export NONCE_AUTH_SYNC_MODE=NORMAL
export NONCE_AUTH_CLEANUP_BATCH_SIZE=2000
export NONCE_AUTH_DEFAULT_TTL=180
export NONCE_AUTH_DEFAULT_TIME_WINDOW=30
```

### Mobile Application Backend
```bash
export NONCE_AUTH_CACHE_SIZE=2048
export NONCE_AUTH_WAL_MODE=true
export NONCE_AUTH_SYNC_MODE=NORMAL
export NONCE_AUTH_CLEANUP_BATCH_SIZE=1000
export NONCE_AUTH_DEFAULT_TTL=600
export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
```

### Development and Testing
```bash
export NONCE_AUTH_DB_PATH=":memory:"
export NONCE_AUTH_CACHE_SIZE=512
export NONCE_AUTH_WAL_MODE=false
export NONCE_AUTH_SYNC_MODE=OFF
export NONCE_AUTH_CLEANUP_BATCH_SIZE=100
export NONCE_AUTH_DEFAULT_TTL=60
export NONCE_AUTH_DEFAULT_TIME_WINDOW=300
```

## Performance Test Results

### Benchmarks
- **100 authentication requests**: ~47ms
- **Cleanup operations**: ~145μs
- **Concurrent access**: Supports thread-safe multi-threaded access

### Configuration Comparison

| Configuration | Cache Size | WAL Mode | Sync Mode | Use Case |
|---------------|------------|----------|-----------|----------|
| Development | 512KB | Disabled | OFF | Testing, development |
| Production | 8MB | Enabled | NORMAL | Production deployment |
| High Performance | 16MB | Enabled | NORMAL | High-load scenarios |

## Performance Tuning Guide

### 1. Cache Size Tuning
- Monitor memory usage
- Adjust based on concurrency
- Avoid over-allocation

**Trade-off Considerations:**
- Too small: Poor performance
- Too large: High memory usage
- Recommendation: Adjust based on available memory

### 2. WAL Mode Optimization
- Recommended for production environments
- Monitor WAL file size
- Regular checkpoint operations

**Limitations:**
- Only applicable to file databases
- Automatically disabled for in-memory databases
- Requires file system support

### 3. Cleanup Strategy Optimization
- Adjust batch size based on load
- Monitor cleanup operation duration
- Avoid cleanup operations blocking business

**Batch Operation Considerations:**
- Avoid single large transactions
- Use appropriate batch sizes
- Commit transactions regularly

### 4. Security Parameter Balance
- TTL should not be too short (performance) or too long (security)
- Consider network environment for time window
- Regularly review security settings

## Best Practices

### 1. Choose Appropriate Configuration
```rust
// Choose configuration based on environment
let config = match env::var("ENVIRONMENT").as_deref() {
    Ok("production") => NonceConfig::production(),
    Ok("development") => NonceConfig::development(),
    _ => NonceConfig::default(),
};

unsafe { config.apply_env_vars(); }
```

### 2. Regular Cleanup
```rust
// Set up regular cleanup tasks
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        if let Err(e) = NonceServer::cleanup_expired_nonces(Duration::from_secs(300)).await {
            eprintln!("Cleanup failed: {}", e);
        }
    }
});
```

### 3. Monitor Database Status
```rust
// Get database statistics
let stats = db.get_stats()?;
println!("Database records: {}", stats.total_records);
println!("Database size: {} bytes", stats.database_size_bytes);
println!("Cache size: {} KB", stats.cache_size_kb);
```

### 4. Configuration Validation
```rust
// Validate configuration reasonableness
let issues = config.validate();
if !issues.is_empty() {
    for issue in issues {
        println!("Configuration issue: {}", issue);
    }
}
```

### 5. Environment Isolation
- Use different configurations for different environments
- Validate configuration before deployment
- Set up monitoring for key metrics
- Regularly review and update configurations
- Keep configuration documentation updated
- Test thoroughly before configuration changes

## Monitoring and Maintenance

### Key Metrics
- Database file size
- Cache hit rate
- Cleanup operation frequency
- Error rate and latency

### Maintenance Recommendations
- Regular database backups
- Monitor disk space
- Check configuration reasonableness
- Update security parameters

## Troubleshooting

### Common Issues

**1. Performance Issues**
- Check cache size settings
- Confirm WAL mode is enabled
- Adjust cleanup batch size

**2. High Memory Usage**
- Reduce cache size
- Check cleanup strategy
- Monitor concurrent connections

**3. Database Locking**
- Enable WAL mode
- Reduce transaction size
- Check concurrent access patterns

**4. Time-Related Errors**
- Check system time synchronization
- Adjust time window settings
- Verify network latency

### Debugging Tips

```rust
// Enable verbose logging
std::env::set_var("RUST_LOG", "nonce_auth=debug");

// Check configuration
let config = NonceConfig::default();
println!("Configuration summary: {}", config.summary());

// Validate configuration
let issues = config.validate();
for issue in issues {
    println!("Configuration warning: {}", issue);
}
```

## Future Optimization Directions

1. **Connection Pool**: Consider implementing connection pooling for higher concurrency
2. **Read-Write Separation**: For high read load scenarios
3. **Partitioned Tables**: For large data scenarios
4. **Compression**: Consider data compression to reduce storage space
5. **Monitoring**: Add performance monitoring and alerting

## Summary

Through the above configuration and optimization measures, the SQLite performance of the nonce-auth project has been significantly improved:

- ✅ **Cache Optimization**: Improved query performance
- ✅ **WAL Mode**: Enhanced concurrent performance
- ✅ **Index Optimization**: Accelerated query and cleanup operations
- ✅ **Batch Operations**: Reduced transaction overhead
- ✅ **Configuration Management**: Flexible environment adaptation
- ✅ **Monitoring Support**: Facilitates performance tuning

These optimizations ensure stable and efficient nonce authentication services under various load scenarios.

---

For more information, please refer to:
- [API Documentation](https://docs.rs/nonce-auth)
- [Example Code](examples/) 