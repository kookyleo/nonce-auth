use hmac::Mac;
use nonce_auth::nonce::NonceConfig;
use nonce_auth::{NonceClient, NonceServer};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Nonce Authentication with Optimized SQLite ===\n");

    // 1. Set environment for production configuration
    unsafe {
        std::env::set_var("NONCE_AUTH_PRESET", "production");
        // Override specific settings if needed
        std::env::set_var("NONCE_AUTH_CACHE_SIZE", "16384"); // 16MB for demo
    }

    // Configuration is automatically loaded from environment
    let config = NonceConfig::from_env();
    println!("Production Configuration (NONCE_AUTH_PRESET=production):");
    println!("{}\n", config.summary());

    // 2. Initialize the optimized database
    println!("Initializing optimized database...");
    NonceServer::init().await?;
    println!("✓ Database initialized with performance optimizations\n");

    // 3. Create server with custom settings
    let server = NonceServer::new(
        b"production_secret_key_12345",
        Some(Duration::from_secs(600)), // 10 minutes TTL
        Some(Duration::from_secs(120)), // 2 minutes time window
    );

    let client = NonceClient::new(b"production_secret_key_12345");

    // 4. Simulate high-load scenario
    println!("Simulating high-load authentication scenario...");

    let start = std::time::Instant::now();
    let mut successful_auths = 0;

    for i in 0..100 {
        // Create protection data
        let protection_data = client.create_protection_data(|mac, timestamp, nonce| {
            mac.update(timestamp.as_bytes());
            mac.update(nonce.as_bytes());
            mac.update(format!("request_{}", i).as_bytes());
        })?;

        // Verify protection data
        match server
            .verify_protection_data(&protection_data, Some("api_v1"), |mac| {
                mac.update(protection_data.timestamp.to_string().as_bytes());
                mac.update(protection_data.nonce.as_bytes());
                mac.update(format!("request_{}", i).as_bytes());
            })
            .await
        {
            Ok(()) => successful_auths += 1,
            Err(e) => println!("Authentication failed for request {}: {}", i, e),
        }

        // Simulate some processing time
        if i % 10 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    let duration = start.elapsed();
    println!("✓ Processed 100 authentication requests in {:?}", duration);
    println!("✓ Successful authentications: {}/100\n", successful_auths);

    // 5. Demonstrate cleanup performance
    println!("Testing cleanup performance...");
    let cleanup_start = std::time::Instant::now();
    let deleted_count = NonceServer::cleanup_expired_nonces(Duration::from_secs(1)).await?;
    let cleanup_duration = cleanup_start.elapsed();

    println!(
        "✓ Cleaned up {} expired nonces in {:?}\n",
        deleted_count, cleanup_duration
    );

    // 6. Test different configuration presets
    println!("=== Configuration Presets ===\n");

    // Development configuration
    let dev_config = NonceConfig::development();
    println!("Development Configuration:");
    println!("{}\n", dev_config.summary());

    // High-performance configuration
    let perf_config = NonceConfig::high_performance();
    println!("High-Performance Configuration:");
    println!("{}\n", perf_config.summary());

    // 7. Configuration validation
    println!("=== Configuration Validation ===\n");

    let configs = vec![
        ("Production", NonceConfig::production()),
        ("Development", NonceConfig::development()),
        ("High-Performance", NonceConfig::high_performance()),
    ];

    for (name, config) in configs {
        let issues = config.validate();
        if issues.is_empty() {
            println!("✓ {} configuration is valid", name);
        } else {
            println!("⚠ {} configuration has issues:", name);
            for issue in issues {
                println!("  - {}", issue);
            }
        }
    }

    println!("\n=== Performance Tips ===");
    println!("1. Use WAL mode for better concurrency (enabled by default)");
    println!("2. Adjust cache size based on available memory");
    println!("3. Use batch operations for bulk inserts");
    println!("4. Regular cleanup prevents database bloat");
    println!("5. Monitor database size and performance metrics");

    Ok(())
}
