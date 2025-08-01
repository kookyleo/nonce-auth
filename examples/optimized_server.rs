use hmac::Mac;
use nonce_auth::nonce::NonceConfig;
use nonce_auth::{
    NonceClient, NonceServer,
    storage::{MemoryStorage, NonceStorage},
};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Nonce Authentication with Optimized Storage ===\n");

    // 1. Create different storage backends for demonstration
    let memory_storage = Arc::new(MemoryStorage::new());

    // 2. Configuration examples
    println!("=== Configuration Examples ===\n");

    let configs = vec![
        ("Production", NonceConfig::production()),
        ("Development", NonceConfig::development()),
        ("High-Security", NonceConfig::high_security()),
    ];

    for (name, config) in &configs {
        println!("{name} Configuration:");
        println!("{}", config.summary());

        let issues = config.validate();
        if issues.is_empty() {
            println!("✓ Configuration is valid\n");
        } else {
            println!("⚠ Configuration issues:");
            for issue in issues {
                println!("  - {issue}");
            }
            println!();
        }
    }

    // 3. Create server with production configuration
    let config = NonceConfig::production();
    let server = NonceServer::new(
        b"production_secret_key_12345",
        memory_storage.clone(),
        Some(config.default_ttl),
        Some(config.time_window),
    );

    // Initialize storage
    server.init().await?;

    let client = NonceClient::new(b"production_secret_key_12345");

    // 4. Simulate high-load scenario
    println!("=== High-Load Authentication Scenario ===\n");
    println!("Processing 100 authentication requests...");

    let start = std::time::Instant::now();
    let mut successful_auths = 0;

    for i in 0..100 {
        // Create a credential with additional payload
        let payload = format!("request_{i}").into_bytes();
        let credential = client.credential_builder().sign(&payload)?;

        // Verify the credential with context
        match server
            .credential_verifier(&credential)
            .with_context(Some("api_v1"))
            .verify_with(|mac| {
                mac.update(credential.timestamp.to_string().as_bytes());
                mac.update(credential.nonce.as_bytes());
                mac.update(&payload);
            })
            .await
        {
            Ok(()) => successful_auths += 1,
            Err(e) => println!("Authentication failed for request {i}: {e}"),
        }

        // Simulate some processing time
        if i % 20 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    let duration = start.elapsed();
    println!("✓ Processed 100 authentication requests in {duration:?}");
    println!("✓ Successful authentications: {successful_auths}/100\n");

    // 5. Storage statistics
    println!("=== Storage Statistics ===\n");
    let stats = server.storage().get_stats().await?;
    println!("Storage Backend: {}", stats.backend_info);
    println!("Total Records: {}", stats.total_records);
    println!();

    // 6. Demonstrate cleanup performance
    println!("=== Cleanup Performance ===\n");
    let cleanup_start = std::time::Instant::now();
    let deleted_count = server
        .cleanup_expired_nonces(Duration::from_secs(1))
        .await?;
    let cleanup_duration = cleanup_start.elapsed();

    println!("✓ Cleaned up {deleted_count} expired nonces in {cleanup_duration:?}");

    // Show updated stats
    let stats_after = server.storage().get_stats().await?;
    println!("✓ Records after cleanup: {}", stats_after.total_records);
    println!();

    // 7. Context isolation demonstration
    println!("=== Context Isolation Demonstration ===\n");

    let payload = b"context_payload";
    let credential = client.credential_builder().sign(payload)?;

    // Same nonce should work in different contexts
    let contexts = ["api_v1", "api_v2", "admin_panel"];
    for context in contexts {
        match server
            .credential_verifier(&credential)
            .with_context(Some(context))
            .verify(payload)
            .await
        {
            Ok(()) => println!("✓ Nonce accepted in context: {context}"),
            Err(e) => println!("❌ Nonce rejected in context {context}: {e}"),
        }
    }

    // Try to reuse in the same context (should fail)
    match server
        .credential_verifier(&credential)
        .with_context(Some("api_v1"))
        .verify(payload)
        .await
    {
        Ok(()) => println!("❌ This should not happen - nonce reuse detected"),
        Err(e) => println!("✓ Correctly rejected duplicate nonce in api_v1: {e}"),
    }

    println!();

    // 8. Server configuration info
    println!("=== Server Configuration ===\n");
    println!("TTL: {:?}", server.ttl());
    println!("Time Window: {:?}", server.time_window());
    println!();

    println!("=== Performance Tips ===");
    println!("1. Choose appropriate storage backend based on needs:");
    println!("   - MemoryStorage: Fast, but data lost on restart");
    println!("   - SQLite: Persistent, good for single-instance apps");
    println!("   - Redis: Distributed, good for multi-instance apps");
    println!("2. Adjust TTL based on security vs usability trade-offs");
    println!("3. Use context isolation for different API endpoints");
    println!("4. Regular cleanup prevents storage bloat");
    println!("5. Monitor storage statistics for performance insights");

    Ok(())
}
