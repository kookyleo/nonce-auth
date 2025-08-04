//! Redis storage usage example
//!
//! This example demonstrates how to use the optimized Redis storage backend
//! with connection pooling and batch operations.
//!
//! Run with: cargo run --example redis_example --features redis-storage

#[cfg(feature = "redis-storage")]
use nonce_auth::{NonceStorage, storage::RedisStorage};
#[cfg(feature = "redis-storage")]
use std::sync::Arc;
#[cfg(feature = "redis-storage")]
use std::time::Duration;

#[cfg(not(feature = "redis-storage"))]
fn main() {
    eprintln!("This example requires the redis-storage feature.");
    eprintln!("Run with: cargo run --example redis_example --features redis-storage");
}

#[cfg(feature = "redis-storage")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Redis Storage Example");
    println!("====================\n");

    // Connect to Redis with authentication
    let redis_url = "redis://:passwd@localhost:6379";
    let storage = Arc::new(RedisStorage::new(redis_url, "example")?);

    // Initialize the storage (this will test the connection)
    match storage.init().await {
        Ok(_) => println!("✅ Connected to Redis successfully!"),
        Err(e) => {
            eprintln!("❌ Failed to connect to Redis: {e}");
            eprintln!("   Make sure Redis is running on localhost:6379 with password 'passwd'");
            return Err(e.into());
        }
    }

    // Clean up any existing test data
    let _ = storage.cleanup_expired(9999999999).await;

    println!("\n1. Basic Operations");
    println!("------------------");

    // Store a nonce
    storage
        .set("example-nonce-1", None, Duration::from_secs(300))
        .await?;
    println!("✅ Stored nonce: example-nonce-1");

    // Store a nonce with context
    storage
        .set(
            "example-nonce-2",
            Some("user-auth"),
            Duration::from_secs(300),
        )
        .await?;
    println!("✅ Stored nonce with context: example-nonce-2 (user-auth)");

    // Check if nonces exist
    let exists1 = storage.exists("example-nonce-1", None).await?;
    let exists2 = storage.exists("example-nonce-2", Some("user-auth")).await?;
    println!("✅ Nonce 1 exists: {exists1}");
    println!("✅ Nonce 2 exists: {exists2}");

    // Retrieve nonces
    if let Some(entry) = storage.get("example-nonce-1", None).await? {
        println!(
            "✅ Retrieved nonce: {} (created at: {})",
            entry.nonce, entry.created_at
        );
    }

    // Try to store duplicate nonce
    match storage
        .set("example-nonce-1", None, Duration::from_secs(300))
        .await
    {
        Err(e) => println!("✅ Duplicate nonce correctly rejected: {e}"),
        Ok(_) => println!("❌ Duplicate nonce should have been rejected"),
    }

    println!("\n2. Context Isolation");
    println!("-------------------");

    // Same nonce in different contexts
    storage
        .set("shared-nonce", Some("context-1"), Duration::from_secs(300))
        .await?;
    storage
        .set("shared-nonce", Some("context-2"), Duration::from_secs(300))
        .await?;
    storage
        .set("shared-nonce", None, Duration::from_secs(300))
        .await?; // No context

    println!("✅ Stored same nonce in 3 different contexts");

    // Verify isolation
    let ctx1_exists = storage.exists("shared-nonce", Some("context-1")).await?;
    let ctx2_exists = storage.exists("shared-nonce", Some("context-2")).await?;
    let no_ctx_exists = storage.exists("shared-nonce", None).await?;
    let wrong_ctx_exists = storage.exists("shared-nonce", Some("context-3")).await?;

    println!("  Context-1: {ctx1_exists}");
    println!("  Context-2: {ctx2_exists}");
    println!("  No context: {no_ctx_exists}");
    println!("  Wrong context: {wrong_ctx_exists}");

    println!("\n3. Performance with Connection Pooling");
    println!("--------------------------------------");

    // Demonstrate fast sequential operations (benefits from connection pooling)
    let start = std::time::Instant::now();
    for i in 0..100 {
        storage
            .set(&format!("perf-test-{i}"), None, Duration::from_secs(60))
            .await?;
    }
    let elapsed = start.elapsed();

    println!("✅ 100 sequential operations completed in {elapsed:?}");
    println!(
        "   Average: {:.2}ms per operation",
        elapsed.as_millis() as f64 / 100.0
    );
    println!("   Rate: {:.0} ops/second", 100.0 / elapsed.as_secs_f64());

    println!("\n4. Concurrent Operations");
    println!("-----------------------");

    // Demonstrate concurrent operations
    let start = std::time::Instant::now();
    let mut tasks = tokio::task::JoinSet::new();

    for task_id in 0..5 {
        let storage_clone = storage.clone();
        tasks.spawn(async move {
            for i in 0..20 {
                let nonce = format!("concurrent-{task_id}-{i}");
                storage_clone
                    .set(&nonce, None, Duration::from_secs(60))
                    .await
                    .unwrap();
            }
        });
    }

    while (tasks.join_next().await).is_some() {}
    let elapsed = start.elapsed();

    println!(
        "✅ 100 concurrent operations (5 tasks × 20) completed in {elapsed:?}"
    );
    println!("   Rate: {:.0} ops/second", 100.0 / elapsed.as_secs_f64());

    println!("\n5. Storage Statistics");
    println!("--------------------");

    let stats = storage.get_stats().await?;
    println!("✅ Total records: {}", stats.total_records);
    println!("✅ Backend info: {}", stats.backend_info);

    println!("\n6. TTL Demonstration");
    println!("-------------------");

    // Store with short TTL
    storage
        .set("short-ttl-nonce", None, Duration::from_secs(2))
        .await?;
    println!("✅ Stored nonce with 2-second TTL");

    // Check immediately
    let exists_now = storage.exists("short-ttl-nonce", None).await?;
    println!("   Exists immediately: {exists_now}");

    // Wait and check again
    println!("   Waiting 3 seconds...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    let exists_after = storage.exists("short-ttl-nonce", None).await?;
    println!("   Exists after TTL: {exists_after}");

    println!("\n7. Cleanup Operations");
    println!("--------------------");

    // Use optimized batch cleanup
    let cleanup_start = std::time::Instant::now();
    let deleted = storage.cleanup_expired(9999999999).await?;
    let cleanup_elapsed = cleanup_start.elapsed();

    println!("✅ Cleaned up {deleted} entries in {cleanup_elapsed:?}");
    println!(
        "   Cleanup rate: {:.0} entries/second",
        deleted as f64 / cleanup_elapsed.as_secs_f64()
    );

    println!("\n✅ Redis storage example completed successfully!");
    println!("\nKey benefits of the optimized Redis storage:");
    println!("- Connection pooling for better performance");
    println!("- SCAN-based operations for production safety");
    println!("- Batch cleanup for efficient maintenance");
    println!("- Automatic TTL handling with 1-second minimum");
    println!("- Thread-safe concurrent access");

    Ok(())
}
