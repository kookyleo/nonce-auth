//! Performance tests for Redis storage backend
//!
//! These tests measure the performance characteristics of the optimized Redis storage
//! implementation and verify that optimizations provide expected improvements.
//!
//! Run with: cargo test --test performance --features redis-storage -- redis

use nonce_auth::NonceStorage;
#[cfg(feature = "redis-storage")]
use nonce_auth::storage::RedisStorage;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

const LARGE_DATASET_SIZE: usize = 10_000;
const MEDIUM_DATASET_SIZE: usize = 5_000;
const SMALL_DATASET_SIZE: usize = 1_000;

#[cfg(feature = "redis-storage")]
async fn get_test_storage() -> Option<Arc<RedisStorage>> {
    let redis_url = "redis://:passwd@localhost:6379";
    match RedisStorage::new(redis_url, "perf_test") {
        Ok(storage) => {
            let storage = Arc::new(storage);
            match storage.init().await {
                Ok(_) => {
                    // Clean up any existing test data
                    let _ = storage.cleanup_expired(9999999999).await;
                    Some(storage)
                }
                Err(_) => {
                    println!("Skipping Redis tests - no Redis server available");
                    None
                }
            }
        }
        Err(_) => {
            println!("Skipping Redis tests - cannot create Redis client");
            None
        }
    }
}

#[cfg(feature = "redis-storage")]
#[tokio::test]
async fn test_connection_pooling_performance() {
    let storage = match get_test_storage().await {
        Some(s) => s,
        None => return,
    };
    
    let dataset_size = MEDIUM_DATASET_SIZE;
    
    // Sequential operations (benefits from connection pooling)
    let start = Instant::now();
    for i in 0..dataset_size {
        storage.set(&format!("pool-test-{}", i), None, Duration::from_secs(60)).await.unwrap();
    }
    let pooled_time = start.elapsed();
    
    println!("Redis connection pooling test:");
    println!("  Sequential operations with pooling: {:?} ({:.0} ops/sec)", 
        pooled_time, dataset_size as f64 / pooled_time.as_secs_f64());
    
    // Should achieve good performance with connection pooling
    let ops_per_sec = dataset_size as f64 / pooled_time.as_secs_f64();
    assert!(ops_per_sec > 1_000.0, "Connection pooling should exceed 1k ops/sec");
    
    // Verify all operations succeeded
    let stats = storage.get_stats().await.unwrap();
    assert!(stats.total_records >= dataset_size);
    assert!(stats.backend_info.contains("persistent conn"));
}

#[cfg(feature = "redis-storage")]
#[tokio::test]
async fn test_scan_vs_keys_simulation() {
    let storage = match get_test_storage().await {
        Some(s) => s,
        None => return,
    };
    
    let dataset_size = LARGE_DATASET_SIZE;
    
    // Add many keys for testing SCAN performance
    println!("Populating {} entries for SCAN test...", dataset_size);
    let populate_start = Instant::now();
    for i in 0..dataset_size {
        storage.set(&format!("scan-test-{}", i), None, Duration::from_secs(300)).await.unwrap();
    }
    println!("Population completed in {:?}", populate_start.elapsed());
    
    // Test SCAN performance (via get_stats)
    let scan_start = Instant::now();
    let stats = storage.get_stats().await.unwrap();
    let scan_time = scan_start.elapsed();
    
    println!("Redis SCAN performance test:");
    println!("  SCAN operation found {} keys in {:?}", stats.total_records, scan_time);
    println!("  Keys/sec: {:.0}", stats.total_records as f64 / scan_time.as_secs_f64());
    
    // SCAN should be fast and non-blocking
    assert!(stats.total_records >= dataset_size);
    assert!(scan_time < Duration::from_millis(100), "SCAN should complete quickly");
    
    let scan_rate = stats.total_records as f64 / scan_time.as_secs_f64();
    assert!(scan_rate > 50_000.0, "SCAN should process at least 50k keys/sec");
}

#[cfg(feature = "redis-storage")]
#[tokio::test]
async fn test_batch_cleanup_performance() {
    let storage = match get_test_storage().await {
        Some(s) => s,
        None => return,
    };
    
    let dataset_size = LARGE_DATASET_SIZE;
    
    // Add test data
    println!("Populating {} entries for batch cleanup test...", dataset_size);
    for i in 0..dataset_size {
        storage.set(&format!("cleanup-test-{}", i), None, Duration::from_secs(300)).await.unwrap();
    }
    
    // Test batch cleanup performance
    let cleanup_start = Instant::now();
    let deleted = storage.cleanup_expired(9999999999).await.unwrap();
    let cleanup_time = cleanup_start.elapsed();
    
    println!("Redis batch cleanup test:");
    println!("  Cleaned up {} entries in {:?}", deleted, cleanup_time);
    println!("  Cleanup rate: {:.0} entries/sec", deleted as f64 / cleanup_time.as_secs_f64());
    
    assert!(deleted >= dataset_size);
    
    // Batch cleanup should be very efficient
    let cleanup_rate = deleted as f64 / cleanup_time.as_secs_f64();
    assert!(cleanup_rate > 10_000.0, "Batch cleanup should exceed 10k entries/sec");
}

#[cfg(feature = "redis-storage")]
#[tokio::test]
async fn test_concurrent_operations() {
    let storage = match get_test_storage().await {
        Some(s) => s,
        None => return,
    };
    
    let tasks = 10;
    let ops_per_task = SMALL_DATASET_SIZE;
    let total_ops = tasks * ops_per_task;
    
    // Concurrent writes
    let start = Instant::now();
    let mut write_tasks = JoinSet::new();
    
    for task_id in 0..tasks {
        let storage_clone = storage.clone();
        write_tasks.spawn(async move {
            for i in 0..ops_per_task {
                let nonce = format!("concurrent-{}-{}", task_id, i);
                storage_clone.set(&nonce, None, Duration::from_secs(60)).await.unwrap();
            }
        });
    }
    
    while let Some(_) = write_tasks.join_next().await {}
    let write_time = start.elapsed();
    
    // Concurrent reads
    let start = Instant::now();
    let mut read_tasks = JoinSet::new();
    
    for task_id in 0..tasks {
        let storage_clone = storage.clone();
        read_tasks.spawn(async move {
            for i in 0..ops_per_task {
                let nonce = format!("concurrent-{}-{}", task_id, i);
                let _ = storage_clone.get(&nonce, None).await.unwrap();
            }
        });
    }
    
    while let Some(_) = read_tasks.join_next().await {}
    let read_time = start.elapsed();
    
    println!("Redis concurrent operations test:");
    println!("  Concurrent writes ({} tasks × {} ops): {:?} ({:.0} ops/sec)", 
        tasks, ops_per_task, write_time, total_ops as f64 / write_time.as_secs_f64());
    println!("  Concurrent reads ({} tasks × {} ops): {:?} ({:.0} ops/sec)", 
        tasks, ops_per_task, read_time, total_ops as f64 / read_time.as_secs_f64());
    
    // Should handle concurrent operations well
    let write_ops_per_sec = total_ops as f64 / write_time.as_secs_f64();
    let read_ops_per_sec = total_ops as f64 / read_time.as_secs_f64();
    
    assert!(write_ops_per_sec > 1_000.0, "Concurrent writes should exceed 1k ops/sec");
    assert!(read_ops_per_sec > 3_000.0, "Concurrent reads should exceed 3k ops/sec");
}

#[cfg(feature = "redis-storage")]
#[tokio::test]
async fn test_ttl_handling() {
    let storage = match get_test_storage().await {
        Some(s) => s,
        None => return,
    };
    
    // Test minimum TTL handling (Redis minimum is 1 second)
    let start = Instant::now();
    for i in 0..100 {
        // All sub-second TTLs should be rounded up to 1 second
        storage.set(&format!("ttl-test-{}", i), None, Duration::from_millis(500)).await.unwrap();
    }
    let ttl_time = start.elapsed();
    
    println!("Redis TTL handling test:");
    println!("  Set 100 nonces with 500ms TTL: {:?}", ttl_time);
    
    // All should exist immediately
    for i in 0..100 {
        assert!(storage.exists(&format!("ttl-test-{}", i), None).await.unwrap());
    }
    
    // Wait for TTL to expire (should be rounded to 1 second)
    tokio::time::sleep(Duration::from_millis(1100)).await;
    
    // Should be expired now
    let mut expired_count = 0;
    for i in 0..100 {
        if !storage.exists(&format!("ttl-test-{}", i), None).await.unwrap() {
            expired_count += 1;
        }
    }
    
    println!("  Expired entries after 1.1s: {}/100", expired_count);
    
    // Most should be expired (some might still exist due to timing)
    assert!(expired_count > 50, "Most entries should expire after TTL");
}

#[cfg(feature = "redis-storage")]
#[tokio::test]
async fn test_memory_usage_reporting() {
    let storage = match get_test_storage().await {
        Some(s) => s,
        None => return,
    };
    
    // Add some data
    for i in 0..1000 {
        storage.set(&format!("memory-test-{}", i), None, Duration::from_secs(300)).await.unwrap();
    }
    
    let stats = storage.get_stats().await.unwrap();
    
    println!("Redis memory usage test:");
    println!("  {}", stats.backend_info);
    
    // Should report memory usage and persistent connection info
    assert!(stats.backend_info.contains("memory:"));
    assert!(stats.backend_info.contains("persistent conn"));
    assert!(stats.backend_info.contains("Redis"));
    assert_eq!(stats.total_records, 1000);
}

#[cfg(feature = "redis-storage")]
#[tokio::test]
async fn test_connection_resilience() {
    let storage = match get_test_storage().await {
        Some(s) => s,
        None => return,
    };
    
    // Perform many operations to test connection reuse and resilience
    let operations = 1000;
    let start = Instant::now();
    
    for i in 0..operations {
        let nonce = format!("resilience-test-{}", i);
        
        // Mix of operations
        match i % 3 {
            0 => {
                storage.set(&nonce, None, Duration::from_secs(60)).await.unwrap();
            }
            1 => {
                let _ = storage.get(&nonce, None).await.unwrap();
            }
            _ => {
                let _ = storage.exists(&nonce, None).await.unwrap();
            }
        }
    }
    
    let total_time = start.elapsed();
    
    println!("Redis connection resilience test:");
    println!("  {} mixed operations: {:?} ({:.0} ops/sec)", 
        operations, total_time, operations as f64 / total_time.as_secs_f64());
    
    // Should maintain good performance throughout
    let ops_per_sec = operations as f64 / total_time.as_secs_f64();
    assert!(ops_per_sec > 1_000.0, "Mixed operations should exceed 1k ops/sec");
}

#[cfg(feature = "redis-storage")]
#[tokio::test]
async fn test_duplicate_handling() {
    let storage = match get_test_storage().await {
        Some(s) => s,
        None => return,
    };
    
    let nonce = "duplicate-test-nonce";
    
    // First set should succeed
    let start = Instant::now();
    storage.set(nonce, None, Duration::from_secs(60)).await.unwrap();
    let first_time = start.elapsed();
    
    // Multiple duplicate attempts
    let duplicate_attempts = 100;
    let start = Instant::now();
    let mut errors = 0;
    
    for _ in 0..duplicate_attempts {
        if let Err(_) = storage.set(nonce, None, Duration::from_secs(60)).await {
            errors += 1;
        }
    }
    let duplicate_time = start.elapsed();
    
    println!("Redis duplicate handling test:");
    println!("  First set: {:?}", first_time);
    println!("  {} duplicate attempts: {:?} ({} errors)", 
        duplicate_attempts, duplicate_time, errors);
    
    // All duplicates should be rejected
    assert_eq!(errors, duplicate_attempts);
    
    // Duplicate detection should be fast
    let duplicate_ops_per_sec = duplicate_attempts as f64 / duplicate_time.as_secs_f64();
    assert!(duplicate_ops_per_sec > 5_000.0, "Duplicate detection should be fast");
}

#[cfg(feature = "redis-storage")]
#[tokio::test]
async fn test_context_isolation_performance() {
    let storage = match get_test_storage().await {
        Some(s) => s,
        None => return,
    };
    
    let contexts = vec!["ctx1", "ctx2", "ctx3", "ctx4", "ctx5"];
    let nonces_per_context = 200;
    
    // Set nonces across different contexts
    let start = Instant::now();
    for (ctx_idx, context) in contexts.iter().enumerate() {
        for i in 0..nonces_per_context {
            let nonce = format!("ctx-test-{}", i);
            storage.set(&nonce, Some(context), Duration::from_secs(60)).await.unwrap();
        }
    }
    let set_time = start.elapsed();
    
    // Read across contexts
    let start = Instant::now();
    for (ctx_idx, context) in contexts.iter().enumerate() {
        for i in 0..nonces_per_context {
            let nonce = format!("ctx-test-{}", i);
            let entry = storage.get(&nonce, Some(context)).await.unwrap();
            assert!(entry.is_some());
        }
    }
    let read_time = start.elapsed();
    
    let total_ops = contexts.len() * nonces_per_context;
    
    println!("Redis context isolation test:");
    println!("  Set {} nonces across {} contexts: {:?} ({:.0} ops/sec)", 
        total_ops, contexts.len(), set_time, total_ops as f64 / set_time.as_secs_f64());
    println!("  Read {} nonces across {} contexts: {:?} ({:.0} ops/sec)", 
        total_ops, contexts.len(), read_time, total_ops as f64 / read_time.as_secs_f64());
    
    // Should handle context isolation efficiently
    let set_ops_per_sec = total_ops as f64 / set_time.as_secs_f64();
    let read_ops_per_sec = total_ops as f64 / read_time.as_secs_f64();
    
    assert!(set_ops_per_sec > 800.0, "Context writes should exceed 800 ops/sec");
    assert!(read_ops_per_sec > 2_000.0, "Context reads should exceed 2k ops/sec");
}

#[cfg(not(feature = "redis-storage"))]
#[tokio::test]
async fn test_redis_feature_disabled() {
    println!("Redis storage tests skipped - redis-storage feature not enabled");
    println!("Run with: cargo test --features redis-storage");
}