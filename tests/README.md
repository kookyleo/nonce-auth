# Performance Tests

This directory contains comprehensive performance tests for all nonce-auth storage backends to ensure optimizations meet performance targets and provide expected improvements.

## Structure

- `integration_performance.rs` - Cross-backend comparison and regression detection
- `performance/` - Detailed per-backend performance tests
  - `memory_storage.rs` - Memory storage performance tests
  - `sqlite_storage.rs` - SQLite storage performance tests  
  - `redis_storage.rs` - Redis storage performance tests

## Running Tests

### All Performance Tests
```bash
cargo test --test integration_performance
```

### Memory Storage Performance
```bash
cargo test --test performance memory
```

### SQLite Storage Performance
```bash
cargo test --test performance --features sqlite-storage sqlite
```

### Redis Storage Performance
```bash
cargo test --test performance --features redis-storage redis
```

### All Features
```bash
cargo test --test integration_performance --all-features
```

## Performance Targets

### Memory Storage
- Sequential writes: >200k ops/sec
- Batch operations: >500k ops/sec
- Concurrent reads: >500k ops/sec
- Cleanup rate: >1M entries/sec

### SQLite Storage
- Sequential writes: >10k ops/sec  
- Cached reads: >50k ops/sec
- Concurrent operations: >1k ops/sec
- Cleanup rate: >100k entries/sec

### Redis Storage
- Sequential writes: >1k ops/sec
- Concurrent operations: >1k ops/sec
- SCAN operations: >50k keys/sec
- Cleanup rate: >10k entries/sec

## Optimizations Tested

### Memory Storage
- ✅ Capacity pre-allocation (~1.5x improvement)
- ✅ Batch operations (2-3x improvement)
- ✅ Accurate memory tracking
- ✅ Safe timestamp generation

### SQLite Storage  
- ✅ WAL mode for better concurrency
- ✅ Prepared statement caching
- ✅ Transaction-based batch operations
- ✅ PRAGMA optimizations

### Redis Storage
- ✅ Connection pooling (4x improvement)
- ✅ SCAN vs KEYS (non-blocking)
- ✅ Batch operations (27x improvement)
- ✅ Automatic reconnection

## Continuous Integration

These tests serve as:
- Performance regression detection
- Optimization validation
- Cross-platform performance verification
- Production readiness validation

Run these tests before releases to ensure performance standards are maintained.