# 配置指南

本文档为 `nonce-auth` 库中所有可用的配置选项提供了参考。

## 服务端配置

`NonceServer` 的配置通过 `NonceServer::new` 函数完成，该函数接受可选的 `Duration` 值作为 TTL 和时间窗口。

```rust
use nonce_auth::{NonceServer, storage::MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

let storage = Arc::new(MemoryStorage::new());

// 示例：自定义10分钟的 TTL 和 2分钟的时间窗口。
let server = NonceServer::new(
    b"your-secret-key",
    storage,
    Some(Duration::from_secs(600)),  // 自定义 TTL
    Some(Duration::from_secs(120)),  // 自定义时间窗口
);
```

- **`default_ttl`**: `Option<Duration>`
  - **默认值**: `Some(Duration::from_secs(300))` (5 分钟)
  - **描述**: Nonce 在存储后端中的默认生存时间。超过此时长的 Nonce 将被视为过期。

- **`time_window`**: `Option<Duration>`
  - **默认值**: `Some(Duration::from_secs(60))` (1 分钟)
  - **描述**: 服务器时钟与传入凭证上的时间戳之间允许的最大时间差。

### 环境变量

这些参数也可以通过环境变量进行配置。如果在 `NonceServer::new` 中未提供值，则会使用环境变量。

- `NONCE_AUTH_DEFAULT_TTL`: 覆盖默认的 TTL (单位：秒)。
- `NONCE_AUTH_DEFAULT_TIME_WINDOW`: 覆盖默认的时间窗口 (单位：秒)。

```bash
# 示例：设置10分钟的 TTL 和 2分钟的时间窗口。
export NONCE_AUTH_DEFAULT_TTL=600
export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
```

## 存储后端配置

本库使用基于 trait 的存储系统。您可以使用内置的 `MemoryStorage` 或创建自己的实现。

### 内存存储 (默认)

适用于测试、示例或不需要持久化的单实例应用。

```rust
use nonce_auth::storage::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
```

### 自定义存储 (例如 SQLite, Redis)

您可以通过实现 `NonceStorage` trait 来创建自定义后端。这对于需要持久化存储或跨多实例分布的应用程序是必需的。

完整的参考实现，请参阅 [SQLite 示例](examples/sqlite_storage.rs)。

```rust
use async_trait::async_trait;
use nonce_auth::storage::{NonceStorage, NonceEntry, StorageStats};
use nonce_auth::NonceError;
use std::time::Duration;

pub struct MyCustomStorage; // 在此实现您的细节

#[async_trait]
impl NonceStorage for MyCustomStorage {
    // ... 实现所需的方法 ...
    # async fn get(&self, nonce: &str, context: Option<&str>) -> Result<Option<NonceEntry>, NonceError> { todo!() }
    # async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> { todo!() }
    # async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> { todo!() }
    # async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> { todo!() }
    # async fn get_stats(&self) -> Result<StorageStats, NonceError> { todo!() }
}
```