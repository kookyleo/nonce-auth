# 配置指南

本文档为 `nonce-auth` 库中所有可用的配置选项提供了参考。

## 服务端配置

`NonceServer` 的配置通过构建器模式完成，允许自定义 TTL 和时间窗口。

```rust
use nonce_auth::NonceServer;
use std::time::Duration;

// 示例：自定义10分钟的 TTL 和 2分钟的时间窗口。
let server = NonceServer::builder(b"your-secret-key")
    .with_ttl(Duration::from_secs(600))         // 自定义 TTL
    .with_time_window(Duration::from_secs(120)) // 自定义时间窗口
    .build_and_init()
    .await?;
```

- **`default_ttl`**: `Option<Duration>`
  - **默认值**: `Some(Duration::from_secs(300))` (5 分钟)
  - **描述**: Nonce 在存储后端中的默认生存时间。超过此时长的 Nonce 将被视为过期。

- **`time_window`**: `Option<Duration>`
  - **默认值**: `Some(Duration::from_secs(60))` (1 分钟)
  - **描述**: 服务器时钟与传入凭证上的时间戳之间允许的最大时间差。

### 配置预设

库提供了针对常见使用场景的内置配置预设：

```rust
use nonce_auth::NonceConfig;

// 生产环境：5分钟 TTL，1分钟窗口 - 平衡安全性和可用性
let config = NonceConfig::production();

// 开发环境：10分钟 TTL，2分钟窗口 - 对开发者友好
let config = NonceConfig::development();

// 高安全性：2分钟 TTL，30秒窗口 - 最大安全性
let config = NonceConfig::high_security();

// 将配置应用到服务器
let server = NonceServer::builder(b"your-secret-key")
    .with_ttl(config.default_ttl)
    .with_time_window(config.time_window)
    .build_and_init()
    .await?;
```

### 环境变量

这些参数也可以通过环境变量进行配置。环境变量将作为构建器的默认值使用：

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

默认存储后端是 `MemoryStorage`，当您使用 `NonceServer::builder()` 创建服务器时会自动使用。这适用于测试、示例或不需要持久化的单实例应用。

```rust
use nonce_auth::NonceServer;

// 默认使用 MemoryStorage
let server = NonceServer::builder(b"your-secret-key")
    .build_and_init()
    .await?;
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
    # async fn init(&self) -> Result<(), NonceError> { Ok(()) }
}

// 使用构建器模式使用自定义存储
let server = NonceServer::builder(b"your-secret-key")
    .with_storage(Arc::new(MyCustomStorage))
    .build_and_init()
    .await?;
```
```