# Nonce-Auth 配置指南

本文档详细说明了如何配置 nonce-auth 库的可插拔存储后端。

## 概览

nonce-auth 提供了灵活的配置系统，支持通过环境变量和程序化配置来调整安全参数。该库使用基于 trait 的存储抽象，允许您根据需要插入不同的存储后端（内存、SQLite、Redis 等）。

## 配置方式

### 1. 环境变量配置

库支持通过环境变量配置安全参数：

```bash
# 安全配置
export NONCE_AUTH_DEFAULT_TTL=300                  # 默认 TTL (秒)
export NONCE_AUTH_DEFAULT_TIME_WINDOW=60           # 时间窗口 (秒)
```

### 2. 程序化配置

通过编程方式创建自定义配置：

```rust
use nonce_auth::{NonceServer, storage::MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

// 创建存储后端
let storage = Arc::new(MemoryStorage::new());

// 创建带自定义配置的服务器
let server = NonceServer::new(
    b"your-secret-key",
    storage,
    Some(Duration::from_secs(600)),  // 自定义 TTL
    Some(Duration::from_secs(120)),  // 自定义时间窗口
);

// 初始化服务器
server.init().await?;
```

## 配置参数

### 安全配置

#### `NONCE_AUTH_DEFAULT_TTL`
- **类型**: 整数 (秒)
- **默认值**: `300` (5分钟)
- **范围**: 30 - 86400 (30秒 - 24小时)
- **说明**: nonce 记录的默认生存时间

**推荐值：**
- 高安全场景: 60-300 秒
- 一般场景: 300-600 秒
- 宽松场景: 600-1800 秒

```bash
# 高安全：1分钟
export NONCE_AUTH_DEFAULT_TTL=60

# 标准：5分钟
export NONCE_AUTH_DEFAULT_TTL=300

# 宽松：10分钟
export NONCE_AUTH_DEFAULT_TTL=600
```

#### `NONCE_AUTH_DEFAULT_TIME_WINDOW`
- **类型**: 整数 (秒)
- **默认值**: `60` (1分钟)
- **范围**: 10 - 3600 (10秒 - 1小时)
- **说明**: 时间戳验证的允许偏差

**考虑因素：**
- 网络延迟
- 时钟同步精度
- 安全要求

```bash
# 严格：30秒
export NONCE_AUTH_DEFAULT_TIME_WINDOW=30

# 标准：1分钟
export NONCE_AUTH_DEFAULT_TIME_WINDOW=60

# 宽松：2分钟
export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
```

## 存储后端配置

### 内置存储后端

#### 内存存储（默认）
```rust
use nonce_auth::storage::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
```

**特点：**
- 使用 HashMap 的快速内存存储
- 适用于单实例应用
- 重启时不保留数据
- 使用 Arc<Mutex<HashMap>> 保证线程安全

#### 自定义存储后端

您可以通过实现 `NonceStorage` trait 来实现自己的存储后端：

```rust
use async_trait::async_trait;
use nonce_auth::storage::{NonceStorage, NonceEntry, StorageStats};
use nonce_auth::NonceError;
use std::time::Duration;

pub struct MyCustomStorage {
    // 您的存储实现
}

#[async_trait]
impl NonceStorage for MyCustomStorage {
    async fn init(&self) -> Result<(), NonceError> {
        // 初始化您的存储
        Ok(())
    }

    async fn get(&self, nonce: &str, context: Option<&str>) -> Result<Option<NonceEntry>, NonceError> {
        // 实现获取逻辑
        unimplemented!()
    }

    async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> {
        // 实现设置逻辑
        unimplemented!()
    }

    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
        // 实现存在性检查逻辑
        unimplemented!()
    }

    async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
        // 实现过期清理逻辑
        unimplemented!()
    }

    async fn get_stats(&self) -> Result<StorageStats, NonceError> {
        // 实现统计逻辑
        unimplemented!()
    }
}
```

### 存储实现示例

库包含了不同存储后端的示例实现：

- **SQLite 存储**: 参考 `examples/sqlite_storage.rs` 获取完整的 SQLite 实现
- **内存存储**: 用于测试和单实例使用的内置实现
- **Redis 存储**: 可以使用类似的模式实现

## 配置示例

### 高并发 Web 服务
```rust
use nonce_auth::{NonceServer, storage::MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

// 用于单实例高并发场景
let storage = Arc::new(MemoryStorage::new());
let server = NonceServer::new(
    b"your-secret-key",
    storage,
    Some(Duration::from_secs(300)),  // 5分钟 TTL
    Some(Duration::from_secs(60)),   // 1分钟时间窗口
);
```

### 微服务架构
```rust
// 为分布式场景使用自定义存储后端
let storage = Arc::new(MyDistributedStorage::new());
let server = NonceServer::new(
    b"your-secret-key",
    storage,
    Some(Duration::from_secs(180)),  // 3分钟 TTL
    Some(Duration::from_secs(30)),   // 30秒时间窗口
);
```

### 开发和测试
```bash
# 开发环境的宽松设置
export NONCE_AUTH_DEFAULT_TTL=60
export NONCE_AUTH_DEFAULT_TIME_WINDOW=300
```

```rust
// 使用内存存储进行测试
let storage = Arc::new(MemoryStorage::new());
let server = NonceServer::new(b"test-key", storage, None, None);
```

## 最佳实践

### 1. 选择合适的存储后端
- **内存存储**: 单实例应用、测试
- **SQLite 存储**: 单实例且需持久化
- **Redis/数据库存储**: 多实例、分布式应用

### 2. 安全参数调优
- **TTL**: 在安全性和可用性之间平衡
- **时间窗口**: 考虑网络延迟和时钟同步
- **上下文隔离**: 为不同业务场景使用上下文

### 3. 错误处理
```rust
match server.verify_protection_data(&data, None, |mac| {
    mac.update(data.timestamp.to_string().as_bytes());
    mac.update(data.nonce.as_bytes());
}).await {
    Ok(()) => println!("✅ 认证成功"),
    Err(NonceError::DuplicateNonce) => println!("❌ Nonce 已使用"),
    Err(NonceError::ExpiredNonce) => println!("❌ Nonce 已过期"),
    Err(NonceError::TimestampOutOfWindow) => println!("❌ 时间戳超出窗口"),
    Err(e) => println!("❌ 其他错误: {e}"),
}
```

### 4. 性能考虑
- 使用合适的 TTL 值来平衡安全性和存储增长
- 在自定义存储后端中实现高效的清理策略
- 对于数据库支持的存储考虑使用连接池

## 总结

nonce-auth 库提供了专注于安全参数的灵活配置系统：

- ✅ **可插拔存储**: 为您的需求选择合适的存储后端
- ✅ **环境变量**: 通过环境变量轻松配置
- ✅ **程序化配置**: 完全控制安全参数
- ✅ **上下文隔离**: 支持不同业务场景
- ✅ **异步支持**: 完全异步的 API 设计

更多信息，请参考：
- [API 文档](https://docs.rs/nonce-auth)
- [示例代码](examples/)
- [GitHub 仓库](https://github.com/kookyleo/nonce-auth) 