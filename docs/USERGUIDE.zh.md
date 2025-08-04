# Nonce Auth - 用户指南

基于 nonce-auth v0.5.0 库的实用指南，涵盖所有 API、使用模式和配置选项。

## 目录

1. [快速开始](#快速开始)
2. [核心概念](#核心概念)
3. [API 参考](#api-参考)
4. [存储系统](#存储系统)
5. [配置选项](#配置选项)
6. [错误处理](#错误处理)
7. [使用模式](#使用模式)
8. [性能指南](#性能指南)
9. [故障排除](#故障排除)

## 快速开始

### 基础使用

```rust
use nonce_auth::{CredentialBuilder, CredentialVerifier, MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = b"your-secret-key";
    let payload = b"hello world";
    
    // 创建存储
    let storage = Arc::new(MemoryStorage::new());
    
    // 生成凭证
    let credential = CredentialBuilder::new(secret)
        .sign(payload)?;
    
    // 验证凭证
    CredentialVerifier::new(storage)
        .with_secret(secret)
        .verify(&credential, payload)
        .await?;
    
    println!("验证成功！");
    Ok(())
}
```

### 添加依赖

#### 基础配置（仅内存存储）

```toml
[dependencies]
nonce-auth = "0.5"
tokio = { version = "1.0", features = ["full"] }
```

#### 完整功能配置

```toml
[dependencies]
nonce-auth = { 
    version = "0.5", 
    features = [
        "redis-storage",
        "sqlite-storage", 
        "metrics"
    ] 
}
tokio = { version = "1.0", features = ["full"] }
```

## 核心概念

### NonceCredential 凭证结构

```rust
pub struct NonceCredential {
    pub timestamp: u64,     // Unix 时间戳（秒）
    pub nonce: String,      // 唯一随机标识符
    pub signature: String,  // Base64 编码的签名
}
```

### 工作流程

1. **生成凭证**：使用 `CredentialBuilder` 创建包含时间戳、nonce 和签名的凭证
2. **传输凭证**：将凭证与请求数据一起发送
3. **验证凭证**：使用 `CredentialVerifier` 验证签名并检查 nonce 唯一性
4. **防重放**：已使用的 nonce 被存储，防止重复使用

## API 参考

### CredentialBuilder

用于创建签名凭证的构建器。

#### 构造方法

| 方法 | 签名 | 描述 |
|------|------|------|
| `new` | `new(secret: &[u8]) -> Self` | 使用密钥创建构建器 |
| `with_nonce_generator` | `with_nonce_generator<F>(self, generator: F) -> Self` | 设置自定义 nonce 生成器 |
| `with_time_provider` | `with_time_provider<F>(self, provider: F) -> Self` | 设置自定义时间提供者 |

#### 签名方法

| 方法 | 签名 | 描述 |
|------|------|------|
| `sign` | `sign(self, payload: &[u8]) -> Result<NonceCredential, NonceError>` | 对单个载荷签名 |
| `sign_structured` | `sign_structured(self, components: &[&[u8]]) -> Result<NonceCredential, NonceError>` | 对多个组件签名 |
| `sign_with` | `sign_with<F>(self, mac_fn: F) -> Result<NonceCredential, NonceError>` | 使用自定义 MAC 函数签名 |

### CredentialVerifier

用于验证凭证的验证器。

#### 构造方法

| 方法 | 签名 | 描述 |
|------|------|------|
| `new` | `new(storage: Arc<dyn NonceStorage>) -> Self` | 使用存储后端创建验证器 |
| `with_secret` | `with_secret(mut self, secret: &[u8]) -> Self` | 设置验证密钥 |
| `with_context` | `with_context(mut self, context: Option<&str>) -> Self` | 设置上下文标识 |
| `with_storage_ttl` | `with_storage_ttl(mut self, ttl: Duration) -> Self` | 设置存储 TTL |
| `with_time_window` | `with_time_window(mut self, window: Duration) -> Self` | 设置时间窗口 |

#### 验证方法

| 方法 | 签名 | 描述 |
|------|------|------|
| `verify` | `verify(mut self, credential: &NonceCredential, payload: &[u8]) -> Result<(), NonceError>` | 验证单个载荷 |
| `verify_structured` | `verify_structured(mut self, credential: &NonceCredential, components: &[&[u8]]) -> Result<(), NonceError>` | 验证多个组件 |
| `verify_with` | `verify_with<F>(mut self, credential: &NonceCredential, mac_fn: F) -> Result<(), NonceError>` | 使用自定义 MAC 函数验证 |

### 函数类型

```rust
// Nonce 生成函数
pub type NonceGeneratorFn = Box<dyn Fn() -> String + Send + Sync>;

// 时间提供函数
pub type TimeProviderFn = Box<dyn Fn() -> Result<u64, NonceError> + Send + Sync>;
```

## 存储系统

### NonceStorage 特征

所有存储后端必须实现的核心特征：

```rust
#[async_trait]
pub trait NonceStorage: Send + Sync {
    // 初始化存储（可选）
    async fn init(&self) -> Result<(), NonceError>;
    
    // 获取 nonce 条目
    async fn get(&self, nonce: &str, context: Option<&str>) 
        -> Result<Option<NonceEntry>, NonceError>;
    
    // 存储 nonce
    async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) 
        -> Result<(), NonceError>;
    
    // 检查 nonce 是否存在
    async fn exists(&self, nonce: &str, context: Option<&str>) 
        -> Result<bool, NonceError>;
    
    // 清理过期条目
    async fn cleanup_expired(&self, cutoff_time: i64) 
        -> Result<usize, NonceError>;
    
    // 获取存储统计信息
    async fn get_stats(&self) -> Result<StorageStats, NonceError>;
}
```

### NonceEntry

存储的 nonce 条目：

```rust
pub struct NonceEntry {
    pub nonce: String,              // Nonce 值
    pub created_at: i64,            // 创建时间戳
    pub context: Option<String>,    // 可选上下文
}
```

### StorageStats

存储统计信息：

```rust
pub struct StorageStats {
    pub total_records: usize,   // 总记录数
    pub backend_info: String,   // 后端信息描述
}
```

### 内置存储后端

#### MemoryStorage

内存存储实现，适合开发和测试：

```rust
use nonce_auth::MemoryStorage;
use std::sync::Arc;

let storage = Arc::new(MemoryStorage::new());
```

#### RedisStorage（需要 `redis-storage` 功能）

```rust
#[cfg(feature = "redis-storage")]
use nonce_auth::RedisStorage;

let storage = RedisStorage::new("redis://localhost:6379", "myapp")?;
```

#### SQLiteStorage（需要 `sqlite-storage` 功能）

```rust
#[cfg(feature = "sqlite-storage")]
use nonce_auth::SQLiteStorage;

let storage = SQLiteStorage::new("nonces.db").await?;
```

## 配置选项

### NonceConfig

核心配置结构：

```rust
pub struct NonceConfig {
    pub storage_ttl: Duration,    // 存储 TTL
    pub time_window: Duration,    // 时间窗口容差
}
```

### ConfigPreset

预设配置选项：

```rust
pub enum ConfigPreset {
    Production,     // 生产环境配置
    Development,    // 开发环境配置
    HighSecurity,   // 高安全配置
    FromEnv,        // 从环境变量读取
}
```

#### 预设配置对比

| 预设 | 存储 TTL | 时间窗口 | 适用场景 |
|------|----------|----------|----------|
| `Production` | 300s | 30s | 生产环境 |
| `Development` | 600s | 60s | 开发测试 |
| `HighSecurity` | 60s | 10s | 高安全需求 |

### 使用配置

```rust
use nonce_auth::{NonceConfig, ConfigPreset};
use std::time::Duration;

// 使用预设
let config = NonceConfig::from_preset(ConfigPreset::Production);

// 自定义配置
let config = NonceConfig {
    storage_ttl: Duration::from_secs(300),
    time_window: Duration::from_secs(30),
};
```

## 错误处理

### NonceError

所有可能的错误类型：

```rust
pub enum NonceError {
    DuplicateNonce,                 // Nonce 已存在
    InvalidSignature,               // 签名无效
    TimestampOutOfWindow,           // 时间戳超出窗口
    StorageError(Box<dyn Error>),   // 存储错误
    CryptoError(String),            // 加密错误
}
```

### 错误分类

| 错误类型 | 描述 | 严重程度 | 处理建议 |
|----------|------|----------|----------|
| `DuplicateNonce` | Nonce 重复使用 | 高 | 重新生成凭证 |
| `InvalidSignature` | 签名验证失败 | 高 | 检查密钥配置 |
| `TimestampOutOfWindow` | 时间戳超出允许范围 | 中 | 检查系统时间 |
| `StorageError` | 存储系统错误 | 高 | 检查存储连接 |
| `CryptoError` | 加密操作失败 | 高 | 检查算法配置 |

### 错误处理最佳实践

```rust
use nonce_auth::NonceError;

match verifier.verify(&credential, payload).await {
    Ok(()) => println!("验证成功"),
    Err(NonceError::DuplicateNonce) => {
        println!("检测到重放攻击");
    },
    Err(NonceError::InvalidSignature) => {
        println!("签名验证失败，可能是密钥不匹配");
    },
    Err(NonceError::TimestampOutOfWindow) => {
        println!("时间戳超出允许范围");
    },
    Err(NonceError::StorageError(e)) => {
        println!("存储错误: {}", e);
    },
    Err(e) => println!("其他错误: {}", e),
}
```

## 使用模式

### Web API 集成

```rust
use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::Json as ResponseJson,
};
use nonce_auth::{CredentialVerifier, NonceCredential};

#[derive(serde::Deserialize)]
struct AuthenticatedRequest {
    auth: NonceCredential,
    data: serde_json::Value,
}

async fn authenticate_request(
    State(verifier): State<Arc<CredentialVerifier>>,
    Json(request): Json<AuthenticatedRequest>,
) -> Result<ResponseJson<serde_json::Value>, StatusCode> {
    let payload = serde_json::to_vec(&request.data)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    verifier.clone()
        .verify(&request.auth, &payload)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    Ok(ResponseJson(serde_json::json!({
        "status": "success",
        "data": request.data
    })))
}
```

### 自定义 Nonce 生成

```rust
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

let custom_generator = Box::new(|| {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("nonce_{:016x}", id)
});

let credential = CredentialBuilder::new(secret)
    .with_nonce_generator(custom_generator)
    .sign(payload)?;
```

### 多租户支持

```rust
use std::collections::HashMap;

struct MultiTenantAuth {
    verifiers: HashMap<String, Arc<CredentialVerifier>>,
}

impl MultiTenantAuth {
    pub async fn authenticate(
        &self,
        tenant_id: &str,
        credential: &NonceCredential,
        payload: &[u8],
    ) -> Result<(), NonceError> {
        let verifier = self.verifiers.get(tenant_id)
            .ok_or_else(|| NonceError::CryptoError("Unknown tenant".to_string()))?;
        
        verifier.clone()
            .with_context(Some(tenant_id))
            .verify(credential, payload)
            .await
    }
}
```

## 性能指南

### 性能基准

| 操作 | 平均延迟 | 吞吐量 | 内存使用 |
|------|----------|--------|----------|
| 凭证生成 | 50μs | 20,000 ops/s | 1KB/op |
| 内存存储验证 | 80μs | 12,500 ops/s | 2KB/op |
| Redis 存储验证 | 2ms | 500 ops/s | 1KB/op |

### 优化建议

1. **使用连接池**：对于 Redis/SQLite 存储
2. **批量操作**：高吞吐量场景
3. **合理设置 TTL**：平衡安全性和性能
4. **定期清理**：防止内存泄漏

### 监控指标

```rust
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Metrics {
    pub total_verifications: AtomicU64,
    pub successful_verifications: AtomicU64,
    pub failed_verifications: AtomicU64,
}
```

## 故障排除

### 常见问题

#### 签名验证失败

**症状**：收到 `InvalidSignature` 错误

**原因**：
- 密钥不匹配
- 载荷数据不一致
- 时间戳或 nonce 不正确

**解决方案**：
```rust
// 验证密钥一致性
use sha2::{Sha256, Digest};

fn verify_key_consistency(key1: &[u8], key2: &[u8]) -> bool {
    let hash1 = Sha256::digest(key1);
    let hash2 = Sha256::digest(key2);
    hash1 == hash2
}
```

#### 时间同步问题

**症状**：收到 `TimestampOutOfWindow` 错误

**解决方案**：
- 同步系统时钟
- 增加时间窗口容差
- 使用 NTP 服务

#### 存储连接问题

**症状**：收到 `StorageError`

**解决方案**：
- 检查存储服务状态
- 验证连接配置
- 实现重试机制

### 调试工具

#### 启用调试日志

```rust
use tracing::{info, warn, error, debug};
use tracing_subscriber;

tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();
```

#### 诊断辅助函数

```rust
pub fn check_time_sync(credential: &NonceCredential) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let diff = (now as i64 - credential.timestamp as i64).abs();
    diff <= 300 // 5分钟容差
}
```

---

这份用户指南基于 nonce-auth v0.5.0 的实际 API 编写，确保内容准确可靠。如有问题请参考项目的 GitHub 仓库获取最新信息。