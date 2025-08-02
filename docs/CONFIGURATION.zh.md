# 配置指南

本文档为 `nonce-auth` 库中所有可用的配置选项提供了全面的参考。

## 服务端配置

### 服务端构建器模式

`NonceServer` 通过构建器模式进行配置，支持以下方法：

```rust
use nonce_auth::{NonceServer, NonceConfig};
use std::time::Duration;
use std::sync::Arc;

// 完整的服务端配置示例
let server = NonceServer::builder()
    .with_ttl(Duration::from_secs(600))         // 自定义 TTL (默认: 300秒)
    .with_time_window(Duration::from_secs(120)) // 自定义时间窗口 (默认: 60秒)
    .with_storage(Arc::new(custom_storage))     // 自定义存储后端
    .build_and_init()                           // 初始化存储并返回服务器
    .await?;
```

#### 可用的构建器方法

| 方法 | 描述 | 默认值 |
|-----|------|-------|
| `with_ttl(Duration)` | 设置 nonce 生存时间 | 5 分钟 |
| `with_time_window(Duration)` | 设置时间戳验证窗口 | 1 分钟 |
| `with_storage(Arc<T>)` | 设置自定义存储后端 | `MemoryStorage` |
| `build_and_init()` | 构建并初始化服务器 | - |

### 配置预设

针对常见场景的内置配置预设：

```rust
use nonce_auth::NonceConfig;

// 生产环境：平衡安全性和可用性
let config = NonceConfig::production();
assert_eq!(config.default_ttl, Duration::from_secs(300));  // 5 分钟
assert_eq!(config.time_window, Duration::from_secs(60));   // 1 分钟

// 开发环境：对开发者友好的设置
let config = NonceConfig::development();
assert_eq!(config.default_ttl, Duration::from_secs(600));  // 10 分钟
assert_eq!(config.time_window, Duration::from_secs(120));  // 2 分钟

// 高安全性：最大安全性，较短的时间窗口
let config = NonceConfig::high_security();
assert_eq!(config.default_ttl, Duration::from_secs(120));  // 2 分钟
assert_eq!(config.time_window, Duration::from_secs(30));   // 30 秒

// 将预设应用到服务器
let server = NonceServer::builder()
    .with_ttl(config.default_ttl)
    .with_time_window(config.time_window)
    .build_and_init()
    .await?;
```

### 配置验证和监控

```rust
use nonce_auth::NonceConfig;

let config = NonceConfig::production();

// 获取人类可读的摘要
println!("{}", config.summary());
// 输出: "NonceConfig { TTL: 300s, Time Window: 60s }"

// 验证配置并获取警告
let issues = config.validate();
if issues.is_empty() {
    println!("✓ 配置有效");
} else {
    println!("⚠ 配置问题:");
    for issue in issues {
        println!("  - {}", issue);
    }
}
```

### 环境变量

通过环境变量配置默认值：

```bash
# 设置默认 TTL (单位：秒)
export NONCE_AUTH_DEFAULT_TTL=600

# 设置默认时间窗口 (单位：秒)
export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
```

```rust
// 使用环境变量作为默认值
let config = NonceConfig::from_env();
let server = NonceServer::builder()
    .with_ttl(config.default_ttl)
    .with_time_window(config.time_window)
    .build_and_init()
    .await?;
```

### 服务端检查和管理

创建服务器后，可以使用以下方法进行检查和管理：

```rust
// 检查服务器配置
println!("服务器 TTL: {:?}", server.ttl());
println!("服务器时间窗口: {:?}", server.time_window());

// 访问存储后端获取统计信息
let stats = server.storage().get_stats().await?;
println!("总 nonce 记录数: {}", stats.total_records);
println!("存储后端: {}", stats.backend_info);
```

### 自动清理配置

服务器包含在后台运行的自动清理功能：

#### 默认自动清理

默认情况下，服务器使用混合清理策略，在以下情况下触发清理：
- 处理了 100 个请求，或
- 距离上次清理已过去 5 分钟

```rust
// 使用默认自动清理的服务器
let server = NonceServer::builder()
    .build_and_init()
    .await?;
// 清理在后台自动进行
```

#### 自定义清理阈值

自定义混合清理策略的阈值：

```rust
use std::time::Duration;

let server = NonceServer::builder()
    .with_hybrid_cleanup_thresholds(
        50,                       // 每 50 个请求清理一次
        Duration::from_secs(120)  // 或每 2 分钟清理一次
    )
    .build_and_init()
    .await?;
```

#### 自定义清理策略

提供完全自定义的清理逻辑：

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

// 示例：基于内存使用的清理
let server = NonceServer::builder()
    .with_custom_cleanup_strategy(|| async {
        // 您的自定义逻辑
        let memory_usage = get_current_memory_usage();
        memory_usage > 80 // 内存使用超过 80% 时清理
    })
    .build_and_init()
    .await?;

// 示例：渐进式清理频率
let request_count = Arc::new(AtomicU32::new(0));
let count_clone = Arc::clone(&request_count);

let server = NonceServer::builder()
    .with_custom_cleanup_strategy(move || {
        let count = count_clone.fetch_add(1, Ordering::SeqCst);
        async move {
            // 随着负载增加，更频繁地清理
            match count {
                0..=100 => count % 100 == 0,    // 每 100 个请求
                101..=500 => count % 50 == 0,   // 每 50 个请求
                _ => count % 25 == 0,            // 每 25 个请求
            }
        }
    })
    .build_and_init()
    .await?;
```

#### 手动清理

虽然推荐使用自动清理，但如果需要，您仍然可以手动触发清理：

```rust
// 手动清理（由于自动清理，很少需要）
let deleted_count = server.cleanup_expired_nonces(Duration::from_secs(300)).await?;
println!("手动清理了 {} 个过期的 nonces", deleted_count);
```

## 存储后端配置

### 内置存储后端

#### 内存存储 (默认)

```rust
use nonce_auth::NonceServer;

// 默认使用 MemoryStorage - 适用于测试和单实例应用
let server = NonceServer::builder()
    .build_and_init()
    .await?;
```

#### 自定义存储实现

实现 `NonceStorage` trait 创建自定义后端：

```rust
use async_trait::async_trait;
use nonce_auth::storage::{NonceStorage, NonceEntry, StorageStats};
use nonce_auth::NonceError;
use std::time::Duration;

pub struct MyCustomStorage {
    // 您的存储实现细节
}

#[async_trait]
impl NonceStorage for MyCustomStorage {
    async fn init(&self) -> Result<(), NonceError> {
        // 初始化存储 (创建表、连接等)
        Ok(())
    }

    async fn get(&self, nonce: &str, context: Option<&str>) -> Result<Option<NonceEntry>, NonceError> {
        // 检索 nonce 条目
        todo!()
    }

    async fn set(&self, nonce: &str, context: Option<&str>, ttl: Duration) -> Result<(), NonceError> {
        // 使用 TTL 存储 nonce
        todo!()
    }

    async fn exists(&self, nonce: &str, context: Option<&str>) -> Result<bool, NonceError> {
        // 检查 nonce 是否存在 (get 的优化版本)
        todo!()
    }

    async fn cleanup_expired(&self, cutoff_time: i64) -> Result<usize, NonceError> {
        // 移除过期的 nonces，返回删除记录数
        todo!()
    }

    async fn get_stats(&self) -> Result<StorageStats, NonceError> {
        // 返回存储统计信息
        Ok(StorageStats {
            total_records: 0,
            backend_info: "自定义存储后端".to_string(),
        })
    }
}

// 使用自定义存储
let custom_storage = Arc::new(MyCustomStorage {});
let server = NonceServer::builder()
    .with_storage(custom_storage)
    .build_and_init()
    .await?;
```

参考 [SQLite 示例](../examples/sqlite_storage.rs) 获取完整实现。

## 客户端配置

### 基础客户端用法

```rust
use nonce_auth::NonceClient;

// 使用默认设置的简单客户端 (UUID v4 nonces, 系统时间)
let client = NonceClient::new(b"my_secret");
let credential = client.credential_builder().sign(b"payload")?;
```

### 高级客户端配置

使用构建器模式进行完全自定义：

```rust
use nonce_auth::NonceClient;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

let client = NonceClient::builder()
    .with_secret(b"my_secret")
    .with_nonce_generator(|| {
        // 自定义 nonce 生成策略
        format!("api-req-{}", uuid::Uuid::new_v4())
    })
    .with_time_provider(|| {
        // 自定义时间源 (例如，NTP 同步)
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| nonce_auth::NonceError::CryptoError(format!("Time error: {}", e)))
    })
    .build();
```

#### 可用的客户端构建器方法

| 方法 | 参数 | 描述 |
|-----|------|------|
| `with_secret(&[u8])` | 密钥字节 | 设置共享密钥 (必需) |
| `with_nonce_generator(F)` | `F: Fn() -> String` | 自定义 nonce 生成函数 |
| `with_time_provider(F)` | `F: Fn() -> Result<u64, NonceError>` | 自定义时间戳提供器 |
| `build()` | - | 构建客户端 (无密钥时 panic) |

### 客户端配置示例

#### 测试用固定值

```rust
// 测试用的确定性值
let test_client = NonceClient::builder()
    .with_secret(b"test_secret")
    .with_nonce_generator(|| "fixed-test-nonce".to_string())
    .with_time_provider(|| Ok(1234567890))
    .build();

let credential = test_client.credential_builder().sign(b"test")?;
assert_eq!(credential.nonce, "fixed-test-nonce");
assert_eq!(credential.timestamp, 1234567890);
```

#### 顺序 Nonces

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

let counter = Arc::new(AtomicU64::new(0));
let counter_clone = counter.clone();

let client = NonceClient::builder()
    .with_secret(b"secret")
    .with_nonce_generator(move || {
        let id = counter_clone.fetch_add(1, Ordering::SeqCst);
        format!("seq-{:010}", id)
    })
    .build();

// 生成: seq-0000000000, seq-0000000001, seq-0000000002, ...
```

#### 自定义时间源

```rust
// NTP 同步时间或自定义时间源
let client = NonceClient::builder()
    .with_secret(b"secret")
    .with_time_provider(|| {
        // 您的自定义时间实现
        get_ntp_synchronized_time()
            .map_err(|e| nonce_auth::NonceError::CryptoError(format!("NTP error: {}", e)))
    })
    .build();
```

### 自定义签名逻辑

#### 客户端自定义签名

```rust
let client = NonceClient::new(b"secret");

// 标准签名 (推荐)
let credential = client.credential_builder().sign(b"payload")?;

// 带额外数据的自定义签名
let credential = client.credential_builder()
    .sign_with(|mac, timestamp, nonce| {
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(b"payload");
        mac.update(b"extra_context_data");  // 额外的认证数据
    })?;

// 复杂的结构化数据签名
let credential = client.credential_builder()
    .sign_with(|mac, timestamp, nonce| {
        mac.update(b"prefix:");
        mac.update(timestamp.as_bytes());
        mac.update(b":nonce:");
        mac.update(nonce.as_bytes());
        mac.update(b":user_id:");
        mac.update(b"12345");
        mac.update(b":payload:");
        mac.update(payload);
        mac.update(b":suffix");
    })?;

// 二进制数据签名
let binary_data = vec![0x01, 0x02, 0x03, 0x04];
let credential = client.credential_builder()
    .sign_with(|mac, timestamp, nonce| {
        mac.update(timestamp.as_bytes());
        mac.update(nonce.as_bytes());
        mac.update(&binary_data);  // 二进制载荷
        mac.update(b"metadata");   // 额外元数据
    })?;
```

## 凭证验证

### 基础验证

```rust
// 标准验证
let result = server
    .credential_verifier(&credential)
    .with_secret(b"shared_secret")
    .verify(b"payload")
    .await;

match result {
    Ok(()) => println!("✓ 凭证验证成功"),
    Err(e) => println!("✗ 验证失败: {}", e),
}
```

### 高级验证选项

```rust
// 带上下文隔离的验证
let result = server
    .credential_verifier(&credential)
    .with_secret(user_secret)
    .with_context(Some("api_v1"))  // 上下文特定的 nonce 隔离
    .verify(payload)
    .await;

// 匹配自定义签名的自定义验证逻辑
let result = server
    .credential_verifier(&credential)
    .with_secret(shared_secret)
    .with_context(Some("special_context"))
    .verify_with(|mac| {
        mac.update(credential.timestamp.to_string().as_bytes());
        mac.update(credential.nonce.as_bytes());
        mac.update(payload);
        mac.update(b"extra_context_data");  // 必须匹配客户端逻辑
    })
    .await;

// 复杂验证匹配结构化签名
let result = server
    .credential_verifier(&credential)
    .with_secret(shared_secret)
    .verify_with(|mac| {
        mac.update(b"prefix:");
        mac.update(credential.timestamp.to_string().as_bytes());
        mac.update(b":nonce:");
        mac.update(credential.nonce.as_bytes());
        mac.update(b":user_id:");
        mac.update(b"12345");  // 必须匹配签名时的确切 user_id
        mac.update(b":payload:");
        mac.update(payload);
        mac.update(b":suffix");
    })
    .await;

// 二进制数据验证
let binary_data = vec![0x01, 0x02, 0x03, 0x04];
let result = server
    .credential_verifier(&credential)
    .with_secret(shared_secret)
    .verify_with(|mac| {
        mac.update(credential.timestamp.to_string().as_bytes());
        mac.update(credential.nonce.as_bytes());
        mac.update(&binary_data);  // 与签名时相同的二进制数据
        mac.update(b"metadata");   // 与签名时相同的元数据
    })
    .await;

// 基于凭证数据的条件验证
let result = server
    .credential_verifier(&credential)
    .with_secret(shared_secret)
    .verify_with(|mac| {
        mac.update(credential.timestamp.to_string().as_bytes());
        mac.update(credential.nonce.as_bytes());
        mac.update(payload);
        
        // 根据时间戳添加条件数据
        if credential.timestamp > 1640995200 {  // 2022-01-01 之后
            mac.update(b"new_format");
        } else {
            mac.update(b"legacy_format");
        }
    })
    .await;
```

#### 可用的验证方法

| 方法 | 参数 | 描述 |
|-----|------|------|
| `with_secret(&[u8])` | 密钥字节 | 设置验证密钥 (必需) |
| `with_context(Option<&str>)` | 上下文字符串 | 设置 nonce 隔离上下文 |
| `verify(&[u8])` | 载荷字节 | 标准验证 |
| `verify_with<F>(F)` | MAC 构建器闭包 | 自定义验证逻辑 |

## 多密钥和上下文支持

### 多用户认证

```rust
let server = NonceServer::builder().build_and_init().await?;

// 不同用户使用不同的密钥
let user1_secret = b"user1_key_12345";
let user2_secret = b"user2_key_67890";

// 用户1验证
server.credential_verifier(&user1_credential)
    .with_secret(user1_secret)
    .verify(payload)
    .await?;

// 用户2在同一服务器实例上验证
server.credential_verifier(&user2_credential)
    .with_secret(user2_secret)
    .verify(payload)
    .await?;
```

### 上下文隔离

```rust
// 相同的 nonce 可以在不同上下文中使用
let credential = client.credential_builder().sign(b"data")?;

// API v1 上下文
server.credential_verifier(&credential)
    .with_secret(secret)
    .with_context(Some("api_v1"))
    .verify(b"data")
    .await?;  // ✓ 成功

// API v2 上下文 (相同 nonce，不同上下文)
server.credential_verifier(&credential)
    .with_secret(secret)
    .with_context(Some("api_v2"))
    .verify(b"data")
    .await?;  // ✓ 成功

// 在相同上下文中重用失败
server.credential_verifier(&credential)
    .with_secret(secret)
    .with_context(Some("api_v1"))
    .verify(b"data")
    .await?;  // ✗ DuplicateNonce 错误
```

## 错误处理

### 错误类型和处理

```rust
use nonce_auth::NonceError;

match server.credential_verifier(&credential)
    .with_secret(secret)
    .verify(payload)
    .await
{
    Ok(()) => println!("✓ 验证成功"),
    
    Err(NonceError::DuplicateNonce) => {
        // Nonce 已被使用 - 重放攻击防护
        println!("⚠ 检测到 nonce 重用 - 可能的重放攻击");
    },
    
    Err(NonceError::ExpiredNonce) => {
        // Nonce 超过 TTL
        println!("⚠ Nonce 已过期 - 客户端应生成新请求");
    },
    
    Err(NonceError::InvalidSignature) => {
        // 签名验证失败
        println!("⚠ 无效签名 - 检查共享密钥或请求完整性");
    },
    
    Err(NonceError::TimestampOutOfWindow) => {
        // 时间戳超出允许窗口
        println!("⚠ 请求时间戳超出范围 - 检查时钟同步");
    },
    
    Err(NonceError::DatabaseError(msg)) => {
        // 存储后端错误
        println!("⚠ 存储错误: {}", msg);
    },
    
    Err(NonceError::CryptoError(msg)) => {
        // 加密操作错误
        println!("⚠ 加密错误: {}", msg);
    },
}
```

### 高级错误处理模式

```rust
use nonce_auth::NonceError;
use std::time::Duration;

// 数据库错误的重试逻辑
async fn verify_with_retry(
    server: &NonceServer<impl NonceStorage>,
    credential: &NonceCredential,
    secret: &[u8],
    payload: &[u8],
    max_retries: u32,
) -> Result<(), NonceError> {
    let mut attempts = 0;
    
    loop {
        match server
            .credential_verifier(credential)
            .with_secret(secret)
            .verify(payload)
            .await
        {
            Ok(()) => return Ok(()),
            
            Err(NonceError::DatabaseError(_)) if attempts < max_retries => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                continue;
            },
            
            Err(e) => return Err(e),
        }
    }
}

// 生产环境的优雅错误处理
async fn handle_verification_error(error: NonceError) -> (u16, String) {
    match error {
        NonceError::DuplicateNonce => {
            (409, "请求已处理".to_string())
        },
        
        NonceError::ExpiredNonce => {
            (401, "请求已过期，请生成新的请求".to_string())
        },
        
        NonceError::InvalidSignature => {
            (401, "无效的认证凭据".to_string())
        },
        
        NonceError::TimestampOutOfWindow => {
            (400, "请求时间戳超出可接受范围".to_string())
        },
        
        NonceError::DatabaseError(_) => {
            // 内部记录实际错误但不暴露细节
            eprintln!("数据库错误: {}", error);
            (503, "服务暂时不可用".to_string())
        },
        
        NonceError::CryptoError(_) => {
            // 内部记录实际错误
            eprintln!("加密错误: {}", error);
            (500, "内部服务器错误".to_string())
        },
    }
}

// verify_with 的自定义错误处理
async fn verify_with_detailed_error(
    server: &NonceServer<impl NonceStorage>,
    credential: &NonceCredential,
    secret: &[u8],
    payload: &[u8],
) -> Result<(), String> {
    server
        .credential_verifier(credential)
        .with_secret(secret)
        .verify_with(|mac| {
            mac.update(credential.timestamp.to_string().as_bytes());
            mac.update(credential.nonce.as_bytes());
            mac.update(payload);
        })
        .await
        .map_err(|e| match e {
            NonceError::InvalidSignature => {
                "签名不匹配：检查 MAC 构建顺序和数据".to_string()
            },
            other => format!("验证失败: {}", other),
        })
}
```

## 性能和安全考虑

### TTL 配置指南

| 使用场景 | 推荐 TTL | 权衡 |
|---------|---------|------|
| 高安全性 API | 2-5 分钟 | 更好的安全性，可能影响用户体验 |
| 标准 Web API | 5-10 分钟 | 平衡安全性/可用性 |
| 开发/测试 | 10-30 分钟 | 对开发者友好 |
| 批处理 | 30-60 分钟 | 适应较长的处理时间 |

### 时间窗口指南

| 网络条件 | 推荐窗口 | 说明 |
|---------|---------|------|
| 本地/局域网 | 30-60 秒 | 紧密同步 |
| 互联网/广域网 | 60-120 秒 | 考虑网络延迟 |
| 移动/不稳定 | 120-300 秒 | 需要更高容忍度 |

### 存储后端选择

| 后端 | 使用场景 | 优点 | 缺点 |
|-----|---------|------|------|
| MemoryStorage | 测试，单实例 | 快速，简单 | 无持久化，无扩展性 |
| SQLite | 单实例，需要持久化 | 持久化，可靠 | 无水平扩展 |
| Redis | 多实例，高扩展性 | 分布式，快速 | 需要额外基础设施 |

### 安全最佳实践

```rust
// 生产就绪的服务器配置
let server = NonceServer::builder()
    .with_ttl(Duration::from_secs(300))     // 5分钟 TTL
    .with_time_window(Duration::from_secs(60))  // 1分钟窗口
    .with_storage(Arc::new(persistent_storage)) // 使用持久化存储
    .build_and_init()
    .await?;

// 自动清理默认启用
// 无需手动清理任务 - 服务器自动处理
```

## 完整示例：生产环境设置

```rust
use nonce_auth::{NonceServer, NonceClient, NonceConfig};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 使用生产环境设置配置服务器
    let config = NonceConfig::production();
    let server = NonceServer::builder()
        .with_ttl(config.default_ttl)
        .with_time_window(config.time_window)
        .with_storage(Arc::new(setup_persistent_storage().await?))
        .build_and_init()
        .await?;

    // 2. 配置带自定义 nonce 策略的客户端
    let client = NonceClient::builder()
        .with_secret(b"production_secret_key")
        .with_nonce_generator(|| {
            format!("prod-{}-{}", 
                std::process::id(), 
                uuid::Uuid::new_v4())
        })
        .build();

    // 3. 自动清理默认启用
    // 服务器将基于默认的混合策略（每 100 个请求或每 5 分钟）
    // 自动清理过期的 nonces

    // 4. 处理请求
    let payload = b"important_request_data";
    let credential = client.credential_builder().sign(payload)?;

    match server
        .credential_verifier(&credential)
        .with_secret(b"production_secret_key")
        .with_context(Some("api_v1"))
        .verify(payload)
        .await
    {
        Ok(()) => println!("✅ 请求认证成功"),
        Err(e) => eprintln!("❌ 认证失败: {}", e),
    }

    Ok(())
}
```

这份全面的配置指南涵盖了 nonce-auth 库中所有可用的选项。更多示例请参阅 [examples 目录](../examples/)。