# Nonce Auth

![Nonce Auth Banner](docs/banner.png)

[![CI](https://github.com/kookyleo/nonce-auth/workflows/CI/badge.svg)](https://github.com/kookyleo/nonce-auth/actions)
[![Crates.io](https://img.shields.io/crates/v/nonce-auth.svg)](https://crates.io/crates/nonce-auth)
[![Documentation](https://docs.rs/nonce-auth/badge.svg)](https://docs.rs/nonce-auth)
[![License](https://img.shields.io/crates/l/nonce-auth.svg)](https://github.com/kookyleo/nonce-auth#license)

一个轻量、安全的基于 nonce 的 Rust 认证库，专为防止 API 和其他服务的重放攻击而设计。

## 核心特性

- **🛡️ 重放攻击防护**: 结合 nonce、时间戳和 HMAC-SHA256 签名，确保每个请求的唯一性和真实性
- **🚀 简单易用**: 清晰的构建者模式 API，引导开发者安全使用
- **⚡ 异步与可插拔**: 完全异步设计，支持可插拔的存储后端（内存、Redis、SQLite 等）
- **🔧 灵活配置**: 可自定义 TTL、时间窗口、nonce 生成和密钥管理

## 快速开始

```bash
cargo add nonce-auth tokio
```

### Quick Start

```rust
use nonce_auth::{CredentialBuilder, CredentialVerifier, storage::MemoryStorage, storage::NonceStorage};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 凭证创建者和验证者之间的共享密钥
    let secret = b"my-super-secret-key";
    let payload = b"important_api_request_data";

    // 创建存储后端（本示例使用内存存储）
    let storage: Arc<dyn NonceStorage> = Arc::new(MemoryStorage::new());

    // 1. 创建凭证
    let credential = CredentialBuilder::new(secret)
        .sign(payload)?;

    println!("✅ 生成凭证，nonce: {}", credential.nonce);

    // 2. 验证凭证
    CredentialVerifier::new(Arc::clone(&storage))
        .with_secret(secret)
        .verify(&credential, payload)
        .await?;

    println!("✅ 首次验证成功！");

    // 3. 重放攻击自动被拒绝
    let replay_result = CredentialVerifier::new(storage)
        .with_secret(secret)
        .verify(&credential, payload)
        .await;

    assert!(replay_result.is_err());
    println!("✅ 重放攻击被正确拒绝！");

    Ok(())
}
```

更多高级用法，请参考 [`examples`](examples/) 示例和和 [用户指南](docs/USERGUIDE.zh.md)。

## 存储后端

- **内存** (`MemoryStorage`): 快速、内置，适合单实例应用
- **Redis** (`RedisStorage`): 分布式、生产就绪，支持连接池 (feature: `redis-storage`)
- **SQLite**: (`SQLiteStorage`): 支持 WAL 模式，支持连接池 (feature: `sqlite-storage`)
- **自定义**: 实现 `NonceStorage` trait 以支持您自己的后端

## 配置

库提供多种配置方式：

- **预设**: `ConfigPreset::Production`、`ConfigPreset::Development`、`ConfigPreset::HighSecurity`
- **环境变量**: `NONCE_AUTH_DEFAULT_TTL`、`NONCE_AUTH_DEFAULT_TIME_WINDOW`
- **自定义配置**: 通过构建者方法进行细粒度控制

详细配置选项请参阅 [用户指南](docs/USERGUIDE.zh.md)。

## 示例

- [`simple.rs`](examples/simple.rs) - 基础凭证创建和验证
- [`web.rs`](examples/web.rs) - Web demo
- [`sqlite_storage.rs`](examples/sqlite_storage.rs) - SQLite 存储后端
- [`redis_example.rs`](examples/redis_example.rs) - 带连接池的 Redis
- [`performance_test.rs`](examples/performance_test.rs) - 性能基准测试

## 文档

- [完整用户指南](docs/USERGUIDE.zh.md) - 全面的 API 文档
- [API 文档](https://docs.rs/nonce-auth) - 生成的 API 文档

## 安全特性

- **HMAC-SHA256** 签名用于篡改检测
- **时间戳验证** 具有可配置的时间窗口
- **Nonce 唯一性** 强制防止重放攻击
- **上下文隔离** 用于多租户应用
- **常数时间比较** 防止时序攻击

## 性能

- **零拷贝验证** 在可能的情况下
- **异步优先设计** 支持高并发
- **连接池** 用于 Redis 后端
- **批量操作** 提高吞吐量
- **可配置清理策略** 优化内存使用

## 许可证

采用以下任一许可证：

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) 或 http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) 或 http://opensource.org/licenses/MIT)

您可以任选其一。