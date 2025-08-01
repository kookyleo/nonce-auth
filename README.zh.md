# Nonce Auth

[![CI](https://github.com/kookyleo/nonce-auth/workflows/CI/badge.svg)](https://github.com/kookyleo/nonce-auth/actions)
[![Crates.io](https://img.shields.io/crates/v/nonce-auth.svg)](https://crates.io/crates/nonce-auth)
[![Documentation](https://docs.rs/nonce-auth/badge.svg)](https://docs.rs/nonce-auth)
[![License](https://img.shields.io/crates/l/nonce-auth.svg)](https://github.com/kookyleo/nonce-auth#license)

一个轻量、安全的 nonce 认证库，专为 Rust 设计，旨在有效防止 API 和其他服务中的重放攻击。

##核心特性

- **防重放攻击**: 结合使用 Nonce、时间戳和 HMAC-SHA256 签名，确保每个请求的唯一性和真实性。
- **安全且易用的 API**: 采用构建者模式 (`credential_builder`)，引导开发者安全使用，避免常见的安全陷阱。
- **异步与可插拔存储**: 完全异步的设计，以及基于 trait 的存储系统，允许轻松集成内存、SQLite 或 Redis 等后端。

## 快速上手

```rust
use nonce_auth::{NonceClient, NonceServer, storage::MemoryStorage};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 共享密钥和需要保护的业务数据
    let secret = b"my-super-secret-key";
    let payload = b"important_api_request_data";

    // 2. 创建服务端和存储后端
    let storage = Arc::new(MemoryStorage::new());
    let server = NonceServer::new(secret, storage, None, None);
    server.init().await?;

    // 3. 创建客户端，并为业务数据生成凭证
    let client = NonceClient::new(secret);
    let credential = client.credential_builder().sign(payload)?;
    println!("生成的凭证: {:?}", credential);

    // 4. 服务端使用标准的、对称的方法验证凭证
    let verification_result = server
        .credential_verifier(&credential)
        .verify(payload)
        .await;

    assert!(verification_result.is_ok());
    println!("✅ 首次验证成功!");

    // 5. 再次使用相同的凭证将会失败
    let replay_result = server
        .credential_verifier(&credential)
        .verify(payload)
        .await;

    assert!(replay_result.is_err());
    println!("✅ 成功拒绝重放攻击!");

    Ok(())
}
```

## 配置与示例

- 关于 TTL、时间窗口和存储后端的详细配置，请参阅 [CONFIGURATION.zh.md](CONFIGURATION.zh.md)。
- 更多高级用法，包括一个完整的 Web 服务器实现，请参阅 [examples](examples/) 目录。

## 许可证

本项目采用以下任一许可证：

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) 或 http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) 或 http://opensource.org/licenses/MIT)

您可以任选其一。