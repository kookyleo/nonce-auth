# Release Guide

本文档说明如何发布 `nonce-auth` 的新版本。

## 前置条件

1. **GitHub Secrets 配置**：
   - `CRATES_IO_TOKEN`: 从 [crates.io](https://crates.io/me) 获取的 API token

2. **权限要求**：
   - 对仓库有 push 权限
   - 对 crates.io 上的 `nonce-auth` crate 有发布权限

## 发布步骤

### 1. 准备发布

```bash
# 确保在 main 分支
git checkout main
git pull origin main

# 运行完整测试
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

### 2. 更新版本号

编辑 `Cargo.toml` 中的版本号：

```toml
[package]
version = "0.1.10"  # 更新为新版本
```

### 3. 提交变更

```bash
git add Cargo.toml
git commit -m "Bump version to 0.1.10"
git push origin main
```

### 4. 创建并推送 tag

```bash
# 创建 tag（必须以 'v' 开头）
git tag v0.1.10

# 推送 tag 到 GitHub
git push origin v0.1.10
```

### 5. 自动发布流程

推送 tag 后，GitHub Actions 会自动：

1. **运行测试**：确保代码质量
2. **验证版本**：检查 tag 版本与 Cargo.toml 版本是否一致
3. **发布到 crates.io**：自动发布新版本
4. **创建 GitHub Release**：使用专业的 changelog 生成器自动生成 release notes

## 版本号规范

遵循 [Semantic Versioning](https://semver.org/)：

- `MAJOR.MINOR.PATCH` (例如: `1.2.3`)
- **MAJOR**: 不兼容的 API 变更
- **MINOR**: 向后兼容的功能添加
- **PATCH**: 向后兼容的问题修复

## 故障排除

### 发布失败

如果发布失败，检查：

1. **版本冲突**：Tag 版本与 Cargo.toml 版本不匹配
2. **权限问题**：CRATES_IO_TOKEN 无效或权限不足
3. **测试失败**：代码质量检查未通过

### 回滚发布

如果需要回滚：

1. **删除 tag**：
   ```bash
   git tag -d v0.1.10
   git push origin :refs/tags/v0.1.10
   ```

2. **从 crates.io 撤回**（仅限 72 小时内）：
   ```bash
   cargo yank --vers 0.1.10
   ```

## 发布后验证

1. 访问 [crates.io/crates/nonce-auth](https://crates.io/crates/nonce-auth) 确认新版本
2. 检查 [docs.rs/nonce-auth](https://docs.rs/nonce-auth) 文档是否更新
3. 验证 GitHub Release 页面

## 发布历史

### v0.1.9 (当前版本)
- 升级到专业的 Release Changelog Builder
- 修复了 GitHub Actions 中的版本号格式问题
- 优化了 Release Notes 的格式和内容
- 添加了智能的 changelog 分类系统

### v0.1.8
- 修复了 GitHub Actions 输出格式问题
- 解决了 docs.rs 构建兼容性问题
- 添加了条件编译支持

### v0.1.2
- 修复了代码格式和 Clippy 警告
- 完善了文档和示例

### v0.1.1
- 初始功能实现
- 客户端服务端分离设计
- 灵活的签名算法支持

### v0.1.0
- 项目初始发布