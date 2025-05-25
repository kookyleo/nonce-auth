# Release Guide

本文档说明如何发布 `nonce-auth` 的新版本。

## 前置条件

1. **GitHub Secrets 配置**：
   - `CRATES_IO_TOKEN`: 从 [crates.io](https://crates.io/me) 获取的 API token
   - `CODECOV_TOKEN`: 从 [Codecov](https://codecov.io) 获取的上传 token

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
cargo clippy
cargo fmt --check

# 检查文档
cargo doc --no-deps --all-features
```

### 2. 更新版本号

编辑 `Cargo.toml` 中的版本号：

```toml
[package]
version = "0.2.0"  # 更新为新版本
```

### 3. 更新 CHANGELOG（可选）

如果有 `CHANGELOG.md` 文件，添加新版本的变更记录。

### 4. 提交变更

```bash
git add Cargo.toml
git commit -m "Bump version to 0.2.0"
git push origin main
```

### 5. 创建并推送 tag

```bash
# 创建 tag（必须以 'v' 开头）
git tag v0.2.0

# 推送 tag 到 GitHub
git push origin v0.2.0
```

### 6. 自动发布流程

推送 tag 后，GitHub Actions 会自动：

1. **运行测试**：确保代码质量
2. **验证版本**：检查 tag 版本与 Cargo.toml 版本是否一致
3. **发布到 crates.io**：自动发布新版本
4. **创建 GitHub Release**：生成 release notes

## 版本号规范

遵循 [Semantic Versioning](https://semver.org/)：

- `MAJOR.MINOR.PATCH` (例如: `1.2.3`)
- **MAJOR**: 不兼容的 API 变更
- **MINOR**: 向后兼容的功能添加
- **PATCH**: 向后兼容的问题修复

## 发布检查清单

- [ ] 所有测试通过
- [ ] 代码格式正确 (`cargo fmt`)
- [ ] 无 clippy 警告
- [ ] 文档构建成功
- [ ] 版本号已更新
- [ ] Tag 已创建并推送
- [ ] GitHub Actions 工作流成功运行
- [ ] crates.io 上可以看到新版本
- [ ] GitHub Release 已创建

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
   git tag -d v0.2.0
   git push origin :refs/tags/v0.2.0
   ```

2. **从 crates.io 撤回**（仅限 72 小时内）：
   ```bash
   cargo yank --vers 0.2.0
   ```

## 发布后验证

1. 访问 [crates.io/crates/nonce-auth](https://crates.io/crates/nonce-auth) 确认新版本
2. 检查 [docs.rs/nonce-auth](https://docs.rs/nonce-auth) 文档是否更新
3. 验证 GitHub Release 页面
4. 测试新版本安装：
   ```bash
   cargo install nonce-auth --version 0.2.0
   ``` 