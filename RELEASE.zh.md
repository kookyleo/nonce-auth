# Release Guide

本文档说明如何发布 `nonce-auth` 的新版本。

## 前置条件

1. **GitHub Secrets 配置**：
   - `CRATES_IO_TOKEN`: 从 [crates.io](https://crates.io/me) 获取的 API token

2. **权限要求**：
   - 对仓库有 push 权限
   - 对 crates.io 上的 `nonce-auth` crate 有发布权限

3. **环境要求**：
   - Git 已配置并能推送到 origin
   - Rust 工具链已安装 (cargo, rustfmt, clippy)

## 🚀 自动化发布（推荐）

### 使用发布脚本

项目提供了自动化发布脚本 `release.sh`，可以一键完成整个发布流程：

```bash
# 确保在项目根目录
cd nonce-auth

# 运行发布脚本
./release.sh
```

### 脚本功能

发布脚本会自动执行以下操作：

1. **环境检查**：
   - 检查是否在 git 仓库中
   - 确认当前在 main 分支
   - 检查工作目录是否干净

2. **版本号输入**：
   - 提示输入新版本号（如 `0.2.0`）
   - 验证版本号格式（MAJOR.MINOR.PATCH）
   - 确认发布操作

3. **自动更新**：
   - 拉取最新代码
   - 自动更新 `Cargo.toml` 中的版本号
   - 验证版本号更新成功

4. **质量检查**：
   - 代码格式检查（自动修复）
   - Clippy 静态分析
   - 单元测试
   - 文档测试
   - 文档生成
   - 示例代码测试

5. **Git 操作**：
   - 提交版本更新
   - 删除现有同名 tag（如果存在）
   - 创建新 tag
   - 推送代码和 tag 到远程

6. **发布确认**：
   - 显示发布状态
   - 提供相关链接

### 脚本输出示例

```bash
$ ./release.sh

[INFO] === Nonce Auth 发布脚本 ===

请输入新版本号 (例如: 0.2.0): 0.2.0
[INFO] 准备发布版本: 0.2.0
[INFO] Git tag: v0.2.0

确认要发布版本 0.2.0 吗? (y/N): y

[INFO] === 开始发布流程 ===
[INFO] 1. 拉取最新代码...
[INFO] 2. 更新 Cargo.toml 版本号...
[SUCCESS] 版本号已更新为: 0.2.0
[INFO] 3. 检查代码格式...
[INFO] 4. 运行 Clippy 检查...
[INFO] 5. 运行测试套件...
[INFO] 6. 运行文档测试...
[INFO] 7. 生成文档...
[INFO] 8. 测试示例代码...
[SUCCESS] 所有检查通过！
[INFO] 9. 提交版本更新...
[INFO] 10. 创建新 tag: v0.2.0
[INFO] 11. 推送代码和 tag 到远程...

[SUCCESS] === 发布完成！ ===
[INFO] 版本: 0.2.0
[INFO] Tag: v0.2.0
```

## 📋 手动发布步骤（备选）

如果需要手动发布或脚本出现问题，可以按照以下步骤操作：

### 1. 准备发布

```bash
# 确保在 main 分支
git checkout main
git pull origin main

# 运行完整测试
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

### 2. 更新版本号

编辑 `Cargo.toml` 中的版本号：

```toml
[package]
version = "0.2.0"  # 更新为新版本
```

### 3. 提交变更

```bash
git add Cargo.toml
git commit -m "Bump version to 0.2.0"
git push origin main
```

### 4. 创建并推送 tag

```bash
# 删除现有 tag（如果存在）
git tag -d v0.2.0 2>/dev/null || true
git push origin :refs/tags/v0.2.0 2>/dev/null || true

# 创建新 tag
git tag v0.2.0

# 推送 tag 到 GitHub
git push origin v0.2.0
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
4. **网络问题**：无法推送到 GitHub 或 crates.io

### 脚本问题

如果自动化脚本出现问题：

1. **权限问题**：确保脚本有执行权限 (`chmod +x release.sh`)
2. **环境问题**：确保所有依赖工具已安装
3. **Git 问题**：确保 Git 配置正确且能推送到 origin
4. **回退到手动**：使用上述手动发布步骤

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
4. 检查 GitHub Actions 执行状态

## 发布历史

### v0.1.9
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