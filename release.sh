#!/bin/bash

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否在 git 仓库中
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "当前目录不是 git 仓库"
    exit 1
fi

# 检查是否在 main 分支
current_branch=$(git branch --show-current)
if [ "$current_branch" != "main" ]; then
    print_error "请切换到 main 分支后再执行发布"
    print_info "当前分支: $current_branch"
    exit 1
fi

# 检查工作目录是否干净
if ! git diff-index --quiet HEAD --; then
    print_error "工作目录有未提交的更改，请先提交或暂存"
    git status --short
    exit 1
fi

# 获取版本号输入
echo
print_info "=== Nonce Auth 发布脚本 ==="
echo
read -p "请输入新版本号 (例如: 0.2.0): " NEW_VERSION

# 验证版本号格式
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    print_error "版本号格式不正确，请使用 MAJOR.MINOR.PATCH 格式 (例如: 0.2.0)"
    exit 1
fi

TAG_NAME="v$NEW_VERSION"

print_info "准备发布版本: $NEW_VERSION"
print_info "Git tag: $TAG_NAME"
echo

# 确认发布
read -p "确认要发布版本 $NEW_VERSION 吗? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "发布已取消"
    exit 0
fi

echo
print_info "=== 开始发布流程 ==="

# 1. 拉取最新代码
print_info "1. 拉取最新代码..."
git pull origin main

# 2. 更新 Cargo.toml 中的版本号
print_info "2. 更新 Cargo.toml 版本号..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
else
    # Linux
    sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
fi

# 验证版本号更新
UPDATED_VERSION=$(grep '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
if [ "$UPDATED_VERSION" != "$NEW_VERSION" ]; then
    print_error "版本号更新失败"
    exit 1
fi
print_success "版本号已更新为: $UPDATED_VERSION"

# 3. 运行代码格式检查
print_info "3. 检查代码格式..."
if ! cargo fmt --all -- --check; then
    print_error "代码格式检查失败，正在自动修复..."
    cargo fmt --all
    print_warning "代码格式已自动修复，请检查更改"
fi

# 4. 运行 Clippy 检查
print_info "4. 运行 Clippy 检查..."
if ! cargo clippy --all-targets --all-features -- -D warnings; then
    print_error "Clippy 检查失败，请修复警告后重试"
    exit 1
fi

# 5. 运行测试
print_info "5. 运行测试套件..."
if ! cargo test; then
    print_error "测试失败，请修复后重试"
    exit 1
fi

# 6. 运行文档测试
print_info "6. 运行文档测试..."
if ! cargo test --doc; then
    print_error "文档测试失败，请修复后重试"
    exit 1
fi

# 7. 生成文档
print_info "7. 生成文档..."
if ! cargo doc --no-deps; then
    print_error "文档生成失败，请修复后重试"
    exit 1
fi

# 8. 测试示例
print_info "8. 测试示例代码..."
if ! cargo run --example simple > /dev/null 2>&1; then
    print_error "示例代码测试失败"
    exit 1
fi

print_success "所有检查通过！"

# 9. 提交版本更新
print_info "9. 提交版本更新..."
git add Cargo.toml
git commit -m "Bump version to $NEW_VERSION"

# 10. 删除现有同名 tag（如果存在）
if git tag -l | grep -q "^$TAG_NAME$"; then
    print_warning "发现现有 tag: $TAG_NAME，正在删除..."
    git tag -d "$TAG_NAME"
    
    # 尝试删除远程 tag
    if git ls-remote --tags origin | grep -q "refs/tags/$TAG_NAME"; then
        print_warning "删除远程 tag: $TAG_NAME"
        git push origin ":refs/tags/$TAG_NAME"
    fi
fi

# 11. 创建新 tag
print_info "10. 创建新 tag: $TAG_NAME"
git tag "$TAG_NAME"

# 12. 推送到远程
print_info "11. 推送代码和 tag 到远程..."
git push origin main
git push origin "$TAG_NAME"

echo
print_success "=== 发布完成！ ==="
print_info "版本: $NEW_VERSION"
print_info "Tag: $TAG_NAME"
print_info ""
print_info "GitHub Actions 将自动："
print_info "  - 运行测试"
print_info "  - 发布到 crates.io"
print_info "  - 创建 GitHub Release"
print_info ""
print_info "请访问以下链接查看发布状态："
print_info "  - GitHub Actions: https://github.com/kookyleo/nonce-auth/actions"
print_info "  - GitHub Releases: https://github.com/kookyleo/nonce-auth/releases"
print_info "  - Crates.io: https://crates.io/crates/nonce-auth"
echo 