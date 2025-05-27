#!/bin/bash

set -e  # Exit immediately on error

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored messages
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

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "Current directory is not a git repository"
    exit 1
fi

# Check if we're on main branch
current_branch=$(git branch --show-current)
if [ "$current_branch" != "main" ]; then
    print_error "Please switch to main branch before releasing"
    print_info "Current branch: $current_branch"
    exit 1
fi

# Check if working directory is clean
if ! git diff-index --quiet HEAD --; then
    print_error "Working directory has uncommitted changes, please commit or stash them first"
    git status --short
    exit 1
fi

# Get version input
echo
print_info "=== Nonce Auth Release Script ==="
echo
read -p "Please enter new version number (e.g., 0.2.0): " NEW_VERSION

# Validate version format
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    print_error "Invalid version format, please use MAJOR.MINOR.PATCH format (e.g., 0.2.0)"
    exit 1
fi

TAG_NAME="v$NEW_VERSION"

print_info "Preparing to release version: $NEW_VERSION"
print_info "Git tag: $TAG_NAME"
echo

# Confirm release
read -p "Confirm release of version $NEW_VERSION? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Release cancelled"
    exit 0
fi

echo
print_info "=== Starting release process ==="

# 1. Pull latest code
print_info "1. Pulling latest code..."
git pull origin main

# 2. Update version in Cargo.toml
print_info "2. Updating Cargo.toml version..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
else
    # Linux
    sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" Cargo.toml
fi

# Verify version update
UPDATED_VERSION=$(grep '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
if [ "$UPDATED_VERSION" != "$NEW_VERSION" ]; then
    print_error "Version update failed"
    exit 1
fi
print_success "Version updated to: $UPDATED_VERSION"

# 3. Run code format check
print_info "3. Checking code format..."
if ! cargo fmt --all -- --check; then
    print_error "Code format check failed, auto-fixing..."
    cargo fmt --all
    print_warning "Code format has been auto-fixed, please review changes"
fi

# 4. Run Clippy check
print_info "4. Running Clippy check..."
if ! cargo clippy --all-targets --all-features -- -D warnings; then
    print_error "Clippy check failed, please fix warnings and retry"
    exit 1
fi

# 5. Run tests
print_info "5. Running test suite..."
if ! cargo test; then
    print_error "Tests failed, please fix and retry"
    exit 1
fi

# 6. Run doc tests
print_info "6. Running doc tests..."
if ! cargo test --doc; then
    print_error "Doc tests failed, please fix and retry"
    exit 1
fi

# 7. Generate documentation
print_info "7. Generating documentation..."
if ! cargo doc --no-deps; then
    print_error "Documentation generation failed, please fix and retry"
    exit 1
fi

# 8. Test examples
print_info "8. Testing example code..."
if ! cargo run --example simple > /dev/null 2>&1; then
    print_error "Example code test failed"
    exit 1
fi

print_success "All checks passed!"

# 9. Commit version update
print_info "9. Committing version update..."
git add Cargo.toml
git commit -m "Bump version to $NEW_VERSION"

# 10. Delete existing tag with same name (if exists)
if git tag -l | grep -q "^$TAG_NAME$"; then
    print_warning "Found existing tag: $TAG_NAME, deleting..."
    git tag -d "$TAG_NAME"
    
    # Try to delete remote tag
    if git ls-remote --tags origin | grep -q "refs/tags/$TAG_NAME"; then
        print_warning "Deleting remote tag: $TAG_NAME"
        git push origin ":refs/tags/$TAG_NAME"
    fi
fi

# 11. Create new tag
print_info "10. Creating new tag: $TAG_NAME"
git tag "$TAG_NAME"

# 12. Push to remote
print_info "11. Pushing code and tag to remote..."
git push origin main
git push origin "$TAG_NAME"

echo
print_success "=== Release completed! ==="
print_info "Version: $NEW_VERSION"
print_info "Tag: $TAG_NAME"
print_info ""
print_info "GitHub Actions will automatically:"
print_info "  - Run tests"
print_info "  - Publish to crates.io"
print_info "  - Create GitHub Release"
print_info ""
print_info "Please visit the following links to check release status:"
print_info "  - GitHub Actions: https://github.com/kookyleo/nonce-auth/actions"
print_info "  - GitHub Releases: https://github.com/kookyleo/nonce-auth/releases"
print_info "  - Crates.io: https://crates.io/crates/nonce-auth"
echo 