# Nonce-Auth 配置与优化指南

本文档详细说明了 nonce-auth 库的所有配置选项、SQLite 优化措施和性能调优方法。

## 概览

nonce-auth 提供了灵活的配置系统，支持通过环境变量、预设配置和程序化配置来调整数据库性能、安全参数和系统行为。通过合理的配置和优化，可以在各种负载场景下提供稳定、高效的 nonce 认证服务。

## 配置方式

### 1. 环境变量配置

#### 预设配置选择

使用 `NONCE_AUTH_PRESET` 选择预设配置：

```bash
# 选择预设配置（默认为 'production'）
export NONCE_AUTH_PRESET=production        # 或 'development' 或 'high_performance'
```

#### 单独配置覆盖

单独的环境变量会覆盖预设值：

```bash
# 数据库配置
export NONCE_AUTH_DB_PATH="nonce_auth.db"          # 数据库文件路径
export NONCE_AUTH_CACHE_SIZE=8192                  # 缓存大小 (KB)
export NONCE_AUTH_WAL_MODE=true                    # WAL 模式
export NONCE_AUTH_SYNC_MODE=NORMAL                 # 同步模式
export NONCE_AUTH_TEMP_STORE=MEMORY                # 临时存储

# 性能配置
export NONCE_AUTH_CLEANUP_BATCH_SIZE=2000          # 清理批次大小
export NONCE_AUTH_CLEANUP_THRESHOLD=500            # 优化阈值

# 安全配置
export NONCE_AUTH_DEFAULT_TTL=300                  # 默认 TTL (秒)
export NONCE_AUTH_DEFAULT_TIME_WINDOW=60           # 时间窗口 (秒)
```

#### 配置优先级

最终配置按以下优先级顺序：
1. **单独环境变量**（最高优先级）
2. **预设配置**（由 `NONCE_AUTH_PRESET` 选择）
3. **默认值**（最低优先级）

**示例：**
```bash
# 使用生产预设并自定义缓存大小
export NONCE_AUTH_PRESET=production
export NONCE_AUTH_CACHE_SIZE=16384      # 覆盖预设缓存大小
```

### 2. 预设配置

#### 生产环境配置
```bash
# 设置生产环境预设
export NONCE_AUTH_PRESET=production

# 可选：覆盖特定设置
export NONCE_AUTH_CACHE_SIZE=16384  # 16MB 缓存用于高负载
```

```rust
use nonce_auth::NonceServer;

// 配置自动从环境变量加载
let server = NonceServer::new(b"your-secret-key", None, None);
```

**特点：**
- 8MB 缓存，平衡性能和内存使用
- 启用 WAL 模式提高并发性能
- 2000 批次大小，优化清理性能
- 5 分钟 TTL，1 分钟时间窗口

#### 开发环境配置
```bash
# 设置开发环境预设
export NONCE_AUTH_PRESET=development

# 可选：覆盖特定设置
export NONCE_AUTH_DB_PATH="test_nonce.db"  # 使用文件而非内存
```

```rust
use nonce_auth::NonceServer;

// 配置自动从环境变量加载
let server = NonceServer::new(b"your-secret-key", None, None);
```

**特点：**
- 内存数据库，测试快速
- 512KB 缓存，节省内存
- 关闭 WAL 模式，简化调试
- 1 分钟 TTL，5 分钟时间窗口（宽松）

#### 高性能配置
```bash
# 设置高性能预设
export NONCE_AUTH_PRESET=high_performance

# 可选：覆盖特定设置
export NONCE_AUTH_CACHE_SIZE=32768  # 32MB 缓存最大化性能
```

```rust
use nonce_auth::NonceServer;

// 配置自动从环境变量加载
let server = NonceServer::new(b"your-secret-key", None, None);
```

**特点：**
- 16MB 缓存，最大化性能
- 5000 批次大小，减少事务开销
- 1000 优化阈值，积极优化

### 3. 程序化配置

对于高级用例，您仍然可以创建自定义配置：

```rust
use nonce_auth::NonceConfig;
use std::time::Duration;

// 创建自定义配置
let config = NonceConfig {
    db_path: "custom_nonce.db".to_string(),
    cache_size_kb: 4096,
    wal_mode: true,
    sync_mode: "NORMAL".to_string(),
    temp_store: "MEMORY".to_string(),
    cleanup_batch_size: 1500,
    cleanup_optimize_threshold: 300,
    default_ttl: Duration::from_secs(600),
    time_window: Duration::from_secs(120),
};

// 如需要可应用环境变量覆盖
let config = config.update_from_env();

// 使用配置进行检查或验证
println!("配置: {}", config.summary());
let issues = config.validate();
if !issues.is_empty() {
    println!("配置问题: {:?}", issues);
}
```

**注意：** 库会自动使用 `NonceConfig::from_env()` 进行数据库初始化，因此程序化配置主要用于检查、验证或测试目的。

## 配置参数详解

### 预设配置

#### `NONCE_AUTH_PRESET`
- **类型**: 字符串
- **默认值**: `"production"`
- **选项**: `production`, `development`, `high_performance`
- **说明**: 选择要使用的预设配置作为基础

**预设对比：**

| 设置 | 生产环境 | 开发环境 | 高性能 |
|------|----------|----------|--------|
| 缓存大小 | 8MB | 512KB | 16MB |
| 数据库 | 文件 | 内存 | 文件 |
| WAL 模式 | 启用 | 禁用 | 启用 |
| 同步模式 | NORMAL | OFF | NORMAL |
| 批次大小 | 2000 | 100 | 5000 |
| TTL | 5 分钟 | 1 分钟 | 5 分钟 |
| 时间窗口 | 1 分钟 | 5 分钟 | 1 分钟 |

```bash
# 使用开发预设进行测试
export NONCE_AUTH_PRESET=development

# 使用高性能预设用于高负载生产环境
export NONCE_AUTH_PRESET=high_performance
```

### 数据库配置

#### `NONCE_AUTH_DB_PATH`
- **类型**: 字符串
- **默认值**: `"nonce_auth.db"`
- **说明**: SQLite 数据库文件路径
- **特殊值**: 
  - `:memory:` - 内存数据库（测试用）
  - 文件路径 - 持久化存储

```bash
# 使用内存数据库
export NONCE_AUTH_DB_PATH=":memory:"

# 使用自定义路径
export NONCE_AUTH_DB_PATH="/var/lib/nonce_auth/nonce.db"
```

#### `NONCE_AUTH_CACHE_SIZE`
- **类型**: 整数 (KB)
- **默认值**: `2048` (2MB)
- **范围**: 64 - 32768 (64KB - 32MB)
- **说明**: SQLite 页面缓存大小

**推荐值：**
- 开发环境: 512KB
- 生产环境: 8MB
- 高负载: 16MB

```bash
# 设置 4MB 缓存
export NONCE_AUTH_CACHE_SIZE=4096
```

**实现细节：**
```rust
// 设置缓存大小为 8MB
conn.pragma_update(None, "cache_size", -8192)?;
```

#### `NONCE_AUTH_WAL_MODE`
- **类型**: 布尔值
- **默认值**: `true`
- **说明**: 启用 Write-Ahead Logging 模式

**优势：**
- 提高并发读写性能
- 减少锁竞争
- 更好的崩溃恢复

**注意：**
- 仅适用于文件数据库
- 内存数据库自动禁用

```bash
# 启用 WAL 模式
export NONCE_AUTH_WAL_MODE=true

# 禁用 WAL 模式
export NONCE_AUTH_WAL_MODE=false
```

**实现细节：**
```rust
// 启用 WAL 模式
conn.pragma_update(None, "journal_mode", "WAL")?;
```

#### `NONCE_AUTH_SYNC_MODE`
- **类型**: 字符串
- **默认值**: `"NORMAL"`
- **选项**: `OFF`, `NORMAL`, `FULL`
- **说明**: 数据同步模式

**模式对比：**
| 模式 | 性能 | 安全性 | 说明 |
|------|------|--------|------|
| OFF | 最快 | 最低 | 可能丢失数据 |
| NORMAL | 平衡 | 中等 | 推荐生产环境 |
| FULL | 最慢 | 最高 | 最大数据安全 |

```bash
# 平衡模式（推荐）
export NONCE_AUTH_SYNC_MODE=NORMAL

# 高性能模式（风险较高）
export NONCE_AUTH_SYNC_MODE=OFF

# 高安全模式（性能较低）
export NONCE_AUTH_SYNC_MODE=FULL
```

**实现细节：**
```rust
// 设置同步模式
conn.pragma_update(None, "synchronous", "NORMAL")?;
```

#### `NONCE_AUTH_TEMP_STORE`
- **类型**: 字符串
- **默认值**: `"MEMORY"`
- **选项**: `MEMORY`, `FILE`
- **说明**: 临时表和索引存储位置

```bash
# 内存存储（推荐）
export NONCE_AUTH_TEMP_STORE=MEMORY

# 文件存储
export NONCE_AUTH_TEMP_STORE=FILE
```

**实现细节：**
```rust
// 使用内存临时存储
conn.pragma_update(None, "temp_store", "MEMORY")?;
```

### 性能配置

#### `NONCE_AUTH_CLEANUP_BATCH_SIZE`
- **类型**: 整数
- **默认值**: `1000`
- **范围**: 10 - 10000
- **说明**: 清理操作的批次大小

**影响：**
- 过小：频繁事务，性能差
- 过大：长事务，可能阻塞

```bash
# 高性能设置
export NONCE_AUTH_CLEANUP_BATCH_SIZE=5000

# 保守设置
export NONCE_AUTH_CLEANUP_BATCH_SIZE=500
```

**实现细节：**
```rust
// 分批删除避免长事务
let batch_size = 1000;
loop {
    let deleted = tx.execute(
        "DELETE FROM nonce_record WHERE id IN (
            SELECT id FROM nonce_record 
            WHERE created_at <= ? 
            LIMIT ?
        )",
        params![cutoff_time, batch_size],
    )?;
    
    if deleted < batch_size { break; }
}
```

#### `NONCE_AUTH_CLEANUP_THRESHOLD`
- **类型**: 整数
- **默认值**: `100`
- **说明**: 触发数据库优化的删除记录阈值

```bash
# 积极优化
export NONCE_AUTH_CLEANUP_THRESHOLD=50

# 保守优化
export NONCE_AUTH_CLEANUP_THRESHOLD=1000
```

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

## SQLite 优化措施

### 1. 索引优化

#### 复合索引设计
```sql
-- 主查询索引 (nonce 存在性检查)
CREATE INDEX idx_nonce_context ON nonce_record (nonce, context);

-- 清理操作索引
CREATE INDEX idx_created_at ON nonce_record (created_at);

-- 上下文特定操作索引
CREATE INDEX idx_context_created_at ON nonce_record (context, created_at);
```

#### 查询优化器
```rust
// 分析表结构以优化查询计划
conn.execute("ANALYZE", [])?;
```

### 2. 事务和批量操作

#### 批量插入
```rust
// 事务中批量插入
let tx = conn.unchecked_transaction()?;
let mut stmt = tx.prepare("INSERT INTO nonce_record (nonce, created_at, context) VALUES (?, ?, ?)")?;

for (nonce, created_at, context) in nonces {
    stmt.execute(params![nonce, created_at, context])?;
}

tx.commit()?;
```

### 3. 连接管理

#### 单例模式
```rust
// 全局数据库实例，避免频繁连接
lazy_static! {
    static ref DATABASE: Mutex<Option<Database>> = Mutex::new(None);
}
```

#### 线程安全
```rust
// Arc<Mutex<Connection>> 支持多线程访问
pub struct Database {
    connection: Arc<Mutex<Connection>>,
    config: DatabaseConfig,
}
```

## 配置验证

使用内置验证功能检查配置合理性：

```rust
use nonce_auth::nonce::NonceConfig;

let config = NonceConfig::default();
let issues = config.validate();

if !issues.is_empty() {
    for issue in issues {
        println!("配置问题: {}", issue);
    }
}
```

**常见警告：**
- 缓存大小过小/过大
- TTL 时间过短/过长
- 时间窗口过严格/过宽松
- 批次大小不合理

## 配置摘要

查看当前配置摘要：

```rust
let config = NonceConfig::default();
println!("当前配置:\n{}", config.summary());
```

输出示例：
```
Nonce Authentication Configuration:
Database:
  Path: nonce_auth.db
  Cache Size: 8192 KB
  WAL Mode: true
  Sync Mode: NORMAL
  Temp Store: MEMORY

Performance:
  Cleanup Batch Size: 2000
  Optimize Threshold: 500

Security:
  Default TTL: 300 seconds
  Time Window: 60 seconds
```

## 场景化配置建议

### 高并发 Web 服务
```bash
export NONCE_AUTH_CACHE_SIZE=16384
export NONCE_AUTH_WAL_MODE=true
export NONCE_AUTH_SYNC_MODE=NORMAL
export NONCE_AUTH_CLEANUP_BATCH_SIZE=5000
export NONCE_AUTH_DEFAULT_TTL=300
export NONCE_AUTH_DEFAULT_TIME_WINDOW=60
```

### 微服务架构
```bash
export NONCE_AUTH_CACHE_SIZE=4096
export NONCE_AUTH_WAL_MODE=true
export NONCE_AUTH_SYNC_MODE=NORMAL
export NONCE_AUTH_CLEANUP_BATCH_SIZE=2000
export NONCE_AUTH_DEFAULT_TTL=180
export NONCE_AUTH_DEFAULT_TIME_WINDOW=30
```

### 移动应用后端
```bash
export NONCE_AUTH_CACHE_SIZE=2048
export NONCE_AUTH_WAL_MODE=true
export NONCE_AUTH_SYNC_MODE=NORMAL
export NONCE_AUTH_CLEANUP_BATCH_SIZE=1000
export NONCE_AUTH_DEFAULT_TTL=600
export NONCE_AUTH_DEFAULT_TIME_WINDOW=120
```

### 开发和测试
```bash
export NONCE_AUTH_DB_PATH=":memory:"
export NONCE_AUTH_CACHE_SIZE=512
export NONCE_AUTH_WAL_MODE=false
export NONCE_AUTH_SYNC_MODE=OFF
export NONCE_AUTH_CLEANUP_BATCH_SIZE=100
export NONCE_AUTH_DEFAULT_TTL=60
export NONCE_AUTH_DEFAULT_TIME_WINDOW=300
```

## 性能测试结果

### 基准测试
- **100 次认证请求**: ~47ms
- **清理操作**: ~145μs
- **并发访问**: 支持多线程安全访问

### 配置对比

| 配置 | 缓存大小 | WAL模式 | 同步模式 | 适用场景 |
|------|----------|---------|----------|----------|
| 开发环境 | 512KB | 关闭 | OFF | 测试、开发 |
| 生产环境 | 8MB | 启用 | NORMAL | 生产部署 |
| 高性能 | 16MB | 启用 | NORMAL | 高负载场景 |

## 性能调优指南

### 1. 缓存大小调优
- 监控内存使用情况
- 根据并发量调整
- 避免过度分配

**权衡考虑：**
- 过小: 性能不佳
- 过大: 内存占用高
- 建议: 根据可用内存调整

### 2. WAL 模式优化
- 生产环境建议启用
- 监控 WAL 文件大小
- 定期检查点操作

**限制：**
- 仅适用于文件数据库
- 内存数据库自动禁用
- 需要文件系统支持

### 3. 清理策略优化
- 根据负载调整批次大小
- 监控清理操作耗时
- 避免清理操作阻塞业务

**批量操作注意事项：**
- 避免单个大事务
- 使用合适的批次大小
- 定期提交事务

### 4. 安全参数平衡
- TTL 不宜过短（性能）或过长（安全）
- 时间窗口考虑网络环境
- 定期审查安全设置

## 最佳实践

### 1. 选择合适的配置
```rust
// 根据环境选择配置
let config = match env::var("ENVIRONMENT").as_deref() {
    Ok("production") => NonceConfig::production(),
    Ok("development") => NonceConfig::development(),
    _ => NonceConfig::default(),
};

// 直接使用配置：Database::new(config)
```

### 2. 定期清理
```rust
// 设置定期清理任务
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        if let Err(e) = NonceServer::cleanup_expired_nonces(Duration::from_secs(300)).await {
            eprintln!("清理失败: {}", e);
        }
    }
});
```

### 3. 监控数据库状态
```rust
// 获取数据库统计信息
let stats = db.get_stats()?;
println!("数据库记录数: {}", stats.total_records);
println!("数据库大小: {} bytes", stats.database_size_bytes);
println!("缓存大小: {} KB", stats.cache_size_kb);
```

### 4. 配置验证
```rust
// 验证配置合理性
let issues = config.validate();
if !issues.is_empty() {
    for issue in issues {
        println!("配置问题: {}", issue);
    }
}
```

### 5. 环境隔离
- 不同环境使用不同配置
- 部署前验证配置合理性
- 设置关键指标监控
- 定期检查和更新配置
- 保持配置文档更新
- 配置变更前充分测试

## 监控和维护

### 关键指标
- 数据库文件大小
- 缓存命中率
- 清理操作频率
- 错误率和延迟

### 维护建议
- 定期备份数据库
- 监控磁盘空间
- 检查配置合理性
- 更新安全参数

## 故障排除

### 常见问题

**1. 性能问题**
- 检查缓存大小设置
- 确认 WAL 模式启用
- 调整清理批次大小

**2. 内存使用过高**
- 减少缓存大小
- 检查清理策略
- 监控并发连接数

**3. 数据库锁定**
- 启用 WAL 模式
- 减少事务大小
- 检查并发访问模式

**4. 时间相关错误**
- 检查系统时间同步
- 调整时间窗口设置
- 验证网络延迟

### 调试技巧

```rust
// 启用详细日志
std::env::set_var("RUST_LOG", "nonce_auth=debug");

// 检查配置
let config = NonceConfig::default();
println!("配置摘要: {}", config.summary());

// 验证配置
let issues = config.validate();
for issue in issues {
    println!("配置警告: {}", issue);
}
```

## 未来优化方向

1. **连接池**: 考虑实现连接池以支持更高并发
2. **读写分离**: 对于高读取负载场景
3. **分区表**: 对于大量数据场景
4. **压缩**: 考虑数据压缩以减少存储空间
5. **监控**: 添加性能监控和告警

## 总结

通过以上配置和优化措施，nonce-auth 项目的 SQLite 性能得到了显著提升：

- ✅ **缓存优化**: 提高查询性能
- ✅ **WAL 模式**: 改善并发性能
- ✅ **索引优化**: 加速查询和清理操作
- ✅ **批量操作**: 减少事务开销
- ✅ **配置管理**: 灵活的环境适配
- ✅ **监控支持**: 便于性能调优

这些优化确保了在各种负载场景下都能提供稳定、高效的 nonce 认证服务。

---

更多信息请参考：
- [API 文档](https://docs.rs/nonce-auth)
- [示例代码](examples/) 