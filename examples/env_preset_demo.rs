use nonce_auth::NonceConfig;

fn main() {
    println!("=== 环境变量预设配置演示 ===\n");

    // 演示不同的预设配置
    println!("1. 默认配置（无环境变量）:");
    unsafe {
        std::env::remove_var("NONCE_AUTH_PRESET");
    }
    let config = NonceConfig::from_env();
    println!("{}\n", config.summary());

    // 演示开发环境预设
    println!("2. 开发环境预设 (NONCE_AUTH_PRESET=development):");
    unsafe {
        std::env::set_var("NONCE_AUTH_PRESET", "development");
    }
    let config = NonceConfig::from_env();
    println!("{}\n", config.summary());

    // 演示高性能预设
    println!("3. 高性能预设 (NONCE_AUTH_PRESET=high_performance):");
    unsafe {
        std::env::set_var("NONCE_AUTH_PRESET", "high_performance");
    }
    let config = NonceConfig::from_env();
    println!("{}\n", config.summary());

    // 演示预设 + 环境变量覆盖
    println!(
        "4. 生产预设 + 自定义缓存 (NONCE_AUTH_PRESET=production + NONCE_AUTH_CACHE_SIZE=32768):"
    );
    unsafe {
        std::env::set_var("NONCE_AUTH_PRESET", "production");
        std::env::set_var("NONCE_AUTH_CACHE_SIZE", "32768");
    }
    let config = NonceConfig::from_env();
    println!("{}\n", config.summary());

    // 演示无效预设回退到生产环境
    println!("5. 无效预设回退 (NONCE_AUTH_PRESET=invalid):");
    unsafe {
        std::env::set_var("NONCE_AUTH_PRESET", "invalid");
        std::env::remove_var("NONCE_AUTH_CACHE_SIZE");
    }
    let config = NonceConfig::from_env();
    println!("{}\n", config.summary());

    println!("=== 配置优先级说明 ===");
    println!("1. 单独环境变量（最高优先级）");
    println!("2. 预设配置（由 NONCE_AUTH_PRESET 选择）");
    println!("3. 默认值（最低优先级）");

    // 清理环境变量
    unsafe {
        std::env::remove_var("NONCE_AUTH_PRESET");
        std::env::remove_var("NONCE_AUTH_CACHE_SIZE");
    }
}
