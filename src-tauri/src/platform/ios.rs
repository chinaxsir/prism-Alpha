//! iOS 隧道控制桥接：
//!
//! 主 App 的 Rust 通过 C ABI 调用主 App 内 Swift 暴露的控制函数
//! （PrismTunnelController.swift，@_cdecl），由 NETunnelProviderManager
//! 启动/停止独立的 NEPacketTunnelProvider 扩展。内核（Go libbox）与
//! TUN 全部运行在扩展进程内。

use std::ffi::CString;

use anyhow::{Context, Result, anyhow};

unsafe extern "C" {
    /// 返回 0 = 成功；负数 = 错误（具体错误在扩展/系统日志中）
    fn prism_ios_vpn_start(config_content: *const std::os::raw::c_char) -> i32;
    fn prism_ios_vpn_stop();
    /// 返回 1 = 已连接/连接中；0 = 已断开/无效（Swift NEVPNStatus，
    /// 见 PrismTunnelController.swift @_cdecl）
    fn prism_ios_vpn_is_connected() -> i32;
    /// 返回系统级 VPN 连接起始 Unix 毫秒时间戳（NEVPNConnection.connectedDate）；
    /// 未连接时返回 0（IPA-12，见 PrismTunnelController.swift @_cdecl）
    fn prism_ios_vpn_connected_timestamp() -> i64;
    /// 覆盖升级启动自愈（APP-5 任务2）：返回 1 = 本次为升级后首次启动且
    /// 已执行清理（杀驻留旧扩展 + 标记待重启），0 = 非升级启动
    fn prism_ios_upgrade_selfheal() -> i32;
    /// 取走并清除「升级后待自动重启」标记（APP-5 任务2）；
    /// 返回 1 = 需要在清理后自动重建隧道
    fn prism_ios_take_pending_restart() -> i32;
    /// 返回 Keychain 持久化的 64 字符 hex SHA-256 硬件指纹
    /// （APP-7 任务2.3）；nilptr 表示 Swift 侧拿不到
    fn prism_ios_get_device_id() -> *const std::os::raw::c_char;
    /// 返回 App Group（group.com.prism.proxy）共享容器路径（APP6 任务1）；
    /// nilptr 表示 Swift 侧拿不到
    fn prism_ios_app_group_dir() -> *const std::os::raw::c_char;
}

pub fn start_tunnel(config_content: &str) -> Result<()> {
    let cc = CString::new(config_content).context("invalid config string")?;
    let rc = unsafe { prism_ios_vpn_start(cc.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        // Swift 侧把 NSError 完整描述写入 NSTemporaryDirectory()/
        // prism_vpn_start_error.txt（iOS 沙盒 tmp，与 std::env::temp_dir 一致）
        let detail = std::fs::read_to_string(
            std::env::temp_dir().join("prism_vpn_start_error.txt")
        )
        .unwrap_or_default();
        if detail.is_empty() {
            Err(anyhow!(
                "NETunnelProviderManager 启动失败（代码 {rc}）：请检查系统 VPN 授权与扩展安装"
            ))
        } else {
            Err(anyhow!(
                "VPN 启动失败（代码 {rc}）：{detail}"
            ))
        }
    }
}

pub fn stop_tunnel() {
    unsafe { prism_ios_vpn_stop() }
}

/// VPN 会话是否仍存活（build 157 用户方案）：查询 Swift 侧缓存的
/// NETunnelProviderManager connection.status。内核状态轮询据此把
/// 系统侧已失效的会话同步为 Stopped
pub fn vpn_is_connected() -> bool {
    unsafe { prism_ios_vpn_is_connected() == 1 }
}

/// 系统级 VPN 连接起始 Unix 毫秒时间戳（IPA-12）：connectedDate 由 iOS
/// nesessionmanagerd 维护，不受 App 挂起、锁屏甚至主 App 重启影响。
/// AppState 进入 Running 时若 >0 则优先采用，前端据此亮屏 0ms 瞬时同步时长；
/// 未连接返回 0（调用方回退本地时钟）
pub fn vpn_connected_timestamp_ms() -> u64 {
    let ts = unsafe { prism_ios_vpn_connected_timestamp() };
    if ts > 0 { ts as u64 } else { 0 }
}

/// 覆盖升级启动自愈（APP-5 任务2）：比对「版本号|build|二进制 mtime」指纹，
/// 变化时清理驻留的旧版扩展进程并标记待重启。返回 true 表示本次是升级后
/// 首次启动（调用方据此决定是否自动重建隧道）。
pub fn upgrade_selfheal() -> bool {
    unsafe { prism_ios_upgrade_selfheal() == 1 }
}

/// 取走并清除「升级后待自动重启」标记（一次性）
pub fn take_pending_restart() -> bool {
    unsafe { prism_ios_take_pending_restart() == 1 }
}

/// iOS 设备 ID：经 Swift Keychain 读取（持久化、绝不同步 iCloud）。
/// 返回 64 字符小写 hex SHA-256；None = Swift 侧 nilptr 或 UTF-8 转换失败。
pub fn get_device_id() -> Option<String> {
    unsafe {
        let p = prism_ios_get_device_id();
        if p.is_null() {
            return None;
        }
        let cstr = std::ffi::CStr::from_ptr(p);
        Some(cstr.to_string_lossy().into_owned())
    }
}

/// App Group（group.com.prism.proxy）共享容器路径（APP6 任务1）：
/// 运行日志系统据此读取扩展诊断日志。None = Swift 侧拿不到。
pub fn app_group_dir() -> Option<String> {
    unsafe {
        let p = prism_ios_app_group_dir();
        if p.is_null() {
            return None;
        }
        let cstr = std::ffi::CStr::from_ptr(p);
        Some(cstr.to_string_lossy().into_owned())
    }
}
