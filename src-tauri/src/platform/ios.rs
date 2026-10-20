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
