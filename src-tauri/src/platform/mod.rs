//! 平台系统集成层
//!
//! 职责：
//! - 系统代理设置/清除（Windows 注册表 / macOS networksetup / Linux gsettings）
//! - 管理员/root 权限检测（TUN 模式需要）
//! - 开机自启动注册
//! - 代理独占：备份并恢复原有系统代理设置，确保只有当前 APP 的代理生效

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "ios")]
pub mod ios;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

/// 移动端平台初始化（Tauri setup 调用；桌面端 no-op）：
/// Android 注册 JNI/libbox 回调；iOS 无需在此初始化（Swift 侧自管理）
pub fn mobile_init(app: &tauri::AppHandle) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    {
        android::init(app.clone())?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
    }
    Ok(())
}

/// Android：检查系统 VPN 授权。false 表示需用户在系统弹窗中允许；
/// iOS 的授权由 NETunnelProviderManager 流程内部处理
pub fn ensure_vpn_permission() -> anyhow::Result<bool> {
    #[cfg(target_os = "android")]
    {
        return Ok(android::ensure_permission()?);
    }
    #[cfg(not(target_os = "android"))]
    Ok(true)
}

/// 系统代理备份（停止时恢复原设置，实现独占性）。
/// 类型统一定义在此，各平台模块通过 `super::ProxyBackup` 引用，
/// 保证 iOS/Android 等无系统代理的平台也能编译（移动端运行时为 no-op）。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProxyBackup {
    pub enabled: bool,
    pub server: String,
}

/// 读取当前系统代理设置（用于备份）
pub fn get_system_proxy() -> anyhow::Result<ProxyBackup> {
    #[cfg(target_os = "windows")]
    return Ok(windows::get_system_proxy()?);
    #[cfg(target_os = "macos")]
    return Ok(macos::get_system_proxy()?);
    #[cfg(target_os = "linux")]
    return Ok(linux::get_system_proxy()?);
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        // 移动端无系统代理概念，返回空备份（enabled=false）
        Ok(ProxyBackup::default())
    }
}

/// 设置系统代理（HTTP/HTTPS/SOCKS 统一指向 mixed 端口）
pub fn set_system_proxy(host: &str, port: u16) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    windows::set_system_proxy(host, port)?;
    #[cfg(target_os = "macos")]
    macos::set_system_proxy(host, port)?;
    #[cfg(target_os = "linux")]
    linux::set_system_proxy(host, port)?;

    tracing::info!("system proxy set -> {}:{}", host, port);
    Ok(())
}

/// 清除系统代理（必须在停止/崩溃时兜底调用，防止代理残留断网）
pub fn clear_system_proxy() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    windows::clear_system_proxy()?;
    #[cfg(target_os = "macos")]
    macos::clear_system_proxy()?;
    #[cfg(target_os = "linux")]
    linux::clear_system_proxy()?;

    tracing::info!("system proxy cleared");
    Ok(())
}

/// 恢复系统代理到备份状态（停止/切换时调用）
pub fn restore_system_proxy(backup: &ProxyBackup) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    windows::restore_system_proxy(backup)?;
    #[cfg(target_os = "macos")]
    macos::restore_system_proxy(backup)?;
    #[cfg(target_os = "linux")]
    linux::restore_system_proxy(backup)?;

    tracing::info!(
        "system proxy restored -> enabled={}, server={:?}",
        backup.enabled,
        backup.server
    );
    Ok(())
}

/// 强制结束指定 pid 的内核进程（panic 兜底使用，尽力而为不返回错误）
#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(unused_variables))]
pub fn kill_pid(pid: u32) {
    #[cfg(target_os = "windows")]
    {
        windows::kill_pid(pid);
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    unsafe {
        let _ = libc::kill(pid as i32, libc::SIGKILL);
    }
}

/// 是否具有 TUN 所需的提权（Windows 管理员 / Unix root）
pub fn has_elevated_privilege() -> bool {
    #[cfg(target_os = "windows")]
    {
        windows::is_elevated()
    }
    #[cfg(not(target_os = "windows"))]
    {
        unsafe { libc::geteuid() == 0 }
    }
}

/// 设置/取消开机自启动
pub fn set_auto_start(enabled: bool) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    windows::set_auto_start(enabled)?;
    #[cfg(target_os = "macos")]
    macos::set_auto_start(enabled)?;
    #[cfg(target_os = "linux")]
    linux::set_auto_start(enabled)?;

    tracing::info!("auto start -> {}", enabled);
    Ok(())
}
