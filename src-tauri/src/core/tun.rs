//! TUN 虚拟网卡跨平台适配
//!
//! 重要架构约定：
//! TUN 数据面由 sing-box 内核的 tun inbound 处理（基于 gVisor/system stack）。
//! 开启 `auto_route` + `strict_route` 后，路由表、DNS 劫持、流量绕行
//! 全部由内核自动完成。Rust 侧的职责是：
//!   1. 提权检测与引导（TUN 必须管理员/root）
//!   2. 手动路由模式（auto_route 关闭）下的路由与 DNS 配置
//!   3. 移动端获取/传递 TUN 文件描述符（Android VpnService / iOS NE）
//!
//! 平台要点：
//! - Windows: 内核内嵌 wintun.dll（sing-box 自带），需管理员
//! - macOS:   utun 设备 + root；App Store 路线必须用 Network Extension
//! - Linux:   /dev/net/tun + CAP_NET_ADMIN
//! - Android: VpnService.establish() 返回的 fd 传给内核 tun inbound
//! - iOS:     NEPacketTunnelProvider，sing-box 以 Package 编译进扩展

// run_cmd 仅在 macOS/Linux 手动路由模式使用，Duration 随之门控
// （APP27：移动端不编译该函数，避免 iOS 目标出现 unused 警告）
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::Duration;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
// Command 仅桌面手动路由/路由命令使用；移动端不编译（APP27 消除 unused 警告）
#[cfg(not(any(target_os = "ios", target_os = "android")))]
use tokio::process::Command;

/// TUN 网段固定使用 sing-box 默认 fake-tun 网段
pub const TUN_GATEWAY4: &str = "198.18.0.1";
const TUN_DEVICE_NAME: &str = "prism-tun";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunConfig {
    /// 设备名（桌面端参考值，内核可能自行命名 utun/wintun）
    pub name: String,
    pub mtu: u32,
    /// 是否由内核自动配置路由（默认 true，此时 Rust 不动路由表）
    pub auto_route: bool,
    /// 劫持 DNS
    pub auto_detect_dns: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: TUN_DEVICE_NAME.to_string(),
            mtu: 9000,
            auto_route: true,
            auto_detect_dns: true,
        }
    }
}

/// TUN 生命周期守卫：Drop 时尽力清理
pub struct TunGuard {
    config: TunConfig,
    manual_routes_added: bool,
}

impl TunGuard {
    /// 启用 TUN（在内核启动成功后调用）
    pub async fn enable(config: TunConfig) -> Result<Self> {
        if !crate::platform::has_elevated_privilege() {
            bail!(
                "TUN 模式需要管理员/root 权限，请以管理员身份重启 Prism 后再试"
            );
        }

        let manual_routes_added = if !config.auto_route {
            // 手动路由模式：Rust 接管路由表与 DNS
            Self::configure_routes(&config.name).await?;
            if config.auto_detect_dns {
                Self::configure_dns(TUN_GATEWAY4)?;
            }
            true
        } else {
            // 内核 auto_route 模式：无需 Rust 操作
            tracing::info!("TUN auto_route enabled, kernel manages routing");
            false
        };

        tracing::info!("TUN device '{}' enabled", config.name);
        Ok(Self {
            config,
            manual_routes_added,
        })
    }

    /// 禁用 TUN 并清理
    pub async fn disable(&mut self) -> Result<()> {
        if self.manual_routes_added {
            Self::cleanup_routes(&self.config.name).await?;
            Self::restore_dns()?;
        }
        tracing::info!("TUN disabled");
        Ok(())
    }

    /// 添加默认路由劫持（拆成两段 /1，避免直接覆盖默认路由，便于回滚）
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(unused_variables))]
    async fn configure_routes(device: &str) -> Result<()> {
        #[cfg(windows)]
        {
            run_route(&["add", "0.0.0.0", "mask", "128.0.0.0", TUN_GATEWAY4]).await?;
            run_route(&["add", "128.0.0.0", "mask", "128.0.0.0", TUN_GATEWAY4]).await?;
        }

        #[cfg(target_os = "macos")]
        {
            run_cmd(
                "route",
                &["add", "-net", "0.0.0.0/1", "-interface", device],
            )
            .await?;
            run_cmd(
                "route",
                &["add", "-net", "128.0.0.0/1", "-interface", device],
            )
            .await?;
        }

        #[cfg(target_os = "linux")]
        {
            run_cmd(
                "ip",
                &["route", "add", "0.0.0.0/1", "dev", device],
            )
            .await?;
            run_cmd(
                "ip",
                &["route", "add", "128.0.0.0/1", "dev", device],
            )
            .await?;
        }

        Ok(())
    }

    /// 回滚手动路由
    // device 仅 Linux 分支消费（macOS/Windows 使用固定网段），允许未使用
    #[allow(unused_variables)]
    async fn cleanup_routes(device: &str) -> Result<()> {
        #[cfg(windows)]
        {
            let _ = run_route(&["delete", "0.0.0.0", "mask", "128.0.0.0"]).await;
            let _ = run_route(&["delete", "128.0.0.0", "mask", "128.0.0.0"]).await;
        }
        #[cfg(target_os = "macos")]
        {
            let _ = run_cmd("route", &["delete", "-net", "0.0.0.0/1"]).await;
            let _ = run_cmd("route", &["delete", "-net", "128.0.0.0/1"]).await;
        }
        #[cfg(target_os = "linux")]
        {
            let _ = run_cmd("ip", &["route", "del", "0.0.0.0/1", "dev", device]).await;
            let _ = run_cmd("ip", &["route", "del", "128.0.0.0/1", "dev", device]).await;
        }
        Ok(())
    }

    /// 将系统 DNS 指向 TUN 网关（内核 fake-ip）
    #[cfg_attr(any(target_os = "android", target_os = "ios"), allow(unused_variables))]
    fn configure_dns(dns: &str) -> Result<()> {
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("netsh")
                .args([
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    "name=", // TODO: 绑定到 TUN 适配器名
                    "source=static",
                    "addr=",
                    dns,
                ])
                .status();
        }
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("bash")
                .args(["-c", &format!("networksetup -setdnsservers Wi-Fi {}", dns)])
                .status();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("resolvectl")
                .args(["dns", TUN_DEVICE_NAME, dns])
                .status();
        }
        Ok(())
    }

    /// 恢复自动 DNS
    fn restore_dns() -> Result<()> {
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("netsh")
                .args(["interface", "ip", "set", "dns", "name=", "source=dhcp"])
                .status();
        }
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("networksetup")
                .args(["-setdnsservers", "Wi-Fi", "empty"])
                .status();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("resolvectl")
                .args(["revert", TUN_DEVICE_NAME])
                .status();
        }
        Ok(())
    }
}

impl Drop for TunGuard {
    fn drop(&mut self) {
        // Drop 中无法安全执行 async 清理，仅记录警告。
        // 调用方必须在停止流程中显式 await disable()。
        if self.manual_routes_added {
            tracing::error!(
                "TUN guard dropped without disable(); manual routes may remain, \
                 system networking could be affected until reboot/network reset"
            );
        }
    }
}

#[cfg(windows)]
async fn run_route(args: &[&str]) -> Result<()> {
    let status = Command::new("route")
        .args(args)
        .status()
        .await?;
    if !status.success() {
        bail!("route {:?} failed: {}", args, status);
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(program).args(args).output(),
    )
    .await??;
    if !output.status.success() {
        bail!(
            "{} {:?} failed: {}",
            program,
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
