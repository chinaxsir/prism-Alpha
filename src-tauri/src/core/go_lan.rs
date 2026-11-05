//! Go Lan —— 家庭局域网隧穿（回家网络，Pro 专属）
//!
//! 三种配置模式：
//! 1. Manual WireGuard：直接填写家庭 WG 服务器的私钥/对端公钥等；
//! 2. Manual 分享链接：粘贴家庭节点分享链接（vless/vmess/ss/trojan/hy2/tuic 等）；
//! 3. Managed（远端拉取）：设备上报 device_code，由授权服务器下发回家节点。
//!
//! 生成的 `go-lan-home` 出站会在 config_builder 中合成最高优先级路由规则：
//! - `lan_domains`（域名后缀）→ go-lan-home
//! - `lan_cidrs`（网段）→ go-lan-home
//! 规则必须位于 `geosite: private` 与 `ip_is_private: true -> direct` 之前，
//! 否则会被内置"私网直连"规则抢先命中。
//! iOS 端 PacketTunnelProvider 会做"智能同网段防环回"：本机 Wi-Fi IP 落在
//! lan_cidrs 内时自动把这些规则的出站改为直连。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::AppHandle;
use tauri::Manager;

use crate::core::config_builder::{node_to_outbound, ClashNode};
use crate::core::license;
use crate::core::state::AppState;
use crate::core::uri_parser;

pub const GO_LAN_TAG: &str = "go-lan-home";
pub const GO_LAN_DNS_TAG: &str = "dns-home";

fn default_mode() -> String {
    "manual".into()
}

fn default_managed_server() -> String {
    crate::obf!("https://prism.sarl")
}

fn default_mtu() -> u32 {
    1420
}

/// 【APP30 任务2 / APP48 任务1.2】go-lan-home 运行时隧道 MTU = 1380
/// （不修改用户保存的 `settings.go_lan.wg_config.mtu`，前端仍显示导入值；
/// 仅写入内核 JSON）。
/// 1280（MSS 1240）虽然兼容性最好，但内网 SMB/WebDAV/飞牛影视大流量下
/// 每 1240 字节就切一次包，实测吞吐被锁在 500–600KB/s；1380 → MSS 1340，
/// 扣除 60 字节 WG 头后仍低于 PPPoE(1492) / 蜂窝典型 MTU(1420/1500)，
/// 内网大包一次通过，兼容性与吞吐兼顾。
pub const GO_LAN_RUNTIME_MTU: u32 = 1380;

/// 历史常量：用户配置 MTU 的展示默认值（不再直接写入内核 JSON）
pub const GO_LAN_MTU_FLOOR: u32 = 1280;

/// 历史常量：用户配置 MTU 的展示默认值（对齐家庭 WG 服务端 1420）
pub const GO_LAN_MTU_DEFAULT: u32 = 1420;

// ---------------------------------------------------------------- 数据模型

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WgManualConfig {
    /// 家庭 WG 服务器地址（公网 DDNS/IP）
    pub server: String,
    pub server_port: u16,
    /// 本端私钥
    pub private_key: String,
    /// 服务器对端公钥
    pub peer_public_key: String,
    #[serde(default)]
    pub pre_shared_key: Option<String>,
    /// 隧道内地址，如 10.0.0.2/32
    pub local_ip: String,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
}

/// 【APP40 任务2】单路内网档案（家里 / 公司 / 工作室……）。
/// 每个 `enabled == true` 的档案在内核中生成独立的 `go-lan-{tag}` 出站。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoLanProfile {
    /// 唯一标识，如 "home" / "office" / "studio"
    #[serde(default)]
    pub id: String,
    /// 档案名称（展示用）
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    /// 本机连上该内网对应的局域网 Wi-Fi（物理 IP 落在 lan_cidrs 内）时，
    /// 自动跳过该网段的 WireGuard 隧道，直接走本地局域网。
    /// 【APP45 任务1.1】默认关闭：常见回家网段（192.168.10.0/24 等）极易与
    /// 外部 Wi-Fi 网段重合，默认开启会把回家隧道误判为本地直连（0ms/1ms 假象）。
    #[serde(default)]
    pub bypass_on_local_lan: bool,
    /// 可选：显式指定的 Wi-Fi SSID（留空则按 lan_cidrs 同网段智能匹配）
    #[serde(default)]
    pub local_wifi_ssid: String,
    #[serde(default)]
    pub lan_cidrs: Vec<String>,
    #[serde(default)]
    pub wg_config: Option<WgManualConfig>,
    #[serde(default)]
    pub node_uri: String,
    /// 该档案保存的内网检测目标（如 "192.168.10.253:8001"）
    #[serde(default)]
    pub probe_target: String,
}

impl Default for GoLanProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: false,
            bypass_on_local_lan: false,
            local_wifi_ssid: String::new(),
            lan_cidrs: Vec::new(),
            wg_config: None,
            node_uri: String::new(),
            probe_target: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoLanSettings {
    #[serde(default)]
    pub enabled: bool,
    /// 顶层 On-Demand 开关（旧版兼容；新档案以 profile.bypass_on_local_lan 为准）
    /// 【APP45 任务1.1】默认关闭，理由同 GoLanProfile.bypass_on_local_lan。
    #[serde(default)]
    pub bypass_on_local_lan: bool,
    /// 多路内网档案（APP40）。为空时由 normalize_go_lan_settings 从旧字段迁移。
    #[serde(default)]
    pub profiles: Vec<GoLanProfile>,
    /// 当前前端正在查看的档案 id（仅 UI 状态）
    #[serde(default)]
    pub active_profile_id: String,
    /// manual | managed
    #[serde(default = "default_mode")]
    pub mode: String,
    /// 手动模式：回家节点分享链接
    #[serde(default)]
    pub node_uri: String,
    /// 手动模式：WireGuard 完整参数
    #[serde(default)]
    pub wg_config: Option<WgManualConfig>,
    /// 需要回家路由的网段（如 192.168.1.0/24）
    #[serde(default)]
    pub lan_cidrs: Vec<String>,
    /// 家庭局域网 DNS（如 192.168.1.1），可选
    #[serde(default)]
    pub lan_dns: Option<String>,
    /// 内网域名后缀（如 nas.home），可选
    #[serde(default)]
    pub lan_domains: Vec<String>,
    /// Managed 模式：授权服务器地址
    #[serde(default = "default_managed_server")]
    pub managed_server: String,
    /// Managed 模式：设备识别码
    #[serde(default)]
    pub device_code: String,
    /// Managed 模式：缓存的出站配置（加密缓存见 CHANGELOG；Alpha 明文存储）
    #[serde(default)]
    pub cached_managed_outbound: Option<Value>,
    /// Managed 模式：家庭节点名称（展示用）
    #[serde(default)]
    pub home_name: Option<String>,
}

impl Default for GoLanSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            bypass_on_local_lan: false,
            profiles: Vec::new(),
            active_profile_id: String::new(),
            mode: default_mode(),
            node_uri: String::new(),
            wg_config: None,
            lan_cidrs: Vec::new(),
            lan_dns: None,
            lan_domains: Vec::new(),
            managed_server: default_managed_server(),
            device_code: String::new(),
            cached_managed_outbound: None,
            home_name: None,
        }
    }
}

impl GoLanSettings {
    pub fn is_empty(&self) -> bool {
        self.node_uri.is_empty()
            && self.wg_config.is_none()
            && self.cached_managed_outbound.is_none()
            && self.lan_cidrs.is_empty()
            && self.lan_domains.is_empty()
            && self.profiles.iter().all(|p| p.is_empty())
    }

    /// 当前所有「启用」的档案（保持声明顺序）。
    pub fn enabled_profiles(&self) -> Vec<(String, GoLanProfile)> {
        enabled_profiles(self)
    }
}

impl GoLanProfile {
    pub fn is_empty(&self) -> bool {
        self.node_uri.is_empty()
            && self.wg_config.is_none()
            && self.lan_cidrs.is_empty()
    }

    /// 单路档案是否配置完整（与前端 isGoLanConfigured 对齐）。
    pub fn is_configured(&self, mode: &str, device_code: &str) -> bool {
        if mode == "managed" {
            return !device_code.trim().is_empty() && !self.lan_cidrs.is_empty();
        }
        let has_cidrs = !self.lan_cidrs.is_empty();
        let has_uri = !self.node_uri.trim().is_empty();
        let has_wg = self
            .wg_config
            .as_ref()
            .map(|wg| {
                !wg.server.trim().is_empty()
                    && !wg.private_key.trim().is_empty()
                    && !wg.peer_public_key.trim().is_empty()
            })
            .unwrap_or(false);
        has_cidrs && (has_uri || has_wg)
    }
}

/// 【APP40 任务2】档案 id 净化（仅保留 ASCII 字母数字 / - / _）
fn sanitize_profile_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
        .to_lowercase()
}

/// 【APP40 任务2】为每个启用档案分配内核出站 tag：
/// 第 1 个启用档案恒为 `go-lan-home`（保持旧版完全兼容），
/// 后续依次为 `go-lan-{id}` / `go-lan-2` / `go-lan-3`（保证唯一）。
pub fn enabled_profiles(settings: &GoLanSettings) -> Vec<(String, GoLanProfile)> {
    let mut out: Vec<(String, GoLanProfile)> = Vec::new();
    if !settings.enabled {
        return out;
    }
    let mut used: Vec<String> = Vec::new();
    for profile in settings.profiles.iter().filter(|p| p.enabled) {
        let tag = if out.is_empty() {
            GO_LAN_TAG.to_string()
        } else {
            let id = sanitize_profile_id(&profile.id);
            let candidate = if !id.is_empty() && id != "home" {
                format!("go-lan-{id}")
            } else {
                format!("go-lan-{}", out.len() + 1)
            };
            if used.contains(&candidate) || candidate == GO_LAN_TAG {
                format!("go-lan-{}", out.len() + 1)
            } else {
                candidate
            }
        };
        used.push(tag.clone());
        out.push((tag, profile.clone()));
    }
    out
}

/// 【APP40 任务2】自动无损迁移旧版单配置 + 校正档案字段。
/// 当 profiles 为空且顶层存在旧版 wg_config / node_uri / lan_cidrs 时，
/// 自动生成默认档案「家里」（id = home）。
pub fn normalize_go_lan_settings(settings: &mut GoLanSettings) {
    if settings.profiles.is_empty()
        && (settings.wg_config.is_some()
            || !settings.node_uri.trim().is_empty()
            || !settings.lan_cidrs.is_empty()
            || settings.cached_managed_outbound.is_some())
    {
        settings.profiles.push(GoLanProfile {
            id: "home".into(),
            name: "家里".into(),
            enabled: settings.enabled,
            bypass_on_local_lan: settings.bypass_on_local_lan,
            local_wifi_ssid: String::new(),
            lan_cidrs: settings.lan_cidrs.clone(),
            wg_config: settings.wg_config.clone(),
            node_uri: settings.node_uri.clone(),
            probe_target: String::new(),
        });
    }
    // 档案 id 去重 / 补齐（前端旧数据或手改 JSON 的兜底）
    let mut seen: Vec<String> = Vec::new();
    for (i, p) in settings.profiles.iter_mut().enumerate() {
        if p.name.trim().is_empty() {
            p.name = if p.id.trim().is_empty() {
                format!("内网 {}", i + 1)
            } else {
                p.id.clone()
            };
        }
        let mut id = sanitize_profile_id(&p.id);
        if id.is_empty() || seen.contains(&id) {
            id = format!("profile{}", i + 1);
        }
        while seen.contains(&id) {
            id.push('x');
        }
        p.id = id.clone();
        seen.push(id);
    }
    if settings.active_profile_id.trim().is_empty() {
        if let Some(first) = settings.profiles.first() {
            settings.active_profile_id = first.id.clone();
        }
    } else if !settings
        .profiles
        .iter()
        .any(|p| p.id == settings.active_profile_id)
    {
        settings.active_profile_id = settings
            .profiles
            .first()
            .map(|p| p.id.clone())
            .unwrap_or_default();
    }
    // 【APP45 任务1.2】profiles 非空时，顶层旧版字段 100% 镜像「第 1 个启用档案」
    // 的自身状态（供 resolve_probe_target 等旧代码路径读取）；没有任何启用档案
    // 或档案已清空时，顶层同步置 None / [] / ""。严禁反向回填——用户在前端
    // 「清空配置」后，绝不允许把顶层残留的旧 wg_config 再复制回档案。
    if !settings.profiles.is_empty() {
        if let Some(first_enabled) = settings.profiles.iter().find(|p| p.enabled) {
            settings.wg_config = first_enabled.wg_config.clone();
            settings.node_uri = first_enabled.node_uri.clone();
            settings.lan_cidrs = first_enabled.lan_cidrs.clone();
            settings.bypass_on_local_lan = first_enabled.bypass_on_local_lan;
        } else {
            settings.wg_config = None;
            settings.node_uri = String::new();
            settings.lan_cidrs = Vec::new();
            settings.bypass_on_local_lan = false;
        }
    }
}

/// 【APP40 任务2】档案路由网段（含 WG 虚拟子网/多 Local Address 推导出的 /24）。
pub fn profile_route_cidrs(profile: &GoLanProfile) -> Vec<String> {
    let local_addr = profile
        .wg_config
        .as_ref()
        .map(|wg| wg.local_ip.as_str())
        .unwrap_or("");
    normalize_cidr_list(&profile.lan_cidrs, local_addr)
}

/// 【APP40 任务2】WireGuard 自身虚拟隧道互联网段（永不参与 On-Demand 直连判定）
fn profile_virtual_cidrs(profile: &GoLanProfile) -> Vec<String> {
    let local_addr = profile
        .wg_config
        .as_ref()
        .map(|wg| wg.local_ip.as_str())
        .unwrap_or("");
    let (_primary, mut cidrs) = parse_wg_local_addresses(local_addr);
    if let Some(v) = extract_virtual_subnet(local_addr) {
        if !cidrs.contains(&v) {
            cidrs.push(v);
        }
    }
    cidrs
}

/// 【APP40 任务2】On-Demand 分网段：返回 (走隧道的网段, 命中本地局域网直连的网段)。
pub fn split_profile_cidrs_for_on_demand(
    profile: &GoLanProfile,
    physical_ips: &[std::net::Ipv4Addr],
) -> (Vec<String>, Vec<String>) {
    let cidrs = profile_route_cidrs(profile);
    if !profile.bypass_on_local_lan {
        return (cidrs, Vec::new());
    }
    let virtual_cidrs = profile_virtual_cidrs(profile);
    let mut tunnel: Vec<String> = Vec::new();
    let mut direct: Vec<String> = Vec::new();
    for cidr in cidrs {
        if virtual_cidrs.contains(&cidr) {
            tunnel.push(cidr);
            continue;
        }
        let hit = physical_ips
            .iter()
            .any(|ip| ipv4_in_any_cidr(*ip, std::slice::from_ref(&cidr)));
        if hit {
            direct.push(cidr);
        } else {
            tunnel.push(cidr);
        }
    }
    (tunnel, direct)
}

/// 【APP40 任务2】跨平台枚举本机物理网卡的真实局域网 IPv4。
/// 过滤 utun / tun / ppp / wg / loopback / 172.19.0.x / 169.254.x.x /
/// WireGuard 虚拟地址 10.196.0.2 与 fake-ip 198.18/15。
/// 【APP44 任务6】iOS 主程序同样经 getifaddrs 枚举（Wi-Fi 优先）。
pub fn detect_physical_lan_ipv4s() -> Vec<std::net::Ipv4Addr> {
    // 【APP44 任务6】iOS 主程序不再恒返回空：getifaddrs 枚举 en0（Wi-Fi）/
    // pdp_ip0（蜂窝），保证设置页「局域网地址」展示真实内网 IP，而不是
    // 198.18.x.x 的 fake-ip 或 utun 的 10.196.0.2。按 Wi-Fi > 有线 > 蜂窝排序。
    #[cfg(target_os = "ios")]
    {
        use std::net::Ipv4Addr;
        let mut found: Vec<(u8, Ipv4Addr)> = Vec::new();
        unsafe {
            let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut head) == 0 {
                let mut cur = head;
                while !cur.is_null() {
                    let ifa = &*cur;
                    if !ifa.ifa_addr.is_null()
                        && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET as i32
                    {
                        let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                            .to_string_lossy()
                            .into_owned();
                        let sin = ifa.ifa_addr as *const libc::sockaddr_in;
                        let ip = Ipv4Addr::from(u32::from_be((*sin).sin_addr.s_addr));
                        let rank = if name == "en0" {
                            0
                        } else if name.starts_with("en") || name.starts_with("eth") {
                            1
                        } else if name.starts_with("pdp_ip") {
                            3
                        } else {
                            9
                        };
                        if rank < 9 {
                            found.push((rank, ip));
                        }
                    }
                    cur = ifa.ifa_next;
                }
                libc::freeifaddrs(head);
            }
        }
        found.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.octets().cmp(&b.1.octets())));
        let mut out: Vec<Ipv4Addr> = Vec::new();
        for (_, ip) in found {
            if !is_usable_lan_ip(ip) {
                continue;
            }
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        return out;
    }
    #[cfg(not(target_os = "ios"))]
    {
        let mut candidates: Vec<std::net::Ipv4Addr> = Vec::new();
        #[cfg(target_os = "windows")]
        {
            if let Ok(out) = std::process::Command::new("ipconfig").output() {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut in_virtual_adapter = false;
                for raw in text.lines() {
                    let line = raw.trim_end_matches('\r');
                    let trimmed = line.trim();
                    // 适配器标题行（无缩进、以 ':' 结尾）
                    if !line.starts_with(char::is_whitespace) && trimmed.ends_with(':') {
                        let lower = trimmed.to_lowercase();
                        in_virtual_adapter = [
                            "wireguard",
                            "tap",
                            "tun",
                            "loopback",
                            "vethernet",
                            "hyper-v",
                            "wsl",
                            "vmware",
                            "virtualbox",
                            "bluetooth",
                            "蓝牙",
                        ]
                        .iter()
                        .any(|k| lower.contains(k));
                        continue;
                    }
                    if in_virtual_adapter {
                        continue;
                    }
                    if let Some(idx) = line.rfind(':') {
                        let val = line[idx + 1..].trim();
                        if let Ok(ip) = val.parse::<std::net::Ipv4Addr>() {
                            candidates.push(ip);
                        }
                    }
                }
            }
        }
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "android"))]
        {
            let output = std::process::Command::new("ifconfig")
                .output()
                .or_else(|_| std::process::Command::new("ip").arg("-4").arg("addr").output());
            if let Ok(out) = output {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut current_virtual = false;
                for raw in text.lines() {
                    let line = raw.trim_end_matches('\r');
                    if !line.starts_with(char::is_whitespace) {
                        let name = line.split(':').next().unwrap_or("").trim();
                        current_virtual = [
                            "utun", "tun", "ppp", "wg", "llw", "awdl", "lo",
                        ]
                        .iter()
                        .any(|k| name.starts_with(k));
                    }
                    if current_virtual {
                        continue;
                    }
                    let trimmed = line.trim();
                    if let Some(rest) = trimmed.strip_prefix("inet ") {
                        let ip_s = rest.split_whitespace().next().unwrap_or("");
                        if let Ok(ip) = ip_s.parse::<std::net::Ipv4Addr>() {
                            candidates.push(ip);
                        }
                    } else if trimmed.starts_with("inet ") {
                        // `ip -4 addr` 输出：inet 192.168.10.88/24 brd ...
                        let ip_s = trimmed
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("")
                            .split('/')
                            .next()
                            .unwrap_or("");
                        if let Ok(ip) = ip_s.parse::<std::net::Ipv4Addr>() {
                            candidates.push(ip);
                        }
                    }
                }
            }
        }
        let mut out: Vec<std::net::Ipv4Addr> = Vec::new();
        for ip in candidates {
            if !is_usable_lan_ip(ip) {
                continue;
            }
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        out
    }
}

/// 【APP44 任务6】判定是否可作为「本机局域网地址」展示 / 用于 On-Demand 判定：
/// - 排除 loopback / 未指定 / 169.254 链路本地；
/// - 排除 TUN fake-ip 段 198.18.0.0/15 与容器段 172.19.0.0/16、WG 虚拟地址；
/// - 只接受私网（10/8、172.16/12、192.168/16）与 CGNAT 100.64/10。
fn is_usable_lan_ip(ip: std::net::Ipv4Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() {
        return false;
    }
    let o = ip.octets();
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return false;
    }
    if o[0] == 172 && o[1] == 19 {
        return false;
    }
    if ip.to_string() == "10.196.0.2" {
        return false;
    }
    o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
}

/// 【APP40 任务2】每个启用档案的运行时元数据（供 iOS 扩展侧 On-Demand 判定 /
/// 侧车 golan_profiles.json 使用，不写入内核 JSON，避免 unknown field）。
pub fn profiles_metadata(settings: &GoLanSettings) -> Vec<Value> {
    enabled_profiles(settings)
        .into_iter()
        .map(|(tag, profile)| {
            json!({
                "tag": tag,
                "name": profile.name,
                "cidrs": profile_route_cidrs(&profile),
                "bypassOnLocalLan": profile.bypass_on_local_lan,
            })
        })
        .collect()
}

/// APP 任务5：Go Lan 配置完整性检查（未配置时后端兜底拦截启用）。
/// 与前端 ipc.ts `isGoLanConfigured` 逻辑保持一致：
/// - manual：lan_cidrs 非空，且（node_uri 非空，或 wg_config 的
///   server/private_key/peer_public_key 均非空）
/// - managed：device_code 非空且 lan_cidrs 非空（已成功拉取过配置）
pub fn is_configured(lan: &GoLanSettings) -> bool {
    // 【APP40 任务2】多路档案模式：只要任意「启用」档案配置完整即视为已配置
    if !lan.profiles.is_empty() {
        return lan
            .profiles
            .iter()
            .filter(|p| p.enabled)
            .any(|p| p.is_configured(&lan.mode, &lan.device_code));
    }
    if lan.mode == "manual" {
        let has_cidrs = !lan.lan_cidrs.is_empty();
        let has_uri = !lan.node_uri.trim().is_empty();
        let has_wg = lan
            .wg_config
            .as_ref()
            .map(|wg| {
                !wg.server.trim().is_empty()
                    && !wg.private_key.trim().is_empty()
                    && !wg.peer_public_key.trim().is_empty()
            })
            .unwrap_or(false);
        has_cidrs && (has_uri || has_wg)
    } else {
        !lan.device_code.trim().is_empty() && !lan.lan_cidrs.is_empty()
    }
}

// ---------------------------------------------------------------- WireGuard 密钥规范化（APP-6 任务1）

/// WireGuard 密钥规范化：清洗 → 解码 → 校验 32 字节 → 重编码标准 Base64。
///
/// 背景：开启 Go Lan 后内核报 `decode pre shared key for peer 0: illegal
/// base64 data at input byte 43`。标准 WG 密钥为 32 字节 = 44 位 Base64
/// （第 44 字符固定 `=`）。`wireguard://` 导入时末尾 `=` 常被 URL 编码成
/// `%3D`（byte 43 变成 `%`），或 .conf 解析时引入引号/换行/URL-safe 字符，
/// 内核 `base64.StdEncoding` 解析失败直接拒绝启动。
///
/// 处理步骤：
/// 1. URL 百分号解码（%3D/=、%2B/+、%2F//、%20/空格）；
/// 2. 剥离首尾空白、`\r`/`\n`、单双引号，截断行内注释 `#`；
/// 3. 兼容 URL-safe Base64（`-`→`+`、`_`→`/`）与 64 位 Hex 直通；
/// 4. 只保留合法 Base64 数据字符，32 字节密钥有效数据位固定 43 字符；
/// 5. 解码校验 32 字节（且不全为 0）后用标准 Base64 重编码返回。
///
/// 返回 None 表示输入不是合法密钥：必填密钥（private_key /
/// peer_public_key）应跳过注入，可选 pre_shared_key 应忽略。
pub fn normalize_wg_key(raw: &str) -> Option<String> {
    use base64::engine::GeneralPurpose;
    use base64::engine::GeneralPurposeConfig;
    use base64::Engine as _;
    // 宽松解码引擎：允许非规范尾位（与 Go base64.StdEncoding 行为一致），
    // 但输出统一走标准重编码，保证内核拿到的一定是规范 44 位
    let lenient = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    // 1. URL 百分号解码
    let mut s = raw
        .replace("%3D", "=")
        .replace("%3d", "=")
        .replace("%2B", "+")
        .replace("%2b", "+")
        .replace("%2F", "/")
        .replace("%2f", "/")
        .replace("%20", " ");
    // 2. 剥离空白、引号、行内注释
    s = s.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
    if let Some(idx) = s.find('#') {
        s.truncate(idx);
    }
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // 3a. Hex 直通：64 位纯十六进制即 32 字节原始密钥
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();
        return valid_wg_bytes(&lenient, &bytes);
    }
    // 3b. URL-safe Base64 → 标准字符
    let replaced = s.replace('-', "+").replace('_', "/");
    // 4. 只保留合法 Base64 数据字符（空白/引号/换行残留一并剔除）；
    //    32 字节 → 43 个数据字符 + 1 个 `=` 填充
    let cleaned: String = replaced
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/')
        .collect();
    if cleaned.len() != 43 {
        return None;
    }
    let bytes = lenient.decode(format!("{cleaned}=").as_bytes()).ok()?;
    // 5. 校验 32 字节后重编码为标准 44 位 Base64
    valid_wg_bytes(&lenient, &bytes)
}

fn valid_wg_bytes(engine: &impl base64::Engine, bytes: &[u8]) -> Option<String> {
    if bytes.len() != 32 || bytes.iter().all(|b| *b == 0) {
        return None;
    }
    Some(engine.encode(bytes))
}

/// 手写百分号解码（%XX），用于 wireguard:// 链接的密钥/地址参数。
/// 不把裸 `+` 转空格——Base64 的 `+` 必须保留（残余非法字符会在
/// normalize_wg_key 的清洗步骤剔除，不影响结果）。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 解析 endpoint（host:port / [IPv6]:port），无端口默认 51820
fn split_endpoint(hostport: &str) -> Result<(String, u16), String> {
    let hostport = hostport.trim().trim_end_matches('/');
    if let Some(stripped) = hostport.strip_prefix('[') {
        let (host, rest) = stripped.split_once(']').ok_or("IPv6 endpoint 缺少 ']'")?;
        let port = rest
            .trim_start_matches(':')
            .parse::<u16>()
            .map_err(|_| "endpoint 端口无效")?;
        return Ok((host.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|_| "endpoint 端口无效")?;
            Ok((h.to_string(), port))
        }
        None => Ok((hostport.to_string(), 51820)),
    }
}

/// 【APP30 任务3】WireGuard Endpoint 域名 → IPv4（同步，60s 短缓存 + DoH 优先）。
///
/// log8.txt 实证：首次启动内存缓存为空时直接跳过解析，域名 `ishow.indevs.in`
/// 原样留在配置里，扩展侧系统 `getaddrinfo` 读到旧缓存 `14.105.65.44`；
/// 第二次启动才连到正确的新 IP `14.105.65.122`。
///
/// 解析顺序：
/// 1. 已是合法 IP 字面量 → 原样返回；
/// 2. 60s 内缓存命中 → 0ms 返回（超过 60s 自动重解析，适配家庭 DDNS）；
/// 3. 同步 DoH（阿里 223.5.5.5 → 腾讯 1.12.12.12，`.no_proxy()` 直连，
///    1500ms 上限），取 `type == 1` 的最新 IPv4 记录；
/// 4. DoH 失败才回退系统 `ToSocketAddrs`（800ms）；
/// 5. 全部超时 → 后台线程继续解析并回填缓存，本次原样返回域名。
pub fn resolve_endpoint_host_to_ip(host: &str) -> String {
    let host = host.trim().trim_end_matches('/');
    if host.is_empty() {
        return host.to_string();
    }
    // 1. 已是 IP 字面量
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    let key = host.to_ascii_lowercase();
    if let Some(ip) = endpoint_cache_get(&key) {
        return ip;
    }
    // 2. 同步 DoH（国内 223.5.5.5 / 1.12.12.12，1500ms）
    if let Some(ip) = doh_resolve_ipv4(host) {
        endpoint_cache_put(&key, &ip);
        return ip;
    }
    // 3. DoH 失败：回退系统原生解析（800ms 硬性限时）
    if let Some(ip) = resolve_with_deadline(host, 800) {
        endpoint_cache_put(&key, &ip);
        return ip;
    }
    // 4. 超时：后台继续解析并回填缓存，本次先原样返回域名
    let host_owned = host.to_string();
    std::thread::spawn(move || {
        if let Some(ip) =
            doh_resolve_ipv4(&host_owned).or_else(|| resolve_with_deadline(&host_owned, 5000))
        {
            endpoint_cache_put(&host_owned.to_ascii_lowercase(), &ip);
        }
    });
    host.to_string()
}

/// 【APP30 任务3】Endpoint 解析缓存有效期：60 秒。家庭宽带 DDNS 随时变 IP，
/// 过长缓存会把第一次启动的旧 IP 一直带到后续会话。
const ENDPOINT_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// 【APP30 任务3】WireGuard Endpoint 域名 → IPv4 的进程内缓存（含时间戳）。
fn endpoint_ip_cache(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, (String, std::time::Instant)>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, (String, std::time::Instant)>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn endpoint_cache_get(key: &str) -> Option<String> {
    let mut cache = endpoint_ip_cache().lock().ok()?;
    if let Some((ip, at)) = cache.get(key) {
        if at.elapsed() < ENDPOINT_CACHE_TTL {
            return Some(ip.clone());
        }
        cache.remove(key);
    }
    None
}

fn endpoint_cache_put(key: &str, ip: &str) {
    if let Ok(mut c) = endpoint_ip_cache().lock() {
        c.insert(
            key.to_string(),
            (ip.to_string(), std::time::Instant::now()),
        );
    }
}

/// 【APP30 任务3】同步 DoH 解析：工作线程内建独立 current-thread runtime，
/// 调用方最多阻塞 1500ms，绝不影响主 async runtime（在 tokio 运行中直接
/// block_on 会 panic）。
fn doh_resolve_ipv4(host: &str) -> Option<String> {
    let host_owned = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        let result = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(doh_query_ipv4(&host_owned)),
            Err(_) => None,
        };
        let _ = tx.send(result);
    });
    rx.recv_timeout(std::time::Duration::from_millis(1500))
        .ok()
        .flatten()
}

/// 阿里云 DoH（223.5.5.5）与腾讯 DoH（1.12.12.12）并发不可用时的顺序请求。
async fn doh_query_ipv4(host: &str) -> Option<String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_millis(800))
        .timeout(std::time::Duration::from_millis(1500))
        .build()
        .ok()?;
    let urls = [
        format!("https://223.5.5.5/resolve?name={host}&type=A"),
        format!("https://1.12.12.12/dns-query?name={host}&type=A"),
    ];
    for url in urls {
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.json::<Value>().await else {
            continue;
        };
        if let Some(ip) = pick_ipv4_a_record(&body) {
            return Some(ip);
        }
    }
    None
}

// ---------------- 【APP45 任务2.2】代理节点域名批量预解析 ----------------
// 【APP50 任务2】config_builder 重新启用：log11 实证 iOS 扩展内节点域名
// UDP DNS 被 utun 自拦截失败（0ms 超时），主进程构建期 DoH 预解析为
// 公网 IPv4 写入 server（SNI/Host 保留原域名），内核 dns-direct 兜底。
const NODE_HOST_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

fn node_host_cache(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, (String, std::time::Instant)>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, (String, std::time::Instant)>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 【APP45 任务2.2】并发 DoH 批量解析代理节点域名 → 真实公网 IPv4。
///
/// 背景：`hk1.xxx.the-best-airport.com` 等多级动态域名在 iOS
/// NEPacketTunnelProvider 扩展内经系统 DNS 解析会被 utun 自拦截超时；
/// 主进程（有正常网络权限）在构建配置前并发 DoH 解析并把节点 server
/// 替换为真实 IPv4（TLS server_name 已独立保存 SNI，不受影响），内核
/// 0ms 直接 TCP+TLS 握手。解析失败/超时的域名不在返回表内，调用方保留
/// 原域名，由内核 dns-direct（UDP 223.5.5.5 + detour direct + 物理网卡
/// 绑定）兜底解析（保险 2）。
///
/// 整体在独立工作线程 + current_thread runtime 内并发执行，调用方最多
/// 阻塞 2600ms；命中 300s 缓存的域名 0ms 返回。拒绝返回环回/未指定/
/// 私网/fake-ip（198.18/15）等非法解析结果。
pub(crate) fn doh_resolve_node_hosts_ipv4(
    hosts: &[String],
) -> std::collections::HashMap<String, String> {
    let mut out: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut todo: Vec<String> = Vec::new();
    for h in hosts {
        let key = h.trim().to_ascii_lowercase();
        if key.is_empty() || key.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }
        // 300s 缓存命中直接用
        if let Ok(mut c) = node_host_cache().lock() {
            if let Some((ip, at)) = c.get(&key) {
                if at.elapsed() < NODE_HOST_CACHE_TTL {
                    out.insert(key, ip.clone());
                    continue;
                }
                c.remove(&key);
            }
        }
        if !todo.contains(&key) {
            todo.push(key);
        }
    }
    if todo.is_empty() {
        return out;
    }
    let (tx, rx) = std::sync::mpsc::channel::<Vec<(String, Option<String>)>>();
    std::thread::spawn(move || {
        let result = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(async move {
                let mut set: tokio::task::JoinSet<(String, Option<String>)> =
                    tokio::task::JoinSet::new();
                for host in todo {
                    set.spawn(async move {
                        let ip = doh_query_ipv4(&host).await;
                        (host, ip)
                    });
                }
                let mut done = Vec::new();
                while let Some(joined) = set.join_next().await {
                    if let Ok(pair) = joined {
                        done.push(pair);
                    }
                }
                done
            }),
            Err(_) => Vec::new(),
        };
        let _ = tx.send(result);
    });
    let resolved = rx
        .recv_timeout(std::time::Duration::from_millis(2600))
        .unwrap_or_default();
    for (host, maybe_ip) in resolved {
        let Some(ip) = maybe_ip else { continue };
        // 只接受真实公网 IPv4：拒绝环回/0.0.0.0/私网/fake-ip 等污染结果
        let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() else {
            continue;
        };
        if v4.is_loopback()
            || v4.is_unspecified()
            || v4.is_private()
            || v4.is_link_local()
            || v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19)
        {
            continue;
        }
        if let Ok(mut c) = node_host_cache().lock() {
            c.insert(host.clone(), (ip.clone(), std::time::Instant::now()));
        }
        out.insert(host, ip);
    }
    out
}

/// 从 DoH JSON 的 Answer 数组取第一条 `type == 1` 的合法 IPv4 记录。
fn pick_ipv4_a_record(body: &Value) -> Option<String> {
    let answers = body
        .get("Answer")
        .or_else(|| body.get("answer"))
        .and_then(Value::as_array)?;
    for item in answers {
        if item.get("type").and_then(Value::as_u64) != Some(1) {
            continue;
        }
        let Some(data) = item.get("data").and_then(Value::as_str) else {
            continue;
        };
        if data.parse::<std::net::Ipv4Addr>().is_ok() {
            return Some(data.to_string());
        }
    }
    None
}

/// 限时域名解析：工作线程解析 + 通道超时，绝不阻塞调用方。
fn resolve_with_deadline(host: &str, timeout_ms: u64) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
    let host_owned = host.to_string();
    std::thread::spawn(move || {
        let mut result: Option<String> = None;
        if let Ok(mut addrs) =
            std::net::ToSocketAddrs::to_socket_addrs(&(host_owned.as_str(), 51820u16))
        {
            let mut v6: Option<String> = None;
            for a in addrs.by_ref() {
                match a {
                    std::net::SocketAddr::V4(v4) => {
                        result = Some(v4.ip().to_string());
                        break;
                    }
                    std::net::SocketAddr::V6(v6a) => {
                        if v6.is_none() {
                            v6 = Some(v6a.ip().to_string());
                        }
                    }
                }
            }
            if result.is_none() {
                result = v6;
            }
        }
        let _ = tx.send(result);
    });
    rx.recv_timeout(std::time::Duration::from_millis(timeout_ms))
        .ok()
        .flatten()
}

/// 解析 `wireguard://`（含 `wg://`）分享链接 → WgManualConfig。
///
/// 格式：`wireguard://<私钥>@<host>:<port>/?address=10.0.0.2/32&publickey=...&presharedkey=...&mtu=...`
/// 密钥参数先 percent_decode 再 normalize_wg_key；可选 presharedkey/psk
/// 无效时置 None（忽略，不阻断连接）。
pub fn parse_wireguard_uri(uri: &str) -> Result<WgManualConfig, String> {
    let trimmed = uri.trim();
    let rest = trimmed
        .strip_prefix("wireguard://")
        .or_else(|| trimmed.strip_prefix("wg://"))
        .ok_or("不是 wireguard:// 链接")?;
    let (userinfo, rest2) = rest.split_once('@').ok_or("缺少 '@'（私钥段）")?;
    let (hostport, query) = match rest2.split_once('?') {
        Some((h, q)) => (h, q),
        None => (rest2, ""),
    };
    let private_key = normalize_wg_key(&percent_decode(userinfo))
        .ok_or("私钥不是合法的 32 字节 WireGuard 密钥")?;
    let (server, server_port) = split_endpoint(hostport)?;
    let mut peer_public_key: Option<String> = None;
    let mut pre_shared_key: Option<String> = None;
    let mut local_ip = String::new();
    let mut mtu = default_mtu();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let val = percent_decode(v);
        match k.trim().to_ascii_lowercase().as_str() {
            "publickey" | "peerpublickey" | "peer_public_key" => {
                peer_public_key = normalize_wg_key(&val);
            }
            // 可选字段：无效 PSK 直接忽略
            "presharedkey" | "psk" | "preshared_key" | "pre_shared_key" => {
                pre_shared_key = normalize_wg_key(&val);
            }
            "address" | "ip" | "localaddress" | "local_address" => {
                if local_ip.is_empty() {
                    local_ip = val;
                }
            }
            "mtu" => mtu = val.trim().parse().unwrap_or(default_mtu()),
            _ => {}
        }
    }
    let peer_public_key =
        peer_public_key.ok_or("publickey 缺失或不是合法的 32 字节密钥")?;
    if local_ip.is_empty() {
        local_ip = "10.0.0.2/32".into();
    }
    Ok(WgManualConfig {
        server,
        server_port,
        private_key,
        peer_public_key,
        pre_shared_key,
        local_ip,
        mtu,
    })
}

/// 解析 wg-quick 风格 `.conf` 文本 → WgManualConfig。
///
/// 铁律：键值必须用 `split_once('=')` 切割——`split('=').nth(1)` 会把
/// 密钥末尾的填充 `=` 吃掉，正是 byte 43 报错的来源之一。
/// 可选 PresharedKey 无效时置 None。
///
/// 【APP-4 任务4】折行合并解析（与前端 GoLanModal.parseWgConf 同一算法）：
/// 只有以已知 WG 关键字开头的行才开启新字段，无 `=` 的非注释/非节名行
/// 自动拼接到上一字段末尾——兼容微信/IM 把 44 位 Base64 密钥折成两行的场景。
pub fn parse_wireguard_conf(text: &str) -> Result<WgManualConfig, String> {
    const KNOWN_KEYS: [&str; 11] = [
        "privatekey",
        "address",
        "dns",
        "mtu",
        "listenport",
        "table",
        "publickey",
        "presharedkey",
        "allowedips",
        "endpoint",
        "persistentkeepalive",
    ];
    // (是否 [Peer] 段, 键, 值)
    let mut entries: Vec<(bool, String, String)> = Vec::new();
    let mut in_peer = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.eq_ignore_ascii_case("[Interface]") {
            in_peer = false;
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") {
            in_peer = true;
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_ascii_lowercase();
            if KNOWN_KEYS.contains(&key.as_str()) {
                // 行内注释剔除（# 之后的内容）
                let value = line[eq + 1..]
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                entries.push((in_peer, key, value));
                continue;
            }
            // 含 '=' 但不是已知键 → 视为折行续行（Base64 密钥末尾的 = 填充），
            // 落入下方续行拼接；与前端 GoLanModal 的 KNOWN_KEYS 正则算法一致。
        }
        // 续行：无缝拼接到上一字段末尾（微信折行 / Base64 尾位 = 片段）
        if let Some(last) = entries.last_mut() {
            last.2.push_str(&line.split_whitespace().collect::<String>());
        }
    }
    let get = |peer: bool, key: &str| {
        entries
            .iter()
            .find(|(p, k, _)| *p == peer && k == key)
            .map(|(_, _, v)| v.clone())
    };
    let private_key = normalize_wg_key(&get(false, "privatekey").ok_or("缺少 PrivateKey")?)
        .ok_or("PrivateKey 不是合法的 32 字节密钥")?;
    let peer_public_key =
        normalize_wg_key(&get(true, "publickey").ok_or("缺少 Peer PublicKey")?)
            .ok_or("Peer PublicKey 不是合法的 32 字节密钥")?;
    let pre_shared_key = get(true, "presharedkey").and_then(|k| normalize_wg_key(&k));
    let local_ip = get(false, "address")
        .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "10.0.0.2/32".into());
    let mtu = get(false, "mtu")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(default_mtu);
    let endpoint = get(true, "endpoint").ok_or("缺少 Endpoint")?;
    let (server, server_port) = split_endpoint(&endpoint)?;
    Ok(WgManualConfig {
        server,
        server_port,
        private_key,
        peer_public_key,
        pre_shared_key,
        local_ip,
        mtu,
    })
}

// ---------------------------------------------------------------- 持久化

pub fn load(data_dir: &std::path::Path) -> GoLanSettings {
    let path = data_dir.join("go_lan.json");
    let mut settings = match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str::<GoLanSettings>(&text).unwrap_or_default(),
        Err(_) => GoLanSettings::default(),
    };
    // 【APP40 任务2】旧版单配置自动无损迁移为默认档案「家里」
    normalize_go_lan_settings(&mut settings);
    settings
}

pub fn save(data_dir: &std::path::Path, settings: &GoLanSettings) -> Result<(), String> {
    let path = data_dir.join("go_lan.json");
    let text = serde_json::to_string_pretty(settings).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- 内网 IP 连通性检测（APP-5 任务2）

/// 内网 IP 连通性检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoLanProbeResult {
    pub reachable: bool,
    pub target_ip: String,
    pub latency_ms: Option<u64>,
    pub message: String,
}

/// 【APP6 任务2】从 WireGuard local_address（如 "10.1.8.2/24"）推导对端
/// 网关 IP（同网段 .1）。无 /24 掩码时按 normalize_local_address 的 /24
/// 扩展逻辑推导；返回 None 表示无法推导。
pub fn derive_gateway_from_local_address(local_addr: &str) -> Option<String> {
    // 【APP15 任务1.1】先按逗号/分号/空白拆分并只取第 1 个主隧道地址，
    // 否则整串（"10.196.0.2/32,192.168.10.222/24"）解析失败导致推导不出网关。
    let (primary, _extras) = parse_wg_local_addresses(local_addr);
    let (ip_s, mask_s) = primary.split_once('/')?;
    let ip: std::net::Ipv4Addr = ip_s.parse().ok()?;
    let mask: u8 = mask_s.parse().ok()?;
    if mask == 0 {
        return None;
    }
    // 掩码不足 /24 按 /24 网段找 .1；更宽同理取该网段首个可用主机
    let eff_mask = mask.min(24);
    let bits = u32::from(ip);
    let net_mask: u32 = u32::MAX << (32 - eff_mask);
    let net = bits & net_mask;
    Some(std::net::Ipv4Addr::from(net + 1).to_string())
}

/// 【APP6 任务2】推导探测目标：显式传入的 target_ip 优先；
/// 未传时自动从 local_address 推导家庭网关（10.1.8.2/24 → 10.1.8.1）。
pub fn resolve_probe_target(target_ip_raw: Option<&str>, lan: &GoLanSettings) -> Option<String> {
    let explicit = target_ip_raw
        .map(strip_invisible_and_non_ascii)
        .map(|s| s.replace(|c: char| c.is_whitespace(), ""))
        .map(|s| {
            s.split(';').next().unwrap_or("").split(':').next().unwrap_or("").split('/').next().unwrap_or("").to_string()
        })
        .filter(|s| !s.is_empty());
    if let Some(t) = explicit {
        return Some(t);
    }
    let local = lan
        .wg_config
        .as_ref()
        .map(|wg| wg.local_ip.as_str())
        .unwrap_or("");
    derive_gateway_from_local_address(local)
}

/// 【APP40 任务1】单端口探测命中结果（协议 + 延迟）。
struct PortProbeHit {
    scheme: String,
    latency_ms: u64,
}

/// 单端口 HTTP/HTTPS 探测窗口（Clash API 与直连均 2500ms）
const PROBE_PORT_WINDOW_MS: u64 = 2500;

/// 【APP40 任务1】经 Clash API 对指定 `go-lan-*` 出站做单协议延迟测试。
/// 请求由 sing-box 内核 ctx 承载，`timeout` 到期立即由内核 Close() 销毁
/// 底层连接，绝不会残留半开连接（log7/log8 中 2m7s 超时的根因）。
async fn probe_clash_delay_for_tag(
    tag: &str,
    ip: &str,
    port: u16,
    scheme: &str,
    path: &str,
    api_addr: &str,
    api_secret: &str,
    timeout_ms: u64,
) -> Result<u64, String> {
    if api_addr.is_empty() {
        return Err("Clash API 未就绪".to_string());
    }
    let base = api_addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string();
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_millis(800))
        .timeout(std::time::Duration::from_millis(timeout_ms + 300))
        .build()
        .map_err(|e| format!("Clash 探测客户端构建失败: {e}"))?;
    let target = format!("{scheme}://{ip}:{port}{path}");
    let mut req = client
        .get(format!("http://{base}/proxies/{tag}/delay"))
        .query(&[("url", target.as_str()), ("timeout", &timeout_ms.to_string())]);
    if !api_secret.is_empty() {
        req = req.bearer_auth(api_secret);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("Clash API 请求失败: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if status == 200 {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            // 严格校验：必须无 message 错误字段且 delay > 0，
            // 否则内核错误响应会被误判为成功延迟。
            if v.get("message").is_none() {
                if let Some(d) = v.get("delay").and_then(|d| d.as_u64()) {
                    if d > 0 {
                        return Ok(d);
                    }
                }
            }
        }
    }
    Err(format!("Clash API HTTP {status}"))
}

/// 【APP40 任务1】应用层直连探测：开启 `danger_accept_invalid_certs`
/// （忽略内网自签名证书）、禁止重定向、2500ms 超时。
/// 返回 (状态码, 毫秒)。
async fn probe_app_layer(
    ip: &str,
    port: u16,
    scheme: &str,
    path: &str,
) -> Result<(u16, u64), String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(std::time::Duration::from_millis(PROBE_PORT_WINDOW_MS))
        .timeout(std::time::Duration::from_millis(PROBE_PORT_WINDOW_MS))
        .build()
        .map_err(|e| format!("探测客户端构建失败: {e}"))?;
    let url = format!("{scheme}://{ip}:{port}{path}");
    let start = std::time::Instant::now();
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let ms = start.elapsed().as_millis() as u64;
    // 本地混合代理的 502/504 不算目标真实应答
    if status == 502 || status == 504 {
        return Err(format!("代理返回 HTTP {status}"));
    }
    Ok((status, ms))
}

/// 【APP40 任务1】仅对用户指定的唯一端口做一次 TCP 握手兜底
/// （非 Web 端口如 3389 / 22 / 445），绝不触碰任何其他端口。
async fn probe_single_port_tcp(ip: &str, port: u16) -> Result<u64, String> {
    let start = std::time::Instant::now();
    let fut = tokio::net::TcpStream::connect((ip, port));
    match tokio::time::timeout(
        std::time::Duration::from_millis(PROBE_PORT_WINDOW_MS),
        fut,
    )
    .await
    {
        Ok(Ok(_stream)) => Ok(start.elapsed().as_millis() as u64),
        Ok(Err(e)) => Err(format!("TCP 连接失败: {e}")),
        Err(_) => Err("TCP 握手超时".to_string()),
    }
}

/// 【APP40 任务1】只在用户指定的唯一 `IP:端口` 上并发探测 HTTPS / HTTP，
/// 返回识别出的协议与延迟。显式协议优先；裸 `IP:端口` 时 HTTP 有效
/// 状态码优先（避免向 HTTP 端口发 HTTPS 得到 400 被误判为 HTTPS）。
async fn probe_web_protocols(
    ip: &str,
    port: u16,
    scheme_hint: Option<&str>,
    path: &str,
    api_addr: &str,
    api_secret: &str,
    tag: &str,
) -> Result<PortProbeHit, String> {
    let schemes: Vec<&str> = match scheme_hint {
        Some(s) => vec![s],
        None => vec!["http", "https"],
    };
    // 第 1 步：Clash API（经对应 go-lan-* 隧道，内核级超时）
    let mut tasks: tokio::task::JoinSet<(String, Result<u64, String>)> =
        tokio::task::JoinSet::new();
    for scheme in &schemes {
        let (ip_o, path_o, api_o, secret_o, tag_o) = (
            ip.to_string(),
            path.to_string(),
            api_addr.to_string(),
            api_secret.to_string(),
            tag.to_string(),
        );
        let scheme_o = scheme.to_string();
        tasks.spawn(async move {
            let res = probe_clash_delay_for_tag(
                &tag_o,
                &ip_o,
                port,
                &scheme_o,
                &path_o,
                &api_o,
                &secret_o,
                PROBE_PORT_WINDOW_MS,
            )
            .await;
            (scheme_o, res)
        });
    }
    let mut last_err = String::from("Clash API 探测超时");
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((scheme, Ok(ms))) => {
                return Ok(PortProbeHit {
                    scheme: scheme.to_uppercase(),
                    latency_ms: ms,
                });
            }
            Ok((_, Err(e))) => last_err = e,
            Err(_) => continue,
        }
    }
    // 第 2 步：应用层直连智能识别（忽略自签名证书 / 不跟随重定向）
    let mut direct_tasks: tokio::task::JoinSet<(String, Result<(u16, u64), String>)> =
        tokio::task::JoinSet::new();
    for scheme in &schemes {
        let (ip_o, path_o) = (ip.to_string(), path.to_string());
        let scheme_o = scheme.to_string();
        direct_tasks.spawn(async move {
            let res = probe_app_layer(&ip_o, port, &scheme_o, &path_o).await;
            (scheme_o, res)
        });
    }
    let mut http_hit: Option<(u64, u16)> = None;
    let mut https_hit: Option<(u64, u16)> = None;
    while let Some(joined) = direct_tasks.join_next().await {
        match joined {
            Ok((scheme, Ok((status, ms)))) => {
                // 400 多半是「HTTP 服务收到 HTTPS 请求」，不采纳为 HTTPS
                if scheme == "https" && status != 400 {
                    https_hit = Some((ms, status));
                } else if scheme == "http" {
                    http_hit = Some((ms, status));
                }
            }
            Ok((_, Err(e))) => last_err = e,
            Err(_) => continue,
        }
    }
    if scheme_hint.is_none() {
        // 裸 IP:端口：HTTP 有有效应答优先（兼容 HTTP 端口误发 TLS 的场景）
        if let Some((ms, _)) = http_hit {
            return Ok(PortProbeHit {
                scheme: "HTTP".into(),
                latency_ms: ms,
            });
        }
    }
    if let Some((ms, _)) = https_hit.or(http_hit) {
        return Ok(PortProbeHit {
            scheme: if https_hit.is_some() { "HTTPS" } else { "HTTP" }.into(),
            latency_ms: ms,
        });
    }
    Err(last_err)
}

/// 【APP40 任务1】精准检测输入解析结果。
struct ProbeInput {
    ip: String,
    port: u16,
    /// 显式协议（http / https）；裸 `IP:端口` 为 None
    scheme: Option<String>,
    path: String,
}

/// 未输入端口时的友好提示（中文 / 英文）。
const PROBE_MISSING_PORT_MSG: &str =
    "⚠️ 请输入「IP:端口」格式进行精准检测（例如 192.168.10.253:8001）";

/// 【APP40 任务1】严格解析 `IP:端口` / `http(s)://IP:端口/path`：
/// - 显式 `http://` 未写端口 → 默认 80；显式 `https://` 未写端口 → 443；
/// - 【APP50 任务3】纯 IP（无端口且无协议头）→ 端口哨兵 0，探测阶段仅
///   依次尝试 http:80 → https:443（最多 2 次 Clash API 延迟测试），
///   绝不盲目扫描其他端口。
fn parse_probe_input(raw: &str) -> Result<ProbeInput, String> {
    let no_invisible = strip_invisible_and_non_ascii(raw);
    let first = no_invisible.split(';').next().unwrap_or("").trim();
    let (scheme, rest) = if let Some(r) = first.strip_prefix("https://") {
        (Some("https"), r)
    } else if let Some(r) = first.strip_prefix("http://") {
        (Some("http"), r)
    } else {
        (None, first.trim_start_matches("//"))
    };
    // 剥离路径与 CIDR 掩码
    let host_port = rest.split('/').next().unwrap_or("");
    let (host, port, path) = {
        let p = match rest.split_once('/') {
            Some((_, tail)) => format!("/{}", tail.trim_start_matches('/')),
            None => "/".to_string(),
        };
        // IPv6 字面量（[::1]:port）本项目不处理
        if host_port.contains('[') {
            return Err("暂不支持 IPv6 目标，请输入 IPv4:端口（如 192.168.10.253:8001）".into());
        }
        match host_port.rsplit_once(':') {
            Some((h, port_s)) if !h.is_empty() => {
                let parsed = port_s.parse::<u16>().ok().filter(|p| *p > 0);
                match parsed {
                    Some(port_num) => (h.to_string(), port_num, p.clone()),
                    None => {
                        if let Some(default) = p_scheme_default(scheme) {
                            (host_port.to_string(), default, p.clone())
                        } else {
                            return Err(PROBE_MISSING_PORT_MSG.into());
                        }
                    }
                }
            }
            _ => match p_scheme_default(scheme) {
                Some(default) => (host_port.to_string(), default, p.clone()),
                // 【APP50 任务3】纯 IP → 端口哨兵 0（默认探测 80/443）
                None => (host_port.to_string(), 0, p.clone()),
            },
        }
    };
    if host.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(format!("IP 地址格式无效: {host}"));
    }
    Ok(ProbeInput {
        ip: host,
        port,
        scheme: scheme.map(str::to_string),
        path,
    })
}

fn p_scheme_default(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    }
}

/// 【APP15 任务2】兼容旧调用：返回 (ip, 显式端口)。
/// 【APP50 任务3】纯 IP 的端口哨兵 0 在此映射回 None（语义：未指定端口）。
pub fn parse_probe_target(raw: &str) -> (String, Option<u16>) {
    match parse_probe_input(raw) {
        Ok(t) => (t.ip, if t.port == 0 { None } else { Some(t.port) }),
        Err(_) => {
            let no_invisible = strip_invisible_and_non_ascii(raw);
            let host = no_invisible
                .split(';')
                .next()
                .unwrap_or("")
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .to_string();
            (host, None)
        }
    }
}

/// 【APP11 任务2】判断 IPv4 是否落在任一 CIDR 网段内（按掩码位运算）。
fn ipv4_in_any_cidr(ip: std::net::Ipv4Addr, cidrs: &[String]) -> bool {
    let ipu = u32::from(ip);
    for c in cidrs {
        let Some((net_s, mask_s)) = c.split_once('/') else {
            continue;
        };
        if let (Ok(net), Ok(mask)) = (
            net_s.parse::<std::net::Ipv4Addr>(),
            mask_s.parse::<u8>(),
        ) {
            if mask > 32 {
                continue;
            }
            let m: u32 = if mask == 0 { 0 } else { u32::MAX << (32 - mask) };
            if (ipu & m) == (u32::from(net) & m) {
                return true;
            }
        }
    }
    false
}

/// 【APP40 任务1/3】精准 `IP:端口` 智能检测：
///
/// - 强制 `IP:端口`（或 `http(s)://IP[:端口]`）：纯 IP 不发起任何扫描，
///   直接返回友好提示；
/// - 网段归属硬校验：目标必须落在当前已启用档案的 lan_cidrs 内；
/// - 拒绝检测本机自身的 WireGuard 虚拟 IP；
/// - 仅对用户指定的**唯一端口**并发 HTTPS（忽略自签名证书）/ HTTP 探测，
///   必要时再做一次单端口 TCP 握手兜底，绝不触碰任何其他端口；
/// - On-Demand 命中本地同网段时，直接走物理网络并返回 ⚡ 提示。
pub async fn probe_intranet_ip(
    target_ip_raw: Option<&str>,
    api_addr: &str,
    api_secret: &str,
    is_running: bool,
    go_lan_enabled: bool,
    lan: &GoLanSettings,
) -> GoLanProbeResult {
    let log = crate::core::logger::MOD_GO_LAN;
    // 1. 严格解析输入（未带端口 → 直接提示，绝不扫描）
    let input = match target_ip_raw.map(parse_probe_input) {
        Some(Ok(input)) => input,
        Some(Err(msg)) => {
            crate::core::logger::info(log, &msg);
            return GoLanProbeResult {
                reachable: false,
                target_ip: target_ip_raw.unwrap_or("").to_string(),
                latency_ms: None,
                message: msg,
            };
        }
        None => {
            return GoLanProbeResult {
                reachable: false,
                target_ip: String::new(),
                latency_ms: None,
                message: PROBE_MISSING_PORT_MSG.into(),
            };
        }
    };
    let target_ip = input.ip.clone();
    let target_v4: std::net::Ipv4Addr = match target_ip.parse() {
        Ok(v4) => v4,
        Err(_) => {
            let message = format!("IP 地址格式无效: {target_ip}");
            crate::core::logger::warn(log, &message);
            return GoLanProbeResult {
                reachable: false,
                target_ip,
                latency_ms: None,
                message,
            };
        }
    };

    // 2. 运行前置
    if !is_running {
        crate::core::logger::warn(log, "VPN 尚未启动，跳过内网检测");
        return GoLanProbeResult {
            reachable: false,
            target_ip: target_ip.clone(),
            latency_ms: None,
            message: "VPN 尚未启动，请先在仪表盘启动代理后再检测".into(),
        };
    }
    if !go_lan_enabled {
        crate::core::logger::warn(log, "Go Lan 尚未开启，跳过内网检测");
        return GoLanProbeResult {
            reachable: false,
            target_ip: target_ip.clone(),
            latency_ms: None,
            message: "Go Lan 尚未开启，请先打开 Go Lan 开关".into(),
        };
    }
    let mut profiles = enabled_profiles(lan);
    if profiles.is_empty()
        && lan.enabled
        && (lan.wg_config.is_some()
            || !lan.node_uri.trim().is_empty()
            || !lan.lan_cidrs.is_empty())
    {
        // 旧版单配置兜底（尚未执行 normalize_go_lan_settings 的调用方）
        profiles.push((
            GO_LAN_TAG.to_string(),
            GoLanProfile {
                id: "home".into(),
                name: "家里".into(),
                enabled: true,
                bypass_on_local_lan: lan.bypass_on_local_lan,
                local_wifi_ssid: String::new(),
                lan_cidrs: lan.lan_cidrs.clone(),
                wg_config: lan.wg_config.clone(),
                node_uri: lan.node_uri.clone(),
                probe_target: String::new(),
            },
        ));
    }
    if profiles.is_empty() {
        crate::core::logger::warn(log, "没有任何已启用的内网档案，跳过内网检测");
        return GoLanProbeResult {
            reachable: false,
            target_ip: target_ip.clone(),
            latency_ms: None,
            message: "没有已启用的内网档案，请先在 Go Lan 中启用一路内网".into(),
        };
    }

    // 3. 本机虚拟 IP 不得作为检测目标
    let self_ips: Vec<String> = profiles
        .iter()
        .flat_map(|(_, p)| {
            let local_addr = p
                .wg_config
                .as_ref()
                .map(|wg| wg.local_ip.as_str())
                .unwrap_or("");
            parse_all_wg_local_addresses(local_addr)
                .0
                .into_iter()
                .map(|a| a.split('/').next().unwrap_or("").to_string())
                .collect::<Vec<String>>()
        })
        .filter(|s| !s.is_empty())
        .collect();
    if self_ips.iter().any(|s| s == &target_ip) {
        let msg = format!(
            "不能检测本机自身的虚拟 IP ({target_ip})，请输入内网设备 IP（如 192.168.10.253:8001）"
        );
        crate::core::logger::warn(log, &msg);
        return GoLanProbeResult {
            reachable: false,
            target_ip,
            latency_ms: None,
            message: msg,
        };
    }

    // 4. 找到目标所属的档案 + 是否触发 On-Demand 同局域网直连
    let physical_ips = detect_physical_lan_ipv4s();
    let owner = profiles.iter().find_map(|(tag, profile)| {
        let cidrs = profile_route_cidrs(profile);
        if !ipv4_in_any_cidr(target_v4, &cidrs) {
            return None;
        }
        let (tunnel, direct) = split_profile_cidrs_for_on_demand(profile, &physical_ips);
        let bypassed = direct
            .iter()
            .any(|c| ipv4_in_any_cidr(target_v4, std::slice::from_ref(c)));
        Some((tag.clone(), profile.clone(), tunnel, direct, bypassed))
    });
    let Some((tag, profile, tunnel, direct, bypassed)) = owner else {
        let all_cidrs: Vec<String> = profiles
            .iter()
            .flat_map(|(_, p)| profile_route_cidrs(p))
            .collect();
        let msg = format!(
            "❌ 目标 IP {target_ip} 不在已启用的内网网段 [{}] 内，不会经过 Go Lan 隧道",
            all_cidrs.join(", ")
        );
        crate::core::logger::warn(log, &msg);
        return GoLanProbeResult {
            reachable: false,
            target_ip,
            latency_ms: None,
            message: msg,
        };
    };
    if bypassed {
        crate::core::logger::info(
            log,
            &format!(
                "⚡ On-Demand 智能直连已触发：档案「{}」命中本机局域网 {:?}，跳过 WG 隧道（网段 {:?}，其余隧道 {:?}）",
                profile.name, physical_ips, direct, tunnel
            ),
        );
    }

    let scheme_hint = input.scheme.as_deref();
    // 【APP50 任务3】端口哨兵 0（纯 IP）→ 展示 80/443
    let port_desc = if input.port == 0 {
        "80/443".to_string()
    } else {
        input.port.to_string()
    };
    crate::core::logger::info(
        log,
        &format!(
            "正在检测内网目标: {target_ip}:{port_desc}{}（出站 {tag}）...",
            scheme_hint.map(|s| format!(" [{s}]")).unwrap_or_default()
        ),
    );

    // 5. 探测：On-Demand 直连 → 仅直连；否则 Clash API → 直连 → 单端口 TCP
    // 【APP50 任务3】纯 IP（端口哨兵 0）：仅依次探测 http:80 → https:443
    // （最多 2 次 Clash API 延迟测试，绝不盲目扫描其他端口），首次成功即返回
    let mut result: Result<PortProbeHit, String> = if input.port == 0 {
        let mut r = Err("未发起探测".to_string());
        for (scheme, port) in [("http", 80u16), ("https", 443u16)] {
            r = if bypassed {
                probe_web_protocols_direct_only(&target_ip, port, Some(scheme), &input.path).await
            } else {
                probe_web_protocols(
                    &target_ip,
                    port,
                    Some(scheme),
                    &input.path,
                    api_addr,
                    api_secret,
                    &tag,
                )
                .await
            };
            if r.is_ok() {
                break;
            }
        }
        r
    } else if bypassed {
        probe_web_protocols_direct_only(&target_ip, input.port, scheme_hint, &input.path).await
    } else {
        probe_web_protocols(
            &target_ip,
            input.port,
            scheme_hint,
            &input.path,
            api_addr,
            api_secret,
            &tag,
        )
        .await
    };
    if result.is_err() && !bypassed && input.port != 0 {
        // 非 Web 端口（3389 / 22 / 445…）单端口握手兜底，绝不扫描其他端口
        if let Ok(ms) = probe_single_port_tcp(&target_ip, input.port).await {
            result = Ok(PortProbeHit {
                scheme: "TCP".into(),
                latency_ms: ms,
            });
        }
    }
    match result {
        Ok(hit) => {
            // 【APP50 任务3】彻底删除「延迟 ≤1ms 误判拦截」：真实内网或高速隧道
            // 完全可能是 1~5ms；超时的真实特征是 Clash API HTTP 非 200 /
            // delay 字段缺失或为 0（probe_clash_delay_for_tag 已严格拦截，
            // 只有 HTTP 200 且 delay > 0 才会走到这里）。
            let shown_port = if input.port == 0 {
                if hit.scheme.eq_ignore_ascii_case("https") {
                    443
                } else {
                    80
                }
            } else {
                input.port
            };
            let od_note = if bypassed {
                "（⚡ On-Demand 同局域网直连，已自动跳过隧道）"
            } else {
                ""
            };
            let msg = format!(
                "✅ 已通过「{}」隧道连通 {}://{target_ip}:{shown_port}{od_note} · 延迟 {} ms",
                profile.name, hit.scheme, hit.latency_ms
            );
            crate::core::logger::info(log, &msg);
            GoLanProbeResult {
                reachable: true,
                target_ip,
                latency_ms: Some(hit.latency_ms),
                message: msg,
            }
        }
        Err(_) => {
            // 【APP50 任务3】明确失败文案：含档案名；纯 IP 时不带端口号
            let target_desc = if input.port == 0 {
                target_ip.clone()
            } else {
                format!("{target_ip}:{}", input.port)
            };
            let msg = format!(
                "❌ 未能通过「{}」隧道连通 {target_desc}（握手或目标端口响应超时，请确认 WG 配置及目标端口已开放）",
                profile.name
            );
            crate::core::logger::warn(log, &msg);
            GoLanProbeResult {
                reachable: false,
                target_ip,
                latency_ms: None,
                message: msg,
            }
        }
    }
}

/// 【APP40 任务3】On-Demand 直连模式下只走物理网络的应用层探测
/// （目标网段已进入 iOS excludedRoutes，不经过 utun）。
async fn probe_web_protocols_direct_only(
    ip: &str,
    port: u16,
    scheme_hint: Option<&str>,
    path: &str,
) -> Result<PortProbeHit, String> {
    let schemes: Vec<&str> = match scheme_hint {
        Some(s) => vec![s],
        None => vec!["http", "https"],
    };
    let mut tasks: tokio::task::JoinSet<(String, Result<(u16, u64), String>)> =
        tokio::task::JoinSet::new();
    for scheme in &schemes {
        let (ip_o, path_o) = (ip.to_string(), path.to_string());
        let scheme_o = scheme.to_string();
        tasks.spawn(async move {
            let res = probe_app_layer(&ip_o, port, &scheme_o, &path_o).await;
            (scheme_o, res)
        });
    }
    let mut http_hit: Option<u64> = None;
    let mut https_hit: Option<u64> = None;
    let mut last_err = String::from("直连探测超时");
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((scheme, Ok((status, ms)))) => {
                if scheme == "https" && status != 400 {
                    https_hit = Some(ms);
                } else if scheme == "http" {
                    http_hit = Some(ms);
                }
            }
            Ok((_, Err(e))) => last_err = e,
            Err(_) => continue,
        }
    }
    if scheme_hint.is_none() {
        if let Some(ms) = http_hit {
            return Ok(PortProbeHit {
                scheme: "HTTP".into(),
                latency_ms: ms,
            });
        }
    }
    if let Some(ms) = https_hit.or(http_hit) {
        return Ok(PortProbeHit {
            scheme: if https_hit.is_some() { "HTTPS" } else { "HTTP" }.into(),
            latency_ms: ms,
        });
    }
    Err(last_err)
}

// ---------------------------------------------------------------- 出站构建

/// 将 WgManualConfig 构建为 sing-box WireGuard 出站（APP-6 任务2）。
/// 私钥/对端公钥必须通过 normalize_wg_key 校验（32 字节标准重编码），
/// 否则返回 None——**严禁**把空串、未解码的 `%3D` 或长度不对的密钥写入
/// 生成的 prism_config.json，防止内核 decode base64 失败导致启动崩溃。
/// 可选 pre_shared_key 仅在通过校验时写入；无效 PSK 忽略并给出警告。
///
/// 【APP6 任务2】统一改回 sing-box v1.11.3 **顶层单节点模式**（connect=true）：
/// - 顶层直接写 `server` / `server_port` / `peer_public_key` / `pre_shared_key`，
///   **严禁 `peers` 数组**——peers 模式走 ListenPacket("udp","") 双栈非连接
///   Socket，在 iOS 扩展沙盒被 NECP 拦截报
///   `listen outbound packet connection: operation not permitted`；
/// - 顶层单节点走 DialContext("udp4", server:port) 连接型 Socket，可穿透；
/// - **严禁 `allowed_ips` / `persistent_keepalive_interval`**——顶层
///   LegacyWireGuardOutbound 与 peers 元素均不支持这些字段，写入直接
///   `json: unknown field` 拒绝启动；
/// - 【IPA9 任务4.3】移除 `inet4_bind_address`：5G 蜂窝网络下写入物理
///   网卡 IP（如 10.66.92.229）会导致 `dial tcp 10.66.92.229:0->8.8.4.4:853:
///   i/o timeout`；改用 `domain_strategy: ipv4_only` + 扩展侧
///   prism_protect_socket 绑定物理网卡即可保证纯 IPv4 Socket 不被 EPERM。
fn wg_outbound_value(
    wg: &WgManualConfig,
    warnings: &mut Vec<String>,
    tag: &str,
) -> Option<Value> {
    let private_key = normalize_wg_key(&wg.private_key)?;
    let peer_public_key = normalize_wg_key(&wg.peer_public_key)?;
    // APP-8 任务2：预解析 WireGuard 对端域名为 IP——内核 post-start 阶段
    // 对 wireguard 出站必须同步解析 server 域名，若 dns-direct(-bak) 解析
    // 被 RST 会中断整个 VPN 启动。提前把 server 换成 IP，post-start 零 DNS
    // 请求、瞬时启动；解析失败则原样保留域名（扩展侧还有兜底重试）。
    // 【APP-11B】先剔除 \u2060 等隐形字符再解析
    let server = resolve_endpoint_host_to_ip(&strip_invisible_and_non_ascii(&wg.server));
    // 【APP21 任务3.1】local_address 完整保留全部合法地址（严禁只取第 1 个）：
    // 服务端专门分配的第 2 个地址（如 192.168.10.222/24）是访问同网段内网
    // （飞牛 NAS 192.168.10.253）时必须使用的同网段源 IP——丢弃后只能用
    // 跨网段的 10.196.0.2 做源 IP，NAS 回包受阻。内核按最长前缀匹配自动
    // 选源 IP，与官方 WireGuard 客户端 100% 一致。
    let (local_addrs, _extra_lan_cidrs) = parse_all_wg_local_addresses(&wg.local_ip);
    let local_addrs = if local_addrs.is_empty() {
        vec!["10.0.0.2/24".to_string()]
    } else {
        local_addrs
    };
    let local_addrs_log = local_addrs.join(", ");
    let mut outbound = json!({
        "type": "wireguard",
        "tag": tag,
        "server": server,
        "server_port": wg.server_port,
        "peer_public_key": peer_public_key,
        "private_key": private_key,
        "local_address": local_addrs,
        // iOS 关闭 IPv6 时双栈 Socket 绑定 IPv4 网卡会被 EPERM 拒绝，
        // 强制 ipv4_only 保证 UDP（WireGuard）可正常发握手包；
        // 物理网卡绑定由扩展侧 prism_protect_socket 动态完成，
        // 不再写死 inet4_bind_address（5G 蜂窝下会引发 i/o timeout）。
        "domain_strategy": "ipv4_only",
    });
    if let Some(psk) = &wg.pre_shared_key {
        match normalize_wg_key(psk) {
            Some(valid) => outbound["pre_shared_key"] = Value::String(valid),
            None if !psk.trim().is_empty() => {
                warnings.push("预共享密钥格式无效，已忽略（不影响连接）".into());
            }
            None => {}
        }
    }
    // 【APP48 任务1.2】内核 JSON 的 go-lan-home MTU 无条件锁死 1380（用户
    // 保存的 wg_config.mtu 保持不变），并附加 connect_timeout 5s。
    let mtu = GO_LAN_RUNTIME_MTU;
    outbound["mtu"] = json!(mtu);
    outbound["connect_timeout"] = json!("5s");
    crate::core::logger::info(
        crate::core::logger::MOD_GO_LAN,
        &format!(
            "已构建 {tag} 顶层单节点出站: {}:{}（隧道地址 {local_addrs_log}，运行时 MTU 1380 / MSS 1340）",
            outbound["server"].as_str().unwrap_or("?"),
            wg.server_port
        ),
    );
    Some(outbound)
}

/// 【APP6 任务2】把历史 peers 数组结构的 wireguard 出站归一化为顶层单节点：
/// 将 peers[0] 的 server / server_port / public_key(→peer_public_key) /
/// pre_shared_key 提升到顶层，删除 peers / allowed_ips /
/// persistent_keepalive_interval。用于 Managed 远端缓存等历史数据兜底。
fn normalize_wg_outbound_to_single_node(outbound: &mut Value) {
    let is_wg = outbound.get("type").and_then(Value::as_str) == Some("wireguard");
    if !is_wg {
        return;
    }
    let peer = outbound
        .get("peers")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first().cloned());
    if let Some(peer) = peer {
        let obj = outbound.as_object_mut().expect("wg outbound is object");
        if !obj.contains_key("server") {
            if let Some(s) = peer.get("server") {
                obj.insert("server".into(), s.clone());
            }
        }
        if !obj.contains_key("server_port") {
            if let Some(p) = peer.get("server_port") {
                obj.insert("server_port".into(), p.clone());
            }
        }
        if !obj.contains_key("peer_public_key") {
            if let Some(pk) = peer.get("public_key") {
                obj.insert("peer_public_key".into(), pk.clone());
            }
        }
        if !obj.contains_key("pre_shared_key") {
            if let Some(psk) = peer.get("pre_shared_key") {
                obj.insert("pre_shared_key".into(), psk.clone());
            }
        }
        obj.remove("peers");
    }
    if let Some(obj) = outbound.as_object_mut() {
        obj.remove("allowed_ips");
        obj.remove("persistent_keepalive_interval");
    }
}

/// 【APP40 任务2】构建全部启用档案的出站（每个档案一个独立 WireGuard 出站）。
pub fn build_outbounds(lan: &GoLanSettings) -> (Vec<Value>, Vec<String>) {
    let mut outbounds: Vec<Value> = Vec::new();
    let mut warnings = Vec::new();
    if !lan.enabled {
        return (outbounds, warnings);
    }
    let profiles = enabled_profiles(lan);
    if profiles.is_empty() {
        // 旧版兜底（尚未 normalize 的单配置）
        let mut legacy = lan.clone();
        legacy.enabled = true;
        let (ob, mut w) = build_outbound_with_tag(&legacy, GO_LAN_TAG);
        warnings.append(&mut w);
        if let Some(ob) = ob {
            outbounds.push(ob);
        }
        return (outbounds, warnings);
    }
    for (i, (tag, profile)) in profiles.iter().enumerate() {
        let temp = GoLanSettings {
            enabled: true,
            node_uri: profile.node_uri.clone(),
            wg_config: profile.wg_config.clone(),
            lan_cidrs: profile.lan_cidrs.clone(),
            // Managed 模式：授权服务器下发的缓存出站挂到第 1 个启用档案
            cached_managed_outbound: if i == 0 {
                lan.cached_managed_outbound.clone()
            } else {
                None
            },
            ..Default::default()
        };
        let (ob, mut w) = build_outbound_with_tag(&temp, tag);
        warnings.append(&mut w);
        if let Some(ob) = ob {
            outbounds.push(ob);
        }
    }
    (outbounds, warnings)
}

/// 兼容旧接口：返回第一个启用档案的出站。
pub fn build_outbound(lan: &GoLanSettings) -> (Option<Value>, Vec<String>) {
    let (mut outbounds, warnings) = build_outbounds(lan);
    (outbounds.drain(..).next(), warnings)
}

/// 构建单个回家出站（指定 tag）；配置无效返回 (None, 警告)
pub fn build_outbound_with_tag(lan: &GoLanSettings, tag: &str) -> (Option<Value>, Vec<String>) {
    let mut warnings = Vec::new();
    if !lan.enabled {
        return (None, warnings);
    }
    // 1. 手动 WireGuard：密钥一律先规范化校验，无效必填密钥 → 不注入
    if let Some(wg) = &lan.wg_config {
        if !wg.server.trim().is_empty() {
            if let Some(outbound) = wg_outbound_value(wg, &mut warnings, tag) {
                return (Some(outbound), warnings);
            }
            if normalize_wg_key(&wg.private_key).is_none()
                || normalize_wg_key(&wg.peer_public_key).is_none()
            {
                warnings.push(
                    "WireGuard 私钥/对端公钥不是合法的 32 字节密钥，已忽略（请检查是否带引号或未解码）"
                        .into(),
                );
            }
        }
        warnings.push("WireGuard 配置不完整（服务器/私钥/对端公钥缺失），已忽略".into());
    }
    // 2. 手动分享链接：wireguard:// / wg:// / wg-quick .conf 走专用解析器
    //    （密钥先 URL 解码 + normalize_wg_key 规范化），其余协议交给通用 uri_parser
    //    【APP-11B】先剔除 \u2060 等隐形字符再解析
    let cleaned_uri = strip_invisible_and_non_ascii(&lan.node_uri);
    if !cleaned_uri.is_empty() {
        let uri = cleaned_uri.as_str();
        if uri.starts_with("wireguard://") || uri.starts_with("wg://") {
            match parse_wireguard_uri(uri) {
                Ok(wg) => {
                    if let Some(outbound) = wg_outbound_value(&wg, &mut warnings, tag) {
                        return (Some(outbound), warnings);
                    }
                }
                Err(e) => warnings.push(format!("wireguard:// 链接解析失败: {e}")),
            }
        } else if uri.contains("[Interface]") {
            match parse_wireguard_conf(uri) {
                Ok(wg) => {
                    if let Some(outbound) = wg_outbound_value(&wg, &mut warnings, tag) {
                        return (Some(outbound), warnings);
                    }
                }
                Err(e) => warnings.push(format!(".conf 解析失败: {e}")),
            }
        } else {
            match uri_parser::parse_line(&cleaned_uri) {
                Ok(Some(node_value)) => match serde_json::from_value::<ClashNode>(node_value) {
                    Ok(node) => match node_to_outbound(&node) {
                        Some((mut outbound, warn)) => {
                            if let Some(w) = warn {
                                warnings.push(w);
                            }
                            outbound["tag"] = json!(tag);
                            return (Some(outbound), warnings);
                        }
                        None => warnings.push("回家链接节点类型不受支持或密钥无效，已忽略".into()),
                    },
                    Err(e) => warnings.push(format!("回家链接解析失败: {e}")),
                },
                Ok(None) => warnings.push("回家链接为空或不支持的协议".into()),
                Err(e) => warnings.push(format!("回家链接解析失败: {e}")),
            }
        }
    }
    // 3. Managed 缓存的出站（历史缓存可能带 URL 编码密钥，同样兜底规范化；
    // 【APP6 任务2】历史 peers 结构统一归一化为顶层单节点）
    if let Some(cached) = &lan.cached_managed_outbound {
        let mut outbound = cached.clone();
        if let Some(t) = outbound.get("type").and_then(Value::as_str) {
            if t == "wireguard" {
                normalize_wg_outbound_to_single_node(&mut outbound);
                for key in ["private_key", "peer_public_key"] {
                    if let Some(raw) = outbound.get(key).and_then(Value::as_str) {
                        if let Some(valid) = normalize_wg_key(raw) {
                            outbound[key] = json!(valid);
                        }
                    }
                }
                if let Some(psk) = outbound.get("pre_shared_key").cloned() {
                    match psk.as_str().and_then(normalize_wg_key) {
                        Some(valid) => outbound["pre_shared_key"] = json!(valid),
                        // 损坏/未解码的 PSK 直接移除，绝不写入非法值
                        None => {
                            if let Some(obj) = outbound.as_object_mut() {
                                obj.remove("pre_shared_key");
                            }
                        }
                    }
                }
            }
            outbound["tag"] = json!(tag);
            return (Some(outbound), warnings);
        }
    }
    (None, warnings)
}

// ---------------------------------------------------------------- 规则合成

/// 【APP-11B 任务1.1】通用可见 ASCII 提纯：仅保留 0x21..=0x7E 可见字符，
/// 物理剔除空格、`\u2060` Word Joiner、`\u200B..\u200F` 零宽字符、`\uFEFF`
/// BOM、换行符及一切非 ASCII 字符。从微信/网页长按复制配置时 iOS 剪贴板
/// 常塞入零宽字符，`.trim()` 只清理 Whitespace 无法去除它们。
pub fn strip_invisible_and_non_ascii(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii() && (*c as u8) >= 0x21 && (*c as u8) <= 0x7E)
        .collect()
}

/// 【APP-11B 任务1.1】IP/CIDR 前缀提纯与严格校验。
///
/// 第一步仅保留合法 IP 字符（hex + `.` `:` `/`），100% 物理剥离 `\u2060`
/// 等隐藏符号——`"10.195.0.2/32\u{2060}"` → `"10.195.0.2/32"`；
/// 第二步不含 `/` 时自动补默认前缀（IPv6 恒 /64）；
/// 第三步用 `IpAddr` + 位数范围（v4 0..=32 / v6 0..=128）严格解析后
/// 重新格式化返回标准字符串。解析失败返回 None（调用方应忽略并告警）。
pub fn sanitize_ip_prefix(raw: &str, default_prefix_v4: u8) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == '.' || *c == ':' || *c == '/')
        .collect();
    if cleaned.is_empty() {
        return None;
    }
    let (addr_s, bits) = match cleaned.split_once('/') {
        Some((a, b)) => (a.to_string(), b.parse::<u8>().ok()?),
        None => {
            if cleaned.contains(':') {
                (cleaned.clone(), 64u8)
            } else {
                (cleaned.clone(), default_prefix_v4.min(32))
            }
        }
    };
    let addr = addr_s.parse::<std::net::IpAddr>().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if bits > max {
        return None;
    }
    Some(format!("{addr}/{bits}"))
}

/// 【APP21 任务3.1】完整解析 WireGuard Local Address 的全部地址，支持
/// 逗号/分号/中文标点/换行/空白分隔（如 `"10.196.0.2/32, 192.168.10.222/24"`）。
///
/// 规则：
/// - 逐项清除零宽字符后保留其主机 IP 与前缀位数（掩码缺失补 `/24`；
///   输入框截断写成的 `/2` 等 `< 8` 的掩码自动修正还原为 `/24`）；
/// - **只有 1 个地址**时（如 `"10.196.0.2/32"`）统一转为 `/24`
///   （协议栈需同子网前缀识别链路内邻居）；
/// - **多个地址**时完整保留所有合法项的原前缀
///   （`vec!["10.196.0.2/32", "192.168.10.222/24"]`）——第 2 个地址是
///   服务端分配的同网段源 IP，访问 `192.168.10.253` 时内核按最长前缀
///   匹配自动选用 `192.168.10.222`，与官方 WireGuard 客户端一致；
///
/// 返回：
/// - 第 1 个：全部合法 IPv4 CIDR 地址（可能为空，调用方兜底）；
/// - 第 2 个：每个地址对应的 `/24` 网段（去重），并入回家路由 `ip_cidr`。
pub fn parse_all_wg_local_addresses(raw: &str) -> (Vec<String>, Vec<String>) {
    let mut addrs: Vec<String> = Vec::new();
    let mut lan_cidrs: Vec<String> = Vec::new();
    // 先按分隔符切分，再逐项提纯 —— 不能先 strip 空白，否则
    // "10.0.0.2/32 192.168.10.222/24" 会被粘成一个串。
    for token in raw.split(|c: char| {
        c == ',' || c == ';' || c == '\u{FF0C}' || c == '\u{FF1B}' || c.is_whitespace()
    }) {
        let Some(clean) = sanitize_ip_prefix(token, 24) else {
            continue;
        };
        let (ip_s, bits_s) = clean.split_once('/').unwrap_or((clean.as_str(), "24"));
        let Ok(ip) = ip_s.parse::<std::net::Ipv4Addr>() else {
            continue;
        };
        let mut bits: u8 = bits_s.parse().unwrap_or(24);
        // 输入框截断（如 192.168.10.222/2）产生 < 8 的掩码无意义，还原 /24
        if bits < 8 {
            bits = 24;
        }
        let cidr = format!("{ip_s}/{bits}");
        if !addrs.contains(&cidr) {
            addrs.push(cidr);
        }
        let net = network_of_v4(ip, 24);
        if !lan_cidrs.contains(&net) {
            lan_cidrs.push(net);
        }
    }
    // 只有 1 个地址时统一 /24（gVisor/system 栈识别同子网邻居需要）
    if addrs.len() == 1 {
        let ip_s = addrs[0].split('/').next().unwrap_or("").to_string();
        addrs[0] = format!("{ip_s}/24");
    }
    (addrs, lan_cidrs)
}

/// 【APP15 任务1.1 / APP21 任务3.1】解析 WireGuard Local Address。
///
/// 返回：
/// - 第 1 个：主隧道地址（第 1 个地址，**统一 `/24`**）；
/// - 第 2 个：所有地址对应的 `/24` 回家网段（去重）。
///
/// 解析失败（无任何合法 IPv4）时主地址兜底 `10.0.0.2/24`。
pub fn parse_wg_local_addresses(raw: &str) -> (String, Vec<String>) {
    let (addrs, lan_cidrs) = parse_all_wg_local_addresses(raw);
    let primary = addrs
        .first()
        .map(|a| {
            let ip_s = a.split('/').next().unwrap_or("");
            format!("{ip_s}/24")
        })
        .unwrap_or_else(|| "10.0.0.2/24".to_string());
    (primary, lan_cidrs)
}

/// 【APP-11 任务1.1】规范化回家内网网段列表。
///
/// 用户常见填法是不带掩码的单个 IP（`192.168.1.1`）或主机位非零的 CIDR
/// （`192.168.1.1/24`）。前者交给内核会解析失败/匹配不到网段，后者会被
/// `netip.Prefix` 规范化成 `192.168.1.0/24` 但仍需保留精确主机路由。
/// 处理策略：
/// - 纯 IP（无 `/`）→ 同时产出 `/32` 精确路由与对应 `/24` 网段；
/// - CIDR 主机位非零 → 保留原精确 `/32` + 归一化后的网络前缀；
/// - 已规范的 CIDR → 原样保留；
/// - 最后自动并入 WireGuard 虚拟子网（local_address 推导）。
pub(crate) fn normalize_cidr_list(cidrs: &[String], local_addr: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |v: String| {
        if !v.is_empty() && !out.contains(&v) {
            out.push(v);
        }
    };
    for raw in cidrs {
        // 【APP-11B 任务1.1】先经 sanitize_ip_prefix 剔除 \u2060 等隐形字符、
        // 无掩码自动补 /24、严格校验；清洗后无法解析的条目直接丢弃
        let Some(clean) = sanitize_ip_prefix(raw, 24) else {
            continue;
        };
        let (ip_s, mask_s) = clean.split_once('/').unwrap_or((clean.as_str(), ""));
        if let (Ok(ip), Ok(mask)) =
            (ip_s.parse::<std::net::Ipv4Addr>(), mask_s.parse::<u8>())
        {
            if mask >= 32 {
                // 精确主机路由原样保留
                push(clean.clone());
            } else {
                // 主机位非零：保留精确 /32 并归一化为网络前缀
                let net = network_of_v4(ip, mask);
                if net != format!("{ip}/{mask}") {
                    push(format!("{ip}/32"));
                }
                push(net);
            }
        } else {
            // IPv6 或其他已校验格式原样保留
            push(clean);
        }
    }
    // 【APP15 任务1.1】local_address 可能是逗号分隔的多个地址，其中每个
    // 地址对应的 /24 网段都必须并入回家网段，否则第 2 个地址所在内网
    // （如 192.168.10.0/24）永远不会走隧道。
    let (_primary, extra_cidrs) = parse_wg_local_addresses(local_addr);
    for c in extra_cidrs {
        push(c);
    }
    if let Some(virtual_cidr) = extract_virtual_subnet(local_addr) {
        push(virtual_cidr);
    }
    out
}

/// 计算 IPv4 网络前缀（掩码 0..=32），如 192.168.1.1/24 → 192.168.1.0/24
fn network_of_v4(ip: std::net::Ipv4Addr, mask: u8) -> String {
    let mask = mask.min(32);
    let bits = u32::from(ip);
    let net_mask: u32 = if mask == 0 {
        0
    } else {
        u32::MAX << (32 - mask)
    };
    format!("{}/{mask}", std::net::Ipv4Addr::from(bits & net_mask))
}

/// 【APP40 任务2】合成全部启用档案的回家路由规则：
/// - 最顶部先插入 On-Demand 命中本机局域网的 `direct` 规则；
/// - 随后每个启用档案一条 `ip_cidr → go-lan-{tag}`（按档案顺序）。
/// 这些规则必须插在 `geosite: private` / `ip_is_private -> direct` 之前。
pub(crate) fn go_lan_route_rules(lan: &GoLanSettings) -> (Vec<Value>, Vec<String>) {
    let mut rules = Vec::new();
    let mut warnings = Vec::new();
    if !lan.enabled {
        return (rules, warnings);
    }
    let profiles = enabled_profiles(lan);
    if profiles.is_empty() {
        // 旧版兜底（尚未 normalize 的单配置）
        let legacy_profile = GoLanProfile {
            id: "home".into(),
            name: "家里".into(),
            enabled: true,
            bypass_on_local_lan: lan.bypass_on_local_lan,
            local_wifi_ssid: String::new(),
            lan_cidrs: lan.lan_cidrs.clone(),
            wg_config: lan.wg_config.clone(),
            node_uri: lan.node_uri.clone(),
            probe_target: String::new(),
        };
        let (tunnel, direct) =
            split_profile_cidrs_for_on_demand(&legacy_profile, &detect_physical_lan_ipv4s());
        if !direct.is_empty() {
            rules.push(json!({ "ip_cidr": direct, "outbound": "direct" }));
        }
        if !tunnel.is_empty() {
            rules.push(json!({ "ip_cidr": tunnel, "outbound": GO_LAN_TAG }));
        }
        for raw in &lan.lan_cidrs {
            if sanitize_ip_prefix(raw, 24).is_none()
                && !strip_invisible_and_non_ascii(raw).is_empty()
            {
                warnings.push(format!("无效网段「{}」已忽略", raw.trim()));
            }
        }
        let domains = cleaned_lan_domains(lan);
        if !domains.is_empty() {
            rules.push(json!({ "domain_suffix": domains, "outbound": GO_LAN_TAG }));
        }
        return (rules, warnings);
    }

    let physical_ips = detect_physical_lan_ipv4s();
    let mut bypassed: Vec<String> = Vec::new();
    let mut per_tunnel: Vec<(String, Vec<String>)> = Vec::new();
    for (tag, profile) in &profiles {
        for raw in &profile.lan_cidrs {
            if sanitize_ip_prefix(raw, 24).is_none()
                && !strip_invisible_and_non_ascii(raw).is_empty()
            {
                warnings.push(format!(
                    "档案「{}」无效网段「{}」已忽略",
                    profile.name,
                    raw.trim()
                ));
            }
        }
        let (tunnel, direct) = split_profile_cidrs_for_on_demand(profile, &physical_ips);
        if !direct.is_empty() {
            if !physical_ips.is_empty() {
                crate::core::logger::info(
                    crate::core::logger::MOD_GO_LAN,
                    &format!(
                        "⚡ On-Demand 智能直连已触发：检测到本机处于局域网 {:?}，档案「{}」已自动跳过 WG 隧道改走局域网直连（网段: {:?}）",
                        physical_ips, profile.name, direct
                    ),
                );
            }
            for c in direct {
                if !bypassed.contains(&c) {
                    bypassed.push(c);
                }
            }
        }
        if !tunnel.is_empty() {
            per_tunnel.push((tag.clone(), tunnel));
        }
    }
    // ① On-Demand 直连规则严格第一（先于所有 go-lan 隧道与代理规则）
    if !bypassed.is_empty() {
        rules.push(json!({ "ip_cidr": bypassed, "outbound": "direct" }));
    }
    // ② 每路内网隧道：独立 ip_cidr → go-lan-{tag}
    for (tag, cidrs) in per_tunnel {
        rules.push(json!({ "ip_cidr": cidrs, "outbound": tag }));
    }
    // ③ 内网域名后缀统一走第一个启用档案（go-lan-home）
    let domains = cleaned_lan_domains(lan);
    if !domains.is_empty() {
        rules.push(json!({ "domain_suffix": domains, "outbound": GO_LAN_TAG }));
    }
    (rules, warnings)
}

/// 【APP40 任务2】清洗全局内网域名后缀
fn cleaned_lan_domains(lan: &GoLanSettings) -> Vec<String> {
    lan.lan_domains
        .iter()
        .map(|d| strip_invisible_and_non_ascii(d).trim_start_matches("*.").to_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

/// 从 WireGuard local_ip（如 "10.8.0.2/24" 或 "10.0.0.2/32"）提取虚拟子网 /24。
/// 仅处理 IPv4；返回 None 表示无法提取。
fn extract_virtual_subnet(local_ip: &str) -> Option<String> {
    let ip_str = local_ip.trim().split('/').next()?;
    let parts: Vec<&str> = ip_str.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        Some(format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

/// 合成家庭 DNS 服务器与域名解析规则（lan_dns + lan_domains）。
/// 返回 (dns 服务器配置, dns 规则)；二者需并入内核 dns 配置。
pub(crate) fn go_lan_dns(lan: &GoLanSettings) -> (Option<Value>, Option<Value>) {
    if !lan.enabled {
        return (None, None);
    }
    // 【APP-11B】剔除 \u2060 等隐形字符
    let cleaned_dns = lan
        .lan_dns
        .as_deref()
        .map(strip_invisible_and_non_ascii)
        .filter(|s| !s.is_empty());
    let Some(dns) = cleaned_dns.as_deref() else {
        return (None, None);
    };
    let domains: Vec<String> = lan
        .lan_domains
        .iter()
        // 【APP-11B】剔除 \u2060 等隐形字符
        .map(|d| strip_invisible_and_non_ascii(d).trim_start_matches("*.").to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    if domains.is_empty() {
        return (None, None);
    }
    let server = json!({
        "tag": GO_LAN_DNS_TAG,
        "address": dns,
        "detour": GO_LAN_TAG,
    });
    let rule = json!({ "domain_suffix": domains, "server": GO_LAN_DNS_TAG });
    (Some(server), Some(rule))
}

// ---------------------------------------------------------------- Managed 远端拉取

/// Managed 模式：向授权服务器拉取回家节点配置。
/// POST {server}/api/golan/fetch-config
/// 请求头：Content-Type: application/json、X-Request-Source: prism-app
/// 携带：device_code、device_id、license_key
pub async fn sync_managed(app: &AppHandle) -> Result<GoLanSettings, String> {
    let state = app.state::<AppState>();
    // Pro 门控
    if !state.is_pro_active() {
        return Err("Go Lan 是 Pro 专属功能，请先激活授权".into());
    }
    let data_dir = state.data_dir.clone();
    let (lan, creds) = {
        let lan = state.go_lan.read().clone();
        let creds = license::cached_credentials(&data_dir).map(|(lic, _email)| lic);
        (lan, creds)
    };
    let license_key = creds.ok_or("尚未激活授权，无法拉取回家配置")?;
    if lan.device_code.trim().is_empty() {
        return Err("请先填写设备识别码".into());
    }
    let server = lan.managed_server.trim().trim_end_matches('/').to_string();
    if server.is_empty() {
        return Err("请先填写授权服务器地址".into());
    }
    let device_id = license::device_id(&data_dir).map_err(|e| format!("设备 ID 生成失败: {e}"))?;

    let client = reqwest::Client::builder()
        .user_agent("ClashforWindows/0.20.39")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(format!("{server}/api/golan/fetch-config"))
        .header("Content-Type", "application/json")
        .header("X-Request-Source", "prism-app")
        .json(&serde_json::json!({
            "device_code": lan.device_code.trim(),
            "device_id": device_id,
            "license_key": license_key,
        }))
        .send()
        .await
        .map_err(|e| format!("拉取回家配置失败: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("授权服务器返回 HTTP {}", resp.status()));
    }
    let payload: Value = resp.json().await.map_err(|e| format!("响应解析失败: {e}"))?;
    if payload.get("valid").and_then(Value::as_bool) != Some(true) {
        let msg = payload
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("设备识别码未在服务器注册");
        return Err(msg.to_string());
    }
    let mut lan = lan;
    lan.home_name = payload
        .get("home_name")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or(lan.home_name);
    if let Some(uri) = payload.get("node_uri").and_then(Value::as_str) {
        if !uri.is_empty() {
            lan.node_uri = uri.to_string();
        }
    }
    if let Some(outbound) = payload.get("outbound").cloned() {
        if outbound.is_object() {
            lan.cached_managed_outbound = Some(outbound);
        }
    }
    if let Some(arr) = payload.get("lan_cidrs").and_then(Value::as_array) {
        lan.lan_cidrs = arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
    }
    if let Some(arr) = payload.get("lan_domains").and_then(Value::as_array) {
        lan.lan_domains = arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
    }
    if let Some(d) = payload.get("lan_dns").and_then(Value::as_str) {
        if !d.is_empty() {
            lan.lan_dns = Some(d.to_string());
        }
    }
    lan.enabled = true;
    // 【APP40 任务2】Managed 下发结果同步到内网档案，并执行旧数据迁移
    if let Some(first) = lan.profiles.first_mut() {
        first.node_uri = lan.node_uri.clone();
        first.lan_cidrs = lan.lan_cidrs.clone();
        first.enabled = true;
    }
    normalize_go_lan_settings(&mut lan);
    save(&data_dir, &lan)?;
    *state.go_lan.write() = lan.clone();
    Ok(lan)
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// 生成确定性的合法 32 字节 WireGuard 密钥（标准 44 位 Base64）
    fn test_key(seed: u8) -> String {
        let bytes: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(31).wrapping_add(seed) | 1)
            .collect();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// 【APP11 任务2 铁律1 / 任务5.3】不在回家网段内的 IP 必须 100% 拒绝
    #[tokio::test]
    async fn test_probe_rejects_ip_outside_lan_cidrs() {
        let lan = GoLanSettings {
            enabled: true,
            lan_cidrs: vec!["10.1.8.0/24".into(), "192.168.10.0/24".into()],
            wg_config: Some(WgManualConfig {
                server: "home.example.com".into(),
                server_port: 51820,
                private_key: test_key(1),
                peer_public_key: test_key(2),
                pre_shared_key: None,
                local_ip: "10.1.8.2/24".into(),
                mtu: 1420,
            }),
            ..Default::default()
        };
        // 192.168.0.1 不在 [10.1.8.0/24, 192.168.10.0/24] 内 → 直接拒绝，不发起探测
        let r = probe_intranet_ip(Some("192.168.0.1:8001"), "", "", true, true, &lan).await;
        assert!(!r.reachable, "网段外 IP 必须拒绝: {r:?}");
        assert!(
            r.message.contains("不在已启用的内网网段"),
            "错误消息应说明网段不匹配: {}",
            r.message
        );
    }

    /// 【APP11 任务2 铁律1】本机自身 WireGuard 虚拟 IP 必须拒绝
    #[tokio::test]
    async fn test_probe_rejects_self_virtual_ip() {
        let lan = GoLanSettings {
            enabled: true,
            lan_cidrs: vec!["10.1.8.0/24".into(), "192.168.10.0/24".into()],
            wg_config: Some(WgManualConfig {
                server: "home.example.com".into(),
                server_port: 51820,
                private_key: test_key(3),
                peer_public_key: test_key(4),
                pre_shared_key: None,
                local_ip: "10.1.8.2/24".into(),
                mtu: 1420,
            }),
            ..Default::default()
        };
        let r = probe_intranet_ip(Some("10.1.8.2:8001"), "", "", true, true, &lan).await;
        assert!(!r.reachable, "本机虚拟 IP 必须拒绝: {r:?}");
        assert!(
            r.message.contains("本机自身"),
            "错误消息应提示本机虚拟 IP: {}",
            r.message
        );
    }

    /// 【APP11 任务2 铁律1】CIDR 归属位运算校验
    #[test]
    fn test_ipv4_in_any_cidr() {
        let cidrs = vec!["10.1.8.0/24".to_string(), "192.168.10.0/24".to_string()];
        assert!(ipv4_in_any_cidr("10.1.8.1".parse().unwrap(), &cidrs));
        assert!(ipv4_in_any_cidr("10.1.8.253".parse().unwrap(), &cidrs));
        assert!(ipv4_in_any_cidr("192.168.10.253".parse().unwrap(), &cidrs));
        assert!(!ipv4_in_any_cidr("192.168.0.1".parse().unwrap(), &cidrs));
        assert!(!ipv4_in_any_cidr("8.8.8.8".parse().unwrap(), &cidrs));
        assert!(!ipv4_in_any_cidr("192.168.11.1".parse().unwrap(), &cidrs));
    }

    /// 【APP44 任务6】局域网地址白名单：FakeIP / TUN / 容器段 / 公网必须拒绝，
    /// 只保留私网与 CGNAT（否则设置页会展示 198.18.x.x 这类假地址）
    #[test]
    fn test_lan_ip_filter() {
        assert!(!is_usable_lan_ip("198.18.0.1".parse().unwrap()));
        assert!(!is_usable_lan_ip("198.19.255.1".parse().unwrap()));
        assert!(!is_usable_lan_ip("172.19.0.1".parse().unwrap()));
        assert!(!is_usable_lan_ip("10.196.0.2".parse().unwrap()));
        assert!(!is_usable_lan_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_usable_lan_ip("169.254.1.1".parse().unwrap()));
        assert!(!is_usable_lan_ip("8.8.8.8".parse().unwrap()));
        assert!(is_usable_lan_ip("192.168.10.5".parse().unwrap()));
        assert!(is_usable_lan_ip("10.1.8.23".parse().unwrap()));
        assert!(is_usable_lan_ip("172.20.0.7".parse().unwrap()));
        assert!(is_usable_lan_ip("100.64.0.8".parse().unwrap()));
    }

    /// 【APP40 任务1】检测目标严格支持 `IP:端口`；协议头缺省端口按 80/443。
    #[test]
    fn test_parse_probe_target() {
        // 纯 IP（无端口）→ 不再隐式扫描，交由 parse_probe_input 返回友好提示，
        // 兼容接口 parse_probe_target 只回传 IP、端口 None
        assert_eq!(parse_probe_target("10.1.8.1"), ("10.1.8.1".to_string(), None));
        assert_eq!(
            parse_probe_target("192.168.10.100:5000"),
            ("192.168.10.100".to_string(), Some(5000))
        );
        // 带不可见字符 / 前后空白时仍能正确解析
        assert_eq!(
            parse_probe_target(" 192.168.10.253:8001\u{200b} "),
            ("192.168.10.253".to_string(), Some(8001))
        );
        // 端口非法时降级为纯 IP 检测（兼容旧接口行为）
        assert_eq!(
            parse_probe_target("10.1.8.1:abc"),
            ("10.1.8.1".to_string(), None)
        );
        // 【APP15 任务2/APP40】支持 https:// / http:// 完整 URL 输入
        assert_eq!(
            parse_probe_target("https://192.168.10.253:8001/"),
            ("192.168.10.253".to_string(), Some(8001))
        );
        assert_eq!(
            parse_probe_target("http://192.168.10.253:8000/webman"),
            ("192.168.10.253".to_string(), Some(8000))
        );
        // 协议头未写端口 → https 默认 443、http 默认 80
        assert_eq!(
            parse_probe_target("https://192.168.10.253"),
            ("192.168.10.253".to_string(), Some(443))
        );
        assert_eq!(
            parse_probe_target("http://192.168.10.253"),
            ("192.168.10.253".to_string(), Some(80))
        );
    }

    /// 【APP40 任务1 / APP50 任务3】未输入目标必须返回友好提示；
    /// 纯 IP 现在合法——默认探测 http:80 / https:443（最多 2 次延迟测试，
    /// 绝不盲目扫描其他端口），目标不可达时返回「未能通过」失败文案。
    #[tokio::test]
    async fn test_probe_requires_explicit_port() {
        let lan = GoLanSettings {
            enabled: true,
            lan_cidrs: vec!["192.168.10.0/24".into()],
            wg_config: Some(WgManualConfig {
                server: "home.example.com".into(),
                server_port: 51820,
                private_key: test_key(30),
                peer_public_key: test_key(31),
                pre_shared_key: None,
                local_ip: "10.9.0.2/32".into(),
                mtu: 1420,
            }),
            ..Default::default()
        };
        // 未输入目标 → 友好提示
        let r = probe_intranet_ip(None, "", "", true, true, &lan).await;
        assert!(!r.reachable, "无输入必须直接提示: {r:?}");
        assert!(
            r.message.contains("IP:端口"),
            "必须提示用户输入 IP:端口: {}",
            r.message
        );
        // 【APP50 任务3】纯 IP 不再被拦截：进入默认 80/443 探测流程。
        // 可达性取决于测试环境（本机恰在同网段且目标在线时会真实连通成功），
        // 因此只断言文案结构：含目标 IP、绝无「请输入端口」拦截、
        // 绝无「延迟仅 1 ms」式误报
        let r = probe_intranet_ip(Some("192.168.10.253"), "", "", true, true, &lan).await;
        assert!(r.message.contains("192.168.10.253"), "{}", r.message);
        assert!(
            !r.message.contains("请输入"),
            "纯 IP 不得再被端口拦截: {}",
            r.message
        );
        assert!(
            !r.message.contains("延迟仅"),
            "超时不得误报为低延迟: {}",
            r.message
        );
        // 显式 IP:端口 且内核未运行 → 提示启动
        let r = probe_intranet_ip(Some("192.168.10.253:8001"), "", "", false, true, &lan).await;
        assert!(r.message.contains("VPN 尚未启动"), "{}", r.message);
    }

    /// 【APP50 任务3】「清空当前配置」后的空档案必须可保存：
    /// enabled=false 的空档案（无 WG 私钥/服务端/网段）不得触发
    /// save_go_lan_settings 的「请先填写完整的回家节点参数」校验拦截，
    /// 且顶层旧字段不得被反向回填。
    #[test]
    fn empty_disabled_profile_is_saveable() {
        let mut s = GoLanSettings {
            // 模拟清空前顶层残留的旧配置
            wg_config: Some(WgManualConfig {
                server: "old.example.com".into(),
                server_port: 51820,
                private_key: test_key(40),
                peer_public_key: test_key(41),
                pre_shared_key: None,
                local_ip: "10.0.0.2/32".into(),
                mtu: 1420,
            }),
            lan_cidrs: vec!["192.168.10.0/24".into()],
            ..Default::default()
        };
        s.profiles.push(GoLanProfile {
            id: "home".into(),
            name: "家里".into(),
            enabled: false, // 清空后的空档案
            ..Default::default()
        });
        normalize_go_lan_settings(&mut s);
        // save_go_lan_settings 的拒绝条件为 enabled && !is_configured(&lan)
        assert!(
            !(s.enabled && !is_configured(&s)),
            "空档案（enabled=false）保存不得被校验拦截"
        );
        // 无启用档案时顶层字段必须同步清空（严禁反向回填旧配置）
        assert!(s.wg_config.is_none(), "顶层 wg_config 必须清空");
        assert!(s.lan_cidrs.is_empty(), "顶层 lan_cidrs 必须清空");
    }

    #[test]
    fn test_build_wg_outbound() {
        let lan = GoLanSettings {
            enabled: true,
            wg_config: Some(WgManualConfig {
                server: "home.example.com".into(),
                server_port: 51820,
                private_key: test_key(1),
                peer_public_key: test_key(2),
                pre_shared_key: None,
                local_ip: "10.0.0.2/32".into(),
                mtu: 1420,
            }),
            ..Default::default()
        };
        let (outbound, _) = build_outbound(&lan);
        let ob = outbound.expect("应构建出 WireGuard 出站");
        assert_eq!(ob["type"], "wireguard");
        assert_eq!(ob["tag"], GO_LAN_TAG);
        // 【APP6 任务2】顶层单节点模式（connect=true）：server/server_port/
        // peer_public_key 全部在顶层，严禁 peers / allowed_ips /
        // persistent_keepalive_interval（peers 数组在 iOS 走 ListenPacket
        // 双栈非连接 Socket 被 NECP 拦截，顶层单节点走 DialContext("udp4")）
        assert_eq!(ob["server_port"], 51820);
        assert!(ob.get("peers").is_none(), "顶层单节点模式严禁 peers 数组");
        assert!(ob.get("allowed_ips").is_none(), "顶层严禁出现 allowed_ips");
        assert!(
            ob.get("persistent_keepalive_interval").is_none(),
            "严禁 persistent_keepalive_interval（sing-box v1.11.3 不支持）"
        );
        assert_eq!(ob["peer_public_key"].as_str(), Some(test_key(2).as_str()));
        // 【IPA9 任务4.3】不再写死 inet4_bind_address（5G 蜂窝下引发 i/o
        // timeout），改由扩展侧 prism_protect_socket 动态绑定物理网卡
        assert!(
            ob.get("inet4_bind_address").is_none(),
            "严禁 inet4_bind_address（5G 蜂窝下导致 i/o timeout）"
        );
        assert_eq!(ob["domain_strategy"], "ipv4_only");
        // 【APP17 任务5.1】local_address 只写第 1 个主隧道地址，并保持 /24
        // 前缀（gVisor 需同子网前缀识别邻居；其余地址转 /24 进 ip_cidr）
        assert_eq!(ob["local_address"][0], "10.0.0.2/24");
        // 密钥必须是重编码后的标准 44 位 Base64
        assert_eq!(ob["private_key"].as_str(), Some(test_key(1).as_str()));
        assert_eq!(
            ob["private_key"].as_str().unwrap().len(),
            44,
            "输出必须是标准 44 位 Base64"
        );
        // 【APP48 任务1.2】内核 JSON 的 MTU 无条件锁死 GO_LAN_RUNTIME_MTU（1380）
        assert_eq!(
            ob["mtu"].as_u64(),
            Some(GO_LAN_RUNTIME_MTU as u64),
            "go-lan-home 写入内核的 MTU 必须为 1380"
        );
        assert_eq!(
            ob["connect_timeout"].as_str(),
            Some("5s"),
            "go-lan-home 必须设置 connect_timeout 5s，避免半开连接挂起 2m7s"
        );
    }

    /// 【APP48 任务1.2】无论用户配置多少（1280 / 1400 / 1500 / 9000），
    /// 写入内核 JSON 的 go-lan-home MTU 一律统一为 1380（MSS 1340）。
    #[test]
    fn test_wg_runtime_mtu_unified() {
        let make = |mtu: u32| GoLanSettings {
            enabled: true,
            wg_config: Some(WgManualConfig {
                server: "home.example.com".into(),
                server_port: 51820,
                private_key: test_key(10),
                peer_public_key: test_key(11),
                pre_shared_key: None,
                local_ip: "10.0.0.2/32".into(),
                mtu,
            }),
            ..Default::default()
        };
        for mtu in [0_u32, 1000, 1280, 1400, 1420, 1500, 9000] {
            let (outbound, _) = build_outbound(&make(mtu));
            let ob = outbound.expect("合法配置应构建出站");
            assert_eq!(
                ob["mtu"].as_u64(),
                Some(GO_LAN_RUNTIME_MTU as u64),
                "用户配置 MTU {mtu} 必须统一改写为 1380"
            );
        }
    }

    /// 【APP21 任务3.1】逗号分隔的多虚拟地址必须完整保留全部地址
    /// （含原前缀），严禁只取第 1 个丢弃其余地址。
    #[test]
    fn test_parse_all_wg_local_addresses() {
        // 方案指定用例：多地址保留全部原前缀
        let (addrs, cidrs) = parse_all_wg_local_addresses("10.196.0.2/32,192.168.10.222/24");
        assert_eq!(addrs, vec!["10.196.0.2/32", "192.168.10.222/24"]);
        assert_eq!(cidrs, vec!["10.196.0.0/24", "192.168.10.0/24"]);

        // 分号 / 中文标点 / 换行 / 空白分隔同样支持
        for raw in [
            "10.196.0.2/32;192.168.10.222/24",
            "10.196.0.2/32，192.168.10.222/24",
            "10.196.0.2/32\n192.168.10.222/24",
            "10.196.0.2/32 192.168.10.222/24",
            "10.196.0.2/32, 192.168.10.222/24",
        ] {
            let (a, c) = parse_all_wg_local_addresses(raw);
            assert_eq!(a, vec!["10.196.0.2/32", "192.168.10.222/24"], "分隔符 {raw:?} 解析失败");
            assert_eq!(c, vec!["10.196.0.0/24", "192.168.10.0/24"]);
        }

        // 输入框截断的 /2 小掩码自动还原为 /24
        let (a2, _) = parse_all_wg_local_addresses("10.196.0.2/32, 192.168.10.222/2");
        assert_eq!(a2, vec!["10.196.0.2/32", "192.168.10.222/24"]);

        // 只有 1 个地址时统一 /24（协议栈需同子网前缀识别邻居）
        let (a3, _) = parse_all_wg_local_addresses("10.196.0.2/32");
        assert_eq!(a3, vec!["10.196.0.2/24"]);

        // 无掩码自动补 /24；无有效 IPv4 返回空数组（调用方兜底）
        let (a4, _) = parse_all_wg_local_addresses("10.8.0.2");
        assert_eq!(a4, vec!["10.8.0.2/24"]);
        let (a5, _) = parse_all_wg_local_addresses("");
        assert!(a5.is_empty());
    }

    /// 【APP15 任务1.1 / APP17 任务5.1】逗号分隔的 Local Address 必须正确
    /// 拆分为主隧道地址（统一 /24）+ 各地址对应的 /24 回家网段，
    /// 绝不能再回退硬编码 10.0.0.2/24 丢地址。
    #[test]
    fn test_parse_wg_local_addresses() {
        let (primary, extras) = parse_wg_local_addresses("10.196.0.2/32,192.168.10.222/24");
        assert_eq!(primary, "10.196.0.2/24", "主隧道地址必须取第 1 个并统一 /24");
        assert_eq!(extras, vec!["10.196.0.0/24", "192.168.10.0/24"]);

        // 分号 / 中文标点 / 换行 / 空白分隔同样支持
        for raw in [
            "10.196.0.2/32;192.168.10.222/24",
            "10.196.0.2/32，192.168.10.222/24",
            "10.196.0.2/32\n192.168.10.222/24",
            "10.196.0.2/32 192.168.10.222/24",
        ] {
            let (p, e) = parse_wg_local_addresses(raw);
            assert_eq!(p, "10.196.0.2/24", "分隔符 {raw:?} 解析失败");
            assert_eq!(e, vec!["10.196.0.0/24", "192.168.10.0/24"]);
        }

        // 单个 /24 地址保持 /24
        assert_eq!(parse_wg_local_addresses("10.8.0.2/24").0, "10.8.0.2/24");
        // 无有效 IPv4 → 兜底安全默认
        assert_eq!(parse_wg_local_addresses("").0, "10.0.0.2/24");
    }

    /// 【APP15 任务1.1】逗号地址时，第 2 个地址所在网段必须自动并入回家路由
    #[test]
    fn test_go_lan_route_rules_merges_extra_lan_cidrs() {
        let lan = GoLanSettings {
            enabled: true,
            bypass_on_local_lan: false,
            lan_cidrs: vec![],
            wg_config: Some(WgManualConfig {
                server: "home.example.com".into(),
                server_port: 51820,
                private_key: test_key(12),
                peer_public_key: test_key(13),
                pre_shared_key: None,
                local_ip: "10.196.0.2/32,192.168.10.222/24".into(),
                mtu: 1420,
            }),
            ..Default::default()
        };
        let (rules, _) = go_lan_route_rules(&lan);
        let cidrs: Vec<String> = rules
            .iter()
            .filter_map(|r| r.get("ip_cidr").and_then(Value::as_array))
            .flatten()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect();
        assert!(
            cidrs.contains(&"10.196.0.0/24".to_string()),
            "主隧道地址 /24 必须并入: {cidrs:?}"
        );
        assert!(
            cidrs.contains(&"192.168.10.0/24".to_string()),
            "第 2 个地址 /24 必须并入: {cidrs:?}"
        );
    }

    #[test]
    fn test_normalize_url_encoded_psk() {
        // 崩溃场景还原：末尾 '=' 被 URL 编码成 %3D，byte 43 变成 '%'
        let std_b64 = test_key(3);
        let url_encoded = std_b64.replace('=', "%3D");
        assert_eq!(
            normalize_wg_key(&url_encoded).as_deref(),
            Some(std_b64.as_str()),
            "%3D 必须还原为 '=' 并输出标准 44 位 Base64"
        );
    }

    #[test]
    fn test_normalize_variants() {
        let std_b64 = test_key(4);
        // 引号 + 换行 + \r
        let quoted = format!("\"{}\"\r\n", std_b64.trim_end_matches('='));
        assert_eq!(normalize_wg_key(&quoted).as_deref(), Some(std_b64.as_str()));
        // URL-safe（-/ _）且缺末尾填充
        let urlsafe = std_b64
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_");
        assert_eq!(
            normalize_wg_key(&urlsafe).as_deref(),
            Some(std_b64.as_str())
        );
        // 43 位缺末尾 '='
        assert_eq!(
            normalize_wg_key(std_b64.trim_end_matches('=')).as_deref(),
            Some(std_b64.as_str())
        );
        // Hex 64 位直通
        let hex: String = (0..32u8).map(|i| format!("{:02x}", i ^ 0x3C)).collect();
        assert!(normalize_wg_key(&hex).is_some(), "64 位 Hex 应可解码");
        // 非法输入一律 None
        assert!(normalize_wg_key("").is_none());
        assert!(normalize_wg_key("   ").is_none());
        assert!(normalize_wg_key(&"A".repeat(43)).is_none(), "全 0 密钥拒绝");
        assert!(normalize_wg_key(&"A".repeat(42)).is_none(), "长度不对拒绝");
        assert!(normalize_wg_key("short-broken").is_none());
    }

    #[test]
    fn test_broken_psk_dropped() {
        let lan = GoLanSettings {
            enabled: true,
            wg_config: Some(WgManualConfig {
                server: "home.example.com".into(),
                server_port: 51820,
                private_key: test_key(5),
                peer_public_key: test_key(6),
                // 模拟 %3D 未解码且长度损坏的 PSK
                pre_shared_key: Some("short-broken%3D".into()),
                local_ip: "10.0.0.2/32".into(),
                mtu: 1420,
            }),
            ..Default::default()
        };
        let (outbound, warnings) = build_outbound(&lan);
        let ob = outbound.expect("合法私钥/公钥仍应构建出站");
        assert!(
            ob.get("pre_shared_key").is_none(),
            "损坏的 PSK 不得写入配置"
        );
        assert!(!warnings.is_empty(), "PSK 被忽略时应有警告");
    }

    #[test]
    fn test_invalid_required_keys_skip_outbound() {
        let lan = GoLanSettings {
            enabled: true,
            wg_config: Some(WgManualConfig {
                server: "home.example.com".into(),
                server_port: 51820,
                private_key: "PRIV".into(),
                peer_public_key: "PUB".into(),
                pre_shared_key: None,
                local_ip: "10.0.0.2/32".into(),
                mtu: 1420,
            }),
            ..Default::default()
        };
        let (outbound, warnings) = build_outbound(&lan);
        assert!(outbound.is_none(), "无效必填密钥不得注入出站");
        assert!(warnings.iter().any(|w| w.contains("32 字节")));
    }

    #[test]
    fn test_wireguard_uri_with_encoded_keys() {
        let priv_key = test_key(7);
        let peer = test_key(8);
        let psk = test_key(9);
        let uri = format!(
            "wireguard://{priv_key}%3D@home.example.com:51820/?address=10.0.0.2%2F32&publickey={peer}&presharedkey={psk_trimmed}%3D&mtu=1420",
            psk_trimmed = psk.trim_end_matches('='),
        );
        let wg = parse_wireguard_uri(&uri).expect("wireguard:// 解析成功");
        assert_eq!(wg.private_key, priv_key);
        assert_eq!(wg.peer_public_key, peer);
        assert_eq!(wg.pre_shared_key.as_deref(), Some(psk.as_str()));
        assert_eq!(wg.local_ip, "10.0.0.2/32");
        assert_eq!(wg.mtu, 1420);
        assert_eq!(wg.server, "home.example.com");
        assert_eq!(wg.server_port, 51820);
    }

    #[test]
    fn test_wireguard_uri_invalid_key_rejected() {
        let uri = format!(
            "wireguard://{}@home.example.com:51820/?publickey={}",
            "not-a-valid-key",
            test_key(10)
        );
        assert!(parse_wireguard_uri(&uri).is_err());
    }

    #[test]
    fn test_wireguard_conf_split_once() {
        // 回归：PresharedKey 末尾的 '=' 必须保留——split_once('=') 铁律
        let priv_key = test_key(11);
        let peer = test_key(12);
        let psk = test_key(13);
        let conf = format!(
            "[Interface]\r\nPrivateKey = {priv_key}\r\nAddress = 10.0.0.2/32\r\nMTU = 1400\r\n\r\n[Peer]\r\nPublicKey = {peer}\r\nPresharedKey = {psk}\r\nEndpoint = home.example.com:51820\r\nAllowedIPs = 192.168.0.0/16\r\n"
        );
        let wg = parse_wireguard_conf(&conf).expect(".conf 解析成功");
        assert_eq!(wg.private_key, priv_key);
        assert_eq!(wg.peer_public_key, peer);
        assert_eq!(wg.pre_shared_key.as_deref(), Some(psk.as_str()));
        assert_eq!(wg.local_ip, "10.0.0.2/32");
        assert_eq!(wg.mtu, 1400);
    }

    /// 【APP-4 任务4】微信折行 .conf：44 位 Base64 密钥被折成两行
    /// （PrivateKey =\nxxxx \nyyyy=），折行合并后必须还原完整密钥
    #[test]
    fn test_parse_conf_with_wrapped_lines() {
        let priv_key = test_key(21);
        let peer = test_key(22);
        // 把密钥从中间折断成两行（模拟微信自动换行）
        let (pk_a, pk_b) = priv_key.split_at(20);
        let (pub_a, pub_b) = peer.split_at(30);
        let conf = format!(
            "[Interface]\nPrivateKey =\n{pk_a}\n{pk_b}\nAddress = 10.1.8.2/24\n\n[Peer]\nPublicKey = {pub_a}\n{pub_b}\nEndpoint = ishow.indevs.in:51820\nAllowedIPs = 0.0.0.0/0\n"
        );
        let wg = parse_wireguard_conf(&conf).expect("折行 .conf 必须解析成功");
        assert_eq!(wg.private_key, priv_key, "折行私钥必须完整还原");
        assert_eq!(wg.peer_public_key, peer, "折行公钥必须完整还原");
        assert_eq!(wg.server, "ishow.indevs.in");
        assert_eq!(wg.server_port, 51820);
        assert_eq!(wg.local_ip, "10.1.8.2/24");
    }

    #[test]
    fn test_build_outbound_via_wireguard_uri() {
        let priv_key = test_key(14);
        let peer = test_key(15);
        let lan = GoLanSettings {
            enabled: true,
            node_uri: format!(
                "wireguard://{priv_key}@10.1.2.3:51820/?publickey={peer}&address=10.0.0.5/32"
            ),
            lan_cidrs: vec!["192.168.1.0/24".into()],
            ..Default::default()
        };
        let (outbound, _) = build_outbound(&lan);
        let ob = outbound.expect("wireguard:// 链接应构建出出站");
        assert_eq!(ob["tag"], GO_LAN_TAG);
        assert_eq!(ob["private_key"].as_str(), Some(priv_key.as_str()));
        // 【APP6 任务2】顶层单节点结构：public_key → 顶层 peer_public_key
        assert_eq!(ob["peer_public_key"].as_str(), Some(peer.as_str()));
        assert_eq!(ob["server"], "10.1.2.3");
        assert!(ob.get("peers").is_none(), "顶层单节点模式严禁 peers 数组");
        assert!(
            ob.get("persistent_keepalive_interval").is_none(),
            "严禁 persistent_keepalive_interval"
        );
    }

    #[test]
    fn test_route_rules_order_safety() {
        // 规则只含 ip_cidr / domain_suffix，且出站为 go-lan-home；
        // config_builder 负责将其插在 geosite: private 之前（见 config_builder 测试）。
        let lan = GoLanSettings {
            enabled: true,
            bypass_on_local_lan: false,
            lan_cidrs: vec!["192.168.1.0/24".into()],
            lan_domains: vec!["*.nas.home".into()],
            ..Default::default()
        };
        let (rules, _) = go_lan_route_rules(&lan);
        assert_eq!(rules.len(), 2);
        // 【APP30 任务2】ip_cidr 规则严格第一，域名规则紧随其后
        assert_eq!(rules[0]["ip_cidr"][0], "192.168.1.0/24");
        assert_eq!(rules[0]["outbound"], GO_LAN_TAG);
        assert_eq!(rules[1]["domain_suffix"][0], "nas.home");
    }

    #[test]
    fn test_invalid_cidr_filtered() {
        let lan = GoLanSettings {
            enabled: true,
            bypass_on_local_lan: false,
            lan_cidrs: vec!["10.77.0.0/24".into(), "bad-cidr".into(), "10.0.0.0/33".into()],
            ..Default::default()
        };
        let (rules, warnings) = go_lan_route_rules(&lan);
        let tunnel_rules = rules.iter().filter(|r| r["outbound"] == GO_LAN_TAG).count();
        assert_eq!(tunnel_rules, 1);
        assert_eq!(warnings.len(), 2);
    }

    /// 【IPA9 任务4.1】多行内网网段解析回归：用户分两行输入
    /// `10.1.8.0/24` 与 `192.168.10.0/24`，前端按 `/[\r\n,;，；\s]+/`
    /// 拆分后传入后端。normalize_cidr_list 必须完整保留两个网段，
    /// 绝不能因隐形字符清洗把换行吞掉拼成 `10.1.8.0/24192.168.10.0/24`。
    #[test]
    fn test_multi_line_cidrs_preserved() {
        let cidrs = vec![
            "10.1.8.0/24".to_string(),
            "192.168.10.0/24".to_string(),
        ];
        let normalized = normalize_cidr_list(&cidrs, "");
        assert!(
            normalized.contains(&"10.1.8.0/24".to_string()),
            "第一行网段 10.1.8.0/24 必须保留: {normalized:?}"
        );
        assert!(
            normalized.contains(&"192.168.10.0/24".to_string()),
            "第二行网段 192.168.10.0/24 必须保留: {normalized:?}"
        );
    }

    /// 【IPA9 任务4.1】主机位非零的 CIDR（如 192.168.10.253/24）必须按掩码
    /// 与运算规范化为网络前缀 192.168.10.0/24，避免内核路由匹配失败。
    #[test]
    fn test_host_bits_normalized_to_network() {
        let cidrs = vec!["192.168.10.253/24".to_string()];
        let normalized = normalize_cidr_list(&cidrs, "");
        assert!(
            normalized.contains(&"192.168.10.0/24".to_string()),
            "主机位非零必须归一化为网络前缀: {normalized:?}"
        );
    }

    #[test]
    fn test_dns_synthesis() {
        let lan = GoLanSettings {
            enabled: true,
            lan_dns: Some("192.168.1.1".into()),
            lan_domains: vec!["nas.home".into()],
            ..Default::default()
        };
        let (server, rule) = go_lan_dns(&lan);
        assert_eq!(server.unwrap()["tag"], GO_LAN_DNS_TAG);
        assert_eq!(rule.unwrap()["server"], GO_LAN_DNS_TAG);
    }

    #[test]
    fn test_disabled_produces_nothing() {
        let lan = GoLanSettings::default();
        let (outbound, _) = build_outbound(&lan);
        assert!(outbound.is_none());
        let (rules, _) = go_lan_route_rules(&lan);
        assert!(rules.is_empty());
    }

    // ----------------------------------------------------------------
    // APP-11B 任务1.4：\u2060（U+2060 Word Joiner）等隐形字符清洗回归测试
    //
    // 真机日志（erro-2.txt Build 211）：
    //   decode config: outbounds[3].local_address:
    //   netip.ParsePrefix("10.195.0.2/32\u2060"): bad bits after slash
    // iOS 剪贴板从微信/网页长按复制时自动塞入 \u2060，`.trim()` /
    // `.trimmingCharacters(.whitespacesAndNewlines)` 均无法去除
    // （U+2060 不属于 Unicode Whitespace）。必须物理剔除所有
    // 非可见 ASCII 字符。
    // ----------------------------------------------------------------

    #[test]
    fn test_strip_invisible_removes_word_joiner() {
        // U+2060 Word Joiner（真机报错元凶）
        let s = "10.195.0.2/32\u{2060}";
        assert_eq!(strip_invisible_and_non_ascii(s), "10.195.0.2/32");
    }

    #[test]
    fn test_strip_invisible_removes_zero_width_family() {
        // U+200B Zero Width Space / U+200C ZWNJ / U+200D ZWJ / U+FEFF BOM
        assert_eq!(strip_invisible_and_non_ascii("abc\u{200B}def"), "abcdef");
        assert_eq!(strip_invisible_and_non_ascii("abc\u{200C}def"), "abcdef");
        assert_eq!(strip_invisible_and_non_ascii("abc\u{200D}def"), "abcdef");
        assert_eq!(strip_invisible_and_non_ascii("\u{FEFF}10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn test_strip_invisible_removes_whitespace_and_non_ascii() {
        // 空格、Tab、换行、中文全被剔除
        assert_eq!(strip_invisible_and_non_ascii(" 10.0.0.1 "), "10.0.0.1");
        assert_eq!(strip_invisible_and_non_ascii("10.0.0.1\n"), "10.0.0.1");
        assert_eq!(strip_invisible_and_non_ascii("10.0.0.1中"), "10.0.0.1");
    }

    #[test]
    fn test_strip_invisible_preserves_visible_ascii() {
        // 所有可见 ASCII 原样保留
        assert_eq!(strip_invisible_and_non_ascii("abc123!@#"), "abc123!@#");
        assert_eq!(
            strip_invisible_and_non_ascii("example.com:51820"),
            "example.com:51820"
        );
    }

    #[test]
    fn test_sanitize_ip_prefix_word_joiner_real_world() {
        // 真机日志原文："10.195.0.2/32\u{2060}"
        let raw = "10.195.0.2/32\u{2060}";
        assert_eq!(
            sanitize_ip_prefix(raw, 32),
            Some("10.195.0.2/32".to_string())
        );
    }

    #[test]
    fn test_sanitize_ip_prefix_no_slash_appends_default() {
        // 无斜杠时补默认前缀
        assert_eq!(
            sanitize_ip_prefix("10.195.0.2", 32),
            Some("10.195.0.2/32".to_string())
        );
        assert_eq!(
            sanitize_ip_prefix("192.168.1.0", 24),
            Some("192.168.1.0/24".to_string())
        );
    }

    #[test]
    fn test_sanitize_ip_prefix_strips_quotes_and_spaces() {
        // 复制粘贴常带引号、空格
        assert_eq!(
            sanitize_ip_prefix("\"10.0.0.1/32\"", 32),
            Some("10.0.0.1/32".to_string())
        );
        assert_eq!(
            sanitize_ip_prefix("  10.0.0.1/32  ", 32),
            Some("10.0.0.1/32".to_string())
        );
    }

    #[test]
    fn test_sanitize_ip_prefix_invalid_falls_back_to_none() {
        // 完全非法的输入返回 None（由调用方决定 fallback）
        assert_eq!(sanitize_ip_prefix("not-an-ip", 32), None);
        assert_eq!(sanitize_ip_prefix("", 32), None);
    }

    // ----------------------------------------------------------------
    // APP40 任务2：多路内网档案（Profiles）回归测试
    // --------------------------------------------------------------

    fn sample_wg(seed: u8, local_ip: &str) -> WgManualConfig {
        WgManualConfig {
            server: "home.example.com".into(),
            server_port: 51820,
            private_key: test_key(seed),
            peer_public_key: test_key(seed.wrapping_add(1)),
            pre_shared_key: None,
            local_ip: local_ip.into(),
            mtu: 1420,
        }
    }

    fn sample_profile(id: &str, name: &str, cidrs: &[&str], local_ip: &str, seed: u8) -> GoLanProfile {
        GoLanProfile {
            id: id.into(),
            name: name.into(),
            enabled: true,
            bypass_on_local_lan: true,
            local_wifi_ssid: String::new(),
            lan_cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
            wg_config: Some(sample_wg(seed, local_ip)),
            node_uri: String::new(),
            probe_target: String::new(),
        }
    }

    /// 旧版单配置加载后必须自动生成「家里」档案，且不丢任何字段。
    #[test]
    fn test_normalize_migrates_legacy_settings() {
        let mut lan = GoLanSettings {
            enabled: true,
            mode: "manual".into(),
            node_uri: String::new(),
            wg_config: Some(sample_wg(20, "10.196.0.2/32")),
            lan_cidrs: vec!["192.168.10.0/24".into()],
            ..Default::default()
        };
        normalize_go_lan_settings(&mut lan);
        assert_eq!(lan.profiles.len(), 1);
        let p = &lan.profiles[0];
        assert_eq!(p.id, "home");
        assert_eq!(p.name, "家里");
        assert!(p.enabled);
        // 【APP45 任务1.1】On-Demand 默认关闭（避免回家网段被误判本地直连）
        assert!(!p.bypass_on_local_lan);
        assert_eq!(p.lan_cidrs, vec!["192.168.10.0/24".to_string()]);
        assert_eq!(
            p.wg_config.as_ref().map(|w| w.server.as_str()),
            Some("home.example.com")
        );
        assert_eq!(lan.active_profile_id, "home");

        // 再次归一化必须幂等（不重复生成档案）
        normalize_go_lan_settings(&mut lan);
        assert_eq!(lan.profiles.len(), 1);

        // 空配置不生成任何档案
        let mut empty = GoLanSettings::default();
        normalize_go_lan_settings(&mut empty);
        assert!(empty.profiles.is_empty());
    }

    /// 档案 id 冲突 / 缺失时必须自动补齐为唯一 id。
    #[test]
    fn test_normalize_dedupes_profile_ids() {
        let mut lan = GoLanSettings {
            enabled: true,
            profiles: vec![
                sample_profile("", "", &["10.1.0.0/24"], "10.9.0.2/32", 40),
                sample_profile("office", "", &["10.2.0.0/24"], "10.10.0.2/32", 42),
                sample_profile("office", "公司2", &["10.3.0.0/24"], "10.11.0.2/32", 44),
            ],
            ..Default::default()
        };
        normalize_go_lan_settings(&mut lan);
        let ids: Vec<String> = lan.profiles.iter().map(|p| p.id.clone()).collect();
        assert_eq!(ids, vec!["profile1", "office", "profile3"]);
        assert!(!lan.profiles[0].name.trim().is_empty());
        assert_eq!(lan.active_profile_id, "profile1");
    }

    /// 多档案启用：首个档案恒为 go-lan-home，其余为 go-lan-{id}。
    #[test]
    fn test_multi_profiles_outbounds_and_rules() {
        let lan = GoLanSettings {
            enabled: true,
            profiles: vec![
                GoLanProfile {
                    bypass_on_local_lan: false,
                    ..sample_profile("home", "家里", &["192.168.10.0/24"], "10.196.0.2/32", 50)
                },
                GoLanProfile {
                    bypass_on_local_lan: false,
                    ..sample_profile("office", "公司", &["10.8.0.0/24"], "10.197.0.2/32", 52)
                },
                // 未启用档案绝不生成出站/规则
                GoLanProfile {
                    enabled: false,
                    ..sample_profile("studio", "工作室", &["10.20.0.0/24"], "10.198.0.2/32", 54)
                },
            ],
            lan_domains: vec!["*.nas.home".into()],
            ..Default::default()
        };
        let (outbounds, warnings) = build_outbounds(&lan);
        assert!(warnings.is_empty(), "合法多档案不应产生警告: {warnings:?}");
        assert_eq!(outbounds.len(), 2);
        assert_eq!(outbounds[0]["tag"], GO_LAN_TAG);
        assert_eq!(outbounds[1]["tag"], "go-lan-office");
        for ob in &outbounds {
            assert_eq!(ob["type"], "wireguard");
            assert_eq!(ob["mtu"].as_u64(), Some(GO_LAN_RUNTIME_MTU as u64));
            // 【APP40 任务2】多 Local Address 必须完整保留
            assert!(
                ob["local_address"].as_array().is_some_and(|a| !a.is_empty()),
                "local_address 不得为空"
            );
        }
        let tags: Vec<String> = enabled_profiles(&lan).into_iter().map(|(t, _)| t).collect();
        assert_eq!(tags, vec![GO_LAN_TAG.to_string(), "go-lan-office".to_string()]);

        // 规则：每个启用档案一条 ip_cidr → 对应 tag
        let (rules, _) = go_lan_route_rules(&lan);
        let tunnel: Vec<(String, String)> = rules
            .iter()
            .filter_map(|r| {
                let out = r.get("outbound")?.as_str()?.to_string();
                let first = r.get("ip_cidr")?.as_array()?.first()?.as_str()?.to_string();
                Some((out, first))
            })
            .collect();
        assert!(tunnel.contains(&(GO_LAN_TAG.to_string(), "192.168.10.0/24".to_string())));
        assert!(tunnel.contains(&("go-lan-office".to_string(), "10.8.0.0/24".to_string())));
        assert!(
            !tunnel.iter().any(|(t, _)| t == "go-lan-studio"),
            "未启用档案不得生成规则: {tunnel:?}"
        );
    }

    /// On-Demand：本机物理 IP 落在「家里」网段时直连，公司网段仍走隧道。
    #[test]
    fn test_split_profile_cidrs_on_demand() {
        let home = sample_profile("home", "家里", &["192.168.10.0/24"], "10.196.0.2/32", 60);
        let office = sample_profile("office", "公司", &["10.8.0.0/24"], "10.197.0.2/32", 62);
        let physical: Vec<std::net::Ipv4Addr> =
            vec!["192.168.10.88".parse().unwrap()];

        // 家里：命中同网段 → 直连，隧道内仅保留 WG 虚拟子网
        let (tunnel, direct) = split_profile_cidrs_for_on_demand(&home, &physical);
        assert!(direct.contains(&"192.168.10.0/24".to_string()), "{direct:?}");
        assert!(
            !tunnel.contains(&"192.168.10.0/24".to_string()),
            "命中本机局域网必须退出隧道: {tunnel:?}"
        );
        assert!(tunnel.contains(&"10.196.0.0/24".to_string()), "{tunnel:?}");
        assert!(
            !direct.contains(&"10.196.0.0/24".to_string()),
            "WG 虚拟子网永不直连: {direct:?}"
        );

        // 公司：不在本机局域网 → 全部走隧道
        let (tunnel, direct) = split_profile_cidrs_for_on_demand(&office, &physical);
        assert!(direct.is_empty());
        assert!(tunnel.contains(&"10.8.0.0/24".to_string()));

        // 蜂窝网络（无物理局域网 IP）→ 恢复全部走隧道
        let (tunnel, direct) = split_profile_cidrs_for_on_demand(&home, &[]);
        assert!(direct.is_empty());
        assert!(tunnel.contains(&"192.168.10.0/24".to_string()));

        // 关闭 On-Demand 时即使命中同网段也必须走隧道
        let mut disabled = home.clone();
        disabled.bypass_on_local_lan = false;
        let (tunnel, direct) = split_profile_cidrs_for_on_demand(&disabled, &physical);
        assert!(direct.is_empty());
        assert!(tunnel.contains(&"192.168.10.0/24".to_string()));
    }

    /// 多档案运行时元数据（供 iOS 扩展侧车 golan_profiles.json）。
    #[test]
    fn test_profiles_metadata() {
        let lan = GoLanSettings {
            enabled: true,
            profiles: vec![
                GoLanProfile {
                    local_wifi_ssid: "Home-5G".into(),
                    ..sample_profile("home", "家里", &["192.168.10.0/24"], "10.196.0.2/32", 70)
                },
                GoLanProfile {
                    bypass_on_local_lan: false,
                    ..sample_profile("office", "公司", &["10.8.0.0/24"], "10.197.0.2/32", 72)
                },
            ],
            ..Default::default()
        };
        let meta = profiles_metadata(&lan);
        assert_eq!(meta.len(), 2);
        assert_eq!(meta[0]["tag"], GO_LAN_TAG);
        assert_eq!(meta[0]["name"], "家里");
        assert_eq!(meta[0]["bypassOnLocalLan"], true);
        assert!(
            meta[0]["cidrs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c.as_str() == Some("192.168.10.0/24")),
            "cidrs 必须包含 lan 网段: {meta:?}"
        );
        assert_eq!(meta[1]["tag"], "go-lan-office");
        assert_eq!(meta[1]["bypassOnLocalLan"], false);

        // 未启用时不产生任何元数据
        let mut off = lan.clone();
        off.enabled = false;
        assert!(profiles_metadata(&off).is_empty());
    }

    /// 【APP45 任务1.2】profiles 非空时顶层镜像第 1 个启用档案；
    /// 用户清空档案后严禁把顶层残留 wg_config 回填回来。
    #[test]
    fn test_normalize_mirrors_first_enabled_and_never_refills() {
        let mut lan = GoLanSettings {
            enabled: true,
            profiles: vec![
                sample_profile("home", "家里", &["192.168.10.0/24"], "10.196.0.2/32", 80),
                sample_profile("office", "公司", &["10.8.0.0/24"], "10.197.0.2/32", 82),
            ],
            ..Default::default()
        };
        normalize_go_lan_settings(&mut lan);
        // 顶层镜像第 1 个启用档案（家里）
        assert_eq!(lan.lan_cidrs, vec!["192.168.10.0/24".to_string()]);
        assert!(lan.wg_config.is_some(), "顶层应镜像家里 wg_config");

        // 用户清空「家里」档案（wg_config/lan_cidrs/node_uri 全空）
        lan.profiles[0].wg_config = None;
        lan.profiles[0].lan_cidrs = Vec::new();
        lan.profiles[0].node_uri = String::new();
        normalize_go_lan_settings(&mut lan);
        // 档案保持空（严禁回填），顶层同步镜像空状态
        assert!(lan.profiles[0].wg_config.is_none(), "清空后严禁回填");
        assert!(lan.profiles[0].lan_cidrs.is_empty(), "清空后严禁回填网段");
        assert!(lan.wg_config.is_none(), "档案已空时顶层同步置 None");
        assert!(lan.lan_cidrs.is_empty(), "档案已空时顶层同步置 []");

        // 再次 normalize 幂等：依旧不回填
        normalize_go_lan_settings(&mut lan);
        assert!(lan.profiles[0].wg_config.is_none());

        // 全部档案禁用 → 顶层同步清空
        for p in &mut lan.profiles {
            p.enabled = false;
        }
        normalize_go_lan_settings(&mut lan);
        assert!(lan.wg_config.is_none());
        assert!(lan.lan_cidrs.is_empty());
        assert!(!lan.bypass_on_local_lan);
    }

    /// 【APP45 任务1.1】On-Demand 默认关闭（serde 缺省 + Default 均为 false）。
    #[test]
    fn test_bypass_on_local_lan_defaults_false() {
        assert!(!GoLanProfile::default().bypass_on_local_lan);
        assert!(!GoLanSettings::default().bypass_on_local_lan);
        // serde 缺省（旧 JSON 无此字段）→ false
        let p: GoLanProfile = serde_json::from_str("{}").unwrap();
        assert!(!p.bypass_on_local_lan);
        let s: GoLanSettings = serde_json::from_str("{}").unwrap();
        assert!(!s.bypass_on_local_lan);
    }
}
