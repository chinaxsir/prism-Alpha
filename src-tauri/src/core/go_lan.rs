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
    "https://prism.sarl".into()
}

fn default_mtu() -> u32 {
    1420
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoLanSettings {
    #[serde(default)]
    pub enabled: bool,
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
    }
}

/// APP 任务5：Go Lan 配置完整性检查（未配置时后端兜底拦截启用）。
/// 与前端 ipc.ts `isGoLanConfigured` 逻辑保持一致：
/// - manual：lan_cidrs 非空，且（node_uri 非空，或 wg_config 的
///   server/private_key/peer_public_key 均非空）
/// - managed：device_code 非空且 lan_cidrs 非空（已成功拉取过配置）
pub fn is_configured(lan: &GoLanSettings) -> bool {
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

// ---------------------------------------------------------------- 持久化

pub fn load(data_dir: &std::path::Path) -> GoLanSettings {
    let path = data_dir.join("go_lan.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => GoLanSettings::default(),
    }
}

pub fn save(data_dir: &std::path::Path, settings: &GoLanSettings) -> Result<(), String> {
    let path = data_dir.join("go_lan.json");
    let text = serde_json::to_string_pretty(settings).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- 出站构建

/// 构建回家出站；配置无效返回 (None, 警告)
pub fn build_outbound(lan: &GoLanSettings) -> (Option<Value>, Vec<String>) {
    let mut warnings = Vec::new();
    if !lan.enabled {
        return (None, warnings);
    }
    // 1. 手动 WireGuard
    if let Some(wg) = &lan.wg_config {
        if !wg.server.is_empty() && !wg.private_key.is_empty() && !wg.peer_public_key.is_empty() {
            let mut outbound = json!({
                "type": "wireguard",
                "tag": GO_LAN_TAG,
                "server": wg.server,
                "server_port": wg.server_port,
                "private_key": wg.private_key,
                "peer_public_key": wg.peer_public_key,
                "local_address": [wg.local_ip],
            });
            if let Some(psk) = &wg.pre_shared_key {
                if !psk.is_empty() {
                    outbound["pre_shared_key"] = Value::String(psk.clone());
                }
            }
            if wg.mtu > 0 {
                outbound["mtu"] = json!(wg.mtu);
            }
            return (Some(outbound), warnings);
        }
        warnings.push("WireGuard 配置不完整（服务器/私钥/对端公钥缺失），已忽略".into());
    }
    // 2. 手动分享链接
    if !lan.node_uri.is_empty() {
        match uri_parser::parse_line(&lan.node_uri) {
            Ok(Some(node_value)) => match serde_json::from_value::<ClashNode>(node_value) {
                Ok(node) => match node_to_outbound(&node) {
                    Some((mut outbound, warn)) => {
                        if let Some(w) = warn {
                            warnings.push(w);
                        }
                        outbound["tag"] = json!(GO_LAN_TAG);
                        return (Some(outbound), warnings);
                    }
                    None => warnings.push("回家链接节点类型不受支持，已忽略".into()),
                },
                Err(e) => warnings.push(format!("回家链接解析失败: {e}")),
            },
            Ok(None) => warnings.push("回家链接为空或不支持的协议".into()),
            Err(e) => warnings.push(format!("回家链接解析失败: {e}")),
        }
    }
    // 3. Managed 缓存的出站
    if let Some(cached) = &lan.cached_managed_outbound {
        if cached.get("type").and_then(|t| t.as_str()).is_some() {
            let mut outbound = cached.clone();
            outbound["tag"] = json!(GO_LAN_TAG);
            return (Some(outbound), warnings);
        }
    }
    (None, warnings)
}

// ---------------------------------------------------------------- 规则合成

/// 校验 CIDR 网段合法性
pub(crate) fn is_valid_cidr(cidr: &str) -> bool {
    let Some((ip, mask)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(mask) = mask.parse::<u8>() else {
        return false;
    };
    if ip.contains(':') {
        mask <= 128 && ip.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        mask <= 32 && ip.parse::<std::net::Ipv4Addr>().is_ok()
    }
}

/// 合成回家路由规则（domain_suffix + ip_cidr → go-lan-home）。
/// 这些规则必须插在 `geosite: private` / `ip_is_private -> direct` 之前。
pub(crate) fn go_lan_route_rules(lan: &GoLanSettings) -> (Vec<Value>, Vec<String>) {
    let mut rules = Vec::new();
    let mut warnings = Vec::new();
    if !lan.enabled {
        return (rules, warnings);
    }
    let domains: Vec<String> = lan
        .lan_domains
        .iter()
        .map(|d| d.trim().trim_start_matches("*.").to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    if !domains.is_empty() {
        rules.push(json!({ "domain_suffix": domains, "outbound": GO_LAN_TAG }));
    }
    let cidrs: Vec<String> = lan
        .lan_cidrs
        .iter()
        .map(|c| c.trim().to_string())
        .filter(|c| {
            let ok = is_valid_cidr(c);
            if !ok {
                warnings.push(format!("无效网段「{c}」已忽略"));
            }
            ok
        })
        .collect();
    if !cidrs.is_empty() {
        rules.push(json!({ "ip_cidr": cidrs, "outbound": GO_LAN_TAG }));
    }
    (rules, warnings)
}

/// 合成家庭 DNS 服务器与域名解析规则（lan_dns + lan_domains）。
/// 返回 (dns 服务器配置, dns 规则)；二者需并入内核 dns 配置。
pub(crate) fn go_lan_dns(lan: &GoLanSettings) -> (Option<Value>, Option<Value>) {
    if !lan.enabled {
        return (None, None);
    }
    let Some(dns) = lan.lan_dns.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return (None, None);
    };
    let domains: Vec<String> = lan
        .lan_domains
        .iter()
        .map(|d| d.trim().trim_start_matches("*.").to_lowercase())
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
    save(&data_dir, &lan)?;
    *state.go_lan.write() = lan.clone();
    Ok(lan)
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_wg_outbound() {
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
        let (outbound, _) = build_outbound(&lan);
        let ob = outbound.expect("应构建出 WireGuard 出站");
        assert_eq!(ob["type"], "wireguard");
        assert_eq!(ob["tag"], GO_LAN_TAG);
        assert_eq!(ob["server_port"], 51820);
        assert_eq!(ob["local_address"][0], "10.0.0.2/32");
    }

    #[test]
    fn test_route_rules_order_safety() {
        // 规则只含 ip_cidr / domain_suffix，且出站为 go-lan-home；
        // config_builder 负责将其插在 geosite: private 之前（见 config_builder 测试）。
        let lan = GoLanSettings {
            enabled: true,
            lan_cidrs: vec!["192.168.1.0/24".into()],
            lan_domains: vec!["*.nas.home".into()],
            ..Default::default()
        };
        let (rules, _) = go_lan_route_rules(&lan);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1]["ip_cidr"][0], "192.168.1.0/24");
        assert_eq!(rules[0]["domain_suffix"][0], "nas.home");
    }

    #[test]
    fn test_invalid_cidr_filtered() {
        let lan = GoLanSettings {
            enabled: true,
            lan_cidrs: vec!["192.168.1.0/24".into(), "bad-cidr".into(), "10.0.0.0/33".into()],
            ..Default::default()
        };
        let (rules, warnings) = go_lan_route_rules(&lan);
        assert_eq!(rules.len(), 1);
        assert_eq!(warnings.len(), 2);
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
}
