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

/// 【APP26 任务1.1】go-lan-home 出站隧道 MTU = 1420，与家庭 WireGuard
/// 服务端保持一致（log7.txt 显示 1280 时 Web 端口仍全部失败，说明
/// MTU 并非内网 Web 打不开的根因；真正的根因是 tun-in 的 gvisor 延迟
/// 握手、缺失的 NEProxySettings 与被破坏的系统子网路由，均已在本轮修复）。
pub const GO_LAN_RUNTIME_MTU: u32 = 1420;

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

/// APP-8 任务2：将 WireGuard 对端域名预解析为 IP 地址（同步版）。
///
/// 内核在 post-start 阶段对 wireguard 出站必须同步解析 server 域名，
/// 若 dns-direct 被运营商 RST（明文 TCP 53 嗅探 .indevs.in 等 DDNS），
/// 会直接中断整个 VPN 启动。提前在配置生成阶段把域名换成 IP，post-start
/// 阶段零 DNS 请求、0ms 瞬时启动。
///
/// 本函数在同步配置生成路径调用，仅做零网络请求的快速解析：
/// 1. 已是合法 IP 字面量 → 原样返回；
/// 2. 系统原生解析 `ToSocketAddrs`（优先 IPv4，无 IPv4 取 IPv6）；
/// 3. 失败 → 原样返回域名（iOS 扩展侧 getaddrinfo + 兜底重试接管，
///    见 PacketTunnelProvider.swift resolveHostToIP / go-lan-home 剥离重试）。
pub fn resolve_endpoint_host_to_ip(host: &str) -> String {
    let host = host.trim().trim_end_matches('/');
    if host.is_empty() {
        return host.to_string();
    }
    // 1. 已是 IP 字面量
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    // 【APP26 任务2.2】命中缓存直接 0ms 返回：点击「启动」时 build_config
    // 不再因 DoH/系统 DNS 阻塞数秒（log7.txt 启动耗时 9.8s 的主因之一）。
    let key = host.to_ascii_lowercase();
    if let Some(ip) = endpoint_cache_get(&key) {
        return ip;
    }
    // 2. 未命中：系统原生解析，硬性限时 800ms（超时立即返回域名并在后台刷新）
    if let Some(ip) = resolve_with_deadline(host, 800) {
        endpoint_cache_put(&key, &ip);
        return ip;
    }
    // 3. 超时：后台继续解析并回填缓存，本次先原样返回域名
    //    （扩展侧 getaddrinfo + go-lan 剥离兜底仍会接管）。
    let host_owned = host.to_string();
    std::thread::spawn(move || {
        if let Some(ip) = resolve_with_deadline(&host_owned, 5000) {
            endpoint_cache_put(&host_owned.to_ascii_lowercase(), &ip);
        }
    });
    host.to_string()
}

/// 【APP26 任务2.2】WireGuard Endpoint 域名 → IPv4 的进程内缓存。
/// 首次解析命中后写入，后续 build_config 直接 0ms 取用。
fn endpoint_ip_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, String>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn endpoint_cache_get(key: &str) -> Option<String> {
    endpoint_ip_cache()
        .lock()
        .ok()
        .and_then(|c| c.get(key).cloned())
}

fn endpoint_cache_put(key: &str, ip: &str) {
    if let Ok(mut c) = endpoint_ip_cache().lock() {
        c.insert(key.to_string(), ip.to_string());
    }
}

/// 【APP26 任务2.2】限时域名解析：工作线程解析 + 通道超时，绝不阻塞调用方。
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

/// 【APP18 任务3 / APP19 任务4】需要发送协议首包、读取远端特征字节的端口。
/// 445 走 SMB2 Negotiate，21 走 FTP 欢迎语；139/515/631/9100 等无统一
/// 明文欢迎语的服务以 TCP 建连成功判定（流量已穿过 go-lan-home）。
fn is_raw_probe_port(port: u16) -> bool {
    matches!(port, 3389 | 22 | 21 | 445 | 139 | 515 | 631 | 9100)
}

/// 【APP18 任务3】单端口探测命中结果。
struct PortProbeHit {
    port: u16,
    detail: String,
    latency_ms: u64,
}

/// 【APP18 任务3】经本地 mixed 入站建立到 (ip, port) 的 SOCKS5 连接。
/// 手写最小握手（免认证 + CONNECT IPv4），零额外依赖。
async fn socks5_connect(
    mixed_port: u16,
    ip: &str,
    port: u16,
) -> Result<tokio::net::TcpStream, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(("127.0.0.1", mixed_port)),
    )
    .await
    .map_err(|_| "本地代理连接超时".to_string())?
    .map_err(|e| format!("本地代理连接失败: {e}"))?;

    // 1) 问候：仅支持免认证
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| format!("SOCKS5 问候写入失败: {e}"))?;
    let mut head = [0u8; 2];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|e| format!("SOCKS5 问候读取失败: {e}"))?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err("本地代理不支持免认证 SOCKS5".into());
    }

    // 2) CONNECT 目标 IPv4
    let v4: std::net::Ipv4Addr = ip
        .parse()
        .map_err(|_| format!("目标 IP 非 IPv4 字面量: {ip}"))?;
    let mut req = vec![0x05u8, 0x01, 0x00, 0x01];
    req.extend_from_slice(&v4.octets());
    req.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&req)
        .await
        .map_err(|e| format!("SOCKS5 CONNECT 写入失败: {e}"))?;

    let mut rep = [0u8; 4];
    stream
        .read_exact(&mut rep)
        .await
        .map_err(|e| format!("SOCKS5 CONNECT 应答读取失败: {e}"))?;
    if rep[0] != 0x05 || rep[1] != 0x00 {
        return Err(format!("SOCKS5 目标不可达 (code 0x{:02x})", rep[1]));
    }
    match rep[3] {
        0x01 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await.map_err(|e| e.to_string())?;
            let mut b = vec![0u8; l[0] as usize];
            stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        }
        0x04 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        }
        _ => return Err("SOCKS5 应答地址类型异常".into()),
    }
    let mut tail = [0u8; 2];
    stream.read_exact(&mut tail).await.map_err(|e| e.to_string())?;
    Ok(stream)
}

/// 【APP18 任务3】建立探测流：优先经本地 mixed 代理（SOCKS5），
/// 失败再回落到 TUN 直连（VPN 运行中时 App 进程的 TCP 同样被 utun 默认
/// 路由接管，与 Safari / 远程桌面走同一条 go-lan-home 路径）。
async fn open_probe_stream(
    ip: &str,
    port: u16,
    mixed_port: u16,
) -> Result<tokio::net::TcpStream, String> {
    let mut proxy_err = String::new();
    if mixed_port > 0 {
        match socks5_connect(mixed_port, ip, port).await {
            Ok(s) => return Ok(s),
            Err(e) => proxy_err = e,
        }
    }
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect((ip, port)),
    )
    .await
    {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(if proxy_err.is_empty() {
            format!("直连失败: {e}")
        } else {
            format!("{proxy_err}; 直连失败: {e}")
        }),
        Err(_) => Err(if proxy_err.is_empty() {
            "连接超时".to_string()
        } else {
            format!("{proxy_err}; 直连超时")
        }),
    }
}

/// 【APP18 任务3】对 RDP(3389) / SSH(22) / SMB(445) 发送协议首包并读取远端
/// 特征字节：只有真实在线的内网主机才会回 X.224 TPKT 或 "SSH-" 应答，
/// 不存在的 IP 必然超时 → 100% 判定不可达。
async fn probe_raw_service(
    ip: &str,
    port: u16,
    mixed_port: u16,
) -> Result<(String, u64), String> {
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let start = Instant::now();
    let mut stream = open_probe_stream(ip, port, mixed_port).await?;
    let read_timeout = Duration::from_secs(5);
    let elapsed_ms = |start: Instant| start.elapsed().as_millis().max(1) as u64;

    match port {
        3389 => {
            // RDP 标准 X.224 Connection Request（19 字节）
            const X224: [u8; 19] = [
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
            ];
            stream
                .write_all(&X224)
                .await
                .map_err(|e| format!("RDP 握手包发送失败: {e}"))?;
            let mut buf = [0u8; 16];
            let n = tokio::time::timeout(read_timeout, stream.read(&mut buf))
                .await
                .map_err(|_| "RDP 握手应答超时".to_string())?
                .map_err(|e| format!("RDP 应答读取失败: {e}"))?;
            if n >= 2 && buf[0] == 0x03 && buf[1] == 0x00 {
                Ok((
                    format!("远程桌面 RDP 握手成功（X.224 {n} 字节应答）"),
                    elapsed_ms(start),
                ))
            } else {
                Err(format!("RDP 应答非 TPKT 特征（收到 {n} 字节）"))
            }
        }
        22 => {
            let mut buf = [0u8; 64];
            let n = tokio::time::timeout(read_timeout, stream.read(&mut buf))
                .await
                .map_err(|_| "SSH 握手应答超时".to_string())?
                .map_err(|e| format!("SSH 应答读取失败: {e}"))?;
            if n >= 4 && &buf[..4] == b"SSH-" {
                Ok(("SSH 服务握手成功".to_string(), elapsed_ms(start)))
            } else {
                Err(format!("SSH 应答非 SSH- 特征（收到 {n} 字节）"))
            }
        }
        21 => {
            // FTP 服务器建立连接后主动回 220 欢迎语
            let mut buf = [0u8; 64];
            let n = tokio::time::timeout(read_timeout, stream.read(&mut buf))
                .await
                .map_err(|_| "FTP 欢迎语超时".to_string())?
                .map_err(|e| format!("FTP 欢迎语读取失败: {e}"))?;
            if n >= 3 && &buf[..3] == b"220" {
                Ok(("FTP 服务握手成功".to_string(), elapsed_ms(start)))
            } else {
                Err(format!("FTP 欢迎语非 220 特征（收到 {n} 字节）"))
            }
        }
        445 => {
            // SMB2 Negotiate Protocol 请求：NBSS(4) + SMB2 Header(64) + 体(36)
            let mut req: Vec<u8> = vec![0x00, 0x00, 0x00, 0x64]; // NBSS，长度 100
            req.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // ProtocolId
            req.extend_from_slice(&[0x40, 0x00]); // StructureSize 64
            req.extend_from_slice(&[0x00, 0x00]); // CreditCharge
            req.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Status
            req.extend_from_slice(&[0x00, 0x00]); // Command = NEGOTIATE
            req.extend_from_slice(&[0x01, 0x00]); // Credits
            req.extend_from_slice(&[0x00u8; 4]); // Flags
            req.extend_from_slice(&[0x00u8; 4]); // NextCommand
            req.extend_from_slice(&[0x00u8; 8]); // MessageId
            req.extend_from_slice(&[0x00u8; 4]); // ProcessId
            req.extend_from_slice(&[0x00u8; 4]); // TreeId
            req.extend_from_slice(&[0x00u8; 8]); // SessionId
            req.extend_from_slice(&[0x00u8; 16]); // Signature
            req.extend_from_slice(&[0x24, 0x00]); // StructureSize 36
            req.extend_from_slice(&[0x02, 0x00]); // DialectCount = 2
            req.extend_from_slice(&[0x01, 0x00]); // SecurityMode
            req.extend_from_slice(&[0x00, 0x00]); // Reserved
            req.extend_from_slice(&[0x00u8; 4]); // Capabilities
            req.extend_from_slice(&[0x00u8; 16]); // ClientGuid
            req.extend_from_slice(&[0x00u8; 8]); // ClientStartTime
            req.extend_from_slice(&[0x10, 0x02]); // SMB 2.1.0
            req.extend_from_slice(&[0x02, 0x02]); // SMB 2.0.2
            stream
                .write_all(&req)
                .await
                .map_err(|e| format!("SMB2 Negotiate 发送失败: {e}"))?;
            let mut buf = [0u8; 32];
            let n = tokio::time::timeout(read_timeout, stream.read(&mut buf))
                .await
                .map_err(|_| "SMB2 Negotiate 应答超时".to_string())?
                .map_err(|e| format!("SMB2 应答读取失败: {e}"))?;
            if n >= 8 && buf[0] == 0x00 && &buf[4..8] == [0xFE, b'S', b'M', b'B'] {
                Ok((
                    format!("SMB 文件共享 Negotiate 握手成功（{n} 字节应答）"),
                    elapsed_ms(start),
                ))
            } else {
                Err(format!("SMB2 应答非 NBSS/SMB 特征（收到 {n} 字节）"))
            }
        }
        _ => {
            // NetBIOS / IPP / RAW / LPD 等无统一明文欢迎语：TCP 建连成功即
            // 证明数据包已穿过 go-lan-home 隧道抵达对端。
            Ok((
                format!("端口 {port} 已连通（TCP 建连成功）"),
                elapsed_ms(start),
            ))
        }
    }
}

/// 【APP18 任务3】HTTP / HTTPS 端口三条真实通道探测，任一成功即判定可达：
/// 1) 本地 mixed 代理（127.0.0.1:{mixed_port}）转发真实 GET；
/// 2) Clash API /proxies/go-lan-home/delay（见独立函数 probe_clash_delay）。
/// 本地代理代答的 502 / 504 一律不算成功；APP26 已删除 TUN 直连通道
/// （gvisor 会伪造 SYN-ACK，直连「成功」不能证明内网主机在线）。
async fn probe_http_port(
    ip: &str,
    port: u16,
    path: &str,
    mixed_port: u16,
) -> Result<(String, u64), String> {
    let mut last_err = String::from("HTTP 探测超时");
    let schemes: [&str; 2] = if matches!(port, 443 | 5001) {
        ["https", "http"]
    } else {
        ["http", "https"]
    };

    let build = |proxy: Option<&str>| -> Result<reqwest::Client, String> {
        let mut b = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(4));
        b = match proxy {
            Some(p) => b.proxy(reqwest::Proxy::all(p).map_err(|e| format!("代理构建失败: {e}"))?),
            None => b.no_proxy(),
        };
        b.build().map_err(|e| format!("探测客户端构建失败: {e}"))
    };

    // 通道 1：本地 mixed 代理
    if mixed_port > 0 {
        if let Ok(client) = build(Some(&format!("http://127.0.0.1:{mixed_port}"))) {
            for scheme in schemes {
                let url = format!("{scheme}://{ip}:{port}{path}");
                let start = std::time::Instant::now();
                match client.get(&url).send().await {
                    Ok(resp) => {
                        let code = resp.status().as_u16();
                        let bytes = resp.bytes().await.map(|b| b.len()).unwrap_or(0);
                        let ms = start.elapsed().as_millis().max(1) as u64;
                        if code != 502 && code != 504 && bytes > 0 {
                            return Ok((format!("HTTP {code} · {bytes} 字节"), ms));
                        }
                        last_err = format!("本地代理代答 HTTP {code}（对端不可达）");
                    }
                    Err(e) => last_err = format!("代理 GET 失败: {e}"),
                }
            }
        }
    }

    // 通道 2（Clash API 直驱 go-lan-home）已拆分到独立函数
    // `probe_clash_delay`（APP26 任务1.2），与本地代理通道并发执行，
    // 避免同一路径重复请求两次。

    Err(last_err)
}

/// 【APP26 任务1.2】未指定端口时只探测 5 个代表性端口——严禁向 TUN
/// 一次性并发轰炸 13~17 个端口：每一条半开连接都会在 go-lan-home
/// 内部挂起 2 分 07 秒（log7.txt 第 47~68 行 22 条
/// `connect tcp ... operation timed out (2m7s)` 即由此产生）。
const PROBE_DEFAULT_PORTS: [u16; 5] = [8000, 8001, 80, 443, 3389];

/// 未指定端口时的整体探测窗口（内核 Clash API 侧 2500ms 即回收连接）
const PROBE_WINDOW_MS: u64 = 2500;

/// 显式端口（用户输入 `IP:端口`）时的整体探测窗口
const PROBE_EXPLICIT_WINDOW_MS: u64 = 3500;

/// 【APP26 任务1.2】Clash API 直驱 go-lan-home 出站延迟测试。
///
/// 与本地 HTTP 代理探测的本质区别：请求由 sing-box 内核的 ctx 承载，
/// `timeout` 到期立即由内核 Close() 并销毁底层连接，绝不会在
/// go-lan-home 内部残留半开连接（这是 log7.txt 中 2m7s 超时错误的根因）。
async fn probe_clash_delay(
    ip: &str,
    port: u16,
    path: &str,
    api_addr: &str,
    api_secret: &str,
    timeout_ms: u64,
) -> Result<(String, u64), String> {
    if api_addr.is_empty() {
        return Err("Clash API 未就绪".to_string());
    }
    let base = api_addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string();
    let schemes: [&str; 2] = if matches!(port, 443 | 5001) {
        ["https", "http"]
    } else {
        ["http", "https"]
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_millis(800))
        .timeout(std::time::Duration::from_millis(timeout_ms + 300))
        .build()
        .map_err(|e| format!("Clash 探测客户端构建失败: {e}"))?;
    let mut last_err = String::from("Clash API 探测超时");
    for scheme in schemes {
        let target = format!("{scheme}://{ip}:{port}{path}");
        let mut req = client
            .get(format!("http://{base}/proxies/go-lan-home/delay"))
            .query(&[("url", target.as_str()), ("timeout", &timeout_ms.to_string())]);
        if !api_secret.is_empty() {
            req = req.bearer_auth(api_secret);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                if status == 200 {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(d) = v.get("delay").and_then(|d| d.as_u64()) {
                            if d > 0 {
                                return Ok((
                                    "go-lan-home 实测延迟（Clash API）".to_string(),
                                    d,
                                ));
                            }
                        }
                    }
                }
                last_err = format!("Clash API HTTP {status}");
            }
            Err(e) => last_err = format!("Clash API 请求失败: {e}"),
        }
    }
    Err(last_err)
}

/// 【APP26 任务1.2】单端口探测调度：
/// - 原始协议端口（3389 RDP / 22 SSH / 445 SMB ...）→ 经 mixed-in 的协议首包校验；
/// - Web 端口 → 本地 mixed 代理 HTTP（真实状态码）+ Clash API 双通道并发。
async fn probe_one_port(
    ip: &str,
    port: u16,
    path: &str,
    mixed_port: u16,
    api_addr: &str,
    api_secret: &str,
    clash_timeout_ms: u64,
) -> Result<(String, u64), String> {
    if is_raw_probe_port(port) {
        return probe_raw_service(ip, port, mixed_port).await;
    }
    let mut tasks: tokio::task::JoinSet<Result<(String, u64), String>> =
        tokio::task::JoinSet::new();
    {
        let ip_owned = ip.to_string();
        let path_owned = path.to_string();
        let api_owned = api_addr.to_string();
        let secret_owned = api_secret.to_string();
        tasks.spawn(async move {
            probe_clash_delay(&ip_owned, port, &path_owned, &api_owned, &secret_owned, clash_timeout_ms)
                .await
        });
    }
    if mixed_port > 0 {
        let ip_owned = ip.to_string();
        let path_owned = path.to_string();
        tasks.spawn(async move {
            probe_http_port(&ip_owned, port, &path_owned, mixed_port).await
        });
    }
    let mut last_err = String::from("端口探测超时");
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(hit)) => return Ok(hit),
            Ok(Err(e)) => last_err = e,
            Err(_) => continue,
        }
    }
    Err(last_err)
}

/// 【APP26 任务1.2】并发探测一组端口：首个真实命中立即胜出。
/// 每个探测任务内部都有独立的 2500ms 内核级超时，绝不会残留半开连接。
async fn probe_port_batch(
    ports: &[u16],
    ip: &str,
    path: &str,
    mixed_port: u16,
    api_addr: &str,
    api_secret: &str,
    clash_timeout_ms: u64,
) -> Result<PortProbeHit, String> {
    let mut tasks: tokio::task::JoinSet<(u16, Result<(String, u64), String>)> =
        tokio::task::JoinSet::new();
    for &p in ports {
        let ip_owned = ip.to_string();
        let path_owned = path.to_string();
        let api_owned = api_addr.to_string();
        let secret_owned = api_secret.to_string();
        tasks.spawn(async move {
            let res =
                probe_one_port(&ip_owned, p, &path_owned, mixed_port, &api_owned, &secret_owned, clash_timeout_ms)
                    .await;
            (p, res)
        });
    }
    let mut last_err = String::from("本批端口全部不可达");
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((p, Ok((detail, latency_ms)))) => {
                return Ok(PortProbeHit {
                    port: p,
                    detail,
                    latency_ms,
                })
            }
            Ok((_, Err(e))) => last_err = e,
            Err(_) => continue,
        }
    }
    Err(last_err)
}

/// 【APP26 任务1.2】探测入口：显式端口只测该端口；未指定则只测
/// 5 个代表性端口（8000 / 8001 / 80 / 443 / 3389），整体窗口 2500ms。
async fn probe_target_ports(
    ip: &str,
    explicit_port: Option<u16>,
    path: &str,
    mixed_port: u16,
    api_addr: &str,
    api_secret: &str,
) -> Result<PortProbeHit, String> {
    let total_ms = if explicit_port.is_some() {
        PROBE_EXPLICIT_WINDOW_MS
    } else {
        PROBE_WINDOW_MS
    };
    match tokio::time::timeout(
        std::time::Duration::from_millis(total_ms),
        probe_target_ports_inner(ip, explicit_port, path, mixed_port, api_addr, api_secret),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => Err(format!("隧道探测超时（{total_ms}ms 内无任何端口应答）")),
    }
}

async fn probe_target_ports_inner(
    ip: &str,
    explicit_port: Option<u16>,
    path: &str,
    mixed_port: u16,
    api_addr: &str,
    api_secret: &str,
) -> Result<PortProbeHit, String> {
    if let Some(p) = explicit_port {
        let (detail, latency_ms) =
            probe_one_port(ip, p, path, mixed_port, api_addr, api_secret, PROBE_WINDOW_MS).await?;
        return Ok(PortProbeHit {
            port: p,
            detail,
            latency_ms,
        });
    }
    probe_port_batch(
        &PROBE_DEFAULT_PORTS,
        ip,
        path,
        mixed_port,
        api_addr,
        api_secret,
        PROBE_WINDOW_MS,
    )
    .await
}

/// 【APP15 任务2】解析用户输入的检测目标，支持纯 IP、`IP:Port` 与
/// `https://IP:Port/path`、`http://IP:Port/path` 三种写法。
///
/// 返回 (ip 字符串, 显式端口)。IPv4 专用（本项目回家网段均为 IPv4）。
fn parse_probe_target(raw: &str) -> (String, Option<u16>) {
    // 先剥离不可见字符（零宽空格/Word Joiner 等）与全部空白，再切分分号多目标
    let no_invisible = strip_invisible_and_non_ascii(raw);
    let first = no_invisible.split(';').next().unwrap_or("");
    // 【APP15 任务2】自动剥离协议前缀与路径：
    // "https://192.168.10.253:8001/" → "192.168.10.253:8001"
    let host_part = first
        .strip_prefix("https://")
        .or_else(|| first.strip_prefix("http://"))
        .or_else(|| first.strip_prefix("//"))
        .unwrap_or(first);
    // 剥路径与 CIDR 掩码
    let cleaned = host_part.split('/').next().unwrap_or("").to_string();
    // IPv6 字面量（[::1]:port 形式）本模块不处理，直接返回原文
    if cleaned.contains('[') {
        return (cleaned, None);
    }
    match cleaned.rsplit_once(':') {
        Some((host, port_s)) if !host.is_empty() => match port_s.parse::<u16>() {
            Ok(p) if p > 0 => (host.to_string(), Some(p)),
            _ => (cleaned, None),
        },
        _ => (cleaned, None),
    }
}

/// 【APP17 任务5.2】从用户输入中提取 HTTP 请求路径（默认 "/"）。
/// 支持 http://IP[:Port]/path、https://... 与直接粘贴的 NAS 页面地址。
fn probe_request_path(raw: &str) -> String {
    let no_invisible = strip_invisible_and_non_ascii(raw);
    let first = no_invisible.split(';').next().unwrap_or("").trim();
    let rest = match first.split_once("://") {
        Some((_scheme, r)) => r,
        None => first.trim_start_matches("//"),
    };
    match rest.split_once('/') {
        Some((_host, path)) => format!("/{}", path.trim_start_matches('/')),
        None => "/".to_string(),
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

/// 【APP11 任务2 / APP17 任务5.2】穿过 go-lan-home 隧道检测内网 IP：
///
/// - 网段归属硬校验：target_ip 必须落在已配置的回家网段
///   （lan_cidrs ∪ local_address 所在 /24）内，否则直接拒绝、绝不发起探测；
///   同时拒绝探测本机自身的 WireGuard 虚拟 IP；
/// - 严禁用网关结果顶替目标：reachable 只由 target_ip 本身的真实应答决定；
/// - **真实字节判据**：走 Clash API / go-lan-home 隧道发一次真实 HTTP GET，
///   以「实际收到的应答字节数 > 0」为唯一成功标准，彻底杜绝端口连通但
///   零数据的假成功（此前 SOCKS5/TCP 探测会把伪造 SYN-ACK 当成可达）。
pub async fn probe_intranet_ip(
    target_ip_raw: Option<&str>,
    mixed_port: u16,
    api_addr: &str,
    api_secret: &str,
    is_running: bool,
    go_lan_enabled: bool,
    lan: &GoLanSettings,
) -> GoLanProbeResult {
    let log = crate::core::logger::MOD_GO_LAN;
    // 1. 净化输入 + 目标推导（【APP14 任务3】支持 IP 与 IP:Port）
    let (target_ip, explicit_port) = match target_ip_raw.map(parse_probe_target) {
        Some((ip, p)) if !ip.is_empty() => (ip, p),
        _ => match resolve_probe_target(None, lan) {
            Some(gw) => (gw, None),
            None => {
                crate::core::logger::warn(
                    log,
                    "未提供检测目标且无法从 local_address 推导网关，请手动输入内网 IP（如 10.1.8.1）",
                );
                return GoLanProbeResult {
                    reachable: false,
                    target_ip: String::new(),
                    latency_ms: None,
                    message: "请输入有效的内网 IP 地址（如 10.1.8.1 或 192.168.10.253）".into(),
                };
            }
        },
    };
    let target_v4: std::net::Ipv4Addr = match target_ip.parse() {
        Ok(v4) => v4,
        Err(_) => {
            crate::core::logger::warn(log, &format!("IP 地址格式无效: {target_ip}"));
            return GoLanProbeResult {
                reachable: false,
                target_ip: target_ip.clone(),
                latency_ms: None,
                message: format!("IP 地址格式无效: {target_ip}"),
            };
        }
    };
    // 【APP17 任务5.2】提取请求路径（用户可直接粘贴 NAS 页面地址）
    let req_path = target_ip_raw
        .map(probe_request_path)
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/".to_string());

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

    // 3. 铁律 1：网段归属硬校验（不在回家网段内直接拒绝）
    let local_addr = lan
        .wg_config
        .as_ref()
        .map(|wg| wg.local_ip.as_str())
        .unwrap_or("");
    let wg_gateway = derive_gateway_from_local_address(local_addr);
    // 【APP21 任务3.1】本机隧道 IP 可能不止 1 个（逗号分隔的多虚拟地址，
    // 如 10.196.0.2/32 + 192.168.10.222/24），全部纳入「不能检测自身」判定
    let self_ips: Vec<String> = parse_all_wg_local_addresses(local_addr)
        .0
        .iter()
        .map(|a| a.split('/').next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let allow_cidrs = normalize_cidr_list(&lan.lan_cidrs, local_addr);

    if self_ips.iter().any(|s| s == &target_ip) {
        let self_ip = target_ip.clone();
        let hint = wg_gateway.clone().unwrap_or_else(|| "10.1.8.1".into());
        let msg = format!(
            "不能检测本机自身的虚拟 IP ({self_ip})，请输入对端网关 (如 {hint}) 或家里内网设备 IP (如 192.168.10.253)"
        );
        crate::core::logger::warn(log, &msg);
        return GoLanProbeResult {
            reachable: false,
            target_ip: target_ip.clone(),
            latency_ms: None,
            message: msg,
        };
    }
    if !ipv4_in_any_cidr(target_v4, &allow_cidrs) {
        let cidrs_str = allow_cidrs.join(", ");
        let msg = format!(
            "❌ 目标 IP {target_ip} 不在已配置的回家网段 [{cidrs_str}] 内，不会经过 Go Lan 隧道"
        );
        crate::core::logger::warn(log, &msg);
        return GoLanProbeResult {
            reachable: false,
            target_ip: target_ip.clone(),
            latency_ms: None,
            message: msg,
        };
    }

    crate::core::logger::info(
        log,
        &format!(
            "正在通过 go-lan-home 隧道检测内网目标: {}{} ...",
            target_ip,
            explicit_port.map(|p| format!(":{p}")).unwrap_or_default()
        ),
    );

    // 4. 【APP18 任务3】三条真实通道并发探测（本地代理 / Clash API /
    // TUN 直连），HTTP 端口要求真实状态码 + 非空应答体，RDP/SSH 端口要求
    // 协议特征字节；提示信息 100% 针对用户输入的 target_ip。
    match probe_target_ports(
        &target_ip,
        explicit_port,
        &req_path,
        mixed_port,
        api_addr,
        api_secret,
    )
    .await
    {
        Ok(hit) => {
            crate::core::logger::info(
                log,
                &format!(
                    "✅ 内网检测成功: {target_ip}:{} {}，延迟 {} ms",
                    hit.port, hit.detail, hit.latency_ms
                ),
            );
            GoLanProbeResult {
                reachable: true,
                target_ip: target_ip.clone(),
                latency_ms: Some(hit.latency_ms),
                message: format!(
                    "✅ 已成功到达内网 {target_ip}:{}（{} · {} ms）",
                    hit.port, hit.detail, hit.latency_ms
                ),
            }
        }
        Err(e) => {
            let message = format!(
                "❌ 未能到达内网 {target_ip}（{e}），请检查该设备是否在线及 WG 服务端转发配置"
            );
            crate::core::logger::warn(log, &message);
            GoLanProbeResult {
                reachable: false,
                target_ip: target_ip.clone(),
                latency_ms: None,
                message,
            }
        }
    }
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
fn wg_outbound_value(wg: &WgManualConfig, warnings: &mut Vec<String>) -> Option<Value> {
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
        "tag": GO_LAN_TAG,
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
    // 【APP26 任务1.1】内核 JSON 的 go-lan-home MTU 统一 1420（对齐家庭
    // WireGuard 服务端），并附加 connect_timeout 5s：连不上的内网端口
    // 由内核在 5 秒内主动回收，绝不再出现 log7.txt 的
    // `connect tcp ... operation timed out (2m7s)`。
    let mtu = GO_LAN_RUNTIME_MTU;
    outbound["mtu"] = json!(mtu);
    // 【APP26 任务1.2】内网端口连不上时由内核 5 秒内主动回收连接，
    // 杜绝 2 分 07 秒半开挂起堵死整条隧道。
    outbound["connect_timeout"] = json!("5s");
    crate::core::logger::info(
        crate::core::logger::MOD_GO_LAN,
        &format!(
            "已构建 go-lan-home 顶层单节点出站: {}:{}（隧道地址 {local_addrs_log}，MTU {mtu}）",
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

/// 构建回家出站；配置无效返回 (None, 警告)
pub fn build_outbound(lan: &GoLanSettings) -> (Option<Value>, Vec<String>) {
    let mut warnings = Vec::new();
    if !lan.enabled {
        return (None, warnings);
    }
    // 1. 手动 WireGuard：密钥一律先规范化校验，无效必填密钥 → 不注入
    if let Some(wg) = &lan.wg_config {
        if !wg.server.trim().is_empty() {
            if let Some(outbound) = wg_outbound_value(wg, &mut warnings) {
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
                    if let Some(outbound) = wg_outbound_value(&wg, &mut warnings) {
                        return (Some(outbound), warnings);
                    }
                }
                Err(e) => warnings.push(format!("wireguard:// 链接解析失败: {e}")),
            }
        } else if uri.contains("[Interface]") {
            match parse_wireguard_conf(uri) {
                Ok(wg) => {
                    if let Some(outbound) = wg_outbound_value(&wg, &mut warnings) {
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
                            outbound["tag"] = json!(GO_LAN_TAG);
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
            outbound["tag"] = json!(GO_LAN_TAG);
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

/// 合成回家路由规则（domain_suffix + ip_cidr → go-lan-home）。
/// 这些规则必须插在 `geosite: private` / `ip_is_private -> direct` 之前。
/// 【APP-10 任务1.2】自动将 WireGuard 虚拟子网（从 local_ip 推导 /24）
/// 并入 ip_cidr 规则，确保用户能直接访问虚拟网关（如 10.8.0.1）。
pub(crate) fn go_lan_route_rules(lan: &GoLanSettings) -> (Vec<Value>, Vec<String>) {
    let mut rules = Vec::new();
    let mut warnings = Vec::new();
    if !lan.enabled {
        return (rules, warnings);
    }
    let domains: Vec<String> = lan
        .lan_domains
        .iter()
        // 【APP-11B】剔除 \u2060 等隐形字符
        .map(|d| strip_invisible_and_non_ascii(d).trim_start_matches("*.").to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    if !domains.is_empty() {
        rules.push(json!({ "domain_suffix": domains, "outbound": GO_LAN_TAG }));
    }
    // 【APP-11 任务1.1】统一走 normalize_cidr_list：单 IP 自动补 /32 + /24，
    // 主机位非零 CIDR 归一化为网络前缀，并自动并入 WireGuard 虚拟子网
    let local_addr = lan
        .wg_config
        .as_ref()
        .map(|wg| wg.local_ip.as_str())
        .unwrap_or("");
    for raw in &lan.lan_cidrs {
        // 【APP-11B】清洗后仍无法解析才告警（隐形字符会被自动剔除，不误报）
        if sanitize_ip_prefix(raw, 24).is_none() && !strip_invisible_and_non_ascii(raw).is_empty()
        {
            warnings.push(format!("无效网段「{}」已忽略", raw.trim()));
        }
    }
    let cidrs = normalize_cidr_list(&lan.lan_cidrs, local_addr);
    if !cidrs.is_empty() {
        rules.push(json!({ "ip_cidr": cidrs, "outbound": GO_LAN_TAG }));
    }
    (rules, warnings)
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
        let r = probe_intranet_ip(Some("192.168.0.1"), 0, "", "", true, true, &lan).await;
        assert!(!r.reachable, "网段外 IP 必须拒绝: {r:?}");
        assert!(
            r.message.contains("不在已配置的回家网段"),
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
        let r = probe_intranet_ip(Some("10.1.8.2"), 0, "", "", true, true, &lan).await;
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

    /// 【APP14 任务3】检测目标支持 `IP` 与 `IP:Port` 两种写法
    #[test]
    fn test_parse_probe_target() {
        assert_eq!(
            parse_probe_target("10.1.8.1"),
            ("10.1.8.1".to_string(), None)
        );
        assert_eq!(
            parse_probe_target("192.168.10.100:5000"),
            ("192.168.10.100".to_string(), Some(5000))
        );
        // 带不可见字符 / 前后空白 / 掩码时仍能正确解析
        assert_eq!(
            parse_probe_target(" 10.1.8.2\u{200b}/24 "),
            ("10.1.8.2".to_string(), None)
        );
        assert_eq!(
            parse_probe_target("10.1.8.1:8080/24"),
            ("10.1.8.1".to_string(), Some(8080))
        );
        // 端口非法时降级为纯 IP 检测
        assert_eq!(
            parse_probe_target("10.1.8.1:abc"),
            ("10.1.8.1:abc".to_string(), None)
        );
        // 【APP15 任务2】支持 https:// / http:// 完整 URL 输入
        assert_eq!(
            parse_probe_target("https://192.168.10.253:8001/"),
            ("192.168.10.253".to_string(), Some(8001))
        );
        assert_eq!(
            parse_probe_target("http://192.168.10.253:8000/webman"),
            ("192.168.10.253".to_string(), Some(8000))
        );
        assert_eq!(
            parse_probe_target("https://192.168.10.253"),
            ("192.168.10.253".to_string(), None)
        );
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
        // 【APP26 任务1.1】内核 JSON 的 MTU 统一为 GO_LAN_RUNTIME_MTU（1420）
        assert_eq!(
            ob["mtu"].as_u64(),
            Some(GO_LAN_RUNTIME_MTU as u64),
            "go-lan-home 写入内核的 MTU 必须为 1420"
        );
        assert_eq!(
            ob["connect_timeout"].as_str(),
            Some("5s"),
            "go-lan-home 必须设置 connect_timeout 5s，避免半开连接挂起 2m7s"
        );
    }

    /// 【APP26 任务1.1】无论用户配置多少（1280 / 1400 / 1500 / 9000），
    /// 写入内核 JSON 的 go-lan-home MTU 一律统一为 1420。
    #[test]
    fn test_wg_runtime_mtu_unified_1420() {
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
                "用户配置 MTU {mtu} 必须统一改写为 1420"
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
}
