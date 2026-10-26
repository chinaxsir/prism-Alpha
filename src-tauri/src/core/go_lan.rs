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
    // 2. 系统原生解析（优先 IPv4）
    if let Ok(mut addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(host, 51820u16)) {
        let mut v6: Option<String> = None;
        for a in addrs.by_ref() {
            match a {
                std::net::SocketAddr::V4(v4) => return v4.ip().to_string(),
                std::net::SocketAddr::V6(v6a) => {
                    if v6.is_none() {
                        v6 = Some(v6a.ip().to_string());
                    }
                }
            }
        }
        if let Some(v6) = v6 {
            return v6;
        }
    }
    // 3. 失败，原样返回域名（扩展侧还有 getaddrinfo 预解析与 go-lan 剥离兜底）
    host.to_string()
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
    let sanitized = sanitize_ip_prefix(local_addr, 32)?;
    let (ip_s, mask_s) = sanitized.split_once('/')?;
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

/// 【APP10 任务3】经 go-lan-home 出站的真实连通性探测（单目标单端口）。
///
/// 双通道全部强制穿越 WireGuard 隧道，绝不使用裸 TcpStream::connect
/// （tun-in 会在本地伪造 SYN-ACK 假握手，造成 2502ms 假阳性）：
///
/// 方法 1（Clash API 直接驱动 go-lan-home 出站）：
///   GET http://{api}/proxies/go-lan-home/delay?url=http://{ip}:{port}&timeout=2500
///   - HTTP 200 且 JSON delay > 0 && delay < 2450 → Ok(delay)
///   - HTTP 503/504/400 → 读取 JSON message（sing-box go-lan-home 出站返回的
///     最真实底层错误，如 i/o timeout / handshake initiation failed）；
///     message 含 "connection refused" 说明数据包已穿过隧道到达对端
///     （对端协议栈回了 RST，只是没开 HTTP 端口）→ 同样判定可达
/// 方法 2（经本地 mixed 入站 SOCKS5 发真实 HTTP 请求）：
///   reqwest Proxy::all(socks5://127.0.0.1:{mixed_port}) GET http://{ip}:{port}/
///   - 收到真实非 502/504 状态码 → Ok(耗时)
///   - 底层错误为 Connection refused 且耗时 < 2300ms → Ok(耗时)
///   - 任何耗时 >= 2400ms 的超时 → Err("连接超时")，杜绝 2502ms 假阳性
async fn probe_via_go_lan_outbound(
    ip: &str,
    port: u16,
    mixed_port: u16,
    api_addr: &str,
    api_secret: &str,
) -> Result<u64, String> {
    let mut last_err = String::from("无可用探测通道");

    // ---- 方法 1：Clash API /proxies/go-lan-home/delay ----
    if !api_addr.is_empty() {
        let base = api_addr
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let url = format!(
            "http://{base}/proxies/go-lan-home/delay?url=http://{ip}:{port}&timeout=2500"
        );
        if let Ok(client) = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(3500))
            .build()
        {
            let mut req = client.get(&url);
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
                                // delay 必须 >0 且明显小于 2500ms 超时阈值，
                                // 卡满阈值的伪延迟一律不可信
                                if d > 0 && d < 2450 {
                                    return Ok(d);
                                }
                                last_err = format!("Clash API 延迟 {d}ms 不可信（卡超时阈值）");
                            }
                        }
                    } else if status == 503 || status == 504 || status == 400 {
                        let msg = serde_json::from_str::<serde_json::Value>(&body)
                            .ok()
                            .and_then(|v| {
                                v.get("message").and_then(|m| m.as_str()).map(String::from)
                            })
                            .unwrap_or_else(|| format!("HTTP {status}"));
                        let lower = msg.to_lowercase();
                        if lower.contains("connection refused") || lower.contains("refused") {
                            // RST 回包 = 数据包已穿隧道抵达对端主机
                            return Ok(1);
                        }
                        last_err = format!("go-lan-home 出站: {msg}");
                    } else {
                        last_err = format!("Clash API HTTP {status}");
                    }
                }
                Err(e) => {
                    last_err = format!("Clash API 请求失败: {e}");
                }
            }
        }
    }

    // ---- 方法 2：经本地 mixed 入站 SOCKS5 真实 HTTP 探测 ----
    if mixed_port > 0 {
        let proxy = reqwest::Proxy::all(format!("socks5://127.0.0.1:{mixed_port}"))
            .map_err(|e| format!("SOCKS5 代理构建失败: {e}"))?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(2500))
            .proxy(proxy)
            .build()
            .map_err(|e| format!("HTTP 客户端构建失败: {e}"))?;
        let start = std::time::Instant::now();
        match client
            .get(format!("http://{ip}:{port}/"))
            .send()
            .await
        {
            Ok(resp) => {
                let code = resp.status().as_u16();
                let ms = start.elapsed().as_millis().max(1) as u64;
                // 本地 mixed 入站在对端不可达时会代答 502/504，必须排除；
                // 仅 2xx/3xx/4xx/5xx(非 502/504) 才是对端真实回包
                if code == 502 || code == 504 {
                    last_err = format!("本地代理代答 HTTP {code}（对端不可达）");
                } else {
                    return Ok(ms);
                }
            }
            Err(e) => {
                let ms = start.elapsed().as_millis().max(1) as u64;
                let text = format!("{e:?}").to_lowercase();
                // ECONNREFUSED：包已穿隧道到对端，对端协议栈回 RST
                if text.contains("connection refused") && ms < 2300 {
                    return Ok(ms);
                }
                if ms >= 2400 {
                    last_err = "连接超时".into();
                } else {
                    last_err = format!("{e}");
                }
            }
        }
    }

    Err(last_err)
}

/// 【APP10 任务3】穿过 go-lan-home 隧道检测内网 IP，实现
/// 「WireGuard 网关 + 目标设备」双级真实诊断：
///
/// 1. 从 local_address（10.1.8.2/24）推导 WG 服务端虚拟网关（10.1.8.1）；
/// 2. 目标 IP ≠ 网关时并发探测两者：
///    - 目标通 → ✅ 已成功到达内网 {ip} · 延迟 {ms} ms
///    - 网关通/目标超时 → ⚠️ 隧道已连通但目标不可达（检查 NAT/IP 转发/在线）
///    - 网关也超时 → ❌ 隧道未握手成功（检查端口/密钥）
///
/// 彻底废除会被 tun-in 假握手欺骗的裸 TcpStream::connect 通道。
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
    // 1. 净化输入 + 目标推导
    let Some(target_ip) = resolve_probe_target(target_ip_raw, lan) else {
        crate::core::logger::warn(
            log,
            "未提供检测目标且无法从 local_address 推导网关，请手动输入内网 IP（如 10.1.8.1）",
        );
        return GoLanProbeResult {
            reachable: false,
            target_ip: String::new(),
            latency_ms: None,
            message: "请输入有效的内网 IP 地址（如 10.1.8.1 或 192.168.1.1）".into(),
        };
    };
    if target_ip.parse::<std::net::IpAddr>().is_err() {
        crate::core::logger::warn(log, &format!("IP 地址格式无效: {target_ip}"));
        return GoLanProbeResult {
            reachable: false,
            target_ip: target_ip.clone(),
            latency_ms: None,
            message: format!("IP 地址格式无效: {target_ip}"),
        };
    }

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

    // 3. 推导 WG 网关（local_address 同网段 .1）与服务器端口
    let local_addr = lan
        .wg_config
        .as_ref()
        .map(|wg| wg.local_ip.as_str())
        .unwrap_or("");
    let wg_gateway = derive_gateway_from_local_address(local_addr);
    let server_port = lan
        .wg_config
        .as_ref()
        .map(|wg| wg.server_port)
        .unwrap_or(51820);

    crate::core::logger::info(
        log,
        &format!("正在通过 go-lan-home 隧道检测内网目标: {target_ip} ..."),
    );

    // 4. 目标即网关（或无法推导网关，如分享链接/Managed 模式）→ 单级探测
    if wg_gateway.is_none() || wg_gateway.as_deref() == Some(target_ip.as_str()) {
        return match probe_via_go_lan_outbound(&target_ip, 80, mixed_port, api_addr, api_secret)
            .await
        {
            Ok(ms) => {
                crate::core::logger::info(
                    log,
                    &format!(
                        "✅ 内网检测成功: 已到达 {target_ip}（go-lan-home 出站，延迟 {ms} ms）"
                    ),
                );
                GoLanProbeResult {
                    reachable: true,
                    target_ip: target_ip.clone(),
                    latency_ms: Some(ms),
                    message: format!("✅ 已成功到达内网 {target_ip} · 延迟 {ms} ms"),
                }
            }
            Err(e) => {
                crate::core::logger::warn(
                    log,
                    &format!("❌ 内网检测失败: {target_ip} 不可达: {e}"),
                );
                GoLanProbeResult {
                    reachable: false,
                    target_ip: target_ip.clone(),
                    latency_ms: None,
                    message: format!(
                        "❌ 未能到达 {target_ip}（{e}）。请检查隧道配置与对端设备是否在线"
                    ),
                }
            }
        };
    }

    // 5. 双级诊断：并发探测 网关（10.1.8.1）+ 目标 IP（192.168.10.253）
    let gw = wg_gateway.clone().unwrap_or_default();
    let gw_fut = probe_via_go_lan_outbound(&gw, 80, mixed_port, api_addr, api_secret);
    let target_fut =
        probe_via_go_lan_outbound(&target_ip, 80, mixed_port, api_addr, api_secret);
    let (gw_res, target_res) = tokio::join!(gw_fut, target_fut);

    match (gw_res, target_res) {
        // 情况 1：目标可达（网关通常也通；目标通即最终目的达成）
        (_, Ok(ms)) => {
            crate::core::logger::info(
                log,
                &format!("✅ 内网检测成功: 已到达 {target_ip}（网关 {gw} 连通，延迟 {ms} ms）"),
            );
            GoLanProbeResult {
                reachable: true,
                target_ip: target_ip.clone(),
                latency_ms: Some(ms),
                message: format!("✅ 已成功到达内网 {target_ip} · 延迟 {ms} ms"),
            }
        }
        // 情况 2：隧道通（网关可达）但目标不可达 → NAT/IP 转发/设备离线
        (Ok(gw_ms), Err(e)) => {
            let msg = format!(
                "⚠️ WireGuard 隧道已连通 (网关 {gw} 延迟 {gw_ms}ms)，但无法到达 {target_ip} ({e})。请检查家里 WG 服务端是否开启 IP 转发/NAT 或 {target_ip} 是否在线"
            );
            crate::core::logger::warn(log, &msg);
            GoLanProbeResult {
                reachable: false,
                target_ip: target_ip.clone(),
                latency_ms: Some(gw_ms),
                message: msg,
            }
        }
        // 情况 3：连网关都不可达 → 隧道未握手成功
        (Err(gw_err), Err(_)) => {
            let msg = format!(
                "❌ WireGuard 隧道未握手成功 (网关 {gw} 超时: {gw_err})，请检查服务器端口 {server_port} 及密钥配置"
            );
            crate::core::logger::warn(log, &msg);
            GoLanProbeResult {
                reachable: false,
                target_ip: target_ip.clone(),
                latency_ms: None,
                message: msg,
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
    let local_address = normalize_local_address(&wg.local_ip);
    let mut outbound = json!({
        "type": "wireguard",
        "tag": GO_LAN_TAG,
        "server": server,
        "server_port": wg.server_port,
        "peer_public_key": peer_public_key,
        "private_key": private_key,
        "local_address": [local_address],
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
    // 【APP-10 任务1.2】MTU 上限 1380：外层 TUN 1400 套内层 WireGuard
    // 封装（60 字节头）后不分片；用户配置 > 1380 时强制压到 1380
    let mtu = if wg.mtu > 0 { wg.mtu.min(1380) } else { 1280 };
    outbound["mtu"] = json!(mtu);
    crate::core::logger::info(
        crate::core::logger::MOD_GO_LAN,
        &format!(
            "已构建 go-lan-home 顶层单节点出站: {}:{}（隧道地址 {local_address}，MTU {mtu}）",
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

/// 【APP-11B 任务1.1】规范化 local_address：先经 `sanitize_ip_prefix` 剔除
/// 隐形字符并补默认前缀（IPv4 /32、IPv6 /64）；解析失败时回退安全默认，
/// 绝不让脏字符串进入内核配置导致 `netip.ParsePrefix` 崩溃。
///
/// 【APP-12 任务1.2】IPv4 统一扩为 /24：wireguard-go 内部路由表需识别
/// 同网段网关（如 10.195.0.1），/32 会让内核认为同网段只有本机一个 IP，
/// 直接访问 10.195.0.1 会被判为"非本机网段"而路由失败。扩为 /24 后
/// 内核把整个 10.195.0.0/24 视为本地链路可达。
fn normalize_local_address(raw: &str) -> String {
    let sanitized = sanitize_ip_prefix(raw, 32).unwrap_or_else(|| "10.0.0.2/32".into());
    // 仅对 IPv4 /32 做扩 /24；已是 /24 或更宽直接保留，IPv6 原样保留
    if let Some((ip_s, mask_s)) = sanitized.split_once('/') {
        if let (Ok(_ip), Ok(mask)) = (
            ip_s.parse::<std::net::Ipv4Addr>(),
            mask_s.parse::<u8>(),
        ) {
            if mask == 32 {
                return format!("{ip_s}/24");
            }
        }
    }
    sanitized
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
        // 【APP-12 任务1.2】/32 自动扩为 /24，wireguard-go 内部路由表
        // 可识别同网段网关（10.0.0.1）
        assert_eq!(ob["local_address"][0], "10.0.0.2/24");
        // 密钥必须是重编码后的标准 44 位 Base64
        assert_eq!(ob["private_key"].as_str(), Some(test_key(1).as_str()));
        assert_eq!(
            ob["private_key"].as_str().unwrap().len(),
            44,
            "输出必须是标准 44 位 Base64"
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
