//! 多格式订阅解析器：Clash/Meta YAML、Surge/Loon、SIP008、sing-box、
//! Quantumult X、URI 分享链接列表
//!
//! 机场下发的订阅格式五花八门：`commands.rs` 旧链路只做「单层 base64 解码 +
//! URI 列表 → Clash YAML」，遇到 Surge/Loon INI、SIP008 JSON、sing-box JSON、
//! Quantumult X 时完全解析不出节点。本模块先做多层自适应 base64 剥壳，再按
//! 格式特征依次嗅探，统一产出 Clash 节点（`serde_json::Value`，字段命名与
//! `uri_parser.rs` 保持一致），供上层合并进统一 pipeline。
//!
//! 所有解析器对“格式不匹配”返回空列表，对“格式匹配但内容损坏”返回错误，
//! 单个解析器失败不会影响其它解析器。

use std::collections::{HashMap, HashSet};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde_json::{json, Value};

/// 明文特征：命中任一即认为已经是可解析的明文，无需 base64 解码
const PLAINTEXT_MARKERS: &[&str] = &[
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "ssr://",
    "hysteria2://",
    "hy2://",
    "hysteria://",
    "tuic://",
    "wireguard://",
    "wg://",
    "anytls://",
    "socks5://",
    "socks://",
    "proxies:",
    "[Proxy]",
    "[server_local]",
    "\"outbounds\"",
    "\"servers\"",
    "\"server\"",
    "\"type\"",
];

/// Surge/Loon 行内协议白名单（含常见别名）
const CONF_PROTOCOLS: &[&str] = &[
    "ss",
    "shadowsocks",
    "trojan",
    "vmess",
    "vless",
    "tuic",
    "hysteria2",
    "hy2",
    "hysteria",
    "http",
    "https",
    "socks5",
    "socks",
    "snell",
    "wireguard",
];

/// Quantumult X 协议前缀白名单
const QX_PROTOCOLS: &[&str] = &[
    "shadowsocks",
    "ss",
    "trojan",
    "vmess",
    "vless",
    "http",
    "https",
    "socks5",
    "socks",
    "hysteria2",
    "hy2",
    "tuic",
    "snell",
];

/// Clash 支持的节点类型（用于 YAML 解析时过滤非节点项）
const CLASH_TYPES: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria2",
    "hysteria",
    "tuic",
    "wireguard",
    "anytls",
    "socks5",
    "socks",
    "http",
    "snell",
];

// ---------------- 公开 API ----------------

/// 多层自适应 Base64 自动剥壳（最多 3 层），返回尽量还原的明文。
///
/// - 剥离 UTF-8 BOM 与首尾空白；
/// - HTML 错误页（`<html`/`<body`）且不含节点特征时原样返回；
/// - 仅当「不含任何明文特征」或「整段只由 base64 字符集组成」时才尝试解码；
/// - 每层解码结果必须是可识别结构，否则视为误判并保留上一层文本。
pub fn auto_decrypt_base64_payload(raw: &str) -> String {
    let text = raw
        .trim()
        .trim_start_matches('\u{feff}')
        .trim()
        .to_string();

    // HTML 错误页（机场被墙 / 套餐失效时常返回）：不做破坏性处理
    let lower = text.to_ascii_lowercase();
    if (lower.contains("<html") || lower.contains("<body")) && !contains_plaintext_marker(&text) {
        return text;
    }

    if !should_try_decode(&text) {
        return text;
    }

    let mut current = text;
    for _ in 0..3 {
        if !should_try_decode(&current) {
            break;
        }
        let Some(decoded) = b64_decode_layer(&current) else {
            break;
        };
        // 普通 YAML / 纯文本被误判成 base64 时，解码结果不可识别 → 保留原文；
        // 解码结果仍是较长 base64 串时视为还有一层包裹，继续剥壳
        let another_layer = is_pure_base64(&decoded) && decoded.trim().len() >= 16;
        if !is_recognizable(&decoded) && !another_layer {
            break;
        }
        let hit_marker = contains_plaintext_marker(&decoded);
        current = decoded;
        // 一旦解出含特征的明文立即停止（多层包裹已还原）
        if hit_marker {
            break;
        }
    }
    current
}

/// 综合解析：先 `auto_decrypt_base64_payload`，再串行跑 6 个解析器并合并去重。
///
/// 返回 `(Clash 节点 JSON 列表, 错误/提示信息列表)`；任何单个解析器失败只记录
/// 错误，不会 panic。节点按 `type|server|port` 去重。
pub fn parse_subscription_content(raw: &str) -> (Vec<Value>, Vec<String>) {
    let text = auto_decrypt_base64_payload(raw);
    let mut nodes: Vec<Value> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    let parsers: [(&str, fn(&str) -> Result<Vec<Value>, String>); 5] = [
        ("Clash/Meta YAML", parse_clash_and_meta_yaml),
        ("Surge/Loon", parse_surge_and_loon_conf),
        ("SIP008", parse_ss_sip008_json),
        ("sing-box", parse_singbox_json),
        ("Quantumult X", parse_quantumult_x_lines),
    ];
    for (label, parser) in parsers {
        match parser(&text) {
            Ok(mut list) => nodes.append(&mut list),
            Err(e) => errors.push(format!("{label} 解析失败：{e}")),
        }
    }

    // URI 分享链接列表：复用既有解析器（已处理机场提示节点）
    if crate::core::uri_parser::is_uri_list(&text) {
        let (uri_nodes, uri_errors, notice) = crate::core::uri_parser::parse_lines(&text);
        nodes.extend(uri_nodes);
        if let Some(n) = notice {
            errors.push(format!("AIRPORT_NOTICE:{n}"));
        }
        for e in uri_errors {
            if let Some(n) = e.strip_prefix("AIRPORT_NOTICE:") {
                errors.push(format!("AIRPORT_NOTICE:{}", n.trim()));
            } else {
                errors.push(e);
            }
        }
    }

    // 按 type|server|port 去重（不同格式可能重复列出同一节点）
    let mut seen = HashSet::new();
    let mut unique = Vec::with_capacity(nodes.len());
    for node in nodes {
        let key = format!(
            "{}|{}|{}",
            node["type"].as_str().unwrap_or_default(),
            node["server"].as_str().unwrap_or_default(),
            node["port"].as_u64().unwrap_or_default()
        );
        if seen.insert(key) {
            unique.push(node);
        }
    }
    (unique, errors)
}

// ---------------- base64 剥壳工具 ----------------

/// 是否包含任一明文特征（大小写不敏感）
fn contains_plaintext_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    PLAINTEXT_MARKERS.iter().any(|m| {
        if m.contains(|c: char| c.is_ascii_uppercase()) {
            text.contains(*m)
        } else {
            lower.contains(*m)
        }
    })
}

/// 是否需要尝试 base64 解码：不含明文特征，或整段只由 base64 字符集组成
fn should_try_decode(text: &str) -> bool {
    !contains_plaintext_marker(text) || is_pure_base64(text)
}

/// 整段（忽略空白）是否只由 base64 / base64url 字符集组成
fn is_pure_base64(text: &str) -> bool {
    let mut count = 0usize;
    for c in text.chars() {
        if c.is_whitespace() {
            continue;
        }
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_') {
            count += 1;
        } else {
            return false;
        }
    }
    count >= 8
}

/// 解码一层 base64：去空白 → URL-Safe 归一 → 补 `=` → 依次尝试四种引擎
fn b64_decode_layer(text: &str) -> Option<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    let normalized: String = compact
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let pad = (4 - normalized.len() % 4) % 4;
    let mut padded = normalized.clone();
    padded.extend(std::iter::repeat('=').take(pad));

    let candidates = [padded.as_str(), normalized.as_str(), compact.as_str()];
    for s in candidates {
        for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
            if let Ok(bytes) = engine.decode(s)
                && let Ok(decoded) = String::from_utf8(bytes)
                && !decoded.trim().is_empty()
            {
                return Some(decoded);
            }
        }
    }
    None
}

/// 解码结果是否为可识别结构（节点明文 / JSON / Surge·Loon·QX 节点行）
fn is_recognizable(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if contains_plaintext_marker(text) {
        return true;
    }
    if serde_json::from_str::<Value>(trimmed).is_ok() {
        return true;
    }
    text.lines().any(looks_like_conf_node_line)
}

/// 粗略判断一行是否形如 `名称 = 协议, ...` 的客户端配置节点行
fn looks_like_conf_node_line(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with('[') {
        return false;
    }
    let Some((name, rest)) = line.split_once('=') else {
        return false;
    };
    if name.trim().is_empty() {
        return false;
    }
    let rest = rest.trim();
    if !rest.contains(',') {
        return false;
    }
    // Quantumult X：左值为协议前缀，右值首段是 host:port
    let name_lower = name.trim().to_ascii_lowercase();
    if QX_PROTOCOLS.contains(&name_lower.as_str()) {
        return true;
    }
    let proto = rest
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    CONF_PROTOCOLS.contains(&proto.as_str())
}

// ---------------- 1. Clash / Meta YAML ----------------

/// 解析 Clash / Clash.Meta YAML 的 `proxies:` 段。
///
/// 兼容 block 与 flow 内联字典（`- { name: x, type: vmess, ... }`）；
/// serde_yaml 的 Value 与 serde_json 不互通（YAML 的 key 可能非字符串），
/// 故通过 `yaml_to_json` 递归转换。name 缺失时用 `server:port` 补齐，
/// 并剔除 server 为空 / port 非法的项。
fn parse_clash_and_meta_yaml(text: &str) -> Result<Vec<Value>, String> {
    if !text
        .lines()
        .any(|l| l.trim_start().starts_with("proxies:"))
    {
        return Ok(Vec::new());
    }
    let doc: serde_yaml::Value =
        serde_yaml::from_str(text).map_err(|e| format!("YAML 语法错误：{e}"))?;
    let Some(proxies) = doc.get("proxies").and_then(|v| v.as_sequence()) else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for item in proxies {
        let Value::Object(mut map) = yaml_to_json(item.clone()) else {
            continue;
        };
        let server = map
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim()
            .to_string();
        if server.is_empty() {
            continue;
        }
        let Some(port) = json_port(map.get("port")) else {
            continue;
        };
        let kind = map
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !CLASH_TYPES.contains(&kind.as_str()) {
            continue;
        }
        let name = map
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim()
            .to_string();
        if name.is_empty() {
            map.insert("name".into(), json!(format!("{server}:{port}")));
        }
        map.insert("type".into(), json!(kind));
        map.insert("port".into(), json!(port));
        out.push(Value::Object(map));
    }
    Ok(out)
}

/// YAML Value → JSON Value 递归转换（YAML 允许非字符串 key，直接
/// `serde_json::to_value` 会失败，因此手写转换）
fn yaml_to_json(value: serde_yaml::Value) -> Value {
    match value {
        serde_yaml::Value::Null => Value::Null,
        serde_yaml::Value::Bool(b) => json!(b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                json!(i)
            } else if let Some(u) = n.as_u64() {
                json!(u)
            } else if let Some(f) = n.as_f64() {
                json!(f)
            } else {
                Value::Null
            }
        }
        serde_yaml::Value::String(s) => json!(s),
        serde_yaml::Value::Sequence(seq) => {
            Value::Array(seq.into_iter().map(yaml_to_json).collect())
        }
        serde_yaml::Value::Mapping(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    serde_yaml::Value::String(s) => s,
                    other => match yaml_to_json(other) {
                        Value::String(s) => s,
                        v => v.to_string(),
                    },
                };
                obj.insert(key, yaml_to_json(v));
            }
            Value::Object(obj)
        }
        serde_yaml::Value::Tagged(tagged) => yaml_to_json(tagged.value),
    }
}

// ---------------- 2. Surge / Loon ----------------

/// 解析 Surge / Loon 配置：`[Proxy]` 段或形如
/// `节点名 = 协议, 服务器, 端口, ...` 的行。
///
/// 支持 ss / trojan / vmess / vless / tuic / hysteria2 / http(s) /
/// socks5 / snell / wireguard；跳过 DIRECT / REJECT / PASS 等内置策略
/// 与 `Proxy = select, ...` 策略组行。字段映射：
/// `encrypt-method`/`method`→cipher、`password`→password、
/// `username`→uuid(vmess)、`sni`/`tls-name`/`tls-host`→servername、
/// `ws=true`/`transport=ws`→network+ws-opts、`transport=grpc`→grpc。
fn parse_surge_and_loon_conf(text: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(node) = parse_conf_line(line) {
            out.push(node);
        }
    }
    Ok(out)
}

fn parse_conf_line(line: &str) -> Option<Value> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with('[') {
        return None;
    }
    let (name, rest) = line.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let segs: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
    let raw_proto = segs.first()?.to_ascii_lowercase();
    let kind = normalize_conf_protocol(&raw_proto)?;
    if segs.len() < 3 {
        return None;
    }
    let server = segs[1].trim_matches('"').to_string();
    if server.is_empty() {
        return None;
    }
    let port: u16 = segs[2].trim_matches('"').parse().ok()?;
    if port == 0 {
        return None;
    }

    let mut kv: HashMap<String, String> = HashMap::new();
    let mut positional: Vec<String> = Vec::new();
    for seg in segs.iter().skip(3) {
        if seg.is_empty() {
            continue;
        }
        if let Some((k, v)) = seg.split_once('=') {
            kv.insert(
                k.trim().to_ascii_lowercase(),
                v.trim().trim_matches('"').to_string(),
            );
        } else {
            positional.push(seg.trim_matches('"').to_string());
        }
    }

    let mut node = json!({
        "name": name,
        "type": kind,
        "server": server,
        "port": port,
    });

    // 通用 TLS 字段
    // 【APP64 任务1】trojan 默认走 TLS；任何协议显式写 tls/over-tls/over_tls/https 也开启
    let tls_flag = ["tls", "over-tls", "over_tls"]
        .iter()
        .any(|k| kv.get(*k).is_some_and(|v| truthy(v)));
    if tls_flag || raw_proto == "https" || kind == "trojan" {
        node["tls"] = json!(true);
    }
    // 【APP64 任务1】完整 SNI 优先级链：sni → servername → peer → tls-name → tls-host
    if let Some(sni) = ["sni", "servername", "peer", "tls-name", "tls-host"]
        .iter()
        .find_map(|k| kv.get(*k).filter(|s| !s.is_empty()))
    {
        node["servername"] = json!(sni);
    }
    // 【APP64 任务1】Clash / Clash.Meta YAML 里的四种写法统一归一：
    //   skip-cert-verify: true / 1
    //   insecure: true / yes / 1
    //   allow-insecure: true / 1
    //   verify: false / no / 0
    let cert_insecure = {
        let truthy = |v: &str| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
        let falsy = |v: &str| matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off");
        ["skip-cert-verify", "insecure", "allow-insecure", "allow_insecure"]
            .iter()
            .any(|k| kv.get(*k).is_some_and(|v| truthy(v)))
            || kv.get("verify").is_some_and(|v| falsy(v))
    };
    if cert_insecure {
        node["skip-cert-verify"] = json!(true);
    }

    // 传输层：ws / grpc
    let transport = kv
        .get("transport")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let ws = kv.get("ws").is_some_and(|v| truthy(v))
        || transport == "ws"
        || kv.get("obfs").is_some_and(|v| v.eq_ignore_ascii_case("ws"));
    if ws {
        node["network"] = json!("ws");
        let mut ws_opts = serde_json::Map::new();
        if let Some(path) = kv
            .get("ws-path")
            .or_else(|| kv.get("path"))
            .filter(|p| !p.is_empty())
        {
            ws_opts.insert("path".into(), json!(path));
        }
        if let Some(host) = conf_ws_host(&kv) {
            ws_opts.insert("headers".into(), json!({ "Host": host }));
        }
        node["ws-opts"] = Value::Object(ws_opts);
    } else if transport == "grpc" {
        node["network"] = json!("grpc");
        if let Some(service) = kv
            .get("grpc-service-name")
            .or_else(|| kv.get("service-name"))
            .filter(|s| !s.is_empty())
        {
            node["grpc-opts"] = json!({ "grpc-service-name": service });
        }
    }

    if let Some(flow) = kv.get("flow").filter(|f| !f.is_empty()) {
        node["flow"] = json!(flow);
    }
    if let Some(public_key) = kv.get("public-key").filter(|k| !k.is_empty()) {
        let short_id = kv.get("short-id").cloned().unwrap_or_default();
        node["reality-opts"] = json!({ "public-key": public_key, "short-id": short_id });
    }

    // 协议专属字段
    match kind {
        "ss" => {
            if let Some(cipher) = kv
                .get("encrypt-method")
                .or_else(|| kv.get("method"))
                .cloned()
                .or_else(|| positional.first().cloned())
                .filter(|c| !c.is_empty())
            {
                node["cipher"] = json!(cipher);
            }
            if let Some(password) = kv
                .get("password")
                .cloned()
                .or_else(|| positional.get(1).cloned())
                .filter(|p| !p.is_empty())
            {
                node["password"] = json!(password);
            }
        }
        "vmess" => {
            let (cipher, uuid) = if positional.len() >= 2 {
                (
                    kv.get("encrypt-method")
                        .or_else(|| kv.get("method"))
                        .cloned()
                        .unwrap_or_else(|| positional[0].clone()),
                    kv.get("username")
                        .or_else(|| kv.get("uuid"))
                        .cloned()
                        .unwrap_or_else(|| positional[1].clone()),
                )
            } else if positional.len() == 1 {
                (
                    kv.get("encrypt-method")
                        .or_else(|| kv.get("method"))
                        .cloned()
                        .unwrap_or_else(|| "auto".to_string()),
                    kv.get("username")
                        .or_else(|| kv.get("uuid"))
                        .cloned()
                        .unwrap_or_else(|| positional[0].clone()),
                )
            } else {
                (
                    kv.get("encrypt-method")
                        .or_else(|| kv.get("method"))
                        .cloned()
                        .unwrap_or_else(|| "auto".to_string()),
                    kv.get("username")
                        .or_else(|| kv.get("uuid"))
                        .cloned()
                        .unwrap_or_default(),
                )
            };
            node["cipher"] = json!(cipher);
            if !uuid.is_empty() {
                node["uuid"] = json!(uuid);
            }
        }
        "vless" => {
            if let Some(uuid) = kv
                .get("username")
                .or_else(|| kv.get("uuid"))
                .cloned()
                .or_else(|| positional.first().cloned())
                .filter(|u| !u.is_empty())
            {
                node["uuid"] = json!(uuid);
            }
        }
        "trojan" | "hysteria2" | "hysteria" | "anytls" | "snell" => {
            if let Some(password) = kv
                .get("password")
                .cloned()
                .or_else(|| positional.first().cloned())
                .filter(|p| !p.is_empty())
            {
                node["password"] = json!(password);
            }
            if kind == "anytls" {
                node["tls"] = json!(true);
            }
            if kind == "snell"
                && let Some(version) = kv.get("version").filter(|v| !v.is_empty())
            {
                node["version"] = json!(version);
            }
        }
        "tuic" => {
            let uuid = kv
                .get("uuid")
                .or_else(|| kv.get("username"))
                .cloned()
                .or_else(|| positional.first().cloned())
                .unwrap_or_default();
            let password = kv
                .get("password")
                .cloned()
                .or_else(|| positional.get(1).cloned())
                .unwrap_or_default();
            if !uuid.is_empty() {
                node["uuid"] = json!(uuid);
            }
            if !password.is_empty() {
                node["password"] = json!(password);
            }
        }
        "http" | "socks5" => {
            if let Some(username) = kv
                .get("username")
                .or_else(|| kv.get("user"))
                .cloned()
                .or_else(|| positional.first().cloned())
                .filter(|u| !u.is_empty())
            {
                node["username"] = json!(username);
            }
            if let Some(password) = kv
                .get("password")
                .or_else(|| kv.get("pass"))
                .cloned()
                .or_else(|| positional.get(1).cloned())
                .filter(|p| !p.is_empty())
            {
                node["password"] = json!(password);
            }
        }
        "wireguard" => {
            if let Some(v) = kv
                .get("private-key")
                .or_else(|| kv.get("private_key"))
                .filter(|v| !v.is_empty())
            {
                node["private-key"] = json!(v);
            }
            if let Some(v) = kv
                .get("public-key")
                .or_else(|| kv.get("public_key"))
                .filter(|v| !v.is_empty())
            {
                node["public-key"] = json!(v);
            }
            if let Some(v) = kv
                .get("ip")
                .or_else(|| kv.get("address"))
                .filter(|v| !v.is_empty())
            {
                node["ip"] = json!(v);
            }
            if let Some(v) = kv
                .get("preshared-key")
                .or_else(|| kv.get("psk"))
                .filter(|v| !v.is_empty())
            {
                node["preshared-key"] = json!(v);
            }
            if let Some(mtu) = kv.get("mtu").and_then(|v| v.parse::<u32>().ok()) {
                node["mtu"] = json!(mtu);
            }
            if let Some(reserved) = kv.get("reserved") {
                let bytes: Vec<u8> = reserved
                    .split(',')
                    .filter_map(|v| v.trim().parse::<u8>().ok())
                    .collect();
                if bytes.len() == 3 {
                    node["reserved"] = json!(bytes);
                }
            }
        }
        _ => {}
    }

    Some(node)
}

/// Surge/Loon 协议名归一化为 Clash 类型
fn normalize_conf_protocol(proto: &str) -> Option<&'static str> {
    Some(match proto {
        "ss" | "shadowsocks" => "ss",
        "trojan" => "trojan",
        "vmess" => "vmess",
        "vless" => "vless",
        "tuic" => "tuic",
        "hysteria2" | "hy2" => "hysteria2",
        "hysteria" => "hysteria",
        "http" => "http",
        "https" => "http",
        "socks5" | "socks" => "socks5",
        "snell" => "snell",
        "wireguard" | "wg" => "wireguard",
        _ => return None,
    })
}

/// 从 `ws-headers=Host:x` / `host=x` 提取 Host 头
fn conf_ws_host(kv: &HashMap<String, String>) -> Option<String> {
    if let Some(headers) = kv.get("ws-headers") {
        for part in headers.split('|') {
            if let Some((k, v)) = part.split_once(':')
                && k.trim().eq_ignore_ascii_case("host")
            {
                let host = v.trim();
                if !host.is_empty() {
                    return Some(host.to_string());
                }
            }
        }
    }
    kv.get("host").filter(|h| !h.is_empty()).cloned()
}

// ---------------- 3. SIP008 JSON ----------------

/// 解析 SIP008 订阅 JSON（`{"servers":[{server, server_port, password,
/// method, remarks, plugin, plugin_opts}]}`），输出 type=ss 的 Clash 节点。
fn parse_ss_sip008_json(text: &str) -> Result<Vec<Value>, String> {
    if !text.contains("\"servers\"") {
        return Ok(Vec::new());
    }
    let doc: Value =
        serde_json::from_str(text.trim()).map_err(|e| format!("JSON 语法错误：{e}"))?;
    let Some(servers) = doc.get("servers").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for item in servers {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let server = obj
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim()
            .to_string();
        if server.is_empty() {
            continue;
        }
        let Some(port) = json_port(obj.get("server_port").or_else(|| obj.get("port"))) else {
            continue;
        };
        let password = obj
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let method = obj
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let remarks = obj
            .get("remarks")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim();
        let name = if remarks.is_empty() {
            format!("{server}:{port}")
        } else {
            remarks.to_string()
        };

        let mut node = json!({
            "name": name,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
        });

        if let Some(plugin) = obj.get("plugin").and_then(|v| v.as_str()) {
            let opts = obj
                .get("plugin_opts")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            apply_ss_plugin(&mut node, plugin, opts);
        }
        out.push(node);
    }
    Ok(out)
}

/// SIP008 plugin → Clash plugin / plugin-opts（obfs-local / simple-obfs）
fn apply_ss_plugin(node: &mut Value, plugin: &str, opts: &str) {
    let plugin = plugin.trim().to_ascii_lowercase();
    if plugin.contains("obfs") {
        let mut mode = "http";
        let mut host = String::new();
        for seg in opts.split(';') {
            let seg = seg.trim();
            if let Some(h) = seg.strip_prefix("obfs-host=") {
                host = h.to_string();
            } else if seg == "obfs=tls" {
                mode = "tls";
            }
        }
        node["plugin"] = json!("obfs");
        node["plugin-opts"] = json!({ "mode": mode, "host": host });
    } else if plugin.contains("v2ray") {
        node["plugin"] = json!("v2ray-plugin");
    }
}

// ---------------- 4. sing-box JSON ----------------

/// 解析 sing-box 配置 JSON 的 `outbounds` 数组，转换为 Clash 节点。
///
/// 跳过 direct/block/dns/selector/urltest 等非代理出站；支持
/// vless/vmess/trojan/shadowsocks/hysteria2/tuic/wireguard/anytls/socks/http。
/// `server_port`→port、`tag`→name、shadowsocks 的 `method`→cipher、
/// `tls.enabled`→tls、`tls.server_name`→servername、`transport.type`→network。
fn parse_singbox_json(text: &str) -> Result<Vec<Value>, String> {
    if !text.contains("\"outbounds\"") {
        return Ok(Vec::new());
    }
    let doc: Value =
        serde_json::from_str(text.trim()).map_err(|e| format!("JSON 语法错误：{e}"))?;
    let Some(outbounds) = doc.get("outbounds").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for ob in outbounds {
        let Some(obj) = ob.as_object() else {
            continue;
        };
        let raw_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let kind = match raw_type.as_str() {
            "vless" => "vless",
            "vmess" => "vmess",
            "trojan" => "trojan",
            "shadowsocks" => "ss",
            "hysteria2" => "hysteria2",
            "tuic" => "tuic",
            "wireguard" => "wireguard",
            "anytls" => "anytls",
            "socks" => "socks5",
            "http" => "http",
            _ => continue,
        };
        let tag = obj
            .get("tag")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim()
            .to_string();
        if matches!(
            tag.to_ascii_lowercase().as_str(),
            "direct" | "block" | "dns" | "selector" | "urltest"
        ) {
            continue;
        }
        let server = obj
            .get("server")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .trim()
            .to_string();
        if server.is_empty() {
            continue;
        }
        let Some(port) = json_port(obj.get("server_port").or_else(|| obj.get("port"))) else {
            continue;
        };
        let name = if tag.is_empty() {
            format!("{server}:{port}")
        } else {
            tag
        };

        let mut node = json!({
            "name": name,
            "type": kind,
            "server": server,
            "port": port,
        });

        if let Some(uuid) = obj
            .get("uuid")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            node["uuid"] = json!(uuid);
        }
        if let Some(password) = obj
            .get("password")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            node["password"] = json!(password);
        }
        if let Some(method) = obj
            .get("method")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            node["cipher"] = json!(method);
        }

        // TLS 块
        if let Some(tls) = obj.get("tls").and_then(|v| v.as_object())
            && tls.get("enabled").and_then(|v| v.as_bool()) == Some(true)
        {
            node["tls"] = json!(true);
            if let Some(server_name) = tls
                .get("server_name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                node["servername"] = json!(server_name);
            }
            if tls.get("insecure").and_then(|v| v.as_bool()) == Some(true) {
                node["skip-cert-verify"] = json!(true);
            }
        }

        // 传输层
        if let Some(transport) = obj.get("transport").and_then(|v| v.as_object()) {
            let ty = transport
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            match ty.as_str() {
                "ws" => {
                    node["network"] = json!("ws");
                    let mut ws_opts = serde_json::Map::new();
                    if let Some(path) = transport
                        .get("path")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        ws_opts.insert("path".into(), json!(path));
                    }
                    if let Some(host) = transport
                        .get("headers")
                        .and_then(|v| v.get("Host"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        ws_opts.insert("headers".into(), json!({ "Host": host }));
                    }
                    node["ws-opts"] = Value::Object(ws_opts);
                }
                "grpc" => {
                    node["network"] = json!("grpc");
                    let service = transport
                        .get("service_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    node["grpc-opts"] = json!({ "grpc-service-name": service });
                }
                "http" | "h2" => {
                    node["network"] = json!("http");
                }
                _ => {}
            }
        }

        // hysteria2 混淆
        if let Some(obfs) = obj.get("obfs").and_then(|v| v.as_object())
            && let Some(obfs_type) = obfs.get("type").and_then(|v| v.as_str())
        {
            node["obfs"] = json!(obfs_type);
            if let Some(password) = obfs.get("password").and_then(|v| v.as_str()) {
                node["obfs-password"] = json!(password);
            }
        }

        // tuic 拥塞控制
        if let Some(cc) = obj
            .get("congestion_control")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            node["congestion-controller"] = json!(cc);
        }

        // wireguard 字段
        if kind == "wireguard" {
            if let Some(private_key) = obj.get("private_key").and_then(|v| v.as_str()) {
                node["private-key"] = json!(private_key);
            }
            if let Some(public_key) = obj.get("peer_public_key").and_then(|v| v.as_str()) {
                node["public-key"] = json!(public_key);
            }
            if let Some(local) = obj.get("local_address") {
                let ip = match local {
                    Value::String(s) => s.clone(),
                    Value::Array(arr) => arr
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                    _ => String::new(),
                };
                if !ip.is_empty() {
                    node["ip"] = json!(ip);
                }
            }
            if let Some(mtu) = obj.get("mtu").and_then(|v| v.as_u64()) {
                node["mtu"] = json!(mtu);
            }
        }

        out.push(node);
    }
    Ok(out)
}

// ---------------- 5. Quantumult X ----------------

/// 解析 Quantumult X 节点行，如：
/// `shadowsocks = host:port, method=aes-256-gcm, password=pwd, tag=Name`。
///
/// 协议前缀映射到 Clash type（shadowsocks→ss）；`obfs=ws`→network ws，
/// `obfs-host`/`obfs-uri`→ws-opts，`over-tls`→tls，`tls-host`→servername。
fn parse_quantumult_x_lines(text: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(node) = parse_qx_line(line) {
            out.push(node);
        }
    }
    Ok(out)
}

fn parse_qx_line(line: &str) -> Option<Value> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with('[') {
        return None;
    }
    let (left, rest) = line.split_once('=')?;
    let proto_key = left.trim().to_ascii_lowercase();
    if !QX_PROTOCOLS.contains(&proto_key.as_str()) {
        return None;
    }
    let kind = match proto_key.as_str() {
        "shadowsocks" | "ss" => "ss",
        "trojan" => "trojan",
        "vmess" => "vmess",
        "vless" => "vless",
        "http" | "https" => "http",
        "socks5" | "socks" => "socks5",
        "hysteria2" | "hy2" => "hysteria2",
        "tuic" => "tuic",
        "snell" => "snell",
        _ => return None,
    };

    let mut segs = rest.split(',').map(|s| s.trim());
    let hostport = segs.next()?.trim();
    let (server, port) = hostport.rsplit_once(':')?;
    let server = server.trim().trim_matches(|c| c == '[' || c == ']');
    if server.is_empty() {
        return None;
    }
    let port: u16 = port.trim().parse().ok()?;
    if port == 0 {
        return None;
    }

    let mut kv: HashMap<String, String> = HashMap::new();
    for seg in segs {
        if let Some((k, v)) = seg.split_once('=') {
            kv.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let tag = kv.get("tag").cloned().unwrap_or_default();
    let name = if tag.trim().is_empty() {
        format!("{server}:{port}")
    } else {
        tag.trim().to_string()
    };
    let mut node = json!({
        "name": name,
        "type": kind,
        "server": server,
        "port": port,
    });

    let method = kv.get("method").cloned().unwrap_or_default();
    let password = kv.get("password").cloned().unwrap_or_default();
    match kind {
        "ss" => {
            if !method.is_empty() {
                node["cipher"] = json!(method);
            }
            if !password.is_empty() {
                node["password"] = json!(password);
            }
        }
        "vmess" => {
            node["cipher"] = json!(if method.is_empty() { "auto" } else { method.as_str() });
            if !password.is_empty() {
                node["uuid"] = json!(password);
            }
        }
        "vless" => {
            if !password.is_empty() {
                node["uuid"] = json!(password);
            }
        }
        "trojan" | "hysteria2" | "snell" => {
            if !password.is_empty() {
                node["password"] = json!(password);
            }
        }
        "tuic" => {
            let uuid = kv.get("uuid").cloned().unwrap_or_else(|| password.clone());
            if !uuid.is_empty() {
                node["uuid"] = json!(uuid);
            }
        }
        "http" | "socks5" => {
            if let Some(user) = kv.get("username").or_else(|| kv.get("user")) {
                node["username"] = json!(user);
            }
            if !password.is_empty() {
                node["password"] = json!(password);
            }
        }
        _ => {}
    }

    // 混淆 / WebSocket
    let obfs = kv
        .get("obfs")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if obfs == "ws" || obfs == "wss" {
        node["network"] = json!("ws");
        let mut ws_opts = serde_json::Map::new();
        if let Some(host) = kv.get("obfs-host").filter(|h| !h.is_empty()) {
            ws_opts.insert("headers".into(), json!({ "Host": host }));
        }
        if let Some(path) = kv.get("obfs-uri").filter(|p| !p.is_empty()) {
            ws_opts.insert("path".into(), json!(path));
        }
        node["ws-opts"] = Value::Object(ws_opts);
    }

    if kv.get("over-tls").is_some_and(|v| truthy(v)) || proto_key == "https" {
        node["tls"] = json!(true);
    }
    if let Some(server_name) = kv
        .get("tls-host")
        .or_else(|| kv.get("sni"))
        .filter(|s| !s.is_empty())
    {
        node["servername"] = json!(server_name);
    }
    if kv
        .get("tls-verify")
        .is_some_and(|v| v == "false" || v == "0")
    {
        node["skip-cert-verify"] = json!(true);
    }

    Some(node)
}

// ---------------- 通用工具 ----------------

/// JSON 值转合法端口（1-65535），兼容数字与字符串两种写法
fn json_port(v: Option<&Value>) -> Option<u16> {
    let v = v?;
    let n = if let Some(u) = v.as_u64() {
        u
    } else if let Some(i) = v.as_i64() {
        u64::try_from(i).ok()?
    } else if let Some(s) = v.as_str() {
        s.trim().parse::<u64>().ok()?
    } else {
        return None;
    };
    if (1..=65535).contains(&n) {
        Some(n as u16)
    } else {
        None
    }
}

/// 客户端配置里常见的布尔写法
fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

// ---------------- 单元测试 ----------------

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    fn find<'a>(nodes: &'a [Value], name: &str) -> &'a Value {
        nodes
            .iter()
            .find(|n| n["name"] == name)
            .unwrap_or_else(|| panic!("缺少节点：{name}"))
    }

    #[test]
    fn decrypts_single_layer_base64() {
        let plain = "vless://uuid-1@1.2.3.4:443?security=tls&type=ws&path=%2Fws&host=a.com#单层\ntrojan://pwd@5.6.7.8:443#T1";
        let decoded = auto_decrypt_base64_payload(&b64(plain));
        assert_eq!(decoded, plain);
    }

    #[test]
    fn decrypts_double_layer_base64() {
        let plain = "vless://uuid-1@1.2.3.4:443?security=tls#双层\nvmess://eyJ2IjoiMiJ9";
        let twice = b64(&b64(plain));
        assert_eq!(auto_decrypt_base64_payload(&twice), plain);
    }

    #[test]
    fn parses_surge_proxy_section() {
        let text = r#"
[Proxy]
HK-SS = ss, 1.1.1.1, 8388, encrypt-method=aes-256-gcm, password=pwd
HK-Trojan = trojan, 2.2.2.2, 443, password=tpwd, sni=t.example.com, skip-cert-verify=true, ws=true, ws-path=/ws, ws-headers=Host:cdn.example.com
HK-VMess = vmess, 3.3.3.3, 443, chacha20-poly1305, "uuid-1234", ws=true, ws-path=/vm, tls=true, sni=vm.example.com
DIRECT = direct
REJECT = reject
Proxy = select, HK-SS, HK-Trojan
"#;
        let (nodes, errors) = parse_subscription_content(text);
        assert_eq!(nodes.len(), 3, "Surge 应解析 3 个节点：{errors:?}");

        let ss = find(&nodes, "HK-SS");
        assert_eq!(ss["type"], "ss");
        assert_eq!(ss["server"], "1.1.1.1");
        assert_eq!(ss["port"], 8388);
        assert_eq!(ss["cipher"], "aes-256-gcm");
        assert_eq!(ss["password"], "pwd");

        let tj = find(&nodes, "HK-Trojan");
        assert_eq!(tj["type"], "trojan");
        assert_eq!(tj["password"], "tpwd");
        assert_eq!(tj["servername"], "t.example.com");
        assert_eq!(tj["skip-cert-verify"], true);
        assert_eq!(tj["network"], "ws");
        assert_eq!(tj["ws-opts"]["path"], "/ws");
        assert_eq!(tj["ws-opts"]["headers"]["Host"], "cdn.example.com");

        let vm = find(&nodes, "HK-VMess");
        assert_eq!(vm["type"], "vmess");
        assert_eq!(vm["uuid"], "uuid-1234");
        assert_eq!(vm["cipher"], "chacha20-poly1305");
        assert_eq!(vm["tls"], true);
        assert_eq!(vm["servername"], "vm.example.com");
        assert_eq!(vm["ws-opts"]["path"], "/vm");
    }

    #[test]
    fn parses_loon_conf() {
        let text = r#"
[Proxy]
HK = Shadowsocks, 1.1.1.1, 443, aes-128-gcm, "pwd"
JP = Trojan, 2.2.2.2, 443, "pwd", tls-name=jp.example.com
US = vmess, 3.3.3.3, 443, auto, "uuid", transport=ws, ws-path=/ws, ws-headers=Host:us.example.com
"#;
        let (nodes, errors) = parse_subscription_content(text);
        assert_eq!(nodes.len(), 3, "Loon 应解析 3 个节点：{errors:?}");

        let hk = find(&nodes, "HK");
        assert_eq!(hk["type"], "ss");
        assert_eq!(hk["cipher"], "aes-128-gcm");
        assert_eq!(hk["password"], "pwd");

        let jp = find(&nodes, "JP");
        assert_eq!(jp["type"], "trojan");
        assert_eq!(jp["password"], "pwd");
        assert_eq!(jp["servername"], "jp.example.com");

        let us = find(&nodes, "US");
        assert_eq!(us["uuid"], "uuid");
        assert_eq!(us["network"], "ws");
        assert_eq!(us["ws-opts"]["path"], "/ws");
        assert_eq!(us["ws-opts"]["headers"]["Host"], "us.example.com");
    }

    #[test]
    fn parses_clash_yaml_block_and_flow() {
        let text = r#"
proxies:
  - name: HK1
    type: vmess
    server: 1.2.3.4
    port: 443
    uuid: uuid-1
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
  - { name: HK2, type: ss, server: 5.6.7.8, port: 8388, cipher: aes-256-gcm, password: pwd }
  - { type: ss, server: 9.9.9.9, port: 9999, cipher: aes-128-gcm, password: x }
"#;
        let (nodes, errors) = parse_subscription_content(text);
        assert_eq!(nodes.len(), 3, "Clash YAML 应解析 3 个节点：{errors:?}");

        let hk1 = find(&nodes, "HK1");
        assert_eq!(hk1["type"], "vmess");
        assert_eq!(hk1["uuid"], "uuid-1");
        assert_eq!(hk1["tls"], true);
        assert_eq!(hk1["network"], "ws");
        assert_eq!(hk1["ws-opts"]["path"], "/ws");
        assert_eq!(hk1["ws-opts"]["headers"]["Host"], "cdn.example.com");

        let hk2 = find(&nodes, "HK2");
        assert_eq!(hk2["type"], "ss");
        assert_eq!(hk2["cipher"], "aes-256-gcm");

        // 缺失 name 时用 server:port 补齐
        let fallback = find(&nodes, "9.9.9.9:9999");
        assert_eq!(fallback["type"], "ss");
    }

    #[test]
    fn parses_sip008_json() {
        let text = r#"{
  "version": 1,
  "servers": [
    {"server": "1.1.1.1", "server_port": 8388, "password": "p1", "method": "aes-256-gcm", "remarks": "SS1"},
    {"server": "2.2.2.2", "server_port": 8389, "password": "p2", "method": "chacha20-ietf-poly1305", "remarks": "SS2"}
  ]
}"#;
        let (nodes, errors) = parse_subscription_content(text);
        assert_eq!(nodes.len(), 2, "SIP008 应解析 2 个节点：{errors:?}");
        let n1 = find(&nodes, "SS1");
        assert_eq!(n1["type"], "ss");
        assert_eq!(n1["server"], "1.1.1.1");
        assert_eq!(n1["port"], 8388);
        assert_eq!(n1["cipher"], "aes-256-gcm");
        assert_eq!(n1["password"], "p1");
        assert_eq!(find(&nodes, "SS2")["port"], 8389);
    }

    #[test]
    fn parses_singbox_json() {
        let text = r#"{
  "outbounds": [
    {
      "type": "vless",
      "tag": "VL",
      "server": "1.2.3.4",
      "server_port": 443,
      "uuid": "uuid-1",
      "tls": {"enabled": true, "server_name": "sni.example.com", "insecure": true},
      "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"}}
    },
    {"type": "shadowsocks", "tag": "SS", "server": "5.6.7.8", "server_port": 8388, "method": "aes-256-gcm", "password": "pwd"},
    {"type": "selector", "tag": "selector", "outbounds": ["VL", "SS"]},
    {"type": "direct", "tag": "direct"}
  ]
}"#;
        let (nodes, errors) = parse_subscription_content(text);
        assert_eq!(nodes.len(), 2, "sing-box 应解析 2 个节点：{errors:?}");

        let vl = find(&nodes, "VL");
        assert_eq!(vl["type"], "vless");
        assert_eq!(vl["uuid"], "uuid-1");
        assert_eq!(vl["tls"], true);
        assert_eq!(vl["servername"], "sni.example.com");
        assert_eq!(vl["skip-cert-verify"], true);
        assert_eq!(vl["network"], "ws");
        assert_eq!(vl["ws-opts"]["path"], "/ws");
        assert_eq!(vl["ws-opts"]["headers"]["Host"], "cdn.example.com");

        let ss = find(&nodes, "SS");
        assert_eq!(ss["type"], "ss");
        assert_eq!(ss["cipher"], "aes-256-gcm");
        assert_eq!(ss["password"], "pwd");
    }

    #[test]
    fn parses_quantumult_x() {
        let text = r#"
shadowsocks = 1.1.1.1:8388, method=aes-256-gcm, password=pwd, tag=QX-SS
trojan = 2.2.2.2:443, password=tpwd, over-tls=true, tls-host=t.example.com, tag=QX-TJ
vmess = 3.3.3.3:443, method=chacha20-poly1305, password=uuid-1, obfs=ws, obfs-host=cdn.example.com, obfs-uri=/ws, tag=QX-VM
vless = 4.4.4.4:443, method=none, password=uuid-2, obfs=ws, obfs-host=cdn.example.com, obfs-uri=/vl, tag=QX-VL
"#;
        let (nodes, errors) = parse_subscription_content(text);
        assert_eq!(nodes.len(), 4, "Quantumult X 应解析 4 个节点：{errors:?}");

        let ss = find(&nodes, "QX-SS");
        assert_eq!(ss["type"], "ss");
        assert_eq!(ss["cipher"], "aes-256-gcm");
        assert_eq!(ss["password"], "pwd");

        let tj = find(&nodes, "QX-TJ");
        assert_eq!(tj["type"], "trojan");
        assert_eq!(tj["password"], "tpwd");
        assert_eq!(tj["tls"], true);
        assert_eq!(tj["servername"], "t.example.com");

        let vm = find(&nodes, "QX-VM");
        assert_eq!(vm["type"], "vmess");
        assert_eq!(vm["uuid"], "uuid-1");
        assert_eq!(vm["cipher"], "chacha20-poly1305");
        assert_eq!(vm["network"], "ws");
        assert_eq!(vm["ws-opts"]["path"], "/ws");
        assert_eq!(vm["ws-opts"]["headers"]["Host"], "cdn.example.com");

        let vl = find(&nodes, "QX-VL");
        assert_eq!(vl["type"], "vless");
        assert_eq!(vl["uuid"], "uuid-2");
        assert_eq!(vl["network"], "ws");
        assert_eq!(vl["ws-opts"]["path"], "/vl");
    }

    #[test]
    fn parses_uri_mixed_list() {
        let text = "vless://uuid-1@1.2.3.4:443?security=tls&sni=a.com#V1\ntrojan://pwd@5.6.7.8:443#T1";
        let (nodes, errors) = parse_subscription_content(text);
        assert_eq!(nodes.len(), 2, "URI 列表应解析 2 个节点：{errors:?}");
        assert_eq!(find(&nodes, "V1")["type"], "vless");
        assert_eq!(find(&nodes, "T1")["type"], "trojan");
    }
}
