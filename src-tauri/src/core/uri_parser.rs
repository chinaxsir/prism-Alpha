//! 分享链接（URI）解析器：ss/vmess/vless/trojan/hysteria(2)/tuic/socks → Clash 节点
//! （ssr:// 明确报错：内核 sing-box 1.6.0+ 已移除该协议）
//!
//! 机场默认订阅多为 base64 包裹的 URI 列表，本模块负责把每行链接还原成
//! `ClashNode`（config_builder 的 Clash 结构），再合并进统一 pipeline。
//! 语法与各客户端（Clash / Surge / sing-box 订阅转换器）的通行实现保持一致。

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

/// 检测文本是否为 URI 列表订阅（含 ss:// 等分享链接行）
pub fn is_uri_list(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim();
        l.starts_with("ss://")
            || l.starts_with("ssr://")
            || l.starts_with("vmess://")
            || l.starts_with("vless://")
            || l.starts_with("trojan://")
            || l.starts_with("hysteria2://")
            || l.starts_with("hy2://")
            || l.starts_with("hysteria://")
            || l.starts_with("hy://")
            || l.starts_with("tuic://")
            || l.starts_with("socks5://")
            || l.starts_with("socks://")
    })
}

/// 解析单个分享链接 → Clash 节点 JSON
pub fn parse_line(line: &str) -> Result<Option<Value>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let (scheme, rest) = line.split_once("://").context("缺少 ://")?;
    let node = match scheme {
        "ss" => parse_ss(rest)?,
        // SSR 已被内核（sing-box 1.6.0+）移除：明确报错而非解析后静默丢弃
        "ssr" => bail!("SSR 协议已被内核移除（1.6.0+ 版本不再支持），无法使用"),
        "vmess" => parse_vmess(rest)?,
        "vless" => parse_vless(rest)?,
        "trojan" => parse_trojan(rest)?,
        "hysteria2" | "hy2" => parse_hysteria2(rest)?,
        "hysteria" | "hy" => parse_hysteria(rest)?,
        "tuic" => parse_tuic(rest)?,
        "socks5" | "socks" => parse_socks(rest)?,
        _ => bail!("不支持的协议：{scheme}"),
    };
    Ok(Some(node))
}

/// 批量解析（返回 (节点列表, 无法解析的行号+原因, 机场提示信息)）
/// 机场提示：如「终端超限，请至面板重置」等，由 AIRPORT_NOTICE: 前缀标识
pub fn parse_lines(text: &str) -> (Vec<Value>, Vec<String>, Option<String>) {
    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    let mut notice = None;
    for (idx, line) in text.lines().enumerate() {
        match parse_line(line) {
            Ok(Some(node)) => nodes.push(node),
            Ok(None) => {}
            Err(e) => {
                let msg = e.to_string();
                if let Some(notice_text) = msg.strip_prefix("AIRPORT_NOTICE:") {
                    // 机场提示优先级最高，直接返回给上层展示
                    notice = Some(notice_text.to_string());
                } else {
                    errors.push(format!("第 {} 行：{}", idx + 1, msg));
                }
            }
        }
    }
    (nodes, errors, notice)
}

/// 订阅文本 base64 包裹还原：已是 URI 列表则原样返回；否则尝试 base64
/// 解码（机场默认订阅多为 base64 包裹的 URI 列表）。解码失败原样返回
pub fn unwrap_base64(text: &str) -> String {
    if is_uri_list(text) {
        return text.to_string();
    }
    b64_decode_str(text.trim()).unwrap_or_else(|_| text.to_string())
}

// ---------------- 通用工具 ----------------

/// base64 解码（先尝试标准，再尝试 URL_SAFE_NO_PAD，最后 URL_SAFE）
fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};
    for eng in [&STANDARD, &URL_SAFE_NO_PAD, &URL_SAFE] {
        if let Ok(b) = eng.decode(s.trim()) {
            return Ok(b);
        }
    }
    bail!("base64 解码失败")
}

fn b64_decode_str(s: &str) -> Result<String> {
    String::from_utf8(b64_decode(s)?).context("base64 内容不是 UTF-8")
}

/// 从 URI 提取 host:port（支持 IPv6 [..]:port）
fn split_host_port(s: &str) -> Result<(String, u16)> {
    if let Some(start) = s.find('[') {
        // IPv6
        let end = s.rfind(']').context("IPv6 缺少 ]")?;
        let host = s[start + 1..end].to_string();
        let port_str = s[end + 1..].strip_prefix(':').context("IPv6 缺少端口")?;
        let port = port_str.parse::<u16>().context("端口无效")?;
        Ok((host, port))
    } else {
        let (host, port) = s.rsplit_once(':').context("缺少端口")?;
        Ok((host.to_string(), port.parse::<u16>().context("端口无效")?))
    }
}

/// 解析 URI 尾部 #fragment 为 name（URL 解码 + UTF-8 字节还原）
fn decode_name(frag: &str) -> String {
    let decoded = urlencoding_decode(frag).unwrap_or_else(|| frag.to_string());
    // 【APP-4 任务1】修复 UTF-8 被按 Latin-1/cp1252 逐字节解码导致的乱码：
    // 例如 `%E5%AE%B6%E5%AE%BD%E4%BC%98%E9%80%895`（家宽优选5）被旧代码
    // 按 `byte as char` 逐字节展开为 `å®¶å®½ä¼˜é€‰5`。这里把每个字符
    // 映射回原始字节再按 UTF-8 重组，能还原出正确中文。
    fix_utf8_mojibake(&decoded)
}

/// cp1252/Latin-1 高位字符 → 原始字节映射。
/// 0x00-0xFF 直接对应；0x80-0x9F 区间在 cp1252 里有特殊字符映射。
fn cp1252_to_byte(ch: char) -> Option<u8> {
    let code = ch as u32;
    if code <= 0xFF {
        return Some(code as u8);
    }
    match ch {
        '€' => Some(0x80), '‚' => Some(0x82), 'ƒ' => Some(0x83),
        '„' => Some(0x84), '…' => Some(0x85), '†' => Some(0x86),
        '‡' => Some(0x87), 'ˆ' => Some(0x88), '‰' => Some(0x89),
        'Š' => Some(0x8A), '‹' => Some(0x8B), 'Œ' => Some(0x8C),
        'Ž' => Some(0x8E), '‘' => Some(0x91), '’' => Some(0x92),
        '“' => Some(0x93), '”' => Some(0x94), '•' => Some(0x95),
        '–' => Some(0x96), '—' => Some(0x97), '˜' => Some(0x98),
        '™' => Some(0x99), 'š' => Some(0x9A), '›' => Some(0x9B),
        'œ' => Some(0x9C), 'ž' => Some(0x9E), 'Ÿ' => Some(0x9F),
        _ => None,
    }
}

/// 修复 UTF-8 字节被按 Latin-1/cp1252 单字节解码产生的乱码。
/// 如果字符串中所有字符都能映射回单字节，且这些字节恰好组成合法
/// UTF-8 多字节文本（含中文或扩展字符），则还原为正确的 UTF-8 字符串。
/// 纯 ASCII 或包含无法映射字符时原样返回。
pub fn fix_utf8_mojibake(s: &str) -> String {
    if s.is_ascii() {
        return s.to_string();
    }
    let mut raw_bytes = Vec::with_capacity(s.len());
    for ch in s.chars() {
        if let Some(b) = cp1252_to_byte(ch) {
            raw_bytes.push(b);
        } else {
            return s.to_string();
        }
    }
    if let Ok(decoded) = String::from_utf8(raw_bytes) {
        if decoded != s
            && decoded
                .chars()
                .any(|c| ('\u{4E00}'..='\u{9FFF}').contains(&c) || c > '\u{00FF}')
        {
            return decoded;
        }
    }
    s.to_string()
}

/// 简易 URL percent-decode（处理 %20、%40 等）。
/// 注意：返回的是按 Latin-1 逐字节展开的字符串，调用方需配合
/// `fix_utf8_mojibake` 还原真实 UTF-8 内容。
fn urlencoding_decode(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            let byte = u8::from_str_radix(&hex, 16).ok()?;
            out.push(byte as char);
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// 解析 query string 为键值对（保留顺序）
fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let mut it = p.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or_default();
            Some((
                urlencoding_decode(k).unwrap_or_else(|| k.to_string()),
                urlencoding_decode(v).unwrap_or_else(|| v.to_string()),
            ))
        })
        .collect()
}

// ---------------- 各协议实现 ----------------

/// ss:// 三种形态：
/// 1) SIP002：ss://base64url(method:password)@host:port[?plugin=...]#name
/// 2) 明文 userinfo：ss://method:password@host:port#name
/// 3) 旧版整体编码：ss://base64(method:password@host:port)#name
fn parse_ss(rest: &str) -> Result<Value> {
    let (payload, name) = payload_and_name(rest);
    let (payload, query) = payload.split_once('?').unwrap_or((payload, ""));
    let name = decode_name(name);

    let (method, password, server, port) = if payload.contains('@') {
        // SIP002 或明文 userinfo
        let (userinfo, hostport) = payload.rsplit_once('@').context("SS 缺少 @")?;
        let up = b64_decode_str(userinfo).unwrap_or_else(|_| userinfo.to_string());
        let (method, password) = up.split_once(':').context("SS 缺少密码分隔符 :")?;
        let (server, port) = split_host_port(hostport)?;
        (method.to_string(), password.to_string(), server, port)
    } else {
        // 旧版：整体 base64
        let decoded = b64_decode_str(payload)?;
        let (userinfo, hostport) = decoded.rsplit_once('@').context("SS 缺少 @")?;
        let (method, password) = userinfo.split_once(':').context("SS 缺少密码分隔符 :")?;
        let (server, port) = split_host_port(hostport)?;
        (method.to_string(), password.to_string(), server, port)
    };

    let mut node = json!({
        "name": name,
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": method,
        "password": password,
    });

    // SIP002 plugin 参数（obfs-local / simple-obfs）
    if !query.is_empty() {
        let params: std::collections::HashMap<_, _> = parse_query(query).into_iter().collect();
        if let Some(plugin) = params.get("plugin") {
            let segs: Vec<&str> = plugin.split(';').collect();
            let kind = segs.first().copied().unwrap_or_default();
            if kind.contains("obfs") {
                let mut mode = "http".to_string();
                let mut host = String::new();
                for seg in &segs[1..] {
                    match *seg {
                        "obfs=http" | "http" => mode = "http".into(),
                        "obfs=tls" | "tls" => mode = "tls".into(),
                        _ => {
                            if let Some(h) = seg.strip_prefix("obfs-host=") {
                                host = h.to_string();
                            }
                        }
                    }
                }
                node["plugin"] = json!("obfs");
                node["plugin-opts"] = json!({ "mode": mode, "host": host });
            }
        }
    }

    Ok(node)
}

/// 分离载荷与 #name（fragment 可能含 %XX 编码）
fn payload_and_name(rest: &str) -> (&str, &str) {
    rest.split_once('#').unwrap_or((rest, ""))
}

/// vmess://base64(JSON)（名称取 JSON 的 ps 字段，#fragment 忽略）
fn parse_vmess(rest: &str) -> Result<Value> {
    let (payload, _) = payload_and_name(rest);
    let text = b64_decode_str(payload)?;
    let j: Value = serde_json::from_str(&text).context("VMess JSON 解析失败")?;

    let name = j["ps"].as_str().unwrap_or_default().to_string();
    let server = j["add"].as_str().context("缺少 add")?.to_string();
    let port: u16 = j["port"]
        .as_u64()
        .or_else(|| j["port"].as_str().and_then(|s| s.parse::<u64>().ok()))
        .and_then(|v| u16::try_from(v).ok())
        .context("端口无效")?;

    // 机场返回的提示节点（流量超限/到期/重置引导等）：server 为环回地址，
    // 名称包含提示关键词。识别后跳过，由上层统一给出友好错误
    let is_placeholder = server.starts_with("127.")
        || server.starts_with("localhost")
        || name.contains("剩余流量")
        || name.contains("下次重置")
        || name.contains("已用流量")
        || name.contains("超限")
        || name.contains("重置接入")
        || name.contains("到期")
        || name.contains("请至面板")
        || name.contains("请联系客服");
    if is_placeholder {
        bail!("AIRPORT_NOTICE:{name}");
    }

    let uuid = j["id"].as_str().unwrap_or_default().to_string();
    // vmess 分享 JSON 的 port/aid 常为字符串，兼容数字与字符串两种
    let alter_id = j["aid"]
        .as_i64()
        .or_else(|| j["aid"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0);
    let cipher = j["scy"].as_str().or_else(|| j["security"].as_str()).unwrap_or("auto").to_string();
    let network = j["net"].as_str().unwrap_or("tcp").to_string();
    let host = j["host"].as_str().unwrap_or_default().to_string();
    let path = j["path"].as_str().unwrap_or_default().to_string();
    let tls = j["tls"].as_str().unwrap_or_default().to_string();
    let sni = j["sni"].as_str().or_else(|| j["servername"].as_str()).unwrap_or_default().to_string();
    let alpn = j["alpn"].as_str().map(|s| {
        s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect::<Vec<_>>()
    });
    let fp = j["fp"].as_str().unwrap_or_default().to_string();

    let mut node = json!({
        "name": name,
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alter_id": alter_id,
        "cipher": cipher,
    });

    if network != "tcp" {
        node["network"] = json!(network);
    }
    match network.as_str() {
        "ws" => {
            let mut ws_opts = json!({});
            if !path.is_empty() {
                ws_opts["path"] = json!(path);
            }
            if !host.is_empty() {
                ws_opts["headers"] = json!({ "Host": host });
            }
            node["ws-opts"] = ws_opts;
        }
        "grpc" => {
            node["grpc-opts"] = json!({ "grpc-service-name": host.clone() });
        }
        "http" | "h2" => {
            // http / h2 通过 http-opts / h2-opts 补齐
            let key = if network == "http" { "http-opts" } else { "h2-opts" };
            let mut opts = json!({});
            if !path.is_empty() {
                opts["path"] = if network == "http" { json!([path]) } else { json!(path) };
            }
            if !host.is_empty() {
                if network == "http" {
                    opts["headers"] = json!({ "Host": [host] });
                } else {
                    opts["host"] = json!([host]);
                }
            }
            node[key] = opts;
        }
        _ => {}
    }

    if tls == "tls" {
        node["tls"] = json!(true);
        if !sni.is_empty() {
            node["sni"] = json!(sni);
        }
        if let Some(al) = alpn {
            node["alpn"] = json!(al);
        }
        if !fp.is_empty() {
            node["client-fingerprint"] = json!(fp);
        }
    }

    Ok(node)
}

/// vless://uuid@host:port?security=...&type=...&...#name
fn parse_vless(rest: &str) -> Result<Value> {
    let (addr_query, name) = rest.split_once('#').unwrap_or((rest, ""));
    let (addr, query) = addr_query.split_once('?').unwrap_or((addr_query, ""));
    let (uuid, hostport) = addr.rsplit_once('@').context("缺少 @")?;
    let (server, port) = split_host_port(hostport)?;
    let name = decode_name(name);

    // 机场返回的提示节点（流量超限/到期/重置引导等）
    if server.starts_with("127.") || server.starts_with("localhost")
        || name.contains("剩余流量") || name.contains("下次重置")
        || name.contains("超限") || name.contains("重置接入")
        || name.contains("到期") || name.contains("请至面板") {
        bail!("AIRPORT_NOTICE:{name}");
    }

    let params: std::collections::HashMap<_, _> = parse_query(query).into_iter().collect();
    let security = params.get("security").cloned().unwrap_or_else(|| "none".into());
    let network = params.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let sni = params.get("sni").cloned().or_else(|| params.get("peer").cloned()).unwrap_or_default();
    let fp = params.get("fp").cloned().unwrap_or_default();
    let flow = params.get("flow").cloned().unwrap_or_default();
    let public_key = params.get("pbk").cloned().unwrap_or_default();
    let short_id = params.get("sid").cloned().unwrap_or_default();
    let alpn = params.get("alpn").cloned().unwrap_or_default();
    let path = params.get("path").cloned().unwrap_or_default();
    let host = params.get("host").cloned().unwrap_or_default();
    let service_name = params.get("serviceName").cloned().unwrap_or_default();

    let mut node = json!({
        "name": name,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
    });

    if network != "tcp" {
        node["network"] = json!(network);
    }
    match network.as_str() {
        "ws" => {
            let mut ws = json!({});
            if !path.is_empty() {
                ws["path"] = json!(path);
            }
            if !host.is_empty() {
                ws["headers"] = json!({ "Host": host });
            }
            node["ws-opts"] = ws;
        }
        "grpc" => {
            node["grpc-opts"] = json!({ "grpc-service-name": service_name });
        }
        _ => {}
    }

    if !flow.is_empty() {
        node["flow"] = json!(flow);
    }
    if security == "tls" || security == "reality" {
        node["tls"] = json!(true);
        if !sni.is_empty() {
            node["sni"] = json!(sni);
        }
        if !fp.is_empty() {
            node["client-fingerprint"] = json!(fp);
        }
        if !alpn.is_empty() {
            node["alpn"] = json!(alpn.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>());
        }
    }
    if security == "reality" && !public_key.is_empty() {
        node["reality-opts"] = json!({ "public-key": public_key, "short-id": short_id });
    }

    Ok(node)
}

/// trojan://password@host:port?...#name
fn parse_trojan(rest: &str) -> Result<Value> {
    let (addr_query, name) = rest.split_once('#').unwrap_or((rest, ""));
    let (addr, query) = addr_query.split_once('?').unwrap_or((addr_query, ""));
    let (password, hostport) = addr.rsplit_once('@').context("缺少 @")?;
    let (server, port) = split_host_port(hostport)?;
    let name = decode_name(name);

    // 机场返回的提示节点
    if server.starts_with("127.") || server.starts_with("localhost")
        || name.contains("剩余流量") || name.contains("下次重置")
        || name.contains("超限") || name.contains("重置接入")
        || name.contains("到期") || name.contains("请至面板") {
        bail!("AIRPORT_NOTICE:{name}");
    }

    let params: std::collections::HashMap<_, _> = parse_query(query).into_iter().collect();
    let sni = params.get("sni").cloned().or_else(|| params.get("peer").cloned()).unwrap_or_default();
    let alpn = params.get("alpn").cloned().unwrap_or_default();
    let network = params.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let path = params.get("path").cloned().unwrap_or_default();
    let host = params.get("host").cloned().unwrap_or_default();

    let mut node = json!({
        "name": name,
        "type": "trojan",
        "server": server,
        "port": port,
        "password": password,
    });

    if !sni.is_empty() {
        node["sni"] = json!(sni);
    }
    if !alpn.is_empty() {
        node["alpn"] = json!(alpn.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>());
    }
    if network == "ws" {
        let mut ws = json!({});
        if !path.is_empty() {
            ws["path"] = json!(path);
        }
        if !host.is_empty() {
            ws["headers"] = json!({ "Host": host });
        }
        node["ws-opts"] = ws;
        node["network"] = json!("ws");
    } else if network == "grpc" {
        node["network"] = json!("grpc");
        node["grpc-opts"] = json!({ "grpc-service-name": host });
    }

    Ok(node)
}

/// hysteria2://password@host:port?...#name  （也支持 hy2://）
fn parse_hysteria2(rest: &str) -> Result<Value> {
    let (addr_query, name) = rest.split_once('#').unwrap_or((rest, ""));
    let (addr, query) = addr_query.split_once('?').unwrap_or((addr_query, ""));
    let (password, hostport) = addr.rsplit_once('@').context("缺少 @")?;
    let (server, port) = split_host_port(hostport)?;
    let name = decode_name(name);

    let params: std::collections::HashMap<_, _> = parse_query(query).into_iter().collect();
    let sni = params.get("sni").cloned().unwrap_or_default();
    let obfs = params.get("obfs").cloned().unwrap_or_default();
    let obfs_password = params.get("obfs-password").cloned().unwrap_or_default();
    let insecure = params.get("insecure").cloned().unwrap_or_default();

    let mut node = json!({
        "name": name,
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": password,
    });

    if !sni.is_empty() {
        node["sni"] = json!(sni);
    }
    if obfs == "salamander" && !obfs_password.is_empty() {
        node["obfs"] = json!("salamander");
        node["obfs-password"] = json!(obfs_password);
    }
    if insecure == "1" || insecure.eq_ignore_ascii_case("true") {
        node["skip-cert-verify"] = json!(true);
    }

    Ok(node)
}

/// tuic://uuid:password@host:port?...#name
fn parse_tuic(rest: &str) -> Result<Value> {
    let (addr_query, name) = rest.split_once('#').unwrap_or((rest, ""));
    let (addr, query) = addr_query.split_once('?').unwrap_or((addr_query, ""));
    let (uuid_pass, hostport) = addr.rsplit_once('@').context("缺少 @")?;
    let (uuid, password) = uuid_pass.split_once(':').context("TUIC 缺少 uuid:password")?;
    let (server, port) = split_host_port(hostport)?;
    let name = decode_name(name);

    let params: std::collections::HashMap<_, _> = parse_query(query).into_iter().collect();
    let congestion = params.get("congestion_control").cloned().unwrap_or_else(|| "bbr".into());
    let alpn = params.get("alpn").cloned().unwrap_or_else(|| "h3".into());
    let sni = params.get("sni").cloned().unwrap_or_default();

    let mut node = json!({
        "name": name,
        "type": "tuic",
        "server": server,
        "port": port,
        "uuid": uuid,
        "password": password,
        "congestion-controller": congestion,
    });

    if !alpn.is_empty() {
        node["alpn"] = json!(alpn.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>());
    }
    if !sni.is_empty() {
        node["sni"] = json!(sni);
    }

    Ok(node)
}

/// hysteria://host:port?auth=<password>&peer=<sni>&insecure=1#name
/// （Hysteria 1 分享链接；与 hysteria2 的密码在 userinfo 不同，这里认证在 query）
fn parse_hysteria(rest: &str) -> Result<Value> {
    let (addr_query, name) = rest.split_once('#').unwrap_or((rest, ""));
    let (hostport, query) = addr_query.split_once('?').unwrap_or((addr_query, ""));
    let (server, port) = split_host_port(hostport)?;
    let name = decode_name(name);

    let params: std::collections::HashMap<_, _> = parse_query(query).into_iter().collect();
    // 认证字段：auth / password / token 均可能出现
    let password = params
        .get("auth")
        .or_else(|| params.get("password"))
        .or_else(|| params.get("token"))
        .cloned()
        .context("hysteria 缺少认证参数（auth/password/token）")?;
    let sni = params
        .get("peer")
        .or_else(|| params.get("sni"))
        .cloned()
        .unwrap_or_default();
    let insecure = params.get("insecure").cloned().unwrap_or_default();
    let alpn = params.get("alpn").cloned().unwrap_or_default();

    let mut node = json!({
        "name": name,
        "type": "hysteria",
        "server": server,
        "port": port,
        "password": password,
    });

    if !sni.is_empty() {
        node["sni"] = json!(sni);
    }
    if !alpn.is_empty() {
        node["alpn"] = json!(alpn.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>());
    }
    if insecure == "1" || insecure.eq_ignore_ascii_case("true") {
        node["skip-cert-verify"] = json!(true);
    }

    Ok(node)
}

// ---------------- 分享链接：SOCKS5 ----------------

/// socks5://[user:pass@]host:port#name （userinfo 可缺省；也兼容 query user/pass）
fn parse_socks(rest: &str) -> Result<Value> {
    let (addr_query, name) = rest.split_once('#').unwrap_or((rest, ""));
    let (addr, query) = addr_query.split_once('?').unwrap_or((addr_query, ""));
    let (userinfo, hostport) = match addr.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, addr),
    };
    let (server, port) = split_host_port(hostport)?;
    let name = decode_name(name);

    let mut username = String::new();
    let mut password = String::new();
    if let Some(u) = userinfo {
        if let Some((raw_user, raw_pass)) = u.split_once(':') {
            username = urlencoding_decode(raw_user).unwrap_or_else(|| raw_user.to_string());
            password = urlencoding_decode(raw_pass).unwrap_or_else(|| raw_pass.to_string());
        } else {
            username = urlencoding_decode(u).unwrap_or_else(|| u.to_string());
        }
    }
    // query 形式补充：socks5://host:port?user=u&pass=p
    let params: std::collections::HashMap<_, _> = parse_query(query).into_iter().collect();
    if username.is_empty() {
        username = params
            .get("user")
            .or_else(|| params.get("username"))
            .cloned()
            .unwrap_or_default();
    }
    if password.is_empty() {
        password = params
            .get("pass")
            .or_else(|| params.get("password"))
            .cloned()
            .unwrap_or_default();
    }

    let mut node = json!({
        "name": name,
        "type": "socks5",
        "server": server,
        "port": port,
    });
    if !username.is_empty() {
        node["username"] = json!(username);
    }
    if !password.is_empty() {
        node["password"] = json!(password);
    }
    Ok(node)
}

// ---------------- 单元测试 ----------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hysteria() {
        let raw = "hysteria://hy1.example.com:443?auth=secret123&peer=sni.example.com&insecure=1&alpn=h3#hy-node";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["type"], "hysteria");
        assert_eq!(node["server"], "hy1.example.com");
        assert_eq!(node["port"], 443);
        assert_eq!(node["password"], "secret123");
        assert_eq!(node["sni"], "sni.example.com");
        assert_eq!(node["skip-cert-verify"], true);
        assert_eq!(node["alpn"], json!(["h3"]));
    }

    #[test]
    fn parses_hysteria_with_password_param() {
        let raw = "hysteria://host.example.com:443?password=pwd&peer=sni.example.com#hy2";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["type"], "hysteria");
        assert_eq!(node["password"], "pwd");
    }

    #[test]
    fn detects_uri_list() {
        assert!(is_uri_list("ss://abc#def"));
        assert!(is_uri_list("vmess://eyJ2IjoiMiJ9"));
        assert!(!is_uri_list("proxies:\n  - name: a"));
        assert!(!is_uri_list("mixed content\nwith ss:// but no"));
    }

    #[test]
    fn parses_ss_base64() {
        let raw = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#test-node";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["type"], "ss");
        assert_eq!(node["server"], "1.2.3.4");
        assert_eq!(node["port"], 8388);
        assert_eq!(node["cipher"], "aes-256-gcm");
        assert_eq!(node["password"], "password");
        assert_eq!(node["name"], "test-node");
    }

    #[test]
    fn parses_ss_plain() {
        let raw = "ss://chacha20-ietf-poly1305:secret@example.com:443#plain";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["cipher"], "chacha20-ietf-poly1305");
        assert_eq!(node["password"], "secret");
        assert_eq!(node["server"], "example.com");
    }

    #[test]
    fn parses_vmess() {
        let json = r#"{"v":"2","ps":"vm-node","add":"vm.example.com","port":"443","id":"uuid-1234","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"sni.example.com","alpn":"h2,http/1.1","fp":"chrome"}"#;
        let b64 = URL_SAFE_NO_PAD.encode(json);
        let raw = format!("vmess://{b64}");
        let node = parse_line(&raw).unwrap().unwrap();
        assert_eq!(node["name"], "vm-node");
        assert_eq!(node["server"], "vm.example.com");
        assert_eq!(node["port"], 443);
        assert_eq!(node["uuid"], "uuid-1234");
        assert_eq!(node["network"], "ws");
        assert_eq!(node["tls"], true);
        assert_eq!(node["sni"], "sni.example.com");
        assert_eq!(node["client-fingerprint"], "chrome");
        assert_eq!(node["ws-opts"]["path"], "/ws");
        assert_eq!(node["ws-opts"]["headers"]["Host"], "cdn.example.com");
    }

    #[test]
    fn parses_vless_reality() {
        let raw = "vless://uuid-5678@1.2.3.4:443?security=reality&flow=xtls-rprx-vision&sni=dl.google.com&fp=chrome&pbk=pubkey123&sid=ab&type=tcp#vless-reality";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["type"], "vless");
        assert_eq!(node["uuid"], "uuid-5678");
        assert_eq!(node["server"], "1.2.3.4");
        assert_eq!(node["tls"], true);
        assert_eq!(node["flow"], "xtls-rprx-vision");
        assert_eq!(node["sni"], "dl.google.com");
        assert_eq!(node["client-fingerprint"], "chrome");
        assert_eq!(node["reality-opts"]["public-key"], "pubkey123");
        assert_eq!(node["reality-opts"]["short-id"], "ab");
    }

    #[test]
    fn parses_vless_ws() {
        let raw = "vless://uuid@cdn.com:443?security=tls&type=ws&path=%2Fapi&host=cdn.com#vless-ws";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["network"], "ws");
        assert_eq!(node["ws-opts"]["path"], "/api");
        assert_eq!(node["ws-opts"]["headers"]["Host"], "cdn.com");
    }

    #[test]
    fn parses_trojan() {
        let raw = "trojan://pass123@trojan.example.com:443?sni=trojan.example.com&type=ws&path=%2Ftj&host=trojan.example.com#trojan";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["type"], "trojan");
        assert_eq!(node["password"], "pass123");
        assert_eq!(node["server"], "trojan.example.com");
        assert_eq!(node["sni"], "trojan.example.com");
        assert_eq!(node["network"], "ws");
    }

    #[test]
    fn parses_hysteria2() {
        let raw = "hysteria2://pass456@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=obfspass&insecure=1#hy2-node";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["type"], "hysteria2");
        assert_eq!(node["password"], "pass456");
        assert_eq!(node["obfs"], "salamander");
        assert_eq!(node["obfs-password"], "obfspass");
        assert_eq!(node["skip-cert-verify"], true);
    }

    #[test]
    fn parses_tuic() {
        let raw = "tuic://uuid-999:pass999@tuic.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic.example.com#tuic-node";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["type"], "tuic");
        assert_eq!(node["uuid"], "uuid-999");
        assert_eq!(node["password"], "pass999");
        assert_eq!(node["congestion-controller"], "bbr");
    }

    #[test]
    fn parses_ipv6_ss() {
        let raw = "ss://YWVzLTI1Ni1nY206cGFzcw==@[2001:db8::1]:8388#ipv6";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["server"], "2001:db8::1");
        assert_eq!(node["port"], 8388);
    }

    #[test]
    fn parses_batch() {
        let text = "ss://YWVzLTI1Ni1nY206cGFzcw==@a.com:443#a\ninvalid-line\nvmess://eyJ2IjoiMiIsInBzIjoiYiIsImFkZCI6ImIuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoidiJ9#b";
        let (nodes, errors, _notice) = parse_lines(text);
        assert_eq!(nodes.len(), 2);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("第 2 行"));
    }

    #[test]
    fn parses_socks5_with_auth() {
        let raw = "socks5://alice:s3cret@5.6.7.8:1080#socks-node";
        let node = parse_line(raw).unwrap().unwrap();
        assert_eq!(node["type"], "socks5");
        assert_eq!(node["server"], "5.6.7.8");
        assert_eq!(node["port"], 1080);
        assert_eq!(node["username"], "alice");
        assert_eq!(node["password"], "s3cret");
    }

    // ============================================================
    // 【APP-4 任务1】fix_utf8_mojibake 单元测试
    // ============================================================
    #[test]
    fn fix_mojibake_restores_chinese_name() {
        // "UCN优选1" UTF-8 字节被逐字节按 Latin-1 展开后的乱码
        let garbled = "UCN\u{00e4}\u{00bc}\u{0098}\u{00e9}\u{0080}\u{0089}1";
        assert_eq!(fix_utf8_mojibake(garbled), "UCN优选1");
    }

    #[test]
    fn fix_mojibake_restores_pure_chinese() {
        // "家宽优选5" UTF-8 乱码
        let garbled = "\u{00e5}\u{00ae}\u{00b6}\u{00e5}\u{00ae}\u{00bd}\u{00e4}\u{00bc}\u{0098}\u{00e9}\u{0080}\u{0089}5";
        assert_eq!(fix_utf8_mojibake(garbled), "家宽优选5");
    }

    #[test]
    fn fix_mojibake_keeps_ascii_unchanged() {
        assert_eq!(fix_utf8_mojibake("HK-01"), "HK-01");
        assert_eq!(fix_utf8_mojibake("US West"), "US West");
    }

    #[test]
    fn fix_mojibake_keeps_normal_unicode_unchanged() {
        // 正常的中文节点名不应被误改
        let normal = "香港节点01";
        assert_eq!(fix_utf8_mojibake(normal), normal);
    }

    #[test]
    fn fix_mojibake_mixed_ascii_and_garbled() {
        // 混合 ASCII + 乱码：只有乱码部分被还原
        let garbled = "JP-\u{00e6}\u{0097}\u{00a5}\u{00e6}\u{009c}\u{00ac}";
        assert_eq!(fix_utf8_mojibake(garbled), "JP-日本");
    }

    #[test]
    fn percent_decode_plus_fix_mojibake() {
        // 模拟订阅链接中 #fragment 的 %XX 编码 UTF-8 中文
        let frag = "%E5%AE%B6%E5%AE%BD%E4%BC%98%E9%80%895";
        let decoded = urlencoding_decode(frag).unwrap();
        assert_eq!(fix_utf8_mojibake(&decoded), "家宽优选5");
    }

    #[test]
    fn parses_socks5_anonymous_and_query_auth() {
        let node = parse_line("socks5://5.6.7.8:1080#anon").unwrap().unwrap();
        assert!(node.get("username").is_none());
        assert!(node.get("password").is_none());

        let node2 = parse_line("socks5://5.6.7.8:1080?user=bob&pass=qp").unwrap().unwrap();
        assert_eq!(node2["username"], "bob");
        assert_eq!(node2["password"], "qp");
    }
}
