//! 内核事件流订阅
//!
//! Rust 作为 WebSocket 客户端连接内核的 Clash API 数据流，
//! 将消息原样转为 Tauri 事件推送给前端：
//!
//!   ws://{api}/traffic     → "traffic://tick"     { up, down }
//!   ws://{api}/connections → "connections://tick" { downloadTotal, uploadTotal, connections: [...] }
//!   ws://{api}/memory      → "memory://tick"      { inuse, ... }
//!
//! 除原样转发外，收到消息时还会把实时流量/连接/聚合分析写入 AppState
//! （供 get_runtime_snapshot IPC 使用）——所有更新都在同步段完成，
//! 绝不跨 await 持有 parking_lot 守卫（守卫非 Send）。
//!
//! spawn_all 返回所有订阅任务的 JoinHandle，内核停止时必须 abort，
//! 否则重连循环永不退出，stop/start 后订阅者翻倍导致事件重复。

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use futures_util::StreamExt;
use tauri::{AppHandle, Emitter, Manager};
use tokio::task::JoinHandle;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, HeaderValue};
use tokio_tungstenite::tungstenite::Message;

use super::state::{AppState, AggStat, ConnSnapshot, OutboundMode, TrafficSample};

/// 60 秒实时流量环形队列容量
const TRAFFIC_HISTORY_CAP: usize = 60;

/// 活跃 / 近期连接池容量（超出时优先淘汰最旧的已关闭连接）
const CONN_POOL_CAP: usize = 300;

/// 启动全部内核事件流订阅，返回任务句柄（调用方在停止内核时 abort）
pub fn spawn_all(
    api_addr: &str,
    api_secret: &str,
    app: AppHandle,
) -> Vec<JoinHandle<()>> {
    vec![
        spawn_stream(api_addr, api_secret, "/traffic", "traffic://tick", app.clone()),
        spawn_stream(api_addr, api_secret, "/connections", "connections://tick", app.clone()),
        spawn_stream(api_addr, api_secret, "/memory", "memory://tick", app),
    ]
}

fn spawn_stream(
    api_addr: &str,
    api_secret: &str,
    path: &'static str,
    event_name: &'static str,
    app: AppHandle,
) -> JoinHandle<()> {
    let url = format!("ws://{api_addr}{path}");
    let api_secret = api_secret.to_string();

    tokio::spawn(async move {
        // 断线自动重连
        loop {
            // 构造带 Bearer 鉴权头的 WS 请求（clash_api 配置了 secret 时必须携带）
            let connect = async {
                let mut request = url.as_str().into_client_request()?;
                if !api_secret.is_empty()
                    && let Ok(value) = HeaderValue::from_str(&format!("Bearer {api_secret}"))
                {
                    request.headers_mut().insert(AUTHORIZATION, value);
                }
                connect_async(request).await
            };

            match connect.await {
                Ok((ws, _)) => {
                    tracing::info!("subscribed kernel stream: {}", path);
                    let (_, mut read) = ws.split();

                    while let Some(Ok(msg)) = read.next().await {
                        if let Message::Text(text) = msg
                            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
                        {
                            // 前后台感知：后台（锁屏/切 App）时只维护累计总量，
                            // 不做连接聚合、不向 WebView 发事件，主 App 静默零耗电；
                            // 扩展内核仍在底层继续走流量，切回前台数据无缝续接
                            let foreground = app
                                .state::<AppState>()
                                .app_in_foreground
                                .load(Ordering::Relaxed);
                            apply_metrics(&app, path, &value, foreground);
                            if foreground && app.emit(event_name, value).is_err() {
                                tracing::debug!("emit {} failed (no listeners)", event_name);
                            }
                        }
                    }
                    tracing::warn!("kernel stream closed: {}", path);
                }
                Err(e) => {
                    tracing::debug!("subscribe {} failed: {}", path, e);
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
}

/// 按数据流类型更新 AppState 运行时统计（/memory 不做处理）
fn apply_metrics(app: &AppHandle, path: &str, value: &serde_json::Value, foreground: bool) {
    let state = app.state::<AppState>();
    match path {
        "/traffic" => apply_traffic_update(&state, value),
        "/connections" => apply_connections_update(&state, value, foreground),
        _ => {}
    }
}

/// /traffic：把本轮 up/down（字节/秒）推入 60 秒环形队列
fn apply_traffic_update(state: &AppState, value: &serde_json::Value) {
    let up = value.get("up").and_then(|v| v.as_u64()).unwrap_or(0);
    let down = value.get("down").and_then(|v| v.as_u64()).unwrap_or(0);
    let mut hist = state.traffic_history.write();
    while hist.len() >= TRAFFIC_HISTORY_CAP {
        hist.pop_front();
    }
    hist.push_back(TrafficSample {
        time: local_hhmmss(),
        up,
        down,
    });
}

/// /connections：更新当前会话绝对累计值（落盘）、活跃连接快照、按维度聚合分析
/// 【APP51 任务3】按连接 chains（不是 outbound）判定分流类别：
/// 含 go-lan → 内网；DIRECT / dns-direct → 直连；REJECT / block → 拦截；其余 → 代理。
/// 拦截流量单独统计并排除在三分占比之外（不展示、不污染分母）。
#[derive(Debug, PartialEq)]
enum RouteCategory {
    Proxy,
    Direct,
    Lan,
    Block,
}

fn route_category(chains: &[String]) -> RouteCategory {
    let mut has_direct = false;
    for c in chains {
        let n = c.trim().to_ascii_lowercase();
        if n.contains("go-lan") || n == "golan" {
            return RouteCategory::Lan;
        }
        if n == "reject" || n == "block" || n.contains("reject") {
            return RouteCategory::Block;
        }
        if n == "direct" || n == "dns-direct" || n.contains("dns-direct") {
            has_direct = true;
        }
    }
    if has_direct {
        RouteCategory::Direct
    } else {
        RouteCategory::Proxy
    }
}

/// 【APP51 任务3】未归类差额按路由模式摊入三分：
/// 直连模式全给 direct；全局模式全给 proxy；规则模式按 80% / 20% 分摊。
/// 提取为纯函数便于单测，保证三项之和永远等于内核总量。
fn allocate_untracked(mode: &OutboundMode, untracked: u64) -> (u64, u64) {
    match mode {
        OutboundMode::Direct => (0, untracked),
        OutboundMode::Global => (untracked, 0),
        OutboundMode::Rule => {
            let proxy = untracked.saturating_mul(4) / 5;
            (proxy, untracked.saturating_sub(proxy))
        }
    }
}

/// 【APP54 任务3】规则命中日志去重（进程内单例集合，最多 500 条）。
fn log_rule_hit_dedupe(rule: &str, payload: &str) {
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
    let Ok(mut set) = seen.lock() else { return };
    if set.len() >= 500 {
        return;
    }
    let key = format!("{rule}|{payload}");
    if !set.insert(key) {
        return;
    }
    super::logger::info(
        super::logger::MOD_RULE,
        &format!("规则命中: {rule} {payload}"),
    );
}

fn apply_connections_update(state: &AppState, value: &serde_json::Value, foreground: bool) {
    let download_total = value
        .get("downloadTotal")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let upload_total = value
        .get("uploadTotal")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let session_total = download_total.saturating_add(upload_total);

    // 1) 当前会话绝对累计值落盘 + 今日流量缓存刷新（重启后今日流量不丢）
    if let Err(e) = super::store::set_current_session(&state.data_dir, session_total) {
        tracing::debug!("更新当前会话流量失败: {e}");
    }
    *state.today_bytes_cache.write() = super::store::today_total_bytes(&state.data_dir);

    // 2) 后台时到此为止：连接池与聚合分析没有 UI 消费方，
    //    纯属浪费 CPU/功耗（这也是锁屏耗电的主要来源之一）
    if !foreground {
        return;
    }

    // 3) 解析本帧连接快照（id → ConnSnapshot）
    let mut incoming: HashMap<String, ConnSnapshot> = HashMap::new();
    if let Some(arr) = value.get("connections").and_then(|v| v.as_array()) {
        for c in arr {
            let id = c
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if id.is_empty() {
                continue;
            }
            let meta = c.get("metadata");
            let meta_str = |key: &str| {
                meta.and_then(|m| m.get(key))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string()
            };
            let destination_ip = meta_str("destinationIP");
            let host = {
                let h = meta_str("host");
                if !h.is_empty() {
                    h
                } else if !destination_ip.is_empty() {
                    destination_ip.clone()
                } else {
                    "未知".to_string()
                }
            };
            let chains: Vec<String> = c
                .get("chains")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            // 【APP48 任务4】隐身过滤：prism.sarl 及其 DoH 解析出的 IP
            // 一律不进连接列表、不进 ip→domain 缓存、不进聚合分析，
            // 防止用户/第三方从「连接」「分析 Top 主机」反推授权服务并恶意阻断。
            if super::license::is_stealth_protected_host_or_ip(&host)
                || super::license::is_stealth_protected_host_or_ip(&destination_ip)
                || super::license::is_stealth_protected_host_or_ip(&meta_str(
                    "rulePayload",
                ))
            {
                continue;
            }
            incoming.insert(
                id.clone(),
                ConnSnapshot {
                    id,
                    host,
                    destination_ip,
                    source_ip: meta_str("sourceIP"),
                    source_port: meta_str("sourcePort"),
                    destination_port: meta_str("destinationPort"),
                    network: meta_str("network"),
                    upload: c.get("upload").and_then(|v| v.as_u64()).unwrap_or(0),
                    download: c.get("download").and_then(|v| v.as_u64()).unwrap_or(0),
                    chains,
                    rule: c
                        .get("rule")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    rule_payload: c
                        .get("rulePayload")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    start: c
                        .get("start")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    active: true,
                    seq: 0,
                },
            );
        }
    }

    // 【APP54 任务3】规则命中日志（去重：同一 rule+payload 仅记录一次，
    // 上限 500 条，避免高频连接把环形日志刷满）
    for conn in incoming.values() {
        if conn.rule.is_empty() && conn.rule_payload.is_empty() {
            continue;
        }
        log_rule_hit_dedupe(&conn.rule, &conn.rule_payload);
    }

    // 3) 增量聚合（host / outbound / rule）：与 last_seen 上次值求差累加；
    //    新 id 视为 count+1，随后刷新 last_seen（已消失的从 last_seen 移除）
    {
        let mut agg = state.analytics.write();
        // 【APP51 任务3】本帧三分累加量 + 拦截量，用于总量差额兜底
        let mut proxy_inc = 0u64;
        let mut direct_inc = 0u64;
        let mut lan_inc = 0u64;
        let mut blocked_inc = 0u64;
        for (id, conn) in &incoming {
            let prev = agg.last_seen.get(id).copied();
            let (prev_up, prev_down) = prev.unwrap_or((0, 0));
            let inc_up = conn.upload.saturating_sub(prev_up);
            let inc_down = conn.download.saturating_sub(prev_down);
            let is_new = prev.is_none();
            let inc_total = inc_up.saturating_add(inc_down);

            // 【APP51 任务3】按 chains 归类累加三分字节
            match route_category(&conn.chains) {
                RouteCategory::Proxy => proxy_inc += inc_total,
                RouteCategory::Direct => direct_inc += inc_total,
                RouteCategory::Lan => lan_inc += inc_total,
                RouteCategory::Block => blocked_inc += inc_total,
            }

            let host_key = if conn.host.is_empty() {
                "未知".to_string()
            } else {
                conn.host.clone()
            };
            let outbound_key = conn
                .chains
                .first()
                .cloned()
                .unwrap_or_else(|| "DIRECT".to_string());
            let rule_key = {
                let joined = format!("{} {}", conn.rule, conn.rule_payload);
                let trimmed = joined.trim();
                if trimmed.is_empty() {
                    "其他".to_string()
                } else {
                    trimmed.to_string()
                }
            };

            accumulate(&mut agg.hosts, host_key, inc_up, inc_down, is_new);
            accumulate(&mut agg.outbounds, outbound_key, inc_up, inc_down, is_new);
            accumulate(&mut agg.rules, rule_key, inc_up, inc_down, is_new);

            // 【APP49 任务4】按传输协议（metadata.network）分别计数，
            // 归一为大写 TCP / UDP；未知协议不入聚合
            let proto_key = match conn.network.to_ascii_lowercase().as_str() {
                "tcp" => "TCP",
                "udp" => "UDP",
                _ => "",
            };
            if !proto_key.is_empty() {
                accumulate(
                    &mut agg.protocols,
                    proto_key.to_string(),
                    inc_up,
                    inc_down,
                    is_new,
                );
            }

            // 【APP39 任务3】域名 / IP 双聚合 + IP→域名 反向缓存：
            // 1) host 为真实域名时立刻写入缓存，后续同 IP 无域名连接可补齐；
            // 2) ips 严格按目标 IP（纯 IP，绝不混入域名）；
            // 3) domains 只收录能解析出有效域名的条目。
            if !conn.host.is_empty()
                && !is_ip_literal(&conn.host)
                && is_ip_literal(&conn.destination_ip)
            {
                agg.ip_to_domain
                    .insert(conn.destination_ip.clone(), conn.host.clone());
            }
            if !conn.destination_ip.is_empty() && is_ip_literal(&conn.destination_ip) {
                accumulate(
                    &mut agg.ips,
                    conn.destination_ip.clone(),
                    inc_up,
                    inc_down,
                    is_new,
                );
            }
            if let Some(domain) = resolve_domain(
                &conn.host,
                &conn.destination_ip,
                &conn.rule_payload,
                &agg.ip_to_domain,
            ) {
                accumulate(&mut agg.domains, domain, inc_up, inc_down, is_new);
            }
        }
        // 【APP51 任务3】差额兜底：内核总量 - 已归类量 = 未归类（隐身过滤/已关闭连接等），
        // 按当前路由模式补入三分累计，保证占比永远有数据、三项之和接近内核总量。
        let tagged = proxy_inc
            .saturating_add(direct_inc)
            .saturating_add(lan_inc)
            .saturating_add(blocked_inc);
        let total_inc = download_total
            .saturating_sub(agg.last_total_down)
            .saturating_add(upload_total.saturating_sub(agg.last_total_up));
        let untracked = total_inc.saturating_sub(tagged);
        let (to_proxy, to_direct) = allocate_untracked(&state.settings.read().outbound_mode, untracked);
        proxy_inc = proxy_inc.saturating_add(to_proxy);
        direct_inc = direct_inc.saturating_add(to_direct);
        agg.proxy_bytes = agg.proxy_bytes.saturating_add(proxy_inc);
        agg.direct_bytes = agg.direct_bytes.saturating_add(direct_inc);
        agg.lan_bytes = agg.lan_bytes.saturating_add(lan_inc);
        agg.last_total_down = download_total;
        agg.last_total_up = upload_total;

        agg.last_seen.retain(|id, _| incoming.contains_key(id));
        for (id, conn) in &incoming {
            agg.last_seen.insert(id.clone(), (conn.upload, conn.download));
        }
    }

    // 4) 合并进「活跃 / 近期连接池」：本帧仍在的连接更新为活跃；本帧消失的
    //    保留但标记 active=false（近期历史，供连接页展示）；超容量时优先淘汰
    //    最旧的已关闭项
    let live_ids: std::collections::HashSet<String> = incoming.keys().cloned().collect();
    {
        let mut pool = state.connections_live.write();
        for (id, conn) in incoming {
            match pool.get_mut(&id) {
                Some(existing) => {
                    // 保留首次分配的 seq，其余字段刷新为最新帧
                    let seq = existing.seq;
                    *existing = conn;
                    existing.seq = seq;
                    existing.active = true;
                }
                None => {
                    let seq = state.next_conn_seq();
                    let mut snap = conn;
                    snap.seq = seq;
                    pool.insert(id, snap);
                }
            }
        }
        for (id, c) in pool.iter_mut() {
            if !live_ids.contains(id) {
                c.active = false;
            }
        }
        if pool.len() > CONN_POOL_CAP {
            let mut closed: Vec<(u64, String)> = pool
                .iter()
                .filter(|(_, c)| !c.active)
                .map(|(id, c)| (c.seq, id.clone()))
                .collect();
            closed.sort_by_key(|(seq, _)| *seq);
            let mut over = pool.len() - CONN_POOL_CAP;
            for (_, id) in closed {
                if over == 0 {
                    break;
                }
                pool.remove(&id);
                over -= 1;
            }
        }
    }
}

/// 向聚合 map 累加一次增量；新连接（本帧首次出现）额外 count+1
fn accumulate(map: &mut HashMap<String, AggStat>, key: String, up: u64, down: u64, is_new: bool) {
    let entry = map.entry(key).or_default();
    if is_new {
        entry.count = entry.count.saturating_add(1);
    }
    entry.up = entry.up.saturating_add(up);
    entry.down = entry.down.saturating_add(down);
}

// ---------------------------------------------------------------- 【APP39 任务3】

/// 判断字符串是否为纯 IP 字面量（IPv4 或 IPv6）。
/// IPv6 允许携带 `%` 区段后缀（如 `fe80::1%en0`）。
fn is_ip_literal(s: &str) -> bool {
    let core = s.split('%').next().unwrap_or(s);
    core.parse::<std::net::IpAddr>().is_ok()
}

/// 判断规则载荷是否像域名后缀（不含 `/`、含字母、非 IP）。
fn looks_like_domain_suffix(s: &str) -> bool {
    !s.is_empty()
        && !s.contains('/')
        && !is_ip_literal(s)
        && s.chars().any(|c| c.is_ascii_alphabetic())
}

/// 【APP39 任务3】内置常用 IP → 域名映射：没有任何嗅探/规则信息时，
/// 域名视图也能显示可读名字而不是纯 IP。
fn builtin_ip_domain(ip: &str) -> Option<&'static str> {
    match ip {
        "8.8.8.8" | "8.8.4.4" => Some("dns.google"),
        "1.1.1.1" | "1.0.0.1" => Some("one.one.one.one"),
        "223.5.5.5" | "223.6.6.6" => Some("dns.alidns.com"),
        "119.29.29.29" => Some("dns.pub"),
        "192.168.10.253" => Some("fnos-nas.lan"),
        "192.168.10.100" => Some("rdp-pc.lan"),
        _ => None,
    }
}

/// 【APP39 任务3】解析一条连接的有效域名（优先级：
/// 1. metadata.host（嗅探出的真实域名，非 IP 字面量）
/// 2. ip_to_domain 反向缓存
/// 3. rulePayload 域名后缀（如 `youtube.com`）
/// 4. 内置常用 IP 映射表
/// 5. 无 → 返回 None（该连接只进 IP 聚合）
fn resolve_domain(
    host: &str,
    destination_ip: &str,
    rule_payload: &str,
    cache: &HashMap<String, String>,
) -> Option<String> {
    if !host.is_empty() && !is_ip_literal(host) {
        return Some(host.to_string());
    }
    if !destination_ip.is_empty()
        && let Some(d) = cache.get(destination_ip)
    {
        return Some(d.clone());
    }
    if looks_like_domain_suffix(rule_payload) {
        return Some(rule_payload.to_string());
    }
    if !destination_ip.is_empty()
        && let Some(d) = builtin_ip_domain(destination_ip)
    {
        return Some(d.to_string());
    }
    None
}

/// 当前时间 HH:MM:SS（不引入 chrono：以 Unix 秒换算，仅用于曲线刻度）
fn local_hhmmss() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let day = secs % 86400;
    format!("{:02}:{:02}:{:02}", day / 3600, day % 3600 / 60, day % 60)
}

#[cfg(test)]
mod tests {
    use super::{
        allocate_untracked, builtin_ip_domain, is_ip_literal, looks_like_domain_suffix,
        resolve_domain, route_category, OutboundMode, RouteCategory,
    };
    use std::collections::HashMap;

    /// 【APP39 任务3】域名解析优先级：嗅探 host > 反向缓存 > 规则后缀 > 内置映射
    #[test]
    fn test_resolve_domain_priority() {
        let mut cache = HashMap::new();
        cache.insert("142.250.199.142".to_string(), "www.youtube.com".to_string());

        // 1. 真实嗅探域名优先
        assert_eq!(
            resolve_domain("chatgpt.com", "1.2.3.4", "", &cache).as_deref(),
            Some("chatgpt.com")
        );
        // 2. host 为 IP（无嗅探结果）时走反向缓存
        assert_eq!(
            resolve_domain("142.250.199.142", "142.250.199.142", "", &cache).as_deref(),
            Some("www.youtube.com")
        );
        // 3. 缓存未命中时用域名后缀规则载荷
        assert_eq!(
            resolve_domain("", "1.2.3.4", "icloud.com", &cache).as_deref(),
            Some("icloud.com")
        );
        // 4. 内置常用 IP 映射
        assert_eq!(
            resolve_domain("", "192.168.10.253", "", &cache).as_deref(),
            Some("fnos-nas.lan")
        );
        // 5. 完全无信息 → None（该连接只进 IP 聚合）
        assert_eq!(resolve_domain("", "203.0.113.9", "", &cache), None);
    }

    #[test]
    fn test_ip_literal_and_domain_suffix() {
        assert!(is_ip_literal("142.250.199.142"));
        assert!(is_ip_literal("::1"));
        assert!(!is_ip_literal("www.youtube.com"));

        assert!(looks_like_domain_suffix("youtube.com"));
        assert!(!looks_like_domain_suffix("10.0.0.0/8"));
        assert!(!looks_like_domain_suffix("142.250.199.142"));
        assert_eq!(builtin_ip_domain("119.29.29.29"), Some("dns.pub"));
    }

    /// 【APP51 任务3】连接 chains 分流分类：go-lan / direct / reject / 其余代理
    #[test]
    fn test_route_category_from_chains() {
        let chains = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            route_category(&chains(&["go-lan-home", "节点选择"])),
            RouteCategory::Lan
        );
        assert_eq!(
            route_category(&chains(&["DIRECT"])),
            RouteCategory::Direct
        );
        assert_eq!(
            route_category(&chains(&["节点", "dns-direct"])),
            RouteCategory::Direct
        );
        assert_eq!(
            route_category(&chains(&["REJECT"])),
            RouteCategory::Block
        );
        // 普通代理链：首个出站即节点名，未命中以上规则 → proxy
        assert_eq!(
            route_category(&chains(&["香港01", "节点选择"])),
            RouteCategory::Proxy
        );
    }

    /// 【APP51 任务3】未归类差额按路由模式摊入：三项之和必须恒等于差额
    #[test]
    fn test_allocate_untracked_by_mode() {
        assert_eq!(allocate_untracked(&OutboundMode::Direct, 1000), (0, 1000));
        assert_eq!(allocate_untracked(&OutboundMode::Global, 1000), (1000, 0));
        let (p, d) = allocate_untracked(&OutboundMode::Rule, 1000);
        assert_eq!(p + d, 1000);
        assert_eq!((p, d), (800, 200));
        // 差额为 0（全部连接已归类）时不产生任何额外分摊
        assert_eq!(allocate_untracked(&OutboundMode::Rule, 0), (0, 0));
    }
}
