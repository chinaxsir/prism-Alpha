//! 全模块环形日志系统（APP6 任务1）。
//!
//! 统一记录 APP 内所有模块（GoLan / Kernel / GoAim / GoCus / Sub / Pro）
//! 的运行日志，供「设置 -> 运行日志」与「Go Lan 实时日志」面板展示。
//!
//! 设计：
//! - 内存 `VecDeque<LogEntry>` 环形缓冲，最多保留最近 800 条；
//! - 持久化文件 `data_dir/prism_app.log`：超过 512 KB 自动截断保留最新一半，
//!   绝不占用用户终端过多存储空间；
//! - `get_app_logs` 时自动合并 sing-box 内核日志（kernel.log）与 iOS
//!   App Group（group.com.prism.proxy）共享目录下的扩展诊断日志
//!   （prism_error.txt / prism_work/box.log / vpn_trace.log），
//!   含 `wireguard` / `go-lan-home` 字样的归入 GoLan 模块；
//! - 导出日志强制对 WireGuard 私钥、License Key 中间位做 `*` 脱敏。

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// 内存环形缓冲上限（条）
pub const MAX_ENTRIES: usize = 800;
/// 持久化文件容量上限：512 KB（524,288 字节）
pub const MAX_LOG_FILE_BYTES: u64 = 512 * 1024;

/// 模块名常量（前端筛选标签与后端埋点保持一致）
pub const MOD_GO_LAN: &str = "GoLan";
pub const MOD_KERNEL: &str = "Kernel";
pub const MOD_GO_AIM: &str = "GoAIM";
pub const MOD_GO_CUS: &str = "GoCus";
pub const MOD_SUB: &str = "Sub";
pub const MOD_PRO: &str = "Pro";
/// 【APP52 任务4】节点生命周期日志分类
pub const MOD_NODE: &str = "Node";
/// 【APP54 任务3】规则运行日志分类（规则汇总 / 模式切换 / 规则命中）
pub const MOD_RULE: &str = "Rule";
/// 【APP52 任务4】节点连接四阶段生命周期日志前缀（顺序固定，供日志检索）
pub const PHASE_NODE_IDENT: &str = "[节点识别]";
pub const PHASE_HANDSHAKE: &str = "[握手阶段]";
pub const PHASE_CONNECTED: &str = "[连接成功]";
pub const PHASE_FORWARDING: &str = "[流量开始转发]";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: u64,
    /// 格式: "YYYY-MM-DD HH:mm:ss.SSS"（本地时区）
    pub timestamp: String,
    /// "INFO" | "WARN" | "ERROR"
    pub level: String,
    /// "GoLan" | "Kernel" | "GoAIM" | "GoCus" | "Sub" | "Pro"
    pub module: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsPayload {
    pub entries: Vec<LogEntry>,
    /// 当前日志总占用（字节，含持久化文件与内存条目估算）
    pub total_bytes: usize,
}

struct LogState {
    seq: AtomicU64,
    entries: VecDeque<LogEntry>,
    /// 持久化文件路径（data_dir/prism_app.log；未 init 时为 None）
    file_path: Option<PathBuf>,
    /// 距上次磁盘容量检查累计写入条数（避免每条日志都 stat 文件）
    writes_since_check: u32,
}

static STATE: OnceLock<Mutex<LogState>> = OnceLock::new();

/// 【IPA9 任务1.2】最近一次「清空日志」的 Unix 毫秒时间戳。
/// 外部日志文件（kernel.log / iOS App Group box.log 等）由内核或网络扩展
/// 进程持有写入，主进程 truncate/remove_file 后扩展仍可能继续向旧 fd
/// 写入导致旧内容回弹。collect_kernel_and_extension_logs 读取外部文件时
/// 只采纳 mtime >= LAST_CLEARED 的内容，确保清空后历史日志不再复活。
static LAST_CLEARED_UNIX_MS: AtomicU64 = AtomicU64::new(0);

fn state() -> Option<&'static Mutex<LogState>> {
    STATE.get()
}

/// APP 启动时初始化（lib.rs setup 调用）：绑定持久化文件路径
pub fn init(data_dir: &std::path::Path) {
    let _ = STATE.set(Mutex::new(LogState {
        seq: AtomicU64::new(1),
        entries: VecDeque::with_capacity(MAX_ENTRIES),
        file_path: Some(data_dir.join("prism_app.log")),
        writes_since_check: 0,
    }));
}

/// 【APP54 任务3】北京时间字符串（UTC+8 固定偏移，格式 `YYYY-MM-DD HH:mm:ss.SSS`）。
/// 四端统一：无论系统处于哪个时区，日志时间戳一律为北京时间。
pub fn beijing_now_string() -> String {
    use time::macros::format_description;
    let fmt = format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
    );
    let bj = time::UtcOffset::from_hms(8, 0, 0).unwrap_or(time::UtcOffset::UTC);
    time::OffsetDateTime::now_utc()
        .to_offset(bj)
        .format(&fmt)
        .unwrap_or_else(|_| "0000-00-00 00:00:00.000".into())
}

/// 本地时间戳（北京时间）："YYYY-MM-DD HH:mm:ss.SSS"
fn now_timestamp() -> String {
    beijing_now_string()
}

/// 【APP56 任务4 / APP57 任务4】统一强制分类归属器：每条日志只能且必须
/// 归入唯一一个精准分类，且**绝不允许关键词猜测**：
/// - 调用方显式传入 7 个合法分类之一（Kernel / Node / Rule / GoAIM /
///   GoLan / GoCus / Sub）→ 直接采用，非法值一律归 Kernel；
/// - 传入 Kernel（典型为 sing-box 底层 stdout 日志）→ 只认**显式标签 / 前缀**：
///   `[节点识别]` `[握手阶段]` `[节点握手]` `[连接成功]` `[流量开始转发]`
///   `[测速]` / `outbound/<协议>` → Node；`[规则` `路由规则` `分流模式`
///   `规则命中` / `match rule` → Rule；`[GoAIM]` `GO-AIM-PROBE` → GoAIM；
///   `[GoLan]` `[GoLan-Ext]` `outbound/wireguard` → GoLan；`[GoCus]` → GoCus；
///   `[Sub]` → Sub；
/// - 其余（DNS / TUN / 路由表 / 进程启停等）一律 Kernel。
/// 关键修复：DNS 失败日志即使包含节点域名，也绝不会再被误归为 Node。
pub fn enforce_strict_log_category(raw_category: &str, message: &str) -> &'static str {
    let raw = raw_category.trim();
    // 1. 显式模块标签优先，且只接受 7 类合法值
    if raw.eq_ignore_ascii_case(MOD_NODE) {
        return MOD_NODE;
    }
    if raw.eq_ignore_ascii_case(MOD_RULE) {
        return MOD_RULE;
    }
    if raw.eq_ignore_ascii_case(MOD_GO_AIM) {
        return MOD_GO_AIM;
    }
    if raw.eq_ignore_ascii_case(MOD_GO_LAN) {
        return MOD_GO_LAN;
    }
    if raw.eq_ignore_ascii_case(MOD_GO_CUS) {
        return MOD_GO_CUS;
    }
    if raw.eq_ignore_ascii_case(MOD_SUB) {
        return MOD_SUB;
    }

    // 2. raw 为 Kernel / 未知：只按显式标签与前缀识别，禁止关键词劫持
    let lower = message.to_lowercase();
    let trimmed = message.trim_start();

    // Go Lan：显式模块标签与 WG 底层出站日志
    if lower.contains("[golan]")
        || lower.contains("[go lan]")
        || lower.contains("[golan-ext]")
        || lower.contains("outbound/wireguard")
        || trimmed.starts_with("go-lan-")
    {
        return MOD_GO_LAN;
    }
    // Go AIM：显式模块标签与探测通道标记
    if lower.contains("[goaim]")
        || lower.contains("[go aim]")
        || lower.contains("go-aim-probe")
        || lower.contains("aim-probe-in")
    {
        return MOD_GO_AIM;
    }
    // Go Cus：显式模块标签
    if lower.contains("[gocus]") || lower.contains("[go cus]") {
        return MOD_GO_CUS;
    }
    // 订阅：显式标签
    if lower.contains("[sub]") {
        return MOD_SUB;
    }
    // 规则：显式前缀 / 标签 / 内核路由匹配行
    if trimmed.starts_with("[规则")
        || lower.contains("[rule]")
        || trimmed.starts_with("路由规则")
        || trimmed.starts_with("分流模式")
        || trimmed.starts_with("规则命中")
        || lower.contains("match rule")
        || lower.contains("route(")
    {
        return MOD_RULE;
    }
    // 节点：仅节点生命周期显式前缀，或 outbound/<协议> 底层日志
    if trimmed.starts_with("[节点识别]")
        || trimmed.starts_with("[握手阶段]")
        || trimmed.starts_with("[节点握手]")
        || trimmed.starts_with("[连接成功]")
        || trimmed.starts_with("[流量开始转发]")
        || trimmed.starts_with("[测速]")
        || lower.contains("[node]")
        || trimmed.starts_with("outbound/vless")
        || trimmed.starts_with("outbound/trojan")
        || trimmed.starts_with("outbound/vmess")
        || trimmed.starts_with("outbound/shadowsocks")
        || trimmed.starts_with("outbound/hysteria")
        || trimmed.starts_with("outbound/tuic")
        || trimmed.starts_with("outbound/anytls")
        || trimmed.starts_with("outbound/socks")
    {
        return MOD_NODE;
    }

    // 3. Kernel（兜底：纯内核进程启停 / TUN 网卡 / DNS / 底层状态）
    MOD_KERNEL
}

/// 追加一条日志（内存环形缓冲 + 追加写持久化文件）
fn push_entry(level: &str, module: &str, message: &str) {
    // 单条消息截断到 2000 字符，防止异常刷屏吃满缓冲
    let message = if message.chars().count() > 2000 {
        message.chars().take(2000).collect::<String>()
    } else {
        message.to_string()
    };
    // 【APP56 任务4】写内存缓冲前强制归入唯一分类（严禁 Kernel 混装）
    let module = enforce_strict_log_category(module, &message);
    let entry = LogEntry {
        id: 0,
        timestamp: now_timestamp(),
        level: level.to_string(),
        module: module.to_string(),
        message,
    };

    let Some(mutex) = state() else { return };
    let Ok(mut st) = mutex.lock() else { return };
    let id = st.seq.fetch_add(1, Ordering::Relaxed);
    let mut entry = entry;
    entry.id = id;
    st.entries.push_back(entry.clone());
    while st.entries.len() > MAX_ENTRIES {
        st.entries.pop_front();
    }
    // 追加写磁盘（每 20 条做一次 512 KB 容量检查）
    st.writes_since_check += 1;
    if let Some(path) = st.file_path.clone() {
        let need_truncate = st.writes_since_check >= 20
            && std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > MAX_LOG_FILE_BYTES;
        if need_truncate {
            st.writes_since_check = 0;
            truncate_log_file(&path);
        }
        let line = format!(
            "[{}][{}][{}] {}\n",
            entry.timestamp, entry.level, entry.module, entry.message
        );
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// 超过 512 KB：截断保留最新一半（按行）
fn truncate_log_file(path: &std::path::Path) {
    let Ok(text) = std::fs::read_to_string(path) else { return };
    let lines: Vec<&str> = text.lines().collect();
    let keep_from = lines.len() / 2;
    let kept: String = lines[keep_from..].join("\n");
    let _ = std::fs::write(path, kept.as_bytes());
}

/// 各模块埋点入口（INFO）
pub fn info(module: &str, message: impl AsRef<str>) {
    push_entry("INFO", module, message.as_ref());
}

/// 各模块埋点入口（WARN）
pub fn warn(module: &str, message: impl AsRef<str>) {
    push_entry("WARN", module, message.as_ref());
}

/// 各模块埋点入口（ERROR）
pub fn error(module: &str, message: impl AsRef<str>) {
    push_entry("ERROR", module, message.as_ref());
}

/// 【APP55 任务5】外部日志行（sing-box kernel.log / iOS extension.log）→
/// 精确单一类别归属 + 剥离冗余前缀。严禁把 Go Lan / Go AIM / 规则 / 节点
/// 日志一律塞进 Kernel：
/// - [GoLan-Ext] / [GoLan] / go-lan- / outbound/wireguard → GoLan
/// - [GoAIM] / GO-AIM-PROBE / aim-probe-in → GoAim
/// - [GoCus] → GoCus
/// - [Rule] / route( / match rule → Rule
/// - [Node] / outbound/vless|trojan|vmess|shadowsocks|hysteria2|tuic → Node
/// - [Sub] → Sub
/// - 其余纯内核启停、DNS 与系统网卡日志 → Kernel
pub fn classify_external_log_line(raw_line: &str) -> (&'static str, String) {
    let lower = raw_line.to_lowercase();
    let module = if lower.contains("[golan-ext]")
        || lower.contains("[golan]")
        || lower.contains("go-lan-")
        || lower.contains("outbound/wireguard")
        || lower.contains("go-lan-home")
    {
        MOD_GO_LAN
    } else if lower.contains("[goaim]") || lower.contains("go-aim-probe") || lower.contains("aim-probe-in") {
        MOD_GO_AIM
    } else if lower.contains("[gocus]") {
        MOD_GO_CUS
    } else if lower.contains("[rule]") || lower.contains("route(") || lower.contains("match rule") {
        MOD_RULE
    } else if lower.contains("[node]")
        || lower.contains("outbound/vless")
        || lower.contains("outbound/trojan")
        || lower.contains("outbound/vmess")
        || lower.contains("outbound/shadowsocks")
        || lower.contains("outbound/hysteria2")
        || lower.contains("outbound/tuic")
    {
        MOD_NODE
    } else if lower.contains("[sub]") {
        MOD_SUB
    } else {
        MOD_KERNEL
    };
    // 【APP55 任务5】GoLan 扩展日志剥离 `[GoLan-Ext]` 前缀，正文更干净
    let message = if module == MOD_GO_LAN {
        let trimmed = raw_line.trim_start();
        match trimmed.get(..11) {
            Some(prefix) if prefix.eq_ignore_ascii_case("[GoLan-Ext]") => {
                trimmed[11..].trim_start().to_string()
            }
            _ => trimmed.to_string(),
        }
    } else {
        raw_line.trim().to_string()
    };
    (module, message)
}

/// 【APP11 任务5.2】解析 sing-box 内核日志行自带的时间戳。
/// 形如 `+0800 2026-10-27 14:23:11 ERROR [...]`，返回统一格式
/// `YYYY-MM-DD HH:MM:SS.mmm`（无则 None，调用方回退当前时间）。
fn parse_kernel_timestamp(line: &str) -> Option<String> {
    let b = line.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    while i + 19 <= n {
        let d = |k: usize| b[k].is_ascii_digit();
        if d(i)
            && d(i + 1)
            && d(i + 2)
            && d(i + 3)
            && b[i + 4] == b'-'
            && d(i + 5)
            && d(i + 6)
            && b[i + 7] == b'-'
            && d(i + 8)
            && d(i + 9)
            && (b[i + 10] == b' ' || b[i + 10] == b'T' || b[i + 10] == b't')
            && d(i + 11)
            && d(i + 12)
            && b[i + 13] == b':'
            && d(i + 14)
            && d(i + 15)
            && b[i + 16] == b':'
            && d(i + 17)
            && d(i + 18)
        {
            let base = &line[i..i + 19];
            // 【APP54 任务3】ISO/RFC3339 形式（如 sing-box `2025-11-06T12:34:56.789Z`）
            // 先按原时区解析，再强制转换为北京时间（UTC+8）。
            if i + 19 < n && (b[i + 10] == b'T' || b[i + 10] == b't') {
                let end = line[i..]
                    .find(|c: char| c == ' ' || c == ']' || c == '[')
                    .map(|k| i + k)
                    .unwrap_or(n);
                let raw = &line[i..end];
                if let Ok(dt) = time::OffsetDateTime::parse(
                    raw,
                    &time::format_description::well_known::Rfc3339,
                ) {
                    use time::macros::format_description;
                    let fmt = format_description!(
                        "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
                    );
                    let bj =
                        time::UtcOffset::from_hms(8, 0, 0).unwrap_or(time::UtcOffset::UTC);
                    if let Ok(s) = dt.to_offset(bj).format(&fmt) {
                        return Some(s);
                    }
                }
            }
            let mut ms = String::from("000");
            if i + 20 <= n && b[i + 19] == b'.' {
                let mut j = i + 20;
                let mut frac = String::new();
                while j < n && b[j].is_ascii_digit() && frac.len() < 3 {
                    frac.push(b[j] as char);
                    j += 1;
                }
                if !frac.is_empty() {
                    while frac.len() < 3 {
                        frac.push('0');
                    }
                    ms = frac;
                }
            }
            return Some(format!("{base}.{ms}"));
        }
        i += 1;
    }
    None
}

/// 【APP54 任务3】去掉日志行开头重复的时间戳前缀（时间戳已单独放在卡片右上角），
/// 支持 `YYYY-MM-DD HH:mm:ss[.fff]` 与 `YYYY-MM-DDTHH:mm:ss[.fff][Z|±hh:mm]`。
fn strip_leading_datetime(line: &str) -> &str {
    let b = line.as_bytes();
    if b.len() < 19 {
        return line;
    }
    let d = |k: usize| b[k].is_ascii_digit();
    let looks_like_date = d(0)
        && d(1)
        && d(2)
        && d(3)
        && b[4] == b'-'
        && d(5)
        && d(6)
        && b[7] == b'-'
        && d(8)
        && d(9)
        && (b[10] == b' ' || b[10] == b'T' || b[10] == b't')
        && d(11)
        && d(12)
        && b[13] == b':'
        && d(14)
        && d(15)
        && b[16] == b':'
        && d(17)
        && d(18);
    if !looks_like_date {
        return line;
    }
    let mut end = 19usize;
    if end < b.len() && b[end] == b'.' {
        end += 1;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
    }
    if end < b.len() && (b[end] == b'Z' || b[end] == b'z') {
        end += 1;
    } else if end + 5 < b.len()
        && (b[end] == b'+' || b[end] == b'-')
        && b[end + 3] == b':'
    {
        end += 6;
    }
    line[end..].trim_start()
}

/// 【APP11 任务5.2】解析扩展自写日志行开头的 10 位 Unix 秒级时间戳
/// （如 vpn_trace.log `1793015059 INFO [GoLan-Ext] ...`），转为本地
/// `YYYY-MM-DD HH:MM:SS.mmm`。
fn parse_leading_epoch(line: &str) -> Option<String> {
    let (head, _) = line.split_once(' ')?;
    if head.len() != 10 || !head.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let secs: i64 = head.parse().ok()?;
    use time::macros::format_description;
    let fmt =
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");
    let dt = time::OffsetDateTime::from_unix_timestamp(secs).ok()?;
    // 【APP53 任务4.1】内核日志转换统一北京时间（UTC+8）
    let bj = time::UtcOffset::from_hms(8, 0, 0).unwrap_or(time::UtcOffset::UTC);
    dt.to_offset(bj).format(&fmt).ok()
}

/// 把外部文本日志（内核 kernel.log / iOS 扩展诊断文件）按行合并为条目。
/// 【APP11 任务5.3】对连续完全相同的行去重，避免内核高频报错刷屏。
/// 【APP14 任务4】iOS NECP 沙盒下的 EPERM 刷屏噪声。
///
/// 典型样本（文本(1) 第 37、39 行）：
///   `listen outbound packet connection: operation not permitted`
///   `sing-box started (0ms)`
/// 这类条目每几秒重复一次，把真正有价值的 GoLan/代理日志淹没，且 0ms/1ms
/// 说明它发生在 Socket 创建阶段、对用户无任何可操作信息。仅当同时命中
/// 「operation not permitted / eperm」与「0ms|1ms」两个特征时才丢弃，
/// 避免误伤带真实耗时、可定位问题的 EPERM 报错。
fn is_noise_eperm_line(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    if !(l.contains("operation not permitted") || l.contains("eperm")) {
        return false;
    }
    has_tiny_ms_duration(&l)
}

/// 判断日志行里是否出现「恰好 0ms 或 1ms」的耗时（而非 1240ms / 2500ms）。
///
/// 直接 `contains("0ms")` 会误伤以 0 结尾的毫秒值（124**0ms**、250**0ms**），
/// 因此逐字符找出 `Nms` 里的整数 N，只有 N 的十进制字符串正好是 "0"/"1"
/// 才算命中（且数字前不能紧邻字母，避免误判 "s10ms" 之类）。
fn has_tiny_ms_duration(l: &str) -> bool {
    let bytes = l.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'm' && bytes[i + 1] == b's' {
            let mut j = i;
            while j > 0 && bytes[j - 1].is_ascii_digit() {
                j -= 1;
            }
            let digits = &bytes[j..i];
            if !digits.is_empty() {
                let preceded_by_letter = j > 0 && bytes[j - 1].is_ascii_alphabetic();
                if !preceded_by_letter && (digits == b"0" || digits == b"1") {
                    return true;
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    false
}

/// 【APP39 任务2.2】客户端正常关闭连接 / 策略拦截预期内的内核日志。
///
/// 这些条目并不代表故障，却因包含 error/eof 字样被误判为 ERROR 刷屏：
/// - `ws closed: 1005|1000`          WebSocket 客户端正常关闭
/// - `connection download/upload closed: unexpected EOF`  客户端提前断流
/// - `context canceled` / `use of closed network connection`  主动取消
/// - `... operation not permitted`   block 出站拦截 QUIC/DoT 的正常返回
/// - `report handshake success`      握手阶段回环探测失败（gvisor 下已消失）
fn is_benign_close_line(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    const BENIGN: &[&str] = &[
        "ws closed: 1005",
        "ws closed: 1000",
        "connection download closed: unexpected eof",
        "connection upload closed: unexpected eof",
        "context canceled",
        "use of closed network connection",
        "listen outbound packet connection: operation not permitted",
        "open outbound connection: operation not permitted",
        "report handshake success",
    ];
    BENIGN.iter().any(|p| l.contains(p))
}

fn merge_external_text(lines_text: &str, out: &mut Vec<LogEntry>, seq: &AtomicU64, max_lines: usize) {
    let mut count = 0usize;
    let mut last_key: Option<String> = None;
    for line in lines_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 【APP14 任务4】过滤 NECP 沙盒 EPERM 刷屏噪声
        if is_noise_eperm_line(line) {
            continue;
        }
        // 【APP39 任务2.2】过滤客户端正常关闭/策略拦截的非故障日志
        if is_benign_close_line(line) {
            continue;
        }
        // 【APP55 任务5】外部日志行精确归类（GoLan/GoAIM/GoCus/Rule/Node/Sub/Kernel）
        let (raw_module, classified) = classify_external_log_line(line);
        // 【APP56 任务4】再经强制分类器兜底，保证唯一分类
        let module = enforce_strict_log_category(raw_module, &classified);
        let lower = line.to_lowercase();
        let level = if lower.contains("error") || lower.contains("fatal") || lower.contains("失败") {
            "ERROR"
        } else if lower.contains("warn") {
            "WARN"
        } else {
            "INFO"
        };
        // 连续重复行去重
        let key = format!("{level}|{module}|{line}");
        if last_key.as_deref() == Some(key.as_str()) {
            continue;
        }
        last_key = Some(key);
        if count >= max_lines {
            break;
        }
        count += 1;
        // 【APP11 任务5.2】优先使用日志行自带时间戳（内核 + 扩展 epoch）
        let timestamp = parse_kernel_timestamp(line)
            .or_else(|| parse_leading_epoch(line))
            .unwrap_or_else(now_timestamp);
        out.push(LogEntry {
            id: seq.fetch_add(1, Ordering::Relaxed),
            timestamp,
            level: level.into(),
            module: module.into(),
            message: strip_leading_datetime(&classified).chars().take(500).collect(),
        });
    }
}

/// iOS App Group 共享目录（扩展诊断日志所在）；非 iOS 或拿不到时返回 None
#[cfg(target_os = "ios")]
fn ios_app_group_dir() -> Option<PathBuf> {
    crate::platform::ios::app_group_dir().map(PathBuf::from)
}

/// 判断外部日志文件是否在「最近一次清空」之后被修改过。
/// 外部进程（内核 / iOS 网络扩展）持有文件 fd，主进程 truncate 后扩展仍
/// 可能向旧 fd 写入旧内容；只采纳 mtime 晚于清空时刻的文件，避免旧日志回弹。
fn file_modified_after_clear(path: &std::path::Path) -> bool {
    let cleared = LAST_CLEARED_UNIX_MS.load(Ordering::Relaxed);
    if cleared == 0 {
        return true; // 从未清空过，正常读取
    }
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    mtime_ms >= cleared
}

/// 收集 sing-box 内核日志 + iOS 扩展诊断日志（合并进内存条目列表）
fn collect_kernel_and_extension_logs(
    data_dir: &std::path::Path,
    entries: &mut Vec<LogEntry>,
    seq: &AtomicU64,
) {
    // 1. 桌面端（含 Android）：sing-box 子进程日志 kernel.log
    {
        let kernel_log = data_dir.join("kernel").join("kernel.log");
        if file_modified_after_clear(&kernel_log) {
            if let Ok(text) = std::fs::read_to_string(&kernel_log) {
                // 只取末尾 200 行（前面是历史，环形日志只关心近期现场）
                let tail: Vec<&str> = text.lines().collect();
                let start = tail.len().saturating_sub(200);
                let joined = tail[start..].join("\n");
                merge_external_text(&joined, entries, seq, 200);
            }
        }
    }
    // 2. iOS：App Group 共享目录下的扩展诊断日志
    #[cfg(target_os = "ios")]
    if let Some(group) = ios_app_group_dir() {
        for name in ["prism_error.txt", "vpn_trace.log"] {
            let p = group.join(name);
            if file_modified_after_clear(&p) {
                if let Ok(text) = std::fs::read_to_string(&p) {
                    merge_external_text(&text, entries, seq, 100);
                }
            }
        }
        let box_log = group.join("prism_work").join("box.log");
        if file_modified_after_clear(&box_log) {
            if let Ok(text) = std::fs::read_to_string(&box_log) {
                let tail: Vec<&str> = text.lines().collect();
                let start = tail.len().saturating_sub(200);
                let joined = tail[start..].join("\n");
                merge_external_text(&joined, entries, seq, 200);
            }
        }
    }
}

/// 读取日志（module_filter: Some("GoLan") 等按模块过滤；None 返回全部）。
/// 自动合并内核日志与 iOS 扩展日志（外部来源排在内存条目之后）。
pub fn get_logs(data_dir: &std::path::Path, module_filter: Option<&str>) -> LogsPayload {
    let mut mem_entries: Vec<LogEntry> = Vec::new();
    let mut file_bytes = 0usize;
    let seq = AtomicU64::new(u64::MAX / 2); // 外部日志 id 从高位段分配，避免与内存条目冲突
    if let Some(mutex) = state()
        && let Ok(st) = mutex.lock()
    {
        for e in &st.entries {
            // 【APP56 任务4】返回前端前再统一归类，历史日志同样严格分区
            let mut entry = e.clone();
            entry.module =
                enforce_strict_log_category(&entry.module, &entry.message).to_string();
            let matched = module_filter
                .map(|f| entry.module == f)
                .unwrap_or(true);
            if matched {
                mem_entries.push(entry);
            }
        }
        if let Some(p) = &st.file_path {
            file_bytes = std::fs::metadata(p).map(|m| m.len() as usize).unwrap_or(0);
        }
        drop(st);
        let mut ext = Vec::new();
        collect_kernel_and_extension_logs(data_dir, &mut ext, &seq);
        for mut e in ext {
            // 【APP56 任务4】外部日志同样按唯一分类下发
            e.module = enforce_strict_log_category(&e.module, &e.message).to_string();
            let matched = module_filter
                .map(|f| e.module == f)
                .unwrap_or(true);
            if matched {
                mem_entries.push(e);
            }
        }
    }
    // 估算内存占用（每条 ≈ 时间戳 23 + 级别/模块 10 + 消息 UTF-8 字节）
    let mem_bytes: usize = mem_entries
        .iter()
        .map(|e| 33 + e.module.len() + e.message.len())
        .sum();
    LogsPayload {
        entries: mem_entries,
        total_bytes: file_bytes + mem_bytes,
    }
}

/// 清空全部日志：内存环形缓冲 + 删除本地 prism_app.log +
/// 清空内核 kernel.log + iOS 共享容器中的旧日志缓存
///
/// 【IPA9 任务1.2】同步设置 LAST_CLEARED_UNIX_MS，collect_kernel_and_extension_logs
/// 会据此过滤外部文件中清空时刻之前的旧内容，防止内核/扩展进程持有的旧 fd
/// 继续写入导致历史日志回弹。
pub fn clear_logs(data_dir: &std::path::Path) {
    // 先记录清空时刻（早于文件 truncate，确保 truncate 后产生的新内容
    // 的 mtime >= 此刻，能被正常读取）
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    LAST_CLEARED_UNIX_MS.store(now_ms, Ordering::Relaxed);

    if let Some(mutex) = state()
        && let Ok(mut st) = mutex.lock()
    {
        st.entries.clear();
        st.seq.store(1, Ordering::Relaxed);
        if let Some(p) = st.file_path.clone() {
            let _ = std::fs::write(&p, b"");
        }
    }
    // 内核日志截断
    let kernel_log = data_dir.join("kernel").join("kernel.log");
    if kernel_log.exists() {
        let _ = std::fs::write(&kernel_log, b"");
    }
    // iOS App Group 扩展诊断缓存清理
    #[cfg(target_os = "ios")]
    if let Some(group) = ios_app_group_dir() {
        let _ = std::fs::remove_file(group.join("prism_error.txt"));
        let _ = std::fs::remove_file(group.join("vpn_trace.log"));
        let _ = std::fs::remove_file(group.join("prism_work").join("box.log"));
    }
}

// ---------------------------------------------------------------- 导出脱敏

/// 把标准 44 位 Base64 WG 密钥（数据位 43 + '='）中间打星：
/// `QEFB...Cg==` 风格 → `QEFB****（32 字节密钥已脱敏）****`。
/// 只处理「前后都有非 base64 边界」的独立 token，避免误伤普通文本。
fn mask_wg_key(token: &str) -> Option<String> {
    let bytes = token.as_bytes();
    if bytes.len() != 44 || *bytes.last()? != b'=' {
        return None;
    }
    if !bytes[..43]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=')
    {
        return None;
    }
    // WG 密钥固定 44 位且第 44 字符是 '='；数据位只有末尾一个 '='
    if bytes[..43].iter().filter(|b| **b == b'=').count() != 0 {
        return None;
    }
    Some(format!("{}****[密钥已脱敏]****{}", &token[..6], &token[40..]))
}

/// License Key 脱敏：保留前 4 位与后 4 位，中间打星
fn mask_license_key(token: &str) -> Option<String> {
    if token.len() < 10 || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    // 排除普通单词/UUID 误伤：License Key 至少含一个 '-' 或为 16+ 位大写混合
    let has_dash = token.contains('-');
    let looks_key = token.chars().filter(|c| c.is_ascii_uppercase()).count() >= 6;
    if !has_dash && !looks_key {
        return None;
    }
    Some(format!("{}****{}", &token[..4], &token[token.len() - 4..]))
}

/// 对导出文本做敏感字段脱敏：WireGuard 私钥、License Key 中间位打 `*`
pub fn sanitize_sensitive(text: &str) -> String {
    use regex::Regex;
    // WG 密钥：private_key / privateKey / -密钥= 值，以及 wireguard:// 链接中的裸密钥
    let key_patterns = [
        r#"(?i)(private[_\s-]?key|peer[_\s-]?public[_\s-]?key|public[_\s-]?key|pre[_\s-]?shared[_\s-]?key)("?\s*[:=]\s*"?)([A-Za-z0-9+/]{43}=)"#,
    ];
    let mut out = text.to_string();
    for pat in key_patterns {
        if let Ok(re) = Regex::new(pat) {
            out = re
                .replace_all(&out, |caps: &regex::Captures| {
                    let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let sep = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let key = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let masked = mask_wg_key(key).unwrap_or_else(|| "*".repeat(44));
                    format!("{prefix}{sep}{masked}")
                })
                .into_owned();
        }
    }
    // License Key：license_key / licenseKey / 授权码 后跟的 token
    if let Ok(re) =
        Regex::new(r#"(?i)(license[_\s-]?key|授权码)("?\s*[:=]\s*"?)([A-Za-z0-9][A-Za-z0-9-]{9,})"#)
    {
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let sep = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let key = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                let masked = mask_license_key(key)
                    .unwrap_or_else(|| "*".repeat(key.len().min(44)));
                format!("{prefix}{sep}{masked}")
            })
            .into_owned();
    }
    // 兜底：文本中独立出现的 44 位 WG 密钥（wireguard:// 链接、裸密钥行）
    if let Ok(re) = Regex::new(r"([A-Za-z0-9+/]{43}=)") {
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                mask_wg_key(caps.get(1).map(|m| m.as_str()).unwrap_or(""))
                    .unwrap_or_else(|| caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string())
            })
            .into_owned();
    }
    out
}

/// 【APP57 任务3.2】安全截断：一律按 Unicode 字符边界截取，绝不按字节
/// 索引（如 `&s[..n]`）切片，中文 / emoji 内容永不 panic。
pub fn safe_truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars).collect();
    out.push('…');
    out
}

/// 生成带设备环境头信息的格式化纯文本日志全文（供前端复制 / 导出 .log）
pub fn export_logs(data_dir: &std::path::Path, module_filter: Option<&str>) -> String {
    let payload = get_logs(data_dir, module_filter);
    let mut out = String::new();
    out.push_str("================ Prism 诊断日志 ================\n");
    out.push_str(&format!(
        "App 版本: {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS
    ));
    out.push_str(&format!(
        "导出时间: {}\n",
        now_timestamp()
    ));
    if let Some(f) = module_filter {
        out.push_str(&format!("模块筛选: {f}\n"));
    }
    out.push_str(&format!(
        "日志条数: {}（占用约 {:.1} KB / 上限 512 KB）\n",
        payload.entries.len(),
        payload.total_bytes as f64 / 1024.0
    ));
    out.push_str("说明: WireGuard 密钥与 License Key 已自动脱敏\n");
    out.push_str("===============================================\n\n");
    // 【APP56 任务4】导出严格按 7 个分类分章节，彻底杜绝不同模块日志混杂
    const SECTIONS: &[(&str, &str)] = &[
        (MOD_KERNEL, "=== [内核 Kernel] ==="),
        (MOD_NODE, "=== [节点 Node] ==="),
        (MOD_RULE, "=== [规则 Rule] ==="),
        (MOD_GO_AIM, "=== [Go AIM] ==="),
        (MOD_GO_LAN, "=== [Go Lan] ==="),
        (MOD_GO_CUS, "=== [Go Cus] ==="),
        (MOD_SUB, "=== [订阅 Sub] ==="),
    ];
    for (module, title) in SECTIONS {
        if module_filter.is_some_and(|f| f != *module) {
            continue;
        }
        let rows: Vec<&LogEntry> = payload
            .entries
            .iter()
            .filter(|e| e.module == *module)
            .collect();
        out.push_str(title);
        out.push('\n');
        for e in rows {
            out.push_str(&format!(
                "[{}][{}][{}] {}\n",
                e.timestamp, e.level, e.module, sanitize_sensitive(&e.message)
            ));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        beijing_now_string, classify_external_log_line, enforce_strict_log_category,
        is_benign_close_line, is_noise_eperm_line, safe_truncate_str, strip_leading_datetime,
        MOD_GO_AIM, MOD_GO_CUS,
        MOD_GO_LAN, MOD_KERNEL, MOD_NODE, MOD_RULE, MOD_SUB, PHASE_CONNECTED, PHASE_FORWARDING,
        PHASE_HANDSHAKE, PHASE_NODE_IDENT,
    };

    /// 【APP57 任务4】强制分类器：显式模块优先；Kernel 底层日志只按显式
    /// 标签 / 前缀升级分类，DNS 行即使含节点域名也必须留在 Kernel。
    #[test]
    fn test_enforce_strict_log_category_isolated() {
        let cases: [(&str, &str, &str); 16] = [
            ("Kernel", "[测速] 节点测速完成，自动选择最低延迟节点", MOD_NODE),
            ("Kernel", "节点测速完成，自动选择最低延迟节点", MOD_KERNEL),
            ("Kernel", "dns: exchange failed: timeout for hk1.company-example.com", MOD_KERNEL),
            ("Kernel", "[规则] 命中 DOMAIN-SUFFIX,google.com,PROXY", MOD_RULE),
            ("Kernel", "[GoAIM] probe gpt unlocked", MOD_GO_AIM),
            ("Kernel", "[GoLan] 隧道握手完成 go-lan-home", MOD_GO_LAN),
            ("Kernel", "Go Lan 隧道握手完成 go-lan-home", MOD_KERNEL),
            ("Kernel", "[GoCus] 去广告模板已加载", MOD_GO_CUS),
            ("Kernel", "Go Cus 去广告模板已加载", MOD_KERNEL),
            ("Kernel", "[Sub] 订阅更新完成 18/20", MOD_SUB),
            ("Kernel", "start inbound/tun[tun-in]: create tun", MOD_KERNEL),
            ("GoAIM", "任意内容", MOD_GO_AIM),
            ("GoLan", "任意内容", MOD_GO_LAN),
            ("GoCus", "任意内容", MOD_GO_CUS),
            ("Node", "任意内容", MOD_NODE),
            ("Pro", "授权校验通过", MOD_KERNEL),
        ];
        let allowed = [
            MOD_KERNEL, MOD_NODE, MOD_RULE, MOD_GO_AIM, MOD_GO_LAN, MOD_GO_CUS, MOD_SUB,
        ];
        for (raw, message, want) in cases {
            let got = enforce_strict_log_category(raw, message);
            assert_eq!(got, want, "raw={raw} message={message}");
            assert!(allowed.contains(&got), "必须是唯一 7 分类之一");
        }
    }

    /// 【APP57 任务3.2】按字符截断：中文 / emoji 永不 panic、不产生半个字符
    #[test]
    fn test_safe_truncate_str_unicode() {
        assert_eq!(safe_truncate_str("中文中文中文", 2), "中文…");
        assert_eq!(safe_truncate_str("😀😀", 1), "😀…");
        assert_eq!(safe_truncate_str("abc", 5), "abc");
        assert_eq!(safe_truncate_str("", 0), "");
    }

    /// 【APP55 任务5】外部日志行必须精确落入单一类别，禁止一律归 Kernel
    #[test]
    fn test_classify_external_log_line_categories() {
        let cases = [
            ("[GoLan-Ext] 内网直连探测 10.10.10.253:8001 可达", MOD_GO_LAN),
            ("[GoLan] profile home bypass on local lan", MOD_GO_LAN),
            ("outbound/wireguard[home]: handshake complete", MOD_GO_LAN),
            ("[GoAIM] probe gpt unlocked", MOD_GO_AIM),
            ("GO-AIM-PROBE-IN: 已进入探测通道", MOD_GO_AIM),
            ("[GoCus] 模块已加载: AdBlock", MOD_GO_CUS),
            ("[Rule] 命中 DOMAIN-SUFFIX,google.com,PROXY", MOD_RULE),
            ("match rule: DOMAIN,www.apple.com,DIRECT", MOD_RULE),
            ("[Node] HK-01 握手成功 32ms", MOD_NODE),
            ("outbound/vless[HK1]: connected", MOD_NODE),
            ("outbound/hysteria2[US2]: connected", MOD_NODE),
            ("[Sub] 订阅更新完成 18/20", MOD_SUB),
            ("start inbound/tun[tun-in]: create tun", MOD_KERNEL),
            ("router: loaded 102 rules", MOD_KERNEL),
        ];
        for (line, want) in cases {
            assert_eq!(classify_external_log_line(line).0, want, "line={line}");
        }
        // GoLan 扩展前缀必须剥离，正文保留
        let (module, message) = classify_external_log_line("[GoLan-Ext] 直连 10.10.10.253:8001");
        assert_eq!(module, MOD_GO_LAN);
        assert_eq!(message, "直连 10.10.10.253:8001");
        // 普通中文行不得因按字节切片而 panic
        let (_, message) = classify_external_log_line("中文开头且足够长的普通内核日志行");
        assert_eq!(message, "中文开头且足够长的普通内核日志行");
    }

    /// 【APP39 任务2.2】正常关闭/策略拦截日志必须被识别并丢弃，不再显示 ERROR
    #[test]
    fn test_benign_close_filtered() {
        assert!(is_benign_close_line(
            "connection download closed: unexpected EOF: io: read/write on closed pipe"
        ));
        assert!(is_benign_close_line("websocket: ws closed: 1005"));
        assert!(is_benign_close_line(
            "open outbound connection: operation not permitted"
        ));
        assert!(is_benign_close_line(
            "connection: report handshake success: connection refused"
        ));
        assert!(is_benign_close_line("context canceled"));
    }

    /// 真实故障绝不能误伤
    #[test]
    fn test_benign_close_not_overfiltered() {
        assert!(!is_benign_close_line("outbound/vless[HK1]: EOF"));
        assert!(!is_benign_close_line(
            "start inbound/tun[tun-in]: create tun: operation not permitted"
        ));
        assert!(!is_benign_close_line("go-lan-home: dial udp i/o timeout"));
    }

    /// 【APP14 任务4】NECP 沙盒 EPERM 刷屏噪声必须被识别并丢弃
    #[test]
    fn test_noise_eperm_detected() {
        assert!(is_noise_eperm_line(
            "listen outbound packet connection: operation not permitted (0ms)"
        ));
        assert!(is_noise_eperm_line(
            "sing-box: listen tcp 127.0.0.1:2080: operation not permitted 1ms"
        ));
    }

    /// 带真实耗时或与 EPERM 无关的日志绝不能误伤
    #[test]
    fn test_noise_eperm_not_overfiltered() {
        assert!(!is_noise_eperm_line(
            "go-lan-home: dial udp 14.105.65.122:51820: operation not permitted (1240ms)"
        ));
        assert!(!is_noise_eperm_line("sing-box started (0ms)"));
        assert!(!is_noise_eperm_line(
            "✅ 内网检测成功: 已到达 10.1.8.1:5000（端口开放，延迟 12 ms）"
        ));
    }

    /// 【APP52 任务4】四阶段日志前缀必须齐全、互不重复且分类为 Node
    #[test]
    fn test_four_phase_logs_complete() {
        let phases = [
            PHASE_NODE_IDENT,
            PHASE_HANDSHAKE,
            PHASE_CONNECTED,
            PHASE_FORWARDING,
        ];
        for p in phases {
            assert!(!p.is_empty());
            assert!(p.starts_with('[') && p.ends_with(']'));
        }
        let unique: std::collections::HashSet<_> = phases.iter().collect();
        assert_eq!(unique.len(), 4, "四阶段前缀必须唯一");
        assert_eq!(MOD_NODE, "Node");
        assert_eq!(MOD_RULE, "Rule", "规则运行日志必须归类为 Rule");
    }

    /// 【APP54 任务3】北京时间戳格式 + 去重旧前缀
    #[test]
    fn test_beijing_now_string_and_strip_prefix() {
        let s = beijing_now_string();
        assert_eq!(s.len(), 23, "格式 YYYY-MM-DD HH:mm:ss.SSS");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], " ");
        assert_eq!(&s[13..14], ":");
        assert_eq!(&s[16..17], ":");
        assert_eq!(&s[19..20], ".");
        // 固定 UTC+8：与 UTC 时间相差 8 小时（按分钟对比，规避秒级抖动）
        let bj = time::OffsetDateTime::now_utc().to_offset(
            time::UtcOffset::from_hms(8, 0, 0).unwrap_or(time::UtcOffset::UTC),
        );
        let expect = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            bj.year(),
            u8::from(bj.month()),
            bj.day(),
            bj.hour(),
            bj.minute()
        );
        assert!(s.starts_with(&expect), "must be UTC+8: {s} vs {expect}");

        // 卡片时间戳单独展示 → 正文必须剥掉重复前缀
        assert_eq!(
            strip_leading_datetime("2026-11-06 20:30:59.123 INFO hello"),
            "INFO hello"
        );
        assert_eq!(
            strip_leading_datetime("2026-11-06T12:30:59.123Z INFO hello"),
            "INFO hello"
        );
        assert_eq!(strip_leading_datetime("plain message"), "plain message");
    }
}
