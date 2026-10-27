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
pub const MOD_GO_AIM: &str = "GoAim";
pub const MOD_GO_CUS: &str = "GoCus";
pub const MOD_SUB: &str = "Sub";
pub const MOD_PRO: &str = "Pro";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: u64,
    /// 格式: "YYYY-MM-DD HH:mm:ss.SSS"（本地时区）
    pub timestamp: String,
    /// "INFO" | "WARN" | "ERROR"
    pub level: String,
    /// "GoLan" | "Kernel" | "GoAim" | "GoCus" | "Sub" | "Pro"
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

/// 本地时间戳："YYYY-MM-DD HH:mm:ss.SSS"；取不到本地时区时回退 UTC
fn now_timestamp() -> String {
    use time::macros::format_description;
    let fmt = format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
    );
    let dt = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    dt.format(&fmt).unwrap_or_else(|_| "0000-00-00 00:00:00.000".into())
}

/// 追加一条日志（内存环形缓冲 + 追加写持久化文件）
fn push_entry(level: &str, module: &str, message: &str) {
    // 单条消息截断到 2000 字符，防止异常刷屏吃满缓冲
    let message = if message.chars().count() > 2000 {
        message.chars().take(2000).collect::<String>()
    } else {
        message.to_string()
    };
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

/// 内核/扩展日志行 → 模块归类：含 wireguard / go-lan-home 归 GoLan，其余 Kernel
fn classify_kernel_line(line: &str) -> &'static str {
    let lower = line.to_lowercase();
    if lower.contains("wireguard") || lower.contains("go-lan-home") {
        MOD_GO_LAN
    } else {
        MOD_KERNEL
    }
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
            && b[i + 10] == b' '
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
    let off = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
    dt.to_offset(off).format(&fmt).ok()
}

/// 把外部文本日志（内核 kernel.log / iOS 扩展诊断文件）按行合并为条目。
/// 【APP11 任务5.3】对连续完全相同的行去重，避免内核高频报错刷屏。
fn merge_external_text(lines_text: &str, out: &mut Vec<LogEntry>, seq: &AtomicU64, max_lines: usize) {
    let mut count = 0usize;
    let mut last_key: Option<String> = None;
    for line in lines_text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let module = classify_kernel_line(line);
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
            message: line.chars().take(500).collect(),
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
            let matched = module_filter
                .map(|f| e.module == f)
                .unwrap_or(true);
            if matched {
                mem_entries.push(e.clone());
            }
        }
        if let Some(p) = &st.file_path {
            file_bytes = std::fs::metadata(p).map(|m| m.len() as usize).unwrap_or(0);
        }
        drop(st);
        let mut ext = Vec::new();
        collect_kernel_and_extension_logs(data_dir, &mut ext, &seq);
        for e in ext {
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
    for e in &payload.entries {
        out.push_str(&format!(
            "[{}][{}][{}] {}\n",
            e.timestamp, e.level, e.module, sanitize_sensitive(&e.message)
        ));
    }
    out
}
