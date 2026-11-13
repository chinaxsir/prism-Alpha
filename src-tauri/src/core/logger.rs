//! 全模块环形日志系统（APP6 任务1）。
//!
//! 统一记录 APP 内所有模块（GoLan / Kernel / GoAim / GoCus / Sub / Pro）
//! 的运行日志，供「设置 -> 运行日志」与「Go Lan 实时日志」面板展示。
//!
//! 设计：
//! - 【APP59 任务2.2】7 个分类物理隔离的环形队列，每个分类最多 150 条，
//!   单一分类刷屏不会挤掉其他分类的日志；
//! - 持久化文件 `data_dir/logs_v2.jsonl`（结构化 JSONL，每行
//!   `{category, level, timestamp, message}`）：超过 512 KB 自动截断保留
//!   最新一半，绝不占用用户终端过多存储空间；旧版纯文本 `prism_app.log`
//!   在升级后首次启动时自动删除；
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

/// 内存环形缓冲上限（条，兼容旧常量；实际按分类分桶，见 PER_CATEGORY_MAX）
pub const MAX_ENTRIES: usize = 800;
/// 【APP59 任务2.2】每个分类独立环形队列的容量：7 个物理分桶各 150 条，
/// 任一分类刷屏都不会挤掉其他分类的日志。
pub const PER_CATEGORY_MAX: usize = 150;
/// 持久化文件容量上限：512 KB（524,288 字节）
pub const MAX_LOG_FILE_BYTES: u64 = 512 * 1024;
/// 【APP71 任务1.1】Go AIM 专属有界队列上限：400 条，超出自动弹出最旧条目。
/// 与其余 6 个分类桶（150 条）物理隔离，AIM 高频日志绝不挤掉其他模块。
pub const AIM_BUCKET_MAX: usize = 400;
/// 【APP71 任务1.1】Go AIM 结构化日志落盘防抖窗口（毫秒）
pub const AIM_FLUSH_DEBOUNCE_MS: u64 = 250;
/// 【APP71 任务1.1】待落盘 AIM 日志硬上限：超过立即同步刷盘，防内存无限增长
const AIM_PENDING_MAX: usize = 300;

/// 【APP71 任务1.1】DEBUG 级别 AIM 日志开关（默认关闭，诊断时开启）。
/// INFO / WARN / ERROR 始终写入，不受该开关影响。
pub static AIM_DEBUG_LOG_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 【APP59 任务2.2】结构化 JSONL 持久化文件名（旧版纯文本 prism_app.log
/// 在升级首次启动时自动清理，防止历史混排数据继续被读出）。
const JSONL_FILE_NAME: &str = "logs_v2.jsonl";
const LEGACY_FILE_NAME: &str = "prism_app.log";

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
    // ---- 【APP71 任务1.1】Go AIM 结构化上下文字段 ----
    // 全部可选且 `skip_serializing_if`：其余模块与旧前端 100% 向下兼容。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

impl LogEntry {
    /// 基础条目（无 AIM 上下文），供旧调用点零改动复用。
    pub fn plain(id: u64, timestamp: String, level: &str, module: &str, message: String) -> Self {
        Self {
            id,
            timestamp,
            level: level.to_string(),
            module: module.to_string(),
            message,
            run_id: None,
            node_name: None,
            slot: None,
            service: None,
            elapsed_ms: None,
        }
    }
}

/// 【APP71 任务1.1】Go AIM 结构化日志上下文（runId / 节点 / 槽位 / 平台 / 耗时）。
#[derive(Debug, Clone, Default)]
pub struct AimLogMeta {
    pub run_id: Option<String>,
    pub node_name: Option<String>,
    pub slot: Option<usize>,
    pub service: Option<String>,
    pub elapsed_ms: Option<u64>,
}

impl AimLogMeta {
    pub fn run(run_id: &str) -> Self {
        Self {
            run_id: Some(run_id.to_string()),
            ..Default::default()
        }
    }

    pub fn node(mut self, node: &str) -> Self {
        self.node_name = Some(node.to_string());
        self
    }

    pub fn slot(mut self, slot: usize) -> Self {
        self.slot = Some(slot);
        self
    }

    pub fn service(mut self, service: &str) -> Self {
        self.service = Some(service.to_string());
        self
    }

    pub fn elapsed(mut self, ms: u64) -> Self {
        self.elapsed_ms = Some(ms);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsPayload {
    pub entries: Vec<LogEntry>,
    /// 当前日志总占用（字节，含持久化文件与内存条目估算）
    pub total_bytes: usize,
}

/// 【APP62 任务4】单个分类桶在 `CategorizedLogsPayload.logs` 中的区间。
/// 前端按分类切片时只做 `logs.slice(start, end)`，**零网络请求**。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogBucket {
    /// 分类名（Kernel / Node / Rule / GoAIM / GoLan / GoCus / Sub）
    pub module: String,
    /// 该分类在 logs 数组中的起始下标（含）
    pub start: usize,
    /// 该分类在 logs 数组中的结束下标（不含）
    pub end: usize,
    /// 该分类日志条数（= end - start）
    pub count: usize,
}

/// 【APP62 任务4】一次性返回全部分类日志 + 桶区间 + 增量游标：
/// 前端切换分类不再发请求，彻底消除「切标签 -> 网络抖动 -> 列表清空/卡死」。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategorizedLogsPayload {
    /// 按固定桶顺序（Kernel → Node → Rule → GoAIM → GoLan → GoCus → Sub）
    /// 拼接的全量日志，桶内按时间升序
    pub logs: Vec<LogEntry>,
    pub buckets: Vec<LogBucket>,
    pub total_bytes: usize,
    /// 本次返回的最大日志 id（增量拉取的游标）
    pub last_offset: u64,
}

/// 分类桶的固定顺序（与前端 CATEGORY_TABS 完全一致）
pub const BUCKET_ORDER: [&str; 7] = [
    MOD_KERNEL, MOD_NODE, MOD_RULE, MOD_GO_AIM, MOD_GO_LAN, MOD_GO_CUS, MOD_SUB,
];

struct LogState {
    seq: AtomicU64,
    /// 【APP59 任务2.2】7 个物理隔离的分类环形队列：键恒为 7 个合法分类之一，
    /// 前端按标签读取时只取对应桶，从数据结构底层杜绝跨标签混排。
    buckets: std::collections::HashMap<&'static str, VecDeque<LogEntry>>,
    /// 持久化文件路径（data_dir/logs_v2.jsonl；未 init 时为 None）
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

/// 【APP71 任务1.1】分类桶容量：GoAIM 专属 400 条，其余分类维持 150 条。
pub fn bucket_capacity(module: &str) -> usize {
    if module == MOD_GO_AIM {
        AIM_BUCKET_MAX
    } else {
        PER_CATEGORY_MAX
    }
}

/// 【APP71 任务1.1】有界入队（纯函数，便于单元测试）：
/// 超出容量自动弹出最旧条目，内存占用严格封顶。
fn push_bounded(bucket: &mut VecDeque<LogEntry>, entry: LogEntry, cap: usize) {
    bucket.push_back(entry);
    while bucket.len() > cap {
        bucket.pop_front();
    }
}

/// 【APP71 任务1.1】待落盘的 AIM JSONL 行（250ms 防抖批量追加）
static AIM_PENDING: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
static AIM_WRITER_STARTED: OnceLock<()> = OnceLock::new();
static AIM_WRITE_ERRORS: AtomicU64 = AtomicU64::new(0);

fn aim_pending() -> &'static Mutex<Vec<String>> {
    AIM_PENDING.get_or_init(|| Mutex::new(Vec::new()))
}

/// APP 启动时初始化（lib.rs setup 调用）：绑定持久化文件路径
pub fn init(data_dir: &std::path::Path) {
    // 【APP59 任务2.2】升级清理：旧版纯文本混排日志整体删除，
    // 新会话只写结构化 JSONL，历史脏数据不会再被任何界面读出。
    let legacy = data_dir.join(LEGACY_FILE_NAME);
    if legacy.exists() {
        let _ = std::fs::remove_file(&legacy);
    }
    let mut buckets = std::collections::HashMap::new();
    for module in [
        MOD_KERNEL, MOD_NODE, MOD_RULE, MOD_GO_AIM, MOD_GO_LAN, MOD_GO_CUS, MOD_SUB,
    ] {
        buckets.insert(module, VecDeque::with_capacity(bucket_capacity(module)));
    }
    let _ = STATE.set(Mutex::new(LogState {
        seq: AtomicU64::new(1),
        buckets,
        file_path: Some(data_dir.join(JSONL_FILE_NAME)),
        writes_since_check: 0,
    }));
    // 【APP71 任务1.1】250ms 防抖刷盘线程：只服务 GoAIM 结构化日志，
    // 与既有同步写入路径完全隔离，不影响其他模块。
    let _ = AIM_WRITER_STARTED.get_or_init(|| {
        std::thread::spawn(|| {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(AIM_FLUSH_DEBOUNCE_MS));
                flush_aim_pending();
            }
        });
    });
}

/// 【APP54 任务3】北京时间字符串（UTC+8 固定偏移，格式 `YYYY-MM-DD HH:mm:ss.SSS`）。
/// 四端统一：无论系统处于哪个时区，日志时间戳一律为北京时间。
pub fn beijing_now_string() -> String {
    use time::macros::format_description;
    let fmt =
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]");
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

/// 【APP58 任务5】唯一强制分类归属器（第一道铁闸）：每条日志只能且必须归入
/// 7 个合法分类之一（Kernel / Node / Rule / GoAIM / GoLan / GoCus / Sub）：
/// - 显式模块名先归一化（`Go Lan`→GoLan、`Go AIM`→GoAIM、`Go Cus`→GoCus）；
/// - 非法 / 空值一律降级为 Kernel；
/// - **绝不读取 message 内容做任何关键词猜测**：sing-box 原生日志即使正文里
///   出现 `go-lan-home`、`match rule`、节点域名等字样，也不会被篡改成
///   GoLan / Rule / Node，彻底杜绝跨分类污染。
pub fn enforce_strict_log_category(raw_category: &str, _message: &str) -> &'static str {
    let compact = raw_category.trim().to_lowercase().replace(' ', "");
    match compact.as_str() {
        "kernel" => MOD_KERNEL,
        "node" => MOD_NODE,
        "rule" => MOD_RULE,
        "goaim" => MOD_GO_AIM,
        "golan" => MOD_GO_LAN,
        "gocus" => MOD_GO_CUS,
        "sub" => MOD_SUB,
        _ => MOD_KERNEL,
    }
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
    let entry = LogEntry::plain(0, now_timestamp(), level, module, message);

    let Some(mutex) = state() else { return };
    let Ok(mut st) = mutex.lock() else { return };
    let id = st.seq.fetch_add(1, Ordering::Relaxed);
    let mut entry = entry;
    entry.id = id;
    // 【APP59 任务2.2】写入对应分类的独立环形队列；【APP71】GoAIM 桶 400 条，
    // 其余分类维持 150 条，互不挤占。
    let cap = bucket_capacity(module);
    let bucket = st.buckets.entry(module).or_default();
    push_bounded(bucket, entry.clone(), cap);
    // 追加写磁盘（每 20 条做一次 512 KB 容量检查）
    st.writes_since_check += 1;
    if let Some(path) = st.file_path.clone() {
        let need_truncate = st.writes_since_check >= 20
            && std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > MAX_LOG_FILE_BYTES;
        if need_truncate {
            st.writes_since_check = 0;
            truncate_log_file(&path);
        }
        // 【APP59 任务2.2】结构化 JSONL：每行一个独立日志对象，
        // 字段固定 category / level / timestamp / message
        let line = serde_json::json!({
            "category": entry.module,
            "level": entry.level,
            "timestamp": entry.timestamp,
            "message": entry.message,
        })
        .to_string();
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(line.as_bytes());
            let _ = f.write_all(b"\n");
        }
    }
}

/// 超过 512 KB：截断保留最新一半（按行）
fn truncate_log_file(path: &std::path::Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let lines: Vec<&str> = text.lines().collect();
    let keep_from = lines.len() / 2;
    let kept: String = lines[keep_from..].join("\n");
    let _ = std::fs::write(path, kept.as_bytes());
}

// ================= 【APP71 任务1.1】Go AIM 结构化日志 =================

/// Go AIM 日志脱敏：自动抹除 UUID、节点密码、订阅 URL 凭据、
/// Authorization / Cookie 头、WireGuard 私钥与 License Key。
/// 只用于 AIM 日志；不改变既有 `sanitize_sensitive` 行为。
pub fn sanitize_aim_log_message(raw: &str) -> String {
    use regex::Regex;
    let mut out = raw.to_string();
    // 1) UUID（节点 uuid / 订阅标识）
    if let Ok(re) =
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
    {
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                let s = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                format!("{}****{}", &s[..4], &s[s.len() - 4..])
            })
            .into_owned();
    }
    // 2) Authorization / Cookie 头
    if let Ok(re) = Regex::new(r"(?i)\b(authorization|cookie)\b(\s*[:=]\s*)[^\r\n,;]+") {
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                format!(
                    "{}{}***",
                    caps.get(1).map(|m| m.as_str()).unwrap_or(""),
                    caps.get(2).map(|m| m.as_str()).unwrap_or(": ")
                )
            })
            .into_owned();
    }
    // 3) 节点口令 / 认证串
    if let Ok(re) = Regex::new(
        r#"(?i)\b(password|passwd|pwd|auth-str|auth_str|token)\b(\s*[:=]\s*"?)[^\s",}]+"#,
    ) {
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                format!(
                    "{}{}***",
                    caps.get(1).map(|m| m.as_str()).unwrap_or(""),
                    caps.get(2).map(|m| m.as_str()).unwrap_or(": ")
                )
            })
            .into_owned();
    }
    // 4) 订阅 URL：仅保留 scheme + host（含查询串 / 超长 token 的 URL 一律折叠）
    if let Ok(re) = Regex::new(r"(?i)\b(https?)://([^/\s:?#]+)([^\s]*)") {
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                let scheme = caps.get(1).map(|m| m.as_str()).unwrap_or("https");
                let host = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                let rest = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                if rest.len() > 24 || rest.contains('?') {
                    format!("{scheme}://{host}/***")
                } else {
                    format!("{scheme}://{host}{rest}")
                }
            })
            .into_owned();
    }
    // 5) WireGuard 私钥 / License Key（复用导出脱敏规则）
    sanitize_sensitive(&out)
}

fn aim_level(raw: &str) -> &'static str {
    match raw.trim().to_uppercase().as_str() {
        "ERROR" => "ERROR",
        "WARN" | "WARNING" => "WARN",
        "DEBUG" => "DEBUG",
        _ => "INFO",
    }
}

/// 【APP71 任务1.1】Go AIM 专属结构化日志入口：
/// - DEBUG 受 `AIM_DEBUG_LOG_ENABLED` 开关控制，INFO/WARN/ERROR 始终写入；
/// - 写入 GoAIM 独立有界队列（400 条），与其余分类物理隔离；
/// - 250ms 防抖批量追加 `logs_v2.jsonl`（超过 300 条立即刷盘）；
/// - 同步输出一次 tracing 事件（不再回调 logger，杜绝重复）。
pub fn log_aim(level: &str, meta: &AimLogMeta, message: &str) {
    let level = aim_level(level);
    if level == "DEBUG" && !AIM_DEBUG_LOG_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let mut message = sanitize_aim_log_message(message);
    if message.chars().count() > 2000 {
        message = message.chars().take(2000).collect();
    }
    let run_id = meta.run_id.as_deref().unwrap_or("-");
    // tracing 单次输出：开发态控制台可见，且不回调 logger（无环）
    match level {
        "ERROR" => tracing::error!(target: "go_aim", "[{run_id}] {message}"),
        "WARN" => tracing::warn!(target: "go_aim", "[{run_id}] {message}"),
        "DEBUG" => tracing::debug!(target: "go_aim", "[{run_id}] {message}"),
        _ => tracing::info!(target: "go_aim", "[{run_id}] {message}"),
    }

    let Some(mutex) = state() else {
        // logger 尚未初始化：关键错误绝不静默丢弃
        AIM_WRITE_ERRORS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let entry = {
        let Ok(mut st) = mutex.lock() else {
            AIM_WRITE_ERRORS.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let id = st.seq.fetch_add(1, Ordering::Relaxed);
        let entry = LogEntry {
            id,
            timestamp: now_timestamp(),
            level: level.to_string(),
            module: MOD_GO_AIM.to_string(),
            message,
            run_id: meta.run_id.clone(),
            node_name: meta.node_name.clone(),
            slot: meta.slot,
            service: meta.service.clone(),
            elapsed_ms: meta.elapsed_ms,
        };
        let bucket = st.buckets.entry(MOD_GO_AIM).or_default();
        push_bounded(bucket, entry.clone(), AIM_BUCKET_MAX);
        entry
    };

    let mut line = serde_json::json!({
        "category": entry.module,
        "level": entry.level,
        "timestamp": entry.timestamp,
        "message": entry.message,
    });
    if let Some(obj) = line.as_object_mut() {
        if let Some(v) = entry.run_id.clone() {
            obj.insert("runId".into(), serde_json::Value::String(v));
        }
        if let Some(v) = entry.node_name.clone() {
            obj.insert("nodeName".into(), serde_json::Value::String(v));
        }
        if let Some(v) = entry.slot {
            obj.insert("slot".into(), serde_json::json!(v));
        }
        if let Some(v) = entry.service.clone() {
            obj.insert("service".into(), serde_json::Value::String(v));
        }
        if let Some(v) = entry.elapsed_ms {
            obj.insert("elapsedMs".into(), serde_json::json!(v));
        }
    }
    let mut need_flush = false;
    if let Ok(mut pending) = aim_pending().lock() {
        pending.push(line.to_string());
        need_flush = pending.len() >= AIM_PENDING_MAX;
    }
    if need_flush {
        flush_aim_pending();
    }
}

/// 将待落盘的 AIM 日志批量追加到 `logs_v2.jsonl`，并做文件容量轮转检查。
pub fn flush_aim_pending() {
    let lines: Vec<String> = {
        let Ok(mut pending) = aim_pending().lock() else {
            return;
        };
        if pending.is_empty() {
            return;
        }
        std::mem::take(&mut *pending)
    };
    let Some(mutex) = state() else { return };
    let Ok(mut st) = mutex.lock() else { return };
    let Some(path) = st.file_path.clone() else {
        return;
    };
    st.writes_since_check += lines.len() as u32;
    let need_truncate = st.writes_since_check >= 20
        && std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > MAX_LOG_FILE_BYTES;
    if need_truncate {
        st.writes_since_check = 0;
        truncate_log_file(&path);
    }
    drop(st);
    use std::io::Write;
    let mut failed = 0usize;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        for line in lines {
            if f.write_all(line.as_bytes()).is_err() || f.write_all(b"\n").is_err() {
                failed += 1;
            }
        }
    } else {
        failed = 1;
    }
    if failed > 0 {
        let total = AIM_WRITE_ERRORS.fetch_add(failed as u64, Ordering::Relaxed) + failed as u64;
        // 严禁静默丢弃：落盘异常必须留下可检索告警（低频，避免刷屏）
        if total <= 1 || total % 64 == 0 {
            tracing::warn!(target: "go_aim", "AIM 日志落盘异常（累计 {total} 条），内存队列仍保留");
            push_entry(
                "WARN",
                MOD_GO_AIM,
                &format!("AIM 日志落盘异常（累计 {total} 条），内存队列仍保留"),
            );
        }
    }
}

/// 【APP71】当前分类桶实际条数（用于有界队列回归测试与内存诊断）。
pub fn bucket_len(module: &str) -> usize {
    state()
        .and_then(|m| {
            m.lock()
                .ok()
                .map(|st| st.buckets.get(module).map_or(0, |b| b.len()))
        })
        .unwrap_or(0)
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

/// 【APP58 任务5】外部日志文件（sing-box kernel.log / iOS extension.log）
/// 分类铁闸（第二道）：**只认显式标签，绝不按正文关键词猜测**：
/// - 显式 `[GoLan-Ext]` / `[GoLan]` 标签，或 sing-box 明确属于
///   `outbound/wireguard` 的日志 → GoLan；
/// - 其余全部（`dns:`、`inbound/tun`、`started`、进程启停、路由表等，
///   哪怕正文里出现 go-lan-home / match rule / 节点域名）→ Kernel。
/// 原生 sing-box 日志永远不会产出 Node / Rule / Sub / GoAIM / GoCus。
pub fn classify_external_log_line(raw_line: &str) -> (&'static str, String) {
    let lower = raw_line.to_lowercase();
    let module = if lower.contains("[golan-ext]")
        || lower.contains("[golan]")
        || lower.contains("outbound/wireguard")
    {
        MOD_GO_LAN
    } else {
        MOD_KERNEL
    };
    // 【APP69 任务4】彻底剥离 `±HHMM / epoch + 日期 + ERROR + [id 12ms]`
    // 等前缀，卡片右上角已单独展示时间戳与级别，正文只保留有效信息。
    let message = strip_log_prefix(raw_line);
    (module, message)
}

/// 【APP69 任务4】清理日志正文前缀（时区偏移 / epoch / 日期 / 级别 / 耗时括号）。
fn strip_log_prefix(line: &str) -> String {
    let mut s = line.trim();
    // `+0000 ` / `-0700 ` 时区前缀
    if let Some(rest) = s.strip_prefix('+').or_else(|| s.strip_prefix('-'))
        && rest.len() > 5
        && rest[..4].bytes().all(|c| c.is_ascii_digit())
        && rest.as_bytes()[4] == b' '
    {
        s = rest[5..].trim_start();
    }
    // 10 位 Unix 秒时间戳
    let first = s.split_whitespace().next().unwrap_or("");
    if first.len() == 10 && first.bytes().all(|c| c.is_ascii_digit()) {
        s = s[first.len()..].trim_start();
    }
    s = strip_leading_datetime(s);
    // 级别词
    for level in ["ERROR", "WARN", "INFO", "DEBUG", "FATAL", "TRACE"] {
        if let Some(rest) = s.strip_prefix(level)
            && (rest.starts_with(' ') || rest.starts_with('['))
        {
            s = rest.trim_start();
            break;
        }
    }
    // `[123 456ms]` / `[12ms]` 耗时括号
    if let Some(rest) = s.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let inside = &rest[..end];
        if inside.contains("ms") && inside.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            s = rest[end + 1..].trim_start();
        }
    }
    // `[GoLan-Ext]` / `[GoLan]` 标签
    for tag in ["[GoLan-Ext]", "[GoLan]"] {
        if let Some(rest) = s.strip_prefix(tag) {
            s = rest.trim_start();
            break;
        }
    }
    // 扩展日志的 `🌐 ` 图标前缀（`INFO 🌐 内核已切换至 ...`）
    if let Some(rest) = s.strip_prefix('🌐') {
        s = rest.trim_start();
    }
    s.to_string()
}

/// 【APP69 任务4】重复报错抑制：同一级别 + 模块 + 正文前 80 字符，
/// 60 秒窗口内最多记录前 3 条，杜绝 DNS/连接错误刷屏淹没有效日志。
fn should_suppress_repeated(level: &str, module: &str, message: &str) -> bool {
    if level == "INFO" {
        return false;
    }
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    static SEEN: OnceLock<Mutex<std::collections::HashMap<String, (Instant, u32)>>> =
        OnceLock::new();
    let map = SEEN.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    // 【APP69 任务4】按“错误类型”归一，而非按完整报文：
    // `dns: exchange failed for a.com` 与 `... for b.com` 属同一类型，
    // `dial tcp 1.2.3.4:443: i/o timeout` 也统一折叠。
    let normalized = if let Some(pos) = message.find(" for ") {
        &message[..pos]
    } else if let Some(pos) = message.find("i/o timeout") {
        &message[..(pos + "i/o timeout".len()).min(message.len())]
    } else {
        message
    };
    let key: String = format!(
        "{level}|{module}|{}",
        normalized.chars().take(80).collect::<String>()
    );
    let Ok(mut map) = map.lock() else {
        return false;
    };
    if map.len() > 512 {
        map.clear();
    }
    let now = Instant::now();
    let entry = map.entry(key).or_insert((now, 0));
    if now.duration_since(entry.0) > Duration::from_secs(60) {
        *entry = (now, 0);
    }
    if entry.1 >= 3 {
        return true;
    }
    entry.1 += 1;
    false
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
            // 【APP69 任务4】ISO/RFC3339 形式（如 sing-box `2025-11-06T12:34:56.789Z`）
            // 先按原时区解析，再强制转换为北京时间（UTC+8）。
            if i + 19 < n && (b[i + 10] == b'T' || b[i + 10] == b't') {
                let end = line[i..]
                    .find(|c: char| c == ' ' || c == ']' || c == '[')
                    .map(|k| i + k)
                    .unwrap_or(n);
                let raw = &line[i..end];
                if let Ok(dt) =
                    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
                {
                    use time::macros::format_description;
                    let fmt = format_description!(
                        "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
                    );
                    let bj = time::UtcOffset::from_hms(8, 0, 0).unwrap_or(time::UtcOffset::UTC);
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
            // 【APP69 任务4】带 `±HHMM ` 前缀时按该时区解析并换算到 UTC+8：
            // `+0000 2026-11-12 03:05:21` 应显示为 `11:05:21`，而非 03:05:21。
            let offset_minutes: Option<i32> = if i >= 6 {
                let p = &line[i - 6..i];
                let pb = p.as_bytes();
                if (pb[0] == b'+' || pb[0] == b'-')
                    && pb[1..5].iter().all(|c| c.is_ascii_digit())
                    && pb[5] == b' '
                {
                    let hh: i32 = p[1..3].parse().ok()?;
                    let mm: i32 = p[3..5].parse().ok()?;
                    Some(if pb[0] == b'-' {
                        -(hh * 60 + mm)
                    } else {
                        hh * 60 + mm
                    })
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(minutes) = offset_minutes {
                use time::{Date, Month, PrimitiveDateTime, Time, UtcOffset};
                let year: i32 = line[i..i + 4].parse().ok()?;
                let month: u8 = line[i + 5..i + 7].parse().ok()?;
                let day: u8 = line[i + 8..i + 10].parse().ok()?;
                let hour: u8 = line[i + 11..i + 13].parse().ok()?;
                let minute: u8 = line[i + 14..i + 16].parse().ok()?;
                let second: u8 = line[i + 17..i + 19].parse().ok()?;
                let millis: i32 = ms.parse().unwrap_or(0);
                let date =
                    Date::from_calendar_date(year, Month::try_from(month).ok()?, day).ok()?;
                let time_of_day = Time::from_hms_milli(hour, minute, second, millis as u16).ok()?;
                let source_offset = UtcOffset::from_whole_seconds(minutes * 60).ok()?;
                let beijing = UtcOffset::from_hms(8, 0, 0).unwrap_or(UtcOffset::UTC);
                let local = PrimitiveDateTime::new(date, time_of_day)
                    .assume_offset(source_offset)
                    .to_offset(beijing);
                return Some(format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
                    local.year(),
                    u8::from(local.month()),
                    local.day(),
                    local.hour(),
                    local.minute(),
                    local.second(),
                    local.millisecond()
                ));
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
    } else if end + 5 < b.len() && (b[end] == b'+' || b[end] == b'-') && b[end + 3] == b':' {
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

fn merge_external_text(
    lines_text: &str,
    out: &mut Vec<LogEntry>,
    seq: &AtomicU64,
    max_lines: usize,
) {
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
        let level = if lower.contains("error") || lower.contains("fatal") || lower.contains("失败")
        {
            "ERROR"
        } else if lower.contains("warn") {
            "WARN"
        } else {
            "INFO"
        };
        // 连续重复行去重（使用已清理前缀的正文，避免时间戳差异导致漏判）
        let key = format!("{level}|{module}|{classified}");
        if last_key.as_deref() == Some(key.as_str()) {
            continue;
        }
        last_key = Some(key);
        // 【APP69 任务4】高频报错熔断：同签名 60 秒内最多 3 条
        if should_suppress_repeated(level, module, &classified) {
            continue;
        }
        if count >= max_lines {
            break;
        }
        count += 1;
        // 【APP11 任务5.2】优先使用日志行自带时间戳（内核 + 扩展 epoch）
        let timestamp = parse_kernel_timestamp(line)
            .or_else(|| parse_leading_epoch(line))
            .unwrap_or_else(now_timestamp);
        out.push(LogEntry::plain(
            seq.fetch_add(1, Ordering::Relaxed),
            timestamp,
            &level,
            module,
            classified.chars().take(500).collect(),
        ));
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

/// 【APP62 任务4】外部日志（kernel.log / 扩展诊断日志）增量读取状态：
/// - `EXT_READ_OFFSETS`：每个文件已消费到的字节偏移；
/// - `EXT_ENTRY_CACHE`：已解析外部条目缓存（多次轮询结果稳定、不丢日志）。
/// get_app_logs 每 2 秒轮询时只读取文件新增字节，绝不每次从头全量重读。
static EXT_READ_OFFSETS: OnceLock<Mutex<std::collections::HashMap<PathBuf, u64>>> = OnceLock::new();
static EXT_ENTRY_CACHE: OnceLock<Mutex<Vec<LogEntry>>> = OnceLock::new();
static EXT_SEQ: AtomicU64 = AtomicU64::new(u64::MAX / 2);
/// 外部条目缓存上限（条），只保留近期现场
const EXT_CACHE_MAX: usize = 600;
/// 首次读取大文件时只取末尾 256 KB，避免历史日志一次性灌入
const EXT_FIRST_READ_MAX: u64 = 256 * 1024;

/// 读取文件「自上次消费位置以来」的新增字节（增量读取）。
/// - 文件被截断（长度 < 偏移）→ 偏移归零重新读；
/// - 首次读取超大文件 → 只取末尾 `EXT_FIRST_READ_MAX`；
/// - 只消费到最后一个换行，半行留到下次，避免把一行拆成两条日志。
fn read_new_segment(path: &std::path::Path) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(meta) = std::fs::metadata(path) else {
        return String::new();
    };
    let len = meta.len();
    let offsets = EXT_READ_OFFSETS.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let Ok(mut map) = offsets.lock() else {
        return String::new();
    };
    let prev = *map.get(path).unwrap_or(&0);
    let mut start = if len < prev { 0 } else { prev };
    if prev == 0 && len > EXT_FIRST_READ_MAX {
        start = len - EXT_FIRST_READ_MAX;
    }
    if start >= len {
        map.insert(path.to_path_buf(), len);
        return String::new();
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return String::new();
    }
    let consumed = match buf.iter().rposition(|b| *b == b'\n') {
        Some(i) => i + 1,
        // 没有换行：首次读取视为单行文件全部消费；增量读取则等待下一行写完
        None if prev == 0 => buf.len(),
        None => return String::new(),
    };
    buf.truncate(consumed);
    map.insert(path.to_path_buf(), start + consumed as u64);
    String::from_utf8_lossy(&buf).into_owned()
}

/// 【APP62 任务4】增量同步内核 / 扩展外部日志到解析缓存。
fn sync_kernel_and_extension_logs(data_dir: &std::path::Path) {
    let mut fresh: Vec<LogEntry> = Vec::new();
    {
        let mut feed = |path: &std::path::Path, max: usize| {
            if !file_modified_after_clear(path) {
                return;
            }
            let chunk = read_new_segment(path);
            if chunk.is_empty() {
                return;
            }
            merge_external_text(&chunk, &mut fresh, &EXT_SEQ, max);
        };
        // 1. 桌面端（含 Android）：sing-box 子进程日志 kernel.log
        feed(&data_dir.join("kernel").join("kernel.log"), 200);
        // 2. iOS：App Group 共享目录下的扩展诊断日志
        #[cfg(target_os = "ios")]
        if let Some(group) = ios_app_group_dir() {
            feed(&group.join("prism_error.txt"), 100);
            feed(&group.join("vpn_trace.log"), 100);
            feed(&group.join("prism_work").join("box.log"), 200);
        }
    }
    if fresh.is_empty() {
        return;
    }
    let cache = EXT_ENTRY_CACHE.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut c) = cache.lock() {
        c.extend(fresh);
        let overflow = c.len().saturating_sub(EXT_CACHE_MAX);
        if overflow > 0 {
            c.drain(0..overflow);
        }
    }
}

/// 读取日志（module_filter: Some("GoLan") 等按模块过滤；None 返回全部）。
/// 自动合并内核日志与 iOS 扩展日志（外部来源排在内存条目之后）。
pub fn get_logs(data_dir: &std::path::Path, module_filter: Option<&str>) -> LogsPayload {
    // 【APP58 任务5】筛选条件也强制归一化为 7 类合法值之一，非法/未知 → Kernel，
    // 与列表、徽章使用同一投影结果
    let filter: Option<&'static str> = module_filter.map(|f| enforce_strict_log_category(f, ""));
    let mut mem_entries: Vec<LogEntry> = Vec::new();
    let mut file_bytes = 0usize;
    if let Some(mutex) = state()
        && let Ok(st) = mutex.lock()
    {
        // 【APP59 任务2.2】只从目标分类桶读取；无筛选时按 7 个分类依次汇总，
        // 再按 id 还原时间顺序 —— 从物理存储层杜绝跨分类混排。
        let mut buckets: Vec<&VecDeque<LogEntry>> = Vec::new();
        match filter {
            Some(f) => {
                if let Some(b) = st.buckets.get(f) {
                    buckets.push(b);
                }
            }
            None => {
                for module in [
                    MOD_KERNEL, MOD_NODE, MOD_RULE, MOD_GO_AIM, MOD_GO_LAN, MOD_GO_CUS, MOD_SUB,
                ] {
                    if let Some(b) = st.buckets.get(module) {
                        buckets.push(b);
                    }
                }
            }
        }
        for b in buckets {
            for e in b {
                let mut entry = e.clone();
                entry.module =
                    enforce_strict_log_category(&entry.module, &entry.message).to_string();
                mem_entries.push(entry);
            }
        }
        mem_entries.sort_by_key(|e| e.id);
        if let Some(p) = &st.file_path {
            file_bytes = std::fs::metadata(p).map(|m| m.len() as usize).unwrap_or(0);
        }
        drop(st);
        // 【APP62 任务4】增量读取外部日志（只读新增字节），再从缓存取出
        sync_kernel_and_extension_logs(data_dir);
        let cached: Vec<LogEntry> = EXT_ENTRY_CACHE
            .get()
            .and_then(|m| m.lock().ok().map(|c| c.clone()))
            .unwrap_or_default();
        for mut e in cached {
            // 【APP56 任务4】外部日志同样按唯一分类下发
            e.module = enforce_strict_log_category(&e.module, &e.message).to_string();
            let matched = filter.map(|f| e.module == f).unwrap_or(true);
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

/// 【APP62 任务4】分类聚合读取：一次性返回全部 7 个分类的日志 + 每个分类
/// 在数组中的区间下标 + 增量游标。前端切换分类只做本地切片，零请求。
///
/// 逻辑：
/// 1. 复用 `get_logs(None)` 拿到全量（含内核 / 扩展外部日志）；
/// 2. 按固定桶顺序分组，桶内按「时间戳 → id」升序（时间戳格式等长，
///    字典序即时间序），保证某分类内部严格按时间排列；
/// 3. 逐桶记录 start/end，供前端 `logs.slice(start, end)`。
pub fn get_logs_categorized(data_dir: &std::path::Path) -> CategorizedLogsPayload {
    let payload = get_logs(data_dir, None);
    let mut logs: Vec<LogEntry> = Vec::with_capacity(payload.entries.len());
    let mut buckets: Vec<LogBucket> = Vec::with_capacity(BUCKET_ORDER.len());
    for module in BUCKET_ORDER {
        let mut rows: Vec<LogEntry> = payload
            .entries
            .iter()
            .filter(|e| e.module == module)
            .cloned()
            .collect();
        rows.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));
        let start = logs.len();
        let count = rows.len();
        logs.extend(rows);
        buckets.push(LogBucket {
            module: module.to_string(),
            start,
            end: logs.len(),
            count,
        });
    }
    let last_offset = logs.iter().map(|e| e.id).max().unwrap_or(0);
    CategorizedLogsPayload {
        logs,
        buckets,
        total_bytes: payload.total_bytes,
        last_offset,
    }
}

/// 清空全部日志：内存环形缓冲 + 删除本地 prism_app.log +
/// 清空内核 kernel.log + iOS 共享容器中的旧日志缓存
///
/// 【IPA9 任务1.2】同步设置 LAST_CLEARED_UNIX_MS，sync_kernel_and_extension_logs
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

    // 【APP62 任务4】清空外部日志增量偏移与解析缓存，
    // 防止清空后仍从旧偏移继续拼接、或缓存旧内容回弹
    if let Some(m) = EXT_ENTRY_CACHE.get()
        && let Ok(mut c) = m.lock()
    {
        c.clear();
    }
    if let Some(m) = EXT_READ_OFFSETS.get()
        && let Ok(mut o) = m.lock()
    {
        o.clear();
    }
    // 【APP71】清空待落盘的 AIM 日志，防止清空后旧内容回弹
    if let Ok(mut pending) = aim_pending().lock() {
        pending.clear();
    }

    if let Some(mutex) = state()
        && let Ok(mut st) = mutex.lock()
    {
        // 【APP59 任务2.2】7 个分类桶全部清空
        for bucket in st.buckets.values_mut() {
            bucket.clear();
        }
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
    Some(format!(
        "{}****[密钥已脱敏]****{}",
        &token[..6],
        &token[40..]
    ))
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
                let masked = mask_license_key(key).unwrap_or_else(|| "*".repeat(key.len().min(44)));
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
    // 【APP71】导出前强制刷盘，保证最新 AIM 结构化日志一并落盘
    flush_aim_pending();
    let payload = get_logs(data_dir, module_filter);
    let mut out = String::new();
    out.push_str("================ Prism 诊断日志 ================\n");
    out.push_str(&format!(
        "App 版本: {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS
    ));
    out.push_str(&format!("导出时间: {}\n", now_timestamp()));
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
                e.timestamp,
                e.level,
                e.module,
                sanitize_sensitive(&e.message)
            ));
        }
        out.push('\n');
    }
    out
}

/// 【APP63 任务2.2】全 7 分类诊断日志导出全文（iOS 原生分享 / 桌面 Downloads）。
///
/// 全程使用字符级安全截断 `safe_truncate_str`，**绝不做字节切片**
/// （`&s[..n]`），中文 / emoji 日志永不 panic。
pub fn export_diagnostic_text(data_dir: &std::path::Path) -> String {
    export_diagnostic_text_filtered(data_dir, None)
}

/// 【APP71 任务5】按模块导出诊断日志（`Some("GoAIM")` 仅导出 AIM 诊断）。
/// AIM 行附带 runId / 节点 / 平台 / 槽位 / 耗时结构化上下文。
pub fn export_diagnostic_text_filtered(
    data_dir: &std::path::Path,
    module_filter: Option<&str>,
) -> String {
    flush_aim_pending();
    let payload = get_logs_categorized(data_dir);
    let mut out = String::new();
    out.push_str("================ Prism 诊断日志 ================\n");
    out.push_str(&format!(
        "App 版本: {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS
    ));
    out.push_str(&format!("导出时间: {}\n", beijing_now_string()));
    out.push_str(&format!("日志条数: {}\n", payload.logs.len()));
    out.push_str("说明: WireGuard 密钥与 License Key 已自动脱敏\n");
    out.push_str("===============================================\n\n");
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
        if let Some(filter) = module_filter {
            if *module != filter {
                continue;
            }
        }
        out.push_str(title);
        out.push('\n');
        for e in payload.logs.iter().filter(|e| e.module == *module) {
            let msg = safe_truncate_str(&sanitize_sensitive(&e.message), 4000);
            if e.run_id.is_some() || e.node_name.is_some() || e.service.is_some() {
                out.push_str(&format!(
                    "[{}][{}][{}][run={}][node={}][slot={}][service={}][{}ms] {}\n",
                    e.timestamp,
                    e.level,
                    e.module,
                    e.run_id.as_deref().unwrap_or("-"),
                    e.node_name.as_deref().unwrap_or("-"),
                    e.slot.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
                    e.service.as_deref().unwrap_or("-"),
                    e.elapsed_ms
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "-".into()),
                    msg
                ));
            } else {
                out.push_str(&format!(
                    "[{}][{}][{}] {}\n",
                    e.timestamp, e.level, e.module, msg
                ));
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        MOD_GO_AIM, MOD_GO_CUS, MOD_GO_LAN, MOD_KERNEL, MOD_NODE, MOD_RULE, MOD_SUB,
        PHASE_CONNECTED, PHASE_FORWARDING, PHASE_HANDSHAKE, PHASE_NODE_IDENT, beijing_now_string,
        classify_external_log_line, enforce_strict_log_category, is_benign_close_line,
        is_noise_eperm_line, parse_kernel_timestamp, safe_truncate_str, should_suppress_repeated,
        strip_leading_datetime, strip_log_prefix,
    };

    /// 【APP69 任务4】同类型错误 60 秒内最多记录 3 条，INFO 永不抑制
    #[test]
    fn test_repeated_error_suppression() {
        assert!(!should_suppress_repeated(
            "ERROR",
            "dedupe-test",
            "dns: exchange failed for a.com"
        ));
        assert!(!should_suppress_repeated(
            "ERROR",
            "dedupe-test",
            "dns: exchange failed for b.com"
        ));
        assert!(!should_suppress_repeated(
            "ERROR",
            "dedupe-test",
            "dns: exchange failed for c.com"
        ));
        // 第 4 条同类型（不同域名）必须被抑制
        assert!(should_suppress_repeated(
            "ERROR",
            "dedupe-test",
            "dns: exchange failed for d.com"
        ));
        // 不同类型不受影响
        assert!(!should_suppress_repeated(
            "ERROR",
            "dedupe-test",
            "dial tcp: connection refused"
        ));
        // INFO 永不抑制
        for _ in 0..10 {
            assert!(!should_suppress_repeated(
                "INFO",
                "dedupe-test",
                "节点已切换"
            ));
        }
        assert_eq!(
            strip_log_prefix("1794452721 INFO 🌐 内核已切换至 pdp_ip0"),
            "内核已切换至 pdp_ip0"
        );
    }

    /// 【APP69 任务4】`+0000` 前缀必须按 UTC 解析并换算为北京时间（+8h）
    #[test]
    fn test_kernel_timestamp_utc_offset() {
        let ts = parse_kernel_timestamp("+0000 2026-11-12 03:05:21 ERROR [1 2ms] dns: x")
            .expect("must parse");
        assert_eq!(ts, "2026-11-12 11:05:21.000");
        // 已是 +0800 的日志保持原时分
        let ts =
            parse_kernel_timestamp("+0800 2026-11-12 11:05:21 INFO started").expect("must parse");
        assert_eq!(ts, "2026-11-12 11:05:21.000");
    }

    /// 【APP69 任务4】正文前缀（时区 / 日期 / 级别 / 耗时括号 / epoch）全部剥离
    #[test]
    fn test_strip_log_prefix() {
        assert_eq!(
            strip_log_prefix("+0000 2026-11-12 03:05:21 ERROR [123 4ms] dns: exchange failed"),
            "dns: exchange failed"
        );
        assert_eq!(
            strip_log_prefix("1793015059 INFO [GoLan-Ext] 自主握手已触发"),
            "自主握手已触发"
        );
        assert_eq!(
            classify_external_log_line("+0000 2026-11-12 03:05:21 INFO [GoLan-Ext] 握手").1,
            "握手"
        );
    }

    /// 【APP58 任务5】强制分类器（第一道铁闸）：显式模块名先归一化；
    /// **绝不读取 message 做关键词猜测**，Kernel 底层日志无论正文含什么
    /// 标签 / 域名一律留在 Kernel。
    #[test]
    fn test_enforce_strict_log_category_isolated() {
        let cases: [(&str, &str, &str); 18] = [
            (
                "Kernel",
                "[测速] 节点测速完成，自动选择最低延迟节点",
                MOD_KERNEL,
            ),
            (
                "Kernel",
                "[规则] 命中 DOMAIN-SUFFIX,google.com,PROXY",
                MOD_KERNEL,
            ),
            ("Kernel", "[GoAIM] probe gpt unlocked", MOD_KERNEL),
            ("Kernel", "[GoLan] 隧道握手完成 go-lan-home", MOD_KERNEL),
            ("Kernel", "[GoCus] 去广告模板已加载", MOD_KERNEL),
            ("Kernel", "[Sub] 订阅更新完成 18/20", MOD_KERNEL),
            (
                "Kernel",
                "dns: exchange failed: timeout for hk1.company-example.com",
                MOD_KERNEL,
            ),
            (
                "Kernel",
                "start inbound/tun[tun-in]: create tun",
                MOD_KERNEL,
            ),
            ("Go Lan", "任意内容", MOD_GO_LAN),
            ("Go AIM", "任意内容", MOD_GO_AIM),
            ("Go Cus", "任意内容", MOD_GO_CUS),
            ("golan", "任意内容", MOD_GO_LAN),
            ("GoAIM", "任意内容", MOD_GO_AIM),
            ("Node", "任意内容", MOD_NODE),
            ("Rule", "任意内容", MOD_RULE),
            ("Sub", "任意内容", MOD_SUB),
            ("Pro", "授权校验通过", MOD_KERNEL),
            ("", "任意内容", MOD_KERNEL),
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

    /// 【APP58 任务5】外部日志行（第二道铁闸）：只认显式 GoLan 标签与
    /// `outbound/wireguard`，原生 sing-box 日志一律 Kernel
    #[test]
    fn test_classify_external_log_line_categories() {
        let cases = [
            (
                "[GoLan-Ext] 内网直连探测 10.10.10.253:8001 可达",
                MOD_GO_LAN,
            ),
            ("[GoLan] profile home bypass on local lan", MOD_GO_LAN),
            ("outbound/wireguard[home]: handshake complete", MOD_GO_LAN),
            ("[GoAIM] probe gpt unlocked", MOD_KERNEL),
            ("GO-AIM-PROBE-IN: 已进入探测通道", MOD_KERNEL),
            ("[GoCus] 模块已加载: AdBlock", MOD_KERNEL),
            ("[Rule] 命中 DOMAIN-SUFFIX,google.com,PROXY", MOD_KERNEL),
            ("match rule: DOMAIN,www.apple.com,DIRECT", MOD_KERNEL),
            ("[Node] HK-01 握手成功 32ms", MOD_KERNEL),
            ("outbound/vless[HK1]: connected", MOD_KERNEL),
            ("outbound/hysteria2[US2]: connected", MOD_KERNEL),
            ("[Sub] 订阅更新完成 18/20", MOD_KERNEL),
            ("start inbound/tun[tun-in]: create tun", MOD_KERNEL),
            ("router: loaded 102 rules", MOD_KERNEL),
            // 正文出现 go-lan-home 字样也不得被劫持为 GoLan
            ("INFO outbound/vless[HK1]: dial go-lan-home", MOD_KERNEL),
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

    /// 【APP71 任务6 测试8】AIM 日志脱敏：UUID / 口令 / 订阅凭据 / 认证头全覆盖
    #[test]
    fn test_sanitize_aim_log_message() {
        let raw = "uuid=123e4567-e89b-12d3-a456-426614174000 password=secret123 \
                   sub=https://sub.example.com/api/v1/client/subscribe?token=abcdef1234567890 \
                   Authorization: Bearer abc.def.ghi Cookie: sid=xyz987";
        let out = super::sanitize_aim_log_message(raw);
        assert!(
            !out.contains("123e4567-e89b-12d3-a456-426614174000"),
            "{out}"
        );
        assert!(!out.contains("secret123"), "{out}");
        assert!(!out.contains("abcdef1234567890"), "{out}");
        assert!(!out.contains("Bearer"), "{out}");
        assert!(!out.contains("sid=xyz987"), "{out}");
        assert!(out.contains("https://sub.example.com/***"), "{out}");
        // 普通探针 URL（短路径、无凭据）必须保留，便于诊断
        let keep = super::sanitize_aim_log_message("probe https://chatgpt.com/ 200");
        assert!(keep.contains("https://chatgpt.com/"), "{keep}");
    }

    /// 【APP71 任务6 测试9】GoAIM 有界队列：写入 1000 条后严格保持 400 条
    #[test]
    fn test_aim_bucket_bounded_400() {
        let cap = super::bucket_capacity(super::MOD_GO_AIM);
        assert_eq!(cap, super::AIM_BUCKET_MAX);
        assert_eq!(cap, 400);
        assert_eq!(
            super::bucket_capacity(super::MOD_KERNEL),
            super::PER_CATEGORY_MAX
        );
        let mut q: std::collections::VecDeque<super::LogEntry> = std::collections::VecDeque::new();
        for i in 0..1000u64 {
            super::push_bounded(
                &mut q,
                super::LogEntry::plain(
                    i,
                    "2026-11-12 00:00:00.000".into(),
                    "INFO",
                    super::MOD_GO_AIM,
                    format!("line {i}"),
                ),
                cap,
            );
        }
        assert_eq!(q.len(), 400, "有界队列必须恒定封顶 400 条");
        assert_eq!(q.front().map(|e| e.id), Some(600), "应淘汰最旧 600 条");
        assert_eq!(q.back().map(|e| e.id), Some(999));
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
        let bj = time::OffsetDateTime::now_utc()
            .to_offset(time::UtcOffset::from_hms(8, 0, 0).unwrap_or(time::UtcOffset::UTC));
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

    /// 【APP62 任务4】7 个日志分类桶必须严格隔离：
    /// 1. 桶区间从 0 连续覆盖整个 logs 数组，顺序固定；
    /// 2. 桶内 `count == end - start`；
    /// 3. `prism.sarl` 只允许出现在 Sub 桶，绝不出现在 Node / Rule 桶。
    #[test]
    fn test_categorized_buckets_partition_and_isolate() {
        let dir = std::env::temp_dir().join(format!(
            "prism-log-cat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).ok();
        super::init(&dir);

        let tag = format!("APP62-CAT-{}", std::process::id());
        super::info(MOD_NODE, format!("{tag}-node"));
        super::info(MOD_RULE, format!("{tag}-rule"));
        super::info(MOD_SUB, format!("{tag}-sub prism.sarl"));

        let payload = super::get_logs_categorized(&dir);
        assert_eq!(payload.buckets.len(), super::BUCKET_ORDER.len());

        let mut cursor = 0usize;
        for (i, b) in payload.buckets.iter().enumerate() {
            assert_eq!(b.module, super::BUCKET_ORDER[i], "桶顺序不符合固定规范");
            assert_eq!(b.start, cursor, "桶 {} 区间不连续", b.module);
            assert_eq!(b.end - b.start, b.count, "桶 {} 条数不一致", b.module);
            cursor = b.end;
        }
        assert_eq!(cursor, payload.logs.len(), "桶区间未覆盖全部日志");
        assert_eq!(
            payload.last_offset,
            payload.logs.iter().map(|e| e.id).max().unwrap_or(0)
        );

        for b in &payload.buckets {
            if b.module == MOD_SUB {
                continue;
            }
            for e in &payload.logs[b.start..b.end] {
                assert!(
                    !e.message.contains("prism.sarl"),
                    "prism.sarl 泄漏到 {} 分类",
                    b.module
                );
            }
        }

        let sub = payload
            .buckets
            .iter()
            .find(|b| b.module == MOD_SUB)
            .expect("缺少 Sub 桶");
        assert!(
            payload.logs[sub.start..sub.end]
                .iter()
                .any(|e| e.message.contains("prism.sarl")),
            "Sub 桶未收到 prism.sarl 日志"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 【APP63 任务2.2】全分类导出文本：中文 / emoji / 超长行均不得 panic，
    /// 且 7 个分类章节齐全。
    #[test]
    fn test_export_diagnostic_text_handles_cjk() {
        let dir = std::env::temp_dir().join(format!(
            "prism-log-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).ok();
        super::init(&dir);

        let long_line = format!("中文诊断日志😀{}", "内核状态正常".repeat(900));
        super::info(MOD_NODE, &long_line);
        super::info(MOD_KERNEL, "中文内核日志：连接成功");

        let text = super::export_diagnostic_text(&dir);
        for title in [
            "=== [内核 Kernel] ===",
            "=== [节点 Node] ===",
            "=== [规则 Rule] ===",
            "=== [Go AIM] ===",
            "=== [Go Lan] ===",
            "=== [Go Cus] ===",
            "=== [订阅 Sub] ===",
        ] {
            assert!(text.contains(title), "缺少章节 {title}");
        }
        assert!(text.contains("中文内核日志"));
        assert!(text.contains("中文诊断日志😀"));
        // 字符级安全截断：中文 / emoji 不得被截成半个字符（无替换符 U+FFFD）
        assert!(!text.contains('\u{FFFD}'));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 【APP71 任务6-9】AIM 诊断导出支持按模块过滤：只输出指定分类章节，
    /// 其余分类既不出现标题也不出现正文；无过滤时仍导出完整 7 章节。
    #[test]
    fn test_export_diagnostic_text_filtered_by_module() {
        let dir = std::env::temp_dir().join(format!(
            "prism-log-aim-export-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).ok();
        super::init(&dir);

        let kernel_tag = format!("内核唯一标记-{}", std::process::id());
        let node_tag = format!("节点唯一标记-{}", std::process::id());
        super::info(MOD_KERNEL, &kernel_tag);
        super::info(MOD_NODE, &node_tag);

        let aim_only = super::export_diagnostic_text_filtered(&dir, Some(MOD_GO_AIM));
        assert!(aim_only.contains("=== [Go AIM] ==="));
        assert!(!aim_only.contains("=== [内核 Kernel] ==="));
        assert!(!aim_only.contains(&kernel_tag));
        assert!(!aim_only.contains(&node_tag));

        let full = super::export_diagnostic_text_filtered(&dir, None);
        assert!(full.contains(&kernel_tag));
        assert!(full.contains(&node_tag));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
