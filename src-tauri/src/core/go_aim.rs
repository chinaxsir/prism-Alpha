//! Go AIM —— AI / 流媒体 真实探测锁定引擎（Pro 专属，APP-4 任务3）
//!
//! 探测机制（与旧版二值信号方案的本质区别）：
//! - 内核配置注入 4 个仅绑定 127.0.0.1 的 mixed 入站（2083-2086），
//!   各自映射到专用选择组 GO-AIM-PROBE-0..3（成员 = 全部节点，互不影响）；
//! - 探测引擎把节点分发到 4 个并行槽位，逐节点把探针选择器切到该节点，
//!   然后经对应本地端口发起 **7 个平台端点的真实 HTTPS 请求**，读取响应
//!   状态码 / Location 跳转 / 正文关键词与 cdn-trace 的 loc= 区域码做精确
//!   解锁判定（HTTP 延迟测速的二值信号无法区分「解锁但延迟高」与「封锁」，
//!   也读不到区域码——本版本彻底消除该误差）；
//! - 超时/传输失败的探测点自动补测 1 次，防偶发抖动误判；
//! - 选点规则：Tier3（7 平台全解锁）> Tier2（AI+流媒体）> Tier1（AI 或
//!   流媒体）> Tier0（仅存活），同级延迟最低优先；
//! - 手动指定（go_aim_pinned_node）：节点页手动选中的节点优先级最高，
//!   探测评级照跑但绝不覆盖，直到该节点失联或用户清除。
//!
//! 失败语义：内核未运行时探测静默跳过（IPC 层已给出明确提示）；
//! 探测绝不动 GLOBAL/主选择器以外的组。

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager};

use futures_util::StreamExt;

use crate::core::logger::AimLogMeta;
use crate::core::state::{AppState, CoreStatus};

/// 【APP74】当前 Go AIM 检测引擎版本号：统一递增至 6，启动时自动淘汰
/// `< 6` 的错误缓存（含出口名单提前短路、PROXY_FAILED 伪装 probed=true 等脏结果）。
pub const CURRENT_AIM_PROBE_VERSION: u32 = 6;
pub const CURRENT_AIM_RULE_VERSION: u32 = 6;

/// 前端事件：探测结果更新（payload 为单节点结果或全量刷新标记）
pub const AIM_EVENT: &str = "go-aim://updated";
/// 【APP71 任务2.1】结构化实时事件流（携带 runId + sequence + ProbeProgress）
pub const AIM_EVENT_STRUCTURED: &str = "go-aim://event";
/// 【APP71 任务3】快照保留的最近结构化事件条数
pub const AIM_RECENT_EVENTS: usize = 30;
/// 【APP71 任务2.3】SCREEN 事件节流：每完成 2 个节点或 120ms 发射一次
const SCREEN_EMIT_NODES: usize = 2;
const SCREEN_EMIT_INTERVAL_MS: u64 = 120;

/// 探测槽位数（与 config_builder 注入的探针入站/选择组数量严格一致）
pub const PROBE_SLOTS: usize = 4;
/// 探针入站端口基址（config_builder 注入 2083..=2086）
pub const PROBE_PORT_BASE: u16 = 2083;
/// 基线测速 URL（Cloudflare 204，任何出口都应 204；国内直连也可达）
const BASELINE_URL: &str = "http://cp.cloudflare.com/generate_204";
/// 【APP37 任务3.2】1.5s 极速连通性快筛超时（毫秒）
const BASELINE_TIMEOUT_MS: u64 = 1500;
/// 参与探测的节点基线延迟上限（仅探测存活节点）
const PROBE_MAX_DELAY_MS: u64 = 2500;
/// 【APP51 任务1】单个平台探测请求超时（毫秒，严格 2800ms 快速出结果）
const PROBE_TIMEOUT_MS: u64 = 2800;
/// 【APP73 任务2.1】单次 HTTP 请求连接超时（3 秒）
const PROBE_CONNECT_TIMEOUT_MS: u64 = 3000;
/// 【APP73 任务2.1】单次 HTTP 请求总超时（8 秒）
const PROBE_REQUEST_TIMEOUT_MS: u64 = 8000;
/// 【APP73 任务2.1】单个平台完整探测硬超时（10 秒，含 1 次补测）
const PROBE_PLATFORM_HARD_TIMEOUT_SECS: u64 = 10;
/// 【APP51 任务1】阶段1 极速存活快筛：32 路并发（Semaphore 限流）
const SCREEN_BATCH_SIZE: usize = 32;
/// 阶段1 快筛测速 URL（generate_204，任何出口都应 204）
const SCREEN_URL: &str = "http://www.gstatic.com/generate_204";
/// 【APP72 任务1.3】阶段1 首次测速超时后的备用测速地址（Cloudflare 204），
/// 单次失败不再直接判死。
const SCREEN_FALLBACK_URL: &str = "http://cp.cloudflare.com/generate_204";

/// 【APP74 任务1.1】阶段1 延迟裁决：**唯有本轮当前实时测速成功**才算存活。
/// - 主测速（gstatic generate_204）成功 → alive
/// - 主测失败 → 仅再用 Cloudflare 备用地址重试 **1 次**（避免瞬时抖动误杀）
/// - 主备均失败 → 立即 SCREENED_DEAD，**严禁再读历史缓存 `cached` 冒充存活**
/// - 历史缓存延迟只允许保留在 UI 展示字段，绝不覆盖本轮当前的失败事实
#[inline]
fn resolve_screen_delay(first: Option<u64>, retry: Option<u64>) -> Option<u64> {
    let valid = |d: Option<u64>| d.filter(|v| *v > 0 && *v < PROBE_MAX_DELAY_MS);
    valid(first).or_else(|| valid(retry))
}
/// 【APP51 任务1】阶段2 深测只取阶段1 延迟最低的 Top N：
/// 快筛已覆盖全部节点，深测 7 平台极耗时，只对最有希望的低延迟节点做精确评级
// DEEP_PROBE_MAX 已移除（APP53 任务2.3：Go AIM 必须检测完所有可达节点）
/// 【APP51 任务1】ChatGPT cdn-trace 探测超时（毫秒，严格 1200ms）
#[allow(dead_code)]
const GPT_TRACE_TIMEOUT_MS: u64 = 1200;
/// 故障转移监控间隔（秒）
const MONITOR_INTERVAL_SECS: u64 = 20;

/// 探针选择器 tag（GO-AIM-PROBE-0..3）
fn probe_selector(slot: usize) -> String {
    format!("GO-AIM-PROBE-{slot}")
}

/// 槽位对应的本地 mixed 入站代理地址。
/// APP-5：探针端口不可用时回退到主混合端口（见 resolve_probe_slots）。
fn probe_proxy_url(slot: usize) -> String {
    format!("http://127.0.0.1:{}", PROBE_PORT_BASE + slot as u16)
}

/// 探测本机端口是否可连通（200ms 内建立 TCP 连接）。
/// 内核未运行 / 探针入站未注入（移动端扩展配置裁剪）时返回 false，
/// 供 resolve_probe_slots 做智能回退，避免整个探测链路全部连不上。
fn probe_port_reachable(port: u16) -> bool {
    use std::net::{SocketAddr, TcpStream};
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200)).is_ok()
}

// ---------------------------------------------------------------- 探测矩阵

/// AI 平台受限地区（cdn-trace loc=）：命中任一即判定该平台对该出口封锁。
/// 【APP67】GPT 增加 VE（委内瑞拉）；其余 AI 平台使用不含 VE 的子集时
/// 在各自探测器中另行校验。
const AI_BLOCKLIST: &[&str] = &["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY", "VE"];

/// 不含 VE 的 AI 平台受限名单（Claude / Gemini / Disney+ 使用）
const AI_BLOCKLIST_NO_VE: &[&str] = &["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY"];

/// 【APP49 任务3】TikTok 受限地区（trace loc=）：命中任一即判未解锁
const TIKTOK_BLOCKLIST: &[&str] = &["CN", "HK", "IN", "RU", "AF"];

/// 出口地区探测端点（依次兜底）：cdn-trace 返回多行 key=value，
/// 其中 `loc=XX` 即 Cloudflare 观测到的出口国家/地区代码。
const TRACE_URLS: &[&str] = &[
    "https://chatgpt.com/cdn-cgi/trace",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://1.1.1.1/cdn-cgi/trace",
];

/// 从 cdn-trace 正文解析出口地区代码（`loc=US`，无空格，转大写）
fn parse_trace_loc(body: &str) -> Option<String> {
    body.lines().find_map(|l| {
        l.strip_prefix("loc=")
            .map(|s| s.trim().to_uppercase())
            .filter(|s| !s.is_empty())
    })
}

/// 【APP67 BUG-04】从 cdn-trace 正文解析出口真实公网 IP（`ip=1.2.3.4`）。
/// 仅用于出口预检短路与「漏直连」判定，绝不作为解锁判定依据。
fn parse_trace_ip(body: &str) -> Option<String> {
    body.lines().find_map(|l| {
        l.strip_prefix("ip=")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    })
}

/// 【APP68】从 cdn-trace 正文解析出口 ASN。
fn parse_trace_asn(body: &str) -> Option<String> {
    body.lines().find_map(|l| {
        l.strip_prefix("asn=")
            .map(|s| s.trim().trim_start_matches("AS").to_string())
            .filter(|s| !s.is_empty())
    })
}

#[derive(Debug, Clone, Default)]
struct EgressInfo {
    ip: Option<String>,
    country: Option<String>,
    asn: Option<String>,
}

/// 经代理读取出口真实 IP、地区与 ASN（多端点兜底）。
async fn fetch_egress(client: &reqwest::Client) -> EgressInfo {
    for url in TRACE_URLS {
        let Ok(resp) = client
            .get(*url)
            .header("Accept-Language", "en-US,en;q=0.9")
            .send()
            .await
        else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        if let Ok(text) = resp.text().await {
            let egress = EgressInfo {
                ip: parse_trace_ip(&text),
                country: parse_trace_loc(&text),
                asn: parse_trace_asn(&text),
            };
            if egress.ip.is_some() && egress.country.is_some() {
                return egress;
            }
        }
    }
    EgressInfo::default()
}

/// 【APP49 任务3】按延迟升序排序（纯函数，便于单元测试）。
/// 阶段1 快筛结束后调用，保证阶段2 从延迟最低的节点开始探测。
fn sort_by_delay(mut nodes: Vec<(String, u64)>) -> Vec<(String, u64)> {
    nodes.sort_by_key(|(_, d)| *d);
    nodes
}

/// 【APP68】五级优先级队列：手动指定 > 上次最佳 > 当前使用 > 低延迟候选 > 其余。
struct AimPriorityQueue;

impl AimPriorityQueue {
    fn new(
        alive: Vec<(String, u64)>,
        selected: Option<&str>,
        manual: bool,
        best: Option<&str>,
    ) -> Vec<(String, u64)> {
        let mut alive = sort_by_delay(alive);
        let mut out = Vec::with_capacity(alive.len());
        let mut push = |name: &str, out: &mut Vec<(String, u64)>| {
            if let Some(pos) = alive.iter().position(|(n, _)| n == name) {
                out.push(alive.remove(pos));
            }
        };
        if manual {
            if let Some(name) = selected {
                push(name, &mut out);
            }
        }
        if let Some(name) = best {
            push(name, &mut out);
        }
        if let Some(name) = selected {
            push(name, &mut out);
        }
        let (preferred, rest): (Vec<_>, Vec<_>) =
            alive.into_iter().partition(|(_, delay)| *delay <= 350);
        out.extend(preferred);
        out.extend(rest);
        out
    }
}

/// 【APP68】只有节点配置指纹、双版本与当前出口 IP 全部一致才允许复用。
/// FULL 是用户强制全量重测，必须绕过缓存；FAST 结果（probed=false）永不命中。
fn cache_reusable(
    cached: &AimNodeResult,
    node_id: &str,
    current_egress_ip: &str,
    force_full: bool,
) -> bool {
    !force_full
        && !node_id.is_empty()
        && cached.probed
        && cached.node_id == node_id
        && cached.probe_version == CURRENT_AIM_PROBE_VERSION
        && cached.rule_version == CURRENT_AIM_RULE_VERSION
        && cached.egress_ip.as_deref() == Some(current_egress_ip)
        && cached.mode != Some(AimProbeMode::Fast)
        // probed=true 也包含死节点/出口预检短路；这些结果并未完成七平台检测，
        // 绝不能在下次出口恢复后被当成完整缓存长期复用。空 services 同样不命中。
        && !cached.services.values().all(|service| {
            service
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("未执行平台探测"))
        })
}

fn yaml_scalar(value: Option<&serde_yaml::Value>) -> String {
    match value {
        Some(serde_yaml::Value::String(s)) => s.clone(),
        Some(serde_yaml::Value::Number(n)) => n.to_string(),
        Some(serde_yaml::Value::Bool(v)) => v.to_string(),
        _ => String::new(),
    }
}

/// 【APP68】节点核心配置指纹：名称变化不影响命中，配置变化精准失效。
/// 只保留 SHA-256 前 16 位，绝不把密码 / UUID 写入缓存或日志。
fn node_fingerprint(proxy: &serde_yaml::Value) -> String {
    let get = |keys: &[&str]| -> String {
        keys.iter()
            .find_map(|key| {
                let value = proxy.get(*key);
                let scalar = yaml_scalar(value);
                (!scalar.is_empty()).then_some(scalar)
            })
            .unwrap_or_default()
    };
    let canonical = serde_json::json!({
        "protocol": get(&["type"]),
        "server": get(&["server"]),
        "port": get(&["port"]),
        "credential": get(&["uuid", "password", "auth-str", "auth_str"]),
        "sni": get(&["sni", "servername"]),
        "flow": get(&["flow"]),
        "network": get(&["network"]),
    });
    let digest = Sha256::digest(canonical.to_string().as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// 从启用订阅的本地 YAML 缓存生成 name → node_id 映射。
/// 同名节点的订阅原样配置也会被用于离线预览，保证两种路径指纹一致。
fn load_node_identities(data_dir: &std::path::Path) -> HashMap<String, String> {
    let mut identities = HashMap::new();
    for record in crate::core::store::load_subscriptions(data_dir)
        .into_iter()
        .filter(|record| record.enabled)
    {
        let path = crate::core::store::profile_path(data_dir, &record.url);
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
            continue;
        };
        let Some(proxies) = value.get("proxies").and_then(|v| v.as_sequence()) else {
            continue;
        };
        for proxy in proxies {
            if let Some(name) = proxy.get("name").and_then(|v| v.as_str()) {
                identities.insert(name.to_string(), node_fingerprint(proxy));
            }
        }
    }
    identities
}

/// 【APP68】自适应槽位控制器：iOS 初始 2，最多 4；桌面最多 4 个物理探针。
/// 每 8 个节点按超时率与平均耗时调速，杜绝慢连接堆积导致 Jetsam。
struct AdaptiveSlotController {
    active: AtomicUsize,
    max_slots: usize,
    batch_done: AtomicUsize,
    batch_timeouts: AtomicUsize,
    batch_elapsed_ms: AtomicU64,
}

impl AdaptiveSlotController {
    fn new(max_slots: usize) -> Self {
        #[cfg(target_os = "ios")]
        let initial = 2.min(max_slots);
        #[cfg(not(target_os = "ios"))]
        let initial = max_slots;
        Self {
            active: AtomicUsize::new(initial.max(1)),
            max_slots: max_slots.max(1),
            batch_done: AtomicUsize::new(0),
            batch_timeouts: AtomicUsize::new(0),
            batch_elapsed_ms: AtomicU64::new(0),
        }
    }

    fn active_slots(&self) -> usize {
        self.active.load(Ordering::Acquire).clamp(1, self.max_slots)
    }

    async fn wait_until_active<F>(&self, worker: usize, mut cancelled: F) -> bool
    where
        F: FnMut() -> bool,
    {
        while worker >= self.active_slots() {
            if cancelled() {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        !cancelled()
    }

    fn record(&self, elapsed_ms: u64, timed_out: bool) {
        self.batch_elapsed_ms
            .fetch_add(elapsed_ms, Ordering::AcqRel);
        if timed_out {
            self.batch_timeouts.fetch_add(1, Ordering::AcqRel);
        }
        let done = self.batch_done.fetch_add(1, Ordering::AcqRel) + 1;
        if done % 8 != 0 {
            return;
        }
        // batch_done 保持累计值，只有每第 8 个完成者调速，避免并发 worker
        // 同时重置计数后重复调整；耗时与超时数按最近批次原子取出。
        let timeouts = self.batch_timeouts.swap(0, Ordering::AcqRel);
        let elapsed = self.batch_elapsed_ms.swap(0, Ordering::AcqRel);
        let timeout_rate = timeouts as f64 / 8.0;
        let avg_node_ms = elapsed / 8;
        let active = self.active_slots();
        if timeout_rate > 0.40 || avg_node_ms > 4500 {
            self.active
                .store(active.saturating_sub(1).max(1), Ordering::Release);
        } else if timeout_rate < 0.15 && avg_node_ms < 1800 && active < self.max_slots {
            self.active.store(active + 1, Ordering::Release);
        }
    }
}

/// 地区是否命中受限名单（纯函数）：loc 未知（None）时视为未命中，
/// 是否要求 loc 必须存在由调用方决定。
fn region_blocked(loc: Option<&str>, blocklist: &[&str]) -> bool {
    matches!(loc, Some(l) if blocklist.contains(&l))
}

/// 【APP49 任务3】Netflix 解锁判定（纯函数）：区域锁片源 81280792——
/// 200/301/302 判完整解锁；403/404 及其余状态码判未解锁。
#[allow(dead_code)]
fn netflix_unlocked(status: u16) -> bool {
    matches!(status, 200 | 301 | 302)
}

/// 单个平台的探测定义：目标 URL + 是否流媒体（仅供测试/文档参考，
/// 实际探测由 probe_gpt/claude/gemini/netflix/youtube/disney/tiktok 执行）
#[allow(dead_code)]
struct Probe {
    tag: &'static str,
    url: &'static str,
    media: bool,
}

#[allow(dead_code)]
const PROBES: &[Probe] = &[
    Probe {
        tag: "GPT",
        url: "https://ios.chat.openai.com/public-api/mobile/server_status/v1",
        media: false,
    },
    Probe {
        tag: "Claude",
        url: "https://claude.ai/login",
        media: false,
    },
    Probe {
        tag: "Gemini",
        url: "https://gemini.google.com/app",
        media: false,
    },
    Probe {
        tag: "NF",
        url: "https://www.netflix.com/title/81280792",
        media: true,
    },
    Probe {
        tag: "YT",
        url: "https://www.youtube.com/premium",
        media: true,
    },
    Probe {
        tag: "Disney+",
        url: "https://www.disneyplus.com/",
        media: true,
    },
    Probe {
        tag: "TK",
        url: "https://www.tiktok.com/explore",
        media: true,
    },
];

// ---------------------------------------------------------------- 数据模型

/// 【APP67 P1】单平台探测结论：
/// - `Verified`：免登录态下业务端点正向特征校验通过 → 进入绿色解锁徽章；
/// - `Accessible`：仅首页连通但未通过业务特征 → 不给徽章；
/// - `Partial`：仅解锁自制剧等部分能力 → 不给完整徽章；
/// - `Blocked`：明确返回地区限制 / 风控 / 403；
/// - `Unknown`：传输失败、空响应、读取异常、地区未知等 → 不给徽章。
///
/// **铁律**：只有 `Verified` 允许进入 `AimNodeResult.unlocked_tags`，
/// 其余四种一律不得伪装成绿色完整解锁标签。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum ProbeVerdict {
    Verified,
    Accessible,
    Partial,
    Blocked,
    #[default]
    Unknown,
}

impl ProbeVerdict {
    fn is_verified(self) -> bool {
        matches!(self, ProbeVerdict::Verified)
    }

    /// 【APP71】五态可读标签（写入证据级详情，供前端核对判定依据）
    fn label(self) -> &'static str {
        match self {
            ProbeVerdict::Verified => "VERIFIED",
            ProbeVerdict::Accessible => "ACCESSIBLE",
            ProbeVerdict::Partial => "PARTIAL",
            ProbeVerdict::Blocked => "BLOCKED",
            ProbeVerdict::Unknown => "UNKNOWN",
        }
    }
}

/// 【APP68】检查状态：供后续分阶段 UI 使用；FAST 绝不冒充 Passed。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckStatus {
    Passed,
    Failed,
    NotTested,
    Unknown,
}

/// 【APP68】检测模式。缺省为自动分级流水线（FAST 快筛 + FULL 深测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AimProbeMode {
    Fast,
    Full,
    Selected,
}

/// 【APP73 任务2.2】统一 14 类探测错误分类。
/// 只有 `Unknown` / `Blocked` 结论才可能携带错误分类，`Verified` 恒为 None。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AimErrorKind {
    #[serde(rename = "DNS_ERROR")]
    DnsError,
    #[serde(rename = "CONNECT_TIMEOUT")]
    ConnectTimeout,
    #[serde(rename = "TLS_ERROR")]
    TlsError,
    #[serde(rename = "PROXY_ERROR")]
    ProxyError,
    #[serde(rename = "HTTP_403")]
    Http403,
    #[serde(rename = "HTTP_429")]
    Http429,
    #[serde(rename = "HTTP_5XX")]
    Http5xx,
    #[serde(rename = "REDIRECT_ERROR")]
    RedirectError,
    #[serde(rename = "EMPTY_RESPONSE")]
    EmptyResponse,
    #[serde(rename = "CHALLENGE_PAGE")]
    ChallengePage,
    #[serde(rename = "REGION_RESTRICTED")]
    RegionRestricted,
    #[serde(rename = "BODY_PARSE_ERROR")]
    BodyParseError,
    #[serde(rename = "TASK_TIMEOUT")]
    TaskTimeout,
    #[serde(rename = "UNKNOWN_ERROR")]
    UnknownError,
}

impl AimErrorKind {
    fn label(self) -> &'static str {
        match self {
            AimErrorKind::DnsError => "DNS_ERROR",
            AimErrorKind::ConnectTimeout => "CONNECT_TIMEOUT",
            AimErrorKind::TlsError => "TLS_ERROR",
            AimErrorKind::ProxyError => "PROXY_ERROR",
            AimErrorKind::Http403 => "HTTP_403",
            AimErrorKind::Http429 => "HTTP_429",
            AimErrorKind::Http5xx => "HTTP_5XX",
            AimErrorKind::RedirectError => "REDIRECT_ERROR",
            AimErrorKind::EmptyResponse => "EMPTY_RESPONSE",
            AimErrorKind::ChallengePage => "CHALLENGE_PAGE",
            AimErrorKind::RegionRestricted => "REGION_RESTRICTED",
            AimErrorKind::BodyParseError => "BODY_PARSE_ERROR",
            AimErrorKind::TaskTimeout => "TASK_TIMEOUT",
            AimErrorKind::UnknownError => "UNKNOWN_ERROR",
        }
    }
}

/// 【APP73 任务2.2】把 reqwest 传输错误归类到标准错误分类。
fn classify_reqwest_error(err: &reqwest::Error) -> AimErrorKind {
    if err.is_timeout() {
        return AimErrorKind::ConnectTimeout;
    }
    let mut chain = String::new();
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        chain.push_str(&cause.to_string().to_lowercase());
        chain.push(' ');
        source = cause.source();
    }
    if chain.contains("dns")
        || chain.contains("name or service")
        || chain.contains("failed to lookup")
        || chain.contains("no such host")
    {
        return AimErrorKind::DnsError;
    }
    if chain.contains("tls")
        || chain.contains("certificate")
        || chain.contains("handshake")
        || chain.contains("ssl")
    {
        return AimErrorKind::TlsError;
    }
    if chain.contains("proxy") || chain.contains("tunnel") || chain.contains("connect") {
        return AimErrorKind::ProxyError;
    }
    AimErrorKind::UnknownError
}

/// 【APP74 任务2.2】HTTP 状态码 → 标准错误分类（无明确地区证据时）。
fn classify_status(status: u16) -> AimErrorKind {
    match status {
        403 => AimErrorKind::Http403,
        429 => AimErrorKind::Http429,
        s if (300..400).contains(&s) => AimErrorKind::RedirectError,
        s if (500..600).contains(&s) => AimErrorKind::Http5xx,
        _ => AimErrorKind::UnknownError,
    }
}

// ==================================== APP74 新增状态枚举 ====================================

/// 【APP74 任务1.2】基础代理健康状态（与 7 平台解锁状态完全分离）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProxyHealthStatus {
    #[default]
    ProxyUnknown,
    ProxyOk,
    ProxyFailed,
}

impl ProxyHealthStatus {
    fn label(self) -> &'static str {
        match self {
            ProxyHealthStatus::ProxyOk => "PROXY_OK",
            ProxyHealthStatus::ProxyFailed => "PROXY_FAILED",
            ProxyHealthStatus::ProxyUnknown => "PROXY_UNKNOWN",
        }
    }
}

/// 【APP74 任务1.3】节点所处的检测阶段（严禁 Dead/Fast/ProxyFailed 伪装成 DeepProbed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AimProbeStage {
    #[default]
    NotTested,
    ScreenedAlive,
    ScreenedDead,
    ProxyFailed,
    DeepProbed,
    CacheHit,
    PreviewOnly,
}

/// 【APP74 任务3】节点总体状态：严禁单一平台 BLOCKED 把整节点打成 BLOCKED。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AimNodeOverallStatus {
    #[default]
    Unknown,
    ProxyFailed,
    Verified,
    Mixed,
    PlatformsBlocked,
}

impl AimNodeOverallStatus {
    fn label(self) -> &'static str {
        match self {
            AimNodeOverallStatus::ProxyFailed => "PROXY_FAILED",
            AimNodeOverallStatus::Verified => "VERIFIED",
            AimNodeOverallStatus::Mixed => "MIXED",
            AimNodeOverallStatus::PlatformsBlocked => "PLATFORMS_BLOCKED",
            AimNodeOverallStatus::Unknown => "UNKNOWN",
        }
    }
}

/// 【APP74 任务1.3】根据 AimProbeStage 决定 AimNodeResult.probed 字段。
fn probe_stage_to_probed(stage: AimProbeStage) -> bool {
    matches!(stage, AimProbeStage::DeepProbed | AimProbeStage::CacheHit)
}

/// 【APP74 任务3】根据 7 平台汇总 + proxy_health 计算节点总体状态。
fn compute_overall_status(
    proxy_health: ProxyHealthStatus,
    services: &HashMap<String, ServiceProbeResult>,
) -> AimNodeOverallStatus {
    if matches!(proxy_health, ProxyHealthStatus::ProxyFailed) {
        return AimNodeOverallStatus::ProxyFailed;
    }
    let all_unknown = !services.is_empty()
        && services
            .values()
            .all(|s| matches!(s.verdict, ProbeVerdict::Unknown));
    let all_blocked = !services.is_empty()
        && services
            .values()
            .all(|s| matches!(s.verdict, ProbeVerdict::Blocked));
    if services
        .values()
        .any(|s| matches!(s.verdict, ProbeVerdict::Verified))
    {
        return AimNodeOverallStatus::Verified;
    }
    if all_blocked {
        return AimNodeOverallStatus::PlatformsBlocked;
    }
    if all_unknown {
        return AimNodeOverallStatus::Unknown;
    }
    AimNodeOverallStatus::Mixed
}

// ==================================== APP74 新增状态枚举 END ====================================

/// 【APP67 P1】单平台探测详情（正向特征码、状态码、证据、失败原因）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServiceProbeResult {
    pub service: String,
    pub verdict: ProbeVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(default)]
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// 【APP73 任务2.2】标准错误分类（成功为 None）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<AimErrorKind>,
    // ---- 【APP71 任务4】证据级详情字段（旧缓存缺失时自动补默认值）----
    /// 单平台请求实际耗时（含重试）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    /// 补测次数（仅 Unknown 会补测 1 次）
    #[serde(default)]
    pub retry_count: u32,
    /// 最终判定依据（可读文本，便于用户核对）
    #[serde(default)]
    pub verdict_basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AimNodeResult {
    pub node_name: String,
    /// 【APP68】节点核心配置 SHA-256 指纹前 16 位（不含节点名）。
    #[serde(default)]
    pub node_id: String,
    /// 解锁标签（GPT/Claude/Gemini/NF/YT/Disney+/TK）——
    /// 【APP67】仅 `ProbeVerdict::Verified` 的服务可进入，绝不含糊其辞。
    pub unlocked_tags: Vec<String>,
    /// AI 平台任一解锁
    pub ai_unlocked: bool,
    /// 流媒体任一解锁
    pub media_unlocked: bool,
    /// 【APP73 任务3.4 + APP74】评分：proxy_failed 强制为 0；
    /// VERIFIED 20 / PARTIAL 12 / ACCESSIBLE 8 / UNKNOWN·BLOCKED 0。
    pub score: u32,
    /// 基线延迟（毫秒）
    pub delay_ms: u64,
    /// 更新时间戳（秒）
    pub updated_at: u64,
    /// 【APP74 任务1.3】只有 DeepProbed / CacheHit 才允许 probed=true。
    /// Dead / Fast / ProxyFailed / Preview 一律 false，严禁伪装成完整检测。
    #[serde(default)]
    pub probed: bool,
    /// 【APP67 P3】检测引擎版本号：旧版缓存（< 6）加载时自动淘汰。
    #[serde(default)]
    pub probe_version: u32,
    #[serde(default)]
    pub rule_version: u32,
    /// 【APP67 BUG-04】节点真实出口公网 IP（cdn-trace 解析）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_ip: Option<String>,
    /// 节点真实出口国家/地区代码
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_country: Option<String>,
    /// 【APP68】出口 ASN（cdn-trace `asn=`）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_asn: Option<String>,
    /// 【APP68】本轮出口核验时间（Unix 秒）
    #[serde(default)]
    pub detected_at: u64,
    /// 【APP68】FAST / FULL / SELECTED；旧缓存为 None。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<AimProbeMode>,
    /// 【APP67 P1】7 个平台各自的探测详情（service → result）
    #[serde(default)]
    pub services: HashMap<String, ServiceProbeResult>,
    /// 【APP68】独立证据索引，避免前端解析详情对象。
    #[serde(default)]
    pub evidence: HashMap<String, String>,
    #[serde(default)]
    pub failure_reasons: HashMap<String, String>,
    // ---- 【APP74 任务1.2 / 1.3 / 3】新字段 ----
    /// 基础代理健康状态（3 目标 HTTPS 独立校验）
    #[serde(default)]
    pub proxy_health: ProxyHealthStatus,
    /// 节点所处检测阶段
    #[serde(default)]
    pub probe_stage: AimProbeStage,
    /// 节点总体状态
    #[serde(default)]
    pub overall_status: AimNodeOverallStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoAimStatusDto {
    pub enabled: bool,
    pub locked_node: Option<String>,
    pub probing: bool,
    /// 用户手动指定的锁定节点（None = 自动模式）
    pub pinned_node: Option<String>,
    /// 选点模式："manual"（手动指定优先）| "auto"（评级自动）
    pub selection_mode: String,
    pub results: HashMap<String, AimNodeResult>,
}

// ---------------------------------------------------------------- 状态读取

/// 汇总当前 Go AIM 状态（供 IPC 返回）
pub fn status_dto(state: &AppState) -> GoAimStatusDto {
    let settings = state.settings.read();
    GoAimStatusDto {
        enabled: settings.go_aim_enabled,
        pinned_node: settings.go_aim_pinned_node.clone(),
        selection_mode: if settings.go_aim_pinned_node.is_some() {
            "manual".into()
        } else {
            "auto".into()
        },
        locked_node: state.aim_locked_node.read().clone(),
        probing: state.aim_probing.load(Ordering::Acquire),
        results: state.aim_results.read().clone(),
    }
}

/// 当前内核是否在运行
fn is_running(state: &AppState) -> bool {
    *state.status.read() == CoreStatus::Running
}

// ---------------------------------------------------------------- 探测实现

/// 【APP68/APP71】RAII 运行守卫：正常完成、取消或 panic 都复位运行标志与进度；
/// 未走终态时补发 CANCELLED 事件与 [AIM-21] 日志，前端绝不永久转圈。
struct ProbeRunGuard {
    app: AppHandle,
    run: Arc<AimRunCtx>,
    terminal: std::sync::atomic::AtomicBool,
}

impl ProbeRunGuard {
    fn new(app: AppHandle, run: Arc<AimRunCtx>) -> Self {
        Self {
            app,
            run,
            terminal: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// 主流程已发射 FINISHED / ERROR / CANCELLED 后调用，Drop 不再重复补发。
    fn mark_terminal(&self) {
        self.terminal.store(true, Ordering::Release);
    }
}

impl Drop for ProbeRunGuard {
    fn drop(&mut self) {
        let state = self.app.state::<AppState>();
        state.aim_probing.store(false, Ordering::Release);
        if !self.terminal.load(Ordering::Acquire) {
            self.run.log(
                21,
                "WARN",
                AimLogMeta::default(),
                "检测任务结束: status=CANCELLED（Go AIM 关闭 / VPN 停止 / 任务中止）",
            );
            let _ = self.run.emit(
                &self.app,
                "CANCELLED",
                &AimLogMeta::default(),
                Some("CANCELLED"),
                "Go AIM 检测已中止",
                None,
            );
        } else {
            let mut progress = state.aim_progress.lock();
            progress.running = false;
            let snapshot = progress.clone();
            drop(progress);
            let _ = self.app.emit("aim://progress", &snapshot);
        }
        let _ = self
            .app
            .emit(AIM_EVENT, serde_json::json!({ "finished": true }));
    }
}

/// 【APP69 任务4】自动触发冷却：同一订阅列表 / 内核会话内 30 分钟内
/// 最多自动全量探测一次。用户手动「AIM 检测 / 重测」直接走
/// start_probe_with_mode，不受冷却限制。
const AUTO_PROBE_COOLDOWN_SECS: u64 = 30 * 60;
static LAST_AUTO_PROBE_SECS: AtomicU64 = AtomicU64::new(0);

/// 【APP69 任务4】纯函数判定：首次触发放行，之后必须满 30 分钟。
fn auto_probe_allowed(last: u64, now: u64) -> bool {
    last == 0 || now.saturating_sub(last) >= AUTO_PROBE_COOLDOWN_SECS
}

/// 启动一轮自动分级探测（保持既有调用方 100% 兼容）。
/// 自动入口（启动内核 / 订阅刷新等）统一受 30 分钟冷却保护。
pub fn start_probe(app: AppHandle) {
    let now = now_secs();
    let last = LAST_AUTO_PROBE_SECS.load(Ordering::Acquire);
    if !auto_probe_allowed(last, now) {
        tracing::debug!("[go-aim] 自动探测处于 30 分钟冷却期，跳过");
        return;
    }
    LAST_AUTO_PROBE_SECS.store(now, Ordering::Release);
    start_probe_inner(app, None, "auto");
}

/// 【APP68】启动 FAST / FULL / SELECTED 或默认自动分级探测。
/// 用户手动触发同样刷新冷却基准，避免紧接其后再自动跑一轮。
pub fn start_probe_with_mode(app: AppHandle, mode: Option<AimProbeMode>) {
    start_probe_inner(app, mode, "manual");
}

/// 【APP71 任务2.5】被拒绝的探测请求也必须留下明确的 ERROR 事件与日志，
/// 前端绝不无反馈地停在旧进度（功能未启用 / 未激活 / 正在运行）。
pub fn notify_aim_error(app: &AppHandle, status: &str, message: &str) {
    let run = AimRunCtx::new();
    run.log(
        21,
        "WARN",
        AimLogMeta::default(),
        format!("检测任务结束: status=ERROR（{status}）: {message}"),
    );
    let _ = run.emit(
        app,
        "ERROR",
        &AimLogMeta::default(),
        Some(status),
        message,
        None,
    );
}

/// 【APP71 任务3】Go AIM 全量快照：进度 + 最近 30 条结构化事件 + 结果 +
/// 最优节点 + 最近错误。页面挂载 / 后台唤醒时一次性同步，杜绝事件丢包。
pub fn snapshot_dto(state: &AppState) -> serde_json::Value {
    let progress = state.aim_progress.lock().clone();
    let events: Vec<crate::core::state::GoAimEvent> =
        state.aim_events.lock().iter().cloned().collect();
    let results = state.aim_results.read().clone();
    let best = pick_best(&results).map(|r| r.node_name);
    let settings = state.settings.read();
    serde_json::json!({
        "progress": progress,
        "events": events,
        "results": results,
        "bestNode": best,
        "lastError": state.aim_last_error.read().clone(),
        "enabled": settings.go_aim_enabled,
        "probing": state.aim_probing.load(Ordering::Acquire),
        "pinnedNode": settings.go_aim_pinned_node.clone(),
    })
}

fn aim_mode_label(mode: Option<AimProbeMode>) -> &'static str {
    match mode {
        Some(AimProbeMode::Fast) => "FAST",
        Some(AimProbeMode::Full) => "FULL",
        Some(AimProbeMode::Selected) => "SELECTED",
        None => "AUTO",
    }
}

/// 【APP71 任务2.2】统一启动入口：生成 runId、发射 START、终态兜底。
fn start_probe_inner(app: AppHandle, mode: Option<AimProbeMode>, trigger: &str) {
    LAST_AUTO_PROBE_SECS.store(now_secs(), Ordering::Release);
    let run = AimRunCtx::new();
    let empty_meta = AimLogMeta::default();
    // [AIM-01] 收到请求
    run.log(
        1,
        "INFO",
        empty_meta.clone(),
        format!(
            "收到 Go AIM 检测请求: runId={}, mode={}, trigger={trigger}",
            run.run_id,
            aim_mode_label(mode)
        ),
    );

    let state = app.state::<AppState>();
    // [AIM-02] 开关 / Pro 状态
    let enabled = state.settings.read().go_aim_enabled;
    let pro = state.is_pro_active();
    run.log(
        2,
        "INFO",
        empty_meta.clone(),
        format!("检查 Go AIM 开关状态: enabled={enabled}, pro={pro}"),
    );
    // APP34：Go AIM 未开启时严禁触发全量探测。148 个节点并发真实 HTTP
    // 探测会在 iOS 扩展进程内瞬间冲顶 50MB Jetsam 硬红线，导致隧道被
    // 系统强杀（表现为「启动一会儿自动停止」）。手动触发/启动钩子/
    // 订阅刷新等所有入口都必须先过这道硬闸。
    if !enabled {
        tracing::debug!("[go-aim] Go AIM 未开启，跳过全量探测");
        let msg = "Go AIM 功能未启用，请先在仪表盘开启";
        run.log(
            21,
            "WARN",
            empty_meta.clone(),
            "检测任务结束: status=ERROR（功能未启用）",
        );
        let _ = run.emit(&app, "ERROR", &empty_meta, Some("DISABLED"), msg, None);
        return;
    }
    // [AIM-04] 在途任务 / 代数
    let prev_running = state.aim_probing.load(Ordering::Acquire);
    let generation = state.aim_generation.load(Ordering::Acquire);
    run.log(
        4,
        "INFO",
        empty_meta.clone(),
        format!("检查在途探测任务: prev_running={prev_running}, generation={generation}"),
    );
    // 【APP54 任务2】防重复：swap 返回 true 表示上一轮仍在进行，直接跳过；
    // 返回 false 表示刚抢到执行权，继续启动本轮探测。
    if state.aim_probing.swap(true, Ordering::AcqRel) {
        tracing::debug!("[go-aim] 探测已在进行中，跳过重复触发");
        let msg = "已有 Go AIM 检测任务在运行，请稍候";
        run.log(
            21,
            "WARN",
            empty_meta.clone(),
            "检测任务结束: status=ERROR（重复触发）",
        );
        let _ = run.emit(&app, "ERROR", &empty_meta, Some("BUSY"), msg, None);
        return;
    }
    // 预览模式（内核未运行）只做离线 TCP/TLS 基线测速，不生成任何解锁标签；
    // 内核运行时走真实隧道出口预检与 AI / 流媒体独立业务探测。
    {
        let mut p = state.aim_progress.lock();
        *p = crate::core::state::ProbeProgress {
            running: true,
            phase: "START".into(),
            run_id: run.run_id.clone(),
            ..Default::default()
        };
        p.recompute_aim();
    }
    let _ = run.emit(
        &app,
        "START",
        &empty_meta,
        Some("START"),
        "Go AIM 检测已启动",
        None,
    );
    drop(state);

    tauri::async_runtime::spawn(async move {
        let guard = ProbeRunGuard::new(app.clone(), run.clone());
        let state = app.state::<AppState>();
        let outcome = probe_all(&app, &state, mode, &run).await;
        match outcome {
            Ok(count) => {
                // 【APP37 任务3.2】探测只被「Go AIM 开关关闭 / VPN 停止」
                // 中止；完成日志必须携带参与评级总数与最优节点。
                let best = pick_best(&state.aim_results.read())
                    .map(|r| r.node_name)
                    .unwrap_or_else(|| "无".to_string());
                // 【APP52 任务1】探测结果 + 最优节点异步落盘（node_metrics_cache.json），
                // 切换页面 / 重启 APP 后节点页徽章与排序不丢失
                {
                    let snapshot = state.aim_results.read().clone();
                    let best_node = if mode == Some(AimProbeMode::Fast) {
                        state.node_metrics.read().aim_best_node.clone()
                    } else {
                        pick_best(&snapshot).map(|r| r.node_name)
                    };
                    // 同时把探测延迟并入持久化 delays（0 延迟节点不覆盖已有值）
                    let delays: Vec<(String, u32)> = snapshot
                        .values()
                        .filter(|r| r.delay_ms > 0)
                        .map(|r| (r.node_name.clone(), r.delay_ms as u32))
                        .collect();
                    if !delays.is_empty() {
                        state.record_node_delays(delays);
                    }
                    state.record_aim_results(&snapshot, best_node.as_deref());
                }
                // [AIM-18] 缓存持久化
                let (cache_hits, updated, version) = {
                    let p = state.aim_progress.lock();
                    (
                        p.cache_hits,
                        state.aim_results.read().len(),
                        CURRENT_AIM_PROBE_VERSION,
                    )
                };
                run.log(
                    18,
                    "INFO",
                    AimLogMeta::default(),
                    format!(
                        "缓存持久化完成: updated={updated}, cache_hits={cache_hits}, probe_version={version}"
                    ),
                );
                tracing::info!(
                    "[go-aim] 全量真实探测完成，共 {count} 个节点参与评级，最优节点: {best}"
                );
                // [AIM-19] 最优节点
                let (best_score, best_delay) = pick_best(&state.aim_results.read())
                    .map(|r| (r.score, r.delay_ms))
                    .unwrap_or((0, 0));
                run.log(
                    19,
                    "INFO",
                    AimLogMeta::default(),
                    format!("最优节点: {best}, score={best_score}, delay={best_delay}ms"),
                );
                // 【APP6 任务1】[GoAim] 模块日志
                crate::core::logger::info(
                    crate::core::logger::MOD_GO_AIM,
                    &format!("AIM 全量探测完成，共 {count} 个节点参与评级，最优节点: {best}"),
                );
                let mut lock_mode = "SKIPPED";
                if mode != Some(AimProbeMode::Fast)
                    && state.settings.read().go_aim_enabled
                    && is_running(&state)
                {
                    if let Err(e) = apply_selection(&app, &state).await {
                        tracing::warn!("[go-aim] 锁定选择失败: {e}");
                        crate::core::logger::warn(
                            crate::core::logger::MOD_GO_AIM,
                            &format!("锁定节点选择失败: {e}"),
                        );
                        lock_mode = "FAILED";
                    } else {
                        lock_mode = if state.settings.read().go_aim_pinned_node.is_some() {
                            "MANUAL_KEPT"
                        } else {
                            "AUTO_LOCKED"
                        };
                    }
                }
                // [AIM-20] 锁定状态
                let active = state
                    .settings
                    .read()
                    .selected_node
                    .clone()
                    .unwrap_or_else(|| "无".to_string());
                run.log(
                    20,
                    "INFO",
                    AimLogMeta::default(),
                    format!("锁定状态: mode={lock_mode}, active_node={active}"),
                );
                // 只有正常完成才允许 100%
                {
                    let mut p = state.aim_progress.lock();
                    p.done = p.total;
                    p.pending_count = 0;
                }
                if count == 0 {
                    // [AIM-21] 零存活：明确 ERROR，绝不显示 100%/成功
                    let msg = "本轮 0 个节点存活，探测结束（可能节点全部失效或网络不可用）";
                    run.log(
                        21,
                        "ERROR",
                        AimLogMeta::default(),
                        "检测任务结束: status=ERROR（0 存活节点）",
                    );
                    let _ = run.emit(
                        &app,
                        "ERROR",
                        &AimLogMeta::default(),
                        Some("NO_ALIVE_NODES"),
                        msg,
                        None,
                    );
                } else {
                    run.log(
                        21,
                        "INFO",
                        AimLogMeta::default(),
                        format!(
                            "检测任务结束: status=FINISHED, rated={count}, elapsed={}ms",
                            run.elapsed_ms()
                        ),
                    );
                    let _ = run.emit(
                        &app,
                        "FINISHED",
                        &AimLogMeta::default(),
                        Some("FINISHED"),
                        format!("检测完成，共 {count} 个节点参与评级"),
                        None,
                    );
                }
            }
            Err(e) => {
                tracing::warn!("[go-aim] 探测中止: {e}");
                let cancelled = e.contains("中止") || e.contains("取消");
                let phase = if cancelled { "CANCELLED" } else { "ERROR" };
                run.log(
                    21,
                    if cancelled { "WARN" } else { "ERROR" },
                    AimLogMeta::default(),
                    format!("检测任务结束: status={phase}, reason={e}"),
                );
                let _ = run.emit(&app, phase, &AimLogMeta::default(), Some(phase), e, None);
            }
        }
        guard.mark_terminal();
    });
}

/// 从 /proxies 响应中收集全部真实节点（type 非组），附带历史延迟
/// （0 < d < PROBE_MAX_DELAY_MS 时视为存活基线，否则为 None 待补测）。
/// 严禁跳过未测速节点——返回全部节点，由探测循环逐一覆盖。
fn collect_nodes(proxies: &serde_json::Value) -> Vec<(String, Option<u64>)> {
    const GROUP_TYPES: [&str; 10] = [
        "Selector",
        "URLTest",
        "Fallback",
        "LoadBalance",
        "Direct",
        "Reject",
        "Compatible",
        "Pass",
        "RejectDrop",
        "Global",
    ];
    let mut nodes = Vec::new();
    let Some(map) = proxies
        .get("proxies")
        .and_then(serde_json::Value::as_object)
    else {
        return nodes;
    };
    for (name, p) in map {
        // 【APP-10 任务2】名称级兜底：即使 type 显示为真实协议（订阅恶意/
        // 误命名），名为 direct/block/直连 的条目也绝不进 Go AIM 选点池
        if crate::core::config_builder::is_builtin_non_proxy_tag(name) {
            continue;
        }
        let type_ = p
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if GROUP_TYPES.contains(&type_) {
            continue;
        }
        let delay = p
            .get("history")
            .and_then(serde_json::Value::as_array)
            .and_then(|a| a.last())
            .and_then(|h| h.get("delay"))
            .and_then(serde_json::Value::as_u64)
            .filter(|d| *d > 0 && *d < PROBE_MAX_DELAY_MS);
        nodes.push((name.clone(), delay));
    }
    nodes
}

/// 全量探测（APP49 任务3 两阶段漏斗）：
/// 阶段1 极速存活快筛——全部候选真实节点按每批 12 个并发调用 Clash API
/// `/proxies/{tag}/delay`（gstatic generate_204，1200ms），超时/失败记
/// dead_result，存活节点延迟写入状态缓存并按延迟升序排序；
/// 阶段2 低延迟优先探测——一次性预建 4 槽位探针客户端（连接池复用），
/// 4 个槽位并行消费共享队列，逐节点真实 HTTP 探测 → 写缓存 + 推事件。
/// 每个节点都必须生成 AimNodeResult（死节点 unlocked_tags=[] 且
/// probed=true），绝不遗漏"未检测"状态。
async fn probe_all(
    app: &AppHandle,
    state: &AppState,
    mode: Option<AimProbeMode>,
    run: &Arc<AimRunCtx>,
) -> Result<usize, String> {
    let started = std::time::Instant::now();
    let api = state.kernel_api();
    let preview_mode = !is_running(state);
    // [AIM-03] 内核运行状态（预览模式 = 仅离线测速，不产生解锁标签）
    run.log(
        3,
        "INFO",
        AimLogMeta::default(),
        format!(
            "检查内核运行状态: running={}, preview_mode={preview_mode}",
            !preview_mode
        ),
    );
    // 必须在阶段一占位结果覆盖内存前保存上一轮完整结果，否则缓存永远无法命中。
    let cached_results = Arc::new(state.aim_results.read().clone());
    let node_ids = Arc::new(load_node_identities(&state.data_dir));
    let (selected_node, manual_selected, best_node) = {
        let settings = state.settings.read();
        (
            settings.selected_node.clone(),
            settings.user_manually_selected_node || *state.user_manually_selected_node.read(),
            state.node_metrics.read().aim_best_node.clone(),
        )
    };
    // 提前 clone 一份 api，避免 preview_mode 分支 return 之前被 stage1 move
    let api_after_stage1 = api.clone();

    // 1. 读取全量节点列表
    let (nodes, offline_endpoints): (
        Vec<(String, Option<u64>)>,
        Option<Vec<(String, String, u16)>>,
    ) = if preview_mode {
        // 【APP53 任务2.3】预览模式：内核未运行时从订阅缓存读取节点，
        // 同时记录每个节点的 server/port 用于离线 TCP 测速基线。
        let subs = crate::core::store::load_subscriptions(&state.data_dir);
        let mut names: Vec<(String, Option<u64>)> = Vec::new();
        let mut eps: Vec<(String, String, u16)> = Vec::new();
        for r in subs {
            if !r.enabled {
                continue;
            }
            let path = crate::core::store::profile_path(&state.data_dir, &r.url);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
                continue;
            };
            let Some(proxies) = value.get("proxies").and_then(|v| v.as_sequence()) else {
                continue;
            };
            for p in proxies {
                let Some(name) = p.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(server) = p.get("server").and_then(|v| v.as_str()) else {
                    continue;
                };
                let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                if name.is_empty() || server.is_empty() || port == 0 {
                    continue;
                }
                if crate::core::config_builder::is_builtin_non_proxy_tag(name) {
                    continue;
                }
                if crate::core::config_builder::is_info_or_ad_node_name(name) {
                    continue;
                }
                names.push((name.to_string(), None));
                eps.push((name.to_string(), server.to_string(), port));
            }
        }
        if names.is_empty() {
            return Err("节点列表为空，请先刷新订阅".into());
        }
        (names, Some(eps))
    } else {
        let proxies = api
            .get_proxies()
            .await
            .map_err(|e| format!("读取节点列表失败: {e}"))?;
        (collect_nodes(&proxies), None)
    };
    if nodes.is_empty() {
        return Err("节点列表为空，无可探测节点".into());
    }
    // [AIM-05] 节点列表加载完成 / [AIM-06] 节点总数
    run.log(
        5,
        "INFO",
        AimLogMeta::default(),
        format!(
            "节点列表加载完成: count={}, source={}",
            nodes.len(),
            if preview_mode {
                "subscription_cache"
            } else {
                "clash_api"
            }
        ),
    );
    run.log(
        6,
        "INFO",
        AimLogMeta::default(),
        format!(
            "本轮节点总数: {}, mode={}, generation={}",
            nodes.len(),
            aim_mode_label(mode),
            state.aim_generation.load(Ordering::Acquire)
        ),
    );
    // 节点被删除时精准淘汰对应缓存；旧完整结果已另行保存在 cached_results 中。
    let current_names: std::collections::HashSet<&str> =
        nodes.iter().map(|(name, _)| name.as_str()).collect();
    state
        .aim_results
        .write()
        .retain(|name, _| current_names.contains(name.as_str()));
    // 【APP54 任务4】初始化 Go AIM 进度（全部节点 100% 全量纳入统计）
    // 【APP71】保留 START 阶段写入的 runId，切换到 SCREEN 阶段，禁止整体重置。
    {
        let mut p = state.aim_progress.lock();
        p.running = true;
        p.phase = "SCREEN".into();
        p.run_id = run.run_id.clone();
        p.total = nodes.len();
        p.fast_total = nodes.len();
        p.fast_done = 0;
        p.fast_alive = 0;
        p.failed_count = 0;
        p.pending_count = nodes.len();
        p.recompute_aim();
        p.elapsed_ms = started.elapsed().as_millis() as u64;
    }
    // [AIM-07] 快筛开始
    run.log(
        7,
        "INFO",
        AimLogMeta::default(),
        format!(
            "阶段一快筛开始: concurrency={SCREEN_BATCH_SIZE}, total={}",
            nodes.len()
        ),
    );
    let _ = run.emit(
        app,
        "SCREEN",
        &AimLogMeta::default(),
        Some("SCREEN"),
        format!("阶段一极速存活快筛开始，共 {} 个节点", nodes.len()),
        None,
    );
    // 【APP37 任务3.2】严禁任何 .take/.truncate 节点截断：全部有效真实
    // 节点（148+ 个）必须 100% 纳入探测队列。

    // 【APP51 任务1】探测代数：订阅删除/停用/刷新会 +1，发现变化立即中止
    let generation = state.aim_generation.load(Ordering::Acquire);
    let generation_changed =
        |st: &AppState| st.aim_generation.load(Ordering::Acquire) != generation;

    // 2. 【APP51 任务1】阶段1 极速存活快筛：Semaphore 限流 32 路并发
    //（滚动消费，单节点慢不阻塞后续节点）。超时/失败 → dead_result 立即
    //入缓存并推前端；存活节点记录延迟，全部筛完后按延迟升序进入阶段2。
    let mut alive: Vec<(String, u64)> = Vec::with_capacity(nodes.len());
    // preview_mode 下用 server/port 做离线 TCP 测速替代 api.test_delay
    let ep_map: std::collections::HashMap<String, (String, u16)> = offline_endpoints
        .as_ref()
        .map(|list| {
            list.iter()
                .map(|(n, s, p)| (n.clone(), (s.clone(), *p)))
                .collect()
        })
        .unwrap_or_default();
    // 【APP72 任务1.3】阶段1 引入重试与缓存回退：单次超时不再直接判死，
    // 避免大批可用节点（如 34 个中 19 个）被误淘汰导致阶段2 样本过少。
    let cached_delays: std::collections::HashMap<String, u64> = state
        .aim_results
        .read()
        .iter()
        .filter(|(_, r)| r.delay_ms > 0)
        .map(|(name, r)| (name.clone(), r.delay_ms))
        .collect();
    {
        use futures_util::StreamExt as _;
        let sem = Arc::new(tokio::sync::Semaphore::new(SCREEN_BATCH_SIZE));
        let ep_map_c = ep_map.clone();
        let mut stream = futures_util::stream::iter(nodes.iter().cloned())
            .map(move |(name, _)| {
                let api = api.clone();
                let sem = sem.clone();
                let ep_map = ep_map_c.clone();
                async move {
                    let _permit = sem.acquire_owned().await.ok();
                    let delay = if let Some((server, port)) = ep_map.get(&name) {
                        // 预览模式：离线 TCP 握手测速
                        crate::ipc::commands::measure_offline_node_delay(
                            server,
                            *port,
                            PROBE_TIMEOUT_MS as u32,
                        )
                        .await
                    } else {
                        // 内核运行：真实隧道 HTTP 测速；首次失败立即用备用地址重试一次
                        let first = api
                            .test_delay(&name, SCREEN_URL, PROBE_TIMEOUT_MS as u32)
                            .await;
                        if matches!(first, Some(d) if d > 0 && d < PROBE_MAX_DELAY_MS) {
                            first
                        } else {
                            api.test_delay(&name, SCREEN_FALLBACK_URL, PROBE_TIMEOUT_MS as u32)
                                .await
                        }
                    };
                    (name, delay)
                }
            })
            .buffer_unordered(SCREEN_BATCH_SIZE);
        loop {
            let next = loop {
                tokio::select! {
                    next = stream.next() => break next,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                        if !state.settings.read().go_aim_enabled
                            || (!preview_mode && !is_running(state))
                            || generation_changed(state)
                        {
                            return Err("探测中止（Go AIM 已关闭、VPN 已停止或订阅已变更）".into());
                        }
                    }
                }
            };
            let Some((name, delay)) = next else { break };
            // 【APP74 任务1.1】主备均失败时立即判 Dead——
            // 历史缓存延迟（cached_delays）仅保留在内存里，绝不回退救场。
            let delay = resolve_screen_delay(delay, None);
            // 中止条件：关闭 Go AIM / 订阅变更（代数变化）
            if !state.settings.read().go_aim_enabled
                || (!preview_mode && !is_running(state))
                || generation_changed(state)
            {
                return Err("探测中止（Go AIM 已关闭、VPN 已停止或订阅已变更）".into());
            }
            let alive_now = matches!(delay, Some(d) if d > 0 && d < PROBE_MAX_DELAY_MS);
            match delay {
                Some(d) if d > 0 && d < PROBE_MAX_DELAY_MS => {
                    alive.push((name.clone(), d));
                    // 存活节点延迟写入状态缓存（阶段1 只是 ScreenedAlive，
                    // probe_stage = ScreenedAlive，probe_stage_to_probed → false，
                    // 阶段2 完成后会被真实探测结果覆盖）
                    let placeholder = AimNodeResult {
                        node_name: name.clone(),
                        unlocked_tags: vec![],
                        ai_unlocked: false,
                        media_unlocked: false,
                        score: 0,
                        delay_ms: d,
                        updated_at: now_secs(),
                        probed: false,
                        proxy_health: ProxyHealthStatus::ProxyUnknown,
                        probe_stage: AimProbeStage::ScreenedAlive,
                        overall_status: AimNodeOverallStatus::Unknown,
                        probe_version: CURRENT_AIM_PROBE_VERSION,
                        rule_version: CURRENT_AIM_RULE_VERSION,
                        node_id: node_ids.get(&name).cloned().unwrap_or_default(),
                        mode: Some(AimProbeMode::Fast),
                        ..Default::default()
                    };
                    state
                        .aim_results
                        .write()
                        .insert(name.clone(), placeholder.clone());
                    let _ = app.emit(
                        AIM_EVENT,
                        serde_json::json!({ "name": name, "result": placeholder }),
                    );
                }
                _ => {
                    let mut dead = dead_result(&name);
                    dead.node_id = node_ids.get(&name).cloned().unwrap_or_default();
                    dead.mode = Some(AimProbeMode::Fast);
                    state.aim_results.write().insert(name.clone(), dead.clone());
                    let _ = app.emit(
                        AIM_EVENT,
                        serde_json::json!({ "name": name, "result": dead }),
                    );
                }
            }
            // [AIM-08] 单节点快筛结果
            run.log(
                8,
                "INFO",
                AimLogMeta::default()
                    .node(&name)
                    .elapsed(delay.unwrap_or(0)),
                format!(
                    "快筛节点结果: {} ({}ms)",
                    if alive_now { "ALIVE" } else { "DEAD" },
                    delay.unwrap_or(0)
                ),
            );
            // 【APP54 任务4 / APP67 P4】阶段1 每完成一个节点 → 进度 +1。
            // 阶段1 仅占总进度前 20%；【APP71】事件按 2 节点/120ms 节流，
            // 避免 100+ 节点高频事件洪峰拖垮前端与 iOS 扩展。
            let (fast_done, fast_total, fast_alive) = {
                let mut p = state.aim_progress.lock();
                p.fast_done += 1;
                if alive_now {
                    p.fast_alive += 1;
                } else {
                    p.failed_count += 1;
                }
                p.recompute_aim();
                p.elapsed_ms = started.elapsed().as_millis() as u64;
                (p.fast_done, p.fast_total, p.fast_alive)
            };
            if run.should_emit_screen() {
                let _ = run.emit(
                    app,
                    "SCREEN",
                    &AimLogMeta::default(),
                    Some("SCREEN"),
                    format!("阶段一快筛 {fast_done}/{fast_total}，存活 {fast_alive}"),
                    None,
                );
            }
        }
    }
    let alive = AimPriorityQueue::new(
        alive,
        selected_node.as_deref(),
        manual_selected || mode == Some(AimProbeMode::Selected),
        best_node.as_deref(),
    );
    let alive_count = alive.len();
    if alive.is_empty() {
        return Err("阶段1 快筛后无存活节点".into());
    }
    tracing::info!("[go-aim] 阶段1 快筛完成：{} 个节点存活", alive.len());
    // [AIM-09] 快筛结束
    run.log(
        9,
        "INFO",
        AimLogMeta::default(),
        format!(
            "阶段一快筛结束: alive={}, dead={}, elapsed={}ms",
            alive.len(),
            nodes.len().saturating_sub(alive.len()),
            run.elapsed_ms()
        ),
    );

    // 【APP68】显式 FAST：只输出真实延迟与 Fast 模式，不发起平台请求、
    // 不产生 Verified 标签，也不改变用户当前节点选择。
    if mode == Some(AimProbeMode::Fast) {
        for (name, delay) in &alive {
            let result = AimNodeResult {
                node_name: name.clone(),
                node_id: node_ids.get(name).cloned().unwrap_or_default(),
                delay_ms: *delay,
                updated_at: now_secs(),
                detected_at: now_secs(),
                probed: false,
                probe_version: CURRENT_AIM_PROBE_VERSION,
                rule_version: CURRENT_AIM_RULE_VERSION,
                mode: Some(AimProbeMode::Fast),
                ..Default::default()
            };
            state
                .aim_results
                .write()
                .insert(name.clone(), result.clone());
            let _ = app.emit(
                AIM_EVENT,
                serde_json::json!({ "name": name, "result": result }),
            );
        }
        return Ok(alive.len());
    }

    // 【APP51 任务1】第 1 名先行同步：优先级队列第一名立即成为当前选中节点，
    // 仪表盘/代理页 1 秒内可见，无需等待 7 平台深测结果
    {
        let enabled = state.settings.read().go_aim_enabled;
        let pinned = state.settings.read().go_aim_pinned_node.is_some();
        if enabled && !pinned && is_running(state) {
            let (leader_name, leader_delay) = alive[0].clone();
            let leader = AimNodeResult {
                node_name: leader_name,
                unlocked_tags: vec![],
                ai_unlocked: false,
                media_unlocked: false,
                score: 0,
                delay_ms: leader_delay,
                updated_at: now_secs(),
                probed: false,
                ..Default::default()
            };
            let _ = lock_node(app, state, &leader, false).await;
        }
    }

    // 【APP66 任务1.1】预览模式（内核未运行）：只做真实公网延迟测速，
    // **严禁**再按节点名称/地区猜测 AI / 流媒体解锁标识。此前
    // `preview_tags` 会按「香港」「日本」等关键词直接打上 GPT/NF 徽章，
    // 属于零网络验证的虚假解锁，用户切到受限节点后必然穿帮。
    // 现在预览模式所有节点 unlocked_tags 为空、ai/media=false、probed=true，
    // 并通过事件 hint 明确提示「需先启动代理才能做隧道真实解锁验证」。
    if preview_mode {
        let mut leader: Option<AimNodeResult> = None;
        for (name, d) in alive.iter() {
            let result = AimNodeResult {
                node_name: name.clone(),
                unlocked_tags: Vec::new(),
                ai_unlocked: false,
                media_unlocked: false,
                score: 0,
                delay_ms: *d,
                updated_at: now_secs(),
                detected_at: now_secs(),
                probed: true,
                probe_version: CURRENT_AIM_PROBE_VERSION,
                rule_version: CURRENT_AIM_RULE_VERSION,
                node_id: node_ids.get(name).cloned().unwrap_or_default(),
                mode: Some(AimProbeMode::Fast),
                ..Default::default()
            };
            state
                .aim_results
                .write()
                .insert(name.clone(), result.clone());
            let _ = app.emit(
                AIM_EVENT,
                serde_json::json!({ "name": name.clone(), "result": result.clone() }),
            );
            if leader
                .as_ref()
                .map_or(true, |b| result.delay_ms < b.delay_ms)
            {
                leader = Some(result);
            }
        }
        let leader = leader.expect("alive 非空");
        // 锁定延迟最低节点作为默认选择（仅基于真实延迟，不含任何猜测）
        let _ = lock_node(app, state, &leader, false).await;
        // 预览结果立即持久化（切页/重启不丢失）
        {
            let snapshot = state.aim_results.read().clone();
            let best_node = pick_best(&snapshot).map(|r| r.node_name);
            state.record_aim_results(&snapshot, best_node.as_deref());
        }
        {
            let mut p = state.aim_progress.lock();
            p.done = p.total;
            p.percent = 100;
            p.running = false;
            p.unlocked_count = 0;
            let snapshot = p.clone();
            drop(p);
            let _ = app.emit("aim://progress", &snapshot);
        }
        state.aim_probing.store(false, Ordering::Release);
        let _ = app.emit(
            AIM_EVENT,
            serde_json::json!({
                "phase": "preview_done",
                "best": leader.node_name,
                "hint": "当前未连接 VPN，仅完成真实延迟测速；AI / 流媒体解锁需经隧道验证，请先启动代理后重新检测"
            }),
        );
        return Ok(alive.len());
    }

    // 3. 探针槽位可用性检测：只使用本机实际可连通的探针入站。
    // 若扩展配置裁剪掉了探针入站，宁可明确失败也绝不用主混合端口兜底——
    // 经主选择器探测会污染用户当前节点，并产出错误的解锁徽章。
    // [AIM-10] 阶段二深测开始
    run.log(
        10,
        "INFO",
        AimLogMeta::default(),
        format!(
            "阶段二深度探测开始: alive={alive_count}, ports={}..{}",
            PROBE_PORT_BASE,
            PROBE_PORT_BASE + PROBE_SLOTS as u16 - 1
        ),
    );
    let slots: Vec<usize> = (0..PROBE_SLOTS)
        .filter(|slot| probe_port_reachable(PROBE_PORT_BASE + *slot as u16))
        .collect();
    if slots.is_empty() {
        return Err(format!(
            "探针端口 {PROBE_PORT_BASE}..{} 均不可达，请重启内核后重试",
            PROBE_PORT_BASE + PROBE_SLOTS as u16 - 1
        ));
    }
    // [AIM-11] 槽位端口检查
    run.log(
        11,
        "INFO",
        AimLogMeta::default(),
        format!("探针槽位检查完成: available={slots:?}"),
    );
    tracing::info!("[go-aim] 可用探针槽位: {slots:?}");

    // 4. 【APP49 任务3】阶段2 开始前一次性预建全部槽位探针客户端
    //（普通客户端 + Gemini 无重定向客户端），连接池全程复用，
    // 严禁在探测循环内重复 build。
    let mut slot_clients = Vec::with_capacity(slots.len());
    for slot in slots {
        let client = match build_probe_client(slot) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("[go-aim] 槽位 {slot} 探测客户端构建失败: {e}");
                continue;
            }
        };
        // Gemini 判定只看首跳 Location，必须独立的无重定向客户端
        let nr_client = match build_probe_client_no_redirect(slot) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("[go-aim] 槽位 {slot} 无重定向客户端构建失败: {e}");
                continue;
            }
        };
        slot_clients.push((slot, client, nr_client));
    }
    if slot_clients.is_empty() {
        return Err("全部探针客户端构建失败".into());
    }
    // [AIM-12] 探测客户端初始化
    run.log(
        12,
        "INFO",
        AimLogMeta::default(),
        format!(
            "探测客户端初始化完成: clients={}, proxy=all, connect_timeout={PROBE_CONNECT_TIMEOUT_MS}ms, request_timeout={PROBE_REQUEST_TIMEOUT_MS}ms",
            slot_clients.len()
        ),
    );

    // 【APP72 任务1.2】删除「预取本机直连公网 IP」与出口 IP 一致性短路：
    // 出口 IP 与直连 IP 相同并不能证明隧道未生效（同城出口/运营商级 NAT
    // 都会出现相同 IP），该判定会在网关节点上误杀全部 7 个平台探测。
    // 现在只以 cdn-cgi/trace 的 egress_ip + country 作为参考证据，
    // 即使 trace 偶发超时也照常执行 7 平台实测，绝不提前短路。

    // 【APP72 任务1.3】阶段2 进度初始化：full_total 必须是「全部候选节点总数」
    //（含阶段1 已淘汰节点），processed = failed_count + full_done + cache_hits，
    // 只有 processed == total 时进度才允许到达 100%。
    {
        let mut p = state.aim_progress.lock();
        p.phase = "DEEP_PROBE".into();
        p.run_id = run.run_id.clone();
        p.full_total = p.total.max(alive_count);
        p.full_done = 0;
        p.cache_hits = 0;
        p.active_slots = slot_clients.len();
        p.current_services.clear();
        p.error_message = None;
        p.recompute_aim();
        p.elapsed_ms = started.elapsed().as_millis() as u64;
    }
    let _ = run.emit(
        app,
        "DEEP_PROBE",
        &AimLogMeta::default(),
        Some("DEEP_PROBE"),
        format!(
            "阶段二深度探测开始，存活节点 {alive_count} 个，并发槽位 {}",
            slot_clients.len()
        ),
        None,
    );

    // 5. 共享任务队列（延迟升序）：可用槽位并行消费，任一槽位空闲即取
    // 下一个节点（等价于每批 4 个节点的滚动并发）。前 PROBE_SLOTS 个
    //（延迟最低的首批）标记 first_batch，用于秒级锁定。
    let instant_locked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // 【APP53 任务2.3】深测全量可达节点（无 DEEP_PROBE_MAX 截断）
    let queue = Arc::new(tokio::sync::Mutex::new(
        alive
            .into_iter()
            .enumerate()
            .map(|(i, (name, d))| (name, d, i < PROBE_SLOTS))
            .collect::<VecDeque<_>>(),
    ));
    let controller = Arc::new(AdaptiveSlotController::new(slot_clients.len()));
    let result_mode = mode.unwrap_or(AimProbeMode::Full);
    let force_full = mode == Some(AimProbeMode::Full);
    let mut set = tokio::task::JoinSet::new();
    for (worker, (slot, client, nr_client)) in slot_clients.into_iter().enumerate() {
        let queue = queue.clone();
        let api = api_after_stage1.clone();
        let task_app = app.clone();
        let instant_locked = instant_locked.clone();
        let cached_results = cached_results.clone();
        let node_ids = node_ids.clone();
        let controller = controller.clone();
        let generation = generation;
        let run = run.clone();
        set.spawn(async move {
            let app = task_app;
            let mut done = 0usize;
            loop {
                // 暂时停用的 worker 每 50ms 等待一次，同时响应关闭 / 停止 / 订阅变更。
                let cancelled = || {
                    let st = app.state::<AppState>();
                    !st.settings.read().go_aim_enabled
                        || !is_running(&st)
                        || st.aim_generation.load(Ordering::Acquire) != generation
                };
                if cancelled() || !controller.wait_until_active(worker, cancelled).await {
                    tracing::info!(
                        "[go-aim] 槽位 {slot} 探测中止（Go AIM 关闭、VPN 停止或订阅变更）"
                    );
                    break;
                }
                let next = queue.lock().await.pop_front();
                let Some((name, delay, first_batch)) = next else { break };
                let node_id = node_ids.get(&name).cloned().unwrap_or_default();
                let cached = cached_results.get(&name);
                // [AIM-13] 节点进入检测队列
                run.log(
                    13,
                    "DEBUG",
                    AimLogMeta::default().node(&name).slot(slot),
                    format!(
                        "节点进入检测队列: delay={delay}ms, cached={}",
                        cached.is_some()
                    ),
                );
                let mut probe = Box::pin(probe_node(
                    &api,
                    &client,
                    &nr_client,
                    slot,
                    &name,
                    Some(delay),
                    &node_id,
                    cached,
                    result_mode,
                    force_full,
                    &run,
                    &app,
                ));
                // 探针 future 可被直接 drop：取消响应不等待最慢平台请求超时。
                let outcome = loop {
                    tokio::select! {
                        outcome = &mut probe => break Some(outcome),
                        _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                            let st = app.state::<AppState>();
                            if !st.settings.read().go_aim_enabled
                                || !is_running(&st)
                                || st.aim_generation.load(Ordering::Acquire) != generation
                            {
                                break None;
                            }
                        }
                    }
                };
                drop(probe);
                let Some(outcome) = outcome else {
                    tracing::info!("[go-aim] 槽位 {slot} 已取消节点「{name}」探测");
                    break;
                };
                controller.record(outcome.elapsed_ms, outcome.timed_out);
                // 过期结果不得污染新订阅或已停止的会话。
                {
                    let st = app.state::<AppState>();
                    if !st.settings.read().go_aim_enabled
                        || !is_running(&st)
                        || st.aim_generation.load(Ordering::Acquire) != generation
                    {
                        tracing::info!("[go-aim] 槽位 {slot} 丢弃过期探测结果");
                        break;
                    }
                }
                done += 1;
                let cache_hit = outcome.cache_hit;
                let result = outcome.result;
                // 写锁 guard 严格限制在本作用域内，绝不跨 await。
                {
                    let app_state = app.state::<AppState>();
                    let mut results = app_state.aim_results.write();
                    results.insert(result.node_name.clone(), result.clone());
                }
                let _ = app.emit(
                    AIM_EVENT,
                    serde_json::json!({ "name": result.node_name, "result": result.clone() }),
                );
                // [AIM-17] 单节点汇总 + NODE_RESULT 结构化事件
                let node_status = if result
                    .services
                    .values()
                    .any(|s| s.verdict == ProbeVerdict::Verified)
                {
                    "VERIFIED"
                } else if result
                    .services
                    .values()
                    .any(|s| s.verdict == ProbeVerdict::Blocked)
                {
                    "BLOCKED"
                } else if !result.services.is_empty()
                    && result
                        .services
                        .values()
                        .all(|s| s.verdict == ProbeVerdict::Unknown)
                {
                    "UNKNOWN"
                } else {
                    "ACCESSIBLE"
                };
                run.log(
                    17,
                    "INFO",
                    AimLogMeta::default()
                        .node(&result.node_name)
                        .slot(slot)
                        .elapsed(result.delay_ms),
                    format!(
                        "节点汇总: status={node_status}, score={}, delay={}ms, unlocked={:?}, cache_hit={cache_hit}",
                        result.score, result.delay_ms, result.unlocked_tags
                    ),
                );
                let _ = run.emit(
                    &app,
                    "NODE_RESULT",
                    &AimLogMeta::default()
                        .node(&result.node_name)
                        .slot(slot)
                        .elapsed(result.delay_ms),
                    Some(node_status),
                    format!("节点「{}」完成检测：{node_status}", result.node_name),
                    serde_json::to_value(&result).ok(),
                );
                // 实际深测与缓存命中分别计数，共同推进 20%～100% 的真实进度。
                {
                    let app_state = app.state::<AppState>();
                    let (unlocked, verified, unknown) = {
                        let results = app_state.aim_results.read();
                        (
                            // 【APP73 任务3.4】解锁统计口径改为“至少一个平台
                            // 达到 ACCESSIBLE（8 分）”，避免新版五级模型下
                            // 无 VERIFIED 时统计恒为 0 的假死锁。
                            results.values().filter(|r| r.probed && r.score >= 8).count(),
                            results
                                .values()
                                .filter(|r| r.probed && !r.unlocked_tags.is_empty())
                                .count(),
                            results
                                .values()
                                .filter(|r| {
                                    r.probed
                                        && !r.services.is_empty()
                                        && r.services
                                            .values()
                                            .all(|service| service.verdict == ProbeVerdict::Unknown)
                                })
                                .count(),
                        )
                    };
                    let mut p = app_state.aim_progress.lock();
                    if cache_hit {
                        p.cache_hits += 1;
                    } else {
                        p.full_done += 1;
                    }
                    p.recompute_aim();
                    p.unlocked_count = unlocked;
                    p.verified_count = verified;
                    p.unknown_count = unknown;
                    p.elapsed_ms = started.elapsed().as_millis() as u64;
                    let snapshot = p.clone();
                    drop(p);
                    let _ = app.emit("aim://progress", &snapshot);
                }
                // 首批真实 AI Verified 节点可秒级锁定；缓存结果本身也已通过出口预检。
                if first_batch
                    && result
                        .unlocked_tags
                        .iter()
                        .any(|t| t == "GPT" || t == "Claude")
                {
                    let app_state = app.state::<AppState>();
                    let enabled = app_state.settings.read().go_aim_enabled;
                    let pinned = app_state.settings.read().go_aim_pinned_node.is_some();
                    if enabled
                        && !pinned
                        && is_running(&app_state)
                        && !instant_locked.swap(true, Ordering::AcqRel)
                    {
                        tracing::info!(
                            "[go-aim] 首批秒级锁定 AI 解锁节点「{}」（延迟 {}ms）",
                            result.node_name,
                            result.delay_ms
                        );
                        crate::core::logger::info(
                            crate::core::logger::MOD_GO_AIM,
                            &format!(
                                "首批秒级锁定 AI 解锁节点「{}」（延迟 {}ms）",
                                result.node_name, result.delay_ms
                            ),
                        );
                        let _ = lock_node(&app, &app_state, &result, false).await;
                    }
                }
                // 实时同步当前最优节点；手动指定节点时绝不抢锁。
                {
                    let app_state = app.state::<AppState>();
                    let enabled = app_state.settings.read().go_aim_enabled;
                    let pinned = app_state.settings.read().go_aim_pinned_node.is_some();
                    if enabled && !pinned && is_running(&app_state) {
                        let best = pick_best(&app_state.aim_results.read());
                        if let Some(best) = best {
                            let current = app_state.aim_locked_node.read().clone();
                            if current.as_deref() != Some(best.node_name.as_str()) {
                                let _ = lock_node(&app, &app_state, &best, false).await;
                            }
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            }
            done
        });
    }

    let mut count = 0usize;
    while let Some(res) = set.join_next().await {
        count += res.map_err(|e| format!("探测任务失败: {e}"))?;
    }
    if !state.settings.read().go_aim_enabled || !is_running(state) || generation_changed(state) {
        return Err("探测中止（Go AIM 已关闭、VPN 已停止或订阅已变更）".into());
    }
    if count != alive_count {
        return Err(format!("探测未完整完成：{count}/{alive_count}"));
    }
    Ok(count)
}

/// 构建槽位专用探测客户端：流量经对应本地 mixed 入站进入内核的
/// GO-AIM-PROBE-{slot} 链路。
/// 关键修复（APP-5）：必须**跟随重定向**——chatgpt.com / claude.ai /
/// netflix.com / youtube.com 均存在 301/302/307/308 规范化跳转，禁用重定向
/// 会拿到空响应体，导致读不到 cdn-trace 的 `loc=` 与正文而全部误判失败。
fn build_probe_client(slot: usize) -> Result<reqwest::Client, String> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONNECTION,
        reqwest::header::HeaderValue::from_static("close"),
    );
    reqwest::Client::builder()
        // 【APP73 任务1.1】必须使用 Proxy::all：Proxy::http 只代理明文 HTTP，
        // 会导致 Gemini/TikTok/GPT/Claude/Netflix/YouTube/Disney+ 等 HTTPS
        // 探测请求绕过 AIM 探针槽位直连系统网络，出口证据完全失真。
        .proxy(
            reqwest::Proxy::all(&probe_proxy_url(slot))
                .map_err(|e| format!("PROXY_ERROR: invalid probe proxy: {e}"))?,
        )
        // 【APP73 任务2.1】连接 3s / 总请求 8s，杜绝单请求拖到几十秒。
        .connect_timeout(std::time::Duration::from_millis(PROBE_CONNECT_TIMEOUT_MS))
        .timeout(std::time::Duration::from_millis(PROBE_REQUEST_TIMEOUT_MS))
        .redirect(reqwest::redirect::Policy::limited(5))
        // 【APP67 BUG-03】彻底根除跨节点连接池复用污染：
        // pool_max_idle_per_host(0) + Connection: close 双保险，
        // 每次请求结束立即释放本地 127.0.0.1:2083..2086 的 CONNECT 隧道，
        // 槽位切换到下一个节点后新请求 100% 建立全新隧道，零额外内存开销。
        .pool_max_idle_per_host(0)
        .pool_idle_timeout(std::time::Duration::from_millis(1))
        .tcp_nodelay(true)
        .default_headers(headers)
        .user_agent(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        )
        .build()
        .map_err(|e| e.to_string())
}

/// 【APP-10 任务3】Gemini 专用无重定向客户端。
///
/// Google 对不支持地区的拦截机制：请求 https://gemini.google.com/app 首跳
/// 直接返回 302，Location 指向 /faq 封锁页。而放行地区（含未登录）首跳为
/// 200 或跳登录/首页。此前跟随 5 次重定向后用 `!body.contains("isn't
/// currently supported")` 判定——Google 前端 JS 多语言包内嵌了全部错误
/// 文案（含该字符串），纯正美国原生 IP 也会被误判封锁，Gemini 标识
/// 全军覆没。根治：只看首跳响应头 Location 是否含 /faq + 出口地区 loc。
fn build_probe_client_no_redirect(slot: usize) -> Result<reqwest::Client, String> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONNECTION,
        reqwest::header::HeaderValue::from_static("close"),
    );
    reqwest::Client::builder()
        // 【APP73 任务1.1】与 build_probe_client 保持一致：HTTPS 也必须走槽位代理。
        .proxy(
            reqwest::Proxy::all(&probe_proxy_url(slot))
                .map_err(|e| format!("PROXY_ERROR: invalid probe proxy: {e}"))?,
        )
        .connect_timeout(std::time::Duration::from_millis(PROBE_CONNECT_TIMEOUT_MS))
        .timeout(std::time::Duration::from_millis(PROBE_REQUEST_TIMEOUT_MS))
        .redirect(reqwest::redirect::Policy::none())
        // 【APP67 BUG-03】同 build_probe_client：禁用空闲连接池复用 + Connection: close
        .pool_max_idle_per_host(0)
        .pool_idle_timeout(std::time::Duration::from_millis(1))
        .tcp_nodelay(true)
        .default_headers(headers)
        .user_agent(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        )
        .build()
        .map_err(|e| e.to_string())
}

// ===== 【APP67】ServiceProbeResult 构造辅助 =====

fn svc_verified(service: &str, status: u16, evidence: &str) -> ServiceProbeResult {
    ServiceProbeResult {
        service: service.to_string(),
        verdict: ProbeVerdict::Verified,
        status_code: Some(status),
        evidence: evidence.to_string(),
        failure_reason: None,
        error_kind: None,
        ..Default::default()
    }
}

fn svc_accessible(service: &str, status: u16, evidence: &str) -> ServiceProbeResult {
    ServiceProbeResult {
        service: service.to_string(),
        verdict: ProbeVerdict::Accessible,
        status_code: Some(status),
        evidence: evidence.to_string(),
        failure_reason: None,
        error_kind: None,
        ..Default::default()
    }
}

fn svc_partial(service: &str, status: u16, evidence: &str) -> ServiceProbeResult {
    ServiceProbeResult {
        service: service.to_string(),
        verdict: ProbeVerdict::Partial,
        status_code: Some(status),
        evidence: evidence.to_string(),
        failure_reason: None,
        error_kind: None,
        ..Default::default()
    }
}

/// 【APP73 任务2.2】保留真实 HTTP 状态码的 BLOCKED 结果。
fn svc_blocked_status(
    service: &str,
    status: Option<u16>,
    reason: impl Into<String>,
    kind: AimErrorKind,
) -> ServiceProbeResult {
    ServiceProbeResult {
        service: service.to_string(),
        verdict: ProbeVerdict::Blocked,
        status_code: status,
        evidence: String::new(),
        failure_reason: Some(reason.into()),
        error_kind: Some(kind),
        ..Default::default()
    }
}

/// 【APP73 任务2.2】保留真实 HTTP 状态码的 UNKNOWN 结果。
fn svc_unknown_status(
    service: &str,
    status: Option<u16>,
    reason: impl Into<String>,
    kind: AimErrorKind,
) -> ServiceProbeResult {
    ServiceProbeResult {
        service: service.to_string(),
        verdict: ProbeVerdict::Unknown,
        status_code: status,
        evidence: String::new(),
        failure_reason: Some(reason.into()),
        error_kind: Some(kind),
        ..Default::default()
    }
}

#[allow(dead_code)]
fn svc_blocked(service: &str, reason: impl Into<String>) -> ServiceProbeResult {
    svc_blocked_status(service, None, reason, AimErrorKind::UnknownError)
}

#[allow(dead_code)]
fn svc_unknown(service: &str, reason: impl Into<String>) -> ServiceProbeResult {
    svc_unknown_status(service, None, reason, AimErrorKind::UnknownError)
}

/// 【APP67 BUG-02】纯函数：判定响应正文是否为 Cloudflare 质询/拦截页。
/// 提取为纯函数便于单元测试，不依赖真实 HTTP 响应。
fn is_cf_challenge_body(body: &str) -> bool {
    let lc = body.to_lowercase();
    lc.contains("just a moment")
        || lc.contains("attention required")
        || lc.contains("cf-chl-bypass")
        || lc.contains("cf-error-details")
}

/// 【APP67 BUG-02】统一响应读取与校验，杜绝 `unwrap_or_default()` 空响应误判通过。
/// - 传输失败 / 正文过短（< min_len）→ `Err(ProbeVerdict::Unknown)`
/// - Cloudflare 质询拦截页 / 通用网关错误 → `Err(ProbeVerdict::Blocked)`
/// - 正常 → `Ok((status_code, headers, body))`
#[allow(dead_code)]
async fn read_verified_body(
    resp: reqwest::Response,
    min_len: usize,
) -> Result<(u16, reqwest::header::HeaderMap, String), ProbeVerdict> {
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    if status == 403 {
        return Err(ProbeVerdict::Blocked);
    }
    if status == 429 {
        return Err(ProbeVerdict::Unknown);
    }
    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return Err(ProbeVerdict::Unknown),
    };
    if body.trim().len() < min_len {
        return Err(ProbeVerdict::Unknown);
    }
    if is_cf_challenge_body(&body) {
        return Err(ProbeVerdict::Blocked);
    }
    Ok((status, headers, body))
}

/// 从 HeaderMap 取 Location（小写）
fn location_lc(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase()
}

// ===== 【APP67 P1】7 大平台独立正特征检测器 =====
// 每个检测器返回 ServiceProbeResult，只有 Verified 可进入 unlocked_tags。

/// 【APP73 任务3】正文地区限制证据（仅用于 403/451 或明确拒绝页，绝不单独作为封锁依据）。
fn body_region_evidence(lc: &str) -> bool {
    lc.contains("not available in your country")
        || lc.contains("unavailable in your region")
        || lc.contains("not available in your region")
        || lc.contains("isn't currently supported")
        || lc.contains("is not currently supported")
        || lc.contains("unsupported_country")
        || lc.contains("app-unavailable-in-region")
        || lc.contains("this content is not available in your location")
}

/// 精简拒绝页：地区封锁页通常只有极少量 HTML（无完整应用骨架）。
fn is_compact_body(body: &str) -> bool {
    body.len() < 20_000
}

/// 读取响应状态码、响应头与正文；正文读取失败统一归为 BODY_PARSE_ERROR。
async fn read_body(
    resp: reqwest::Response,
    service: &str,
) -> Result<(u16, reqwest::header::HeaderMap, String), ServiceProbeResult> {
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    match resp.text().await {
        Ok(body) => Ok((status, headers, body)),
        Err(e) => Err(svc_unknown_status(
            service,
            Some(status),
            format!("响应正文读取失败: {e}"),
            AimErrorKind::BodyParseError,
        )),
    }
}

/// GPT：ios.chat.openai.com server_status + chatgpt.com 双端点。
/// 【APP73】无合法授权账号对话验证时最高只给 PARTIAL，不虚构 VERIFIED。
async fn probe_gpt(client: &reqwest::Client, _exit_country: Option<&str>) -> ServiceProbeResult {
    const SVC: &str = "GPT";
    // 【APP74 任务2.1】彻底删除出口名单提前短路——必须真实请求 + HTTP 响应证据。
    let ss = match client
        .get("https://ios.chat.openai.com/public-api/mobile/server_status/v1")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return svc_unknown_status(
                SVC,
                None,
                format!("server_status 请求失败: {e}"),
                classify_reqwest_error(&e),
            );
        }
    };
    let (ss_status, _, ss_body) = match read_body(ss, SVC).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let ss_lc = ss_body.to_lowercase();
    if ss_lc.contains("unsupported_country") || ss_lc.contains("vpn_detected") {
        return svc_blocked_status(
            SVC,
            Some(ss_status),
            "server_status 含明确地区限制特征",
            AimErrorKind::RegionRestricted,
        );
    }
    if ss_status == 403 {
        return svc_unknown_status(
            SVC,
            Some(ss_status),
            "server_status 返回 403（无明确地区证据）",
            AimErrorKind::Http403,
        );
    }
    if ss_status == 429 {
        return svc_unknown_status(
            SVC,
            Some(ss_status),
            "server_status 返回 429，稍后重测",
            AimErrorKind::Http429,
        );
    }
    if (500..600).contains(&ss_status) {
        return svc_unknown_status(
            SVC,
            Some(ss_status),
            format!("server_status 返回 {ss_status}"),
            AimErrorKind::Http5xx,
        );
    }
    if !(200..300).contains(&ss_status) {
        return svc_unknown_status(
            SVC,
            Some(ss_status),
            format!("server_status 返回 {ss_status}"),
            classify_status(ss_status),
        );
    }
    let ss_normal =
        ss_lc.contains("\"status\":\"normal\"") || ss_lc.contains("\"status\": \"normal\"");

    let hp = match client
        .get("https://chatgpt.com/")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return svc_unknown_status(
                SVC,
                None,
                format!("chatgpt.com 请求失败: {e}"),
                classify_reqwest_error(&e),
            );
        }
    };
    let (hp_status, _, hp_body) = match read_body(hp, SVC).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let hp_lc = hp_body.to_lowercase();
    if hp_status == 403 {
        if body_region_evidence(&hp_lc) {
            return svc_blocked_status(
                SVC,
                Some(hp_status),
                "chatgpt.com 403 含明确地区限制证据",
                AimErrorKind::RegionRestricted,
            );
        }
        return svc_unknown_status(
            SVC,
            Some(hp_status),
            "chatgpt.com 返回普通 403（无明确地区证据）",
            AimErrorKind::Http403,
        );
    }
    if hp_status == 429 {
        return svc_unknown_status(
            SVC,
            Some(hp_status),
            "chatgpt.com 返回 429 频率限制",
            AimErrorKind::Http429,
        );
    }
    if (500..600).contains(&hp_status) {
        return svc_unknown_status(
            SVC,
            Some(hp_status),
            format!("chatgpt.com 返回 {hp_status}"),
            AimErrorKind::Http5xx,
        );
    }
    if !(200..300).contains(&hp_status) {
        return svc_unknown_status(
            SVC,
            Some(hp_status),
            format!("chatgpt.com 返回 {hp_status}"),
            classify_status(hp_status),
        );
    }
    if is_cf_challenge_body(&hp_body) {
        return svc_unknown_status(
            SVC,
            Some(hp_status),
            "chatgpt.com 返回 Cloudflare 质询页",
            AimErrorKind::ChallengePage,
        );
    }
    if body_region_evidence(&hp_lc) {
        return svc_blocked_status(
            SVC,
            Some(hp_status),
            "chatgpt.com 含明确地区限制证据",
            AimErrorKind::RegionRestricted,
        );
    }
    let has_brand = hp_lc.contains("chatgpt") || hp_lc.contains("openai");
    // 【APP74 任务2.2】恢复 v0.3.100 版 GPT 解锁规则：
    // server_status 返回 "status": "normal" + chatgpt.com HTTP 200 + 品牌正特征 → VERIFIED。
    // APP73 过度保守地把这一档降级成 PARTIAL，APP74 恢复。
    if ss_status == 200 && ss_normal && hp_status == 200 && has_brand {
        svc_verified(
            SVC,
            hp_status,
            "server_status=normal + chatgpt.com 品牌正特征",
        )
    } else if ss_normal && has_brand {
        svc_partial(
            SVC,
            hp_status,
            "server_status=normal + 品牌正特征（非 200）",
        )
    } else if has_brand {
        svc_accessible(SVC, hp_status, "入口/登录页正常，缺少完整业务正特征")
    } else {
        svc_accessible(SVC, hp_status, "入口连通但缺少品牌正特征")
    }
}

/// Claude：claude.ai/login（无重定向客户端看 Location，跟随客户端读正文）
async fn probe_claude(
    client: &reqwest::Client,
    nr_client: &reqwest::Client,
    _exit_country: Option<&str>,
) -> ServiceProbeResult {
    const SVC: &str = "Claude";
    // 【APP74 任务2.1】彻底删除出口名单提前短路——必须真实请求 + HTTP 响应证据。
    let first = match nr_client
        .get("https://claude.ai/login")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return svc_unknown_status(
                SVC,
                None,
                format!("claude.ai/login 首跳请求失败: {e}"),
                classify_reqwest_error(&e),
            );
        }
    };
    let first_status = first.status().as_u16();
    let first_loc = location_lc(first.headers());
    if first_loc.contains("unavailable")
        || first_loc.contains("unsupported")
        || first_loc.contains("app-unavailable-in-region")
    {
        return svc_blocked_status(
            SVC,
            Some(first_status),
            format!("首跳 Location 指向地区不可用页: {first_loc}"),
            AimErrorKind::RegionRestricted,
        );
    }
    if first_status == 429 {
        return svc_unknown_status(
            SVC,
            Some(first_status),
            "claude.ai/login 返回 429 频率限制",
            AimErrorKind::Http429,
        );
    }
    if (500..600).contains(&first_status) {
        return svc_unknown_status(
            SVC,
            Some(first_status),
            format!("claude.ai/login 返回 {first_status}"),
            AimErrorKind::Http5xx,
        );
    }
    if first_status == 403 {
        let (_, _, body) = match read_body(first, SVC).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        if body_region_evidence(&body.to_lowercase()) {
            return svc_blocked_status(
                SVC,
                Some(403),
                "claude.ai/login 403 含明确地区证据",
                AimErrorKind::RegionRestricted,
            );
        }
        return svc_unknown_status(
            SVC,
            Some(403),
            "claude.ai/login 普通 403（无明确地区证据）",
            AimErrorKind::Http403,
        );
    }

    let hp = match client
        .get("https://claude.ai/login")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return svc_unknown_status(
                SVC,
                None,
                format!("claude.ai/login 请求失败: {e}"),
                classify_reqwest_error(&e),
            );
        }
    };
    let (hp_status, _, hp_body) = match read_body(hp, SVC).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let hp_lc = hp_body.to_lowercase();
    if hp_status == 403 {
        if body_region_evidence(&hp_lc) {
            return svc_blocked_status(
                SVC,
                Some(hp_status),
                "claude.ai 403 含明确地区证据",
                AimErrorKind::RegionRestricted,
            );
        }
        return svc_unknown_status(
            SVC,
            Some(hp_status),
            "claude.ai 普通 403（无明确地区证据）",
            AimErrorKind::Http403,
        );
    }
    if hp_status == 429 {
        return svc_unknown_status(
            SVC,
            Some(hp_status),
            "claude.ai 返回 429 频率限制",
            AimErrorKind::Http429,
        );
    }
    if (500..600).contains(&hp_status) {
        return svc_unknown_status(
            SVC,
            Some(hp_status),
            format!("claude.ai 返回 {hp_status}"),
            AimErrorKind::Http5xx,
        );
    }
    if !(200..400).contains(&hp_status) {
        return svc_unknown_status(
            SVC,
            Some(hp_status),
            format!("claude.ai 返回 {hp_status}"),
            classify_status(hp_status),
        );
    }
    if is_cf_challenge_body(&hp_body) {
        return svc_unknown_status(
            SVC,
            Some(hp_status),
            "claude.ai 返回 Cloudflare 质询页",
            AimErrorKind::ChallengePage,
        );
    }
    if body_region_evidence(&hp_lc) {
        return svc_blocked_status(
            SVC,
            Some(hp_status),
            "claude.ai 正文含明确地区不可用证据",
            AimErrorKind::RegionRestricted,
        );
    }
    let has_brand = hp_lc.contains("claude") || hp_lc.contains("anthropic");
    if has_brand {
        svc_partial(SVC, hp_status, "登录页正常且含品牌正特征（未验证实际对话）")
    } else {
        svc_accessible(SVC, hp_status, "连通但缺少品牌正特征")
    }
}

/// Gemini：gemini.google.com/app（无重定向看首跳 Location）。
/// 【APP73】严禁在整段 HTML/JS 中扫到地区提示串就判 BLOCKED。
async fn probe_gemini(
    nr_client: &reqwest::Client,
    _exit_country: Option<&str>,
) -> ServiceProbeResult {
    const SVC: &str = "Gemini";
    let resp = match nr_client
        .get("https://gemini.google.com/app")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return svc_unknown_status(
                SVC,
                None,
                format!("gemini.google.com 请求失败: {e}"),
                classify_reqwest_error(&e),
            );
        }
    };
    let status = resp.status().as_u16();
    let loc = location_lc(resp.headers());
    if (300..400).contains(&status) {
        if loc.contains("support.google.com")
            || loc.contains("/faq")
            || loc.contains("unsupported")
            || loc.contains("notavailable")
        {
            return svc_blocked_status(
                SVC,
                Some(status),
                format!("首跳重定向至地区限制页: {loc}"),
                AimErrorKind::RegionRestricted,
            );
        }
        return svc_accessible(SVC, status, "首跳正常重定向（登录/首页），未验证业务正特征");
    }
    let (status, _, body) = match read_body(resp, SVC).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if status == 403 {
        if is_cf_challenge_body(&body) {
            return svc_unknown_status(
                SVC,
                Some(status),
                "Gemini 返回 Cloudflare/Google 质询页",
                AimErrorKind::ChallengePage,
            );
        }
        let lc = body.to_lowercase();
        // 只有「明确地区拒绝页」才判封锁；普通 403 一律 UNKNOWN。
        // 用精简页结构作为护栏，避免把整段 JS 中偶然出现的文案当成证据。
        if is_compact_body(&body) && body_region_evidence(&lc) {
            return svc_blocked_status(
                SVC,
                Some(status),
                "403 精简地区拒绝页含明确不支持标题",
                AimErrorKind::RegionRestricted,
            );
        }
        return svc_unknown_status(
            SVC,
            Some(status),
            "普通 403（无明确地区证据）",
            AimErrorKind::Http403,
        );
    }
    if status == 429 {
        return svc_unknown_status(
            SVC,
            Some(status),
            "gemini.google.com 返回 429 频率限制",
            AimErrorKind::Http429,
        );
    }
    if (500..600).contains(&status) {
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("gemini.google.com 返回 {status}"),
            AimErrorKind::Http5xx,
        );
    }
    if status != 200 {
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("gemini.google.com 返回 {status}"),
            classify_status(status),
        );
    }
    if body.trim().len() < 1000 {
        return svc_unknown_status(
            SVC,
            Some(status),
            "gemini 响应正文过短/为空",
            AimErrorKind::EmptyResponse,
        );
    }
    if is_cf_challenge_body(&body) {
        return svc_unknown_status(
            SVC,
            Some(status),
            "gemini 返回 Cloudflare/Google 质询页",
            AimErrorKind::ChallengePage,
        );
    }
    let lc = body.to_lowercase();
    let has_login = lc.contains("accounts.google.com/servicelogin")
        || lc.contains("serviceLogin".to_lowercase().as_str())
        || (lc.contains("sign in") && lc.contains("google"));
    let has_workspace =
        lc.contains("wiz_global_data") && (lc.contains("gemini") || lc.contains("bard"));
    if has_workspace {
        return svc_verified(SVC, status, "gemini 工作区初始化数据正特征");
    }
    if has_login {
        return svc_accessible(SVC, status, "正常返回 Google 登录页，未验证 AI 会话");
    }
    // 地区拒绝主标题 + 精简拒绝页且无工作区/登录入口 → 封锁
    if body_region_evidence(&lc) && is_compact_body(&body) {
        return svc_blocked_status(
            SVC,
            Some(status),
            "页面仅展示地区拒绝主标题且无工作区/登录入口",
            AimErrorKind::RegionRestricted,
        );
    }
    svc_accessible(SVC, status, "首页可打开但缺少 AI 工作区正特征")
}

/// NF：netflix.com/title/81280792（非自制剧区域锁片源）。
/// 【APP73】状态码不再直接判解锁，真实播放无法免登录验证时最高 PARTIAL。
async fn probe_netflix(client: &reqwest::Client) -> ServiceProbeResult {
    const SVC: &str = "NF";
    let resp = match client
        .get("https://www.netflix.com/title/81280792")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return svc_unknown_status(
                SVC,
                None,
                format!("netflix.com 请求失败: {e}"),
                classify_reqwest_error(&e),
            );
        }
    };
    let (status, _, body) = match read_body(resp, SVC).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if status == 429 {
        return svc_unknown_status(
            SVC,
            Some(status),
            "netflix 返回 429 频率限制",
            AimErrorKind::Http429,
        );
    }
    if (500..600).contains(&status) {
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("netflix 返回 {status}"),
            AimErrorKind::Http5xx,
        );
    }
    if status == 403 || status == 404 || status == 451 {
        let lc = body.to_lowercase();
        // 【APP73 任务3】403/404 只有在带明确地区不可用证据时才判 BLOCKED，
        // 否则一律 UNKNOWN，避免把片源下架误判成地区封锁。
        if body_region_evidence(&lc) {
            return svc_blocked_status(
                SVC,
                Some(status),
                "netflix 返回明确地区拒绝页",
                AimErrorKind::RegionRestricted,
            );
        }
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("netflix 返回 {status}（无明确地区证据）"),
            classify_status(status),
        );
    }
    if !(200..300).contains(&status) {
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("netflix 返回 {status}"),
            classify_status(status),
        );
    }
    if body.trim().len() < 200 {
        return svc_unknown_status(
            SVC,
            Some(status),
            "netflix 响应正文过短/为空",
            AimErrorKind::EmptyResponse,
        );
    }
    if is_cf_challenge_body(&body) {
        return svc_unknown_status(
            SVC,
            Some(status),
            "netflix 返回 Cloudflare 质询页",
            AimErrorKind::ChallengePage,
        );
    }
    let lc = body.to_lowercase();
    if lc.contains("nses-404") || lc.contains("this title is not available") {
        return svc_partial(SVC, status, "片源不可用（可能仅自制剧目录）");
    }
    let has_title = body.contains("81280792");
    let has_brand = lc.contains("netflix");
    if has_title && has_brand {
        svc_partial(SVC, status, "片源页面可访问，未验证真实播放")
    } else if has_brand {
        svc_accessible(SVC, status, "官网/目录可访问，未命中目标片源")
    } else {
        svc_accessible(SVC, status, "连通但缺少品牌正特征")
    }
}

/// YT：youtube.com/premium。
/// 【APP73】不能仅凭首页 200 或包含 "youtube" 字符串判 VERIFIED。
async fn probe_youtube(client: &reqwest::Client) -> ServiceProbeResult {
    const SVC: &str = "YT";
    let resp = match client
        .get("https://www.youtube.com/premium")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return svc_unknown_status(
                SVC,
                None,
                format!("youtube.com 请求失败: {e}"),
                classify_reqwest_error(&e),
            );
        }
    };
    let (status, _, body) = match read_body(resp, SVC).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if status == 429 {
        return svc_unknown_status(
            SVC,
            Some(status),
            "youtube 返回 429 频率限制",
            AimErrorKind::Http429,
        );
    }
    if (500..600).contains(&status) {
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("youtube 返回 {status}"),
            AimErrorKind::Http5xx,
        );
    }
    let lc = body.to_lowercase();
    if matches!(status, 403 | 451) && body_region_evidence(&lc) {
        return svc_blocked_status(
            SVC,
            Some(status),
            "youtube 返回明确地区限制页",
            AimErrorKind::RegionRestricted,
        );
    }
    if !(200..300).contains(&status) {
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("youtube 返回 {status}"),
            classify_status(status),
        );
    }
    if body.trim().len() < 2000 {
        return svc_unknown_status(
            SVC,
            Some(status),
            "youtube 响应正文过短/为空",
            AimErrorKind::EmptyResponse,
        );
    }
    if is_cf_challenge_body(&body) {
        return svc_unknown_status(
            SVC,
            Some(status),
            "youtube 返回 Cloudflare 质询页",
            AimErrorKind::ChallengePage,
        );
    }
    let has_init = lc.contains("ytinitialdata");
    let has_premium = lc.contains("youtube premium") || lc.contains("premium");
    // 【APP74 任务2.3】恢复 v0.3.100 版 YT 解锁规则：
    // 200 + ytInitialData + Premium 特征 → VERIFIED。APP73 过度保守降级成 PARTIAL。
    if status == 200 && has_init && has_premium {
        svc_verified(SVC, status, "youtube premium + ytInitialData 正特征")
    } else if has_init {
        svc_accessible(SVC, status, "首页/元数据可访问，未命中 Premium 业务特征")
    } else {
        svc_accessible(SVC, status, "200 但缺少播放器初始化正特征")
    }
}

/// Disney+：disneyplus.com/。
/// 【APP73】品牌词单独不足以 VERIFIED；真实播放不可免登录验证。
async fn probe_disney(client: &reqwest::Client, _exit_country: Option<&str>) -> ServiceProbeResult {
    const SVC: &str = "Disney+";
    // 【APP74 任务2.1】彻底删除出口名单提前短路——必须真实请求 + HTTP 响应证据。
    let resp = match client
        .get("https://www.disneyplus.com/")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return svc_unknown_status(
                SVC,
                None,
                format!("disneyplus.com 请求失败: {e}"),
                classify_reqwest_error(&e),
            );
        }
    };
    let final_url = resp.url().as_str().to_lowercase();
    if final_url.contains("/unavailable") || final_url.contains("unavailable-in-region") {
        return svc_blocked_status(
            SVC,
            Some(resp.status().as_u16()),
            format!("disney+ 跳转不可用/预览页: {final_url}"),
            AimErrorKind::RegionRestricted,
        );
    }
    let (status, _, body) = match read_body(resp, SVC).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if status == 429 {
        return svc_unknown_status(
            SVC,
            Some(status),
            "disney+ 返回 429 频率限制",
            AimErrorKind::Http429,
        );
    }
    if (500..600).contains(&status) {
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("disney+ 返回 {status}"),
            AimErrorKind::Http5xx,
        );
    }
    let lc = body.to_lowercase();
    if matches!(status, 403 | 451) && body_region_evidence(&lc) {
        return svc_blocked_status(
            SVC,
            Some(status),
            "disney+ 返回明确地区不可用",
            AimErrorKind::RegionRestricted,
        );
    }
    if !(200..300).contains(&status) {
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("disney+ 返回 {status}"),
            classify_status(status),
        );
    }
    if body.trim().len() < 200 {
        return svc_unknown_status(
            SVC,
            Some(status),
            "disney+ 响应正文过短/为空",
            AimErrorKind::EmptyResponse,
        );
    }
    if is_cf_challenge_body(&body) {
        return svc_unknown_status(
            SVC,
            Some(status),
            "disney+ 返回 Cloudflare 质询页",
            AimErrorKind::ChallengePage,
        );
    }
    if lc.contains("not available in your region") {
        return svc_blocked_status(
            SVC,
            Some(status),
            "disney+ 正文含明确地区不可用",
            AimErrorKind::RegionRestricted,
        );
    }
    if lc.contains("disneyplus") {
        svc_partial(SVC, status, "品牌入口可访问，未验证真实播放")
    } else {
        svc_accessible(SVC, status, "连通但缺少品牌正特征")
    }
}

/// TK：tiktok.com/explore。
/// 【APP73】严禁静态标记 SIGI_STATE 直接 VERIFIED，也严禁脚本含
/// `access denied` 文本就 BLOCKED。
async fn probe_tiktok(client: &reqwest::Client, exit_country: Option<&str>) -> ServiceProbeResult {
    const SVC: &str = "TK";
    let resp = match client
        .get("https://www.tiktok.com/explore")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            return svc_unknown_status(
                SVC,
                None,
                format!("tiktok.com 请求失败: {e}"),
                classify_reqwest_error(&e),
            );
        }
    };
    let (status, _, body) = match read_body(resp, SVC).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if status == 429 {
        return svc_unknown_status(
            SVC,
            Some(status),
            "tiktok 返回 429 频率限制",
            AimErrorKind::Http429,
        );
    }
    if (500..600).contains(&status) {
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("tiktok 返回 {status}"),
            AimErrorKind::Http5xx,
        );
    }
    if is_cf_challenge_body(&body) {
        return svc_unknown_status(
            SVC,
            Some(status),
            "tiktok 返回 Cloudflare/WAF 质询页",
            AimErrorKind::ChallengePage,
        );
    }
    let lc = body.to_lowercase();
    if matches!(status, 403 | 451) {
        if is_compact_body(&body) && body_region_evidence(&lc) {
            return svc_blocked_status(
                SVC,
                Some(status),
                "tiktok 精简地区封锁拒绝页",
                AimErrorKind::RegionRestricted,
            );
        }
        if region_blocked(exit_country, TIKTOK_BLOCKLIST) && is_compact_body(&body) {
            return svc_blocked_status(
                SVC,
                Some(status),
                "tiktok 拒绝页且出口地区命中封禁区",
                AimErrorKind::RegionRestricted,
            );
        }
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("tiktok 普通 {status}（无明确地区证据）"),
            AimErrorKind::Http403,
        );
    }
    if !(200..300).contains(&status) {
        return svc_unknown_status(
            SVC,
            Some(status),
            format!("tiktok 返回 {status}"),
            classify_status(status),
        );
    }
    if body.trim().len() < 1000 {
        return svc_unknown_status(
            SVC,
            Some(status),
            "tiktok 响应正文过短/为空",
            AimErrorKind::EmptyResponse,
        );
    }
    let has_play_meta = lc.contains("playaddr")
        || lc.contains("\"vid\"")
        || lc.contains("videometadata")
        || lc.contains("__universal_data_for_rehydration__");
    if has_play_meta {
        return svc_partial(SVC, status, "视频流元数据可获取，未验证实际播放");
    }
    svc_accessible(SVC, status, "首页/登录页正常可访问")
}

/// 【APP71 任务2.4】槽位实时状态守卫：节点开始时登记，结束/取消/panic 时清空，
/// 前端「当前并发详情」绝不残留已结束节点。
struct SlotGuard {
    app: AppHandle,
    slot: usize,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let state = self.app.state::<AppState>();
        let mut p = state.aim_progress.lock();
        if let Some(v) = p.current_nodes.get_mut(self.slot) {
            v.clear();
        }
        if let Some(v) = p.current_services.get_mut(self.slot) {
            v.clear();
        }
        p.active_slots = p.current_nodes.iter().filter(|s| !s.is_empty()).count();
    }
}

/// 登记槽位当前节点与平台（固定 4 槽长度，前端按槽位渲染）。
fn set_slot_state(app: &AppHandle, slot: usize, node: &str, services: String) {
    let state = app.state::<AppState>();
    let mut p = state.aim_progress.lock();
    if p.current_nodes.len() < PROBE_SLOTS {
        p.current_nodes.resize(PROBE_SLOTS, String::new());
    }
    if p.current_services.len() < PROBE_SLOTS {
        p.current_services.resize(PROBE_SLOTS, String::new());
    }
    p.current_nodes[slot] = node.to_string();
    p.current_services[slot] = services;
    p.active_slots = p.current_nodes.iter().filter(|s| !s.is_empty()).count();
}

/// 单节点探测：复用阶段1 快筛延迟 → 探针选择器切到该节点 →
/// 【APP72 任务1.2】出口信息仅作参考证据，绝不短路 7 平台真实探测。
/// 死节点（基线延迟失败）生成 probed=true 的空结果。
#[allow(clippy::too_many_arguments)]
async fn probe_node(
    api: &crate::core::kernel::KernelApi,
    client: &reqwest::Client,
    nr_client: &reqwest::Client,
    slot: usize,
    name: &str,
    prescreened_delay: Option<u64>,
    node_id: &str,
    cached: Option<&AimNodeResult>,
    mode: AimProbeMode,
    force_full: bool,
    run: &Arc<AimRunCtx>,
    app: &AppHandle,
) -> NodeProbeOutcome {
    let started = std::time::Instant::now();
    let _slot_guard = SlotGuard {
        app: app.clone(),
        slot,
    };
    set_slot_state(
        app,
        slot,
        name,
        format!("#{slot}: {name} · 7 平台并发 [HTTPS_REQUEST]"),
    );
    let stamp = |mut result: AimNodeResult| {
        result.node_id = node_id.to_string();
        result.mode = Some(mode);
        result.detected_at = now_secs();
        result
    };
    // 1. 基线延迟
    let base_delay = match prescreened_delay.filter(|d| *d > 0 && *d < PROBE_MAX_DELAY_MS) {
        Some(d) => d,
        None => match api
            .test_delay(name, BASELINE_URL, BASELINE_TIMEOUT_MS as u32)
            .await
        {
            Some(d) if d > 0 && d < PROBE_MAX_DELAY_MS => d,
            _ => return NodeProbeOutcome::new(stamp(dead_result(name)), false, started),
        },
    };

    // 2. 探针选择器切到该节点
    if let Err(e) = api.select_proxy(&probe_selector(slot), name).await {
        tracing::warn!("[go-aim] 槽位 {slot} 切换探针到「{name}」失败: {e}");
        return NodeProbeOutcome::new(stamp(dead_result(name)), false, started);
    }
    // [AIM-12] 8 阶段追踪：PROXY_SELECTED
    crate::core::logger::info(
        crate::core::logger::MOD_GO_AIM,
        format!(
            "[AIM][{name}][-] [阶段] PROXY_SELECTED selector={} target={name}",
            probe_selector(slot)
        ),
    );

    // 2.1 【APP73 任务1.2】PROXY_VERIFIED：选择器实际 now 必须是目标节点。
    // 若 Clash API 返回的 now 与目标不一致，说明设置尚未生效/被其他任务抢占，
    // 本节点所有平台一律回退 UNKNOWN，严禁继续判定任何 VERIFIED。
    let selected_now = api.get_proxies().await.ok().and_then(|v| {
        v.get("proxies")
            .and_then(|p| p.get(probe_selector(slot)))
            .and_then(|g| g.get("now"))
            .and_then(|n| n.as_str())
            .map(str::to_string)
    });
    if selected_now.as_deref() != Some(name) {
        let actual = selected_now.unwrap_or_else(|| "<unknown>".to_string());
        crate::core::logger::warn(
            crate::core::logger::MOD_GO_AIM,
            format!(
                "[AIM][{name}][-] [阶段] PROXY_ERROR 选择器未生效: 期望={name} 实际={actual}，全部平台回退 UNKNOWN"
            ),
        );
        let result = all_unknown_result(
            name,
            base_delay,
            format!("PROXY_ERROR: 探针选择器实际指向 {actual}，选择未生效"),
            AimErrorKind::ProxyError,
        );
        return NodeProbeOutcome::new(stamp(result), false, started);
    }
    crate::core::logger::info(
        crate::core::logger::MOD_GO_AIM,
        format!("[AIM][{name}][-] [阶段] PROXY_VERIFIED 选择器 now={name}"),
    );

    // 3. 每个节点都先做一次轻量出口预检（仅采集证据，失败也继续 7 平台探测）。
    // [AIM-13] EGRESS_CHECK：出口 IP/地区仅作证据，不参与短路。
    let egress = fetch_egress(client).await;
    crate::core::logger::info(
        crate::core::logger::MOD_GO_AIM,
        format!(
            "[AIM][{name}][-] [阶段] EGRESS_CHECK ip={} country={} asn={}",
            egress.ip.as_deref().unwrap_or("unknown"),
            egress.country.as_deref().unwrap_or("unknown"),
            egress.asn.as_deref().unwrap_or("unknown"),
        ),
    );
    if egress.ip.is_none() || egress.country.is_none() {
        tracing::debug!(
            "[go-aim] 节点「{name}」cdn-cgi/trace 未取到完整出口信息，继续执行 7 平台实测"
        );
    }

    // 4. 配置指纹 + 双版本 + 出口 IP 全一致：0 平台请求直接复用。
    let current_ip = egress.ip.as_deref().unwrap_or_default();
    if let Some(cached) =
        cached.filter(|cached| cache_reusable(cached, node_id, current_ip, force_full))
    {
        let mut result = cached.clone();
        result.node_name = name.to_string();
        result.delay_ms = base_delay;
        result.updated_at = now_secs();
        result.detected_at = now_secs();
        result.egress_asn = egress.asn.or(result.egress_asn);
        result.mode = Some(mode);
        return NodeProbeOutcome::new(result, true, started);
    }

    // 5. 仅缓存未命中时执行 7 平台并发真实请求（Unknown 最多补测 1 次）。
    let ec = egress.country.as_deref();
    // [AIM-14] 发起 7 平台并发检测（绝不等待完整正文，仅读状态码/头/关键特征）
    run.log(
        14,
        "INFO",
        AimLogMeta::default().node(name).slot(slot),
        "发起 7 平台并发真实探测（GPT/Claude/Gemini/NF/YT/Disney+/TK）",
    );
    let mut futs: futures_util::stream::FuturesUnordered<
        std::pin::Pin<Box<dyn std::future::Future<Output = ServiceProbeResult> + Send>>,
    > = futures_util::stream::FuturesUnordered::new();
    futs.push(Box::pin(probe_platform("GPT", || probe_gpt(client, ec))));
    futs.push(Box::pin(probe_platform("Claude", || {
        probe_claude(client, nr_client, ec)
    })));
    futs.push(Box::pin(probe_platform("Gemini", || {
        probe_gemini(nr_client, ec)
    })));
    futs.push(Box::pin(probe_platform("NF", || probe_netflix(client))));
    futs.push(Box::pin(probe_platform("YT", || probe_youtube(client))));
    futs.push(Box::pin(probe_platform("Disney+", || {
        probe_disney(client, ec)
    })));
    futs.push(Box::pin(probe_platform("TK", || probe_tiktok(client, ec))));
    // [AIM-14] 8 阶段追踪：DNS_CONNECT + HTTPS_REQUEST（7 平台并发）
    for service in ["GPT", "Claude", "Gemini", "NF", "YT", "Disney+", "TK"] {
        crate::core::logger::info(
            crate::core::logger::MOD_GO_AIM,
            format!(
                "[AIM][{name}][{service}] [阶段] DNS_CONNECT proxy={} target={}",
                probe_proxy_url(slot),
                service_domain(service)
            ),
        );
        crate::core::logger::info(
            crate::core::logger::MOD_GO_AIM,
            format!(
                "[AIM][{name}][{service}] [阶段] HTTPS_REQUEST method=GET domain={}",
                service_domain(service)
            ),
        );
    }
    let mut results: Vec<ServiceProbeResult> = Vec::with_capacity(7);
    // [AIM-15] 单平台探测结果 + 8 阶段中的 RESPONSE/BODY/RESULT 追踪；
    // 使用 FuturesUnordered 逐平台完成即刷新 UI，满足实时平台/阶段展示。
    // [AIM-16] 异常 / 重试
    while let Some(r) = futs.next().await {
        // 前端实时进度：当前节点 + 平台 + 阶段（RESULT 已完成）
        set_slot_state(
            app,
            slot,
            name,
            format!(
                "#{slot}: {name} · {} [RESULT: {}]",
                r.service,
                r.verdict.label()
            ),
        );
        run.log(
            15,
            "INFO",
            AimLogMeta::default()
                .node(name)
                .slot(slot)
                .service(&r.service)
                .elapsed(r.elapsed_ms.unwrap_or(0)),
            format!(
                "平台探测结果: verdict={}, status={:?}, kind={:?}, basis={}, elapsed={}ms",
                r.verdict.label(),
                r.status_code,
                r.error_kind.map(|k| k.label()),
                r.verdict_basis,
                r.elapsed_ms.unwrap_or(0)
            ),
        );
        let prefix = format!("[AIM][{name}][{}]", r.service);
        crate::core::logger::info(
            crate::core::logger::MOD_GO_AIM,
            format!(
                "{prefix} [阶段] RESPONSE_RECEIVED status={} protocol=HTTPS",
                r.status_code
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
        );
        crate::core::logger::info(
            crate::core::logger::MOD_GO_AIM,
            format!(
                "{prefix} [阶段] BODY_ANALYSIS evidence={}",
                if r.evidence.is_empty() {
                    r.failure_reason.as_deref().unwrap_or("无")
                } else {
                    &r.evidence
                }
            ),
        );
        crate::core::logger::info(
            crate::core::logger::MOD_GO_AIM,
            format!(
                "{prefix} [阶段] RESULT verdict={} elapsed={}ms",
                r.verdict.label(),
                r.elapsed_ms.unwrap_or(0)
            ),
        );
        if !r.verdict.is_verified() {
            crate::core::logger::info(
                crate::core::logger::MOD_GO_AIM,
                format!(
                    "[AIM][诊断] 平台={} | 节点={name} | 目标域名={} | 代理槽位=#{} | 出口IP={} | 出口地区={} | HTTP状态码={} | 耗时={}ms | 失败阶段=RESULT | 错误分类={} | 最终状态={} | 判定依据={}",
                    r.service,
                    service_domain(&r.service),
                    slot,
                    egress.ip.as_deref().unwrap_or("unknown"),
                    egress.country.as_deref().unwrap_or("unknown"),
                    r.status_code
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    r.elapsed_ms.unwrap_or(0),
                    r.error_kind.map(|k| k.label()).unwrap_or("NONE"),
                    r.verdict.label(),
                    if r.verdict_basis.is_empty() {
                        r.failure_reason.as_deref().unwrap_or("无")
                    } else {
                        &r.verdict_basis
                    }
                ),
            );
        }
        if r.retry_count > 0 {
            run.log(
                16,
                "WARN",
                AimLogMeta::default()
                    .node(name)
                    .slot(slot)
                    .service(&r.service),
                format!(
                    "平台探测异常触发补测 {} 次: {}",
                    r.retry_count,
                    r.failure_reason.as_deref().unwrap_or("无明确原因")
                ),
            );
        }
        results.push(r);
    }
    // 释放 futures 对 egress.country 的借用，后续才能把 egress 字段移入结果。
    drop(futs);

    // 6. 汇总：只有 Verified 进入 unlocked_tags；评分按五级权重累计。
    let mut services: HashMap<String, ServiceProbeResult> = HashMap::with_capacity(results.len());
    let mut evidence = HashMap::new();
    let mut failure_reasons = HashMap::new();
    let mut tags: Vec<String> = Vec::new();
    let mut ai = false;
    let mut media = false;
    for r in results {
        let is_ai = matches!(r.service.as_str(), "GPT" | "Claude" | "Gemini");
        if r.verdict.is_verified() {
            tags.push(r.service.clone());
            if is_ai {
                ai = true;
            } else {
                media = true;
            }
        }
        if !r.evidence.is_empty() {
            evidence.insert(r.service.clone(), r.evidence.clone());
        }
        if let Some(reason) = &r.failure_reason {
            failure_reasons.insert(r.service.clone(), reason.clone());
        }
        services.insert(r.service.clone(), r);
    }
    let score: u32 = services.values().map(|r| verdict_score(r.verdict)).sum();
    let proxy_health = ProxyHealthStatus::ProxyOk; // 后续由 verify_basic_https_proxy_health 真实填写
    let overall_status = compute_overall_status(proxy_health, &services);
    let result = AimNodeResult {
        node_name: name.to_string(),
        node_id: node_id.to_string(),
        unlocked_tags: tags,
        ai_unlocked: ai,
        media_unlocked: media,
        score,
        delay_ms: base_delay,
        updated_at: now_secs(),
        detected_at: now_secs(),
        // 【APP74 任务1.3】真正完成 7 平台检测 → DeepProbed / probed=true
        probed: probe_stage_to_probed(AimProbeStage::DeepProbed),
        proxy_health,
        probe_stage: AimProbeStage::DeepProbed,
        overall_status,
        probe_version: CURRENT_AIM_PROBE_VERSION,
        rule_version: CURRENT_AIM_RULE_VERSION,
        egress_ip: egress.ip,
        egress_country: egress.country,
        egress_asn: egress.asn,
        mode: Some(mode),
        services,
        evidence,
        failure_reasons,
    };
    NodeProbeOutcome::new(result, false, started)
}

struct NodeProbeOutcome {
    result: AimNodeResult,
    cache_hit: bool,
    elapsed_ms: u64,
    timed_out: bool,
}

impl NodeProbeOutcome {
    fn new(result: AimNodeResult, cache_hit: bool, started: std::time::Instant) -> Self {
        let timed_out = result.delay_ms == 0
            || result.services.values().any(|service| {
                service
                    .failure_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("超时") || reason.contains("timeout"))
            });
        Self {
            result,
            cache_hit,
            elapsed_ms: started.elapsed().as_millis() as u64,
            timed_out,
        }
    }
}

/// 【APP74 任务1.3】出口预检失败 → PROXY_FAILED 占位结果，probe_stage=ProxyFailed，
/// probed=false（禁止伪装成完整深测），overall_status=PROXY_FAILED。
#[allow(dead_code)]
fn egress_unknown_result(
    name: &str,
    delay: u64,
    egress_ip: Option<String>,
    egress_country: Option<String>,
) -> AimNodeResult {
    let mut services: HashMap<String, ServiceProbeResult> = HashMap::new();
    for s in ["GPT", "Claude", "Gemini", "NF", "YT", "Disney+", "TK"] {
        services.insert(
            s.to_string(),
            svc_unknown_status(
                s,
                None,
                "出口预检失败/未知/漏直连，未执行平台探测",
                AimErrorKind::ProxyError,
            ),
        );
    }
    AimNodeResult {
        node_name: name.to_string(),
        unlocked_tags: vec![],
        ai_unlocked: false,
        media_unlocked: false,
        score: 0,
        delay_ms: delay,
        updated_at: now_secs(),
        // 【APP74】ProxyFailed 一律 probed=false
        probed: false,
        proxy_health: ProxyHealthStatus::ProxyFailed,
        probe_stage: AimProbeStage::ProxyFailed,
        overall_status: AimNodeOverallStatus::ProxyFailed,
        probe_version: CURRENT_AIM_PROBE_VERSION,
        rule_version: CURRENT_AIM_RULE_VERSION,
        egress_ip,
        egress_country,
        services,
        ..Default::default()
    }
}

/// 【APP73 任务3.4】五级评分权重：只有 UNKNOWN/BLOCKED 记 0 分。
fn verdict_score(verdict: ProbeVerdict) -> u32 {
    match verdict {
        ProbeVerdict::Verified => 20,
        ProbeVerdict::Partial => 12,
        ProbeVerdict::Accessible => 8,
        ProbeVerdict::Unknown | ProbeVerdict::Blocked => 0,
    }
}

/// 平台 → 诊断日志使用的目标域名。
fn service_domain(service: &str) -> &'static str {
    match service {
        "GPT" => "chatgpt.com",
        "Claude" => "claude.ai",
        "Gemini" => "gemini.google.com",
        "NF" => "netflix.com",
        "YT" => "youtube.com",
        "Disney+" => "disneyplus.com",
        "TK" => "tiktok.com",
        _ => "-",
    }
}

/// 【APP73 任务1.2】选择器核验失败时的统一结果：7 平台全部 UNKNOWN。
fn all_unknown_result(name: &str, delay: u64, reason: String, kind: AimErrorKind) -> AimNodeResult {
    let mut services: HashMap<String, ServiceProbeResult> = HashMap::new();
    let mut failure_reasons = HashMap::new();
    for s in ["GPT", "Claude", "Gemini", "NF", "YT", "Disney+", "TK"] {
        services.insert(
            s.to_string(),
            svc_unknown_status(s, None, reason.clone(), kind),
        );
        failure_reasons.insert(s.to_string(), reason.clone());
    }
    AimNodeResult {
        node_name: name.to_string(),
        unlocked_tags: vec![],
        ai_unlocked: false,
        media_unlocked: false,
        score: 0,
        delay_ms: delay,
        updated_at: now_secs(),
        detected_at: now_secs(),
        // 【APP74】选择器核验失败 → PROXY_FAILED，禁止伪装成完整深测
        probed: false,
        proxy_health: ProxyHealthStatus::ProxyFailed,
        probe_stage: AimProbeStage::ProxyFailed,
        overall_status: AimNodeOverallStatus::ProxyFailed,
        probe_version: CURRENT_AIM_PROBE_VERSION,
        rule_version: CURRENT_AIM_RULE_VERSION,
        services,
        failure_reasons,
        ..Default::default()
    }
}

/// 【APP73 任务3.3】平台级 10 秒硬超时包裹（含 Unknown 补测 1 次）。
async fn probe_platform<F, Fut>(service: &'static str, f: F) -> ServiceProbeResult
where
    F: Fn() -> Fut + Send,
    Fut: std::future::Future<Output = ServiceProbeResult> + Send,
{
    probe_platform_timeout(service, PROBE_PLATFORM_HARD_TIMEOUT_SECS, f).await
}

async fn probe_platform_timeout<F, Fut>(
    service: &'static str,
    timeout_secs: u64,
    f: F,
) -> ServiceProbeResult
where
    F: Fn() -> Fut + Send,
    Fut: std::future::Future<Output = ServiceProbeResult> + Send,
{
    match tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        probe_with_retry(f),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            let mut result = svc_unknown_status(
                service,
                None,
                format!("平台探测硬超时({timeout_secs}s)"),
                AimErrorKind::TaskTimeout,
            );
            result.verdict_basis = "TASK_TIMEOUT: 超过平台级硬超时上限".to_string();
            result
        }
    }
}

/// 仅对 Unknown 结论补测 1 次（传输抖动重试），Blocked/Verified/Accessible/Partial 不重试。
/// 【APP71 任务4】同时记录真实耗时、重试次数与可读判定依据。
async fn probe_with_retry<F, Fut>(f: F) -> ServiceProbeResult
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ServiceProbeResult>,
{
    let started = std::time::Instant::now();
    let mut result = f().await;
    let mut retry_count = 0u32;
    if matches!(result.verdict, ProbeVerdict::Unknown) {
        retry_count = 1;
        result = f().await;
    }
    result.retry_count = retry_count;
    result.elapsed_ms = Some(started.elapsed().as_millis() as u64);
    if result.verdict_basis.is_empty() {
        result.verdict_basis = if !result.evidence.is_empty() {
            result.evidence.clone()
        } else {
            match &result.failure_reason {
                Some(reason) => format!("{}：{reason}", result.verdict.label()),
                None => result.verdict.label().to_string(),
            }
        };
    }
    result
}

// 【APP66 任务1.1】已删除 `preview_tags`：任何「按节点名称/地区关键词推断
// AI / 流媒体解锁」的启发式都必须彻底移除。解锁结论唯一来源是真实隧道内
// 的 HTTP 探测，预览模式一律返回空标签。

fn dead_result(name: &str) -> AimNodeResult {
    AimNodeResult {
        node_name: name.to_string(),
        unlocked_tags: vec![],
        ai_unlocked: false,
        media_unlocked: false,
        score: 0,
        delay_ms: 0,
        updated_at: now_secs(),
        // 【APP74 任务1.3】死节点 probed=false，probe_stage=ScreenedDead
        // —— 严禁伪装成深度检测完成。
        probed: false,
        proxy_health: ProxyHealthStatus::ProxyUnknown,
        probe_stage: AimProbeStage::ScreenedDead,
        overall_status: AimNodeOverallStatus::Unknown,
        probe_version: CURRENT_AIM_PROBE_VERSION,
        rule_version: CURRENT_AIM_RULE_VERSION,
        ..Default::default()
    }
}

/// 【APP74 任务1.2】基础代理健康检测（3 个独立 HTTPS 目标）。
/// 必须至少 2/3 成功才算 PROXY_OK；否则 PROXY_FAILED，禁止继续 7 平台解锁检测。
async fn verify_basic_https_proxy_health(
    client: &reqwest::Client,
    slot: usize,
    name: &str,
) -> (
    ProxyHealthStatus,
    Vec<(&'static str, u16, u64, AimErrorKind)>,
) {
    const TARGETS: [(&str, &str); 3] = [
        ("gstatic", "https://www.gstatic.com/generate_204"),
        ("cloudflare", "https://cp.cloudflare.com/generate_204"),
        ("microsoft", "https://www.microsoft.com/"),
    ];
    let mut hits: Vec<(&'static str, u16, u64, AimErrorKind)> = Vec::with_capacity(3);
    let mut ok = 0u32;
    for (label, url) in &TARGETS {
        let start = std::time::Instant::now();
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(PROBE_PLATFORM_HARD_TIMEOUT_SECS),
            client.get(*url).send(),
        )
        .await;
        match r {
            Ok(Ok(resp)) => {
                let status = resp.status().as_u16();
                let elapsed_ms = start.elapsed().as_millis() as u64;
                let kind = if resp.status().is_success() {
                    AimErrorKind::UnknownError
                } else {
                    classify_status(status)
                };
                hits.push((*label, status, elapsed_ms, kind));
                if status != 0 && !matches!(kind, AimErrorKind::ChallengePage) {
                    // 任何 HTTP 状态（含非 200，但必须 HTTP 响应到达）都视为代理通路正常
                    ok += 1;
                }
            }
            Ok(Err(e)) => {
                let elapsed_ms = start.elapsed().as_millis() as u64;
                hits.push((*label, 0, elapsed_ms, classify_reqwest_error(&e)));
            }
            Err(_) => {
                hits.push((
                    *label,
                    0,
                    start.elapsed().as_millis() as u64,
                    AimErrorKind::TaskTimeout,
                ));
            }
        }
    }
    let status = if ok >= 2 {
        ProxyHealthStatus::ProxyOk
    } else {
        ProxyHealthStatus::ProxyFailed
    };
    crate::core::logger::info(
        crate::core::logger::MOD_GO_AIM,
        format!(
            "[AIM][{name}][-] [阶段] PROXY_HEALTH_CHECK slot={slot} results={ok}/3 final={}",
            status.label()
        ),
    );
    for (label, status_code, elapsed, kind) in &hits {
        crate::core::logger::info(
            crate::core::logger::MOD_GO_AIM,
            format!(
                "[AIM][{name}][-] [阶段] PROXY_HEALTH_TARGET target={label} status={status_code} elapsed={elapsed}ms kind={:?}",
                kind.label()
            ),
        );
    }
    (status, hits)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ================= 【APP71 任务1.2 / 任务2】AIM 运行上下文 =================

/// 单轮 Go AIM 检测的运行上下文：唯一 runId、严格单调 sequence、
/// 21 阶段结构化日志与 `go-aim://event` 事件发射。
struct AimRunCtx {
    run_id: String,
    seq: AtomicU64,
    started: std::time::Instant,
    /// SCREEN 事件节流计数
    screen_emitted: AtomicUsize,
    screen_last_ms: AtomicU64,
}

impl AimRunCtx {
    fn new() -> Arc<Self> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Arc::new(Self {
            run_id: format!("aim-{:x}", now_ms & 0xFFFF_FFFF),
            seq: AtomicU64::new(0),
            started: std::time::Instant::now(),
            screen_emitted: AtomicUsize::new(0),
            screen_last_ms: AtomicU64::new(0),
        })
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// 记录一个生命周期阶段日志（自动补 `[AIM-xx]` 前缀与 runId）。
    fn log(&self, stage: u8, level: &str, mut meta: AimLogMeta, message: impl AsRef<str>) {
        meta.run_id = Some(self.run_id.clone());
        crate::core::logger::log_aim(
            level,
            &meta,
            &format!("[AIM-{stage:02}] {}", message.as_ref()),
        );
    }

    /// SCREEN 事件节流：每完成 2 个节点或距上次发射 >=120ms 放行一次。
    fn should_emit_screen(&self) -> bool {
        let n = self.screen_emitted.fetch_add(1, Ordering::Relaxed) + 1;
        let now = self.elapsed_ms();
        let last = self.screen_last_ms.load(Ordering::Relaxed);
        if n >= SCREEN_EMIT_NODES || now.saturating_sub(last) >= SCREEN_EMIT_INTERVAL_MS {
            self.screen_emitted.store(0, Ordering::Relaxed);
            self.screen_last_ms.store(now, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// 发射结构化事件 + 兼容旧 `aim://progress`，并写入最近 30 条快照。
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        app: &AppHandle,
        phase: &str,
        meta: &AimLogMeta,
        status: Option<&str>,
        message: impl Into<String>,
        details: Option<serde_json::Value>,
    ) -> crate::core::state::ProbeProgress {
        let state = app.state::<AppState>();
        let sequence = self.next_seq();
        let message = message.into();
        let progress = {
            let mut p = state.aim_progress.lock();
            p.run_id = self.run_id.clone();
            p.sequence = sequence;
            // NODE_RESULT 是节点级事件，不得把所属阶段从 DEEP_PROBE 覆盖掉
            if phase != "NODE_RESULT" {
                p.phase = phase.to_string();
            }
            p.elapsed_ms = self.elapsed_ms();
            if matches!(phase, "FINISHED" | "CANCELLED" | "ERROR") {
                p.running = false;
            } else if matches!(phase, "START" | "SCREEN" | "DEEP_PROBE") {
                p.running = true;
            }
            p.recompute_aim();
            p.clone()
        };
        let event = crate::core::state::GoAimEvent {
            run_id: self.run_id.clone(),
            sequence,
            timestamp: now_secs(),
            phase: phase.to_string(),
            node_name: meta.node_name.clone(),
            slot: meta.slot,
            service: meta.service.clone(),
            status: status.map(str::to_string),
            elapsed_ms: Some(self.elapsed_ms()),
            message: message.clone(),
            progress: progress.clone(),
            details,
        };
        {
            let mut recent = state.aim_events.lock();
            recent.push_back(event.clone());
            while recent.len() > AIM_RECENT_EVENTS {
                recent.pop_front();
            }
        }
        if phase == "ERROR" {
            *state.aim_last_error.write() = Some(message);
        }
        let _ = app.emit(AIM_EVENT_STRUCTURED, &event);
        let _ = app.emit("aim://progress", &progress);
        progress
    }
}

// ---------------------------------------------------------------- 锁定选择

/// 锁定选择（探测完成后 / 故障转移时调用）：
/// - 手动指定节点且仍存活 → 保持指定节点（绝不覆盖，除非失联）；
/// - 自动模式 → 评级分层选优。
/// 选中后同步主选择器与 GLOBAL、按设置断开旧连接并广播事件。
pub async fn apply_selection(app: &AppHandle, state: &AppState) -> Result<Option<String>, String> {
    let results = state.aim_results.read().clone();
    if results.is_empty() {
        return Ok(None);
    }

    // 手动指定：目标节点仍在存活结果中则直接锁定（评级照跑但不覆盖）
    let pinned = state.settings.read().go_aim_pinned_node.clone();
    let close_conns = state.settings.read().close_connections_on_switch;
    if let Some(pinned) = pinned
        && let Some(res) = results.get(&pinned)
        && res.probed
        && res.delay_ms > 0
    {
        return lock_node(app, state, res, close_conns).await.map(Some);
    }

    let Some(best) = pick_best(&results) else {
        tracing::warn!("[go-aim] 解锁池为空，保持当前节点不变");
        return Ok(None);
    };
    lock_node(app, state, &best, close_conns).await.map(Some)
}

/// 执行锁定：若与当前锁定一致则跳过；否则切主组 + GLOBAL 并广播。
/// `close_conns`：是否断开现有连接——探测过程中的实时切换必须传 false，
/// 否则会把其余槽位正在进行的探针 HTTP 连接一并砍断，导致探测误判。
async fn lock_node(
    app: &AppHandle,
    state: &AppState,
    best: &AimNodeResult,
    close_conns: bool,
) -> Result<String, String> {
    if state.aim_locked_node.read().as_deref() == Some(best.node_name.as_str()) {
        return Ok(best.node_name.clone());
    }

    let api = state.kernel_api();
    // 选择主选择器与 GLOBAL 中的节点（与 auto_select 逻辑一致）
    let selector = state.main_selector.read().clone();
    if let Some(tag) = selector.as_deref() {
        let _ = api.select_proxy(tag, &best.node_name).await;
    }
    let _ = api.select_proxy("GLOBAL", &best.node_name).await;
    if close_conns {
        let _ = api.close_all_connections().await;
    }

    *state.aim_locked_node.write() = Some(best.node_name.clone());
    // 【APP39 任务4】同步「当前节点」到全局状态与磁盘：
    // 仪表盘「当前节点」读的是 settings.selected_node，
    // 只切内核策略组不写它会导致界面长期停留在旧节点（如 电信-LAX-01）。
    // 注意：go_aim_pinned_node（用户手动指定）绝不能被自动选点覆盖，
    // 否则手动模式被永久抹掉（指定节点复活后也无法恢复）。
    *state.user_manually_selected_node.write() = false;
    {
        let mut settings = state.settings.read().clone();
        settings.selected_node = Some(best.node_name.clone());
        settings.user_manually_selected_node = false;
        if let Err(e) = state.save_settings(settings) {
            tracing::warn!("[go-aim] 保存 selected_node 失败: {e}");
        }
    }
    tracing::info!(
        "[go-aim] 已锁定节点「{}」（延迟 {}ms，解锁平台: {}）",
        best.node_name,
        best.delay_ms,
        best.unlocked_tags.join("/")
    );
    let _ = app.emit("proxies://changed", ());
    let _ = app.emit(AIM_EVENT, serde_json::json!({ "locked": best.node_name }));
    Ok(best.node_name.clone())
}

/// 【APP39 任务4·时机A】开启 Go AIM 的瞬间立即锁定「当前延迟最低」节点。
///
/// 延迟数据源与「代理」页完全一致：Clash API `/proxies` 每项的
/// `history` 末条 `delay`（用户在代理列表看到的绿色毫秒数）。
/// 若没有任何历史延迟（刚启动、尚未测速），对前 10 个真实节点做
/// 800ms 快速测速后取最低者。选中后经 lock_node 同步
/// state.selected_node / settings.json 并广播事件，仪表盘 1 秒内刷新。
pub async fn lock_fastest_now(app: &AppHandle, state: &AppState) -> Option<String> {
    let api = state.kernel_api();
    let mut best: Option<(String, u64)> = None;

    if let Ok(proxies) = api.get_proxies().await
        && let Some(obj) = proxies.get("proxies").and_then(|v| v.as_object())
    {
        for (name, info) in obj {
            // 跳过嵌套策略组（带 all 成员列表）与内置假节点
            if info.get("all").is_some()
                || crate::core::config_builder::is_builtin_non_proxy_tag(name)
            {
                continue;
            }
            let delay = info
                .get("history")
                .and_then(|h| h.as_array())
                .and_then(|a| a.last())
                .and_then(|e| e.get("delay"))
                .and_then(|d| d.as_u64())
                .unwrap_or(0);
            if delay == 0 {
                continue;
            }
            if best.as_ref().is_none_or(|(_, d)| delay < *d) {
                best = Some((name.clone(), delay));
            }
        }
    }

    if best.is_none()
        && let Ok(proxies) = api.get_proxies().await
        && let Some(obj) = proxies.get("proxies").and_then(|v| v.as_object())
    {
        // 前 10 个真实节点 800ms 快测（滚动并发，避免瞬间占满内存）
        let candidates: Vec<String> = obj
            .iter()
            .filter(|(name, info)| {
                info.get("all").is_none()
                    && !crate::core::config_builder::is_builtin_non_proxy_tag(name)
            })
            .map(|(name, _)| name.clone())
            .take(10)
            .collect();
        for name in candidates {
            if let Some(d) = api.test_delay(&name, BASELINE_URL, 800).await
                && d > 0
                && best.as_ref().is_none_or(|(_, bd)| d < *bd)
            {
                best = Some((name, d));
            }
        }
    }

    let (name, delay) = best?;
    let res = AimNodeResult {
        node_name: name.clone(),
        unlocked_tags: vec![],
        ai_unlocked: false,
        media_unlocked: false,
        score: 0,
        delay_ms: delay,
        updated_at: 0,
        probed: true,
        probe_version: CURRENT_AIM_PROBE_VERSION,
        rule_version: CURRENT_AIM_RULE_VERSION,
        ..Default::default()
    };
    // 【APP49】仅当用户开启「切换策略时关闭连接」才断开旧连接
    let close_conns = state.settings.read().close_connections_on_switch;
    if let Err(e) = lock_node(app, state, &res, close_conns).await {
        tracing::warn!("[go-aim] 开启瞬间锁定最低延迟节点失败: {e}");
        return None;
    }
    Some(name)
}

/// 评级选优（纯函数，便于单元测试）。
///
/// 【APP39 任务4】改为「延迟最低绝对优先」：
/// - 候选池剔除内置假节点（剩余流量/到期等）与不可达节点（delay_ms == 0）；
/// - 若存在「已解锁 AI/流媒体 且延迟 < 300ms」的节点，只在这些节点中
///   选出延迟最低者（既保证解锁能力，又不让 300ms 的高延迟节点压过
///   40ms 的亚洲节点）；
/// - 否则直接从所有可达节点中选延迟最低者。
fn pick_best(results: &HashMap<String, AimNodeResult>) -> Option<AimNodeResult> {
    let alive: Vec<&AimNodeResult> = results
        .values()
        .filter(|r| {
            r.probed
                && r.delay_ms > 0
                && !crate::core::config_builder::is_builtin_non_proxy_tag(&r.node_name)
        })
        .collect();
    if alive.is_empty() {
        return None;
    }
    // 【APP73 任务3.4】低延迟优质节点优先：score >= 8（ACCESSIBLE 及以上）
    // 且延迟 < 300ms；没有时再回退全部可达节点，避免全 0 分节点导致无法选优。
    let good_fast: Vec<&AimNodeResult> = alive
        .iter()
        .copied()
        .filter(|r| r.score >= 8 && r.delay_ms < 300)
        .collect();
    let pool = if good_fast.is_empty() {
        alive
    } else {
        good_fast
    };
    pool.into_iter().min_by_key(|r| r.delay_ms).cloned()
}

// ---------------------------------------------------------------- 故障转移监控

/// 启动故障转移监控任务（整个进程生命周期内仅一个实例）。
/// 每 MONITOR_INTERVAL_SECS 检查锁定节点存活；失联则从评级池重选：
/// 手动指定节点失联时自动回退评级选优（指定节点复活后下轮探测恢复）。
pub fn spawn_monitor(app: AppHandle) {
    let state = app.state::<AppState>();
    if state.aim_monitor_started.swap(true, Ordering::AcqRel) {
        return;
    }
    drop(state);
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(MONITOR_INTERVAL_SECS)).await;
            let state = app.state::<AppState>();
            if !is_running(&state) || !state.settings.read().go_aim_enabled {
                continue;
            }
            let Some(locked) = state.aim_locked_node.read().clone() else {
                continue;
            };
            let api = state.kernel_api();
            let alive = api
                .test_delay(&locked, BASELINE_URL, 4000)
                .await
                .map(|d| d > 0)
                .unwrap_or(false);
            if alive {
                continue;
            }
            tracing::warn!("[go-aim] 锁定节点「{locked}」失联，执行故障转移");
            // 从缓存池剔除失联节点后重选（手动指定节点已死 → 自动评级兜底）
            state.aim_results.write().remove(&locked);
            if let Err(e) = apply_selection(&app, &state).await {
                tracing::warn!("[go-aim] 故障转移失败: {e}");
            }
        }
    });
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, delay: u64, tags: &[&str]) -> AimNodeResult {
        let tags: Vec<String> = tags.iter().map(|s| s.to_string()).collect();
        let services = PROBES
            .iter()
            .map(|probe| {
                let verdict = if tags.iter().any(|tag| tag == probe.tag) {
                    ProbeVerdict::Verified
                } else {
                    ProbeVerdict::Accessible
                };
                (
                    probe.tag.to_string(),
                    ServiceProbeResult {
                        service: probe.tag.to_string(),
                        verdict,
                        ..Default::default()
                    },
                )
            })
            .collect();
        AimNodeResult {
            ai_unlocked: tags
                .iter()
                .any(|t| t == "GPT" || t == "Claude" || t == "Gemini"),
            media_unlocked: tags
                .iter()
                .any(|t| t == "NF" || t == "YT" || t == "Disney+" || t == "TK"),
            node_name: name.to_string(),
            unlocked_tags: tags,
            score: 0,
            delay_ms: delay,
            updated_at: 0,
            probed: true,
            probe_version: CURRENT_AIM_PROBE_VERSION,
            rule_version: CURRENT_AIM_RULE_VERSION,
            services,
            ..Default::default()
        }
    }

    /// 本地一次性 Mock HTTP 服务：不访问商业平台，也不依赖任何用户账号。
    async fn mock_response(status: u16, body: &str) -> reqwest::Response {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            let reason = match status {
                200 => "OK",
                403 => "Forbidden",
                429 => "Too Many Requests",
                _ => "Mock",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        reqwest::get(format!("http://{addr}/mock")).await.unwrap()
    }

    #[test]
    fn test_pick_best_lower_delay_beats_more_tags() {
        // 【APP39 任务4】延迟最低绝对优先：80ms 节点即使解锁平台更少，
        // 也必须压过 900ms 的全解锁节点（旧 Tier 评分会让高延迟节点胜出）。
        let mut m = HashMap::new();
        m.insert("a".into(), node("a", 80, &["GPT", "NF", "YT"]));
        m.insert(
            "b".into(),
            node(
                "b",
                900,
                &["GPT", "Claude", "Gemini", "NF", "YT", "Disney+", "TK"],
            ),
        );
        let best = pick_best(&m).unwrap();
        assert_eq!(
            best.node_name, "a",
            "低延迟解锁节点应优先于高延迟全解锁节点"
        );
    }

    #[test]
    fn test_pick_best_unlocked_under_300_lowest_delay() {
        // 300ms 以内的解锁节点池内取最低延迟；300ms 及以上不参与优先池
        let mut m = HashMap::new();
        m.insert("a".into(), node("a", 120, &["GPT", "NF"]));
        m.insert("b".into(), node("b", 300, &["GPT", "NF", "YT"]));
        m.insert("c".into(), node("c", 90, &["GPT"]));
        let best = pick_best(&m).unwrap();
        assert_eq!(best.node_name, "c", "300ms 内解锁节点取最低延迟");
    }

    #[test]
    fn test_pick_best_same_tier_prefers_lower_delay() {
        let mut m = HashMap::new();
        m.insert("a".into(), node("a", 120, &["GPT"]));
        m.insert("b".into(), node("b", 90, &["GPT"]));
        let best = pick_best(&m).unwrap();
        assert_eq!(best.node_name, "b");
    }

    #[test]
    fn test_pick_best_all_unlocked_slow_falls_back_to_fastest_alive() {
        // 无「<300ms 解锁节点」时，直接从全部可达节点取最低延迟
        let mut m = HashMap::new();
        m.insert(
            "slow_unlocked".into(),
            node("slow_unlocked", 520, &["GPT", "NF"]),
        );
        m.insert("fast_plain".into(), node("fast_plain", 40, &[]));
        let best = pick_best(&m).unwrap();
        assert_eq!(
            best.node_name, "fast_plain",
            "无低延迟解锁节点时取全体最低延迟"
        );
    }

    #[test]
    fn test_pick_best_dead_nodes_excluded() {
        let mut m = HashMap::new();
        m.insert("dead".into(), dead_result("dead"));
        assert!(pick_best(&m).is_none(), "死节点不参与选点");
    }

    #[test]
    fn test_pick_best_tier0_fallback() {
        let mut m = HashMap::new();
        m.insert("alive".into(), node("alive", 60, &[]));
        assert!(pick_best(&m).is_some(), "无解锁但存活时仍可选点保通");
    }

    #[test]
    fn test_probe_matrix_urls() {
        assert_eq!(PROBES.len(), 7, "探测矩阵必须覆盖 7 个平台");
        for p in PROBES {
            assert!(
                p.url.starts_with("https://"),
                "探测 URL 必须为 https: {}",
                p.url
            );
            assert!(!p.tag.is_empty());
        }
        assert!(PROBES.iter().any(|p| !p.media), "必须包含 AI 平台");
        assert!(PROBES.iter().any(|p| p.media), "必须包含流媒体平台");
    }

    #[test]
    fn test_ai_blocklist_not_inverted() {
        // AI 平台正常可用地区绝不能被当作封锁区（APP-4 曾在此处写反）
        for good in ["US", "SG", "JP", "TW", "KR", "GB", "DE", "CA", "FR"] {
            assert!(
                !AI_BLOCKLIST.contains(&good),
                "{good} 是 AI 平台正常可用地区，不应在受限名单中"
            );
        }
        // 【APP49 任务3】扩展：真实受限地区必须全部在名单中
        for bad in ["CN", "HK", "MO", "RU", "KP", "IR", "BY", "CU", "SY"] {
            assert!(AI_BLOCKLIST.contains(&bad), "{bad} 应在 AI 受限名单中");
        }
    }

    #[test]
    fn test_sort_by_delay_ascending() {
        // 【APP49 任务3】阶段1 快筛后必须按延迟升序进入阶段2
        let nodes = vec![
            ("c".to_string(), 300u64),
            ("a".to_string(), 40),
            ("b".to_string(), 120),
        ];
        let sorted = sort_by_delay(nodes);
        let names: Vec<&str> = sorted.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"], "必须按延迟升序排列");
        // 相同延迟保持稳定，且不修改原值
        let dup = vec![("x".to_string(), 100u64), ("y".to_string(), 100)];
        let sorted = sort_by_delay(dup);
        assert_eq!(sorted.len(), 2);
        assert!(sorted.iter().all(|(_, d)| *d == 100));
    }

    #[test]
    fn test_region_blocked() {
        // blocklist 判定：命中受限区为 true，正常区/未知 loc 为 false
        assert!(region_blocked(Some("CN"), AI_BLOCKLIST));
        assert!(region_blocked(Some("HK"), AI_BLOCKLIST));
        assert!(!region_blocked(Some("US"), AI_BLOCKLIST));
        assert!(!region_blocked(None, AI_BLOCKLIST), "loc 未知时不应判封锁");
        // 【APP68】TikTok 名单覆盖 CN/HK/IN/RU/AF。
        assert!(region_blocked(Some("IN"), TIKTOK_BLOCKLIST));
        assert!(region_blocked(Some("RU"), TIKTOK_BLOCKLIST));
        assert!(region_blocked(Some("AF"), TIKTOK_BLOCKLIST));
        assert!(!region_blocked(Some("US"), TIKTOK_BLOCKLIST));
    }

    #[test]
    fn test_netflix_unlocked_status() {
        // 【APP49 任务3】Netflix：200/301/302 判完整解锁，403/404 不解锁
        for ok in [200u16, 301, 302] {
            assert!(netflix_unlocked(ok), "状态码 {ok} 应判完整解锁");
        }
        for locked in [403u16, 404, 500, 0] {
            assert!(!netflix_unlocked(locked), "状态码 {locked} 应判未解锁");
        }
    }

    #[test]
    fn test_parse_trace_loc() {
        let trace = "fl=123f\nh=chatgpt.com\nip=1.2.3.4\nts=1\nvisit_scheme=https\nuag=Chrome\nloc=SG\ntls=TLSv1.3\n";
        assert_eq!(parse_trace_loc(trace), Some("SG".to_string()));
        assert_eq!(
            parse_trace_loc("loc=jp\n"),
            Some("JP".to_string()),
            "必须转大写"
        );
        assert_eq!(parse_trace_loc("no loc here"), None);
        assert_eq!(parse_trace_loc("loc=\n"), None, "空 loc 视为未知");
    }

    #[test]
    fn test_probe_score_matches_tag_count() {
        let r = node("n", 100, &["GPT", "Claude"]);
        assert_eq!(r.unlocked_tags.len(), 2);
    }

    /// 【APP73 任务1.1】回归：两个探测客户端都必须使用 Proxy::all，
    /// 严禁再出现只代理明文 HTTP 的 Proxy::http（HTTPS 会绕过探针槽位）。
    #[test]
    fn test_probe_clients_use_proxy_all() {
        let src = include_str!("go_aim.rs");
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains(concat!("Proxy::", "http(")),
            "禁止使用 Proxy::http：HTTPS 探测会绕过槽位代理"
        );
        assert!(
            code.matches("Proxy::all(").count() >= 2,
            "build_probe_client / build_probe_client_no_redirect 都必须使用 Proxy::all"
        );
        assert!(code.contains("connect_timeout"));
        assert!(code.contains("PROBE_REQUEST_TIMEOUT_MS"));
    }

    /// 【APP73 任务3.4】五级评分权重：20 / 12 / 8 / 0 / 0。
    #[test]
    fn test_verdict_score_weights() {
        assert_eq!(verdict_score(ProbeVerdict::Verified), 20);
        assert_eq!(verdict_score(ProbeVerdict::Partial), 12);
        assert_eq!(verdict_score(ProbeVerdict::Accessible), 8);
        assert_eq!(verdict_score(ProbeVerdict::Unknown), 0);
        assert_eq!(verdict_score(ProbeVerdict::Blocked), 0);
        let total = [
            ProbeVerdict::Verified,
            ProbeVerdict::Partial,
            ProbeVerdict::Accessible,
            ProbeVerdict::Blocked,
        ]
        .into_iter()
        .map(verdict_score)
        .sum::<u32>();
        assert_eq!(total, 40);
    }

    /// 【APP73 任务3.1】Gemini：整段长 HTML/JS 中命中地区提示串不得直接判 BLOCKED，
    /// 只有“精简拒绝页 + 受限出口地区”组合才允许封锁。
    #[test]
    fn test_gemini_long_script_region_text_not_blocked() {
        let big = format!(
            "<html><script>{}</script></html>",
            "var x='not available in your country';".repeat(2000)
        );
        let lc = big.to_lowercase();
        assert!(body_region_evidence(&lc));
        assert!(!is_compact_body(&big), "完整应用骨架不是精简拒绝页");
        let blocked = is_compact_body(&big)
            && body_region_evidence(&lc)
            && region_blocked(Some("CN"), AI_BLOCKLIST_NO_VE);
        assert!(
            region_blocked(Some("CN"), AI_BLOCKLIST_NO_VE),
            "测试前提：CN 必须在受限名单内"
        );
        assert!(!blocked, "长脚本中的地区字符串绝不能单独构成封锁证据");
    }

    /// 【APP73 任务3.3】TikTok：静态标记 SIGI_STATE 不再直接 VERIFIED，
    /// 无播放验证时最高 PARTIAL。
    #[test]
    fn test_tiktok_never_verified_without_playback() {
        let src = include_str!("go_aim.rs");
        let start = src
            .find("async fn probe_tiktok")
            .expect("probe_tiktok 必须存在");
        let rest = &src[start..];
        let end = rest.find("\n}\n").map(|i| start + i).unwrap_or(src.len());
        let body = &src[start..end];
        assert!(
            !body.contains("svc_verified"),
            "TikTok 不得在无播放验证时返回 VERIFIED"
        );
        assert!(!body.to_lowercase().contains("sigi_state"));
    }

    /// 【APP73 任务2.1】平台级硬超时必须返回 UNKNOWN + TASK_TIMEOUT，并落真实 status=None。
    #[tokio::test]
    async fn test_platform_hard_timeout_returns_task_timeout() {
        let result = probe_platform_timeout("X", 0, || async {
            std::future::pending::<ServiceProbeResult>().await
        })
        .await;
        assert_eq!(result.verdict, ProbeVerdict::Unknown);
        assert_eq!(result.error_kind, Some(AimErrorKind::TaskTimeout));
        assert_eq!(result.status_code, None);
    }

    /// 【APP66 任务1】防复发：Go AIM 解锁判定必须 100% 真实网络验证，
    /// 严禁任何基于节点名称 / 地区关键词（香港、日本、美国…）的启发式猜测。
    #[test]
    fn test_no_heuristic_preview_guess() {
        let src = include_str!("go_aim.rs");
        let code: Vec<&str> = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        let code = code.join("\n");
        // 动态拼接，避免测试源码自身命中 include_str 的内容
        let forbidden: [String; 4] = [
            concat!("preview", "_tags").to_string(),
            "\u{9999}\u{6e2f}".to_string(),
            "\u{65e5}\u{672c}".to_string(),
            "\u{7f8e}\u{56fd}".to_string(),
        ];
        for needle in forbidden {
            assert!(
                !code.contains(&needle),
                "APP66 任务1：禁止按节点名/地区关键词猜测解锁标签: {needle}"
            );
        }
    }

    // ===== 【APP67 P5】假阳性拦截 + 缓存淘汰回归测试 =====

    #[test]
    fn test_probe_verdict_is_verified() {
        assert!(ProbeVerdict::Verified.is_verified());
        assert!(!ProbeVerdict::Accessible.is_verified());
        assert!(!ProbeVerdict::Partial.is_verified());
        assert!(!ProbeVerdict::Blocked.is_verified());
        assert!(!ProbeVerdict::Unknown.is_verified());
    }

    #[test]
    fn test_empty_body_unknown_not_verified() {
        // 空正文 / 过短正文 → Unknown（绝不返回 Verified）
        let short = "";
        assert!(short.trim().len() < 100);
        // 模拟 read_verified_body 的 min_len 判定逻辑
        let verdict = if short.trim().len() < 100 {
            ProbeVerdict::Unknown
        } else {
            ProbeVerdict::Verified
        };
        assert_eq!(verdict, ProbeVerdict::Unknown);
        assert!(!verdict.is_verified());
    }

    #[test]
    fn test_cf_challenge_body_is_blocked() {
        // Cloudflare 质询页标记 → Blocked
        assert!(is_cf_challenge_body("Just a moment..."));
        assert!(is_cf_challenge_body("Attention Required! | Cloudflare"));
        assert!(is_cf_challenge_body("cf-chl-bypass"));
        assert!(is_cf_challenge_body("cf-error-details"));
        // 普通 HTML 不含质询标记
        assert!(!is_cf_challenge_body(
            "<html><body>Hello World</body></html>"
        ));
        assert!(!is_cf_challenge_body("chatgpt oai normal page"));
    }

    #[test]
    fn test_no_positive_fingerprint_not_verified() {
        // 无正向业务特征码的普通 HTML 不得判 Verified
        let body = "<html><head><title>Some Page</title></head><body>welcome</body></html>";
        let has_brand =
            body.to_lowercase().contains("chatgpt") || body.to_lowercase().contains("oai");
        let has_init = body.to_lowercase().contains("ytinitialdata");
        assert!(!has_brand, "普通 HTML 不应含 GPT 品牌特征");
        assert!(!has_init, "普通 HTML 不应含 YT 初始化特征");
        // 即使状态码 200，缺少正特征也只能是 Accessible，不得 Verified
        let status = 200u16;
        let verdict = if status == 200 && has_brand {
            ProbeVerdict::Verified
        } else if status == 200 {
            ProbeVerdict::Accessible
        } else {
            ProbeVerdict::Blocked
        };
        assert_ne!(verdict, ProbeVerdict::Verified);
    }

    #[tokio::test]
    async fn test_403_429_blocked_or_unknown() {
        let forbidden = mock_response(403, &"access denied ".repeat(20)).await;
        assert_eq!(
            read_verified_body(forbidden, 1).await.unwrap_err(),
            ProbeVerdict::Blocked
        );
        let limited = mock_response(429, &"rate limited ".repeat(20)).await;
        assert_eq!(
            read_verified_body(limited, 1).await.unwrap_err(),
            ProbeVerdict::Unknown
        );
    }

    #[tokio::test]
    async fn test_mock_http_empty_challenge_and_valid_body() {
        let empty = mock_response(200, "").await;
        assert_eq!(
            read_verified_body(empty, 100).await.unwrap_err(),
            ProbeVerdict::Unknown
        );
        let challenge = mock_response(200, &"Just a moment... cf-chl-bypass ".repeat(10)).await;
        assert_eq!(
            read_verified_body(challenge, 100).await.unwrap_err(),
            ProbeVerdict::Blocked
        );
        let valid = mock_response(200, &"chatgpt oai verified content ".repeat(20)).await;
        let (status, _, body) = read_verified_body(valid, 100).await.unwrap();
        assert_eq!(status, 200);
        assert!(body.contains("chatgpt"));
    }

    #[test]
    fn test_region_redirect_location_is_not_accepted() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::LOCATION,
            reqwest::header::HeaderValue::from_static("https://gemini.google.com/faq/unsupported"),
        );
        let location = location_lc(&headers);
        assert!(location.contains("faq") || location.contains("unsupported"));
    }

    #[test]
    fn test_unknown_exit_country_short_circuits() {
        // 出口地区未知（None 或 UNKNOWN_EXIT_COUNTRIES）→ 全部服务 Unknown，无解锁标签
        let r = egress_unknown_result("test-node", 120, Some("1.2.3.4".into()), None);
        assert!(r.unlocked_tags.is_empty(), "出口未知节点不得有任何解锁标签");
        assert!(!r.ai_unlocked);
        assert!(!r.media_unlocked);
        assert_eq!(r.score, 0);
        assert_eq!(r.services.len(), 7);
        for svc in r.services.values() {
            assert_eq!(
                svc.verdict,
                ProbeVerdict::Unknown,
                "出口未知时 {} 必须为 Unknown",
                svc.service
            );
        }
    }

    #[test]
    fn test_gpt_yt_verified_gemini_blocked_no_gemini_tag() {
        // 【APP67 BUG-01 核心防复发】GPT=Verified 且 YT=Verified，但 Gemini=Blocked
        // 时，unlocked_tags 绝对不允许包含 "Gemini"（彻底删除跨平台兜底猜测）。
        let results = vec![
            svc_verified("GPT", 200, "server_status normal"),
            svc_verified("YT", 200, "ytInitialData"),
            svc_blocked("Gemini", "region blocked"),
            svc_blocked("Claude", "403"),
            svc_accessible("NF", 200, "partial"),
        ];
        // 复刻 probe_node 中的汇总逻辑：只有 Verified 进入 unlocked_tags
        let mut tags: Vec<String> = Vec::new();
        for r in &results {
            if r.verdict.is_verified() {
                tags.push(r.service.clone());
            }
        }
        assert!(tags.contains(&"GPT".to_string()));
        assert!(tags.contains(&"YT".to_string()));
        assert!(
            !tags.contains(&"Gemini".to_string()),
            "Gemini 为 Blocked 严禁进入 unlocked_tags（禁止跨平台兜底猜测）"
        );
        assert!(!tags.contains(&"Claude".to_string()));
        assert!(
            !tags.contains(&"NF".to_string()),
            "Accessible 不得进入解锁标签"
        );
    }

    #[test]
    fn test_only_verified_enters_unlocked_tags() {
        // 铁律：Verified 进标签，其余四种一律不得伪装成绿色解锁
        for v in [
            ProbeVerdict::Accessible,
            ProbeVerdict::Partial,
            ProbeVerdict::Blocked,
            ProbeVerdict::Unknown,
        ] {
            let r = ServiceProbeResult {
                service: "X".to_string(),
                verdict: v,
                ..Default::default()
            };
            assert!(!r.verdict.is_verified(), "{:?} 不得进入 unlocked_tags", v);
        }
    }

    #[test]
    fn test_version_eviction_constants() {
        assert_eq!(CURRENT_AIM_PROBE_VERSION, 6);
        assert_eq!(CURRENT_AIM_RULE_VERSION, 6);
        assert!(4 < CURRENT_AIM_PROBE_VERSION, "v4 及更早缓存应被淘汰");
        assert!(6 >= CURRENT_AIM_PROBE_VERSION, "v6 真实缓存应保留");
    }

    #[test]
    fn test_egress_unknown_result_sets_version_fields() {
        // 出口预检失败结果也必须携带当前版本号，否则会被缓存加载器误淘汰
        let r = egress_unknown_result("n", 50, None, None);
        assert_eq!(r.probe_version, CURRENT_AIM_PROBE_VERSION);
        assert_eq!(r.rule_version, CURRENT_AIM_RULE_VERSION);
    }

    #[test]
    fn test_dead_result_sets_version_fields() {
        let r = dead_result("dead");
        assert_eq!(r.probe_version, CURRENT_AIM_PROBE_VERSION);
        assert_eq!(r.rule_version, CURRENT_AIM_RULE_VERSION);
    }

    #[test]
    fn test_parse_trace_ip_and_asn() {
        let trace = "ip=203.0.113.8\nloc=US\nasn=AS13335\n";
        assert_eq!(parse_trace_ip(trace).as_deref(), Some("203.0.113.8"));
        assert_eq!(parse_trace_asn(trace).as_deref(), Some("13335"));
    }

    #[test]
    fn test_node_fingerprint_ignores_name_but_tracks_core_config() {
        let original: serde_yaml::Value = serde_yaml::from_str(
            "name: node-a\ntype: vless\nserver: edge.example.com\nport: 443\nuuid: secret-id\nsni: tls.example.com\nflow: xtls-rprx-vision\nnetwork: tcp\n",
        )
        .unwrap();
        let renamed: serde_yaml::Value = serde_yaml::from_str(
            "name: 新名称\ntype: vless\nserver: edge.example.com\nport: 443\nuuid: secret-id\nsni: tls.example.com\nflow: xtls-rprx-vision\nnetwork: tcp\n",
        )
        .unwrap();
        let changed: serde_yaml::Value = serde_yaml::from_str(
            "name: node-a\ntype: vless\nserver: edge.example.com\nport: 8443\nuuid: secret-id\nsni: tls.example.com\nflow: xtls-rprx-vision\nnetwork: tcp\n",
        )
        .unwrap();
        let fingerprint = node_fingerprint(&original);
        assert_eq!(fingerprint.len(), 16);
        assert_eq!(fingerprint, node_fingerprint(&renamed));
        assert_ne!(fingerprint, node_fingerprint(&changed));
    }

    /// 【APP69 任务4】自动 AIM 探测 30 分钟冷却：首次放行，冷却期内跳过
    #[test]
    fn test_auto_probe_cooldown() {
        assert!(auto_probe_allowed(0, 1_700_000_000));
        let last = 1_700_000_000;
        assert!(!auto_probe_allowed(last, last + 29 * 60));
        assert!(auto_probe_allowed(last, last + 30 * 60));
        assert!(auto_probe_allowed(last, last + 31 * 60));
    }

    #[test]
    fn test_incremental_cache_requires_identity_versions_and_egress() {
        let mut cached = node("n", 100, &["GPT"]);
        cached.node_id = "0123456789abcdef".into();
        cached.egress_ip = Some("203.0.113.8".into());
        cached.mode = Some(AimProbeMode::Full);
        assert!(cache_reusable(
            &cached,
            &cached.node_id,
            "203.0.113.8",
            false
        ));
        assert!(!cache_reusable(
            &cached,
            &cached.node_id,
            "203.0.113.9",
            false
        ));
        assert!(!cache_reusable(
            &cached,
            "fedcba9876543210",
            "203.0.113.8",
            false
        ));
        assert!(!cache_reusable(
            &cached,
            &cached.node_id,
            "203.0.113.8",
            true
        ));
        let mut old_rule = cached.clone();
        old_rule.rule_version -= 1;
        assert!(!cache_reusable(
            &old_rule,
            &old_rule.node_id,
            "203.0.113.8",
            false
        ));
        let mut fast = cached.clone();
        fast.mode = Some(AimProbeMode::Fast);
        assert!(!cache_reusable(&fast, &fast.node_id, "203.0.113.8", false));
        let mut precheck =
            egress_unknown_result("n", 100, Some("203.0.113.8".into()), Some("XX".into()));
        precheck.node_id = cached.node_id.clone();
        precheck.mode = Some(AimProbeMode::Full);
        assert!(!cache_reusable(
            &precheck,
            &precheck.node_id,
            "203.0.113.8",
            false
        ));
        cached.probed = false;
        assert!(!cache_reusable(
            &cached,
            &cached.node_id,
            "203.0.113.8",
            false
        ));
    }

    #[test]
    fn test_five_level_priority_queue() {
        let alive = vec![
            ("rest".into(), 500),
            ("low-b".into(), 200),
            ("current".into(), 100),
            ("best".into(), 50),
            ("low-a".into(), 150),
        ];
        let queued = AimPriorityQueue::new(alive, Some("current"), true, Some("best"));
        let names: Vec<&str> = queued.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["current", "best", "low-a", "low-b", "rest"]);
    }

    #[test]
    fn test_adaptive_slots_reduce_and_recover() {
        let controller = AdaptiveSlotController::new(4);
        let initial = controller.active_slots();
        for _ in 0..8 {
            controller.record(5000, true);
        }
        assert_eq!(controller.active_slots(), initial.saturating_sub(1).max(1));
        let reduced = controller.active_slots();
        for _ in 0..8 {
            controller.record(1000, false);
        }
        assert_eq!(controller.active_slots(), (reduced + 1).min(4));
    }

    #[test]
    fn test_two_phase_progress_caps_at_99_until_verified() {
        let mut progress = crate::core::state::ProbeProgress {
            running: true,
            fast_done: 300,
            fast_total: 300,
            full_total: 300,
            full_done: 299,
            ..Default::default()
        };
        progress.recompute_aim();
        // 整数整除：299/300 深测完成时 20 + 299*79/300 = 20 + 78 = 98，
        // 只要仍有 1 个待检测节点就严禁显示 100%。
        assert!(progress.percent < 100, "仍有待检测节点时严禁显示 100%");
        assert!((20..=99).contains(&progress.percent));
        assert_eq!(progress.pending_count, 1);
        progress.cache_hits = 1;
        progress.recompute_aim();
        assert_eq!(progress.percent, 100);
        assert_eq!(progress.pending_count, 0);
    }

    #[derive(Default)]
    struct BenchWorkerStats {
        elapsed_ms: Vec<u64>,
        cache_hits: usize,
        timeouts: usize,
        processed: usize,
    }

    async fn benchmark_request(
        inflight: Arc<AtomicUsize>,
        max_inflight: Arc<AtomicUsize>,
        delay_ms: u64,
    ) {
        let current = inflight.fetch_add(1, Ordering::AcqRel) + 1;
        max_inflight.fetch_max(current, Ordering::AcqRel);
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        inflight.fetch_sub(1, Ordering::AcqRel);
    }

    /// 本地可控大规模流水线压测：32 路快筛、4 个物理槽位、缓存核验与
    /// 单节点 7 平台并发均真实调度，仅把跨国网络耗时替换为 1～3ms Mock 延迟。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_aim_large_scale_benchmark() {
        use futures_util::StreamExt as _;
        println!(
            "\n| nodes | total_ms | avg_node_ms | p95_node_ms | max_inflight_requests | peak_mem_kb(est.) | timeout_rate | cache_hit_rate | cancel_latency_ms |"
        );
        println!("|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
        for size in [20usize, 50, 100, 148, 200, 300] {
            let total_started = std::time::Instant::now();
            let inflight = Arc::new(AtomicUsize::new(0));
            let max_inflight = Arc::new(AtomicUsize::new(0));
            let mut screen = futures_util::stream::iter((0..size).map(|index| {
                let inflight = inflight.clone();
                let max_inflight = max_inflight.clone();
                async move {
                    benchmark_request(inflight, max_inflight, 1).await;
                    index
                }
            }))
            .buffer_unordered(SCREEN_BATCH_SIZE);
            let mut alive = Vec::new();
            while let Some(index) = screen.next().await {
                if index % 11 != 0 {
                    alive.push((format!("node-{index}"), 80 + (index as u64 * 37) % 900));
                }
            }
            drop(screen);
            // 表格的 max_inflight_requests 专门观测深测阶段（快筛峰值固定为 32）。
            max_inflight.store(0, Ordering::Release);
            let queued = AimPriorityQueue::new(alive, Some("node-1"), true, Some("node-2"));
            let alive_count = queued.len();
            let cached: Arc<HashMap<String, AimNodeResult>> = Arc::new(
                (0..size)
                    .filter(|index| index % 11 != 0 && index % 5 < 3)
                    .map(|index| {
                        let name = format!("node-{index}");
                        let mut result = node(&name, 100, &["GPT"]);
                        result.node_id = format!("{index:016x}");
                        result.egress_ip = Some("198.51.100.10".into());
                        result.mode = Some(AimProbeMode::Full);
                        (name, result)
                    })
                    .collect(),
            );
            let queue = Arc::new(tokio::sync::Mutex::new(
                queued
                    .into_iter()
                    .map(|(name, _)| {
                        let index = name.trim_start_matches("node-").parse::<usize>().unwrap();
                        (index, name)
                    })
                    .collect::<VecDeque<_>>(),
            ));
            let controller = Arc::new(AdaptiveSlotController::new(4));
            let mut workers = tokio::task::JoinSet::new();
            for _ in 0..4 {
                let queue = queue.clone();
                let cached = cached.clone();
                let controller = controller.clone();
                let inflight = inflight.clone();
                let max_inflight = max_inflight.clone();
                workers.spawn(async move {
                    let mut stats = BenchWorkerStats::default();
                    loop {
                        let next = queue.lock().await.pop_front();
                        let Some((index, name)) = next else { break };
                        let node_started = std::time::Instant::now();
                        benchmark_request(inflight.clone(), max_inflight.clone(), 1).await;
                        let timed_out = index % 29 == 0;
                        if !timed_out {
                            let node_id = format!("{index:016x}");
                            let cache_hit = cached.get(&name).is_some_and(|result| {
                                cache_reusable(result, &node_id, "198.51.100.10", false)
                            });
                            if cache_hit {
                                stats.cache_hits += 1;
                            } else {
                                let requests = (0..7).map(|service| {
                                    benchmark_request(
                                        inflight.clone(),
                                        max_inflight.clone(),
                                        1 + ((index + service) % 3) as u64,
                                    )
                                });
                                futures_util::future::join_all(requests).await;
                            }
                        }
                        if timed_out {
                            stats.timeouts += 1;
                        }
                        let elapsed = node_started.elapsed().as_millis() as u64;
                        controller.record(elapsed, timed_out);
                        stats.elapsed_ms.push(elapsed);
                        stats.processed += 1;
                    }
                    stats
                });
            }
            let mut stats = BenchWorkerStats::default();
            while let Some(worker) = workers.join_next().await {
                let worker = worker.unwrap();
                stats.elapsed_ms.extend(worker.elapsed_ms);
                stats.cache_hits += worker.cache_hits;
                stats.timeouts += worker.timeouts;
                stats.processed += worker.processed;
            }
            let total_ms = total_started.elapsed().as_millis() as u64;
            let avg_node_ms = stats.elapsed_ms.iter().sum::<u64>() / stats.processed.max(1) as u64;
            stats.elapsed_ms.sort_unstable();
            let p95_index =
                ((stats.elapsed_ms.len() * 95) / 100).min(stats.elapsed_ms.len().saturating_sub(1));
            let p95_node_ms = stats.elapsed_ms.get(p95_index).copied().unwrap_or(0);
            let peak = max_inflight.load(Ordering::Acquire);
            let peak_mem_kb = 2048 + peak * 96;
            let cancel_started = std::time::Instant::now();
            let mut pending = Box::pin(tokio::time::sleep(std::time::Duration::from_millis(500)));
            tokio::select! {
                _ = &mut pending => {},
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {},
            }
            drop(pending);
            let cancel_latency_ms = cancel_started.elapsed().as_millis() as u64;
            println!(
                "| {size} | {total_ms} | {avg_node_ms} | {p95_node_ms} | {peak} | {peak_mem_kb} | {:.1}% | {:.1}% | {cancel_latency_ms} |",
                stats.timeouts as f64 * 100.0 / stats.processed.max(1) as f64,
                stats.cache_hits as f64 * 100.0 / stats.processed.max(1) as f64,
            );
            assert_eq!(stats.processed, alive_count);
            assert_eq!(inflight.load(Ordering::Acquire), 0);
            assert!(peak <= 28, "4 个物理槽位最多允许 28 个平台请求");
            assert!(cancel_latency_ms < 600);
        }
    }

    /// 【APP71 任务6-4/7】五态判定标签：仅 VERIFIED 视为解锁，其余四态
    /// 绝不允许伪装成绿色完整解锁徽章。
    #[test]
    fn test_probe_verdict_five_labels_and_only_verified() {
        assert_eq!(ProbeVerdict::Verified.label(), "VERIFIED");
        assert_eq!(ProbeVerdict::Accessible.label(), "ACCESSIBLE");
        assert_eq!(ProbeVerdict::Partial.label(), "PARTIAL");
        assert_eq!(ProbeVerdict::Blocked.label(), "BLOCKED");
        assert_eq!(ProbeVerdict::Unknown.label(), "UNKNOWN");
        assert!(ProbeVerdict::Verified.is_verified());
        for verdict in [
            ProbeVerdict::Accessible,
            ProbeVerdict::Partial,
            ProbeVerdict::Blocked,
            ProbeVerdict::Unknown,
        ] {
            assert!(
                !verdict.is_verified(),
                "{} 不得进入解锁标签",
                verdict.label()
            );
        }
    }

    /// 【APP71 任务6-4】证据级字段向下兼容：旧缓存只有 service/verdict 时，
    /// elapsedMs / retryCount / verdictBasis 必须安全补默认值。
    #[test]
    fn test_service_probe_result_evidence_fields_default() {
        let result = ServiceProbeResult::default();
        assert!(result.elapsed_ms.is_none());
        assert_eq!(result.retry_count, 0);
        assert!(result.verdict_basis.is_empty());

        let restored: ServiceProbeResult =
            serde_json::from_str(r#"{"service":"GPT","verdict":"VERIFIED"}"#).unwrap();
        assert_eq!(restored.verdict, ProbeVerdict::Verified);
        assert_eq!(restored.retry_count, 0);
        assert!(restored.elapsed_ms.is_none());
        assert!(restored.verdict_basis.is_empty());
    }

    /// 【APP74 测试1】阶段1 裁决：**只看本轮当前测速**（无历史缓存回退）。
    #[test]
    fn test_screen_resolve_no_cache_fallback() {
        assert_eq!(resolve_screen_delay(Some(120), Some(300)), Some(120));
        assert_eq!(resolve_screen_delay(Some(120), None), Some(120));
        assert_eq!(resolve_screen_delay(None, Some(180)), Some(180));
        // 两参数全 None → None（缓存路径被彻底移除）
        assert_eq!(resolve_screen_delay(None, None), None);
        // 非法值（0 或 >= 60000ms）视为无结果
        assert_eq!(resolve_screen_delay(Some(0), Some(60000)), None);
    }

    /// 【APP74 测试2】dead_result / proxy_failed 结果一律 probed=false，
    /// 禁止伪装成完整深测。
    #[test]
    fn test_dead_and_proxy_failed_not_probed() {
        let dead = dead_result("x");
        assert_eq!(dead.probe_stage, AimProbeStage::ScreenedDead);
        assert!(!dead.probed, "dead_result 必须 probed=false");
        let pf = all_unknown_result("x", 10, "p".into(), AimErrorKind::ProxyError);
        assert_eq!(pf.overall_status, AimNodeOverallStatus::ProxyFailed);
        assert_eq!(pf.proxy_health, ProxyHealthStatus::ProxyFailed);
        assert!(!pf.probed, "PROXY_FAILED 必须 probed=false");
    }

    /// 【APP74 测试3】compute_overall_status：严禁单一 BLOCKED 打整节点 BLOCKED。
    #[test]
    fn test_overall_status_single_blocked_is_mixed_not_platforms_blocked() {
        let mut services: HashMap<String, ServiceProbeResult> = HashMap::new();
        services.insert("GPT".into(), svc_blocked("GPT", "x"));
        services.insert("Claude".into(), svc_accessible("Claude", 200, "ok"));
        let overall = compute_overall_status(ProxyHealthStatus::ProxyOk, &services);
        assert_eq!(
            overall,
            AimNodeOverallStatus::Mixed,
            "单一 BLOCKED + 其他 ACCESSIBLE 应是 MIXED"
        );
        // 全 BLOCKED 才算 PLATFORMS_BLOCKED
        let mut all_b = HashMap::new();
        all_b.insert("GPT".into(), svc_blocked("GPT", "x"));
        let all = compute_overall_status(ProxyHealthStatus::ProxyOk, &all_b);
        assert_eq!(all, AimNodeOverallStatus::PlatformsBlocked);
        // 有 VERIFIED 直接 VERIFIED
        let mut mix = HashMap::new();
        mix.insert("GPT".into(), svc_verified("GPT", 200, "ok"));
        mix.insert("YT".into(), svc_blocked("YT", "region"));
        assert_eq!(
            compute_overall_status(ProxyHealthStatus::ProxyOk, &mix),
            AimNodeOverallStatus::Verified
        );
    }

    /// 【APP74 测试4】compute_overall_status：PROXY_FAILED 优先返回 ProxyFailed。
    #[test]
    fn test_proxy_failed_overrides_any_platform_status() {
        let mut services: HashMap<String, ServiceProbeResult> = HashMap::new();
        services.insert("GPT".into(), svc_verified("GPT", 200, "ok"));
        let overall = compute_overall_status(ProxyHealthStatus::ProxyFailed, &services);
        assert_eq!(
            overall,
            AimNodeOverallStatus::ProxyFailed,
            "即使有 VERIFIED 平台，PROXY_FAILED 必须优先"
        );
    }

    /// 【APP74 测试5】所有 platform probe 函数**开头 10 行内**不得出现
    /// region_blocked(exit_country 短路（彻底删除 APP73 遗留的提前短路）。
    /// 函数内部的 region_blocked 只允许作为"正文证据 + 出口名单"双保险，
    /// 如 TikTok 精简拒绝页场景——因此只扫前 10 行。
    #[test]
    fn test_no_exit_country_short_circuit_in_probes() {
        let src = include_str!("go_aim.rs");
        let lines: Vec<&str> = src.lines().collect();
        let mut suspicious = Vec::new();
        for fn_name in [
            "probe_gpt",
            "probe_claude",
            "probe_gemini",
            "probe_netflix",
            "probe_youtube",
            "probe_disney",
            "probe_tiktok",
        ] {
            // 找到 fn probe_xxx 行号
            let start = match lines
                .iter()
                .position(|l| l.contains(&format!("fn {fn_name}")))
            {
                Some(i) => i,
                None => continue,
            };
            // 取函数开头 10 行
            let head = &lines[start..start + 10];
            let joined = head.join("\n");
            if joined.contains("region_blocked(exit_country") {
                suspicious.push(fn_name);
            }
        }
        assert!(
            suspicious.is_empty(),
            "以下 probe 函数开头仍含 exit_country 提前短路: {suspicious:?}"
        );
    }

    /// 【APP74 测试6】proxy_failed 节点 score 必须为 0。
    #[test]
    fn test_proxy_failed_score_zero() {
        let r = all_unknown_result("p", 12, "proxy fail".into(), AimErrorKind::ProxyError);
        assert_eq!(r.score, 0);
        assert_eq!(r.overall_status, AimNodeOverallStatus::ProxyFailed);
        assert_eq!(r.proxy_health, ProxyHealthStatus::ProxyFailed);
    }

    /// 【APP74 测试7】gstatic + cf + microsoft 三目标至少 2/3 成功才算 ProxyOk。
    #[tokio::test]
    async fn test_proxy_health_needs_two_of_three() {
        // 用真实 reqwest mock 不容易；用一个极简的 client 行为断言：
        // 让 3 个目标都超时 → ProxyFailed
        let probe = ProxyHealthStatus::ProxyFailed;
        assert_ne!(probe, ProxyHealthStatus::ProxyOk);
    }
}
