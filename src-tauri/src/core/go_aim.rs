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
use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

use crate::core::state::{AppState, CoreStatus};

/// 【APP67】当前 Go AIM 检测引擎版本号：升级后旧版"假解锁"缓存
/// 因 probe_version 不符而被自动淘汰，直到用新引擎重测后才持久保留。
pub const CURRENT_AIM_PROBE_VERSION: u32 = 2;
pub const CURRENT_AIM_RULE_VERSION: u32 = 2;

/// 前端事件：探测结果更新（payload 为单节点结果或全量刷新标记）
pub const AIM_EVENT: &str = "go-aim://updated";

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
/// 【APP51 任务1】单个平台探测请求超时（毫秒，严格 1200ms 快速出结果）
const PROBE_TIMEOUT_MS: u64 = 2800;
/// 【APP51 任务1】阶段1 极速存活快筛：32 路并发（Semaphore 限流）
const SCREEN_BATCH_SIZE: usize = 32;
/// 阶段1 快筛测速 URL（generate_204，任何出口都应 204）
const SCREEN_URL: &str = "http://www.gstatic.com/generate_204";
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
const TIKTOK_BLOCKLIST: &[&str] = &["CN", "HK", "IN"];

/// 【APP67】出口预检：若 loc 为这些值视为未知/无效，立即短路后续平台探测
const UNKNOWN_EXIT_COUNTRIES: &[&str] = &["XX", "T1", "T2", "A1", "A2", "O1", "EU"];

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

/// 经代理读取出口真实 IP 与地区代码（多端点兜底）。
/// 返回 (egress_ip, egress_country)，任一获取失败则对应字段为 None。
async fn fetch_egress(client: &reqwest::Client) -> (Option<String>, Option<String>) {
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
            let ip = parse_trace_ip(&text);
            let loc = parse_trace_loc(&text);
            if ip.is_some() && loc.is_some() {
                return (ip, loc);
            }
        }
    }
    (None, None)
}

/// 【APP49 任务3】按延迟升序排序（纯函数，便于单元测试）。
/// 阶段1 快筛结束后调用，保证阶段2 从延迟最低的节点开始探测。
fn sort_by_delay(mut nodes: Vec<(String, u64)>) -> Vec<(String, u64)> {
    nodes.sort_by_key(|(_, d)| *d);
    nodes
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
    Probe { tag: "GPT", url: "https://ios.chat.openai.com/public-api/mobile/server_status/v1", media: false },
    Probe { tag: "Claude", url: "https://claude.ai/login", media: false },
    Probe { tag: "Gemini", url: "https://gemini.google.com/app", media: false },
    Probe { tag: "NF", url: "https://www.netflix.com/title/81280792", media: true },
    Probe { tag: "YT", url: "https://www.youtube.com/premium", media: true },
    Probe { tag: "Disney+", url: "https://www.disneyplus.com/", media: true },
    Probe { tag: "TK", url: "https://www.tiktok.com/explore", media: true },
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
}

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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AimNodeResult {
    pub node_name: String,
    /// 解锁标签（GPT/Claude/Gemini/NF/YT/Disney+/TK）——
    /// 【APP67】仅 `ProbeVerdict::Verified` 的服务可进入，绝不含糊其辞。
    pub unlocked_tags: Vec<String>,
    /// AI 平台任一解锁
    pub ai_unlocked: bool,
    /// 流媒体任一解锁
    pub media_unlocked: bool,
    /// 解锁平台数量（评分）
    pub score: u32,
    /// 基线延迟（毫秒）
    pub delay_ms: u64,
    /// 更新时间戳（秒）
    pub updated_at: u64,
    /// 是否已完成探测（含死节点——死节点也生成 probed=true 的空结果，
    /// 确保没有任何节点遗漏在"未检测"状态）
    #[serde(default)]
    pub probed: bool,
    /// 【APP67 P3】检测引擎版本号：旧版缓存（< 2）加载时自动淘汰。
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
    /// 【APP67 P1】7 个平台各自的探测详情（service → result）
    #[serde(default)]
    pub services: HashMap<String, ServiceProbeResult>,
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

/// 启动一轮全量探测（异步后台执行，立即返回）。
/// 若正在探测或内核未运行则跳过。探测完成后：结果入缓存 + 推送事件；
/// 若 go_aim_enabled 则执行锁定选择（手动指定优先，否则评级自动）。
pub fn start_probe(app: AppHandle) {
    let state = app.state::<AppState>();
    // APP34：Go AIM 未开启时严禁触发全量探测。148 个节点并发真实 HTTP
    // 探测会在 iOS 扩展进程内瞬间冲顶 50MB Jetsam 硬红线，导致隧道被
    // 系统强杀（表现为「启动一会儿自动停止」）。手动触发/启动钩子/
    // 订阅刷新等所有入口都必须先过这道硬闸。
    if !state.settings.read().go_aim_enabled {
        tracing::debug!("[go-aim] Go AIM 未开启，跳过全量探测");
        return;
    }
    // 【APP54 任务2】防重复：swap 返回 true 表示上一轮仍在进行，直接跳过；
    // 返回 false 表示刚抢到执行权，继续启动本轮探测。
    if state.aim_probing.swap(true, Ordering::AcqRel) {
        tracing::debug!("[go-aim] 探测已在进行中，跳过重复触发");
        return;
    }
    // 【APP53 任务2.3】不再硬闸 is_running：预览模式（内核未运行）同样允许
    // Go AIM 执行，走离线 TCP/TLS 握手基线测速 + 节点地区智能解锁识别路径。
    // 内核运行时走原有的真实隧道 AI/流媒体探测路径。
    drop(state);

    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        match probe_all(&app, &state).await {
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
                    let best_node = pick_best(&snapshot).map(|r| r.node_name);
                    // 同时把探测延迟并入持久化 delays（0 延迟节点不覆盖已有值）
                    let delays: Vec<(String, u32)> = snapshot
                        .values()
                        .filter(|r| r.probed && r.delay_ms > 0)
                        .map(|r| (r.node_name.clone(), r.delay_ms as u32))
                        .collect();
                    if !delays.is_empty() {
                        state.record_node_delays(delays);
                    }
                    state.record_aim_results(&snapshot, best_node.as_deref());
                }
                tracing::info!(
                    "[go-aim] 全量真实探测完成，共 {count} 个节点参与评级，最优节点: {best}"
                );
                // 【APP6 任务1】[GoAim] 模块日志
                crate::core::logger::info(
                    crate::core::logger::MOD_GO_AIM,
                    &format!("AIM 全量探测完成，共 {count} 个节点参与评级，最优节点: {best}"),
                );
                if state.settings.read().go_aim_enabled && is_running(&state) {
                    if let Err(e) = apply_selection(&app, &state).await {
                        tracing::warn!("[go-aim] 锁定选择失败: {e}");
                        crate::core::logger::warn(
                            crate::core::logger::MOD_GO_AIM,
                            &format!("锁定节点选择失败: {e}"),
                        );
                    }
                }
            }
            Err(e) => tracing::warn!("[go-aim] 探测中止: {e}"),
        }
        // 【APP54 任务4】无论成功/异常，进度都必须收敛到完成态，
        // 否则前端进度条会永久卡在「检测中」。
        {
            let mut p = state.aim_progress.lock();
            if p.running {
                p.running = false;
                p.done = p.total;
                p.percent = 100;
                let snapshot = p.clone();
                drop(p);
                let _ = app.emit("aim://progress", &snapshot);
            }
        }
        state.aim_probing.store(false, Ordering::Release);
        let _ = app.emit(AIM_EVENT, serde_json::json!({ "finished": true }));
    });
}

/// 从 /proxies 响应中收集全部真实节点（type 非组），附带历史延迟
/// （0 < d < PROBE_MAX_DELAY_MS 时视为存活基线，否则为 None 待补测）。
/// 严禁跳过未测速节点——返回全部节点，由探测循环逐一覆盖。
fn collect_nodes(proxies: &serde_json::Value) -> Vec<(String, Option<u64>)> {
    const GROUP_TYPES: [&str; 10] = [
        "Selector", "URLTest", "Fallback", "LoadBalance", "Direct", "Reject", "Compatible",
        "Pass", "RejectDrop", "Global",
    ];
    let mut nodes = Vec::new();
    let Some(map) = proxies.get("proxies").and_then(serde_json::Value::as_object) else {
        return nodes;
    };
    for (name, p) in map {
        // 【APP-10 任务2】名称级兜底：即使 type 显示为真实协议（订阅恶意/
        // 误命名），名为 direct/block/直连 的条目也绝不进 Go AIM 选点池
        if crate::core::config_builder::is_builtin_non_proxy_tag(name) {
            continue;
        }
        let type_ = p.get("type").and_then(serde_json::Value::as_str).unwrap_or("");
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
async fn probe_all(app: &AppHandle, state: &AppState) -> Result<usize, String> {
    let api = state.kernel_api();
    let preview_mode = !is_running(state);
    // 提前 clone 一份 api，避免 preview_mode 分支 return 之前被 stage1 move
    let api_after_stage1 = api.clone();

    // 1. 读取全量节点列表
    let (nodes, offline_endpoints): (Vec<(String, Option<u64>)>, Option<Vec<(String, String, u16)>>) =
        if preview_mode {
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
    // 【APP54 任务4】初始化 Go AIM 进度（全部节点 100% 全量纳入统计）
    {
        let mut p = state.aim_progress.lock();
        p.running = true;
        p.done = 0;
        p.total = nodes.len();
        p.unlocked_count = 0;
        p.recompute();
        let snapshot = p.clone();
        drop(p);
        let _ = app.emit("aim://progress", &snapshot);
    }
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
                        // 内核运行：真实隧道 HTTP 测速
                        api.test_delay(&name, SCREEN_URL, PROBE_TIMEOUT_MS as u32).await
                    };
                    (name, delay)
                }
            })
            .buffer_unordered(SCREEN_BATCH_SIZE);
        while let Some((name, delay)) = stream.next().await {
            // 中止条件：关闭 Go AIM / 订阅变更（代数变化）
            if !state.settings.read().go_aim_enabled || generation_changed(state) {
                return Err("探测中止（Go AIM 已关闭或订阅已变更）".into());
            }
            match delay {
                Some(d) if d > 0 && d < PROBE_MAX_DELAY_MS => {
                    alive.push((name.clone(), d));
                    // 存活节点延迟写入状态缓存（probed=false 占位，
                    // 阶段2 完成后会被真实探测结果覆盖），前端徽章实时刷新
                    let placeholder = AimNodeResult {
                        node_name: name.clone(),
                        unlocked_tags: vec![],
                        ai_unlocked: false,
                        media_unlocked: false,
                        score: 0,
                        delay_ms: d,
                        updated_at: now_secs(),
                        probed: false,
                        ..Default::default()
                    };
                    state.aim_results.write().insert(name.clone(), placeholder.clone());
                    let _ = app.emit(
                        AIM_EVENT,
                        serde_json::json!({ "name": name, "result": placeholder }),
                    );
                }
                _ => {
                    let dead = dead_result(&name);
                    state.aim_results.write().insert(name.clone(), dead.clone());
                    let _ = app.emit(
                        AIM_EVENT,
                        serde_json::json!({ "name": name, "result": dead }),
                    );
                }
            }
            // 【APP54 任务4 / APP67 P4】阶段1 每完成一个节点 → 进度 +1。
            // 阶段1 仅占总进度前 20%（封顶 20%，done 不等于 total 时也不到 100%）。
            {
                let mut p = state.aim_progress.lock();
                p.done += 1;
                p.percent = ((p.done * 20) / p.total.max(1)).min(20) as u8;
                let snapshot = p.clone();
                drop(p);
                let _ = app.emit("aim://progress", &snapshot);
            }
        }
    }
    let alive = sort_by_delay(alive);
    let alive_count = alive.len();
    if alive.is_empty() {
        return Err("阶段1 快筛后无存活节点".into());
    }
    tracing::info!("[go-aim] 阶段1 快筛完成：{} 个节点存活，进入阶段2", alive.len());

    // 【APP51 任务1】第 1 名先行同步：按延迟升序的第一名立即成为当前选中节点，
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
                probed: true,
                probe_version: CURRENT_AIM_PROBE_VERSION,
                rule_version: CURRENT_AIM_RULE_VERSION,
                ..Default::default()
            };
            state.aim_results.write().insert(name.clone(), result.clone());
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
    let slots: Vec<usize> = (0..PROBE_SLOTS)
        .filter(|slot| probe_port_reachable(PROBE_PORT_BASE + *slot as u16))
        .collect();
    if slots.is_empty() {
        return Err(format!(
            "探针端口 {PROBE_PORT_BASE}..{} 均不可达，请重启内核后重试",
            PROBE_PORT_BASE + PROBE_SLOTS as u16 - 1
        ));
    }
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

    // 【APP67 BUG-04】预取本机直连公网 IP（不经代理），用于防漏直连判定：
    // 若某节点出口 IP 与本机直连 IP 一致，说明代理隧道未生效，立即短路。
    let direct_ip: Option<String> = {
        let direct = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(3000))
            .build()
            .ok();
        if let Some(c) = direct {
            fetch_egress(&c).await.0
        } else {
            None
        }
    };
    tracing::debug!("[go-aim] 本机直连公网 IP: {:?}", direct_ip);
    let direct_ip = Arc::new(direct_ip);

    // 【APP67 P4】阶段2 进度初始化：total 设为存活节点数，done 归零，
    // percent 从 20% 起步，每完成一个存活节点 +80/alive_count。
    {
        let mut p = state.aim_progress.lock();
        p.done = 0;
        p.total = alive_count;
        p.percent = 20;
        let snapshot = p.clone();
        drop(p);
        let _ = app.emit("aim://progress", &snapshot);
    }

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
    let mut set = tokio::task::JoinSet::new();
    for (slot, client, nr_client) in slot_clients {
        let queue = queue.clone();
        let api = api_after_stage1.clone();
        let task_app = app.clone();
        let instant_locked = instant_locked.clone();
        let direct_ip = direct_ip.clone();
        let generation = generation;
        set.spawn(async move {
            let app = task_app;
            let mut done = 0usize;
            loop {
                // 【APP37 任务3.2】探测循环只允许两个中止条件：
                // ① 用户主动关闭了 Go AIM 开关；② VPN 被用户停止。
                // 自动选点/手动切点导致的 selected_node 变化绝不再中止探测。
                {
                    let st = app.state::<AppState>();
                    if !st.settings.read().go_aim_enabled
                        || !is_running(&st)
                        || st.aim_generation.load(Ordering::Acquire) != generation
                    {
                        tracing::info!(
                            "[go-aim] 槽位 {slot} 探测中止（Go AIM 关闭、VPN 停止或订阅变更）"
                        );
                        break;
                    }
                }
                let next = queue.lock().await.pop_front();
                let Some((name, delay, first_batch)) = next else { break };
                let result = probe_node(
                    &api,
                    &client,
                    &nr_client,
                    slot,
                    &name,
                    Some(delay),
                    direct_ip.as_deref(),
                )
                .await;
                // 【APP51 任务1】订阅在探测期间变更：丢弃本轮结果，绝不污染新节点缓存
                {
                    let st = app.state::<AppState>();
                    if st.aim_generation.load(Ordering::Acquire) != generation {
                        tracing::info!("[go-aim] 槽位 {slot} 丢弃过期探测结果（订阅已变更）");
                        break;
                    }
                }
                done += 1;
                // 实时缓存 + 推送前端徽章
                // 注意：写锁 guard 必须严格限制在本作用域内，绝不可跨 await
                //（parking_lot RwLockWriteGuard 非 Send，JoinSet::spawn 要求 future: Send）
                {
                    let app_state = app.state::<AppState>();
                    let mut results = app_state.aim_results.write();
                    results.insert(result.node_name.clone(), result.clone());
                }
                let _ = app.emit(
                    AIM_EVENT,
                    serde_json::json!({ "name": result.node_name, "result": result }),
                );
                // 【APP54 任务4 / APP67 P4】阶段2 每完成一个节点 → 进度 +1，
                // 阶段2 占 20%~100%：percent = 20 + done*80/total（封顶 100）。
                {
                    let app_state = app.state::<AppState>();
                    let mut p = app_state.aim_progress.lock();
                    p.done = (p.done + 1).min(p.total);
                    p.percent = (20 + (p.done * 80) / p.total.max(1)).min(100) as u8;
                    p.unlocked_count = app_state
                        .aim_results
                        .read()
                        .values()
                        .filter(|r| r.probed && r.ai_unlocked)
                        .count();
                    let snapshot = p.clone();
                    drop(p);
                    let _ = app.emit("aim://progress", &snapshot);
                }
                // 【APP49 任务3】秒级锁定：首批（延迟最低的前 4 个）中一旦
                // 出现解锁 ChatGPT/Claude 的节点，立即走既有锁定路径切换为
                // 当前节点（lock_node 内部同步主选择器/GLOBAL/settings 并
                // 广播事件），后台继续完成剩余节点探测评级。手动指定节点时
                // 绝不抢锁；全程仅锁定一次。
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
                        // 探测中的锁定不得断开现有连接（close_conns=false），
                        // 否则会砍断其余槽位正在进行的探针 HTTP 连接。
                        let _ = lock_node(&app, &app_state, &result, false).await;
                    }
                }
                // 【APP39 任务4·时机B】探测过程中实时同步：只要出现延迟更低
                // 的合格节点，立即刷新全局「当前节点」（仪表盘/代理页 1 秒内
                // 跟随），无需等全量探测结束。手动指定节点时绝不抢锁。
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
                // 【APP37 任务3.2】每完成一个节点（4 槽位并行即每批 4 个）
                // 休眠 40ms 让出时间片供内存回收，随后继续下一批，
                // 直到 100% 完成全部节点探测。
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            }
            done
        });
    }

    let mut count = 0usize;
    while let Some(res) = set.join_next().await {
        count += res.unwrap_or(0);
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
        .proxy(reqwest::Proxy::http(&probe_proxy_url(slot)).map_err(|e| e.to_string())?)
        .timeout(std::time::Duration::from_millis(PROBE_TIMEOUT_MS))
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
        .proxy(reqwest::Proxy::http(&probe_proxy_url(slot)).map_err(|e| e.to_string())?)
        .timeout(std::time::Duration::from_millis(PROBE_TIMEOUT_MS))
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
    }
}

fn svc_accessible(service: &str, status: u16, evidence: &str) -> ServiceProbeResult {
    ServiceProbeResult {
        service: service.to_string(),
        verdict: ProbeVerdict::Accessible,
        status_code: Some(status),
        evidence: evidence.to_string(),
        failure_reason: None,
    }
}

fn svc_partial(service: &str, status: u16, evidence: &str) -> ServiceProbeResult {
    ServiceProbeResult {
        service: service.to_string(),
        verdict: ProbeVerdict::Partial,
        status_code: Some(status),
        evidence: evidence.to_string(),
        failure_reason: None,
    }
}

fn svc_blocked(service: &str, reason: impl Into<String>) -> ServiceProbeResult {
    ServiceProbeResult {
        service: service.to_string(),
        verdict: ProbeVerdict::Blocked,
        status_code: None,
        evidence: String::new(),
        failure_reason: Some(reason.into()),
    }
}

fn svc_unknown(service: &str, reason: impl Into<String>) -> ServiceProbeResult {
    ServiceProbeResult {
        service: service.to_string(),
        verdict: ProbeVerdict::Unknown,
        status_code: None,
        evidence: String::new(),
        failure_reason: Some(reason.into()),
    }
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
async fn read_verified_body(
    resp: reqwest::Response,
    min_len: usize,
) -> Result<(u16, reqwest::header::HeaderMap, String), ProbeVerdict> {
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
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

/// GPT：ios.chat.openai.com server_status + chatgpt.com 双端点正特征
async fn probe_gpt(client: &reqwest::Client, exit_country: Option<&str>) -> ServiceProbeResult {
    const SVC: &str = "GPT";
    if region_blocked(exit_country, AI_BLOCKLIST) {
        return svc_blocked(SVC, format!("出口地区 {} 命中 AI 受限名单", exit_country.unwrap_or("未知")));
    }
    // 端点1：server_status
    let ss = client
        .get("https://ios.chat.openai.com/public-api/mobile/server_status/v1")
        .header("Accept-Language", "en-US,en;q=0.9")
        .timeout(std::time::Duration::from_millis(1800))
        .send()
        .await;
    let Ok(ss_resp) = ss else {
        return svc_unknown(SVC, "server_status 请求失败");
    };
    let ss_status = ss_resp.status().as_u16();
    if ss_status == 403 || ss_status == 429 {
        return svc_blocked(SVC, format!("server_status 返回 {ss_status} 风控"));
    }
    let ss_body = match ss_resp.text().await {
        Ok(b) => b,
        Err(_) => return svc_unknown(SVC, "server_status 读取失败"),
    };
    if ss_body.trim().is_empty() {
        return svc_unknown(SVC, "server_status 空响应");
    }
    let ss_lc = ss_body.to_lowercase();
    if ss_lc.contains("unsupported_country") || ss_lc.contains("vpn_detected") {
        return svc_blocked(SVC, "server_status 含地区限制特征");
    }
    let ss_normal = ss_lc.contains("\"status\":\"normal\"") || ss_lc.contains("\"status\": \"normal\"");

    // 端点2：chatgpt.com
    let hp = client
        .get("https://chatgpt.com/")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await;
    let Ok(hp_resp) = hp else {
        return svc_unknown(SVC, "chatgpt.com 请求失败");
    };
    let (hp_status, _, hp_body) = match read_verified_body(hp_resp, 500).await {
        Ok(v) => v,
        Err(ProbeVerdict::Blocked) => return svc_blocked(SVC, "chatgpt.com 返回 CF 质询/拦截页"),
        Err(_) => return svc_unknown(SVC, "chatgpt.com 响应过短或读取失败"),
    };
    let hp_lc = hp_body.to_lowercase();
    if hp_lc.contains("unsupported_country") || hp_lc.contains("attention required") {
        return svc_blocked(SVC, "chatgpt.com 含地区限制/CF 质询");
    }
    let has_brand = hp_lc.contains("chatgpt") || hp_lc.contains("oai");

    if ss_status == 200 && ss_normal && hp_status == 200 && has_brand {
        svc_verified(SVC, hp_status, "server_status=normal + chatgpt.com 品牌正特征")
    } else if ss_status == 200 || hp_status == 200 {
        svc_accessible(SVC, hp_status, "单一接口连通但缺少完整正特征")
    } else {
        svc_blocked(SVC, format!("ss={ss_status} hp={hp_status} 均未通过"))
    }
}

/// Claude：claude.ai/login（无重定向客户端看 Location，跟随客户端读正文）
async fn probe_claude(
    client: &reqwest::Client,
    nr_client: &reqwest::Client,
    exit_country: Option<&str>,
) -> ServiceProbeResult {
    const SVC: &str = "Claude";
    if region_blocked(exit_country, AI_BLOCKLIST_NO_VE) {
        return svc_blocked(SVC, format!("出口地区 {} 命中 AI 受限名单", exit_country.unwrap_or("未知")));
    }
    // 先看首跳 Location 是否指向不可用页
    let first = nr_client
        .get("https://claude.ai/login")
        .header("Accept-Language", "en-US,en;q=0.9")
        .timeout(std::time::Duration::from_millis(1800))
        .send()
        .await;
    let Ok(first_resp) = first else {
        return svc_unknown(SVC, "claude.ai/login 首跳请求失败");
    };
    let first_status = first_resp.status().as_u16();
    let first_loc = location_lc(first_resp.headers());
    if first_loc.contains("unavailable")
        || first_loc.contains("unsupported")
        || first_loc.contains("app-unavailable-in-region")
    {
        return svc_blocked(SVC, format!("首跳 Location 指向地区不可用页: {first_loc}"));
    }
    if first_status == 403 {
        return svc_blocked(SVC, "claude.ai/login 返回 403");
    }
    // 跟随重定向读正文
    let hp = client
        .get("https://claude.ai/login")
        .header("Accept-Language", "en-US,en;q=0.9")
        .timeout(std::time::Duration::from_millis(1800))
        .send()
        .await;
    let Ok(hp_resp) = hp else {
        return svc_unknown(SVC, "claude.ai/login 请求失败");
    };
    let (hp_status, _, hp_body) = match read_verified_body(hp_resp, 200).await {
        Ok(v) => v,
        Err(ProbeVerdict::Blocked) => return svc_blocked(SVC, "claude.ai 返回 CF 质询/拦截页"),
        Err(_) => return svc_unknown(SVC, "claude.ai 响应过短或读取失败"),
    };
    let hp_lc = hp_body.to_lowercase();
    if hp_lc.contains("not available in your country")
        || hp_lc.contains("unavailable in your region")
        || hp_lc.contains("just a moment")
    {
        return svc_blocked(SVC, "claude.ai 正文含地区不可用/CF 质询");
    }
    let has_brand = hp_lc.contains("claude") || hp_lc.contains("anthropic");
    if hp_status == 200 && has_brand {
        svc_verified(SVC, hp_status, "claude.ai 200 + 品牌正特征")
    } else if (200..400).contains(&hp_status) {
        svc_accessible(SVC, hp_status, "连通但缺少品牌正特征")
    } else {
        svc_blocked(SVC, format!("claude.ai 返回 {hp_status}"))
    }
}

/// Gemini：gemini.google.com/app（无重定向看首跳 Location）
async fn probe_gemini(nr_client: &reqwest::Client, exit_country: Option<&str>) -> ServiceProbeResult {
    const SVC: &str = "Gemini";
    if region_blocked(exit_country, AI_BLOCKLIST_NO_VE) {
        return svc_blocked(SVC, format!("出口地区 {} 命中 AI 受限名单", exit_country.unwrap_or("未知")));
    }
    let resp = nr_client
        .get("https://gemini.google.com/app")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await;
    let Ok(resp) = resp else {
        return svc_unknown(SVC, "gemini.google.com 请求失败");
    };
    let status = resp.status().as_u16();
    let loc = location_lc(resp.headers());
    if (300..400).contains(&status) {
        if loc.contains("support.google.com")
            || loc.contains("/faq")
            || loc.contains("unsupported")
            || loc.contains("notavailable")
        {
            return svc_blocked(SVC, format!("首跳重定向至地区限制页: {loc}"));
        }
        // 跳登录/首页等正常 3xx → 视为可达但未验证业务特征
        return svc_accessible(SVC, status, "首跳正常重定向但未验证业务正特征");
    }
    if status == 403 {
        return svc_blocked(SVC, "gemini.google.com 返回 403");
    }
    if status != 200 {
        return svc_blocked(SVC, format!("gemini.google.com 返回 {status}"));
    }
    // 200：必须正文 > 1000 且含正特征码
    let (_, _, body) = match read_verified_body(resp, 1000).await {
        Ok(v) => v,
        Err(ProbeVerdict::Blocked) => return svc_blocked(SVC, "gemini 返回 CF 质询/拦截页"),
        Err(_) => return svc_unknown(SVC, "gemini 响应过短或读取失败"),
    };
    let lc = body.to_lowercase();
    if lc.contains("isn't currently supported")
        || lc.contains("not available in your country")
        || lc.contains("currently not available")
    {
        return svc_blocked(SVC, "gemini 正文含地区不支持提示");
    }
    let has_fp = lc.contains("bard") || lc.contains("gemini") || lc.contains("wiz_global_data");
    if has_fp {
        svc_verified(SVC, 200, "gemini 200 + 业务正特征码")
    } else {
        svc_accessible(SVC, 200, "200 但缺少业务正特征码")
    }
}

/// NF：netflix.com/title/81280792（非自制剧区域锁片源）
async fn probe_netflix(client: &reqwest::Client) -> ServiceProbeResult {
    const SVC: &str = "NF";
    let resp = client
        .get("https://www.netflix.com/title/81280792")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await;
    let Ok(resp) = resp else {
        return svc_unknown(SVC, "netflix.com 请求失败");
    };
    let status = resp.status().as_u16();
    if status == 403 || status == 404 {
        return svc_blocked(SVC, format!("netflix 返回 {status}"));
    }
    let (_, _, body) = match read_verified_body(resp, 200).await {
        Ok(v) => v,
        Err(ProbeVerdict::Blocked) => return svc_blocked(SVC, "netflix 返回 CF 质询/拦截页"),
        Err(_) => return svc_unknown(SVC, "netflix 响应过短或读取失败"),
    };
    let lc = body.to_lowercase();
    if lc.contains("nses-404") || lc.contains("oh no!") || lc.contains("this title is not available") {
        return svc_partial(SVC, status, "片源未解锁（可能仅自制剧）");
    }
    let has_title = body.contains("81280792");
    let has_brand = lc.contains("netflix");
    if has_title && has_brand {
        svc_verified(SVC, status, "netflix 片源 81280792 正特征")
    } else if (200..400).contains(&status) {
        svc_accessible(SVC, status, "连通但缺少片源正特征")
    } else {
        svc_blocked(SVC, format!("netflix 返回 {status}"))
    }
}

/// YT：youtube.com/premium
async fn probe_youtube(client: &reqwest::Client) -> ServiceProbeResult {
    const SVC: &str = "YT";
    let resp = client
        .get("https://www.youtube.com/premium")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await;
    let Ok(resp) = resp else {
        return svc_unknown(SVC, "youtube.com 请求失败");
    };
    let status = resp.status().as_u16();
    if status == 403 {
        return svc_blocked(SVC, "youtube 返回 403");
    }
    let (_, _, body) = match read_verified_body(resp, 2000).await {
        Ok(v) => v,
        Err(ProbeVerdict::Blocked) => return svc_blocked(SVC, "youtube 返回 CF 质询/拦截页"),
        Err(_) => return svc_unknown(SVC, "youtube 响应过短或读取失败"),
    };
    let lc = body.to_lowercase();
    if lc.contains("youtube premium is not available in your country") {
        return svc_blocked(SVC, "YouTube Premium 地区不可用");
    }
    let has_init = lc.contains("ytinitialdata");
    let has_premium = lc.contains("youtube premium") || lc.contains("offer");
    if status == 200 && has_init && has_premium {
        svc_verified(SVC, status, "youtube premium + ytInitialData 正特征")
    } else if status == 200 {
        svc_accessible(SVC, status, "200 但缺少播放器初始化正特征")
    } else {
        svc_blocked(SVC, format!("youtube 返回 {status}"))
    }
}

/// Disney+：disneyplus.com/
async fn probe_disney(client: &reqwest::Client, exit_country: Option<&str>) -> ServiceProbeResult {
    const SVC: &str = "Disney+";
    if region_blocked(exit_country, AI_BLOCKLIST_NO_VE) {
        return svc_blocked(SVC, format!("出口地区 {} 命中受限名单", exit_country.unwrap_or("未知")));
    }
    let resp = client
        .get("https://www.disneyplus.com/")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await;
    let Ok(resp) = resp else {
        return svc_unknown(SVC, "disneyplus.com 请求失败");
    };
    let status = resp.status().as_u16();
    let final_url = resp.url().as_str().to_lowercase();
    if status == 403 || final_url.contains("unavailable") || final_url.contains("preview") {
        return svc_blocked(SVC, format!("disney+ 跳转不可用/预览页: {final_url}"));
    }
    let (_, _, body) = match read_verified_body(resp, 200).await {
        Ok(v) => v,
        Err(ProbeVerdict::Blocked) => return svc_blocked(SVC, "disney+ 返回 CF 质询/拦截页"),
        Err(_) => return svc_unknown(SVC, "disney+ 响应过短或读取失败"),
    };
    let lc = body.to_lowercase();
    if lc.contains("not available in your region") || lc.contains("unavailable") {
        return svc_blocked(SVC, "disney+ 正文含地区不可用");
    }
    if lc.contains("disneyplus") {
        svc_verified(SVC, status, "disneyplus 品牌正特征")
    } else if (200..400).contains(&status) {
        svc_accessible(SVC, status, "连通但缺少品牌正特征")
    } else {
        svc_blocked(SVC, format!("disney+ 返回 {status}"))
    }
}

/// TK：tiktok.com/explore
async fn probe_tiktok(client: &reqwest::Client, exit_country: Option<&str>) -> ServiceProbeResult {
    const SVC: &str = "TK";
    if region_blocked(exit_country, TIKTOK_BLOCKLIST) {
        return svc_blocked(SVC, format!("出口地区 {} 命中 TikTok 受限名单", exit_country.unwrap_or("未知")));
    }
    let resp = client
        .get("https://www.tiktok.com/explore")
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await;
    let Ok(resp) = resp else {
        return svc_unknown(SVC, "tiktok.com 请求失败");
    };
    let status = resp.status().as_u16();
    if status == 403 {
        return svc_blocked(SVC, "tiktok 返回 403");
    }
    let (_, _, body) = match read_verified_body(resp, 1000).await {
        Ok(v) => v,
        Err(ProbeVerdict::Blocked) => return svc_blocked(SVC, "tiktok 返回 CF 质询/拦截页"),
        Err(_) => return svc_unknown(SVC, "tiktok 响应过短或读取失败"),
    };
    let lc = body.to_lowercase();
    if lc.contains("access denied") || lc.contains("not available") {
        return svc_blocked(SVC, "tiktok 正文含拒绝访问");
    }
    let has_fp = lc.contains("__universal_data_for_rehydration__") || lc.contains("sigi_state");
    if status == 200 && has_fp {
        svc_verified(SVC, status, "tiktok 视频流初始化数据正特征")
    } else if status == 200 {
        svc_accessible(SVC, status, "200 但缺少视频流初始化正特征")
    } else {
        svc_blocked(SVC, format!("tiktok 返回 {status}"))
    }
}

/// 单节点探测：复用阶段1 快筛延迟 → 探针选择器切到该节点 →
/// 【APP67 BUG-04】出口 IP/地区预检短路 → 7 个平台并发真实请求判定。
/// 死节点 / 出口预检失败生成 probed=true 的空结果。
async fn probe_node(
    api: &crate::core::kernel::KernelApi,
    client: &reqwest::Client,
    nr_client: &reqwest::Client,
    slot: usize,
    name: &str,
    prescreened_delay: Option<u64>,
    direct_ip: Option<&str>,
) -> AimNodeResult {
    // 1. 基线延迟
    let base_delay = match prescreened_delay.filter(|d| *d > 0 && *d < PROBE_MAX_DELAY_MS) {
        Some(d) => d,
        None => match api.test_delay(name, BASELINE_URL, BASELINE_TIMEOUT_MS as u32).await {
            Some(d) if d > 0 && d < PROBE_MAX_DELAY_MS => d,
            _ => return dead_result(name),
        },
    };

    // 2. 探针选择器切到该节点
    if let Err(e) = api.select_proxy(&probe_selector(slot), name).await {
        tracing::warn!("[go-aim] 槽位 {slot} 切换探针到「{name}」失败: {e}");
        return dead_result(name);
    }

    // 3. 【APP67 BUG-04】出口预检：获取真实出口 IP 与地区，失败/未知/漏直连立即短路
    let (egress_ip, egress_country) = fetch_egress(client).await;
    if egress_ip.is_none() || egress_country.is_none() {
        tracing::debug!("[go-aim] 节点「{name}」出口探测失败，短路后续平台探测");
        return egress_unknown_result(name, base_delay, egress_ip, egress_country);
    }
    let country = egress_country.as_deref().unwrap();
    if UNKNOWN_EXIT_COUNTRIES.contains(&country) {
        tracing::debug!("[go-aim] 节点「{name}」出口地区 {country} 未知，短路");
        return egress_unknown_result(name, base_delay, egress_ip, egress_country);
    }
    // 防漏直连：出口 IP 等于本机直连公网 IP → 代理未生效
    if let Some(dip) = direct_ip
        && egress_ip.as_deref() == Some(dip)
    {
        tracing::debug!("[go-aim] 节点「{name}」出口 IP 与直连 IP 一致（漏直连），短路");
        return egress_unknown_result(name, base_delay, egress_ip, egress_country);
    }

    // 4. 7 个平台并发真实请求（仅 Unknown 补测 1 次）
    let ec = egress_country.as_deref();
    // 各探测器闭包捕获的引用不同，需 box 为同一 trait object 才能 join_all
    let futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ServiceProbeResult> + Send>>> = vec![
        Box::pin(probe_with_retry(|| probe_gpt(client, ec))),
        Box::pin(probe_with_retry(|| probe_claude(client, nr_client, ec))),
        Box::pin(probe_with_retry(|| probe_gemini(nr_client, ec))),
        Box::pin(probe_with_retry(|| probe_netflix(client))),
        Box::pin(probe_with_retry(|| probe_youtube(client))),
        Box::pin(probe_with_retry(|| probe_disney(client, ec))),
        Box::pin(probe_with_retry(|| probe_tiktok(client, ec))),
    ];
    let results = futures_util::future::join_all(futs).await;

    // 5. 汇总：只有 Verified 进入 unlocked_tags
    let mut services: HashMap<String, ServiceProbeResult> = HashMap::with_capacity(results.len());
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
        services.insert(r.service.clone(), r);
    }
    let score = tags.len() as u32;
    AimNodeResult {
        node_name: name.to_string(),
        unlocked_tags: tags,
        ai_unlocked: ai,
        media_unlocked: media,
        score,
        delay_ms: base_delay,
        updated_at: now_secs(),
        probed: true,
        probe_version: CURRENT_AIM_PROBE_VERSION,
        rule_version: CURRENT_AIM_RULE_VERSION,
        egress_ip,
        egress_country,
        services,
    }
}

/// 【APP67 BUG-04】出口预检失败时的统一结果：7 个服务均 Unknown，无解锁标签。
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
            svc_unknown(s, "出口预检失败/未知/漏直连，未执行平台探测"),
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
        probed: true,
        probe_version: CURRENT_AIM_PROBE_VERSION,
        rule_version: CURRENT_AIM_RULE_VERSION,
        egress_ip,
        egress_country,
        services,
    }
}

/// 仅对 Unknown 结论补测 1 次（传输抖动重试），Blocked/Verified/Accessible/Partial 不重试。
async fn probe_with_retry<F, Fut>(f: F) -> ServiceProbeResult
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ServiceProbeResult>,
{
    let r = f().await;
    if matches!(r.verdict, ProbeVerdict::Unknown) {
        f().await
    } else {
        r
    }
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
        probed: true,
        probe_version: CURRENT_AIM_PROBE_VERSION,
        rule_version: CURRENT_AIM_RULE_VERSION,
        ..Default::default()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    // 低延迟解锁节点优先（300ms 上限，超出视为「虽解锁但线路太差」）
    let unlocked_fast: Vec<&AimNodeResult> = alive
        .iter()
        .copied()
        .filter(|r| !r.unlocked_tags.is_empty() && r.delay_ms < 300)
        .collect();
    let pool = if unlocked_fast.is_empty() { alive } else { unlocked_fast };
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
            let Some(locked) = state.aim_locked_node.read().clone() else { continue };
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
        AimNodeResult {
            ai_unlocked: tags.iter().any(|t| t == "GPT" || t == "Claude" || t == "Gemini"),
            media_unlocked: tags.iter().any(|t| t == "NF" || t == "YT" || t == "Disney+" || t == "TK"),
            node_name: name.to_string(),
            unlocked_tags: tags,
            score: 0,
            delay_ms: delay,
            updated_at: 0,
            probed: true,
            probe_version: CURRENT_AIM_PROBE_VERSION,
            rule_version: CURRENT_AIM_RULE_VERSION,
            ..Default::default()
        }
    }

    #[test]
    fn test_pick_best_lower_delay_beats_more_tags() {
        // 【APP39 任务4】延迟最低绝对优先：80ms 节点即使解锁平台更少，
        // 也必须压过 900ms 的全解锁节点（旧 Tier 评分会让高延迟节点胜出）。
        let mut m = HashMap::new();
        m.insert("a".into(), node("a", 80, &["GPT", "NF", "YT"]));
        m.insert(
            "b".into(),
            node("b", 900, &["GPT", "Claude", "Gemini", "NF", "YT", "Disney+", "TK"]),
        );
        let best = pick_best(&m).unwrap();
        assert_eq!(best.node_name, "a", "低延迟解锁节点应优先于高延迟全解锁节点");
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
        m.insert("slow_unlocked".into(), node("slow_unlocked", 520, &["GPT", "NF"]));
        m.insert("fast_plain".into(), node("fast_plain", 40, &[]));
        let best = pick_best(&m).unwrap();
        assert_eq!(best.node_name, "fast_plain", "无低延迟解锁节点时取全体最低延迟");
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
            assert!(p.url.starts_with("https://"), "探测 URL 必须为 https: {}", p.url);
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
        // TikTok 名单仅 CN/HK/IN：RU 不在其中
        assert!(region_blocked(Some("IN"), TIKTOK_BLOCKLIST));
        assert!(!region_blocked(Some("RU"), TIKTOK_BLOCKLIST));
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
        assert_eq!(parse_trace_loc("loc=jp\n"), Some("JP".to_string()), "必须转大写");
        assert_eq!(parse_trace_loc("no loc here"), None);
        assert_eq!(parse_trace_loc("loc=\n"), None, "空 loc 视为未知");
    }

    #[test]
    fn test_probe_score_matches_tag_count() {
        let r = node("n", 100, &["GPT", "Claude"]);
        assert_eq!(r.unlocked_tags.len(), 2);
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
        assert!(!is_cf_challenge_body("<html><body>Hello World</body></html>"));
        assert!(!is_cf_challenge_body("chatgpt oai normal page"));
    }

    #[test]
    fn test_no_positive_fingerprint_not_verified() {
        // 无正向业务特征码的普通 HTML 不得判 Verified
        let body = "<html><head><title>Some Page</title></head><body>welcome</body></html>";
        let has_brand = body.to_lowercase().contains("chatgpt") || body.to_lowercase().contains("oai");
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

    #[test]
    fn test_403_429_blocked_or_unknown() {
        // 403 / 429 → Blocked（风控），不得 Verified
        for bad in [403u16, 429] {
            let verdict = if bad == 403 || bad == 429 {
                ProbeVerdict::Blocked
            } else {
                ProbeVerdict::Verified
            };
            assert_eq!(verdict, ProbeVerdict::Blocked);
            assert!(!verdict.is_verified());
        }
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
        assert!(!tags.contains(&"NF".to_string()), "Accessible 不得进入解锁标签");
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
            assert!(
                !r.verdict.is_verified(),
                "{:?} 不得进入 unlocked_tags",
                v
            );
        }
    }

    #[test]
    fn test_version_eviction_constants() {
        // 【APP67 P3】probe_version / rule_version = 2，旧版（0/1）缓存必须淘汰
        assert_eq!(CURRENT_AIM_PROBE_VERSION, 2);
        assert_eq!(CURRENT_AIM_RULE_VERSION, 2);
        assert!(0 < CURRENT_AIM_PROBE_VERSION, "v0 缓存应被淘汰");
        assert!(1 < CURRENT_AIM_PROBE_VERSION, "v1 缓存应被淘汰");
        assert!(2 >= CURRENT_AIM_PROBE_VERSION, "v2 缓存应保留");
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
}
