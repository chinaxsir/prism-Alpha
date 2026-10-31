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

/// 前端事件：探测结果更新（payload 为单节点结果或全量刷新标记）
pub const AIM_EVENT: &str = "go-aim://updated";

/// 探测槽位数（与 config_builder 注入的探针入站/选择组数量严格一致）
pub const PROBE_SLOTS: usize = 4;
/// 探针入站端口基址（config_builder 注入 2083..=2086）
pub const PROBE_PORT_BASE: u16 = 2083;
/// 基线测速 URL（gstatic 204，任何出口都应 200）
const BASELINE_URL: &str = "https://www.gstatic.com/generate_204";
/// 基线测速超时（毫秒）
const BASELINE_TIMEOUT_MS: u64 = 2500;
/// 参与探测的节点基线延迟上限（仅探测存活节点）
const PROBE_MAX_DELAY_MS: u64 = 2500;
/// 单个平台探测请求超时（毫秒）
const PROBE_TIMEOUT_MS: u64 = 4000;
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
/// 注意：US/CA/GB/DE/FR/SG 等是 AI 平台**正常可用**的地区，绝不能列入黑名单
/// （APP-4 曾把黑名单写反，导致所有节点被判为未解锁）。
const AI_BLOCKLIST: &[&str] = &["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY"];

/// 流媒体受限地区（TikTok 等在 CN/HK/MO/RU 等地不可用）
const MEDIA_BLOCKLIST: &[&str] = &["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU"];

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

/// 经代理读取当前出口地区代码（多端点兜底）。
async fn fetch_exit_loc(client: &reqwest::Client) -> Option<String> {
    for url in TRACE_URLS {
        let Ok(resp) = client.get(*url).header("Accept-Language", "en-US,en;q=0.9").send().await
        else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        if let Ok(text) = resp.text().await
            && let Some(loc) = parse_trace_loc(&text)
        {
            return Some(loc);
        }
    }
    None
}

/// 单个平台的探测定义：目标 URL + 响应判定
struct Probe {
    tag: &'static str,
    url: &'static str,
    media: bool,
}

const PROBES: &[Probe] = &[
    Probe { tag: "GPT", url: "https://chatgpt.com/cdn-cgi/trace", media: false },
    Probe { tag: "Claude", url: "https://claude.ai/cdn-cgi/trace", media: false },
    Probe { tag: "Gemini", url: "https://gemini.google.com/app", media: false },
    Probe { tag: "NF", url: "https://www.netflix.com/title/81280792", media: true },
    Probe { tag: "YT", url: "https://www.youtube.com/premium", media: true },
    Probe { tag: "Disney+", url: "https://www.disneyplus.com", media: true },
    Probe { tag: "TK", url: "https://www.tiktok.com/cdn-cgi/trace", media: true },
];

// ---------------------------------------------------------------- 数据模型

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AimNodeResult {
    pub node_name: String,
    /// 解锁标签（GPT/Claude/Gemini/NF/YT/Disney+/TK）
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
    if state.aim_probing.swap(true, Ordering::AcqRel) {
        tracing::debug!("[go-aim] 探测已在进行中，跳过重复触发");
        return;
    }
    // 【APP11 任务4.3】新的一轮探测开始，清除中止信号
    state.aim_abort.store(false, Ordering::Release);
    if !is_running(&state) {
        state.aim_probing.store(false, Ordering::Release);
        tracing::debug!("[go-aim] 内核未运行，跳过探测");
        return;
    }
    drop(state);

    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        match probe_all(&app, &state).await {
            Ok(count) => {
                if state.aim_abort.load(Ordering::Acquire) {
                    // 【APP11 任务4.3】用户中途切换节点 → 跳过锁定，尊重用户选择
                    tracing::info!("[go-aim] 探测被用户切换节点中止，跳过分组锁定");
                    crate::core::logger::info(
                        crate::core::logger::MOD_GO_AIM,
                        "AIM 探测被用户手动切换节点中止，跳过分组锁定以尊重用户选择",
                    );
                } else {
                    tracing::info!("[go-aim] 全量真实探测完成，共 {count} 个节点参与评级");
                    // 【APP6 任务1】[GoAim] 模块日志
                    crate::core::logger::info(
                        crate::core::logger::MOD_GO_AIM,
                        &format!("AIM 全量探测完成，共 {count} 个节点参与评级"),
                    );
                    if state.settings.read().go_aim_enabled {
                        if let Err(e) = apply_selection(&app, &state).await {
                            tracing::warn!("[go-aim] 锁定选择失败: {e}");
                            crate::core::logger::warn(
                                crate::core::logger::MOD_GO_AIM,
                                &format!("锁定节点选择失败: {e}"),
                            );
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("[go-aim] 探测中止: {e}"),
        }
        state.aim_probing.store(false, Ordering::Release);
        state.aim_abort.store(false, Ordering::Release);
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

/// 全量探测：读取全部节点 → 4 个槽位并行消费共享队列 → 逐节点真实
/// HTTP 探测 → 写缓存 + 推事件。每个节点都必须生成 AimNodeResult
/// （死节点 unlocked_tags=[] 且 probed=true），绝不遗漏"未检测"状态。
async fn probe_all(app: &AppHandle, state: &AppState) -> Result<usize, String> {
    let api = state.kernel_api();
    // APP34：移动端扩展进程受 Jetsam 50MB 硬限制，探测规模必须收敛。
    let mobile = cfg!(any(target_os = "ios", target_os = "android"));

    // 1. 读取全量节点列表
    let proxies = api
        .get_proxies()
        .await
        .map_err(|e| format!("读取节点列表失败: {e}"))?;
    let mut nodes = collect_nodes(&proxies);

    // 2. 全部节点都没有延迟数据 → 先做一次组测速拿基线。
    // 移动端严禁全量组测速（同样会一次性打满 148 个节点），直接跳过：
    // 无历史延迟的节点由 probe_node 内的单节点基线补测覆盖。
    if !mobile && !nodes.is_empty() && nodes.iter().all(|(_, d)| d.is_none()) {
        tracing::info!("[go-aim] 无历史延迟数据，先执行组基线测速");
        let _ = api
            .group_url_test(
                "PROXY",
                Some(BASELINE_URL),
                Some(BASELINE_TIMEOUT_MS as u32),
                None,
            )
            .await;
        let proxies = api
            .get_proxies()
            .await
            .map_err(|e| format!("读取节点列表失败: {e}"))?;
        nodes = collect_nodes(&proxies);
    }
    if nodes.is_empty() {
        return Err("节点列表为空，无可探测节点".into());
    }
    // 有基线延迟的优先探测（延迟从低到高），无延迟的排后（探测循环内逐个补测）
    nodes.sort_by_key(|(_, d)| d.unwrap_or(u64::MAX));
    // APP34：移动端只探测延迟最优的前 15 个节点，其余留待后续轮次，
    // 绝不让 148 个节点同时进入内存与并发池。
    if mobile {
        nodes.truncate(15);
    }

    // 3. 探针槽位可用性检测（智能回退）：只使用本机实际可连通的探针入站。
    // 若扩展配置裁剪掉了探针入站，宁可明确失败也绝不用主混合端口兜底——
    // 经主选择器探测会污染用户当前节点，并产出错误的解锁徽章。
    let slots: Vec<usize> = (0..PROBE_SLOTS)
        .filter(|slot| probe_port_reachable(PROBE_PORT_BASE + *slot as u16))
        .take(if mobile { 2 } else { PROBE_SLOTS })
        .collect();
    if slots.is_empty() {
        return Err(format!(
            "探针端口 {PROBE_PORT_BASE}..{} 均不可达，请重启内核后重试",
            PROBE_PORT_BASE + PROBE_SLOTS as u16 - 1
        ));
    }
    tracing::info!("[go-aim] 可用探针槽位: {slots:?}");

    // 4. 共享任务队列：可用槽位并行消费，任一槽位空闲即取下一个节点
    let queue = Arc::new(tokio::sync::Mutex::new(
        nodes.into_iter().collect::<VecDeque<_>>(),
    ));
    let mut set = tokio::task::JoinSet::new();
    for slot in slots {
        let queue = queue.clone();
        let api = api.clone();
        let task_app = app.clone();
        set.spawn(async move {
            let app = task_app;
            let client = match build_probe_client(slot) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("[go-aim] 槽位 {slot} 探测客户端构建失败: {e}");
                    return 0usize;
                }
            };
            // Gemini 判定只看首跳 Location，必须独立的无重定向客户端
            let nr_client = match build_probe_client_no_redirect(slot) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("[go-aim] 槽位 {slot} 无重定向客户端构建失败: {e}");
                    return 0usize;
                }
            };
            let mut done = 0usize;
            loop {
                // 【APP11 任务4.3】用户中途切换节点 → 立即停止本轮探测
                if app.state::<AppState>().aim_abort.load(Ordering::Acquire) {
                    tracing::info!("[go-aim] 槽位 {slot} 探测被中止信号停止");
                    break;
                }
                let next = queue.lock().await.pop_front();
                let Some((name, history_delay)) = next else { break };
                let result =
                    probe_node(&api, &client, &nr_client, slot, &name, history_delay).await;
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
                // APP34：移动端每完成一个节点休眠 200ms，把并发探针压成
                // 「每批一个」的节奏，避免多槽位同时并发真实 HTTP 请求。
                if mobile {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
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
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(&probe_proxy_url(slot)).map_err(|e| e.to_string())?)
        .timeout(std::time::Duration::from_millis(PROBE_TIMEOUT_MS))
        .redirect(reqwest::redirect::Policy::limited(5))
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
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(&probe_proxy_url(slot)).map_err(|e| e.to_string())?)
        .timeout(std::time::Duration::from_millis(PROBE_TIMEOUT_MS))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        )
        .build()
        .map_err(|e| e.to_string())
}

/// 单节点探测：基线测速确认存活 → 探针选择器切到该节点 → 7 个平台
/// 并发真实请求判定。死节点生成 probed=true 的空结果。
async fn probe_node(
    api: &crate::core::kernel::KernelApi,
    client: &reqwest::Client,
    nr_client: &reqwest::Client,
    slot: usize,
    name: &str,
    history_delay: Option<u64>,
) -> AimNodeResult {
    // 1. 基线测速：无历史数据的节点先补测（严禁直接跳过）
    let base_delay = match history_delay {
        Some(d) => d,
        None => match api.test_delay(name, BASELINE_URL, BASELINE_TIMEOUT_MS as u32).await {
            Some(d) if d > 0 && d < PROBE_MAX_DELAY_MS => d,
            _ => {
                return dead_result(name);
            }
        },
    };

    // 2. 探针选择器切到该节点（独立组，绝不影响主选择器/GLOBAL）
    if let Err(e) = api.select_proxy(&probe_selector(slot), name).await {
        tracing::warn!("[go-aim] 槽位 {slot} 切换探针到「{name}」失败: {e}");
        return dead_result(name);
    }

    // 3. 出口地区码只读取一次（7 个平台共用，避免每平台各打一次 cdn-trace）
    let exit_loc = fetch_exit_loc(client).await;

    // 4. 7 个平台并发真实请求（每个探测点超时/传输失败自动补测 1 次）
    let mut checks = Vec::with_capacity(PROBES.len());
    for probe in PROBES {
        let loc = exit_loc.clone();
        checks.push(check_platform(client, nr_client, probe, loc));
    }
    let outcomes = futures_util::future::join_all(checks).await;

    let mut tags: Vec<String> = Vec::new();
    let mut ai = false;
    let mut media = false;
    for (probe, ok) in PROBES.iter().zip(outcomes) {
        if ok {
            tags.push(probe.tag.to_string());
            if probe.media {
                media = true;
            } else {
                ai = true;
            }
        }
    }
    // 【APP-13 任务2】Gemini 兜底放行：gemini.google.com 握手偶发超时（
    // Google 前端首包 RTT 高），单次失败不应把整批节点的 Gemini 标识清空。
    // 若出口地区已确认不在 AI 受限名单，且该节点已实测解锁 GPT 或 YT
    // （同属 Google/OpenAI 体系，链路质量充分），则补回 Gemini 标识。
    if !tags.iter().any(|t| t == "Gemini")
        && exit_loc
            .as_deref()
            .is_some_and(|l| !AI_BLOCKLIST.contains(&l))
        && tags.iter().any(|t| t == "GPT" || t == "YT")
    {
        tags.push("Gemini".to_string());
        ai = true;
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
    }
}

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
    }
}

/// 单平台探测：请求 + 按平台规则判定（超时/传输错误自动补测 1 次）
async fn check_platform(
    client: &reqwest::Client,
    nr_client: &reqwest::Client,
    probe: &Probe,
    exit_loc: Option<String>,
) -> bool {
    let loc = exit_loc.as_deref();
    match check_once(client, nr_client, probe, loc).await {
        Some(ok) => ok,
        None => match check_once(client, nr_client, probe, loc).await {
            Some(ok) => ok,
            None => false,
        },
    }
}

/// 发起单次请求并按平台规则判定；None = 传输失败/超时（区别于「封锁」）
async fn check_once(
    client: &reqwest::Client,
    nr_client: &reqwest::Client,
    probe: &Probe,
    exit_loc: Option<&str>,
) -> Option<bool> {
    // 【APP-10 任务3】Gemini 提前分支：只看首跳 Location 是否含 /faq，
    // 绝不跟随重定向读正文（Google JS 多语言包内嵌错误文案会误伤）。
    if probe.tag == "Gemini" {
        return check_gemini_first_hop(nr_client, probe.url, exit_loc).await;
    }
    let resp = match client
        .get(probe.url)
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return None, // 传输失败 → 由 check_platform 补测
    };
    let status = resp.status().as_u16();
    // 跟随重定向后的最终 URL（Gemini 跳 FAQ / Disney+ 跳不可用页的判定依据）
    let final_url = resp.url().as_str().to_lowercase();
    // 读正文（响应体一般 < 8KB，截断防止异常大响应拖慢探测；
    // 按字符边界截断，避免多字节 UTF-8 被切断 panic）
    let body = resp
        .text()
        .await
        .map(|b| {
            const LIMIT: usize = 64 * 1024;
            if b.len() > LIMIT {
                let mut end = LIMIT;
                while end > 0 && !b.is_char_boundary(end) {
                    end -= 1;
                }
                b[..end].to_string()
            } else {
                b
            }
        })
        .unwrap_or_default();
    let body_lc = body.to_lowercase();
    // 出口地区：优先使用 probe_node 预取的共享值，其次解析本次响应体
    // （GPT/Claude/TK 的探测 URL 本身就是 cdn-trace 端点）
    let loc = exit_loc.map(str::to_string).or_else(|| parse_trace_loc(&body));
    // 地区未知（cdn-trace 不可达）时不因未知而判死，交由状态码/正文判定
    let region_allowed = |list: &[&str]| match loc.as_deref() {
        Some(l) => !list.contains(&l),
        None => true,
    };

    let verdict = match probe.tag {
        // GPT：出口地区非受限 + OpenAI 边缘节点放行（200/401 为标准放行）。
        // 旧接口 ios.chat.openai.com/.../server_status 已下线（404），必须废弃
        "GPT" => {
            if !region_allowed(AI_BLOCKLIST) {
                return Some(false);
            }
            Some(match client.get("https://api.openai.com/v1/models").send().await {
                Ok(r) => {
                    let s = r.status().as_u16();
                    let b = r.text().await.unwrap_or_default().to_lowercase();
                    if b.contains("unsupported_country")
                        || b.contains("not supported in your country")
                    {
                        false
                    } else {
                        match s {
                            // 合法地区：200 正常 / 401 未带 Key 的标准响应
                            200 | 401 => true,
                            // 地区封锁
                            403 => false,
                            // 429 等限流：以出口地区为准
                            _ => loc.is_some(),
                        }
                    }
                }
                // 二次请求失败：以主端点可达 + 出口地区判定为准
                Err(_) => status == 200 && loc.is_some(),
            })
        }
        // Claude：出口地区非受限，且未被 Cloudflare 403 拦截
        "Claude" => {
            if !region_allowed(AI_BLOCKLIST) {
                return Some(false);
            }
            Some(if status == 403 { loc.is_some() } else { status < 500 })
        }
        // Gemini：已在 check_once 入口提前分支（首跳 Location 判定），此处不可达
        "Gemini" => Some(false),
        // NF：区域锁片源 81280792——跟随重定向后 200 即解锁，404 判封锁
        "NF" => Some(status == 200),
        // Disney+：200 且未跳到不可用提示页
        "Disney+" => Some(status == 200 && !final_url.contains("unavailable")),
        // YT：Premium 页 200 且正文不含「国家不可用」
        "YT" => Some(status == 200 && !body_lc.contains("youtube premium is not available")),
        // TikTok：出口地区不在流媒体受限名单
        "TK" => Some(status == 200 && region_allowed(MEDIA_BLOCKLIST)),
        _ => Some(false),
    };
    verdict
}

/// 【APP-10 任务3】Gemini 首跳判定（无重定向客户端）：
/// - 出口地区命中 AI 受限名单 → 封锁；
/// - 首跳 3xx 且 Location 含 `/faq` → 地区封锁页，判封锁；
/// - 首跳 200（已进 App）或其他 3xx（跳登录/首页）→ 放行；
/// - 传输失败/超时 → None，交由上层补测一次。
async fn check_gemini_first_hop(
    nr_client: &reqwest::Client,
    url: &str,
    exit_loc: Option<&str>,
) -> Option<bool> {
    if let Some(l) = exit_loc
        && AI_BLOCKLIST.contains(&l)
    {
        return Some(false);
    }
    let resp = match nr_client
        .get(url)
        .header("Accept-Language", "en-US,en;q=0.9")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return None,
    };
    let status = resp.status().as_u16();
    if status == 200 {
        return Some(true);
    }
    if (300..400).contains(&status) {
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        return Some(!location.contains("/faq"));
    }
    Some(false)
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
    if let Some(pinned) = pinned
        && let Some(res) = results.get(&pinned)
        && res.probed
        && res.delay_ms > 0
    {
        return lock_node(app, state, res).await.map(Some);
    }

    let Some(best) = pick_best(&results) else {
        tracing::warn!("[go-aim] 解锁池为空，保持当前节点不变");
        return Ok(None);
    };
    lock_node(app, state, &best).await.map(Some)
}

/// 执行锁定：若与当前锁定一致则跳过；否则切主组 + GLOBAL 并广播
async fn lock_node(
    app: &AppHandle,
    state: &AppState,
    best: &AimNodeResult,
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
    let _ = api.close_all_connections().await;

    *state.aim_locked_node.write() = Some(best.node_name.clone());
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

/// 评级选优（纯函数，便于单元测试）。
/// 分层规则（APP-4 任务3.3）：
/// - Tier3：7 平台全解锁（unlocked_tags.len() == 7）优先级最高；
/// - Tier2：AI 与流媒体同时解锁，按解锁平台数降序；
/// - Tier1：AI 或流媒体任一解锁，按解锁平台数降序；
/// - Tier0：仅存活（无任何解锁）。
/// 同层内基线延迟最低者优先。
fn pick_best(results: &HashMap<String, AimNodeResult>) -> Option<AimNodeResult> {
    let tier = |r: &AimNodeResult| -> u8 {
        if r.unlocked_tags.len() == PROBES.len() {
            3
        } else if r.ai_unlocked && r.media_unlocked {
            2
        } else if r.ai_unlocked || r.media_unlocked {
            1
        } else if r.probed && r.delay_ms > 0 {
            0
        } else {
            return 255; // 死节点不参与
        }
    };
    let mut pool: Vec<&AimNodeResult> =
        results.values().filter(|r| tier(r) != 255).collect();
    if pool.is_empty() {
        return None;
    }
    pool.sort_by(|a, b| {
        // tier 越大越优（Tier3 全解锁 > Tier2 > Tier1 > Tier0），
        // 同层解锁平台数多者优先，再按基线延迟升序
        tier(b)
            .cmp(&tier(a))
            .then(b.unlocked_tags.len().cmp(&a.unlocked_tags.len()))
            .then(a.delay_ms.cmp(&b.delay_ms))
    });
    Some(pool[0].clone())
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
        }
    }

    #[test]
    fn test_pick_best_full_unlock_first() {
        let mut m = HashMap::new();
        // 低延迟但只解锁 3 个平台
        m.insert("a".into(), node("a", 80, &["GPT", "NF", "YT"]));
        // 高延迟但 7 平台全解锁（Tier3）
        m.insert(
            "b".into(),
            node("b", 900, &["GPT", "Claude", "Gemini", "NF", "YT", "Disney+", "TK"]),
        );
        let best = pick_best(&m).unwrap();
        assert_eq!(best.node_name, "b", "全解锁节点（Tier3）应优先于更低延迟的部分解锁节点");
    }

    #[test]
    fn test_pick_best_tier2_by_tag_count_then_delay() {
        let mut m = HashMap::new();
        // Tier2（AI+流媒体），解锁 2 个
        m.insert("a".into(), node("a", 120, &["GPT", "NF"]));
        // Tier2，解锁 3 个
        m.insert("b".into(), node("b", 300, &["GPT", "NF", "YT"]));
        // Tier1（仅 AI），延迟最低
        m.insert("c".into(), node("c", 90, &["GPT"]));
        let best = pick_best(&m).unwrap();
        assert_eq!(best.node_name, "b", "Tier2 内解锁平台数多者优先于 Tier1");
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
        // 真实受限地区必须在名单中
        for bad in ["CN", "HK", "MO", "RU", "KP", "IR"] {
            assert!(AI_BLOCKLIST.contains(&bad), "{bad} 应在 AI 受限名单中");
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
}
