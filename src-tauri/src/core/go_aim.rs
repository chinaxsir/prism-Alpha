//! Go AIM —— AI / 流媒体 自动探测锁定引擎（Pro 专属）
//!
//! 设计原则（与 IPA-3 方案一致）：
//! - 全量探测过程只通过内核 Clash API 的单节点延迟端点（GET /proxies/{name}/delay）
//!   进行，**绝不切换 GLOBAL/主选择器**，不污染全局当前连接；
//! - 探测 URL 采用"区域封锁二值信号"：被封锁区域的出口访问会返回 403/404（延迟测速
//!   视为失败），已解锁区域返回 200（测速成功）。由此把"出口区域黑名单校验"压缩成
//!   一次可测的 RTT；
//! - 结果实时缓存并推送前端（go-aim://updated）徽章展示；
//! - 启用后自动选择"已解锁 AI/流媒体节点池"中延迟最低者，并做故障转移监控。
//!
//! 注意：内核 1.11 的延迟端点只回传延迟数值（不回传响应体），因此 cdn-trace 的
//! loc= 区域码无法直接读取；本引擎以"HTTP 状态码二值信号"等价实现方案中的
//! 黑名单判定（封锁区域 → 探测失败）。

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

use crate::core::state::{AppState, CoreStatus};

/// 前端事件：探测结果更新（payload 为单节点结果或全量刷新标记）
pub const AIM_EVENT: &str = "go-aim://updated";

/// 探测并发上限（同时进行的 delay 测试数）
const PROBE_CONCURRENCY: usize = 12;
/// 单次探测超时（毫秒）
const PROBE_TIMEOUT_MS: u64 = 3000;
/// 基线测速超时（毫秒），用于首次拉取节点延迟
const BASELINE_TIMEOUT_MS: u64 = 2500;
/// 基线测速 URL（gstatic 204，任何出口都应 200）
const BASELINE_URL: &str = "http://www.gstatic.com/generate_204";
/// 参与探测的节点延迟上限（仅探测存活节点）
const PROBE_MAX_DELAY_MS: u64 = 2500;
/// 故障转移监控间隔（秒）
const MONITOR_INTERVAL_SECS: u64 = 20;

// ---------------------------------------------------------------- 探测矩阵

struct Probe {
    tag: &'static str,
    url: &'static str,
    media: bool,
}

/// 二值信号探测矩阵：封锁区域 → 403/404/302（测速失败），解锁区域 → 200
const PROBES: &[Probe] = &[
    // ---- AI 平台 ----
    // OpenAI 官方移动端服务状态接口：封锁区域拒绝，解锁区域 200
    Probe { tag: "GPT", url: "https://ios.chat.openai.com/public-api/mobile/server_status/v1", media: false },
    // Claude：Cloudflare 按区域拦截，封锁区域 403
    Probe { tag: "Claude", url: "https://claude.ai/cdn-cgi/trace", media: false },
    // Gemini：封锁区域 302 跳转 FAQ（非 200 → 失败），解锁区域 200
    Probe { tag: "Gemini", url: "https://gemini.google.com", media: false },
    // ---- 流媒体 ----
    // Netflix 区域锁片源：未解锁区域 404/403
    Probe { tag: "NF", url: "https://www.netflix.com/title/81280792", media: true },
    // YouTube Premium 页面
    Probe { tag: "YT", url: "https://www.youtube.com/premium", media: true },
    // Disney+：不可用区域 403
    Probe { tag: "Disney+", url: "https://www.disneyplus.com", media: true },
    // TikTok CDN trace
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
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoAimStatusDto {
    pub enabled: bool,
    pub locked_node: Option<String>,
    pub probing: bool,
    pub results: HashMap<String, AimNodeResult>,
}

// ---------------------------------------------------------------- 状态读取

/// 汇总当前 Go AIM 状态（供 IPC 返回）
pub fn status_dto(state: &AppState) -> GoAimStatusDto {
    GoAimStatusDto {
        enabled: state.settings.read().go_aim_enabled,
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
/// 若 go_aim_enabled 则自动执行锁定选择。
pub fn start_probe(app: AppHandle) {
    let state = app.state::<AppState>();
    if state.aim_probing.swap(true, Ordering::AcqRel) {
        tracing::debug!("[go-aim] 探测已在进行中，跳过重复触发");
        return;
    }
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
                tracing::info!("[go-aim] 全量探测完成，共 {count} 个节点参与评级");
                if state.settings.read().go_aim_enabled {
                    if let Err(e) = apply_selection(&app, &state).await {
                        tracing::warn!("[go-aim] 自动锁定失败: {e}");
                    }
                }
            }
            Err(e) => tracing::warn!("[go-aim] 探测中止: {e}"),
        }
        state.aim_probing.store(false, Ordering::Release);
        let _ = app.emit(AIM_EVENT, serde_json::json!({ "finished": true }));
    });
}

/// 从 /proxies 响应中收集存活节点（type 非组、历史延迟 0 < d < PROBE_MAX_DELAY_MS）
fn collect_alive(proxies: &serde_json::Value) -> Vec<(String, u64)> {
    const GROUP_TYPES: [&str; 10] = [
        "Selector", "URLTest", "Fallback", "LoadBalance", "Direct", "Reject", "Compatible",
        "Pass", "RejectDrop", "Global",
    ];
    let mut alive = Vec::new();
    let Some(map) = proxies.get("proxies").and_then(serde_json::Value::as_object) else {
        return alive;
    };
    for (name, p) in map {
        let type_ = p.get("type").and_then(serde_json::Value::as_str).unwrap_or("");
        if GROUP_TYPES.contains(&type_) {
            continue;
        }
        if let Some(hist) = p.get("history").and_then(serde_json::Value::as_array).and_then(|a| a.last()) {
            let delay = hist.get("delay").and_then(serde_json::Value::as_u64).unwrap_or(0);
            if delay > 0 && delay < PROBE_MAX_DELAY_MS {
                alive.push((name.clone(), delay));
            }
        }
    }
    alive
}

/// 全量探测：读取存活节点 → 并发二值信号探测 → 写缓存 + 推事件。
async fn probe_all(app: &AppHandle, state: &AppState) -> Result<usize, String> {
    let api = state.kernel_api();

    // 1. 读取全量节点列表并筛出存活节点
    let proxies = api.get_proxies().await.map_err(|e| format!("读取节点列表失败: {e}"))?;
    let mut alive = collect_alive(&proxies);

    // 2. 无延迟数据 → 先做一次组测速拿基线
    if alive.is_empty() {
        tracing::info!("[go-aim] 无历史延迟数据，先执行组基线测速");
        let _ = api
            .group_url_test("PROXY", Some(BASELINE_URL), Some(BASELINE_TIMEOUT_MS as u32), None)
            .await;
        let proxies = api.get_proxies().await.map_err(|e| format!("读取节点列表失败: {e}"))?;
        alive = collect_alive(&proxies);
    }
    if alive.is_empty() {
        return Err("没有存活节点可供探测".into());
    }
    alive.sort_by_key(|(_, d)| *d);
    let total = alive.len();

    // 4. 并发探测：节点级并行（限流），节点内串行 7 个探测点
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(PROBE_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();
    for (name, base_delay) in alive {
        let api = api.clone();
        let sem = semaphore.clone();
        set.spawn(async move {
            let mut tags: Vec<String> = Vec::new();
            let mut ai = false;
            let mut media = false;
            for probe in PROBES {
                let permit = sem.clone().acquire_owned().await;
                if permit.is_err() {
                    continue;
                }
                let ok = {
                    let _permit = permit.unwrap();
                    api.test_delay(&name, probe.url, PROBE_TIMEOUT_MS as u32)
                        .await
                        .map(|d| d > 0)
                        .unwrap_or(false)
                };
                if ok {
                    tags.push(probe.tag.to_string());
                    if probe.media {
                        media = true;
                    } else {
                        ai = true;
                    }
                }
            }
            AimProbeOutcome {
                result: AimNodeResult {
                    node_name: name.clone(),
                    unlocked_tags: tags,
                    ai_unlocked: ai,
                    media_unlocked: media,
                    score: 0,
                    delay_ms: base_delay,
                    updated_at: now_secs(),
                },
            }
        });
    }

    let mut count = 0usize;
    while let Some(out) = set.join_next().await {
        let Ok(outcome) = out else { continue };
        let mut result = outcome.result;
        result.score = result.unlocked_tags.len() as u32;
        count += 1;
        // 实时缓存 + 推送前端徽章
        state.aim_results.write().insert(result.node_name.clone(), result.clone());
        let _ = app.emit(
            AIM_EVENT,
            serde_json::json!({ "name": result.node_name, "result": result }),
        );
    }
    Ok(count)
}

struct AimProbeOutcome {
    result: AimNodeResult,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------- 锁定选择

/// 从已解锁池中选择最佳节点并锁定。
/// 排序：AI 解锁优先 → 流媒体解锁次之 → 延迟最低 → 解锁平台数。
pub async fn apply_selection(app: &AppHandle, state: &AppState) -> Result<Option<String>, String> {
    let results = state.aim_results.read().clone();
    if results.is_empty() {
        return Ok(None);
    }
    let best = pick_best(&results);
    let Some(best) = best else {
        tracing::warn!("[go-aim] 解锁池为空，保持当前节点不变");
        return Ok(None);
    };
    if state.aim_locked_node.read().as_deref() == Some(best.node_name.as_str()) {
        return Ok(Some(best.node_name));
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
    Ok(Some(best.node_name))
}

/// 评分选优（纯函数，便于单元测试）
fn pick_best(results: &HashMap<String, AimNodeResult>) -> Option<AimNodeResult> {
    let mut pool: Vec<&AimNodeResult> = results
        .values()
        .filter(|r| r.ai_unlocked || r.media_unlocked)
        .collect();
    if pool.is_empty() {
        return None;
    }
    pool.sort_by(|a, b| {
        b.ai_unlocked
            .cmp(&a.ai_unlocked)
            .then(b.media_unlocked.cmp(&a.media_unlocked))
            .then(a.delay_ms.cmp(&b.delay_ms))
            .then(b.score.cmp(&a.score))
    });
    Some(pool[0].clone())
}

// ---------------------------------------------------------------- 故障转移监控

/// 启动故障转移监控任务（整个进程生命周期内仅一个实例）。
/// 每 MONITOR_INTERVAL_SECS 检查锁定节点存活；失联则从解锁池重选次低延迟节点。
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
            // 从缓存池剔除失联节点后重选
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

    fn node(name: &str, delay: u64, ai: bool, media: bool, tags: &[&str]) -> AimNodeResult {
        AimNodeResult {
            node_name: name.to_string(),
            unlocked_tags: tags.iter().map(|s| s.to_string()).collect(),
            ai_unlocked: ai,
            media_unlocked: media,
            score: tags.len() as u32,
            delay_ms: delay,
            updated_at: 0,
        }
    }

    #[test]
    fn test_pick_best_prefers_ai_then_delay() {
        let mut m = HashMap::new();
        m.insert("a".into(), node("a", 80, false, true, &["NF"]));
        m.insert("b".into(), node("b", 200, true, true, &["GPT", "NF"]));
        m.insert("c".into(), node("c", 50, false, false, &[]));
        let best = pick_best(&m).unwrap();
        assert_eq!(best.node_name, "b", "AI 解锁节点应优先于更低延迟的纯流媒体节点");
    }

    #[test]
    fn test_pick_best_delay_tiebreak() {
        let mut m = HashMap::new();
        m.insert("a".into(), node("a", 120, true, false, &["GPT"]));
        m.insert("b".into(), node("b", 90, true, false, &["GPT"]));
        let best = pick_best(&m).unwrap();
        assert_eq!(best.node_name, "b");
    }

    #[test]
    fn test_pick_best_empty_pool() {
        let mut m = HashMap::new();
        m.insert("c".into(), node("c", 50, false, false, &[]));
        assert!(pick_best(&m).is_none());
    }

    #[test]
    fn test_probe_matrix_binary_urls() {
        // 所有探测 URL 必须是 https 且指向二值信号端点
        for p in PROBES {
            assert!(p.url.starts_with("https://"), "探测 URL 必须为 https: {}", p.url);
            assert!(!p.tag.is_empty());
        }
        // 必须包含 AI 与流媒体两类
        assert!(PROBES.iter().any(|p| !p.media));
        assert!(PROBES.iter().any(|p| p.media));
    }
}
