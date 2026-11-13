//! 订阅链接云端同步（Pro / 买断会员专属，https://prism.sarl/api）
//!
//! - 对账（reconcile）：激活成功与 App 启动（每小时循环首轮）触发一次，
//!   本地与云端双向静默合并——云端新增拉取到本地、云端已删除的同步删除本地、
//!   本地独有的（首次对账）上传到云端
//! - 单条上报：本地添加订阅 → PUT；本地删除订阅 → DELETE（静默，失败仅记日志）
//! - 对账基线：sync_links.json 记录最近一次已知的云端列表，用于区分
//!   「云端已删除」与「本地新增未上报」，避免误删本地独有订阅
//! - 管控处理：403 sync_paused / sync_disabled → 本次会话不再尝试（云端数据保留与否由服务端决定）
//! - 频控：凭据错误与激活共享失败节流，因此只在对账入口调用且不无限重试；
//!   瞬态失败静默跳过，等下次触发点

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Manager};

use super::license;
use super::state::AppState;

/// 服务端约束：每用户云端订阅链接上限
const LINK_LIMIT: usize = 5;

/// 管控（sync_paused/sync_disabled）后本次会话内不再请求
static SYNC_SESSION_DISABLED: AtomicBool = AtomicBool::new(false);

/// 对账互斥：避免激活触发与启动循环并发对账
static RECONCILE_RUNNING: AtomicBool = AtomicBool::new(false);

/// 云端一条订阅链接
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloudLink {
    url: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}

/// 对账基线（本地落盘的「最近一次已知云端列表」）
#[derive(Debug, Default, Serialize, Deserialize)]
struct SyncMirror {
    links: Vec<CloudLink>,
}

fn mirror_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("sync_links.json")
}

fn load_mirror(data_dir: &std::path::Path) -> SyncMirror {
    std::fs::read(mirror_path(data_dir))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_mirror(data_dir: &std::path::Path, links: &[CloudLink]) {
    if let Ok(bytes) = serde_json::to_vec_pretty(&SyncMirror {
        links: links.to_vec(),
    }) {
        let _ = super::store::atomic_write(&mirror_path(data_dir), &bytes);
    }
}

/// 同步是否可用：授权 active + 服务端允许 + 本地有完整凭据对
fn sync_eligible(state: &AppState) -> Option<(String, String)> {
    if !state.is_pro_active() || !state.entitlement.read().sync_available {
        return None;
    }
    license::cached_credentials(&state.data_dir)
}

/// 同步 API 错误分类
enum SyncError {
    /// 管理员管控：本次会话禁用
    AdminDisabled(String),
    /// 凭据问题（activation_failed / subscription_required）：静默跳过
    Rejected(String),
    /// 瞬态（网络/5xx/429/解析失败）：静默跳过
    Transient(String),
}

/// 统一响应检查：非 2xx 按错误码分类；2xx 返回 JSON 体
async fn check_response(resp: reqwest::Response) -> Result<Value, SyncError> {
    let code = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let body: Value = serde_json::from_str(&text)
        .unwrap_or_else(|_| serde_json::json!({ "error": "invalid_response", "message": text }));
    if (200..300).contains(&code) {
        return Ok(body);
    }
    let err_code = body
        .get("error")
        .and_then(|e| e.as_str())
        .unwrap_or_default()
        .to_string();
    let msg = body
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_string();
    let detail = format!("HTTP {code} {err_code} {msg}");
    match err_code.as_str() {
        "sync_paused" | "sync_disabled" => Err(SyncError::AdminDisabled(detail)),
        "activation_failed" | "subscription_required" => Err(SyncError::Rejected(detail)),
        _ => Err(SyncError::Transient(detail)),
    }
}

/// GET /sync/links：拉取云端订阅链接列表
async fn api_get_links(base: &str, key: &str, email: &str) -> Result<Vec<CloudLink>, SyncError> {
    let resp = license::send_with_v4_fallback(|c| {
        c.get(&format!("{base}/api/sync/links"))
            .query(&[("license_key", key), ("email", email)])
            .header("X-Request-Source", "prism-app")
    })
    .await
    .map_err(|e| SyncError::Transient(license::sanitize_license_error(&e.to_string())))?;
    let body = check_response(resp).await?;
    Ok(body
        .get("links")
        .and_then(|l| l.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default())
}

/// PUT /sync/links：上传/更新一条订阅链接（同 url 幂等）
async fn api_put_link(
    base: &str,
    key: &str,
    email: &str,
    url: &str,
    name: Option<&str>,
) -> Result<CloudLink, SyncError> {
    let mut body = serde_json::json!({ "license_key": key, "email": email, "url": url });
    if let Some(n) = name
        && !n.is_empty()
    {
        body["name"] = Value::String(n.chars().take(100).collect());
    }
    let resp = license::send_with_v4_fallback(|c| {
        c.put(&format!("{base}/api/sync/links"))
            .header("X-Request-Source", "prism-app")
            .json(&body)
    })
    .await
    .map_err(|e| SyncError::Transient(license::sanitize_license_error(&e.to_string())))?;
    let body = check_response(resp).await?;
    Ok(body
        .get("link")
        .cloned()
        .and_then(|l| serde_json::from_value(l).ok())
        .unwrap_or(CloudLink {
            url: url.to_string(),
            name: name.map(String::from),
            updated_at: None,
        }))
}

/// DELETE /sync/links：删除一条云端订阅链接（幂等）
async fn api_delete_link(base: &str, key: &str, email: &str, url: &str) -> Result<(), SyncError> {
    let resp = license::send_with_v4_fallback(|c| {
        c.delete(&format!("{base}/api/sync/links"))
            .header("X-Request-Source", "prism-app")
            .json(&serde_json::json!({
                "license_key": key,
                "email": email,
                "url": url,
            }))
    })
    .await
    .map_err(|e| SyncError::Transient(license::sanitize_license_error(&e.to_string())))?;
    check_response(resp).await?;
    Ok(())
}

/// 把 SyncError 转为日志（全部静默，不打扰用户）
fn log_sync_err(context: &str, e: SyncError) {
    match e {
        SyncError::AdminDisabled(d) => {
            SYNC_SESSION_DISABLED.store(true, Ordering::Relaxed);
            tracing::warn!("订阅同步被管控，本次会话停用：{d}");
        }
        SyncError::Rejected(d) => tracing::warn!("订阅同步凭据被拒（不重试）：{d}"),
        SyncError::Transient(d) => tracing::warn!("订阅同步瞬态失败（{context}）：{d}"),
    }
}

/// 本地添加订阅后上报云端（静默；成功后把镜像更新为服务端返回的 link）
pub async fn push_link(app: &AppHandle, url: &str, name: Option<String>) {
    let state = app.state::<AppState>();
    let Some((key, email)) = sync_eligible(&state) else {
        return;
    };
    if SYNC_SESSION_DISABLED.load(Ordering::Relaxed) {
        return;
    }
    let base = license::api_base(&state.settings.read().clone());
    let data_dir = state.data_dir.clone();
    let url = url.to_string();
    tauri::async_runtime::spawn(async move {
        match api_put_link(&base, &key, &email, &url, name.as_deref()).await {
            Ok(link) => {
                let mut mirror = load_mirror(&data_dir);
                mirror.links.retain(|l| l.url != url);
                mirror.links.push(link);
                save_mirror(&data_dir, &mirror.links);
                tracing::info!("订阅已同步到云端：{url}");
            }
            Err(e) => log_sync_err("push_link", e),
        }
    });
}

/// 本地删除订阅后上报云端（静默；成功后从镜像移除）
pub async fn push_delete(app: &AppHandle, url: &str) {
    let state = app.state::<AppState>();
    let Some((key, email)) = sync_eligible(&state) else {
        return;
    };
    if SYNC_SESSION_DISABLED.load(Ordering::Relaxed) {
        return;
    }
    let base = license::api_base(&state.settings.read().clone());
    let data_dir = state.data_dir.clone();
    let url = url.to_string();
    tauri::async_runtime::spawn(async move {
        match api_delete_link(&base, &key, &email, &url).await {
            Ok(()) => {
                let mut mirror = load_mirror(&data_dir);
                mirror.links.retain(|l| l.url != url);
                save_mirror(&data_dir, &mirror.links);
                tracing::info!("云端订阅已删除：{url}");
            }
            Err(e) => log_sync_err("push_delete", e),
        }
    });
}

/// 全量对账：本地 ↔ 云端 双向静默合并
///
/// - 云端有、本地无 → 拉取到本地（下载订阅内容；失败则先建记录供手动更新）
/// - 云端无、本地有、且在基线中 → 其他设备已删除 → 同步删除本地
/// - 云端无、本地有、不在基线中 → 本地新增未上报 → 上传（受 5 条上限约束）
/// - 结束后基线 = 云端最新列表；本地有增删且内核运行中 → 重启生效
pub async fn reconcile(app: &AppHandle) {
    if RECONCILE_RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    let result = reconcile_inner(app).await;
    RECONCILE_RUNNING.store(false, Ordering::SeqCst);
    if let Err(e) = result {
        log_sync_err("reconcile", e);
    }
}

async fn reconcile_inner(app: &AppHandle) -> Result<(), SyncError> {
    let state = app.state::<AppState>();
    let Some((key, email)) = sync_eligible(&state) else {
        return Ok(());
    };
    if SYNC_SESSION_DISABLED.load(Ordering::Relaxed) {
        return Ok(());
    }
    let base = license::api_base(&state.settings.read().clone());
    let data_dir = state.data_dir.clone();

    // 1. 拉取云端列表
    let cloud = api_get_links(&base, &key, &email).await?;
    let mut cloud = {
        // url 去重（理论上一致性存储不会重复，防御性处理）
        let mut seen = std::collections::HashSet::new();
        cloud
            .into_iter()
            .filter(|l| !l.url.is_empty() && seen.insert(l.url.clone()))
            .take(LINK_LIMIT)
            .collect::<Vec<_>>()
    };

    let local = super::store::load_subscriptions(&data_dir);
    let mirror = load_mirror(&data_dir);
    let cloud_urls: std::collections::HashSet<String> =
        cloud.iter().map(|l| l.url.clone()).collect();
    let mirror_urls: std::collections::HashSet<&str> =
        mirror.links.iter().map(|l| l.url.as_str()).collect();

    let mut changed = false; // 本地是否发生增删（决定是否重启内核）

    // 2. 云端有、本地无（或本地为空壳）→ 拉取到本地。
    // 空壳判定：缓存文件缺失，或内容解析不出可用节点——这正是
    // 「订阅同步了却没有节点」的场景：上一台设备同步时只建了记录
    // （下载失败保底），本台设备对账必须重新拉取内容
    for link in &cloud {
        let has_record = local.iter().any(|r| r.url == link.url);
        if has_record && !profile_is_empty_shell(&data_dir, &link.url) {
            continue;
        }
        if has_record {
            tracing::info!(
                "订阅同步：本地为空壳（缓存缺失或 0 节点），重新拉取 {}",
                link.url
            );
        } else {
            tracing::info!("订阅同步：从云端拉取 {}", link.url);
        }
        match crate::ipc::commands::refresh_subscription(app, &state, &link.url).await {
            Ok(()) => {}
            Err(e) => {
                // 下载失败（临时网络/机场不可达）：先建记录保底，
                // updated_at 置 0（前端显示「从未更新」标识内容待补）
                tracing::warn!("订阅同步：拉取内容失败（先建空壳记录）：{e}");
                if super::store::upsert_subscription_pending(&data_dir, &link.url).is_ok() {
                    set_local_name(&data_dir, &link.url, link.name.clone());
                }
            }
        }
        // refresh_subscription 内部 upsert 会覆盖 enabled=true，此处对齐备注名
        set_local_name(&data_dir, &link.url, link.name.clone());
        changed = true;
    }

    // 2.5 【APP42 任务2.2】本地优先对账：内容完整的已有订阅
    // - 本地有备注名且与云端不一致 → 以本地上行为准（重命名跨设备同步）
    // - 本地无备注名而云端有 → 采纳云端名（新装设备继承备注）
    // - 超过 6 小时未更新 → 自动刷新节点（拉取列表即自动更新）
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    for idx in 0..cloud.len() {
        let link = cloud[idx].clone();
        let Some(local_rec) = super::store::load_subscriptions(&data_dir)
            .into_iter()
            .find(|r| r.url == link.url)
        else {
            continue;
        };
        let local_name = local_rec.name.clone().filter(|n| !n.is_empty());
        let cloud_name = link.name.clone().filter(|n| !n.is_empty());
        if local_name.is_none() && cloud_name.is_some() {
            set_local_name(&data_dir, &link.url, cloud_name.clone());
        } else if local_name != cloud_name {
            tracing::info!("订阅同步：本地上行重命名 {} -> {:?}", link.url, local_name);
            match api_put_link(&base, &key, &email, &link.url, local_name.as_deref()).await {
                Ok(updated) => {
                    cloud[idx] = updated;
                }
                Err(e) => log_sync_err("reconcile_rename", e),
            }
        }
        // 云端已有且本地有记录 → 超过 6 小时自动刷新一次节点数据
        if local_rec.updated_at > 0
            && local_rec.enabled
            && now.saturating_sub(local_rec.updated_at) > 6 * 3600
        {
            tracing::info!("订阅同步：内容超过 6 小时未更新，自动刷新 {}", link.url);
            match crate::ipc::commands::refresh_subscription(app, &state, &link.url).await {
                Ok(()) => {}
                Err(e) => tracing::warn!("订阅同步：自动刷新失败 {}：{e}", link.url),
            }
        }
    }

    // 3. 云端无、本地有、在基线中 → 其他设备已删除，静默删除本地
    for record in &local {
        if cloud_urls.contains(record.url.as_str()) || !mirror_urls.contains(record.url.as_str()) {
            continue;
        }
        // 内核运行中删除最后一条启用订阅会被拦截；此时跳过删除并保留本地（极端场景）
        let target_enabled = super::store::load_subscriptions(&data_dir)
            .iter()
            .any(|r| r.url == record.url && r.enabled);
        if target_enabled && running_enabled_count(&state) <= 1 {
            tracing::warn!("订阅同步：跳过删除最后一条启用订阅 {}", record.url);
            continue;
        }
        tracing::info!("订阅同步：云端已删除，移除本地 {}", record.url);
        if super::store::delete_subscription(&data_dir, &record.url).unwrap_or(false) {
            std::fs::remove_file(super::store::profile_path(&data_dir, &record.url)).ok();
            changed = true;
        }
    }

    // 4. 云端无、本地有、不在基线中 → 本地新增未上报，逐条上传
    for record in &local {
        if cloud_urls.contains(record.url.as_str()) || mirror_urls.contains(record.url.as_str()) {
            continue;
        }
        if cloud.len() >= LINK_LIMIT {
            tracing::warn!(
                "订阅同步：云端已达 {LINK_LIMIT} 条上限，未上传 {}",
                record.url
            );
            continue;
        }
        tracing::info!("订阅同步：上传本地订阅 {}", record.url);
        match api_put_link(&base, &key, &email, &record.url, record.name.as_deref()).await {
            Ok(link) => cloud.push(link),
            Err(SyncError::Transient(d)) if d.contains("409") => {
                tracing::warn!("订阅同步：云端已达上限（409），停止上传");
            }
            Err(e) => log_sync_err("reconcile_upload", e),
        }
    }

    // 5. 基线对齐云端最新状态
    save_mirror(&data_dir, &cloud);

    // 6. 本地有增删且内核运行中 → 仅在前台时重启生效（一次性）。
    // 【APP48 任务5.3】后台定时对账（App 在后台/锁屏/扩展刚被系统回收时）
    // 绝不重启隧道：iOS 扩展在 50MB Jetsam 红线内重建必然被系统强杀，
    // 表现为「用着用着自动断开」。后台只落盘缓存并广播事件，
    // 下一次用户主动启动或回前台时自然加载最新订阅。
    let foreground = state
        .app_in_foreground
        .load(std::sync::atomic::Ordering::Relaxed);
    if changed
        && *state.status.read() == super::state::CoreStatus::Running
        && foreground
        && cfg!(not(any(target_os = "ios", target_os = "android")))
    {
        tracing::info!("订阅同步：本地订阅已变更，前台重启内核生效");
        if let Err(e) = crate::ipc::commands::restart_core(app, &state).await {
            tracing::warn!("订阅同步后内核重启失败：{e}");
        }
    } else if changed {
        tracing::info!("订阅同步：后台/移动端变更仅落盘缓存，隧道保持不重启");
    }

    // 7. 有任何变更（新增/删除/空壳补拉）→ 通知前端刷新订阅列表与
    // 节点缓存。对账全程静默，仅以事件驱动 UI 更新，不弹窗
    if changed {
        use tauri::Emitter;
        let _ = app.emit("subscriptions://changed", ());
        let _ = app.emit("proxies://changed", ());
    }
    // 【APP6 任务1】[Sub] 模块日志：云端对账结果
    crate::core::logger::info(
        crate::core::logger::MOD_SUB,
        if changed {
            "云端订阅对账完成，本地订阅列表已更新"
        } else {
            "云端订阅对账完成，云端与本地一致"
        },
    );
    Ok(())
}

/// 判断本地订阅缓存是否为「空壳」：profile 文件缺失，或内容解析不出
/// 任何可用节点（127.x/localhost 机场提示节点不算）。空壳在对账时
/// 会被重新拉取（「同步了却没有节点」的根治入口）
fn profile_is_empty_shell(data_dir: &std::path::Path, url: &str) -> bool {
    let path = super::store::profile_path(data_dir, url);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return true;
    };
    // 缓存统一为 Clash YAML（refresh_subscription 落盘前已归一化）；
    // 解析失败同样按空壳处理，触发重新拉取兜底
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
        return true;
    };
    let real_nodes = value
        .get("proxies")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter(|p| {
                    let server = p.get("server").and_then(|v| v.as_str()).unwrap_or("");
                    !server.is_empty() && !server.starts_with("127.") && server != "localhost"
                })
                .count()
        })
        .unwrap_or(0);
    let has_providers = value
        .get("proxy-providers")
        .and_then(|v| v.as_mapping())
        .is_some_and(|m| !m.is_empty());
    real_nodes == 0 && !has_providers
}

/// 更新本地订阅记录的备注名（记录不存在则忽略）
fn set_local_name(data_dir: &std::path::Path, url: &str, name: Option<String>) {
    let new_name = name.filter(|n| !n.is_empty());
    let mut records = super::store::load_subscriptions(data_dir);
    let mut touched = false;
    for r in records.iter_mut() {
        if r.url == url {
            r.name = new_name.clone();
            touched = true;
        }
    }
    if touched {
        let _ = super::store::save_subscriptions(data_dir, &records);
    }
}

/// 当前启用订阅数（删除保护判定用）
fn running_enabled_count(state: &AppState) -> usize {
    super::store::load_subscriptions(&state.data_dir)
        .iter()
        .filter(|r| r.enabled)
        .count()
}
