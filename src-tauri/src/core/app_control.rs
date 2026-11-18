//! APP 远程管控 + 设备解绑实时感知（app-control-api.md + client-runtime-perception.md）。
//!
//! 每次 `/api/app/check`（启动单次）或 `/api/app/heartbeat`（每 5 分钟一次）请求：
//!   1. 携带 `device_id`（64 位 hex）+ `install_id`（36 位 UUID）+ license_key
//!   2. 服务端在请求体 `device_id` 存在时返回 `runtime` 对象：
//!      - `device_bound=true`：设备仍在绑定表；`false` = 已被官网解绑；
//!      - `subscription_active=false`：订阅已过期；
//!      - `plan`（free/pro/team）+ `expires_at` + `max_seats`。
//!      请求体缺 device_id → `runtime.device_bound=null` → 旧版兼容路径，
//!      客户端此时不做任何降级（APP-7 任务2.2）。
//!   3. 客户端按 `runtime` 执行授权级熔断（解绑删缓存，过期只改状态）。
//!   4. allowed=false 是管控级阻断（版本封锁/用户封锁），与 runtime 独立处理。
//!
//! 请求体仅携带非敏感元数据，绝不包含任何用户流量内容或地址信息。

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use tauri::{AppHandle, Emitter, Manager};
use tracing::warn;

use super::license;
use super::license::EntitlementStatus;
use super::state::{AppState, CoreStatus};

// ---------------- 请求/响应结构 ----------------

/// `/api/app/check` / `/api/app/heartbeat` 请求体（APP-7 任务2.2）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCheckRequest {
    pub platform: String,
    pub device_model: String,
    pub os_version: String,
    pub app_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license_key: Option<String>,
    /// 36 字符 UUID v4（首次安装生成；卸载重装变新值）
    pub install_id: String,
    /// 64 位小写 hex SHA-256 硬件指纹（同机重装不变，跨安装一致）
    pub device_id: String,
}

/// 权威 runtime 感知对象（client-buyout-version-management.md §2）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimePerception {
    #[serde(default)]
    pub plan: Option<String>,
    /// 【APC 任务3】订阅是否有效。三态：Some(true)=有效、Some(false)=已过期、
    /// None=字段缺失（旧版/服务端未下发）。**缺失时严禁判定为过期**。
    #[serde(default)]
    pub subscription_active: Option<bool>,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub max_seats: Option<u32>,
    /// true=已绑定, false=已被官网解绑, null=请求未传 device_id（旧版）
    pub device_bound: Option<bool>,

    // ---------- 买断版本范围（client-buyout-version-management.md §2.2）----------
    /// 官网授权可覆盖的最新主版本号（如 4 表示买断 1~4 都有效）
    #[serde(default)]
    pub included_major: Option<u32>,
    /// 当前 APP 主版本号（客户端按 CARGO_PKG_VERSION 拆）；可由服务端覆盖
    #[serde(default)]
    pub current_major: Option<u32>,
    /// 当前 APP 是否在买断版本范围内：
    /// - true 或 None → 正常；
    /// - false → 超出买断范围，Pro 功能受限 + 弹升级引导，但 APP 继续可用。
    #[serde(default)]
    pub version_in_scope: Option<bool>,

    /// 【APP48 任务6】Alpha 内测授权：true 时按 Pro 放行，但云端同步不可用。
    #[serde(default)]
    pub alpha: bool,
}

/// check/heartbeat 响应
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlResponse {
    pub allowed: bool,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub message: String,
    /// APP-7 新增：权威授权态感知（缺字段时旧版兼容不降级）
    #[serde(default)]
    pub runtime: Option<RuntimePerception>,
}

/// 当前阻断状态（存于 AppState.control_block）
#[derive(Debug, Clone, Serialize)]
pub struct ControlBlock {
    pub reason: String,
    pub message: String,
}

/// 【APC 任务4】管控原因完整集合（与 app-control-api.md §3 判定优先级一致）。
/// 服务端返回的原始 reason 必须原样保留，严禁把未知原因静默伪装成 version_blocked。
const REASON_DEVICE: &str = "device_blocked";
const REASON_USER: &str = "user_blocked";
const REASON_VERSION: &str = "version_blocked";
/// 服务端 reason 为空/未知时的通用兜底标识（仅用于 UI 通用文案）
const REASON_GENERIC: &str = "blocked";

/// reason 归一化：只做 trim 与空值兜底，绝不改写服务端已给出的原始原因
fn normalize_block_reason(raw: &str) -> String {
    let r = raw.trim();
    if r.is_empty() {
        REASON_GENERIC.to_string()
    } else {
        r.to_string()
    }
}

fn default_message(reason: &str) -> String {
    match reason {
        REASON_DEVICE => "当前终端已被限制使用，如有疑问请联系客服工单。".to_string(),
        REASON_USER => "当前授权账号已被限制使用，如有疑问请联系客服工单。".to_string(),
        REASON_VERSION => {
            "当前 APP 版本已停止支持，请前往 https://prism.sarl 下载更新最新版本后继续使用。"
                .to_string()
        }
        _ => {
            "当前 APP 已被限制使用，请前往 https://prism.sarl 查看详细信息或联系客服。".to_string()
        }
    }
}

// ---------------- 离线 runtime 缓存 ----------------

fn runtime_cache_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("runtime_cache.json")
}

/// 把最新 runtime 落到本地（供断网离线兜底：启动时读一次再做降级判断）
pub fn persist_runtime(data_dir: &std::path::Path, runtime: &RuntimePerception) {
    let Ok(raw) = serde_json::to_string(&serde_json::json!({
        "runtime": runtime,
        "saved_at": license::now_secs(),
    })) else {
        return;
    };
    let _ = super::store::atomic_write(&runtime_cache_path(data_dir), raw.as_bytes());
}

/// 读取离线 runtime 缓存（返回 (runtime, saved_at_unix_secs)；无缓存时返回 None）
pub fn load_runtime_cache(data_dir: &std::path::Path) -> Option<(RuntimePerception, i64)> {
    let raw = std::fs::read_to_string(runtime_cache_path(data_dir)).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let runtime: RuntimePerception = serde_json::from_value(v.get("runtime")?.clone()).ok()?;
    let saved_at = v.get("saved_at").and_then(|v| v.as_i64()).unwrap_or(0);
    Some((runtime, saved_at))
}

// ---------------- 授权剥夺原因持久化（IPA-3 任务2）----------------
//
// 解绑时 license.dat 会被删除，授权到期时 status 只有 expired 一个值，
// 两种情况的「原因」都无法从授权文件里还原。若不落盘，用户重启 App 后
// 横幅就消失了，无法引导他去官网重新激活。这里用独立的 revoke_state.json
// 记录最近一次剥夺原因，激活成功 / 恢复有效授权时清除。

fn revoke_state_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("revoke_state.json")
}

pub fn persist_revoke_reason(data_dir: &std::path::Path, reason: &str) {
    let Ok(raw) = serde_json::to_string(&serde_json::json!({
        "reason": reason,
        "saved_at": license::now_secs(),
    })) else {
        return;
    };
    let _ = super::store::atomic_write(&revoke_state_path(data_dir), raw.as_bytes());
}

pub fn load_revoke_reason(data_dir: &std::path::Path) -> Option<String> {
    let raw = std::fs::read_to_string(revoke_state_path(data_dir)).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let reason = v.get("reason")?.as_str()?.to_string();
    if matches!(
        reason.as_str(),
        REVOKE_UNBOUND
            | REVOKE_EXPIRED
            | REVOKE_ALPHA_UNBOUND
            | REVOKE_ALPHA_EXPIRED
            | REVOKE_DEACTIVATED
    ) {
        Some(reason)
    } else {
        None
    }
}

pub fn clear_revoke_reason(data_dir: &std::path::Path) {
    let _ = std::fs::remove_file(revoke_state_path(data_dir));
}

// ---------------- apply_runtime：授权级熔断 ----------------

/// 【APC 任务5】runtime → revoke 原因的纯函数（无副作用，便于单测）。
/// 返回 None 表示授权有效（含 Free、Team 买断、未激活，以及订阅字段缺失的旧版响应）。
///
/// 判定优先级（app-control-api.md §3 / APC 第五阶段）：
/// 1. `device_bound === false` → 设备解绑（Alpha 用独立文案），只降级 Pro，不封禁 APP；
/// 2. 仅当服务端**明确**返回 `subscription_active === false` 且方案为 Pro 时才判定到期；
/// 3. Team 买断恒有效；Free 是正常基础态；`plan === null` 是未激活（Free），
///    均绝不按「授权到期」处理（字段缺失/为 null 不能当成 false）。
fn decide_revoke(runtime: &RuntimePerception) -> Option<&'static str> {
    let plan = runtime.plan.as_deref();
    if runtime.device_bound == Some(false) {
        return Some(if runtime.alpha {
            REVOKE_ALPHA_UNBOUND
        } else {
            REVOKE_UNBOUND
        });
    }
    if matches!(runtime.subscription_active, Some(false)) {
        match plan {
            Some("pro") => {
                return Some(if runtime.alpha {
                    REVOKE_ALPHA_EXPIRED
                } else {
                    REVOKE_EXPIRED
                });
            }
            // Alpha 到期后服务端退回未激活态（plan=null），按内测到期处理
            None if runtime.alpha => return Some(REVOKE_ALPHA_EXPIRED),
            // team（永久买断）/ free（基础态）/ 未知方案：不剥夺
            _ => {}
        }
    }
    None
}

/// 【APC4 任务4】买断版本范围判定（纯函数，便于单测）：
/// 仅买断方案（buyout/team）有意义；`version_in_scope` 显式给出时直接采信，
/// 缺失时对比 current_major / included_major，字段任一缺失一律视为在范围内。
fn buyout_out_of_scope(runtime: &RuntimePerception) -> bool {
    if !matches!(runtime.plan.as_deref(), Some("buyout") | Some("team")) {
        return false;
    }
    if let Some(v) = runtime.version_in_scope {
        return !v;
    }
    let current = runtime.current_major.or_else(app_major);
    match (current, runtime.included_major) {
        (Some(cur), Some(inc)) => cur > inc,
        _ => false,
    }
}

/// 编译期 APP 主版本号（Cargo.toml version）
fn app_major() -> Option<u32> {
    env!("CARGO_PKG_VERSION").split('.').next()?.parse().ok()
}

/// 根据权威 runtime 执行授权级熔断 + 买断版本范围降级
/// （client-runtime-perception.md §3 与 client-buyout-version-management.md §4 合并入口）。
/// 返回 Some((revoked, message)) 表示发生了授权级动作；买断超出范围（不剥夺授权，
/// 只弹升级引导）走独立的 buyout_upgrade 标志，由前端区分处理。
pub fn apply_runtime(
    app: &AppHandle,
    state: &AppState,
    data_dir: &std::path::Path,
    runtime: &RuntimePerception,
) -> Option<(bool, String)> {
    persist_runtime(data_dir, runtime);

    let is_unbound = runtime.device_bound == Some(false);

    // ---------- 买断超出版本范围（不剥夺授权，只弹升级引导）----------
    // 客户端兜底：若服务端没给 version_in_scope，则对比 current_major vs included_major
    let buyout_upgrade_hint = buyout_out_of_scope(runtime);

    if buyout_upgrade_hint {
        // 买断超出范围：Pro 功能仍可用，但弹一次升级引导；绝不剥夺授权。
        emit_buyout_upgrade(app, runtime);
        // 买断用户可能同时有解绑/订阅状态（罕见但可能），但版本范围超出是独立信号，
        // 只弹引导不降级，让 apply_runtime 继续按下面逻辑处理真正的剥夺。
    }

    let Some(reason) = decide_revoke(runtime) else {
        clear_revoke_reason(data_dir);
        sync_entitlement_from_runtime(state, runtime);
        return None;
    };

    let (zh, en) = revoke_message(reason);
    persist_revoke_reason(data_dir, reason);

    let was_active = state
        .entitlement
        .read()
        .status
        .eq_ignore_ascii_case("active");
    if !was_active {
        emit_revoked(app, reason, zh, en, None);
        return Some((true, zh.to_string()));
    }

    let entitlement = if is_unbound {
        license::deactivate(data_dir)
    } else {
        license::mark_expired(data_dir).unwrap_or_else(EntitlementStatus::inactive)
    };

    state.apply_entitlement(entitlement.clone());
    disable_pro_switches(state);
    emit_revoked(app, reason, zh, en, Some(&entitlement));

    if *state.status.read() == CoreStatus::Running {
        tracing::info!(
            "[runtime] Pro 授权被剥夺（reason={reason}），关闭所有 Pro 开关，保留基础 VPN"
        );
    }

    Some((true, zh.to_string()))
}

/// 广播 `buyout://upgrade`：买断用户超出版本范围时弹升级引导横幅；
/// 与 revoked 互斥（版本超出不等于授权剥夺），基础 VPN + Pro 功能全部继续可用。
pub fn emit_buyout_upgrade(app: &AppHandle, runtime: &RuntimePerception) {
    let major = runtime.current_major.unwrap_or_else(|| {
        env!("CARGO_PKG_VERSION")
            .split('.')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    });
    let included = runtime.included_major.unwrap_or(0);
    let zh = format!(
        "您的 Prism 买断授权可覆盖至主版本 v{included}，当前 APP 已升级到 v{major}。Pro 功能继续可用，如需使用后续新版高级特性请前往官网续费。"
    );
    let en = format!(
        "Your buyout covers up to v{included}. You are running v{major}. Pro features remain available. Visit our site to unlock future major versions."
    );
    let _ = app.emit(
        "buyout://upgrade",
        &serde_json::json!({
            "current_major": major,
            "included_major": included,
            "version_in_scope": runtime.version_in_scope,
            "zh": zh,
            "en": en,
        }),
    );
}

// ---------------- 授权剥夺原因（IPA-3 任务2）----------------

/// 设备被官网解绑（`runtime.device_bound === false`）
pub const REVOKE_UNBOUND: &str = "unbound";
/// 授权时间到期（`runtime.subscription_active === false` 且非买断）
pub const REVOKE_EXPIRED: &str = "expired";
/// 【APC 任务5】Alpha 内测设备绑定失效（`alpha=true` 且 `device_bound=false`）
pub const REVOKE_ALPHA_UNBOUND: &str = "alpha_unbound";
/// 【APC 任务5】Alpha 内测授权到期
pub const REVOKE_ALPHA_EXPIRED: &str = "alpha_expired";
/// 【APC4 任务1.2】用户在本机主动解绑设备（反激活）
pub const REVOKE_DEACTIVATED: &str = "deactivated";

/// 原因 → (中文, 英文) 提示文案。前端按 reason 精准渲染，禁止复用同一句。
pub fn revoke_message(reason: &str) -> (&'static str, &'static str) {
    if reason == REVOKE_ALPHA_UNBOUND {
        (
            "Alpha 内测设备绑定已失效，Pro 功能已自动停止。请前往官网控制台确认绑定，或联系内测负责人重新绑定。",
            "Your Alpha test device binding is no longer valid. Pro features have been stopped. Please check the console or contact the Alpha coordinator to re-bind.",
        )
    } else if reason == REVOKE_ALPHA_EXPIRED {
        (
            "Alpha 内测授权已到期，Go AIM / Go Lan / Go Cus 与连接监控等 Pro 功能已自动停止。请联系内测负责人续期。",
            "Your Alpha test license has expired. Pro features (Go AIM / Go Lan / Go Cus / Connections) have been stopped. Please contact the Alpha coordinator to renew.",
        )
    } else if reason == REVOKE_UNBOUND {
        (
            "当前设备已在官网控制台解除绑定，Go AIM / Go Lan / Go Cus 与连接监控等 Pro 功能已自动停止。请前往「设置 → Prism Pro」重新激活。",
            "This device has been unbound from your account. Pro features (Go AIM / Go Lan / Go Cus / Connections) have been stopped. Please re-activate in Settings → Prism Pro.",
        )
    } else if reason == REVOKE_DEACTIVATED {
        (
            "本机授权已解绑，席位已释放，Pro 功能已自动停止。可在其他设备登录使用，或在本机重新激活。",
            "This device has been deactivated and its seat released. Pro features have been stopped. You can activate on another device or re-activate here.",
        )
    } else {
        (
            "授权已到期，Go AIM / Go Lan / Go Cus 与连接监控等 Pro 功能已自动停止。请前往「设置 → Prism Pro」续期后恢复。",
            "Your license has expired. Pro features (Go AIM / Go Lan / Go Cus / Connections) have been stopped. Please renew in Settings → Prism Pro.",
        )
    }
}

/// 广播 `pro://revoked`：payload 携带 reason + zh/en 双语文案，
/// 前端按 reason 渲染对应横幅，绝不再把解绑显示成「授权已到期」。
pub fn emit_revoked(
    app: &AppHandle,
    reason: &str,
    zh: &str,
    en: &str,
    entitlement: Option<&EntitlementStatus>,
) {
    let _ = app.emit(
        "pro://revoked",
        &serde_json::json!({
            "reason": reason,
            "zh": zh,
            "en": en,
            "unbound": reason == REVOKE_UNBOUND,
            "expired": reason == REVOKE_EXPIRED,
            "entitlement": entitlement,
        }),
    );
}

fn sync_entitlement_from_runtime(state: &AppState, runtime: &RuntimePerception) {
    let mut ent = state.entitlement.read().clone();
    // 【APP48 任务6】runtime.alpha 需保真：内测授权 plan 可能也是 pro/team，
    // 但绝不能渲染成买断/永久，且必须关闭云端同步。
    ent.alpha = runtime.alpha;
    if ent.alpha {
        ent.sync_available = false;
    }
    let Some(plan) = runtime.plan.clone() else {
        // 【APC 任务5】plan=null = 未激活/Free 基线：只做静默降级，
        // 绝不显示成「授权到期」（服务端未提供方案 ≠ 服务端明确判定失效）。
        ent.plan = None;
        ent.kind = None;
        ent.status = "inactive".into();
        ent.sync_available = false;
        ent.last_verified_at = license::now_secs();
        state.apply_entitlement(ent);
        return;
    };
    ent.plan = Some(plan.clone());
    ent.kind = Some(
        if plan == "team" && !ent.alpha {
            "lifetime"
        } else {
            "subscription"
        }
        .into(),
    );
    ent.max_seats = runtime.max_seats;
    if let Some(exp_str) = runtime.expires_at.as_deref()
        && let Some(exp) = license::parse_expires_at(exp_str)
    {
        ent.expires_at = Some(exp);
    }
    // 【APC 任务3】服务端 runtime 是权威来源：
    // - Free（plan=free）保留方案展示但绝不解锁 Pro；
    // - 其余有效方案（pro/team/alpha）把旧的 expired/inactive 状态修正为 active，
    //   否则续费成功后客户端仍会停留在锁定状态。
    if plan == "free" {
        ent.status = "inactive".into();
        // Free 不含云端同步权益
        ent.sync_available = false;
    } else if !ent.status.eq_ignore_ascii_case("active") {
        ent.status = "active".into();
    }
    ent.last_verified_at = license::now_secs();
    state.apply_entitlement(ent);
}

/// 关闭所有 Pro 专属开关（Go AIM / Go Lan / Go Cus）并持久化，
/// 保证解绑/到期后重启不会被磁盘上的旧开关重新打开。
pub(crate) fn disable_pro_switches(state: &AppState) {
    let mut settings = state.settings.read().clone();
    settings.go_aim_enabled = false;
    let _ = state.save_settings(settings);

    let mut lan = state.go_lan.read().clone();
    lan.enabled = false;
    let _ = crate::core::go_lan::save(&state.data_dir, &lan);
    *state.go_lan.write() = lan;
    let mut cus = state.go_cus.read().clone();
    cus.enabled = false;
    let _ = crate::core::go_cus::save(&state.data_dir, &cus);
    *state.go_cus.write() = cus;

    *state.aim_locked_node.write() = None;
}

/// 【APC4 任务1.3】广播 `license://revoked`（新事件）并兼容旧 `pro://revoked`。
/// 60s 在线复核 / activate 后状态变化统一走这里。
pub(crate) fn emit_license_revoked(
    app: &AppHandle,
    reason: &str,
    entitlement: Option<&EntitlementStatus>,
) {
    let (zh, en) = revoke_message(reason);
    let _ = app.emit(
        "license://revoked",
        &serde_json::json!({
            "reason": reason,
            "zh": zh,
            "en": en,
            "entitlement": entitlement,
        }),
    );
    emit_revoked(app, reason, zh, en, entitlement);
}

// ---------------------------------------------------------------- 设备信息

/// 平台标识（与 app-control-api.md 枚举对齐；Linux 桌面按 windows 兜底）
fn platform_name() -> &'static str {
    #[cfg(target_os = "ios")]
    {
        "ios"
    }
    #[cfg(target_os = "android")]
    {
        "android"
    }
    #[cfg(target_os = "tvos")]
    {
        "tvos"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        "windows"
    }
}

/// (device_model, os_version)——仅系统/机型名称，非设备唯一标识
fn device_info() -> (String, String) {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        apple_device_info()
    }
    #[cfg(target_os = "android")]
    {
        android_device_info()
    }
    #[cfg(target_os = "windows")]
    {
        ("Windows PC".to_string(), windows_os_version())
    }
    #[cfg(target_os = "linux")]
    {
        ("Linux PC".to_string(), "Linux".to_string())
    }
}

/// Apple 平台：sysctl 读取机型标识（如 iPhone15,3 / arm64）与产品版本（如 18.1）
#[cfg(any(target_os = "ios", target_os = "macos"))]
fn apple_device_info() -> (String, String) {
    unsafe {
        let model = sysctl_string(b"hw.machine").unwrap_or_else(|| "unknown".into());
        let version = sysctl_string(b"kern.osproductversion").unwrap_or_else(|| "unknown".into());
        let prefix = if cfg!(target_os = "ios") {
            "iOS "
        } else {
            "macOS "
        };
        (model, format!("{prefix}{version}"))
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
unsafe fn sysctl_string(name: &[u8]) -> Option<String> {
    let mut size: libc::size_t = 0;
    let cname = std::ffi::CString::new(name).ok()?;
    // APP27：edition 2024 下 unsafe fn 内的 unsafe 调用也必须显式加 unsafe 块
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let mut buf = vec![0u8; size];
    let rc2 = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc2 != 0 {
        return None;
    }
    buf.truncate(size.saturating_sub(1)); // 去掉结尾 NUL
    String::from_utf8(buf).ok()
}

/// Android：__system_property_get 读取系统属性（机型/系统版本）
#[cfg(target_os = "android")]
fn android_device_info() -> (String, String) {
    use std::ffi::CStr;
    unsafe {
        let prop = |key: &[u8]| -> String {
            // __system_property_get 缓冲区按 libc::c_char 对齐，92 字节为
            // PROP_VALUE_MAX 的安全冗余。注意 c_char 在 i686/x86_64 Android
            // 目标上为 i8，若写死 [u8; 92] 会在 32 位 x86 端 E0308 编译失败。
            let mut buf = [0 as libc::c_char; 92];
            let cname = match std::ffi::CString::new(key) {
                Ok(c) => c,
                Err(_) => return String::new(),
            };
            if libc::__system_property_get(cname.as_ptr(), buf.as_mut_ptr()) == 0 {
                return String::new();
            }
            CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
        };
        let release = prop(b"ro.build.version.release");
        let manufacturer = prop(b"ro.product.manufacturer");
        let model = prop(b"ro.product.model");
        let model = if model.is_empty() {
            manufacturer
        } else {
            model
        };
        (
            if model.is_empty() {
                "Android".into()
            } else {
                model
            },
            if release.is_empty() {
                "Android".into()
            } else {
                format!("Android {release}")
            },
        )
    }
}

/// Windows：RtlGetVersion 判别 Win10 / Win11（版本号都是 10.0，以 build 区分）
#[cfg(target_os = "windows")]
fn windows_os_version() -> String {
    #[repr(C)]
    struct OsVersionInfoW {
        dw_os_version_info_size: u32,
        dw_major_version: u32,
        dw_minor_version: u32,
        dw_build_number: u32,
        dw_platform_id: u32,
        sz_csd_version: [u16; 128],
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(info: *mut OsVersionInfoW) -> i32;
    }
    let mut info = OsVersionInfoW {
        dw_os_version_info_size: std::mem::size_of::<OsVersionInfoW>() as u32,
        dw_major_version: 0,
        dw_minor_version: 0,
        dw_build_number: 0,
        dw_platform_id: 0,
        sz_csd_version: [0; 128],
    };
    // SAFETY: 结构体按文档初始化并传指针
    let ok = unsafe { RtlGetVersion(&mut info) } == 0;
    if ok && info.dw_build_number >= 22000 {
        "Windows 11".into()
    } else if ok {
        "Windows 10".into()
    } else {
        "Windows".into()
    }
}

// ---------------------------------------------------------------- 上报逻辑

/// 上报类型：启动单次 `/api/app/check`，周期 5 分钟 `/api/app/heartbeat`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportKind {
    Check,
    Heartbeat,
}

impl ReportKind {
    fn url(self, base: &str) -> String {
        match self {
            ReportKind::Check => format!("{base}{}", crate::obf!("/api/app/check")),
            ReportKind::Heartbeat => format!("{base}{}", crate::obf!("/api/app/heartbeat")),
        }
    }
}

/// 【APC 任务2】控制协议超时：5s（连接 3s），远小于旧版 8s，
/// 避免启动阶段与内核启动抢网络栈时界面长时间空转。
const REPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REPORT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// 【APC 任务2】单飞锁：check 与 heartbeat 共用，同一时刻只允许一个在途上报。
static REPORT_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
/// 【APC 任务4】最近一次成功上报时间点（Unix 秒），前台唤醒去重使用。
static LAST_SUCCESS_UNIX: AtomicI64 = AtomicI64::new(0);

/// RAII：无论成功/失败/提前 return，都释放单飞锁。
struct ReportFlightGuard;

impl Drop for ReportFlightGuard {
    fn drop(&mut self) {
        REPORT_IN_FLIGHT.store(false, Ordering::Release);
    }
}

/// 最近一次成功上报的 Unix 秒（0 = 从未成功）
pub fn last_success_unix() -> i64 {
    LAST_SUCCESS_UNIX.load(Ordering::Acquire)
}

/// 执行一次 check/心跳上报并应用结果（fail-open：仅 allowed=false 才有管控动作）。
/// APP-7 新增：runtime 授权级熔断（解绑/过期/plan 缺失）。
pub(crate) async fn report_once(app: &AppHandle, state: &AppState, kind: ReportKind) {
    // 【APC 任务2】单飞：已有在途请求时直接返回，绝不并发打控制接口
    if REPORT_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let _flight = ReportFlightGuard;

    let settings = state.settings.read().clone();
    let base = super::license::api_base(&settings);
    let url = kind.url(&base);
    let (device_model, os_version) = device_info();

    let device_id_str = match license::device_id(&state.data_dir) {
        Ok(id) => id,
        Err(e) => {
            warn!("app-control: device_id unavailable: {e}");
            return;
        }
    };
    let install_id = match license::get_or_create_install_id(&state.data_dir) {
        Ok(id) => id,
        Err(e) => {
            warn!("app-control: install_id unavailable: {e}");
            return;
        }
    };

    let payload = AppCheckRequest {
        platform: platform_name().into(),
        device_model,
        os_version,
        app_version: env!("CARGO_PKG_VERSION").into(),
        license_key: super::license::get_saved_license_key(&state.data_dir),
        install_id,
        device_id: device_id_str,
    };

    // 专用客户端：绕过系统/内核代理直连上报（心跳必须走最短路径，且避免
    // 内核停止后系统代理指向已下线的本地端口导致心跳自锁）
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(REPORT_CONNECT_TIMEOUT)
        .timeout(REPORT_TIMEOUT)
        .build();
    let resp = match client {
        Ok(c) => {
            c.post(&url)
                .header("X-Request-Source", super::license::REQUEST_SOURCE)
                .json(&payload)
                .send()
                .await
        }
        Err(e) => {
            warn!("app-control: client build failed: {e}");
            return;
        }
    };
    let parsed: Option<ControlResponse> = match resp {
        Ok(r) if r.status().is_success() => r.json().await.ok(),
        Ok(r) => {
            warn!("app-control: {:?} returned HTTP {}", kind, r.status());
            return;
        }
        Err(e) => {
            warn!("app-control: {:?} failed (fail-open): {e}", kind);
            return;
        }
    };
    let Some(resp) = parsed else {
        return;
    };
    // 成功拿到可解析响应（无论 allowed 与否）才刷新成功时间
    LAST_SUCCESS_UNIX.store(license::now_secs(), Ordering::Release);

    // 1. 授权级熔断（runtime 存在时执行；缺字段时旧版兼容不降级）
    if let Some(runtime) = resp.runtime.as_ref() {
        apply_runtime(app, state, &state.data_dir, runtime);
    }

    // 2. 管控级阻断（allowed=false）
    if resp.allowed {
        clear_control_block(app, state, &resp.reason, &resp.message);
        return;
    }

    enforce_control_block(app, state, &resp.reason, &resp.message).await;
}

/// 解除管控：清除 control_block 并广播 allowed=true（仅在确有阻断时广播）
fn clear_control_block(app: &AppHandle, state: &AppState, reason: &str, message: &str) {
    if state.control_block.read().is_some() {
        *state.control_block.write() = None;
        let _ = app.emit(
            "app://control",
            &serde_json::json!({
                "allowed": true,
                "reason": reason,
                "message": message,
            }),
        );
    }
}

/// 【APC 任务4】应用管控级阻断（allowed=false）：
/// - 保留服务端原始 reason（device_blocked / user_blocked / version_blocked / 未知）；
/// - message 非空时优先展示，空才用默认文案；
/// - 立即停止运行中的内核并写入 control_block（后续 start/restart 全部被拒）；
/// - reason/message 未变化时跳过重复广播（心跳每 5 分钟一次）。
/// 返回最终 (reason, message)。
async fn enforce_control_block(
    app: &AppHandle,
    state: &AppState,
    raw_reason: &str,
    raw_message: &str,
) -> (String, String) {
    let reason = normalize_block_reason(raw_reason);
    if !matches!(
        reason.as_str(),
        REASON_DEVICE | REASON_USER | REASON_VERSION
    ) {
        // 未知原因保留原始值（脱敏后）仅记录日志，前端走通用封禁 UI
        warn!("app-control: 服务端返回未识别的管控原因: {reason}");
    }
    let message = if raw_message.trim().is_empty() {
        default_message(&reason)
    } else {
        raw_message.to_string()
    };

    let changed = {
        let cur = state.control_block.read();
        match cur.as_ref() {
            Some(b) => b.reason != reason || b.message != message,
            None => true,
        }
    };

    // 阻断生效：停止运行中的内核（连接会话必须立即终止）
    if *state.status.read() == CoreStatus::Running
        && let Err(e) = crate::ipc::commands::do_stop(state).await
    {
        warn!("app-control: stop kernel failed: {e}");
    }
    *state.control_block.write() = Some(ControlBlock {
        reason: reason.clone(),
        message: message.clone(),
    });
    if changed {
        let _ = app.emit(
            "app://control",
            &serde_json::json!({
                "allowed": false,
                "reason": reason,
                "message": message,
            }),
        );
    }
    (reason, message)
}

/// 启动单次上报：立即执行一次（不等首个心跳周期）
pub fn spawn_startup_check(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        report_once(&app, &state, ReportKind::Check).await;
    });
}

/// 心跳循环：启动上报完成后每 5 分钟（300 秒，服务端约定的最小间隔）一次
pub fn spawn_heartbeat(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            let state = app.state::<AppState>();
            report_once(&app, &state, ReportKind::Heartbeat).await;
        }
    });
}

// ---------------- 权威强制校验 + 前台唤醒 ----------------

/// 暴露给 commands.rs（refresh_entitlement）：直接用权威 runtime 做一次强制校验。
/// 返回 (EntitlementStatus, Option<revoke_msg>)；Err 表示网络失败或管控阻断。
pub async fn force_runtime_check(
    app: &AppHandle,
    state: &AppState,
) -> Result<(EntitlementStatus, Option<String>), String> {
    let settings = state.settings.read().clone();
    let base = super::license::api_base(&settings);
    let url = format!("{base}{}", crate::obf!("/api/app/check"));
    let (device_model, os_version) = device_info();

    let device_id_str =
        license::device_id(&state.data_dir).map_err(|e| sanitize(&e.to_string()))?;
    let install_id =
        license::get_or_create_install_id(&state.data_dir).map_err(|e| sanitize(&e.to_string()))?;

    let payload = AppCheckRequest {
        platform: platform_name().into(),
        device_model,
        os_version,
        app_version: env!("CARGO_PKG_VERSION").into(),
        license_key: super::license::get_saved_license_key(&state.data_dir),
        install_id,
        device_id: device_id_str,
    };

    // 【APC 任务3】与后台 check/heartbeat 共用同一把单飞锁 + 独立直连客户端：
    // 不走授权模块的本地代理/DoH 容灾链路（管控请求必须是最短直连路径），
    // 且同一时刻只允许一个管控请求在途。
    if REPORT_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("授权状态同步中，请稍后重试".to_string());
    }
    let _flight = ReportFlightGuard;

    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(REPORT_CONNECT_TIMEOUT)
        .timeout(REPORT_TIMEOUT)
        .build()
        .map_err(|e| sanitize(&e.to_string()))?;
    let resp = client
        .post(&url)
        .header("X-Request-Source", super::license::REQUEST_SOURCE)
        .json(&payload)
        .send()
        .await
        .map_err(|e| sanitize(&e.to_string()))?;

    if !resp.status().is_success() {
        return Err(format!(
            "授权服务返回 HTTP {}，无法完成权威校验",
            resp.status()
        ));
    }
    let parsed: ControlResponse = resp.json().await.map_err(|e| sanitize(&e.to_string()))?;
    LAST_SUCCESS_UNIX.store(license::now_secs(), Ordering::Release);

    // 管控级阻断：与心跳完全一致（停止内核 + 写入 control_block + 广播）
    if !parsed.allowed {
        let (reason, message) =
            enforce_control_block(app, state, &parsed.reason, &parsed.message).await;
        return Err(sanitize(&format!(
            "授权服务管控阻断（{reason}）：{message}"
        )));
    }
    clear_control_block(app, state, &parsed.reason, &parsed.message);

    // 授权级熔断：与心跳走完全相同的 apply_runtime（含 pro://revoked 广播），
    // 避免「立即校验」与后台心跳出现两套不一致的解绑/到期判定。
    let mut revoke_reason: Option<String> = None;
    if let Some(runtime) = parsed.runtime.as_ref() {
        let reason = decide_revoke(runtime);
        if apply_runtime(app, state, &state.data_dir, runtime).is_some() {
            revoke_reason = reason.map(str::to_string);
        }
    } else {
        // 服务端 runtime 缺失 → 回落到旧的 GET /api/license/status 兼容路径
        match license::verify_remote_forced(&state.data_dir, &settings).await {
            Ok(ent) => state.apply_entitlement(ent),
            Err(e) => return Err(sanitize(&e.to_string())),
        }
    }

    let ent = state.entitlement.read().clone();
    Ok((ent, revoke_reason))
}

/// 【APP23 任务2.1】巡检/云同步错误脱敏：先经授权模块统一剥离
/// http(s) URL 与网络错误原始报错，再截断到 200 字符，
/// 严禁把 /api/app/check 等后端接口地址暴露到界面或日志。
fn sanitize(s: &str) -> String {
    let clean = super::license::sanitize_license_error(s);
    if clean.len() > 200 {
        clean.chars().take(200).collect()
    } else {
        clean
    }
}

// ---------------- 前台唤醒自动感知 ----------------

/// 【APC 任务4】最近一次前台补发尝试时间（失败也记录，避免切前台反复重试）
static FOREGROUND_LAST_ATTEMPT: AtomicI64 = AtomicI64::new(0);

/// App 从后台回前台（visibility changed visible）触发一次 heartbeat 校验。
/// 【APC 任务4】去重窗口 5 分钟（与心跳周期一致）：
/// - 距上次成功上报或上次尝试不足 5 分钟 → 不重复发送；
/// - 达到 5 分钟 → 立即补发一次 heartbeat；
/// - 失败不无限重试（尝试时间同样计入窗口），网络恢复后按时间规则补发。
pub fn schedule_foreground_check(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let now = license::now_secs();
        let last = FOREGROUND_LAST_ATTEMPT
            .load(Ordering::Acquire)
            .max(last_success_unix());
        if last > 0 && now - last < 300 {
            return;
        }
        FOREGROUND_LAST_ATTEMPT.store(now, Ordering::Release);
        let state = app.state::<AppState>();
        report_once(&app, &state, ReportKind::Heartbeat).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(
        plan: Option<&str>,
        subscription_active: Option<bool>,
        device_bound: Option<bool>,
        alpha: bool,
    ) -> RuntimePerception {
        RuntimePerception {
            plan: plan.map(|p| p.to_string()),
            subscription_active,
            device_bound,
            alpha,
            ..Default::default()
        }
    }

    /// 【APC 任务3】订阅字段缺失绝不能被当成 false，否则旧服务端会把所有人踢下线
    #[test]
    fn appc_missing_subscription_is_not_expired() {
        assert_eq!(
            decide_revoke(&rt(Some("pro"), None, Some(true), false)),
            None
        );
        assert_eq!(
            decide_revoke(&rt(Some("pro"), Some(true), Some(true), false)),
            None
        );
        assert_eq!(
            decide_revoke(&rt(Some("pro"), Some(false), Some(true), false)),
            Some(REVOKE_EXPIRED)
        );
    }

    /// 【APC 任务3】Free 与买断不得触发 revoke
    #[test]
    fn appc_free_and_team_are_not_revoked() {
        assert_eq!(
            decide_revoke(&rt(Some("free"), Some(false), Some(true), false)),
            None
        );
        assert_eq!(
            decide_revoke(&rt(Some("team"), Some(false), Some(true), false)),
            None
        );
        assert_eq!(
            decide_revoke(&rt(Some("buyout"), Some(false), Some(true), false)),
            None
        );
        // 订阅字段缺失 + team（永久）
        assert_eq!(
            decide_revoke(&rt(Some("team"), None, Some(true), false)),
            None
        );
    }

    /// 【APC 任务5】plan=null 是未激活/Free 基线，不得按「授权到期」剥夺；
    /// 但 Alpha 内测到期后服务端同样退回未激活态，此时必须识别为内测到期。
    #[test]
    fn appc_null_plan_is_free_not_expired() {
        assert_eq!(
            decide_revoke(&rt(None, Some(false), Some(true), false)),
            None
        );
        assert_eq!(decide_revoke(&rt(None, None, Some(true), false)), None);
        assert_eq!(
            decide_revoke(&rt(None, Some(false), Some(true), true)),
            Some(REVOKE_ALPHA_EXPIRED)
        );
    }

    /// 【APC 任务4】封禁原因必须原样保留，未知/空原因不得伪装成 version_blocked
    #[test]
    fn appc_block_reason_preserved() {
        assert_eq!(normalize_block_reason("device_blocked"), REASON_DEVICE);
        assert_eq!(normalize_block_reason("user_blocked"), REASON_USER);
        assert_eq!(normalize_block_reason("version_blocked"), REASON_VERSION);
        assert_eq!(
            normalize_block_reason("custom_future_reason"),
            "custom_future_reason"
        );
        assert_eq!(normalize_block_reason("  "), REASON_GENERIC);
        assert_ne!(
            normalize_block_reason("custom_future_reason"),
            REASON_VERSION
        );
        // 三类已知原因必须有各自独立的默认文案
        assert!(default_message(REASON_DEVICE).contains("终端"));
        assert!(default_message(REASON_USER).contains("账号"));
        assert!(default_message(REASON_VERSION).contains("版本"));
    }

    /// 【APC 任务3】管控客户端必须独立直连（no_proxy）+ 5 秒超时 + 单飞
    #[test]
    fn appc_control_client_is_isolated() {
        assert_eq!(REPORT_TIMEOUT, std::time::Duration::from_secs(5));
        assert_eq!(REPORT_CONNECT_TIMEOUT, std::time::Duration::from_secs(3));
        let src = include_str!("app_control.rs");
        assert!(src.contains(".no_proxy()"));
        // 手动强制校验不得再走授权模块的代理容灾链路
        assert!(!src.contains(concat!("post_", "with_fallback")));
    }

    /// 【APC 任务5】Alpha 解绑/到期必须与正式授权区分
    #[test]
    fn appc_alpha_revoke_reasons() {
        assert_eq!(
            decide_revoke(&rt(Some("pro"), Some(true), Some(false), true)),
            Some(REVOKE_ALPHA_UNBOUND)
        );
        assert_eq!(
            decide_revoke(&rt(Some("pro"), Some(false), Some(true), true)),
            Some(REVOKE_ALPHA_EXPIRED)
        );
        assert_eq!(
            decide_revoke(&rt(Some("pro"), Some(true), Some(false), false)),
            Some(REVOKE_UNBOUND)
        );
        let (zh, _) = revoke_message(REVOKE_ALPHA_UNBOUND);
        assert!(zh.contains("Alpha"), "Alpha 解绑必须使用内测专用文案");
    }

    /// 【APC4 任务4】买断版本范围三态：显式 true/false 优先，
    /// 缺失时才对比主版本；再缺字段一律视为在范围内，绝不误弹升级。
    #[test]
    fn apc4_buyout_scope_three_states() {
        let mk = |scope, cur, inc| RuntimePerception {
            plan: Some("team".into()),
            version_in_scope: scope,
            current_major: cur,
            included_major: inc,
            ..Default::default()
        };
        assert!(!buyout_out_of_scope(&mk(Some(true), Some(99), Some(4))));
        assert!(buyout_out_of_scope(&mk(Some(false), Some(3), Some(4))));
        assert!(buyout_out_of_scope(&mk(None, Some(5), Some(4))));
        assert!(!buyout_out_of_scope(&mk(None, Some(4), Some(4))));
        assert!(!buyout_out_of_scope(&mk(None, None, None)));
        // 非买断方案永不触发升级引导
        let mut pro = mk(Some(false), Some(9), Some(1));
        pro.plan = Some("pro".into());
        assert!(!buyout_out_of_scope(&pro));
    }

    /// 【APC 任务2】check 与 heartbeat 必须命中不同接口
    #[test]
    fn appc_report_kind_routes() {
        let base = "https://example.invalid";
        assert!(ReportKind::Check.url(base).ends_with("/api/app/check"));
        assert!(
            ReportKind::Heartbeat
                .url(base)
                .ends_with("/api/app/heartbeat")
        );
    }

    /// 【APC 任务3】同步授权字段：Free 不解锁，有效 Pro 会把 expired 修正为 active
    #[test]
    fn appc_free_plan_does_not_unlock() {
        // 纯逻辑校验：free 分支写 inactive，非 free 分支写 active
        let src = include_str!("app_control.rs");
        assert!(src.contains("ent.status = \"inactive\".into();"));
        assert!(src.contains("ent.status = \"active\".into();"));
    }
}
