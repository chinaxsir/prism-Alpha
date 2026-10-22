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

/// 权威 runtime 感知对象（APP-7 任务2.2 §1.3）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimePerception {
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub subscription_active: bool,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub max_seats: Option<u32>,
    /// true=已绑定, false=已被官网解绑, null=请求未传 device_id（旧版）
    pub device_bound: Option<bool>,
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

/// reason 的白名单兜底：服务端返回未知 reason 时按 version_blocked 处理
const REASON_VERSION: &str = "version_blocked";
const REASON_USER: &str = "user_blocked";

fn default_message(reason: &str) -> String {
    if reason == REASON_USER {
        "当前授权账号已被限制使用，如有疑问请联系客服工单。".to_string()
    } else {
        "当前 APP 版本已停止支持，请前往 https://prism.sarl 下载更新最新版本后继续使用。"
            .to_string()
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
    let runtime: RuntimePerception =
        serde_json::from_value(v.get("runtime")?.clone()).ok()?;
    let saved_at = v.get("saved_at").and_then(|v| v.as_i64()).unwrap_or(0);
    Some((runtime, saved_at))
}

// ---------------- apply_runtime：授权级熔断 ----------------

/// 根据权威 runtime 执行授权级熔断（APP-7 任务2.2 §3）。
/// 与管控级阻断（allowed=false）独立——两者可能同时返回，各做各的事。
pub fn apply_runtime(
    app: &AppHandle,
    state: &AppState,
    data_dir: &std::path::Path,
    runtime: &RuntimePerception,
) -> Option<(bool, String)> {
    persist_runtime(data_dir, runtime);

    let is_unbound = runtime.device_bound == Some(false);
    let is_expired =
        !runtime.subscription_active && runtime.plan.as_deref() != Some("team");
    let pro_revoked = is_unbound || is_expired || runtime.plan.is_none();

    if !pro_revoked {
        sync_entitlement_from_runtime(state, runtime);
        return None;
    }

    let was_active = state
        .entitlement
        .read()
        .status
        .eq_ignore_ascii_case("active");
    if !was_active {
        let msg = if is_unbound {
            "此设备已从您的账户解绑。如需继续使用 Pro 功能，请在官网重新激活。"
        } else if is_expired {
            "订阅已过期。续费后 Pro 功能将自动恢复。"
        } else {
            "Pro 授权已失效。"
        };
        let _ = app.emit(
            "pro://revoked",
            &serde_json::json!({
                "reason": "runtime",
                "message": msg,
                "unbound": is_unbound,
                "expired": is_expired,
            }),
        );
        return Some((true, msg.to_string()));
    }

    let entitlement = if is_unbound {
        license::deactivate(data_dir)
    } else {
        license::mark_expired(data_dir).unwrap_or_else(EntitlementStatus::inactive)
    };

    state.apply_entitlement(entitlement.clone());
    disable_pro_switches(state);

    let msg = if is_unbound {
        "此设备已从您的账户解绑。如需继续使用 Pro 功能，请在官网重新激活。"
    } else {
        "订阅已过期。续费后 Pro 功能将自动恢复。"
    };

    let _ = app.emit(
        "pro://revoked",
        &serde_json::json!({
            "reason": "runtime",
            "message": msg,
            "unbound": is_unbound,
            "expired": is_expired,
            "entitlement": entitlement,
        }),
    );

    if *state.status.read() == CoreStatus::Running {
        tracing::info!(
            "[runtime] Pro 授权被剥夺（unbound={is_unbound}, expired={is_expired}），关闭所有 Pro 开关，保留基础 VPN"
        );
    }

    Some((true, msg.to_string()))
}

fn sync_entitlement_from_runtime(state: &AppState, runtime: &RuntimePerception) {
    let mut ent = state.entitlement.read().clone();
    let Some(plan) = runtime.plan.clone() else {
        return;
    };
    ent.plan = Some(plan.clone());
    ent.kind = Some(if plan == "team" { "lifetime" } else { "subscription" }.into());
    ent.max_seats = runtime.max_seats;
    if let Some(exp_str) = runtime.expires_at.as_deref()
        && let Some(exp) = license::parse_expires_at(exp_str)
    {
        ent.expires_at = Some(exp);
    }
    ent.last_verified_at = license::now_secs();
    state.apply_entitlement(ent);
}

/// 关闭所有 Pro 专属开关（Go AIM / Go Lan / Go Cus）
fn disable_pro_switches(state: &AppState) {
    let mut settings = state.settings.read().clone();
    settings.go_aim_enabled = false;
    let _ = state.save_settings(settings);

    let mut lan = state.go_lan.read().clone();
    lan.enabled = false;
    *state.go_lan.write() = lan;
    let mut cus = state.go_cus.read().clone();
    cus.enabled = false;
    *state.go_cus.write() = cus;

    *state.aim_locked_node.write() = None;
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
        let version =
            sysctl_string(b"kern.osproductversion").unwrap_or_else(|| "unknown".into());
        let prefix = if cfg!(target_os = "ios") { "iOS " } else { "macOS " };
        (model, format!("{prefix}{version}"))
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
unsafe fn sysctl_string(name: &[u8]) -> Option<String> {
    let mut size: libc::size_t = 0;
    let cname = std::ffi::CString::new(name).ok()?;
    if libc::sysctlbyname(cname.as_ptr(), std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0)
        != 0
    {
        return None;
    }
    let mut buf = vec![0u8; size];
    if libc::sysctlbyname(
        cname.as_ptr(),
        buf.as_mut_ptr() as *mut libc::c_void,
        &mut size,
        std::ptr::null_mut(),
        0,
    ) != 0
    {
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
            // __system_property_get 缓冲区按 c_char（u8）对齐，92 字节为
            // PROP_VALUE_MAX 的安全冗余
            let mut buf = [0u8; 92];
            let cname = match std::ffi::CString::new(key) {
                Ok(c) => c,
                Err(_) => return String::new(),
            };
            if libc::__system_property_get(cname.as_ptr(), buf.as_mut_ptr()) == 0 {
                return String::new();
            }
            CStr::from_ptr(buf.as_ptr().cast())
                .to_string_lossy()
                .into_owned()
        };
        let release = prop(b"ro.build.version.release");
        let manufacturer = prop(b"ro.product.manufacturer");
        let model = prop(b"ro.product.model");
        let model = if model.is_empty() { manufacturer } else { model };
        (
            if model.is_empty() { "Android".into() } else { model },
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

/// 执行一次 check/心跳上报并应用结果（fail-open：仅 allowed=false 才有管控动作）。
/// APP-7 新增：runtime 授权级熔断（解绑/过期/plan 缺失）。
pub(crate) async fn report_once(app: &AppHandle, state: &AppState) {
    let settings = state.settings.read().clone();
    let base = super::license::api_base(&settings);
    let url = format!("{base}{}", crate::obf!("/api/app/check"));
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
        .timeout(std::time::Duration::from_secs(8))
        .build();
    let resp = match client {
        Ok(c) => c.post(&url).json(&payload).send().await,
        Err(e) => {
            warn!("app-control: client build failed: {e}");
            return;
        }
    };
    let parsed: Option<ControlResponse> = match resp {
        Ok(r) if r.status().is_success() => r.json().await.ok(),
        Ok(r) => {
            warn!("app-control: check returned HTTP {}", r.status());
            return;
        }
        Err(e) => {
            warn!("app-control: check failed (fail-open): {e}");
            return;
        }
    };
    let Some(resp) = parsed else {
        return;
    };

    // 1. 授权级熔断（runtime 存在时执行；缺字段时旧版兼容不降级）
    if let Some(runtime) = resp.runtime.as_ref() {
        apply_runtime(app, state, &state.data_dir, runtime);
    }

    // 2. 管控级阻断（allowed=false）
    if resp.allowed {
        // 已解除管控（或从未管控）：清状态并广播
        if state.control_block.read().is_some() {
            *state.control_block.write() = None;
            let _ = app.emit(
                "app://control",
                &serde_json::json!({
                    "allowed": true,
                    "reason": resp.reason,
                    "message": resp.message,
                }),
            );
        }
        return;
    }

    let reason = if resp.reason == REASON_USER {
        REASON_USER.to_string()
    } else {
        REASON_VERSION.to_string()
    };
    let message = if resp.message.trim().is_empty() {
        default_message(&reason)
    } else {
        resp.message.clone()
    };

    // 已处于阻断且 reason/message 均未变化：跳过重复广播（心跳每 5 分钟一次）
    let changed = {
        let cur = state.control_block.read();
        match cur.as_ref() {
            Some(b) => b.reason != reason || b.message != message,
            None => true,
        }
    };

    // 阻断生效：停止运行中的内核（连接会话必须立即终止）
    if *state.status.read() == CoreStatus::Running {
        if let Err(e) = crate::ipc::commands::do_stop(state).await {
            warn!("app-control: stop kernel failed: {e}");
        }
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
}

/// 启动单次上报：立即执行一次（不等首个心跳周期）
pub fn spawn_startup_check(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        report_once(&app, &state).await;
    });
}

/// 心跳循环：启动上报完成后每 5 分钟（300 秒，服务端约定的最小间隔）一次
pub fn spawn_heartbeat(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            let state = app.state::<AppState>();
            report_once(&app, &state).await;
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
    let install_id = license::get_or_create_install_id(&state.data_dir)
        .map_err(|e| sanitize(&e.to_string()))?;

    let payload = AppCheckRequest {
        platform: platform_name().into(),
        device_model,
        os_version,
        app_version: env!("CARGO_PKG_VERSION").into(),
        license_key: super::license::get_saved_license_key(&state.data_dir),
        install_id,
        device_id: device_id_str,
    };

    let resp = license::post_with_fallback(&url, &serde_json::json!(payload))
        .await
        .map_err(|e| sanitize(&e.to_string()))?;

    if !resp.status().is_success() {
        return Err(format!(
            "授权服务返回 HTTP {}，无法完成权威校验",
            resp.status()
        ));
    }
    let parsed: ControlResponse = resp.json().await.map_err(|e| sanitize(&e.to_string()))?;

    // 管控级阻断
    if !parsed.allowed {
        return Err(format!(
            "授权服务管控阻断（{}）：{}",
            parsed.reason, parsed.message
        ));
    }

    // 授权级熔断
    let (ent, revoke_msg) = if let Some(runtime) = parsed.runtime.as_ref() {
        persist_runtime(&state.data_dir, runtime);
        let is_unbound = runtime.device_bound == Some(false);
        let is_expired = !runtime.subscription_active
            && runtime.plan.as_deref() != Some("team");
        if is_unbound || is_expired || runtime.plan.is_none() {
            let msg = if is_unbound {
                license::deactivate(&state.data_dir);
                "此设备已从您的账户解绑。如需继续使用 Pro 功能，请在官网重新激活。"
                    .to_string()
            } else {
                license::mark_expired(&state.data_dir)
                    .unwrap_or_else(EntitlementStatus::inactive);
                "订阅已过期。续费后 Pro 功能将自动恢复。".to_string()
            };
            let ent = license::cached_entitlement(&state.data_dir);
            (ent, Some(msg))
        } else {
            let mut ent = state.entitlement.read().clone();
            if let Some(plan) = runtime.plan.as_ref() {
                ent.plan = Some(plan.clone());
                ent.kind = Some(
                    if plan == "team" {
                        "lifetime"
                    } else {
                        "subscription"
                    }
                    .into(),
                );
            }
            ent.max_seats = runtime.max_seats;
            if let Some(exp_str) = runtime.expires_at.as_deref()
                && let Some(exp) = license::parse_expires_at(exp_str)
            {
                ent.expires_at = Some(exp);
            }
            ent.last_verified_at = license::now_secs();
            (ent, None)
        }
    } else {
        // 服务端 runtime 缺失 → 回落到旧的 GET /api/license/status 兼容路径
        match license::verify_remote_forced(&state.data_dir, &settings).await {
            Ok(ent) => (ent, None),
            Err(e) => return Err(sanitize(&e.to_string())),
        }
    };

    state.apply_entitlement(ent.clone());
    Ok((ent, revoke_msg))
}

fn sanitize(s: &str) -> String {
    if s.len() > 200 {
        s.chars().take(200).collect()
    } else {
        s.to_string()
    }
}

// ---------------- 前台唤醒自动感知 ----------------

/// App 从后台回前台（visibility changed visible）且距离上次 check/heartbeat
/// 超过 30 秒时，立即触发一次后台 heartbeat 校验——用户在浏览器解绑设备后
/// 切回 APP 瞬间就能自动感知并弹出横幅提示，无需手动点按钮。
pub fn schedule_foreground_check(
    app: AppHandle,
    last_check_ts: std::sync::Arc<std::sync::atomic::AtomicI64>,
) {
    tauri::async_runtime::spawn(async move {
        let now = license::now_secs();
        let last = last_check_ts.load(std::sync::atomic::Ordering::Acquire);
        if last > 0 && now - last < 30 {
            return;
        }
        last_check_ts.store(now, std::sync::atomic::Ordering::Release);
        let state = app.state::<AppState>();
        report_once(&app, &state).await;
    });
}
