//! APP 远程管控（app-control-api.md）：启动单次上报 + 每 5 分钟心跳。
//!
//! 服务端 `/api/app/check` 返回 `{ allowed, reason, message }`：
//! - `allowed=true`（或任何网络失败）：**fail-open**——完全不影响 APP 使用，
//!   静默忽略。服务管控绝不能把断网/服务器故障的用户挡在外面。
//! - `allowed=false`：立即停止运行中的 VPN 内核、阻止 start_core，
//!   并向前端广播 `app://control` 展示全屏不可关闭提示框。
//!
//! 请求体仅携带非敏感元数据（平台 / 机型 / 系统版本 / APP 版本 /
//! License Key），绝不包含任何用户流量内容或地址信息。

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use tracing::warn;

use super::state::AppState;

/// check 响应
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ControlResponse {
    pub allowed: bool,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub message: String,
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

/// 执行一次 check/心跳上报并应用结果（fail-open：仅 allowed=false 才有动作）
async fn report_once(app: &AppHandle, state: &AppState) {
    let settings = state.settings.read().clone();
    let base = super::license::api_base(&settings);
    let url = format!("{base}{}", crate::obf!("/api/app/check"));
    let (device_model, os_version) = device_info();
    let payload = serde_json::json!({
        "platform": platform_name(),
        "device_model": device_model,
        "os_version": os_version,
        "app_version": env!("CARGO_PKG_VERSION"),
        "license_key": super::license::get_saved_license_key(&state.data_dir),
    });

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
            // 非 2xx（限流/鉴权失败/服务器错误）一律 fail-open
            warn!("app-control: check returned HTTP {}", r.status());
            return;
        }
        Err(e) => {
            // 网络失败 fail-open：断网/服务器不可达绝不阻断用户
            warn!("app-control: check failed (fail-open): {e}");
            return;
        }
    };
    let Some(resp) = parsed else { return };

    if resp.allowed {
        // 已解除管控（或从未管控）：清状态并广播，前端收到后撤下阻断框
        if state.control_block.read().is_some() {
            *state.control_block.write() = None;
            let _ = app.emit("app://control", &serde_json::json!({
                "allowed": true,
                "reason": resp.reason,
                "message": resp.message,
            }));
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
    if *state.status.read() == super::state::CoreStatus::Running {
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
