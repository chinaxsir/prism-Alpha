//! Android VPN 承载桥接：
//!
//! Rust（本模块）→ JNI → Kotlin `PrismVpnBridge`（object）→ `PrismVpnService`
//! （android.net.VpnService）建立系统 VPN 并产出 TUN fd。
//!
//! 反向通道：系统撤销 VPN（VpnService.onRevoke）→ Kotlin 调 JNI 原生方法
//! `nativeVpnRevoked`（本模块注册）→ 前端事件。

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use jni::JNIEnv;
use jni::objects::{JClass, JValue};
use jni::sys::{JNI_VERSION_1_6, jint};
use tauri::{AppHandle, Emitter};

const BRIDGE_CLASS: &str = "com/prism/proxy/PrismVpnBridge";

static JVM: OnceLock<jni::JavaVM> = OnceLock::new();
static APP: OnceLock<AppHandle> = OnceLock::new();

/// cdylib 被 System.loadLibrary 加载时触发：缓存 JavaVM
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm: jni::JavaVM, _: *mut std::ffi::c_void) -> jint {
    let _ = JVM.set(vm);
    JNI_VERSION_1_6
}

fn with_env<T>(f: impl FnOnce(&mut JNIEnv) -> Result<T>) -> Result<T> {
    let vm = JVM
        .get()
        .ok_or_else(|| anyhow!("JavaVM unavailable (JNI_OnLoad not called)"))?;
    let mut guard = vm
        .attach_current_thread_as_daemon()
        .context("attach current thread")?;
    f(&mut guard)
}

/// JNI 调用失败统一清理（apk-1 方案）：Android ART 的 CheckJNI 要求同一线程
/// 的 JNIEnv 先清除挂起异常才能继续调用其他 JNI 函数。Rust 侧 Tokio 工作线程
/// 池会复用线程——任一 JNI 调用返回 Err 后若不清除 Pending Exception，下一次
/// 复用该线程的任意 JNI 调用都会触发 CheckJNI 致命断言（SIGABRT 闪退）。
/// 返回 anyhow::Error（不能是 String：String 未实现 StdError，无法被
/// anyhow 的 `?` 吸收——build #178 的编译错误根因）
fn jni_err(env: &mut JNIEnv, step: &str, err: jni::errors::Error) -> anyhow::Error {
    if env.exception_check().unwrap_or(false) {
        // 将 Java 异常栈输出到 adb logcat 方便排查
        let _ = env.exception_describe();
        // 关键：清除当前线程挂起的 Java 异常
        let _ = env.exception_clear();
    }
    anyhow!("{step}: {err}")
}

/// 平台初始化（Tauri setup 中调用）：注册原生方法 + libbox C 回调
pub fn init(app: AppHandle) -> Result<()> {
    let _ = APP.set(app);

    with_env(|env| {
        let methods = [jni::NativeMethod {
            name: "nativeVpnRevoked".into(),
            sig: "()V".into(),
            fn_ptr: native_vpn_revoked as *mut std::ffi::c_void,
        }];
        env.register_native_methods(BRIDGE_CLASS, &methods)
            .context("register nativeVpnRevoked")?;
        Ok(())
    })?;

    // libbox PlatformInterface 回调：Go 线程 → C → JNI → Kotlin
    crate::core::kernel::mobile_register_vpn_callbacks(
        crate::core::kernel::MobileVpnCallbacks {
            open_tun: cb_open_tun,
            protect_socket: cb_protect,
            under_extension: cb_under_extension,
        },
    );
    Ok(())
}

/// 系统 VPN 授权检查；返回 false 表示需用户在系统弹窗中授权
pub fn ensure_permission() -> Result<bool> {
    with_env(|env| {
        let granted = env
            .call_static_method(BRIDGE_CLASS, "ensurePermission", "()Z", &[])
            .map_err(|e| jni_err(env, "call ensurePermission", e))?
            .z()
            .map_err(|e| anyhow!("ensurePermission ret: {e}"))?;
        Ok(granted)
    })
}

/// 启动前台 VpnService 并等待就绪（libbox 启动前调用）
pub fn start_service_and_wait() -> Result<()> {
    with_env(|env| {
        let ok = env
            .call_static_method(BRIDGE_CLASS, "startServiceAndWait", "()Z", &[])
            .map_err(|e| jni_err(env, "call startServiceAndWait", e))?
            .z()
            .map_err(|e| anyhow!("startServiceAndWait ret: {e}"))?;
        if ok {
            Ok(())
        } else {
            Err(anyhow!("VPN 前台服务未能在 8 秒内就绪"))
        }
    })
}

/// 停止并销毁前台 VpnService（libbox 停止后调用）
pub fn stop_service() {
    let _ = with_env(|env| {
        env.call_static_method(BRIDGE_CLASS, "stopService", "()V", &[])
            .map_err(|e| jni_err(env, "call stopService", e))?;
        Ok(())
    });
}

// ---------------- libbox C 回调（Go 线程触发） ----------------

extern "C" fn cb_open_tun(json: *const c_char) -> c_int {
    if json.is_null() {
        return -1;
    }
    let payload = unsafe { CStr::from_ptr(json) };
    match open_tun(payload.to_string_lossy().as_ref()) {
        Ok(fd) => fd as c_int,
        Err(e) => {
            tracing::error!("open_tun jni failed: {e:#}");
            -1
        }
    }
}

extern "C" fn cb_protect(fd: c_int) -> c_int {
    match protect_socket(fd) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("protect socket failed: {e:#}");
            -1
        }
    }
}

extern "C" fn cb_under_extension() -> c_int {
    0
}

fn open_tun(options_json: &str) -> Result<i32> {
    with_env(|env| {
        let arg = env.new_string(options_json).context("new jstring")?;
        let fd = env
            .call_static_method(
                BRIDGE_CLASS,
                "openTun",
                "(Ljava/lang/String;)I",
                &[JValue::Object(arg.as_ref())],
            )
            .map_err(|e| jni_err(env, "call openTun", e))?
            .i()
            .map_err(|e| anyhow!("openTun ret: {e}"))?;
        if fd < 0 {
            return Err(anyhow!("VpnService.establish() failed (service not foreground?)"));
        }
        Ok(fd)
    })
}

fn protect_socket(fd: c_int) -> Result<()> {
    with_env(|env| {
        let ok = env
            .call_static_method(
                BRIDGE_CLASS,
                "protectSocket",
                "(I)Z",
                &[JValue::Int(fd)],
            )
            .map_err(|e| jni_err(env, "call protectSocket", e))?
            .z()
            .map_err(|e| anyhow!("protectSocket ret: {e}"))?;
        if ok {
            Ok(())
        } else {
            Err(anyhow!("VpnService.protect({fd}) failed"))
        }
    })
}

// ---------------- 系统撤销 VPN ----------------

extern "C" fn native_vpn_revoked(_env: JNIEnv, _class: JClass) {
    tracing::warn!("Android VPN revoked by system");
    if let Some(app) = APP.get() {
        let _ = app.emit("pro://vpn-revoked", ());
    }
}
