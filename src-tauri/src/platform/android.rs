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
use jni::objects::{GlobalRef, JClass, JValue};
use jni::sys::{JNI_VERSION_1_6, jint};
use tauri::{AppHandle, Emitter};

const BRIDGE_CLASS: &str = "com/prism/proxy/PrismVpnBridge";

static JVM: OnceLock<jni::JavaVM> = OnceLock::new();
static APP: OnceLock<AppHandle> = OnceLock::new();

/// PrismVpnBridge 的全局类引用。
///
/// 必须缓存的原因：本模块后续所有 JNI 调用都发生在 Go/libbox 回调线程或
/// Rust 后台线程上，这些线程通过 `attach_current_thread_as_daemon()` 挂接，
/// 其 `FindClass` 走的是系统（Boot）ClassLoader，无法解析应用自带类，
/// 表现为 `ClassNotFoundException: com.prism.proxy.PrismVpnBridge`。
/// 只有在具备应用 ClassLoader 的线程（Tauri setup / 主线程）用 `find_class`
/// 拿到类并转成 `GlobalRef` 后，其它线程才能稳定转发调用。
static BRIDGE: OnceLock<GlobalRef> = OnceLock::new();

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

/// 返回已缓存的 PrismVpnBridge 全局类引用（在 `init()` 中建立）。
fn bridge_class() -> Result<&'static GlobalRef> {
    BRIDGE.get().ok_or_else(|| {
        anyhow!("PrismVpnBridge class ref missing: platform::android::init() 未成功执行")
    })
}

/// JNI 调用返回 Err 时提取并清理当前线程挂起的 Java 异常：
/// 1) 先取出异常对象（Java `Throwable`），再 `exception_describe` 把完整异常栈
///    打到 logcat，随后 `exception_clear` 清除挂起异常——避免下次复用同一线程
///    调用 JNI 时触发 CheckJNI SIGABRT 闪退；
/// 2) 清除后仍可安全地对异常对象调用 `getMessage()`，把真实 Java 报错文本带出，
///    不再只返回模糊的 "Java exception was thrown"。
fn jni_err(env: &mut JNIEnv, step: &str, err: jni::errors::Error) -> String {
    let mut detail: Option<String> = None;
    if env.exception_check().unwrap_or(false) {
        // 先取异常对象（Java Throwable），再打印完整栈到 logcat，随后清除挂起异常
        let throwable = env.exception_occurred().ok();
        let _ = env.exception_describe();
        let _ = env.exception_clear();
        // 清除后仍可对该异常对象调用 getMessage()，取出真实 Java 报错文本
        if let Some(t) = throwable {
            if let Ok(v) = env.call_method(t, "getMessage", "()Ljava/lang/String;", &[]) {
                if let Ok(obj) = v.l() {
                    if !obj.is_null() {
                        if let Ok(s) = env.get_string((&obj).into()) {
                            let m: String = s.into();
                            let m = m.trim().to_string();
                            if !m.is_empty() {
                                detail = Some(m);
                            }
                        }
                    }
                }
            }
        }
    }
    match detail {
        Some(m) => format!("{step}: {m}"),
        None => format!("{step}: {err}"),
    }
}

/// 解析 PrismVpnBridge 类并缓存为全局引用，同时注册原生回调方法。
/// 幂等：桥类引用已存在时直接返回。
///
/// 必须在「携带应用 ClassLoader 的线程」上调用（Kotlin 主线程或 Tauri setup 线程）。
fn cache_bridge(env: &mut JNIEnv) -> Result<()> {
    if BRIDGE.get().is_some() {
        return Ok(());
    }

    let local = match env.find_class(BRIDGE_CLASS) {
        Ok(c) => c,
        Err(e) => return Err(anyhow!(jni_err(env, "find PrismVpnBridge class", e))),
    };
    let global = env
        .new_global_ref(&local)
        .context("cache global ref for PrismVpnBridge")?;
    let _ = BRIDGE.set(global);

    let methods = [jni::NativeMethod {
        name: "nativeVpnRevoked".into(),
        sig: "()V".into(),
        fn_ptr: native_vpn_revoked as *mut std::ffi::c_void,
    }];
    env.register_native_methods(bridge_class()?, &methods)
        .context("register nativeVpnRevoked")?;
    Ok(())
}

/// 导出给 Kotlin 的初始化入口，由 `PrismVpnBridge.attach()` 在 MainActivity
/// 构造期（主线程）调用。此时传入的 JNIEnv 一定携带应用 ClassLoader，
/// 是缓存 GlobalRef 最可靠的时机。
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_prism_proxy_PrismVpnBridge_initNative<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    if let Err(e) = cache_bridge(&mut env) {
        // 不 fatal_error（避免直接 abort 掉 App），只记录到 logcat
        tracing::error!("PrismVpnBridge.initNative failed: {e:#}");
    }
}

/// 平台初始化（Tauri setup 中调用）：注册原生方法 + libbox C 回调
pub fn init(app: AppHandle) -> Result<()> {
    let _ = APP.set(app);

    // 正常情况下 GlobalRef 已由 Kotlin 侧 PrismVpnBridge.attach() → initNative()
    // 在主线程建立；此处兜底一次（attach 未被执行时），同样是具备应用
    // ClassLoader 的线程，避免后台线程 FindClass 失败。
    if BRIDGE.get().is_none() {
        with_env(|env| cache_bridge(env)).context("cache PrismVpnBridge class ref")?;
    }

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
            .call_static_method(bridge_class()?, "ensurePermission", "()Z", &[])
            .map_err(|e| anyhow!(jni_err(env, "call ensurePermission", e)))?
            .z()
            .context("ensurePermission return type")?;
        Ok(granted)
    })
}

/// 启动前台 VpnService 并等待就绪（libbox 启动前调用）
pub fn start_service_and_wait() -> Result<()> {
    with_env(|env| {
        let ok = env
            .call_static_method(bridge_class()?, "startServiceAndWait", "()Z", &[])
            .map_err(|e| anyhow!(jni_err(env, "call startServiceAndWait", e)))?
            .z()
            .context("startServiceAndWait return type")?;
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
        env.call_static_method(bridge_class()?, "stopService", "()V", &[])
            .map_err(|e| anyhow!(jni_err(env, "call stopService", e)))?;
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
                bridge_class()?,
                "openTun",
                "(Ljava/lang/String;)I",
                &[JValue::Object(arg.as_ref())],
            )
            .map_err(|e| anyhow!(jni_err(env, "call openTun", e)))?
            .i()
            .context("openTun return type")?;
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
                bridge_class()?,
                "protectSocket",
                "(I)Z",
                &[JValue::Int(fd)],
            )
            .map_err(|e| anyhow!(jni_err(env, "call protectSocket", e)))?
            .z()
            .context("protectSocket return type")?;
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
