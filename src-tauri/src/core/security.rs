//! 运行时安全自检与防篡改防线（仅 Release 生效；Debug 开发环境完全不介入）。
//!
//! 业务代码只需：
//! 1. 启动时调用一次 [`init_runtime_guard`]；
//! 2. 在既有巡检协程中低频调用 [`periodic_integrity_check`]（前台每 30 秒，零额外线程）：
//! - iOS / macOS：`PT_DENY_ATTACH` + `sysctl(P_TRACED)` 内核调试标志检测 +
//!   dyld 注入库检测（仅匹配显式逆向攻击工具 `frida`/`cycript`/`SSLKillSwitch`/
//!   `RevealServer`/`libdebugserver`，绝不误伤 TrollStore 或系统组件）；
//! - Android / Linux：`/proc/self/status` `TracerPid` + `/proc/self/maps` 活跃 Frida
//!   注入扫描 + Android 启动期 Frida 默认端口检测；
//! - Windows：`IsDebuggerPresent` 检测；
//! - 全平台：内存授权状态采用 32 字节 `OsRng` 随机会话密钥 + SHA-256 签名，
//!   同时绑定 `status / plan / expires_at / last_verified_at / sync_available / alpha`，
//!   防止内存修改器篡改任意授权字段（签名不符即判定环境受损，Pro 立即熔断锁定）。

use std::sync::atomic::{AtomicBool, Ordering};

use rand::RngCore;
use sha2::{Digest, Sha256};

/// 运行环境是否已被判定为受损（调试器附加 / 动态注入 / 内存篡改签名不符）
static COMPROMISED: AtomicBool = AtomicBool::new(false);

/// 进程级 256-bit 随机会话密钥（仅内存，启动时由 OsRng 生成，绝不落盘）
static SESSION_SECRET: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();

/// 启动时调用一次：Release 下开启原生反调试与反注入检测，Debug 下为空操作。
pub fn init_runtime_guard() {
    #[cfg(all(not(debug_assertions), any(target_os = "ios", target_os = "macos")))]
    {
        deny_attach();
        if is_darwin_traced() {
            mark_compromised("darwin-traced");
        }
        if has_suspicious_darwin_dylib() {
            mark_compromised("darwin-inject");
        }
    }

    #[cfg(all(not(debug_assertions), any(target_os = "android", target_os = "linux")))]
    {
        if tracer_pid() != 0 {
            mark_compromised("tracer");
        }
        if has_suspicious_proc_maps() {
            mark_compromised("inject-maps");
        }
        #[cfg(target_os = "android")]
        if frida_default_port_open() {
            mark_compromised("frida");
        }
    }

    #[cfg(all(not(debug_assertions), target_os = "windows"))]
    {
        if is_windows_debugger_present() {
            mark_compromised("win-debugger");
        }
    }
}

/// 运行期低频完整性复核（由 lib.rs 既有巡检循环在前台每 30 秒调用一次，零额外唤醒）。
/// 拦截「启动后再附加调试器 / 动态注入 Frida」的二次攻击；Debug 下为空操作。
pub fn periodic_integrity_check() -> bool {
    #[cfg(not(debug_assertions))]
    {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            if is_darwin_traced() {
                mark_compromised("darwin-traced-rt");
            }
            if has_suspicious_darwin_dylib() {
                mark_compromised("darwin-inject-rt");
            }
        }
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            if tracer_pid() != 0 {
                mark_compromised("tracer-rt");
            }
            if has_suspicious_proc_maps() {
                mark_compromised("inject-maps-rt");
            }
        }
        #[cfg(target_os = "windows")]
        {
            if is_windows_debugger_present() {
                mark_compromised("win-debugger-rt");
            }
        }
    }
    is_compromised()
}

/// 是否已判定环境受损：为 true 时所有 Pro 功能一律锁定。
pub fn is_compromised() -> bool {
    COMPROMISED.load(Ordering::Relaxed)
}

/// 标记环境受损（只在首次打印日志，避免巡检刷屏）
pub fn mark_compromised(reason: &str) {
    if !COMPROMISED.swap(true, Ordering::Relaxed) {
        tracing::warn!("security: runtime compromised ({reason})");
    }
}

fn session_secret() -> &'static [u8; 32] {
    SESSION_SECRET.get_or_init(|| {
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf
    })
}

/// 授权状态 SHA-256 会话签名：全字段绑定 status / plan / expires_at /
/// last_verified_at / sync_available / alpha 与 256-bit 进程随机会话密钥。
/// 内存修改器篡改任意字段后签名立即失配，`is_pro_active()` 熔断返回 false。
pub fn entitlement_signature(
    status: &str,
    plan: Option<&str>,
    expires_at: Option<i64>,
    last_verified_at: i64,
    sync_available: bool,
    alpha: bool,
) -> [u8; 32] {
    let secret = session_secret();
    let mut h = Sha256::new();
    h.update(secret);
    h.update(b"|st:");
    h.update(status.as_bytes());
    h.update(b"|pl:");
    h.update(plan.unwrap_or("").as_bytes());
    h.update(b"|ex:");
    h.update(expires_at.unwrap_or(i64::MIN).to_le_bytes());
    h.update(b"|lv:");
    h.update(last_verified_at.to_le_bytes());
    h.update([u8::from(sync_available), u8::from(alpha)]);
    h.update(secret);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// iOS / macOS：PT_DENY_ATTACH 阻止调试器附加（系统调用号在 Darwin 上恒为 31）。
#[cfg(all(not(debug_assertions), any(target_os = "ios", target_os = "macos")))]
fn deny_attach() {
    const PT_DENY_ATTACH: std::ffi::c_int = 31;
    unsafe extern "C" {
        fn ptrace(
            request: std::ffi::c_int,
            pid: std::ffi::c_int,
            addr: *mut std::ffi::c_void,
            data: *mut std::ffi::c_void,
        ) -> std::ffi::c_int;
    }
    // SAFETY: 参数为文档规定的固定值，失败也仅是内核忽略该请求
    unsafe {
        ptrace(
            PT_DENY_ATTACH,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}

/// iOS / macOS：通过内核 sysctl 读取当前进程 kinfo_proc.kp_proc.p_flag 的 P_TRACED (0x800)。
/// 即便 ptrace 被 hook 绕过，内核进程标志仍会暴露调试器附加状态；100% 兼容 TrollStore。
#[cfg(all(not(debug_assertions), any(target_os = "ios", target_os = "macos")))]
fn is_darwin_traced() -> bool {
    const CTL_KERN: libc::c_int = 1;
    const KERN_PROC: libc::c_int = 14;
    const KERN_PROC_PID: libc::c_int = 1;
    const P_TRACED: i32 = 0x0000_0800;
    // 64-bit Darwin (arm64/x86_64) kinfo_proc 固定为 648 字节，kp_proc.p_flag 位于偏移 32
    let mut buf = [0u8; 648];
    let mut size = buf.len();
    let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, unsafe { libc::getpid() }];
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size < 36 {
        return false;
    }
    let p_flag = i32::from_ne_bytes([buf[32], buf[33], buf[34], buf[35]]);
    (p_flag & P_TRACED) != 0
}

/// iOS / macOS：扫描已加载动态库，仅拦截显式逆向/Hook/抓包破解框架
/// （不检测越狱路径或常规系统框架，确保 TrollStore 环境零误报）。
#[cfg(all(not(debug_assertions), any(target_os = "ios", target_os = "macos")))]
fn has_suspicious_darwin_dylib() -> bool {
    unsafe extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_name(image_index: u32) -> *const std::ffi::c_char;
    }
    const NEEDLES: [&str; 6] = [
        "fridagadget",
        "frida-agent",
        "cycript",
        "sslkillswitch",
        "revealserver",
        "libdebugserver",
    ];
    let count = unsafe { _dyld_image_count() };
    for i in 0..count {
        let ptr = unsafe { _dyld_get_image_name(i) };
        if ptr.is_null() {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_string_lossy()
            .to_ascii_lowercase();
        if NEEDLES.iter().any(|n| name.contains(n)) {
            return true;
        }
    }
    false
}

/// Android / Linux：读取 /proc/self/status 的 TracerPid（非 0 = 有调试器附加）。
#[cfg(all(not(debug_assertions), any(target_os = "android", target_os = "linux")))]
fn tracer_pid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("TracerPid:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0)
}

/// Android / Linux：检查 /proc/self/maps 是否被注入 Frida 引擎。
#[cfg(all(not(debug_assertions), any(target_os = "android", target_os = "linux")))]
fn has_suspicious_proc_maps() -> bool {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return false;
    };
    let lower = maps.to_ascii_lowercase();
    ["frida-agent", "frida-gadget", "libfrida", "gum-js-loop"]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// 【APP59 任务3.2】Frida 默认端口（27042 / 27043）本机可达性检查。
#[cfg(all(not(debug_assertions), target_os = "android"))]
fn frida_default_port_open() -> bool {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    [27042u16, 27043u16].iter().any(|port| {
        TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], *port)),
            Duration::from_millis(50),
        )
        .is_ok()
    })
}

/// Windows：检测用户态调试器附加。
#[cfg(all(not(debug_assertions), target_os = "windows"))]
fn is_windows_debugger_present() -> bool {
    unsafe extern "system" {
        fn IsDebuggerPresent() -> i32;
    }
    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entitlement_signature_binds_all_privilege_fields() {
        let base = entitlement_signature("active", Some("pro"), Some(1_900_000_000), 1_800_000_000, true, false);
        assert_eq!(
            base,
            entitlement_signature("active", Some("pro"), Some(1_900_000_000), 1_800_000_000, true, false)
        );
        assert_ne!(
            base,
            entitlement_signature("expired", Some("pro"), Some(1_900_000_000), 1_800_000_000, true, false)
        );
        assert_ne!(
            base,
            entitlement_signature("active", Some("team"), Some(1_900_000_000), 1_800_000_000, true, false)
        );
        assert_ne!(
            base,
            entitlement_signature("active", Some("pro"), None, 1_800_000_000, true, false)
        );
        assert_ne!(
            base,
            entitlement_signature("active", Some("pro"), Some(1_900_000_000), 1_800_000_000, false, false)
        );
        assert_ne!(
            base,
            entitlement_signature("active", Some("pro"), Some(1_900_000_000), 1_800_000_000, true, true)
        );
    }
}
