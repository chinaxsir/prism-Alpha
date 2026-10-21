//! 运行时安全自检（仅 Release 生效；Debug 开发环境完全不介入）。
//!
//! 业务代码只需在启动时调用一次 [`init_runtime_guard`]：
//! - iOS：`PT_DENY_ATTACH` 阻止 LLDB / Frida 动态附加（不检测越狱目录，
//!   100% 兼容 TrollStore 巨魔安装环境）；
//! - Android：检查 `/proc/self/status` 的 `TracerPid`，非 0 视为被动态调试；
//! - 全平台：内存授权状态附带基于进程随机会话密钥的签名，防止内存修改器
//!   把 `expired` 强行改回 `active`（签名不符即判定环境受损，Pro 一律锁定）。

use std::sync::atomic::{AtomicBool, Ordering};

/// 运行环境是否已被判定为受损（调试器附加 / 内存篡改签名不符）
static COMPROMISED: AtomicBool = AtomicBool::new(false);

/// 进程级随机会话密钥（仅内存，启动时生成，不落盘）
static SESSION_SECRET: std::sync::OnceLock<[u8; 16]> = std::sync::OnceLock::new();

/// 启动时调用一次：Release 下开启原生反调试，Debug 下为空操作。
pub fn init_runtime_guard() {
    #[cfg(all(not(debug_assertions), target_os = "ios"))]
    deny_attach();

    #[cfg(all(not(debug_assertions), target_os = "android"))]
    if tracer_pid() != 0 {
        mark_compromised("tracer");
    }
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

fn session_secret() -> &'static [u8; 16] {
    SESSION_SECRET.get_or_init(|| *uuid::Uuid::new_v4().as_bytes())
}

/// 授权状态签名：绑定 status / expires_at / last_verified_at 与会话密钥。
/// 内存修改器改 status 后签名不再匹配，`is_pro_active()` 随即返回 false。
pub fn entitlement_signature(
    status: &str,
    expires_at: Option<i64>,
    last_verified_at: i64,
) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in session_secret().iter().chain(status.as_bytes()) {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for v in [expires_at.unwrap_or(i64::MIN), last_verified_at] {
        for b in v.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

/// iOS：PT_DENY_ATTACH 阻止调试器附加（系统调用号在 Darwin 上恒为 31）。
#[cfg(all(not(debug_assertions), target_os = "ios"))]
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

/// Android：读取 /proc/self/status 的 TracerPid（非 0 = 有调试器附加）。
#[cfg(all(not(debug_assertions), target_os = "android"))]
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
