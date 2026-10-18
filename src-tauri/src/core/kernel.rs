//! Go 代理内核封装
//!
//! 通信策略：将 sing-box 编译为独立 sidecar 二进制，Rust 通过本地 HTTP API
//! (默认 127.0.0.1:9090，占用时动态选择) 与其通信，并订阅其 WebSocket 数据流。
//!
//! 注意：sing-box 只接受 **JSON** 配置，运行时配置必须写入 config.json。

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
#[cfg(not(any(target_os = "ios", target_os = "android")))]
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
#[cfg(not(any(target_os = "ios", target_os = "android")))]
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Child;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
use tokio::process::Command;
use tokio::task::JoinHandle;

/// 首选 external-controller 地址；被占用时会退回到系统分配的随机端口
pub const PREFERRED_API_ADDR: &str = "127.0.0.1:9090";

/// 内核报错脱敏：任何返回前端 / 用户可见的错误文本，统一把底层
/// 内核商标字样（sing-box / libbox 等大小写变体）替换为「内核」，
/// 防止二进制或库自带报错直接露出内核名称。
pub fn sanitize_kernel_error(msg: &str) -> String {
    let mut out = msg.to_string();
    for pat in ["sing-box", "Sing-Box", "SING-BOX", "singbox", "SingBox", "libbox"] {
        out = out.replace(pat, "内核");
    }
    out
}

/// iOS/Android 内嵌内核版本（与 ios-kernel/go.mod 的 sing-box 依赖保持一致）
#[cfg(any(target_os = "ios", target_os = "android"))]
pub const EMBEDDED_VERSION: &str = "1.11.3";

/// iOS/Android 内嵌内核 FFI（sing-box c-archive，见 src-tauri/ios-kernel/）。
///
/// 移动端真正的系统级代理：libbox BoxService 启动时回调
/// PlatformInterface.OpenTun，由宿主原生层建立系统 VPN 并返回 TUN fd。
/// Android 上宿主是本进程 Kotlin VpnService（经 Rust 注册 C 回调）；
/// iOS 上内核运行于独立的 NEPacketTunnelProvider 扩展，回调由 Swift 注册，
/// Rust 侧仅在启动隧道前用到 PrismKernelCheck。
#[cfg(any(target_os = "ios", target_os = "android"))]
mod mobile_ffi {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_int};
    use std::path::Path;

    /// libbox PlatformInterface 回调表（Go vpn.go 的 prism_vpn_cbs）
    #[repr(C)]
    pub struct VpnCallbacks {
        pub open_tun: extern "C" fn(*const c_char) -> c_int,
        pub protect_socket: extern "C" fn(c_int) -> c_int,
        pub under_extension: extern "C" fn() -> c_int,
    }

    // edition 2024：extern 块必须声明为 unsafe（内部函数调用仍需 unsafe {}）
    unsafe extern "C" {
        fn PrismKernelCheck(config_path: *const c_char, work_dir: *const c_char) -> *mut c_char;
        fn PrismKernelFree(p: *mut c_char);
        fn PrismVPNSetCallbacks(callbacks: VpnCallbacks);
        fn PrismVPNStart(config_content: *const c_char, work_dir: *const c_char) -> *mut c_char;
        fn PrismVPNStop();
    }

    pub fn check(config_path: &Path, work_dir: &Path) -> Result<(), String> {
        let cp = CString::new(config_path.to_string_lossy().as_bytes()).map_err(|e| e.to_string())?;
        let wd = CString::new(work_dir.to_string_lossy().as_bytes()).map_err(|e| e.to_string())?;
        unsafe {
            let err = PrismKernelCheck(cp.as_ptr(), wd.as_ptr());
            if !err.is_null() {
                let msg = CStr::from_ptr(err).to_string_lossy().into_owned();
                PrismKernelFree(err);
                return Err(msg);
            }
        }
        Ok(())
    }

    /// 注册 PlatformInterface C 回调（Android：由平台初始化调用一次）
    pub fn set_vpn_callbacks(callbacks: VpnCallbacks) {
        unsafe { PrismVPNSetCallbacks(callbacks) }
    }

    /// 启动 libbox VPN 承载（Android：进程内直接执行）
    pub fn vpn_start(config_content: &str, work_dir: &Path) -> Result<(), String> {
        let cc = CString::new(config_content).map_err(|e| e.to_string())?;
        let wd = CString::new(work_dir.to_string_lossy().as_bytes()).map_err(|e| e.to_string())?;
        unsafe {
            let err = PrismVPNStart(cc.as_ptr(), wd.as_ptr());
            if !err.is_null() {
                let msg = CStr::from_ptr(err).to_string_lossy().into_owned();
                PrismKernelFree(err);
                return Err(msg);
            }
        }
        Ok(())
    }

    pub fn vpn_stop() {
        unsafe { PrismVPNStop() }
    }
}

/// Android 平台经此向 libbox 注册 PlatformInterface 回调
#[cfg(target_os = "android")]
pub(crate) type MobileVpnCallbacks = mobile_ffi::VpnCallbacks;

#[cfg(target_os = "android")]
pub(crate) fn mobile_register_vpn_callbacks(callbacks: mobile_ffi::VpnCallbacks) {
    mobile_ffi::set_vpn_callbacks(callbacks);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KernelConfig {
    /// sidecar 内核二进制路径
    pub binary_path: PathBuf,
    /// 工作目录（存放 config.json / 缓存 / kernel.log）
    pub work_dir: PathBuf,
    /// external-controller 监听地址
    pub api_addr: String,
    /// clash_api 鉴权密钥（写入配置 + 所有请求/WS 带 Bearer 头）
    pub api_secret: String,
    /// 生成的 sing-box 运行时配置（JSON）
    pub runtime_config: serde_json::Value,
}

pub struct KernelHandle {
    pub config: KernelConfig,
    /// sidecar 子进程句柄（停止时取出并等待退出）
    child: Mutex<Option<Child>>,
    /// 子进程 pid
    pub pid: u32,
    /// 内核事件流任务（停止内核时 abort，避免重连任务泄漏导致事件翻倍）
    stream_tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl KernelHandle {
    /// 启动内核 sidecar 进程
    pub async fn spawn(config: KernelConfig, app_handle: AppHandle) -> Result<Self> {
        // 1. 写入运行时配置（sing-box 只解析 JSON）
        std::fs::create_dir_all(&config.work_dir)
            .context("failed to create kernel work dir")?;
        let config_path = config.work_dir.join("config.json");
        let config_bytes = serde_json::to_vec_pretty(&config.runtime_config)
            .context("failed to serialize kernel config")?;
        std::fs::write(&config_path, &config_bytes)
            .context("failed to write kernel config.json")?;

        // 2. 清空旧内核日志，接管子进程 stdout/stderr（Go 日志默认写 stderr）
        let log_path = config.work_dir.join("kernel.log");
        std::fs::write(&log_path, b"").ok();

        // 2.5 确保 geoip.db / geosite.db 就位：legacy geoip/geosite 规则需要本地
        // 数据库，缺失时 sing-box 会走代理出站下载（启动期代理未就绪，必失败）。
        // 数据库随包分发（见 scripts/fetch-kernel.cjs），这里从候选位置拷贝到工作目录。
        // 原则：任何必需文件缺失都直接报错，绝不允许内核运行时联网下载
        ensure_geo_databases(&config, &app_handle)?;

        // 3. 启动内核：
        //   Android —— libbox 进程内启动（Go 回调 → Rust → Kotlin VpnService 建立 VPN）
        //   iOS     —— 请求 NEPacketTunnelProvider 扩展启动（Swift 控制，内核在扩展内）
        //   其他平台 —— spawn sidecar 进程
        #[cfg(target_os = "android")]
        let (child, pid): (Option<Child>, u32) = {
            let content = std::str::from_utf8(&config_bytes)
                .map_err(|e| anyhow::anyhow!("内核配置编码错误: {e}"))?;
            // 先建立前台 VpnService，libbox 才能经回调拿到 TUN fd
            crate::platform::android::start_service_and_wait()
                .map_err(|e| anyhow::anyhow!("VPN 服务启动失败: {e}"))?;
            mobile_ffi::vpn_start(content, &config.work_dir)
                .map_err(|e| anyhow::anyhow!("VPN 启动失败: {e}"))?;
            tracing::info!("sing-box libbox VPN started in-process");
            (None, std::process::id())
        };
        #[cfg(target_os = "ios")]
        let (child, pid): (Option<Child>, u32) = {
            let content = std::str::from_utf8(&config_bytes)
                .map_err(|e| anyhow::anyhow!("内核配置编码错误: {e}"))?
                .to_owned();
            // start_tunnel 内部用 semaphore 等待扩展进程建立隧道（可阻塞
            // 数秒）。Tauri 的 async command 跑在 Tokio worker 上，同步
            // 阻塞会卡死整个 worker 池——前端所有 IPC（状态轮询、切页、
            // UI 事件）全部无响应，"正在启动"状态丢失（build 144 方案）
            tokio::task::spawn_blocking(move || crate::platform::ios::start_tunnel(&content))
                .await
                .map_err(|e| anyhow::anyhow!("VPN 启动任务异常退出: {e}"))?
                .map_err(|e| anyhow::anyhow!("VPN 启动失败: {e}"))?;
            tracing::info!("iOS packet tunnel extension start requested");
            (None, std::process::id())
        };
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        let (child, pid): (Option<Child>, u32) = {
            let mut cmd = Command::new(&config.binary_path);
            cmd.arg("run")
                .arg("-c")
                .arg(&config_path)
                .env("ENABLE_DEPRECATED_GEOIP", "true")
                .env("ENABLE_DEPRECATED_GEOSITE", "true")
                // 固定工作目录：sing-box 在此读写 geoip.db / geosite.db / cache.db
                .current_dir(&config.work_dir)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            // Windows：sing-box 是控制台程序，默认会弹出黑色命令行窗口。
            // CREATE_NO_WINDOW 让内核进程不分配控制台，主进程保持 UI 干净。
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            let mut child = cmd
                .spawn()
                .context("内核进程启动失败")?;

            let pid = child
                .id()
                .context("内核进程启动后立即退出")?;
            tracing::info!("sing-box process started, PID: {}", pid);
            register_kernel_pid(pid);

            spawn_log_pipe(
                child.stdout.take().context("missing child stdout")?,
                "out",
                &log_path,
            );
            spawn_log_pipe(
                child.stderr.take().context("missing child stderr")?,
                "err",
                &log_path,
            );
            (Some(child), pid)
        };

        // 4. 轮询 API 直到就绪（最长 15 秒）
        let api = KernelApi::new(&config.api_addr, &config.api_secret);
        let mut ready = false;

        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(500)).await;

            if let Ok(value) = api.get_version().await {
                tracing::info!("sing-box ready: {}", value);
                ready = true;
                break;
            }
        }

        if !ready {
            // 启动失败则回收内核并落盘错误上下文，避免残留
            #[cfg(target_os = "android")]
            {
                mobile_ffi::vpn_stop();
                crate::platform::android::stop_service();
            }
            #[cfg(target_os = "ios")]
            crate::platform::ios::stop_tunnel();
            #[cfg(not(any(target_os = "ios", target_os = "android")))]
            {
                if let Some(mut c) = child {
                    let _ = c.start_kill();
                    let _ = c.wait().await;
                }
                clear_kernel_pid(pid);
            }
            let tail = read_log_tail(&log_path);
            anyhow::bail!(
                "{}",
                sanitize_kernel_error(&format!(
                    "内核在 15 秒内未就绪，请查看内核日志 {} ；末尾输出：{}",
                    log_path.display(),
                    tail
                ))
            );
        }

        // 4.5 iOS：内核就绪后自动测速选最低延迟节点（用户可随后在 UI 手动指定）
        #[cfg(target_os = "ios")]
        {
            let auto_api = api.clone();
            // 主选择组 = route.final 直指 selector（与 resolve_main_selector
            // 顶层语义一致，build 159）：不再取字母序第一个 selector——
            // 那可能是只含少量节点的地区子分组
            let final_group = config
                .runtime_config
                .get("route")
                .and_then(|r| r.get("final"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = auto_select_best_proxy(&auto_api, &final_group).await {
                    tracing::warn!("自动选择节点失败: {e:#}");
                }
            });
        }

        // 5. 订阅内核 WebSocket 数据流（traffic / connections / memory）
        let mut stream_tasks = super::events::spawn_all(
            &config.api_addr,
            &config.api_secret,
            app_handle.clone(),
        );

        // 6. iOS：VPN 唯一性实时监控（build 157 用户方案）。系统可在任意
        // 时刻杀掉扩展进程/注销 VPN 会话（用户在系统设置关闭、其他 VPN
        // 抢占、NESM 会话失效），Rust 状态必须实时跟随，否则前端一直显示
        // "运行中"。轮询 Swift 导出的 C ABI prism_ios_vpn_is_connected
        // （见 PrismTunnelController.swift @_cdecl），发现掉线：停掉本
        // handle 的事件流任务 + 状态迁移（transition 内部自动广播
        // core://status，前端对齐 UI）
        #[cfg(target_os = "ios")]
        {
            let app = app_handle.clone();
            stream_tasks.push(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    if crate::platform::ios::vpn_is_connected() {
                        continue;
                    }
                    tracing::warn!("iOS VPN 连接已丢失，同步内核状态为 Stopped");
                    let state = app.state::<crate::core::state::AppState>();
                    // 仅 Running 时迁移；用户主动停止（Stopping/Stopped）
                    // 期间检测到掉线属正常收尾，不重复处理
                    if state
                        .transition(crate::core::state::CoreStatus::Stopping)
                        .is_ok()
                    {
                        // parking_lot 读守卫不能跨 await：clone 后立刻放锁
                        let handle = state.kernel_handle.read().clone();
                        if let Some(handle) = handle {
                            let _ = handle.shutdown().await;
                        }
                        let _ =
                            state.transition(crate::core::state::CoreStatus::Stopped);
                        *state.started_at.write() = None;
                    }
                    break;
                }
            }));
        }

        Ok(Self {
            config,
            child: Mutex::new(child),
            pid,
            stream_tasks: Mutex::new(stream_tasks),
        })
    }

    /// 优雅停止内核
    pub async fn shutdown(&self) -> Result<()> {
        tracing::info!("shutting down sing-box process {}", self.pid);

        // 先终止事件流任务，防止 stop/start 后订阅者翻倍
        // 锁守卫必须在 await 前释放（parking_lot 守卫不是 Send）
        {
            let mut tasks = self.stream_tasks.lock();
            for task in tasks.drain(..) {
                task.abort();
            }
        }

        let child = self.child.lock().take();
        if let Some(mut child) = child {
            // Unix 先 SIGTERM 给 5 秒优雅退出；Windows 直接 TerminateProcess
            #[cfg(unix)]
            unsafe {
                libc::kill(self.pid as i32, libc::SIGTERM);
            }

            let exited = tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .is_ok_and(|r| r.is_ok());

            if !exited {
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }

        #[cfg(target_os = "android")]
        {
            mobile_ffi::vpn_stop();
            crate::platform::android::stop_service();
        }

        #[cfg(target_os = "ios")]
        crate::platform::ios::stop_tunnel();

        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        clear_kernel_pid(self.pid);
        tracing::info!("sing-box process {} stopped", self.pid);
        Ok(())
    }
}

/// 静态校验待应用的配置：sing-box check -c <path>。
/// 重启前调用——校验失败时旧内核保留，网络不中断。
/// iOS/Android 上无法 spawn 子进程，改为调用内嵌 FFI 的 PrismKernelCheck（解析+构建后关闭）。
pub async fn check_config(
    binary: &std::path::Path,
    work_dir: &std::path::Path,
    config_path: &std::path::Path,
) -> Result<()> {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        let _ = binary;
        mobile_ffi::check(config_path, work_dir)
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    sanitize_kernel_error(&format!("新配置校验未通过，已保留当前内核：\n{e}"))
                )
            })?;
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let mut cmd = Command::new(binary);
        cmd.arg("check")
            .arg("-c")
            .arg(config_path)
            // 与 spawn 一致：legacy GEOIP/GEOSITE 规则需要环境变量启用
            .env("ENABLE_DEPRECATED_GEOIP", "true")
            .env("ENABLE_DEPRECATED_GEOSITE", "true")
            .current_dir(work_dir);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        let output = cmd
            .output()
            .await
            .context("内核配置校验执行失败")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // 只保留末尾 800 字符，避免前端 toast 被刷屏
            let chars: Vec<char> = stderr.chars().collect();
            let skip = chars.len().saturating_sub(800);
            let tail: String = chars[skip..].iter().collect();
            anyhow::bail!(
                "{}",
                sanitize_kernel_error(&format!("新配置校验未通过，已保留当前内核：\n{}", tail.trim()))
            );
        }
    }
    Ok(())
}

/// 生成随机 clash_api secret（本地环回用途，基于时间+pid 两次哈希拼成 32 hex）
pub fn generate_secret() -> String {
    fn hash_seed(seed: u64) -> u64 {
        let mut h = DefaultHasher::new();
        UNIX_EPOCH.elapsed().map(|d| d.as_nanos()).unwrap_or(0).hash(&mut h);
        std::process::id().hash(&mut h);
        seed.hash(&mut h);
        h.finish()
    }
    format!("{:016x}{:016x}", hash_seed(1), hash_seed(2))
}

/// 执行 `<binary> version` 并提取版本号（sing-box 输出 JSON）。
/// iOS/Android 无二进制可执行，直接返回内嵌内核版本。
pub async fn probe_version(binary: &std::path::Path) -> Option<String> {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        let _ = binary;
        return Some(format!("{} （内置）", EMBEDDED_VERSION));
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let mut cmd = Command::new(binary);
        cmd.arg("version");
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        let output = cmd.output().await.ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str::<serde_json::Value>(text.trim())
            .ok()
            .and_then(|v| v.get("version").and_then(|x| x.as_str().map(str::to_string)))
    }
}

/// 读取内核日志末尾最多 2KB，用于启动失败提示
fn read_log_tail(path: &std::path::Path) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return "<无日志>".into();
    };
    let start = bytes.len().saturating_sub(2048);
    String::from_utf8_lossy(&bytes[start..]).replace('\n', " | ")
}

/// 将 geoip.db / geosite.db 落到内核工作目录（已存在则跳过）。
/// 桌面候选来源：内核二进制同级（sidecar 位置）、应用资源目录、源码树 binaries（dev）。
/// iOS / Android 无真实文件系统资源可依赖（实测 Tauri iOS 不会把 bundle
/// resources 打进 .app，APK assets 亦非真实文件系统），数据库在编译期直接
/// 内嵌（include_bytes!，CI 构建前 fetch；文件缺失即编译失败，等于硬校验），
/// 运行时写入工作目录。
///
/// 硬性原则：任一数据库最终仍不可用即返回错误，**绝不放内核去联网下载**。
fn ensure_geo_databases(config: &KernelConfig, app_handle: &AppHandle) -> Result<()> {
    const DBS: [&str; 2] = ["geoip.db", "geosite.db"];

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = config.binary_path.parent() {
        candidates.push(dir.to_path_buf());
    }
    if let Ok(dir) = app_handle.path().resource_dir() {
        candidates.push(dir.clone());
        // 数组形式声明的 resources 会保留原目录结构（$RESOURCE/binaries/*.db）
        candidates.push(dir.join("binaries"));
    }
    // dev：内核二进制在 target/debug，数据库在源码树 src-tauri/binaries
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries"));

    for db in DBS {
        let dest = config.work_dir.join(db);
        if dest.is_file() {
            continue;
        }
        let mut provisioned = false;
        for dir in &candidates {
            let src = dir.join(db);
            if src.is_file() {
                match std::fs::copy(&src, &dest) {
                    Ok(_) => {
                        tracing::info!("copied {} -> {}", src.display(), dest.display());
                        provisioned = true;
                        break;
                    }
                    Err(e) => tracing::warn!("copy {} failed: {e}", src.display()),
                }
            }
        }

        // iOS / Android：无真实文件系统资源，写编译期内嵌副本
        #[cfg(any(target_os = "ios", target_os = "android"))]
        if !provisioned {
            let bytes: &[u8] = match db {
                "geoip.db" => include_bytes!("../../binaries/geoip.db").as_slice(),
                "geosite.db" => include_bytes!("../../binaries/geosite.db").as_slice(),
                _ => unreachable!(),
            };
            match std::fs::write(&dest, bytes) {
                Ok(_) => {
                    tracing::info!("wrote embedded {db} -> {}", dest.display());
                    provisioned = true;
                }
                Err(e) => tracing::warn!("write embedded {db} failed: {e}"),
            }
        }

        if !provisioned {
            anyhow::bail!(
                "必需的 {db} 缺失且安装包内未找到（Prism 不会联网下载内核文件）：请重新安装 Prism，或检查安全软件是否删除了应用文件"
            );
        }
    }
    Ok(())
}

/// work_dir 下的内核二进制最终路径（桌面：手动放置/历史落盘位置）
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub fn kernel_binary_path(work_dir: &std::path::Path) -> PathBuf {
    let exe = if cfg!(windows) {
        "sing-box.exe"
    } else {
        "sing-box"
    };
    work_dir.join(exe)
}

/// 将子进程的一条输出管道按行写入 kernel.log，同时转发到 tracing
/// （iOS/Android 内核进程内运行，日志由 Go 侧直接写文件，无管道可接）
#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn spawn_log_pipe<R>(reader: R, tag: &'static str, log_path: &std::path::Path)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let log_path = log_path.to_path_buf();
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::info!(target: "kernel", "[{tag}] {line}");
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
            {
                let ts = chrono_like_timestamp();
                let _ = writeln!(f, "[{ts}] [{tag}] {line}");
            }
        }
    });
}

/// 简易 UTC 时间戳（不引入 chrono 依赖，仅用于内核日志排障）
#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn chrono_like_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let day_secs = secs % 86400;
    let (h, m, s) = (day_secs / 3600, day_secs % 3600 / 60, day_secs % 60);
    format!("{h:02}:{m:02}:{s:02}")
}

// ---------------- 全局 PID（panic hook 兜底强杀） ----------------

static KERNEL_PID: OnceLock<Mutex<Option<u32>>> = OnceLock::new();

fn pid_store() -> &'static Mutex<Option<u32>> {
    KERNEL_PID.get_or_init(|| Mutex::new(None))
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn register_kernel_pid(pid: u32) {
    *pid_store().lock() = Some(pid);
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn clear_kernel_pid(pid: u32) {
    let mut guard = pid_store().lock();
    if *guard == Some(pid) {
        *guard = None;
    }
}

/// panic 兜底时使用：获取当前未清理的内核 pid
pub fn current_kernel_pid() -> Option<u32> {
    *pid_store().lock()
}

/// 内核 API 客户端（与 external-controller 通信）
#[derive(Clone)]
pub struct KernelApi {
    base: String,
    client: reqwest::Client,
}

impl KernelApi {
    pub fn new(api_addr: &str, api_secret: &str) -> Self {
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if !api_secret.is_empty() {
            let mut headers = reqwest::header::HeaderMap::new();
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {api_secret}"))
            {
                headers.insert(reqwest::header::AUTHORIZATION, value);
            }
            builder = builder.default_headers(headers);
        }
        Self {
            base: format!("http://{api_addr}"),
            client: builder.build().expect("failed to build HTTP client"),
        }
    }

    /// 获取版本信息
    pub async fn get_version(&self) -> Result<serde_json::Value> {
        Ok(self
            .client
            .get(format!("{}/version", self.base))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?)
    }

    /// 获取单个代理/策略组详情（含 all 成员列表）
    pub async fn get_proxy(&self, name: &str) -> Result<serde_json::Value> {
        Ok(self
            .client
            .get(format!("{}/proxies/{}", self.base, name))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?)
    }

    /// 获取所有代理节点和策略组
    pub async fn get_proxies(&self) -> Result<serde_json::Value> {
        Ok(self
            .client
            .get(format!("{}/proxies", self.base))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?)
    }

    /// 切换 Selector 策略组选择
    pub async fn select_proxy(&self, group: &str, name: &str) -> Result<()> {
        let url = format!("{}/proxies/{}", self.base, group);
        let resp = self
            .client
            .put(&url)
            .json(&serde_json::json!({ "name": name }))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("select proxy failed: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// 热切换出站模式：PATCH /configs {"mode": ...}（build 157 用户方案）。
    /// sing-box 侧路由行为由 config 内 clash_mode 规则驱动，切换无需重启
    pub async fn patch_mode(&self, mode: &str) -> Result<()> {
        let resp = self
            .client
            .patch(format!("{}/configs", self.base))
            .json(&serde_json::json!({ "mode": mode }))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("patch mode failed: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// 策略组整组测速：并发（20 路）调用 /proxies/{name}/delay 并汇总为 map。
    /// 历史实现直接调用 /group/{name}/delay，但 sing-box 1.11.3 对该端点
    /// 只返回组本身的延迟（非成员 map），导致前端把全部节点标记为超时。
    /// 改为逐节点测速后，结果可靠且与 Clash API 响应格式一致。
    ///
    /// build 157 用户方案：串行 51 节点 × 5s 超时实测过慢（>2 分钟），
    /// 改为 buffer_unordered(32) 并发 + 默认超时 2000ms；app 提供时逐结果
    /// 推送 `url-test-update` 事件（delay=null 表示失败），前端实时刷新
    /// 单节点延迟，无需等全部完成
    pub async fn group_url_test(
        &self,
        name: &str,
        url: Option<&str>,
        timeout_ms: Option<u32>,
        app: Option<&AppHandle>,
    ) -> Result<serde_json::Value> {
        // 1. 先取组成员列表
        let group_info = self.get_proxy(name).await?;
        let members: Vec<String> = group_info
            .get("all")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        if members.is_empty() {
            anyhow::bail!("策略组 '{}' 没有可测速的成员", name);
        }

        let test_url = url.unwrap_or("http://www.gstatic.com/generate_204");
        // 单节点超时强制 2000ms：真实反映可用性——2s 内无响应的节点视为不可用，
        // 拉满超时只会拖慢整体测速。并发 32 路下整体耗时 ≈ ceil(节点数/32) × 2s；
        // 每个结果完成后立即推送 url-test-update，前端逐节点实时刷新
        let timeout = timeout_ms.unwrap_or(2000).min(2000);
        let group_tag = name.to_string();

        use futures_util::StreamExt;
        const TEST_CONCURRENCY: usize = 32;
        let results: Vec<(String, Option<u64>)> = futures_util::stream::iter(members)
            .map(|member| {
                let endpoint = format!("{}/proxies/{}/delay", self.base, member);
                let req = self.client.get(&endpoint).query(&[
                    ("url", test_url.to_string()),
                    ("timeout", timeout.to_string()),
                ]);
                let app = app.map(|a| a.clone());
                let group_tag = group_tag.clone();
                async move {
                    let delay = match req.send().await {
                        Ok(resp) if resp.status().is_success() => resp
                            .json::<serde_json::Value>()
                            .await
                            .ok()
                            .and_then(|j| j.get("delay").and_then(|d| d.as_u64())),
                        Ok(resp) => {
                            tracing::warn!("delay test {}: HTTP {}", member, resp.status());
                            None
                        }
                        Err(e) => {
                            tracing::warn!("delay test {}: {}", member, e);
                            None
                        }
                    };
                    if let Some(app) = app {
                        use tauri::Emitter;
                        let _ = app.emit(
                            "url-test-update",
                            serde_json::json!({
                                "group": group_tag,
                                "name": member,
                                "delay": delay,
                            }),
                        );
                    }
                    (member, delay)
                }
            })
            .buffer_unordered(TEST_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;

        let mut map = serde_json::Map::new();
        for (member, delay) in results {
            if let Some(d) = delay {
                map.insert(member, serde_json::json!(d));
            }
        }
        Ok(serde_json::Value::Object(map))
    }

    /// 获取当前规则列表
    pub async fn get_rules(&self) -> Result<serde_json::Value> {
        Ok(self
            .client
            .get(format!("{}/rules", self.base))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?)
    }

    /// 获取实时连接快照
    pub async fn get_connections(&self) -> Result<serde_json::Value> {
        Ok(self
            .client
            .get(format!("{}/connections", self.base))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?)
    }

    /// 关闭单条连接：DELETE /connections/{id}
    /// （sing-box 连接 id 为十六进制字符串，可直接拼路径）
    pub async fn close_connection(&self, id: &str) -> Result<()> {
        let resp = self
            .client
            .delete(format!("{}/connections/{}", self.base, id))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("close connection failed: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// 关闭全部连接：DELETE /connections
    pub async fn close_all_connections(&self) -> Result<()> {
        let resp = self
            .client
            .delete(format!("{}/connections", self.base))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("close all connections failed: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// 单节点测延迟：GET /proxies/{name}/delay，返回毫秒数；超时/失败返回 None
    pub async fn test_delay(&self, name: &str, url: &str, timeout_ms: u32) -> Option<u64> {
        let resp = self
            .client
            .get(format!("{}/proxies/{}/delay", self.base, name))
            .query(&[
                ("url", url.to_string()),
                ("timeout", timeout_ms.to_string()),
            ])
            .timeout(Duration::from_millis(timeout_ms as u64 + 2000))
            .send()
            .await
            .ok()?;
        let json = resp.json::<serde_json::Value>().await.ok()?;
        json.get("delay").and_then(|d| d.as_u64())
    }
}

/// 自动测速并选择延迟最低的节点（build 150 新需求：APP 运行后自动选优，
/// 用户可随后在 UI 手动指定节点覆盖）。
/// 流程：取 /proxies → 定位主选择组（final 直指 selector，build 159；
/// 找不到时回退第一个 Selector）→ 并发对其真实节点测延迟
/// （排除内置出站与嵌套策略组，3 秒超时）→ 选最低者 select_proxy。
/// 全部超时则放弃并保持默认选择，不影响启动流程。
#[cfg(target_os = "ios")]
async fn auto_select_best_proxy(api: &KernelApi, final_group: &str) -> Result<()> {
    const TEST_URL: &str = "http://www.gstatic.com/generate_204";
    const TEST_TIMEOUT_MS: u32 = 3000;
    /// 内置出站与不可选择项（不做真实测速）
    const EXCLUDED: [&str; 8] = [
        "direct", "block", "dns-out", "REJECT", "REJECT-DROP", "COMPATIBLE", "GLOBAL", "PASS",
    ];

    let proxies = api.get_proxies().await?;
    let map = proxies
        .get("proxies")
        .and_then(|p| p.as_object())
        .context("clash api 返回缺少 proxies 字段")?;

    // 主选择组：final 直指的 selector（build 159，与 resolve_main_selector
    // 一致）；缺失/类型不符时回退第一个 Selector
    let (group, members) = {
        let is_selector = |name: &str| {
            map.get(name)
                .and_then(|v| v.get("type"))
                .and_then(|t| t.as_str())
                .is_some_and(|t| t.eq_ignore_ascii_case("selector"))
        };
        let preferred = if !final_group.is_empty() && is_selector(final_group) {
            Some(final_group.to_string())
        } else {
            None
        };
        let name = preferred.or_else(|| {
            map.iter()
                .find(|(_, v)| {
                    v.get("type")
                        .and_then(|t| t.as_str())
                        .is_some_and(|t| t.eq_ignore_ascii_case("selector"))
                })
                .map(|(name, _)| name.clone())
        });
        let name = name.context("未找到 Selector 策略组")?;
        let all: Vec<String> = map
            .get(&name)
            .and_then(|v| v.get("all"))
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        (name, all)
    };

    // 只对真实节点测速：排除内置出站 + 嵌套策略组（含 all 成员列表的项）
    let nodes: Vec<String> = members
        .into_iter()
        .filter(|m| !EXCLUDED.iter().any(|e| m.eq_ignore_ascii_case(e)))
        .filter(|m| {
            map.get(m)
                .map(|info| info.get("all").is_none())
                .unwrap_or(true)
        })
        .collect();
    anyhow::ensure!(!nodes.is_empty(), "策略组 '{group}' 无可用节点");

    // 并发测速（节点可达 50+，串行太慢）
    let mut tasks: Vec<tokio::task::JoinHandle<Option<(String, u64)>>> =
        Vec::with_capacity(nodes.len());
    for node in nodes {
        let api = api.clone();
        tasks.push(tokio::spawn(async move {
            let delay = api.test_delay(&node, TEST_URL, TEST_TIMEOUT_MS).await?;
            Some((node, delay))
        }));
    }

    let mut best: Option<(String, u64)> = None;
    for task in tasks {
        if let Ok(Some((node, delay))) = task.await {
            if best.as_ref().is_none_or(|(_, d)| delay < *d) {
                best = Some((node, delay));
            }
        }
    }

    let (node, delay) = best.context("所有节点测速均超时，保持默认选择")?;
    api.select_proxy(&group, &node).await?;
    // GLOBAL 组同步选择：与手动 select_proxy 行为一致，全局模式
    // （clash_mode global → GLOBAL 组）也走本次测速选出的最优节点
    if let Err(e) = api.select_proxy("GLOBAL", &node).await {
        tracing::debug!("GLOBAL 组同步选择失败（组不存在时忽略）: {e}");
    }
    // 切换后清理全部旧连接：否则已建立的连接继续走旧节点（cache.db
    // 已由扩展 sanitize 禁用并在启动时删除，无恢复问题；但运行中切换
    // 必须主动清，与手动 select_proxy 命令行为一致——build 156）
    if let Err(e) = api.close_all_connections().await {
        tracing::warn!("自动选节点后清理旧连接失败: {e}");
    }
    tracing::info!("自动选择节点: {node}（{delay}ms，组: {group}）");
    Ok(())
}
