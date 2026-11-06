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
use tauri::{AppHandle, Emitter, Manager};
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
// APP27：VPN 回调与 Start/Stop 符号仅 Android 使用；iOS 上保留同签名定义
// 但不调用，允许 dead_code 以免 iOS 目标 check 出现警告。
#[cfg_attr(target_os = "ios", allow(dead_code))]
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
                .map_err(|e| anyhow::anyhow!("内核配置编码错误: {e}"))?
                .to_owned();
            let kernel_work_dir = config.work_dir.clone();
            // IPA-12 2.3：startServiceAndWait 内部经 runOnUiThread 拉起前台
            // 服务并 latch 等待最长 8s，libbox 启动期间还会同步等待回调，
            // 与 iOS start_tunnel 同理必须放 spawn_blocking，否则 Tokio
            // worker 被阻塞，前端所有 IPC（状态/切页/事件）全部无响应
            let started = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                crate::platform::android::start_service_and_wait()
                    .map_err(|e| anyhow::anyhow!("VPN 服务启动失败: {e}"))?;
                mobile_ffi::vpn_start(&content, &kernel_work_dir)
                    .map_err(|e| anyhow::anyhow!("VPN 启动失败: {e}"))?;
                Ok(())
            })
            .await
            .map_err(|e| anyhow::anyhow!("VPN 启动任务异常退出: {e}"))?;
            started?;
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

        // 5. 订阅内核 WebSocket 数据流（traffic / connections / memory）
        // （移动端会追加故障转移/掉线监控任务，桌面端不会 push，故条件允许）
        #[cfg_attr(not(any(target_os = "ios", target_os = "android")), allow(unused_mut))]
        let mut stream_tasks = super::events::spawn_all(
            &config.api_addr,
            &config.api_secret,
            app_handle.clone(),
        );

        // 5.5 移动端（iOS/Android）：内核就绪后按三级规则自动选点
        // （用户可随后在 UI 手动指定）；桌面平台不自动选点
        #[cfg(any(target_os = "ios", target_os = "android"))]
        {
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
            let auto_api = api.clone();
            let auto_group = final_group.clone();
            let auto_app = app_handle.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = auto_select_best_proxy(&auto_api, &auto_group, auto_app).await {
                    tracing::warn!("自动选择节点失败: {e:#}");
                }
            });

            // 【APP-4.3】运行期被动故障转移：与事件流同生命周期（stop 时 abort）
            let failover_api = api.clone();
            let failover_app = app_handle.clone();
            stream_tasks.push(tokio::spawn(async move {
                run_node_failover(failover_api, final_group, failover_app).await;
            }));
        }

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
                        *state.started_at_ms.write() = None;
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

    /// 认领一个「内核侧已在运行、本进程却没有句柄」的隧道（APP-5 任务3）。
    /// 不启动任何进程：仅重建事件流订阅，使流量/连接/内存统计立即续接。
    /// 停止时由平台侧 stop_tunnel / stop_service 回收，不依赖子进程句柄。
    pub(crate) fn reattach(config: KernelConfig, app_handle: AppHandle) -> Self {
        let stream_tasks =
            super::events::spawn_all(&config.api_addr, &config.api_secret, app_handle);
        Self {
            config,
            child: Mutex::new(None),
            // 无真实子进程：pid 置 0，避免误杀或清错 PID 记录
            pid: 0,
            stream_tasks: Mutex::new(stream_tasks),
        }
    }
}

/// 强退重开后自动认领后台仍在运行的 VPN 隧道（APP-5 任务3）。
///
/// 用户未点「停止」直接划掉主 App 时，系统底层隧道（iOS 的
/// NEPacketTunnelProvider / Android 的 VpnService）仍在转发流量。重开 App
/// 时 Rust 侧 AppState 全新初始化为 Stopped，必须主动认领，否则 UI 显示
/// 「未连接」而实际已在代理，且连接时长/流量统计全部归零。
///
/// 返回 true 表示已成功认领（状态已迁移到 Running 并广播事件）。
pub async fn try_reattach_running_kernel(
    app: &AppHandle,
    state: &crate::core::state::AppState,
) -> bool {
    // 已有句柄 / 非 Stopped：无需认领
    if state.kernel_handle.read().is_some() {
        return false;
    }
    if *state.status.read() != crate::core::state::CoreStatus::Stopped {
        return false;
    }

    // 1. 读取上次运行写入的运行时配置，恢复 clash_api 地址与鉴权密钥
    //    （密钥每次启动随机生成，只能从落盘的 config.json 还原）
    let work_dir = state.work_dir();
    let Ok(raw) = std::fs::read_to_string(work_dir.join("config.json")) else {
        return false;
    };
    let Ok(runtime_config) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    let api_addr = runtime_config
        .pointer("/experimental/clash_api/external_controller")
        .and_then(|v| v.as_str())
        .unwrap_or(PREFERRED_API_ADDR)
        .to_string();
    let api_secret = runtime_config
        .pointer("/experimental/clash_api/secret")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // 2. 平台侧确认隧道仍在运行（iOS 由系统 nesessionmanagerd 维护连接状态）
    #[cfg(target_os = "ios")]
    if !crate::platform::ios::vpn_is_connected() {
        return false;
    }

    // 3. 内核 API 必须在线：事件流、节点同步、Go AIM 探测都依赖它
    let api = KernelApi::new(&api_addr, &api_secret);
    if api.get_version().await.is_err() {
        tracing::debug!("[reattach] 内核 API 不在线，跳过认领");
        return false;
    }

    // 4. 重建句柄 + 事件流订阅
    *state.api_addr.write() = api_addr.clone();
    *state.api_secret.write() = api_secret.clone();
    let kernel_config = KernelConfig {
        // 认领场景不需要二进制路径（内核不在本进程内）
        binary_path: std::path::PathBuf::new(),
        work_dir: work_dir.clone(),
        api_addr: api_addr.clone(),
        api_secret,
        runtime_config: runtime_config.clone(),
    };
    *state.kernel_handle.write() = Some(std::sync::Arc::new(KernelHandle::reattach(
        kernel_config,
        app.clone(),
    )));

    // 5. 恢复主选择组（节点页/仪表盘需要真实出口）。
    //    优先用运行时配置的 route.final；缺失时回落到第一个 Selector。
    if let Ok(proxies) = api.get_proxies().await
        && let Some(map) = proxies.get("proxies").and_then(|p| p.as_object())
    {
        let is_selector = |name: &str| {
            map.get(name)
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str())
                == Some("Selector")
        };
        let preferred = runtime_config
            .pointer("/route/final")
            .and_then(|v| v.as_str())
            .filter(|name| is_selector(name))
            .map(str::to_string)
            .or_else(|| {
                map.iter()
                    .find(|(name, _)| is_selector(name) && name.as_str() != "GLOBAL")
                    .map(|(name, _)| name.clone())
            });
        if let Some(group) = preferred {
            *state.main_selector.write() = Some(group);
        }
    }

    // 6. 状态迁移 Stopped → Starting → Running（transition 内部会写入
    //    started_at_ms 并广播 core://status）
    if state
        .transition(crate::core::state::CoreStatus::Starting)
        .is_err()
    {
        return false;
    }
    // iOS 的 transition 已用系统 connectedDate 写入 started_at_ms；
    // 其他平台用落盘的会话起点覆盖，保证「已连接时长」连续
    if state
        .transition(crate::core::state::CoreStatus::Running)
        .is_err()
    {
        return false;
    }
    #[cfg(not(target_os = "ios"))]
    {
        let persisted = crate::core::store::session_started_at(&state.data_dir);
        if persisted > 0 {
            *state.started_at_ms.write() = Some(persisted);
        }
    }
    *state.started_at.write() = Some(std::time::Instant::now());

    tracing::info!("[reattach] 已认领后台运行中的隧道（api={api_addr}）");
    let _ = app.emit("proxies://changed", ());
    true
}

/// 【APP43 任务2.2】状态自检与自动恢复：主 APP 被用户划掉/系统强杀后，
/// 系统级 VPN 隧道（iOS NEPacketTunnelProvider）仍在转发流量、状态栏
/// 仍有 VPN 图标，而重开 APP 时 Rust 侧 AppState 全新初始化为 Stopped。
/// 每次状态轮询/启动前调用本函数，发现隧道或内核 API 仍在位就直接认领，
/// 恢复「已连接」状态、计时器与流量统计，用户无需再点启动（也不报错）。
///
/// 返回 true 表示当前（或恢复后）处于运行状态。
pub async fn sync_or_recover_running_vpn(
    app: &AppHandle,
    state: &crate::core::state::AppState,
) -> bool {
    if *state.status.read() != crate::core::state::CoreStatus::Stopped {
        return true;
    }
    // 探活节流：3s 内只探测一次（前端状态轮询 ~1s/次，避免重复 I/O 与
    // Swift 侧 loadAllFromPreferences 的 400ms 阻塞被连续触发）。
    // 失败后下一轮仍会重试，保证「VPN 稍后才起来」也能自动接管。
    static REATTACH_LAST: OnceLock<Mutex<Option<std::time::Instant>>> = OnceLock::new();
    let last = REATTACH_LAST.get_or_init(|| Mutex::new(None));
    {
        let guard = last.lock();
        if let Some(at) = *guard
            && at.elapsed() < Duration::from_secs(3)
        {
            return false;
        }
    }
    // iOS：系统 VPN 会话不在 connected/connecting 时一定没在运行，
    // 先行短路，避免每次都去读 config.json + 打内核 API。
    #[cfg(target_os = "ios")]
    if !crate::platform::ios::vpn_is_connected() {
        *last.lock() = Some(std::time::Instant::now());
        return false;
    }
    let recovered =
        try_reattach_running_kernel(app, state).await;
    *last.lock() = Some(std::time::Instant::now());
    if recovered {
        tracing::info!("[Kernel] 检测到系统 VPN 隧道仍在运行，已自动接管并恢复代理连接状态");
    }
    recovered
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
        // 【APP12 任务2】返回纯版本号（前端统一加 v 前缀展示，不再拼 "（内置）"）
        return Some(EMBEDDED_VERSION.to_string());
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let mut cmd = Command::new(binary);
        cmd.arg("version");
        #[cfg(target_os = "windows")]
        {
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

/// 【APP43 任务1.1】全进程复用的 HTTP 客户端：
/// 每次 `KernelApi::new` 都 `Client::builder().build()` 会重新初始化整套
/// TLS/连接池，切页高频轮询（连接/规则/状态）时不断申请系统资源，是
/// IPC 响应变慢直至“整机卡死”的重要原因。鉴权头改为逐请求 `bearer_auth`，
/// 这样同一个客户端可安全复用于不同 secret 的内核实例。
static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn shared_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(800))
            .timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client")
    })
}

/// 内核 API 客户端（与 external-controller 通信）
#[derive(Clone)]
pub struct KernelApi {
    base: String,
    secret: String,
}

impl KernelApi {
    pub fn new(api_addr: &str, api_secret: &str) -> Self {
        Self {
            base: format!("http://{api_addr}"),
            secret: api_secret.to_string(),
        }
    }

    /// 附加 clash_api 鉴权（secret 为空时不加头）
    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.secret.is_empty() {
            req
        } else {
            req.bearer_auth(&self.secret)
        }
    }

    /// 获取版本信息（探活场景，300ms 内必须返回）
    pub async fn get_version(&self) -> Result<serde_json::Value> {
        Ok(self
            .authed(shared_client().get(format!("{}/version", self.base)))
            .timeout(Duration::from_millis(300))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?)
    }

    /// 获取单个代理/策略组详情（含 all 成员列表）
    pub async fn get_proxy(&self, name: &str) -> Result<serde_json::Value> {
        Ok(self
            .authed(shared_client().get(format!("{}/proxies/{}", self.base, name)))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?)
    }

    /// 获取所有代理节点和策略组
    pub async fn get_proxies(&self) -> Result<serde_json::Value> {
        Ok(self
            .authed(shared_client().get(format!("{}/proxies", self.base)))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?)
    }

    /// 切换 Selector 策略组选择
    pub async fn select_proxy(&self, group: &str, name: &str) -> Result<()> {
        let url = format!("{}/proxies/{}", self.base, group);
        let resp = self
            .authed(shared_client().put(&url))
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
            .authed(shared_client().patch(format!("{}/configs", self.base)))
            .json(&serde_json::json!({ "mode": mode }))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("patch mode failed: HTTP {}", resp.status());
        }
        Ok(())
    }

    /// 策略组整组测速：逐节点调用 /proxies/{name}/delay 并汇总为 map。
    /// 历史实现直接调用 /group/{name}/delay，但 sing-box 1.11.3 对该端点
    /// 只返回组本身的延迟（非成员 map），导致前端把全部节点标记为超时。
    ///
    /// 【APP37 任务3.1】每批 8 个节点滚动并发（buffer_unordered(8)），
    /// 单次 Clash API 超时 2200ms，失败回退主进程 TcpStream 握手 1500ms；
    /// 严禁任何 .take/.truncate 截断，100% 测完全部成员。每节点推送
    /// `url-test-update`（delay=null 表示失败），每批结束推送
    /// `proxies://changed` 并让出 30ms 时间片。全部完成后：未开启
    /// Go AIM 且用户未手动指定节点时，自动选中 delay>0 最低延迟节点。
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

        let test_url = url.unwrap_or("http://cp.cloudflare.com/generate_204");
        // 【APP42 任务1.3】单次超时 2200ms；100% 走内核真实出站测速。
        // 严禁 TcpStream 回退：TUN 开启时主进程 TCP 握手命中 utun 栈，
        // 会返回 2~4ms 虚假本地回环延迟，导致大量节点显示「绿色极快」实为瘫死。
        let timeout = timeout_ms.unwrap_or(2200).min(2200);
        let group_tag = name.to_string();

        use futures_util::StreamExt;
        // 【APP37 任务3.1】每批 8 个节点滚动并发：既 100% 测完全部节点，
        // 又绝不撑爆 iOS 扩展内存（严禁任何 .take/.truncate 截断）。
        const BATCH_SIZE: usize = 8;
        let mut map = serde_json::Map::new();
        for batch in members.chunks(BATCH_SIZE) {
            let batch_results: Vec<(String, Option<u64>)> = futures_util::stream::iter(
                batch.iter().cloned(),
            )
            .map(|member| {
                // 【APP42 任务1.3】节点名含 emoji/空格/中文，路径段必须显式
                // 百分号编码，否则 reqwest 构建 URL 失败 → 误判节点不可用
                let endpoint = format!(
                    "{}/proxies/{}/delay",
                    self.base,
                    encode_path_segment(&member)
                );
                let req = shared_client()
                    .get(&endpoint)
                    .query(&[
                        ("url", test_url.to_string()),
                        ("timeout", timeout.to_string()),
                    ])
                    .bearer_auth(self.secret.clone());
                let app = app.cloned();
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
            .buffer_unordered(BATCH_SIZE)
            .collect::<Vec<_>>()
            .await;
            for (member, delay) in &batch_results {
                if let Some(d) = delay {
                    map.insert(member.clone(), serde_json::json!(d));
                }
            }
            // 每完成一批：批次事件让节点页立即整体刷新本批延迟数字，
            // 随后让出 30ms 时间片供内存回收，继续下一批。
            if let Some(app) = app {
                let _ = app.emit("proxies://changed", ());
            }
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }

        // 3. 【APP37 任务3.1】全部测速完成后：未开启 Go AIM 且用户未手动
        //    指定节点时，自动选中实测 delay > 0 且延迟最低的节点
        //    （排除内置出站与嵌套策略组）。
        if let Some(app) = app {
            // 【APP52 任务1】完整测速结果（含超时=0）异步落盘，节点页/仪表盘
            // 在内核重启或 APP 重启后继续显示上次真实延迟与升序排列。
            {
                let st = app.state::<crate::core::state::AppState>();
                let delays: Vec<(String, u32)> = members
                    .iter()
                    .map(|m| {
                        let d = map.get(m).and_then(|v| v.as_u64()).unwrap_or(0);
                        (m.clone(), d as u32)
                    })
                    .collect();
                st.record_node_delays(delays);
                // 【APP52 任务1】用户主动重测 = 回到自动选点模式
                *st.user_manually_selected_node.write() = false;
                let mut settings = st.settings.read().clone();
                settings.user_manually_selected_node = false;
                let _ = st.save_settings(settings);
            }
            let (aim_on, manual) = {
                let st = app.state::<crate::core::state::AppState>();
                (
                    st.settings.read().go_aim_enabled,
                    *st.user_manually_selected_node.read(),
                )
            };
            if !aim_on && !manual {
                // 嵌套策略组（含 all 成员列表的项）不可选中，一并排除
                let nested: std::collections::HashSet<String> = self
                    .get_proxies()
                    .await
                    .ok()
                    .and_then(|p| {
                        p.get("proxies").and_then(|v| v.as_object()).map(|obj| {
                            obj.iter()
                                .filter(|(_, v)| v.get("all").is_some())
                                .map(|(k, _)| k.clone())
                                .collect()
                        })
                    })
                    .unwrap_or_default();
                let best = map
                    .iter()
                    .filter_map(|(name, v)| v.as_u64().map(|d| (name.clone(), d)))
                    .filter(|(name, d)| {
                        *d > 0
                            && !crate::core::config_builder::is_builtin_non_proxy_tag(name)
                            && !nested.contains(name)
                    })
                    .min_by_key(|(_, d)| *d);
                if let Some((best_node, best_delay)) = best {
                    tracing::info!("[url_test] APP37 自动选点：{best_node}（{best_delay}ms）");
                    let _ = self.select_proxy(&group_tag, &best_node).await;
                    let _ = self.select_proxy("GLOBAL", &best_node).await;
                    let _ = self.close_all_connections().await;
                    // 【APP52 任务1】自动选点结果同步 settings.selected_node 并落盘
                    let st = app.state::<crate::core::state::AppState>();
                    let mut settings = st.settings.read().clone();
                    if settings.selected_node.as_deref() != Some(best_node.as_str()) {
                        settings.selected_node = Some(best_node.clone());
                        settings.user_manually_selected_node = false;
                        if let Err(e) = st.save_settings(settings) {
                            tracing::warn!("[url_test] 自动选点落盘失败: {e}");
                        }
                    }
                    let _ = app.emit("proxies://changed", serde_json::json!({}));
                }
            }
        }
        Ok(serde_json::Value::Object(map))
    }

    /// 获取当前规则列表
    pub async fn get_rules(&self) -> Result<serde_json::Value> {
        Ok(self
            .authed(shared_client().get(format!("{}/rules", self.base)))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?)
    }

    /// 获取实时连接快照（切页高频轮询：严格 800ms 超时，绝不挂起 IPC）
    pub async fn get_connections(&self) -> Result<serde_json::Value> {
        // 【APP51 任务2】超时放宽到 1500ms：Windows 内核首次响应常超过 800ms，
        // 过短超时会让仪表盘误判「内核未运行」并导致速率卡死
        self.get_connections_with_timeout(1500).await
    }

    /// 【APP52 任务2】可指定超时的 /connections 探测（后台遥测协程用 1200ms）
    pub async fn get_connections_with_timeout(
        &self,
        timeout_ms: u64,
    ) -> Result<serde_json::Value> {
        Ok(self
            .authed(shared_client().get(format!("{}/connections", self.base)))
            .timeout(Duration::from_millis(timeout_ms))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?)
    }

    /// 关闭单条连接：DELETE /connections/{id}
    /// （sing-box 连接 id 为十六进制字符串，可直接拼路径）
    pub async fn close_connection(&self, id: &str) -> Result<()> {
        let resp = self
            .authed(shared_client().delete(format!("{}/connections/{}", self.base, id)))
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
            .authed(shared_client().delete(format!("{}/connections", self.base)))
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
            .authed(shared_client().get(format!(
                "{}/proxies/{}/delay",
                self.base,
                encode_path_segment(name)
            )))
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

/// 移动端自动测速并按三级规则选择节点（build 150 新需求：APP 运行后自动选优，
/// 用户可随后在 UI 手动指定节点覆盖）。
///
/// 三级规则（读取 AppState）：
///   A. 非 Pro：在全部真实节点里选 test_delay 最低的存活节点；
///   B. Pro 且 go_aim_enabled == false：同样选全量最低延迟节点，并后台静默跑一次
///      Go AIM 解锁探测（不切换节点）；
///   C. Pro 且 go_aim_enabled == true：优先在「ai_unlocked || media_unlocked」的
///      解锁池内选最低延迟；优先池为空或全部测速失败时回退全量最低延迟。
///      探测结果异步写入，启动瞬间可能为空——此时按全量最低延迟选择并同时
///      触发探测，等 go_aim 自身 monitor 后续锁定时再切换（此处不阻塞等待）。
///
/// 流程：取 /proxies → 定位主选择组（final 直指 selector，build 159；找不到时
/// 回退第一个 Selector）→ 并发测延迟（排除内置出站与嵌套策略组，3 秒超时）→
/// 选最低者 select_proxy（同步 GLOBAL）→ 清理旧连接 → 发射 proxies://changed。
/// 全部超时则放弃并保持默认选择，不影响启动流程。
#[cfg(any(target_os = "ios", target_os = "android"))]
async fn auto_select_best_proxy(
    api: &KernelApi,
    final_group: &str,
    app_handle: AppHandle,
) -> Result<()> {
    const TEST_URL: &str = "http://www.gstatic.com/generate_204";
    const TEST_TIMEOUT_MS: u32 = 3000;
    // 【APP-10 任务2】内置出站与不可选择项统一由
    // config_builder::is_builtin_non_proxy_tag 判定（大小写不敏感 +
    // 中文"直连" + GO-AIM-PROBE 探测组），替代局部 EXCLUDED 名单——
    // 订阅里 direct 可能被当成最低延迟节点（延迟 1ms），一旦漏过滤
    // 就会选到 direct 变成"假翻墙真直连"。

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
        .filter(|m| !crate::core::config_builder::is_builtin_non_proxy_tag(m))
        .filter(|m| {
            map.get(m)
                .map(|info| info.get("all").is_none())
                .unwrap_or(true)
        })
        .collect();
    anyhow::ensure!(!nodes.is_empty(), "策略组 '{group}' 无可用节点");

    // ---- 三级规则：确定候选优先级池 + 是否需要触发 Go AIM 探测 ----
    let state = app_handle.state::<crate::core::state::AppState>();
    let pro_unlocked = state.is_pro_active();
    let go_aim_enabled = pro_unlocked && state.settings.read().go_aim_enabled;

    // APP-5 任务3 最高守卫：用户手动指定了节点（go_aim_pinned_node）时，
    // 无论 VPN 启动自动选点、后台 failover、还是重测，**一律严格锁定**用户
    // 手动选择的节点，绝不再自动回跳延迟最低的节点——除非用户主动
    // 「恢复自动」清除 pinned（clear_go_aim_pinned_node 命令）。
    // 与 go_aim.rs apply_selection 中的 pinned 检查完全对齐，两条链路一致。
    let pinned = state.settings.read().go_aim_pinned_node.clone();
    if let Some(pinned_node) = pinned
        && go_aim_enabled
        && nodes.iter().any(|n| n == &pinned_node)
    {
        tracing::info!(
            "[auto_select] 命中 go_aim_pinned_node={pinned_node}，跳过自动测速，严格锁定用户手动指定"
        );
        let _ = api.select_proxy(&group, &pinned_node).await;
        let _ = api.select_proxy("GLOBAL", &pinned_node).await;
        let _ = api.close_all_connections().await;
        let _ = app_handle.emit("proxies://changed", serde_json::json!({}));
        return Ok(());
    }

    // C：Go AIM 已解锁节点优先池（探测结果异步写入，启动瞬间可能为空）
    let mut priority: Vec<String> = Vec::new();
    if go_aim_enabled {
        let results = state.aim_results.read();
        for node in &nodes {
            if results
                .get(node)
                .is_some_and(|r| r.ai_unlocked || r.media_unlocked)
            {
                priority.push(node.clone());
            }
        }
    }

    // 优先在解锁池内选最低延迟；池为空或全部失败则回退
    let mut best: Option<(String, u64)> = if priority.is_empty() {
        None
    } else {
        test_fastest(api, &priority, TEST_URL, TEST_TIMEOUT_MS).await
    };
    if best.is_none() {
        if !priority.is_empty() {
            tracing::info!("Go AIM 优先池测速全部失败，回退全量节点");
        }
        // APP34：严禁对全量 148 个节点逐个调用 Clash API 延迟测速——上百个
        // 并发探测会瞬间把 iOS 扩展进程内存推过 50MB Jetsam 红线，导致
        // 「启动一会儿自动停止」。改为主进程 TCP 握手轻量测速：
        // 前 20 个有效节点 / 并发 6 / 单点超时 1000ms，选出最低延迟后由
        // 下方仅发送 1 次 PUT 切换。
        let endpoints = collect_node_endpoints(&state.data_dir);
        best = tcp_select_fastest(&nodes, &endpoints).await;
    }

    // 后台静默跑一次 Go AIM 解锁探测；延迟数秒触发以等待内核状态迁移到
    // Running（start_probe 要求内核运行中）。
    // 【APP25 任务3】重启内核（保存回家配置 / 网络切换热重载）后必须
    // 无条件重跑一次探测：旧逻辑仅在「AIM 未开启」或「优先池为空」时触发，
    // 导致用户已有评级结果且开启 AIM 时，重启后仍沿用旧缓存锁定旧线路。
    // 【APP34】但必须严格跟随 Go AIM 开关：关闭时绝不触发全量探测，
    // 否则 148 节点真实 HTTP 探测会撑爆扩展进程内存。
    let trigger_probe = go_aim_enabled;
    if trigger_probe {
        let probe_app = app_handle.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            crate::core::go_aim::start_probe(probe_app);
        });
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
    // 通知节点页刷新当前选中项（前端依赖该事件对齐当前节点）
    let _ = app_handle.emit("proxies://changed", serde_json::json!({}));
    tracing::info!("自动选择节点: {node}（{delay}ms，组: {group}）");
    Ok(())
}

/// 【APP-4.3】运行期节点被动故障转移。
/// 每 45s 用真实的 generate_204 探测主组当前节点；连续 2 次超时/失败
/// （排除偶发抖动）才重新选点——复用 auto_select_best_proxy 的三级规则，
/// 开启 Go AIM 时自然优先切到次低延迟的解锁节点。探测与选点均在后台
/// 异步执行，不阻塞 UI 与事件流；用户手动切节点后下次探测以新节点为准。
#[cfg(any(target_os = "ios", target_os = "android"))]
async fn run_node_failover(api: KernelApi, final_group: String, app_handle: AppHandle) {
    const TEST_URL: &str = "http://www.gstatic.com/generate_204";
    const TEST_TIMEOUT_MS: u32 = 3000;
    const FAIL_THRESHOLD: u8 = 2;

    let mut consecutive_failures: u8 = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(45)).await;
        // 内核已停止则退出：本次 handle 的事件流也被 abort，避免任务重复累积
        let running = *app_handle
            .state::<crate::core::state::AppState>()
            .status
            .read()
            == crate::core::state::CoreStatus::Running;
        if !running {
            break;
        }
        // 主组当前选中的节点
        let current = api.get_proxies().await.ok().and_then(|p| {
            p.get("proxies")
                .and_then(|m| m.get(&final_group))
                .and_then(|g| g.get("now"))
                .and_then(|v| v.as_str().map(String::from))
        });
        let Some(current) = current else { continue };
        // 策略组/内置出站不参与探测（组名或内置出口不可测速）
        if current == final_group
            || ["DIRECT", "REJECT", "PASS", "COMPATIBLE"].contains(&current.as_str())
        {
            continue;
        }

        if api.test_delay(&current, TEST_URL, TEST_TIMEOUT_MS).await.is_some() {
            if consecutive_failures > 0 {
                tracing::info!("节点 {current} 恢复可用，重置故障计数");
            }
            consecutive_failures = 0;
            continue;
        }

        consecutive_failures += 1;
        tracing::warn!(
            "节点 {current} 探测失败（连续 {consecutive_failures}/{FAIL_THRESHOLD}）"
        );
        if consecutive_failures < FAIL_THRESHOLD {
            continue;
        }
        consecutive_failures = 0;
        match auto_select_best_proxy(&api, &final_group, app_handle.clone()).await {
            Ok(()) => {
                let _ = app_handle.emit(
                    "failover://switched",
                    serde_json::json!({ "from": current }),
                );
                tracing::warn!("故障转移：{current} 不可用，已按三级规则重新选点");
            }
            Err(e) => tracing::warn!("故障转移自动选点失败: {e:#}"),
        }
    }
}

/// 并发测速给定节点列表，返回延迟最低者（全部失败返回 None）
#[cfg(any(target_os = "ios", target_os = "android"))]
async fn test_fastest(
    api: &KernelApi,
    nodes: &[String],
    url: &str,
    timeout_ms: u32,
) -> Option<(String, u64)> {
    let mut tasks: Vec<tokio::task::JoinHandle<Option<(String, u64)>>> =
        Vec::with_capacity(nodes.len());
    for node in nodes {
        let api = api.clone();
        let node = node.clone();
        let url = url.to_string();
        tasks.push(tokio::spawn(async move {
            let delay = api.test_delay(&node, &url, timeout_ms).await?;
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
    best
}

/// APP34：从已启用订阅的 profile 提取「节点名 → (server, port)」映射。
///
/// Clash API `/proxies` 只返回类型/延迟等元数据，不含 server/port；
/// 想在**主进程**做 TCP 握手测速（不占用 50MB 的扩展进程），必须回源
/// 订阅缓存解析出真实出口地址。
/// 【APP37 任务3】全平台可用：go_aim 快筛与整组测速的 Clash API
/// 失败回退（TcpStream::connect 握手）在桌面端同样需要。
#[cfg_attr(
    not(any(target_os = "ios", target_os = "android")),
    allow(dead_code)
)]
pub(crate) fn collect_node_endpoints(
    data_dir: &std::path::Path,
) -> std::collections::HashMap<String, (String, u16)> {
    use crate::core::config_builder::{is_builtin_non_proxy_tag, is_info_or_ad_node_name};
    let mut map = std::collections::HashMap::new();
    for record in crate::core::store::load_subscriptions(data_dir) {
        if !record.enabled {
            continue;
        }
        let path = crate::core::store::profile_path(data_dir, &record.url);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
            continue;
        };
        let Some(proxies) = value.get("proxies").and_then(|v| v.as_sequence()) else {
            continue;
        };
        for p in proxies {
            let name = crate::core::uri_parser::fix_utf8_mojibake(
                p.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            );
            let server = p.get("server").and_then(|v| v.as_str()).unwrap_or("");
            let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
            if name.is_empty() || server.is_empty() || !(2..=65535).contains(&port) {
                continue;
            }
            if is_builtin_non_proxy_tag(&name) || is_info_or_ad_node_name(&name) {
                continue;
            }
            if server.starts_with("127.") || server == "localhost" || server == "0.0.0.0" {
                continue;
            }
            map.entry(name)
                .or_insert_with(|| (server.to_string(), port as u16));
        }
    }
    map
}

/// 【APP42 任务1.3】URL 路径段百分号编码（保留 A-Za-z0-9-._~）。
/// Clash API 节点名常含 emoji/空格/斜杠/中文，直接拼进 URL 会构建失败。
pub(crate) fn encode_path_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 3);
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// 【APP42 任务1.3】RFC1918 / 回环 / 链路本地 / IPv6 ULA 判定
fn is_private_lan_ip(server: &str) -> bool {
    if let Ok(v4) = server.parse::<std::net::Ipv4Addr>() {
        return v4.is_private() || v4.is_loopback() || v4.is_link_local();
    }
    if let Ok(v6) = server.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback()
            || v6.is_unicast_link_local()
            || (v6.segments()[0] & 0xfe00) == 0xfc00;
    }
    false
}

/// 【APP42 任务1.3】主进程 TCP 握手测速（不占用扩展进程内存），
/// 超时/失败返回 None。
/// 注意：VPN 未运行时 TUN 不接管流量，此函数仅用于「启动前预选」；
/// 若握手 < 8ms 且目标不是局域网地址，视为本机劫持/回环假阳性，直接判失败，
/// 避免用户误以为节点可用。
#[allow(dead_code)] // iOS 端不使用启动前 TCP 预选（仅桌面/Android 预选路径调用）
pub(crate) async fn tcp_handshake_delay_ms(server: &str, port: u16, timeout_ms: u64) -> Option<u64> {
    use std::time::Instant;
    let start = Instant::now();
    match tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        tokio::net::TcpStream::connect((server, port)),
    )
    .await
    {
        Ok(Ok(_stream)) => {
            let elapsed = start.elapsed().as_millis() as u64;
            if elapsed < 8 && !is_private_lan_ip(server) {
                tracing::warn!("TCP 握手 {server}:{port} 仅 {elapsed}ms，判定为假阳性并丢弃");
                None
            } else {
                Some(elapsed)
            }
        }
        _ => None,
    }
}

/// APP34：主进程 TCP 握手测速选点。
///
/// 【APP37 任务3.1】严禁节点数量截断：全部有效节点滚动并发测速
/// （并发 8、单点超时 1500ms）。返回握手延迟最低者；全部失败返回 None。
#[cfg(any(target_os = "ios", target_os = "android"))]
pub(crate) async fn tcp_select_fastest(
    nodes: &[String],
    endpoints: &std::collections::HashMap<String, (String, u16)>,
) -> Option<(String, u64)> {
    use std::time::{Duration, Instant};
    use tokio::net::TcpStream;
    use tokio::sync::Semaphore;

    const CONCURRENCY: usize = 8;
    const TIMEOUT_MS: u64 = 1500;

    let candidates: Vec<(String, String, u16)> = nodes
        .iter()
        .filter_map(|n| {
            endpoints
                .get(n)
                .map(|(server, port)| (n.clone(), server.clone(), *port))
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }

    let sem = std::sync::Arc::new(Semaphore::new(CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();
    for (name, server, port) in candidates {
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let start = Instant::now();
            let connected = tokio::time::timeout(
                Duration::from_millis(TIMEOUT_MS),
                TcpStream::connect((server.as_str(), port)),
            )
            .await;
            match connected {
                Ok(Ok(_stream)) => Some((name, start.elapsed().as_millis() as u64)),
                _ => None,
            }
        });
    }

    let mut best: Option<(String, u64)> = None;
    while let Some(res) = set.join_next().await {
        if let Ok(Some((node, delay))) = res {
            if best.as_ref().is_none_or(|(_, d)| delay < *d) {
                best = Some((node, delay));
            }
        }
    }
    best
}
