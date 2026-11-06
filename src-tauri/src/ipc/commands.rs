//! Tauri commands，供前端通过 invoke() 调用

use std::sync::Arc;

use base64::{engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD}, Engine as _};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::core::kernel::{
    KernelApi, KernelConfig, KernelHandle, check_config, generate_secret, probe_version,
    sanitize_kernel_error,
};
use crate::core::license::EntitlementStatus;
use crate::core::state::{AppState, CoreStatus, OutboundMode, RunMode, UserSettings, pick_api_addr};

/// 返回前端前的错误文本统一脱敏（抹除内核商标字样）
fn sanitize_err(msg: &str) -> String {
    sanitize_kernel_error(msg)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreStatusDto {
    pub status: CoreStatus,
    pub mode: RunMode,
    pub uptime_secs: u64,
    /// 连接起始 Unix 毫秒时间戳（IPA-12）：前端亮屏 0ms 差值渲染的时钟基准；
    /// 未运行时为 null（前端回退由 uptimeSecs 推导）
    pub started_at_ms: Option<u64>,
    /// 主选择组（route.final 链上最深的 selector；内核未运行时为 None）
    pub main_selector: Option<String>,
    /// 出站模式（规则/全局/直连；Dashboard/Proxies 快捷切换条数据源）
    pub outbound_mode: OutboundMode,
    /// 【APP47 任务1.2】持久化的选中节点名（settings.selected_node）。
    /// 内核未运行时 Dashboard「当前节点」卡也展示上次选中的真实节点名，
    /// 不再显示「—」死状态。
    pub selected_node: Option<String>,
    /// 【APP54 任务1】是否有任一启用 Go Lan 档案处于「⚡ 局域网直连」状态
    pub go_lan_any_direct: bool,
    /// 【APP54 任务1】档案 id → 是否直连（Dashboard/设置页副标题数据源）
    pub go_lan_profile_direct_map: std::collections::HashMap<String, bool>,
    /// 【APP54 任务4】全量测速进度
    pub delay_progress: crate::core::state::ProbeProgress,
    /// 【APP54 任务4】Go AIM 探测进度
    pub aim_progress: crate::core::state::ProbeProgress,
}

/// 内核信息（设置页 / 下载向导用）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KernelInfoDto {
    pub exists: bool,
    pub path: Option<String>,
    pub version: Option<String>,
}

#[tauri::command]
pub async fn start_core(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    start_core_inner(&app, state.inner()).await
}

/// 启动内核的实际实现（Tauri 命令与「升级后自动重建隧道」共用）
async fn start_core_inner(app: &AppHandle, state: &AppState) -> Result<(), String> {
    // APP 远程管控（APP-4 任务2）：管控优先级最高——被管控的设备禁止启动内核
    if let Some(block) = state.control_block.read().clone() {
        return Err(block.message);
    }
    // 【APP43 任务2.2】重开 APP 场景：系统 VPN 隧道其实仍在运行（状态栏有
    // VPN 图标），用户再点「启动」时绝不重复冷启动报冲突——直接认领并返回成功。
    if *state.status.read() == CoreStatus::Stopped
        && crate::core::kernel::sync_or_recover_running_vpn(app, state).await
    {
        // 【APP48 任务3】系统隧道其实仍在运行 → 登记本地代理供授权容灾使用
        crate::core::license::set_local_mixed_port(state.settings.read().mixed_port);
        return Ok(());
    }
    // 【APP33 任务3.1】启动前纠偏 selected_node：若残留「剩余流量」等假
    // 节点，立即替换为真实节点并落盘，避免仪表盘与内核默认节点不一致。
    ensure_valid_selected_node(state);
    // 【APP52 任务4】[节点识别] 阶段一：启动前确认选中节点与主选择组，
    // 后续 [握手阶段]/[连接成功]/[流量开始转发] 均围绕该节点记录。
    {
        let node = state
            .settings
            .read()
            .selected_node
            .clone()
            .unwrap_or_else(|| "自动（等待测速）".into());
        let group = state.main_selector.read().clone().unwrap_or_else(|| "Proxy".into());
        crate::core::logger::info(
            crate::core::logger::MOD_NODE,
            &format!(
                "{} 选中节点「{node}」，主选择组「{group}」",
                crate::core::logger::PHASE_NODE_IDENT
            ),
        );
    }
    // 幂等：启动含下载内核/构建配置等长耗时步骤，期间重复点击或前端自动
    // 重试会再次进入本函数。只有一个调用完成 Stopped/Error -> Starting，
    // 其余若已在 Starting（启动进行中）或 Running（已启动）直接成功返回，
    // 避免抛出 "invalid state transition: Starting -> Starting"
    if let Err(e) = state.transition(CoreStatus::Starting) {
        let current = *state.status.read();
        if matches!(current, CoreStatus::Starting | CoreStatus::Running) {
            return Ok(());
        }
        return Err(sanitize_err(&e.to_string()));
    }

    // 启动失败时统一回滚，避免半成品状态
    if let Err(e) = do_start(app, state).await {
        let _ = do_stop(state).await;
        let _ = state.transition(CoreStatus::Error);
        return Err(e);
    }

    *state.started_at.write() = Some(std::time::Instant::now());
    state
        .transition(CoreStatus::Running)
        .map_err(|e| sanitize_err(&e.to_string()))?;
    // 【APP52 任务4】[连接成功] 阶段三：内核已 Running，开始接管流量
    {
        let node = state
            .settings
            .read()
            .selected_node
            .clone()
            .unwrap_or_else(|| "自动".into());
        crate::core::logger::info(
            crate::core::logger::MOD_NODE,
            &format!(
                "{} 内核已运行，当前节点「{node}」开始接管流量",
                crate::core::logger::PHASE_CONNECTED
            ),
        );
    }
    // 【APP48 任务3】内核运行中：授权请求优先借道本地混合代理穿透阻断
    crate::core::license::set_local_mixed_port(state.settings.read().mixed_port);

    // 启动后自动测速并切换到延迟最低的可用节点（用户随后仍可手动改选）
    // 【APP26 任务2.3】仅当未开启 Go AIM 且用户从未手动点选节点时才自动优选
    // APP34：移动端由内核启动流程（kernel.rs auto_select_best_proxy）统一
    // 负责自动选点，这里跳过，避免同一轮启动并发两套测速重复轰击扩展内存。
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    if should_auto_select(state)
        && let Some(group) = state.main_selector.read().clone()
    {
        spawn_auto_select(
            app.clone(),
            state.api_addr.read().clone(),
            state.api_secret.read().clone(),
            group,
        );
    }
    // 【APP6 任务2】iOS 上 VPN 运行在独立 PrismVPN 扩展进程，此前启动后
    // 从不执行首次内网握手激活；这里无论平台统一在启动成功后对开启的
    // Go Lan 触发一次 WireGuard 握手（发包即握手，wg-easy 立即显示在线）
    {
        crate::core::logger::info(
            crate::core::logger::MOD_KERNEL,
            &format!("VPN 内核启动成功（模式切换至 {:?}）", state.mode.read()),
        );
        let lan = state.go_lan.read().clone();
        if lan.enabled && crate::core::go_lan::is_configured(&lan) {
            crate::core::logger::info(
                crate::core::logger::MOD_GO_LAN,
                "VPN 启动完成，自动触发 go-lan-home 首次握手",
            );
            spawn_go_lan_warmup(
                state.api_addr.read().clone(),
                state.api_secret.read().clone(),
                &lan,
            );
        }
    }
    Ok(())
}

/// 覆盖升级后自动重建隧道（APP-5 任务2，仅 iOS 由 lib.rs setup 调用）。
/// 升级前隧道在使用中且旧扩展已被清理时，用户无需手动点「连接」。
pub async fn auto_start_after_upgrade(
    app: AppHandle,
    state: &AppState,
) -> Result<(), String> {
    start_core_inner(&app, state).await
}

/// 启动准备结果：校验通过但尚未停机/启动（restart 时先产出它再做静态校验）
struct PreparedStart {
    settings: UserSettings,
    work_dir: std::path::PathBuf,
    api_addr: String,
    api_secret: String,
    built: crate::core::config_builder::BuiltConfig,
    binary_path: std::path::PathBuf,
}

/// 启动前的全部准备与校验（不提权变更、不写内核状态）：
/// 提权预检 → 工作目录 → 订阅 profile → 内核二进制 → 端口预检 → 构建配置
async fn prepare_start(app: &AppHandle, state: &AppState) -> Result<PreparedStart, String> {
    let mode = *state.mode.read();
    let settings = state.settings.read().clone();

    // 提权/授权预检：
    // - 桌面 TUN 模式：非管理员/root 时 tun inbound 必然失败，提前报错
    // - 移动端：系统 VPN 授权（Android VpnService.prepare）。
    //   未授权时返回 false，前端提示用户在系统弹窗中允许后重试
    //   （IPA-12 2.3：ensurePermission 内部经 runOnUiThread 弹窗 + latch
    //   阻塞等待最长 60s，必须放 spawn_blocking，防止卡死 Tokio worker）
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        let granted =
            tauri::async_runtime::spawn_blocking(crate::platform::ensure_vpn_permission)
                .await
                .map_err(|e| format!("VPN 授权检查任务异常退出: {e}"))?
                .map_err(|e| sanitize_err(&e.to_string()))?;
        if !granted {
            return Err("需要系统 VPN 授权：请在弹出的系统对话框中点击「允许」，然后再次点击启动".into());
        }
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    if mode == RunMode::Tun && !crate::platform::has_elevated_privilege() {
        return Err(
            "TUN 模式需要管理员/root 权限：请完全退出 Prism 后以管理员身份重新运行（macOS/Linux 使用 sudo）"
                .into(),
        );
    }

    let work_dir = state.work_dir();
    std::fs::create_dir_all(&work_dir)
        .map_err(|e| format!("创建内核工作目录失败: {}", e))?;

    // 读取全部启用订阅的 profile（多订阅模型；旧版单 profile.yaml 自动兼容）
    let profiles = load_enabled_profiles(state);
    if profiles.is_empty() {
        // 空缓存兜底（ipa-8）：启用订阅存在但内容未拉取成功（云同步对账
        // 时网络抖动只建了保底记录）→ 启动前自动补拉一次，避免用户必须
        // 先去订阅页手动更新。仅在非运行态执行：restart_core 期间内核
        // 仍在运行，refresh_subscription 会再次触发重启造成递归
        if *state.status.read() != CoreStatus::Running {
            let records = crate::core::store::load_subscriptions(&state.data_dir);
            for r in records.iter().filter(|r| r.enabled) {
                let path = crate::core::store::profile_path(&state.data_dir, &r.url);
                if !path.exists() {
                    tracing::info!("启动前自动补拉缺失缓存的订阅：{}", r.url);
                    // Box::pin 打断 prepare_start → refresh_subscription →
                    // restart_core → prepare_start 的静态递归环（运行时已有
                    // status != Running 守卫，实际不会递归执行）
                    if let Err(e) =
                        Box::pin(refresh_subscription(app, state, &r.url)).await
                    {
                        tracing::warn!("启动前补拉失败（继续启动流程）：{e}");
                    }
                }
            }
            // 自动补拉后不再读取 profiles：下方直接返回错误提示
        }
        let has_records =
            !crate::core::store::load_subscriptions(&state.data_dir).is_empty();
        return Err(if has_records {
            "订阅内容缺失（本地缓存不存在）：请在「订阅」页点击更新，成功后再启动内核".into()
        } else {
            "尚未导入订阅：请先在「订阅」页添加订阅".into()
        });
    }

    // 内核必须随安装包分发，任何平台都不运行时联网下载：
    // - 桌面：Tauri sidecar（bundle.externalBin）
    // - iOS/Android：c-archive 静态链接进主程序（ios-kernel，无二进制路径）
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    let binary_path = resolve_kernel_path(&work_dir).map_err(|_| {
        "内核文件缺失（Prism 不会联网下载内核）：请重新安装 Prism；若被安全软件删除或隔离，请恢复后重试"
    })?;
    #[cfg(any(target_os = "ios", target_os = "android"))]
    let binary_path = std::path::PathBuf::new();

    // 端口预检，避免与本机其他代理内核冲突。
    // 移动端 mixed 入站已移除（流量全走 TUN），无需检查混合端口。
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let listen_host = if settings.allow_lan { "0.0.0.0" } else { "127.0.0.1" };
        if !crate::core::state::is_port_free(listen_host, settings.mixed_port) {
            return Err(format!(
                "混合端口 {} 已被占用，请在“设置”中更换端口后重试",
                settings.mixed_port
            ));
        }
    }

    // clash_api 动态选址/密钥；仅在本地持有，apply_prepared 时才写入状态
    let api_addr = pick_api_addr();
    let api_secret = generate_secret();

    // 配置构建：自定义规则 + Clash YAML（多订阅合并）→ sing-box runtime JSON
    // Go Lan / Go Cus 仅在授权激活时生效（未激活传入默认配置 = 完全关闭）
    let custom_rules = crate::core::store::load_custom_rules(&state.data_dir);
    let pro_unlocked = state.is_pro_active();
    let (go_lan_cfg, go_cus_cfg) = if pro_unlocked {
        (state.go_lan.read().clone(), state.go_cus.read().clone())
    } else {
        (Default::default(), Default::default())
    };
    let built = crate::core::config_builder::build(
        &profiles,
        &custom_rules,
        mode,
        &settings,
        &state.data_dir,
        &work_dir,
        &api_addr,
        &api_secret,
        &go_lan_cfg,
        &go_cus_cfg,
    )
    .map_err(|e| sanitize_err(&e.to_string()))?;

    // 【APP43 任务2】构建后校验是否存在至少一个「真实叶子节点」：
    // 排除 direct/reject/block/dns/go-lan-* 内置/系统标签；订阅里全是
    // info/ad 假节点（"剩余流量 100GB"、"节点名称 | 机场"）或机场占位
    // 127.0.0.1 时，内核虽能启动但无节点可连——直接给用户明确友好提示，
    // 不让他看到仪表盘一堆 0ms 或空白。
    {
        let real_count = built
            .config
            .get("outbounds")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|o| {
                        let Some(tag) = o.get("tag").and_then(|v| v.as_str()) else {
                            return false;
                        };
                        let Some(otype) = o.get("type").and_then(|v| v.as_str()) else {
                            return false;
                        };
                        if matches!(otype, "direct" | "block" | "dns" | "oracle") {
                            return false;
                        }
                        if tag.starts_with("go-lan")
                            || tag.starts_with("go-lan-")
                            || tag == "go-lan"
                        {
                            return false;
                        }
                        // 系统 DNS / 内置控制器出站
                        if tag.starts_with("dns-")
                            || tag == "dns-local"
                            || tag == "dns-remote"
                            || tag == "dns-direct"
                            || tag.starts_with("ctrl-")
                        {
                            return false;
                        }
                        true
                    })
                    .count()
            })
            .unwrap_or(0);
        if real_count == 0 {
            return Err(
                "当前订阅未解析到任何可连接的实际节点：可能是机场面板限流、订阅链接已失效，或返回了机场公告页。请在「订阅」页点击更新，成功后再启动内核。".into(),
            );
        }
    }
    for warning in &built.warnings {
        tracing::warn!("config builder: {}", warning);
    }

    Ok(PreparedStart {
        settings,
        work_dir,
        api_addr,
        api_secret,
        built,
        binary_path,
    })
}

/// 应用已校验的启动准备：写 API 状态 → 启动内核 → 主选择组 → 系统代理
async fn apply_prepared(
    prepared: PreparedStart,
    app: &AppHandle,
    state: &AppState,
) -> Result<(), String> {
    let PreparedStart {
        settings,
        work_dir,
        api_addr,
        api_secret,
        built,
        binary_path,
    } = prepared;

    *state.api_addr.write() = api_addr.clone();
    *state.api_secret.write() = api_secret.clone();
    tracing::info!("clash api listening on {api_addr}");
    // 【APP52 任务4】[握手阶段] 发起：记录内核进程启动与 Clash API 接管
    crate::core::logger::info(
        crate::core::logger::MOD_NODE,
        &format!(
            "{} 发起内核握手：Clash API {api_addr}",
            crate::core::logger::PHASE_HANDSHAKE
        ),
    );
    let handshake_started = std::time::Instant::now();

    let kernel_config = KernelConfig {
        binary_path: binary_path.clone(),
        work_dir: work_dir.clone(),
        api_addr,
        api_secret,
        runtime_config: built.config,
    };

    let handle = KernelHandle::spawn(kernel_config, app.clone())
        .await
        .map_err(|e| format!("内核启动失败: {}", sanitize_err(&e.to_string())))?;

    // 探测并缓存版本号供设置页展示（失败不影响启动）
    if let Some(version) = probe_version(&binary_path).await {
        tracing::info!("kernel version: {version}");
        *state.kernel_version.write() = Some(version);
    }

    *state.kernel_handle.write() = Some(Arc::new(handle));

    // 内核启动成功：清空运行时统计（60s 队列 / 活跃连接 / 分析聚合），
    // 今日流量基数不动（事件流随后会重新填充）
    state.reset_runtime_stats();

    // 解析主选择组：route.final 沿 selector 链走到最深的选择组。
    // 节点页默认落在该组——GLOBAL 等虚拟组不在路由链路中，在其中选节点不会生效。
    let api = state.kernel_api();
    let main = resolve_main_selector(&api, &built.final_group).await;
    if let Some(group) = &main {
        tracing::info!("main selector group: {group} (final: {})", built.final_group);
    } else {
        tracing::warn!(
            "no main selector resolved from final group '{}'",
            built.final_group
        );
    }
    *state.main_selector.write() = main.clone();
    // 【APP52 任务4】[握手阶段] RTT 完成：内核 API 已应答并解析出主选择组
    crate::core::logger::info(
        crate::core::logger::MOD_NODE,
        &format!(
            "{} RTT 完成：{}ms，主选择组 {}",
            crate::core::logger::PHASE_HANDSHAKE,
            handshake_started.elapsed().as_millis(),
            main.as_deref().unwrap_or("未解析")
        ),
    );

    // 出站模式同步（build 157）：内核启动后 Clash API 默认为 rule，用户
    // 保存的全局/直连必须立即 PATCH 生效，否则显示与实际路由脱节
    {
        let mode_str = match state.settings.read().outbound_mode {
            OutboundMode::Rule => "rule",
            OutboundMode::Global => "global",
            OutboundMode::Direct => "direct",
        };
        if mode_str != "rule" {
            if let Err(e) = state.kernel_api().patch_mode(mode_str).await {
                tracing::warn!("启动后同步出站模式失败: {e}");
            }
        }
    }

    // TUN 模式下路由由内核 auto_route 接管；系统代理模式按用户设置写入系统代理
    if *state.mode.read() == RunMode::SystemProxy && settings.system_proxy {
        // 备份当前系统代理，确保停止时可恢复（代理独占：只有当前 APP 的设置生效）
        if let Ok(backup) = crate::platform::get_system_proxy() {
            *state.proxy_backup.write() = Some(backup);
        }
        crate::platform::set_system_proxy("127.0.0.1", settings.mixed_port)
            .map_err(|e| sanitize_err(&e.to_string()))?;
    }

    // Go Cus 边车：授权激活且启用覆写时拉起本地处理服务（进程内单例）
    {
        let pro_unlocked = state.is_pro_active();
        if pro_unlocked && state.go_cus.read().enabled {
            crate::core::go_cus::ensure_sidecar(app.clone());
        }
    }

    // Go AIM（Pro）：授权激活即后台探测评级；开关打开时自动锁定 + 故障转移监控
    {
        let pro_unlocked = state.is_pro_active();
        if pro_unlocked {
            let enabled = state.settings.read().go_aim_enabled;
            if enabled {
                crate::core::go_aim::spawn_monitor(app.clone());
            }
            crate::core::go_aim::start_probe(app.clone());
        }
    }

    Ok(())
}

async fn do_start(app: &AppHandle, state: &AppState) -> Result<(), String> {
    let prepared = prepare_start(app, state).await?;
    apply_prepared(prepared, app, state).await
}

/// 收集启用订阅的 profile 内容；无记录时回退旧版 work_dir/profile.yaml（升级兼容）。
/// 元素：(订阅URL, 展示名, profile内容)
fn load_enabled_profiles(state: &AppState) -> Vec<(String, String, String)> {
    let records = crate::core::store::load_subscriptions(&state.data_dir);
    let enabled: Vec<_> = records.iter().filter(|r| r.enabled).cloned().collect();
    let mut profiles = Vec::new();

    // 旧版（单订阅时代）内容落盘位置，仅用于一次性迁移
    let legacy_candidates = [
        state.data_dir.join("profile.yaml"),
        state.work_dir().join("profile.yaml"),
    ];
    let legacy_text: Option<String> = legacy_candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok());

    for (i, record) in enabled.iter().enumerate() {
        let path = crate::core::store::profile_path(&state.data_dir, &record.url);
        // 已缓存内容必须是含节点的有效 Clash YAML；空壳（如机场返回的
        // JSON 错误页）视为缺失，走旧版迁移兜底恢复
        let cached_valid = std::fs::read_to_string(&path)
            .ok()
            .filter(|text| {
                crate::core::config_builder::validate_subscription_text(text)
                    .map(|_| true)
                    .unwrap_or_else(|e| {
                        tracing::warn!("cached profile invalid for {}: {e}", record.url);
                        false
                    })
            });
        let text = match cached_valid {
            Some(text) => text,
            None => {
                // 新版按 URL 哈希落盘；旧版本内容在 data_dir/profile.yaml 或
                // kernel/profile.yaml——首次升级时迁移到哈希路径，后续逻辑统一
                if let Some(text) = &legacy_text {
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    if std::fs::write(&path, text).is_ok() {
                        tracing::info!("migrated legacy profile.yaml -> {}", path.display());
                        text.clone()
                    } else {
                        tracing::warn!("profile missing and legacy migration failed: {}", path.display());
                        continue;
                    }
                } else {
                    tracing::warn!("read profile failed for {}: file missing", record.url);
                    continue;
                }
            }
        };
        let name = record
            .name
            .clone()
            .unwrap_or_else(|| format!("订阅{}", i + 1));
        profiles.push((record.url.clone(), name, text));
    }
    // 无任何启用记录时，旧版单 profile.yaml 仍可兜底
    if profiles.is_empty()
        && let Some(text) = legacy_text
    {
        profiles.push((String::new(), "默认".to_string(), text));
    }
    profiles
}

/// 重建配置并重启内核（调用方保证当前为 Running）。
/// 先构建并静态校验新配置，通过后才停旧内核；校验失败则网络不中断。
pub(crate) async fn restart_core(app: &AppHandle, state: &AppState) -> Result<(), String> {
    // APP 远程管控：被管控的设备禁止重启内核（与 start_core 同一优先级）
    if let Some(block) = state.control_block.read().clone() {
        return Err(block.message);
    }
    // 1. 准备新配置（不改变任何状态）
    let prepared = prepare_start(app, state).await?;

    // 2. sing-box check 静态校验
    let check_path = state.work_dir().join("config.precheck.json");
    let bytes = serde_json::to_vec_pretty(&prepared.built.config)
        .map_err(|e| format!("序列化预检配置失败: {e}"))?;
    std::fs::write(&check_path, bytes).map_err(|e| format!("写入预检配置失败: {e}"))?;
    if let Err(e) = check_config(&prepared.binary_path, &state.work_dir(), &check_path).await {
        let _ = std::fs::remove_file(&check_path);
        return Err(sanitize_err(&e.to_string()));
    }
    let _ = std::fs::remove_file(&check_path);

    // 3. 停止旧内核
    state
        .transition(CoreStatus::Stopping)
        .map_err(|e| sanitize_err(&e.to_string()))?;
    if let Err(e) = do_stop(state).await {
        let _ = state.transition(CoreStatus::Error);
        return Err(sanitize_err(&e.to_string()));
    }
    *state.started_at.write() = None;
    state
        .transition(CoreStatus::Stopped)
        .map_err(|e| sanitize_err(&e.to_string()))?;

    // 4. 应用已校验的配置启动新内核；失败仍转 Error 允许重试
    state
        .transition(CoreStatus::Starting)
        .map_err(|e| sanitize_err(&e.to_string()))?;
    if let Err(e) = apply_prepared(prepared, app, state).await {
        let _ = do_stop(state).await;
        let _ = state.transition(CoreStatus::Error);
        return Err(e);
    }
    *state.started_at.write() = Some(std::time::Instant::now());
    state
        .transition(CoreStatus::Running)
        .map_err(|e| sanitize_err(&e.to_string()))?;
    crate::core::license::set_local_mixed_port(state.settings.read().mixed_port);

    // 与 start_core 一致：重启后自动测速选点（APP26：同样受 Go AIM /
    // 用户手动选点条件约束）
    // APP34：移动端重启后的选点由 kernel.rs 统一负责，这里跳过避免重复测速。
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    if should_auto_select(state)
        && let Some(group) = state.main_selector.read().clone()
    {
        spawn_auto_select(
            app.clone(),
            state.api_addr.read().clone(),
            state.api_secret.read().clone(),
            group,
        );
    }
    Ok(())
}

/// 从 route.final 沿 selector 链解析「主选择组」：
/// 该组成员为叶子节点（或 urltest 组），用户的选择真实影响出口流量。
async fn resolve_main_selector(api: &KernelApi, final_group: &str) -> Option<String> {
    let proxies = api.get_proxies().await.ok()?;
    let map = proxies.get("proxies")?.as_object()?;

    // 顶层 selector 即主选择组（build 159 用户方案）：不再沿 now 下钻——
    // 订阅顶层组默认选中地区子分组时，旧逻辑会把 main_selector 落到
    // 只含少量节点的子分组，启动后节点列表从 49 个缩成 10 个。
    // config_builder 已把全部真实节点合并进顶层组，这里直接返回 final
    let entry = map.get(final_group)?;
    if entry.get("type")?.as_str()? == "Selector" {
        Some(final_group.to_string())
    } else {
        // final 直指 urltest/叶子：无可手选的 selector
        None
    }
}

/// 【APP43 任务3】是否应执行「自动整组测速选最优节点」：
/// 仅当 Go AIM 未开启、内核未运行中、且当前选中节点可能是废节点（手动纠偏后
/// 会自动触发）——Pro 和非 Pro 均跑，不做「用户是否手动选过节点」的短路；
/// 用户手动选点只是让 selected_node 立即切到目标节点，但后台整组测速依然跑：
/// 一方面更新每个节点的实时延迟，另一方面如果所有节点均不可用则选出相对
/// 最优（哪怕延迟大）自动兜底，避免仪表盘空白。
fn should_auto_select(state: &AppState) -> bool {
    if state.settings.read().go_aim_enabled {
        return false;
    }
    true
}

/// 【APP33 任务3.1】selected_node 自愈：若当前选中节点为「剩余流量」等
/// 假节点或不在有效节点列表中，自动替换为首个真实节点并写回 settings.json，
/// 杜绝仪表盘「当前节点」长期残留假节点名。返回纠偏后的节点名（可能为 None）。
fn ensure_valid_selected_node(state: &AppState) -> Option<String> {
    // 从已启用订阅加载真实节点名集合
    let mut valid: Vec<String> = Vec::new();
    let records = crate::core::store::load_subscriptions(&state.data_dir);
    for r in records {
        if !r.enabled {
            continue;
        }
        let path = crate::core::store::profile_path(&state.data_dir, &r.url);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
            if let Some(proxies) = value.get("proxies").and_then(|v| v.as_sequence()) {
                for p in proxies {
                    let name = crate::core::uri_parser::fix_utf8_mojibake(
                        p.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                    let server = p.get("server").and_then(|v| v.as_str()).unwrap_or("");
                    let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                    if name.is_empty() || server.is_empty() || port <= 1 {
                        continue;
                    }
                    if crate::core::config_builder::is_builtin_non_proxy_tag(&name) {
                        continue;
                    }
                    if crate::core::config_builder::is_info_or_ad_node_name(&name) {
                        continue;
                    }
                    if server.starts_with("127.") || server == "localhost" || server == "0.0.0.0" {
                        continue;
                    }
                    if !valid.contains(&name) {
                        valid.push(name);
                    }
                }
            }
        }
    }

    let cur = state.settings.read().selected_node.clone();
    let needs_correct = match &cur {
        None => true,
        Some(n) => {
            crate::core::config_builder::is_info_or_ad_node_name(n) || !valid.contains(n)
        }
    };
    if needs_correct {
        if let Some(pick) = valid.first() {
            let mut settings = state.settings.read().clone();
            settings.selected_node = Some(pick.clone());
            settings.user_manually_selected_node = false;
            if let Err(e) = state.save_settings(settings) {
                tracing::error!("save corrected selected_node failed: {e}");
            }
            *state.user_manually_selected_node.write() = false;
            tracing::info!("[APP33] selected_node 纠偏：{:?} -> {}", cur, pick);
            return Some(pick.clone());
        }
    }
    cur
}

/// 后台任务：对主选择组整组测速，自动切换到延迟最低的可用叶子节点
fn spawn_auto_select(app: AppHandle, api_addr: String, api_secret: String, group: String) {
    tauri::async_runtime::spawn(async move {
        use tauri::Emitter as _;
        // 【APP26 任务2.3 时机2】启动成功后延迟 800ms 再整组测速：给内核
        // Clash API 与代理连接留出就绪时间，测速结果更准确
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        // 等待期间用户手动点选节点或开启了 Go AIM → 尊重用户，不覆盖
        {
            let st = app.state::<AppState>();
            if !should_auto_select(&st) {
                tracing::info!("auto select skipped: Go AIM 已开启或用户已手动选点");
                return;
            }
        }
        let api = KernelApi::new(&api_addr, &api_secret);
        let data_dir = app.state::<AppState>().data_dir.clone();
        match auto_select_fastest(&api, &group, &data_dir).await {
            Ok(Some(best)) => {
                tracing::info!("auto selected fastest node in [{group}]: {best}");
                // 通知节点页刷新（当前选中项/延迟已变化）
                let _ = app.emit("proxies://changed", ());
            }
            Ok(None) => tracing::warn!("auto select: no alive leaf node in [{group}]"),
            Err(e) => tracing::warn!("auto select in [{group}] failed: {e}"),
        }
    });
}

/// 整组测速并选择最优叶子节点；返回被选中的节点名。
/// direct 延迟最低但无法翻墙，嵌套策略组也不可作为目标，均需排除。
///
/// APP34：移动端严禁整组 Clash API 测速（148 节点并发会瞬间撑爆 iOS
/// 扩展进程 50MB Jetsam 红线）——改为主进程 TCP 握手轻量测速。
async fn auto_select_fastest(
    api: &KernelApi,
    group: &str,
    data_dir: &std::path::Path,
) -> anyhow::Result<Option<String>> {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        let endpoints = crate::core::kernel::collect_node_endpoints(data_dir);
        if endpoints.is_empty() {
            tracing::warn!("auto select: 无可用节点 server/port，跳过 TCP 测速");
            return Ok(None);
        }
        let proxies = api.get_proxies().await?;
        let empty = serde_json::Map::new();
        let map = proxies
            .get("proxies")
            .and_then(|p| p.as_object())
            .unwrap_or(&empty);
        let members: Vec<String> = map
            .get(group)
            .and_then(|g| g.get("all"))
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let candidates: Vec<String> = members
            .into_iter()
            .filter(|n| !crate::core::config_builder::is_builtin_non_proxy_tag(n))
            .filter(|n| map.get(n).map(|i| i.get("all").is_none()).unwrap_or(true))
            .collect();
        let best = crate::core::kernel::tcp_select_fastest(&candidates, &endpoints).await;
        if let Some((name, _)) = &best {
            // 仅发送 1 次 PUT 切换，避免任何额外重启动作
            api.select_proxy(group, name).await?;
        }
        return Ok(best.map(|(name, _)| name));
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        // 桌面端无需回源订阅缓存（Clash API 整组测速即可）
        let _ = data_dir;
        const GROUP_TYPES: [&str; 4] = ["Selector", "URLTest", "Fallback", "LoadBalance"];

        let delays = api.group_url_test(group, None, Some(2000), None).await?;
        let proxies = api.get_proxies().await?;
        let empty = serde_json::Map::new();
        let map = proxies
            .get("proxies")
            .and_then(|p| p.as_object())
            .unwrap_or(&empty);

        let members_all: Vec<String> = map
            .get(group)
            .and_then(|g| g.get("all"))
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let real_leafs: Vec<String> = members_all
            .into_iter()
            .filter(|n| !crate::core::config_builder::is_builtin_non_proxy_tag(n.as_str()))
            .filter(|n| {
                let kind = map
                    .get(n)
                    .and_then(|e| e.get("type"))
                    .and_then(|t| t.as_str())
                    .unwrap_or_default();
                !GROUP_TYPES.contains(&kind)
            })
            .collect();

        // 全量跑完，按延迟升序；全部 null 时兜底选第一个真实叶子节点，避免仪表盘空白
        let mut ranked: Vec<(String, u64)> = delays
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(name, _)| real_leafs.contains(name))
            .filter_map(|(name, delay)| delay.as_u64().map(|d| (name.clone(), d)))
            .collect();
        ranked.sort_by_key(|(_, d)| *d);

        let best = ranked
            .first()
            .map(|(n, _)| n.clone())
            .or_else(|| real_leafs.first().cloned());

        if let Some(best) = &best {
            api.select_proxy(group, best).await?;
        }
        Ok(best)
    }
}

/// 解析 sing-box 二进制位置，优先级：
/// 1. 环境变量 PRISM_KERNEL_PATH
/// 2. 内核工作目录内 sing-box[.exe]（历史版本/手动放置位置）
/// 3. 主程序同级目录 sing-box[.exe]
/// （iOS/Android 内核内嵌于主程序，无独立二进制可解析）
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub(crate) fn resolve_kernel_path(work_dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let exe_name = if cfg!(windows) {
        "sing-box.exe"
    } else {
        "sing-box"
    };

    let candidates: Vec<std::path::PathBuf> = match std::env::var("PRISM_KERNEL_PATH") {
        Ok(path) => vec![path.into()],
        Err(_) => {
            let mut list = vec![
                crate::core::kernel::kernel_binary_path(work_dir),
            ];
            if let Ok(exe) = std::env::current_exe()
                && let Some(dir) = exe.parent()
            {
                list.push(dir.join(exe_name));
            }
            list
        }
    };

    for path in candidates {
        if path.is_file() {
            tracing::info!("using kernel binary: {}", path.display());
            return Ok(path);
        }
    }

    anyhow::bail!("未找到内核二进制")
}

#[tauri::command]
pub async fn stop_core(state: State<'_, AppState>) -> Result<(), String> {
    // 幂等：停止需要等待内核退出（最长 5 秒），期间重复点击/退出清理
    // 会再次进入本函数。transition 内部持写锁，并发下只有一个调用能
    // 完成 Running -> Stopping，其余落入此分支直接忽略
    if let Err(e) = state.transition(CoreStatus::Stopping) {
        let current = *state.status.read();
        if matches!(current, CoreStatus::Stopped | CoreStatus::Stopping) {
            return Ok(());
        }
        return Err(sanitize_err(&e.to_string()));
    }

    if let Err(e) = do_stop(&state).await {
        // 停止失败不能留在 Stopping（没有出边，会永久卡死），转入 Error 允许重试
        let _ = state.transition(CoreStatus::Error);
        return Err(sanitize_err(&e.to_string()));
    }
    *state.started_at.write() = None;

    state
        .transition(CoreStatus::Stopped)
        .map_err(|e| sanitize_err(&e.to_string()))?;
    Ok(())
}

/// 停止/退出时统一调用：回收 TUN 守卫 → 停内核 → 清系统代理
pub(crate) async fn do_stop(state: &AppState) -> anyhow::Result<()> {
    // 【APP6 任务1】[Kernel] 模块日志：VPN 停止
    crate::core::logger::info(crate::core::logger::MOD_KERNEL, "正在停止 VPN 内核...");
    // 1. 关闭 TUN 守卫（手动路由/DNS 回滚，通常为 None）
    // 先在独立语句完成 write()，避免临时写守卫跨越 await（parking_lot 守卫 !Send）
    let tun_taken = state.tun_guard.write().take();
    if let Some(mut guard) = tun_taken {
        guard.disable().await?;
    }

    // 2. 停止内核
    let handle = state.kernel_handle.write().take();
    if let Some(handle) = handle {
        handle.shutdown().await?;
    }

    // 3. 恢复系统代理到启动前状态（代理独占：停止后归还控制权）
    let backup = state.proxy_backup.write().take();
    match backup {
        Some(backup) if backup.enabled && !backup.server.is_empty() => {
            if let Err(e) = crate::platform::restore_system_proxy(&backup) {
                tracing::warn!("restore system proxy failed: {e}");
                crate::platform::clear_system_proxy()?;
            }
        }
        _ => {
            // 无备份或之前未启用代理，直接清除
            crate::platform::clear_system_proxy()?;
        }
    }

    // 4. 会话归档：把本次会话累计写入今日基数并归零内存运行时统计
    // （内核停止 → 今日流量基数保持，重启后今日流量不丢）
    if let Err(e) = crate::core::store::archive_session(&state.data_dir) {
        tracing::warn!("归档会话流量失败: {e}");
    }
    state.reset_runtime_stats();
    *state.today_bytes_cache.write() = crate::core::store::today_total_bytes(&state.data_dir);
    // 【APP48 任务3】内核已停：授权请求不再借道本地代理，回落到 DoH/直连
    crate::core::license::clear_local_mixed_port();

    Ok(())
}

#[tauri::command]
pub async fn get_core_status(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreStatusDto, String> {
    // 【APP43 任务2.2】状态自检：VPN 在后台运行（状态栏有图标）时重开 APP，
    // 每次状态轮询都尝试自动认领存活隧道，恢复「已连接」与计时器；
    // 内部 3s 节流 + 300ms 探活超时，不会拖慢 IPC。
    if *state.status.read() == CoreStatus::Stopped {
        let _ = crate::core::kernel::sync_or_recover_running_vpn(&app, state.inner()).await;
    }

    let uptime_secs = state
        .started_at
        .read()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    // 【APP33 任务3.1】仪表盘每次刷新状态时纠偏 selected_node：
    // 若为「剩余流量：96GB」等假节点或已不存在，自动替换为真实节点并落盘。
    ensure_valid_selected_node(state.inner());

    // 【APP54 任务1】Go Lan 直连状态随状态查询一起下发（Dashboard 副标题 /
    // 设置页徽章无需额外 IPC 往返）。未启用 Go Lan 时零开销直接返回空表。
    let lan = state.go_lan.read().clone();
    let (go_lan_any_direct, go_lan_profile_direct_map) = if lan.enabled {
        let physical = crate::core::go_lan::detect_physical_lan_ipv4s();
        let profiles = crate::core::go_lan::enabled_profiles(&lan);
        let map: std::collections::HashMap<String, bool> = {
            let phys = physical.clone();
            tokio::task::spawn_blocking(move || {
                profiles
                    .into_iter()
                    .map(|(_, p)| {
                        let hit = crate::core::go_lan::is_profile_lan_direct_active(&p, &phys);
                        (p.id.clone(), hit)
                    })
                    .collect::<std::collections::HashMap<String, bool>>()
            })
            .await
            .unwrap_or_default()
        };
        let any = map.values().any(|v| *v);
        (any, map)
    } else {
        (false, std::collections::HashMap::new())
    };

    Ok(CoreStatusDto {
        status: *state.status.read(),
        mode: *state.mode.read(),
        uptime_secs,
        started_at_ms: *state.started_at_ms.read(),
        main_selector: state.main_selector.read().clone(),
        outbound_mode: state.settings.read().outbound_mode,
        selected_node: state.settings.read().selected_node.clone(),
        go_lan_any_direct,
        go_lan_profile_direct_map,
        delay_progress: state.delay_progress.lock().clone(),
        aim_progress: state.aim_progress.lock().clone(),
    })
}

#[tauri::command]
pub fn set_app_foreground(foreground: bool, state: State<'_, AppState>) {
    state
        .app_in_foreground
        .store(foreground, std::sync::atomic::Ordering::Relaxed);
}

#[tauri::command]
pub async fn set_mode(
    requested_mode: RunMode,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // iOS 强制 TUN 模式（build 149 方案）：不存在桌面端系统代理，
    // 前端若仍传 SystemProxy 一律归一为 Tun
    #[cfg(target_os = "ios")]
    let mode = {
        let _ = requested_mode;
        RunMode::Tun
    };
    #[cfg(not(target_os = "ios"))]
    let mode = requested_mode;
    let prev = *state.mode.read();
    if prev == mode {
        return Ok(());
    }
    *state.mode.write() = mode;
    // 【APP54 任务3】规则模块：运行模式切换
    crate::core::logger::info(
        crate::core::logger::MOD_RULE,
        &format!("运行模式切换: {prev:?} → {mode:?}"),
    );

    // 持久化到 settings.json，重启应用后恢复同一模式（仪表盘显示才有权威来源）
    let mut settings = state.settings.read().clone();
    settings.mode = mode;
    state
        .save_settings(settings)
        .map_err(|e| format!("保存运行模式失败: {e}"))?;

    // 内核运行中：模式决定入站结构与系统代理行为，必须重建配置重启才能真实生效，
    // 否则显示的模式与实际代理效果必然不一致
    if *state.status.read() == CoreStatus::Running {
        tracing::info!("mode changed {prev:?} -> {mode:?}, restarting core");
        restart_core(&app, &state).await?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlTestRequest {
    pub group: String,
    pub url: Option<String>,
    pub timeout_ms: Option<u32>,
}

#[tauri::command]
pub async fn url_test(
    req: UrlTestRequest,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    state
        .kernel_api()
        .group_url_test(&req.group, req.url.as_deref(), req.timeout_ms, Some(&app))
        .await
        .map_err(|e| sanitize_err(&e.to_string()))
}

/// 出站模式热切换（build 157 用户方案）：立即保存设置；内核运行中经
/// Clash API PATCH /configs {"mode": ...} 生效（config 内 clash_mode
/// 规则驱动路由），无需重启内核。移除旧「先停 VPN 再保存」限制
#[tauri::command]
pub async fn set_outbound_mode(
    mode: OutboundMode,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut snapshot = state.settings.read().clone();
    snapshot.outbound_mode = mode;
    state
        .save_settings(snapshot)
        .map_err(|e| format!("保存设置失败: {e}"))?;
    // 【APP54 任务3】规则模块：出站模式切换
    crate::core::logger::info(
        crate::core::logger::MOD_RULE,
        &format!(
            "出站模式切换: {}（{}）",
            match mode {
                OutboundMode::Rule => "规则",
                OutboundMode::Global => "全局",
                OutboundMode::Direct => "直连",
            },
            if *state.status.read() == CoreStatus::Running { "热切换" } else { "已保存" }
        ),
    );

    if *state.status.read() == CoreStatus::Running {
        let mode_str = match mode {
            OutboundMode::Rule => "rule",
            OutboundMode::Global => "global",
            OutboundMode::Direct => "direct",
        };
        let api = state.kernel_api();
        api.patch_mode(mode_str)
            .await
            .map_err(|e| format!("热切换出站模式失败: {}", sanitize_err(&e.to_string())))?;
        // 【APP49 任务1】仅在「切换策略时关闭连接」开启时清理旧连接；
        // 内核始终保持运行（VPN 不断开、计时器不重置、Go Lan 不受影响）
        if state.settings.read().close_connections_on_switch {
            let _ = api.close_all_connections().await;
        }
        use tauri::Emitter;
        let _ = app.emit("outbound-mode://changed", mode_str);
    }
    Ok(())
}

#[tauri::command]
pub async fn select_proxy(
    app: AppHandle,
    group: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // 【APP-10 任务2】任何链路都严禁选中内置非代理出站（direct/block/直连 等）
    if crate::core::config_builder::is_builtin_non_proxy_tag(&name) {
        return Err(format!("「{name}」是内置功能出站，不能作为代理节点选中"));
    }
    // 【APP33 任务3.1】严禁选中「剩余流量/到期时间/官网」等信息/广告类假节点
    if crate::core::config_builder::is_info_or_ad_node_name(&name) {
        return Err(format!("「{name}」是信息/广告类假节点，已自动过滤"));
    }
    // 【APP26 任务2.3】记录「用户已手动选点」：此后启动 / 关闭 Go AIM 时的
    // 自动最低延迟优选不再覆盖用户的选择
    *state.user_manually_selected_node.write() = true;
    // 【APP33 任务3.1】持久化选中节点到 settings.json，重启后仪表盘恢复同一节点
    {
        let mut settings = state.settings.read().clone();
        if settings.selected_node.as_deref() != Some(name.as_str())
            || !settings.user_manually_selected_node
        {
            settings.selected_node = Some(name.clone());
            settings.user_manually_selected_node = true;
            if let Err(e) = state.save_settings(settings) {
                tracing::error!("save selected_node failed: {e}");
            }
        }
    }
    // 【APP37 任务3.2】用户手动切换节点绝不再中止 Go AIM 探测：
    // 探测循环只响应「Go AIM 开关关闭」与「VPN 停止」两个中止条件，
    // 自动选点/手动切点导致的 selected_node 变化不再误触中止锁。
    // 【APP46 任务1.4】全量同步所有顶层 selector 策略组：
    // 用户只在「节点页 Proxy 主组」选点，但 GLOBAL、任何 top-level Selector
    // 组（规则里可能引用）仍然挂着旧节点——一旦规则把流量切到这些组，就会
    // 回到旧代理！彻底修复：枚举所有 Selector 类型组，逐个 PUT 同步到同一
    // 节点，任何一组返回 404（节点刚导入、内核还不认识）→ 自动重新生成
    // config.json + 重启内核（start_core_inner），确保节点 100% 接管。
    let api = state.kernel_api();
    let mut had_404 = false;
    if let Ok(proxies_map) = api.get_proxies().await {
        if let Some(map) = proxies_map.get("proxies").and_then(|m| m.as_object()) {
            let mut all_selectors: Vec<String> = Vec::new();
            for (k, v) in map {
                let Some(t) = v.get("type").and_then(|t| t.as_str()) else { continue };
                if t == "Selector"
                    && !crate::core::config_builder::is_builtin_non_proxy_tag(k)
                    // 已经切过的组（用户指定 group + GLOBAL）不再切两次
                    && k != &group
                    && k != "GLOBAL"
                {
                    all_selectors.push(k.clone());
                }
            }
            // 顺序：用户指定 group → GLOBAL → 其余 Selector。
            // GLOBAL 先于其余组避免被内核默认同步覆盖；用户组最先保证
            // 主选择器立即生效（仪表盘首帧显示选中节点）。
            let try_select = async |sel: &str| -> bool {
                match api.select_proxy(sel, &name).await {
                    Ok(()) => false,
                    Err(e) => {
                        let msg = e.to_string();
                        tracing::warn!("selector '{sel}' 切节点失败: {msg}");
                        msg.contains("404")
                    }
                }
            };
            if try_select(&group).await { had_404 = true; }
            if group != "GLOBAL" && try_select("GLOBAL").await {
                had_404 = true;
            }
            for sel in &all_selectors {
                if try_select(sel).await { had_404 = true; }
            }
        }
    }

    // 任何一个 selector 返回 404 → 重新构建 config.json + 重启内核
    // （内核启动流程会自动把 selected_node 写入所有 selector 默认项）
    if had_404 && *state.status.read() == crate::core::state::CoreStatus::Running {
        tracing::info!("触发 vpn reload 以接纳新节点 '{name}'");
        // 先停再启（do_stop + start_core_inner）
        let inner = state.inner();
        let _ = do_stop(inner).await;
        if let Err(e) = start_core_inner(&app, inner).await {
            tracing::error!("vpn reload 失败: {e}");
        }
    }

    // Go AIM 手动指定（APP-4 任务3.3）：用户在节点页手动选中节点时，
    // 若 Go AIM 开启，立即写入 go_aim_pinned_node 并落盘——此后探测评级
    // 照跑，但选点始终尊重该节点（手动指定优先级高于自动评级，绝不覆盖）
    let main_group = state.main_selector.read().clone();
    if state.settings.read().go_aim_enabled && Some(&group) == main_group.as_ref() {
        let mut settings = state.settings.read().clone();
        if settings.go_aim_pinned_node.as_deref() != Some(name.as_str()) {
            settings.go_aim_pinned_node = Some(name.clone());
            if let Err(e) = state.save_settings(settings.clone()) {
                tracing::error!("save go_aim_pinned_node failed: {e}");
            }
            *state.aim_locked_node.write() = Some(name.clone());
            let _ = app.emit(
                crate::core::go_aim::AIM_EVENT,
                serde_json::json!({ "locked": name }),
            );
        }
    }

    // 「切换策略时关闭连接」：断开后由应用按新节点重建，避免旧连接继续走旧节点
    if state.settings.read().close_connections_on_switch {
        let _ = state.kernel_api().close_all_connections().await;
    }

    // 仪表盘「当前节点」卡与 Go AIM 卡一致性（APP-4 任务4.1）：
    // 切换节点后广播 proxies://changed，Dashboard 立即重拉主组 now
    let _ = app.emit("proxies://changed", serde_json::json!({ "group": group }));
    Ok(())
}

/// 下载订阅并写入 profile.yaml。
/// 兼容两种返回：Clash YAML 明文、base64 包裹的内容。
/// 【APP42 任务2.1】name 为可选的用户自定义备注名。
#[tauri::command]
pub async fn update_subscription(
    url: String,
    name: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    refresh_subscription(&app, &state, &url).await?;
    if let Some(n) = name.as_deref() {
        crate::core::store::set_subscription_name(&state.data_dir, &url, Some(n))
            .map_err(|e| format!("保存订阅备注名失败: {e}"))?;
    }
    // Pro/买断：静默上报云端（其他设备下次对账时拉取）
    let app2 = app.clone();
    let url2 = url.clone();
    let name2 = name.clone();
    tauri::async_runtime::spawn(async move {
        super::super::core::sync_links::push_link(&app2, &url2, name2).await;
    });
    Ok(())
}

/// 【APP49 任务2.2】「全部更新」按钮：一键拉取全部已启用订阅。
/// 逐条顺序执行（复用 refresh_subscription 的多 UA/代理/DoH 通道），
/// 全部完成后广播 subscriptions://changed 刷新列表；全部失败才报错。
#[tauri::command]
pub async fn update_all_subscriptions(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let urls: Vec<String> = crate::core::store::load_subscriptions(&state.data_dir)
        .into_iter()
        .filter(|r| r.enabled)
        .map(|r| r.url)
        .collect();
    if urls.is_empty() {
        return Err("暂无可更新的订阅".to_string());
    }
    let mut ok = 0usize;
    let mut last_err = String::new();
    for url in &urls {
        match refresh_subscription(&app, &state, url).await {
            Ok(()) => ok += 1,
            Err(e) => {
                tracing::warn!("[SubUpdateAll] 更新失败 {url}: {e}");
                last_err = e;
            }
        }
    }
    use tauri::Emitter;
    let _ = app.emit("subscriptions://changed", ());
    if ok == 0 {
        Err(format!("全部更新失败：{last_err}"))
    } else {
        Ok(())
    }
}

/// 【APP42 任务2.1】重命名订阅备注（本地优先：立即落盘 + 广播事件；
/// Pro 用户同时静默上报云端，其他设备下次对账时同步改名）
#[tauri::command]
pub async fn rename_subscription(
    url: String,
    name: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let found = crate::core::store::set_subscription_name(&state.data_dir, &url, Some(&name))
        .map_err(|e| format!("保存订阅备注名失败: {e}"))?;
    if !found {
        return Err("订阅记录不存在".into());
    }
    let app2 = app.clone();
    let url2 = url.clone();
    let name2 = name.clone();
    tauri::async_runtime::spawn(async move {
        super::super::core::sync_links::push_link(&app2, &url2, Some(name2)).await;
    });
    use tauri::Emitter;
    let _ = app.emit("subscriptions://changed", ());
    Ok(())
}

/// 订阅刷新核心逻辑（IPC 命令与云端同步对账共用）。
/// 下载 → 解析校验 → 落盘 → 记录 → 拉取 providers → 内核运行中则重启生效。
pub(crate) async fn refresh_subscription(
    app: &AppHandle,
    state: &AppState,
    url: &str,
) -> Result<(), String> {
    // 入口即清洗：微信/网页复制的链接常带 \u2060 等零宽字符，
    // 若不清洗会污染 profile 文件哈希、订阅记录与后续所有请求
    let url = sanitize_subscription_url(url);
    // 内核运行中时，直连失败的最终兜底是经本地 mixed 入站转发。
    // 移动端 mixed 入站已移除，流量全走 TUN，无需本地代理兜底。
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    let local_proxy = (*state.status.read() == CoreStatus::Running)
        .then(|| state.settings.read().mixed_port);
    #[cfg(any(target_os = "ios", target_os = "android"))]
    let local_proxy: Option<u16> = None;
    let (mut text, mut quota) = fetch_remote_text(&url, local_proxy, None).await?;

    // base64 包裹：明文不含 YAML/JSON 结构时尝试解码
    text = prepare_subscription_payload(text)?;

    // 【APP42 任务1.1】首拉解析出 0 个节点（典型：面板按 UA 下发不同格式）
    // → 用 v2rayN UA 再重试一次，成功则改用重试结果
    if subscription_real_node_count(&text) == 0 {
        tracing::warn!("订阅首拉解析出 0 节点，使用 v2rayN UA 重试一次: {url}");
        let (retry_text, retry_quota) =
            fetch_remote_text(&url, local_proxy, Some(SUBSCRIPTION_RETRY_UA)).await?;
        let retry_text = prepare_subscription_payload(retry_text)?;
        if subscription_real_node_count(&retry_text) > 0 {
            text = retry_text;
            quota = retry_quota;
            tracing::info!("v2rayN UA 重试成功，节点数 {}", subscription_real_node_count(&text));
        }
    }

    // 落盘前校验：防止机场返回 HTML 错误页/限流提示等空内容覆盖本地可用订阅
    if let Err(e) = crate::core::config_builder::validate_subscription_text(&text) {
        return Err(e);
    }

    // 每条订阅独立 profile 文件（多订阅模型），路径由 URL 哈希派生
    let profile_path = crate::core::store::profile_path(&state.data_dir, &url);
    if let Some(parent) = profile_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| sanitize_err(&e.to_string()))?;
    }
    std::fs::write(&profile_path, &text)
        .map_err(|e| format!("写入订阅文件失败: {}", e))?;
    tracing::info!("subscription saved to {}", profile_path.display());

    // 持久化订阅记录（机场下发了 subscription-userinfo 则同步流量配额）
    crate::core::store::upsert_subscription(&state.data_dir, &url)
        .map_err(|e| format!("保存订阅记录失败: {e}"))?;
    if let Some(quota) = &quota
        && let Err(e) = crate::core::store::set_subscription_quota(&state.data_dir, &url, quota)
    {
        tracing::warn!("保存订阅流量配额失败: {e}");
    }

    // 拉取订阅内声明的 http proxy-providers（失败只告警，不阻断订阅更新）
    refresh_providers(state, &url, &text).await;

    // 【APP51 任务1】订阅刷新后第一时间清理失效节点缓存并中止旧探测任务
    purge_disabled_or_deleted_subscription_nodes(state);

    // 内核运行中：重建配置重启，新订阅即刻生效。
    // APP34：移动端 VPN 运行期间严禁「停隧道 + 重启隧道」——iOS 扩展在
    // 50MB Jetsam 红线内重启必然崩溃（表现为启动 10~15 秒后自动停止）。
    // 此时只落盘订阅缓存并广播事件，新节点在下次正常启动时生效。
    let mobile = cfg!(any(target_os = "ios", target_os = "android"));
    if *state.status.read() == CoreStatus::Running {
        if mobile {
            tracing::info!("subscription updated, mobile running: skip tunnel restart");
            crate::core::logger::info(
                crate::core::logger::MOD_SUB,
                "移动端 VPN 运行中，订阅缓存已更新，隧道保持不重启（下次启动生效）",
            );
        } else {
            tracing::info!("subscription updated, restarting core");
            restart_core(app, state).await?;
        }
    }

    Ok(())
}

/// 【APP47 任务3.1】统计订阅内容实际节点数（用于双 UA 择优）。
/// 机场面板常按 UA 下发不同节点集：v2rayNG UA 拿到的是完整 base64 URI 列表，
/// Clash.Meta UA 有时只拿到精简 YAML。两个 UA 并发拉取后按节点数取更多者。
fn count_nodes_in_text(text: &str) -> usize {
    let prepared = prepare_subscription_payload(text.to_string()).unwrap_or_else(|_| text.to_string());
    if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(&prepared)
        && let Some(list) = v.get("proxies").and_then(|p| p.as_sequence())
    {
        return list.len();
    }
    0
}

/// 订阅下载候选 User-Agent（按兼容性从强到弱轮询）：
/// 【APP42 任务1.1】首位改为 Clash.Meta/mihomo 组合标识：机场面板普遍
/// 依赖 UA 判定客户端并下发 Clash YAML + subscription-userinfo 配额头；
/// 只写 clash-verge 会被部分面板识别为旧版 Verge 而返回精简节点。
/// 1. Clash.Meta/mihomo/Prism/sing-box 组合标识 —— 首选；
/// 2. v2rayN —— 仅放行 v2ray 客户端 UA 的面板（首拉 0 节点时重试）；
/// 3. Shadowrocket —— 屏蔽 Clash UA 的面板；
/// 4. 通用浏览器 —— 只放行浏览器 UA 的兜底。
const SUBSCRIPTION_UAS: [&str; 4] = [
    "Clash.Meta/v1.18.3 mihomo/1.18.3 Prism/0.3.69 sing-box/1.11.3",
    "v2rayN/6.45",
    "Shadowrocket/2078 CFNetwork/1410.0.3 Darwin/22.6.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
];

/// 首拉解析出 0 个节点时用于二次重试的 UA
const SUBSCRIPTION_RETRY_UA: &str = "v2rayN/6.45";

/// 单次订阅请求总超时。【APP15 任务3.1】12s → 30s：大订阅（数千行 YAML）
/// 在弱网/CDN 回源慢时 12s 经常读到一半就断开，导致尾部截断的畸形 YAML。
const SUBSCRIPTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 清洗订阅 URL：剔除首尾空白与零宽/不可见控制字符。
/// 从微信、网页复制的链接常带入 \u2060（Word Joiner）、\u200B..\u200F、
/// \uFEFF（BOM）等，直接特征会被 reqwest 判为非法 URL 或触发面板 WAF。
fn sanitize_subscription_url(raw: &str) -> String {
    raw.chars()
        .filter(|c| {
            !matches!(
                *c,
                '\u{200B}'..='\u{200F}'
                    | '\u{2060}'
                    | '\u{FEFF}'
                    | '\u{00AD}'
                    | '\u{180E}'
            ) && !c.is_control()
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// 【APP42 任务1.1】订阅内容归一化：
/// base64 解包 + URI 列表（ss/vmess/vless/trojan/hysteria2/tuic/anytls…）
/// → 统一 Clash YAML，供后续校验与落盘复用。
fn prepare_subscription_payload(mut text: String) -> Result<String, String> {
    // base64 包裹：明文不含 YAML/JSON 结构时尝试解码
    if !text.contains("proxies") && !text.trim_start().starts_with('{')
        && let Ok(decoded) = try_decode_base64(&text)
    {
        text = decoded;
    }

    // URI 列表订阅：解析为节点并合成 Clash YAML，复用统一 pipeline
    if crate::core::uri_parser::is_uri_list(&text) {
        let (nodes, errors, notice) = crate::core::uri_parser::parse_lines(&text);
        // 机场提示（流量超限/到期等）优先展示，引导用户去机场面板处理
        if let Some(notice_text) = notice {
            return Err(format!(
                "机场提示：{notice_text}\n\n请至机场面板重置接入记录或续费后重试"
            ));
        }
        if nodes.is_empty() {
            return Err(format!(
                "URI 列表订阅解析失败：{}",
                errors.first().cloned().unwrap_or_else(|| "内容为空".into())
            ));
        }
        if !errors.is_empty() {
            tracing::warn!("subscription partial parse: {}", errors.join("；"));
        }
        tracing::info!("URI subscription parsed: {} nodes ({} errors)", nodes.len(), errors.len());
        // 节点名称去重（同名节点会互相覆盖）
        let mut seen = std::collections::HashSet::new();
        let mut proxies = Vec::new();
        for mut node in nodes {
            // 【APP-4 任务1】还原被 Latin-1 展开的 UTF-8 乱码节点名
            let base = crate::core::uri_parser::fix_utf8_mojibake(
                node["name"].as_str().unwrap_or_default(),
            );
            let base = if base.is_empty() {
                format!(
                    "{}:{}",
                    node["server"].as_str().unwrap_or_default(),
                    node["port"]
                )
            } else {
                base
            };
            let mut name = base.clone();
            let mut i = 2;
            while !seen.insert(name.clone()) {
                name = format!("{base} #{i}");
                i += 1;
            }
            node["name"] = serde_json::json!(name);
            proxies.push(node);
        }
        let names: Vec<&str> = proxies
            .iter()
            .filter_map(|n| n["name"].as_str())
            .collect();
        let profile = serde_json::json!({
            "proxies": proxies,
            "proxy-groups": [
                { "name": "节点选择", "type": "select", "proxies": names }
            ],
            "rules": ["MATCH,节点选择"],
        });
        text = serde_yaml::to_string(&profile).map_err(|e| format!("订阅转换失败: {e}"))?;
    }

    if !text.contains("proxies") && !text.contains("{") {
        return Err("订阅内容无法识别：既不是 Clash YAML，也不是内核 JSON".into());
    }
    Ok(text)
}

/// 统计 Clash YAML 中的真实节点数（排除机场提示用的 127.x / localhost 占位节点）
fn subscription_real_node_count(text: &str) -> usize {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(text) else {
        return 0;
    };
    value
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
        .unwrap_or(0)
}

/// 下载远程文本（订阅 / proxy-provider 共用）。
/// 三级回退闭环：
/// 1. 多 UA 直连竞速（自动探测 + 强制 IPv4 同时发起）；
/// 2. 内核运行中经本地 mixed 入站转发（受限网络走节点出境）；
/// 3. 全部失败时给出可自助定位的精确原因。
async fn fetch_remote_text(
    url: &str,
    local_proxy: Option<u16>,
    force_ua: Option<&str>,
) -> Result<(String, Option<crate::core::store::SubscriptionQuota>), String> {
    use futures_util::stream::{FuturesUnordered, StreamExt as _};
    use std::time::Instant;

    let url = sanitize_subscription_url(url);
    if url.is_empty() {
        return Err("订阅链接为空（可能只粘贴了不可见字符）".into());
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!(
            "订阅链接格式有误：必须以 http:// 或 https:// 开头（当前为「{}」）",
            truncate_for_msg(&url)
        ));
    }

    let fetch_started = Instant::now();
    let mut last_err = String::new();

    // ---- 直连双栈竞速（自动探测 + 强制 IPv4 同时发起）× 多 UA ----
    // 原串行实现：第一次请求若撞上 IPv6 黑洞，必须等满 10s 连接超时才
    // 发起第二次，导入体感「非常慢」。竞速后任一栈先成功立即返回，
    // 整体只受实际网络 RTT 约束，不再为黑洞等待。
    // http1_only：CF Worker 类端点 HTTP/2 流关闭顺序异常会触发
    //   error decoding response body（即「读取响应失败」），强制 HTTP/1.1。
    let build_client = |force_v4: bool, ua: &str| -> Result<reqwest::Client, String> {
        let mut builder = reqwest::Client::builder()
            .http1_only()
            .user_agent(ua)
            .timeout(SUBSCRIPTION_TIMEOUT)
            // 连接阶段独立短超时：黑洞地址快速失败
            .connect_timeout(std::time::Duration::from_secs(10))
            // 部分机场使用自签名/过期证书，忽略校验换取可用性
            .danger_accept_invalid_certs(true)
            // 机场面板常有 CDN 多级跳转，最多跟随 5 次
            .redirect(reqwest::redirect::Policy::limited(5))
            .no_proxy();
        if force_v4 {
            builder =
                builder.local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        }
        builder.build().map_err(|e| format!("创建 HTTP 客户端失败: {e}"))
    };

    let mut attempts = FuturesUnordered::new();
    // 【APP42 任务1.1】force_ua 非空时只发该 UA（首拉 0 节点的 v2rayN 重试）
    let uas: Vec<&str> = match force_ua {
        Some(ua) => vec![ua],
        None => SUBSCRIPTION_UAS.to_vec(),
    };
    for ua in &uas {
        for force_v4 in [false, true] {
            let client = build_client(force_v4, ua)?;
            let target = url.clone();
            let ua: String = (*ua).to_string();
            attempts.push(async move { (force_v4, ua, try_fetch_text(&client, &target).await) });
        }
    }

    // 【APP47 任务3.1】双 UA 择优：机场按 UA 下发不同节点集（v2rayNG 给完整
    // base64 URI 列表，Clash.Meta 有时给精简 YAML）。不再"先到先得"，而是让
    // Clash.Meta 与 v2rayN 两族都产出结果后，按实际节点数取更多者；
    // 同等节点数时保留先到者。
    let no_force = force_ua.is_none();
    let mut best: Option<(String, Option<crate::core::store::SubscriptionQuota>, usize, String)> =
        None;
    let mut got_clash = false;
    let mut got_v2ray = false;
    while let Some((force_v4, ua, result)) = attempts.next().await {
        match result {
            Ok((text, quota)) => {
                tracing::info!(
                    "fetch succeeded (ua={}, force_v4={force_v4}) in {}ms",
                    ua.split('/').next().unwrap_or(ua.as_str()),
                    fetch_started.elapsed().as_millis()
                );
                let count = count_nodes_in_text(&text);
                tracing::info!(
                    "fetch ua={} nodes={count}",
                    ua.split('/').next().unwrap_or(ua.as_str())
                );
                if ua == SUBSCRIPTION_UAS[0] {
                    got_clash = true;
                }
                if ua == SUBSCRIPTION_RETRY_UA {
                    got_v2ray = true;
                }
                match &best {
                    Some((_, _, best_count, _)) if *best_count >= count => {}
                    _ => best = Some((text, quota, count, ua)),
                }
                if !no_force {
                    let (text, quota, _, _) = best.unwrap();
                    return Ok((text, quota));
                }
                // 两个核心 UA 族都已产出 → 立即择优，不再等冷门 UA
                if got_clash && got_v2ray {
                    break;
                }
                // 非核心 UA 先成功时先记下，继续等核心 UA（最多到 attempts 耗尽）
            }
            Err(e) => {
                last_err = e;
                tracing::warn!(
                    "fetch direct (ua={}, force_v4={force_v4}) failed at {}ms: {last_err}",
                    ua.split('/').next().unwrap_or(ua.as_str()),
                    fetch_started.elapsed().as_millis()
                );
            }
        }
    }
    if let Some((text, quota, count, ua)) = best {
        if no_force {
            tracing::info!(
                "fetch pick ua={} nodes={count}",
                ua.split('/').next().unwrap_or(ua.as_str())
            );
        }
        return Ok((text, quota));
    }

    // ---- 内核运行中：经本地 mixed 入站转发（同样轮询多 UA）----
    if let Some(port) = local_proxy {
        let proxy = reqwest::Proxy::all(&format!("http://127.0.0.1:{port}"))
            .map_err(|e| format!("配置本地代理失败: {e}"))?;
        for ua in &uas {
            let builder = reqwest::Client::builder()
                .http1_only()
                .user_agent(*ua)
                .timeout(SUBSCRIPTION_TIMEOUT)
                .connect_timeout(std::time::Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::limited(5))
                .proxy(proxy.clone());
            let client = match builder.build() {
                Ok(c) => c,
                Err(e) => {
                    last_err = format!("创建 HTTP 客户端失败: {e}");
                    continue;
                }
            };
            match try_fetch_text(&client, &url).await {
                Ok((text, quota)) => {
                    tracing::info!("fetch remote text succeeded via local mixed proxy :{port}");
                    return Ok((text, quota));
                }
                Err(e) => {
                    last_err = e;
                    tracing::warn!("fetch remote text via local proxy failed: {last_err}");
                }
            }
        }
    }

    // ---- 【APP49 任务2.1 通道B】DoH 防污染：直连（与本地代理）均失败时，
    // 通过阿里/腾讯/Cloudflare DoH 解析订阅域名真实 IP，`.resolve` 固定解析
    // 直连拉取（绕过运营商 DNS 污染，SNI/证书链不受影响）----
    if let Ok(parsed) = reqwest::Url::parse(&url) {
        if let Some(host) = parsed.host_str() {
            let ips = crate::core::license::doh_resolve_ips(host).await;
            if !ips.is_empty() {
                let port = parsed
                    .port()
                    .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
                'doh: for ip in ips.iter().take(3) {
                    for ua in &uas {
                        let client = match reqwest::Client::builder()
                            .http1_only()
                            .user_agent(*ua)
                            .timeout(SUBSCRIPTION_TIMEOUT)
                            .connect_timeout(std::time::Duration::from_secs(8))
                            .danger_accept_invalid_certs(true)
                            .redirect(reqwest::redirect::Policy::limited(5))
                            .no_proxy()
                            .resolve(host, std::net::SocketAddr::new(*ip, port))
                            .build()
                        {
                            Ok(c) => c,
                            Err(e) => {
                                last_err = format!("创建 HTTP 客户端失败: {e}");
                                continue;
                            }
                        };
                        match try_fetch_text(&client, &url).await {
                            Ok((text, quota)) => {
                                tracing::info!(
                                    "fetch remote text succeeded via DoH-pinned {host}->{ip}"
                                );
                                return Ok((text, quota));
                            }
                            Err(e) => {
                                last_err = e;
                                tracing::warn!("fetch via DoH-pinned {ip} failed: {last_err}");
                            }
                        }
                    }
                    // 首个 IP 全部 UA 失败再试下一个 IP，最多 3 个
                    if last_err.is_empty() {
                        break 'doh;
                    }
                }
            }
        }
    }

    if local_proxy.is_some() {
        Err(format!(
            "下载失败：{last_err}（直连、本地代理转发与 DoH 防污染通道均已尝试，请检查节点可用性后重试）"
        ))
    } else {
        Err(format!(
            "下载失败：{last_err}（已尝试多 UA/IPv4 直连与 DoH 防污染解析；若机器处于受限网络，请先启动内核再更新订阅）"
        ))
    }
}

/// 错误提示里限制 URL 长度，避免超长链接撑爆 Toast
fn truncate_for_msg(s: &str) -> String {
    let chars: Vec<char> = s.chars().take(48).collect();
    let mut out: String = chars.into_iter().collect();
    if s.chars().count() > 48 {
        out.push('…');
    }
    out
}

/// 用给定客户端执行一次 GET 文本下载（状态码 / UTF-8 校验）
async fn try_fetch_text(
    client: &reqwest::Client,
    url: &str,
) -> Result<(String, Option<crate::core::store::SubscriptionQuota>), String> {
    let mut resp = client
        .get(url)
        // 与 Clash 通行 UA 配套：部分面板按 Accept 头判定客户端类型
        .header("Accept", "*/*")
        // 禁用压缩：部分 Worker 端点返回的 Content-Encoding 与实际正文
        // 编码不一致，会触发 reqwest 解压器报错
        .header("Accept-Encoding", "identity")
        .send()
        .await
        .map_err(|e| describe_reqwest_error(&e))?;
    if !resp.status().is_success() {
        return Err(format!(
            "HTTP {}（订阅链接可能已失效）",
            resp.status()
        ));
    }
    // 机场流量配额（Clash / SIP008 通用的 subscription-userinfo 响应头）
    let quota = resp
        .headers()
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
        .and_then(crate::core::store::SubscriptionQuota::parse);
    // 分段流式读取（禁用 resp.text()/bytes 整包等待）：Cloudflare Worker
    // 类端点下发完正文后常不发 TLS close_notify（或 HTTP/2 提前重置流），
    // 整包读取会把已完整收到的数据包装成 error decoding response body
    // 整包丢弃。流末尾报错时只要已读到有效内容（>32 字节）就保留使用
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => buf.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(e) => {
                if buf.len() > 32 {
                    tracing::warn!(
                        "订阅流末尾非致命中断，保留已接收的 {} 字节: {e}",
                        buf.len()
                    );
                    break;
                }
                return Err(format!("读取响应失败: {e}"));
            }
        }
    }

    // 已请求 Accept-Encoding: identity，但部分面板无视请求头强制返回 gzip。
    // 此类响应交给 reqwest 解码器会报 error decoding response body；
    // 这里按 gzip 魔数（0x1f 0x8b）手动流式解压。
    if buf.len() >= 2 && buf[0] == 0x1f && buf[1] == 0x8b {
        use std::io::Read as _;
        let mut decoded = Vec::new();
        match flate2::read::GzDecoder::new(&buf[..]).read_to_end(&mut decoded) {
            Ok(_) => {
                tracing::info!("订阅响应为 gzip 压缩，已手动解压 {} → {} 字节", buf.len(), decoded.len());
                buf = decoded;
            }
            Err(e) => {
                if buf.len() > 32 {
                    tracing::warn!("gzip 解压失败，保留原始字节: {e}");
                } else {
                    return Err(format!("gzip 解压失败: {e}"));
                }
            }
        }
    }

    // 非 UTF-8 字节（面板偶发夹杂控制字符）按 lossy 转换，绝不因编码直接失败
    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok((text, quota))
}

/// reqwest 顶层 Display 只有 "error sending request"，
/// 链式展开到最底层原因（DNS / 连接超时 / TLS 证书等）便于用户自救
fn describe_reqwest_error(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    let mut src: Option<&dyn std::error::Error> = Some(&e);
    while let Some(s) = src.and_then(std::error::Error::source) {
        msg.push_str(&format!("（原因: {s}）"));
        src = Some(s);
    }
    msg
}

/// 解析订阅内的 proxy-providers（仅 http），并发下载落盘
async fn refresh_providers(state: &AppState, sub_url: &str, profile_text: &str) {
    use futures_util::future::FutureExt as _;
    use std::time::Instant;

    let started = Instant::now();
    let view: crate::core::config_builder::ClashProfileView =
        match serde_yaml::from_str(profile_text) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("parse providers from subscription failed: {e}");
                return;
            }
        };

    // 移动端 mixed 入站已移除，流量全走 TUN，无需本地代理兜底。
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    let local_proxy = (*state.status.read() == CoreStatus::Running)
        .then(|| state.settings.read().mixed_port);
    #[cfg(any(target_os = "ios", target_os = "android"))]
    let local_proxy: Option<u16> = None;

    // 收集所有可下载任务后并发执行：原 for 循环串行下载，N 个 provider
    // 的耗时是 N 倍 RTT（各带 30s 超时），这是多 provider 订阅导入慢的
    // 另一主因；并发后总耗时约等于最慢的一个。
    let mut tasks = Vec::new();
    for (name, provider) in view.proxy_providers {
        if provider.kind != "http" {
            continue;
        }
        let Some(url) = provider.url.filter(|u| !u.is_empty()) else {
            tracing::warn!("provider '{name}' missing url, skipped");
            continue;
        };

        let data_dir = state.data_dir.clone();
        tasks.push(
            async move {
                match fetch_remote_text(&url, local_proxy, None).await {
                    Ok((text, _)) => {
                        let path =
                            crate::core::store::provider_path(&data_dir, sub_url, &name);
                        if let Some(parent) = path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        if let Err(e) = std::fs::write(&path, &text) {
                            tracing::warn!("write provider '{name}' failed: {e}");
                        } else {
                            tracing::info!("proxy-provider '{name}' refreshed");
                        }
                    }
                    Err(e) => tracing::warn!("fetch proxy-provider '{name}' failed: {e}"),
                }
            }
            .boxed(),
        );
    }

    if tasks.is_empty() {
        return;
    }
    let count = tasks.len();
    futures_util::future::join_all(tasks).await;
    tracing::info!(
        "{count} proxy-providers refreshed concurrently in {}ms",
        started.elapsed().as_millis()
    );
}

/// 尝试 base64 解码（容错换行/空白；依次尝试标准 / URL-safe 两种字符集），
/// 成功且结果为可读 UTF-8 时返回
fn try_decode_base64(input: &str) -> Result<String, String> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    for eng in [&STANDARD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = eng.decode(&compact)
            && let Ok(text) = String::from_utf8(bytes)
        {
            return Ok(text);
        }
    }
    Err("not base64".into())
}

/// 订阅记录（前端展示用）：在存储记录上附加节点数统计
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionDto {
    pub url: String,
    pub updated_at: i64,
    pub name: Option<String>,
    /// 是否参与配置合并
    pub enabled: bool,
    /// 节点数（解析该订阅自己的 profile 文件统计；文件缺失/解析失败为 None）
    pub node_count: Option<usize>,
    /// 机场流量配额（subscription-userinfo 头，未下发为 None）
    pub upload_bytes: Option<u64>,
    pub download_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub expire_at: Option<u64>,
}

/// 【APP49 任务2.2】启动时自动更新全部已启用订阅：默认开启，每天仅一次
/// （上次成功日期 < 今天才执行），避免多设备订阅同步风暴。
/// 更新完成后广播 subscriptions://changed 让列表页实时刷新。
pub async fn auto_update_subscriptions_daily(app: AppHandle) {
    let state = app.state::<AppState>();
    let (enabled, last_day) = {
        let s = state.settings.read();
        (
            s.auto_update_subs_daily,
            s.last_auto_update_subs_date.clone(),
        )
    };
    if !enabled {
        return;
    }
    let today = (crate::core::license::now_unix().max(0) / 86_400) as u64;
    if last_day.parse::<u64>().ok() == Some(today) {
        return;
    }
    let urls: Vec<String> = crate::core::store::load_subscriptions(&state.data_dir)
        .into_iter()
        .filter(|r| r.enabled)
        .map(|r| r.url)
        .collect();
    if urls.is_empty() {
        return;
    }
    tracing::info!("[AutoUpdate] 每日自动更新 {} 条订阅", urls.len());
    for url in &urls {
        if let Err(e) = refresh_subscription(&app, &state, url).await {
            tracing::warn!("[AutoUpdate] 更新失败 {url}: {e}");
        }
    }
    // 无论个别订阅失败与否都记录当天日期：失败走下次启动重试，
    // 避免「某条订阅永久 404」导致每次启动都全量拉一轮。
    let mut settings = state.settings.read().clone();
    settings.last_auto_update_subs_date = today.to_string();
    if let Err(e) = state.save_settings(settings) {
        tracing::warn!("[AutoUpdate] 记录更新日期失败: {e}");
    }
    use tauri::Emitter;
    let _ = app.emit("subscriptions://changed", ());
}

/// 获取已保存的订阅记录（订阅页展示）
#[tauri::command]
pub async fn list_subscriptions(
    state: State<'_, AppState>,
) -> Result<Vec<SubscriptionDto>, String> {
    let records = crate::core::store::load_subscriptions(&state.data_dir);
    Ok(records
        .into_iter()
        .map(|r| {
            let path = crate::core::store::profile_path(&state.data_dir, &r.url);
            let node_count = std::fs::read_to_string(&path)
                .ok()
                .and_then(|text| count_profile_nodes(&text));
            SubscriptionDto {
                url: r.url,
                updated_at: r.updated_at,
                name: r.name,
                enabled: r.enabled,
                node_count,
                upload_bytes: r.upload_bytes,
                download_bytes: r.download_bytes,
                total_bytes: r.total_bytes,
                expire_at: r.expire_at,
            }
        })
        .collect())
}

/// 统计 profile 内容的 proxies 条目数；解析失败返回 None
fn count_profile_nodes(text: &str) -> Option<usize> {
    let value: serde_yaml::Value = serde_yaml::from_str(text).ok()?;
    value.get("proxies")?.as_sequence().map(|s| s.len())
}

/// 节点简表（内核未运行时从订阅缓存读取，供节点页预览）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedProxyDto {
    pub name: String,
    pub kind: String,
    pub server: String,
    pub port: u16,
    /// 来源订阅 URL（用于 UI 分组）
    pub from_subscription: String,
    /// 【APP52 任务1】持久化的最近一次真实延迟：
    /// None = 从未测速；Some(0) = 超时；Some(d>0) = 实测延迟
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<u32>,
}

/// 内核未运行时从订阅缓存读取节点列表（节点页预览）
/// 内核运行时优先用 get_proxy_groups（含实时延迟）
#[tauri::command]
pub async fn get_cached_proxies(
    state: State<'_, AppState>,
) -> Result<Vec<CachedProxyDto>, String> {
    Ok(collect_cached_proxies(&state))
}

/// 【APP44 任务1.3】内核未运行时从订阅缓存读取节点列表（测速复用同一份解析）
fn collect_cached_proxies(state: &AppState) -> Vec<CachedProxyDto> {
    let records = crate::core::store::load_subscriptions(&state.data_dir);
    let mut out: Vec<CachedProxyDto> = Vec::new();
    for r in records {
        if !r.enabled {
            continue;
        }
        let path = crate::core::store::profile_path(&state.data_dir, &r.url);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        // 双格式解析：Clash YAML 优先；解析失败或未产出节点时回退
        // base64/URI 列表（正常落盘已归一化为 YAML，此为兜底防漏）
        let before = out.len();
        if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
            if let Some(proxies) = value.get("proxies").and_then(|v| v.as_sequence()) {
                for p in proxies {
                    let name = crate::core::uri_parser::fix_utf8_mojibake(
                        p.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                    let kind = p.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let server = p.get("server").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let port = p.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    if name.is_empty() || server.is_empty() {
                        continue;
                    }
                    // 【APP-10 任务2】名为 direct/block/直连 的节点绝不进 UI 列表
                    if crate::core::config_builder::is_builtin_non_proxy_tag(&name) {
                        continue;
                    }
                    // 【APP33 任务1.1/3.2】过滤「剩余流量/到期时间/官网」等
                    // 信息/广告类假节点，代理页与仪表盘节点弹窗彻底不显示。
                    if crate::core::config_builder::is_info_or_ad_node_name(&name) {
                        continue;
                    }
                    // 跳过机场提示节点（127.x / localhost）
                    if server.starts_with("127.") || server == "localhost" {
                        continue;
                    }
                    out.push(CachedProxyDto {
                        name,
                        kind,
                        server,
                        port,
                        from_subscription: r.url.clone(),
                        delay: None,
                    });
                }
            }
        }
        if out.len() == before {
            let decoded = crate::core::uri_parser::unwrap_base64(&text);
            let (nodes, errors, _notice) = crate::core::uri_parser::parse_lines(&decoded);
            if !errors.is_empty() {
                tracing::warn!("cached proxies URI fallback: {}", errors.join("；"));
            }
            for node in nodes {
                let name = crate::core::uri_parser::fix_utf8_mojibake(
                    node.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                );
                let kind = node.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let server = node.get("server").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let port = node.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                if name.is_empty() || server.is_empty() {
                    continue;
                }
                // 【APP-10 任务2】名为 direct/block/直连 的节点绝不进 UI 列表
                if crate::core::config_builder::is_builtin_non_proxy_tag(&name) {
                    continue;
                }
                // 【APP33 任务1.1/3.2】过滤信息/广告类假节点
                if crate::core::config_builder::is_info_or_ad_node_name(&name) {
                    continue;
                }
                if server.starts_with("127.") || server == "localhost" {
                    continue;
                }
                out.push(CachedProxyDto {
                    name,
                    kind,
                    server,
                    port,
                    from_subscription: r.url.clone(),
                    delay: None,
                });
            }
        }
    }
    // 【APP52 任务1】注入持久化延迟并全局按延迟升序排列：
    // 实测 >0 升序 → 未测速居中 → 超时(0) 置底。切换页面 / 重启 APP 后顺序不变。
    {
        let delays = state.node_metrics.read().delays.clone();
        for p in out.iter_mut() {
            p.delay = delays.get(&p.name).copied();
        }
        out.sort_by_key(|p| crate::core::state::node_delay_sort_key(p.delay));
    }
    out
}

/// 【APP51 任务1】选中节点失效回退：仍有效则原样保留，失效/为空取第一个可用节点。
fn fallback_selected_node(selected: Option<&str>, valid_names: &[String]) -> Option<String> {
    if let Some(sel) = selected
        && valid_names.iter().any(|v| v == sel)
    {
        return Some(sel.to_string());
    }
    valid_names.first().cloned()
}

/// 【APP51 任务1】订阅删除 / 停用 / 刷新后的统一清理：
/// 1. aim_generation +1，正在进行的 Go AIM 探测发现代数变化立即中止；
/// 2. 清空已失效节点（不存在于当前启用订阅）的 aim_results 与 aim_locked_node；
/// 3. 选中节点 / 手动指定节点若已失效，重置为当前可用节点中的第一个，并落盘。
/// 必须在订阅变更的第一时间调用（重启内核之前），杜绝旧节点继续被锁定。
pub(crate) fn purge_disabled_or_deleted_subscription_nodes(state: &AppState) {
    use std::sync::atomic::Ordering;
    let valid_names: Vec<String> = collect_cached_proxies(state)
        .into_iter()
        .map(|p| p.name)
        .collect();
    let valid: std::collections::HashSet<&str> =
        valid_names.iter().map(|s| s.as_str()).collect();
    // 代数自增：旧探测任务立即失效
    state.aim_generation.fetch_add(1, Ordering::AcqRel);
    // 【APP52 任务1】持久化指标缓存同步清理已失效节点（刷新/删除订阅时）
    {
        let valid_owned: std::collections::HashSet<String> =
            valid_names.iter().cloned().collect();
        state.retain_node_metrics(&valid_owned);
    }

    // 1) 清除失效节点的探测缓存
    {
        let mut results = state.aim_results.write();
        results.retain(|name, _| valid.contains(name.as_str()));
    }
    // 2) 锁定的节点已失效 → 清空，交由后续探测/自动选点重建
    {
        let mut locked = state.aim_locked_node.write();
        if locked
            .as_deref()
            .is_some_and(|n| !valid.contains(n))
        {
            *locked = None;
        }
    }
    // 3) 选中节点 / 手动指定节点失效 → 重置为当前第一个可用节点并落盘
    let mut settings = state.settings.read().clone();
    let mut changed = false;
    let next_selected = fallback_selected_node(settings.selected_node.as_deref(), &valid_names);
    if next_selected != settings.selected_node {
        settings.selected_node = next_selected;
        changed = true;
    }
    if let Some(pinned) = settings.go_aim_pinned_node.clone()
        && !valid.contains(pinned.as_str())
    {
        settings.go_aim_pinned_node = None;
        changed = true;
    }
    if changed {
        let _ = state.save_settings(settings);
        let _ = state.app_handle.emit("settings://changed", ());
        let _ = state.app_handle.emit("proxies://changed", ());
    }
}

/// 【APP44 任务1.3】内核未运行时的真实测速：DoH / 系统 DNS 解析节点服务器
/// 【APP54 任务2】全局节点域名预解析缓存（系统 DNS + 阿里/腾讯 DoH）。
/// 一次全量测速只解析去重后的服务器域名（20 路并发），失败不缓存。
static NODE_DNS_CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, Vec<std::net::Ipv4Addr>>>> =
    std::sync::OnceLock::new();

fn node_dns_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, Vec<std::net::Ipv4Addr>>> {
    NODE_DNS_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// 解析节点服务器真实 IPv4（系统 DNS 优先，再回退阿里 DoH 223.5.5.5、
/// 腾讯 DoH 1.12.12.12），结果写入 NODE_DNS_CACHE 供后续测速直接命中。
async fn resolve_server_ipv4s(server: &str) -> Vec<std::net::Ipv4Addr> {
    let key = server.trim().to_ascii_lowercase();
    if let Ok(ip) = key.parse::<std::net::Ipv4Addr>() {
        return if is_virtual_speedtest_ip(std::net::IpAddr::V4(ip)) {
            Vec::new()
        } else {
            vec![ip]
        };
    }
    if let Ok(cache) = node_dns_cache().lock()
        && let Some(hit) = cache.get(&key).filter(|v| !v.is_empty())
    {
        return hit.clone();
    }
    let mut out: Vec<std::net::Ipv4Addr> = Vec::new();
    // 1) 系统 DNS
    if let Ok(addrs) = tokio::net::lookup_host((server, 443)).await {
        for addr in addrs {
            if let std::net::IpAddr::V4(ip) = addr.ip()
                && !is_virtual_speedtest_ip(addr.ip())
                && !out.contains(&ip)
            {
                out.push(ip);
            }
        }
    }
    // 2) DoH 兜底（阿里 / 腾讯），JSON 接口返回 Answer 数组
    if out.is_empty() {
        let client = SPEEDTEST_DOH_CLIENT.get_or_init(|| {
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(2500))
                .connect_timeout(std::time::Duration::from_millis(1500))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        });
        for endpoint in ["https://223.5.5.5/resolve", "https://1.12.12.12/resolve"] {
            if let Ok(resp) = client
                .get(endpoint)
                .query(&[("name", server), ("type", "A")])
                .send()
                .await
                && let Ok(json) = resp.json::<serde_json::Value>().await
                && let Some(answers) = json.get("Answer").and_then(|a| a.as_array())
            {
                for a in answers {
                    if let Some(ip) = a
                        .get("data")
                        .and_then(|d| d.as_str())
                        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
                        && !is_virtual_speedtest_ip(std::net::IpAddr::V4(ip))
                        && !out.contains(&ip)
                    {
                        out.push(ip);
                    }
                }
            }
            if !out.is_empty() {
                break;
            }
        }
    }
    if !out.is_empty()
        && let Ok(mut cache) = node_dns_cache().lock()
    {
        cache.insert(key, out.clone());
    }
    out
}

/// 依次尝试预解析 IP 的 TCP 握手（单 IP 2000ms 超时）
async fn tcp_connect_ips(
    ips: &[std::net::Ipv4Addr],
    port: u16,
    timeout_ms: u32,
) -> Option<u64> {
    for ip in ips.iter().take(4) {
        let start = std::time::Instant::now();
        let fut = tokio::net::TcpStream::connect(std::net::SocketAddr::from((*ip, port)));
        if let Ok(Ok(_)) =
            tokio::time::timeout(std::time::Duration::from_millis(timeout_ms as u64), fut).await
        {
            return Some(start.elapsed().as_millis().max(1) as u64);
        }
    }
    None
}

/// 【APP54 任务2/4】全量测速：100% 覆盖全部节点并升序持久化。
/// - 第一步：去重服务器域名 20 路并发预解析（系统 DNS + 阿里/腾讯 DoH）；
/// - 第二步：20 路并发滑动窗口逐节点测速（运行中 Clash API 2200ms，
///   失败/未运行回退预解析 IPv4 TCP 2000ms，超时重试 1 次）；
/// - 每节点写入延迟缓存（超时记 0），每 6 个落盘，每 3 个推送增量；
/// - 完成后未手动选点则自动切换到最低延迟节点。
/// 任何情况下都绝不清空已有延迟缓存（切页/启停/重启不丢失）。
#[tauri::command]
pub async fn test_all_delays(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let nodes = collect_cached_proxies(&state);
    if nodes.is_empty() {
        return Err("节点列表为空，请先刷新订阅".into());
    }
    let running = *state.status.read() == CoreStatus::Running;
    let total = nodes.len();
    // 初始化进度并广播
    {
        let mut p = state.delay_progress.lock();
        p.running = true;
        p.done = 0;
        p.total = total;
        p.unlocked_count = 0;
        p.recompute();
        let snapshot = p.clone();
        drop(p);
        let _ = app.emit("delays://progress", &snapshot);
    }
    crate::core::logger::info(
        crate::core::logger::MOD_NODE,
        &format!("开始全量测速：共 {total} 个节点（{}）", if running { "内核实测" } else { "离线 TCP" }),
    );

    // 第一步：20 路并发预解析去重域名
    {
        let mut unique: Vec<String> = nodes.iter().map(|n| n.server.clone()).collect();
        unique.sort();
        unique.dedup();
        use futures_util::StreamExt;
        let mut stream = futures_util::stream::iter(unique.into_iter())
            .map(|server| async move { resolve_server_ipv4s(&server).await })
            .buffer_unordered(20);
        while stream.next().await.is_some() {}
    }

    // 第二步：20 路并发滑动窗口测速
    let api = state.kernel_api();
    let mut all: Vec<(String, u32)> = Vec::with_capacity(total);
    let mut batch: Vec<(String, u32)> = Vec::new();
    let mut updates = serde_json::Map::new();
    let mut done = 0usize;
    {
        use futures_util::StreamExt;
        let mut stream = futures_util::stream::iter(nodes.into_iter())
            .map(|n| {
                let api = api.clone();
                async move {
                    let d = if running {
                        // 内核运行：真实隧道 gstatic generate_204 2200ms
                        if let Some(d) = api
                            .test_delay(&n.name, "http://www.gstatic.com/generate_204", 2200)
                            .await
                            .filter(|d| *d > 0)
                        {
                            d as u32
                        } else {
                            // 失败回退预解析 IPv4 TCP 握手（2000ms，重试 1 次）
                            let ips = resolve_server_ipv4s(&n.server).await;
                            let mut d = 0u32;
                            for _ in 0..2 {
                                if let Some(v) = tcp_connect_ips(&ips, n.port, 2000).await {
                                    d = v as u32;
                                    break;
                                }
                            }
                            d
                        }
                    } else {
                        // 未运行：直接 IPv4 + 端口 TCP 握手（2000ms，重试 1 次）
                        let ips = resolve_server_ipv4s(&n.server).await;
                        let mut d = 0u32;
                        for _ in 0..2 {
                            if let Some(v) = tcp_connect_ips(&ips, n.port, 2000).await {
                                d = v as u32;
                                break;
                            }
                        }
                        d
                    };
                    (n.name, d)
                }
            })
            .buffer_unordered(20);
        while let Some((name, d)) = stream.next().await {
            done += 1;
            all.push((name.clone(), d));
            batch.push((name.clone(), d));
            updates.insert(name, serde_json::json!(d));
            let percent = ((done.min(total) * 100) / total) as u8;
            let _ = app.emit(
                "delays://progress",
                serde_json::json!({
                    "running": true,
                    "done": done,
                    "total": total,
                    "percent": percent,
                    "unlockedCount": 0,
                }),
            );
            if done % 3 == 0 || done == total {
                let _ = app.emit("delays://updated", serde_json::Value::Object(updates.clone()));
            }
            if batch.len() >= 6 || done == total {
                state.record_node_delays(std::mem::take(&mut batch));
            }
        }
    }

    // 自动选点：用户未手动锁定 → 最低延迟（仅实测 > 0）
    let best = all
        .iter()
        .filter(|(_, d)| *d > 0)
        .min_by_key(|(_, d)| *d)
        .map(|(n, d)| (n.clone(), *d));
    if !*state.user_manually_selected_node.read()
        && let Some((best_name, best_delay)) = best.clone()
    {
        let mut settings = state.settings.read().clone();
        if settings.selected_node.as_deref() != Some(best_name.as_str()) {
            settings.selected_node = Some(best_name.clone());
            settings.user_manually_selected_node = false;
            if let Err(e) = state.save_settings(settings) {
                tracing::warn!("[APP54] 测速自动选点落盘失败: {e}");
            }
        }
        if running {
            let group = state.main_selector.read().clone();
            if let Some(group) = group {
                let _ = api.select_proxy(&group, &best_name).await;
                let _ = api.select_proxy("GLOBAL", &best_name).await;
            }
        }
        let _ = app.emit("proxies://changed", ());
        crate::core::logger::info(
            crate::core::logger::MOD_NODE,
            &format!("全量测速完成，自动选择最低延迟节点「{best_name}」({best_delay}ms)"),
        );
    } else {
        crate::core::logger::info(
            crate::core::logger::MOD_NODE,
            &format!("全量测速完成，共 {total} 个节点（用户手动锁定，未自动切换）"),
        );
    }

    // 完成态进度 + 全量落盘
    state.record_node_delays(all.iter().cloned());
    {
        let mut p = state.delay_progress.lock();
        p.running = false;
        p.done = total;
        p.total = total;
        p.percent = 100;
        let snapshot = p.clone();
        drop(p);
        let _ = app.emit("delays://progress", &snapshot);
    }
    let _ = app.emit(
        "delays://updated",
        serde_json::Value::Object(
            all.iter()
                .map(|(n, d)| (n.clone(), serde_json::json!(d)))
                .collect(),
        ),
    );

    Ok(serde_json::Value::Object(
        all.into_iter()
            .map(|(n, d)| (n, serde_json::json!(d)))
            .collect(),
    ))
}

/// 域名 → 过滤 FakeIP 与虚拟网段 → 真实 TCP 握手计时。
/// 仅在 VPN 未运行时调用（TUN 开启时握手指向 utun，延迟全是假的）。
#[tauri::command]
pub async fn test_cached_proxies(
    timeout_ms: Option<u32>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let nodes = collect_cached_proxies(&state);
    if nodes.is_empty() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    // 【APP51 任务1】严格 1500ms 超时 + 32 路并发滚动测速（测完全部启用节点）
    let timeout = timeout_ms.unwrap_or(1500).clamp(800, 3000);
    use futures_util::StreamExt;
    const BATCH: usize = 32;
    let mut map = serde_json::Map::new();
    let mut all_delays: Vec<(String, u32)> = Vec::new();
    for batch in nodes.chunks(BATCH) {
        let results: Vec<(String, Option<u64>)> =
            futures_util::stream::iter(batch.iter().cloned())
                .map(|n| async move {
                    let delay = measure_offline_node_delay(&n.server, n.port, timeout).await;
                    (n.name, delay)
                })
                .buffer_unordered(BATCH)
                .collect()
                .await;
        for (name, delay) in results {
            // 【APP52 任务1】完整记录成功与超时（0），供节点页排序与持久化
            let d = delay.unwrap_or(0);
            all_delays.push((name.clone(), d as u32));
            if let Some(d) = delay {
                map.insert(name, serde_json::json!(d));
            }
        }
    }
    // 【APP52 任务1】测速结果持久化 + 自动选最低延迟节点（用户未手动指定时）
    state.record_node_delays(all_delays.iter().cloned());
    if !*state.user_manually_selected_node.read()
        && let Some((best, _)) = all_delays.iter().filter(|(_, d)| *d > 0).min_by_key(|(_, d)| *d)
    {
        let mut settings = state.settings.read().clone();
        if settings.selected_node.as_deref() != Some(best.as_str()) {
            settings.selected_node = Some(best.clone());
            settings.user_manually_selected_node = false;
            if let Err(e) = state.save_settings(settings) {
                tracing::warn!("[APP52] 离线测速自动选点落盘失败: {e}");
            }
            let _ = state.app_handle.emit("proxies://changed", ());
        }
    }
    Ok(serde_json::Value::Object(map))
}

/// FakeIP / TUN / WireGuard 虚拟网段判定（测速解析结果必须经此过滤，
/// 否则 198.18.x.x 会给出 2ms 假延迟）
fn is_virtual_speedtest_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_unspecified() || v4.is_link_local() {
                return true;
            }
            let o = v4.octets();
            (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 172 && o[1] == 19)
                || (o[0] == 10 && o[1] == 196)
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

static SPEEDTEST_DOH_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

/// 解析节点服务器的真实 IPv4：DoH（223.5.5.5）优先，失败回退系统 DNS
async fn resolve_real_ipv4s(
    server: &str,
    port: u16,
    _timeout_ms: u32,
) -> Vec<std::net::Ipv4Addr> {
    if let Ok(ip) = server.trim().parse::<std::net::Ipv4Addr>() {
        return if is_virtual_speedtest_ip(std::net::IpAddr::V4(ip)) {
            Vec::new()
        } else {
            vec![ip]
        };
    }
    let mut out: Vec<std::net::Ipv4Addr> = Vec::new();
    let client = SPEEDTEST_DOH_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(2500))
            .connect_timeout(std::time::Duration::from_millis(1500))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    });
    if let Ok(resp) = client
        .get("https://223.5.5.5/resolve")
        .query(&[("name", server), ("type", "A")])
        .send()
        .await
        && let Ok(json) = resp.json::<serde_json::Value>().await
        && let Some(answers) = json.get("Answer").and_then(|a| a.as_array())
    {
        for a in answers {
            if let Some(ip) = a
                .get("data")
                .and_then(|d| d.as_str())
                .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
                && !is_virtual_speedtest_ip(std::net::IpAddr::V4(ip))
                && !out.contains(&ip)
            {
                out.push(ip);
            }
        }
    }
    if out.is_empty()
        && let Ok(addrs) = tokio::net::lookup_host((server, port)).await
    {
        for addr in addrs {
            if let std::net::IpAddr::V4(ip) = addr.ip()
                && !is_virtual_speedtest_ip(addr.ip())
                && !out.contains(&ip)
            {
                out.push(ip);
            }
        }
    }
    out
}

pub(crate) async fn measure_offline_node_delay(
    server: &str,
    port: u16,
    timeout_ms: u32,
) -> Option<u64> {
    let ips = resolve_real_ipv4s(server, port, timeout_ms).await;
    for ip in ips.into_iter().take(4) {
        let start = std::time::Instant::now();
        let fut = tokio::net::TcpStream::connect(std::net::SocketAddr::from((ip, port)));
        if let Ok(Ok(_)) = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms as u64),
            fut,
        )
        .await
        {
            return Some(start.elapsed().as_millis().max(1) as u64);
        }
    }
    None
}

/// 获取自定义规则（规则页编辑器；Clash 行格式，顺序即优先级）
#[tauri::command]
pub async fn get_custom_rules(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(crate::core::store::load_custom_rules(&state.data_dir))
}

/// 保存自定义规则（内核运行中自动重启生效）
#[tauri::command]
pub async fn save_custom_rules(
    rules: Vec<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // 【APP48 任务4】隐身保护：禁止任何针对授权服务域名/隐身 IP 的拦截规则，
    // 防止用户或恶意配置把 prism.sarl 打进 REJECT，导致授权校验永久失败。
    let filtered: Vec<String> = rules
        .into_iter()
        .filter(|rule| {
            let lower = rule.to_ascii_lowercase();
            let target_auth = crate::core::license::is_stealth_protected_host_or_ip(&lower);
            let is_block = lower.contains("reject")
                || lower.contains("block")
                || lower.contains("drop");
            if target_auth && is_block {
                tracing::warn!("已忽略针对授权服务的拦截规则: {rule}");
                false
            } else {
                true
            }
        })
        .collect();
    // 【APP54 任务3】规则模块：保存后输出真实汇总（按类型计数）
    {
        let mut by_type: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for r in &filtered {
            let kind = r.split(',').next().unwrap_or("UNKNOWN").trim().to_string();
            *by_type.entry(kind).or_insert(0) += 1;
        }
        let summary: Vec<String> = by_type
            .iter()
            .map(|(k, v)| format!("{k}×{v}"))
            .collect();
        crate::core::logger::info(
            crate::core::logger::MOD_RULE,
            &format!(
                "规则已保存：共 {} 条（{}），出站模式: {:?}",
                filtered.len(),
                if summary.is_empty() { "无".to_string() } else { summary.join("、") },
                state.settings.read().outbound_mode
            ),
        );
    }
    crate::core::store::save_custom_rules(&state.data_dir, &filtered)
        .map_err(|e| format!("保存自定义规则失败: {e}"))?;
    if *state.status.read() == CoreStatus::Running {
        restart_core(&app, &state).await?;
        crate::core::logger::info(
            crate::core::logger::MOD_KERNEL,
            "规则变更已热重载内核配置（无需重新启动 VPN）",
        );
    }
    Ok(())
}

/// 当前启用订阅数
fn enabled_subscription_count(state: &AppState) -> usize {
    crate::core::store::load_subscriptions(&state.data_dir)
        .iter()
        .filter(|r| r.enabled)
        .count()
}

/// 内核运行中至少需要一条启用订阅，避免走"重启时 profile 为空"的异常停机路径
fn ensure_not_last_enabled(state: &AppState) -> Result<(), String> {
    if *state.status.read() == CoreStatus::Running && enabled_subscription_count(state) <= 1 {
        return Err(
            "内核运行中至少需要保留一条启用订阅：请先停止内核，再执行该操作".into(),
        );
    }
    Ok(())
}

/// 启停单条订阅（多订阅模型；内核运行中自动重启生效）
#[tauri::command]
pub async fn toggle_subscription(
    url: String,
    enabled: bool,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // 停用最后一条启用订阅前拦截（启用操作无需拦截）
    if !enabled {
        ensure_not_last_enabled(&state)?;
    }

    let found = crate::core::store::set_subscription_enabled(&state.data_dir, &url, enabled)
        .map_err(|e| format!("更新订阅状态失败: {e}"))?;
    if !found {
        return Err("订阅记录不存在".into());
    }
    // 【APP51 任务1】订阅启停第一时间清理失效节点并中止旧探测
    purge_disabled_or_deleted_subscription_nodes(&state);
    if *state.status.read() == CoreStatus::Running {
        restart_core(&app, &state).await?;
    }
    Ok(())
}

/// 删除一条订阅记录（同时移除其 profile 文件；内核运行中自动重启生效）
#[tauri::command]
pub async fn delete_subscription(
    url: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    // 目标为启用状态时，删除前校验是否为最后一条
    let target_enabled = crate::core::store::load_subscriptions(&state.data_dir)
        .iter()
        .any(|r| r.url == url && r.enabled);
    if target_enabled {
        ensure_not_last_enabled(&state)?;
    }

    let removed = crate::core::store::delete_subscription(&state.data_dir, &url)
        .map_err(|e| format!("删除订阅失败: {e}"))?;
    if removed {
        std::fs::remove_file(crate::core::store::profile_path(&state.data_dir, &url)).ok();
        // 【APP51 任务1】删除订阅后立即清理其全部节点缓存与失效选中节点
        purge_disabled_or_deleted_subscription_nodes(&state);
        // Pro/买断：静默上报云端删除（其他设备下次对账时同步删除）
        let app2 = app.clone();
        let url2 = url.clone();
        tauri::async_runtime::spawn(async move {
            super::super::core::sync_links::push_delete(&app2, &url2).await;
        });
        if *state.status.read() == CoreStatus::Running {
            restart_core(&app, &state).await?;
        }
    }
    Ok(removed)
}

/// 上次自动全量同步时间戳（Unix 秒）；0 = 从未同步。
/// 启动循环每小时都会触发对账，全量节点刷新以 24h 节流防重复下载。
static LAST_AUTO_SYNC: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// 【APP6 任务3】激活 Pro / 启动校验 Pro 有效后：自动开启云端同步并拉取
/// 云端订阅列表（云端空而本地有则上传备份），拉取完成后立即自动下载并
/// 解析所有启用订阅的最新节点，全程零手动干预。
///
/// 触发时机：
/// A. `activate_pro` 激活成功后立即 spawn；
/// B. APP 启动校验 Pro 有效后（lib.rs 启动循环首轮；内部 24h 节流）；
/// C. `refresh_entitlement`「立即校验」确认有效后。
///
/// 内核运行中时先停机，全部订阅刷新完再一次性重启恢复，避免逐条刷新
/// 反复重启内核。全程写 [Sub] 模块日志。
pub async fn auto_sync_and_refresh_subscriptions(app: AppHandle) {
    use std::sync::atomic::Ordering;
    let log = crate::core::logger::MOD_SUB;
    let state = app.state::<AppState>();

    // 资格自校验：未解锁或服务端未允许云同步时静默返回
    let ent = state.entitlement.read().clone();
    if !ent.is_unlocked() || !ent.sync_available {
        return;
    }
    if crate::core::license::cached_credentials(&state.data_dir).is_none() {
        return;
    }
    // 24h 全量刷新节流（reconcile 本身幂等且轻量，可重复执行）
    let now = crate::core::license::now_unix();
    let last = LAST_AUTO_SYNC.load(Ordering::Relaxed);
    if last > 0 && now - last < 24 * 3600 {
        return;
    }
    LAST_AUTO_SYNC.store(now, Ordering::Relaxed);

    crate::core::logger::info(log, "Pro 授权有效，自动开启云端订阅同步并更新节点...");
    // APP37 任务1.2：VPN 运行期间绝不调用 vpn_stop / vpn_start 重启隧道
    //（任何平台）：重启会打断在网用户且移动端 50MB Jetsam 下重启必崩。
    // 后台同步只更新磁盘/内存中的订阅缓存，正在运行的隧道保持不变，
    // 新节点随下次启动自然生效。
    let before = crate::core::store::load_subscriptions(&state.data_dir);

    // 1. 对账云端订阅链接（云端有 → 拉取合并；云端空而本地有 → 上传备份）
    crate::core::sync_links::reconcile(&app).await;
    let after = crate::core::store::load_subscriptions(&state.data_dir);
    let pulled = after.len().saturating_sub(before.len());
    if pulled > 0 {
        crate::core::logger::info(
            log,
            &format!("已从云端同步 {pulled} 条订阅链接，开始下载最新节点..."),
        );
        let _ = app.emit("subscriptions://changed", ());
    }

    // 2. 立即下载并解析全部启用订阅的最新节点
    let mut ok = 0usize;
    let mut fail = 0usize;
    for r in after.iter().filter(|r| r.enabled) {
        let url = r.url.clone();
        match refresh_subscription(&app, &state, &url).await {
            Ok(()) => {
                ok += 1;
                crate::core::logger::info(log, &format!("订阅节点更新成功: {}", truncate_for_msg(&url)));
            }
            Err(e) => {
                fail += 1;
                crate::core::logger::warn(log, &format!("订阅节点更新失败（{}）: {}", truncate_for_msg(&url), e));
            }
        }
    }
    crate::core::logger::info(
        log,
        &format!("自动同步完成：{ok} 个订阅成功 / {fail} 个失败"),
    );
    if ok > 0 {
        let _ = app.emit("proxies://changed", ());
        // 【APP6 任务3】激活同步完成通知（前端 toast 提示用户节点已更新）
        let _ = app.emit(
            "subscriptions://auto-synced",
            serde_json::json!({ "ok": ok, "fail": fail }),
        );
    }
}

/// 激活码激活（邮箱+授权码；联网校验；服务端签名后本地缓存授权）
#[tauri::command]
pub async fn activate_pro(
    code: String,
    email: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<EntitlementStatus, String> {
    let data_dir = state.data_dir.clone();
    let settings = state.settings.read().clone();
    let next = crate::core::license::activate(&data_dir, &settings, &code, &email)
        .await
        .map_err(|e| sanitize_err(&e.to_string()))?;
    state.apply_entitlement(next.clone());
    // 激活成功：清除历史剥夺原因，前端横幅随 proUnlocked=true 一并消失
    if next.is_unlocked() {
        crate::core::app_control::clear_revoke_reason(&data_dir);
        // 【APP6 任务3】激活成功后立即自动同步云端订阅并刷新全部节点
        crate::core::logger::info(
            crate::core::logger::MOD_PRO,
            "Pro 激活成功，已触发云端订阅自动同步",
        );
        tauri::async_runtime::spawn(async move {
            auto_sync_and_refresh_subscriptions(app).await;
        });
    }
    Ok(next)
}

/// 查询当前授权状态（读内存，不联网）
#[tauri::command]
pub async fn get_entitlement(
    state: State<'_, AppState>,
) -> Result<EntitlementStatus, String> {
    Ok(state.entitlement.read().clone())
}

/// 读取最近一次授权剥夺原因（IPA-3 任务2：unbound / expired / null）。
/// 前端启动时调用一次，保证重启后横幅仍是「设备已解绑」而不是「已到期」。
#[tauri::command]
pub async fn get_revoke_reason(state: State<'_, AppState>) -> Result<Option<String>, String> {
    Ok(crate::core::app_control::load_revoke_reason(&state.data_dir))
}

/// 读取本机设备 ID（激活绑定与设置页展示用；首次调用时生成并落盘）
#[tauri::command]
pub async fn get_device_id(state: State<'_, AppState>) -> Result<String, String> {
    crate::core::license::device_id(&state.data_dir).map_err(|e| sanitize_err(&e.to_string()))
}

/// 主动联网刷新授权（设置页「立即校验」按钮；APP-7：改用权威 runtime 校验，
/// 自动感知解绑/过期/plan 缺失并执行授权级熔断）
#[tauri::command]
pub async fn refresh_entitlement(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<EntitlementStatus, String> {
    let (ent, revoke_msg) = crate::core::app_control::force_runtime_check(&app, &state)
        .await
        .map_err(|e| sanitize_err(&e))?;
    // 【APP6 任务3】校验确认 Pro 有效：自动同步云端订阅并刷新节点
    //（reconcile 内部自校验同步资格并幂等去重；auto_sync 内部 24h 节流）
    if ent.is_unlocked() {
        let app2 = app.clone();
        tauri::async_runtime::spawn(async move {
            auto_sync_and_refresh_subscriptions(app2).await;
        });
    }
    // 如果触发了授权剥夺（解绑/过期），force_runtime_check 内部已经 apply_entitlement
    // 并 emit pro://revoked；这里正常返回 entitlement 给前端显示即可
    let _ = revoke_msg; // force_runtime_check 内部已 emit 事件
    Ok(ent)
}

/// 移除本机授权：清理本地授权/同步缓存文件，并自动关闭依赖 Pro 授权的开关
/// （Go AIM / Go Lan / Go Cus 落盘保存为关闭），防止移除授权后后台仍残留运行
/// Pro 模块。所有清理均为 best-effort，绝不导致移除失败。
///
/// 【APP28 任务3】零等待：先同步捕获解绑凭据 → 立即删除本地授权文件、关闭
/// Pro 模块并广播状态 → 服务端解绑（POST /api/license/deactivate）放入
/// `tauri::async_runtime::spawn` 后台异步执行，前端 1ms 内即可收到 Ok。
#[tauri::command]
pub async fn deactivate_pro(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<EntitlementStatus, String> {
    // 【APP48 任务6】Alpha 内测 Key 只能绑定 1 台设备，用户端不支持自行解绑
    // （服务端 /license/deactivate 亦返回 403 alpha_unbind_not_allowed）。
    if state.entitlement.read().alpha {
        return Err("内测授权不支持自行解绑，请联系管理员解绑后再更换设备".into());
    }
    // 解绑凭据（license_key / email / device_id）存在 license.dat 内，
    // 必须在下方本地清理前同步捕获，随后交给后台任务异步上报。
    let binding = {
        let settings = state.settings.read().clone();
        crate::core::license::ReleaseBinding::capture(&state.data_dir, &settings)
    };

    // 本地清理（同步、纯磁盘操作）：license.dat / license_cache.json /
    // sync_links.json；runtime_cache.json 一并清除避免残留旧感知数据。
    let next = crate::core::license::deactivate(&state.data_dir);
    let _ = std::fs::remove_file(state.data_dir.join("runtime_cache.json"));
    state.apply_entitlement(next.clone());
    // 用户主动移除授权：不是「被解绑/已到期」，清掉历史原因避免误弹横幅
    crate::core::app_control::clear_revoke_reason(&state.data_dir);

    // Go AIM：落盘关闭 + 清理锁定节点并通知前端
    let mut settings = state.settings.read().clone();
    settings.go_aim_enabled = false;
    let _ = state.save_settings(settings);
    *state.aim_locked_node.write() = None;
    let _ = app.emit(
        crate::core::go_aim::AIM_EVENT,
        serde_json::json!({ "locked": null }),
    );

    // Go Lan / Go Cus：落盘关闭并同步内存状态（内核下次启动/重建即不再启用）
    let mut lan = state.go_lan.read().clone();
    if lan.enabled {
        lan.enabled = false;
        let _ = crate::core::go_lan::save(&state.data_dir, &lan);
        *state.go_lan.write() = lan;
    }
    let mut cus = state.go_cus.read().clone();
    if cus.enabled {
        cus.enabled = false;
        let _ = crate::core::go_cus::save(&state.data_dir, &cus);
        *state.go_cus.write() = cus;
    }

    // 服务端解绑：后台异步执行，不阻塞前端返回（失败静默忽略）
    if let Some(binding) = binding {
        tauri::async_runtime::spawn(async move {
            let _ = binding.notify().await;
        });
    }

    Ok(next)
}

/// 授权到期收口函数：启动加载 / 每 10 秒巡检 / 手动校验任一路径检测到到期后
/// 统一调用——强制关闭全部 Pro 专属功能、清理运行态、按新配置重载内核，
/// 并向前端广播 expired 与专门的 `pro://expired` 通知。
pub(crate) async fn terminate_pro_features_on_expiry(app: &AppHandle, state: &AppState) {
    // 1. 本地缓存同步落盘为 expired（重启后不会被旧缓存复活）
    match crate::core::license::mark_expired(&state.data_dir) {
        Some(next) => state.apply_entitlement(next),
        None => {
            if state.entitlement.read().status != "expired" {
                let mut ent = state.entitlement.read().clone();
                ent.status = "expired".into();
                state.apply_entitlement(ent);
            }
        }
    }

    // 2. 强制关闭 Pro 专属开关并落盘
    let mut settings = state.settings.read().clone();
    settings.go_aim_enabled = false;
    let _ = state.save_settings(settings);

    let mut lan = state.go_lan.read().clone();
    if lan.enabled {
        lan.enabled = false;
        let _ = crate::core::go_lan::save(&state.data_dir, &lan);
        *state.go_lan.write() = lan;
    }
    let mut cus = state.go_cus.read().clone();
    if cus.enabled {
        cus.enabled = false;
        let _ = crate::core::go_cus::save(&state.data_dir, &cus);
        *state.go_cus.write() = cus;
    }

    // 3. 清空 Go AIM 运行态并通知前端
    state.aim_results.write().clear();
    *state.aim_locked_node.write() = None;
    let _ = app.emit(
        crate::core::go_aim::AIM_EVENT,
        serde_json::json!({ "locked": null }),
    );

    // 4. 内核运行中：按关闭 Pro 功能后的配置重载，剥离回家隧道与覆写规则
    if *state.status.read() == CoreStatus::Running
        && let Err(e) = restart_core(app, state).await
    {
        tracing::error!("restart after license expiry failed: {e}");
    }

    // 5. 专门的到期通知（前端按 reason 渲染「授权已到期」专属横幅）
    let (zh, en) = crate::core::app_control::revoke_message(
        crate::core::app_control::REVOKE_EXPIRED,
    );
    crate::core::app_control::emit_revoked(
        app,
        crate::core::app_control::REVOKE_EXPIRED,
        zh,
        en,
        None,
    );
    // 兼容旧前端：保留空 payload 的 pro://expired 广播
    let _ = app.emit("pro://expired", serde_json::json!({}));
}

/// 移动端商店收据上报（apple | google），服务端校验后签发授权
#[tauri::command]
pub async fn submit_receipt(
    store: String,
    receipt: serde_json::Value,
    state: State<'_, AppState>,
) -> Result<EntitlementStatus, String> {
    let data_dir = state.data_dir.clone();
    let settings = state.settings.read().clone();
    let next = crate::core::license::submit_store_receipt(&data_dir, &settings, &store, receipt)
        .await
        .map_err(|e| sanitize_err(&e.to_string()))?;
    state.apply_entitlement(next.clone());
    Ok(next)
}

/// 查询内核是否就位（不触发下载）
#[tauri::command]
pub async fn get_kernel_info(state: State<'_, AppState>) -> Result<KernelInfoDto, String> {
    Ok(kernel_info(&state))
}

/// 校验内核完整性（设置页按钮）。内核始终随包分发，本命令只做探测，
/// 缺失时给出明确指引，绝不联网下载
#[tauri::command]
pub async fn ensure_kernel(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<KernelInfoDto, String> {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        let _ = app;
        // 【APP12 任务2】不再拼 "（内置）" 后缀——前端统一加 v 前缀展示
        *state.kernel_version.write() = Some(crate::core::kernel::EMBEDDED_VERSION.to_string());
        return Ok(kernel_info(&state));
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        let _ = &app;
        let work_dir = state.work_dir();
        let path = resolve_kernel_path(&work_dir).map_err(|_| {
            "内核文件缺失（Prism 不会联网下载内核）：请重新安装 Prism；若被安全软件删除或隔离，请恢复后重试".to_string()
        })?;

        if let Some(version) = probe_version(&path).await {
            *state.kernel_version.write() = Some(version);
        }
        Ok(kernel_info(&state))
    }
}

fn kernel_info(state: &AppState) -> KernelInfoDto {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        // 【APP12 任务2】移动端始终返回纯版本号，不再带 "（内置）" 后缀
        let version = state.kernel_version.read().clone()
            .or_else(|| Some(crate::core::kernel::EMBEDDED_VERSION.to_string()));
        KernelInfoDto {
            exists: true,
            path: None,
            version,
        }
    }
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        match resolve_kernel_path(&state.work_dir()) {
            Ok(path) => KernelInfoDto {
                exists: true,
                path: Some(path.to_string_lossy().to_string()),
                version: state.kernel_version.read().clone(),
            },
            Err(_) => KernelInfoDto {
                exists: false,
                path: None,
                version: None,
            },
        }
    }
}

/// 【APP48 任务4】从 Clash API `/connections` 响应中剥离 prism.sarl 隐身连接：
/// host / destinationIP / rulePayload 任一命中隐身白名单即整条丢弃，
/// 不计入连接列表，也不进入 ip→domain 缓存与聚合统计。
fn strip_stealth_connections(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(arr) = value
        .get_mut("connections")
        .and_then(|v| v.as_array_mut())
    {
        arr.retain(|c| {
            let meta = c.get("metadata");
            let get = |key: &str| {
                meta.and_then(|m| m.get(key))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
            };
            !(crate::core::license::is_stealth_protected_host_or_ip(get("host"))
                || crate::core::license::is_stealth_protected_host_or_ip(
                    get("destinationIP"),
                )
                || crate::core::license::is_stealth_protected_host_or_ip(get("rulePayload")))
        });
    }
    value
}

#[tauri::command]
pub async fn get_connections(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    state
        .kernel_api()
        .get_connections()
        .await
        .map(strip_stealth_connections)
        .map_err(|e| sanitize_err(&e.to_string()))
}

/// 关闭单条连接（连接页行内按钮）
#[tauri::command]
pub async fn close_connection(
    id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if !state.is_pro_active() {
        return Err("该功能需要有效的 Pro 授权".to_string());
    }
    state
        .kernel_api()
        .close_connection(&id)
        .await
        .map_err(|e| sanitize_err(&e.to_string()))
}

/// 关闭全部连接（连接页头部按钮）
#[tauri::command]
pub async fn close_all_connections(state: State<'_, AppState>) -> Result<(), String> {
    if !state.is_pro_active() {
        return Err("该功能需要有效的 Pro 授权".to_string());
    }
    state
        .kernel_api()
        .close_all_connections()
        .await
        .map_err(|e| sanitize_err(&e.to_string()))
}

/// 【APP49 任务4】清空分析聚合统计（分析页「清空统计」按钮）。
/// 聚合仅存于内存（AppState.analytics，无磁盘缓存），清空后前端经
/// get_runtime_snapshot 轮询自动拿到空数据；保留 last_seen 增量基准，
/// 避免仍活跃的连接被重复计数。
#[tauri::command]
pub async fn reset_analytics_stats(state: State<'_, AppState>) -> Result<(), String> {
    state.reset_analytics();
    Ok(())
}

#[tauri::command]
pub async fn get_traffic_stats(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    // 实时流量走 WebSocket 事件（traffic://tick），此处返回持久化统计 + 当前连接快照
    let stats = crate::core::store::load_traffic_stats(&state.data_dir);
    let conns = state
        .kernel_api()
        .get_connections()
        .await
        .map(strip_stealth_connections)
        .unwrap_or_default();
    Ok(serde_json::json!({
        "stats": stats,
        "connections": conns,
    }))
}

/// 【APP52 任务2】常驻后台遥测协程：600ms 一轮，VPN 运行中无条件探测
/// `/connections`（1200ms 硬超时）。切换页面、切到系统后台都不停止；
/// 速率经 EMA(0.65/0.35) 平滑，raw==0 且上次 <1KB/s 时归零，杜绝尾巴
/// 抖动与「速率卡死」。每个 tick 广播 `telemetry://tick`，前端仪表盘零延迟
/// 刷新，并在此处记录「[流量开始转发]」四阶段日志（每个节点会话仅一次）。
pub fn spawn_background_telemetry_worker(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut logged_node: Option<String> = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
            let state = app.state::<AppState>();
            let today = crate::core::store::today_total_bytes(&state.data_dir)
                .max(*state.today_bytes_cache.read());
            let selected = state.settings.read().selected_node.clone();
            let running = *state.status.read() == CoreStatus::Running;
            if !running {
                logged_node = None;
                let _ = app.emit(
                    "telemetry://tick",
                    serde_json::json!({
                        "down": 0,
                        "up": 0,
                        "today": today,
                        "running": false,
                        "selectedNode": selected,
                    }),
                );
                continue;
            }

            let api = state.kernel_api();
            let Ok(conn_json) = api.get_connections_with_timeout(1200).await else {
                // 探测失败：沿用上次速率（不做衰减、绝不归零闪断）
                let (down, up) = state
                    .last_traffic_sample
                    .lock()
                    .map(|s| (s.3, s.4))
                    .unwrap_or((0, 0));
                let _ = app.emit(
                    "telemetry://tick",
                    serde_json::json!({
                        "down": down, "up": up, "today": today,
                        "running": true, "selectedNode": selected,
                    }),
                );
                continue;
            };

            let total_down = conn_json
                .get("downloadTotal")
                .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)))
                .unwrap_or(0);
            let total_up = conn_json
                .get("uploadTotal")
                .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)))
                .unwrap_or(0);

            let (down, up) = {
                let now = std::time::Instant::now();
                let mut sample = state.last_traffic_sample.lock();
                match *sample {
                    Some((prev_t, prev_down, prev_up, last_down, last_up)) => {
                        let dt = now.duration_since(prev_t).as_secs_f64();
                        let (down, up) = if dt < 0.25 {
                            // 高频采样（<250ms）：沿用上次平滑值
                            (last_down, last_up)
                        } else {
                            let raw_down = if total_down >= prev_down {
                                ((total_down - prev_down) as f64 / dt) as f64
                            } else {
                                0.0
                            };
                            let raw_up = if total_up >= prev_up {
                                ((total_up - prev_up) as f64 / dt) as f64
                            } else {
                                0.0
                            };
                            // EMA 平滑：0.65 * prev + 0.35 * raw
                            let smooth_down = if raw_down == 0.0 && last_down < 1024 {
                                0.0
                            } else {
                                0.65 * last_down as f64 + 0.35 * raw_down
                            };
                            let smooth_up = if raw_up == 0.0 && last_up < 1024 {
                                0.0
                            } else {
                                0.65 * last_up as f64 + 0.35 * raw_up
                            };
                            (smooth_down as u64, smooth_up as u64)
                        };
                        *sample = Some((now, total_down, total_up, down, up));
                        (down, up)
                    }
                    None => {
                        *sample = Some((now, total_down, total_up, 0, 0));
                        (0, 0)
                    }
                }
            };

            // 【APP52 任务4】[流量开始转发]：选中节点会话内首次出现真实
            // download/upload 流量时记录一次（first_host + ip + 速率），
            // 节点切换或内核重启后重置，绝不刷屏。
            if let Some(conns) = conn_json.get("connections").and_then(|v| v.as_array()) {
                let first = conns.iter().find(|c| {
                    let dl = c.get("download").and_then(|v| v.as_u64()).unwrap_or(0);
                    let ul = c.get("upload").and_then(|v| v.as_u64()).unwrap_or(0);
                    dl > 0 || ul > 0
                });
                if let Some(c) = first {
                    let node_name = selected.clone().unwrap_or_else(|| "自动".into());
                    if logged_node.as_deref() != Some(node_name.as_str()) {
                        let meta = c.get("metadata").cloned().unwrap_or_default();
                        let host = meta
                            .get("host")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let dest_ip = meta
                            .get("destinationIP")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        crate::core::logger::info(
                            crate::core::logger::MOD_NODE,
                            &format!(
                                "{} 节点「{node_name}」首条流量 host={} ip={} ↓{} ↑{} B/s",
                                crate::core::logger::PHASE_FORWARDING,
                                if host.is_empty() { "-" } else { host },
                                if dest_ip.is_empty() { "-" } else { dest_ip },
                                down,
                                up
                            ),
                        );
                        logged_node = Some(node_name);
                    }
                }
            }

            let _ = app.emit(
                "telemetry://tick",
                serde_json::json!({
                    "down": down,
                    "up": up,
                    "today": today,
                    "running": true,
                    "selectedNode": selected,
                }),
            );
        }
    });
}

/// 运行时统计快照：今日流量 / 实时速率 / 60s 曲线 / 活跃连接 / 分析聚合。
/// 数据由 events.rs 的内核数据流实时维护在 AppState，前端无需轮询内核。
/// 【APP51 任务2】每次拉快照无条件 GET /connections（1500ms 硬超时）：
/// - HTTP 200 → 内核确实存活，若状态误报 Stopped/Error 立即自愈为 Running；
/// - dt < 0.15s → 直接沿用缓存的上下行速率（严禁 0,0 闪一下）；
/// - 超时/失败 → 保留上次速率的一半衰减，曲线不断档、绝不空白。
#[tauri::command]
pub async fn get_runtime_snapshot(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    // 1. 无条件探测：内核 API 可访问即视为运行中（修复「内核未运行」误报）
    let telemetry = async {
        let conn_json = state.kernel_api().get_connections().await.ok()?;
        let total_down = conn_json
            .get("downloadTotal")
            .and_then(|v| v.as_u64())
            .or_else(|| conn_json.get("downloadTotal").and_then(|v| v.as_f64().map(|f| f as u64)))?;
        let total_up = conn_json
            .get("uploadTotal")
            .and_then(|v| v.as_u64())
            .or_else(|| conn_json.get("uploadTotal").and_then(|v| v.as_f64().map(|f| f as u64)))?;
        Some((total_down, total_up))
    }
    .await;

    // 仅当处于 Stopped/Error 且内核 API 正常应答时自愈，避免干扰启动/停止中间态
    if telemetry.is_some() {
        let current = *state.status.read();
        if matches!(current, CoreStatus::Stopped | CoreStatus::Error) {
            let _ = state.transition(CoreStatus::Starting);
            let _ = state.transition(CoreStatus::Running);
        }
    }

    let mut display: Option<(u64, u64)> = None;
    if let Some((total_down, total_up)) = telemetry {
        let now = std::time::Instant::now();
        let mut sample = state.last_traffic_sample.lock();
        let (speed_down, speed_up) = match *sample {
            Some((prev_t, prev_down, prev_up, last_down, last_up)) => {
                let dt = now.duration_since(prev_t).as_secs_f64();
                if dt < 0.15 {
                    // 高频重复调用：沿用缓存，绝不返回 0,0
                    (last_down, last_up)
                } else if dt <= 10.0 && total_down >= prev_down && total_up >= prev_up {
                    // 【APP52 任务2】与后台遥测一致的 EMA(0.65/0.35) 平滑，
                    // 避免快照与 telemetry://tick 两路速率互相覆盖造成抖动。
                    let raw_down = (total_down - prev_down) as f64 / dt;
                    let raw_up = (total_up - prev_up) as f64 / dt;
                    let smooth_down = if raw_down == 0.0 && last_down < 1024 {
                        0.0
                    } else {
                        0.65 * last_down as f64 + 0.35 * raw_down
                    };
                    let smooth_up = if raw_up == 0.0 && last_up < 1024 {
                        0.0
                    } else {
                        0.65 * last_up as f64 + 0.35 * raw_up
                    };
                    (smooth_down as u64, smooth_up as u64)
                } else if dt <= 10.0 {
                    // 内核重启导致总量归零：本轮真实速率为 0
                    (0, 0)
                } else {
                    // 间隔过长（休眠/挂起）：沿用缓存避免瞬时尖峰
                    (last_down, last_up)
                }
            }
            None => (0, 0),
        };
        *sample = Some((now, total_down, total_up, speed_down, speed_up));
        drop(sample);
        display = Some((speed_down, speed_up));
    } else {
        // 探测失败：保留上次速率的一半衰减（不归零、不空白）
        let mut sample = state.last_traffic_sample.lock();
        if let Some((t, d, u, last_down, last_up)) = *sample {
            let decay_down = last_down / 2;
            let decay_up = last_up / 2;
            *sample = Some((t, d, u, decay_down, decay_up));
            display = Some((decay_down, decay_up));
        }
    }

    // 2. 追加一条 60s 环形队列样本（每秒一条）
    if let Some((down, up)) = display {
        // 不引入 chrono：以 Unix 秒换算 HH:MM:SS（events.rs 同款）
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let day = secs % 86400;
        let ts = format!("{:02}:{:02}:{:02}", day / 3600, day % 3600 / 60, day % 60);
        let mut hist = state.traffic_history.write();
        hist.push_back(crate::core::state::TrafficSample { time: ts, up, down });
        while hist.len() > 60 {
            hist.pop_front();
        }
    }

    Ok(state.runtime_snapshot())
}

#[tauri::command]
pub async fn add_traffic_tick(
    state: State<'_, AppState>,
    up: u64,
    down: u64,
) -> Result<crate::core::store::TrafficStats, String> {
    crate::core::store::add_traffic(&state.data_dir, up, down)
        .map_err(|e| sanitize_err(&e.to_string()))
}

#[tauri::command]
pub async fn get_rules(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mut result = state.kernel_api().get_rules().await.map_err(|e| sanitize_err(&e.to_string()))?;
    // 【APP-9 任务2.1c】Go Lan 启用时，在规则列表最顶部附带展示当前生效的
    // Go Lan 回家路由规则（type=IP-CIDR / DOMAIN-SUFFIX, proxy=go-lan-home），
    // 让用户在「代理 -> 规则」页直观看到 Go Lan 与规则系统的联动状态。
    let lan = state.go_lan.read().clone();
    if lan.enabled && !lan.lan_cidrs.is_empty() {
        if let Some(obj) = result.as_object_mut() {
            let mut go_lan_rules: Vec<serde_json::Value> = Vec::new();
            // 域名规则（若有）
            let domains: Vec<&str> = lan.lan_domains.iter()
                .map(|d| d.trim())
                .filter(|d| !d.is_empty())
                .collect();
            if !domains.is_empty() {
                go_lan_rules.push(serde_json::json!({
                    "type": "DOMAIN-SUFFIX",
                    "payload": format!("{} (Go Lan 回家域名)", domains.join(", ")),
                    "proxy": "go-lan-home",
                }));
            }
            // 网段规则
            go_lan_rules.push(serde_json::json!({
                "type": "IP-CIDR",
                "payload": format!("{} (Go Lan 回家内网)", lan.lan_cidrs.join(", ")),
                "proxy": "go-lan-home",
            }));
            if let Some(arr) = obj.get_mut("rules").and_then(|r| r.as_array_mut()) {
                let mut new_rules = go_lan_rules;
                new_rules.append(arr);
                *arr = new_rules;
            }
        }
    }
    Ok(result)
}

/// 【APP-9 任务1.3】获取本机局域网 IPv4 地址。
/// 通过 UDP socket connect("223.5.5.5:80") 读取 local_addr().ip()，
/// 无需真实发送数据包即可获取系统默认出口的局域网 IP。
/// 设置页「允许局域网连接」开启后展示给其他设备配置代理使用。
#[tauri::command]
pub async fn get_lan_ip() -> Result<Option<String>, String> {
    // 【APP44 任务6】优先取物理网卡的真实内网 IPv4（iOS 同样经 getifaddrs
    // 枚举 en0/pdp_ip0），避免 VPN 运行中 UDP 探测拿到 utun 的 10.196.0.2
    // 或 fake-ip 198.18.x.x，设置页展示的「局域网地址」才可被其他设备使用。
    if let Some(ip) = crate::core::go_lan::detect_physical_lan_ipv4s()
        .into_iter()
        .next()
    {
        return Ok(Some(ip.to_string()));
    }
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    // 连接到一个公网地址（不会真实发包），让系统选择最佳出口网卡
    socket.connect("223.5.5.5:80").map_err(|e| e.to_string())?;
    let addr = socket.local_addr().map_err(|e| e.to_string())?;
    let ip = addr.ip();
    if ip.is_ipv4() && !ip.is_loopback() {
        Ok(Some(ip.to_string()))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub async fn get_proxy_groups(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut resp = state
        .kernel_api()
        .get_proxies()
        .await
        .map_err(|e| sanitize_err(&e.to_string()))?;
    // 【APP52 任务1】后端双重排序（所有用户含非 Pro）：
    // 内核 history 末条延迟优先，缺失时用持久化缓存；
    // 每个策略组 all 数组按「>0 升序 → 未测速 → 0 超时」重排，
    // 并下发 prismDelays 供前端在内核重启后仍能恢复延迟显示。
    let mut effective: std::collections::HashMap<String, u32> =
        state.node_metrics.read().delays.clone();
    if let Some(proxies) = resp.get("proxies").and_then(|v| v.as_object()) {
        for (name, info) in proxies {
            if let Some(d) = info
                .get("history")
                .and_then(|h| h.as_array())
                .and_then(|a| a.last())
                .and_then(|e| e.get("delay"))
                .and_then(|d| d.as_u64())
            {
                effective.insert(name.clone(), d as u32);
            }
        }
    }
    if let Some(proxies) = resp.get_mut("proxies").and_then(|v| v.as_object_mut()) {
        for info in proxies.values_mut() {
            let Some(all) = info.get_mut("all").and_then(|v| v.as_array_mut()) else {
                continue;
            };
            all.sort_by_key(|item| {
                let name = item.as_str().unwrap_or("");
                crate::core::state::node_delay_sort_key(effective.get(name).copied())
            });
        }
    }
    if let Some(obj) = resp.as_object_mut() {
        obj.insert(
            "prismDelays".into(),
            serde_json::to_value(&effective).unwrap_or_default(),
        );
    }
    Ok(resp)
}

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> Result<UserSettings, String> {
    Ok(state.settings.read().clone())
}

#[tauri::command]
pub async fn save_settings(
    mut settings: UserSettings,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let prev = state.settings.read().clone();

    // 运行模式以 set_mode 为唯一入口（设置表单可能携带旧值，直接覆盖防止回退）
    settings.mode = *state.mode.read();
    // 【APP-11 任务3】Go AIM 开关与锁定节点由 set_go_aim_enabled 命令专属管理：
    // 设置表单不携带真实状态时会把仪表盘刚打开的 Go AIM 覆盖成 false，
    // 这里强制保留内存中的权威值，杜绝跨页面状态互相踩踏。
    settings.go_aim_enabled = prev.go_aim_enabled;
    settings.go_aim_pinned_node = prev.go_aim_pinned_node.clone();

    // 自启动立即生效
    crate::platform::set_auto_start(settings.auto_start).map_err(|e| sanitize_err(&e.to_string()))?;

    // 落盘 settings.json，重启后恢复
    let next = settings.clone();
    state
        .save_settings(settings)
        .map_err(|e| format!("保存设置失败: {e}"))?;

    // 影响入站/系统代理/出站结构的字段变更必须重建配置才能真实生效，
    // 否则系统代理指向旧端口、内核监听旧端口，显示与实际脱节
    // 【APP49 任务1】outbound_mode 不再触发重启：改走 Clash API PATCH 热切换
    let needs_restart = prev.mixed_port != next.mixed_port
        || prev.allow_lan != next.allow_lan
        || prev.system_proxy != next.system_proxy
        || prev.ipv6 != next.ipv6
        || prev.block_quic != next.block_quic;
    if needs_restart && *state.status.read() == CoreStatus::Running {
        restart_core(&app, &state).await?;
    }
    // 出站模式变化时热切换（与 set_outbound_mode 一致：内核不重启，
    // 仅按用户设置决定是否清理旧连接）
    if prev.outbound_mode != next.outbound_mode
        && *state.status.read() == CoreStatus::Running
    {
        let mode_str = match next.outbound_mode {
            crate::core::state::OutboundMode::Rule => "rule",
            crate::core::state::OutboundMode::Global => "global",
            crate::core::state::OutboundMode::Direct => "direct",
        };
        let api = state.kernel_api();
        if api.patch_mode(mode_str).await.is_ok() && next.close_connections_on_switch {
            let _ = api.close_all_connections().await;
        }
    }
    // 【APP-11 任务3】保存后广播最新设置，前端所有页面（仪表盘/设置）实时同步
    let _ = app.emit(
        "settings://updated",
        serde_json::to_value(state.settings.read().clone()).unwrap_or_default(),
    );
    Ok(())
}

// ============================== Go AIM（Pro） ==============================

/// Go AIM 状态：开关 / 锁定节点 / 探测进度 / 全量评级结果
#[tauri::command]
pub async fn get_go_aim_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    Ok(serde_json::to_value(crate::core::go_aim::status_dto(&state))
        .map_err(|e| sanitize_err(&e.to_string()))?)
}

/// 开关 Go AIM 自动锁定；开启且内核运行中时立即探测并锁定
///
/// 【APP-9 任务4.2】无论关闭还是重新打开，一律清空 go_aim_pinned_node，
/// 确保「关闭再打开」即刻恢复自动优选模式：
/// - enabled=false：清除锁定节点 + 清空手动指定；
/// - enabled=true：pinned 已清空 → 恢复自动模式；若内存有探测结果立即
///   按「全功能解锁 + 最低延迟」自动选点，否则启动新一轮探测后自动锁定。
#[tauri::command]
pub async fn set_go_aim_enabled(
    enabled: bool,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if enabled && !state.is_pro_active() {
        return Err("Go AIM 是 Pro 专属功能，请先激活授权".into());
    }
    let mut settings = state.settings.read().clone();
    settings.go_aim_enabled = enabled;
    // 关键：无论开关方向，一律清空手动指定节点，恢复自动优选
    settings.go_aim_pinned_node = None;
    // 【APP52 任务1】重开 Go AIM = 回到自动选点模式，允许按最低延迟重新指定
    settings.user_manually_selected_node = false;
    *state.user_manually_selected_node.write() = false;
    state
        .save_settings(settings)
        .map_err(|e| format!("保存设置失败: {e}"))?;
    if enabled && *state.status.read() == CoreStatus::Running {
        // 【APP51 任务1】开启动作 <1ms 返回：耗时探测全部转入后台任务，
        // 前端开关点击后立即变绿/变灰，绝不等待网络探测
        let app2 = app.clone();
        tauri::async_runtime::spawn(async move {
            let state = app2.state::<AppState>();
            if !state.settings.read().go_aim_enabled || *state.status.read() != CoreStatus::Running
            {
                return;
            }
            // 【APP39 任务4·时机A】开启瞬间立即锁定「当前延迟最低」节点
            let _ = crate::core::go_aim::lock_fastest_now(&app2, &state).await;
            // 用户可能在锁定期间关闭开关：再次确认
            if !state.settings.read().go_aim_enabled || *state.status.read() != CoreStatus::Running
            {
                return;
            }
            // 内存已有探测结果 → 按评级规则再校准一次；
            // 否则启动新一轮探测，完成后 apply_selection 自动锁定最佳节点
            let has_results = !state.aim_results.read().is_empty();
            if has_results {
                let _ = crate::core::go_aim::apply_selection(&app2, &state).await;
            } else {
                crate::core::go_aim::spawn_monitor(app2.clone());
                crate::core::go_aim::start_probe(app2.clone());
            }
        });
    }
    if !enabled {
        *state.aim_locked_node.write() = None;
        let _ = app.emit(crate::core::go_aim::AIM_EVENT, serde_json::json!({ "locked": null }));
        // 【APP26 任务2.3 时机3】关闭 Go AIM 且用户未手动点选节点 →
        // 自动回退到实测延迟最低的节点
        if *state.status.read() == CoreStatus::Running
            && should_auto_select(&state)
            && let Some(group) = state.main_selector.read().clone()
        {
            spawn_auto_select(
                app.clone(),
                state.api_addr.read().clone(),
                state.api_secret.read().clone(),
                group,
            );
        }
    }
    // 【APP-11 任务3】广播权威设置，仪表盘/代理页/设置页开关实时同步
    let _ = app.emit(
        "settings://updated",
        serde_json::to_value(state.settings.read().clone()).unwrap_or_default(),
    );
    Ok(())
}

/// 手动触发一轮全量探测（需内核运行中 + 授权激活）
#[tauri::command]
pub async fn run_go_aim_probe(app: AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
    // APP34：Go AIM 关闭时严禁执行全量探测——148 节点并发真实 HTTP
    // 探测会瞬间撑爆 iOS 扩展进程 50MB Jetsam 上限（「启动一会儿自动停止」）。
    if !state.settings.read().go_aim_enabled {
        return Ok(false);
    }
    if !state.is_pro_active() {
        return Err("Go AIM 是 Pro 专属功能，请先激活授权".into());
    }
    // 【APP53 任务2.3】预览模式（内核未运行）同样允许 Go AIM 执行：
    // 先全量测速（离线 TCP/TLS 握手）对可达节点做基线，再基于节点地区/出口 IP
    // 归属地智能识别 AI/流媒体解锁能力，内核启动后会二次用真实隧道刷新。
    // 内核运行时走原有的真实隧道探测路径（2800ms 超时 + 4 探针槽位）。
    let already = state.aim_probing.load(std::sync::atomic::Ordering::Acquire);
    if !already {
        let mut settings = state.settings.read().clone();
        settings.user_manually_selected_node = false;
        *state.user_manually_selected_node.write() = false;
        let _ = state.save_settings(settings);
        crate::core::go_aim::start_probe(app);
    }
    Ok(already)
}

/// 清除 Go AIM 手动指定的锁定节点，回到自动评级选点（APP-4 任务3.3）。
/// 内核运行中时立即触发一轮重新探测评级，自动模式即刻生效。
#[tauri::command]
pub async fn clear_go_aim_pinned_node(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if !state.is_pro_active() {
        return Err("Go AIM 是 Pro 专属功能，请先激活授权".into());
    }
    let mut settings = state.settings.read().clone();
    settings.go_aim_pinned_node = None;
    settings.user_manually_selected_node = false;
    *state.user_manually_selected_node.write() = false;
    state
        .save_settings(settings)
        .map_err(|e| format!("保存设置失败: {e}"))?;
    // 解除手动指定后立即重新评级选点（运行中才有意义）
    if state.settings.read().go_aim_enabled
        && *state.status.read() == CoreStatus::Running
    {
        crate::core::go_aim::spawn_monitor(app.clone());
        crate::core::go_aim::start_probe(app);
    }
    Ok(())
}

// ============================== Go Lan（Pro） ==============================

/// 读取回家网络配置
#[tauri::command]
pub async fn get_go_lan_settings(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    if !state.is_pro_active() {
        return Err("Go Lan 是 Pro 专属功能，请先激活授权".into());
    }
    let lan = state.go_lan.read().clone();
    let physical = crate::core::go_lan::detect_physical_lan_ipv4s();
    // 【APP54 任务1】每个档案注入运行时 isDirect（同网段命中或 35ms 内网网关可达）
    let direct_map: std::collections::HashMap<String, bool> = {
        let profiles = crate::core::go_lan::enabled_profiles(&lan);
        let phys = physical.clone();
        tokio::task::spawn_blocking(move || {
            profiles
                .into_iter()
                .map(|(_, p)| {
                    let hit = crate::core::go_lan::is_profile_lan_direct_active(&p, &phys);
                    (p.id.clone(), hit)
                })
                .collect::<std::collections::HashMap<String, bool>>()
        })
        .await
        .unwrap_or_default()
    };
    let mut value = serde_json::to_value(&lan).map_err(|e| sanitize_err(&e.to_string()))?;
    let mut any_direct = false;
    if let Some(profiles) = value.get_mut("profiles").and_then(|v| v.as_array_mut()) {
        for p in profiles.iter_mut() {
            let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let is_direct = direct_map.get(&id).copied().unwrap_or(false);
            if is_direct {
                any_direct = true;
            }
            if let Some(obj) = p.as_object_mut() {
                obj.insert("isDirect".into(), serde_json::json!(is_direct));
            }
        }
    }
    let direct_map_json: serde_json::Map<String, serde_json::Value> = direct_map
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!(v)))
        .collect();
    if let Some(obj) = value.as_object_mut() {
        obj.insert("goLanAnyDirect".into(), serde_json::json!(any_direct));
        obj.insert(
            "goLanProfileDirectMap".into(),
            serde_json::Value::Object(direct_map_json),
        );
    }
    Ok(value)
}

/// 【APP-11 任务1.3 / APP40 任务2】为每路启用档案推导探测目标网关
/// （取该档案每个 /24 与 WireGuard 虚拟地址的 `.1` 地址），返回 (tag, 网关)。
fn go_lan_gateway_targets(
    lan: &crate::core::go_lan::GoLanSettings,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (tag, profile) in crate::core::go_lan::enabled_profiles(lan) {
        let mut gateways: Vec<String> = Vec::new();
        let mut push = |ip_str: &str| {
            let parts: Vec<&str> = ip_str.split('.').collect();
            if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                let gw = format!("{}.{}.{}.1", parts[0], parts[1], parts[2]);
                if !gateways.contains(&gw) {
                    gateways.push(gw);
                }
            }
        };
        for cidr in crate::core::go_lan::profile_route_cidrs(&profile) {
            push(cidr.split('/').next().unwrap_or(""));
        }
        if let Some(wg) = &profile.wg_config {
            push(wg.local_ip.trim().split('/').next().unwrap_or(""));
        }
        if let Some(gw) = gateways.into_iter().next() {
            out.push((tag, gw));
        }
    }
    out
}

/// 【APP-11 任务1.3】主动触发 WireGuard 首次握手。
/// 内核就绪后（延迟 800ms）对每个启用档案的出站各探测一次网关：
/// 哪怕网关不响应 HTTP，探测包也会穿过隧道，立即在家庭路由器上
/// 产生 WireGuard 握手与连接记录。
/// 【APP30 任务3】每路档案只向主网关发起 1 次 Clash API delay
/// （timeout 1500ms），绝不再对多个网关逐个发裸 TCP / SOCKS5 握手——
/// log8.txt 第 78~81 行 4 条 `operation timed out (2m7s)` 就是多目标
/// 裸探测留下的半开连接。
fn spawn_go_lan_warmup(
    api_addr: String,
    api_secret: String,
    lan: &crate::core::go_lan::GoLanSettings,
) {
    let targets = go_lan_gateway_targets(lan);
    if api_addr.is_empty() || targets.is_empty() {
        return;
    }
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        let api = KernelApi::new(&api_addr, &api_secret);
        for (tag, gw) in targets {
            // 探测结果不重要（家庭网关多半不开 HTTP），只要 1 次请求触发握手
            let _ = api.test_delay(&tag, &format!("http://{gw}"), 1500).await;
            crate::core::logger::info(
                crate::core::logger::MOD_GO_LAN,
                &format!("主动握手探测完成，已向 {tag} 网关 {gw} 发送 1 次 Clash API 请求"),
            );
        }
    });
}

/// 保存回家网络配置；内核运行中时重建配置生效
///
/// 【IPA9 任务2】保存与重启解耦：持久化写入 + state 更新 + 事件广播后
/// 立即返回 Ok，内核/隧道重启（iOS 会同步停止并重载扩展）放入后台
/// `tauri::async_runtime::spawn` 异步执行，避免前端 saveGoLanSettings IPC
/// 卡在等待 iOS 扩展重启上导致弹窗 saving 状态永久卡死。
#[tauri::command]
pub async fn save_go_lan_settings(
    settings: serde_json::Value,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    if !state.is_pro_active() {
        return Err("Go Lan 是 Pro 专属功能，请先激活授权".into());
    }
    let mut lan: crate::core::go_lan::GoLanSettings =
        serde_json::from_value(settings).map_err(|e| format!("配置格式错误: {e}"))?;
    // 【APP40 任务2】保存前自动迁移旧版单配置 → 多路档案，并校正档案 id
    crate::core::go_lan::normalize_go_lan_settings(&mut lan);
    // 【APP52 任务3】标准 WireGuard 完整性硬校验：启用档案若是 WG 隧道
    // （无分享链接）但 endpoint/私钥/CIDR 非标准 → 拒绝启用，绝不进入隧道。
    if lan.enabled && lan.mode == "manual" {
        for (_, profile) in crate::core::go_lan::enabled_profiles(&lan) {
            if profile.node_uri.trim().is_empty()
                && let Some(_wg) = profile.wg_config.as_ref()
                && !crate::core::go_lan::is_valid_standard_wg_config(&profile)
            {
                return Err(format!(
                    "内网档案「{}」的 WireGuard 配置不完整或格式非标准（endpoint/端口、IPv4 CIDR、32 字节 Base64 密钥、有效内网网段均为必填）",
                    profile.name
                ));
            }
        }
    }
    // APP 任务5 后端兜底：未配置完整参数时严禁启用
    if lan.enabled && !crate::core::go_lan::is_configured(&lan) {
        return Err("请先填写完整的回家节点参数与内网网段后再启用 Go Lan".into());
    }
    // 【APP52 任务3】保存前后「有效启用隧道」快照比较：完全相等时只写
    // settings.json + 持久化，绝不触发 vpn_reload / 内核重启。
    let prev_tunnel_snapshot = crate::core::go_lan::valid_enabled_tunnel_snapshot(&state.go_lan.read());
    let next_tunnel_snapshot = crate::core::go_lan::valid_enabled_tunnel_snapshot(&lan);
    let tunnels_unchanged = prev_tunnel_snapshot == next_tunnel_snapshot;
    crate::core::go_lan::save(&state.data_dir, &lan)?;
    *state.go_lan.write() = lan.clone();

    // 【APP30 任务3】保存即预热 Endpoint 域名解析（DoH 60s 缓存）：
    // 下次启动 build_config 直接命中缓存拿到最新 IPv4，避免扩展侧系统
    // getaddrinfo 读到旧 DDNS 记录（log8.txt 第 39~44 行
    // ishow.indevs.in 旧 14.105.65.44 / 新 14.105.65.122）。
    // 【APP40 任务2】逐档案预热（每路内网可能有独立 Endpoint 域名）
    for (_, profile) in crate::core::go_lan::enabled_profiles(&lan) {
        if let Some(server) = profile.wg_config.as_ref().map(|wg| wg.server.clone()) {
            if !server.trim().is_empty() {
                std::thread::spawn(move || {
                    let _ = crate::core::go_lan::resolve_endpoint_host_to_ip(&server);
                });
            }
        }
    }

    let (_, warnings) = crate::core::go_lan::go_lan_route_rules(&lan);

    let _ = app.emit("go-lan://updated", serde_json::to_value(&lan).unwrap_or_default());
    let _ = app.emit(
        "settings://updated",
        serde_json::to_value(state.settings.read().clone()).unwrap_or_default(),
    );

    // 运行中且隧道结构确有变化 → 后台异步重建内核配置生效；
    // 【APP52 任务3】快照相等（如新增空白档案 / 仅改名）只写 settings.json，
    // 严禁 vpn_reload / 重启内核，避免无意义断网。
    if *state.status.read() == CoreStatus::Running && !tunnels_unchanged {
        let app_clone = app.clone();
        let lan_clone = lan.clone();
        tauri::async_runtime::spawn(async move {
            // 在 spawn 内部通过 app.state() 获取 'static 生命周期的 AppState，
            // 避免命令参数 State<'_, AppState> 的非 'static 借用逃逸
            let state_static = app_clone.state::<AppState>();
            if let Err(e) = restart_core(&app_clone, &state_static).await {
                tracing::warn!("[go-lan] 保存后后台重启内核失败: {e}");
            }
            // 【APP-11 任务1.3】开启后主动打一个回家探测包
            if lan_clone.enabled {
                spawn_go_lan_warmup(
                    state_static.api_addr.read().clone(),
                    state_static.api_secret.read().clone(),
                    &lan_clone,
                );
            }
        });
    }
    Ok(warnings)
}

/// 【APP40 任务2】内网档案运行状态（Dashboard / Settings / GoLanModal 徽章数据源）。
/// 返回每个启用档案的 On-Demand 判定结果：
/// - `direct`：本机物理局域网命中该档案网段，已跳过 WG 隧道；
/// - `tunnel`：需要走 WireGuard 隧道；
/// - iOS 侧由扩展实时判定并写入 `golan_bypass.json` 侧车，主程序读取后保持一致。
#[tauri::command]
pub async fn get_go_lan_status(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let lan = state.go_lan.read().clone();
    let physical = crate::core::go_lan::detect_physical_lan_ipv4s();
    let ios_bypass = read_ios_bypass_sidecar(&state.work_dir());
    // 【APP54 任务1】直连判定含 35ms 同步 TCP 探针，放 blocking 线程执行，
    // 避免阻塞 tokio runtime；判定结果同时供 profile.isDirect / anyDirect 使用。
    let direct_map: std::collections::HashMap<String, bool> = {
        let profiles = crate::core::go_lan::enabled_profiles(&lan);
        let phys = physical.clone();
        tokio::task::spawn_blocking(move || {
            profiles
                .into_iter()
                .map(|(tag, p)| {
                    let hit = crate::core::go_lan::is_profile_lan_direct_active(&p, &phys);
                    (tag, hit)
                })
                .collect::<std::collections::HashMap<String, bool>>()
        })
        .await
        .unwrap_or_default()
    };
    let mut items: Vec<serde_json::Value> = Vec::new();
    let mut any_on_demand_direct = false;
    let mut profile_states = serde_json::Map::new();
    let mut profile_direct_map = serde_json::Map::new();
    for (tag, profile) in crate::core::go_lan::enabled_profiles(&lan) {
        let direct_hit = direct_map.get(&tag).copied().unwrap_or(false);
        let (tunnel, direct) =
            crate::core::go_lan::split_profile_cidrs_for_on_demand(&profile, &physical);
        let mut bypassed = direct.clone();
        if bypassed.is_empty() {
            if let Some(cidrs) = ios_bypass.iter().find(|(t, _)| t == &tag).map(|(_, c)| c) {
                bypassed = cidrs.clone();
            }
        }
        let state_str = if direct_hit || !bypassed.is_empty() {
            "direct"
        } else {
            "tunnel"
        };
        if state_str == "direct" {
            any_on_demand_direct = true;
        }
        profile_states.insert(profile.id.clone(), serde_json::json!(state_str));
        profile_direct_map.insert(profile.id.clone(), serde_json::json!(direct_hit));
        items.push(serde_json::json!({
            "tag": tag,
            "id": profile.id,
            "name": profile.name,
            "enabled": profile.enabled,
            "onDemand": profile.bypass_on_local_lan,
            "isDirect": direct_hit,
            "state": state_str,
            "bypassCidrs": bypassed,
            "tunnelCidrs": tunnel,
        }));
    }
    for profile in lan.profiles.iter().filter(|p| !p.enabled) {
        profile_states.insert(profile.id.clone(), serde_json::json!("off"));
        profile_direct_map.insert(profile.id.clone(), serde_json::json!(false));
    }
    Ok(serde_json::json!({
        "profiles": items,
        "physicalIps": physical.iter().map(|ip| ip.to_string()).collect::<Vec<String>>(),
        "anyOnDemandDirect": any_on_demand_direct,
        "goLanAnyDirect": any_on_demand_direct,
        "profileStates": profile_states,
        "goLanProfileDirectMap": profile_direct_map,
    }))
}

/// iOS 扩展写入的 On-Demand 侧车（`[{"tag": "...", "cidrs": [...]}]`）。
/// 其他平台恒为空，由 Rust 侧 `detect_physical_lan_ipv4s` 直接判定。
fn read_ios_bypass_sidecar(
    work_dir: &std::path::Path,
) -> Vec<(String, Vec<String>)> {
    #[cfg(not(target_os = "ios"))]
    {
        let _ = work_dir;
        return Vec::new();
    }
    #[cfg(target_os = "ios")]
    {
        let path = work_dir.join("golan_bypass.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            return Vec::new();
        };
        value
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let tag = item.get("tag")?.as_str()?.to_string();
                        let cidrs = item
                            .get("cidrs")?
                            .as_array()?
                            .iter()
                            .filter_map(|c| c.as_str())
                            .map(str::to_string)
                            .collect::<Vec<String>>();
                        Some((tag, cidrs))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Managed 模式：向授权服务器拉取回家节点配置
#[tauri::command]
pub async fn sync_go_lan_managed(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let lan = crate::core::go_lan::sync_managed(&app).await?;
    // 拉取成功后若内核运行中，重建配置生效
    if *state.status.read() == CoreStatus::Running {
        restart_core(&app, &state).await?;
    }
    serde_json::to_value(lan).map_err(|e| sanitize_err(&e.to_string()))
}

/// 【APP-5 任务2】穿过 go-lan-home 隧道检测是否能到达指定内网 IP，
/// 返回真实延迟毫秒数并瞬间触发 wg-easy 连接状态。
#[tauri::command]
pub async fn test_go_lan_ip(
    target_ip: Option<String>,
    state: State<'_, AppState>,
) -> Result<crate::core::go_lan::GoLanProbeResult, String> {
    // 提前 .clone() 取走锁内值，避免 parking_lot::RwLockReadGuard（非 Send）
    // 跨越 await 边界导致 tauri::command Future + Send 要求失败
    let (go_lan_enabled, api_addr, api_secret, lan) = {
        let go_lan_cfg = state.go_lan.read();
        (
            go_lan_cfg.enabled,
            state.api_addr.read().clone(),
            state.api_secret.read().clone(),
            go_lan_cfg.clone(),
        )
    };
    // 【APP6 任务2】iOS 上 VPN 内核运行在独立 PrismVPN 扩展进程，
    // 子进程句柄恒为空，必须结合 NEPacketTunnelFlow 的连接状态判断，
    // 否则 iOS 上启动 VPN 后「检测内网」被误判为未运行
    let is_running = is_vpn_actually_running(&state);
    let result = crate::core::go_lan::probe_intranet_ip(
        target_ip.as_deref(),
        &api_addr,
        &api_secret,
        is_running,
        go_lan_enabled,
        &lan,
    )
    .await;
    Ok(result)
}

/// 【APP6 任务2】VPN 是否真实在运行：
/// 桌面端看内核子进程状态；iOS 上内核运行在独立 PrismVPN 扩展进程，
/// `state.is_running()` 恒为 false，必须叠加 `vpn_is_connected()`
/// （NEVPNManager 连接状态）才能准确识别。
pub fn is_vpn_actually_running(state: &AppState) -> bool {
    let core_running = *state.status.read() == CoreStatus::Running;
    #[cfg(target_os = "ios")]
    {
        core_running || crate::platform::ios::vpn_is_connected()
    }
    #[cfg(not(target_os = "ios"))]
    {
        core_running
    }
}

// ============================== Go Cus（Pro） ==============================

/// 读取覆写引擎配置
#[tauri::command]
pub async fn get_go_cus_settings(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    if !state.is_pro_active() {
        return Err("Go Cus 是 Pro 专属功能，请先激活授权".into());
    }
    let cus = state.go_cus.read().clone();
    serde_json::to_value(cus).map_err(|e| sanitize_err(&e.to_string()))
}

/// 保存覆写引擎基础设置（enabled / mitm / dns / hosts）；运行中重建生效
#[tauri::command]
pub async fn save_go_cus_settings(
    settings: serde_json::Value,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if !state.is_pro_active() {
        return Err("Go Cus 是 Pro 专属功能，请先激活授权".into());
    }
    let cus: crate::core::go_cus::GoCusSettings =
        serde_json::from_value(settings).map_err(|e| format!("配置格式错误: {e}"))?;
    crate::core::go_cus::save(&state.data_dir, &cus)?;
    *state.go_cus.write() = cus.clone();
    if *state.status.read() == CoreStatus::Running {
        restart_core(&app, &state).await?;
    }
    // 【APP-11 任务3】广播 Go Cus 最新配置，仪表盘/代理页开关实时同步
    let _ = app.emit(
        "go-cus://updated",
        serde_json::to_value(&cus).unwrap_or_default(),
    );
    Ok(())
}

/// 导入模块：http(s) URL 自动下载，否则按本地内容解析
#[tauri::command]
pub async fn import_go_cus_module(
    source: String,
    name: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    if !state.is_pro_active() {
        return Err("Go Cus 是 Pro 专属功能，请先激活授权".into());
    }
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return Err("请输入模块链接或粘贴模块内容".into());
    }
    let raw = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        crate::core::go_cus::fetch_module_text(trimmed).await?
    } else {
        trimmed.to_string()
    };
    let mut cus = state.go_cus.read().clone();
    let module = crate::core::go_cus::upsert_module(&mut cus, trimmed, &raw, name.as_deref())?;
    crate::core::go_cus::save(&state.data_dir, &cus)?;
    *state.go_cus.write() = cus.clone();
    // 【APP6 任务1】[GoCus] 模块日志：模块加载数量
    crate::core::logger::info(
        crate::core::logger::MOD_GO_CUS,
        &format!(
            "Go Cus 模块已导入: {}（当前共 {} 个模块）",
            module.name,
            cus.modules.len()
        ),
    );
    // 首个模块导入即自动启用引擎并拉起边车
    let mut cus = state.go_cus.read().clone();
    let mut changed = false;
    if !cus.enabled {
        cus.enabled = true;
        changed = true;
    }
    if changed {
        crate::core::go_cus::save(&state.data_dir, &cus)?;
        *state.go_cus.write() = cus;
    }
    crate::core::go_cus::ensure_sidecar(app.clone());
    if *state.status.read() == CoreStatus::Running {
        restart_core(&app, &state).await?;
    }
    serde_json::to_value(module).map_err(|e| sanitize_err(&e.to_string()))
}

/// 启停模块；启用状态变化时运行中内核重建生效
#[tauri::command]
pub async fn toggle_go_cus_module(
    id: String,
    enabled: bool,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if !state.is_pro_active() {
        return Err("Go Cus 是 Pro 专属功能，请先激活授权".into());
    }
    let mut cus = state.go_cus.read().clone();
    let Some(module) = cus.modules.iter_mut().find(|m| m.id == id) else {
        return Err("模块不存在".into());
    };
    module.enabled = enabled;
    crate::core::go_cus::save(&state.data_dir, &cus)?;
    *state.go_cus.write() = cus;
    if *state.status.read() == CoreStatus::Running {
        restart_core(&app, &state).await?;
    }
    Ok(())
}

/// 删除模块
#[tauri::command]
pub async fn delete_go_cus_module(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if !state.is_pro_active() {
        return Err("Go Cus 是 Pro 专属功能，请先激活授权".into());
    }
    let mut cus = state.go_cus.read().clone();
    let before = cus.modules.len();
    cus.modules.retain(|m| m.id != id);
    if cus.modules.len() == before {
        return Err("模块不存在".into());
    }
    crate::core::go_cus::save(&state.data_dir, &cus)?;
    *state.go_cus.write() = cus;
    if *state.status.read() == CoreStatus::Running {
        restart_core(&app, &state).await?;
    }
    Ok(())
}

/// 生成/读取 Root CA 并确保分发服务运行（返回指纹 + 安装 URL）
#[tauri::command]
pub async fn generate_or_get_ca_url(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    if !state.is_pro_active() {
        return Err("Go Cus 是 Pro 专属功能，请先激活授权".into());
    }
    let info = crate::core::go_cus::generate_or_get_ca(&state, app)?;
    serde_json::to_value(info).map_err(|e| sanitize_err(&e.to_string()))
}

// ============================== 全模块运行日志（APP6 任务1） ==============================

/// 读取全模块运行日志（可选按模块过滤），自动合并内核日志与 iOS 扩展诊断日志
#[tauri::command]
pub async fn get_app_logs(
    module_filter: Option<String>,
    state: State<'_, AppState>,
) -> Result<crate::core::logger::LogsPayload, String> {
    Ok(crate::core::logger::get_logs(
        &state.data_dir,
        module_filter.as_deref(),
    ))
}

/// 清空全部日志（内存 + prism_app.log + 内核 kernel.log + iOS 扩展诊断缓存）
#[tauri::command]
pub async fn clear_app_logs(state: State<'_, AppState>) -> Result<(), String> {
    crate::core::logger::clear_logs(&state.data_dir);
    crate::core::logger::info(crate::core::logger::MOD_KERNEL, "日志已清空（内存与本地文件）");
    Ok(())
}

/// 导出带设备环境头信息的格式化纯文本日志（WireGuard 私钥 / License Key 自动脱敏）
#[tauri::command]
pub async fn export_app_logs(
    module_filter: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    Ok(crate::core::logger::export_logs(
        &state.data_dir,
        module_filter.as_deref(),
    ))
}

#[cfg(test)]
mod app51_tests {
    use super::fallback_selected_node;

    /// 【APP51 任务1】停用/删除订阅后的选中节点清理：
    /// 节点仍有效 → 保留；节点失效 → 回退到第一个可用节点；无可用节点 → None。
    #[test]
    fn test_fallback_selected_node_after_subscription_change() {
        let valid = vec!["香港01".to_string(), "日本02".to_string()];
        assert_eq!(
            fallback_selected_node(Some("日本02"), &valid).as_deref(),
            Some("日本02")
        );
        // 被停用/删除订阅里的旧节点 → 回退
        assert_eq!(
            fallback_selected_node(Some("已删除节点"), &valid).as_deref(),
            Some("香港01")
        );
        assert_eq!(fallback_selected_node(None, &valid).as_deref(), Some("香港01"));
        assert_eq!(fallback_selected_node(Some("任意"), &[]), None);
    }
}
