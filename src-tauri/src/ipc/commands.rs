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
use crate::core::state::{AppState, CoreStatus, OutboundMode, RunMode, UserSettings, is_port_free, pick_api_addr};

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

    // 启动后自动测速并切换到延迟最低的可用节点（用户随后仍可手动改选）
    if let Some(group) = state.main_selector.read().clone() {
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
    let mut profiles = load_enabled_profiles(state);
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
            profiles = load_enabled_profiles(state);
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
        if !is_port_free(listen_host, settings.mixed_port) {
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
    *state.main_selector.write() = main;

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

    // 与 start_core 一致：重启后自动测速选点
    if let Some(group) = state.main_selector.read().clone() {
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

/// 后台任务：对主选择组整组测速，自动切换到延迟最低的可用叶子节点
fn spawn_auto_select(app: AppHandle, api_addr: String, api_secret: String, group: String) {
    tauri::async_runtime::spawn(async move {
        use tauri::Emitter as _;
        let api = KernelApi::new(&api_addr, &api_secret);
        match auto_select_fastest(&api, &group).await {
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
async fn auto_select_fastest(api: &KernelApi, group: &str) -> anyhow::Result<Option<String>> {
    const GROUP_TYPES: [&str; 4] = ["Selector", "URLTest", "Fallback", "LoadBalance"];

    let delays = api.group_url_test(group, None, Some(2000), None).await?;
    let proxies = api.get_proxies().await?;
    let empty = serde_json::Map::new();
    let map = proxies
        .get("proxies")
        .and_then(|p| p.as_object())
        .unwrap_or(&empty);

    let best = delays
        .as_object()
        .into_iter()
        .flatten()
        // 【APP-10 任务2】大小写不敏感 + 中文"直连"统一过滤内置非代理出站
        .filter(|(name, _)| {
            !crate::core::config_builder::is_builtin_non_proxy_tag(name.as_str())
        })
        .filter(|(name, _)| {
            let kind = map
                .get(*name)
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str())
                .unwrap_or_default();
            !GROUP_TYPES.contains(&kind)
        })
        .filter_map(|(name, delay)| delay.as_u64().map(|d| (name.clone(), d)))
        .min_by_key(|(_, d)| *d)
        .map(|(name, _)| name);

    if let Some(best) = &best {
        api.select_proxy(group, best).await?;
    }
    Ok(best)
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

    Ok(())
}

#[tauri::command]
pub async fn get_core_status(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreStatusDto, String> {
    // APP-5 任务3：强退重开后首帧即认领后台仍在运行的隧道。
    // 进程内只尝试一次（reattach_attempted），避免状态轮询反复探测。
    if *state.status.read() == CoreStatus::Stopped
        && !state
            .reattach_attempted
            .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        if crate::core::kernel::try_reattach_running_kernel(&app, state.inner()).await {
            tracing::info!("[reattach] 状态已恢复为 Running");
        }
    }

    let uptime_secs = state
        .started_at
        .read()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    Ok(CoreStatusDto {
        status: *state.status.read(),
        mode: *state.mode.read(),
        uptime_secs,
        started_at_ms: *state.started_at_ms.read(),
        main_selector: state.main_selector.read().clone(),
        outbound_mode: state.settings.read().outbound_mode,
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
    mode: RunMode,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // iOS 强制 TUN 模式（build 149 方案）：不存在桌面端系统代理，
    // 前端若仍传 SystemProxy 一律归一为 Tun
    #[cfg(target_os = "ios")]
    let mode = RunMode::Tun;
    #[cfg(not(target_os = "ios"))]
    let mode = mode;
    let prev = *state.mode.read();
    if prev == mode {
        return Ok(());
    }
    *state.mode.write() = mode;

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
        // 旧连接继续走旧出口直至自然结束，主动清理保证立即按新模式路由
        let _ = api.close_all_connections().await;
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
    // 【APP11 任务4.3】用户手动切换节点时，若 Go AIM 正在探测，立即发出
    // 中止信号：避免探测继续消耗探针槽位、干扰内核日志，并被随后的
    // 自动锁定覆盖掉用户刚选的节点。
    if state.aim_probing.load(std::sync::atomic::Ordering::Acquire) {
        state
            .aim_abort
            .store(true, std::sync::atomic::Ordering::Release);
        tracing::info!("[go-aim] 检测到用户手动切换节点，已发出探测中止信号");
    }
    state
        .kernel_api()
        .select_proxy(&group, &name)
        .await
        .map_err(|e| sanitize_err(&e.to_string()))?;

    // 全局模式同步（build 172 方案）：GLOBAL 选择组与主组保持同一节点。
    // clash_mode global 规则指向独立的 GLOBAL 组，若只切主组，切到
    // 全局模式后流量会落到 GLOBAL 的默认（第一个）节点——与用户所选脱节
    if group != "GLOBAL" {
        let _ = state.kernel_api().select_proxy("GLOBAL", &name).await;
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
#[tauri::command]
pub async fn update_subscription(
    url: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    refresh_subscription(&app, &state, &url).await?;
    // Pro/买断：静默上报云端（其他设备下次对账时拉取）
    let app2 = app.clone();
    let url2 = url.clone();
    tauri::async_runtime::spawn(async move {
        super::super::core::sync_links::push_link(&app2, &url2, None).await;
    });
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
    let (mut text, quota) = fetch_remote_text(&url, local_proxy).await?;

    // base64 包裹：明文不含 YAML/JSON 结构时尝试解码
    if !text.contains("proxies") && !text.trim_start().starts_with('{') {
        if let Ok(decoded) = try_decode_base64(&text) {
            text = decoded;
        }
    }

    // URI 列表订阅（ss:// vmess:// vless:// trojan:// hysteria2:// tuic:// 分享链接）：
    // 解析为节点并合成 Clash YAML，复用统一 pipeline，不再拒绝
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

    // 内核运行中：重建配置重启，新订阅即刻生效
    if *state.status.read() == CoreStatus::Running {
        tracing::info!("subscription updated, restarting core");
        restart_core(app, state).await?;
    }

    Ok(())
}

/// 订阅下载候选 User-Agent（按兼容性从强到弱轮询）：
/// 1. clash-verge —— 绝大多数要求 Clash 格式的面板；
/// 2. Shadowrocket —— 屏蔽 Clash UA 的面板；
/// 3. 通用浏览器 —— 只放行浏览器 UA 的兜底。
const SUBSCRIPTION_UAS: [&str; 3] = [
    "clash-verge/v1.7.7",
    "Shadowrocket/2078 CFNetwork/1410.0.3 Darwin/22.6.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
];

/// 单次订阅请求超时（方案要求 12 秒；黑洞地址由 connect_timeout 快速失败）
const SUBSCRIPTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);

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

/// 下载远程文本（订阅 / proxy-provider 共用）。
/// 三级回退闭环：
/// 1. 多 UA 直连竞速（自动探测 + 强制 IPv4 同时发起）；
/// 2. 内核运行中经本地 mixed 入站转发（受限网络走节点出境）；
/// 3. 全部失败时给出可自助定位的精确原因。
async fn fetch_remote_text(
    url: &str,
    local_proxy: Option<u16>,
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
            .connect_timeout(std::time::Duration::from_secs(8))
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
    for ua in SUBSCRIPTION_UAS {
        for force_v4 in [false, true] {
            let client = build_client(force_v4, ua)?;
            let target = url.clone();
            attempts.push(async move { (force_v4, ua, try_fetch_text(&client, &target).await) });
        }
    }

    while let Some((force_v4, ua, result)) = attempts.next().await {
        match result {
            Ok((text, quota)) => {
                tracing::info!(
                    "fetch succeeded (ua={}, force_v4={force_v4}) in {}ms",
                    ua.split('/').next().unwrap_or(ua),
                    fetch_started.elapsed().as_millis()
                );
                return Ok((text, quota));
            }
            Err(e) => {
                last_err = e;
                tracing::warn!(
                    "fetch direct (ua={}, force_v4={force_v4}) failed at {}ms: {last_err}",
                    ua.split('/').next().unwrap_or(ua),
                    fetch_started.elapsed().as_millis()
                );
            }
        }
    }

    // ---- 内核运行中：经本地 mixed 入站转发（同样轮询多 UA）----
    if let Some(port) = local_proxy {
        let proxy = reqwest::Proxy::all(&format!("http://127.0.0.1:{port}"))
            .map_err(|e| format!("配置本地代理失败: {e}"))?;
        for ua in SUBSCRIPTION_UAS {
            let builder = reqwest::Client::builder()
                .http1_only()
                .user_agent(ua)
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
        Err(format!(
            "下载失败：{last_err}（直连与本地代理转发均已尝试，请检查节点可用性后重试）"
        ))
    } else {
        Err(format!(
            "下载失败：{last_err}（已尝试多 UA 与 IPv4 直连；若机器处于受限网络，请先启动内核再更新订阅）"
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
                match fetch_remote_text(&url, local_proxy).await {
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
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedProxyDto {
    pub name: String,
    pub kind: String,
    pub server: String,
    pub port: u16,
    /// 来源订阅 URL（用于 UI 分组）
    pub from_subscription: String,
}

/// 内核未运行时从订阅缓存读取节点列表（节点页预览）
/// 内核运行时优先用 get_proxy_groups（含实时延迟）
#[tauri::command]
pub async fn get_cached_proxies(
    state: State<'_, AppState>,
) -> Result<Vec<CachedProxyDto>, String> {
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
                if server.starts_with("127.") || server == "localhost" {
                    continue;
                }
                out.push(CachedProxyDto {
                    name,
                    kind,
                    server,
                    port,
                    from_subscription: r.url.clone(),
                });
            }
        }
    }
    Ok(out)
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
    crate::core::store::save_custom_rules(&state.data_dir, &rules)
        .map_err(|e| format!("保存自定义规则失败: {e}"))?;
    if *state.status.read() == CoreStatus::Running {
        restart_core(&app, &state).await?;
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
    let was_running = *state.status.read() == CoreStatus::Running;
    let before = crate::core::store::load_subscriptions(&state.data_dir);
    if was_running {
        let _ = do_stop(&state).await;
    }

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

    // 3. 恢复内核（若同步前在运行）
    if was_running {
        let app2 = app.clone();
        let state2 = app2.state::<AppState>();
        let _ = start_core_inner(&app2, &state2).await;
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
#[tauri::command]
pub async fn deactivate_pro(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<EntitlementStatus, String> {
    // 【APP-13 任务4】先通知服务端解绑（释放设备名额，其他设备可直接激活），
    // 必须在本地缓存清理前调用；失败静默忽略，绝不阻断本地移除。
    // 先克隆 settings 再 await：避免 RwLock 读锁跨 await 导致 future 非 Send。
    let settings_snapshot = state.settings.read().clone();
    let _ = crate::core::license::release_device(&state.data_dir, &settings_snapshot).await;
    let next = crate::core::license::deactivate(&state.data_dir);
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
        *state.kernel_version.write() =
            Some(format!("{} （内置）", crate::core::kernel::EMBEDDED_VERSION));
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
        let version = state.kernel_version.read().clone().or_else(|| {
            Some(format!("{} （内置）", crate::core::kernel::EMBEDDED_VERSION))
        });
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

#[tauri::command]
pub async fn get_connections(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    state
        .kernel_api()
        .get_connections()
        .await
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

#[tauri::command]
pub async fn get_traffic_stats(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    // 实时流量走 WebSocket 事件（traffic://tick），此处返回持久化统计 + 当前连接快照
    let stats = crate::core::store::load_traffic_stats(&state.data_dir);
    let conns = state.kernel_api().get_connections().await.unwrap_or_default();
    Ok(serde_json::json!({
        "stats": stats,
        "connections": conns,
    }))
}

/// 运行时统计快照：今日流量 / 实时速率 / 60s 曲线 / 活跃连接 / 分析聚合。
/// 数据由 events.rs 的内核数据流实时维护在 AppState，前端无需轮询内核。
#[tauri::command]
pub async fn get_runtime_snapshot(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
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
    state
        .kernel_api()
        .get_proxies()
        .await
        .map_err(|e| sanitize_err(&e.to_string()))
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
    let needs_restart = prev.mixed_port != next.mixed_port
        || prev.allow_lan != next.allow_lan
        || prev.system_proxy != next.system_proxy
        || prev.outbound_mode != next.outbound_mode
        || prev.ipv6 != next.ipv6
        || prev.block_quic != next.block_quic;
    if needs_restart && *state.status.read() == CoreStatus::Running {
        restart_core(&app, &state).await?;
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
    state
        .save_settings(settings)
        .map_err(|e| format!("保存设置失败: {e}"))?;
    if enabled && *state.status.read() == CoreStatus::Running {
        // 内存已有探测结果 → 0ms 立即按评级规则自动锁定最优节点；
        // 否则启动探测，完成后 apply_selection 会自动选中最佳节点
        let has_results = !state.aim_results.read().is_empty();
        if has_results {
            let _ = crate::core::go_aim::apply_selection(&app, &state).await;
        } else {
            crate::core::go_aim::spawn_monitor(app.clone());
            crate::core::go_aim::start_probe(app.clone());
        }
    }
    if !enabled {
        *state.aim_locked_node.write() = None;
        let _ = app.emit(crate::core::go_aim::AIM_EVENT, serde_json::json!({ "locked": null }));
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
    if !state.is_pro_active() {
        return Err("Go AIM 是 Pro 专属功能，请先激活授权".into());
    }
    if *state.status.read() != CoreStatus::Running {
        return Err("请先启动代理内核后再执行 Go AIM 真实节点检测".into());
    }
    let already = state.aim_probing.load(std::sync::atomic::Ordering::Acquire);
    if !already {
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
    serde_json::to_value(lan).map_err(|e| sanitize_err(&e.to_string()))
}

/// 【APP-11 任务1.3】从回家网段推导探测目标网关（取每个 /24 的 .1 地址）。
fn go_lan_gateway_targets(lan: &crate::core::go_lan::GoLanSettings) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |ip_str: &str| {
        let parts: Vec<&str> = ip_str.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            let gw = format!("{}.{}.{}.1", parts[0], parts[1], parts[2]);
            if !out.contains(&gw) {
                out.push(gw);
            }
        }
    };
    for cidr in &lan.lan_cidrs {
        push(cidr.trim().split('/').next().unwrap_or(""));
    }
    if let Some(wg) = &lan.wg_config {
        push(wg.local_ip.trim().split('/').next().unwrap_or(""));
    }
    out
}

/// 【APP-11 任务1.3】主动触发 WireGuard 首次握手。
/// 内核就绪后（延迟 800ms）对 go-lan-home 出站逐个探测家庭网关：
/// 哪怕网关不响应 HTTP，探测包也会穿过隧道，立即在家庭路由器上
/// 产生 WireGuard 握手与连接记录。
fn spawn_go_lan_warmup(
    api_addr: String,
    api_secret: String,
    lan: &crate::core::go_lan::GoLanSettings,
) {
    let targets = go_lan_gateway_targets(lan);
    if targets.is_empty() || api_addr.is_empty() {
        return;
    }
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        let api = KernelApi::new(&api_addr, &api_secret);
        for gw in targets.clone() {
            // 探测结果不重要（家庭网关多半不开 HTTP），只要发包即可触发握手
            let _ = api
                .test_delay(
                    crate::core::go_lan::GO_LAN_TAG,
                    &format!("http://{gw}"),
                    1500,
                )
                .await;
        }
        crate::core::logger::info(
            crate::core::logger::MOD_GO_LAN,
            &format!("主动握手探测完成，已向家庭网关发包: {targets:?}"),
        );
        tracing::info!("[go-lan] 主动握手探测已完成");
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
    let lan: crate::core::go_lan::GoLanSettings =
        serde_json::from_value(settings).map_err(|e| format!("配置格式错误: {e}"))?;
    // APP 任务5 后端兜底：未配置完整参数时严禁启用
    if lan.enabled && !crate::core::go_lan::is_configured(&lan) {
        return Err("请先填写完整的回家节点参数与内网网段后再启用 Go Lan".into());
    }
    crate::core::go_lan::save(&state.data_dir, &lan)?;
    *state.go_lan.write() = lan.clone();

    let (_, warnings) = crate::core::go_lan::go_lan_route_rules(&lan);

    let _ = app.emit("go-lan://updated", serde_json::to_value(&lan).unwrap_or_default());
    let _ = app.emit(
        "settings://updated",
        serde_json::to_value(state.settings.read().clone()).unwrap_or_default(),
    );

    // 运行中 → 后台异步重建内核配置生效（iOS 会重启扩展加载 go-lan-home），
    // 不阻塞前端保存响应
    if *state.status.read() == CoreStatus::Running {
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
    let (go_lan_enabled, mixed_port, api_addr, api_secret, lan) = {
        let go_lan_cfg = state.go_lan.read();
        let settings = state.settings.read();
        (
            go_lan_cfg.enabled,
            settings.mixed_port,
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
        mixed_port,
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
