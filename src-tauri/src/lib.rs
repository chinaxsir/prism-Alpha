pub mod core;
pub mod ipc;
pub mod platform;
pub mod plugins;

#[cfg(desktop)]
use tauri::menu::{Menu, MenuItem};
#[cfg(desktop)]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent};
#[cfg(desktop)]
use tauri::WindowEvent;
use tracing_subscriber::EnvFilter;

/// 显示并聚焦主窗口（托盘左键 / 菜单“显示主窗口”）
#[cfg(desktop)]
fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// 真正退出：先回收内核/TUN/系统代理，再退出进程
fn quit_app(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(state) = app.try_state::<core::state::AppState>() {
            if let Err(e) = ipc::commands::do_stop(&state).await {
                tracing::error!("exit cleanup failed: {e}");
            }
        }
        app.exit(0);
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // RUST_LOG 未设置时默认 info（静音高频网络库日志）
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,want=off,mio=off,polling=off"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // 运行时安全自检（仅 Release 生效）：iOS 反调试附加、Android TracerPid 检测
    core::security::init_runtime_guard();

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init());
    // 移动端 IAP（StoreKit2 / Google Play Billing），桌面不编译
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder.plugin(tauri_plugin_iap::init());

    let app = builder
        // 注意：日志统一走 tracing-subscriber（见 run() 开头），
        // 它已注册全局 log facade，再注册 tauri-plugin-log 会导致
        // “attempted to set a logger after the logging system was already initialized” panic
        .setup(|app| {
            // 数据目录：settings.json / subscriptions.json / kernel/（config.json 等）
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir).ok();
            app.manage(core::state::AppState::new(data_dir.clone(), app.handle().clone()));
            // APP6 任务1：全模块环形日志系统（内存 800 条 + 512KB 磁盘轮转）
            core::logger::init(&data_dir);
            core::logger::info(
                core::logger::MOD_KERNEL,
                &format!("Prism 启动，版本 {}（{}）", env!("CARGO_PKG_VERSION"), std::env::consts::OS),
            );

            // 【APP52 任务2】常驻后台遥测：600ms 采样 + telemetry://tick，
            // 切换页面/系统后台/停启 VPN 都不中断（仅运行中真实探测）。
            ipc::commands::spawn_background_telemetry_worker(app.handle().clone());

            // 移动端平台初始化：Android 注册 libbox/JNI VPN 回调
            #[cfg(any(target_os = "android", target_os = "ios"))]
            if let Err(e) = platform::mobile_init(app.handle()) {
                tracing::error!("mobile platform init failed: {e:#}");
            }

            // 每日授权同步：每天首次启动 APP 时与服务器同步一次授权信息并
            // 更新本地加密缓存；当天内授权只从缓存文件读取，不再联网。
            // 断网/服务不可达时授权从本地加密文件读取（未过期继续可用），
            // 每小时重试一次，恢复联网即以服务端结果修正。
            // Pro/买断（sync_available）：每轮循环顺带做一次订阅云端对账，
            // 换设备登录后自动双向合并（静默）。
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let state = handle.state::<core::state::AppState>();
                loop {
                    let settings = state.settings.read().clone();
                    if let Some(next) =
                        core::license::daily_sync(&data_dir, &settings).await
                    {
                        tracing::info!("license synced: {}", next.status);
                        state.apply_entitlement(next);
                    } else if let Some(cache) = core::license::cached_entitlement_opt(&data_dir) {
                        // 同步未产生变更（当天已同步或失败）：失败场景下缓存
                        // 状态可能随时间跨过有效期，按文件内容刷新内存态
                        state.apply_entitlement(cache);
                    }
                    core::sync_links::reconcile(&handle).await;
                    // 【APP6 任务3】启动校验 Pro 有效后：本地订阅为空或距上次
                    // 全量同步超过 24h 时，自动拉取云端订阅并刷新全部节点
                    //（auto_sync 内部自校验资格并 24h 节流，此处每轮触发即可）
                    ipc::commands::auto_sync_and_refresh_subscriptions(handle.clone()).await;
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                }
            });

            // 【APP49 任务2.2】启动时自动更新全部订阅（默认开启，每天仅一次）。
            // 启动后延迟 5s 等网络就绪；当天已更新则直接跳过。
            let auto_update_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                ipc::commands::auto_update_subscriptions_daily(auto_update_handle).await;
            });

            // 授权到期实时巡检（每 10 秒一次纯内存整数比较）：
            // 无论是否联网，跨过 expires_at 立即终止全部 Pro 功能并通知前端；
            // 同时维护进程内时钟高水位线，运行中被调回系统时间也立即熔断。
            let expiry_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut high_water = core::license::now_unix();
                loop {
                    let now = core::license::now_unix();
                    let state = expiry_handle.state::<core::state::AppState>();
                    let expired = {
                        let ent = state.entitlement.read();
                        // 仅 active 态触发一次收口，避免已锁定后每轮重复重启内核
                        ent.status == "active"
                            && (core::license::is_expired(&ent, now)
                                || now + core::license::CLOCK_ROLLBACK_TOLERANCE < high_water)
                    };
                    if expired {
                        ipc::commands::terminate_pro_features_on_expiry(&expiry_handle, &state)
                            .await;
                    }
                    high_water = high_water.max(now);
                    drop(state);
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            });

            // APP 远程管控（APP-4 任务2）：启动单次上报 + 每 5 分钟心跳。
            // fail-open——服务不可达/断网完全不影响使用；仅服务端明确
            // allowed=false 时停止内核并阻止启动（管控优先级最高）。
            let control_handle = app.handle().clone();
            core::app_control::spawn_startup_check(control_handle.clone());
            core::app_control::spawn_heartbeat(control_handle);

            // APP-5 任务2：iOS 覆盖升级启动自愈。指纹（版本号|build|二进制
            // mtime）变化即清理驻留的旧版扩展进程——不清理则系统里运行的是
            // 旧 appex，UI 显示未连接而实际仍在代理。
            #[cfg(target_os = "ios")]
            {
                if platform::ios::upgrade_selfheal() {
                    tracing::info!("[upgrade] 检测到覆盖升级，已清理驻留的旧版扩展进程");
                }
            }

            // APP-5 任务3：强退重开自动认领后台仍在运行的隧道。
            // 延迟 1s 启动，给 iOS 侧的覆盖升级自愈（杀旧扩展 + 删旧配置）
            // 留出清理窗口，避免刚认领就被清理流程打断。
            let reattach_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let state = reattach_handle.state::<core::state::AppState>();
                if state
                    .reattach_attempted
                    .swap(true, std::sync::atomic::Ordering::AcqRel)
                {
                    return;
                }
                if core::kernel::try_reattach_running_kernel(&reattach_handle, state.inner()).await
                {
                    tracing::info!("[reattach] 后台隧道已认领，状态恢复为运行中");
                }
            });

            // APP-5 任务2：升级前隧道在使用中 → 清理完成后自动重建隧道，
            // 避免用户升级后看到「未连接」而误以为配置/订阅丢失
            #[cfg(target_os = "ios")]
            {
                let upgrade_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if !platform::ios::take_pending_restart() {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    let state = upgrade_handle.state::<core::state::AppState>();
                    // 已被「强退重开认领」接管则不再重建（避免双启动）
                    if *state.status.read() != core::state::CoreStatus::Stopped {
                        return;
                    }
                    // 旧扩展可能仍处于 connecting/connected：先同步停掉，
                    // 否则 startVPNTunnel 会因会话被占用而失败
                    if platform::ios::vpn_is_connected() {
                        platform::ios::stop_tunnel();
                        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                    }
                    tracing::info!("[upgrade] 升级前隧道在使用中，自动重建隧道");
                    if let Err(e) = ipc::commands::auto_start_after_upgrade(
                        upgrade_handle.clone(),
                        state.inner(),
                    )
                    .await
                    {
                        tracing::warn!("[upgrade] 自动重建隧道失败: {e}");
                    }
                });
            }

            // 系统托盘（仅桌面端；menu/tray API 在移动端被 cfg 移除）：
            // 左键单击显示主窗口；菜单提供 显示/退出
            #[cfg(desktop)]
            {
                let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
                let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&show, &quit])?;
                let mut tray = TrayIconBuilder::with_id("main-tray")
                    .menu(&menu)
                    .tooltip("Prism Proxy")
                    .show_menu_on_left_click(false)
                    .on_menu_event(|app, event| match event.id().as_ref() {
                        "show" => show_main_window(app),
                        "quit" => quit_app(app),
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            show_main_window(tray.app_handle());
                        }
                    });
                if let Some(icon) = app.default_window_icon() {
                    tray = tray.icon(icon.clone());
                }
                tray.build(app)?;
            }
            Ok(())
        })
        .on_window_event(|_window, event| {
            // 点关闭按钮 → 隐藏到托盘常驻；真正退出走托盘菜单“退出”。
            // hide() 仅桌面端可用；移动端无关闭窗口语义
            #[cfg(desktop)]
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = _window.hide();
            }
            let _ = event;
        })
        .invoke_handler(tauri::generate_handler![
            ipc::commands::start_core,
            ipc::commands::stop_core,
            ipc::commands::get_core_status,
            ipc::commands::set_app_foreground,
            ipc::commands::set_mode,
            ipc::commands::url_test,
            ipc::commands::set_outbound_mode,
            ipc::commands::select_proxy,
            ipc::commands::update_subscription,
            ipc::commands::update_all_subscriptions,
            ipc::commands::rename_subscription,
            ipc::commands::list_subscriptions,
            ipc::commands::get_cached_proxies,
            ipc::commands::test_cached_proxies,
            ipc::commands::toggle_subscription,
            ipc::commands::delete_subscription,
            ipc::commands::get_custom_rules,
            ipc::commands::save_custom_rules,
            ipc::commands::activate_pro,
            ipc::commands::get_entitlement,
            ipc::commands::get_revoke_reason,
            ipc::commands::get_device_id,
            ipc::commands::refresh_entitlement,
            ipc::commands::deactivate_pro,
            ipc::commands::submit_receipt,
            ipc::commands::get_connections,
            ipc::commands::close_connection,
            ipc::commands::close_all_connections,
            ipc::commands::reset_analytics_stats,
            ipc::commands::get_traffic_stats,
            ipc::commands::get_runtime_snapshot,
            ipc::commands::add_traffic_tick,
            ipc::commands::get_rules,
            ipc::commands::get_proxy_groups,
            ipc::commands::get_settings,
            ipc::commands::get_lan_ip,
            ipc::commands::save_settings,
            ipc::commands::get_go_aim_status,
            ipc::commands::set_go_aim_enabled,
            ipc::commands::run_go_aim_probe,
            ipc::commands::clear_go_aim_pinned_node,
            ipc::commands::get_go_lan_settings,
            ipc::commands::get_go_lan_status,
            ipc::commands::save_go_lan_settings,
            ipc::commands::sync_go_lan_managed,
            ipc::commands::test_go_lan_ip,
            ipc::commands::get_go_cus_settings,
            ipc::commands::save_go_cus_settings,
            ipc::commands::import_go_cus_module,
            ipc::commands::toggle_go_cus_module,
            ipc::commands::delete_go_cus_module,
            ipc::commands::generate_or_get_ca_url,
            ipc::commands::get_kernel_info,
            ipc::commands::ensure_kernel,
            ipc::commands::get_app_logs,
            ipc::commands::clear_app_logs,
            ipc::commands::export_app_logs,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| {
        // 退出兜底：防止系统代理残留 / sing-box 孤儿进程
        if let RunEvent::ExitRequested { api, .. } = event {
            api.prevent_exit();
            quit_app(app_handle);
        }
    });
}
