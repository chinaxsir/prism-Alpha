//! 【mac 任务3】Mac 版顶部系统状态栏（MenuBar Tray）：
//! 高清模板图标 + 实时上下行网速显示 + 快捷切换节点 / 出站模式 / Pro 引擎菜单。
//! 仅桌面端编译生效（移动端无 tray API）。

use std::sync::Arc;
use std::time::Duration;

use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::core::state::{AppState, CoreStatus, OutboundMode};
use crate::ipc::commands;

/// 托盘唯一 ID
const TRAY_ID: &str = "prism-mac-tray";

/// 初始化 macOS 状态栏托盘：构建图标 + 菜单 + 网速刷新协程。
pub fn init_tray(app: &AppHandle) -> tauri::Result<()> {
    let menu = build_tray_menu(app)?;
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip("Prism")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            handle_menu_event(&app, event.id().as_ref());
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
        builder = builder.icon(icon.clone());
    }
    let _tray = builder.build(app)?;

    // 后台刷新协程：每 1500ms 读取实时速率并刷新托盘标题；状态变化时重建菜单
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut last_running = false;
        let mut last_mode: Option<OutboundMode> = None;
        let mut last_node: Option<String> = None;
        loop {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let Some(state) = app.try_state::<AppState>() else {
                continue;
            };
            let running = *state.status.read() == CoreStatus::Running;
            let mode = state.settings.read().outbound_mode;
            let node = state.settings.read().selected_node.clone();

            // 更新网速标题
            let title = if running {
                let (down, up) = state
                    .last_traffic_sample
                    .lock()
                    .map(|s| (s.3, s.4))
                    .unwrap_or((0, 0));
                format_speed_title(down, up)
            } else {
                String::new()
            };
            if let Some(t) = app.tray_by_id(TRAY_ID) {
                let _ = t.set_title(if title.is_empty() { None } else { Some(title) });
            }

            // 状态 / 模式 / 节点变化时重建菜单（勾选态、启停文案、节点列表）
            let state_changed = running != last_running
                || Some(mode) != last_mode
                || node.as_deref() != last_node.as_deref();
            if state_changed {
                last_running = running;
                last_mode = Some(mode);
                last_node = node;
                if let Ok(menu) = build_tray_menu(&app) {
                    if let Some(t) = app.tray_by_id(TRAY_ID) {
                        let _ = t.set_menu(Some(menu));
                    }
                }
            }
        }
    });

    Ok(())
}

/// 构建托盘菜单（状态概览 / 启停 / 出站模式 / 节点切换 / 测速 / Pro 引擎 / 窗口）
fn build_tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let state = app.state::<AppState>();
    let running = *state.status.read() == CoreStatus::Running;
    let mode = state.settings.read().outbound_mode;
    let selected_node = state
        .settings
        .read()
        .selected_node
        .clone()
        .unwrap_or_default();
    let delay = state
        .node_metrics
        .read()
        .delays
        .get(&selected_node)
        .copied()
        .unwrap_or(0);

    // 顶部状态概览
    let status_text = if running {
        let mode_label = match mode {
            OutboundMode::Rule => "规则模式",
            OutboundMode::Global => "全局模式",
            OutboundMode::Direct => "直连模式",
        };
        format!("● 已连接 · {mode_label}")
    } else {
        "○ 未启动".to_string()
    };
    let status_header = MenuItem::with_id(app, "status_header", status_text, false, None::<&str>)?;
    let node_text = if running && !selected_node.is_empty() {
        if delay > 0 {
            format!("当前节点: {selected_node} ({delay}ms)")
        } else {
            format!("当前节点: {selected_node}")
        }
    } else {
        "当前节点: —".to_string()
    };
    let node_info = MenuItem::with_id(app, "current_node_info", node_text, false, None::<&str>)?;

    // 一键启停
    let toggle_text = if running {
        "🛑 停止代理内核"
    } else {
        "🚀 启动代理内核"
    };
    let toggle_vpn = MenuItem::with_id(app, "toggle_vpn", toggle_text, true, None::<&str>)?;

    // 出站模式（3 个 CheckMenuItem）
    let mode_rule = CheckMenuItem::with_id(
        app,
        "mode_rule",
        "规则模式 (Rule)",
        true,
        mode == OutboundMode::Rule,
        None::<&str>,
    )?;
    let mode_global = CheckMenuItem::with_id(
        app,
        "mode_global",
        "全局模式 (Global)",
        true,
        mode == OutboundMode::Global,
        None::<&str>,
    )?;
    let mode_direct = CheckMenuItem::with_id(
        app,
        "mode_direct",
        "直连模式 (Direct)",
        true,
        mode == OutboundMode::Direct,
        None::<&str>,
    )?;

    // 「快捷切换节点」子菜单
    let node_submenu = build_node_submenu(app, &state, &selected_node)?;

    // 全量测速
    let test_all = MenuItem::with_id(app, "test_all_nodes", "⚡ 立即全量测速", true, None::<&str>)?;

    // Pro 引擎快捷开关
    let go_aim_enabled = state.settings.read().go_aim_enabled;
    let go_lan_enabled = state.go_lan.read().enabled;
    let go_cus_enabled = state.go_cus.read().enabled;
    let toggle_go_aim = CheckMenuItem::with_id(
        app,
        "toggle_go_aim",
        "🎯 Go AIM 智能解锁优选",
        true,
        go_aim_enabled,
        None::<&str>,
    )?;
    let toggle_go_lan = CheckMenuItem::with_id(
        app,
        "toggle_go_lan",
        "🏠 Go Lan 异地组网直连",
        true,
        go_lan_enabled,
        None::<&str>,
    )?;
    let toggle_go_cus = CheckMenuItem::with_id(
        app,
        "toggle_go_cus",
        "🧩 Go Cus 分流覆写引擎",
        true,
        go_cus_enabled,
        None::<&str>,
    )?;

    // 窗口与应用操作
    let show_window = MenuItem::with_id(
        app,
        "show_window",
        "📊 显示 Prism 主窗口",
        true,
        None::<&str>,
    )?;
    let quit_app = MenuItem::with_id(app, "quit_app", "🚪 彻底退出 Prism", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let sep3 = PredefinedMenuItem::separator(app)?;
    let sep4 = PredefinedMenuItem::separator(app)?;

    let menu = Menu::with_items(
        app,
        &[
            &status_header,
            &node_info,
            &sep1,
            &toggle_vpn,
            &sep2,
            &mode_rule,
            &mode_global,
            &mode_direct,
            &sep3,
            &node_submenu,
            &test_all,
            &toggle_go_aim,
            &toggle_go_lan,
            &toggle_go_cus,
            &sep4,
            &show_window,
            &quit_app,
        ],
    )?;
    Ok(menu)
}

/// 构建「快捷切换节点」子菜单：AIM 自动优选 + 节点列表（最多 35 个）
fn build_node_submenu(
    app: &AppHandle,
    state: &State<'_, AppState>,
    selected_node: &str,
) -> tauri::Result<Submenu<tauri::Wry>> {
    let aim_item = MenuItem::with_id(
        app,
        "aim_auto_select",
        "🎯 Go AIM 自动优选最佳节点",
        true,
        None::<&str>,
    )?;
    let sep = PredefinedMenuItem::separator(app)?;
    let mut items: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = vec![&aim_item, &sep];

    // 收集节点（从订阅缓存 + 实时延迟）
    let cached = commands::collect_cached_proxies(state.inner());
    let metrics = state.node_metrics.read();
    let mut nodes: Vec<(String, u32)> = cached
        .into_iter()
        .map(|c| {
            let d = metrics
                .delays
                .get(&c.name)
                .copied()
                .or(c.delay)
                .unwrap_or(0);
            (c.name, d)
        })
        .collect();
    drop(metrics);
    // 按延迟升序（0/超时排后）
    nodes.sort_by(|a, b| {
        let av = if a.1 > 0 { a.1 } else { u32::MAX };
        let bv = if b.1 > 0 { b.1 } else { u32::MAX };
        av.cmp(&bv)
    });
    nodes.truncate(35);

    let mut owned: Vec<CheckMenuItem<tauri::Wry>> = Vec::with_capacity(nodes.len());
    for (name, delay) in &nodes {
        let title = if *delay > 0 {
            format!("{name}  ·  {delay}ms")
        } else {
            name.clone()
        };
        let checked = name == selected_node;
        let id = format!("select_node::{name}");
        if let Ok(item) = CheckMenuItem::with_id(app, id, title, true, checked, None::<&str>) {
            owned.push(item);
        }
    }
    for item in &owned {
        items.push(item);
    }
    let submenu = Submenu::with_items(app, "🌐 快捷切换节点", true, &items)?;
    Ok(submenu)
}

/// 处理托盘菜单点击事件
fn handle_menu_event(app: &AppHandle, id: &str) {
    match id {
        "show_window" => show_main_window(app),
        "quit_app" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(state) = app.try_state::<AppState>() {
                    let _ = commands::do_stop(&state).await;
                }
                app.exit(0);
            });
        }
        "toggle_vpn" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(state) = app.try_state::<AppState>() {
                    let running = *state.status.read() == CoreStatus::Running;
                    if running {
                        let _ = commands::do_stop(&state).await;
                    } else {
                        let _ = commands::do_start(&app, &state).await;
                    }
                    let _ = app.emit("status://updated", ());
                }
            });
        }
        "mode_rule" => set_mode(app, OutboundMode::Rule),
        "mode_global" => set_mode(app, OutboundMode::Global),
        "mode_direct" => set_mode(app, OutboundMode::Direct),
        "aim_auto_select" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(state) = app.try_state::<AppState>() {
                    let _ = commands::run_go_aim_probe(app.clone(), state, None).await;
                }
            });
        }
        "test_all_nodes" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(state) = app.try_state::<AppState>() {
                    let _ = commands::test_all_delays(app.clone(), state).await;
                }
            });
        }
        "toggle_go_aim" => toggle_go_aim(app),
        "toggle_go_lan" => toggle_go_lan(app),
        "toggle_go_cus" => toggle_go_cus(app),
        other if other.starts_with("select_node::") => {
            let name = other.trim_start_matches("select_node::").to_string();
            select_node(app, name);
        }
        _ => {}
    }
}

fn set_mode(app: &AppHandle, mode: OutboundMode) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(state) = app.try_state::<AppState>() {
            let _ = commands::set_outbound_mode(mode, app.clone(), state).await;
        }
    });
}

fn select_node(app: &AppHandle, name: String) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(state) = app.try_state::<AppState>() {
            let group = state.main_selector.read().clone().unwrap_or_default();
            if group.is_empty() {
                return;
            }
            let _ = commands::select_proxy(app.clone(), group, name, state).await;
            let _ = app.emit("status://updated", ());
        }
    });
}

fn toggle_go_aim(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(state) = app.try_state::<AppState>() {
            let enabled = state.settings.read().go_aim_enabled;
            let _ = commands::set_go_aim_enabled(!enabled, app.clone(), state).await;
        }
    });
}

fn toggle_go_lan(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(state) = app.try_state::<AppState>() {
            let mut s = state.go_lan.read().clone();
            s.enabled = !s.enabled;
            if let Ok(v) = serde_json::to_value(&s) {
                let _ = commands::save_go_lan_settings(v, app.clone(), state).await;
            }
        }
    });
}

fn toggle_go_cus(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(state) = app.try_state::<AppState>() {
            let mut s = state.go_cus.read().clone();
            s.enabled = !s.enabled;
            if let Ok(v) = serde_json::to_value(&s) {
                let _ = commands::save_go_cus_settings(v, app.clone(), state).await;
            }
        }
    });
}

/// 显示并聚焦主窗口
fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// 格式化 macOS 状态栏网速标题（紧凑等宽，例如 ↓1.2M ↑48K）
fn format_speed_title(down: u64, up: u64) -> String {
    fn compact(bytes: u64) -> String {
        if bytes >= 1024 * 1024 {
            format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{:.0}K", bytes as f64 / 1024.0)
        } else {
            format!("{bytes}B")
        }
    }
    format!("↓{} ↑{}", compact(down), compact(up))
}

// 显式持有 Arc 以避免未使用警告（API 一致性预留）
#[allow(dead_code)]
fn _hold_arc(_a: Arc<()>) {}
