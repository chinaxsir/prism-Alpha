//! 核心代理模块
//!
//! 架构说明：
//! - `state`: 全局应用状态机（AppState），管理内核生命周期与用户设置
//! - `kernel`: Go 代理内核（sing-box）sidecar 封装，通过本地 HTTP API 通信
//! - `events`: 订阅内核 WebSocket 数据流，转为 Tauri 事件
//! - `config_builder`: Clash YAML 订阅 → sing-box runtime JSON
//! - `tun`: TUN 虚拟网卡挂载（跨平台抽象）

pub mod config_builder;
pub mod events;
pub mod go_aim;
pub mod go_cus;
pub mod go_lan;
pub mod kernel;
pub mod license;
pub mod state;
pub mod store;
pub mod sync_links;
pub mod tun;
pub mod uri_parser;
