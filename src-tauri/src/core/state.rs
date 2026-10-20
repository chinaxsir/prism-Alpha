//! 应用核心状态机与用户设置
//!
//! 状态流转：
//!   Stopped ──start()──▶ Starting ──init ok──▶ Running
//!      ▲                    │                    │
//!      │                    └──fail──▶ Error ◀───┘
//!      └──────────stop()───────────────┘

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CoreStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RunMode {
    /// 仅系统代理（HTTP/SOCKS 入站）
    SystemProxy,
    /// TUN 全局接管
    Tun,
}

impl Default for RunMode {
    fn default() -> Self {
        Self::SystemProxy
    }
}

/// 兼容旧配置：历史版本存在 RuleOnly（仅规则）模式，读取时映射到 SystemProxy
impl RunMode {
    pub fn from_stored(s: &str) -> Self {
        match s {
            "ruleOnly" | "rule_only" | "RuleOnly" => Self::SystemProxy,
            "tun" | "Tun" => Self::Tun,
            _ => Self::SystemProxy,
        }
    }
}

/// 出站模式（流量最终走向；对应 Clash 的 rule/global/direct）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OutboundMode {
    /// 按规则分流（默认）
    Rule,
    /// 全部走 GLOBAL 选择组（用户手动选节点）
    Global,
    /// 全部直连
    Direct,
}

impl Default for OutboundMode {
    fn default() -> Self {
        Self::Rule
    }
}

/// 用户设置（可由设置页修改，持久化到 settings.json）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSettings {
    /// mixed 混合入站端口（HTTP + SOCKS）
    pub mixed_port: u16,
    /// 允许局域网连接
    pub allow_lan: bool,
    /// 启动时设置系统代理（SystemProxy 模式下生效）
    pub system_proxy: bool,
    /// 运行模式（由 set_mode 持久化，重启应用后恢复；save_settings 表单携带的旧值会被忽略）
    #[serde(default)]
    pub mode: RunMode,
    /// 开机自启动
    pub auto_start: bool,
    /// 出站模式（规则/全局/直连）
    #[serde(default)]
    pub outbound_mode: OutboundMode,
    /// 启用 IPv6（关闭时 DNS 仅解析 A 记录，避免 TUN 下 AAAA 泄漏）
    #[serde(default)]
    pub ipv6: bool,
    /// 阻止 QUIC（UDP/443），强制回退 TCP（避免 QUIC 绕过分流/审计）
    #[serde(default)]
    pub block_quic: bool,
    /// 手动切换策略后关闭现有连接（让新策略立即生效）
    #[serde(default)]
    pub close_connections_on_switch: bool,
    /// Go AIM（Pro）：AI/流媒体自动探测锁定开关
    #[serde(default)]
    pub go_aim_enabled: bool,
    /// 界面语言（system | zh | en；随设置表单一起落盘）
    #[serde(default = "default_system")]
    pub language: String,
    /// 界面主题（system | dark | light；随设置表单一起落盘）
    #[serde(default = "default_system")]
    pub theme: String,
}

/// language / theme 等枚举字符串字段缺失时的兜底默认值
fn default_system() -> String {
    "system".to_string()
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            mixed_port: 2080,
            allow_lan: false,
            system_proxy: true,
            // iOS 无桌面「系统代理」概念（build 149 方案第 2 步第 1 点）：
            // 所有流量必须经 TUN 虚拟网卡接管，默认与恢复时统一归一 Tun
            #[cfg(target_os = "ios")]
            mode: RunMode::Tun,
            #[cfg(not(target_os = "ios"))]
            mode: RunMode::SystemProxy,
            auto_start: false,
            outbound_mode: OutboundMode::Rule,
            ipv6: false,
            block_quic: false,
            close_connections_on_switch: false,
            go_aim_enabled: false,
            language: "system".to_string(),
            theme: "system".to_string(),
        }
    }
}

// ---------------------------------------------------------------- 运行时统计
// 内核 WebSocket 数据流（traffic / connections）在 events.rs 中被解析并写入
// 下列结构；get_runtime_snapshot IPC 读取它们给前端展示实时曲线与分析。

/// 单次实时流量采样（60 秒环形队列元素）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSample {
    /// 本地时间 HH:MM:SS
    pub time: String,
    /// 上行速率（字节/秒）
    pub up: u64,
    /// 下行速率（字节/秒）
    pub down: u64,
}

/// 单条连接快照（/connections 流每次覆盖写）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnSnapshot {
    pub id: String,
    pub host: String,
    pub destination_ip: String,
    pub source_ip: String,
    pub source_port: String,
    pub destination_port: String,
    pub network: String,
    pub upload: u64,
    pub download: u64,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    pub start: String,
    /// 是否活跃（本帧仍在内核连接表）；false 表示近期已关闭但仍保留展示
    pub active: bool,
    /// 保留序号（越大越新）：仅用于淘汰与排序，不下发前端
    #[serde(skip)]
    pub seq: u64,
}

/// 聚合统计（count / up / down）
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AggStat {
    pub count: u32,
    pub up: u64,
    pub down: u64,
}

/// 按 host / outbound / rule 三个维度的聚合容器
/// last_seen 保存每个连接 id 上次的 (up, down)，用于计算增量
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsAgg {
    pub hosts: HashMap<String, AggStat>,
    pub outbounds: HashMap<String, AggStat>,
    pub rules: HashMap<String, AggStat>,
    pub last_seen: HashMap<String, (u64, u64)>,
}

/// 跨 IPC 共享的全局状态
pub struct AppState {
    /// 应用句柄：状态流转后广播 core://status，前端无需轮询即可对齐
    pub app_handle: AppHandle,
    /// 应用数据目录（config.json / profile / 内核 / 持久化配置）
    pub data_dir: PathBuf,
    pub status: RwLock<CoreStatus>,
    pub mode: RwLock<RunMode>,
    pub settings: RwLock<UserSettings>,
    /// 本次启动时间（用于计算 uptime）
    pub started_at: RwLock<Option<Instant>>,
    pub kernel_handle: RwLock<Option<Arc<super::kernel::KernelHandle>>>,
    /// TUN 生命周期守卫（仅 TUN 模式下存在）
    pub tun_guard: RwLock<Option<super::tun::TunGuard>>,
    /// 当前内核 clash_api 实际地址（启动前为首选值）
    pub api_addr: RwLock<String>,
    /// 当前内核 clash_api 鉴权密钥
    pub api_secret: RwLock<String>,
    /// 已探测到的内核版本（用于设置页展示）
    pub kernel_version: RwLock<Option<String>>,
    /// 主选择组：route.final 链上最深的 selector。
    /// 节点页默认落在该组（GLOBAL 等虚拟组不在路由链路中，选择无效），
    /// 内核启动后自动对该组测速并切换至延迟最低的可用节点。
    pub main_selector: RwLock<Option<String>>,
    /// 当前 Pro 授权状态（启动时由 license 缓存恢复；后台校验后刷新）
    pub entitlement: RwLock<super::license::EntitlementStatus>,
    /// 系统代理备份：启动时备份原设置，停止/切换时恢复，确保代理独占
    pub proxy_backup: RwLock<Option<crate::platform::ProxyBackup>>,

    // ---- Go 三引擎（Pro）运行时状态 ----
    /// Go AIM：各节点解锁评级缓存（node → result）
    pub aim_results: RwLock<std::collections::HashMap<String, super::go_aim::AimNodeResult>>,
    /// Go AIM：探测进行中标志
    pub aim_probing: std::sync::atomic::AtomicBool,
    /// Go AIM：当前锁定的解锁节点
    pub aim_locked_node: RwLock<Option<String>>,
    /// Go AIM：监控任务已启动标志（进程内单例）
    pub aim_monitor_started: std::sync::atomic::AtomicBool,
    /// Go Lan：回家网络配置（go_lan.json）
    pub go_lan: RwLock<super::go_lan::GoLanSettings>,
    /// Go Cus：覆写引擎配置（go_cus.json）
    pub go_cus: RwLock<super::go_cus::GoCusSettings>,

    // ---- 运行时统计（前后台不间断；内核停止/启动时经 reset_runtime_stats 清空）----
    /// 60 秒实时流量环形队列（最新在尾部）
    pub traffic_history: RwLock<VecDeque<TrafficSample>>,
    /// 当前活跃连接快照（id → snapshot）
    pub connections_live: RwLock<HashMap<String, ConnSnapshot>>,
    /// 按 host / outbound / rule 聚合的分析数据
    pub analytics: RwLock<AnalyticsAgg>,
    /// 今日流量缓存（store::today_total_bytes 的最新值）
    pub today_bytes_cache: RwLock<u64>,
    /// 连接保留序号发生器（单调递增，用于活跃/近期连接池的排序与淘汰）
    pub conn_seq: std::sync::atomic::AtomicU64,
}

impl AppState {
    /// 创建状态并从 data_dir/settings.json 恢复用户设置（含运行模式）
    pub fn new(data_dir: PathBuf, app_handle: AppHandle) -> Self {
        let settings = super::store::load_settings(&data_dir);
        // iOS 强制归一 TUN 模式：settings.json 里可能存有历史 systemProxy
        //（build 149 方案第 2 步第 1 点）
        #[cfg(target_os = "ios")]
        let mode = RunMode::Tun;
        #[cfg(not(target_os = "ios"))]
        let mode = settings.mode;
        Self {
            app_handle,
            data_dir: data_dir.clone(),
            status: RwLock::new(CoreStatus::Stopped),
            mode: RwLock::new(mode),
            settings: RwLock::new(settings),
            started_at: RwLock::new(None),
            kernel_handle: RwLock::new(None),
            tun_guard: RwLock::new(None),
            api_addr: RwLock::new(super::kernel::PREFERRED_API_ADDR.to_string()),
            api_secret: RwLock::new(String::new()),
            kernel_version: RwLock::new(None),
            main_selector: RwLock::new(None),
            entitlement: RwLock::new(super::license::cached_entitlement(&data_dir)),
            proxy_backup: RwLock::new(None),
            aim_results: RwLock::new(std::collections::HashMap::new()),
            aim_probing: std::sync::atomic::AtomicBool::new(false),
            aim_locked_node: RwLock::new(None),
            aim_monitor_started: std::sync::atomic::AtomicBool::new(false),
            go_lan: RwLock::new(super::go_lan::load(&data_dir)),
            go_cus: RwLock::new(super::go_cus::load(&data_dir)),
            traffic_history: RwLock::new(VecDeque::new()),
            connections_live: RwLock::new(HashMap::new()),
            analytics: RwLock::new(AnalyticsAgg::default()),
            today_bytes_cache: RwLock::new(0),
            conn_seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// 分配下一个连接保留序号（单调递增）
    pub fn next_conn_seq(&self) -> u64 {
        self.conn_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1
    }

    /// 构造与当前内核对话的 API 客户端
    pub fn kernel_api(&self) -> super::kernel::KernelApi {
        super::kernel::KernelApi::new(&self.api_addr.read(), &self.api_secret.read())
    }

    /// 更新内存授权状态并广播 pro://status 事件。
    /// IPC 命令与后台周期校验任务共用，保证前端 gating 实时一致。
    pub fn apply_entitlement(&self, next: super::license::EntitlementStatus) {
        *self.entitlement.write() = next.clone();
        let _ = self.app_handle.emit("pro://status", &next);
    }

    /// 保存设置到内存 + settings.json
    pub fn save_settings(&self, next: UserSettings) -> anyhow::Result<()> {
        super::store::save_settings(&self.data_dir, &next)?;
        *self.settings.write() = next;
        Ok(())
    }

    /// 清空运行时统计（内核停止/启动时调用）：60s 队列 / 活跃连接 / 分析聚合。
    /// 今日流量基数不动（由 store::archive_session 负责归档）
    pub fn reset_runtime_stats(&self) {
        self.traffic_history.write().clear();
        self.connections_live.write().clear();
        let mut agg = self.analytics.write();
        agg.hosts.clear();
        agg.outbounds.clear();
        agg.rules.clear();
        agg.last_seen.clear();
    }

    /// 构造运行时统计快照（供 get_runtime_snapshot IPC 返回）。
    /// todayBytes 取「落盘值」与「内存缓存」的较大者，避免落盘滞后导致回退。
    pub fn runtime_snapshot(&self) -> serde_json::Value {
        let disk_today = super::store::today_total_bytes(&self.data_dir);
        let today_bytes = disk_today.max(*self.today_bytes_cache.read());

        // 60s 流量队列（按时间先后；最新一次同时作为当前速率）
        let history = self.traffic_history.read();
        let (up_speed, down_speed) = history
            .back()
            .map(|s| (s.up, s.down))
            .unwrap_or((0, 0));
        let traffic_history: Vec<serde_json::Value> = history
            .iter()
            .map(|s| serde_json::json!({ "time": s.time, "up": s.up, "down": s.down }))
            .collect();
        drop(history);

        // 活跃/近期连接快照：按保留序号降序（新连接在前），含已关闭项
        let conns = self.connections_live.read();
        let mut conn_list: Vec<&ConnSnapshot> = conns.values().collect();
        conn_list.sort_by(|a, b| b.seq.cmp(&a.seq));
        let connections: Vec<serde_json::Value> = conn_list
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "host": c.host,
                    "destinationIP": c.destination_ip,
                    "sourceIP": c.source_ip,
                    "sourcePort": c.source_port,
                    "destinationPort": c.destination_port,
                    "network": c.network,
                    "upload": c.upload,
                    "download": c.download,
                    "chains": c.chains,
                    "rule": c.rule,
                    "rulePayload": c.rule_payload,
                    "start": c.start,
                    "active": c.active,
                })
            })
            .collect();
        drop(conns);

        // 分析聚合：每个维度按 up+down 降序取前 8
        let agg = self.analytics.read();
        fn top8(map: &HashMap<String, AggStat>) -> Vec<serde_json::Value> {
            let mut items: Vec<(&String, &AggStat)> = map.iter().collect();
            items.sort_by(|a, b| (b.1.up + b.1.down).cmp(&(a.1.up + a.1.down)));
            items
                .into_iter()
                .take(8)
                .map(|(k, s)| {
                    serde_json::json!([k, { "count": s.count, "up": s.up, "down": s.down }])
                })
                .collect()
        }
        let analytics = serde_json::json!({
            "hosts": top8(&agg.hosts),
            "outbounds": top8(&agg.outbounds),
            "rules": top8(&agg.rules),
        });
        drop(agg);

        serde_json::json!({
            "todayBytes": today_bytes,
            "upSpeed": up_speed,
            "downSpeed": down_speed,
            "trafficHistory60s": traffic_history,
            "connections": connections,
            "analyticsSummary": analytics,
        })
    }

    /// 内核工作目录（config.json / profile.yaml / kernel.log 所在）
    pub fn work_dir(&self) -> PathBuf {
        self.data_dir.join("kernel")
    }

    /// 带合法性校验的状态流转；成功后广播 core://status 供前端对齐
    pub fn transition(&self, next: CoreStatus) -> anyhow::Result<()> {
        let current = *self.status.read();
        let valid = matches!(
            (current, next),
            (CoreStatus::Stopped, CoreStatus::Starting)
                | (CoreStatus::Error, CoreStatus::Starting)
                | (CoreStatus::Starting, CoreStatus::Running)
                | (CoreStatus::Starting, CoreStatus::Error)
                | (CoreStatus::Running, CoreStatus::Stopping)
                | (CoreStatus::Running, CoreStatus::Error)
                | (CoreStatus::Stopping, CoreStatus::Stopped)
                | (CoreStatus::Stopping, CoreStatus::Error)
                | (CoreStatus::Error, CoreStatus::Stopped)
        );
        if !valid {
            anyhow::bail!("invalid state transition: {:?} -> {:?}", current, next);
        }
        *self.status.write() = next;
        tracing::info!("core state: {:?} -> {:?}", current, next);

        // 广播在锁外执行；失败（无监听者）忽略
        let _ = self.app_handle.emit("core://status", self.status_payload());
        Ok(())
    }

    /// 构造状态广播载荷（字段与 get_core_status 一致）
    fn status_payload(&self) -> serde_json::Value {
        let status = *self.status.read();
        let mode = *self.mode.read();
        let main_selector = self.main_selector.read().clone();
        let uptime_secs = self
            .started_at
            .read()
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);
        serde_json::json!({
            "status": status,
            "mode": mode,
            "uptimeSecs": uptime_secs,
            "mainSelector": main_selector,
        })
    }
}

/// 供 IPC 层使用：判断端口是否可绑定
pub fn is_port_free(host: &str, port: u16) -> bool {
    std::net::TcpListener::bind((host, port)).is_ok()
}

/// 选择 clash_api 监听地址：优先 9090，被占用则让系统分配随机端口
pub fn pick_api_addr() -> String {
    if is_port_free("127.0.0.1", 9090) {
        return super::kernel::PREFERRED_API_ADDR.to_string();
    }
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener
            .local_addr()
            .map(|a| format!("127.0.0.1:{}", a.port()))
            .unwrap_or_else(|_| "127.0.0.1:0".into()),
        Err(e) => {
            tracing::error!("failed to allocate api port: {e}");
            super::kernel::PREFERRED_API_ADDR.to_string()
        }
    }
}
