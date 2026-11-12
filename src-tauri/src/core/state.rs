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

use parking_lot::{Mutex, RwLock};
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
    /// 【APP47 任务3.3】默认 true：切换节点后立即断开旧连接，
    /// 新选中节点 0 延迟接管全部网页与 App 流量（用户仍可在设置中关闭）。
    #[serde(default = "default_true")]
    pub close_connections_on_switch: bool,
    /// Go AIM（Pro）：AI/流媒体自动探测锁定开关
    #[serde(default)]
    pub go_aim_enabled: bool,
    /// Go AIM（Pro）：用户手动指定的锁定节点（APP-4 任务3.3）。
    /// Some(node) = 手动指定模式（探测评级照跑，选点始终尊重该节点，绝不覆盖）；
    /// None = 自动模式。节点页手动选中节点时自动写入。
    #[serde(default)]
    pub go_aim_pinned_node: Option<String>,
    /// 【APP33 任务3.1】用户最近选中的代理节点名（持久化到 settings.json）。
    /// 启动/刷新状态时由 ensure_valid_selected_node 纠偏：若为「剩余流量」
    /// 等假节点或已不存在，自动替换为首个真实节点并写回磁盘，杜绝仪表盘
    /// 「当前节点」长期残留假节点名。
    #[serde(default)]
    pub selected_node: Option<String>,
    /// 【APP52 任务1】用户是否手动点选过节点（默认 false）。
    /// false = 自动模式：重启 Go AIM / 重新测速后自动把最低延迟节点设为
    /// selected_node；true = 手动模式：自动选点绝不覆盖用户选择。
    /// 仅 select_proxy 命令置 true；重开 Go AIM / 重测速时复位 false。
    #[serde(default)]
    pub user_manually_selected_node: bool,
    /// 界面语言（system | zh | en；随设置表单一起落盘）
    #[serde(default = "default_system")]
    pub language: String,
    /// 界面主题（system | dark | light；随设置表单一起落盘）
    #[serde(default = "default_system")]
    pub theme: String,
    /// 【APP49 任务2.2】启动时自动更新全部订阅（每天一次，默认开启）。
    #[serde(default = "default_true")]
    pub auto_update_subs_daily: bool,
    /// 最近一次自动更新成功执行的日期（YYYY-MM-DD），用于「每天仅一次」。
    #[serde(default)]
    pub last_auto_update_subs_date: String,
}

/// language / theme 等枚举字符串字段缺失时的兜底默认值
fn default_system() -> String {
    "system".to_string()
}

/// 布尔字段默认 true（用于 close_connections_on_switch 等「新行为默认开启」项）
fn default_true() -> bool {
    true
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
            close_connections_on_switch: true,
            go_aim_enabled: false,
            go_aim_pinned_node: None,
            selected_node: None,
            user_manually_selected_node: false,
            language: "system".to_string(),
            theme: "system".to_string(),
            auto_update_subs_daily: true,
            last_auto_update_subs_date: String::new(),
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
    /// 【APP39 任务3】按域名聚合（只收录解析出有效域名的连接）
    pub domains: HashMap<String, AggStat>,
    /// 【APP39 任务3】按目标 IP 聚合（纯 IP 地址，绝不混入域名）
    pub ips: HashMap<String, AggStat>,
    /// 【APP39 任务3】IP → 域名 反向缓存（由 metadata.host 实时填充），
    /// 供后续同一 IP 的无域名连接补齐域名
    pub ip_to_domain: HashMap<String, String>,
    /// 【APP49 任务4】按传输协议聚合（TCP / UDP，源自 metadata.network）。
    /// 聚合结构无磁盘缓存，新增字段天然兼容旧数据（启动即空表）
    #[serde(default)]
    pub protocols: HashMap<String, AggStat>,
    /// 【APP51 任务3】三方分流累计字节（代理 / 直连 / Go Lan）。
    /// 由连接 chains 分类累加，再用内核 downloadTotal+uploadTotal 的
    /// 未归类差额按路由模式补入，保证分流占比永远 100%、绝不空表。
    #[serde(default)]
    pub proxy_bytes: u64,
    #[serde(default)]
    pub direct_bytes: u64,
    #[serde(default)]
    pub lan_bytes: u64,
    /// 【APP51 任务3】上一帧内核累计总量，用于计算未归类差额
    #[serde(default)]
    pub last_total_down: u64,
    #[serde(default)]
    pub last_total_up: u64,
    /// 【APP69 任务3】上次分析统计重置时刻（30 秒冷却），不参与序列化
    #[serde(skip)]
    pub last_reset_at: Option<std::time::Instant>,
}

/// 【APP54 任务4】测速 / Go AIM 探测进度（原子统计，供前端进度条实时渲染）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeProgress {
    /// 是否正在进行
    #[serde(default)]
    pub running: bool,
    /// 已完成节点数
    #[serde(default)]
    pub done: usize,
    /// 本轮总节点数
    #[serde(default)]
    pub total: usize,
    /// 完成百分比（0~100）
    #[serde(default)]
    pub percent: u8,
    /// Go AIM 已解锁节点数（测速进度恒为 0）
    #[serde(default)]
    pub unlocked_count: usize,
    /// 【APP68】阶段一快筛进度
    #[serde(default)]
    pub fast_done: usize,
    #[serde(default)]
    pub fast_total: usize,
    /// 【APP68】阶段二实际发起的完整检测数（不含缓存命中）
    #[serde(default)]
    pub full_done: usize,
    #[serde(default)]
    pub full_total: usize,
    #[serde(default)]
    pub cache_hits: usize,
    #[serde(default)]
    pub pending_count: usize,
    #[serde(default)]
    pub verified_count: usize,
    #[serde(default)]
    pub unknown_count: usize,
    #[serde(default)]
    pub elapsed_ms: u64,
}

impl ProbeProgress {
    /// 按 done/total 重算百分比（total 为 0 时记 0）
    pub fn recompute(&mut self) {
        self.percent = if self.total == 0 {
            0
        } else {
            ((self.done.min(self.total) * 100) / self.total) as u8
        };
    }

    /// 【APP68】真实两阶段进度：快筛 0~20%，深测 + 缓存核验 20~100%。
    /// 未完成全部阶段二节点时封顶 99%，绝不提前显示完成。
    pub fn recompute_aim(&mut self) {
        if self.full_total > 0 {
            self.total = self.full_total;
            self.done = (self.full_done + self.cache_hits).min(self.full_total);
            self.pending_count = self.full_total.saturating_sub(self.done);
            let percent = 20 + (self.done * 80) / self.full_total.max(1);
            self.percent = if self.pending_count == 0 {
                100
            } else {
                percent.min(99) as u8
            };
        } else {
            self.total = self.fast_total;
            self.done = self.fast_done.min(self.fast_total);
            self.pending_count = self.fast_total.saturating_sub(self.fast_done);
            self.percent = ((self.fast_done * 20) / self.fast_total.max(1)).min(20) as u8;
        }
    }
}

/// 【APP52 任务1】节点测速 / Go AIM 探测持久化缓存（`node_metrics_cache.json`）。
/// 切换页面、停止/启动 VPN、重启 APP 都绝不清空；仅 refresh_subscription /
/// delete_subscription 清理对应已失效节点。启动时恢复到内存，供节点页在
/// 内核未运行时仍显示上次真实延迟与 AI/流媒体徽章。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedNodeMetrics {
    /// 节点名 → 最近一次真实延迟（0 = 超时，前端排序时置底）
    #[serde(default)]
    pub delays: HashMap<String, u32>,
    /// 节点名 → Go AIM 评级结果
    #[serde(default)]
    pub aim_results: HashMap<String, super::go_aim::AimNodeResult>,
    /// Go AIM 当前最优节点
    #[serde(default)]
    pub aim_best_node: Option<String>,
    /// 最近更新时间（Unix 秒）
    #[serde(default)]
    pub updated_at: u64,
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
    /// 连接起始 Unix 毫秒时间戳（IPA-12）：前端亮屏第一帧用
    /// Date.now() - startedAtMs 差值渲染时长，实现 0ms 瞬时同步。
    /// iOS 上优先采用系统 nesessionmanagerd 维护的 connectedDate
    /// （不受 App 挂起/锁屏影响）；仅 Running 态存在，停止/出错清空
    pub started_at_ms: RwLock<Option<u64>>,
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
    /// 【APP26 任务2.3】用户是否手动点选过节点（仅 select_proxy 命令写入）。
    /// 【APP52 任务1】bool 语义：false = 自动选点模式；true = 用户手动指定，
    /// 自动最低延迟选点不再覆盖用户选择。
    pub user_manually_selected_node: RwLock<bool>,
    /// 【APP52 任务1】节点测速 / Go AIM 探测持久化缓存（磁盘 + 内存双份）
    pub node_metrics: RwLock<PersistedNodeMetrics>,
    /// 当前 Pro 授权状态（启动时由 license 缓存恢复；后台校验后刷新）
    pub entitlement: RwLock<super::license::EntitlementStatus>,
    /// entitlement 的会话签名（防内存篡改：status 被改写后签名校验失败）
    pub entitlement_sign: RwLock<u64>,
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
    /// 【APP54 任务4】全量测速进度（原子统计 + 事件推送）
    pub delay_progress: Mutex<ProbeProgress>,
    /// 【APP54 任务4】Go AIM 探测进度（原子统计 + 事件推送）
    pub aim_progress: Mutex<ProbeProgress>,
    /// 【APP51 任务1】Go AIM 探测代数计数器：订阅删除/停用/刷新时 +1，
    /// 正在运行的探测任务发现代数变化立即中止，杜绝旧节点结果污染缓存
    pub aim_generation: std::sync::atomic::AtomicU64,
    /// Go Lan：回家网络配置（go_lan.json）
    pub go_lan: RwLock<super::go_lan::GoLanSettings>,
    /// Go Cus：覆写引擎配置（go_cus.json）
    pub go_cus: RwLock<super::go_cus::GoCusSettings>,

    // ---- 运行时统计（前后台不间断；内核停止/启动时经 reset_runtime_stats 清空）----
    /// 60 秒实时流量环形队列（最新在尾部）
    pub traffic_history: RwLock<VecDeque<TrafficSample>>,
    /// 【APP46 任务4.1 / APP51 任务2】/connections 顶层 downloadTotal/uploadTotal
    /// 差分基准：(采样时刻, 上次下行总量, 上次上行总量, 上次下行速率, 上次上行速率)。
    /// 每次前端拉 runtime_snapshot 时主动 GET /connections（1500ms 超时），
    /// dt < 0.15s 直接返回缓存速率；超时则保留上次速率的一半衰减（绝不归零）。
    pub last_traffic_sample: Mutex<Option<(Instant, u64, u64, u64, u64)>>,
    /// 当前活跃连接快照（id → snapshot）
    pub connections_live: RwLock<HashMap<String, ConnSnapshot>>,
    /// 按 host / outbound / rule 聚合的分析数据
    pub analytics: RwLock<AnalyticsAgg>,
    /// 今日流量缓存（store::today_total_bytes 的最新值）
    pub today_bytes_cache: RwLock<u64>,
    /// 连接保留序号发生器（单调递增，用于活跃/近期连接池的排序与淘汰）
    pub conn_seq: std::sync::atomic::AtomicU64,
    /// 前端是否处于前台（由 App.tsx visibilitychange 经 IPC 上报）。
    /// 后台（锁屏/切到其他 App）时暂停向 WebView 推送高频事件与连接聚合，
    /// 主 App 静默零唤醒耗电；扩展内核仍在底层持续累计总流量。
    pub app_in_foreground: std::sync::atomic::AtomicBool,
    /// APP 远程管控阻断状态（app-control：服务端返回 allowed=false 时置位）。
    /// None = 无管控；Some(block) = 阻止 start_core 并已广播前端。
    pub control_block: RwLock<Option<super::app_control::ControlBlock>>,
    /// 强退重开认领流程是否已尝试过（进程内只尝试一次，避免每次状态
    /// 查询都重复读配置 + 探测内核 API）
    pub reattach_attempted: std::sync::atomic::AtomicBool,
}

impl AppState {
    /// 创建状态并从 data_dir/settings.json 恢复用户设置（含运行模式）
    pub fn new(data_dir: PathBuf, app_handle: AppHandle) -> Self {
        let mut settings = super::store::load_settings(&data_dir);
        // 【APP-10 任务2】启动清洗：历史版本可能把 direct/block 等内置出站
        // 持久化为 Go AIM 手动指定节点——一旦发现立即清空，回退自动选点
        if let Some(pinned) = settings.go_aim_pinned_node.clone()
            && super::config_builder::is_builtin_non_proxy_tag(&pinned)
        {
            tracing::warn!("[startup] 清洗历史遗留的非法 go_aim_pinned_node={pinned}");
            settings.go_aim_pinned_node = None;
            let _ = super::store::save_settings(&data_dir, &settings);
        }
        // iOS 强制归一 TUN 模式：settings.json 里可能存有历史 systemProxy
        //（build 149 方案第 2 步第 1 点）
        #[cfg(target_os = "ios")]
        let mode = RunMode::Tun;
        #[cfg(not(target_os = "ios"))]
        let mode = settings.mode;
        // 启动即执行到期熔断（本地缓存可能跨过了 expires_at）
        let mut entitlement = super::license::cached_entitlement(&data_dir);
        super::license::enforce_expiry(&mut entitlement, super::license::now_unix());
        let entitlement_sign = super::security::entitlement_signature(
            &entitlement.status,
            entitlement.expires_at,
            entitlement.last_verified_at,
        );
        // 【APP52 任务1】启动恢复节点测速/Go AIM 持久化缓存
        let node_metrics = load_node_metrics(&data_dir);
        let restored_aim = node_metrics.aim_results.clone();
        let restored_best = node_metrics.aim_best_node.clone();
        let manual_node = settings.user_manually_selected_node;
        Self {
            app_handle,
            data_dir: data_dir.clone(),
            status: RwLock::new(CoreStatus::Stopped),
            mode: RwLock::new(mode),
            settings: RwLock::new(settings),
            started_at: RwLock::new(None),
            started_at_ms: RwLock::new(None),
            kernel_handle: RwLock::new(None),
            tun_guard: RwLock::new(None),
            api_addr: RwLock::new(super::kernel::PREFERRED_API_ADDR.to_string()),
            api_secret: RwLock::new(String::new()),
            kernel_version: RwLock::new(None),
            main_selector: RwLock::new(None),
            user_manually_selected_node: RwLock::new(manual_node),
            node_metrics: RwLock::new(node_metrics),
            entitlement: RwLock::new(entitlement),
            entitlement_sign: RwLock::new(entitlement_sign),
            proxy_backup: RwLock::new(None),
            aim_results: RwLock::new(restored_aim),
            aim_probing: std::sync::atomic::AtomicBool::new(false),
            aim_locked_node: RwLock::new(restored_best),
            aim_monitor_started: std::sync::atomic::AtomicBool::new(false),
            delay_progress: Mutex::new(ProbeProgress::default()),
            aim_progress: Mutex::new(ProbeProgress::default()),
            aim_generation: std::sync::atomic::AtomicU64::new(0),
            go_lan: RwLock::new(super::go_lan::load(&data_dir)),
            go_cus: RwLock::new(super::go_cus::load(&data_dir)),
            traffic_history: RwLock::new(VecDeque::new()),
            last_traffic_sample: Mutex::new(None),
            connections_live: RwLock::new(HashMap::new()),
            analytics: RwLock::new(AnalyticsAgg::default()),
            today_bytes_cache: RwLock::new(0),
            conn_seq: std::sync::atomic::AtomicU64::new(0),
            app_in_foreground: std::sync::atomic::AtomicBool::new(true),
            control_block: RwLock::new(None),
            reattach_attempted: std::sync::atomic::AtomicBool::new(false),
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
    /// 写入前强制执行到期熔断，并刷新会话签名。
    pub fn apply_entitlement(&self, mut next: super::license::EntitlementStatus) {
        super::license::enforce_expiry(&mut next, super::license::now_unix());
        let sign = super::security::entitlement_signature(
            &next.status,
            next.expires_at,
            next.last_verified_at,
        );
        // 两把锁顺序获取（禁止嵌套），避免与 is_pro_active 并发时死锁
        *self.entitlement.write() = next.clone();
        *self.entitlement_sign.write() = sign;
        let _ = self.app_handle.emit("pro://status", &next);
    }

    /// 当前是否拥有有效 Pro 授权（所有 Pro 守卫的唯一入口）：
    /// 1. 运行环境未被判定受损（调试器附加 / 内存篡改）；
    /// 2. 内存授权状态签名自洽（防内存修改器把 expired 改回 active）；
    /// 3. 状态为 active 且当前系统时间早于 expires_at（离线也生效）。
    pub fn is_pro_active(&self) -> bool {
        if super::security::is_compromised() {
            return false;
        }
        let now = super::license::now_unix();
        let (status, expires_at, last_verified_at, unlocked) = {
            let ent = self.entitlement.read();
            (
                ent.status.clone(),
                ent.expires_at,
                ent.last_verified_at,
                ent.is_unlocked(),
            )
        };
        let sign = *self.entitlement_sign.read();
        let expect =
            super::security::entitlement_signature(&status, expires_at, last_verified_at);
        if sign != expect {
            super::security::mark_compromised("entitlement signature mismatch");
            return false;
        }
        unlocked && !super::license::is_expired(&self.entitlement.read(), now)
    }

    /// 保存设置到内存 + settings.json
    pub fn save_settings(&self, next: UserSettings) -> anyhow::Result<()> {
        super::store::save_settings(&self.data_dir, &next)?;
        *self.settings.write() = next;
        Ok(())
    }

    /// 【APP55 任务4】清空瞬时运行时数据（内核停止/启动时调用）。
    ///
    /// 只重置 60s 流量队列、活跃连接池与总量差分基准；分析聚合
    /// （hosts / domains / ips / outbounds / rules / protocols）与
    /// proxy/direct/lan 三类累计字节一律保留——
    /// VPN 断开重连、内核 downloadTotal 从 0 重新计时时，后续帧在新基准上
    /// 继续累加，历史统计不会因重启而清零。
    /// 今日流量基数仍由 store::archive_session 负责归档。
    pub fn reset_runtime_stats(&self) {
        self.traffic_history.write().clear();
        self.connections_live.write().clear();
        let mut agg = self.analytics.write();
        // 新会话连接 id 从头分配，清空差值基准避免旧会话残留
        agg.last_seen.clear();
        agg.last_total_down = 0;
        agg.last_total_up = 0;
    }

    /// 【APP49 任务4】清空分析聚合（分析页「清空统计」按钮）。
    /// 与 reset_runtime_stats 不同：保留 last_seen 增量基准，
    /// 避免清空后仍活跃的连接在下一帧被当作新连接重复 count+1；
    /// 流量曲线 / 连接池不动。前端经运行时快照轮询拿到清空后的数据。
    pub fn reset_analytics(&self) {
        let mut agg = self.analytics.write();
        agg.hosts.clear();
        agg.domains.clear();
        agg.ips.clear();
        agg.ip_to_domain.clear();
        agg.outbounds.clear();
        agg.rules.clear();
        agg.protocols.clear();
    }

    /// 【APP57 任务2】内核会话切换（启动 / 停止 / 重启 / 内核计数器归零）时
    /// 清零全部分析统计：三分字节、主机 / 域名 / IP / 出站 / 规则 / 协议排行、
    /// 连接差分工信与流量差分基准全部归零，新会话从 0 重新统计。
    pub fn reset_analytics_session(&self) {
        let mut agg = self.analytics.write();
        agg.hosts.clear();
        agg.domains.clear();
        agg.ips.clear();
        agg.ip_to_domain.clear();
        agg.outbounds.clear();
        agg.rules.clear();
        agg.protocols.clear();
        agg.last_seen.clear();
        agg.proxy_bytes = 0;
        agg.direct_bytes = 0;
        agg.lan_bytes = 0;
        agg.last_total_down = 0;
        agg.last_total_up = 0;
        drop(agg);
        *self.last_traffic_sample.lock() = None;
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
            // 【APP39 任务3】域名视图 / IP 视图两份独立聚合：
            // domains 只含真实域名（含反向解析与常用 IP 映射补齐），
            // ips 只含纯 IP 地址，前端切换按钮时数据必然显著不同。
            "domains": top8(&agg.domains),
            "ips": top8(&agg.ips),
            "outbounds": top8(&agg.outbounds),
            "rules": top8(&agg.rules),
            // 【APP49 任务4】TCP / UDP 协议维度聚合（camelCase 序列化）
            "protocols": top8(&agg.protocols),
            // 【APP51 任务3】三方分流累计字节：前端据此画三色占比条，
            // 不再依赖 outbounds 首跳分组，杜绝「暂无流量数据」
            "proxyBytes": agg.proxy_bytes,
            "directBytes": agg.direct_bytes,
            "lanBytes": agg.lan_bytes,
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

    /// 【APP52 任务1】写入一批节点延迟（0 = 超时），并异步落盘。
    /// 说明：切换页面 / 停止启动 VPN / 重启 APP 都不会清空本缓存，
    /// 只有订阅刷新或删除时由 purge 清理已失效节点。
    pub fn record_node_delays<I>(&self, items: I)
    where
        I: IntoIterator<Item = (String, u32)>,
    {
        {
            let mut metrics = self.node_metrics.write();
            for (name, delay) in items {
                metrics.delays.insert(name, delay);
            }
            metrics.updated_at = now_unix();
        }
        self.persist_node_metrics();
    }

    /// 【APP52 任务1】写入 Go AIM 探测结果（含最优节点），异步落盘。
    pub fn record_aim_results(
        &self,
        results: &HashMap<String, super::go_aim::AimNodeResult>,
        best: Option<&str>,
    ) {
        {
            let mut metrics = self.node_metrics.write();
            metrics.aim_results = results.clone();
            metrics.aim_best_node = best.map(str::to_string);
            metrics.updated_at = now_unix();
        }
        self.persist_node_metrics();
    }

    /// 【APP52 任务1】订阅刷新/删除后只保留仍存在的节点，并异步落盘。
    pub fn retain_node_metrics(&self, valid: &std::collections::HashSet<String>) {
        {
            let mut metrics = self.node_metrics.write();
            metrics.delays.retain(|name, _| valid.contains(name));
            metrics.aim_results.retain(|name, _| valid.contains(name));
            if metrics
                .aim_best_node
                .as_ref()
                .is_some_and(|n| !valid.contains(n))
            {
                metrics.aim_best_node = None;
            }
            metrics.updated_at = now_unix();
        }
        self.persist_node_metrics();
    }

    /// 异步落盘节点指标缓存（小文件原子写，绝不阻塞 UI 线程）
    pub fn persist_node_metrics(&self) {
        let snapshot = self.node_metrics.read().clone();
        let data_dir = self.data_dir.clone();
        std::thread::spawn(move || {
            if let Err(e) = save_node_metrics(&data_dir, &snapshot) {
                tracing::warn!("[node-metrics] 持久化失败: {e}");
            }
        });
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

        // IPA-12：进入 Running 时记录连接起始 Unix 毫秒时间戳（前端基准时钟）。
        // iOS 优先使用系统级 connectedDate（prism_ios_vpn_connected_timestamp，
        // 由 nesessionmanagerd 维护，不受 App 挂起/锁屏影响）；扩展尚未完成
        // 建隧时回退本地时钟。停止/出错清空，保证非 Running 态不残留旧值
        if next == CoreStatus::Running {
            #[cfg(target_os = "ios")]
            let started = {
                let sys = crate::platform::ios::vpn_connected_timestamp_ms();
                if sys > 0 { sys } else { unix_now_ms() }
            };
            #[cfg(not(target_os = "ios"))]
            let started = unix_now_ms();
            *self.started_at_ms.write() = Some(started);
            // 会话起点落盘：强退重开后认领后台隧道时用它恢复连续计时
            if let Err(e) = super::store::set_session_started_at(&self.data_dir, started) {
                tracing::warn!("持久化会话起始时间失败: {e}");
            }
        } else if matches!(next, CoreStatus::Stopped | CoreStatus::Error) {
            *self.started_at_ms.write() = None;
        }

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
        let started_at_ms = *self.started_at_ms.read();
        serde_json::json!({
            "status": status,
            "mode": mode,
            "uptimeSecs": uptime_secs,
            "startedAtMs": started_at_ms,
            "mainSelector": main_selector,
        })
    }
}

/// 当前 Unix 毫秒时间戳（IPA-12 连接起始基准时钟）
fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 当前 Unix 秒时间戳（节点指标缓存 updated_at 用）
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 【APP56 任务2】虚假延迟清洗：`0 < delay < 5` 必为本机回环 / FakeIP 假值，
/// 一律归为超时 0，杜绝列表出现 `1 ms`。
pub fn sanitize_fake_delay(delay: u32) -> u32 {
    if delay > 0 && delay < 5 { 0 } else { delay }
}

/// 【APP52 任务1】读取节点指标缓存；文件缺失/损坏一律回退空缓存，绝不阻塞启动。
/// 【APP56 任务2】加载时立即清洗历史 `< 5 ms` 的虚假延迟（回环 SYN-ACK 假值）。
/// 【APP67 P3】加载时按 probe_version / rule_version 淘汰旧版假解锁缓存：
/// 旧版引擎（< 2）产出的"假解锁"结果在加载时立即丢弃，只有新版引擎
/// 测出的真实 Verified 结果才会持久保留。
pub fn load_node_metrics(data_dir: &std::path::Path) -> PersistedNodeMetrics {
    let path = data_dir.join("node_metrics_cache.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return PersistedNodeMetrics::default();
    };
    let mut metrics: PersistedNodeMetrics = serde_json::from_str(&text).unwrap_or_default();
    metrics
        .delays
        .retain(|_, d| *d == 0 || *d >= 5);
    for d in metrics.delays.values_mut() {
        *d = sanitize_fake_delay(*d);
    }
    // 【APP67 P3】版本化淘汰：probe_version / rule_version 低于当前引擎版本的
    // 旧缓存一律丢弃，杜绝此前遗留的"显示已解锁、实际无法使用"假阳性。
    use crate::core::go_aim::{CURRENT_AIM_PROBE_VERSION, CURRENT_AIM_RULE_VERSION};
    metrics.aim_results.retain(|_, r| {
        r.probe_version >= CURRENT_AIM_PROBE_VERSION && r.rule_version >= CURRENT_AIM_RULE_VERSION
    });
    metrics
}

/// 【APP52 任务1】原子写入节点指标缓存（先 .tmp 再 rename）
pub fn save_node_metrics(
    data_dir: &std::path::Path,
    metrics: &PersistedNodeMetrics,
) -> anyhow::Result<()> {
    let path = data_dir.join("node_metrics_cache.json");
    let bytes = serde_json::to_vec_pretty(metrics)?;
    super::store::atomic_write(&path, &bytes)
}

/// 供 IPC 层使用：判断端口是否可绑定
pub fn is_port_free(host: &str, port: u16) -> bool {
    std::net::TcpListener::bind((host, port)).is_ok()
}

/// 【APP69 任务3】移动端 Clash API 端口必须恒定：iOS NEPacketTunnelProvider
/// 与 Android VpnService 在重载时，主 App / 看门狗若按随机端口重连会反复
/// `12 UNAVAILABLE`（Android 侧更是写死 http://127.0.0.1:9090）。
/// 桌面端保持 9090 优先、被占用则随机兜底。
pub fn pick_api_addr_for(is_mobile: bool) -> String {
    if is_mobile || is_port_free("127.0.0.1", 9090) {
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

/// 选择 clash_api 监听地址（桌面：9090 优先，占用则随机；移动端恒定 9090）
pub fn pick_api_addr() -> String {
    pick_api_addr_for(cfg!(any(target_os = "ios", target_os = "android")))
}

/// 【APP52 任务1】节点延迟统一排序键（后端 get_proxies / 前端 Proxies 双重排序）：
/// - 实测 delay > 0：分组 0，按延迟升序
/// - 未测速(None)：分组 1，居中
/// - 超时(delay == 0)：分组 2，置底
pub fn node_delay_sort_key(delay: Option<u32>) -> (u8, u32) {
    match delay {
        Some(d) if d > 0 => (0, d),
        None => (1, 0),
        _ => (2, 0),
    }
}

#[cfg(test)]
mod app52_tests {
    use super::*;

    /// 【APP69 任务3】移动端 Clash API 端口必须恒定 9090，绝不随机分配
    #[test]
    fn test_pick_api_addr_fixed_on_mobile() {
        assert_eq!(
            pick_api_addr_for(true),
            super::super::kernel::PREFERRED_API_ADDR
        );
    }

    #[test]
    fn test_node_delay_sort_key_order() {
        let mut items = vec![
            ("timeout".to_string(), Some(0)),
            ("untested".to_string(), None),
            ("slow".to_string(), Some(300)),
            ("fast".to_string(), Some(80)),
        ];
        items.sort_by_key(|(_, d)| node_delay_sort_key(*d));
        let order: Vec<&str> = items.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(order, vec!["fast", "slow", "untested", "timeout"]);
    }

    /// 【APP52 任务1】PersistedNodeMetrics 写入后必须能原样恢复
    #[test]
    fn test_persisted_node_metrics_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "prism_app52_metrics_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut metrics = PersistedNodeMetrics {
            updated_at: 123,
            aim_best_node: Some("HK-01".into()),
            ..Default::default()
        };
        metrics.delays.insert("HK-01".into(), 45);
        metrics.delays.insert("US-02".into(), 0);
        save_node_metrics(&dir, &metrics).unwrap();
        let restored = load_node_metrics(&dir);
        assert_eq!(restored.delays.get("HK-01"), Some(&45));
        assert_eq!(restored.delays.get("US-02"), Some(&0));
        assert_eq!(restored.aim_best_node.as_deref(), Some("HK-01"));
        assert_eq!(restored.updated_at, 123);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_missing_metrics_cache_falls_back_to_empty() {
        let dir = std::env::temp_dir().join("prism_app52_missing_metrics");
        let _ = std::fs::remove_dir_all(&dir);
        let m = load_node_metrics(&dir);
        assert!(m.delays.is_empty());
        assert!(m.aim_results.is_empty());
    }

    /// 【APP54 任务2】102 个节点必须 100% 覆盖持久化，且按延迟升序稳定
    /// （实测 >0 升序 → 未测速居中 → 超时置底），重新加载后完全一致。
    #[test]
    fn test_102_nodes_full_persist_and_sorted() {
        let dir = std::env::temp_dir().join(format!(
            "prism_app54_all_delays_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut metrics = PersistedNodeMetrics::default();
        for i in 0..102u32 {
            let name = format!("node-{i:03}");
            // 每 10 个制造一个超时（0），其余给出 5..=106ms 的真实延迟
            // （【APP56 任务2】`< 5ms` 一律视为虚假延迟，加载时清洗）
            let delay = if i % 10 == 9 { 0 } else { i + 5 };
            metrics.delays.insert(name, delay);
        }
        save_node_metrics(&dir, &metrics).unwrap();
        let restored = load_node_metrics(&dir);
        assert_eq!(restored.delays.len(), 102, "全部 102 个节点都必须持久化");
        let mut names: Vec<(String, Option<u32>)> = restored
            .delays
            .iter()
            .map(|(n, d)| (n.clone(), Some(*d)))
            .collect();
        names.sort_by_key(|(_, d)| node_delay_sort_key(*d));
        let keys: Vec<u32> = names.iter().map(|(_, d)| d.unwrap()).collect();
        assert!(keys.iter().take(92).all(|d| *d > 0), "实测延迟必须升序在前");
        assert!(keys.windows(2).take(91).all(|w| w[0] <= w[1]), "升序稳定");
        assert_eq!(keys.iter().filter(|d| **d == 0).count(), 10, "超时节点置底");
        assert_eq!(node_delay_sort_key(None), (1, 0), "未测速居中");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 【APP56 任务2】`0 < delay < 5` 的虚假延迟（本机回环 SYN-ACK / FakeIP）
    /// 加载时必须被清洗为超时 0，列表中绝不再出现 `1 ms`。
    #[test]
    fn test_sub_five_ms_fake_delay_is_purged_on_load() {
        let dir = std::env::temp_dir().join(format!(
            "prism_app56_fake_delay_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut metrics = PersistedNodeMetrics::default();
        metrics.delays.insert("fake-1ms".into(), 1);
        metrics.delays.insert("fake-4ms".into(), 4);
        metrics.delays.insert("real-5ms".into(), 5);
        metrics.delays.insert("real-120ms".into(), 120);
        metrics.delays.insert("timeout".into(), 0);
        save_node_metrics(&dir, &metrics).unwrap();
        let restored = load_node_metrics(&dir);
        assert!(!restored.delays.contains_key("fake-1ms"));
        assert!(!restored.delays.contains_key("fake-4ms"));
        assert_eq!(restored.delays.get("real-5ms"), Some(&5));
        assert_eq!(restored.delays.get("real-120ms"), Some(&120));
        assert_eq!(restored.delays.get("timeout"), Some(&0));
        assert_eq!(sanitize_fake_delay(1), 0);
        assert_eq!(sanitize_fake_delay(4), 0);
        assert_eq!(sanitize_fake_delay(5), 5);
        assert_eq!(sanitize_fake_delay(0), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 旧版缓存（probe_version / rule_version 低于当前 v3）加载时必须淘汰，
    /// 只有当前引擎版本的真实结果才保留，彻底清除遗留假解锁标签。
    #[test]
    fn test_old_aim_cache_evicted_on_load() {
        use crate::core::go_aim::{CURRENT_AIM_PROBE_VERSION, CURRENT_AIM_RULE_VERSION, AimNodeResult};
        let dir = std::env::temp_dir().join(format!(
            "prism_app67_aim_cache_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut metrics = PersistedNodeMetrics::default();
        // 旧版假解锁缓存（probe_version: 0）—— 必须被淘汰
        metrics.aim_results.insert(
            "old-fake-gpt".into(),
            AimNodeResult {
                node_name: "old-fake-gpt".into(),
                unlocked_tags: vec!["GPT".into()],
                probe_version: 0,
                rule_version: 0,
                probed: true,
                ..Default::default()
            },
        );
        // 旧版 rule_version（probe_version 够但 rule_version 不够）—— 也淘汰
        metrics.aim_results.insert(
            "old-rule".into(),
            AimNodeResult {
                node_name: "old-rule".into(),
                unlocked_tags: vec!["NF".into()],
                probe_version: CURRENT_AIM_PROBE_VERSION,
                rule_version: 1,
                probed: true,
                ..Default::default()
            },
        );
        // 新版真实结果 —— 保留
        metrics.aim_results.insert(
            "new-real".into(),
            AimNodeResult {
                node_name: "new-real".into(),
                unlocked_tags: vec!["GPT".into(), "YT".into()],
                probe_version: CURRENT_AIM_PROBE_VERSION,
                rule_version: CURRENT_AIM_RULE_VERSION,
                probed: true,
                ..Default::default()
            },
        );
        save_node_metrics(&dir, &metrics).unwrap();
        let restored = load_node_metrics(&dir);
        assert!(
            !restored.aim_results.contains_key("old-fake-gpt"),
            "probe_version:0 旧缓存必须淘汰"
        );
        assert!(
            !restored.aim_results.contains_key("old-rule"),
            "旧 rule_version 缓存必须淘汰"
        );
        assert!(
            restored.aim_results.contains_key("new-real"),
            "当前版本真实结果必须保留"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
