//! 本地持久化存储
//!
//! - settings.json：用户设置（端口 / 局域网 / 系统代理 / 开机自启）
//! - subscriptions.json：已导入的订阅记录（当前为单订阅模型，保留数组结构便于扩展）
//!
//! 所有文件损坏或缺失时回退默认值，绝不阻塞应用启动。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::state::UserSettings;

/// 一条订阅记录
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRecord {
    /// 订阅地址（http/https）或本地文件路径
    pub url: String,
    /// 更新时间（Unix 秒）
    pub updated_at: i64,
    /// 可选备注名
    #[serde(default)]
    pub name: Option<String>,
    /// 是否参与配置合并（多订阅模型；旧记录缺省视为启用）
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 订阅流量配额（机场下发 subscription-userinfo 头才有值）
    #[serde(default)]
    pub upload_bytes: Option<u64>,
    #[serde(default)]
    pub download_bytes: Option<u64>,
    #[serde(default)]
    pub total_bytes: Option<u64>,
    /// 到期时间（Unix 秒）
    #[serde(default)]
    pub expire_at: Option<u64>,
}

/// 机场通过 `subscription-userinfo` 响应头下发的流量配额
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionQuota {
    pub upload_bytes: Option<u64>,
    pub download_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub expire_at: Option<u64>,
}

impl SubscriptionQuota {
    /// 解析 `upload=1; download=2; total=100; expire=1700000000`
    pub fn parse(raw: &str) -> Option<Self> {
        let mut quota = SubscriptionQuota::default();
        let mut matched = false;
        for part in raw.split(';') {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            let Ok(num) = value.trim().parse::<u64>() else {
                continue;
            };
            match key.trim() {
                "upload" => quota.upload_bytes = Some(num),
                "download" => quota.download_bytes = Some(num),
                "total" => quota.total_bytes = Some(num),
                "expire" => quota.expire_at = Some(num),
                _ => continue,
            }
            matched = true;
        }
        matched.then_some(quota)
    }
}

fn default_enabled() -> bool {
    true
}

/// 通用原子写入：先写 .tmp 再 rename（调用方负责父目录存在）
pub fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension(
        path.extension()
            .map(|e| format!("{}.tmp", e.to_string_lossy()))
            .unwrap_or_else(|| "tmp".into()),
    );
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// 订阅内容落盘路径：data_dir/profiles/{url哈希}.yaml（由 URL 确定性派生）
pub fn profile_path(data_dir: &Path, url: &str) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    url.hash(&mut h);
    data_dir
        .join("profiles")
        .join(format!("{:016x}.yaml", h.finish()))
}

/// proxy-provider 节点落盘路径：data_dir/providers/{subURL哈希}_{provider名哈希}.yaml
pub fn provider_path(data_dir: &Path, sub_url: &str, provider_name: &str) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    sub_url.hash(&mut h);
    provider_name.hash(&mut h);
    data_dir
        .join("providers")
        .join(format!("{:016x}.yaml", h.finish()))
}

/// 流量统计持久化：日/周/月累计（字节）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficStats {
    /// 今日已用（下载+上传，字节）
    pub today_bytes: u64,
    /// 本周已用（字节）
    pub week_bytes: u64,
    /// 本月已用（字节）
    pub month_bytes: u64,
    /// 上次统计的日期戳（用于判断是否需要重置 today/week/month）
    pub last_date: String,
    /// 上次统计的 ISO 周数（用于判断是否需要重置 week）
    pub last_week: u32,
    /// 上次统计的月份（用于判断是否需要重置 month）
    pub last_month: u32,
    /// 今日日期戳（与 last_date 同款算法，全天一致；用于跨天归零判断）
    #[serde(default)]
    pub today_date: String,
    /// 今日已结束会话累计（字节）
    #[serde(default)]
    pub today_archived_bytes: u64,
    /// 当前会话最新绝对累计值（内核 uploadTotal + downloadTotal）
    #[serde(default)]
    pub current_session_bytes: u64,
    /// 当前会话起始 Unix 毫秒时间戳（APP-5）：强退重开后认领后台隧道时，
    /// 用它恢复「已连接时长」的连续计时（0 = 无有效会话）
    #[serde(default)]
    pub session_started_at_ms: u64,
}

impl Default for TrafficStats {
    fn default() -> Self {
        let now = std::time::SystemTime::now();
        let epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let days = (epoch.as_secs() / 86400) as i64;
        // 简化日期计算：用 chrono 太重，这里用 naive 算法
        // 对于统计用途，只需区分日/周/月即可
        Self {
            today_bytes: 0,
            week_bytes: 0,
            month_bytes: 0,
            last_date: format!("day-{}", days),
            last_week: (days / 7) as u32,
            last_month: ((days / 30) as u32) % 12,
            today_date: format!("day-{}", days),
            today_archived_bytes: 0,
            current_session_bytes: 0,
            session_started_at_ms: 0,
        }
    }
}

/// 当前日期戳（与 TrafficStats 的 last_date / today_date 同款算法，保证全天一致）
fn current_day_stamp() -> String {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("day-{}", (epoch.as_secs() / 86400) as i64)
}

fn traffic_stats_path(data_dir: &Path) -> PathBuf {
    data_dir.join("traffic_stats.json")
}

/// 读取流量统计
pub fn load_traffic_stats(data_dir: &Path) -> TrafficStats {
    match std::fs::read(traffic_stats_path(data_dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => TrafficStats::default(),
    }
}

/// 写入流量统计
pub fn save_traffic_stats(data_dir: &Path, stats: &TrafficStats) -> anyhow::Result<()> {
    std::fs::create_dir_all(data_dir).ok();
    let path = traffic_stats_path(data_dir);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(stats)?;
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// 追加流量并自动重置过期统计
pub fn add_traffic(data_dir: &Path, up: u64, down: u64) -> anyhow::Result<TrafficStats> {
    let mut stats = load_traffic_stats(data_dir);
    let now = std::time::SystemTime::now();
    let epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let days = (epoch.as_secs() / 86400) as i64;
    let current_date = format!("day-{}", days);
    let current_week = (days / 7) as u32;
    let current_month = ((days / 30) as u32) % 12;

    // 重置日/周/月统计
    if stats.last_date != current_date {
        stats.today_bytes = 0;
        stats.last_date = current_date;
    }
    if stats.last_week != current_week {
        stats.week_bytes = 0;
        stats.last_week = current_week;
    }
    if stats.last_month != current_month {
        stats.month_bytes = 0;
        stats.last_month = current_month;
    }

    let total = up + down;
    stats.today_bytes += total;
    stats.week_bytes += total;
    stats.month_bytes += total;

    save_traffic_stats(data_dir, &stats)?;
    Ok(stats)
}

/// 读取当前会话绝对累计值；跨天视为 0（上个会话不计入今日）
pub fn session_bytes(data_dir: &Path) -> u64 {
    let stats = load_traffic_stats(data_dir);
    if stats.today_date != current_day_stamp() {
        return 0;
    }
    stats.current_session_bytes
}

/// 写入当前会话绝对累计值（内核 /connections 流上报的 uploadTotal+downloadTotal）。
/// 跨天则把 today_archived_bytes 清零、today_date 重新盖章（上一个会话归属昨日）
pub fn set_current_session(data_dir: &Path, bytes: u64) -> anyhow::Result<()> {
    let mut stats = load_traffic_stats(data_dir);
    let today = current_day_stamp();
    if stats.today_date != today {
        stats.today_date = today;
        stats.today_archived_bytes = 0;
    }
    stats.current_session_bytes = bytes;
    save_traffic_stats(data_dir, &stats)
}

/// 记录当前会话起始时间戳（进入 Running 时落盘，供强退重开后恢复计时）
pub fn set_session_started_at(data_dir: &Path, ms: u64) -> anyhow::Result<()> {
    let mut stats = load_traffic_stats(data_dir);
    stats.session_started_at_ms = ms;
    save_traffic_stats(data_dir, &stats)
}

/// 读取当前会话起始时间戳（0 = 无有效会话记录）
pub fn session_started_at(data_dir: &Path) -> u64 {
    load_traffic_stats(data_dir).session_started_at_ms
}

/// 归档当前会话：把 current_session_bytes 累加进 today_archived_bytes 并归零。
/// 跨天则清空 archived 与 legacy today_bytes（新的一天从零重新累计）
pub fn archive_session(data_dir: &Path) -> anyhow::Result<()> {
    let mut stats = load_traffic_stats(data_dir);
    let today = current_day_stamp();
    if stats.today_date != today {
        stats.today_date = today;
        stats.today_archived_bytes = 0;
        stats.today_bytes = 0;
    } else {
        stats.today_archived_bytes = stats
            .today_archived_bytes
            .saturating_add(stats.current_session_bytes);
    }
    stats.current_session_bytes = 0;
    stats.session_started_at_ms = 0;
    save_traffic_stats(data_dir, &stats)
}

/// 今日总流量：today_archived_bytes + current_session_bytes（跨天返回 current_session_bytes）
pub fn today_total_bytes(data_dir: &Path) -> u64 {
    let stats = load_traffic_stats(data_dir);
    if stats.today_date != current_day_stamp() {
        return stats.current_session_bytes;
    }
    stats
        .today_archived_bytes
        .saturating_add(stats.current_session_bytes)
}

fn settings_path(data_dir: &Path) -> PathBuf {
    data_dir.join("settings.json")
}

fn subscriptions_path(data_dir: &Path) -> PathBuf {
    data_dir.join("subscriptions.json")
}

fn custom_rules_path(data_dir: &Path) -> PathBuf {
    data_dir.join("custom_rules.json")
}

/// 读取自定义规则（Clash 行格式，顺序即优先级）；损坏/缺失回退空列表
pub fn load_custom_rules(data_dir: &Path) -> Vec<String> {
    match std::fs::read(custom_rules_path(data_dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!("custom_rules.json 解析失败：{e}");
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

/// 原子写入自定义规则
pub fn save_custom_rules(data_dir: &Path, rules: &[String]) -> anyhow::Result<()> {
    std::fs::create_dir_all(data_dir).ok();
    let path = custom_rules_path(data_dir);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(rules)?;
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// 读取用户设置；任何错误（不存在/损坏）都回退默认值
pub fn load_settings(data_dir: &Path) -> UserSettings {
    let path = settings_path(data_dir);
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<UserSettings>(&bytes) {
            Ok(settings) => settings,
            Err(e) => {
                tracing::warn!("settings.json 解析失败，使用默认设置：{e}");
                UserSettings::default()
            }
        },
        Err(_) => UserSettings::default(),
    }
}

/// 原子写入用户设置（先写临时文件再 rename，避免写一半损坏配置）
pub fn save_settings(data_dir: &Path, settings: &UserSettings) -> anyhow::Result<()> {
    std::fs::create_dir_all(data_dir).ok();
    let path = settings_path(data_dir);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(settings)?;
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// 读取订阅记录列表
pub fn load_subscriptions(data_dir: &Path) -> Vec<SubscriptionRecord> {
    match std::fs::read(subscriptions_path(data_dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!("subscriptions.json 解析失败：{e}");
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

/// 写入完整订阅列表
fn write_subscriptions(data_dir: &Path, records: &[SubscriptionRecord]) -> anyhow::Result<()> {
    std::fs::create_dir_all(data_dir).ok();
    let path = subscriptions_path(data_dir);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(records)?;
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// 写入完整订阅列表（云端同步对账时更新备注名等场景）
pub fn save_subscriptions(data_dir: &Path, records: &[SubscriptionRecord]) -> anyhow::Result<()> {
    write_subscriptions(data_dir, records)
}

/// 记录一次订阅更新（同 URL 覆盖时间戳；多订阅模型，保留全部记录）
pub fn upsert_subscription(data_dir: &Path, url: &str) -> anyhow::Result<()> {
    let mut records = load_subscriptions(data_dir);
    let now = unix_now();

    if let Some(existing) = records.iter_mut().find(|r| r.url == url) {
        existing.updated_at = now;
    } else {
        records.push(SubscriptionRecord {
            url: url.to_string(),
            updated_at: now,
            name: None,
            enabled: true,
            upload_bytes: None,
            download_bytes: None,
            total_bytes: None,
            expire_at: None,
        });
    }
    write_subscriptions(data_dir, &records)
}

/// 更新订阅流量配额（机场在 `subscription-userinfo` 响应头下发；
/// 未下发时保留旧值，避免一次无头响应把已展示的配额清空）
pub fn set_subscription_quota(
    data_dir: &Path,
    url: &str,
    quota: &SubscriptionQuota,
) -> anyhow::Result<()> {
    let mut records = load_subscriptions(data_dir);
    let Some(record) = records.iter_mut().find(|r| r.url == url) else {
        return Ok(());
    };
    record.upload_bytes = quota.upload_bytes;
    record.download_bytes = quota.download_bytes;
    record.total_bytes = quota.total_bytes;
    record.expire_at = quota.expire_at;
    write_subscriptions(data_dir, &records)
}

/// 建立「待补内容」的保底记录：updated_at 置 0（前端显示「从未更新」）。
/// 供订阅云同步对账使用——云端拉取下载失败时先落记录，下次手动更新/
/// 对账空壳重拉时补齐内容；不能误用 now，否则用户会误以为内容已就绪
pub fn upsert_subscription_pending(data_dir: &Path, url: &str) -> anyhow::Result<()> {
    let mut records = load_subscriptions(data_dir);

    if let Some(existing) = records.iter_mut().find(|r| r.url == url) {
        existing.updated_at = 0;
    } else {
        records.push(SubscriptionRecord {
            url: url.to_string(),
            updated_at: 0,
            name: None,
            enabled: true,
            upload_bytes: None,
            download_bytes: None,
            total_bytes: None,
            expire_at: None,
        });
    }
    write_subscriptions(data_dir, &records)
}

/// 设置订阅启用状态；返回是否存在该记录
pub fn set_subscription_enabled(
    data_dir: &Path,
    url: &str,
    enabled: bool,
) -> anyhow::Result<bool> {
    let mut records = load_subscriptions(data_dir);
    let Some(record) = records.iter_mut().find(|r| r.url == url) else {
        return Ok(false);
    };
    record.enabled = enabled;
    write_subscriptions(data_dir, &records)?;
    Ok(true)
}

/// 删除一条订阅记录（按 URL 匹配），返回是否有记录被移除
pub fn delete_subscription(data_dir: &Path, url: &str) -> anyhow::Result<bool> {
    let mut records = load_subscriptions(data_dir);
    let before = records.len();
    records.retain(|r| r.url != url);
    if records.len() == before {
        return Ok(false);
    }
    write_subscriptions(data_dir, &records)?;
    Ok(true)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
