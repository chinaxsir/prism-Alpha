//! Pro 授权客户端：设备标识、HTTP 激活与状态查询、加密本地缓存、每日同步。
//!
//! 协议（无 token 鉴权；服务端部署于 Cloudflare 后，所有请求带 `X-Request-Source: prism-app` 头）：
//! - 激活：POST /api/license/activate，body {license_key, email, device_id, device_name}
//!   200 → {ok, device_id, plan: "free"|"pro"|"team", max_seats, expires_at}；
//!   400 invalid_input；403 activation_failed；409 seat_limit_reached；429 → {retry_after: 秒}；5xx server_error
//! - 状态：GET /api/license/status?license_key=...
//!   200 → {valid, plan, status, expires_at(ISO8601|null), max_seats, used_seats}
//!
//! 授权有效性策略：每天首次启动 APP 时自动与服务器同步一次并更新本地加密
//! 缓存；当天内授权信息只从该文件读取，不再联网。断网/服务不可达时不锁定：
//! 授权信息从本地加密文件读取（active 且未过期则继续可用，缓存有效期已过
//! 才降级为 expired），恢复联网后自动重试并以服务端结果修正。
//!
//! 本地缓存整体 AES-256-GCM 加密落盘（license.dat），密钥由设备 ID 派生：
//! 拷走文件读不出 Key/邮箱/有效期，篡改密文解密即失败，防逆向与破解。

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{LazyLock, RwLock};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::core::state::UserSettings;

/// 编译期固定授权服务地址（构建时可用 PRISM_LICENSE_URL 覆盖；App 内置，用户无需输入）。
/// 默认地址经 `obf!` 编译期加密，发布包二进制中不含明文域名。
fn default_server() -> String {
    match option_env!("PRISM_LICENSE_URL") {
        Some(v) => v.to_string(),
        None => crate::obf!("https://prism.sarl"),
    }
}

/// 新协议要求的请求来源标识头
const REQUEST_SOURCE: &str = "prism-app";

// ---------------- 对外类型 ----------------

/// 授权状态快照（前端 gating 直接消费；字段名 camelCase）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementStatus {
    /// inactive | active | offline | expired | revoked
    pub status: String,
    /// lifetime | subscription
    pub kind: Option<String>,
    pub expires_at: Option<i64>,
    /// code | apple | google
    pub source: Option<String>,
    pub last_verified_at: i64,
    /// 服务端方案：free | pro | team（与 /api/license/status 响应一致）
    pub plan: Option<String>,
    /// 授权席位上限（服务端返回时透传）
    pub max_seats: Option<u32>,
    /// 已用席位数（服务端返回时透传）
    pub used_seats: Option<u32>,
    /// 服务端允许订阅云端同步（Pro/买断且未被管控）；
    /// 旧版缓存缺失该字段时默认 false（每日同步后自动修正）
    #[serde(default)]
    pub sync_available: bool,
    /// 【APP48】Alpha 内测授权标记：true 时 UI 显示「Alpha 内测版 · 到期时间」，
    /// 按 Pro 能力放行但强制关闭云端链接同步；正式授权恒为 false
    #[serde(default)]
    pub alpha: bool,
}

impl EntitlementStatus {
    pub fn inactive() -> Self {
        Self {
            status: "inactive".into(),
            kind: None,
            expires_at: None,
            source: None,
            last_verified_at: 0,
            plan: None,
            max_seats: None,
            used_seats: None,
            sync_available: false,
            alpha: false,
        }
    }

    /// 是否可使用 Pro：仅服务端联网校验有效时解锁。
    /// offline（断网）/ expired / revoked / inactive 一律锁定。
    pub fn is_unlocked(&self) -> bool {
        self.status == "active"
    }
}

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 当前 Unix 秒（供 state / 巡检协程复用）
pub fn now_unix() -> i64 {
    now_secs()
}

/// 系统时间回拨容忍阈值（秒）：超过 3 分钟视为人为改时间作弊
pub const CLOCK_ROLLBACK_TOLERANCE: i64 = 180;

/// 统一到期判定：买断版（plan=team）永久有效；其余存在 expires_at 时，
/// 只要 `now >= expires_at` 即视为已过期（与是否联网、当天是否已校验无关）。
pub fn is_expired(ent: &EntitlementStatus, now: i64) -> bool {
    if ent.plan.as_deref() == Some("team") {
        return false;
    }
    ent.expires_at.map(|exp| now >= exp).unwrap_or(false)
}

/// 强制到期熔断：已过期则把 status 置为 expired，返回是否发生变更。
/// 每次读取缓存 / 刷新内存授权 / 判断 Pro 可用性前都必须调用。
pub fn enforce_expiry(ent: &mut EntitlementStatus, now: i64) -> bool {
    if ent.status != "expired" && is_expired(ent, now) {
        ent.status = "expired".into();
        true
    } else {
        false
    }
}

/// 本地缓存的运行期规范化：先做时钟回拨检测，再强制到期熔断。
/// 返回 true 表示内容有变更（调用方负责写回 license.dat）。
fn normalize_cache(cache: &mut CachedLicense) -> bool {
    let now = now_secs();
    let mut changed = false;

    if cache.max_seen_unix > 0 && now + CLOCK_ROLLBACK_TOLERANCE < cache.max_seen_unix {
        // 系统时间被调回（例如到期后改回到期前）：离线授权立即失效
        if cache.entitlement.status != "expired" {
            cache.entitlement.status = "expired".into();
            changed = true;
        }
        // 高水位线绝不回退：保留观测到的最大时间
    } else if now > cache.max_seen_unix {
        cache.max_seen_unix = now;
        changed = true;
    }

    // 核心：无论是否联网，到达 expires_at 立即熔断
    if enforce_expiry(&mut cache.entitlement, now) {
        changed = true;
    }
    changed
}

/// 当前 UTC 日期（YYYY-MM-DD），用于「每天首次启动同步」节流。
/// 同步节流以 UTC 日期为准（与服务器时间基准一致，不受设备本地时区影响）。
fn today_utc() -> String {
    let days = now_secs().div_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Howard Hinnant 的 civil_from_days 算法：距 1970-01-01 的天数 → 公历日期
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------- 设备标识 ----------------

/// 读取/首次生成设备 ID（每安装实例唯一，落盘 device.json）。
///
/// APP-7 任务2.1 核心规则（必须严格遵守，否则所有老用户会被解绑）：
/// - **向后兼容铁律**：如果 device.json 已存在且含 `id` 字段，
///   **无论它是旧版 UUID v4 还是新版 SHA-256 硬件指纹**，直接返回；
///   绝不重新生成——老用户在服务端 devices 表里绑定的就是这枚 UUID，
///   切 SHA-256 会让所有老用户突然 device_bound=false 被解绑。
/// - **首次安装（device.json 不存在）**：按目标平台采集硬件指纹并
///   计算 SHA-256 64 位小写 hex（见各平台 hardware_fingerprint 实现）。
/// - **全 APP 统一铁律**：activate / check / heartbeat / 订阅同步 /
///   设置页「设备 ID」展示，必须 100% 调用同一个 `device_id(data_dir)`。
///   任何绕过本函数直接生成 UUID 的路径都是 bug。
pub fn device_id(data_dir: &Path) -> Result<String> {
    let path = data_dir.join("device.json");
    if let Ok(raw) = std::fs::read_to_string(&path)
        && let Ok(v) = serde_json::from_str::<Value>(&raw)
        && let Some(id) = v.get("id").and_then(|i| i.as_str())
        && !id.trim().is_empty()
    {
        return Ok(id.to_string());
    }

    let fp = hardware_fingerprint();
    let hex = hex_lower(&Sha256::digest(fp.as_bytes()));
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({ "id": hex, "fingerprint_fp": fp }))?,
    )?;
    Ok(hex)
}

/// 跨进程唯一安装 ID（36 字符标准 UUID v4）——首次启动时生成并落盘
/// data_dir/install_id.txt，后续直接读取。与 device_id 的区别：
/// device_id 绑定硬件（卸载重装同机一致），install_id 绑定当前安装
/// 实例（卸载即消失）。服务端用它做「同设备多 App 实例」去重。
pub fn get_or_create_install_id(data_dir: &Path) -> Result<String> {
    let path = data_dir.join("install_id.txt");
    if let Ok(raw) = std::fs::read_to_string(&path)
        && let Ok(id) = uuid::Uuid::parse_str(raw.trim())
    {
        return Ok(id.to_string());
    }
    let fresh = uuid::Uuid::new_v4().to_string();
    std::fs::write(&path, fresh.as_bytes())?;
    Ok(fresh)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 令牌 licenseRef = sha256(license_key.trim()) 前 8 字节的 16 位小写 hex。
/// 哈希输入必须与请求体 `license_key` 完全一致：只允许 trim()，
/// 严禁任何大小写转换（该字段用于确认令牌对应的正是用户输入的那个 Key）。
fn license_ref(key: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.trim().as_bytes());
    hex_lower(&h.finalize()[..8])
}

/// 平台硬件指纹原始串（送入 SHA-256 算 device_id）。
/// 不同平台用各自权威系统标识：iOS identifierForVendor + hostname、
/// Android ANDROID_ID + Build.MODEL、macOS IOPlatformUUID、Windows MachineGuid、
/// Linux machine-id。指纹变化 → SHA-256 变化 → 视为新设备，合理。
fn hardware_fingerprint() -> String {
    #[cfg(target_os = "ios")]
    {
        // iOS 端硬件指纹由 Swift @_cdecl prism_ios_get_device_id 直接返回
        // （Keychain 读取 identifierForVendor + hostname 的 SHA-256，
        // 且 kSecAttrSynchronizable = false 绝不 iCloud 同步）。
        // 这里直接返回 Swift 侧已经算好的 hex 值——它本身就是 64 位 hex，
        // 绕过再算一次 SHA-256（license::device_id 会再算一次；我们让
        // hardware_fingerprint 返回已经是 hex 的值，再 SHA-256 也能得到
        // 稳定值；更简单的方案是直接让 iOS 的 device_id 用 Swift 值）。
        // 但为了统一全平台 device_id 的「硬件指纹 → SHA-256 hex」语义，
        // 这里返回 Swift 值作为硬件指纹串即可。
        if let Some(swift_hex) = crate::platform::ios::get_device_id() {
            return swift_hex;
        }
        return "ios-fallback-".into();
    }
    #[cfg(target_os = "android")]
    {
        // Android 设备标识（Settings.Secure.ANDROID_ID + Model）
        return "android-fallback-".into();
    }
    #[cfg(target_os = "macos")]
    {
        let uuid = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find_map(|l| {
                        if l.contains("IOPlatformUUID") {
                            l.split('"').nth(3).map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
            })
            .unwrap_or_else(|| "macos-unknown-uuid".into());
        let host = hostname_fallback();
        return format!("macos|{uuid}|{host}");
    }
    #[cfg(target_os = "windows")]
    {
        // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
        let guid = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find_map(|l| {
                        let mut p = l.split_whitespace();
                        let _ = p.next()?; // "MachineGuid"
                        let _ = p.next()?; // "REG_SZ"
                        Some(p.collect::<Vec<_>>().join(" "))
                    })
            })
            .unwrap_or_else(|| "windows-unknown".into());
        let host = hostname_fallback();
        return format!("windows|{guid}|{host}");
    }
    #[cfg(target_os = "linux")]
    {
        let machine_id = std::fs::read_to_string("/etc/machine-id")
            .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "linux-unknown".into());
        let host = hostname_fallback();
        return format!("linux|{machine_id}|{host}");
    }
    #[cfg(not(any(
        target_os = "ios",
        target_os = "android",
        target_os = "macos",
        target_os = "windows",
        target_os = "linux"
    )))]
    {
        hostname_fallback()
    }
}

/// 主机名兜底（仅 Windows/Linux 及未知平台使用；iOS/Android/macOS 走各自分支）
#[allow(dead_code)]
fn hostname_fallback() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("USERDOMAIN"))
        .unwrap_or_else(|_| "unknown-host".into())
}

/// 设备名：主机名优先，缺失时用固定值（activate 协议要求 device_name 字段）
fn device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Prism Client".into())
}

// ---------------- 本地加密缓存 ----------------

/// 缓存明文结构（整体加密后落盘）
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedLicense {
    license: String,
    /// 激活时绑定的邮箱（同步/查询凭据对）
    #[serde(default)]
    email: String,
    /// 最近一次与服务器同步成功的日期（UTC YYYY-MM-DD）
    #[serde(default)]
    synced_on: String,
    /// 运行期观测到的最大系统时间（Unix 秒）：防时钟回拨作弊的高水位线。
    /// 旧版缓存缺失时默认 0，首次读取自动补写为当前时间。
    #[serde(default)]
    max_seen_unix: i64,
    entitlement: EntitlementStatus,
}

/// 旧版明文缓存（license_cache.json），仅用于一次性迁移
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyCache {
    license: String,
    entitlement: EntitlementStatus,
}

/// 加密容器魔数 + 版本（换密钥/格式时递增）
const CACHE_MAGIC: &[u8; 6] = b"PRLIC1";
/// GCM nonce 长度
const NONCE_LEN: usize = 12;

fn cache_path(data_dir: &Path) -> PathBuf {
    data_dir.join(crate::obf!("license.dat"))
}

fn legacy_cache_path(data_dir: &Path) -> PathBuf {
    data_dir.join("license_cache.json")
}

/// 缓存加密密钥：SHA-256(固定盐 || 设备 ID)。
/// 绑定本机设备标识——文件被拷到其他机器/环境无法解密。
fn cache_key(data_dir: &Path) -> [u8; 32] {
    let device = device_id(data_dir).unwrap_or_else(|_| "prism-unknown-device".into());
    let digest = Sha256::digest(format!("prism-license-v1:{device}").as_bytes());
    digest.into()
}

/// AES-256-GCM 加密：输出 PRLIC1 || nonce(12B) || ciphertext(+tag)
fn encrypt_cache(key: &[u8; 32], cache: &CachedLicense) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("license cache key error: {e}"))?;
    // uuid v4 内部使用系统 CSPRNG：取 16 字节随机数截 12 字节作 nonce
    let uuid_bytes = *uuid::Uuid::new_v4().as_bytes();
    let nonce = Nonce::from_slice(&uuid_bytes[..NONCE_LEN]);
    let ciphertext = cipher
        .encrypt(nonce, serde_json::to_vec(cache)?.as_slice())
        .map_err(|e| anyhow::anyhow!("license cache encrypt error: {e}"))?;

    let mut out = Vec::with_capacity(CACHE_MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(CACHE_MAGIC);
    out.extend_from_slice(&uuid_bytes[..NONCE_LEN]);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// 解密并反序列化；密文损坏/被篡改/密钥不匹配均返回 None
fn decrypt_cache(key: &[u8; 32], raw: &[u8]) -> Option<CachedLicense> {
    if raw.len() < CACHE_MAGIC.len() + NONCE_LEN + 16 {
        return None;
    }
    if &raw[..CACHE_MAGIC.len()] != CACHE_MAGIC {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::from_slice(&raw[CACHE_MAGIC.len()..CACHE_MAGIC.len() + NONCE_LEN]);
    let plaintext = cipher
        .decrypt(nonce, &raw[CACHE_MAGIC.len() + NONCE_LEN..])
        .ok()?;
    serde_json::from_slice(&plaintext).ok()
}

fn load_cache(data_dir: &Path) -> Option<CachedLicense> {
    let key = cache_key(data_dir);

    if let Ok(raw) = std::fs::read(cache_path(data_dir))
        && let Some(mut cache) = decrypt_cache(&key, &raw)
    {
        // 每次读取都执行「时钟回拨检测 + 到期熔断」，变更即时写回
        if normalize_cache(&mut cache) {
            let _ = save_cache(data_dir, &cache);
        }
        return Some(cache);
    }

    // 旧版明文缓存一次性迁移为加密格式（随后删除明文文件）
    if let Ok(text) = std::fs::read_to_string(legacy_cache_path(data_dir))
        && let Ok(legacy) = serde_json::from_str::<LegacyCache>(&text)
    {
        let mut migrated = CachedLicense {
            license: legacy.license,
            email: String::new(),
            synced_on: String::new(),
            max_seen_unix: 0,
            entitlement: legacy.entitlement,
        };
        normalize_cache(&mut migrated);
        if save_cache(data_dir, &migrated).is_ok() {
            std::fs::remove_file(legacy_cache_path(data_dir)).ok();
        }
        return Some(migrated);
    }

    None
}

fn save_cache(data_dir: &Path, cache: &CachedLicense) -> Result<()> {
    let key = cache_key(data_dir);
    super::store::atomic_write(&cache_path(data_dir), &encrypt_cache(&key, cache)?)?;
    Ok(())
}

pub fn clear_cache(data_dir: &Path) {
    std::fs::remove_file(cache_path(data_dir)).ok();
    std::fs::remove_file(legacy_cache_path(data_dir)).ok();
}

/// 启动期从缓存恢复（不联网；当天有效性以后台每日同步为准）。
/// 旧版缓存可能存有 grace（离线宽限）/offline 状态：统一按当前策略映射——
/// 未过期视为 active（离线可用），已过期则锁定为 expired。
pub fn cached_entitlement(data_dir: &Path) -> EntitlementStatus {
    cached_entitlement_opt(data_dir).unwrap_or_else(EntitlementStatus::inactive)
}

/// 同 cached_entitlement，但本地无缓存（未激活）时返回 None，
/// 供后台周期任务区分「无缓存」与「缓存状态」，避免无意义的状态广播。
pub fn cached_entitlement_opt(data_dir: &Path) -> Option<EntitlementStatus> {
    load_cache(data_dir).map(|mut c| {
        if matches!(c.entitlement.status.as_str(), "grace" | "offline") {
            c.entitlement = offline_status(&c.entitlement);
        }
        c.entitlement
    })
}

/// 到期熔断落盘：把本地缓存中的授权状态强制写为 expired。
/// 无缓存（未激活）时返回 None；返回 Some 供调用方同步内存态。
pub fn mark_expired(data_dir: &Path) -> Option<EntitlementStatus> {
    let mut cache = load_cache(data_dir)?;
    if cache.entitlement.status != "expired" {
        cache.entitlement.status = "expired".into();
        save_cache(data_dir, &cache).ok();
    }
    Some(cache.entitlement)
}

// ---------------- 服务端通信 ----------------

fn server_base(_settings: &UserSettings) -> String {
    default_server().trim_end_matches('/').to_string()
}

/// 授权/同步 API 共用基地址（订阅云端同步与授权同域）
pub(crate) fn api_base(_settings: &UserSettings) -> String {
    default_server().trim_end_matches('/').to_string()
}

/// 【APP23 任务2.1】错误脱敏：reqwest 的 `Error::to_string()` 固定携带
/// `error sending request for url (https://.../api/license/activate)`，
/// 断网/离线激活时若直接透传，会把后端完整验证接口地址暴露到界面上。
/// 本函数把所有网络层错误统一转为用户可读文案，并强制剥离任何
/// `http(s)://` URL 以及 `for url (...)` 片段。
/// 授权、云端同步、后台巡检全部必须经过本函数。
pub fn sanitize_license_error(raw: &str) -> String {
    let lower = raw.to_lowercase();
    if lower.contains("error sending request")
        || lower.contains("connection refused")
        || lower.contains("network is unreachable")
        || lower.contains("failed to lookup address")
        || lower.contains("dns error")
        || lower.contains("no route to host")
        || lower.contains("software caused connection abort")
    {
        return "网络连接失败，请检查网络设置后重试".to_string();
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return "连接服务器超时，请检查网络后重试".to_string();
    }
    // 强制剥离任何 http:// 或 https:// URL 以及 "for url (...)" 片段，
    // 严禁暴露任何后端接口地址
    let mut cleaned = raw.to_string();
    while let Some(start) = cleaned.find("http://").or_else(|| cleaned.find("https://")) {
        let rest = &cleaned[start..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == ')' || c == '"' || c == '\'' || c == '>')
            .unwrap_or(rest.len());
        cleaned.replace_range(start..start + end, "");
    }
    cleaned = cleaned
        .replace("for url ()", "")
        .replace("for url ( )", "")
        .trim()
        .to_string();
    if cleaned.is_empty() {
        "请求失败，请检查网络连接后重试".to_string()
    } else {
        cleaned
    }
}

pub(crate) fn http_builder() -> Result<reqwest::ClientBuilder> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        // 连接阶段短超时：黑洞地址快速失败，尽快进入 IPv4 重试
        .connect_timeout(std::time::Duration::from_secs(8))
        // 不走系统代理：内核运行时系统代理指向本机，走代理会自回环；
        // 授权服务为公网 HTTPS，直连即可
        .no_proxy())
}

/// 授权服务固定域名（编译期 obf，运行时判断隐身白名单时使用明文常量）
pub const PRISM_HOST: &str = "prism.sarl";

/// 本地混合代理端口（内核运行中才非 0）：授权请求优先借道代理穿透。
/// 【APP48 任务3】由 commands 在内核启动/停止时写入，避免授权层反向依赖 AppState。
static LOCAL_MIXED_PORT: AtomicU16 = AtomicU16::new(0);

/// prism.sarl 经 DoH 解析出的真实公网 IP 集合（隐身白名单，任务 4 复用）
static STEALTH_IPS: LazyLock<RwLock<HashSet<String>>> =
    LazyLock::new(|| RwLock::new(HashSet::new()));

/// 内核启动成功后登记本地混合代理端口（0 = 未运行/不可用）
pub fn set_local_mixed_port(port: u16) {
    LOCAL_MIXED_PORT.store(port, Ordering::Relaxed);
}

/// 内核停止时清空端口，确保后续授权请求不再走已失效的本地代理
pub fn clear_local_mixed_port() {
    LOCAL_MIXED_PORT.store(0, Ordering::Relaxed);
}

fn local_mixed_port() -> Option<u16> {
    let p = LOCAL_MIXED_PORT.load(Ordering::Relaxed);
    (p > 0).then_some(p)
}

/// 记住 prism.sarl 解析出的 IP（任务 4 隐身过滤 + 后续直接命中）
pub fn remember_stealth_ip(ip: &str) {
    if let Ok(addr) = ip.trim().parse::<IpAddr>() {
        STEALTH_IPS
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(addr.to_string());
    }
}

/// 当前隐身 IP 快照（测试与前端过滤复用）
pub fn stealth_ips_snapshot() -> Vec<String> {
    STEALTH_IPS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect()
}

/// 【APP48 任务4】隐身判断：命中 prism.sarl 域名或其 DoH 解析出的任意 IP。
/// 连接采集 / 分析统计 / 规则选择器在返回前端前必须用它过滤。
pub fn is_stealth_protected_host_or_ip(val: &str) -> bool {
    let s = val.trim().to_ascii_lowercase();
    if s.is_empty() {
        return false;
    }
    if s.contains(PRISM_HOST) {
        return true;
    }
    let ips = STEALTH_IPS.read().unwrap_or_else(|e| e.into_inner());
    ips.iter().any(|ip| s == *ip || s.contains(ip.as_str()))
}

/// 从任意 DNS 响应 JSON 中递归提取 IPv4 字面量（兼容 Cloudflare DNS-JSON
/// `Answer[].data` 与 AdGuard/ AliDNS `data[]` 两种结构）。
fn collect_ipv4_from_json(v: &Value, out: &mut Vec<IpAddr>) {
    match v {
        Value::String(s) => {
            if let Ok(addr) = s.trim().parse::<IpAddr>()
                && addr.is_ipv4()
            {
                out.push(addr);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_ipv4_from_json(item, out);
            }
        }
        Value::Object(map) => {
            // DNS-JSON 的 Answer[].type == 1 才是 A 记录；其余字段递归即可
            for item in map.values() {
                collect_ipv4_from_json(item, out);
            }
        }
        _ => {}
    }
}

/// 【APP48 任务3 通道2】通过加密 DoH（阿里 / 腾讯 / Cloudflare）解析
/// prism.sarl 的真实公网 IP。客户端用 `.resolve(host, IP)` 固定解析结果，
/// 既能绕过运营商 DNS 污染，又不破坏 HTTPS 证书链（SNI 仍为 DoH 主机名）。
pub async fn doh_resolve_prism_ips() -> Vec<IpAddr> {
    let ips = doh_resolve_ips(PRISM_HOST).await;
    for addr in &ips {
        remember_stealth_ip(&addr.to_string());
    }
    ips
}

/// 【APP49 任务2.1 通道B】通用 DoH 解析：对任意主机名经阿里/腾讯/
/// Cloudflare 三家 DoH 取真实 IPv4（供订阅下载等场景绕过 DNS 污染）。
pub async fn doh_resolve_ips(target_host: &str) -> Vec<IpAddr> {
    // (DoH 主机名, 其公网 IP, 路径)
    // 【APP59 任务3.1】四家 DoH（阿里 / 腾讯 / Google / Cloudflare）轮询取源，
    // 全部为公共 DoH 端点，绝不依赖任何特定 CDN 厂商的响应头做校验
    const PROVIDERS: [(&str, &str, &str); 4] = [
        ("dns.alidns.com", "223.5.5.5", "/resolve"),
        ("doh.pub", "119.29.29.29", "/dns-query"),
        ("dns.google", "8.8.8.8", "/resolve"),
        ("cloudflare-dns.com", "1.1.1.1", "/dns-query"),
    ];
    let mut found: Vec<IpAddr> = Vec::new();
    for (host, ip, path) in PROVIDERS {
        let Ok(addr) = ip.parse::<IpAddr>() else {
            continue;
        };
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .resolve(host, SocketAddr::new(addr, 443))
            .build()
        {
            Ok(c) => c,
            Err(_) => continue,
        };
        let url = format!("https://{host}{path}?name={target_host}&type=A");
        let resp = client
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
            .await;
        let Ok(resp) = resp else { continue };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(body) = resp.json::<Value>().await else {
            continue;
        };
        let mut ips = Vec::new();
        collect_ipv4_from_json(&body, &mut ips);
        for addr in ips {
            if !found.contains(&addr) {
                found.push(addr);
            }
        }
        if !found.is_empty() {
            break;
        }
    }
    found
}

/// 【APP48 任务3】四级容灾授权请求引擎：
/// 1. 本地代理隧道（内核运行中 127.0.0.1:{mixed_port}）穿透网络阻断；
/// 2. DoH 解析真实 IP 后 `resolve` 固定解析直连（免疫 DNS 污染）；
/// 3. 系统默认网络栈直连（含 IPv4 源强制重试）；
/// 4. 全部失败由上层 `offline_status` 保留本地有效授权（不掉 Pro）。
pub(crate) async fn send_with_v4_fallback(
    make: impl Fn(&reqwest::Client) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    let mut last: Option<String> = None;

    // ---- 通道 1：本地代理隧道 ----
    if let Some(port) = local_mixed_port()
        && let Ok(proxy) = reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
    {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .no_proxy()
            .proxy(proxy)
            .build();
        if let Ok(client) = client {
            match make(&client).send().await {
                Ok(resp) => {
                    tracing::info!("license request via local proxy 127.0.0.1:{port} ok");
                    return Ok(resp);
                }
                Err(e) => {
                    let clean = sanitize_license_error(&e.to_string());
                    tracing::warn!("license via local proxy failed: {clean}");
                    last = Some(clean);
                }
            }
        }
    }

    // ---- 通道 2：DoH 解析真实 IP + 固定解析直连 ----
    let resolved = doh_resolve_prism_ips().await;
    for addr in resolved {
        let mut builder = http_builder()?;
        builder = builder
            .timeout(Duration::from_secs(5))
            .resolve(PRISM_HOST, SocketAddr::new(addr, 443));
        let Ok(client) = builder.build() else {
            continue;
        };
        match make(&client).send().await {
            Ok(resp) => {
                tracing::info!("license request via DoH-pinned {addr} ok");
                return Ok(resp);
            }
            Err(e) => {
                let clean = sanitize_license_error(&e.to_string());
                tracing::warn!("license via DoH-pinned {addr} failed: {clean}");
                last = Some(clean);
            }
        }
    }

    // ---- 通道 3：标准直连（IPv4 源强制重试） ----
    for force_v4 in [false, true] {
        let mut b = http_builder()?;
        if force_v4 {
            b = b.local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        }
        match make(&b.build()?).send().await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                // 【APP23 任务2.1】日志与界面均只写脱敏文案，严禁打印
                // "error sending request for url (https://...)" 原始报错
                let clean = sanitize_license_error(&e.to_string());
                tracing::warn!("license request (force_v4={force_v4}) failed: {clean}");
                last = Some(clean);
            }
        }
    }
    bail!("{}", last.unwrap_or_else(|| "网络连接失败，请检查网络设置后重试".to_string()))
}

/// POST JSON 带兜底重试
pub(crate) async fn post_with_fallback(url: &str, body: &Value) -> Result<reqwest::Response> {
    send_with_v4_fallback(|c| {
        c.post(url)
            .header("X-Request-Source", REQUEST_SOURCE)
            .json(body)
    })
    .await
}

/// GET 带兜底重试（query: license_key）
async fn get_with_fallback(url: &str, license_key: &str) -> Result<reqwest::Response> {
    send_with_v4_fallback(|c| {
        c.get(url)
            .query(&[("license_key", license_key)])
            .header("X-Request-Source", REQUEST_SOURCE)
    })
    .await
}

// ---------------- 协议响应体 ----------------

/// POST /api/license/activate 成功响应（device_id 回显不消费，忽略）
#[derive(Deserialize)]
struct ActivateResponse {
    ok: bool,
    #[serde(default)]
    plan: String,
    #[serde(default)]
    max_seats: Option<u32>,
    /// 到期时间（ISO8601）：试用 = 到期时间；Pro = 当前计费周期结束；买断 = null
    #[serde(default)]
    expires_at: Option<String>,
    /// Pro/买断且未被管控 → 允许订阅云端同步
    #[serde(default)]
    sync_available: bool,
    /// 【APP48】Alpha 内测授权（plan 仍为 pro，但 UI 显示「内测版」且无云端同步）
    #[serde(default)]
    alpha: bool,
    /// 【110.txt】服务端签名令牌；服务端切换到新协议后返回，旧返回体兼容保留
    #[serde(default)]
    token: Option<crate::core::ed25519_verify::SignedEnvelope>,
}

/// GET /api/license/status 响应
#[derive(Deserialize)]
struct StatusResponse {
    valid: bool,
    #[serde(default)]
    plan: String,
    #[serde(default)]
    status: String,
    expires_at: Option<String>,
    #[serde(default)]
    max_seats: Option<u32>,
    #[serde(default)]
    used_seats: Option<u32>,
    #[serde(default)]
    sync_available: bool,
    /// 【APP48】Alpha 内测授权标记（/license/status 同步返回）
    #[serde(default)]
    alpha: bool,
    /// 【110.txt】服务端签名信封；缺失表示服务端仍在旧协议，走回退但功能锁降级
    #[serde(default)]
    signed: Option<serde_json::Value>,
}

/// 状态查询失败分类：决定走「清除缓存」还是「离线锁定」
#[derive(Debug)]
enum StatusError {
    /// 429：携带服务端要求的重试等待秒数（透传给前端）
    RateLimited(i64),
    /// 服务端明确判定凭证无效（4xx）：应清除本地缓存
    Rejected(u16, String),
    /// 瞬态故障（网络不可达、5xx、响应解析失败）：可走离线宽限
    Transient(String),
}

/// 提取服务端错误体的官方文案与机器可读码，组装为
/// 「{官方 message}（错误码 {error} / HTTP {status}）」格式——
/// 用户可拿错误码到官网帮助中心查询具体原因。
/// 兼容 {message, error:"code"} 与 {error:{message}} 两种错误体。
async fn error_message(resp: reqwest::Response) -> String {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);

    let code = parsed.get("error").and_then(|e| e.as_str());
    let message = parsed
        .get("message")
        .and_then(|m| m.as_str())
        .or_else(|| {
            parsed
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
        })
        .filter(|m| !m.is_empty())
        .unwrap_or(text.trim());

    match (code, message.is_empty()) {
        (Some(c), false) => format!("{message}（错误码 {c} / HTTP {status}）"),
        (Some(c), true) => format!("授权服务返回错误（错误码 {c} / HTTP {status}）"),
        (None, false) => format!("{message}（HTTP {status}）"),
        (None, true) => format!("授权服务返回错误（HTTP {status}）"),
    }
}

/// 从非 200 响应提取 (机器错误码, 服务端具体描述)（APK-3 任务2 / APP6 任务4）。
/// 机器码优先取 JSON 的 "error" 字符串字段；解析失败按 HTTP 状态码映射：
/// 400→invalid_input、403→activation_failed、409→seat_limit_reached、
/// 429→activation_throttled、5xx→server_error。
/// 描述依次尝试 JSON 的 message / reason / detail / error 字段，
/// 用于「激活未通过 (HTTP xxx): {服务端原文}」的精准透传。
async fn extract_error_detail(http: u16, resp: reqwest::Response) -> (String, String) {
    let text = resp.text().await.unwrap_or_default();
    let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let machine = parsed
        .get("error")
        .and_then(|e| e.as_str())
        .filter(|c| !c.is_empty())
        .map(String::from)
        .unwrap_or_else(|| {
            match http {
                400 => "invalid_input",
                403 => "activation_failed",
                409 => "seat_limit_reached",
                429 => "activation_throttled",
                s if s >= 500 => "server_error",
                _ => "activation_failed",
            }
            .to_string()
        });
    let server_msg = ["message", "reason", "detail"]
        .iter()
        .find_map(|k| {
            parsed
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
        .or_else(|| {
            // 兼容 {error:{message}} 结构
            parsed
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
        .unwrap_or_default();
    (machine, server_msg)
}

/// 【APP6 任务4】把服务端机器码 / HTTP 状态映射为前端精准中文文案的
/// 标准错误码（前端 LICENSE_ERROR_MAP 1:1 渲染）。返回 None 表示
/// 无法归入已知类别——调用方应透传服务端原文（err_raw）。
fn map_activation_error(http: u16, machine: &str, server_msg: &str) -> Option<&'static str> {
    // 综合机器码与服务端原文关键词做归类（大小写不敏感）
    let hay = format!("{machine} {server_msg}").to_lowercase();
    let hit = |words: &[&str]| words.iter().any(|w| hay.contains(w));
    if hit(&["not_found", "invalid_key", "invalid_license", "no_such"]) || http == 404 {
        Some("invalid_key")
    } else if hit(&["alpha_device_bound", "alpha_unbind", "内测授权已绑定"]) {
        // 【APP48】内测 Key 只能绑 1 台设备；提示联系管理员解绑，绝不重复重试
        Some("alpha_device_bound")
    } else if hit(&["email", "mismatch", "account"]) {
        Some("email_mismatch")
    } else if hit(&["rate", "too_many", "throttl"]) {
        // rate/too_many 优先于 seat 判定，避免 "rate limit" 误归为席位限制
        Some("activation_throttled")
    } else if hit(&["seat", "limit", "max_devices", "full"]) || http == 409 {
        Some("seat_limit_reached")
    } else if hit(&["expired"]) {
        Some("license_expired")
    } else if hit(&["blocked", "disabled", "banned", "revoked", "suspended"]) {
        Some("license_blocked")
    } else {
        None
    }
}

/// 从 429 响应体提取 retry_after（秒）；缺失/非法时回退 30
async fn retry_after_secs(resp: reqwest::Response) -> i64 {
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    body.get("retry_after")
        .and_then(|v| v.as_i64())
        .unwrap_or(30)
        .max(1)
}

/// GET /api/license/status：200 返回状态体，其余按 StatusError 分类
async fn fetch_status(base: &str, license_key: &str, data_dir: &Path) -> std::result::Result<StatusResponse, StatusError> {
    let resp = get_with_fallback(
        &format!("{base}{}", crate::obf!("/api/license/status")),
        license_key,
    )
    .await
    .map_err(|e| StatusError::Transient(sanitize_license_error(&e.to_string())))?;
    let code = resp.status().as_u16();
    if code == 429 {
        return Err(StatusError::RateLimited(retry_after_secs(resp).await));
    }
    if code >= 500 {
        return Err(StatusError::Transient(format!("HTTP {code}")));
    }
    if !resp.status().is_success() {
        return Err(StatusError::Rejected(code, error_message(resp).await));
    }
    let status: StatusResponse = resp
        .json()
        .await
        .map_err(|e| StatusError::Transient(sanitize_license_error(&e.to_string())))?;
    // 【110.txt】GET /api/license/status 响应验签
    if let Some(signed) = status.signed.as_ref() {
        let env: crate::core::ed25519_verify::SignedEnvelope = serde_json::from_value(signed.clone())
            .map_err(|e| StatusError::Transient(format!("signed envelope json: {e}")))?;
        let device_id_str = device_id(data_dir)
            .map_err(|e| StatusError::Transient(format!("device_id: {e}")))?;
        let now = crate::core::ed25519_verify::unix_now();
        crate::core::ed25519_verify::verify(
            &env,
            &device_id_str,
            "",
            Some(&license_ref(license_key)),
            Some("status"),
            now,
        )
        .map_err(|e| StatusError::Rejected(401, format!("signature_invalid: {e}")))?;
    } else {
        crate::core::logger::warn(
            crate::core::logger::MOD_PRO,
            "GET /api/license/status 响应缺少 signed 信封",
        );
    }
    Ok(status)
}

// ---------------- 状态映射 ----------------

/// 将新协议响应映射为本地授权状态（沿用现有枚举语义，不新增枚举值）。
///
/// 调用方均已在「服务端认定凭证有效」的前提下调用本函数
/// （activate 已校验 `ok=true`；status 已校验 `valid=true`）：
/// - `free` 为合法试用版方案（1 席位，带 expires_at），与 `pro`（订阅）/
///   `team`（买断）同为「有效授权」，一律映射 active —— 严禁把 free 判为 inactive；
/// - 服务端 status=expired 或 expires_at 已过 → expired；
/// - plan 为 team → lifetime（永久），其余 → subscription。
fn map_entitlement(
    plan: &str,
    server_status: &str,
    expires_at: Option<i64>,
    max_seats: Option<u32>,
    used_seats: Option<u32>,
    sync_available: bool,
    alpha: bool,
) -> EntitlementStatus {
    let expired =
        server_status == "expired" || expires_at.map(|exp| exp <= now_secs()).unwrap_or(false);
    let status = if expired { "expired" } else { "active" };
    EntitlementStatus {
        status: status.into(),
        // 【APP48】Alpha 内测授权虽是 plan=pro，但绝不能被渲染成「买断/永久」；
        // 统一按 subscription + 到期时间展示。
        kind: Some(if plan == "team" && !alpha { "lifetime" } else { "subscription" }.into()),
        expires_at,
        source: Some("code".into()),
        last_verified_at: now_secs(),
        plan: (!plan.is_empty()).then(|| plan.to_string()),
        max_seats,
        used_seats,
        // Alpha 内测授权不包含云端链接同步（服务端亦返回 403 sync_unavailable_for_alpha）
        sync_available: sync_available && !alpha,
        alpha,
    }
}

/// 解析服务端返回的 ISO8601/RFC3339 时间戳为 Unix 秒。
/// 支持 "YYYY-MM-DDTHH:MM:SS(.fff)?(Z|±HH[:MM])?"（空格分隔日期也兼容）；失败返回 None。
/// 公开（pub）供 app_control.rs 运行时授权感知直接调用。
pub fn parse_expires_at(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once(['T', 't', ' '])?;
    let mut dp = date.split('-');
    let year: i64 = dp.next()?.parse().ok()?;
    let month: i64 = dp.next()?.parse().ok()?;
    let day: i64 = dp.next()?.parse().ok()?;

    // 拆出时间与时区偏移
    let (time, offset_secs): (&str, i64) = if let Some(z) = rest.find(['Z', 'z']) {
        (&rest[..z], 0)
    } else if let Some(p) = rest.find(['+', '-']) {
        let sign: i64 = if rest.as_bytes()[p] == b'+' { 1 } else { -1 };
        let mut op = rest[p + 1..].split(':');
        let oh: i64 = op.next().unwrap_or("0").parse().ok()?;
        let om: i64 = op.next().unwrap_or("0").parse().ok()?;
        (&rest[..p], sign * (oh * 3600 + om * 60))
    } else {
        (rest, 0)
    };

    let mut tp = time.split(':');
    let hh: i64 = tp.next()?.parse().ok()?;
    let mm: i64 = tp.next()?.parse().ok()?;
    let ss_raw = tp.next().unwrap_or("0");
    let ss: i64 = ss_raw.split('.').next().unwrap_or("0").parse().ok()?;

    Some(days_from_civil(year, month, day) * 86400 + hh * 3600 + mm * 60 + ss - offset_secs)
}

/// Howard Hinnant 的 days_from_civil 算法：公历日期 → 距 1970-01-01 的天数
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

// ---------------- 业务操作 ----------------

/// 邮箱格式校验（与服务端规则一致）
fn valid_email(e: &str) -> bool {
    let Some((local, domain)) = e.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && e.len() <= 254
}

/// 激活码激活（邮箱+授权码模式：首次激活绑定邮箱，之后必须一致）
pub async fn activate(
    data_dir: &Path,
    settings: &UserSettings,
    code: &str,
    email: &str,
) -> Result<EntitlementStatus> {
    // 输入预处理：Key 去首尾空格并统一大写，邮箱去首尾空格并统一小写
    // （与服务端 Key+邮箱联合校验的口径一致，避免大小写/空格导致 403）。
    let email = email.trim().to_lowercase();
    let license_key = code.trim().to_uppercase();

    // 本地必填校验：License Key 与注册邮箱缺一不可。绝不在缺项时向服务端发请求——
    // 服务端对「邮箱不匹配」的失败同样计数，连续 3 次将触发 60 秒指数级临时锁定。
    if license_key.is_empty() || email.is_empty() || !email.contains('@') {
        bail!("请输入完整的 License Key 和注册账号邮箱（两者均为必填项）");
    }
    if !valid_email(&email) {
        bail!("请输入有效的邮箱地址（格式如 you@example.com）");
    }
    let base = server_base(settings);
    let device_id_str = device_id(data_dir)?;

    // 【APP48 任务6】Alpha 内测 Key（A- 开头）无需额外字段：
    // 依据 api-license-activate.md，正式 Key 与内测 Key 共用同一套接口，
    // 客户端不区分类型，直接放入 license_key，按响应中的 alpha 做 UI 区分。
    let body = serde_json::json!({
        "license_key": license_key.clone(),
        "email": email,
        "device_id": device_id_str,
        "device_name": device_name(),
    });
    let resp = post_with_fallback(
        &format!("{base}{}", crate::obf!("/api/license/activate")),
        &body,
    )
    .await?;

    // 429 频率限制：把 retry_after 与标准错误码编进错误文本透传给前端。
    // 前端解析约定："rate_limited:{secs}:activation_throttled"，
    // 例如 "rate_limited:30:activation_throttled" 表示 30 秒后可重试。
    if resp.status().as_u16() == 429 {
        let secs = retry_after_secs(resp).await;
        bail!("rate_limited:{secs}:activation_throttled");
    }
    // 非 200：【APP6 任务4】废除笼统报错——提取机器码 + 服务端具体描述，
    // 按精准规则映射中文文案（"err_code:{code}" 前端 1:1 渲染）；
    // 无法归入已知类别时透传服务端原文（"err_raw:{描述}"）。全程写 [Pro] 日志。
    if !resp.status().is_success() {
        let http = resp.status().as_u16();
        let (machine, server_msg) = extract_error_detail(http, resp).await;
        crate::core::logger::warn(
            crate::core::logger::MOD_PRO,
            &format!(
                "激活请求被拒绝：HTTP {http}，错误码 {machine}{}",
                if server_msg.is_empty() { String::new() } else { format!("，服务端描述：{server_msg}") }
            ),
        );
        if let Some(mapped) = map_activation_error(http, &machine, &server_msg) {
            bail!("err_code:{mapped}");
        }
        if !server_msg.is_empty() {
            bail!("err_raw:激活未通过 (HTTP {http}): {server_msg}");
        }
        bail!("err_code:{}", machine);
    }
    let data: ActivateResponse = resp.json().await?;
    if !data.ok {
        bail!("激活失败：服务端未确认（ok=false）");
    }

    // 【110.txt】激活响应签名信封验签（服务端新旧协议兼容：无 token 时记录 warn 继续）
    if let Some(env) = data.token.as_ref() {
        let now = crate::core::ed25519_verify::unix_now();
        match crate::core::ed25519_verify::verify(
            env,
            &device_id_str,
            "",
            Some(&license_ref(&license_key)),
            Some("activation"),
            now,
        ) {
            Ok(_claims) => {}
            Err(e) => {
                crate::core::logger::warn(
                    crate::core::logger::MOD_PRO,
                    &format!("激活响应验签失败：{e}"),
                );
                bail!("err_code:signature_invalid");
            }
        }
    } else {
        crate::core::logger::warn(
            crate::core::logger::MOD_PRO,
            "激活响应缺少签名信封，将继续但服务端需尽快升级到 110.txt 协议",
        );
    }

    // 优先用激活响应自带的 expires_at；缺失时 best-effort 拉一次状态补全
    // （查询失败不影响激活结果，恢复联网后每日同步会修正）
    let mut ent = map_entitlement(
        &data.plan,
        "",
        data.expires_at.as_deref().and_then(parse_expires_at),
        data.max_seats,
        None,
        data.sync_available,
        data.alpha,
    );
    match fetch_status(&base, &license_key, data_dir).await {
        Ok(s) if s.valid => {
            ent = map_entitlement(
                &s.plan,
                &s.status,
                s.expires_at.as_deref().and_then(parse_expires_at),
                s.max_seats,
                s.used_seats,
                s.sync_available,
                s.alpha,
            );
        }
        Ok(_) => {}
        Err(StatusError::RateLimited(secs)) => {
            tracing::warn!("post-activate status query rate limited (retry after {secs}s)");
        }
        Err(e) => tracing::warn!("post-activate status query failed: {e:?}"),
    }

    // 首次激活：授权中心信息（Key、邮箱、有效期）加密落盘并记为当天已同步
    save_cache(
        data_dir,
        &CachedLicense {
            license: license_key.to_string(),
            email,
            synced_on: today_utc(),
            max_seen_unix: now_secs(),
            entitlement: ent.clone(),
        },
    )?;
    Ok(ent)
}

/// 联网校验授权并更新本地加密缓存（成功后记为当天已同步）。
///
/// - `force == false`（App 启动/后台定时器的每日自动同步路径）：同一 UTC 日内
///   已同步且状态非 offline 时短路——只读本地 `license.dat`，不发网络请求；
/// - `force == true`（设置页「立即校验」）：无视当日缓存短路，强制实时请求
///   `GET {server}/api/license/status`，成功后用服务端最新 plan/expires_at/
///   seats/sync_available 与当前时间戳重新加密写入 `license.dat`。
pub async fn verify_remote(
    data_dir: &Path,
    settings: &UserSettings,
    force: bool,
) -> Result<EntitlementStatus> {
    let Some(cache) = load_cache(data_dir) else {
        return Ok(EntitlementStatus::inactive());
    };

    // 每日自动同步路径：当天已同步则只读本地缓存（ipa-8：手动校验走 force=true 不短路）。
    // 短路也必须强制执行到期熔断——当天校验过不代表这一天内不会到期。
    if !force && cache.synced_on == today_utc() && cache.entitlement.status != "offline" {
        let mut ent = cache.entitlement.clone();
        if enforce_expiry(&mut ent, now_secs()) {
            save_cache(
                data_dir,
                &CachedLicense {
                    license: cache.license,
                    email: cache.email,
                    synced_on: cache.synced_on,
                    max_seen_unix: cache.max_seen_unix,
                    entitlement: ent.clone(),
                },
            )?;
        }
        return Ok(ent);
    }

    let base = server_base(settings);

    match fetch_status(&base, &cache.license, data_dir).await {
        Ok(s) => {
            // 服务端明确判定凭证无效（停用/删除）→ 清除缓存
            if !s.valid {
                tracing::warn!("license invalid per server (status={})", s.status);
                clear_cache(data_dir);
                return Ok(EntitlementStatus::inactive());
            }
            let ent = map_entitlement(
                &s.plan,
                &s.status,
                s.expires_at.as_deref().and_then(parse_expires_at),
                s.max_seats,
                s.used_seats,
                s.sync_available,
                s.alpha,
            );
            // 同步成功：授权信息（含有效期）重新加密落盘，并记为当天已同步
            save_cache(
                data_dir,
                &CachedLicense {
                    license: cache.license,
                    email: cache.email,
                    synced_on: today_utc(),
                    max_seen_unix: now_secs(),
                    entitlement: ent.clone(),
                },
            )?;
            Ok(ent)
        }
        Err(StatusError::RateLimited(secs)) => {
            // 429 同样透传给前端（refresh_entitlement 按钮会展示）；
            // 前端解析约定同 activate："rate_limited:N:activation_throttled"
            tracing::warn!("license status rate limited (retry after {secs}s)");
            bail!("rate_limited:{secs}:activation_throttled");
        }
        Err(StatusError::Rejected(code, message)) => {
            tracing::warn!("license rejected by server (HTTP {code}): {message}");
            clear_cache(data_dir);
            Ok(EntitlementStatus::inactive())
        }
        Err(StatusError::Transient(e)) => {
            tracing::warn!("license status unreachable, locking Pro: {e}");
            Ok(offline_status(&cache.entitlement))
        }
    }
}

/// 手动强制立即校验（设置页「立即校验」按钮）：无视当日缓存短路，
/// 实时向服务端发起状态查询并用结果重写本地加密缓存
pub async fn verify_remote_forced(
    data_dir: &Path,
    settings: &UserSettings,
) -> Result<EntitlementStatus> {
    verify_remote(data_dir, settings, true).await
}

/// 每天首次启动时与服务器同步授权；当天内已同步则只读本地加密缓存，不再联网。
/// 返回 Some(状态) 表示需要应用到内存并广播（None = 无需变更）。
///
/// 判定规则：
/// - 本地无缓存（未激活）→ 无需同步
/// - 缓存 synced_on == 今天 且状态非 offline → 当天已同步，只读文件
/// - 否则（跨天 / 上次同步失败留有 offline）→ 联网校验：
///   成功 → 更新缓存并应用新状态；失败 → 应用 offline 锁定（不更新 synced_on，
///   恢复联网后下一轮自动重试）
pub async fn daily_sync(
    data_dir: &Path,
    settings: &UserSettings,
) -> Option<EntitlementStatus> {
    let cache = load_cache(data_dir)?;
    let today = today_utc();

    if cache.synced_on == today && cache.entitlement.status != "offline" {
        return None;
    }

    match verify_remote(data_dir, settings, false).await {
        Ok(next) => Some(next),
        Err(e) => {
            // 429 限流等：保持缓存状态不变，等下一轮重试
            tracing::warn!("daily license sync failed: {e}");
            None
        }
    }
}

/// 断网/服务不可达时的授权状态：按用户策略从本地加密文件读取——
/// 缓存授权仍有效（active/grace 且未过期）则继续可用（status=active）；
/// 缓存有效期已过则锁定为 expired。恢复联网后每日同步自动以服务端结果修正。
fn offline_status(prev: &EntitlementStatus) -> EntitlementStatus {
    let expired = prev
        .expires_at
        .map(|exp| exp <= now_secs())
        .unwrap_or(false);
    let mut next = prev.clone();
    if expired {
        next.status = "expired".into();
    } else if matches!(next.status.as_str(), "grace" | "offline") {
        next.status = "active".into();
    }
    next
}

/// 移动端商店收据上报（购买/恢复购买后调用）。
/// 新协议（prism.sarl HTTP API）未提供商店收据端点，暂不支持；
/// 保留函数与签名以兼容 ipc/commands.rs 调用点，前端收到明确错误提示。
pub async fn submit_store_receipt(
    data_dir: &Path,
    settings: &UserSettings,
    store: &str,
    receipt: Value,
) -> Result<EntitlementStatus> {
    let _ = (data_dir, settings, store, receipt);
    bail!("商店内购激活暂未开放，请使用授权码 + 邮箱激活");
}

/// 【APP28 任务3】解绑所需的服务端凭据快照。
/// 必须在删除本地缓存 **之前** 捕获（凭据存在 license.dat 内），之后交给
/// 后台任务异步 POST，前端无需等待网络返回。
pub struct ReleaseBinding {
    base: String,
    license_key: String,
    email: String,
    device_id: String,
}

impl ReleaseBinding {
    /// 从本地缓存捕获解绑凭据；未激活 / 缺邮箱 / 取不到设备 ID 时返回 None
    pub fn capture(data_dir: &Path, settings: &UserSettings) -> Option<Self> {
        let (license_key, email) = cached_credentials(data_dir)?;
        let device_id = device_id(data_dir).ok()?;
        Some(Self {
            base: server_base(settings),
            license_key,
            email,
            device_id,
        })
    }

    /// POST /api/license/deactivate：best-effort，断网/404 静默返回 false
    pub async fn notify(&self) -> bool {
        let result = post_with_fallback(
            &format!("{}{}", self.base, crate::obf!("/api/license/deactivate")),
            &serde_json::json!({
                "license_key": self.license_key,
                "email": self.email,
                "device_id": self.device_id,
            }),
        )
        .await;
        match result {
            Ok(resp) => {
                let ok = resp.status().is_success();
                tracing::info!("license deactivate notify: http={} ok={ok}", resp.status().as_u16());
                ok
            }
            Err(e) => {
                tracing::warn!("license deactivate notify failed (ignored): {e}");
                false
            }
        }
    }
}

/// 移除本机授权（切换账号/退款后）：删除本地所有授权与同步缓存文件——
/// 加密缓存 license.dat、旧版 license_cache.json 与订阅同步基线 sync_links.json。
/// 文件不存在均忽略；本函数纯本地操作，绝不因远端接口 404 或断网而失败，
/// 确保本地移除授权 100% 成功（重新激活后由 reconcile 重建同步基线）。
pub fn deactivate(data_dir: &Path) -> EntitlementStatus {
    clear_cache(data_dir);
    let _ = std::fs::remove_file(data_dir.join("sync_links.json"));
    EntitlementStatus::inactive()
}

/// 本地已激活的 License Key（app-control 心跳上报用；未激活返回 None）
pub fn get_saved_license_key(data_dir: &Path) -> Option<String> {
    load_cache(data_dir)
        .map(|c| c.license)
        .filter(|k| !k.trim().is_empty())
}

/// 从加密缓存读取同步凭据对 (license_key, email)；
/// 未激活或邮箱缺失（旧版迁移缓存）时返回 None —— 云端同步不可用。
pub fn cached_credentials(data_dir: &Path) -> Option<(String, String)> {
    load_cache(data_dir).and_then(|c| {
        let email = c.email.trim().to_lowercase();
        (!c.license.is_empty() && !email.is_empty())
            .then(|| (c.license, email))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 截图场景：试用版 2026-10-21 18:43 到期，系统时间 18:48 仍显示已激活
    fn trial(expires_at: i64) -> EntitlementStatus {
        EntitlementStatus {
            status: "active".into(),
            kind: Some("subscription".into()),
            expires_at: Some(expires_at),
            source: Some("code".into()),
            last_verified_at: 0,
            plan: Some("free".into()),
            max_seats: Some(1),
            used_seats: Some(1),
            sync_available: false,
            alpha: false,
        }
    }

    #[test]
    fn expired_trial_immediately_flips_to_expired_offline() {
        let exp = parse_expires_at("2026-10-21 18:43").expect("parse expires_at");
        let now = exp + 5 * 60; // 18:48

        // 到期前：保持 active
        let mut fresh = trial(exp);
        assert!(!is_expired(&fresh, now - 600));
        assert!(!enforce_expiry(&mut fresh, now - 600));
        assert_eq!(fresh.status, "active");
        assert!(fresh.is_unlocked());

        // 到期后（离线、当天已校验过）：立即熔断
        let mut ent = trial(exp);
        assert!(is_expired(&ent, now));
        assert!(enforce_expiry(&mut ent, now));
        assert_eq!(ent.status, "expired");
        assert!(!ent.is_unlocked());
    }

    /// 【APP23 任务2.2】断网激活：reqwest 原始报错含完整验证接口 URL，
    /// 脱敏后必须是纯中文提示，绝不能出现 http 或 prism.sarl
    #[test]
    fn test_sanitize_license_error_strips_urls() {
        let raw = "error sending request for url (https://prism.sarl/api/license/activate): client error (Connect)";
        let out = sanitize_license_error(raw);
        assert_eq!(out, "网络连接失败，请检查网络设置后重试");
        assert!(!out.contains("http"));
        assert!(!out.contains("prism.sarl"));

        // 非网络类错误：仅剥离 URL 片段，保留其余可读信息
        let raw2 = "激活未通过 for url (https://prism.sarl/api/license/activate) HTTP 403";
        let out2 = sanitize_license_error(raw2);
        assert!(!out2.contains("http"));
        assert!(!out2.contains("prism.sarl"));

        // 超时走统一文案
        let out3 = sanitize_license_error("operation timed out");
        assert_eq!(out3, "连接服务器超时，请检查网络后重试");
    }

    #[test]
    fn lifetime_plan_never_expires() {
        let exp = parse_expires_at("2026-10-21 18:43").unwrap();
        let mut ent = trial(exp);
        ent.plan = Some("team".into());
        ent.kind = Some("lifetime".into());
        assert!(!is_expired(&ent, exp + 86_400));
        assert!(!enforce_expiry(&mut ent, exp + 86_400));
        assert_eq!(ent.status, "active");
    }

    #[test]
    fn clock_rollback_locks_cache() {
        let exp = parse_expires_at("2026-10-21 18:43").unwrap();
        let now = now_secs();
        let mut cache = CachedLicense {
            license: "KEY".into(),
            email: "a@b.com".into(),
            synced_on: String::new(),
            // 高水位线远超前于当前系统时间 → 判定为人为回拨
            max_seen_unix: now + CLOCK_ROLLBACK_TOLERANCE + 60,
            entitlement: trial(exp),
        };
        normalize_cache(&mut cache);
        assert_eq!(cache.entitlement.status, "expired");
        // 高水位线绝不回退
        assert!(cache.max_seen_unix >= now + CLOCK_ROLLBACK_TOLERANCE + 60);
    }

    /// 【APP48 任务6】Alpha 内测授权：plan 虽是 pro，但必须按订阅+到期展示，
    /// 绝不能被渲染成「买断/永久」，且云端同步恒不可用。
    #[test]
    fn alpha_license_not_lifetime_and_sync_off() {
        let exp = parse_expires_at("2026-12-31 23:59").unwrap();
        let ent = map_entitlement(
            "pro",
            "active",
            Some(exp),
            Some(1),
            Some(1),
            true, // 服务端即便返回可同步，Alpha 也必须关闭
            true,
        );
        assert_eq!(ent.kind.as_deref(), Some("subscription"));
        assert!(ent.alpha, "alpha 标记必须保真传给前端");
        assert!(!ent.sync_available, "Alpha 内测授权不允许云端同步");
        assert_eq!(ent.status, "active");
        assert!(exp > now_secs(), "内测授权按到期时间正常失效");
    }

    /// 【APP48 任务4】隐身白名单：prism.sarl 与其 DoH 解析 IP 必须命中。
    #[test]
    fn stealth_guard_hides_domain_and_ip() {
        remember_stealth_ip("203.0.113.9");
        assert!(is_stealth_protected_host_or_ip("prism.sarl"));
        assert!(is_stealth_protected_host_or_ip("203.0.113.9"));
        assert!(is_stealth_protected_host_or_ip("https://prism.sarl/api/x"));
        assert!(!is_stealth_protected_host_or_ip("example.com"));
        assert!(!is_stealth_protected_host_or_ip("8.8.8.8"));
        assert!(stealth_ips_snapshot().iter().any(|ip| ip == "203.0.113.9"));
    }

    /// 服务端真实令牌中的 licenseRef 固定向量（已核对一致）
    #[test]
    fn license_ref_matches_server_fixed_vector() {
        assert_eq!(license_ref("ASKC-LDP2-M4VT-ZSBU"), "02d716abf16c817c");
    }

    /// 只允许 trim，严禁大小写转换：哈希输入必须与请求体 license_key 完全一致
    #[test]
    fn license_ref_trims_but_preserves_case() {
        assert_eq!(license_ref("  ASKC-LDP2-M4VT-ZSBU  "), "02d716abf16c817c");
        assert_ne!(license_ref("askc-ldp2-m4vt-zsbu"), "02d716abf16c817c");
    }
}
