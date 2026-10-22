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

use std::path::{Path, PathBuf};

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

fn clear_cache(data_dir: &Path) {
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

pub(crate) fn http_builder() -> Result<reqwest::ClientBuilder> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        // 连接阶段短超时：黑洞地址快速失败，尽快进入 IPv4 重试
        .connect_timeout(std::time::Duration::from_secs(8))
        // 不走系统代理：内核运行时系统代理指向本机，走代理会自回环；
        // 授权服务为公网 HTTPS，直连即可
        .no_proxy())
}

/// 直连失败后强制 IPv4 源重试：部分网络 IPv6 出口为黑洞（AAAA 优先 +
/// SYN 无响应），hyper 顺序尝试地址会耗尽超时。用 0.0.0.0 绑定源地址时
/// v6 目标因地址族不匹配立即跳过，连接器秒级回退到 v4 目标。
pub(crate) async fn send_with_v4_fallback(
    make: impl Fn(&reqwest::Client) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response> {
    let mut last: Option<String> = None;
    for force_v4 in [false, true] {
        let mut b = http_builder()?;
        if force_v4 {
            b = b.local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        }
        match make(&b.build()?).send().await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                tracing::warn!("license request (force_v4={force_v4}) failed: {e}");
                last = Some(e.to_string());
            }
        }
    }
    bail!("网络请求失败：{}（已尝试 IPv4 直连）", last.unwrap_or_default())
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

/// 从非 200 响应提取标准机器错误码（APK-3 任务2）。
/// 优先取 JSON 的 "error" 字符串字段；解析失败按 HTTP 状态码映射：
/// 400→invalid_input、403→activation_failed、409→seat_limit_reached、
/// 429→activation_throttled、5xx→server_error。
async fn extract_error_code(http: u16, resp: reqwest::Response) -> String {
    let text = resp.text().await.unwrap_or_default();
    let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if let Some(c) = parsed.get("error").and_then(|e| e.as_str()) {
        if !c.is_empty() {
            return c.to_string();
        }
    }
    match http {
        400 => "invalid_input",
        403 => "activation_failed",
        409 => "seat_limit_reached",
        429 => "activation_throttled",
        s if s >= 500 => "server_error",
        _ => "activation_failed",
    }
    .to_string()
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
async fn fetch_status(base: &str, license_key: &str) -> std::result::Result<StatusResponse, StatusError> {
    let resp = get_with_fallback(
        &format!("{base}{}", crate::obf!("/api/license/status")),
        license_key,
    )
    .await
    .map_err(|e| StatusError::Transient(e.to_string()))?;
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
    resp.json()
        .await
        .map_err(|e| StatusError::Transient(e.to_string()))
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
) -> EntitlementStatus {
    let expired =
        server_status == "expired" || expires_at.map(|exp| exp <= now_secs()).unwrap_or(false);
    let status = if expired { "expired" } else { "active" };
    EntitlementStatus {
        status: status.into(),
        kind: Some(if plan == "team" { "lifetime" } else { "subscription" }.into()),
        expires_at,
        source: Some("code".into()),
        last_verified_at: now_secs(),
        plan: (!plan.is_empty()).then(|| plan.to_string()),
        max_seats,
        used_seats,
        sync_available,
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

    let resp = post_with_fallback(
        &format!("{base}{}", crate::obf!("/api/license/activate")),
        &serde_json::json!({
            "license_key": license_key.clone(),
            "email": email,
            "device_id": device_id_str,
            "device_name": device_name(),
        }),
    )
    .await?;

    // 429 频率限制：把 retry_after 与标准错误码编进错误文本透传给前端。
    // 前端解析约定："rate_limited:{secs}:activation_throttled"，
    // 例如 "rate_limited:30:activation_throttled" 表示 30 秒后可重试。
    if resp.status().as_u16() == 429 {
        let secs = retry_after_secs(resp).await;
        bail!("rate_limited:{secs}:activation_throttled");
    }
    // 非 200：透传标准机器错误码（"err_code:{code}"），
    // 前端 LICENSE_ERROR_MAP 按错误码 1:1 逐字渲染提示卡片
    if !resp.status().is_success() {
        let http = resp.status().as_u16();
        let code = extract_error_code(http, resp).await;
        bail!("err_code:{code}");
    }
    let data: ActivateResponse = resp.json().await?;
    if !data.ok {
        bail!("激活失败：服务端未确认（ok=false）");
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
    );
    match fetch_status(&base, &license_key).await {
        Ok(s) if s.valid => {
            ent = map_entitlement(
                &s.plan,
                &s.status,
                s.expires_at.as_deref().and_then(parse_expires_at),
                s.max_seats,
                s.used_seats,
                s.sync_available,
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

    match fetch_status(&base, &cache.license).await {
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
}
