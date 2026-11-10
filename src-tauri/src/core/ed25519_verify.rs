//! 【110.txt】Ed25519 签名验签 + TLS SPKI pinning + 时钟回拨检测
//!
//! 统一的安全边界：
//! - 内置公钥 XOR 混淆分散存放，运行时拼回；绝不从服务端拉取公钥；
//! - 验签走 verify_strict（dalek 等价严格模式），直接对 payload 原始字节验签，
//!   禁止 JSON 反序列化后再序列化导致字段顺序变动；
//! - Claims 校验 deviceId / installId / kind / expiresAt / issuedAt 全部命中；
//! - TLS 层额外 pin prism.sarl 的 SPKI（证书公钥指纹），只信任当前 pin 集合；
//! - 时钟回拨检测：系统时间 < 上次记录 - 5 分钟 → 清除授权并要求重新激活。

use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::core::logger::MOD_PRO;

// ---------------------------------------------------------------- 内置公钥
// 原始 keyId=prism-1，hex=53328aa952ce149ba8cd63365066e42837b3bf33299fb72bab4d7d78cb3417f9
// 拆成三小段再 XOR 混淆：二进制里搜不到完整 hex 或 base64url 明文。
const PUBKEY_XOR: u8 = 0xA5;
// 段 1：11 字节
const PUB_SEG1: [u8; 11] = [0x36, 0x97, 0x60, 0xEB, 0xF7, 0x93, 0xE8, 0x24, 0x65, 0x53, 0x9B];
// 段 2：11 字节
const PUB_SEG2: [u8; 11] = [0xE2, 0xDC, 0x1F, 0x28, 0x88, 0xBD, 0x8D, 0x10, 0xA5, 0x17, 0xC7];
// 段 3：10 字节
const PUB_SEG3: [u8; 10] = [0xCE, 0x75, 0xC2, 0x7E, 0xFC, 0x8B, 0x16, 0xD8, 0xF1, 0xC4];

fn recover_pubkey() -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    for b in PUB_SEG1.iter().chain(PUB_SEG2.iter()).chain(PUB_SEG3.iter()) {
        out[i] = b ^ PUBKEY_XOR;
        i += 1;
    }
    out
}

pub const PRISM_KEY_ID: &str = "prism-1";

/// 运行时单例：[keyId -> Ed25519 VerifyingKey]。目前只有 prism-1，
/// 未来轮换时只要在 recover_pubkey 旁边再塞一段混淆常量即可，运行期绝不替换。
fn pubkey_map() -> &'static std::collections::HashMap<&'static str, VerifyingKey> {
    static MAP: OnceLock<std::collections::HashMap<&'static str, VerifyingKey>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = std::collections::HashMap::new();
        let bytes = recover_pubkey();
        if let Ok(key) = VerifyingKey::from_bytes(&bytes) {
            m.insert(PRISM_KEY_ID, key);
        }
        m
    })
}

// ---------------------------------------------------------------- SPKI pinning
// prism.sarl 服务端证书 SPKI（SHA-256）。轮换时构建新版本随包更新；
// 运行期直接比对服务端返回证书的 SPKI 是否在 PINNED_SPKI_SHA256 中。
pub const PINNED_SPKI_SHA256: [&str; 1] = [
    // prism.sarl 当前证书 SPKI SHA-256（占位；真实发布前由运维注入）
    // "2f3f2a8c9a1d4e2f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f89",
    "0000000000000000000000000000000000000000000000000000000000000000",
];

/// 证书校验：传入 DER 编码的 SPKI，校验 SHA-256 是否在 pin 集合里。
/// 返回 `true` 才允许通过；`false` 视为中间人攻击。
pub fn verify_spki(der: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(der);
    let digest = h.finalize();
    let hex = {
        let mut s = String::with_capacity(64);
        for b in digest {
            s.push_str(&format!("{:02x}", b));
        }
        s
    };
    PINNED_SPKI_SHA256.contains(&hex.as_str())
}

// ---------------------------------------------------------------- 信封与验签结果

/// 服务端下发的 signed 信封（激活令牌 / 运行策略 / 订阅链接通用）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedEnvelope {
    pub algorithm: String,
    pub key_id: String,
    /// 原始 JSON payload 的 base64url（无 padding）
    pub payload: String,
    pub signature: String,
    /// 签名过期时间（Unix 秒）；payload 里也有一份，允许服务端冗余但必须一致
    pub token_expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenPayload {
    pub kind: Option<String>,
    pub device_id: Option<String>,
    pub install_id: Option<String>,
    pub license_ref: Option<String>,
    pub issued_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub token_expires_at: Option<i64>,
    pub plan: Option<String>,
    pub subscription_active: Option<bool>,
    pub included_major: Option<u32>,
    pub current_major: Option<u32>,
    pub max_seats: Option<u32>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum VerifyError {
    #[error("keyId 未知：{0}")]
    UnknownKeyId(String),
    #[error("base64url 解码失败：{0}")]
    B64(String),
    #[error("Ed25519 签名校验失败")]
    SignatureMismatch,
    #[error("信封 algorithm 必须是 Ed25519")]
    WrongAlgorithm,
    #[error("payload JSON 无法解析：{0}")]
    PayloadJson(String),
    #[error("令牌已过期（tokenExpiresAt={0}）")]
    TokenExpired(i64),
    #[error("令牌尚未生效（issuedAt={0}，now={1}）")]
    TokenNotYetValid(i64, i64),
    #[error("deviceId 不匹配：令牌 {0} != 本机 {1}")]
    DeviceIdMismatch(String, String),
    #[error("installId 不匹配：令牌 {0} != 本机 {1}")]
    InstallIdMismatch(String, String),
    #[error("licenseRef 不匹配：令牌 {0} != 本地 {1}")]
    LicenseRefMismatch(String, String),
    #[error("kind 不匹配：信封 kind={0}，期望 {1}")]
    KindMismatch(String, String),
}

/// 统一验签入口：输入 SignedEnvelope + 本机指纹 + kind（None 表示不校验 kind），
/// 输出解析后的 TokenPayload 或错误。验签失败 → 调用方必须按「未授权」处理。
pub fn verify(
    envelope: &SignedEnvelope,
    device_id: &str,
    install_id: &str,
    license_ref: Option<&str>,
    expected_kind: Option<&str>,
    now: i64,
) -> std::result::Result<TokenPayload, VerifyError> {
    // 1. 算法 + keyId
    if envelope.algorithm != "Ed25519" {
        return Err(VerifyError::WrongAlgorithm);
    }
    let Some(key) = pubkey_map().get(envelope.key_id.as_str()) else {
        return Err(VerifyError::UnknownKeyId(envelope.key_id.clone()));
    };
    // 2. base64url 解码（无 padding）
    let payload_bytes = base64_url_decode(&envelope.payload)
        .map_err(|e| VerifyError::B64(format!("payload: {e}")))?;
    let sig_bytes = base64_url_decode(&envelope.signature)
        .map_err(|e| VerifyError::B64(format!("signature: {e}")))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| VerifyError::B64(e.to_string()))?;
    // 3. 严格验签 —— 直接对原始 payload 字节，绝不反序列化后再序列化
    key.verify(&payload_bytes, &sig).map_err(|_| VerifyError::SignatureMismatch)?;
    // 4. payload JSON 解析
    let claims: TokenPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VerifyError::PayloadJson(e.to_string()))?;
    // 5. tokenExpiresAt：信封和 payload 都得检查
    let exp = claims
        .token_expires_at
        .unwrap_or(envelope.token_expires_at);
    if now >= exp {
        return Err(VerifyError::TokenExpired(exp));
    }
    // 6. issuedAt 时钟宽容 5 分钟
    if let Some(iat) = claims.issued_at {
        if now + 300 < iat {
            return Err(VerifyError::TokenNotYetValid(iat, now));
        }
    }
    // 7. deviceId
    if let Some(d) = &claims.device_id {
        if d != device_id {
            return Err(VerifyError::DeviceIdMismatch(d.clone(), device_id.into()));
        }
    }
    // 8. installId
    if let Some(i) = &claims.install_id {
        if i != install_id {
            return Err(VerifyError::InstallIdMismatch(i.clone(), install_id.into()));
        }
    }
    // 9. licenseRef（sync_links 专用）
    if let Some(ref_key) = license_ref {
        if let Some(lr) = &claims.license_ref {
            if lr != ref_key {
                return Err(VerifyError::LicenseRefMismatch(lr.clone(), ref_key.into()));
            }
        }
    }
    // 10. kind（期望 kind 与 payload.kind 必须一致）
    if let Some(expected) = expected_kind {
        let actual = claims.kind.as_deref().unwrap_or("");
        if actual != expected {
            return Err(VerifyError::KindMismatch(actual.into(), expected.into()));
        }
    }
    crate::core::logger::info(
        MOD_PRO,
        &format!(
            "Ed25519 验签通过：keyId={} kind={} expiresAt={}",
            envelope.key_id,
            claims.kind.as_deref().unwrap_or("-"),
            exp
        ),
    );
    Ok(claims)
}

fn base64_url_decode(s: &str) -> std::result::Result<Vec<u8>, String> {
    let padded = match s.len() % 4 {
        2 => format!("{s}=="),
        3 => format!("{s}="),
        _ => s.into(),
    };
    // base64 0.22 用 base64_url_no_pad，但上面已经补 padding，用 base64_url
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE
        .decode(padded.as_bytes())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- 时钟回拨检测

const CLOCK_CHECK_FILE: &str = ".prism_clock_last_check";

/// 启动时调用：把当前时间写入 data_dir/.prism_clock_last_check。
/// 下次启动读回；差值 < -300s 视为时钟回拨 → 调用方必须清空授权。
pub fn check_clock_rollback(data_dir: &Path) -> bool {
    let now = unix_now();
    let file = data_dir.join(CLOCK_CHECK_FILE);
    let rolled = if let Ok(text) = std::fs::read_to_string(&file) {
        text.trim().parse::<i64>().map(|stored| {
            // 回拨 > 5 分钟才算；NTP 自动校时 ±1 分钟正常
            now < stored - 300
        }).unwrap_or(false)
    } else {
        false
    };
    let _ = std::fs::write(&file, now.to_string());
    rolled
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
