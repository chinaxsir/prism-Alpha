//! 【110.txt / 用户修正方案】Ed25519 严格验签 + 时钟回拨检测
//!
//! 验签固定 7 步，绝不做任何 JSON 重新序列化：
//!   1. base64url 无 padding 解码 token.payload → payloadBytes（原始 JSON 字节，
//!      不做任何 parse 成对象再 stringify 的动作）
//!   2. base64url 无 padding 解码 token.signature → sig（必须正好 64 字节）
//!   3. 内置公钥 prism-1 = 32 字节 raw，hex 见 PUBKEY_PRISM_1
//!   4. Ed25519-Verifier.verify(sig, payloadBytes) == true 才继续
//!   5. 验签通过后才 serde_json::from_slice(payloadBytes) 读 claims
//!   6. 断点检查：payloadBytes 长度 150..=300，sig 必须 64 字节，公钥必须 32 字节
//!   7. 单元测试用固定向量（base64url / hex / 临时密钥对自签）返回 true

use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::core::logger::MOD_PRO;

// ---------------------------------------------------------------- 内置公钥
// 生产公钥 prism-1（固定向量，不得变更）
//   base64url (无 padding): UzKKqVLOFJuozWM2UGbkKDezvzMpn7crq019eMs0F_k
//   hex:                    53328aa952ce149ba8cd63365066e42837b3bf33299fb72bab4d7d78cb3417f9
//   raw bytes (32):         硬编码下方数组（不再混淆：还原逻辑曾出错导致验签直接失败）
const PUBKEY_PRISM_1: [u8; 32] = [
    0x53, 0x32, 0x8a, 0xa9, 0x52, 0xce, 0x14, 0x9b,
    0xa8, 0xcd, 0x63, 0x36, 0x50, 0x66, 0xe4, 0x28,
    0x37, 0xb3, 0xbf, 0x33, 0x29, 0x9f, 0xb7, 0x2b,
    0xab, 0x4d, 0x7d, 0x78, 0xcb, 0x34, 0x17, 0xf9,
];

pub const PRISM_KEY_ID: &str = "prism-1";

/// 运行期单例：[keyId -> Ed25519 VerifyingKey]。当前只有 prism-1；
/// 未来轮换时只需在本文件新增 PUBKEY_xxx 数组并补进 `init_key_map`。
pub fn init_key_map() -> &'static std::collections::HashMap<&'static str, VerifyingKey> {
    use std::collections::HashMap;
    static MAP: OnceLock<HashMap<&'static str, VerifyingKey>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = HashMap::new();
        if let Ok(k) = VerifyingKey::from_bytes(&PUBKEY_PRISM_1) {
            m.insert(PRISM_KEY_ID, k);
        }
        m
    })
}

// ---------------------------------------------------------------- SPKI pinning
pub const PINNED_SPKI_SHA256: [&str; 1] = [
    // prism.sarl 服务端证书 SPKI SHA-256（运维注入后替换）
    "0000000000000000000000000000000000000000000000000000000000000000",
];

/// SPKI 证书 pinning：SHA-256(der) 在 PINNED_SPKI_SHA256 中才返回 true。
pub fn verify_spki(der: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(der);
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{:02x}", b));
    }
    PINNED_SPKI_SHA256.contains(&hex.as_str())
}

// ---------------------------------------------------------------- 信封与验签结果

/// 服务端下发的签名信封（激活令牌 / 运行策略 / 订阅链接通用；
/// payload 必须是原始 JSON 的 base64url 无 padding，signature 是 Ed25519 签名的
/// base64url 无 padding）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedEnvelope {
    pub algorithm: String,
    pub key_id: String,
    /// 原始 JSON payload 的 base64url（无 padding）
    pub payload: String,
    pub signature: String,
    /// 签名过期时间（Unix 秒）；payload 内会有同字段
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
    #[error("信封 algorithm 必须是 Ed25519，实际 {0}")]
    WrongAlgorithm(String),
    #[error("公钥长度异常：{0}（必须 32 字节）")]
    PubKeyLength(usize),
    #[error("payload base64url 解码失败：{0}")]
    PayloadB64(String),
    #[error("payload 长度异常：{0}（必须 150..=300 字节）")]
    PayloadLength(usize),
    #[error("signature base64url 解码失败：{0}")]
    SigB64(String),
    #[error("signature 长度异常：{0}（必须 64 字节）")]
    SigLength(usize),
    #[error("Ed25519 签名校验失败（payload 字节被篡改或公钥/签名不匹配）")]
    SignatureMismatch,
    #[error("payload JSON 无法解析（验签虽通过，但结构不符合预期）：{0}")]
    PayloadJson(String),
    #[error("令牌已过期（tokenExpiresAt={0}，now={1}）")]
    TokenExpired(i64, i64),
    #[error("令牌尚未生效（issuedAt={0}，now={1}，时钟宽容 5 分钟）")]
    TokenNotYetValid(i64, i64),
    #[error("deviceId 不匹配：令牌 {0} != 本机 {1}")]
    DeviceIdMismatch(String, String),
    #[error("installId 不匹配：令牌 {0} != 本机 {1}")]
    InstallIdMismatch(String, String),
    #[error("licenseRef 不匹配：令牌 {0} != 本地 {1}")]
    LicenseRefMismatch(String, String),
    #[error("kind 不匹配：payload.kind={0}，期望 {1}")]
    KindMismatch(String, String),
}

/// 【方案 1-7】严格验签：绝不做任何 JSON 重新序列化。
/// 输入 SignedEnvelope + 本机指纹 + 期望 kind + now(Unix 秒)。
/// 成功返回解析后的 TokenPayload；失败返回 VerifyError（调用方必须按「未授权」处理）。
pub fn verify(
    envelope: &SignedEnvelope,
    device_id: &str,
    install_id: &str,
    license_ref: Option<&str>,
    expected_kind: Option<&str>,
    now: i64,
) -> std::result::Result<TokenPayload, VerifyError> {
    // 方案 3 前置：公钥长度兜底（理论上 VerifyingKey 构造时已校验）
    if PUBKEY_PRISM_1.len() != 32 {
        return Err(VerifyError::PubKeyLength(PUBKEY_PRISM_1.len()));
    }
    let key_map = init_key_map();

    // 方案 3 续：keyId 命中
    let Some(key) = key_map.get(envelope.key_id.as_str()) else {
        return Err(VerifyError::UnknownKeyId(envelope.key_id.clone()));
    };

    // 方案 4 前置：algorithm 严格等于 "Ed25519"
    if envelope.algorithm != "Ed25519" {
        return Err(VerifyError::WrongAlgorithm(envelope.algorithm.clone()));
    }

    // 方案 1：base64url 无 padding 解码 payload → payloadBytes（原始 JSON 字节，
    // 不做任何 parse 成对象再 stringify 的动作）
    let payload_bytes =
        base64url_no_pad_decode(&envelope.payload).map_err(VerifyError::PayloadB64)?;

    // 方案 6：payload 长度 150..=300（异常直接拒绝，避免大包绕过）
    if !(150..=300).contains(&payload_bytes.len()) {
        return Err(VerifyError::PayloadLength(payload_bytes.len()));
    }

    // 方案 2：base64url 无 padding 解码 signature → sig_bytes（必须正好 64 字节）
    let sig_bytes =
        base64url_no_pad_decode(&envelope.signature).map_err(VerifyError::SigB64)?;
    if sig_bytes.len() != 64 {
        return Err(VerifyError::SigLength(sig_bytes.len()));
    }

    // 方案 4：Ed25519-Verifier.verify(sig, payloadBytes) == true 才继续
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| VerifyError::SigB64(e.to_string()))?;
    key.verify(&payload_bytes, &sig)
        .map_err(|_| VerifyError::SignatureMismatch)?;

    // 方案 5：验签通过后才把 payloadBytes 解析成 JSON 读取 claims
    let claims: TokenPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| VerifyError::PayloadJson(e.to_string()))?;

    // 后续 claims 校验：只用于业务判断，不参与验签
    let exp = claims
        .token_expires_at
        .unwrap_or(envelope.token_expires_at);
    if now >= exp {
        return Err(VerifyError::TokenExpired(exp, now));
    }
    if let Some(iat) = claims.issued_at {
        if now + 300 < iat {
            return Err(VerifyError::TokenNotYetValid(iat, now));
        }
    }
    if let Some(d) = &claims.device_id {
        if d != device_id {
            return Err(VerifyError::DeviceIdMismatch(d.clone(), device_id.into()));
        }
    }
    if let Some(i) = &claims.install_id {
        if i != install_id {
            return Err(VerifyError::InstallIdMismatch(i.clone(), install_id.into()));
        }
    }
    if let Some(ref_key) = license_ref {
        if let Some(lr) = &claims.license_ref {
            if lr != ref_key {
                return Err(VerifyError::LicenseRefMismatch(lr.clone(), ref_key.into()));
            }
        }
    }
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

/// base64url (RFC 4648 §5) 无 padding 解码：
/// 只接受 `-` `_` 字符，拒绝 `+` `/` `=`；和 JWS / COSE 严格一致。
pub fn base64url_no_pad_decode(s: &str) -> std::result::Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- 时钟回拨检测

const CLOCK_CHECK_FILE: &str = ".prism_clock_last_check";

pub fn check_clock_rollback(data_dir: &Path) -> bool {
    let now = unix_now();
    let file = data_dir.join(CLOCK_CHECK_FILE);
    let rolled = if let Ok(text) = std::fs::read_to_string(&file) {
        text.trim()
            .parse::<i64>()
            .map(|stored| now < stored - 300) // 回拨 > 5 分钟才触发
            .unwrap_or(false)
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

// ---------------------------------------------------------------- 单元测试（用用户给定的固定向量）

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// 固定向量：用户指定的生产公钥 base64url / hex / raw bytes 三者必须一一对应
    const PUBKEY_B64URL: &str = "UzKKqVLOFJuozWM2UGbkKDezvzMpn7crq019eMs0F_k";
    const PUBKEY_HEX: &str = "53328aa952ce149ba8cd63365066e42837b3bf33299fb72bab4d7d78cb3417f9";

    #[test]
    fn test_pubkey_fixed_vector_decodes_to_32_bytes() {
        let bytes = base64url_no_pad_decode(PUBKEY_B64URL).expect("base64url 解码应成功");
        assert_eq!(bytes.len(), 32, "公钥必须正好 32 字节");
        assert_eq!(
            hex_encode(&bytes).to_ascii_lowercase(),
            PUBKEY_HEX.to_ascii_lowercase(),
            "base64url 解码出的字节必须等于用户给定的 hex"
        );
    }

    #[test]
    fn test_hardcoded_pubkey_matches_fixed_vector() {
        // 硬编码的 PUBKEY_PRISM_1 必须等于用户给定的 hex → 防止混淆还原出错
        assert_eq!(
            hex_encode(&PUBKEY_PRISM_1).to_ascii_lowercase(),
            PUBKEY_HEX.to_ascii_lowercase(),
            "硬编码公钥必须精确匹配用户给定的 hex 固定向量"
        );
        // 硬编码公钥必须等于 base64url 解码结果
        let from_b64 = base64url_no_pad_decode(PUBKEY_B64URL).unwrap();
        assert_eq!(from_b64.as_slice(), PUBKEY_PRISM_1);
    }

    #[test]
    fn test_verify_key_map_constructs_successfully() {
        // 确保 init_key_map 能构造 VerifyingKey（dalek 的 Curve25519 合法性检查会拒绝
        // 一些特殊形式，但生产公钥是标准 Ed25519 公钥，必须通过）
        let map = init_key_map();
        assert!(map.contains_key(PRISM_KEY_ID), "keyId prism-1 必须在 map 中");
    }

    #[test]
    fn test_verify_rejects_wrong_algorithm() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = sk.verifying_key();
        let payload = r#"{"kind":"activation","deviceId":"x","tokenExpiresAt":9999999999}"#;
        let sig = sk.sign(payload.as_bytes());
        let env = SignedEnvelope {
            algorithm: "RS256".into(), // 必须是 Ed25519
            key_id: PRISM_KEY_ID.into(),
            payload: base64url_encode(payload.as_bytes()),
            signature: base64url_encode(&sig.to_bytes()),
            token_expires_at: 9999999999,
        };
        let r = verify(&env, "x", "", None, Some("activation"), 0);
        assert!(matches!(r, Err(VerifyError::WrongAlgorithm(_))));
        let _ = vk; // 抑制未使用告警
    }

    #[test]
    fn test_verify_accepts_valid_signed_envelope_roundtrip() {
        // 全链路自签验证：临时密钥对自签 payload → 临时 VerifyingKey 验签 == true
        // （注：生产 verify 用的是全局 PUBKEY_PRISM_1，此处用临时密钥独立验证算法本身）
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = sk.verifying_key();
        let payload_bytes = br#"{"kind":"activation","deviceId":"dev-123","installId":"inst-abc","licenseRef":"LIC-001","issuedAt":1700000000,"tokenExpiresAt":9999999999,"plan":"pro","subscriptionActive":true}"#;
        assert!(
            (150..=300).contains(&payload_bytes.len()),
            "测试 payload 必须落在 150..=300 范围（实际 {}）",
            payload_bytes.len()
        );
        let sig = sk.sign(payload_bytes);
        assert_eq!(sig.to_bytes().len(), 64, "签名必须正好 64 字节");
        // 关键：临时公钥能验证自己签的 payload
        assert!(
            vk.verify(payload_bytes, &sig).is_ok(),
            "Ed25519 自签信封必须能被同一密钥对的 VerifyingKey 验签通过"
        );
        // payload/sig 都通过 base64url 无 padding 解码再喂给 verify 也必须 OK
        let env_payload = base64url_encode(payload_bytes);
        let env_sig = base64url_encode(&sig.to_bytes());
        assert_eq!(
            base64url_no_pad_decode(&env_payload).unwrap().as_slice(),
            payload_bytes,
            "base64url 无 padding 往返必须无损还原 payloadBytes"
        );
        assert_eq!(
            base64url_no_pad_decode(&env_sig).unwrap().as_slice(),
            sig.to_bytes(),
            "base64url 无 padding 往返必须无损还原 sig"
        );
    }

    #[test]
    fn test_payload_length_out_of_range_rejected() {
        // payload 小于 150 字节必须被拒（长度边界检查优先于验签）
        let short = b"{\"kind\":\"a\",\"d\":\"x\",\"t\":9999999999}";
        assert!(short.len() < 150);
        let env = SignedEnvelope {
            algorithm: "Ed25519".into(),
            key_id: PRISM_KEY_ID.into(),
            payload: base64url_encode(short),
            signature: base64url_encode(&[0u8; 64]),
            token_expires_at: 9999999999,
        };
        let r = verify(&env, "x", "", None, Some("activation"), 0);
        assert!(matches!(r, Err(VerifyError::PayloadLength(_))));
    }

    #[test]
    fn test_sig_length_not_64_rejected() {
        // signature 长度不是 64 字节必须被拒
        let payload = r#"{"kind":"activation","deviceId":"device-abcdefghijklmnop","installId":"inst-abcdefghij","licenseRef":"LIC-001-ABCDEF","issuedAt":1700000000,"tokenExpiresAt":9999999999,"plan":"pro","subscriptionActive":true}"#;
        assert!(
            (150..=300).contains(&payload.len()),
            "payload 必须落在 150..=300 范围（实际 {}）",
            payload.len()
        );
        let sig_b64 = base64url_encode(&[0u8; 32]); // 32 ≠ 64
        assert_eq!(sig_b64.len(), 43); // 32 字节 → 43 base64url 字符
        let env = SignedEnvelope {
            algorithm: "Ed25519".into(),
            key_id: PRISM_KEY_ID.into(),
            payload: base64url_encode(payload.as_bytes()),
            signature: sig_b64,
            token_expires_at: 9999999999,
        };
        let r = verify(&env, "x", "", None, Some("activation"), 0);
        eprintln!("verify result: {:?}", r);
        assert!(matches!(r, Err(VerifyError::SigLength(_))));
    }

    #[test]
    fn test_tampered_payload_rejected() {
        // payload 被篡改 → 签名不匹配
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let good = br#"{"kind":"activation","deviceId":"x","installId":"inst","licenseRef":"LIC","issuedAt":1700000000,"tokenExpiresAt":9999999999,"plan":"pro"}"#;
        let bad = br#"{"kind":"activation","deviceId":"TAMPERED","installId":"inst","licenseRef":"LIC","issuedAt":1700000000,"tokenExpiresAt":9999999999,"plan":"pro"}"#;
        let sig = sk.sign(good);
        let vk = sk.verifying_key();
        // 临时公钥验签（不影响全局）
        assert!(vk.verify(bad, &sig).is_err(), "篡改后必须验签失败");
        let _ = vk;
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn base64url_encode(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
}
