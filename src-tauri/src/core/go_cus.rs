//! Go Cus —— 全兼容覆写 / 改写 / MitM / 脚本引擎（Pro 专属）
//!
//! 能力总览：
//! 1. **全兼容模块解析**：Surge `.sgmodule` / QuantumultX `[rewrite_local]+[filter_local]`
//!    / Loon / Stash `.stoverride`，统一解析为 Rule / URL-Rewrite / Script / MitM / Host；
//! 2. **配置编译**：模块规则 → sing-box 路由规则（REJECT→block、DIRECT→direct、
//!    其他→主策略组）；DNS 覆写；[Host] 映射；MitM 域名路由到本地边车；
//! 3. **本地边车**（127.0.0.1:2081）：HTTP/1.1 改写管线，覆盖 reject 全动作、
//!    302/307、请求/响应头改写、沙盒 JS 脚本；
//! 4. **MitM**：对 `[MITM] hostname` 命中的 CONNECT 用已生成的 Root CA 动态签发
//!    叶子证书做 TLS 终结，非 MitM 的 CONNECT 仍透明隧道转发；
//! 5. **命中统计**：静态 DashMap + AtomicU64，键 `<module_id>` / `<module_id>#<rule_index>`。
//!
//! 安全护栏（编译与边车匹配双处生效）：
//! `prism.sarl` / `localhost` / `127.0.0.1` / `::1` / `*.local` / RFC1918 /
//! `100.64.0.0/10` / `fd00::/8` 永不被改写、阻断或解密。MitM 另有硬编码
//! 永不解密名单（Apple / iCloud / 支付宝 / 微信 / 各大银行）。

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use dashmap::DashMap;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value, json};
use tauri::Manager;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::core::go_cus_script;
use crate::core::logger::{self, MOD_GO_CUS};

/// 边车出站 tag（sing-box 配置中引用）
pub const SIDECAR_TAG: &str = "go-cus-sidecar";
/// 本地边车监听端口
pub const SIDECAR_PORT: u16 = 2081;
/// CA 证书分发服务端口
pub const CA_PORT: u16 = 2082;

/// 单次请求缓冲上限（超过则退化为原始透传，不执行响应改写/脚本）
const MAX_FORWARD_BODY: usize = 8 * 1024 * 1024;
/// 脚本源码读取上限
const MAX_SCRIPT_SOURCE: usize = 96 * 1024;
/// MitM 叶子证书缓存上限
const LEAF_CACHE_CAP: usize = 64;

// ---------------------------------------------------------------- 设置与模块模型

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CusRewriteRule {
    /// URL 正则（兼容 Surge/QuanX 写法）
    pub pattern: String,
    /// reject | reject-200 | reject-img | reject-tinygif | reject-dict |
    /// reject-array | 302 | 307 | header-request | header-response | none
    pub action: String,
    /// 重定向目标 / 头改写规格
    pub target: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CusScriptRule {
    pub name: String,
    /// http-request | http-response | cron
    #[serde(rename = "type")]
    pub kind: String,
    pub pattern: Option<String>,
    pub script_path: String,
    pub requires_body: bool,
    pub cron: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CusModuleStats {
    pub rules: u32,
    pub rewrites: u32,
    pub scripts: u32,
    pub mitm_hosts: u32,
    pub hosts: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CusModule {
    pub id: String,
    pub name: String,
    pub desc: Option<String>,
    /// http(s)://… 远程来源 或 local
    pub source: String,
    pub raw_content: String,
    pub enabled: bool,
    pub stats: CusModuleStats,
    pub updated_at: u64,
    /// 运行期命中次数（不持久化真实值；序列化时实时从命中表读取）
    #[serde(default)]
    pub hits: u64,
}

/// 手工序列化：`hits` 取自运行时命中表，保证 `get_go_cus_settings`
/// 无需改动命令层即可返回实时计数。
impl Serialize for CusModule {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut st = serializer.serialize_struct("CusModule", 9)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("name", &self.name)?;
        st.serialize_field("desc", &self.desc)?;
        st.serialize_field("source", &self.source)?;
        st.serialize_field("rawContent", &self.raw_content)?;
        st.serialize_field("enabled", &self.enabled)?;
        st.serialize_field("stats", &self.stats)?;
        st.serialize_field("updatedAt", &self.updated_at)?;
        st.serialize_field("hits", &module_hits(&self.id))?;
        st.end()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoCusSettings {
    #[serde(default)]
    pub enabled: bool,
    /// MitM 开关（仅对模块声明的 hostname 生效）
    #[serde(default)]
    pub mitm_enabled: bool,
    /// 手动 DNS 覆写（优先于模块 [General] dns-server）
    #[serde(default)]
    pub dns_override: Option<String>,
    /// 手动 [Host] 映射（domain → ip/域名）
    #[serde(default)]
    pub host_overrides: Vec<(String, String)>,
    #[serde(default)]
    pub modules: Vec<CusModule>,
    /// 用户已安装 CA 后回执置位
    #[serde(default)]
    pub ca_installed: bool,
}

impl Default for GoCusSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            mitm_enabled: false,
            dns_override: None,
            host_overrides: Vec::new(),
            modules: Vec::new(),
            ca_installed: false,
        }
    }
}

// ---------------------------------------------------------------- 持久化

pub fn load(data_dir: &std::path::Path) -> GoCusSettings {
    match std::fs::read_to_string(data_dir.join("go_cus.json")) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => GoCusSettings::default(),
    }
}

pub fn save(data_dir: &std::path::Path, settings: &GoCusSettings) -> Result<(), String> {
    let text = serde_json::to_string_pretty(settings).map_err(|e| e.to_string())?;
    std::fs::write(data_dir.join("go_cus.json"), text).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- 命中统计

static HITS: Lazy<DashMap<String, AtomicU64>> = Lazy::new(DashMap::new);

fn record_hit(module_id: &str, kind: &str, rule_index: usize) {
    let bump = |key: String| {
        HITS.entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    };
    bump(module_id.to_string());
    bump(format!("{module_id}#{kind}:{rule_index}"));
}

fn module_hits(module_id: &str) -> u64 {
    HITS.get(module_id)
        .map(|v| v.value().load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// 命中快照：`{"modules":{id:n},"rules":{"id#rw:i":n},"total":n}`
/// 注意：`total` 仅按模块维累加，避免同一命中同时记入模块与规则后翻倍。
pub fn hits_snapshot() -> Value {
    let mut modules = Map::new();
    let mut rules = Map::new();
    let mut total: u64 = 0;
    for entry in HITS.iter() {
        let count = entry.value().load(Ordering::Relaxed);
        if entry.key().contains('#') {
            rules.insert(entry.key().clone(), json!(count));
        } else {
            total = total.saturating_add(count);
            modules.insert(entry.key().clone(), json!(count));
        }
    }
    json!({ "modules": modules, "rules": rules, "total": total })
}

/// 清空全部命中计数
pub fn reset_hits() {
    HITS.clear();
}

// ---------------------------------------------------------------- 通用解析

/// 解析产物（五类条目）
#[derive(Debug, Default)]
pub struct ParsedCusModule {
    pub name: Option<String>,
    pub desc: Option<String>,
    /// (kind, target, policy) policy ∈ block | direct | proxy
    pub rules: Vec<(String, String, String)>,
    pub rewrites: Vec<CusRewriteRule>,
    pub scripts: Vec<CusScriptRule>,
    pub mitm_hosts: Vec<String>,
    /// [Host] 映射 domain → 值
    pub hosts: Vec<(String, String)>,
    /// [General] dns-server 列表
    pub dns_servers: Vec<String>,
    /// 内联脚本源码映射：`inline:<hash>` → JS 源码
    pub inline_scripts: HashMap<String, String>,
}

impl ParsedCusModule {
    pub fn stats(&self) -> CusModuleStats {
        CusModuleStats {
            rules: self.rules.len() as u32,
            rewrites: self.rewrites.len() as u32,
            scripts: self.scripts.len() as u32,
            mitm_hosts: self.mitm_hosts.len() as u32,
            hosts: self.hosts.len() as u32,
        }
    }
}

/// 全兼容入口：自动识别 sgmodule/quanx/loon（行式）与 Stash YAML
pub fn parse_universal_module(raw: &str) -> ParsedCusModule {
    let trimmed = raw.trim_start();
    if trimmed.starts_with("name:") {
        if let Some(parsed) = parse_stash_yaml(raw) {
            return parsed;
        }
    }
    parse_line_based(raw)
}

fn is_section_header(line: &str) -> bool {
    line.starts_with('[') && line.ends_with(']')
}

fn section_name(line: &str) -> String {
    line.trim_start_matches('[')
        .trim_end_matches(']')
        .trim()
        .to_ascii_lowercase()
}

/// 解析 `# --- inline script <id> begin ---` / `end` 标记
fn parse_inline_marker(line: &str) -> Option<(String, bool)> {
    let rest = line.strip_prefix('#')?.trim();
    let rest = rest.strip_prefix("---")?.trim();
    let rest = rest.strip_suffix("---")?.trim();
    let lower = rest.to_ascii_lowercase();
    let after = lower.strip_prefix("inline script ")?;
    let raw_after = rest.get(14..)?.trim();
    if after.ends_with(" begin") {
        let id = raw_after[..raw_after.len().saturating_sub(6)].trim();
        if !id.is_empty() {
            return Some((id.to_string(), true));
        }
    } else if after.ends_with(" end") {
        let id = raw_after[..raw_after.len().saturating_sub(4)].trim();
        if !id.is_empty() {
            return Some((id.to_string(), false));
        }
    }
    None
}

/// 行式解析：Surge sgmodule / QuanX / Loon 通用状态机
fn parse_line_based(raw: &str) -> ParsedCusModule {
    let mut out = ParsedCusModule::default();
    let mut section = String::new();
    let mut inline_id: Option<String> = None;
    let mut inline_buf: Vec<String> = Vec::new();
    for raw_line in raw.lines() {
        let line = raw_line.trim();
        // 优先提取内联脚本注释块（`# --- inline script <hash> begin ---` ... `end ---`）
        if let Some(ref active_id) = inline_id {
            if let Some((marker_id, is_begin)) = parse_inline_marker(line) {
                if !is_begin && marker_id.eq_ignore_ascii_case(active_id) {
                    out.inline_scripts
                        .insert(format!("inline:{active_id}"), inline_buf.join("\n"));
                    inline_id = None;
                    inline_buf.clear();
                    continue;
                }
            }
            let code_line = raw_line
                .strip_prefix("# ")
                .or_else(|| raw_line.strip_prefix('#'))
                .unwrap_or(raw_line);
            inline_buf.push(code_line.to_string());
            continue;
        }
        if let Some((marker_id, is_begin)) = parse_inline_marker(line) {
            if is_begin {
                inline_id = Some(marker_id);
                inline_buf.clear();
                continue;
            }
        }
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("#!name=") {
            out.name = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("#!desc=") {
            out.desc = Some(rest.trim().to_string());
            continue;
        }
        if line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        if is_section_header(line) {
            section = section_name(line);
            continue;
        }
        match section.as_str() {
            "rule" | "filter_local" => {
                if let Some(r) = parse_module_rule_line(line) {
                    out.rules.push(r);
                }
            }
            "url rewrite" | "rewrite" | "rewrite_local" | "header rewrite" => {
                if let Some((rw, script)) = parse_rewrite_line(line) {
                    if let Some(s) = script {
                        out.scripts.push(s);
                    } else if let Some(r) = rw {
                        out.rewrites.push(r);
                    }
                }
            }
            "script" => {
                if let Some(s) = parse_script_line(line) {
                    out.scripts.push(s);
                }
            }
            "mitm" => {
                if let Some(rest) = line.split_once('=').map(|(_, v)| v) {
                    for host in split_hosts_value(rest) {
                        if !out.mitm_hosts.contains(&host) {
                            out.mitm_hosts.push(host);
                        }
                    }
                }
            }
            "general" => {
                if let Some((k, v)) = line.split_once('=') {
                    if k.trim().eq_ignore_ascii_case("dns-server") {
                        for d in v.split(',') {
                            let d = d.trim();
                            if !d.is_empty() && !out.dns_servers.contains(&d.to_string()) {
                                out.dns_servers.push(d.to_string());
                            }
                        }
                    }
                }
            }
            "host" => {
                if let Some((k, v)) = line.split_once('=') {
                    let domain = k.trim().trim_start_matches("*.").to_lowercase();
                    let value = v.trim().to_string();
                    if !domain.is_empty() && !value.is_empty() {
                        out.hosts.push((domain, value));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// MitM hostname 行值解析：去掉 %APPEND% / %INSERT%，保留 `*.` 与 `-exclude`
fn split_hosts_value(v: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    let cleaned = v.replace("%APPEND%", "").replace("%INSERT%", "");
    for h in cleaned.split(',') {
        let h = h.trim();
        if h.is_empty() || h == "-" {
            continue;
        }
        let h = h.to_lowercase();
        if !hosts.contains(&h) {
            hosts.push(h);
        }
    }
    hosts
}

/// 规则行解析（Surge/QuanX/Clash 通用）→ (kind, target, policy)
fn parse_module_rule_line(line: &str) -> Option<(String, String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return None;
    }
    let kind_raw = parts[0].to_ascii_uppercase();
    let kind = match kind_raw.as_str() {
        "HOST" => "DOMAIN".to_string(),
        "HOST-SUFFIX" => "DOMAIN-SUFFIX".to_string(),
        "HOST-KEYWORD" => "DOMAIN-KEYWORD".to_string(),
        "IP6-CIDR" => "IP-CIDR6".to_string(),
        other => other.to_string(),
    };
    if kind == "FINAL" {
        return Some(("FINAL".into(), "-".into(), normalize_policy(parts[1])));
    }
    if parts.len() < 3 {
        return None;
    }
    let flags = ["NO-RESOLVE", "FORCED-REMOTE-DNS", "UDP", "PRE-MATCH"];
    let mut idx = parts.len() - 1;
    while idx >= 2 && flags.contains(&parts[idx].to_ascii_uppercase().as_str()) {
        idx -= 1;
    }
    let policy = normalize_policy(parts[idx]);
    let target = parts[1..idx].join(",");
    if target.is_empty() {
        return None;
    }
    Some((kind, target, policy))
}

/// 策略归一：REJECT*→block，DIRECT→direct，其余→proxy
fn normalize_policy(policy: &str) -> String {
    let p = policy.trim();
    let upper = p.to_ascii_uppercase();
    if upper.starts_with("REJECT") {
        "block".into()
    } else if upper == "DIRECT" || upper == "DIRECT,NO-RESOLVE" {
        "direct".into()
    } else {
        "proxy".into()
    }
}

/// 改写动作归一（保持各 reject 变体彼此独立，不再折叠为同一值）
fn normalize_rewrite_action(action_raw: &str) -> Option<String> {
    let a = action_raw.trim().to_ascii_lowercase();
    let mapped = match a.as_str() {
        "reject" | "reject-drop" | "reject-403" => "reject",
        "reject-200" => "reject-200",
        "reject-img" => "reject-img",
        "reject-tinygif" => "reject-tinygif",
        "reject-dict" => "reject-dict",
        "reject-array" => "reject-array",
        "302" => "302",
        "307" => "307",
        "request-header" | "header" | "header-add" | "header-replace" | "header-del" => {
            "header-request"
        }
        "response-header" => "header-response",
        "echo" | "none" => "none",
        other if other.starts_with("script-") => return None,
        _ => return None,
    };
    Some(mapped.to_string())
}

/// 改写行解析。返回 (改写规则, 脚本规则)——script-* 动作产出脚本。
fn parse_rewrite_line(line: &str) -> Option<(Option<CusRewriteRule>, Option<CusScriptRule>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 3 {
        return None;
    }
    let pattern = tokens[0].to_string();

    // QuantumultX 风格：<regex> url <action> [target...]
    if tokens[1].eq_ignore_ascii_case("url") {
        let action_raw = tokens[2].to_ascii_lowercase();
        let target = tokens[3..].join(" ");
        return quanx_action(&pattern, &action_raw, &target);
    }

    // QuanX / Surge 头改写：<regex> request-header <spec> / response-header <spec>
    if tokens[1].eq_ignore_ascii_case("request-header")
        || tokens[1].eq_ignore_ascii_case("response-header")
    {
        let action = if tokens[1].eq_ignore_ascii_case("response-header") {
            "header-response"
        } else {
            "header-request"
        };
        let target = tokens[2..].join(" ");
        if target.is_empty() {
            return None;
        }
        return Some((
            Some(CusRewriteRule {
                pattern,
                action: action.into(),
                target: Some(target),
                enabled: true,
            }),
            None,
        ));
    }

    // Surge [Header Rewrite]：<regex> header-add|header-replace|header-del ...
    let head = tokens[1].to_ascii_lowercase();
    if head == "header-add" || head == "header-replace" || head == "header-del" {
        let target = tokens[1..].join(" ");
        return Some((
            Some(CusRewriteRule {
                pattern,
                action: "header-request".into(),
                target: Some(target),
                enabled: true,
            }),
            None,
        ));
    }

    // Surge / Shadowrocket 变体：<regex> - <302|307> <target>
    if (tokens[1] == "-" || tokens[1] == "_") && tokens.len() >= 4 {
        let action = tokens[2].to_ascii_lowercase();
        if matches!(action.as_str(), "302" | "307") {
            return Some((
                Some(CusRewriteRule {
                    pattern,
                    action,
                    target: Some(tokens[3..].join(" ")),
                    enabled: true,
                }),
                None,
            ));
        }
    }

    // Surge / Shadowrocket 风格：<regex> <target|-|_> <action>
    let action_raw = tokens[tokens.len() - 1].to_ascii_lowercase();
    let target = tokens[1..tokens.len() - 1].join(" ");
    let dash = target == "-" || target == "_";
    let Some(action) = normalize_rewrite_action(&action_raw) else {
        // 兼容 `^url - script-...` 形态
        if action_raw.starts_with("script-") {
            let kind = if action_raw.contains("response") {
                "http-response"
            } else {
                "http-request"
            };
            return Some((
                None,
                Some(CusScriptRule {
                    name: format!("script-{}", short_hash(&pattern)),
                    kind: kind.into(),
                    pattern: Some(pattern),
                    script_path: target,
                    requires_body: action_raw.contains("body"),
                    cron: None,
                    enabled: true,
                }),
            ));
        }
        return None;
    };
    if (action == "302" || action == "307") && dash {
        return None;
    }
    Some((
        Some(CusRewriteRule {
            pattern,
            action,
            target: if dash { None } else { Some(target) },
            enabled: true,
        }),
        None,
    ))
}

/// QuanX 动作映射（含 script-* 展开为脚本规则）
fn quanx_action(
    pattern: &str,
    action_raw: &str,
    target: &str,
) -> Option<(Option<CusRewriteRule>, Option<CusScriptRule>)> {
    if action_raw.starts_with("script-") {
        let kind = if action_raw.contains("response") {
            "http-response"
        } else {
            "http-request"
        };
        return Some((
            None,
            Some(CusScriptRule {
                name: format!("script-{}", short_hash(pattern)),
                kind: kind.into(),
                pattern: Some(pattern.to_string()),
                script_path: target.to_string(),
                requires_body: action_raw.contains("body"),
                cron: None,
                enabled: true,
            }),
        ));
    }
    let action = normalize_rewrite_action(action_raw)?;
    Some((
        Some(CusRewriteRule {
            pattern: pattern.to_string(),
            action,
            target: if target.is_empty() {
                None
            } else {
                Some(target.to_string())
            },
            enabled: true,
        }),
        None,
    ))
}

/// 脚本行解析：kv 风格（name = type=…,…）与位置风格（http-response ^url …）
fn parse_script_line(line: &str) -> Option<CusScriptRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (name, kv_text): (Option<String>, &str) = if let Some((n, rest)) = line.split_once('=') {
        if rest.contains("type=") {
            (Some(n.trim().to_string()), rest)
        } else {
            (None, line)
        }
    } else {
        (None, line)
    };
    let mut kind = String::new();
    let mut pattern = None;
    let mut path = String::new();
    let mut requires_body = false;
    let mut cron = None;
    let mut tag: Option<String> = None;
    let mut first_two: Vec<&str> = Vec::new();
    for kv in kv_text.split(',') {
        let kv = kv.trim();
        if kv.is_empty() {
            continue;
        }
        if let Some((k, v)) = kv.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            match k.as_str() {
                "type" => kind = v.to_ascii_lowercase(),
                "pattern" => pattern = Some(v.to_string()),
                "script-path" | "path" => path = v.to_string(),
                "requires-body" => requires_body = v == "1" || v.eq_ignore_ascii_case("true"),
                "cron" => cron = Some(v.to_string()),
                "tag" => {
                    if !v.is_empty() {
                        tag = Some(v.to_string());
                    }
                }
                _ => {}
            }
        } else if first_two.len() < 2 {
            first_two.push(kv);
        }
    }
    if kind.is_empty() {
        if let Some(t) = first_two.first() {
            kind = t.to_ascii_lowercase();
        }
    }
    if pattern.is_none() {
        if let Some(p) = first_two.get(1) {
            pattern = Some(p.to_string());
        }
    }
    if kind.is_empty() || path.is_empty() {
        return None;
    }
    Some(CusScriptRule {
        name: name
            .or(tag)
            .unwrap_or_else(|| format!("script-{}", short_hash(&path))),
        kind,
        pattern,
        script_path: path,
        requires_body,
        cron,
        enabled: true,
    })
}

/// Stash / Clash 覆写 YAML 解析（rules: 列表）
fn parse_stash_yaml(raw: &str) -> Option<ParsedCusModule> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(raw).ok()?;
    let mut out = ParsedCusModule::default();
    if let Some(n) = yaml.get("name").and_then(|v| v.as_str()) {
        out.name = Some(n.to_string());
    }
    if let Some(d) = yaml.get("desc").and_then(|v| v.as_str()) {
        out.desc = Some(d.to_string());
    }
    if let Some(rules) = yaml.get("rules").and_then(|v| v.as_sequence()) {
        for r in rules.iter().filter_map(|v| v.as_str()) {
            if let Some(rule) = parse_module_rule_line(r) {
                out.rules.push(rule);
            }
        }
    }
    if out.rules.is_empty() && out.rewrites.is_empty() {
        return None;
    }
    Some(out)
}

fn short_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:08x}")
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ---------------------------------------------------------------- 安全护栏

/// 永不被改写 / 阻断 / 解密的本地与内网主机名
pub(crate) fn is_guardrail_host(host: &str) -> bool {
    let h = host
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('-')
        .trim_start_matches('+')
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h.is_empty() {
        return true;
    }
    if h == "prism.sarl" || h.ends_with(".prism.sarl") {
        return true;
    }
    if h == "localhost" || h.ends_with(".localhost") || h == "local" || h.ends_with(".local") {
        return true;
    }
    if h == "127.0.0.1" || h == "::1" || h == "0.0.0.0" || h == "[::1]" {
        return true;
    }
    match h.parse::<std::net::IpAddr>() {
        Ok(ip) => is_guardrail_ip(ip),
        Err(_) => false,
    }
}

fn is_guardrail_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        std::net::IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || (seg[0] & 0xfe00) == 0xfc00
                || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

/// 硬编码永不解密域名（含子域）
const NEVER_MITM_SUFFIXES: &[&str] = &[
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    "alipay.com",
    "wechat.com",
    "icbc.com.cn",
    "ccb.com",
    "abchina.com",
    "boc.cn",
    "cmbchina.com",
];

/// 是否属于硬编码永不解密名单
pub(crate) fn is_never_mitm_host(host: &str) -> bool {
    let h = host
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('-')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if is_guardrail_host(&h) {
        return true;
    }
    NEVER_MITM_SUFFIXES
        .iter()
        .any(|suffix| h == *suffix || h.ends_with(&format!(".{suffix}")))
}

/// MitM hostname 通配匹配（支持 `*.example.com`；非通配为精确匹配）
fn host_matches_pattern(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = p.strip_prefix("*.") {
        h == suffix || h.ends_with(&format!(".{suffix}"))
    } else if let Some(suffix) = p.strip_prefix('.') {
        h == suffix || h.ends_with(&format!(".{suffix}"))
    } else {
        h == p
    }
}

/// 综合判定：是否对 host 做 TLS 终止
fn mitm_should_decrypt(patterns: &[String], host: &str) -> bool {
    if is_never_mitm_host(host) {
        return false;
    }
    let mut included = false;
    for pattern in patterns {
        let p = pattern.trim();
        if let Some(exclude) = p.strip_prefix('-') {
            if host_matches_pattern(exclude, host) {
                return false;
            }
        } else if host_matches_pattern(p, host) {
            included = true;
        }
    }
    included
}

// ---------------------------------------------------------------- 运行时缓存

struct RuntimeRewrite {
    rule: CusRewriteRule,
    re: Option<regex::Regex>,
}

struct RuntimeScript {
    rule: CusScriptRule,
    re: Option<regex::Regex>,
}

struct RuntimeModule {
    rewrites: Vec<RuntimeRewrite>,
    scripts: Vec<RuntimeScript>,
    inline_scripts: HashMap<String, String>,
}

static MODULE_CACHE: Lazy<DashMap<u64, Arc<RuntimeModule>>> = Lazy::new(DashMap::new);

fn runtime_module(module: &CusModule) -> Arc<RuntimeModule> {
    let key = fnv1a(module.raw_content.as_bytes()) ^ fnv1a(module.id.as_bytes()).rotate_left(17);
    if let Some(hit) = MODULE_CACHE.get(&key) {
        return hit.clone();
    }
    let parsed = parse_universal_module(&module.raw_content);
    let rewrites = parsed
        .rewrites
        .into_iter()
        .map(|rule| RuntimeRewrite {
            re: regex::Regex::new(&rule.pattern).ok(),
            rule,
        })
        .collect();
    let scripts = parsed
        .scripts
        .into_iter()
        .map(|rule| RuntimeScript {
            re: rule
                .pattern
                .as_ref()
                .and_then(|p| regex::Regex::new(p).ok()),
            rule,
        })
        .collect();
    let runtime = Arc::new(RuntimeModule {
        rewrites,
        scripts,
        inline_scripts: parsed.inline_scripts,
    });
    if MODULE_CACHE.len() > 64 {
        MODULE_CACHE.clear();
    }
    MODULE_CACHE.insert(key, runtime.clone());
    runtime
}

// ---------------------------------------------------------------- 编译

#[derive(Debug, Default)]
pub(crate) struct CusCompiled {
    pub rules: Vec<Value>,
    pub sidecar_domains: Vec<String>,
    pub sidecar_needed: bool,
    pub dns_local_domains: Vec<String>,
    pub dns_override: Option<String>,
    pub warnings: Vec<String>,
}

/// 从 URL 正则中提取可路由域名，并丢弃护栏主机名
fn safe_domains_from_pattern(pattern: &str) -> Vec<String> {
    extract_domains_from_pattern(pattern)
        .into_iter()
        .filter(|d| {
            if is_guardrail_host(d) {
                logger::warn(
                    MOD_GO_CUS,
                    format!("安全护栏：已丢弃主机名 {d}（来源规则 {pattern}）"),
                );
                false
            } else {
                true
            }
        })
        .collect()
}

/// 编译全部启用模块 + 手动覆写设置
pub(crate) fn compile(settings: &GoCusSettings, proxy_tag: &str) -> CusCompiled {
    let mut out = CusCompiled::default();
    if !settings.enabled {
        return out;
    }
    let mut rule_buckets: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut block_domains: Vec<String> = Vec::new();

    let push_rule = |kind: &str, policy: &str, targets: Vec<String>, out: &mut CusCompiled| {
        let matcher = match kind {
            "DOMAIN" => "domain",
            "DOMAIN-SUFFIX" => "domain_suffix",
            "DOMAIN-KEYWORD" => "domain_keyword",
            "IP-CIDR" | "IP-CIDR6" => "ip_cidr",
            "GEOIP" => "geoip",
            other => {
                out.warnings
                    .push(format!("Go Cus 规则类型 {other} 暂不支持，已忽略"));
                return;
            }
        };
        let policy_out = match policy {
            "block" => "block",
            "direct" => "direct",
            _ => proxy_tag,
        };
        out.rules
            .push(json!({ matcher: targets, "outbound": policy_out }));
    };

    for module in &settings.modules {
        if !module.enabled {
            continue;
        }
        let parsed = parse_universal_module(&module.raw_content);
        for (kind, target, policy) in &parsed.rules {
            if kind == "FINAL" {
                out.warnings
                    .push("Go Cus 模块 FINAL 规则暂不支持，已忽略".into());
                continue;
            }
            if kind == "URL-REGEX" {
                out.warnings
                    .push("Go Cus 模块 URL-REGEX 规则暂不支持（已按域名提取尝试）".into());
                block_domains.extend(safe_domains_from_pattern(target));
                continue;
            }
            if matches!(kind.as_str(), "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD")
                && is_guardrail_host(target)
            {
                logger::warn(
                    MOD_GO_CUS,
                    format!(
                        "安全护栏：已丢弃规则主机名 {target}（模块 {}）",
                        module.name
                    ),
                );
                continue;
            }
            if let Some(bucket) = rule_buckets.last_mut() {
                if &bucket.0 == kind && &bucket.1 == policy {
                    bucket.2.push(target.clone());
                    continue;
                }
            }
            rule_buckets.push((kind.clone(), policy.clone(), vec![target.clone()]));
        }
        // 改写：reject 族阻断域名；302/307/header 域名走边车
        for rw in &parsed.rewrites {
            if !rw.enabled {
                continue;
            }
            let domains = safe_domains_from_pattern(&rw.pattern);
            match rw.action.as_str() {
                "reject" | "reject-200" | "reject-img" | "reject-tinygif" | "reject-dict"
                | "reject-array" => block_domains.extend(domains),
                "302" | "307" | "header-request" | "header-response" => {
                    out.sidecar_domains.extend(domains)
                }
                _ => {}
            }
        }
        // 脚本：pattern 域名走边车
        for s in &parsed.scripts {
            if !s.enabled {
                continue;
            }
            if let Some(p) = &s.pattern {
                out.sidecar_domains.extend(safe_domains_from_pattern(p));
            }
        }
        // MitM hostname（护栏 + 永不解密名单直接丢弃）
        if settings.mitm_enabled {
            for h in &parsed.mitm_hosts {
                if h.starts_with('-') {
                    continue;
                }
                let host = h.trim_start_matches("*.").to_string();
                if is_guardrail_host(&host) {
                    logger::warn(
                        MOD_GO_CUS,
                        format!("安全护栏：已丢弃 MitM 主机名 {h}（模块 {}）", module.name),
                    );
                    continue;
                }
                if is_never_mitm_host(&host) {
                    logger::warn(
                        MOD_GO_CUS,
                        format!("MitM 永不解密名单：已忽略 {h}（模块 {}）", module.name),
                    );
                    continue;
                }
                out.sidecar_domains.push(host);
            }
        }
        // [Host] 映射
        for (domain, value) in &parsed.hosts {
            if is_guardrail_host(domain) {
                logger::warn(
                    MOD_GO_CUS,
                    format!(
                        "安全护栏：已丢弃 [Host] 主机名 {domain}（模块 {}）",
                        module.name
                    ),
                );
                continue;
            }
            let v = value.to_ascii_lowercase();
            if v.starts_with("0.0.0.0")
                || v.starts_with("127.0.0.1")
                || v == "::1"
                || v == "-"
                || v == "reject"
            {
                block_domains.push(domain.clone());
            } else {
                out.dns_local_domains.push(domain.clone());
            }
        }
        if out.dns_override.is_none() {
            if let Some(d) = parsed.dns_servers.first() {
                out.dns_override = Some(d.clone());
            }
        }
    }

    for (domain, value) in &settings.host_overrides {
        if is_guardrail_host(domain) {
            logger::warn(
                MOD_GO_CUS,
                format!("安全护栏：已丢弃手动 [Host] 主机名 {domain}"),
            );
            continue;
        }
        let v = value.to_ascii_lowercase();
        if v.starts_with("0.0.0.0") || v.starts_with("127.0.0.1") || v == "::1" || v == "reject" {
            block_domains.push(domain.clone());
        } else {
            out.dns_local_domains.push(domain.clone());
        }
    }
    if let Some(d) = &settings.dns_override {
        if !d.trim().is_empty() {
            out.dns_override = Some(d.trim().to_string());
        }
    }

    block_domains.sort();
    block_domains.dedup();
    out.sidecar_domains.sort();
    out.sidecar_domains.dedup();
    out.dns_local_domains.sort();
    out.dns_local_domains.dedup();

    if !block_domains.is_empty() {
        if let Some(bucket) = rule_buckets
            .iter_mut()
            .find(|(k, p, _)| k == "DOMAIN-SUFFIX" && p == "block")
        {
            bucket.2.extend(block_domains);
            bucket.2.sort();
            bucket.2.dedup();
        } else {
            rule_buckets.push(("DOMAIN-SUFFIX".into(), "block".into(), block_domains));
        }
    }
    for (kind, policy, targets) in &rule_buckets {
        push_rule(kind, policy, targets.clone(), &mut out);
    }
    if !out.sidecar_domains.is_empty() {
        out.sidecar_needed = true;
        out.rules
            .push(json!({ "domain_suffix": out.sidecar_domains.clone(), "outbound": SIDECAR_TAG }));
    }
    if !out.dns_local_domains.is_empty() {
        out.warnings.push(
            "Go Cus [Host] 静态映射已降级为本地直连 DNS 解析（内核 1.11 暂不支持静态记录，1.12 起可完整支持）"
                .into(),
        );
    }
    out
}

/// 从 URL 正则中提取可路由的域名（\. → . 后匹配域名形态 token）
pub(crate) fn extract_domains_from_pattern(pattern: &str) -> Vec<String> {
    let unescaped = pattern.replace("\\.", ".");
    let re = regex::Regex::new(r"([A-Za-z0-9-]+\.)+[A-Za-z]{2,}").expect("内置正则必然合法");
    let mut out: Vec<String> = Vec::new();
    for m in re.find_iter(&unescaped) {
        let d = m.as_str().trim_end_matches('.').to_lowercase();
        if d.split('.').count() >= 2 && !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

/// 是否存在至少 1 条启用的 rewrite / header / mitm / script 规则
pub(crate) fn has_active_rules(settings: &GoCusSettings) -> bool {
    if !settings.enabled {
        return false;
    }
    settings.modules.iter().filter(|m| m.enabled).any(|m| {
        let parsed = parse_universal_module(&m.raw_content);
        parsed
            .rewrites
            .iter()
            .any(|r| r.enabled && r.action != "none")
            || parsed.scripts.iter().any(|s| s.enabled)
            || (settings.mitm_enabled && !parsed.mitm_hosts.is_empty())
    })
}

// ---------------------------------------------------------------- Header 改写

#[derive(Debug, Clone, PartialEq, Eq)]
enum HeaderOp {
    Add(String, String),
    Replace(String, String),
    Del(String),
}

/// 解析 `$(remove-X-Foo)` / `$(add-X-Foo: v)` / `$(replace-X-Foo: v)` 与
/// Surge 风格 `header-add X-Foo: v` / `header-replace` / `header-del`
fn parse_header_ops(spec: &str) -> Vec<HeaderOp> {
    let mut ops = Vec::new();
    let dollar = regex::Regex::new(r"\$\(([^)]*)\)").expect("内置正则必然合法");
    for cap in dollar.captures_iter(spec) {
        if let Some(op) = parse_header_op_inner(cap.get(1).map(|m| m.as_str()).unwrap_or("")) {
            ops.push(op);
        }
    }
    // Surge 风格（不在 $() 内）
    let rest = dollar.replace_all(spec, " ").to_string();
    let surge =
        regex::Regex::new(r"(?i)header-(add|replace|del)\s+([^,;]+)").expect("内置正则必然合法");
    for cap in surge.captures_iter(&rest) {
        let kind = cap
            .get(1)
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        let payload = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        if payload.is_empty() {
            continue;
        }
        match kind.as_str() {
            "del" => {
                let name = payload.split_whitespace().next().unwrap_or("").trim();
                if !name.is_empty() {
                    ops.push(HeaderOp::Del(name.to_ascii_lowercase()));
                }
            }
            "add" | "replace" => {
                if let Some((name, value)) = payload.split_once(':') {
                    let name = name.trim().to_ascii_lowercase();
                    if !name.is_empty() {
                        let value = value.trim().to_string();
                        ops.push(if kind == "add" {
                            HeaderOp::Add(name, value)
                        } else {
                            HeaderOp::Replace(name, value)
                        });
                    }
                }
            }
            _ => {}
        }
    }
    ops
}

fn parse_header_op_inner(inner: &str) -> Option<HeaderOp> {
    let text = inner.trim();
    if text.is_empty() {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("remove-") {
        let name = text[7..].trim().to_ascii_lowercase();
        if name.is_empty() {
            return None;
        }
        return Some(HeaderOp::Del(name));
    }
    if lower.starts_with("add-") {
        let rest = &text[4..];
        let (name, value) = rest.split_once(':')?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return None;
        }
        return Some(HeaderOp::Add(name, value.trim().to_string()));
    }
    if lower.starts_with("replace-") {
        let rest = &text[8..];
        let (name, value) = rest.split_once(':')?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return None;
        }
        return Some(HeaderOp::Replace(name, value.trim().to_string()));
    }
    None
}

fn apply_header_ops(headers: &mut Vec<(String, String)>, ops: &[HeaderOp]) {
    for op in ops {
        match op {
            HeaderOp::Del(name) => headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name)),
            HeaderOp::Add(name, value) => headers.push((name.clone(), value.clone())),
            HeaderOp::Replace(name, value) => {
                let mut replaced = false;
                for (k, v) in headers.iter_mut() {
                    if k.eq_ignore_ascii_case(name) {
                        *v = value.clone();
                        replaced = true;
                        break;
                    }
                }
                if !replaced {
                    headers.push((name.clone(), value.clone()));
                }
            }
        }
    }
}

// ---------------------------------------------------------------- 边车匹配

#[derive(Clone)]
struct MatchedRewrite {
    module_id: String,
    rule_index: usize,
    action: String,
    target: Option<String>,
    re: Option<regex::Regex>,
}

#[derive(Clone)]
struct MatchedScript {
    module_id: String,
    rule_index: usize,
    rule: CusScriptRule,
    inline_code: Option<String>,
}

#[derive(Default, Clone)]
struct MatchOutcome {
    terminal: Option<MatchedRewrite>,
    request_header_rules: Vec<(MatchedRewrite, Vec<HeaderOp>)>,
    response_header_rules: Vec<(MatchedRewrite, Vec<HeaderOp>)>,
    request_script: Option<MatchedScript>,
    response_script: Option<MatchedScript>,
}

impl MatchOutcome {
    fn is_empty(&self) -> bool {
        self.terminal.is_none()
            && self.request_header_rules.is_empty()
            && self.response_header_rules.is_empty()
            && self.request_script.is_none()
            && self.response_script.is_none()
    }

    fn request_header_ops(&self) -> Vec<HeaderOp> {
        self.request_header_rules
            .iter()
            .flat_map(|(_, ops)| ops.clone())
            .collect()
    }

    fn response_header_ops(&self) -> Vec<HeaderOp> {
        self.response_header_rules
            .iter()
            .flat_map(|(_, ops)| ops.clone())
            .collect()
    }
}

fn match_rules(settings: &GoCusSettings, url: &str) -> MatchOutcome {
    let mut out = MatchOutcome::default();
    if !settings.enabled {
        return out;
    }
    // 边车侧护栏：护栏主机名绝不匹配任何改写/脚本
    if let Some(host) = host_of(url) {
        if is_guardrail_host(&host) {
            return out;
        }
    }
    for module in settings.modules.iter().filter(|m| m.enabled) {
        let runtime = runtime_module(module);
        for (idx, rw) in runtime.rewrites.iter().enumerate() {
            if !rw.rule.enabled {
                continue;
            }
            let Some(re) = &rw.re else { continue };
            if !re.is_match(url) {
                continue;
            }
            let matched = MatchedRewrite {
                module_id: module.id.clone(),
                rule_index: idx,
                action: rw.rule.action.clone(),
                target: rw.rule.target.clone(),
                re: Some(re.clone()),
            };
            match matched.action.as_str() {
                "reject" | "reject-200" | "reject-img" | "reject-tinygif" | "reject-dict"
                | "reject-array" | "302" | "307" => {
                    if out.terminal.is_none() {
                        out.terminal = Some(matched);
                    }
                }
                "header-request" => {
                    let ops = parse_header_ops(matched.target.as_deref().unwrap_or(""));
                    if !ops.is_empty() {
                        out.request_header_rules.push((matched, ops));
                    }
                }
                "header-response" => {
                    let ops = parse_header_ops(matched.target.as_deref().unwrap_or(""));
                    if !ops.is_empty() {
                        out.response_header_rules.push((matched, ops));
                    }
                }
                _ => {}
            }
        }
        for (idx, script) in runtime.scripts.iter().enumerate() {
            if !script.rule.enabled {
                continue;
            }
            let Some(re) = &script.re else { continue };
            if !re.is_match(url) {
                continue;
            }
            let matched = MatchedScript {
                module_id: module.id.clone(),
                rule_index: idx,
                inline_code: runtime
                    .inline_scripts
                    .get(script.rule.script_path.trim())
                    .cloned(),
                rule: script.rule.clone(),
            };
            if script.rule.kind.contains("response") {
                if out.response_script.is_none() {
                    out.response_script = Some(matched);
                }
            } else if out.request_script.is_none() {
                out.request_script = Some(matched);
            }
        }
    }
    out
}

// ---------------------------------------------------------------- 响应构造

/// 1x1 透明 PNG
const TINY_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

/// 1x1 透明 GIF
const TINY_GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3B,
];

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        _ => "OK",
    }
}

fn build_simple_response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", status_text(status));
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// 终端动作（reject 族 / 302 / 307）响应
fn build_terminal_response(matched: &MatchedRewrite, url: &str) -> Vec<u8> {
    match matched.action.as_str() {
        "reject" => build_simple_response(403, &[], b""),
        "reject-200" => build_simple_response(200, &[], b""),
        "reject-img" => build_simple_response(200, &[("Content-Type", "image/png")], TINY_PNG),
        "reject-tinygif" => build_simple_response(200, &[("Content-Type", "image/gif")], TINY_GIF),
        "reject-dict" => build_simple_response(200, &[("Content-Type", "application/json")], b"{}"),
        "reject-array" => {
            build_simple_response(200, &[("Content-Type", "application/json")], b"[]")
        }
        action @ ("302" | "307") => {
            let status = if action == "302" { 302 } else { 307 };
            let location = match (&matched.target, &matched.re) {
                (Some(target), Some(re)) => re.replace(url, target.as_str()).to_string(),
                (Some(target), None) => target.clone(),
                _ => String::new(),
            };
            build_simple_response(status, &[("Location", &location)], b"")
        }
        _ => build_simple_response(403, &[], b""),
    }
}

// ---------------------------------------------------------------- 边车服务

static SIDECAR_STARTED: AtomicBool = AtomicBool::new(false);

fn sidecar_should_run(app: &tauri::AppHandle) -> bool {
    let state = app.state::<crate::core::state::AppState>();
    if !state.is_pro_active() {
        return false;
    }
    has_active_rules(&state.go_cus.read())
}

/// 确保边车已启动（进程内单例）。无任何启用的 rewrite/header/mitm/script
/// 规则时不监听 2081，避免空转占用端口。
pub fn ensure_sidecar(app: tauri::AppHandle) {
    if !sidecar_should_run(&app) {
        return;
    }
    if SIDECAR_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        if let Err(e) = run_sidecar(app).await {
            SIDECAR_STARTED.store(false, Ordering::Release);
            tracing::error!("[go-cus] 边车启动失败: {e}");
            logger::warn(MOD_GO_CUS, format!("边车启动失败: {e}"));
        }
    });
}

async fn run_sidecar(app: tauri::AppHandle) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", SIDECAR_PORT))
        .await
        .map_err(|e| format!("绑定 127.0.0.1:{SIDECAR_PORT} 失败: {e}"))?;
    tracing::info!("[go-cus] 边车已启动 127.0.0.1:{SIDECAR_PORT}");
    logger::info(
        MOD_GO_CUS,
        format!("边车已启动 127.0.0.1:{SIDECAR_PORT}（含 MitM TLS 终止）"),
    );
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = handle_sidecar_conn(app, stream).await;
        });
    }
}

/// 读取并解析 HTTP 请求头（最多 64KB），返回 (头, 头列表, 头之后剩余字节)
async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(String, Vec<(String, String)>, Vec<u8>), String> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let split = loop {
        if let Some(pos) = find_head_end(&buf) {
            break pos;
        }
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("连接在请求头结束前关闭".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err("请求头超过 64KB 上限".into());
        }
    };
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let leftover = buf[split..].to_vec();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((request_line, headers, leftover))
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split('/').next()?;
    split_authority(authority, 443).ok().map(|(h, _)| h)
}

/// authority → (host, port)；支持 `a.com:8080` 与 `[::1]:9090`
fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16), String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err("缺少主机名".into());
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or("IPv6 主机名缺少 ]")?;
        let host = rest[..end].to_string();
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !port.is_empty() => {
            let port = port
                .parse::<u16>()
                .map_err(|_| format!("非法端口: {port}"))?;
            Ok((host.to_string(), port))
        }
        _ => Ok((authority.to_string(), default_port)),
    }
}

/// 绝对 URL → (scheme, host, port, path)
fn split_url(url: &str) -> Result<(String, String, u16, String), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("非法 URL: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let default_port = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    let (host, port) = split_authority(authority, default_port)?;
    Ok((scheme.to_string(), host, port, path.to_string()))
}

async fn write_all<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> std::io::Result<()> {
    stream.write_all(data).await
}

async fn handle_sidecar_conn(
    app: tauri::AppHandle,
    mut stream: tokio::net::TcpStream,
) -> Result<(), String> {
    let (request_line, headers, leftover) = read_head(&mut stream).await?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Ok(());
    }
    let (settings, data_dir) = {
        let state = app.state::<crate::core::state::AppState>();
        (state.go_cus.read().clone(), state.data_dir.clone())
    };

    // ---- CONNECT：reject 拦截 / MitM TLS 终止 / 透明隧道 ----
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_authority(&target, 443)?;
        if settings.enabled {
            let probe_url = format!("https://{target}/");
            if let Some(terminal) = match_rules(&settings, &probe_url).terminal {
                if terminal.action.starts_with("reject") {
                    record_hit(&terminal.module_id, "rw", terminal.rule_index);
                    let resp = build_terminal_response(&terminal, &probe_url);
                    let _ = write_all(&mut stream, &resp).await;
                    return Ok(());
                }
            }
            if settings.mitm_enabled && mitm_should_decrypt(&mitm_patterns(&settings), &host) {
                return handle_mitm(app, stream, host, port, settings, data_dir).await;
            }
        }
        let mut upstream = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| format!("边车上游连接失败 {host}:{port}: {e}"))?;
        let _ = write_all(&mut stream, b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        return Ok(());
    }

    // ---- 绝对 / origin 形式 HTTP 请求 ----
    let url = if target.starts_with("http") {
        target.clone()
    } else {
        let host = header_get(&headers, "host").unwrap_or_default().to_string();
        format!("http://{host}{target}")
    };
    handle_http(
        &mut stream,
        &method,
        &url,
        &headers,
        leftover,
        &settings,
        &data_dir,
        false,
    )
    .await
}

/// 汇总全部启用模块的 MitM hostname 模式
fn mitm_patterns(settings: &GoCusSettings) -> Vec<String> {
    settings
        .modules
        .iter()
        .filter(|m| m.enabled)
        .flat_map(|m| parse_universal_module(&m.raw_content).mitm_hosts)
        .collect()
}

// ---------------------------------------------------------------- HTTP 处理

#[allow(clippy::too_many_arguments)]
async fn handle_http<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    leftover: Vec<u8>,
    settings: &GoCusSettings,
    data_dir: &Path,
    https_tunnel: bool,
) -> Result<(), String> {
    let host = host_of(url).unwrap_or_default();
    if host.is_empty() || is_guardrail_host(&host) {
        if https_tunnel {
            let resp = build_simple_response(403, &[], b"");
            return write_all(stream, &resp).await.map_err(|e| e.to_string());
        }
        return raw_forward(stream, method, url, headers, leftover, &[]).await;
    }
    let matched = match_rules(settings, url);
    if matched.is_empty() {
        if https_tunnel {
            let empty = MatchOutcome::default();
            let body = read_body_best_effort(stream, headers, leftover).await;
            return forward_via_reqwest(stream, method, url, headers, body, &empty, data_dir).await;
        }
        return raw_forward(stream, method, url, headers, leftover, &[]).await;
    }

    // 终端动作优先：不读 body，直接返回合成响应
    if let Some(terminal) = &matched.terminal {
        record_hit(&terminal.module_id, "rw", terminal.rule_index);
        let resp = build_terminal_response(terminal, url);
        return write_all(stream, &resp).await.map_err(|e| e.to_string());
    }

    let body = match read_request_body(stream, headers, leftover).await {
        Ok(body) => body,
        Err(reason) => {
            logger::warn(
                MOD_GO_CUS,
                format!("请求体不可缓冲（{reason}），已跳过响应改写/脚本: {url}"),
            );
            if https_tunnel {
                let resp = build_simple_response(413, &[], b"");
                return write_all(stream, &resp).await.map_err(|e| e.to_string());
            }
            let ops = matched.request_header_ops();
            for (hit, _) in &matched.request_header_rules {
                record_hit(&hit.module_id, "rw", hit.rule_index);
            }
            return raw_forward(stream, method, url, headers, Vec::new(), &ops).await;
        }
    };
    forward_via_reqwest(stream, method, url, headers, body, &matched, data_dir).await
}

/// 读取请求体（Content-Length 已知且 ≤ 8MB）；chunked / 超限返回 Err
async fn read_request_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    headers: &[(String, String)],
    leftover: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if let Some(te) = header_get(headers, "transfer-encoding") {
        if te.to_ascii_lowercase().contains("chunked") {
            return Err("chunked".into());
        }
    }
    let len = header_get(headers, "content-length")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if len > MAX_FORWARD_BODY {
        return Err("超过 8MB 缓冲上限".into());
    }
    let mut body = leftover;
    if body.len() >= len {
        body.truncate(len);
        return Ok(body);
    }
    while body.len() < len {
        let want = (len - body.len()).min(65536);
        let mut chunk = vec![0u8; want];
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(body)
}

/// MITM 透传路径：请求体尽力读取（不阻塞在 chunked 上）
async fn read_body_best_effort<S: AsyncRead + Unpin>(
    stream: &mut S,
    headers: &[(String, String)],
    leftover: Vec<u8>,
) -> Vec<u8> {
    read_request_body(stream, headers, leftover)
        .await
        .unwrap_or_default()
}

fn is_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "connection" | "proxy-connection" | "keep-alive"
    )
}

fn is_reqwest_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "content-length"
            | "transfer-encoding"
    )
}

/// 原始透传（不缓冲响应；仅可应用请求头改写）
async fn raw_forward<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    leftover: Vec<u8>,
    ops: &[HeaderOp],
) -> Result<(), String> {
    let (_scheme, host, port, path) = split_url(url)?;
    let mut upstream = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| format!("边车上游连接失败 {host}:{port}: {e}"))?;
    let mut out = headers.to_vec();
    out.retain(|(k, _)| !is_hop_header(k));
    apply_header_ops(&mut out, ops);
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in &out {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    let host_header = if port == 80 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    head.push_str(&format!("Host: {host_header}\r\nConnection: close\r\n\r\n"));
    write_all(&mut upstream, head.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    if !leftover.is_empty() {
        write_all(&mut upstream, &leftover)
            .await
            .map_err(|e| e.to_string())?;
    }
    let _ = tokio::io::copy_bidirectional(stream, &mut upstream).await;
    Ok(())
}

fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("内置 HTTP 客户端构建必然成功")
    })
}

fn headers_object(headers: &[(String, String)]) -> Value {
    let mut map = Map::new();
    for (k, v) in headers {
        map.insert(k.to_ascii_lowercase(), json!(v));
    }
    Value::Object(map)
}

fn object_to_headers(object: &Map<String, Value>) -> Vec<(String, String)> {
    object
        .iter()
        .map(|(k, v)| {
            let value = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            (k.clone(), value)
        })
        .collect()
}

fn value_to_bytes(value: &Value) -> Vec<u8> {
    match value {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Null => Vec::new(),
        other => other.to_string().into_bytes(),
    }
}

fn request_value(method: &str, url: &str, headers: &[(String, String)], body: &[u8]) -> Value {
    json!({
        "url": url,
        "method": method,
        "headers": headers_object(headers),
        "body": String::from_utf8_lossy(body),
    })
}

fn script_key(script: &MatchedScript) -> String {
    format!("{}#{}", script.module_id, script.rule_index)
}

/// 加载脚本源码：优先内联源码 `inline:<hash>`，其次 http(s) 远程带内存缓存，最后 data_dir 本地路径
async fn load_script_code(
    rule: &CusScriptRule,
    inline_code: Option<&str>,
    data_dir: &Path,
) -> Option<String> {
    static SCRIPT_CACHE: Lazy<DashMap<String, String>> = Lazy::new(DashMap::new);
    if let Some(code) = inline_code {
        if !code.trim().is_empty() {
            return Some(truncate_text(code, MAX_SCRIPT_SOURCE));
        }
    }
    let path = rule.script_path.trim();
    if path.is_empty() || path.starts_with("inline:") {
        return None;
    }
    if path.starts_with("http://") || path.starts_with("https://") {
        if let Some(cached) = SCRIPT_CACHE.get(path) {
            return Some(cached.clone());
        }
        match fetch_module_text(path).await {
            Ok(text) => {
                let text = truncate_text(&text, MAX_SCRIPT_SOURCE);
                SCRIPT_CACHE.insert(path.to_string(), text.clone());
                Some(text)
            }
            Err(e) => {
                logger::warn(MOD_GO_CUS, format!("脚本下载失败 {path}: {e}"));
                None
            }
        }
    } else {
        let candidate = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            data_dir.join(path)
        };
        let root = data_dir.canonicalize().ok()?;
        let real = candidate.canonicalize().ok()?;
        if !real.starts_with(&root) {
            logger::warn(
                MOD_GO_CUS,
                format!("本地脚本路径越界（仅允许 data_dir 内）: {path}"),
            );
            return None;
        }
        std::fs::read_to_string(real)
            .ok()
            .map(|text| truncate_text(&text, MAX_SCRIPT_SOURCE))
    }
}

fn truncate_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn apply_request_patch(
    patch: &Value,
    method: &mut String,
    url: &mut String,
    headers: &mut Vec<(String, String)>,
    body: &mut Vec<u8>,
) {
    if let Some(u) = patch.get("url").and_then(Value::as_str) {
        if !u.trim().is_empty() {
            *url = u.trim().to_string();
        }
    }
    if let Some(m) = patch.get("method").and_then(Value::as_str) {
        if !m.trim().is_empty() {
            *method = m.trim().to_ascii_uppercase();
        }
    }
    if let Some(h) = patch.get("headers").and_then(Value::as_object) {
        *headers = object_to_headers(h);
    }
    if let Some(b) = patch.get("body") {
        *body = value_to_bytes(b);
    }
}

/// 应用请求/响应头改写与脚本后转发，并回写响应
#[allow(clippy::too_many_arguments)]
async fn forward_via_reqwest<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: &mut S,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
    matched: &MatchOutcome,
    data_dir: &Path,
) -> Result<(), String> {
    let mut method = method.to_string();
    let mut url = url.to_string();
    let mut out_headers: Vec<(String, String)> = headers
        .iter()
        .filter(|(k, _)| !is_reqwest_hop_header(k))
        .cloned()
        .collect();
    apply_header_ops(&mut out_headers, &matched.request_header_ops());
    for (hit, _) in &matched.request_header_rules {
        record_hit(&hit.module_id, "rw", hit.rule_index);
    }
    let mut body = body;

    // 请求脚本（放到阻塞线程池执行 boa_engine，不阻塞 tokio worker）
    if let Some(script) = &matched.request_script {
        if let Some(code) =
            load_script_code(&script.rule, script.inline_code.as_deref(), data_dir).await
        {
            if go_cus_script::body_allowed(body.len()) {
                let req_value = request_value(&method, &url, &out_headers, &body);
                let data_dir_owned = data_dir.to_path_buf();
                let key = script_key(script);
                let run_res = tokio::task::spawn_blocking(move || {
                    go_cus_script::run_script(&data_dir_owned, &key, &code, &req_value, None)
                })
                .await
                .unwrap_or_else(|e| Err(format!("脚本任务异常: {e}")));
                match run_res {
                    Ok(run) => {
                        record_hit(&script.module_id, "sc", script.rule_index);
                        if let Some(done) = run.done {
                            if let Some(resp) = done.get("response") {
                                return write_json_response(stream, resp).await;
                            }
                            if let Some(patch) = done.get("request") {
                                apply_request_patch(
                                    patch,
                                    &mut method,
                                    &mut url,
                                    &mut out_headers,
                                    &mut body,
                                );
                            }
                        }
                    }
                    Err(e) => logger::warn(MOD_GO_CUS, format!("请求脚本已跳过: {e}")),
                }
            }
        }
    }

    // 护栏二次校验（脚本可能改写 URL）
    if let Some(host) = host_of(&url) {
        if is_guardrail_host(&host) {
            logger::warn(
                MOD_GO_CUS,
                format!("安全护栏：脚本把请求指向护栏主机 {host}，已拒绝"),
            );
            return write_http_response(stream, 403, &[], b"").await;
        }
    }

    let reqwest_method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|e| format!("非法请求方法 {method}: {e}"))?;
    let mut builder = http_client().request(reqwest_method, &url);
    for (k, v) in &out_headers {
        builder = builder.header(k, v);
    }
    if !body.is_empty() {
        builder = builder.body(body.clone());
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("边车上游请求失败 {url}: {e}"))?;
    let mut status = resp.status().as_u16();
    let mut resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let mut resp_body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();

    apply_header_ops(&mut resp_headers, &matched.response_header_ops());
    for (hit, _) in &matched.response_header_rules {
        record_hit(&hit.module_id, "rw", hit.rule_index);
    }

    // 响应脚本
    if let Some(script) = &matched.response_script {
        if let Some(code) =
            load_script_code(&script.rule, script.inline_code.as_deref(), data_dir).await
        {
            if go_cus_script::body_allowed(resp_body.len()) {
                let req_value = request_value(&method, &url, &out_headers, &body);
                let resp_value = json!({
                    "status": status,
                    "headers": headers_object(&resp_headers),
                    "body": String::from_utf8_lossy(&resp_body),
                });
                let data_dir_owned = data_dir.to_path_buf();
                let key = script_key(script);
                let run_res = tokio::task::spawn_blocking(move || {
                    go_cus_script::run_script(
                        &data_dir_owned,
                        &key,
                        &code,
                        &req_value,
                        Some(&resp_value),
                    )
                })
                .await
                .unwrap_or_else(|e| Err(format!("脚本任务异常: {e}")));
                match run_res {
                    Ok(run) => {
                        record_hit(&script.module_id, "sc", script.rule_index);
                        if let Some(done) = run.done {
                            if let Some(resp) = done.get("response") {
                                if let Some(s) = resp.get("status").and_then(Value::as_u64) {
                                    status = s as u16;
                                }
                                if let Some(h) = resp.get("headers").and_then(Value::as_object) {
                                    resp_headers = object_to_headers(h);
                                }
                                if let Some(b) = resp.get("body") {
                                    resp_body = value_to_bytes(b);
                                }
                            }
                        }
                    }
                    Err(e) => logger::warn(MOD_GO_CUS, format!("响应脚本已跳过: {e}")),
                }
            }
        }
    }

    write_http_response(stream, status, &resp_headers, &resp_body).await
}

async fn write_http_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), String> {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", status_text(status));
    for (k, v) in headers {
        let lower = k.to_ascii_lowercase();
        if lower == "content-length" || lower == "transfer-encoding" || lower == "connection" {
            continue;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    write_all(stream, head.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    if !body.is_empty() {
        write_all(stream, body).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// 脚本返回的 `{status, headers, body}` → HTTP 响应
async fn write_json_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    resp: &Value,
) -> Result<(), String> {
    let status = resp.get("status").and_then(Value::as_u64).unwrap_or(200) as u16;
    let headers = resp
        .get("headers")
        .and_then(Value::as_object)
        .map(object_to_headers)
        .unwrap_or_default();
    let body = resp.get("body").map(value_to_bytes).unwrap_or_default();
    write_http_response(stream, status, &headers, &body).await
}

// ---------------------------------------------------------------- MitM

struct LeafCache {
    order: VecDeque<String>,
    map: HashMap<String, Arc<tokio_rustls::rustls::ServerConfig>>,
}

static LEAF_CACHE: Lazy<Mutex<LeafCache>> = Lazy::new(|| {
    Mutex::new(LeafCache {
        order: VecDeque::new(),
        map: HashMap::new(),
    })
});

fn ca_stamp(data_dir: &Path) -> u64 {
    std::fs::metadata(data_dir.join("go_cus_ca.crt"))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 动态签发叶子证书并构造 rustls ServerConfig（LRU 上限 64）
fn mitm_server_config(
    data_dir: &Path,
    host: &str,
) -> Result<Arc<tokio_rustls::rustls::ServerConfig>, String> {
    let cache_key = format!("{host}|{}", ca_stamp(data_dir));
    {
        let cache = LEAF_CACHE.lock();
        if let Some(cfg) = cache.map.get(&cache_key) {
            return Ok(cfg.clone());
        }
    }

    use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let (_crt_pem, key_pem) = ensure_ca_files(data_dir)?;
    let ca_key = KeyPair::from_pem(&key_pem).map_err(|e| format!("CA 私钥解析失败: {e}"))?;
    // 用与 CA 生成时完全一致的参数重建签发者对象：DN 与 KeyIdentifier 均由
    // 同一私钥推导，因此签出的叶子证书能被已安装的 Root CA 正常验证。
    // （避免为解析 PEM 引入 x509-parser 依赖，保持四端交叉编译零额外负担。）
    let ca_cert = ca_params()?
        .self_signed(&ca_key)
        .map_err(|e| format!("CA 证书重建失败: {e}"))?;

    let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = CertificateParams::new(vec![host.to_string()])
        .map_err(|e| format!("叶子证书参数失败: {e}"))?;
    params.distinguished_name.push(DnType::CommonName, host);
    params.is_ca = IsCa::ExplicitNoCa;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);
    let leaf = params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(|e| format!("叶子证书签发失败: {e}"))?;

    let certs = vec![leaf.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("MitM TLS 配置失败: {e}"))?;
    // 只协商 HTTP/1.1，避免 h2 帧解析复杂度
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);

    let mut cache = LEAF_CACHE.lock();
    cache.map.insert(cache_key.clone(), config.clone());
    cache.order.push_back(cache_key);
    while cache.order.len() > LEAF_CACHE_CAP {
        if let Some(old) = cache.order.pop_front() {
            cache.map.remove(&old);
        }
    }
    Ok(config)
}

async fn handle_mitm(
    app: tauri::AppHandle,
    mut stream: tokio::net::TcpStream,
    host: String,
    port: u16,
    settings: GoCusSettings,
    data_dir: PathBuf,
) -> Result<(), String> {
    if write_all(&mut stream, b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return Ok(());
    }
    let config = mitm_server_config(&data_dir, &host)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let mut tls = match acceptor.accept(stream).await {
        Ok(tls) => tls,
        Err(e) => {
            logger::warn(MOD_GO_CUS, format!("MitM TLS 握手失败 {host}: {e}"));
            return Ok(());
        }
    };
    drop(app);
    let (request_line, headers, leftover) = match read_head(&mut tls).await {
        Ok(v) => v,
        Err(e) => {
            logger::warn(MOD_GO_CUS, format!("MitM 请求读取失败 {host}: {e}"));
            return Ok(());
        }
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let path = if path.starts_with("http") {
        // 绝对形式：取 path 部分
        path.split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_string()))
            .unwrap_or_else(|| "/".to_string())
    } else {
        path
    };
    let url = if port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{port}{path}")
    };
    handle_http(
        &mut tls, &method, &url, &headers, leftover, &settings, &data_dir, true,
    )
    .await
}

// ---------------------------------------------------------------- CA 证书管理

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaInfo {
    pub exists: bool,
    pub fingerprint: String,
    pub install_url: String,
    pub cert_url: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaMeta {
    not_before: String,
    not_after: String,
}

fn format_iso_date(dt: time::OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}", dt.year(), u8::from(dt.month()), dt.day())
}

fn read_or_infer_ca_validity(data_dir: &Path) -> (Option<String>, Option<String>) {
    let meta_path = data_dir.join("go_cus_ca.meta.json");
    if let Ok(text) = std::fs::read_to_string(&meta_path) {
        if let Ok(meta) = serde_json::from_str::<CaMeta>(&text) {
            return (Some(meta.not_before), Some(meta.not_after));
        }
    }
    if let Ok(mtime) = std::fs::metadata(data_dir.join("go_cus_ca.crt")).and_then(|m| m.modified())
    {
        let dt = time::OffsetDateTime::from(mtime);
        let nb = format_iso_date(dt - time::Duration::days(1));
        let na = format_iso_date(dt + time::Duration::days(3650));
        return (Some(nb), Some(na));
    }
    (None, None)
}

/// 读取或生成 CA 文件（返回 PEM），不启动分发服务
fn ensure_ca_files(data_dir: &Path) -> Result<(String, String), String> {
    let crt_path = data_dir.join("go_cus_ca.crt");
    let key_path = data_dir.join("go_cus_ca.key");
    if let (Ok(crt), Ok(key)) = (
        std::fs::read_to_string(&crt_path),
        std::fs::read_to_string(&key_path),
    ) {
        return Ok((crt, key));
    }
    let (crt, key) = generate_self_signed_ca().map_err(|e| format!("CA 生成失败: {e}"))?;
    std::fs::write(&crt_path, &crt).map_err(|e| e.to_string())?;
    std::fs::write(&key_path, &key).map_err(|e| e.to_string())?;
    let now = time::OffsetDateTime::now_utc();
    let meta = CaMeta {
        not_before: format_iso_date(now - time::Duration::days(1)),
        not_after: format_iso_date(now + time::Duration::days(3650)),
    };
    if let Ok(text) = serde_json::to_string_pretty(&meta) {
        let _ = std::fs::write(data_dir.join("go_cus_ca.meta.json"), text);
    }
    Ok((crt, key))
}

/// 只读查询本机 CA 状态（不存在时返回 Ok(None)，不主动生成）
pub fn get_ca_status(
    state: &crate::core::state::AppState,
    app: tauri::AppHandle,
) -> Result<Option<CaInfo>, String> {
    let data_dir = state.data_dir.clone();
    let crt_path = data_dir.join("go_cus_ca.crt");
    let key_path = data_dir.join("go_cus_ca.key");
    if !crt_path.exists() || !key_path.exists() {
        return Ok(None);
    }
    let crt_pem = std::fs::read_to_string(&crt_path).map_err(|e| e.to_string())?;
    let fingerprint = ca_fingerprint(&crt_pem)?;
    let (not_before, not_after) = read_or_infer_ca_validity(&data_dir);
    ensure_ca_service(app, crt_pem);
    Ok(Some(CaInfo {
        exists: true,
        fingerprint,
        install_url: format!("http://127.0.0.1:{CA_PORT}/prism-ca.mobileconfig"),
        cert_url: format!("http://127.0.0.1:{CA_PORT}/prism-ca.crt"),
        not_before,
        not_after,
        created: false,
    }))
}

/// 生成或读取自签名 Root CA（rcgen/ring 纯 Rust），并确保 2082 分发服务运行
pub fn generate_or_get_ca(
    state: &crate::core::state::AppState,
    app: tauri::AppHandle,
) -> Result<CaInfo, String> {
    let data_dir = state.data_dir.clone();
    let existed = data_dir.join("go_cus_ca.crt").exists();
    let (crt_pem, _key_pem) = ensure_ca_files(&data_dir)?;
    let fingerprint = ca_fingerprint(&crt_pem)?;
    let (not_before, not_after) = read_or_infer_ca_validity(&data_dir);
    ensure_ca_service(app, crt_pem);
    Ok(CaInfo {
        exists: true,
        fingerprint,
        install_url: format!("http://127.0.0.1:{CA_PORT}/prism-ca.mobileconfig"),
        cert_url: format!("http://127.0.0.1:{CA_PORT}/prism-ca.crt"),
        not_before,
        not_after,
        created: !existed,
    })
}

/// 构造 Root CA 的证书参数（生成与 MitM 重建签发者共用同一份定义）
fn ca_params() -> Result<rcgen::CertificateParams, String> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyUsagePurpose};
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "Prism Root CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Prism");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(3650);
    Ok(params)
}

/// rcgen 自签名 CA（ECDSA P-256，10 年有效期）
fn generate_self_signed_ca() -> Result<(String, String), String> {
    use rcgen::KeyPair;
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = ca_params()?.self_signed(&key).map_err(|e| e.to_string())?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// 从 PEM 提取 DER 并计算 SHA-256 指纹（大写冒号分组）
fn ca_fingerprint(crt_pem: &str) -> Result<String, String> {
    use base64::Engine as _;
    let b64: String = crt_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("证书 PEM 解析失败: {e}"))?;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&der);
    let hex: Vec<String> = digest.iter().map(|b| format!("{b:02X}")).collect();
    Ok(hex.join(":"))
}

/// 生成 iOS .mobileconfig 描述文件（DER base64 封装）
pub fn build_mobileconfig(crt_pem: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let b64: String = crt_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der_b64 = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| e.to_string())?;
    let der_b64 = base64::engine::general_purpose::STANDARD.encode(der_b64);
    let uuid1 = uuid::Uuid::new_v4().to_string().to_uppercase();
    let uuid2 = uuid::Uuid::new_v4().to_string().to_uppercase();
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>PrismRootCA.cer</string>
      <key>PayloadContent</key>
      <data>{der_b64}</data>
      <key>PayloadDescription</key>
      <string>Prism Go Cus MitM Root CA（仅用于本机改写功能，可在描述文件中随时移除）</string>
      <key>PayloadDisplayName</key>
      <string>Prism Root CA</string>
      <key>PayloadIdentifier</key>
      <string>com.prism.go-cus.ca</string>
      <key>PayloadOrganization</key>
      <string>Prism</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{uuid1}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>Prism Root CA</string>
  <key>PayloadIdentifier</key>
  <string>com.prism.go-cus.profile</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{uuid2}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"#
    );
    Ok(xml.into_bytes())
}

static CA_SERVICE_STARTED: AtomicBool = AtomicBool::new(false);

fn pem_to_der(crt_pem: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let b64: String = crt_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| format!("证书 PEM 解析失败: {e}"))
}

/// 确保 CA 分发服务运行（127.0.0.1:2082）：同时提供 iOS/macOS .mobileconfig、
/// Windows/Android/Linux .crt/.pem 以及浏览器引导页 `/`
fn ensure_ca_service(_app: tauri::AppHandle, crt_pem: String) {
    if CA_SERVICE_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mobileconfig = match build_mobileconfig(&crt_pem) {
        Ok(data) => data,
        Err(e) => {
            CA_SERVICE_STARTED.store(false, Ordering::Release);
            tracing::error!("[go-cus] mobileconfig 生成失败: {e}");
            return;
        }
    };
    let cert_der = match pem_to_der(&crt_pem) {
        Ok(der) => der,
        Err(e) => {
            CA_SERVICE_STARTED.store(false, Ordering::Release);
            tracing::error!("[go-cus] CA DER 解码失败: {e}");
            return;
        }
    };
    let cert_pem_bytes = crt_pem.into_bytes();
    let portal_html = br#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Prism Root CA</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;background:#0b0d13;color:#f3f4f6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;box-sizing:border-box}
.card{max-width:420px;width:100%;background:#1c1c1e;border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:24px}
h1{font-size:18px;margin:0 0 8px}p{font-size:13px;color:#9ca3af;line-height:1.6;margin:0 0 18px}
a.btn{display:block;text-align:center;text-decoration:none;border-radius:10px;padding:11px 14px;font-size:13px;font-weight:600;margin-bottom:10px}
.primary{background:#0a84ff;color:#fff}.secondary{background:#2c2c2e;color:#e5e7eb}
</style>
</head>
<body>
<div class="card">
<h1>Prism Root CA</h1>
<p>Install this local Root CA only on your own device to enable Go Cus HTTPS rewrite and scripting.</p>
<a class="btn primary" href="/prism-ca.mobileconfig">Install Profile (iOS / macOS)</a>
<a class="btn secondary" href="/prism-ca.crt">Download Certificate (.crt - Windows / Android / Linux)</a>
<a class="btn secondary" href="/prism-ca.pem">Download PEM (.pem)</a>
</div>
</body>
</html>"#
        .to_vec();

    tauri::async_runtime::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", CA_PORT)).await {
            Ok(l) => l,
            Err(e) => {
                CA_SERVICE_STARTED.store(false, Ordering::Release);
                tracing::error!("[go-cus] CA 服务绑定 {CA_PORT} 失败: {e}");
                return;
            }
        };
        tracing::info!("[go-cus] CA 分发服务已启动 127.0.0.1:{CA_PORT}");
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let mc = mobileconfig.clone();
            let der = cert_der.clone();
            let pem = cert_pem_bytes.clone();
            let html = portal_html.clone();
            tauri::async_runtime::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let head = String::from_utf8_lossy(&buf);
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let (content_type, disposition, body): (&str, Option<&str>, &[u8]) = match path {
                    "/prism-ca.mobileconfig" => (
                        "application/x-apple-aspen-config",
                        Some("attachment; filename=\"PrismRootCA.mobileconfig\""),
                        &mc,
                    ),
                    "/prism-ca.crt" | "/prism-ca.cer" => (
                        "application/x-x509-ca-cert",
                        Some("attachment; filename=\"PrismRootCA.crt\""),
                        &der,
                    ),
                    "/prism-ca.pem" => (
                        "application/x-pem-file",
                        Some("attachment; filename=\"PrismRootCA.pem\""),
                        &pem,
                    ),
                    "/" | "/index.html" => ("text/html; charset=utf-8", None, &html),
                    _ => {
                        let _ = stream
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        return;
                    }
                };
                let mut resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n"
                );
                if let Some(disp) = disposition {
                    resp.push_str(&format!("Content-Disposition: {disp}\r\n"));
                }
                resp.push_str(&format!(
                    "Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                ));
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
            });
        }
    });
}

// ---------------------------------------------------------------- 模块导入

/// 远程下载模块内容
pub async fn fetch_module_text(source: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .user_agent("ClashforWindows/0.20.39")
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(source)
        .send()
        .await
        .map_err(|e| format!("模块下载失败: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("模块下载失败: HTTP {}", resp.status()));
    }
    resp.text()
        .await
        .map_err(|e| format!("模块内容读取失败: {e}"))
}

/// 解析并写入/更新模块（按 source 去重）
pub fn upsert_module(
    settings: &mut GoCusSettings,
    source: &str,
    raw: &str,
    name_hint: Option<&str>,
) -> Result<CusModule, String> {
    let parsed = parse_universal_module(raw);
    let empty = parsed.rules.is_empty()
        && parsed.rewrites.is_empty()
        && parsed.scripts.is_empty()
        && parsed.mitm_hosts.is_empty()
        && parsed.hosts.is_empty();
    if empty {
        return Err("未能从内容中解析出任何规则/改写/脚本/MitM/Host 条目".into());
    }
    let stats = parsed.stats();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = parsed
        .name
        .clone()
        .or_else(|| name_hint.map(str::to_string))
        .unwrap_or_else(|| {
            source
                .split('/')
                .last()
                .filter(|s| !s.is_empty())
                .unwrap_or("未命名模块")
                .to_string()
        });
    if let Some(existing) = settings.modules.iter_mut().find(|m| m.source == source) {
        existing.name = name.clone();
        existing.desc = parsed.desc.clone();
        existing.raw_content = raw.to_string();
        existing.stats = stats.clone();
        existing.updated_at = now;
        let id = existing.id.clone();
        return Ok(CusModule {
            id,
            name,
            desc: parsed.desc,
            source: source.to_string(),
            raw_content: raw.to_string(),
            enabled: existing.enabled,
            stats,
            updated_at: now,
            hits: 0,
        });
    }
    let module = CusModule {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        desc: parsed.desc.clone(),
        source: source.to_string(),
        raw_content: raw.to_string(),
        enabled: true,
        stats,
        updated_at: now,
        hits: 0,
    };
    settings.modules.push(module.clone());
    Ok(module)
}

/// 便捷封装：设置对象 → 带实时 hits 的 JSON（供命令层直接返回）
pub fn settings_with_hits(settings: &GoCusSettings) -> Value {
    serde_json::to_value(settings).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SGMODULE: &str = r#"
#!name=测试模块
#!desc=解析验证用
[Rule]
DOMAIN-SUFFIX,example.com,REJECT
DOMAIN,api.foo.com,DIRECT
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
[URL Rewrite]
^https?://ad\.example\.com/ url reject-200
^https?://jump\.foo\.com/ url 302 https://target.example.com/
^https?://www\.bar\.com/ad - reject
[MITM]
hostname = %APPEND% *.api.example.com, ssl.foo.com
[Script]
test = type=http-response,pattern=^https?://script\.foo\.com,requires-body=1,script-path=https://x.com/a.js
[General]
dns-server = 1.1.1.1, 8.8.8.8
[Host]
nas.home = 192.168.1.100
tracker.bad.com = 0.0.0.0
"#;

    #[test]
    fn test_parse_sgmodule() {
        let parsed = parse_universal_module(SGMODULE);
        assert_eq!(parsed.name.as_deref(), Some("测试模块"));
        assert_eq!(parsed.rules.len(), 3);
        assert_eq!(
            parsed.rules[0],
            ("DOMAIN-SUFFIX".into(), "example.com".into(), "block".into())
        );
        assert_eq!(
            parsed.rules[1],
            ("DOMAIN".into(), "api.foo.com".into(), "direct".into())
        );
        assert_eq!(parsed.rules[2].2, "direct");
        assert_eq!(parsed.rewrites.len(), 3);
        assert_eq!(parsed.rewrites[0].action, "reject-200");
        assert_eq!(parsed.rewrites[1].action, "302");
        assert_eq!(parsed.rewrites[2].action, "reject");
        assert_eq!(
            parsed.mitm_hosts,
            vec!["*.api.example.com".to_string(), "ssl.foo.com".to_string()]
        );
        assert_eq!(parsed.scripts.len(), 1);
        assert_eq!(parsed.scripts[0].kind, "http-response");
        assert!(parsed.scripts[0].requires_body);
        assert_eq!(
            parsed.dns_servers.first().map(String::as_str),
            Some("1.1.1.1")
        );
        assert_eq!(parsed.hosts.len(), 2);
    }

    #[test]
    fn test_parse_quanx_filter_local() {
        let raw = "[filter_local]\nhost-suffix, google.com, reject\nhost, api.cn.com, direct\nip-cidr, 192.168.0.0/16, direct\n";
        let parsed = parse_universal_module(raw);
        assert_eq!(parsed.rules.len(), 3);
        assert_eq!(parsed.rules[0].0, "DOMAIN-SUFFIX");
        assert_eq!(parsed.rules[0].2, "block");
        assert_eq!(parsed.rules[1].0, "DOMAIN");
        assert_eq!(parsed.rules[2].0, "IP-CIDR");
    }

    #[test]
    fn test_parse_stash_yaml() {
        let raw = "name: Stash 覆写\ndesc: 测试\nrules:\n  - DOMAIN-SUFFIX,ads.com,REJECT\n  - DOMAIN-SUFFIX,cn.com,DIRECT\n";
        let parsed = parse_stash_yaml(raw).expect("stash 解析应成功");
        assert_eq!(parsed.name.as_deref(), Some("Stash 覆写"));
        assert_eq!(parsed.rules.len(), 2);
        assert_eq!(parsed.rules[0].2, "block");
    }

    /// URL 各动作分类 + `$1` 捕获组替换
    #[test]
    fn test_url_rewrite_actions_and_capture_groups() {
        let raw = concat!(
            "[URL Rewrite]\n",
            "^https?://a\\.com/ url reject\n",
            "^https?://b\\.com/ url reject-200\n",
            "^https?://c\\.com/ url reject-img\n",
            "^https?://d\\.com/ url reject-tinygif\n",
            "^https?://e\\.com/ url reject-dict\n",
            "^https?://f\\.com/ url reject-array\n",
            "^https?://g\\.com/(.*)$ url 302 https://h.com/$1\n",
            "^https?://i\\.com/(.*)$ - 307 https://j.com/$1\n",
        );
        let parsed = parse_universal_module(raw);
        let actions: Vec<&str> = parsed.rewrites.iter().map(|r| r.action.as_str()).collect();
        assert_eq!(
            actions,
            vec![
                "reject",
                "reject-200",
                "reject-img",
                "reject-tinygif",
                "reject-dict",
                "reject-array",
                "302",
                "307"
            ]
        );

        let re = regex::Regex::new(r"^https?://g\.com/(.*)$").unwrap();
        let matched = MatchedRewrite {
            module_id: "m".into(),
            rule_index: 6,
            action: "302".into(),
            target: Some("https://h.com/$1".into()),
            re: Some(re),
        };
        let resp =
            String::from_utf8(build_terminal_response(&matched, "https://g.com/x/y")).unwrap();
        assert!(resp.starts_with("HTTP/1.1 302"));
        assert!(resp.contains("Location: https://h.com/x/y"));

        let re_b = regex::Regex::new(r"^https?://b\.com/").unwrap();
        let reject200 = MatchedRewrite {
            module_id: "m".into(),
            rule_index: 1,
            action: "reject-200".into(),
            target: None,
            re: Some(re_b),
        };
        let resp = build_terminal_response(&reject200, "https://b.com/");
        assert!(String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"));

        let img = MatchedRewrite {
            module_id: "m".into(),
            rule_index: 2,
            action: "reject-img".into(),
            target: None,
            re: None,
        };
        let resp = build_terminal_response(&img, "https://c.com/");
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("Content-Type: image/png"));

        let dict = MatchedRewrite {
            module_id: "m".into(),
            rule_index: 4,
            action: "reject-dict".into(),
            target: None,
            re: None,
        };
        let resp = build_terminal_response(&dict, "https://e.com/");
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("application/json"));
        assert!(text.ends_with("{}"));
    }

    #[test]
    fn test_header_op_parsing() {
        assert_eq!(
            parse_header_ops("$(remove-X-Foo)"),
            vec![HeaderOp::Del("x-foo".into())]
        );
        assert_eq!(
            parse_header_ops("$(add-X-Foo: bar)"),
            vec![HeaderOp::Add("x-foo".into(), "bar".into())]
        );
        // 值大小写必须保留（如 Bearer Token / User-Agent）
        assert_eq!(
            parse_header_ops("$(add-Authorization: Bearer AbCdEf123)"),
            vec![HeaderOp::Add(
                "authorization".into(),
                "Bearer AbCdEf123".into()
            )]
        );
        assert_eq!(
            parse_header_ops("$(replace-X-Foo: BazValue)"),
            vec![HeaderOp::Replace("x-foo".into(), "BazValue".into())]
        );
        assert_eq!(
            parse_header_ops("header-add X-Foo: bar"),
            vec![HeaderOp::Add("x-foo".into(), "bar".into())]
        );
        assert_eq!(
            parse_header_ops("header-del X-Foo"),
            vec![HeaderOp::Del("x-foo".into())]
        );
        assert_eq!(
            parse_header_ops("header-replace X-Foo: v2"),
            vec![HeaderOp::Replace("x-foo".into(), "v2".into())]
        );
    }

    #[test]
    fn test_inline_script_parsing_and_matching() {
        let raw = concat!(
            "#!name=自定义脚本\n",
            "[Script]\n",
            "http-request, ^https://api\\.example\\.com/v1, script-path=inline:a1b2c3d4, tag=MyInline, requires-body=1\n",
            "# --- inline script a1b2c3d4 begin ---\n",
            "# console.log('hello');\n",
            "# $done({ response: { status: 200, body: 'ok' } });\n",
            "# --- inline script a1b2c3d4 end ---\n",
        );
        let parsed = parse_universal_module(raw);
        assert_eq!(parsed.scripts.len(), 1);
        assert_eq!(parsed.scripts[0].name, "MyInline");
        assert_eq!(parsed.scripts[0].script_path, "inline:a1b2c3d4");
        let code = parsed
            .inline_scripts
            .get("inline:a1b2c3d4")
            .expect("应解析出内联脚本源码");
        assert!(code.contains("console.log('hello')"));
        assert!(code.contains("$done("));

        let settings = GoCusSettings {
            enabled: true,
            modules: vec![CusModule {
                id: "local-custom-scripts".into(),
                name: "自定义脚本".into(),
                desc: None,
                source: "local://local-custom-scripts".into(),
                raw_content: raw.into(),
                enabled: true,
                stats: parsed.stats(),
                updated_at: 0,
                hits: 0,
            }],
            ..Default::default()
        };
        let matched = match_rules(&settings, "https://api.example.com/v1/user");
        let req_sc = matched.request_script.expect("应命中请求脚本");
        assert!(
            req_sc
                .inline_code
                .as_deref()
                .unwrap_or("")
                .contains("$done(")
        );
    }

    #[test]
    fn test_guardrail_filtering_on_compile() {
        let raw = concat!(
            "#!name=护栏验证\n",
            "[Rule]\n",
            "DOMAIN-SUFFIX,prism.sarl,REJECT\n",
            "DOMAIN,127.0.0.1,REJECT\n",
            "DOMAIN-SUFFIX,192.168.1.10,REJECT\n",
            "[URL Rewrite]\n",
            "^https?://127\\.0\\.0\\.1/ url reject\n",
            "^https?://prism\\.sarl/ url reject-200\n",
            "[MITM]\n",
            "hostname = *.local, 10.0.0.8, evil.com\n",
            "[Host]\n",
            "localhost = 0.0.0.0\n",
        );
        let mut settings = GoCusSettings {
            enabled: true,
            mitm_enabled: true,
            ..Default::default()
        };
        settings.modules.push(CusModule {
            id: "guard".into(),
            name: "护栏验证".into(),
            desc: None,
            source: "local".into(),
            raw_content: raw.into(),
            enabled: true,
            stats: CusModuleStats::default(),
            updated_at: 0,
            hits: 0,
        });
        let compiled = compile(&settings, "PROXY");
        let dump = serde_json::to_string(&compiled.rules).unwrap();
        for bad in ["prism.sarl", "127.0.0.1", "192.168.1.10", "localhost"] {
            assert!(
                !dump.contains(bad),
                "护栏主机名 {bad} 不应进入路由规则: {dump}"
            );
        }
        assert!(compiled.sidecar_domains.contains(&"evil.com".into()));
        assert!(!compiled.sidecar_domains.iter().any(|d| d == "10.0.0.8"));
        assert!(!compiled.sidecar_domains.iter().any(|d| d == "local"));
    }

    #[test]
    fn test_mitm_wildcard_and_exclude() {
        assert!(host_matches_pattern("*.example.com", "a.example.com"));
        assert!(host_matches_pattern("*.example.com", "example.com"));
        assert!(!host_matches_pattern("*.example.com", "badexample.com"));
        assert!(!host_matches_pattern("example.com", "a.example.com"));

        let patterns = vec!["*.example.com".to_string(), "-a.example.com".to_string()];
        assert!(mitm_should_decrypt(&patterns, "b.example.com"));
        assert!(!mitm_should_decrypt(&patterns, "a.example.com"));

        // 硬编码永不解密
        assert!(!mitm_should_decrypt(&["*.apple.com".into()], "x.apple.com"));
        assert!(!mitm_should_decrypt(
            &["*.alipay.com".into()],
            "m.alipay.com"
        ));
        assert!(!mitm_should_decrypt(
            &["*.wechat.com".into()],
            "wx.wechat.com"
        ));
        // 护栏主机名
        assert!(!mitm_should_decrypt(&["*.foo.local".into()], "a.foo.local"));
        assert!(!mitm_should_decrypt(&["*.example.com".into()], "127.0.0.1"));
    }

    #[test]
    fn test_compile_blocks_and_sidecar() {
        let settings = GoCusSettings {
            enabled: true,
            mitm_enabled: true,
            modules: vec![
                CusModule {
                    id: "m1".into(),
                    name: "测试模块".into(),
                    desc: None,
                    source: "local".into(),
                    raw_content: SGMODULE.into(),
                    enabled: true,
                    stats: CusModuleStats::default(),
                    updated_at: 0,
                    hits: 0,
                },
                CusModule {
                    id: "m2".into(),
                    name: "占位验证".into(),
                    desc: None,
                    source: "local".into(),
                    raw_content: "[Rule]\nDOMAIN,policy.test.com,My-Group\n".into(),
                    enabled: true,
                    stats: CusModuleStats::default(),
                    updated_at: 0,
                    hits: 0,
                },
            ],
            ..Default::default()
        };
        let compiled = compile(&settings, "PROXY");
        let block_rule = compiled
            .rules
            .iter()
            .find(|r| r.get("outbound").and_then(Value::as_str) == Some("block"))
            .expect("应有 block 规则");
        let domains: Vec<&str> = block_rule["domain_suffix"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(domains.contains(&"example.com"));
        assert!(domains.contains(&"ad.example.com"));
        assert!(domains.contains(&"tracker.bad.com"));
        assert!(compiled.sidecar_needed);
        assert!(compiled.sidecar_domains.contains(&"jump.foo.com".into()));
        assert!(compiled.sidecar_domains.contains(&"script.foo.com".into()));
        assert!(compiled.sidecar_domains.contains(&"api.example.com".into()));
        assert_eq!(compiled.dns_override.as_deref(), Some("1.1.1.1"));
        assert!(compiled.dns_local_domains.contains(&"nas.home".into()));
        let proxy_rule = compiled
            .rules
            .iter()
            .find(|r| r.get("outbound").and_then(Value::as_str) == Some("PROXY"));
        assert!(proxy_rule.is_some());
    }

    #[test]
    fn test_compile_disabled_produces_nothing() {
        let settings = GoCusSettings::default();
        let compiled = compile(&settings, "PROXY");
        assert!(compiled.rules.is_empty());
        assert!(!compiled.sidecar_needed);
        assert!(!has_active_rules(&settings));
    }

    #[test]
    fn test_extract_domains_from_pattern() {
        assert_eq!(
            extract_domains_from_pattern("^https?://ad\\.example\\.com/"),
            vec!["ad.example.com".to_string()]
        );
        assert!(extract_domains_from_pattern("https?://").is_empty());
        assert_eq!(
            extract_domains_from_pattern("^https?://(www\\.)?x\\.foo\\.com"),
            vec!["x.foo.com".to_string()]
        );
    }

    #[test]
    fn test_split_authority() {
        assert_eq!(
            split_authority("a.com:8443", 443).unwrap(),
            ("a.com".into(), 8443)
        );
        assert_eq!(
            split_authority("a.com", 443).unwrap(),
            ("a.com".into(), 443)
        );
        assert_eq!(
            split_authority("[::1]:9090", 80).unwrap(),
            ("::1".into(), 9090)
        );
    }

    #[test]
    fn test_split_url() {
        let (scheme, host, port, path) = split_url("http://a.com:8080/x/y?z=1").unwrap();
        assert_eq!(
            (scheme.as_str(), host.as_str(), port, path.as_str()),
            ("http", "a.com", 8080, "/x/y?z=1")
        );
    }

    #[test]
    fn test_ca_generation_and_fingerprint() {
        let (crt, key) = generate_self_signed_ca().expect("CA 应生成成功");
        assert!(crt.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key.contains("PRIVATE KEY"));
        let fp = ca_fingerprint(&crt).expect("指纹应可计算");
        assert_eq!(fp.len(), 95, "SHA-256 指纹应为 64 位十六进制 + 31 个冒号");
        let mc = build_mobileconfig(&crt).expect("mobileconfig 应生成成功");
        let text = String::from_utf8(mc).unwrap();
        assert!(text.contains("com.apple.security.root"));
        assert!(text.contains("PayloadContent"));
    }

    #[test]
    fn test_hits_snapshot_shape() {
        reset_hits();
        record_hit("mod-x", "rw", 3);
        record_hit("mod-x", "rw", 3);
        let snap = hits_snapshot();
        assert_eq!(snap["modules"]["mod-x"], json!(2));
        assert_eq!(snap["rules"]["mod-x#rw:3"], json!(2));
        assert_eq!(snap["total"], json!(2));
        reset_hits();
        assert_eq!(hits_snapshot()["total"], json!(0));
    }

    /// 官方一键模板（前端 GoCus.tsx CUS_TEMPLATES 的等价内容）：
    /// 去广告 → block；隐私保护 → header 改写 + MitM 域名进入边车集合。
    #[test]
    fn test_official_templates_compile_to_expected_rules() {
        // 去广告模板
        let adblock =
            "#!name=adblock\n#!desc=去广告\n[Rule]\nDOMAIN-SUFFIX,doubleclick.net,REJECT\n";
        let parsed = parse_universal_module(adblock);
        assert_eq!(parsed.rules.len(), 1);
        let mut settings = GoCusSettings {
            enabled: true,
            ..Default::default()
        };
        settings.modules.push(CusModule {
            id: "adblock".into(),
            name: "adblock".into(),
            desc: None,
            source: "builtin://adblock".into(),
            raw_content: adblock.into(),
            enabled: true,
            stats: parsed.stats(),
            updated_at: 0,
            hits: 0,
        });
        let compiled = compile(&settings, "PROXY");
        let hit = compiled.rules.iter().any(|r| {
            r.get("outbound").and_then(Value::as_str) == Some("block")
                && r.get("domain_suffix")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().any(|d| d.as_str() == Some("doubleclick.net")))
                    .unwrap_or(false)
        });
        assert!(hit, "adblock 模板应编译出 block 规则: {:?}", compiled.rules);

        // 隐私保护模板：header 改写 + MitM 域名
        let privacy = concat!(
            "#!name=privacy\n",
            "#!desc=隐私保护\n",
            "[URL Rewrite]\n",
            "^https?://([^/]*\\.)?google\\.com/ url request-header $(remove-X-Forwarded-For)\n",
            "[MITM]\n",
            "hostname = *.google.com, -accounts.google.com\n",
        );
        let parsed = parse_universal_module(privacy);
        assert_eq!(parsed.rewrites.len(), 1, "隐私模板应解析出 1 条改写");
        assert_eq!(parsed.rewrites[0].action, "header-request");
        assert_eq!(parsed.mitm_hosts.len(), 2);

        let mut settings = GoCusSettings {
            enabled: true,
            mitm_enabled: true,
            ..Default::default()
        };
        settings.modules.push(CusModule {
            id: "privacy".into(),
            name: "privacy".into(),
            desc: None,
            source: "builtin://privacy".into(),
            raw_content: privacy.into(),
            enabled: true,
            stats: parsed.stats(),
            updated_at: 0,
            hits: 0,
        });
        assert!(has_active_rules(&settings));
        let compiled = compile(&settings, "PROXY");
        assert!(
            compiled.sidecar_domains.contains(&"google.com".to_string()),
            "隐私模板域名必须进入边车集合（MITM + header）: {:?}",
            compiled.sidecar_domains
        );
        // -accounts.google.com 只作为排除项，不应成为边车路由域名
        assert!(
            !compiled
                .sidecar_domains
                .iter()
                .any(|d| d == "accounts.google.com")
        );
        assert!(mitm_should_decrypt(&parsed.mitm_hosts, "www.google.com"));
        assert!(!mitm_should_decrypt(
            &parsed.mitm_hosts,
            "accounts.google.com"
        ));
    }
}
