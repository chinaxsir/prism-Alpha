//! Go Cus —— 全兼容覆写 / 改写 / MitM / 脚本引擎（Pro 专属）
//!
//! 三大能力（与 IPA-3 方案一致）：
//! 1. **全兼容模块解析**：Surge `.sgmodule` / QuantumultX `[rewrite_local]+[filter_local]`
//!    / Loon / Stash `.stoverride`，统一解析为 Rule / URL-Rewrite / Script / MitM / Host 五类；
//! 2. **配置编译**：模块规则 → sing-box 路由规则（REJECT→block、DIRECT→direct、
//!    其他→主策略组）；DNS 覆写；[Host] 映射；MitM 域名路由到本地边车；
//! 3. **本地边车**（127.0.0.1:2081）：极简异步 HTTP/1.1 处理服务，应用 URL 改写
//!    （reject / reject-200 / 302 / 307 / header），并承载 MitM CA 证书分发服务（2082）。
//!
//! Alpha 边界说明（诚实记录，供后续迭代）：
//! - 边车对 HTTPS 流量仅支持 CONNECT 级 reject（无 TLS 终结，URL/302 改写对
//!   HTTPS 需要内核 1.12 的 TLS 解密能力，此处先完成架构与路由闭环）；
//! - 脚本（http-request/response、cron）完成解析、存储与展示，执行器待接 JS 运行时。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::Manager;

/// 边车出站 tag（sing-box 配置中引用）
pub const SIDECAR_TAG: &str = "go-cus-sidecar";
/// 本地边车监听端口
pub const SIDECAR_PORT: u16 = 2081;
/// CA 证书分发服务端口
pub const CA_PORT: u16 = 2082;

// ---------------------------------------------------------------- 设置与模块模型

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CusRewriteRule {
    /// URL 正则（兼容 Surge/QuanX 写法）
    pub pattern: String,
    /// reject | reject200 | redirect302 | redirect307 | header | none
    pub action: String,
    /// 重定向目标地址 / header 操作说明
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
        // Stash .stoverride / Clash 覆写 YAML（解析失败则回落行式）
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

/// 行式解析：Surge sgmodule / QuanX / Loon 通用状态机
fn parse_line_based(raw: &str) -> ParsedCusModule {
    let mut out = ParsedCusModule::default();
    let mut section = String::new();
    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        // 头部元信息
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
            "url rewrite" | "rewrite" | "rewrite_local" => {
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

/// MitM hostname 行值解析：去掉 %APPEND% / %INSERT%，展开 *. 前缀
fn split_hosts_value(v: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    let cleaned = v.replace("%APPEND%", "").replace("%INSERT%", "");
    for h in cleaned.split(',') {
        let h = h.trim().trim_start_matches("*.").trim();
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
    // QuanX 小写类型归一
    let kind = match kind_raw.as_str() {
        "HOST" => "DOMAIN".to_string(),
        "HOST-SUFFIX" => "DOMAIN-SUFFIX".to_string(),
        "HOST-KEYWORD" => "DOMAIN-KEYWORD".to_string(),
        "IP6-CIDR" => "IP-CIDR6".to_string(),
        other => other.to_string(),
    };
    // FINAL 特例：FINAL,POLICY
    if kind == "FINAL" {
        return Some(("FINAL".into(), "-".into(), normalize_policy(parts[1])));
    }
    if parts.len() < 3 {
        return None;
    }
    // 末位为策略；其前若为 no-resolve / forced-remote-dns / udp 等旗标则回退一位
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
    } else if upper == "PROXY" || upper == "GLOBAL" {
        "proxy".into()
    } else {
        "proxy".into()
    }
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
    if tokens[1] == "url" {
        let action_raw = tokens[2].to_ascii_lowercase();
        let target = tokens[3..].join(" ");
        return quanx_action(&pattern, &action_raw, &target);
    }

    // Surge / Shadowrocket 风格：<regex> <target|-|_> <action>
    let action_raw = tokens[tokens.len() - 1].to_ascii_lowercase();
    let target = tokens[1..tokens.len() - 1].join(" ");
    let dash = target == "-" || target == "_";
    if action_raw == "302" || action_raw == "307" {
        if dash {
            return None;
        }
        return Some((
            Some(CusRewriteRule {
                pattern,
                action: format!("redirect{action_raw}"),
                target: Some(target),
                enabled: true,
            }),
            None,
        ));
    }
    if action_raw.starts_with("reject") {
        return Some((
            Some(CusRewriteRule {
                pattern,
                action: if action_raw == "reject-200" || action_raw == "reject-img"
                    || action_raw == "reject-dict" || action_raw == "reject-array"
                {
                    "reject200".into()
                } else {
                    "reject".into()
                },
                target: None,
                enabled: true,
            }),
            None,
        ));
    }
    None
}

/// QuanX 动作映射（含 script-* 展开为脚本规则）
fn quanx_action(
    pattern: &str,
    action_raw: &str,
    target: &str,
) -> Option<(Option<CusRewriteRule>, Option<CusScriptRule>)> {
    let action = match action_raw {
        "reject" | "reject-drop" => "reject",
        "reject-200" | "reject-img" | "reject-dict" | "reject-array" => "reject200",
        "302" => "redirect302",
        "307" => "redirect307",
        "request-header" | "response-header" => "header",
        "echo" | "none" => "none",
        a if a.starts_with("script-") => {
            // script-response-body / script-response-header / script-request-*
            let kind = if a.contains("response") {
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
                    requires_body: a.contains("body"),
                    cron: None,
                    enabled: true,
                }),
            ));
        }
        _ => return None,
    };
    Some((
        Some(CusRewriteRule {
            pattern: pattern.to_string(),
            action: action.into(),
            target: if target.is_empty() { None } else { Some(target.to_string()) },
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
                _ => {}
            }
        } else if first_two.len() < 2 {
            first_two.push(kv);
        }
    }
    // 位置风格补位：type 与 pattern
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
        name: name.unwrap_or_else(|| format!("script-{}", short_hash(&path))),
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
    // 空解析视为失败
    if out.rules.is_empty() && out.rewrites.is_empty() {
        return None;
    }
    Some(out)
}

fn short_hash(s: &str) -> String {
    // 8 位稳定短哈希（FNV-1a）
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:08x}")
}

// ---------------------------------------------------------------- 编译

/// 编译产物：供 config_builder 并入 sing-box 配置
#[derive(Debug, Default)]
pub(crate) struct CusCompiled {
    /// 路由规则（proxy 占位由调用方解析为主策略组）
    pub rules: Vec<Value>,
    /// 需路由到边车的域名（改写重定向 / 脚本 / MitM hostname）
    pub sidecar_domains: Vec<String>,
    /// 需要挂载边车出站
    pub sidecar_needed: bool,
    /// 需经本地直连 DNS 解析的域名（[Host] 非阻断映射，防远程污染）
    pub dns_local_domains: Vec<String>,
    /// DNS 覆写地址
    pub dns_override: Option<String>,
    pub warnings: Vec<String>,
}

/// 编译全部启用模块 + 手动覆写设置
pub(crate) fn compile(settings: &GoCusSettings, proxy_tag: &str) -> CusCompiled {
    let mut out = CusCompiled::default();
    if !settings.enabled {
        return out;
    }
    // 聚合容器：按 (kind, policy) 合并相邻同类目标，控制规则条数
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
                out.warnings.push(format!("Go Cus 规则类型 {other} 暂不支持，已忽略"));
                return;
            }
        };
        let policy_out = match policy {
            "block" => "block",
            "direct" => "direct",
            _ => proxy_tag,
        };
        out.rules.push(json!({ matcher: targets, "outbound": policy_out }));
    };

    for module in &settings.modules {
        if !module.enabled {
            continue;
        }
        let parsed = parse_universal_module(&module.raw_content);
        // 模块规则
        for (kind, target, policy) in &parsed.rules {
            if kind == "FINAL" {
                out.warnings.push("Go Cus 模块 FINAL 规则暂不支持，已忽略".into());
                continue;
            }
            if kind == "URL-REGEX" {
                out.warnings.push("Go Cus 模块 URL-REGEX 规则暂不支持（已按域名提取尝试）".into());
                for d in extract_domains_from_pattern(target) {
                    block_domains.push(d);
                }
                continue;
            }
            // 相邻同 (kind, policy) 合并
            if let Some(bucket) = rule_buckets.last_mut() {
                if &bucket.0 == kind && &bucket.1 == policy {
                    bucket.2.push(target.clone());
                    continue;
                }
            }
            rule_buckets.push((kind.clone(), policy.clone(), vec![target.clone()]));
        }
        // 改写：reject 提取域名阻断；redirect/header 域名走边车
        for rw in &parsed.rewrites {
            match rw.action.as_str() {
                "reject" | "reject200" => {
                    block_domains.extend(extract_domains_from_pattern(&rw.pattern));
                }
                "redirect302" | "redirect307" | "header" => {
                    out.sidecar_domains.extend(extract_domains_from_pattern(&rw.pattern));
                }
                _ => {}
            }
        }
        // 脚本：pattern 域名走边车
        for s in &parsed.scripts {
            if let Some(p) = &s.pattern {
                out.sidecar_domains.extend(extract_domains_from_pattern(p));
            }
        }
        // MitM hostname
        if settings.mitm_enabled {
            for h in &parsed.mitm_hosts {
                out.sidecar_domains.push(h.clone());
            }
        }
        // [Host] 映射
        for (domain, value) in &parsed.hosts {
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
        // [General] dns-server：取第一个作为覆写候选（手动设置优先）
        if out.dns_override.is_none() {
            if let Some(d) = parsed.dns_servers.first() {
                out.dns_override = Some(d.clone());
            }
        }
    }

    // 手动 [Host] 覆写
    for (domain, value) in &settings.host_overrides {
        let v = value.to_ascii_lowercase();
        if v.starts_with("0.0.0.0") || v.starts_with("127.0.0.1") || v == "::1" || v == "reject" {
            block_domains.push(domain.clone());
        } else {
            out.dns_local_domains.push(domain.clone());
        }
    }
    // 手动 DNS 覆写优先
    if let Some(d) = &settings.dns_override {
        if !d.trim().is_empty() {
            out.dns_override = Some(d.trim().to_string());
        }
    }

    // 去重
    block_domains.sort();
    block_domains.dedup();
    out.sidecar_domains.sort();
    out.sidecar_domains.dedup();
    out.dns_local_domains.sort();
    out.dns_local_domains.dedup();

    // 产出规则
    // reject 改写 / URL-REGEX / Host 提取的阻断域名与模块 REJECT 规则
    // 合并为同一条 block 规则，避免内核配置出现重复的 domain_suffix 规则
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
        out.rules.push(json!({ "domain_suffix": out.sidecar_domains.clone(), "outbound": SIDECAR_TAG }));
    }
    // 静态 Host 映射降级说明（内核 1.11 无 DNS 静态记录）
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

// ---------------------------------------------------------------- 边车服务

static SIDECAR_STARTED: AtomicBool = AtomicBool::new(false);

/// 确保边车已启动（进程内单例）
pub fn ensure_sidecar(app: tauri::AppHandle) {
    if SIDECAR_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    tauri::async_runtime::spawn(async move {
        if let Err(e) = run_sidecar(app).await {
            tracing::error!("[go-cus] 边车启动失败: {e}");
        }
    });
}

async fn run_sidecar(app: tauri::AppHandle) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", SIDECAR_PORT))
        .await
        .map_err(|e| format!("绑定 127.0.0.1:{SIDECAR_PORT} 失败: {e}"))?;
    tracing::info!("[go-cus] 边车已启动 127.0.0.1:{SIDECAR_PORT}");
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let _ = handle_sidecar_conn(app, stream).await;
        });
    }
}

/// 读取并解析 HTTP 请求头（最多 64KB）
async fn read_head(
    stream: &mut tokio::net::TcpStream,
) -> Result<(String, HashMap<String, String>), String> {
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err("请求头超过 64KB 上限".into());
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Ok((request_line, headers))
}

async fn handle_sidecar_conn(
    app: tauri::AppHandle,
    mut stream: tokio::net::TcpStream,
) -> Result<(), String> {
    let (request_line, headers) = read_head(&mut stream).await?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Ok(());
    }
    let state = app.state::<crate::core::state::AppState>();
    let settings = state.go_cus.read().clone();

    // ---- CONNECT：HTTPS 隧道（仅支持 CONNECT 级 reject；改写需 TLS 终结，后续迭代）----
    if method == "CONNECT" {
        let probe_url = format!("https://{target}/");
        if settings.enabled {
            if let Some(action) = match_rewrite(&settings, &probe_url) {
                if action == "reject" {
                    let _ = write_all(&mut stream, b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    return Ok(());
                }
                // redirect/header 对 CONNECT 无法注入，按隧道透传处理
            }
        }
        let (host, port) = split_authority(&target, 443)?;
        let mut upstream = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| format!("边车上游连接失败 {host}:{port}: {e}"))?;
        let _ = write_all(&mut stream, b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream);
        return Ok(());
    }

    // ---- 绝对形式 HTTP 请求：完整改写管线 ----
    let url = if target.starts_with("http") {
        target.clone()
    } else {
        // origin-form：补全 host
        let host = headers.get("host").cloned().unwrap_or_default();
        format!("http://{host}{target}")
    };
    let action = if settings.enabled { match_rewrite(&settings, &url) } else { None };
    let Some(action) = action else {
        // 未命中改写：透传（直连转发）
        return forward_plain(&mut stream, &request_line, &headers, &url).await;
    };
    match action.as_str() {
        "reject" => {
            let _ = write_all(
                &mut stream,
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
        }
        "reject200" => {
            let _ = write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
        }
        a if a == "redirect302" || a == "redirect307" => {
            let target_url = find_rewrite_target(&settings, &url).unwrap_or_default();
            let status = if a == "redirect302" { "302 Found" } else { "307 Temporary Redirect" };
            let resp = format!(
                "HTTP/1.1 {status}\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = write_all(&mut stream, resp.as_bytes()).await;
        }
        "header" => {
            // header 改写后转发（Alpha：支持 $(remove-NAME) 删除头）
            forward_plain_with_header_ops(&mut stream, &request_line, &headers, &url, &settings).await?;
        }
        _ => {
            forward_plain(&mut stream, &request_line, &headers, &url).await?;
        }
    }
    Ok(())
}

/// 查找 URL 命中的首个启用改写动作
fn match_rewrite(settings: &GoCusSettings, url: &str) -> Option<String> {
    for module in &settings.modules {
        if !module.enabled {
            continue;
        }
        let parsed = parse_universal_module(&module.raw_content);
        for rw in &parsed.rewrites {
            if !rw.enabled {
                continue;
            }
            if let Ok(re) = regex::Regex::new(&rw.pattern) {
                if re.is_match(url) {
                    return Some(rw.action.clone());
                }
            }
        }
    }
    None
}

/// 查找 URL 命中的首个改写目标（重定向地址）
fn find_rewrite_target(settings: &GoCusSettings, url: &str) -> Option<String> {
    for module in &settings.modules {
        if !module.enabled {
            continue;
        }
        let parsed = parse_universal_module(&module.raw_content);
        for rw in &parsed.rewrites {
            if !rw.enabled {
                continue;
            }
            if let Ok(re) = regex::Regex::new(&rw.pattern) {
                if re.is_match(url) {
                    return rw.target.clone();
                }
            }
        }
    }
    None
}

/// 解析 host[:port]
fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6
        let Some(end) = stripped.find(']') else {
            return Err("非法 IPv6 authority".into());
        };
        let host = stripped[..end].to_string();
        let port = stripped[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            Ok((h.to_string(), p.parse().unwrap_or(default_port)))
        }
        _ => Ok((authority.to_string(), default_port)),
    }
}

async fn write_all(stream: &mut tokio::net::TcpStream, data: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    stream.write_all(data).await
}

/// URL 拆解 (scheme, host, port, path)
fn split_url(url: &str) -> Result<(String, String, u16, String), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("非法 URL: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = split_authority(authority, default_port)?;
    Ok((scheme.to_string(), host, port, path.to_string()))
}

/// 透传转发（重建请求行 + 原样头 + 双向拷贝）
async fn forward_plain(
    stream: &mut tokio::net::TcpStream,
    request_line: &str,
    headers: &HashMap<String, String>,
    url: &str,
) -> Result<(), String> {
    forward_plain_inner(stream, request_line, headers, url, None, None).await
}

/// 带头操作转发（$(remove-NAME) 删除头）
async fn forward_plain_with_header_ops(
    stream: &mut tokio::net::TcpStream,
    request_line: &str,
    headers: &HashMap<String, String>,
    url: &str,
    settings: &GoCusSettings,
) -> Result<(), String> {
    // 找到命中的 header 规格说明
    let mut spec: Option<String> = None;
    'outer: for module in &settings.modules {
        if !module.enabled {
            continue;
        }
        let parsed = parse_universal_module(&module.raw_content);
        for rw in &parsed.rewrites {
            if rw.enabled && rw.action == "header" {
                if let Ok(re) = regex::Regex::new(&rw.pattern) {
                    if re.is_match(url) {
                        spec = rw.target.clone();
                        break 'outer;
                    }
                }
            }
        }
    }
    forward_plain_inner(stream, request_line, headers, url, spec.as_deref(), Some(settings)).await
}

async fn forward_plain_inner(
    stream: &mut tokio::net::TcpStream,
    request_line: &str,
    headers: &HashMap<String, String>,
    url: &str,
    header_spec: Option<&str>,
    settings: Option<&GoCusSettings>,
) -> Result<(), String> {
    let (_scheme, host, port, path) = split_url(url)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    // 重建头（应用 header 操作）
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in headers {
        let k_l = k.to_ascii_lowercase();
        if k_l == "host" {
            continue;
        }
        let mut value = v.clone();
        if let (Some(spec), Some(_)) = (header_spec, settings) {
            let spec_t = spec.trim();
            if let Some(name) = spec_t
                .strip_prefix("$(remove-")
                .and_then(|s| s.strip_suffix(")"))
            {
                if k.eq_ignore_ascii_case(name) {
                    continue; // 删除该头
                }
            }
            // Alpha：替换规格（regex replacement）暂不生效，仅删除与透传
            let _ = &mut value;
        }
        head.push_str(&format!("{k}: {value}\r\n"));
    }
    head.push_str(&format!("Host: {host}\r\nConnection: close\r\n\r\n"));
    let mut upstream = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| format!("边车上游连接失败 {host}:{port}: {e}"))?;
    write_all(&mut upstream, head.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    // 双向拷贝：请求体与响应体透传
    let _ = tokio::io::copy_bidirectional(stream, &mut upstream);
    Ok(())
}

// ---------------------------------------------------------------- CA 证书管理

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaInfo {
    /// SHA-256 指纹（冒号分组大写）
    pub fingerprint: String,
    /// 本地安装 URL
    pub install_url: String,
    /// 本次是否新生成
    pub created: bool,
}

/// 生成或读取自签名 Root CA（rcgen/ring 纯 Rust），并确保 2082 分发服务运行
pub fn generate_or_get_ca(
    state: &crate::core::state::AppState,
    app: tauri::AppHandle,
) -> Result<CaInfo, String> {
    let data_dir = state.data_dir.clone();
    let crt_path = data_dir.join("go_cus_ca.crt");
    let key_path = data_dir.join("go_cus_ca.key");
    let mut created = false;
    let (crt_pem, key_pem) = match (
        std::fs::read_to_string(&crt_path),
        std::fs::read_to_string(&key_path),
    ) {
        (Ok(c), Ok(k)) => (c, k),
        _ => {
            let (c, k) = generate_self_signed_ca().map_err(|e| format!("CA 生成失败: {e}"))?;
            std::fs::write(&crt_path, &c).map_err(|e| e.to_string())?;
            std::fs::write(&key_path, &k).map_err(|e| e.to_string())?;
            created = true;
            (c, k)
        }
    };
    // 指纹：对证书 PEM 中 DER 部分 SHA-256
    let fingerprint = ca_fingerprint(&crt_pem)?;
    // 确保 CA 分发服务运行
    ensure_ca_service(app, crt_pem);
    drop(key_pem);
    Ok(CaInfo {
        fingerprint,
        install_url: format!("http://127.0.0.1:{CA_PORT}/prism-ca.mobileconfig"),
        created,
    })
}

/// rcgen 自签名 CA（ECDSA P-256，10 年有效期）
fn generate_self_signed_ca() -> Result<(String, String), String> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    };
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    params.distinguished_name.push(DnType::CommonName, "Prism Root CA");
    params.distinguished_name.push(DnType::OrganizationName, "Prism");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(3650);
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
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

/// 确保 CA 分发服务运行（127.0.0.1:2082）
fn ensure_ca_service(_app: tauri::AppHandle, crt_pem: String) {
    if CA_SERVICE_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mobileconfig = match build_mobileconfig(&crt_pem) {
        Ok(data) => data,
        Err(e) => {
            tracing::error!("[go-cus] mobileconfig 生成失败: {e}");
            return;
        }
    };
    tauri::async_runtime::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", CA_PORT)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("[go-cus] CA 服务绑定 {CA_PORT} 失败: {e}");
                return;
            }
        };
        tracing::info!("[go-cus] CA 分发服务已启动 127.0.0.1:{CA_PORT}");
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { continue };
            let body = mobileconfig.clone();
            tauri::async_runtime::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let head = String::from_utf8_lossy(&buf);
                if head.starts_with("GET /prism-ca.mobileconfig") {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/x-apple-aspen-config\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                } else {
                    let _ = stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                }
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
    resp.text().await.map_err(|e| format!("模块内容读取失败: {e}"))
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
    };
    settings.modules.push(module.clone());
    Ok(module)
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(parsed.rules[0], ("DOMAIN-SUFFIX".into(), "example.com".into(), "block".into()));
        assert_eq!(parsed.rules[1], ("DOMAIN".into(), "api.foo.com".into(), "direct".into()));
        assert_eq!(parsed.rules[2].2, "direct");
        // 改写：3 条（含 surge reject）
        assert_eq!(parsed.rewrites.len(), 3);
        assert_eq!(parsed.rewrites[0].action, "reject200");
        assert_eq!(parsed.rewrites[1].action, "redirect302");
        assert_eq!(parsed.rewrites[2].action, "reject");
        // MitM
        assert_eq!(parsed.mitm_hosts, vec!["api.example.com".to_string(), "ssl.foo.com".to_string()]);
        // 脚本
        assert_eq!(parsed.scripts.len(), 1);
        assert_eq!(parsed.scripts[0].kind, "http-response");
        assert!(parsed.scripts[0].requires_body);
        // DNS / Host
        assert_eq!(parsed.dns_servers.first().map(String::as_str), Some("1.1.1.1"));
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
                },
                // 自定义策略规则：验证非 block/direct 策略映射为 proxy 占位
                CusModule {
                    id: "m2".into(),
                    name: "占位验证".into(),
                    desc: None,
                    source: "local".into(),
                    raw_content: "[Rule]\nDOMAIN,policy.test.com,My-Group\n".into(),
                    enabled: true,
                    stats: CusModuleStats::default(),
                    updated_at: 0,
                },
            ],
            ..Default::default()
        };
        let compiled = compile(&settings, "PROXY");
        // 阻断域名：example.com（规则）+ ad.example.com（reject 改写提取）+ tracker.bad.com（Host 阻断）
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
        // 边车域名：重定向 + 脚本 + MitM
        assert!(compiled.sidecar_needed);
        assert!(compiled.sidecar_domains.contains(&"jump.foo.com".into()));
        assert!(compiled.sidecar_domains.contains(&"script.foo.com".into()));
        assert!(compiled.sidecar_domains.contains(&"api.example.com".into()));
        // DNS 覆写
        assert_eq!(compiled.dns_override.as_deref(), Some("1.1.1.1"));
        // [Host] 非阻断映射 → 本地直连 DNS
        assert!(compiled.dns_local_domains.contains(&"nas.home".into()));
        // proxy 占位
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
    }

    #[test]
    fn test_extract_domains_from_pattern() {
        assert_eq!(
            extract_domains_from_pattern("^https?://ad\\.example\\.com/"),
            vec!["ad.example.com".to_string()]
        );
        assert!(extract_domains_from_pattern("https?://").is_empty());
        // 非重叠匹配：整段域名优先命中
        assert_eq!(
            extract_domains_from_pattern("^https?://(www\\.)?x\\.foo\\.com"),
            vec!["x.foo.com".to_string()]
        );
    }

    #[test]
    fn test_split_authority() {
        assert_eq!(split_authority("a.com:8443", 443).unwrap(), ("a.com".into(), 8443));
        assert_eq!(split_authority("a.com", 443).unwrap(), ("a.com".into(), 443));
        assert_eq!(split_authority("[::1]:9090", 80).unwrap(), ("::1".into(), 9090));
    }

    #[test]
    fn test_split_url() {
        let (scheme, host, port, path) = split_url("http://a.com:8080/x/y?z=1").unwrap();
        assert_eq!((scheme.as_str(), host.as_str(), port, path.as_str()), ("http", "a.com", 8080, "/x/y?z=1"));
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
}
