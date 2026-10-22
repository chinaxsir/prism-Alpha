//! 配置构建器：Clash YAML 订阅 → sing-box runtime JSON
//!
//! 输入支持：
//! 1. Clash/Mihomo 格式 YAML（最常见的订阅格式）
//! 2. 已是 sing-box JSON 的配置（原样透传）
//!
//! 输出 sing-box 配置包含：mixed 入站、可选 tun 入站、内置出站、
//! 节点出站、策略组、DNS、路由规则、clash_api 实验功能。
//!
//! 无法无损转换的项会写入 warnings，调用方应记录日志而不是直接失败。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use super::state::{OutboundMode, RunMode, UserSettings};

const DEFAULT_TEST_URL: &str = "http://www.gstatic.com/generate_204";
const TUN_TAG: &str = "tun-in";
const MIXED_TAG: &str = "mixed-in";

pub struct BuiltConfig {
    pub config: Value,
    /// 转换过程中的降级/跳过提示（不致命）
    pub warnings: Vec<String>,
    /// route.final 指向的出站（主策略组链入口，用于解析主选择组）
    pub final_group: String,
}

// ---------------- 输入：Clash 订阅结构 ----------------

#[derive(Deserialize, Default)]
struct ClashProfile {
    #[serde(default)]
    proxies: Vec<ClashNode>,
    #[serde(default, rename = "proxy-groups")]
    proxy_groups: Vec<ClashGroup>,
    #[serde(default)]
    rules: Vec<String>,
    /// 策略组通过 `use:` 引用的节点集合（多数为远程 http 订阅片段）
    #[serde(default, rename = "proxy-providers")]
    proxy_providers: HashMap<String, ProviderDef>,
}

/// 供外部模块（订阅更新流程）读取 proxy-providers 的公开视图
#[derive(Deserialize, Default)]
pub struct ClashProfileView {
    #[serde(default, rename = "proxy-providers")]
    pub proxy_providers: HashMap<String, ProviderView>,
}

/// 订阅内容落盘前校验：必须包含节点 / 策略组 / proxy-provider 之一。
/// 防止机场返回 HTML 错误页、限流提示等无效内容覆盖掉本地可用订阅，
/// 导致启动时报「未解析到任何节点或策略组」。
pub fn validate_subscription_text(text: &str) -> Result<(), String> {
    let profile: ClashProfile = serde_yaml::from_str(text.trim())
        .map_err(|e| format!("订阅内容不是有效的 Clash YAML（{e}）"))?;

    // 检查 proxies：不仅要有节点，且节点 server 不能全是环回地址（机场提示页）
    // 注意：emit_node 会跳过 127.x/localhost 节点，这里必须同步过滤，否则
    // 更新时通过校验、启动时却被过滤导致「无节点」
    let real_nodes: Vec<_> = profile
        .proxies
        .iter()
        .filter(|n| {
            let server = n.server.to_lowercase();
            !server.starts_with("127.") && !server.starts_with("localhost") && !server.is_empty()
        })
        .collect();

    // 有可用节点 或 有 proxy-providers（启动时会下载）即视为有效
    if real_nodes.is_empty() && profile.proxy_providers.is_empty() {
        return Err(
            "订阅内容未包含可用节点（可能是机场限流/到期提示页），已保留原订阅".into(),
        );
    }
    // 只有策略组没有节点：策略组成员为空，同样无法启动
    if real_nodes.is_empty()
        && profile.proxy_providers.is_empty()
        && !profile.proxy_groups.is_empty()
    {
        return Err(
            "订阅内容包含策略组但无可用节点（可能是机场限流/到期提示页），已保留原订阅".into(),
        );
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct ProviderView {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ClashNode {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    server: String,
    port: u16,

    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    /// SS 加密方式；VMess 中为 security
    #[serde(default)]
    cipher: Option<String>,
    #[serde(default)]
    alter_id: Option<i64>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    tls: Option<bool>,
    #[serde(default)]
    sni: Option<String>,
    /// Clash vless/vmess 常用 servername 字段（与 sni 同义）
    #[serde(default, rename = "servername")]
    servername: Option<String>,
    /// uTLS 指纹（如 chrome）；CDN 类节点缺失时易被 reset
    #[serde(default, rename = "client-fingerprint")]
    client_fingerprint: Option<String>,
    /// Reality 配置（vless + tls 节点；缺失 public-key 时视为普通 TLS）
    #[serde(default, rename = "reality-opts")]
    reality_opts: Option<RealityOpts>,
    #[serde(default)]
    skip_cert_verify: Option<bool>,
    #[serde(default)]
    alpn: Option<Vec<String>>,
    #[serde(default, rename = "ws-opts")]
    ws_opts: Option<WsOpts>,
    #[serde(default, rename = "grpc-opts")]
    grpc_opts: Option<GrpcOpts>,
    #[serde(default)]
    flow: Option<String>,
    #[serde(default, rename = "congestion-controller")]
    congestion_control: Option<String>,
    /// SS 插件 obfs / v2ray-plugin
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default, rename = "plugin-opts")]
    plugin_opts: Option<Value>,
    /// hysteria2 混淆类型（Clash 中通常为 salamander）
    #[serde(default)]
    obfs: Option<String>,
    /// hysteria2 混淆密码（字段 obfs-password）
    #[serde(default, rename = "obfs-password")]
    obfs_password: Option<String>,

    // ---- Hysteria v1 鉴权（mihomo 字段拼写不一：auth-str / auth_str / auth_str2）----
    #[serde(default, rename = "auth-str", alias = "auth_str", alias = "auth_str2")]
    auth_str: Option<String>,
    /// hysteria v1 上行/下行带宽提示（"50 Mbps"）；sing-box 侧可选，仅接受纯数字
    #[serde(default)]
    up: Option<String>,
    #[serde(default)]
    down: Option<String>,
    #[serde(default, rename = "http-opts")]
    http_opts: Option<HttpOpts>,
    #[serde(default, rename = "h2-opts")]
    h2_opts: Option<H2Opts>,

    // ---- socks5 / http 节点鉴权 ----
    #[serde(default)]
    username: Option<String>,

    // ---- WireGuard 节点（mihomo 字段名）----
    #[serde(default, rename = "private-key")]
    private_key: Option<String>,
    #[serde(default, rename = "public-key")]
    public_key: Option<String>,
    /// 本端接口地址，mihomo 支持裸 IP（"10.0.0.2"）或逗号分隔多个
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    ipv6: Option<String>,
    #[serde(default, rename = "preshared-key")]
    preshared_key: Option<String>,
    #[serde(default)]
    mtu: Option<u32>,
    #[serde(default)]
    reserved: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct RealityOpts {
    #[serde(default, rename = "public-key")]
    public_key: Option<String>,
    #[serde(default, rename = "short-id")]
    short_id: Option<String>,
}

#[derive(Deserialize)]
struct WsOpts {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    headers: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct GrpcOpts {
    #[serde(default, rename = "grpc-service-name")]
    service_name: Option<String>,
}

#[derive(Deserialize)]
struct HttpOpts {
    /// Clash path 为列表（HTTP/2 多路复用风格），取首个
    #[serde(default)]
    path: Option<Vec<String>>,
    #[serde(default)]
    method: Option<String>,
    /// Clash 头值为列表，sing-box 同样期望字符串列表
    #[serde(default)]
    headers: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Deserialize)]
struct H2Opts {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    host: Option<Vec<String>>,
}

/// proxy-provider 定义（仅 http 可由客户端拉取；file 依赖运行时目录，不支持）
#[derive(Deserialize)]
struct ProviderDef {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    url: Option<String>,
}

/// provider 载荷（标准格式只含 proxies 列表；也可能是完整 Clash 配置）
#[derive(Deserialize, Default)]
struct ProviderPayload {
    #[serde(default)]
    proxies: Vec<ClashNode>,
}

#[derive(Deserialize)]
struct ClashGroup {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    proxies: Vec<String>,
    #[serde(default)]
    url: Option<String>,
    /// Clash 间隔单位为秒
    #[serde(default)]
    interval: Option<i64>,
    #[serde(default)]
    strategy: Option<String>,
    /// 通过 proxy-provider 引入的节点集合（provider 名称）
    #[serde(default, rename = "use")]
    use_providers: Vec<String>,
}

// ---------------- 入口 ----------------

pub fn build(
    profiles: &[(String, String, String)],
    custom_rules: &[String],
    mode: RunMode,
    settings: &UserSettings,
    data_dir: &Path,
    work_dir: &Path,
    api_addr: &str,
    api_secret: &str,
    go_lan_cfg: &crate::core::go_lan::GoLanSettings,
    go_cus_cfg: &crate::core::go_cus::GoCusSettings,
) -> Result<BuiltConfig> {
    // 单条 sing-box JSON：原样透传，但自定义规则仍可前置合并（见 merge_json_custom）
    if profiles.len() == 1 && profiles[0].2.trim().starts_with('{') {
        let trimmed = profiles[0].2.trim();
        let mut config: Value = serde_json::from_str(trimmed)
            .context("profile looks like JSON but failed to parse")?;
        let mut warnings = vec!["内核 JSON 配置原样透传，未做模式/端口合并".into()];
        merge_json_custom(&mut config, custom_rules, &mut warnings);
        let final_group = config
            .get("route")
            .and_then(|r| r.get("final"))
            .and_then(|f| f.as_str())
            .unwrap_or_default()
            .to_string();
        return Ok(BuiltConfig {
            config,
            warnings,
            final_group,
        });
    }

    let mut warnings = Vec::new();
    // 发射判重：emit_node/group 用 insert 返回值判断首次发射，
    // 只能在发射阶段写入（预解析写这里会把全部名字误判为重复）
    let mut known_tags: HashSet<String> =
        ["direct", "block", "dns-out"].map(str::to_string).into_iter().collect();
    // 跨订阅改名追踪：预解析阶段登记全部订阅的标签，供后续订阅冲突改名
    let mut seen_tags: HashSet<String> =
        ["direct", "block", "dns-out"].map(str::to_string).into_iter().collect();

    let mut outbounds = vec![
        json!({ "type": "direct", "tag": "direct" }),
        json!({ "type": "block", "tag": "block" }),
        json!({ "type": "dns", "tag": "dns-out" }),
    ];

    let mut route_rules: Vec<Value> = Vec::new();
    let mut final_tag: Option<String> = None;
    let mut first_group_tag: Option<String> = None;
    let mut total_nodes = 0usize;
    let mut total_groups = 0usize;

    // ---- 预解析：profile + provider 节点，并构建冲突改名表 ----
    // 改名必须在处理节点/组之前算完，自定义规则才能解析到跨订阅的改名标签
    struct ParsedProfile {
        name: String,
        profile: ClashProfile,
        rename: HashMap<String, String>,
        /// provider 名称 → 节点（文件缺失的 provider 不出现）
        provider_nodes: HashMap<String, Vec<ClashNode>>,
    }

    let mut parsed_list: Vec<ParsedProfile> = Vec::new();
    // 合并全部订阅的改名表：原名 → 改名（重名冲突时先订阅优先）
    let mut global_rename: HashMap<String, String> = HashMap::new();

    for (url, sub_name, text) in profiles {
        let profile: ClashProfile = serde_yaml::from_str(text.trim())
            .with_context(|| format!("无法解析订阅「{sub_name}」为 Clash YAML（请检查订阅格式）"))?;

        // 读取已落盘的 proxy-provider 节点（update_subscription 时按 URL 下载）
        let mut provider_nodes: HashMap<String, Vec<ClashNode>> = HashMap::new();
        for (pname, pdef) in &profile.proxy_providers {
            if pdef.kind != "http" {
                warnings.push(format!(
                    "proxy-provider '{pname}' 类型为 {}（仅支持 http），已忽略",
                    pdef.kind
                ));
                continue;
            }
            let path = crate::core::store::provider_path(data_dir, url, pname);
            match std::fs::read_to_string(&path) {
                Ok(payload) => {
                    let parsed: ProviderPayload = serde_yaml::from_str(&payload).unwrap_or_default();
                    provider_nodes.insert(pname.clone(), parsed.proxies);
                }
                Err(_) => warnings.push(format!(
                    "proxy-provider '{pname}' 节点文件缺失（请更新订阅），已忽略"
                )),
            }
        }

        // 与已注册标签冲突的本订阅节点/provider节点/组名 → "[订阅名] 原名"
        let mut rename: HashMap<String, String> = HashMap::new();
        let candidates = profile
            .proxies
            .iter()
            .map(|p| &p.name)
            .chain(provider_nodes.values().flatten().map(|p| &p.name))
            .chain(profile.proxy_groups.iter().map(|g| &g.name));
        for name in candidates {
            if seen_tags.contains(name) && !rename.contains_key(name) {
                rename.insert(name.clone(), format!("[{sub_name}] {name}"));
            }
        }
        // 把本订阅的全部标签（含改名结果）登记进 seen_tags，供后续订阅做冲突判定
        for name in profile
            .proxies
            .iter()
            .map(|p| &p.name)
            .chain(provider_nodes.values().flatten().map(|p| &p.name))
            .chain(profile.proxy_groups.iter().map(|g| &g.name))
        {
            let mapped = rename.get(name).cloned().unwrap_or_else(|| name.clone());
            seen_tags.insert(mapped);
        }
        for (from, to) in &rename {
            if !global_rename.contains_key(from) {
                global_rename.insert(from.clone(), to.clone());
            }
        }

        parsed_list.push(ParsedProfile {
            name: sub_name.clone(),
            profile,
            rename,
            provider_nodes,
        });
    }

    // 自定义规则：优先级最高，插在所有订阅规则之前；策略名走全局改名
    let custom_apply = |name: &str| -> String {
        let mapped = map_ref(name);
        global_rename.get(&mapped).cloned().unwrap_or(mapped)
    };
    for line in custom_rules {
        let parsed = parse_rule_line(line, &custom_apply, &mut warnings);
        if final_tag.is_none() {
            final_tag = parsed.final_target;
        }
        if let Some(rule) = parsed.rule {
            route_rules.push(rule);
        }
    }

    // ---- Go Lan 回家路由（Pro）：必须先于内置 geosite: private /
    // ip_is_private -> direct，否则会被"私网直连"抢先命中导致回家失效 ----
    let (lan_outbound, lan_warnings) = crate::core::go_lan::build_outbound(go_lan_cfg);
    let (lan_rules, lan_rule_warnings) = crate::core::go_lan::go_lan_route_rules(go_lan_cfg);
    let (lan_dns_server, lan_dns_rule) = crate::core::go_lan::go_lan_dns(go_lan_cfg);
    if let Some(outbound) = lan_outbound {
        outbounds.push(outbound);
        route_rules.extend(lan_rules);
    }
    warnings.extend(lan_warnings);
    warnings.extend(lan_rule_warnings);

    // ---- Go Cus 覆写引擎（Pro）：模块规则 / 改写阻断 / MitM 边车路由 ----
    let cus_compiled = crate::core::go_cus::compile(go_cus_cfg, "PROXY");
    if cus_compiled.sidecar_needed {
        outbounds.push(json!({
            "type": "http",
            "tag": crate::core::go_cus::SIDECAR_TAG,
            "server": "127.0.0.1",
            "server_port": crate::core::go_cus::SIDECAR_PORT,
        }));
    }
    route_rules.extend(cus_compiled.rules);
    warnings.extend(cus_compiled.warnings);
    let cus_dns_override = cus_compiled.dns_override;
    let cus_dns_local_domains = cus_compiled.dns_local_domains;

    // ---- 内置常见分流规则·域名类（全平台，位于订阅规则之前）----
    // 仅域名匹配（不触发 DNS 解析，无污染改道风险）：
    // 1. 广告域名拦截——category-ads-all 命中即 block，浏览器直接失败回退
    // 2. 局域网主机名直连——geosite private（localhost/*.local 等）
    // 3. 国内域名直连——geosite cn（含 .com 国内站），域名匹配零解析开销
    // IP 类规则（geoip private/cn）位于订阅规则之后（见下方）——被墙域名
    // 的 DNS 污染会返回中国/私有 IP（如 gstatic → 113.108.239.226），
    // 若 geoip 规则在订阅 MATCH 之前，会强制解析并命中 geoip cn/private，
    // 把应走节点的流量改道直连，导致「选了节点却上不了网」。
    route_rules.push(json!({ "geosite": "category-ads-all", "outbound": "block" }));
    route_rules.push(json!({ "geosite": "private", "outbound": "direct" }));
    route_rules.push(json!({ "geosite": "cn", "outbound": "direct" }));
    warnings.push(
        "已内置常见分流规则：广告域名拦截、局域网与国内域名直连".into(),
    );

    // ---- 逐订阅产出出站/组/规则 ----
    let mut node_tags: Vec<String> = Vec::new();
    for parsed in &parsed_list {
        let ParsedProfile {
            name: sub_name,
            profile,
            rename,
            provider_nodes,
        } = parsed;

        let apply = |name: &str| -> String {
            let mapped = map_ref(name);
            rename.get(&mapped).cloned().unwrap_or(mapped)
        };

        // 订阅自身节点
        for node in &profile.proxies {
            if let Some(t) = emit_node(&mut outbounds, &mut known_tags, &mut warnings, node, &apply, &mut total_nodes) {
                node_tags.push(t);
            }
        }
        // provider 节点
        for nodes in provider_nodes.values() {
            for node in nodes {
                if let Some(t) = emit_node(
                    &mut outbounds,
                    &mut known_tags,
                    &mut warnings,
                    node,
                    &apply,
                    &mut total_nodes,
                ) {
                    node_tags.push(t);
                }
            }
        }

        // 策略组：成员 = proxies + use: 引用的 provider 节点
        for group in &profile.proxy_groups {
            let tag = apply(&group.name);
            if !known_tags.insert(tag.clone()) {
                warnings.push(format!("节点/组标签重复，已跳过：{}", tag));
                continue;
            }

            let mut members: Vec<String> = group.proxies.clone();
            for pname in &group.use_providers {
                match provider_nodes.get(pname) {
                    Some(nodes) => members.extend(nodes.iter().map(|n| n.name.clone())),
                    None => warnings.push(format!(
                        "策略组 '{}' 引用的 proxy-provider '{pname}' 不可用，已忽略",
                        group.name
                    )),
                }
            }
            if members.is_empty() {
                warnings.push(format!(
                    "策略组 '{}' 没有任何成员（proxies/use 均为空或不可用）",
                    group.name
                ));
            }

            let mut outbound = group_to_outbound(group, &members, &mut warnings, rename);
            outbound["tag"] = json!(tag.clone());
            if first_group_tag.is_none() {
                first_group_tag = Some(tag);
            }
            outbounds.push(outbound);
            total_groups += 1;
        }

        // 规则 → sing-box route.rules（多订阅按记录顺序拼接，先订阅优先）
        //
        // iOS 精简（build 145 方案）：机场订阅常内联数万条域名/IP 规则
        // （实测 2.47MB），网络扩展进程 Jetsam 内存红线仅 15~50MB，Go
        // json.Unmarshal 构建规则 AST 瞬间 40MB+ 必被 SIGKILL（code=12
        // 且来不及写错误文件）。iOS 丢弃订阅内联规则，只保留自定义规则
        // 与 block_quic，分流退化为默认出站（节点/策略组全保留）；桌面
        // 与 Android 不受扩展内存红线约束，保持完整规则
        let keep_subscription_rules = !cfg!(target_os = "ios");
        for line in &profile.rules {
            if !keep_subscription_rules {
                continue;
            }
            let parsed = parse_rule_line(line, &apply, &mut warnings);
            if final_tag.is_none() {
                final_tag = parsed.final_target;
            }
            if let Some(rule) = parsed.rule {
                route_rules.push(rule);
            }
        }
    }

    // iOS 基础分流（build 149 方案 → 全平台内置规则取代）：订阅内联规则在
    // 构建期丢弃后，「分析-规则统计/命中」与国内直连分流由内置规则
    // （域名类在前 + IP 类在此）继续提供，其余走策略组（默认出站）

    // ---- 内置常见分流规则·兜底域名类（订阅规则之后、geoip 之前）----
    // 无规则订阅（纯节点，如 Cloudflare Worker 订阅）场景：MATCH 兜底
    // 不存在，被墙域名会一路落到 geoip cn 触发本地解析→污染 CN IP→
    // 误判直连断网。geolocation-!cn（非中国大陆域名）零解析开销直接走
    // 主选择组；有规则订阅中更具体的订阅域名规则优先级不受影响
    // （geolocation-!cn 仅在订阅规则未命中时兜底）
    let rule_final = final_tag
        .or(first_group_tag)
        .unwrap_or_else(|| "direct".into());
    if rule_final != "direct" {
        route_rules.push(json!({
            "geosite": "geolocation-!cn",
            "outbound": rule_final,
        }));
    }

    // ---- 内置常见分流规则·IP 类（全平台，位于订阅规则之后）----
    // 订阅 MATCH 命中的流量（被墙域名，无论 DNS 污染成什么 IP）已在上方
    // 走节点，永远不会到达这两条——杜绝污染 IP 触发 geoip 改道直连；
    // 未被订阅覆盖的流量按真实 IP 兜底：局域网/私有网段与国内网段直连
    // （IP 字面量目标无需解析即匹配；域名目标才会触发解析）
    route_rules.push(json!({ "geoip": "private", "outbound": "direct" }));
    // ip_is_private：不依赖 geoip 数据库的内置私网判定（IPA-3 方案 6.3，
    // iOS 端 sanitize 流程同样引用该规则，Go Lan 回家规则已排在其前）
    route_rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));
    route_rules.push(json!({ "geoip": "cn", "outbound": "direct" }));

    // 未显式 MATCH：优先全部订阅中的首个策略组，否则 direct（上方已算）

    // 出站模式：规则=按订阅 MATCH 分流；全局=所有流量进 GLOBAL 选择组；直连=全部 direct。
    // GLOBAL 组常驻生成（节点存在时）：sing-box 的 mode 不是内置路由开关，
    // 热切换依赖 clash_mode 规则 + 运行中的 GLOBAL 组，见下方规则注入
    if !node_tags.is_empty() {
        let mut members = node_tags.clone();
        members.push("direct".to_string());
        let default = node_tags[0].clone();
        outbounds.push(json!({
            "type": "selector",
            "tag": "GLOBAL",
            "outbounds": members,
            "default": default,
        }));
    } else if settings.outbound_mode == OutboundMode::Global {
        warnings.push("全局模式需要至少一个节点，当前订阅无节点，回退为规则模式".into());
    }
    let final_tag = match settings.outbound_mode {
        OutboundMode::Rule => rule_final,
        OutboundMode::Direct => "direct".to_string(),
        OutboundMode::Global => {
            if node_tags.is_empty() {
                // 无节点时 GLOBAL 组未生成，final 不能指向不存在的组
                rule_final
            } else {
                "GLOBAL".to_string()
            }
        }
    };

    // clash_mode 热切换规则置顶（build 157 用户方案）：sing-box 的
    // PATCH /configs {"mode": ...} 只改 clashServer.Mode() 字符串，路由
    // 行为变化完全由 clash_mode 规则驱动（route/rule/rule_item_clash_mode.go:
    // strings.EqualFold(clashServer.Mode(), r.mode)）。规则/直连模式回落
    // 到原 final 链，无需重建配置即可热切换
    if !node_tags.is_empty() {
        route_rules.insert(0, json!({ "clash_mode": "global", "outbound": "GLOBAL" }));
        route_rules.insert(1, json!({ "clash_mode": "direct", "outbound": "direct" }));
    }

    // 阻止 QUIC：UDP/443 直接拦截，强制浏览器回退 TCP（规则链最前，优先级最高）
    if settings.block_quic {
        route_rules.insert(
            0,
            json!({ "network": "udp", "port": 443, "outbound": "block" }),
        );
    }

    // 官网域名强制直连（最高优先级）：官方站点用于授权激活/续费与客户端下载，
    // 经节点在部分机场会被 CDN 或上游策略拦截，表现为「开代理后官网打不开」。
    // 置于 clash_mode（全局/直连）与内置 geosite 规则之前，确保任何出站模式下
    // 官网始终可访问；域名后缀匹配零解析开销，不影响其它流量分流。
    route_rules.insert(
        0,
        json!({ "domain_suffix": [crate::obf!("prism.sarl")], "outbound": "direct" }),
    );

    // 校验策略组引用，剔除悬空目标
    // 注意：必须用 get_mut 探测，直接 outbound["outbounds"] 可变索引会给
    // 普通节点出站插入 "outbounds": null，导致 sing-box 报 unknown field
    for outbound in outbounds.iter_mut().skip(3) {
        let tag = outbound["tag"].as_str().unwrap_or_default().to_string();
        let list = outbound.get_mut("outbounds").and_then(Value::as_array_mut);
        if let Some(list) = list {
            let before = list.len();
            list.retain(|item| {
                let t = item.as_str().unwrap_or_default();
                known_tags.contains(t) || matches!(t, "direct" | "block")
            });
            if list.len() != before {
                warnings.push(format!("策略组 '{}' 中存在无效引用，已剔除", tag));
            }
        }
    }

    // 真实节点统一并入主选择组（build 159 用户方案）。
    // 部分订阅把节点全部挂在地区子分组下：旧「仅补游离节点」规则会让
    // 顶层组不含任何真实节点，启动后从 Clash API 拉到的主选择组只剩
    // 子分组（用户实例：启动前 49 个节点，启动后只剩 10 个 CB 节点）。
    // 顶层主选择组必须包含全部真实节点 tag，保证每个节点可见/可选/可测速。
    //
    // 1) 定位主选择组：route.final 直指的 selector（顶层组）。旧实现沿
    //    首成员链下钻到最深 selector——顶层组默认选中地区子分组后，
    //    main_selector 会落到只含少量节点的子分组，同样造成节点骤减。
    //    final 非 selector（urltest/叶子）时沿成员链找第一个 selector 兜底。
    let mut main_group_tag: Option<String> = None;
    {
        let lookup =
            |tag: &str| outbounds.iter().find(|o| o["tag"].as_str() == Some(tag));
        let mut current = final_tag.clone();
        let mut visited: HashSet<String> = HashSet::new();
        loop {
            if !visited.insert(current.clone()) {
                break;
            }
            let Some(group) = lookup(&current) else { break };
            if group["type"].as_str() == Some("selector") {
                main_group_tag = Some(current);
                break;
            }
            let Some(next) = group
                .get("outbounds")
                .and_then(|l| l.as_array())
                .and_then(|l| l.first())
                .and_then(|v| v.as_str())
                .map(String::from)
            else {
                break;
            };
            current = next;
        }
    }

    // Go Cus 模块规则中的 PROXY 占位 → 主选择组（无主组时回落 final）
    // 置于主组定位之后、配置组装之前，保证占位符解析到真实组 tag
    let proxy_target = main_group_tag.clone().unwrap_or_else(|| final_tag.clone());
    if !proxy_target.is_empty() && proxy_target != "PROXY" {
        for rule in route_rules.iter_mut() {
            if rule.get("outbound").and_then(Value::as_str) == Some("PROXY") {
                rule["outbound"] = json!(proxy_target);
            }
        }
    }

    // 【APP-4.1】Go Cus 边车容错：127.0.0.1:2081 只在水印检修（主 App 前台）
    // 时可用。主 App 被系统冻结、边车崩溃或用户后台运行时，直接指向边车的
    // 规则会整条断网。把边车出站包进一个 urltest 组（边车优先、主组兜底），
    // 边车不可达时内核自动回落到主组，网络不中断。
    if !proxy_target.is_empty() && proxy_target != crate::core::go_cus::SIDECAR_TAG
        && outbounds
            .iter()
            .any(|o| o["tag"].as_str() == Some(crate::core::go_cus::SIDECAR_TAG))
    {
        const FALLBACK_TAG: &str = "go-cus-fallback";
        outbounds.push(json!({
            "type": "urltest",
            "tag": FALLBACK_TAG,
            "outbounds": [crate::core::go_cus::SIDECAR_TAG, proxy_target],
            "url": "http://www.gstatic.com/generate_204",
            "interval": "1m",
            "tolerance": 50,
        }));
        for rule in route_rules.iter_mut() {
            if rule.get("outbound").and_then(Value::as_str)
                == Some(crate::core::go_cus::SIDECAR_TAG)
            {
                rule["outbound"] = json!(FALLBACK_TAG);
            }
        }
        warnings.push("Go Cus 边车已配置主组容错回落（边车不可用时自动走节点）".into());
    }

    match main_group_tag {
        Some(ref main_tag) => {
            if let Some(group) =
                outbounds.iter_mut().find(|o| o["tag"].as_str() == Some(main_tag.as_str()))
            {
                let existing: Vec<String> = group
                    .get("outbounds")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut merged = existing.clone();
                for t in &node_tags {
                    if !existing.contains(t) {
                        merged.push(t.clone());
                    }
                }
                group["outbounds"] = json!(merged);
                // default 失效（指向 direct/block 或不在成员列表中）时
                // 修正为首个真实节点
                let default_valid = group
                    .get("default")
                    .and_then(Value::as_str)
                    .map(|d| {
                        // 订阅里 direct 可能因为延迟最低被设为 default——必须过滤
                        // REJECT/PASS/COMPATIBLE/block/dns-out 这类内置出站绝不生效
                        let is_builtin = matches!(
                            d.to_ascii_uppercase().as_str(),
                            "DIRECT"
                                | "BLOCK"
                                | "REJECT"
                                | "REJECT-DROP"
                                | "PASS"
                                | "COMPATIBLE"
                                | "DNS-OUT"
                                | "GLOBAL"
                        );
                        !is_builtin && merged.iter().any(|m| m == d)
                    })
                    .unwrap_or(false);
                if !default_valid {
                    if let Some(first) = node_tags.first() {
                        group["default"] = json!(first);
                    }
                }
            }
        }
        None => warnings.push(
            "订阅中存在不属于任何策略组的节点，但未找到可挂接的主选择组，这些节点无法在节点页选择".into(),
        ),
    }

    // 4. 入站
    // 移动端（iOS/Android）所有流量经 TUN 接管，mixed 入站非必需且可能在
    // NetworkExtension 沙箱内绑定端口失败导致内核启动失败，故移动端不包含。
    let mut inbounds: Vec<Value> = Vec::new();
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    inbounds.push(json!({
        "type": "mixed",
        "tag": MIXED_TAG,
        "listen": if settings.allow_lan { "0.0.0.0" } else { "127.0.0.1" },
        "listen_port": settings.mixed_port,
    }));

    // 桌面端仅 TUN 模式加 TUN 入站；移动端（iOS/Android）必须始终包含：
    // 普通 App 无法设置系统代理，libbox 经 tun 入站回调 PlatformInterface.OpenTun
    // 向系统 VPN（VpnService / NEPacketTunnelProvider）索要 TUN fd
    if mode == RunMode::Tun || cfg!(any(target_os = "ios", target_os = "android")) {
        // 1.10 起 inet4_address/inet6_address 合并为 address（legacy 字段
        // 需 ENABLE_DEPRECATED_TUN_ADDRESS_X env，check/run 均会 FATAL）
        let mut tun_addresses = vec!["198.18.0.1/30"];
        if settings.ipv6 {
            tun_addresses.push("fdfe:dcba:9876::1/126");
        }
        // Android（IPA-12 2.5）：内核运行于 App 进程内，SELinux 严禁内核
        // 自行 netlink 改路由/枚举网卡——
        // - auto_route 仍为 true：libbox 平台接口模式下它只是传给
        //   OpenTun 回调的选项，由 Kotlin VpnService.Builder（系统合法通道）
        //   建立 0.0.0.0/0 路由与 DNS；置 false 会导致 VPN 无路由、全断网
        // - strict_route / interface_name 移除：二者是桌面内核路由语义，
        //   Android 上要么无意义、要么触发 netlink 权限拒绝；TUN fd 由
        //   OpenTun 回调返回，路由全部由 VpnService.Builder 配置
        let mut tun = json!({
            "type": "tun",
            "tag": TUN_TAG,
            "address": tun_addresses,
            "mtu": 9000,
            "auto_route": true,
            // mixed 栈（仅移动端）：TCP 走系统原生高性能协议栈，UDP 走 gvisor。
            // 原 gvisor 强制用户态 TCP 实现（拥塞控制/滑动窗口全软件模拟）
            // 单核吞吐明显低于系统栈，大流量下载/4K 播放时 CPU 占用高。
            // 桌面端保持 gvisor（随包 sidecar 的编译标签不保证含 gvisor 栈）。
            "stack": if cfg!(any(target_os = "ios", target_os = "android")) {
                "mixed"
            } else {
                "gvisor"
            },
            // 首包嗅探：100ms 内取不到域名即按目标 IP 直连，避免固定等待
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "100ms",
            // UDP NAT 会话保持 5 分钟（默认值，显式声明避免频繁重建）
            "udp_timeout": "5m",
        });
        {
            let obj = tun.as_object_mut().expect("tun inbound is an object");
            if cfg!(target_os = "android") {
                obj.remove("strict_route");
                obj.remove("interface_name");
            } else {
                obj.insert("strict_route".into(), json!(true));
                obj.insert("interface_name".into(), json!("prism-tun"));
            }
        }
        inbounds.push(tun);
    }

    // 5. DNS（1.11 legacy 格式：servers 用 address；1.12 的 type/server 尚未支持）
    //
    // dns-remote 用国内可达的阿里 DoH 直连：原先的 https://1.1.1.1/dns-query 在国内
    // 直连 TCP/443 被墙（kernel.log 实证：dial tcp 1.1.1.1:443: i/o timeout），
    // 所有非 CN 域名解析全部失败，节点服务器为域名的节点必然拨号超时。
    // UDP 53 的 8.8.8.8 同样不可用（污染 + 不可达）。
    // geosite cn 覆盖国内域名（含 .com），".cn" 后缀规则仅作兜底。
    // IPv6 关闭时 ipv4_only：不返回 AAAA，避免 TUN/代理链路下的 v6 泄漏与连接失败。

    // 服务器为域名的节点：节点入口域名（如 node-1.sub.ibuy.eu.cc）必须经国内
    // 解析器解析——它们是面向国内的入口域名，且整条解析链路不得依赖境外可达性。
    // DNS 规则的 outbound 匹配器专门用于匹配「正在拨号的出站 tag」。
    const RESOLVABLE_NODE_TYPES: [&str; 8] = [
        "shadowsocks", "vmess", "vless", "trojan", "tuic", "hysteria", "hysteria2", "wireguard",
    ];
    let is_ip_literal = |s: &str| {
        s.parse::<std::net::Ipv4Addr>().is_ok() || s.parse::<std::net::Ipv6Addr>().is_ok()
    };
    let mut domain_server_tags: Vec<Value> = Vec::new();
    for outbound in &outbounds {
        let ty = outbound.get("type").and_then(|v| v.as_str());
        let server = outbound.get("server").and_then(|v| v.as_str());
        if ty.is_some_and(|t| RESOLVABLE_NODE_TYPES.contains(&t))
            && server.is_some_and(|s| !is_ip_literal(s))
            && let Some(tag) = outbound.get("tag").and_then(|v| v.as_str())
        {
            domain_server_tags.push(json!(tag));
        }
    }

    let mut dns_rules: Vec<Value> = Vec::new();
    if !domain_server_tags.is_empty() {
        // 最具体的规则放最前，优先于 geosite/后缀规则
        dns_rules.push(json!({ "outbound": domain_server_tags, "server": "dns-local" }));
    }
    dns_rules.push(json!({ "geosite": ["cn"], "server": "dns-local" }));
    dns_rules.push(json!({ "domain_suffix": [".cn"], "server": "dns-local" }));

    // Go Cus [Host] 非阻断映射：走本地直连 DNS（防远程 DoH 解析私网域名失败）
    if !cus_dns_local_domains.is_empty() {
        dns_rules.push(json!({ "domain_suffix": cus_dns_local_domains, "server": "dns-local" }));
    }
    // Go Lan 家庭 DNS：lan_domains 域名经隧道内家庭 DNS 解析（置顶最高优先级）
    if let Some(rule) = lan_dns_rule {
        dns_rules.insert(0, rule);
    }

    // dns-local 地址：Go Cus DNS 覆写优先（[General] dns-server / 手动设置）
    let dns_local_addr = cus_dns_override.unwrap_or_else(|| "223.5.5.5".to_string());
    let mut dns_servers = vec![
        // DoH 地址是域名，需 address_resolver 经 dns-local（223.5.5.5）自举解析，
        // 否则 sing-box 报 missing address_resolver
        json!({ "tag": "dns-remote", "address": "https://dns.alidns.com/dns-query", "address_resolver": "dns-local", "detour": "direct" }),
        json!({ "tag": "dns-local", "address": dns_local_addr, "detour": "direct" }),
    ];

    // Android DNS 清洗（APP-2 断层二修复）：
    // Android 被墙环境下阿里 DoH（dns.alidns.com）本身也可能因域名污染/阻断
    // 不可达，改用 tcp://8.8.8.8 并经主组出境更稳（绕过国内 DNS 封锁）。
    // 本地直连 DNS（dns-local）仍用 223.5.5.5 兜底国内域名。
    #[cfg(target_os = "android")]
    {
        if let Some(main_tag) = &main_group_tag {
            dns_servers[0] = json!({
                "tag": "dns-remote",
                "address": "tcp://8.8.8.8",
                "detour": main_tag,
            });
        }
    }
    if let Some(server) = lan_dns_server {
        dns_servers.push(server);
    }
    let dns = json!({
        "servers": dns_servers,
        "rules": dns_rules,
        "final": "dns-remote",
        "strategy": if settings.ipv6 { "prefer_ipv4" } else { "ipv4_only" }
    });

    // 6. clash_api（驱动前端实时数据；地址动态选择，secret 随机生成）
    // 注意：store_selected 等字段在 1.8+ 已从 clash_api 移除，写了会 FATAL
    let cache_path = work_dir.join("cache.db");
    let mut clash_api = json!({
        "external_controller": api_addr
    });
    if !api_secret.is_empty() {
        clash_api["secret"] = json!(api_secret);
    }
    let experimental = json!({
        "clash_api": clash_api,
        "cache_file": {
            "enabled": true,
            "path": cache_path.to_string_lossy()
        }
    });

    // Android DNS 清洗（APP-2 断层二修复）：两条规则放在 route_rules 最顶部
    // （最先匹配），确保所有 UDP/53 和 DNS 协议请求都被劫持到 dns-out，
    // 再由 DNS 模块按 detour 走主组出境，防止内核绕过 sing-box DNS 流程
    // 直连外发；非 Android 平台使用原始 route_rules
    #[cfg(target_os = "android")]
    let final_route_rules: Vec<serde_json::Value> = {
        let mut android_sanitized = vec![
            json!({ "protocol": "dns", "outbound": "dns-out" }),
            json!({ "port": 53, "outbound": "dns-out" }),
        ];
        android_sanitized.extend(route_rules);
        android_sanitized
    };
    #[cfg(not(target_os = "android"))]
    let final_route_rules: Vec<serde_json::Value> = route_rules;

    let mut config = json!({
        "log": { "level": "info", "timestamp": true },
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": final_route_rules,
            "final": final_tag,
            // Android（IPA-12 2.5）：必须关闭——auto_detect_interface 经
            // netlink 枚举默认网卡并按名绑定，Android 11+ SELinux 拦截普通
            // 应用的 netlink 操作（permission denied）。出站 socket 保护由
            // protect 回调（cb_protect → VpnService.protect）完成；桌面/iOS
            // 维持 true（iOS 无 netlink 实现不会实际触发，保持原状不变）
            "auto_detect_interface": !cfg!(target_os = "android")
        },
        "experimental": experimental
    });

    // ---- GO-AIM 4 路隔离探针（APP-4 任务3.1）----
    // 仅存在真实节点时注入：4 个仅绑定 127.0.0.1 的 mixed 入站（2083-2086）
    // 各自独立映射一个专用选择组 GO-AIM-PROBE-0..3（成员 = 全部节点）。
    // go_aim 真实探测引擎把探针选择器切到目标节点后，经对应本地端口发起
    // 7 个平台的真实 HTTPS 请求并按响应判定解锁情况——4 条链路互不影响，
    // 也绝不触碰主选择器/GLOBAL。
    // 路由规则位置：inbound 匹配必须先于 clash_mode 规则（否则全局模式下
    // 探针流量被吞）；Android 上紧随顶部两条 port:53 -> dns-out 之后。
    if !node_tags.is_empty() {
        if let Some(arr) = config["inbounds"].as_array_mut() {
            for (slot, port) in [2083u16, 2084, 2085, 2086].iter().enumerate() {
                arr.push(json!({
                    "type": "mixed",
                    "tag": format!("aim-probe-in-{slot}"),
                    "listen": "127.0.0.1",
                    "listen_port": port,
                    "sniff": false
                }));
            }
        }
        if let Some(arr) = config["outbounds"].as_array_mut() {
            for slot in 0..4 {
                arr.push(json!({
                    "type": "selector",
                    "tag": format!("GO-AIM-PROBE-{slot}"),
                    "outbounds": &node_tags
                }));
            }
        }
        if let Some(rules) = config["route"]["rules"].as_array_mut() {
            let insert_at = rules
                .iter()
                .take_while(|r| {
                    r.get("outbound").and_then(|o| o.as_str()) == Some("dns-out")
                })
                .count();
            for slot in 0..4 {
                rules.insert(
                    insert_at + slot,
                    json!({
                        "inbound": [format!("aim-probe-in-{slot}")],
                        "outbound": format!("GO-AIM-PROBE-{slot}")
                    }),
                );
            }
        }
    }

    // iOS 体积校验（build 145 方案）：网络扩展解析配置的内存峰值与
    // JSON 体积正相关，>100KB 说明订阅节点/组本身过大（内联规则已在
    // 构建期丢弃），打警告供诊断日志远程确认瘦身是否达标
    #[cfg(target_os = "ios")]
    {
        let size = serde_json::to_vec(&config).map(|v| v.len()).unwrap_or(0);
        if size > 100 * 1024 {
            warnings.push(format!(
                "iOS 配置体积 {size} 字节超出网络扩展安全预算（100KB），\
                 若启动仍被强杀需进一步裁剪节点出站"
            ));
        } else {
            warnings.push(format!("iOS 配置体积 {size} 字节（安全预算内）"));
        }
    }

    if total_nodes == 0 && total_groups == 0 {
        // 诊断信息：帮助定位是订阅为空、provider 未下载、还是节点类型不支持
        let mut diag = Vec::new();
        if profiles.is_empty() {
            diag.push("未加载任何订阅".to_string());
        }
        for (i, (url, name, text)) in profiles.iter().enumerate() {
            let p: ClashProfile = serde_yaml::from_str(text.trim()).unwrap_or_default();
            let provider_ok = p
                .proxy_providers
                .keys()
                .filter(|k| {
                    let path = crate::core::store::provider_path(data_dir, url, k);
                    path.exists()
                })
                .count();
            diag.push(format!(
                "订阅{}「{}」: proxies={} groups={} providers={}/{}",
                i + 1,
                name,
                p.proxies.len(),
                p.proxy_groups.len(),
                provider_ok,
                p.proxy_providers.len()
            ));
        }
        bail!(
            "订阅内容未解析到任何节点或策略组。\n诊断：{}\n可能原因：1) 机场限流返回提示页 2) proxy-provider 下载失败 3) 节点类型不支持",
            diag.join("; ")
        );
    }

    Ok(BuiltConfig {
        config,
        warnings,
        final_group: final_tag,
    })
}

// ---------------- 构建小助手 ----------------

/// 转换并登记一个节点出站；apply 决定最终 tag（含冲突改名）。
/// 成功发射时返回最终 tag（用于 GLOBAL 组收集全部节点）。
fn emit_node(
    outbounds: &mut Vec<Value>,
    known_tags: &mut HashSet<String>,
    warnings: &mut Vec<String>,
    node: &ClashNode,
    apply: &dyn Fn(&str) -> String,
    total_nodes: &mut usize,
) -> Option<String> {
    let tag = apply(&node.name);
    if !known_tags.insert(tag.clone()) {
        warnings.push(format!("节点/组标签重复，已跳过：{}", tag));
        return None;
    }
    match node_to_outbound(node) {
        Some((mut outbound, note)) => {
            if outbound.is_null() {
                // 转换器返回 Null：字段缺失等带原因的跳过（区别于未知类型）
                if let Some(note) = note {
                    warnings.push(format!("节点 '{}': {}", node.name, note));
                }
                return None;
            }
            outbound["tag"] = json!(tag);
            if let Some(note) = note {
                warnings.push(format!("节点 '{}': {}", node.name, note));
            }
            outbounds.push(outbound);
            *total_nodes += 1;
            Some(tag)
        }
        None => {
            warnings.push(format!(
                "不支持的节点类型，已跳过 '{}' ({})",
                node.name, node.kind
            ));
            None
        }
    }
}

/// sing-box JSON 透传时，把自定义规则前置合并到 route.rules（只改 JSON，不影响透传语义）
fn merge_json_custom(config: &mut Value, custom_rules: &[String], warnings: &mut Vec<String>) {
    if custom_rules.is_empty() {
        return;
    }
    let mut extra: Vec<Value> = Vec::new();
    for line in custom_rules {
        let parsed = parse_rule_line(line, &|n| map_ref(n), warnings);
        if parsed.final_target.is_some() {
            warnings.push(format!("JSON 透传模式忽略自定义 MATCH 行：{}", line));
        }
        if let Some(rule) = parsed.rule {
            extra.push(rule);
        }
    }
    if extra.is_empty() {
        return;
    }
    // route 缺失时安全创建（避免可变索引插入 null 污染）
    if config.get("route").is_none() {
        config["route"] = json!({});
    }
    let route = config.get_mut("route").expect("route ensured");
    let existing = route
        .get("rules")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    let added = extra.len();
    let merged: Vec<Value> = extra.into_iter().chain(existing).collect();
    route["rules"] = json!(merged);
    warnings.push(format!(
        "已在 JSON 配置前置合并 {} 条自定义规则",
        added
    ));
}

// ---------------- 规则行解析 ----------------

/// 一条 Clash 规则行的解析结果
struct ParsedLine {
    /// route.rules 项（MATCH/FINAL/空行/被跳过时为 None）
    rule: Option<Value>,
    /// MATCH/FINAL 的目标出站（仅本行是 MATCH/FINAL 时）
    final_target: Option<String>,
}

/// 解析一条 Clash 规则行；apply 负责策略名映射（内置 tag 转换 + 多订阅冲突改名）
fn parse_rule_line(
    line: &str,
    apply: &dyn Fn(&str) -> String,
    warnings: &mut Vec<String>,
) -> ParsedLine {
    const NONE: ParsedLine = ParsedLine {
        rule: None,
        final_target: None,
    };
    let parts: Vec<&str> = line.split(',').map(str::trim).collect();
    if parts.is_empty() || parts[0].is_empty() {
        return NONE;
    }

    let kind = parts[0].to_ascii_uppercase();

    // MATCH / FINAL 不产生规则项，只影响 route.final
    if kind == "MATCH" || kind == "FINAL" {
        return ParsedLine {
            rule: None,
            final_target: Some(apply(parts.get(1).copied().unwrap_or("DIRECT"))),
        };
    }

    let Some(payload) = parts.get(1).copied() else {
        warnings.push(format!("规则缺少参数，已跳过：{}", line));
        return NONE;
    };
    let policy = parts.get(2).copied().unwrap_or("DIRECT");
    let outbound = apply(policy);

    let rule = match kind.as_str() {
        "DOMAIN" => Some(json!({ "domain": [payload], "outbound": outbound })),
        "DOMAIN-SUFFIX" => Some(json!({ "domain_suffix": [payload], "outbound": outbound })),
        "DOMAIN-KEYWORD" => Some(json!({ "domain_keyword": [payload], "outbound": outbound })),
        "IP-CIDR" | "IP-CIDR6" => Some(json!({ "ip_cidr": [payload], "outbound": outbound })),
        "GEOIP" => Some(json!({ "geoip": payload, "outbound": outbound })),
        "GEOSITE" => Some(json!({ "geosite": payload, "outbound": outbound })),
        "PROCESS-NAME" => Some(json!({ "process_name": [payload], "outbound": outbound })),
        "PROCESS-PATH" => Some(json!({ "process_path": [payload], "outbound": outbound })),
        "SRC-IP-CIDR" => Some(json!({ "source_ip_cidr": [payload], "outbound": outbound })),
        "SRC-PORT" => Some(json!({ "source_port": [payload.parse::<u32>().unwrap_or(0)], "outbound": outbound })),
        "DST-PORT" => Some(json!({ "port": [payload.parse::<u32>().unwrap_or(0)], "outbound": outbound })),
        "NETWORK" => Some(json!({ "network": payload, "outbound": outbound })),
        // RULE-SET 依赖 rule-providers 元信息，无法从纯 Clash 配置无损转换
        "RULE-SET" => {
            warnings.push(format!(
                "RULE-SET ({}) 需要规则集元信息，已跳过；请改用 GEOSITE 或内核 rule_set",
                payload
            ));
            None
        }
        "AND" | "OR" | "NOT" | "SUB-RULE" => {
            warnings.push(format!("组合规则 {} 暂不支持转换，已跳过", kind));
            None
        }
        other => {
            warnings.push(format!("未知规则类型 {}，已跳过：{}", other, line));
            None
        }
    };

    ParsedLine {
        rule,
        final_target: None,
    }
}

// ---------------- 节点转换 ----------------

/// mihomo 带宽字段（"50" / "50 Mbps"）→ Mbps 数值；取首段数字，
/// 非纯数字头部（如 "5MB/s"）返回 None（sing-box 侧该字段可选）
fn parse_bandwidth(raw: &Option<String>) -> Option<u32> {
    raw.as_deref()
        .and_then(|s| s.trim().split_whitespace().next())
        .and_then(|head| head.parse::<u32>().ok())
}

/// 节点转换；返回 (出站, 可选警告)，未知类型返回 None
pub(crate) fn node_to_outbound(node: &ClashNode) -> Option<(Value, Option<String>)> {
    let base = json!({
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
    });

    let outbound = match node.kind.as_str() {
        "ss" | "shadowsocks" => {
            let mut o = json!({
                "type": "shadowsocks",
                "method": node.cipher.clone().unwrap_or_else(|| "aes-256-gcm".into()),
                "password": node.password.clone().unwrap_or_default(),
            });
            merge(&mut o, &base);

            // SS 简单插件映射（obfs）
            if let Some(plugin) = &node.plugin
                && plugin.starts_with("obfs")
            {
                let mode = node
                    .plugin_opts
                    .as_ref()
                    .and_then(|v| v.get("mode"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("http");
                let host = node
                    .plugin_opts
                    .as_ref()
                    .and_then(|v| v.get("host"))
                    .and_then(|v| v.as_str());
                let plugin = json!({
                    "type": "obfs",
                    "mode": mode,
                    "host": host
                });
                o["plugin"] = plugin;
            }
            (o, None)
        }

        "vmess" => {
            let mut o = json!({
                "type": "vmess",
                "uuid": node.uuid.clone().unwrap_or_default(),
                "security": node.cipher.clone().unwrap_or_else(|| "auto".into()),
                "alter_id": node.alter_id.unwrap_or(0),
            });
            merge(&mut o, &base);
            if let Some(tls) = build_tls(node) {
                o["tls"] = tls;
            }
            let note = attach_transport(&mut o, node);
            (o, note)
        }

        "vless" => {
            let mut o = json!({
                "type": "vless",
                "uuid": node.uuid.clone().unwrap_or_default(),
            });
            if let Some(flow) = &node.flow {
                o["flow"] = json!(flow);
            }
            merge(&mut o, &base);
            if let Some(tls) = build_tls(node) {
                o["tls"] = tls;
            }
            let note = attach_transport(&mut o, node);
            (o, note)
        }

        "trojan" => {
            let mut o = json!({
                "type": "trojan",
                "password": node.password.clone().unwrap_or_default(),
            });
            merge(&mut o, &base);
            // Trojan 始终 TLS
            o["tls"] = tls_block(node);
            let note = attach_transport(&mut o, node);
            (o, note)
        }

        "tuic" => {
            let mut o = json!({
                "type": "tuic",
                "uuid": node.uuid.clone().unwrap_or_default(),
                "password": node.password.clone().unwrap_or_default(),
                "congestion_control": node.congestion_control.clone().unwrap_or_else(|| "bbr".into()),
            });
            merge(&mut o, &base);
            o["tls"] = tls_block(node);
            (o, None)
        }

        "hysteria2" | "hy2" => {
            let mut o = json!({
                "type": "hysteria2",
                "password": node.password.clone().unwrap_or_default(),
            });
            merge(&mut o, &base);
            o["tls"] = tls_block(node);
            // salamander 混淆：Clash obfs / obfs-password → sing-box obfs 块
            if let Some(kind) = &node.obfs
                && !kind.is_empty()
            {
                let mut block = json!({ "type": kind });
                if let Some(password) = &node.obfs_password
                    && !password.is_empty()
                {
                    block["password"] = json!(password);
                }
                o["obfs"] = block;
            }
            (o, None)
        }

        "hysteria" => {
            // Hysteria v1（QUIC）：mihomo 认证字段拼写不一
            // （auth-str / auth_str / auth_str2 / password），依次回退
            let auth_str = node
                .auth_str
                .clone()
                .or_else(|| node.password.clone())
                .unwrap_or_default();
            if auth_str.is_empty() {
                return Some((
                    Value::Null,
                    Some(format!(
                        "节点「{}」hysteria 缺少 auth-str/password 鉴权字段，已跳过",
                        node.name
                    )),
                ));
            }
            let mut o = json!({
                "type": "hysteria",
                "auth_str": auth_str,
            });
            // 带宽提示仅接受纯数字 Mbps（"50 Mbps" 取头部数字，单位串忽略）
            if let Some(bw) = parse_bandwidth(&node.up) {
                o["up_mbps"] = json!(bw);
            }
            if let Some(bw) = parse_bandwidth(&node.down) {
                o["down_mbps"] = json!(bw);
            }
            merge(&mut o, &base);
            o["tls"] = tls_block(node);
            (o, None)
        }

        "wireguard" => {
            // mihomo 裸 IP（10.0.0.2）→ sing-box local_address 需带前缀长度
            let mut local_address: Vec<String> = Vec::new();
            for raw in [node.ip.as_deref(), node.ipv6.as_deref()].into_iter().flatten() {
                for part in raw.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    if part.contains('/') {
                        local_address.push(part.to_string());
                    } else if let Ok(v4) = part.parse::<std::net::Ipv4Addr>() {
                        local_address.push(format!("{v4}/32"));
                    } else if let Ok(v6) = part.parse::<std::net::Ipv6Addr>() {
                        local_address.push(format!("{v6}/128"));
                    }
                }
            }

            let mut o = json!({
                "type": "wireguard",
                "private_key": node.private_key.clone().unwrap_or_default(),
                "peer_public_key": node.public_key.clone().unwrap_or_default(),
                "local_address": local_address,
            });
            if let Some(psk) = &node.preshared_key
                && !psk.is_empty()
            {
                o["pre_shared_key"] = json!(psk);
            }
            if let Some(mtu) = node.mtu {
                o["mtu"] = json!(mtu);
            }
            if let Some(reserved) = &node.reserved
                && reserved.len() == 3
            {
                o["reserved"] = json!(reserved);
            }
            merge(&mut o, &base);
            (o, None)
        }

        // Clash socks5 节点 → sing-box socks 出站（version 默认 5）
        "socks5" | "socks" => {
            let mut o = json!({ "type": "socks", "version": "5" });
            if let Some(u) = &node.username {
                o["username"] = json!(u);
            }
            if let Some(p) = &node.password {
                o["password"] = json!(p);
            }
            merge(&mut o, &base);
            (o, None)
        }

        // Clash http/https 节点 → sing-box http 出站（https 显式带 TLS）
        "http" | "https" => {
            let mut o = json!({ "type": "http" });
            if let Some(u) = &node.username {
                o["username"] = json!(u);
            }
            if let Some(p) = &node.password {
                o["password"] = json!(p);
            }
            merge(&mut o, &base);
            if node.kind == "https" || node.tls.unwrap_or(false) {
                o["tls"] = tls_block(node);
            }
            (o, None)
        }

        _ => return None,
    };

    // 移除值为 null 的可选字段，保持输出干净
    let (mut value, note) = outbound;
    strip_nulls(&mut value);
    Some((value, note))
}

/// 给出站附加传输层；返回可选警告（如 h2 不支持）
fn attach_transport(outbound: &mut Value, node: &ClashNode) -> Option<String> {
    let (transport, warning) = build_transport(node);
    if let Some(transport) = transport {
        outbound["transport"] = transport;
    }
    warning
}

fn build_tls(node: &ClashNode) -> Option<Value> {
    if !node.tls.unwrap_or(false) {
        return None;
    }
    Some(tls_block(node))
}

/// 节点 SNI 解析顺序：sni → servername → ws Host 头 → server。
/// 直接用 server（常为 CDN IP）作 SNI 会被对端拒绝（tls: handshake failure）
fn node_sni(node: &ClashNode) -> String {
    for cand in [&node.sni, &node.servername] {
        if let Some(s) = cand
            && !s.is_empty()
        {
            return s.clone();
        }
    }
    if let Some(host) = node
        .ws_opts
        .as_ref()
        .and_then(|w| w.headers.as_ref())
        .and_then(|h| h.get("Host").or_else(|| h.get("host")))
        && !host.is_empty()
    {
        return host.clone();
    }
    node.server.clone()
}

/// 完整 TLS 块：SNI / insecure / alpn / uTLS 指纹（trojan/hy2 等强制 TLS 的节点也用）
fn tls_block(node: &ClashNode) -> Value {
    let mut tls = json!({
        "enabled": true,
        "server_name": node_sni(node),
        "insecure": node.skip_cert_verify.unwrap_or(false),
    });
    if let Some(alpn) = &node.alpn
        && !alpn.is_empty()
    {
        tls["alpn"] = json!(alpn);
    }
    if let Some(fp) = &node.client_fingerprint
        && !fp.is_empty()
    {
        tls["utls"] = json!({ "enabled": true, "fingerprint": fp });
    }
    // Reality：sing-box 字段为 public_key / short_id；缺 public-key 不启用
    if let Some(reality) = &node.reality_opts
        && let Some(pk) = &reality.public_key
        && !pk.is_empty()
    {
        let mut r = json!({ "enabled": true, "public_key": pk });
        if let Some(sid) = &reality.short_id
            && !sid.is_empty()
        {
            r["short_id"] = json!(sid);
        }
        tls["reality"] = r;
    }
    tls
}

/// 传输层转换；返回 (传输块, 可选警告)。
/// 支持 ws/grpc/http；h2 sing-box 无对应传输，返回警告且不附加传输。
fn build_transport(node: &ClashNode) -> (Option<Value>, Option<String>) {
    match node.network.as_deref() {
        Some("ws") => {
            let mut transport = json!({
                "type": "ws",
                "path": node.ws_opts.as_ref().and_then(|w| w.path.clone()).unwrap_or_else(|| "/".into())
            });
            if let Some(headers) = node.ws_opts.as_ref().and_then(|w| w.headers.clone()) {
                transport["headers"] = json!(headers);
            }
            (Some(transport), None)
        }
        Some("grpc") => (Some(json!({
            "type": "grpc",
            "service_name": node.grpc_opts.as_ref().and_then(|g| g.service_name.clone()).unwrap_or_default()
        })), None),
        Some("http") => {
            let mut transport = json!({ "type": "http" });
            if let Some(opts) = &node.http_opts {
                if let Some(paths) = &opts.path
                    && let Some(first) = paths.first()
                {
                    transport["path"] = json!(first);
                }
                if let Some(method) = &opts.method
                    && !method.is_empty()
                {
                    transport["method"] = json!(method);
                }
                if let Some(headers) = &opts.headers {
                    // Host 头 → sing-box http transport 的 host 列表
                    if let Some(host) = headers.get("Host").or_else(|| headers.get("host")) {
                        transport["host"] = json!(host);
                    }
                    // 其余头原样保留（值为字符串列表，与 sing-box 契约一致）
                    let rest: BTreeMap<&String, &Vec<String>> = headers
                        .iter()
                        .filter(|(k, _)| k.to_ascii_lowercase() != "host")
                        .collect();
                    if !rest.is_empty() {
                        transport["headers"] = json!(rest);
                    }
                }
            }
            (Some(transport), None)
        }
        Some("h2") => (
            None,
            Some(
                "节点使用 HTTP/2 (h2) 传输，内核无对应传输类型，已移除传输（节点可能不可达）"
                    .into(),
            ),
        ),
        _ => (None, None),
    }
}

// ---------------- 策略组转换 ----------------

fn group_to_outbound(
    group: &ClashGroup,
    members: &[String],
    warnings: &mut Vec<String>,
    rename: &HashMap<String, String>,
) -> Value {
    // 成员引用同步应用冲突重命名（多订阅合并时指向本订阅的改名节点/组）
    let refs: Vec<Value> = members
        .iter()
        .map(|r| {
            let mapped = map_ref(r);
            let mapped = rename.get(&mapped).cloned().unwrap_or(mapped);
            json!(mapped)
        })
        .collect();
    let interval = format!("{}s", group.interval.unwrap_or(300));
    let test_url = group.url.clone().unwrap_or_else(|| DEFAULT_TEST_URL.into());

    match group.kind.as_str() {
        "select" | "Selector" => {
            // default 必须指向首个真实节点：部分订阅把 DIRECT 放在首位，
            // 直接取 refs.first() 会让默认出站直连（实测 build 156 全局
            // 模式下自动测速选中 direct）。direct/block 统一挪到队尾，
            // default 取首个非 direct/block 成员（build 157 用户方案）
            let mut ordered: Vec<Value> = Vec::with_capacity(refs.len());
            let mut tail: Vec<Value> = Vec::new();
            for r in refs {
                if matches!(r.as_str(), Some("direct") | Some("block")) {
                    tail.push(r);
                } else {
                    ordered.push(r);
                }
            }
            ordered.extend(tail);
            let mut obj = serde_json::Map::new();
            obj.insert("type".into(), json!("selector"));
            obj.insert("tag".into(), json!(group.name));
            obj.insert("outbounds".into(), Value::Array(ordered.clone()));
            if let Some(default) = ordered.iter().find(|r| {
                !matches!(r.as_str(), Some("direct") | Some("block"))
            }) {
                obj.insert("default".into(), default.clone());
            }
            Value::Object(obj)
        }
        "url-test" | "URLTest" => json!({
            "type": "urltest",
            "tag": group.name,
            "outbounds": refs,
            "url": test_url,
            "interval": interval,
            "tolerance": 50
        }),
        "fallback" | "Fallback" => {
            // sing-box 无 fallback 类型，降级为 urltest（高容忍度近似故障转移）
            warnings.push(format!(
                "策略组 '{}' 类型为 Fallback，内核无对应类型，已降级为 urltest",
                group.name
            ));
            json!({
                "type": "urltest",
                "tag": group.name,
                "outbounds": refs,
                "url": test_url,
                "interval": interval,
                "tolerance": 0
            })
        }
        // sing-box 的 loadbalance 出站 1.12 才引入，当前内核 1.11 不支持，
        // 降级为 urltest（自动选延迟最低节点，行为最接近）
        "load-balance" | "LoadBalance" => {
            warnings.push(format!(
                "策略组 '{}' 为 load-balance，内核 1.11 不支持，已降级为 url-test",
                group.name
            ));
            json!({
                "type": "urltest",
                "tag": group.name,
                "outbounds": refs,
                "url": test_url,
                "interval": interval,
                "tolerance": 50
            })
        }
        other => {
            warnings.push(format!(
                "策略组 '{}' 类型 {} 未知，降级为 selector",
                group.name, other
            ));
            json!({
                "type": "selector",
                "tag": group.name,
                "outbounds": refs
            })
        }
    }
}

// ---------------- 小工具 ----------------

/// Clash 策略引用 → sing-box 内置 tag
fn map_ref(reference: &str) -> String {
    match reference {
        "DIRECT" => "direct".into(),
        "REJECT" | "REJECT-DROP" => "block".into(),
        other => other.into(),
    }
}

/// 将 src 的字段并入 dst（已存在的键会被覆盖）
fn merge(dst: &mut Value, src: &Value) {
    if let (Some(dst_obj), Some(src_obj)) = (dst.as_object_mut(), src.as_object()) {
        for (k, v) in src_obj {
            dst_obj.insert(k.clone(), v.clone());
        }
    }
}

/// 递归移除 null 字段
fn strip_nulls(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let null_keys: Vec<String> = map
                .iter()
                .filter(|(_, v)| v.is_null())
                .map(|(k, _)| k.clone())
                .collect();
            for key in null_keys {
                map.remove(&key);
            }
            for v in map.values_mut() {
                strip_nulls(v);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                strip_nulls(v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归（协议补全）：hysteria v1 认证字段 auth-str / auth_str / auth_str2
    /// 与 password 依次回退；全部缺失时节点被跳过并给出原因
    #[test]
    fn hysteria_v1_auth_str_fallbacks() {
        let yaml = |extra: &str| {
            format!(
                r#"
proxies:
  - {{name: HY1, type: hysteria, server: 1.2.3.4, port: 443, {extra}}}
  - {{name: HK1, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}}
proxy-groups:
  - {{name: 节点选择, type: select, proxies: [HY1, HK1]}}
rules:
  - MATCH,节点选择
"#
            )
        };
        for extra in [
            "auth-str: myauth",
            "auth_str: myauth",
            "auth_str2: myauth",
            "password: myauth",
        ] {
            let built = build(
                &[("https://sub.example".into(), "订阅1".into(), yaml(extra))],
                &[],
                RunMode::SystemProxy,
                &UserSettings::default(),
                &std::env::temp_dir().join("prism-cb-test-hy1"),
                &std::env::temp_dir().join("prism-cb-test-hy1/kernel"),
                "127.0.0.1:9090",
                "secret",
                &crate::core::go_lan::GoLanSettings::default(),
                &crate::core::go_cus::GoCusSettings::default(),
            )
            .unwrap_or_else(|e| panic!("{extra}: {e}"));
            let hy = built.config["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["type"] == "hysteria")
                .unwrap_or_else(|| panic!("{extra}: hysteria outbound missing"));
            assert_eq!(hy["auth_str"].as_str(), Some("myauth"), "{extra}");
        }

        // 全缺鉴权字段：节点被跳过（不出站）且原因写入 warnings
        let built = build(
            &[("https://sub.example".into(), "订阅1".into(), yaml(""))],
            &[],
            RunMode::SystemProxy,
            &UserSettings::default(),
            &std::env::temp_dir().join("prism-cb-test-hy1"),
            &std::env::temp_dir().join("prism-cb-test-hy1/kernel"),
            "127.0.0.1:9090",
            "secret",
            &crate::core::go_lan::GoLanSettings::default(),
            &crate::core::go_cus::GoCusSettings::default(),
        )
        .expect("build must succeed");
        assert!(built.config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["type"] != "hysteria"));
        assert!(built
            .warnings
            .iter()
            .any(|w| w.contains("缺少 auth-str/password")));
    }

    /// 回归（内置分流规则）：域名类内置规则在自定义之后、订阅规则之前；
    /// IP 类（geoip）内置规则必须在订阅规则之后——被墙域名的 DNS 污染
    /// 会返回中国/私有 IP，geoip 规则若在订阅 MATCH 之前会强制解析并
    /// 把应走节点的流量改道直连（「选了节点却上不了网」的根因）。
    /// clash_mode 热切换规则保持置顶。
    #[test]
    fn builtin_rules_placed_between_custom_and_subscription() {
        let clash = r#"
proxies:
  - {name: HK-01, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}
proxy-groups:
  - {name: 节点选择, type: select, proxies: [HK-01]}
rules:
  - DOMAIN-SUFFIX,sub.example.cc,节点选择
  - MATCH,节点选择
"#;
        let built = build(
            &[("https://sub.example".into(), "订阅1".into(), clash.into())],
            &["DOMAIN-SUFFIX,example.org,block".into()],
            RunMode::SystemProxy,
            &UserSettings::default(),
            &std::env::temp_dir().join("prism-cb-test-builtin"),
            &std::env::temp_dir().join("prism-cb-test-builtin/kernel"),
            "127.0.0.1:9090",
            "secret",
            &crate::core::go_lan::GoLanSettings::default(),
            &crate::core::go_cus::GoCusSettings::default(),
        )
        .expect("build must succeed");

        let rules = built.config["route"]["rules"].as_array().unwrap();
        let sig = |r: &Value| -> Option<String> {
            if r.get("clash_mode").is_some() {
                return Some("clash_mode".into());
            }
            if let Some(a) = r.get("domain_suffix").and_then(|v| v.as_array()) {
                if a.iter().any(|x| x.as_str() == Some("example.org")) {
                    return Some("custom".into());
                }
                if a.iter().any(|x| x.as_str() == Some("sub.example.cc")) {
                    return Some("subrule".into());
                }
            }
            match r.get("geosite").and_then(|v| v.as_str()) {
                Some("category-ads-all") => return Some("builtin-ads".into()),
                Some("private") => return Some("builtin-geosite-private".into()),
                Some("cn") => return Some("builtin-cn".into()),
                _ => {}
            }
            match r.get("geoip").and_then(|v| v.as_str()) {
                Some("private") => return Some("builtin-geoip-private".into()),
                Some("cn") => return Some("builtin-geoip-cn".into()),
                _ => {}
            }
            None
        };
        let sigs: Vec<String> = rules.iter().filter_map(sig).collect();
        let find = |k: &str| sigs.iter().position(|s| s == k).unwrap_or_else(|| panic!("{k} missing: {sigs:?}"));
        let (custom, ads, gpriv, cn) = (
            find("custom"),
            find("builtin-ads"),
            find("builtin-geosite-private"),
            find("builtin-cn"),
        );
        let (subrule, ippriv, ipcn) = (
            find("subrule"),
            find("builtin-geoip-private"),
            find("builtin-geoip-cn"),
        );
        // 域名类内置规则：自定义 < 内置（域名类）< 订阅规则
        assert!(custom < ads && ads < gpriv && gpriv < cn, "域名类内置规则顺序: {sigs:?}");
        assert!(cn < subrule, "域名类内置规则必须先于订阅规则: {sigs:?}");
        // IP 类内置规则：订阅规则之后（污染改道回归）
        assert!(
            subrule < ippriv && ippriv < ipcn,
            "geoip 规则必须在订阅规则之后: {sigs:?}"
        );
        // clash_mode 热切换规则置顶（出现在最前两条）
        assert_eq!(&sigs[..2], &["clash_mode", "clash_mode"], "{sigs:?}");
        // route.final 仍取订阅 MATCH 目标
        assert_eq!(built.config["route"]["final"].as_str(), Some("节点选择"));
    }

    /// 回归（DNS 污染改道）：订阅 MATCH 目标的出站链路里不得出现
    /// 前置 geoip 规则——gstatic/youtube 等被墙域名经国内 DNS 解析会返回
    /// 中国 IP（实测 gstatic → 113.108.239.226 广州电信），任何位于
    /// MATCH 之前的 geoip cn/private 都会把这些流量改道直连。
    #[test]
    fn polluted_domains_reach_subscription_final_not_geoip() {
        let clash = r#"
proxies:
  - {name: HK-01, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}
proxy-groups:
  - {name: 节点选择, type: select, proxies: [HK-01]}
rules:
  - MATCH,节点选择
"#;
        let built = build(
            &[("https://sub.example".into(), "订阅1".into(), clash.into())],
            &[],
            RunMode::SystemProxy,
            &UserSettings::default(),
            &std::env::temp_dir().join("prism-cb-test-builtin"),
            &std::env::temp_dir().join("prism-cb-test-builtin/kernel"),
            "127.0.0.1:9090",
            "secret",
            &crate::core::go_lan::GoLanSettings::default(),
            &crate::core::go_cus::GoCusSettings::default(),
        )
        .expect("build must succeed");
        let rules = built.config["route"]["rules"].as_array().unwrap();
        // 规则序列中最后一条非 clash_mode 规则之后的 geoip 规则才合法：
        // 即不允许任何 geoip 规则出现在「最终 MATCH 等价物」（route.final）
        // 之前且拦截了域名为目标的流量——等价判定：geoip 规则之前不允许
        // 存在会把域名流量导向 direct 的规则（geoip 本身）。这里直接验证
        // geoip 规则位于规则列表尾部（其后仅有可能的 empty/最终兜底）。
        let geoip_positions: Vec<usize> = rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.get("geoip").is_some())
            .map(|(i, _)| i)
            .collect();
        if let (Some(first), Some(last)) = (geoip_positions.first(), geoip_positions.last()) {
            // geoip 规则之后不得再有域名规则（订阅 MATCH 不产生规则，
            // 但订阅域名规则必须全部位于 geoip 之前）
            for (i, r) in rules.iter().enumerate().skip(*last + 1) {
                assert!(
                    r.get("geoip").is_some() || r.get("geosite").is_none(),
                    "geoip 之后出现域名规则会重新引入污染改道: idx={i} rule={r}"
                );
            }
            assert!(*first > 0, "sanity");
        }
    }

    /// 回归：预解析曾把全部标签写入 known_tags（发射判重集），
    /// 导致 emit_node 判定所有节点/组「标签重复」而全部跳过 → 0 节点。
    /// 修复后改名追踪走独立的 seen_tags，正常订阅必须发射出节点与组。
    #[test]
    fn multi_sub_emits_all_nodes_not_deduped() {
        let clash = r#"
proxies:
  - name: HK-01
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pw
  - name: US-01
    type: trojan
    server: 5.6.7.8
    port: 443
    password: pw2
proxy-groups:
  - name: 节点选择
    type: select
    proxies: [HK-01, US-01]
rules:
  - MATCH,节点选择
"#;
        let settings = UserSettings::default();
        let data_dir = std::env::temp_dir().join("prism-cb-test-dedupe");
        let work_dir = data_dir.join("kernel");
        std::fs::create_dir_all(&work_dir).unwrap();
        let built = build(
            &[("https://sub.example".into(), "订阅1".into(), clash.into())],
            &[],
            crate::core::state::RunMode::SystemProxy,
            &settings,
            &data_dir,
            &work_dir,
            "127.0.0.1:9090",
            "secret",
            &crate::core::go_lan::GoLanSettings::default(),
            &crate::core::go_cus::GoCusSettings::default(),
        )
        .expect("build must succeed with real nodes");
        let tags: Vec<&str> = built.config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["tag"].as_str())
            .collect();
        assert!(tags.contains(&"HK-01"), "node HK-01 must be emitted, got {tags:?}");
        assert!(tags.contains(&"US-01"), "node US-01 must be emitted, got {tags:?}");
        assert!(tags.contains(&"节点选择"), "group must be emitted, got {tags:?}");
    }

    /// 回归（51 节点只见 10 个）：策略组只引用一个节点时，
    /// 其余「游离节点」必须被追加到主选择组，全部可见/可选。
    #[test]
    fn uncovered_nodes_are_attached_to_main_selector() {
        let clash = r#"
proxies:
  - {name: IN-01, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}
  - {name: IN-02, type: trojan, server: 5.6.7.8, port: 443, password: pw2}
  - {name: IN-03, type: vless, server: node-1.sub.example.cc, port: 443, uuid: u}
proxy-groups:
  - {name: 节点选择, type: select, proxies: [IN-01]}
rules:
  - MATCH,节点选择
"#;
        let built = build(
            &[("https://sub.example".into(), "订阅1".into(), clash.into())],
            &[],
            RunMode::SystemProxy,
            &UserSettings::default(),
            &std::env::temp_dir().join("prism-cb-test-uncovered"),
            &std::env::temp_dir().join("prism-cb-test-uncovered/kernel"),
            "127.0.0.1:9090",
            "secret",
            &crate::core::go_lan::GoLanSettings::default(),
            &crate::core::go_cus::GoCusSettings::default(),
        )
        .expect("build must succeed");

        let selector = built.config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"].as_str() == Some("节点选择"))
            .expect("main selector must exist");
        let members: Vec<&str> = selector["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(members.contains(&"IN-01"), "original member kept: {members:?}");
        assert!(members.contains(&"IN-02"), "uncovered node attached: {members:?}");
        assert!(members.contains(&"IN-03"), "uncovered node attached: {members:?}");
    }

    /// 回归（测速全部超时）：服务器为域名的节点必须出现在 DNS outbound 规则中
    /// 且指向 dns-local；dns-remote 必须是国内可达的 DoH（不再是 1.1.1.1）。
    #[test]
    fn node_server_domains_resolve_via_dns_local() {
        let clash = r#"
proxies:
  - {name: IP-NODE, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}
  - {name: DOM-NODE, type: vless, server: node-9.sub.ibuy.eu.cc, port: 443, uuid: u}
proxy-groups:
  - {name: 节点选择, type: select, proxies: [IP-NODE, DOM-NODE]}
rules:
  - MATCH,节点选择
"#;
        let built = build(
            &[("https://sub.example".into(), "订阅1".into(), clash.into())],
            &[],
            RunMode::SystemProxy,
            &UserSettings::default(),
            &std::env::temp_dir().join("prism-cb-test-dns"),
            &std::env::temp_dir().join("prism-cb-test-dns/kernel"),
            "127.0.0.1:9090",
            "secret",
            &crate::core::go_lan::GoLanSettings::default(),
            &crate::core::go_cus::GoCusSettings::default(),
        )
        .expect("build must succeed");

        let dns = &built.config["dns"];
        let remote = dns["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["tag"].as_str() == Some("dns-remote"))
            .unwrap();
        assert_eq!(
            remote["address"].as_str(),
            Some("https://dns.alidns.com/dns-query"),
            "dns-remote must be a domestically reachable DoH"
        );

        let outbound_rule = dns["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r.get("outbound").is_some())
            .expect("outbound DNS rule must exist");
        let tags: Vec<&str> = outbound_rule["outbound"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(tags.contains(&"DOM-NODE"), "domain-server node routed to dns-local: {tags:?}");
        assert!(!tags.contains(&"IP-NODE"), "IP node must not be listed: {tags:?}");
        assert_eq!(outbound_rule["server"].as_str(), Some("dns-local"));
    }

    /// 真实订阅端到端校验（默认跳过；设 PRISM_REAL_PROFILE=<profile.yaml> 时执行）。
    /// 保证：①每个节点出站都至少被一个策略组引用（节点页不会再"消失"）；
    /// ②每个服务器为域名的节点都在 DNS outbound 规则中（解析不再依赖境外可达性）。
    #[test]
    fn real_subscription_every_node_covered() {
        let Ok(profile_path) = std::env::var("PRISM_REAL_PROFILE") else {
            eprintln!("skipped: set PRISM_REAL_PROFILE to run");
            return;
        };
        let text = std::fs::read_to_string(&profile_path).expect("read real profile");
        let dir = std::env::temp_dir().join("prism-cb-real");
        std::fs::create_dir_all(dir.join("kernel")).unwrap();
        let built = build(
            &[("https://sub.example".into(), "订阅1".into(), text)],
            &[],
            RunMode::SystemProxy,
            &UserSettings::default(),
            &dir,
            &dir.join("kernel"),
            "127.0.0.1:9090",
            "secret",
            &crate::core::go_lan::GoLanSettings::default(),
            &crate::core::go_cus::GoCusSettings::default(),
        )
        .expect("real profile must build");

        // 落盘以便用 sing-box check 做运行期 schema 校验
        std::fs::write(
            dir.join("config.json"),
            serde_json::to_vec_pretty(&built.config).unwrap(),
        )
        .unwrap();

        const NODE_TYPES: [&str; 7] = [
            "shadowsocks", "vmess", "vless", "trojan", "tuic", "hysteria", "hysteria2",
        ];
        let outbounds = built.config["outbounds"].as_array().unwrap();
        let node_tags: Vec<&str> = outbounds
            .iter()
            .filter(|o| o.get("type").and_then(|t| t.as_str()).is_some_and(|t| NODE_TYPES.contains(&t)))
            .filter_map(|o| o["tag"].as_str())
            .collect();

        let mut referenced = std::collections::HashSet::new();
        for o in outbounds {
            if let Some(list) = o.get("outbounds").and_then(|l| l.as_array()) {
                for item in list {
                    if let Some(t) = item.as_str() {
                        referenced.insert(t);
                    }
                }
            }
        }
        let unreferenced: Vec<&&str> = node_tags.iter().filter(|t| !referenced.contains(**t)).collect();
        assert!(unreferenced.is_empty(), "nodes still invisible: {unreferenced:?}");

        let is_ip = |s: &str| {
            s.parse::<std::net::Ipv4Addr>().is_ok() || s.parse::<std::net::Ipv6Addr>().is_ok()
        };
        let domain_nodes: Vec<&str> = node_tags
            .iter()
            .copied()
            .filter(|t| {
                let o = outbounds.iter().find(|x| x["tag"].as_str() == Some(*t)).unwrap();
                o.get("server").and_then(|s| s.as_str()).is_some_and(|s| !is_ip(s))
            })
            .collect();

        let dns_rule_tags: std::collections::HashSet<&str> = built.config["dns"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r.get("outbound").is_some())
            .flat_map(|r| r["outbound"].as_array().unwrap().iter().filter_map(|v| v.as_str()))
            .collect();
        let missing_dns: Vec<&str> = domain_nodes.iter().copied().filter(|t| !dns_rule_tags.contains(t)).collect();
        assert!(missing_dns.is_empty(), "domain nodes missing DNS rule: {missing_dns:?}");
        eprintln!(
            "OK: {} nodes all referenced, {} domain-server nodes covered by dns-local rule",
            node_tags.len(), domain_nodes.len()
        );
    }

    /// 协议补全：Clash wireguard/socks5/http/https 节点必须成功转换为 sing-box
    /// 出站；WG 裸 IP 自动补 /32、/128 前缀；https 节点带 TLS 块。
    #[test]
    fn wireguard_socks_http_nodes_convert() {
        let clash = r#"
proxies:
  - name: WG-01
    type: wireguard
    server: 1.2.3.4
    port: 51820
    private-key: eHpMh6Hc8S1p...example
    public-key: bLvT9zWq2fQ...example
    ip: 10.0.0.2
    ipv6: fdfe:dcba:9876::2
    mtu: 1280
    reserved: [1, 2, 3]
    preshared-key: psk-example
  - name: SOCKS-01
    type: socks5
    server: 5.6.7.8
    port: 1080
    username: alice
    password: s3cret
  - name: HTTP-01
    type: http
    server: proxy.example.com
    port: 8080
    username: bob
    password: pw
  - name: HTTPS-01
    type: https
    server: secure.example.com
    port: 8443
proxy-groups:
  - name: 节点选择
    type: select
    proxies: [WG-01, SOCKS-01, HTTP-01, HTTPS-01]
rules:
  - MATCH,节点选择
"#;
        let dir = std::env::temp_dir().join("prism-cb-test-protocols");
        std::fs::create_dir_all(dir.join("kernel")).unwrap();
        let built = build(
            &[("https://sub.example".into(), "订阅1".into(), clash.into())],
            &[],
            RunMode::SystemProxy,
            &UserSettings::default(),
            &dir,
            &dir.join("kernel"),
            "127.0.0.1:9090",
            "secret",
            &crate::core::go_lan::GoLanSettings::default(),
            &crate::core::go_cus::GoCusSettings::default(),
        )
        .expect("build must succeed with wg/socks/http nodes");

        let outbounds = built.config["outbounds"].as_array().unwrap();
        let find = |tag: &str| {
            outbounds
                .iter()
                .find(|o| o["tag"].as_str() == Some(tag))
                .unwrap_or_else(|| panic!("outbound {tag} must exist"))
        };

        let wg = find("WG-01");
        assert_eq!(wg["type"].as_str(), Some("wireguard"));
        let addrs: Vec<&str> = wg["local_address"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(addrs.contains(&"10.0.0.2/32"), "bare v4 normalized: {addrs:?}");
        assert!(addrs.contains(&"fdfe:dcba:9876::2/128"), "bare v6 normalized: {addrs:?}");
        assert_eq!(wg["mtu"].as_u64(), Some(1280));
        assert_eq!(wg["reserved"][0].as_u64(), Some(1));
        assert_eq!(wg["pre_shared_key"].as_str(), Some("psk-example"));

        let socks = find("SOCKS-01");
        assert_eq!(socks["type"].as_str(), Some("socks"));
        assert_eq!(socks["version"].as_str(), Some("5"));
        assert_eq!(socks["username"].as_str(), Some("alice"));
        assert_eq!(socks["password"].as_str(), Some("s3cret"));

        let http = find("HTTP-01");
        assert_eq!(http["type"].as_str(), Some("http"));
        assert_eq!(http["username"].as_str(), Some("bob"));
        assert!(http.get("tls").is_none(), "plain http has no tls block");

        let https = find("HTTPS-01");
        assert_eq!(https["type"].as_str(), Some("http"));
        assert!(https.get("tls").is_some(), "https node must carry tls block");
    }

    // ============================== Go 引擎集成 ==============================

    #[test]
    fn test_go_lan_rules_before_private_builtin() {
        // 方案 6.3：go-lan-home 回家规则必须位于 geosite: private 与
        // ip_is_private -> direct 之前，否则被"私网直连"抢先命中导致回家失效
        let clash = r#"
proxies:
  - name: HK-01
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pw
proxy-groups:
  - name: 节点选择
    type: select
    proxies: [HK-01]
rules:
  - MATCH,节点选择
"#;
        let lan = crate::core::go_lan::GoLanSettings {
            enabled: true,
            node_uri: "ss://YWVzLTI1Ni1nY206cHc@5.6.7.8:8388#Home".into(),
            lan_cidrs: vec!["192.168.1.0/24".into()],
            lan_domains: vec!["nas.home".into()],
            // 家庭 DNS 未配置时 dns-home 不注入（实现按需降级），测试显式配置
            lan_dns: Some("192.168.1.1".into()),
            ..Default::default()
        };
        let dir = std::env::temp_dir().join("prism-cb-test-golan");
        std::fs::create_dir_all(dir.join("kernel")).unwrap();
        let built = build(
            &[("https://sub.example".into(), "订阅1".into(), clash.into())],
            &[],
            RunMode::SystemProxy,
            &UserSettings::default(),
            &dir,
            &dir.join("kernel"),
            "127.0.0.1:9090",
            "secret",
            &lan,
            &crate::core::go_cus::GoCusSettings::default(),
        )
        .expect("build must succeed");

        let outbounds = built.config["outbounds"].as_array().unwrap();
        assert!(
            outbounds.iter().any(|o| o["tag"].as_str() == Some("go-lan-home")),
            "必须注入 go-lan-home 出站"
        );
        let rules = built.config["route"]["rules"].as_array().unwrap();
        let pos = |pred: &dyn Fn(&Value) -> bool| -> Option<usize> {
            rules.iter().position(|r| pred(r))
        };
        let lan_ip = pos(&|r| {
            r.get("outbound").and_then(Value::as_str) == Some("go-lan-home")
                && r.get("ip_cidr").is_some()
        });
        let private_geosite = pos(&|r| {
            r.get("geosite").and_then(Value::as_str) == Some("private")
                && r.get("outbound").and_then(Value::as_str) == Some("direct")
        });
        let private_ip = pos(&|r| {
            r.get("ip_is_private").and_then(Value::as_bool) == Some(true)
                && r.get("outbound").and_then(Value::as_str) == Some("direct")
        });
        assert!(lan_ip.is_some(), "缺少回家 ip_cidr 规则");
        assert!(private_geosite.is_some(), "缺少内置 geosite: private 规则");
        assert!(private_ip.is_some(), "缺少 ip_is_private 直连规则");
        assert!(lan_ip.unwrap() < private_geosite.unwrap(), "回家规则必须先于 geosite: private");
        assert!(lan_ip.unwrap() < private_ip.unwrap(), "回家规则必须先于 ip_is_private 直连");
        // dns-home 已并入 DNS 配置
        let dns_servers = built.config["dns"]["servers"].as_array().unwrap();
        assert!(
            dns_servers.iter().any(|s| s["tag"].as_str() == Some("dns-home")),
            "lan_domains 需经家庭 DNS 解析，必须注入 dns-home"
        );
    }

    #[test]
    fn test_go_cus_sidecar_and_rules() {
        // 方案 6.3：Go Cus 启用 → 边车出站挂载 + 模块规则注入 + PROXY 占位解析
        let clash = r#"
proxies:
  - name: HK-01
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pw
proxy-groups:
  - name: 节点选择
    type: select
    proxies: [HK-01]
rules:
  - MATCH,节点选择
"#;
        let cus = crate::core::go_cus::GoCusSettings {
            enabled: true,
            mitm_enabled: true,
            modules: vec![crate::core::go_cus::CusModule {
                id: "m1".into(),
                name: "测试".into(),
                desc: None,
                source: "local".into(),
                raw_content: "[Rule]\nDOMAIN-SUFFIX,ads.example.com,REJECT\n[MITM]\nhostname = *.api.example.com\n".into(),
                enabled: true,
                stats: Default::default(),
                updated_at: 0,
            }],
            ..Default::default()
        };
        let dir = std::env::temp_dir().join("prism-cb-test-gocus");
        std::fs::create_dir_all(dir.join("kernel")).unwrap();
        let built = build(
            &[("https://sub.example".into(), "订阅1".into(), clash.into())],
            &[],
            RunMode::SystemProxy,
            &UserSettings::default(),
            &dir,
            &dir.join("kernel"),
            "127.0.0.1:9090",
            "secret",
            &crate::core::go_lan::GoLanSettings::default(),
            &cus,
        )
        .expect("build must succeed");

        let outbounds = built.config["outbounds"].as_array().unwrap();
        assert!(
            outbounds.iter().any(|o| o["tag"].as_str() == Some("go-cus-sidecar")),
            "MitM 域名需要边车出站"
        );
        let rules = built.config["route"]["rules"].as_array().unwrap();
        // 阻断规则存在
        assert!(
            rules.iter().any(|r| r.get("outbound").and_then(Value::as_str) == Some("block")
                && r["domain_suffix"]
                    .as_array()
                    .map(|a| a.iter().any(|v| v.as_str() == Some("ads.example.com")))
                    .unwrap_or(false)),
            "模块 REJECT 规则应编译为 block"
        );
        // MitM 域名路由到边车容错组（边车不可达时回落主组），且不残留 PROXY 占位
        assert!(
            outbounds.iter().any(|o| o["tag"].as_str() == Some("go-cus-fallback")
                && o["type"].as_str() == Some("urltest")),
            "边车必须包进 urltest 容错组"
        );
        assert!(
            rules.iter().any(|r| r.get("outbound").and_then(Value::as_str) == Some("go-cus-fallback")),
            "MitM 域名必须路由到边车容错组"
        );
        assert!(
            rules.iter().all(|r| r.get("outbound").and_then(Value::as_str) != Some("PROXY")),
            "PROXY 占位符必须全部解析为真实组 tag"
        );
    }
}
