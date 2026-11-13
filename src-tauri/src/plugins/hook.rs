//! 插件钩子事件定义

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum HookEvent {
    /// DNS 解析前：插件可返回自定义 IP 或拒绝
    PreDnsResolve { domain: String },
    /// 连接建立前：插件可修改目标、强制指定出站
    PreConnect {
        source: String,
        dest_host: String,
        dest_port: u16,
        network: String,
    },
    /// HTTP 请求/响应改写（去广告等）
    HttpRequest {
        url: String,
        headers: Vec<(String, String)>,
    },
    HttpResponse {
        url: String,
        status: u16,
        body: Vec<u8>,
    },
    /// 规则匹配后：插件可覆盖匹配结果
    PostRuleMatch {
        matched_rule: String,
        outbound: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum HookResult {
    Pass,
    Reject,
    Modify { payload: serde_json::Value },
}
