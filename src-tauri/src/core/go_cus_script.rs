//! Go Cus 沙盒 JS 执行器（boa_engine，纯 Rust，无 C 依赖）
//!
//! 提供的脚本 API（与 Surge / QuanX 兼容的最小子集）：
//! - `$request{url, method, headers, body}`
//! - `$response{status, headers, body}`（仅响应钩子）
//! - `$done(result)`：result 形如 `{response:{status,headers,body}}` 或
//!   `{request:{url,method,headers,body}}`
//! - `$persistentStore.read(key)` / `.write(value, key)`：落盘
//!   `<data_dir>/go_cus_kv.json`
//! - `$notification.post(title, subtitle, body)`：写入 `[GoCus]` 日志
//! - `console.log(...)`：脱敏 + 单条截断 512 字符后写入 `[GoCus]` 日志
//!
//! 安全边界：
//! - **不注册任何宿主函数**：`$request` / `$persistentStore` / `console` /
//!   `$notification` 全部由注入的纯 JS 代码实现，脚本无法触达文件系统、
//!   进程、环境变量或任何 IPC。
//! - body 超过 512KB 时不进入脚本（由调用方 `body_allowed` 判定后直接透传）。
//! - 单脚本连续 5 次异常/超时自动熔断停用（内存态，重启应用复原）。
//!
//! 超时能力边界（诚实记录）：
//! boa 是解释器而非可抢占的运行环境，**无法从外部强杀正在执行的脚本**。
//! 这里用 `RuntimeLimits::set_loop_iteration_limit` + `set_recursion_limit`
//! 近似约束：死循环脚本最多跑到迭代上限后抛错，深递归在递归/栈上限处抛错。
//! 墙钟 1500ms 只做「事后判定」——执行结束若超过预算，按失败计并计入熔断，
//! 但不保证在 1500ms 时精确中断（不伪装成抢占式超时）。

use std::path::Path;
use std::time::Instant;

use boa_engine::{Context, Source};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde_json::Value;

use crate::core::logger::{self, MOD_GO_CUS};

/// 允许进入脚本的最大 body（字节）
pub const MAX_SCRIPT_BODY_BYTES: usize = 512 * 1024;
/// 墙钟预算（毫秒，事后判定）
pub const WALL_CLOCK_BUDGET_MS: u128 = 1500;
/// 单个循环的最大迭代数（近似时限）
const LOOP_ITERATION_LIMIT: u64 = 5_000_000;
/// 递归深度上限（boa 同时还有宿主栈上限兜底）
const RECURSION_LIMIT: usize = 256;
/// 单条日志最大字符数
const MAX_LOG_CHARS: usize = 512;
/// 连续失败熔断阈值
const MAX_CONSECUTIVE_FAILURES: u32 = 5;
/// 持久化 KV 文件名
const KV_FILE: &str = "go_cus_kv.json";

static CONSECUTIVE_FAILURES: Lazy<DashMap<String, u32>> = Lazy::new(DashMap::new);
static CIRCUIT_OPEN: Lazy<DashMap<String, ()>> = Lazy::new(DashMap::new);

/// body 是否允许进入脚本
pub fn body_allowed(len: usize) -> bool {
    len <= MAX_SCRIPT_BODY_BYTES
}

/// 脚本是否已熔断停用
pub fn is_circuit_open(script_id: &str) -> bool {
    CIRCUIT_OPEN.contains_key(script_id)
}

/// 当前连续失败次数（测试 / 诊断用）
pub fn consecutive_failures(script_id: &str) -> u32 {
    CONSECUTIVE_FAILURES
        .get(script_id)
        .map(|v| *v.value())
        .unwrap_or(0)
}

/// 复原单个脚本的熔断状态
pub fn reset_circuit(script_id: &str) {
    CIRCUIT_OPEN.remove(script_id);
    CONSECUTIVE_FAILURES.remove(script_id);
}

/// 复原全部熔断状态（重启应用等价于此）
pub fn reset_all_circuits() {
    CIRCUIT_OPEN.clear();
    CONSECUTIVE_FAILURES.clear();
}

/// 单次脚本执行结果
#[derive(Debug, Default, Clone)]
pub struct ScriptRun {
    /// `$done(...)` 传入的值；未调用为 None
    pub done: Option<Value>,
    /// 被 `console.*` 输出的日志（已脱敏）
    pub logs: Vec<String>,
    /// `$notification.post` 收集到的三元组
    pub notifications: Vec<(String, String, String)>,
}

/// 执行脚本（边车内部入口）。`script_id` 为熔断/统计键，建议
/// `"<module_id>#<rule_index>"` 或脚本路径。
pub fn run_script(
    data_dir: &Path,
    script_id: &str,
    code: &str,
    request: &Value,
    response: Option<&Value>,
) -> Result<ScriptRun, String> {
    if is_circuit_open(script_id) {
        return Err(format!(
            "脚本 {script_id} 因连续异常已被自动停用（重启应用可复原）"
        ));
    }
    let started = Instant::now();
    let result = execute_inner(data_dir, code, request, response);
    match result {
        Ok(run) => {
            if started.elapsed().as_millis() > WALL_CLOCK_BUDGET_MS {
                let msg = format!(
                    "脚本 {script_id} 执行耗时 {}ms，超过 1500ms 预算（已按失败计）",
                    started.elapsed().as_millis()
                );
                record_failure(script_id, &msg);
                return Err(msg);
            }
            CONSECUTIVE_FAILURES.remove(script_id);
            Ok(run)
        }
        Err(e) => {
            record_failure(script_id, &format!("脚本 {script_id} 执行异常: {e}"));
            Err(e)
        }
    }
}

/// 供命令层 / 前端「测试脚本」按钮调用：执行一次并返回 `$done` 的值。
/// 测试使用独立的脚本键，执行后立即复原，不污染真实规则的熔断状态。
pub fn test_script(data_dir: &Path, script: &str, request_json: Value) -> Result<Value, String> {
    let id = format!("__test__{}", fnv1a(script.as_bytes()));
    let run = run_script(data_dir, &id, script, &request_json, None)?;
    reset_circuit(&id);
    Ok(run.done.unwrap_or(Value::Null))
}

fn record_failure(script_id: &str, message: &str) {
    let count = {
        let mut entry = CONSECUTIVE_FAILURES
            .entry(script_id.to_string())
            .or_insert(0);
        *entry += 1;
        *entry
    };
    if count >= MAX_CONSECUTIVE_FAILURES {
        CIRCUIT_OPEN.insert(script_id.to_string(), ());
        logger::error(
            MOD_GO_CUS,
            format!(
                "{message}；连续 {count} 次失败，已自动停用该脚本（熔断状态常驻内存，重启可复原）"
            ),
        );
    } else {
        logger::warn(
            MOD_GO_CUS,
            format!("{message}（连续失败 {count}/{MAX_CONSECUTIVE_FAILURES}）"),
        );
    }
}

// ---------------------------------------------------------------- 执行内核

fn execute_inner(
    data_dir: &Path,
    code: &str,
    request: &Value,
    response: Option<&Value>,
) -> Result<ScriptRun, String> {
    let kv = read_kv(data_dir);
    let mut ctx = Context::default();
    ctx.runtime_limits_mut()
        .set_loop_iteration_limit(LOOP_ITERATION_LIMIT);
    ctx.runtime_limits_mut()
        .set_recursion_limit(RECURSION_LIMIT);
    // boa 无宿主栈上限接口时由 recursion_limit 兜底
    let prelude = build_prelude(request, response, &kv);
    ctx.eval(Source::from_bytes(&prelude))
        .map_err(|e| format!("沙盒初始化失败: {e:?}"))?;
    ctx.eval(Source::from_bytes(code))
        .map_err(|e| format!("脚本执行异常: {e:?}"))?;
    let text = read_back(&mut ctx)?;
    let parsed: Value =
        serde_json::from_str(&text).map_err(|e| format!("脚本结果读取失败: {e}"))?;

    // KV 回写（仅在脚本确实修改时写盘）
    if let Some(kv_out) = parsed.get("kv").and_then(Value::as_object) {
        let same = kv_out.len() == kv.len()
            && kv_out
                .iter()
                .all(|(k, v)| kv.get(k).map(|old| old == v).unwrap_or(false));
        if !same {
            write_kv(data_dir, kv_out);
        }
    }

    let mut run = ScriptRun::default();
    if parsed
        .get("called")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        run.done = parsed.get("done").cloned();
    }
    if let Some(logs) = parsed.get("logs").and_then(Value::as_array) {
        for line in logs.iter().filter_map(Value::as_str) {
            let safe = sanitize(line);
            run.logs.push(safe.clone());
            logger::info(MOD_GO_CUS, format!("[脚本] {safe}"));
        }
    }
    if let Some(notes) = parsed.get("notes").and_then(Value::as_array) {
        for note in notes.iter().filter_map(Value::as_array) {
            let title = note.first().and_then(Value::as_str).unwrap_or("");
            let subtitle = note.get(1).and_then(Value::as_str).unwrap_or("");
            let body = note.get(2).and_then(Value::as_str).unwrap_or("");
            let safe = sanitize(&format!("{title} | {subtitle} | {body}"));
            run.notifications
                .push((title.to_string(), subtitle.to_string(), body.to_string()));
            logger::info(MOD_GO_CUS, format!("[通知] {safe}"));
        }
    }
    Ok(run)
}

fn read_back(ctx: &mut Context) -> Result<String, String> {
    let probe = "JSON.stringify({called:__prism_done_called,\
                 done:__prism_done_value,\
                 kv:__prism_kv,\
                 logs:__prism_logs,\
                 notes:__prism_notes})";
    let value = ctx
        .eval(Source::from_bytes(probe))
        .map_err(|e| format!("脚本结果读取失败: {e:?}"))?;
    value
        .as_string()
        .map(|s| s.to_std_string_escaped())
        .ok_or_else(|| "脚本结果不是字符串".to_string())
}

/// 组装沙盒前置脚本：全部能力均由纯 JS 实现，不注册任何宿主函数。
fn build_prelude(
    request: &Value,
    response: Option<&Value>,
    kv: &serde_json::Map<String, Value>,
) -> String {
    let request_text = serde_json::to_string(request).unwrap_or_else(|_| "{}".into());
    let response_text = serde_json::to_string(&response.cloned().unwrap_or(Value::Null))
        .unwrap_or_else(|_| "null".into());
    let kv_text = serde_json::to_string(kv).unwrap_or_else(|_| "{}".into());
    // 二次编码为 JS 字符串字面量（JSON.parse 的入参）
    let request_lit = serde_json::to_string(&request_text).unwrap_or_else(|_| "\"{}\"".into());
    let response_lit = serde_json::to_string(&response_text).unwrap_or_else(|_| "\"null\"".into());
    let kv_lit = serde_json::to_string(&kv_text).unwrap_or_else(|_| "\"{}\"".into());
    format!(
        r#"
var $request = JSON.parse({request_lit});
var $response = JSON.parse({response_lit});
var __prism_kv = JSON.parse({kv_lit});
var __prism_logs = [];
var __prism_notes = [];
var __prism_done_called = false;
var __prism_done_value = null;
function $done(result) {{ __prism_done_called = true; __prism_done_value = result; }}
var $persistentStore = {{
  read: function(k) {{
    if (k === undefined || k === null) return null;
    k = String(k);
    return Object.prototype.hasOwnProperty.call(__prism_kv, k) ? __prism_kv[k] : null;
  }},
  write: function(v, k) {{
    if (k === undefined || k === null) return false;
    __prism_kv[String(k)] = v;
    return true;
  }}
}};
function __prism_fmt(args) {{
  var parts = [];
  for (var i = 0; i < args.length; i++) {{
    var a = args[i];
    if (typeof a === 'string') {{ parts.push(a); }}
    else {{ try {{ parts.push(JSON.stringify(a)); }} catch (e) {{ parts.push(String(a)); }} }}
  }}
  return parts.join(' ');
}}
var console = {{
  log: function() {{ __prism_logs.push(__prism_fmt(arguments)); }},
  info: function() {{ __prism_logs.push(__prism_fmt(arguments)); }},
  warn: function() {{ __prism_logs.push(__prism_fmt(arguments)); }},
  error: function() {{ __prism_logs.push(__prism_fmt(arguments)); }}
}};
var $notification = {{
  post: function(t, s, b) {{
    __prism_notes.push([String(t), String(s), String(b)]);
  }}
}};
"#
    )
}

// ---------------------------------------------------------------- KV 持久化

fn kv_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(KV_FILE)
}

fn read_kv(data_dir: &Path) -> serde_json::Map<String, Value> {
    match std::fs::read_to_string(kv_path(data_dir)) {
        Ok(text) => serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default(),
        Err(_) => serde_json::Map::new(),
    }
}

fn write_kv(data_dir: &Path, kv: &serde_json::Map<String, Value>) {
    let text =
        serde_json::to_string_pretty(&Value::Object(kv.clone())).unwrap_or_else(|_| "{}".into());
    if let Err(e) = std::fs::write(kv_path(data_dir), text) {
        logger::warn(MOD_GO_CUS, format!("脚本 KV 落盘失败: {e}"));
    }
}

// ---------------------------------------------------------------- 日志脱敏

static SENSITIVE_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r"(?i)(token|key|password|passwd|secret|auth|sign|session|cookie|authorization)=([^&\s,;]+)",
    )
    .expect("内置脱敏正则必然合法")
});

/// 脱敏 + 单条截断到 512 字符
fn sanitize(text: &str) -> String {
    let masked = SENSITIVE_RE.replace_all(text, "$1=***");
    masked.chars().take(MAX_LOG_CHARS).collect()
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ---------------------------------------------------------------- 测试

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("prism-go-cus-script-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_done_and_request_are_available() {
        let dir = temp_dir("done");
        let request = json!({
            "url": "https://example.com/a",
            "method": "GET",
            "headers": {"x-a": "1"},
            "body": ""
        });
        let code = r#"
            console.log('url=' + $request.url);
            $done({ response: { status: 200, headers: { 'x-test': 'ok' }, body: 'hi' } });
        "#;
        let run = run_script(&dir, "t-done", code, &request, None).expect("脚本应成功");
        assert_eq!(run.done.as_ref().unwrap()["response"]["status"], json!(200));
        assert_eq!(run.logs.len(), 1);
        assert!(run.logs[0].contains("url=https://example.com/a"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_response_hook_and_persistent_store_roundtrip() {
        let dir = temp_dir("kv");
        let request =
            json!({"url": "https://example.com/", "method": "GET", "headers": {}, "body": ""});
        let response = json!({"status": 200, "headers": {}, "body": "old"});
        let code = r#"
            var n = $persistentStore.read('count') || 0;
            $persistentStore.write(n + 1, 'count');
            $done({ response: { status: $response.status, headers: {}, body: 'new' } });
        "#;
        let run = run_script(&dir, "t-kv", code, &request, Some(&response)).expect("脚本应成功");
        assert_eq!(run.done.unwrap()["response"]["body"], json!("new"));
        let stored: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join(KV_FILE)).unwrap()).unwrap();
        assert_eq!(stored["count"], json!(1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_circuit_breaker_after_five_failures() {
        let dir = temp_dir("circuit");
        let request = json!({"url": "https://x/", "method": "GET", "headers": {}, "body": ""});
        let id = "t-circuit";
        reset_circuit(id);
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            assert!(run_script(&dir, id, "throw new Error('boom');", &request, None).is_err());
        }
        assert_eq!(consecutive_failures(id), MAX_CONSECUTIVE_FAILURES);
        assert!(is_circuit_open(id));
        // 熔断后即便正常脚本也不再执行
        assert!(run_script(&dir, id, "$done({ok:1});", &request, None).is_err());
        reset_circuit(id);
        assert!(!is_circuit_open(id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_body_limit() {
        assert!(body_allowed(MAX_SCRIPT_BODY_BYTES));
        assert!(!body_allowed(MAX_SCRIPT_BODY_BYTES + 1));
    }

    #[test]
    fn test_sanitize_truncates_and_masks() {
        let long = format!("token=abcdef&x={}", "a".repeat(600));
        let out = sanitize(&long);
        assert!(out.chars().count() <= MAX_LOG_CHARS);
        assert!(out.contains("token=***"));
        assert!(!out.contains("abcdef"));
    }

    #[test]
    fn test_infinite_loop_is_bounded() {
        let dir = temp_dir("loop");
        let request = json!({"url": "https://x/", "method": "GET", "headers": {}, "body": ""});
        let id = "t-loop";
        reset_circuit(id);
        // 迭代上限触发异常，而不是永久挂起
        let err = run_script(&dir, id, "while (true) {}", &request, None);
        assert!(err.is_err());
        reset_circuit(id);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
