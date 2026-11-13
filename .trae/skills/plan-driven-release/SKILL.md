---
name: plan-driven-release
description: Run a plan-doc release for Prism Alpha end to end including audit, Rust/Swift/frontend edits, verification, version bump, tag and push. Use when the user attaches appNN.txt and says 按此方案更新. Not for single-file fixes.
---

# Plan-Driven Release (Prism Alpha)

用户上传 `appNN.txt` 方案文档并说「按此方案进行更新」时，按本流程执行。核心原则：**先审计、再改动、后验证、最后发版**，任何一项不通过不得声称完成。

## 0. 方案解析与现状审计（必须先做）

1. 读取方案全文，把每条要求拆成可验证的条目，标记为 `已实现 / 部分实现 / 未实现 / 已过时`。
2. 用 Grep 审计现状，**不要按方案字面直接覆盖已有代码**。方案常基于旧版本写成，文档里的「预期代码」可能与仓库中已落地的更优实现冲突。
3. 若方案某条已被当前等价实现覆盖（例如 DNS final、route 顺序），保留现状，在最终报告中说明理由；仅在方案提供了明确故障证据时才重写。
4. 记录审计结论到 TodoWrite，进入实施。

## 1. 关键文件地图

| 层 | 文件 |
|---|---|
| AIM 探测引擎 | `src-tauri/src/core/go_aim.rs` |
| sing-box 配置生成 | `src-tauri/src/core/config_builder.rs` |
| Clash API 封装 | `src-tauri/src/core/kernel.rs` |
| 日志 | `src-tauri/src/core/logger.rs`（`MOD_GO_AIM`） |
| iOS 网络扩展 | `src-tauri/mobile-src/ios/PrismVPN/PacketTunnelProvider.swift` |
| 前后端契约 | `src/api/ipc.ts` |
| 代理页 UI | `src/pages/Proxies.tsx` |
| 节点报告 | `src/utils/aimReport.ts` + `aimReport.test.ts` |
| 文案 | `src/i18n/parts/proxies.ts` |
| 版本号 | `package.json`、`src-tauri/tauri.conf.json`、`src-tauri/Cargo.toml`、`src-tauri/Cargo.lock` |

## 2. 实施顺序

1. **Rust 核心**：先改 `go_aim.rs` / `config_builder.rs`，立即 `cargo check --lib`，把编译错误清零再继续。
2. **Swift 同步**：Rust 生成的配置必须与 `PacketTunnelProvider.swift` 的兜底逻辑逐项一致（DNS 上游、`dns.rules`、`route.rules` 顺序、tun 地址、`sniff*`、端口拦截）。改一处 Rust 配置就检查一遍 Swift。
3. **前端契约**：`ipc.ts` 补字段（全部可选 `?:`，保持向后兼容），再改 UI。列表徽章规则通常是「只显示 VERIFIED」，其余状态只在详情面板展示。
4. **测试**：更新受影响的断言，并为新行为补回归测试。

## 3. 本仓库已知陷阱

- **Swift 与 Rust 双份配置漂移**：历史上多次出现 Rust 已改、Swift 仍是旧值（`sniff_override_destination`、`tcp://8.8.8.8`）。这是最高频回归源，必须成对修改。
- **源码扫描型测试**：多个测试用 `include_str!("go_aim.rs")` 截取函数体做字符串断言。修改函数签名、文案或判定顺序会让它们失败；改逻辑后同步改断言。
- **AimNodeResult 构造点分散**：新增字段会导致多处 E0063（`probe_node` 汇总、`dead_result`、`all_unknown_result`、`egress_unknown_result`、`proxy_failed_result`），用 `cargo check` 逐个补齐。
- **版本常量与淘汰测试**：改 `CURRENT_AIM_PROBE_VERSION` / `CURRENT_AIM_RULE_VERSION` 后，必须同步 `test_version_eviction_constants` 的期望值；语义变化（判定规则改变）必须升版本以淘汰旧缓存，否则 UI 继续显示错误结论。
- **不要写死地区名单参与解锁判定**：AIM 的解锁/封锁结论只能来自 HTTP 状态码、重定向落地 URL、正文业务特征。出口国家（`exit_country`）只能用于展示。
- **硬超时与并发**：单平台硬超时、单节点平台并发（Semaphore）是防止瞬时限流的必要手段；超时必须包在 permit 获取之后，排队时间不计入平台超时。
- **PowerShell 输出截断**：命令输出多用 `2>&1 | Select-Object -Last N`，但被截断的行不会显示前面的编译错误；排查时先用 `cargo check --lib` 单独跑一次。
- **前端 i18n**：新增可见文案要同时写中英文；`t("...")` 的插值参数若未定义会导致 TS 报错或显示原始 key。

## 4. 验证矩阵（顺序执行，全部通过）

```powershell
cargo fmt --manifest-path "src-tauri/Cargo.toml"
cargo check --manifest-path "src-tauri/Cargo.toml" --lib      # 0 error / 0 warning
cargo test  --manifest-path "src-tauri/Cargo.toml"
npm run test                                                  # vitest
npm run build                                                 # tsc + vite
npm run verify:ios                                            # 脚本自检 18 项
cargo check --manifest-path "src-tauri/Cargo.toml" --target aarch64-linux-android --lib
cargo check --manifest-path "src-tauri/Cargo.toml" --target aarch64-apple-darwin --lib
```

- Windows 上 `aarch64-apple-ios` 交叉编译必然因缺少 `xcrun` 失败，属于环境限制；iOS 以 `npm run verify:ios` 为准，不要伪报通过。
- 仓库没有 `verify:android` / `verify:macos` 脚本，不要调用不存在的 script。
- 测试失败先读完整错误再改，禁止通过删除断言或放宽阈值「修复」。

## 5. 版本与发版

1. 版本号顺延（已发布过 `v0.4.4` 就不能再发 `v0.4.4`），四个文件同步：`package.json`、`tauri.conf.json`、`Cargo.toml`、`Cargo.lock`（`Cargo.lock` 用 `cargo check` 自动刷新）。
2. 提交前确认 `git status` 只包含本次相关文件，不带入临时产物。
3. 提交与推送：

```powershell
git add <明确列出的文件>
git commit -m "release: vX.Y.Z"
git tag -a vX.Y.Z -m "Prism Alpha vX.Y.Z"
git push alpha main --follow-tags
git push origin main --follow-tags
```

4. 推送后核对：`git log --oneline -3`、`git ls-remote --tags origin vX.Y.Z`、`git ls-remote --tags alpha vX.Y.Z`、`git status --short`（应为空）。
5. **禁止**重写已发布 tag（不要 `git tag -f` 覆盖旧版本）；**禁止** force push。

## 6. 交付报告

按以下结构回复，简洁、可核对：

- 修复概览：分模块列出「问题 → 改法」，附 `file:///` 行号链接
- 验证结果表：命令 / 结果（逐项）
- Git：commit hash、tag、双远程推送状态、工作区是否干净
- 偏差说明：方案中未采纳的条目及原因（若无可省略）
