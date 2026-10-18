# 更新日志

本项目版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
每次发布前更新本文件，并在 Git 打对应 tag。
移动端与桌面端共用同一版本 tag；更新内容按平台分节说明。

## [Alpha 0.1.0] - 2026-10-18

> 三大 Pro 引擎上线：Go AIM 解锁加速 / Go Lan 回家网络 / Go Cus 覆写引擎。

### 共用更新（移动端 + 桌面端）

#### Go AIM · AI/流媒体自动探测锁定（Pro）
- 全量节点解锁评级：对每个存活节点经内核单节点延迟端点做 7 点
  二值信号探测（GPT/Claude/Gemini/NF/YT/Disney+/TK），**绝不切换
  全局选择器**，不污染当前连接；结果实时缓存并推送前端徽章。
- 启用后自动锁定「AI 优先 → 流媒体 → 延迟最低」的最优解锁节点；
  节点失联时每 20 秒自动故障转移至次优解锁节点。
- 节点页新增 全部/Go AIM/AI/流媒体 筛选与 AI/NF 徽章及「AI检测」
  一键探测；仪表盘新增 Pro 引擎矩阵卡。

#### Go Lan · 家庭局域网隧穿（Pro）
- 三种配置：手动 WireGuard 完整参数 / 手动回家分享链接 / Managed
  授权服务器下发（POST /api/golan/fetch-config，携带设备识别码与
  授权密钥）。
- `go-lan-home` 出站注入 sing-box 配置，lan_domains / lan_cidrs
  路由规则置于 `geosite: private` 与 `ip_is_private` 之前（否则被
  私网直连抢先命中）；lan_domains 经隧道内家庭 DNS（dns-home）
  解析。
- iOS 扩展智能同网段防环回：本机 Wi-Fi IP 落在回家网段时自动改走
  直连（蜂窝 CGNAT 10.x 豁免）；DNS 重构保留 dns-home 服务器与
  规则；ip_is_private 直连规则强制排在回家规则之后。

#### Go Cus · 全兼容覆写引擎（Pro）
- 全兼容模块解析：Surge `.sgmodule` / QuantumultX `[rewrite_local]`
  / Loon / Stash `.stoverride`，统一产出 规则/URL改写/脚本/MitM/
  Host 五类条目。
- 编译注入：REJECT*→block、DIRECT→direct、其余→主策略组；改写
  阻断域名提取并入 block；重定向/脚本/MitM 域名路由到本地边车
  （127.0.0.1:2081）；DNS 覆写与 [Host] 映射（静态映射降级为本地
  直连解析，内核 1.12 起完整支持）。
- 本地边车：极简异步 HTTP/1.1 处理服务，应用 reject / reject-200 /
  302 / 307 / header 改写；HTTPS CONNECT 级阻断生效。
- MitM CA：纯 Rust 自签名 Root CA（rcgen/ring）+ SHA-256 指纹展示
  + .mobileconfig 描述文件本地分发服务（127.0.0.1:2082）。
- 新增 Go Cus 管理页（模块/改写/MitM/脚本 四子标签）；脚本 Alpha
  版完成解析与展示，JS 执行器后续接入（诚实标注）。

#### 其他
- 版本号统一切换为 Alpha 0.1.0 体系（package.json / tauri.conf.json /
  Cargo.toml 同步）。

## [0.3.14] - 2026-10-17

> 锁屏防误停、安全区适配与仪表盘节点卡片优化。

### 共用更新（移动端 + 桌面端）
- **仪表盘「当前节点」卡片**：顶部标签禁止换行，右箭头移到节点名
  称行右侧——启动前后布局一致，三列窄卡片内不再折行变形；未启动
  时读取订阅缓存展示第一个节点名并支持点击预选节点。
- **移动端顶部安全区**：滚动容器上方新增固定占位条
  （max(safe-area-inset-top, 48px)），页面标题不再与系统时间/信号
  栏重叠，滚动时内容不穿透到状态栏下方。
- **启动空缓存兜底**：启用订阅缺失本地缓存时（云同步对账时网络
  抖动只建了保底记录），启动内核前自动补拉一次再继续，无需先去
  订阅页手动更新。

### 移动端（iOS）
- **锁屏防误杀**：看门狗心跳滞后时先校验系统连接状态——仍为
  connected/reasserting/connecting 一律保持连接（iOS 休眠会挂起
  定时器导致心跳文件停更，utun 与隧道实际正常待机）；仅系统也判定
  断开才走崩溃处理路径。
- **无网卡时不热重载**：网卡探测新增 hasRoutableIP 标记，仅真实
  可路由网卡才触发热重载；电梯/飞行模式等短暂无网时保持隧道待机
  等信号恢复，绝不切到死网卡报错停止。

## [0.3.13] - 2026-10-17

> 根治订阅下载「error decoding response body」与三种模式上网断连。

### 共用更新（移动端 + 桌面端）
- **订阅下载流式容错**：弃用整包读取改为 chunk 分段流式——Cloudflare
  Worker 类端点下发完正文后常不发 TLS close_notify（或 HTTP/2 提前
  重置流），整包读取会把已完整收到的数据以 error decoding response
  body 整包丢弃；流末尾报错时只要已收到有效内容即保留使用。
- **直连客户端 http1_only**：规避 HTTP/2 流异常关闭诱因；UA 统一为
  ClashforWindows/0.20.39 并带 Accept-Encoding: identity（禁压缩
  协商，规避解压器报错）。
- **geoip 抢跑兜底**：内置规则在订阅规则之后、geoip 之前新增
  geosite geolocation-!cn → 主选择组——无规则订阅（纯节点）下被墙
  域名零解析开销直达节点，不再触发 geoip cn 的污染解析改道直连。
- **GLOBAL 组同步选择**：手动选点与启动自动测速同时同步主组与
  GLOBAL 组，全局模式不再落到 GLOBAL 默认第一个节点。
- **开关 SVG 化**：Switch 组件改为 44×24 SVG viewBox 内绘轨道+滑块
  （内置 ✓/− 图标，零 CSS 位移），滑块物理上不可能冲出轨道。

### 移动端（iOS）
- **DNS 致命修正**：扩展配置 dns-remote 从 tcp://1.1.1.1 改为
  tcp://8.8.8.8——Cloudflare 官方安全策略禁止 Worker 节点出站连接
  1.1.1.1，代理 DNS 请求 100% 被边缘拒绝导致全部域名无法解析。
- **DNS 模式分流补齐**：DNS rules 新增 clash_mode direct → dns-direct、
  global → dns-remote、geosite cn/private → dns-direct——直连模式下
  国内域名 DNS 不再被强送代理 DNS。

## [0.3.12] - 2026-10-17

> 修复「订阅同步了却没有节点」与开关滑块溢出。

### 共用更新（移动端 + 桌面端）
- **订阅云同步空壳重拉**：对账时本地已有记录但缓存文件缺失、或解析
  不出可用节点（127.x 机场提示节点不算）的「空壳」订阅，自动重新
  拉取内容——上一台设备同步时下载失败只建了保底记录，本台设备
  登录后对账即可补齐节点（根治「有订阅没节点」）。
- **保底记录不误导**：云端拉取下载失败时先建的保底记录
  updated_at 置 0，订阅页显示「从未更新」标识内容待补，不再伪装
  「刚刚更新」。
- **同步结果静默通知**：对账发生增删/补拉后后台 emit
  subscriptions://changed 与 proxies://changed，订阅页与节点页
  自动刷新，全程无弹窗。
- **订阅下载 UA 伪装**：直连双栈与本地代理转发统一使用
  mihomo/1.18.3 ClashMetaForAndroid/2.10.1.Meta + Accept: */*，
  防止机场面板按 UA 返回浏览器提示页（0 节点）。
- **节点缓存双格式解析**：get_cached_proxies 在 Clash YAML 解析失败
  或无节点时回退 base64/URI 逐行解析，不再静默跳过导致列表为空。
- **开关滑块溢出修复**：Switch 组件改为 flex + padding 确定性布局
  （36×20 轨道 + 16px 滑块，两侧各留 2px），滑块不再溢出轨道。

## [0.3.11] - 2026-10-17

> 修复 iOS 端 VPN 隧道「managers=0 ↔ Code=12」死循环（build 169 方案）。

### 移动端（iOS）
- **修复选择节点后无法通过节点代理上网**：三个组合 Bug 形成死循环——
  1. `recoverOrFinish` 遇 Code=12 且扩展无心跳时自动删除 VPN 配置，
     导致 managers=0；现改为任何失败路径绝不删配置，仅调一次
     PrismHelper killext 清理驻留旧扩展进程，reload 会话句柄后 1.0s
     自动重试一次（仅一次，防循环）；
  2. 新建配置 saveToPreferences 后未 loadFromPreferences 即启动隧道，
     nesessionmanagerd 会话未绑定必报 Code=12；现保存后先
     loadFromPreferences 并等待 0.8s 再 startVPNTunnel；
  3. 覆盖安装时 disable/enable 连续双写易卡死系统会话；现仅 killext
     一次 + 保持 isEnabled 单次 save。
- **init() 级最早心跳**：扩展进程被系统实例化瞬间即写入 "init" 心跳，
  精准区分「进程未拉起」与「拉起了但未进 startTunnel」。
- **主副包版本一致性兜底**：CI 从主程序 Info.plist 读回
  CFBundleShortVersionString 强制写入 appex，杜绝 pkd 因版本漂移拒载。

## [0.3.10] - 2026-10-16

> 修复「选择了节点却无法通过节点上网」的路由回归。

### 共用更新（移动端 + 桌面端）
- **修复节点代理失效**：v0.3.8 引入的内置分流规则中，IP 类直连规则
  （geoip private / geoip cn）位于订阅规则（MATCH）之前。sing-box 对
  域名目标命中 IP 类规则会强制触发 DNS 解析，被墙域名经国内 DNS 解析
  返回的是 GFW 污染的中国 IP（如 gstatic → 113.108.239.226），命中
  geoip cn 后流量被改道直连——表现为已选择节点但无法代理上网。
  现将 IP 类内置规则移至订阅规则之后：订阅 MATCH 命中的流量（被墙
  域名，无论 DNS 污染成什么 IP）直接走节点；未被订阅覆盖的流量仍按
  真实 IP 兜底局域网/国内直连。域名类内置规则（广告拦截、geosite
  private/cn）不触发解析，保持在订阅规则之前。新增两个回归测试锁定
  规则顺序，防止复发。

## [0.3.9] - 2026-10-16

> 订阅云端同步（Pro/买断）、设置页重排 + APP 版本展示、节点协议补全。

### 共用更新（移动端 + 桌面端）
- **订阅云端同步**（Pro/买断会员，全程静默）：首次激活后自动把本地订阅
  链接同步到授权中心；更换设备登录相同授权信息后自动双向合并——云端
  新增的拉取到本地、云端已删除的同步删除、本地新增未上报的自动上传
  （上限 5 条）。添加/删除订阅即时报云端；服务端管控（sync_paused/
  sync_disabled）时本次会话自动停用，瞬态失败静默重试。
- **设置页调整**：「PRISM PRO」板块移至「代理内核」之后；设备 ID 下方
  新增 APP 版本显示。
- **节点协议补全**：Hysteria v1 支持 mihomo 全部认证字段拼写
  （auth-str / auth_str / auth_str2 → password 回退）与 up/down 带宽字段；
  SSR 分享链接改为明确报错（内核 sing-box 1.6.0+ 已移除该协议），
  不再解析后静默丢失。

## [0.3.8] - 2026-10-16

> 授权断网可用、内置常见分流规则、仪表盘直接切换节点、测速结果按延迟排序。

### 共用更新（移动端 + 桌面端）
- **授权离线不再锁定**：首次激活同步授权中心信息（key、邮箱、有效期），
  AES-256-GCM 设备绑定加密落盘；联网时每日与服务器同步一次并更新本地
  加密缓存，断网时授权信息直接从该文件读取——未过期继续可用，仅缓存
  有效期已过才降级为 expired，恢复联网后自动以服务端结果修正。
- **内置常见分流规则**（全平台生效）：局域网/私有网段直连、广告域名拦截
  （geosite category-ads-all）、国内域名与网段直连（geosite/geoip cn）；
  优先级为自定义规则 > 内置规则 > 订阅规则，仅引用随包分发的 geo 数据库
  （数百字节引用，非内联展开），移动端内存安全。
- **仪表盘「当前节点」**：「运行时长」指标卡改为「当前节点」，实时显示
  主选择组正在使用的节点名，点击弹出节点选择器（按延迟从低到高排列），
  一键指定使用节点。
- **测速按延迟排序**：节点测速完成后按延迟从低到高排列（未测速的保持
  原序居中、超时的垫底），测速进行中不重排避免列表跳动，无测速数据时
  保持订阅原始顺序。
- 修复节点变化事件名不匹配（后端 `proxies://changed` vs 前端监听
  `proxies::changed`）：启动自动选点后，节点页与仪表盘现在能正确刷新。

## [0.3.7] - 2026-10-07

> 修复 v0.3.4-0.3.6 均未根治的两个问题：订阅节点大量「消失」、测速全部超时。
> 本次以用户真实订阅做了端到端实证（51 节点全部可见、实测延迟正常）。
> 同时优化订阅导入速度、补全主流节点协议，并按「专业区域放专业模块」
> 全面梳理各页面功能归属。

### 共用修复（移动端 + 桌面端）
- **修复订阅节点大量「消失」**：部分订阅的 `proxies` 含全部节点，但
  `proxy-groups` 只引用其中一小部分（用户订阅 51 个节点，组仅引用 10 个
  CB节点），按组展示的节点页导致其余 41 个节点不可见。配置构建器现在将
  未被任何策略组引用的「游离节点」自动补入主选择组（route.final 链末端的
  selector），全部节点可见、可选、可测速；不改变订阅原有的默认选择。
- **修复测速全部超时**：
  - DNS 远端解析器从国内直连被墙的 `https://1.1.1.1/dns-query`
    （kernel.log 实证 `dial tcp 1.1.1.1:443: i/o timeout`）改为国内可达的
    `https://dns.alidns.com/dns-query`，并配置 `address_resolver` 自举解析。
  - 节点服务器域名（如 `node-1.sub.ibuy.eu.cc`）新增 DNS `outbound` 规则，
    强制经国内解析器（223.5.5.5）解析，节点拨号不再依赖任何境外可达性。
- **订阅导入速度优化**：
  - 订阅地址的「自动双栈」与「强制 IPv4」两次尝试由**串行**改为**竞速**：
    IPv6 出口黑洞时原实现要白等 10s 连接超时才发起第二次，现在任一栈先
    成功立即返回，连接超时同时收紧到 8s。
  - 订阅内 `proxy-providers` 由**逐个串行下载**改为**全部并发下载**，
    N 个 provider 的总耗时从 N 倍 RTT 降为约等于最慢的一个；
    全链路增加毫秒级耗时日志。
- **补全主流节点协议**：
  - Clash 订阅新增 `wireguard`、`socks5`、`http/https` 节点转换（此前这些
    节点会被静默跳过）；WireGuard 本端裸 IP 自动补全 /32、/128 前缀，
    支持 MTU、reserved、预共享密钥。
  - 分享链接新增 `socks5://`（兼容 userinfo 与 query 两种鉴权写法）。
  - 注：SSR 已被 sing-box 在 1.6.0 移除（内核注册直接返回错误），
    无法支持；当前流行协议 VLESS/Reality、Hysteria2、TUIC、Trojan 等均已支持。
- 新增 5 个回归测试（累计 Rust 20 个 / 前端 35 个）：协议转换、
  socks5 链接解析、游离节点补挂、域名解析规则、真实订阅全节点覆盖校验。

### 移动端（iOS / Android）
- 设置页隐藏移动端不成立的选项：「系统代理」接入模式、「设置系统代理」
  开关、「开机自启动」及「以管理员身份运行」提示；接入模式仅保留 TUN。
- **实现真正的系统级 VPN 代理（重大架构升级）**：移动端启动内核时建立
  系统 VPN 接管全局流量，与商业代理软件（SFA/SFI）同款技术路线——
  - 内核侧集成 sing-box **libbox**（官方移动端承载层）：新增
    `PrismVPNStart/PrismVPNStop/PrismVPNSetCallbacks` 导出，
    `PlatformInterface` 实现 OpenTun / AutoDetectInterfaceControl（protect）/
    WriteLog 等完整回调链；TUN 选项（地址/路由/DNS/MTU/分应用）序列化为
    JSON 传给宿主原生层。
  - **Android**：新增前台 `PrismVpnService`（VpnService.Builder →
    `establish()` 返回 TUN fd 交予内核；`protect()` 保护底层拨号 socket
    防止路由回环；`onRevoke` 撤销后自动停止代理并通知前端；常驻通知栏；
    13+ systemExempted 前台服务类型；本 App 流量排除出隧道）。Rust 经
    JNI（jni crate）驱动 Kotlin `PrismVpnBridge`，启动前先经系统弹窗
    请求 VPN 授权（`VpnService.prepare`）。
  - **iOS**：新增 `PrismVPN` Network Extension（NEPacketTunnelProvider），
    内核运行于扩展进程内：`setTunnelNetworkSettings` 配置地址/路由/DNS，
    `packetFlow` 文件描述符交予内核；主 App 通过 NETunnelProviderManager
    启停隧道（PrismTunnelController.swift）。CI 经 xcodeproj 注入扩展
    target（链接 libprismkernel.a、打包 geo 数据库）并嵌入主 App。
  - 配置构建器：移动端配置始终包含 TUN 入站（原仅桌面 TUN 模式）；
    TUN 地址迁移到 sing-box 1.10+ 合并后的 `address` 字段（legacy
    `inet4_address` 在 1.11 会 FATAL）。
- 启动前统一进行系统 VPN 授权预检；未授权时给出明确提示。
- 前端监听系统 VPN 撤销事件（用户在系统设置关闭/其他 VPN 抢占）：
  自动停止内核并对齐状态，弹窗提示。

### 桌面端（Windows / macOS / Linux）
- **移除节点页重复的「启动内核」按钮**：启停入口统一收敛到仪表盘，
  节点页空状态改为引导「前往仪表盘启动」；仪表盘按钮文案简化为「启动 / 停止」。

### 验证记录
- 真实订阅：clash API 返回 51 个 VLESS 节点；主选择组 55 个成员
  （含全部节点）；实测 `CB节点 10` 437ms、`UCN优选12` 1093ms。
- 新协议配置通过 `sing-box check` 运行期校验（wireguard/socks/http 出站）。
- 五目标交叉编译：Windows x64、macOS x64/ARM、iOS、Android 全部通过。
- Go 内核（libbox VPN 集成）本地完整编译 + go vet 通过（含移动端构建标签）。
- TUN 入站配置（`address` 合并字段）通过 `sing-box check` 运行期校验。
- 个别节点返回 503 为节点服务端当下不可用（机场节点质量问题），非客户端问题。

## [0.3.6] - 2026-10-07

> 0.3.5 桌面端正常出包，但移动端 CI 编译失败，移动端产物缺失；
> 本版本修复该编译错误，内容与 0.3.5 完全一致，五端重新出包。

### 移动端（iOS / Android）
- **修复 v0.3.5 移动端编译失败**：`platform/mod.rs` 顶部对
  `windows/macos/linux::ProxyBackup` 的 re-export 未加平台门控，
  移动端目标无这些模块，报 E0432 无法解析导入。现 `ProxyBackup`
  类型统一定义在 `mod.rs`，各平台模块通过 `super::ProxyBackup` 引用，
  移动端 `get_system_proxy` 返回空备份（无系统代理概念，运行时为 no-op）。
- 功能与 0.3.5 一致：仪表盘「今日流量」会话内实时统计、关闭清零。

### 桌面端（Windows / macOS / Linux）
- 无功能变更；上述重构对桌面端行为无影响，随同一 tag 重新出包。
- 功能与 0.3.5 一致：系统代理独占（启动备份/停止恢复）、关闭最小化到托盘。

## [0.3.5] - 2026-10-07

### 移动端（iOS / Android）
- **仪表盘简化**：隐藏「内存占用」卡片，替换为「今日流量」——实时显示当前会话
  累计流量（关闭 APP 后自动清零），无持久化存储负担。

### 桌面端（Windows / macOS / Linux）
- **系统代理独占性**：启动时备份当前系统代理设置，停止/退出时恢复原设置，
  确保只有当前运行的 Prism 的代理配置生效，不干扰其他代理软件。
- 点关闭按钮自动最小化到系统托盘；托盘菜单提供「显示主窗口」「退出」。

### 共用修复
- 修复节点测速全部失败：`group_url_test` 改为逐节点调用 `/proxies/{name}/delay`，
  解决 sing-box 1.11.3 `/group` 端点不返回成员延迟的问题。
- 修复订阅节点丢失：新增 hysteria（hy）协议支持；base64 解码兼容 URL-safe
  字符集；前端过滤嵌套策略组，避免把组当成节点展示。
- 移除「手动代理」接入模式：旧配置自动映射为系统代理，避免用户误选后无法上网。
- Pro 功能调整：连接管理改为免费；Pro 保留 TUN 模式、多订阅、规则自定义。

## [0.3.3] - 2026-10-07

### 移动端（iOS / Android）
- **修复节点测速全部失败**：`group_url_test` 原先调用 `/group/{name}/delay`，
  但 sing-box 1.11.3 对该端点只返回组本身延迟而非成员 map，导致前端把全部
  节点标记为超时。改为逐个节点调用 `/proxies/{name}/delay` 汇总，结果可靠。
- **修复订阅节点丢失**：新增 hysteria（hy）协议解析支持；base64 解码改为
  尝试标准/URL-safe 两种字符集；URI 解析增加节点计数日志便于排查。
- **移除「手动代理」接入模式**：旧配置中的 `ruleOnly` 自动映射为系统代理，
  避免用户误选后无法上网。Pro 功能保留 TUN/多订阅/规则自定义，
  连接管理改为免费功能。

### 桌面端（Windows / macOS / Linux）
- 同上三项修复。
- 接入模式选项从三个减为两个（系统代理 / TUN），UI 更简洁。

## [0.3.3] - 2026-10-07

### 移动端（iOS / Android）
- **修复 v0.3.2 Release 缺失移动端产物**：`mobile.yml` 此前仅在 push main 时
  构建为 workflow artifact（不进 Release），导致 tag Release 只有桌面端。
  现改为 tag 触发，并将已签名 Android APK 与 TrollStore IPA 通过
  `softprops/action-gh-release` 上传到同一 Release。

### 桌面端（Windows / macOS / Linux）
- 无功能变更，随同一 tag `v0.3.3` 出包。

## [0.3.2] - 2026-10-07

> 0.3.1 因移动端构建失败未发布，其 tag 作废，全部内容并入本版本。

### 移动端（iOS / Android）
- **修复 0.3.1 构建失败**（此前 0.3.0 起移动端无法出包）：
  - iOS：`kernel.rs` 中 `clear_kernel_pid(self.pid)` 缺少 `not(ios, android)`
    门控，导致 iOS 编译报 `cannot find function clear_kernel_pid`
  - Android：Go 在 android 目标不支持 `-buildmode=c-archive`，改用
    `-buildmode=c-shared` 产出四架构 `.so`（arm64-v8a / armeabi-v7a /
    x86 / x86_64），`build.rs` 以 dylib 链接，CI 拷入 `jniLibs/<abi>/` 随 APK 打包
- **geo 数据库改为编译期内嵌**（iOS + Android 统一方案）：实测 Tauri iOS
  不会把 bundle resources 打进 .app（数组/映射写法均无效），APK assets
  亦非真实文件系统；改用 `include_bytes!` 内嵌进主二进制，启动时写入
  工作目录。数据库文件缺失即编译失败，天然成为构建期硬校验
- Android 内嵌内核完整落地：sing-box 1.11.3 进程内运行，四架构全覆盖

### 桌面端（Windows / macOS / Linux）
- 本版本桌面端无功能变更，随同一 tag 正常出包
- 沿用 0.3.0 的零运行时下载方案：内核 sidecar + geo 数据库随包分发，
  缺失直接报错（应用不联网下载任何内核文件），CI 打包前硬校验

## [0.3.1] - 2026-10-07（构建失败，未发布）

- 尝试修复 0.3.0 移动端构建失败（iOS cfg 门控 + Android c-shared），
  但 iOS geo 数据库 bundle 问题未在此版本内解决，tag 作废。

## [0.3.0] - 2026-10-07

### 核心变更
- **全平台零运行时下载**：内核（sing-box）与 geoip/geosite 数据库必须随安装包分发，
  任何平台缺失时直接报错，绝不依赖用户网络补齐（用户网络可能无法访问 GitHub）
- **Android 内嵌内核**：与 iOS 相同，sing-box 以 c-archive 静态链接进主程序
  （四架构 arm64/arm/386/amd64），不再有 sidecar 与运行时下载
- **Android geo 数据库编译期内嵌**：APK assets 非真实文件系统，
  改用 `include_bytes!` 在编译期打入二进制，启动时写入工作目录
- **桌面端删除 `kernel_download.rs`**：缺失内核直接提示重新安装

### UI 防混淆
- 设置页「运行模式」→「接入模式」，与「出站模式」明确区分两个独立维度
- 消除重名：RunMode 的 `TUN 全局`→`TUN 虚拟网卡`、`仅规则`→`手动代理`；
  OutboundMode 的 `规则`→`规则分流`、`全局`→`全局代理`、`直连`→`全部直连`
- 内核校验按钮图标由 `Download` 改为 `ShieldCheck`（不再下载）
- 连接管理页 ProGate 包裹整页（原工具栏在门外可点但表格被锁）
- 规则页策略输入补充 direct/block/策略组名 提示
- 节点页空状态按钮「更新订阅」→「管理订阅」
- 模式切换增加 toast 反馈（运行中=已重启生效，未运行=下次启动生效）

### 测试
- 引入 Vitest + Testing Library 测试基础设施
- 抽取 modes / latency / ruleType / time 纯逻辑模块
- 35 个单元测试覆盖模式标签唯一性、延迟/规则类型映射、时间与字节格式化

### CI
- 桌面 `build.yml` 打包前硬校验 sidecar + geoip.db + geosite.db 均已就位
- Android `mobile.yml` 新增 Go 环境、geo 数据库抓取、四架构 c-archive 构建

## [0.2.0] - 历史版本
- 初始公开发布版本
