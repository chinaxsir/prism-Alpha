/**
 * 代理 / 节点 / 连接 / 规则 / Go Cus 词条。
 * 由「代理集群」任务维护（ProxiesHub / Proxies / Connections / Rules / GoCus）。
 */
const zh: Record<string, string> = {
  // ---- 节点 / Go AIM 筛选 ----
  "proxies.aim.ai": "AI",
  "proxies.aim.media": "流媒体",
  "proxies.aim.probing": "正在检测节点的 AI 与流媒体解锁能力，请稍候…",
  "proxies.aim.probingDesc":
    "检测逐节点进行，结果会实时刷新到列表中；检测期间可继续浏览「全部」节点。",
  "proxies.proto.direct": "直连",
  "proxies.proto.block": "阻断",
  "proxies.goAim.guard": "请先激活 Pro 授权以使用 Go AIM 智能筛选与检测",
  "proxies.autoSelected": "已自动选择延迟最低节点：{name}",
  "proxies.err.noMainGroup": "未找到主选择组，请先启动内核",
  "proxies.err.noNodesToTest": "当前没有可测速的节点",
  "proxies.err.testFailed": "测速失败：{error}",
  "proxies.err.coreNotRunningProbe": "内核未运行，无法探测",
  "proxies.goAim.probeStarted": "Go AIM 探测已启动，结果将实时更新",
  "proxies.empty.noNodes": "暂无节点",
  "proxies.empty.noNodesDesc":
    "请导入订阅或更新已导入的订阅；启动内核后可在此测速、切换节点。",
  "proxies.manageSub": "管理订阅",
  "proxies.goDashboard": "前往仪表盘启动",
  "proxies.goAim.lockedTip": "Pro 功能：激活授权后可用",
  "proxies.goAim.probeTip": "运行 Go AIM 解锁探测（AI / 流媒体）",
  "proxies.goAim.probeNeedCore": "启动内核后可探测",
  "proxies.goAim.detect": "AI检测",
  "proxies.searchNodes": "搜索节点…",
  "proxies.speedTestNeedCore": "启动内核后可测速",
  "proxies.speedTest": "测速",
  "proxies.speedTesting": "测速中",
  "proxies.current": "当前：",
  "proxies.notSelected": "未选择",
  "proxies.coreNotRunningPreview": "· 内核未运行（预览模式）",
  "proxies.nodeCount": "{count} 节点",
  "proxies.empty.noMatch": "无符合筛选条件的节点",
  "proxies.resetFilter": "重置筛选",
  "proxies.badge.netflix": "Netflix (NF)",
  "proxies.badge.ai": "AI 解锁",

  // ---- 连接 ----
  "proxies.conn.active": "活跃",
  "proxies.conn.tcp": "TCP",
  "proxies.conn.udp": "UDP",
  "proxies.conn.status": "状态",
  "proxies.conn.time": "时间",
  "proxies.conn.protocol": "协议",
  "proxies.conn.source": "来源",
  "proxies.conn.target": "目标",
  "proxies.conn.matchedRule": "命中规则",
  "proxies.conn.outbound": "出站节点",
  "proxies.conn.traffic": "流量 ↑/↓",
  "proxies.conn.action": "操作",
  "proxies.conn.resume": "继续",
  "proxies.conn.pause": "暂停",
  "proxies.conn.closeAllTip": "全部关闭（断开内核当前所有连接）",
  "proxies.conn.clearList": "清空列表",
  "proxies.conn.paused": "已暂停接收连接事件",
  "proxies.conn.empty": "暂无连接记录（内核未启动或无流量）",
  "proxies.conn.allClosed": "已关闭全部连接",
  "proxies.conn.closeThis": "关闭此连接",
  "proxies.conn.quickRule": "快捷分流",
  "proxies.conn.quickRuleTitle": "为 {host} 添加规则",
  "proxies.conn.quickRuleDirect": "直连 DIRECT",
  "proxies.conn.quickRuleProxy": "走节点 PROXY",
  "proxies.conn.quickRuleReject": "拦截 REJECT",
  "proxies.conn.ruleAdded": "已添加规则：{rule}",
  "proxies.failover": "节点 {from} 不可用，已自动切换",

  // ---- 规则 ----
  "proxies.rules.customTitle": "自定义规则（{count} 条）",
  "proxies.rules.customDesc": "自上而下优先匹配，全部排在订阅规则之前",
  "proxies.rules.payloadPlaceholder": "规则内容，如 google.com 或 1.2.3.0/24",
  "proxies.rules.policyPlaceholder": "策略：direct / block / 策略组名",
  "proxies.rules.add": "添加",
  "proxies.rules.policyHint":
    "策略可选：direct（直连）、block（拦截），或订阅中的策略组名（内核运行时自动列出）。留空默认 direct。",
  "proxies.rules.saved": "自定义规则已保存",
  "proxies.rules.err.emptyPayload": "请输入规则内容（域名 / IP / 关键词）",
  "proxies.rules.err.exists": "规则已存在",
  "proxies.rules.effectiveTitle": "生效规则（{count} 条，含内置 / 自定义与订阅）",
  "proxies.rules.empty": "暂无规则（内核未启动）",

  // ---- Go Cus ----
  "proxies.goCus.tab.modules": "模块",
  "proxies.goCus.tab.rewrites": "改写",
  "proxies.goCus.tab.mitm": "MitM",
  "proxies.goCus.tab.scripts": "脚本",
  "proxies.goCus.loadFailed": "Go Cus 设置读取失败，请重启应用后重试",
  "proxies.goCus.engineTitle": "Go Cus 引擎",
  "proxies.goCus.engineDesc":
    "覆写 / 改写 / MitM / 脚本 —— 兼容 Loon · Surge · QuantumultX 模块",
  "proxies.goCus.engineSwitch": "Go Cus 引擎总开关",
  "proxies.goCus.importTitle": "导入模块",
  "proxies.goCus.importDesc":
    "支持 http(s) 模块链接，或直接粘贴模块内容（Loon / Surge / QX 格式）",
  "proxies.goCus.importPlaceholder":
    "https://example.com/module.snippet 或粘贴模块内容",
  "proxies.goCus.noModules": "暂无模块",
  "proxies.goCus.noModulesDesc":
    "支持导入兼容格式的模块、覆写规则与脚本（.sgmodule / .conf / .plugin / .stoverride），导入后规则 / 改写 / 脚本 / MitM 声明将分别在此展示",
  "proxies.goCus.remote": "远程",
  "proxies.goCus.local": "本地",
  "proxies.goCus.disableModule": "停用模块",
  "proxies.goCus.enableModule": "启用模块",
  "proxies.goCus.deleteModule": "删除模块",
  "proxies.goCus.rewritesTitle": "改写规则（{count} 条）",
  "proxies.goCus.fromModulesOnly": "来自已启用模块，仅展示",
  "proxies.goCus.noRewrites": "暂无改写规则",
  "proxies.goCus.noRewritesDesc":
    "启用包含 [URL Rewrite] 区段的模块后在此展示",
  "proxies.goCus.mitmDesc":
    "开启后对下方主机名的 HTTPS 流量进行解密，供改写与脚本使用",
  "proxies.goCus.mitmSwitch": "MitM 总开关",
  "proxies.goCus.mitmHostsTitle": "MitM 主机名（{count} 个）",
  "proxies.goCus.noMitmHosts":
    "暂无 MitM 主机名（启用包含 [mitm] 区段的模块后在此展示）",
  "proxies.goCus.caTitle": "CA 证书",
  "proxies.goCus.caGenerate": "生成 / 读取 CA",
  "proxies.goCus.caFingerprint": "SHA-256 指纹",
  "proxies.goCus.caInstallUrl": "安装链接",
  "proxies.goCus.installCopied": "安装链接已复制",
  "proxies.goCus.copyInstall": "复制安装链接",
  "proxies.goCus.caTrusted": "我已在系统安装并信任该证书",
  "proxies.goCus.caHint":
    "HTTPS 改写与脚本需安装 CA 并信任（iOS 需在 设置→通用→关于本机→证书信任设置 中开启完全信任）。",
  "proxies.goCus.scriptsTitle": "脚本（{count} 个）",
  "proxies.goCus.noScripts": "暂无脚本",
  "proxies.goCus.noScriptsDesc":
    "启用包含 [Script] 区段或 script-* 改写的模块后在此展示",
  "proxies.goCus.scriptPathCopied": "脚本路径已复制",
  "proxies.goCus.clickToCopy": "点击复制：{path}",
  "proxies.goCus.scriptAlphaNote":
    "Alpha 版脚本已完成解析与展示，JS 执行器将在后续版本接入。",
  "proxies.goCus.err.emptySource": "请输入模块链接或直接粘贴模块内容",
  "proxies.goCus.importSuccess": "模块「{name}」导入成功",
  "proxies.goCus.deleteConfirm": "确定删除模块「{name}」？该操作不可撤销。",
  "proxies.goCus.moduleDeleted": "模块已删除",
  "proxies.goCus.caGenerated": "CA 证书已生成",
};

const en: Record<string, string> = {
  // ---- Nodes / Go AIM filter ----
  "proxies.aim.ai": "AI",
  "proxies.aim.media": "Streaming",
  "proxies.aim.probing":
    "Detecting AI & streaming unlock capability for each node, please wait…",
  "proxies.aim.probingDesc":
    "Detection runs node by node and results stream into the list in real time. You can keep browsing the All tab meanwhile.",
  "proxies.proto.direct": "Direct",
  "proxies.proto.block": "Block",
  "proxies.goAim.guard":
    "Please activate Pro to use Go AIM smart filtering and probing",
  "proxies.autoSelected": "Auto-selected the lowest-latency node: {name}",
  "proxies.err.noMainGroup":
    "Main selector group not found, please start the core first",
  "proxies.err.noNodesToTest": "No nodes available for a speed test",
  "proxies.err.testFailed": "Speed test failed: {error}",
  "proxies.err.coreNotRunningProbe": "Core is not running, cannot probe",
  "proxies.goAim.probeStarted":
    "Go AIM probe started, results will update in real time",
  "proxies.empty.noNodes": "No nodes",
  "proxies.empty.noNodesDesc":
    "Import a subscription or update existing ones; once the core is running you can speed-test and switch nodes here.",
  "proxies.manageSub": "Manage Subscriptions",
  "proxies.goDashboard": "Go to Dashboard to start",
  "proxies.goAim.lockedTip": "Pro feature: available after activation",
  "proxies.goAim.probeTip": "Run Go AIM unlock probe (AI / streaming)",
  "proxies.goAim.probeNeedCore": "Probe available after starting the core",
  "proxies.goAim.detect": "AI Check",
  "proxies.searchNodes": "Search nodes…",
  "proxies.speedTestNeedCore": "Speed test available after starting the core",
  "proxies.speedTest": "Speed Test",
  "proxies.speedTesting": "Testing",
  "proxies.current": "Current:",
  "proxies.notSelected": "None",
  "proxies.coreNotRunningPreview": "· Core not running (preview mode)",
  "proxies.nodeCount": "{count} nodes",
  "proxies.empty.noMatch": "No nodes match the current filter",
  "proxies.resetFilter": "Reset filters",
  "proxies.badge.netflix": "Netflix (NF)",
  "proxies.badge.ai": "AI unlocked",

  // ---- Connections ----
  "proxies.conn.active": "Active",
  "proxies.conn.tcp": "TCP",
  "proxies.conn.udp": "UDP",
  "proxies.conn.status": "Status",
  "proxies.conn.time": "Time",
  "proxies.conn.protocol": "Protocol",
  "proxies.conn.source": "Source",
  "proxies.conn.target": "Target",
  "proxies.conn.matchedRule": "Matched Rule",
  "proxies.conn.outbound": "Outbound",
  "proxies.conn.traffic": "Traffic ↑/↓",
  "proxies.conn.action": "Action",
  "proxies.conn.resume": "Resume",
  "proxies.conn.pause": "Pause",
  "proxies.conn.closeAllTip":
    "Close all (disconnect all current core connections)",
  "proxies.conn.clearList": "Clear list",
  "proxies.conn.paused": "Paused receiving connection events",
  "proxies.conn.empty":
    "No connection records (core not started or no traffic)",
  "proxies.conn.allClosed": "All connections closed",
  "proxies.conn.closeThis": "Close this connection",
  "proxies.conn.quickRule": "Quick rule",
  "proxies.conn.quickRuleTitle": "Add a rule for {host}",
  "proxies.conn.quickRuleDirect": "Direct",
  "proxies.conn.quickRuleProxy": "Via proxy",
  "proxies.conn.quickRuleReject": "Reject",
  "proxies.conn.ruleAdded": "Rule added: {rule}",
  "proxies.failover": "Node {from} is unavailable, switched automatically",

  // ---- Rules ----
  "proxies.rules.customTitle": "Custom Rules ({count})",
  "proxies.rules.customDesc":
    "Matched top-down with priority, all placed before subscription rules",
  "proxies.rules.payloadPlaceholder":
    "Rule content, e.g. google.com or 1.2.3.0/24",
  "proxies.rules.policyPlaceholder": "Policy: direct / block / policy group name",
  "proxies.rules.add": "Add",
  "proxies.rules.policyHint":
    "Policy can be direct, block, or a policy group name from the subscription (auto-listed when the core is running). Empty defaults to direct.",
  "proxies.rules.saved": "Custom rules saved",
  "proxies.rules.err.emptyPayload":
    "Please enter the rule content (domain / IP / keyword)",
  "proxies.rules.err.exists": "Rule already exists",
  "proxies.rules.effectiveTitle":
    "Effective Rules ({count}, incl. built-in / custom & subscription)",
  "proxies.rules.empty": "No rules (core not started)",

  // ---- Go Cus ----
  "proxies.goCus.tab.modules": "Modules",
  "proxies.goCus.tab.rewrites": "Rewrites",
  "proxies.goCus.tab.mitm": "MitM",
  "proxies.goCus.tab.scripts": "Scripts",
  "proxies.goCus.loadFailed":
    "Failed to load Go Cus settings, please restart the app and try again",
  "proxies.goCus.engineTitle": "Go Cus Engine",
  "proxies.goCus.engineDesc":
    "Rewrite / redirect / MitM / scripts — compatible with Loon · Surge · QuantumultX modules",
  "proxies.goCus.engineSwitch": "Go Cus engine master switch",
  "proxies.goCus.importTitle": "Import Module",
  "proxies.goCus.importDesc":
    "Supports http(s) module links, or paste module content directly (Loon / Surge / QX format)",
  "proxies.goCus.importPlaceholder":
    "https://example.com/module.snippet or paste module content",
  "proxies.goCus.noModules": "No modules",
  "proxies.goCus.noModulesDesc":
    "Compatible formats: .sgmodule / .conf / .plugin / .stoverride. Imported rules / rewrites / scripts / MitM declarations appear here",
  "proxies.goCus.remote": "Remote",
  "proxies.goCus.local": "Local",
  "proxies.goCus.disableModule": "Disable module",
  "proxies.goCus.enableModule": "Enable module",
  "proxies.goCus.deleteModule": "Delete module",
  "proxies.goCus.rewritesTitle": "Rewrite Rules ({count})",
  "proxies.goCus.fromModulesOnly": "From enabled modules, view only",
  "proxies.goCus.noRewrites": "No rewrite rules",
  "proxies.goCus.noRewritesDesc":
    "Enable modules containing an [URL Rewrite] section to display them here",
  "proxies.goCus.mitmDesc":
    "When enabled, decrypts HTTPS traffic for the hostnames below for rewrites and scripts",
  "proxies.goCus.mitmSwitch": "MitM master switch",
  "proxies.goCus.mitmHostsTitle": "MitM Hostnames ({count})",
  "proxies.goCus.noMitmHosts":
    "No MitM hostnames (enable modules containing a [mitm] section to display them here)",
  "proxies.goCus.caTitle": "CA Certificate",
  "proxies.goCus.caGenerate": "Generate / Load CA",
  "proxies.goCus.caFingerprint": "SHA-256 Fingerprint",
  "proxies.goCus.caInstallUrl": "Install Link",
  "proxies.goCus.installCopied": "Install link copied",
  "proxies.goCus.copyInstall": "Copy install link",
  "proxies.goCus.caTrusted":
    "I have installed and trusted this certificate on the system",
  "proxies.goCus.caHint":
    "HTTPS rewrites and scripts require the CA to be installed and trusted (on iOS enable full trust in Settings → General → About → Certificate Trust Settings).",
  "proxies.goCus.scriptsTitle": "Scripts ({count})",
  "proxies.goCus.noScripts": "No scripts",
  "proxies.goCus.noScriptsDesc":
    "Enable modules containing a [Script] section or script-* rewrites to display them here",
  "proxies.goCus.scriptPathCopied": "Script path copied",
  "proxies.goCus.clickToCopy": "Click to copy: {path}",
  "proxies.goCus.scriptAlphaNote":
    "Alpha scripts are parsed and displayed; the JS runtime will be added in a later version.",
  "proxies.goCus.err.emptySource":
    "Please enter a module link or paste module content",
  "proxies.goCus.importSuccess": "Module \"{name}\" imported successfully",
  "proxies.goCus.deleteConfirm": "Delete module \"{name}\"? This cannot be undone.",
  "proxies.goCus.moduleDeleted": "Module deleted",
  "proxies.goCus.caGenerated": "CA certificate generated",
};

export default { zh, en };
