/** 仪表盘词条 */
const zh: Record<string, string> = {
  "dashboard.title": "仪表盘",
  "dashboard.pickerTitle": "选择节点",
  "dashboard.noSelection": "未选择",
  "dashboard.pickerSwitched": "已切换节点：{name}",
  "dashboard.pickerPreselected": "已预选节点：{name}（内核启动后生效）",
  "dashboard.pickerFailed": "切换节点失败：{error}",
  "dashboard.runModeLabel": "运行模式 · {mode}",
  "dashboard.errorTitle": "操作失败",
  "dashboard.proBannerDesc":
    "激活授权解锁 AI/流媒体智选、回家内网直通与脚本覆写引擎",
  "dashboard.proEngines": "Pro 智联引擎",
  "dashboard.aim.locked": "已锁定: {node} · 已评级解锁 {count} 个节点",
  "dashboard.aim.pinned": "已指定: {node}（手动锁定）",
  "dashboard.aim.restoreAuto": "恢复自动",
  "dashboard.aim.idle": "自动优选解锁 ChatGPT / Claude / Netflix 的最低延迟节点",
  "dashboard.aim.probing": "探测中",
  "dashboard.aim.retest": "重测",
  "dashboard.aim.retestFailed": "重测失败：{error}",
  "dashboard.lan.managed": "组网模式",
  "dashboard.lan.manual": "手动模式",
  "dashboard.lan.configured": "{mode} · 内网 {cidrs}",
  "dashboard.lan.unset": "未配置回家网络 · 点击右侧配置",
  "dashboard.cus.enabled": "已启用 {modules} 个模块 · {rewrites} 改写 / {scripts} 脚本",
  "dashboard.cus.unset": "未配置模块 · 点击右侧导入",
  "dashboard.lan.configureFirst":
    "请先配置 Go Lan 回家网络参数并保存后，再启用该功能",
  "dashboard.cus.configureFirst": "请先添加或导入至少一个 Go Cus 模块后再启用",
};

const en: Record<string, string> = {
  "dashboard.title": "Dashboard",
  "dashboard.pickerTitle": "Select Node",
  "dashboard.noSelection": "Not selected",
  "dashboard.pickerSwitched": "Switched to {name}",
  "dashboard.pickerPreselected": "Preselected {name} (applies after kernel starts)",
  "dashboard.pickerFailed": "Failed to switch node: {error}",
  "dashboard.runModeLabel": "Mode · {mode}",
  "dashboard.errorTitle": "Operation Failed",
  "dashboard.proBannerDesc":
    "Activate to unlock Go AIM, Go Lan home network and the Go Cus rewrite engine",
  "dashboard.proEngines": "Pro Engines",
  "dashboard.aim.locked": "Locked: {node} · {count} nodes rated & unlocked",
  "dashboard.aim.pinned": "Pinned: {node} (manual lock)",
  "dashboard.aim.restoreAuto": "Auto",
  "dashboard.aim.idle":
    "Auto-picks the lowest-latency node unlocking ChatGPT / Claude / Netflix",
  "dashboard.aim.probing": "Probing",
  "dashboard.aim.retest": "Retest",
  "dashboard.aim.retestFailed": "Retest failed: {error}",
  "dashboard.lan.managed": "Managed",
  "dashboard.lan.manual": "Manual",
  "dashboard.lan.configured": "{mode} · LAN {cidrs}",
  "dashboard.lan.unset": "Home network not configured · tap Configure",
  "dashboard.cus.enabled": "{modules} modules enabled · {rewrites} rewrites / {scripts} scripts",
  "dashboard.cus.unset": "No modules configured · tap Import",
  "dashboard.lan.configureFirst":
    "Please configure and save Go Lan home network parameters before enabling",
  "dashboard.cus.configureFirst":
    "Add or import at least one Go Cus module before enabling",
};

export default { zh, en };
