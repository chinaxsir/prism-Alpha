/**
 * 分析页词条（Top 主机名 / 策略分布 / 规则统计 / 规则命中）。
 * 由「分析」页面维护（Analytics.tsx）。
 */
const zh: Record<string, string> = {
  "analytics.title": "分析",
  "analytics.coreNotRunningHint": "内核未运行，仅展示已采集数据",
  "analytics.hostsTitle": "Top 主机名（按流量）",
  "analytics.outboundTitle": "策略分布（按出站）",
  "analytics.ruleTypesTitle": "规则统计（按类型）",
  "analytics.ruleHitsTitle": "规则命中（按流量）",
  "analytics.emptyConnections": "暂无连接数据",
  "analytics.emptyHits": "暂无命中记录",
  "analytics.emptyRules": "暂无规则",
  "analytics.coreNotRunning": "内核未运行",
  "analytics.hitsCount": "{count} 次",
  "analytics.other": "其他",
  "analytics.displayDomain": "域名",
  "analytics.displayIp": "IP",
};

const en: Record<string, string> = {
  "analytics.title": "Analytics",
  "analytics.coreNotRunningHint": "Kernel not running, showing collected data only",
  "analytics.hostsTitle": "Top Hosts (by traffic)",
  "analytics.outboundTitle": "Strategy Distribution (by outbound)",
  "analytics.ruleTypesTitle": "Rule Stats (by type)",
  "analytics.ruleHitsTitle": "Rule Hits (by traffic)",
  "analytics.emptyConnections": "No connection data",
  "analytics.emptyHits": "No hit records",
  "analytics.emptyRules": "No rules",
  "analytics.coreNotRunning": "Kernel not running",
  "analytics.hitsCount": "{count} hits",
  "analytics.other": "Other",
  "analytics.displayDomain": "Domain",
  "analytics.displayIp": "IP",
};

export default { zh, en };
