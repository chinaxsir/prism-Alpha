import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowDownUp,
  Globe2,
  ListFilter,
  PieChart,
  Plus,
  Trash2,
} from "lucide-react";

import {
  getCustomRules,
  getRules,
  resetAnalyticsStats,
  saveCustomRules,
} from "@/api/ipc";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";
import { isIpLiteral, useCoreStore } from "@/stores/core";
import { extractRootDomain, isIpHost } from "@/utils/domain";
import { formatBytes } from "@/utils/format";

interface Agg {
  count: number;
  down: number;
  up: number;
}

interface RuleItem {
  type: string;
  payload: string;
  proxy: string;
}

type RuleAction = "DIRECT" | "PROXY" | "REJECT";

/// 分析页：主机名 / 策略 / 规则聚合统计。
/// 聚合数据由后端在 kernel.rs + events.rs 中持续累积（store.analytics），
/// 切页与后台不丢；本页仅保留规则类型的本地查询。
export default function Analytics() {
  const { t } = useTranslation();
  const status = useCoreStore((s) => s.status);
  const analytics = useCoreStore((s) => s.analytics);
  const ipToDomain = useCoreStore((s) => s.ipToDomain);
  const domainToIp = useCoreStore((s) => s.domainToIp);
  const setAnalytics = useCoreStore((s) => s.setAnalytics);
  const running = status === "running";
  // 【APP35 任务3】Top 主机名默认显示域名，可一键切换为 IP 聚合
  const [hostDisplayMode, setHostDisplayMode] = useState<"domain" | "ip">("domain");
  // 【APP49 任务4】Top 主机搜索（大小写不敏感）与「+规则」弹层
  const [hostQuery, setHostQuery] = useState("");
  const [ruleHost, setRuleHost] = useState<string | null>(null);

  // 内核聚合按 key 归类，部分 key 为后端占位（未知/其他）——按语言归一显示
  const mapKey = (k: string) =>
    k === "未知" ? t("common.unknown") : k === "其他" ? t("analytics.other") : k;

  const outboundTop: [string, Agg][] = analytics.outbounds as [string, Agg][];
  const ruleTop: [string, Agg][] = analytics.rules as [string, Agg][];

  // 【APP49 任务4】顶部指标：总流量 / 连接数 / 请求总数（全部由聚合求和）
  const totals = useMemo(() => {
    let up = 0;
    let down = 0;
    let conn = 0;
    for (const [, a] of analytics.hosts) {
      up += a.up;
      down += a.down;
      conn += a.count;
    }
    let requests = 0;
    for (const [, a] of analytics.domains) requests += a.count;
    return { bytes: up + down, conn, requests };
  }, [analytics.hosts, analytics.domains]);

  // 【APP49 任务4】TCP / UDP 计数（后端按 metadata.network 聚合）
  const protocolCounts = useMemo(() => {
    let tcp = 0;
    let udp = 0;
    for (const [key, a] of analytics.protocols ?? []) {
      if (key.toUpperCase() === "TCP") tcp += a.count;
      else if (key.toUpperCase() === "UDP") udp += a.count;
    }
    return { tcp, udp };
  }, [analytics.protocols]);

  // 【APP49 任务4】分流占比：outbound key 归并为 Proxy / Direct / Go Lan / 其他
  const share = useMemo(() => {
    const groups = { proxy: 0, direct: 0, goLan: 0, other: 0 };
    for (const [key, agg] of analytics.outbounds) {
      const total = agg.down + agg.up;
      const lower = key.toLowerCase();
      if (lower.startsWith("go-lan")) groups.goLan += total;
      else if (lower.includes("direct")) groups.direct += total;
      else if (lower.includes("proxy") || lower.includes("global") || key.includes("节点选择"))
        groups.proxy += total;
      else groups.other += total;
    }
    const total = groups.proxy + groups.direct + groups.goLan + groups.other;
    return [
      { key: "analytics.shareProxy", value: groups.proxy, color: "bg-accent" },
      { key: "analytics.shareDirect", value: groups.direct, color: "bg-surge-green" },
      { key: "analytics.shareGoLan", value: groups.goLan, color: "bg-surge-orange" },
      { key: "analytics.shareOther", value: groups.other, color: "bg-gray-500" },
    ].map((s) => ({ ...s, pct: total > 0 ? (s.value / total) * 100 : 0 }));
  }, [analytics.outbounds]);

  // 【APP39 任务3】后端已分别维护「域名」与「IP」两套独立聚合：
  // - 域名视图：analytics.domains（只含有效域名，副标题显示关联 IP）
  // - IP 视图：analytics.ips（只含纯 IP，绝不混入域名）
  // 这样点击切换按钮时列表内容会在两种视图间发生显著变化，
  // 不再出现「切了没反应」（旧版 host 字段同时存 IP 导致两视图相同）。
  const mapLegacyRows = (): [string, Agg, string?][] => {
    const hostRows = analytics.hosts.map(([key, agg]) => {
      const keyIsIp = isIpLiteral(key);
      if (keyIsIp) {
        return { domain: ipToDomain[key] ?? key, ip: key, agg } as HostRow;
      }
      return { domain: key, ip: domainToIp[key] ?? "", agg } as HostRow;
    });
    const groupedHosts = new Map<string, { key: string; sub?: string; agg: Agg }>();
    for (const row of hostRows) {
      const groupKey = hostDisplayMode === "ip" ? row.ip || row.domain : row.domain;
      const sub =
        hostDisplayMode === "domain"
          ? row.ip && row.ip !== row.domain
            ? row.ip
            : undefined
          : row.domain !== groupKey
            ? row.domain
            : undefined;
      const prev = groupedHosts.get(groupKey);
      if (prev) {
        prev.agg = {
          count: prev.agg.count + row.agg.count,
          up: prev.agg.up + row.agg.up,
          down: prev.agg.down + row.agg.down,
        };
      } else {
        groupedHosts.set(groupKey, { key: groupKey, sub, agg: row.agg });
      }
    }
    return [...groupedHosts.values()]
      .sort((a, b) => b.agg.down + b.agg.up - (a.agg.down + a.agg.up))
      .slice(0, 12)
      .map(({ key, sub, agg }) => [key, agg, sub] as [string, Agg, string?]);
  };

  const hostTop: [string, Agg, string?][] = (() => {
    const rows = hostDisplayMode === "ip" ? analytics.ips : analytics.domains;
    if (!rows || rows.length === 0) return mapLegacyRows();
    return rows
      .slice()
      .sort((a, b) => b[1].down + b[1].up - (a[1].down + a[1].up))
      .slice(0, 12)
      .map(([key, agg]) => {
        const sub =
          hostDisplayMode === "ip"
            ? ipToDomain[key] || undefined
            : domainToIp[key] || undefined;
        return [key, agg, sub] as [string, Agg, string?];
      });
  })();

  // 【APP49 任务4】搜索过滤（大小写不敏感，同时匹配主标题与副标题）
  const filteredHostTop = useMemo(() => {
    const q = hostQuery.trim().toLowerCase();
    if (!q) return hostTop;
    return hostTop.filter(
      ([key, , sub]) =>
        key.toLowerCase().includes(q) || (sub ?? "").toLowerCase().includes(q),
    );
  }, [hostTop, hostQuery]);

  // 规则统计：内核规则全集按类型计数（非实时统计，独立查询）
  const [ruleTypes, setRuleTypes] = useState<[string, number][]>([]);
  useEffect(() => {
    if (!running) {
      setRuleTypes([]);
      return;
    }
    getRules()
      .then((data) => {
        const rules = (data as { rules?: RuleItem[] }).rules ?? [];
        const byType = new Map<string, number>();
        for (const r of rules) byType.set(r.type, (byType.get(r.type) ?? 0) + 1);
        setRuleTypes([...byType.entries()].sort((a, b) => b[1] - a[1]));
      })
      .catch(() => setRuleTypes([]));
  }, [running]);

  // 【APP49 任务4】清空统计：后端清空聚合，前端立即置空等下一帧快照续接
  const handleReset = async () => {
    try {
      await resetAnalyticsStats();
      setAnalytics({ hosts: [], domains: [], ips: [], outbounds: [], rules: [], protocols: [] });
      toast.success(t("analytics.resetDone"));
    } catch (e) {
      console.error("reset analytics failed:", e);
      toast.error(String(e));
    }
  };

  // 【APP49 任务4】快捷规则：域名折算根域用 DOMAIN-SUFFIX，IP 用 IP-CIDR 精确匹配
  const applyQuickRule = async (action: RuleAction) => {
    const host = ruleHost;
    if (!host) return;
    const isIp = isIpHost(host);
    const target = isIp ? host : extractRootDomain(host);
    const rule = isIp
      ? `IP-CIDR,${target}${host.includes(":") ? "/128" : "/32"},${action}`
      : `DOMAIN-SUFFIX,${target},${action}`;
    try {
      const existing = await getCustomRules();
      if (!existing.includes(rule)) await saveCustomRules([...existing, rule]);
      toast.success(t("analytics.ruleAdded", { rule }));
      setRuleHost(null);
    } catch (e) {
      console.error("quick rule failed:", e);
      toast.error(String(e));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-3">
        <h1 className="text-[22px] font-bold tracking-tight">{t("analytics.title")}</h1>
        <div className="flex items-center gap-3">
          {!running && (
            <span className="text-xs text-gray-500">{t("analytics.coreNotRunningHint")}</span>
          )}
          <button
            type="button"
            onClick={() => void handleReset()}
            title={t("analytics.resetStats")}
            className="flex items-center gap-1.5 rounded-lg bg-surface-card px-3 py-1.5 text-xs text-text-muted transition-colors hover:bg-surface-hover hover:text-text"
          >
            <Trash2 size={13} />
            {t("analytics.resetStats")}
          </button>
        </div>
      </div>

      {/* 【APP49 任务4】顶部指标卡 */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          icon={<ArrowDownUp size={15} />}
          label={t("analytics.totalTraffic")}
          value={formatBytes(totals.bytes)}
          tone="text-accent"
        />
        <StatCard
          icon={<Activity size={15} />}
          label={t("analytics.connections")}
          value={String(totals.conn)}
          tone="text-gray-200"
        />
        <StatCard
          icon={<Globe2 size={15} />}
          label={t("analytics.requests")}
          value={String(totals.requests)}
          tone="text-surge-blue"
        />
        <StatCard
          icon={<ArrowDownUp size={15} />}
          label={t("analytics.protocols")}
          value={`TCP ${protocolCounts.tcp} · UDP ${protocolCounts.udp}`}
          tone="text-surge-teal"
        />
      </div>

      {/* 【APP49 任务4】分流占比堆叠条 */}
      <div className="bg-surface-card rounded-xl p-5 shadow-md">
        <h2 className="text-[17px] font-bold tracking-tight mb-4 flex items-center gap-2">
          <PieChart size={17} className="text-surge-green" />
          {t("analytics.shareTitle")}
        </h2>
        {share.every((s) => s.value === 0) ? (
          <div className="py-4 text-center text-sm text-gray-500">{t("analytics.shareEmpty")}</div>
        ) : (
          <>
            <div className="flex h-8 w-full overflow-hidden rounded-lg bg-glass">
              {share.map((s) =>
                s.pct > 0 ? (
                  <div
                    key={s.key}
                    className={`flex items-center justify-center overflow-hidden whitespace-nowrap text-[11px] font-medium text-white transition-[width] duration-500 ease-out ${s.color}`}
                    style={{ width: `${s.pct}%` }}
                    title={`${t(s.key)} ${s.pct.toFixed(1)}%`}
                  >
                    {s.pct >= 12 ? `${t(s.key)} ${s.pct.toFixed(0)}%` : null}
                  </div>
                ) : null,
              )}
            </div>
            <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[11px] text-gray-400">
              {share.map((s) => (
                <div key={s.key} className="flex items-center gap-1.5">
                  <span className={`inline-block h-2 w-2 rounded-full ${s.color}`} />
                  {t(s.key)} {s.pct.toFixed(1)}% · {formatBytes(s.value)}
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* 聚合统计：实时曲线在仪表盘，本页专注聚合 */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Top 主机名 */}
        <AggCard
          icon={<Globe2 size={17} className="text-surge-orange" />}
          title={t("analytics.hostsTitle")}
          rows={filteredHostTop}
          empty={t("analytics.emptyConnections")}
          mapLabel={mapKey}
          toolbar={
            <input
              value={hostQuery}
              onChange={(e) => setHostQuery(e.target.value)}
              placeholder={t("analytics.searchPlaceholder")}
              className="w-full rounded-lg bg-background border border-border px-2.5 py-1.5 text-xs text-text placeholder:text-text-muted focus:border-accent focus:outline-none"
            />
          }
          onAddRule={(k) => setRuleHost(k)}
          headerExtra={
            <div className="inline-flex rounded-lg bg-background p-0.5 border border-border text-[11px]">
              <button
                type="button"
                onClick={() => setHostDisplayMode("domain")}
                className={`px-2 py-0.5 rounded-md font-medium transition-colors ${
                  hostDisplayMode === "domain"
                    ? "bg-accent text-white"
                    : "text-text-muted hover:text-text"
                }`}
              >
                {t("analytics.displayDomain")}
              </button>
              <button
                type="button"
                onClick={() => setHostDisplayMode("ip")}
                className={`px-2 py-0.5 rounded-md font-medium transition-colors ${
                  hostDisplayMode === "ip"
                    ? "bg-accent text-white"
                    : "text-text-muted hover:text-text"
                }`}
              >
                {t("analytics.displayIp")}
              </button>
            </div>
          }
        />
        {/* 策略分布 */}
        <AggCard
          icon={<PieChart size={17} className="text-surge-green" />}
          title={t("analytics.outboundTitle")}
          rows={outboundTop}
          empty={t("analytics.emptyConnections")}
        />
      </div>

      {/* 规则统计 */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-surface-card rounded-xl p-5 shadow-md">
          <h2 className="text-[17px] font-bold tracking-tight mb-4 flex items-center gap-2">
            <ListFilter size={17} className="text-surge-blue" />
            {t("analytics.ruleTypesTitle")}
          </h2>
          {ruleTypes.length === 0 ? (
            <div className="py-6 text-center text-sm text-gray-500">
              {running ? t("analytics.emptyRules") : t("analytics.coreNotRunning")}
            </div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {ruleTypes.map(([type, n]) => (
                <span
                  key={type}
                  className="px-3 py-1.5 rounded-lg bg-surface-hover text-xs text-gray-300"
                >
                  {type} <span className="text-accent font-medium">{n}</span>
                </span>
              ))}
            </div>
          )}
        </div>
        <AggCard
          icon={<ListFilter size={17} className="text-surge-purple" />}
          title={t("analytics.ruleHitsTitle")}
          rows={ruleTop}
          empty={t("analytics.emptyHits")}
          mapLabel={mapKey}
        />
      </div>

      {/* 【APP49 任务4】快捷规则弹层：直连 / 代理 / 拦截（默认高亮直连） */}
      {ruleHost && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          onClick={() => setRuleHost(null)}
        >
          <div
            className="w-full max-w-xs rounded-xl bg-surface-card p-4 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-3 text-sm font-medium">
              {t("analytics.addRuleTitle", { host: ruleHost })}
            </div>
            <div className="space-y-2">
              {(
                [
                  ["DIRECT", "analytics.ruleDirect"],
                  ["PROXY", "analytics.ruleProxy"],
                  ["REJECT", "analytics.ruleReject"],
                ] as const
              ).map(([action, key], i) => (
                <button
                  key={action}
                  type="button"
                  onClick={() => void applyQuickRule(action)}
                  className={`w-full rounded-lg px-3 py-2 text-left text-sm transition-colors ${
                    i === 0
                      ? "bg-accent/15 text-accent hover:bg-accent/25"
                      : "bg-surface-hover text-gray-200 hover:bg-accent/20 hover:text-accent"
                  }`}
                >
                  {t(key)}
                </button>
              ))}
            </div>
            <button
              type="button"
              onClick={() => setRuleHost(null)}
              className="mt-3 w-full rounded-lg bg-surface-card py-1.5 text-xs text-gray-400 hover:text-gray-200"
            >
              {t("common.cancel")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

interface HostRow {
  domain: string;
  ip: string;
  agg: Agg;
}

/// 【APP42 任务4.1】顶部统计卡（大号数字 + 说明），样式对齐连接页
function StatCard({
  icon,
  label,
  value,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone: string;
}) {
  return (
    <div className="card-sheen bg-surface-card rounded-xl p-3.5 shadow-md">
      <div className="flex items-center gap-1.5 text-[11px] text-gray-500">
        {icon}
        {label}
      </div>
      <div className={`mt-1.5 font-mono text-lg font-semibold tabular-nums ${tone}`}>
        {value}
      </div>
    </div>
  );
}

function AggCard({
  icon,
  title,
  rows,
  empty,
  headerExtra,
  toolbar,
  mapLabel,
  onAddRule,
}: {
  icon: React.ReactNode;
  title: string;
  rows: [string, Agg, string?][];
  empty: string;
  headerExtra?: React.ReactNode;
  toolbar?: React.ReactNode;
  mapLabel?: (key: string) => string;
  onAddRule?: (host: string) => void;
}) {
  const { t } = useTranslation();
  const max = rows.reduce((m, [, a]) => Math.max(m, a.down + a.up), 1);
  return (
    <div className="card-sheen bg-surface-card rounded-xl p-5 shadow-md">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-[17px] font-bold tracking-tight flex items-center gap-2">
          {icon}
          {title}
        </h2>
        {headerExtra}
      </div>
      {toolbar ? <div className="mb-3">{toolbar}</div> : null}
      {rows.length === 0 ? (
        <div className="py-6 text-center text-sm text-gray-500">{empty}</div>
      ) : (
        <div className="space-y-2.5">
          {rows.map(([key, a, sub]) => {
            const total = a.down + a.up;
            const pct = Math.max((total / max) * 100, 2);
            const label = mapLabel ? mapLabel(key) : key;
            return (
              <div key={key}>
                <div className="mb-1 flex items-center justify-between gap-2 text-xs">
                  <span className="min-w-0 truncate text-gray-300" title={label}>
                    {label}
                    {sub ? (
                      <span className="ml-2 text-[11px] text-gray-500">{sub}</span>
                    ) : null}
                  </span>
                  <div className="flex shrink-0 items-center gap-2">
                    <span className="pl-1 text-gray-500 font-mono tabular-nums">
                      {t("analytics.hitsCount", { count: a.count })} · {formatBytes(total)}
                    </span>
                    {onAddRule ? (
                      <button
                        type="button"
                        onClick={() => onAddRule(key)}
                        title={t("analytics.addRule")}
                        className="flex items-center gap-0.5 rounded-md border border-border px-1.5 py-0.5 text-[10px] text-text-muted transition-colors hover:border-accent hover:text-accent"
                      >
                        <Plus size={10} />
                        {t("analytics.addRule")}
                      </button>
                    ) : null}
                  </div>
                </div>
                <div className="relative h-1.5 rounded-full bg-glass overflow-hidden">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-accent/55 via-accent/80 to-accent transition-[width] duration-500 ease-out"
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
