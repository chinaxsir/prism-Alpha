import { useEffect, useState } from "react";
import { Globe2, ListFilter, PieChart } from "lucide-react";

import { getRules } from "@/api/ipc";
import { useTranslation } from "@/i18n";
import { isIpLiteral, useCoreStore } from "@/stores/core";
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

/// 分析页：主机名 / 策略 / 规则聚合统计。
/// 聚合数据由后端在 kernel.rs + events.rs 中持续累积（store.analytics），
/// 切页与后台不丢；本页仅保留规则类型的本地查询。
export default function Analytics() {
  const { t } = useTranslation();
  const status = useCoreStore((s) => s.status);
  const analytics = useCoreStore((s) => s.analytics);
  const ipToDomain = useCoreStore((s) => s.ipToDomain);
  const domainToIp = useCoreStore((s) => s.domainToIp);
  const running = status === "running";
  // 【APP35 任务3】Top 主机名默认显示域名，可一键切换为 IP 聚合
  const [hostDisplayMode, setHostDisplayMode] = useState<"domain" | "ip">("domain");

  // 内核聚合按 key 归类，部分 key 为后端占位（未知/其他）——按语言归一显示
  const mapKey = (k: string) =>
    k === "未知" ? t("common.unknown") : k === "其他" ? t("analytics.other") : k;

  const outboundTop: [string, Agg][] = analytics.outbounds as [string, Agg][];
  const ruleTop: [string, Agg][] = analytics.rules as [string, Agg][];

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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t("analytics.title")}</h1>
        {!running && (
          <span className="text-xs text-gray-500">{t("analytics.coreNotRunningHint")}</span>
        )}
      </div>

      {/* 聚合统计：实时曲线在仪表盘，本页专注聚合 */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Top 主机名 */}
        <AggCard
          icon={<Globe2 size={16} className="text-accent" />}
          title={t("analytics.hostsTitle")}
          rows={hostTop.map(([k, a, sub]) => [mapKey(k), a, sub] as [string, Agg, string?])}
          empty={t("analytics.emptyConnections")}
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
          icon={<PieChart size={16} className="text-accent" />}
          title={t("analytics.outboundTitle")}
          rows={outboundTop}
          empty={t("analytics.emptyConnections")}
        />
      </div>

      {/* 规则统计 */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-surface-card rounded-xl p-5 shadow-md">
          <h2 className="text-base font-semibold mb-4 flex items-center gap-2">
            <ListFilter size={16} className="text-accent" />
            {t("analytics.ruleTypesTitle")}
          </h2>
          {ruleTypes.length === 0 ? (
            <div className="py-6 text-center text-sm text-gray-500">
              {running ? t("analytics.emptyRules") : t("analytics.coreNotRunning")}
            </div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {ruleTypes.map(([t, n]) => (
                <span
                  key={t}
                  className="px-3 py-1.5 rounded-lg bg-surface-hover text-xs text-gray-300"
                >
                  {t} <span className="text-accent font-medium">{n}</span>
                </span>
              ))}
            </div>
          )}
        </div>
        <AggCard
          icon={<ListFilter size={16} className="text-accent" />}
          title={t("analytics.ruleHitsTitle")}
          rows={ruleTop.map(([k, a]) => [mapKey(k), a] as [string, Agg, string?])}
          empty={t("analytics.emptyHits")}
        />
      </div>
    </div>
  );
}

interface HostRow {
  domain: string;
  ip: string;
  agg: Agg;
}

function AggCard({
  icon,
  title,
  rows,
  empty,
  headerExtra,
}: {
  icon: React.ReactNode;
  title: string;
  rows: [string, Agg, string?][];
  empty: string;
  headerExtra?: React.ReactNode;
}) {
  const { t } = useTranslation();
  const max = rows.reduce((m, [, a]) => Math.max(m, a.down + a.up), 1);
  return (
    <div className="card-sheen bg-surface-card rounded-xl p-5 shadow-md">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-base font-semibold flex items-center gap-2">
          {icon}
          {title}
        </h2>
        {headerExtra}
      </div>
      {rows.length === 0 ? (
        <div className="py-6 text-center text-sm text-gray-500">{empty}</div>
      ) : (
        <div className="space-y-2.5">
          {rows.map(([key, a, sub]) => {
            const total = a.down + a.up;
            const pct = Math.max((total / max) * 100, 2);
            return (
              <div key={key}>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="truncate text-gray-300" title={key}>
                    {key}
                    {sub ? (
                      <span className="ml-2 text-[10px] text-gray-500">{sub}</span>
                    ) : null}
                  </span>
                  <span className="shrink-0 pl-3 text-gray-500 font-mono tabular-nums">
                    {t("analytics.hitsCount", { count: a.count })} · {formatBytes(total)}
                  </span>
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
