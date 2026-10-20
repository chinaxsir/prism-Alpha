import { useEffect, useState } from "react";
import { Globe2, ListFilter, PieChart } from "lucide-react";

import { getRules } from "@/api/ipc";
import { useTranslation } from "@/i18n";
import { useCoreStore } from "@/stores/core";
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
  const running = status === "running";

  // 内核聚合按 key 归类，部分 key 为后端占位（未知/其他）——按语言归一显示
  const mapKey = (k: string) =>
    k === "未知" ? t("common.unknown") : k === "其他" ? t("analytics.other") : k;

  const hostTop: [string, Agg][] = analytics.hosts as [string, Agg][];
  const outboundTop: [string, Agg][] = analytics.outbounds as [string, Agg][];
  const ruleTop: [string, Agg][] = analytics.rules as [string, Agg][];

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
          rows={hostTop.map(([k, a]) => [mapKey(k), a] as [string, Agg])}
          empty={t("analytics.emptyConnections")}
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
          rows={ruleTop.map(([k, a]) => [mapKey(k), a] as [string, Agg])}
          empty={t("analytics.emptyHits")}
        />
      </div>
    </div>
  );
}

function AggCard({
  icon,
  title,
  rows,
  empty,
}: {
  icon: React.ReactNode;
  title: string;
  rows: [string, Agg][];
  empty: string;
}) {
  const { t } = useTranslation();
  const max = rows.reduce((m, [, a]) => Math.max(m, a.down + a.up), 1);
  return (
    <div className="bg-surface-card rounded-xl p-5 shadow-md">
      <h2 className="text-base font-semibold mb-4 flex items-center gap-2">
        {icon}
        {title}
      </h2>
      {rows.length === 0 ? (
        <div className="py-6 text-center text-sm text-gray-500">{empty}</div>
      ) : (
        <div className="space-y-2.5">
          {rows.map(([key, a]) => {
            const total = a.down + a.up;
            return (
              <div key={key}>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="truncate text-gray-300" title={key}>
                    {key}
                  </span>
                  <span className="shrink-0 pl-3 text-gray-500 font-mono">
                    {t("analytics.hitsCount", { count: a.count })} · {formatBytes(total)}
                  </span>
                </div>
                <div className="h-1.5 rounded-full bg-glass overflow-hidden">
                  <div
                    className="h-full bg-accent/70 rounded-full"
                    style={{ width: `${Math.max((total / max) * 100, 2)}%` }}
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
