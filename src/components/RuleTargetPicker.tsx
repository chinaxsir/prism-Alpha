import { useEffect, useMemo, useState } from "react";
import { Globe, Network, Search, X } from "lucide-react";

import { getRuntimeSnapshot } from "@/api/ipc";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";
import type { AggStat } from "@/stores/core";
import { isIpLiteral, useCoreStore } from "@/stores/core";
import { extractRootDomain } from "@/utils/domain";

interface Props {
  open: boolean;
  onClose: () => void;
  onConfirm: (lines: string[]) => void;
}

type Tab = "domain" | "ip";
type Action = "PROXY" | "DIRECT" | "REJECT";

interface Candidate {
  /** 去重后的规则内容（域名根域 / IP 字面量） */
  key: string;
  /** 流量（排序用） */
  bytes: number;
  /** IP 反查得到的域名提示 */
  hint?: string;
}

/// 【APP43 任务3】从「连接 / 分析」中挑选域名或 IP 批量生成自定义规则。
/// 数据源：全局 store 的分析聚合（后端按域名 / IP 独立统计）+ 实时连接；
/// 打开时主动拉一次运行时快照，保证列表最新且不阻塞主线程。
export default function RuleTargetPicker({ open, onClose, onConfirm }: Props) {
  const { t } = useTranslation();
  const connections = useCoreStore((s) => s.connections);
  const analytics = useCoreStore((s) => s.analytics);
  const ipToDomain = useCoreStore((s) => s.ipToDomain);
  const applyRuntimeSnapshot = useCoreStore((s) => s.applyRuntimeSnapshot);

  const [tab, setTab] = useState<Tab>("domain");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [action, setAction] = useState<Action>("PROXY");
  const [loading, setLoading] = useState(false);

  // 打开时刷新一次快照（未运行时静默忽略，仍用 store 内已有数据）
  useEffect(() => {
    if (!open) return;
    setSelected(new Set());
    setQuery("");
    setLoading(true);
    getRuntimeSnapshot()
      .then((snap) => applyRuntimeSnapshot(snap))
      .catch(() => undefined)
      .finally(() => setLoading(false));
  }, [open, applyRuntimeSnapshot]);

  /** 域名候选：分析聚合 + 实时连接，统一折算到根域名后按流量排序 */
  const domainCandidates = useMemo<Candidate[]>(() => {
    const map = new Map<string, Candidate>();
    const add = (raw: string, stat?: AggStat) => {
      const key = extractRootDomain(raw);
      if (!key || isIpLiteral(key) || !key.includes(".")) return;
      const bytes = stat ? stat.up + stat.down : 0;
      const prev = map.get(key);
      if (prev) prev.bytes += bytes;
      else map.set(key, { key, bytes });
    };
    analytics.domains.forEach(([d, st]) => add(d, st));
    connections.forEach((c) => {
      if (!c.host || isIpLiteral(c.host)) return;
      add(c.host, {
        count: 1,
        up: c.upload ?? 0,
        down: c.download ?? 0,
      });
    });
    return [...map.values()].sort((a, b) => b.bytes - a.bytes);
  }, [analytics.domains, connections]);

  /** IP 候选：分析聚合 + 实时连接，附带反查域名提示 */
  const ipCandidates = useMemo<Candidate[]>(() => {
    const map = new Map<string, Candidate>();
    const add = (raw: string, stat?: AggStat) => {
      const ip = (raw ?? "").replace(/^\[|\]$/g, "").trim();
      if (!isIpLiteral(ip) && !ip.includes(":")) return;
      const bytes = stat ? stat.up + stat.down : 0;
      const prev = map.get(ip);
      if (prev) prev.bytes += bytes;
      else map.set(ip, { key: ip, bytes, hint: ipToDomain[ip] });
    };
    analytics.ips.forEach(([ip, st]) => add(ip, st));
    connections.forEach((c) => {
      add(c.destinationIP, {
        count: 1,
        up: c.upload ?? 0,
        down: c.download ?? 0,
      });
    });
    return [...map.values()].sort((a, b) => b.bytes - a.bytes);
  }, [analytics.ips, connections, ipToDomain]);

  const list = tab === "domain" ? domainCandidates : ipCandidates;
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const base = q
      ? list.filter(
          (c) =>
            c.key.toLowerCase().includes(q) ||
            (c.hint ?? "").toLowerCase().includes(q),
        )
      : list;
    // 渲染上限：避免上千条时一次性挂载大量 DOM（搜索仍覆盖全量）
    return base.slice(0, 150);
  }, [list, query]);

  const toggle = (key: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const handleConfirm = () => {
    if (selected.size === 0) {
      toast.error(t("proxies.rules.err.emptyPayload"));
      return;
    }
    const lines = [...selected].map((key) =>
      tab === "domain"
        ? `DOMAIN-SUFFIX,${extractRootDomain(key)},${action}`
        : key.includes(":")
          ? `IP-CIDR6,${key}/128,${action}`
          : `IP-CIDR,${key}/32,${action}`,
    );
    onConfirm(lines);
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="flex max-h-[80vh] w-full max-w-lg flex-col rounded-xl border border-border bg-surface-card p-4 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-1 flex items-start justify-between gap-2">
          <div className="min-w-0">
            <h3 className="text-sm font-semibold">
              {t("proxies.rules.targetTitle")}
            </h3>
            <p className="mt-0.5 text-[11px] text-gray-500">
              {t("proxies.rules.targetDesc")}
            </p>
          </div>
          <button
            onClick={onClose}
            className="shrink-0 rounded p-1 text-gray-400 hover:text-gray-100"
          >
            <X size={15} />
          </button>
        </div>

        {/* 域名 / IP 切换 */}
        <div className="my-3 flex items-center gap-1 rounded-lg bg-surface-hover p-1">
          {(
            [
              ["domain", Globe, t("proxies.rules.targetTabDomain")],
              ["ip", Network, t("proxies.rules.targetTabIp")],
            ] as const
          ).map(([value, Icon, label]) => (
            <button
              key={value}
              onClick={() => {
                setTab(value);
                setSelected(new Set());
              }}
              className={`flex flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-xs transition-colors ${
                tab === value
                  ? "bg-surface-card text-gray-100 shadow-sm"
                  : "text-gray-500 hover:text-gray-300"
              }`}
            >
              <Icon size={13} />
              {label}
              <span className="ml-0.5 tabular-nums text-[11px] text-gray-500">
                {value === "domain" ? domainCandidates.length : ipCandidates.length}
              </span>
            </button>
          ))}
        </div>

        <div className="mb-2 flex items-center gap-2 rounded-lg border border-border bg-surface-hover px-3 py-1.5">
          <Search size={13} className="shrink-0 text-gray-500" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("proxies.rules.targetSearch")}
            className="min-w-0 flex-1 bg-transparent text-sm outline-none"
          />
        </div>

        <div className="min-h-0 flex-1 space-y-1 overflow-y-auto pr-1">
          {loading && list.length === 0 ? (
            <p className="py-8 text-center text-xs text-gray-500">
              {t("common.loading")}
            </p>
          ) : filtered.length === 0 ? (
            <p className="py-8 text-center text-xs text-gray-500">
              {t("proxies.rules.targetEmpty")}
            </p>
          ) : (
            filtered.map((c) => (
              <button
                key={c.key}
                onClick={() => toggle(c.key)}
                className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-xs transition-colors hover:bg-surface-hover ${
                  selected.has(c.key) ? "bg-surface-hover" : ""
                }`}
              >
                <span
                  className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border text-[10px] ${
                    selected.has(c.key)
                      ? "border-accent bg-accent text-white"
                      : "border-border text-transparent"
                  }`}
                >
                  ✓
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-gray-200">
                    {c.key}
                  </span>
                  {c.hint && (
                    <span className="block truncate text-[11px] text-gray-500">
                      {c.hint}
                    </span>
                  )}
                </span>
                {c.bytes > 0 && (
                  <span className="shrink-0 tabular-nums text-[11px] text-gray-500">
                    {formatBytes(c.bytes)}
                  </span>
                )}
              </button>
            ))
          )}
        </div>

        <div className="mt-3 border-t border-border pt-3">
          <p className="mb-2 text-[11px] text-gray-500">
            {t("proxies.rules.targetPolicy")}
          </p>
          <div className="flex flex-wrap items-center gap-2">
            {(
              [
                ["PROXY", t("proxies.rules.targetPolicyProxy")],
                ["DIRECT", t("proxies.rules.targetPolicyDirect")],
                ["REJECT", t("proxies.rules.targetPolicyBlock")],
              ] as const
            ).map(([value, label]) => (
              <button
                key={value}
                onClick={() => setAction(value)}
                className={`rounded-lg border px-3 py-1.5 text-xs transition-colors ${
                  action === value
                    ? "border-accent bg-accent/10 text-accent"
                    : "border-border text-gray-400 hover:text-gray-200"
                }`}
              >
                {label}
              </button>
            ))}
            <span className="ml-auto text-[11px] text-gray-500">
              {t("proxies.rules.targetSelected", { count: selected.size })}
            </span>
            <button
              onClick={handleConfirm}
              disabled={selected.size === 0}
              className="rounded-lg bg-accent px-4 py-1.5 text-xs text-white hover:bg-accent-hover disabled:opacity-40"
            >
              {t("proxies.rules.targetConfirm", { count: selected.size })}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/// 轻量字节格式化（与连接页保持一致口径，避免为格式化引入额外依赖）
function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${
    units[unit]
  }`;
}
