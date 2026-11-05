import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  Copy,
  Gauge,
  Pause,
  Play,
  Trash2,
  X,
  XCircle,
} from "lucide-react";

import { closeAllConnections, closeConnection, getCustomRules, saveCustomRules } from "@/api/ipc";
import { formatBytes } from "@/utils/format";
import { extractRootDomain } from "@/utils/domain";
import { useTranslation } from "@/i18n";
import { useAppVisible } from "@/hooks/useAppVisible";
import { useCoreStore, type ConnItem } from "@/stores/core";
import { useProStore } from "@/stores/pro";
import { Feature } from "@/pro/gating";
import ProGate from "@/components/ProGate";
import { toast } from "@/components/ui/Toast";

type FilterKey = "all" | "active" | "tcp" | "udp";

const FILTERS: { key: FilterKey; labelKey: string }[] = [
  { key: "all", labelKey: "common.all" },
  { key: "active", labelKey: "proxies.conn.active" },
  { key: "tcp", labelKey: "proxies.conn.tcp" },
  { key: "udp", labelKey: "proxies.conn.udp" },
];

/// 连接页：数据源来自后端运行时快照（store.connections 由 App.tsx 定时/回前台刷新），
/// 切页与后台不丢；本页仅保留筛选、暂停冻结、清空视图等纯 UI 状态。
/// 后端维护「活跃 / 近期连接池」，已关闭连接以 active=false 保留展示。
export default function Connections() {
  const { t, resolved } = useTranslation();
  const connections = useCoreStore((s) => s.connections);
  // 连接监控与快捷分流为 Pro 功能：未激活/已到期一律只展示引导卡
  const proUnlocked = useProStore((s) => s.unlocked);
  const proReady = useProStore((s) => s.ready);
  const proStatus = useProStore((s) => s.entitlement.status);

  const [filter, setFilter] = useState<FilterKey>("all");
  const [paused, setPaused] = useState(false);
  // 快捷分流：点击「目标」列弹出规则菜单（域名/IP 自动判定匹配类型）
  const [ruleHost, setRuleHost] = useState<string | null>(null);
  // 暂停时冻结的快照（纯 UI 状态，非数据源）
  const frozenRef = useRef<ConnItem[]>([]);
  // 清空视图：隐藏按下清空时的既有连接（其后新连接照常出现）
  const hiddenRef = useRef<Set<string>>(new Set());
  const [, forceTick] = useState(0);

  const rows = useMemo(() => {
    const list = paused ? frozenRef.current : connections;
    const filtered = list
      .filter((c) => !hiddenRef.current.has(c.id))
      .filter((c) => {
        if (filter === "all") return true;
        if (filter === "active") return c.active;
        return (c.network || "tcp") === filter;
      });
    // 【APP43 任务3.3】连接数上百时只挂载前 150 条：筛选/统计仍按全量计算，
    // 避免一次性渲染数千 DOM 节点导致切页卡顿与内存峰值。
    return filtered.slice(0, 150);
  }, [connections, filter, paused]);

  // 会话时长累计（上行/下行）：当前连接池内所有连接的累计值之和
  const totals = useMemo(() => {
    let up = 0;
    let down = 0;
    for (const c of connections) {
      up += c.upload;
      down += c.download;
    }
    return { up, down };
  }, [connections]);

  const fmtTime = (start?: string) => {
    if (!start) return "—";
    const d = new Date(start);
    if (Number.isNaN(d.getTime())) return "—";
    return d.toLocaleTimeString(resolved === "zh" ? "zh-CN" : "en-US", {
      hour12: false,
    });
  };

  // 【APP42 任务4.1】下行实时速度（全局 store，events.rs 每帧推送）
  const downSpeed = useCoreStore((s) => s.downSpeed);
  // 会话时长每秒跳动：连接本身不重绘，仅本页 tick 刷新；
  // 【APP49 任务6】后台时清理定时器（彻底静止待机），回前台立即补刷一次再恢复
  const appVisible = useAppVisible();
  useEffect(() => {
    if (!appVisible) return;
    forceTick((n) => n + 1);
    const timer = setInterval(() => forceTick((n) => n + 1), 1000);
    return () => clearInterval(timer);
  }, [appVisible]);

  const fmtDuration = (start?: string) => {
    if (!start) return "—";
    const ms = Date.now() - new Date(start).getTime();
    if (!Number.isFinite(ms) || ms < 0) return "—";
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return h > 0
      ? `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
      : `${m}:${String(sec).padStart(2, "0")}`;
  };

  const copyTarget = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(t("proxies.conn.copied"));
    } catch {
      toast.error(t("proxies.conn.copyFailed"));
    }
  };

  const activeCount = connections.filter((c) => c.active).length;

  const togglePause = () => {
    if (!paused) frozenRef.current = connections;
    setPaused((p) => !p);
  };

  /// 清空视图：隐藏当前所有连接（新连接照常出现）
  const clearList = () => {
    for (const c of connections) hiddenRef.current.add(c.id);
    frozenRef.current = [];
    setPaused(false);
    forceTick((n) => n + 1);
  };

  /// 关闭单条：成功后隐藏该行（内核下一帧会将其标记为已关闭）
  const handleClose = async (id: string) => {
    try {
      await closeConnection(id);
      hiddenRef.current.add(id);
      forceTick((n) => n + 1);
    } catch (e) {
      console.error("close connection failed:", e);
      toast.error(String(e));
    }
  };

  /// 关闭内核全部连接
  const handleCloseAll = async () => {
    try {
      await closeAllConnections();
      toast.success(t("proxies.conn.allClosed"));
    } catch (e) {
      console.error("close all connections failed:", e);
      toast.error(String(e));
    }
  };

  /// 快捷分流：把当前连接的目标域名/IP 写成一条自定义规则（内核运行中会自动重启生效）
  const applyQuickRule = async (action: "DIRECT" | "PROXY" | "REJECT") => {
    const host = ruleHost;
    if (!host) return;
    // 纯 IP / IPv6 用 IP-CIDR 精确匹配；域名统一折算根域（www.a.com → a.com），
    // 避免同一站点被拆成多条子域规则（与规则页「从连接/分析选择」口径一致）
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":");
    const target = isIp ? host : extractRootDomain(host);
    const rule = isIp
      ? `IP-CIDR,${target}${host.includes(":") ? "/128" : "/32"},${action}`
      : `DOMAIN-SUFFIX,${target},${action}`;
    try {
      const existing = await getCustomRules();
      if (!existing.includes(rule)) {
        await saveCustomRules([...existing, rule]);
      }
      toast.success(t("proxies.conn.ruleAdded", { rule }));
      setRuleHost(null);
    } catch (e) {
      console.error("quick rule failed:", e);
      toast.error(String(e));
    }
  };

  // 未授权 / 已到期：只渲染干净的引导卡，不渲染搜索框、统计条与实时连接流
  if (proReady && !proUnlocked) {
    const expired = proStatus === "expired";
    return (
      <ProGate
        feature={Feature.Connections}
        title={t(expired ? "pro.conn.expiredTitle" : "pro.conn.lockedTitle")}
        description={t("pro.conn.lockedDesc")}
      >
        {null}
      </ProGate>
    );
  }

  return (
    <div className="space-y-5">
      {/* 【APP42 任务4.1】顶部统计卡：上行 / 下行 / 实时下行速度 / 活跃连接 */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          icon={<ArrowUp size={15} />}
          label={t("proxies.conn.statUp")}
          value={formatBytes(totals.up)}
          tone="text-latency-warn"
        />
        <StatCard
          icon={<ArrowDown size={15} />}
          label={t("proxies.conn.statDown")}
          value={formatBytes(totals.down)}
          tone="text-latency-good"
        />
        <StatCard
          icon={<Gauge size={15} />}
          label={t("proxies.conn.statSpeed")}
          value={`${(downSpeed / 1024).toFixed(1)} KB/s`}
          tone="text-accent"
        />
        <StatCard
          icon={<Activity size={15} />}
          label={t("proxies.conn.statActive")}
          value={String(activeCount)}
          tone="text-gray-200"
        />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* 筛选器 */}
        <div className="flex gap-2">
          {FILTERS.map(({ key, labelKey }) => (
            <button
              key={key}
              onClick={() => setFilter(key)}
              className={`px-4 py-1.5 rounded-lg text-sm transition-colors ${
                filter === key
                  ? "bg-accent text-white"
                  : "bg-surface-card text-gray-400 hover:text-gray-200"
              }`}
            >
              {t(labelKey)}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={togglePause}
            className="p-2 rounded-lg bg-surface-card hover:bg-surface-hover transition-colors"
            title={paused ? t("proxies.conn.resume") : t("proxies.conn.pause")}
          >
            {paused ? <Play size={16} /> : <Pause size={16} />}
          </button>
          <button
            onClick={handleCloseAll}
            className="p-2 rounded-lg bg-surface-card hover:bg-surface-hover transition-colors"
            title={t("proxies.conn.closeAllTip")}
          >
            <XCircle size={16} />
          </button>
          <button
            onClick={clearList}
            className="p-2 rounded-lg bg-surface-card hover:bg-surface-hover transition-colors"
            title={t("proxies.conn.clearList")}
          >
            <Trash2 size={16} />
          </button>
        </div>
      </div>

      {/* 【APP42 任务4.1】卡片式连接列表 */}
      {rows.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border bg-surface-card/60 py-12 text-center text-sm text-gray-500">
          {paused ? t("proxies.conn.paused") : t("proxies.conn.empty")}
        </div>
      ) : (
        <div className="space-y-2">
          {rows.map((r) => {
            const host = r.host || r.destinationIP;
            const target = host
              ? `${host}${r.destinationPort ? `:${r.destinationPort}` : ""}`
              : "";
            const chain = (r.chains ?? []).slice().reverse().join(" → ") || "DIRECT";
            return (
              <div
                key={r.id}
                className="group rounded-xl border border-border bg-surface-card p-3 transition-colors hover:border-accent/40"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`inline-block h-2 w-2 shrink-0 rounded-full ${
                          r.active ? "bg-latency-good" : "bg-gray-600"
                        }`}
                      />
                      <span
                        className="truncate text-sm font-medium"
                        title={host}
                      >
                        {host || t("common.unknown")}
                      </span>
                      {target && (
                        <button
                          onClick={() => copyTarget(target)}
                          className="shrink-0 rounded p-0.5 text-gray-600 opacity-0 transition-opacity hover:text-accent group-hover:opacity-100"
                          title={t("proxies.conn.copy")}
                        >
                          <Copy size={11} />
                        </button>
                      )}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[11px] text-gray-500">
                      <span>
                        {r.destinationIP || "—"}:{r.destinationPort || "—"}
                      </span>
                      <span className="text-gray-700">·</span>
                      <span>
                        {r.sourceIP}:{r.sourcePort}
                      </span>
                      <span className="text-gray-700">·</span>
                      <span>{fmtTime(r.start)}</span>
                      <span className="text-gray-700">·</span>
                      <span>{fmtDuration(r.start)}</span>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <div className="text-right font-mono text-[11px] tabular-nums">
                      <div className="text-latency-warn">
                        ↑ {formatBytes(r.upload)}
                      </div>
                      <div className="text-latency-good">
                        ↓ {formatBytes(r.download)}
                      </div>
                    </div>
                    {r.active && (
                      <button
                        onClick={() => handleClose(r.id)}
                        className="rounded-md p-1.5 text-gray-500 transition-colors hover:bg-surface-hover hover:text-latency-bad"
                        title={t("proxies.conn.closeThis")}
                      >
                        <X size={14} />
                      </button>
                    )}
                  </div>
                </div>
                <div className="mt-2.5 flex flex-wrap items-center gap-2 border-t border-border/60 pt-2">
                  <span
                    className={`rounded px-1.5 py-0.5 text-[11px] font-medium uppercase ${
                      (r.network || "tcp") === "udp"
                        ? "bg-purple-500/15 text-purple-300"
                        : "bg-sky-500/15 text-sky-300"
                    }`}
                  >
                    {r.network || "tcp"}
                  </span>
                  <button
                    onClick={() => {
                      const h = r.host || r.destinationIP;
                      if (h) setRuleHost(h);
                    }}
                    title={t("proxies.conn.quickRule")}
                    className="max-w-[45%] truncate rounded bg-surface-hover px-1.5 py-0.5 text-[11px] text-gray-400 transition-colors hover:text-accent"
                  >
                    {r.rule
                      ? `${r.rule}${r.rulePayload ? ` · ${r.rulePayload}` : ""}`
                      : "—"}
                  </button>
                  <span className="truncate text-[11px] text-accent">
                    {chain}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* 快捷分流弹层：为选中连接的目标添加自定义规则 */}
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
              {t("proxies.conn.quickRuleTitle", { host: ruleHost })}
            </div>
            <div className="space-y-2">
              {(
                [
                  ["DIRECT", "proxies.conn.quickRuleDirect"],
                  ["PROXY", "proxies.conn.quickRuleProxy"],
                  ["REJECT", "proxies.conn.quickRuleReject"],
                ] as const
              ).map(([action, key]) => (
                <button
                  key={action}
                  onClick={() => void applyQuickRule(action)}
                  className="w-full rounded-lg bg-surface-hover px-3 py-2 text-left text-sm text-gray-200 transition-colors hover:bg-accent/20 hover:text-accent"
                >
                  {t(key)}
                </button>
              ))}
            </div>
            <button
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

/// 【APP42 任务4.1】顶部统计卡（大号数字 + 说明）
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
    <div className="card-sheen rounded-xl border border-border bg-surface-card p-3.5">
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
