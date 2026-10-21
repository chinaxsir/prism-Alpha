import { useMemo, useRef, useState } from "react";
import { Pause, Play, Trash2, X, XCircle } from "lucide-react";

import { closeAllConnections, closeConnection, getCustomRules, saveCustomRules } from "@/api/ipc";
import { formatBytes } from "@/utils/format";
import { useTranslation } from "@/i18n";
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
    return list
      .filter((c) => !hiddenRef.current.has(c.id))
      .filter((c) => {
        if (filter === "all") return true;
        if (filter === "active") return c.active;
        return (c.network || "tcp") === filter;
      });
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
    // 纯 IP / IPv6 用 IP-CIDR 精确匹配，其余按域名后缀匹配（含子域）
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":");
    const rule = isIp
      ? `IP-CIDR,${host}${host.includes(":") ? "/128" : "/32"},${action}`
      : `DOMAIN-SUFFIX,${host},${action}`;
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
        actionLabel={expired ? t("pro.renew") : undefined}
      >
        {null}
      </ProGate>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-400">
            ↑ {formatBytes(totals.up)} / ↓ {formatBytes(totals.down)}
          </span>
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

      {/* 连接表格 */}
      <div className="bg-surface-card rounded-xl overflow-hidden overflow-x-auto">
        <table className="w-full text-sm min-w-[800px]">
          <thead>
            <tr className="text-left text-xs text-gray-500 border-b border-border">
              <th className="px-4 py-3 font-medium">{t("proxies.conn.status")}</th>
              <th className="px-4 py-3 font-medium">{t("proxies.conn.time")}</th>
              <th className="px-4 py-3 font-medium">{t("proxies.conn.protocol")}</th>
              <th className="px-4 py-3 font-medium">{t("proxies.conn.source")}</th>
              <th className="px-4 py-3 font-medium">{t("proxies.conn.target")}</th>
              <th className="px-4 py-3 font-medium">{t("proxies.conn.matchedRule")}</th>
              <th className="px-4 py-3 font-medium">{t("proxies.conn.outbound")}</th>
              <th className="px-4 py-3 font-medium text-right">
                {t("proxies.conn.traffic")}
              </th>
              <th className="px-4 py-3 font-medium text-right">
                {t("proxies.conn.action")}
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-4 py-10 text-center text-gray-500">
                  {paused ? t("proxies.conn.paused") : t("proxies.conn.empty")}
                </td>
              </tr>
            ) : (
              rows.map((r) => (
                <tr
                  key={r.id}
                  className="border-b border-border last:border-0 hover:bg-surface-hover/50"
                >
                  <td className="px-4 py-2.5">
                    <span
                      className={`inline-block w-2 h-2 rounded-full ${
                        r.active ? "bg-latency-good" : "bg-gray-600"
                      }`}
                    />
                  </td>
                  <td className="px-4 py-2.5 text-gray-400 font-mono text-xs">
                    {fmtTime(r.start)}
                  </td>
                  <td className="px-4 py-2.5 uppercase text-xs">
                    {r.network || "tcp"}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-gray-400">
                    {r.sourceIP}:{r.sourcePort}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs">
                    <button
                      onClick={() => {
                        const host = r.host || r.destinationIP;
                        if (host) setRuleHost(host);
                      }}
                      title={t("proxies.conn.quickRule")}
                      className="text-left transition-colors hover:text-accent"
                    >
                      {r.host || r.destinationIP || t("common.unknown")}
                      <span className="text-gray-500">:{r.destinationPort}</span>
                    </button>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-gray-300">
                    {r.rule
                      ? `${r.rule}${r.rulePayload ? ` · ${r.rulePayload}` : ""}`
                      : "—"}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-accent">
                    {r.chains?.[0] ?? "DIRECT"}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-gray-400 text-right font-mono">
                    {formatBytes(r.upload)} / {formatBytes(r.download)}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {r.active ? (
                      <button
                        onClick={() => handleClose(r.id)}
                        className="p-1.5 rounded-md text-gray-500 hover:text-latency-bad hover:bg-surface-hover transition-colors"
                        title={t("proxies.conn.closeThis")}
                      >
                        <X size={14} />
                      </button>
                    ) : (
                      <span className="text-gray-700 text-xs">—</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

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
