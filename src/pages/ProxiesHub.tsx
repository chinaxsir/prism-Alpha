import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import clsx from "clsx";
import { Sparkles, Wand2, type LucideIcon } from "lucide-react";

import Proxies from "./Proxies";
import Connections from "./Connections";
import Rules from "./Rules";
import GoCus from "./GoCus";
import { ActivateProModal } from "@/components/ProGate";
import { useTranslation } from "@/i18n";
import { useProStore } from "@/stores/pro";

type TabKey = "nodes" | "connections" | "rules" | "goCus";

const TABS: Array<{
  key: TabKey;
  labelKey: string;
  icon?: LucideIcon;
  /** 是否 Pro 专属（已激活后完整解锁） */
  pro?: boolean;
}> = [
  { key: "nodes", labelKey: "metric.nodes" },
  { key: "connections", labelKey: "metric.connections", pro: true },
  { key: "rules", labelKey: "metric.rules", pro: true },
  { key: "goCus", labelKey: "engine.goCus", icon: Wand2, pro: true },
];

/** 代理中心：节点 / 连接 / 规则 / Go Cus 四合一。
 *  APP-5 任务2：未激活授权时不再渲染带锁的 4 栏标签导航，
 *  改为一张与仪表盘完全统一的 Pro 套件卡片 + 强制 tab=nodes；
 *  激活后完整展现 4 栏（Lock 图标一并移除）。 */
export default function ProxiesHub() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const [showActivate, setShowActivate] = useState(false);
  const proUnlocked = useProStore((s) => s.unlocked);
  const proReady = useProStore((s) => s.ready);

  // APP-5 任务2：未激活时强制视图锁定到「节点」列表，
  // 避免用户在路由层直接打到 /proxies?tab=goCus 看到空壳页
  const raw = params.get("tab");
  const tab: TabKey =
    !proReady || !proUnlocked
      ? "nodes"
      : TABS.some((it) => it.key === raw)
        ? (raw as TabKey)
        : "nodes";

  const openProModal = () => setShowActivate(true);

  return (
    <div className="space-y-6">
      {/* 顶部页面标题：保持干净，不放激活按钮（APP-7 任务1） */}
      <h1 className="text-2xl font-bold">{t("nav.proxies")}</h1>

      {!proReady || !proUnlocked ? (
        /* 未激活：Pro 代理套件卡片，激活按钮位于卡片内部右侧垂直居中，
           与仪表盘 Pro 智联引擎卡片样式 100% 对齐 */
        <div className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface-card px-3.5 py-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-nowrap items-center gap-1.5 overflow-hidden">
              <Sparkles size={14} className="shrink-0 text-amber-400" />
              <span className="whitespace-nowrap text-sm font-semibold text-text">
                {t("pro.proxySuite")}
              </span>
              <span className="whitespace-nowrap rounded bg-surface-hover px-1.5 py-0.5 text-[10px] text-text-muted">
                {t("metric.connections")}
              </span>
              <span className="whitespace-nowrap rounded bg-surface-hover px-1.5 py-0.5 text-[10px] text-text-muted">
                {t("metric.rules")}
              </span>
              <span className="whitespace-nowrap rounded bg-surface-hover px-1.5 py-0.5 text-[10px] text-text-muted">
                Go Cus
              </span>
            </div>
            <p className="mt-1 truncate text-[11px] text-text-muted">
              {t("pro.proxySuiteDesc")}
            </p>
          </div>
          <button
            type="button"
            onClick={openProModal}
            className="shrink-0 rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent/90"
          >
            {t("pro.activatePro")}
          </button>
        </div>
      ) : (
        /* 已激活：4 栏分段导航 */
        <div className="flex rounded-lg border border-border bg-surface-hover p-1">
          {TABS.map((tabItem) => (
            <button
              key={tabItem.key}
              onClick={() =>
                setParams(tabItem.key === "nodes" ? {} : { tab: tabItem.key })
              }
              className={clsx(
                "flex items-center gap-1.5 rounded-md px-4 py-1.5 text-sm transition-colors",
                tab === tabItem.key
                  ? "bg-accent text-white"
                  : "text-gray-400 hover:text-gray-200"
              )}
            >
              {tabItem.icon && <tabItem.icon size={14} />}
              {t(tabItem.labelKey)}
            </button>
          ))}
        </div>
      )}

      {tab === "nodes" && <Proxies />}
      {tab === "connections" && <Connections />}
      {tab === "rules" && <Rules />}
      {tab === "goCus" && <GoCus />}

      <ActivateProModal
        open={showActivate}
        onClose={() => setShowActivate(false)}
      />
    </div>
  );
}
