import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import clsx from "clsx";
import { Lock, Wand2, type LucideIcon } from "lucide-react";

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
 *  【APP-13 任务3】未激活时 4 栏导航常驻、Pro 项置灰带锁，点击弹激活窗；
 *  激活后完整展现并正常切换。 */
export default function ProxiesHub() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const [showActivate, setShowActivate] = useState(false);
  const proUnlocked = useProStore((s) => s.unlocked);

  // 【APP-13 任务3】4 栏导航常驻：未激活时 Pro 标签置灰带锁图标，
  // 点击只弹激活弹窗、不切换视图；同时防止路由层直达
  // /proxies?tab=goCus 看到空壳页。
  const raw = params.get("tab");
  const rawTab = TABS.some((it) => it.key === raw) ? (raw as TabKey) : "nodes";
  const tab: TabKey =
    !proUnlocked && TABS.find((it) => it.key === rawTab)?.pro ? "nodes" : rawTab;

  const openProModal = () => setShowActivate(true);

  return (
    <div className="space-y-6">
      {/* 顶部页面标题：保持干净，不放激活按钮（APP-7 任务1） */}
      <h1 className="text-2xl font-bold">{t("nav.proxies")}</h1>

      {/* 4 栏分段导航：Pro 专属项在未激活时置灰 + 锁图标 */}
      <div className="flex rounded-lg border border-border bg-surface-hover p-1">
        {TABS.map((tabItem) => {
          const locked = !!tabItem.pro && !proUnlocked;
          return (
            <button
              key={tabItem.key}
              onClick={() =>
                locked
                  ? openProModal()
                  : setParams(tabItem.key === "nodes" ? {} : { tab: tabItem.key })
              }
              className={clsx(
                "flex items-center gap-1.5 rounded-md px-4 py-1.5 text-sm transition-colors",
                locked
                  ? "text-gray-500 opacity-60"
                  : tab === tabItem.key
                    ? "bg-accent text-white"
                    : "text-gray-400 hover:text-gray-200"
              )}
            >
              {tabItem.icon && <tabItem.icon size={14} />}
              {t(tabItem.labelKey)}
              {locked && <Lock size={11} className="shrink-0" />}
            </button>
          );
        })}
      </div>

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
