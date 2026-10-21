import { useSearchParams } from "react-router-dom";
import clsx from "clsx";
import { Lock, Wand2, type LucideIcon } from "lucide-react";

import Proxies from "./Proxies";
import Connections from "./Connections";
import Rules from "./Rules";
import GoCus from "./GoCus";
import { useTranslation } from "@/i18n";
import { useProStore } from "@/stores/pro";

type TabKey = "nodes" | "connections" | "rules" | "goCus";

const TABS: Array<{
  key: TabKey;
  labelKey: string;
  icon?: LucideIcon;
  /** 是否 Pro 专属（未激活/已到期时在标签旁渲染小锁） */
  pro?: boolean;
}> = [
  { key: "nodes", labelKey: "metric.nodes" },
  { key: "connections", labelKey: "metric.connections", pro: true },
  { key: "rules", labelKey: "metric.rules" },
  { key: "goCus", labelKey: "engine.goCus", icon: Wand2, pro: true },
];

/** 代理中心：节点 / 连接 / 规则 / Go Cus 四合一（原三个独立导航项合并） */
export default function ProxiesHub() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const tab: TabKey = TABS.some((it) => it.key === raw) ? (raw as TabKey) : "nodes";
  // Pro 未解锁：在「连接 / Go Cus」标签旁显示小锁（ready 前不显示，避免闪烁）
  const proUnlocked = useProStore((s) => s.unlocked);
  const proReady = useProStore((s) => s.ready);
  const showLock = proReady && !proUnlocked;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-bold">{t("nav.proxies")}</h1>
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
              {showLock && tabItem.pro && (
                <Lock size={11} className="ml-0.5 text-gray-500" />
              )}
            </button>
          ))}
        </div>
      </div>
      {tab === "nodes" && <Proxies />}
      {tab === "connections" && <Connections />}
      {tab === "rules" && <Rules />}
      {tab === "goCus" && <GoCus />}
    </div>
  );
}
