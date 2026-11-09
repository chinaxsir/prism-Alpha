import { useSearchParams } from "react-router-dom";
import clsx from "clsx";
import { Lock } from "lucide-react";

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
  /** 是否 Pro 专属（已激活后完整解锁） */
  pro?: boolean;
}> = [
  { key: "nodes", labelKey: "proxyHub.tab.nodes" },
  { key: "connections", labelKey: "proxyHub.tab.connections", pro: true },
  { key: "rules", labelKey: "proxyHub.tab.rules", pro: true },
  { key: "goCus", labelKey: "proxyHub.tab.goCus", pro: true },
];

/** 代理中心：节点 / 连接 / 规则 / Go Cus 四合一。
 *  【APP-4 任务3】未激活时 4 栏导航常驻、Pro 项置灰带锁并 disabled
 *  静默禁用（点击无任何反馈，不弹 Toast / 激活窗）；激活后正常切换。 */
export default function ProxiesHub() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const proUnlocked = useProStore((s) => s.unlocked);

  // 【APP-13 任务3】4 栏导航常驻：未激活时 Pro 标签置灰带锁图标；
  // 同时防止路由层直达 /proxies?tab=goCus 看到空壳页。
  const raw = params.get("tab");
  const rawTab = TABS.some((it) => it.key === raw) ? (raw as TabKey) : "nodes";
  const tab: TabKey =
    !proUnlocked && TABS.find((it) => it.key === rawTab)?.pro ? "nodes" : rawTab;

  return (
    <div className="space-y-6">
      {/* 顶部页面标题：保持干净，不放激活按钮（APP-7 任务1） */}
      <h1 className="text-[22px] font-bold tracking-tight">{t("nav.proxies")}</h1>

      {/* 【APP58 任务4】4 栏分段导航：整行 flex 布局、取消 truncate，
          Go Cus 标签完整显示不省略；Pro 专属项未激活时置灰 + 锁图标 +
          disabled 静默禁用 */}
      <div className="grid w-full grid-cols-4 gap-1 rounded-[12px] border border-border bg-surface-hover p-1">
        {TABS.map((tabItem) => {
          const locked = !!tabItem.pro && !proUnlocked;
          return (
            <button
              key={tabItem.key}
              type="button"
              disabled={locked}
              onClick={() =>
                locked
                  ? undefined
                  : setParams(tabItem.key === "nodes" ? {} : { tab: tabItem.key })
              }
              className={clsx(
                "flex h-9 items-center justify-center gap-1 whitespace-nowrap rounded-[10px] px-2 py-1.5 text-[13px] font-bold transition-colors",
                locked
                  ? "text-gray-500 opacity-50 cursor-not-allowed"
                  : tab === tabItem.key
                    ? "bg-accent text-white"
                    : "text-gray-400 hover:text-gray-200"
              )}
            >
              <span>{t(tabItem.labelKey)}</span>
              {locked && <Lock size={11} className="shrink-0" />}
            </button>
          );
        })}
      </div>

      {tab === "nodes" && <Proxies />}
      {tab === "connections" && <Connections />}
      {tab === "rules" && <Rules />}
      {tab === "goCus" && <GoCus />}
    </div>
  );
}
