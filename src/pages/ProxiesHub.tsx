import { useSearchParams } from "react-router-dom";
import clsx from "clsx";
import { Wand2, type LucideIcon } from "lucide-react";

import Proxies from "./Proxies";
import Connections from "./Connections";
import Rules from "./Rules";
import GoCus from "./GoCus";

type TabKey = "nodes" | "connections" | "rules" | "goCus";

const TABS: Array<{ key: TabKey; label: string; icon?: LucideIcon }> = [
  { key: "nodes", label: "节点" },
  { key: "connections", label: "连接" },
  { key: "rules", label: "规则" },
  { key: "goCus", label: "Go Cus", icon: Wand2 },
];

/** 代理中心：节点 / 连接 / 规则 / Go Cus 四合一（原三个独立导航项合并） */
export default function ProxiesHub() {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const tab: TabKey = TABS.some((t) => t.key === raw) ? (raw as TabKey) : "nodes";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-bold">代理</h1>
        <div className="flex rounded-lg border border-white/5 bg-surface-hover p-1">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setParams(t.key === "nodes" ? {} : { tab: t.key })}
              className={clsx(
                "flex items-center gap-1.5 rounded-md px-4 py-1.5 text-sm transition-colors",
                tab === t.key
                  ? "bg-accent text-white"
                  : "text-gray-400 hover:text-gray-200"
              )}
            >
              {t.icon && <t.icon size={14} />}
              {t.label}
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
