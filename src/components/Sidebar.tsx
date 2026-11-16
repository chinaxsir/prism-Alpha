import { NavLink } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import {
  LayoutDashboard,
  Globe,
  Rss,
  BarChart3,
  Settings as SettingsIcon,
} from "lucide-react";
import clsx from "clsx";

import { useTranslation } from "@/i18n";
import { useCoreStore } from "@/stores/core";

export const navItems = [
  { to: "/dashboard", icon: LayoutDashboard, labelKey: "nav.dashboard" },
  { to: "/proxies", icon: Globe, labelKey: "nav.proxies" },
  { to: "/subscription", icon: Rss, labelKey: "nav.subscription" },
  { to: "/analytics", icon: BarChart3, labelKey: "nav.analytics" },
  { to: "/settings", icon: SettingsIcon, labelKey: "nav.settings" },
];

function isTauri() {
  return typeof window !== "undefined" && Boolean((window as any).__TAURI__);
}

export default function Sidebar() {
  const { t } = useTranslation();
  const status = useCoreStore((s) => s.status);
  const running = status === "running";

  const ctrl = (action: string) => {
    if (!isTauri()) return;
    void invoke("app_window_control", { action });
  };

  return (
    <aside className="hidden md:flex w-56 bg-surface-card border-r border-border flex-col p-4 gap-1">
      {/* macOS 交通灯窗口控制组（红黄绿）+ 拖拽区 */}
      {isTauri() && (
        <div
          data-tauri-drag-region
          className="flex items-center gap-2 px-1 pt-1 pb-3 select-none"
        >
          <button
            onClick={() => ctrl("close")}
            title={t("titlebar.closeToTray")}
            className="w-3 h-3 rounded-full bg-[#FF5F56] ring-1 ring-black/10 hover:brightness-110 transition-all flex items-center justify-center group"
          >
            <span className="opacity-0 group-hover:opacity-100 text-[8px] text-black/70 leading-none">
              ×
            </span>
          </button>
          <button
            onClick={() => ctrl("minimize")}
            title={t("titlebar.minimize")}
            className="w-3 h-3 rounded-full bg-[#FFBD2E] ring-1 ring-black/10 hover:brightness-110 transition-all flex items-center justify-center group"
          >
            <span className="opacity-0 group-hover:opacity-100 text-[8px] text-black/70 leading-none">
              −
            </span>
          </button>
          <button
            onClick={() => ctrl("toggle_maximize")}
            title={t("titlebar.zoom")}
            className="w-3 h-3 rounded-full bg-[#28C840] ring-1 ring-black/10 hover:brightness-110 transition-all flex items-center justify-center group"
          >
            <span className="opacity-0 group-hover:opacity-100 text-[8px] text-black/70 leading-none">
              +
            </span>
          </button>
        </div>
      )}

      {/* App 图标 + 内核运行状态呼吸点（替换原 Prism 文字） */}
      <div
        data-tauri-drag-region
        className={clsx(
          "flex items-center gap-3 px-1 pb-4 select-none",
          !isTauri() && "pt-1"
        )}
      >
        <div className="relative group">
          <img
            src="/icon.png"
            alt="Prism"
            className="w-11 h-11 rounded-[12px] object-cover shadow-md ring-1 ring-black/10 dark:ring-white/15 transition-transform duration-200 group-hover:scale-105"
          />
          <span
            className={clsx(
              "absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full ring-2 ring-surface-card",
              running ? "bg-emerald-500 animate-pulse" : "bg-gray-400"
            )}
          />
        </div>
      </div>

      {navItems.map(({ to, icon: Icon, labelKey }) => (
        <NavLink
          key={to}
          to={to}
          className={({ isActive }) =>
            clsx(
              "flex items-center gap-3 px-3 py-2 rounded-lg transition-colors",
              isActive
                ? "bg-accent/20 text-accent"
                : "text-gray-400 hover:bg-surface-hover hover:text-gray-200"
            )
          }
        >
          <Icon size={18} />
          <span>{t(labelKey)}</span>
        </NavLink>
      ))}
    </aside>
  );
}
