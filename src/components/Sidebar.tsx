import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Globe,
  Rss,
  BarChart3,
  Settings as SettingsIcon,
} from "lucide-react";
import clsx from "clsx";

import { useTranslation } from "@/i18n";

export const navItems = [
  { to: "/dashboard", icon: LayoutDashboard, labelKey: "nav.dashboard" },
  { to: "/proxies", icon: Globe, labelKey: "nav.proxies" },
  { to: "/subscription", icon: Rss, labelKey: "nav.subscription" },
  { to: "/analytics", icon: BarChart3, labelKey: "nav.analytics" },
  { to: "/settings", icon: SettingsIcon, labelKey: "nav.settings" },
];

export default function Sidebar() {
  const { t } = useTranslation();
  return (
    <aside className="hidden md:flex w-56 bg-surface-card border-r border-border flex-col p-4 gap-1">
      <div className="text-lg font-bold text-accent mb-6 px-2">Prism</div>
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
