import { NavLink } from "react-router-dom";
import clsx from "clsx";

import { navItems } from "./Sidebar";
import { useTranslation } from "@/i18n";

/// 移动端底部标签栏（桌面端隐藏，由 Sidebar 承担导航）
export default function BottomNav() {
  const { t } = useTranslation();
  return (
    <nav className="fixed bottom-0 inset-x-0 z-40 md:hidden bg-surface-card border-t border-border pb-[env(safe-area-inset-bottom)]">
      <div className="flex">
        {navItems.map(({ to, icon: Icon, labelKey }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                "flex-1 flex flex-col items-center gap-0.5 py-2 text-[11px] transition-colors",
                isActive ? "text-accent" : "text-gray-500"
              )
            }
          >
            <Icon size={20} />
            <span>{t(labelKey)}</span>
          </NavLink>
        ))}
      </div>
    </nav>
  );
}
