import { NavLink } from "react-router-dom";
import clsx from "clsx";

import { navItems } from "./Sidebar";
import { useTranslation } from "@/i18n";

/// 移动端底部标签栏（桌面端隐藏，由 Sidebar 承担导航）
export default function BottomNav() {
  const { t } = useTranslation();
  return (
    <nav className="fixed bottom-0 inset-x-0 z-40 md:hidden bg-tabbar/95 backdrop-blur-xl border-t border-border pb-[env(safe-area-inset-bottom)]">
      <div className="flex">
        {navItems.map(({ to, icon: Icon, labelKey }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                "relative flex-1 flex flex-col items-center gap-1 py-2 text-[11px] transition-colors",
                isActive ? "text-accent" : "text-gray-500"
              )
            }
          >
            {({ isActive }) => (
              <>
                {/* 【APP44 任务2】当前标签顶部指示条：移动端一眼可辨当前所在页 */}
                <span
                  className={clsx(
                    "absolute top-0 h-0.5 w-6 rounded-full transition-opacity",
                    isActive ? "bg-accent opacity-100" : "opacity-0"
                  )}
                />
                <Icon size={20} strokeWidth={isActive ? 2.2 : 1.8} />
                <span className={clsx(isActive && "font-medium")}>{t(labelKey)}</span>
              </>
            )}
          </NavLink>
        ))}
      </div>
    </nav>
  );
}
