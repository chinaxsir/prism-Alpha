import { Minus, X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";

import { useTranslation } from "@/i18n";

/// 无边框窗口的自定义标题栏：可拖动区域 + 最小化/关闭（窗口固定尺寸，无最大化）
export default function TitleBar() {
  const { t } = useTranslation();

  // Conditionally render the TitleBar only if running in Tauri environment
  if (typeof window !== 'undefined' && !(window as any).__TAURI__) {
    return null; // Don't render TitleBar if not in Tauri
  }

  const appWindow = getCurrentWindow();

  return (
    <div
      data-tauri-drag-region
      className="hidden md:flex h-9 shrink-0 items-center justify-between pl-4 pr-2 bg-surface border-b border-border select-none"
    >
      <span
        data-tauri-drag-region
        className="text-xs text-gray-500 font-medium tracking-wide"
      >
        Prism Proxy
      </span>

      <div className="flex items-center gap-1">
        <button
          onClick={() => appWindow.minimize()}
          className="p-1.5 rounded-md hover:bg-surface-hover text-gray-400 hover:text-gray-200 transition-colors"
          title={t("titlebar.minimize")}
        >
          <Minus size={14} />
        </button>
        <button
          onClick={() => appWindow.close()}
          className="p-1.5 rounded-md hover:bg-latency-bad/80 text-gray-400 hover:text-white transition-colors"
          title={t("titlebar.closeToTray")}
        >
          <X size={14} />
        </button>
      </div>
    </div>
  );
}
