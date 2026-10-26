import { useCallback, useEffect, useRef, useState } from "react";
import { Download, Eraser, FileTerminal, RefreshCw, X } from "lucide-react";
import clsx from "clsx";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";
import {
  clearAppLogs,
  exportAppLogs,
  getAppLogs,
  type AppLogEntry,
} from "@/api/ipc";

/** 【APP6 任务1.2】「设置 -> 运行日志」全局诊断中心弹窗
 *
 * - 顶部模块筛选标签栏：全部 | Go Lan | 内核 | 订阅 | Pro 授权 | Go AIM | Go Cus
 * - 右上角实时显示日志占用空间（上限 512 KB，超出自动轮转）
 * - 等宽字体深色高对比日志列表：ERROR 红色 / WARN 琥珀色 / INFO 常规
 * - 底部操作：刷新 / 导出日志（下载 .log + 复制全文）/ 清空日志
 * - 打开期间每 2 秒自动轮询，实时滚动输出
 */

const MODULE_TABS: { key: string; value: string | null; labelKey: string }[] = [
  { key: "all", value: null, labelKey: "logs.filterAll" },
  { key: "golan", value: "GoLan", labelKey: "logs.filterGoLan" },
  { key: "kernel", value: "Kernel", labelKey: "logs.filterKernel" },
  { key: "sub", value: "Sub", labelKey: "logs.filterSub" },
  { key: "pro", value: "Pro", labelKey: "logs.filterPro" },
  { key: "goaim", value: "GoAim", labelKey: "logs.filterGoAim" },
  { key: "gocus", value: "GoCus", labelKey: "logs.filterGoCus" },
];

interface LogViewerModalProps {
  open: boolean;
  onClose: () => void;
  /** 打开时预选的模块筛选（如 GoLan 弹窗嵌入时传 "GoLan"） */
  initialModule?: string | null;
  /** 隐藏底部操作栏（GoLanModal 内嵌紧凑模式自行渲染按钮） */
  compact?: boolean;
  /** 外部刷新信号：变化时立即重新拉取（保存/检测后触发实时滚动） */
  refreshSignal?: number;
}

const levelColor = (level: string) =>
  level === "ERROR"
    ? "text-red-400"
    : level === "WARN"
      ? "text-amber-400"
      : "text-gray-300";

const moduleBadge = (module: string) =>
  module === "GoLan"
    ? "bg-emerald-500/15 text-emerald-300"
    : module === "Pro"
      ? "bg-violet-500/15 text-violet-300"
      : module === "Sub"
        ? "bg-sky-500/15 text-sky-300"
        : module === "GoAim"
          ? "bg-amber-500/15 text-amber-300"
          : module === "GoCus"
            ? "bg-pink-500/15 text-pink-300"
            : "bg-gray-500/15 text-gray-300";

export default function LogViewerModal({
  open,
  onClose,
  initialModule = null,
  compact = false,
  refreshSignal = 0,
}: LogViewerModalProps) {
  const { t } = useTranslation();
  const [activeModule, setActiveModule] = useState<string | null>(initialModule);
  const [entries, setEntries] = useState<AppLogEntry[]>([]);
  const [totalBytes, setTotalBytes] = useState(0);
  const [loading, setLoading] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const load = useCallback(
    async (module: string | null) => {
      setLoading(true);
      try {
        const payload = await getAppLogs(module ?? undefined);
        setEntries(payload.entries ?? []);
        setTotalBytes(payload.totalBytes ?? 0);
      } catch (e) {
        console.warn("[LogViewer] 读取日志失败:", e);
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    if (!open) return;
    void load(activeModule);
    const timer = window.setInterval(() => void load(activeModule), 2000);
    return () => window.clearInterval(timer);
  }, [open, activeModule, load, refreshSignal]);

  // 新日志到达时自动滚动到底部（实时滚动输出）
  useEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [entries.length]);

  if (!open) return null;

  const kb = (totalBytes / 1024).toFixed(1);

  const handleExport = async () => {
    try {
      const text = await exportAppLogs(activeModule ?? undefined);
      // 同步复制到剪贴板
      try {
        await navigator.clipboard.writeText(text);
        toast.success(t("logs.exportCopied"));
      } catch {
        /* 剪贴板权限受限时仅下载文件 */
      }
      // 导出保存为 .log 文件
      const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `prism-logs-${new Date()
        .toISOString()
        .slice(0, 19)
        .replace(/[:T]/g, "-")}.log`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleClear = async () => {
    try {
      await clearAppLogs();
      await load(activeModule);
      toast.success(t("logs.cleared"));
    } catch (e) {
      toast.error(String(e));
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="flex max-h-[82vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-border bg-surface"
        onClick={(e) => e.stopPropagation()}
      >
        {/* 标题栏 */}
        <div className="flex shrink-0 items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <FileTerminal size={16} className="text-accent" />
            <h3 className="text-sm font-semibold">{t("logs.title")}</h3>
          </div>
          <div className="flex items-center gap-3">
            <span className="rounded-full bg-surface-hover px-2 py-0.5 text-[11px] text-gray-400">
              {kb} KB / {t("logs.quotaSuffix")}
            </span>
            <button
              onClick={onClose}
              className="rounded p-1 text-gray-400 hover:bg-surface-hover hover:text-gray-200"
              aria-label={t("common.close")}
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* 模块筛选标签栏 */}
        <div className="flex shrink-0 gap-1 overflow-x-auto border-b border-border px-3 py-2 text-xs">
          {MODULE_TABS.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveModule(tab.value)}
              className={clsx(
                "shrink-0 rounded-full px-3 py-1 transition-colors",
                activeModule === tab.value
                  ? "bg-accent text-white"
                  : "bg-surface-hover text-gray-400 hover:text-gray-200",
              )}
            >
              {t(tab.labelKey)}
            </button>
          ))}
        </div>

        {/* 日志列表（等宽深色高对比） */}
        <div
          ref={listRef}
          className="flex-1 overflow-y-auto bg-black/40 px-3 py-2 font-mono text-[11px] leading-relaxed"
        >
          {entries.length === 0 ? (
            <div className="py-10 text-center text-gray-500">
              {loading ? t("logs.loading") : t("logs.empty")}
            </div>
          ) : (
            entries.map((e) => (
              <div key={e.id} className="flex gap-2 py-0.5">
                <span className="shrink-0 text-gray-500">{e.timestamp}</span>
                <span
                  className={clsx(
                    "shrink-0 font-semibold",
                    levelColor(e.level),
                  )}
                >
                  {e.level}
                </span>
                <span
                  className={clsx(
                    "shrink-0 rounded px-1 text-[10px] font-medium",
                    moduleBadge(e.module),
                  )}
                >
                  {e.module}
                </span>
                <span
                  className={clsx(
                    "break-all",
                    e.level === "ERROR"
                      ? "text-red-300"
                      : e.level === "WARN"
                        ? "text-amber-200"
                        : "text-gray-300",
                  )}
                >
                  {e.message}
                </span>
              </div>
            ))
          )}
        </div>

        {/* 底部操作栏 */}
        {!compact && (
          <div className="flex shrink-0 items-center justify-between gap-2 border-t border-border px-4 py-3">
            <button
              onClick={() => void load(activeModule)}
              className="flex items-center gap-1.5 rounded-lg bg-surface-hover px-3 py-1.5 text-xs text-gray-300 hover:text-white"
            >
              <RefreshCw size={13} />
              {t("logs.refresh")}
            </button>
            <div className="flex gap-2">
              <button
                onClick={() => void handleExport()}
                className="flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs text-white hover:opacity-90"
              >
                <Download size={13} />
                {t("logs.export")}
              </button>
              <button
                onClick={() => void handleClear()}
                className="flex items-center gap-1.5 rounded-lg bg-red-500/90 px-3 py-1.5 text-xs text-white hover:opacity-90"
              >
                <Eraser size={13} />
                {t("logs.clear")}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
