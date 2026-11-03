import { useCallback, useEffect, useRef, useState } from "react";
import { Download, Eraser, FileTerminal, RefreshCw, X } from "lucide-react";
import clsx from "clsx";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";
import {
  clearAppLogs,
  getAppLogs,
  type AppLogEntry,
} from "@/api/ipc";

/** 【IPA9 任务1】「设置 -> 运行日志」全局诊断中心弹窗
 *
 * - 顶部模块筛选标签栏（flex-wrap 自动换行，最右侧标签不被截断）
 * - 右上角实时显示日志占用空间（上限 512 KB）
 * - 每条日志渲染为上下两行全宽卡片：
 *   第一行 level 徽章 + module 徽章 + 时分秒毫秒时间戳；
 *   第二行 100% 全宽日志正文（Kernel 日志自动剥离重复头部）。
 * - 底部操作：刷新 / 导出日志（同步剪贴板 + iOS 原生分享）/ 清空日志
 * - 打开期间每 2 秒自动轮询
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
  /** 外部刷新信号：变化时立即重新拉取 */
  refreshSignal?: number;
}

const levelColor = (level: string) =>
  level === "ERROR"
    ? "bg-red-500/15 text-red-400"
    : level === "WARN"
      ? "bg-amber-500/15 text-amber-400"
      : "bg-sky-500/15 text-sky-300";

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

/** 剥离 Kernel 日志中重复的头部前缀：
 *  `+0000 2026-10-26 09:44:10 ERROR [xxxx] connection: ...` → `connection: ...`
 *  保留干净的核心信息。
 */
function stripKernelHeader(msg: string): string {
  // 匹配：可选 +0000 → 日期时间 → 级别 → [模块] → 正文
  return msg.replace(
    /^[+-]\d{4}\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(?:ERROR|WARN|INFO|DEBUG|FATAL)\s+\[[^\]]*\]\s*/,
    "",
  );
}

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
  const [exporting, setExporting] = useState(false);
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

  // 新日志到达时自动滚动到底部
  useEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [entries.length]);

  if (!open) return null;

  const kb = (totalBytes / 1024).toFixed(1);

  /** 关闭弹窗：主动失焦，避免 iOS 保留输入框撤销栈 */
  const closeModal = () => {
    (document.activeElement as HTMLElement | null)?.blur();
    onClose();
  };

  /** 【IPA9 任务1.3】iOS WKWebView 不支持 <a download> Blob 下载，且
   *  await 异步之后调用剪贴板会被 iOS 系统拦截。改为在点击瞬间同步
   *  基于已加载 entries 构造导出文本，直接写入剪贴板并调起原生分享。 */
  const handleExport = async () => {
    if (entries.length === 0) {
      toast.error(t("logs.exportEmpty"));
      return;
    }
    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, "0");
    const ts = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
    const lines: string[] = [];
    lines.push(t("logs.exportHeader"));
    lines.push(t("logs.exportTime", { time: ts }));
    lines.push(t("logs.exportCount", { count: entries.length }));
    if (activeModule) lines.push(t("logs.exportModule", { module: activeModule }));
    lines.push("===============================================");
    lines.push("");
    for (const e of entries) {
      lines.push(`[${e.timestamp}][${e.level}][${e.module}] ${e.message}`);
    }
    const exportText = lines.join("\n");

    // 第 1 步：优先使用异步剪贴板（https / localhost 可用）；
    // textarea + execCommand 仅作兜底，避免污染 iOS Undo Paste 历史栈
    let copied = false;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(exportText);
        copied = true;
      }
    } catch {
      copied = false;
    }
    if (!copied) {
      try {
        const ta = document.createElement("textarea");
        ta.value = exportText;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        copied = document.execCommand("copy");
        document.body.removeChild(ta);
      } catch {
        copied = false;
      }
    }

    // 第 2 步：iOS 原生分享面板 / 桌面端 Blob 下载
    if (navigator.share) {
      navigator
        .share({ title: "Prism-Logs.txt", text: exportText })
        .catch(() => {});
    } else {
      const blob = new Blob([exportText], {
        type: "text/plain;charset=utf-8",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `prism-logs-${ts.replace(/[: ]/g, "-")}.log`;
      a.click();
      URL.revokeObjectURL(url);
    }

    // 第 3 步：按钮反馈
    setExporting(true);
    window.setTimeout(() => setExporting(false), 2500);
    toast.success(t("logs.exportCopied"));
  };

  /** 【IPA9 任务1.2】清空日志：调用后端 clear_app_logs 后立即把前端
   *  列表置空、容量归零，避免轮询把旧日志又拉回来（后端 LAST_CLEARED
   *  机制会过滤外部文件中的旧内容）。 */
  const handleClear = async () => {
    try {
      await clearAppLogs();
      setEntries([]);
      setTotalBytes(0);
      toast.success(t("logs.cleared"));
    } catch (e) {
      toast.error(String(e));
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={closeModal}
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
              onClick={closeModal}
              className="rounded p-1 text-gray-400 hover:bg-surface-hover hover:text-gray-200"
              aria-label={t("common.close")}
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* 模块筛选标签栏：flex-wrap 自动换行，最右侧标签不被截断 */}
        <div className="flex shrink-0 flex-wrap gap-1.5 border-b border-border px-3 py-2 text-xs">
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

        {/* 日志列表：每条为上下两行全宽卡片 */}
        <div
          ref={listRef}
          className="flex-1 space-y-1.5 overflow-y-auto bg-black/40 px-3 py-2"
        >
          {entries.length === 0 ? (
            <div className="py-10 text-center text-gray-500">
              {loading ? t("logs.loading") : t("logs.empty")}
            </div>
          ) : (
            entries.map((e) => {
              const msg =
                e.module === "Kernel" ? stripKernelHeader(e.message) : e.message;
              // 时间戳只显示时分秒毫秒（去掉日期前缀）
              const shortTs = e.timestamp.length >= 12 ? e.timestamp.slice(11) : e.timestamp;
              return (
                <div
                  key={e.id}
                  className="rounded-lg bg-background/60 border border-border/50 px-3 py-2 space-y-1"
                >
                  {/* 第一行：level 徽章 + module 徽章 + 精简时间戳 */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={clsx(
                          "rounded px-1.5 py-0.5 text-[11px] font-semibold",
                          levelColor(e.level),
                        )}
                      >
                        {e.level}
                      </span>
                      <span
                        className={clsx(
                          "rounded px-1.5 py-0.5 text-[11px] font-medium",
                          moduleBadge(e.module),
                        )}
                      >
                        {e.module}
                      </span>
                    </div>
                    <span className="shrink-0 font-mono text-[11px] text-gray-500">
                      {shortTs}
                    </span>
                  </div>
                  {/* 第二行：100% 全宽日志正文 */}
                  <div
                    className={clsx(
                      "w-full text-[11px] font-mono leading-relaxed break-all whitespace-pre-wrap select-text",
                      e.level === "ERROR"
                        ? "text-red-300"
                        : e.level === "WARN"
                          ? "text-amber-200"
                          : "text-gray-300",
                    )}
                  >
                    {msg}
                  </div>
                </div>
              );
            })
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
                className={clsx(
                  "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs text-white hover:opacity-90",
                  exporting ? "bg-emerald-500/90" : "bg-accent",
                )}
              >
                <Download size={13} />
                {exporting ? t("logs.exported") : t("logs.export")}
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
