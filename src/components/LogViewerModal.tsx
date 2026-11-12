import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Download,
  Eraser,
  FileTerminal,
  RefreshCw,
  X,
} from "lucide-react";
import clsx from "clsx";
import { invoke } from "@tauri-apps/api/core";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";
import {
  clearAppLogs,
  getAppLogs,
  type AppLogEntry,
  type LogBucket,
} from "@/api/ipc";

/** 【IPA9 任务1】「设置 -> 运行日志」全局诊断中心弹窗
 *
 * - 【APP50 任务4】顶部诊断摘要卡与「复制诊断报告」区块已删除
 *   （iOS 小屏挤压日志可视区，诊断信息以导出日志为准）
 * - 顶部分类筛选 chips（全部/内核/Go Lan/Go AIM/订阅/仅看异常，
 *   flex-wrap 自动换行，最右侧标签不被截断）
 * - 右上角实时显示日志占用空间（上限 512 KB）
 * - 每条日志渲染为上下两行全宽卡片：
 *   第一行 level 徽章 + module 徽章 + 时分秒毫秒时间戳；
 *   第二行 100% 全宽日志正文（Kernel 日志自动剥离重复头部）。
 * - 底部操作：刷新 / 导出日志（同步剪贴板 + iOS 原生分享）/ 清空日志
 * - 打开期间每 2 秒自动轮询
 */

/** 【APP56 任务4】固定 7 个独立分类标签（无「全部」混合视图）：
 *  内核（默认选中）/ 节点 / 规则 / Go AIM / Go Lan / Go Cus / 订阅。
 *  value 与后端强制分类后的 module 字段严格一一对应。 */
const CATEGORY_TABS: { key: string; value: string; labelKey: string }[] = [
  { key: "kernel", value: "Kernel", labelKey: "logs.filterKernel" },
  { key: "node", value: "Node", labelKey: "logs.filterNode" },
  { key: "rule", value: "Rule", labelKey: "logs.filterRule" },
  { key: "goaim", value: "GoAIM", labelKey: "logs.filterGoAim" },
  { key: "golan", value: "GoLan", labelKey: "logs.filterGoLan" },
  { key: "gocus", value: "GoCus", labelKey: "logs.filterGoCus" },
  { key: "sub", value: "Sub", labelKey: "logs.filterSub" },
];

const CATEGORY_VALUES = new Set(CATEGORY_TABS.map((t) => t.value));

/** 【APP58 任务5】日志分类归一化：显式分类只允许 7 类合法值；
 *  `Go Lan` / `Go AIM` / `Go Cus` 去空格统一成 GoLan / GoAIM / GoCus；
 *  未知分类一律落到 Kernel。**绝不读取 message 内容猜测分类**。 */
function normalizeCat(raw?: string | null): string {
  const s = (raw ?? "").trim();
  if (CATEGORY_VALUES.has(s)) return s;
  const compact = s.toLowerCase().replace(/\s+/g, "");
  switch (compact) {
    case "kernel":
      return "Kernel";
    case "node":
    case "节点":
      return "Node";
    case "rule":
    case "规则":
      return "Rule";
    case "golan":
      return "GoLan";
    case "goaim":
      return "GoAIM";
    case "gocus":
      return "GoCus";
    case "sub":
    case "subscription":
    case "订阅":
      return "Sub";
    default:
      return "Kernel";
  }
}

/** 完整投影：`projectCategory(e.module)` → 必定是 7 类之一。
 *  过滤、计数、徽章文字 / 颜色全部使用同一个投影值，保证「筛选=徽章」。 */
function projectCategory(raw?: string | null): string {
  const normalized = normalizeCat(raw);
  return CATEGORY_VALUES.has(normalized) ? normalized : "Kernel";
}

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

const moduleBadge = (module: string) => {
  switch (module) {
    case "Kernel":
      return "bg-indigo-500/15 text-indigo-300";
    case "Node":
      return "bg-blue-600/15 text-blue-300";
    case "Rule":
      return "bg-cyan-500/15 text-cyan-300";
    case "GoAIM":
      return "bg-emerald-500/15 text-emerald-300";
    case "GoLan":
      return "bg-orange-500/15 text-orange-300";
    case "GoCus":
      return "bg-purple-500/15 text-purple-300";
    case "Sub":
      return "bg-rose-500/15 text-rose-300";
    default:
      return "bg-gray-500/15 text-gray-300";
  }
};

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
  // 【APP56 任务4】默认选中「内核」，不存在「全部」混合视图
  const [activeModule, setActiveModule] = useState<string>(initialModule ?? "Kernel");
  // 【APP62 任务4】一次性拿到全部分类日志 + 桶区间，切标签只在本地切片
  const [logs, setLogs] = useState<AppLogEntry[]>([]);
  const [buckets, setBuckets] = useState<LogBucket[]>([]);
  const [, setLastOffset] = useState(0);
  const [totalBytes, setTotalBytes] = useState(0);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  /** 【APP63 任务2.2】导出成功提示条（翠绿色） */
  const [exportedTip, setExportedTip] = useState(false);
  // 【APP71 任务5】Go AIM 多维筛选（批次 / 节点 / 平台 / 级别）
  const [aimRunId, setAimRunId] = useState("");
  const [aimNode, setAimNode] = useState("");
  const [aimService, setAimService] = useState("");
  const [aimLevel, setAimLevel] = useState("");
  const listRef = useRef<HTMLDivElement>(null);

  /** 【APP62 任务4】拉取分类聚合日志：失败自动重试 3 次（指数退避），
   *  避免一次性网络抖动导致某个分类列表被清空 / 卡在加载态。 */
  const load = useCallback(async () => {
    setLoading(true);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        const payload = await getAppLogs();
        setLogs(payload.logs ?? []);
        setBuckets(payload.buckets ?? []);
        setTotalBytes(payload.totalBytes ?? 0);
        setLastOffset(payload.lastOffset ?? 0);
        setLoading(false);
        return;
      } catch (e) {
        if (attempt === 2) {
          console.warn("[LogViewer] 读取日志失败:", e);
        } else {
          await new Promise((r) => window.setTimeout(r, 300 * (attempt + 1)));
        }
      }
    }
    setLoading(false);
  }, []);

  /** 【APP62 任务4】切换分类只做本地切片：bucket.start ~ bucket.end，
   *  全程零网络请求，也就不会出现「黑色挡住内容」的加载遮罩。 */
  const visibleEntries = useMemo(() => {
    const bucket = buckets.find((b) => b.module === activeModule);
    if (!bucket) return [];
    let rows = logs.slice(bucket.start, bucket.end);
    // 【APP71 任务5】GoAIM 桶内再按 runId / 节点 / 平台 / 级别精确筛选
    if (activeModule === "GoAIM") {
      if (aimRunId) rows = rows.filter((e) => (e.runId ?? "") === aimRunId);
      if (aimNode) rows = rows.filter((e) => (e.nodeName ?? "") === aimNode);
      if (aimService) rows = rows.filter((e) => (e.service ?? "") === aimService);
      if (aimLevel) rows = rows.filter((e) => (e.level ?? "") === aimLevel);
    }
    return rows;
  }, [logs, buckets, activeModule, aimRunId, aimNode, aimService, aimLevel]);

  /** 【APP71 任务5】GoAIM 筛选下拉选项（来自当前桶内真实出现过的值） */
  const aimFilterOptions = useMemo(() => {
    const empty = { runs: [] as string[], nodes: [] as string[], services: [] as string[], levels: [] as string[] };
    if (activeModule !== "GoAIM") return empty;
    const bucket = buckets.find((b) => b.module === "GoAIM");
    if (!bucket) return empty;
    const rows = logs.slice(bucket.start, bucket.end);
    const uniq = (values: (string | undefined)[]) =>
      Array.from(new Set(values.filter((v): v is string => Boolean(v))));
    return {
      runs: uniq(rows.map((e) => e.runId)).slice(-10).reverse(),
      nodes: uniq(rows.map((e) => e.nodeName)),
      services: uniq(rows.map((e) => e.service)),
      levels: uniq(rows.map((e) => e.level)),
    };
  }, [logs, buckets, activeModule]);

  /** 每个分类标签的实时条数（直接取自后端桶区间，与切片同源） */
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const tab of CATEGORY_TABS) counts[tab.value] = 0;
    for (const b of buckets) {
      if (b.module in counts) counts[b.module] = b.count;
    }
    return counts;
  }, [buckets]);

  // 打开期间每 2 秒轮询全量分类（切换分类不再触发请求）
  useEffect(() => {
    if (!open) return;
    void load();
    const timer = window.setInterval(() => void load(), 2000);
    return () => window.clearInterval(timer);
  }, [open, load, refreshSignal]);

  // 新日志到达时自动滚动到底部
  useEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [visibleEntries.length]);

  if (!open) return null;

  const kb = (totalBytes / 1024).toFixed(1);

  /** 关闭弹窗：主动失焦，避免 iOS 保留输入框撤销栈 */
  const closeModal = () => {
    (document.activeElement as HTMLElement | null)?.blur();
    onClose();
  };

  /** 【APP63 任务2.2】零闪退导出：彻底移除 Blob URL / <a download> /
   *  navigator 分享面板 API（三者都会让 iOS WKWebView 崩溃）。改为：
   *  1. 调后端 export_diagnostic_logs（iOS 原生分享 + 剪贴板兜底，
   *     桌面写入 Downloads）；
   *  2. 前端 navigator.clipboard 冗余复制；
   *  3. 顶部翠绿色成功提示条。 */
  const handleExport = async () => {
    if (exporting) return;
    if (logs.length === 0) {
      toast.error(t("logs.exportEmpty"));
      return;
    }
    setExporting(true);
    try {
      const text = await invoke<string>("export_diagnostic_logs");
      try {
        await navigator.clipboard?.writeText(text);
      } catch {
        // 剪贴板不可用时忽略：iOS 原生层已在主线程写入剪贴板
      }
      setExportedTip(true);
      window.setTimeout(() => setExportedTip(false), 4000);
      toast.success(t("logs.exported"));
    } catch (e) {
      console.error("[LogViewer] 导出诊断日志失败:", e);
      toast.error(String(e));
    } finally {
      setExporting(false);
    }
  };

  /** 【APP71 任务5】仅导出 Go AIM 诊断日志（后端按模块过滤 + 结构化上下文） */
  const handleExportAim = async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const text = await invoke<string>("export_diagnostic_logs", {
        module: "GoAIM",
      });
      try {
        await navigator.clipboard?.writeText(text);
      } catch {
        // 剪贴板不可用时忽略：iOS 原生层已在主线程写入剪贴板
      }
      setExportedTip(true);
      window.setTimeout(() => setExportedTip(false), 4000);
      toast.success(t("logs.exported"));
    } catch (e) {
      console.error("[LogViewer] 导出 AIM 诊断日志失败:", e);
      toast.error(String(e));
    } finally {
      setExporting(false);
    }
  };

  /** 【IPA9 任务1.2】清空日志：调用后端 clear_app_logs 后立即把前端
   *  列表置空、容量归零，避免轮询把旧日志又拉回来（后端 LAST_CLEARED
   *  机制会过滤外部文件中的旧内容）。 */
  const handleClear = async () => {
    try {
      await clearAppLogs();
      setLogs([]);
      setBuckets([]);
      setTotalBytes(0);
      setLastOffset(0);
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

        {/* 【APP63 任务2.2】导出成功提示条（翠绿色，4 秒自动消失） */}
        {exportedTip && (
          <div className="shrink-0 border-b border-emerald-500/40 bg-emerald-500/15 px-4 py-2 text-[12px] font-medium leading-relaxed text-emerald-300">
            ✅ 诊断日志已导出（已同步复制到剪贴板，可直接粘贴或通过系统面板保存）
          </div>
        )}

        {/* 【APP56 任务4 / APP57 任务4】固定 7 个独立分类标签（无「全部」），
            上下两行 4 + 3 排布，任何标签都不省略、不截断，并显示真实条数 */}
        <div className="shrink-0 space-y-1.5 border-b border-border px-3 py-2">
          {(() => {
            const ordered = [...CATEGORY_TABS].sort(
              (a, b) =>
                (categoryCounts[b.value] ?? 0) - (categoryCounts[a.value] ?? 0),
            );
            const renderTab = (tab: (typeof CATEGORY_TABS)[number]) => (
              <button
                key={tab.key}
                onClick={() => setActiveModule(tab.value)}
                className={clsx(
                  "flex min-w-0 items-center justify-center gap-1 rounded-full px-2 py-1 text-xs transition-colors",
                  activeModule === tab.value
                    ? "bg-accent text-white"
                    : "bg-surface-hover text-gray-400 hover:text-gray-200",
                )}
              >
                <span className="whitespace-nowrap">{t(tab.labelKey)}</span>
                <span className="shrink-0 rounded-full bg-black/20 px-1.5 py-0.5 text-[10px] leading-none">
                  {categoryCounts[tab.value] ?? 0}
                </span>
              </button>
            );
            return (
              <>
                <div className="grid grid-cols-4 gap-1.5">
                  {ordered.slice(0, 4).map(renderTab)}
                </div>
                <div className="grid grid-cols-3 gap-1.5">
                  {ordered.slice(4).map(renderTab)}
                </div>
              </>
            );
          })()}
        </div>

        {/* 【APP71 任务5】GoAIM 多维筛选 + 一键导出 AIM 诊断 */}
        {activeModule === "GoAIM" && (
          <div className="flex shrink-0 flex-wrap items-center gap-1.5 border-b border-border px-3 py-2">
            <select
              value={aimRunId}
              onChange={(e) => setAimRunId(e.target.value)}
              className="min-w-0 rounded-lg border border-border bg-surface-hover px-2 py-1 text-[11px] text-gray-300"
            >
              <option value="">{t("logs.aimRunAll")}</option>
              {aimFilterOptions.runs.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
            <select
              value={aimNode}
              onChange={(e) => setAimNode(e.target.value)}
              className="min-w-0 max-w-[8rem] rounded-lg border border-border bg-surface-hover px-2 py-1 text-[11px] text-gray-300"
            >
              <option value="">{t("logs.aimNodeAll")}</option>
              {aimFilterOptions.nodes.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
            <select
              value={aimService}
              onChange={(e) => setAimService(e.target.value)}
              className="rounded-lg border border-border bg-surface-hover px-2 py-1 text-[11px] text-gray-300"
            >
              <option value="">{t("logs.aimServiceAll")}</option>
              {aimFilterOptions.services.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
            <select
              value={aimLevel}
              onChange={(e) => setAimLevel(e.target.value)}
              className="rounded-lg border border-border bg-surface-hover px-2 py-1 text-[11px] text-gray-300"
            >
              <option value="">{t("logs.aimLevelAll")}</option>
              {aimFilterOptions.levels.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
            <button
              onClick={() => void handleExportAim()}
              disabled={exporting}
              className="ml-auto rounded-lg border border-border px-2 py-1 text-[11px] text-gray-300 hover:border-accent/40 disabled:opacity-50"
            >
              {t("logs.exportAim")}
            </button>
          </div>
        )}

        {/* 日志列表：每条为上下两行全宽卡片。
            【APP62 任务4】key={activeModule} 强制切换分类时重建列表，
            彻底清除上一分类的滚动位置 / 残留节点 */}
        <div
          key={activeModule}
          ref={listRef}
          className="flex-1 space-y-1.5 overflow-y-auto bg-black/40 px-3 py-2"
        >
          {visibleEntries.length === 0 ? (
            <div className="py-10 text-center text-gray-500">
              {loading ? t("logs.loading") : t("logs.empty")}
            </div>
          ) : (
            visibleEntries.map((e) => {
              // 【APP58 任务5】徽章与筛选使用同一个投影分类，颜色同源
              const displayModule = projectCategory(e.module);
              const msg =
                displayModule === "Kernel" ? stripKernelHeader(e.message) : e.message;
              return (
                <div
                  key={e.id}
                  className="rounded-lg bg-background/60 border border-border/50 px-3 py-2 space-y-1"
                >
                  {/* 第一行：左 级别徽章 + 模块徽章，右 北京时间戳（等宽加粗） */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-1.5">
                      <span
                        className={clsx(
                          "shrink-0 rounded px-1.5 py-0.5 text-[11px] font-bold tracking-wide",
                          levelColor(e.level),
                        )}
                      >
                        {e.level}
                      </span>
                      <span
                        className={clsx(
                          "shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium",
                          moduleBadge(displayModule),
                        )}
                      >
                        {displayModule}
                      </span>
                    </div>
                    {/* 【APP54 任务3】北京时间戳（UTC+8，后端已统一转换）；日志区为深色底，固定浅色等宽加粗 */}
                    <span className="shrink-0 whitespace-nowrap font-mono text-[11px] font-bold text-[#E5E5EA]">
                      {e.timestamp}
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
              onClick={() => void load()}
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
