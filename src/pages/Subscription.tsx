import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { RefreshCw, Rss, Trash2, Pencil, Check, X } from "lucide-react";

import {
  deleteSubscription,
  listSubscriptions,
  renameSubscription,
  toggleSubscription,
  updateAllSubscriptions,
  updateSubscription,
  type SubscriptionRecord,
} from "@/api/ipc";
import EmptyState from "@/components/ui/EmptyState";
import Spinner from "@/components/ui/Spinner";
import Switch from "@/components/ui/Switch";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";
import { useProStore } from "@/stores/pro";
import { useCoreStore } from "@/stores/core";
import { formatRelativeTime } from "@/utils/time";
import { formatBytes } from "@/utils/format";

function displayName(record: SubscriptionRecord): string {
  if (record.name) return record.name;
  try {
    return new URL(record.url).hostname;
  } catch {
    return record.url;
  }
}

export default function Subscription() {
  const { t } = useTranslation();
  // 【APP-10 任务4】首帧直出全局 store 缓存（App 启动已水合），
  // 消除订阅启用开关切页闪烁；无缓存时回落空列表走原加载路径
  const [subs, setSubs] = useState<SubscriptionRecord[]>(
    () => useCoreStore.getState().subscriptions ?? [],
  );
  const [loading, setLoading] = useState(
    () => useCoreStore.getState().subscriptions == null,
  );
  const [url, setUrl] = useState("");
  // 【APP42 任务2.1】可选的订阅备注名（留空则展示机场域名）
  const [name, setName] = useState("");
  const [adding, setAdding] = useState(false);
  const [updatingUrl, setUpdatingUrl] = useState<string | null>(null);
  /// 【APP49 任务2.2】「全部更新」进行中标记
  const [updatingAll, setUpdatingAll] = useState(false);
  // 【APP47 任务2.2】订阅操作错误：文档流内联高对比横幅（不再用悬浮 Toast
  // 遮挡下方「添加并更新」按钮，且浅色外观下为深红字/浅红底，绝不白底白字）
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmUrl, setConfirmUrl] = useState<string | null>(null);
  // 行内重命名：正在编辑的 URL 与草稿值
  const [editingUrl, setEditingUrl] = useState<string | null>(null);
  const [draftName, setDraftName] = useState("");
  const unlocked = useProStore((s) => s.unlocked);

  const load = useCallback(async () => {
    try {
      const records = await listSubscriptions();
      setSubs(records ?? []);
      // 回写全局 store，保持后续切页首帧为最新值
      useCoreStore.getState().setSubscriptions(records ?? []);
    } catch (e) {
      console.error("load subscriptions failed:", e);
      toast.error(t("sub.loadFailed", { error: String(e) }));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    // 订阅云同步对账（新增/删除/空壳补拉）后端完成时静默刷新列表，
    // 无需用户手动下拉
    const unSubs = listen("subscriptions://changed", () => load());
    return () => {
      unSubs.then((f) => f());
    };
  }, [load]);

  const handleAdd = async () => {
    const trimmed = url.trim();
    if (!/^https?:\/\/.+/.test(trimmed)) {
      setActionError(t("sub.invalidUrl"));
      return;
    }
    // 免费版仅支持单订阅：第二条起需要 Pro（全平台门控）
    // 【APP-4 任务3】未激活点击静默忽略：不弹 Toast / 激活弹窗
    if (!unlocked && subs.length >= 1) {
      return;
    }
    setAdding(true);
    setActionError(null);
    try {
      await updateSubscription(trimmed, name.trim() || null);
      toast.success(t("sub.added"));
      setUrl("");
      setName("");
      await load();
    } catch (e) {
      console.error("add subscription failed:", e);
      setActionError(String(e));
    } finally {
      setAdding(false);
    }
  };

  /// 【APP42 任务2.1】行内重命名：本地立即生效，Pro 用户静默上行云端
  const handleRename = async (record: SubscriptionRecord) => {
    const next = draftName.trim();
    setEditingUrl(null);
    const prev = (record.name ?? "").trim();
    if (next === prev) return;
    try {
      await renameSubscription(record.url, next);
      toast.success(t("sub.renamed"));
      await load();
    } catch (e) {
      console.error("rename subscription failed:", e);
      toast.error(String(e));
    }
  };

  /// 【APP49 任务2.2】一键更新全部已启用订阅
  const handleUpdateAll = async () => {
    if (updatingAll) return;
    setUpdatingAll(true);
    setActionError(null);
    try {
      await updateAllSubscriptions();
      toast.success(t("sub.allUpdated"));
      await load();
    } catch (e) {
      console.error("update all subscriptions failed:", e);
      setActionError(String(e));
    } finally {
      setUpdatingAll(false);
    }
  };

  const handleUpdate = async (record: SubscriptionRecord) => {
    if (updatingUrl) return;
    setUpdatingUrl(record.url);
    setActionError(null);
    try {
      await updateSubscription(record.url);
      toast.success(t("sub.updated"));
      await load();
    } catch (e) {
      console.error("update subscription failed:", e);
      setActionError(String(e));
    } finally {
      setUpdatingUrl(null);
    }
  };

  const handleToggle = async (record: SubscriptionRecord) => {
    // 【APP51 任务1.3】0ms 乐观 UI：先本地翻转开关，再异步落盘
    const next = !record.enabled;
    const optimistic = subs.map((r) =>
      r.url === record.url ? { ...r, enabled: next } : r,
    );
    setSubs(optimistic);
    useCoreStore.getState().setSubscriptions(optimistic);
    try {
      await toggleSubscription(record.url, next);
      toast.success(t(record.enabled ? "sub.disabled" : "sub.enabled"));
      await load();
    } catch (e) {
      console.error("toggle subscription failed:", e);
      toast.error(String(e));
      await load();
    }
  };

  const handleDelete = async (record: SubscriptionRecord) => {
    try {
      await deleteSubscription(record.url);
      toast.success(t("sub.deleted"));
      setConfirmUrl(null);
      await load();
    } catch (e) {
      console.error("delete subscription failed:", e);
      toast.error(String(e));
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="text-[22px] font-bold tracking-tight">{t("sub.title")}</h1>

      {/* 【APP47 任务2.2】错误横幅：标准文档流、位于「添加订阅」卡片上方，
          浅色 深红字 #B91C1C + 浅红底 #FEF2F2 + 红框 #F87171；
          深色 亮红字 #FCA5A5 + 暗红底 #3B1219 + 红框 #EF4444 */}
      {actionError && (
        <div className="mb-3 flex items-start gap-2 rounded-xl border px-4 py-3 bg-[#FEF2F2] border-[#F87171] text-[#B91C1C] dark:bg-[#3B1219] dark:border-[#EF4444] dark:text-[#FCA5A5]">
          <span className="flex-1 text-[14px] font-semibold break-all">
            {actionError}
          </span>
          <button
            onClick={() => setActionError(null)}
            className="shrink-0 rounded p-1 text-[#B91C1C] dark:text-[#FCA5A5] hover:opacity-70"
            title={t("common.cancel")}
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* 添加订阅 */}
      <div className="bg-surface-card rounded-xl p-5">
        <h2 className="text-[16px] font-bold text-text mb-4">{t("sub.addTitle")}</h2>
        <div className="flex flex-col gap-3 md:flex-row">
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("sub.namePlaceholder")}
            maxLength={40}
            className="w-full md:w-48 px-4 py-2 rounded-lg bg-surface-hover border border-border focus:border-accent outline-none text-sm"
          />
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={t("sub.urlPlaceholder")}
            className="flex-1 px-4 py-2 rounded-lg bg-surface-hover border border-border focus:border-accent outline-none text-sm"
          />
          {/* 【APP47 任务2.2】实心高亮皇家蓝主按钮（杜绝发灰浅蓝底配暗字） */}
          <button
            onClick={handleAdd}
            disabled={adding || !url.trim()}
            className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-[#007AFF] hover:bg-[#0066DD] transition-colors text-[15px] font-bold text-white shadow-sm disabled:opacity-50"
          >
            {adding && <Spinner size={14} className="text-white" />}
            {adding ? t("sub.adding") : t("sub.addAndUpdate")}
          </button>
        </div>
      </div>

      {/* 订阅列表 */}
      <div className="bg-surface-card rounded-xl p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="text-[16px] font-bold text-text">
            {t("sub.myList", { count: subs.length })}
          </h2>
          {/* 【APP49 任务2.2】一键更新全部已启用订阅（多 UA + 本地代理/DoH 通道） */}
          {subs.length > 0 && (
            <button
              onClick={handleUpdateAll}
              disabled={updatingAll}
              className="flex shrink-0 items-center gap-1.5 rounded-lg bg-surface-hover px-3 py-1.5 text-[13px] font-semibold text-text transition-colors hover:bg-accent/10 hover:text-accent disabled:opacity-50"
            >
              {updatingAll ? (
                <Spinner size={12} />
              ) : (
                <RefreshCw size={13} />
              )}
              {updatingAll ? t("sub.updatingAll") : t("sub.updateAll")}
            </button>
          )}
        </div>

        {loading ? (
          <div className="flex justify-center py-10">
            <Spinner />
          </div>
        ) : subs.length === 0 ? (
          <EmptyState
            icon={<Rss size={32} />}
            title={t("sub.emptyTitle")}
            description={t("sub.emptyDesc")}
          />
        ) : (
          <div className="space-y-3">
            {subs.map((record) => (
              <div
                key={record.url}
                className="flex flex-col gap-3 rounded-lg bg-surface-hover p-4 md:flex-row md:items-center"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    {editingUrl === record.url ? (
                      <div className="flex items-center gap-1.5">
                        <input
                          autoFocus
                          value={draftName}
                          onChange={(e) => setDraftName(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") handleRename(record);
                            if (e.key === "Escape") setEditingUrl(null);
                          }}
                          placeholder={t("sub.namePlaceholder")}
                          maxLength={40}
                          className="w-40 rounded-md border border-accent bg-background px-2 py-1 text-sm outline-none"
                        />
                        <button
                          onClick={() => handleRename(record)}
                          className="rounded p-1 text-latency-good hover:bg-surface-card"
                          title={t("common.save")}
                        >
                          <Check size={13} />
                        </button>
                        <button
                          onClick={() => setEditingUrl(null)}
                          className="rounded p-1 text-gray-400 hover:bg-surface-card"
                          title={t("common.cancel")}
                        >
                          <X size={13} />
                        </button>
                      </div>
                    ) : (
                      <>
                        <span className="min-w-0 flex-1 truncate text-[16px] font-bold text-text">
                          {displayName(record)}
                        </span>
                        <button
                          onClick={() => {
                            setEditingUrl(record.url);
                            setDraftName(record.name ?? "");
                          }}
                          className="shrink-0 rounded p-1 text-gray-500 hover:bg-surface-card hover:text-accent"
                          title={t("sub.rename")}
                        >
                          <Pencil size={12} />
                        </button>
                      </>
                    )}
                    {record.enabled && (
                      <span className="shrink-0 rounded bg-accent/20 px-1.5 py-0.5 text-[11px] text-accent">
                        {t("sub.badgeEnabled")}
                      </span>
                    )}
                  </div>
                  <div className="mt-1 truncate font-mono text-[11px] text-gray-500">
                    {record.url}
                  </div>
                  <div className="mt-1 text-[11px] text-gray-500">
                    {t("sub.updatedAt", { time: formatRelativeTime(record.updatedAt) })}
                    {record.nodeCount != null && (
                      <span className="ml-2">
                        {t("sub.nodes", { count: record.nodeCount })}
                      </span>
                    )}
                  </div>
                  {/* 机场流量配额进度条（subscription-userinfo 下发才有） */}
                  {record.totalBytes != null && record.totalBytes > 0 && (() => {
                    const used =
                      (record.uploadBytes ?? 0) + (record.downloadBytes ?? 0);
                    const pct = Math.min(100, (used / record.totalBytes!) * 100);
                    const expired =
                      record.expireAt != null && record.expireAt * 1000 < Date.now();
                    const barColor =
                      expired || pct >= 90
                        ? "bg-latency-bad"
                        : pct >= 70
                          ? "bg-latency-medium"
                          : "bg-accent";
                    return (
                      <div className="mt-2 max-w-md">
                        <div className="flex items-center justify-between text-[11px] text-gray-400">
                          <span>
                            {t("sub.traffic", {
                              used: formatBytes(used),
                              total: formatBytes(record.totalBytes!),
                            })}
                          </span>
                          <span className="font-mono tabular-nums">
                            {pct.toFixed(0)}%
                          </span>
                        </div>
                        <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-border">
                          <div
                            className={`h-full rounded-full transition-all ${barColor}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        {record.expireAt != null && (
                          <div className="mt-1 text-[11px] text-gray-500">
                            {expired
                              ? t("sub.expired")
                              : t("sub.expireAt", {
                                  date: new Date(
                                    record.expireAt * 1000
                                  ).toLocaleDateString(),
                                })}
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>

                <div className="flex shrink-0 flex-wrap items-center gap-2">
                  {/* 启停开关：停用后该订阅不参与配置合并 */}
                  <Switch
                    checked={record.enabled}
                    onChange={() => handleToggle(record)}
                    title={t(record.enabled ? "sub.toggleDisable" : "sub.toggleEnable")}
                  />
                  <button
                    onClick={() => handleUpdate(record)}
                    disabled={updatingUrl === record.url}
                    className="flex items-center gap-1.5 rounded-lg bg-[#EEEEF0] dark:bg-[#2C2C2E] px-4 py-1.5 text-[14px] font-bold text-[#000000] dark:text-[#FFFFFF] active:opacity-70 transition-opacity disabled:opacity-50"
                  >
                    {updatingUrl === record.url ? (
                      <Spinner size={12} />
                    ) : (
                      <RefreshCw size={12} />
                    )}
                    {t("sub.update")}
                  </button>

                  {confirmUrl === record.url ? (
                    <>
                      <button
                        onClick={() => handleDelete(record)}
                        className="rounded-lg bg-latency-bad/20 px-4 py-1.5 text-[14px] font-bold text-latency-bad hover:bg-latency-bad/30"
                      >
                        {t("sub.confirmDelete")}
                      </button>
                      <button
                        onClick={() => setConfirmUrl(null)}
                        className="rounded-lg bg-[#EEEEF0] dark:bg-[#2C2C2E] px-4 py-1.5 text-[14px] font-bold text-[#000000] dark:text-[#FFFFFF] active:opacity-70 transition-opacity"
                      >
                        {t("common.cancel")}
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => setConfirmUrl(record.url)}
                      className="flex items-center gap-1.5 rounded-lg bg-[#EEEEF0] dark:bg-[#2C2C2E] px-4 py-1.5 text-[14px] font-bold text-[#000000] dark:text-[#FFFFFF] active:opacity-70 transition-opacity hover:text-latency-bad"
                    >
                      <Trash2 size={12} />
                      {t("common.delete")}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
