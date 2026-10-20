import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { RefreshCw, Rss, Trash2 } from "lucide-react";

import {
  deleteSubscription,
  listSubscriptions,
  toggleSubscription,
  updateSubscription,
  type SubscriptionRecord,
} from "@/api/ipc";
import { ActivateProModal } from "@/components/ProGate";
import EmptyState from "@/components/ui/EmptyState";
import Spinner from "@/components/ui/Spinner";
import Switch from "@/components/ui/Switch";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";
import { useProStore } from "@/stores/pro";
import { formatRelativeTime } from "@/utils/time";

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
  const [subs, setSubs] = useState<SubscriptionRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [url, setUrl] = useState("");
  const [adding, setAdding] = useState(false);
  const [updatingUrl, setUpdatingUrl] = useState<string | null>(null);
  const [confirmUrl, setConfirmUrl] = useState<string | null>(null);
  const [showActivate, setShowActivate] = useState(false);
  const unlocked = useProStore((s) => s.unlocked);

  const load = useCallback(async () => {
    try {
      const records = await listSubscriptions();
      setSubs(records ?? []);
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
      toast.error(t("sub.invalidUrl"));
      return;
    }
    // 免费版仅支持单订阅：第二条起需要 Pro（全平台门控）
    if (!unlocked && subs.length >= 1) {
      setShowActivate(true);
      return;
    }
    setAdding(true);
    try {
      await updateSubscription(trimmed);
      toast.success(t("sub.added"));
      setUrl("");
      await load();
    } catch (e) {
      console.error("add subscription failed:", e);
      toast.error(String(e));
    } finally {
      setAdding(false);
    }
  };

  const handleUpdate = async (record: SubscriptionRecord) => {
    if (updatingUrl) return;
    setUpdatingUrl(record.url);
    try {
      await updateSubscription(record.url);
      toast.success(t("sub.updated"));
      await load();
    } catch (e) {
      console.error("update subscription failed:", e);
      toast.error(String(e));
    } finally {
      setUpdatingUrl(null);
    }
  };

  const handleToggle = async (record: SubscriptionRecord) => {
    try {
      await toggleSubscription(record.url, !record.enabled);
      toast.success(t(record.enabled ? "sub.disabled" : "sub.enabled"));
      await load();
    } catch (e) {
      console.error("toggle subscription failed:", e);
      toast.error(String(e));
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
      <h1 className="text-2xl font-bold">{t("sub.title")}</h1>

      {/* 添加订阅 */}
      <div className="bg-surface-card rounded-xl p-5">
        <h2 className="text-base font-semibold mb-4">{t("sub.addTitle")}</h2>
        <div className="flex flex-col gap-3 md:flex-row">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder={t("sub.urlPlaceholder")}
            className="flex-1 px-4 py-2 rounded-lg bg-surface-hover border border-border focus:border-accent outline-none text-sm"
          />
          <button
            onClick={handleAdd}
            disabled={adding || !url.trim()}
            className="flex items-center justify-center gap-2 px-6 py-2 rounded-lg bg-accent hover:bg-accent-hover transition-colors text-sm disabled:opacity-50"
          >
            {adding && <Spinner size={14} className="text-white" />}
            {adding ? t("sub.adding") : t("sub.addAndUpdate")}
          </button>
        </div>
      </div>

      {/* 订阅列表 */}
      <div className="bg-surface-card rounded-xl p-5">
        <h2 className="text-base font-semibold mb-4">
          {t("sub.myList", { count: subs.length })}
        </h2>

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
                    <span className="truncate text-sm font-medium">
                      {displayName(record)}
                    </span>
                    {record.enabled && (
                      <span className="shrink-0 rounded bg-accent/20 px-1.5 py-0.5 text-[10px] text-accent">
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
                </div>

                <div className="flex shrink-0 items-center gap-2">
                  {/* 启停开关：停用后该订阅不参与配置合并 */}
                  <Switch
                    checked={record.enabled}
                    onChange={() => handleToggle(record)}
                    title={t(record.enabled ? "sub.toggleDisable" : "sub.toggleEnable")}
                  />
                  <button
                    onClick={() => handleUpdate(record)}
                    disabled={updatingUrl === record.url}
                    className="flex items-center gap-1.5 rounded-lg bg-surface-card px-3 py-1.5 text-xs text-gray-300 hover:text-gray-100 disabled:opacity-50"
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
                        className="rounded-lg bg-latency-bad/20 px-3 py-1.5 text-xs text-latency-bad hover:bg-latency-bad/30"
                      >
                        {t("sub.confirmDelete")}
                      </button>
                      <button
                        onClick={() => setConfirmUrl(null)}
                        className="rounded-lg bg-surface-card px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200"
                      >
                        {t("common.cancel")}
                      </button>
                    </>
                  ) : (
                    <button
                      onClick={() => setConfirmUrl(record.url)}
                      className="flex items-center gap-1.5 rounded-lg bg-surface-card px-3 py-1.5 text-xs text-gray-400 hover:text-latency-bad"
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

      <ActivateProModal
        open={showActivate}
        onClose={() => setShowActivate(false)}
      />
    </div>
  );
}
