import { useEffect, useState } from "react";
import {
  AppWindow,
  Check,
  Copy,
  Fingerprint,
  RefreshCw,
  ShieldAlert,
  Smartphone,
  Sparkles,
  X,
} from "lucide-react";
import { getVersion } from "@tauri-apps/api/app";
import clsx from "clsx";

import { getDeviceId, type EntitlementState } from "@/api/ipc";
import { useProStore } from "@/stores/pro";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";

/** 【APP-12 任务2.3】Prism Pro 授权详情弹窗
 *
 * 承载原 Settings 页 PRISM PRO 大表格的全部内容：
 * 设备 ID（带复制）/ APP 版本 / 当前方案 / 到期时间 / 设备名额 / 上次校验，
 * 底部保留「立即校验」「移除授权」两个操作。
 */

/** 授权状态 → 文案 key 与状态点颜色 */
const STATUS_META: Record<EntitlementState, { key: string; dot: string }> = {
  active: { key: "pro.status.active", dot: "bg-latency-good" },
  offline: { key: "pro.status.offline", dot: "bg-yellow-400" },
  expired: { key: "pro.status.expired", dot: "bg-latency-bad" },
  revoked: { key: "pro.status.revoked", dot: "bg-latency-bad" },
  inactive: { key: "pro.status.inactive", dot: "bg-gray-500" },
};

/** 服务端方案名 → 文案 key（API: free=试用版 / pro=Pro 订阅版 / team=终身买断版） */
const PLAN_LABEL: Record<string, string> = {
  free: "pro.plan.free",
  pro: "pro.plan.pro",
  team: "pro.plan.team",
};

function fmtDate(secs: number | null): string {
  if (!secs) return "—";
  return new Date(secs * 1000).toLocaleDateString();
}

/** Unix 秒 → "YYYY-MM-DD HH:mm"（本地时区），用于展示授权到期时间 */
export function fmtDateTime(secs: number | null): string {
  if (!secs) return "—";
  const d = new Date(secs * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** 距到期不足 3 天（用于「即将到期」黄色提醒） */
function expiringSoon(secs: number | null): boolean {
  if (!secs) return false;
  const diff = secs * 1000 - Date.now();
  return diff > 0 && diff < 3 * 86_400_000;
}

/** 状态标签：激活后按档位显示，未激活沿用状态文案 */
function statusTextT(
  plan: string | null,
  status: EntitlementState,
  t: (k: string) => string,
): string {
  if (status !== "active") return t(STATUS_META[status].key);
  if (plan === "team") return t("pro.status.teamPermanent");
  if (plan === "pro") return t("pro.status.proActive");
  if (plan === "free") return t("pro.status.freeActive");
  return t("pro.status.active");
}

/** 方案名展示（Settings 紧凑卡与授权详情弹窗共用） */
export function planTextT(
  plan: string | null,
  kind: string | null,
  t: (k: string) => string,
): string {
  if (plan && PLAN_LABEL[plan]) return t(PLAN_LABEL[plan]);
  if (kind === "lifetime") return t("pro.plan.lifetime");
  if (kind === "subscription") return t("pro.plan.subscription");
  return "—";
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function ProManageModal({ open, onClose }: Props) {
  const { t } = useTranslation();
  const entitlement = useProStore((s) => s.entitlement);
  const proBusy = useProStore((s) => s.busy);
  const refreshPro = useProStore((s) => s.refresh);
  const deactivatePro = useProStore((s) => s.deactivate);
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [appVersion, setAppVersion] = useState<string>("");
  // ipa-8：移除授权的组件内二次确认（iOS WKWebView 会静默拦截 window.confirm 返回 false）
  const [confirmDeactivate, setConfirmDeactivate] = useState(false);
  const [deactivating, setDeactivating] = useState(false);

  useEffect(() => {
    if (!open) return;
    getDeviceId()
      .then(setDeviceId)
      .catch((e) => console.error("get device id failed:", e));
    getVersion()
      .then(setAppVersion)
      .catch((e) => console.error("get app version failed:", e));
  }, [open]);

  const copyDeviceId = async () => {
    if (!deviceId) return;
    try {
      await navigator.clipboard.writeText(deviceId);
      toast.success(t("pro.deviceIdCopy"));
    } catch {
      toast.error(t("common.copyFailed"));
    }
  };

  // ipa-8：「立即校验」直连后端强制联网校验（verify_remote_forced），完成后给出明确 Toast
  const handleVerifyEntitlement = async () => {
    await refreshPro();
    const s = useProStore.getState();
    if (s.error) {
      const m = s.error;
      if (m.startsWith("rate_limited:")) {
        toast.error(
          t("pro.verifyTooFrequent", { secs: m.split(":")[1] ?? "30" }),
        );
      } else {
        toast.error(m);
      }
      return;
    }
    const st = s.entitlement.status;
    if (st === "active") {
      toast.success(t("pro.verifySuccess"));
    } else if (s.revokeReason === "unbound") {
      // IPA-3 任务2：设备被官网解绑 ≠ 授权到期，必须给出独立的重新激活引导
      toast.error(t("pro.verifyUnbound"));
    } else if (st === "expired" || st === "revoked") {
      toast.error(t("pro.verifyExpired"));
    } else if (st === "offline") {
      toast.info(t("pro.verifyOffline"));
    } else {
      toast.info(t("pro.verifyNone"));
    }
  };

  // ipa-8：移除授权——组件内二次确认替代 window.confirm：
  // 第一次点击进入红色确认态（3 秒未点击自动恢复），第二次点击才真正执行移除
  const handleDeactivate = async () => {
    if (!confirmDeactivate) {
      setConfirmDeactivate(true);
      setTimeout(() => setConfirmDeactivate(false), 3000);
      return;
    }
    setDeactivating(true);
    try {
      await deactivatePro();
      toast.success(t("pro.removedToast"));
      onClose();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setDeactivating(false);
      setConfirmDeactivate(false);
    }
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="max-h-[90vh] w-full max-w-md overflow-y-auto rounded-xl border border-border bg-surface-card"
        onClick={(e) => e.stopPropagation()}
      >
        {/* 标题栏：左侧标题，右侧状态点 + 关闭 */}
        <div className="flex items-center justify-between px-5 pb-3 pt-4">
          <div className="flex items-center gap-2">
            <Sparkles size={16} className="text-accent" />
            <h3 className="text-sm font-semibold">Prism Pro · 授权详情</h3>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 text-xs text-gray-400">
              <span
                className={`inline-block h-1.5 w-1.5 rounded-full ${STATUS_META[entitlement.status].dot}`}
              />
              {statusTextT(entitlement.plan, entitlement.status, t)}
            </span>
            <button
              onClick={onClose}
              className="rounded p-1 text-gray-400 transition-colors hover:bg-surface-hover hover:text-gray-200"
              aria-label="关闭"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {entitlement.status === "offline" && (
          <div className="flex items-start gap-2 border-y border-border bg-yellow-500/5 px-5 py-2.5 text-xs text-yellow-400">
            <ShieldAlert size={14} className="mt-0.5 shrink-0" />
            <span>{t("pro.offlineBanner")}</span>
          </div>
        )}

        {/* 已到期：红色提示行（后端已自动停止全部 Pro 功能） */}
        {entitlement.status === "expired" && (
          <div className="flex items-start gap-2 border-y border-border bg-latency-bad/5 px-5 py-2.5 text-xs text-latency-bad">
            <ShieldAlert size={14} className="mt-0.5 shrink-0" />
            <span>
              {t("pro.expiredAt", {
                time: fmtDateTime(entitlement.expiresAt),
              })}
            </span>
          </div>
        )}

        <div className="border-t border-border">
          {/* 设备 ID：激活时与服务端绑定，点击复制 */}
          <button
            onClick={copyDeviceId}
            className="flex w-full items-center justify-between gap-3 overflow-hidden border-b border-border px-5 py-3 text-left transition-colors hover:bg-surface-hover/40"
          >
            <span className="flex min-w-0 items-center gap-3">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-glass">
                <Fingerprint size={16} className="text-gray-400" />
              </span>
              <span className="min-w-0">
                <span className="block text-sm">{t("pro.deviceId")}</span>
                <span className="block text-[11px] text-gray-500">
                  {t("pro.deviceIdHint")}
                </span>
              </span>
            </span>
            <span className="flex min-w-0 items-center gap-1.5 font-mono text-[11px] text-gray-400">
              <span className="max-w-[150px] truncate">
                {deviceId ?? t("common.loading")}
              </span>
              <Copy size={12} className="shrink-0 text-gray-500" />
            </span>
          </button>

          {/* APP 版本：当前安装的 Prism 版本号 */}
          <DetailRow
            icon={<AppWindow size={16} className="text-gray-400" />}
            title={t("pro.appVersion")}
            value={appVersion ? `v${appVersion}` : "—"}
          />
          <DetailRow
            icon={<Sparkles size={16} className="text-accent" />}
            iconBg="bg-accent/10"
            title={t("pro.currentPlan")}
            value={planTextT(entitlement.plan, entitlement.kind, t)}
          />
          <DetailRow
            icon={<Check size={16} className="text-gray-400" />}
            title={t("pro.expiry")}
            value={
              <span className="flex items-center gap-1.5">
                {entitlement.plan === "team" ||
                (entitlement.kind === "lifetime" && !entitlement.expiresAt)
                  ? t("pro.permanent")
                  : fmtDateTime(entitlement.expiresAt)}
                {expiringSoon(entitlement.expiresAt) && (
                  <span className="text-[11px] text-yellow-400">
                    {t("pro.expiringSoon")}
                  </span>
                )}
              </span>
            }
          />
          {entitlement.maxSeats != null && (
            <DetailRow
              icon={<Smartphone size={16} className="text-gray-400" />}
              title={t("pro.seats")}
              value={`${entitlement.usedSeats ?? "?"} / ${entitlement.maxSeats}`}
            />
          )}
          <DetailRow
            icon={<RefreshCw size={16} className="text-gray-400" />}
            title={t("pro.lastVerify")}
            value={fmtDate(entitlement.lastVerifiedAt)}
          />
        </div>

        {/* 底部操作：立即校验 / 移除授权 */}
        <div className="flex gap-2 px-5 py-4">
          <button
            onClick={handleVerifyEntitlement}
            disabled={proBusy}
            className="flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-surface-hover px-3 py-2 text-xs transition-colors hover:bg-glass-strong disabled:opacity-50"
          >
            <RefreshCw size={12} className={proBusy ? "animate-spin" : ""} />
            {proBusy ? t("pro.licensingBusy") : t("pro.verifyNow")}
          </button>
          <button
            onClick={handleDeactivate}
            disabled={deactivating}
            className={clsx(
              "flex-1 rounded-lg px-3 py-2 text-xs transition-colors disabled:opacity-50",
              confirmDeactivate
                ? "bg-latency-bad/20 text-latency-bad hover:bg-latency-bad/30"
                : "bg-surface-hover text-gray-400 hover:bg-latency-bad/20 hover:text-latency-bad"
            )}
          >
            {confirmDeactivate ? t("pro.removeConfirm") : t("pro.remove")}
          </button>
        </div>
      </div>
    </div>
  );
}

/// 授权详情行：图标 + 标题 + 右侧值
function DetailRow({
  icon,
  iconBg = "bg-glass",
  title,
  value,
}: {
  icon: React.ReactNode;
  iconBg?: string;
  title: string;
  value: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border px-5 py-3 last:border-b-0">
      <span className="flex min-w-0 items-center gap-3">
        <span
          className={clsx(
            "flex h-7 w-7 shrink-0 items-center justify-center rounded-md",
            iconBg
          )}
        >
          {icon}
        </span>
        <span className="text-sm">{title}</span>
      </span>
      <span className="min-w-0 text-right text-xs text-gray-400">{value}</span>
    </div>
  );
}
