import { useEffect, useState, type ReactNode } from "react";
import { Check, Loader2, Lock, Sparkles } from "lucide-react";

import { Feature } from "@/pro/gating";
import type { Entitlement } from "@/api/ipc";
import { useProStore } from "@/stores/pro";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";

/** 服务端 429 时从错误信息中解析 retry_after 秒数（容忍 JSON / 纯文本格式）。
 *  后端约定：错误字符串以 "rate_limited:{秒数}" 开头（见 license.rs activate）。 */
function parseRetryAfter(message: string): number {
  if (!message) return 0;
  const prefixed = message.match(/rate[_\s-]*limited[^0-9]{0,12}(\d{1,5})/i);
  if (prefixed) return parseInt(prefixed[1], 10);
  const explicit = message.match(/retry[_\s-]*after[^0-9]{0,12}(\d{1,5})/i);
  if (explicit) return parseInt(explicit[1], 10);
  const plain = message.match(/(\d{1,5})\s*(?:秒|seconds?|s)\b/i);
  if (plain) return parseInt(plain[1], 10);
  return 0;
}

/** 服务端方案名 → 文案 key（API: free=试用版 / pro=Pro 订阅版 / team=终身买断版） */
const PLAN_LABEL: Record<string, string> = {
  free: "pro.plan.free",
  pro: "pro.plan.pro",
  team: "pro.plan.team",
};

/** 门控功能名 → 文案 key */
const FEATURE_KEY: Record<Feature, string> = {
  [Feature.MultiSubscription]: "feature.multiSubscription",
  [Feature.Connections]: "feature.connections",
  [Feature.Rules]: "feature.rules",
  [Feature.GoAim]: "feature.goAim",
  [Feature.GoLan]: "feature.goLan",
  [Feature.GoCus]: "feature.goCus",
};

/** Unix 秒 → "YYYY-MM-DD HH:mm"（本地时区） */
function formatExpiry(secs: number): string {
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

/// 激活 Pro 弹窗：License Key + 邮箱（全平台统一；不提供商店内购）
export function ActivateProModal({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const activate = useProStore((s) => s.activate);
  const error = useProStore((s) => s.error);
  const [licenseKey, setLicenseKey] = useState("");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);
  const [activated, setActivated] = useState<Entitlement | null>(null);

  // 429 倒计时：每秒递减，归零后恢复按钮
  useEffect(() => {
    if (retryAfter <= 0) return;
    const timer = setTimeout(() => setRetryAfter((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(timer);
  }, [retryAfter]);

  if (!open) return null;

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  const counting = retryAfter > 0;

  /** 展示当前方案：优先服务端 plan 字段（free/pro/team），回落到授权类型 */
  const planText = (e: Entitlement): string => {
    if (e.plan && PLAN_LABEL[e.plan]) return t(PLAN_LABEL[e.plan]);
    if (e.kind === "lifetime") return t("pro.plan.lifetime");
    if (e.kind === "subscription") return t("pro.plan.subscription");
    return "—";
  };

  /** 到期时间文案：买断版永久有效（expires_at 为 null） */
  const expiryText = (e: Entitlement): string => {
    if (e.plan === "team" || (e.kind === "lifetime" && !e.expiresAt))
      return t("pro.permanent");
    if (!e.expiresAt) return "—";
    return formatExpiry(e.expiresAt);
  };

  // License Key 激活：服务端强制「Key + 注册邮箱」联合校验，两者均为必填
  const submitLicense = async () => {
    if (busy || counting) return;
    // 本地必填/格式校验：缺项绝不打服务端，避免白白触发 3 次防爆破锁定
    if (!licenseKey.trim() || !email.trim()) {
      toast.error(t("pro.requiredMissing"));
      return;
    }
    if (!emailOk) {
      toast.error(t("pro.emailInvalid"));
      return;
    }
    setBusy(true);
    const ok = await activate(licenseKey.trim(), email.trim());
    setBusy(false);
    if (ok) {
      toast.success(t("pro.activatedToast"));
      setActivated(useProStore.getState().entitlement);
      setLicenseKey("");
      setEmail("");
    } else {
      const wait = parseRetryAfter(error ?? "");
      if (wait > 0) setRetryAfter(wait);
      toast.error(
        wait > 0
          ? t("pro.rateLimited", { secs: wait })
          : (error ?? t("pro.activateFailed"))
      );
    }
  };

  // 关闭并复位成功态（倒计时保留，避免限流期内立即重试）
  const dismiss = () => {
    setActivated(null);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={dismiss}
    >
      <div
        className="max-h-[90vh] w-full max-w-sm space-y-5 overflow-y-auto rounded-xl bg-surface-card p-6"
        onClick={(e) => e.stopPropagation()}
      >
        {activated ? (
          <>
            <div className="flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-full bg-latency-good/15">
                <Check size={16} className="text-latency-good" />
              </span>
              <h3 className="text-base font-semibold">{t("pro.activateSuccess")}</h3>
            </div>
            <div className="space-y-2.5 rounded-lg border border-border bg-surface-hover px-4 py-3.5 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-gray-400">{t("pro.currentPlan")}</span>
                <span className="font-medium text-gray-100">
                  {planText(activated)}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">{t("pro.expiry")}</span>
                <span className="flex items-center gap-1.5 font-medium tabular-nums text-gray-100">
                  {expiryText(activated)}
                  {expiringSoon(activated.expiresAt) && (
                    <span className="text-[11px] font-normal text-yellow-400">
                      {t("pro.expiringSoon")}
                    </span>
                  )}
                </span>
              </div>
            </div>
            <button
              onClick={dismiss}
              className="w-full rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
            >
              {t("common.done")}
            </button>
          </>
        ) : (
          <>
            <div className="flex items-center gap-2">
              <Sparkles size={18} className="text-accent" />
              <h3 className="text-base font-semibold">{t("pro.activateTitle")}</h3>
            </div>

            {/* License Key + 注册邮箱（联合校验，均为必填） */}
            <div className="space-y-3">
              <div className="space-y-1.5">
                <label className="text-xs text-gray-400">{t("pro.licenseLabel")}</label>
                <input
                  type="text"
                  value={licenseKey}
                  onChange={(e) => setLicenseKey(e.target.value)}
                  placeholder={t("pro.licensePlaceholder")}
                  autoComplete="off"
                  spellCheck={false}
                  className="w-full rounded-lg border border-border bg-surface-hover px-4 py-2 font-mono text-sm outline-none focus:border-accent"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs text-gray-400">{t("pro.emailLabel")}</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder={t("pro.emailPlaceholder")}
                  autoComplete="email"
                  className="w-full rounded-lg border border-border bg-surface-hover px-4 py-2 text-sm outline-none focus:border-accent"
                />
                {email.trim() && !emailOk && (
                  <p className="text-xs text-red-400">{t("pro.emailInvalid")}</p>
                )}
              </div>
              <p className="text-xs text-gray-500">{t("pro.modalHint")}</p>
              <p className="text-[11px] text-gray-600">{t("pro.modalHint2")}</p>
              <div className="flex justify-end gap-2">
                <button
                  onClick={dismiss}
                  className="rounded-lg px-4 py-2 text-sm text-gray-400 hover:text-gray-200"
                >
                  {t("common.cancel")}
                </button>
                <button
                  onClick={submitLicense}
                  disabled={
                    busy ||
                    counting ||
                    !licenseKey.trim() ||
                    !email.trim() ||
                    !emailOk
                  }
                  className="flex items-center gap-1 rounded-lg bg-accent px-5 py-2 text-sm transition-colors hover:bg-accent-hover disabled:opacity-50"
                >
                  {busy && <Loader2 size={14} className="animate-spin" />}
                  {counting ? t("pro.retryIn", { secs: retryAfter }) : t("common.activate")}
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/**
 * Pro 门控（ipa-9 重构）：未授权时只渲染一张紧凑居中的引导卡，
 * 绝不渲染 children（严禁旧版「渲染完整子组件 + 高斯模糊 + 悬浮大锁遮罩」
 * 的实现——那会在长表单页撑出满屏模糊黑框，在窄卡片上导致元素溢出重叠）；
 * 已授权（active，服务端联网校验有效）时完全透明穿透。
 */
export default function ProGate({
  feature,
  children,
}: {
  feature: Feature;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  const unlocked = useProStore((s) => s.unlocked);
  const ready = useProStore((s) => s.ready);
  const [showActivate, setShowActivate] = useState(false);

  if (unlocked) return <>{children}</>;

  // 启动瞬间（授权状态尚未读出）先保持可用，避免闪烁误锁
  if (!ready) return <>{children}</>;

  return (
    <>
      <div className="flex flex-col items-center justify-center gap-2.5 rounded-xl border border-border bg-surface-card px-5 py-6 text-center">
        <Lock size={18} className="text-accent" />
        <p className="text-sm text-gray-300">
          {t("pro.featureLocked", { feature: t(FEATURE_KEY[feature]) })}
        </p>
        <button
          onClick={() => setShowActivate(true)}
          className="rounded-lg bg-accent px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover"
        >
          {t("pro.activatePro")}
        </button>
      </div>
      <ActivateProModal
        open={showActivate}
        onClose={() => setShowActivate(false)}
      />
    </>
  );
}
