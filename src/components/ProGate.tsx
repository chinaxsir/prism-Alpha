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

/** APK-3 任务2：激活错误码 → 错误卡片文案 key（与《软件激活（客户端提示）》1:1 逐字对齐） */
const LICENSE_ERROR_MAP: Record<
  string,
  { code: string; titleKey: string; detailKey: string }
> = {
  invalid_input: {
    code: "invalid_input",
    titleKey: "pro.err.invalid_input.title",
    detailKey: "pro.err.invalid_input.detail",
  },
  activation_failed: {
    code: "activation_failed",
    titleKey: "pro.err.activation_failed.title",
    detailKey: "pro.err.activation_failed.detail",
  },
  seat_limit_reached: {
    code: "seat_limit_reached",
    titleKey: "pro.err.seat_limit_reached.title",
    detailKey: "pro.err.seat_limit_reached.detail",
  },
  activation_throttled: {
    code: "activation_throttled",
    titleKey: "pro.err.activation_throttled.title",
    detailKey: "pro.err.activation_throttled.detail",
  },
  server_error: {
    code: "server_error",
    titleKey: "pro.err.server_error.title",
    detailKey: "pro.err.server_error.detail",
  },
  // 【APP6 任务4】服务端具体原因精准映射（license.rs map_activation_error）
  invalid_key: {
    code: "invalid_key",
    titleKey: "pro.err.invalid_key.title",
    detailKey: "pro.err.invalid_key.detail",
  },
  email_mismatch: {
    code: "email_mismatch",
    titleKey: "pro.err.email_mismatch.title",
    detailKey: "pro.err.email_mismatch.detail",
  },
  license_expired: {
    code: "license_expired",
    titleKey: "pro.err.license_expired.title",
    detailKey: "pro.err.license_expired.detail",
  },
  license_blocked: {
    code: "license_blocked",
    titleKey: "pro.err.license_blocked.title",
    detailKey: "pro.err.license_blocked.detail",
  },
};

/** 从后端错误字符串提取标准错误码并映射到错误卡片文案。
 *  后端约定（见 license.rs）：
 *  - "err_code:{code}"（非 429 失败）
 *  - "rate_limited:{秒数}:{code}"（429 限流）
 *  - "err_raw:{服务端原文}"（【APP6 任务4】无法归入已知类别时透传原文） */
function parseLicenseError(
  message: string
): { code: string; titleKey: string; detailKey: string; rawTitle?: string } | null {
  if (!message) return null;
  const errCode = message.match(/err_code:([a-z_]+)/i);
  const rate = message.match(/rate_limited:\d+:([a-z_]+)/i);
  const code = errCode?.[1] ?? rate?.[1] ?? null;
  if (code) {
    return (
      LICENSE_ERROR_MAP[code] ?? {
        code,
        titleKey: "",
        detailKey: "",
        rawTitle: message.replace(/^err_code:/, ""),
      }
    );
  }
  // err_raw 透传：直接展示服务端返回的具体原因（已含 HTTP 状态）
  const raw = message.match(/^err_raw:(.+)$/s);
  if (raw?.[1]) {
    return { code: "err_raw", titleKey: "", detailKey: "", rawTitle: raw[1].trim() };
  }
  return null;
}

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
  const [licenseKey, setLicenseKey] = useState("");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [retryAfter, setRetryAfter] = useState(0);
  const [activated, setActivated] = useState<Entitlement | null>(null);
  // 激活失败的结构化错误卡片（错误码 + 加粗标题 + 详细说明，APK-3 任务2）
  const [parsedError, setParsedError] = useState<{
    code: string;
    title: string;
    detail: string;
  } | null>(null);

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

  /** 【APP23 任务2】前端二次兜底脱敏：即使后端漏网，也强制抹除任何
   *  http(s):// URL 与 "for url (...)" 片段——断网激活时 reqwest 原始报错
   *  形如 "error sending request for url (https://.../api/license/activate)"，
   *  严禁把后端验证接口地址暴露给用户。 */
  const cleanErrorMsg = (raw: unknown): string => {
    const s = String(raw ?? "")
      .replace(/^Error:\s*/i, "")
      .replace(/for url \([^)]*\)/gi, "")
      .replace(/https?:\/\/[^\s)"']+/gi, "")
      .replace(/\s+/g, " ")
      .trim();
    if (
      !s ||
      /error sending request|failed to fetch|networkerror|network is unreachable|connection refused|dns error|no route to host/i.test(
        s
      )
    ) {
      return t("pro.networkFailed");
    }
    return s;
  };

  // License Key 激活：服务端强制「Key + 注册邮箱」联合校验，两者均为必填
  const submitLicense = async () => {
    if (busy || counting) return;
    // 【APP21 任务1】激活相关的所有报错（含本地校验）只在弹窗内部以错误
    // 卡片展示，严禁调用 toast.error 触发页面顶部全局红色横幅（图1 空白
    // 红叉黑框的根因之一）。
    if (!licenseKey.trim() || !email.trim()) {
      // 本地必填/格式校验：缺项绝不打服务端，避免白白触发 3 次防爆破锁定
      setParsedError({
        code: "invalid_input",
        title: t("pro.requiredMissing"),
        detail: "",
      });
      return;
    }
    if (!emailOk) {
      setParsedError({
        code: "invalid_input",
        title: t("pro.emailInvalid"),
        detail: "",
      });
      return;
    }
    setBusy(true);
    setParsedError(null);
    const ok = await activate(licenseKey.trim(), email.trim());
    setBusy(false);
    if (ok) {
      toast.success(t("pro.activatedToast"));
      setActivated(useProStore.getState().entitlement);
      setLicenseKey("");
      setEmail("");
    } else {
      // 必须读 store 里的最新错误——本闭包捕获的 error 是激活前的旧值(null)，
      // 直接用它会丢失服务端返回的具体错误原因/错误码。
      const rawError = useProStore.getState().error ?? "";
      const wait = parseRetryAfter(rawError);
      if (wait > 0) setRetryAfter(wait);
      // 【APP23 任务2】进入文案前先做前端脱敏（剥离 URL / 网络错误原文）
      const freshError = cleanErrorMsg(rawError);
      // 【APP21 任务1】无论是否命中标准错误码，错误一律渲染到弹窗内错误
      // 卡片（输入框下方 text-red-400 区域），绝不触发顶部全局 Toast 横幅。
      const mapped = parseLicenseError(rawError);
      const mappedCard = mapped
        ? {
            code: mapped.code,
            title: cleanErrorMsg(mapped.rawTitle ?? t(mapped.titleKey)),
            detail: mapped.detailKey ? t(mapped.detailKey) : "",
          }
        : null;
      setParsedError(
        mappedCard ?? {
          code: "activation_failed",
          title: freshError || t("pro.activateFailed"),
          detail: wait > 0 ? t("pro.rateLimited", { secs: wait }) : "",
        }
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

            {/* 【APP22 任务1】弹窗内不再渲染任何到期/解绑提示框：
                报错仅在点击「激活」后以官网原始错误信息卡片展示 */}

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
              {parsedError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 space-y-1.5 text-left">
                  <div className="flex items-center gap-2 flex-wrap">
                    <code className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 font-mono text-[11px]">
                      {parsedError.code}
                    </code>
                    <span className="font-semibold text-xs text-red-200">
                      {parsedError.title}
                    </span>
                  </div>
                  <p className="text-[11px] text-red-200/80 leading-relaxed">
                    {parsedError.detail}
                  </p>
                </div>
              )}
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
  title,
  description,
  children,
}: {
  /** 门控的功能标识（保留用于埋点/扩展；文案已统一，APP-5 任务4） */
  feature: Feature;
  /** 自定义标题（缺省用统一标题「解锁 Prism Pro 全场景智联」） */
  title?: string;
  /** 自定义说明文案（缺省用统一说明） */
  description?: string;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  const unlocked = useProStore((s) => s.unlocked);
  const ready = useProStore((s) => s.ready);

  if (unlocked) return <>{children}</>;

  // 启动瞬间（授权状态尚未读出）先保持可用，避免闪烁误锁
  if (!ready) return <>{children}</>;

  // 【APP-4 任务3】未激活仅展示静默锁定卡：不提供任何激活按钮/弹窗，
  // 全 APP 唯一激活入口为「设置 → Prism Pro」
  return (
    <div className="flex flex-col items-center justify-center gap-2.5 rounded-xl border border-border bg-surface-card px-5 py-6 text-center opacity-60 select-none">
      <Lock size={18} className="text-accent" />
      <p className="text-sm text-gray-300">
        {title ?? t("pro.featureLocked")}
      </p>
      <p className="max-w-md text-xs leading-relaxed text-gray-500">
        {description ?? t("pro.gate.desc")}
      </p>
    </div>
  );
}
