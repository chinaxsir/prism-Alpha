import { useEffect, useState, type ReactNode } from "react";
import { Check, Loader2, Lock, Sparkles } from "lucide-react";

import { FEATURE_LABEL, type Feature } from "@/pro/gating";
import type { Entitlement } from "@/api/ipc";
import { useProStore } from "@/stores/pro";
import { toast } from "@/components/ui/Toast";

/** 服务端 429 时从错误信息中解析 retry_after 秒数（容忍 JSON / 纯文本格式） */
function parseRetryAfter(message: string): number {
  if (!message) return 0;
  const explicit = message.match(/retry[_\s-]*after[^0-9]{0,12}(\d{1,5})/i);
  if (explicit) return parseInt(explicit[1], 10);
  const plain = message.match(/(\d{1,5})\s*(?:秒|seconds?|s)\b/i);
  if (plain) return parseInt(plain[1], 10);
  return 0;
}

const PLAN_LABEL: Record<string, string> = {
  free: "Free",
  pro: "Pro",
  team: "Team",
};

/** 展示当前方案：优先服务端 plan 字段（free/pro/team），回落到授权类型 */
function planLabel(e: Entitlement): string {
  if (e.plan && PLAN_LABEL[e.plan]) return PLAN_LABEL[e.plan];
  if (e.kind === "lifetime") return "终身买断";
  if (e.kind === "subscription") return "订阅";
  return "—";
}

function expiryText(e: Entitlement): string {
  if (e.kind === "lifetime" && !e.expiresAt) return "永久有效";
  if (!e.expiresAt) return "—";
  return new Date(e.expiresAt * 1000).toLocaleDateString();
}

/// 激活 Pro 弹窗：License Key + 邮箱（全平台统一；不提供商店内购）
export function ActivateProModal({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
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

  // License Key 激活（邮箱可选，激活时提交）
  const submitLicense = async () => {
    if (busy || counting || !licenseKey.trim()) return;
    if (email.trim() && !emailOk) return;
    setBusy(true);
    const ok = await activate(licenseKey.trim(), email.trim() || undefined);
    setBusy(false);
    if (ok) {
      toast.success("Pro 已激活，高级功能全部解锁");
      setActivated(useProStore.getState().entitlement);
      setLicenseKey("");
      setEmail("");
    } else {
      const wait = parseRetryAfter(error ?? "");
      if (wait > 0) setRetryAfter(wait);
      toast.error(
        wait > 0
          ? `激活尝试过于频繁，请 ${wait} 秒后重试`
          : (error ?? "激活失败，请检查 License Key 与邮箱")
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
              <h3 className="text-base font-semibold">激活成功</h3>
            </div>
            <div className="space-y-2.5 rounded-lg border border-white/5 bg-surface-hover px-4 py-3.5 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-gray-400">当前方案</span>
                <span className="font-medium text-gray-100">
                  {planLabel(activated)}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400">到期时间</span>
                <span className="font-medium tabular-nums text-gray-100">
                  {expiryText(activated)}
                </span>
              </div>
            </div>
            <button
              onClick={dismiss}
              className="w-full rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
            >
              完成
            </button>
          </>
        ) : (
          <>
            <div className="flex items-center gap-2">
              <Sparkles size={18} className="text-accent" />
              <h3 className="text-base font-semibold">激活授权</h3>
            </div>

            {/* License Key + 邮箱（可选） */}
            <div className="space-y-3">
              <div className="space-y-1.5">
                <label className="text-xs text-gray-400">License Key</label>
                <input
                  type="text"
                  value={licenseKey}
                  onChange={(e) => setLicenseKey(e.target.value)}
                  placeholder="ASKC-XXXX-XXXX-XXXX-XXXX"
                  autoComplete="off"
                  spellCheck={false}
                  className="w-full rounded-lg border border-white/5 bg-surface-hover px-4 py-2 font-mono text-sm outline-none focus:border-accent"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs text-gray-400">邮箱（可选）</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  autoComplete="email"
                  className="w-full rounded-lg border border-white/5 bg-surface-hover px-4 py-2 text-sm outline-none focus:border-accent"
                />
                {email.trim() && !emailOk && (
                  <p className="text-xs text-red-400">邮箱格式不正确</p>
                )}
              </div>
              <p className="text-xs text-gray-500">
                邮箱为可选，用于授权校验；若该 License Key 需邮箱验证，请填写购买时预留的邮箱。激活成功后本页将自动显示订阅信息。
              </p>
              <p className="text-[11px] text-gray-600">
                激活失败时请记下提示中的错误码，可在官网帮助中心按错误码查询具体原因。
              </p>
              <div className="flex justify-end gap-2">
                <button
                  onClick={dismiss}
                  className="rounded-lg px-4 py-2 text-sm text-gray-400 hover:text-gray-200"
                >
                  取消
                </button>
                <button
                  onClick={submitLicense}
                  disabled={
                    busy ||
                    counting ||
                    !licenseKey.trim() ||
                    (email.trim() !== "" && !emailOk)
                  }
                  className="flex items-center gap-1 rounded-lg bg-accent px-5 py-2 text-sm transition-colors hover:bg-accent-hover disabled:opacity-50"
                >
                  {busy && <Loader2 size={14} className="animate-spin" />}
                  {counting ? `请 ${retryAfter} 秒后重试` : "激活"}
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
  const unlocked = useProStore((s) => s.unlocked);
  const ready = useProStore((s) => s.ready);
  const [showActivate, setShowActivate] = useState(false);

  if (unlocked) return <>{children}</>;

  // 启动瞬间（授权状态尚未读出）先保持可用，避免闪烁误锁
  if (!ready) return <>{children}</>;

  return (
    <>
      <div className="flex flex-col items-center justify-center gap-2.5 rounded-xl border border-white/5 bg-surface-card px-5 py-6 text-center">
        <Lock size={18} className="text-accent" />
        <p className="text-sm text-gray-300">{FEATURE_LABEL[feature]}为 Pro 功能</p>
        <button
          onClick={() => setShowActivate(true)}
          className="rounded-lg bg-accent px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover"
        >
          激活 Pro
        </button>
      </div>
      <ActivateProModal
        open={showActivate}
        onClose={() => setShowActivate(false)}
      />
    </>
  );
}
