import { useEffect, useState } from "react";
import { create } from "zustand";
import { CheckCircle2, Info, XCircle } from "lucide-react";
import clsx from "clsx";

type ToastType = "success" | "error" | "info";

interface ToastItem {
  id: number;
  type: ToastType;
  message: string;
}

interface ToastState {
  toasts: ToastItem[];
  push: (type: ToastType, message: string) => void;
  dismiss: (id: number) => void;
}

let nextId = 1;

/// 兜底脱敏：任何 toast 消息都不得出现内核商标字样
const clean = (message: string) => message.replace(/sing-?box|libbox/gi, "内核");

export const useToast = create<ToastState>((set) => ({
  toasts: [],
  push: (type, message) => {
    // 【APP21 任务1】空文本守卫：消息为空 / 纯空白时直接丢弃，绝不渲染
    // 顶部「空白红叉黑框」（图1 激活报错上方出现空白红色横幅的根因）。
    const text = clean(message);
    if (!text.trim()) return;
    const id = nextId++;
    set((s) => ({ toasts: [...s.toasts, { id, type, message: text }] }));
  },
  dismiss: (id) =>
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));

/// 全局 toast API：toast.success("...") / toast.error("...") / toast.info("...")
export const toast = {
  success: (message: string) => useToast.getState().push("success", message),
  error: (message: string) => useToast.getState().push("error", message),
  info: (message: string) => useToast.getState().push("info", message),
};

export default function ToastViewport() {
  const toasts = useToast((s) => s.toasts);

  return (
    // 【APP-4 任务4.2】顶部安全区偏移：iPhone 刘海屏/灵动岛下不遮挡状态栏
    <div className="fixed top-[calc(env(safe-area-inset-top,24px)+12px)] inset-x-4 md:inset-x-auto md:right-4 md:w-80 z-50 space-y-2">
      {/* 【APP21 任务1】渲染层双保险：空消息绝不渲染（防历史脏数据入队） */}
      {toasts
        .filter((t) => t.message.trim().length > 0)
        .map((t) => (
          <ToastCard key={t.id} item={t} />
        ))}
    </div>
  );
}

function ToastCard({ item }: { item: ToastItem }) {
  const dismiss = useToast((s) => s.dismiss);
  const [visible, setVisible] = useState(false);

  // 进场动画 + 3 秒自动消失
  useEffect(() => {
    const enter = requestAnimationFrame(() => setVisible(true));
    const hideTimer = setTimeout(() => setVisible(false), 2800);
    const removeTimer = setTimeout(() => dismiss(item.id), 3000);
    return () => {
      cancelAnimationFrame(enter);
      clearTimeout(hideTimer);
      clearTimeout(removeTimer);
    };
  }, [dismiss, item.id]);

  const success = item.type === "success";
  const info = item.type === "info";

  return (
    <div
      className={clsx(
        "flex items-start gap-2 rounded-lg border bg-surface-card px-4 py-3 text-sm shadow-lg transition-all duration-200",
        success
          ? "border-accent/50"
          : info
            ? "border-border-strong"
            : "border-latency-bad/50",
        visible ? "opacity-100 translate-y-0" : "opacity-0 -translate-y-2"
      )}
    >
      {success ? (
        <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-accent" />
      ) : info ? (
        <Info size={16} className="mt-0.5 shrink-0 text-gray-400" />
      ) : (
        <XCircle size={16} className="mt-0.5 shrink-0 text-latency-bad" />
      )}
      {/* 【APP21 任务1】显式指定浅色文字：防止继承深色文字导致黑底黑字看不见 */}
      <span className="break-all text-slate-100 font-medium">{item.message}</span>
    </div>
  );
}
