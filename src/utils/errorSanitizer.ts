/**
 * 前端错误脱敏：把后端 / 内核 / 系统原始报错转换为用户可读文案。
 *
 * 原则：
 * 1. 先匹配已知业务错误（VPN 权限、未导入订阅、授权校验、设备席位、网络超时）；
 * 2. 命中任何技术特征（源码路径、堆栈、内核实现细节）时强制替换为通用商业文案；
 * 3. 其余文本原样透传，交由页面自己的业务映射处理。
 */

export type UiErrorLang = "zh" | "en";

export interface SanitizedUiError {
  title: string;
  message: string;
  isPermissionGuide?: boolean;
}

function toText(raw: unknown): string {
  if (raw == null) return "";
  if (typeof raw === "string") return raw;
  if (raw instanceof Error) return raw.message || String(raw);
  try {
    return String(raw);
  } catch {
    return "";
  }
}

function matches(text: string, hints: string[]): boolean {
  const lower = text.toLowerCase();
  return hints.some((hint) => lower.includes(hint.toLowerCase()));
}

const VPN_PERMISSION_HINTS = [
  "nevnperrordomain",
  "permission denied",
  "code=5",
  "user denied",
  "vpn 权限",
  "vpn permission",
  "vpnservice",
  "configuration read write failed",
  "configuration is invalid",
  "not allowed to configure",
];

const NO_SUBSCRIPTION_HINTS = [
  "尚未导入订阅",
  "未导入订阅",
  "请先导入订阅",
  "no subscription",
  "no subscriptions",
  "subscription not found",
];

const LICENSE_HINTS = [
  "invalid_key",
  "email_mismatch",
  "activation_failed",
  "license key",
  "授权码",
  "邮箱不匹配",
  "account email",
];

const SEAT_HINTS = [
  "seat_limit_reached",
  "seat limit",
  "device limit",
  "no seats",
  "席位",
  "设备数已达",
  "设备名额",
];

const NETWORK_HINTS = [
  "ipc-timeout",
  "timed out",
  "timeout",
  "网络超时",
  "连接超时",
  "network unreachable",
  "network error",
  "network connection failed",
];

const TECH_SIGNATURES = [
  "src-tauri",
  ".rs:",
  ".swift:",
  ".go:",
  ".ts:",
  "panicked",
  "backtrace",
  "nserror",
  "nevn",
  "domain=",
  "userinfo=",
  "sing-box",
  "singbox",
  "libbox",
  "decode config",
  "os error",
  "exit code",
  "error:",
  "exception",
  "/users/",
  "c:\\",
  "d:\\",
];

const TECH_ZH = ["源码", "堆栈"];

const GENERIC = {
  zh: {
    title: "启动遇到短暂异常",
    message:
      "网络服务未能完成启动，请稍候点击「启动」重试。详细排查信息已记录至「运行日志 → 内核」。",
  },
  en: {
    title: "Connection Issue",
    message:
      "The network service encountered a temporary issue while starting. Please tap Start to retry, or check Logs → Kernel for diagnostics.",
  },
} as const;

/** 是否包含不应展示给用户的技术实现痕迹 */
export function hasTechnicalLeak(raw: string): boolean {
  if (!raw) return false;
  const lower = raw.toLowerCase();
  if (TECH_SIGNATURES.some((sig) => lower.includes(sig))) return true;
  if (TECH_ZH.some((sig) => raw.includes(sig))) return true;
  return false;
}

/**
 * 将任意错误输入转成 UI 可展示的标题 + 正文。
 * 返回的 title 为空字符串表示「业务原文透传」，由页面自行加标题。
 */
export function sanitizeUiError(
  raw: unknown,
  lang: "zh" | "en",
): SanitizedUiError {
  const text = toText(raw).trim();
  const zh = lang === "zh";
  if (!text) return { title: "", message: "" };

  if (matches(text, VPN_PERMISSION_HINTS)) {
    return {
      title: zh ? "需要启用 VPN 配置权限" : "VPN Configuration Permission Required",
      message: zh
        ? "首次连接需要系统授权添加 VPN 配置。请再次点击「启动」，并在系统弹窗中选择「允许」以开启网络加速。"
        : "System authorization is required to add a VPN configuration on first use. Please tap Start again and select Allow in the system prompt.",
      isPermissionGuide: true,
    };
  }

  if (matches(text, NO_SUBSCRIPTION_HINTS)) {
    return {
      title: zh ? "尚未导入订阅" : "No Subscription Imported",
      message: zh
        ? "请先在「订阅」页添加订阅链接，再启动网络加速。"
        : "Please add a subscription on the Subs page first, then start the VPN.",
    };
  }

  if (matches(text, LICENSE_HINTS)) {
    return {
      title: zh ? "授权信息未通过验证" : "License Verification Failed",
      message: zh
        ? "授权码与邮箱不匹配、已过期或被停用，请核对后重试。"
        : "The license key does not match the email, or the license has expired or been disabled. Please verify and try again.",
    };
  }

  if (matches(text, SEAT_HINTS)) {
    return {
      title: zh ? "设备席位已达上限" : "Device Seat Limit Reached",
      message: zh
        ? "该授权允许的设备数已用完，请先解绑其他设备后再试。"
        : "All device seats for this license are in use. Please deactivate another device and try again.",
    };
  }

  if (matches(text, NETWORK_HINTS)) {
    return {
      title: zh ? "网络响应超时" : "Network Timeout",
      message: zh
        ? "网络请求未能及时完成，请检查网络后重试。"
        : "The network request timed out. Please check your connection and try again.",
    };
  }

  if (hasTechnicalLeak(text)) {
    return { ...GENERIC[lang] };
  }

  return { title: "", message: text };
}

/** 当前界面语言（读取 <html lang>，回落到系统语言） */
export function currentUiLang(): "zh" | "en" {
  if (typeof document !== "undefined") {
    const lang = document.documentElement.lang?.toLowerCase() ?? "";
    if (lang) return lang.startsWith("zh") ? "zh" : "en";
  }
  if (typeof navigator !== "undefined") {
    return navigator.language?.toLowerCase().startsWith("zh") ? "zh" : "en";
  }
  return "zh";
}

/** 仅需一行文案时的便捷入口（invoke 兜底 / toast） */
export function sanitizeUiErrorText(
  raw: unknown,
  lang: "zh" | "en" = currentUiLang(),
): string {
  return sanitizeUiError(raw, lang).message;
}
