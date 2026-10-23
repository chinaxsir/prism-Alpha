import { create } from "zustand";

/** 语言偏好：跟随系统 / 简体中文 / English */
export type Language = "system" | "zh" | "en";
/** 外观偏好：跟随系统 / 深色 / 浅色 */
export type ThemePref = "system" | "dark" | "light";
/** 解析后的实际外观 */
export type ResolvedTheme = "dark" | "light";

interface PrefsState {
  language: Language;
  theme: ThemePref;
  setLanguage: (l: Language) => void;
  setTheme: (t: ThemePref) => void;
}

/** 系统当前外观（matchMedia 不可用时回退 dark） */
export function systemTheme(): ResolvedTheme {
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  } catch {
    return "dark";
  }
}

/** 偏好 → 实际外观 */
export function resolveTheme(pref: ThemePref): ResolvedTheme {
  if (pref === "dark" || pref === "light") return pref;
  return systemTheme();
}

/** 主题色：同步到 <meta name="theme-color"> 供 iOS/Android 状态栏底色使用 */
const THEME_COLORS = { dark: "#0B0D13", light: "#F4F5F9" } as const;

/** 把实际外观写入 html（data-theme 供 CSS 变量选择，dark 类供 Tailwind dark: 变体）
 *  APP-7 任务2：同步设置 color-scheme 与 theme-color meta，
 *  浅色模式下 iOS/Android 状态栏时间/信号文字自动变为深色，不再看不清。 */
export function applyTheme(pref: ThemePref): ResolvedTheme {
  const resolved = resolveTheme(pref);
  const root = document.documentElement;
  root.setAttribute("data-theme", resolved);
  root.classList.toggle("dark", resolved === "dark");
  // CSS color-scheme：浏览器原生控件（滚动条/表单）+ WebView 状态栏适配
  root.style.colorScheme = resolved;
  // <meta name="theme-color">：PWA/WebView 状态栏底色
  const bg = THEME_COLORS[resolved];
  let meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  if (!meta) {
    meta = document.createElement("meta");
    meta.setAttribute("name", "theme-color");
    document.head.appendChild(meta);
  }
  meta.setAttribute("content", bg);
  return resolved;
}

export const usePrefsStore = create<PrefsState>((set) => ({
  language: "system",
  theme: "system",
  setLanguage: (language) => set({ language }),
  setTheme: (theme) => {
    applyTheme(theme);
    set({ theme });
  },
}));
