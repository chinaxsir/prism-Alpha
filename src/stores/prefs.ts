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

/** 把实际外观写入 html（data-theme 供 CSS 变量选择，dark 类供 Tailwind dark: 变体） */
export function applyTheme(pref: ThemePref): ResolvedTheme {
  const resolved = resolveTheme(pref);
  const root = document.documentElement;
  root.setAttribute("data-theme", resolved);
  root.classList.toggle("dark", resolved === "dark");
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
