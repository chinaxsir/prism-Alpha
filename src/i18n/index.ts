import { useCallback } from "react";

import { usePrefsStore, type Language } from "@/stores/prefs";
import common from "./parts/common";
import dashboard from "./parts/dashboard";
import proxies from "./parts/proxies";
import analytics from "./parts/analytics";
import subscription from "./parts/subscription";
import settings from "./parts/settings";

export type { Language } from "@/stores/prefs";
export type ResolvedLang = "zh" | "en";

/** 词典分片（各业务域独立维护，便于协作与增量扩展） */
const PARTS = [common, dashboard, proxies, analytics, subscription, settings] as const;

const zh: Record<string, string> = Object.assign({}, ...PARTS.map((p) => p.zh));
const en: Record<string, string> = Object.assign({}, ...PARTS.map((p) => p.en));

const DICT: Record<ResolvedLang, Record<string, string>> = { zh, en };

/** 语言偏好 → 实际语言：system 时按 navigator.language 判定（zh 开头为中文，否则英文） */
export function resolveLang(lang: Language): ResolvedLang {
  if (lang === "zh" || lang === "en") return lang;
  const nav = typeof navigator !== "undefined" ? navigator.language || "" : "";
  return nav.toLowerCase().startsWith("zh") ? "zh" : "en";
}

/**
 * 翻译函数：取当前语言词条，缺失时回退中文词条，再回退 key 本身。
 * vars 用于插值，如 t("pro.retryIn", { secs: 30 })。
 */
export function translate(
  key: string,
  lang: Language = "system",
  vars?: Record<string, string | number>,
): string {
  const resolved = resolveLang(lang);
  let out = DICT[resolved][key] ?? DICT.zh[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      out = out.replace(new RegExp(`\\{${k}\\}`, "g"), String(v));
    }
  }
  return out;
}

/** 轻量响应式 Hook：语言偏好变化时全 App 立即重渲染并切换文案 */
export function useTranslation() {
  const lang = usePrefsStore((s) => s.language);
  const t = useCallback(
    (key: string, vars?: Record<string, string | number>) =>
      translate(key, lang, vars),
    [lang],
  );
  return { t, lang, resolved: resolveLang(lang) };
}

/** 供非组件场景（如错误处理）直接调用 */
export const t = (key: string, vars?: Record<string, string | number>) =>
  translate(key, usePrefsStore.getState().language, vars);

export { DICT };
