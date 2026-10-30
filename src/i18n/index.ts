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

/** 【APP25 任务1】形如 `goLan.saved` 的代码标识符（全项目字典漏配时兜底） */
const CODE_KEY_RE = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/;

/** 【APP25 任务1】代码键名 → 自然语言兜底：按最后一个后缀匹配，
 *  保证任何情况下都不会把 `xxx.yyy` 形式的代码字符串渲染到界面。 */
const KEY_SUFFIX_FALLBACK: Record<ResolvedLang, Record<string, string>> = {
  zh: {
    saved: "配置已保存",
    cleared: "已清空",
    copied: "已复制到剪贴板",
    imported: "已自动识别并填入配置",
    invalidconfig: "配置格式无效",
    added: "已添加",
    updated: "已更新",
    deleted: "已删除",
    started: "已启动",
    stopped: "已停止",
    error: "操作失败",
    failed: "操作失败",
    locked: "该功能尚未解锁",
  },
  en: {
    saved: "Configuration saved",
    cleared: "Cleared",
    copied: "Copied to clipboard",
    imported: "Configuration imported",
    invalidconfig: "Invalid configuration",
    added: "Added",
    updated: "Updated",
    deleted: "Deleted",
    started: "Started",
    stopped: "Stopped",
    error: "Operation failed",
    failed: "Operation failed",
    locked: "Feature locked",
  },
};

/** 代码键名兜底：未命中字典时按后缀翻译，绝不再把 key 原样吐出 */
function fallbackForKey(key: string, lang: ResolvedLang): string | undefined {
  if (!CODE_KEY_RE.test(key)) return undefined;
  const suffix = key.slice(key.lastIndexOf(".") + 1).toLowerCase();
  const hit = KEY_SUFFIX_FALLBACK[lang][suffix];
  if (hit) return hit;
  return lang === "zh" ? "操作已完成" : "Done";
}

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
  let out = DICT[resolved][key] ?? DICT.zh[key];
  if (out === undefined) {
    // 【APP25 任务1】防御拦截：字典漏配的 `xxx.yyy` 代码键名自动转为
    // 自然语言，绝不把带点号的代码标识符渲染给用户；普通文案原样返回。
    out = fallbackForKey(key, resolved) ?? key;
    console.warn(`[i18n] 缺少词条: ${key}`);
  }
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
