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

/**
 * 【v0.4.18 任务1】统一翻译 Rust 后端返回的中文错误/状态文案。
 * 仅当目标语言为 `en` 时做中英映射；`zh` 原样返回。
 * 覆盖 Dashboard 弹窗、Toast、节点页、订阅页共用的中文报错与状态描述。
 */
export function translateBackendMessage(
  raw: string | null | undefined,
  lang: ResolvedLang,
): string {
  if (!raw || lang !== "en") return raw ?? "";
  const replacements: Array<[string, string]> = [
    ["尚未导入订阅：请先在「订阅」页添加订阅", "No subscription imported: Please add a subscription on the 'Subs' page first"],
    ["请先在「订阅」页添加订阅", "Please add a subscription on the 'Subs' page first"],
    ["尚未导入订阅", "No subscription imported"],
    ["所有订阅均已停用，请先启用至少一个订阅", "All subscriptions are disabled. Please enable at least one subscription"],
    ["订阅内容未解析到任何节点或策略组", "No valid proxy nodes or groups found in subscription"],
    ["未找到可用节点，请先更新或导入订阅", "No available nodes found. Please update or import a subscription first"],
    ["内核正在运行或状态切换中", "Kernel is already running or switching state"],
    ["正在停止 VPN 内核...", "Stopping VPN kernel..."],
    ["VPN 内核启动成功", "VPN kernel started successfully"],
    ["无法读取共享配置文件", "Failed to read shared configuration file"],
    ["缺少配置", "Configuration missing"],
    ["本地代理端口未就绪", "Local proxy port is not ready"],
    ["请先启动代理以执行真实隧道 AI/流媒体解锁验证", "Please start the proxy first to run real-tunnel AI & streaming verification"],
    ["所有候选节点快筛均超时不可达", "All candidate nodes timed out during fast screening"],
    ["已有 Go AIM 检测任务在运行，请稍候", "A Go AIM inspection task is already running, please wait"],
    ["该内测授权已绑定其他设备", "This license is already bound to another device"],
    ["License Key 与邮箱不匹配，或授权已失效", "License Key does not match email, or license has expired"],
    ["激活失败", "Activation failed"],
    ["操作失败", "Operation Failed"],
    ["自动（等待测速）", "Auto (Pending Speedtest)"],
    ["未选择", "Not selected"],
    ["未测速", "Untested"],
    ["超时", "Timeout"],
    ["代理不可用", "Proxy Unavailable"],
  ];
  let out = raw;
  for (const [zh, en] of replacements) {
    if (out.includes(zh)) {
      out = out.split(zh).join(en);
    }
  }
  // 【ACP7 任务2】Go AIM 动态进度是后端拼接的中文长句（含实时数字），
  // 固定词条替换覆盖不到，必须用正则翻译（顺序：从最具体到最宽泛）。
  const aimRules: Array<[RegExp, string]> = [
    [
      /阶段一极速存活快筛开始，共 (\d+) 个节点/g,
      "Stage 1 fast screening started · $1 nodes",
    ],
    [
      /阶段一快筛 (\d+)\/(\d+)，存活 (\d+)/g,
      "Fast screening $1/$2 · $3 alive",
    ],
    [
      /节点「([^」]+)」完成检测：([A-Z_]+)/g,
      'Node "$1" checked: $2',
    ],
    [
      /检测完成，共 (\d+) 个节点参与评级；最优节点「([^」]+)」(\d+)ms/g,
      'Probe finished · $1 nodes rated · best "$2" $3 ms',
    ],
    [
      /检测完成，共 (\d+) 个节点参与评级/g,
      "Probe finished · $1 nodes rated",
    ],
    [
      /检测任务结束: status=([A-Z_]+)（([^）]*)）: (.*)/g,
      "Task ended: status=$1 ($2): $3",
    ],
    [
      /检测任务结束: status=([A-Z_]+), reason=(.*)/g,
      "Task ended: status=$1, reason=$2",
    ],
    [
      /最优节点: ([^,]+), score=(\d+), delay=(\d+)ms/g,
      "Best node: $1, score=$2, delay=$3 ms",
    ],
    [
      /锁定状态: mode=([^,]+), active_node=(.*)/g,
      "Locked: mode=$1, node=$2",
    ],
    [
      /正在检测[:：]\s*([^·]+?)·\s*已完成\s*(\d+)%/g,
      "Probing: $1 · $2%",
    ],
  ];
  for (const [re, en] of aimRules) {
    out = out.replace(re, en);
  }
  return out;
}
