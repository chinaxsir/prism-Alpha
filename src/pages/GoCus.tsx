import { useEffect, useMemo, useState } from "react";
import {
  Copy,
  Download,
  FileCode2,
  Loader2,
  Package,
  ShieldCheck,
  Trash2,
  Wand2,
} from "lucide-react";

import {
  deleteGoCusModule,
  generateOrGetCaUrl,
  getGoCusSettings,
  importGoCusModule,
  saveGoCusSettings,
  toggleGoCusModule,
  type CaInfo,
  type CusModule,
  type GoCusSettings,
} from "@/api/ipc";
import ProGate from "@/components/ProGate";
import Switch from "@/components/ui/Switch";
import Spinner from "@/components/ui/Spinner";
import EmptyState from "@/components/ui/EmptyState";
import { toast } from "@/components/ui/Toast";
import { Feature } from "@/pro/gating";
import { useTranslation } from "@/i18n";
import { useCoreStore } from "@/stores/core";

// ============================== 本地解析（仅展示用） ==============================

interface RewriteEntry {
  pattern: string;
  action: string;
  target?: string;
}

interface ScriptEntry {
  name: string;
  type: string;
  pattern: string;
  scriptPath: string;
}

/// 已识别的改写动作（QuantumultX url 语法的 action 集合，Surge 语法共用）
const REWRITE_ACTIONS = new Set([
  "reject",
  "reject-200",
  "reject-img",
  "reject-dict",
  "reject-array",
  "302",
  "307",
  "request-header",
  "response-header",
]);

// ============================== 【APP50 任务5】官方精选一键模板库 ==============================

/** 模板定义：content 为标准 sgmodule（#!name/#!desc + [Rule]/[URL Rewrite]）。
 *  导入走后端 import_go_cus_module：本地内容直接解析、按内容去重（重复导入
 *  为更新而非重复新增）、首个模块导入自动开启引擎、VPN 运行中自动热重载。 */
interface CusTemplate {
  key: string;
  nameKey: string;
  descKey: string;
  content: string;
}

const CUS_TEMPLATES: CusTemplate[] = [
  {
    key: "adblock",
    nameKey: "proxies.goCus.tpl.adblock.name",
    descKey: "proxies.goCus.tpl.adblock.desc",
    content: `#!name=🛡️ 去广告净化
#!desc=屏蔽主流广告/统计/埋点域名（谷歌/百度/腾讯/字节/快手/友盟等）
[Rule]
DOMAIN-SUFFIX,ad.com,REJECT
DOMAIN-SUFFIX,ads.google.com,REJECT
DOMAIN-SUFFIX,doubleclick.net,REJECT
DOMAIN-SUFFIX,googlesyndication.com,REJECT
DOMAIN-SUFFIX,google-analytics.com,REJECT
DOMAIN-SUFFIX,hm.baidu.com,REJECT
DOMAIN-SUFFIX,pos.baidu.com,REJECT
DOMAIN-SUFFIX,cpro.baidu.com,REJECT
DOMAIN-SUFFIX,e.qq.com,REJECT
DOMAIN-SUFFIX,gdt.qq.com,REJECT
DOMAIN-SUFFIX,bugly.qq.com,REJECT
DOMAIN-SUFFIX,umeng.com,REJECT
DOMAIN-SUFFIX,umengcloud.com,REJECT
DOMAIN-SUFFIX,miaozhen.com,REJECT
DOMAIN-SUFFIX,tanx.com,REJECT
DOMAIN-SUFFIX,pangolin-sdk-toutiao.com,REJECT
DOMAIN-SUFFIX,adkwai.com,REJECT
DOMAIN-SUFFIX,app-measurement.com,REJECT`,
  },
  {
    key: "ai",
    nameKey: "proxies.goCus.tpl.ai.name",
    descKey: "proxies.goCus.tpl.ai.desc",
    content: `#!name=🤖 AI 服务分流
#!desc=OpenAI/Claude/Gemini/Copilot/Cursor 等 AI 服务走代理
[Rule]
DOMAIN-SUFFIX,openai.com,PROXY
DOMAIN-SUFFIX,chatgpt.com,PROXY
DOMAIN-SUFFIX,oaistatic.com,PROXY
DOMAIN-SUFFIX,oaiusercontent.com,PROXY
DOMAIN-SUFFIX,anthropic.com,PROXY
DOMAIN-SUFFIX,claude.ai,PROXY
DOMAIN-SUFFIX,gemini.google.com,PROXY
DOMAIN-SUFFIX,bard.google.com,PROXY
DOMAIN-SUFFIX,generativelanguage.googleapis.com,PROXY
DOMAIN-SUFFIX,perplexity.ai,PROXY
DOMAIN-SUFFIX,cursor.sh,PROXY
DOMAIN-SUFFIX,copilot.microsoft.com,PROXY
DOMAIN-SUFFIX,grok.com,PROXY
DOMAIN-SUFFIX,x.ai,PROXY`,
  },
  {
    key: "media",
    nameKey: "proxies.goCus.tpl.media.name",
    descKey: "proxies.goCus.tpl.media.desc",
    content: `#!name=🎬 流媒体解锁
#!desc=Netflix/YouTube/Disney+/TikTok/Spotify/Twitch 等流媒体走代理
[Rule]
DOMAIN-SUFFIX,netflix.com,PROXY
DOMAIN-SUFFIX,netflix.net,PROXY
DOMAIN-SUFFIX,nflxvideo.net,PROXY
DOMAIN-SUFFIX,nflximg.net,PROXY
DOMAIN-SUFFIX,youtube.com,PROXY
DOMAIN-SUFFIX,googlevideo.com,PROXY
DOMAIN-SUFFIX,ytimg.com,PROXY
DOMAIN-SUFFIX,disneyplus.com,PROXY
DOMAIN-SUFFIX,bamgrid.com,PROXY
DOMAIN-SUFFIX,tiktok.com,PROXY
DOMAIN-SUFFIX,tiktokv.com,PROXY
DOMAIN-SUFFIX,tiktokcdn.com,PROXY
DOMAIN-SUFFIX,spotify.com,PROXY
DOMAIN-SUFFIX,scdn.co,PROXY
DOMAIN-SUFFIX,twitch.tv,PROXY
DOMAIN-SUFFIX,hbomax.com,PROXY`,
  },
  {
    key: "cnDirect",
    nameKey: "proxies.goCus.tpl.cnDirect.name",
    descKey: "proxies.goCus.tpl.cnDirect.desc",
    content: `#!name=⚡ 国内直连加速
#!desc=.cn 域名与国内主流站点、Apple/微软 CDN 直连
[Rule]
DOMAIN-SUFFIX,cn,DIRECT
DOMAIN-SUFFIX,baidu.com,DIRECT
DOMAIN-SUFFIX,qq.com,DIRECT
DOMAIN-SUFFIX,weixin.qq.com,DIRECT
DOMAIN-SUFFIX,taobao.com,DIRECT
DOMAIN-SUFFIX,tmall.com,DIRECT
DOMAIN-SUFFIX,jd.com,DIRECT
DOMAIN-SUFFIX,bilibili.com,DIRECT
DOMAIN-SUFFIX,hdslb.com,DIRECT
DOMAIN-SUFFIX,douyin.com,DIRECT
DOMAIN-SUFFIX,163.com,DIRECT
DOMAIN-SUFFIX,xiaomi.com,DIRECT
DOMAIN-SUFFIX,icloud-content.com,DIRECT
DOMAIN-SUFFIX,mzstatic.com,DIRECT
DOMAIN-SUFFIX,akadns.net,DIRECT
DOMAIN-SUFFIX,windowsupdate.com,DIRECT`,
  },
  {
    key: "privacy",
    nameKey: "proxies.goCus.tpl.privacy.name",
    descKey: "proxies.goCus.tpl.privacy.desc",
    content: `#!name=🧹 隐私头净化
#!desc=对主流站点删除 X-Forwarded-For 追踪请求头（当前仅 HTTP 明文生效）
# 注：QUIC(UDP/443) 降级需在系统防火墙层实现，sing-box 路由规则不承载；
# HTTPS 请求的 CONNECT 隧道为端到端加密，请求头改写无法注入。
[URL Rewrite]
^https?://([^/]*\\.)?google\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?youtube\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?facebook\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?instagram\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?x\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?reddit\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?wikipedia\\.org/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?github\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?stackoverflow\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?amazon\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?bing\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?baidu\\.com/ url request-header $(remove-X-Forwarded-For)`,
  },
];

function isRewriteSection(header: string): boolean {
  const h = header.trim().toLowerCase();
  return h === "[url rewrite]" || h === "[rewrite_local]" || h === "[rewrite]";
}

/** 提取指定区段（大小写不敏感）内的有效行，跳过注释与空行 */
function sectionLines(raw: string, match: (header: string) => boolean): string[] {
  const lines: string[] = [];
  let inside = false;
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const header = line.match(/^\[(.+)\]$/);
    if (header) {
      inside = match(header[1]);
      continue;
    }
    if (inside && !line.startsWith("#") && !line.startsWith(";")) {
      lines.push(line);
    }
  }
  return lines;
}

/**
 * 解析模块 rawContent 中的改写条目，支持两种语法：
 * a) QuantumultX：`<regex> url <action> [target]`（reject / 302 / 307 / header / script-*）
 * b) Surge / Shadowrocket：`<regex> <target|-> <302|307|reject...>`
 */
function parseRewritesForDisplay(raw: string): RewriteEntry[] {
  const out: RewriteEntry[] = [];
  for (const line of sectionLines(raw, isRewriteSection)) {
    const tokens = line.split(/\s+/);
    if (tokens.length < 3) continue;
    if (tokens[1] === "url") {
      // QuantumultX：action 固定在第 3 列，其后为可选目标
      out.push({
        pattern: tokens[0],
        action: tokens[2].toLowerCase(),
        target: tokens.slice(3).join(" ") || undefined,
      });
    } else {
      // Surge / Shadowrocket：action 在末列，第 2 列为目标（"-" 表示无目标）
      const action = tokens[tokens.length - 1].toLowerCase();
      if (!REWRITE_ACTIONS.has(action)) continue;
      out.push({
        pattern: tokens[0],
        action,
        target: tokens[1] === "-" ? undefined : tokens[1],
      });
    }
  }
  return out;
}

/** 解析 [mitm] 区段的 hostname 行：去 %APPEND%/%INSERT%、去 *. 前缀、去重 */
function parseMitmHosts(raw: string): string[] {
  const hosts: string[] = [];
  for (const line of sectionLines(raw, (h) => h.trim().toLowerCase() === "[mitm]")) {
    const m = line.match(/^hostname\s*=\s*(.+)$/i);
    if (!m) continue;
    const value = m[1].replace(/%(?:append|insert)%/gi, "");
    for (const part of value.split(",")) {
      let host = part.trim().replace(/^\*\./, "");
      if (!host) continue;
      if (!hosts.includes(host)) hosts.push(host);
    }
  }
  return hosts;
}

function fileNameOf(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx >= 0 ? path.slice(idx + 1) : path;
}

/**
 * 解析脚本条目：[Script] 区段（Surge / Loon 的 http-request / http-response / cron）
 * 以及改写区段中的 script-* 行（QX 的 script-request-body 等）。
 */
function parseScriptsForDisplay(raw: string): ScriptEntry[] {
  const out: ScriptEntry[] = [];

  for (const line of sectionLines(raw, (h) => h.trim().toLowerCase() === "[script]")) {
    const tokens = line.split(/\s+/);
    if (tokens.length < 2) continue;
    const type = tokens[0].toLowerCase();
    let pattern = "";
    const kvParts: string[] = [];
    for (const t of tokens.slice(1)) {
      if (!pattern && !t.includes("=")) pattern = t;
      else kvParts.push(t);
    }
    const kv = kvParts.join(" ");
    const scriptPath = kv.match(/script-path\s*=\s*([^,\s]+)/i)?.[1] ?? "";
    if (!scriptPath) continue;
    const tag = kv.match(/\btag\s*=\s*([^,\s]+)/i)?.[1];
    out.push({
      name: tag ?? fileNameOf(scriptPath),
      type,
      pattern,
      scriptPath,
    });
  }

  // script-* 改写行：<pattern> url script-xxx <path>
  for (const line of sectionLines(raw, isRewriteSection)) {
    const m = line.match(/^(\S+)\s+url\s+(script-[^\s]+)\s+(\S+)/i);
    if (!m) continue;
    out.push({
      name: fileNameOf(m[3]),
      type: m[2].toLowerCase(),
      pattern: m[1],
      scriptPath: m[3],
    });
  }

  return out;
}

// ============================== 徽章配色 ==============================

function rewriteBadgeClass(action: string): string {
  if (action.startsWith("reject")) return "bg-latency-bad/15 text-latency-bad";
  if (action === "302" || action === "307") return "bg-blue-500/15 text-blue-400";
  if (action.includes("header")) return "bg-purple-500/15 text-purple-400";
  if (action.startsWith("script-")) return "bg-accent/15 text-accent";
  return "bg-glass text-gray-400";
}

function scriptBadgeClass(type: string): string {
  if (type.includes("request")) return "bg-blue-500/15 text-blue-400";
  if (type.includes("response")) return "bg-purple-500/15 text-purple-400";
  if (type === "cron") return "bg-latency-medium/15 text-latency-medium";
  return "bg-glass text-gray-400";
}

// ============================== 页面 ==============================

const SUB_TABS = [
  { key: "modules", labelKey: "proxies.goCus.tab.modules" },
  { key: "rewrites", labelKey: "proxies.goCus.tab.rewrites" },
  { key: "mitm", labelKey: "proxies.goCus.tab.mitm" },
  { key: "scripts", labelKey: "proxies.goCus.tab.scripts" },
] as const;

type SubTabKey = (typeof SUB_TABS)[number]["key"];

/** Go Cus 引擎：覆写 / 改写 / MitM / 脚本（Pro 功能） */
export default function GoCus() {
  const { t } = useTranslation();
  // 【APP-10 任务4】首帧直出全局 store 缓存（App 启动已水合），
  // 消除引擎/MitM 开关切页闪烁；无缓存时回落 null 走原加载路径
  const [settings, setSettings] = useState<GoCusSettings | null>(
    () => useCoreStore.getState().goCusSettings,
  );
  const [loading, setLoading] = useState(
    () => useCoreStore.getState().goCusSettings == null,
  );
  const [subTab, setSubTab] = useState<SubTabKey>("modules");

  // 模块导入
  const [source, setSource] = useState("");
  const [importing, setImporting] = useState(false);
  // 【APP50 任务5】模板库一键导入的进行中标记（按模板 key）
  const [importingTpl, setImportingTpl] = useState<string | null>(null);
  // 【APP50 任务4】iOS WKWebView 静默拦截 window.confirm（恒返回 false），
  // 模块删除改用「二次点击确认」（3s 自动复位）
  const [confirmingDeleteId, setConfirmingDeleteId] = useState<string | null>(null);

  // CA
  const [ca, setCa] = useState<CaInfo | null>(null);
  const [caBusy, setCaBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getGoCusSettings()
      .then((s) => {
        if (!cancelled) setSettings(s);
        // 回写全局 store，保持后续切页首帧为最新值
        useCoreStore.getState().setGoCusSettings(s);
      })
      .catch((e) => toast.error(String(e)))
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  /** 整体保存 settings（乐观更新，失败回滚） */
  const persist = async (next: GoCusSettings) => {
    if (!settings) return;
    const prev = settings;
    setSettings(next);
    try {
      await saveGoCusSettings(next);
      // 保存成功即写回全局 store
      useCoreStore.getState().setGoCusSettings(next);
    } catch (e) {
      toast.error(String(e));
      setSettings(prev);
    }
  };

  const reload = async () => {
    try {
      const s = await getGoCusSettings();
      setSettings(s);
      useCoreStore.getState().setGoCusSettings(s);
    } catch (e) {
      toast.error(String(e));
    }
  };

  const handleImport = async () => {
    const src = source.trim();
    if (!src) {
      toast.error(t("proxies.goCus.err.emptySource"));
      return;
    }
    setImporting(true);
    try {
      const m = await importGoCusModule(src);
      toast.success(t("proxies.goCus.importSuccess", { name: m.name }));
      setSource("");
      await reload();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setImporting(false);
    }
  };

  /** 【APP50 任务5】一键导入官方模板：后端自动开启引擎（首个模块）并在
   *  VPN 运行中热重载；重复导入同一模板为更新（按内容去重） */
  const importTemplate = async (tpl: CusTemplate) => {
    setImportingTpl(tpl.key);
    try {
      const m = await importGoCusModule(tpl.content);
      toast.success(t("proxies.goCus.importSuccess", { name: m.name }));
      await reload();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setImportingTpl(null);
    }
  };

  const toggleModule = async (m: CusModule, enabled: boolean) => {
    if (!settings) return;
    const next: GoCusSettings = {
      ...settings,
      modules: settings.modules.map((x) =>
        x.id === m.id ? { ...x, enabled } : x
      ),
    };
    setSettings(next); // 乐观更新
    try {
      await toggleGoCusModule(m.id, enabled);
    } catch (e) {
      toast.error(String(e));
      setSettings(settings); // 回滚
    }
  };

  const removeModule = async (m: CusModule) => {
    // 【APP50 任务4】二次点击确认（iOS 无 window.confirm）
    if (confirmingDeleteId !== m.id) {
      setConfirmingDeleteId(m.id);
      window.setTimeout(
        () => setConfirmingDeleteId((cur) => (cur === m.id ? null : cur)),
        3000,
      );
      return;
    }
    setConfirmingDeleteId(null);
    try {
      await deleteGoCusModule(m.id);
      toast.success(t("proxies.goCus.moduleDeleted"));
      await reload();
    } catch (e) {
      toast.error(String(e));
    }
  };

  const loadCa = async () => {
    setCaBusy(true);
    try {
      const info = await generateOrGetCaUrl();
      setCa(info);
      if (info.created) toast.success(t("proxies.goCus.caGenerated"));
    } catch (e) {
      toast.error(String(e));
    } finally {
      setCaBusy(false);
    }
  };

  const copyText = async (text: string, okMsg: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(okMsg);
    } catch (e) {
      toast.error(String(e));
    }
  };

  // 启用模块聚合出的改写 / MitM 主机 / 脚本（仅展示）
  const rewrites = useMemo(
    () =>
      (settings?.modules ?? [])
        .filter((m) => m.enabled)
        .flatMap((m) =>
          parseRewritesForDisplay(m.rawContent).map((e) => ({
            ...e,
            module: m.name,
          }))
        ),
    [settings]
  );

  const mitmHosts = useMemo(
    () =>
      Array.from(
        new Set(
          (settings?.modules ?? [])
            .filter((m) => m.enabled)
            .flatMap((m) => parseMitmHosts(m.rawContent))
        )
      ),
    [settings]
  );

  const scripts = useMemo(
    () =>
      (settings?.modules ?? [])
        .filter((m) => m.enabled)
        .flatMap((m) =>
          parseScriptsForDisplay(m.rawContent).map((e) => ({
            ...e,
            module: m.name,
          }))
        ),
    [settings]
  );

  if (loading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner />
      </div>
    );
  }

  if (!settings) {
    return (
      <div className="rounded-2xl border border-border bg-surface-card p-5">
        <p className="py-6 text-center text-sm text-gray-500">
          {t("proxies.goCus.loadFailed")}
        </p>
      </div>
    );
  }

  return (
    <ProGate feature={Feature.GoCus}>
      <div className="space-y-4">
        {/* 引擎总开关 */}
        <div className="flex items-center justify-between rounded-2xl border border-border bg-surface-card p-5">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent/15">
              <Wand2 size={17} className="text-accent" />
            </span>
            <div>
              <h3 className="text-sm font-semibold text-gray-100">
                {t("proxies.goCus.engineTitle")}
              </h3>
              <p className="mt-0.5 text-xs text-gray-500">
                {t("proxies.goCus.engineDesc")}
              </p>
            </div>
          </div>
          <Switch
            checked={settings.enabled}
            onChange={(v) => persist({ ...settings, enabled: v })}
            title={t("proxies.goCus.engineSwitch")}
          />
        </div>

        {/* 子标签 */}
        <div className="flex rounded-lg border border-border bg-surface-hover p-1">
          {SUB_TABS.map((tabItem) => (
            <button
              key={tabItem.key}
              onClick={() => setSubTab(tabItem.key)}
              className={`flex-1 rounded-md px-3 py-1.5 text-sm transition-colors ${
                subTab === tabItem.key
                  ? "bg-accent text-white"
                  : "text-gray-400 hover:text-gray-200"
              }`}
            >
              {t(tabItem.labelKey)}
            </button>
          ))}
        </div>

        {/* ---------- 模块 ---------- */}
        {subTab === "modules" && (
          <div className="space-y-4">
            <div className="rounded-2xl border border-border bg-surface-card p-5">
              <h3 className="mb-1 text-sm font-semibold text-gray-100">
                {t("proxies.goCus.importTitle")}
              </h3>
              <p className="mb-3 text-xs text-gray-500">
                {t("proxies.goCus.importDesc")}
              </p>
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleImport()}
                  placeholder={t("proxies.goCus.importPlaceholder")}
                  spellCheck={false}
                  className="flex-1 rounded-lg border border-border bg-surface-hover px-3 py-2 text-sm outline-none focus:border-accent"
                />
                <button
                  onClick={handleImport}
                  disabled={importing}
                  className="flex items-center justify-center gap-1.5 rounded-lg bg-accent px-4 py-2 text-sm transition-colors hover:bg-accent-hover disabled:opacity-50"
                >
                  {importing ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <Download size={14} />
                  )}
                  {t("common.import")}
                </button>
              </div>
            </div>

            {/* 【APP50 任务5】官方精选一键模板库 */}
            <div className="rounded-2xl border border-border bg-surface-card p-5">
              <h3 className="mb-1 text-sm font-semibold text-gray-100">
                {t("proxies.goCus.templateLibTitle")}
              </h3>
              <p className="mb-3 text-xs text-gray-500">
                {t("proxies.goCus.templateLibDesc")}
              </p>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {CUS_TEMPLATES.map((tpl) => (
                  <div
                    key={tpl.key}
                    className="flex items-center justify-between gap-2 rounded-xl border border-border bg-surface-hover px-3 py-2.5"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-xs font-semibold text-gray-200">
                        {t(tpl.nameKey)}
                      </p>
                      <p className="mt-0.5 line-clamp-2 text-[11px] leading-4 text-gray-500">
                        {t(tpl.descKey)}
                      </p>
                    </div>
                    <button
                      onClick={() => void importTemplate(tpl)}
                      disabled={importingTpl === tpl.key}
                      className="flex shrink-0 items-center gap-1 rounded-lg bg-accent px-2.5 py-1.5 text-[11px] text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
                    >
                      {importingTpl === tpl.key ? (
                        <Loader2 size={12} className="animate-spin" />
                      ) : (
                        <Download size={12} />
                      )}
                      {t("proxies.goCus.templateImport")}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {settings.modules.length === 0 ? (
              <div className="rounded-2xl border border-border bg-surface-card">
                <EmptyState
                  icon={<Package size={28} />}
                  title={t("proxies.goCus.noModules")}
                  description={t("proxies.goCus.noModulesDesc")}
                />
              </div>
            ) : (
              <div className="space-y-3">
                {settings.modules.map((m) => (
                  <div
                    key={m.id}
                    className="rounded-2xl border border-border bg-surface-card p-5"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <h3 className="truncate text-sm font-semibold text-gray-100">
                            {m.name}
                          </h3>
                          <span
                            className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] ${
                              m.source.startsWith("http")
                                ? "bg-accent/15 text-accent"
                                : "bg-glass text-gray-400"
                            }`}
                          >
                            {m.source.startsWith("http")
                              ? t("proxies.goCus.remote")
                              : t("proxies.goCus.local")}
                          </span>
                        </div>
                        {m.desc && (
                          <p className="mt-0.5 truncate text-xs text-gray-500">
                            {m.desc}
                          </p>
                        )}
                        <p
                          className="mt-1 truncate font-mono text-[11px] text-gray-600"
                          title={m.source}
                        >
                          {m.source.startsWith("http") ? m.source : "local"}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <Switch
                          checked={m.enabled}
                          onChange={(v) => toggleModule(m, v)}
                          title={
                            m.enabled
                              ? t("proxies.goCus.disableModule")
                              : t("proxies.goCus.enableModule")
                          }
                        />
                        <button
                          onClick={() => removeModule(m)}
                          title={
                            confirmingDeleteId === m.id
                              ? t("proxies.goCus.confirmDeleteAgain")
                              : t("proxies.goCus.deleteModule")
                          }
                          className={`rounded p-1.5 transition-colors ${
                            confirmingDeleteId === m.id
                              ? "bg-red-500/20 text-latency-bad ring-1 ring-red-500/40"
                              : "text-gray-500 hover:text-latency-bad"
                          }`}
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </div>
                    <div className="mt-3 grid grid-cols-4 gap-2">
                      {[
                        { label: t("metric.rules"), value: m.stats.rules },
                        {
                          label: t("proxies.goCus.tab.rewrites"),
                          value: m.stats.rewrites,
                        },
                        {
                          label: t("proxies.goCus.tab.scripts"),
                          value: m.stats.scripts,
                        },
                        {
                          label: t("proxies.goCus.tab.mitm"),
                          value: m.stats.mitmHosts,
                        },
                      ].map((s) => (
                        <div
                          key={s.label}
                          className="rounded-lg bg-surface-hover px-2 py-1.5 text-center"
                        >
                          <p className="text-sm font-semibold tabular-nums text-gray-200">
                            {s.value}
                          </p>
                          <p className="text-[11px] text-gray-500">{s.label}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ---------- 改写 ---------- */}
        {subTab === "rewrites" && (
          <div className="rounded-2xl border border-border bg-surface-card p-5">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-100">
                {t("proxies.goCus.rewritesTitle", { count: rewrites.length })}
              </h3>
              <p className="text-[11px] text-gray-500">
                {t("proxies.goCus.fromModulesOnly")}
              </p>
            </div>
            {rewrites.length === 0 ? (
              <EmptyState
                icon={<Wand2 size={28} />}
                title={t("proxies.goCus.noRewrites")}
                description={t("proxies.goCus.noRewritesDesc")}
              />
            ) : (
              <div className="max-h-[28rem] space-y-1.5 overflow-y-auto pr-1">
                {rewrites.map((r, i) => (
                  <div
                    key={`${r.pattern}-${i}`}
                    className="flex items-center gap-3 rounded-lg bg-surface-hover px-3 py-2"
                  >
                    <span
                      className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium ${rewriteBadgeClass(r.action)}`}
                    >
                      {r.action}
                    </span>
                    <span
                      className="min-w-0 flex-1 truncate font-mono text-xs text-gray-300"
                      title={r.pattern}
                    >
                      {r.pattern}
                    </span>
                    {r.target && (
                      <span
                        className="max-w-[30%] shrink-0 truncate text-[11px] text-accent"
                        title={r.target}
                      >
                        → {r.target}
                      </span>
                    )}
                    <span className="shrink-0 text-[11px] text-gray-600">
                      {r.module}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ---------- MitM ---------- */}
        {subTab === "mitm" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between rounded-2xl border border-border bg-surface-card p-5">
              <div>
                <h3 className="text-sm font-semibold text-gray-100">
                  {t("proxies.goCus.tab.mitm")}
                </h3>
                <p className="mt-0.5 text-xs text-gray-500">
                  {t("proxies.goCus.mitmDesc")}
                </p>
              </div>
              <Switch
                checked={settings.mitmEnabled}
                onChange={(v) => persist({ ...settings, mitmEnabled: v })}
                title={t("proxies.goCus.mitmSwitch")}
              />
            </div>

            <div className="rounded-2xl border border-border bg-surface-card p-5">
              <h3 className="mb-3 text-sm font-semibold text-gray-100">
                {t("proxies.goCus.mitmHostsTitle", { count: mitmHosts.length })}
              </h3>
              {mitmHosts.length === 0 ? (
                <p className="py-4 text-center text-sm text-gray-500">
                  {t("proxies.goCus.noMitmHosts")}
                </p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {mitmHosts.map((h) => (
                    <span
                      key={h}
                      className="rounded-md bg-surface-hover px-2 py-1 font-mono text-[11px] text-gray-300"
                    >
                      {h}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="space-y-4 rounded-2xl border border-border bg-surface-card p-5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldCheck size={16} className="text-accent" />
                  <h3 className="text-sm font-semibold text-gray-100">
                    {t("proxies.goCus.caTitle")}
                  </h3>
                </div>
                <button
                  onClick={loadCa}
                  disabled={caBusy}
                  className="flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-xs transition-colors hover:bg-accent-hover disabled:opacity-50"
                >
                  {caBusy ? (
                    <Loader2 size={13} className="animate-spin" />
                  ) : (
                    <ShieldCheck size={13} />
                  )}
                  {t("proxies.goCus.caGenerate")}
                </button>
              </div>

              {ca && (
                <div className="space-y-3">
                  <div>
                    <p className="mb-1 text-xs text-gray-500">
                      {t("proxies.goCus.caFingerprint")}
                    </p>
                    <p className="break-all rounded-lg bg-surface-hover px-3 py-2 font-mono text-[11px] leading-relaxed text-gray-300">
                      {ca.fingerprint}
                    </p>
                  </div>
                  <div>
                    <p className="mb-1 text-xs text-gray-500">
                      {t("proxies.goCus.caInstallUrl")}
                    </p>
                    <div className="flex items-center gap-2">
                      <a
                        href={ca.installUrl}
                        target="_blank"
                        rel="noreferrer"
                        title={ca.installUrl}
                        className="min-w-0 flex-1 truncate rounded-lg bg-surface-hover px-3 py-2 font-mono text-[11px] text-accent hover:underline"
                      >
                        {ca.installUrl}
                      </a>
                      <button
                        onClick={() =>
                          copyText(ca.installUrl, t("proxies.goCus.installCopied"))
                        }
                        className="flex shrink-0 items-center gap-1 rounded-lg bg-surface-hover px-3 py-2 text-xs text-gray-300 transition-colors hover:text-gray-100"
                      >
                        <Copy size={13} />
                        {t("proxies.goCus.copyInstall")}
                      </button>
                    </div>
                  </div>
                  <label className="flex cursor-pointer items-center gap-2 text-xs text-gray-300">
                    <input
                      type="checkbox"
                      checked={settings.caInstalled}
                      onChange={(e) =>
                        persist({ ...settings, caInstalled: e.target.checked })
                      }
                      className="h-4 w-4 accent-indigo-500"
                    />
                    {t("proxies.goCus.caTrusted")}
                  </label>
                </div>
              )}

              <p className="text-[11px] leading-relaxed text-gray-500">
                {t("proxies.goCus.caHint")}
              </p>
            </div>
          </div>
        )}

        {/* ---------- 脚本 ---------- */}
        {subTab === "scripts" && (
          <div className="rounded-2xl border border-border bg-surface-card p-5">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-100">
                {t("proxies.goCus.scriptsTitle", { count: scripts.length })}
              </h3>
              <p className="text-[11px] text-gray-500">
                {t("proxies.goCus.fromModulesOnly")}
              </p>
            </div>
            {scripts.length === 0 ? (
              <EmptyState
                icon={<FileCode2 size={28} />}
                title={t("proxies.goCus.noScripts")}
                description={t("proxies.goCus.noScriptsDesc")}
              />
            ) : (
              <div className="max-h-[28rem] space-y-1.5 overflow-y-auto pr-1">
                {scripts.map((s, i) => (
                  <div
                    key={`${s.scriptPath}-${i}`}
                    className="flex items-center gap-3 rounded-lg bg-surface-hover px-3 py-2"
                  >
                    <span
                      className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium ${scriptBadgeClass(s.type)}`}
                    >
                      {s.type}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs text-gray-200">{s.name}</p>
                      {s.pattern && (
                        <p
                          className="truncate font-mono text-[11px] text-gray-500"
                          title={s.pattern}
                        >
                          {s.pattern}
                        </p>
                      )}
                    </div>
                    <button
                      onClick={() =>
                        copyText(s.scriptPath, t("proxies.goCus.scriptPathCopied"))
                      }
                      title={t("proxies.goCus.clickToCopy", { path: s.scriptPath })}
                      className="flex max-w-[40%] shrink-0 items-center gap-1 text-[11px] text-gray-400 transition-colors hover:text-accent"
                    >
                      <Copy size={11} className="shrink-0" />
                      <span className="truncate font-mono">{s.scriptPath}</span>
                    </button>
                    <span className="shrink-0 text-[11px] text-gray-600">
                      {s.module}
                    </span>
                  </div>
                ))}
              </div>
            )}
            <p className="mt-4 text-[11px] leading-relaxed text-gray-500">
              {t("proxies.goCus.scriptAlphaNote")}
            </p>
          </div>
        )}
      </div>
    </ProGate>
  );
}
