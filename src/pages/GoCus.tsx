import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  ChevronDown,
  Copy,
  Download,
  FileCode2,
  Loader2,
  Package,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Wand2,
  X,
} from "lucide-react";

import {
  deleteGoCusModule,
  generateOrGetCaUrl,
  getGoCusSettings,
  importGoCusModule,
  saveGoCusSettings,
  testGoCusScript,
  toggleGoCusModule,
  type CaInfo,
  type CusModule,
  type CusModuleStats,
  type GoCusScriptTestResult,
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
import { sanitizeUiError } from "@/utils/errorSanitizer";

// ============================== 本地解析 ==============================

interface RewriteEntry {
  pattern: string;
  action: string;
  target?: string;
  moduleId: string;
  module: string;
}

interface ScriptEntry {
  name: string;
  type: string;
  pattern: string;
  scriptPath: string;
  moduleId: string;
  module: string;
}

/// 已识别的改写动作（QuantumultX url 语法的 action 集合，Surge 语法共用）
const REWRITE_ACTION_OPTIONS = [
  "reject",
  "reject-200",
  "reject-img",
  "reject-tinygif",
  "reject-dict",
  "reject-array",
  "302",
  "307",
  "request-header",
  "response-header",
] as const;

const REWRITE_ACTIONS = new Set<string>(REWRITE_ACTION_OPTIONS);

// ============================== 官方精选一键模板库 ==============================

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
    content: `#!name=🛡️ 全网广告与开屏净化
#!desc=拦截常见广告/统计/埋点域名，并净化开屏与广告配置请求
[Rule]
DOMAIN-SUFFIX,ad.com,REJECT
DOMAIN-SUFFIX,ads.google.com,REJECT
DOMAIN-SUFFIX,doubleclick.net,REJECT
DOMAIN-SUFFIX,googlesyndication.com,REJECT
DOMAIN-SUFFIX,google-analytics.com,REJECT
DOMAIN-SUFFIX,googletagmanager.com,REJECT
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
DOMAIN-SUFFIX,app-measurement.com,REJECT
[URL Rewrite]
^https?://.*/(splash|openads?)/.* url reject-img
^https?://.*/api/ad_config.* url reject-dict`,
  },
  {
    key: "privacy",
    nameKey: "proxies.goCus.tpl.privacy.name",
    descKey: "proxies.goCus.tpl.privacy.desc",
    content: `#!name=🧹 隐私追踪与请求头净化
#!desc=剥离 X-Forwarded-For 与 X-Client-Data 追踪请求头，并纳入 MitM 主机名
[URL Rewrite]
^https?://([^/]*\\.)?google\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?google\\.com/ url request-header $(remove-X-Client-Data)
^https?://([^/]*\\.)?youtube\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?youtube\\.com/ url request-header $(remove-X-Client-Data)
^https?://([^/]*\\.)?facebook\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?x\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?reddit\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?github\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?amazon\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?bing\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://([^/]*\\.)?baidu\\.com/ url request-header $(remove-X-Forwarded-For)
[MITM]
hostname = %APPEND% google.com, youtube.com, facebook.com, x.com, reddit.com, github.com, amazon.com, bing.com, baidu.com`,
  },
  {
    key: "shortlink",
    nameKey: "proxies.goCus.tpl.shortlink.name",
    descKey: "proxies.goCus.tpl.shortlink.desc",
    content: `#!name=🔗 短链直达与跳转净化
#!desc=还原短链真实目标，清理 utm_* 等中间跳转页
[URL Rewrite]
^https?://link\\.zhihu\\.com/\\?target=(.*) url 302 $1
^https?://([^/]+)/.*[?&]utm_\\S* url 302 https://$1/
^https?://[^/]+/.*[?&]target=(https?://[^&]+) url 302 $1`,
  },
  {
    key: "host",
    nameKey: "proxies.goCus.tpl.host.name",
    descKey: "proxies.goCus.tpl.host.desc",
    content: `#!name=⚡ 自定义本地 Host 映射
#!desc=仅影响本地域名解析，不改变代理路由
[Host]
printer.lan = 192.168.1.20
nas.lan = 192.168.1.10
router.lan = 192.168.1.1`,
  },
];

// ============================== 自定义模块 ==============================

const CUSTOM_MODULE_IDS = {
  rewrites: "local-custom-rewrites",
  mitm: "local-custom-mitm",
  scripts: "local-custom-scripts",
  host: "local-custom-host",
} as const;

type CreateKind = keyof typeof CUSTOM_MODULE_IDS;

const INPUT_CLASS =
  "w-full min-w-0 rounded-lg border border-border bg-surface-card px-3 py-2 text-sm outline-none focus:border-accent";

function shortHash(input: string): string {
  let h = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

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
function parseRewritesForDisplay(raw: string): Omit<RewriteEntry, "moduleId" | "module">[] {
  const out: Omit<RewriteEntry, "moduleId" | "module">[] = [];
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
      const host = part.trim().replace(/^\*\./, "");
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
function parseScriptsForDisplay(raw: string): Omit<ScriptEntry, "moduleId" | "module">[] {
  const out: Omit<ScriptEntry, "moduleId" | "module">[] = [];

  for (const line of sectionLines(raw, (h) => h.trim().toLowerCase() === "[script]")) {
    const tokens = line.split(/\s+/);
    if (tokens.length < 2) continue;
    // 本页生成的脚本采用逗号分隔格式（后端解析器可识别），展示时去掉行尾逗号
    const type = tokens[0].toLowerCase().replace(/,+$/, "");
    let pattern = "";
    const kvParts: string[] = [];
    for (const t of tokens.slice(1)) {
      if (!pattern && !t.includes("=")) pattern = t.replace(/,+$/, "");
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

function countRuleLines(raw: string): number {
  return sectionLines(raw, (h) => {
    const n = h.trim().toLowerCase();
    return n === "[rule]" || n === "[filter_local]";
  }).length;
}

function computeModuleStats(raw: string): CusModuleStats {
  return {
    rules: countRuleLines(raw),
    rewrites: parseRewritesForDisplay(raw).length,
    scripts: parseScriptsForDisplay(raw).length,
    mitmHosts: parseMitmHosts(raw).length,
    hosts: sectionLines(raw, (h) => h.trim().toLowerCase() === "[host]").length,
  };
}

function appendSectionLines(raw: string, lines: string[]): string {
  return `${raw.trimEnd()}\n${lines.join("\n")}\n`;
}

type LegacyKind = "ai" | "media" | "cnDirect";

/** 旧版模板（已由系统内置能力接管）识别：仅按模板标题/首行精确匹配，避免误伤用户模块 */
function legacyKindOf(m: CusModule): LegacyKind | null {
  const name = m.name.trim().toLowerCase();
  const raw = m.rawContent.toLowerCase();
  const first = raw.split(/\r?\n/, 1)[0] ?? "";
  const lists: Array<[LegacyKind, string[]]> = [
    ["ai", ["🤖 ai 服务分流", "ai services routing"]],
    ["media", ["🎬 流媒体解锁", "global media unlock"]],
    ["cnDirect", ["⚡ 国内直连加速", "cn & apple cdn direct"]],
  ];
  for (const [kind, names] of lists) {
    if (names.includes(name)) return kind;
    if (names.some((n) => first.includes(n))) return kind;
  }
  return null;
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

/** 表单容器（新建改写 / MitM / 脚本 / Host 共用） */
function FormCard({
  title,
  onCancel,
  children,
  footer,
}: {
  title: string;
  onCancel: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="mt-3 w-full min-w-0 overflow-hidden rounded-xl border border-accent/30 bg-surface-hover p-3 box-border">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h4 className="text-[13px] font-semibold text-gray-100">{title}</h4>
        <button
          onClick={onCancel}
          title="Close"
          className="shrink-0 rounded p-1 text-gray-500 transition-colors hover:text-gray-200"
        >
          <X size={14} />
        </button>
      </div>
      <div className="space-y-2">{children}</div>
      {footer && <div className="mt-2 flex justify-end gap-2">{footer}</div>}
    </div>
  );
}

// ============================== 页面 ==============================

/** 【APP54 任务6】子分类标签栏（英文精简：All | Override | Rewrite | Script | MitM），
 *  容器 flex-wrap 允许自动换行，严禁单行硬撑超出屏幕 */
const SUB_TABS = [
  { key: "all", labelKey: "proxies.goCus.tab.all" },
  { key: "modules", labelKey: "proxies.goCus.tab.override" },
  { key: "rewrites", labelKey: "proxies.goCus.tab.rewrites" },
  { key: "scripts", labelKey: "proxies.goCus.tab.scripts" },
  { key: "mitm", labelKey: "proxies.goCus.tab.mitm" },
] as const;

type SubTabKey = (typeof SUB_TABS)[number]["key"];

/** Go Cus 引擎：覆写 / 改写 / MitM / 脚本（Pro 功能） */
export default function GoCus() {
  const { t, resolved: lang } = useTranslation();
  // 【APP-10 任务4】首帧直出全局 store 缓存（App 启动已水合），
  // 消除引擎/MitM 开关切页闪烁；无缓存时回落 null 走原加载路径
  const [settings, setSettings] = useState<GoCusSettings | null>(
    () => useCoreStore.getState().goCusSettings,
  );
  const [loading, setLoading] = useState(
    () => useCoreStore.getState().goCusSettings == null,
  );
  const [subTab, setSubTab] = useState<SubTabKey>("all");

  // 模块导入
  const [source, setSource] = useState("");
  const [importing, setImporting] = useState(false);
  const [importingTpl, setImportingTpl] = useState<string | null>(null);
  const [importedTpls, setImportedTpls] = useState<string[]>([]);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  // 【APP50 任务4】iOS WKWebView 静默拦截 window.confirm（恒返回 false），
  // 模块删除改用「二次点击确认」（3s 自动复位）
  const [confirmingDeleteId, setConfirmingDeleteId] = useState<string | null>(null);

  // CA
  const [ca, setCa] = useState<CaInfo | null>(null);
  const [caBusy, setCaBusy] = useState(false);
  const [showIosGuide, setShowIosGuide] = useState(false);

  // 新建表单
  const [createOpen, setCreateOpen] = useState<CreateKind | null>(null);
  const [savingCustom, setSavingCustom] = useState(false);
  const [rwPattern, setRwPattern] = useState("");
  const [rwAction, setRwAction] = useState<string>("reject");
  const [rwTarget, setRwTarget] = useState("");
  const [mitmInput, setMitmInput] = useState("");
  const [scriptName, setScriptName] = useState("");
  const [scriptPattern, setScriptPattern] = useState("");
  const [scriptCode, setScriptCode] = useState("");
  const [scriptTestUrl, setScriptTestUrl] = useState("https://example.com/");
  const [scriptTestBusy, setScriptTestBusy] = useState(false);
  const [scriptTestResult, setScriptTestResult] =
    useState<GoCusScriptTestResult | null>(null);
  const [hostDomain, setHostDomain] = useState("");
  const [hostValue, setHostValue] = useState("");

  const isIOS = useMemo(() => {
    if (typeof navigator === "undefined") return false;
    return (
      /iPad|iPhone|iPod/.test(navigator.userAgent) ||
      (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1)
    );
  }, []);

  useEffect(() => {
    let cancelled = false;
    getGoCusSettings()
      .then((s) => {
        if (!cancelled) setSettings(s);
        // 回写全局 store，保持后续切页首帧为最新值
        useCoreStore.getState().setGoCusSettings(s);
      })
      .catch((e) => toast.error(sanitizeUiError(e, lang).message))
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [lang]);

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
      toast.error(sanitizeUiError(e, lang).message);
      setSettings(prev);
    }
  };

  const reload = async () => {
    try {
      const s = await getGoCusSettings();
      setSettings(s);
      useCoreStore.getState().setGoCusSettings(s);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
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
      toast.error(sanitizeUiError(e, lang).message);
    } finally {
      setImporting(false);
    }
  };

  /** 一键导入官方模板：后端自动开启引擎（首个模块）并在 VPN 运行中热重载；
   *  重复导入同一模板为更新（按内容去重） */
  const importTemplate = async (tpl: CusTemplate) => {
    setImportingTpl(tpl.key);
    try {
      const m = await importGoCusModule(tpl.content);
      toast.success(t("proxies.goCus.importSuccess", { name: m.name }));
      setImportedTpls((prev) =>
        prev.includes(tpl.key) ? prev : [...prev, tpl.key],
      );
      await reload();
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    } finally {
      setImportingTpl(null);
    }
  };

  /** 远程模块更新：重新导入同一 URL 即覆盖本地缓存 */
  const updateRemoteModule = async (m: CusModule) => {
    setUpdatingId(m.id);
    try {
      await importGoCusModule(m.source);
      toast.success(t("proxies.goCus.updatedRemote"));
      await reload();
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    } finally {
      setUpdatingId(null);
    }
  };

  const toggleModule = async (m: CusModule, enabled: boolean) => {
    if (!settings) return;
    const next: GoCusSettings = {
      ...settings,
      modules: settings.modules.map((x) =>
        x.id === m.id ? { ...x, enabled } : x,
      ),
    };
    setSettings(next); // 乐观更新
    try {
      await toggleGoCusModule(m.id, enabled);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
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
      toast.error(sanitizeUiError(e, lang).message);
    }
  };

  const loadCa = async () => {
    setCaBusy(true);
    try {
      const info = await generateOrGetCaUrl();
      setCa(info);
      if (info.created) toast.success(t("proxies.goCus.caGenerated"));
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    } finally {
      setCaBusy(false);
    }
  };

  const copyText = async (text: string, okMsg: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(okMsg);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    }
  };

  /** 将自定义内容写入本地模块 raw_content（存在则更新，不存在则创建） */
  const saveCustomModule = async (
    id: string,
    name: string,
    desc: string,
    rawContent: string,
  ): Promise<boolean> => {
    if (!settings) return false;
    const prev = settings;
    const existing = prev.modules.find((m) => m.id === id);
    const module: CusModule = {
      id,
      name,
      desc,
      source: `local://${id}`,
      rawContent,
      enabled: true,
      stats: computeModuleStats(rawContent),
      updatedAt: Math.floor(Date.now() / 1000),
      hits: existing?.hits,
    };
    const modules = existing
      ? prev.modules.map((m) => (m.id === id ? module : m))
      : [...prev.modules, module];
    const next: GoCusSettings = { ...prev, enabled: true, modules };
    setSettings(next);
    setSavingCustom(true);
    try {
      await saveGoCusSettings(next);
      useCoreStore.getState().setGoCusSettings(next);
      return true;
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
      setSettings(prev);
      return false;
    } finally {
      setSavingCustom(false);
    }
  };

  const closeCreate = () => {
    setCreateOpen(null);
    setScriptTestResult(null);
  };

  /** 新建 URL 改写：写入自定义模块的 [URL Rewrite] 段 */
  const saveRewrite = async () => {
    if (!settings) return;
    const pattern = rwPattern.trim();
    const target = rwTarget.trim();
    if (!pattern) {
      toast.error(t("proxies.goCus.err.patternRequired"));
      return;
    }
    if (/[,\s=]/.test(pattern)) {
      toast.error(t("proxies.goCus.err.patternComma"));
      return;
    }
    const needsTarget =
      rwAction === "302" ||
      rwAction === "307" ||
      rwAction.includes("header");
    if (needsTarget && !target) {
      toast.error(t("proxies.goCus.err.targetRequired"));
      return;
    }
    const line = `${pattern} url ${rwAction}${target ? ` ${target}` : ""}`;
    const existing = settings.modules.find(
      (m) => m.id === CUSTOM_MODULE_IDS.rewrites,
    );
    const existingLines = existing
      ? sectionLines(existing.rawContent, isRewriteSection)
      : [];
    if (existingLines.includes(line)) {
      toast.error(t("proxies.goCus.err.duplicate"));
      return;
    }
    const name = t("proxies.goCus.customRewriteName");
    const raw = existing
      ? appendSectionLines(existing.rawContent, [line])
      : `#!name=${name}\n#!desc=${t("proxies.goCus.customRewriteDesc")}\n[URL Rewrite]\n${line}\n`;
    const ok = await saveCustomModule(CUSTOM_MODULE_IDS.rewrites, name, t("proxies.goCus.customRewriteDesc"), raw);
    if (!ok) return;
    toast.success(t("proxies.goCus.rwSaved"));
    setRwPattern("");
    setRwTarget("");
    closeCreate();
  };

  /** 新建 MitM 主机：写入自定义模块的 [MITM] 段 */
  const saveMitm = async () => {
    if (!settings) return;
    const hosts = mitmInput
      .split(",")
      .map((h) => h.trim().replace(/^\*\./, ""))
      .filter(Boolean);
    if (!hosts.length) {
      toast.error(t("proxies.goCus.err.hostRequired"));
      return;
    }
    const existing = settings.modules.find(
      (m) => m.id === CUSTOM_MODULE_IDS.mitm,
    );
    const known = existing ? parseMitmHosts(existing.rawContent) : [];
    const fresh = hosts.filter((h, i) => !known.includes(h) && hosts.indexOf(h) === i);
    if (!fresh.length) {
      toast.error(t("proxies.goCus.err.duplicate"));
      return;
    }
    const name = t("proxies.goCus.customMitmName");
    const line = `hostname = %APPEND% ${fresh.join(", ")}`;
    const raw = existing
      ? appendSectionLines(existing.rawContent, [line])
      : `#!name=${name}\n#!desc=${t("proxies.goCus.customMitmDesc")}\n[MITM]\n${line}\n`;
    const ok = await saveCustomModule(CUSTOM_MODULE_IDS.mitm, name, t("proxies.goCus.customMitmDesc"), raw);
    if (!ok) return;
    toast.success(t("proxies.goCus.mitmSaved"));
    setMitmInput("");
    closeCreate();
  };

  /** 保存脚本：生成 [Script] 条目，JS 代码以注释形式内联保存在同一模块 */
  const saveScript = async () => {
    if (!settings) return;
    const safeName = scriptName.trim().replace(/[\s,=]/g, "-");
    const pattern = scriptPattern.trim();
    if (!safeName || !pattern || !scriptCode.trim()) {
      toast.error(t("proxies.goCus.err.scriptRequired"));
      return;
    }
    if (/[,\s=]/.test(pattern)) {
      toast.error(t("proxies.goCus.err.patternComma"));
      return;
    }
    const hash = shortHash(`${safeName}|${pattern}`);
    const scriptPath = `inline:${hash}`;
    const line = `http-request, ${pattern}, script-path=${scriptPath}, tag=${safeName}, requires-body=1`;
    const codeLines = scriptCode
      .split(/\r?\n/)
      .map((l) => `# ${l}`)
      .join("\n");
    const block = `${line}\n# --- inline script ${hash} begin ---\n${codeLines}\n# --- inline script ${hash} end ---`;
    const existing = settings.modules.find(
      (m) => m.id === CUSTOM_MODULE_IDS.scripts,
    );
    // 同名同正则重复保存视为更新：先移除旧条目
    const oldLineRe = new RegExp(
      `^http-request,\\s*${pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*,.*${scriptPath}`,
    );
    let base = existing?.rawContent ?? "";
    if (base) {
      base = base
        .split(/\r?\n/)
        .filter((l, i, arr) => {
          if (oldLineRe.test(l)) {
            // 同时跳过紧随其后的旧注释块
            return false;
          }
          if (
            i > 0 &&
            /^# --- inline script .+ begin ---$/.test(arr[i - 1]) &&
            oldLineRe.test(arr[i - 2] ?? "")
          ) {
            return false;
          }
          return true;
        })
        .join("\n");
    }
    const name = t("proxies.goCus.customScriptsName");
    const raw = base.trim()
      ? appendSectionLines(base, [block])
      : `#!name=${name}\n#!desc=${t("proxies.goCus.customScriptsDesc")}\n[Script]\n${block}\n`;
    const ok = await saveCustomModule(CUSTOM_MODULE_IDS.scripts, name, t("proxies.goCus.customScriptsDesc"), raw);
    if (!ok) return;
    toast.success(t("proxies.goCus.scriptSaved"));
    setScriptName("");
    setScriptPattern("");
    setScriptCode("");
    setScriptTestResult(null);
    closeCreate();
  };

  /** 新建 Host 映射：写入自定义模块的 [Host] 段 */
  const saveHost = async () => {
    if (!settings) return;
    const domain = hostDomain.trim().toLowerCase();
    const value = hostValue.trim();
    if (
      !/^[a-z0-9.-]+$/.test(domain) ||
      !/^[a-zA-Z0-9.:-]+$/.test(value)
    ) {
      toast.error(t("proxies.goCus.err.hostInvalid"));
      return;
    }
    const line = `${domain} = ${value}`;
    const existing = settings.modules.find(
      (m) => m.id === CUSTOM_MODULE_IDS.host,
    );
    const existingLines = existing
      ? sectionLines(existing.rawContent, (h) => h.trim().toLowerCase() === "[host]")
      : [];
    if (existingLines.includes(line)) {
      toast.error(t("proxies.goCus.err.duplicate"));
      return;
    }
    const name = t("proxies.goCus.customHostName");
    const raw = existing
      ? appendSectionLines(existing.rawContent, [line])
      : `#!name=${name}\n#!desc=${t("proxies.goCus.customHostDesc")}\n[Host]\n${line}\n`;
    const ok = await saveCustomModule(CUSTOM_MODULE_IDS.host, name, t("proxies.goCus.customHostDesc"), raw);
    if (!ok) return;
    toast.success(t("proxies.goCus.hostSaved"));
    setHostDomain("");
    setHostValue("");
    closeCreate();
  };

  const runScriptTest = async () => {
    if (!scriptCode.trim()) {
      toast.error(t("proxies.goCus.err.scriptRequired"));
      return;
    }
    setScriptTestBusy(true);
    setScriptTestResult(null);
    try {
      const res = await testGoCusScript(scriptCode, {
        url: scriptTestUrl.trim() || "https://example.com/",
        method: "GET",
        headers: { "User-Agent": "Prism-GoCus-Test" },
      });
      setScriptTestResult(res);
    } catch (e) {
      setScriptTestResult({
        ok: false,
        error: sanitizeUiError(e, lang).message,
      });
    } finally {
      setScriptTestBusy(false);
    }
  };

  // 启用模块聚合出的改写 / MitM 主机 / 脚本
  const rewrites = useMemo(
    () =>
      (settings?.modules ?? [])
        .filter((m) => m.enabled)
        .flatMap((m) =>
          parseRewritesForDisplay(m.rawContent).map((e) => ({
            ...e,
            moduleId: m.id,
            module: m.name,
          })),
        ),
    [settings],
  );

  const mitmHosts = useMemo(
    () =>
      Array.from(
        new Set(
          (settings?.modules ?? [])
            .filter((m) => m.enabled)
            .flatMap((m) => parseMitmHosts(m.rawContent)),
        ),
      ),
    [settings],
  );

  const scripts = useMemo(
    () =>
      (settings?.modules ?? [])
        .filter((m) => m.enabled)
        .flatMap((m) =>
          parseScriptsForDisplay(m.rawContent).map((e) => ({
            ...e,
            moduleId: m.id,
            module: m.name,
          })),
        ),
    [settings],
  );

  /** 命中次数查询：兼容后端多种 key 形式，缺失时如实显示 0 */
  const ruleHits = (moduleId: string, pattern: string): number => {
    const map = settings?.hits?.rules;
    if (!map) return 0;
    const keys = [
      `${moduleId}:${pattern}`,
      `${moduleId}|${pattern}`,
      `${moduleId}#${pattern}`,
      pattern,
    ];
    for (const key of keys) {
      const v = map[key];
      if (typeof v === "number") return v;
    }
    return 0;
  };

  const moduleHits = (m: CusModule): number =>
    m.hits ?? settings?.hits?.modules?.[m.id] ?? 0;

  if (loading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner />
      </div>
    );
  }

  if (!settings) {
    return (
      <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
        <p className="py-6 text-center text-sm text-gray-500">
          {t("proxies.goCus.loadFailed")}
        </p>
      </div>
    );
  }

  const enabledModules = settings.modules.filter((m) => m.enabled);
  const activeRules = enabledModules.reduce(
    (sum, m) =>
      sum +
      (m.stats?.rules ?? 0) +
      (m.stats?.rewrites ?? 0) +
      (m.stats?.scripts ?? 0) +
      (m.stats?.hosts ?? 0) +
      (m.stats?.mitmHosts ?? 0),
    0,
  );
  const todayHits = settings.hits?.total ?? 0;
  const caStatus: "none" | "pending" | "ready" = settings.caInstalled
    ? "ready"
    : ca
      ? "pending"
      : "none";
  const caStatusClass =
    caStatus === "ready"
      ? "bg-latency-good/15 text-latency-good border-latency-good/30"
      : caStatus === "pending"
        ? "bg-latency-medium/15 text-latency-medium border-latency-medium/30"
        : "bg-glass text-gray-400 border-border";

  return (
    <ProGate feature={Feature.GoCus}>
      <div className="space-y-4">
        {/* 引擎总控 */}
        <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
          <div className="flex w-full min-w-0 items-center justify-between gap-2">
            <div className="flex min-w-0 flex-1 items-center gap-3 pr-2">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent/15">
                <Wand2 size={17} className="text-accent" />
              </span>
              <div className="min-w-0 flex-1">
                <h3 className="text-sm font-semibold text-gray-100">
                  {t("proxies.goCus.engineTitle")}
                </h3>
                <p className="mt-0.5 text-[13px] leading-snug text-gray-500 break-words">
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
          <div className="mt-2.5 flex w-full min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-gray-500">
            <span className="tabular-nums">
              {t("proxies.goCus.metric.enabledModules", {
                count: enabledModules.length,
              })}
            </span>
            <span className="text-gray-600">·</span>
            <span className="tabular-nums">
              {t("proxies.goCus.metric.activeRules", { count: activeRules })}
            </span>
            <span className="text-gray-600">·</span>
            <span className="tabular-nums">
              {t("proxies.goCus.metric.hitsToday", { count: todayHits })}
            </span>
          </div>
        </div>

        {/* 子标签（英文精简：All | Override | Rewrite | Script | MitM，自动换行防溢出） */}
        <div className="flex w-full max-w-full flex-wrap gap-1.5 rounded-lg border border-border bg-surface-hover p-1 box-border">
          {SUB_TABS.map((tabItem) => (
            <button
              key={tabItem.key}
              onClick={() => setSubTab(tabItem.key)}
              className={`whitespace-nowrap rounded-md px-3 py-1.5 text-[13px] font-semibold transition-colors ${
                subTab === tabItem.key
                  ? "bg-accent text-white"
                  : "text-gray-400 hover:text-gray-200"
              }`}
            >
              {t(tabItem.labelKey)}
            </button>
          ))}
        </div>

        {/* ---------- 模块 / 覆写 ---------- */}
        {(subTab === "all" || subTab === "modules") && (
          <div className="space-y-4">
            <div className="flex w-full min-w-0 items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-gray-100">
                {t("proxies.goCus.overrideTitle")}
              </h3>
              <button
                onClick={() =>
                  setCreateOpen((cur) => (cur === "host" ? null : "host"))
                }
                className="flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg bg-accent px-3 py-1.5 text-[12px] font-bold text-white transition-colors hover:bg-accent-hover"
              >
                <Plus size={13} />
                {t("proxies.goCus.addNew")}
              </button>
            </div>

            {createOpen === "host" && (
              <FormCard
                title={t("proxies.goCus.hostFormTitle")}
                onCancel={closeCreate}
                footer={
                  <>
                    <button
                      onClick={closeCreate}
                      className="rounded-lg border border-border px-3 py-1.5 text-xs text-gray-300 hover:text-gray-100"
                    >
                      {t("proxies.goCus.cancel")}
                    </button>
                    <button
                      onClick={() => void saveHost()}
                      disabled={savingCustom}
                      className="rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-white hover:bg-accent-hover disabled:opacity-50"
                    >
                      {t("proxies.goCus.save")}
                    </button>
                  </>
                }
              >
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <input
                    value={hostDomain}
                    onChange={(e) => setHostDomain(e.target.value)}
                    placeholder={t("proxies.goCus.hostDomain")}
                    spellCheck={false}
                    className={INPUT_CLASS}
                  />
                  <input
                    value={hostValue}
                    onChange={(e) => setHostValue(e.target.value)}
                    placeholder={t("proxies.goCus.hostValue")}
                    spellCheck={false}
                    className={INPUT_CLASS}
                  />
                </div>
                <p className="text-[11px] text-gray-500">
                  {t("proxies.goCus.hostDesc")}
                </p>
              </FormCard>
            )}

            <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
              <h3 className="mb-1 text-sm font-semibold text-gray-100">
                {t("proxies.goCus.importTitle")}
              </h3>
              <p className="mb-3 text-xs leading-snug text-gray-500 break-words">
                {t("proxies.goCus.importDesc")}
              </p>
              <div className="flex w-full min-w-0 flex-col gap-2 sm:flex-row">
                <input
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleImport()}
                  placeholder={t("proxies.goCus.importPlaceholder")}
                  spellCheck={false}
                  className="w-full min-w-0 flex-1 rounded-lg border border-border bg-surface-hover px-3 py-2 text-sm outline-none focus:border-accent"
                />
                <button
                  onClick={handleImport}
                  disabled={importing}
                  className="flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-lg bg-accent px-4 py-2 text-sm transition-colors hover:bg-accent-hover disabled:opacity-50"
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

            {/* 官方精选一键模板库 */}
            <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
              <h3 className="mb-1 text-sm font-semibold text-gray-100">
                {t("proxies.goCus.templateLibTitle")}
              </h3>
              <p className="mb-3 text-xs leading-snug text-gray-500 break-words">
                {t("proxies.goCus.templateLibDesc")}
              </p>
              <div className="grid w-full min-w-0 grid-cols-1 gap-2 sm:grid-cols-2">
                {CUS_TEMPLATES.map((tpl) => (
                  <div
                    key={tpl.key}
                    className="flex w-full min-w-0 items-start justify-between gap-2.5 overflow-hidden rounded-xl border border-border bg-surface-hover px-3 py-2.5 box-border"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="text-[14px] font-bold leading-snug text-gray-200 break-words">
                        {t(tpl.nameKey)}
                      </p>
                      <p className="mt-0.5 text-[11px] leading-4 text-gray-500 break-words">
                        {t(tpl.descKey)}
                      </p>
                    </div>
                    <button
                      onClick={() => void importTemplate(tpl)}
                      disabled={importingTpl === tpl.key}
                      className="shrink-0 whitespace-nowrap rounded-lg bg-accent px-3 py-1.5 text-[12px] font-bold text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
                    >
                      {importingTpl === tpl.key
                        ? t("proxies.goCus.templateImport")
                        : importedTpls.includes(tpl.key)
                          ? t("proxies.goCus.templateAdded")
                          : t("proxies.goCus.templateImport")}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {settings.modules.length === 0 ? (
              <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card box-border">
                <EmptyState
                  icon={<Package size={28} />}
                  title={t("proxies.goCus.noModules")}
                  description={t("proxies.goCus.noModulesDesc")}
                />
              </div>
            ) : (
              <div className="space-y-3">
                {settings.modules.map((m) => {
                  const legacyKind = legacyKindOf(m);
                  return (
                    <div
                      key={m.id}
                      className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border"
                    >
                      <div className="flex w-full min-w-0 items-start justify-between gap-2.5">
                        <div className="min-w-0 flex-1">
                          <div className="flex min-w-0 flex-wrap items-center gap-2">
                            <h3 className="text-[14px] font-bold leading-snug text-gray-100 break-words">
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
                            <span className="shrink-0 rounded bg-surface-hover px-1.5 py-0.5 text-[11px] tabular-nums text-gray-500">
                              {t("proxies.goCus.hits", {
                                count: moduleHits(m),
                              })}
                            </span>
                          </div>
                          {m.desc && (
                            <p className="mt-0.5 text-xs leading-snug text-gray-500 break-words">
                              {m.desc}
                            </p>
                          )}
                          <p
                            className="mt-1 w-full min-w-0 break-all font-mono text-[11px] text-gray-600"
                            title={m.source}
                          >
                            {m.source.startsWith("http") ? m.source : "local"}
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          {m.source.startsWith("http") && (
                            <button
                              onClick={() => void updateRemoteModule(m)}
                              disabled={updatingId === m.id}
                              title={t("proxies.goCus.updateRemote")}
                              className="shrink-0 rounded p-1.5 text-gray-500 transition-colors hover:text-accent disabled:opacity-50"
                            >
                              {updatingId === m.id ? (
                                <Loader2 size={14} className="animate-spin" />
                              ) : (
                                <RefreshCw size={14} />
                              )}
                            </button>
                          )}
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
                            className={`shrink-0 rounded p-1.5 transition-colors ${
                              confirmingDeleteId === m.id
                                ? "bg-red-500/20 text-latency-bad ring-1 ring-red-500/40"
                                : "text-gray-500 hover:text-latency-bad"
                            }`}
                          >
                            <Trash2 size={15} />
                          </button>
                        </div>
                      </div>
                      <div className="mt-3 grid w-full grid-cols-3 gap-2 sm:grid-cols-5">
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
                          {
                            label: t("proxies.goCus.hostsLabel"),
                            value: m.stats.hosts,
                          },
                        ].map((s) => (
                          <div
                            key={s.label}
                            className="min-w-0 rounded-lg bg-surface-hover px-1.5 py-1.5 text-center"
                          >
                            <p className="text-sm font-semibold tabular-nums text-gray-200">
                              {s.value}
                            </p>
                            <p className="truncate text-[11px] text-gray-500">
                              {s.label}
                            </p>
                          </div>
                        ))}
                      </div>
                      {legacyKind && (
                        <div className="mt-2 flex w-full min-w-0 flex-wrap items-center justify-between gap-2 rounded-lg border border-latency-medium/30 bg-latency-medium/10 px-2.5 py-1.5">
                          <span className="min-w-0 break-words text-[11px] text-latency-medium">
                            {t("proxies.goCus.legacyHint")}
                          </span>
                          <button
                            onClick={() => removeModule(m)}
                            className="shrink-0 whitespace-nowrap rounded border border-latency-medium/40 px-2 py-0.5 text-[11px] text-latency-medium hover:bg-latency-medium/10"
                          >
                            {confirmingDeleteId === m.id
                              ? t("proxies.goCus.confirmDeleteAgain")
                              : t("proxies.goCus.legacyDelete")}
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ---------- 改写 ---------- */}
        {(subTab === "all" || subTab === "rewrites") && (
          <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
            <div className="mb-3 flex w-full min-w-0 flex-wrap items-center justify-between gap-1.5">
              <h3 className="text-sm font-semibold text-gray-100">
                {t("proxies.goCus.rewritesTitle", { count: rewrites.length })}
              </h3>
              <button
                onClick={() =>
                  setCreateOpen((cur) => (cur === "rewrites" ? null : "rewrites"))
                }
                className="flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg bg-accent px-2.5 py-1.5 text-[12px] font-bold text-white transition-colors hover:bg-accent-hover"
              >
                <Plus size={13} />
                {t("proxies.goCus.addNew")}
              </button>
            </div>

            {createOpen === "rewrites" && (
              <FormCard
                title={t("proxies.goCus.rwFormTitle")}
                onCancel={closeCreate}
                footer={
                  <>
                    <button
                      onClick={closeCreate}
                      className="rounded-lg border border-border px-3 py-1.5 text-xs text-gray-300 hover:text-gray-100"
                    >
                      {t("proxies.goCus.cancel")}
                    </button>
                    <button
                      onClick={() => void saveRewrite()}
                      disabled={savingCustom}
                      className="rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-white hover:bg-accent-hover disabled:opacity-50"
                    >
                      {t("proxies.goCus.save")}
                    </button>
                  </>
                }
              >
                <input
                  value={rwPattern}
                  onChange={(e) => setRwPattern(e.target.value)}
                  placeholder={t("proxies.goCus.rwPattern")}
                  spellCheck={false}
                  className={`${INPUT_CLASS} font-mono`}
                />
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <select
                    value={rwAction}
                    onChange={(e) => setRwAction(e.target.value)}
                    className={INPUT_CLASS}
                  >
                    {REWRITE_ACTION_OPTIONS.map((a) => (
                      <option key={a} value={a}>
                        {a}
                      </option>
                    ))}
                  </select>
                  <input
                    value={rwTarget}
                    onChange={(e) => setRwTarget(e.target.value)}
                    placeholder={t("proxies.goCus.rwTarget")}
                    spellCheck={false}
                    className={`${INPUT_CLASS} font-mono`}
                  />
                </div>
                <p className="text-[11px] text-gray-500">
                  {t("proxies.goCus.rwTargetHint")}
                </p>
              </FormCard>
            )}

            {rewrites.length === 0 ? (
              <EmptyState
                icon={<Wand2 size={28} />}
                title={t("proxies.goCus.noRewrites")}
                description={t("proxies.goCus.noRewritesDesc")}
              />
            ) : (
              <div className="max-h-[28rem] w-full min-w-0 space-y-1.5 overflow-y-auto pr-1">
                {rewrites.map((r, i) => (
                  <div
                    key={`${r.moduleId}-${r.pattern}-${i}`}
                    className="w-full min-w-0 overflow-hidden rounded-lg bg-surface-hover px-3 py-2 box-border"
                  >
                    <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                      <span
                        className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium ${rewriteBadgeClass(r.action)}`}
                      >
                        {r.action}
                      </span>
                      <span className="min-w-0 max-w-full truncate text-[11px] text-gray-600">
                        {r.module}
                      </span>
                      <span className="ml-auto shrink-0 text-[11px] tabular-nums text-gray-500">
                        {t("proxies.goCus.hits", {
                          count: ruleHits(r.moduleId, r.pattern),
                        })}
                      </span>
                    </div>
                    <p
                      className="mt-1 w-full min-w-0 break-all font-mono text-xs text-gray-300"
                      title={r.pattern}
                    >
                      {r.pattern}
                    </p>
                    {r.target && (
                      <p
                        className="mt-0.5 w-full min-w-0 break-all text-[11px] text-accent"
                        title={r.target}
                      >
                        → {r.target}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ---------- MitM ---------- */}
        {(subTab === "all" || subTab === "mitm") && (
          <div className="space-y-4">
            <div className="flex w-full max-w-full items-center justify-between overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
              <div className="min-w-0 flex-1 pr-2">
                <h3 className="text-sm font-semibold text-gray-100">
                  {t("proxies.goCus.tab.mitm")}
                </h3>
                <p className="mt-0.5 text-[13px] leading-snug text-gray-500 break-words">
                  {t("proxies.goCus.mitmDesc")}
                </p>
              </div>
              <Switch
                checked={settings.mitmEnabled}
                onChange={(v) => persist({ ...settings, mitmEnabled: v })}
                title={t("proxies.goCus.mitmSwitch")}
              />
            </div>

            <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
              <div className="mb-3 flex w-full min-w-0 flex-wrap items-center justify-between gap-1.5">
                <h3 className="text-sm font-semibold text-gray-100">
                  {t("proxies.goCus.mitmHostsTitle", { count: mitmHosts.length })}
                </h3>
                <button
                  onClick={() =>
                    setCreateOpen((cur) => (cur === "mitm" ? null : "mitm"))
                  }
                  className="flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg bg-accent px-2.5 py-1.5 text-[12px] font-bold text-white transition-colors hover:bg-accent-hover"
                >
                  <Plus size={13} />
                  {t("proxies.goCus.addNew")}
                </button>
              </div>

              {createOpen === "mitm" && (
                <FormCard
                  title={t("proxies.goCus.mitmFormTitle")}
                  onCancel={closeCreate}
                  footer={
                    <>
                      <button
                        onClick={closeCreate}
                        className="rounded-lg border border-border px-3 py-1.5 text-xs text-gray-300 hover:text-gray-100"
                      >
                        {t("proxies.goCus.cancel")}
                      </button>
                      <button
                        onClick={() => void saveMitm()}
                        disabled={savingCustom}
                        className="rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-white hover:bg-accent-hover disabled:opacity-50"
                      >
                        {t("proxies.goCus.save")}
                      </button>
                    </>
                  }
                >
                  <input
                    value={mitmInput}
                    onChange={(e) => setMitmInput(e.target.value)}
                    placeholder={t("proxies.goCus.mitmHostname")}
                    spellCheck={false}
                    className={`${INPUT_CLASS} font-mono`}
                  />
                </FormCard>
              )}

              {mitmHosts.length === 0 ? (
                <p className="py-4 text-center text-sm text-gray-500">
                  {t("proxies.goCus.noMitmHosts")}
                </p>
              ) : (
                <div className="flex w-full min-w-0 flex-wrap gap-1.5">
                  {mitmHosts.map((h) => (
                    <span
                      key={h}
                      className="max-w-full break-all rounded-md bg-surface-hover px-2 py-1 font-mono text-[11px] text-gray-300"
                    >
                      {h}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="w-full max-w-full space-y-3 overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
              <div className="flex w-full min-w-0 flex-wrap items-center justify-between gap-2">
                <div className="flex min-w-0 items-center gap-2">
                  <ShieldCheck size={16} className="shrink-0 text-accent" />
                  <h3 className="text-sm font-semibold text-gray-100">
                    {t("proxies.goCus.caTitle")}
                  </h3>
                  <span
                    className={`shrink-0 rounded-full border px-2 py-0.5 text-[11px] ${caStatusClass}`}
                  >
                    {t(`proxies.goCus.caStatus.${caStatus}`)}
                  </span>
                </div>
                <button
                  onClick={loadCa}
                  disabled={caBusy}
                  className="flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg bg-accent px-3 py-1.5 text-xs transition-colors hover:bg-accent-hover disabled:opacity-50"
                >
                  {caBusy ? (
                    <Loader2 size={13} className="animate-spin" />
                  ) : (
                    <ShieldCheck size={13} />
                  )}
                  {t("proxies.goCus.caGenerate")}
                </button>
              </div>

              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <div className="w-full min-w-0">
                  <p className="mb-1 text-xs text-gray-500">
                    {t("proxies.goCus.caFingerprint")}
                  </p>
                  <p className="w-full min-w-0 break-all rounded-lg bg-surface-hover px-3 py-2 font-mono text-[11px] leading-relaxed text-gray-300">
                    {ca?.fingerprint ?? t("proxies.goCus.caUnknown")}
                  </p>
                </div>
                <div className="w-full min-w-0">
                  <p className="mb-1 text-xs text-gray-500">
                    {t("proxies.goCus.caValidity")}
                  </p>
                  <p className="w-full min-w-0 break-all rounded-lg bg-surface-hover px-3 py-2 font-mono text-[11px] leading-relaxed text-gray-300">
                    {t("proxies.goCus.caUnknown")}
                  </p>
                </div>
              </div>

              {ca && (
                <div className="w-full min-w-0">
                  <p className="mb-1 text-xs text-gray-500">
                    {t("proxies.goCus.caInstallUrl")}
                  </p>
                  <div className="flex w-full min-w-0 flex-wrap items-center gap-2">
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
                      className="flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg bg-surface-hover px-3 py-2 text-xs text-gray-300 transition-colors hover:text-gray-100"
                    >
                      <Copy size={13} />
                      {t("proxies.goCus.copyInstall")}
                    </button>
                  </div>
                </div>
              )}

              <div className="flex w-full min-w-0 flex-wrap items-center gap-2">
                <a
                  href={ca?.installUrl ?? "http://127.0.0.1:2082"}
                  target="_blank"
                  rel="noreferrer"
                  className="flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg bg-surface-hover px-3 py-2 text-xs text-gray-300 transition-colors hover:text-gray-100"
                >
                  <Download size={13} />
                  {t("proxies.goCus.installCert")}
                </a>
                <label className="flex min-w-0 cursor-pointer items-start gap-2 text-xs leading-snug text-gray-300">
                  <input
                    type="checkbox"
                    checked={settings.caInstalled}
                    onChange={(e) =>
                      persist({ ...settings, caInstalled: e.target.checked })
                    }
                    className="mt-0.5 h-4 w-4 shrink-0 accent-indigo-500"
                  />
                  <span className="min-w-0 break-words">
                    {t("proxies.goCus.caTrusted")}
                  </span>
                </label>
              </div>

              {isIOS ? (
                <div className="w-full min-w-0">
                  <button
                    onClick={() => setShowIosGuide((v) => !v)}
                    className="flex items-center gap-1 text-[11px] text-gray-500 transition-colors hover:text-gray-300"
                  >
                    <ChevronDown
                      size={13}
                      className={`transition-transform ${showIosGuide ? "rotate-180" : ""}`}
                    />
                    {t("proxies.goCus.iosGuideToggle")}
                  </button>
                  {showIosGuide && (
                    <ol className="mt-2 space-y-1 rounded-lg bg-surface-hover px-3 py-2 text-[11px] leading-relaxed text-gray-400">
                      <li>{t("proxies.goCus.iosGuide1")}</li>
                      <li>{t("proxies.goCus.iosGuide2")}</li>
                      <li>{t("proxies.goCus.iosGuide3")}</li>
                    </ol>
                  )}
                </div>
              ) : (
                <p className="text-[11px] leading-relaxed text-gray-500 break-words">
                  {t("proxies.goCus.desktopHint")}
                </p>
              )}

              <p className="text-[11px] leading-relaxed text-gray-500 break-words">
                {t("proxies.goCus.caHint")}
              </p>
            </div>
          </div>
        )}

        {/* ---------- 脚本 ---------- */}
        {(subTab === "all" || subTab === "scripts") && (
          <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
            <div className="mb-3 flex w-full min-w-0 flex-wrap items-center justify-between gap-1.5">
              <h3 className="text-sm font-semibold text-gray-100">
                {t("proxies.goCus.scriptsTitle", { count: scripts.length })}
              </h3>
              <button
                onClick={() =>
                  setCreateOpen((cur) => (cur === "scripts" ? null : "scripts"))
                }
                className="flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg bg-accent px-2.5 py-1.5 text-[12px] font-bold text-white transition-colors hover:bg-accent-hover"
              >
                <Plus size={13} />
                {t("proxies.goCus.addNew")}
              </button>
            </div>

            {createOpen === "scripts" && (
              <FormCard
                title={t("proxies.goCus.scriptFormTitle")}
                onCancel={closeCreate}
                footer={
                  <>
                    <button
                      onClick={closeCreate}
                      className="rounded-lg border border-border px-3 py-1.5 text-xs text-gray-300 hover:text-gray-100"
                    >
                      {t("proxies.goCus.cancel")}
                    </button>
                    <button
                      onClick={() => void saveScript()}
                      disabled={savingCustom}
                      className="rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-white hover:bg-accent-hover disabled:opacity-50"
                    >
                      {t("proxies.goCus.save")}
                    </button>
                  </>
                }
              >
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <input
                    value={scriptName}
                    onChange={(e) => setScriptName(e.target.value)}
                    placeholder={t("proxies.goCus.scriptName")}
                    spellCheck={false}
                    className={INPUT_CLASS}
                  />
                  <input
                    value={scriptPattern}
                    onChange={(e) => setScriptPattern(e.target.value)}
                    placeholder={t("proxies.goCus.scriptPattern")}
                    spellCheck={false}
                    className={`${INPUT_CLASS} font-mono`}
                  />
                </div>
                <textarea
                  value={scriptCode}
                  onChange={(e) => setScriptCode(e.target.value)}
                  placeholder={t("proxies.goCus.scriptCode")}
                  spellCheck={false}
                  rows={7}
                  className={`${INPUT_CLASS} resize-y font-mono text-[12px]`}
                />
                <div className="flex w-full min-w-0 flex-col gap-2 sm:flex-row sm:items-center">
                  <input
                    value={scriptTestUrl}
                    onChange={(e) => setScriptTestUrl(e.target.value)}
                    placeholder={t("proxies.goCus.scriptTestUrl")}
                    spellCheck={false}
                    className={`${INPUT_CLASS} font-mono`}
                  />
                  <button
                    onClick={() => void runScriptTest()}
                    disabled={scriptTestBusy}
                    className="flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-lg border border-accent/40 bg-accent/10 px-3 py-2 text-xs font-semibold text-accent transition-colors hover:bg-accent/20 disabled:opacity-50"
                  >
                    {scriptTestBusy ? (
                      <Loader2 size={13} className="animate-spin" />
                    ) : (
                      <Play size={13} />
                    )}
                    {scriptTestBusy
                      ? t("proxies.goCus.scriptTesting")
                      : t("proxies.goCus.scriptTest")}
                  </button>
                </div>

                {scriptTestResult && (
                  <div className="space-y-1.5 rounded-lg bg-surface-card p-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-semibold ${
                          scriptTestResult.ok
                            ? "bg-latency-good/15 text-latency-good"
                            : "bg-latency-bad/15 text-latency-bad"
                        }`}
                      >
                        {scriptTestResult.ok ? "OK" : "FAILED"}
                      </span>
                      <span className="text-[11px] text-gray-500">
                        {t("proxies.goCus.scriptTestResult")}
                      </span>
                    </div>
                    {scriptTestResult.error && (
                      <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-hover p-2 font-mono text-[11px] text-latency-bad">
                        {scriptTestResult.error}
                      </pre>
                    )}
                    {scriptTestResult.log && scriptTestResult.log.length > 0 && (
                      <div>
                        <p className="mb-0.5 text-[11px] text-gray-500">
                          {t("proxies.goCus.scriptTestLog")}
                        </p>
                        <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-hover p-2 font-mono text-[11px] text-gray-300">
                          {scriptTestResult.log.join("\n")}
                        </pre>
                      </div>
                    )}
                    {scriptTestResult.request && (
                      <div>
                        <p className="mb-0.5 text-[11px] text-gray-500">
                          {t("proxies.goCus.scriptTestRequest")}
                        </p>
                        <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-hover p-2 font-mono text-[11px] text-gray-300">
                          {`${scriptTestResult.request.method} ${scriptTestResult.request.url}`}
                        </pre>
                      </div>
                    )}
                    {scriptTestResult.response && (
                      <div>
                        <p className="mb-0.5 text-[11px] text-gray-500">
                          {t("proxies.goCus.scriptTestResponse")}
                        </p>
                        <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-hover p-2 font-mono text-[11px] text-gray-300">
                          {`${scriptTestResult.response.status ?? "—"}\n${scriptTestResult.response.body ?? ""}`}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </FormCard>
            )}

            {scripts.length === 0 ? (
              <EmptyState
                icon={<FileCode2 size={28} />}
                title={t("proxies.goCus.noScripts")}
                description={t("proxies.goCus.noScriptsDesc")}
              />
            ) : (
              <div className="max-h-[28rem] w-full min-w-0 space-y-1.5 overflow-y-auto pr-1">
                {scripts.map((s, i) => (
                  <div
                    key={`${s.moduleId}-${s.scriptPath}-${i}`}
                    className="flex w-full min-w-0 items-start gap-2 overflow-hidden rounded-lg bg-surface-hover px-3 py-2 box-border"
                  >
                    <span
                      className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium ${scriptBadgeClass(s.type)}`}
                    >
                      {s.type}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                        <p className="min-w-0 break-words text-xs leading-snug text-gray-200">
                          {s.name}
                        </p>
                        <span className="ml-auto shrink-0 text-[11px] tabular-nums text-gray-500">
                          {t("proxies.goCus.hits", {
                            count: ruleHits(s.moduleId, s.pattern),
                          })}
                        </span>
                      </div>
                      {s.pattern && (
                        <p
                          className="w-full min-w-0 break-all font-mono text-[11px] text-gray-500"
                          title={s.pattern}
                        >
                          {s.pattern}
                        </p>
                      )}
                      <button
                        onClick={() =>
                          copyText(s.scriptPath, t("proxies.goCus.scriptPathCopied"))
                        }
                        title={t("proxies.goCus.clickToCopy", { path: s.scriptPath })}
                        className="flex w-full min-w-0 items-center gap-1 text-left text-[11px] text-gray-400 transition-colors hover:text-accent"
                      >
                        <Copy size={11} className="shrink-0" />
                        <span className="min-w-0 break-all font-mono">
                          {s.scriptPath}
                        </span>
                      </button>
                    </div>
                    <span className="shrink-0 text-[11px] text-gray-600">
                      {s.module}
                    </span>
                  </div>
                ))}
              </div>
            )}
            <p className="mt-4 text-[11px] leading-relaxed text-gray-500 break-words">
              {t("proxies.goCus.scriptInlineNote")}
            </p>
          </div>
        )}
      </div>
    </ProGate>
  );
}
