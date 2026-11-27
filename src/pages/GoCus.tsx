import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ClipboardPaste,
  Code2,
  Copy,
  Download,
  ExternalLink,
  FileCode2,
  FileUp,
  Globe,
  Loader2,
  Package,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldCheck,
  Sparkles,
  Trash2,
  Wand2,
  X,
} from "lucide-react";

import {
  deleteGoCusModule,
  generateOrGetCaUrl,
  getGoCusCaStatus,
  getGoCusSettings,
  importGoCusModule,
  openExternalUrl,
  resetGoCusHits,
  saveGoCusSettings,
  testGoCusScript,
  toggleGoCusModule,
  type CaInfo,
  type CusModule,
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
import {
  CUSTOM_MODULE_IDS,
  REWRITE_ACTION_OPTIONS,
  computeModuleStats,
  isValidRegex,
  legacyKindOf,
  parseUniversalModuleLocal,
  removeCustomHost,
  removeCustomMitmHost,
  removeCustomRewrite,
  removeCustomScript,
  upsertCustomHost,
  upsertCustomMitmHosts,
  upsertCustomRewrite,
  upsertCustomScript,
  type CustomModuleKind,
  type ParsedMitmHost,
  type ParsedRewrite,
  type ParsedScript,
} from "@/utils/goCusParser";

// ============================== 官方精选一键模板库 ==============================

interface CusTemplate {
  key: string;
  nameKey: string;
  descKey: string;
  matchNames: string[];
  content: string;
}

const CUS_TEMPLATES: CusTemplate[] = [
  {
    key: "adblock",
    nameKey: "proxies.goCus.tpl.adblock.name",
    descKey: "proxies.goCus.tpl.adblock.desc",
    matchNames: ["🛡️ 全网广告与开屏净化"],
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
    matchNames: ["🧹 隐私追踪与请求头净化"],
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
    matchNames: ["🔗 短链直达与跳转净化"],
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
    matchNames: ["⚡ 自定义本地 Host 映射"],
    content: `#!name=⚡ 自定义本地 Host 映射
#!desc=仅影响本地域名解析，不改变代理路由
[Host]
printer.lan = 192.168.1.20
nas.lan = 192.168.1.10
router.lan = 192.168.1.1`,
  },
];

// ============================== 脚本快捷代码片段 ==============================

const SCRIPT_SNIPPETS = {
  reqHeader: `// 修改请求头示例 (http-request)
var headers = Object.assign({}, $request.headers);
headers["X-Prism-Custom"] = "enabled";
delete headers["X-Forwarded-For"];
console.log("Rewriting request:", $request.url);
$done({ request: { headers: headers } });`,
  mockJson: `// 直接返回本地模拟 JSON 响应 (http-request)
console.log("Mocking:", $request.url);
$done({
  response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ok: true, source: "go-cus" })
  }
});`,
  respBody: `// 修改响应体示例 (http-response)
try {
  var data = JSON.parse($response.body || "{}");
  data.adFree = true;
  console.log("Patched response for:", $request.url);
  $done({ response: { status: $response.status || 200, body: JSON.stringify(data) } });
} catch (e) {
  console.warn("Non-JSON response:", String(e));
  $done({});
}`,
} as const;

const HEADER_PRESETS = [
  "$(remove-X-Forwarded-For)",
  "$(add-X-Custom: value)",
  "$(replace-User-Agent: Mozilla/5.0)",
] as const;

// ============================== 样式与徽章 ==============================

const INPUT_CLASS =
  "w-full min-w-0 rounded-lg border border-border bg-surface-card px-3 py-2 text-sm text-gray-100 placeholder:text-gray-500 outline-none transition-colors focus:border-accent";

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
    <div className="mt-3 w-full min-w-0 overflow-hidden rounded-xl border border-accent/30 bg-surface-hover p-3.5 box-border">
      <div className="mb-2.5 flex items-center justify-between gap-2">
        <h4 className="text-[13px] font-semibold text-gray-100">{title}</h4>
        <button
          type="button"
          onClick={onCancel}
          title="Close"
          className="shrink-0 rounded p-1 text-gray-500 transition-colors hover:text-gray-200"
        >
          <X size={14} />
        </button>
      </div>
      <div className="space-y-2.5">{children}</div>
      {footer && <div className="mt-3 flex justify-end gap-2">{footer}</div>}
    </div>
  );
}

// ============================== 子标签与扩展类型 ==============================

const SUB_TABS = [
  { key: "all", labelKey: "proxies.goCus.tab.all" },
  { key: "modules", labelKey: "proxies.goCus.tab.override" },
  { key: "rewrites", labelKey: "proxies.goCus.tab.rewrites" },
  { key: "scripts", labelKey: "proxies.goCus.tab.scripts" },
  { key: "mitm", labelKey: "proxies.goCus.tab.mitm" },
] as const;

type SubTabKey = (typeof SUB_TABS)[number]["key"];
type ImportMode = "url" | "paste" | "file";

interface DisplayRewrite extends ParsedRewrite {
  moduleId: string;
  module: string;
  isCustom: boolean;
}

interface DisplayScript extends ParsedScript {
  moduleId: string;
  module: string;
  isCustom: boolean;
}

interface DisplayMitmHost extends ParsedMitmHost {
  moduleIds: string[];
  isCustomOnly: boolean;
  inCustomModule: boolean;
}

interface DisplayHost {
  domain: string;
  value: string;
  moduleId: string;
  module: string;
  isOverride: boolean;
  canDelete: boolean;
}

/** Go Cus 引擎：覆写 / 改写 / MitM / 脚本（Pro 功能） */
export default function GoCus() {
  const { t, resolved: lang } = useTranslation();

  // 全局 store 订阅：Dashboard / 托盘 / 其他页面改动即时同步，首帧零闪烁
  const storeSettings = useCoreStore((s) => s.goCusSettings);
  const [settings, setSettings] = useState<GoCusSettings | null>(
    () => storeSettings,
  );
  const [loading, setLoading] = useState(() => storeSettings == null);
  const [subTab, setSubTab] = useState<SubTabKey>("all");
  const [refreshingStats, setRefreshingStats] = useState(false);

  // 模块导入（支持 URL / 多行粘贴 / 本地文件）
  const [importMode, setImportMode] = useState<ImportMode>("url");
  const [sourceUrl, setSourceUrl] = useState("");
  const [pasteContent, setPasteContent] = useState("");
  const [pasteName, setPasteName] = useState("");
  const [importing, setImporting] = useState(false);
  const [importingTpl, setImportingTpl] = useState<string | null>(null);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // 模块源码查看/编辑
  const [editingModuleId, setEditingModuleId] = useState<string | null>(null);
  const [editingModuleRaw, setEditingModuleRaw] = useState("");
  const [savingModuleRaw, setSavingModuleRaw] = useState(false);

  // 二次点击确认删除（iOS WKWebView 禁 window.confirm）
  const [confirmingDeleteId, setConfirmingDeleteId] = useState<string | null>(null);

  // DNS 覆写草稿
  const [dnsDraft, setDnsDraft] = useState(() => storeSettings?.dnsOverride ?? "");
  const [savingDns, setSavingDns] = useState(false);

  // 搜索过滤
  const [rewriteQuery, setRewriteQuery] = useState("");
  const [scriptQuery, setScriptQuery] = useState("");
  const [mitmQuery, setMitmQuery] = useState("");

  // CA 状态
  const [ca, setCa] = useState<CaInfo | null>(null);
  const [caBusy, setCaBusy] = useState(false);
  const [showIosGuide, setShowIosGuide] = useState(false);

  // 新建 / 编辑表单
  const [createOpen, setCreateOpen] = useState<CustomModuleKind | null>(null);
  const [savingCustom, setSavingCustom] = useState(false);

  // 改写表单
  const [editingRewriteLine, setEditingRewriteLine] = useState<string | null>(null);
  const [rwPattern, setRwPattern] = useState("");
  const [rwAction, setRwAction] = useState<string>("reject");
  const [rwTarget, setRwTarget] = useState("");

  // MitM 表单
  const [mitmInput, setMitmInput] = useState("");

  // 脚本表单 & 测试器
  const [editingScriptPath, setEditingScriptPath] = useState<string | null>(null);
  const [scriptName, setScriptName] = useState("");
  const [scriptType, setScriptType] = useState<"http-request" | "http-response">(
    "http-request",
  );
  const [scriptPattern, setScriptPattern] = useState("");
  const [scriptCode, setScriptCode] = useState("");
  const [scriptTestUrl, setScriptTestUrl] = useState("https://example.com/api/test");
  const [scriptTestMethod, setScriptTestMethod] = useState("GET");
  const [scriptTestMockResp, setScriptTestMockResp] = useState('{"ok":true}');
  const [scriptTestBusy, setScriptTestBusy] = useState(false);
  const [scriptTestResult, setScriptTestResult] =
    useState<GoCusScriptTestResult | null>(null);

  // Host 表单
  const [hostDomain, setHostDomain] = useState("");
  const [hostValue, setHostValue] = useState("");

  const platform = useMemo(() => {
    if (typeof navigator === "undefined") {
      return { isIOS: false, isApple: false };
    }
    const ua = navigator.userAgent || "";
    const isIOS =
      /iPad|iPhone|iPod/.test(ua) ||
      (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    const isMac = /Macintosh|Mac OS X/.test(ua);
    return { isIOS, isApple: isIOS || isMac };
  }, []);

  // 同步来自全局 store 的后端广播更新
  useEffect(() => {
    if (storeSettings) {
      setSettings(storeSettings);
      setDnsDraft((prev) =>
        prev === (storeSettings.dnsOverride ?? "")
          ? prev
          : storeSettings.dnsOverride ?? "",
      );
      setLoading(false);
    }
  }, [storeSettings]);

  // 挂载拉取最新配置与只读 CA 状态
  useEffect(() => {
    let cancelled = false;
    Promise.allSettled([getGoCusSettings(), getGoCusCaStatus()]).then(
      ([settingsRes, caRes]) => {
        if (cancelled) return;
        if (settingsRes.status === "fulfilled") {
          setSettings(settingsRes.value);
          setDnsDraft(settingsRes.value.dnsOverride ?? "");
          useCoreStore.getState().setGoCusSettings(settingsRes.value);
        } else {
          toast.error(sanitizeUiError(settingsRes.reason, lang).message);
        }
        if (caRes.status === "fulfilled" && caRes.value) {
          setCa(caRes.value);
        }
        setLoading(false);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [lang]);

  // Esc 快捷键关闭当前打开的表单或源码编辑器
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      if (editingModuleId) {
        setEditingModuleId(null);
      } else if (createOpen) {
        setCreateOpen(null);
        setEditingRewriteLine(null);
        setEditingScriptPath(null);
        setScriptTestResult(null);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [editingModuleId, createOpen]);

  /** 整体保存 settings（乐观更新，失败回滚） */
  const persist = async (next: GoCusSettings): Promise<boolean> => {
    if (!settings) return false;
    const prev = settings;
    setSettings(next);
    try {
      await saveGoCusSettings(next);
      useCoreStore.getState().setGoCusSettings(next);
      return true;
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
      setSettings(prev);
      return false;
    }
  };

  const reload = async (silent = false) => {
    if (!silent) setRefreshingStats(true);
    try {
      const s = await getGoCusSettings();
      setSettings(s);
      setDnsDraft(s.dnsOverride ?? "");
      useCoreStore.getState().setGoCusSettings(s);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    } finally {
      if (!silent) setRefreshingStats(false);
    }
  };

  const handleResetHits = async () => {
    try {
      await resetGoCusHits();
      toast.success(t("proxies.goCus.hitsReset"));
      await reload(true);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
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

  const pasteInto = async (setter: (v: string) => void) => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) setter(text);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    }
  };

  // ---- 模块导入 / 更新 / 启停 / 删除 / 源码编辑 ----

  const handleImportUrl = async () => {
    const src = sourceUrl.trim();
    if (!src) {
      toast.error(t("proxies.goCus.err.emptySource"));
      return;
    }
    setImporting(true);
    try {
      const m = await importGoCusModule(src);
      toast.success(t("proxies.goCus.importSuccess", { name: m.name }));
      setSourceUrl("");
      await reload(true);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    } finally {
      setImporting(false);
    }
  };

  const handleImportPaste = async () => {
    const content = pasteContent.trim();
    if (!content) {
      toast.error(t("proxies.goCus.err.emptySource"));
      return;
    }
    setImporting(true);
    try {
      const m = await importGoCusModule(content, pasteName.trim() || undefined);
      toast.success(t("proxies.goCus.importSuccess", { name: m.name }));
      setPasteContent("");
      setPasteName("");
      await reload(true);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    } finally {
      setImporting(false);
    }
  };

  const handleImportFile = async (file: File | null) => {
    if (!file) return;
    setImporting(true);
    try {
      const text = await file.text();
      if (!text.trim()) {
        toast.error(t("proxies.goCus.err.emptySource"));
        return;
      }
      const fallbackName = file.name.replace(/\.[^.]+$/, "").trim() || undefined;
      const m = await importGoCusModule(text, fallbackName);
      toast.success(t("proxies.goCus.importSuccess", { name: m.name }));
      await reload(true);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    } finally {
      setImporting(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const importTemplate = async (tpl: CusTemplate) => {
    setImportingTpl(tpl.key);
    try {
      const m = await importGoCusModule(tpl.content);
      toast.success(t("proxies.goCus.importSuccess", { name: m.name }));
      await reload(true);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    } finally {
      setImportingTpl(null);
    }
  };

  const updateRemoteModule = async (m: CusModule) => {
    setUpdatingId(m.id);
    try {
      await importGoCusModule(m.source);
      toast.success(t("proxies.goCus.updatedRemote"));
      await reload(true);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    } finally {
      setUpdatingId(null);
    }
  };

  const toggleModule = async (m: CusModule, enabled: boolean) => {
    if (!settings) return;
    const prev = settings;
    const next: GoCusSettings = {
      ...settings,
      modules: settings.modules.map((x) =>
        x.id === m.id ? { ...x, enabled } : x,
      ),
    };
    setSettings(next);
    useCoreStore.getState().setGoCusSettings(next);
    try {
      await toggleGoCusModule(m.id, enabled);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
      setSettings(prev);
      useCoreStore.getState().setGoCusSettings(prev);
    }
  };

  const removeModule = async (m: CusModule) => {
    if (confirmingDeleteId !== m.id) {
      setConfirmingDeleteId(m.id);
      window.setTimeout(
        () => setConfirmingDeleteId((cur) => (cur === m.id ? null : cur)),
        3000,
      );
      return;
    }
    setConfirmingDeleteId(null);
    if (editingModuleId === m.id) setEditingModuleId(null);
    try {
      await deleteGoCusModule(m.id);
      toast.success(t("proxies.goCus.moduleDeleted"));
      await reload(true);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    }
  };

  const openModuleEditor = (m: CusModule) => {
    if (editingModuleId === m.id) {
      setEditingModuleId(null);
      return;
    }
    setEditingModuleId(m.id);
    setEditingModuleRaw(m.rawContent);
  };

  const saveModuleEditor = async (m: CusModule) => {
    if (!settings) return;
    const stats = computeModuleStats(editingModuleRaw);
    const totalItems =
      stats.rules + stats.rewrites + stats.scripts + stats.mitmHosts + stats.hosts;
    if (totalItems === 0) {
      toast.error(t("proxies.goCus.err.emptySource"));
      return;
    }
    setSavingModuleRaw(true);
    try {
      const next: GoCusSettings = {
        ...settings,
        modules: settings.modules.map((x) =>
          x.id === m.id
            ? {
                ...x,
                rawContent: editingModuleRaw,
                stats,
                updatedAt: Math.floor(Date.now() / 1000),
              }
            : x,
        ),
      };
      const ok = await persist(next);
      if (ok) {
        toast.success(t("proxies.goCus.moduleSaved"));
        setEditingModuleId(null);
      }
    } finally {
      setSavingModuleRaw(false);
    }
  };

  // ---- CA 证书 ----

  const loadCa = async (): Promise<CaInfo | null> => {
    setCaBusy(true);
    try {
      const info = await generateOrGetCaUrl();
      setCa(info);
      if (info.created) toast.success(t("proxies.goCus.caGenerated"));
      return info;
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
      return null;
    } finally {
      setCaBusy(false);
    }
  };

  const handleInstallCa = async (kind: "profile" | "cert" | "portal") => {
    const info = ca ?? (await loadCa());
    if (!info) return;
    const targetUrl =
      kind === "cert"
        ? info.certUrl ?? "http://127.0.0.1:2082/prism-ca.crt"
        : kind === "portal"
          ? "http://127.0.0.1:2082/"
          : info.installUrl;
    try {
      await openExternalUrl(targetUrl);
    } catch (e) {
      toast.error(sanitizeUiError(e, lang).message);
    }
  };

  // ---- 自定义模块持久化辅助 ----

  const saveCustomModule = async (
    id: string,
    name: string,
    desc: string,
    rawContent: string,
    removeIfEmpty = false,
  ): Promise<boolean> => {
    if (!settings) return false;
    const stats = computeModuleStats(rawContent);
    const totalItems =
      stats.rules + stats.rewrites + stats.scripts + stats.mitmHosts + stats.hosts;
    const existing = settings.modules.find((m) => m.id === id);

    let modules: CusModule[];
    if (removeIfEmpty && totalItems === 0) {
      modules = settings.modules.filter((m) => m.id !== id);
    } else {
      const mod: CusModule = {
        id,
        name,
        desc,
        source: `local://${id}`,
        rawContent,
        enabled: true,
        stats,
        updatedAt: Math.floor(Date.now() / 1000),
        hits: existing?.hits,
      };
      modules = existing
        ? settings.modules.map((m) => (m.id === id ? mod : m))
        : [...settings.modules, mod];
    }

    const next: GoCusSettings = {
      ...settings,
      enabled: totalItems > 0 ? true : settings.enabled,
      modules,
    };
    setSavingCustom(true);
    try {
      return await persist(next);
    } finally {
      setSavingCustom(false);
    }
  };

  const closeCreate = () => {
    setCreateOpen(null);
    setEditingRewriteLine(null);
    setEditingScriptPath(null);
    setScriptTestResult(null);
  };

  // ---- DNS 覆写保存 ----

  const saveDnsOverride = async (clear = false) => {
    if (!settings) return;
    const nextVal = clear ? null : dnsDraft.trim() || null;
    setSavingDns(true);
    try {
      const ok = await persist({ ...settings, dnsOverride: nextVal });
      if (ok) {
        if (clear) setDnsDraft("");
        toast.success(
          nextVal
            ? t("proxies.goCus.dnsOverrideSaved")
            : t("proxies.goCus.dnsOverrideCleared"),
        );
      }
    } finally {
      setSavingDns(false);
    }
  };

  // ---- URL 改写 CRUD ----

  const openNewRewrite = () => {
    setEditingRewriteLine(null);
    setRwPattern("");
    setRwAction("reject");
    setRwTarget("");
    setCreateOpen((cur) => (cur === "rewrites" && !editingRewriteLine ? null : "rewrites"));
  };

  const openEditRewrite = (r: DisplayRewrite) => {
    setEditingRewriteLine(r.rawLine);
    setRwPattern(r.pattern);
    setRwAction(
      REWRITE_ACTION_OPTIONS.includes(r.action as (typeof REWRITE_ACTION_OPTIONS)[number])
        ? r.action
        : "reject",
    );
    setRwTarget(r.target ?? "");
    setCreateOpen("rewrites");
  };

  const rwNeedsTarget =
    rwAction === "302" || rwAction === "307" || rwAction.includes("header");

  const saveRewrite = async () => {
    if (!settings) return;
    const pattern = rwPattern.trim();
    const target = rwNeedsTarget ? rwTarget.trim() : "";
    if (!pattern) {
      toast.error(t("proxies.goCus.err.patternRequired"));
      return;
    }
    if (/[,\s=]/.test(pattern)) {
      toast.error(t("proxies.goCus.err.patternComma"));
      return;
    }
    if (!isValidRegex(pattern)) {
      toast.error(t("proxies.goCus.err.regexInvalid"));
      return;
    }
    if (rwNeedsTarget && !target) {
      toast.error(t("proxies.goCus.err.targetRequired"));
      return;
    }
    const line = `${pattern} url ${rwAction}${target ? ` ${target}` : ""}`;
    const existing = settings.modules.find(
      (m) => m.id === CUSTOM_MODULE_IDS.rewrites,
    );
    const name = t("proxies.goCus.customRewriteName");
    const desc = t("proxies.goCus.customRewriteDesc");
    const { raw, duplicate } = upsertCustomRewrite(
      existing?.rawContent,
      name,
      desc,
      line,
      editingRewriteLine ?? undefined,
    );
    if (duplicate) {
      toast.error(t("proxies.goCus.err.duplicate"));
      return;
    }
    const ok = await saveCustomModule(CUSTOM_MODULE_IDS.rewrites, name, desc, raw);
    if (!ok) return;
    toast.success(t("proxies.goCus.rwSaved"));
    setRwPattern("");
    setRwTarget("");
    closeCreate();
  };

  const deleteRewrite = async (r: DisplayRewrite) => {
    if (!settings) return;
    const existing = settings.modules.find(
      (m) => m.id === CUSTOM_MODULE_IDS.rewrites,
    );
    if (!existing) return;
    const nextRaw = removeCustomRewrite(existing.rawContent, r.rawLine);
    const ok = await saveCustomModule(
      CUSTOM_MODULE_IDS.rewrites,
      existing.name,
      existing.desc ?? t("proxies.goCus.customRewriteDesc"),
      nextRaw,
      true,
    );
    if (ok) toast.success(t("proxies.goCus.rwDeleted"));
  };

  // ---- MitM 主机 CRUD ----

  const saveMitm = async () => {
    if (!settings) return;
    const hosts = mitmInput
      .split(/[,\r\n]+/)
      .map((h) => h.trim().toLowerCase())
      .filter((h) => Boolean(h) && h !== "-");
    if (!hosts.length) {
      toast.error(t("proxies.goCus.err.hostRequired"));
      return;
    }
    const existing = settings.modules.find((m) => m.id === CUSTOM_MODULE_IDS.mitm);
    const name = t("proxies.goCus.customMitmName");
    const desc = t("proxies.goCus.customMitmDesc");
    const { raw, added } = upsertCustomMitmHosts(
      existing?.rawContent,
      name,
      desc,
      hosts,
    );
    if (!added.length) {
      toast.error(t("proxies.goCus.err.duplicate"));
      return;
    }
    const ok = await saveCustomModule(CUSTOM_MODULE_IDS.mitm, name, desc, raw);
    if (!ok) return;
    toast.success(t("proxies.goCus.mitmSaved"));
    setMitmInput("");
    closeCreate();
  };

  const deleteMitmHost = async (rawHost: string) => {
    if (!settings) return;
    const existing = settings.modules.find((m) => m.id === CUSTOM_MODULE_IDS.mitm);
    if (!existing) return;
    const name = existing.name;
    const desc = existing.desc ?? t("proxies.goCus.customMitmDesc");
    const { raw } = removeCustomMitmHost(existing.rawContent, name, desc, rawHost);
    const ok = await saveCustomModule(CUSTOM_MODULE_IDS.mitm, name, desc, raw, true);
    if (ok) toast.success(t("proxies.goCus.mitmHostRemoved"));
  };

  // ---- 脚本 CRUD & 沙盒测试 ----

  const openNewScript = () => {
    setEditingScriptPath(null);
    setScriptName("");
    setScriptType("http-request");
    setScriptPattern("");
    setScriptCode("");
    setScriptTestResult(null);
    setCreateOpen((cur) => (cur === "scripts" && !editingScriptPath ? null : "scripts"));
  };

  const openEditScript = (s: DisplayScript) => {
    setEditingScriptPath(s.scriptPath);
    setScriptName(s.name);
    setScriptType(s.type.includes("response") ? "http-response" : "http-request");
    setScriptPattern(s.pattern);
    setScriptCode(s.inlineCode ?? "");
    setScriptTestResult(null);
    setCreateOpen("scripts");
  };

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
    if (!isValidRegex(pattern)) {
      toast.error(t("proxies.goCus.err.regexInvalid"));
      return;
    }
    const existing = settings.modules.find(
      (m) => m.id === CUSTOM_MODULE_IDS.scripts,
    );
    const name = t("proxies.goCus.customScriptsName");
    const desc = t("proxies.goCus.customScriptsDesc");
    const raw = upsertCustomScript(existing?.rawContent, name, desc, {
      name: safeName,
      type: scriptType,
      pattern,
      code: scriptCode,
      oldScriptPath: editingScriptPath ?? undefined,
    });
    const ok = await saveCustomModule(CUSTOM_MODULE_IDS.scripts, name, desc, raw);
    if (!ok) return;
    toast.success(t("proxies.goCus.scriptSaved"));
    setScriptName("");
    setScriptPattern("");
    setScriptCode("");
    closeCreate();
  };

  const deleteScript = async (s: DisplayScript) => {
    if (!settings) return;
    const existing = settings.modules.find(
      (m) => m.id === CUSTOM_MODULE_IDS.scripts,
    );
    if (!existing) return;
    const nextRaw = removeCustomScript(existing.rawContent, s.scriptPath);
    const ok = await saveCustomModule(
      CUSTOM_MODULE_IDS.scripts,
      existing.name,
      existing.desc ?? t("proxies.goCus.customScriptsDesc"),
      nextRaw,
      true,
    );
    if (ok) toast.success(t("proxies.goCus.scriptDeleted"));
  };

  const runScriptTest = async () => {
    if (!scriptCode.trim()) {
      toast.error(t("proxies.goCus.err.scriptRequired"));
      return;
    }
    setScriptTestBusy(true);
    setScriptTestResult(null);
    try {
      const mockResponse =
        scriptType === "http-response"
          ? {
              status: 200,
              headers: { "content-type": "application/json" },
              body: scriptTestMockResp,
            }
          : null;
      const res = await testGoCusScript(
        scriptCode,
        {
          url: scriptTestUrl.trim() || "https://example.com/",
          method: scriptTestMethod,
          headers: { "User-Agent": "Prism-GoCus-Test" },
          body: "",
        },
        mockResponse,
      );
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

  // ---- Host 映射 CRUD ----

  const saveHost = async () => {
    if (!settings) return;
    const domain = hostDomain.trim().toLowerCase();
    const value = hostValue.trim();
    if (!/^[a-z0-9.-]+$/.test(domain) || !/^[a-zA-Z0-9.:-]+$/.test(value)) {
      toast.error(t("proxies.goCus.err.hostInvalid"));
      return;
    }
    const existing = settings.modules.find((m) => m.id === CUSTOM_MODULE_IDS.host);
    const name = t("proxies.goCus.customHostName");
    const desc = t("proxies.goCus.customHostDesc");
    const { raw, duplicate } = upsertCustomHost(
      existing?.rawContent,
      name,
      desc,
      domain,
      value,
    );
    if (duplicate) {
      toast.error(t("proxies.goCus.err.duplicate"));
      return;
    }
    const ok = await saveCustomModule(CUSTOM_MODULE_IDS.host, name, desc, raw);
    if (!ok) return;
    toast.success(t("proxies.goCus.hostSaved"));
    setHostDomain("");
    setHostValue("");
    closeCreate();
  };

  const deleteHost = async (h: DisplayHost) => {
    if (!settings) return;
    if (h.isOverride) {
      const next: GoCusSettings = {
        ...settings,
        hostOverrides: settings.hostOverrides.filter(
          ([d, v]) => !(d.toLowerCase() === h.domain && v === h.value),
        ),
      };
      if (await persist(next)) toast.success(t("proxies.goCus.hostDeleted"));
      return;
    }
    const existing = settings.modules.find((m) => m.id === CUSTOM_MODULE_IDS.host);
    if (!existing) return;
    const nextRaw = removeCustomHost(existing.rawContent, h.domain);
    const ok = await saveCustomModule(
      CUSTOM_MODULE_IDS.host,
      existing.name,
      existing.desc ?? t("proxies.goCus.customHostDesc"),
      nextRaw,
      true,
    );
    if (ok) toast.success(t("proxies.goCus.hostDeleted"));
  };

  // ============================== 聚合解析视图 ==============================

  const parsedEnabled = useMemo(() => {
    const enabled = (settings?.modules ?? []).filter((m) => m.enabled);
    return enabled.map((m) => ({
      module: m,
      parsed: parseUniversalModuleLocal(m.rawContent),
    }));
  }, [settings]);

  const rewrites = useMemo<DisplayRewrite[]>(
    () =>
      parsedEnabled.flatMap(({ module, parsed }) =>
        parsed.rewrites.map((rw) => ({
          ...rw,
          moduleId: module.id,
          module: module.name,
          isCustom: module.id === CUSTOM_MODULE_IDS.rewrites,
        })),
      ),
    [parsedEnabled],
  );

  const scripts = useMemo<DisplayScript[]>(
    () =>
      parsedEnabled.flatMap(({ module, parsed }) =>
        parsed.scripts.map((sc) => ({
          ...sc,
          moduleId: module.id,
          module: module.name,
          isCustom: module.id === CUSTOM_MODULE_IDS.scripts,
        })),
      ),
    [parsedEnabled],
  );

  const mitmHosts = useMemo<DisplayMitmHost[]>(() => {
    const map = new Map<string, DisplayMitmHost>();
    for (const { module, parsed } of parsedEnabled) {
      for (const h of parsed.mitmHosts) {
        const existing = map.get(h.raw);
        if (existing) {
          if (!existing.moduleIds.includes(module.id)) {
            existing.moduleIds.push(module.id);
          }
          if (module.id === CUSTOM_MODULE_IDS.mitm) {
            existing.inCustomModule = true;
          } else {
            existing.isCustomOnly = false;
          }
        } else {
          const isCustom = module.id === CUSTOM_MODULE_IDS.mitm;
          map.set(h.raw, {
            ...h,
            moduleIds: [module.id],
            isCustomOnly: isCustom,
            inCustomModule: isCustom,
          });
        }
      }
    }
    return Array.from(map.values());
  }, [parsedEnabled]);

  const hostEntries = useMemo<DisplayHost[]>(() => {
    const out: DisplayHost[] = [];
    for (const { module, parsed } of parsedEnabled) {
      for (const h of parsed.hosts) {
        out.push({
          domain: h.domain,
          value: h.value,
          moduleId: module.id,
          module: module.name,
          isOverride: false,
          canDelete: module.id === CUSTOM_MODULE_IDS.host,
        });
      }
    }
    for (const [domain, value] of settings?.hostOverrides ?? []) {
      out.push({
        domain: domain.toLowerCase(),
        value,
        moduleId: "__override__",
        module: t("proxies.goCus.customHostName"),
        isOverride: true,
        canDelete: true,
      });
    }
    return out;
  }, [parsedEnabled, settings, t]);

  const moduleDnsServers = useMemo(() => {
    const list: string[] = [];
    for (const { parsed } of parsedEnabled) {
      for (const d of parsed.dnsServers) {
        if (!list.includes(d)) list.push(d);
      }
    }
    return list;
  }, [parsedEnabled]);

  const installedTemplateKeys = useMemo(() => {
    const set = new Set<string>();
    const mods = settings?.modules ?? [];
    for (const tpl of CUS_TEMPLATES) {
      const hit = mods.some(
        (m) =>
          tpl.matchNames.includes(m.name.trim()) ||
          m.rawContent.trim() === tpl.content.trim(),
      );
      if (hit) set.add(tpl.key);
    }
    return set;
  }, [settings]);

  const filteredRewrites = useMemo(() => {
    const q = rewriteQuery.trim().toLowerCase();
    if (!q) return rewrites;
    return rewrites.filter(
      (r) =>
        r.pattern.toLowerCase().includes(q) ||
        r.action.toLowerCase().includes(q) ||
        (r.target ?? "").toLowerCase().includes(q) ||
        r.module.toLowerCase().includes(q),
    );
  }, [rewrites, rewriteQuery]);

  const filteredScripts = useMemo(() => {
    const q = scriptQuery.trim().toLowerCase();
    if (!q) return scripts;
    return scripts.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.pattern.toLowerCase().includes(q) ||
        s.type.toLowerCase().includes(q) ||
        s.scriptPath.toLowerCase().includes(q) ||
        s.module.toLowerCase().includes(q),
    );
  }, [scripts, scriptQuery]);

  const filteredMitmHosts = useMemo(() => {
    const q = mitmQuery.trim().toLowerCase();
    if (!q) return mitmHosts;
    return mitmHosts.filter((h) => h.raw.includes(q));
  }, [mitmHosts, mitmQuery]);

  /** 精确规则命中查询：优先匹配后端 `moduleId#rw:idx` / `moduleId#sc:idx` 键 */
  const ruleHits = (
    moduleId: string,
    kind: "rw" | "sc",
    ruleIndex: number,
    pattern: string,
  ): number => {
    const map = settings?.hits?.rules;
    if (!map) return 0;
    const keys = [
      `${moduleId}#${kind}:${ruleIndex}`,
      `${moduleId}#${ruleIndex}`,
      `${moduleId}:${pattern}`,
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

  const caValidityText =
    ca?.notBefore && ca?.notAfter
      ? `${ca.notBefore} ~ ${ca.notAfter}`
      : t("proxies.goCus.caUnknown");

  const showMitmCaWarning =
    settings.enabled && settings.mitmEnabled && !settings.caInstalled;

  const tabCount = (key: SubTabKey): number | null => {
    switch (key) {
      case "modules":
        return settings.modules.length;
      case "rewrites":
        return rewrites.length;
      case "scripts":
        return scripts.length;
      case "mitm":
        return mitmHosts.length;
      default:
        return null;
    }
  };

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
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-sm font-semibold text-gray-100">
                    {t("proxies.goCus.engineTitle")}
                  </h3>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${
                      settings.enabled
                        ? "bg-latency-good/15 text-latency-good"
                        : "bg-glass text-gray-500"
                    }`}
                  >
                    {settings.enabled
                      ? t("proxies.goCus.statusActive")
                      : t("proxies.goCus.statusStandby")}
                  </span>
                </div>
                <p className="mt-0.5 text-[13px] leading-snug text-gray-500 break-words">
                  {t("proxies.goCus.engineDesc")}
                </p>
              </div>
            </div>
            <Switch
              checked={settings.enabled}
              onChange={(v) => void persist({ ...settings, enabled: v })}
              title={t("proxies.goCus.engineSwitch")}
            />
          </div>

          <div className="mt-3 flex w-full min-w-0 flex-wrap items-center justify-between gap-2 border-t border-border pt-2.5">
            <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-gray-500">
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
            <div className="flex shrink-0 items-center gap-1.5">
              <button
                type="button"
                onClick={() => void reload()}
                disabled={refreshingStats}
                title={t("proxies.goCus.refreshStats")}
                className="flex items-center gap-1 rounded-md bg-surface-hover px-2 py-1 text-[11px] text-gray-400 transition-colors hover:text-gray-100 disabled:opacity-50"
              >
                <RefreshCw
                  size={11}
                  className={refreshingStats ? "animate-spin" : ""}
                />
                {t("proxies.goCus.refreshStats")}
              </button>
              {todayHits > 0 && (
                <button
                  type="button"
                  onClick={() => void handleResetHits()}
                  title={t("proxies.goCus.resetHits")}
                  className="flex items-center gap-1 rounded-md bg-surface-hover px-2 py-1 text-[11px] text-gray-400 transition-colors hover:text-latency-bad"
                >
                  <RotateCcw size={11} />
                  {t("proxies.goCus.resetHits")}
                </button>
              )}
            </div>
          </div>

          {showMitmCaWarning && (
            <div className="mt-3 flex w-full min-w-0 flex-wrap items-center justify-between gap-2 rounded-xl border border-latency-medium/30 bg-latency-medium/10 px-3 py-2">
              <div className="flex min-w-0 flex-1 items-start gap-2 text-xs text-latency-medium">
                <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                <span className="min-w-0 break-words leading-snug">
                  {t("proxies.goCus.mitmCaWarn")}
                </span>
              </div>
              {subTab !== "mitm" && (
                <button
                  type="button"
                  onClick={() => setSubTab("mitm")}
                  className="shrink-0 whitespace-nowrap rounded-lg border border-latency-medium/40 bg-latency-medium/15 px-2.5 py-1 text-[11px] font-semibold text-latency-medium transition-colors hover:bg-latency-medium/25"
                >
                  {t("proxies.goCus.goMitmSetup")}
                </button>
              )}
            </div>
          )}
        </div>

        {/* 子标签栏（带数量胶囊，自动换行防溢出） */}
        <div className="flex w-full max-w-full flex-wrap gap-1.5 rounded-xl border border-border bg-surface-hover p-1 box-border">
          {SUB_TABS.map((tabItem) => {
            const cnt = tabCount(tabItem.key);
            const active = subTab === tabItem.key;
            return (
              <button
                key={tabItem.key}
                type="button"
                onClick={() => setSubTab(tabItem.key)}
                className={`flex items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-[13px] font-semibold transition-colors ${
                  active
                    ? "bg-accent text-white shadow-sm"
                    : "text-gray-400 hover:text-gray-200"
                }`}
              >
                <span>{t(tabItem.labelKey)}</span>
                {cnt !== null && cnt > 0 && (
                  <span
                    className={`rounded-full px-1.5 py-0.2 text-[10px] tabular-nums ${
                      active
                        ? "bg-white/20 text-white"
                        : "bg-glass-strong text-gray-400"
                    }`}
                  >
                    {cnt}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* ============================== 模块 / 覆写 ============================== */}
        {(subTab === "all" || subTab === "modules") && (
          <div className="space-y-4">
            {/* 导入模块（URL / 多行粘贴 / 本地文件） */}
            <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
              <div className="mb-3 flex w-full min-w-0 flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <h3 className="text-sm font-semibold text-gray-100">
                    {t("proxies.goCus.importTitle")}
                  </h3>
                  <p className="mt-0.5 text-xs leading-snug text-gray-500 break-words">
                    {t("proxies.goCus.importDesc")}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-1 rounded-lg border border-border bg-surface-hover p-0.5">
                  {(
                    [
                      ["url", "proxies.goCus.importTabUrl"],
                      ["paste", "proxies.goCus.importTabPaste"],
                      ["file", "proxies.goCus.importTabFile"],
                    ] as const
                  ).map(([mode, labelKey]) => (
                    <button
                      key={mode}
                      type="button"
                      onClick={() => setImportMode(mode)}
                      className={`whitespace-nowrap rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors ${
                        importMode === mode
                          ? "bg-accent text-white"
                          : "text-gray-400 hover:text-gray-200"
                      }`}
                    >
                      {t(labelKey)}
                    </button>
                  ))}
                </div>
              </div>

              {importMode === "url" && (
                <div className="flex w-full min-w-0 flex-col gap-2 sm:flex-row">
                  <div className="relative flex min-w-0 flex-1 items-center">
                    <input
                      value={sourceUrl}
                      onChange={(e) => setSourceUrl(e.target.value)}
                      onKeyDown={(e) =>
                        e.key === "Enter" && void handleImportUrl()
                      }
                      placeholder={t("proxies.goCus.importPlaceholder")}
                      spellCheck={false}
                      className={`${INPUT_CLASS} pr-16 font-mono text-xs`}
                    />
                    <button
                      type="button"
                      onClick={() => void pasteInto(setSourceUrl)}
                      className="absolute right-1.5 flex items-center gap-1 rounded-md bg-surface-hover px-2 py-1 text-[11px] text-gray-400 transition-colors hover:text-gray-100"
                    >
                      <ClipboardPaste size={11} />
                      {t("proxies.goCus.importPasteBtn")}
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleImportUrl()}
                    disabled={importing}
                    className="flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
                  >
                    {importing ? (
                      <Loader2 size={14} className="animate-spin" />
                    ) : (
                      <Download size={14} />
                    )}
                    {t("common.import")}
                  </button>
                </div>
              )}

              {importMode === "paste" && (
                <div className="space-y-2">
                  <input
                    value={pasteName}
                    onChange={(e) => setPasteName(e.target.value)}
                    placeholder={t("proxies.goCus.importNameOptional")}
                    spellCheck={false}
                    className={INPUT_CLASS}
                  />
                  <textarea
                    value={pasteContent}
                    onChange={(e) => setPasteContent(e.target.value)}
                    placeholder={t("proxies.goCus.importContentPlaceholder")}
                    spellCheck={false}
                    rows={5}
                    className={`${INPUT_CLASS} resize-y font-mono text-xs`}
                  />
                  <div className="flex flex-wrap items-center justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => void pasteInto(setPasteContent)}
                      className="flex items-center gap-1.5 rounded-lg border border-border bg-surface-hover px-3 py-1.5 text-xs text-gray-300 transition-colors hover:text-gray-100"
                    >
                      <ClipboardPaste size={13} />
                      {t("proxies.goCus.importPasteBtn")}
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleImportPaste()}
                      disabled={importing}
                      className="flex items-center gap-1.5 rounded-lg bg-accent px-4 py-1.5 text-xs font-bold text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
                    >
                      {importing ? (
                        <Loader2 size={13} className="animate-spin" />
                      ) : (
                        <Download size={13} />
                      )}
                      {t("common.import")}
                    </button>
                  </div>
                </div>
              )}

              {importMode === "file" && (
                <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-border-strong bg-surface-hover/60 px-4 py-5 text-center">
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".sgmodule,.conf,.plugin,.stoverride,.yaml,.yml,.txt,.snippet,.list"
                    onChange={(e) =>
                      void handleImportFile(e.target.files?.[0] ?? null)
                    }
                    className="hidden"
                  />
                  <FileUp size={22} className="text-accent" />
                  <p className="text-xs text-gray-400">
                    {t("proxies.goCus.importFileHint")}
                  </p>
                  <button
                    type="button"
                    disabled={importing}
                    onClick={() => fileInputRef.current?.click()}
                    className="flex items-center gap-1.5 rounded-lg bg-accent px-4 py-1.5 text-xs font-bold text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
                  >
                    {importing ? (
                      <Loader2 size={13} className="animate-spin" />
                    ) : (
                      <FileUp size={13} />
                    )}
                    {t("proxies.goCus.importFilePick")}
                  </button>
                </div>
              )}
            </div>

            {/* 官方精选一键模板库 */}
            <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
              <div className="mb-1 flex items-center gap-1.5">
                <Sparkles size={15} className="shrink-0 text-accent" />
                <h3 className="text-sm font-semibold text-gray-100">
                  {t("proxies.goCus.templateLibTitle")}
                </h3>
              </div>
              <p className="mb-3 text-xs leading-snug text-gray-500 break-words">
                {t("proxies.goCus.templateLibDesc")}
              </p>
              <div className="grid w-full min-w-0 grid-cols-1 gap-2 sm:grid-cols-2">
                {CUS_TEMPLATES.map((tpl) => {
                  const installed = installedTemplateKeys.has(tpl.key);
                  const busy = importingTpl === tpl.key;
                  return (
                    <div
                      key={tpl.key}
                      className="flex w-full min-w-0 items-start justify-between gap-2.5 overflow-hidden rounded-xl border border-border bg-surface-hover px-3.5 py-2.5 box-border"
                    >
                      <div className="min-w-0 flex-1">
                        <p className="text-[13px] font-bold leading-snug text-gray-100 break-words">
                          {t(tpl.nameKey)}
                        </p>
                        <p className="mt-0.5 text-[11px] leading-4 text-gray-500 break-words">
                          {t(tpl.descKey)}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => void importTemplate(tpl)}
                        disabled={busy}
                        className={`flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg px-3 py-1.5 text-[12px] font-bold transition-colors disabled:opacity-50 ${
                          installed
                            ? "border border-latency-good/30 bg-latency-good/15 text-latency-good hover:bg-latency-good/25"
                            : "bg-accent text-white hover:bg-accent-hover"
                        }`}
                      >
                        {busy ? (
                          <Loader2 size={12} className="animate-spin" />
                        ) : installed ? (
                          <Check size={12} />
                        ) : null}
                        {installed
                          ? t("proxies.goCus.templateAdded")
                          : t("proxies.goCus.templateImport")}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 已安装模块列表 */}
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
                  const isEditing = editingModuleId === m.id;
                  const isRemote = m.source.startsWith("http");
                  return (
                    <div
                      key={m.id}
                      className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border"
                    >
                      <div className="flex w-full min-w-0 items-start justify-between gap-2.5">
                        <div className="min-w-0 flex-1">
                          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                            <h3 className="text-[14px] font-bold leading-snug text-gray-100 break-words">
                              {m.name}
                            </h3>
                            <span
                              className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium ${
                                isRemote
                                  ? "bg-accent/15 text-accent"
                                  : "bg-glass text-gray-400"
                              }`}
                            >
                              {isRemote
                                ? t("proxies.goCus.remote")
                                : t("proxies.goCus.local")}
                            </span>
                            <span className="shrink-0 rounded bg-surface-hover px-1.5 py-0.5 text-[10px] tabular-nums text-gray-500">
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
                          {isRemote && (
                            <button
                              type="button"
                              onClick={() =>
                                void copyText(
                                  m.source,
                                  t("proxies.goCus.sourceUrlCopied"),
                                )
                              }
                              title={m.source}
                              className="mt-1 flex max-w-full items-center gap-1 text-left font-mono text-[11px] text-gray-500 transition-colors hover:text-accent"
                            >
                              <Copy size={10} className="shrink-0" />
                              <span className="truncate">{m.source}</span>
                            </button>
                          )}
                        </div>
                        <div className="flex shrink-0 items-center gap-1">
                          <button
                            type="button"
                            onClick={() => openModuleEditor(m)}
                            title={t("proxies.goCus.viewEditSource")}
                            className={`shrink-0 rounded p-1.5 transition-colors ${
                              isEditing
                                ? "bg-accent/15 text-accent"
                                : "text-gray-500 hover:text-accent"
                            }`}
                          >
                            <Code2 size={15} />
                          </button>
                          {isRemote && (
                            <button
                              type="button"
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
                            onChange={(v) => void toggleModule(m, v)}
                            title={
                              m.enabled
                                ? t("proxies.goCus.disableModule")
                                : t("proxies.goCus.enableModule")
                            }
                          />
                          <button
                            type="button"
                            onClick={() => void removeModule(m)}
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

                      {/* 5 维规则统计（点击可直达对应分类） */}
                      <div className="mt-3 grid w-full grid-cols-3 gap-2 sm:grid-cols-5">
                        {(
                          [
                            {
                              label: t("metric.rules"),
                              value: m.stats.rules,
                              targetTab: null,
                            },
                            {
                              label: t("proxies.goCus.tab.rewrites"),
                              value: m.stats.rewrites,
                              targetTab: "rewrites" as SubTabKey,
                            },
                            {
                              label: t("proxies.goCus.tab.scripts"),
                              value: m.stats.scripts,
                              targetTab: "scripts" as SubTabKey,
                            },
                            {
                              label: t("proxies.goCus.tab.mitm"),
                              value: m.stats.mitmHosts,
                              targetTab: "mitm" as SubTabKey,
                            },
                            {
                              label: t("proxies.goCus.hostsLabel"),
                              value: m.stats.hosts,
                              targetTab: null,
                            },
                          ] as const
                        ).map((s) => (
                          <button
                            key={s.label}
                            type="button"
                            onClick={() => {
                              if (s.targetTab && s.value > 0) setSubTab(s.targetTab);
                            }}
                            className={`min-w-0 rounded-lg bg-surface-hover px-1.5 py-1.5 text-center transition-colors ${
                              s.targetTab && s.value > 0
                                ? "cursor-pointer hover:bg-glass-strong"
                                : "cursor-default"
                            }`}
                          >
                            <p className="text-sm font-semibold tabular-nums text-gray-200">
                              {s.value}
                            </p>
                            <p className="truncate text-[11px] text-gray-500">
                              {s.label}
                            </p>
                          </button>
                        ))}
                      </div>

                      {/* 内联源码查看与编辑器 */}
                      {isEditing && (
                        <div className="mt-3 space-y-2 rounded-xl border border-accent/30 bg-surface-hover p-3">
                          <div className="flex items-center justify-between gap-2">
                            <span className="truncate text-xs font-semibold text-gray-200">
                              {t("proxies.goCus.moduleEditorTitle", {
                                name: m.name,
                              })}
                            </span>
                            <button
                              type="button"
                              onClick={() =>
                                void copyText(
                                  editingModuleRaw,
                                  t("proxies.goCus.moduleRawCopied"),
                                )
                              }
                              className="flex shrink-0 items-center gap-1 rounded px-2 py-0.5 text-[11px] text-gray-400 hover:text-gray-100"
                            >
                              <Copy size={11} />
                              {t("proxies.goCus.copy")}
                            </button>
                          </div>
                          <textarea
                            value={editingModuleRaw}
                            onChange={(e) => setEditingModuleRaw(e.target.value)}
                            spellCheck={false}
                            rows={10}
                            className={`${INPUT_CLASS} resize-y font-mono text-[12px] leading-relaxed`}
                          />
                          <div className="flex justify-end gap-2">
                            <button
                              type="button"
                              onClick={() => setEditingModuleId(null)}
                              className="rounded-lg border border-border px-3 py-1.5 text-xs text-gray-300 hover:text-gray-100"
                            >
                              {t("proxies.goCus.cancel")}
                            </button>
                            <button
                              type="button"
                              disabled={savingModuleRaw}
                              onClick={() => void saveModuleEditor(m)}
                              className="rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-white hover:bg-accent-hover disabled:opacity-50"
                            >
                              {t("proxies.goCus.save")}
                            </button>
                          </div>
                        </div>
                      )}

                      {legacyKind && (
                        <div className="mt-2.5 flex w-full min-w-0 flex-wrap items-center justify-between gap-2 rounded-lg border border-latency-medium/30 bg-latency-medium/10 px-2.5 py-1.5">
                          <span className="min-w-0 break-words text-[11px] text-latency-medium">
                            {t("proxies.goCus.legacyHint")}
                          </span>
                          <button
                            type="button"
                            onClick={() => void removeModule(m)}
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

            {/* DNS 覆写 & 本地 Host 映射卡片 */}
            <div className="w-full max-w-full space-y-4 overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
              <div className="flex w-full min-w-0 items-center justify-between gap-2">
                <div className="flex min-w-0 items-center gap-2">
                  <Server size={15} className="shrink-0 text-accent" />
                  <h3 className="text-sm font-semibold text-gray-100">
                    {t("proxies.goCus.dnsHostTitle")}
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={() =>
                    setCreateOpen((cur) => (cur === "host" ? null : "host"))
                  }
                  className="flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg bg-accent px-2.5 py-1.5 text-[12px] font-bold text-white transition-colors hover:bg-accent-hover"
                >
                  <Plus size={13} />
                  {t("proxies.goCus.hostsLabel")}
                </button>
              </div>

              {/* DNS 覆写输入 */}
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-gray-400">
                  {t("proxies.goCus.dnsOverrideLabel")}
                </label>
                <div className="flex w-full min-w-0 flex-col gap-2 sm:flex-row">
                  <input
                    value={dnsDraft}
                    onChange={(e) => setDnsDraft(e.target.value)}
                    onKeyDown={(e) =>
                      e.key === "Enter" && void saveDnsOverride(false)
                    }
                    placeholder={t("proxies.goCus.dnsOverridePlaceholder")}
                    spellCheck={false}
                    className={`${INPUT_CLASS} flex-1 font-mono text-xs`}
                  />
                  <div className="flex shrink-0 gap-1.5">
                    <button
                      type="button"
                      disabled={savingDns}
                      onClick={() => void saveDnsOverride(false)}
                      className="rounded-lg bg-accent px-3 py-2 text-xs font-bold text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
                    >
                      {t("proxies.goCus.save")}
                    </button>
                    {(settings.dnsOverride || dnsDraft) && (
                      <button
                        type="button"
                        disabled={savingDns}
                        onClick={() => void saveDnsOverride(true)}
                        className="rounded-lg border border-border bg-surface-hover px-2.5 py-2 text-xs text-gray-300 transition-colors hover:text-gray-100 disabled:opacity-50"
                      >
                        <X size={13} />
                      </button>
                    )}
                  </div>
                </div>
                {moduleDnsServers.length > 0 && (
                  <p className="text-[11px] text-gray-500">
                    {t("proxies.goCus.dnsModuleHint", {
                      servers: moduleDnsServers.join(", "),
                    })}
                  </p>
                )}
              </div>

              {/* 新建 Host 表单 */}
              {createOpen === "host" && (
                <FormCard
                  title={t("proxies.goCus.hostFormTitle")}
                  onCancel={closeCreate}
                  footer={
                    <>
                      <button
                        type="button"
                        onClick={closeCreate}
                        className="rounded-lg border border-border px-3 py-1.5 text-xs text-gray-300 hover:text-gray-100"
                      >
                        {t("proxies.goCus.cancel")}
                      </button>
                      <button
                        type="button"
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
                      onKeyDown={(e) => e.key === "Enter" && void saveHost()}
                      placeholder={t("proxies.goCus.hostDomain")}
                      spellCheck={false}
                      className={`${INPUT_CLASS} font-mono text-xs`}
                    />
                    <input
                      value={hostValue}
                      onChange={(e) => setHostValue(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && void saveHost()}
                      placeholder={t("proxies.goCus.hostValue")}
                      spellCheck={false}
                      className={`${INPUT_CLASS} font-mono text-xs`}
                    />
                  </div>
                  <p className="text-[11px] text-gray-500">
                    {t("proxies.goCus.hostDesc")}
                  </p>
                </FormCard>
              )}

              {/* Host 映射列表 */}
              <div className="space-y-1.5 border-t border-border pt-3">
                <p className="text-xs font-medium text-gray-400">
                  {t("proxies.goCus.hostListTitle", { count: hostEntries.length })}
                </p>
                {hostEntries.length === 0 ? (
                  <p className="py-2 text-xs text-gray-500">
                    {t("proxies.goCus.noHosts")}
                  </p>
                ) : (
                  <div className="max-h-56 space-y-1.5 overflow-y-auto pr-1">
                    {hostEntries.map((h, idx) => (
                      <div
                        key={`${h.moduleId}-${h.domain}-${idx}`}
                        className="flex w-full min-w-0 items-center justify-between gap-2 rounded-lg bg-surface-hover px-3 py-2"
                      >
                        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-xs">
                          <span className="break-all text-gray-200">{h.domain}</span>
                          <span className="text-gray-500">→</span>
                          <span className="break-all text-accent">{h.value}</span>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          <span className="hidden max-w-[110px] truncate text-[11px] text-gray-500 sm:inline">
                            {h.module}
                          </span>
                          {h.canDelete && (
                            <button
                              type="button"
                              onClick={() => void deleteHost(h)}
                              title={t("proxies.goCus.delete")}
                              className="rounded p-1 text-gray-500 transition-colors hover:text-latency-bad"
                            >
                              <Trash2 size={13} />
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ============================== URL 改写 ============================== */}
        {(subTab === "all" || subTab === "rewrites") && (
          <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
            <div className="mb-3 flex w-full min-w-0 flex-wrap items-center justify-between gap-1.5">
              <h3 className="text-sm font-semibold text-gray-100">
                {t("proxies.goCus.rewritesTitle", { count: rewrites.length })}
              </h3>
              <button
                type="button"
                onClick={openNewRewrite}
                className="flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg bg-accent px-2.5 py-1.5 text-[12px] font-bold text-white transition-colors hover:bg-accent-hover"
              >
                <Plus size={13} />
                {t("proxies.goCus.addNew")}
              </button>
            </div>

            {createOpen === "rewrites" && (
              <FormCard
                title={
                  editingRewriteLine
                    ? t("proxies.goCus.rwEditTitle")
                    : t("proxies.goCus.rwFormTitle")
                }
                onCancel={closeCreate}
                footer={
                  <>
                    <button
                      type="button"
                      onClick={closeCreate}
                      className="rounded-lg border border-border px-3 py-1.5 text-xs text-gray-300 hover:text-gray-100"
                    >
                      {t("proxies.goCus.cancel")}
                    </button>
                    <button
                      type="button"
                      onClick={() => void saveRewrite()}
                      disabled={savingCustom}
                      className="rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-white hover:bg-accent-hover disabled:opacity-50"
                    >
                      {t("proxies.goCus.save")}
                    </button>
                  </>
                }
              >
                <div>
                  <input
                    value={rwPattern}
                    onChange={(e) => setRwPattern(e.target.value)}
                    placeholder={t("proxies.goCus.rwPattern")}
                    spellCheck={false}
                    className={`${INPUT_CLASS} font-mono text-xs ${
                      rwPattern.trim() && !isValidRegex(rwPattern.trim())
                        ? "border-latency-bad focus:border-latency-bad"
                        : ""
                    }`}
                  />
                  {rwPattern.trim() && !isValidRegex(rwPattern.trim()) && (
                    <p className="mt-1 text-[11px] text-latency-bad">
                      {t("proxies.goCus.err.regexInvalid")}
                    </p>
                  )}
                </div>

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
                  {rwNeedsTarget && (
                    <input
                      value={rwTarget}
                      onChange={(e) => setRwTarget(e.target.value)}
                      placeholder={
                        rwAction.includes("header")
                          ? "$(remove-X-Forwarded-For)"
                          : "https://example.com/$1"
                      }
                      spellCheck={false}
                      className={`${INPUT_CLASS} font-mono text-xs`}
                    />
                  )}
                </div>

                {rwAction.includes("header") && (
                  <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                    <span className="text-gray-500">
                      {t("proxies.goCus.rwHeaderPresets")}
                    </span>
                    {HEADER_PRESETS.map((preset) => (
                      <button
                        key={preset}
                        type="button"
                        onClick={() => setRwTarget(preset)}
                        className="rounded bg-surface-card px-2 py-0.5 font-mono text-[11px] text-accent transition-colors hover:bg-accent/15"
                      >
                        {preset}
                      </button>
                    ))}
                  </div>
                )}

                <p className="text-[11px] text-gray-500">
                  {t("proxies.goCus.rwTargetHint")}
                </p>
              </FormCard>
            )}

            {rewrites.length >= 4 && (
              <div className="relative mb-2.5 mt-2">
                <Search
                  size={13}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
                />
                <input
                  value={rewriteQuery}
                  onChange={(e) => setRewriteQuery(e.target.value)}
                  placeholder={t("proxies.goCus.searchPlaceholder")}
                  className={`${INPUT_CLASS} pl-8 py-1.5 text-xs`}
                />
              </div>
            )}

            {rewrites.length === 0 ? (
              <EmptyState
                icon={<Wand2 size={28} />}
                title={t("proxies.goCus.noRewrites")}
                description={t("proxies.goCus.noRewritesDesc")}
              />
            ) : filteredRewrites.length === 0 ? (
              <p className="py-6 text-center text-xs text-gray-500">
                {t("proxies.goCus.noSearchMatch")}
              </p>
            ) : (
              <div className="mt-2 max-h-[28rem] w-full min-w-0 space-y-1.5 overflow-y-auto pr-1">
                {filteredRewrites.map((r, i) => (
                  <div
                    key={`${r.moduleId}-${r.ruleIndex}-${i}`}
                    className="w-full min-w-0 overflow-hidden rounded-lg bg-surface-hover px-3 py-2 box-border"
                  >
                    <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                      <span
                        className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium ${rewriteBadgeClass(r.action)}`}
                      >
                        {r.action}
                      </span>
                      <span className="min-w-0 max-w-full truncate text-[11px] text-gray-500">
                        {r.module}
                      </span>
                      <div className="ml-auto flex shrink-0 items-center gap-1.5">
                        <span className="text-[11px] tabular-nums text-gray-500">
                          {t("proxies.goCus.hits", {
                            count: ruleHits(r.moduleId, "rw", r.ruleIndex, r.pattern),
                          })}
                        </span>
                        {r.isCustom && (
                          <>
                            <button
                              type="button"
                              onClick={() => openEditRewrite(r)}
                              title={t("proxies.goCus.edit")}
                              className="rounded p-1 text-gray-500 transition-colors hover:text-accent"
                            >
                              <Pencil size={12} />
                            </button>
                            <button
                              type="button"
                              onClick={() => void deleteRewrite(r)}
                              title={t("proxies.goCus.delete")}
                              className="rounded p-1 text-gray-500 transition-colors hover:text-latency-bad"
                            >
                              <Trash2 size={12} />
                            </button>
                          </>
                        )}
                      </div>
                    </div>
                    <p
                      className="mt-1 w-full min-w-0 break-all font-mono text-xs text-gray-200"
                      title={r.pattern}
                    >
                      {r.pattern}
                    </p>
                    {r.target && (
                      <p
                        className="mt-0.5 w-full min-w-0 break-all font-mono text-[11px] text-accent"
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

        {/* ============================== 脚本 ============================== */}
        {(subTab === "all" || subTab === "scripts") && (
          <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
            <div className="mb-3 flex w-full min-w-0 flex-wrap items-center justify-between gap-1.5">
              <h3 className="text-sm font-semibold text-gray-100">
                {t("proxies.goCus.scriptsTitle", { count: scripts.length })}
              </h3>
              <button
                type="button"
                onClick={openNewScript}
                className="flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg bg-accent px-2.5 py-1.5 text-[12px] font-bold text-white transition-colors hover:bg-accent-hover"
              >
                <Plus size={13} />
                {t("proxies.goCus.addNew")}
              </button>
            </div>

            {createOpen === "scripts" && (
              <FormCard
                title={
                  editingScriptPath
                    ? t("proxies.goCus.scriptEditTitle")
                    : t("proxies.goCus.scriptFormTitle")
                }
                onCancel={closeCreate}
                footer={
                  <>
                    <button
                      type="button"
                      onClick={closeCreate}
                      className="rounded-lg border border-border px-3 py-1.5 text-xs text-gray-300 hover:text-gray-100"
                    >
                      {t("proxies.goCus.cancel")}
                    </button>
                    <button
                      type="button"
                      onClick={() => void saveScript()}
                      disabled={savingCustom}
                      className="rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-white hover:bg-accent-hover disabled:opacity-50"
                    >
                      {t("proxies.goCus.save")}
                    </button>
                  </>
                }
              >
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                  <input
                    value={scriptName}
                    onChange={(e) => setScriptName(e.target.value)}
                    placeholder={t("proxies.goCus.scriptName")}
                    spellCheck={false}
                    className={INPUT_CLASS}
                  />
                  <select
                    value={scriptType}
                    onChange={(e) =>
                      setScriptType(
                        e.target.value === "http-response"
                          ? "http-response"
                          : "http-request",
                      )
                    }
                    title={t("proxies.goCus.scriptTypeLabel")}
                    className={INPUT_CLASS}
                  >
                    <option value="http-request">
                      {t("proxies.goCus.scriptTypeRequest")}
                    </option>
                    <option value="http-response">
                      {t("proxies.goCus.scriptTypeResponse")}
                    </option>
                  </select>
                  <input
                    value={scriptPattern}
                    onChange={(e) => setScriptPattern(e.target.value)}
                    placeholder={t("proxies.goCus.scriptPattern")}
                    spellCheck={false}
                    className={`${INPUT_CLASS} font-mono text-xs ${
                      scriptPattern.trim() && !isValidRegex(scriptPattern.trim())
                        ? "border-latency-bad focus:border-latency-bad"
                        : ""
                    }`}
                  />
                </div>

                {/* 快捷代码片段 */}
                <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                  <span className="text-gray-500">
                    {t("proxies.goCus.scriptSnippets")}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      setScriptType("http-request");
                      setScriptCode(SCRIPT_SNIPPETS.reqHeader);
                    }}
                    className="rounded bg-surface-card px-2 py-0.5 text-accent transition-colors hover:bg-accent/15"
                  >
                    {t("proxies.goCus.snippetReqHeader")}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setScriptType("http-request");
                      setScriptCode(SCRIPT_SNIPPETS.mockJson);
                    }}
                    className="rounded bg-surface-card px-2 py-0.5 text-accent transition-colors hover:bg-accent/15"
                  >
                    {t("proxies.goCus.snippetMockJson")}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setScriptType("http-response");
                      setScriptCode(SCRIPT_SNIPPETS.respBody);
                    }}
                    className="rounded bg-surface-card px-2 py-0.5 text-accent transition-colors hover:bg-accent/15"
                  >
                    {t("proxies.goCus.snippetRespBody")}
                  </button>
                </div>

                <textarea
                  value={scriptCode}
                  onChange={(e) => setScriptCode(e.target.value)}
                  placeholder={t("proxies.goCus.scriptCode")}
                  spellCheck={false}
                  rows={7}
                  className={`${INPUT_CLASS} resize-y font-mono text-[12px] leading-relaxed`}
                />

                {/* 沙盒测试栏 */}
                <div className="space-y-2 rounded-lg border border-border bg-surface-card p-2.5">
                  <div className="flex w-full min-w-0 flex-col gap-2 sm:flex-row sm:items-center">
                    <select
                      value={scriptTestMethod}
                      onChange={(e) => setScriptTestMethod(e.target.value)}
                      title={t("proxies.goCus.scriptTestMethod")}
                      className="shrink-0 rounded-lg border border-border bg-surface-hover px-2.5 py-2 font-mono text-xs text-gray-200 outline-none focus:border-accent"
                    >
                      {["GET", "POST", "PUT", "DELETE"].map((m) => (
                        <option key={m} value={m}>
                          {m}
                        </option>
                      ))}
                    </select>
                    <input
                      value={scriptTestUrl}
                      onChange={(e) => setScriptTestUrl(e.target.value)}
                      placeholder={t("proxies.goCus.scriptTestUrl")}
                      spellCheck={false}
                      className={`${INPUT_CLASS} flex-1 font-mono text-xs`}
                    />
                    <button
                      type="button"
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

                  {scriptType === "http-response" && (
                    <input
                      value={scriptTestMockResp}
                      onChange={(e) => setScriptTestMockResp(e.target.value)}
                      placeholder={t("proxies.goCus.scriptTestMockResp")}
                      spellCheck={false}
                      className={`${INPUT_CLASS} font-mono text-xs`}
                    />
                  )}

                  {scriptTestResult && (
                    <div className="space-y-2 border-t border-border pt-2">
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
                        {typeof scriptTestResult.durationMs === "number" && (
                          <span className="ml-auto text-[11px] tabular-nums text-gray-500">
                            {t("proxies.goCus.scriptTestDuration", {
                              ms: scriptTestResult.durationMs,
                            })}
                          </span>
                        )}
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
                      {scriptTestResult.notifications &&
                        scriptTestResult.notifications.length > 0 && (
                          <div>
                            <p className="mb-0.5 text-[11px] text-gray-500">
                              {t("proxies.goCus.scriptTestNotifications")}
                            </p>
                            <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-hover p-2 font-mono text-[11px] text-accent">
                              {scriptTestResult.notifications
                                .map(([title, sub, body]) =>
                                  [title, sub, body].filter(Boolean).join(" · "),
                                )
                                .join("\n")}
                            </pre>
                          </div>
                        )}
                      {scriptTestResult.request && (
                        <div>
                          <p className="mb-0.5 text-[11px] text-gray-500">
                            {t("proxies.goCus.scriptTestRequest")}
                          </p>
                          <pre className="max-h-36 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-hover p-2 font-mono text-[11px] text-gray-300">
                            {JSON.stringify(scriptTestResult.request, null, 2)}
                          </pre>
                        </div>
                      )}
                      {scriptTestResult.response && (
                        <div>
                          <p className="mb-0.5 text-[11px] text-gray-500">
                            {t("proxies.goCus.scriptTestResponse")}
                          </p>
                          <pre className="max-h-36 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-hover p-2 font-mono text-[11px] text-gray-300">
                            {JSON.stringify(scriptTestResult.response, null, 2)}
                          </pre>
                        </div>
                      )}
                      {!scriptTestResult.request &&
                        !scriptTestResult.response &&
                        scriptTestResult.done !== undefined &&
                        scriptTestResult.done !== null && (
                          <div>
                            <p className="mb-0.5 text-[11px] text-gray-500">
                              {t("proxies.goCus.scriptTestDone")}
                            </p>
                            <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-hover p-2 font-mono text-[11px] text-gray-300">
                              {JSON.stringify(scriptTestResult.done, null, 2)}
                            </pre>
                          </div>
                        )}
                    </div>
                  )}
                </div>
              </FormCard>
            )}

            {scripts.length >= 4 && (
              <div className="relative mb-2.5 mt-2">
                <Search
                  size={13}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
                />
                <input
                  value={scriptQuery}
                  onChange={(e) => setScriptQuery(e.target.value)}
                  placeholder={t("proxies.goCus.searchPlaceholder")}
                  className={`${INPUT_CLASS} pl-8 py-1.5 text-xs`}
                />
              </div>
            )}

            {scripts.length === 0 ? (
              <EmptyState
                icon={<FileCode2 size={28} />}
                title={t("proxies.goCus.noScripts")}
                description={t("proxies.goCus.noScriptsDesc")}
              />
            ) : filteredScripts.length === 0 ? (
              <p className="py-6 text-center text-xs text-gray-500">
                {t("proxies.goCus.noSearchMatch")}
              </p>
            ) : (
              <div className="mt-2 max-h-[28rem] w-full min-w-0 space-y-1.5 overflow-y-auto pr-1">
                {filteredScripts.map((s, i) => (
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
                        <p className="min-w-0 break-words text-xs font-semibold leading-snug text-gray-200">
                          {s.name}
                        </p>
                        <span className="text-[11px] text-gray-500">
                          {s.module}
                        </span>
                        <div className="ml-auto flex shrink-0 items-center gap-1.5">
                          <span className="text-[11px] tabular-nums text-gray-500">
                            {t("proxies.goCus.hits", {
                              count: ruleHits(
                                s.moduleId,
                                "sc",
                                s.ruleIndex,
                                s.pattern,
                              ),
                            })}
                          </span>
                          {s.isCustom && (
                            <>
                              <button
                                type="button"
                                onClick={() => openEditScript(s)}
                                title={t("proxies.goCus.edit")}
                                className="rounded p-1 text-gray-500 transition-colors hover:text-accent"
                              >
                                <Pencil size={12} />
                              </button>
                              <button
                                type="button"
                                onClick={() => void deleteScript(s)}
                                title={t("proxies.goCus.delete")}
                                className="rounded p-1 text-gray-500 transition-colors hover:text-latency-bad"
                              >
                                <Trash2 size={12} />
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                      {s.pattern && (
                        <p
                          className="mt-0.5 w-full min-w-0 break-all font-mono text-[11px] text-gray-400"
                          title={s.pattern}
                        >
                          {s.pattern}
                        </p>
                      )}
                      <button
                        type="button"
                        onClick={() =>
                          void copyText(
                            s.scriptPath,
                            t("proxies.goCus.scriptPathCopied"),
                          )
                        }
                        title={t("proxies.goCus.clickToCopy", {
                          path: s.scriptPath,
                        })}
                        className="mt-0.5 flex w-full min-w-0 items-center gap-1 text-left text-[11px] text-gray-500 transition-colors hover:text-accent"
                      >
                        <Copy size={11} className="shrink-0" />
                        <span className="min-w-0 break-all font-mono">
                          {s.scriptPath}
                        </span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
            <p className="mt-4 text-[11px] leading-relaxed text-gray-500 break-words">
              {t("proxies.goCus.scriptInlineNote")}
            </p>
          </div>
        )}

        {/* ============================== MitM ============================== */}
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
                onChange={(v) => void persist({ ...settings, mitmEnabled: v })}
                title={t("proxies.goCus.mitmSwitch")}
              />
            </div>

            {/* MitM 主机名列表 */}
            <div className="w-full max-w-full overflow-hidden rounded-2xl border border-border bg-surface-card p-5 box-border">
              <div className="mb-3 flex w-full min-w-0 flex-wrap items-center justify-between gap-1.5">
                <div className="flex items-center gap-2">
                  <Globe size={15} className="shrink-0 text-accent" />
                  <h3 className="text-sm font-semibold text-gray-100">
                    {t("proxies.goCus.mitmHostsTitle", {
                      count: mitmHosts.length,
                    })}
                  </h3>
                </div>
                <button
                  type="button"
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
                        type="button"
                        onClick={closeCreate}
                        className="rounded-lg border border-border px-3 py-1.5 text-xs text-gray-300 hover:text-gray-100"
                      >
                        {t("proxies.goCus.cancel")}
                      </button>
                      <button
                        type="button"
                        onClick={() => void saveMitm()}
                        disabled={savingCustom}
                        className="rounded-lg bg-accent px-3 py-1.5 text-xs font-bold text-white hover:bg-accent-hover disabled:opacity-50"
                      >
                        {t("proxies.goCus.save")}
                      </button>
                    </>
                  }
                >
                  <textarea
                    value={mitmInput}
                    onChange={(e) => setMitmInput(e.target.value)}
                    placeholder={t("proxies.goCus.mitmHostname")}
                    spellCheck={false}
                    rows={2}
                    className={`${INPUT_CLASS} resize-y font-mono text-xs`}
                  />
                  <p className="text-[11px] text-gray-500">
                    {t("proxies.goCus.mitmHostnameHint")}
                  </p>
                </FormCard>
              )}

              {mitmHosts.length >= 8 && (
                <div className="relative mb-2.5 mt-2">
                  <Search
                    size={13}
                    className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
                  />
                  <input
                    value={mitmQuery}
                    onChange={(e) => setMitmQuery(e.target.value)}
                    placeholder={t("proxies.goCus.searchPlaceholder")}
                    className={`${INPUT_CLASS} pl-8 py-1.5 text-xs`}
                  />
                </div>
              )}

              {mitmHosts.length === 0 ? (
                <p className="py-4 text-center text-sm text-gray-500">
                  {t("proxies.goCus.noMitmHosts")}
                </p>
              ) : filteredMitmHosts.length === 0 ? (
                <p className="py-4 text-center text-xs text-gray-500">
                  {t("proxies.goCus.noSearchMatch")}
                </p>
              ) : (
                <div className="mt-2 flex w-full min-w-0 flex-wrap gap-1.5">
                  {filteredMitmHosts.map((h) => (
                    <span
                      key={h.raw}
                      className={`inline-flex max-w-full items-center gap-1 rounded-md border px-2 py-1 font-mono text-[11px] ${
                        h.isExcluded
                          ? "border-latency-medium/30 bg-latency-medium/10 text-latency-medium"
                          : h.isWildcard
                            ? "border-accent/25 bg-accent/10 text-accent"
                            : "border-border bg-surface-hover text-gray-200"
                      }`}
                    >
                      <span className="break-all">{h.raw}</span>
                      {h.isExcluded && (
                        <span className="rounded bg-latency-medium/20 px-1 text-[9px] font-sans font-semibold">
                          {t("proxies.goCus.mitmExcluded")}
                        </span>
                      )}
                      {h.inCustomModule && (
                        <button
                          type="button"
                          onClick={() => void deleteMitmHost(h.raw)}
                          title={t("proxies.goCus.delete")}
                          className="ml-0.5 rounded p-0.5 opacity-70 transition-opacity hover:opacity-100"
                        >
                          <X size={10} />
                        </button>
                      )}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* CA 证书管理卡片 */}
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
                  type="button"
                  onClick={() => void loadCa()}
                  disabled={caBusy}
                  className="flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
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
                  <div className="mb-1 flex items-center justify-between">
                    <p className="text-xs text-gray-500">
                      {t("proxies.goCus.caFingerprint")}
                    </p>
                    {ca?.fingerprint && (
                      <button
                        type="button"
                        onClick={() =>
                          void copyText(
                            ca.fingerprint,
                            t("proxies.goCus.caFpCopied"),
                          )
                        }
                        className="flex items-center gap-1 text-[11px] text-gray-500 hover:text-accent"
                      >
                        <Copy size={10} />
                        {t("proxies.goCus.copy")}
                      </button>
                    )}
                  </div>
                  <p className="w-full min-w-0 break-all rounded-lg bg-surface-hover px-3 py-2 font-mono text-[11px] leading-relaxed text-gray-200">
                    {ca?.fingerprint ?? t("proxies.goCus.caUnknown")}
                  </p>
                </div>
                <div className="w-full min-w-0">
                  <p className="mb-1 text-xs text-gray-500">
                    {t("proxies.goCus.caValidity")}
                  </p>
                  <p className="w-full min-w-0 break-all rounded-lg bg-surface-hover px-3 py-2 font-mono text-[11px] leading-relaxed text-gray-200">
                    {caValidityText}
                  </p>
                </div>
              </div>

              {ca && (
                <div className="w-full min-w-0">
                  <p className="mb-1 text-xs text-gray-500">
                    {t("proxies.goCus.caInstallUrl")}
                  </p>
                  <div className="flex w-full min-w-0 flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() =>
                        void handleInstallCa(
                          platform.isApple ? "profile" : "cert",
                        )
                      }
                      title={platform.isApple ? ca.installUrl : ca.certUrl ?? ca.installUrl}
                      className="flex min-w-0 flex-1 items-center gap-1.5 truncate rounded-lg bg-surface-hover px-3 py-2 text-left font-mono text-[11px] text-accent transition-colors hover:underline"
                    >
                      <ExternalLink size={12} className="shrink-0" />
                      <span className="truncate">
                        {platform.isApple ? ca.installUrl : ca.certUrl ?? ca.installUrl}
                      </span>
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        void copyText(
                          platform.isApple
                            ? ca.installUrl
                            : ca.certUrl ?? ca.installUrl,
                          t("proxies.goCus.installCopied"),
                        )
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
                <button
                  type="button"
                  disabled={caBusy}
                  onClick={() =>
                    void handleInstallCa(platform.isApple ? "profile" : "cert")
                  }
                  className="flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg bg-surface-hover px-3 py-2 text-xs font-medium text-gray-200 transition-colors hover:bg-glass-strong disabled:opacity-50"
                >
                  <Download size={13} />
                  {platform.isApple
                    ? t("proxies.goCus.caDownloadProfile")
                    : t("proxies.goCus.caDownloadCert")}
                </button>
                <button
                  type="button"
                  disabled={caBusy}
                  onClick={() => void handleInstallCa("portal")}
                  className="flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg bg-surface-hover px-3 py-2 text-xs text-gray-400 transition-colors hover:text-gray-100 disabled:opacity-50"
                >
                  <ExternalLink size={12} />
                  {t("proxies.goCus.caOpenPortal")}
                </button>
                <label className="flex min-w-0 cursor-pointer items-start gap-2 text-xs leading-snug text-gray-300">
                  <input
                    type="checkbox"
                    checked={settings.caInstalled}
                    onChange={(e) =>
                      void persist({ ...settings, caInstalled: e.target.checked })
                    }
                    className="mt-0.5 h-4 w-4 shrink-0 accent-indigo-500"
                  />
                  <span className="min-w-0 break-words">
                    {t("proxies.goCus.caTrusted")}
                  </span>
                </label>
              </div>

              {platform.isIOS ? (
                <div className="w-full min-w-0">
                  <button
                    type="button"
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
      </div>
    </ProGate>
  );
}
