import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Check,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  ChevronDown,
  ChevronRight,
  Wifi,
  Network,
  Sliders,
  Cpu,
  Power,
  Globe,
  Blocks,
  RefreshCw,
  Fingerprint,
  Copy,
  Smartphone,
  AppWindow,
  Home,
  Languages,
  Palette,
} from "lucide-react";
import { getVersion } from "@tauri-apps/api/app";

import {
  getCoreStatus,
  getDeviceId,
  getKernelInfo,
  getSettings,
  saveSettings,
  setMode,
  getGoLanSettings,
  saveGoLanSettings,
  syncGoLanManaged,
  isGoLanConfigured,
  type KernelInfo,
  type EntitlementState,
  type GoLanSettings,
  type WgManualConfig,
} from "@/api/ipc";
import type { RunMode, UserSettings } from "@/stores/core";
import { useCoreStore } from "@/stores/core";
import { RUN_MODES } from "@/constants/modes";
import { ActivateProModal } from "@/components/ProGate";
import { useProStore } from "@/stores/pro";
import { toast } from "@/components/ui/Toast";
import { isMobile } from "@/pro/gating";
import Switch from "@/components/ui/Switch";
import { usePrefsStore, type Language, type ThemePref } from "@/stores/prefs";
import { useTranslation } from "@/i18n";
import clsx from "clsx";

/** 授权状态 → 文案 key 与状态点颜色 */
const STATUS_META: Record<EntitlementState, { key: string; dot: string }> = {
  active: { key: "pro.status.active", dot: "bg-latency-good" },
  offline: { key: "pro.status.offline", dot: "bg-yellow-400" },
  expired: { key: "pro.status.expired", dot: "bg-latency-bad" },
  revoked: { key: "pro.status.revoked", dot: "bg-latency-bad" },
  inactive: { key: "pro.status.inactive", dot: "bg-gray-500" },
};

/** 服务端方案名 → 文案 key（API: free=试用版 / pro=Pro 订阅版 / team=终身买断版） */
const PLAN_LABEL: Record<string, string> = {
  free: "pro.plan.free",
  pro: "pro.plan.pro",
  team: "pro.plan.team",
};

function fmtDate(secs: number | null): string {
  if (!secs) return "—";
  return new Date(secs * 1000).toLocaleDateString();
}

/** Unix 秒 → "YYYY-MM-DD HH:mm"（本地时区），用于展示授权到期时间 */
function fmtDateTime(secs: number | null): string {
  if (!secs) return "—";
  const d = new Date(secs * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** 距到期不足 3 天（用于「即将到期」黄色提醒） */
function expiringSoon(secs: number | null): boolean {
  if (!secs) return false;
  const diff = secs * 1000 - Date.now();
  return diff > 0 && diff < 3 * 86_400_000;
}

/// 接入模式图标
const RUN_MODE_ICON: Record<RunMode, typeof Wifi> = {
  systemProxy: Wifi,
  tun: Network,
};

// ---- Go Lan · 回家网络 ----

/// 手动配置方式：WireGuard 完整参数 / 回家节点分享链接
type GoLanMethod = "wg" | "uri";

/// Go Lan 卡片本地编辑表单（textarea 内容保持为多行字符串，保存时再拆分）
interface GoLanForm {
  enabled: boolean;
  mode: "manual" | "managed";
  method: GoLanMethod;
  nodeUri: string;
  wgServer: string;
  wgServerPort: number;
  wgPrivateKey: string;
  wgPeerPublicKey: string;
  wgPreSharedKey: string;
  wgLocalIp: string;
  wgMtu: number;
  lanCidrs: string;
  lanDns: string;
  lanDomains: string;
  managedServer: string;
  deviceCode: string;
}

const WG_DEFAULTS = { localIp: "10.0.0.2/32", mtu: 1420 };
const MANAGED_SERVER_DEFAULT = "https://prism.sarl";

const EMPTY_GO_LAN: GoLanForm = {
  enabled: false,
  mode: "manual",
  method: "wg",
  nodeUri: "",
  wgServer: "",
  wgServerPort: 0,
  wgPrivateKey: "",
  wgPeerPublicKey: "",
  wgPreSharedKey: "",
  wgLocalIp: WG_DEFAULTS.localIp,
  wgMtu: WG_DEFAULTS.mtu,
  lanCidrs: "",
  lanDns: "",
  lanDomains: "",
  managedServer: MANAGED_SERVER_DEFAULT,
  deviceCode: "",
};

/// 后端设置 → 本地编辑表单（数组字段反向 join 为多行文本）
function applyGoLanLoaded(s: GoLanSettings): GoLanForm {
  const wg = s.wgConfig ?? null;
  const method: GoLanMethod =
    wg && wg.server ? "wg" : s.nodeUri ? "uri" : "wg";
  return {
    enabled: s.enabled,
    mode: s.mode,
    method,
    nodeUri: s.nodeUri ?? "",
    wgServer: wg?.server ?? "",
    wgServerPort: wg?.serverPort ?? 0,
    wgPrivateKey: wg?.privateKey ?? "",
    wgPeerPublicKey: wg?.peerPublicKey ?? "",
    wgPreSharedKey: wg?.preSharedKey ?? "",
    wgLocalIp: wg?.localIp || WG_DEFAULTS.localIp,
    wgMtu: wg?.mtu || WG_DEFAULTS.mtu,
    lanCidrs: (s.lanCidrs ?? []).join("\n"),
    lanDns: s.lanDns ?? "",
    lanDomains: (s.lanDomains ?? []).join("\n"),
    managedServer: s.managedServer || MANAGED_SERVER_DEFAULT,
    deviceCode: s.deviceCode ?? "",
  };
}

export default function Settings() {
  const { t } = useTranslation();
  const [mode, setRunMode] = useState<RunMode>("systemProxy");
  const [modeBusy, setModeBusy] = useState(false);
  const [form, setForm] = useState<UserSettings>({
    mixedPort: 2080,
    allowLan: false,
    systemProxy: true,
    mode: "systemProxy",
    autoStart: false,
    outboundMode: "rule",
    ipv6: false,
    blockQuic: false,
    closeConnectionsOnSwitch: false,
    language: "system",
    theme: "system",
  });
  const [saved, setSaved] = useState(false);
  const mobile = isMobile();
  const [showActivate, setShowActivate] = useState(false);
  // ipa-8：移除授权的组件内二次确认（iOS WKWebView 会静默拦截 window.confirm 返回 false）
  const [confirmDeactivate, setConfirmDeactivate] = useState(false);
  const [deactivating, setDeactivating] = useState(false);
  const proUnlocked = useProStore((s) => s.unlocked);
  const proReady = useProStore((s) => s.ready);
  const entitlement = useProStore((s) => s.entitlement);
  const proBusy = useProStore((s) => s.busy);
  const refreshPro = useProStore((s) => s.refresh);
  const deactivatePro = useProStore((s) => s.deactivate);
  const tunGated = !proUnlocked;
  // ipa-9：Go Lan 是否渲染完整配置区（启动瞬间 ready=false 先渲染完整表单，避免闪烁）
  const goLanUnlocked = proUnlocked || !proReady;

  // 语言与外观偏好（全局 store，改动即时生效；同时持久化到后端 settings.json）
  const language = usePrefsStore((s) => s.language);
  const themePref = usePrefsStore((s) => s.theme);
  const setLanguage = usePrefsStore((s) => s.setLanguage);
  const setThemePref = usePrefsStore((s) => s.setTheme);

  // ipa-8：仪表盘 Go Lan 卡片「配置」跳转锚点——进入设置页后滚动定位到回家网络卡片
  const [searchParams] = useSearchParams();
  useEffect(() => {
    if (searchParams.get("focus") === "goLan") {
      const timer = setTimeout(() => {
        document
          .getElementById("go-lan-card")
          ?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 150);
      return () => clearTimeout(timer);
    }
  }, [searchParams]);

  const [kernelInfo, setKernelInfo] = useState<KernelInfo | null>(null);
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [appVersion, setAppVersion] = useState<string>("");

  // Go Lan · 回家网络（Pro）：拷贝后端设置到本地表单编辑
  const [goLan, setGoLan] = useState<GoLanForm>(EMPTY_GO_LAN);
  const [goLanLoaded, setGoLanLoaded] = useState<GoLanSettings | null>(null);
  const [goLanBusy, setGoLanBusy] = useState(false);
  const [goLanSyncing, setGoLanSyncing] = useState(false);
  // ipa-9：Go Lan 开关关闭时表单默认收起，点击「展开配置」后再显示
  const [goLanExpanded, setGoLanExpanded] = useState(false);

  useEffect(() => {
    getDeviceId()
      .then(setDeviceId)
      .catch((e) => console.error("get device id failed:", e));
    getVersion()
      .then(setAppVersion)
      .catch((e) => console.error("get app version failed:", e));
    getGoLanSettings()
      .then((s) => {
        setGoLanLoaded(s);
        setGoLan(applyGoLanLoaded(s));
      })
      .catch((e) => console.error("get go lan settings failed:", e));
  }, []);

  const copyDeviceId = async () => {
    if (!deviceId) return;
    try {
      await navigator.clipboard.writeText(deviceId);
      toast.success(t("pro.deviceIdCopy"));
    } catch {
      toast.error(t("common.copyFailed"));
    }
  };

  // ipa-8：「立即校验」直连后端强制联网校验（verify_remote_forced），完成后给出明确 Toast
  const handleVerifyEntitlement = async () => {
    await refreshPro();
    const s = useProStore.getState();
    if (s.error) {
      const m = s.error;
      if (m.startsWith("rate_limited:")) {
        toast.error(
          t("pro.verifyTooFrequent", { secs: m.split(":")[1] ?? "30" }),
        );
      } else {
        toast.error(m);
      }
      return;
    }
    const st = s.entitlement.status;
    if (st === "active") {
      toast.success(t("pro.verifySuccess"));
    } else if (st === "expired" || st === "revoked") {
      toast.error(t("pro.verifyExpired"));
    } else if (st === "offline") {
      toast.info(t("pro.verifyOffline"));
    } else {
      toast.info(t("pro.verifyNone"));
    }
  };

  // ipa-8：移除授权——组件内二次确认替代 window.confirm：
  // 第一次点击进入红色确认态（3 秒未点击自动恢复），第二次点击才真正执行移除
  const handleDeactivate = async () => {
    if (!confirmDeactivate) {
      setConfirmDeactivate(true);
      setTimeout(() => setConfirmDeactivate(false), 3000);
      return;
    }
    setDeactivating(true);
    try {
      await deactivatePro();
      toast.success(t("pro.removedToast"));
    } catch (e) {
      toast.error(String(e));
    } finally {
      setDeactivating(false);
      setConfirmDeactivate(false);
    }
  };

  useEffect(() => {
    getSettings()
      .then((s) => setForm(s))
      .catch((e) => console.error(e));
    getCoreStatus()
      .then((data) => {
        setRunMode(data.mode);
        useCoreStore.getState().setMode(data.mode);
        // 出站模式以内核当前状态为权威（热切换后与 settings.json 一致）
        if (data.outboundMode) {
          useCoreStore.getState().setOutboundMode(data.outboundMode);
          // 表单同步内核当前模式：避免用户在仪表盘切换后，设置页「保存」
          // 把过期的 form.outboundMode 覆盖回 settings.json
          setForm((f) => ({ ...f, outboundMode: data.outboundMode }));
        }
      })
      .catch(() => undefined);
    getKernelInfo()
      .then(setKernelInfo)
      .catch((e) => console.error(e));
  }, []);

  const patch = (p: Partial<UserSettings>) => {
    setForm((f) => ({ ...f, ...p }));
    setSaved(false);
  };

  /// 语言 / 外观：立即生效 + 立即持久化（无需再点「保存」）
  const patchPrefs = (p: Partial<UserSettings>) => {
    const next = { ...form, ...p };
    setForm(next);
    saveSettings(next).catch(() => undefined);
  };

  const chooseLanguage = (l: Language) => {
    setLanguage(l);
    patchPrefs({ language: l });
  };

  const chooseTheme = (th: ThemePref) => {
    setThemePref(th);
    patchPrefs({ theme: th });
  };

  const chooseMode = async (m: RunMode) => {
    if (m === "tun" && tunGated) {
      setShowActivate(true);
      return;
    }
    if (modeBusy || m === mode) return;
    setRunMode(m);
    setForm((f) => ({ ...f, mode: m }));
    useCoreStore.getState().setMode(m);
    setSaved(false);
    setModeBusy(true);
    try {
      await setMode(m);
      const data = await getCoreStatus();
      useCoreStore.getState().setStatus(data.status);
      useCoreStore.getState().setMode(data.mode);
      toast.success(
        data.status === "running"
          ? t("settings.modeSwitchedRunning")
          : t("settings.modeSwitchedNext")
      );
    } catch (e) {
      console.error(e);
      toast.error(String(e));
    } finally {
      setModeBusy(false);
    }
  };

  const handleSave = async () => {
    try {
      await saveSettings(form);
      setSaved(true);
    } catch (e) {
      console.error("save settings failed:", e);
    }
  };

  const patchGoLan = (p: Partial<GoLanForm>) => setGoLan((f) => ({ ...f, ...p }));

  /// 本地表单 → 后端设置（多行文本按行拆分并过滤空行；保留 cachedManagedOutbound 等未编辑字段）
  const buildGoLanPayload = (): GoLanSettings => {
    const base: GoLanSettings = goLanLoaded ?? ({} as GoLanSettings);
    const wgAnyFilled = [
      goLan.wgServer,
      goLan.wgPrivateKey,
      goLan.wgPeerPublicKey,
      goLan.wgPreSharedKey,
    ].some((v) => v.trim() !== "");
    const wgConfig: WgManualConfig | null =
      goLan.mode === "manual" && goLan.method === "wg" && wgAnyFilled
        ? {
            server: goLan.wgServer.trim(),
            serverPort: goLan.wgServerPort || 0,
            privateKey: goLan.wgPrivateKey.trim(),
            peerPublicKey: goLan.wgPeerPublicKey.trim(),
            preSharedKey: goLan.wgPreSharedKey.trim() || null,
            localIp: goLan.wgLocalIp.trim() || WG_DEFAULTS.localIp,
            mtu: goLan.wgMtu || WG_DEFAULTS.mtu,
          }
        : null;
    return {
      ...base,
      enabled: goLan.enabled,
      mode: goLan.mode,
      nodeUri: goLan.nodeUri.trim(),
      wgConfig,
      lanCidrs: goLan.lanCidrs
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean),
      lanDns: goLan.lanDns.trim() || null,
      lanDomains: goLan.lanDomains
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean),
      managedServer: goLan.managedServer.trim() || MANAGED_SERVER_DEFAULT,
      deviceCode: goLan.deviceCode.trim(),
    };
  };

  const handleGoLanSave = async () => {
    // WireGuard 手动配置：任一字段非空时，server / 私钥 / Peer 公钥必填
    if (goLan.mode === "manual" && goLan.method === "wg") {
      const anyFilled = [
        goLan.wgServer,
        goLan.wgPrivateKey,
        goLan.wgPeerPublicKey,
        goLan.wgPreSharedKey,
      ].some((v) => v.trim() !== "");
      if (
        anyFilled &&
        (!goLan.wgServer.trim() ||
          !goLan.wgPrivateKey.trim() ||
          !goLan.wgPeerPublicKey.trim())
      ) {
        toast.error(t("settings.goLan.invalidWg"));
        return;
      }
    }
    setGoLanBusy(true);
    try {
      const warnings = await saveGoLanSettings(buildGoLanPayload());
      if (warnings && warnings.length > 0) {
        warnings.forEach((w) => toast.info(w));
      }
      toast.success(t("settings.goLan.saveToast"));
    } catch (e) {
      toast.error(String(e));
    } finally {
      setGoLanBusy(false);
    }
  };

  const handleGoLanSync = async () => {
    setGoLanSyncing(true);
    try {
      const s = await syncGoLanManaged();
      setGoLanLoaded(s);
      setGoLan(applyGoLanLoaded(s));
      toast.success(t("settings.goLan.syncToast"));
    } catch (e) {
      toast.error(String(e));
    } finally {
      setGoLanSyncing(false);
    }
  };

  const runModes = MODES.filter((m) => (mobile ? m.key === "tun" : true));

  return (
    <div className="space-y-5 max-w-3xl">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t("settings.title")}</h1>
        <button
          onClick={handleSave}
          className={clsx(
            "px-4 py-1.5 rounded-lg text-sm font-medium transition-colors",
            saved
              ? "bg-latency-good/20 text-latency-good"
              : "bg-accent hover:bg-accent-hover text-white"
          )}
        >
          {saved ? (
            <span className="flex items-center gap-1">
              <Check size={14} />
              {t("common.saved")}
            </span>
          ) : (
            t("common.save")
          )}
        </button>
      </div>

      {/* 外观与语言：语言 / 深浅色外观，均可跟随系统 */}
      <SettingsGroup
        title={t("settings.appearance")}
        icon={<Palette size={14} />}
        desc={t("settings.appearanceDesc")}
      >
        <div className="flex flex-wrap items-center justify-between gap-3 px-3 py-3 border-b border-border">
          <div className="flex items-center gap-3">
            <RowIcon>
              <Languages size={16} className="text-gray-400" />
            </RowIcon>
            <div className="text-sm">{t("settings.language")}</div>
          </div>
          <Segmented
            value={language}
            onChange={(v) => chooseLanguage(v as Language)}
            options={[
              { value: "system", label: t("settings.language.system") },
              { value: "zh", label: t("settings.language.zh") },
              { value: "en", label: t("settings.language.en") },
            ]}
          />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 px-3 py-3">
          <div className="flex items-center gap-3">
            <RowIcon>
              <Palette size={16} className="text-gray-400" />
            </RowIcon>
            <div className="text-sm">{t("settings.theme")}</div>
          </div>
          <Segmented
            value={themePref}
            onChange={(v) => chooseTheme(v as ThemePref)}
            options={[
              { value: "system", label: t("settings.theme.system") },
              { value: "dark", label: t("settings.theme.dark") },
              { value: "light", label: t("settings.theme.light") },
            ]}
          />
        </div>
      </SettingsGroup>

      {/* 接入模式：iOS/Android 系统强制 TUN 接管，无切换意义，移动端不渲染 */}
      {!mobile && (
        <SettingsGroup
          title={t("settings.mode")}
          icon={<Wifi size={14} />}
          desc={t("settings.modeDesc")}
        >
          {runModes.map((m) => {
            const Icon = RUN_MODE_ICON[m.key] ?? Wifi;
            const active = mode === m.key;
            return (
              <button
                key={m.key}
                onClick={() => chooseMode(m.key)}
                disabled={modeBusy}
                className="w-full text-left disabled:opacity-60"
              >
                <Row
                  icon={
                    <Icon size={16} className={active ? "text-accent" : "text-gray-400"} />
                  }
                  iconBg={active ? "bg-accent/10" : "bg-glass"}
                  title={
                    <span className="flex items-center gap-1.5">
                      {m.title}
                      {m.key === "tun" && tunGated && (
                        <Lock size={12} className="text-accent" />
                      )}
                    </span>
                  }
                  value={active ? t("settings.modeSelected") : ""}
                  chevron={!active}
                  valueClass={active ? "text-accent" : ""}
                />
              </button>
            );
          })}
          {modeBusy && (
            <div className="px-3 py-2 text-xs text-gray-400 border-t border-border">
              {t("settings.modeSwitching")}
            </div>
          )}
          {mode === "tun" && (
            <div className="px-3 py-2.5 flex items-start gap-2 bg-yellow-500/5 text-yellow-400 text-xs border-t border-border">
              <ShieldAlert size={14} className="mt-0.5 shrink-0" />
              {t("settings.tunHint")}
            </div>
          )}
        </SettingsGroup>
      )}

      {/* 本地入站 */}
      <SettingsGroup title={t("settings.inbound")} icon={<Network size={14} />}>
        <div className="flex items-center justify-between overflow-hidden px-3 py-3 border-b border-border">
          <div className="flex items-center gap-3">
            <RowIcon><Network size={16} className="text-gray-400" /></RowIcon>
            <div>
              <div className="text-sm">{t("settings.mixedPort")}</div>
              <div className="text-[11px] text-gray-500">{t("settings.mixedPortDesc")}</div>
            </div>
          </div>
          <input
            type="number"
            min={1}
            max={65535}
            value={form.mixedPort}
            onChange={(e) => patch({ mixedPort: Number(e.target.value) })}
            className="w-24 px-3 py-1.5 rounded-lg bg-surface-hover border border-border focus:border-accent outline-none text-sm text-right"
          />
        </div>
        <ToggleRow
          icon={<Globe size={16} className="text-gray-400" />}
          title={t("settings.allowLan")}
          desc={t("settings.allowLanDesc")}
          checked={form.allowLan}
          onChange={(v) => patch({ allowLan: v })}
        />
        {!mobile && (
          <ToggleRow
            icon={<Wifi size={16} className="text-gray-400" />}
            title={t("settings.systemProxy")}
            desc={t("settings.systemProxyDesc")}
            checked={form.systemProxy}
            onChange={(v) => patch({ systemProxy: v })}
          />
        )}
        {!mobile && (
          <ToggleRow
            icon={<Power size={16} className="text-gray-400" />}
            title={t("settings.autoStart")}
            desc={t("settings.autoStartDesc")}
            checked={form.autoStart}
            onChange={(v) => patch({ autoStart: v })}
          />
        )}
      </SettingsGroup>

      {/* Go Lan · 回家网络（Pro 门控，ipa-9：未激活时绝不渲染长表单，
          只渲染一张与普通设置行高度一致的紧凑单行引导卡；
          id 供仪表盘「配置」按钮跳转定位） */}
      {!goLanUnlocked ? (
        <div className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface-card px-4 py-3.5">
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent/15">
              <Home size={15} className="text-accent" />
            </span>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="whitespace-nowrap text-sm font-semibold text-gray-100">
                  {t("settings.goLan.lockedTitle")}
                </span>
                <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] font-medium text-accent">
                  PRO
                </span>
              </div>
              <p className="mt-0.5 truncate text-xs text-gray-500">
                {t("settings.goLan.lockedDesc")}
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowActivate(true)}
            className="shrink-0 rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover"
          >
            {t("pro.activatePro")}
          </button>
        </div>
      ) : (
        <SettingsGroup
          id="go-lan-card"
          title={t("settings.goLan.title")}
          icon={<Home size={14} />}
          desc={t("settings.goLan.desc")}
          headerRight={
            <Switch
              checked={goLan.enabled}
              onChange={(v) => {
                // APP 任务5：未配置时拦截开启，Toast 引导并展开配置区
                if (v && !isGoLanConfigured(buildGoLanPayload())) {
                  toast.error(t("dashboard.lan.configureFirst"));
                  setGoLanExpanded(true);
                  return;
                }
                patchGoLan({ enabled: v });
              }}
            />
          }
        >
          {/* ipa-9：开关关闭时表单默认收起，点击「展开配置」后再显示，保持页面清爽 */}
          {!goLan.enabled && (
            <div className="px-3 pt-3">
              <button
                onClick={() => setGoLanExpanded((v) => !v)}
                className="flex items-center gap-1 text-xs text-gray-400 transition-colors hover:text-accent"
              >
                <ChevronDown
                  size={12}
                  className={
                    goLanExpanded ? "rotate-180 transition-transform" : "transition-transform"
                  }
                />
                {goLanExpanded ? t("common.collapse") : t("common.expand")}
              </button>
            </div>
          )}
          {(goLan.enabled || goLanExpanded) && (
          <>
          <div className="space-y-4 px-3 py-3">
            {/* 模式：手动配置 / 托管下发 */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => patchGoLan({ mode: "manual" })}
                className={clsx(
                  "rounded-full px-3 py-1 text-xs transition-colors",
                  goLan.mode === "manual"
                    ? "bg-accent text-white"
                    : "bg-surface-hover text-gray-400 hover:text-gray-200"
                )}
              >
                {t("settings.goLan.manual")}
              </button>
              <button
                onClick={() => patchGoLan({ mode: "managed" })}
                className={clsx(
                  "rounded-full px-3 py-1 text-xs transition-colors",
                  goLan.mode === "managed"
                    ? "bg-accent text-white"
                    : "bg-surface-hover text-gray-400 hover:text-gray-200"
                )}
              >
                {t("settings.goLan.managed")}
              </button>
            </div>

            {goLan.mode === "manual" && (
              <>
                {/* 手动方式：WireGuard 参数 / 节点分享链接 */}
                <div className="flex w-fit items-center gap-1 rounded-lg bg-surface-hover p-0.5 text-xs">
                  <button
                    onClick={() => patchGoLan({ method: "wg" })}
                    className={clsx(
                      "rounded-md px-2.5 py-1 transition-colors",
                      goLan.method === "wg"
                        ? "bg-surface-card text-gray-100"
                        : "text-gray-500 hover:text-gray-300"
                    )}
                  >
                    {t("settings.goLan.wg")}
                  </button>
                  <button
                    onClick={() => patchGoLan({ method: "uri" })}
                    className={clsx(
                      "rounded-md px-2.5 py-1 transition-colors",
                      goLan.method === "uri"
                        ? "bg-surface-card text-gray-100"
                        : "text-gray-500 hover:text-gray-300"
                    )}
                  >
                    {t("settings.goLan.uri")}
                  </button>
                </div>

                {goLan.method === "wg" ? (
                  <div className="space-y-3">
                    <div className="flex gap-2">
                      <GoLanField label={t("settings.goLan.server")} className="flex-1">
                        <input
                          type="text"
                          value={goLan.wgServer}
                          onChange={(e) =>
                            patchGoLan({ wgServer: e.target.value })
                          }
                          placeholder="vpn.home.example.com"
                          spellCheck={false}
                          autoComplete="off"
                          className={GO_LAN_INPUT}
                        />
                      </GoLanField>
                      <GoLanField label={t("settings.goLan.port")} className="w-24 shrink-0">
                        <input
                          type="number"
                          min={0}
                          max={65535}
                          value={goLan.wgServerPort}
                          onChange={(e) =>
                            patchGoLan({ wgServerPort: Number(e.target.value) })
                          }
                          placeholder="51820"
                          className={clsx(GO_LAN_INPUT, "text-right")}
                        />
                      </GoLanField>
                    </div>
                    <GoLanField label={t("settings.goLan.privateKey")}>
                      <input
                        type="password"
                        value={goLan.wgPrivateKey}
                        onChange={(e) =>
                          patchGoLan({ wgPrivateKey: e.target.value })
                        }
                        placeholder={t("settings.goLan.privateKeyPlaceholder")}
                        autoComplete="off"
                        spellCheck={false}
                        className={GO_LAN_INPUT}
                      />
                    </GoLanField>
                    <GoLanField label={t("settings.goLan.peerPublicKey")}>
                      <input
                        type="text"
                        value={goLan.wgPeerPublicKey}
                        onChange={(e) =>
                          patchGoLan({ wgPeerPublicKey: e.target.value })
                        }
                        placeholder={t("settings.goLan.peerPublicKeyPlaceholder")}
                        autoComplete="off"
                        spellCheck={false}
                        className={GO_LAN_INPUT}
                      />
                    </GoLanField>
                    <GoLanField label={t("settings.goLan.psk")}>
                      <input
                        type="password"
                        value={goLan.wgPreSharedKey}
                        onChange={(e) =>
                          patchGoLan({ wgPreSharedKey: e.target.value })
                        }
                        placeholder={t("settings.goLan.pskPlaceholder")}
                        autoComplete="off"
                        spellCheck={false}
                        className={GO_LAN_INPUT}
                      />
                    </GoLanField>
                    <div className="flex gap-2">
                      <GoLanField
                        label={t("settings.goLan.localIp")}
                        className="flex-1"
                      >
                        <input
                          type="text"
                          value={goLan.wgLocalIp}
                          onChange={(e) =>
                            patchGoLan({ wgLocalIp: e.target.value })
                          }
                          placeholder={WG_DEFAULTS.localIp}
                          spellCheck={false}
                          autoComplete="off"
                          className={GO_LAN_INPUT}
                        />
                      </GoLanField>
                      <GoLanField label={t("settings.goLan.mtu")} className="w-24 shrink-0">
                        <input
                          type="number"
                          min={576}
                          max={65535}
                          value={goLan.wgMtu}
                          onChange={(e) =>
                            patchGoLan({ wgMtu: Number(e.target.value) })
                          }
                          placeholder={String(WG_DEFAULTS.mtu)}
                          className={clsx(GO_LAN_INPUT, "text-right")}
                        />
                      </GoLanField>
                    </div>
                  </div>
                ) : (
                  <GoLanField
                    label={t("settings.goLan.nodeLink")}
                    hint={t("settings.goLan.nodeLinkHint")}
                  >
                    <textarea
                      rows={3}
                      value={goLan.nodeUri}
                      onChange={(e) => patchGoLan({ nodeUri: e.target.value })}
                      placeholder="vless://…"
                      spellCheck={false}
                      className={clsx(
                        GO_LAN_INPUT,
                        "resize-none font-mono text-xs leading-relaxed"
                      )}
                    />
                  </GoLanField>
                )}
              </>
            )}

            {goLan.mode === "managed" && (
              <div className="space-y-3">
                <GoLanField
                  label={t("settings.goLan.managedServer")}
                  hint={t("settings.goLan.managedServerHint")}
                >
                  <input
                    type="text"
                    value={goLan.managedServer}
                    onChange={(e) =>
                      patchGoLan({ managedServer: e.target.value })
                    }
                    placeholder={MANAGED_SERVER_DEFAULT}
                    spellCheck={false}
                    autoComplete="off"
                    className={GO_LAN_INPUT}
                  />
                </GoLanField>
                <GoLanField label={t("settings.goLan.deviceCode")}>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={goLan.deviceCode}
                      onChange={(e) =>
                        patchGoLan({ deviceCode: e.target.value })
                      }
                      placeholder={t("settings.goLan.deviceCodePlaceholder")}
                      spellCheck={false}
                      autoComplete="off"
                      className={clsx(GO_LAN_INPUT, "flex-1")}
                    />
                    <button
                      onClick={handleGoLanSync}
                      disabled={goLanSyncing}
                      className="flex shrink-0 items-center gap-1.5 rounded-lg bg-surface-hover px-3 py-2 text-xs transition-colors hover:bg-glass-strong disabled:opacity-50"
                    >
                      <RefreshCw
                        size={12}
                        className={goLanSyncing ? "animate-spin" : ""}
                      />
                      {goLanSyncing ? t("common.syncing") : t("common.sync")}
                    </button>
                  </div>
                </GoLanField>
              </div>
            )}

            {/* 通用字段：回家目标（网段 / DNS / 域名后缀） */}
            <div className="space-y-3 border-t border-border pt-3">
              <GoLanField
                label={t("settings.goLan.lanCidrs")}
                hint={t("settings.goLan.lanCidrsHint")}
              >
                <textarea
                  rows={2}
                  value={goLan.lanCidrs}
                  onChange={(e) => patchGoLan({ lanCidrs: e.target.value })}
                  placeholder={"192.168.1.0/24\n10.8.0.0/24"}
                  spellCheck={false}
                  className={clsx(GO_LAN_INPUT, "resize-none font-mono text-xs leading-relaxed")}
                />
              </GoLanField>
              <GoLanField label={t("settings.goLan.lanDns")}>
                <input
                  type="text"
                  value={goLan.lanDns}
                  onChange={(e) => patchGoLan({ lanDns: e.target.value })}
                  placeholder="192.168.1.1"
                  spellCheck={false}
                  autoComplete="off"
                  className={GO_LAN_INPUT}
                />
              </GoLanField>
              <GoLanField
                label={t("settings.goLan.lanDomains")}
                hint={t("settings.goLan.lanDomainsHint")}
              >
                <textarea
                  rows={2}
                  value={goLan.lanDomains}
                  onChange={(e) => patchGoLan({ lanDomains: e.target.value })}
                  placeholder={"nas.home\nrouter.home"}
                  spellCheck={false}
                  className={clsx(GO_LAN_INPUT, "resize-none font-mono text-xs leading-relaxed")}
                />
              </GoLanField>
            </div>
          </div>

          <div className="flex justify-end px-3 pb-3">
            <button
              onClick={handleGoLanSave}
              disabled={goLanBusy}
              className="flex items-center gap-1.5 rounded-lg bg-accent px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
            >
              <RefreshCw size={12} className={goLanBusy ? "animate-spin" : ""} />
              {t("common.save")}
            </button>
          </div>
          </>
          )}
        </SettingsGroup>
      )}

      {/* 高级 */}
      <SettingsGroup
        title={t("settings.advanced")}
        icon={<Sliders size={14} />}
        desc={t("settings.advancedDesc")}
      >
        <ToggleRow
          icon={<Globe size={16} className="text-gray-400" />}
          title={t("settings.ipv6")}
          desc={t("settings.ipv6Desc")}
          checked={form.ipv6 ?? false}
          onChange={(v) => patch({ ipv6: v })}
        />
        <ToggleRow
          icon={<Blocks size={16} className="text-gray-400" />}
          title={t("settings.blockQuic")}
          desc={t("settings.blockQuicDesc")}
          checked={form.blockQuic ?? false}
          onChange={(v) => patch({ blockQuic: v })}
        />
        <ToggleRow
          icon={<RefreshCw size={16} className="text-gray-400" />}
          title={t("settings.closeConns")}
          desc={t("settings.closeConnsDesc")}
          checked={form.closeConnectionsOnSwitch ?? false}
          onChange={(v) => patch({ closeConnectionsOnSwitch: v })}
        />
      </SettingsGroup>

      {/* 代理内核：仅保留版本状态展示行；启动时后台自动校验，无需手动按钮 */}
      <SettingsGroup title={t("settings.kernel")} icon={<Cpu size={14} />}>
        <Row
          icon={
            <ShieldCheck
              size={16}
              className={kernelInfo?.exists ? "text-latency-good" : "text-latency-bad"}
            />
          }
          iconBg={kernelInfo?.exists ? "bg-latency-good/10" : "bg-latency-bad/10"}
          title={
            kernelInfo?.exists
              ? `${t("settings.kernelInstalled")}${kernelInfo.version ? ` · v${kernelInfo.version}` : ""}`
              : t("settings.kernelMissing")
          }
          value={kernelInfo?.exists ? "" : t("settings.kernelReinstall")}
          valueClass="text-latency-bad"
        />
        {kernelInfo?.path && (
          <div className="px-3 py-2 text-[11px] font-mono break-all text-gray-500 border-t border-border">
            {kernelInfo.path}
          </div>
        )}
      </SettingsGroup>

      {/* Prism Pro 授权卡片：未授权展示设备 ID + 激活入口；已授权展示协议授权信息 */}
      <SettingsGroup
        title={t("pro.title")}
        icon={<Sparkles size={14} className="text-accent" />}
        headerRight={
          <span className="flex items-center gap-1.5 text-xs text-gray-400">
            <span
              className={`inline-block w-1.5 h-1.5 rounded-full ${STATUS_META[entitlement.status].dot}`}
            />
            {statusTextT(entitlement.plan, entitlement.status, t)}
          </span>
        }
      >
        {entitlement.status === "offline" && (
          <div className="flex items-start gap-2 px-3 py-2.5 bg-yellow-500/5 text-yellow-400 text-xs border-b border-border">
            <ShieldAlert size={14} className="mt-0.5 shrink-0" />
            <span>{t("pro.offlineBanner")}</span>
          </div>
        )}

        {/* 已到期：红色提示行（后端已自动停止全部 Pro 功能） */}
        {entitlement.status === "expired" && (
          <div className="flex items-start gap-2 px-3 py-2.5 bg-latency-bad/5 text-latency-bad text-xs border-b border-border">
            <ShieldAlert size={14} className="mt-0.5 shrink-0" />
            <span>
              {t("pro.expiredAt", {
                time: fmtDateTime(entitlement.expiresAt),
              })}
            </span>
          </div>
        )}

        {/* 设备 ID：激活时与服务端绑定，点击复制 */}
        <button
          onClick={copyDeviceId}
          className="w-full flex items-center justify-between gap-3 overflow-hidden px-3 py-3 border-b border-border text-left transition-colors hover:bg-surface-hover/40"
        >
          <span className="flex items-center gap-3 min-w-0">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-glass">
              <Fingerprint size={16} className="text-gray-400" />
            </span>
            <span className="min-w-0">
              <span className="block text-sm">{t("pro.deviceId")}</span>
              <span className="block text-[11px] text-gray-500">
                {t("pro.deviceIdHint")}
              </span>
            </span>
          </span>
          <span className="flex min-w-0 items-center gap-1.5 text-[11px] font-mono text-gray-400">
            <span className="max-w-[150px] truncate">{deviceId ?? t("common.loading")}</span>
            <Copy size={12} className="shrink-0 text-gray-500" />
          </span>
        </button>

        {/* APP 版本：当前安装的 Prism 版本号 */}
        <Row
          icon={<AppWindow size={16} className="text-gray-400" />}
          iconBg="bg-glass"
          title={t("pro.appVersion")}
          value={appVersion ? `v${appVersion}` : "—"}
        />

        {proUnlocked ? (
          <>
            <Row
              icon={<Sparkles size={16} className="text-accent" />}
              iconBg="bg-accent/10"
              title={t("pro.currentPlan")}
              value={planTextT(entitlement.plan, entitlement.kind, t)}
            />
            <Row
              icon={<Check size={16} className="text-gray-400" />}
              iconBg="bg-glass"
              title={t("pro.expiry")}
              value={
                <span className="flex items-center gap-1.5">
                  {entitlement.plan === "team" ||
                  (entitlement.kind === "lifetime" && !entitlement.expiresAt)
                    ? t("pro.permanent")
                    : fmtDateTime(entitlement.expiresAt)}
                  {expiringSoon(entitlement.expiresAt) && (
                    <span className="text-[11px] text-yellow-400">
                      {t("pro.expiringSoon")}
                    </span>
                  )}
                </span>
              }
            />
            {entitlement.maxSeats != null && (
              <Row
                icon={<Smartphone size={16} className="text-gray-400" />}
                iconBg="bg-glass"
                title={t("pro.seats")}
                value={`${entitlement.usedSeats ?? "?"} / ${entitlement.maxSeats}`}
              />
            )}
            <Row
              icon={<RefreshCw size={16} className="text-gray-400" />}
              iconBg="bg-glass"
              title={t("pro.lastVerify")}
              value={fmtDate(entitlement.lastVerifiedAt)}
            />
            <div className="flex flex-wrap gap-2 px-3 py-3 border-t border-border">
              <button
                onClick={handleVerifyEntitlement}
                disabled={proBusy}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-surface-hover hover:bg-glass-strong text-xs transition-colors disabled:opacity-50"
              >
                <RefreshCw size={12} className={proBusy ? "animate-spin" : ""} />
                {proBusy ? t("pro.licensingBusy") : t("pro.verifyNow")}
              </button>
              <button
                onClick={handleDeactivate}
                disabled={deactivating}
                className={clsx(
                  "px-3 py-2 rounded-lg text-xs transition-colors disabled:opacity-50",
                  confirmDeactivate
                    ? "bg-latency-bad/20 text-latency-bad hover:bg-latency-bad/30"
                    : "bg-surface-hover hover:bg-latency-bad/20 text-gray-400 hover:text-latency-bad"
                )}
              >
                {confirmDeactivate ? t("pro.removeConfirm") : t("pro.remove")}
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="space-y-2 border-b border-border px-3 py-3">
              <div className="text-xs font-medium text-gray-200">
                {t("pro.benefitsTitle")}
              </div>
              <ul className="space-y-1 text-[11px] leading-relaxed text-gray-500">
                <li>
                  •{" "}
                  <span className="font-medium text-gray-300">
                    {t("pro.name.goAim")}
                  </span>
                  {t("pro.benefit1")}
                </li>
                <li>
                  •{" "}
                  <span className="font-medium text-gray-300">
                    {t("pro.name.goLan")}
                  </span>
                  {t("pro.benefit2")}
                </li>
                <li>
                  •{" "}
                  <span className="font-medium text-gray-300">
                    {t("pro.name.goCus")}
                  </span>
                  {t("pro.benefit3")}
                </li>
                <li>
                  •{" "}
                  <span className="font-medium text-gray-300">{t("pro.name.sync")}</span>
                  {t("pro.benefit4")}
                </li>
              </ul>
              <div className="border-t border-border pt-1 text-[11px] text-gray-500/80">
                {t("pro.seatsHint")}
              </div>
            </div>
            <div className="flex flex-wrap gap-2 px-3 py-3">
              <button
                onClick={() => setShowActivate(true)}
                className="flex-1 min-w-[120px] flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white text-xs font-medium transition-colors"
              >
                <Sparkles size={12} />
                {entitlement.status === "expired"
                  ? t("pro.reactivate")
                  : t("pro.activateNow")}
              </button>
              <button
                onClick={handleVerifyEntitlement}
                disabled={proBusy}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-surface-hover hover:bg-glass-strong text-xs transition-colors disabled:opacity-50"
              >
                <RefreshCw size={12} className={proBusy ? "animate-spin" : ""} />
                {proBusy ? t("pro.licensingBusy") : t("pro.verifyNow")}
              </button>
            </div>
          </>
        )}
      </SettingsGroup>

      <ActivateProModal
        open={showActivate}
        onClose={() => setShowActivate(false)}
      />
    </div>
  );
}

const MODES = RUN_MODES;

/** 主标题右侧状态标签：激活后按档位显示，未激活沿用状态文案 */
function statusTextT(
  plan: string | null,
  status: EntitlementState,
  t: (k: string) => string,
): string {
  if (status !== "active") return t(STATUS_META[status].key);
  if (plan === "team") return t("pro.status.teamPermanent");
  if (plan === "pro") return t("pro.status.proActive");
  if (plan === "free") return t("pro.status.freeActive");
  return t("pro.status.active");
}

/** 方案名展示 */
function planTextT(
  plan: string | null,
  kind: string | null,
  t: (k: string) => string,
): string {
  if (plan && PLAN_LABEL[plan]) return t(PLAN_LABEL[plan]);
  if (kind === "lifetime") return t("pro.plan.lifetime");
  if (kind === "subscription") return t("pro.plan.subscription");
  return "—";
}

// ---- 复用组件 ----

/// Go Lan 卡片输入框统一样式
const GO_LAN_INPUT =
  "w-full rounded-lg border border-border bg-surface-hover px-3 py-2 text-sm outline-none focus:border-accent";

/// 分段切换器（语言 / 外观等三态选择）
function Segmented({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <div className="flex items-center gap-1 rounded-lg bg-surface-hover p-0.5 text-xs">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={clsx(
            "rounded-md px-2.5 py-1 whitespace-nowrap transition-colors",
            value === o.value
              ? "bg-accent text-white"
              : "text-gray-400 hover:text-gray-200"
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/// Go Lan 字段容器：label + 输入控件 + 可选说明
function GoLanField({
  label,
  hint,
  className,
  children,
}: {
  label: string;
  hint?: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={clsx("min-w-0 space-y-1", className)}>
      <label className="block text-xs text-gray-400">{label}</label>
      {children}
      {hint && <p className="text-[11px] text-gray-600">{hint}</p>}
    </div>
  );
}

function SettingsGroup({
  title,
  desc,
  icon,
  headerRight,
  children,
  id,
}: {
  title: string;
  desc?: string;
  icon?: React.ReactNode;
  headerRight?: React.ReactNode;
  children: React.ReactNode;
  /** DOM 锚点：供其他页面跳转定位（如仪表盘 Go Lan「配置」按钮） */
  id?: string;
}) {
  return (
    <section id={id}>
      <div className="flex items-center justify-between px-3 mb-1.5">
        <div className="flex items-center gap-1.5 text-xs font-medium text-gray-400 uppercase tracking-wide">
          {icon}
          <span>{title}</span>
        </div>
        {headerRight}
      </div>
      {desc && (
        <p className="px-3 mb-1.5 text-[11px] text-gray-500 leading-relaxed">
          {desc}
        </p>
      )}
      <div className="rounded-xl bg-surface-card border border-border overflow-hidden">
        {children}
      </div>
    </section>
  );
}

function RowIcon({ children }: { children: React.ReactNode }) {
  return (
    <span className="flex h-7 w-7 items-center justify-center rounded-md bg-glass">
      {children}
    </span>
  );
}

function Row({
  icon,
  iconBg,
  title,
  value,
  valueClass,
  chevron,
}: {
  icon: React.ReactNode;
  iconBg?: string;
  title: React.ReactNode;
  value?: React.ReactNode;
  valueClass?: string;
  chevron?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3 overflow-hidden px-3 py-3 border-b border-border last:border-0">
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <span
          className={clsx(
            "flex h-7 w-7 shrink-0 items-center justify-center rounded-md",
            iconBg ?? "bg-glass"
          )}
        >
          {icon}
        </span>
        <div className="text-sm truncate">{title}</div>
      </div>
      {value !== undefined && value !== "" && (
        <span className={clsx("shrink-0 text-xs text-gray-400", valueClass)}>{value}</span>
      )}
      {chevron && <ChevronRight size={14} className="shrink-0 text-gray-600 ml-2" />}
    </div>
  );
}

function ToggleRow({
  icon,
  title,
  desc,
  checked,
  onChange,
}: {
  icon?: React.ReactNode;
  title: string;
  desc: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3 overflow-hidden px-3 py-3 border-b border-border last:border-0">
      <div className="flex items-center gap-3 flex-1 min-w-0">
        {icon && (
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-glass">
            {icon}
          </span>
        )}
        <div className="min-w-0">
          <div className="text-sm truncate">{title}</div>
          <div className="text-[11px] text-gray-500 truncate">{desc}</div>
        </div>
      </div>
      <Switch checked={checked} onChange={onChange} />
    </div>
  );
}
