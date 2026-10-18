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
} from "lucide-react";
import { getVersion } from "@tauri-apps/api/app";

import {
  ensureKernel,
  getCoreStatus,
  getDeviceId,
  getKernelInfo,
  getSettings,
  saveSettings,
  setMode,
  getGoLanSettings,
  saveGoLanSettings,
  syncGoLanManaged,
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
import clsx from "clsx";

const STATUS_META: Record<
  EntitlementState,
  { label: string; dot: string }
> = {
  active: { label: "已激活", dot: "bg-latency-good" },
  offline: { label: "离线待校验", dot: "bg-yellow-400" },
  expired: { label: "已过期", dot: "bg-latency-bad" },
  revoked: { label: "已吊销", dot: "bg-latency-bad" },
  inactive: { label: "未授权", dot: "bg-gray-500" },
};

/** 服务端方案名展示（与 /api/license/status 的 plan 字段一致） */
const PLAN_LABEL: Record<string, string> = {
  free: "Free",
  pro: "Pro",
  team: "Team",
};

function planText(plan: string | null, kind: string | null): string {
  if (plan && PLAN_LABEL[plan]) return PLAN_LABEL[plan];
  if (kind === "lifetime") return "终身买断";
  if (kind === "subscription") return "订阅";
  return "—";
}

function fmtDate(secs: number | null): string {
  if (!secs) return "—";
  return new Date(secs * 1000).toLocaleDateString();
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
const MANAGED_SERVER_DEFAULT = "https://askcn.de";

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

  // ipa-8：仪表盘 Go Lan 卡片「配置」跳转锚点——进入设置页后滚动定位到回家网络卡片
  const [searchParams] = useSearchParams();
  useEffect(() => {
    if (searchParams.get("focus") === "goLan") {
      const t = setTimeout(() => {
        document
          .getElementById("go-lan-card")
          ?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 150);
      return () => clearTimeout(t);
    }
  }, [searchParams]);

  const [kernelInfo, setKernelInfo] = useState<KernelInfo | null>(null);
  const [kernelBusy, setKernelBusy] = useState(false);
  const [kernelMsg, setKernelMsg] = useState<string | null>(null);
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
      toast.success("设备 ID 已复制");
    } catch {
      toast.error("复制失败，请长按手动选择");
    }
  };

  // ipa-8：「立即校验」直连后端强制联网校验（verify_remote_forced），完成后给出明确 Toast
  const handleVerifyEntitlement = async () => {
    await refreshPro();
    const s = useProStore.getState();
    if (s.error) {
      const m = s.error;
      if (m.startsWith("rate_limited:")) {
        toast.error(`校验过于频繁，请 ${m.split(":")[1] ?? "30"} 秒后再试`);
      } else {
        toast.error(m);
      }
      return;
    }
    const st = s.entitlement.status;
    if (st === "active") {
      toast.success("授权校验成功：当前方案与有效期已同步");
    } else if (st === "expired" || st === "revoked") {
      toast.error("授权已过期或失效");
    } else if (st === "offline") {
      toast.info("网络不可用，授权校验失败，联网恢复后自动重试");
    } else {
      toast.info("本机暂无授权记录");
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
      toast.success("已成功移除本机授权");
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

  const handleEnsureKernel = async () => {
    setKernelBusy(true);
    setKernelMsg("正在校验内核…");
    try {
      const info = await ensureKernel();
      setKernelInfo(info);
      setKernelMsg(info.exists ? "内核已就绪" : "内核未就位");
    } catch (e) {
      setKernelMsg(String(e));
    } finally {
      setKernelBusy(false);
    }
  };

  const patch = (p: Partial<UserSettings>) => {
    setForm((f) => ({ ...f, ...p }));
    setSaved(false);
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
          ? "模式已切换，内核已重启生效"
          : "模式已切换，下次启动内核时生效"
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
        toast.error("WireGuard 手动配置需填写 Server、私钥与 Peer 公钥");
        return;
      }
    }
    setGoLanBusy(true);
    try {
      const warnings = await saveGoLanSettings(buildGoLanPayload());
      if (warnings && warnings.length > 0) {
        warnings.forEach((w) => toast.info(w));
      }
      toast.success("Go Lan 配置已保存");
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
      toast.success("已拉取回家配置");
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
        <h1 className="text-2xl font-bold">设置</h1>
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
              已保存
            </span>
          ) : (
            "保存"
          )}
        </button>
      </div>

      {/* 接入模式：iOS/Android 系统强制 TUN 接管，无切换意义，移动端不渲染 */}
      {!mobile && (
        <SettingsGroup
          title="接入模式"
          icon={<Wifi size={14} />}
          desc="决定流量如何进入 Prism（与下方出站模式互不影响）"
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
                  iconBg={active ? "bg-accent/10" : "bg-white/5"}
                  title={
                    <span className="flex items-center gap-1.5">
                      {m.title}
                      {m.key === "tun" && tunGated && (
                        <Lock size={12} className="text-accent" />
                      )}
                    </span>
                  }
                  value={active ? "已选" : ""}
                  chevron={!active}
                  valueClass={active ? "text-accent" : ""}
                />
              </button>
            );
          })}
          {modeBusy && (
            <div className="px-3 py-2 text-xs text-gray-400 border-t border-white/5">
              正在切换模式（内核运行中将自动重启生效）…
            </div>
          )}
          {mode === "tun" && (
            <div className="px-3 py-2.5 flex items-start gap-2 bg-yellow-500/5 text-yellow-400 text-xs border-t border-white/5">
              <ShieldAlert size={14} className="mt-0.5 shrink-0" />
              TUN 模式启动时若提示权限不足，请完全退出 Prism 后，右键选择
              “以管理员身份运行”（macOS/Linux 使用 sudo 启动）。
            </div>
          )}
        </SettingsGroup>
      )}

      {/* 本地入站 */}
      <SettingsGroup title="本地入站" icon={<Network size={14} />}>
        <div className="flex items-center justify-between overflow-hidden px-3 py-3 border-b border-white/5">
          <div className="flex items-center gap-3">
            <RowIcon><Network size={16} className="text-gray-400" /></RowIcon>
            <div>
              <div className="text-sm">混合代理端口</div>
              <div className="text-[11px] text-gray-500">同端口提供 HTTP 与 SOCKS5</div>
            </div>
          </div>
          <input
            type="number"
            min={1}
            max={65535}
            value={form.mixedPort}
            onChange={(e) => patch({ mixedPort: Number(e.target.value) })}
            className="w-24 px-3 py-1.5 rounded-lg bg-surface-hover border border-white/5 focus:border-accent outline-none text-sm text-right"
          />
        </div>
        <ToggleRow
          icon={<Globe size={16} className="text-gray-400" />}
          title="允许局域网连接"
          desc="同局域网其他设备可使用本机代理"
          checked={form.allowLan}
          onChange={(v) => patch({ allowLan: v })}
        />
        {!mobile && (
          <ToggleRow
            icon={<Wifi size={16} className="text-gray-400" />}
            title="设置系统代理"
            desc="系统代理模式启动时自动修改系统代理设置"
            checked={form.systemProxy}
            onChange={(v) => patch({ systemProxy: v })}
          />
        )}
        {!mobile && (
          <ToggleRow
            icon={<Power size={16} className="text-gray-400" />}
            title="开机自启动"
            desc="登录系统后自动启动 Prism"
            checked={form.autoStart}
            onChange={(v) => patch({ autoStart: v })}
          />
        )}
      </SettingsGroup>

      {/* Go Lan · 回家网络（Pro 门控，ipa-9：未激活时绝不渲染长表单，
          只渲染一张与普通设置行高度一致的紧凑单行引导卡；
          id 供仪表盘「配置」按钮跳转定位） */}
      {!goLanUnlocked ? (
        <div className="flex items-center justify-between gap-3 rounded-xl border border-white/5 bg-surface-card px-4 py-3.5">
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent/15">
              <Home size={15} className="text-accent" />
            </span>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="whitespace-nowrap text-sm font-semibold text-gray-100">
                  Go Lan · 回家内网
                </span>
                <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] font-medium text-accent">
                  PRO
                </span>
              </div>
              <p className="mt-0.5 truncate text-xs text-gray-500">
                启动代理同时自动连通家中局域网（激活授权后显示配置）
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowActivate(true)}
            className="shrink-0 rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover"
          >
            激活 Pro
          </button>
        </div>
      ) : (
        <SettingsGroup
          id="go-lan-card"
          title="Go Lan · 回家网络"
          icon={<Home size={14} />}
          desc="回家路由：指定网段/域名经家庭隧道直达局域网"
          headerRight={
            <Switch
              checked={goLan.enabled}
              onChange={(v) => patchGoLan({ enabled: v })}
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
                {goLanExpanded ? "收起配置" : "展开配置"}
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
                手动配置
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
                托管下发
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
                    WireGuard 参数
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
                    节点分享链接
                  </button>
                </div>

                {goLan.method === "wg" ? (
                  <div className="space-y-3">
                    <div className="flex gap-2">
                      <GoLanField label="Server" className="flex-1">
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
                      <GoLanField label="端口" className="w-24 shrink-0">
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
                    <GoLanField label="私钥（Private Key）">
                      <input
                        type="password"
                        value={goLan.wgPrivateKey}
                        onChange={(e) =>
                          patchGoLan({ wgPrivateKey: e.target.value })
                        }
                        placeholder="客户端 WireGuard 私钥"
                        autoComplete="off"
                        spellCheck={false}
                        className={GO_LAN_INPUT}
                      />
                    </GoLanField>
                    <GoLanField label="Peer 公钥">
                      <input
                        type="text"
                        value={goLan.wgPeerPublicKey}
                        onChange={(e) =>
                          patchGoLan({ wgPeerPublicKey: e.target.value })
                        }
                        placeholder="家庭端 WireGuard 公钥"
                        autoComplete="off"
                        spellCheck={false}
                        className={GO_LAN_INPUT}
                      />
                    </GoLanField>
                    <GoLanField label="Pre-Shared Key（可选）">
                      <input
                        type="password"
                        value={goLan.wgPreSharedKey}
                        onChange={(e) =>
                          patchGoLan({ wgPreSharedKey: e.target.value })
                        }
                        placeholder="预共享密钥"
                        autoComplete="off"
                        spellCheck={false}
                        className={GO_LAN_INPUT}
                      />
                    </GoLanField>
                    <div className="flex gap-2">
                      <GoLanField
                        label="本机地址（Local IP）"
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
                      <GoLanField label="MTU" className="w-24 shrink-0">
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
                    label="回家节点分享链接"
                    hint="单条 vless / vmess / ss / trojan / hy2 / tuic 链接"
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
                <GoLanField label="托管服务器" hint="从该服务器拉取家庭网络配置">
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
                <GoLanField label="设备码（Device Code）">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={goLan.deviceCode}
                      onChange={(e) =>
                        patchGoLan({ deviceCode: e.target.value })
                      }
                      placeholder="托管端为本机生成的设备码"
                      spellCheck={false}
                      autoComplete="off"
                      className={clsx(GO_LAN_INPUT, "flex-1")}
                    />
                    <button
                      onClick={handleGoLanSync}
                      disabled={goLanSyncing}
                      className="flex shrink-0 items-center gap-1.5 rounded-lg bg-surface-hover px-3 py-2 text-xs transition-colors hover:bg-white/10 disabled:opacity-50"
                    >
                      <RefreshCw
                        size={12}
                        className={goLanSyncing ? "animate-spin" : ""}
                      />
                      {goLanSyncing ? "同步中…" : "同步回家配置"}
                    </button>
                  </div>
                </GoLanField>
              </div>
            )}

            {/* 通用字段：回家目标（网段 / DNS / 域名后缀） */}
            <div className="space-y-3 border-t border-white/5 pt-3">
              <GoLanField label="局域网网段（CIDR）" hint="每行一个，如 192.168.1.0/24">
                <textarea
                  rows={2}
                  value={goLan.lanCidrs}
                  onChange={(e) => patchGoLan({ lanCidrs: e.target.value })}
                  placeholder={"192.168.1.0/24\n10.8.0.0/24"}
                  spellCheck={false}
                  className={clsx(GO_LAN_INPUT, "resize-none font-mono text-xs leading-relaxed")}
                />
              </GoLanField>
              <GoLanField label="局域网 DNS（可选）">
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
              <GoLanField label="域名后缀" hint="每行一个，如 nas.home">
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
              保存
            </button>
          </div>
          </>
          )}
        </SettingsGroup>
      )}

      {/* 高级 */}
      <SettingsGroup title="高级" icon={<Sliders size={14} />} desc="IPv6、QUIC、连接切换等内核行为">
        <ToggleRow
          icon={<Globe size={16} className="text-gray-400" />}
          title="IPv6"
          desc="开启后 DNS 返回 AAAA 并 TUN 接管 v6 流量"
          checked={form.ipv6 ?? false}
          onChange={(v) => patch({ ipv6: v })}
        />
        <ToggleRow
          icon={<Blocks size={16} className="text-gray-400" />}
          title="阻止 QUIC"
          desc="拦截 UDP/443 强制 TCP 回退"
          checked={form.blockQuic ?? false}
          onChange={(v) => patch({ blockQuic: v })}
        />
        <ToggleRow
          icon={<RefreshCw size={16} className="text-gray-400" />}
          title="切换策略时关闭连接"
          desc="切换节点后断开现有连接，新策略立即生效"
          checked={form.closeConnectionsOnSwitch ?? false}
          onChange={(v) => patch({ closeConnectionsOnSwitch: v })}
        />
      </SettingsGroup>

      {/* 代理内核 */}
      <SettingsGroup title="代理内核" icon={<Cpu size={14} />}>
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
              ? `已安装${kernelInfo.version ? ` · v${kernelInfo.version}` : ""}`
              : "内核文件缺失"
          }
          value={kernelInfo?.exists ? "" : "请重新安装"}
          valueClass="text-latency-bad"
        />
        {kernelInfo?.path && (
          <div className="px-3 py-2 text-[11px] font-mono break-all text-gray-500 border-b border-white/5">
            {kernelInfo.path}
          </div>
        )}
        {kernelMsg && (
          <div className="px-3 py-2 text-xs text-gray-300 border-b border-white/5">
            {kernelMsg}
          </div>
        )}
        <div className="px-3 py-3">
          <button
            onClick={handleEnsureKernel}
            disabled={kernelBusy}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-hover hover:bg-white/10 text-xs transition-colors disabled:opacity-50"
          >
            <ShieldCheck size={13} className={kernelBusy ? "animate-pulse" : ""} />
            {kernelBusy ? "处理中…" : "校验内核状态"}
          </button>
        </div>
      </SettingsGroup>

      {/* Prism Pro 授权卡片：未授权展示设备 ID + 激活入口；已授权展示协议授权信息 */}
      <SettingsGroup
        title="Prism Pro"
        icon={<Sparkles size={14} className="text-accent" />}
        headerRight={
          <span className="flex items-center gap-1.5 text-xs text-gray-400">
            <span
              className={`inline-block w-1.5 h-1.5 rounded-full ${STATUS_META[entitlement.status].dot}`}
            />
            {STATUS_META[entitlement.status].label}
          </span>
        }
      >
        {entitlement.status === "offline" && (
          <div className="flex items-start gap-2 px-3 py-2.5 bg-yellow-500/5 text-yellow-400 text-xs border-b border-white/5">
            <ShieldAlert size={14} className="mt-0.5 shrink-0" />
            <span>
              网络不可用，授权校验失败，Pro 功能已暂停；联网恢复后自动重新校验。
            </span>
          </div>
        )}

        {/* 设备 ID：激活时与服务端绑定，点击复制 */}
        <button
          onClick={copyDeviceId}
          className="w-full flex items-center justify-between gap-3 overflow-hidden px-3 py-3 border-b border-white/5 text-left transition-colors hover:bg-surface-hover/40"
        >
          <span className="flex items-center gap-3 min-w-0">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-white/5">
              <Fingerprint size={16} className="text-gray-400" />
            </span>
            <span className="min-w-0">
              <span className="block text-sm">设备 ID</span>
              <span className="block text-[11px] text-gray-500">
                点击复制 · 激活时绑定本机
              </span>
            </span>
          </span>
          <span className="flex min-w-0 items-center gap-1.5 text-[11px] font-mono text-gray-400">
            <span className="max-w-[150px] truncate">{deviceId ?? "生成中…"}</span>
            <Copy size={12} className="shrink-0 text-gray-500" />
          </span>
        </button>

        {/* APP 版本：当前安装的 Prism 版本号 */}
        <Row
          icon={<AppWindow size={16} className="text-gray-400" />}
          iconBg="bg-white/5"
          title="APP 版本"
          value={appVersion ? `v${appVersion}` : "—"}
        />

        {proUnlocked ? (
          <>
            <Row
              icon={<Sparkles size={16} className="text-accent" />}
              iconBg="bg-accent/10"
              title="当前方案"
              value={planText(entitlement.plan, entitlement.kind)}
            />
            <Row
              icon={<Check size={16} className="text-gray-400" />}
              iconBg="bg-white/5"
              title="到期时间"
              value={
                entitlement.kind === "lifetime" && !entitlement.expiresAt
                  ? "永久有效"
                  : fmtDate(entitlement.expiresAt)
              }
            />
            {entitlement.maxSeats != null && (
              <Row
                icon={<Smartphone size={16} className="text-gray-400" />}
                iconBg="bg-white/5"
                title="设备名额"
                value={`${entitlement.usedSeats ?? "?"} / ${entitlement.maxSeats}`}
              />
            )}
            <Row
              icon={<RefreshCw size={16} className="text-gray-400" />}
              iconBg="bg-white/5"
              title="上次校验"
              value={fmtDate(entitlement.lastVerifiedAt)}
            />
            <div className="flex flex-wrap gap-2 px-3 py-3 border-t border-white/5">
              <button
                onClick={handleVerifyEntitlement}
                disabled={proBusy}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-surface-hover hover:bg-white/10 text-xs transition-colors disabled:opacity-50"
              >
                <RefreshCw size={12} className={proBusy ? "animate-spin" : ""} />
                {proBusy ? "校验中..." : "立即校验"}
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
                {confirmDeactivate ? "确认移除授权？" : "移除授权"}
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="px-3 py-3 text-xs leading-relaxed text-gray-500 border-b border-white/5">
              输入 License Key 激活后，解锁多订阅、连接管理、规则自定义等 Pro
              功能。授权联网校验，激活即绑定本机设备。
            </div>
            <div className="flex flex-wrap gap-2 px-3 py-3">
              <button
                onClick={() => setShowActivate(true)}
                className="flex-1 min-w-[120px] flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-accent hover:bg-accent-hover text-white text-xs font-medium transition-colors"
              >
                <Sparkles size={12} />
                激活授权
              </button>
              <button
                onClick={handleVerifyEntitlement}
                disabled={proBusy}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-surface-hover hover:bg-white/10 text-xs transition-colors disabled:opacity-50"
              >
                <RefreshCw size={12} className={proBusy ? "animate-spin" : ""} />
                {proBusy ? "校验中..." : "立即校验"}
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

// ---- 复用组件 ----

/// Go Lan 卡片输入框统一样式
const GO_LAN_INPUT =
  "w-full rounded-lg border border-white/5 bg-surface-hover px-3 py-2 text-sm outline-none focus:border-accent";

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
      <div className="rounded-xl bg-surface-card border border-white/5 overflow-hidden">
        {children}
      </div>
    </section>
  );
}

function RowIcon({ children }: { children: React.ReactNode }) {
  return (
    <span className="flex h-7 w-7 items-center justify-center rounded-md bg-white/5">
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
    <div className="flex items-center justify-between gap-3 overflow-hidden px-3 py-3 border-b border-white/5 last:border-0">
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <span
          className={clsx(
            "flex h-7 w-7 shrink-0 items-center justify-center rounded-md",
            iconBg ?? "bg-white/5"
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
    <div className="flex items-center justify-between gap-3 overflow-hidden px-3 py-3 border-b border-white/5 last:border-0">
      <div className="flex items-center gap-3 flex-1 min-w-0">
        {icon && (
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-white/5">
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
