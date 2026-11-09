import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Lock,
  ShieldAlert,
  Sparkles,
  ChevronRight,
  Wifi,
  Network,
  Sliders,
  Power,
  Globe,
  Blocks,
  RefreshCw,
  Home,
  Languages,
  Palette,
  FileTerminal,
  Rss,
  Send,
  BookOpen,
  Ticket,
} from "lucide-react";

import {
  getCoreStatus,
  getLanIp,
  getSettings,
  saveSettings,
  setMode,
  getGoLanSettings,
  saveGoLanSettings,
  isGoLanConfigured,
  clearAppLogs,
  openExternalUrl,
  type GoLanSettings,
} from "@/api/ipc";
import type { RunMode, UserSettings } from "@/stores/core";
import { useCoreStore } from "@/stores/core";
import { RUN_MODES } from "@/constants/modes";
import { ActivateProModal } from "@/components/ProGate";
import GoLanModal from "@/components/GoLanModal";
import LogViewerModal from "@/components/LogViewerModal";
import ProManageModal, { fmtDateTime } from "@/components/ProManageModal";
import { useProStore } from "@/stores/pro";
import { toast } from "@/components/ui/Toast";
import { isMobile } from "@/pro/gating";
import Switch from "@/components/ui/Switch";
import { usePrefsStore, type Language, type ThemePref } from "@/stores/prefs";
import { useTranslation } from "@/i18n";
import clsx from "clsx";

/// 【APP58 任务2.2】关于帮助：四个官方入口（全部走原生打开，iOS 100% 生效）
const HELP_LINKS = [
  {
    labelKey: "settings.helpGuide",
    url: "https://prism.sarl/guide",
    Icon: BookOpen,
  },
  {
    labelKey: "settings.helpTerms",
    url: "https://prism.sarl/terms",
    Icon: ShieldAlert,
  },
  {
    labelKey: "settings.helpPrivacy",
    url: "https://prism.sarl/privacy",
    Icon: Lock,
  },
  {
    labelKey: "settings.helpTickets",
    url: "https://prism.sarl/tickets",
    Icon: Ticket,
  },
  {
    labelKey: "settings.helpChannel",
    url: "https://t.me/prism_proxy",
    Icon: Send,
  },
] as const;

/// 原生级打开外链：iOS 由 UIApplication 在系统浏览器打开；其余平台由
/// Rust 调系统默认浏览器。任何失败回落 window.location.assign（同窗口导航
/// 在 WKWebView / 桌面 WebView 中都可用，不会被 system 静默丢弃）。
function openHelpLink(url: string) {
  openExternalUrl(url).catch(() => {
    window.location.assign(url);
  });
}

/// 接入模式图标
const RUN_MODE_ICON: Record<RunMode, typeof Wifi> = {
  systemProxy: Wifi,
  tun: Network,
};

export default function Settings() {
  const { t } = useTranslation();
  const [mode, setRunMode] = useState<RunMode>("systemProxy");
  const [modeBusy, setModeBusy] = useState(false);
  const [form, setForm] = useState<UserSettings>(() => ({
    // 【APP-10 任务4】首帧直出全局 store 中的真实设置（App 启动已水合），
    // 杜绝 useState(默认 false) → 异步 true 的开关闪烁；store 未水合时
    // 回落默认值，由 Switch 挂载帧动画锁兜底。
    // store.settings 必含 mixedPort/allowLan/systemProxy/mode/autoStart
    // 必填字段，展开在后覆盖下方可选字段默认值
    outboundMode: "rule",
    ipv6: false,
    blockQuic: false,
    closeConnectionsOnSwitch: false,
    language: "system",
    theme: "system",
    ...useCoreStore.getState().settings,
  }));
  // 【APP45 任务3】自动保存提示：任何修改成功持久化后闪烁 1.5s「✓ 已自动保存」
  const [autoSaved, setAutoSaved] = useState(false);
  const autoSaveFlashTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const kernelSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // 端口草稿：仅 blur/Enter 提交（校验 1024-65535），提交前不回写 form
  const [portDraft, setPortDraft] = useState<string | null>(null);
  const mobile = isMobile();
  const [showActivate, setShowActivate] = useState(false);
  // 【APP-12 任务2.2/2.3】Go Lan 配置弹窗与 Pro 授权详情弹窗开关
  const [goLanModalOpen, setGoLanModalOpen] = useState(false);
  const [proManageOpen, setProManageOpen] = useState(false);
  // 【APP6 任务1.2】运行日志弹窗
  const [logViewerOpen, setLogViewerOpen] = useState(false);
  // 【APP58 任务2.2】软件版本：运行时从 Tauri 读取当前真实版本，杜绝写死漂移
  const [appVersion, setAppVersion] = useState("0.3.91");
  useEffect(() => {
    import("@tauri-apps/api/app")
      .then((m) => m.getVersion())
      .then((v) => setAppVersion(v))
      .catch(() => undefined);
  }, []);
  const proUnlocked = useProStore((s) => s.unlocked);
  const entitlement = useProStore((s) => s.entitlement);
  // 【APP-13 任务4】到期胶囊：永久/买断版直接显示「永久有效」，
  // 订阅版显示到期时间，日期本身作为可点击入口打开授权信息弹窗
  const permanent =
    !entitlement.alpha &&
    (entitlement.plan === "team" ||
      (entitlement.kind === "lifetime" && !entitlement.expiresAt));
  const tunGated = !proUnlocked;

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

  // 【APP-9 任务1.3】本机局域网 IP（allow_lan 开启后展示给其他设备配置代理）
  const [lanIp, setLanIp] = useState<string | null>(null);

  // Go Lan · 回家网络（Pro）：【APP-12 任务2.2】配置编辑已收进 GoLanModal，
  // 设置页只读全局 store 渲染紧凑卡片（首帧直出缓存，消除开关闪烁）
  const goLanCfg = useCoreStore((s) => s.goLanSettings);
  const goLanConfigured = goLanCfg ? isGoLanConfigured(goLanCfg) : false;

  useEffect(() => {
    getGoLanSettings()
      .then((s) => {
        // 回写全局 store，保持后续切页首帧为最新值
        useCoreStore.getState().setGoLanSettings(s);
      })
      .catch((e) => console.error("get go lan settings failed:", e));
  }, []);

  // 【APP-9 任务1.3】开启「允许局域网连接」后动态获取本机局域网 IP，
  // 在设置行副标题中展示完整代理地址，方便其他设备一键对照填写
  useEffect(() => {
    if (!form.allowLan) {
      setLanIp(null);
      return;
    }
    getLanIp()
      .then(setLanIp)
      .catch(() => setLanIp(null));
  }, [form.allowLan]);


  useEffect(() => {
    getSettings()
      .then((s) => {
        setForm(s);
        // 回写全局 store，保持后续切页首帧为最新值
        useCoreStore.getState().setSettings(s);
      })
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
  }, []);

  /// 【APP45 任务3】form 实时镜像（避免防抖闭包读取过期 state）
  const formRef = useRef(form);
  formRef.current = form;

  const flashAutoSaved = () => {
    setAutoSaved(true);
    if (autoSaveFlashTimer.current) clearTimeout(autoSaveFlashTimer.current);
    autoSaveFlashTimer.current = setTimeout(() => setAutoSaved(false), 1500);
  };

  /// 立即持久化 + 成功提示
  const persistSettings = (next: UserSettings) => {
    saveSettings(next)
      .then(flashAutoSaved)
      .catch((e) => toast.error(String(e)));
  };

  /// 【APP45 任务3】内核网络栈相关（allowLan / mixedPort / ipv6 / blockQuic）：
  /// 300ms 防抖保存，后端 saveSettings 运行中自动热重载内核
  const patchKernel = (p: Partial<UserSettings>) => {
    const next = { ...formRef.current, ...p };
    formRef.current = next;
    setForm(next);
    useCoreStore.getState().setSettings(next);
    if (kernelSaveTimer.current) clearTimeout(kernelSaveTimer.current);
    kernelSaveTimer.current = setTimeout(() => persistSettings(next), 300);
  };

  /// 端口提交：blur / Enter 时校验 1024-65535，非法则还原并提示
  const commitPort = () => {
    if (portDraft === null) return;
    const v = Number(portDraft.trim());
    if (!Number.isInteger(v) || v < 1024 || v > 65535) {
      toast.error(t("settings.portInvalid"));
      setPortDraft(null);
      return;
    }
    setPortDraft(null);
    if (v !== formRef.current.mixedPort) {
      patchKernel({ mixedPort: v });
    }
  };

  /// 语言 / 外观：立即生效 + 立即持久化（无需再点「保存」）
  const patchPrefs = (p: Partial<UserSettings>) => {
    const next = { ...formRef.current, ...p };
    formRef.current = next;
    setForm(next);
    saveSettings(next)
      .then(flashAutoSaved)
      .catch(() => undefined);
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
    // 【APP-4 任务3】未激活时 TUN 静默禁用：按钮本身 disabled，此处兜底直接返回
    if (m === "tun" && tunGated) {
      return;
    }
    if (modeBusy || m === mode) return;
    setRunMode(m);
    setForm((f) => ({ ...f, mode: m }));
    useCoreStore.getState().setMode(m);
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

  /// 【APP-11 任务3 / APP-12 任务2.2】设置页 Go Lan 开关拨动即刻保存生效
  /// （与仪表盘同一数据源：全局 store），配置编辑收进 GoLanModal；
  /// 未配置时拦截开启并直接弹出配置弹窗。
  const handleGoLanToggle = async (v: boolean) => {
    const current = useCoreStore.getState().goLanSettings;
    if (!current) return;
    if (v && !isGoLanConfigured(current)) {
      toast.error(t("dashboard.lan.configureFirst"));
      setGoLanModalOpen(true);
      return;
    }
    const payload: GoLanSettings = { ...current, enabled: v };
    // 乐观更新全局 store，失败回滚，避免前端显示"已开启"但后端未生效
    useCoreStore.getState().setGoLanSettings(payload);
    try {
      const warnings = await saveGoLanSettings(payload);
      warnings?.forEach((w) => toast.info(w));
    } catch (e) {
      useCoreStore.getState().setGoLanSettings(current);
      toast.error(String(e));
    }
  };

  // 【APP6 任务1.2】清空全部运行日志
  const handleClearLogs = async () => {
    try {
      await clearAppLogs();
      toast.success(t("logs.cleared"));
    } catch (e) {
      toast.error(String(e));
    }
  };

  const runModes = MODES.filter((m) => (mobile ? m.key === "tun" : true));

  return (
    <div className="space-y-5 max-w-3xl">
      <div className="flex items-center justify-between">
        <h1 className="text-[22px] font-bold tracking-tight">{t("settings.title")}</h1>
        {/* 【APP45 任务3】全量自动保存：彻底移除右上角「保存」按钮，
            任何修改即时持久化并闪烁 1.5s 提示 */}
        <span
          className={clsx(
            "text-xs text-latency-good font-medium transition-opacity duration-300",
            autoSaved ? "opacity-100" : "opacity-0",
          )}
        >
          {t("settings.autoSaved")}
        </span>
      </div>

      {/* 外观与语言：语言 / 深浅色外观，均可跟随系统 */}
      <SettingsGroup
        title={t("settings.appearance")}
        icon={<Palette size={18} />}
        iconColor="text-surge-pink"
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
          icon={<Wifi size={18} />}
          iconColor="text-surge-blue"
          desc={t("settings.modeDesc")}
        >
          {runModes.map((m) => {
            const Icon = RUN_MODE_ICON[m.key] ?? Wifi;
            const active = mode === m.key;
            // 【APP-4 任务3】未激活时 TUN 模式按钮静默禁用
            const disabled = modeBusy || (m.key === "tun" && tunGated);
            return (
              <button
                key={m.key}
                onClick={() => chooseMode(m.key)}
                disabled={disabled}
                className={`w-full text-left disabled:opacity-60 ${
                  m.key === "tun" && tunGated ? "opacity-50 cursor-not-allowed" : ""
                }`}
              >
                <Row
                  icon={
                    <Icon size={16} className={active ? "text-accent" : "text-gray-400"} />
                  }
                  iconBg={active ? "bg-accent/10" : "bg-glass"}
                  title={
                    <span className="flex items-center gap-1.5">
                      {t(`settings.runMode.${m.key}`)}
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
      <SettingsGroup title={t("settings.inbound")} icon={<Network size={18} />} iconColor="text-surge-teal">
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
            min={1024}
            max={65535}
            value={portDraft ?? String(form.mixedPort)}
            onChange={(e) => setPortDraft(e.target.value)}
            onBlur={commitPort}
            onKeyDown={(e) => {
              if (e.key === "Enter") (e.target as HTMLInputElement).blur();
            }}
            className="w-24 px-3 py-1.5 rounded-lg bg-surface-hover border border-border focus:border-accent outline-none text-sm text-right"
          />
        </div>
        <ToggleRow
          icon={<Globe size={16} className="text-gray-400" />}
          title={t("settings.allowLan")}
          desc={
            form.allowLan && lanIp
              ? `${t("settings.allowLanOn")} · ${t("settings.allowLanAddr")}: ${lanIp}:${form.mixedPort}`
              : t("settings.allowLanDesc")
          }
          checked={form.allowLan}
          onChange={(v) => patchKernel({ allowLan: v })}
        />
        {!mobile && (
          <ToggleRow
            icon={<Wifi size={16} className="text-gray-400" />}
            title={t("settings.systemProxy")}
            desc={t("settings.systemProxyDesc")}
            checked={form.systemProxy}
            onChange={(v) => patchPrefs({ systemProxy: v })}
          />
        )}
        {!mobile && (
          <ToggleRow
            icon={<Power size={16} className="text-gray-400" />}
            title={t("settings.autoStart")}
            desc={t("settings.autoStartDesc")}
            checked={form.autoStart}
            onChange={(v) => patchPrefs({ autoStart: v })}
          />
        )}
      </SettingsGroup>

      {/* Go Lan · 回家网络（Pro 门控）：【APP59】背景改为 bg-surface-card，
          与下方各设置板块完全一致（浅色主题下同为白色卡片） */}
      <div
        id="go-lan-card"
        className="rounded-xl border border-border bg-surface-card px-4 py-3 flex items-center justify-between gap-3"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Home className="w-4 h-4 text-surge-orange shrink-0" />
            <span className="font-semibold text-sm text-text">{t("engine.goLan")}</span>
          </div>
          <div className="text-xs text-text-muted mt-1 leading-relaxed break-words">
            {!proUnlocked
              ? t("pro.lockedTap")
              : goLanConfigured
              ? `${t("pro.configured")}: ${
                  (goLanCfg?.profiles ?? [])
                    .filter((p) => p.enabled)
                    .map((p) => {
                      // 【APP56 任务3 / APP57 任务1.3】严格只读本档案自身结果，
                      // 同时兼容 id 与名称两种映射键
                      const isDirect = Boolean(
                        p.enabled &&
                          p.bypassOnLocalLan &&
                          (goLanCfg?.goLanProfileDirectMap?.[p.id] === true ||
                            goLanCfg?.goLanProfileDirectMap?.[p.name] === true),
                      );
                      return `${p.name} (${
                        isDirect
                          ? t("goLan.statusDirect")
                          : t("goLan.statusTunnel")
                      })`;
                    })
                    .join(" · ") ||
                  `${goLanCfg?.wgConfig?.server}:${goLanCfg?.wgConfig?.serverPort} · ${(goLanCfg?.lanCidrs ?? []).join(", ")}`
                }`
              : t("pro.notConfigured")}
          </div>
        </div>
        <div className="flex items-center gap-2.5 shrink-0">
          {proUnlocked && (
            <button
              type="button"
              onClick={() => setGoLanModalOpen(true)}
              className="text-xs text-accent hover:underline font-medium"
            >
              {t("common.configure")}
            </button>
          )}
          <Switch
            checked={proUnlocked ? Boolean(goLanCfg?.enabled) : false}
            disabled={!proUnlocked}
            onChange={handleGoLanToggle}
          />
        </div>
      </div>

      {/* 高级 */}
      <SettingsGroup
        title={t("settings.advanced")}
        icon={<Sliders size={18} />}
        iconColor="text-surge-green"
        desc={t("settings.advancedDesc")}
      >
        <ToggleRow
          icon={<Globe size={16} className="text-gray-400" />}
          title={t("settings.ipv6")}
          desc={t("settings.ipv6Desc")}
          checked={form.ipv6 ?? false}
          onChange={(v) => patchKernel({ ipv6: v })}
        />
        <ToggleRow
          icon={<Blocks size={16} className="text-gray-400" />}
          title={t("settings.blockQuic")}
          desc={t("settings.blockQuicDesc")}
          checked={form.blockQuic ?? false}
          onChange={(v) => patchKernel({ blockQuic: v })}
        />
        <ToggleRow
          icon={<RefreshCw size={16} className="text-gray-400" />}
          title={t("settings.closeConns")}
          desc={t("settings.closeConnsDesc")}
          checked={form.closeConnectionsOnSwitch ?? false}
          onChange={(v) => patchPrefs({ closeConnectionsOnSwitch: v })}
        />
        {/* 【APP49 任务2.2】启动时自动更新全部订阅（每天一次，默认开启） */}
        <ToggleRow
          icon={<Rss size={16} className="text-gray-400" />}
          title={t("sub.autoUpdateDaily")}
          desc={t("sub.autoUpdateDailyDesc")}
          checked={form.autoUpdateSubsDaily ?? true}
          onChange={(v) => patchPrefs({ autoUpdateSubsDaily: v })}
        />
      </SettingsGroup>

      {/* 【APP6 任务1.2】诊断与日志：全模块环形日志查看/导出/清空 */}
      <div className="rounded-xl border border-border bg-surface px-4 py-3 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-surge-purple/15 flex items-center justify-center shrink-0">
            <FileTerminal size={16} className="text-surge-purple" />
          </div>
          <div className="min-w-0">
            <div className="font-semibold text-sm text-text">{t("logs.cardTitle")}</div>
            <div className="text-[11px] text-text-muted truncate">{t("logs.cardDesc")}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setLogViewerOpen(true)}
            className="px-3 py-1.5 rounded-lg bg-surface-hover text-xs text-gray-300 hover:text-white transition-colors"
          >
            {t("logs.view")}
          </button>
          <button
            type="button"
            onClick={handleClearLogs}
            className="px-3 py-1.5 rounded-lg bg-red-500/90 text-xs text-white hover:opacity-90 transition-colors"
          >
            {t("logs.clear")}
          </button>
        </div>
      </div>

      {/* 【APP59】关于帮助：全部竖版排列（版本信息在上、链接逐行在下），
          背景与设置页其他板块一致；所有链接经 Rust 原生打开，iOS 100% 生效 */}
      <div className="rounded-xl border border-border bg-surface-card px-4 py-3 space-y-2">
        <div className="flex items-center gap-2.5 pb-1">
          <div className="w-8 h-8 rounded-lg bg-surge-purple/15 flex items-center justify-center shrink-0">
            <BookOpen size={16} className="text-surge-purple" />
          </div>
          <div className="min-w-0">
            <div className="font-semibold text-sm text-text">
              {t("settings.aboutHelp")}
            </div>
            <div className="text-[11px] text-text-muted truncate">
              {t("settings.aboutHelpDesc")}
            </div>
          </div>
        </div>
        {/* 版本信息：竖版两行，标签左 / 数值右 */}
        <div className="flex items-center justify-between gap-3 rounded-lg bg-surface-hover px-3 py-2">
          <span className="text-xs text-text-muted">{t("settings.appVersion")}</span>
          <span className="text-xs font-semibold text-text">v{appVersion}</span>
        </div>
        <div className="flex items-center justify-between gap-3 rounded-lg bg-surface-hover px-3 py-2">
          <span className="text-xs text-text-muted">{t("settings.kernelVersion")}</span>
          <span className="text-xs font-semibold text-text">v1.11.3</span>
        </div>
        {/* 帮助入口：竖版逐行，图标 + 文字格式完全统一 */}
        <div className="flex flex-col gap-2 pt-0.5">
          {HELP_LINKS.map(({ labelKey, url, Icon }) => (
            <button
              key={labelKey}
              type="button"
              onClick={() => openHelpLink(url)}
              className="flex w-full min-w-0 items-center gap-2 rounded-lg bg-surface-hover px-3 py-2 text-xs text-gray-300 hover:text-white transition-colors"
            >
              <Icon size={14} className="shrink-0 text-accent" />
              <span className="truncate">{t(labelKey)}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Prism Pro：【APP-5 任务4】未激活展示 5 大模块引导，已激活极简单行 */}
      {!proUnlocked ? (
        <div className="rounded-xl bg-surface border border-border p-4 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-surge-amber/15 flex items-center justify-center shrink-0">
                <Sparkles className="w-4 h-4 text-surge-amber" />
              </div>
              <div className="min-w-0">
                <div className="font-semibold text-sm text-text">Prism Pro</div>
                <div className="text-[11px] text-text-muted truncate">
                  {t("pro.activateDesc")}
                </div>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setShowActivate(true)}
              className="px-3.5 py-1.5 rounded-lg bg-accent hover:bg-accent/90 text-white text-xs font-medium shrink-0 transition-colors"
            >
              {t("pro.activatePro")}
            </button>
          </div>
          {/* 激活后可解锁的 Pro 功能模块（2-col grid） */}
          <div className="pt-2.5 border-t border-border/60 grid grid-cols-2 gap-2 text-xs text-text-muted">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-accent shrink-0" />
              <span className="truncate">{t("pro.modules.goAim")}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-accent shrink-0" />
              <span className="truncate">{t("pro.modules.goLan")}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-accent shrink-0" />
              <span className="truncate">{t("pro.modules.goCus")}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-accent shrink-0" />
              <span className="truncate">{t("pro.modules.proxySuite")}</span>
            </div>
            <div className="flex items-center gap-1.5 col-span-2">
              <span className="w-1.5 h-1.5 rounded-full bg-accent shrink-0" />
              <span className="truncate">{t("pro.modules.cloudSync")}</span>
            </div>
          </div>
        </div>
      ) : (
        /* 已激活：上下两行排版（第一行标题+徽章，第二行订阅到期时间），
           与上方 Go Lan 卡片视觉层次完全统一；整张卡片含第二行与右侧
           「授权信息 >」入口，点击任意位置均弹出授权信息窗口 */
        <button
          type="button"
          onClick={() => setProManageOpen(true)}
          className="flex w-full items-center justify-between gap-3 rounded-xl border border-border bg-surface px-4 py-3 text-left transition-colors hover:border-emerald-500/30"
        >
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 shrink-0 text-surge-amber" />
              <span className="truncate text-sm font-semibold text-text">
                {entitlement.alpha
                  ? `Prism ${t("pro.plan.alpha")}`
                  : "Prism Pro"}
              </span>
              <span
                className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium ${
                  entitlement.alpha
                    ? "bg-surge-amber/15 text-surge-amber"
                    : "bg-emerald-500/15 text-emerald-400"
                }`}
              >
                {/* 【APP48】内测授权显示「内测」徽章，绝不冒充 Pro 订阅 */}
                {entitlement.alpha
                  ? t("pro.alphaBadge")
                  : t("pro.status.active")}
              </span>
            </div>
            <div className="mt-1 truncate text-xs text-text-muted">
              {t("pro.subscribeExpiry")}:{" "}
              {permanent ? t("pro.permanent") : fmtDateTime(entitlement.expiresAt)}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1 text-xs font-medium text-emerald-400">
            <span>{t("pro.infoTitle")}</span>
            <ChevronRight className="h-4 w-4" />
          </div>
        </button>
      )}

      <ActivateProModal
        open={showActivate}
        onClose={() => setShowActivate(false)}
      />
      <GoLanModal
        open={goLanModalOpen}
        onClose={() => setGoLanModalOpen(false)}
      />
      <LogViewerModal
        open={logViewerOpen}
        onClose={() => setLogViewerOpen(false)}
      />
      <ProManageModal
        open={proManageOpen}
        onClose={() => setProManageOpen(false)}
      />
    </div>
  );
}

const MODES = RUN_MODES;

// ---- 复用组件 ----

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

function SettingsGroup({
  title,
  desc,
  icon,
  iconColor,
  headerRight,
  children,
  id,
}: {
  title: string;
  desc?: string;
  icon?: React.ReactNode;
  /** 【APP45 任务4】Surge 风格模块标题图标颜色类（如 text-surge-orange） */
  iconColor?: string;
  headerRight?: React.ReactNode;
  children: React.ReactNode;
  /** DOM 锚点：供其他页面跳转定位（如仪表盘 Go Lan「配置」按钮） */
  id?: string;
}) {
  return (
    <section id={id}>
      <div className="flex items-center justify-between px-1 mb-2">
        <div className="flex items-center gap-2 text-[17px] font-bold tracking-tight text-gray-100">
          {icon && (
            <span className={clsx("flex items-center", iconColor ?? "text-accent")}>
              {icon}
            </span>
          )}
          <span>{title}</span>
        </div>
        {headerRight}
      </div>
      {desc && (
        <p className="px-1 mb-1.5 text-[11px] text-gray-500 leading-relaxed">
          {desc}
        </p>
      )}
      <div className="card-sheen rounded-xl bg-surface-card border border-border overflow-hidden">
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
