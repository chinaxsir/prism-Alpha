import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Check,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  ChevronRight,
  Wifi,
  Network,
  Sliders,
  Cpu,
  Power,
  Globe,
  Blocks,
  RefreshCw,
  Home,
  Languages,
  Palette,
} from "lucide-react";

import {
  getCoreStatus,
  getKernelInfo,
  getLanIp,
  getSettings,
  saveSettings,
  setMode,
  getGoLanSettings,
  saveGoLanSettings,
  isGoLanConfigured,
  type KernelInfo,
  type GoLanSettings,
} from "@/api/ipc";
import type { RunMode, UserSettings } from "@/stores/core";
import { useCoreStore } from "@/stores/core";
import { RUN_MODES } from "@/constants/modes";
import { ActivateProModal } from "@/components/ProGate";
import GoLanModal from "@/components/GoLanModal";
import ProManageModal, {
  fmtDateTime,
  planTextT,
} from "@/components/ProManageModal";
import { useProStore } from "@/stores/pro";
import { toast } from "@/components/ui/Toast";
import { isMobile } from "@/pro/gating";
import Switch from "@/components/ui/Switch";
import { usePrefsStore, type Language, type ThemePref } from "@/stores/prefs";
import { useTranslation } from "@/i18n";
import clsx from "clsx";

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
  const [saved, setSaved] = useState(false);
  const mobile = isMobile();
  const [showActivate, setShowActivate] = useState(false);
  // 【APP-12 任务2.2/2.3】Go Lan 配置弹窗与 Pro 授权详情弹窗开关
  const [goLanModalOpen, setGoLanModalOpen] = useState(false);
  const [proManageOpen, setProManageOpen] = useState(false);
  const proUnlocked = useProStore((s) => s.unlocked);
  const proReady = useProStore((s) => s.ready);
  const entitlement = useProStore((s) => s.entitlement);
  // 【APP-13 任务4】到期胶囊：永久/买断版直接显示「永久有效」，
  // 订阅版显示剩余天数，日期本身作为可点击入口打开授权管理弹窗
  const permanent =
    entitlement.plan === "team" ||
    (entitlement.kind === "lifetime" && !entitlement.expiresAt);
  const remainDays = (() => {
    if (permanent || !entitlement.expiresAt) return null;
    const ms = new Date(entitlement.expiresAt).getTime() - Date.now();
    if (Number.isNaN(ms)) return null;
    return Math.max(0, Math.ceil(ms / 86_400_000));
  })();
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
  // 【APP-9 任务1.3】本机局域网 IP（allow_lan 开启后展示给其他设备配置代理）
  const [lanIp, setLanIp] = useState<string | null>(null);

  // Go Lan · 回家网络（Pro）：【APP-12 任务2.2】配置编辑已收进 GoLanModal，
  // 设置页只读全局 store 渲染紧凑卡片（首帧直出缓存，消除开关闪烁）
  const goLanCfg = useCoreStore((s) => s.goLanSettings);
  const goLanConfigured = goLanCfg ? isGoLanConfigured(goLanCfg) : false;
  const goLanSubtitle = goLanConfigured
    ? goLanCfg?.wgConfig?.server
      ? `已配置: ${goLanCfg.wgConfig.server}:${goLanCfg.wgConfig.serverPort} · 网段 ${(goLanCfg.lanCidrs ?? []).join(", ")}`
      : `已配置 · 网段 ${(goLanCfg?.lanCidrs ?? []).join(", ")}`
    : "未配置回家网络 · 点击右侧配置参数";

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
    getKernelInfo()
      .then(setKernelInfo)
      .catch((e) => console.error(e));
  }, []);

  const patch = (p: Partial<UserSettings>) => {
    setForm((f) => ({ ...f, ...p }));
    setSaved(false);
  };

  /// 【APP-11 任务3】开关拨动即刻生效并持久化：
  /// 同步写本地表单 + 全局 store + 后端 saveSettings（运行中自动热重载），
  /// 不再依赖右上角「保存」按钮，彻底避免切页后开关回弹/两处状态不一致。
  const patchSwitch = (p: Partial<UserSettings>) => {
    const next = { ...form, ...p };
    setForm(next);
    useCoreStore.getState().setSettings(next);
    setSaved(false);
    saveSettings(next)
      .then(() => setSaved(true))
      .catch((e) => toast.error(String(e)));
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
      // 保存成功即写回全局 store：切页后首帧直出最新设置
      useCoreStore.getState().setSettings(form);
      setSaved(true);
    } catch (e) {
      console.error("save settings failed:", e);
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
          desc={
            form.allowLan && lanIp
              ? `${t("settings.allowLanOn")} · ${t("settings.allowLanAddr")}: ${lanIp}:${form.mixedPort}`
              : t("settings.allowLanDesc")
          }
          checked={form.allowLan}
          onChange={(v) => patchSwitch({ allowLan: v })}
        />
        {!mobile && (
          <ToggleRow
            icon={<Wifi size={16} className="text-gray-400" />}
            title={t("settings.systemProxy")}
            desc={t("settings.systemProxyDesc")}
            checked={form.systemProxy}
            onChange={(v) => patchSwitch({ systemProxy: v })}
          />
        )}
        {!mobile && (
          <ToggleRow
            icon={<Power size={16} className="text-gray-400" />}
            title={t("settings.autoStart")}
            desc={t("settings.autoStartDesc")}
            checked={form.autoStart}
            onChange={(v) => patchSwitch({ autoStart: v })}
          />
        )}
      </SettingsGroup>

      {/* Go Lan · 回家网络（Pro 门控）：【APP-12 任务2.2】内嵌大表单收进
          GoLanModal，这里只保留与普通设置行一致的紧凑单行卡；
          id 供仪表盘「配置」按钮跳转定位 */}
      {!goLanUnlocked ? (
        /* 【APP-13 任务3】未激活：与已激活行同构，仅整体置灰 + Switch 禁用，
           点击整行弹激活授权弹窗（不再额外渲染醒目「激活 Pro」横幅按钮） */
        <div
          onClick={() => setShowActivate(true)}
          role="button"
          className="flex cursor-pointer items-center justify-between gap-3 rounded-xl border border-border bg-surface-card px-4 py-3.5 opacity-60"
        >
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
                {t("settings.goLan.lockedDesc")}
              </p>
            </div>
          </div>
          <div
            className="flex shrink-0 items-center gap-3"
            onClick={(e) => e.stopPropagation()}
          >
            <Switch checked={false} disabled onChange={() => {}} />
          </div>
        </div>
      ) : (
        <div
          id="go-lan-card"
          className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface-card px-4 py-3.5"
        >
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent/15">
              <Home size={15} className="text-accent" />
            </span>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="whitespace-nowrap text-sm font-semibold text-gray-100">
                  Go Lan · 回家内网
                </span>
              </div>
              <p className="mt-0.5 truncate text-xs text-gray-500">
                {goLanSubtitle}
              </p>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-3">
            <button
              onClick={() => setGoLanModalOpen(true)}
              className="rounded-lg bg-surface-hover px-3 py-1.5 text-xs font-medium text-gray-200 transition-colors hover:bg-glass-strong"
            >
              {t("common.configure")}
            </button>
            <Switch
              checked={goLanCfg?.enabled ?? false}
              onChange={handleGoLanToggle}
            />
          </div>
        </div>
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
          onChange={(v) => patchSwitch({ ipv6: v })}
        />
        <ToggleRow
          icon={<Blocks size={16} className="text-gray-400" />}
          title={t("settings.blockQuic")}
          desc={t("settings.blockQuicDesc")}
          checked={form.blockQuic ?? false}
          onChange={(v) => patchSwitch({ blockQuic: v })}
        />
        <ToggleRow
          icon={<RefreshCw size={16} className="text-gray-400" />}
          title={t("settings.closeConns")}
          desc={t("settings.closeConnsDesc")}
          checked={form.closeConnectionsOnSwitch ?? false}
          onChange={(v) => patchSwitch({ closeConnectionsOnSwitch: v })}
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

      {/* Prism Pro：【APP-12 任务2.3】紧凑卡片，授权详情与操作收进 ProManageModal */}
      {!proUnlocked ? (
        <div className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface-card px-4 py-3.5">
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent/15">
              <Sparkles size={15} className="text-accent" />
            </span>
            <div className="min-w-0">
              <div className="whitespace-nowrap text-sm font-semibold text-gray-100">
                ✨ Prism Pro
              </div>
              <p className="mt-0.5 truncate text-xs text-gray-500">
                解锁 Go AIM、Go Lan、Go Cus、连接规则与云同步
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
        /* 【APP-13 任务4】已激活：极简单行——左侧方案+绿点+剩余天数，
           右侧到期时间胶囊（可点击，直接打开授权管理弹窗）。
           设备名额等细节全部收进弹窗，这一行只回答「我还有效吗、到哪天」。 */
        <div className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface-card px-4 py-3.5">
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent/15">
              <Sparkles size={15} className="text-accent" />
            </span>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 whitespace-nowrap text-sm font-semibold text-gray-100">
                ✨ Prism Pro
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-latency-good" />
                {planTextT(entitlement.plan, entitlement.kind, t)} · {t("pro.status.active")}
              </div>
              <p className="mt-0.5 truncate text-xs text-gray-500">
                {permanent
                  ? t("pro.permanent")
                  : remainDays !== null
                    ? t("pro.remainDays", { days: remainDays })
                    : "—"}
              </p>
            </div>
          </div>
          <button
            onClick={() => setProManageOpen(true)}
            className="flex shrink-0 items-center gap-1 rounded-lg bg-surface-hover px-3 py-1.5 text-xs font-medium text-gray-200 transition-colors hover:bg-glass-strong"
          >
            {permanent ? t("pro.permanent") : fmtDateTime(entitlement.expiresAt)}
            <ChevronRight size={12} className="opacity-60" />
          </button>
        </div>
      )}

      <ActivateProModal
        open={showActivate}
        onClose={() => setShowActivate(false)}
      />
      <GoLanModal
        open={goLanModalOpen}
        onClose={() => setGoLanModalOpen(false)}
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
