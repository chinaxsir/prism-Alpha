import { useCallback, useEffect, useRef, useState } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { ShieldBan } from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import Sidebar from "@/components/Sidebar";
import TitleBar from "@/components/TitleBar";
import BottomNav from "@/components/BottomNav";
import ToastViewport, { toast } from "@/components/ui/Toast";
import Dashboard from "@/pages/Dashboard";
import Subscription from "@/pages/Subscription";
import Analytics from "@/pages/Analytics";
import Settings from "@/pages/Settings";
import {
  applyThemeToDom,
  resolveSystemLanguage,
  useCoreStore,
  type CoreStatus,
  type OutboundMode,
  type RunMode,
  type UserSettings,
} from "@/stores/core";
import { useProStore } from "@/stores/pro";
import { usePrefsStore } from "@/stores/prefs";
import { resolveLang, useTranslation } from "@/i18n";
import { useAppVisible } from "@/hooks/useAppVisible";
import {
  getCoreStatus,
  getRuntimeSnapshot,
  getSettings,
  stopCore,
  getGoAimStatus,
  getGoLanSettings,
  getGoCusSettings,
  listSubscriptions,
  normalizeGoLanSettings,
  setAppForeground,
  type Entitlement,
  type GoCusSettings,
  type GoLanSettings,
  type ProbeProgress,
} from "@/api/ipc";
import { isMobile } from "@/pro/gating";
import ProxiesHub from "@/pages/ProxiesHub";

export default function App() {
  const { t } = useTranslation();
  const initPro = useProStore((s) => s.init);

  // 窗口尺寸变化监听（移动端安全区适配）
  const theme = usePrefsStore((s) => s.theme);
  const language = usePrefsStore((s) => s.language);
  const setLanguage = usePrefsStore((s) => s.setLanguage);
  const setTheme = usePrefsStore((s) => s.setTheme);
  // APP 远程管控阻断状态（app://control 事件维护；null = 无管控）
  const [controlBlock, setControlBlock] = useState<{
    reason: "version_blocked" | "user_blocked";
    message: string;
  } | null>(null);

  /** 拉取后端运行时快照并写入全局 store（今日流量 / 速率 / 60s 曲线 / 连接 / 分析）。
   *  【APP43 任务2.2】未运行时先拉一次内核状态：后端会借此检测「系统 VPN 仍在运行」
   *  并自动接管，重开 APP 无需再点启动即可恢复「已连接」与计时器。
   *  【APP43 任务1.4】防重入：上一次 IPC 未返回前不叠加新请求，避免慢响应时
   *  轮询队列堆积把后端 Mutex 压死 → IPC 5s 超时 → 误判掉授权。 */
  const runtimeBusyRef = useRef(false);
  // 【APP51 任务2】IPC 硬超时保护：后端异常/内核无响应时 1.8s 内必返回，
  // 全局定时器不会被单次请求卡死（速率卡死的根因之一）
  const withIpcTimeout = <T,>(p: Promise<T>, ms = 1800): Promise<T> =>
    Promise.race([
      p,
      new Promise<T>((_, reject) => window.setTimeout(() => reject(new Error("ipc-timeout")), ms)),
    ]);
  const refreshRuntime = useCallback(async () => {
    if (runtimeBusyRef.current) return;
    runtimeBusyRef.current = true;
    try {
      const store = useCoreStore.getState();
      if (store.status !== "running") {
        const st = await withIpcTimeout(getCoreStatus());
        store.setStatus(st.status);
        store.setMode(st.mode);
        if (st.outboundMode) store.setOutboundMode(st.outboundMode);
        // 【APP54 任务4/5】状态查询同时对齐测速 / Go AIM 进度
        store.setDelayProgress({
          running: st.delayProgress?.running === true,
          done: st.delayProgress?.done ?? 0,
          total: st.delayProgress?.total ?? 0,
          percent: st.delayProgress?.percent ?? 0,
          unlockedCount: st.delayProgress?.unlockedCount ?? 0,
        });
        store.setAimProgress({
          running: st.aimProgress?.running === true,
          done: st.aimProgress?.done ?? 0,
          total: st.aimProgress?.total ?? 0,
          percent: st.aimProgress?.percent ?? 0,
          unlockedCount: st.aimProgress?.unlockedCount ?? 0,
        });
        store.syncStartedAt(st);
        if (st.status !== "running") return;
      }
      const snap = await withIpcTimeout(getRuntimeSnapshot());
      store.applyRuntimeSnapshot(snap);
    } catch {
      /* 内核未就绪/超时：静默忽略，等下一轮 1s 定时器 */
    } finally {
      runtimeBusyRef.current = false;
    }
  }, []);

  // 启动时读取授权状态（命令层从 license 缓存恢复）
  useEffect(() => {
    initPro();
  }, [initPro]);

  // 启动预加载 Go 三引擎状态到全局 store（APP 任务1：消除切页闪烁，
  // Dashboard 直接从 store 读作渲染数据源，切回仪表盘不再「先关后开」；
  // 非 Pro 时 get_go_lan_settings / get_go_cus_settings 会 reject，静默忽略）
  useEffect(() => {
    const store = useCoreStore.getState();
    getGoAimStatus().then(store.setGoAimStatus).catch(() => undefined);
    getGoLanSettings().then(store.setGoLanSettings).catch(() => undefined);
    getGoCusSettings().then(store.setGoCusSettings).catch(() => undefined);
    // 【APP-10 任务4】订阅列表同步入 store：订阅页启用开关首帧直出真实状态
    listSubscriptions().then(store.setSubscriptions).catch(() => undefined);
  }, []);

  // 启动时恢复语言与外观偏好（持久化于后端 settings.json）
  useEffect(() => {
    getSettings()
      .then((s) => {
        if (s.language) setLanguage(s.language);
        if (s.theme) setTheme(s.theme);
        // 【APP-10 任务4】settings 写入全局 store：设置页各开关
        // （allowLan/ipv6/blockQuic 等）首帧直接读取真实状态，零闪烁
        useCoreStore.getState().setSettings(s);
      })
      .catch(() => undefined);
  }, [setLanguage, setTheme]);

  // 【APP49 任务5】应用外观（统一收口 applyThemeToDom），并实时监听系统
  // 深浅色变化；document visibilitychange 与 window focus 时重新应用，
  // 保证 iOS 控制中心切深浅色后回到 App 0 延迟跟随
  useEffect(() => {
    applyThemeToDom(theme);
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const reapply = () => {
      if (usePrefsStore.getState().theme === "system") applyThemeToDom("system");
    };
    mq.addEventListener?.("change", reapply);
    // 兼容旧 WebView（addEventListener 缺失时走 addListener）
    mq.addListener?.(reapply);
    document.addEventListener("visibilitychange", reapply);
    window.addEventListener("focus", reapply);
    return () => {
      mq.removeEventListener?.("change", reapply);
      mq.removeListener?.(reapply);
      document.removeEventListener("visibilitychange", reapply);
      window.removeEventListener("focus", reapply);
    };
  }, [theme]);

  // 【APP49 任务5】语言跟随系统：system 时按 navigator.languages[0] 解析，
  // 监听 languagechange 与 visibilitychange 触发重算（重渲染后
  // 各组件 t() 会重新读取系统语言）
  const [, setLangTick] = useState(0);
  useEffect(() => {
    if (language !== "system") return;
    const bump = () => setLangTick((n) => n + 1);
    window.addEventListener("languagechange", bump);
    document.addEventListener("visibilitychange", bump);
    return () => {
      window.removeEventListener("languagechange", bump);
      document.removeEventListener("visibilitychange", bump);
    };
  }, [language]);

  // 同步 <html lang>，保持无障碍与排版字体正确
  useEffect(() => {
    document.documentElement.lang =
      (language === "system" ? resolveSystemLanguage() : resolveLang(language)) === "zh"
        ? "zh-CN"
        : "en";
  }, [language]);

  // 【APP36 任务2.2】拦截全局撤销/重做输入事件：焦点不在输入框时调用
  // preventDefault()，彻底杜绝 iOS 晃动手机弹出 Undo Typing / Undo Paste。
  useEffect(() => {
    const onBeforeInput = (e: Event) => {
      const ie = e as InputEvent;
      if (ie.inputType !== "historyUndo" && ie.inputType !== "historyRedo") return;
      const ae = document.activeElement as HTMLElement | null;
      const inField =
        !!ae &&
        (ae.tagName === "TEXTAREA" ||
          (ae.tagName === "INPUT" && !(ae as HTMLInputElement).readOnly));
      if (!inField) e.preventDefault();
    };
    document.addEventListener("beforeinput", onBeforeInput, true);
    return () => document.removeEventListener("beforeinput", onBeforeInput, true);
  }, []);

  // 【APP-11 任务3】后端权威状态广播 → 全局 store，实现全 APP 开关实时双向同步：
  // 任意页面（仪表盘 / 设置 / 代理）改动开关，其余页面立即跟随，绝不回弹。
  useEffect(() => {
    const store = useCoreStore.getState();
    const unsubs: Array<() => void> = [];
    listen<UserSettings>("settings://updated", (e) => {
      if (e.payload) store.setSettings(e.payload);
    }).then((fn) => unsubs.push(fn));
    listen<GoLanSettings>("go-lan://updated", (e) => {
      // 【APP24 任务4.1】事件 payload 同样需规范化，防止后端字段缺失
      // 直接入 store 后在渲染期触发 undefined.join/map 崩溃黑屏
      if (e.payload) store.setGoLanSettings(normalizeGoLanSettings(e.payload));
    }).then((fn) => unsubs.push(fn));
    listen<GoCusSettings>("go-cus://updated", (e) => {
      if (e.payload) store.setGoCusSettings(e.payload);
    }).then((fn) => unsubs.push(fn));
    return () => {
      unsubs.forEach((fn) => fn());
    };
  }, []);

  // 授权状态广播（每日同步 / 激活 / 解绑后，Rust 侧推送；当天内只读本地缓存不联网）
  useEffect(() => {
    const unlisten = listen<Entitlement>("pro://status", (event) => {
      useProStore.getState().setEntitlement(event.payload);
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  // 授权到期广播（兼容旧事件）：与 pro://revoked 同时发出，这里只做状态收口，
  // 提示统一由下方 pro://revoked 处理，避免重复弹两次 Toast。
  useEffect(() => {
    const unlisten = listen("pro://expired", () => {
      const store = useProStore.getState();
      store.setRevokeReason("expired");
      store.setEntitlement({ ...store.entitlement, status: "expired" });
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  // 【APP6 任务3】Pro 激活/启动校验后的云端订阅自动同步完成通知
  useEffect(() => {
    const unlisten = listen<{ ok?: number; fail?: number }>(
      "subscriptions://auto-synced",
      (event) => {
        const ok = event.payload?.ok ?? 0;
        const fail = event.payload?.fail ?? 0;
        toast.success(
          t("toast.autoSynced", { ok, fail: ok + fail }),
        );
      },
    );
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [t]);

  // 【APP22 任务1】授权剥夺广播（设备解绑 / 授权到期）：只允许静默更新状态
  // 收口 Pro 功能，严禁弹任何全局 Toast / 横幅 / 自动打开激活弹窗——
  // 启动与巡检时的到期提示已全部清除。
  useEffect(() => {
    const unlisten = listen<{
      reason?: "unbound" | "expired";
      zh?: string;
      en?: string;
    }>("pro://revoked", (event) => {
      const reason =
        event.payload?.reason === "unbound" ? "unbound" : "expired";
      useProStore.getState().setRevokeReason(reason);
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  // 监听内核状态广播：订阅增删改/设置变更触发的 restart_core
  // 对前端透明，重启成功或失败转 Error 都能即时对齐，无需轮询
  useEffect(() => {
    const unlisten = listen<{
      status: CoreStatus;
      mode: RunMode;
      uptimeSecs: number;
      startedAtMs?: number | null;
      outboundMode?: OutboundMode;
    }>("core://status", (event) => {
      const { status, mode, uptimeSecs, startedAtMs, outboundMode } = event.payload;
      const store = useCoreStore.getState();
      store.setStatus(status);
      store.setMode(mode);
      store.setUptime(uptimeSecs);
      // IPA-12：对齐连接起始基准时钟（亮屏 0ms 差值渲染）
      store.syncStartedAt({ status, uptimeSecs, startedAtMs });
      if (outboundMode) store.setOutboundMode(outboundMode);
      // 状态切换（启动/停止/重启）后立即对齐一次后端快照
      if (status === "stopped") store.clearRuntime();
      void refreshRuntime();
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [refreshRuntime]);

  // 运行期被动故障转移：内核连续 2 次探测到当前节点不可用并自动换点后轻提示
  useEffect(() => {
    const unlisten = listen<{ from: string }>("failover://switched", (event) => {
      toast.info(t("proxies.failover", { from: event.payload.from }));
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [t]);

  // 实时速率与内存：内核每秒推送，驱动仪表盘曲线平滑刷新
  useEffect(() => {
    const traffic = listen<{ up: number; down: number }>("traffic://tick", (e) => {
      const store = useCoreStore.getState();
      store.setTrafficRate(e.payload.up, e.payload.down);
      store.pushTraffic(e.payload.up, e.payload.down);
    });
    // 【APP52 任务2】后台遥测常驻广播：600ms 一轮、EMA 平滑后的真实速率，
    // 切页 / 系统后台 / 停启 VPN 均持续推送，仪表盘速率零延迟刷新不卡死。
    const telemetry = listen<{
      up: number;
      down: number;
      today?: number;
      running?: boolean;
      selectedNode?: string | null;
    }>("telemetry://tick", (e) => {
      const store = useCoreStore.getState();
      store.setTrafficRate(e.payload.up ?? 0, e.payload.down ?? 0);
      if (typeof e.payload.today === "number") store.setTodayBytes(e.payload.today);
    });
    const memory = listen<{ inuse: number }>("memory://tick", (e) => {
      useCoreStore.getState().setMemoryUsage(e.payload.inuse);
    });
    // 【APP54 任务4/5】测速 / Go AIM 进度广播：全局 store 收口，任意页面实时渲染
    const delayProgress = listen<ProbeProgress>("delays://progress", (e) => {
      if (e.payload) useCoreStore.getState().setDelayProgress(e.payload);
    });
    const aimProgress = listen<ProbeProgress>("aim://progress", (e) => {
      if (e.payload) useCoreStore.getState().setAimProgress(e.payload);
    });
    return () => {
      traffic.then((fn) => fn());
      telemetry.then((fn) => fn());
      memory.then((fn) => fn());
      delayProgress.then((fn) => fn());
      aimProgress.then((fn) => fn());
    };
  }, []);

  // 【APP52 任务2】全局常驻轮询：800ms 定时器任何时候都不暂停（切换页面、
  // 系统后台、停启 VPN 均继续），移除 document.hidden 暂停逻辑；
  // focus / visibilitychange 立即补拉一次，切回前台 0 延迟对齐速率与曲线。
  const appVisible = useAppVisible();
  useEffect(() => {
    // 上报后端：仍用于连接聚合的省电策略，但绝不暂停前端轮询
    void setAppForeground(appVisible).catch(() => undefined);
    // 【APP43】即使显示未连接也要轮询：后台隧道可能仍在运行，
    // refreshRuntime 会先查状态并触发后端自动接管。
    void refreshRuntime();
    const id = window.setInterval(() => void refreshRuntime(), 800);
    const onWake = () => void refreshRuntime();
    window.addEventListener("focus", onWake);
    document.addEventListener("visibilitychange", onWake);
    return () => {
      window.clearInterval(id);
      window.removeEventListener("focus", onWake);
      document.removeEventListener("visibilitychange", onWake);
    };
  }, [appVisible, refreshRuntime]);

  // 系统 VPN 被撤销（Android onRevoke：用户在系统设置关闭 / 其他 VPN 抢占）
  // → 停止内核并对齐前端状态
  useEffect(() => {
    const unlisten = listen("pro://vpn-revoked", () => {
      stopCore()
        .then(() => {
          const store = useCoreStore.getState();
          store.setStatus("stopped");
          store.setUptime(0);
          store.setStartedAtMs(null);
          store.clearRuntime();
        })
        .catch(() => undefined);
      toast.error(t("app.vpnRevoked"));
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [t]);

  // APP 远程管控广播（APP-4 任务2）：allowed=false → 全屏不可关闭阻断框；
  // allowed=true（解除管控）→ 撤下阻断框。后端已同步停止内核并禁止启动。
  useEffect(() => {
    const unlisten = listen<{
      allowed: boolean;
      reason: string;
      message: string;
    }>("app://control", (event) => {
      if (event.payload.allowed) {
        setControlBlock(null);
        return;
      }
      setControlBlock({
        reason: event.payload.reason === "user_blocked" ? "user_blocked" : "version_blocked",
        message: event.payload.message,
      });
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  return (
    <div className="flex flex-col h-screen bg-surface text-gray-200 overflow-hidden">
      <TitleBar />
      {/* 移动端顶部状态栏独立安全区（ipa-8）：占位条固定不滚动，页面标题
          不会与系统时间/信号栏重叠，滚动时内容也不会穿透到状态栏下方 */}
      {isMobile() && (
        <div
          className="w-full shrink-0 bg-surface"
          style={{ height: "max(env(safe-area-inset-top, 0px), 48px)" }}
        />
      )}
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="w-full max-w-full flex-1 overflow-y-auto overflow-x-hidden box-border px-4 pt-3 pb-[calc(4rem+env(safe-area-inset-bottom))] md:pt-[calc(1.5rem+env(safe-area-inset-top))] md:pb-[calc(1.5rem+env(safe-area-inset-bottom))]">
          {/* APP-5 任务1：全局常驻横幅已移除。到期/解绑提示仅在激活 Pro 弹窗
              与设置 → PRISM PRO 激活区内展示，平时界面保持清爽。 */}
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/proxies" element={<ProxiesHub />} />
            <Route path="/subscription" element={<Subscription />} />
            <Route path="/rules" element={<Navigate to="/proxies?tab=rules" replace />} />
            <Route path="/connections" element={<Navigate to="/proxies?tab=connections" replace />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
      <BottomNav />
      <ToastViewport />
      {/* APP 远程管控阻断框（APP-4 任务2）：全屏遮罩、不可关闭——被管控设备
          内核已被后端停止且无法启动，用户只能按提示更新版本或联系客服 */}
      {controlBlock && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-6">
          <div className="w-full max-w-sm space-y-4 rounded-2xl border border-latency-bad/40 bg-surface-card p-6 text-center">
            <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-latency-bad/15">
              <ShieldBan size={22} className="text-latency-bad" />
            </span>
            <h2 className="text-base font-semibold text-gray-100">
              {controlBlock.reason === "user_blocked"
                ? t("appControl.userBlocked")
                : t("appControl.versionBlocked")}
            </h2>
            <p className="break-all text-xs leading-relaxed text-gray-400">
              {controlBlock.message}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
