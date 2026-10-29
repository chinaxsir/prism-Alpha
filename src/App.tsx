import { useCallback, useEffect, useState } from "react";
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
import { useCoreStore, type CoreStatus, type OutboundMode, type RunMode, type UserSettings } from "@/stores/core";
import { useProStore } from "@/stores/pro";
import { applyTheme, usePrefsStore } from "@/stores/prefs";
import { resolveLang, useTranslation } from "@/i18n";
import {
  getRuntimeSnapshot,
  getSettings,
  stopCore,
  getGoAimStatus,
  getGoLanSettings,
  getGoCusSettings,
  listSubscriptions,
  setAppForeground,
  type Entitlement,
  type GoCusSettings,
  type GoLanSettings,
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

  /** 拉取后端运行时快照并写入全局 store（今日流量 / 速率 / 60s 曲线 / 连接 / 分析） */
  const refreshRuntime = useCallback(async () => {
    try {
      const snap = await getRuntimeSnapshot();
      useCoreStore.getState().applyRuntimeSnapshot(snap);
    } catch {
      /* 内核未就绪时静默忽略 */
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

  // 应用外观，并实时监听系统深浅色变化（跟随系统时无感切换）
  useEffect(() => {
    applyTheme(theme);
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      if (usePrefsStore.getState().theme === "system") applyTheme("system");
    };
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, [theme]);

  // 同步 <html lang>，保持无障碍与排版字体正确
  useEffect(() => {
    document.documentElement.lang = resolveLang(language) === "zh" ? "zh-CN" : "en";
  }, [language]);

  // 【APP-11 任务3】后端权威状态广播 → 全局 store，实现全 APP 开关实时双向同步：
  // 任意页面（仪表盘 / 设置 / 代理）改动开关，其余页面立即跟随，绝不回弹。
  useEffect(() => {
    const store = useCoreStore.getState();
    const unsubs: Array<() => void> = [];
    listen<UserSettings>("settings://updated", (e) => {
      if (e.payload) store.setSettings(e.payload);
    }).then((fn) => unsubs.push(fn));
    listen<GoLanSettings>("go-lan://updated", (e) => {
      if (e.payload) store.setGoLanSettings(e.payload);
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
    const memory = listen<{ inuse: number }>("memory://tick", (e) => {
      useCoreStore.getState().setMemoryUsage(e.payload.inuse);
    });
    return () => {
      traffic.then((fn) => fn());
      memory.then((fn) => fn());
    };
  }, []);

  // 前后台不间断：定时拉取后端快照，并在从后台切回前台（亮屏解锁）瞬间立即同步
  useEffect(() => {
    void refreshRuntime();
    const syncForeground = () => {
      const visible = document.visibilityState === "visible";
      // 上报后端：后台时暂停事件推送与连接聚合，切回前台立即恢复
      void setAppForeground(visible).catch(() => undefined);
      if (visible) void refreshRuntime();
    };
    const id = window.setInterval(() => {
      // 隐藏（锁屏/切 App）时不再每 2s 唤醒 JS 线程，彻底静止待机
      if (document.visibilityState !== "visible") return;
      if (useCoreStore.getState().status === "running") void refreshRuntime();
    }, 2000);
    syncForeground();
    document.addEventListener("visibilitychange", syncForeground);
    window.addEventListener("focus", syncForeground);
    // pageshow：移动端系统回退缓存页（bfcache）恢复时 visibilitychange
    // 可能不触发，pageshow 兜底拉取快照（IPA-12）
    window.addEventListener("pageshow", syncForeground);
    return () => {
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", syncForeground);
      window.removeEventListener("focus", syncForeground);
      window.removeEventListener("pageshow", syncForeground);
    };
  }, [refreshRuntime]);

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
        <main className="flex-1 overflow-y-auto overflow-x-hidden px-6 pt-3 pb-[calc(4rem+env(safe-area-inset-bottom))] md:pt-[calc(1.5rem+env(safe-area-inset-top))] md:pb-[calc(1.5rem+env(safe-area-inset-bottom))]">
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
