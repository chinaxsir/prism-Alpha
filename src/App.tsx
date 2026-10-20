import { useCallback, useEffect } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { listen } from "@tauri-apps/api/event";
import Sidebar from "@/components/Sidebar";
import TitleBar from "@/components/TitleBar";
import BottomNav from "@/components/BottomNav";
import ToastViewport, { toast } from "@/components/ui/Toast";
import Dashboard from "@/pages/Dashboard";
import Subscription from "@/pages/Subscription";
import Analytics from "@/pages/Analytics";
import Settings from "@/pages/Settings";
import { useCoreStore, type CoreStatus, type OutboundMode, type RunMode } from "@/stores/core";
import { useProStore } from "@/stores/pro";
import { applyTheme, usePrefsStore } from "@/stores/prefs";
import { resolveLang, useTranslation } from "@/i18n";
import {
  getRuntimeSnapshot,
  getSettings,
  stopCore,
  type Entitlement,
} from "@/api/ipc";
import { isMobile } from "@/pro/gating";
import ProxiesHub from "@/pages/ProxiesHub";

export default function App() {
  const initPro = useProStore((s) => s.init);
  const { t } = useTranslation();
  const theme = usePrefsStore((s) => s.theme);
  const language = usePrefsStore((s) => s.language);
  const setLanguage = usePrefsStore((s) => s.setLanguage);
  const setTheme = usePrefsStore((s) => s.setTheme);

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

  // 启动时恢复语言与外观偏好（持久化于后端 settings.json）
  useEffect(() => {
    getSettings()
      .then((s) => {
        if (s.language) setLanguage(s.language);
        if (s.theme) setTheme(s.theme);
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

  // 授权状态广播（每日同步 / 激活 / 解绑后，Rust 侧推送；当天内只读本地缓存不联网）
  useEffect(() => {
    const unlisten = listen<Entitlement>("pro://status", (event) => {
      useProStore.getState().setEntitlement(event.payload);
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
      outboundMode?: OutboundMode;
    }>("core://status", (event) => {
      const { status, mode, uptimeSecs, outboundMode } = event.payload;
      const store = useCoreStore.getState();
      store.setStatus(status);
      store.setMode(mode);
      store.setUptime(uptimeSecs);
      if (outboundMode) store.setOutboundMode(outboundMode);
      // 状态切换（启动/停止/重启）后立即对齐一次后端快照
      if (status === "stopped") store.clearRuntime();
      void refreshRuntime();
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [refreshRuntime]);

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
    const id = window.setInterval(() => {
      if (useCoreStore.getState().status === "running") void refreshRuntime();
    }, 2000);
    const onVisible = () => {
      if (document.visibilityState === "visible") void refreshRuntime();
    };
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", onVisible);
    return () => {
      window.clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("focus", onVisible);
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
          store.clearRuntime();
        })
        .catch(() => undefined);
      toast.error(t("app.vpnRevoked"));
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [t]);

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
    </div>
  );
}
