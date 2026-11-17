import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import {
  Power,
  Globe,
  Activity,
  X,
  ChevronRight,
  Crosshair,
  Home,
  Wand2,
} from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import clsx from "clsx";

import {
  getCachedProxies,
  getCoreStatus,
  getProxyGroups,
  selectProxy,
  startCore,
  stopCore,
  getGoAimStatus,
  setGoAimEnabled,
  runGoAimProbe,

  getGoLanSettings,
  getGoLanStatus,
  saveGoLanSettings,
  getGoCusSettings,
  saveGoCusSettings,
  isGoLanConfigured,
  type GoLanStatus,
} from "@/api/ipc";
import {
  useCoreStore,
  isDummyNodeName,
  ensureAimListenersRegistered,
  syncAimSnapshot,
} from "@/stores/core";
import { useProStore } from "@/stores/pro";
import { useTranslation } from "@/i18n";
import { useAppVisible } from "@/hooks/useAppVisible";
import { formatBytes, formatSpeed, formatUptime } from "@/utils/format";
import { delayClass, delayText } from "@/utils/latency";
import { toast } from "@/components/ui/Toast";
import OutboundModeSwitch from "@/components/OutboundModeSwitch";
import GoLanModal from "@/components/GoLanModal";
import Switch from "@/components/ui/Switch";

/// 与节点页一致的组类型过滤：只保留真实节点
const GROUP_TYPES = ["Selector", "URLTest", "Fallback", "LoadBalance"];

interface ProxyEntry {
  name: string;
  type: string;
  now?: string;
  all?: Array<ProxyEntry | string>;
  history?: Array<{ delay: number }>;
}

/// 【APP66 任务3】仪表盘丝滑网速插值：
/// 后端每 1000ms 采样一次，若直接渲染会 "瞬移" 跳动。以 160ms（约 6fps）
/// 指数阻尼 0.32 向目标值缓动，纯前端数学插值，0 IPC、CPU 占用 < 0.05%。
function useSmoothSpeed(target: number, active: boolean): number {
  const [display, setDisplay] = useState(0);
  const currentRef = useRef(0);
  const targetRef = useRef(0);

  useEffect(() => {
    targetRef.current = active ? Math.max(0, target) : 0;
    if (!active) {
      currentRef.current = 0;
      setDisplay(0);
    }
  }, [target, active]);

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => {
      const cur = currentRef.current;
      const tgt = targetRef.current;
      const diff = tgt - cur;
      if (Math.abs(diff) < 64) {
        currentRef.current = tgt;
      } else {
        currentRef.current = Math.round(cur + diff * 0.32);
      }
      setDisplay(currentRef.current);
    }, 160);
    return () => window.clearInterval(timer);
  }, [active]);

  return display;
}

export default function Dashboard() {
  const { t } = useTranslation();
  const status = useCoreStore((s) => s.status);
  const upSpeed = useCoreStore((s) => s.upSpeed);
  const downSpeed = useCoreStore((s) => s.downSpeed);
  // 【APP66 任务3】渲染值走 160ms 缓动插值，数字连续滚动不顿挫
  const smoothDown = useSmoothSpeed(downSpeed, status === "running");
  const smoothUp = useSmoothSpeed(upSpeed, status === "running");
  // 【mac 任务3.2】双轨流量波形图：42 点滑动窗口历史队列
  const HISTORY_LEN = 42;
  const [downHistory, setDownHistory] = useState<number[]>(() => new Array(HISTORY_LEN).fill(0));
  const [upHistory, setUpHistory] = useState<number[]>(() => new Array(HISTORY_LEN).fill(0));
  const [peakDown, setPeakDown] = useState(0);
  const [peakUp, setPeakUp] = useState(0);
  // 每 500ms 采样一次当前平滑速率入队
  useEffect(() => {
    const id = window.setInterval(() => {
      const d = status === "running" ? smoothDown : 0;
      const u = status === "running" ? smoothUp : 0;
      setDownHistory((prev) => [...prev.slice(1), d]);
      setUpHistory((prev) => [...prev.slice(1), u]);
      setPeakDown((p) => (d > p ? d : p));
      setPeakUp((p) => (u > p ? u : p));
    }, 500);
    return () => window.clearInterval(id);
  }, [smoothDown, smoothUp, status]);
  // 停止时峰值归零（下次启动重新统计）
  useEffect(() => {
    if (status !== "running") {
      setPeakDown(0);
      setPeakUp(0);
    }
  }, [status]);
  const uptimeSecs = useCoreStore((s) => s.uptimeSecs);
  const startedAtMs = useCoreStore((s) => s.startedAtMs);
  // 今日流量：后端持久化基数 + 当前会话内核绝对累计（前后台不间断）
  const todayBytes = useCoreStore((s) => s.todayBytes);
  const setStatus = useCoreStore((s) => s.setStatus);
  // 【APP53 任务1.1】运行模式已从主控卡移除，但 start/stop/runtime 同步
  // 仍需调用这些 setter（内核 API 会上报 mode + outboundMode）
  const setMode = useCoreStore((s) => s.setMode);
  const setOutboundMode = useCoreStore((s) => s.setOutboundMode);
  const setUptime = useCoreStore((s) => s.setUptime);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  /// 【APP53 任务1.1】只有当用户亲手点击了「启动」按钮后发生的错误才展示红点；
  /// 新装/冷启动/无订阅时一律静默显示灰点「未连接」，绝不误报
  /// 同步 ref：避免 React 异步更新导致 catch 里读到旧值 false
  const manualStartRef = useRef(false);
  /// 【APP55 任务1】手动启动失败标记：仅用户亲手点启动且本次启动失败才为 true；
  /// 页面初始化恒 false，冷启动/自动同步/订阅更新等非手动操作绝不置红
  const [manualStartFailed, setManualStartFailed] = useState(false);
  const navigate = useNavigate();

  // Pro 授权状态（APP-13 任务3：入口常驻，未激活时卡片整体置灰）
  const proUnlocked = useProStore((s) => s.unlocked);
  // 【APP-12 任务2.2】Go Lan 配置弹窗：仪表盘「配置」按钮页内直开，不再跳设置页
  const [goLanModalOpen, setGoLanModalOpen] = useState(false);

  // 当前节点状态：主选择组、当前选中节点名、可选节点列表、选择器弹窗
  const [mainSelector, setMainSelector] = useState("");
  const [currentNode, setCurrentNode] = useState("");
  /// 【APP47 任务1.2】后端持久化的选中节点名：未启动时也直接展示，
  /// 避免「当前节点」卡出现「—」死状态
  const [persistedNode, setPersistedNode] = useState("");
  const [nodes, setNodes] = useState<ProxyEntry[]>([]);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [selecting, setSelecting] = useState(false);

  // Pro 引擎矩阵状态（Go AIM / Go Lan / Go Cus）：APP 任务1 提升到全局
  // store（App.tsx 启动预加载），切页切回仪表盘时直接命中缓存渲染，
  // 消除「先关后开」闪烁
  const aim = useCoreStore((s) => s.goAimStatus);
  const lan = useCoreStore((s) => s.goLanSettings);
  const cus = useCoreStore((s) => s.goCusSettings);
  // 【APP54 任务5】Go AIM 实时进度（全局 store，事件驱动）
  const aimProgress = useCoreStore((s) => s.aimProgress);
  // 【v0.4.17】Go AIM 最近事件：探测中用它展示「正在检测: 节点」
  const aimEvent = useCoreStore((s) => s.aimEvent);
  // 【v0.4.17】Go Lan 内网档案运行状态仍按需拉取更新（状态胶囊改用短状态，
  // 不再直接渲染档案明细），因此只保留 setter，避免未读变量告警。
  const [, setLanState] = useState<GoLanStatus | null>(null);

  const running = status === "running";
  // 【APP53 任务1.2】运行模式字样已从主控卡移除，outboundMode/mode 不再直接渲染；
  // 内核运行模式仍由 start/stop/runtime 同步调用 store.setMode/setOutboundMode 记录。
  // 拉取主选择组与当前节点（内核运行时才有实时数据）
  const loadCurrentNode = async () => {
    try {
      const st = await getCoreStatus();
      setPersistedNode(st.selectedNode ?? "");
      const group = st.mainSelector ?? "";
      setMainSelector(group);
      if (st.status !== "running" || !group) {
        setCurrentNode("");
        // 未启动兜底：读取订阅缓存节点展示第一个，并支持点击预选
        // （ipa-8 方案：启动前卡片不再显示「—」死状态）
        // 【APP33 任务3.2】过滤「剩余流量/到期时间」等信息/广告类假节点
        try {
          const cached = await getCachedProxies();
          setNodes(
            cached
              .filter((c) => !isDummyNodeName(c.name))
              .map((c) => ({ name: c.name, type: c.kind, history: [] }))
          );
        } catch {
          setNodes([]);
        }
        return;
      }
      const resp = (await getProxyGroups()) as {
        proxies?: Record<string, ProxyEntry>;
      };
      const map = resp.proxies ?? {};
      const g = map[group];
      if (!g) return;
      // 【APP33 任务3.2】过滤「剩余流量/到期时间」等信息/广告类假节点
      const realNodes = (g.all ?? [])
        .map((item) => (typeof item === "string" ? map[item] : item))
        .filter((item): item is ProxyEntry => Boolean(item))
        .filter((item) => !GROUP_TYPES.includes(item.type))
        .filter((item) => !isDummyNodeName(item.name));
      setNodes(realNodes);

      const now = g.now ?? "";
      // 当前选中节点是假节点或不在真实列表中 → 自动纠偏到首个真实节点
      const nowValid = now && !isDummyNodeName(now) && realNodes.some((n) => n.name === now);
      if (!nowValid) {
        setCurrentNode("");
        if (realNodes.length > 0) {
          const first = realNodes[0].name;
          try {
            await selectProxy(group, first);
            setCurrentNode(first);
          } catch {
            /* 后端 select_proxy 可能因内核未就绪拒绝，保持空态等待下次刷新 */
          }
        }
      } else {
        setCurrentNode(now);
      }
    } catch {
      /* 内核未运行 / API 未就绪：保持空态 */
    }
  };

  // 当前节点随内核状态与节点变化刷新（启动自动选点、节点页手动切换、
  // 云端订阅同步补拉）
  useEffect(() => {
    loadCurrentNode();
    const unStatus = listen("core://status", () => loadCurrentNode());
    const unProxies = listen("proxies://changed", () => loadCurrentNode());
    const unSubs = listen("subscriptions://changed", () => loadCurrentNode());
    return () => {
      unStatus.then((fn) => fn());
      unProxies.then((fn) => fn());
      unSubs.then((fn) => fn());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 【APP71 任务3】Go AIM 快照同步：挂载与回前台时对齐真实进度 / 结果，
  // 与 go-aim://event 事件流合并后不会出现「进度停在中途 / 结果缺失」。
  useEffect(() => {
    void ensureAimListenersRegistered().catch(() => undefined);
    void syncAimSnapshot();
    const onVisible = () => {
      if (document.visibilityState === "visible") void syncAimSnapshot();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, []);

  // 本地运行时长时钟（IPA-12）：禁止每秒 +1 计数器（锁屏/切后台时
  // 系统 WebView 冻结定时器，亮屏后要等下个 tick 才恢复）。改为维护
  // nowMs 本地时钟，以 250ms 轻量间隔刷新，时长 = (nowMs - startedAtMs)
  // 差值实时计算；亮屏/回前台第一帧由下方唤醒监听 0ms 校准
  const [nowMs, setNowMs] = useState(() => Date.now());
  // 【APP49 任务6】App 前台可见性：后台时所有定时器暂停清理
  const appVisible = useAppVisible();

  useEffect(() => {
    // 【APP-3 / APP49 任务6】后台（锁屏/切 App）停掉 250ms 时钟：清理 interval
    // 不再每秒 4 次唤醒 JS 线程；回前台立即校准一次再恢复定时，时长无跳变
    if (!running || !appVisible) return;
    setNowMs(Date.now());
    const timer = window.setInterval(() => setNowMs(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [running, appVisible]);

  // 关键唤醒监听（IPA-12）：亮屏/回前台瞬间第 1 步 0ms 刷新本地时钟
  // （时长立刻跳到准确值，不等任何异步请求），第 2 步后台静默拉取
  // 最新状态对齐基准时间戳与流量快照
  useEffect(() => {
    const syncClockImmediately = () => {
      if (document.visibilityState === "visible") {
        setNowMs(Date.now());
        getCoreStatus()
          .then((data) => {
            const store = useCoreStore.getState();
            store.setStatus(data.status);
            store.setMode(data.mode);
            store.setUptime(data.uptimeSecs);
            store.syncStartedAt({
              status: data.status,
              uptimeSecs: data.uptimeSecs,
              startedAtMs: data.startedAtMs,
            });
            if (data.outboundMode) store.setOutboundMode(data.outboundMode);
          })
          .catch(() => undefined);
      }
    };
    document.addEventListener("visibilitychange", syncClockImmediately);
    window.addEventListener("focus", syncClockImmediately);
    window.addEventListener("pageshow", syncClockImmediately);
    return () => {
      document.removeEventListener("visibilitychange", syncClockImmediately);
      window.removeEventListener("focus", syncClockImmediately);
      window.removeEventListener("pageshow", syncClockImmediately);
    };
  }, []);

  // 【APP26 任务2.2】启动期间 250ms 快速轮询：iOS 隧道通常约 1.5s 建好，
  // 若后端状态事件滞后，界面也能立即切到「已连接」，不必等默认轮询周期；
  // 【APP49 任务6】后台时清理定时器，回前台立即补拉一次再恢复
  useEffect(() => {
    if (status !== "starting" || !appVisible) return;
    let stopped = false;
    let timer: number | undefined;
    const poll = () => {
      getCoreStatus()
        .then((data) => {
          if (stopped || data.status === "starting") return;
          const store = useCoreStore.getState();
          store.setStatus(data.status);
          store.setMode(data.mode);
          store.setUptime(data.uptimeSecs);
          store.syncStartedAt({
            status: data.status,
            uptimeSecs: data.uptimeSecs,
            startedAtMs: data.startedAtMs,
          });
          if (data.outboundMode) store.setOutboundMode(data.outboundMode);
          stopped = true;
          if (timer !== undefined) window.clearInterval(timer);
        })
        .catch(() => undefined);
    };
    poll();
    timer = window.setInterval(poll, 250);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [status, appVisible]);

  // 实时展示的已连接秒数：固定公式 nowMs - startedAtMs 差值（IPA-12）；
  // 基准尚未就绪时回退 store 内 uptimeSecs（启动事件与首次拉取的间隙）
  const displayUptimeSecs = running
    ? startedAtMs
      ? Math.max(0, Math.floor((nowMs - startedAtMs) / 1000))
      : uptimeSecs
    : 0;

  // 启动时与后端对齐一次状态（含运行模式：权威来源是后端持久化的 settings.json）
  useEffect(() => {
    getCoreStatus()
      .then((data) => {
        setStatus(data.status);
        setMode(data.mode);
        setUptime(data.uptimeSecs);
        useCoreStore.getState().syncStartedAt({
          status: data.status,
          uptimeSecs: data.uptimeSecs,
          startedAtMs: data.startedAtMs,
        });
        if (data.outboundMode) setOutboundMode(data.outboundMode);
      })
      .catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Pro 引擎状态：挂载时静默刷新一次全局缓存（绝不重置为 null/false）；
  // Go AIM 评级结果经事件实时刷新
  useEffect(() => {
    const store = useCoreStore.getState();
    getGoAimStatus().then(store.setGoAimStatus).catch(() => undefined);
    getGoLanSettings().then(store.setGoLanSettings).catch(() => undefined);
    getGoCusSettings().then(store.setGoCusSettings).catch(() => undefined);
    const unAim = listen<{ hint?: string }>("go-aim://updated", (e) => {
      // 【APP66 任务1】未连隧道时只做真实延迟测速：后端随事件下发 hint，
      // 这里明确告知用户「解锁徽章需先启动代理后重新检测」，绝不含糊其辞
      if (e.payload?.hint) toast.info(e.payload.hint);
      getGoAimStatus()
        .then(useCoreStore.getState().setGoAimStatus)
        .catch(() => undefined);
    });
    return () => {
      unAim.then((fn) => fn());
    };
  }, []);

  // 【APP40 任务2】Go Lan 档案状态：任一档案启停变化时刷新 ⚡/🔒 徽章
  // 【APP54 任务1】物理网络切换（连上家里/公司 Wi-Fi）后必须尽快显示直连，
  // 因此启用期间每 3s 轻量刷新一次后端注入的 isDirect（未启用时零开销跳过）
  useEffect(() => {
    if (!lan?.enabled) {
      setLanState(null);
      return;
    }
    let cancelled = false;
    const load = () => {
      getGoLanStatus()
        .then((s) => {
          if (!cancelled) setLanState(s);
        })
        .catch(() => {
          if (!cancelled) setLanState(null);
        });
    };
    load();
    const timer = window.setInterval(load, 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [lan?.enabled, lan?.profiles]);

  // 【APP51 任务1.3】全开关 0ms 乐观 UI：先同步改前端状态，再异步落盘；
  // 失败时回滚并 toast，点击后界面立即变色，绝不等待 IPC/内核重启
  const toggleAim = async (v: boolean) => {
    const store = useCoreStore.getState();
    const prevStatus = store.goAimStatus;
    if (prevStatus) store.setGoAimStatus({ ...prevStatus, enabled: v });
    try {
      await setGoAimEnabled(v);
    } catch (e) {
      if (prevStatus) useCoreStore.getState().setGoAimStatus(prevStatus);
      toast.error(String(e));
    }
  };

  const toggleLan = async (v: boolean) => {
    const store = useCoreStore.getState();
    const s = store.goLanSettings;
    // APP 任务5：未配置时拦截开启，Toast 引导并跳转配置区
    if (v && (!s || !isGoLanConfigured(s))) {
      toast.error(t("dashboard.lan.configureFirst"));
      navigate("/settings?focus=goLan");
      return;
    }
    if (!s) return;
    const next = { ...s, enabled: v };
    store.setGoLanSettings(next); // 乐观更新
    try {
      await saveGoLanSettings(next);
    } catch (e) {
      useCoreStore.getState().setGoLanSettings(s);
      toast.error(String(e));
    }
  };

  const toggleCus = async (v: boolean) => {
    const store = useCoreStore.getState();
    const s = store.goCusSettings;
    // APP 任务5：无模块时拦截开启，Toast 引导并跳转 Go Cus 模块页
    if (v && (!s || s.modules.length === 0)) {
      toast.error(t("dashboard.cus.configureFirst"));
      navigate("/proxies?tab=goCus");
      return;
    }
    if (!s) return;
    const next = { ...s, enabled: v };
    store.setGoCusSettings(next); // 乐观更新
    try {
      await saveGoCusSettings(next);
    } catch (e) {
      useCoreStore.getState().setGoCusSettings(s);
      toast.error(String(e));
    }
  };

  const toggle = async () => {
    setErrorMsg(null);
    try {
      if (running) {
        await stopCore();
        // 【APP57 任务2】停止即清空分析统计，页面立即归零
        useCoreStore.getState().resetAnalytics();
        setStatus("stopped");
        setUptime(0);
        useCoreStore.getState().setStartedAtMs(null);
        // 停止后重置手动启动标记：下次要手动点启动才会再次显示错误
        manualStartRef.current = false;
        setManualStartFailed(false);
      } else {
        // 【APP53 任务1.1】标记用户已亲手点过启动，只有此后的错误才展示红点
        manualStartRef.current = true;
        setManualStartFailed(false);
        setStatus("starting");
        await startCore();
        // 【APP57 任务2】新会话启动即清空上一会话的分析统计
        useCoreStore.getState().resetAnalytics();
        setStatus("running");
      }
    } catch (e) {
      console.error("toggle core failed:", e);
      // 【APP53 任务1.1】只在用户明确手动点过启动后才展示 error；
      // 冷启动/自动恢复/切网重试的失败一律静默显示「未连接」
      if (manualStartRef.current) {
        setManualStartFailed(true);
        setStatus("error");
        setErrorMsg(String(e));
      } else {
        setStatus("stopped");
      }
    }
  };

  // 【APP55 任务1】连接成功后清空失败标记，状态灯回归绿色
  useEffect(() => {
    if (running) setManualStartFailed(false);
  }, [running]);

  /// 节点最近一次延迟（无测速记录为 undefined）
  const nodeDelay = (n: ProxyEntry): number | undefined =>
    n.history && n.history.length > 0
      ? n.history[n.history.length - 1].delay
      : undefined;

  /// 选择器列表：有延迟数据的按延迟从低到高，无数据保持原顺序靠后
  const sortedNodes = useMemo(() => {
    const delayOf = (n: ProxyEntry) => nodeDelay(n) ?? -1;
    const measured = nodes
      .filter((n) => (nodeDelay(n) ?? 0) > 0)
      .sort((a, b) => delayOf(a) - delayOf(b));
    const rest = nodes.filter((n) => !((nodeDelay(n) ?? 0) > 0));
    return [...measured, ...rest];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes]);

  /// 从仪表盘直接指定使用节点
  const pickNode = async (name: string) => {
    if (selecting) return;
    // 未启动时仅做预选：内核 API 不存在，无法真正切换；
    // 本地记住选择，启动自动选点后用户仍可手动改选
    if (!mainSelector) {
      setCurrentNode(name);
      setPickerOpen(false);
      toast.success(t("dashboard.pickerPreselected", { name }));
      return;
    }
    setSelecting(true);
    try {
      await selectProxy(mainSelector, name);
      setCurrentNode(name);
      setPickerOpen(false);
      toast.success(t("dashboard.pickerSwitched", { name }));
    } catch (e) {
      console.error("pick node failed:", e);
      toast.error(t("dashboard.pickerFailed", { error: String(e) }));
    } finally {
      setSelecting(false);
    }
  };

  // ---- 【v0.4.17 任务3】Pro 引擎状态：胶囊只放「短状态」，长句仅出现在底行简介 ----
  // 旧实现把长描述同时塞进状态胶囊与副标题，移动端出现同一句话重复两遍，
  // 且挤压掉 Go Lan / Go Cus 的「配置」按钮。
  const aimRated = Object.keys(aim?.results ?? {}).length;
  const aimRunning = aimProgress.running || Boolean(aim?.probing);
  const aimPill = !aim?.enabled
    ? t("engine.status.standby")
    : aimRunning
      ? t("engine.status.probing", {
          done: aimProgress.done,
          total: aimProgress.total || aimRated,
        })
      : t("engine.status.optimized", { count: aimRated });
  // Go AIM 底行：探测中动态展示当前检测节点与进度，平时展示功能简介
  const aimDesc = aimRunning
    ? t("dashboard.aim.probingDetail", {
        node: aimEvent?.message?.trim() || t("dashboard.aim.probing"),
        percent: aimProgress.percent,
      })
    : t("engine.goAim.desc");
  const lanPill = lan?.enabled
    ? t("engine.status.active")
    : t("engine.status.standby");
  const cusPill = cus?.enabled
    ? t("engine.status.active")
    : t("engine.status.standby");

  // 【v0.4.17 任务1】当前节点展示名与实时延迟（未启动时回退持久化选择）
  const displayNodeName =
    currentNode || persistedNode || nodes[0]?.name || t("dashboard.noSelection");
  const activeNode = nodes.find((n) => n.name === displayNodeName);
  const currentDelay = activeNode ? (nodeDelay(activeNode) ?? 0) : 0;

  // Go AIM 开启时的「重测」：立即触发一轮评级探测（结果经 go-aim://updated 事件刷新）
  const runAimProbe = async () => {
    try {
      await runGoAimProbe();
    } catch (e) {
      toast.error(t("dashboard.aim.retestFailed", { error: String(e) }));
    }
  };

  return (
    // 【mac 任务3.1】商业级四层 Bento 网格布局：自上而下无缝排列，
    // 统一 gap-3.5，消除原先中间大片空白断层。
    <div className="flex h-full min-h-0 flex-col gap-3.5 pb-2">
      {/* 第一层：标题 + 出站模式分段控制器 */}
      <h1 className="text-[22px] font-bold tracking-tight shrink-0">{t("dashboard.title")}</h1>
      <div className="shrink-0">
        <OutboundModeSwitch />
      </div>

      {/* 【v0.4.17 任务1】卡片 A：连接状态与启停主控卡（左：呼吸灯+文案+大号等宽时长；右：启停胶囊） */}
      <div className="rounded-2xl py-3.5 px-4 border bg-surface-card border-border shrink-0">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <span
                className={`inline-block w-2 h-2 shrink-0 rounded-full ${
                  running
                    ? "bg-emerald-500"
                    : status === "starting"
                      ? "bg-amber-400"
                      : manualStartFailed
                        ? "bg-latency-bad"
                        : "bg-gray-500"
                } ${running || status === "starting" ? "animate-pulse" : ""}`}
              />
              {running
                ? t("status.connected")
                : status === "starting"
                  ? t("status.starting")
                  : manualStartFailed
                    ? t("status.startFailed")
                    : t("status.disconnected")}
            </div>
            <div className="mt-0.5 truncate text-2xl md:text-3xl font-bold font-mono tracking-tight tabular-nums text-gray-100">
              {running ? formatUptime(displayUptimeSecs) : "Prism"}
            </div>
          </div>
          <button
            onClick={toggle}
            disabled={status === "starting"}
            className={`shrink-0 flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed ${
              running
                ? "bg-latency-bad/20 text-latency-bad hover:bg-latency-bad/30"
                : "bg-accent text-white hover:bg-accent-hover"
            }`}
          >
            <Power size={16} className={status === "starting" ? "animate-pulse" : ""} />
            {running
              ? t("action.stop")
              : status === "starting"
                ? t("action.starting")
                : t("action.start")}
          </button>
        </div>
      </div>

      {/* 【v0.4.17 任务1】卡片 B：当前节点 + 今日流量 独立双栏 Bento 网格
          （左 7/12 ≈ 62% 展示节点与延迟，右 5/12 ≈ 38% 展示今日流量） */}
      <div className="grid grid-cols-12 gap-3 shrink-0">
        <button
          type="button"
          onClick={nodes.length > 0 ? () => setPickerOpen(true) : undefined}
          disabled={nodes.length === 0}
          className={clsx(
            "col-span-7 md:col-span-8 min-w-0 rounded-2xl bg-surface-card border border-border px-3.5 py-3 text-left flex flex-col justify-between transition-colors",
            nodes.length > 0
              ? "cursor-pointer hover:border-accent/30 active:opacity-80"
              : "cursor-default"
          )}
        >
          <div className="flex items-center gap-1.5 min-w-0">
            <Globe size={14} className="shrink-0 text-[#007AFF] dark:text-[#0A84FF]" />
            <span className="text-xs font-medium text-text-muted whitespace-nowrap">
              {t("metric.currentNode")}
            </span>
            {currentDelay > 0 && (
              <span
                className={clsx(
                  "ml-auto shrink-0 text-[11px] font-mono tabular-nums",
                  delayClass(currentDelay)
                )}
              >
                {delayText(currentDelay)}
              </span>
            )}
            {nodes.length > 0 && (
              <ChevronRight
                size={14}
                className={clsx(
                  "shrink-0 text-text-muted",
                  currentDelay <= 0 && "ml-auto"
                )}
              />
            )}
          </div>
          <div
            className="mt-1 min-w-0 truncate text-sm md:text-base font-semibold text-text"
            title={displayNodeName}
          >
            {displayNodeName}
          </div>
        </button>

        <div className="col-span-5 md:col-span-4 min-w-0 rounded-2xl bg-surface-card border border-border px-3.5 py-3 flex flex-col justify-between">
          <div className="flex items-center gap-1.5 min-w-0">
            <Activity size={14} className="shrink-0 text-[#00C7BE]" />
            <span className="text-xs font-medium text-text-muted whitespace-nowrap">
              {t("metric.todayTraffic")}
            </span>
          </div>
          <div className="mt-1 min-w-0 truncate text-sm md:text-base font-bold font-mono tabular-nums text-text">
            {formatBytes(todayBytes || 0)}
          </div>
        </div>
      </div>

      {/* 启动/停止错误提示 */}
      {errorMsg && (
        <div className="rounded-xl p-4 text-sm bg-red-500/10 text-red-700 dark:text-red-300 border border-red-500/30 shrink-0">
          <div className="font-semibold mb-1">{t("dashboard.errorTitle")}</div>
          <div className="text-xs break-all text-red-700/90 dark:text-red-200">{errorMsg}</div>
        </div>
      )}

      {/* 第三层：实时速率监控 + 双轨流量波形图大卡片 */}
      <TrafficWaveformCard
        down={smoothDown}
        up={smoothUp}
        downHistory={downHistory}
        upHistory={upHistory}
        peakDown={peakDown}
        peakUp={peakUp}
        t={t}
      />

      {/* 第四层：Go AIM / Go Lan / Go Cus Pro 引擎卡片
          移动端单列舒展，Mac 端等高三级列矩阵 */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0">
        <EngineCard
          icon={<Crosshair size={16} className="text-surge-green" />}
          tone="text-surge-green"
          name={t("engine.goAim")}
          status={aimPill}
          subtitle={aimDesc}
          enabled={proUnlocked && (aim?.enabled ?? false)}
          locked={!proUnlocked}
          onToggle={toggleAim}
          action={
            proUnlocked && aim?.enabled ? (
              <button
                onClick={runAimProbe}
                disabled={aim.probing}
                className="text-xs font-medium px-2.5 py-1 rounded-lg bg-accent/10 text-accent hover:bg-accent/20 transition-colors whitespace-nowrap disabled:opacity-50"
              >
                {aim.probing ? t("dashboard.aim.probing") : t("dashboard.aim.retest")}
              </button>
            ) : undefined
          }
        />
        <EngineCard
          icon={<Home size={16} className="text-surge-orange" />}
          tone="text-surge-orange"
          name={t("engine.goLan")}
          status={lanPill}
          subtitle={t("engine.goLan.desc")}
          enabled={proUnlocked && (lan?.enabled ?? false)}
          locked={!proUnlocked}
          onToggle={toggleLan}
          action={
            proUnlocked ? (
              <button
                onClick={() => setGoLanModalOpen(true)}
                className="text-xs font-medium px-2.5 py-1 rounded-lg bg-accent/10 text-accent hover:bg-accent/20 transition-colors whitespace-nowrap"
              >
                {t("common.configure")}
              </button>
            ) : undefined
          }
        />
        <EngineCard
          icon={<Wand2 size={16} className="text-surge-purple" />}
          tone="text-surge-purple"
          name={t("engine.goCus")}
          status={cusPill}
          subtitle={t("engine.goCus.desc")}
          enabled={proUnlocked && (cus?.enabled ?? false)}
          locked={!proUnlocked}
          onToggle={toggleCus}
          action={
            proUnlocked ? (
              <button
                onClick={() => navigate("/proxies?tab=goCus")}
                className="text-xs font-medium px-2.5 py-1 rounded-lg bg-accent/10 text-accent hover:bg-accent/20 transition-colors whitespace-nowrap"
              >
                {t("common.configure")}
              </button>
            ) : undefined
          }
        />
      </div>

      {/* 节点选择器弹窗：点击「当前节点」指标卡打开，按延迟从低到高排列 */}
      {pickerOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          onClick={() => setPickerOpen(false)}
        >
          <div className="absolute inset-0 bg-black/60" />
          <div
            className="relative w-full max-w-md flex flex-col max-h-[70vh] rounded-2xl bg-surface-card border border-border-strong shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <div className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                <Globe size={15} className="text-accent" />
                {t("dashboard.pickerTitle")}
              </div>
              <button
                onClick={() => setPickerOpen(false)}
                className="p-1 text-gray-500 hover:text-gray-200"
              >
                <X size={16} />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-2">
              {sortedNodes.map((n) => {
                const d = nodeDelay(n);
                const selected = currentNode === n.name;
                return (
                  <button
                    key={n.name}
                    onClick={() => pickNode(n.name)}
                    disabled={selecting}
                    className={clsx(
                      "w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-left transition-colors",
                      selected ? "bg-accent/10" : "hover:bg-glass"
                    )}
                  >
                    <span
                      className={clsx(
                        "shrink-0 w-1.5 h-1.5 rounded-full",
                        selected ? "bg-accent" : "bg-transparent"
                      )}
                    />
                    <span
                      className={clsx(
                        "flex-1 truncate text-sm",
                        selected ? "text-gray-100 font-medium" : "text-gray-300"
                      )}
                    >
                      {n.name}
                    </span>
                    <span
                      className={clsx(
                        "shrink-0 text-xs font-mono",
                        delayClass(d)
                      )}
                    >
                      {delayText(d)}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* 【APP-4 任务3】未激活不再提供任何激活弹窗入口，Pro 功能一律静默禁用 */}
      <GoLanModal
        open={goLanModalOpen}
        onClose={() => setGoLanModalOpen(false)}
      />
    </div>
  );
}

/// 【v0.4.17 任务3】Pro 引擎卡两行结构：
/// 顶行：图标 + 标题 + 短状态胶囊 | 右侧：配置/重测按钮 + Switch
/// 底行：唯一一行功能简介（禁止与胶囊文案重复）
function EngineCard({
  icon,
  name,
  status,
  subtitle,
  enabled,
  onToggle,
  action,
  locked = false,
  tone,
}: {
  icon: ReactNode;
  name: string;
  status: string;
  subtitle: string;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  action?: ReactNode;
  locked?: boolean;
  tone?: string;
}) {
  return (
    <div
      className={`card-sheen flex flex-col gap-1.5 px-3.5 py-3 rounded-xl bg-surface-card border border-border transition-colors ${
        locked ? "select-none cursor-not-allowed" : "hover:border-accent/30"
      }`}
    >
      {/* 顶行：图标 + 标题 + 短状态胶囊 | 操作按钮 + 开关 */}
      <div className="flex items-center gap-2 min-w-0">
        <div className="flex items-center gap-1.5 min-w-0 shrink">
          <span className="shrink-0">{icon}</span>
          <span
            className={clsx(
              "min-w-0 truncate text-[15px] font-bold tracking-tight",
              tone ?? "text-gray-100"
            )}
            title={name}
          >
            {name}
          </span>
        </div>
        <span
          className={clsx(
            "inline-flex shrink-0 items-center gap-1 text-[11px] px-1.5 py-0.5 rounded-full font-medium whitespace-nowrap",
            enabled
              ? "bg-emerald-500/15 text-emerald-400"
              : "bg-gray-500/15 text-gray-400"
          )}
        >
          <span
            className={clsx(
              "w-1.5 h-1.5 rounded-full",
              enabled ? "bg-emerald-500 animate-pulse" : "bg-gray-500"
            )}
          />
          {status}
        </span>
        <div className="ml-auto flex shrink-0 items-center gap-1.5">
          {action}
          <Switch checked={enabled} disabled={locked} onChange={onToggle} />
        </div>
      </div>

      {/* 底行：唯一一行功能简介 */}
      <div className="min-w-0 truncate text-xs text-text-muted" title={subtitle}>
        {subtitle}
      </div>
    </div>
  );
}

/// 三次贝塞尔曲线插值：把离散采样点连成平滑连续的 SVG 路径
function buildSmoothSvgPath(
  points: number[],
  width: number,
  height: number,
  maxVal: number
): string {
  const n = points.length;
  if (n === 0) return "";
  const stepX = width / Math.max(1, n - 1);
  const safeMax = Math.max(maxVal, 1);
  const coords = points.map((v, i) => ({
    x: i * stepX,
    y: height - (Math.min(v, safeMax) / safeMax) * height,
  }));
  let d = `M ${coords[0].x.toFixed(2)} ${coords[0].y.toFixed(2)}`;
  for (let i = 0; i < coords.length - 1; i++) {
    const p0 = coords[Math.max(0, i - 1)];
    const p1 = coords[i];
    const p2 = coords[i + 1];
    const p3 = coords[Math.min(coords.length - 1, i + 2)];
    const cp1x = p1.x + (p2.x - p0.x) / 6;
    const cp1y = p1.y + (p2.y - p0.y) / 6;
    const cp2x = p2.x - (p3.x - p1.x) / 6;
    const cp2y = p2.y - (p3.y - p1.y) / 6;
    d += ` C ${cp1x.toFixed(2)} ${cp1y.toFixed(2)}, ${cp2x.toFixed(2)} ${cp2y.toFixed(2)}, ${p2.x.toFixed(2)} ${p2.y.toFixed(2)}`;
  }
  return d;
}

/// 【v0.4.17 任务2】实时速率监控 + 双轨流量波形图：
/// 顶部为左右严格对称的 2 等分网格（标题+峰值一行，大号网速独占第二行），
/// 物理隔离彻底杜绝窄屏下「网速数字 / 峰值徽章」重叠；量程移入波形图右上角角标。
function TrafficWaveformCard({
  down,
  up,
  downHistory,
  upHistory,
  peakDown,
  peakUp,
  t,
}: {
  down: number;
  up: number;
  downHistory: number[];
  upHistory: number[];
  peakDown: number;
  peakUp: number;
  t: (k: string) => string;
}) {
  const W = 600;
  const H = 144;
  // Y 轴量程：取双通道最大值，保底 64 KB/s
  const maxVal = Math.max(64 * 1024, ...downHistory, ...upHistory);
  const downPath = buildSmoothSvgPath(downHistory, W, H, maxVal);
  const upPath = buildSmoothSvgPath(upHistory, W, H, maxVal);
  const downArea = downPath
    ? `${downPath} L ${W} ${H} L 0 ${H} Z`
    : "";
  const upArea = upPath ? `${upPath} L ${W} ${H} L 0 ${H} Z` : "";
  const lastDown = downHistory[downHistory.length - 1] ?? 0;
  const lastUp = upHistory[upHistory.length - 1] ?? 0;
  const lastDownY = H - (Math.min(lastDown, maxVal) / maxVal) * H;
  const lastUpY = H - (Math.min(lastUp, maxVal) / maxVal) * H;
  const lastX = W;

  return (
    <div className="card-sheen rounded-2xl px-3.5 py-3 md:px-4 md:py-3.5 border border-border bg-surface-card shrink-0">
      {/* 顶部：左右严格对称 2 等分网格，中间细分隔线 */}
      <div className="grid grid-cols-2 gap-3 pb-3 border-b border-border">
        {/* 左栏：下载 */}
        <div className="flex min-w-0 flex-col justify-between">
          <div className="flex items-center justify-between gap-1">
            <div className="flex shrink-0 items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span className="text-xs font-medium text-text-secondary whitespace-nowrap">
                ↓ {t("metric.download")}
              </span>
            </div>
            <span className="shrink-0 text-[11px] font-mono text-text-muted tabular-nums whitespace-nowrap">
              {t("dashboard.peak")} {formatSpeed(peakDown)}
            </span>
          </div>
          <div className="mt-1.5 min-w-0 truncate text-xl md:text-2xl font-bold font-mono text-emerald-500 tracking-tight tabular-nums">
            {formatSpeed(down)}
          </div>
        </div>

        {/* 右栏：上传 */}
        <div className="flex min-w-0 flex-col justify-between border-l border-border pl-3">
          <div className="flex items-center justify-between gap-1">
            <div className="flex shrink-0 items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-blue-500" />
              <span className="text-xs font-medium text-text-secondary whitespace-nowrap">
                ↑ {t("metric.upload")}
              </span>
            </div>
            <span className="shrink-0 text-[11px] font-mono text-text-muted tabular-nums whitespace-nowrap">
              {t("dashboard.peak")} {formatSpeed(peakUp)}
            </span>
          </div>
          <div className="mt-1.5 min-w-0 truncate text-xl md:text-2xl font-bold font-mono text-blue-500 tracking-tight tabular-nums">
            {formatSpeed(up)}
          </div>
        </div>
      </div>

      {/* 下部：实时双轨平滑 SVG 波形图，量程为右上角悬浮角标 */}
      <div className="relative mt-2.5 h-24 md:h-32 w-full overflow-hidden rounded-xl bg-surface/40">
        <span className="absolute top-1.5 right-2 z-10 rounded border border-border bg-surface-card/80 px-1.5 py-0.5 text-[10px] font-mono text-text-muted backdrop-blur-sm">
          {t("dashboard.scale")}: {formatSpeed(maxVal)}
        </span>
        <svg
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          className="h-full w-full"
        >
          <defs>
            <linearGradient id="downGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#10B981" stopOpacity="0.30" />
              <stop offset="100%" stopColor="#10B981" stopOpacity="0" />
            </linearGradient>
            <linearGradient id="upGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#3B82F6" stopOpacity="0" />
            </linearGradient>
          </defs>
          {/* 3 条水平参考虚线 */}
          {[0.25, 0.5, 0.75].map((r) => (
            <line
              key={r}
              x1="0"
              y1={H * r}
              x2={W}
              y2={H * r}
              stroke="currentColor"
              strokeOpacity="0.08"
              strokeWidth="1"
              strokeDasharray="4 4"
              className="text-gray-400"
            />
          ))}
          {/* 下载波形层 */}
          {downArea && <path d={downArea} fill="url(#downGrad)" />}
          {downPath && (
            <path
              d={downPath}
              fill="none"
              stroke="#10B981"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}
          {/* 上传波形层 */}
          {upArea && <path d={upArea} fill="url(#upGrad)" />}
          {upPath && (
            <path
              d={upPath}
              fill="none"
              stroke="#3B82F6"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}
          {/* 实时脉动圆点 */}
          <circle cx={lastX} cy={lastDownY} r="3" fill="#10B981">
            <animate attributeName="r" values="3;5;3" dur="1.4s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="1;0.5;1" dur="1.4s" repeatCount="indefinite" />
          </circle>
          <circle cx={lastX} cy={lastUpY} r="3" fill="#3B82F6">
            <animate attributeName="r" values="3;5;3" dur="1.4s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="1;0.5;1" dur="1.4s" repeatCount="indefinite" />
          </circle>
        </svg>
      </div>
    </div>
  );
}
