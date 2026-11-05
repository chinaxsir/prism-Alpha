import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  Power,
  Globe,
  BarChart3,
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
import { useCoreStore, type RunMode, isDummyNodeName } from "@/stores/core";
import { useProStore } from "@/stores/pro";
import { useTranslation } from "@/i18n";
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

export default function Dashboard() {
  const { t } = useTranslation();
  const status = useCoreStore((s) => s.status);
  const mode = useCoreStore((s) => s.mode);
  const upSpeed = useCoreStore((s) => s.upSpeed);
  const downSpeed = useCoreStore((s) => s.downSpeed);
  const uptimeSecs = useCoreStore((s) => s.uptimeSecs);
  const startedAtMs = useCoreStore((s) => s.startedAtMs);
  // 今日流量：后端持久化基数 + 当前会话内核绝对累计（前后台不间断）
  const todayBytes = useCoreStore((s) => s.todayBytes);
  const setStatus = useCoreStore((s) => s.setStatus);
  const setMode = useCoreStore((s) => s.setMode);
  const setOutboundMode = useCoreStore((s) => s.setOutboundMode);
  const setUptime = useCoreStore((s) => s.setUptime);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);
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
  // 【APP40 任务2】内网档案运行状态（⚡同网段直连 / 🔒隧道）
  const [lanState, setLanState] = useState<GoLanStatus | null>(null);

  const running = status === "running";
  const modeLabel = (m: RunMode) => t(m === "tun" ? "runMode.tun" : "runMode.systemProxy");

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

  // 本地运行时长时钟（IPA-12）：禁止每秒 +1 计数器（锁屏/切后台时
  // 系统 WebView 冻结定时器，亮屏后要等下个 tick 才恢复）。改为维护
  // nowMs 本地时钟，以 250ms 轻量间隔刷新，时长 = (nowMs - startedAtMs)
  // 差值实时计算；亮屏/回前台第一帧由下方唤醒监听 0ms 校准
  const [nowMs, setNowMs] = useState(() => Date.now());

  useEffect(() => {
    if (!running) return;
    let timer: number | undefined;
    // 【APP-3】后台（锁屏/切 App）停掉 250ms 时钟：不再每秒 4 次唤醒 JS 线程，
    // 回前台由下方 syncClockImmediately 立即校准，时长显示无跳变
    const start = () => {
      if (timer !== undefined) return;
      setNowMs(Date.now());
      timer = window.setInterval(() => setNowMs(Date.now()), 250);
    };
    const stop = () => {
      if (timer !== undefined) {
        window.clearInterval(timer);
        timer = undefined;
      }
    };
    const sync = () =>
      document.visibilityState === "visible" ? start() : stop();
    sync();
    document.addEventListener("visibilitychange", sync);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", sync);
    };
  }, [running]);

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
  // 若后端状态事件滞后，界面也能立即切到「已连接」，不必等默认轮询周期
  useEffect(() => {
    if (status !== "starting") return;
    let stopped = false;
    const timer = window.setInterval(() => {
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
          window.clearInterval(timer);
        })
        .catch(() => undefined);
    }, 250);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [status]);

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
    const unAim = listen("go-aim://updated", () => {
      getGoAimStatus()
        .then(useCoreStore.getState().setGoAimStatus)
        .catch(() => undefined);
    });
    return () => {
      unAim.then((fn) => fn());
    };
  }, []);

  // 【APP40 任务2】Go Lan 档案状态：任一档案启停变化时刷新 ⚡/🔒 徽章
  useEffect(() => {
    getGoLanStatus()
      .then(setLanState)
      .catch(() => setLanState(null));
  }, [lan?.enabled, lan?.profiles]);

  const toggleAim = async (v: boolean) => {
    try {
      await setGoAimEnabled(v);
      const store = useCoreStore.getState();
      const prev = store.goAimStatus;
      if (prev) store.setGoAimStatus({ ...prev, enabled: v });
    } catch (e) {
      toast.error(String(e));
    }
  };

  const toggleLan = async (v: boolean) => {
    try {
      const s = await getGoLanSettings();
      // APP 任务5：未配置时拦截开启，Toast 引导并跳转配置区
      if (v && !isGoLanConfigured(s)) {
        toast.error(t("dashboard.lan.configureFirst"));
        navigate("/settings?focus=goLan");
        return;
      }
      s.enabled = v;
      await saveGoLanSettings(s);
      useCoreStore.getState().setGoLanSettings(s);
    } catch (e) {
      toast.error(String(e));
    }
  };

  const toggleCus = async (v: boolean) => {
    try {
      const s = await getGoCusSettings();
      // APP 任务5：无模块时拦截开启，Toast 引导并跳转 Go Cus 模块页
      if (v && s.modules.length === 0) {
        toast.error(t("dashboard.cus.configureFirst"));
        navigate("/proxies?tab=goCus");
        return;
      }
      s.enabled = v;
      await saveGoCusSettings(s);
      useCoreStore.getState().setGoCusSettings(s);
    } catch (e) {
      toast.error(String(e));
    }
  };

  const toggle = async () => {
    setErrorMsg(null);
    try {
      if (running) {
        await stopCore();
        setStatus("stopped");
        setUptime(0);
        useCoreStore.getState().setStartedAtMs(null);
      } else {
        setStatus("starting");
        await startCore();
        setStatus("running");
      }
    } catch (e) {
      console.error("toggle core failed:", e);
      setStatus("error");
      setErrorMsg(String(e));
    }
  };

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

  // ---- Pro 引擎矩阵状态文案（ipa-8：横向通栏卡片，一行完整状态信息） ----
  const aimUnlocked = aim
    ? Object.values(aim.results).filter((r) => r.aiUnlocked || r.mediaUnlocked)
        .length
    : 0;
  // APP-5 任务3：Go AIM 状态副标题严格区分「手动锁定」与「自动优选」
  const aimStatus = aim?.enabled
    ? aim.pinnedNode
      ? t("dashboard.aim.pinned", { node: aim.pinnedNode })
      : t("dashboard.aim.locked", {
          node: aim.lockedNode || currentNode || "—",
          count: aimUnlocked,
        })
    : t("dashboard.aim.idle");
  // 【APP23 任务1.2】字段缺失兜底：goLanSettings 任一层为 undefined 时
  // 直接 join 会抛异常导致 React 渲染崩溃黑屏，统一用可选链 + 空数组兜底
  const lanCidrs = lan?.lanCidrs ?? [];
  // 【APP40 任务2】多档案副标题：已启用: 家里 (⚡同网段直连) · 公司 (🔒隧道已连接)
  const enabledLanProfiles = (lan?.profiles ?? []).filter((p) => p.enabled);
  const lanStatus =
    enabledLanProfiles.length > 0
      ? t("dashboard.lan.profiles", {
          profiles: enabledLanProfiles
            .map((p) => {
              const st = lanState?.profiles.find((x) => x.id === p.id);
              const badge =
                st?.state === "direct"
                  ? t("goLan.statusDirect")
                  : t("goLan.statusTunnel");
              return `${p.name} (${badge})`;
            })
            .join(" · "),
        })
      : lanCidrs.length > 0
        ? t("dashboard.lan.configured", {
            mode: t(lan?.mode === "managed" ? "dashboard.lan.managed" : "dashboard.lan.manual"),
            cidrs: lanCidrs.join(", "),
          })
        : t("dashboard.lan.unset");
  const cusEnabledModules = cus?.modules.filter((m) => m.enabled) ?? [];
  const cusStatus =
    cus && cus.modules.length > 0
      ? t("dashboard.cus.enabled", {
          modules: cusEnabledModules.length,
          rewrites: cusEnabledModules.reduce((acc, m) => acc + (m.stats?.rewrites ?? 0), 0),
          scripts: cusEnabledModules.reduce((acc, m) => acc + (m.stats?.scripts ?? 0), 0),
        })
      : t("dashboard.cus.unset");

  // Go AIM 开启时的「重测」：立即触发一轮评级探测（结果经 go-aim://updated 事件刷新）
  const runAimProbe = async () => {
    try {
      await runGoAimProbe();
    } catch (e) {
      toast.error(t("dashboard.aim.retestFailed", { error: String(e) }));
    }
  };

  return (
    <div className="space-y-5">
      <h1 className="text-[22px] font-bold tracking-tight">{t("dashboard.title")}</h1>

      {/* 出站模式快捷切换（规则/全局/直连） */}
      <OutboundModeSwitch />

      {/* Hero 状态卡（Shadowrocket 风格：满宽，左状态右按钮）
          【APP39 任务1】启动前后背景色恒定：严禁随 running 变色，
          始终 bg-surface-card + border-border，与其余卡片完全一致 */}
      <div className="rounded-2xl p-5 border bg-surface-card border-border">
        <div className="flex items-center justify-between">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-xs text-gray-400 mb-1">
              <span
                className={`inline-block w-2 h-2 rounded-full ${
                  running
                    ? "bg-latency-good"
                    : status === "starting"
                      ? "bg-amber-400"
                      : status === "error"
                        ? "bg-latency-bad"
                        : "bg-gray-500"
                } ${running || status === "starting" ? "animate-pulse" : ""}`}
              />
              {/* starting 必须有可见反馈（build 144 方案）：启动期可达
                  数秒（VPN 授权/扩展拉起），若显示"未连接"用户会以为
                  没反应而重复点击（后端幂等保护已兜底，但体验要明确） */}
              {running
                ? t("status.connected")
                : status === "starting"
                  ? t("status.starting")
                  : status === "error"
                    ? t("status.startFailed")
                    : t("status.disconnected")}
            </div>
            <div className="text-2xl font-bold tabular-nums text-gray-100">
              {running ? formatUptime(displayUptimeSecs) : "Prism"}
            </div>
            {/* 未连接/启动中时左侧仅保留状态圆点与 Prism 标题：不再显示
                「正在建立 VPN 隧道，请稍候」副标题，避免点击启动瞬间卡片
                高度跳动（启动反馈由状态点与右侧「启动中」按钮承载）。
                仅「已连接」显示计时器时，下方才显示运行模式。 */}
            {running ? (
              <div className="text-xs text-gray-500 mt-1">
                {t("dashboard.runModeLabel", { mode: modeLabel(mode) })}
              </div>
            ) : null}
          </div>
          <button
            onClick={toggle}
            disabled={status === "starting"}
            className={`shrink-0 flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed ${
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

      {/* 启动/停止错误提示（【APP47 任务2.2】文档流内联 + 深浅色高对比红字） */}
      {errorMsg && (
        <div className="rounded-xl p-4 text-sm bg-red-500/10 text-red-700 dark:text-red-300 border border-red-500/30">
          <div className="font-semibold mb-1">{t("dashboard.errorTitle")}</div>
          <div className="text-xs break-all text-red-700/90 dark:text-red-200">{errorMsg}</div>
        </div>
      )}

      {/* 【APP47 任务1.1】状态指标行强制双列水平并排：禁止任何响应式断点，
          手机竖屏同样一行两卡（当前节点 1.35fr : 今日流量 1fr） */}
      <div
        className="grid grid-cols-2 gap-3"
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1.35fr) minmax(0, 1fr)",
          gap: "12px",
        }}
      >
        <div
          onClick={nodes.length > 0 ? () => setPickerOpen(true) : undefined}
          role={nodes.length > 0 ? "button" : undefined}
          className={clsx(
            "rounded-[16px] bg-surface-card p-4 border border-border flex flex-col justify-between min-h-[88px] min-w-0",
            nodes.length > 0 && "cursor-pointer active:opacity-80 transition-opacity"
          )}
        >
          <div className="flex items-center justify-between gap-1">
            <div className="flex items-center gap-1.5 min-w-0">
              <Globe size={18} className="shrink-0 text-[#007AFF] dark:text-[#0A84FF]" />
              <span className="text-[15px] font-bold text-[#007AFF] dark:text-[#0A84FF] whitespace-nowrap">
                {t("metric.currentNode")}
              </span>
            </div>
            {nodes.length > 0 && (
              <ChevronRight size={16} className="shrink-0 text-text-muted" />
            )}
          </div>
          {/* 【APP47 任务1.2】未启动也展示持久化的上次选中节点，绝不显示「—」 */}
          <div
            className="mt-2 text-[15px] font-bold text-text leading-snug break-all line-clamp-2"
            title={currentNode || persistedNode || nodes[0]?.name}
          >
            {currentNode || persistedNode || nodes[0]?.name || t("dashboard.noSelection")}
          </div>
        </div>

        <div className="rounded-[16px] bg-surface-card p-4 border border-border flex flex-col justify-between min-h-[88px] min-w-0">
          <div className="flex items-center gap-1.5 min-w-0">
            <BarChart3 size={18} className="shrink-0 text-[#00C7BE]" />
            <span className="text-[15px] font-bold text-[#00C7BE] whitespace-nowrap">
              {t("metric.todayTraffic")}
            </span>
          </div>
          <div className="mt-2 text-[17px] font-bold tabular-nums text-text leading-snug whitespace-nowrap">
            {formatBytes(todayBytes || 0)}
          </div>
        </div>
      </div>

      {/* Pro 引擎矩阵（Go AIM / Go Lan / Go Cus）
          【APP-13 任务3】未激活时不再整体折叠为横幅：三张功能卡原位展示并
          置灰，点击卡片弹出激活授权弹窗。功能入口位置固定，避免激活前后
          布局跳变，也让用户一眼看清 Pro 到底解锁了什么。 */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
        <EngineCard
          icon={<Crosshair size={16} className="text-surge-green" />}
          tone="text-surge-green"
          name={t("engine.goAim")}
          tag={t("engine.goAimTag")}
          status={proUnlocked ? aimStatus : t("pro.lockedTap")}
          enabled={proUnlocked && (aim?.enabled ?? false)}
          locked={!proUnlocked}
          onToggle={toggleAim}
          action={
            proUnlocked && aim?.enabled ? (
              // 【APP-9 任务4.2】只保留「重测」按钮——恢复自动选点通过
              // 关闭再打开 Go AIM 开关实现（后端 set_go_aim_enabled 已
              // 清空 go_aim_pinned_node），不再单独提供「恢复自动」按钮
              <button
                onClick={runAimProbe}
                disabled={aim.probing}
                className="text-xs text-accent hover:underline px-1.5 py-1 whitespace-nowrap disabled:opacity-50 disabled:no-underline"
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
          tag={t("engine.goLanTag")}
          status={proUnlocked ? lanStatus : t("pro.lockedTap")}
          enabled={proUnlocked && (lan?.enabled ?? false)}
          locked={!proUnlocked}
          onToggle={toggleLan}
          action={
            proUnlocked ? (
              <button
                onClick={() => setGoLanModalOpen(true)}
                className="text-xs text-accent hover:underline px-1.5 py-1 whitespace-nowrap"
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
          tag={t("engine.goCusTag")}
          status={proUnlocked ? cusStatus : t("pro.lockedTap")}
          enabled={proUnlocked && (cus?.enabled ?? false)}
          locked={!proUnlocked}
          onToggle={toggleCus}
          action={
            proUnlocked ? (
              <button
                onClick={() => navigate("/proxies?tab=goCus")}
                className="text-xs text-accent hover:underline px-1.5 py-1 whitespace-nowrap"
              >
                {t("common.configure")}
              </button>
            ) : undefined
          }
        />
      </div>

      {/* 实时速率（合并卡片，左右分布） */}
      <div className="card-sheen bg-surface-card rounded-2xl p-5 border border-border">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <div className="flex items-center gap-1.5 text-xs font-medium text-text-muted">
              <Activity size={13} className="text-latency-good" />
              {t("metric.download")}
            </div>
            <div className="text-xl font-bold tabular-nums text-latency-good mt-1.5 font-mono tracking-tight">
              {running ? formatSpeed(downSpeed) : "—"}
            </div>
          </div>
          <div className="border-l border-border pl-4">
            <div className="flex items-center gap-1.5 text-xs text-gray-400">
              <Activity size={13} className="text-accent" />
              {t("metric.upload")}
            </div>
            <div className="text-xl font-bold tabular-nums text-accent mt-1.5 font-mono tracking-tight">
              {running ? formatSpeed(upSpeed) : "—"}
            </div>
          </div>
        </div>
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

/// Pro 引擎卡（ipa-8）：横向通栏布局——左侧图标+完整标题+功能标签胶囊+一行状态
/// 副标题，右侧「配置/重测」轻按钮 + Switch；移动端不再因 grid-cols-3 窄卡片截断文字
/// 【APP-4 任务3】locked=true 时整卡静默置灰禁用（无任何点击响应），
/// 不再弹 Toast 或激活弹窗。
/// 【APP47 任务2.3】锁定时严禁 opacity-50：卡片标题始终保持高饱和彩色 + 19px 加粗。
function EngineCard({
  icon,
  name,
  tag,
  status,
  enabled,
  onToggle,
  action,
  locked = false,
  tone,
}: {
  icon: ReactNode;
  name: string;
  tag: string;
  status: string;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  action?: ReactNode;
  locked?: boolean;
  /** 【APP47 任务2.3】模块标题彩色文字类（如 text-surge-green） */
  tone?: string;
}) {
  return (
    <div
      className={`card-sheen flex items-center justify-between gap-3 px-3.5 py-3 rounded-xl bg-surface-card border border-border transition-colors ${
        // 【APP47 任务2.3】锁定时不再 opacity-50 整体变淡（文字发灰看不清），
        // 改为保持正常对比度，仅禁用点击与开关
        locked ? "select-none cursor-not-allowed" : "hover:border-accent/30"
      }`}
    >
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-center gap-2">
          {icon}
          <span
            className={clsx(
              // 【APP48 任务2】英文长标题必须先收缩再截断，绝不把开关挤出屏幕
              "min-w-0 flex-1 truncate text-[19px] font-bold tracking-tight",
              tone ?? "text-gray-100",
            )}
            title={name}
          >
            {name}
          </span>
          <span className="shrink-0 text-[11px] px-1.5 py-0.5 rounded bg-glass text-text-muted whitespace-nowrap">
            {tag}
          </span>
        </div>
        {/* 【APP47 任务2.3】状态副标题 14px medium 深色正文，最多两行完整展示 */}
        <div
          className="mt-1 text-sm font-medium text-text-muted break-all line-clamp-2 leading-snug"
          title={status}
        >
          {status}
        </div>
      </div>
      <div className="flex items-center gap-2.5 shrink-0">
        {action}
        <Switch checked={enabled} disabled={locked} onChange={onToggle} />
      </div>
    </div>
  );
}
