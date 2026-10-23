import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  Cpu,
  Gauge,
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
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

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
  clearGoAimPinnedNode,

  getGoLanSettings,
  saveGoLanSettings,
  getGoCusSettings,
  saveGoCusSettings,
  isGoLanConfigured,
} from "@/api/ipc";
import { useCoreStore, type RunMode } from "@/stores/core";
import { useProStore } from "@/stores/pro";
import { useTranslation } from "@/i18n";
import { formatBytes, formatSpeed, formatUptime } from "@/utils/format";
import { delayClass, delayText } from "@/utils/latency";
import { isMobile } from "@/pro/gating";
import { toast } from "@/components/ui/Toast";
import OutboundModeSwitch from "@/components/OutboundModeSwitch";
import { ActivateProModal } from "@/components/ProGate";
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
  const memoryUsage = useCoreStore((s) => s.memoryUsage);
  const uptimeSecs = useCoreStore((s) => s.uptimeSecs);
  const startedAtMs = useCoreStore((s) => s.startedAtMs);
  const traffic = useCoreStore((s) => s.traffic);
  // 今日流量：后端持久化基数 + 当前会话内核绝对累计（前后台不间断）
  const todayBytes = useCoreStore((s) => s.todayBytes);
  const setStatus = useCoreStore((s) => s.setStatus);
  const setMode = useCoreStore((s) => s.setMode);
  const setOutboundMode = useCoreStore((s) => s.setOutboundMode);
  const setUptime = useCoreStore((s) => s.setUptime);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const mobile = isMobile();
  const navigate = useNavigate();

  // Pro 授权状态（ipa-9：未激活时引擎矩阵折叠为单张横幅卡）
  const proReady = useProStore((s) => s.ready);
  const proUnlocked = useProStore((s) => s.unlocked);
  const [showActivate, setShowActivate] = useState(false);

  // 当前节点状态：主选择组、当前选中节点名、可选节点列表、选择器弹窗
  const [mainSelector, setMainSelector] = useState("");
  const [currentNode, setCurrentNode] = useState("");
  const [nodes, setNodes] = useState<ProxyEntry[]>([]);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [selecting, setSelecting] = useState(false);

  // Pro 引擎矩阵状态（Go AIM / Go Lan / Go Cus）：APP 任务1 提升到全局
  // store（App.tsx 启动预加载），切页切回仪表盘时直接命中缓存渲染，
  // 消除「先关后开」闪烁
  const aim = useCoreStore((s) => s.goAimStatus);
  const lan = useCoreStore((s) => s.goLanSettings);
  const cus = useCoreStore((s) => s.goCusSettings);

  const running = status === "running";
  const modeLabel = (m: RunMode) => t(m === "tun" ? "runMode.tun" : "runMode.systemProxy");

  // 拉取主选择组与当前节点（内核运行时才有实时数据）
  const loadCurrentNode = async () => {
    try {
      const st = await getCoreStatus();
      const group = st.mainSelector ?? "";
      setMainSelector(group);
      if (st.status !== "running" || !group) {
        setCurrentNode("");
        // 未启动兜底：读取订阅缓存节点展示第一个，并支持点击预选
        // （ipa-8 方案：启动前卡片不再显示「—」死状态）
        try {
          const cached = await getCachedProxies();
          setNodes(
            cached.map((c) => ({ name: c.name, type: c.kind, history: [] }))
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
      setCurrentNode(g.now ?? "");
      setNodes(
        (g.all ?? [])
          .map((item) => (typeof item === "string" ? map[item] : item))
          .filter((item): item is ProxyEntry => Boolean(item))
          .filter((item) => !GROUP_TYPES.includes(item.type))
      );
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
  const lanStatus =
    lan && lan.lanCidrs.length > 0
      ? t("dashboard.lan.configured", {
          mode: t(lan.mode === "managed" ? "dashboard.lan.managed" : "dashboard.lan.manual"),
          cidrs: lan.lanCidrs.join(", "),
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
      <h1 className="text-2xl font-bold">{t("dashboard.title")}</h1>

      {/* 出站模式快捷切换（规则/全局/直连） */}
      <OutboundModeSwitch />

      {/* Hero 状态卡（Shadowrocket 风格：满宽，左状态右按钮） */}
      <div
        className={`rounded-2xl p-5 border transition-colors ${
          running
            ? "bg-latency-good/10 border-latency-good/30"
            : "bg-surface-card border-border"
        }`}
      >
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
                  ? t("status.connecting")
                  : status === "error"
                    ? t("status.startFailed")
                    : t("status.disconnected")}
            </div>
            <div className="text-2xl font-bold tabular-nums text-gray-100">
              {running ? formatUptime(displayUptimeSecs) : "Prism"}
            </div>
            {/* 未连接（stopped）时不再显示「点击右侧按钮启动代理」副标题，
                让左侧仅保留状态圆点与 Prism 标题；启动中仍给出隧道提示 */}
            {running ? (
              <div className="text-xs text-gray-500 mt-1">
                {t("dashboard.runModeLabel", { mode: modeLabel(mode) })}
              </div>
            ) : status === "starting" ? (
              <div className="text-xs text-gray-500 mt-1">
                {t("status.startingTunnel")}
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

      {/* 启动/停止错误提示 */}
      {errorMsg && (
        <div className="rounded-xl p-4 text-sm bg-latency-bad/10 text-red-300 border border-red-500/20">
          <div className="font-semibold mb-1">{t("dashboard.errorTitle")}</div>
          <div className="text-xs break-all text-red-200">{errorMsg}</div>
        </div>
      )}

      {/* 状态指标行（3 列） */}
      <div className="grid grid-cols-3 gap-3">
        <StatChip
          icon={<Globe size={14} className="text-gray-400" />}
          label={t("metric.currentNode")}
          value={
            running
              ? currentNode || t("dashboard.noSelection")
              : currentNode || nodes[0]?.name || "—"
          }
          onClick={nodes.length > 0 ? () => setPickerOpen(true) : undefined}
          wrap
        />
        {mobile ? (
          <StatChip
            icon={<BarChart3 size={14} className="text-gray-400" />}
            label={t("metric.todayTraffic")}
            value={running ? formatBytes(todayBytes) : "—"}
          />
        ) : (
          <StatChip
            icon={<Cpu size={14} className="text-gray-400" />}
            label={t("metric.memoryUsage")}
            value={running && memoryUsage > 0 ? formatBytes(memoryUsage) : "—"}
          />
        )}
        <StatChip
          icon={<Gauge size={14} className="text-gray-400" />}
          label={t("metric.mode")}
          value={modeLabel(mode)}
        />
      </div>

      {/* Pro 引擎矩阵（Go AIM / Go Lan / Go Cus，Pro 门控）
          ipa-9：未激活时不渲染三张带遮罩的卡片，折叠为一张紧凑协调的横幅卡；
          已激活时渲染三张功能卡（移动端单列通栏横向卡片，桌面端三列网格） */}
      {proUnlocked ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
          <EngineCard
            icon={<Crosshair size={14} className="text-accent" />}
            name={t("engine.goAim")}
            tag={t("engine.goAimTag")}
            status={aimStatus}
            enabled={aim?.enabled ?? false}
            onToggle={toggleAim}
            action={
              aim?.enabled ? (
                aim.pinnedNode ? (
                  // APP-5 任务3：用户手动指定节点 → 显示"恢复自动"轻按钮
                  // 点击后清空 pinned，回到自动评级选点
                  <button
                    onClick={async () => {
                      await clearGoAimPinnedNode();
                      // 立即刷新状态：pinned 清后端已落盘，前端
                      // 事件 go-aim://updated 会自然回流 selectionMode
                      runAimProbe();
                    }}
                    className="text-xs text-amber-400 hover:underline px-1.5 py-1 whitespace-nowrap"
                  >
                    {t("dashboard.aim.restoreAuto")}
                  </button>
                ) : (
                  <button
                    onClick={runAimProbe}
                    disabled={aim.probing}
                    className="text-xs text-accent hover:underline px-1.5 py-1 whitespace-nowrap disabled:opacity-50 disabled:no-underline"
                  >
                    {aim.probing ? t("dashboard.aim.probing") : t("dashboard.aim.retest")}
                  </button>
                )
              ) : undefined
            }
          />
          <EngineCard
            icon={<Home size={14} className="text-accent" />}
            name={t("engine.goLan")}
            tag={t("engine.goLanTag")}
            status={lanStatus}
            enabled={lan?.enabled ?? false}
            onToggle={toggleLan}
            action={
              <button
                onClick={() => navigate("/settings?focus=goLan")}
                className="text-xs text-accent hover:underline px-1.5 py-1 whitespace-nowrap"
              >
                {t("common.configure")}
              </button>
            }
          />
          <EngineCard
            icon={<Wand2 size={14} className="text-accent" />}
            name={t("engine.goCus")}
            tag={t("engine.goCusTag")}
            status={cusStatus}
            enabled={cus?.enabled ?? false}
            onToggle={toggleCus}
            action={
              <button
                onClick={() => navigate("/proxies?tab=goCus")}
                className="text-xs text-accent hover:underline px-1.5 py-1 whitespace-nowrap"
              >
                {t("common.configure")}
              </button>
            }
          />
        </div>
      ) : proReady ? (
        <div className="flex items-center justify-between gap-3 rounded-xl border border-border bg-surface-card px-4 py-3">
          <div className="min-w-0 flex-1">
            {/* APP-5 任务2：标题 + 三个胶囊强制一行，不再折行 */}
            <div className="flex flex-nowrap items-center gap-1.5 overflow-hidden">
              <span className="whitespace-nowrap text-sm font-semibold text-gray-100">
                ✨ {t("dashboard.proEngines")}
              </span>
              <span className="whitespace-nowrap rounded bg-surface-hover px-1.5 py-0.5 text-[10px] text-text-muted">
                Go AIM
              </span>
              <span className="whitespace-nowrap rounded bg-surface-hover px-1.5 py-0.5 text-[10px] text-text-muted">
                Go Lan
              </span>
              <span className="whitespace-nowrap rounded bg-surface-hover px-1.5 py-0.5 text-[10px] text-text-muted">
                Go Cus
              </span>
            </div>
            <p className="mt-1 truncate text-[11px] text-gray-400">
              {t("dashboard.proBannerDesc")}
            </p>
          </div>
          <button
            onClick={() => setShowActivate(true)}
            className="shrink-0 rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent/90"
          >
            {t("pro.activatePro")}
          </button>
        </div>
      ) : null}

      {/* 实时速率（合并卡片，左右分布） */}
      <div className="bg-surface-card rounded-2xl p-5 border border-border">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <div className="flex items-center gap-1.5 text-xs text-gray-400">
              <Activity size={13} className="text-latency-good" />
              {t("metric.download")}
            </div>
            <div className="text-xl font-bold tabular-nums text-latency-good mt-1.5 font-mono">
              {running ? formatSpeed(downSpeed) : "—"}
            </div>
          </div>
          <div className="border-l border-border pl-4">
            <div className="flex items-center gap-1.5 text-xs text-gray-400">
              <Activity size={13} className="text-accent" />
              {t("metric.upload")}
            </div>
            <div className="text-xl font-bold tabular-nums text-accent mt-1.5 font-mono">
              {running ? formatSpeed(upSpeed) : "—"}
            </div>
          </div>
        </div>
      </div>

      {/* 流量曲线图 */}
      <div className="bg-surface-card rounded-2xl p-5 border border-border">
        <h2 className="text-sm font-semibold mb-4 text-gray-200">
          {t("metric.realtimeTraffic")}
        </h2>
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={traffic} margin={{ top: 4, right: 12, bottom: 0, left: 0 }}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="rgb(var(--border) / 0.15)"
            />
            <XAxis
              dataKey="time"
              stroke="rgb(var(--gray-500))"
              fontSize={10}
              tickLine={false}
              minTickGap={48}
            />
            <YAxis
              stroke="rgb(var(--gray-500))"
              fontSize={10}
              tickLine={false}
              width={60}
              tickFormatter={(v) => formatBytes(Number(v))}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "rgb(var(--surface-card))",
                border: "1px solid rgb(var(--border) / 0.15)",
                borderRadius: 8,
                fontSize: 12,
                padding: '8px 12px',
                color: "rgb(var(--gray-100))",
              }}
              labelStyle={{ color: 'rgb(var(--gray-100))' }}
              itemStyle={{ color: 'rgb(var(--gray-100))' }}
              formatter={(value, name) => [
                formatSpeed(Number(value)),
                name === "down" ? t("metric.download") : t("metric.upload"),
              ]}
            />
            <Legend
              formatter={(v) =>
                v === "down" ? t("metric.download") : t("metric.upload")
              }
              wrapperStyle={{ paddingTop: '12px', fontSize: 11 }}
            />
            <Line
              type="monotone"
              dataKey="down"
              stroke="#22c55e"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
            <Line
              type="monotone"
              dataKey="up"
              stroke="rgb(var(--accent))"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
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

      {/* Pro 激活弹窗（未激活横幅卡「激活 Pro」入口共用） */}
      <ActivateProModal
        open={showActivate}
        onClose={() => setShowActivate(false)}
      />
    </div>
  );
}

function StatChip({
  icon,
  label,
  value,
  onClick,
  /** APP-4 任务4.1：节点名可长达数十字符——不截断，最多两行完整展示 */
  wrap = false,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  onClick?: () => void;
  wrap?: boolean;
}) {
  return (
    <div
      onClick={onClick}
      role={onClick ? "button" : undefined}
      className={clsx(
        "bg-surface-card rounded-xl p-3 border border-border",
        onClick && "cursor-pointer hover:border-accent/40 transition-colors"
      )}
    >
      {/* 顶部标签行禁止换行（ipa-8：三列窄卡片内「当前节点」不再折行）；
          右箭头移到第二行数值右侧，保证启动前后顶部布局一致 */}
      <div className="flex items-center gap-1.5 text-[11px] text-gray-400 whitespace-nowrap">
        {icon}
        <span>{label}</span>
      </div>
      <div className="mt-1 flex items-center gap-0.5 min-w-0">
        <span
          className={clsx(
            "text-sm font-semibold tabular-nums text-gray-100",
            wrap
              ? "break-all line-clamp-2 leading-snug"
              : "truncate"
          )}
          title={value}
        >
          {value}
        </span>
        {onClick && <ChevronRight size={12} className="shrink-0 text-gray-600" />}
      </div>
    </div>
  );
}

/// Pro 引擎卡（ipa-8）：横向通栏布局——左侧图标+完整标题+功能标签胶囊+一行状态
/// 副标题，右侧「配置/重测」轻按钮 + Switch；移动端不再因 grid-cols-3 窄卡片截断文字
function EngineCard({
  icon,
  name,
  tag,
  status,
  enabled,
  onToggle,
  action,
}: {
  icon: ReactNode;
  name: string;
  tag: string;
  status: string;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  action?: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3 px-3.5 py-3 rounded-xl bg-surface-card border border-border">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          {icon}
          <span className="font-semibold text-sm text-gray-100 whitespace-nowrap">
            {name}
          </span>
          <span className="text-[11px] px-1.5 py-0.5 rounded bg-glass text-gray-400 whitespace-nowrap">
            {tag}
          </span>
        </div>
        {/* APP-4 任务4.1：状态副标题（含 Go AIM 锁定节点名）不再单行截断，
            最多两行完整展示——与「当前节点」卡保持同一节点名一致性 */}
        <div
          className="mt-1 text-xs text-gray-400 break-all line-clamp-2 leading-snug"
          title={status}
        >
          {status}
        </div>
      </div>
      <div className="flex items-center gap-2.5 shrink-0">
        {action}
        <Switch checked={enabled} onChange={onToggle} />
      </div>
    </div>
  );
}
