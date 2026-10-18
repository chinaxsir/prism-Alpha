import { useEffect, useMemo, useState, type ReactNode } from "react";
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
  getGoLanSettings,
  saveGoLanSettings,
  getGoCusSettings,
  saveGoCusSettings,
  type GoAimStatus,
  type GoLanSettings,
  type GoCusSettings,
} from "@/api/ipc";
import { useCoreStore, type RunMode } from "@/stores/core";
import { formatBytes, formatSpeed, formatUptime } from "@/utils/format";
import { delayClass, delayText } from "@/utils/latency";
import { Feature, isMobile } from "@/pro/gating";
import { toast } from "@/components/ui/Toast";
import OutboundModeSwitch from "@/components/OutboundModeSwitch";
import ProGate from "@/components/ProGate";
import Switch from "@/components/ui/Switch";

const MODE_LABEL: Record<RunMode, string> = {
  systemProxy: "系统代理",
  tun: "TUN 全局",
};

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
  const status = useCoreStore((s) => s.status);
  const mode = useCoreStore((s) => s.mode);
  const upSpeed = useCoreStore((s) => s.upSpeed);
  const downSpeed = useCoreStore((s) => s.downSpeed);
  const memoryUsage = useCoreStore((s) => s.memoryUsage);
  const uptimeSecs = useCoreStore((s) => s.uptimeSecs);
  const traffic = useCoreStore((s) => s.traffic);
  const sessionTraffic = useCoreStore((s) => s.sessionTraffic);
  const setStatus = useCoreStore((s) => s.setStatus);
  const setMode = useCoreStore((s) => s.setMode);
  const setOutboundMode = useCoreStore((s) => s.setOutboundMode);
  const setTrafficRate = useCoreStore((s) => s.setTrafficRate);
  const setMemoryUsage = useCoreStore((s) => s.setMemoryUsage);
  const setUptime = useCoreStore((s) => s.setUptime);
  const pushTraffic = useCoreStore((s) => s.pushTraffic);

  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const mobile = isMobile();

  // 当前节点状态：主选择组、当前选中节点名、可选节点列表、选择器弹窗
  const [mainSelector, setMainSelector] = useState("");
  const [currentNode, setCurrentNode] = useState("");
  const [nodes, setNodes] = useState<ProxyEntry[]>([]);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [selecting, setSelecting] = useState(false);

  // Pro 引擎矩阵状态（Go AIM / Go Lan / Go Cus）
  const [aim, setAim] = useState<GoAimStatus | null>(null);
  const [lan, setLan] = useState<GoLanSettings | null>(null);
  const [cus, setCus] = useState<GoCusSettings | null>(null);

  const running = status === "running";

  // 订阅内核实时事件
  useEffect(() => {
    const unlistenTraffic = listen<{ up: number; down: number }>(
      "traffic://tick",
      (event) => {
        const { up, down } = event.payload;
        setTrafficRate(up, down);
        pushTraffic(up, down);
      }
    );

    const unlistenMemory = listen<{ inuse: number }>(
      "memory://tick",
      (event) => {
        setMemoryUsage(event.payload.inuse ?? 0);
      }
    );

    return () => {
      unlistenTraffic.then((fn) => fn());
      unlistenMemory.then((fn) => fn());
    };
  }, [setTrafficRate, setMemoryUsage, pushTraffic]);

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

  // 本地运行时长计时
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => {
      setUptime(useCoreStore.getState().uptimeSecs + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [running, setUptime]);

  // 启动时与后端对齐一次状态（含运行模式：权威来源是后端持久化的 settings.json）
  useEffect(() => {
    getCoreStatus()
      .then((data) => {
        setStatus(data.status);
        setMode(data.mode);
        setUptime(data.uptimeSecs);
        if (data.outboundMode) setOutboundMode(data.outboundMode);
      })
      .catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Pro 引擎状态：挂载时拉取一次；Go AIM 评级结果经事件实时刷新
  useEffect(() => {
    getGoAimStatus().then(setAim).catch(() => undefined);
    getGoLanSettings().then(setLan).catch(() => undefined);
    getGoCusSettings().then(setCus).catch(() => undefined);
    const unAim = listen("go-aim://updated", () => {
      getGoAimStatus().then(setAim).catch(() => undefined);
    });
    return () => {
      unAim.then((fn) => fn());
    };
  }, []);

  const toggleAim = async (v: boolean) => {
    try {
      await setGoAimEnabled(v);
      setAim((prev) => (prev ? { ...prev, enabled: v } : prev));
    } catch (e) {
      toast.error(String(e));
    }
  };

  const toggleLan = async (v: boolean) => {
    try {
      const s = await getGoLanSettings();
      s.enabled = v;
      await saveGoLanSettings(s);
      setLan(s);
    } catch (e) {
      toast.error(String(e));
    }
  };

  const toggleCus = async (v: boolean) => {
    try {
      const s = await getGoCusSettings();
      s.enabled = v;
      await saveGoCusSettings(s);
      setCus(s);
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
      toast.success(`已预选节点：${name}（内核启动后生效）`);
      return;
    }
    setSelecting(true);
    try {
      await selectProxy(mainSelector, name);
      setCurrentNode(name);
      setPickerOpen(false);
      toast.success(`已切换节点：${name}`);
    } catch (e) {
      console.error("pick node failed:", e);
      toast.error(`切换节点失败：${String(e)}`);
    } finally {
      setSelecting(false);
    }
  };

  // ---- Pro 引擎矩阵状态文案 ----
  // 内核未运行或配置读取失败时统一显示「—」
  const aimStatus = !running || !aim
    ? "—"
    : aim.probing
      ? "探测中…"
      : aim.lockedNode
        ? `已锁定: ${aim.lockedNode}`
        : "未锁定";
  const aimUnlocked = aim
    ? Object.values(aim.results).filter((r) => r.aiUnlocked || r.mediaUnlocked)
        .length
    : 0;
  const lanStatus = !running || !lan
    ? "—"
    : lan.enabled && lan.homeName
      ? lan.homeName
      : "未配置回家节点";
  const cusStatus = !running || !cus
    ? "—"
    : cus.modules.length === 0
      ? "未配置模块"
      : `${cus.modules.filter((m) => m.enabled).length}/${cus.modules.length} 个模块`;

  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-bold">仪表盘</h1>

      {/* 出站模式快捷切换（规则/全局/直连） */}
      <OutboundModeSwitch />

      {/* Hero 状态卡（Shadowrocket 风格：满宽，左状态右按钮） */}
      <div
        className={`rounded-2xl p-5 border transition-colors ${
          running
            ? "bg-latency-good/10 border-latency-good/30"
            : "bg-surface-card border-white/5"
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
                ? "已连接"
                : status === "starting"
                  ? "连接中…"
                  : status === "error"
                    ? "启动失败"
                    : "未连接"}
            </div>
            <div className="text-2xl font-bold tabular-nums text-gray-100">
              {running ? formatUptime(uptimeSecs) : "Prism"}
            </div>
            <div className="text-xs text-gray-500 mt-1">
              {running
                ? `运行模式 · ${MODE_LABEL[mode]}`
                : status === "starting"
                  ? "正在建立 VPN 隧道，请稍候"
                  : "点击右侧按钮启动代理"}
            </div>
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
            {running ? "停止" : status === "starting" ? "启动中" : "启动"}
          </button>
        </div>
      </div>

      {/* 启动/停止错误提示 */}
      {errorMsg && (
        <div className="rounded-xl p-4 text-sm bg-latency-bad/10 text-red-300 border border-red-500/20">
          <div className="font-semibold mb-1">操作失败</div>
          <div className="text-xs break-all text-red-200">{errorMsg}</div>
        </div>
      )}

      {/* 状态指标行（3 列） */}
      <div className="grid grid-cols-3 gap-3">
        <StatChip
          icon={<Globe size={14} className="text-gray-400" />}
          label="当前节点"
          value={
            running
              ? currentNode || "未选择"
              : currentNode || nodes[0]?.name || "—"
          }
          onClick={nodes.length > 0 ? () => setPickerOpen(true) : undefined}
        />
        {mobile ? (
          <StatChip
            icon={<BarChart3 size={14} className="text-gray-400" />}
            label="今日流量"
            value={running ? formatBytes(sessionTraffic) : "—"}
          />
        ) : (
          <StatChip
            icon={<Cpu size={14} className="text-gray-400" />}
            label="内存占用"
            value={running && memoryUsage > 0 ? formatBytes(memoryUsage) : "—"}
          />
        )}
        <StatChip
          icon={<Gauge size={14} className="text-gray-400" />}
          label="运行模式"
          value={MODE_LABEL[mode]}
        />
      </div>

      {/* Pro 引擎矩阵（Go AIM / Go Lan / Go Cus，Pro 门控） */}
      <div className="grid grid-cols-3 gap-3">
        <ProGate feature={Feature.GoAim}>
          <EngineCard
            icon={<Crosshair size={14} className="text-accent" />}
            name="Go AIM"
            status={aimStatus}
            enabled={aim?.enabled ?? false}
            onToggle={toggleAim}
            footer={`已评级解锁 ${aimUnlocked} 个节点`}
          />
        </ProGate>
        <ProGate feature={Feature.GoLan}>
          <EngineCard
            icon={<Home size={14} className="text-accent" />}
            name="Go Lan"
            status={lanStatus}
            enabled={lan?.enabled ?? false}
            onToggle={toggleLan}
          />
        </ProGate>
        <ProGate feature={Feature.GoCus}>
          <EngineCard
            icon={<Wand2 size={14} className="text-accent" />}
            name="Go Cus"
            status={cusStatus}
            enabled={cus?.enabled ?? false}
            onToggle={toggleCus}
          />
        </ProGate>
      </div>

      {/* 实时速率（合并卡片，左右分布） */}
      <div className="bg-surface-card rounded-2xl p-5 border border-white/5">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <div className="flex items-center gap-1.5 text-xs text-gray-400">
              <Activity size={13} className="text-latency-good" />
              下载
            </div>
            <div className="text-xl font-bold tabular-nums text-latency-good mt-1.5 font-mono">
              {running ? formatSpeed(downSpeed) : "—"}
            </div>
          </div>
          <div className="border-l border-white/5 pl-4">
            <div className="flex items-center gap-1.5 text-xs text-gray-400">
              <Activity size={13} className="text-accent" />
              上传
            </div>
            <div className="text-xl font-bold tabular-nums text-accent mt-1.5 font-mono">
              {running ? formatSpeed(upSpeed) : "—"}
            </div>
          </div>
        </div>
      </div>

      {/* 流量曲线图 */}
      <div className="bg-surface-card rounded-2xl p-5 border border-white/5">
        <h2 className="text-sm font-semibold mb-4 text-gray-200">实时流量（最近 60 秒）</h2>
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={traffic} margin={{ top: 4, right: 12, bottom: 0, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
            <XAxis
              dataKey="time"
              stroke="#9ca3af"
              fontSize={10}
              tickLine={false}
              minTickGap={48}
            />
            <YAxis
              stroke="#9ca3af"
              fontSize={10}
              tickLine={false}
              width={60}
              tickFormatter={(v) => formatBytes(Number(v))}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1E222D",
                border: "1px solid rgba(255,255,255,0.15)",
                borderRadius: 8,
                fontSize: 12,
                padding: '8px 12px',
              }}
              labelStyle={{ color: '#E5E7EB' }}
              itemStyle={{ color: '#E5E7EB' }}
              formatter={(value, name) => [
                formatSpeed(Number(value)),
                name === "down" ? "下载" : "上传",
              ]}
            />
            <Legend
              formatter={(v) => (v === "down" ? "下载" : "上传")}
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
              stroke="#6366f1"
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
            className="relative w-full max-w-md flex flex-col max-h-[70vh] rounded-2xl bg-surface-card border border-white/10 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-white/5">
              <div className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                <Globe size={15} className="text-accent" />
                选择节点
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
                      selected ? "bg-accent/10" : "hover:bg-white/[0.04]"
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
    </div>
  );
}

function StatChip({
  icon,
  label,
  value,
  onClick,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  onClick?: () => void;
}) {
  return (
    <div
      onClick={onClick}
      role={onClick ? "button" : undefined}
      className={clsx(
        "bg-surface-card rounded-xl p-3 border border-white/5",
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
        <span className="text-sm font-semibold tabular-nums text-gray-100 truncate">
          {value}
        </span>
        {onClick && <ChevronRight size={12} className="shrink-0 text-gray-600" />}
      </div>
    </div>
  );
}

/// Pro 引擎卡：紧凑垂直布局（图标+名称一行、状态一行），Switch 位于行尾
function EngineCard({
  icon,
  name,
  status,
  enabled,
  onToggle,
  footer,
}: {
  icon: ReactNode;
  name: string;
  status: string;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  footer?: string;
}) {
  return (
    <div className="bg-surface-card rounded-xl p-3 border border-white/5 flex flex-col">
      <div className="flex items-center justify-between gap-1.5">
        <div className="flex items-center gap-1.5 text-xs font-medium text-gray-200 min-w-0">
          {icon}
          <span className="truncate">{name}</span>
        </div>
        <Switch checked={enabled} onChange={onToggle} />
      </div>
      <div className="mt-1.5 text-xs text-gray-400 truncate" title={status}>
        {status}
      </div>
      {footer && (
        <div className="mt-0.5 text-[10px] text-gray-600 truncate">{footer}</div>
      )}
    </div>
  );
}
