import { create } from "zustand";

import type { Language, ThemePref } from "@/stores/prefs";
import type {
  GoAimStatus,
  GoCusSettings,
  GoLanSettings,
  SubscriptionRecord,
} from "@/api/ipc";

export type CoreStatus = "stopped" | "starting" | "running" | "stopping" | "error";
export type RunMode = "systemProxy" | "tun";
export type OutboundMode = "rule" | "global" | "direct";

export interface UserSettings {
  mixedPort: number;
  allowLan: boolean;
  systemProxy: boolean;
  /** 运行模式（后端权威持久化；表单提交时会被后端以 set_mode 为准覆盖） */
  mode: RunMode;
  autoStart: boolean;
  /** 出站模式（规则/全局/直连） */
  outboundMode?: OutboundMode;
  /** 启用 IPv6 */
  ipv6?: boolean;
  /** 阻止 QUIC（UDP/443） */
  blockQuic?: boolean;
  /** 切换策略后关闭现有连接 */
  closeConnectionsOnSwitch?: boolean;
  /** 界面语言：跟随系统 / 简体中文 / English */
  language?: Language;
  /** 外观：跟随系统 / 深色 / 浅色 */
  theme?: ThemePref;
}

export interface TrafficPoint {
  time: string;
  up: number;
  down: number;
}

/** 连接条目（后端 get_runtime_snapshot / connections://tick 对齐） */
export interface ConnItem {
  id: string;
  host: string;
  destinationIP: string;
  sourceIP: string;
  sourcePort: string;
  destinationPort: string;
  network: string;
  upload: number;
  download: number;
  chains: string[];
  rule: string;
  rulePayload: string;
  start?: string;
  /** 是否活跃：false 表示近期已关闭但仍保留展示 */
  active: boolean;
}

/** 分析聚合条目 */
export interface AggStat {
  count: number;
  up: number;
  down: number;
}

/** 分析聚合汇总（主机名 / 出站策略 / 命中规则） */
export interface AnalyticsSummary {
  hosts: Array<[string, AggStat]>;
  outbounds: Array<[string, AggStat]>;
  rules: Array<[string, AggStat]>;
}

/** 后端运行时快照：一次拉取今日流量、速率、60 秒曲线、连接与分析聚合 */
export interface RuntimeSnapshot {
  todayBytes: number;
  upSpeed: number;
  downSpeed: number;
  trafficHistory60s: TrafficPoint[];
  connections: ConnItem[];
  analyticsSummary: AnalyticsSummary;
}

interface CoreState {
  status: CoreStatus;
  mode: RunMode;
  /** 出站模式（规则/全局/直连），由 get_core_status / core://status 填充 */
  outboundMode: OutboundMode;
  upSpeed: number;
  downSpeed: number;
  memoryUsage: number;
  uptimeSecs: number;
  /** 连接起始 Unix 毫秒时间戳（IPA-12）：基准时钟，亮屏第一帧用
      Date.now() 差值 0ms 瞬时同步时长；非运行态为 null */
  startedAtMs: number | null;
  traffic: TrafficPoint[];
  /** 今日流量（字节）：后端持久化基数 + 当前会话绝对累计，前后台不间断 */
  todayBytes: number;
  /** 活跃/近期连接（后端维护，切页与后台不丢） */
  connections: ConnItem[];
  /** 分析聚合（后端维护，切页与后台不丢） */
  analytics: AnalyticsSummary;
  settings: UserSettings;

  setStatus: (s: CoreStatus) => void;
  setMode: (m: RunMode) => void;
  setOutboundMode: (m: OutboundMode) => void;
  setTrafficRate: (up: number, down: number) => void;
  setMemoryUsage: (bytes: number) => void;
  setUptime: (secs: number) => void;
  setStartedAtMs: (ms: number | null) => void;
  /** 从后端状态 DTO 对齐 startedAtMs（IPA-12）：running 态优先采用后端
      startedAtMs，仅有 uptimeSecs 时推导 Date.now() - uptimeSecs*1000；
      与本地已有基准误差 <2s 时不改写（事件/轮询双源防抖动）。
      非 running 态直接置 null */
  syncStartedAt: (dto: {
    status: CoreStatus;
    uptimeSecs: number;
    startedAtMs?: number | null;
  }) => void;
  setSettings: (s: UserSettings) => void;
  pushTraffic: (up: number, down: number) => void;
  /** 当前会话累计流量（字节），关闭 APP 后清零 */
  sessionTraffic: number;
  setTodayBytes: (bytes: number) => void;
  setConnections: (list: ConnItem[]) => void;
  setAnalytics: (summary: AnalyticsSummary) => void;
  /** 应用后端运行时快照（回前台/定时同步，保证数据无缝衔接） */
  applyRuntimeSnapshot: (snap: RuntimeSnapshot) => void;
  /** 内核停止时清空运行时数据 */
  clearRuntime: () => void;

  // ---- Go 三引擎状态缓存（APP 任务1：提升到全局 store，消除切页闪烁） ----
  /** Go AIM 状态缓存；null = 尚未加载（页面静默刷新后填充） */
  goAimStatus: GoAimStatus | null;
  /** Go Lan 设置缓存；null = 尚未加载 */
  goLanSettings: GoLanSettings | null;
  /** Go Cus 设置缓存；null = 尚未加载 */
  goCusSettings: GoCusSettings | null;
  /** 【APP-10 任务4】订阅列表缓存；null = 尚未加载（订阅页首帧直出，
      消除 Switch 启用态切页闪烁） */
  subscriptions: SubscriptionRecord[] | null;
  setGoAimStatus: (s: GoAimStatus | null) => void;
  setGoLanSettings: (s: GoLanSettings | null) => void;
  setGoCusSettings: (s: GoCusSettings | null) => void;
  setSubscriptions: (s: SubscriptionRecord[] | null) => void;
}

// 环形缓冲：仅保留最近 60 个采样点（1 分钟）
const MAX_POINTS = 60;

export const useCoreStore = create<CoreState>((set, get) => ({
  status: "stopped",
  mode: "systemProxy",
  outboundMode: "rule",
  upSpeed: 0,
  downSpeed: 0,
  memoryUsage: 0,
  uptimeSecs: 0,
  startedAtMs: null,
  traffic: [],
  todayBytes: 0,
  connections: [],
  analytics: { hosts: [], outbounds: [], rules: [] },
  sessionTraffic: 0,
  settings: {
    mixedPort: 2080,
    allowLan: false,
    systemProxy: true,
    mode: "systemProxy",
    autoStart: false,
  },

  setStatus: (status) => set({ status }),
  setMode: (mode) => set({ mode }),
  setOutboundMode: (outboundMode) => set({ outboundMode }),
  setTrafficRate: (upSpeed, downSpeed) => set({ upSpeed, downSpeed }),
  setMemoryUsage: (memoryUsage) => set({ memoryUsage }),
  setUptime: (uptimeSecs) => set({ uptimeSecs }),
  setStartedAtMs: (startedAtMs) => set({ startedAtMs }),

  syncStartedAt: (dto) => {
    if (dto.status !== "running") {
      if (get().startedAtMs !== null) set({ startedAtMs: null });
      return;
    }
    // 优先后端毫秒时间戳（iOS 为系统级 connectedDate，最精确）；
    // 旧后端仅有 uptimeSecs 时推导基准
    let next: number | null = null;
    if (dto.startedAtMs && dto.startedAtMs > 0) {
      next = dto.startedAtMs;
    } else if (dto.uptimeSecs > 0) {
      next = Date.now() - dto.uptimeSecs * 1000;
    }
    if (next === null) return;
    const cur = get().startedAtMs;
    // 误差 <2s 保持原基准不抖动（core://status 事件与轮询可能双源到达）
    if (cur === null || Math.abs(cur - next) > 2000) set({ startedAtMs: next });
  },

  setSettings: (settings) => set({ settings }),

  pushTraffic: (up, down) => {
    const point: TrafficPoint = {
      time: new Date().toLocaleTimeString("zh-CN", { hour12: false }),
      up,
      down,
    };
    const next = [...get().traffic, point];
    if (next.length > MAX_POINTS) next.shift();
    // 累计当前会话流量（关闭 APP 后清零）
    set({ traffic: next, sessionTraffic: get().sessionTraffic + up + down });
  },

  setTodayBytes: (todayBytes) => set({ todayBytes }),
  setConnections: (connections) => set({ connections }),
  setAnalytics: (analytics) => set({ analytics }),

  applyRuntimeSnapshot: (snap) => {
    // 后端权威快照：60 秒曲线直接覆盖（后台期间由内核持续采样，无缝衔接）
    const traffic = snap.trafficHistory60s.length
      ? snap.trafficHistory60s
      : get().traffic;
    set({
      todayBytes: snap.todayBytes,
      upSpeed: snap.upSpeed,
      downSpeed: snap.downSpeed,
      traffic,
      connections: snap.connections,
      analytics: snap.analyticsSummary,
    });
  },

  clearRuntime: () =>
    set({
      traffic: [],
      upSpeed: 0,
      downSpeed: 0,
      memoryUsage: 0,
      startedAtMs: null,
      connections: [],
      analytics: { hosts: [], outbounds: [], rules: [] },
      sessionTraffic: 0,
    }),

  // ---- Go 三引擎状态缓存 ----
  goAimStatus: null,
  goLanSettings: null,
  goCusSettings: null,
  subscriptions: null,
  setGoAimStatus: (goAimStatus) => set({ goAimStatus }),
  setGoLanSettings: (goLanSettings) => set({ goLanSettings }),
  setGoCusSettings: (goCusSettings) => set({ goCusSettings }),
  setSubscriptions: (subscriptions) => set({ subscriptions }),
}));
