import { create } from "zustand";
import { listen } from "@tauri-apps/api/event";
import { getGoAimSnapshot } from "@/api/ipc";

import type { Language, ThemePref } from "@/stores/prefs";
import type {
  AimNodeResult,
  GoAimEvent,
  GoAimSnapshot,
  GoAimStatus,
  GoCusSettings,
  GoLanSettings,
  ProbeProgress,
  SubscriptionRecord,
} from "@/api/ipc";

/** 【APP54 任务2】节点指标前端镜像键：切换页面 / 启停 VPN / 重启 APP 都不清空。
 *  只有「手动重新测速」或「订阅刷新/增删」才会覆盖对应节点。 */
const NODE_METRICS_KEY = "prism_node_metrics_v1";

interface NodeMetricsMirror {
  delays: Record<string, number>;
  updatedAt: number;
}

function loadNodeMetricsMirror(): NodeMetricsMirror {
  try {
    const raw = localStorage.getItem(NODE_METRICS_KEY);
    if (!raw) return { delays: {}, updatedAt: 0 };
    const parsed = JSON.parse(raw) as Partial<NodeMetricsMirror>;
    const src =
      parsed.delays && typeof parsed.delays === "object" ? parsed.delays : {};
    // 【APP56 任务2】初始化读取时清除历史 `< 5 ms` 虚假延迟（回环 / FakeIP）
    const delays: Record<string, number> = {};
    for (const [name, d] of Object.entries(src)) {
      if (typeof d !== "number") continue;
      if (d > 0 && d < 5) continue;
      delays[name] = d;
    }
    return { delays, updatedAt: parsed.updatedAt ?? 0 };
  } catch {
    return { delays: {}, updatedAt: 0 };
  }
}

function saveNodeMetricsMirror(delays: Record<string, number>) {
  try {
    localStorage.setItem(
      NODE_METRICS_KEY,
      JSON.stringify({ delays, updatedAt: Date.now() } satisfies NodeMetricsMirror),
    );
  } catch {
    /* 隐私模式 / 存储已满：静默忽略，内存态仍生效 */
  }
}

export type CoreStatus = "stopped" | "starting" | "running" | "stopping" | "error";
export type RunMode = "systemProxy" | "tun";
export type OutboundMode = "rule" | "global" | "direct";

/** 主题偏好（跟随系统 / 深色 / 浅色） */
export type ThemeSetting = "system" | "dark" | "light";

/** 【APP49 任务5】统一主题应用入口：解析 system 偏好并把结果写入 DOM
 * （dark/light class 与 data-theme 属性），供 App 挂载、系统深浅色变化、
 * visibilitychange / window focus 时 0 延迟跟随调用。 */
export function applyThemeToDom(themeSetting: ThemeSetting): "dark" | "light" {
  let resolved: "dark" | "light";
  if (themeSetting === "dark" || themeSetting === "light") {
    resolved = themeSetting;
  } else {
    try {
      resolved = window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    } catch {
      resolved = "dark";
    }
  }
  const root = document.documentElement;
  root.classList.toggle("dark", resolved === "dark");
  root.classList.toggle("light", resolved === "light");
  root.setAttribute("data-theme", resolved);
  // CSS color-scheme：浏览器原生控件（滚动条/表单）+ WebView 状态栏适配
  root.style.colorScheme = resolved;
  // <meta name="theme-color">：PWA/WebView 状态栏底色
  const bg = resolved === "dark" ? "#0B0D13" : "#F4F5F9";
  let meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  if (!meta) {
    meta = document.createElement("meta");
    meta.setAttribute("name", "theme-color");
    document.head.appendChild(meta);
  }
  meta.setAttribute("content", bg);
  return resolved;
}

/** 【APP49 任务5】系统语言解析：优先 navigator.languages[0]，zh 开头为中文 */
export function resolveSystemLanguage(): "zh" | "en" {
  const nav =
    typeof navigator !== "undefined"
      ? navigator.languages?.[0] || navigator.language || ""
      : "";
  return nav.toLowerCase().startsWith("zh") ? "zh" : "en";
}

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
  /** 【APP49】启动时自动更新全部订阅（每天一次） */
  autoUpdateSubsDaily?: boolean;
  /** 最近一次自动更新成功的日期戳（后端维护） */
  lastAutoUpdateSubsDate?: string;
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

/** 分析聚合汇总（主机名 / 域名 / IP / 出站策略 / 命中规则） */
export interface AnalyticsSummary {
  hosts: Array<[string, AggStat]>;
  /** 【APP39 任务3】后端按域名独立聚合（只含有效域名） */
  domains: Array<[string, AggStat]>;
  /** 【APP39 任务3】后端按目标 IP 独立聚合（只含纯 IP） */
  ips: Array<[string, AggStat]>;
  outbounds: Array<[string, AggStat]>;
  rules: Array<[string, AggStat]>;
  /** 【APP49 任务4】按传输协议聚合（TCP / UDP） */
  protocols: Array<[string, AggStat]>;
  /** 【APP51 任务3】三方分流累计字节（后端按连接 chains 归类 + 差额兜底） */
  proxyBytes: number;
  directBytes: number;
  lanBytes: number;
}

/** 【APP35 任务3】常见公共 IP 的域名兜底映射（无连接元数据时也能显示域名） */
const BUILTIN_IP_DOMAIN: Record<string, string> = {
  "8.8.8.8": "dns.google",
  "8.8.4.4": "dns.google",
  "1.1.1.1": "one.one.one.one",
  "1.0.0.1": "one.one.one.one",
  "223.5.5.5": "dns.alidns.com",
};

/** 是否为 IPv4 字面量（用于区分「域名」与「IP」聚合键） */
export function isIpLiteral(s: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(s);
}

/** 【APP35 任务3】把连接的 host ↔ destinationIP 关系累积进全局映射缓存 */
function collectHostMappings(
  prevIp: Record<string, string>,
  prevDomain: Record<string, string>,
  list: ConnItem[],
): { ipToDomain: Record<string, string>; domainToIp: Record<string, string> } {
  let ipToDomain = prevIp;
  let domainToIp = prevDomain;
  for (const c of list) {
    const host = (c.host ?? "").trim();
    const ip = (c.destinationIP ?? "").trim();
    if (!host || !ip || host === ip || !isIpLiteral(ip)) continue;
    if (ipToDomain[ip] === host && domainToIp[host] === ip) continue;
    if (ipToDomain === prevIp) ipToDomain = { ...prevIp };
    if (domainToIp === prevDomain) domainToIp = { ...prevDomain };
    ipToDomain[ip] = host;
    domainToIp[host] = ip;
  }
  return { ipToDomain, domainToIp };
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
  /** 【APP35 任务3】IP → 域名 映射缓存（连接元数据 + 公共 DNS 兜底） */
  ipToDomain: Record<string, string>;
  /** 【APP35 任务3】域名 → IP 映射缓存（分析页 IP 模式使用） */
  domainToIp: Record<string, string>;
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
  /// 【APP57 任务2】内核启动 / 停止 / 重启时清空分析统计与主机映射缓存
  resetAnalytics: () => void;
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
  /** 【APP54 任务2】节点延迟前端镜像（localStorage 持久化，切页/启停不丢） */
  nodeDelays: Record<string, number>;
  /** 【APP54 任务4】全量测速进度 */
  delayProgress: ProbeProgress;
  /** 【APP54 任务4】Go AIM 探测进度 */
  aimProgress: ProbeProgress;
  /** 【APP71 任务2.3】最近一条 Go AIM 结构化事件（单节点详情弹窗 / 看板） */
  aimEvent: GoAimEvent | null;
  /** 【APP71 任务2.3】最近 30 条事件环形缓冲（页面切回可回放） */
  aimEvents: GoAimEvent[];
  /** 【APP71 任务2.3】当前活跃 runId 与已接收最大 sequence（去重游标） */
  aimRunId: string | null;
  aimSequence: number;
  /** 【APP71】最近一次明确失败原因（0 存活 / 未启用 / 未激活） */
  aimLastError: string | null;
  /** 【APP79 任务2.3】本轮检测评选出的最佳节点（FINISHED 事件携带） */
  aimBestNode: { name: string; delayMs: number | null } | null;
  /** 【APP79 任务2.3】检测完成时刻（毫秒时间戳），用于横幅 3.5s 自动淡出 */
  aimFinishedAt: number | null;
  setGoAimStatus: (s: GoAimStatus | null) => void;
  setGoLanSettings: (s: GoLanSettings | null) => void;
  setGoCusSettings: (s: GoCusSettings | null) => void;
  setSubscriptions: (s: SubscriptionRecord[] | null) => void;
  /** 合并写入延迟（0 = 超时，保留区分未测速）并同步 localStorage */
  mergeNodeDelays: (next: Record<string, number>) => void;
  /** 订阅刷新/增删后清理已失效节点（唯一允许删除延迟缓存的入口） */
  retainNodeDelays: (validNames: string[]) => void;
  setDelayProgress: (p: ProbeProgress) => void;
  setAimProgress: (p: ProbeProgress) => void;
  /** 【APP71 任务2.3】应用一条结构化事件（runId + sequence 去重，丢弃迟到旧事件） */
  applyAimEvent: (ev: GoAimEvent) => void;
  /** 【APP71 任务3】应用一次性快照（页面挂载 / 后台唤醒同步） */
  applyAimSnapshot: (snap: GoAimSnapshot) => void;
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
  analytics: {
    hosts: [],
    domains: [],
    ips: [],
    outbounds: [],
    rules: [],
    protocols: [],
    proxyBytes: 0,
    directBytes: 0,
    lanBytes: 0,
  },
  ipToDomain: { ...BUILTIN_IP_DOMAIN },
  domainToIp: {},
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
  setConnections: (connections) => {
    const { ipToDomain, domainToIp } = get();
    set({ connections, ...collectHostMappings(ipToDomain, domainToIp, connections) });
  },
  setAnalytics: (analytics) => set({ analytics }),
  // 【APP57 任务2】收到 analytics://reset 或本端启停内核时，立即归零展示
  resetAnalytics: () =>
    set({
      analytics: {
        hosts: [],
        domains: [],
        ips: [],
        outbounds: [],
        rules: [],
        protocols: [],
        proxyBytes: 0,
        directBytes: 0,
        lanBytes: 0,
      },
      ipToDomain: {},
      domainToIp: {},
    }),

  applyRuntimeSnapshot: (snap) => {
    // 后端权威快照：60 秒曲线直接覆盖（后台期间由内核持续采样，无缝衔接）
    const traffic = snap.trafficHistory60s.length
      ? snap.trafficHistory60s
      : get().traffic;
    const { ipToDomain, domainToIp } = get();
    set({
      todayBytes: snap.todayBytes,
      upSpeed: snap.upSpeed,
      downSpeed: snap.downSpeed,
      traffic,
      connections: snap.connections,
      analytics: {
        ...snap.analyticsSummary,
        // 【APP51 任务3】旧后端/首帧可能缺省，统一兜底为 0，前端永不 undefined
        proxyBytes: snap.analyticsSummary.proxyBytes ?? 0,
        directBytes: snap.analyticsSummary.directBytes ?? 0,
        lanBytes: snap.analyticsSummary.lanBytes ?? 0,
      },
      ...collectHostMappings(ipToDomain, domainToIp, snap.connections),
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
      analytics: {
        hosts: [],
        domains: [],
        ips: [],
        outbounds: [],
        rules: [],
        protocols: [],
        proxyBytes: 0,
        directBytes: 0,
        lanBytes: 0,
      },
      sessionTraffic: 0,
    }),

  // ---- Go 三引擎状态缓存 ----
  goAimStatus: null,
  goLanSettings: null,
  goCusSettings: null,
  subscriptions: null,
  nodeDelays: loadNodeMetricsMirror().delays,
  delayProgress: { running: false, done: 0, total: 0, percent: 0, unlockedCount: 0 },
  aimProgress: { running: false, done: 0, total: 0, percent: 0, unlockedCount: 0 },
  aimEvent: null,
  aimEvents: [],
  aimRunId: null,
  aimSequence: 0,
  aimLastError: null,
  aimBestNode: null,
  aimFinishedAt: null,
  setGoAimStatus: (goAimStatus) => set({ goAimStatus }),
  setGoLanSettings: (goLanSettings) => set({ goLanSettings }),
  setGoCusSettings: (goCusSettings) => set({ goCusSettings }),
  setSubscriptions: (subscriptions) => set({ subscriptions }),

  mergeNodeDelays: (next) => {
    // 【APP56 任务2】写入前再次拦截 `< 5 ms` 假值，保证镜像永不存 1ms
    const clean: Record<string, number> = {};
    for (const [name, d] of Object.entries(next)) {
      if (typeof d === "number" && !(d > 0 && d < 5)) clean[name] = d;
    }
    if (Object.keys(clean).length === 0) return;
    const merged = { ...get().nodeDelays, ...clean };
    set({ nodeDelays: merged });
    saveNodeMetricsMirror(merged);
  },
  retainNodeDelays: (validNames) => {
    const valid = new Set(validNames);
    const prev = get().nodeDelays;
    const kept: Record<string, number> = {};
    for (const [name, delay] of Object.entries(prev)) {
      if (valid.has(name)) kept[name] = delay;
    }
    set({ nodeDelays: kept });
    saveNodeMetricsMirror(kept);
  },
  setDelayProgress: (delayProgress) => set({ delayProgress }),
  setAimProgress: (aimProgress) => set({ aimProgress }),

  // 【APP71 任务2.3】严格按 (runId, sequence) 去重：旧 runId 的迟到事件、
  // 同一 runId 的重复/乱序事件一律丢弃，绝不回退进度或覆盖新结果。
  applyAimEvent: (ev) => {
    const state = get();
    const currentRun = state.aimRunId;
    if (currentRun && ev.runId !== currentRun) {
      const newer = aimRunIdNum(ev.runId) > aimRunIdNum(currentRun);
      if (ev.phase === "START") {
        if (!newer) return;
      } else if (ev.phase === "ERROR") {
        // 运行中的旧错误不得覆盖新会话；非运行态只接受更新的独立失败事件
        if (!newer || state.aimProgress.running) return;
      } else {
        return; // 旧 run 的迟到进度 / 结果事件
      }
    } else if (currentRun === ev.runId && ev.sequence <= state.aimSequence) {
      return;
    }
    const patch: Partial<CoreState> = {
      aimProgress: ev.progress,
      aimEvent: ev,
      aimRunId: ev.runId,
      aimSequence: ev.sequence,
      aimEvents: [...state.aimEvents, ev].slice(-30),
    };
    if (ev.phase === "ERROR") {
      patch.aimLastError = ev.message;
    } else if (ev.phase === "START") {
      patch.aimLastError = null;
      // 【APP79 任务2.3】新一轮开始：清空上一轮的优选结果与完成时刻
      patch.aimBestNode = null;
      patch.aimFinishedAt = null;
    } else if (ev.phase === "FINISHED") {
      // 【APP79 任务2.3】后端在 FINISHED.details 中携带 bestNode，
      // 前端据此刷新「当前节点」高亮并展示 3.5s 优选横幅。
      const details = (ev.details ?? null) as {
        bestNode?: string | null;
        bestDelay?: number | null;
      } | null;
      patch.aimBestNode = details?.bestNode
        ? { name: details.bestNode, delayMs: details.bestDelay ?? null }
        : null;
      patch.aimFinishedAt = Date.now();
    }
    // NODE_RESULT 携带单节点完整结果：直接合并到状态缓存，无需再拉全量
    if (ev.phase === "NODE_RESULT" && ev.details) {
      const result = ev.details as AimNodeResult;
      const current = state.goAimStatus;
      if (current && result?.nodeName) {
        patch.goAimStatus = {
          ...current,
          results: { ...current.results, [result.nodeName]: result },
        };
      }
    }
    set(patch);
  },

  // 【APP71 任务3】快照同步：页面首次挂载 / 后台唤醒 / visibilitychange 时拉取，
  // 与事件流合并后进度、事件、结果完全一致，彻底消除 listen 注册前的丢包。
  applyAimSnapshot: (snap) => {
    if (!snap) return;
    const previous = get();
    const events = Array.isArray(snap.events) ? snap.events.slice(-30) : [];
    const last = events.length > 0 ? events[events.length - 1] : null;
    const runId = snap.progress?.runId || last?.runId || null;
    const sequence = Math.max(snap.progress?.sequence ?? 0, last?.sequence ?? 0);
    const patch: Partial<CoreState> = {
      aimProgress: snap.progress,
      aimEvents: events,
      aimEvent: last,
      aimRunId: runId,
      aimSequence: sequence,
      aimLastError: snap.lastError ?? null,
    };
    const current = previous.goAimStatus;
    if (current) {
      patch.goAimStatus = {
        ...current,
        enabled: snap.enabled,
        probing: snap.probing,
        pinnedNode: snap.pinnedNode,
        lockedNode: snap.bestNode ?? current.lockedNode,
        results: snap.results ?? current.results,
      };
    }
    // 【APP81 任务3.2】心跳发现后端已结束时，同步完成态与最优节点，
    // 让运行横幅立即消失，并复用现有 3s 完成横幅/徽章渲染链路。
    if (!snap.progress.running && !snap.probing) {
      if (previous.aimProgress.running || previous.goAimStatus?.probing) {
        patch.aimFinishedAt = Date.now();
      }
      if (snap.bestNode) {
        patch.aimBestNode = {
          name: snap.bestNode,
          delayMs: snap.results?.[snap.bestNode]?.delayMs ?? null,
        };
      }
    }
    set(patch);
  },
}));

/** 【APP71】runId 内嵌毫秒时间戳（aim-xxxxxxxx），按数值比较新旧。 */
function aimRunIdNum(runId: string): number {
  const parsed = Number.parseInt(runId.replace(/^aim-/, ""), 16);
  return Number.isFinite(parsed) ? parsed : 0;
}

// 【APP71 任务2.3】Go AIM 事件监听单例：整个 APP 生命周期只注册一次，
// 任意页面挂载/卸载都不会重复监听或漏接事件。
let aimListenersReady: Promise<void> | null = null;
let aimHeartbeatStarted = false;
let aimHeartbeatBusy = false;

/** 【APP81 任务3.2】全局 2500ms 心跳：只读快照对账，绝不触发新探测。 */
function ensureAimHeartbeatStarted(): void {
  if (aimHeartbeatStarted) return;
  aimHeartbeatStarted = true;
  window.setInterval(() => {
    const state = useCoreStore.getState();
    const running = state.aimProgress.running || Boolean(state.goAimStatus?.probing);
    if (!running || aimHeartbeatBusy) return;
    aimHeartbeatBusy = true;
    void syncAimSnapshot().finally(() => {
      aimHeartbeatBusy = false;
    });
  }, 2500);
}

/** 注册 `go-aim://event` 与兼容 `aim://progress` 监听（幂等）。 */
export function ensureAimListenersRegistered(): Promise<void> {
  ensureAimHeartbeatStarted();
  if (aimListenersReady) return aimListenersReady;
  aimListenersReady = (async () => {
    await listen<GoAimEvent>("go-aim://event", (e) => {
      if (e.payload) useCoreStore.getState().applyAimEvent(e.payload);
    });
    await listen<ProbeProgress>("aim://progress", (e) => {
      if (e.payload) useCoreStore.getState().setAimProgress(e.payload);
    });
  })().catch((err) => {
    aimListenersReady = null;
    throw err;
  });
  return aimListenersReady;
}

/** 拉取并应用一次 Go AIM 全量快照（页面挂载 / 回到前台时调用）。 */
export async function syncAimSnapshot(): Promise<void> {
  try {
    const snap = await getGoAimSnapshot();
    useCoreStore.getState().applyAimSnapshot(snap);
  } catch {
    // Tauri IPC 不可用（纯浏览器预览）时静默，不影响页面渲染
  }
}

/**
 * 【APP33 任务3.2】信息/广告类假节点名称识别（前端版，与后端
 * config_builder::is_info_or_ad_node_name 关键词严格一致）。
 * 只拦截「剩余流量/到期时间/官网公告」等信息类名称，绝不包含
 * 「下载/高速/专线/倍率/流媒体」等真实节点常用词，防止误杀
 * 「美国凤凰城|高速下载」这类真实节点。
 */
export function isDummyNodeName(name?: string | null): boolean {
  if (!name) return true;
  const n = name.trim().toLowerCase();
  if (n.length === 0) return true;
  const keywords = [
    "剩余", "流量", "到期", "过期", "重置", "套餐", "有效期", "剩余天数",
    "官网", "网址", "发布页", "地址发布", "最新地址", "备用地址", "防失联",
    "群组", "官方群", "电报群", "tg群", "频道", "客服", "工单",
    "公告", "通知", "使用说明", "使用必读", "教程", "必看",
    "优惠", "折扣", "续费", "购买", "邀请好友", "返利", "推广",
    "请更新", "更新订阅", "节点故障", "维护中",
    "http://", "https://", "t.me/",
  ];
  return keywords.some((kw) => n.includes(kw));
}
