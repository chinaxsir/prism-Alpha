import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import type {
  CoreStatus,
  OutboundMode,
  RunMode,
  RuntimeSnapshot,
  UserSettings,
} from "@/stores/core";

/** 内核报错脱敏：界面任何路径都不得出现内核商标字样（统一显示为「内核」） */
export const sanitizeKernelText = (msg: string): string =>
  msg.replace(/sing-?box|libbox/gi, "内核");

/**
 * 统一 invoke 包装：后端返回的错误消息脱敏后再抛给调用方，
 * 兜底防止底层内核自带的报错文本直接漏到界面。
 */
const invoke = <T,>(cmd: string, args?: Record<string, unknown>): Promise<T> =>
  tauriInvoke<T>(cmd, args).catch((e) => {
    throw typeof e === "string" ? sanitizeKernelText(e) : e;
  });

export const startCore = () => invoke<void>("start_core");
export const stopCore = () => invoke<void>("stop_core");
export const addTrafficTick = (up: number, down: number) =>
  invoke<{ todayBytes: number; weekBytes: number; monthBytes: number }>("add_traffic_tick", { up, down });

export interface CoreStatusDto {
  status: CoreStatus;
  mode: RunMode;
  uptimeSecs: number;
  /** 连接起始 Unix 毫秒时间戳（IPA-12）：亮屏 0ms 差值渲染的时钟基准；未运行时为 null */
  startedAtMs?: number | null;
  /** 主选择组（route.final 链上最深的 selector；内核未运行时为 null） */
  mainSelector?: string | null;
  /** 出站模式（规则/全局/直连） */
  outboundMode?: OutboundMode;
  /** 【APP47 任务1.2】持久化选中节点名（内核未运行时仪表盘也展示） */
  selectedNode?: string | null;
  /** 【APP54 任务1】任一启用 Go Lan 档案处于局域网直连 */
  goLanAnyDirect?: boolean;
  /** 【APP54 任务1】档案 id → 是否直连 */
  goLanProfileDirectMap?: Record<string, boolean>;
  /** 【APP54 任务4/5】全量测速进度快照 */
  delayProgress?: ProbeProgress;
  /** 【APP54 任务4/5】Go AIM 检测进度快照 */
  aimProgress?: ProbeProgress;
}

/** 【APP54 任务4】测速 / Go AIM 进度快照（事件 + 状态查询共用） */
export interface ProbeProgress {
  running: boolean;
  done: number;
  total: number;
  percent: number;
  unlockedCount: number;
}

export const getCoreStatus = () => invoke<CoreStatusDto>("get_core_status");
/// 前后台切换上报：后台时后端暂停高频事件推送与连接聚合，降低待机功耗
export const setAppForeground = (foreground: boolean) =>
  invoke<void>("set_app_foreground", { foreground });
/// 【APP58 任务2.2】原生打开外链：iOS 由 UIApplication 在系统浏览器打开，
/// 其余平台走系统默认浏览器
export const openExternalUrl = (url: string) =>
  invoke<void>("open_external_url", { url });
export const setMode = (mode: RunMode) => invoke<void>("set_mode", { mode });
export const setOutboundMode = (mode: OutboundMode) =>
  invoke<void>("set_outbound_mode", { mode });

export const urlTest = (group: string) =>
  invoke("url_test", { req: { group, url: null, timeoutMs: null } });
export const selectProxy = (group: string, name: string) =>
  invoke("select_proxy", { group, name });

export const updateSubscription = (url: string, name?: string | null) =>
  invoke("update_subscription", { url, name: name ?? null });

/** 【APP49 任务2.2】一键更新全部已启用订阅 */
export const updateAllSubscriptions = () =>
  invoke<void>("update_all_subscriptions");

/** 【APP42 任务2.1】重命名订阅备注（本地立即生效，Pro 用户静默上行云端） */
export const renameSubscription = (url: string, name: string) =>
  invoke<void>("rename_subscription", { url, name });

export interface SubscriptionRecord {
  url: string;
  updatedAt: number;
  name?: string | null;
  /** 是否参与配置合并 */
  enabled: boolean;
  /** 节点数 */
  nodeCount?: number | null;
  /** 机场流量配额（subscription-userinfo 头解析） */
  uploadBytes?: number | null;
  downloadBytes?: number | null;
  totalBytes?: number | null;
  /** 到期时间（Unix 秒） */
  expireAt?: number | null;
}

export const listSubscriptions = () =>
  invoke<SubscriptionRecord[]>("list_subscriptions");

export const toggleSubscription = (url: string, enabled: boolean) =>
  invoke<void>("toggle_subscription", { url, enabled });

export const getCustomRules = () => invoke<string[]>("get_custom_rules");

export const saveCustomRules = (rules: string[]) =>
  invoke<void>("save_custom_rules", { rules });

export const deleteSubscription = (url: string) =>
  invoke<boolean>("delete_subscription", { url });

/** 授权类型 */
export type EntitlementKind = "lifetime" | "subscription";
/** 授权来源 */
export type EntitlementSource = "code" | "apple" | "google";
/** 授权状态 */
export type EntitlementState =
  | "inactive"
  | "active"
  | "offline"
  | "expired"
  | "revoked";

/** 授权状态快照（与后端 EntitlementStatus 对齐） */
export interface Entitlement {
  status: EntitlementState;
  kind: EntitlementKind | null;
  expiresAt: number | null;
  source: EntitlementSource | null;
  lastVerifiedAt: number;
  /** 服务端方案：free | pro | team */
  plan: string | null;
  /** 授权席位上限 */
  maxSeats: number | null;
  /** 已用席位 */
  usedSeats: number | null;
  /** 【APP48】服务端是否允许订阅云端同步（Alpha 内测授权恒为 false） */
  syncAvailable: boolean;
  /** 【APP48】Alpha 内测授权标记：true 时展示「Alpha 内测版」并隐藏云端同步 */
  alpha: boolean;
}

export const activatePro = (code: string, email: string) =>
  invoke<Entitlement>("activate_pro", { code, email });
export const getEntitlement = () =>
  invoke<Entitlement>("get_entitlement");
/** 最近一次授权剥夺原因：unbound（设备解绑）/ expired（到期）/ null */
export const getRevokeReason = () =>
  invoke<"unbound" | "expired" | null>("get_revoke_reason");
/** 读取本机设备 ID（激活绑定与设置页展示用） */
export const getDeviceId = () => invoke<string>("get_device_id");
export const refreshEntitlement = () =>
  invoke<Entitlement>("refresh_entitlement");
export const deactivatePro = () =>
  invoke<Entitlement>("deactivate_pro");
export const submitReceipt = (
  store: "apple" | "google",
  receipt: unknown,
) => invoke<Entitlement>("submit_receipt", { store, receipt });

/** 授权状态变更事件 */
export const PRO_STATUS_EVENT = "pro://status";

export const getConnections = () => invoke("get_connections");
export const getTrafficStats = () => invoke("get_traffic_stats");

/** 运行时快照：今日流量 / 速率 / 60 秒曲线 / 连接 / 分析聚合（前后台不间断） */
export const getRuntimeSnapshot = () =>
  invoke<RuntimeSnapshot>("get_runtime_snapshot");

export const closeConnection = (id: string) =>
  invoke<void>("close_connection", { id });

export const closeAllConnections = () =>
  invoke<void>("close_all_connections");

/** 【APP49 任务4】清空分析聚合统计（分析页「清空统计」按钮） */
export const resetAnalyticsStats = () =>
  invoke<void>("reset_analytics_stats");
export const getRules = () => invoke("get_rules");
export const getProxyGroups = () => invoke("get_proxy_groups");

/// 内核未运行时从订阅缓存读取节点列表（节点页预览）
export const getCachedProxies = () =>
  invoke<
    Array<{
      name: string;
      kind: string;
      server: string;
      port: number;
      fromSubscription: string;
      /** 【APP52 任务1】持久化延迟：undefined=未测速；0=超时；>0=实测 */
      delay?: number;
    }>
  >("get_cached_proxies");

/// 【APP44 任务1.3】内核未运行时的真实测速（DoH + TCP 握手），返回 name→delay
export const testCachedProxies = (timeoutMs?: number) =>
  invoke<Record<string, number>>("test_cached_proxies", { timeoutMs });

/** 【APP54 任务2】全量测速：100% 覆盖全部节点（DoH 预解析 + 20 并发滑窗），
 *  返回 name→delay（0 表示超时）。运行中/未运行均可调用。 */
export const testAllDelays = () =>
  invoke<Record<string, number>>("test_all_delays");

export const getSettings = () => invoke<UserSettings>("get_settings");
export const saveSettings = (settings: UserSettings) =>
  invoke("save_settings", { settings });

/** 获取本机局域网 IPv4 地址（UDP connect 223.5.5.5:80 读 local_addr） */
export const getLanIp = () => invoke<string | null>("get_lan_ip");

export interface KernelInfo {
  exists: boolean;
  path: string | null;
  version: string | null;
}

export const getKernelInfo = () => invoke<KernelInfo>("get_kernel_info");
export const ensureKernel = () => invoke<KernelInfo>("ensure_kernel");

// ============================== Go 三引擎（Pro） ==============================

// ---- Go AIM ----

export interface AimNodeResult {
  nodeName: string;
  unlockedTags: string[];
  aiUnlocked: boolean;
  mediaUnlocked: boolean;
  score: number;
  delayMs: number;
  updatedAt: number;
  /** 是否已完成探测（APP 任务4：死节点也会生成 probed=true 的空结果） */
  probed?: boolean;
}

export interface GoAimStatus {
  enabled: boolean;
  lockedNode: string | null;
  probing: boolean;
  /** 手动指定的锁定节点（APP-4 任务3.3；null = 自动评级模式） */
  pinnedNode: string | null;
  /** 选点模式："manual"（手动指定优先）| "auto"（评级自动） */
  selectionMode: "manual" | "auto";
  results: Record<string, AimNodeResult>;
}

export const getGoAimStatus = () => invoke<GoAimStatus>("get_go_aim_status");
export const setGoAimEnabled = (enabled: boolean) =>
  invoke<void>("set_go_aim_enabled", { enabled });
export const runGoAimProbe = () => invoke<boolean>("run_go_aim_probe");
/** 清除 Go AIM 手动指定节点，回到自动评级选点（APP-4 任务3.3） */
export const clearGoAimPinnedNode = () =>
  invoke<void>("clear_go_aim_pinned_node");

// ---- Go Lan ----

export interface WgManualConfig {
  server: string;
  serverPort: number;
  privateKey: string;
  peerPublicKey: string;
  preSharedKey?: string | null;
  localIp: string;
  mtu: number;
}

/** 【APP40 任务2】单路内网档案（家里 / 公司 / 工作室……）。 */
export interface GoLanProfile {
  id: string;
  name: string;
  enabled: boolean;
  /** 命中本机同网段时跳过隧道，直接走局域网（默认 true） */
  bypassOnLocalLan: boolean;
  /** 可选：显式指定的 Wi-Fi SSID（留空按网段智能匹配） */
  localWifiSsid: string;
  lanCidrs: string[];
  wgConfig?: WgManualConfig | null;
  nodeUri: string;
  /** 该档案保存的内网检测目标（如 192.168.10.253:8001） */
  probeTarget: string;
  /** 【APP54 任务1】后端注入的运行时直连状态（不参与保存） */
  isDirect?: boolean;
}

export interface GoLanSettings {
  enabled: boolean;
  bypassOnLocalLan: boolean;
  profiles: GoLanProfile[];
  activeProfileId: string;
  mode: "manual" | "managed";
  nodeUri: string;
  wgConfig?: WgManualConfig | null;
  lanCidrs: string[];
  lanDns?: string | null;
  lanDomains: string[];
  managedServer: string;
  deviceCode: string;
  cachedManagedOutbound?: unknown | null;
  homeName?: string | null;
  /** 【APP56 任务3】档案 id → 本档案自身网段是否命中物理 WiFi（严禁跨档案聚合） */
  goLanProfileDirectMap?: Record<string, boolean>;
  goLanAnyDirect?: boolean;
}

/** 规范化单个档案：字段缺失时给出合法默认值，避免渲染期 undefined 崩溃 */
export const normalizeGoLanProfile = (raw: Partial<GoLanProfile> | null, index: number): GoLanProfile => {
  const p = raw ?? {};
  return {
    id: typeof p.id === "string" && p.id.trim() ? p.id : `profile${index + 1}`,
    name: typeof p.name === "string" && p.name.trim() ? p.name : `内网 ${index + 1}`,
    enabled: p.enabled === true,
    // 【APP45 任务1.1】On-Demand 同网段跳过默认关闭（缺省即 false）
    bypassOnLocalLan: p.bypassOnLocalLan === true,
    localWifiSsid: typeof p.localWifiSsid === "string" ? p.localWifiSsid : "",
    lanCidrs: Array.isArray(p.lanCidrs) ? p.lanCidrs : [],
    wgConfig: p.wgConfig ?? null,
    nodeUri: typeof p.nodeUri === "string" ? p.nodeUri : "",
    probeTarget: typeof p.probeTarget === "string" ? p.probeTarget : "",
    isDirect: p.isDirect === true,
  };
};

/** 【APP24 任务4.1】后端返回字段缺失兜底：wgConfig 可能为 null、
 *  lanCidrs/lanDomains/nodeUri/deviceCode 等可能因旧配置缺失而为
 *  null/undefined，前端一律规范化为合法默认值，杜绝 React 渲染期
 *  对 undefined 调用 .join/.map/.trim 导致 #root 卸载黑屏 */
export const normalizeGoLanSettings = (raw: GoLanSettings | null): GoLanSettings => {
  const r = raw ?? ({} as GoLanSettings);
  return {
    enabled: r.enabled === true,
    // 【APP45 任务1.1】On-Demand 默认关闭，理由同 normalizeGoLanProfile
    bypassOnLocalLan: r.bypassOnLocalLan === true,
    profiles: Array.isArray(r.profiles) ? r.profiles.map((p, i) => normalizeGoLanProfile(p, i)) : [],
    activeProfileId: typeof r.activeProfileId === "string" ? r.activeProfileId : "",
    mode: r.mode === "managed" ? "managed" : "manual",
    nodeUri: typeof r.nodeUri === "string" ? r.nodeUri : "",
    wgConfig: r.wgConfig ?? null,
    lanCidrs: Array.isArray(r.lanCidrs) ? r.lanCidrs : [],
    lanDns: r.lanDns ?? null,
    lanDomains: Array.isArray(r.lanDomains) ? r.lanDomains : [],
    managedServer: typeof r.managedServer === "string" ? r.managedServer : "",
    deviceCode: typeof r.deviceCode === "string" ? r.deviceCode : "",
    cachedManagedOutbound: r.cachedManagedOutbound ?? null,
    homeName: r.homeName ?? null,
    // 【APP56 任务3】保留后端逐档案直连映射（UI 只读本档案 id 对应值）
    goLanProfileDirectMap:
      r.goLanProfileDirectMap && typeof r.goLanProfileDirectMap === "object"
        ? r.goLanProfileDirectMap
        : {},
    goLanAnyDirect: r.goLanAnyDirect === true,
  };
};

/** 【APP40 任务2】内网档案运行状态（On-Demand ⚡直连 / 🔒隧道） */
export interface GoLanProfileStatus {
  tag: string;
  id: string;
  name: string;
  enabled: boolean;
  onDemand: boolean;
  /**【APP54 任务1】运行时直连判定（同网段命中或 35ms 内网探针可达） */
  isDirect?: boolean;
  state: "direct" | "tunnel";
  bypassCidrs: string[];
  tunnelCidrs: string[];
}
export interface GoLanStatus {
  profiles: GoLanProfileStatus[];
  physicalIps: string[];
  /** 【APP52 任务3】任一启用隧道命中本机局域网 → 仪表盘翠绿胶囊 */
  anyOnDemandDirect?: boolean;
  /** 【APP54 任务1】同 anyOnDemandDirect（方案字段名） */
  goLanAnyDirect?: boolean;
  /** 【APP52 任务3】档案 id → direct / tunnel / off */
  profileStates?: Record<string, "direct" | "tunnel" | "off">;
  /** 【APP54 任务1】档案 id → isDirect */
  goLanProfileDirectMap?: Record<string, boolean>;
}
export const getGoLanStatus = async (): Promise<GoLanStatus> => {
  const raw = await invoke<GoLanStatus>("get_go_lan_status");
  return {
    profiles: Array.isArray(raw?.profiles) ? raw.profiles : [],
    physicalIps: Array.isArray(raw?.physicalIps) ? raw.physicalIps : [],
    anyOnDemandDirect: raw?.anyOnDemandDirect === true,
    goLanAnyDirect: raw?.goLanAnyDirect === true || raw?.anyOnDemandDirect === true,
    profileStates: raw?.profileStates ?? {},
    goLanProfileDirectMap: raw?.goLanProfileDirectMap ?? {},
  };
};

export const getGoLanSettings = async (): Promise<GoLanSettings> =>
  normalizeGoLanSettings(await invoke<GoLanSettings>("get_go_lan_settings"));
export const saveGoLanSettings = (settings: GoLanSettings) =>
  invoke<string[]>("save_go_lan_settings", { settings });
export const syncGoLanManaged = async (): Promise<GoLanSettings> =>
  normalizeGoLanSettings(await invoke<GoLanSettings>("sync_go_lan_managed"));

/** 【APP-5 任务2 / APP6 任务2】穿过 go-lan-home 隧道检测指定内网 IP 可达性。
 *  targetIp 可省略：后端自动从 WireGuard local_address 推导对端网关 */
export interface GoLanProbeResult {
  reachable: boolean;
  targetIp: string;
  latencyMs: number | null;
  message: string;
}
export const testGoLanIp = (targetIp?: string) =>
  invoke<GoLanProbeResult>("test_go_lan_ip", { targetIp: targetIp ?? null });

/** 【APP6 任务1】全模块环形日志系统 */
export interface AppLogEntry {
  id: number;
  timestamp: string;
  level: "INFO" | "WARN" | "ERROR" | string;
  module: string;
  message: string;
}
export interface AppLogsPayload {
  entries: AppLogEntry[];
  totalBytes: number;
}
/** 【APP62 任务4】单个分类桶在 logs 数组中的区间 */
export interface LogBucket {
  module: string;
  start: number;
  end: number;
  count: number;
}
/** 【APP62 任务4】分类聚合日志：一次请求拿全部分类，切标签零请求 */
export interface CategorizedLogsPayload {
  logs: AppLogEntry[];
  buckets: LogBucket[];
  totalBytes: number;
  lastOffset: number;
}
export const getAppLogs = (moduleFilter?: string) =>
  invoke<CategorizedLogsPayload>("get_app_logs", {
    moduleFilter: moduleFilter ?? null,
  });
export const clearAppLogs = () => invoke<void>("clear_app_logs");
export const exportAppLogs = (moduleFilter?: string) =>
  invoke<string>("export_app_logs", { moduleFilter: moduleFilter ?? null });

/** APP 任务5：Go Lan 配置完整性检查（未配置时前端拦截开启操作）
 *  - 多档案（APP40）：任一启用档案网段非空，且 manual 下具备 nodeUri/wgConfig
 *  - 旧版单配置（100% 兼容）：manual 下 lanCidrs 非空且具备 nodeUri/wgConfig；
 *    managed 下 deviceCode + lanCidrs 非空 */
export const isGoLanConfigured = (cfg: GoLanSettings): boolean => {
  // 【APP24 任务4.1】字段缺失兜底：任何字段为 null/undefined 时不抛异常
  const lanCidrs = Array.isArray(cfg?.lanCidrs) ? cfg.lanCidrs : [];
  const profiles = Array.isArray(cfg?.profiles) ? cfg.profiles : [];
  const hasManualLink = (p: GoLanProfile): boolean => {
    const wg = p.wgConfig;
    return (
      (p.nodeUri ?? "").trim().length > 0 ||
      (!!wg &&
        (wg.server ?? "").trim().length > 0 &&
        (wg.privateKey ?? "").trim().length > 0 &&
        (wg.peerPublicKey ?? "").trim().length > 0)
    );
  };
  if (profiles.length > 0) {
    return profiles.some((p) => {
      if (p.enabled !== true) return false;
      const cidrs = Array.isArray(p.lanCidrs) ? p.lanCidrs : [];
      if (cidrs.length === 0) return false;
      if (cfg.mode === "manual") return hasManualLink(p);
      return true;
    });
  }
  if (cfg.mode === "manual") {
    const hasCidrs = lanCidrs.length > 0;
    const hasUri = (cfg.nodeUri ?? "").trim().length > 0;
    const wg = cfg.wgConfig;
    const hasWg =
      !!wg &&
      (wg.server ?? "").trim().length > 0 &&
      (wg.privateKey ?? "").trim().length > 0 &&
      (wg.peerPublicKey ?? "").trim().length > 0;
    return hasCidrs && (hasUri || hasWg);
  }
  return (cfg.deviceCode ?? "").trim().length > 0 && lanCidrs.length > 0;
};

// ---- Go Cus ----

export interface CusModuleStats {
  rules: number;
  rewrites: number;
  scripts: number;
  mitmHosts: number;
  hosts: number;
}

export interface CusModule {
  id: string;
  name: string;
  desc?: string | null;
  source: string;
  rawContent: string;
  enabled: boolean;
  stats: CusModuleStats;
  updatedAt: number;
}

export interface GoCusSettings {
  enabled: boolean;
  mitmEnabled: boolean;
  dnsOverride?: string | null;
  hostOverrides: Array<[string, string]>;
  modules: CusModule[];
  caInstalled: boolean;
}

export const getGoCusSettings = () => invoke<GoCusSettings>("get_go_cus_settings");
export const saveGoCusSettings = (settings: GoCusSettings) =>
  invoke<void>("save_go_cus_settings", { settings });
export const importGoCusModule = (source: string, name?: string) =>
  invoke<CusModule>("import_go_cus_module", { source, name: name ?? null });
export const toggleGoCusModule = (id: string, enabled: boolean) =>
  invoke<void>("toggle_go_cus_module", { id, enabled });
export const deleteGoCusModule = (id: string) =>
  invoke<void>("delete_go_cus_module", { id });

export interface CaInfo {
  fingerprint: string;
  installUrl: string;
  created: boolean;
}

export const generateOrGetCaUrl = () => invoke<CaInfo>("generate_or_get_ca_url");
