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
}

export const getCoreStatus = () => invoke<CoreStatusDto>("get_core_status");
export const setMode = (mode: RunMode) => invoke<void>("set_mode", { mode });
export const setOutboundMode = (mode: OutboundMode) =>
  invoke<void>("set_outbound_mode", { mode });

export const urlTest = (group: string) =>
  invoke("url_test", { req: { group, url: null, timeoutMs: null } });
export const selectProxy = (group: string, name: string) =>
  invoke("select_proxy", { group, name });

export const updateSubscription = (url: string) =>
  invoke("update_subscription", { url });

export interface SubscriptionRecord {
  url: string;
  updatedAt: number;
  name?: string | null;
  /** 是否参与配置合并 */
  enabled: boolean;
  /** 节点数 */
  nodeCount?: number | null;
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
}

export const activatePro = (code: string, email: string) =>
  invoke<Entitlement>("activate_pro", { code, email });
export const getEntitlement = () =>
  invoke<Entitlement>("get_entitlement");
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
export const getRules = () => invoke("get_rules");
export const getProxyGroups = () => invoke("get_proxy_groups");

/// 内核未运行时从订阅缓存读取节点列表（节点页预览）
export const getCachedProxies = () =>
  invoke<Array<{ name: string; kind: string; server: string; port: number; fromSubscription: string }>>(
    "get_cached_proxies"
  );

export const getSettings = () => invoke<UserSettings>("get_settings");
export const saveSettings = (settings: UserSettings) =>
  invoke("save_settings", { settings });

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
}

export interface GoAimStatus {
  enabled: boolean;
  lockedNode: string | null;
  probing: boolean;
  results: Record<string, AimNodeResult>;
}

export const getGoAimStatus = () => invoke<GoAimStatus>("get_go_aim_status");
export const setGoAimEnabled = (enabled: boolean) =>
  invoke<void>("set_go_aim_enabled", { enabled });
export const runGoAimProbe = () => invoke<boolean>("run_go_aim_probe");

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

export interface GoLanSettings {
  enabled: boolean;
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
}

export const getGoLanSettings = () => invoke<GoLanSettings>("get_go_lan_settings");
export const saveGoLanSettings = (settings: GoLanSettings) =>
  invoke<string[]>("save_go_lan_settings", { settings });
export const syncGoLanManaged = () => invoke<GoLanSettings>("sync_go_lan_managed");

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
