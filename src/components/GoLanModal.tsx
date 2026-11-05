import { useEffect, useState } from "react";
import { ClipboardPaste, Home, Plus, Trash2, X } from "lucide-react";
import { toast } from "@/components/ui/Toast";
import Switch from "@/components/ui/Switch";
import { useCoreStore } from "@/stores/core";
import { useTranslation } from "@/i18n";
import clsx from "clsx";
import {
  getGoLanSettings,
  getGoLanStatus,
  normalizeGoLanProfile,
  saveGoLanSettings,
  syncGoLanManaged,
  testGoLanIp,
  type GoLanProbeResult,
  type GoLanProfile,
  type GoLanSettings,
  type GoLanStatus,
  type WgManualConfig,
} from "@/api/ipc";

/** 【APP-12 任务2.1】Go Lan 独立配置弹窗
 *
 * 替代 Settings.tsx 内嵌大表单，提供：
 * - 一键粘贴 WireGuard .conf 自动识别填充所有字段
 * - 手动 WG / 托管 Managed 双模式
 * - 统一净化 \u2060 等零宽隐形字符
 * - 保存后立即热重载（内核运行中时由后端 restart_core 处理）
 */

type GoLanMethod = "wg" | "uri";

interface GoLanForm {
  /** 【APP40 任务2】档案标识 / 名称 / 本档案启用状态 */
  id: string;
  name: string;
  enabled: boolean;
  bypassOnLocalLan: boolean;
  probeTarget: string;
  mode: "manual" | "managed";
  method: GoLanMethod;
  nodeUri: string;
  wgServer: string;
  wgServerPort: number;
  wgPrivateKey: string;
  wgPeerPublicKey: string;
  wgPreSharedKey: string;
  wgLocalIp: string;
  wgMtu: number;
  lanCidrs: string; // 多行文本，保存时拆分
  lanDns: string;
  lanDomains: string; // 多行文本
  managedServer: string;
  deviceCode: string;
}

// 【APP14 任务1】MTU 默认值改为 WireGuard 标准值 1420，严禁再写死 1280。
const WG_DEFAULTS = { localIp: "10.0.0.2/24", mtu: 1420 };
const MANAGED_SERVER_DEFAULT = "https://prism.sarl";

/** 【APP6 任务2.3】从 WireGuard local_address（如 10.1.8.2/24）推导
 *  对端家庭网关（同网段 .1），作为「内网连通性检测」默认目标。
 *  【APP21 任务3.1】多地址（逗号分隔）时取第 1 个地址推导。 */
function deriveGateway(localIp: string): string {
  const first = localIp.trim().split(/[\r\n,;，；\s]+/)[0] ?? "";
  const m = first.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/\d{1,2})?$/);
  if (!m) return "";
  const parts = m[1].split(".");
  parts[3] = "1";
  return parts.join(".");
}

const EMPTY_GO_LAN: GoLanForm = {
  id: "home",
  name: "家里",
  enabled: false,
  // 【APP45 任务1.1】On-Demand 默认关闭
  bypassOnLocalLan: false,
  probeTarget: "",
  mode: "manual",
  method: "wg",
  nodeUri: "",
  wgServer: "",
  wgServerPort: 51820,
  wgPrivateKey: "",
  wgPeerPublicKey: "",
  wgPreSharedKey: "",
  // 【APP51 任务4】空白档案：本机虚拟地址必须为空，绝不预填 10.0.0.2
  wgLocalIp: "",
  // 【APP51 任务4】新档案展示默认 MTU 1380（运行时仍由 go_lan 锁定 1280）
  wgMtu: 1380,
  lanCidrs: "",
  lanDns: "",
  lanDomains: "",
  managedServer: MANAGED_SERVER_DEFAULT,
  deviceCode: "",
};

/** 网段文本拆分（换行/逗号/分号/空格混输），逐个净化隐形字符 */
const splitCidrsText = (raw: string): string[] =>
  raw
    .split(/[\r\n,;，；\s]+/)
    .map((l) => cleanInput(l))
    .filter(Boolean);

/// 【APP40 任务2】把一路档案 + 全局设置填入编辑表单
function applyProfileToForm(p: GoLanProfile, s: GoLanSettings): GoLanForm {
  const wg = p.wgConfig ?? null;
  const method: GoLanMethod = wg && wg.server ? "wg" : p.nodeUri ? "uri" : "wg";
  return {
    id: p.id,
    name: p.name,
    enabled: p.enabled,
    bypassOnLocalLan: p.bypassOnLocalLan,
    // 未保存过检测目标时，用 local_address 推导的网关作为默认值
    probeTarget: p.probeTarget || deriveGateway(wg?.localIp ?? ""),
    mode: s.mode,
    method,
    nodeUri: p.nodeUri ?? "",
    wgServer: wg?.server ?? "",
    wgServerPort: wg?.serverPort ?? 51820,
    wgPrivateKey: wg?.privateKey ?? "",
    wgPeerPublicKey: wg?.peerPublicKey ?? "",
    wgPreSharedKey: wg?.preSharedKey ?? "",
    // 【APP51 任务4】严禁回退到默认 10.0.0.2/24：空档案必须显示为空
    wgLocalIp: wg?.localIp ?? "",
    wgMtu: wg?.mtu || WG_DEFAULTS.mtu,
    lanCidrs: (p.lanCidrs ?? []).join("\n"),
    lanDns: s.lanDns ?? "",
    lanDomains: (s.lanDomains ?? []).join("\n"),
    managedServer: s.managedServer || MANAGED_SERVER_DEFAULT,
    deviceCode: s.deviceCode ?? "",
  };
}

/// 后端设置 → 本地编辑表单（旧版兼容：无档案时用顶层字段）
function applyGoLanLoaded(s: GoLanSettings): GoLanForm {
  if (s.profiles.length > 0) {
    const active = s.profiles.find((p) => p.id === s.activeProfileId) ?? s.profiles[0];
    return applyProfileToForm(active, s);
  }
  const wg = s.wgConfig ?? null;
  return {
    ...EMPTY_GO_LAN,
    name: s.homeName || "家里",
    enabled: s.enabled,
    bypassOnLocalLan: s.bypassOnLocalLan,
    mode: s.mode,
    method: wg && wg.server ? "wg" : s.nodeUri ? "uri" : "wg",
    nodeUri: s.nodeUri ?? "",
    wgServer: wg?.server ?? "",
    wgServerPort: wg?.serverPort ?? 51820,
    wgPrivateKey: wg?.privateKey ?? "",
    wgPeerPublicKey: wg?.peerPublicKey ?? "",
    wgPreSharedKey: wg?.preSharedKey ?? "",
    // 【APP51 任务4】空档案本地地址保持空白
    wgLocalIp: wg?.localIp ?? "",
    wgMtu: wg?.mtu || WG_DEFAULTS.mtu,
    lanCidrs: (s.lanCidrs ?? []).join("\n"),
    lanDns: s.lanDns ?? "",
    lanDomains: (s.lanDomains ?? []).join("\n"),
    managedServer: s.managedServer || MANAGED_SERVER_DEFAULT,
    deviceCode: s.deviceCode ?? "",
  };
}

/// 【APP-11B / APP-12】零宽隐形字符正则（U+200B-200F / U+202A-202E /
/// U+2060-206F / U+FEFF / 空白符）。iOS 剪贴板从微信/网页复制时常带入
/// \u2060 Word Joiner，trim 无法去除，会导致内核 netip.ParsePrefix 崩溃。
const INVISIBLE_CHARS = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\s]/g;
const cleanInput = (s: string): string => s.replace(INVISIBLE_CHARS, "");

/** 零宽隐形字符（保留空白与换行，供逐行解析使用） */
const INVISIBLE_ONLY = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g;

/** 中文字符检测：后端 message 为中文时，英文界面改用结构化字段拼英文 */
const CJK_RE = /[\u4e00-\u9fff]/;

/** 【APP21 任务3.1】解析 WireGuard Local Address（支持逗号/分号/中文标点/
 *  换行/空白分隔）：
 *  - addresses：**完整保留全部合法地址**（用英文逗号连接写回输入框，如
 *    "10.196.0.2/32, 192.168.10.222/24"）——第 2 个地址是服务端分配的
 *    同网段源 IP，访问 192.168.10.253 时内核按最长前缀匹配自动选用
 *    192.168.10.222，严禁只取第 1 个地址而删掉后面的地址；
 *    掩码缺失补 /24，输入框截断的小掩码（<8，如 /2）自动还原 /24。
 *  - cidrs：每个 IPv4 地址对应的 /24 网段，需并入「回家内网网段」。 */
function splitLocalAddresses(raw: string): { addresses: string[]; cidrs: string[] } {
  const addresses: string[] = [];
  const cidrs: string[] = [];
  for (const token of raw.split(/[\r\n,;，；\s]+/)) {
    const tok = cleanInput(token);
    if (!tok) continue;
    const m = tok.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/);
    if (!m) continue;
    let prefix = m[2] ? parseInt(m[2], 10) : 24;
    if (Number.isNaN(prefix) || prefix < 8 || prefix > 32) prefix = 24;
    const addr = `${m[1]}/${prefix}`;
    if (!addresses.includes(addr)) addresses.push(addr);
    const parts = m[1].split(".");
    const net = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    if (!cidrs.includes(net)) cidrs.push(net);
  }
  return { addresses, cidrs };
}

const WG_KNOWN_KEYS =
  /^(PrivateKey|Address|DNS|MTU|ListenPort|Table|PublicKey|PresharedKey|PreSharedKey|AllowedIPs|Endpoint|PersistentKeepalive)\s*=/i;

/** 【APP-4 任务4】解析 WireGuard .conf 全文为 GoLanForm 片段
 *
 * 折行合并解析算法：同时兼容 wg-easy 标准配置与微信跨行折行配置——
 * 只有以标准 WG 关键字开头的行才开启新字段，其余非注释/非节名行自动
 * 拼接到上一字段末尾（PrivateKey =\noJms...\nkJj...= 场景）。
 *
 * 自动提取：
 * - [Interface] PrivateKey/Address/MTU（MTU 原样保留，缺省 1420）
 * - [Peer] PublicKey/PresharedKey/Endpoint（按最后一个 : 拆分 host/port）
 * - 从 Address 推导 /24 内网网段（10.1.8.2/24 → 10.1.8.0/24）+
 *   AllowedIPs 中非默认网段，一并填入「回家内网网段」
 * - 识别成功后自动开启「启用 Go Lan」开关
 */
function parseWgConf(text: string): Partial<GoLanForm> | null {
  const cleaned = text.replace(INVISIBLE_ONLY, "");
  if (!/\[interface\]/i.test(cleaned)) return null;

  // 【APP14 任务1】只有 Base64 密钥字段才允许跨行续接（微信/网页复制常折行）；
  // Address / DNS / MTU / ListenPort / Table / PersistentKeepalive / Endpoint /
  // AllowedIPs 等字段绝不拼接后续未知行，否则会把下一行内容粘到 MTU 后面。
  const BASE64_KEY = /^(privatekey|publickey|presharedkey)$/;

  const entries: { section: string; key: string; value: string }[] = [];
  let section = "";
  for (const rawLine of cleaned.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    if (/^\[interface\]$/i.test(line)) {
      // 两段 [Interface]（服务端+客户端拼接）且尚无 [Peer] 时重置之前的字段
      if (!entries.some((e) => e.section === "peer")) entries.length = 0;
      section = "interface";
      continue;
    }
    if (/^\[peer\]$/i.test(line)) {
      section = "peer";
      continue;
    }
    if (WG_KNOWN_KEYS.test(line)) {
      const eq = line.indexOf("=");
      const key = line.slice(0, eq).trim().toLowerCase();
      const value = line
        .slice(eq + 1)
        .replace(/#.*$/, "")
        .trim();
      entries.push({ section, key, value });
    } else if (entries.length > 0) {
      const last = entries[entries.length - 1];
      // 仅裸 Base64 续行（无 = 号）且当前字段是密钥字段时才拼接
      const isBase64Chunk = /^[A-Za-z0-9+/=_-]+$/.test(line);
      if (last && BASE64_KEY.test(last.key) && last.value.length < 44 && isBase64Chunk) {
        last.value += line;
      }
    }
  }

  const get = (sec: string, key: string) =>
    entries.find((e) => e.section === sec && e.key === key)?.value;

  const out: Partial<GoLanForm> = {};
  const priv = get("interface", "privatekey");
  if (priv) out.wgPrivateKey = priv;
  const addr = get("interface", "address");
  // 【APP21 任务3.1】Address 可能是逗号分隔的多个地址（如
  // "10.196.0.2/32,192.168.10.222/24"）：**完整保留全部地址**写回
  // 「本机虚拟地址」输入框（英文逗号连接），严禁只取第 1 个删掉其余；
  // 同时把每个地址对应的 /24 网段并入「回家内网网段」。
  let addrCidrs: string[] = [];
  if (addr) {
    const parsed = splitLocalAddresses(addr);
    if (parsed.addresses.length > 0) out.wgLocalIp = parsed.addresses.join(", ");
    addrCidrs = parsed.cidrs;
  }
  const mtuRaw = get("interface", "mtu");
  if (mtuRaw) {
    // 【APP14 任务1】只提取纯数字部分，576..9000 范围内 100% 原样保留
    // （如配置文件写 1420 就填 1420），严禁再改成 1280 / 1380。
    const m = mtuRaw.match(/\d+/);
    const n = m ? parseInt(m[0], 10) : 0;
    out.wgMtu = n >= 576 && n <= 9000 ? n : WG_DEFAULTS.mtu;
  }
  const pub = get("peer", "publickey");
  if (pub) out.wgPeerPublicKey = pub;
  const psk = get("peer", "presharedkey");
  if (psk) out.wgPreSharedKey = psk;
  const ep = get("peer", "endpoint");
  if (ep) {
    const idx = ep.lastIndexOf(":");
    if (idx > 0) {
      out.wgServer = ep.slice(0, idx).replace(/^\[|\]$/g, "").trim();
      out.wgServerPort = parseInt(ep.slice(idx + 1), 10) || 51820;
    } else {
      out.wgServer = ep.trim();
      out.wgServerPort = 51820;
    }
  }
  // 回家内网网段：Address 拆分出的全部 /24 + AllowedIPs 非默认网段
  const cidrs = new Set<string>();
  for (const c of addrCidrs) cidrs.add(c);
  const allowed = get("peer", "allowedips");
  if (allowed) {
    for (const c of allowed.split(",")) {
      const seg = c.trim();
      if (seg && seg !== "0.0.0.0/0" && seg !== "::/0") cidrs.add(seg);
    }
  }
  if (cidrs.size > 0) out.lanCidrs = Array.from(cidrs).join("\n");
  // 识别成功自动开启「启用 Go Lan」
  out.enabled = true;
  return out;
}

/** 【APP40 任务2】编辑表单 → 单路档案（保存/切标签时统一走这里） */
function formToProfile(f: GoLanForm, prev?: GoLanProfile): GoLanProfile {
  const localAddr = splitLocalAddresses(f.wgLocalIp);
  // 【APP51 任务4】WG 模式即使全空也写入「完整空对象」（server/私钥等为空串、
  // 端口 51820、MTU 1380），绝不返回 null 让后端回填旧顶层配置。
  const wgConfig: WgManualConfig | null =
    f.mode === "manual" && f.method === "wg"
      ? {
          server: cleanInput(f.wgServer),
          serverPort: f.wgServerPort || 51820,
          privateKey: cleanInput(f.wgPrivateKey),
          peerPublicKey: cleanInput(f.wgPeerPublicKey),
          preSharedKey: cleanInput(f.wgPreSharedKey) || null,
          // 空档案保持空串，严禁默认 10.0.0.2/24
          localIp: localAddr.addresses.join(", "),
          mtu: f.wgMtu || 1380,
        }
      : null;
  return {
    id: f.id,
    name: f.name.trim() || "内网",
    enabled: f.enabled,
    bypassOnLocalLan: f.bypassOnLocalLan,
    localWifiSsid: prev?.localWifiSsid ?? "",
    // 【APP15 任务1.1】Local Address 拆分出的附加地址 /24 一并并入回家网段
    lanCidrs: Array.from(
      new Set([...splitCidrsText(f.lanCidrs), ...localAddr.cidrs]),
    ),
    wgConfig,
    nodeUri: cleanInput(f.nodeUri),
    probeTarget: f.probeTarget.trim(),
  };
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function GoLanModal({ open, onClose }: Props) {
  const { t, resolved } = useTranslation();
  const goLanCached = useCoreStore((s) => s.goLanSettings);
  const setGoLanSettings = useCoreStore((s) => s.setGoLanSettings);
  const [form, setForm] = useState<GoLanForm>(() =>
    goLanCached ? applyGoLanLoaded(goLanCached) : EMPTY_GO_LAN,
  );
  const [loaded, setLoaded] = useState<GoLanSettings | null>(goLanCached);
  // 【APP40 任务2】多路内网档案：profiles 为全部档案，activeId 为当前编辑档案
  const [profiles, setProfiles] = useState<GoLanProfile[]>(
    () => goLanCached?.profiles ?? [],
  );
  const [activeId, setActiveId] = useState(() => form.id);
  const [status, setStatus] = useState<GoLanStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [pasteBuf, setPasteBuf] = useState("");
  // 【APP-4 任务4】内联黄色提示（替代遮挡状态栏的顶部 Toast 报错）
  const [pasteHint, setPasteHint] = useState("");
  const [probing, setProbing] = useState(false);
  const [probeMsg, setProbeMsg] = useState("");
  const [probeOk, setProbeOk] = useState<boolean | null>(null);
  // 【APP51 任务4】清空 / 删除取消一切二次确认：单击立即执行并落盘
  // 【APP14 任务1】客户端私钥明文/密文切换，方便核对一键识别是否完整
  const [showPrivKey, setShowPrivKey] = useState(false);

  /** 当前档案的运行状态徽章（⚡ 直连中 / 🔒 隧道） */
  const statusOf = (id: string): GoLanStatus["profiles"][number] | undefined =>
    status?.profiles.find((p) => p.id === id);

  /** 把当前表单回写进 profiles（切换标签/保存前调用） */
  const mergeActiveForm = (list: GoLanProfile[]): GoLanProfile[] =>
    list.map((p) => (p.id === form.id ? formToProfile(form, p) : p));

  const switchProfile = (id: string) => {
    if (id === form.id) return;
    const merged = mergeActiveForm(profiles);
    setProfiles(merged);
    const target = merged.find((p) => p.id === id);
    if (!target) return;
    setActiveId(id);
    setForm(applyProfileToForm(target, loaded ?? ({} as GoLanSettings)));
    setProbeMsg("");
    setProbeOk(null);
  };

  /** 【APP51 任务4】统一落盘：档案列表 + 全局字段一起保存并回读，
   *  供新增/删除/清空/开关即时持久化复用（不校验表单，允许空白档案）。 */
  const persistProfiles = async (
    list: GoLanProfile[],
    f: GoLanForm,
    opts?: { silent?: boolean; successMsg?: string },
  ) => {
    const base: GoLanSettings = loaded ?? ({} as GoLanSettings);
    const active = list.find((p) => p.id === f.id) ?? list[0];
    const payload: GoLanSettings = {
      ...base,
      enabled: list.some((p) => p.enabled),
      bypassOnLocalLan: f.bypassOnLocalLan,
      profiles: list,
      activeProfileId: active?.id ?? "",
      mode: f.mode,
      nodeUri: active?.nodeUri ?? "",
      wgConfig: active?.wgConfig ?? null,
      lanCidrs: active?.lanCidrs ?? [],
      lanDns: cleanInput(f.lanDns) || null,
      lanDomains: splitCidrsText(f.lanDomains),
      managedServer: cleanInput(f.managedServer) || MANAGED_SERVER_DEFAULT,
      deviceCode: cleanInput(f.deviceCode),
    };
    try {
      await saveGoLanSettings(payload);
      const fresh = await getGoLanSettings();
      setLoaded(fresh);
      setGoLanSettings(fresh);
      setStatus(await getGoLanStatus().catch(() => null));
      if (!opts?.silent) toast.success(opts?.successMsg ?? t("goLan.saved"));
    } catch (e) {
      if (!opts?.silent) toast.error(String(e));
    }
  };

  /** 【APP51 任务4】空白档案工厂：wgConfig 为完整空对象（端口 51820 / MTU 1380），
   *  严禁复用任何旧档案字段（normalizeGoLanProfile 不得参与新建）。 */
  const blankProfile = (id: string, name: string): GoLanProfile => ({
    id,
    name,
    enabled: false,
    bypassOnLocalLan: false,
    localWifiSsid: "",
    lanCidrs: [],
    nodeUri: "",
    probeTarget: "",
    wgConfig: {
      server: "",
      serverPort: 51820,
      privateKey: "",
      peerPublicKey: "",
      preSharedKey: null,
      localIp: "",
      mtu: 1380,
    },
  });

  const addProfile = async () => {
    const merged = mergeActiveForm(profiles);
    const id = `p${Date.now().toString(36)}`;
    // 【APP51 任务4】新档案 100% 空白，并立即落盘
    const created = blankProfile(id, `内网 ${merged.length + 1}`);
    const next = [...merged, created];
    const nextForm = applyProfileToForm(created, loaded ?? ({} as GoLanSettings));
    setProfiles(next);
    setActiveId(id);
    setForm(nextForm);
    // 同步重置粘贴识别框与检测状态，杜绝残留上一条隧道的任何一个字符
    setPasteBuf("");
    setPasteHint("");
    setProbeMsg("");
    setProbeOk(null);
    await persistProfiles(next, nextForm, { silent: true });
  };

  /** 【APP51 任务4】清空当前配置：单击立即执行并落盘（无二次确认）。 */
  const clearCurrentProfile = async () => {
    const clearedForm: GoLanForm = {
      ...EMPTY_GO_LAN,
      id: form.id,
      name: form.name,
      enabled: false,
      // 清空即真正清空：隧道地址留空、MTU 1380（运行时仍锁 1280）
      wgLocalIp: "",
      wgMtu: 1380,
      // 全局字段（局域网 DNS / 域名后缀 / 托管参数 / 模式）不属于单档案，保持原值
      mode: form.mode,
      lanDns: form.lanDns,
      lanDomains: form.lanDomains,
      managedServer: form.managedServer,
      deviceCode: form.deviceCode,
    };
    const prev = profiles.find((p) => p.id === form.id);
    const clearedProfile = formToProfile(clearedForm, prev);
    const nextProfiles = profiles.map((p) =>
      p.id === form.id ? clearedProfile : p,
    );
    setForm(clearedForm);
    setProfiles(nextProfiles);
    setPasteBuf("");
    setPasteHint("");
    setProbeMsg("");
    setProbeOk(null);
    await persistProfiles(nextProfiles, clearedForm, {
      successMsg: t("goLan.cleared"),
    });
  };

  /** 【APP51 任务4】删除内网：单击立即删除并落盘；删光后自动生成一个空白默认档案 */
  const deleteProfile = async () => {
    let next = profiles.filter((p) => p.id !== form.id);
    if (next.length === 0) {
      const fallback = blankProfile("home", "家里");
      next = [fallback];
    }
    const target = next[0];
    const nextForm = applyProfileToForm(target, loaded ?? ({} as GoLanSettings));
    setProfiles(next);
    setActiveId(target.id);
    setForm(nextForm);
    setPasteBuf("");
    setPasteHint("");
    setProbeMsg("");
    setProbeOk(null);
    await persistProfiles(next, nextForm, { successMsg: t("goLan.saved") });
  };

  /** 【APP51 任务4】开关 0ms 乐观切换 + 自动落盘（启用 / On-Demand 共用） */
  const patchAndSave = (p: Partial<GoLanForm>) => {
    const nextForm = { ...form, ...p };
    setForm(nextForm);
    const nextProfiles =
      profiles.length > 0
        ? profiles.map((pr) =>
            pr.id === form.id ? formToProfile(nextForm, pr) : pr,
          )
        : [formToProfile(nextForm)];
    setProfiles(nextProfiles);
    void persistProfiles(nextProfiles, nextForm, { silent: true });
  };

  // 每次打开都从后端拉取最新配置（防止 Settings 页与 Dashboard 双入口数据漂移）
  useEffect(() => {
    if (!open) return;
    getGoLanSettings()
      .then((s) => {
        setLoaded(s);
        let list = s.profiles;
        if (list.length === 0) {
          // 旧版单配置兼容：首次进入时合成为一个「家里」档案
          let legacyProbe = "";
          try {
            legacyProbe = localStorage.getItem("prism.golan.probe_ip") ?? "";
          } catch {
            legacyProbe = "";
          }
          list = [
            normalizeGoLanProfile(
              {
                id: "home",
                name: s.homeName || "家里",
                enabled: s.enabled,
                bypassOnLocalLan: s.bypassOnLocalLan,
                lanCidrs: s.lanCidrs,
                wgConfig: s.wgConfig ?? null,
                nodeUri: s.nodeUri,
                probeTarget: legacyProbe,
              },
              0,
            ),
          ];
        }
        setProfiles(list);
        setForm(applyGoLanLoaded(s));
        setActiveId((prev) =>
          list.some((p) => p.id === prev)
            ? prev
            : (list.find((p) => p.id === s.activeProfileId) ?? list[0]).id,
        );
        setGoLanSettings(s);
        getGoLanStatus()
          .then(setStatus)
          .catch(() => setStatus(null));
      })
      .catch((e) => console.error("load go lan failed:", e));
  }, [open, setGoLanSettings]);

  // 【IPA9 任务2】锁屏唤醒 / 切后台回来时复位视口并重置 saving 状态，
  // 修复 iOS 锁屏解锁后键盘收起导致 WKWebView 视口触摸坐标偏移、
  // 以及 IPC 挂起导致 saving 卡死的问题。
  useEffect(() => {
    const handleWake = () => {
      window.scrollTo(0, 0);
      document.body.scrollTop = 0;
      setBusy(false);
    };
    document.addEventListener("visibilitychange", handleWake);
    window.addEventListener("focus", handleWake);
    return () => {
      document.removeEventListener("visibilitychange", handleWake);
      window.removeEventListener("focus", handleWake);
    };
  }, []);

  const patch = (p: Partial<GoLanForm>) => setForm((f) => ({ ...f, ...p }));

  /** 关闭弹窗：主动失焦，避免 iOS 保留输入框撤销栈 */
  const closeModal = () => {
    (document.activeElement as HTMLElement | null)?.blur();
    onClose();
  };

  /** 后端检测结果 message 为中文时，英文界面用结构化字段拼英文展示 */
  const probeText = (r: GoLanProbeResult): string => {
    const fallback = r.reachable
      ? t("goLan.probeReachable", {
          target: r.targetIp,
          latency: r.latencyMs ?? 0,
        })
      : t("goLan.probeUnreachable", { target: r.targetIp });
    if (resolved === "en" && CJK_RE.test(r.message ?? "")) return fallback;
    return r.message || fallback;
  };

  /** 【APP-4 任务4】统一识别入口：严格非空校验——确实解析出
   *  privateKey / peerPublicKey / server 之一才算成功，严禁假阳性提示 */
  const recognizeFromText = (
    text: string,
    opts?: { silent?: boolean },
  ): boolean => {
    const parsed = parseWgConf(text);
    if (
      parsed &&
      (parsed.wgPrivateKey || parsed.wgPeerPublicKey || parsed.wgServer)
    ) {
      patch(parsed);
      setPasteHint("");
      // 【APP14 任务1】识别成功但缺 PrivateKey 时给出明确内联提示，
      // 而不是让用户面对「只填了 IP 和 Port」的空白表单不知所措。
      if (!parsed.wgPrivateKey) {
        setPasteHint(t("goLan.hintMissingPrivateKey"));
      }
      if (!opts?.silent) {
        toast.success(t("goLan.recognizedToast"));
      }
      return true;
    }
    return false;
  };

  /** 一键识别按钮：粘贴框优先，为空再读系统剪贴板；都为空给内联黄色提示 */
  const handlePasteRecognize = async () => {
    let text = pasteBuf;
    if (!text.trim()) {
      try {
        text = await navigator.clipboard.readText();
      } catch {
        text = "";
      }
      if (text) setPasteBuf(text);
    }
    if (!text.trim()) {
      setPasteHint(t("goLan.hintEmptyPaste"));
      return;
    }
    if (!recognizeFromText(text)) {
      setPasteHint(t("goLan.hintInvalidConfig"));
    }
  };

  const handleSyncManaged = async () => {
    setSyncing(true);
    try {
      const s = await syncGoLanManaged();
      setLoaded(s);
      setForm(applyGoLanLoaded(s));
      setGoLanSettings(s);
      toast.success(t("goLan.syncSuccess"));
    } catch (e) {
      toast.error(String(e));
    } finally {
      setSyncing(false);
    }
  };

  // 【APP50 任务3】内网目标探测：支持纯 IP（默认测 http:80 / https:443）、
  // IP:端口、域名:端口与 http(s):// 完整 URL，后端逐个尝试常用 Web 端口。
  const handleProbe = async () => {
    const target = form.probeTarget.trim();
    if (!target) return;
    // 【APP50 任务3】支持纯 IP（后端默认探测该 IP 的 http:80 / https:443）
    // 与 IP:端口 / 域名:端口；不再前端强制要求端口号
    setProbing(true);
    setProbeOk(null);
    setProbeMsg(t("logs.probeRunning"));
    try {
      const r = await testGoLanIp(target);
      setProbeOk(r.reachable);
      const text = probeText(r);
      setProbeMsg(text);
      if (r.reachable) toast.success(text);
    } catch (e) {
      setProbeOk(false);
      setProbeMsg(String(e));
    } finally {
      setProbing(false);
    }
  };

  const handleSave = async () => {
    const current = formToProfile(form, profiles.find((p) => p.id === form.id));
    // 「一键清空」后无档案：仅在用户重新填写内容时才合成新档案
    const list =
      profiles.length > 0
        ? profiles.map((p) => (p.id === form.id ? current : p))
        : form.enabled || form.lanCidrs.trim()
          ? [current]
          : [];
    // 必填校验（仅校验当前档案）
    if (list.length > 0) {
      if (form.mode === "manual" && form.method === "wg") {
        if (!form.wgServer.trim()) return toast.error(t("goLan.errServerRequired"));
        if (!form.wgPrivateKey.trim())
          return toast.error(t("goLan.errPrivateKeyRequired"));
        if (!form.wgPeerPublicKey.trim())
          return toast.error(t("goLan.errPeerKeyRequired"));
      }
      if (form.mode === "manual" && form.method === "uri") {
        if (!form.nodeUri.trim()) return toast.error(t("goLan.errNodeUriRequired"));
      }
      if (!form.lanCidrs.trim())
        return toast.error(t("goLan.errLanCidrsRequired"));
    }
    setBusy(true);
    try {
      const base: GoLanSettings = loaded ?? ({} as GoLanSettings);
      const payload: GoLanSettings = {
        ...base,
        // 顶层旧字段与首个档案保持一致（100% 向下兼容旧版读取方）
        enabled: list.some((p) => p.enabled),
        bypassOnLocalLan: form.bypassOnLocalLan,
        profiles: list,
        activeProfileId: form.id,
        mode: form.mode,
        nodeUri: current.nodeUri,
        wgConfig: current.wgConfig ?? null,
        lanCidrs: current.lanCidrs,
        lanDns: cleanInput(form.lanDns) || null,
        lanDomains: splitCidrsText(form.lanDomains),
        managedServer: cleanInput(form.managedServer) || MANAGED_SERVER_DEFAULT,
        deviceCode: cleanInput(form.deviceCode),
      };
      // 【IPA9 任务2】Promise.race 2500ms 超时保底：saveGoLanSettings 后端
      // 已改为后台异步重启，这里再兜底一层，确保 saving 状态最多 2.5s
      // 就释放，绝不让弹窗卡死。
      const warnings = await Promise.race([
        saveGoLanSettings(payload),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(t("goLan.saveTimeout"))), 2500),
        ),
      ]);
      try {
        if (form.probeTarget) localStorage.setItem("prism.golan.probe_ip", form.probeTarget);
      } catch {
        /* localStorage 不可用时静默忽略 */
      }
      // 回读最新设置到全局 store（含 enabled 状态）
      const fresh = await getGoLanSettings();
      setGoLanSettings(fresh);
      setStatus(await getGoLanStatus().catch(() => null));
      if (warnings && warnings.length > 0) {
        toast.error(warnings[0]);
      } else {
        toast.success(t("goLan.saved"));
      }
      closeModal();
    } catch (e) {
      toast.error(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 p-4 pb-[calc(env(safe-area-inset-bottom,16px)+16px)]"
      onClick={closeModal}
    >
      {/* 【APP-4 任务4.2】三段式布局：固定头部 / 可滚动中部 / 固定底部，
          底部保存按钮永远完整显示不被屏幕截断 */}
      <div
        className="flex max-h-[82vh] w-full max-w-md flex-col overflow-hidden rounded-2xl border border-border bg-surface"
        onClick={(e) => e.stopPropagation()}
      >
        {/* 标题栏（固定） */}
        <div className="flex shrink-0 items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <Home size={16} className="text-accent" />
            <h3 className="text-sm font-semibold">{t("goLan.modalTitle")}</h3>
          </div>
          {/* 【IPA9 任务2】× 关闭按钮永不禁用：任何时候点击都立即关闭弹窗 */}
          <button
            onClick={closeModal}
            className="rounded p-1 text-gray-400 hover:bg-surface-hover hover:text-gray-200"
            aria-label={t("common.close")}
          >
            <X size={16} />
          </button>
        </div>

        {/* 可滚动表单区 */}
        <div className="flex-1 space-y-2.5 overflow-y-auto px-4 py-3">

        {/* 【APP40 任务2】内网档案 Tabs（家里 / 公司 / 工作室……） */}
        <div className="rounded-xl border border-border bg-surface-hover/40 p-2">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[11px] font-medium text-gray-400">
              {t("goLan.profiles")}
            </span>
            {/* 【APP51 任务4】单击即清空并落盘，无二次确认 */}
            <button
              onClick={() => void clearCurrentProfile()}
              className="rounded px-1.5 py-0.5 text-[11px] text-red-400 transition-colors hover:bg-red-500/10"
            >
              {t("goLan.clearCurrent")}
            </button>
          </div>
          <div className="no-scrollbar flex items-center gap-1.5 overflow-x-auto pb-0.5">
            {profiles.map((p) => {
              const st = statusOf(p.id);
              const on = p.id === form.id ? form.enabled : p.enabled;
              return (
                <button
                  key={p.id}
                  onClick={() => switchProfile(p.id)}
                  className={clsx(
                    "pressable flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] transition-colors",
                    p.id === activeId
                      ? "border-accent/60 bg-accent/15 text-accent"
                      : "border-border bg-surface text-gray-400 hover:text-gray-200",
                  )}
                >
                  <span
                    className={clsx(
                      "h-1.5 w-1.5 shrink-0 rounded-full",
                      on ? "bg-emerald-400" : "bg-gray-600",
                    )}
                  />
                  <span className="max-w-[82px] truncate">{p.name}</span>
                  {st && on && (
                    <span
                      className={clsx(
                        "tabular-nums",
                        st.state === "direct" ? "text-amber-300" : "text-sky-300",
                      )}
                    >
                      {st.state === "direct"
                        ? t("goLan.statusDirect")
                        : t("goLan.statusTunnel")}
                    </span>
                  )}
                </button>
              );
            })}
            <button
              onClick={addProfile}
              className="flex shrink-0 items-center gap-1 rounded-full border border-dashed border-accent/50 px-2.5 py-1 text-[11px] text-accent transition-colors hover:bg-accent/10"
            >
              <Plus size={12} />
              {t("goLan.addProfile")}
            </button>
          </div>
          {profiles.length === 0 && (
            <p className="mt-1.5 px-1 text-[11px] text-gray-500">
              {t("goLan.profilesEmpty")}
            </p>
          )}
        </div>

        {/* 档案名称 + 删除该档案 */}
        {profiles.length > 0 && (
          <div className="flex gap-2">
            <input
              value={form.name}
              onChange={(e) => patch({ name: e.target.value })}
              placeholder={t("goLan.profileNamePlaceholder")}
              className="min-w-0 flex-1 rounded-md border border-border bg-surface px-2 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:border-accent focus:outline-none"
            />
            {/* 【APP51 任务4】单击即删除并落盘，无二次确认 */}
            <button
              onClick={() => void deleteProfile()}
              title={t("goLan.deleteProfile")}
              className="flex shrink-0 items-center justify-center rounded-md border border-red-500/30 bg-red-500/10 px-2.5 text-red-400 transition-colors hover:bg-red-500/20"
            >
              <Trash2 size={14} />
            </button>
          </div>
        )}

        {/* 模式切换 */}
        <div className="flex gap-2 rounded-lg bg-surface-hover p-1 text-xs">
          {(["manual", "managed"] as const).map((m) => (
            <button
              key={m}
              onClick={() => patch({ mode: m })}
              className={clsx(
                "flex-1 rounded py-1.5 font-medium transition-colors",
                form.mode === m
                  ? "bg-accent text-white"
                  : "text-gray-400 hover:text-gray-200",
              )}
            >
              {m === "manual" ? t("goLan.mode.manual") : t("goLan.mode.managed")}
            </button>
          ))}
        </div>

        {form.mode === "manual" ? (
          <>
            {/* 一键粘贴识别 */}
            <div className="rounded-lg border border-accent/30 bg-accent/5 p-3">
              <button
                onClick={handlePasteRecognize}
                className="flex w-full items-center justify-center gap-2 rounded-md bg-accent/20 px-3 py-2 text-xs font-medium text-accent transition-colors hover:bg-accent/30"
              >
                <ClipboardPaste size={14} />
                {t("goLan.pasteRecognize")}
              </button>
              <textarea
                value={pasteBuf}
                onPaste={(e) => {
                  // 【APP-4 任务4】粘贴瞬间立即解析填入，无需再点按钮
                  const txt = e.clipboardData.getData("text");
                  if (!txt) return;
                  e.preventDefault();
                  setPasteBuf(txt);
                  recognizeFromText(txt);
                }}
                onChange={(e) => {
                  const v = e.target.value;
                  setPasteBuf(v);
                  setPasteHint("");
                  // 兜底：部分 WebView onPaste 不触发时，onChange 静默即时解析
                  if (/\[interface\]/i.test(v)) {
                    recognizeFromText(v, { silent: true });
                  }
                }}
                placeholder={t("goLan.pastePlaceholder")}
                rows={3}
                className="mt-2 w-full resize-none rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-[11px] text-gray-300 placeholder-gray-600 focus:border-accent focus:outline-none"
              />
              {pasteHint && (
                <p className="mt-1.5 text-[11px] leading-snug text-yellow-400">
                  {pasteHint}
                </p>
              )}
            </div>

            {/* 回家网段 */}
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                {t("goLan.lanCidrs")}
              </span>
              <textarea
                value={form.lanCidrs}
                onChange={(e) => patch({ lanCidrs: e.target.value })}
                placeholder={t("goLan.lanCidrsPlaceholder")}
                rows={2}
                className="w-full resize-none rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 placeholder-gray-600 focus:border-accent focus:outline-none"
              />
            </label>

            {/* 服务器地址 + 端口 */}
            <div className="grid grid-cols-4 gap-2">
              <label className="col-span-3 block">
                <span className="mb-1 block text-xs text-gray-400">
                  {t("goLan.endpointHost")}
                </span>
                <input
                  value={form.wgServer}
                  onChange={(e) => patch({ wgServer: e.target.value })}
                  placeholder="ishow.indevs.in"
                  className="w-full rounded-md border border-border bg-surface px-2 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:border-accent focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs text-gray-400">
                  {t("goLan.port")}
                </span>
                <input
                  type="number"
                  value={form.wgServerPort || ""}
                  onChange={(e) =>
                    patch({ wgServerPort: parseInt(e.target.value, 10) || 0 })
                  }
                  placeholder="51820"
                  className="w-full rounded-md border border-border bg-surface px-2 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:border-accent focus:outline-none"
                />
              </label>
            </div>

            {/* 本机虚拟地址 + MTU */}
            <div className="grid grid-cols-4 gap-2">
              <label className="col-span-3 block">
                <span className="mb-1 block text-xs text-gray-400">
                  {t("goLan.localIp")}
                </span>
                <input
                  value={form.wgLocalIp}
                  onChange={(e) => patch({ wgLocalIp: e.target.value })}
                  placeholder="10.195.0.2/32"
                  className="w-full rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 placeholder-gray-600 focus:border-accent focus:outline-none"
                />
                <span className="mt-1 block text-[11px] leading-4 text-gray-500">
                  {t("goLan.localIpHint")}
                </span>
              </label>
              <label className="block">
                <span className="mb-1 block text-xs text-gray-400">
                  {t("goLan.mtu")}
                </span>
                <input
                  type="number"
                  value={form.wgMtu || ""}
                  onChange={(e) =>
                    patch({ wgMtu: parseInt(e.target.value, 10) || 0 })
                  }
                  placeholder="1420"
                  className="w-full rounded-md border border-border bg-surface px-2 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:border-accent focus:outline-none"
                />
              </label>
            </div>

            {/* 私钥 / 公钥 / PSK */}
            <label className="block">
              <span className="mb-1 flex items-center justify-between text-xs text-gray-400">
                {t("goLan.privateKey")}
                <button
                  type="button"
                  onClick={() => setShowPrivKey((v) => !v)}
                  className="rounded px-1 text-[11px] text-accent hover:underline"
                >
                  {showPrivKey ? t("goLan.hide") : t("goLan.show")}
                </button>
              </span>
              <input
                type={showPrivKey ? "text" : "password"}
                value={form.wgPrivateKey}
                onChange={(e) => patch({ wgPrivateKey: e.target.value })}
                className="w-full rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 focus:border-accent focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                {t("goLan.peerPublicKey")}
              </span>
              <input
                value={form.wgPeerPublicKey}
                onChange={(e) => patch({ wgPeerPublicKey: e.target.value })}
                className="w-full rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 focus:border-accent focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                {t("goLan.psk")}
              </span>
              <input
                value={form.wgPreSharedKey}
                onChange={(e) => patch({ wgPreSharedKey: e.target.value })}
                className="w-full rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 focus:border-accent focus:outline-none"
              />
            </label>
          </>
        ) : (
          <>
            {/* 托管模式 */}
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                {t("goLan.managedServer")}
              </span>
              <input
                value={form.managedServer}
                onChange={(e) => patch({ managedServer: e.target.value })}
                className="w-full rounded-md border border-border bg-surface px-2 py-1.5 text-xs text-gray-200 focus:border-accent focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                {t("goLan.deviceCode")}
              </span>
              <input
                value={form.deviceCode}
                onChange={(e) => patch({ deviceCode: e.target.value })}
                className="w-full rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 focus:border-accent focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                {t("goLan.lanCidrs")}
              </span>
              <textarea
                value={form.lanCidrs}
                onChange={(e) => patch({ lanCidrs: e.target.value })}
                rows={2}
                className="w-full resize-none rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 focus:border-accent focus:outline-none"
              />
            </label>
            <button
              onClick={handleSyncManaged}
              disabled={syncing}
              className="w-full rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent transition-colors hover:bg-accent/20 disabled:opacity-50"
            >
              {syncing ? t("goLan.syncing") : t("goLan.syncNow")}
            </button>
          </>
        )}

        {/* 启用开关 */}
        <div className="flex items-center justify-between rounded-lg border border-border bg-surface px-3 py-2">
          <span className="text-xs text-gray-300">{t("goLan.enable")}</span>
          <Switch
            checked={form.enabled}
            onChange={(v) => patchAndSave({ enabled: v })}
          />
        </div>

        {/* 【APP50 任务2】On-Demand 局域网直连：自适应高度两行卡片，
            标题与开关一行、完整说明文字独占一行，杜绝边框压住文字 */}
        <div className="rounded-xl border border-border bg-surface-elevated p-3.5">
          <div className="flex items-center justify-between gap-3">
            <span className="text-[13px] font-semibold text-gray-200">
              {t("goLan.bypassTitle")}
            </span>
            <Switch
              checked={form.bypassOnLocalLan}
              onChange={(v) => patchAndSave({ bypassOnLocalLan: v })}
            />
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-gray-500">
            {t("goLan.bypassHint")}
          </p>
        </div>

        {/* 【APP40 任务1】内网服务连通性检测：强制 IP:端口，前端先校验格式 */}
        <div className="rounded-lg border border-border bg-surface px-3 py-2">
          <span className="mb-1.5 block text-xs text-gray-400">
            {t("goLan.testTitle")}
          </span>
          <div className="flex gap-2">
            <input
              value={form.probeTarget}
              onChange={(e) => patch({ probeTarget: e.target.value })}
              placeholder={t("goLan.testPlaceholder")}
              className="min-w-0 flex-1 rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 focus:border-accent focus:outline-none"
            />
            <button
              onClick={handleProbe}
              disabled={probing || !form.probeTarget.trim()}
              className="shrink-0 rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent transition-colors hover:bg-accent/20 disabled:opacity-50"
            >
              {probing ? t("logs.probing") : t("logs.probe")}
            </button>
          </div>
          {probeMsg && (
            <div
              className={clsx(
                "mt-1.5 text-[11px]",
                probeOk === true
                  ? "text-emerald-400"
                  : probeOk === false
                    ? "text-red-400"
                    : "text-gray-400",
              )}
            >
              {probeMsg}
            </div>
          )}
        </div>
        </div>

        {/* 底部操作栏（固定，永不被屏幕底部截断） */}
        <div className="flex shrink-0 gap-2 border-t border-border bg-surface px-4 py-3">
          {/* 【IPA9 任务2】取消按钮永不禁用：任何时候点击都立即关闭弹窗，
              防止 saving 状态卡死时用户无法退出 */}
          <button
            onClick={closeModal}
            className="pressable flex-1 rounded-md border border-border bg-surface px-3 py-2 text-xs font-medium text-gray-300 transition-colors hover:bg-surface-hover"
          >
            {t("common.cancel")}
          </button>
          <button
            onClick={handleSave}
            disabled={busy}
            className="pressable flex-1 rounded-md bg-accent px-3 py-2 text-xs font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
          >
            {busy ? t("goLan.saving") : t("goLan.saveConfig")}
          </button>
        </div>
      </div>
    </div>
  );
}
