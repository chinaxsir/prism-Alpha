import { useEffect, useState } from "react";
import { ClipboardPaste, Home, X } from "lucide-react";
import { toast } from "@/components/ui/Toast";
import Switch from "@/components/ui/Switch";
import { useCoreStore } from "@/stores/core";
import { useTranslation } from "@/i18n";
import clsx from "clsx";
import {
  getGoLanSettings,
  saveGoLanSettings,
  syncGoLanManaged,
  testGoLanIp,
  type GoLanSettings,
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
  enabled: boolean;
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
  enabled: false,
  mode: "manual",
  method: "wg",
  nodeUri: "",
  wgServer: "",
  wgServerPort: 51820,
  wgPrivateKey: "",
  wgPeerPublicKey: "",
  wgPreSharedKey: "",
  wgLocalIp: WG_DEFAULTS.localIp,
  wgMtu: WG_DEFAULTS.mtu,
  lanCidrs: "",
  lanDns: "",
  lanDomains: "",
  managedServer: MANAGED_SERVER_DEFAULT,
  deviceCode: "",
};

/// 后端设置 → 本地编辑表单
function applyGoLanLoaded(s: GoLanSettings): GoLanForm {
  const wg = s.wgConfig ?? null;
  const method: GoLanMethod = wg && wg.server ? "wg" : s.nodeUri ? "uri" : "wg";
  return {
    enabled: s.enabled,
    mode: s.mode,
    method,
    nodeUri: s.nodeUri ?? "",
    wgServer: wg?.server ?? "",
    wgServerPort: wg?.serverPort ?? 51820,
    wgPrivateKey: wg?.privateKey ?? "",
    wgPeerPublicKey: wg?.peerPublicKey ?? "",
    wgPreSharedKey: wg?.preSharedKey ?? "",
    wgLocalIp: wg?.localIp || WG_DEFAULTS.localIp,
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

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function GoLanModal({ open, onClose }: Props) {
  const { t } = useTranslation();
  const goLanCached = useCoreStore((s) => s.goLanSettings);
  const setGoLanSettings = useCoreStore((s) => s.setGoLanSettings);
  const [form, setForm] = useState<GoLanForm>(() =>
    goLanCached ? applyGoLanLoaded(goLanCached) : EMPTY_GO_LAN,
  );
  const [loaded, setLoaded] = useState<GoLanSettings | null>(goLanCached);
  const [busy, setBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [pasteBuf, setPasteBuf] = useState("");
  // 【APP-4 任务4】内联黄色提示（替代遮挡状态栏的顶部 Toast 报错）
  const [pasteHint, setPasteHint] = useState("");
  // 【APP6 任务2.3】内网连通性检测：默认目标=local_address 推导的网关
  // 【IPA9 任务3】用户输入的检测 IP 持久化到 localStorage，下次直接使用
  const [probeTarget, setProbeTarget] = useState(() => {
    try {
      return localStorage.getItem("prism.golan.probe_ip") ?? "";
    } catch {
      return "";
    }
  });
  const [probing, setProbing] = useState(false);
  const [probeMsg, setProbeMsg] = useState("");
  const [probeOk, setProbeOk] = useState<boolean | null>(null);
  // 【APP14 任务1】客户端私钥明文/密文切换，方便核对一键识别是否完整
  const [showPrivKey, setShowPrivKey] = useState(false);

  // 打开时：若用户从未输入过检测 IP，用 local_address 推导的网关初始化
  useEffect(() => {
    if (open) {
      setProbeTarget((prev) => {
        if (prev) return prev; // 尊重用户已保存的输入
        const derived = deriveGateway(form.wgLocalIp);
        return derived;
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // 持久化用户输入的检测 IP
  useEffect(() => {
    try {
      if (probeTarget) localStorage.setItem("prism.golan.probe_ip", probeTarget);
    } catch {
      /* localStorage 不可用时静默忽略 */
    }
  }, [probeTarget]);

  // 每次打开都从后端拉取最新配置（防止 Settings 页与 Dashboard 双入口数据漂移）
  useEffect(() => {
    if (!open) return;
    getGoLanSettings()
      .then((s) => {
        setLoaded(s);
        setForm(applyGoLanLoaded(s));
        setGoLanSettings(s);
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
        setPasteHint(
          "已识别到服务器地址，但配置里没找到 PrivateKey = 行，请确认完整复制了 [Interface] 段",
        );
      }
      if (!opts?.silent) {
        toast.success("已自动识别并填入 WireGuard 配置，请确认家里局域网段后点击保存");
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
      setPasteHint("请先将 WireGuard 配置文本长按粘贴到上方输入框中");
      return;
    }
    if (!recognizeFromText(text)) {
      setPasteHint("未识别到 WireGuard [Interface]/[Peer] 配置，请检查格式");
    }
  };

  const handleSyncManaged = async () => {
    setSyncing(true);
    try {
      const s = await syncGoLanManaged();
      setLoaded(s);
      setForm(applyGoLanLoaded(s));
      setGoLanSettings(s);
      toast.success(t("goLan.syncSuccess") || "已拉取家庭节点配置");
    } catch (e) {
      toast.error(String(e));
    } finally {
      setSyncing(false);
    }
  };

  // 【APP6 任务2.3】内网连通性检测：经 go-lan-home 隧道三路并发穿透探测；
  // 结果就地展示在输入框正下方（无需顶部 Toast 遮挡页面）
  const handleProbe = async () => {
    const target = probeTarget.trim();
    if (!target) return;
    setProbing(true);
    setProbeOk(null);
    setProbeMsg(t("logs.probeRunning"));
    try {
      const r = await testGoLanIp(target);
      setProbeOk(r.reachable);
      setProbeMsg(r.message);
      if (r.reachable) toast.success(r.message);
    } catch (e) {
      setProbeOk(false);
      setProbeMsg(String(e));
    } finally {
      setProbing(false);
    }
  };

  const handleSave = async () => {
    // 必填校验
    if (form.mode === "manual" && form.method === "wg") {
      if (!form.wgServer.trim()) return toast.error("请填写服务器地址");
      if (!form.wgPrivateKey.trim()) return toast.error("请填写客户端私钥");
      if (!form.wgPeerPublicKey.trim()) return toast.error("请填写服务端公钥");
    }
    if (form.mode === "manual" && form.method === "uri") {
      if (!form.nodeUri.trim()) return toast.error("请粘贴回家节点分享链接");
    }
    if (!form.lanCidrs.trim()) return toast.error("请填写回家内网网段（如 10.195.0.0/24）");

    setBusy(true);
    try {
      const base: GoLanSettings = loaded ?? ({} as GoLanSettings);
      // 【APP21 任务3.1】保存时完整保留「本机虚拟地址」里的全部地址
      // （英文逗号连接，严禁只取第 1 个）；每个地址的 /24 网段并入回家网段。
      const localAddr = splitLocalAddresses(form.wgLocalIp);
      const wgAnyFilled = [
        form.wgServer,
        form.wgPrivateKey,
        form.wgPeerPublicKey,
        form.wgPreSharedKey,
      ].some((v) => v.trim() !== "");
      const wgConfig: WgManualConfig | null =
        form.mode === "manual" && form.method === "wg" && wgAnyFilled
          ? {
              server: cleanInput(form.wgServer),
              serverPort: form.wgServerPort || 51820,
              privateKey: cleanInput(form.wgPrivateKey),
              peerPublicKey: cleanInput(form.wgPeerPublicKey),
              preSharedKey: cleanInput(form.wgPreSharedKey) || null,
              localIp:
                localAddr.addresses.join(", ") || WG_DEFAULTS.localIp,
              // 前端 UI 保留用户配置值（如 1420）；后端严禁压到 1280，
              // 低于 1420 的值会被钳制回 1420（匹配家庭 WG 服务端）
              mtu: form.wgMtu || WG_DEFAULTS.mtu,
            }
          : null;
      // 【IPA9 任务4.1】lanCidrs 解析：先按 /[\r\n,;，；\s]+/ 拆分（支持
      // 换行、逗号、分号、空格混输），再对每个子串 cleanInput。严禁在
      // split 之前整体 .replace(/\s/g,"")，否则会把两行拼成
      // "10.1.8.0/24192.168.10.0/24" 导致第二行网段丢失。
      const splitCidrs = (raw: string) =>
        raw
          .split(/[\r\n,;，；\s]+/)
          .map((l) => cleanInput(l))
          .filter(Boolean);
      const payload: GoLanSettings = {
        ...base,
        enabled: form.enabled,
        mode: form.mode,
        nodeUri: cleanInput(form.nodeUri),
        wgConfig,
        // 【APP15 任务1.1】Local Address 拆分出的附加地址 /24 一并并入回家网段
        lanCidrs: Array.from(
          new Set([...splitCidrs(form.lanCidrs), ...localAddr.cidrs]),
        ),
        lanDns: cleanInput(form.lanDns) || null,
        lanDomains: splitCidrs(form.lanDomains),
        managedServer: cleanInput(form.managedServer) || MANAGED_SERVER_DEFAULT,
        deviceCode: cleanInput(form.deviceCode),
      };
      // 【IPA9 任务2】Promise.race 2500ms 超时保底：saveGoLanSettings 后端
      // 已改为后台异步重启，这里再兜底一层，确保 saving 状态最多 2.5s
      // 就释放，绝不让弹窗卡死。
      const warnings = await Promise.race([
        saveGoLanSettings(payload),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("保存超时，请稍后重试")), 2500),
        ),
      ]);
      // 回读最新设置到全局 store（含 enabled 状态）
      const fresh = await getGoLanSettings();
      setGoLanSettings(fresh);
      if (warnings && warnings.length > 0) {
        toast.error(warnings[0]);
      } else {
        toast.success(t("goLan.saved") || "Go Lan 配置已保存");
      }
      onClose();
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
      onClick={onClose}
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
            <h3 className="text-sm font-semibold">Go Lan · 回家内网配置</h3>
          </div>
          {/* 【IPA9 任务2】× 关闭按钮永不禁用：任何时候点击都立即关闭弹窗 */}
          <button
            onClick={onClose}
            className="rounded p-1 text-gray-400 hover:bg-surface-hover hover:text-gray-200"
            aria-label="关闭"
          >
            <X size={16} />
          </button>
        </div>

        {/* 可滚动表单区 */}
        <div className="flex-1 space-y-2.5 overflow-y-auto px-4 py-3">

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
              {m === "manual" ? "手动配置 (WireGuard)" : "托管模式 (Managed)"}
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
                📋 粘贴配置文本 / 链接一键识别
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
                placeholder="粘贴 [Interface] ... [Peer] ... 全文到此处，松开即刻自动识别填入"
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
                回家内网网段（LAN CIDRs）
              </span>
              <textarea
                value={form.lanCidrs}
                onChange={(e) => patch({ lanCidrs: e.target.value })}
                placeholder="如 10.195.0.0/24, 192.168.1.0/24"
                rows={2}
                className="w-full resize-none rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 placeholder-gray-600 focus:border-accent focus:outline-none"
              />
            </label>

            {/* 服务器地址 + 端口 */}
            <div className="grid grid-cols-4 gap-2">
              <label className="col-span-3 block">
                <span className="mb-1 block text-xs text-gray-400">
                  服务器地址（Endpoint Host）
                </span>
                <input
                  value={form.wgServer}
                  onChange={(e) => patch({ wgServer: e.target.value })}
                  placeholder="ishow.indevs.in"
                  className="w-full rounded-md border border-border bg-surface px-2 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:border-accent focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs text-gray-400">端口</span>
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
                  本机虚拟地址（Local Address）
                </span>
                <input
                  value={form.wgLocalIp}
                  onChange={(e) => patch({ wgLocalIp: e.target.value })}
                  placeholder="10.195.0.2/32"
                  className="w-full rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 placeholder-gray-600 focus:border-accent focus:outline-none"
                />
                <span className="mt-1 block text-[10px] leading-4 text-gray-500">
                  支持逗号分隔多个地址：第 1 个写入隧道，其余自动转为 /24 并入回家网段
                </span>
              </label>
              <label className="block">
                <span className="mb-1 block text-xs text-gray-400">MTU</span>
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
                客户端私钥（PrivateKey）
                <button
                  type="button"
                  onClick={() => setShowPrivKey((v) => !v)}
                  className="rounded px-1 text-[11px] text-accent hover:underline"
                >
                  {showPrivKey ? "隐藏" : "显示"}
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
                服务端公钥（Peer PublicKey）
              </span>
              <input
                value={form.wgPeerPublicKey}
                onChange={(e) => patch({ wgPeerPublicKey: e.target.value })}
                className="w-full rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 focus:border-accent focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                预共享密钥（PresharedKey，选填）
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
                托管服务器
              </span>
              <input
                value={form.managedServer}
                onChange={(e) => patch({ managedServer: e.target.value })}
                className="w-full rounded-md border border-border bg-surface px-2 py-1.5 text-xs text-gray-200 focus:border-accent focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                设备识别码
              </span>
              <input
                value={form.deviceCode}
                onChange={(e) => patch({ deviceCode: e.target.value })}
                className="w-full rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 focus:border-accent focus:outline-none"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                回家内网网段（LAN CIDRs）
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
              {syncing ? "拉取中..." : "立即拉取家庭节点配置"}
            </button>
          </>
        )}

        {/* 启用开关 */}
        <div className="flex items-center justify-between rounded-lg border border-border bg-surface px-3 py-2">
          <span className="text-xs text-gray-300">启用 Go Lan</span>
          <Switch
            checked={form.enabled}
            onChange={(v) => patch({ enabled: v })}
          />
        </div>

        {/* 【APP6 任务2.3】内网连通性检测：默认目标=推导网关，结果与延迟
            就地展示，检测过程实时写入下方 Go Lan 日志面板 */}
        <div className="rounded-lg border border-border bg-surface px-3 py-2">
          <span className="mb-1.5 block text-xs text-gray-400">
            内网连通性检测
          </span>
          <div className="flex gap-2">
            <input
              value={probeTarget}
              onChange={(e) => setProbeTarget(e.target.value)}
              placeholder="如 10.1.8.1 或 192.168.1.1"
              className="min-w-0 flex-1 rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-xs text-gray-200 focus:border-accent focus:outline-none"
            />
            <button
              onClick={handleProbe}
              disabled={probing || !probeTarget.trim()}
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
            onClick={onClose}
            className="flex-1 rounded-md border border-border bg-surface px-3 py-2 text-xs font-medium text-gray-300 transition-colors hover:bg-surface-hover"
          >
            取消
          </button>
          <button
            onClick={handleSave}
            disabled={busy}
            className="flex-1 rounded-md bg-accent px-3 py-2 text-xs font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
          >
            {busy ? "保存中..." : "保存配置"}
          </button>
        </div>
      </div>
    </div>
  );
}
