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

const WG_DEFAULTS = { localIp: "10.0.0.2/24", mtu: 1280 };
const MANAGED_SERVER_DEFAULT = "https://prism.sarl";

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

const WG_KNOWN_KEYS =
  /^(PrivateKey|Address|DNS|MTU|ListenPort|Table|PublicKey|PresharedKey|PreSharedKey|AllowedIPs|Endpoint|PersistentKeepalive)\s*=/i;

/** 【APP-4 任务4】解析 WireGuard .conf 全文为 GoLanForm 片段
 *
 * 折行合并解析算法：同时兼容 wg-easy 标准配置与微信跨行折行配置——
 * 只有以标准 WG 关键字开头的行才开启新字段，其余非注释/非节名行自动
 * 拼接到上一字段末尾（PrivateKey =\noJms...\nkJj...= 场景）。
 *
 * 自动提取：
 * - [Interface] PrivateKey/Address/MTU（MTU > 1380 默认 1280）
 * - [Peer] PublicKey/PresharedKey/Endpoint（按最后一个 : 拆分 host/port）
 * - 从 Address 推导 /24 内网网段（10.1.8.2/24 → 10.1.8.0/24）+
 *   AllowedIPs 中非默认网段，一并填入「回家内网网段」
 * - 识别成功后自动开启「启用 Go Lan」开关
 */
function parseWgConf(text: string): Partial<GoLanForm> | null {
  const cleaned = text.replace(INVISIBLE_ONLY, "");
  if (!/\[interface\]/i.test(cleaned)) return null;

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
      // 微信折行续行：无缝拼接到上一字段末尾
      entries[entries.length - 1].value += line.replace(/\s+/g, "");
    }
  }

  const get = (sec: string, key: string) =>
    entries.find((e) => e.section === sec && e.key === key)?.value;

  const out: Partial<GoLanForm> = {};
  const priv = get("interface", "privatekey");
  if (priv) out.wgPrivateKey = priv;
  const addr = get("interface", "address");
  if (addr) out.wgLocalIp = addr.split(",")[0].trim();
  const mtuRaw = get("interface", "mtu");
  if (mtuRaw) {
    const n = parseInt(mtuRaw, 10);
    if (!isNaN(n) && n > 0) out.wgMtu = n > 1380 ? WG_DEFAULTS.mtu : n;
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
  // 回家内网网段：Address 所在 /24 + AllowedIPs 非默认网段
  const cidrs = new Set<string>();
  if (out.wgLocalIp) {
    const parts = out.wgLocalIp.split("/")[0].split(".");
    if (parts.length === 4) cidrs.add(`${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
  }
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
              localIp: cleanInput(form.wgLocalIp) || WG_DEFAULTS.localIp,
              mtu: form.wgMtu || WG_DEFAULTS.mtu,
            }
          : null;
      const payload: GoLanSettings = {
        ...base,
        enabled: form.enabled,
        mode: form.mode,
        nodeUri: cleanInput(form.nodeUri),
        wgConfig,
        lanCidrs: form.lanCidrs
          .split("\n")
          .map((l) => cleanInput(l))
          .filter(Boolean),
        lanDns: cleanInput(form.lanDns) || null,
        lanDomains: form.lanDomains
          .split("\n")
          .map((l) => cleanInput(l))
          .filter(Boolean),
        managedServer: cleanInput(form.managedServer) || MANAGED_SERVER_DEFAULT,
        deviceCode: cleanInput(form.deviceCode),
      };
      const warnings = await saveGoLanSettings(payload);
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
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
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
              </label>
              <label className="block">
                <span className="mb-1 block text-xs text-gray-400">MTU</span>
                <input
                  type="number"
                  value={form.wgMtu || ""}
                  onChange={(e) =>
                    patch({ wgMtu: parseInt(e.target.value, 10) || 0 })
                  }
                  placeholder="1280"
                  className="w-full rounded-md border border-border bg-surface px-2 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:border-accent focus:outline-none"
                />
              </label>
            </div>

            {/* 私钥 / 公钥 / PSK */}
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                客户端私钥（PrivateKey）
              </span>
              <input
                type="password"
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
        </div>

        {/* 底部操作栏（固定，永不被屏幕底部截断） */}
        <div className="flex shrink-0 gap-2 border-t border-border bg-surface px-4 py-3">
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
