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

/** 解析 WireGuard .conf 全文为 GoLanForm 片段
 *
 * 识别 [Interface] 的 PrivateKey/Address/MTU 与 [Peer] 的
 * PublicKey/PresharedKey/Endpoint/AllowedIPs，自动填充所有字段。
 * 同时剔除所有零宽隐形字符。
 */
function parseWgConf(text: string): Partial<GoLanForm> | null {
  const cleaned = cleanInput(text);
  if (!cleaned.includes("[Interface]") && !cleaned.startsWith("wireguard://")) {
    return null;
  }
  const out: Partial<GoLanForm> = {};
  const lines = cleaned.split(/\r?\n/);
  let section = "";
  let endpointHost = "";
  let endpointPort = 0;
  const allowedIps: string[] = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line.slice(1, -1).toLowerCase();
      continue;
    }
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim().toLowerCase();
    const val = line.slice(eq + 1).trim();
    if (section === "interface") {
      if (key === "privatekey") out.wgPrivateKey = val;
      else if (key === "address") out.wgLocalIp = val.split(",")[0].trim();
      else if (key === "mtu") {
        const n = parseInt(val, 10);
        if (!isNaN(n) && n > 0) out.wgMtu = n;
      }
    } else if (section === "peer") {
      if (key === "publickey") out.wgPeerPublicKey = val;
      else if (key === "presharedkey") out.wgPreSharedKey = val;
      else if (key === "endpoint") {
        const idx = val.lastIndexOf(":");
        if (idx > 0) {
          endpointHost = val.slice(0, idx).replace(/^\[|\]$/g, "");
          endpointPort = parseInt(val.slice(idx + 1), 10) || 51820;
        }
      } else if (key === "allowedips") {
        for (const cidr of val.split(",")) {
          const t = cidr.trim();
          if (t && t !== "0.0.0.0/0" && t !== "::/0") allowedIps.push(t);
        }
      }
    }
  }
  if (endpointHost) {
    out.wgServer = endpointHost;
    out.wgServerPort = endpointPort || 51820;
  }
  // AllowedIPs + Address 所在 /24 网段并入回家内网网段
  const cidrs = new Set<string>(allowedIps);
  if (out.wgLocalIp) {
    const ipPart = out.wgLocalIp.split("/")[0];
    const parts = ipPart.split(".");
    if (parts.length === 4) {
      cidrs.add(`${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
    }
  }
  if (cidrs.size > 0) {
    out.lanCidrs = Array.from(cidrs).join("\n");
  }
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

  /** 一键粘贴 .conf 自动识别 */
  const handlePasteRecognize = async () => {
    let text = pasteBuf;
    if (!text) {
      try {
        text = await navigator.clipboard.readText();
      } catch {
        toast.error(t("common.pasteFailed") || "读取剪贴板失败，请手动粘贴到下方文本框");
        return;
      }
    }
    const parsed = parseWgConf(text);
    if (!parsed) {
      toast.error("未识别到 WireGuard [Interface]/[Peer] 配置，请检查格式");
      return;
    }
    patch(parsed);
    setPasteBuf("");
    toast.success("已自动识别并填入 WireGuard 配置，请确认家里局域网段后点击保存");
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
      <div
        className="max-h-[90vh] w-full max-w-md space-y-4 overflow-y-auto rounded-xl bg-surface-card p-5"
        onClick={(e) => e.stopPropagation()}
      >
        {/* 标题栏 */}
        <div className="flex items-center justify-between">
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
                onChange={(e) => setPasteBuf(e.target.value)}
                placeholder="或手动粘贴 [Interface] ... [Peer] ... 全文到此处，再点上方按钮"
                rows={3}
                className="mt-2 w-full resize-none rounded-md border border-border bg-surface px-2 py-1.5 font-mono text-[11px] text-gray-300 placeholder-gray-600 focus:border-accent focus:outline-none"
              />
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

        {/* 底部按钮 */}
        <div className="flex gap-2 pt-2">
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
