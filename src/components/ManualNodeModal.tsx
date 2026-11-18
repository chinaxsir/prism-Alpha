import { useEffect, useMemo, useState } from "react";
import { ClipboardPaste, Plus, SlidersHorizontal, X } from "lucide-react";

import {
  addManualNodeStruct,
  importQrOrTextPayload,
  type ImportOutcome,
  type ManualNodeInput,
} from "@/api/ipc";
import Spinner from "@/components/ui/Spinner";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";

interface Props {
  open: boolean;
  onClose: () => void;
  onImported: (outcome: ImportOutcome) => void;
}

type Tab = "form" | "paste";

const PROTOCOLS = [
  "ss",
  "vmess",
  "vless",
  "trojan",
  "hysteria2",
  "socks5",
  "http",
] as const;

const inputCls =
  "w-full rounded-lg border border-border bg-surface-hover px-3 py-2 text-sm outline-none focus:border-accent";

/**
 * 【ACP7 任务1.2】手动添加节点弹窗：
 * - 表单 Tab：可视化填写协议 / 地址 / 端口 / 凭据 / TLS / 传输层
 * - 粘贴 Tab：任意节点 URI / Clash YAML / Base64 文本
 * 两者最终都落到 `local://manual-nodes` 本地订阅。
 */
export default function ManualNodeModal({
  open,
  onClose,
  onImported,
}: Props) {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>("form");
  const [submitting, setSubmitting] = useState(false);
  const [protocol, setProtocol] = useState<string>("vmess");
  const [name, setName] = useState("");
  const [server, setServer] = useState("");
  const [port, setPort] = useState("443");
  const [password, setPassword] = useState("");
  const [uuid, setUuid] = useState("");
  const [cipher, setCipher] = useState("");
  const [alterId, setAlterId] = useState("0");
  const [tls, setTls] = useState(true);
  const [sni, setSni] = useState("");
  const [network, setNetwork] = useState("tcp");
  const [wsPath, setWsPath] = useState("/");
  const [wsHost, setWsHost] = useState("");
  const [skipCert, setSkipCert] = useState(false);
  const [pasteText, setPasteText] = useState("");

  // 每次打开重置（避免上次草稿串到下一次）
  useEffect(() => {
    if (!open) return;
    setTab("form");
    setSubmitting(false);
    setProtocol("vmess");
    setName("");
    setServer("");
    setPort("443");
    setPassword("");
    setUuid("");
    setCipher("");
    setAlterId("0");
    setTls(true);
    setSni("");
    setNetwork("tcp");
    setWsPath("/");
    setWsHost("");
    setSkipCert(false);
    setPasteText("");
  }, [open]);

  const needsUuid = protocol === "vmess" || protocol === "vless";
  const needsPassword = !needsUuid;
  const supportsTls = protocol !== "ss" && protocol !== "socks5";
  const supportsNetwork =
    protocol === "vmess" || protocol === "vless" || protocol === "trojan";
  const supportsSkipCert = protocol !== "ss" && protocol !== "socks5";
  const defaultCipher = useMemo(() => {
    if (protocol === "ss") return "aes-256-gcm";
    if (protocol === "vmess") return "auto";
    return "";
  }, [protocol]);

  const finish = (outcome: ImportOutcome) => {
    toast.success(
      t("sub.importSuccess", {
        count: outcome.nodeCount,
        total: outcome.total,
      }),
    );
    onImported(outcome);
    onClose();
  };

  const handleSubmitForm = async () => {
    const portNum = Number(port);
    if (!server.trim()) {
      toast.error(t("sub.manualServerRequired"));
      return;
    }
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      toast.error(t("sub.manualPortInvalid"));
      return;
    }
    const payload: ManualNodeInput = {
      name: name.trim(),
      protocol,
      server: server.trim(),
      port: portNum,
      password: needsPassword ? password.trim() || null : null,
      uuid: needsUuid ? uuid.trim() || null : null,
      cipher: (cipher.trim() || defaultCipher) || null,
      alterId: protocol === "vmess" ? Number(alterId) || 0 : null,
      tls: supportsTls ? tls : null,
      sni: sni.trim() || null,
      network: supportsNetwork ? network : null,
      wsPath: supportsNetwork && network === "ws" ? wsPath.trim() || "/" : null,
      wsHost: supportsNetwork && network === "ws" ? wsHost.trim() || null : null,
      skipCertVerify: supportsSkipCert ? skipCert : null,
    };
    setSubmitting(true);
    try {
      finish(await addManualNodeStruct(payload));
    } catch (e) {
      console.error("add manual node failed:", e);
      toast.error(t("sub.importFailed", { error: String(e) }));
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmitPaste = async () => {
    const text = pasteText.trim();
    if (!text) {
      toast.error(t("sub.manualPasteRequired"));
      return;
    }
    setSubmitting(true);
    try {
      finish(await importQrOrTextPayload(text, name.trim() || null));
    } catch (e) {
      console.error("paste import failed:", e);
      toast.error(t("sub.importFailed", { error: String(e) }));
    } finally {
      setSubmitting(false);
    }
  };

  if (!open) return null;

  return (
    <div
      className="pointer-events-auto fixed inset-0 z-[999] flex touch-manipulation items-center justify-center bg-black/60 p-4 pb-[calc(env(safe-area-inset-bottom,16px)+16px)]"
      onClick={onClose}
    >
      <div
        className="flex max-h-[86vh] w-full max-w-md flex-col overflow-hidden rounded-2xl border border-border bg-surface"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex shrink-0 items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <Plus size={16} className="text-accent" />
            <h3 className="text-sm font-semibold">{t("sub.manualTitle")}</h3>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-gray-400 hover:bg-surface-hover hover:text-gray-200"
            aria-label={t("common.close")}
          >
            <X size={16} />
          </button>
        </div>

        {/* Tab 切换 */}
        <div className="flex shrink-0 gap-1 border-b border-border px-4 py-2">
          <button
            onClick={() => setTab("form")}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[12px] font-semibold transition-colors ${
              tab === "form"
                ? "bg-accent/15 text-accent"
                : "text-text-secondary hover:bg-surface-hover"
            }`}
          >
            <SlidersHorizontal size={13} />
            {t("sub.manualForm")}
          </button>
          <button
            onClick={() => setTab("paste")}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[12px] font-semibold transition-colors ${
              tab === "paste"
                ? "bg-accent/15 text-accent"
                : "text-text-secondary hover:bg-surface-hover"
            }`}
          >
            <ClipboardPaste size={13} />
            {t("sub.manualPaste")}
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-4">
          <p className="mb-3 text-[12px] text-text-secondary">
            {t("sub.manualDesc")}
          </p>

          {tab === "form" ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <label className="block">
                  <span className="mb-1 block text-[11px] text-text-secondary">
                    {t("sub.manualProtocol")}
                  </span>
                  <select
                    value={protocol}
                    onChange={(e) => {
                      setProtocol(e.target.value);
                      setCipher("");
                    }}
                    className={inputCls}
                  >
                    {PROTOCOLS.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-text-secondary">
                    {t("sub.manualName")}
                  </span>
                  <input
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    maxLength={40}
                    className={inputCls}
                    placeholder={t("sub.manualName")}
                  />
                </label>
              </div>

              <div className="grid grid-cols-[1fr_100px] gap-3">
                <label className="block">
                  <span className="mb-1 block text-[11px] text-text-secondary">
                    {t("sub.manualServer")}
                  </span>
                  <input
                    value={server}
                    onChange={(e) => setServer(e.target.value)}
                    className={inputCls}
                    placeholder="example.com"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                  />
                </label>
                <label className="block">
                  <span className="mb-1 block text-[11px] text-text-secondary">
                    {t("sub.manualPort")}
                  </span>
                  <input
                    value={port}
                    onChange={(e) => setPort(e.target.value.replace(/[^\d]/g, ""))}
                    inputMode="numeric"
                    className={inputCls}
                    placeholder="443"
                  />
                </label>
              </div>

              {needsUuid && (
                <label className="block">
                  <span className="mb-1 block text-[11px] text-text-secondary">
                    {t("sub.manualUuid")}
                  </span>
                  <input
                    value={uuid}
                    onChange={(e) => setUuid(e.target.value)}
                    className={inputCls}
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                  />
                </label>
              )}

              {needsPassword && (
                <label className="block">
                  <span className="mb-1 block text-[11px] text-text-secondary">
                    {t("sub.manualPassword")}
                  </span>
                  <input
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    type="password"
                    className={inputCls}
                    autoCapitalize="none"
                    autoCorrect="off"
                  />
                </label>
              )}

              {protocol === "vmess" && (
                <div className="grid grid-cols-2 gap-3">
                  <label className="block">
                    <span className="mb-1 block text-[11px] text-text-secondary">
                      {t("sub.manualCipher")}
                    </span>
                    <input
                      value={cipher}
                      onChange={(e) => setCipher(e.target.value)}
                      className={inputCls}
                      placeholder="auto"
                    />
                  </label>
                  <label className="block">
                    <span className="mb-1 block text-[11px] text-text-secondary">
                      {t("sub.manualAlterId")}
                    </span>
                    <input
                      value={alterId}
                      onChange={(e) =>
                        setAlterId(e.target.value.replace(/[^\d]/g, ""))
                      }
                      inputMode="numeric"
                      className={inputCls}
                    />
                  </label>
                </div>
              )}

              {protocol === "ss" && (
                <label className="block">
                  <span className="mb-1 block text-[11px] text-text-secondary">
                    {t("sub.manualCipher")}
                  </span>
                  <input
                    value={cipher}
                    onChange={(e) => setCipher(e.target.value)}
                    className={inputCls}
                    placeholder={defaultCipher}
                  />
                </label>
              )}

              {(supportsTls || supportsSkipCert) && (
                <div className="space-y-2">
                  {supportsTls && (
                    <label className="flex items-center justify-between rounded-lg bg-surface-hover px-3 py-2">
                      <span className="text-[12px] text-text">
                        {t("sub.manualTls")}
                      </span>
                      <input
                        type="checkbox"
                        checked={tls}
                        onChange={(e) => setTls(e.target.checked)}
                        className="h-4 w-4 accent-[#007AFF]"
                      />
                    </label>
                  )}
                  {supportsSkipCert && (
                    <label className="flex items-center justify-between rounded-lg bg-surface-hover px-3 py-2">
                      <span className="text-[12px] text-text">
                        {t("sub.manualSkipCert")}
                      </span>
                      <input
                        type="checkbox"
                        checked={skipCert}
                        onChange={(e) => setSkipCert(e.target.checked)}
                        className="h-4 w-4 accent-[#007AFF]"
                      />
                    </label>
                  )}
                </div>
              )}

              <label className="block">
                <span className="mb-1 block text-[11px] text-text-secondary">
                  {t("sub.manualSni")}
                </span>
                <input
                  value={sni}
                  onChange={(e) => setSni(e.target.value)}
                  className={inputCls}
                  placeholder="example.com"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                />
              </label>

              {supportsNetwork && (
                <div className="grid grid-cols-2 gap-3">
                  <label className="block">
                    <span className="mb-1 block text-[11px] text-text-secondary">
                      {t("sub.manualNetwork")}
                    </span>
                    <select
                      value={network}
                      onChange={(e) => setNetwork(e.target.value)}
                      className={inputCls}
                    >
                      <option value="tcp">tcp</option>
                      <option value="ws">ws</option>
                      <option value="grpc">grpc</option>
                    </select>
                  </label>
                  {network === "ws" && (
                    <label className="block">
                      <span className="mb-1 block text-[11px] text-text-secondary">
                        {t("sub.manualWsPath")}
                      </span>
                      <input
                        value={wsPath}
                        onChange={(e) => setWsPath(e.target.value)}
                        className={inputCls}
                        placeholder="/"
                      />
                    </label>
                  )}
                </div>
              )}

              {supportsNetwork && network === "ws" && (
                <label className="block">
                  <span className="mb-1 block text-[11px] text-text-secondary">
                    {t("sub.manualWsHost")}
                  </span>
                  <input
                    value={wsHost}
                    onChange={(e) => setWsHost(e.target.value)}
                    className={inputCls}
                    placeholder="example.com"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                  />
                </label>
              )}
            </div>
          ) : (
            <textarea
              value={pasteText}
              onChange={(e) => setPasteText(e.target.value)}
              placeholder={t("sub.manualPastePlaceholder")}
              className="h-56 w-full resize-none rounded-lg border border-border bg-surface-hover px-3 py-2 font-mono text-[12px] leading-relaxed outline-none focus:border-accent"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
          )}
        </div>

        <div className="shrink-0 border-t border-border p-4">
          <button
            onClick={() =>
              void (tab === "form" ? handleSubmitForm() : handleSubmitPaste())
            }
            disabled={submitting}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-[#007AFF] px-4 py-3 text-[14px] font-bold text-white transition-colors hover:bg-[#0066DD] disabled:opacity-50"
          >
            {submitting && <Spinner size={14} className="text-white" />}
            {submitting ? t("sub.manualSubmitting") : t("sub.manualSubmit")}
          </button>
        </div>
      </div>
    </div>
  );
}
