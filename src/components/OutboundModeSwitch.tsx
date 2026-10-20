import { useState } from "react";
import { Sliders, Globe, Power } from "lucide-react";
import clsx from "clsx";

import { setOutboundMode } from "@/api/ipc";
import { useCoreStore, type OutboundMode } from "@/stores/core";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";

const MODES: { key: OutboundMode; labelKey: string; Icon: typeof Globe }[] = [
  { key: "rule", labelKey: "outbound.rule", Icon: Sliders },
  { key: "global", labelKey: "outbound.global", Icon: Globe },
  { key: "direct", labelKey: "outbound.direct", Icon: Power },
];

/**
 * 出站模式快捷切换条（仪表盘 / 节点页共用）。
 * 当前模式来自 coreStore（get_core_status / core://status 填充），
 * 点击后乐观更新 UI，再调 set_outbound_mode；失败回滚并 toast 提示。
 */
export default function OutboundModeSwitch() {
  const { t } = useTranslation();
  const mode = useCoreStore((s) => s.outboundMode);
  const setStoreMode = useCoreStore((s) => s.setOutboundMode);
  const [busy, setBusy] = useState(false);

  const choose = async (key: OutboundMode) => {
    if (busy || key === mode) return;
    const prev = mode;
    setStoreMode(key); // 乐观更新
    setBusy(true);
    try {
      await setOutboundMode(key);
      toast.success(t("toast.outboundSwitched"));
    } catch (e) {
      setStoreMode(prev); // 失败回滚
      toast.error(t("toast.outboundFailed", { error: String(e) }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex rounded-lg border border-border bg-surface-hover p-1">
      {MODES.map(({ key, labelKey, Icon }) => (
        <button
          key={key}
          onClick={() => choose(key)}
          disabled={busy && key !== mode}
          className={clsx(
            "flex flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-60",
            mode === key
              ? "bg-accent text-white"
              : "text-gray-400 hover:bg-glass hover:text-gray-200"
          )}
        >
          <Icon size={13} />
          {t(labelKey)}
        </button>
      ))}
    </div>
  );
}
