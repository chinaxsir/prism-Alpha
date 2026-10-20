import { useEffect, useState } from "react";
import { ArrowDown, ArrowUp, Plus, RefreshCw, Trash2 } from "lucide-react";

import {
  getCustomRules,
  getProxyGroups,
  getRules,
  saveCustomRules,
} from "@/api/ipc";
import ProGate from "@/components/ProGate";
import Spinner from "@/components/ui/Spinner";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";
import { Feature } from "@/pro/gating";
import { ruleTypeClass } from "@/utils/ruleType";

interface Rule {
  type: string;
  payload: string;
  proxy?: string;
  outbound?: string;
}

const RULE_TYPES = [
  "DOMAIN",
  "DOMAIN-SUFFIX",
  "DOMAIN-KEYWORD",
  "IP-CIDR",
  "GEOIP",
  "GEOSITE",
];

export default function Rules() {
  const { t } = useTranslation();
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(false);

  // 自定义规则编辑器状态
  const [custom, setCustom] = useState<string[]>([]);
  const [kind, setKind] = useState("DOMAIN-SUFFIX");
  const [payload, setPayload] = useState("");
  const [policy, setPolicy] = useState("");
  const [saving, setSaving] = useState(false);
  const [policyOptions, setPolicyOptions] = useState<string[]>([
    "direct",
    "block",
  ]);

  useEffect(() => {
    loadRules();
    getCustomRules()
      .then((r) => setCustom(r ?? []))
      .catch((e) => console.error("load custom rules failed:", e));
    // 策略候选：内置 + 内核全部出站（内核未启动时仅内置项）
    getProxyGroups()
      .then((resp) => {
        const map =
          (resp as { proxies?: Record<string, { name: string }> }).proxies ??
          {};
        const names = Object.values(map)
          .map((p) => p.name)
          .filter((n) => n && n !== "GLOBAL");
        setPolicyOptions(["direct", "block", ...names]);
      })
      .catch(() => undefined);
  }, []);

  const loadRules = async () => {
    setLoading(true);
    try {
      const resp = (await getRules()) as { rules?: Rule[] };
      setRules(resp.rules ?? []);
    } catch (e) {
      console.error("load rules failed:", e);
    } finally {
      setLoading(false);
    }
  };

  /// 每次修改即整体保存；内核运行中后端自动重启生效
  const persist = async (next: string[]) => {
    if (saving) return;
    setSaving(true);
    try {
      await saveCustomRules(next);
      setCustom(next);
      toast.success(t("proxies.rules.saved"));
      loadRules();
    } catch (e) {
      console.error("save custom rules failed:", e);
      toast.error(String(e));
    } finally {
      setSaving(false);
    }
  };

  const handleAdd = () => {
    const p = payload.trim();
    if (!p) {
      toast.error(t("proxies.rules.err.emptyPayload"));
      return;
    }
    const line = `${kind},${p},${policy.trim() || "direct"}`;
    if (custom.includes(line)) {
      toast.error(t("proxies.rules.err.exists"));
      return;
    }
    setPayload("");
    persist([...custom, line]);
  };

  const move = (index: number, delta: number) => {
    const target = index + delta;
    if (target < 0 || target >= custom.length) return;
    const next = [...custom];
    [next[index], next[target]] = [next[target], next[index]];
    persist(next);
  };

  const removeAt = (index: number) =>
    persist(custom.filter((_, i) => i !== index));

  return (
    <div className="space-y-6">
      <ProGate feature={Feature.Rules}>
        {/* 自定义规则编辑器 */}
        <div className="bg-surface-card rounded-xl p-5 mb-6">
          <h2 className="text-base font-semibold mb-1">
            {t("proxies.rules.customTitle", { count: custom.length })}
          </h2>
          <p className="text-xs text-gray-500 mb-4">
            {t("proxies.rules.customDesc")}
          </p>

          <div className="flex flex-col gap-2 md:flex-row">
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value)}
              className="rounded-lg bg-surface-hover border border-border px-3 py-2 text-sm outline-none focus:border-accent"
            >
              {RULE_TYPES.map((rt) => (
                <option key={rt} value={rt}>
                  {rt}
                </option>
              ))}
            </select>
            <input
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAdd()}
              placeholder={t("proxies.rules.payloadPlaceholder")}
              className="flex-1 rounded-lg bg-surface-hover border border-border px-3 py-2 text-sm outline-none focus:border-accent"
            />
            <input
              value={policy}
              onChange={(e) => setPolicy(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAdd()}
              list="rule-policy-options"
              placeholder={t("proxies.rules.policyPlaceholder")}
              className="md:w-56 rounded-lg bg-surface-hover border border-border px-3 py-2 text-sm outline-none focus:border-accent"
            />
            <datalist id="rule-policy-options">
              {policyOptions.map((n) => (
                <option key={n} value={n} />
              ))}
            </datalist>
            <button
              onClick={handleAdd}
              disabled={saving}
              className="flex items-center justify-center gap-1.5 rounded-lg bg-accent px-4 py-2 text-sm hover:bg-accent-hover disabled:opacity-50"
            >
              <Plus size={15} />
              {t("proxies.rules.add")}
            </button>
          </div>
          <p className="text-[11px] text-gray-500 -mt-1">
            {t("proxies.rules.policyHint")}
          </p>

          {custom.length > 0 && (
            <div className="mt-4 space-y-1.5 max-h-72 overflow-y-auto pr-1">
              {custom.map((line, index) => {
                const parts = line.split(",").map((s) => s.trim());
                return (
                  <div
                    key={`${line}-${index}`}
                    className="flex items-center gap-3 p-2.5 rounded-lg bg-surface-hover"
                  >
                    <span className="w-6 text-right text-[11px] text-gray-600 font-mono">
                      {index + 1}
                    </span>
                    <span
                      className={`w-32 text-[11px] font-mono ${ruleTypeClass(
                        parts[0] ?? ""
                      )}`}
                    >
                      {parts[0]}
                    </span>
                    <span className="flex-1 text-xs font-mono truncate">
                      {parts[1] ?? ""}
                    </span>
                    <span className="text-[11px] text-accent">
                      → {parts[2] ?? "direct"}
                    </span>
                    <button
                      onClick={() => move(index, -1)}
                      disabled={saving || index === 0}
                      className="p-1 text-gray-500 hover:text-gray-200 disabled:opacity-30"
                    >
                      <ArrowUp size={13} />
                    </button>
                    <button
                      onClick={() => move(index, 1)}
                      disabled={saving || index === custom.length - 1}
                      className="p-1 text-gray-500 hover:text-gray-200 disabled:opacity-30"
                    >
                      <ArrowDown size={13} />
                    </button>
                    <button
                      onClick={() => removeAt(index)}
                      disabled={saving}
                      className="p-1 text-gray-500 hover:text-latency-bad disabled:opacity-30"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* 内核生效规则（只读） */}
        <div className="bg-surface-card rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold">
              {t("proxies.rules.effectiveTitle", { count: rules.length })}
            </h2>
            <button
              onClick={loadRules}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-hover text-xs text-gray-400 hover:text-gray-200"
            >
              <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
              {t("common.refresh")}
            </button>
          </div>

          {loading && rules.length === 0 ? (
            <div className="flex justify-center py-8">
              <Spinner />
            </div>
          ) : rules.length === 0 ? (
            <p className="text-gray-500 text-sm py-8 text-center">
              {t("proxies.rules.empty")}
            </p>
          ) : (
            <div className="space-y-1.5 max-h-[28rem] overflow-y-auto pr-1">
              {rules.map((rule, index) => (
                <div
                  key={`${rule.type}-${rule.payload}-${index}`}
                  className="flex items-center gap-3 p-2.5 rounded-lg bg-surface-hover"
                >
                  <span className="w-8 text-right text-[11px] text-gray-600 font-mono">
                    {index + 1}
                  </span>
                  <span
                    className={`w-32 text-[11px] font-mono ${ruleTypeClass(
                      rule.type
                    )}`}
                  >
                    {rule.type}
                  </span>
                  <span className="flex-1 text-xs font-mono truncate">
                    {rule.payload}
                  </span>
                  <span className="text-[11px] text-accent">
                    → {rule.proxy ?? rule.outbound ?? "—"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </ProGate>
    </div>
  );
}
