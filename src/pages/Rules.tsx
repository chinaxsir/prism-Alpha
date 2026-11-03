import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Crosshair, Pencil, Plus, RefreshCw, Search, Trash2, X } from "lucide-react";

import {
  getCustomRules,
  getProxyGroups,
  getRules,
  saveCustomRules,
} from "@/api/ipc";
import ProGate from "@/components/ProGate";
import RuleTargetPicker from "@/components/RuleTargetPicker";
import Spinner from "@/components/ui/Spinner";
import { toast } from "@/components/ui/Toast";
import { useTranslation } from "@/i18n";
import { Feature } from "@/pro/gating";
import { extractRootDomain } from "@/utils/domain";
import { ruleTypeClass } from "@/utils/ruleType";

// 兼容旧引用（Connections / 其他地方从本页导入根域提取）
export { extractRootDomain } from "@/utils/domain";

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
  // 【APP42 任务4.2】策略选择器弹窗：点击行末编辑图标或双击行打开
  const [pickerIndex, setPickerIndex] = useState<number | null>(null);
  const [pickerQuery, setPickerQuery] = useState("");
  // 【APP43 任务3】从连接 / 分析页选择域名或 IP 批量生成规则
  const [targetPickerOpen, setTargetPickerOpen] = useState(false);
  const payloadRef = useRef<HTMLInputElement>(null);
  // 防重入：刷新按钮 / 保存后自动刷新 / 首次加载可能并发，避免重复 IPC
  const loadingRef = useRef(false);

  const filteredPolicies = useMemo(() => {
    const q = pickerQuery.trim().toLowerCase();
    if (!q) return policyOptions;
    return policyOptions.filter((p) => p.toLowerCase().includes(q));
  }, [policyOptions, pickerQuery]);

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
    if (loadingRef.current) return;
    loadingRef.current = true;
    setLoading(true);
    try {
      const resp = (await getRules()) as { rules?: Rule[] };
      setRules(resp.rules ?? []);
    } catch (e) {
      console.error("load rules failed:", e);
    } finally {
      loadingRef.current = false;
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
    let p = payload.trim();
    if (!p) {
      toast.error(t("proxies.rules.err.emptyPayload"));
      return;
    }
    // 【APP42 任务4.2】域名类规则自动提取根域名：
    // 用户粘贴 https://www.example.com/path 或 a.b.example.com 时，
    // 统一落成 example.com，避免同一站点被拆成多条子域规则
    if (kind === "DOMAIN" || kind === "DOMAIN-SUFFIX") {
      p = extractRootDomain(p);
    }
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

  /// 弹窗内选择策略：替换当前行的第 3 段并整体保存
  const applyPolicy = (nextPolicy: string) => {
    if (pickerIndex == null) return;
    const line = custom[pickerIndex];
    const parts = line.split(",").map((s) => s.trim());
    const next = `${parts[0]},${parts[1]},${nextPolicy}`;
    setPickerIndex(null);
    setPickerQuery("");
    if (next === line) return;
    persist(custom.map((l, i) => (i === pickerIndex ? next : l)));
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

  /// 【APP43 任务3】目标选择器确认：批量合并去重后整体保存
  const handleTargetConfirm = (lines: string[]) => {
    setTargetPickerOpen(false);
    const merged = [...custom];
    let added = 0;
    for (const line of lines) {
      if (!merged.includes(line)) {
        merged.push(line);
        added += 1;
      }
    }
    if (added === 0) {
      toast.error(t("proxies.rules.err.exists"));
      return;
    }
    persist(merged);
  };

  return (
    <div className="space-y-6">
      <ProGate feature={Feature.Rules}>
        {/* 自定义规则编辑器：标题 + 操作按钮同一行，按钮不再与标题/DOM 重叠 */}
        <div className="bg-surface-card rounded-xl p-5 mb-6">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <h2 className="text-base font-semibold leading-tight">
              {t("proxies.rules.customTitle", { count: custom.length })}
            </h2>
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setTargetPickerOpen(true)}
                className="flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-border bg-surface-hover px-3 py-1.5 text-xs text-gray-300 hover:border-accent/50 hover:text-gray-100"
              >
                <Crosshair size={13} className="text-accent" />
                {t("proxies.rules.pickTarget")}
              </button>
              <button
                type="button"
                onClick={() => payloadRef.current?.focus()}
                className="flex items-center gap-1.5 whitespace-nowrap rounded-lg bg-accent px-3 py-1.5 text-xs text-white hover:bg-accent-hover"
              >
                <Plus size={13} />
                {t("proxies.rules.manualAdd")}
              </button>
            </div>
          </div>
          <p className="mb-4 mt-1.5 text-xs text-gray-500">
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
              ref={payloadRef}
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAdd()}
              placeholder={t("proxies.rules.payloadPlaceholder")}
              className="min-w-0 flex-1 rounded-lg bg-surface-hover border border-border px-3 py-2 text-sm outline-none focus:border-accent"
            />
            <input
              value={policy}
              onChange={(e) => setPolicy(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleAdd()}
              list="rule-policy-options"
              placeholder={t("proxies.rules.policyPlaceholder")}
              className="min-w-0 rounded-lg bg-surface-hover border border-border px-3 py-2 text-sm outline-none focus:border-accent md:w-56"
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
          {(kind === "DOMAIN" || kind === "DOMAIN-SUFFIX") && (
            <p className="text-[11px] text-gray-500 -mt-1">
              {t("proxies.rules.rootHint")}
            </p>
          )}

          {custom.length > 0 && (
            <div className="mt-4 space-y-1.5 max-h-72 overflow-y-auto pr-1">
              {custom.map((line, index) => {
                const parts = line.split(",").map((s) => s.trim());
                return (
                  <div
                    key={`${line}-${index}`}
                    onDoubleClick={() => {
                      setPickerIndex(index);
                      setPickerQuery("");
                    }}
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
                    {/* 【APP42 任务4.2】点击策略徽章弹出策略选择器 */}
                    <button
                      onClick={() => {
                        setPickerIndex(index);
                        setPickerQuery("");
                      }}
                      className="flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] text-accent hover:bg-surface-card"
                      title={t("proxies.rules.pickPolicy")}
                    >
                      → {parts[2] ?? "direct"}
                      <Pencil size={10} />
                    </button>
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

      {/* 【APP43 任务3】从连接 / 分析页选择域名或 IP → 批量生成规则 */}
      <RuleTargetPicker
        open={targetPickerOpen}
        onClose={() => setTargetPickerOpen(false)}
        onConfirm={handleTargetConfirm}
      />

      {/* 【APP42 任务4.2】策略选择器：搜索过滤 + 一键应用 */}
      {pickerIndex != null && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          onClick={() => {
            setPickerIndex(null);
            setPickerQuery("");
          }}
        >
          <div
            className="flex max-h-[70vh] w-full max-w-sm flex-col rounded-xl border border-border bg-surface-card p-4 shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold">
                {t("proxies.rules.pickPolicy")}
                <span className="ml-2 font-mono text-[11px] text-gray-500">
                  {custom[pickerIndex]?.split(",")[1]}
                </span>
              </h3>
              <button
                onClick={() => {
                  setPickerIndex(null);
                  setPickerQuery("");
                }}
                className="rounded p-1 text-gray-400 hover:text-gray-100"
              >
                <X size={15} />
              </button>
            </div>
            <div className="mb-2 flex items-center gap-2 rounded-lg border border-border bg-surface-hover px-3 py-1.5">
              <Search size={13} className="text-gray-500" />
              <input
                autoFocus
                value={pickerQuery}
                onChange={(e) => setPickerQuery(e.target.value)}
                placeholder={t("proxies.rules.searchPolicy")}
                className="flex-1 bg-transparent text-sm outline-none"
              />
            </div>
            <div className="min-h-0 flex-1 space-y-1 overflow-y-auto pr-1">
              {filteredPolicies.length === 0 ? (
                <p className="py-6 text-center text-xs text-gray-500">
                  {t("proxies.rules.noPolicy")}
                </p>
              ) : (
                filteredPolicies.map((p) => (
                  <button
                    key={p}
                    onClick={() => applyPolicy(p)}
                    className={`flex w-full items-center justify-between rounded-lg px-3 py-2 text-left text-xs transition-colors hover:bg-surface-hover ${
                      p === custom[pickerIndex]?.split(",")[2]?.trim()
                        ? "text-accent"
                        : "text-gray-300"
                    }`}
                  >
                    <span className="truncate font-mono">{p}</span>
                    {p === custom[pickerIndex]?.split(",")[2]?.trim() && (
                      <span className="text-[11px]">{t("proxies.rules.currentPolicy")}</span>
                    )}
                  </button>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
