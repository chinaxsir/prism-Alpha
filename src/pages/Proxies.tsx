import { useEffect, useMemo, useRef, useState } from "react";
import { Zap, Gauge, RefreshCw, ChevronRight, Search, Crosshair, Lock } from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import { Link } from "react-router-dom";

import {
  getCoreStatus,
  getProxyGroups,
  getCachedProxies,
  selectProxy,
  urlTest,
  getGoAimStatus,
  runGoAimProbe,
  type GoAimStatus,
} from "@/api/ipc";
import { useCoreStore } from "@/stores/core";
import { useProStore } from "@/stores/pro";
import { toast } from "@/components/ui/Toast";
import { delayClass, delayText, type Delay } from "@/utils/latency";
import { ActivateProModal } from "@/components/ProGate";
import { useTranslation } from "@/i18n";
import clsx from "clsx";

interface DelaySample {
  delay: number;
}

interface ProxyEntry {
  name: string;
  type: string;
  now?: string;
  all?: Array<ProxyEntry | string>;
  history?: DelaySample[];
  /// 订阅缓存预览用：服务器地址
  server?: string;
}

const GROUP_TYPES = ["Selector", "URLTest", "Fallback", "LoadBalance"];

const PROTOCOL_LABEL: Record<string, string> = {
  Vless: "VLESS",
  VMess: "VMess",
  Trojan: "Trojan",
  Hysteria: "HY",
  Hysteria2: "HY2",
  TUIC: "TUIC",
  Shadowsocks: "SS",
  ShadowsocksR: "SSR",
  WireGuard: "WG",
  Socks: "SOCKS",
  HTTP: "HTTP",
};

/// Go AIM 筛选 pills
type AimFilter = "all" | "aim" | "ai" | "media";
const AIM_FILTERS: Array<{ value: AimFilter; labelKey: string }> = [
  { value: "all", labelKey: "common.all" },
  { value: "aim", labelKey: "engine.goAim" },
  { value: "ai", labelKey: "proxies.aim.ai" },
  { value: "media", labelKey: "proxies.aim.media" },
];

/** Go AIM 平台细分徽章配色（APP 任务3，与指令 1:1 对齐） */
const AIM_BADGE_STYLE: Record<string, string> = {
  GPT: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  Claude: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  Gemini: "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
  NF: "bg-red-500/15 text-red-400 border-red-500/30",
  YT: "bg-rose-500/15 text-rose-400 border-rose-500/30",
  "Disney+": "bg-sky-500/15 text-sky-400 border-sky-500/30",
  TK: "bg-pink-500/15 text-pink-400 border-pink-500/30",
};

export default function Proxies() {
  const { t } = useTranslation();

  const protocolTag = (type: string): string => {
    if (type === "Direct") return t("proxies.proto.direct");
    if (type === "Block") return t("proxies.proto.block");
    return PROTOCOL_LABEL[type] ?? type ?? "—";
  };

  const coreStatus = useCoreStore((s) => s.status);
  // Go AIM 智能筛选/检测的 Pro 守卫（ipa-9）：未激活时锁定筛选与探测入口
  const proReady = useProStore((s) => s.ready);
  const proUnlocked = useProStore((s) => s.unlocked);
  const [showActivate, setShowActivate] = useState(false);
  const [mainSelectorName, setMainSelectorName] = useState("");
  const [current, setCurrent] = useState<string>("");
  const [nodes, setNodes] = useState<ProxyEntry[]>([]);
  const [testing, setTesting] = useState(false);
  /// 上一轮组测速中失败的节点（显示为「超时」）
  const [failed, setFailed] = useState<Set<string>>(new Set());
  /// 最新一轮测速结果（用于实时刷新延迟显示，避免等 loadProxies 往返）
  const [delays, setDelays] = useState<Record<string, number>>({});
  /// 用户手动选择标记：一旦用户点选过某节点，不再自动切换到最低延迟
  const [userTouched, setUserTouched] = useState(false);
  const [keyword, setKeyword] = useState("");
  /// Go AIM 解锁评级结果与筛选 pill
  const [aim, setAim] = useState<GoAimStatus | null>(null);
  const [filter, setFilter] = useState<AimFilter>("all");

  // 未激活授权时禁止停留在 Go AIM 筛选态：自动重置回「全部」
  useEffect(() => {
    if (proReady && !proUnlocked && filter !== "all") setFilter("all");
  }, [proReady, proUnlocked, filter]);

  // 授权是否可用（启动瞬间 ready=false 时保持可用，避免闪烁误锁）
  const proActive = proUnlocked || !proReady;

  /// 未激活授权时的统一拦截：提示 + 弹出激活弹窗，绝不执行筛选/探测
  const guardPro = () => {
    toast.error(t("proxies.goAim.guard"));
    setShowActivate(true);
  };

  // 用 ref 保存最新值，避免 useEffect([]) 闭包捕获到初始值（stale closure）。
  // loadProxies 由 core://status / proxies://changed 事件触发，必须读到最新状态。
  const coreStatusRef = useRef(coreStatus);
  const mainSelectorRef = useRef(mainSelectorName);
  const userTouchedRef = useRef(userTouched);
  useEffect(() => { coreStatusRef.current = coreStatus; }, [coreStatus]);
  useEffect(() => { mainSelectorRef.current = mainSelectorName; }, [mainSelectorName]);
  useEffect(() => { userTouchedRef.current = userTouched; }, [userTouched]);

  useEffect(() => {
    getCoreStatus()
      .then((d) => {
        setMainSelectorName(d.mainSelector ?? "");
        if (d.outboundMode) useCoreStore.getState().setOutboundMode(d.outboundMode);
        loadProxies(d.mainSelector ?? "");
      })
      .catch(() => loadProxies());

    // Go AIM 评级结果：挂载时拉取，探测/评级更新经事件实时刷新
    getGoAimStatus().then(setAim).catch(() => undefined);

    // 事件名与后端一致（commands.rs emit "proxies://changed"）：
    // 启动自动选点/手动切换后刷新当前选中项与延迟
    const unStatus = listen("core://status", () => loadProxies());
    const unProxies = listen("proxies://changed", () => loadProxies());
    const unAim = listen("go-aim://updated", () => {
      getGoAimStatus().then(setAim).catch(() => undefined);
    });
    // 测速增量事件：后端逐节点推送 { group, name, delay }（delay=null 为超时）。
    // 仅应用与当前主选择组匹配的节点，测试中实时刷新延迟显示。
    const unUrlTest = listen<{ group: string; name: string; delay: number | null }>(
      "url-test-update",
      (event) => {
        const { group, name, delay } = event.payload;
        if (group !== mainSelectorRef.current) return;
        if (delay === null || delay <= 0) {
          setFailed((f) => new Set(f).add(name));
        } else {
          setDelays((d) => ({ ...d, [name]: delay }));
        }
      }
    );
    return () => {
      unStatus.then((fn) => fn());
      unProxies.then((fn) => fn());
      unAim.then((fn) => fn());
      unUrlTest.then((fn) => fn());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadProxies = async (preferred?: string) => {
    try {
      // 内核运行：从 clash API 拿实时延迟与选中态。
      // 注意：必须读 ref，否则闭包捕获的是初始 "stopped"，导致内核运行时
      // 仍走 loadCached 分支，节点页永远显示「暂无节点」。
      if (coreStatusRef.current === "running") {
        const resp = (await getProxyGroups()) as {
          proxies?: Record<string, ProxyEntry>;
        };
        const map = resp.proxies ?? {};

        const groupName = preferred || mainSelectorRef.current;
        const group = map[groupName];
        if (!group) {
          // 主选择组未就绪，回落到缓存预览
          await loadCached();
          return;
        }

        const all = (group.all ?? [])
          .map((item) => (typeof item === "string" ? map[item] : item))
          .filter((item): item is ProxyEntry => Boolean(item))
          .filter((item) => !GROUP_TYPES.includes(item.type));
        setNodes(all);
        setCurrent(group.now ?? "");

        // 未选默认延迟最低：now 为空或不在节点列表中，且用户未手动操作过
        const nowValid = group.now && all.some((n) => n.name === group.now);
        if (!nowValid && !userTouchedRef.current && all.length > 0) {
          autoSelectFastest(groupName);
        }
      } else {
        // 内核未运行：从订阅缓存预览（商业 APP 行为）
        await loadCached();
      }
    } catch (e) {
      console.error("load proxies failed:", e);
    }
  };

  /// 从订阅缓存读取节点列表（内核未运行时使用）
  const loadCached = async () => {
    try {
      const list = await getCachedProxies();
      const entries: ProxyEntry[] = list.map((p) => ({
        name: p.name,
        type: p.kind,
        server: p.server,
      }));
      setNodes(entries);
      setCurrent("");
      setDelays({});
      setFailed(new Set());
    } catch (e) {
      console.error("load cached proxies failed:", e);
      setNodes([]);
    }
  };

  const autoSelectFastest = async (groupName: string) => {
    try {
      const result = (await urlTest(groupName)) as Record<
        string,
        number
      > | null;
      if (!result || Object.keys(result).length === 0) return;
      const entries = Object.entries(result).filter(
        ([, d]) => d > 0
      );
      if (entries.length === 0) return;
      entries.sort((a, b) => a[1] - b[1]);
      const fastest = entries[0][0];
      if (fastest) {
        await selectProxy(groupName, fastest);
        setCurrent(fastest);
        toast.info(t("proxies.autoSelected", { name: fastest }));
        await loadProxies();
      }
    } catch (e) {
      console.error("auto select failed:", e);
    }
  };

  const lastDelay = (node: ProxyEntry): Delay => {
    if (failed.has(node.name)) return 0;
    // 优先用最新测速结果
    if (node.name in delays) return delays[node.name];
    const history = node.history ?? [];
    if (history.length === 0) return undefined;
    return history[history.length - 1].delay;
  };

  const handleTest = async () => {
    if (testing) return;
    // 测速前确保拿到最新主选择组名（事件触发时可能尚未同步到 state）
    const groupName = mainSelectorRef.current;
    if (!groupName) {
      // 兜底：重新拉取一次状态，拿到 mainSelector 后再测
      try {
        const d = await getCoreStatus();
        if (d.mainSelector) {
          setMainSelectorName(d.mainSelector);
          mainSelectorRef.current = d.mainSelector;
        }
      } catch {
        /* ignore */
      }
      if (!mainSelectorRef.current) {
        toast.error(t("proxies.err.noMainGroup"));
        return;
      }
    }
    if (nodes.length === 0) {
      toast.error(t("proxies.err.noNodesToTest"));
      return;
    }
    setTesting(true);
    // 清空上一轮失败标记：本轮结果由 url-test-update 增量事件与最终结果重建
    setFailed(new Set());
    try {
      const result = (await urlTest(mainSelectorRef.current)) as Record<
        string,
        number
      > | null;
      const res = result ?? {};
      // APP 任务4：res[name] 不存在或为 0 一律进 failed 集合（显示超时），
      // 绝不允许测速完成后任何节点残留空白「—」未检测状态
      const ok = new Set(
        Object.entries(res)
          .filter(([, d]) => d > 0)
          .map(([n]) => n)
      );
      setFailed(
        new Set(nodes.map((n) => n.name).filter((n) => !ok.has(n)))
      );
      setDelays(
        Object.fromEntries(Object.entries(res).filter(([, d]) => d > 0))
      );
    } catch (e) {
      console.error("url test failed:", e);
      toast.error(t("proxies.err.testFailed", { error: String(e) }));
    } finally {
      setTesting(false);
    }
  };

  const handleSelect = async (name: string) => {
    if (current === name) return;
    setUserTouched(true);
    try {
      await selectProxy(mainSelectorRef.current, name);
      setCurrent(name);
      await loadProxies();
    } catch (e) {
      console.error("select proxy failed:", e);
    }
  };

  /// Go AIM 解锁探测：结果经 go-aim://updated 事件实时刷新到列表徽章
  const handleAimProbe = async () => {
    if (!proActive) {
      guardPro();
      return;
    }
    if (coreStatus !== "running") {
      toast.error(t("proxies.err.coreNotRunningProbe"));
      return;
    }
    try {
      await runGoAimProbe();
      toast.info(t("proxies.goAim.probeStarted"));
    } catch (e) {
      // 含 "Pro" 的错误为门控/授权类错误，直接原样提示
      toast.error(String(e));
    }
  };

  /// 关键字 + Go AIM 解锁状态联合过滤
  const keywordLower = keyword.trim().toLowerCase();
  const filtered = nodes.filter((n) => {
    if (keywordLower && !n.name.toLowerCase().includes(keywordLower)) return false;
    if (filter === "all") return true;
    const r = aim?.results[n.name];
    if (!r) return false;
    if (filter === "aim") return r.aiUnlocked || r.mediaUnlocked;
    if (filter === "ai") return r.aiUnlocked;
    return r.mediaUnlocked;
  });

  const resetFilters = () => {
    setFilter("all");
    setKeyword("");
  };

  /// 测速完成后按延迟从低到高排列：有延迟的升序在前，未测速保持原序居中，
  /// 超时的最后。测速进行中不排序（增量结果会导致列表跳动），
  /// 没有任何测速数据时保持订阅原始顺序。
  const sorted = useMemo(() => {
    if (testing) return filtered;
    const hasData = filtered.some((n) => {
      const d = lastDelay(n);
      return typeof d === "number" && d > 0;
    });
    if (!hasData) return filtered;
    const measured = filtered
      .filter((n) => {
        const d = lastDelay(n);
        return typeof d === "number" && d > 0;
      })
      .sort(
        (a, b) => (lastDelay(a) as number) - (lastDelay(b) as number)
      );
    const unknown = filtered.filter((n) => lastDelay(n) === undefined);
    const timedOut = filtered.filter((n) => {
      const d = lastDelay(n);
      return typeof d === "number" && d <= 0;
    });
    return [...measured, ...unknown, ...timedOut];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtered, delays, failed, testing]);

  if (nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-border-strong bg-surface-card/50 py-16 px-6 text-center">
        <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-accent/10 text-accent">
          <Gauge size={26} />
        </div>
        <h3 className="text-base font-semibold text-gray-200">
          {t("proxies.empty.noNodes")}
        </h3>
        <p className="mt-2 max-w-sm text-sm leading-relaxed text-gray-500">
          {t("proxies.empty.noNodesDesc")}
        </p>
        <div className="mt-6 flex items-center gap-3">
          <Link
            to="/subscription"
            className="flex items-center gap-2 rounded-lg bg-accent px-5 py-2.5 text-sm font-medium text-white transition-colors hover:bg-accent-hover"
          >
            <RefreshCw size={14} />
            {t("proxies.manageSub")}
          </Link>
          {coreStatus !== "running" && (
            <Link
              to="/dashboard"
              className="flex items-center gap-2 rounded-lg border border-border px-5 py-2.5 text-sm text-gray-300 transition-colors hover:border-border-strong"
            >
              <Gauge size={15} />
              {t("proxies.goDashboard")}
            </Link>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Go AIM 筛选 pills + AI 检测入口（Go AIM / AI / 流媒体与检测为 Pro 功能：
          未激活时锁定并弹激活弹窗，ipa-9） */}
      <div className="flex items-center gap-2">
        <div className="flex items-center gap-1.5 overflow-x-auto">
          {AIM_FILTERS.map((f) => {
            const locked = f.value !== "all" && !proActive;
            return (
              <button
                key={f.value}
                onClick={() => (locked ? guardPro() : setFilter(f.value))}
                className={clsx(
                  "shrink-0 flex items-center gap-1 px-3 py-1 rounded-full text-xs transition-colors",
                  filter === f.value
                    ? "bg-accent text-white font-medium"
                    : "bg-glass text-gray-400 hover:text-gray-200"
                )}
              >
                {locked && <Lock size={12} className="opacity-70" />}
                {t(f.labelKey)}
              </button>
            );
          })}
        </div>
        <button
          onClick={proActive ? handleAimProbe : guardPro}
          className="ml-auto shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border-strong text-xs text-gray-300 transition-colors hover:border-accent/40 hover:text-accent"
          title={
            !proActive
              ? t("proxies.goAim.lockedTip")
              : coreStatus === "running"
                ? t("proxies.goAim.probeTip")
                : t("proxies.goAim.probeNeedCore")
          }
        >
          {!proActive ? (
            <Lock size={12} className="opacity-70" />
          ) : (
            <Crosshair size={13} />
          )}
          {t("proxies.goAim.detect")}
        </button>
      </div>

      {/* 顶部工具栏：搜索 + 测速 */}
      <div className="flex items-center gap-2">
        <div className="flex-1 flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-card border border-border">
          <Search size={14} className="text-gray-500" />
          <input
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder={t("proxies.searchNodes")}
            className="flex-1 bg-transparent text-sm outline-none placeholder:text-gray-600"
          />
        </div>
        <button
          onClick={handleTest}
          disabled={testing || coreStatus !== "running"}
          className="shrink-0 flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-accent text-white text-xs font-medium disabled:opacity-50 disabled:cursor-not-allowed"
          title={
            coreStatus !== "running"
              ? t("proxies.speedTestNeedCore")
              : t("proxies.speedTest")
          }
        >
          <Zap size={13} className={testing ? "animate-pulse" : ""} />
          {testing ? t("proxies.speedTesting") : t("proxies.speedTest")}
        </button>
      </div>

      {/* 当前选中节点信息 */}
      <div className="flex items-center justify-between px-1 text-xs text-gray-400">
        <span>
          {t("proxies.current")}
          <span className="text-accent">{current || t("proxies.notSelected")}</span>
          {coreStatus !== "running" && (
            <span className="text-gray-600 ml-2">
              {t("proxies.coreNotRunningPreview")}
            </span>
          )}
        </span>
        <span>{t("proxies.nodeCount", { count: filtered.length })}</span>
      </div>

      {/* 节点列表流（Shadowrocket 风格；测速完成后按延迟升序） */}
      {sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl bg-surface-card border border-border py-12 px-6 text-center">
          <Search size={22} className="text-gray-600" />
          <p className="mt-3 text-sm text-gray-400">{t("proxies.empty.noMatch")}</p>
          <button
            onClick={resetFilters}
            className="mt-4 rounded-lg border border-border-strong px-4 py-1.5 text-xs text-gray-300 transition-colors hover:border-accent/40 hover:text-accent"
          >
            {t("proxies.resetFilter")}
          </button>
        </div>
      ) : (
      <div className="rounded-2xl bg-surface-card overflow-hidden border border-border">
        {sorted.map((node, idx) => {
          const delay = lastDelay(node);
          const selected = current === node.name;
          const aimResult = aim?.results[node.name];
          return (
            <button
              key={node.name}
              onClick={() => handleSelect(node.name)}
              disabled={coreStatus !== "running"}
              className={clsx(
                "w-full flex items-center gap-3 px-4 py-3 text-left transition-colors",
                selected ? "bg-accent/10" : "hover:bg-glass",
                coreStatus !== "running" && "cursor-default opacity-80",
                idx !== sorted.length - 1 && "border-b border-border"
              )}
            >
              {/* 选中指示器 */}
              <span
                className={clsx(
                  "shrink-0 w-2 h-2 rounded-full transition-colors",
                  selected ? "bg-accent" : "bg-transparent"
                )}
              />

              {/* 节点名 */}
              <span
                className={clsx(
                  "flex-1 truncate text-sm",
                  selected ? "text-gray-100 font-medium" : "text-gray-300"
                )}
              >
                {node.name}
              </span>

              {/* 协议标签 */}
              <span className="shrink-0 px-1.5 py-0.5 rounded text-[10px] font-mono uppercase tracking-wide bg-glass text-gray-400">
                {protocolTag(node.type)}
              </span>

              {/* Go AIM 解锁徽章（APP 任务3：具体平台细分徽章，
                  最多展示前 5 个 + 超出显示 +N；未激活授权不渲染） */}
              {proActive && aimResult && aimResult.unlockedTags.length > 0 && (
                <>
                  {aimResult.unlockedTags.slice(0, 5).map((tag) => (
                    <span
                      key={tag}
                      title={aimResult.unlockedTags.join(" ")}
                      className={clsx(
                        "shrink-0 px-1 py-0.5 rounded border text-[9px] font-medium",
                        AIM_BADGE_STYLE[tag] ??
                          "bg-glass text-gray-400 border-border"
                      )}
                    >
                      {tag}
                    </span>
                  ))}
                  {aimResult.unlockedTags.length > 5 && (
                    <span
                      title={aimResult.unlockedTags.join(" ")}
                      className="shrink-0 px-1 py-0.5 rounded text-[9px] font-medium bg-glass text-gray-400"
                    >
                      +{aimResult.unlockedTags.length - 5}
                    </span>
                  )}
                </>
              )}

              {/* 延迟 */}
              <span
                className={clsx(
                  "shrink-0 w-14 text-right text-xs font-mono",
                  delayClass(delay)
                )}
              >
                {delayText(delay)}
              </span>

              <ChevronRight size={14} className="shrink-0 text-gray-600" />
            </button>
          );
        })}
      </div>
      )}

      {/* Pro 激活弹窗（Go AIM 筛选/检测拦截入口共用） */}
      <ActivateProModal
        open={showActivate}
        onClose={() => setShowActivate(false)}
      />
    </div>
  );
}
