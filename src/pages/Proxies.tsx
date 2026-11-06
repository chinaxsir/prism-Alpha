import { useEffect, useMemo, useRef, useState } from "react";
import { Zap, Gauge, RefreshCw, ChevronRight, Search, Crosshair, Lock } from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import { Link } from "react-router-dom";

import {
  getCoreStatus,
  getProxyGroups,
  getCachedProxies,
  testCachedProxies,
  selectProxy,
  urlTest,
  getGoAimStatus,
  runGoAimProbe,
  type AimNodeResult,
  type GoAimStatus,
} from "@/api/ipc";
import { useCoreStore, isDummyNodeName } from "@/stores/core";
import { useProStore } from "@/stores/pro";
import { toast } from "@/components/ui/Toast";
import { delayClass, delayText, type Delay } from "@/utils/latency";
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

/// Go AIM 筛选 pills（APP53 任务2.1 去掉 AI / 流媒体分类，仅保留 全部 / Go AIM）
type AimFilter = "all" | "aim";
const AIM_FILTERS: Array<{ value: AimFilter; labelKey: string }> = [
  { value: "all", labelKey: "common.all" },
  { value: "aim", labelKey: "engine.goAim" },
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

/** AI 平台标签集合（用于筛选与布尔字段失配时的交叉校验） */
const AI_TAGS = ["GPT", "Claude", "Gemini", "AI"];
/** 流媒体平台标签集合 */
const MEDIA_TAGS = ["NF", "Disney+", "YT", "TK"];

/** 节点是否解锁任一 AI 平台：兼容后端布尔字段与 unlockedTags 数组 */
const isNodeAiUnlocked = (r?: AimNodeResult) =>
  Boolean(
    r &&
      (r.aiUnlocked || r.unlockedTags?.some((t) => AI_TAGS.includes(t)))
  );

/** 节点是否解锁任一流媒体平台 */
const isNodeMediaUnlocked = (r?: AimNodeResult) =>
  Boolean(
    r &&
      (r.mediaUnlocked ||
        r.unlockedTags?.some((t) => MEDIA_TAGS.includes(t)))
  );

/** 节点是否解锁任一平台（Go AIM 汇总筛选） */
const isNodeAimUnlocked = (r?: AimNodeResult) =>
  isNodeAiUnlocked(r) || isNodeMediaUnlocked(r);

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

  // 【APP-4 任务3】未激活不再拦截提示：Pro 控件一律 disabled 静默禁用

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
          /** 【APP52 任务1】后端持久化延迟（节点名 → 最近真实延迟） */
          prismDelays?: Record<string, number>;
        };
        const map = resp.proxies ?? {};
        // 【APP52 任务1】内核重启会清空 history：先用持久化缓存补齐延迟，
        // 有实时 history 的节点以 history 为准，保证延迟显示/排序不丢失。
        if (resp.prismDelays) {
          setDelays((prev) => {
            const next = { ...prev };
            for (const [name, d] of Object.entries(resp.prismDelays ?? {})) {
              const hist = map[name]?.history ?? [];
              const fresh = hist.length ? hist[hist.length - 1]?.delay : undefined;
              if (typeof fresh === "number" && fresh > 0) next[name] = fresh;
              else if (!(name in next) && d > 0) next[name] = d;
            }
            return next;
          });
        }

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
          .filter((item) => !GROUP_TYPES.includes(item.type))
          // 【APP33 任务3.2】过滤「剩余流量/到期时间」等信息/广告类假节点
          .filter((item) => !isDummyNodeName(item.name));
        setNodes(all);
        setCurrent(group.now ?? "");

        // 未选默认延迟最低：now 为空、为假节点或不在节点列表中，且用户未手动操作过
        const nowValid =
          group.now &&
          !isDummyNodeName(group.now) &&
          all.some((n) => n.name === group.now);
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
      const entries: ProxyEntry[] = list
        // 【APP33 任务3.2】过滤「剩余流量/到期时间」等信息/广告类假节点
        .filter((p) => !isDummyNodeName(p.name))
        .map((p) => ({
          name: p.name,
          type: p.kind,
          server: p.server,
        }));
      setNodes(entries);
      setCurrent("");
      // 【APP52 任务1】恢复持久化延迟：实测 >0 进 delays，0 进 failed，
      // 未测速保持 undefined（排序居中），停止/重启 APP 后依旧按延迟升序。
      const persistedDelays: Record<string, number> = {};
      const persistedFailed = new Set<string>();
      for (const p of list) {
        if (typeof p.delay !== "number") continue;
        if (p.delay > 0) persistedDelays[p.name] = p.delay;
        else persistedFailed.add(p.name);
      }
      setDelays(persistedDelays);
      setFailed(persistedFailed);
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
        ([name, d]) => d > 0 && !isDummyNodeName(name)
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
    // 【APP44 任务1.3】内核未运行：走 DoH + TCP 真实握手测速（不依赖 Clash API）
    if (coreStatusRef.current !== "running") {
      if (nodes.length === 0) {
        toast.error(t("proxies.err.noNodesToTest"));
        return;
      }
      setTesting(true);
      setFailed(new Set());
      try {
        const res = (await testCachedProxies(3000)) ?? {};
        const ok = new Set(
          Object.entries(res)
            .filter(([, d]) => d > 0)
            .map(([n]) => n)
        );
        setFailed(new Set(nodes.map((n) => n.name).filter((n) => !ok.has(n))));
        setDelays(
          Object.fromEntries(Object.entries(res).filter(([, d]) => d > 0))
        );
      } catch (e) {
        console.error("offline delay test failed:", e);
        toast.error(t("proxies.err.testFailed", { error: String(e) }));
      } finally {
        setTesting(false);
      }
      return;
    }
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
    // 【APP-4 任务3】未激活静默忽略（按钮本身已 disabled，此处兜底）
    if (!proActive) {
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
  /// （兼容后端布尔字段与 unlockedTags 数组，APP-5）
  const keywordLower = keyword.trim().toLowerCase();
  const filtered = nodes.filter((n) => {
    if (keywordLower && !n.name.toLowerCase().includes(keywordLower)) return false;
    if (filter === "all") return true;
    const r = aim?.results[n.name];
    if (!r) return false;
    if (filter === "aim") return isNodeAimUnlocked(r);
    return false;
  });

  /// 已探测到的结果数：为 0 说明还没跑过探测（切到 AI/流媒体栏时自动补一次）
  const aimResultCount = Object.keys(aim?.results ?? {}).length;
  const aimProbing = Boolean(aim?.probing);

  // 切到 Go AIM / AI / 流媒体栏且尚无结果时自动触发一次探测，
  // 避免用户看到空白列表而误以为「没有可用节点」
  const aimAutoProbeRef = useRef(false);
  useEffect(() => {
    if (filter === "all") {
      aimAutoProbeRef.current = false;
      return;
    }
    if (!proActive || coreStatus !== "running") return;
    if (aimAutoProbeRef.current || aimProbing || aimResultCount > 0) return;
    aimAutoProbeRef.current = true;
    runGoAimProbe().catch(() => undefined);
  }, [filter, proActive, coreStatus, aimProbing, aimResultCount]);

  /// 筛选态下探测尚未产生结果：列表区展示加载提示而非「无匹配节点」
  const aimPending = filter !== "all" && (aimProbing || aimResultCount === 0);

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
          【APP-4 任务3】未激活时 disabled 静默禁用，不弹 Toast / 激活窗） */}
      <div className="flex items-center gap-2">
        <div className="flex items-center gap-1.5 overflow-x-auto">
          {AIM_FILTERS.map((f) => {
            const locked = f.value !== "all" && !proActive;
            return (
              <button
                key={f.value}
                disabled={locked}
                onClick={() => (locked ? undefined : setFilter(f.value))}
                className={clsx(
                  "shrink-0 flex items-center gap-1 px-3 py-1 rounded-full text-xs transition-colors",
                  locked
                    ? "bg-glass text-gray-500 opacity-50 cursor-not-allowed"
                    : filter === f.value
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
          disabled={!proActive}
          onClick={proActive ? handleAimProbe : undefined}
          className={clsx(
            "ml-auto shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border-strong text-xs transition-colors",
            proActive
              ? "text-gray-300 hover:border-accent/40 hover:text-accent"
              : "text-gray-500 opacity-50 cursor-not-allowed"
          )}
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
          disabled={testing || nodes.length === 0}
          className="shrink-0 flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-accent text-white text-xs font-medium disabled:opacity-50 disabled:cursor-not-allowed"
          title={t("proxies.speedTest")}
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
        aimPending ? (
          <div className="flex flex-col items-center justify-center rounded-2xl bg-surface-card border border-border py-12 px-6 text-center">
            <RefreshCw size={22} className="animate-spin text-accent" />
            <p className="mt-3 text-sm text-gray-300">{t("proxies.aim.probing")}</p>
            <p className="mt-2 max-w-sm text-xs leading-relaxed text-gray-500">
              {t("proxies.aim.probingDesc")}
            </p>
          </div>
        ) : (
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
        )
      ) : (
      <div className="rounded-2xl bg-surface-card overflow-hidden border border-border">
        {sorted.map((node, idx) => {
          const delay = lastDelay(node);
          const selected = current === node.name;
          const aimResult = aim?.results[node.name];
          /// 未激活授权不渲染解锁徽章（与原先 Pro 守卫保持一致）
          const unlockedTags = proActive ? (aimResult?.unlockedTags ?? []) : [];
          return (
            <button
              key={node.name}
              onClick={() => handleSelect(node.name)}
              disabled={coreStatus !== "running"}
              className={clsx(
                "w-full px-3.5 py-2.5 text-left transition-colors",
                selected ? "bg-accent/10" : "hover:bg-glass",
                coreStatus !== "running" && "cursor-default opacity-80",
                idx !== sorted.length - 1 && "border-b border-border"
              )}
            >
              {/* 第一行（主信息）：选中圆点 + 完整节点名（独占剩余宽度）+ 延迟 + 箭头。
                  节点名与延迟绝不和徽章挤在同一行，彻底消除截断 */}
              <div className="flex items-center justify-between gap-2">
                <div className="flex min-w-0 flex-1 items-center gap-2">
                  <span
                    className={clsx(
                      "shrink-0 w-2 h-2 rounded-full transition-colors",
                      selected ? "bg-accent" : "bg-transparent"
                    )}
                  />
                  <span
                    className={clsx(
                      "truncate text-sm",
                      selected ? "text-gray-100 font-medium" : "text-gray-300"
                    )}
                  >
                    {node.name}
                  </span>
                  {/* 无解锁徽章时保持紧凑单行：协议标签内联显示 */}
                  {unlockedTags.length === 0 && (
                    <span className="shrink-0 px-1.5 py-0.5 rounded text-[11px] font-mono uppercase tracking-wide bg-glass text-gray-400">
                      {protocolTag(node.type)}
                    </span>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  <span
                    className={clsx(
                      "text-xs font-mono tabular-nums font-medium",
                      delayClass(delay)
                    )}
                  >
                    {delayText(delay)}
                  </span>
                  <ChevronRight size={14} className="shrink-0 text-gray-600" />
                </div>
              </div>

              {/* 第二行（自适应）：协议标签 + 全部 Go AIM 平台徽章，flex-wrap
                  自然换行，不挤占第一行的名称与延迟；无徽章时不渲染 */}
              {unlockedTags.length > 0 && (
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5 pl-4">
                  <span className="px-1.5 py-0.5 rounded bg-surface-hover text-[11px] font-mono uppercase tracking-wide text-gray-400">
                    {protocolTag(node.type)}
                  </span>
                  {unlockedTags.map((tag) => (
                    <span
                      key={tag}
                      className={clsx(
                        "px-1.5 py-0.5 rounded border text-[11px] font-medium",
                        AIM_BADGE_STYLE[tag] ??
                          "bg-glass text-gray-400 border-border"
                      )}
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              )}
            </button>
          );
        })}
      </div>
      )}
    </div>
  );
}
