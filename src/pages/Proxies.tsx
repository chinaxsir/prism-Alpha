import { useEffect, useMemo, useRef, useState } from "react";
import { Zap, Gauge, RefreshCw, ChevronRight, Search, Lock } from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import { Link } from "react-router-dom";

import {
  getCoreStatus,
  getProxyGroups,
  getCachedProxies,
  testAllDelays,
  selectProxy,
  urlTest,
  getGoAimStatus,
  runGoAimProbe,
  exportSingleNodeReport,
  type AimNodeResult,
  type GoAimStatus,
} from "@/api/ipc";
import { useCoreStore, isDummyNodeName, ensureAimListenersRegistered, syncAimSnapshot } from "@/stores/core";
import { useProStore } from "@/stores/pro";
import { toast } from "@/components/ui/Toast";
import { delayClass, delayText, type Delay } from "@/utils/latency";
import { formatStandardNodeAimReport } from "@/utils/aimReport";
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

/** 【APP56 任务2】有效延迟下限：`0 < delay < 5` 为本机回环 / FakeIP 假值，
 *  一律按超时 0 处理，绝不在列表渲染 `1 ms`。 */
const isValidDelay = (d: unknown): d is number =>
  typeof d === "number" && d >= 5;

/** 【APP74 任务5.1】列表只允许 VERIFIED 平台渲染徽章；
 * ACCESSIBLE / PARTIAL / BLOCKED / UNKNOWN 一律隐藏，避免"似解锁非解锁"的假暗示。 */
const aimListBadgesOf = (r?: AimNodeResult): string[] =>
  AIM_DETAIL_ORDER.filter(
    (s) => r?.services?.[s]?.verdict === "VERIFIED",
  );
/** 详情面板展示全部 7 平台（不区分状态） */
const aimDetailBadgesOf = (r?: AimNodeResult): string[] =>
  AIM_DETAIL_ORDER.filter((s) => r?.services?.[s]);
/** 【APP73 任务3.4】综合评分 > 0 即视为 AIM 支持节点 */
const aimScoreOf = (r?: AimNodeResult): number => r?.score ?? 0;

/// 【APP71 任务4】7 平台固定展示顺序（与后端探测顺序一致）
const AIM_DETAIL_ORDER = ["GPT", "Claude", "Gemini", "NF", "YT", "Disney+", "TK"];

/// 【APP73 任务3.1】五级状态统一配色（列表 / 详情 / 统计共用）：
/// VERIFIED 翠绿、ACCESSIBLE 皇家蓝、PARTIAL 琥珀橙、BLOCKED 珊瑚红、UNKNOWN 中性灰。
const AIM_VERDICT_STYLE: Record<string, string> = {
  VERIFIED: "bg-[#24B414]/15 text-[#24B414] border-[#24B414]/30",
  ACCESSIBLE: "bg-[#4169E1]/15 text-[#5B8DEF] border-[#4169E1]/30",
  PARTIAL: "bg-[#FF9F0A]/12 text-[#FF9F0A] border-[#FF9F0A]/30",
  BLOCKED: "bg-[#FF6B6B]/12 text-[#FF6B6B] border-[#FF6B6B]/30",
  UNKNOWN: "bg-glass text-gray-500 border-border",
};

/// 【APP71 任务4】单节点 7 平台五态详情弹窗：出口、耗时、补测次数、
/// 判定依据（永不包含完整 HTTP 响应正文），并支持导出单节点 JSON 报告。
function AimNodeDetailModal({
  node,
  protocol,
  result,
  onClose,
}: {
  node: string;
  protocol?: string;
  result?: AimNodeResult;
  onClose: () => void;
}) {
  const { t, resolved } = useTranslation();
  const services = result?.services ?? {};
  const rows = aimDetailBadgesOf(result);

  // 【APP73 任务4.2】单节点报告导出：中英双语标准节点报告。
  // 剪贴板 + 系统分享（iOS）/ Downloads（桌面）；失败只提示、不中断弹窗。
  const [exporting, setExporting] = useState(false);
  const exportReport = async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const text = formatStandardNodeAimReport({
        node,
        protocol,
        result,
        lang: resolved,
      });
      try {
        await navigator.clipboard?.writeText(text);
      } catch {
        // 剪贴板不可用时静默忽略，不影响文件导出
      }
      await exportSingleNodeReport(node, text);
      toast.success(t("proxies.aimDetail.exported"));
    } catch (e) {
      toast.error(String(e));
    } finally {
      setExporting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="flex max-h-[82vh] w-full max-w-lg flex-col gap-2 overflow-y-auto rounded-2xl border border-border bg-surface-card p-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-2">
          <span className="min-w-0 truncate text-sm font-bold text-gray-100">
            {t("proxies.aimDetail.title")} · {node}
          </span>
          <button
            onClick={onClose}
            className="shrink-0 rounded-lg border border-border px-2.5 py-1 text-[11px] text-gray-400 hover:text-accent"
          >
            {t("proxies.aimDetail.close")}
          </button>
        </div>
        <div className="text-[11px] text-gray-400">
          {t("proxies.aimDetail.egress")}: {result?.egressIp ?? "—"}
          {result?.egressCountry ? ` (${result.egressCountry})` : ""}
          {result?.egressAsn ? ` · AS${result.egressAsn}` : ""} · score{" "}
          {result?.score ?? 0} · {result?.delayMs ?? 0}ms
        </div>
        {rows.length === 0 ? (
          <div className="rounded-lg bg-glass px-3 py-4 text-center text-[11px] text-gray-500">
            {t("proxies.aimDetail.empty")}
          </div>
        ) : (
          rows.map((service) => {
            const r = services[service];
            const basis = r.verdictBasis || r.evidence || r.failureReason || "—";
            return (
              <div
                key={service}
                className="rounded-lg bg-glass px-2.5 py-1.5 text-[11px]"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-gray-200">{service}</span>
                  <span
                    className={clsx(
                      "rounded border px-1.5 py-0.5 font-mono text-[10px]",
                      AIM_VERDICT_STYLE[r.verdict] ?? AIM_VERDICT_STYLE.UNKNOWN,
                    )}
                  >
                    {r.verdict}
                  </span>
                </div>
                <div className="mt-0.5 flex flex-wrap gap-x-2 text-gray-400">
                  {r.elapsedMs != null && (
                    <span className="tabular-nums">{r.elapsedMs}ms</span>
                  )}
                  {r.statusCode != null && (
                    <span className="tabular-nums">HTTP {r.statusCode}</span>
                  )}
                  {(r.retryCount ?? 0) > 0 && (
                    <span>{t("proxies.aimDetail.retry", { n: r.retryCount ?? 0 })}</span>
                  )}
                </div>
                <div className="mt-0.5 break-words text-[11px] text-gray-500">
                  {t("proxies.aimDetail.basis")}: {basis}
                </div>
              </div>
            );
          })
        )}
        <button
          onClick={exportReport}
          disabled={exporting}
          className="mt-1 rounded-xl border border-border px-3 py-2 text-[12px] font-bold text-gray-200 hover:border-accent/40 disabled:opacity-60"
        >
          {t("proxies.aimDetail.export")}
        </button>
      </div>
    </div>
  );
}

export default function Proxies() {
  const { t } = useTranslation();

  const protocolTag = (type: string): string => {
    if (type === "Direct") return t("proxies.proto.direct");
    if (type === "Block") return t("proxies.proto.block");
    return PROTOCOL_LABEL[type] ?? type ?? "—";
  };

  const coreStatus = useCoreStore((s) => s.status);
  // 【APP54 任务5】测速 / Go AIM 实时进度（全局 store 收口，事件驱动）
  const delayProgress = useCoreStore((s) => s.delayProgress);
  const aimProgress = useCoreStore((s) => s.aimProgress);
  // 【APP71 任务3/4】结构化事件失败原因与快照结果（节点详情弹窗数据源）
  const aimLastError = useCoreStore((s) => s.aimLastError);
  const storeAim = useCoreStore((s) => s.goAimStatus);
  const mergeNodeDelays = useCoreStore((s) => s.mergeNodeDelays);
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
  /// Go AIM 解锁评级结果（APP56 任务1.1 起不再提供分类胶囊）
  const [aim, setAim] = useState<GoAimStatus | null>(null);
  /// 【APP71 任务4】单节点详情弹窗
  const [detailNode, setDetailNode] = useState<string | null>(null);
  /// 【APP71 任务3】合并快照结果（store 实时 NODE_RESULT 优先）
  const aimResults = useMemo(
    () => ({ ...(aim?.results ?? {}), ...(storeAim?.results ?? {}) }),
    [aim?.results, storeAim?.results],
  );

  // 授权是否可用（启动瞬间 ready=false 时保持可用，避免闪烁误锁）
  const proActive = proUnlocked || !proReady;

  // 【APP56 任务1.2/任务2.2】「Pro 且已开启 Go AIM」模式判定与 AIM 优先排序
  const goAimEnabled = Boolean(aim?.enabled);
  const isProAimMode = Boolean(proUnlocked && goAimEnabled);

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
    getGoAimStatus()
      .then((d) => {
        setAim(d);
        useCoreStore.getState().setGoAimStatus(d);
      })
      .catch(() => undefined);

    // 事件名与后端一致（commands.rs emit "proxies://changed"）：
    // 启动自动选点/手动切换后刷新当前选中项与延迟
    const unStatus = listen("core://status", () => loadProxies());
    const unProxies = listen("proxies://changed", () => loadProxies());
    const unAim = listen("go-aim://updated", () => {
      getGoAimStatus()
        .then((d) => {
          setAim(d);
          useCoreStore.getState().setGoAimStatus(d);
        })
        .catch(() => undefined);
    });
    // 测速增量事件：后端逐节点推送 { group, name, delay }（delay=null 为超时）。
    // 仅应用与当前主选择组匹配的节点，测试中实时刷新延迟显示。
    const unUrlTest = listen<{ group: string; name: string; delay: number | null }>(
      "url-test-update",
      (event) => {
        const { group, name, delay } = event.payload;
        if (group !== mainSelectorRef.current) return;
        // 【APP56 任务2】`< 5 ms` 与本机回环假值一律记超时
        if (delay === null || !isValidDelay(delay)) {
          setFailed((f) => new Set(f).add(name));
        } else {
          setDelays((d) => ({ ...d, [name]: delay }));
        }
      }
    );
    // 【APP54 任务2/5】全量测速增量结果：逐批合并到延迟/超时集合，
    // 并同步前端镜像（localStorage），切页回来也不会丢
    const unDelays = listen<Record<string, number>>("delays://updated", (event) => {
      const payload = event.payload ?? {};
      const ok: Record<string, number> = {};
      const timedOut: string[] = [];
      for (const [name, delay] of Object.entries(payload)) {
        // 【APP56 任务2】`< 5 ms` 虚假延迟记入超时集合
        if (isValidDelay(delay)) ok[name] = delay;
        else timedOut.push(name);
      }
      setDelays((prev) => ({ ...prev, ...ok }));
      setFailed((prev) => {
        const next = new Set(prev);
        timedOut.forEach((n) => next.add(n));
        return next;
      });
      mergeNodeDelays(ok);
    });
    return () => {
      unStatus.then((fn) => fn());
      unProxies.then((fn) => fn());
      unAim.then((fn) => fn());
      unUrlTest.then((fn) => fn());
      unDelays.then((fn) => fn());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 【APP71 任务3】页面挂载 / 回到前台：先确保事件监听已注册，再拉一次
  // 全量快照合并，彻底消除「listen 尚未生效」窗口内的进度与结果丢包。
  useEffect(() => {
    void ensureAimListenersRegistered().catch(() => undefined);
    void syncAimSnapshot();
    const onVisible = () => {
      if (document.visibilityState === "visible") void syncAimSnapshot();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
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
              // 【APP56 任务2】只有 `>= 5 ms` 才是真实延迟
              if (isValidDelay(fresh)) next[name] = fresh;
              else if (!(name in next) && isValidDelay(d)) next[name] = d;
            }
            return next;
          });
          // 同步前端镜像（只存实测 >=5，0 表示超时）
          mergeNodeDelays(
            Object.fromEntries(
              Object.entries(resp.prismDelays).filter(([, d]) => isValidDelay(d))
            )
          );
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
      // 未测速保持 undefined（排序居中）。【APP54 任务2】再叠加前端镜像，
      // 切页/启停 VPN 均不会丢失已测出的延迟。
      const mirrored = useCoreStore.getState().nodeDelays;
      const persistedDelays: Record<string, number> = { ...mirrored };
      const persistedFailed = new Set<string>();
      for (const p of list) {
        if (typeof p.delay !== "number") continue;
        if (p.delay > 0) persistedDelays[p.name] = p.delay;
        else if (!(p.name in mirrored)) persistedFailed.add(p.name);
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
    // 优先用最新测速结果；【APP56 任务2】`< 5 ms` 假值一律按超时 0 处理
    const live = delays[node.name];
    if (typeof live === "number") return isValidDelay(live) ? live : 0;
    const history = node.history ?? [];
    if (history.length === 0) return undefined;
    const d = history[history.length - 1]?.delay;
    return isValidDelay(d) ? d : 0;
  };

  const handleTest = async () => {
    if (testing || delayProgress.running) return;
    if (nodes.length === 0) {
      toast.error(t("proxies.err.noNodesToTest"));
      return;
    }
    setTesting(true);
    // 清空上一轮失败标记：本轮结果由 delays://updated 增量事件与最终结果重建
    setFailed(new Set());
    try {
      // 【APP54 任务2】全量测速：运行中/未运行统一入口，100% 覆盖全部节点。
      // 后端逐节点写延迟缓存 + 推送进度，完成后自动选最低延迟节点。
      const res = (await testAllDelays()) ?? {};
      // 【APP56 任务2】只有 `>= 5 ms` 才视为有效延迟，`1~4 ms` 直接记超时
      const ok = Object.fromEntries(
        Object.entries(res).filter(([, d]) => isValidDelay(d))
      );
      setDelays((prev) => ({ ...prev, ...ok }));
      setFailed(new Set(nodes.map((n) => n.name).filter((n) => !(n in ok))));
      mergeNodeDelays(ok);
      await loadProxies();
    } catch (e) {
      console.error("all delays test failed:", e);
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

  /// 【APP56 任务1.1】仅保留关键字搜索（分类胶囊已移除）
  const keywordLower = keyword.trim().toLowerCase();
  const filtered = nodes.filter(
    (n) => !keywordLower || n.name.toLowerCase().includes(keywordLower),
  );

  /// 已探测到的结果数：为 0 说明还没跑过探测
  const aimResultCount = Object.keys(aimResults).length;
  const aimProbing = Boolean(aim?.probing);
  /// 【APP54 任务5】已测速节点数（实测 >0 或超时 0 都算已测，未测为 undefined）
  const testedCount = nodes.filter((n) => typeof lastDelay(n) === "number").length;
  const aimRunning = aimProgress.running || aimProbing;

  /// 【APP56 任务1.2 情况 A】默认：总节点数 + 测速进度
  const totalCount = nodes.length;
  const delayDone = delayProgress.running ? delayProgress.done : testedCount;
  const delayPct =
    totalCount > 0
      ? Math.min(100, Math.round((delayDone * 100) / totalCount))
      : 0;
  /// 【APP73 任务3.4】AIM 支持节点：综合评分 > 0（ACCESSIBLE 起步）
  const supportedAimCount = nodes.filter(
    (n) => aimScoreOf(aimResults[n.name]) > 0 && isValidDelay(lastDelay(n)),
  ).length;
  const aimDone = aimProgress.running
    ? aimProgress.done
    : aimResultCount || testedCount;
  const aimPct = aimRunning
    ? aimProgress.percent
    : totalCount > 0
      ? Math.min(100, Math.round((aimDone * 100) / totalCount))
      : 0;
  const progressPct = isProAimMode ? aimPct : delayPct;

  // 【APP71 任务2.4/2.5】双阶段看板文案与并发槽位实时详情
  const aimPhase = aimProgress.phase ?? "";
  const aimPhaseText =
    aimPhase === "SCREEN"
      ? t("proxies.aimBoard.screen")
      : aimPhase === "DEEP_PROBE"
        ? t("proxies.aimBoard.deep")
        : aimPhase === "FINISHED"
          ? t("proxies.aimBoard.finished")
          : aimPhase === "ERROR"
            ? t("proxies.aimBoard.error")
            : aimPhase === "CANCELLED"
              ? t("proxies.aimBoard.cancelled")
              : t("proxies.aimBoard.start");
  const activeServiceLines = (aimProgress.currentServices ?? []).filter(Boolean);
  const aimBoardError = aimProgress.errorMessage || aimLastError;

  // 【APP56 任务2.2】Pro + Go AIM 且尚无解锁标识时自动补一次全量探测
  const aimAutoProbeRef = useRef(false);
  useEffect(() => {
    if (!isProAimMode) {
      aimAutoProbeRef.current = false;
      return;
    }
    if (coreStatus !== "running") return;
    if (aimAutoProbeRef.current || aimProbing || aimResultCount > 0) return;
    aimAutoProbeRef.current = true;
    runGoAimProbe().catch(() => undefined);
  }, [isProAimMode, coreStatus, aimProbing, aimResultCount]);

  const resetFilters = () => {
    setKeyword("");
  };

  /// 【APP56 任务2.2】排序规则：
  /// - 非 Pro 或未开启 Go AIM：有效延迟(≥5)升序 → 未测速中间 → 超时最后；
  /// - Pro + Go AIM：AIM 支持节点优先（延迟升序，同延迟徽章多者优先）
  ///   → 其余有效延迟升序 → 未测速/超时末尾。
  const sorted = useMemo(() => {
    const badges = (n: ProxyEntry) => aimScoreOf(aimResults[n.name]);
    const byDelay = (a: ProxyEntry, b: ProxyEntry) =>
      (lastDelay(a) as number) - (lastDelay(b) as number);
    const valid = filtered.filter((n) => isValidDelay(lastDelay(n)));
    const unknown = filtered.filter((n) => lastDelay(n) === undefined);
    const timedOut = filtered.filter((n) => {
      const d = lastDelay(n);
      return typeof d === "number" && !isValidDelay(d);
    });
    if (isProAimMode) {
      const aimFirst = valid
        .filter((n) => badges(n) > 0)
        .sort((a, b) => {
          const diff = byDelay(a, b);
          return diff !== 0 ? diff : badges(b) - badges(a);
        });
      const rest = valid.filter((n) => badges(n) === 0).sort(byDelay);
      return [...aimFirst, ...rest, ...unknown, ...timedOut];
    }
    return [...valid.sort(byDelay), ...unknown, ...timedOut];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtered, delays, failed, testing, isProAimMode, aim]);

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
      {/* 【APP56 任务1.1】红框分类胶囊行已删除：搜索框 + 🎯 AIM检测 + ⚡ 测速 单行布局 */}
      <div className="flex w-full items-center gap-2">
        <div className="flex min-w-0 flex-1 items-center gap-2 rounded-xl border border-border bg-surface-card px-3 py-2">
          <Search size={14} className="shrink-0 text-gray-500" />
          <input
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder={t("proxies.searchNodes")}
            className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-gray-600"
          />
        </div>
        <button
          disabled={!proActive}
          onClick={proActive ? handleAimProbe : undefined}
          className={clsx(
            "flex shrink-0 items-center gap-1.5 rounded-xl border border-border px-3 py-2 text-[13px] font-bold transition-colors active:opacity-75",
            proActive
              ? "bg-surface-card text-gray-200 hover:border-accent/40"
              : "bg-glass text-gray-500 opacity-50 cursor-not-allowed",
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
            <Lock size={12} className="shrink-0 opacity-70" />
          ) : (
            <span aria-hidden className="shrink-0">🎯</span>
          )}
          <span className="whitespace-nowrap">{t("proxies.goAim.detect")}</span>
          {aimRunning && (
            <span className="tabular-nums text-[11px]">{aimProgress.percent}%</span>
          )}
        </button>
        <button
          onClick={handleTest}
          disabled={testing || delayProgress.running || nodes.length === 0}
          className="flex shrink-0 items-center gap-1.5 rounded-xl bg-[#007AFF] px-3.5 py-2 text-[13px] font-bold text-white active:opacity-80 disabled:opacity-50 disabled:cursor-not-allowed"
          title={t("proxies.speedTest")}
        >
          <Zap size={13} className={clsx("shrink-0", testing && "animate-pulse")} />
          {testing || delayProgress.running ? (
            <span className="tabular-nums">{delayProgress.percent}%</span>
          ) : (
            <span className="whitespace-nowrap">{t("proxies.speedTest")}</span>
          )}
        </button>
      </div>

      {/* 【APP56 任务1.2】蓝框 / 绿框：上下两行 + 实时进度条 */}
      <div className="flex flex-col gap-1.5 px-1 py-1.5">
        <div className="flex min-w-0 items-center gap-1.5 truncate text-[13px] font-semibold text-gray-400">
          <span className="shrink-0">{t("proxies.current")}</span>
          <span className="truncate font-bold text-[#007AFF] dark:text-[#0A84FF]">
            {current || t("proxies.notSelected")}
          </span>
          <span className="shrink-0">·</span>
          <span
            className={clsx(
              "shrink-0",
              coreStatus === "running"
                ? "text-[#24B414] dark:text-[#30D158]"
                : "text-gray-400",
            )}
          >
            {coreStatus === "running"
              ? t("proxies.kernelRunning")
              : t("proxies.kernelStoppedPreview")}
          </span>
        </div>
        <div className="flex min-w-0 items-center gap-2 text-xs text-gray-400">
          <span className="truncate tabular-nums">
            {isProAimMode
              ? t("proxies.progress.aimLine", {
                  aim: supportedAimCount,
                  done: aimDone,
                  total: totalCount,
                  percent: aimPct,
                })
              : t("proxies.progress.nodesLine", {
                  done: delayDone,
                  total: totalCount,
                  percent: delayPct,
                })}
          </span>
          {isProAimMode && aimRunning && (
            <span className="shrink-0 font-semibold tabular-nums text-[#24B414] dark:text-[#30D158]">
              {aimProgress.percent}%
            </span>
          )}
        </div>
        <div className="h-1 w-full overflow-hidden rounded-full bg-surface-elevated">
          <span
            className={clsx(
              "block h-full rounded-full transition-all",
              isProAimMode
                ? "bg-[#24B414] dark:bg-[#30D158]"
                : "bg-[#007AFF] dark:bg-[#0A84FF]",
            )}
            style={{ width: `${progressPct}%` }}
          />
        </div>

        {/* 【APP71 任务2.4】双阶段看板：快筛最高 20%，深测 20~99%，
            完成才 100%；并发槽位 / 存活 / 耗时 / 失败原因一目了然 */}
        {isProAimMode &&
          (aimRunning || aimPhase === "ERROR" || aimPhase === "CANCELLED") && (
            <div className="mt-0.5 flex flex-col gap-1 rounded-xl border border-border bg-surface-card px-3 py-2 text-[11px]">
              <div className="flex items-center justify-between gap-2">
                <span className="font-bold text-gray-200">{aimPhaseText}</span>
                <span className="tabular-nums font-semibold text-gray-300">
                  {aimProgress.percent}%
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-gray-400">
                <span className="tabular-nums">
                  {t("proxies.aimBoard.alive", {
                    alive: aimProgress.fastAlive ?? 0,
                    total: aimProgress.fastTotal ?? aimProgress.total ?? 0,
                  })}
                </span>
                {(aimProgress.fullTotal ?? 0) > 0 && (
                  <span className="tabular-nums">
                    {t("proxies.aimBoard.deepProgress", {
                      done: aimProgress.done ?? aimProgress.fullDone ?? 0,
                      total: aimProgress.fullTotal ?? 0,
                    })}
                  </span>
                )}
                {(aimProgress.activeSlots ?? 0) > 0 && (
                  <span className="tabular-nums">
                    {t("proxies.aimBoard.slots", {
                      n: aimProgress.activeSlots ?? 0,
                    })}
                  </span>
                )}
                {(aimProgress.elapsedMs ?? 0) > 0 && (
                  <span className="tabular-nums">
                    {Math.round((aimProgress.elapsedMs ?? 0) / 1000)}s
                  </span>
                )}
              </div>
              {activeServiceLines.length > 0 && (
                <div className="truncate text-gray-500">
                  {activeServiceLines.join(" · ")}
                </div>
              )}
              {aimBoardError && (
                <div className="text-[#FF453A] dark:text-[#FF6961]">{aimBoardError}</div>
              )}
            </div>
          )}
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
          const aimResult = aimResults[node.name];
          /// 【APP74 任务5.1】列表只给 VERIFIED 渲染徽章；PROXY_FAILED 加红标
          const aimPlatforms = proActive ? aimListBadgesOf(aimResult) : [];
          const proxyFailed = aimResult?.overallStatus === "PROXY_FAILED";
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
                  {/* 【APP75 任务3.3】PROXY_FAILED 显示「代理不可用」红标 */}
                  {proxyFailed && (
                    <span
                      title="PROXY_FAILED"
                      className="shrink-0 px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 text-[10px] tracking-wide"
                    >
                      代理不可用
                    </span>
                  )}
                  {/* 无 AIM 平台徽章时保持紧凑单行：协议标签内联显示 */}
                  {!proxyFailed && aimPlatforms.length === 0 && (
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
                  自然换行，不挤占第一行的名称与延迟；无结果时不渲染 */}
              {(aimPlatforms.length > 0 || aimResult?.probed) && (
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5 pl-4">
                  <span className="px-1.5 py-0.5 rounded bg-surface-hover text-[11px] font-mono uppercase tracking-wide text-gray-400">
                    {protocolTag(node.type)}
                  </span>
                  {aimPlatforms.map((tag) => {
                    const verdict =
                      aimResult?.services?.[tag]?.verdict ?? "UNKNOWN";
                    return (
                      <span
                        key={tag}
                        title={`${tag}: ${verdict}`}
                        className={clsx(
                          "px-1.5 py-0.5 rounded border text-[11px] font-medium",
                          AIM_VERDICT_STYLE[verdict] ?? AIM_VERDICT_STYLE.UNKNOWN,
                        )}
                      >
                        {tag}
                      </span>
                    );
                  })}
                  {aimResult?.probed && (
                    <span
                      role="button"
                      tabIndex={-1}
                      onClick={(e) => {
                        e.stopPropagation();
                        setDetailNode(node.name);
                      }}
                      className="px-1.5 py-0.5 rounded border border-border text-[11px] text-gray-400 hover:border-accent/40 hover:text-accent"
                    >
                      {t("proxies.aimDetail.detail")}
                    </span>
                  )}
                </div>
              )}
            </button>
          );
        })}
      </div>
      )}
      {/* 【APP71 任务4】单节点 7 平台五态详情 */}
      {detailNode && (
        <AimNodeDetailModal
          node={detailNode}
          protocol={protocolTag(
            nodes.find((n) => n.name === detailNode)?.type ?? "",
          )}
          result={aimResults[detailNode]}
          onClose={() => setDetailNode(null)}
        />
      )}
    </div>
  );
}
