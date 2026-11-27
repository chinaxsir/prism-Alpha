import type { CusModule, CusModuleStats } from "@/api/ipc";

export const CUSTOM_MODULE_IDS = {
  rewrites: "local-custom-rewrites",
  mitm: "local-custom-mitm",
  scripts: "local-custom-scripts",
  host: "local-custom-host",
} as const;

export type CustomModuleKind = keyof typeof CUSTOM_MODULE_IDS;

/** 改写动作（与后端 go_cus.rs normalize_rewrite_action 对齐） */
export const REWRITE_ACTION_OPTIONS = [
  "reject",
  "reject-200",
  "reject-img",
  "reject-tinygif",
  "reject-dict",
  "reject-array",
  "302",
  "307",
  "request-header",
  "response-header",
] as const;

export type RewriteActionOption = (typeof REWRITE_ACTION_OPTIONS)[number];

export interface ParsedRewrite {
  pattern: string;
  action: string;
  target?: string;
  ruleIndex: number;
  rawLine: string;
}

export interface ParsedScript {
  name: string;
  type: string;
  pattern: string;
  scriptPath: string;
  requiresBody: boolean;
  inlineCode?: string;
  ruleIndex: number;
  rawLine: string;
}

export interface ParsedMitmHost {
  /** 保留原始写法（小写），如 *.example.com 或 -accounts.example.com */
  raw: string;
  /** 去掉前导 - 与 *. 后的主机名 */
  host: string;
  isWildcard: boolean;
  isExcluded: boolean;
}

export interface ParsedHostMapping {
  domain: string;
  value: string;
  rawLine: string;
}

export interface ParsedModuleLocal {
  rulesCount: number;
  rewrites: ParsedRewrite[];
  scripts: ParsedScript[];
  mitmHosts: ParsedMitmHost[];
  hosts: ParsedHostMapping[];
  dnsServers: string[];
  inlineScripts: Record<string, string>;
}

export function shortHash(input: string): string {
  let h = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

export function isValidRegex(pattern: string): boolean {
  if (!pattern.trim()) return false;
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

function fileNameOf(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx >= 0 ? path.slice(idx + 1) : path;
}

function isRewriteSectionName(name: string): boolean {
  const n = name.trim().toLowerCase();
  return (
    n === "url rewrite" ||
    n === "rewrite_local" ||
    n === "rewrite" ||
    n === "header rewrite"
  );
}

function normalizeRewriteAction(actionRaw: string): string | null {
  const a = actionRaw.trim().toLowerCase();
  switch (a) {
    case "reject":
    case "reject-drop":
    case "reject-403":
      return "reject";
    case "reject-200":
    case "reject-img":
    case "reject-tinygif":
    case "reject-dict":
    case "reject-array":
    case "302":
    case "307":
      return a;
    case "request-header":
    case "header":
    case "header-add":
    case "header-replace":
    case "header-del":
      return "request-header";
    case "response-header":
      return "response-header";
    case "echo":
    case "none":
      return "none";
    default:
      return null;
  }
}

/** 提取内联脚本代码块：`# --- inline script <hash> begin ---` ... `# --- inline script <hash> end ---` */
export function extractInlineScripts(raw: string): Record<string, string> {
  const map: Record<string, string> = {};
  let currentId: string | null = null;
  let buf: string[] = [];

  for (const rawLine of raw.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!currentId) {
      const m = trimmed.match(/^#\s*---\s*inline script\s+(\S+)\s+begin\s*---$/i);
      if (m) {
        currentId = m[1];
        buf = [];
      }
      continue;
    }
    const endRe = new RegExp(
      `^#\\s*---\\s*inline script\\s+${currentId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s+end\\s*---$`,
      "i",
    );
    if (endRe.test(trimmed)) {
      map[`inline:${currentId}`] = buf.join("\n");
      currentId = null;
      buf = [];
      continue;
    }
    if (rawLine.startsWith("# ")) {
      buf.push(rawLine.slice(2));
    } else if (rawLine.startsWith("#")) {
      buf.push(rawLine.slice(1));
    } else {
      buf.push(rawLine);
    }
  }
  return map;
}

function parseScriptLine(
  line: string,
  inlineScripts: Record<string, string>,
  ruleIndex: number,
): ParsedScript | null {
  let name: string | null = null;
  let kvText = line;
  const eqIdx = line.indexOf("=");
  if (eqIdx > 0) {
    const left = line.slice(0, eqIdx).trim();
    const right = line.slice(eqIdx + 1);
    if (/\btype\s*=/i.test(right)) {
      name = left;
      kvText = right;
    }
  }

  let type = "";
  let pattern = "";
  let scriptPath = "";
  let requiresBody = false;
  let tag: string | null = null;
  const firstTwo: string[] = [];

  for (const rawPart of kvText.split(",")) {
    const part = rawPart.trim();
    if (!part) continue;
    const kvEq = part.indexOf("=");
    if (kvEq > 0) {
      const k = part.slice(0, kvEq).trim().toLowerCase();
      const v = part.slice(kvEq + 1).trim();
      if (k === "type") type = v.toLowerCase();
      else if (k === "pattern") pattern = v;
      else if (k === "script-path" || k === "path") scriptPath = v;
      else if (k === "requires-body") requiresBody = v === "1" || v.toLowerCase() === "true";
      else if (k === "tag") tag = v;
    } else if (firstTwo.length < 2) {
      firstTwo.push(part);
    }
  }

  if (!type && firstTwo[0]) type = firstTwo[0].toLowerCase();
  if (!pattern && firstTwo[1]) pattern = firstTwo[1];
  if (!type || !scriptPath) return null;

  return {
    name: name || tag || fileNameOf(scriptPath),
    type,
    pattern,
    scriptPath,
    requiresBody,
    inlineCode: inlineScripts[scriptPath],
    ruleIndex,
    rawLine: line,
  };
}

function parseRewriteOrScriptLine(
  line: string,
  inlineScripts: Record<string, string>,
  nextRewriteIdx: number,
  nextScriptIdx: number,
): { rewrite?: ParsedRewrite; script?: ParsedScript } {
  const tokens = line.split(/\s+/);
  if (tokens.length < 3) return {};
  const pattern = tokens[0];

  // QuanX: <regex> url <action> [target...]
  if (tokens[1].toLowerCase() === "url") {
    const actionRaw = tokens[2].toLowerCase();
    const target = tokens.slice(3).join(" ").trim();
    if (actionRaw.startsWith("script-")) {
      if (!target) return {};
      return {
        script: {
          name: fileNameOf(target),
          type: actionRaw.includes("response") ? "http-response" : "http-request",
          pattern,
          scriptPath: target,
          requiresBody: actionRaw.includes("body"),
          inlineCode: inlineScripts[target],
          ruleIndex: nextScriptIdx,
          rawLine: line,
        },
      };
    }
    const action = normalizeRewriteAction(actionRaw);
    if (!action) return {};
    return {
      rewrite: {
        pattern,
        action,
        target: target || undefined,
        ruleIndex: nextRewriteIdx,
        rawLine: line,
      },
    };
  }

  // <regex> request-header|response-header <spec>
  const second = tokens[1].toLowerCase();
  if (second === "request-header" || second === "response-header") {
    const target = tokens.slice(2).join(" ").trim();
    if (!target) return {};
    return {
      rewrite: {
        pattern,
        action: second,
        target,
        ruleIndex: nextRewriteIdx,
        rawLine: line,
      },
    };
  }

  // Surge [Header Rewrite]: <regex> header-add|header-replace|header-del ...
  if (second === "header-add" || second === "header-replace" || second === "header-del") {
    return {
      rewrite: {
        pattern,
        action: "request-header",
        target: tokens.slice(1).join(" "),
        ruleIndex: nextRewriteIdx,
        rawLine: line,
      },
    };
  }

  // Surge / Shadowrocket: <regex> - <302|307> <target>
  if ((tokens[1] === "-" || tokens[1] === "_") && tokens.length >= 4) {
    const act = tokens[2].toLowerCase();
    if (act === "302" || act === "307") {
      return {
        rewrite: {
          pattern,
          action: act,
          target: tokens.slice(3).join(" "),
          ruleIndex: nextRewriteIdx,
          rawLine: line,
        },
      };
    }
  }

  // Surge / Shadowrocket: <regex> <target|-|_> <action>
  const actionRaw = tokens[tokens.length - 1].toLowerCase();
  const target = tokens.slice(1, -1).join(" ");
  const isDash = target === "-" || target === "_";

  if (actionRaw.startsWith("script-")) {
    if (!target || isDash) return {};
    return {
      script: {
        name: fileNameOf(target),
        type: actionRaw.includes("response") ? "http-response" : "http-request",
        pattern,
        scriptPath: target,
        requiresBody: actionRaw.includes("body"),
        inlineCode: inlineScripts[target],
        ruleIndex: nextScriptIdx,
        rawLine: line,
      },
    };
  }

  const action = normalizeRewriteAction(actionRaw);
  if (!action) return {};
  if ((action === "302" || action === "307") && isDash) return {};
  return {
    rewrite: {
      pattern,
      action,
      target: isDash ? undefined : target,
      ruleIndex: nextRewriteIdx,
      rawLine: line,
    },
  };
}

/** 解析 Stash YAML 中的简易 rules（用于本地展示统计） */
function parseStashRulesCount(raw: string): number {
  let inRules = false;
  let count = 0;
  for (const rawLine of raw.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (/^rules\s*:/i.test(trimmed)) {
      inRules = true;
      continue;
    }
    if (inRules) {
      if (trimmed.startsWith("- ")) {
        count += 1;
      } else if (/^[a-zA-Z0-9_-]+\s*:/.test(trimmed)) {
        inRules = false;
      }
    }
  }
  return count;
}

/**
 * 统一解析模块内容（与后端 go_cus.rs parse_universal_module 保持一致）：
 * - 修复 header[1] 去括号导致 sectionLines 恒空的 bug
 * - 支持 Rule / URL Rewrite / Header Rewrite / Script / MitM / Host / General DNS / Stash YAML
 * - 精准保留 ruleIndex 与 inlineScripts 源码，供命中统计与编辑复用
 */
export function parseUniversalModuleLocal(raw: string): ParsedModuleLocal {
  const inlineScripts = extractInlineScripts(raw);
  const out: ParsedModuleLocal = {
    rulesCount: 0,
    rewrites: [],
    scripts: [],
    mitmHosts: [],
    hosts: [],
    dnsServers: [],
    inlineScripts,
  };

  if (raw.trimStart().startsWith("name:")) {
    const stashRules = parseStashRulesCount(raw);
    if (stashRules > 0) {
      out.rulesCount = stashRules;
      return out;
    }
  }

  let section = "";
  const seenMitm = new Set<string>();

  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("#") || line.startsWith("//") || line.startsWith(";")) {
      continue;
    }
    const header = line.match(/^\[(.+)\]$/);
    if (header) {
      section = header[1].trim().toLowerCase();
      continue;
    }

    if (section === "rule" || section === "filter_local") {
      if (line.split(",").length >= 2) {
        out.rulesCount += 1;
      }
    } else if (isRewriteSectionName(section)) {
      const parsed = parseRewriteOrScriptLine(
        line,
        inlineScripts,
        out.rewrites.length,
        out.scripts.length,
      );
      if (parsed.script) out.scripts.push(parsed.script);
      else if (parsed.rewrite) out.rewrites.push(parsed.rewrite);
    } else if (section === "script") {
      const parsed = parseScriptLine(line, inlineScripts, out.scripts.length);
      if (parsed) out.scripts.push(parsed);
    } else if (section === "mitm") {
      const eq = line.indexOf("=");
      if (eq < 0) continue;
      const key = line.slice(0, eq).trim().toLowerCase();
      if (key !== "hostname") continue;
      const val = line.slice(eq + 1).replace(/%(?:append|insert)%/gi, "");
      for (const part of val.split(",")) {
        const cleaned = part.trim().toLowerCase();
        if (!cleaned || cleaned === "-") continue;
        if (seenMitm.has(cleaned)) continue;
        seenMitm.add(cleaned);
        const isExcluded = cleaned.startsWith("-");
        const withoutSign = isExcluded ? cleaned.slice(1).trim() : cleaned;
        const isWildcard = withoutSign.startsWith("*.");
        const host = isWildcard ? withoutSign.slice(2) : withoutSign;
        if (!host) continue;
        out.mitmHosts.push({
          raw: cleaned,
          host,
          isWildcard,
          isExcluded,
        });
      }
    } else if (section === "host") {
      const eq = line.indexOf("=");
      if (eq < 0) continue;
      const domain = line.slice(0, eq).trim().replace(/^\*\./, "").toLowerCase();
      const value = line.slice(eq + 1).trim();
      if (domain && value) {
        out.hosts.push({ domain, value, rawLine: line });
      }
    } else if (section === "general") {
      const eq = line.indexOf("=");
      if (eq < 0) continue;
      const key = line.slice(0, eq).trim().toLowerCase();
      if (key === "dns-server") {
        for (const d of line.slice(eq + 1).split(",")) {
          const item = d.trim();
          if (item && !out.dnsServers.includes(item)) {
            out.dnsServers.push(item);
          }
        }
      }
    }
  }

  return out;
}

export function computeModuleStats(raw: string): CusModuleStats {
  const parsed = parseUniversalModuleLocal(raw);
  return {
    rules: parsed.rulesCount,
    rewrites: parsed.rewrites.length,
    scripts: parsed.scripts.length,
    mitmHosts: parsed.mitmHosts.length,
    hosts: parsed.hosts.length,
  };
}

// ============================== 自定义模块条目增删改 ==============================

function ensureSection(
  raw: string | undefined,
  name: string,
  desc: string,
  sectionHeader: string,
): string {
  if (!raw || !raw.trim()) {
    return `#!name=${name}\n#!desc=${desc}\n${sectionHeader}\n`;
  }
  const hasSection = raw
    .split(/\r?\n/)
    .some((l) => l.trim().toLowerCase() === sectionHeader.toLowerCase());
  if (hasSection) return raw.trimEnd() + "\n";
  return `${raw.trimEnd()}\n${sectionHeader}\n`;
}

export function upsertCustomRewrite(
  existingRaw: string | undefined,
  name: string,
  desc: string,
  newLine: string,
  replaceOldLine?: string,
): { raw: string; duplicate: boolean } {
  const base = ensureSection(existingRaw, name, desc, "[URL Rewrite]");
  const lines = base.split(/\r?\n/);
  const trimmedNew = newLine.trim();
  const trimmedOld = replaceOldLine?.trim();

  if (
    lines.some((l) => l.trim() === trimmedNew) &&
    trimmedNew !== trimmedOld
  ) {
    return { raw: base, duplicate: true };
  }

  if (trimmedOld) {
    let replaced = false;
    const next = lines.map((l) => {
      if (!replaced && l.trim() === trimmedOld) {
        replaced = true;
        return trimmedNew;
      }
      return l;
    });
    if (replaced) {
      return { raw: next.join("\n").trimEnd() + "\n", duplicate: false };
    }
  }

  return { raw: `${base.trimEnd()}\n${trimmedNew}\n`, duplicate: false };
}

export function removeCustomRewrite(
  existingRaw: string,
  targetLine: string,
): string {
  const trimmedTarget = targetLine.trim();
  let removed = false;
  const kept = existingRaw.split(/\r?\n/).filter((l) => {
    if (!removed && l.trim() === trimmedTarget) {
      removed = true;
      return false;
    }
    return true;
  });
  return kept.join("\n").trimEnd() + "\n";
}

export function upsertCustomMitmHosts(
  existingRaw: string | undefined,
  name: string,
  desc: string,
  inputHosts: string[],
): { raw: string; added: string[] } {
  const existingParsed = existingRaw
    ? parseUniversalModuleLocal(existingRaw).mitmHosts.map((h) => h.raw)
    : [];
  const normalized = inputHosts
    .map((h) => h.trim().toLowerCase())
    .filter((h) => Boolean(h) && h !== "-");
  const uniqueFresh = normalized.filter(
    (h, idx) => !existingParsed.includes(h) && normalized.indexOf(h) === idx,
  );
  if (uniqueFresh.length === 0) {
    return { raw: existingRaw ?? "", added: [] };
  }
  const merged = [...existingParsed, ...uniqueFresh];
  const raw = `#!name=${name}\n#!desc=${desc}\n[MITM]\nhostname = %APPEND% ${merged.join(", ")}\n`;
  return { raw, added: uniqueFresh };
}

export function removeCustomMitmHost(
  existingRaw: string,
  name: string,
  desc: string,
  rawHostToRemove: string,
): { raw: string; remaining: number } {
  const target = rawHostToRemove.trim().toLowerCase();
  const kept = parseUniversalModuleLocal(existingRaw)
    .mitmHosts.map((h) => h.raw)
    .filter((h) => h !== target);
  if (kept.length === 0) {
    return { raw: "", remaining: 0 };
  }
  return {
    raw: `#!name=${name}\n#!desc=${desc}\n[MITM]\nhostname = %APPEND% ${kept.join(", ")}\n`,
    remaining: kept.length,
  };
}

/** 从 rawContent 中移除指定 inline:<hash> 脚本条目及其完整 begin..end 注释块 */
export function removeCustomScript(
  existingRaw: string,
  scriptPath: string,
): string {
  const hash = scriptPath.startsWith("inline:")
    ? scriptPath.slice("inline:".length)
    : null;
  const beginRe = hash
    ? new RegExp(
        `^#\\s*---\\s*inline script\\s+${hash.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s+begin\\s*---$`,
        "i",
      )
    : null;
  const endRe = hash
    ? new RegExp(
        `^#\\s*---\\s*inline script\\s+${hash.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s+end\\s*---$`,
        "i",
      )
    : null;

  let skippingBlock = false;
  const kept: string[] = [];
  for (const line of existingRaw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (skippingBlock) {
      if (endRe && endRe.test(trimmed)) {
        skippingBlock = false;
      }
      continue;
    }
    if (beginRe && beginRe.test(trimmed)) {
      skippingBlock = true;
      continue;
    }
    if (
      !trimmed.startsWith("#") &&
      trimmed.includes(`script-path=${scriptPath}`)
    ) {
      continue;
    }
    kept.push(line);
  }
  return kept.join("\n").trimEnd() + "\n";
}

export function upsertCustomScript(
  existingRaw: string | undefined,
  moduleName: string,
  moduleDesc: string,
  params: {
    name: string;
    type: "http-request" | "http-response";
    pattern: string;
    code: string;
    oldScriptPath?: string;
  },
): string {
  const safeName = params.name.trim().replace(/[\s,=]/g, "-");
  const pattern = params.pattern.trim();
  const hash = shortHash(`${safeName}|${params.type}|${pattern}`);
  const scriptPath = `inline:${hash}`;

  let cleaned = existingRaw ?? "";
  if (params.oldScriptPath && params.oldScriptPath !== scriptPath && cleaned) {
    cleaned = removeCustomScript(cleaned, params.oldScriptPath);
  }
  if (cleaned) {
    cleaned = removeCustomScript(cleaned, scriptPath);
  }

  const base = ensureSection(cleaned, moduleName, moduleDesc, "[Script]");
  const line = `${params.type}, ${pattern}, script-path=${scriptPath}, tag=${safeName}, requires-body=1`;
  const codeLines = params.code
    .split(/\r?\n/)
    .map((l) => `# ${l}`)
    .join("\n");
  const block = `${line}\n# --- inline script ${hash} begin ---\n${codeLines}\n# --- inline script ${hash} end ---`;
  return `${base.trimEnd()}\n${block}\n`;
}

export function upsertCustomHost(
  existingRaw: string | undefined,
  name: string,
  desc: string,
  domain: string,
  value: string,
): { raw: string; duplicate: boolean } {
  const d = domain.trim().toLowerCase();
  const v = value.trim();
  const line = `${d} = ${v}`;
  const base = ensureSection(existingRaw, name, desc, "[Host]");
  const existing = parseUniversalModuleLocal(base).hosts;
  if (existing.some((h) => h.domain === d && h.value === v)) {
    return { raw: base, duplicate: true };
  }
  // 同域名覆盖旧映射，避免重复冲突
  const cleaned = existingRaw
    ? removeCustomHost(base, d)
    : base;
  return { raw: `${cleaned.trimEnd()}\n${line}\n`, duplicate: false };
}

export function removeCustomHost(existingRaw: string, domain: string): string {
  const target = domain.trim().toLowerCase();
  const kept = existingRaw.split(/\r?\n/).filter((l) => {
    const trimmed = l.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("[")) {
      return true;
    }
    const eq = trimmed.indexOf("=");
    if (eq < 0) return true;
    const d = trimmed.slice(0, eq).trim().replace(/^\*\./, "").toLowerCase();
    return d !== target;
  });
  return kept.join("\n").trimEnd() + "\n";
}

export type LegacyKind = "ai" | "media" | "cnDirect";

/** 旧版模板识别：仅按模板标题/首行精确匹配 */
export function legacyKindOf(m: CusModule): LegacyKind | null {
  const name = m.name.trim().toLowerCase();
  const raw = m.rawContent.toLowerCase();
  const first = raw.split(/\r?\n/, 1)[0] ?? "";
  const lists: Array<[LegacyKind, string[]]> = [
    ["ai", ["🤖 ai 服务分流", "ai services routing"]],
    ["media", ["🎬 流媒体解锁", "global media unlock"]],
    ["cnDirect", ["⚡ 国内直连加速", "cn & apple cdn direct"]],
  ];
  for (const [kind, names] of lists) {
    if (names.includes(name)) return kind;
    if (names.some((n) => first.includes(n))) return kind;
  }
  return null;
}
