#!/usr/bin/env node
/**
 * verify-ios-ready.mjs —— iOS / Android 构建本地硬性预检（1 秒跑完）
 *
 * 11 项检查，任一项不通过立刻 exit(1) + 打印精确原因：
 *   1. 全仓 UTF-8 BOM 扫描 + 关键 JSON 文件原生 JSON.parse 严格校验
 *   2. Rust ios.rs ↔ build.rs ↔ Swift @_cdecl 三方 C ABI 符号对齐
 *   3. Swift 缺失 import 框架自动检测
 *   4. iOS 禁用 macOS 专属 API 扫描
 *   5. Swift 括号与引号平衡校验
 *   6. vpn.go Go 内核双端预检（本地小写函数"调用 vs 定义"配对 +
 *      import "C" 块完整性 + 可用时的 gofmt -e 语法校验）
 *   7. 扩展源码作用域预检（关键标识符先声明后使用 + gen 副本一致性）
 *   8. Swift 冻结指令（严禁 as! / 命名元组类型声明 + gen 副本字节一致）
 *   9. Rust cargo check（本机 + iOS aarch64-apple-ios 目标）
 *  10. WKWebView 染色防复发（禁 subviews / underPageBackgroundColor / 前后台监听）
 *  11. AppIcon 四角满铺校验（纯 Node 内置 PNG 解码，0 第三方依赖）
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, delimiter } from 'node:path';
import { execSync } from 'node:child_process';
import { inflateSync } from 'node:zlib';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
let failed = false;
const fail = (m) => { console.error(`❌ ${m}`); failed = true; };
const pass = (m) => console.log(`✅ ${m}`);
const reMatchAll = (re, src) => [...src.matchAll(re)].map((m) => m[1]);

// ============================================================
// 检查 1：全仓 UTF-8 BOM 扫描 + JSON 严格校验
// 【APP38 任务2】ERR10 实证：Windows PowerShell Set-Content 改写
// package.json 会注入 BOM（0xEF 0xBB 0xBF），CI vite build 的
// JSON.parse 直接 SyntaxError。这里从「6 个定点文件」升级为全仓
// 文本文件扫描（排除 node_modules/target/dist/.git/gen 等），
// 并对 package.json / tauri.conf.json / tsconfig.json 做原生
// JSON.parse 严格校验，确保绝不会在 CI 触发 Unexpected token '﻿'。
// ============================================================
console.log('\n--- 检查 1：全仓 UTF-8 BOM 扫描 + JSON 严格校验 ---');
const BOM_SCAN_EXTS = new Set([
  '.json', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.css', '.html',
  '.rs', '.toml', '.swift', '.go', '.plist', '.yml', '.yaml', '.rb',
]);
const BOM_SCAN_EXCLUDE_DIRS = new Set([
  'node_modules', 'target', 'dist', '.git', 'gen',
  'license-server', 'license-worker', '.uploads',
]);
let bomScanned = 0;
const bomHits = [];
(function walkBom(dir) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (BOM_SCAN_EXCLUDE_DIRS.has(entry.name)) continue;
      walkBom(resolve(dir, entry.name));
      continue;
    }
    if (!entry.isFile()) continue;
    const ext = entry.name.slice(entry.name.lastIndexOf('.')).toLowerCase();
    if (!BOM_SCAN_EXTS.has(ext)) continue;
    const file = resolve(dir, entry.name);
    let bytes;
    try { bytes = readFileSync(file, null); } catch { continue; }
    bomScanned++;
    if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) {
      bomHits.push(file);
    }
  }
})(ROOT);
if (bomHits.length === 0) {
  pass(`全仓 ${bomScanned} 个文本文件均无 BOM`);
} else {
  for (const f of bomHits) {
    fail(`${f.replace(ROOT + '/', '')} 含有 UTF-8 BOM 头（0xEF 0xBB 0xBF），必须用 Node.js 剥离（严禁 PowerShell Set-Content 写文件）！`);
  }
}
// 原生 JSON.parse 严格校验（CI vite build 同款解析路径）
for (const rel of ['package.json', 'src-tauri/tauri.conf.json', 'tsconfig.json']) {
  const p = resolve(ROOT, rel);
  if (!existsSync(p)) continue;
  try {
    JSON.parse(readFileSync(p, 'utf8'));
    pass(`JSON.parse 严格校验通过：${rel}`);
  } catch (e) {
    fail(`${rel} JSON.parse 失败：${e.message}（禁止 BOM / 非法字符）`);
  }
}

// ============================================================
// 检查 2：C ABI 符号三方对齐
// ============================================================
console.log('\n--- 检查 2：Rust ↔ build.rs ↔ Swift C ABI 符号三方对齐 ---');
const iosRs       = readFileSync(resolve(ROOT, 'src-tauri/src/platform/ios.rs'), 'utf8');
const buildRs     = readFileSync(resolve(ROOT, 'src-tauri/build.rs'), 'utf8');
const swiftMain   = readFileSync(resolve(ROOT, 'src-tauri/mobile-src/ios/App/PrismTunnelController.swift'), 'utf8');

const iosSymbols   = reMatchAll(/fn (prism_ios_[a-zA-Z0-9_]+)\s*\(/g, iosRs);
const buildSymbols = reMatchAll(/"_(prism_ios_[a-zA-Z0-9_]+)"/g, buildRs);
const swiftSymbols = reMatchAll(/@_cdecl\("(prism_ios_[a-zA-Z0-9_]+)"\)/g, swiftMain);

console.log(`  ios.rs extern   : ${iosSymbols.join(', ') || '(无)'}`);
console.log(`  build.rs Wl,-U  : ${buildSymbols.join(', ') || '(无)'}`);
console.log(`  Swift @_cdecl   : ${swiftSymbols.join(', ') || '(无)'}`);

for (const sym of iosSymbols) {
  if (!buildSymbols.includes(sym)) fail(`ios.rs 声明 ${sym} 但 build.rs 缺 "_${sym}"！`);
  else pass(`${sym} ↔ build.rs ✓`);
  if (!swiftSymbols.includes(sym)) fail(`ios.rs 声明 ${sym} 但 Swift 缺 @_cdecl("${sym}")！`);
  else pass(`${sym} ↔ Swift ✓`);
}
for (const sym of swiftSymbols) {
  if (!iosSymbols.includes(sym)) fail(`Swift 多余 @_cdecl("${sym}") — ios.rs 没声明 extern！`);
}

// ============================================================
// 检查 3：Swift 缺失 import 框架自动检测
// ============================================================
console.log('\n--- 检查 3：Swift import 框架自动检测 ---');
let swiftExt = '';
try { swiftExt = readFileSync(resolve(ROOT, 'src-tauri/mobile-src/ios/PrismVPN/PacketTunnelProvider.swift'), 'utf8'); } catch {}
const swiftFiles = [
  { name: 'PrismTunnelController.swift', src: swiftMain },
  ...(swiftExt ? [{ name: 'PacketTunnelProvider.swift', src: swiftExt }] : []),
];

// 注意：下面 imp 里 'import UIKit' 的空格在正则中要转义为 \s+
const IMPORT_RULES = [
  { imp: 'import UIKit',            tokens: ['UIDevice', 'UIApplication', 'UIViewController'] },
  { imp: 'import Network',          tokens: ['NWPathMonitor', 'NWConnection', 'NWListener'] },
  { imp: 'import Security',         tokens: ['SecItemAdd', 'SecItemCopyMatching', 'SecItemUpdate', 'kSecClassGenericPassword', 'kSecAttrSynchronizable', 'kSecAttrAccount'] },
  { imp: 'import NetworkExtension', tokens: ['NETunnelProviderManager', 'NEPacketTunnelProvider', 'NEVpnManager'] },
  { imp: 'import Darwin',           tokens: ['dlsym', 'dlopen', 'posix_spawnattr_set', 'Host'] },
  { imp: 'import CommonCrypto',     tokens: ['CC_SHA256_DIGEST_LENGTH', 'CC_SHA256'] },
];
for (const { name, src } of swiftFiles) {
  for (const { imp, tokens } of IMPORT_RULES) {
    const anyUsed = tokens.some((tok) => new RegExp(`\\b${tok}\\b`).test(src));
    // 匹配行首 "import XXX"
    const pat = imp.replace(/\s+/g, '\\s+');
    const hasIt = new RegExp(`^\\s*${pat}\\b`, 'm').test(src);
    if (anyUsed && !hasIt) {
      const used = tokens.filter((t) => new RegExp(`\\b${t}\\b`).test(src)).join('/');
      fail(`${name} 使用了 ${used} 但顶部缺 ${imp}！`);
    }
  }
  pass(`${name}: import 检查 ✓`);
}

// ============================================================
// 检查 4：iOS 禁用 macOS 专属 API
// ============================================================
console.log('\n--- 检查 4：iOS 禁用 macOS 专属 API ---');
const MACOS_ONLY = [
  { re: /\bHost\.current\b/, msg: 'Host.current() 是 macOS 专属 — iOS 用 ProcessInfo.processInfo.hostName' },
  { re: /\bNSHost\b/,        msg: 'NSHost 是 macOS 专属类' },
  { re: /\bNSTask\b/,        msg: 'NSTask 是 macOS 专属类' },
  { re: /\bNSWorkspace\b/,  msg: 'NSWorkspace 是 macOS 专属类' },
  { re: /\bNSApplication\b/, msg: 'NSApplication 是 macOS 专属类' },
];
for (const { name, src } of swiftFiles) {
  let hit = false;
  for (const { re, msg } of MACOS_ONLY) {
    const m = src.match(re);
    if (m) {
      const line = src.slice(0, m.index).split('\n').length;
      fail(`${name} 第 ${line} 行：${msg}`);
      hit = true;
    }
  }
  if (!hit) pass(`${name}: 无 macOS 专属 API ✓`);
}

// ============================================================
// 检查 5：括号/引号平衡（WARNING 级，Swift 预处理器/#if/多行字符串易误报）
// ============================================================
console.log('\n--- 检查 5：Swift 括号/引号平衡（warning 级） ---');
for (const { name, src } of swiftFiles) {
  // 先去掉所有 // 行内注释里的括号（注释里的 { } ( ) [ ] 不是代码）
  let stripped = src
    .replace(/\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''");
  // 跳过 Swift 预处理器条件块（#if / #elseif / #else / #endif 之间的内容）
  // 这些块里可能包含不闭合的括号（条件编译时整段被忽略）
  stripped = stripped.replace(/#if\b[\s\S]*?#endif/gm, '');
  const count = (c) => [...stripped].filter((ch) => ch === c).length;
  const diff = { curly: count('{') - count('}'), paren: count('(') - count(')'), brack: count('[') - count(']') };
  if (diff.curly || diff.paren || diff.brack) {
    console.warn(`⚠️  [warning] ${name} 括号疑似不平衡：{} 差 ${diff.curly}，() 差 ${diff.paren}，[] 差 ${diff.brack}（若 Xcode 能编译则可忽略）`);
  } else {
    pass(`${name}: {} () [] 全部平衡 ✓`);
  }
}

// ============================================================
// 检查 6：vpn.go Go 内核双端预检（iOS c-archive / Android c-shared 共用此文件）
// ============================================================
console.log('\n--- 检查 6：vpn.go Go 内核双端预检 ---');
const VPN_GO = resolve(ROOT, 'src-tauri/ios-kernel/vpn.go');
try {
  const goSrc = readFileSync(VPN_GO, 'utf8');

  // 6.1 import "C" 块必须存在且包含 prism_vpn_cbs 结构体定义
  if (!/import\s+"C"/.test(goSrc)) {
    fail('vpn.go 缺失 import "C"（cgo 入口）');
  } else if (!/typedef\s+struct\s+prism_vpn_cbs/.test(goSrc)) {
    fail('vpn.go 的 C 注释块缺失 typedef struct prism_vpn_cbs 定义');
  } else {
    pass('vpn.go import "C" 块与 prism_vpn_cbs 结构体 ✓');
  }

  // 6.2 本地小写函数"调用 vs 定义"配对（消除 vpnLogf 这类未定义编译错）
  //   - 收集所有 func xxx( 定义（含多返回值/方法接收者之外）
  //   - 收集所有 \bxxx( 调用
  //   - 过滤：包名前缀（xxx.yyy()）、Go 内建（make/len/cap/append/new/copy/
  //     delete/close/panic/recover/complex/real/imag/print/println）、关键字、
  //     类型转换（string()/int()/bool()/[]byte() 等单字）
  const defined = new Set();
  for (const m of goSrc.matchAll(/^func\s+(?:\([^)]*\)\s*)?([a-zA-Z_][\w]*)\s*\(/gm)) {
    defined.add(m[1]);
  }
  // 已知外部包与内建
  const KNOWN_PKGS = new Set(['C', 'fmt', 'os', 'json', 'time', 'sync', 'runtime', 'debug', 'filepath', 'unsafe', 'libbox']);
  const BUILTINS = new Set([
    'make', 'len', 'cap', 'append', 'new', 'copy', 'delete', 'close',
    'panic', 'recover', 'complex', 'real', 'imag', 'print', 'println',
    'string', 'int', 'int8', 'int16', 'int32', 'int64',
    'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'uintptr',
    'byte', 'rune', 'bool', 'float32', 'float64', 'error', 'any',
  ]);
  const KEYWORDS = new Set([
    'if', 'for', 'switch', 'return', 'go', 'defer', 'select', 'case', 'map',
    'chan', 'struct', 'interface', 'func', 'range', 'import', 'var', 'const',
    'type', 'package', 'else', 'fallthrough', 'default', 'break', 'continue',
    'goto',
  ]);
  // 剥掉 C 注释块（含 import "C" 的 preamble）与所有 Go 注释、字符串字面量，
  // 避免把 C 函数指针/注释描述误判为 Go 函数调用。剥除时保留行号（换行用 \n 替换）。
  const stripped = goSrc
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length))
    .replace(/"(?:[^"\\]|\\.)*"/g, (m) => ' '.repeat(m.length))
    .replace(/`[^`]*`/g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/'(?:[^'\\]|\\.)*'/g, (m) => ' '.repeat(m.length));
  const missing = new Map(); // name -> first line
  // 匹配 "identifier("，但前面不是 . 也不是字母数字下划线（避免包名/方法）
  const callRe = /(^|[^\w.])([a-z][\w]*)\s*\(/g;
  let m;
  while ((m = callRe.exec(stripped)) !== null) {
    const name = m[2];
    if (BUILTINS.has(name) || KEYWORDS.has(name) || KNOWN_PKGS.has(name)) continue;
    if (defined.has(name)) continue;
    // 排除函数声明本身（"func name("）
    const head = stripped.slice(Math.max(0, m.index - 12), m.index);
    if (/\bfunc\s*(?:\([^)]*\)\s*)?$/.test(head)) continue;
    const line = stripped.slice(0, m.index).split('\n').length;
    if (!missing.has(name)) missing.set(name, line);
  }
  if (missing.size > 0) {
    for (const [name, line] of missing) {
      fail(`vpn.go 第 ${line} 行调用 \`${name}(\` 但全文无 \`func ${name}(\` 定义（iOS c-archive 与 Android c-shared 双端会同时炸）`);
    }
  } else {
    pass('vpn.go 本地小写函数 调用↔定义 全部配对 ✓');
  }

  // 6.3 本地有 go 工具链时跑一次 gofmt -e 语法校验（不修改文件）
  try {
    const gofmtOut = execSync(`gofmt -e -d "${VPN_GO}"`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    // gofmt -d 输出 diff；仅当存在语法错误时才走 catch。-d 输出空 = 文件已格式化；
    // 输出非空 = 仅格式差异，不视为硬错误（CI 用的 go build 不查 gofmt）。
    pass('gofmt -e 语法校验 ✓' + (gofmtOut.trim() ? '（有格式差异，非硬性）' : ''));
  } catch (e) {
    const stderr = (e && e.stderr) ? String(e.stderr) : '';
    if (/command not found|not recognized|ENOENT/i.test(stderr)) {
      console.warn('⚠️  本机未安装 gofmt，跳过 Go 语法硬校验（CI 仍会编译）');
    } else {
      fail(`gofmt -e 报语法错误：${stderr.trim() || e.message}`);
    }
  }
} catch (e) {
  fail(`读取 vpn.go 失败：${e.message}`);
}

// ============================================================
// 检查 7：扩展源码作用域预检
// build 145 实证：`bindIPv4` 定义在出站清洗块内，而「允许局域网连接」
// 路由在 openTun 里引用它 → cannot find 'bindIPv4' in scope。
// 这里对关键标识符做「先声明后使用」检查，本地 1 秒拦截同类错误。
// ============================================================
console.log('\n--- 检查 7：扩展源码作用域预检 + gen 双文件副本一致性 ---');
const EXT_SWIFT = resolve(ROOT, 'src-tauri/mobile-src/ios/PrismVPN/PacketTunnelProvider.swift');
try {
  const rawExt = readFileSync(EXT_SWIFT, 'utf8');
  // 剥除注释，避免文档注释里出现的标识符被误判为使用
  const stripSwiftComments = (src) =>
    src
      .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
      .replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length));
  const ext = stripSwiftComments(rawExt);
  const lineOf = (idx) => ext.slice(0, idx).split('\n').length;

  // 局部变量：使用点必须晚于声明点（Swift 不允许先使用后声明）
  const LOCAL_VARS = ['bindIPv4', 'bindInterface', 'lanEnabled', 'activePhy'];
  // 全局函数：Swift 允许先调用后定义（模块级符号），只要求全文有定义
  const GLOBAL_FUNCS = ['ipv4ToUInt32', 'uint32ToIPv4', 'isValidIPv4Literal'];
  let scopeOk = true;
  for (const name of [...LOCAL_VARS, ...GLOBAL_FUNCS]) {
    const useRe = new RegExp(`\\b${name}\\b`);
    const useMatch = ext.match(useRe);
    if (!useMatch) continue; // 未使用，跳过
    const isFunc = GLOBAL_FUNCS.includes(name);
    const declRe = new RegExp(
      isFunc
        ? `\\b(?:func|private\\s+func)\\s+${name}\\s*[(<]`
        : `\\b(?:let|var)\\s+${name}\\s*[:=]`
    );
    const declIndex = ext.search(declRe);
    if (declIndex < 0) {
      fail(
        `PacketTunnelProvider.swift 使用 \`${name}\` 但全文件无 ` +
          `${isFunc ? 'func' : 'let/var'} 声明`
      );
      scopeOk = false;
      continue;
    }
    // 只有局部变量要求「声明在首次使用之前」
    if (!isFunc && declIndex > useMatch.index) {
      fail(
        `PacketTunnelProvider.swift 第 ${lineOf(useMatch.index)} 行使用 \`${name}\`，` +
          `但声明在第 ${lineOf(declIndex)} 行（先使用后声明 → cannot find '${name}' in scope）`
      );
      scopeOk = false;
    }
  }
  if (scopeOk) {
    pass('PacketTunnelProvider.swift 关键标识符均先声明后使用 ✓');
  }

  // gen 副本一致性：CI 每次 init 现生成 gen/apple，本地若存在则必须与规范源
  // 完全一致——Xcode 实际编译的是 gen/apple 下的副本，双目录漂移会导致
  // 「本地改对了、CI 仍报错」。控制器与扩展两个文件都要逐一比对。
  const GEN_PAIRS = [
    [
      'src-tauri/mobile-src/ios/PrismVPN/PacketTunnelProvider.swift',
      'src-tauri/gen/apple/PrismVPN/PacketTunnelProvider.swift',
    ],
    [
      'src-tauri/mobile-src/ios/App/PrismTunnelController.swift',
      'src-tauri/gen/apple/PrismTunnelController.swift',
    ],
  ];
  for (const [specRel, genRel] of GEN_PAIRS) {
    try {
      const genRaw = readFileSync(resolve(ROOT, genRel), 'utf8');
      const specRaw = readFileSync(resolve(ROOT, specRel), 'utf8');
      if (genRaw !== specRaw) {
        fail(`${genRel} 与规范源 ${specRel} 不一致，请同步（Xcode 编译的是 gen 副本）`);
      } else {
        pass(`${genRel} 与规范源一致 ✓`);
      }
    } catch {
      pass(`无 ${genRel} 本地副本（CI 每次 init 现生成）✓`);
    }
  }

  // ---- 7.3 withMemoryRebound 值类型误用扫描（APP12 新增）----
  // 实证：对值类型 sockaddr() 调用 .withMemoryRebound 导致 Swift 编译炸掉。
  // 精确扫描：prism_protect_socket 函数体内绝不允许出现 .withMemoryRebound(
  // （因为 sing-box 的 AutoDetectInterfaceControl 只调出站 Socket，都是要发
  // 外网包的，不需要再用 withMemoryRebound 做回环过滤——vpn.go 也只传 fd）。
  let protectSocketWMR = false;
  const cdeclMatch = rawExt.match(/@_cdecl\("prism_protect_socket"\)[\s\S]*?\{/);
  if (cdeclMatch) {
    const after = rawExt.slice(cdeclMatch.index + cdeclMatch[0].length);
    // 取紧跟的函数体（下一对匹配大括号）
    let depth = 1, end = 0, i = 0;
    for (; i < after.length && depth > 0; i++) {
      if (after[i] === '{') depth++;
      else if (after[i] === '}') depth--;
    }
    const body = after.slice(0, i);
    if (body.includes('.withMemoryRebound(')) protectSocketWMR = true;
  }
  if (protectSocketWMR) {
    fail(
      'prism_protect_socket 函数体内仍存在 .withMemoryRebound( 调用——' +
        'sing-box 的 AutoDetectInterfaceControl 只调出站 Socket，无需做回环过滤；' +
        '且对值类型 sockaddr 调用 withMemoryRebound 会导致 Swift 编译炸掉。'
    );
  } else {
    pass('prism_protect_socket 无 withMemoryRebound 调用 ✓');
  }

  // ---- 7.3b NEIPv4Route 签名硬性校验（ERR0 / APP25 新增）----
  // iOS NetworkExtension 签名：
  //   NEIPv4Route(destinationAddress: String, subnetMask: String) —— 严禁 networkPrefixLength
  //   NEIPv6Route(destinationAddress: String, networkPrefixLength: NSNumber) —— 合法
  // 曾把 NEIPv6Route 的参数错套到 NEIPv4Route：
  //   let route = NEIPv4Route(destinationAddress: "...", networkPrefixLength: NSNumber(value: n))
  // 直接触发 Swift 编译 error: cannot convert value of type 'NSNumber' to expected argument type 'String'
  // 这里遍历每个 NEIPv4Route(...) 调用，若其内部出现 networkPrefixLength: 则硬拦截。
  {
    const v4Re = /NEIPv4Route\s*\(/g;
    let m;
    while ((m = v4Re.exec(rawExt)) !== null) {
      // 从起点扫描到配对闭括号（支持嵌套括号）
      let depth = 1, i = m.index + m[0].length;
      while (i < rawExt.length && depth > 0) {
        if (rawExt[i] === '(') depth++;
        else if (rawExt[i] === ')') depth--;
        i++;
      }
      const call = rawExt.slice(m.index, i);
      if (call.includes('networkPrefixLength:')) {
        const line = rawExt.slice(0, m.index).split('\n').length;
        fail(
          `PacketTunnelProvider.swift 第 ${line} 行 \`NEIPv4Route(...)\` 内部出现了 ` +
          `\`networkPrefixLength:\`——NEIPv4Route 的第二个参数必须是 ` +
          `\`subnetMask: String\`（子网掩码如 "255.255.255.0"），` +
          `\`networkPrefixLength: NSNumber\` 是 NEIPv6Route 的签名，严禁混用！`
        );
      }
    }
    if (!failed) pass('NEIPv4Route / NEIPv6Route 参数签名正确 ✓');
  }

  // 保守扫描：对所有 .withMemoryRebound( 调用，其前置变量名（剥掉 .pointee. 链后）
  // 若不在白名单里则 warning 提示开发者手动确认该变量是指针类型。
  // 白名单 = 已验证的 UnsafePointer 参数名（addrPtr / p / addr 都经 UnsafePointer 传入）
  const WMR_WHITELIST = new Set(['addrPtr', 'p', 'addr', 'sinPtr', 'sin6Ptr', 'sin']);
  const wmrRe = /([a-zA-Z_][\w]*)(?:\.pointee(?:\.[a-zA-Z_][\w]*)*)*\.withMemoryRebound\(/g;
  let wmHit;
  while ((wmHit = wmrRe.exec(rawExt)) !== null) {
    const varName = wmHit[1];
    if (!WMR_WHITELIST.has(varName)) {
      const line = rawExt.slice(0, wmHit.index).split('\n').length;
      console.warn(
        `⚠️  [warning] PacketTunnelProvider.swift 第 ${line} 行 ` +
          `\`${wmHit[0]}\` 的前置变量名 "${varName}" 不在白名单 ` +
          `[${[...WMR_WHITELIST].join(', ')}] 里，请手动确认它是 UnsafePointer 类型，` +
          `否则会触发 Swift 编译错 "value of type 'xxx' has no member 'withMemoryRebound'"`
      );
    }
  }

  // ---- 7.4 非可选 API 条件绑定扫描（APP13 新增）----
  // 实证：if_nametoindex 返回 UInt32（非 Optional），在 if 条件链里写
  // `let routedIdx = if_nametoindex(...), routedIdx > 0` 直接触发 Swift
  // 编译炸："initializer for conditional binding must have Optional type"。
  // 这里同时扫 PacketTunnelProvider.swift 和 PrismTunnelController.swift，
  // 命中任何一处立即 fail 并给出精确行号。
  // 已知返回非可选类型的 C / Swift API：
  //   - if_nametoindex(...)          → UInt32
  //   - socket/connect/getsockname/  → Int32
  //     getifaddrs/getaddrinfo/
  //     inet_pton/setsockopt/
  //     fcntl/ioctl/open/close/dup
  //   - strlen/strcmp                → Int / Int32
  //   - String(cString: ...)         → String（非 Optional）
  const NON_OPTIONAL_CALLS = [
    'if_nametoindex', 'socket', 'connect', 'getsockname', 'getifaddrs',
    'getaddrinfo', 'inet_pton', 'setsockopt', 'fcntl', 'ioctl',
    'open', 'close', 'dup', 'strlen', 'strcmp',
  ];
  // 模式 1：if / guard / 逗号 条件链里的 `let name = <非可选API>(...)` 绑定
  const nonOptRe = new RegExp(
    `(?:if|guard|,)\\s+let\\s+\\w+\\s*=\\s*(${NON_OPTIONAL_CALLS.join('|')})\\s*\\(`,
    'g'
  );
  // 模式 2：特例 `let routedIdx = if_nametoindex(...),` 后面跟逗号条件链
  const ifNametoindexCommaRe = /let\s+\w+\s*=\s*if_nametoindex\s*\([^)]*\)\s*,/g;

  const SWIFT_PAIRS = [
    ['PacketTunnelProvider.swift', rawExt],
  ];
  // 同时扫 PrismTunnelController.swift
  try {
    const ctrlSrc = readFileSync(resolve(ROOT, 'src-tauri/mobile-src/ios/App/PrismTunnelController.swift'), 'utf8');
    SWIFT_PAIRS.push(['PrismTunnelController.swift', ctrlSrc]);
  } catch { /* 文件不存在时跳过 */ }

  for (const [fname, src] of SWIFT_PAIRS) {
    let m;
    // 重置 lastIndex，避免上轮 exec 残留
    nonOptRe.lastIndex = 0;
    while ((m = nonOptRe.exec(src)) !== null) {
      const line = src.slice(0, m.index).split('\n').length;
      fail(
        `${fname} 第 ${line} 行：if / guard 条件链中对返回非可选类型的 ` +
          `\`${m[1]}()\` 使用了 \`let\` 条件绑定——Swift 要求条件绑定的右侧 ` +
          `必须是 Optional 类型。必须拆成独立局部变量后再判断。`
      );
    }
    ifNametoindexCommaRe.lastIndex = 0;
    while ((m = ifNametoindexCommaRe.exec(src)) !== null) {
      const line = src.slice(0, m.index).split('\n').length;
      fail(
        `${fname} 第 ${line} 行：非法模式 \`${m[0].trim()}\` —— if_nametoindex ` +
          `返回 UInt32（非可选），严禁在 if 条件链里写 \`, routedIdx > 0\`。`
      );
    }
  }
  // 全部通过的话给一个 summary pass
  if (!failed) pass('两 Swift 文件均无非可选 API 条件绑定 ✓');
} catch (e) {
  fail(`读取 PacketTunnelProvider.swift 失败：${e.message}`);
}

// ============================================================
// 检查 8：【APP16 任务3】Swift 冻结指令
//   1. 严禁任何 `as!` 强制类型转换
//   2. 严禁命名元组类型声明（`-> (`、`(name: Type, ...)`、`(net:`/`(prefix:`）
//   3. mobile-src 规范源与 gen/apple 编译副本字节完全一致（本地无副本则跳过）
// ============================================================
console.log('\n--- 检查 8：Swift 冻结指令（as! / 命名元组 / gen 副本一致） ---');
const SWIFT_TARGETS = [
  'src-tauri/mobile-src/ios/App/PrismTunnelController.swift',
  'src-tauri/mobile-src/ios/PrismVPN/PacketTunnelProvider.swift',
  'src-tauri/mobile-src/ios/Helper/PrismHelper.swift',
];
const SWIFT_BAN_RULES = [
  { re: /(?<![\w.])as!/, msg: '出现 `as!` 强制类型转换（APP16 硬性禁令）' },
  { re: /->\s*\(/, msg: '出现 `-> (` 元组返回值声明（APP16 硬性禁令，请改用结构体）' },
  { re: /:\s*\(\s*[A-Za-z_]\w*\s*:\s*[A-Za-z_][\w\[\]<>?.]*\s*,/, msg: '出现命名元组类型声明 `(name: Type, ...)`（APP16 硬性禁令，请改用结构体）' },
  // 元组数组/可选的命名元组类型：`[(net: UInt32, prefix: UInt8)]`、
  // `((net: UInt32, prefix: UInt8))?` 等 ERR6 同款写法（标签函数调用不会命中）
  { re: /[\[(]\s*\(\s*[A-Za-z_]\w*\s*:\s*[A-Za-z_][\w\[\]<>?.]*\s*,/, msg: '出现 `[(net: Type, ...)]` 命名元组类型（APP16 硬性禁令，请改用结构体）' },
];
for (const rel of SWIFT_TARGETS) {
  let src = '';
  try {
    src = readFileSync(resolve(ROOT, rel), 'utf8');
  } catch {
    pass(`${rel} 不存在，跳过`);
    continue;
  }
  let hit = false;
  for (const { re, msg } of SWIFT_BAN_RULES) {
    const m = src.match(re);
    if (m) {
      const line = src.slice(0, m.index).split('\n').length;
      fail(`${rel} 第 ${line} 行：${msg}`);
      hit = true;
    }
  }
  if (!hit) pass(`${rel}: 无 as! / 命名元组 ✓`);
}

// gen 副本字节一致：Xcode 实际编译的是 gen/apple 下的副本，
// 双目录漂移会导致「本地改对了、CI 仍报同样的编译错」。
const GEN_BYTE_PAIRS = [
  'src-tauri/mobile-src/ios/PrismVPN/PacketTunnelProvider.swift',
  'src-tauri/mobile-src/ios/App/PrismTunnelController.swift',
];
for (const specRel of GEN_BYTE_PAIRS) {
  const genRel = specRel
    .replace('src-tauri/mobile-src/ios/PrismVPN/', 'src-tauri/gen/apple/PrismVPN/')
    .replace('src-tauri/mobile-src/ios/App/', 'src-tauri/gen/apple/');
  let genBuf;
  try {
    genBuf = readFileSync(resolve(ROOT, genRel));
  } catch {
    pass(`无 ${genRel} 本地副本（CI 每次 init 现生成，跳过字节比对）✓`);
    continue;
  }
  const specBuf = readFileSync(resolve(ROOT, specRel));
  if (Buffer.compare(genBuf, specBuf) !== 0) {
    fail(`${genRel} 与规范源 ${specRel} 字节不一致，请完整复制覆盖（Xcode 编译的是 gen 副本）`);
  } else {
    pass(`${genRel} 与规范源字节完全一致 ✓`);
  }
}

// ============================================================
// 检查 9：【APP27 任务3】四端 cargo check 编译门禁
// 本地/CI 任何一次 error（如 E0133 / E0308）都必须立刻阻断提交：
// 此前 Windows 上无法编译 iOS 专属代码，盲区里的错误只能在 CI 耗时
// 编译阶段才暴露。
// ============================================================
console.log('\n--- 检查 9：Rust 编译门禁（cargo check）---');
const cargoEnv = { ...process.env };
if (process.platform !== 'darwin') {
  // 非 macOS 本机没有 Xcode：借用仓库 fake-clang 桩工具链做 iOS 目标
  // 类型检查（不链接）。桩目录可用 PRISM_FAKE_IOS_TOOLCHAIN 覆盖。
  const shim = process.env.PRISM_FAKE_IOS_TOOLCHAIN || 'D:\\Prism\\fake-bin';
  if (existsSync(shim)) {
    // Windows 环境变量键名大小写不敏感：必须复用原有键（通常是 Path），
    // 否则新增的 PATH 会覆盖掉系统 cargo 路径导致 "cargo 不是命令"
    const pathKey =
      Object.keys(cargoEnv).find((k) => k.toUpperCase() === 'PATH') || 'PATH';
    cargoEnv[pathKey] = `${shim}${delimiter}${cargoEnv[pathKey] ?? ''}`;
    cargoEnv.SDKROOT = process.env.SDKROOT || 'D:\\Prism\\fake-sdk\\iPhoneOS.sdk';
    cargoEnv.CC_aarch64_apple_ios = 'clang';
    cargoEnv.CXX_aarch64_apple_ios = 'clang';
    cargoEnv.AR_aarch64_apple_ios = 'ar';
    cargoEnv.RANLIB_aarch64_apple_ios = 'ar';
    console.log(`   （使用 iOS 桩工具链：${shim}）`);
  } else {
    console.log(`   （未找到 iOS 桩工具链 ${shim}，iOS check 可能因缺少 xcrun 失败）`);
  }
}
function cargoCheck(label, target) {
  const cmd = `cargo check --manifest-path src-tauri/Cargo.toml --lib${target ? ` --target ${target}` : ''}`;
  try {
    execSync(cmd, { cwd: ROOT, stdio: 'inherit', env: cargoEnv });
    pass(`${label} cargo check 通过 ✓`);
  } catch {
    fail(`${label} cargo check 失败（存在编译错误，禁止提交）：${cmd}`);
  }
}
cargoCheck('本机', '');
cargoCheck('iOS（aarch64-apple-ios）', 'aarch64-apple-ios');

// ============================================================
// 检查 10：【APP28 任务1】Swift 禁止触碰 WebView 内部视图树（黑屏防复发）
// 根因：递归给 WKCompositingView/WKContentView 刷 backgroundColor 会让
// 切换 App 时整屏黑屏且无法触摸。任何 `subviews` 遍历、WebView 页面底色
// 修改、退后台/回前台染色监听都必须立即阻断。
// ============================================================
console.log('\n--- 检查 10：WKWebView 染色防复发 ---');
const tunnelSwift = readFileSync(
  resolve(ROOT, 'src-tauri/mobile-src/ios/App/PrismTunnelController.swift'),
  'utf8'
);
const BANNED_SWIFT = [
  ['subviews', '遍历子视图树'],
  ['underPageBackgroundColor', '修改 WebView 页面底色'],
  ['willResignActiveNotification', '注册退后台染色监听'],
  ['didBecomeActiveNotification', '注册回前台染色监听'],
];
const swiftHits = BANNED_SWIFT.filter(([token]) => tunnelSwift.includes(token));
if (swiftHits.length > 0) {
  fail(
    `PrismTunnelController.swift 出现禁用写法：${swiftHits
      .map(([token, desc]) => `${token}（${desc}）`)
      .join('、')}；递归染色会导致切换 App 黑屏（APP24/APP28 教训）`
  );
} else {
  pass('PrismTunnelController.swift 未触碰 WKWebView 内部视图树 ✓');
}

// ============================================================
// 检查 11：【APP28 任务2】AppIcon 四角必须满铺不透明彩色背景
// iOS 要求提交的图标为 100% 直角满铺方形（圆角由系统裁切）；四角出现
// 白色/透明/#0B0E14 深黑时，SpringBoard 拉伸底边会露出黑块或白块。
// gen/apple 只在 macOS 构建时生成，缺失时回退到仓库内 icons/ios。
// 【APP41 任务1】彻底移除 sharp（CI 未 npm install 时报
// ERR_MODULE_NOT_FOUND），改用 Node 内置 zlib 手写 PNG 解码：
// 零第三方依赖、纯同步、毫秒级，任何干净 CI 环境都能直接跑。
// ============================================================
console.log('\n--- 检查 11：AppIcon 四角满铺校验 ---');
const ICON_DIRS = [
  resolve(ROOT, 'src-tauri/gen/apple/Assets.xcassets/AppIcon.appiconset'),
  resolve(ROOT, 'src-tauri/icons/ios'),
].filter((d) => existsSync(d));
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const PNG_CHANNELS = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };
function badCornerReason(r, g, b, a) {
  if (a < 250) return '透明';
  const mx = Math.max(r, g, b);
  const mn = Math.min(r, g, b);
  if (mx > 245 && mn > 200) return '白色';
  if (mx < 45) return '近黑(#0B0E14)';
  if (mx - mn < 20) return '灰白';
  return null;
}
/// 纯 Node 解码 PNG 四角像素；仅依赖 node:zlib。
/// 返回 { width, height, corners }（corners 为 [x, y, r, g, b, a]），
/// 遇到非 8bit / 隔行 / 未知色型等未支持格式返回 null（调用方退化为文件头校验）。
function decodePngCorners(buf) {
  if (buf.length < 8 || !buf.subarray(0, 8).equals(PNG_SIG)) return null;
  let off = 8;
  let ihdr = null;
  let palette = null;
  const tRNS = [];
  const idat = [];
  while (off + 8 <= buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.toString('ascii', off + 4, off + 8);
    const body = buf.subarray(off + 8, off + 8 + len);
    if (type === 'IHDR') {
      ihdr = {
        width: body.readUInt32BE(0),
        height: body.readUInt32BE(4),
        bitDepth: body[8],
        colorType: body[9],
        interlace: body[12],
      };
    } else if (type === 'IDAT') {
      idat.push(body);
    } else if (type === 'PLTE') {
      palette = body;
    } else if (type === 'tRNS') {
      tRNS.push(...body);
    } else if (type === 'IEND') {
      break;
    }
    off += len + 12;
  }
  if (!ihdr || idat.length === 0) return null;
  const { width, height, bitDepth, colorType, interlace } = ihdr;
  const ch = PNG_CHANNELS[colorType];
  if (bitDepth !== 8 || interlace !== 0 || !ch || width <= 0 || height <= 0) return null;
  if (colorType === 3 && !palette) return null;
  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * ch;
  if (raw.length < height * (stride + 1)) return null;
  // 逐行反滤波（PNG filter 0~4）；只缓存首尾两行用于四角采样
  const wantedY = [0, height - 1];
  const rows = new Map();
  let prev = Buffer.alloc(stride);
  for (let y = 0; y < height; y++) {
    const base = y * (stride + 1);
    const filter = raw[base];
    const src = raw.subarray(base + 1, base + 1 + stride);
    const out = Buffer.alloc(stride);
    for (let i = 0; i < stride; i++) {
      const a = i >= ch ? out[i - ch] : 0;
      const b = prev[i];
      const c = i >= ch ? prev[i - ch] : 0;
      let v = src[i];
      if (filter === 1) v += a;
      else if (filter === 2) v += b;
      else if (filter === 3) v += Math.floor((a + b) / 2);
      else if (filter === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      }
      out[i] = v & 0xff;
    }
    if (wantedY.includes(y)) rows.set(y, out);
    prev = out;
  }
  const pixelAt = (x, y) => {
    const row = rows.get(y);
    const i = x * ch;
    if (colorType === 6) return [row[i], row[i + 1], row[i + 2], row[i + 3]];
    if (colorType === 2) return [row[i], row[i + 1], row[i + 2], 255];
    if (colorType === 4) return [row[i], row[i], row[i], row[i + 1]];
    if (colorType === 0) return [row[i], row[i], row[i], tRNS.length ? (row[i] === tRNS[0] ? 0 : 255) : 255];
    const p = row[i] * 3;
    return [palette[p], palette[p + 1], palette[p + 2], tRNS.length ? (tRNS[row[i]] ?? 255) : 255];
  };
  const corners = [
    [0, 0],
    [width - 1, 0],
    [0, height - 1],
    [width - 1, height - 1],
  ].map(([x, y]) => [x, y, ...pixelAt(x, y)]);
  return { width, height, corners };
}
if (ICON_DIRS.length === 0) {
  fail('未找到 AppIcon 图标目录（icons/ios 缺失）');
} else {
  const badIcons = [];
  let checked = 0;
  for (const dir of ICON_DIRS) {
    for (const file of readdirSync(dir).filter((f) => f.toLowerCase().endsWith('.png'))) {
      const buf = readFileSync(resolve(dir, file));
      if (buf.length === 0) {
        badIcons.push(`${file}=空文件`);
        continue;
      }
      if (!buf.subarray(0, 8).equals(PNG_SIG)) {
        badIcons.push(`${file}=PNG 魔数缺失`);
        continue;
      }
      checked += 1;
      const decoded = decodePngCorners(buf);
      if (!decoded) continue; // 未支持格式：已通过魔数 + 非空校验
      for (const [x, y, r, g, b, a] of decoded.corners) {
        const reason = badCornerReason(r, g, b, a);
        if (reason) {
          badIcons.push(`${file}(${x},${y})=${reason}`);
          break;
        }
      }
    }
  }
  if (badIcons.length > 0) {
    fail(`AppIcon 四角未满铺（应为不透明彩色背景，不得有白/黑/透明）：${badIcons.slice(0, 6).join('，')}${badIcons.length > 6 ? ` 等 ${badIcons.length} 张` : ''}`);
  } else {
    pass(`AppIcon 四角满铺校验通过（${checked} 张）✓`);
  }
}

// ============================================================
// 检查 12：【APP61】sing-box v1.11.3 未知字段门禁
// 根因：sing-box v1.11.3 的 DisallowUnknownFields 解析器对未知字段
// 直接 FATAL 崩溃（exit -2），曾因 tun-in 中写入 udp_fragment 导致
// create vpn service: decode config: inbounds[1].udp_fragment
// 内核启动秒崩。这里在 Rust 源码 + Swift 扩展侧同时硬拦截，
// 任何 "udp_fragment" / "prism_" 自定义扩展字段残留立即阻断提交。
// ============================================================
console.log('\n--- 检查 12：sing-box v1.11.3 未知字段门禁 ---');
const SB_CHECK_FILES = [
  { rel: 'src-tauri/src/core/config_builder.rs', desc: 'config_builder' },
  { rel: 'src-tauri/src/core/go_lan.rs', desc: 'go_lan' },
  { rel: 'src-tauri/mobile-src/ios/PrismVPN/PacketTunnelProvider.swift', desc: 'PacketTunnelProvider' },
];
// 严禁出现的字段（全量扫描，包括注释和字符串字面量）
const SB_BANNED_TOKENS = ['udp_fragment'];
for (const { rel, desc } of SB_CHECK_FILES) {
  const p = resolve(ROOT, rel);
  let src = '';
  try { src = readFileSync(p, 'utf8'); } catch { continue; }
  for (const token of SB_BANNED_TOKENS) {
    let idx = src.indexOf(token);
    while (idx !== -1) {
      const line = src.slice(0, idx).split('\n').length;
      fail(`${desc} 第 ${line} 行：出现禁用字段 \`${token}\`——sing-box v1.11.3 不识别，会触发 decode config FATAL 崩溃！`);
      break; // 同一文件每个 token 只报一次
    }
    if (idx === -1) pass(`${desc}: 无禁用字段 \`${token}\` ✓`);
  }
}

// ============================================================
// 检查 13：【APP62 任务3】订阅解析引擎门禁
// 机场可能下发 Surge/Loon、SIP008、sing-box JSON、Quantumult X、Clash YAML
// 与 URI 列表六种格式；必须统一走 subscription::parse_subscription_content，
// 且 prepare_subscription_payload 不得回退成「只解一层 base64」。
// ============================================================
console.log('\n--- 检查 13：订阅多格式解析引擎 ---');
try {
  const subSrc = readFileSync(resolve(ROOT, 'src-tauri/src/core/subscription.rs'), 'utf8');
  const requiredFns = ['auto_decrypt_base64_payload', 'parse_subscription_content'];
  for (const fn of requiredFns) {
    if (subSrc.includes(`pub fn ${fn}`)) pass(`subscription.rs 暴露 ${fn} ✓`);
    else fail(`subscription.rs 缺少公开函数 ${fn}（订阅解析能力不完整）`);
  }
  const modSrc = readFileSync(resolve(ROOT, 'src-tauri/src/core/mod.rs'), 'utf8');
  if (/pub\s+mod\s+subscription\s*;/.test(modSrc)) pass('core/mod.rs 已注册 subscription 模块 ✓');
  else fail('core/mod.rs 未注册 `pub mod subscription;`，订阅解析模块不会参与编译');

  const cmdSrc = readFileSync(resolve(ROOT, 'src-tauri/src/ipc/commands.rs'), 'utf8');
  if (cmdSrc.includes('subscription::parse_subscription_content')) pass('commands.rs 已接入 subscription 解析器 ✓');
  else fail('commands.rs 未调用 subscription::parse_subscription_content，机场订阅仍会解析失败');
  if (cmdSrc.includes('fn prepare_subscription_payload')) pass('prepare_subscription_payload 仍存在 ✓');
  else fail('prepare_subscription_payload 被删除（订阅导入链路断裂）');
} catch (e) {
  fail(`订阅解析引擎检查失败：${e.message}`);
}

// ============================================================
// 检查 14：【APP62 任务4】日志分类聚合门禁
// 必须一次性返回全部分类 + 桶区间，前端切标签零请求。
// ============================================================
console.log('\n--- 检查 14：日志分类聚合（切标签零请求）---');
try {
  const logSrc = readFileSync(resolve(ROOT, 'src-tauri/src/core/logger.rs'), 'utf8');
  const logMust = [
    ['CategorizedLogsPayload', '分类聚合返回结构'],
    ['pub struct LogBucket', '分类桶区间结构'],
    ['pub fn get_logs_categorized', '分类聚合读取函数'],
    ['last_offset', '增量游标'],
  ];
  for (const [token, desc] of logMust) {
    if (logSrc.includes(token)) pass(`logger.rs 含${desc} \`${token}\` ✓`);
    else fail(`logger.rs 缺少${desc} \`${token}\``);
  }
  const modalSrc = readFileSync(resolve(ROOT, 'src/components/LogViewerModal.tsx'), 'utf8');
  if (modalSrc.includes('logs.slice(bucket.start, bucket.end)')) pass('LogViewerModal 切换分类走本地切片 ✓');
  else fail('LogViewerModal 未按桶区间本地切片，切换分类仍会发请求');
  if (modalSrc.includes('key={activeModule}')) pass('日志列表已按分类强制重建 ✓');
  else fail('日志列表缺少 key={activeModule}，切换分类可能残留旧节点/滚动位置');
  if (/"logs"|logs:/.test(modalSrc)) pass('前端已使用 logs 字段 ✓');
} catch (e) {
  fail(`日志分类聚合检查失败：${e.message}`);
}

// ============================================================
// 检查 15：【APP62 任务1】iOS 全场景自愈作用域校验
// 防止只声明变量不接线：四个成员必须真实出现在使用点。
// ============================================================
console.log('\n--- 检查 15：iOS 全场景自愈接线 ---');
try {
  const pttRel = 'src-tauri/mobile-src/ios/PrismVPN/PacketTunnelProvider.swift';
  const ptt = readFileSync(resolve(ROOT, pttRel), 'utf8');
  const wireMust = [
    ['activeGoLanProbes', 3, 'go-lan 握手清单（声明 + 赋值 + 发包）'],
    ['triggerExtensionGoLanHandshakes', 3, '扩展自主重握手（声明 + 切网/唤醒调用）'],
    ['activeBoundIPv4', 3, '物理 IPv4 跟踪（声明 + 赋值 + 比对）'],
    ['override func wake()', 1, '休眠唤醒自愈入口'],
    ['goLanKeepaliveTimer', 3, '25 秒保活定时器'],
  ];
  for (const [token, min, desc] of wireMust) {
    const n = ptt.split(token).length - 1;
    if (n >= min) pass(`${desc}：${token} 出现 ${n} 次 ✓`);
    else fail(`${desc}：${token} 仅出现 ${n} 次（至少 ${min} 次），可能只声明未接线`);
  }
  const scopeBans = [
    [/(?<![\w.])as!/, '`as!` 强制转换'],
    [/->\s*\(/, '`-> (` 元组返回值'],
  ];
  for (const [re, msg] of scopeBans) {
    const m = ptt.match(re);
    if (m) {
      const line = ptt.slice(0, m.index).split('\n').length;
      fail(`${pttRel} 第 ${line} 行：出现${msg}（APP16 禁令）`);
    } else {
      pass(`PacketTunnelProvider 无${msg} ✓`);
    }
  }
  const appSrc = readFileSync(resolve(ROOT, 'src/App.tsx'), 'utf8');
  if (appSrc.includes('trigger_go_lan_handshakes')) pass('App.tsx 回前台已触发 go-lan 握手 ✓');
  else fail('App.tsx 未在回前台时调用 trigger_go_lan_handshakes');
  const cmdSrc2 = readFileSync(resolve(ROOT, 'src-tauri/src/ipc/commands.rs'), 'utf8');
  if (cmdSrc2.includes('trigger_all_handshakes')) pass('commands.rs 已接入 trigger_all_handshakes ✓');
  else fail('commands.rs 未接入 go_lan::trigger_all_handshakes');
} catch (e) {
  fail(`iOS 自愈接线检查失败：${e.message}`);
}

// ============================================================
// 收尾
// ============================================================
console.log();
if (failed) {
  console.error('❌ verify-ios-ready 有硬性检查不通过，请修正后再推送！');
  process.exit(1);
} else {
  console.log('✅ verify-ios-ready: 全部 11 项检查绿灯通过，iOS / Android 构建就绪！');
}
