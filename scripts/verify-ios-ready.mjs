#!/usr/bin/env node
/**
 * verify-ios-ready.mjs —— iOS / Android 构建本地硬性预检（1 秒跑完）
 *
 * 6 项检查，任一项不通过立刻 exit(1) + 打印精确原因：
 *   1. UTF-8 BOM 头扫描
 *   2. Rust ios.rs ↔ build.rs ↔ Swift @_cdecl 三方 C ABI 符号对齐
 *   3. Swift 缺失 import 框架自动检测
 *   4. iOS 禁用 macOS 专属 API 扫描
 *   5. Swift 括号与引号平衡校验
 *   6. vpn.go Go 内核双端预检（本地小写函数"调用 vs 定义"配对 +
 *      import "C" 块完整性 + 可用时的 gofmt -e 语法校验）
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { execSync } from 'node:child_process';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
let failed = false;
const fail = (m) => { console.error(`❌ ${m}`); failed = true; };
const pass = (m) => console.log(`✅ ${m}`);
const reMatchAll = (re, src) => [...src.matchAll(re)].map((m) => m[1]);

// ============================================================
// 检查 1：UTF-8 BOM 扫描
// ============================================================
console.log('\n--- 检查 1：UTF-8 BOM 扫描 ---');
const BOM_TARGETS = [
  'src-tauri/tauri.conf.json',
  'package.json',
  'src-tauri/Cargo.toml',
  'scripts/inject-ios-vpn.rb',
  'src-tauri/mobile-src/ios/App/PrismTunnelController.swift',
  'src-tauri/mobile-src/ios/PrismVPN/PacketTunnelProvider.swift',
];
for (const rel of BOM_TARGETS) {
  try {
    const bytes = readFileSync(resolve(ROOT, rel), null);
    if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) {
      fail(`${rel} 含有 UTF-8 BOM 头（首字节 0xEF 0xBB 0xBF），必须移除！`);
    } else {
      pass(`${rel} 无 BOM`);
    }
  } catch { /* 文件可能不存在，跳过 */ }
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
// 收尾
// ============================================================
console.log();
if (failed) {
  console.error('❌ verify-ios-ready 有硬性检查不通过，请修正后再推送！');
  process.exit(1);
} else {
  console.log('✅ verify-ios-ready: 全部 6 项检查绿灯通过，iOS / Android 构建就绪！');
}
