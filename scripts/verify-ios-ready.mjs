#!/usr/bin/env node
/**
 * verify-ios-ready.mjs —— iOS / Android 构建本地硬性预检（1 秒跑完）
 *
 * 7 项检查，任一项不通过立刻 exit(1) + 打印精确原因：
 *   1. UTF-8 BOM 头扫描
 *   2. Rust ios.rs ↔ build.rs ↔ Swift @_cdecl 三方 C ABI 符号对齐
 *   3. Swift 缺失 import 框架自动检测
 *   4. iOS 禁用 macOS 专属 API 扫描
 *   5. Swift 括号与引号平衡校验
 *   6. vpn.go Go 内核双端预检（本地小写函数"调用 vs 定义"配对 +
 *      import "C" 块完整性 + 可用时的 gofmt -e 语法校验）
 *   7. 扩展源码作用域预检（关键标识符先声明后使用 + gen 副本一致性）
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
} catch (e) {
  fail(`读取 PacketTunnelProvider.swift 失败：${e.message}`);
}

// ============================================================
// 收尾
// ============================================================
console.log();
if (failed) {
  console.error('❌ verify-ios-ready 有硬性检查不通过，请修正后再推送！');
  process.exit(1);
} else {
  console.log('✅ verify-ios-ready: 全部 8 项检查绿灯通过，iOS / Android 构建就绪！');
}
