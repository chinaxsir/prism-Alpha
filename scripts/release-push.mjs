#!/usr/bin/env node
/**
 * release-push.mjs —— Prism 标准发布流程（APP38 任务3，永久生效）
 *
 * 每次代码修复/功能更新后固定执行：
 *   node scripts/release-push.mjs [新版本号] [--msg "自定义提交信息"]
 *
 * 流程（任何一步失败立即中断，绝不推送半成品）：
 *   1. 版本号同步递增（默认 patch+1，可显式指定），通过 Node.js
 *      fs.writeFileSync(..., "utf8") 无 BOM 写入：
 *      package.json / src-tauri/tauri.conf.json / src-tauri/Cargo.toml
 *      （严禁 PowerShell Set-Content —— ERR10 实证会注入 UTF-8 BOM）
 *   2. cargo update -p prism-proxy 同步 Cargo.lock
 *   3. 五项门禁：
 *      ① node scripts/verify-ios-ready.mjs（含全仓 BOM + JSON 校验 + 双端 check）
 *      ② npx tsc --noEmit
 *      ③ npm run build
 *      ④ cargo test --manifest-path src-tauri/Cargo.toml
 *      ⑤ 四端 cargo check（宿主机 / aarch64-apple-ios /
 *         aarch64-linux-android / aarch64-apple-darwin，
 *         Windows 下自动注入 D:\Prism\fake-bin 桩工具链）
 *   4. git add -A（.gitignore 自动排除 license-server/、license-worker/、gen/）
 *      → git commit → git tag -f vX.Y.Z
 *   5. 同时推送 main 分支与版本号 Tag 到 origin 与 alpha 双远端，
 *      确保 main 和 Tag 指向同一个包含完整代码的 Commit。
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { execSync } from 'node:child_process';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const IS_WIN = process.platform === 'win32';
const FAKE_BIN = 'D:\\Prism\\fake-bin';
const PROXY = 'http://127.0.0.1:3067';
const REMOTES = ['origin', 'alpha'];

const run = (cmd, env = {}) => {
  console.log(`\n$ ${cmd}`);
  execSync(cmd, { cwd: ROOT, stdio: 'inherit', env: { ...process.env, ...env } });
};

/** 显式指定时直接用；否则 patch 位 +1 */
function versionBump(oldVer, explicit) {
  if (explicit) return explicit;
  const [major, minor, patch] = oldVer.split('.').map(Number);
  return `${major}.${minor}.${patch + 1}`;
}

// ---------- 参数解析 ----------
const args = process.argv.slice(2);
let msgIdx = args.indexOf('--msg');
const customMsg = msgIdx >= 0 ? args[msgIdx + 1] : null;
const versionArg = args.find((a, i) => i !== msgIdx && i !== msgIdx + 1 && !a.startsWith('--'));

// ---------- 1. 版本号同步递增（Node.js 无 BOM 写入） ----------
console.log('\n=== 步骤 1：版本号同步递增（无 BOM） ===');
const pkgPath = resolve(ROOT, 'package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
const oldVer = pkg.version;
let newVer = versionBump(oldVer, versionArg);
if (!/^\d+\.\d+\.\d+$/.test(newVer)) {
  console.error(`❌ 非法版本号：${newVer}`);
  process.exit(1);
}
console.log(`  ${oldVer} → ${newVer}`);

pkg.version = newVer;
writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n', 'utf8');

const tauriPath = resolve(ROOT, 'src-tauri/tauri.conf.json');
const tauri = JSON.parse(readFileSync(tauriPath, 'utf8'));
tauri.version = newVer;
writeFileSync(tauriPath, JSON.stringify(tauri, null, 2) + '\n', 'utf8');

const cargoPath = resolve(ROOT, 'src-tauri/Cargo.toml');
const cargoToml = readFileSync(cargoPath, 'utf8').replace(
  /^version = "[0-9]+\.[0-9]+\.[0-9]+"/m,
  `version = "${newVer}"`,
);
writeFileSync(cargoPath, cargoToml, 'utf8');

// 回读校验：JSON.parse 必须 100% 通过（ERR10 防线）
JSON.parse(readFileSync(pkgPath, 'utf8'));
JSON.parse(readFileSync(tauriPath, 'utf8'));
console.log('✅ 三处版本号已同步，JSON.parse 回读校验通过');

// ---------- 2. 同步 Cargo.lock ----------
console.log('\n=== 步骤 2：同步 Cargo.lock ===');
run('cargo update -p prism-proxy --manifest-path src-tauri/Cargo.toml');

// ---------- 3. 五项门禁 ----------
console.log('\n=== 步骤 3：五项门禁 ===');
const checkEnv = IS_WIN && existsSync(FAKE_BIN)
  ? { Path: `${FAKE_BIN};${process.env.Path}` }
  : {};

run('node scripts/verify-ios-ready.mjs');
run('npx tsc --noEmit');
run('npm run build');
run('cargo test --manifest-path src-tauri/Cargo.toml');
for (const target of ['aarch64-apple-ios', 'aarch64-linux-android', 'aarch64-apple-darwin']) {
  run(`cargo check --manifest-path src-tauri/Cargo.toml --target ${target}`, checkEnv);
}
console.log('\n✅ 五项门禁全部通过');

// ---------- 4. 提交 + 打 Tag ----------
console.log('\n=== 步骤 4：提交 main + 打版本号 Tag ===');
const commitMsg = customMsg || `release: v${newVer}`;
run('git add -A');
run(`git commit -m "${commitMsg.replace(/"/g, '\\"')}"`);
run(`git tag -f v${newVer}`);

// ---------- 5. 双远端推送 main + Tag ----------
console.log('\n=== 步骤 5：推送 main 与版本号 Tag ===');
for (const remote of REMOTES) {
  run(`git -c http.proxy=${PROXY} push ${remote} main`);
  run(`git -c http.proxy=${PROXY} push ${remote} v${newVer} --force`);
}

console.log(`\n🎉 发布完成：v${newVer} —— main 与 Tag 已同步推送（${REMOTES.join(' / ')}）`);
