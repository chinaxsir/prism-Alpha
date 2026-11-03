#!/usr/bin/env node
/**
 * 下载 sing-box 内核并放置为 Tauri sidecar（src-tauri/binaries/，已 gitignore）。
 * 打包后随安装包分发，终端用户无需联网下载内核。
 *
 * 用法: node scripts/fetch-kernel.cjs [--force] [--geo-only] [--target <rust-triplet>]
 *   --geo-only  只下载 geoip/geosite 数据库（iOS 内嵌内核场景，无需 sidecar）
 *   --target    显式指定目标三元组（交叉构建；也可用 TAURI_ENV_TARGET_TRIPLE）
 */

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const KERNEL_VERSION = "1.11.3";
const ROOT = path.join(__dirname, "..");
const OUT_DIR = path.join(ROOT, "src-tauri", "binaries");

/** 当前平台 → [Rust target triplet, 发行包文件名]；
 *  也可用 --triplet <rust-triplet> 强制指定（CI 交叉构建场景） */
const TRIPLET_MAP = {
  "x86_64-pc-windows-msvc": `sing-box-${KERNEL_VERSION}-windows-amd64.zip`,
  "aarch64-pc-windows-msvc": `sing-box-${KERNEL_VERSION}-windows-arm64.zip`,
  "x86_64-apple-darwin": `sing-box-${KERNEL_VERSION}-darwin-amd64.tar.gz`,
  "aarch64-apple-darwin": `sing-box-${KERNEL_VERSION}-darwin-arm64.tar.gz`,
  "x86_64-unknown-linux-gnu": `sing-box-${KERNEL_VERSION}-linux-amd64.tar.gz`,
  "aarch64-unknown-linux-gnu": `sing-box-${KERNEL_VERSION}-linux-arm64.tar.gz`,
};

/** 【APP44 任务1】三元组别名归一化：CI / 本地脚本可能传入 cargo 简写或平台名，
 *  统一映射到 sing-box 发行包对应的 Rust triple。
 *  - 关键修复：macOS arm64 主机交叉构建 x86_64 时，绝不按 host 架构下载 */
const TRIPLET_ALIASES = {
  "x86_64-pc-windows-gnu": "x86_64-pc-windows-msvc",
  "aarch64-pc-windows-gnu": "aarch64-pc-windows-msvc",
  "x86_64-unknown-linux-musl": "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-musl": "aarch64-unknown-linux-gnu",
};

function normalizeTriplet(raw) {
  const key = String(raw || "").trim();
  if (TRIPLET_ALIASES[key]) return TRIPLET_ALIASES[key];
  // 裸平台名（macos / darwin / linux / windows）按本机架构补全，避免
  // 在 Intel Mac 上误下载 arm64 包
  const arm = process.arch === "arm64" || process.arch === "aarch64";
  if (key === "macos" || key === "darwin") {
    return arm ? "aarch64-apple-darwin" : "x86_64-apple-darwin";
  }
  if (key === "linux") {
    return arm ? "aarch64-unknown-linux-gnu" : "x86_64-unknown-linux-gnu";
  }
  if (key === "windows") {
    return arm ? "aarch64-pc-windows-msvc" : "x86_64-pc-windows-msvc";
  }
  return key;
}

function explicitTarget() {
  // 优先级：--triplet / --target 参数 > TAURI_ENV_TARGET_TRIPLE（Tauri v2
  // 交叉构建时注入）> PRISM_TARGET / CARGO_BUILD_TARGET
  const argIdx = process.argv.findIndex(
    (a) => a === "--triplet" || a === "--target",
  );
  return (
    (argIdx !== -1 && process.argv[argIdx + 1]) ||
    process.env.TAURI_ENV_TARGET_TRIPLE ||
    process.env.PRISM_TARGET ||
    process.env.CARGO_BUILD_TARGET ||
    ""
  );
}

function assetForTriplet(triplet) {
  const asset = TRIPLET_MAP[triplet];
  if (!asset) {
    throw new Error(
      `不支持的目标架构: ${triplet}；支持: ${Object.keys(TRIPLET_MAP).join(", ")}`,
    );
  }
  return asset;
}

function targetInfo() {
  const explicit = explicitTarget();
  if (explicit) {
    const triplet = normalizeTriplet(explicit);
    return [triplet, assetForTriplet(triplet)];
  }
  const key = `${process.platform}-${process.arch}`;
  const map = {
    "win32-x64": "x86_64-pc-windows-msvc",
    "win32-arm64": "aarch64-pc-windows-msvc",
    "darwin-x64": "x86_64-apple-darwin",
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-x64": "x86_64-unknown-linux-gnu",
    "linux-arm64": "aarch64-unknown-linux-gnu",
  };
  const triplet = map[key];
  if (!triplet) {
    throw new Error(
      `不支持的平台: ${key}，请用 --triplet 指定目标（如 aarch64-apple-darwin）`,
    );
  }
  return [triplet, TRIPLET_MAP[triplet]];
}

/** 下载源：官方 + GitHub 镜像。仅构建期（CI/打包）使用——所有产物必须随包分发，应用运行时绝不联网下载 */
function mirrorUrls(official) {
  const urls = [official];
  if (process.env.PRISM_KERNEL_MIRROR) {
    urls.push(`${process.env.PRISM_KERNEL_MIRROR}${official}`);
  }
  urls.push(
    `https://ghfast.top/${official}`,
    `https://gh-proxy.com/${official}`,
    `https://mirror.ghproxy.com/${official}`,
  );
  return urls;
}

function candidateUrls(asset) {
  return mirrorUrls(`https://github.com/SagerNet/sing-box/releases/download/v${KERNEL_VERSION}/${asset}`);
}

/** geoip/geosite 数据库（平台无关）：legacy GEOIP/GEOSITE 规则需要本地库，
 *  缺失时内核会在启动期尝试联网下载（走代理出站，必失败），故随包分发 */
const GEO_DBS = [
  ["geoip.db", "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db"],
  ["geosite.db", "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db"],
];

async function ensureGeoDbs(force) {
  for (const [name, official] of GEO_DBS) {
    const dest = path.join(OUT_DIR, name);
    if (!force && fs.existsSync(dest)) {
      console.log(`[fetch-kernel] 已存在，跳过: src-tauri/binaries/${name}`);
      continue;
    }
    await download(mirrorUrls(official), dest);
    console.log(`[fetch-kernel] 数据库就绪: src-tauri/binaries/${name}`);
  }
}

async function download(urls, dest) {
  let lastErr;
  for (const url of urls) {
    try {
      console.log(`[fetch-kernel] downloading: ${url}`);
      const resp = await fetch(url, { redirect: "follow" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const buf = Buffer.from(await resp.arrayBuffer());
      if (buf.length < 1024 * 1024) throw new Error(`文件过小 (${buf.length} B)，疑似损坏`);
      fs.writeFileSync(dest, buf);
      return;
    } catch (e) {
      console.warn(`[fetch-kernel] 源失败: ${e.message}`);
      lastErr = e;
    }
  }
  throw lastErr ?? new Error("没有可用的下载源");
}

/** 解压 zip/tar.gz：优先系统 tar（Windows 10+ 自带 bsdtar 支持 zip） */
function extract(archive, destDir) {
  try {
    execFileSync("tar", ["-xf", archive, "-C", destDir], { stdio: "inherit" });
    return;
  } catch (e) {
    if (process.platform === "win32" && archive.endsWith(".zip")) {
      execFileSync(
        "powershell",
        ["-NoProfile", "-NonInteractive", "-Command",
          "Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1] -Force", "--", archive, destDir],
        { stdio: "inherit" },
      );
      return;
    }
    throw e;
  }
}

function findBinary(dir, exeSuffix) {
  const want = `sing-box${exeSuffix}`;
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      const p = path.join(cur, entry.name);
      if (entry.isDirectory()) stack.push(p);
      else if (entry.name === want) return p;
    }
  }
  throw new Error(`压缩包内未找到 ${want}`);
}

async function ensureKernel(triplet, force) {
  const asset = assetForTriplet(triplet);
  const exeSuffix = triplet.includes("windows") ? ".exe" : "";
  const target = path.join(OUT_DIR, `sing-box-${triplet}${exeSuffix}`);

  if (!force && fs.existsSync(target)) {
    console.log(`[fetch-kernel] 已存在，跳过: ${path.relative(ROOT, target)}（--force 可重新下载）`);
    return;
  }

  const stageDir = path.join(OUT_DIR, `stage-${Date.now()}`);
  fs.mkdirSync(stageDir, { recursive: true });

  try {
    const archive = path.join(stageDir, asset);
    await download(candidateUrls(asset), archive);
    console.log("[fetch-kernel] extracting…");
    extract(archive, stageDir);
    const found = findBinary(stageDir, exeSuffix);
    fs.copyFileSync(found, target);
    if (process.platform !== "win32") fs.chmodSync(target, 0o755);
    console.log(`[fetch-kernel] sidecar 就绪: ${path.relative(ROOT, target)}`);
  } finally {
    fs.rmSync(stageDir, { recursive: true, force: true });
  }
}

async function main() {
  const force = process.argv.includes("--force");
  const geoOnly = process.argv.includes("--geo-only");

  fs.mkdirSync(OUT_DIR, { recursive: true });

  // 数据库与内核独立获取：内核已存在时也要保证数据库就位
  await ensureGeoDbs(force);

  if (geoOnly) return;

  const explicit = explicitTarget();
  // 【APP44 任务1】macOS 未显式指定目标时必须同时产出 arm64 与 x86_64
  // 两个 sidecar，避免在 Apple Silicon 上交叉构建 x86_64 时报文件不存在
  if (!explicit && process.platform === "darwin") {
    await ensureKernel("aarch64-apple-darwin", force);
    await ensureKernel("x86_64-apple-darwin", force);
    return;
  }

  const [triplet] = targetInfo();
  await ensureKernel(triplet, force);
}

main().catch((e) => {
  console.error(`[fetch-kernel] 失败: ${e.message}`);
  process.exit(1);
});
