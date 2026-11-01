#!/usr/bin/env node
/**
 * 【APP38 任务1】全仓 UTF-8 BOM（0xEF 0xBB 0xBF）扫描与清除。
 * 扫描根目录及子目录（排除 node_modules/target/dist/.git/gen）下所有文本类
 * 源码与配置文件；发现 BOM 立即剥离前 3 字节并以无 BOM 纯 UTF-8 写回。
 * 结束后对 package.json / tauri.conf.json / tsconfig.json 做 JSON.parse 校验。
 */
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const EXCLUDE_DIRS = new Set([
  "node_modules",
  "target",
  "dist",
  ".git",
  "gen",
  "license-server",
  "license-worker",
  ".uploads",
]);
const EXTENSIONS = new Set([
  ".json", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".css", ".html",
  ".rs", ".toml", ".swift", ".go", ".plist", ".yml", ".yaml", ".rb",
]);

const bomFiles = [];
let scanned = 0;

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (EXCLUDE_DIRS.has(entry.name)) continue;
      walk(path.join(dir, entry.name));
      continue;
    }
    if (!entry.isFile()) continue;
    if (!EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;
    const file = path.join(dir, entry.name);
    scanned++;
    const fd = fs.openSync(file, "r");
    const head = Buffer.alloc(3);
    const read = fs.readSync(fd, head, 0, 3, 0);
    fs.closeSync(fd);
    if (read === 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) {
      const content = fs.readFileSync(file);
      fs.writeFileSync(file, content.subarray(3), { encoding: "utf8" });
      bomFiles.push(path.relative(ROOT, file));
    }
  }
}

walk(ROOT);

console.log(`已扫描 ${scanned} 个文本文件`);
if (bomFiles.length === 0) {
  console.log("✅ 未发现任何 UTF-8 BOM 头");
} else {
  console.log(`⚠️  已剥离 ${bomFiles.length} 个文件的 BOM 头：`);
  for (const f of bomFiles) console.log(`   - ${f}`);
}

// 关键 JSON 文件原生 JSON.parse 严格校验
let jsonOk = true;
for (const rel of ["package.json", "src-tauri/tauri.conf.json", "tsconfig.json"]) {
  const p = path.join(ROOT, rel);
  if (!fs.existsSync(p)) continue;
  try {
    JSON.parse(fs.readFileSync(p, "utf8"));
    console.log(`✅ JSON.parse 校验通过：${rel}`);
  } catch (e) {
    jsonOk = false;
    console.error(`❌ JSON.parse 校验失败：${rel} → ${e.message}`);
  }
}
process.exit(jsonOk ? 0 : 1);
