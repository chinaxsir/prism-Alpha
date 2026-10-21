#!/usr/bin/env node
/**
 * 将移动端 VPN 原生代码注入 `tauri android init` 生成的工程。
 *
 * gen/android 由 CLI 在 CI/本地现生成（不入库），因此所有定制必须
 * 在 init 之后经本脚本幂等注入：
 *   1. 拷贝 mobile-src/android（PrismVpnBridge / PrismVpnService）
 *   2. MainActivity.kt 增加 PrismVpnBridge.attach(this)
 *   3. AndroidManifest.xml 增加 BIND_VPN_SERVICE/前台服务权限与 VPN Service
 *   4. build.gradle.kts 关闭 Release R8 压缩混淆（APK-3 任务1）：
 *      isMinifyEnabled / isShrinkResources / optimization.enable → false
 *   5. proguard-rules.pro 以无 BOM 纯 UTF-8 整体重写（APK-3 任务1）
 */
const fs = require('fs')
const path = require('path')

const ROOT = path.resolve(__dirname, '..')
const GEN = path.join(ROOT, 'src-tauri', 'gen', 'android')
const SRC = path.join(ROOT, 'src-tauri', 'mobile-src', 'android')

if (!fs.existsSync(GEN)) {
  console.error(`[inject-android-vpn] ${GEN} 不存在，请先执行 npx tauri android init`)
  process.exit(1)
}

function copyDir(from, to) {
  fs.mkdirSync(to, { recursive: true })
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const s = path.join(from, entry.name)
    const d = path.join(to, entry.name)
    if (entry.isDirectory()) copyDir(s, d)
    else fs.copyFileSync(s, d)
  }
}

// 1. 拷贝 Kotlin 源
copyDir(SRC, GEN)
console.log('[inject-android-vpn] copied mobile-src/android -> gen/android')

// 2. MainActivity 注入 attach
// （APK-3：不再注入 @Keep——Release 已关闭 R8，混淆裁剪不存在；
//   且 @Keep 需要 androidx.annotation 依赖，缺失时直接编译失败）
function patchMainActivity() {
  const rel = path.join('app', 'src', 'main', 'java', 'com', 'prism', 'proxy', 'MainActivity.kt')
  const file = path.join(GEN, rel)
  if (!fs.existsSync(file)) {
    console.error(`[inject-android-vpn] MainActivity 未找到：${rel}`)
    process.exit(1)
  }
  let text = fs.readFileSync(file, 'utf8')
  let touched = false
  if (!text.includes('PrismVpnBridge.attach')) {
    const initBlock = '    init { PrismVpnBridge.attach(this) }'
    const brace = text.indexOf('{')
    if (brace >= 0) {
      text = text.slice(0, brace + 1) + '\n' + initBlock + text.slice(brace + 1)
    } else {
      // class MainActivity : TauriActivity() —— 无类体
      text = text.replace(/(class\s+MainActivity[^\n]*)/, `$1 {\n${initBlock}\n}`)
    }
    touched = true
  }
  if (touched) {
    fs.writeFileSync(file, text)
    console.log('[inject-android-vpn] MainActivity patched')
  } else {
    console.log('[inject-android-vpn] MainActivity already patched')
  }
}
patchMainActivity()

// 3. AndroidManifest 注入权限与 Service
function patchManifest() {
  const file = path.join(GEN, 'app', 'src', 'main', 'AndroidManifest.xml')
  let text = fs.readFileSync(file, 'utf8')
  if (!text.includes('PrismVpnService')) {
    const permissions = [
      '<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>',
      '<uses-permission android:name="android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED"/>',
    ].join('\n    ')

    const service = `
        <service
            android:name=".PrismVpnService"
            android:exported="false"
            android:foregroundServiceType="systemExempted"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService"/>
            </intent-filter>
        </service>`

    if (!text.includes('</application>') || !text.includes('</manifest>')) {
      console.error('[inject-android-vpn] AndroidManifest 结构异常')
      process.exit(1)
    }
    text = text.replace('</application>', `${service}\n        </application>`)
    text = text.replace('</manifest>', `    ${permissions}\n</manifest>`)
    fs.writeFileSync(file, text)
    console.log('[inject-android-vpn] AndroidManifest patched')
  } else {
    console.log('[inject-android-vpn] AndroidManifest already patched')
  }
  // IPA-12 2.4：Android 14+ 前台服务类型兼容声明。部分 ROM 校验
  // SPECIAL_USE 类型时需此权限；systemExempted 主路径不变。
  // 独立幂等判断，兼容旧版脚本已注入过 service 的工程
  if (!text.includes('FOREGROUND_SERVICE_SPECIAL_USE')) {
    text = text.replace(
      '</manifest>',
      `    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE"/>\n</manifest>`,
    )
    fs.writeFileSync(file, text)
    console.log('[inject-android-vpn] FOREGROUND_SERVICE_SPECIAL_USE added')
  }
}
patchManifest()

// 4. 关闭 Release 构建的 R8 压缩混淆（APK-3 任务1）
//
// 根因：R8 在 :app:minifyUniversalReleaseWithR8 阶段即可能因 proguard 配置
// 编码问题（PowerShell 写入的 UTF-8 BOM）或严格检查直接编译失败；即便构建
// 通过，R8 也会把仅由 Rust 经 JNI 反射调用的 Kotlin 方法（ensurePermission /
// startServiceAndWait / openTun / protectSocket）当成无用代码裁剪或改名，
// 真机首次启动即抛 NoSuchMethodError（"call ensurePermission: Java exception
// was thrown"）。彻底根治：关闭 minify/shrinkResources，直接跳过 R8 任务。
// 幂等：重复执行结果不变。
function patchBuildGradle() {
  const file = path.join(GEN, 'app', 'build.gradle.kts')
  if (!fs.existsSync(file)) {
    console.error('[inject-android-vpn] build.gradle.kts 未找到')
    process.exit(1)
  }
  let text = fs.readFileSync(file, 'utf8')
  const before = text
  // 经典 DSL（AGP ≤ 8 模板）与 AGP 9 的 optimization DSL 两种写法都覆盖
  text = text
    .replace(/isMinifyEnabled\s*=\s*true/g, 'isMinifyEnabled = false')
    .replace(/isShrinkResources\s*=\s*true/g, 'isShrinkResources = false')
    .replace(
      /(optimization\s*\{[^}]*?)enable\s*=\s*true/g,
      '$1enable = false',
    )
  if (text !== before) {
    fs.writeFileSync(file, text)
    console.log('[inject-android-vpn] build.gradle.kts: R8 minify/shrink disabled')
  } else {
    console.log('[inject-android-vpn] build.gradle.kts: R8 already disabled')
  }
}
patchBuildGradle()

// 5. proguard-rules.pro 以无 BOM 纯 UTF-8 整体重写（APK-3 任务1）
//
// R8 已关闭，本文件实际不再参与构建；保留一份简洁规则仅作防御（若未来
// 重新开启混淆时 JNI 入口仍受保护）。严禁 PowerShell Set-Content 写入
// （PS 5.1 默认带 0xEF 0xBB 0xBF BOM 头，R8/Gradle 解析器直接报错）——
// Node fs.writeFileSync 默认输出无 BOM 的 UTF-8。
function patchProguard() {
  const file = path.join(GEN, 'app', 'proguard-rules.pro')
  const rules = `-dontwarn **
-dontoptimize
-dontobfuscate
-keep class com.prism.proxy.** { *; }
-keep class app.tauri.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
`
  fs.writeFileSync(file, rules, 'utf8')
  // 校验首字节不是 BOM（防御性自检，失败即中断注入）
  const first = fs.readFileSync(file)[0]
  if (first === 0xef) {
    console.error('[inject-android-vpn] proguard-rules.pro 检测到 BOM 头，写入失败')
    process.exit(1)
  }
  console.log('[inject-android-vpn] proguard-rules.pro rewritten (no BOM)')
}
patchProguard()

console.log('[inject-android-vpn] done')
