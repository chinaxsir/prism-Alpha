#!/usr/bin/env node
/**
 * 将移动端 VPN 原生代码注入 `tauri android init` 生成的工程。
 *
 * gen/android 由 CLI 在 CI/本地现生成（不入库），因此所有定制必须
 * 在 init 之后经本脚本幂等注入：
 *   1. 拷贝 mobile-src/android（PrismVpnBridge / PrismVpnService）
 *   2. MainActivity.kt 增加 PrismVpnBridge.attach(this)
 *   3. AndroidManifest.xml 增加 BIND_VPN_SERVICE/前台服务权限与 VPN Service
 *   4. proguard-rules.pro 增加 JNI 防裁剪与防混淆规则
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
function patchMainActivity() {
  const rel = path.join('app', 'src', 'main', 'java', 'com', 'prism', 'proxy', 'MainActivity.kt')
  const file = path.join(GEN, rel)
  if (!fs.existsSync(file)) {
    console.error(`[inject-android-vpn] MainActivity 未找到：${rel}`)
    process.exit(1)
  }
  let text = fs.readFileSync(file, 'utf8')
  if (text.includes('PrismVpnBridge.attach')) {
    console.log('[inject-android-vpn] MainActivity already patched')
    return
  }

  const initBlock = '    init { PrismVpnBridge.attach(this) }'
  const brace = text.indexOf('{')
  if (brace >= 0) {
    text = text.slice(0, brace + 1) + '\n' + initBlock + text.slice(brace + 1)
  } else {
    // class MainActivity : TauriActivity() —— 无类体
    text = text.replace(/(class\s+MainActivity[^\n]*)/, `$1 {\n${initBlock}\n}`)
  }
  fs.writeFileSync(file, text)
  console.log('[inject-android-vpn] MainActivity patched')
}
patchMainActivity()

// 3. AndroidManifest 注入权限与 Service
function patchManifest() {
  const file = path.join(GEN, 'app', 'src', 'main', 'AndroidManifest.xml')
  let text = fs.readFileSync(file, 'utf8')
  if (text.includes('PrismVpnService')) {
    console.log('[inject-android-vpn] AndroidManifest already patched')
    return
  }

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
}
patchManifest()

// 4. ProGuard 注入防混淆规则（防止 R8 裁剪 JNI 反射调用的 PrismVpnBridge 方法）
function patchProguard() {
  const file = path.join(GEN, 'app', 'proguard-rules.pro')
  let text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : ''
  if (text.includes('com.prism.proxy.PrismVpnBridge')) {
    console.log('[inject-android-vpn] proguard-rules.pro already patched')
    return
  }

  const rules = `
# --- Prism VPN JNI Keep Rules ---
-keep class com.prism.proxy.** { *; }
-keepclassmembers class com.prism.proxy.** { *; }
-dontwarn com.prism.proxy.**
`
  fs.writeFileSync(file, text + '\n' + rules)
  console.log('[inject-android-vpn] proguard-rules.pro patched')
}
patchProguard()

console.log('[inject-android-vpn] done')
