#!/usr/bin/env node
/**
 * 将移动端 VPN 原生代码注入 `tauri android init` 生成的工程。
 *
 * gen/android 由 CLI 在 CI/本地现生成（不入库），因此所有定制必须
 * 在 init 之后经本脚本幂等注入：
 *   1. 拷贝 mobile-src/android（PrismVpnBridge / PrismVpnService）
 *   2. MainActivity.kt 增加 PrismVpnBridge.attach(this) 与 @Keep
 *   3. AndroidManifest.xml 增加 BIND_VPN_SERVICE/前台服务权限与 VPN Service
 *   4. proguard-rules.pro 增加 JNI 防裁剪与防混淆规则（IPA-12 2.2）
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

// 2. MainActivity 注入 attach 与 @Keep
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
  // @Keep（IPA-12 2.2）：MainActivity 被 Tauri 宿主/外部反射引用，
  // Release 构建禁止 R8 裁剪与改名
  if (!text.includes('@Keep')) {
    if (!text.includes('import androidx.annotation.Keep')) {
      text = text.replace(/(package [^\n]+\n)/, `$1\nimport androidx.annotation.Keep\n`)
    }
    text = text.replace(/(class\s+MainActivity[^\n{]*)/, '@Keep\n$1')
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

// 4. ProGuard 注入防混淆规则（IPA-12 2.2）
//
// 根因：Release 构建启用 R8 后，ensurePermission / startServiceAndWait /
// openTun / protectSocket 等方法仅由 Rust 经 JNI 反射调用，Kotlin 侧无
// 直接引用，R8 会将其裁剪或改名（a()/b()），真机首次启动即抛
// NoSuchMethodError（表现为 "call ensurePermission: Java exception was thrown"）
function patchProguard() {
  const file = path.join(GEN, 'app', 'proguard-rules.pro')
  let text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : ''
  if (text.includes('IPA-12 2.2')) {
    console.log('[inject-android-vpn] proguard-rules.pro already patched')
    return
  }

  const rules = `
# --- Prism VPN JNI Keep Rules（IPA-12 2.2）---
# Prism 全部 Kotlin 类（PrismVpnBridge / PrismVpnService / MainActivity）
# 的成员原样保留：JNI 按名反射调用，禁止裁剪与混淆改名
-keep class com.prism.proxy.** { *; }
-keepclassmembers class com.prism.proxy.** { *; }
# Tauri 宿主层同样被反射与 JNI 引用
-keep class app.tauri.** { *; }
-keepclassmembers class app.tauri.** { *; }
# native 方法名必须与 SO 导出符号严格对应
-keepclasseswithmembernames class * {
    native <methods>;
}
# 标注 @androidx.annotation.Keep 的类/字段/方法强制保留
-keep class * {
    @androidx.annotation.Keep *;
}
-keepclassmembers class * {
    @androidx.annotation.Keep <fields>;
    @androidx.annotation.Keep <methods>;
}
-dontwarn com.prism.proxy.**
-dontwarn app.tauri.**
`
  fs.writeFileSync(file, text + '\n' + rules)
  console.log('[inject-android-vpn] proguard-rules.pro patched')
}
patchProguard()

console.log('[inject-android-vpn] done')
