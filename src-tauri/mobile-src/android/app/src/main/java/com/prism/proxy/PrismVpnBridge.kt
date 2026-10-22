package com.prism.proxy

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Looper
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

// Prism VPN 桥：Rust（JNI）唯一入口。
//
// 生命周期顺序（Rust 侧保证）：
//   ensurePermission() → startServiceAndWait() → [libbox openTun/protect] → stopService()
//
// Release 构建已关闭 R8 压缩混淆（isMinifyEnabled=false），JNI 反射调用的
// 方法不会被裁剪/改名，无需 @Keep 注解（避免引入 androidx.annotation 依赖）
object PrismVpnBridge {
    private const val TAG = "PrismVpn"
    /// 已处理的安装指纹（APP-5 任务2）
    private const val PREF_UPGRADE_FP = "prism_android_install_fingerprint"

    @Volatile
    private var activity: ComponentActivity? = null
    private var consentLauncher: ActivityResultLauncher<Intent>? = null
    @Volatile
    private var consentInFlight = false
    @Volatile
    private var consentLatch: CountDownLatch? = null
    @Volatile
    private var consentGranted = false

    @Volatile
    private var service: PrismVpnService? = null
    @Volatile
    private var ready = CountDownLatch(1)

    @JvmStatic
    external fun nativeVpnRevoked()

    // Rust 侧初始化入口：在「携带应用 ClassLoader 的主线程」里解析
    // com/prism/proxy/PrismVpnBridge 并缓存为 JNI GlobalRef。
    // 由 attach() 调用，彻底规避 Rust 后台线程 FindClass 走系统 ClassLoader
    // 导致的 ClassNotFoundException。
    @JvmStatic
    external fun initNative()

    // 由 MainActivity 的 init 块调用（必须早于 Activity STARTED，
    // 因为 registerForActivityResult 要求注册在启动之前）
    @JvmStatic
    fun attach(activity: ComponentActivity) {
        this.activity = activity

        // APP-5 任务2：覆盖升级检测（必须在任何 VPN 服务交互前执行）。
        // 升级会杀掉旧进程，系统侧残留的前台服务/TUN fd/静态引用全部失效，
        // 不做清理会出现「设置里显示 VPN 已连接但实际无内核」的假连接状态。
        handleUpgradeIfNeeded(activity)

        // 主线程主动触发 Rust 初始化：先确保 so 已加载，再回调 initNative()
        try {
            System.loadLibrary("prism_proxy_lib")
            initNative()
        } catch (t: Throwable) {
            Log.e(TAG, "load native lib / initNative failed", t)
        }

        try {
            this.consentLauncher = activity.registerForActivityResult(
                ActivityResultContracts.StartActivityForResult()
            ) { result ->
                consentGranted = (result.resultCode == Activity.RESULT_OK)
                consentInFlight = false
                consentLatch?.countDown()
                Log.i(TAG, "vpn consent result=${result.resultCode}, granted=$consentGranted")
            }
        } catch (t: Throwable) {
            Log.e(TAG, "registerForActivityResult failed", t)
        }
    }

    // 系统 VPN 授权检查：
    //   true  —— 已授权（或弹窗后用户点击“确定”完成授权）
    //   false —— 用户拒绝授权或当前无法拉起弹窗
    @JvmStatic
    fun ensurePermission(): Boolean {
        return try {
            val act = this.activity ?: return false
            val intent = VpnService.prepare(act) ?: return true

            // 若已在主线程，不能阻塞等待，直接拉起弹窗并返回 false
            if (Looper.myLooper() == Looper.getMainLooper()) {
                if (!consentInFlight) {
                    consentInFlight = true
                    try {
                        consentLauncher?.launch(intent)
                    } catch (t: Throwable) {
                        Log.e(TAG, "launch consent on main thread failed", t)
                        consentInFlight = false
                    }
                }
                return false
            }

            // 在 Rust 工作线程中：切到主线程拉起系统 VPN 授权弹窗，并阻塞等待用户点击结果
            val latch = if (consentInFlight && consentLatch != null) {
                consentLatch!!
            } else {
                CountDownLatch(1).also {
                    consentLatch = it
                    consentGranted = false
                    consentInFlight = true
                    act.runOnUiThread {
                        try {
                            val launcher = consentLauncher
                            if (launcher != null) {
                                launcher.launch(intent)
                            } else {
                                @Suppress("DEPRECATION")
                                act.startActivityForResult(intent, 0x5052)
                                consentInFlight = false
                                it.countDown()
                            }
                        } catch (t: Throwable) {
                            Log.e(TAG, "launch consent failed", t)
                            consentInFlight = false
                            it.countDown()
                        }
                    }
                }
            }

            latch.await(60, TimeUnit.SECONDS)
            consentGranted || VpnService.prepare(act) == null
        } catch (t: Throwable) {
            Log.e(TAG, "ensurePermission error", t)
            consentInFlight = false
            false
        }
    }

    // 启动前台 VPN 服务并阻塞等待其就绪（Go 索要 TUN fd 前服务必须已前台化）
    @JvmStatic
    fun startServiceAndWait(): Boolean {
        return try {
            val act = this.activity ?: return false
            ready = CountDownLatch(1)
            service = null
            val intent = Intent().apply {
                component = ComponentName(act, PrismVpnService::class.java)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                act.applicationContext.startForegroundService(intent)
            } else {
                act.applicationContext.startService(intent)
            }
            ready.await(8, TimeUnit.SECONDS)
            service != null
        } catch (t: Throwable) {
            Log.e(TAG, "start vpn service failed", t)
            false
        }
    }

    fun onServiceReady(service: PrismVpnService) {
        this.service = service
        ready.countDown()
    }

    // APP-5 任务2：覆盖升级检测。
    // 指纹 = versionCode|lastUpdateTime：版本号相同但被重装/重签时
    // lastUpdateTime 也会变化，比单纯 versionCode 更可靠。
    private fun installFingerprint(activity: Activity): String {
        return try {
            val pm = activity.packageManager
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(activity.packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(activity.packageName, 0)
            }
            "${info.longVersionCode}|${info.lastUpdateTime}"
        } catch (t: Throwable) {
            Log.w(TAG, "read install fingerprint failed", t)
            ""
        }
    }

    private fun handleUpgradeIfNeeded(activity: Activity) {
        val fingerprint = installFingerprint(activity)
        if (fingerprint.isEmpty()) return
        val prefs = activity.getSharedPreferences("prism_state", Context.MODE_PRIVATE)
        val last = prefs.getString(PREF_UPGRADE_FP, null)
        if (last == fingerprint) return
        prefs.edit().putString(PREF_UPGRADE_FP, fingerprint).apply()
        Log.i(TAG, "检测到覆盖安装 $last -> $fingerprint，清理陈旧 VPN 状态")
        // 旧服务的 TUN fd 与前台通知随旧进程销毁已失效，这里只清引用并
        // 尽力停掉可能残留的服务，避免下次启动复用无效 fd
        try {
            stopService()
        } catch (t: Throwable) {
            Log.w(TAG, "cleanup stale vpn service failed", t)
        }
    }

    // 停止并销毁前台 VPN 服务
    @JvmStatic
    fun stopService() {
        val act = this.activity
        try {
            service?.shutdown()
        } catch (t: Throwable) {
            Log.w(TAG, "service shutdown error", t)
        }
        if (act != null) {
            val intent = Intent().apply {
                component = ComponentName(act, PrismVpnService::class.java)
            }
            try {
                act.applicationContext.stopService(intent)
            } catch (_: Throwable) {
            }
        }
        service = null
    }

    @JvmStatic
    fun openTun(optionsJson: String): Int {
        val svc = this.service ?: run {
            Log.e(TAG, "openTun: service not ready")
            return -1
        }
        return try {
            svc.openTun(optionsJson)
        } catch (t: Throwable) {
            Log.e(TAG, "openTun failed", t)
            -1
        }
    }

    @JvmStatic
    fun protectSocket(fd: Int): Boolean {
        val svc = this.service ?: return false
        return try {
            svc.protect(fd)
        } catch (t: Throwable) {
            Log.e(TAG, "protect($fd) failed", t)
            false
        }
    }
}
