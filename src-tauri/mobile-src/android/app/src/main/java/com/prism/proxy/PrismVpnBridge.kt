package com.prism.proxy

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Looper
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.Keep
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

// Prism VPN 桥：Rust（JNI）唯一入口。
//
// 生命周期顺序（Rust 侧保证）：
//   ensurePermission() → startServiceAndWait() → [libbox openTun/protect] → stopService()
@Keep
object PrismVpnBridge {
    private const val TAG = "PrismVpn"

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

    @Keep
    @JvmStatic
    external fun nativeVpnRevoked()

    // Rust 侧初始化入口：在「携带应用 ClassLoader 的主线程」里解析
    // com/prism/proxy/PrismVpnBridge 并缓存为 JNI GlobalRef。
    // 由 attach() 调用，彻底规避 Rust 后台线程 FindClass 走系统 ClassLoader
    // 导致的 ClassNotFoundException。
    @Keep
    @JvmStatic
    external fun initNative()

    // 由 MainActivity 的 init 块调用（必须早于 Activity STARTED，
    // 因为 registerForActivityResult 要求注册在启动之前）
    @Keep
    @JvmStatic
    fun attach(activity: ComponentActivity) {
        this.activity = activity

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
    @Keep
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
    @Keep
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

    @Keep
    fun onServiceReady(service: PrismVpnService) {
        this.service = service
        ready.countDown()
    }

    // 停止并销毁前台 VPN 服务
    @Keep
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

    @Keep
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

    @Keep
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
