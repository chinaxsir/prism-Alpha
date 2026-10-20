package com.prism.proxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

// Prism 系统 VPN 服务：建立 TUN 并把文件描述符交给 Go libbox。
// 参考 sing-box 官方 Android 实现 VPNService.kt。
// @Keep（IPA-12 2.2）：openTun/shutdown 由 Rust 经 JNI 反射调用，
// R8 裁剪/改名将导致真机 NoSuchMethodError
@androidx.annotation.Keep
class PrismVpnService : VpnService() {

    companion object {
        private const val TAG = "PrismVpn"
        private const val NOTIFICATION_ID = 0x7012
        private const val CHANNEL_ID = "prism_vpn"
    }

    private var tunFd: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        startAsForeground()
        PrismVpnBridge.onServiceReady(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 桥已在 onCreate 完成 attach；保持粘性以应对系统回收
        return START_STICKY
    }

    // 由 Go（经 JNI）在 libbox 启动时调用（IPA-12 2.2：@Keep 防 R8 裁剪）
    @androidx.annotation.Keep
    fun openTun(optionsJson: String): Int {
        val options = JSONObject(optionsJson)
        val builder = Builder()
            .setSession("Prism")
            .setMtu(options.optInt("mtu", 9000))

        val v4 = options.optJSONArray("inet4_address") ?: JSONArray()
        for (i in 0 until v4.length()) {
            val p = v4.getJSONObject(i)
            builder.addAddress(p.getString("address"), p.getInt("prefix"))
        }
        val v6 = options.optJSONArray("inet6_address") ?: JSONArray()
        for (i in 0 until v6.length()) {
            val p = v6.getJSONObject(i)
            builder.addAddress(p.getString("address"), p.getInt("prefix"))
        }

        if (options.optBoolean("auto_route", true)) {
            // VPN DNS 指向 libbox 虚拟 DNS（tun 地址 +1）
            options.optString("dns_server").takeIf { it.isNotEmpty() }?.let {
                builder.addDnsServer(it)
            }

            addRoutes(builder, options.optJSONArray("inet4_route_address"), "0.0.0.0", 0)
            addRoutes(builder, options.optJSONArray("inet6_route_address"), "::", 0)
            addExcludedRoutes(builder, options.optJSONArray("inet4_route_exclude_address"))
            addExcludedRoutes(builder, options.optJSONArray("inet6_route_exclude_address"))

            // 分应用代理
            val include = options.optJSONArray("include_package")
            if (include != null && include.length() > 0) {
                for (i in 0 until include.length()) builder.addAllowedApplication(include.getString(i))
            }
            val exclude = options.optJSONArray("exclude_package")
            if (exclude != null && exclude.length() > 0) {
                for (i in 0 until exclude.length()) builder.addDisallowedApplication(exclude.getString(i))
            }
        }

        // 始终放行本 App，避免 UI/API 流量被卷进隧道
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }

        val pfd = builder.establish() ?: return -1
        tunFd = pfd
        Log.i(TAG, "tun established fd=${pfd.fd}")
        return pfd.fd
    }

    private fun addRoutes(
        builder: Builder,
        routes: JSONArray?,
        defaultAddress: String,
        defaultPrefix: Int,
    ) {
        if (routes == null || routes.length() == 0) {
            builder.addRoute(defaultAddress, defaultPrefix)
            return
        }
        for (i in 0 until routes.length()) {
            val p = routes.getJSONObject(i)
            builder.addRoute(p.getString("address"), p.getInt("prefix"))
        }
    }

    private fun addExcludedRoutes(builder: Builder, routes: JSONArray?) {
        // Android VpnService.Builder 无排除路由 API（系统 VPN 只支持全量路由），
        // 排除由内核 strict_route / 路由规则在数据面处理
        if (routes != null && routes.length() > 0) {
            Log.i(TAG, "exclude routes ignored at platform layer (${routes.length()})")
        }
    }

    // 系统撤销 VPN（用户在系统设置中关闭 / 其他 VPN 抢占）
    override fun onRevoke() {
        Log.w(TAG, "vpn revoked")
        try {
            PrismVpnBridge.nativeVpnRevoked()
        } catch (e: Exception) {
            Log.w(TAG, "notify revoke failed", e)
        }
        shutdown()
        super.onRevoke()
        stopSelf()
    }

    fun shutdown() {
        try {
            tunFd?.close()
        } catch (_: Exception) {
        }
        tunFd = null
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun startAsForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Prism VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply { setShowBadge(false) }
            manager.createNotificationChannel(channel)
        }

        // Notification.Builder(Context, String) 为 API 26(Android 8.0) 起新增构造器，
        // minSdk=24，Android 7.x 直接调用会抛 NoSuchMethodError 导致前台服务崩溃，
        // 故按系统版本选择构造器。
        @Suppress("DEPRECATION")
        val notification: Notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Prism")
                .setContentText("VPN 已连接")
                .setSmallIcon(R.mipmap.ic_launcher_foreground)
                .setOngoing(true)
                .build()
        } else {
            Notification.Builder(this)
                .setContentTitle("Prism")
                .setContentText("VPN 已连接")
                .setSmallIcon(R.mipmap.ic_launcher_foreground)
                .setOngoing(true)
                .build()
        }

        // Android 14+（API 34）必须显式声明前台服务类型；部分国产定制 ROM 对
        // SYSTEM_EXEMPTED 校验过严可能抛异常，逐级 try-catch 兜底降级（IPA-12 2.4）：
        // 先按 SYSTEM_EXEMPTED 前台化，失败则退回无类型 startForeground——
        // 任何路径都不允许让服务启动直接闪退
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            try {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED,
                )
                return
            } catch (_: Throwable) {
                // fallthrough 到无类型前台化
            }
        }
        try {
            startForeground(NOTIFICATION_ID, notification)
        } catch (_: Throwable) {
            Log.e(TAG, "startForeground failed on all paths")
        }
    }
}
