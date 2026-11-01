package com.prism.proxy

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.annotation.Keep

// @Keep（IPA-12 2.2）：MainActivity 生命周期/桥接方法被 Tauri 宿主与
// R8 外部（JNI/反射）引用，Release 构建禁止裁剪与改名
@Keep
class MainActivity : TauriActivity() {
    init { PrismVpnBridge.attach(this) }
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }
}
