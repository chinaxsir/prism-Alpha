-dontwarn **
-dontoptimize
-dontobfuscate
-keep class com.prism.proxy.** { *; }
-keep class app.tauri.** { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
