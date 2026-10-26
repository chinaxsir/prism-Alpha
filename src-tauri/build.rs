//! 构建脚本：
//! 1. tauri_build：能力/codegen，并在 Android 编译期生成
//!    gen/android/tauri.settings.gradle（缺失会导致 Gradle settings 评估失败）、
//!    注入 desktop/mobile cfg 别名（缺它会报 unexpected `cfg` condition `desktop`）。
//! 2. iOS 目标链接内嵌 sing-box 静态库（c-archive，.a）；
//!    Android 目标链接内嵌 sing-box 共享库（c-shared，.so——Go 不支持
//!    android 上的 c-archive），产物由 CI 构建并拷入 jniLibs 供 APK 打包。

use std::path::{Path, PathBuf};

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let kernel_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ios-kernel");

    generate_obf_seed();

    match target_os.as_str() {
        "ios" => {
            println!("cargo:rustc-link-search=native={}", kernel_dir.display());
            println!("cargo:rustc-link-lib=static=prismkernel");
            // Go runtime / x509 根证书在 Apple 平台的依赖框架
            for fw in ["Security", "Foundation", "CoreFoundation", "SystemConfiguration"] {
                println!("cargo:rustc-link-lib=framework={fw}");
            }
            // Go c-archive iOS 运行时还依赖 libresolv（res_9_ninit/nclose/nsearch）与 libz
            for lib in ["resolv", "z"] {
                println!("cargo:rustc-link-lib={lib}");
            }
            // prism_ios_vpn_start/stop/is_connected/connected_timestamp 由主 App
            // Swift（@_cdecl）实现，在 Xcode 最终链接 staticlib 时才存在；crate-type
            // 里的 cdylib 会单独链接 libprism_proxy_lib.dylib（CI run 37707763501
            // 实证 Undefined symbols → exit 65）。用 ld64 -U 只放行这些
            // 符号（dylib 在 iOS 真机构建中从不被加载，真实解析仍由 Xcode
            // 链接期强校验；is_connected 为 build 157 状态轮询新增，
            // CI run 38753559779 实证缺它会 Undefined symbols；
            // connected_timestamp 为 IPA-12 零延迟时长同步新增；
            // upgrade_selfheal / take_pending_restart 为 APP-6 自愈新增；
            // get_device_id 为 APP-7 设备解绑感知新增）
            for sym in [
                "_prism_ios_vpn_start",
                "_prism_ios_vpn_stop",
                "_prism_ios_vpn_is_connected",
                "_prism_ios_vpn_connected_timestamp",
                "_prism_ios_take_pending_restart",
                "_prism_ios_upgrade_selfheal",
                "_prism_ios_get_device_id",
                "_prism_ios_app_group_dir",
            ] {
                println!("cargo:rustc-link-arg=-Wl,-U,{sym}");
            }
            // 双重保险：Xcode 最终链接期若新加入 Swift @_cdecl 但忘了
            // 更新上方符号列表，dynamic_lookup 让 ld64 不提前报错；
            // 真正是否存在仍由运行时 dlsym 强校验（iOS 端会在启动时
            // 主动探测），绝不会放行缺失符号到用户设备上才崩溃
            println!("cargo:rustc-link-arg=-Wl,-undefined,dynamic_lookup");
            println!(
                "cargo:rerun-if-changed={}",
                kernel_dir.join("libprismkernel.a").display()
            );
        }
        "android" => {
            // Go 在 android 上不支持 c-archive，改用 c-shared 产出 .so；
            // 按架构单独命名（CI 在 ios-kernel/ 一次产出四个），并拷入 jniLibs 打包。
            let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
            let name = match arch.as_str() {
                "aarch64" => "prismkernel-arm64",
                "arm" => "prismkernel-arm",
                "x86" => "prismkernel-386",
                "x86_64" => "prismkernel-amd64",
                other => panic!("android: 内嵌内核不支持的架构: {other}"),
            };
            println!("cargo:rustc-link-search=native={}", kernel_dir.display());
            println!("cargo:rustc-link-lib=dylib={name}");
            // Go android 运行时需要 liblog（__android_log_print）
            println!("cargo:rustc-link-lib=log");
            println!(
                "cargo:rerun-if-changed={}",
                Path::new(&kernel_dir)
                    .join(format!("lib{name}.so"))
                    .display()
            );
        }
        _ => {}
    }

    tauri_build::build()
}

/// 生成编译期字符串混淆密钥（`$OUT_DIR/obf_seed.rs`）。
/// 由项目指纹（名称/版本/目标平台）经 FNV-1a 派生并扩展为 32 字节——
/// 同一版本可复现、不同版本/平台密钥不同；源码侧仍是明文 `obf!("...")`。
fn generate_obf_seed() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    let seed = format!(
        "{}:{}:{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default()
    );

    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in seed.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }

    let mut key = [0u8; 32];
    for (i, slot) in key.iter_mut().enumerate() {
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h = h.wrapping_add((i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        *slot = (h >> 32) as u8;
    }

    let src = format!(
        "// 由 build.rs 自动生成（编译期字符串混淆密钥），请勿手改\n\
         pub const OBF_KEY: [u8; 32] = {key:?};\n"
    );
    std::fs::write(out_dir.join("obf_seed.rs"), src).expect("write obf_seed.rs");
    println!("cargo:rerun-if-changed=build.rs");
}
