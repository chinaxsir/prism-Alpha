//! 编译期字符串混淆（源码保持 100% 明文可读，发布包二进制中不出现明文常量）。
//!
//! 用法：`crate::obf!("https://prism.sarl")`、`crate::obf!("/api/license/status")`。
//! `obf!` 在编译期把字面量与 build.rs 生成的随机密钥异或为字节数组常量，
//! 运行时再异或还原为 `String`——源码里始终是清晰可搜索的明文，
//! 修改字符串与普通字面量无异；Release 包的 `.exe/.so/Mach-O` 中
//! 用 `strings` / IDA 搜不到任何接口地址或路径。

include!(concat!(env!("OUT_DIR"), "/obf_seed.rs"));

/// 运行时还原密文（位置相关非线性混淆 + `black_box` 阻断编译器把常量折叠回明文）
#[inline(never)]
pub fn deobf(cipher: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(cipher.len());
    for (i, b) in cipher.iter().enumerate() {
        let k = OBF_KEY[i % OBF_KEY.len()].wrapping_add((i as u8).wrapping_mul(0x5d));
        let plain = (*b ^ k).wrapping_sub((i as u8).wrapping_mul(0x2b));
        bytes.push(plain);
    }
    let s = String::from_utf8(bytes).unwrap_or_default();
    std::hint::black_box(s)
}

/// 编译期字符串混淆宏：展开为运行时解密的 `String`
#[macro_export]
macro_rules! obf {
    ($s:literal) => {{
        const __OBF_PLAIN: &str = $s;
        const __OBF_LEN: usize = __OBF_PLAIN.len();
        const __OBF_CIPHER: [u8; __OBF_LEN] = {
            let bytes = __OBF_PLAIN.as_bytes();
            let mut out = [0u8; __OBF_LEN];
            let mut i = 0;
            while i < __OBF_LEN {
                let k = $crate::core::obf::OBF_KEY[i % $crate::core::obf::OBF_KEY.len()]
                    .wrapping_add((i as u8).wrapping_mul(0x5d));
                out[i] = bytes[i].wrapping_add((i as u8).wrapping_mul(0x2b)) ^ k;
                i += 1;
            }
            out
        };
        $crate::core::obf::deobf(std::hint::black_box(&__OBF_CIPHER))
    }};
}
