//! Windows 系统集成
//!
//! 系统代理写入 HKCU 注册表，并通过 WinInet InternetSetOption 通知应用刷新；
//! 提权检测读取当前进程令牌的 TokenElevation。

use std::io;

use windows::Win32::Networking::WinInet::{
    INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Registry::{
    HKEY_CURRENT_USER, KEY_SET_VALUE, REG_DWORD, REG_SZ, RegCloseKey, RegOpenKeyExW, RegSetValueExW,
};
use windows::core::PCWSTR;
// windows 0.52 中 OpenProcessToken 位于 System::Threading
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::ProxyBackup;

const INTERNET_SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APP_NAME: &str = "Prism";

/// &str -> 以 0 结尾的 UTF-16
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 通知系统代理设置已变更（让 IE/Edge/Chrome 等立即生效）
fn notify_settings_changed() -> io::Result<()> {
    unsafe {
        InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    }
    Ok(())
}

/// 写入注册表字符串/双字值
fn write_reg_value(key_name: &str, value_name: &str, value: &RegValue) -> io::Result<()> {
    let subkey = wide(key_name);
    let value_wide = wide(value_name);

    unsafe {
        let mut hkey = Default::default();
        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );
        if let Err(e) = result {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("RegOpenKeyExW failed: {:?}", e.code()),
            ));
        }

        let set_result = match value {
            RegValue::Dword(dw) => RegSetValueExW(
                hkey,
                PCWSTR(value_wide.as_ptr()),
                0,
                REG_DWORD,
                Some(&dw.to_ne_bytes()),
            ),
            RegValue::Sz(s) => {
                let data_wide = wide(s);
                let bytes: &[u8] = std::slice::from_raw_parts(
                    data_wide.as_ptr() as *const u8,
                    data_wide.len() * 2,
                );
                RegSetValueExW(hkey, PCWSTR(value_wide.as_ptr()), 0, REG_SZ, Some(bytes))
            }
        };

        let _ = RegCloseKey(hkey);

        if let Err(e) = set_result {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("RegSetValueExW failed: {:?}", e.code()),
            ));
        }
    }

    Ok(())
}

enum RegValue {
    Dword(u32),
    Sz(String),
}

/// 读取注册表 DWORD 值
fn read_reg_dword(key_name: &str, value_name: &str) -> io::Result<u32> {
    let subkey = wide(key_name);
    let value_wide = wide(value_name);
    unsafe {
        let mut hkey = Default::default();
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            0,
            windows::Win32::System::Registry::KEY_READ,
            &mut hkey,
        )
        .map_err(|e| io::Error::other(format!("RegOpenKeyExW failed: {:?}", e)))?;
        let mut data = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let result = windows::Win32::System::Registry::RegQueryValueExW(
            hkey,
            PCWSTR(value_wide.as_ptr()),
            None,
            None,
            Some(&mut data as *mut _ as *mut u8),
            Some(&mut size),
        );
        let _ = RegCloseKey(hkey);
        result.map_err(|e| io::Error::other(format!("RegQueryValueExW failed: {:?}", e)))?;
        Ok(data)
    }
}

/// 读取注册表字符串值
fn read_reg_string(key_name: &str, value_name: &str) -> io::Result<String> {
    let subkey = wide(key_name);
    let value_wide = wide(value_name);
    unsafe {
        let mut hkey = Default::default();
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            0,
            windows::Win32::System::Registry::KEY_READ,
            &mut hkey,
        )
        .map_err(|e| io::Error::other(format!("RegOpenKeyExW failed: {:?}", e)))?;
        let mut buffer = vec![0u16; 256];
        let mut size = (buffer.len() * 2) as u32;
        let result = windows::Win32::System::Registry::RegQueryValueExW(
            hkey,
            PCWSTR(value_wide.as_ptr()),
            None,
            None,
            Some(buffer.as_mut_ptr() as *mut u8),
            Some(&mut size),
        );
        let _ = RegCloseKey(hkey);
        result.map_err(|e| io::Error::other(format!("RegQueryValueExW failed: {:?}", e)))?;
        let len = (size as usize) / 2;
        buffer.truncate(len.saturating_sub(1)); // 去掉结尾 null
        Ok(String::from_utf16_lossy(&buffer))
    }
}

/// 读取当前系统代理设置（用于备份）
pub fn get_system_proxy() -> io::Result<ProxyBackup> {
    let enabled = read_reg_dword(INTERNET_SETTINGS_KEY, "ProxyEnable").unwrap_or(0);
    let server = read_reg_string(INTERNET_SETTINGS_KEY, "ProxyServer").unwrap_or_default();
    Ok(ProxyBackup {
        enabled: enabled == 1,
        server,
    })
}

pub fn set_system_proxy(host: &str, port: u16) -> io::Result<()> {
    write_reg_value(INTERNET_SETTINGS_KEY, "ProxyEnable", &RegValue::Dword(1))?;
    write_reg_value(
        INTERNET_SETTINGS_KEY,
        "ProxyServer",
        &RegValue::Sz(format!("{}:{}", host, port)),
    )?;
    notify_settings_changed()
}

pub fn clear_system_proxy() -> io::Result<()> {
    write_reg_value(INTERNET_SETTINGS_KEY, "ProxyEnable", &RegValue::Dword(0))?;
    notify_settings_changed()
}

/// 恢复系统代理到备份状态
pub fn restore_system_proxy(backup: &ProxyBackup) -> io::Result<()> {
    if backup.enabled && !backup.server.is_empty() {
        write_reg_value(
            INTERNET_SETTINGS_KEY,
            "ProxyServer",
            &RegValue::Sz(backup.server.clone()),
        )?;
        write_reg_value(INTERNET_SETTINGS_KEY, "ProxyEnable", &RegValue::Dword(1))?;
    } else {
        write_reg_value(INTERNET_SETTINGS_KEY, "ProxyEnable", &RegValue::Dword(0))?;
    }
    notify_settings_changed()
}

/// 强制结束进程树（panic 兜底，best-effort）
pub fn kill_pid(pid: u32) {
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/T", "/PID", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// 当前进程是否以管理员身份运行
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = Default::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len = 0u32;

        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .is_ok();

        ok && elevation.TokenIsElevated != 0
    }
}

/// 开机自启动：写入 HKCU Run 键
pub fn set_auto_start(enabled: bool) -> io::Result<()> {
    if enabled {
        let exe = std::env::current_exe().map_err(|e| io::Error::other(e.to_string()))?;
        // 路径加引号，避免 Program Files 中空格问题
        let command = format!("\"{}\"", exe.display());
        write_reg_value(RUN_KEY, APP_NAME, &RegValue::Sz(command))
    } else {
        // 删除值：用空 REG_SZ 数据调用等效删除，这里改用删除键值的规范方式
        delete_reg_value(RUN_KEY, APP_NAME)
    }
}

/// 删除注册表值
fn delete_reg_value(key_name: &str, value_name: &str) -> io::Result<()> {
    let subkey = wide(key_name);
    let value_wide = wide(value_name);

    unsafe {
        let mut hkey = Default::default();
        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey.as_ptr()),
            0,
            windows::Win32::System::Registry::KEY_SET_VALUE,
            &mut hkey,
        );
        if result.is_err() {
            return Err(io::Error::other("RegOpenKeyExW failed"));
        }

        // RegSetValueExW 配合 None 数据用于删除（或使用 RegDeleteValueW）
        let delete =
            windows::Win32::System::Registry::RegDeleteValueW(hkey, PCWSTR(value_wide.as_ptr()));
        let _ = RegCloseKey(hkey);

        // 值不存在时忽略错误（win32 ERROR_FILE_NOT_FOUND = 2，
        // HRESULT 形式为 0x80070002，取低 16 位判断）
        if let Err(e) = delete {
            if e.code().0 & 0xFFFF != 2 {
                return Err(io::Error::other(format!("RegDeleteValueW: {:?}", e.code())));
            }
        }
    }
    Ok(())
}
