//! Linux 系统集成
//!
//! 通过 GNOME gsettings 设置系统代理（覆盖 GNOME 及兼容实现，如 Budgie/Cinnamon）；
//! 自启动通过 ~/.config/autostart 下的 .desktop 文件实现。
//!
//! 无图形/无 gsettings 的环境（headless、纯 TUN 服务器）中静默跳过。

use std::io;
use std::process::Command;

use super::ProxyBackup;

fn gsettings(args: &[&str]) -> bool {
    Command::new("gsettings")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 读取当前系统代理设置（用于备份）
pub fn get_system_proxy() -> io::Result<ProxyBackup> {
    // 检查 mode 是否为 manual
    let output = Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy", "mode"])
        .output()?;
    let mode = String::from_utf8_lossy(&output.stdout)
        .trim()
        .replace("'", "");
    if mode != "manual" {
        return Ok(ProxyBackup::default());
    }

    // 读取 http host/port 作为代表
    let host_out = Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy.http", "host"])
        .output()?;
    let host = String::from_utf8_lossy(&host_out.stdout)
        .trim()
        .replace("'", "");
    let port_out = Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy.http", "port"])
        .output()?;
    let port = String::from_utf8_lossy(&port_out.stdout).trim().to_string();

    if host.is_empty() || port.is_empty() || port == "0" {
        return Ok(ProxyBackup::default());
    }

    Ok(ProxyBackup {
        enabled: true,
        server: format!("{}:{}", host, port),
    })
}

pub fn set_system_proxy(host: &str, port: u16) -> io::Result<()> {
    let port = port.to_string();

    // gsettings 不可用时静默返回（例如 CI/headless）
    if !gsettings(&["get", "org.gnome.system.proxy", "mode"]) {
        tracing::debug!("gsettings unavailable, skip setting system proxy");
        return Ok(());
    }

    gsettings(&["set", "org.gnome.system.proxy", "mode", "'manual'"]);

    for scheme in ["http", "https", "socks"] {
        gsettings(&[
            "set",
            &format!("org.gnome.system.proxy.{}", scheme),
            "host",
            &format!("'{}'", host),
        ]);
        gsettings(&[
            "set",
            &format!("org.gnome.system.proxy.{}", scheme),
            "port",
            &port,
        ]);
    }

    Ok(())
}

pub fn clear_system_proxy() -> io::Result<()> {
    gsettings(&["set", "org.gnome.system.proxy", "mode", "'none'"]);
    Ok(())
}

/// 恢复系统代理到备份状态
pub fn restore_system_proxy(backup: &ProxyBackup) -> io::Result<()> {
    if backup.enabled && !backup.server.is_empty() {
        let parts: Vec<&str> = backup.server.split(':').collect();
        let host = parts.first().copied().unwrap_or("127.0.0.1");
        let port = parts.get(1).copied().unwrap_or("7890");
        gsettings(&["set", "org.gnome.system.proxy", "mode", "'manual'"]);
        for scheme in ["http", "https", "socks"] {
            gsettings(&[
                "set",
                &format!("org.gnome.system.proxy.{}", scheme),
                "host",
                &format!("'{}'", host),
            ]);
            gsettings(&[
                "set",
                &format!("org.gnome.system.proxy.{}", scheme),
                "port",
                port,
            ]);
        }
    } else {
        clear_system_proxy()?;
    }
    Ok(())
}

/// 开机自启动：XDG autostart .desktop 文件
pub fn set_auto_start(enabled: bool) -> io::Result<()> {
    let home = std::env::var("HOME").map_err(|_| io::Error::other("no HOME"))?;
    let dir = format!("{}/.config/autostart", home);
    let desktop_path = format!("{}/prism-proxy.desktop", dir);

    if enabled {
        std::fs::create_dir_all(&dir)?;
        let exe = std::env::current_exe()?;
        let desktop = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Prism Proxy\n\
             Exec=\"{}\"\n\
             Terminal=false\n\
             X-GNOME-Autostart-enabled=true\n",
            exe.display()
        );
        std::fs::write(&desktop_path, desktop)?;
    } else if std::path::Path::new(&desktop_path).exists() {
        std::fs::remove_file(&desktop_path)?;
    }

    Ok(())
}
