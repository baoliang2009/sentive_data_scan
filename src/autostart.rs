use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[cfg_attr(not(all(unix, not(target_os = "macos"))), allow(dead_code))]
const SERVICE_NAME: &str = "data-sentinel.service";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const LAUNCH_LABEL: &str = "com.datasentinel.scanner";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WINDOWS_TASK: &str = "DataSentinel";

pub fn install(config_path: &Path) -> Result<()> {
    imp::install(config_path)
}

pub fn uninstall() -> Result<()> {
    imp::uninstall()
}

pub fn status() -> Result<String> {
    imp::status()
}

fn exe_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("无法获取当前可执行文件路径")?;
    #[cfg(target_os = "windows")]
    {
        // Avoid `\\?\` extended-length paths in Task Scheduler / registry values.
        Ok(exe)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(exe.canonicalize().unwrap_or(exe))
    }
}

fn config_absolute(config_path: &Path) -> Result<PathBuf> {
    let absolute = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        std::env::current_dir()?.join(config_path)
    };
    #[cfg(target_os = "windows")]
    {
        Ok(absolute)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(absolute.canonicalize().unwrap_or(absolute))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use anyhow::{Context, Result};

    use super::{config_absolute, exe_path, SERVICE_NAME};
    use crate::config::ensure_private_dir;

    pub fn install(config_path: &Path) -> Result<()> {
        let exe = exe_path()?;
        let config = config_absolute(config_path)?;
        let unit_dir = dirs::config_dir()
            .context("无法定位用户配置目录")?
            .join("systemd/user");
        ensure_private_dir(&unit_dir)?;
        let unit_path = unit_dir.join(SERVICE_NAME);
        let unit = format!(
            "[Unit]\n\
             Description=DataSentinel sensitive data scanner\n\
             After=graphical-session.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={} daemon --config {}\n\
             Restart=on-failure\n\
             RestartSec=10\n\
             StandardOutput=journal\n\
             StandardError=journal\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            quote_systemd(&exe.to_string_lossy()),
            quote_systemd(&config.to_string_lossy())
        );
        fs::write(&unit_path, &unit)
            .with_context(|| format!("无法写入 systemd 服务 {}", unit_path.display()))?;

        let reload = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let enable = Command::new("systemctl")
            .args(["--user", "enable", "--now", SERVICE_NAME])
            .status();
        if matches!(reload, Ok(status) if status.success())
            && matches!(enable, Ok(status) if status.success())
        {
            println!("已安装 systemd 用户服务: {}", unit_path.display());
            println!("开机登录后将自动启动 DataSentinel。");
            return Ok(());
        }

        // Fallback for minimal Kylin/Linux images without a usable systemd user manager.
        let autostart_dir = dirs::config_dir()
            .context("无法定位用户配置目录")?
            .join("autostart");
        ensure_private_dir(&autostart_dir)?;
        let desktop_path = autostart_dir.join("data-sentinel.desktop");
        let desktop = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=DataSentinel\n\
             Comment=本地敏感数据扫描与落盘监控\n\
             Exec={} daemon --config {}\n\
             Terminal=false\n\
             X-GNOME-Autostart-enabled=true\n\
             NoDisplay=false\n",
            quote_desktop(&exe.to_string_lossy()),
            quote_desktop(&config.to_string_lossy())
        );
        fs::write(&desktop_path, desktop)
            .with_context(|| format!("无法写入 XDG 自启文件 {}", desktop_path.display()))?;
        println!(
            "systemd 不可用，已写入 XDG 自启文件: {}",
            desktop_path.display()
        );
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let unit_path = dirs::config_dir()
            .context("无法定位用户配置目录")?
            .join("systemd/user")
            .join(SERVICE_NAME);
        if unit_path.exists() {
            let _ = Command::new("systemctl")
                .args(["--user", "disable", "--now", SERVICE_NAME])
                .status();
            let _ = fs::remove_file(&unit_path);
            let _ = Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
            println!("已移除 systemd 用户服务。");
        }
        let desktop_path = dirs::config_dir()
            .context("无法定位用户配置目录")?
            .join("autostart/data-sentinel.desktop");
        if desktop_path.exists() {
            let _ = fs::remove_file(&desktop_path);
            println!("已移除 XDG 自启文件。");
        }
        Ok(())
    }

    pub fn status() -> Result<String> {
        let unit_path = dirs::config_dir()
            .context("无法定位用户配置目录")?
            .join("systemd/user")
            .join(SERVICE_NAME);
        let desktop_path = dirs::config_dir()
            .context("无法定位用户配置目录")?
            .join("autostart/data-sentinel.desktop");
        let mut lines = Vec::new();
        lines.push(format!(
            "systemd 用户服务: {} ({})",
            if unit_path.exists() {
                "已安装"
            } else {
                "未安装"
            },
            unit_path.display()
        ));
        let enabled = Command::new("systemctl")
            .args(["--user", "is-enabled", SERVICE_NAME])
            .output();
        if let Ok(output) = enabled {
            lines.push(format!(
                "systemctl is-enabled: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            ));
        }
        lines.push(format!(
            "XDG 自启文件: {} ({})",
            if desktop_path.exists() {
                "已安装"
            } else {
                "未安装"
            },
            desktop_path.display()
        ));
        Ok(lines.join("\n"))
    }

    fn quote_systemd(value: &str) -> String {
        if value
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\\' | '$' | '`'))
        {
            format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
        } else {
            value.to_string()
        }
    }

    fn quote_desktop(value: &str) -> String {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('`', "\\`")
            .replace('$', "\\$");
        format!("\"{escaped}\"")
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use anyhow::{bail, Context, Result};

    use super::{config_absolute, exe_path, LAUNCH_LABEL};
    use crate::config::ensure_private_dir;

    pub fn install(config_path: &Path) -> Result<()> {
        let exe = exe_path()?;
        let config = config_absolute(config_path)?;
        let home = dirs::home_dir().context("无法定位用户主目录")?;
        let launch_dir = home.join("Library/LaunchAgents");
        let log_dir = home.join("Library/Logs/DataSentinel");
        ensure_private_dir(&launch_dir)?;
        ensure_private_dir(&log_dir)?;
        let plist_path = launch_dir.join(format!("{LAUNCH_LABEL}.plist"));

        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>daemon</string>
    <string>--config</string>
    <string>{config}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>{stdout}</string>
  <key>StandardErrorPath</key>
  <string>{stderr}</string>
</dict>
</plist>
"#,
            label = LAUNCH_LABEL,
            exe = xml_escape(&exe.to_string_lossy()),
            config = xml_escape(&config.to_string_lossy()),
            stdout = xml_escape(&log_dir.join("stdout.log").to_string_lossy()),
            stderr = xml_escape(&log_dir.join("stderr.log").to_string_lossy()),
        );
        fs::write(&plist_path, plist)
            .with_context(|| format!("无法写入 LaunchAgent {}", plist_path.display()))?;

        let uid = current_uid()?;
        // Idempotent reinstall: unload an old instance first if present.
        let _ = Command::new("launchctl")
            .arg("bootout")
            .arg(format!("gui/{uid}/{LAUNCH_LABEL}"))
            .status();
        let bootstrap = Command::new("launchctl")
            .arg("bootstrap")
            .arg(format!("gui/{uid}"))
            .arg(&plist_path)
            .status();
        if matches!(bootstrap, Ok(status) if status.success()) {
            println!("已安装 LaunchAgent: {}", plist_path.display());
            return Ok(());
        }

        let load = Command::new("launchctl")
            .arg("load")
            .arg("-w")
            .arg(&plist_path)
            .status();
        match load {
            Ok(status) if status.success() => {
                println!("已安装 LaunchAgent: {}", plist_path.display());
                Ok(())
            }
            _ => bail!("launchctl 加载失败，请检查 {}", plist_path.display()),
        }
    }

    pub fn uninstall() -> Result<()> {
        let home = dirs::home_dir().context("无法定位用户主目录")?;
        let plist_path = home
            .join("Library/LaunchAgents")
            .join(format!("{LAUNCH_LABEL}.plist"));
        if !plist_path.exists() {
            println!("未找到 LaunchAgent，无需卸载。");
            return Ok(());
        }
        let uid = current_uid()?;
        let _ = Command::new("launchctl")
            .arg("bootout")
            .arg(format!("gui/{uid}/{LAUNCH_LABEL}"))
            .status();
        let _ = Command::new("launchctl")
            .arg("unload")
            .arg(&plist_path)
            .status();
        fs::remove_file(&plist_path)
            .with_context(|| format!("无法删除 {}", plist_path.display()))?;
        println!("已移除 LaunchAgent。");
        Ok(())
    }

    pub fn status() -> Result<String> {
        let home = dirs::home_dir().context("无法定位用户主目录")?;
        let plist_path = home
            .join("Library/LaunchAgents")
            .join(format!("{LAUNCH_LABEL}.plist"));
        let uid = current_uid()?;
        let output = Command::new("launchctl")
            .arg("print")
            .arg(format!("gui/{uid}/{LAUNCH_LABEL}"))
            .output();
        let state = match output {
            Ok(output) if output.status.success() => "已加载",
            _ => "未加载",
        };
        Ok(format!(
            "LaunchAgent: {} ({})\n运行状态: {}",
            if plist_path.exists() {
                "已安装"
            } else {
                "未安装"
            },
            plist_path.display(),
            state
        ))
    }

    fn current_uid() -> Result<String> {
        let output = Command::new("id")
            .arg("-u")
            .output()
            .context("无法执行 id -u")?;
        if !output.status.success() {
            bail!("id -u 返回失败");
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn xml_escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
}

#[cfg(target_os = "windows")]
mod imp {
    use std::path::Path;
    use std::process::Command;

    use anyhow::{bail, Result};

    use super::{config_absolute, exe_path, WINDOWS_TASK};

    pub fn install(config_path: &Path) -> Result<()> {
        let exe = exe_path()?;
        let config = config_absolute(config_path)?;
        let command = format!(
            "\"{}\" daemon --config \"{}\"",
            exe.display(),
            config.display()
        );

        let status = Command::new("schtasks")
            .args([
                "/Create",
                "/TN",
                WINDOWS_TASK,
                "/SC",
                "ONLOGON",
                "/DELAY",
                "0000:30",
                "/RL",
                "LIMITED",
                "/TR",
            ])
            .arg(command.as_str())
            .arg("/F")
            .status();
        if matches!(status, Ok(status) if status.success()) {
            println!("已创建登录启动任务计划: {WINDOWS_TASK}");
            return Ok(());
        }

        let run_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        let status = Command::new("reg")
            .args(["add", run_key, "/v", WINDOWS_TASK, "/t", "REG_SZ", "/d"])
            .arg(command.as_str())
            .arg("/f")
            .status();
        if matches!(status, Ok(status) if status.success()) {
            println!("任务计划创建失败，已写入注册表自启项: {run_key}");
            return Ok(());
        }
        bail!("无法安装 Windows 自启项（任务计划与注册表均失败）");
    }

    pub fn uninstall() -> Result<()> {
        let _ = Command::new("schtasks")
            .args(["/Delete", "/TN", WINDOWS_TASK, "/F"])
            .status();
        let run_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        let _ = Command::new("reg")
            .args(["delete", run_key, "/v", WINDOWS_TASK, "/f"])
            .status();
        println!("已移除 Windows 自启项。");
        Ok(())
    }

    pub fn status() -> Result<String> {
        let task = Command::new("schtasks")
            .args(["/Query", "/TN", WINDOWS_TASK])
            .output();
        let task_state = match task {
            Ok(output) if output.status.success() => "已安装",
            _ => "未安装",
        };
        let run_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        let registry = Command::new("reg")
            .args(["query", run_key, "/v", WINDOWS_TASK])
            .output();
        let registry_state = match registry {
            Ok(output) if output.status.success() => "已安装",
            _ => "未安装",
        };
        Ok(format!(
            "任务计划: {task_state}\n注册表 Run 项: {registry_state}"
        ))
    }
}
