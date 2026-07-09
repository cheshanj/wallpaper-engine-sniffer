# Sysmon Setup

Sysmon is optional but recommended. It gives the monitor stronger evidence for DNS and file-create activity tied to Wallpaper Engine processes.

## Install Sysmon

Install Sysmon only from Microsoft Sysinternals or a trusted package manager source.

Using WinGet:

```powershell
winget install --id Microsoft.Sysinternals.Sysmon --exact --accept-package-agreements --accept-source-agreements
```

## Apply This Project's Config

Open PowerShell as Administrator from the repository root and run:

```powershell
sysmon64.exe -accepteula -i .\config\sysmon-wallpaperengine-config.xml
```

If Sysmon is already installed and you only need to update its config:

```powershell
sysmon64.exe -c .\config\sysmon-wallpaperengine-config.xml
```

## Verify Sysmon

```powershell
Get-Service Sysmon64
Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational
```

Then restart the monitor. Startup should report:

```text
Sysmon enrichment enabled: Microsoft-Windows-Sysmon/Operational
```

## Notes

The included config focuses on Wallpaper Engine paths and sensitive file-create targets. It is intentionally narrow so it does not turn Sysmon into a broad noisy system monitor.
