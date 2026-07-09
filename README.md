# Wallpaper Engine Sniffer

Wallpaper Engine Sniffer is a Windows PowerShell monitor for reviewing potentially risky Wallpaper Engine behavior. It records Wallpaper Engine process activity, outbound network connections, and, when Sysmon is enabled, related DNS and file-create events.

The tool is designed for cautious local auditing. It does not block traffic or modify Wallpaper Engine. It writes human-readable summaries and JSON Lines logs so you can inspect what happened later.

## Features

- Detects Wallpaper Engine processes and child processes.
- Logs outbound TCP connections from Wallpaper Engine processes.
- Alerts on public outbound connections, unusual ports, and sensitive service ports.
- Alerts when Wallpaper Engine or a child process launches risky command-line tools such as PowerShell, cmd, rundll32, curl, or wget.
- Uses Sysmon, when installed, to enrich reports with process, network, DNS, and file-create telemetry.
- Writes reports dynamically beside the monitor script under `scripts/reports`.

## Repository Layout

```text
.
├── WallpaperEngineRiskMonitor.ps1      # Root launcher for convenience
├── scripts/
│   ├── WallpaperEngineRiskMonitor.ps1  # Main monitor
│   └── reports/                        # Generated logs; ignored by Git
├── config/
│   └── sysmon-wallpaperengine-config.xml
├── docs/
│   ├── getting-started.md
│   ├── sysmon-setup.md
│   ├── reports.md
│   └── security-notes.md
├── NOTICE.md
├── CONTRIBUTING.md
├── AGENTS.md
├── CLAUDE.md
└── LICENSE
```

## Quick Start

Open PowerShell in the repository root and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1
```

Or run the main script directly:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\WallpaperEngineRiskMonitor.ps1
```

Stop the monitor with `Ctrl+C`.

## Useful Options

```powershell
# Run without popup alerts; logs only
powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1 -NoPopup

# Run one check and exit
powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1 -Once

# Poll every 2 seconds instead of every 5 seconds
powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1 -PollSeconds 2

# Write reports somewhere else
powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1 -LogRoot "C:\Temp\wallpaper-reports"
```

## Reports

By default, generated reports are written to:

```text
scripts\reports
```

The report folder is resolved dynamically from the location of the main script, so the project can be moved without changing paths.

See [docs/reports.md](docs/reports.md) for file details.

## Sysmon

Sysmon is optional but recommended. Without Sysmon, the monitor still records process and network activity. With Sysmon, it can also correlate Wallpaper Engine with DNS and file-create events.

See [docs/sysmon-setup.md](docs/sysmon-setup.md) for setup steps.

## Security Notes

This project is an audit helper, not a replacement for EDR, firewall controls, or malware analysis. Treat alerts as leads to investigate, not automatic proof of malicious behavior.

See [docs/security-notes.md](docs/security-notes.md) for limitations and safe handling guidance.

## License and Copyright

Copyright (c) 2026 Cheshan Jayathilaka.

This project is distributed under the MIT License. If you copy, modify, redistribute, or include substantial portions of this project elsewhere, keep the copyright and license notices intact.

See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
