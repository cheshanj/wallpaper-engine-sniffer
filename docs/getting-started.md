# Getting Started

## Requirements

- Windows 10 or Windows 11.
- Windows PowerShell 5.1 or PowerShell 7+.
- Wallpaper Engine installed through Steam.
- Administrator rights only if you want to install or configure Sysmon.

## Run the Monitor

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1
```

From the `scripts` folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1
```

The monitor keeps running until you press `Ctrl+C`.

## First Verification

Run a one-shot check:

```powershell
powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1 -Once -NoPopup
```

Expected output includes the report folder and whether Sysmon enrichment is enabled.

## Where Reports Go

By default, reports are written under:

```text
scripts\reports
```

Use `-LogRoot` to override this for a single run.
