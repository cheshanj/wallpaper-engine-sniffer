# CLAUDE.md

## Project

Wallpaper Engine Sniffer is a Windows PowerShell security-audit helper. Keep it portable and easy for non-developers to run.

## Conventions

- Keep paths dynamic. Do not hardcode a user's profile path, mapped drive, or machine-specific install path.
- Generated reports belong under `scripts/reports` and must remain ignored by Git.
- Keep the root `WallpaperEngineRiskMonitor.ps1` as a convenience launcher.
- Keep the main monitor implementation in `scripts/WallpaperEngineRiskMonitor.ps1`.
- Keep Sysmon config under `config/`.
- Prefer PowerShell 5.1-compatible syntax unless there is a strong reason not to.
- Use concise comments only for non-obvious monitoring or parsing behavior.

## Validation

Before committing monitor changes, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1 -Once -NoPopup
```

Confirm startup reports the expected report folder and, when installed, Sysmon enrichment.
