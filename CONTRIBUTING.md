# Contributing

Thanks for helping improve Wallpaper Engine Sniffer.

## Copyright and License

By contributing to this repository, you agree that your contribution may be distributed under the repository's MIT License.

Do not remove copyright, license, or notice text from existing files. New source files should include a short copyright header when practical.

## Development Notes

- Keep paths dynamic and portable.
- Do not commit generated reports from `scripts/reports`.
- Keep PowerShell 5.1 compatibility unless there is a clear reason not to.
- Document user-facing behavior changes in `README.md` or `docs/`.

## Validation

Before opening a pull request or pushing a change, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\WallpaperEngineRiskMonitor.ps1 -Once -NoPopup
```
