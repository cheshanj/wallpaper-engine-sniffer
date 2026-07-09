# Reports

Reports are written to `scripts/reports` by default. The folder is created automatically.

## Files

- `latest-summary.txt`: current state from the most recent polling loop.
- `wallpaper-engine-events.jsonl`: process, network, Sysmon, DNS, and file events captured by the monitor.
- `wallpaper-engine-alerts.jsonl`: only events the monitor classified as risky or unusual.

## JSON Lines Format

The `.jsonl` files contain one JSON object per line. This format is easy to tail, archive, and import into other tools.

Example:

```powershell
Get-Content .\scripts\reports\wallpaper-engine-events.jsonl -Tail 20
Get-Content .\scripts\reports\wallpaper-engine-alerts.jsonl -Tail 20
```

## Git Tracking

Generated report files are ignored by Git. The repository keeps only `scripts/reports/.gitkeep` so the folder exists after clone.

## Rotation

The script does not rotate logs automatically yet. If the reports folder grows too large, stop the monitor, archive or delete old `.jsonl` files, and start it again.
