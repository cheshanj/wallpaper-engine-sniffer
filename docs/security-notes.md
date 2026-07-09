# Security Notes

## What This Tool Can Tell You

Wallpaper Engine Sniffer can show:

- Which Wallpaper Engine processes are running.
- Which outbound TCP connections those processes open.
- Whether those connections use public IPs or unusual ports.
- Whether child processes use risky command-line tools.
- With Sysmon, related DNS and file-create activity.

## What This Tool Cannot Prove

An alert does not automatically prove data theft or malware. Some wallpapers use web content, embedded browsers, APIs, or Steam services. Treat alerts as leads for review.

Windows and PowerShell do not expose every per-process file read through simple polling. Exact file-read auditing requires heavier Windows auditing or EDR tooling. This project uses Sysmon file-create/file-modify events because they are practical and lower-noise.

## Safe Investigation Tips

- Keep the raw `.jsonl` logs if you need evidence later.
- Compare suspicious remote IPs or DNS names with the wallpaper source and Steam Workshop item.
- Disable or unsubscribe from a wallpaper if it repeatedly triggers unexpected network or command alerts.
- Do not run unknown wallpapers with elevated privileges.
- Prefer official Sysinternals builds for Sysmon.

## Privacy

Reports may include local usernames, process command lines, file paths, IP addresses, and DNS names. Do not publish raw reports without reviewing them first.
