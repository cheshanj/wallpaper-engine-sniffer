# Copyright (c) 2026 Cheshan Jayathilaka.
# Licensed under the MIT License. See LICENSE and NOTICE.md in the repository root.

# Convenience launcher for the main monitor under scripts/.
[CmdletBinding()]
param(
    [int]$PollSeconds = 5,
    [string]$LogRoot = "",
    [switch]$NoPopup,
    [switch]$IncludePrivateNetworkAlerts,
    [switch]$Once
)

$scriptPath = Join-Path $PSScriptRoot "scripts\WallpaperEngineRiskMonitor.ps1"
$forward = @{
    PollSeconds = $PollSeconds
}
if ($PSBoundParameters.ContainsKey("LogRoot")) { $forward.LogRoot = $LogRoot }
if ($NoPopup) { $forward.NoPopup = $true }
if ($IncludePrivateNetworkAlerts) { $forward.IncludePrivateNetworkAlerts = $true }
if ($Once) { $forward.Once = $true }

& $scriptPath @forward

