# PowerShell script to restart the MTG Tournament Swiss App.
# Stops the running server, then starts it again so config.yaml is reloaded.
$ErrorActionPreference = "Stop"

$configPath = Join-Path $PSScriptRoot "config.yaml"
$stopScript = Join-Path $PSScriptRoot "stop-server.ps1"
$startScript = Join-Path $PSScriptRoot "start-server.ps1"

if (!(Test-Path $configPath)) {
    Write-Error "Missing config.yaml"
    exit 1
}

if (!(Test-Path $stopScript)) {
    Write-Error "Missing stop-server.ps1"
    exit 1
}

if (!(Test-Path $startScript)) {
    Write-Error "Missing start-server.ps1"
    exit 1
}

Write-Host "Restarting server to reload $configPath..."
& $stopScript
& $startScript
Write-Host "Server restart complete; config.yaml has been reloaded."
