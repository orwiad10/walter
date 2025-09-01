# PowerShell script to stop the MTG Tournament Swiss App.
# Terminates the Flask server process and any python process holding
# an open handle to the SQLite database using native PowerShell.

# Load settings from YAML config
$configPath = Join-Path $PSScriptRoot 'config.yaml'
if(!(Test-Path $configPath)){
    Write-Error 'Missing config.yaml'
    exit 1
}

try {
    $pythonScript = @"
import sys, json
import yaml
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)
print(json.dumps(data))
"@
    $cfgJson = & python -c $pythonScript $configPath
    $cfg = $cfgJson | ConvertFrom-Json
} catch {
    Write-Error 'Failed to parse config.yaml'
    exit 1
}

$flaskPort = $cfg.flask_port
$dbPath = Join-Path $PSScriptRoot $cfg.db_file

Write-Host "Stopping server on port $flaskPort"

# Kill flask process listening on the configured port
$flaskConn = Get-NetTCPConnection -LocalPort $flaskPort -ErrorAction SilentlyContinue | Select-Object -First 1
if($flaskConn){
    $proc = Get-Process -Id $flaskConn.OwningProcess -ErrorAction SilentlyContinue
    if($proc){
        Write-Host "Terminating Flask process $($proc.Id)"
        $proc | Stop-Process -Force
    }
}

# Determine if a file is locked by attempting to open it with exclusive access
function Test-FileLock {
    param([string]$Path)
    try {
        $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $fs.Close()
        return $false
    } catch [System.IO.IOException] {
        return $true
    }
}

# Kill any python process with a handle on the database file
$pyProcs = Get-Process python -ErrorAction SilentlyContinue
foreach($p in $pyProcs){
    if(Test-FileLock $dbPath){
        Write-Host "Terminating Python process $($p.Id) using $dbPath"
        $p | Stop-Process -Force
    } else {
        break
    }
}

Start-Sleep -Seconds 1
if(Test-FileLock $dbPath){
    Write-Warning "Database $dbPath is still in use."
} else {
    Write-Host "Database $dbPath is quiesced."
}
