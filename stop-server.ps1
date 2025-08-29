# PowerShell script to stop the MTG Tournament Swiss App.
# Terminates the Flask server process and any python process holding
# an open handle to the SQLite database.
# Requires the Sysinternals 'handle' utility to check open file handles.

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

# Kill any python process with handle on the database file
$pyProcs = Get-Process python -ErrorAction SilentlyContinue
foreach($p in $pyProcs){
    $handles = & handle.exe -p $p.Id $dbPath 2>$null
    if($handles){
        Write-Host "Terminating Python process $($p.Id) using $dbPath"
        $p | Stop-Process -Force
    }
}

Start-Sleep -Seconds 1
$remaining = & handle.exe $dbPath 2>$null
if($remaining){
    Write-Warning "Database $dbPath is still in use."
} else {
    Write-Host "Database $dbPath is quiesced."
}
