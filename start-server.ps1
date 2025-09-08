# PowerShell script to set up and run the MTG Tournament Swiss App.
# Installs dependencies, initializes the database, and starts the FastAPI/NiceGUI server.
# Load settings from YAML config
$configPath = Join-Path $PSScriptRoot "config.yaml"
if(!(Test-Path $configPath)){
    Write-Error "Missing config.yaml"
    exit 1
}

function ConvertTo-Hashtable {
    param([Parameter(ValueFromPipeline = $true)][object]$InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $hash = @{}
        foreach ($key in $InputObject.Keys) {
            $hash[$key] = ConvertTo-Hashtable $InputObject[$key]
        }
        return $hash
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject.GetType().Name -ne "String") {
        return @($InputObject | ForEach-Object { ConvertTo-Hashtable $_ })
    }
    return $InputObject
}

try {
    $pythonScript = @"
import sys, json
try:
    import yaml
except ModuleNotFoundError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet', 'PyYAML'])
    import yaml
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)
print(json.dumps(data))
"@
    $cfgJson = & python -c $pythonScript $configPath
    $cfg = $cfgJson | ConvertFrom-Json | ConvertTo-Hashtable
} catch {
    Write-Error "Failed to parse config.yaml"
    exit 1
}

$DefaultDb = "mtg_tournament.db"
$DefaultLogDb = "mtg_tournament_logs.db"

$DatabasePath = $cfg.db_file
$LogDatabasePath = $cfg.log_db_file
$PasswordSeed = $cfg.password_seed
$FlaskIP = $cfg.flask_ip
$FlaskPort = $cfg.flask_port

if([string]::IsNullOrEmpty($DatabasePath)){ $DatabasePath = $DefaultDb }
if([string]::IsNullOrEmpty($LogDatabasePath)){ $LogDatabasePath = $DefaultLogDb }
if([string]::IsNullOrEmpty($PasswordSeed)){ $PasswordSeed = "dev-password-seed-change-me" }
if([string]::IsNullOrEmpty($FlaskIP)){ $FlaskIP = "127.0.0.1" }
if([string]::IsNullOrEmpty($FlaskPort)){ $FlaskPort = 5000 }

#check if server is already running and stop it if necessary
<#
    $serverpid = try{
        Get-NetTCPConnection -LocalPort $FlaskPort -State Listen -ErrorAction Stop | Select-Object -ExpandProperty OwningProcess
    }catch{
        $null
    }

    if($null -ne $serverpid){
        Get-Process -Id $serverpid | Stop-Process -Force -Confirm:$false
    }
#>

Stop-Process -Name "uvicorn" -Force -ErrorAction SilentlyContinue | Out-Null

# Ensure the script runs from its own directory so relative paths work
Set-Location -Path $PSScriptRoot

# Configure password seed for AES encryption
$env:PASSWORD_SEED = $PasswordSeed

$timestamp = Get-Date -Format "yyyyMMddHHmmss"

if($DatabasePath -eq $DefaultDb){
    $DatabasePath = "mtg_tournament_$timestamp.db"
    $LogDatabasePath = "mtg_tournament_logs_$timestamp.db"
} elseif($LogDatabasePath -eq $DefaultLogDb) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($DatabasePath)
    $dir = [System.IO.Path]::GetDirectoryName($DatabasePath)
    if([string]::IsNullOrEmpty($dir)){ $dir = "." }
    $LogDatabasePath = Join-Path $dir "$base`_logs.db"
}

$env:MTG_DB_PATH = $DatabasePath
$env:MTG_LOG_DB_PATH = $LogDatabasePath

Write-Host "Installing dependencies..."
python -m pip install -r "$PSScriptRoot/requirements.txt"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install dependencies"
    exit $LASTEXITCODE
}

Write-Host "Initializing database..."
python -c "from app.app import create_app, db; create_app(); db.create_all()"

Write-Host "Starting FastAPI server..."
Start-Process -NoNewWindow -FilePath "python" -ArgumentList "-m", "uvicorn", "app.app:app", "--reload", "--host=$FlaskIP", "--port=$FlaskPort"

Start-Sleep -Seconds 3

# open the browser to the app
Start-Process "http://$($FlaskIP):$($FlaskPort)/"
