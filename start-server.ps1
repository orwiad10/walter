# PowerShell script to set up and run the MTG Tournament Swiss App.
# Installs dependencies, initializes the database, creates an admin user,
# and starts the Flask development server.
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
$FlaskSecret = $cfg.flask_secret
$PasswordSeed = $cfg.password_seed
$FlaskIP = $cfg.flask_ip
$FlaskPort = $cfg.flask_port
$newadmin = New-Object System.Management.Automation.PSCredential($cfg.admin_email, (ConvertTo-SecureString $cfg.admin_pass -AsPlainText -Force))

if([string]::IsNullOrEmpty($DatabasePath)){ $DatabasePath = $DefaultDb }
if([string]::IsNullOrEmpty($LogDatabasePath)){ $LogDatabasePath = $DefaultLogDb }
if([string]::IsNullOrEmpty($FlaskSecret)){ $FlaskSecret = "dev-secret-change-me" }
if([string]::IsNullOrEmpty($PasswordSeed)){ $PasswordSeed = "dev-password-seed-change-me" }
if([string]::IsNullOrEmpty($FlaskIP)){ $FlaskIP = "127.0.0.1" }
if([string]::IsNullOrEmpty($FlaskPort)){ $FlaskPort = 5000 }

#check if Flask is already running and stop it if necessary
$flaskpid = try{
    Get-NetTCPConnection -LocalPort $FlaskPort -State Listen -ErrorAction Stop | Select-Object -ExpandProperty OwningProcess
}catch{
    $null
}

if($flaskpid){
    Get-Process -Id $flaskpid | Stop-Process -Force -Confirm:$false
}

Stop-Process -Name "flask" -Force -ErrorAction SilentlyContinue | Out-Null

# Ensure the script runs from its own directory so relative paths work
Set-Location -Path $PSScriptRoot

# Configure password seed for AES encryption
$env:PASSWORD_SEED = $PasswordSeed

# Configure Flask secret
$env:FLASK_SECRET = $FlaskSecret

$env:FLASK_RUN_HOST = $FlaskIP
$env:FLASK_RUN_PORT = $FlaskPort

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
python -m pip install -r "$PSScriptRoot/requirements.txt" | Out-Null

Write-Host "Setting Flask environment..."
$env:FLASK_APP = "app.app:app"

Write-Host "Initializing database..."
python -m flask --app app.app db-init

Write-Host "Creating default admin user..."
python -m flask --app app.app create-admin --email $newadmin.UserName --password $newadmin.GetNetworkCredential().Password

Write-Host "Starting Flask development server..."
#python -m flask --app app.app run --debug

Start-Process -NoNewWindow -FilePath "flask" -ArgumentList "--app app.app run --debug --host=$FlaskIP --port=$FlaskPort"

Start-Sleep -Seconds 3

#open the browser to the Flask app
Start-Process "http://$($FlaskIP):$($FlaskPort)/"
