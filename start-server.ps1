# PowerShell script to set up and run the MTG Tournament Swiss App.
# Installs dependencies, initializes the database, creates an admin user,
# and starts the Flask development server.
# Load settings from YAML config
$configPath = Join-Path $PSScriptRoot "config.yaml"
if(!(Test-Path $configPath)){
    Write-Error "Missing config.yaml"
    exit 1
}

try{
    $cfg = Get-Content $configPath | ConvertFrom-Yaml
}catch{
    Write-Error "Failed to parse config.yaml"
    exit 1
}

$DatabasePath = $cfg.db_file
$FlaskSecret = $cfg.secret
$PasswordSeed = New-Object System.Management.Automation.PSCredential("dev-password-seed-change-me", (ConvertTo-SecureString "dev-password-seed-change-me" -AsPlainText -Force))
$newadmin = New-Object System.Management.Automation.PSCredential($cfg.admin_email, (ConvertTo-SecureString $cfg.admin_pass -AsPlainText -Force))

#check if Flask is already running and stop it if necessary
$flaskpid = try{
    Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction Stop | Select-Object -ExpandProperty OwningProcess
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
$env:PASSWORD_SEED = $PasswordSeed.UserName

# Configure Flask secret
$env:FLASK_SECRET = $FlaskSecret

# Determine database path
if([string]::IsNullOrEmpty($DatabasePath)){
    $timestamp = Get-Date -Format "yyyyMMddHHmmss"
    $DatabasePath = "mtg_tournament_$timestamp.db"
}

$env:MTG_DB_PATH = $DatabasePath

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

Start-Process -NoNewWindow -FilePath "flask" -ArgumentList "--app app.app run --debug"

#open the browser to the Flask app
Start-Process "http://127.0.0.1:5000/"
