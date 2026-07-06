# PowerShell script to set up and run the MTG Tournament Swiss App.
# Installs dependencies, initializes the database, creates an admin user,
# and starts the app with Waitress.
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
$MailgunApiKey = $cfg.mailgun_api_key
$MailgunDomain = $cfg.mailgun_domain
$MailgunFromEmail = $cfg.mailgun_from_email
$RegistrationPinTtlMinutes = $cfg.registration_pin_ttl_minutes
$AccountCreationInviteOnly = $cfg.account_creation_invite_only
$AccountLockoutAttempts = $cfg.account_lockout_attempts
$IpBlacklistAttempts = $cfg.ip_blacklist_attempts
$PasswordResetTtlMinutes = $cfg.password_reset_ttl_minutes
$BotInstallEnabled = $cfg.bot_install_enabled
$BotInstallPath = $cfg.bot_install_path
$BotInstallEditable = $cfg.bot_install_editable
$BotInstallExtras = $cfg.bot_install_extras
$BotRuntimeEnabled = $cfg.bot_runtime_enabled
$BotRuntimeModule = $cfg.bot_runtime_module
$BotRuntimeScript = $cfg.bot_runtime_script
$BotRuntimeArgs = $cfg.bot_runtime_args
$BotRuntimeLogFile = $cfg.bot_runtime_log_file
$BotRuntimeErrorLogFile = $cfg.bot_runtime_error_log_file
$BotApiBaseUrl = $cfg.bot_api_base_url
$BotApiKey = $cfg.bot_api_key
$BotPollTournamentId = $cfg.bot_poll_tournament_id
$BotPollIntervalSeconds = $cfg.bot_poll_interval_seconds
$BotToken = $cfg.bot_token
$BotAppId = $cfg.bot_appid
$BotPubKey = $cfg.bot_pubkey
$BotClientId = $cfg.bot_client_id
$BotSecretKey = $cfg.bot_secret_key
$BotPermissionsInt = $cfg.bot_permissions_int
$BotChannelId = $cfg.bot_channel_id
$BotAnnounceReady = $cfg.bot_announce_ready
$BotSyncGuildCommands = $cfg.bot_sync_guild_commands
$BotClearGuildCommands = $cfg.bot_clear_guild_commands
$newadmin = New-Object System.Management.Automation.PSCredential($cfg.admin_email, (ConvertTo-SecureString $cfg.admin_pass -AsPlainText -Force))

######enable testing###########
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
###############################

if([string]::IsNullOrEmpty($DatabasePath)){ $DatabasePath = $DefaultDb }
if([string]::IsNullOrEmpty($LogDatabasePath)){ $LogDatabasePath = $DefaultLogDb }
if([string]::IsNullOrEmpty($FlaskSecret)){ $FlaskSecret = "dev-secret-change-me" }
if([string]::IsNullOrEmpty($PasswordSeed)){ $PasswordSeed = "dev-password-seed-change-me" }
if([string]::IsNullOrEmpty($FlaskIP)){ $FlaskIP = "0.0.0.0" }
if([string]::IsNullOrEmpty($FlaskPort)){ $FlaskPort = 5000 }
if([string]::IsNullOrEmpty($RegistrationPinTtlMinutes)){ $RegistrationPinTtlMinutes = 15 }
if($null -eq $AccountCreationInviteOnly){ $AccountCreationInviteOnly = $false }
if([string]::IsNullOrEmpty($AccountLockoutAttempts)){ $AccountLockoutAttempts = 3 }
if([string]::IsNullOrEmpty($IpBlacklistAttempts)){ $IpBlacklistAttempts = 10 }
if([string]::IsNullOrEmpty($PasswordResetTtlMinutes)){ $PasswordResetTtlMinutes = 60 }
if($null -eq $BotInstallEnabled){ $BotInstallEnabled = $false }
if([string]::IsNullOrEmpty($BotInstallPath)){ $BotInstallPath = "walter-bot" }
if($null -eq $BotInstallEditable){ $BotInstallEditable = $true }
if($null -eq $BotRuntimeEnabled){ $BotRuntimeEnabled = "auto" }
if([string]::IsNullOrEmpty($BotRuntimeLogFile)){ $BotRuntimeLogFile = "walter-bot.log" }
if([string]::IsNullOrEmpty($BotRuntimeErrorLogFile)){ $BotRuntimeErrorLogFile = "walter-bot.err.log" }
if([string]::IsNullOrEmpty($BotApiBaseUrl)){ $BotApiBaseUrl = "http://127.0.0.1:$FlaskPort" }
if([string]::IsNullOrEmpty($BotPollIntervalSeconds)){ $BotPollIntervalSeconds = 30 }
if($null -eq $BotAnnounceReady){ $BotAnnounceReady = $false }
if($null -eq $BotSyncGuildCommands){ $BotSyncGuildCommands = $false }
if($null -eq $BotClearGuildCommands){ $BotClearGuildCommands = $true }

#check if Flask/Waitress is already running and stop it if necessary
$flaskpid = try{
    Get-NetTCPConnection -LocalPort $FlaskPort -State Listen -ErrorAction Stop | Select-Object -ExpandProperty OwningProcess
}catch{
    $null
}

if($flaskpid){
    Get-Process -Id $flaskpid | Stop-Process -Force -Confirm:$false
}

Stop-Process -Name "flask" -Force -ErrorAction SilentlyContinue | Out-Null
Stop-Process -Name "waitress-serve" -Force -ErrorAction SilentlyContinue | Out-Null

# Ensure the script runs from its own directory so relative paths work
Set-Location -Path $PSScriptRoot

# Configure password seed for AES encryption
$env:PASSWORD_SEED = $PasswordSeed

# Configure Flask secret
$env:FLASK_SECRET = $FlaskSecret

$env:FLASK_RUN_HOST = $FlaskIP
$env:FLASK_RUN_PORT = $FlaskPort
$env:MAILGUN_API_KEY = $MailgunApiKey
$env:MAILGUN_DOMAIN = $MailgunDomain
$env:MAILGUN_FROM_EMAIL = $MailgunFromEmail
$env:REGISTRATION_PIN_TTL_MINUTES = $RegistrationPinTtlMinutes
$env:ACCOUNT_CREATION_INVITE_ONLY = $AccountCreationInviteOnly
$env:ACCOUNT_LOCKOUT_ATTEMPTS = $AccountLockoutAttempts
$env:IP_BLACKLIST_ATTEMPTS = $IpBlacklistAttempts
$env:PASSWORD_RESET_TTL_MINUTES = $PasswordResetTtlMinutes
$env:BOT_API_BASE_URL = $BotApiBaseUrl
$env:BOT_API_KEY = $BotApiKey
$env:BOT_POLL_TOURNAMENT_ID = $BotPollTournamentId
$env:BOT_POLL_INTERVAL_SECONDS = $BotPollIntervalSeconds
$env:BOT_TOKEN = $BotToken
$env:BOT_APPID = $BotAppId
$env:BOT_PUBKEY = $BotPubKey
$env:BOT_CLIENT_ID = $BotClientId
$env:BOT_SECRET_KEY = $BotSecretKey
$env:BOT_PERMISSIONS_INT = $BotPermissionsInt
$env:BOT_CHANNEL_ID = $BotChannelId
$env:BOT_ANNOUNCE_READY = $BotAnnounceReady
$env:BOT_SYNC_GUILD_COMMANDS = $BotSyncGuildCommands
$env:BOT_CLEAR_GUILD_COMMANDS = $BotClearGuildCommands

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

# The vendored discord.py package is imported directly by discord_bot.py, so
# make sure its third-party runtime dependency is present even if an existing
# environment was created before aiohttp was added to requirements.txt.
python -c "import aiohttp" 2>$null
if($LASTEXITCODE -ne 0){
    Write-Host "Installing missing Discord bot dependency aiohttp..."
    python -m pip install 'aiohttp>=3.7.4,<4' | Out-Null
}

if($BotInstallEnabled){
    $botInstallTarget = $BotInstallPath
    if(-not [string]::IsNullOrEmpty($BotInstallExtras)){ $botInstallTarget = "$botInstallTarget[$BotInstallExtras]" }
    Write-Host "Installing Walter bot package from $BotInstallPath..."
    if($BotInstallEditable){
        python -m pip install -e $botInstallTarget | Out-Null
    } else {
        python -m pip install $botInstallTarget | Out-Null
    }
}


function Stop-ExistingBotRuntime {
    if([string]::IsNullOrEmpty($BotRuntimeModule) -and [string]::IsNullOrEmpty($BotRuntimeScript)){ return }

    Write-Host "Stopping existing Walter bot runtime if present..."
    $scriptName = if([string]::IsNullOrEmpty($BotRuntimeScript)){ "" } else { [System.IO.Path]::GetFileName($BotRuntimeScript) }
    Get-CimInstance Win32_Process -Filter "Name = 'python.exe' OR Name = 'python3.exe'" | ForEach-Object {
        $cmd = $_.CommandLine
        if([string]::IsNullOrEmpty($cmd)){ return }
        $matchesModule = (-not [string]::IsNullOrEmpty($BotRuntimeModule)) -and ($cmd -match [regex]::Escape("-m $BotRuntimeModule") -or $cmd -match [regex]::Escape($BotRuntimeModule))
        $matchesScript = (-not [string]::IsNullOrEmpty($BotRuntimeScript)) -and ($cmd -match [regex]::Escape($BotRuntimeScript) -or $cmd -match [regex]::Escape($scriptName))
        if($matchesModule -or $matchesScript){
            Write-Host "Stopping Walter bot process $($_.ProcessId)"
            Stop-Process -Id $_.ProcessId -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

Stop-ExistingBotRuntime

Write-Host "Initializing database..."
python -m flask --app app.app db-init

Write-Host "Creating default admin user..."
python -m flask --app app.app create-admin --email $newadmin.UserName --password $newadmin.GetNetworkCredential().Password

function Test-BotRuntimeShouldStart {
    $mode = [string]$BotRuntimeEnabled
    if([string]::IsNullOrWhiteSpace($mode) -or $mode.ToLowerInvariant() -eq "auto"){
        return (-not [string]::IsNullOrEmpty($BotRuntimeModule) -or -not [string]::IsNullOrEmpty($BotRuntimeScript))
    }
    return ($mode.ToLowerInvariant() -in @("1", "true", "yes", "y", "on"))
}

Write-Host "Starting Waitress server..."
$waitressLog = Join-Path $PSScriptRoot "waitress-server.log"
$waitressErrorLog = Join-Path $PSScriptRoot "waitress-server.err.log"
$waitressArgs = @("-m", "waitress", "--host=$FlaskIP", "--port=$FlaskPort", "app.app:app")
Start-Process -NoNewWindow -FilePath "python" -ArgumentList $waitressArgs -RedirectStandardOutput $waitressLog -RedirectStandardError $waitressErrorLog
Write-Host "Waitress server started. Logs: $waitressLog; errors: $waitressErrorLog"

if(Test-BotRuntimeShouldStart){
    if(-not [string]::IsNullOrEmpty($BotRuntimeModule) -and -not [string]::IsNullOrEmpty($BotRuntimeScript)){
        Write-Error "Only one of bot_runtime_module or bot_runtime_script may be configured."
        exit 1
    }
    if([string]::IsNullOrEmpty($BotRuntimeModule) -and [string]::IsNullOrEmpty($BotRuntimeScript)){
        Write-Error "bot_runtime_enabled is true, but neither bot_runtime_module nor bot_runtime_script is configured."
        exit 1
    }
    $botLog = Join-Path $PSScriptRoot $BotRuntimeLogFile
    $botErrorLog = Join-Path $PSScriptRoot $BotRuntimeErrorLogFile
    $botExtraArgs = @()
    if(-not [string]::IsNullOrWhiteSpace($BotRuntimeArgs)){ $botExtraArgs = $BotRuntimeArgs -split ' ' }
    if(-not [string]::IsNullOrEmpty($BotRuntimeModule)){
        $botArgs = @("-m", $BotRuntimeModule) + $botExtraArgs
        Start-Process -NoNewWindow -FilePath "python" -ArgumentList $botArgs -RedirectStandardOutput $botLog -RedirectStandardError $botErrorLog
    } else {
        $botArgs = @($BotRuntimeScript) + $botExtraArgs
        Start-Process -NoNewWindow -FilePath "python" -ArgumentList $botArgs -RedirectStandardOutput $botLog -RedirectStandardError $botErrorLog
    }
    Write-Host "Walter bot started. Logs: $botLog; errors: $botErrorLog"
}

Start-Sleep -Seconds 3

function Get-AppUrlHost {
    param([string]$HostName)

    # Use the configured Flask host exactly as provided in config.yaml so the
    # startup output and browser launch match the configured bind address. Only
    # fall back when the config value is empty.
    if([string]::IsNullOrWhiteSpace($HostName)){ return "127.0.0.1" }

    return $HostName
}

#open the browser to the Flask app
$AppUrlHost = Get-AppUrlHost $FlaskIP
Start-Process "http://$($AppUrlHost):$($FlaskPort)/"
Write-Host "Application URL: http://$($AppUrlHost):$($FlaskPort)/"
