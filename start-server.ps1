# PowerShell script to set up and run the MTG Tournament Swiss App.
# Installs dependencies, initializes the database, creates an admin user,
# and starts the Flask development server.
param(
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]    
        $PasswordSeed
)

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

if($null -eq $PasswordSeed){
    $PasswordSeed.UserName = "dev-password-seed-change-me"
}

# Configure password seed for AES encryption
$env:PASSWORD_SEED = $PasswordSeed.UserName

Write-Host "Installing dependencies..."
python -m pip install -r "$PSScriptRoot/requirements.txt" | Out-Null

Write-Host "Setting Flask environment..."
$env:FLASK_APP = "app.app:app"

Write-Host "Initializing database..."
python -m flask --app app.app db-init

Write-Host "Creating default admin user..."
python -m flask --app app.app create-admin --email admin@example.com --password admin123

Write-Host "Starting Flask development server..."
#python -m flask --app app.app run --debug

Start-Process -NoNewWindow -FilePath "flask" -ArgumentList "--app app.app run --debug"

#open the browser to the Flask app
Start-Process "http://127.0.0.1:5000/"
