# PowerShell script to set up and run the MTG Tournament Swiss App.
# Installs dependencies, initializes the database, creates an admin user,
# and starts the Flask development server.

Write-Host "Installing dependencies..."
python -m pip install -r requirements.txt

Write-Host "Setting Flask environment..."
$env:FLASK_APP = "app.app:app"

Write-Host "Initializing database..."
flask --app app.app db-init

Write-Host "Creating default admin user..."
flask --app app.app create-admin --email admin@example.com --password admin123

Write-Host "Starting Flask development server..."
flask --app app.app run --debug
