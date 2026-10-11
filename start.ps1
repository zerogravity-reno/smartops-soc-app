# SmartOps SOC — Quick Start
# Run this after filling in .env

# Load .env
Get-Content .env | Where-Object { $_ -notmatch "^#" -and $_ -match "=" } | ForEach-Object {
    $k, $v = $_ -split "=", 2
    [System.Environment]::SetEnvironmentVariable($k.Trim(), $v.Trim(), "Process")
}

# Install dependencies
uv sync

# Build the frontend (served by the server at /)
Push-Location frontend
npm install
npm run build
Pop-Location

# Start server
Write-Host "Starting SmartOps SOC on http://localhost:8013" -ForegroundColor Green
uv run uvicorn webapp.main:app --host 0.0.0.0 --port 8013 --reload
