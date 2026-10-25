# SmartOps SOC — Quick Start
# Run this after filling in .env (the server loads it at startup).

# Install dependencies
uv sync

# Build the frontend (served by the server at /)
Push-Location frontend
npm install
npm run build
Pop-Location

# Start server
Write-Host "Starting SmartOps SOC on http://localhost:8013" -ForegroundColor Green
uv run uvicorn smartops.main:app --host 0.0.0.0 --port 8013 --reload --reload-dir engine
