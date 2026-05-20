# Safeguard-AI Lite - Single Command Launcher
# Usage: .\start.ps1

param()

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPath = Join-Path $Root ".venv"
$VenvPython = Join-Path $VenvPath "Scripts\python.exe"
$VenvPip = Join-Path $VenvPath "Scripts\pip.exe"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "   Safeguard-AI Lite - Starting Up..."      -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Python
Write-Host "[1/4] Checking Python..." -ForegroundColor Yellow
try {
    $pyVersion = & python --version 2>&1
    Write-Host "      Found: $pyVersion" -ForegroundColor DarkGray
} catch {
    Write-Host "ERROR: Python not found. Install Python 3.11+ first." -ForegroundColor Red
    exit 1
}

# Step 2: Create venv if it does not exist
if (-Not (Test-Path $VenvPython)) {
    Write-Host "[2/4] Creating virtual environment (.venv)..." -ForegroundColor Yellow
    & python -m venv "$VenvPath"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to create virtual environment." -ForegroundColor Red
        exit 1
    }
    Write-Host "      Virtual environment created." -ForegroundColor DarkGray
} else {
    Write-Host "[2/4] Virtual environment found. Skipping creation." -ForegroundColor Yellow
}

# Step 3: Install/update requirements into venv
Write-Host "[3/4] Installing requirements into .venv..." -ForegroundColor Yellow
& "$VenvPip" install -r "$Root\requirements.txt" --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: pip install failed. Check requirements.txt." -ForegroundColor Red
    exit 1
}
Write-Host "      Dependencies ready." -ForegroundColor DarkGray

# Step 4: Launch Backend
Write-Host ""
Write-Host "[4/4] Launching Safeguard-AI Lite Backend..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Backend -> http://127.0.0.1:8000"      -ForegroundColor Green
Write-Host "  (To run the Next.js frontend, open a new terminal, cd to 'safeguard-ai-frontend', and run 'npm run dev')" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop."                    -ForegroundColor DarkGray
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $Root
& "$VenvPython" -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
