# PowerShell script to start the Candidate Filtration System
# Updated with correct Python path

$pythonPath = "C:\Users\edex7\AppData\Local\Programs\Python\Python313\python.exe"

Write-Host "🎯 Starting Candidate Filtration System..." -ForegroundColor Green
Write-Host ""

# Check if Python is available at the expected path
if (!(Test-Path $pythonPath)) {
    Write-Host "❌ Error: Python not found at expected location" -ForegroundColor Red
    Write-Host "Expected: $pythonPath" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

$pythonVersion = & $pythonPath --version
Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green

# Check if virtual environment exists
if (!(Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    & $pythonPath -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Error: Could not create virtual environment" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "✓ Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"

# Install dependencies if not already installed
if (!(Test-Path "venv\.installed")) {
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    & "venv\Scripts\pip.exe" install -r requirements.txt
    if ($LASTEXITCODE -eq 0) {
        New-Item -Path "venv\.installed" -ItemType File -Force | Out-Null
        Write-Host "✓ Dependencies installed" -ForegroundColor Green
    } else {
        Write-Host "❌ Error: Could not install dependencies" -ForegroundColor Red
        Write-Host "Trying to install with base Python..." -ForegroundColor Yellow
        & $pythonPath -m pip install -r requirements.txt
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ Dependencies installed with base Python" -ForegroundColor Green
        } else {
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
}

# Start the Flask application
Write-Host ""
Write-Host "🚀 Starting Flask application..." -ForegroundColor Green
Write-Host ""
Write-Host "Open your web browser and go to: http://localhost:5000" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
Write-Host ""

try {
    & "venv\Scripts\python.exe" app.py
} catch {
    Write-Host "Trying with base Python..." -ForegroundColor Yellow
    & $pythonPath app.py
}
