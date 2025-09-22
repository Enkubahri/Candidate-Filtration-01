# PowerShell script to start the Candidate Filtration System

Write-Host "🎯 Starting Candidate Filtration System..." -ForegroundColor Green
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Python not found"
    }
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python from https://python.org/downloads" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if virtual environment exists
if (!(Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
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
    pip install -r requirements.txt
    if ($LASTEXITCODE -eq 0) {
        New-Item -Path "venv\.installed" -ItemType File -Force | Out-Null
        Write-Host "✓ Dependencies installed" -ForegroundColor Green
    } else {
        Write-Host "❌ Error: Could not install dependencies" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# Start the Flask application
Write-Host ""
Write-Host "🚀 Starting Flask application..." -ForegroundColor Green
Write-Host ""
Write-Host "Open your web browser and go to: http://localhost:5000" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
Write-Host ""

python app.py
