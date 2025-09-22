@echo off
echo Starting Candidate Filtration System...
echo.

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo Error: Could not create virtual environment. Make sure Python is installed.
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies if requirements.txt is newer than last install
if not exist "venv\.installed" (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo Error: Could not install dependencies.
        pause
        exit /b 1
    )
    echo. > venv\.installed
)

REM Start the Flask application
echo Starting Flask application...
echo.
echo Open your web browser and go to: http://localhost:5000
echo Press Ctrl+C to stop the application
echo.
python app.py
