# Candidate Filtration System - Dependency Management Guide

This guide covers the new dependency management system using both **Pipenv** (recommended) and traditional **pip + requirements.txt**.

## 📋 Requirements Files Overview

We now have a streamlined dependency management system:

### 📁 **Requirements Files:**
- `requirements.txt` - **Production-ready consolidated dependencies** (merged from all previous files)
- `requirements-dev.txt` - **Development-only dependencies** (testing, linting, etc.)
- `api/requirements.txt` - **Minimal API deployment dependencies**
- `Pipfile` - **Pipenv configuration** with Python version specification
- `requirements.txt.backup` - **Backup of original requirements**

## 🐍 Python Version
- **Required**: Python 3.13+
- **Current**: Python 3.13.7 (detected)

---

## 🚀 Setup Methods

### **Method 1: Pipenv (Recommended)**

Pipenv provides better dependency management, virtual environments, and lock files for reproducible builds.

#### **1.1 Install Pipenv** (already installed)
```powershell
py -m pip install pipenv
```

#### **1.2 Install Dependencies**
```powershell
# Install production dependencies
pipenv install

# Install development dependencies
pipenv install --dev
```

#### **1.3 Activate Virtual Environment**
```powershell
pipenv shell
```

#### **1.4 Run Application**
```powershell
# Main application
pipenv run start

# API server
pipenv run start-api

# Production mode
pipenv run production
```

#### **1.5 Development Tools**
```powershell
# Run tests
pipenv run test

# Format code
pipenv run format

# Lint code
pipenv run lint

# Type checking
pipenv run type-check
```

---

### **Method 2: Traditional pip + requirements.txt**

#### **2.1 Create Virtual Environment**
```powershell
# Create virtual environment
py -m venv venv

# Activate virtual environment
venv\Scripts\Activate.ps1
```

#### **2.2 Install Dependencies**
```powershell
# Production dependencies only
py -m pip install -r requirements.txt

# Production + Development dependencies
py -m pip install -r requirements.txt -r requirements-dev.txt

# API deployment (minimal)
py -m pip install -r api/requirements.txt
```

#### **2.3 Run Application**
```powershell
# Main application
python app.py

# API server
python api/index.py

# Production with Gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 2 app:app
```

---

## 📦 Dependency Categories

### **Core Flask Framework**
- Flask, Flask-Login, Flask-WTF, Flask-CORS
- WTForms, Werkzeug, Jinja2

### **Security Features**
- `cryptography` - Data encryption
- `passlib[bcrypt]` - Password hashing
- `argon2-cffi` - Advanced password hashing
- `bleach` - XSS prevention
- `flask-talisman` - Security headers

### **File Processing**
- `PyPDF2` - PDF processing
- `python-docx` - Word document processing
- `python-magic` - File type validation

### **Production Features**
- `gunicorn` - WSGI server
- `gevent` - Async workers
- `redis` - Caching/sessions
- `Flask-Limiter` - Rate limiting

### **Development Tools** (dev-only)
- `pytest` - Testing framework
- `black` - Code formatting
- `flake8` - Linting
- `mypy` - Type checking

---

## 🛠 Common Commands

### **Pipenv Commands**
```powershell
pipenv --version              # Check pipenv version
pipenv --python 3.13          # Create with specific Python version
pipenv install package        # Add new package
pipenv install package --dev  # Add development package
pipenv uninstall package      # Remove package
pipenv lock                   # Generate Pipfile.lock
pipenv requirements > req.txt # Generate requirements.txt
pipenv graph                  # Show dependency graph
```

### **Development Workflow**
```powershell
# Setup development environment
pipenv install --dev

# Activate shell
pipenv shell

# Format code before committing
pipenv run format
pipenv run lint

# Run tests
pipenv run test

# Start development server
pipenv run start
```

### **Production Deployment**
```powershell
# Production installation (no dev dependencies)
pipenv install --deploy

# Or with pip
py -m pip install --no-cache-dir -r requirements.txt

# Run production server
pipenv run production
```

---

## 🔧 Quick Start Commands

### **Using Pipenv (Recommended):**
```powershell
# Setup everything
pipenv install --dev
pipenv shell
pipenv run start
```

### **Using pip + venv:**
```powershell
# Setup everything
py -m venv venv
venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
python app.py
```

---

## 📚 What Changed

### **✅ Improvements Made:**

1. **Consolidated Requirements**: Merged `requirements.txt`, `requirements-production.txt`, and `api/requirements.txt` into one comprehensive file
2. **Added Pipfile**: Created Pipenv configuration with Python 3.13 specification
3. **Separated Dev Dependencies**: Created `requirements-dev.txt` for development-only packages
4. **Version Standardization**: Aligned all version numbers across files
5. **Added Scripts**: Pipfile includes convenient script shortcuts
6. **Better Documentation**: Each requirements file now has detailed comments

### **📁 File Structure:**
```
candidate-filtration-system/
├── Pipfile                    # Pipenv configuration (NEW)
├── requirements.txt           # Production dependencies (UPDATED - consolidated)
├── requirements-dev.txt       # Development dependencies (NEW)
├── requirements.txt.backup    # Original requirements backup
├── app.py                     # Main Flask application
├── api/
│   ├── index.py              # API entry point
│   └── requirements.txt      # Minimal API requirements (UPDATED)
├── DEPENDENCY_SETUP.md       # This guide (NEW)
└── SETUP.md                  # Original setup guide
```

---

**Your dependency management is now properly organized and production-ready!** 🎉

Choose your preferred method (Pipenv recommended) and follow the quick start commands above.
