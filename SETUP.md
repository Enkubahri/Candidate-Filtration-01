# Quick Setup Guide

## 🚀 Getting Started

### Step 1: Install Python
Since Python is not currently installed on your system:

1. Go to https://www.python.org/downloads/
2. Download Python 3.9 or later
3. **IMPORTANT**: During installation, check "Add Python to PATH"
4. Complete the installation

### Step 2: Test the Demo
Once Python is installed, test the filtration logic:

```powershell
# In PowerShell, run:
python demo.py
```

This will:
- Create a demo database with sample candidates
- Set up filtration criteria
- Show how each candidate is evaluated
- Display pass/fail results

### Step 3: Run the Web Application

#### Option A: Using PowerShell Script
```powershell
.\run.ps1
```

#### Option B: Manual Setup
```powershell
# Create virtual environment
python -m venv venv

# Activate it
venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Step 4: Access the System
Open your browser and go to: http://localhost:5000

## 🧪 Testing the System

### Test Scenario 1: Set Up Admin Criteria
1. Go to http://localhost:5000/admin
2. Set criteria:
   - Min Experience: 3 years
   - Required Skills: Python, SQL, Communication
   - Min Education: Bachelor's Degree
   - Notification Email: your-email@example.com
3. Save the criteria

### Test Scenario 2: Submit Test Applications
Submit these test candidates to see different outcomes:

**Candidate A (Should PASS):**
- Name: Alice Johnson
- Email: alice@test.com
- Experience: 5 years
- Education: Master's Degree
- Skills: Python, SQL, JavaScript, Communication
- Upload any PDF file as resume

**Candidate B (Should FAIL):**
- Name: Bob Smith
- Email: bob@test.com
- Experience: 1 year
- Education: High School
- Skills: HTML, CSS
- Upload any PDF file as resume

## 🔧 Configuration

### Email Setup (Optional)
To enable actual email notifications:

1. Copy `.env.example` to `.env`
2. Fill in your SMTP settings:
   ```
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-specific-password
   ```
3. For Gmail, you need to:
   - Enable 2-factor authentication
   - Generate an "App Password"
   - Use the app password in the .env file

## 📂 Project Overview

The system includes:

- **`app.py`** - Main Flask application with all routes and logic
- **`templates/`** - HTML templates for all pages
- **`static/`** - CSS and JavaScript files
- **`uploads/`** - Directory for uploaded resumes
- **`demo.py`** - Test script to demonstrate filtration logic
- **Database** - SQLite database created automatically

## ⚡ Quick Commands

```powershell
# Test the filtration logic
python demo.py

# Start the web application
python app.py

# Install a new dependency
pip install package-name

# View current directory structure
tree /f
```

## 🎯 System Features

### Automatic Filtration
- Evaluates candidates on 3 criteria: experience, skills, education
- Requires 2 out of 3 criteria to pass
- 70% skill match threshold
- Hierarchical education comparison

### Security Features
- File upload validation (PDF/Word only, 16MB max)
- Secure filename handling
- Form validation and CSRF protection
- Input sanitization

### User Experience
- Responsive design with Bootstrap
- Real-time form validation
- Loading states during submission
- Automatic phone number formatting
- File upload preview
