#!/usr/bin/env python3
"""
Dependency Setup Verification Script
Verifies that the new dependency management structure is correctly set up
"""

import os
import sys
from pathlib import Path

def check_file_exists(file_path, description):
    """Check if a file exists and return status"""
    if os.path.exists(file_path):
        size = os.path.getsize(file_path)
        print(f"✅ {description}: {file_path} ({size} bytes)")
        return True
    else:
        print(f"❌ {description}: {file_path} (Missing)")
        return False

def count_dependencies(file_path):
    """Count non-comment, non-empty lines in requirements file"""
    if not os.path.exists(file_path):
        return 0
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    count = 0
    for line in lines:
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('-'):
            count += 1
    
    return count

def main():
    print("🔍 Verifying Candidate Filtration System Dependency Setup")
    print("=" * 60)
    
    # Check Python version
    python_version = sys.version
    print(f"🐍 Python Version: {python_version.split()[0]}")
    print()
    
    # Check main files
    print("📁 Main Files:")
    files_ok = 0
    total_files = 0
    
    files_to_check = [
        ("Pipfile", "Pipenv configuration"),
        ("requirements.txt", "Production requirements (consolidated)"),
        ("requirements-dev.txt", "Development requirements"),
        ("requirements.txt.backup", "Original requirements backup"),
        ("DEPENDENCY_SETUP.md", "Dependency setup guide"),
    ]
    
    for file_path, description in files_to_check:
        total_files += 1
        if check_file_exists(file_path, description):
            files_ok += 1
    
    print()
    
    # Check API files
    print("🔌 API Files:")
    api_files = [
        ("api/requirements.txt", "API minimal requirements"),
        ("api/index.py", "API entry point"),
        ("api/README.md", "API documentation"),
    ]
    
    for file_path, description in api_files:
        total_files += 1
        if check_file_exists(file_path, description):
            files_ok += 1
    
    print()
    
    # Count dependencies
    print("📦 Dependency Counts:")
    if os.path.exists("requirements.txt"):
        prod_deps = count_dependencies("requirements.txt")
        print(f"   Production dependencies: {prod_deps}")
    
    if os.path.exists("requirements-dev.txt"):
        dev_deps = count_dependencies("requirements-dev.txt")
        print(f"   Development dependencies: {dev_deps}")
    
    if os.path.exists("api/requirements.txt"):
        api_deps = count_dependencies("api/requirements.txt")
        print(f"   API dependencies: {api_deps}")
    
    print()
    
    # Check for pipenv
    print("🛠 Tools Check:")
    try:
        import subprocess
        result = subprocess.run([sys.executable, "-m", "pipenv", "--version"], 
                              capture_output=True, text=True, check=True)
        print(f"✅ Pipenv installed: {result.stdout.strip()}")
        pipenv_ok = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Pipenv not found or not working")
        pipenv_ok = False
    
    print()
    
    # Summary
    print("📊 Setup Summary:")
    print(f"   Files: {files_ok}/{total_files} present")
    print(f"   Pipenv: {'✅ Ready' if pipenv_ok else '❌ Issues'}")
    print()
    
    # Recommendations
    print("🚀 Next Steps:")
    if files_ok == total_files and pipenv_ok:
        print("   ✅ Setup is complete! Choose your preferred method:")
        print()
        print("   📋 Quick Start Options:")
        print("   1. With Pipenv (Recommended):")
        print("      pipenv install --dev")
        print("      pipenv shell")
        print("      pipenv run start")
        print()
        print("   2. With pip + venv:")
        print("      py -m venv venv")
        print("      venv\\Scripts\\Activate.ps1")
        print("      py -m pip install -r requirements.txt")
        print("      python app.py")
        print()
        print("   📚 Read DEPENDENCY_SETUP.md for detailed instructions")
        
    else:
        print("   ⚠️  Some files are missing. Please check the setup.")
        if not pipenv_ok:
            print("   💡 Install pipenv: py -m pip install pipenv")
    
    print()
    print("=" * 60)
    print("🎉 Verification complete!")

if __name__ == "__main__":
    main()
