#!/usr/bin/env python3
"""
Deployment script for Candidate Filtration System API
Supports multiple deployment platforms
"""

import os
import sys
import subprocess
import json
import argparse

def run_command(command, check=True):
    """Run a shell command and return the result"""
    print(f"Running: {command}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=check)
        if result.stdout:
            print(result.stdout)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        if check:
            sys.exit(1)
        return e

def check_prerequisites():
    """Check if required tools are installed"""
    print("Checking prerequisites...")
    
    # Check Python
    result = run_command("python --version", check=False)
    if result.returncode != 0:
        result = run_command("py --version", check=False)
        if result.returncode != 0:
            print("❌ Python not found")
            return False
    print("✅ Python found")
    
    # Check pip
    result = run_command("pip --version", check=False)
    if result.returncode != 0:
        print("❌ pip not found")
        return False
    print("✅ pip found")
    
    return True

def install_dependencies():
    """Install required dependencies"""
    print("Installing dependencies...")
    run_command("pip install -r requirements.txt")
    print("✅ Dependencies installed")

def setup_environment():
    """Set up environment variables"""
    print("Setting up environment...")
    
    if not os.path.exists('.env'):
        print("Creating .env file from template...")
        run_command("cp .env.example .env")
        print("⚠️  Please edit .env file with your configuration")
    else:
        print("✅ .env file already exists")

def test_local():
    """Test the application locally"""
    print("Testing application locally...")
    print("This will start the server. Press Ctrl+C to stop.")
    
    try:
        # Start server in background for testing
        import threading
        import time
        import requests
        
        def start_server():
            os.system("python index.py")
        
        server_thread = threading.Thread(target=start_server)
        server_thread.daemon = True
        server_thread.start()
        
        # Wait for server to start
        time.sleep(3)
        
        # Test health endpoint
        try:
            response = requests.get("http://localhost:5000/health", timeout=5)
            if response.status_code == 200:
                print("✅ Local test passed!")
                return True
            else:
                print(f"❌ Local test failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Local test error: {e}")
            return False
            
    except KeyboardInterrupt:
        print("\n✅ Test stopped by user")
        return True

def deploy_heroku():
    """Deploy to Heroku"""
    print("Deploying to Heroku...")
    
    # Check if Heroku CLI is installed
    result = run_command("heroku --version", check=False)
    if result.returncode != 0:
        print("❌ Heroku CLI not found. Please install it first.")
        print("Visit: https://devcenter.heroku.com/articles/heroku-cli")
        return False
    
    # Check if logged in
    result = run_command("heroku auth:whoami", check=False)
    if result.returncode != 0:
        print("Please log in to Heroku:")
        run_command("heroku login")
    
    # Create app if it doesn't exist
    app_name = input("Enter Heroku app name (or press Enter to generate): ").strip()
    if not app_name:
        run_command("heroku create")
    else:
        run_command(f"heroku create {app_name}")
    
    # Set environment variables
    print("Setting environment variables...")
    run_command("heroku config:set FLASK_ENV=production")
    
    secret_key = input("Enter SECRET_KEY (or press Enter to generate): ").strip()
    if not secret_key:
        import secrets
        secret_key = secrets.token_urlsafe(32)
    run_command(f"heroku config:set SECRET_KEY={secret_key}")
    
    # Deploy
    print("Deploying...")
    run_command("git add .")
    run_command('git commit -m "Deploy API to Heroku"')
    run_command("git push heroku main")
    
    # Open app
    run_command("heroku open")
    print("✅ Deployed to Heroku!")

def deploy_docker():
    """Build and run Docker container"""
    print("Building Docker container...")
    
    # Check if Docker is installed
    result = run_command("docker --version", check=False)
    if result.returncode != 0:
        print("❌ Docker not found. Please install Docker first.")
        return False
    
    # Build image
    image_name = "candidate-filtration-api"
    print(f"Building image: {image_name}")
    run_command(f"docker build -t {image_name} .")
    
    # Run container
    port = input("Enter port to run on (default: 5000): ").strip() or "5000"
    print(f"Starting container on port {port}...")
    run_command(f"docker run -p {port}:5000 -d --name {image_name} {image_name}")
    
    print(f"✅ Docker container running on http://localhost:{port}")
    print(f"To stop: docker stop {image_name}")
    print(f"To remove: docker rm {image_name}")

def deploy_vps():
    """Generate deployment instructions for VPS"""
    print("VPS Deployment Instructions:")
    print("=" * 40)
    print("""
1. Copy files to your server:
   scp -r . user@your-server:/path/to/app/

2. SSH into your server:
   ssh user@your-server

3. Navigate to app directory:
   cd /path/to/app/api

4. Install Python dependencies:
   pip install -r requirements.txt

5. Set up environment:
   cp .env.example .env
   nano .env  # Edit configuration

6. Install and configure nginx:
   sudo apt update
   sudo apt install nginx

7. Create nginx configuration:
   sudo nano /etc/nginx/sites-available/candidate-filtration

8. Add this configuration:
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
   }

9. Enable site:
   sudo ln -s /etc/nginx/sites-available/candidate-filtration /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx

10. Run with Gunicorn:
    gunicorn --bind 127.0.0.1:5000 --workers 2 --daemon index:app

11. Set up systemd service (optional):
    sudo nano /etc/systemd/system/candidate-filtration.service
    
    [Unit]
    Description=Candidate Filtration API
    After=network.target

    [Service]
    User=your-user
    WorkingDirectory=/path/to/app/api
    ExecStart=/usr/local/bin/gunicorn --bind 127.0.0.1:5000 --workers 2 index:app
    Restart=always

    [Install]
    WantedBy=multi-user.target

12. Enable and start service:
    sudo systemctl daemon-reload
    sudo systemctl enable candidate-filtration
    sudo systemctl start candidate-filtration
    """)
    print("✅ VPS deployment instructions generated!")

def main():
    parser = argparse.ArgumentParser(description="Deploy Candidate Filtration System API")
    parser.add_argument('command', choices=['setup', 'test', 'heroku', 'docker', 'vps'], 
                       help='Deployment command')
    
    args = parser.parse_args()
    
    if not check_prerequisites():
        print("❌ Prerequisites check failed")
        return
    
    if args.command == 'setup':
        install_dependencies()
        setup_environment()
        print("✅ Setup complete! Run 'python deploy.py test' to test locally.")
        
    elif args.command == 'test':
        test_local()
        
    elif args.command == 'heroku':
        deploy_heroku()
        
    elif args.command == 'docker':
        deploy_docker()
        
    elif args.command == 'vps':
        deploy_vps()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Deployment cancelled by user")
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        sys.exit(1)
