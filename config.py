import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Email configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # Database
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'candidates.db'
    
    # File upload settings
    ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}
    
    # Filtration settings
    SKILL_MATCH_THRESHOLD = float(os.environ.get('SKILL_MATCH_THRESHOLD') or 0.7)  # 70% match required
    PASS_CRITERIA_COUNT = int(os.environ.get('PASS_CRITERIA_COUNT') or 2)  # 2 out of 3 criteria must pass
