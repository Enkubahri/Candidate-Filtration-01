"""
Security utilities and configuration for production-ready Flask application.
Implements industry-standard security measures including encryption, validation, and monitoring.
"""

import os
import re
import hashlib
import secrets
import logging
import functools
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import request, session, current_app, g
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import magic  # For file type detection
import bleach  # For HTML sanitization

# Configure security logging
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')

class SecurityConfig:
    """Centralized security configuration management."""
    
    def __init__(self):
        self.load_config()
    
    def load_config(self):
        """Load security configuration from environment variables."""
        self.SECRET_KEY = os.getenv('SECRET_KEY', self._generate_secret_key())
        self.DATABASE_ENCRYPTION_KEY = os.getenv('DATABASE_ENCRYPTION_KEY', self._generate_secret_key())
        self.BACKUP_ENCRYPTION_KEY = os.getenv('BACKUP_ENCRYPTION_KEY', self._generate_secret_key())
        
        # Password requirements
        self.PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', '12'))
        self.PASSWORD_REQUIRE_UPPERCASE = os.getenv('PASSWORD_REQUIRE_UPPERCASE', 'True').lower() == 'true'
        self.PASSWORD_REQUIRE_LOWERCASE = os.getenv('PASSWORD_REQUIRE_LOWERCASE', 'True').lower() == 'true'
        self.PASSWORD_REQUIRE_DIGITS = os.getenv('PASSWORD_REQUIRE_DIGITS', 'True').lower() == 'true'
        self.PASSWORD_REQUIRE_SPECIAL = os.getenv('PASSWORD_REQUIRE_SPECIAL', 'True').lower() == 'true'
        
        # File security
        self.FILE_ENCRYPTION_ENABLED = os.getenv('FILE_ENCRYPTION_ENABLED', 'True').lower() == 'true'
        self.FILE_NAME_OBFUSCATION = os.getenv('FILE_NAME_OBFUSCATION', 'True').lower() == 'true'
        self.VIRUS_SCAN_ENABLED = os.getenv('VIRUS_SCAN_ENABLED', 'False').lower() == 'true'
        self.ALLOWED_EXTENSIONS = os.getenv('ALLOWED_EXTENSIONS', 'pdf,doc,docx').split(',')
        
        # Rate limiting
        self.LOGIN_ATTEMPTS_LIMIT = int(os.getenv('LOGIN_ATTEMPTS_LIMIT', '5'))
        self.FORM_SUBMISSION_LIMIT = int(os.getenv('FORM_SUBMISSION_LIMIT', '10'))
        
        # Session security
        self.PERMANENT_SESSION_LIFETIME = int(os.getenv('PERMANENT_SESSION_LIFETIME', '3600'))
        
    def _generate_secret_key(self) -> str:
        """Generate a secure random key."""
        return secrets.token_urlsafe(32)

# Global security configuration instance
security_config = SecurityConfig()

class PasswordValidator:
    """Advanced password validation with security requirements."""
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, List[str]]:
        """
        Validate password against security requirements.
        Returns (is_valid, list_of_errors)
        """
        errors = []
        
        if len(password) < security_config.PASSWORD_MIN_LENGTH:
            errors.append(f"Password must be at least {security_config.PASSWORD_MIN_LENGTH} characters long")
        
        if security_config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if security_config.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if security_config.PASSWORD_REQUIRE_DIGITS and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if security_config.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Check for common weak passwords
        weak_patterns = [
            r'password',
            r'123456',
            r'qwerty',
            r'admin',
            r'letmein'
        ]
        
        for pattern in weak_patterns:
            if re.search(pattern, password.lower()):
                errors.append("Password contains common weak patterns")
                break
        
        return len(errors) == 0, errors

    @staticmethod
    def hash_password(password: str) -> str:
        """Generate secure password hash with salt."""
        # Use stronger hashing with higher cost factor for production
        return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash."""
        return check_password_hash(password_hash, password)

class DataEncryption:
    """Handle encryption and decryption of sensitive data."""
    
    def __init__(self, key: Optional[str] = None):
        self.key = key or security_config.DATABASE_ENCRYPTION_KEY
        self.cipher_suite = self._get_cipher_suite()
    
    def _get_cipher_suite(self):
        """Create cipher suite from key."""
        key_bytes = self.key.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'stable_salt_for_app',  # In production, use dynamic salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
        return Fernet(key)
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data."""
        if not data:
            return data
        return self.cipher_suite.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        if not encrypted_data:
            return encrypted_data
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
    
    def encrypt_file(self, file_path: str) -> str:
        """Encrypt file and return encrypted file path."""
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        encrypted_data = self.cipher_suite.encrypt(file_data)
        encrypted_path = file_path + '.enc'
        
        with open(encrypted_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
        
        # Remove original file
        os.remove(file_path)
        return encrypted_path
    
    def decrypt_file(self, encrypted_file_path: str, output_path: str):
        """Decrypt file to output path."""
        with open(encrypted_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        
        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
        
        with open(output_path, 'wb') as output_file:
            output_file.write(decrypted_data)

class FileSecurityValidator:
    """Validate and secure file uploads."""
    
    @staticmethod
    def validate_file(file, allowed_extensions: List[str] = None) -> Tuple[bool, str]:
        """
        Comprehensive file validation.
        Returns (is_valid, error_message)
        """
        if not file or not file.filename:
            return False, "No file provided"
        
        allowed_extensions = allowed_extensions or security_config.ALLOWED_EXTENSIONS
        
        # Check file extension
        file_ext = file.filename.rsplit('.', 1)[-1].lower()
        if file_ext not in allowed_extensions:
            return False, f"File type '{file_ext}' not allowed. Allowed types: {', '.join(allowed_extensions)}"
        
        # Check file size (Flask handles this, but double-check)
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        max_size = int(os.getenv('MAX_CONTENT_LENGTH', '16777216'))  # 16MB default
        if file_size > max_size:
            return False, f"File size exceeds maximum allowed size of {max_size / 1024 / 1024:.1f}MB"
        
        # MIME type validation using python-magic
        try:
            file_content = file.read(1024)  # Read first 1KB for MIME detection
            file.seek(0)
            
            mime_type = magic.from_buffer(file_content, mime=True)
            
            allowed_mime_types = {
                'pdf': 'application/pdf',
                'doc': 'application/msword',
                'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            }
            
            if file_ext in allowed_mime_types and mime_type != allowed_mime_types[file_ext]:
                return False, "File content doesn't match file extension"
                
        except Exception as e:
            security_logger.warning(f"MIME type validation failed: {e}")
            # Continue without MIME validation if library fails
        
        return True, ""
    
    @staticmethod
    def generate_secure_filename(original_filename: str) -> str:
        """Generate secure, obfuscated filename."""
        if not security_config.FILE_NAME_OBFUSCATION:
            return original_filename
        
        # Extract file extension
        file_ext = original_filename.rsplit('.', 1)[-1].lower() if '.' in original_filename else ''
        
        # Generate secure random filename
        secure_name = secrets.token_urlsafe(16)
        prefix = os.getenv('SECURE_FILENAME_PREFIX', 'secure_')
        
        return f"{prefix}{secure_name}.{file_ext}" if file_ext else f"{prefix}{secure_name}"

class LoginAttemptTracker:
    """Track and limit login attempts to prevent brute force attacks."""
    
    def __init__(self):
        self.attempts = {}  # In production, use Redis or database
        self.blocked_ips = {}
    
    def record_failed_attempt(self, identifier: str):
        """Record a failed login attempt."""
        current_time = datetime.now()
        
        if identifier not in self.attempts:
            self.attempts[identifier] = []
        
        self.attempts[identifier].append(current_time)
        
        # Clean old attempts (older than 1 hour)
        cutoff_time = current_time - timedelta(hours=1)
        self.attempts[identifier] = [
            attempt for attempt in self.attempts[identifier] 
            if attempt > cutoff_time
        ]
        
        # Block if too many attempts
        if len(self.attempts[identifier]) >= security_config.LOGIN_ATTEMPTS_LIMIT:
            self.blocked_ips[identifier] = current_time + timedelta(hours=1)
            security_logger.warning(f"IP/User blocked due to excessive login attempts: {identifier}")
    
    def is_blocked(self, identifier: str) -> bool:
        """Check if identifier is currently blocked."""
        if identifier in self.blocked_ips:
            if datetime.now() < self.blocked_ips[identifier]:
                return True
            else:
                # Unblock if time has passed
                del self.blocked_ips[identifier]
        
        return False
    
    def record_successful_login(self, identifier: str):
        """Clear failed attempts on successful login."""
        if identifier in self.attempts:
            del self.attempts[identifier]
        if identifier in self.blocked_ips:
            del self.blocked_ips[identifier]

# Global login attempt tracker
login_tracker = LoginAttemptTracker()

class SecurityLogger:
    """Centralized security logging."""
    
    @staticmethod
    def log_security_event(event_type: str, details: Dict[str, Any], severity: str = 'INFO'):
        """Log security events."""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'ip_address': request.remote_addr if request else 'N/A',
            'user_agent': request.headers.get('User-Agent', 'N/A') if request else 'N/A',
            'session_id': session.get('_id', 'N/A') if session else 'N/A',
            'user_id': getattr(g, 'current_user_id', 'N/A'),
            'details': details
        }
        
        log_message = f"SECURITY_EVENT: {event_type} | {details}"
        
        if severity == 'WARNING':
            security_logger.warning(log_message, extra=log_data)
        elif severity == 'ERROR':
            security_logger.error(log_message, extra=log_data)
        elif severity == 'CRITICAL':
            security_logger.critical(log_message, extra=log_data)
        else:
            security_logger.info(log_message, extra=log_data)
    
    @staticmethod
    def log_audit_event(action: str, resource: str, user_id: str, details: Dict[str, Any] = None):
        """Log audit trail events."""
        audit_data = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'resource': resource,
            'user_id': user_id,
            'ip_address': request.remote_addr if request else 'N/A',
            'details': details or {}
        }
        
        audit_logger.info(f"AUDIT: {action} on {resource} by {user_id}", extra=audit_data)

class InputSanitizer:
    """Sanitize and validate input data."""
    
    @staticmethod
    def sanitize_html(html_content: str) -> str:
        """Sanitize HTML content to prevent XSS."""
        allowed_tags = ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li']
        return bleach.clean(html_content, tags=allowed_tags, strip=True)
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent directory traversal."""
        # Remove any directory path components
        filename = os.path.basename(filename)
        
        # Remove or replace dangerous characters
        filename = re.sub(r'[^\w\-_\.]', '_', filename)
        
        # Prevent hidden files and relative paths
        filename = filename.lstrip('.')
        
        return filename
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def sanitize_string(input_str: str, max_length: int = 1000) -> str:
        """General string sanitization."""
        if not input_str:
            return ""
        
        # Truncate if too long
        if len(input_str) > max_length:
            input_str = input_str[:max_length]
        
        # Remove null bytes and control characters
        input_str = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_str)
        
        return input_str.strip()

def security_headers(response):
    """Add security headers to all responses."""
    headers = {
        'X-Content-Type-Options': os.getenv('X_CONTENT_TYPE_OPTIONS', 'nosniff'),
        'X-Frame-Options': os.getenv('X_FRAME_OPTIONS', 'DENY'),
        'X-XSS-Protection': os.getenv('X_XSS_PROTECTION', '1; mode=block'),
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
    }
    
    csp = os.getenv('CONTENT_SECURITY_POLICY')
    if csp:
        headers['Content-Security-Policy'] = csp
    
    for header, value in headers.items():
        response.headers[header] = value
    
    return response

def rate_limit_check(identifier: str, limit: int, window: int = 3600) -> bool:
    """
    Check if request exceeds rate limit.
    Returns True if request should be allowed, False if rate limited.
    """
    # This is a simple in-memory implementation
    # In production, use Redis or database
    current_time = datetime.now()
    
    if not hasattr(g, 'rate_limits'):
        g.rate_limits = {}
    
    if identifier not in g.rate_limits:
        g.rate_limits[identifier] = []
    
    # Clean old requests
    cutoff_time = current_time - timedelta(seconds=window)
    g.rate_limits[identifier] = [
        req_time for req_time in g.rate_limits[identifier]
        if req_time > cutoff_time
    ]
    
    # Check if limit exceeded
    if len(g.rate_limits[identifier]) >= limit:
        return False
    
    # Record this request
    g.rate_limits[identifier].append(current_time)
    return True

# Decorator for rate limiting
def rate_limit(limit: int = 10, window: int = 3600):
    """Rate limiting decorator."""
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            identifier = request.remote_addr
            
            if not rate_limit_check(identifier, limit, window):
                SecurityLogger.log_security_event(
                    'RATE_LIMIT_EXCEEDED',
                    {'endpoint': request.endpoint, 'limit': limit, 'window': window},
                    'WARNING'
                )
                return {'error': 'Rate limit exceeded'}, 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
