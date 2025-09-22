"""
Comprehensive input validation and sanitization module.
Implements SQL injection protection, XSS prevention, and data validation.
"""

import os
import re
import logging
import html
import unicodedata
from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime
import bleach
import phonenumbers
from email_validator import validate_email, EmailNotValidError
from functools import wraps
from flask import request, jsonify, abort, g
import sqlite3
from urllib.parse import urlparse
import magic
import hashlib

# Get loggers
security_logger = logging.getLogger('security')

class InputValidationError(Exception):
    """Custom exception for input validation errors."""
    def __init__(self, message: str, field: str = None, code: str = None):
        self.message = message
        self.field = field
        self.code = code or 'VALIDATION_ERROR'
        super().__init__(self.message)

class InputValidator:
    """Comprehensive input validation and sanitization."""
    
    def __init__(self):
        """Initialize input validator with security configurations."""
        
        # HTML sanitization settings
        self.allowed_html_tags = {
            'p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
        }
        
        self.allowed_html_attributes = {
            '*': ['class'],
            'a': ['href', 'title'],
            'img': ['src', 'alt', 'width', 'height']
        }
        
        # SQL injection patterns
        self.sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|OR|AND)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(SCRIPT|JAVASCRIPT|VBSCRIPT|ONLOAD|ONERROR)\b)",
            r"([\'\"];?\s*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER))",
            r"(\bUNION\b.+\bSELECT\b)",
            r"(\b(EXEC|EXECUTE)\s*\()",
            r"(\bINTO\s+(OUTFILE|DUMPFILE))",
            r"(\bLOAD_FILE\s*\()"
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"vbscript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>.*?</iframe>",
            r"<object[^>]*>.*?</object>",
            r"<embed[^>]*>",
            r"<link[^>]*>",
            r"<meta[^>]*>"
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e\\",
            r"..%2f",
            r"..%5c"
        ]
        
        # Command injection patterns
        self.command_injection_patterns = [
            r"[;&|`$()]",
            r"\b(cat|ls|dir|type|copy|move|del|rm|chmod|chown)\b",
            r"(\||&&|;|`|\$\(|\${)",
            r"(nc|netcat|wget|curl|ping|nslookup)\b"
        ]
        
        # File type validation
        self.allowed_file_extensions = {
            'documents': {'.pdf', '.doc', '.docx', '.txt', '.rtf'},
            'images': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg'},
            'archives': {'.zip', '.rar', '.7z', '.tar', '.gz'},
            'spreadsheets': {'.xls', '.xlsx', '.csv'}
        }
        
        # MIME type validation
        self.allowed_mime_types = {
            'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain', 'text/rtf', 'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/bmp',
            'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
            'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/csv'
        }
        
        # Maximum field lengths
        self.max_lengths = {
            'email': 254,
            'password': 128,
            'name': 100,
            'phone': 20,
            'address': 500,
            'description': 5000,
            'url': 2048,
            'filename': 255,
            'job_title': 200,
            'company': 200
        }
        
        # Regex patterns for validation
        self.patterns = {
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'phone': re.compile(r'^\+?[\d\s\-\(\)\.]+$'),
            'name': re.compile(r'^[a-zA-Z\s\.\-\']+$'),
            'alphanumeric': re.compile(r'^[a-zA-Z0-9]+$'),
            'numeric': re.compile(r'^\d+$'),
            'safe_filename': re.compile(r'^[a-zA-Z0-9._\-]+$'),
            'url': re.compile(r'^https?://[^\s<>"]+$'),
            'job_id': re.compile(r'^\d+$'),
            'status': re.compile(r'^(active|inactive|pending|completed)$', re.IGNORECASE)
        }
    
    def validate_and_sanitize(self, data: Dict[str, Any], rules: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Validate and sanitize input data based on rules.
        
        Args:
            data: Input data dictionary
            rules: Validation rules dictionary
        
        Returns:
            Sanitized and validated data
        
        Raises:
            InputValidationError: If validation fails
        """
        validated_data = {}
        errors = []
        
        for field, field_rules in rules.items():
            try:
                value = data.get(field)
                
                # Check if field is required
                if field_rules.get('required', False) and not value:
                    errors.append(f"{field} is required")
                    continue
                
                # Skip validation if field is optional and empty
                if not value and not field_rules.get('required', False):
                    validated_data[field] = None
                    continue
                
                # Apply validation rules
                validated_value = self._validate_field(field, value, field_rules)
                validated_data[field] = validated_value
                
            except InputValidationError as e:
                errors.append(f"{field}: {e.message}")
            except Exception as e:
                security_logger.error(f"Validation error for field {field}: {e}")
                errors.append(f"{field}: Validation failed")
        
        if errors:
            raise InputValidationError("; ".join(errors))
        
        return validated_data
    
    def _validate_field(self, field_name: str, value: Any, rules: Dict) -> Any:
        """Validate individual field based on rules."""
        
        # Convert to string for text processing
        if value is not None:
            str_value = str(value).strip()
        else:
            str_value = ""
        
        # Length validation
        if 'max_length' in rules:
            if len(str_value) > rules['max_length']:
                raise InputValidationError(f"Maximum length is {rules['max_length']} characters")
        
        if 'min_length' in rules:
            if len(str_value) < rules['min_length']:
                raise InputValidationError(f"Minimum length is {rules['min_length']} characters")
        
        # Type-specific validation
        field_type = rules.get('type', 'string')
        
        if field_type == 'email':
            return self._validate_email(str_value)
        elif field_type == 'phone':
            return self._validate_phone(str_value)
        elif field_type == 'url':
            return self._validate_url(str_value)
        elif field_type == 'integer':
            return self._validate_integer(str_value, rules)
        elif field_type == 'float':
            return self._validate_float(str_value, rules)
        elif field_type == 'date':
            return self._validate_date(str_value)
        elif field_type == 'datetime':
            return self._validate_datetime(str_value)
        elif field_type == 'filename':
            return self._validate_filename(str_value)
        elif field_type == 'safe_string':
            return self._validate_safe_string(str_value, rules)
        elif field_type == 'html':
            return self._sanitize_html(str_value)
        elif field_type == 'choice':
            return self._validate_choice(str_value, rules.get('choices', []))
        else:
            # Default string validation
            return self._validate_string(str_value, rules)
    
    def _validate_email(self, email: str) -> str:
        """Validate email address."""
        if not email:
            raise InputValidationError("Email cannot be empty")
        
        try:
            # Use email_validator library for thorough validation
            validated_email = validate_email(email)
            normalized_email = validated_email.email.lower()
            
            # Additional security checks
            self._check_security_patterns(normalized_email, 'email')
            
            return normalized_email
        except EmailNotValidError as e:
            raise InputValidationError(f"Invalid email format: {str(e)}")
    
    def _validate_phone(self, phone: str) -> str:
        """Validate phone number."""
        if not phone:
            raise InputValidationError("Phone number cannot be empty")
        
        try:
            # Parse and validate phone number
            parsed_phone = phonenumbers.parse(phone, None)
            if not phonenumbers.is_valid_number(parsed_phone):
                raise InputValidationError("Invalid phone number format")
            
            # Format to international format
            formatted_phone = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.E164)
            
            # Security check
            self._check_security_patterns(formatted_phone, 'phone')
            
            return formatted_phone
        except phonenumbers.NumberParseException:
            raise InputValidationError("Invalid phone number format")
    
    def _validate_url(self, url: str) -> str:
        """Validate URL."""
        if not url:
            raise InputValidationError("URL cannot be empty")
        
        try:
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                raise InputValidationError("Invalid URL format")
            
            if parsed.scheme not in ['http', 'https']:
                raise InputValidationError("URL must use HTTP or HTTPS")
            
            # Security checks
            self._check_security_patterns(url, 'url')
            
            return url.lower()
        except Exception:
            raise InputValidationError("Invalid URL format")
    
    def _validate_integer(self, value: str, rules: Dict) -> int:
        """Validate integer value."""
        try:
            int_value = int(value)
            
            if 'min_value' in rules and int_value < rules['min_value']:
                raise InputValidationError(f"Minimum value is {rules['min_value']}")
            
            if 'max_value' in rules and int_value > rules['max_value']:
                raise InputValidationError(f"Maximum value is {rules['max_value']}")
            
            return int_value
        except ValueError:
            raise InputValidationError("Must be a valid integer")
    
    def _validate_float(self, value: str, rules: Dict) -> float:
        """Validate float value."""
        try:
            float_value = float(value)
            
            if 'min_value' in rules and float_value < rules['min_value']:
                raise InputValidationError(f"Minimum value is {rules['min_value']}")
            
            if 'max_value' in rules and float_value > rules['max_value']:
                raise InputValidationError(f"Maximum value is {rules['max_value']}")
            
            return float_value
        except ValueError:
            raise InputValidationError("Must be a valid number")
    
    def _validate_date(self, date_str: str) -> str:
        """Validate date string."""
        try:
            datetime.strptime(date_str, '%Y-%m-%d')
            return date_str
        except ValueError:
            raise InputValidationError("Invalid date format. Use YYYY-MM-DD")
    
    def _validate_datetime(self, datetime_str: str) -> str:
        """Validate datetime string."""
        try:
            datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
            return datetime_str
        except ValueError:
            try:
                datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M:%S')
                return datetime_str
            except ValueError:
                raise InputValidationError("Invalid datetime format. Use YYYY-MM-DD HH:MM:SS or ISO format")
    
    def _validate_filename(self, filename: str) -> str:
        """Validate filename for security."""
        if not filename:
            raise InputValidationError("Filename cannot be empty")
        
        # Check for path traversal
        if any(pattern in filename.lower() for pattern in ['../', '..\\', '%2e%2e']):
            raise InputValidationError("Invalid filename: path traversal detected")
        
        # Check for dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\0']
        if any(char in filename for char in dangerous_chars):
            raise InputValidationError("Invalid filename: contains illegal characters")
        
        # Check length
        if len(filename) > 255:
            raise InputValidationError("Filename too long (maximum 255 characters)")
        
        # Check for executable extensions
        dangerous_extensions = {'.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar', '.sh'}
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext in dangerous_extensions:
            raise InputValidationError("File type not allowed")
        
        return filename
    
    def _validate_safe_string(self, value: str, rules: Dict) -> str:
        """Validate string for safety (no injection attacks)."""
        if not value:
            return value
        
        # Check for security patterns
        self._check_security_patterns(value, 'string')
        
        # Apply pattern matching if specified
        if 'pattern' in rules:
            pattern_name = rules['pattern']
            if pattern_name in self.patterns:
                if not self.patterns[pattern_name].match(value):
                    raise InputValidationError(f"Invalid format for {pattern_name}")
        
        # Normalize unicode
        normalized = unicodedata.normalize('NFKC', value)
        
        # Basic sanitization
        sanitized = normalized.strip()
        
        return sanitized
    
    def _validate_choice(self, value: str, choices: List[str]) -> str:
        """Validate value is in allowed choices."""
        if value not in choices:
            raise InputValidationError(f"Invalid choice. Allowed values: {', '.join(choices)}")
        return value
    
    def _validate_string(self, value: str, rules: Dict) -> str:
        """General string validation."""
        if not value and rules.get('allow_empty', False):
            return value
        
        # Basic security check
        self._check_security_patterns(value, 'general')
        
        # Normalize and sanitize
        normalized = unicodedata.normalize('NFKC', value)
        sanitized = html.escape(normalized.strip(), quote=True)
        
        return sanitized
    
    def _sanitize_html(self, html_content: str) -> str:
        """Sanitize HTML content to prevent XSS."""
        if not html_content:
            return html_content
        
        # Use bleach to sanitize HTML
        cleaned_html = bleach.clean(
            html_content,
            tags=self.allowed_html_tags,
            attributes=self.allowed_html_attributes,
            strip=True,
            strip_comments=True
        )
        
        return cleaned_html
    
    def _check_security_patterns(self, value: str, context: str):
        """Check for various security attack patterns."""
        if not value:
            return
        
        value_lower = value.lower()
        
        # SQL Injection check
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                security_logger.critical(f"SQL injection attempt detected", extra={
                    'action': 'SQL_INJECTION_DETECTED',
                    'context': context,
                    'pattern': pattern,
                    'value_hash': hashlib.sha256(value.encode()).hexdigest()[:16],
                    'user_id': getattr(g, 'current_user_id', None),
                    'ip_address': request.remote_addr if request else None
                })
                raise InputValidationError("Invalid input detected")
        
        # XSS check
        for pattern in self.xss_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                security_logger.critical(f"XSS attempt detected", extra={
                    'action': 'XSS_DETECTED',
                    'context': context,
                    'pattern': pattern,
                    'value_hash': hashlib.sha256(value.encode()).hexdigest()[:16],
                    'user_id': getattr(g, 'current_user_id', None),
                    'ip_address': request.remote_addr if request else None
                })
                raise InputValidationError("Invalid input detected")
        
        # Path traversal check
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                security_logger.critical(f"Path traversal attempt detected", extra={
                    'action': 'PATH_TRAVERSAL_DETECTED',
                    'context': context,
                    'pattern': pattern,
                    'value_hash': hashlib.sha256(value.encode()).hexdigest()[:16],
                    'user_id': getattr(g, 'current_user_id', None),
                    'ip_address': request.remote_addr if request else None
                })
                raise InputValidationError("Invalid input detected")
        
        # Command injection check
        for pattern in self.command_injection_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                security_logger.critical(f"Command injection attempt detected", extra={
                    'action': 'COMMAND_INJECTION_DETECTED',
                    'context': context,
                    'pattern': pattern,
                    'value_hash': hashlib.sha256(value.encode()).hexdigest()[:16],
                    'user_id': getattr(g, 'current_user_id', None),
                    'ip_address': request.remote_addr if request else None
                })
                raise InputValidationError("Invalid input detected")
    
    def validate_file_upload(self, file_obj, allowed_categories: List[str] = None) -> Dict[str, Any]:
        """
        Validate uploaded file for security.
        
        Args:
            file_obj: Flask file object
            allowed_categories: List of allowed file categories
        
        Returns:
            Dictionary with file validation results
        """
        if not file_obj or not file_obj.filename:
            raise InputValidationError("No file uploaded")
        
        filename = file_obj.filename
        file_size = 0
        
        # Read file content for validation
        file_content = file_obj.read()
        file_size = len(file_content)
        file_obj.seek(0)  # Reset file pointer
        
        # File size validation
        max_size = int(os.getenv('MAX_FILE_SIZE', 10 * 1024 * 1024))  # Default 10MB
        if file_size > max_size:
            raise InputValidationError(f"File too large. Maximum size is {max_size // (1024*1024)}MB")
        
        if file_size == 0:
            raise InputValidationError("File is empty")
        
        # Filename validation
        self._validate_filename(filename)
        
        # File extension validation
        file_ext = os.path.splitext(filename)[1].lower()
        if allowed_categories:
            allowed_extensions = set()
            for category in allowed_categories:
                if category in self.allowed_file_extensions:
                    allowed_extensions.update(self.allowed_file_extensions[category])
            
            if file_ext not in allowed_extensions:
                raise InputValidationError(f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}")
        
        # MIME type validation using python-magic
        try:
            mime_type = magic.from_buffer(file_content, mime=True)
            if mime_type not in self.allowed_mime_types:
                security_logger.warning(f"Suspicious file upload: MIME type {mime_type}", extra={
                    'filename': filename,
                    'mime_type': mime_type,
                    'file_size': file_size,
                    'user_id': getattr(g, 'current_user_id', None)
                })
                raise InputValidationError("File type not allowed")
        except Exception as e:
            security_logger.error(f"MIME type detection failed: {e}")
            raise InputValidationError("Could not validate file type")
        
        # Content validation - check for embedded scripts/malware signatures
        content_str = file_content.decode('utf-8', errors='ignore').lower()
        
        # Check for embedded scripts
        script_patterns = [
            r'<script[^>]*>', r'javascript:', r'vbscript:', r'on\w+\s*=',
            r'<%.*?%>', r'<?.*?\?>', r'<\?php', r'<%@', r'<jsp:'
        ]
        
        for pattern in script_patterns:
            if re.search(pattern, content_str):
                security_logger.critical(f"Malicious file upload detected", extra={
                    'filename': filename,
                    'pattern': pattern,
                    'mime_type': mime_type,
                    'user_id': getattr(g, 'current_user_id', None)
                })
                raise InputValidationError("File contains suspicious content")
        
        # Generate secure filename
        secure_filename = self._generate_secure_filename(filename)
        
        return {
            'original_filename': filename,
            'secure_filename': secure_filename,
            'mime_type': mime_type,
            'file_size': file_size,
            'file_extension': file_ext,
            'content_hash': hashlib.sha256(file_content).hexdigest()
        }
    
    def _generate_secure_filename(self, original_filename: str) -> str:
        """Generate a secure filename to prevent conflicts and attacks."""
        import uuid
        import time
        
        # Get file extension
        _, ext = os.path.splitext(original_filename)
        
        # Generate unique filename
        timestamp = int(time.time())
        unique_id = str(uuid.uuid4())[:8]
        
        secure_name = f"{timestamp}_{unique_id}{ext}"
        
        return secure_name
    
    def create_sql_safe_query(self, query_template: str, params: tuple) -> Tuple[str, tuple]:
        """
        Create SQL-safe query with parameterized queries.
        This should be used instead of string concatenation.
        """
        # Validate that the query template doesn't contain user input
        if any(char in query_template for char in ["'", '"'] if not query_template.count(char) % 2 == 0):
            raise InputValidationError("Query template contains unescaped quotes")
        
        # Count placeholders vs parameters
        placeholder_count = query_template.count('?')
        if placeholder_count != len(params):
            raise InputValidationError("Parameter count mismatch")
        
        # Basic SQL injection check on template
        self._check_security_patterns(query_template, 'sql_template')
        
        return query_template, params


# Decorator for input validation
def validate_input(validation_rules: Dict[str, Dict]):
    """Decorator to validate request input based on rules."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            validator = InputValidator()
            
            try:
                # Get input data based on content type
                if request.is_json:
                    input_data = request.get_json() or {}
                elif request.form:
                    input_data = request.form.to_dict()
                else:
                    input_data = request.args.to_dict()
                
                # Validate input
                validated_data = validator.validate_and_sanitize(input_data, validation_rules)
                
                # Store validated data in g for use in route
                g.validated_data = validated_data
                
                return f(*args, **kwargs)
                
            except InputValidationError as e:
                security_logger.warning(f"Input validation failed: {e.message}", extra={
                    'endpoint': request.endpoint,
                    'user_id': getattr(g, 'current_user_id', None),
                    'validation_error': e.message
                })
                
                if request.is_json:
                    return jsonify({
                        'error': 'Invalid input',
                        'message': e.message,
                        'code': e.code
                    }), 400
                else:
                    abort(400)
            
        return decorated_function
    return decorator


# Validation rule templates for common use cases
VALIDATION_RULES = {
    'user_registration': {
        'email': {'type': 'email', 'required': True, 'max_length': 254},
        'password': {'type': 'safe_string', 'required': True, 'min_length': 12, 'max_length': 128},
        'name': {'type': 'safe_string', 'required': True, 'max_length': 100, 'pattern': 'name'},
        'phone': {'type': 'phone', 'required': False}
    },
    
    'job_creation': {
        'title': {'type': 'safe_string', 'required': True, 'max_length': 200},
        'description': {'type': 'html', 'required': True, 'max_length': 5000},
        'company': {'type': 'safe_string', 'required': True, 'max_length': 200},
        'location': {'type': 'safe_string', 'required': False, 'max_length': 200},
        'salary_min': {'type': 'float', 'required': False, 'min_value': 0},
        'salary_max': {'type': 'float', 'required': False, 'min_value': 0},
        'status': {'type': 'choice', 'required': True, 'choices': ['active', 'inactive']}
    },
    
    'candidate_application': {
        'job_id': {'type': 'integer', 'required': True, 'min_value': 1},
        'name': {'type': 'safe_string', 'required': True, 'max_length': 100, 'pattern': 'name'},
        'email': {'type': 'email', 'required': True, 'max_length': 254},
        'phone': {'type': 'phone', 'required': False},
        'cover_letter': {'type': 'html', 'required': False, 'max_length': 2000}
    },
    
    'file_upload': {
        'description': {'type': 'safe_string', 'required': False, 'max_length': 500},
        'category': {'type': 'choice', 'required': False, 'choices': ['resume', 'cover_letter', 'portfolio']}
    }
}

# Global validator instance
validator = InputValidator()
