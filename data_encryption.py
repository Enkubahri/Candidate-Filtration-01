"""
Data obfuscation and encryption module for comprehensive sensitive data protection.
Implements field-level encryption, PII obfuscation, and data masking for logs and storage.
"""

import os
import re
import hashlib
import secrets
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Union, Pattern
from dataclasses import dataclass
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from functools import wraps
import threading
from contextlib import contextmanager

# Get loggers
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')

@dataclass
class EncryptionConfig:
    """Configuration for encryption settings."""
    algorithm: str = 'Fernet'  # Fernet, AES-GCM
    key_derivation: str = 'PBKDF2'  # PBKDF2, Scrypt
    salt_length: int = 32
    iterations: int = 100000  # For PBKDF2
    memory_cost: int = 2**14  # For Scrypt
    block_size: int = 8  # For Scrypt
    parallelism: int = 1  # For Scrypt

class DataEncryption:
    """Handles sensitive data encryption, decryption, and obfuscation."""
    
    def __init__(self, master_key: bytes = None, config: EncryptionConfig = None):
        """Initialize data encryption manager."""
        self.config = config or EncryptionConfig()
        self.master_key = master_key or self._get_or_create_master_key()
        
        # Encryption instances for different data types
        self._field_ciphers = {}
        self._cipher_lock = threading.Lock()
        
        # PII patterns for detection and obfuscation
        self.pii_patterns = self._build_pii_patterns()
        
        # Field-specific encryption settings
        self.encrypted_fields = {
            'email': {'obfuscate_logs': True, 'encrypt_storage': True},
            'phone': {'obfuscate_logs': True, 'encrypt_storage': True},
            'ssn': {'obfuscate_logs': True, 'encrypt_storage': True},
            'credit_card': {'obfuscate_logs': True, 'encrypt_storage': True},
            'address': {'obfuscate_logs': True, 'encrypt_storage': False},
            'name': {'obfuscate_logs': True, 'encrypt_storage': False},
            'date_of_birth': {'obfuscate_logs': True, 'encrypt_storage': True},
            'ip_address': {'obfuscate_logs': True, 'encrypt_storage': False},
            'user_agent': {'obfuscate_logs': True, 'encrypt_storage': False},
            'session_id': {'obfuscate_logs': True, 'encrypt_storage': False},
            'password': {'obfuscate_logs': True, 'encrypt_storage': False},  # Already hashed
            'api_key': {'obfuscate_logs': True, 'encrypt_storage': True},
            'token': {'obfuscate_logs': True, 'encrypt_storage': True}
        }
        
        security_logger.info("Data encryption system initialized")
    
    def _get_or_create_master_key(self) -> bytes:
        """Get or create master encryption key."""
        key_file = os.path.join(self._get_key_directory(), 'master.key')
        
        if os.path.exists(key_file):
            try:
                with open(key_file, 'rb') as f:
                    key_data = f.read()
                
                # Verify key format
                if len(key_data) == 32:  # Fernet key length
                    test_key = base64.urlsafe_b64encode(key_data)
                    Fernet(test_key)  # Test key validity
                    return test_key
                else:
                    return key_data  # Already base64 encoded
                
            except Exception as e:
                security_logger.error(f"Failed to load master key: {e}")
                # Generate new key if current one is invalid
        
        # Generate new master key
        key = Fernet.generate_key()
        
        try:
            with open(key_file, 'wb') as f:
                f.write(key)
            
            # Set secure permissions
            if os.name != 'nt':
                os.chmod(key_file, 0o600)
            
            security_logger.info("New master encryption key generated")
            return key
            
        except Exception as e:
            security_logger.error(f"Failed to save master key: {e}")
            raise
    
    def _get_key_directory(self) -> str:
        """Get secure directory for encryption keys."""
        key_dir = os.getenv('ENCRYPTION_KEY_DIR')
        
        if not key_dir:
            if os.name == 'nt':  # Windows
                key_dir = os.path.join(os.environ.get('LOCALAPPDATA', 'C:\\'), 'CandidateSystem', 'keys')
            else:  # Unix-like systems
                if os.geteuid() == 0:  # Running as root
                    key_dir = '/var/lib/candidate_system/keys'
                else:
                    key_dir = os.path.expanduser('~/.local/share/candidate_system/keys')
        
        # Create directory with secure permissions
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        
        return key_dir
    
    def _build_pii_patterns(self) -> Dict[str, Pattern]:
        """Build regex patterns for PII detection."""
        return {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            'ip_address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            'api_key': re.compile(r'[\'"]?(?:api[_-]?key|token|secret)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9+/=]{20,})[\'"]?', re.IGNORECASE),
            'session_id': re.compile(r'\b[a-fA-F0-9]{32,}\b'),  # Hex strings 32+ chars
            'uuid': re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'),
            'password': re.compile(r'[\'"]?password[\'"]?\s*[:=]\s*[\'"]?([^\'"\s,}]+)[\'"]?', re.IGNORECASE),
            'date_of_birth': re.compile(r'\b\d{1,2}[/\-]\d{1,2}[/\-]\d{4}\b|\b\d{4}[/\-]\d{1,2}[/\-]\d{1,2}\b')
        }
    
    def get_field_cipher(self, field_name: str, salt: bytes = None) -> Fernet:
        """Get or create cipher for specific field."""
        with self._cipher_lock:
            if field_name not in self._field_ciphers:
                # Generate field-specific key
                field_key = self._derive_field_key(field_name, salt)
                self._field_ciphers[field_name] = Fernet(field_key)
            
            return self._field_ciphers[field_name]
    
    def _derive_field_key(self, field_name: str, salt: bytes = None) -> bytes:
        """Derive field-specific encryption key."""
        if salt is None:
            # Use field name as part of salt for consistent key derivation
            salt = hashlib.sha256(field_name.encode()).digest()[:self.config.salt_length]
        
        if self.config.key_derivation == 'PBKDF2':
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # Fernet key length
                salt=salt,
                iterations=self.config.iterations,
            )
        elif self.config.key_derivation == 'Scrypt':
            kdf = Scrypt(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                n=2**14,  # Memory cost
                r=8,      # Block size
                p=1,      # Parallelism
            )
        else:
            raise ValueError(f"Unsupported key derivation: {self.config.key_derivation}")
        
        key_material = base64.urlsafe_b64decode(self.master_key)
        derived_key = kdf.derive(key_material)
        return base64.urlsafe_b64encode(derived_key)
    
    def encrypt_field(self, field_name: str, value: str, context: Dict[str, Any] = None) -> str:
        """Encrypt sensitive field value."""
        if not value:
            return value
        
        try:
            # Get field-specific cipher
            cipher = self.get_field_cipher(field_name)
            
            # Add metadata for context-aware encryption
            metadata = {
                'field': field_name,
                'timestamp': datetime.utcnow().isoformat(),
                'context': context or {}
            }
            
            # Create payload with metadata and value
            payload = {
                'data': value,
                'meta': metadata
            }
            
            # Encrypt the JSON payload
            payload_json = json.dumps(payload)
            encrypted_data = cipher.encrypt(payload_json.encode('utf-8'))
            
            # Return base64 encoded encrypted data
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            security_logger.error(f"Field encryption failed for {field_name}: {e}")
            raise
    
    def decrypt_field(self, field_name: str, encrypted_value: str) -> str:
        """Decrypt sensitive field value."""
        if not encrypted_value:
            return encrypted_value
        
        try:
            # Get field-specific cipher
            cipher = self.get_field_cipher(field_name)
            
            # Decode base64 and decrypt
            encrypted_data = base64.urlsafe_b64decode(encrypted_value.encode('utf-8'))
            decrypted_json = cipher.decrypt(encrypted_data).decode('utf-8')
            
            # Parse JSON payload
            payload = json.loads(decrypted_json)
            
            # Return original data
            return payload['data']
            
        except Exception as e:
            security_logger.error(f"Field decryption failed for {field_name}: {e}")
            raise
    
    def obfuscate_pii_in_text(self, text: str, preserve_format: bool = True) -> str:
        """Obfuscate PII in text using pattern matching."""
        if not text:
            return text
        
        obfuscated_text = text
        
        # Apply obfuscation patterns
        for pii_type, pattern in self.pii_patterns.items():
            if pii_type == 'email':
                obfuscated_text = self._obfuscate_email(obfuscated_text, pattern, preserve_format)
            elif pii_type == 'phone':
                obfuscated_text = self._obfuscate_phone(obfuscated_text, pattern, preserve_format)
            elif pii_type == 'ssn':
                obfuscated_text = pattern.sub('***-**-****', obfuscated_text)
            elif pii_type == 'credit_card':
                obfuscated_text = self._obfuscate_credit_card(obfuscated_text, pattern, preserve_format)
            elif pii_type == 'ip_address':
                obfuscated_text = self._obfuscate_ip_address(obfuscated_text, pattern, preserve_format)
            elif pii_type == 'api_key':
                obfuscated_text = pattern.sub(r'\1***', obfuscated_text)
            elif pii_type == 'session_id':
                obfuscated_text = self._obfuscate_session_id(obfuscated_text, pattern)
            elif pii_type == 'uuid':
                obfuscated_text = pattern.sub('********-****-****-****-************', obfuscated_text)
            elif pii_type == 'password':
                obfuscated_text = pattern.sub(r'\1***', obfuscated_text)
            elif pii_type == 'date_of_birth':
                obfuscated_text = pattern.sub('**/**/****', obfuscated_text)
        
        return obfuscated_text
    
    def _obfuscate_email(self, text: str, pattern: Pattern, preserve_format: bool) -> str:
        """Obfuscate email addresses."""
        def replace_email(match):
            email = match.group()
            if '@' in email:
                username, domain = email.split('@', 1)
                if preserve_format:
                    # Show first and last character of username
                    if len(username) <= 2:
                        masked_username = '*' * len(username)
                    else:
                        masked_username = username[0] + '*' * (len(username) - 2) + username[-1]
                    return f"{masked_username}@{domain}"
                else:
                    return "***@" + domain
            return "***@***.***"
        
        return pattern.sub(replace_email, text)
    
    def _obfuscate_phone(self, text: str, pattern: Pattern, preserve_format: bool) -> str:
        """Obfuscate phone numbers."""
        if preserve_format:
            return pattern.sub(lambda m: re.sub(r'\d', '*', m.group()), text)
        else:
            return pattern.sub('***-***-****', text)
    
    def _obfuscate_credit_card(self, text: str, pattern: Pattern, preserve_format: bool) -> str:
        """Obfuscate credit card numbers."""
        def replace_card(match):
            card = match.group()
            if preserve_format:
                # Show last 4 digits
                digits = re.findall(r'\d', card)
                if len(digits) >= 4:
                    masked_digits = ['*'] * (len(digits) - 4) + digits[-4:]
                    result = card
                    digit_idx = 0
                    for i, char in enumerate(card):
                        if char.isdigit():
                            result = result[:i] + masked_digits[digit_idx] + result[i+1:]
                            digit_idx += 1
                    return result
            return '****-****-****-****'
        
        return pattern.sub(replace_card, text)
    
    def _obfuscate_ip_address(self, text: str, pattern: Pattern, preserve_format: bool) -> str:
        """Obfuscate IP addresses."""
        def replace_ip(match):
            ip = match.group()
            if preserve_format:
                # Keep first octet, mask others
                parts = ip.split('.')
                if len(parts) == 4:
                    return f"{parts[0]}.***.***.***"
            return "***.***.***.***"
        
        return pattern.sub(replace_ip, text)
    
    def _obfuscate_session_id(self, text: str, pattern: Pattern) -> str:
        """Obfuscate session IDs and similar hex strings."""
        def replace_session(match):
            session_id = match.group()
            # Show first 8 and last 4 characters for identification
            if len(session_id) > 12:
                return session_id[:8] + '*' * (len(session_id) - 12) + session_id[-4:]
            else:
                return '*' * len(session_id)
        
        return pattern.sub(replace_session, text)
    
    def create_data_mask(self, data: Dict[str, Any], mask_rules: Dict[str, str] = None) -> Dict[str, Any]:
        """Create masked version of data for logging/display."""
        if not data:
            return data
        
        masked_data = {}
        default_mask_rules = mask_rules or {}
        
        for key, value in data.items():
            field_config = self.encrypted_fields.get(key.lower())
            
            if field_config and field_config.get('obfuscate_logs', False):
                # Apply field-specific masking
                if key.lower() in default_mask_rules:
                    masked_data[key] = default_mask_rules[key.lower()]
                else:
                    masked_data[key] = self._mask_field_value(key, value)
            else:
                # Check if value contains PII patterns
                if isinstance(value, str):
                    masked_data[key] = self.obfuscate_pii_in_text(value)
                else:
                    masked_data[key] = value
        
        return masked_data
    
    def _mask_field_value(self, field_name: str, value: Any) -> str:
        """Apply field-specific masking rules."""
        if not value:
            return str(value) if value is not None else None
        
        value_str = str(value)
        field_lower = field_name.lower()
        
        if field_lower in ['password', 'secret', 'key']:
            return '***'
        elif field_lower in ['email']:
            return self._obfuscate_email(value_str, self.pii_patterns['email'], True)
        elif field_lower in ['phone', 'telephone']:
            return self._obfuscate_phone(value_str, self.pii_patterns['phone'], True)
        elif field_lower in ['ssn', 'social_security']:
            return '***-**-****'
        elif field_lower in ['credit_card', 'card_number']:
            return '****-****-****-' + value_str[-4:] if len(value_str) >= 4 else '****'
        elif field_lower in ['ip_address', 'remote_addr']:
            return self._obfuscate_ip_address(value_str, self.pii_patterns['ip_address'], True)
        elif len(value_str) > 10:
            # Long strings - show first and last few characters
            return value_str[:4] + '*' * (len(value_str) - 8) + value_str[-4:]
        else:
            # Short strings - partial masking
            return value_str[:1] + '*' * (len(value_str) - 1)
    
    def encrypt_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive fields in data dictionary."""
        encrypted_data = data.copy()
        
        for field_name, value in data.items():
            field_config = self.encrypted_fields.get(field_name.lower())
            
            if field_config and field_config.get('encrypt_storage', False) and value:
                try:
                    encrypted_data[field_name] = self.encrypt_field(field_name, str(value))
                except Exception as e:
                    security_logger.error(f"Failed to encrypt field {field_name}: {e}")
                    # Keep original value if encryption fails
                    encrypted_data[field_name] = value
        
        return encrypted_data
    
    def decrypt_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive fields in data dictionary."""
        decrypted_data = data.copy()
        
        for field_name, value in data.items():
            field_config = self.encrypted_fields.get(field_name.lower())
            
            if field_config and field_config.get('encrypt_storage', False) and value:
                try:
                    decrypted_data[field_name] = self.decrypt_field(field_name, str(value))
                except Exception as e:
                    security_logger.error(f"Failed to decrypt field {field_name}: {e}")
                    # Keep encrypted value if decryption fails
                    decrypted_data[field_name] = value
        
        return decrypted_data
    
    def generate_field_hash(self, field_name: str, value: str) -> str:
        """Generate searchable hash for encrypted field."""
        if not value:
            return value
        
        # Use field-specific salt for consistent hashing
        salt = hashlib.sha256(field_name.encode()).digest()[:16]
        
        # Create HMAC hash for searchability
        key_material = base64.urlsafe_b64decode(self.master_key)[:32]
        
        import hmac
        field_hash = hmac.new(
            key_material + salt,
            value.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return field_hash[:32]  # Truncate for storage efficiency
    
    def secure_delete_key(self, field_name: str):
        """Securely delete field-specific encryption key."""
        with self._cipher_lock:
            if field_name in self._field_ciphers:
                del self._field_ciphers[field_name]
        
        security_logger.info(f"Encryption key deleted for field: {field_name}")
    
    def rotate_encryption_keys(self, fields: List[str] = None):
        """Rotate encryption keys for specified fields or all fields."""
        with self._cipher_lock:
            if fields:
                for field in fields:
                    if field in self._field_ciphers:
                        del self._field_ciphers[field]
            else:
                self._field_ciphers.clear()
        
        security_logger.info(f"Encryption keys rotated for fields: {fields or 'all'}")
        audit_logger.info("Encryption key rotation completed", extra={
            'action': 'KEY_ROTATION',
            'fields': fields or 'all',
            'timestamp': datetime.utcnow().isoformat()
        })


# Context manager for data encryption
@contextmanager
def encrypted_data_context(data_encryption: DataEncryption):
    """Context manager for handling encrypted data operations."""
    try:
        yield data_encryption
    except Exception as e:
        security_logger.error(f"Encrypted data operation failed: {e}")
        raise
    finally:
        # Cleanup sensitive data from memory if needed
        pass


# Decorator for automatic data encryption/decryption
def encrypt_sensitive_fields(*field_names):
    """Decorator to automatically encrypt specified fields in function arguments."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import current_app
            
            data_encryption = getattr(current_app, 'data_encryption', None)
            if not data_encryption:
                return f(*args, **kwargs)
            
            # Encrypt specified fields in kwargs
            for field_name in field_names:
                if field_name in kwargs and kwargs[field_name]:
                    try:
                        kwargs[field_name] = data_encryption.encrypt_field(
                            field_name, str(kwargs[field_name])
                        )
                    except Exception as e:
                        security_logger.error(f"Auto-encryption failed for {field_name}: {e}")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def obfuscate_logs(f):
    """Decorator to automatically obfuscate PII in log messages."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        
        try:
            result = f(*args, **kwargs)
            
            # Obfuscate any logged data
            data_encryption = getattr(current_app, 'data_encryption', None)
            if data_encryption and hasattr(threading.current_thread(), 'log_data'):
                log_data = threading.current_thread().log_data
                if isinstance(log_data, dict):
                    threading.current_thread().log_data = data_encryption.create_data_mask(log_data)
                elif isinstance(log_data, str):
                    threading.current_thread().log_data = data_encryption.obfuscate_pii_in_text(log_data)
            
            return result
        except Exception as e:
            security_logger.error(f"Function execution failed: {e}")
            raise
    return decorated_function


# Flask app integration
def init_data_encryption(app, master_key: bytes = None, config: EncryptionConfig = None) -> DataEncryption:
    """Initialize data encryption for Flask application."""
    
    data_encryption = DataEncryption(master_key, config)
    app.data_encryption = data_encryption
    
    # Set up logging filter for PII obfuscation
    class PIIObfuscationFilter(logging.Filter):
        def filter(self, record):
            if hasattr(record, 'msg') and isinstance(record.msg, str):
                record.msg = data_encryption.obfuscate_pii_in_text(record.msg)
            
            if hasattr(record, 'args') and record.args:
                filtered_args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        filtered_args.append(data_encryption.obfuscate_pii_in_text(arg))
                    elif isinstance(arg, dict):
                        filtered_args.append(data_encryption.create_data_mask(arg))
                    else:
                        filtered_args.append(arg)
                record.args = tuple(filtered_args)
            
            return True
    
    # Add PII obfuscation filter to all loggers
    pii_filter = PIIObfuscationFilter()
    
    # Apply to main application loggers
    for logger_name in ['security', 'audit', 'application', 'errors']:
        logger = logging.getLogger(logger_name)
        logger.addFilter(pii_filter)
    
    security_logger.info("Data encryption and PII obfuscation initialized")
    return data_encryption


# Global data encryption instance
data_encryption = None
