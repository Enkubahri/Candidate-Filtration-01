"""
Enhanced password security module with strong hashing, validation, and account protection.
Implements Argon2 hashing, complexity requirements, and brute force protection.
"""

import os
import re
import time
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from argon2 import PasswordHasher, exceptions
from argon2.low_level import Type
import sqlite3
from threading import Lock
import json

# Get logger
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')

@dataclass
class PasswordPolicy:
    """Password complexity requirements."""
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    min_special_count: int = 1
    min_digit_count: int = 1
    max_repeated_chars: int = 2
    disallow_common_patterns: bool = True
    disallow_personal_info: bool = True

@dataclass
class AccountLockout:
    """Account lockout configuration."""
    max_attempts: int = 5
    lockout_duration_minutes: int = 30
    progressive_delay: bool = True  # Increase delay with each failed attempt
    permanent_lockout_threshold: int = 10  # Permanent lockout after X failed attempts

class PasswordSecurityManager:
    """Manages password security, hashing, validation, and account protection."""
    
    def __init__(self, db_path: str = None, policy: PasswordPolicy = None, lockout: AccountLockout = None):
        """Initialize password security manager."""
        self.policy = policy or PasswordPolicy()
        self.lockout_config = lockout or AccountLockout()
        self.db_path = db_path or os.getenv('DATABASE_URL', 'candidates.db')
        
        # Initialize Argon2 password hasher with secure parameters
        self.ph = PasswordHasher(
            time_cost=3,      # Number of iterations
            memory_cost=65536,  # Memory usage in KB (64 MB)
            parallelism=1,    # Number of parallel threads
            hash_len=32,      # Length of hash in bytes
            salt_len=16,      # Length of salt in bytes
            encoding='utf-8',
            type=Type.ID      # Argon2id variant (most secure)
        )
        
        # In-memory cache for failed attempts (for performance)
        self._failed_attempts: Dict[str, List[datetime]] = {}
        self._lock = Lock()
        
        # Common weak passwords to reject
        self.common_passwords = self._load_common_passwords()
        
        # Initialize database tables for security tracking
        self._init_security_tables()
    
    def _load_common_passwords(self) -> set:
        """Load common weak passwords to reject."""
        common_passwords = {
            "password", "123456", "123456789", "12345678", "12345", "1234567",
            "password123", "admin", "qwerty", "abc123", "Password1", "password1",
            "welcome", "monkey", "1234567890", "dragon", "master", "login",
            "admin123", "root", "user", "test", "guest", "demo", "sample",
            "letmein", "trustno1", "football", "baseball", "basketball"
        }
        
        # Try to load from file if it exists
        try:
            common_passwords_file = "common_passwords.txt"
            if os.path.exists(common_passwords_file):
                with open(common_passwords_file, 'r', encoding='utf-8') as f:
                    additional_passwords = {line.strip().lower() for line in f if line.strip()}
                    common_passwords.update(additional_passwords)
        except Exception as e:
            security_logger.warning(f"Could not load common passwords file: {e}")
        
        return common_passwords
    
    def _init_security_tables(self):
        """Initialize database tables for security tracking."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Login attempts tracking table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS login_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        ip_address TEXT,
                        attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        success BOOLEAN DEFAULT FALSE,
                        failure_reason TEXT,
                        user_agent TEXT
                    )
                """)
                
                # Account lockouts table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS account_lockouts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        locked_until TIMESTAMP,
                        reason TEXT,
                        is_permanent BOOLEAN DEFAULT FALSE,
                        unlock_token TEXT
                    )
                """)
                
                # Password history table (to prevent reuse)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS password_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                """)
                
                conn.commit()
        except Exception as e:
            security_logger.error(f"Failed to initialize security tables: {e}")
    
    def hash_password(self, password: str) -> str:
        """Hash password using Argon2."""
        try:
            return self.ph.hash(password)
        except Exception as e:
            security_logger.error(f"Password hashing failed: {e}")
            raise
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        try:
            self.ph.verify(hashed, password)
            return True
        except exceptions.VerifyMismatchError:
            return False
        except Exception as e:
            security_logger.error(f"Password verification failed: {e}")
            return False
    
    def needs_rehash(self, hashed: str) -> bool:
        """Check if password hash needs to be updated."""
        try:
            return self.ph.check_needs_rehash(hashed)
        except Exception:
            return True  # Assume old hash format needs rehashing
    
    def validate_password_strength(self, password: str, user_info: Dict = None) -> Tuple[bool, List[str]]:
        """
        Validate password against security policy.
        
        Args:
            password: Password to validate
            user_info: User information dict (username, email, name) for personal info check
        
        Returns:
            Tuple of (is_valid, list_of_error_messages)
        """
        errors = []
        user_info = user_info or {}
        
        # Length check
        if len(password) < self.policy.min_length:
            errors.append(f"Password must be at least {self.policy.min_length} characters long")
        
        if len(password) > self.policy.max_length:
            errors.append(f"Password must be no more than {self.policy.max_length} characters long")
        
        # Character requirements
        if self.policy.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.policy.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.policy.require_digits:
            digit_count = len(re.findall(r'[0-9]', password))
            if digit_count < self.policy.min_digit_count:
                errors.append(f"Password must contain at least {self.policy.min_digit_count} digit(s)")
        
        if self.policy.require_special:
            special_count = len(re.findall(f'[{re.escape(self.policy.special_chars)}]', password))
            if special_count < self.policy.min_special_count:
                errors.append(f"Password must contain at least {self.policy.min_special_count} special character(s) from: {self.policy.special_chars}")
        
        # Repeated characters check
        if self.policy.max_repeated_chars > 0:
            for i in range(len(password) - self.policy.max_repeated_chars):
                if len(set(password[i:i+self.policy.max_repeated_chars+1])) == 1:
                    errors.append(f"Password cannot have more than {self.policy.max_repeated_chars} consecutive identical characters")
                    break
        
        # Common patterns check
        if self.policy.disallow_common_patterns:
            if password.lower() in self.common_passwords:
                errors.append("Password is too common and cannot be used")
            
            # Check for sequential patterns
            if self._has_sequential_pattern(password):
                errors.append("Password cannot contain sequential patterns (e.g., 123, abc)")
            
            # Check for keyboard patterns
            if self._has_keyboard_pattern(password):
                errors.append("Password cannot contain keyboard patterns (e.g., qwerty, asdf)")
        
        # Personal information check
        if self.policy.disallow_personal_info and user_info:
            if self._contains_personal_info(password, user_info):
                errors.append("Password cannot contain personal information")
        
        return len(errors) == 0, errors
    
    def _has_sequential_pattern(self, password: str) -> bool:
        """Check for sequential character patterns."""
        password_lower = password.lower()
        
        # Check for sequential numbers
        for i in range(len(password_lower) - 2):
            if (password_lower[i:i+3].isdigit() and 
                ord(password_lower[i+1]) == ord(password_lower[i]) + 1 and 
                ord(password_lower[i+2]) == ord(password_lower[i+1]) + 1):
                return True
        
        # Check for sequential letters
        for i in range(len(password_lower) - 2):
            if (password_lower[i:i+3].isalpha() and 
                ord(password_lower[i+1]) == ord(password_lower[i]) + 1 and 
                ord(password_lower[i+2]) == ord(password_lower[i+1]) + 1):
                return True
        
        return False
    
    def _has_keyboard_pattern(self, password: str) -> bool:
        """Check for keyboard patterns."""
        keyboard_patterns = [
            "qwerty", "asdf", "zxcv", "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"
        ]
        
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                return True
        
        return False
    
    def _contains_personal_info(self, password: str, user_info: Dict) -> bool:
        """Check if password contains personal information."""
        password_lower = password.lower()
        
        # Check username
        username = user_info.get('username', '').lower()
        if username and len(username) >= 3 and username in password_lower:
            return True
        
        # Check email username part
        email = user_info.get('email', '')
        if email and '@' in email:
            email_username = email.split('@')[0].lower()
            if len(email_username) >= 3 and email_username in password_lower:
                return True
        
        # Check name parts
        name = user_info.get('name', '').lower()
        if name:
            name_parts = name.split()
            for part in name_parts:
                if len(part) >= 3 and part in password_lower:
                    return True
        
        return False
    
    def record_login_attempt(self, username: str, success: bool, ip_address: str = None, 
                           failure_reason: str = None, user_agent: str = None) -> bool:
        """
        Record login attempt and check if account should be locked.
        
        Returns True if login should be allowed, False if account is locked.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Record the attempt
                cursor.execute("""
                    INSERT INTO login_attempts (username, ip_address, success, failure_reason, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, ip_address, success, failure_reason, user_agent))
                
                if success:
                    # Clear failed attempts on successful login
                    self._clear_failed_attempts(username)
                    audit_logger.info(f"Successful login", extra={
                        'action': 'LOGIN_SUCCESS',
                        'username': username,
                        'ip_address': ip_address
                    })
                    return True
                else:
                    # Handle failed attempt
                    return self._handle_failed_login(username, ip_address, failure_reason)
                    
        except Exception as e:
            security_logger.error(f"Failed to record login attempt: {e}")
            return True  # Allow login if we can't record (fail open for availability)
    
    def _handle_failed_login(self, username: str, ip_address: str, failure_reason: str) -> bool:
        """Handle failed login attempt and determine if account should be locked."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Count recent failed attempts
                cutoff_time = datetime.now() - timedelta(hours=1)  # Look at last hour
                cursor.execute("""
                    SELECT COUNT(*) FROM login_attempts 
                    WHERE username = ? AND success = FALSE AND attempt_time > ?
                """, (username, cutoff_time))
                
                failed_count = cursor.fetchone()[0]
                
                security_logger.warning(f"Failed login attempt #{failed_count}", extra={
                    'action': 'LOGIN_FAILED',
                    'username': username,
                    'ip_address': ip_address,
                    'failure_reason': failure_reason,
                    'failed_attempts_count': failed_count
                })
                
                # Check if account should be locked
                if failed_count >= self.lockout_config.max_attempts:
                    return self._lock_account(username, failed_count)
                
                # Progressive delay (optional)
                if self.lockout_config.progressive_delay and failed_count > 1:
                    delay = min(failed_count * 2, 30)  # Max 30 second delay
                    security_logger.info(f"Applying progressive delay: {delay} seconds")
                    time.sleep(delay)
                
                return True  # Allow continued attempts
                
        except Exception as e:
            security_logger.error(f"Failed to handle failed login: {e}")
            return True
    
    def _lock_account(self, username: str, failed_count: int) -> bool:
        """Lock account due to too many failed attempts."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if account is already locked
                cursor.execute("""
                    SELECT locked_until, is_permanent FROM account_lockouts 
                    WHERE username = ? AND (locked_until > datetime('now') OR is_permanent = TRUE)
                    ORDER BY locked_at DESC LIMIT 1
                """, (username,))
                
                existing_lock = cursor.fetchone()
                if existing_lock:
                    return False  # Already locked
                
                # Determine lock duration
                is_permanent = failed_count >= self.lockout_config.permanent_lockout_threshold
                locked_until = None if is_permanent else (
                    datetime.now() + timedelta(minutes=self.lockout_config.lockout_duration_minutes)
                )
                
                # Generate unlock token for manual unlock
                unlock_token = secrets.token_urlsafe(32) if not is_permanent else None
                
                # Insert lockout record
                cursor.execute("""
                    INSERT INTO account_lockouts (username, locked_until, reason, is_permanent, unlock_token)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, locked_until, f"Too many failed login attempts ({failed_count})", 
                     is_permanent, unlock_token))
                
                lockout_type = "PERMANENT" if is_permanent else "TEMPORARY"
                security_logger.critical(f"Account locked: {lockout_type}", extra={
                    'action': 'ACCOUNT_LOCKED',
                    'username': username,
                    'lockout_type': lockout_type,
                    'failed_attempts': failed_count,
                    'locked_until': locked_until.isoformat() if locked_until else None,
                    'unlock_token': unlock_token
                })
                
                return False  # Block login
                
        except Exception as e:
            security_logger.error(f"Failed to lock account: {e}")
            return True  # Fail open
    
    def is_account_locked(self, username: str) -> Tuple[bool, str]:
        """
        Check if account is currently locked.
        
        Returns (is_locked, reason)
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT locked_until, is_permanent, reason FROM account_lockouts 
                    WHERE username = ? AND (locked_until > datetime('now') OR is_permanent = TRUE)
                    ORDER BY locked_at DESC LIMIT 1
                """, (username,))
                
                result = cursor.fetchone()
                if result:
                    locked_until, is_permanent, reason = result
                    if is_permanent:
                        return True, "Account permanently locked. Contact administrator."
                    else:
                        return True, f"Account temporarily locked until {locked_until}. {reason}"
                
                return False, ""
                
        except Exception as e:
            security_logger.error(f"Failed to check account lock status: {e}")
            return False, ""
    
    def unlock_account(self, username: str, unlock_token: str = None, admin_override: bool = False) -> bool:
        """Unlock account with token or admin override."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if admin_override:
                    # Admin override - unlock unconditionally
                    cursor.execute("""
                        DELETE FROM account_lockouts WHERE username = ?
                    """, (username,))
                    
                    security_logger.info(f"Account unlocked by admin", extra={
                        'action': 'ACCOUNT_UNLOCKED',
                        'username': username,
                        'method': 'ADMIN_OVERRIDE'
                    })
                    return True
                
                elif unlock_token:
                    # Token-based unlock
                    cursor.execute("""
                        DELETE FROM account_lockouts 
                        WHERE username = ? AND unlock_token = ?
                    """, (username, unlock_token))
                    
                    if cursor.rowcount > 0:
                        security_logger.info(f"Account unlocked with token", extra={
                            'action': 'ACCOUNT_UNLOCKED',
                            'username': username,
                            'method': 'TOKEN'
                        })
                        return True
                
                return False
                
        except Exception as e:
            security_logger.error(f"Failed to unlock account: {e}")
            return False
    
    def _clear_failed_attempts(self, username: str):
        """Clear failed attempts for successful login."""
        with self._lock:
            if username in self._failed_attempts:
                del self._failed_attempts[username]
    
    def check_password_history(self, user_id: int, new_password: str, history_limit: int = 5) -> bool:
        """Check if password was used recently (prevent reuse)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT password_hash FROM password_history 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (user_id, history_limit))
                
                recent_hashes = cursor.fetchall()
                
                for (old_hash,) in recent_hashes:
                    if self.verify_password(new_password, old_hash):
                        return False  # Password was used recently
                
                return True  # Password is not in recent history
                
        except Exception as e:
            security_logger.error(f"Failed to check password history: {e}")
            return True  # Allow if we can't check
    
    def add_password_to_history(self, user_id: int, password_hash: str):
        """Add password hash to history."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO password_history (user_id, password_hash)
                    VALUES (?, ?)
                """, (user_id, password_hash))
                
                # Clean up old history (keep last 10)
                cursor.execute("""
                    DELETE FROM password_history 
                    WHERE user_id = ? AND id NOT IN (
                        SELECT id FROM password_history 
                        WHERE user_id = ? 
                        ORDER BY created_at DESC 
                        LIMIT 10
                    )
                """, (user_id, user_id))
                
        except Exception as e:
            security_logger.error(f"Failed to add password to history: {e}")
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure password that meets policy requirements."""
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        special = self.policy.special_chars
        
        # Ensure minimum requirements
        password_chars = []
        
        if self.policy.require_uppercase:
            password_chars.append(secrets.choice(uppercase))
        if self.policy.require_lowercase:
            password_chars.append(secrets.choice(lowercase))
        if self.policy.require_digits:
            for _ in range(self.policy.min_digit_count):
                password_chars.append(secrets.choice(digits))
        if self.policy.require_special:
            for _ in range(self.policy.min_special_count):
                password_chars.append(secrets.choice(special))
        
        # Fill remaining length with random chars from all categories
        all_chars = uppercase + lowercase + digits + special
        remaining_length = length - len(password_chars)
        
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(all_chars))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)

# Global instance
password_manager = PasswordSecurityManager()
