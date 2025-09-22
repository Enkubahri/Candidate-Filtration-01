"""
Database security module with encryption, secure connections, and backup protection.
Implements database encryption, secure connection management, and encrypted backups.
"""

import os
import sqlite3
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from contextlib import contextmanager
from pathlib import Path
import shutil
import json
import zipfile
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import threading
from functools import wraps

# Get loggers
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')

class DatabaseSecurity:
    """Handles database security, encryption, and secure operations."""
    
    def __init__(self, db_path: str = None, encryption_key: bytes = None):
        """Initialize database security manager."""
        self.original_db_path = db_path or os.getenv('DATABASE_URL', 'candidates.db')
        self.secure_db_dir = self._get_secure_db_directory()
        self.secure_db_path = os.path.join(self.secure_db_dir, 'candidates_secure.db')
        
        # Encryption setup
        self.encryption_key = encryption_key or self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Connection pool settings
        self.max_connections = int(os.getenv('DB_MAX_CONNECTIONS', '10'))
        self.connection_timeout = int(os.getenv('DB_CONNECTION_TIMEOUT', '30'))
        self._connection_pool = []
        self._pool_lock = threading.Lock()
        
        # Backup settings
        self.backup_dir = os.path.join(self.secure_db_dir, 'backups')
        self.backup_retention_days = int(os.getenv('DB_BACKUP_RETENTION_DAYS', '30'))
        self.backup_encryption_enabled = os.getenv('DB_BACKUP_ENCRYPTION', 'True').lower() == 'true'
        
        # Initialize secure database environment
        self._setup_secure_database_environment()
        
    def _get_secure_db_directory(self) -> str:
        """Get or create secure database directory."""
        # Use environment variable or create secure location
        secure_dir = os.getenv('SECURE_DB_DIR')
        
        if not secure_dir:
            if os.name == 'nt':  # Windows
                # Use LOCALAPPDATA for Windows
                secure_dir = os.path.join(os.environ.get('LOCALAPPDATA', 'C:\\'), 'CandidateSystem', 'secure_db')
            else:  # Unix-like systems
                # Use /var/lib for system-wide or ~/.local/share for user-specific
                if os.geteuid() == 0:  # Running as root
                    secure_dir = '/var/lib/candidate_system/db'
                else:
                    secure_dir = os.path.expanduser('~/.local/share/candidate_system/db')
        
        # Create directory with secure permissions
        os.makedirs(secure_dir, mode=0o700, exist_ok=True)
        
        # Set secure permissions on Windows
        if os.name == 'nt':
            try:
                import win32security
                import win32api
                import ntsecuritycon as con
                
                # Get current user SID
                user_sid = win32security.GetFileSecurity(
                    secure_dir, win32security.OWNER_SECURITY_INFORMATION
                ).GetSecurityDescriptorOwner()
                
                # Create DACL with only current user access
                dacl = win32security.ACL()
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    con.FILE_ALL_ACCESS,
                    user_sid
                )
                
                # Apply security descriptor
                sd = win32security.SECURITY_DESCRIPTOR()
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(
                    secure_dir, win32security.DACL_SECURITY_INFORMATION, sd
                )
            except ImportError:
                security_logger.warning("win32security not available for setting Windows permissions")
        
        security_logger.info(f"Secure database directory: {secure_dir}")
        return secure_dir
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create database encryption key."""
        key_file = os.path.join(self.secure_db_dir, '.db_key')
        
        if os.path.exists(key_file):
            try:
                with open(key_file, 'rb') as f:
                    key = f.read()
                # Verify key format
                Fernet(key)  # This will raise exception if invalid
                security_logger.info("Database encryption key loaded")
                return key
            except Exception as e:
                security_logger.error(f"Failed to load encryption key: {e}")
                # Generate new key if current one is invalid
        
        # Generate new encryption key
        key = Fernet.generate_key()
        
        try:
            with open(key_file, 'wb') as f:
                f.write(key)
            
            # Set secure permissions on key file
            if os.name != 'nt':  # Unix-like systems
                os.chmod(key_file, 0o600)
            
            security_logger.info("New database encryption key generated")
            
        except Exception as e:
            security_logger.error(f"Failed to save encryption key: {e}")
            raise
        
        return key
    
    def _setup_secure_database_environment(self):
        """Set up secure database environment."""
        try:
            # Create backup directory
            os.makedirs(self.backup_dir, mode=0o700, exist_ok=True)
            
            # Move existing database to secure location if needed
            if os.path.exists(self.original_db_path) and not os.path.exists(self.secure_db_path):
                self._migrate_database_to_secure_location()
            
            # Initialize database with security extensions
            self._initialize_secure_database()
            
            security_logger.info("Secure database environment initialized")
            
        except Exception as e:
            security_logger.error(f"Failed to setup secure database environment: {e}")
            raise
    
    def _migrate_database_to_secure_location(self):
        """Migrate existing database to secure location."""
        try:
            security_logger.info(f"Migrating database from {self.original_db_path} to {self.secure_db_path}")
            
            # Create backup of original database
            backup_path = f"{self.original_db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.original_db_path, backup_path)
            
            # Copy to secure location
            shutil.copy2(self.original_db_path, self.secure_db_path)
            
            # Set secure permissions
            if os.name != 'nt':
                os.chmod(self.secure_db_path, 0o600)
            
            security_logger.info("Database migration completed successfully")
            
            # Log migration for audit
            audit_logger.info("Database migrated to secure location", extra={
                'action': 'DATABASE_MIGRATION',
                'original_path': self.original_db_path,
                'secure_path': self.secure_db_path,
                'backup_path': backup_path
            })
            
        except Exception as e:
            security_logger.error(f"Database migration failed: {e}")
            raise
    
    def _initialize_secure_database(self):
        """Initialize database with security configurations."""
        try:
            with self.get_secure_connection() as conn:
                cursor = conn.cursor()
                
                # Enable WAL mode for better concurrency and crash resistance
                cursor.execute("PRAGMA journal_mode=WAL")
                
                # Enable foreign key constraints
                cursor.execute("PRAGMA foreign_keys=ON")
                
                # Set secure temp store
                cursor.execute("PRAGMA temp_store=MEMORY")
                
                # Set synchronous mode for durability
                cursor.execute("PRAGMA synchronous=FULL")
                
                # Enable query planner stability
                cursor.execute("PRAGMA query_only=OFF")
                
                # Create security audit table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS security_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        event_type TEXT NOT NULL,
                        table_name TEXT,
                        record_id TEXT,
                        user_id INTEGER,
                        ip_address TEXT,
                        operation TEXT,
                        old_values TEXT,
                        new_values TEXT,
                        success BOOLEAN DEFAULT TRUE
                    )
                """)
                
                # Create database integrity checks table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS integrity_checks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        check_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        table_name TEXT NOT NULL,
                        record_count INTEGER,
                        checksum TEXT,
                        status TEXT DEFAULT 'OK'
                    )
                """)
                
                conn.commit()
                
        except Exception as e:
            security_logger.error(f"Failed to initialize secure database: {e}")
            raise
    
    @contextmanager
    def get_secure_connection(self, read_only: bool = False):
        """Get a secure database connection with proper configuration."""
        conn = None
        try:
            # Configure connection
            conn = sqlite3.connect(
                self.secure_db_path,
                timeout=self.connection_timeout,
                isolation_level='DEFERRED' if not read_only else None
            )
            
            # Set secure connection options
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA temp_store=MEMORY")
            
            if read_only:
                conn.execute("PRAGMA query_only=ON")
            
            # Row factory for better data handling
            conn.row_factory = sqlite3.Row
            
            yield conn
            
        except Exception as e:
            if conn:
                conn.rollback()
            security_logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def encrypt_sensitive_field(self, value: str) -> str:
        """Encrypt sensitive field value."""
        if not value:
            return value
        
        try:
            encrypted_bytes = self.cipher_suite.encrypt(value.encode('utf-8'))
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        except Exception as e:
            security_logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_sensitive_field(self, encrypted_value: str) -> str:
        """Decrypt sensitive field value."""
        if not encrypted_value:
            return encrypted_value
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_value.encode('utf-8'))
            decrypted_bytes = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            security_logger.error(f"Decryption failed: {e}")
            raise
    
    def create_encrypted_backup(self, backup_name: str = None) -> str:
        """Create encrypted database backup."""
        try:
            if not backup_name:
                backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            
            backup_path = os.path.join(self.backup_dir, backup_name)
            
            # Create database backup
            with self.get_secure_connection(read_only=True) as conn:
                # Use VACUUM INTO for clean backup
                conn.execute(f"VACUUM INTO ?", (backup_path,))
            
            # Encrypt backup if encryption is enabled
            if self.backup_encryption_enabled:
                encrypted_backup_path = f"{backup_path}.encrypted"
                
                with open(backup_path, 'rb') as infile:
                    plaintext_data = infile.read()
                
                encrypted_data = self.cipher_suite.encrypt(plaintext_data)
                
                with open(encrypted_backup_path, 'wb') as outfile:
                    outfile.write(encrypted_data)
                
                # Remove unencrypted backup
                os.remove(backup_path)
                backup_path = encrypted_backup_path
            
            # Set secure permissions
            if os.name != 'nt':
                os.chmod(backup_path, 0o600)
            
            security_logger.info(f"Database backup created: {backup_path}")
            
            # Log backup creation
            audit_logger.info("Database backup created", extra={
                'action': 'DATABASE_BACKUP_CREATED',
                'backup_path': backup_path,
                'encrypted': self.backup_encryption_enabled
            })
            
            return backup_path
            
        except Exception as e:
            security_logger.error(f"Database backup failed: {e}")
            raise
    
    def restore_from_backup(self, backup_path: str) -> bool:
        """Restore database from encrypted backup."""
        try:
            if not os.path.exists(backup_path):
                raise FileNotFoundError(f"Backup file not found: {backup_path}")
            
            # Create backup of current database
            current_backup = self.create_encrypted_backup(
                f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            )
            
            try:
                temp_restore_path = f"{self.secure_db_path}.restore_temp"
                
                # Decrypt backup if encrypted
                if backup_path.endswith('.encrypted'):
                    with open(backup_path, 'rb') as infile:
                        encrypted_data = infile.read()
                    
                    decrypted_data = self.cipher_suite.decrypt(encrypted_data)
                    
                    with open(temp_restore_path, 'wb') as outfile:
                        outfile.write(decrypted_data)
                else:
                    shutil.copy2(backup_path, temp_restore_path)
                
                # Verify backup integrity
                if self._verify_database_integrity(temp_restore_path):
                    # Replace current database
                    shutil.move(temp_restore_path, self.secure_db_path)
                    
                    security_logger.info(f"Database restored from backup: {backup_path}")
                    
                    audit_logger.info("Database restored from backup", extra={
                        'action': 'DATABASE_RESTORE',
                        'backup_path': backup_path,
                        'pre_restore_backup': current_backup
                    })
                    
                    return True
                else:
                    os.remove(temp_restore_path)
                    raise ValueError("Backup file integrity check failed")
                    
            except Exception as e:
                # Restore from current backup if something goes wrong
                security_logger.error(f"Restore failed, keeping current database: {e}")
                raise
            
        except Exception as e:
            security_logger.error(f"Database restore failed: {e}")
            return False
    
    def _verify_database_integrity(self, db_path: str = None) -> bool:
        """Verify database integrity."""
        try:
            check_db_path = db_path or self.secure_db_path
            
            with sqlite3.connect(check_db_path) as conn:
                cursor = conn.cursor()
                
                # Check database integrity
                cursor.execute("PRAGMA integrity_check")
                result = cursor.fetchone()
                
                if result[0] != 'ok':
                    security_logger.error(f"Database integrity check failed: {result[0]}")
                    return False
                
                # Check foreign key constraints
                cursor.execute("PRAGMA foreign_key_check")
                fk_violations = cursor.fetchall()
                
                if fk_violations:
                    security_logger.error(f"Foreign key violations found: {len(fk_violations)}")
                    return False
                
                return True
                
        except Exception as e:
            security_logger.error(f"Database integrity check failed: {e}")
            return False
    
    def cleanup_old_backups(self):
        """Clean up old backup files."""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.backup_retention_days)
            deleted_count = 0
            
            for backup_file in os.listdir(self.backup_dir):
                backup_path = os.path.join(self.backup_dir, backup_file)
                
                if os.path.isfile(backup_path):
                    file_stat = os.stat(backup_path)
                    file_date = datetime.fromtimestamp(file_stat.st_mtime)
                    
                    if file_date < cutoff_date:
                        os.remove(backup_path)
                        deleted_count += 1
                        security_logger.info(f"Deleted old backup: {backup_file}")
            
            if deleted_count > 0:
                security_logger.info(f"Cleaned up {deleted_count} old backup files")
            
        except Exception as e:
            security_logger.error(f"Backup cleanup failed: {e}")
    
    def perform_integrity_check(self) -> Dict[str, Any]:
        """Perform comprehensive database integrity check."""
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'OK',
                'checks': []
            }
            
            with self.get_secure_connection(read_only=True) as conn:
                cursor = conn.cursor()
                
                # Basic integrity check
                cursor.execute("PRAGMA integrity_check")
                integrity_result = cursor.fetchone()[0]
                results['checks'].append({
                    'check': 'database_integrity',
                    'status': 'OK' if integrity_result == 'ok' else 'FAILED',
                    'details': integrity_result
                })
                
                # Foreign key check
                cursor.execute("PRAGMA foreign_key_check")
                fk_violations = cursor.fetchall()
                results['checks'].append({
                    'check': 'foreign_keys',
                    'status': 'OK' if not fk_violations else 'FAILED',
                    'details': f"{len(fk_violations)} violations found" if fk_violations else 'No violations'
                })
                
                # Check table record counts and checksums
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                
                for table_row in tables:
                    table_name = table_row[0]
                    if table_name.startswith('sqlite_'):
                        continue
                    
                    # Count records
                    cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                    count = cursor.fetchone()[0]
                    
                    # Calculate simple checksum (sum of rowids)
                    try:
                        cursor.execute(f"SELECT SUM(rowid) FROM {table_name}")
                        checksum = cursor.fetchone()[0] or 0
                    except:
                        checksum = 0
                    
                    # Store integrity check result
                    cursor.execute("""
                        INSERT INTO integrity_checks (table_name, record_count, checksum)
                        VALUES (?, ?, ?)
                    """, (table_name, count, str(checksum)))
                    
                    results['checks'].append({
                        'check': f'table_{table_name}',
                        'status': 'OK',
                        'details': f'{count} records, checksum: {checksum}'
                    })
                
                conn.commit()
            
            # Set overall status
            failed_checks = [check for check in results['checks'] if check['status'] == 'FAILED']
            if failed_checks:
                results['overall_status'] = 'FAILED'
            
            security_logger.info(f"Database integrity check completed: {results['overall_status']}")
            
            return results
            
        except Exception as e:
            security_logger.error(f"Database integrity check failed: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'ERROR',
                'error': str(e)
            }
    
    def log_database_operation(self, operation: str, table_name: str = None, 
                             record_id: str = None, user_id: int = None,
                             old_values: Dict = None, new_values: Dict = None):
        """Log database operation for audit trail."""
        try:
            with self.get_secure_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO security_audit 
                    (event_type, table_name, record_id, user_id, ip_address, 
                     operation, old_values, new_values)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    'DATABASE_OPERATION',
                    table_name,
                    str(record_id) if record_id else None,
                    user_id,
                    getattr(threading.current_thread(), 'ip_address', None),
                    operation,
                    json.dumps(old_values) if old_values else None,
                    json.dumps(new_values) if new_values else None
                ))
                
                conn.commit()
                
        except Exception as e:
            security_logger.error(f"Failed to log database operation: {e}")


# Decorator for secure database operations
def secure_db_operation(operation_type: str = None, table_name: str = None):
    """Decorator to log and secure database operations."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            operation = operation_type or f.__name__
            
            try:
                # Execute the function
                result = f(*args, **kwargs)
                
                # Log successful operation
                if hasattr(threading.current_thread(), 'db_security'):
                    db_security = threading.current_thread().db_security
                    db_security.log_database_operation(
                        operation=operation,
                        table_name=table_name,
                        user_id=getattr(threading.current_thread(), 'user_id', None)
                    )
                
                return result
                
            except Exception as e:
                security_logger.error(f"Database operation failed: {operation}: {e}")
                raise
                
        return decorated_function
    return decorator


# Database connection manager
class SecureDatabaseManager:
    """Manages secure database connections and operations."""
    
    def __init__(self, db_security: DatabaseSecurity):
        self.db_security = db_security
        self._local = threading.local()
    
    @contextmanager
    def get_connection(self, read_only: bool = False):
        """Get a secure database connection."""
        with self.db_security.get_secure_connection(read_only=read_only) as conn:
            # Set connection in thread local storage
            self._local.connection = conn
            try:
                yield conn
            finally:
                if hasattr(self._local, 'connection'):
                    delattr(self._local, 'connection')
    
    def execute_secure_query(self, query: str, params: tuple = (), 
                           fetch_one: bool = False, fetch_all: bool = False) -> Any:
        """Execute a secure parameterized query."""
        try:
            if hasattr(self._local, 'connection'):
                conn = self._local.connection
            else:
                raise RuntimeError("No active database connection")
            
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            if fetch_one:
                return cursor.fetchone()
            elif fetch_all:
                return cursor.fetchall()
            else:
                conn.commit()
                return cursor.rowcount
                
        except Exception as e:
            security_logger.error(f"Secure query execution failed: {e}")
            raise


# Global database security instance
db_security = None

def init_database_security(db_path: str = None, encryption_key: bytes = None) -> DatabaseSecurity:
    """Initialize database security."""
    global db_security
    db_security = DatabaseSecurity(db_path, encryption_key)
    security_logger.info("Database security initialized")
    return db_security
