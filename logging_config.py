"""
Production-ready logging configuration with security and audit logging.
Implements structured logging with sensitive data obfuscation.
"""

import os
import re
import logging
import logging.handlers
from datetime import datetime
from typing import Dict, Any
from pythonjsonlogger import jsonlogger

class SensitiveDataFilter(logging.Filter):
    """Filter to obfuscate sensitive data in log messages."""
    
    SENSITIVE_PATTERNS = [
        # Email addresses - keep domain but obfuscate username
        (r'\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', 
         lambda m: f"***@{m.group(2)}"),
        
        # Phone numbers
        (r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b', 
         '***-***-****'),
        
        # Social Security Numbers
        (r'\b\d{3}-\d{2}-\d{4}\b', '***-**-****'),
        
        # Credit Card Numbers
        (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '****-****-****-****'),
        
        # Password fields
        (r'(password["\']?\s*[:=]\s*["\']?)([^"\',\s]+)', r'\1***'),
        
        # API Keys and tokens
        (r'([\'"]?(?:api[_-]?key|token|secret)[\'"]?\s*[:=]\s*[\'"]?)([a-zA-Z0-9+/=]{10,})', r'\1***'),
        
        # Database credentials
        (r'(sqlite:///[^/]*/)([^/\s]+)', r'\1***'),
        
        # IP addresses - partially obfuscate
        (r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b', r'\1***'),
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter log record to obfuscate sensitive data."""
        if hasattr(record, 'msg'):
            message = str(record.msg)
            for pattern, replacement in self.SENSITIVE_PATTERNS:
                if callable(replacement):
                    message = re.sub(pattern, replacement, message)
                else:
                    message = re.sub(pattern, replacement, message)
            record.msg = message
        
        # Also filter arguments
        if hasattr(record, 'args') and record.args:
            filtered_args = []
            for arg in record.args:
                arg_str = str(arg)
                for pattern, replacement in self.SENSITIVE_PATTERNS:
                    if callable(replacement):
                        arg_str = re.sub(pattern, replacement, arg_str)
                    else:
                        arg_str = re.sub(pattern, replacement, arg_str)
                filtered_args.append(arg_str)
            record.args = tuple(filtered_args)
        
        return True

class SecurityFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter for security logs."""
    
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]):
        """Add security-specific fields to log record."""
        super().add_fields(log_record, record, message_dict)
        
        # Add timestamp in ISO format
        log_record['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Add security context
        log_record['logger_name'] = record.name
        log_record['level'] = record.levelname
        log_record['thread_id'] = record.thread
        log_record['process_id'] = record.process
        
        # Add application context if available
        try:
            from flask import request, session, g
            if request:
                log_record['request_id'] = getattr(request, 'id', None)
                log_record['endpoint'] = request.endpoint
                log_record['method'] = request.method
                log_record['path'] = request.path
                log_record['remote_addr'] = request.remote_addr
                log_record['user_agent'] = request.headers.get('User-Agent', '')[:200]  # Truncate
                
            if session:
                log_record['session_id'] = session.get('_id', '')
                
            if hasattr(g, 'current_user_id'):
                log_record['user_id'] = g.current_user_id
                
        except (RuntimeError, ImportError):
            # Outside of Flask request context or Flask not available
            pass

def setup_logging(app=None):
    """Set up production-ready logging configuration."""
    
    # Create logs directory
    log_dir = os.getenv('LOG_DIR', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Security logs directory
    security_log_dir = os.path.join(log_dir, 'security')
    os.makedirs(security_log_dir, exist_ok=True)
    
    # Get log level from environment
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level))
    
    # Remove default handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create sensitive data filter
    sensitive_filter = SensitiveDataFilter()
    
    # ==========================
    # APPLICATION LOGGER
    # ==========================
    app_log_file = os.path.join(log_dir, 'application.log')
    
    # Rotating file handler for application logs
    app_handler = logging.handlers.RotatingFileHandler(
        app_log_file,
        maxBytes=50 * 1024 * 1024,  # 50MB
        backupCount=10,
        encoding='utf-8'
    )
    app_handler.setLevel(getattr(logging, log_level))
    
    # JSON formatter for application logs
    app_formatter = jsonlogger.JsonFormatter(
        '%(timestamp)s %(name)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    app_handler.setFormatter(app_formatter)
    app_handler.addFilter(sensitive_filter)
    
    # Add to root logger
    root_logger.addHandler(app_handler)
    
    # ==========================
    # SECURITY LOGGER
    # ==========================
    security_log_file = os.path.join(security_log_dir, 'security.log')
    
    security_logger = logging.getLogger('security')
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False  # Don't propagate to root logger
    
    # Rotating file handler for security logs
    security_handler = logging.handlers.RotatingFileHandler(
        security_log_file,
        maxBytes=100 * 1024 * 1024,  # 100MB
        backupCount=20,
        encoding='utf-8'
    )
    security_handler.setLevel(logging.INFO)
    
    # Security-specific formatter
    security_formatter = SecurityFormatter(
        '%(timestamp)s %(levelname)s %(message)s'
    )
    security_handler.setFormatter(security_formatter)
    security_handler.addFilter(sensitive_filter)
    
    security_logger.addHandler(security_handler)
    
    # ==========================
    # AUDIT LOGGER
    # ==========================
    audit_log_file = os.path.join(security_log_dir, 'audit.log')
    
    audit_logger = logging.getLogger('audit')
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False  # Don't propagate to root logger
    
    # Rotating file handler for audit logs
    audit_handler = logging.handlers.RotatingFileHandler(
        audit_log_file,
        maxBytes=100 * 1024 * 1024,  # 100MB
        backupCount=30,  # Keep more audit logs
        encoding='utf-8'
    )
    audit_handler.setLevel(logging.INFO)
    
    # Audit-specific formatter
    audit_formatter = SecurityFormatter(
        '%(timestamp)s %(action)s %(resource)s %(user_id)s %(message)s'
    )
    audit_handler.setFormatter(audit_formatter)
    audit_handler.addFilter(sensitive_filter)
    
    audit_logger.addHandler(audit_handler)
    
    # ==========================
    # ERROR LOGGER
    # ==========================
    error_log_file = os.path.join(log_dir, 'errors.log')
    
    error_logger = logging.getLogger('errors')
    error_logger.setLevel(logging.ERROR)
    error_logger.propagate = False
    
    # Rotating file handler for error logs
    error_handler = logging.handlers.RotatingFileHandler(
        error_log_file,
        maxBytes=50 * 1024 * 1024,  # 50MB
        backupCount=15,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    
    # Error formatter with stack traces
    error_formatter = jsonlogger.JsonFormatter(
        '%(timestamp)s %(name)s %(levelname)s %(pathname)s %(lineno)d %(message)s'
    )
    error_handler.setFormatter(error_formatter)
    error_handler.addFilter(sensitive_filter)
    
    error_logger.addHandler(error_handler)
    
    # ==========================
    # CONSOLE LOGGER (Development)
    # ==========================
    if os.getenv('FLASK_ENV') == 'development' or os.getenv('DEBUG', 'False').lower() == 'true':
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        console_handler.addFilter(sensitive_filter)
        
        root_logger.addHandler(console_handler)
    
    # ==========================
    # FLASK LOGGER CONFIGURATION
    # ==========================
    if app:
        # Disable Flask's default logging in production
        if os.getenv('FLASK_ENV') == 'production':
            log = logging.getLogger('werkzeug')
            log.setLevel(logging.WARNING)
        
        # Set up Flask app logger
        app.logger.setLevel(getattr(logging, log_level))
        
        # Add custom request ID to each request
        @app.before_request
        def add_request_id():
            from flask import g
            import uuid
            g.request_id = str(uuid.uuid4())[:8]
    
    # ==========================
    # THIRD-PARTY LOGGERS
    # ==========================
    
    # Reduce noise from third-party libraries
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    return {
        'application': root_logger,
        'security': security_logger,
        'audit': audit_logger,
        'error': error_logger
    }

def log_application_startup():
    """Log application startup information."""
    startup_logger = logging.getLogger('security')
    startup_info = {
        'event': 'APPLICATION_STARTUP',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'python_version': __import__('sys').version,
        'environment': os.getenv('FLASK_ENV', 'unknown'),
        'debug_mode': os.getenv('DEBUG', 'False').lower() == 'true',
        'log_level': os.getenv('LOG_LEVEL', 'INFO'),
    }
    
    startup_logger.info("Application starting up", extra=startup_info)

def log_application_shutdown():
    """Log application shutdown information."""
    shutdown_logger = logging.getLogger('security')
    shutdown_info = {
        'event': 'APPLICATION_SHUTDOWN',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
    }
    
    shutdown_logger.info("Application shutting down", extra=shutdown_info)

# Custom exception handler for unhandled exceptions
def handle_exception(exc_type, exc_value, exc_traceback):
    """Handle unhandled exceptions with logging."""
    if issubclass(exc_type, KeyboardInterrupt):
        # Don't log keyboard interrupts
        return
    
    error_logger = logging.getLogger('errors')
    error_logger.error(
        "Uncaught exception",
        exc_info=(exc_type, exc_value, exc_traceback),
        extra={
            'exception_type': exc_type.__name__,
            'exception_value': str(exc_value)
        }
    )

# Set up global exception handler
import sys
sys.excepthook = handle_exception
