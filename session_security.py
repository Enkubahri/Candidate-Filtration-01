"""
Session security and CSRF protection module.
Implements secure session management, CSRF tokens, and session timeout controls.
"""

import os
import secrets
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from functools import wraps
import hashlib
import hmac
from flask import session, request, g, current_app, abort, jsonify
import sqlite3
from threading import Lock

# Get loggers
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')

class SessionSecurityManager:
    """Manages session security, CSRF protection, and session lifecycle."""
    
    def __init__(self, app=None, db_path: str = None):
        """Initialize session security manager."""
        self.app = app
        self.db_path = db_path or os.getenv('DATABASE_URL', 'candidates.db')
        self._lock = Lock()
        
        # Session security configuration
        self.session_timeout_minutes = int(os.getenv('SESSION_TIMEOUT_MINUTES', '30'))
        self.absolute_timeout_hours = int(os.getenv('SESSION_ABSOLUTE_TIMEOUT_HOURS', '8'))
        self.csrf_token_length = 32
        self.max_sessions_per_user = int(os.getenv('MAX_SESSIONS_PER_USER', '3'))
        
        # Initialize database tables
        self._init_session_tables()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Flask app with session security."""
        self.app = app
        
        # Configure secure session settings
        app.config.update({
            'SESSION_COOKIE_SECURE': os.getenv('SESSION_COOKIE_SECURE', 'True').lower() == 'true',
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Strict',
            'PERMANENT_SESSION_LIFETIME': timedelta(minutes=self.session_timeout_minutes),
            'SESSION_COOKIE_NAME': os.getenv('SESSION_COOKIE_NAME', '__Secure-session'),
            'WTF_CSRF_TIME_LIMIT': self.session_timeout_minutes * 60,  # CSRF token timeout
        })
        
        # Set secure session key if not set
        if not app.config.get('SECRET_KEY'):
            app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
            if not app.config['SECRET_KEY']:
                raise ValueError("SECRET_KEY must be set for session security")
        
        # Register session handlers
        app.before_request(self._before_request_handler)
        app.after_request(self._after_request_handler)
        app.teardown_request(self._teardown_request_handler)
        
        # Add security headers function
        @app.after_request
        def add_security_headers(response):
            return self.add_security_headers(response)
    
    def _init_session_tables(self):
        """Initialize database tables for session tracking."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Active sessions table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS active_sessions (
                        session_id TEXT PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ip_address TEXT,
                        user_agent TEXT,
                        csrf_token TEXT,
                        is_expired BOOLEAN DEFAULT FALSE,
                        logout_reason TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                """)
                
                # Session security events table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS session_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT,
                        event_type TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        ip_address TEXT,
                        details TEXT,
                        user_id INTEGER
                    )
                """)
                
                conn.commit()
        except Exception as e:
            security_logger.error(f"Failed to initialize session tables: {e}")
    
    def _before_request_handler(self):
        """Handle security checks before each request."""
        try:
            # Skip security checks for static files and certain endpoints
            if self._should_skip_security_check():
                return
            
            # Generate request ID for tracking
            g.request_id = secrets.token_hex(8)
            g.request_start_time = time.time()
            
            # Check session validity
            if not self._validate_session():
                return self._handle_invalid_session()
            
            # Check CSRF for state-changing requests
            if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                if not self._validate_csrf_token():
                    return self._handle_csrf_failure()
            
            # Update session activity
            self._update_session_activity()
            
        except Exception as e:
            security_logger.error(f"Session security check failed: {e}")
            # Don't block request if security check fails (fail open for availability)
    
    def _after_request_handler(self, response):
        """Handle response modifications for security."""
        try:
            # Add CSRF token to response if needed
            if hasattr(g, 'current_user_id') and request.endpoint:
                csrf_token = self.get_csrf_token()
                if csrf_token:
                    response.headers['X-CSRF-Token'] = csrf_token
            
            # Log request completion
            if hasattr(g, 'request_start_time'):
                duration = time.time() - g.request_start_time
                if duration > 5.0:  # Log slow requests
                    security_logger.warning(f"Slow request detected: {duration:.2f}s", extra={
                        'request_id': getattr(g, 'request_id', ''),
                        'endpoint': request.endpoint,
                        'method': request.method,
                        'duration': duration
                    })
            
        except Exception as e:
            security_logger.error(f"After request handler failed: {e}")
        
        return response
    
    def _teardown_request_handler(self, exception):
        """Clean up after request."""
        if exception:
            security_logger.error(f"Request failed with exception", extra={
                'request_id': getattr(g, 'request_id', ''),
                'exception': str(exception),
                'endpoint': request.endpoint
            })
    
    def _should_skip_security_check(self) -> bool:
        """Check if security validation should be skipped for this request."""
        # Skip for static files
        if request.endpoint == 'static':
            return True
        
        # Skip for health check endpoints
        if request.endpoint in ['health', 'ping']:
            return True
        
        # Skip for login page (but not login submission)
        if request.endpoint == 'login' and request.method == 'GET':
            return True
        
        return False
    
    def create_session(self, user_id: int, ip_address: str = None, user_agent: str = None) -> str:
        """Create a new secure session."""
        try:
            # Generate secure session ID
            session_id = self._generate_session_id()
            
            # Generate CSRF token
            csrf_token = self._generate_csrf_token()
            
            # Clean up old sessions for this user
            self._cleanup_user_sessions(user_id)
            
            # Store session in database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO active_sessions 
                    (session_id, user_id, ip_address, user_agent, csrf_token)
                    VALUES (?, ?, ?, ?, ?)
                """, (session_id, user_id, ip_address, user_agent, csrf_token))
            
            # Set Flask session
            session.permanent = True
            session['session_id'] = session_id
            session['user_id'] = user_id
            session['csrf_token'] = csrf_token
            session['created_at'] = datetime.utcnow().isoformat()
            session['last_activity'] = datetime.utcnow().isoformat()
            
            # Log session creation
            self._log_session_event(session_id, 'SESSION_CREATED', ip_address, user_id=user_id)
            
            security_logger.info("Session created", extra={
                'action': 'SESSION_CREATED',
                'user_id': user_id,
                'session_id': session_id,
                'ip_address': ip_address
            })
            
            return session_id
            
        except Exception as e:
            security_logger.error(f"Failed to create session: {e}")
            raise
    
    def destroy_session(self, logout_reason: str = "USER_LOGOUT") -> bool:
        """Destroy current session securely."""
        try:
            session_id = session.get('session_id')
            user_id = session.get('user_id')
            
            if session_id:
                # Mark session as expired in database
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE active_sessions 
                        SET is_expired = TRUE, logout_reason = ?
                        WHERE session_id = ?
                    """, (logout_reason, session_id))
                
                # Log session destruction
                self._log_session_event(session_id, 'SESSION_DESTROYED', 
                                      request.remote_addr, f"Reason: {logout_reason}", user_id)
                
                security_logger.info("Session destroyed", extra={
                    'action': 'SESSION_DESTROYED',
                    'user_id': user_id,
                    'session_id': session_id,
                    'reason': logout_reason
                })
            
            # Clear Flask session
            session.clear()
            
            return True
            
        except Exception as e:
            security_logger.error(f"Failed to destroy session: {e}")
            return False
    
    def _validate_session(self) -> bool:
        """Validate current session."""
        session_id = session.get('session_id')
        if not session_id:
            return True  # No session to validate
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT user_id, created_at, last_activity, is_expired, ip_address
                    FROM active_sessions 
                    WHERE session_id = ? AND is_expired = FALSE
                """, (session_id,))
                
                result = cursor.fetchone()
                if not result:
                    self._log_session_event(session_id, 'SESSION_INVALID', request.remote_addr)
                    return False
                
                user_id, created_at, last_activity, is_expired, stored_ip = result
                
                # Check if session is expired
                now = datetime.utcnow()
                last_activity_time = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
                created_time = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                
                # Check session timeout
                if (now - last_activity_time).total_seconds() > (self.session_timeout_minutes * 60):
                    self._log_session_event(session_id, 'SESSION_TIMEOUT', request.remote_addr, user_id=user_id)
                    self.destroy_session("SESSION_TIMEOUT")
                    return False
                
                # Check absolute timeout
                if (now - created_time).total_seconds() > (self.absolute_timeout_hours * 3600):
                    self._log_session_event(session_id, 'SESSION_ABSOLUTE_TIMEOUT', request.remote_addr, user_id=user_id)
                    self.destroy_session("ABSOLUTE_TIMEOUT")
                    return False
                
                # Check IP address consistency (if configured)
                if os.getenv('ENFORCE_SESSION_IP', 'False').lower() == 'true':
                    if stored_ip and stored_ip != request.remote_addr:
                        self._log_session_event(session_id, 'SESSION_IP_MISMATCH', request.remote_addr, 
                                              f"Expected: {stored_ip}, Got: {request.remote_addr}", user_id)
                        self.destroy_session("IP_MISMATCH")
                        return False
                
                # Set current user in g for request context
                g.current_user_id = user_id
                g.session_id = session_id
                
                return True
                
        except Exception as e:
            security_logger.error(f"Session validation failed: {e}")
            return False
    
    def _update_session_activity(self):
        """Update session last activity timestamp."""
        session_id = session.get('session_id')
        if not session_id:
            return
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE active_sessions 
                    SET last_activity = CURRENT_TIMESTAMP 
                    WHERE session_id = ?
                """, (session_id,))
            
            session['last_activity'] = datetime.utcnow().isoformat()
            
        except Exception as e:
            security_logger.error(f"Failed to update session activity: {e}")
    
    def _generate_session_id(self) -> str:
        """Generate cryptographically secure session ID."""
        # Combine multiple entropy sources
        entropy_sources = [
            secrets.token_bytes(32),  # 32 random bytes
            str(time.time()).encode(),  # Current timestamp
            request.remote_addr.encode() if request.remote_addr else b'',
            request.headers.get('User-Agent', '').encode()[:100]  # User agent (truncated)
        ]
        
        # Hash all entropy sources together
        combined = b''.join(entropy_sources)
        session_id = hashlib.sha256(combined).hexdigest()
        
        return session_id
    
    def _generate_csrf_token(self) -> str:
        """Generate CSRF token."""
        return secrets.token_urlsafe(self.csrf_token_length)
    
    def get_csrf_token(self) -> Optional[str]:
        """Get CSRF token for current session."""
        if 'csrf_token' not in session:
            # Generate new CSRF token if missing
            csrf_token = self._generate_csrf_token()
            session['csrf_token'] = csrf_token
            
            # Update database
            session_id = session.get('session_id')
            if session_id:
                try:
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute("""
                            UPDATE active_sessions 
                            SET csrf_token = ? 
                            WHERE session_id = ?
                        """, (csrf_token, session_id))
                except Exception as e:
                    security_logger.error(f"Failed to update CSRF token: {e}")
        
        return session.get('csrf_token')
    
    def _validate_csrf_token(self) -> bool:
        """Validate CSRF token for state-changing requests."""
        if not hasattr(g, 'current_user_id'):
            return True  # No session, no CSRF check needed
        
        # Get CSRF token from request
        csrf_token = None
        
        # Check form data first
        if request.form and 'csrf_token' in request.form:
            csrf_token = request.form.get('csrf_token')
        
        # Check headers
        elif 'X-CSRF-Token' in request.headers:
            csrf_token = request.headers.get('X-CSRF-Token')
        
        # Check JSON body
        elif request.is_json and request.json and 'csrf_token' in request.json:
            csrf_token = request.json.get('csrf_token')
        
        if not csrf_token:
            security_logger.warning("CSRF token missing", extra={
                'action': 'CSRF_TOKEN_MISSING',
                'user_id': g.current_user_id,
                'session_id': g.session_id,
                'endpoint': request.endpoint,
                'method': request.method
            })
            return False
        
        # Validate token
        expected_token = session.get('csrf_token')
        if not expected_token or not hmac.compare_digest(csrf_token, expected_token):
            security_logger.warning("CSRF token invalid", extra={
                'action': 'CSRF_TOKEN_INVALID',
                'user_id': g.current_user_id,
                'session_id': g.session_id,
                'endpoint': request.endpoint,
                'method': request.method
            })
            return False
        
        return True
    
    def _handle_invalid_session(self):
        """Handle invalid session."""
        self.destroy_session("INVALID_SESSION")
        
        if request.is_json:
            return jsonify({
                'error': 'Session invalid',
                'code': 'INVALID_SESSION',
                'redirect': '/login'
            }), 401
        else:
            # Redirect to login page
            from flask import redirect, url_for, flash
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
    
    def _handle_csrf_failure(self):
        """Handle CSRF token validation failure."""
        security_logger.critical("CSRF attack detected", extra={
            'action': 'CSRF_ATTACK_DETECTED',
            'user_id': getattr(g, 'current_user_id', None),
            'session_id': getattr(g, 'session_id', None),
            'ip_address': request.remote_addr,
            'endpoint': request.endpoint,
            'method': request.method,
            'referer': request.headers.get('Referer', ''),
            'user_agent': request.headers.get('User-Agent', '')
        })
        
        if request.is_json:
            return jsonify({
                'error': 'CSRF token invalid',
                'code': 'CSRF_INVALID'
            }), 403
        else:
            abort(403)
    
    def _cleanup_user_sessions(self, user_id: int):
        """Clean up old sessions for user (enforce session limits)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get active sessions for user
                cursor.execute("""
                    SELECT session_id, created_at FROM active_sessions 
                    WHERE user_id = ? AND is_expired = FALSE 
                    ORDER BY last_activity DESC
                """, (user_id,))
                
                sessions = cursor.fetchall()
                
                # If user has too many sessions, expire the oldest ones
                if len(sessions) >= self.max_sessions_per_user:
                    sessions_to_expire = sessions[self.max_sessions_per_user-1:]  # Keep newest N-1
                    
                    for session_id, _ in sessions_to_expire:
                        cursor.execute("""
                            UPDATE active_sessions 
                            SET is_expired = TRUE, logout_reason = 'MAX_SESSIONS_EXCEEDED'
                            WHERE session_id = ?
                        """, (session_id,))
                        
                        self._log_session_event(session_id, 'SESSION_EXPIRED_LIMIT', 
                                              request.remote_addr, user_id=user_id)
        
        except Exception as e:
            security_logger.error(f"Failed to cleanup user sessions: {e}")
    
    def _log_session_event(self, session_id: str, event_type: str, ip_address: str, 
                          details: str = None, user_id: int = None):
        """Log session security event."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO session_events 
                    (session_id, event_type, ip_address, details, user_id)
                    VALUES (?, ?, ?, ?, ?)
                """, (session_id, event_type, ip_address, details, user_id))
        except Exception as e:
            security_logger.error(f"Failed to log session event: {e}")
    
    def add_security_headers(self, response):
        """Add security headers to response."""
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': csp,
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'X-Permitted-Cross-Domain-Policies': 'none'
        }
        
        # Add HSTS in production with HTTPS
        if os.getenv('FLASK_ENV') == 'production' and request.is_secure:
            security_headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions from database (for maintenance tasks)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete sessions older than absolute timeout
                cutoff_time = datetime.utcnow() - timedelta(hours=self.absolute_timeout_hours)
                cursor.execute("""
                    DELETE FROM active_sessions 
                    WHERE created_at < ? OR is_expired = TRUE
                """, (cutoff_time,))
                
                deleted_count = cursor.rowcount
                
                # Clean up old session events (keep last 30 days)
                event_cutoff = datetime.utcnow() - timedelta(days=30)
                cursor.execute("""
                    DELETE FROM session_events 
                    WHERE timestamp < ?
                """, (event_cutoff,))
                
                security_logger.info(f"Cleaned up {deleted_count} expired sessions")
                
        except Exception as e:
            security_logger.error(f"Failed to cleanup expired sessions: {e}")


# Decorator for CSRF protection
def csrf_protect(f):
    """Decorator to require CSRF token for protected endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            session_manager = current_app.session_security
            if not session_manager._validate_csrf_token():
                return session_manager._handle_csrf_failure()
        return f(*args, **kwargs)
    return decorated_function


# Decorator to require authentication
def login_required(f):
    """Decorator to require valid session for protected endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user_id'):
            if request.is_json:
                return jsonify({
                    'error': 'Authentication required',
                    'code': 'AUTH_REQUIRED'
                }), 401
            else:
                from flask import redirect, url_for, flash
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Global instance
session_manager = SessionSecurityManager()
