"""
Rate limiting and DDoS protection module.
Implements comprehensive rate limiting for login attempts, API endpoints, and form submissions.
"""

import os
import time
import redis
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Any, List
from functools import wraps
from flask import request, jsonify, abort, g, current_app
from dataclasses import dataclass
import sqlite3
from threading import Lock
import json
from collections import defaultdict, deque
import ipaddress

# Get loggers
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')

@dataclass
class RateLimit:
    """Rate limit configuration."""
    requests: int  # Number of requests allowed
    window: int    # Time window in seconds
    block_duration: int = None  # Block duration in seconds (None = same as window)

class RateLimiter:
    """Advanced rate limiting with Redis backend and fallback to memory/SQLite."""
    
    def __init__(self, redis_url: str = None, db_path: str = None):
        """Initialize rate limiter."""
        self.redis_client = None
        self.db_path = db_path or os.getenv('DATABASE_URL', 'candidates.db')
        self._memory_cache = defaultdict(lambda: defaultdict(deque))
        self._lock = Lock()
        
        # Rate limiting rules
        self.rate_limits = {
            # Authentication endpoints
            'login': RateLimit(5, 900, 1800),  # 5 attempts per 15 min, block for 30 min
            'password_reset': RateLimit(3, 3600, 3600),  # 3 per hour
            'registration': RateLimit(3, 3600, 1800),  # 3 per hour
            
            # API endpoints
            'api_general': RateLimit(100, 3600),  # 100 requests per hour
            'api_strict': RateLimit(20, 3600),   # 20 requests per hour for sensitive operations
            'file_upload': RateLimit(10, 3600),  # 10 file uploads per hour
            
            # Form submissions
            'contact_form': RateLimit(5, 3600),  # 5 contact forms per hour
            'job_application': RateLimit(10, 86400),  # 10 applications per day
            
            # Search and browsing
            'search': RateLimit(50, 3600),       # 50 searches per hour
            'page_view': RateLimit(1000, 3600),  # 1000 page views per hour
            
            # Admin operations
            'admin_action': RateLimit(50, 3600),  # 50 admin actions per hour
            'bulk_operation': RateLimit(5, 3600), # 5 bulk operations per hour
        }
        
        # DDoS protection thresholds
        self.ddos_thresholds = {
            'requests_per_second': 10,      # Max requests per second per IP
            'requests_per_minute': 300,     # Max requests per minute per IP
            'concurrent_connections': 20,   # Max concurrent connections per IP
            'suspicious_patterns': 5,       # Max suspicious patterns per IP per hour
        }
        
        # Initialize Redis connection
        self._init_redis(redis_url)
        
        # Initialize SQLite fallback
        self._init_sqlite_fallback()
    
    def _init_redis(self, redis_url: str = None):
        """Initialize Redis connection."""
        try:
            redis_url = redis_url or os.getenv('REDIS_URL', 'redis://localhost:6379/0')
            self.redis_client = redis.from_url(redis_url, decode_responses=True)
            
            # Test connection
            self.redis_client.ping()
            security_logger.info("Redis connection established for rate limiting")
            
        except Exception as e:
            security_logger.warning(f"Redis connection failed, using fallback: {e}")
            self.redis_client = None
    
    def _init_sqlite_fallback(self):
        """Initialize SQLite fallback for rate limiting data."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Rate limit tracking table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS rate_limits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        identifier TEXT NOT NULL,
                        endpoint TEXT NOT NULL,
                        request_count INTEGER DEFAULT 1,
                        window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_blocked BOOLEAN DEFAULT FALSE,
                        block_until TIMESTAMP,
                        INDEX(identifier, endpoint),
                        INDEX(window_start),
                        INDEX(block_until)
                    )
                """)
                
                # DDoS detection table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ddos_detection (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        event_count INTEGER DEFAULT 1,
                        window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_event TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_blocked BOOLEAN DEFAULT FALSE,
                        block_until TIMESTAMP,
                        INDEX(ip_address, event_type),
                        INDEX(window_start)
                    )
                """)
                
                conn.commit()
        except Exception as e:
            security_logger.error(f"Failed to initialize SQLite fallback: {e}")
    
    def check_rate_limit(self, identifier: str, endpoint: str, 
                        custom_limit: RateLimit = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is within rate limit.
        
        Args:
            identifier: Unique identifier (IP, user_id, etc.)
            endpoint: Endpoint or operation name
            custom_limit: Custom rate limit override
        
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        try:
            # Get rate limit configuration
            rate_limit = custom_limit or self.rate_limits.get(endpoint, self.rate_limits['api_general'])
            
            # Use Redis if available, otherwise fallback
            if self.redis_client:
                return self._check_rate_limit_redis(identifier, endpoint, rate_limit)
            else:
                return self._check_rate_limit_sqlite(identifier, endpoint, rate_limit)
                
        except Exception as e:
            security_logger.error(f"Rate limiting check failed: {e}")
            # Fail open to maintain availability
            return True, {'error': 'rate_limit_check_failed'}
    
    def _check_rate_limit_redis(self, identifier: str, endpoint: str, 
                               rate_limit: RateLimit) -> Tuple[bool, Dict[str, Any]]:
        """Check rate limit using Redis."""
        current_time = int(time.time())
        key = f"rate_limit:{identifier}:{endpoint}"
        block_key = f"block:{identifier}:{endpoint}"
        
        # Check if currently blocked
        block_until = self.redis_client.get(block_key)
        if block_until and int(block_until) > current_time:
            remaining_block = int(block_until) - current_time
            return False, {
                'blocked': True,
                'block_remaining': remaining_block,
                'reason': 'rate_limit_exceeded'
            }
        
        # Sliding window implementation
        window_start = current_time - rate_limit.window
        
        # Remove old requests
        self.redis_client.zremrangebyscore(key, 0, window_start)
        
        # Count current requests
        current_count = self.redis_client.zcard(key)
        
        if current_count >= rate_limit.requests:
            # Rate limit exceeded - set block
            block_duration = rate_limit.block_duration or rate_limit.window
            block_until_time = current_time + block_duration
            self.redis_client.setex(block_key, block_duration, block_until_time)
            
            # Log rate limit violation
            self._log_rate_limit_violation(identifier, endpoint, current_count, rate_limit)
            
            return False, {
                'blocked': True,
                'block_remaining': block_duration,
                'reason': 'rate_limit_exceeded',
                'requests_made': current_count,
                'requests_allowed': rate_limit.requests,
                'window_seconds': rate_limit.window
            }
        
        # Add current request
        request_id = f"{current_time}:{hash(request.remote_addr if request else '')}"
        self.redis_client.zadd(key, {request_id: current_time})
        self.redis_client.expire(key, rate_limit.window)
        
        return True, {
            'allowed': True,
            'requests_made': current_count + 1,
            'requests_remaining': rate_limit.requests - current_count - 1,
            'reset_time': current_time + rate_limit.window
        }
    
    def _check_rate_limit_sqlite(self, identifier: str, endpoint: str, 
                                rate_limit: RateLimit) -> Tuple[bool, Dict[str, Any]]:
        """Check rate limit using SQLite fallback."""
        current_time = datetime.utcnow()
        window_start = current_time - timedelta(seconds=rate_limit.window)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if currently blocked
                cursor.execute("""
                    SELECT block_until FROM rate_limits 
                    WHERE identifier = ? AND endpoint = ? AND is_blocked = TRUE 
                    AND block_until > datetime('now')
                    ORDER BY block_until DESC LIMIT 1
                """, (identifier, endpoint))
                
                block_result = cursor.fetchone()
                if block_result:
                    block_until = datetime.fromisoformat(block_result[0].replace('Z', '+00:00'))
                    remaining_block = int((block_until - current_time).total_seconds())
                    return False, {
                        'blocked': True,
                        'block_remaining': remaining_block,
                        'reason': 'rate_limit_exceeded'
                    }
                
                # Clean up old requests
                cursor.execute("""
                    DELETE FROM rate_limits 
                    WHERE identifier = ? AND endpoint = ? AND window_start < ?
                """, (identifier, endpoint, window_start))
                
                # Count current requests in window
                cursor.execute("""
                    SELECT SUM(request_count) FROM rate_limits 
                    WHERE identifier = ? AND endpoint = ? AND window_start >= ?
                """, (identifier, endpoint, window_start))
                
                result = cursor.fetchone()
                current_count = result[0] or 0
                
                if current_count >= rate_limit.requests:
                    # Rate limit exceeded - set block
                    block_duration = rate_limit.block_duration or rate_limit.window
                    block_until = current_time + timedelta(seconds=block_duration)
                    
                    cursor.execute("""
                        INSERT OR REPLACE INTO rate_limits 
                        (identifier, endpoint, request_count, window_start, last_request, 
                         is_blocked, block_until)
                        VALUES (?, ?, ?, ?, ?, TRUE, ?)
                    """, (identifier, endpoint, current_count, window_start, current_time, block_until))
                    
                    # Log rate limit violation
                    self._log_rate_limit_violation(identifier, endpoint, current_count, rate_limit)
                    
                    return False, {
                        'blocked': True,
                        'block_remaining': block_duration,
                        'reason': 'rate_limit_exceeded',
                        'requests_made': current_count,
                        'requests_allowed': rate_limit.requests,
                        'window_seconds': rate_limit.window
                    }
                
                # Add current request
                cursor.execute("""
                    INSERT OR REPLACE INTO rate_limits 
                    (identifier, endpoint, request_count, window_start, last_request, is_blocked)
                    VALUES (?, ?, 1, ?, ?, FALSE)
                """, (identifier, endpoint, current_time, current_time))
                
                return True, {
                    'allowed': True,
                    'requests_made': current_count + 1,
                    'requests_remaining': rate_limit.requests - current_count - 1,
                    'reset_time': int((current_time + timedelta(seconds=rate_limit.window)).timestamp())
                }
                
        except Exception as e:
            security_logger.error(f"SQLite rate limit check failed: {e}")
            return True, {'error': 'fallback_failed'}
    
    def _log_rate_limit_violation(self, identifier: str, endpoint: str, 
                                 count: int, rate_limit: RateLimit):
        """Log rate limit violation."""
        security_logger.warning(f"Rate limit exceeded", extra={
            'action': 'RATE_LIMIT_EXCEEDED',
            'identifier': identifier,
            'endpoint': endpoint,
            'requests_made': count,
            'requests_allowed': rate_limit.requests,
            'window_seconds': rate_limit.window,
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent', '') if request else None,
            'user_id': getattr(g, 'current_user_id', None)
        })
    
    def check_ddos_protection(self, ip_address: str) -> Tuple[bool, str]:
        """
        Check for DDoS patterns and suspicious activity.
        
        Args:
            ip_address: Client IP address
        
        Returns:
            Tuple of (is_allowed, block_reason)
        """
        try:
            # Skip DDoS check for whitelisted IPs
            if self._is_whitelisted_ip(ip_address):
                return True, ""
            
            current_time = int(time.time())
            
            # Check multiple DDoS indicators
            checks = [
                self._check_requests_per_second(ip_address, current_time),
                self._check_requests_per_minute(ip_address, current_time),
                self._check_suspicious_patterns(ip_address, current_time),
                self._check_geographic_anomalies(ip_address),
            ]
            
            for is_allowed, reason in checks:
                if not is_allowed:
                    self._block_ip_for_ddos(ip_address, reason)
                    return False, reason
            
            return True, ""
            
        except Exception as e:
            security_logger.error(f"DDoS protection check failed: {e}")
            return True, ""  # Fail open
    
    def _check_requests_per_second(self, ip_address: str, current_time: int) -> Tuple[bool, str]:
        """Check requests per second threshold."""
        key = f"ddos:rps:{ip_address}"
        threshold = self.ddos_thresholds['requests_per_second']
        
        if self.redis_client:
            # Sliding window for last second
            self.redis_client.zremrangebyscore(key, 0, current_time - 1)
            count = self.redis_client.zcard(key)
            
            if count >= threshold:
                return False, f"requests_per_second_exceeded_{count}"
            
            # Add current request
            self.redis_client.zadd(key, {f"{current_time}:{hash(str(time.time()))}": current_time})
            self.redis_client.expire(key, 5)  # Keep for 5 seconds
        
        return True, ""
    
    def _check_requests_per_minute(self, ip_address: str, current_time: int) -> Tuple[bool, str]:
        """Check requests per minute threshold."""
        key = f"ddos:rpm:{ip_address}"
        threshold = self.ddos_thresholds['requests_per_minute']
        window_start = current_time - 60
        
        if self.redis_client:
            # Sliding window for last minute
            self.redis_client.zremrangebyscore(key, 0, window_start)
            count = self.redis_client.zcard(key)
            
            if count >= threshold:
                return False, f"requests_per_minute_exceeded_{count}"
            
            # Add current request
            self.redis_client.zadd(key, {f"{current_time}:{hash(str(time.time()))}": current_time})
            self.redis_client.expire(key, 120)  # Keep for 2 minutes
        
        return True, ""
    
    def _check_suspicious_patterns(self, ip_address: str, current_time: int) -> Tuple[bool, str]:
        """Check for suspicious request patterns."""
        if not request:
            return True, ""
        
        # Check for suspicious patterns
        suspicious_indicators = []
        
        # Rapid-fire identical requests
        user_agent = request.headers.get('User-Agent', '')
        if not user_agent or len(user_agent) < 10:
            suspicious_indicators.append('missing_user_agent')
        
        # Common bot patterns
        if any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget']):
            if not any(legit in user_agent.lower() for legit in ['googlebot', 'bingbot', 'slurp']):
                suspicious_indicators.append('suspicious_bot')
        
        # Unusual referer patterns
        referer = request.headers.get('Referer', '')
        if referer and not referer.startswith(('http://', 'https://')):
            suspicious_indicators.append('invalid_referer')
        
        # Check for too many suspicious indicators
        if len(suspicious_indicators) >= 2:
            return False, f"suspicious_patterns_{','.join(suspicious_indicators)}"
        
        return True, ""
    
    def _check_geographic_anomalies(self, ip_address: str) -> Tuple[bool, str]:
        """Check for geographic anomalies (basic implementation)."""
        try:
            # Skip private IP addresses
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                return True, ""
            
            # This is a placeholder - in production, you'd use a GeoIP service
            # to detect impossible geographic changes or suspicious locations
            
        except Exception:
            pass
        
        return True, ""
    
    def _is_whitelisted_ip(self, ip_address: str) -> bool:
        """Check if IP is whitelisted."""
        whitelist = os.getenv('IP_WHITELIST', '').split(',')
        return ip_address in [ip.strip() for ip in whitelist if ip.strip()]
    
    def _block_ip_for_ddos(self, ip_address: str, reason: str):
        """Block IP address due to DDoS detection."""
        block_duration = int(os.getenv('DDOS_BLOCK_DURATION', '3600'))  # 1 hour default
        
        if self.redis_client:
            block_key = f"ddos_block:{ip_address}"
            self.redis_client.setex(block_key, block_duration, reason)
        
        # Also log to SQLite
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                block_until = datetime.utcnow() + timedelta(seconds=block_duration)
                cursor.execute("""
                    INSERT OR REPLACE INTO ddos_detection 
                    (ip_address, event_type, event_count, window_start, last_event, 
                     is_blocked, block_until)
                    VALUES (?, ?, 1, datetime('now'), datetime('now'), TRUE, ?)
                """, (ip_address, reason, block_until))
        except Exception as e:
            security_logger.error(f"Failed to log DDoS block: {e}")
        
        security_logger.critical(f"IP blocked for DDoS", extra={
            'action': 'DDOS_IP_BLOCKED',
            'ip_address': ip_address,
            'reason': reason,
            'block_duration': block_duration,
            'endpoint': request.endpoint if request else None
        })
    
    def is_ip_blocked(self, ip_address: str) -> Tuple[bool, str]:
        """Check if IP is currently blocked for DDoS."""
        if self.redis_client:
            block_key = f"ddos_block:{ip_address}"
            reason = self.redis_client.get(block_key)
            if reason:
                ttl = self.redis_client.ttl(block_key)
                return True, f"blocked_for_{reason}_remaining_{ttl}s"
        
        # Check SQLite fallback
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT event_type, block_until FROM ddos_detection 
                    WHERE ip_address = ? AND is_blocked = TRUE 
                    AND block_until > datetime('now')
                    ORDER BY block_until DESC LIMIT 1
                """, (ip_address,))
                
                result = cursor.fetchone()
                if result:
                    reason, block_until = result
                    return True, f"blocked_for_{reason}"
        except Exception:
            pass
        
        return False, ""
    
    def cleanup_expired_records(self):
        """Clean up expired rate limiting records (maintenance task)."""
        try:
            current_time = datetime.utcnow() - timedelta(hours=24)  # Keep last 24 hours
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clean up old rate limit records
                cursor.execute("""
                    DELETE FROM rate_limits 
                    WHERE window_start < ? AND (block_until IS NULL OR block_until < datetime('now'))
                """, (current_time,))
                
                # Clean up old DDoS records
                cursor.execute("""
                    DELETE FROM ddos_detection 
                    WHERE window_start < ? AND (block_until IS NULL OR block_until < datetime('now'))
                """, (current_time,))
                
                deleted_count = cursor.rowcount
                security_logger.info(f"Cleaned up {deleted_count} expired rate limiting records")
                
        except Exception as e:
            security_logger.error(f"Failed to cleanup rate limiting records: {e}")


# Decorator for rate limiting
def rate_limit(endpoint: str = None, custom_limit: RateLimit = None, 
               per_user: bool = False, per_ip: bool = True):
    """
    Decorator to apply rate limiting to Flask routes.
    
    Args:
        endpoint: Rate limit endpoint name (defaults to route name)
        custom_limit: Custom rate limit configuration
        per_user: Apply rate limit per authenticated user
        per_ip: Apply rate limit per IP address
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get rate limiter instance
            rate_limiter = getattr(current_app, 'rate_limiter', None)
            if not rate_limiter:
                security_logger.warning("Rate limiter not configured")
                return f(*args, **kwargs)
            
            endpoint_name = endpoint or request.endpoint or f.__name__
            identifiers = []
            
            # Determine identifiers for rate limiting
            if per_ip:
                identifiers.append(f"ip:{request.remote_addr}")
            
            if per_user and hasattr(g, 'current_user_id'):
                identifiers.append(f"user:{g.current_user_id}")
            
            if not identifiers:
                identifiers.append(f"ip:{request.remote_addr}")  # Default to IP
            
            # Check each identifier
            for identifier in identifiers:
                is_allowed, rate_info = rate_limiter.check_rate_limit(
                    identifier, endpoint_name, custom_limit
                )
                
                if not is_allowed:
                    if request.is_json:
                        return jsonify({
                            'error': 'Rate limit exceeded',
                            'message': 'Too many requests',
                            'rate_limit_info': rate_info
                        }), 429
                    else:
                        abort(429)
            
            # Check DDoS protection
            is_allowed, block_reason = rate_limiter.check_ddos_protection(request.remote_addr)
            if not is_allowed:
                security_logger.critical(f"Request blocked by DDoS protection: {block_reason}")
                abort(429)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Specific rate limiting decorators for common use cases
def rate_limit_login(f):
    """Rate limit for login attempts."""
    return rate_limit('login', per_ip=True, per_user=False)(f)

def rate_limit_api(f):
    """Rate limit for general API endpoints."""
    return rate_limit('api_general', per_user=True, per_ip=True)(f)

def rate_limit_upload(f):
    """Rate limit for file upload endpoints."""
    return rate_limit('file_upload', per_user=True, per_ip=True)(f)

def rate_limit_strict(f):
    """Strict rate limit for sensitive operations."""
    return rate_limit('api_strict', per_user=True, per_ip=True)(f)


# Flask app integration
def init_rate_limiting(app, redis_url: str = None, db_path: str = None):
    """Initialize rate limiting for Flask application."""
    rate_limiter = RateLimiter(redis_url, db_path)
    app.rate_limiter = rate_limiter
    
    # Add before request handler for DDoS protection
    @app.before_request
    def ddos_protection():
        if request.endpoint in ['static']:
            return  # Skip static files
        
        # Check if IP is blocked
        is_blocked, reason = rate_limiter.is_ip_blocked(request.remote_addr)
        if is_blocked:
            security_logger.warning(f"Blocked request from {request.remote_addr}: {reason}")
            abort(429)
    
    # Add after request handler for rate limit headers
    @app.after_request
    def add_rate_limit_headers(response):
        # Add rate limiting headers if available
        if hasattr(g, 'rate_limit_info'):
            rate_info = g.rate_limit_info
            if 'requests_remaining' in rate_info:
                response.headers['X-RateLimit-Remaining'] = str(rate_info['requests_remaining'])
            if 'reset_time' in rate_info:
                response.headers['X-RateLimit-Reset'] = str(rate_info['reset_time'])
        
        return response
    
    security_logger.info("Rate limiting initialized")
    return rate_limiter


# Global rate limiter instance (will be set by init_rate_limiting)
rate_limiter = None
