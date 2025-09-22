"""
HTTPS and security headers configuration module.
Implements comprehensive security headers, SSL/TLS configuration, and HTTPS enforcement.
"""

import os
import ssl
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from flask import Flask, request, Response, redirect, url_for
from functools import wraps
import secrets
import base64

# Get loggers
security_logger = logging.getLogger('security')

class HTTPSSecurityManager:
    """Manages HTTPS configuration and security headers."""
    
    def __init__(self, app: Flask = None):
        """Initialize HTTPS security manager."""
        self.app = app
        
        # HTTPS configuration
        self.force_https = os.getenv('FORCE_HTTPS', 'True').lower() == 'true'
        self.hsts_max_age = int(os.getenv('HSTS_MAX_AGE', '31536000'))  # 1 year default
        self.hsts_include_subdomains = os.getenv('HSTS_INCLUDE_SUBDOMAINS', 'True').lower() == 'true'
        self.hsts_preload = os.getenv('HSTS_PRELOAD', 'True').lower() == 'true'
        
        # Certificate configuration
        self.ssl_cert_path = os.getenv('SSL_CERT_PATH')
        self.ssl_key_path = os.getenv('SSL_KEY_PATH')
        self.ssl_ca_path = os.getenv('SSL_CA_PATH')
        
        # Security headers configuration
        self.csp_policy = self._build_csp_policy()
        self.referrer_policy = os.getenv('REFERRER_POLICY', 'strict-origin-when-cross-origin')
        self.permissions_policy = self._build_permissions_policy()
        
        # Security settings
        self.secure_cookies = os.getenv('SECURE_COOKIES', 'True').lower() == 'true'
        self.x_frame_options = os.getenv('X_FRAME_OPTIONS', 'DENY')
        self.x_content_type_options = os.getenv('X_CONTENT_TYPE_OPTIONS', 'nosniff')
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize Flask app with HTTPS security."""
        self.app = app
        
        # Configure SSL context for development
        self._configure_ssl_context()
        
        # Register before/after request handlers
        app.before_request(self._before_request_handler)
        app.after_request(self._after_request_handler)
        
        # Configure secure session settings
        self._configure_secure_sessions()
        
        security_logger.info("HTTPS security initialized")
    
    def _configure_ssl_context(self):
        """Configure SSL context for the application."""
        if not self.app:
            return
        
        # Production SSL configuration
        if self.ssl_cert_path and self.ssl_key_path:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2  # Minimum TLS 1.2
                context.maximum_version = ssl.TLSVersion.TLSv1_3  # Maximum TLS 1.3
                
                # Load certificate and key
                context.load_cert_chain(self.ssl_cert_path, self.ssl_key_path)
                
                # Load CA certificate if provided
                if self.ssl_ca_path:
                    context.load_verify_locations(self.ssl_ca_path)
                
                # Configure cipher suites (secure ones only)
                context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
                
                # Set SSL options for security
                context.options |= ssl.OP_NO_SSLv2
                context.options |= ssl.OP_NO_SSLv3
                context.options |= ssl.OP_NO_TLSv1
                context.options |= ssl.OP_NO_TLSv1_1
                context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
                context.options |= ssl.OP_SINGLE_DH_USE
                context.options |= ssl.OP_SINGLE_ECDH_USE
                
                self.app.config['SSL_CONTEXT'] = context
                security_logger.info("SSL context configured for production")
                
            except Exception as e:
                security_logger.error(f"Failed to configure SSL context: {e}")
        
        # Development SSL configuration
        elif os.getenv('FLASK_ENV') == 'development':
            # Generate self-signed certificate for development
            self._setup_development_ssl()
    
    def _setup_development_ssl(self):
        """Set up development SSL with self-signed certificate."""
        try:
            import ssl
            
            # Create adhoc SSL context for development
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            self.app.config['SSL_CONTEXT'] = 'adhoc'
            
            security_logger.info("Development SSL configured with adhoc certificate")
            security_logger.warning("Using self-signed certificate for development only")
            
        except Exception as e:
            security_logger.error(f"Failed to setup development SSL: {e}")
    
    def _configure_secure_sessions(self):
        """Configure secure session settings."""
        if not self.app:
            return
        
        # Update session configuration for security
        self.app.config.update({
            'SESSION_COOKIE_SECURE': self.secure_cookies,
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Strict',
            'REMEMBER_COOKIE_SECURE': self.secure_cookies,
            'REMEMBER_COOKIE_HTTPONLY': True,
            'REMEMBER_COOKIE_SAMESITE': 'Strict',
        })
        
        # Set secure cookie name if not already set
        if not self.app.config.get('SESSION_COOKIE_NAME'):
            self.app.config['SESSION_COOKIE_NAME'] = '__Secure-session' if self.secure_cookies else 'session'
    
    def _build_csp_policy(self) -> str:
        """Build Content Security Policy based on environment configuration."""
        # Base CSP policy - restrictive by default
        base_policy = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'", "'unsafe-inline'"],  # Allow inline styles for Bootstrap
            "img-src": ["'self'", "data:", "https:"],
            "font-src": ["'self'"],
            "connect-src": ["'self'"],
            "media-src": ["'none'"],
            "object-src": ["'none'"],
            "child-src": ["'none'"],
            "frame-src": ["'none'"],
            "worker-src": ["'none'"],
            "frame-ancestors": ["'none'"],
            "form-action": ["'self'"],
            "base-uri": ["'self'"],
            "manifest-src": ["'self'"],
            "upgrade-insecure-requests": []
        }
        
        # Allow CDN resources if specified in environment
        allowed_cdns = os.getenv('CSP_ALLOWED_CDNS', '').split(',')
        if allowed_cdns and allowed_cdns[0]:  # Check if not empty
            for cdn in allowed_cdns:
                cdn = cdn.strip()
                if cdn:
                    base_policy["script-src"].append(cdn)
                    base_policy["style-src"].append(cdn)
                    base_policy["font-src"].append(cdn)
        
        # Development mode adjustments
        if os.getenv('FLASK_ENV') == 'development':
            # Allow localhost connections for development
            base_policy["connect-src"].extend(["ws://localhost:*", "wss://localhost:*"])
            # Allow data URIs for development
            base_policy["script-src"].append("'unsafe-inline'")  # Only for development
            security_logger.warning("Relaxed CSP policy for development environment")
        
        # Build CSP string
        csp_parts = []
        for directive, sources in base_policy.items():
            if sources:
                csp_parts.append(f"{directive} {' '.join(sources)}")
            else:
                csp_parts.append(directive)
        
        return "; ".join(csp_parts)
    
    def _build_permissions_policy(self) -> str:
        """Build Permissions Policy (formerly Feature Policy)."""
        # Deny most permissions by default
        permissions = {
            "geolocation": [],
            "microphone": [],
            "camera": [],
            "payment": [],
            "usb": [],
            "magnetometer": [],
            "accelerometer": [],
            "gyroscope": [],
            "speaker-selection": [],
            "ambient-light-sensor": [],
            "autoplay": [],
            "encrypted-media": [],
            "fullscreen": ["'self'"],  # Allow fullscreen for our own content
            "picture-in-picture": [],
        }
        
        # Build permissions policy string
        policy_parts = []
        for permission, allowed_origins in permissions.items():
            if allowed_origins:
                policy_parts.append(f"{permission}=({' '.join(allowed_origins)})")
            else:
                policy_parts.append(f"{permission}=()")
        
        return ", ".join(policy_parts)
    
    def _before_request_handler(self):
        """Handle HTTPS enforcement before each request."""
        # Skip HTTPS enforcement for health checks and static files
        if request.endpoint in ['health', 'static']:
            return
        
        # Enforce HTTPS in production
        if self.force_https and not request.is_secure and os.getenv('FLASK_ENV') == 'production':
            # Redirect HTTP to HTTPS
            url = request.url.replace('http://', 'https://', 1)
            
            security_logger.info("Redirecting HTTP to HTTPS", extra={
                'original_url': request.url,
                'redirect_url': url,
                'ip_address': request.remote_addr
            })
            
            return redirect(url, code=301)  # Permanent redirect
        
        # Log insecure requests in production
        if os.getenv('FLASK_ENV') == 'production' and not request.is_secure:
            security_logger.warning("Insecure HTTP request in production", extra={
                'url': request.url,
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', '')
            })
    
    def _after_request_handler(self, response: Response) -> Response:
        """Add security headers to response."""
        # Content Security Policy
        response.headers['Content-Security-Policy'] = self.csp_policy
        
        # HSTS (HTTP Strict Transport Security)
        if request.is_secure or os.getenv('FLASK_ENV') != 'production':
            hsts_value = f"max-age={self.hsts_max_age}"
            if self.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            if self.hsts_preload:
                hsts_value += "; preload"
            response.headers['Strict-Transport-Security'] = hsts_value
        
        # X-Frame-Options
        response.headers['X-Frame-Options'] = self.x_frame_options
        
        # X-Content-Type-Options
        response.headers['X-Content-Type-Options'] = self.x_content_type_options
        
        # X-XSS-Protection (legacy but still useful)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = self.referrer_policy
        
        # Permissions Policy
        response.headers['Permissions-Policy'] = self.permissions_policy
        
        # Cross-Origin Policies
        response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        
        # Security-related headers
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
        response.headers['X-DNS-Prefetch-Control'] = 'off'
        
        # Remove server information
        response.headers.pop('Server', None)
        response.headers['Server'] = 'SecureServer'
        
        # Cache control for security-sensitive responses
        if request.endpoint and any(sensitive in request.endpoint for sensitive in ['login', 'admin', 'password']):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        return response
    
    def generate_ssl_certificate(self, domain: str, output_dir: str = None) -> Dict[str, str]:
        """Generate self-signed SSL certificate for development."""
        if not output_dir:
            output_dir = os.path.join(os.getcwd(), 'ssl')
        
        os.makedirs(output_dir, exist_ok=True)
        
        cert_path = os.path.join(output_dir, f'{domain}.crt')
        key_path = os.path.join(output_dir, f'{domain}.key')
        
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import ipaddress
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create certificate subject
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Development"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Candidate System Dev"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])
            
            # Create certificate
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                    x509.DNSName(f"*.{domain}"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.IPAddress(ipaddress.IPv6Address("::1")),
                ]),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).sign(private_key, hashes.SHA256())
            
            # Write certificate to file
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Write private key to file
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            security_logger.info(f"SSL certificate generated for {domain}")
            
            return {
                'certificate_path': cert_path,
                'private_key_path': key_path,
                'domain': domain,
                'valid_until': (datetime.utcnow() + timedelta(days=365)).isoformat()
            }
            
        except ImportError:
            security_logger.error("cryptography library required for certificate generation")
            raise
        except Exception as e:
            security_logger.error(f"Failed to generate SSL certificate: {e}")
            raise
    
    def validate_ssl_certificate(self, cert_path: str) -> Dict[str, Any]:
        """Validate SSL certificate and return information."""
        try:
            import ssl
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            
            # Load and parse certificate
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                cert = x509.load_pem_x509_certificate(cert_data)
            
            # Extract certificate information
            result = {
                'valid': True,
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'serial_number': str(cert.serial_number),
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'is_expired': datetime.utcnow() > cert.not_valid_after,
                'expires_soon': datetime.utcnow() > (cert.not_valid_after - timedelta(days=30)),
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'warnings': []
            }
            
            # Check for common issues
            if result['is_expired']:
                result['warnings'].append("Certificate has expired")
            elif result['expires_soon']:
                result['warnings'].append("Certificate expires within 30 days")
            
            # Check for weak signature algorithms
            weak_algorithms = ['md5', 'sha1']
            if any(weak in result['signature_algorithm'].lower() for weak in weak_algorithms):
                result['warnings'].append(f"Weak signature algorithm: {result['signature_algorithm']}")
            
            # Extract Subject Alternative Names
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_names = []
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        san_names.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        san_names.append(f"IP:{name.value}")
                result['san_names'] = san_names
            except x509.ExtensionNotFound:
                result['san_names'] = []
            
            return result
            
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
    
    def check_security_headers(self, url: str) -> Dict[str, Any]:
        """Check security headers of a URL (for testing)."""
        try:
            import requests
            
            response = requests.get(url, timeout=10, verify=False)  # Disable SSL verification for testing
            
            required_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Referrer-Policy': 'Referrer policy',
                'Permissions-Policy': 'Permissions policy'
            }
            
            result = {
                'url': url,
                'status_code': response.status_code,
                'headers_present': {},
                'headers_missing': [],
                'security_score': 0,
                'recommendations': []
            }
            
            total_headers = len(required_headers)
            
            for header, description in required_headers.items():
                if header in response.headers:
                    result['headers_present'][header] = {
                        'value': response.headers[header],
                        'description': description
                    }
                    result['security_score'] += 1
                else:
                    result['headers_missing'].append({
                        'header': header,
                        'description': description
                    })
            
            # Calculate security score percentage
            result['security_score'] = int((result['security_score'] / total_headers) * 100)
            
            # Add recommendations
            if result['headers_missing']:
                result['recommendations'].append("Add missing security headers")
            
            if result['security_score'] < 80:
                result['recommendations'].append("Improve security header coverage")
            
            return result
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'security_score': 0
            }


# Decorators for HTTPS enforcement
def require_https(f):
    """Decorator to require HTTPS for specific routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_secure and os.getenv('FLASK_ENV') == 'production':
            # Redirect to HTTPS
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)
        return f(*args, **kwargs)
    return decorated_function


def set_secure_headers(**custom_headers):
    """Decorator to set additional security headers for specific routes."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                for header, value in custom_headers.items():
                    response.headers[header] = value
            return response
        return decorated_function
    return decorator


# Flask app integration
def init_https_security(app: Flask, cert_path: str = None, key_path: str = None) -> HTTPSSecurityManager:
    """Initialize HTTPS security for Flask application."""
    
    # Set SSL paths if provided
    if cert_path:
        os.environ['SSL_CERT_PATH'] = cert_path
    if key_path:
        os.environ['SSL_KEY_PATH'] = key_path
    
    https_security = HTTPSSecurityManager(app)
    app.https_security = https_security
    
    security_logger.info("HTTPS security initialized")
    return https_security


# Global HTTPS security instance
https_security = None
