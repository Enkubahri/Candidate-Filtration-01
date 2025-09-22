"""
File upload security module with comprehensive validation, virus scanning, and secure storage.
Implements multi-layer file validation, malware detection, and secure file storage.
"""

import os
import hashlib
import secrets
import magic
import logging
import subprocess
import shutil
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, BinaryIO
from pathlib import Path
from PIL import Image, ImageFile
import zipfile
import tempfile
import mimetypes
from contextlib import contextmanager
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
import threading
from functools import wraps
import json
import re

# Get loggers
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')

# Configure PIL for security
ImageFile.LOAD_TRUNCATED_IMAGES = False
Image.MAX_IMAGE_PIXELS = 89478485  # Prevent decompression bomb attacks

class FileUploadSecurity:
    """Comprehensive file upload security with validation, scanning, and secure storage."""
    
    def __init__(self, upload_dir: str = None):
        """Initialize file upload security."""
        self.upload_dir = upload_dir or self._get_secure_upload_directory()
        self.quarantine_dir = os.path.join(self.upload_dir, 'quarantine')
        self.temp_dir = os.path.join(self.upload_dir, 'temp')
        
        # File validation settings
        self.max_file_size = int(os.getenv('MAX_FILE_SIZE', 10 * 1024 * 1024))  # 10MB default
        self.max_filename_length = int(os.getenv('MAX_FILENAME_LENGTH', 255))
        self.max_files_per_request = int(os.getenv('MAX_FILES_PER_REQUEST', 5))
        
        # Allowed file types and MIME types
        self.allowed_extensions = {
            'documents': {'.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'},
            'images': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'},
            'archives': {'.zip', '.rar', '.7z', '.tar', '.gz'},
            'spreadsheets': {'.xls', '.xlsx', '.csv', '.ods'},
            'presentations': {'.ppt', '.pptx', '.odp'},
        }
        
        self.allowed_mime_types = {
            # Documents
            'application/pdf', 'application/msword', 
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain', 'text/rtf', 'application/vnd.oasis.opendocument.text',
            
            # Images
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/bmp', 'image/webp',
            
            # Archives
            'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
            'application/x-tar', 'application/gzip',
            
            # Spreadsheets
            'application/vnd.ms-excel', 
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/csv', 'application/vnd.oasis.opendocument.spreadsheet',
            
            # Presentations
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'application/vnd.oasis.opendocument.presentation',
        }
        
        # Dangerous file signatures (magic bytes)
        self.dangerous_signatures = {
            b'\x4d\x5a': 'PE executable',  # PE/COFF executable
            b'\x7f\x45\x4c\x46': 'ELF executable',  # ELF executable
            b'\xca\xfe\xba\xbe': 'Java class file',  # Java class file
            b'\xfe\xed\xfa\xce': 'Mach-O executable',  # Mach-O executable
            b'\x50\x4b\x03\x04': 'ZIP archive',  # ZIP (needs further inspection)
        }
        
        # Virus scanner configuration
        self.virus_scanner_enabled = os.getenv('VIRUS_SCANNER_ENABLED', 'False').lower() == 'true'
        self.virus_scanner_command = os.getenv('VIRUS_SCANNER_COMMAND', 'clamdscan')
        self.virus_scanner_timeout = int(os.getenv('VIRUS_SCANNER_TIMEOUT', '30'))
        
        # Initialize secure upload environment
        self._setup_secure_upload_environment()
        
    def _get_secure_upload_directory(self) -> str:
        """Get or create secure upload directory."""
        upload_dir = os.getenv('SECURE_UPLOAD_DIR')
        
        if not upload_dir:
            if os.name == 'nt':  # Windows
                upload_dir = os.path.join(os.environ.get('LOCALAPPDATA', 'C:\\'), 'CandidateSystem', 'uploads')
            else:  # Unix-like systems
                if os.geteuid() == 0:  # Running as root
                    upload_dir = '/var/lib/candidate_system/uploads'
                else:
                    upload_dir = os.path.expanduser('~/.local/share/candidate_system/uploads')
        
        # Create directory with secure permissions
        os.makedirs(upload_dir, mode=0o700, exist_ok=True)
        
        security_logger.info(f"Secure upload directory: {upload_dir}")
        return upload_dir
    
    def _setup_secure_upload_environment(self):
        """Set up secure upload environment."""
        try:
            # Create subdirectories
            for subdir in ['quarantine', 'temp', 'processed']:
                dir_path = os.path.join(self.upload_dir, subdir)
                os.makedirs(dir_path, mode=0o700, exist_ok=True)
            
            # Set up .htaccess for Apache (if applicable)
            htaccess_path = os.path.join(self.upload_dir, '.htaccess')
            if not os.path.exists(htaccess_path):
                with open(htaccess_path, 'w') as f:
                    f.write("# Prevent execution of uploaded files\n")
                    f.write("Options -ExecCGI\n")
                    f.write("AddHandler cgi-script .php .pl .py .jsp .asp .sh\n")
                    f.write("Options -Indexes\n")
                    f.write("Order allow,deny\n")
                    f.write("Deny from all\n")
            
            security_logger.info("Secure upload environment initialized")
            
        except Exception as e:
            security_logger.error(f"Failed to setup secure upload environment: {e}")
            raise
    
    def validate_file_upload(self, file: FileStorage, allowed_categories: List[str] = None,
                           max_size: int = None) -> Dict[str, Any]:
        """
        Comprehensive file upload validation.
        
        Args:
            file: Uploaded file object
            allowed_categories: List of allowed file categories
            max_size: Maximum file size override
        
        Returns:
            Dictionary with validation results and metadata
        """
        try:
            if not file or not file.filename:
                raise ValueError("No file provided")
            
            # Basic file information
            original_filename = file.filename
            file_size = 0
            
            # Read file content for analysis
            file.seek(0)  # Ensure we're at the beginning
            file_content = file.read()
            file_size = len(file_content)
            file.seek(0)  # Reset for further processing
            
            validation_results = {
                'original_filename': original_filename,
                'file_size': file_size,
                'validation_passed': False,
                'security_checks': [],
                'warnings': [],
                'errors': []
            }
            
            # File size validation
            max_size_check = max_size or self.max_file_size
            if file_size > max_size_check:
                validation_results['errors'].append(
                    f"File too large: {file_size} bytes (max: {max_size_check} bytes)"
                )
                return validation_results
            
            if file_size == 0:
                validation_results['errors'].append("File is empty")
                return validation_results
            
            # Filename validation
            filename_validation = self._validate_filename(original_filename)
            if not filename_validation['valid']:
                validation_results['errors'].extend(filename_validation['errors'])
                return validation_results
            
            # File extension validation
            file_ext = os.path.splitext(original_filename)[1].lower()
            if allowed_categories:
                allowed_extensions = set()
                for category in allowed_categories:
                    if category in self.allowed_extensions:
                        allowed_extensions.update(self.allowed_extensions[category])
                
                if file_ext not in allowed_extensions:
                    validation_results['errors'].append(
                        f"File type not allowed: {file_ext}. Allowed: {', '.join(sorted(allowed_extensions))}"
                    )
                    return validation_results
            
            # MIME type validation
            mime_validation = self._validate_mime_type(file_content, file_ext)
            validation_results['mime_type'] = mime_validation['mime_type']
            validation_results['security_checks'].append(mime_validation)
            
            if not mime_validation['valid']:
                validation_results['errors'].extend(mime_validation['errors'])
                return validation_results
            
            # Magic bytes validation
            magic_validation = self._validate_magic_bytes(file_content)
            validation_results['security_checks'].append(magic_validation)
            
            if not magic_validation['valid']:
                validation_results['errors'].extend(magic_validation['errors'])
                return validation_results
            
            # Content-specific validation
            content_validation = self._validate_file_content(file_content, file_ext, mime_validation['mime_type'])
            validation_results['security_checks'].append(content_validation)
            
            if not content_validation['valid']:
                validation_results['errors'].extend(content_validation['errors'])
                if content_validation.get('quarantine'):
                    validation_results['quarantine_required'] = True
                return validation_results
            
            # Generate secure filename and hash
            validation_results['secure_filename'] = self._generate_secure_filename(original_filename)
            validation_results['file_hash'] = hashlib.sha256(file_content).hexdigest()
            validation_results['content_hash'] = hashlib.md5(file_content).hexdigest()
            
            # Check for duplicate files
            duplicate_check = self._check_duplicate_file(validation_results['file_hash'])
            if duplicate_check['is_duplicate']:
                validation_results['warnings'].append("File already exists")
                validation_results['existing_file'] = duplicate_check['existing_file']
            
            validation_results['validation_passed'] = True
            return validation_results
            
        except Exception as e:
            security_logger.error(f"File validation failed: {e}")
            return {
                'original_filename': file.filename if file else 'unknown',
                'validation_passed': False,
                'errors': [f"Validation error: {str(e)}"]
            }
    
    def _validate_filename(self, filename: str) -> Dict[str, Any]:
        """Validate filename for security issues."""
        result = {'valid': True, 'errors': []}
        
        if not filename:
            result['valid'] = False
            result['errors'].append("Filename is empty")
            return result
        
        # Length check
        if len(filename) > self.max_filename_length:
            result['valid'] = False
            result['errors'].append(f"Filename too long (max: {self.max_filename_length} characters)")
        
        # Path traversal check
        if '..' in filename or '/' in filename or '\\' in filename:
            result['valid'] = False
            result['errors'].append("Filename contains path traversal characters")
        
        # Dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\0', '\n', '\r']
        if any(char in filename for char in dangerous_chars):
            result['valid'] = False
            result['errors'].append("Filename contains dangerous characters")
        
        # Reserved names (Windows)
        if os.name == 'nt':
            reserved_names = ['CON', 'PRN', 'AUX', 'NUL'] + [f'COM{i}' for i in range(1, 10)] + [f'LPT{i}' for i in range(1, 10)]
            name_without_ext = os.path.splitext(filename)[0].upper()
            if name_without_ext in reserved_names:
                result['valid'] = False
                result['errors'].append("Filename uses reserved name")
        
        # Check for executable extensions
        dangerous_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.vbe', '.js', '.jse',
            '.wsf', '.wsh', '.msi', '.msp', '.msc', '.jar', '.app', '.deb', '.rpm', '.dmg',
            '.pkg', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.py', '.rb', '.pl', '.php',
            '.asp', '.aspx', '.jsp', '.cgi'
        }
        
        file_ext = os.path.splitext(filename)[1].lower()
        if file_ext in dangerous_extensions:
            result['valid'] = False
            result['errors'].append(f"Executable file type not allowed: {file_ext}")
        
        return result
    
    def _validate_mime_type(self, file_content: bytes, file_ext: str) -> Dict[str, Any]:
        """Validate MIME type using python-magic."""
        result = {'valid': True, 'errors': [], 'check_type': 'mime_type'}
        
        try:
            # Detect MIME type
            mime_type = magic.from_buffer(file_content, mime=True)
            result['mime_type'] = mime_type
            
            # Check against allowed MIME types
            if mime_type not in self.allowed_mime_types:
                result['valid'] = False
                result['errors'].append(f"MIME type not allowed: {mime_type}")
                return result
            
            # Cross-validate MIME type with file extension
            expected_mimes = mimetypes.guess_type(f"test{file_ext}")[0]
            if expected_mimes and mime_type not in expected_mimes.split(','):
                # Some tolerance for common MIME type variations
                mime_variations = {
                    'image/jpg': 'image/jpeg',
                    'application/x-zip-compressed': 'application/zip',
                }
                
                actual_mime = mime_variations.get(mime_type, mime_type)
                if actual_mime != expected_mimes.strip():
                    result['valid'] = False
                    result['errors'].append(
                        f"MIME type mismatch: detected {mime_type}, expected {expected_mimes} for {file_ext}"
                    )
            
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"MIME type detection failed: {e}")
        
        return result
    
    def _validate_magic_bytes(self, file_content: bytes) -> Dict[str, Any]:
        """Validate file magic bytes for security threats."""
        result = {'valid': True, 'errors': [], 'check_type': 'magic_bytes'}
        
        if len(file_content) < 4:
            return result  # Too small to have meaningful magic bytes
        
        # Check first 4 bytes for dangerous signatures
        file_header = file_content[:4]
        
        for signature, description in self.dangerous_signatures.items():
            if file_content.startswith(signature):
                if description == 'ZIP archive':
                    # ZIP files need special handling - could be legitimate or malicious
                    zip_validation = self._validate_zip_file(file_content)
                    if not zip_validation['valid']:
                        result['valid'] = False
                        result['errors'].extend(zip_validation['errors'])
                else:
                    result['valid'] = False
                    result['errors'].append(f"Dangerous file type detected: {description}")
                break
        
        # Check for embedded executables in the middle of files
        dangerous_patterns = [
            b'\x4d\x5a\x90\x00',  # PE executable header
            b'<script',           # Embedded scripts
            b'<?php',            # PHP code
            b'<%',               # ASP/JSP code
            b'javascript:',      # JavaScript URLs
            b'vbscript:',        # VBScript URLs
        ]
        
        content_lower = file_content.lower()
        for pattern in dangerous_patterns:
            if pattern in content_lower:
                result['valid'] = False
                result['errors'].append(f"Suspicious content pattern detected")
                break
        
        return result
    
    def _validate_zip_file(self, file_content: bytes) -> Dict[str, Any]:
        """Special validation for ZIP files."""
        result = {'valid': True, 'errors': []}
        
        try:
            with tempfile.NamedTemporaryFile() as temp_file:
                temp_file.write(file_content)
                temp_file.flush()
                
                with zipfile.ZipFile(temp_file.name, 'r') as zip_ref:
                    # Check for zip bombs
                    total_uncompressed_size = sum(info.file_size for info in zip_ref.infolist())
                    compressed_size = len(file_content)
                    compression_ratio = total_uncompressed_size / compressed_size if compressed_size > 0 else 0
                    
                    if compression_ratio > 1000:  # Suspicious compression ratio
                        result['valid'] = False
                        result['errors'].append("Potential zip bomb detected")
                        return result
                    
                    if total_uncompressed_size > 500 * 1024 * 1024:  # 500MB uncompressed limit
                        result['valid'] = False
                        result['errors'].append("Archive too large when uncompressed")
                        return result
                    
                    # Check individual files in archive
                    for info in zip_ref.infolist():
                        if info.filename.startswith('..') or '/' in info.filename:
                            result['valid'] = False
                            result['errors'].append("Archive contains path traversal")
                            return result
                        
                        # Check for dangerous file types in archive
                        file_ext = os.path.splitext(info.filename)[1].lower()
                        dangerous_exts = {'.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar'}
                        if file_ext in dangerous_exts:
                            result['valid'] = False
                            result['errors'].append(f"Archive contains dangerous file: {info.filename}")
                            return result
        
        except zipfile.BadZipFile:
            result['valid'] = False
            result['errors'].append("Corrupted or invalid ZIP file")
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"ZIP validation failed: {e}")
        
        return result
    
    def _validate_file_content(self, file_content: bytes, file_ext: str, mime_type: str) -> Dict[str, Any]:
        """Validate file content based on type."""
        result = {'valid': True, 'errors': [], 'check_type': 'content_validation'}
        
        try:
            if mime_type.startswith('image/'):
                content_validation = self._validate_image_content(file_content)
            elif mime_type == 'application/pdf':
                content_validation = self._validate_pdf_content(file_content)
            elif mime_type in ['text/plain', 'text/csv']:
                content_validation = self._validate_text_content(file_content)
            else:
                content_validation = {'valid': True, 'errors': []}
            
            result.update(content_validation)
            
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"Content validation failed: {e}")
        
        return result
    
    def _validate_image_content(self, file_content: bytes) -> Dict[str, Any]:
        """Validate image file content."""
        result = {'valid': True, 'errors': []}
        
        try:
            with tempfile.NamedTemporaryFile() as temp_file:
                temp_file.write(file_content)
                temp_file.flush()
                
                # Use PIL to validate and analyze image
                with Image.open(temp_file.name) as img:
                    # Check image dimensions
                    width, height = img.size
                    if width > 10000 or height > 10000:
                        result['valid'] = False
                        result['errors'].append("Image dimensions too large")
                        return result
                    
                    # Check for suspicious EXIF data
                    if hasattr(img, '_getexif') and img._getexif():
                        exif_data = img._getexif()
                        if exif_data:
                            # Check for suspicious EXIF tags
                            suspicious_tags = [34665, 34853]  # EXIF IFD and GPS IFD
                            for tag in suspicious_tags:
                                if tag in exif_data:
                                    # Just log for now, don't reject
                                    security_logger.info(f"Image contains EXIF data with tag {tag}")
                    
                    # Verify image can be processed
                    img.verify()
        
        except Image.DecompressionBombError:
            result['valid'] = False
            result['errors'].append("Potential image decompression bomb")
            result['quarantine'] = True
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"Invalid image file: {e}")
        
        return result
    
    def _validate_pdf_content(self, file_content: bytes) -> Dict[str, Any]:
        """Validate PDF file content."""
        result = {'valid': True, 'errors': []}
        
        try:
            # Basic PDF structure validation
            if not file_content.startswith(b'%PDF-'):
                result['valid'] = False
                result['errors'].append("Invalid PDF header")
                return result
            
            # Check for suspicious JavaScript in PDF
            content_lower = file_content.lower()
            suspicious_patterns = [
                b'/javascript',
                b'/js',
                b'this.print',
                b'app.alert',
                b'eval(',
            ]
            
            for pattern in suspicious_patterns:
                if pattern in content_lower:
                    result['valid'] = False
                    result['errors'].append("PDF contains suspicious JavaScript")
                    result['quarantine'] = True
                    return result
            
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"PDF validation failed: {e}")
        
        return result
    
    def _validate_text_content(self, file_content: bytes) -> Dict[str, Any]:
        """Validate text file content."""
        result = {'valid': True, 'errors': []}
        
        try:
            # Try to decode as text
            try:
                text_content = file_content.decode('utf-8')
            except UnicodeDecodeError:
                # Try other encodings
                try:
                    text_content = file_content.decode('latin-1')
                except UnicodeDecodeError:
                    result['valid'] = False
                    result['errors'].append("File contains non-text binary data")
                    return result
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'<script[^>]*>',
                r'javascript:',
                r'vbscript:',
                r'on\w+\s*=',
                r'<%.*?%>',
                r'<\?php',
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, text_content, re.IGNORECASE):
                    result['valid'] = False
                    result['errors'].append("Text file contains suspicious script content")
                    result['quarantine'] = True
                    return result
            
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"Text validation failed: {e}")
        
        return result
    
    def _generate_secure_filename(self, original_filename: str) -> str:
        """Generate a secure filename."""
        # Get file extension
        name, ext = os.path.splitext(original_filename)
        
        # Generate secure base name
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        random_id = secrets.token_hex(8)
        
        # Clean original name (keep first 20 chars, alphanumeric only)
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', name)[:20]
        
        secure_filename = f"{timestamp}_{random_id}_{clean_name}{ext}"
        
        return secure_filename
    
    def _check_duplicate_file(self, file_hash: str) -> Dict[str, Any]:
        """Check if file already exists based on hash."""
        result = {'is_duplicate': False}
        
        # This would typically check against a database of file hashes
        # For now, we'll just check if a file with this hash exists in the upload directory
        try:
            for root, dirs, files in os.walk(self.upload_dir):
                for file in files:
                    if file.startswith(file_hash[:16]):  # Simple hash prefix check
                        result['is_duplicate'] = True
                        result['existing_file'] = os.path.join(root, file)
                        break
                if result['is_duplicate']:
                    break
        except Exception:
            pass  # Ignore errors in duplicate check
        
        return result
    
    def scan_for_viruses(self, file_path: str) -> Dict[str, Any]:
        """Scan file for viruses using configured scanner."""
        result = {
            'clean': True,
            'scanner_used': None,
            'scan_output': '',
            'errors': []
        }
        
        if not self.virus_scanner_enabled:
            result['scanner_used'] = 'disabled'
            return result
        
        try:
            # Try different virus scanners
            scanners = [
                ('clamdscan', [self.virus_scanner_command, '--no-summary', file_path]),
                ('clamscan', ['clamscan', '--no-summary', file_path]),
                ('windows_defender', ['powershell', '-Command', f'Get-MpThreatDetection -Path "{file_path}"']),
            ]
            
            for scanner_name, command in scanners:
                if shutil.which(command[0]) or scanner_name == 'windows_defender':
                    try:
                        process = subprocess.run(
                            command,
                            capture_output=True,
                            text=True,
                            timeout=self.virus_scanner_timeout,
                            check=False
                        )
                        
                        result['scanner_used'] = scanner_name
                        result['scan_output'] = process.stdout + process.stderr
                        
                        # Interpret results based on scanner
                        if scanner_name in ['clamdscan', 'clamscan']:
                            # ClamAV returns 0 for clean, 1 for infected
                            result['clean'] = process.returncode == 0
                        elif scanner_name == 'windows_defender':
                            # Windows Defender - if no output, file is clean
                            result['clean'] = len(process.stdout.strip()) == 0
                        
                        break
                        
                    except subprocess.TimeoutExpired:
                        result['errors'].append(f"{scanner_name} scan timed out")
                        continue
                    except Exception as e:
                        result['errors'].append(f"{scanner_name} scan failed: {e}")
                        continue
            
            if not result['scanner_used']:
                result['errors'].append("No virus scanner available")
            
        except Exception as e:
            result['errors'].append(f"Virus scanning failed: {e}")
        
        return result
    
    def store_file_securely(self, file: FileStorage, validation_results: Dict[str, Any],
                           category: str = 'general') -> Dict[str, Any]:
        """Store validated file securely."""
        try:
            if not validation_results.get('validation_passed'):
                raise ValueError("File validation failed")
            
            secure_filename = validation_results['secure_filename']
            
            # Determine storage path
            category_dir = os.path.join(self.upload_dir, 'processed', category)
            os.makedirs(category_dir, mode=0o700, exist_ok=True)
            
            final_path = os.path.join(category_dir, secure_filename)
            
            # Save file
            file.seek(0)  # Reset file pointer
            file.save(final_path)
            
            # Set secure permissions
            if os.name != 'nt':
                os.chmod(final_path, 0o600)
            
            # Virus scan the stored file
            virus_scan_result = self.scan_for_viruses(final_path)
            
            if not virus_scan_result['clean']:
                # Move to quarantine
                quarantine_path = self._quarantine_file(final_path, "Virus detected")
                
                security_logger.critical("Infected file quarantined", extra={
                    'action': 'FILE_QUARANTINED',
                    'original_filename': validation_results['original_filename'],
                    'secure_filename': secure_filename,
                    'quarantine_path': quarantine_path,
                    'scan_result': virus_scan_result
                })
                
                return {
                    'success': False,
                    'error': 'File failed virus scan',
                    'quarantined': True,
                    'quarantine_path': quarantine_path
                }
            
            # Log successful upload
            audit_logger.info("File uploaded successfully", extra={
                'action': 'FILE_UPLOADED',
                'original_filename': validation_results['original_filename'],
                'secure_filename': secure_filename,
                'file_path': final_path,
                'file_size': validation_results['file_size'],
                'file_hash': validation_results['file_hash'],
                'category': category
            })
            
            return {
                'success': True,
                'file_path': final_path,
                'secure_filename': secure_filename,
                'file_hash': validation_results['file_hash'],
                'virus_scan_result': virus_scan_result
            }
            
        except Exception as e:
            security_logger.error(f"File storage failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _quarantine_file(self, file_path: str, reason: str) -> str:
        """Move file to quarantine."""
        try:
            quarantine_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(8)}_{os.path.basename(file_path)}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            shutil.move(file_path, quarantine_path)
            
            # Create metadata file
            metadata_path = f"{quarantine_path}.metadata"
            metadata = {
                'quarantine_time': datetime.now().isoformat(),
                'reason': reason,
                'original_path': file_path,
                'quarantine_path': quarantine_path
            }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return quarantine_path
            
        except Exception as e:
            security_logger.error(f"Failed to quarantine file: {e}")
            raise
    
    def cleanup_temp_files(self, max_age_hours: int = 24):
        """Clean up temporary files older than specified age."""
        try:
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            deleted_count = 0
            
            for temp_file in os.listdir(self.temp_dir):
                temp_path = os.path.join(self.temp_dir, temp_file)
                
                if os.path.isfile(temp_path):
                    file_stat = os.stat(temp_path)
                    file_time = datetime.fromtimestamp(file_stat.st_mtime)
                    
                    if file_time < cutoff_time:
                        os.remove(temp_path)
                        deleted_count += 1
            
            if deleted_count > 0:
                security_logger.info(f"Cleaned up {deleted_count} temporary files")
                
        except Exception as e:
            security_logger.error(f"Temp file cleanup failed: {e}")


# Decorator for secure file upload handling
def secure_file_upload(allowed_categories: List[str] = None, max_size: int = None,
                      storage_category: str = 'general'):
    """Decorator for secure file upload handling."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, g
            
            upload_security = getattr(current_app, 'upload_security', None)
            if not upload_security:
                security_logger.warning("Upload security not configured")
                return f(*args, **kwargs)
            
            # Validate uploaded files
            uploaded_files = []
            validation_results = []
            
            for file_key in request.files:
                file = request.files[file_key]
                if file and file.filename:
                    result = upload_security.validate_file_upload(
                        file, allowed_categories, max_size
                    )
                    validation_results.append(result)
                    
                    if result['validation_passed']:
                        # Store file securely
                        storage_result = upload_security.store_file_securely(
                            file, result, storage_category
                        )
                        uploaded_files.append(storage_result)
                    else:
                        # Log validation failure
                        security_logger.warning("File upload validation failed", extra={
                            'filename': result['original_filename'],
                            'errors': result.get('errors', []),
                            'user_id': getattr(g, 'current_user_id', None)
                        })
            
            # Store results in g for use in route
            g.uploaded_files = uploaded_files
            g.upload_validation_results = validation_results
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Flask app integration
def init_file_upload_security(app, upload_dir: str = None) -> FileUploadSecurity:
    """Initialize file upload security for Flask application."""
    upload_security = FileUploadSecurity(upload_dir)
    app.upload_security = upload_security
    
    security_logger.info("File upload security initialized")
    return upload_security


# Global upload security instance
upload_security = None
