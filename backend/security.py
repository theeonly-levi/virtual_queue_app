# import hashlib
# from cryptography.fernet import Fernet

# key = Fernet.generate_key()
# cipher = Fernet(key)

# def hash_id(input_str):
#     return hashlib.sha256(input_str.encode()).hexdigest()

# def encrypt_data(data):
#     return cipher.encrypt(data.encode())

# def decrypt_data(encrypted_data):
#     return cipher.decrypt(encrypted_data).decode()

# session_data = {}
# def store_session(patient_id, info):
#     session_data[patient_id] = info

# def clear_session():
#     session_data.clear()

# print("test")


#HTTPS Enforcement & Security Headers (Flask Example)

from flask import Flask, redirect, request, jsonify
from functools import wraps
import ssl
import os
import json
import uuid
import time
import logging
import bcrypt
import jwt
from datetime import datetime
from collections import defaultdict
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Middleware to enforce HTTPS
@app.before_request
def enforce_https():
    if not request.is_secure and app.env != 'development':
        return redirect(request.url.replace('http://', 'https://'), code=301)

# Security headers middleware
@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Add missing security headers
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    # Update CSP to be more specific
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'"

    return response

# SSL context for production
def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain('ssl/cert.pem', 'ssl/key.pem')
    return context

#Authentication & Authorization System


import bcrypt
import jwt
import datetime
from functools import wraps
from flask import request, jsonify


class AuthManager:
    def __init__(self, secret_key):
        if not secret_key or len(secret_key) < 32:
            raise ValueError('Secret key must be at least 32 bytes long')
        self.secret_key = secret_key
        self._token_blacklist = set()
        
    def hash_password(self, password):
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password, hashed):
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def generate_token(self, user_id, roles=None):
        """Generate JWT token"""
        payload = {
            'user_id': user_id,
            'roles': roles or [],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow(),
            'jti': str(uuid.uuid4())
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_token(self, token):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            raise Exception('Token expired')
        except jwt.InvalidTokenError:
            raise Exception('Invalid token')

# Initialize auth manager
auth_manager = AuthManager(os.environ.get('SECRET_KEY', 'fallback-secret-change-in-production'))

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        try:
            user_data = auth_manager.verify_token(token)
            request.user = user_data
        except Exception as e:
            return jsonify({'error': str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Role-based authorization decorator
def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user_roles = getattr(request, 'user', {}).get('roles', [])
            if not any(role in user_roles for role in required_roles):
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

    #Input Validation & SQL Injection Protection

    import re
from flask import request
import sqlite3

class InputValidator:
    @staticmethod
    def sanitize_input(input_string, max_length=255):
        """Basic input sanitization"""
        if not input_string:
            return ""
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', input_string)
        sanitized = sanitized.strip()
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_password_strength(password):
        """Validate password meets security requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain lowercase letter"
        if not re.search(r'[0-9]', password):
            return False, "Password must contain number"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain special character"
        return True, "Password is strong"

# Secure database operations using parameterized queries
class SecureDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
    
    def get_user_safe(self, user_id):
        """Safe parameterized query - prevents SQL injection"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Correct way: use parameterized queries
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        conn.close()
        return user
    
    def search_users_unsafe(self, search_term):
        """DANGEROUS: demonstrates SQL injection vulnerability"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # WRONG WAY: vulnerable to SQL injection
        query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"
        cursor.execute(query)  # This is dangerous!
        
        users = cursor.fetchall()
        conn.close()
        return users

        
#Data Encryption & Secure Storage

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class DataEncryptor:
    def __init__(self, password: str, salt: bytes = None):
        self.salt = salt or os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.fernet = Fernet(key)
    
    def encrypt_sensitive_data(self, data: str) -> dict:
        """Encrypt sensitive data like SSN, credit cards"""
        encrypted = self.fernet.encrypt(data.encode())
        return {
            'encrypted_data': base64.urlsafe_b64encode(encrypted).decode(),
            'salt': base64.urlsafe_b64encode(self.salt).decode()
        }
    
    def decrypt_data(self, encrypted_data: str, salt: str) -> str:
        """Decrypt sensitive data"""
        salt_bytes = base64.urlsafe_b64decode(salt)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(b'encryption-password'))
        fernet = Fernet(key)
        
        return fernet.decrypt(encrypted_bytes).decode()

class PrivacyManager:
    def __init__(self):
        self.data_retention_days = 365  # GDPR compliance
    
    def anonymize_user_data(self, user_data):
        """Anonymize data for analytics"""
        anonymized = user_data.copy()
        anonymized['email'] = self._hash_email(anonymized.get('email', ''))
        anonymized['ip_address'] = self._anonymize_ip(anonymized.get('ip_address', ''))
        anonymized.pop('name', None)
        anonymized.pop('address', None)
        return anonymized
    
    def _hash_email(self, email):
        import hashlib
        return hashlib.sha256(email.lower().encode()).hexdigest()
    
    def _anonymize_ip(self, ip_address):
        if '.' in ip_address:  # IPv4
            return '.'.join(ip_address.split('.')[:-1]) + '.0'
        else:  # IPv6
            return ':'.join(ip_address.split(':')[:-1]) + ':0'


#Rate Limiting & Brute Force Protection

import time
from collections import defaultdict

class RateLimiter:
    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self._cleanup_interval = 3600  # Cleanup every hour
        self._last_cleanup = time.time()
    
    def is_rate_limited(self, identifier):
        """Check if request should be rate limited"""
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old requests
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier] 
            if req_time > window_start
        ]
        
        # Check rate limit
        if len(self.requests[identifier]) >= self.max_requests:
            return True
        
        # Record this request
        self.requests[identifier].append(now)
        return False

# Initialize rate limiters
login_limiter = RateLimiter(max_requests=5, window_seconds=300)  # 5 attempts per 5 minutes
api_limiter = RateLimiter(max_requests=100, window_seconds=3600)  # 100 requests per hour

@app.route('/login', methods=['POST'])
def login():
    ip_address = request.remote_addr
    username = request.json.get('username', '')
    
    # Rate limiting by IP and username
    if login_limiter.is_rate_limited(ip_address) or login_limiter.is_rate_limited(username):
        return jsonify({
            'error': 'Too many login attempts. Please try again later.',
            'retry_after': 300
        }), 429
    
    # Continue with authentication...


 #Consent Management & GDPR Compliance

import json
from datetime import datetime, timedelta

class ConsentManager:
    def __init__(self, db_connection):
        if not user_id or not consent_type or not version:
            raise ValueError("Missing required consent parameters")
        
        valid_consent_types = {'cookies', 'marketing', 'analytics'}
        if consent_type not in valid_consent_types:
            raise ValueError(f"Invalid consent type. Must be one of: {valid_consent_types}")
    
    def record_consent(self, user_id, consent_type, version, granted=True):
        """Record user consent for data processing"""
        consent_record = {
            'user_id': user_id,
            'consent_type': consent_type,  # 'cookies', 'marketing', 'analytics'
            'version': version,
            'granted': granted,
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')
        }
        
        # Store in database
        self._store_consent(consent_record)
        return consent_record
    
    def check_consent(self, user_id, consent_type):
        """Check if user has given consent"""
        # Query database for latest consent
        latest_consent = self._get_latest_consent(user_id, consent_type)
        return latest_consent.get('granted', False) if latest_consent else False
    
    def process_data_deletion_request(self, user_id):
        """Process GDPR Right to be Forgotten request"""
        # Anonymize user data
        self._anonymize_user_data(user_id)
        
        # Delete personal data
        self._delete_personal_data(user_id)
        
        # Log the deletion request
        self._log_deletion_request(user_id)
        
        return True

class PrivacyAPI:
    def __init__(self, consent_manager):
        self.consent_manager = consent_manager
    
    @app.route('/api/consent', methods=['POST'])
    def manage_consent():
        user_id = request.user.get('user_id')
        consent_data = request.json
        
        for consent_type, granted in consent_data.items():
            consent_manager.record_consent(user_id, consent_type, '1.0', granted)
        
        return jsonify({'status': 'consent_updated'})
    
    @app.route('/api/user/data', methods=['GET'])
    @login_required
    def get_user_data():
        """GDPR Data Access Request"""
        user_id = request.user['user_id']
        user_data = self._get_all_user_data(user_id)
        return jsonify(user_data)
    
    @app.route('/api/user/delete', methods=['POST'])
    @login_required
    def delete_user_data():
        """GDPR Right to be Forgotten"""
        user_id = request.user['user_id']
        self.consent_manager.process_data_deletion_request(user_id)
        return jsonify({'status': 'data_deleted'})


#Security Event Logging

import logging
import json
from datetime import datetime

class SecurityLogger:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SecurityLogger, cls).__new__(cls)
            cls._instance._init_logger()
        return cls._instance
    
    def _init_logger(self):
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers = []
        
        # Add file handler with rotation
        handler = logging.FileHandler('security.log', mode='a')
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S %z'
        ))
        # Add log rotation
        rotating_handler = RotatingFileHandler(
            'security.log',
            maxBytes=10485760,  # 10MB
            backupCount=10
        )
        self.logger.addHandler(rotating_handler)
    
    def log_security_event(self, event_type, user_id, ip_address, details):
        """Log security-related events with additional validation"""
        try:
            if not all([event_type, user_id, ip_address]):
                raise ValueError('Missing required logging parameters')
                
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'user_id': user_id,
                'ip_address': ip_address,
                'user_agent': request.headers.get('User-Agent', ''),
                'details': details
            }
            self.logger.info(json.dumps(log_entry))
            
            # Also log to console for development
            if app.debug:
                print(json.dumps(log_entry, indent=2))
        except Exception as e:
            self.logger.error(f'Failed to log security event: {str(e)}')
            print(f"SECURITY EVENT: {json.dumps(log_entry, indent=2)}")

# Initialize security logger
security_logger = SecurityLogger()

# Example usage in authentication

@app.route('/login', methods=['POST'],endpoint='login_post')
def login():
    """Login and receive JWT token"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = security.sanitize_input(data.get('username', ''))
        password = data.get('password', '')
        ip_address = request.remote_addr
        
        # Rate limiting check
        if not rate_limit_check(ip_address):
            security_logger.log_security_event(
                'rate_limit_exceeded',
                username,
                ip_address,
                {'reason': 'too_many_attempts'}
            )
            return jsonify({'error': 'Too many login attempts'}), 429
        
        # Input validation
        if not username or not password:
            security_logger.log_security_event(
                'login_failed',
                None,
                ip_address,
                {'username_attempted': username, 'reason': 'missing_credentials'}
            )
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Check if user exists
        if username not in users_db:
            security_logger.log_security_event(
                'login_failed',
                None,
                ip_address,
                {'username_attempted': username, 'reason': 'user_not_found'}
            )
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user = users_db[username]
        
        # Verify password
        if security.verify_password(password, user['password']):
            # Successful login
            user['last_login'] = datetime.datetime.utcnow().isoformat()
            token = auth.generate_token(username)
            
            security_logger.log_security_event(
                'login_success', 
                username,
                ip_address,
                {'method': 'password'}
            )
            
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'username': username
            })
        else:
            # Failed login - wrong password
            security_logger.log_security_event(
                'login_failed',
                username,
                ip_address,
                {'username_attempted': username, 'reason': 'invalid_password'}
            )
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        # Log unexpected errors
        security_logger.log_security_event(
            'login_error',
            None,
            request.remote_addr,
            {'error': str(e)}
        )
        return jsonify({'error': 'Login failed due to system error'}), 500