from flask import request, make_response
from functools import wraps
import re
import time
from typing import Dict, List, Optional
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta

class SecurityMiddleware:
    def __init__(self, app):
        self.app = app
        self.rate_limits: Dict[str, List[float]] = {}
        self.api_keys: Dict[str, Dict] = {}
        self.csrf_tokens: Dict[str, str] = {}
        self.max_requests = 100  # requests per window
        self.window = 3600  # 1 hour window
        self.jwt_secret = secrets.token_hex(32)
        
    def init_app(self, app):
        @app.before_request
        def before_request():
            # Add security headers
            self.add_security_headers()
            
            # Check rate limit
            if not self.check_rate_limit(request.remote_addr):
                return make_response('Rate limit exceeded', 429)
            
            # Validate API key for protected routes
            if self.is_protected_route(request.path):
                if not self.validate_api_key(request):
                    return make_response('Invalid API key', 401)
            
            # Validate CSRF token for POST/PUT/DELETE requests
            if request.method in ['POST', 'PUT', 'DELETE']:
                if not self.validate_csrf_token(request):
                    return make_response('Invalid CSRF token', 403)
    
    def add_security_headers(self):
        """Add security headers to all responses"""
        headers = {
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
        return headers
    
    def check_rate_limit(self, ip: str) -> bool:
        """Check if IP has exceeded rate limit"""
        current_time = time.time()
        
        if ip not in self.rate_limits:
            self.rate_limits[ip] = []
        
        # Clean old requests
        self.rate_limits[ip] = [
            req_time for req_time in self.rate_limits[ip]
            if current_time - req_time < self.window
        ]
        
        if len(self.rate_limits[ip]) >= self.max_requests:
            return False
        
        self.rate_limits[ip].append(current_time)
        return True
    
    def validate_api_key(self, request) -> bool:
        """Validate API key from request"""
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return False
        
        if api_key not in self.api_keys:
            return False
        
        key_data = self.api_keys[api_key]
        if key_data['expires_at'] < datetime.now():
            del self.api_keys[api_key]
            return False
        
        return True
    
    def validate_csrf_token(self, request) -> bool:
        """Validate CSRF token from request"""
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token:
            return False
        
        session_id = request.cookies.get('session_id')
        if not session_id:
            return False
        
        return self.csrf_tokens.get(session_id) == csrf_token
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate new CSRF token for session"""
        token = secrets.token_hex(32)
        self.csrf_tokens[session_id] = token
        return token
    
    def generate_api_key(self, user_id: str, expires_in: int = 30) -> str:
        """Generate new API key for user"""
        api_key = secrets.token_hex(32)
        self.api_keys[api_key] = {
            'user_id': user_id,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(days=expires_in)
        }
        return api_key
    
    def is_protected_route(self, path: str) -> bool:
        """Check if route requires API key"""
        protected_patterns = [
            r'^/api/analyze$',
            r'^/api/admin/.*$',
            r'^/api/settings/.*$'
        ]
        return any(re.match(pattern, path) for pattern in protected_patterns)
    
    def generate_jwt_token(self, user_id: str, role: str) -> str:
        """Generate JWT token for user"""
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def validate_jwt_token(self, token: str) -> Optional[Dict]:
        """Validate JWT token"""
        try:
            return jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return None 