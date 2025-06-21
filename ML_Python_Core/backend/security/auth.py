import re
import bcrypt
import secrets
from typing import Optional, Tuple
from datetime import datetime, timedelta
import jwt
from dataclasses import dataclass

@dataclass
class PasswordPolicy:
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = True
    max_age_days: int = 90
    prevent_reuse: int = 5  # Number of previous passwords to prevent reuse

class Authentication:
    def __init__(self, jwt_secret: str):
        self.jwt_secret = jwt_secret
        self.password_policy = PasswordPolicy()
        self.failed_attempts = {}  # Track failed login attempts
        self.lockout_duration = 15  # minutes
        self.max_attempts = 5
    
    def validate_password(self, password: str) -> Tuple[bool, str]:
        """Validate password against policy"""
        if len(password) < self.password_policy.min_length:
            return False, f"Password must be at least {self.password_policy.min_length} characters"
        
        if self.password_policy.require_uppercase and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if self.password_policy.require_lowercase and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if self.password_policy.require_numbers and not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if self.password_policy.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Password meets requirements"
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode(), hashed.encode())
    
    def generate_session_token(self, user_id: str, role: str) -> str:
        """Generate JWT session token"""
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow(),
            'jti': secrets.token_hex(16)  # Unique token ID
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def verify_session_token(self, token: str) -> Optional[dict]:
        """Verify JWT session token"""
        try:
            return jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            return None
    
    def check_login_attempts(self, user_id: str) -> Tuple[bool, Optional[int]]:
        """Check if user is locked out due to failed attempts"""
        if user_id not in self.failed_attempts:
            return True, None
        
        attempts = self.failed_attempts[user_id]
        if len(attempts) >= self.max_attempts:
            lockout_time = attempts[-1] + timedelta(minutes=self.lockout_duration)
            if datetime.now() < lockout_time:
                remaining = int((lockout_time - datetime.now()).total_seconds() / 60)
                return False, remaining
        
        return True, None
    
    def record_failed_attempt(self, user_id: str):
        """Record failed login attempt"""
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = []
        
        self.failed_attempts[user_id].append(datetime.now())
        
        # Keep only recent attempts
        cutoff = datetime.now() - timedelta(minutes=self.lockout_duration)
        self.failed_attempts[user_id] = [
            attempt for attempt in self.failed_attempts[user_id]
            if attempt > cutoff
        ]
    
    def reset_failed_attempts(self, user_id: str):
        """Reset failed login attempts after successful login"""
        if user_id in self.failed_attempts:
            del self.failed_attempts[user_id]
    
    def generate_password_reset_token(self, user_id: str) -> str:
        """Generate password reset token"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=1),
            'type': 'password_reset'
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def verify_password_reset_token(self, token: str) -> Optional[str]:
        """Verify password reset token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            if payload.get('type') != 'password_reset':
                return None
            return payload.get('user_id')
        except jwt.InvalidTokenError:
            return None 