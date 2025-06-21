import re
import html
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse, parse_qs
import bleach
import json

class InputValidator:
    def __init__(self):
        self.xss_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'data:',
            r'vbscript:',
            r'onload=',
            r'onerror=',
            r'onmouseover=',
            r'expression\(',
            r'eval\(',
            r'alert\(',
            r'confirm\(',
            r'prompt\('
        ]
        
        self.sql_patterns = [
            r'(\%27)|(\')|(\-\-)|(\%23)|(#)',
            r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))',
            r'/\*.*?\*/',
            r'(\%27)|(\')|(\-\-)|(\%23)|(#)',
            r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))'
        ]
        
        self.allowed_tags = ['p', 'br', 'b', 'i', 'u', 'em', 'strong', 'a']
        self.allowed_attrs = {
            'a': ['href', 'title', 'target']
        }
    
    def sanitize_text(self, text: str) -> str:
        """Sanitize text input"""
        if not isinstance(text, str):
            return str(text)
        
        # Remove null bytes
        text = text.replace('\0', '')
        
        # HTML escape
        text = html.escape(text)
        
        # Remove XSS patterns
        for pattern in self.xss_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        
        return text
    
    def sanitize_html(self, html_content: str) -> str:
        """Sanitize HTML content"""
        return bleach.clean(
            html_content,
            tags=self.allowed_tags,
            attributes=self.allowed_attrs,
            strip=True
        )
    
    def validate_url(self, url: str) -> bool:
        """Validate URL format and security"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def sanitize_url(self, url: str) -> Optional[str]:
        """Sanitize and validate URL"""
        if not self.validate_url(url):
            return None
        
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            return None
        
        # Remove potentially dangerous parameters
        query = parse_qs(parsed.query)
        safe_query = {k: v for k, v in query.items() if not any(
            re.search(pattern, k, re.IGNORECASE) for pattern in self.sql_patterns
        )}
        
        # Reconstruct URL
        return parsed._replace(query='&'.join(f"{k}={v[0]}" for k, v in safe_query.items())).geturl()
    
    def validate_json(self, json_str: str) -> bool:
        """Validate JSON string"""
        try:
            json.loads(json_str)
            return True
        except json.JSONDecodeError:
            return False
    
    def sanitize_json(self, json_str: str) -> Optional[Dict]:
        """Sanitize JSON input"""
        try:
            data = json.loads(json_str)
            return self.sanitize_dict(data)
        except json.JSONDecodeError:
            return None
    
    def sanitize_dict(self, data: Dict) -> Dict:
        """Recursively sanitize dictionary values"""
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                sanitized[key] = self.sanitize_text(value)
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [self.sanitize_text(item) if isinstance(item, str) else item for item in value]
            else:
                sanitized[key] = value
        return sanitized
    
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def validate_phone(self, phone: str) -> bool:
        """Validate phone number format"""
        pattern = r'^\+?1?\d{9,15}$'
        return bool(re.match(pattern, phone))
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        return all(0 <= int(x) <= 255 for x in ip.split('.'))
    
    def validate_file_extension(self, filename: str, allowed_extensions: List[str]) -> bool:
        """Validate file extension"""
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
    
    def validate_file_size(self, file_size: int, max_size: int) -> bool:
        """Validate file size"""
        return file_size <= max_size
    
    def validate_date(self, date_str: str, format: str = '%Y-%m-%d') -> bool:
        """Validate date format"""
        try:
            datetime.strptime(date_str, format)
            return True
        except ValueError:
            return False 