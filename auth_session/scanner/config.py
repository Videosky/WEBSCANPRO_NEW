import os
from dataclasses import dataclass
from typing import Dict, List, Optional
import hashlib
import hmac

@dataclass
class ScannerConfig:
    # Application endpoints
    login_url: str = "http://localhost:8000/api/login"
    logout_url: str = "http://localhost:8000/api/logout"
    session_check_url: str = "http://localhost:8000/api/session/check"
    
    # Test credentials
    test_users: List[Dict] = None
    attacker_ips: List[str] = None
    
    # Rate limiting settings
    max_attempts_per_minute: int = 60
    account_lockout_threshold: int = 5
    
    # Anonymization
    anonymization_salt: str = "auth-scanner-salt-2024"
    
    # Feature windows (minutes)
    feature_windows: List[int] = None
    
    def __post_init__(self):
        if self.test_users is None:
            self.test_users = [
                {"username": "user1", "password": "Password123!"},
                {"username": "user2", "password": "SecurePass456!"},
                {"username": "admin", "password": "Admin@12345"},
            ]
        
        if self.attacker_ips is None:
            self.attacker_ips = [
                "192.168.1.100", "192.168.1.101", "192.168.1.102",
                "10.0.0.50", "10.0.0.51", "10.0.0.52"
            ]
        
        if self.feature_windows is None:
            self.feature_windows = [5, 15, 60]  # 5min, 15min, 60min windows

class DataAnonymizer:
    def __init__(self, salt: str):
        self.salt = salt.encode()
    
    def anonymize(self, value: str) -> str:
        """HMAC-based anonymization preserving grouping ability"""
        if not value:
            return ""
        return hmac.new(self.salt, value.encode(), hashlib.sha256).hexdigest()[:16]