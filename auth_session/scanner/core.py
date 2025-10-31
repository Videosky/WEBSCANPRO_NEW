import uuid
import time
import json
import logging
import os  # ADD THIS IMPORT
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import hashlib
import random
from dataclasses import dataclass
import pandas as pd

from config import ScannerConfig, DataAnonymizer

@dataclass
class AuthEvent:
    event_id: str
    timestamp: str
    username: str
    user_id: str
    ip_address: str
    user_agent: str
    endpoint: str
    method: str
    status_code: int
    auth_result: str
    failure_reason: str
    session_id: str
    session_duration: float
    response_time: float
    request_size: int
    response_size: int
    
    # Computed fields
    attempt_count_for_username: int = 0
    attempt_count_from_ip: int = 0
    time_since_last_attempt_for_username: float = 0
    session_reused_flag: int = 0
    password_correct_flag: int = 0
    is_bruteforce_candidate: int = 0
    is_anomalous: int = 0
    notes: str = ""

class AttackPattern:
    def __init__(self, pattern_id: str, description: str, attempt_rate: int, distributed_flag: int, notes: str):
        self.pattern_id = pattern_id
        self.description = description
        self.attempt_rate = attempt_rate  # attempts per minute
        self.distributed_flag = distributed_flag
        self.notes = notes

class AuthScanner:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.anonymizer = DataAnonymizer(config.anonymization_salt)
        self.logger = self._setup_logger()
        
        # State tracking
        self.events: List[AuthEvent] = []
        self.session_tracker: Dict[str, List[Dict]] = {}
        self.attempt_counter = {
            'username': {},
            'ip': {}
        }
        
        # Load attack patterns
        self.attack_patterns = self._load_attack_patterns()
    
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger('auth_scanner')
        logger.setLevel(logging.INFO)
        
        # File handler for detailed logs
        log_file = f"logs/scan_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        os.makedirs('logs', exist_ok=True)  # This line was causing the error
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _load_attack_patterns(self) -> List[AttackPattern]:
        """Load attack patterns from CSV"""
        patterns = []
        try:
            df = pd.read_csv('data/attack_patterns.csv')
            for _, row in df.iterrows():
                pattern = AttackPattern(
                    pattern_id=row['pattern_id'],
                    description=row['description'],
                    attempt_rate=row['attempt_rate'],
                    distributed_flag=row['distributed_flag'],
                    notes=row['notes']
                )
                patterns.append(pattern)
        except FileNotFoundError:
            self.logger.warning("attack_patterns.csv not found, using defaults")
            # Default patterns
            patterns = [
                AttackPattern("BF_FAST", "Fast brute-force", 120, 0, "Rapid attempts"),
                AttackPattern("NORMAL", "Normal behavior", 2, 0, "Legitimate usage"),
            ]
        
        return patterns
    
    def _update_counters(self, username: str, ip: str, timestamp: datetime):
        """Update rolling window counters"""
        window_start = timestamp - timedelta(minutes=60)
        
        # Update username counter
        if username not in self.attempt_counter['username']:
            self.attempt_counter['username'][username] = []
        self.attempt_counter['username'][username].append(timestamp)
        
        # Remove old entries
        self.attempt_counter['username'][username] = [
            ts for ts in self.attempt_counter['username'][username] 
            if ts > window_start
        ]
        
        # Update IP counter
        if ip not in self.attempt_counter['ip']:
            self.attempt_counter['ip'][ip] = []
        self.attempt_counter['ip'][ip].append(timestamp)
        
        self.attempt_counter['ip'][ip] = [
            ts for ts in self.attempt_counter['ip'][ip] 
            if ts > window_start
        ]
    
    def _compute_attempt_counts(self, username: str, ip: str, timestamp: datetime) -> Tuple[int, int]:
        """Compute attempt counts for different windows"""
        username_attempts = 0
        ip_attempts = 0
        
        # 10-minute window for username
        window_10m = timestamp - timedelta(minutes=10)
        if username in self.attempt_counter['username']:
            username_attempts = len([
                ts for ts in self.attempt_counter['username'][username]
                if ts > window_10m
            ])
        
        # 10-minute window for IP
        if ip in self.attempt_counter['ip']:
            ip_attempts = len([
                ts for ts in self.attempt_counter['ip'][ip]
                if ts > window_10m
            ])
        
        return username_attempts, ip_attempts
    
    def _apply_labeling_heuristics(self, event: AuthEvent, events: List[AuthEvent]) -> AuthEvent:
        """Apply automated labeling heuristics"""
        
        # Brute-force candidate heuristics
        if (event.attempt_count_for_username >= 10 or 
            event.attempt_count_from_ip >= 50):
            event.is_bruteforce_candidate = 1
        
        # Account takeover heuristics
        recent_successes = [
            e for e in events 
            if e.username == event.username and 
               e.auth_result == 'success' and
               e.timestamp > (datetime.fromisoformat(event.timestamp) - timedelta(minutes=5)).isoformat()
        ]
        
        if (event.auth_result == 'success' and 
            len(recent_successes) > 0 and 
            any(e.ip_address != event.ip_address for e in recent_successes)):
            event.is_anomalous = 1
        
        # Session reuse detection
        if event.session_id:
            session_events = [
                e for e in events 
                if e.session_id == event.session_id and e.ip_address != event.ip_address
            ]
            if session_events:
                event.session_reused_flag = 1
                event.is_anomalous = 1
        
        return event
    
    def simulate_request(self, pattern: AttackPattern, username: str, password: str, 
                        ip: str, user_agent: str) -> AuthEvent:
        """Simulate authentication request"""
        
        timestamp = datetime.utcnow()
        event_id = str(uuid.uuid4())
        
        # Simulate response based on pattern and credentials
        if password == "correct_password":  # In real implementation, check against actual auth
            status_code = 200
            auth_result = "success"
            failure_reason = ""
            session_id = f"session_{hashlib.md5(f'{username}{timestamp}'.encode()).hexdigest()[:16]}"
            password_correct = 1
        else:
            status_code = 401
            auth_result = "failure"
            failure_reason = "bad_password"
            session_id = ""
            password_correct = 0
        
        # Update counters and compute metrics
        self._update_counters(username, ip, timestamp)
        username_attempts, ip_attempts = self._compute_attempt_counts(username, ip, timestamp)
        
        # Create event
        event = AuthEvent(
            event_id=event_id,
            timestamp=timestamp.isoformat(),
            username=self.anonymizer.anonymize(username),
            user_id=self.anonymizer.anonymize(f"user_{username}"),
            ip_address=self.anonymizer.anonymize(ip),
            user_agent=user_agent,
            endpoint="/login",
            method="POST",
            status_code=status_code,
            auth_result=auth_result,
            failure_reason=failure_reason,
            session_id=self.anonymizer.anonymize(session_id) if session_id else "",
            session_duration=0,
            response_time=random.uniform(0.1, 2.0),
            request_size=len(username) + len(password) + 50,  # Estimate
            response_size=random.randint(200, 2000),
            attempt_count_for_username=username_attempts,
            attempt_count_from_ip=ip_attempts,
            password_correct_flag=password_correct
        )
        
        # Apply labeling
        event = self._apply_labeling_heuristics(event, self.events)
        
        self.events.append(event)
        return event
    
    def run_attack_pattern(self, pattern: AttackPattern, duration_minutes: int = 10):
        """Execute a specific attack pattern"""
        self.logger.info(f"Running attack pattern: {pattern.pattern_id}")
        
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]
        
        while datetime.utcnow() < end_time:
            # Select target based on pattern
            if pattern.distributed_flag:
                ip = random.choice(self.config.attacker_ips)
                username = random.choice([u['username'] for u in self.config.test_users])
            else:
                ip = self.config.attacker_ips[0]
                username = self.config.test_users[0]['username']
            
            # Vary password based on pattern
            if "brute" in pattern.pattern_id.lower():
                password = f"guess_{random.randint(1000, 9999)}"
            else:
                password = random.choice(["correct_password", "wrong_password"])
            
            user_agent = random.choice(user_agents)
            
            # Make request
            self.simulate_request(pattern, username, password, ip, user_agent)
            
            # Control rate
            delay = 60.0 / pattern.attempt_rate if pattern.attempt_rate > 0 else 1.0
            time.sleep(delay + random.uniform(-0.1, 0.1))
    
    def save_events(self):
        """Save events to CSV and log files"""
        # Save raw events
        raw_log_file = f"data/raw_login_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        with open(raw_log_file, 'w') as f:
            for event in self.events:
                f.write(json.dumps(event.__dict__) + '\n')
        
        # Save to CSV dataset
        df = pd.DataFrame([event.__dict__ for event in self.events])
        df.to_csv('data/login_session_dataset.csv', index=False)
        
        self.logger.info(f"Saved {len(self.events)} events to dataset")