import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import hashlib
from typing import List, Dict
import os
import time
import requests
from urllib.parse import urlparse
import logging

def get_project_root():
    """Get the project root directory dynamically"""
    current_file = os.path.abspath(__file__)
    project_root = os.path.dirname(os.path.dirname(current_file))
    return project_root

def setup_logging():
    """Setup logging with timestamped log files"""
    project_root = get_project_root()
    log_dir = os.path.join(project_root, "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Generate timestamps
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Configure log files
    raw_login_log = os.path.join(log_dir, f"raw_login_events_{timestamp}.log")
    scan_run_log = os.path.join(log_dir, f"scan_run_{timestamp}.log")
    
    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(scan_run_log),  # Main scan log
            logging.FileHandler(raw_login_log), # Raw events log  
            logging.StreamHandler()  # Also output to console
        ]
    )
    
    logger = logging.getLogger('auth_scanner')
    logger.info(f"Logging initialized. Scan log: {scan_run_log}")
    logger.info(f"Raw events log: {raw_login_log}")
    
    return logger, raw_login_log, scan_run_log

class AuthScanner:
    def __init__(self, target_url: str = None):
        self.target_url = target_url or "http://localhost:8080/login"
        self.session = requests.Session()
        self.results = []
        
        # Setup logging
        self.logger, self.raw_log_path, self.scan_log_path = setup_logging()
    
    def load_attack_patterns(self, filepath: str) -> pd.DataFrame:
        """Load attack patterns from CSV and enhance with Dataset 1 parameters"""
        try:
            # Use absolute path if relative doesn't work
            if not os.path.exists(filepath):
                project_root = get_project_root()
                filepath = os.path.join(project_root, "data", "attack_patterns.csv")
            
            df = pd.read_csv(filepath)
            self.logger.info(f"Loaded attack patterns from {filepath}")
            self.logger.info(f"Columns found: {df.columns.tolist()}")
            
            # Enhance patterns with Dataset 1 parameters
            enhanced_patterns = self._enhance_patterns(df)
            return enhanced_patterns
            
        except Exception as e:
            self.logger.warning(f"Could not load {filepath}, using defaults: {e}")
            return self._get_default_patterns()
    
    def _enhance_patterns(self, df):
        """Add Dataset 1 specific parameters to patterns"""
        success_rates = {
            'NORMAL_SINGLE': 0.7,      # Normal traffic - high success
            'NORMAL_MULTI': 0.7,       # Normal traffic - high success  
            'BF_FAST_RAPID': 0.45,     # Mixed success brute force
            'BF_FAST_MULTI': 0.45,     # Mixed success brute force
            'BF_SLOW_LOW': 0.3,        # Lower success slow brute force
            'CRED_STUFF_SINGLE': 0.58, # Credential stuffing with mixed success
            'CRED_STUFF_DIST': 0.58,   # Credential stuffing with mixed success
            'DIST_BF_CONSIST': 0.4,    # Distributed with some success
            'DIST_BF_BURST': 0.35,     # Burst attacks with some success
            'ATO_FAIL2SUCCESS': 0.6,    # Account takeover attempts
            'ATO_GEO_HOP': 0.5,        # Geographic hopping
            'SESSION_HIJACK': 0.7,      # Session attacks often succeed
            'SESSION_FIXATION': 0.65,   # Session fixation
            'MIXED_BLEND': 0.55,       # Mixed techniques
            'RATE_LIMIT_TEST': 0.2,    # Rate limit testing - low success
            'SCAN_RECON': 0.1          # Reconnaissance - very low success
        }
        
        # Add success rates and user agent variety
        df['success_rate'] = df['pattern_id'].map(success_rates).fillna(0.3)
        df['user_agent_variety'] = 3  # Multiple user agents like Dataset 1
        df['is_attack'] = ~df['pattern_id'].str.contains('NORMAL')
        
        return df
    
    def _get_default_patterns(self):
        """Create realistic attack patterns for Dataset 1"""
        data = {
            'pattern_id': ['CRED_STUFFING', 'BF_MIXED', 'PASSWORD_SPRAY', 'NORMAL'],
            'description': ['Credential stuffing with mixed success', 'Mixed brute force', 'Password spraying', 'Normal traffic'],
            'attempt_rate': [2.5, 1.8, 0.8, 0.3],
            'distributed_flag': [1, 0, 1, 0],
            'success_rate': [0.58, 0.45, 0.15, 0.7],
            'user_agent_variety': [3, 2, 1, 1],
            'is_attack': [1, 1, 1, 0],
            'notes': ['Mixed success/failure, multiple UAs', 'Some success, single IP', 'Low success, distributed', 'Legitimate traffic']
        }
        return pd.DataFrame(data)
    
    def log_raw_event(self, event_data: Dict):
        """Log raw login events to the raw events log file"""
        try:
            with open(self.raw_log_path, 'a') as f:
                f.write(f"{datetime.now().isoformat()} - {event_data}\n")
        except Exception as e:
            self.logger.error(f"Failed to log raw event: {e}")
    
    def simulate_normal_traffic(self, duration_minutes: int = 120):
        """Generate realistic normal user traffic patterns"""
        self.logger.info("Generating normal user traffic...")
        normal_events = []
        base_time = datetime.now()
        
        for i in range(500):
            time_offset = np.random.exponential(duration_minutes)
            event_time = base_time - timedelta(minutes=min(time_offset, duration_minutes))
            
            user_id = np.random.randint(1, 10)
            event = {
                'timestamp': event_time,
                'username': f"user_{user_id}",
                'user_id': f"usr{user_id:02d}",
                'ip_address': f"192.168.1.{np.random.randint(100,200)}",
                'auth_result': 'success' if np.random.random() > 0.25 else 'failure',
                'session_id': f"norm_sess_{np.random.randint(1000,9999)}",
                'user_agent': "Browser_1",
                'session_duration': np.random.randint(500, 3600),
                'response_time': np.random.uniform(0.1, 1.5),
                'request_size': np.random.randint(65, 75),
                'response_size': np.random.randint(800, 2000),
                'attempt_count_for_username': np.random.randint(1, 5),
                'attempt_count_from_ip': np.random.randint(1, 8),
                'time_since_last_attempt': np.random.randint(300, 3600),
                'session_reused_flag': 1 if np.random.random() > 0.8 else 0,
                'password_correct_flag': 1,
                'is_bruteforce_candidate': 0,
                'is_anomalous': 0,
                'failure_reason': '' if np.random.random() > 0.25 else 'bad_password'
            }
            
            if event['auth_result'] == 'failure':
                event['password_correct_flag'] = 0
                
            normal_events.append(event)
            self.log_raw_event(event)
            
        return pd.DataFrame(normal_events)
    
    def execute_attack_pattern(self, pattern):
        """Execute realistic attack pattern with mixed success/failure"""
        pattern_id = pattern['pattern_id']
        attempt_rate = pattern['attempt_rate']
        distributed = pattern['distributed_flag']
        success_rate = pattern['success_rate']
        ua_variety = pattern['user_agent_variety']
        is_attack = pattern['is_attack']
        
        self.logger.info(f"Executing pattern: {pattern_id} (success rate: {success_rate}, attack: {is_attack})")
        
        max_attempts = int(min(attempt_rate * 30, 200))
        attack_events = []
        base_time = datetime.now()
        
        if 'CRED_STUFF' in pattern_id:
            attack_ip = "5ab4238564ae43fa"
            target_username = "b7ee295dbbb7ad33"
        else:
            attack_ip = f"10.0.1.{np.random.randint(1,20)}" if distributed else f"10.0.1.1"
            target_username = "admin" if np.random.random() > 0.6 else f"user_{np.random.randint(1,8)}"
        
        for i in range(max_attempts):
            time_jitter = np.random.normal(60/attempt_rate, 10)
            event_time = base_time - timedelta(seconds=i * max(1, time_jitter))
            
            if is_attack:
                if np.random.random() < success_rate:
                    auth_result = 'success'
                    session_duration = np.random.randint(100, 5000)
                    password_correct = 1
                    failure_reason = ''
                else:
                    auth_result = 'failure'
                    session_duration = 0 if np.random.random() > 0.4 else np.random.randint(1, 100)
                    password_correct = 0
                    failure_reason = 'bad_password'
            else:
                auth_result = 'success' if np.random.random() > 0.2 else 'failure'
                session_duration = np.random.randint(300, 4000)
                password_correct = 1 if auth_result == 'success' else 0
                failure_reason = '' if auth_result == 'success' else 'bad_password'
            
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36", 
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            ]
            
            if is_attack and ua_variety > 1:
                user_agent = user_agents[i % ua_variety]
            else:
                user_agent = "Browser_1"
            
            event = {
                'timestamp': event_time,
                'username': target_username if is_attack else f"user_{np.random.randint(1,10)}",
                'user_id': f"usr{np.random.randint(1,20):02d}",
                'ip_address': attack_ip if is_attack else f"192.168.1.{np.random.randint(100,200)}",
                'auth_result': auth_result,
                'session_id': f"sess_{np.random.randint(1000,9999)}" if np.random.random() > 0.3 else "",
                'user_agent': user_agent,
                'session_duration': session_duration,
                'response_time': np.random.uniform(0.1, 2.0),
                'request_size': np.random.randint(65, 75),
                'response_size': np.random.randint(800, 2000),
                'attempt_count_for_username': i + 1,
                'attempt_count_from_ip': i + 1,
                'time_since_last_attempt': np.random.randint(1, 60),
                'session_reused_flag': 0 if is_attack else (1 if np.random.random() > 0.8 else 0),
                'password_correct_flag': password_correct,
                'is_bruteforce_candidate': 1 if is_attack and attempt_rate > 1 else 0,
                'is_anomalous': 1 if is_attack else 0,
                'failure_reason': failure_reason
            }
            attack_events.append(event)
            self.log_raw_event(event)
            
        return pd.DataFrame(attack_events)
    
    def run_scan(self, patterns_file: str, output_file: str):
        """Run complete authentication scan"""
        self.logger.info("Starting authentication scan for Dataset 1 generation...")
        
        patterns_df = self.load_attack_patterns(patterns_file)
        all_events = []
        
        self.logger.info("Generating normal traffic...")
        normal_df = self.simulate_normal_traffic(duration_minutes=120)
        all_events.append(normal_df)
        
        for _, pattern in patterns_df.iterrows():
            self.logger.info(f"Executing pattern: {pattern['pattern_id']}")
            pattern_df = self.execute_attack_pattern(pattern)
            all_events.append(pattern_df)
            time.sleep(0.1)
        
        combined_df = pd.concat(all_events, ignore_index=True)
        combined_df = combined_df.sort_values('timestamp').reset_index(drop=True)
        combined_df['event_id'] = [f"evt_{i}" for i in range(len(combined_df))]
        combined_df['timestamp'] = pd.to_datetime(combined_df['timestamp'])
        combined_df['notes'] = ''
        
        combined_df.to_csv(output_file, index=False)
        
        total_events = len(combined_df)
        normal_events = len(combined_df[combined_df['is_anomalous'] == 0])
        attack_events = len(combined_df[combined_df['is_anomalous'] == 1])
        overall_success_rate = (combined_df['auth_result'] == 'success').sum() / total_events
        
        self.logger.info(f"Scan completed! Generated {total_events} events")
        self.logger.info(f"Normal events: {normal_events}, Attack events: {attack_events}")
        self.logger.info(f"Overall success rate: {overall_success_rate:.2%}")
        self.logger.info(f"Results saved to: {output_file}")
        self.logger.info(f"Raw events logged to: {self.raw_log_path}")
        self.logger.info(f"Scan log: {self.scan_log_path}")
        
        return combined_df

def main():
    """Main function to run the authentication scanner"""
    scanner = AuthScanner()
    
    # Use dynamic paths based on project structure
    project_root = get_project_root()
    patterns_file = os.path.join(project_root, "data", "attack_patterns.csv")
    output_file = os.path.join(project_root, "data", "login_session_dataset_type1.csv")
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    try:
        results_df = scanner.run_scan(patterns_file, output_file)
        
        print("\n=== DATASET 1 GENERATION COMPLETE ===")
        print(f"Total events: {len(results_df)}")
        print(f"Normal events: {len(results_df[results_df['is_anomalous'] == 0])}")
        print(f"Attack events: {len(results_df[results_df['is_anomalous'] == 1])}")
        print(f"Output file: {output_file}")
        print(f"Log files created in 'logs' directory")
        
        # Show sample
        print("\nSample of generated data:")
        sample_df = results_df[['timestamp', 'username', 'ip_address', 'auth_result', 'is_anomalous', 'user_agent']].head(10)
        print(sample_df)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()