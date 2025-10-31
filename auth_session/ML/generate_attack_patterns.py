#!/usr/bin/env python3
"""
Generate attack_patterns.csv with comprehensive authentication attack scenarios
"""

import pandas as pd
import os

def generate_attack_patterns():
    """Generate comprehensive attack patterns for authentication testing"""
    
    patterns = [
        # Normal behavior patterns
        {
            'pattern_id': 'NORMAL_SINGLE',
            'description': 'Normal single user behavior',
            'attempt_rate': 2,
            'distributed_flag': 0,
            'notes': 'Legitimate user with occasional login/logout'
        },
        {
            'pattern_id': 'NORMAL_MULTI',
            'description': 'Normal multiple users',
            'attempt_rate': 5,
            'distributed_flag': 0,
            'notes': 'Multiple legitimate users from different IPs'
        },
        
        # Brute-force attacks
        {
            'pattern_id': 'BF_FAST_RAPID',
            'description': 'Rapid brute-force single account',
            'attempt_rate': 120,
            'distributed_flag': 0,
            'notes': '10 attempts/minute from single IP'
        },
        {
            'pattern_id': 'BF_FAST_MULTI',
            'description': 'Fast brute-force multiple accounts',
            'attempt_rate': 90,
            'distributed_flag': 0,
            'notes': 'Single IP targeting multiple usernames'
        },
        {
            'pattern_id': 'BF_SLOW_LOW',
            'description': 'Slow low-and-slow attack',
            'attempt_rate': 12,
            'distributed_flag': 0,
            'notes': '1 attempt/5 minutes to evade detection'
        },
        
        # Credential stuffing
        {
            'pattern_id': 'CRED_STUFF_SINGLE',
            'description': 'Credential stuffing single IP',
            'attempt_rate': 60,
            'distributed_flag': 0,
            'notes': 'Single IP testing breached credentials'
        },
        {
            'pattern_id': 'CRED_STUFF_DIST',
            'description': 'Distributed credential stuffing',
            'attempt_rate': 30,
            'distributed_flag': 1,
            'notes': 'Multiple IPs testing credential pairs'
        },
        
        # Distributed attacks
        {
            'pattern_id': 'DIST_BF_CONSIST',
            'description': 'Distributed brute-force consistent',
            'attempt_rate': 25,
            'distributed_flag': 1,
            'notes': 'Multiple IPs targeting single account'
        },
        {
            'pattern_id': 'DIST_BF_BURST',
            'description': 'Distributed brute-force burst',
            'attempt_rate': 80,
            'distributed_flag': 1,
            'notes': 'Burst attacks from many IPs'
        },
        
        # Account takeover patterns
        {
            'pattern_id': 'ATO_FAIL2SUCCESS',
            'description': 'Account takeover after failures',
            'attempt_rate': 8,
            'distributed_flag': 0,
            'notes': 'Failed attempts followed by success'
        },
        {
            'pattern_id': 'ATO_GEO_HOP',
            'description': 'Geolocation hopping attack',
            'attempt_rate': 15,
            'distributed_flag': 1,
            'notes': 'Rapid logins from different countries'
        },
        
        # Session attacks
        {
            'pattern_id': 'SESSION_HIJACK',
            'description': 'Session hijack simulation',
            'attempt_rate': 3,
            'distributed_flag': 1,
            'notes': 'Session token reuse across IPs'
        },
        {
            'pattern_id': 'SESSION_FIXATION',
            'description': 'Session fixation attempts',
            'attempt_rate': 5,
            'distributed_flag': 0,
            'notes': 'Forcing known session tokens'
        },
        
        # Complex/mixed attacks
        {
            'pattern_id': 'MIXED_BLEND',
            'description': 'Mixed attack patterns',
            'attempt_rate': 45,
            'distributed_flag': 1,
            'notes': 'Combination of multiple techniques'
        },
        
        # Testing patterns
        {
            'pattern_id': 'RATE_LIMIT_TEST',
            'description': 'Rate limit testing',
            'attempt_rate': 200,
            'distributed_flag': 0,
            'notes': 'Testing application rate limits'
        },
        {
            'pattern_id': 'SCAN_RECON',
            'description': 'Reconnaissance scanning',
            'attempt_rate': 20,
            'distributed_flag': 0,
            'notes': 'Username enumeration and system probing'
        }
    ]
    
    # Create DataFrame with only the required columns
    df = pd.DataFrame(patterns)
    
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)
    
    # Save to CSV
    output_file = 'data/attack_patterns.csv'
    df.to_csv(output_file, index=False)
    
    print(f"Generated {len(patterns)} attack patterns")
    print(f"Saved to: {output_file}")
    
    # Print summary
    print("\n=== ATTACK PATTERNS SUMMARY ===")
    print(f"Total patterns: {len(patterns)}")
    print(f"Normal patterns: {len([p for p in patterns if 'NORMAL' in p['pattern_id']])}")
    print(f"Attack patterns: {len([p for p in patterns if not 'NORMAL' in p['pattern_id']])}")
    print(f"Distributed attacks: {len([p for p in patterns if p['distributed_flag'] == 1])}")
    print(f"High-rate attacks (>50/min): {len([p for p in patterns if p['attempt_rate'] > 50])}")
    
    return df

if __name__ == "__main__":
    generate_attack_patterns()