# sample_data_generator.py
import json
import pandas as pd
from datetime import datetime, timedelta
import os

def generate_sample_data():
    """Generate sample scan data for testing"""
    base_path = "C:/Users/vishal/Desktop/WEBSCAN_PRO/webscanprod_reports/data/scans"
    os.makedirs(base_path, exist_ok=True)
    
    print(f"📁 Creating sample data in: {base_path}")
    
    # Sample ZAP JSON data
    zap_data = {
        "vulnerabilities": [
            {
                "vuln_id": "ZAP-001",
                "vuln_name": "SQL Injection",
                "severity": "High",
                "description": "SQL injection vulnerability in login endpoint",
                "affected_url": "https://example.com/login",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "recommendation": "Use parameterized queries and input validation"
            },
            {
                "vuln_id": "ZAP-002", 
                "vuln_name": "XSS",
                "severity": "Medium",
                "description": "Cross-site scripting in search functionality",
                "affected_url": "https://example.com/search",
                "timestamp": (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S'),
                "recommendation": "Implement output encoding"
            },
            {
                "vuln_id": "ZAP-003",
                "vuln_name": "Information Disclosure",
                "severity": "Low",
                "description": "Sensitive information exposed in error messages",
                "affected_url": "https://example.com/api/users",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "recommendation": "Implement proper error handling"
            }
        ]
    }
    
    zap_file = os.path.join(base_path, "zap_scan_2025_11_10.json")
    with open(zap_file, 'w', encoding='utf-8') as f:
        json.dump(zap_data, f, indent=2)
    print(f"✅ Created ZAP scan: {zap_file}")
    
    # Sample Burp CSV data
    burp_data = {
        'vuln_id': ['BURP-001', 'BURP-002', 'BURP-003', 'BURP-004'],
        'vuln_name': ['SQL Injection', 'CSRF', 'Information Disclosure', 'Insecure Headers'],
        'severity': ['High', 'Medium', 'Low', 'Medium'],
        'description': [
            'SQL injection in user registration form',
            'Missing CSRF protection in profile update',
            'Directory listing enabled in images folder',
            'Missing security headers in HTTP responses'
        ],
        'affected_url': [
            'https://example.com/register',
            'https://example.com/update_profile', 
            'https://example.com/images/',
            'https://example.com/'
        ],
        'timestamp': [datetime.now().strftime('%Y-%m-%d %H:%M:%S')] * 4,
        'recommendation': [
            'Use prepared statements and input validation',
            'Add CSRF tokens to all state-changing requests',
            'Disable directory listing in server configuration',
            'Implement security headers like X-Content-Type-Options'
        ]
    }
    
    burp_df = pd.DataFrame(burp_data)
    burp_file = os.path.join(base_path, "burp_scan_2025_11_11.csv")
    burp_df.to_csv(burp_file, index=False)
    print(f"✅ Created Burp scan: {burp_file}")
    
    # Sample ML scanner data
    ml_data = {
        'id': ['ML-001', 'ML-002', 'ML-003'],
        'name': ['XSS', 'Insecure Cookies', 'Security Misconfiguration'],
        'risk': ['Medium', 'Medium', 'Low'], 
        'detail': [
            'Reflected XSS detected in contact form',
            'Missing secure and httpOnly flags on session cookies',
            'Default files and directories accessible'
        ],
        'url': [
            'https://example.com/contact',
            'https://example.com/',
            'https://example.com/admin/'
        ],
        'solution': [
            'Implement proper input sanitization and output encoding',
            'Set secure and httpOnly flags on all cookies',
            'Remove or secure default files and directories'
        ]
    }
    
    ml_df = pd.DataFrame(ml_data)
    ml_file = os.path.join(base_path, "ml_scan_2025_11_12.csv")
    ml_df.to_csv(ml_file, index=False)
    print(f"✅ Created ML scan: {ml_file}")
    
    # Sample Nessus XML data (simplified)
    nessus_data = """<?xml version="1.0"?>
<NessusClientData_v2>
    <Report>
        <ReportHost name="example.com">
            <ReportItem>
                <serialNumber>NESSUS-001</serialNumber>
                <name>SSL/TLS Weak Cipher Suites</name>
                <risk_factor>Medium</risk_factor>
                <description>Server supports weak SSL/TLS cipher suites</description>
                <host>https://example.com:443</host>
                <solution>Disable weak cipher suites and use strong encryption</solution>
            </ReportItem>
            <ReportItem>
                <serialNumber>NESSUS-002</serialNumber>
                <name>HTTP Security Headers Missing</name>
                <risk_factor>Low</risk_factor>
                <description>Missing security headers in HTTP responses</description>
                <host>https://example.com</host>
                <solution>Implement security headers like HSTS, X-Frame-Options</solution>
            </ReportItem>
        </ReportHost>
    </Report>
</NessusClientData_v2>"""
    
    nessus_file = os.path.join(base_path, "nessus_scan_2025_11_13.xml")
    with open(nessus_file, 'w', encoding='utf-8') as f:
        f.write(nessus_data)
    print(f"✅ Created Nessus scan: {nessus_file}")
    
    print(f"\n📊 Sample Data Summary:")
    print(f"   - ZAP: 3 vulnerabilities")
    print(f"   - Burp: 4 vulnerabilities") 
    print(f"   - ML: 3 vulnerabilities")
    print(f"   - Nessus: 2 vulnerabilities")
    print(f"   Total: 12 sample vulnerabilities created")
    print(f"\n🎯 Now run: python scripts/merge_and_report.py")

if __name__ == "__main__":
    generate_sample_data()