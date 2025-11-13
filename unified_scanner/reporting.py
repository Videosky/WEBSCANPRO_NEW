"""
Reporting module for Unified Vulnerability Scanner
"""

import json
import csv
import logging
from datetime import datetime
from typing import List, Dict, Any
from tabulate import tabulate
import os
import sys

# Add current directory to path for local imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from config import SCAN_REPORTS_DIR, get_report_filename

logger = logging.getLogger("unified_scanner.reporting")

class ReportGenerator:
    def __init__(self, output_file: str = None):
        self.output_file = output_file or get_report_filename()
        self.results = []
        self.scan_start_time = datetime.now()
    
    def add_result(self, result: Dict[str, Any]):
        """Add a scan result to the report"""
        self.results.append(result)
    
    def generate_json_report(self) -> str:
        """Generate comprehensive JSON report"""
        report = {
            "metadata": {
                "scan_timestamp": self.scan_start_time.isoformat(),
                "scan_duration_seconds": (datetime.now() - self.scan_start_time).total_seconds(),
                "total_urls_scanned": len(self.results),
                "total_xss_detected": sum(1 for r in self.results if r.get("xss", {}).get("is_malicious", False)),
                "total_sqli_detected": sum(1 for r in self.results if r.get("sqli", {}).get("is_malicious", False)),
                "total_vulnerabilities": sum(1 for r in self.results if 
                    r.get("xss", {}).get("is_malicious", False) or 
                    r.get("sqli", {}).get("is_malicious", False))
            },
            "scan_config": {
                "xss_threshold": 0.75,
                "sqli_threshold": 0.70,
                "max_payloads_per_type": 20
            },
            "results": self.results
        }
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report saved: {self.output_file}")
        return self.output_file
    
    def generate_csv_report(self, csv_file: str = None) -> str:
        """Generate simplified CSV report"""
        if not csv_file:
            csv_file = self.output_file.replace('.json', '.csv')
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "URL", "XSS_Detected", "XSS_Probability", "XSS_Method",
                "SQLi_Detected", "SQLi_Probability", "SQLi_Method", 
                "Risk_Level", "Scan_Time"
            ])
            
            for result in self.results:
                url = result.get("url", "")
                
                xss_result = result.get("xss", {})
                xss_detected = xss_result.get("is_malicious", False)
                xss_prob = xss_result.get("prob", 0.0)
                xss_method = xss_result.get("method", "unknown")
                
                sqli_result = result.get("sqli", {})
                sqli_detected = sqli_result.get("is_malicious", False)
                sqli_prob = sqli_result.get("prob", 0.0)
                sqli_method = sqli_result.get("method", "unknown")
                
                risk_score = max(xss_prob, sqli_prob)
                risk_level = "High" if risk_score >= 0.8 else "Medium" if risk_score >= 0.6 else "Low"
                
                writer.writerow([
                    url,
                    xss_detected,
                    f"{xss_prob:.4f}",
                    xss_method,
                    sqli_detected,
                    f"{sqli_prob:.4f}",
                    sqli_method,
                    risk_level,
                    result.get("scan_timestamp", "")
                ])
        
        logger.info(f"CSV report saved: {csv_file}")
        return csv_file
    
    def generate_console_summary(self):
        """Generate console-friendly summary table"""
        if not self.results:
            print("No scan results to display")
            return
        
        table_data = []
        
        for result in self.results:
            url = result.get("url", "Unknown")
            
            # XSS results
            xss_result = result.get("xss", {})
            xss_detected = "✓" if xss_result.get("is_malicious", False) else "✗"
            xss_prob = xss_result.get("prob", 0.0)
            xss_method = xss_result.get("method", "unknown")[:1].upper()
            xss_display = f"{xss_detected} {xss_prob:.2f} ({xss_method})"
            
            # SQLi results
            sqli_result = result.get("sqli", {})
            sqli_detected = "✓" if sqli_result.get("is_malicious", False) else "✗"
            sqli_prob = sqli_result.get("prob", 0.0)
            sqli_method = sqli_result.get("method", "unknown")[:1].upper()
            sqli_display = f"{sqli_detected} {sqli_prob:.2f} ({sqli_method})"
            
            # Risk score calculation
            risk_score = max(xss_prob, sqli_prob)
            if risk_score >= 0.8:
                risk_level = "HIGH"
            elif risk_score >= 0.6:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
            
            table_data.append([
                url[:40] + "..." if len(url) > 40 else url,
                xss_display,
                sqli_display,
                risk_level
            ])
        
        headers = ["URL", "XSS", "SQLi", "Risk"]
        print("\n" + "="*80)
        print("VULNERABILITY SCAN SUMMARY")
        print("="*80)
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Summary statistics
        total_xss = sum(1 for r in self.results if r.get("xss", {}).get("is_malicious", False))
        total_sqli = sum(1 for r in self.results if r.get("sqli", {}).get("is_malicious", False))
        total_vuln = sum(1 for r in self.results if 
            r.get("xss", {}).get("is_malicious", False) or 
            r.get("sqli", {}).get("is_malicious", False))
        
        print(f"\nSUMMARY:")
        print(f"Total URLs scanned: {len(self.results)}")
        print(f"XSS vulnerabilities detected: {total_xss}")
        print(f"SQLi vulnerabilities detected: {total_sqli}")
        print(f"Total vulnerabilities found: {total_vuln}")
        print(f"Scan duration: {(datetime.now() - self.scan_start_time).total_seconds():.2f} seconds")
        
        # Legend
        print(f"\nLEGEND: ✓=Vulnerable, ✗=Safe, (M)=ML, (R)=Rule-based")