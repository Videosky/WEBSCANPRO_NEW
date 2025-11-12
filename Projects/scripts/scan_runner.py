"""
WebScanProd - Scan Runner for Windows
Handles importing and parsing raw vulnerability scan results
"""

import json
import csv
import os
import pandas as pd
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ScanProcessor:
    def __init__(self, base_path="."):
        self.base_path = Path(base_path)
        self.raw_findings_path = self.base_path / "data" / "raw_findings"
        self.processed_path = self.base_path / "data" / "processed"
        
        # Ensure directories exist
        self.processed_path.mkdir(parents=True, exist_ok=True)
        
    def load_raw_findings(self):
        """Load and parse all raw scan files"""
        all_findings = []
        
        for file_path in self.raw_findings_path.iterdir():
            if file_path.is_file():
                try:
                    if file_path.suffix.lower() == '.json':
                        findings = self.parse_json_findings(file_path)
                    elif file_path.suffix.lower() == '.xml':
                        findings = self.parse_xml_findings(file_path)
                    elif file_path.suffix.lower() == '.csv':
                        findings = self.parse_csv_findings(file_path)
                    else:
                        logger.warning(f"Unsupported file format: {file_path}")
                        continue
                    
                    all_findings.extend(findings)
                    logger.info(f"Processed {len(findings)} findings from {file_path.name}")
                    
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {str(e)}")
        
        return all_findings
    
    def parse_json_findings(self, file_path):
        """Parse JSON format scan results"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        findings = []
        if 'vulnerabilities' in data:
            for vuln in data['vulnerabilities']:
                finding = {
                    'vuln_id': vuln.get('vuln_id', ''),
                    'vuln_name': vuln.get('vuln_name', ''),
                    'description': vuln.get('description', ''),
                    'severity': vuln.get('severity', ''),
                    'affected_url': vuln.get('affected_url', ''),
                    'impact': vuln.get('impact', ''),
                    'recommendation': vuln.get('recommendation', '')
                }
                findings.append(finding)
        
        return findings
    
    def parse_xml_findings(self, file_path):
        """Parse XML format scan results - placeholder implementation"""
        # XML parsing would be implemented based on your specific scanner's format
        logger.warning(f"XML parsing not fully implemented for {file_path}")
        return []
    
    def parse_csv_findings(self, file_path):
        """Parse CSV format scan results"""
        findings = []
        try:
            with open(file_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    finding = {
                        'vuln_id': row.get('vuln_id', ''),
                        'vuln_name': row.get('vuln_name', ''),
                        'description': row.get('description', ''),
                        'severity': row.get('severity', ''),
                        'affected_url': row.get('affected_url', ''),
                        'impact': row.get('impact', ''),
                        'recommendation': row.get('recommendation', '')
                    }
                    findings.append(finding)
        except Exception as e:
            logger.error(f"Error parsing CSV file {file_path}: {str(e)}")
        
        return findings
    
    def categorize_severity(self, severity):
        """Normalize and categorize severity levels"""
        severity_map = {
            'critical': 'Critical',
            'high': 'High', 
            'medium': 'Medium',
            'low': 'Low',
            'informational': 'Low'
        }
        return severity_map.get(severity.lower(), 'Unknown')
    
    def save_processed_findings(self, findings):
        """Save processed findings to CSV"""
        output_file = self.processed_path / "findings.csv"
        
        # Normalize severity levels
        for finding in findings:
            finding['severity'] = self.categorize_severity(finding['severity'])
        
        # Create DataFrame and save
        df = pd.DataFrame(findings)
        df.to_csv(output_file, index=False)
        logger.info(f"Saved {len(findings)} processed findings to {output_file}")
        
        return df
    
    def generate_severity_summary(self, df):
        """Generate severity summary statistics"""
        severity_counts = df['severity'].value_counts()
        total_vulnerabilities = len(df)
        
        summary = {
            'total_vulnerabilities': total_vulnerabilities,
            'critical_count': severity_counts.get('Critical', 0),
            'high_count': severity_counts.get('High', 0),
            'medium_count': severity_counts.get('Medium', 0),
            'low_count': severity_counts.get('Low', 0)
        }
        
        return summary

def main():
    """Main execution function"""
    processor = ScanProcessor()
    
    # Load and process raw findings
    logger.info("Loading raw vulnerability findings...")
    findings = processor.load_raw_findings()
    
    if not findings:
        logger.warning("No findings processed. Check raw data files.")
        return
    
    # Save processed findings
    logger.info("Saving processed findings...")
    df = processor.save_processed_findings(findings)
    
    # Generate summary
    summary = processor.generate_severity_summary(df)
    logger.info(f"Vulnerability Summary: {summary}")

if __name__ == "__main__":
    main()