"""
WebScanProd - Report Validation Script for Windows
Validates that all deliverables meet requirements
"""

import pandas as pd
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReportValidator:
    def __init__(self, base_path="."):
        self.base_path = Path(base_path)
        
    def run_validation_checklist(self):
        """Run complete validation checklist"""
        checklist = {
            'raw_findings_exist': self.check_raw_findings(),
            'processed_findings_exist': self.check_processed_findings(),
            'findings_parsed_successfully': self.check_findings_parsing(),
            'vulnerabilities_categorized': self.check_severity_categorization(),
            'descriptions_valid': self.check_descriptions(),
            'mitigations_valid': self.check_mitigations(),
            'reports_generated': self.check_reports_generated(),
            'summary_counts_match': self.check_summary_counts()
        }
        
        # Print validation results
        print("WebScanProd Validation Checklist Results:")
        print("=" * 50)
        
        all_passed = True
        for check_name, result in checklist.items():
            status = "PASS" if result['passed'] else "FAIL"
            print(f"{status} - {check_name}")
            if not result['passed']:
                print(f"       Details: {result.get('details', 'N/A')}")
                all_passed = False
        
        print("=" * 50)
        print(f"Overall Validation: {'PASSED' if all_passed else 'FAILED'}")
        
        return all_passed
    
    def check_raw_findings(self):
        """Check if raw findings exist"""
        raw_path = self.base_path / "data" / "raw_findings"
        files = list(raw_path.glob("*"))
        return {
            'passed': len(files) > 0,
            'details': f"Found {len(files)} raw finding files"
        }
    
    def check_processed_findings(self):
        """Check if processed findings CSV exists"""
        processed_file = self.base_path / "data" / "processed" / "findings.csv"
        exists = processed_file.exists()
        return {
            'passed': exists,
            'details': f"Processed findings: {'Exists' if exists else 'Missing'}"
        }
    
    def check_findings_parsing(self):
        """Check if findings were parsed successfully"""
        try:
            processed_file = self.base_path / "data" / "processed" / "findings.csv"
            if not processed_file.exists():
                return {'passed': False, 'details': 'Processed file missing'}
            
            df = pd.read_csv(processed_file)
            required_columns = ['vuln_id', 'vuln_name', 'severity', 'affected_url', 'description', 'recommendation']
            has_required_columns = all(col in df.columns for col in required_columns)
            
            return {
                'passed': has_required_columns and len(df) > 0,
                'details': f"Found {len(df)} findings with required columns"
            }
        except Exception as e:
            return {'passed': False, 'details': str(e)}
    
    def check_severity_categorization(self):
        """Check if all vulnerabilities have valid severity levels"""
        try:
            processed_file = self.base_path / "data" / "processed" / "findings.csv"
            df = pd.read_csv(processed_file)
            
            valid_severities = ['Critical', 'High', 'Medium', 'Low']
            invalid_severities = df[~df['severity'].isin(valid_severities)]
            
            return {
                'passed': len(invalid_severities) == 0,
                'details': f"All {len(df)} findings have valid severity levels"
            }
        except Exception as e:
            return {'passed': False, 'details': str(e)}
    
    def check_descriptions(self):
        """Check if all findings have valid descriptions"""
        try:
            processed_file = self.base_path / "data" / "processed" / "findings.csv"
            df = pd.read_csv(processed_file)
            
            missing_descriptions = df[df['description'].isna() | (df['description'] == '')]
            
            return {
                'passed': len(missing_descriptions) == 0,
                'details': f"All {len(df)} findings have descriptions"
            }
        except Exception as e:
            return {'passed': False, 'details': str(e)}
    
    def check_mitigations(self):
        """Check if all findings have mitigation recommendations"""
        try:
            processed_file = self.base_path / "data" / "processed" / "findings.csv"
            df = pd.read_csv(processed_file)
            
            missing_recommendations = df[df['recommendation'].isna() | (df['recommendation'] == '')]
            
            return {
                'passed': len(missing_recommendations) == 0,
                'details': f"All {len(df)} findings have mitigation recommendations"
            }
        except Exception as e:
            return {'passed': False, 'details': str(e)}
    
    def check_reports_generated(self):
        """Check if all report formats were generated"""
        reports_path = self.base_path / "reports"
        required_reports = [
            'webscan_summary.md',
            'vulnerability_report.pdf', 
            'vulnerability_report.docx'
        ]
        
        missing_reports = []
        for report in required_reports:
            if not (reports_path / report).exists():
                missing_reports.append(report)
        
        return {
            'passed': len(missing_reports) == 0,
            'details': f"Missing reports: {missing_reports if missing_reports else 'None'}"
        }
    
    def check_summary_counts(self):
        """Check if summary counts match processed dataset"""
        try:
            processed_file = self.base_path / "data" / "processed" / "findings.csv"
            summary_file = self.base_path / "reports" / "webscan_summary.md"
            
            if not processed_file.exists() or not summary_file.exists():
                return {'passed': False, 'details': 'Required files missing'}
            
            df = pd.read_csv(processed_file)
            processed_count = len(df)
            
            with open(summary_file, 'r', encoding='utf-8') as f:
                summary_content = f.read()
            
            # Check if total count appears in summary
            count_in_summary = f"Total Vulnerabilities Identified: **{processed_count}**" in summary_content
            
            return {
                'passed': count_in_summary,
                'details': f"Summary count matches: {processed_count} vulnerabilities"
            }
        except Exception as e:
            return {'passed': False, 'details': str(e)}

def main():
    """Main validation execution"""
    validator = ReportValidator()
    success = validator.run_validation_checklist()
    
    if success:
        print("\nAll validation checks passed! WebScanProd is ready.")
    else:
        print("\nSome validation checks failed. Please review the issues.")
    
    return success

if __name__ == "__main__":
    success = main()
    input("\nPress Enter to exit...")
    exit(0 if success else 1)