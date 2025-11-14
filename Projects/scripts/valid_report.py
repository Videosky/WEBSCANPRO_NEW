# validate_report.py
import os
import pandas as pd
from datetime import datetime

def validate_report_generation():
    """Validate the report generation process"""
    print("🔍 Validating WebScanProd Report Generation...")
    
    base_path = "C:/Users/vishal/Desktop/WEBSCAN_PRO/webscanprod_reports"
    validation_passed = True
    
    print(f"📁 Validating reports in: {base_path}")
    
    # Check if required files exist
    required_files = [
        "data/processed/combined_findings.csv",
        "reports/html/webscan_combined_report.html", 
        "reports/pdf/webscan_combined_report.pdf"
    ]
    
    for file_path in required_files:
        full_path = os.path.join(base_path, file_path)
        if os.path.exists(full_path):
            file_size = os.path.getsize(full_path)
            print(f"✅ {file_path} - EXISTS ({file_size} bytes)")
        else:
            print(f"❌ {file_path} - MISSING")
            validation_passed = False
    
    # Validate combined findings CSV
    try:
        csv_path = os.path.join(base_path, "data/processed/combined_findings.csv")
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            expected_columns = ['vuln_id', 'vuln_name', 'severity', 'description', 
                              'affected_url', 'scan_source', 'timestamp', 'recommendation']
            
            missing_columns = set(expected_columns) - set(df.columns)
            if missing_columns:
                print(f"❌ Missing columns in combined data: {missing_columns}")
                validation_passed = False
            else:
                print("✅ Combined data schema - VALID")
                
            # Additional data quality checks
            total_findings = len(df)
            unique_scanners = df['scan_source'].nunique() if 'scan_source' in df.columns else 0
            severity_counts = df['severity'].value_counts().to_dict() if 'severity' in df.columns else {}
            
            print(f"📊 Combined data stats:")
            print(f"   - Total findings: {total_findings}")
            print(f"   - Unique scanners: {unique_scanners}")
            print(f"   - Severity distribution: {severity_counts}")
            
            # Check for empty data
            if total_findings == 0:
                print("⚠️  WARNING: Combined data has 0 findings")
            
        else:
            print("❌ Combined findings CSV not found")
            validation_passed = False
        
    except Exception as e:
        print(f"❌ Error reading combined data: {e}")
        validation_passed = False
    
    # Check for duplicates in combined data
    try:
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            if 'vuln_name' in df.columns and 'affected_url' in df.columns:
                duplicates = df.duplicated(subset=['vuln_name', 'affected_url']).sum()
                if duplicates > 0:
                    print(f"⚠️  Found {duplicates} duplicates in combined data")
                else:
                    print("✅ No duplicates found in combined data")
    except Exception as e:
        print(f"⚠️  Could not check for duplicates: {e}")
    
    # Validate HTML report
    try:
        html_path = os.path.join(base_path, "reports/html/webscan_combined_report.html")
        if os.path.exists(html_path):
            with open(html_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            # Check if HTML contains key sections
            required_sections = [
                'WebScanProd - Combined Vulnerability Report',
                'Executive Summary',
                'Scanner Coverage Analysis',
                'Detailed Vulnerability Findings'
            ]
            
            for section in required_sections:
                if section in html_content:
                    print(f"✅ HTML contains '{section}' section")
                else:
                    print(f"⚠️  HTML missing '{section}' section")
            
            # Check for Plotly charts
            if 'plotly' in html_content.lower():
                print("✅ HTML contains Plotly visualizations")
            else:
                print("⚠️  HTML may be missing visualizations")
                
    except Exception as e:
        print(f"❌ Error validating HTML report: {e}")
        validation_passed = False
    
    # Validate PDF report
    try:
        pdf_path = os.path.join(base_path, "reports/pdf/webscan_combined_report.pdf")
        if os.path.exists(pdf_path):
            pdf_size = os.path.getsize(pdf_path)
            if pdf_size > 1000:  # Basic check that PDF has content
                print(f"✅ PDF report appears valid ({pdf_size} bytes)")
            else:
                print(f"⚠️  PDF report seems very small ({pdf_size} bytes)")
        else:
            print("❌ PDF report not found")
            validation_passed = False
    except Exception as e:
        print(f"❌ Error validating PDF report: {e}")
        validation_passed = False
    
    # Check scan source files
    try:
        scans_path = os.path.join(base_path, "data/scans")
        if os.path.exists(scans_path):
            scan_files = [f for f in os.listdir(scans_path) if f.endswith(('.json', '.csv', '.xml'))]
            if scan_files:
                print(f"📂 Found {len(scan_files)} scan files:")
                for scan_file in scan_files:
                    file_path = os.path.join(scans_path, scan_file)
                    file_size = os.path.getsize(file_path)
                    print(f"   - {scan_file} ({file_size} bytes)")
            else:
                print("⚠️  No scan files found in data/scans/ directory")
                print("💡 Run sample_data_generator.py to create sample data")
        else:
            print("❌ Scans directory not found")
    except Exception as e:
        print(f"⚠️  Could not check scan files: {e}")
    
    # Final validation summary
    print("\n" + "="*50)
    if validation_passed:
        print("🎉 ALL VALIDATIONS PASSED!")
        print("✅ Report generation completed successfully")
    else:
        print("❌ SOME VALIDATIONS FAILED!")
        print("💡 Check the errors above and try running the report generator again")
    
    print("="*50)
    
    return validation_passed

def check_data_quality():
    """Perform additional data quality checks"""
    print("\n🔍 Performing Data Quality Checks...")
    
    base_path = "C:/Users/vishal/Desktop/WEBSCAN_PRO/webscanprod_reports"
    csv_path = os.path.join(base_path, "data/processed/combined_findings.csv")
    
    if not os.path.exists(csv_path):
        print("❌ No combined data found for quality checks")
        return
    
    try:
        df = pd.read_csv(csv_path)
        
        print("📊 Data Quality Metrics:")
        
        # Check for missing values
        missing_data = df.isnull().sum()
        if missing_data.sum() > 0:
            print("⚠️  Missing values found:")
            for col, count in missing_data.items():
                if count > 0:
                    print(f"   - {col}: {count} missing values")
        else:
            print("✅ No missing values found")
        
        # Check severity distribution
        if 'severity' in df.columns:
            severity_dist = df['severity'].value_counts()
            print("📈 Severity Distribution:")
            for severity, count in severity_dist.items():
                print(f"   - {severity}: {count} findings")
        
        # Check scanner coverage
        if 'scan_source' in df.columns:
            scanner_coverage = df['scan_source'].value_counts()
            print("🛠️  Scanner Coverage:")
            for scanner, count in scanner_coverage.items():
                print(f"   - {scanner}: {count} findings")
        
        # Check URL patterns
        if 'affected_url' in df.columns:
            unique_urls = df['affected_url'].nunique()
            total_urls = len(df['affected_url'])
            print(f"🌐 URL Analysis: {unique_urls} unique URLs out of {total_urls} findings")
            
        # Check timestamp recency
        if 'timestamp' in df.columns:
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                latest_scan = df['timestamp'].max()
                days_ago = (pd.Timestamp.now() - latest_scan).days
                print(f"⏰ Latest scan: {latest_scan} ({days_ago} days ago)")
            except:
                print("⚠️  Could not parse timestamps")
                
    except Exception as e:
        print(f"❌ Error during data quality checks: {e}")

if __name__ == "__main__":
    # Run main validation
    success = validate_report_generation()
    
    # Run additional quality checks if validation passed
    if success:
        check_data_quality()
    
    print(f"\n💡 Next steps:")
    print(f"   - Open reports/html/webscan_combined_report.html in your browser")
    print(f"   - Check reports/pdf/webscan_combined_report.pdf for printable version")
    print(f"   - Review data/processed/combined_findings.csv for raw data")