#!/usr/bin/env python3
"""
WebScanPro Report Generator - Main CLI
Orchestrates the complete report generation pipeline.
"""

import os
import sys
import argparse
from datetime import datetime

def get_project_root():
    """Get the absolute path to the project root."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(current_dir)

def main():
    parser = argparse.ArgumentParser(description='Generate WebScanPro security reports')
    parser.add_argument('--format', '-f', 
                       choices=['html', 'pdf', 'all'], 
                       default='all',
                       help='Output format(s)')
    
    args = parser.parse_args()
    
    # Get project root
    PROJECT_ROOT = get_project_root()
    
    # Set up paths
    CSV_PATH = os.path.join(PROJECT_ROOT, 'data', 'processed', 'findings.csv')
    SCRIPTS_DIR = os.path.join(PROJECT_ROOT, 'scripts')
    
    print("🚀 WebScanPro Report Generator")
    print("=" * 50)
    print(f"Project root: {PROJECT_ROOT}")
    
    try:
        # Add scripts to path
        sys.path.append(SCRIPTS_DIR)
        
        # Step 1: Generate Visualizations
        print("\n📊 Step 1: Generating visualizations...")
        from generate_visuals import generate_all_visuals
        
        df = generate_all_visuals(CSV_PATH, os.path.join(PROJECT_ROOT, 'assets', 'images'))
        
        # Step 2: Generate HTML Report
        if args.format in ['html', 'all']:
            print("\n🌐 Step 2: Generating HTML report...")
            from export_html import render_html_report
            
            html_output = os.path.join(PROJECT_ROOT, 'reports', 'html', 'report.html')
            render_html_report(
                df, 
                html_output, 
                os.path.join(PROJECT_ROOT, 'assets', 'images'),
                os.path.join(PROJECT_ROOT, 'templates')
            )
        
        # Step 3: Generate PDF Report  
        if args.format in ['pdf', 'all']:
            print("\n📄 Step 3: Generating PDF report...")
            from export_pdf import build_pdf_report
            
            pdf_output = os.path.join(PROJECT_ROOT, 'reports', 'pdf', 'report.pdf')
            build_pdf_report(df, os.path.join(PROJECT_ROOT, 'assets', 'images'), pdf_output)
        
        print("\n✅ Report generation completed successfully!")
        print(f"\n📁 Generated Reports:")
        if args.format in ['html', 'all']:
            print(f"   • HTML Report: {html_output}")
        if args.format in ['pdf', 'all']:
            print(f"   • PDF Report: {pdf_output}")
        
    except Exception as e:
        print(f"\n❌ Error during report generation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()