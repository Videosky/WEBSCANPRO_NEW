#!/usr/bin/env python3
"""
PDF Report Generator for WebScanPro
Generates printable PDF reports with tables and static charts.
"""

import pandas as pd
import os
import sys
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4, LETTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle,
    PageBreak, ListFlowable, ListItem
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

def get_project_root():
    """Get the absolute path to the project root."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(current_dir)

def create_styles():
    """Create custom styles for the PDF report."""
    styles = getSampleStyleSheet()
    
    # Check if style already exists before adding
    if 'MainTitle' not in styles:
        styles.add(ParagraphStyle(
            name='MainTitle',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2c3e50'),
            alignment=1  # Center
        ))
    
    # Use existing Heading1 and Heading2 styles, just modify if needed
    styles['Heading1'].textColor = colors.HexColor('#34495e')
    styles['Heading1'].borderPadding = 5
    
    styles['Heading2'].textColor = colors.HexColor('#2c3e50')
    
    return styles

def create_summary_table(report_data, styles):
    """Create summary table with key metrics."""
    data = [
        ['Total Findings', str(report_data['total_findings'])],
        ['Critical', str(report_data['severity_counts'].get('Critical', 0))],
        ['High', str(report_data['severity_counts'].get('High', 0))],
        ['Medium', str(report_data['severity_counts'].get('Medium', 0))],
        ['Low', str(report_data['severity_counts'].get('Low', 0))],
        ['Info', str(report_data['severity_counts'].get('Info', 0))],
    ]
    
    table = Table(data, colWidths=[2*inch, 1*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8d7da')),  # Critical row
        ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#ffe5d0')),  # High row
        ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#fff3cd')),  # Medium row
        ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#d1ecf1')),  # Low row
        ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#e2e3e5')),  # Info row
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    return table

def create_findings_table(df, styles):
    """Create detailed findings table."""
    # Prepare table data
    table_data = [['ID', 'Vulnerability', 'Severity', 'URL', 'Impact']]
    
    # Add rows (limit to first 50 for PDF readability)
    for _, row in df.head(50).iterrows():
        table_data.append([
            row['vuln_id'],
            str(row['vuln_name'])[:40] + '...' if len(str(row['vuln_name'])) > 40 else str(row['vuln_name']),
            str(row['severity']),
            str(row['affected_url'])[:50] + '...' if len(str(row['affected_url'])) > 50 else str(row['affected_url']),
            str(row['impact'])[:30] + '...' if len(str(row['impact'])) > 30 else str(row['impact'])
        ])
    
    # Create table
    table = Table(table_data, colWidths=[0.8*inch, 1.8*inch, 0.7*inch, 1.5*inch, 1.2*inch])
    
    # Define table style
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ])
    
    # Apply severity-based coloring
    for i, row in enumerate(df.head(50).itertuples(), 1):
        severity = row.severity
        if severity == 'Critical':
            style.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#f8d7da'))
        elif severity == 'High':
            style.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#ffe5d0'))
        elif severity == 'Medium':
            style.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#fff3cd'))
    
    table.setStyle(style)
    return table

def generate_report_data(df):
    """Generate summary data and statistics for the report."""
    total_findings = len(df)
    
    # Severity counts
    severity_counts = df['severity'].value_counts().to_dict()
    
    # Use timezone-aware datetime
    return {
        'total_findings': total_findings,
        'severity_counts': severity_counts,
        'generated_time': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    }

def build_pdf_report(df, images_dir, output_path):
    """Build the complete PDF report."""
    
    # Create document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=LETTER,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18
    )
    
    styles = create_styles()
    story = []
    
    # Generate report data
    report_data = generate_report_data(df)
    
    # Title Page
    story.append(Paragraph('WebScanPro Security Assessment Report', styles['MainTitle']))
    story.append(Spacer(1, 0.5*inch))
    
    story.append(Paragraph(f"Report Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles['Normal']))
    story.append(Paragraph(f"Total Findings: {report_data['total_findings']}", styles['Normal']))
    story.append(Spacer(1, 0.3*inch))
    
    # Executive Summary
    story.append(Paragraph('Executive Summary', styles['Heading1']))
    story.append(Paragraph(
        f"This report summarizes the security findings from the WebScanPro assessment conducted on "
        f"{datetime.now(timezone.utc).strftime('%B %d, %Y')}. The assessment identified {report_data['total_findings']} "
        "vulnerabilities across the target application.",
        styles['Normal']
    ))
    story.append(Spacer(1, 0.2*inch))
    
    # Key Findings Summary
    story.append(Paragraph('Key Findings', styles['Heading2']))
    key_findings = ListFlowable([
        ListItem(Paragraph(f"Critical findings: {report_data['severity_counts'].get('Critical', 0)}", styles['Normal'])),
        ListItem(Paragraph(f"High severity findings: {report_data['severity_counts'].get('High', 0)}", styles['Normal'])),
        ListItem(Paragraph(f"Medium severity findings: {report_data['severity_counts'].get('Medium', 0)}", styles['Normal'])),
        ListItem(Paragraph(f"Low severity findings: {report_data['severity_counts'].get('Low', 0)}", styles['Normal'])),
    ], bulletType='bullet')
    story.append(key_findings)
    story.append(Spacer(1, 0.2*inch))
    
    # Summary Table
    story.append(Paragraph('Quick Statistics', styles['Heading2']))
    story.append(create_summary_table(report_data, styles))
    story.append(Spacer(1, 0.3*inch))
    
    # Page break for detailed findings
    story.append(PageBreak())
    
    # Detailed Findings Section
    story.append(Paragraph('Detailed Vulnerability Findings', styles['Heading1']))
    story.append(Spacer(1, 0.2*inch))
    
    # Add severity distribution chart if available
    severity_chart_path = os.path.join(images_dir, 'severity_distribution.png')
    if os.path.exists(severity_chart_path):
        story.append(Paragraph('Severity Distribution', styles['Heading2']))
        try:
            img = Image(severity_chart_path, width=5*inch, height=3*inch)
            story.append(img)
            story.append(Spacer(1, 0.2*inch))
        except Exception as e:
            print(f"Warning: Could not add severity chart to PDF: {e}")
    
    # Findings Table
    story.append(Paragraph('Vulnerability Details', styles['Heading2']))
    story.append(Paragraph(
        f"Showing {min(50, len(df))} of {len(df)} total findings.",
        styles['Normal']
    ))
    story.append(Spacer(1, 0.1*inch))
    
    findings_table = create_findings_table(df, styles)
    story.append(findings_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Recommendations Section
    story.append(Paragraph('Recommendations', styles['Heading1']))
    story.append(Paragraph(
        "Based on the findings in this report, the following general recommendations are provided:",
        styles['Normal']
    ))
    
    recommendations = [
        "Address Critical and High severity vulnerabilities immediately",
        "Implement secure coding practices and security training",
        "Establish regular security assessment cycles",
        "Implement proper input validation and output encoding",
        "Ensure proper authentication and session management",
        "Keep all components and dependencies up to date"
    ]
    
    rec_list = ListFlowable(
        [ListItem(Paragraph(rec, styles['Normal'])) for rec in recommendations],
        bulletType='bullet'
    )
    story.append(rec_list)
    
    # Build PDF
    doc.build(story)
    print(f"PDF report generated: {output_path}")

if __name__ == '__main__':
    # Get project root and set up paths
    PROJECT_ROOT = get_project_root()
    
    # Configuration with absolute paths
    CSV_PATH = os.path.join(PROJECT_ROOT, 'data', 'processed', 'findings.csv')
    OUTPUT_PDF = os.path.join(PROJECT_ROOT, 'reports', 'pdf', 'report.pdf')
    IMAGES_DIR = os.path.join(PROJECT_ROOT, 'assets', 'images')
    
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Looking for CSV: {CSV_PATH}")
    
    # Load data
    try:
        df = pd.read_csv(CSV_PATH)
        print(f"Loaded {len(df)} records from {CSV_PATH}")
        print(f"Columns: {list(df.columns)}")
    except FileNotFoundError:
        print(f"Error: Input file {CSV_PATH} not found.")
        print("Please run generate_visuals.py first to create sample data.")
        sys.exit(1)
    
    # Create output directory
    os.makedirs(os.path.dirname(OUTPUT_PDF), exist_ok=True)
    
    # Generate PDF report
    build_pdf_report(df, IMAGES_DIR, OUTPUT_PDF)
    
    print(f"✅ PDF report successfully created: {OUTPUT_PDF}")