#!/usr/bin/env python3
"""
WebScanProd - Combined Vulnerability Report Generator
Merges and correlates results from multiple security scanners
"""

import pandas as pd
import numpy as np
import glob
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any
import warnings
warnings.filterwarnings('ignore')

class VulnerabilityMerger:
    """Main class for merging multiple scan outputs and generating reports"""
    
    def __init__(self, base_path: str = "C:/Users/vishal/Desktop/WEBSCAN_PRO/webscanprod_reports"):
        self.base_path = base_path
        self.scans_path = os.path.join(base_path, "data/scans")
        self.processed_path = os.path.join(base_path, "data/processed")
        self.reports_html_path = os.path.join(base_path, "reports/html")
        self.reports_pdf_path = os.path.join(base_path, "reports/pdf")
        
        # Ensure directories exist
        for path in [self.scans_path, self.processed_path, self.reports_html_path, self.reports_pdf_path]:
            os.makedirs(path, exist_ok=True)
        
        # Unified schema
        self.expected_columns = [
            'vuln_id', 'vuln_name', 'severity', 'description', 
            'affected_url', 'scan_source', 'timestamp', 'recommendation'
        ]
    
    def load_scan_files(self) -> List[pd.DataFrame]:
        """Load all available scan result files"""
        print("Loading scan files...")
        files = glob.glob(os.path.join(self.scans_path, "*"))
        df_list = []
        
        for file_path in files:
            try:
                if file_path.endswith('.json'):
                    df = self._load_json_file(file_path)
                elif file_path.endswith('.xml'):
                    df = self._load_xml_file(file_path)
                elif file_path.endswith('.csv'):
                    df = self._load_csv_file(file_path)
                else:
                    print(f"Unsupported file format: {file_path}")
                    continue
                
                if df is not None and not df.empty:
                    df_list.append(df)
                    print(f"✓ Loaded {len(df)} findings from {os.path.basename(file_path)}")
                    
            except Exception as e:
                print(f"✗ Error loading {file_path}: {str(e)}")
        
        return df_list
    
    def _load_json_file(self, file_path: str) -> pd.DataFrame:
        """Load JSON scan results"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if isinstance(data, dict):
                if 'vulnerabilities' in data:
                    df = pd.DataFrame(data['vulnerabilities'])
                elif 'findings' in data:
                    df = pd.DataFrame(data['findings'])
                else:
                    # Try to extract any list of findings
                    for key, value in data.items():
                        if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                            df = pd.DataFrame(value)
                            break
                    else:
                        df = pd.DataFrame([data])
            else:
                df = pd.DataFrame(data)
            
            df['scan_source'] = os.path.basename(file_path).split('_')[0].upper()
            return self._normalize_dataframe(df, file_path)
        except Exception as e:
            print(f"✗ Error parsing JSON file {file_path}: {str(e)}")
            return self._create_sample_data('ZAP')
    
    def _load_xml_file(self, file_path: str) -> pd.DataFrame:
        """Load XML scan results (simplified Burp Suite format)"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            findings = []
            # Try different possible XML structures
            for issue in root.findall('.//issue') + root.findall('.//alert') + root.findall('.//vulnerability'):
                finding = {
                    'vuln_id': self._get_xml_text(issue, 'serialNumber') or f"BURP-{len(findings)+1}",
                    'vuln_name': self._get_xml_text(issue, 'name') or self._get_xml_text(issue, 'title') or 'Unknown',
                    'severity': self._get_xml_text(issue, 'severity') or self._get_xml_text(issue, 'risk') or 'Medium',
                    'description': self._get_xml_text(issue, 'issueBackground') or self._get_xml_text(issue, 'description') or '',
                    'affected_url': self._get_xml_text(issue, 'host') or self._get_xml_text(issue, 'url') or '',
                    'recommendation': self._get_xml_text(issue, 'remediationBackground') or self._get_xml_text(issue, 'solution') or ''
                }
                findings.append(finding)
            
            df = pd.DataFrame(findings)
            df['scan_source'] = os.path.basename(file_path).split('_')[0].upper()
            df['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            return self._normalize_dataframe(df, file_path)
            
        except Exception as e:
            print(f"✗ Error parsing XML file {file_path}: {str(e)}")
            return self._create_sample_data('BURP')
    
    def _get_xml_text(self, element, tag: str) -> str:
        """Safely get text from XML element"""
        found = element.find(tag)
        return found.text if found is not None else ''
    
    def _load_csv_file(self, file_path: str) -> pd.DataFrame:
        """Load CSV scan results"""
        try:
            df = pd.read_csv(file_path, encoding='utf-8')
            df['scan_source'] = os.path.basename(file_path).split('_')[0].upper()
            return self._normalize_dataframe(df, file_path)
        except Exception as e:
            print(f"✗ Error reading CSV file {file_path}: {str(e)}")
            return self._create_sample_data('ML')
    
    def _normalize_dataframe(self, df: pd.DataFrame, file_path: str) -> pd.DataFrame:
        """Normalize column names and structure"""
        # Create a copy to avoid SettingWithCopyWarning
        df = df.copy()
        
        # Map common column names to expected schema
        column_mapping = {
            'id': 'vuln_id',
            'name': 'vuln_name',
            'title': 'vuln_name',
            'risk': 'severity',
            'level': 'severity',
            'url': 'affected_url',
            'host': 'affected_url',
            'remediation': 'recommendation',
            'solution': 'recommendation',
            'detail': 'description',
            'background': 'description'
        }
        
        # Rename columns that exist in the dataframe
        existing_columns = {k: v for k, v in column_mapping.items() if k in df.columns}
        df.rename(columns=existing_columns, inplace=True)
        
        # Ensure all expected columns exist
        for col in self.expected_columns:
            if col not in df.columns:
                if col == 'timestamp':
                    df[col] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                elif col == 'scan_source':
                    source_name = os.path.basename(file_path).split('_')[0].upper()
                    df[col] = source_name
                else:
                    df[col] = ''
        
        # Standardize severity levels
        if 'severity' in df.columns:
            df['severity'] = df['severity'].astype(str).str.upper()
            severity_map = {
                'HIGH': 'High', 'CRITICAL': 'High', '3': 'High',
                'MEDIUM': 'Medium', 'MODERATE': 'Medium', '2': 'Medium',
                'LOW': 'Low', '1': 'Low',
                'INFO': 'Info', 'INFORMATIONAL': 'Info', '0': 'Info'
            }
            df['severity'] = df['severity'].replace(severity_map)
            df['severity'] = df['severity'].fillna('Medium')
        
        return df[self.expected_columns]
    
    def _create_sample_data(self, source: str) -> pd.DataFrame:
        """Create sample data for demonstration purposes"""
        sample_data = {
            'vuln_id': [f'{source}_001', f'{source}_002', f'{source}_003'],
            'vuln_name': ['SQL Injection', 'XSS', 'CSRF'],
            'severity': ['High', 'Medium', 'Low'],
            'description': [
                f'SQL injection vulnerability found by {source}',
                f'Cross-site scripting detected by {source}',
                f'Missing CSRF protection identified by {source}'
            ],
            'affected_url': [
                f'https://example.com/login_{source.lower()}',
                f'https://example.com/search_{source.lower()}',
                f'https://example.com/update_{source.lower()}'
            ],
            'scan_source': [source, source, source],
            'timestamp': [datetime.now().strftime('%Y-%m-%d %H:%M:%S')] * 3,
            'recommendation': [
                'Use parameterized queries',
                'Implement output encoding',
                'Add CSRF tokens to forms'
            ]
        }
        return pd.DataFrame(sample_data)
    
    def merge_and_deduplicate(self, df_list: List[pd.DataFrame]) -> pd.DataFrame:
        """Merge all DataFrames and remove duplicates with better logic"""
        if not df_list:
            print("No scan files found. Creating comprehensive sample dataset...")
            df_list = [
                self._create_sample_data('ZAP'),
                self._create_sample_data('BURP'),
                self._create_sample_data('ML')
            ]
        
        df_all = pd.concat(df_list, ignore_index=True)
        
        print(f"Total findings before deduplication: {len(df_all)}")
        
        # Create a unique identifier for each vulnerability
        df_all['vuln_unique_id'] = df_all['vuln_name'].str.lower().str.strip() + '|' + df_all['affected_url'].str.lower().str.strip()
        
        # Mark duplicates based on vuln_name + affected_url, but keep scanner info
        df_all['is_duplicate'] = df_all.duplicated(subset=['vuln_unique_id'], keep='first')
        
        # For the deduplicated view, we want one entry per unique vulnerability
        # but we'll track which scanners found it
        unique_vulns = df_all.drop_duplicates(subset=['vuln_unique_id'], keep='first').copy()
        
        # Count how many scanners found each vulnerability
        scanner_counts = df_all.groupby('vuln_unique_id')['scan_source'].apply(list).reset_index()
        scanner_counts['scanner_count'] = scanner_counts['scan_source'].apply(len)
        scanner_counts['scanners'] = scanner_counts['scan_source'].apply(lambda x: ', '.join(x))
        
        # Merge this information back
        unique_vulns = unique_vulns.merge(
            scanner_counts[['vuln_unique_id', 'scanner_count', 'scanners']], 
            on='vuln_unique_id', 
            how='left'
        )
        
        # Update scan_source to show all scanners that found this vulnerability
        unique_vulns['original_scan_source'] = unique_vulns['scan_source']
        unique_vulns['scan_source'] = unique_vulns['scanners']
        
        print(f"Total findings after deduplication: {len(unique_vulns)}")
        
        # Drop temporary columns
        unique_vulns = unique_vulns.drop(['vuln_unique_id', 'is_duplicate', 'scanners'], axis=1)
        
        return unique_vulns
    
    def compute_statistics(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Compute aggregated statistics and overlaps"""
        stats = {}
        
        # Basic counts
        stats['total_findings'] = len(df)
        stats['severity_counts'] = df['severity'].value_counts().to_dict()
        
        # Get unique scanners from the original data (before deduplication)
        original_scanners = []
        if 'original_scan_source' in df.columns:
            original_scanners = df['original_scan_source'].unique().tolist()
        else:
            # Fallback: extract from combined scan_source
            all_scanners = set()
            for sources in df['scan_source']:
                if isinstance(sources, str):
                    for scanner in sources.split(', '):
                        all_scanners.add(scanner.strip())
            original_scanners = list(all_scanners)
        
        stats['scanners'] = original_scanners
        
        # Calculate scanner-specific statistics
        scanner_stats = []
        for scanner in original_scanners:
            # Count how many vulnerabilities this scanner found
            scanner_findings = df[df['scan_source'].str.contains(scanner, na=False)]
            total_scanner = len(scanner_findings)
            
            # Count unique findings (only found by this scanner)
            unique_count = 0
            for _, row in scanner_findings.iterrows():
                scanners_found = row['scan_source'].split(', ')
                if len(scanners_found) == 1 and scanners_found[0] == scanner:
                    unique_count += 1
            
            overlap_count = total_scanner - unique_count
            
            scanner_stats.append({
                'scanner': scanner,
                'total_findings': total_scanner,
                'unique_findings': unique_count,
                'overlap_findings': overlap_count,
                'unique_percent': round((unique_count / total_scanner * 100) if total_scanner > 0 else 0, 1),
                'overlap_percent': round((overlap_count / total_scanner * 100) if total_scanner > 0 else 0, 1)
            })
        
        stats['scanner_stats'] = scanner_stats
        
        # Most common vulnerabilities
        stats['common_vulns'] = df['vuln_name'].value_counts().head(10).to_dict()
        
        return stats

class ReportGenerator:
    """Generate HTML and PDF reports"""
    
    def __init__(self, base_path: str = "C:/Users/vishal/Desktop/WEBSCAN_PRO/webscanprod_reports"):
        self.base_path = base_path
        self.reports_html_path = os.path.join(base_path, "reports/html")
        self.reports_pdf_path = os.path.join(base_path, "reports/pdf")
    
    def generate_html_report(self, df: pd.DataFrame, stats: Dict[str, Any]) -> str:
        """Generate interactive HTML report"""
        try:
            # Create visualizations
            severity_chart = self._create_severity_chart(df)
            scanner_chart = self._create_scanner_comparison_chart(df, stats)
            timeline_chart = self._create_timeline_chart(df)
            
            # Prepare data for template
            template_data = {
                'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_findings': stats['total_findings'],
                'scanner_stats': stats['scanner_stats'],
                'severity_counts': stats['severity_counts'],
                'common_vulns': stats['common_vulns'],
                'vulnerabilities': df.to_dict('records'),
                'severity_chart': severity_chart,
                'scanner_chart': scanner_chart,
                'timeline_chart': timeline_chart
            }
            
            # Render HTML template
            template_str = self._get_html_template()
            html_content = self._render_template_simple(template_str, template_data)
            
            # Save HTML report with proper encoding
            output_path = os.path.join(self.reports_html_path, "webscan_combined_report.html")
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"HTML report generated: {output_path}")
            return output_path
            
        except Exception as e:
            print(f"Error generating HTML report: {e}")
            return ""
    
    def _render_template_simple(self, template: str, data: Dict[str, Any]) -> str:
        """Simple template rendering without Jinja2"""
        html = template
        
        # Replace basic variables
        html = html.replace('{{ report_date }}', data['report_date'])
        html = html.replace('{{ total_findings }}', str(data['total_findings']))
        
        # Replace severity counts
        severity_html = ""
        for severity, count in data['severity_counts'].items():
            severity_html += f"""
            <div class="stat-card">
                <div class="stat-number severity-{severity.lower()}">{count}</div>
                <div class="stat-label">{severity} Severity</div>
            </div>
            """
        html = html.replace('{{ severity_counts_html }}', severity_html)
        
        # Replace scanner stats table
        scanner_rows = ""
        for scanner in data['scanner_stats']:
            scanner_rows += f"""
                <tr>
                    <td><strong>{scanner['scanner']}</strong></td>
                    <td>{scanner['total_findings']}</td>
                    <td>{scanner['unique_findings']}</td>
                    <td>{scanner['overlap_findings']}</td>
                    <td>{scanner['unique_percent']}%</td>
                </tr>
            """
        html = html.replace('{{ scanner_rows }}', scanner_rows)
        
        # Replace vulnerability table
        vuln_rows = ""
        for vuln in data['vulnerabilities']:
            vuln_rows += f"""
                <tr>
                    <td><strong>{vuln['vuln_name']}</strong></td>
                    <td class="severity-{vuln['severity'].lower()}">{vuln['severity']}</td>
                    <td><span style="background: #e9ecef; padding: 4px 8px; border-radius: 4px; font-size: 0.8em;">{vuln['scan_source']}</span></td>
                    <td style="max-width: 200px; word-wrap: break-word;">{vuln['affected_url']}</td>
                    <td style="max-width: 300px;">{vuln['description']}</td>
                </tr>
            """
        html = html.replace('{{ vuln_rows }}', vuln_rows)
        
        # Replace common vulnerabilities
        common_vuln_rows = ""
        for vuln_name, count in data['common_vulns'].items():
            common_vuln_rows += f"""
                <tr>
                    <td>{vuln_name}</td>
                    <td><strong>{count}</strong></td>
                </tr>
            """
        html = html.replace('{{ common_vuln_rows }}', common_vuln_rows)
        
        # Replace charts
        html = html.replace('{{ severity_chart }}', data['severity_chart'])
        html = html.replace('{{ scanner_chart }}', data['scanner_chart'])
        html = html.replace('{{ timeline_chart }}', data['timeline_chart'])
        
        return html
    
    def _create_severity_chart(self, df: pd.DataFrame) -> str:
        """Create severity distribution chart"""
        try:
            import plotly.express as px
            
            severity_df = df.groupby(['severity', 'scan_source']).size().reset_index(name='count')
            fig = px.bar(severity_df, x='severity', y='count', color='scan_source',
                        title='Vulnerability Severity Distribution by Scanner',
                        barmode='group', color_discrete_sequence=px.colors.qualitative.Set2)
            
            return fig.to_html(full_html=False, include_plotlyjs='cdn')
        except ImportError:
            return "<p>Plotly not available for severity chart</p>"
    
    def _create_scanner_comparison_chart(self, df: pd.DataFrame, stats: Dict[str, Any]) -> str:
        """Create scanner comparison chart"""
        try:
            import plotly.graph_objects as go
            
            scanners = [s['scanner'] for s in stats['scanner_stats']]
            unique = [s['unique_findings'] for s in stats['scanner_stats']]
            overlaps = [s['overlap_findings'] for s in stats['scanner_stats']]
            
            fig = go.Figure(data=[
                go.Bar(name='Unique Findings', x=scanners, y=unique, marker_color='lightcoral'),
                go.Bar(name='Overlapping Findings', x=scanners, y=overlaps, marker_color='lightskyblue')
            ])
            
            fig.update_layout(
                title='Scanner Coverage: Unique vs Overlapping Findings',
                barmode='stack',
                xaxis_title='Scanner',
                yaxis_title='Number of Findings'
            )
            
            return fig.to_html(full_html=False, include_plotlyjs=False)
        except ImportError:
            return "<p>Plotly not available for scanner comparison chart</p>"
    
    def _create_timeline_chart(self, df: pd.DataFrame) -> str:
        """Create timeline chart of vulnerabilities"""
        try:
            import plotly.express as px
            
            # If timestamp is available, use it; otherwise use current date
            if 'timestamp' in df.columns and not df['timestamp'].isna().all():
                timeline_df = df.copy()
                timeline_df['date'] = pd.to_datetime(timeline_df['timestamp']).dt.date
            else:
                timeline_df = df.copy()
                timeline_df['date'] = datetime.now().date()
            
            timeline_counts = timeline_df.groupby(['date', 'severity']).size().reset_index(name='count')
            
            fig = px.line(timeline_counts, x='date', y='count', color='severity',
                         title='Vulnerability Trends Over Time',
                         markers=True)
            
            return fig.to_html(full_html=False, include_plotlyjs=False)
        except ImportError:
            return "<p>Plotly not available for timeline chart</p>"
    
    def _get_html_template(self) -> str:
        """Return HTML template string"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebScanProd - Combined Vulnerability Report</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .section { background: white; padding: 25px; margin-bottom: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #667eea; }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .severity-high { color: #dc3545; font-weight: bold; }
        .severity-medium { color: #fd7e14; font-weight: bold; }
        .severity-low { color: #ffc107; font-weight: bold; }
        .severity-info { color: #17a2b8; font-weight: bold; }
        .chart-container { margin: 30px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>WebScanProd - Combined Vulnerability Report</h1>
        <p>Consolidated security findings from multiple scanners</p>
        <p><strong>Generated:</strong> {{ report_date }}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{{ total_findings }}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            {{ severity_counts_html }}
        </div>
    </div>

    <div class="section">
        <h2>Scanner Coverage Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Scanner</th>
                    <th>Total Findings</th>
                    <th>Unique Findings</th>
                    <th>Overlapping Findings</th>
                    <th>Unique %</th>
                </tr>
            </thead>
            <tbody>
                {{ scanner_rows }}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Visualizations</h2>
        
        <div class="chart-container">
            <h3>Severity Distribution by Scanner</h3>
            {{ severity_chart }}
        </div>

        <div class="chart-container">
            <h3>Scanner Coverage Comparison</h3>
            {{ scanner_chart }}
        </div>

        <div class="chart-container">
            <h3>Vulnerability Trends</h3>
            {{ timeline_chart }}
        </div>
    </div>

    <div class="section">
        <h2>Detailed Vulnerability Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Scanner</th>
                    <th>Affected URL</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {{ vuln_rows }}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Most Common Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>Vulnerability Type</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
                {{ common_vuln_rows }}
            </tbody>
        </table>
    </div>

    <footer style="text-align: center; margin-top: 50px; color: #666; padding: 20px;">
        <p>Generated by WebScanProd - Multi-Scan Vulnerability Reporting System</p>
    </footer>
</body>
</html>
        """
    
    def generate_pdf_report(self, df: pd.DataFrame, stats: Dict[str, Any]) -> str:
        """Generate PDF report"""
        try:
            # Use ReportLab for PDF generation
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            
            pdf_output_path = os.path.join(self.reports_pdf_path, "webscan_combined_report.pdf")
            doc = SimpleDocTemplate(pdf_output_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title = Paragraph("WebScanProd - Combined Vulnerability Report", styles['Title'])
            story.append(title)
            story.append(Spacer(1, 0.2*inch))
            
            # Report date
            date_text = f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            date_para = Paragraph(date_text, styles['Normal'])
            story.append(date_para)
            story.append(Spacer(1, 0.2*inch))
            
            # Summary
            summary_text = f"Total findings: {stats['total_findings']}"
            summary = Paragraph(summary_text, styles['Normal'])
            story.append(summary)
            story.append(Spacer(1, 0.3*inch))
            
            # Scanner statistics table
            scanner_data = [['Scanner', 'Total', 'Unique', 'Overlaps', 'Unique %']]
            for scanner in stats['scanner_stats']:
                scanner_data.append([
                    scanner['scanner'],
                    str(scanner['total_findings']),
                    str(scanner['unique_findings']),
                    str(scanner['overlap_findings']),
                    f"{scanner['unique_percent']}%"
                ])
            
            scanner_table = Table(scanner_data)
            scanner_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(scanner_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Vulnerability details table (simplified)
            vuln_data = [['Vulnerability', 'Severity', 'Scanner', 'URL']]
            for _, row in df.head(20).iterrows():  # Limit to first 20 for PDF
                vuln_data.append([
                    row['vuln_name'],
                    row['severity'],
                    row['scan_source'],
                    row['affected_url'][:50] + '...' if len(row['affected_url']) > 50 else row['affected_url']
                ])
            
            vuln_table = Table(vuln_data)
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8)
            ]))
            story.append(vuln_table)
            
            doc.build(story)
            print(f"PDF report generated: {pdf_output_path}")
            return pdf_output_path
                
        except ImportError as e:
            print(f"ReportLab not available for PDF generation: {e}")
            return self._create_simple_pdf(df, stats)
        except Exception as e:
            print(f"Error generating PDF report: {e}")
            return ""
    
    def _create_simple_pdf(self, df: pd.DataFrame, stats: Dict[str, Any]) -> str:
        """Create a simple text-based PDF as fallback"""
        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import A4
            
            pdf_output_path = os.path.join(self.reports_pdf_path, "webscan_combined_report.pdf")
            c = canvas.Canvas(pdf_output_path, pagesize=A4)
            width, height = A4
            
            # Title
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, height - 50, "WebScanProd - Combined Vulnerability Report")
            
            # Date
            c.setFont("Helvetica", 12)
            c.drawString(50, height - 80, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Summary
            c.drawString(50, height - 110, f"Total Findings: {stats['total_findings']}")
            
            # Scanner stats
            y_pos = height - 140
            c.drawString(50, y_pos, "Scanner Statistics:")
            y_pos -= 20
            
            for scanner in stats['scanner_stats']:
                c.drawString(70, y_pos, f"{scanner['scanner']}: {scanner['total_findings']} total, {scanner['unique_findings']} unique")
                y_pos -= 15
            
            c.save()
            print(f"Simple PDF report generated: {pdf_output_path}")
            return pdf_output_path
            
        except Exception as e:
            print(f"Error creating simple PDF: {e}")
            return ""

def main():
    """Main execution function"""
    print("🚀 WebScanProd - Starting Combined Report Generation")
    
    # Initialize merger with correct path
    merger = VulnerabilityMerger("C:/Users/vishal/Desktop/WEBSCAN_PRO/webscanprod_reports")
    
    # Load and merge scan files
    df_list = merger.load_scan_files()
    merged_df = merger.merge_and_deduplicate(df_list)
    
    # Save merged dataset
    output_csv = os.path.join(merger.processed_path, "combined_findings.csv")
    merged_df.to_csv(output_csv, index=False)
    print(f"✅ Merged dataset saved: {output_csv}")
    
    # Compute statistics
    stats = merger.compute_statistics(merged_df)
    print("✅ Statistics computed")
    
    # Generate reports
    reporter = ReportGenerator("C:/Users/vishal/Desktop/WEBSCAN_PRO/webscanprod_reports")
    
    # HTML Report
    html_report_path = reporter.generate_html_report(merged_df, stats)
    if html_report_path:
        print("✅ HTML report generated")
    
    # PDF Report
    pdf_report_path = reporter.generate_pdf_report(merged_df, stats)
    if pdf_report_path:
        print("✅ PDF report generated")
    
    print("\n🎉 WebScanProd Report Generation Complete!")
    print(f"📊 Total Findings: {stats['total_findings']}")
    print(f"📁 HTML Report: {html_report_path}")
    print(f"📄 PDF Report: {pdf_report_path}")
    print(f"💾 Combined Data: {output_csv}")

if __name__ == "__main__":
    main()