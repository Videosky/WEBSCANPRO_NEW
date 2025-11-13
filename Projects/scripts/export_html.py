#!/usr/bin/env python3
"""
HTML Report Generator for WebScanPro
Generates responsive HTML reports with interactive charts.
"""

import pandas as pd
import os
import sys
import shutil
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
import plotly.express as px

def get_project_root():
    """Get the absolute path to the project root."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(current_dir)

def load_visualizations(images_dir):
    """Load generated visualization files."""
    viz_files = {
        'severity_chart': os.path.join(images_dir, 'severity_distribution.png'),
        'treemap_chart': os.path.join(images_dir, 'vulnerability_treemap.png'),
        'status_chart': os.path.join(images_dir, 'status_distribution.png'),
    }
    
    # Convert paths to relative for HTML
    relative_viz_files = {}
    for key, path in viz_files.items():
        if os.path.exists(path):
            # Use just the filename since images will be in the same directory as HTML
            relative_viz_files[key] = os.path.basename(path)
            print(f"Found visualization: {path}")
        else:
            print(f"Warning: Visualization file not found: {path}")
            relative_viz_files[key] = ""
    
    return relative_viz_files

def create_interactive_charts(df):
    """Create additional interactive charts for HTML report."""
    charts = {}
    
    # Severity bar chart
    severity_counts = df['severity'].value_counts().reset_index()
    severity_counts.columns = ['severity', 'count']
    
    # Define severity order for consistent display
    severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
    available_severities = [s for s in severity_order if s in severity_counts['severity'].values]
    
    # Reorder the data
    severity_counts['severity'] = pd.Categorical(severity_counts['severity'], categories=available_severities, ordered=True)
    severity_counts = severity_counts.sort_values('severity')
    
    fig_severity = px.bar(
        severity_counts, 
        x='severity', 
        y='count',
        title='Findings by Severity Level',
        color='severity',
        color_discrete_map={
            'Critical': '#dc3545',
            'High': '#fd7e14', 
            'Medium': '#ffc107',
            'Low': '#20c997',
            'Info': '#6c757d'
        }
    )
    fig_severity.update_layout(showlegend=False)
    charts['severity_bar'] = fig_severity.to_html(
        include_plotlyjs=False, 
        full_html=False,
        div_id="severity-chart"
    )
    
    # Don't create status pie chart since we don't have status column
    charts['status_pie'] = "<p>Status data not available</p>"
    
    return charts

def generate_report_data(df):
    """Generate summary data and statistics for the report."""
    total_findings = len(df)
    
    # Severity counts
    severity_counts = df['severity'].value_counts().to_dict()
    
    # Top affected URLs
    top_urls = {}
    if 'affected_url' in df.columns:
        top_urls = df['affected_url'].value_counts().head(10).to_dict()
    
    # Most common vulnerability types
    common_vulns = {}
    if 'vuln_name' in df.columns:
        common_vulns = df['vuln_name'].value_counts().head(10).to_dict()
    
    # Use timezone-aware datetime
    return {
        'total_findings': total_findings,
        'severity_counts': severity_counts,
        'status_counts': {},  # Empty since we don't have status
        'top_urls': top_urls,
        'common_vulns': common_vulns,
        'generated_time': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    }

def copy_chart_images(images_dir, reports_html_dir):
    """Copy chart images to reports directory so they're accessible to HTML."""
    chart_files = [
        ('severity_chart', 'severity_distribution.png'),
        ('treemap_chart', 'vulnerability_treemap.png'),
        ('status_chart', 'status_distribution.png')
    ]
    
    copied_files = {}
    
    for key, filename in chart_files:
        src_path = os.path.join(images_dir, filename)
        if os.path.exists(src_path):
            dst_path = os.path.join(reports_html_dir, filename)
            try:
                # Ensure destination directory exists
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src_path, dst_path)
                copied_files[key] = filename
                print(f"Copied chart image to: {dst_path}")
            except Exception as e:
                print(f"Warning: Could not copy {filename}: {e}")
        else:
            print(f"Note: Chart not available: {src_path}")
    
    return copied_files

def render_html_report(df, output_path, images_dir, template_dir):
    """Render the complete HTML report."""
    
    # Setup Jinja2 environment
    env = Environment(loader=FileSystemLoader(template_dir))
    
    # Copy available chart images to reports directory
    reports_html_dir = os.path.dirname(output_path)
    copied_images = copy_chart_images(images_dir, reports_html_dir)
    
    # Load visualizations (use the copied files)
    viz_files = {key: filename for key, filename in copied_images.items()}
    
    # Create interactive charts
    interactive_charts = create_interactive_charts(df)
    
    # Generate report data
    report_data = generate_report_data(df)
    
    # Prepare findings data for template
    findings_data = df.to_dict(orient='records')
    
    # Render template
    try:
        template = env.get_template('report_template.html.j2')
    except Exception as e:
        print(f"Error loading template: {e}")
        print("Creating a basic template file...")
        create_basic_template(template_dir)
        template = env.get_template('report_template.html.j2')
    
    html_content = template.render(
        project_name='WebScanPro Security Assessment',
        date=datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        report_data=report_data,
        findings=findings_data,
        charts=interactive_charts,
        images=viz_files,
        total_findings=len(df)
    )
    
    # Write HTML file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {output_path}")
    return output_path

def create_basic_template(template_dir):
    """Create a basic template if one doesn't exist."""
    os.makedirs(template_dir, exist_ok=True)
    template_content = """<!DOCTYPE html>
<html>
<head>
    <title>{{ project_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #20c997; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>{{ project_name }}</h1>
    <p>Date: {{ date }}</p>
    
    <h2>Summary</h2>
    <p>Total findings: {{ total_findings }}</p>
    <p>Critical: <span class="severity-critical">{{ report_data.severity_counts.get('Critical', 0) }}</span></p>
    <p>High: <span class="severity-high">{{ report_data.severity_counts.get('High', 0) }}</span></p>
    <p>Medium: <span class="severity-medium">{{ report_data.severity_counts.get('Medium', 0) }}</span></p>
    <p>Low: <span class="severity-low">{{ report_data.severity_counts.get('Low', 0) }}</span></p>
    
    <h2>Findings</h2>
    <table>
        <tr><th>ID</th><th>Name</th><th>Severity</th><th>URL</th><th>Impact</th></tr>
        {% for finding in findings %}
        <tr>
            <td>{{ finding.vuln_id }}</td>
            <td>{{ finding.vuln_name }}</td>
            <td class="severity-{{ finding.severity|lower }}">{{ finding.severity }}</td>
            <td>{{ finding.affected_url }}</td>
            <td>{{ finding.impact }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>"""
    
    template_path = os.path.join(template_dir, 'report_template.html.j2')
    with open(template_path, 'w', encoding='utf-8') as f:
        f.write(template_content)
    print(f"Created basic template at: {template_path}")

if __name__ == '__main__':
    # Get project root and set up paths
    PROJECT_ROOT = get_project_root()
    
    # Configuration with absolute paths
    CSV_PATH = os.path.join(PROJECT_ROOT, 'data', 'processed', 'findings.csv')
    OUTPUT_HTML = os.path.join(PROJECT_ROOT, 'reports', 'html', 'report.html')
    IMAGES_DIR = os.path.join(PROJECT_ROOT, 'assets', 'images')
    TEMPLATE_DIR = os.path.join(PROJECT_ROOT, 'templates')
    
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Looking for CSV: {CSV_PATH}")
    print(f"Template directory: {TEMPLATE_DIR}")
    print(f"Images directory: {IMAGES_DIR}")
    
    # Load data
    try:
        df = pd.read_csv(CSV_PATH)
        print(f"Loaded {len(df)} records from {CSV_PATH}")
        print(f"Columns: {list(df.columns)}")
    except FileNotFoundError:
        print(f"Error: Input file {CSV_PATH} not found.")
        print("Please run generate_visuals.py first to create sample data.")
        sys.exit(1)
    
    # Generate HTML report
    output_file = render_html_report(df, OUTPUT_HTML, IMAGES_DIR, TEMPLATE_DIR)
    print(f"Successfully created HTML report: {output_file}")
    
    # Open the report in default browser
    try:
        import webbrowser
        webbrowser.open(output_file)
        print("Opening report in browser...")
    except:
        print(f"Report saved to: {output_file}")