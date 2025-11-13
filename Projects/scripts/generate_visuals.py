#!/usr/bin/env python3
"""
Generate Visualizations for WebScanPro Reports
Creates static and interactive charts from vulnerability findings data.
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys
import numpy as np

def get_project_root():
    """Get the absolute path to the project root."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(current_dir)

def load_and_clean(csv_path):
    """Load and clean the findings CSV data."""
    try:
        df = pd.read_csv(csv_path)
        print(f"Loaded {len(df)} records from {csv_path}")
        return df
    except FileNotFoundError:
        print(f"Error: File {csv_path} not found.")
        print("Creating sample data for demonstration...")
        return create_sample_data()

def create_sample_data():
    """Create sample data for testing if no CSV exists."""
    np.random.seed(42)
    
    sample_data = {
        'vuln_id': [f'VULN-{i:03d}' for i in range(1, 21)],
        'vuln_name': np.random.choice([
            'SQL Injection', 'XSS', 'CSRF', 'Info Disclosure', 
            'Broken Authentication', 'Sensitive Data Exposure',
            'XXE', 'Security Misconfiguration', 'Insecure Deserialization',
            'Using Components with Known Vulnerabilities'
        ], 20),
        'severity': np.random.choice(['Critical', 'High', 'Medium', 'Low', 'Info'], 
                                   20, p=[0.1, 0.2, 0.4, 0.2, 0.1]),
        'affected_url': [
            f'https://example.com/{page}' 
            for page in np.random.choice(['login', 'admin', 'api/v1/users', 'public', 'upload'], 20)
        ],
        'description': [f'Description for finding {i}' for i in range(1, 21)],
        'recommendation': [f'Recommendation for finding {i}' for i in range(1, 21)],
        'status': np.random.choice(['Open', 'In Progress', 'Closed'], 20, p=[0.6, 0.3, 0.1])
    }
    return pd.DataFrame(sample_data)

def plot_severity_counts(df, out_path):
    """Create severity distribution bar plot using Seaborn."""
    print("Creating severity chart...")
    
    # Get counts and order by severity level
    counts = df['severity'].value_counts().reset_index()
    counts.columns = ['severity', 'count']
    
    # Define severity order for consistent coloring
    severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
    available_severities = [s for s in severity_order if s in counts['severity'].values]
    
    # Create color palette based on severity
    colors = ['#dc3545', '#fd7e14', '#ffc107', '#20c997', '#6c757d']
    color_map = {sev: colors[i] for i, sev in enumerate(severity_order) if sev in available_severities}
    
    plt.figure(figsize=(8, 6))
    bar_plot = sns.barplot(
        data=counts, 
        x='severity', 
        y='count',
        hue='severity',
        palette=color_map,
        order=available_severities,
        legend=False,
        dodge=False
    )
    
    # Add value labels on bars
    for i, v in enumerate(counts['count']):
        bar_plot.text(i, v + 0.1, str(v), ha='center', va='bottom', fontweight='bold')
    
    plt.title('Vulnerability Distribution by Severity', fontsize=14, fontweight='bold')
    plt.xlabel('Severity Level', fontweight='bold')
    plt.ylabel('Number of Findings', fontweight='bold')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    
    # Save plot
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Saved severity chart to: {out_path}")

def create_simple_treemap(df, out_png):
    """Create a simple hierarchical visualization."""
    print("Creating treemap visualization...")
    
    # Create a simple bar chart showing severity and vulnerability types
    plt.figure(figsize=(10, 8))
    
    # Group by severity and vulnerability name
    grouped = df.groupby(['severity', 'vuln_name']).size().reset_index(name='count')
    
    # Create a simple visualization
    severity_counts = df['severity'].value_counts()
    
    colors = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#20c997', 'Info': '#6c757d'}
    
    # Create a nested bar chart
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
    
    # Plot 1: Severity distribution
    severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
    available_severities = [s for s in severity_order if s in severity_counts.index]
    severity_colors = [colors.get(sev, 'blue') for sev in available_severities]
    
    ax1.bar(available_severities, [severity_counts.get(sev, 0) for sev in available_severities], 
            color=severity_colors)
    ax1.set_title('Vulnerability Distribution by Severity', fontweight='bold')
    ax1.set_ylabel('Count')
    
    # Add value labels
    for i, v in enumerate([severity_counts.get(sev, 0) for sev in available_severities]):
        ax1.text(i, v + 0.1, str(v), ha='center', va='bottom')
    
    # Plot 2: Top vulnerability types
    top_vulns = df['vuln_name'].value_counts().head(8)
    ax2.barh(range(len(top_vulns)), top_vulns.values)
    ax2.set_yticks(range(len(top_vulns)))
    ax2.set_yticklabels(top_vulns.index)
    ax2.set_title('Top Vulnerability Types', fontweight='bold')
    ax2.set_xlabel('Count')
    
    # Add value labels
    for i, v in enumerate(top_vulns.values):
        ax2.text(v + 0.1, i, str(v), va='center')
    
    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Saved treemap to: {out_png}")

def plot_status_distribution(df, out_png):
    """Create status distribution chart."""
    print("Creating status distribution chart...")
    
    # Check if status column exists
    if 'status' not in df.columns:
        print("Status column not found. Skipping status chart.")
        return
    
    status_counts = df['status'].value_counts()
    
    plt.figure(figsize=(8, 6))
    colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
    
    plt.pie(status_counts.values, labels=status_counts.index, autopct='%1.1f%%', 
            colors=colors[:len(status_counts)], startangle=90)
    plt.title('Findings by Status', fontweight='bold')
    plt.axis('equal')
    plt.tight_layout()
    
    plt.savefig(out_png, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Saved status chart to: {out_png}")

def generate_all_visuals(csv_path, output_dir):
    """Generate all visualizations."""
    print("Generating visualizations...")
    
    # Create output directories
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, 'interactive'), exist_ok=True)
    
    # Load data
    df = load_and_clean(csv_path)
    
    # Generate visualizations
    severity_img = os.path.join(output_dir, 'severity_distribution.png')
    plot_severity_counts(df, severity_img)
    
    treemap_png = os.path.join(output_dir, 'vulnerability_treemap.png')
    create_simple_treemap(df, treemap_png)
    
    status_png = os.path.join(output_dir, 'status_distribution.png')
    plot_status_distribution(df, status_png)
    
    print("All visualizations generated successfully!")
    return df

if __name__ == '__main__':
    # Configuration
    PROJECT_ROOT = get_project_root()
    CSV_PATH = os.path.join(PROJECT_ROOT, 'data', 'processed', 'findings.csv')
    OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'assets', 'images')
    
    print(f"Input CSV path: {CSV_PATH}")
    print(f"Output directory: {OUTPUT_DIR}")
    
    # Generate visuals
    df = generate_all_visuals(CSV_PATH, OUTPUT_DIR)
    
    # Print summary
    print("\n" + "="*50)
    print("DATA SUMMARY")
    print("="*50)
    print(f"Total findings: {len(df)}")
    print("\nSeverity distribution:")
    print(df['severity'].value_counts().sort_index())
    
    if 'status' in df.columns:
        print("\nStatus distribution:")
        print(df['status'].value_counts())
    else:
        print("\nStatus: Column not available")
    
    print(f"\nAvailable columns: {list(df.columns)}")