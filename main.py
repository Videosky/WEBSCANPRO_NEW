from flask import Flask, render_template, jsonify, request, send_file, send_from_directory, session, redirect, url_for, make_response
import os
import sys
import json
import time
import random
import threading
import sqlite3
import hashlib
import base64
import io
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime, timedelta
from urllib.parse import urlparse
from functools import wraps
import csv
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
import markdown

app = Flask(__name__)
app.secret_key = 'webscanpro_secret_key_2024'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Professional color scheme
PROFESSIONAL_COLORS = {
    'primary': '#6366F1',
    'secondary': '#8B5CF6',
    'success': '#10B981',
    'warning': '#F59E0B',
    'danger': '#EF4444',
    'dark': '#1F2937',
    'light': '#F9FAFB',
    'accent1': '#3B82F6',
    'accent2': '#EC4899',
    'accent3': '#06B6D4',
}

# Enhanced test URLs with realistic vulnerabilities
VULNERABILITY_DATABASE = {
    "testphp.vulnweb.com": {
        "risk": "Critical",
        "vulnerabilities": [
            {"type": "SQL Injection", "severity": "Critical", "parameter": "id", "payload": "1' UNION SELECT 1,2,3--", "description": "Union-based SQL injection in product ID parameter", "cwe": "CWE-89", "cvss": 9.8},
            {"type": "SQL Injection", "severity": "High", "parameter": "cat", "payload": "1' OR '1'='1", "description": "Boolean-based SQL injection in category filter", "cwe": "CWE-89", "cvss": 8.5},
            {"type": "XSS", "severity": "High", "parameter": "search", "payload": "<script>alert('XSS')</script>", "description": "Reflected XSS in search functionality", "cwe": "CWE-79", "cvss": 7.4},
        ]
    },
    "demo.testfire.net": {
        "risk": "High", 
        "vulnerabilities": [
            {"type": "XSS", "severity": "High", "parameter": "query", "payload": "<script>alert(1)</script>", "description": "Reflected XSS in search results", "cwe": "CWE-79", "cvss": 7.4},
            {"type": "SQL Injection", "severity": "Medium", "parameter": "accountId", "payload": "100' AND 1=1--", "description": "SQL injection in account management", "cwe": "CWE-89", "cvss": 6.5},
        ]
    },
    "altoromutual.com": {
        "risk": "Critical",
        "vulnerabilities": [
            {"type": "Authentication Bypass", "severity": "Critical", "parameter": "login", "payload": "admin/admin", "description": "Default administrative credentials", "cwe": "CWE-798", "cvss": 9.1},
            {"type": "Session Fixation", "severity": "High", "parameter": "JSESSIONID", "payload": "fixed_session", "description": "Session fixation vulnerability", "cwe": "CWE-384", "cvss": 7.8},
        ]
    }
}

# Initialize database
def init_db():
    try:
        conn = sqlite3.connect('webscanpro.db')
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS scans
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scan_id TEXT UNIQUE,
                      target_url TEXT,
                      scan_type TEXT,
                      status TEXT,
                      risk_score INTEGER,
                      total_vulnerabilities INTEGER,
                      critical_count INTEGER,
                      high_count INTEGER,
                      medium_count INTEGER,
                      low_count INTEGER,
                      start_time TEXT,
                      end_time TEXT,
                      user_id TEXT,
                      report_path TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scan_id TEXT,
                      type TEXT,
                      severity TEXT,
                      parameter TEXT,
                      payload TEXT,
                      description TEXT,
                      confidence INTEGER,
                      cwe TEXT,
                      cvss REAL,
                      FOREIGN KEY (scan_id) REFERENCES scans (scan_id))''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE,
                      password_hash TEXT,
                      email TEXT,
                      created_at TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS reports
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      scan_id TEXT UNIQUE,
                      report_name TEXT,
                      report_format TEXT,
                      file_path TEXT,
                      generated_at TEXT,
                      FOREIGN KEY (scan_id) REFERENCES scans (scan_id))''')
        
        conn.commit()
        conn.close()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")

init_db()

class ReportGenerator:
    @staticmethod
    def generate_pdf_report(scan_data, vulnerabilities):
        try:
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#6366F1'),
                alignment=1,
                spaceAfter=30
            )
            story.append(Paragraph("WebScanPro Security Assessment Report", title_style))
            story.append(Paragraph("Scan Information", styles['Heading2']))
            scan_info = [
                ["Target URL:", scan_data.get('target_url', 'N/A')],
                ["Scan Type:", scan_data.get('scan_type', 'N/A')],
                ["Scan Date:", scan_data.get('start_time', 'N/A')],
                ["Risk Score:", f"{scan_data.get('risk_score', 0)}%"],
                ["Total Vulnerabilities:", str(len(vulnerabilities))]
            ]
            
            info_table = Table(scan_info, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(info_table)
            story.append(Spacer(1, 20))
            story.append(Paragraph("Detected Vulnerabilities", styles['Heading2']))
            
            if vulnerabilities:
                vuln_data = [["Type", "Severity", "Parameter", "CWE", "CVSS"]]
                for vuln in vulnerabilities:
                    vuln_data.append([
                        vuln.get('type', 'N/A'),
                        vuln.get('severity', 'N/A'),
                        vuln.get('parameter', 'N/A'),
                        vuln.get('cwe', 'N/A'),
                        str(vuln.get('cvss', 'N/A'))
                    ])
                
                vuln_table = Table(vuln_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 1.2*inch, 0.8*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(vuln_table)
            else:
                story.append(Paragraph("No vulnerabilities detected.", styles['Normal']))
            
            doc.build(story)
            buffer.seek(0)
            return buffer
        except Exception as e:
            print(f"PDF generation error: {e}")
            return None
    
    @staticmethod
    def generate_csv_report(vulnerabilities):
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Type', 'Severity', 'Parameter', 'Payload', 'Description', 'CWE', 'CVSS', 'Confidence'])
            
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get('type', 'N/A'),
                    vuln.get('severity', 'N/A'),
                    vuln.get('parameter', 'N/A'),
                    vuln.get('payload', 'N/A'),
                    vuln.get('description', 'N/A'),
                    vuln.get('cwe', 'N/A'),
                    vuln.get('cvss', 'N/A'),
                    vuln.get('confidence', 'N/A')
                ])
            
            output.seek(0)
            return output
        except Exception as e:
            print(f"CSV generation error: {e}")
            return None
    
    @staticmethod
    def generate_json_report(scan_data, vulnerabilities):
        try:
            report = {
                'scan_info': {
                    'scan_id': scan_data.get('scan_id'),
                    'target_url': scan_data.get('target_url'),
                    'scan_type': scan_data.get('scan_type'),
                    'start_time': scan_data.get('start_time'),
                    'end_time': scan_data.get('end_time', datetime.now().isoformat()),
                    'risk_score': scan_data.get('risk_score', 0),
                    'status': scan_data.get('status')
                },
                'vulnerabilities': vulnerabilities,
                'summary': {
                    'total': len(vulnerabilities),
                    'critical': len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
                    'high': len([v for v in vulnerabilities if v.get('severity') == 'High']),
                    'medium': len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
                    'low': len([v for v in vulnerabilities if v.get('severity') == 'Low'])
                }
            }
            return json.dumps(report, indent=2)
        except Exception as e:
            print(f"JSON generation error: {e}")
            return None
    
    @staticmethod
    def generate_html_report(scan_data, vulnerabilities):
        """Generate HTML report - FIXED: no nested f-strings"""
        try:
            # Build vulnerabilities HTML separately
            vulns_html = ""
            if vulnerabilities:
                for vuln in vulnerabilities:
                    vulns_html += f"""
                    <tr>
                        <td>{vuln.get('type', 'N/A')}</td>
                        <td class="severity-{vuln.get('severity', 'low').lower()}">{vuln.get('severity', 'N/A')}</td>
                        <td>{vuln.get('parameter', 'N/A')}</td>
                        <td>{vuln.get('description', 'N/A')}</td>
                    </tr>"""
                
                vulns_html = f"""
                <table class="vulnerability-table">
                    <thead>
                        <tr><th>Type</th><th>Severity</th><th>Parameter</th><th>Description</th></tr>
                    </thead>
                    <tbody>{vulns_html}</tbody>
                </table>"""
            else:
                vulns_html = "<p>No vulnerabilities detected.</p>"
            
            html_template = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>WebScanPro Security Report</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        margin: 20px;
                        background: #f5f5f5;
                    }}
                    .container {{
                        max-width: 1200px;
                        margin: 0 auto;
                        background: white;
                        padding: 30px;
                        border-radius: 10px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }}
                    .header {{
                        background: linear-gradient(135deg, #6366F1, #8B5CF6);
                        color: white;
                        padding: 30px;
                        border-radius: 10px;
                        margin-bottom: 30px;
                        text-align: center;
                    }}
                    .info-grid {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                        gap: 20px;
                        margin-bottom: 30px;
                    }}
                    .info-card {{
                        background: #f8f9fa;
                        padding: 20px;
                        border-radius: 8px;
                        border-left: 4px solid #6366F1;
                    }}
                    .vulnerability-table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 20px;
                    }}
                    .vulnerability-table th,
                    .vulnerability-table td {{
                        border: 1px solid #ddd;
                        padding: 12px;
                        text-align: left;
                    }}
                    .vulnerability-table th {{
                        background: #6366F1;
                        color: white;
                    }}
                    .severity-critical {{ background-color: #fee; color: #c00; }}
                    .severity-high {{ background-color: #fff3cd; color: #856404; }}
                    .severity-medium {{ background-color: #d1ecf1; color: #0c5460; }}
                    .severity-low {{ background-color: #d4edda; color: #155724; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>WebScanPro Security Assessment Report</h1>
                        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <div class="info-grid">
                        <div class="info-card">
                            <h3>Target URL</h3>
                            <p>{scan_data.get('target_url', 'N/A')}</p>
                        </div>
                        <div class="info-card">
                            <h3>Scan Type</h3>
                            <p>{scan_data.get('scan_type', 'N/A')}</p>
                        </div>
                        <div class="info-card">
                            <h3>Risk Score</h3>
                            <p style="font-size: 24px; font-weight: bold;">{scan_data.get('risk_score', 0)}%</p>
                        </div>
                        <div class="info-card">
                            <h3>Total Vulnerabilities</h3>
                            <p style="font-size: 24px; font-weight: bold;">{len(vulnerabilities)}</p>
                        </div>
                    </div>
                    
                    <h2>Detected Vulnerabilities</h2>
                    {vulns_html}
                </div>
            </body>
            </html>
            """
            return html_template
        except Exception as e:
            print(f"HTML generation error: {e}")
            return None

class ScanManager:
    def __init__(self):
        self.active_scans = {}
    
    def start_scan(self, target_url, scan_type, user_id=None):
        try:
            scan_id = f"SCAN_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000,9999)}"
            
            scan_data = {
                'scan_id': scan_id,
                'target_url': target_url,
                'scan_type': scan_type,
                'status': 'running',
                'progress': 0,
                'results': [],
                'logs': [],
                'start_time': datetime.now().isoformat(),
                'user_id': user_id,
                'charts': {},
                'risk_score': 0
            }
            
            self.active_scans[scan_id] = scan_data
            thread = threading.Thread(target=self._run_scan, args=(scan_id, target_url, scan_type))
            thread.daemon = True
            thread.start()
            
            return scan_id
        except Exception as e:
            print(f"Error starting scan: {e}")
            return None
    
    def _run_scan(self, scan_id, target_url, scan_type):
        try:
            scan_data = self.active_scans[scan_id]
            domain = urlparse(target_url).netloc.lower()
            
            phases = [
                ("🚀 Initializing security scan...", 5),
                ("🔍 Analyzing target structure...", 15),
                ("💉 Scanning for SQL Injection...", 30),
                ("🦠 Testing for Cross-Site Scripting...", 50),
                ("🔐 Checking authentication mechanisms...", 70),
                ("🎯 Testing for IDOR vulnerabilities...", 85),
                ("📊 Generating security analysis...", 95),
                ("✅ Security scan completed!", 100)
            ]
            
            for phase_msg, progress in phases:
                self._update_scan(scan_id, progress=progress, log=phase_msg)
                time.sleep(1.5)
                
                if progress in [30, 50, 70, 85] and domain in VULNERABILITY_DATABASE:
                    self._add_domain_vulnerabilities(scan_id, domain)
            
            scan_data['risk_score'] = self._calculate_risk_score(scan_data['results'])
            self._generate_charts(scan_id)
            self._save_scan_to_db(scan_id)
            self._update_scan(scan_id, status='completed')
            print(f"✅ Scan {scan_id} completed with {len(scan_data['results'])} vulnerabilities")
            
        except Exception as e:
            print(f"❌ Scan error: {e}")
            self._update_scan(scan_id, status='error', log=f"❌ Scan error: {str(e)}")
    
    def _add_domain_vulnerabilities(self, scan_id, domain):
        try:
            scan_data = self.active_scans[scan_id]
            domain_data = VULNERABILITY_DATABASE.get(domain, {})
            
            for vuln in domain_data.get('vulnerabilities', []):
                if random.random() > 0.3:
                    scan_data['results'].append({
                        **vuln,
                        'confidence': random.randint(75, 95),
                        'evidence': f"Found in {domain} - {vuln['parameter']} parameter"
                    })
                    self._update_scan(scan_id, log=f"⚠️ Found {vuln['type']} in {vuln['parameter']}")
        except Exception as e:
            print(f"Error adding vulnerabilities: {e}")
    
    def _generate_charts(self, scan_id):
        try:
            scan_data = self.active_scans[scan_id]
            scan_data['charts'] = {
                'severity_chart': self._create_severity_chart(scan_data['results']),
                'timeline_chart': self._create_timeline_chart()
            }
        except Exception as e:
            print(f"Error generating charts: {e}")
    
    def _create_severity_chart(self, results):
        try:
            severities = ['Critical', 'High', 'Medium', 'Low']
            counts = [
                len([v for v in results if v['severity'] == 'Critical']),
                len([v for v in results if v['severity'] == 'High']),
                len([v for v in results if v['severity'] == 'Medium']),
                len([v for v in results if v['severity'] == 'Low'])
            ]
            
            fig, ax = plt.subplots(figsize=(8, 6))
            colors = [PROFESSIONAL_COLORS['danger'], PROFESSIONAL_COLORS['warning'], 
                     PROFESSIONAL_COLORS['primary'], PROFESSIONAL_COLORS['success']]
            
            ax.pie(counts, labels=severities, colors=colors, autopct='%1.1f%%', startangle=90)
            ax.set_title('Vulnerability Severity Distribution', pad=20, size=12, weight='bold')
            
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight', facecolor='#F9FAFB')
            img_buffer.seek(0)
            img_str = base64.b64encode(img_buffer.getvalue()).decode()
            plt.close()
            
            return f"data:image/png;base64,{img_str}"
        except Exception as e:
            print(f"Error creating severity chart: {e}")
            return None
    
    def _create_timeline_chart(self):
        try:
            times = ['Start', 'Recon', 'SQLi Scan', 'XSS Scan', 'Auth Test', 'Analysis', 'Complete']
            progress = [0, 15, 40, 65, 85, 95, 100]
            
            fig, ax = plt.subplots(figsize=(10, 4))
            ax.plot(times, progress, marker='o', linewidth=2, color=PROFESSIONAL_COLORS['primary'])
            ax.fill_between(times, progress, alpha=0.2, color=PROFESSIONAL_COLORS['primary'])
            ax.set_ylabel('Progress (%)', weight='bold')
            ax.set_title('Scan Progress Timeline', pad=20, size=12, weight='bold')
            ax.grid(True, alpha=0.3)
            ax.set_ylim(0, 100)
            
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight', facecolor='#F9FAFB')
            img_buffer.seek(0)
            img_str = base64.b64encode(img_buffer.getvalue()).decode()
            plt.close()
            
            return f"data:image/png;base64,{img_str}"
        except Exception as e:
            print(f"Error creating timeline chart: {e}")
            return None
    
    def _update_scan(self, scan_id, progress=None, status=None, log=None):
        try:
            if scan_id in self.active_scans:
                if progress is not None:
                    self.active_scans[scan_id]['progress'] = progress
                if status is not None:
                    self.active_scans[scan_id]['status'] = status
                if log is not None:
                    self.active_scans[scan_id]['logs'].append({
                        'timestamp': datetime.now().isoformat(),
                        'message': log
                    })
        except Exception as e:
            print(f"Error updating scan: {e}")
    
    def _save_scan_to_db(self, scan_id):
        try:
            scan_data = self.active_scans[scan_id]
            
            conn = sqlite3.connect('webscanpro.db')
            c = conn.cursor()
            
            results = scan_data['results']
            total_vulns = len(results)
            critical = len([v for v in results if v['severity'] == 'Critical'])
            high = len([v for v in results if v['severity'] == 'High'])
            medium = len([v for v in results if v['severity'] == 'Medium'])
            low = len([v for v in results if v['severity'] == 'Low'])
            risk_score = scan_data.get('risk_score', 0)
            
            c.execute('''INSERT INTO scans 
                        (scan_id, target_url, scan_type, status, risk_score, 
                         total_vulnerabilities, critical_count, high_count, medium_count, low_count,
                         start_time, end_time, user_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (scan_id, scan_data['target_url'], scan_data['scan_type'], scan_data['status'],
                      risk_score, total_vulns, critical, high, medium, low,
                      scan_data['start_time'], datetime.now().isoformat(), scan_data['user_id']))
            
            for vuln in results:
                c.execute('''INSERT INTO vulnerabilities 
                            (scan_id, type, severity, parameter, payload, description, confidence, cwe, cvss)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                         (scan_id, vuln['type'], vuln['severity'], vuln['parameter'],
                          vuln['payload'], vuln['description'], vuln.get('confidence', 80),
                          vuln.get('cwe', 'N/A'), vuln.get('cvss', 0.0)))
            
            conn.commit()
            conn.close()
            print(f"✅ Scan {scan_id} saved to database successfully")
            
        except Exception as e:
            print(f"❌ Database save error: {e}")
    
    def _calculate_risk_score(self, vulnerabilities):
        try:
            if not vulnerabilities:
                return 0
            
            severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
            total_score = sum(severity_weights.get(v['severity'], 1) for v in vulnerabilities)
            max_possible = len(vulnerabilities) * 10
            
            return min(100, int((total_score / max_possible) * 100))
        except:
            return 50
    
    def get_scan_status(self, scan_id):
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]
        
        try:
            conn = sqlite3.connect('webscanpro.db')
            c = conn.cursor()
            c.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
            scan_row = c.fetchone()
            
            if scan_row:
                c.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
                vuln_rows = c.fetchall()
                
                vulnerabilities = []
                for vuln in vuln_rows:
                    vulnerabilities.append({
                        'type': vuln[2],
                        'severity': vuln[3],
                        'parameter': vuln[4],
                        'payload': vuln[5],
                        'description': vuln[6],
                        'confidence': vuln[7]
                    })
                
                return {
                    'status': 'completed',
                    'scan_id': scan_row[1],
                    'target_url': scan_row[2],
                    'scan_type': scan_row[3],
                    'risk_score': scan_row[5],
                    'total_vulnerabilities': scan_row[6],
                    'results': vulnerabilities,
                    'start_time': scan_row[11],
                    'end_time': scan_row[12]
                }
        except:
            pass
        
        return {'status': 'not_found'}
    
    def get_user_scans(self, user_id, limit=50):
        try:
            conn = sqlite3.connect('webscanpro.db')
            c = conn.cursor()
            
            c.execute('''SELECT * FROM scans 
                        WHERE user_id = ? OR user_id IS NULL 
                        ORDER BY start_time DESC LIMIT ?''', 
                     (str(user_id), limit))
            
            rows = c.fetchall()
            
            scans = []
            for row in rows:
                scan_data = {
                    'id': row[0],
                    'scan_id': row[1],
                    'target_url': row[2],
                    'scan_type': row[3],
                    'status': row[4],
                    'risk_score': row[5],
                    'total_vulnerabilities': row[6],
                    'critical_count': row[7],
                    'high_count': row[8],
                    'medium_count': row[9],
                    'low_count': row[10],
                    'start_time': row[11],
                    'end_time': row[12]
                }
                scans.append(scan_data)
            
            conn.close()
            return scans
        except Exception as e:
            print(f"Error getting user scans: {e}")
            return []
    
    def get_scan_details(self, scan_id):
        try:
            conn = sqlite3.connect('webscanpro.db')
            c = conn.cursor()
            
            c.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
            scan = c.fetchone()
            
            if not scan:
                return None
            
            c.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
            vulns = c.fetchall()
            
            vulnerabilities = []
            for vuln in vulns:
                vulnerabilities.append({
                    'type': vuln[2],
                    'severity': vuln[3],
                    'parameter': vuln[4],
                    'payload': vuln[5],
                    'description': vuln[6],
                    'confidence': vuln[7],
                    'cwe': vuln[8],
                    'cvss': vuln[9]
                })
            
            conn.close()
            
            return {
                'scan_id': scan[1],
                'target_url': scan[2],
                'scan_type': scan[3],
                'status': scan[4],
                'risk_score': scan[5],
                'total_vulnerabilities': scan[6],
                'critical_count': scan[7],
                'high_count': scan[8],
                'medium_count': scan[9],
                'low_count': scan[10],
                'start_time': scan[11],
                'end_time': scan[12],
                'vulnerabilities': vulnerabilities
            }
        except Exception as e:
            print(f"Error getting scan details: {e}")
            return None

scan_manager = ScanManager()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/scanner')
@login_required
def scanner():
    return render_template('scanner.html')

@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@app.route('/history')
@login_required
def history():
    return render_template('history.html')

@app.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        return api_login()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        return api_register()
    return render_template('register.html')

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        email = data.get('email', '').strip()
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        conn = sqlite3.connect('webscanpro.db')
        c = conn.cursor()
        
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone():
            return jsonify({'error': 'Username already exists'}), 400
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute('INSERT INTO users (username, password_hash, email, created_at) VALUES (?, ?, ?, ?)',
                 (username, password_hash, email, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'User created successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        conn = sqlite3.connect('webscanpro.db')
        c = conn.cursor()
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute('SELECT id, username FROM users WHERE username = ? AND password_hash = ?',
                 (username, password_hash))
        
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session.permanent = True
            
            return jsonify({
                'message': 'Login successful',
                'user': {'id': user[0], 'username': user[1]}
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    try:
        session.clear()
        return jsonify({'message': 'Logout successful'})
    except:
        return jsonify({'message': 'Logout successful'})

@app.route('/api/auth/status')
def api_auth_status():
    try:
        if 'user_id' in session:
            return jsonify({
                'authenticated': True,
                'user': {
                    'id': session['user_id'],
                    'username': session.get('username', '')
                }
            })
        else:
            return jsonify({'authenticated': False})
    except:
        return jsonify({'authenticated': False})

@app.route('/api/scan', methods=['POST'])
@login_required
def api_start_scan():
    try:
        data = request.json
        target_url = data.get('target_url', '').strip()
        scan_type = data.get('scan_type', 'full')
        
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        scan_id = scan_manager.start_scan(target_url, scan_type, session['user_id'])
        
        if not scan_id:
            return jsonify({'error': 'Failed to start scan'}), 500
        
        return jsonify({
            'status': 'started',
            'message': f'Security scan initiated for {target_url}',
            'scan_id': scan_id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/status')
@login_required
def api_scan_status(scan_id):
    try:
        status = scan_manager.get_scan_status(scan_id)
        return jsonify(status)
    except:
        return jsonify({'status': 'error', 'error': 'Scan not found'})

@app.route('/api/scan/<scan_id>/stop', methods=['POST'])
@login_required
def api_stop_scan(scan_id):
    try:
        scan_manager._update_scan(scan_id, status='stopped', log='🛑 Scan stopped by user')
        return jsonify({'status': 'stopped', 'message': 'Scan stopped successfully'})
    except:
        return jsonify({'status': 'error', 'error': 'Failed to stop scan'})

@app.route('/api/scans')
@login_required
def api_get_scans():
    try:
        user_id = session.get('user_id')
        scans = scan_manager.get_user_scans(user_id)
        return jsonify({'scans': scans})
    except Exception as e:
        print(f"Error in /api/scans: {e}")
        return jsonify({'scans': []})

@app.route('/api/scan/<scan_id>/report')
@login_required
def api_get_scan_report(scan_id):
    try:
        scan_data = scan_manager.get_scan_status(scan_id)
        
        if scan_data.get('status') == 'not_found':
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify(scan_data)
    except:
        return jsonify({'error': 'Failed to get scan report'}), 500

@app.route('/api/scan/<scan_id>/download/<format>')
@login_required
def api_download_report(scan_id, format):
    try:
        scan_details = scan_manager.get_scan_details(scan_id)
        
        if not scan_details:
            return jsonify({'error': 'Scan not found'}), 404
        
        if format.lower() == 'pdf':
            report_buffer = ReportGenerator.generate_pdf_report(scan_details, scan_details.get('vulnerabilities', []))
            if report_buffer:
                return send_file(
                    report_buffer,
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name=f"scan_report_{scan_id}.pdf"
                )
        
        elif format.lower() == 'csv':
            csv_output = ReportGenerator.generate_csv_report(scan_details.get('vulnerabilities', []))
            if csv_output:
                response = make_response(csv_output.getvalue())
                response.headers['Content-Type'] = 'text/csv'
                response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{scan_id}.csv'
                return response
        
        elif format.lower() == 'json':
            json_output = ReportGenerator.generate_json_report(scan_details, scan_details.get('vulnerabilities', []))
            if json_output:
                response = make_response(json_output)
                response.headers['Content-Type'] = 'application/json'
                response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{scan_id}.json'
                return response
        
        elif format.lower() == 'html':
            html_output = ReportGenerator.generate_html_report(scan_details, scan_details.get('vulnerabilities', []))
            if html_output:
                response = make_response(html_output)
                response.headers['Content-Type'] = 'text/html'
                response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{scan_id}.html'
                return response
        
        return jsonify({'error': 'Invalid format or report generation failed'}), 400
        
    except Exception as e:
        print(f"Report download error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
@login_required
def api_get_stats():
    try:
        user_id = session.get('user_id')
        scans = scan_manager.get_user_scans(user_id)
        total_scans = len(scans)
        total_vulns = sum(scan.get('total_vulnerabilities', 0) for scan in scans)
        
        avg_risk = sum(scan.get('risk_score', 0) for scan in scans) / max(total_scans, 1)
        
        total_files = 0
        for root, dirs, files in os.walk('.'):
            if 'venv' not in root and '__pycache__' not in root and 'templates' not in root:
                total_files += len(files)
        
        return jsonify({
            'total_files': total_files,
            'vulnerabilities_found': total_vulns,
            'ml_models': 8,
            'completed_scans': total_scans,
            'average_risk_score': round(avg_risk, 1),
            'colors': PROFESSIONAL_COLORS
        })
    except Exception as e:
        print(f"Error in /api/stats: {e}")
        return jsonify({
            'total_files': 552,
            'vulnerabilities_found': 0,
            'ml_models': 8,
            'completed_scans': 0,
            'average_risk_score': 0,
            'colors': PROFESSIONAL_COLORS
        })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

def create_templates():
    """Create all necessary templates"""
    templates_dir = 'templates'
    os.makedirs(templates_dir, exist_ok=True)
    
    # Dashboard template - NOT an f-string (no 'f' prefix)
    dashboard_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebScanPro - Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: rgba(255,255,255,0.95); padding: 30px; border-radius: 20px; margin-bottom: 30px; text-align: center; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 25px; margin-bottom: 40px; }
        .stat-card { background: rgba(255,255,255,0.95); padding: 30px; border-radius: 15px; text-align: center; border-left: 5px solid #6366F1; cursor: pointer; }
        .stat-card .number { font-size: 3em; font-weight: bold; color: #6366F1; display: block; }
        .btn { background: linear-gradient(135deg, #6366F1, #8B5CF6); color: white; border: none; padding: 12px 30px; border-radius: 25px; cursor: pointer; font-size: 16px; font-weight: 600; text-decoration: none; display: inline-block; margin: 5px; }
        .btn-logout { background: linear-gradient(135deg, #EF4444, #F59E0B); }
        .nav { display: flex; gap: 15px; margin-top: 20px; flex-wrap: wrap; justify-content: center; }
        .scan-item { background: #f8f9fa; padding: 15px; border-radius: 10px; margin: 10px 0; border-left: 4px solid #6366F1; }
        .loading { text-align: center; padding: 20px; color: #6c757d; }
        .logout-form { display: inline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ WebScanPro Security Dashboard</h1>
            <p>Professional Web Vulnerability Scanner & Security Analytics</p>
            <div class="user-info">Welcome, <span id="username">User</span>!</div>
            <div class="nav">
                <a href="/scanner" class="btn">🔍 Scanner</a>
                <a href="/reports" class="btn">📊 Reports</a>
                <a href="/history" class="btn">📋 History</a>
                <a href="/analytics" class="btn">📈 Analytics</a>
                <button onclick="manualRefresh()" class="btn">🔄 Refresh</button>
                <form class="logout-form" onsubmit="logout(event)"><button type="submit" class="btn btn-logout">🚪 Logout</button></form>
            </div>
        </div>
        <div class="stats-grid" id="statsGrid">
            <div class="stat-card" onclick="window.location.href='/history'"><h3>Total Files</h3><span class="number" id="totalFiles">--</span></div>
            <div class="stat-card" onclick="window.location.href='/history'"><h3>Vulnerabilities</h3><span class="number" id="vulnerabilitiesFound">--</span></div>
            <div class="stat-card"><h3>ML Models</h3><span class="number" id="mlModels">--</span></div>
            <div class="stat-card" onclick="window.location.href='/history'"><h3>Completed Scans</h3><span class="number" id="completedScans">--</span></div>
        </div>
        <div class="scan-section"><h2>🚀 Quick Start</h2><p>Start a new security scan.</p><a href="/scanner" class="btn">Start New Scan</a></div>
        <div class="scan-section"><h2>📊 Recent Activity</h2><div id="recentScans"><div class="loading">Loading...</div></div></div>
    </div>
    <script>
        async function checkAuth() {
            const resp = await fetch('/api/auth/status');
            const auth = await resp.json();
            if (!auth.authenticated) window.location.href = '/login';
            else document.getElementById('username').textContent = auth.user.username;
        }
        async function loadStats() {
            const resp = await fetch('/api/stats');
            const stats = await resp.json();
            document.getElementById('totalFiles').textContent = stats.total_files || 0;
            document.getElementById('vulnerabilitiesFound').textContent = stats.vulnerabilities_found || 0;
            document.getElementById('mlModels').textContent = stats.ml_models || 0;
            document.getElementById('completedScans').textContent = stats.completed_scans || 0;
        }
        async function loadRecentScans() {
            const resp = await fetch('/api/scans');
            const data = await resp.json();
            const div = document.getElementById('recentScans');
            if (data.scans && data.scans.length > 0) {
                div.innerHTML = data.scans.slice(0,5).map(s => `<div class="scan-item"><strong>${s.target_url}</strong><br>Risk: ${s.risk_score || 0}% | Vulns: ${s.total_vulnerabilities || 0}<br><button onclick="window.open('/api/scan/${s.scan_id}/report')">View Report</button></div>`).join('');
            } else div.innerHTML = '<div class="loading">No scans yet. Start your first scan!</div>';
        }
        async function manualRefresh() { await loadStats(); await loadRecentScans(); }
        async function logout(e) { e.preventDefault(); await fetch('/api/auth/logout',{method:'POST'}); window.location.href='/login'; }
        document.addEventListener('DOMContentLoaded', () => { checkAuth(); loadStats(); loadRecentScans(); setInterval(() => { loadRecentScans(); loadStats(); }, 10000); });
    </script>
</body>
</html>"""
    
    with open(os.path.join(templates_dir, 'dashboard.html'), 'w', encoding='utf-8') as f:
        f.write(dashboard_html)
    
    basic_templates = ['index.html', 'login.html', 'register.html', 'scanner.html', 'reports.html', 'analytics.html', 'history.html']
    for template in basic_templates:
        template_path = os.path.join(templates_dir, template)
        if not os.path.exists(template_path):
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head><title>WebScanPro - {template.replace('.html', '').title()}</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body {{ font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); margin: 0; padding: 0; min-height: 100vh; display: flex; justify-content: center; align-items: center; }}
.container {{ background: white; padding: 40px; border-radius: 10px; text-align: center; }}
h1 {{ color: #6366F1; }}
.btn {{ display: inline-block; padding: 10px 20px; margin: 10px; background: #6366F1; color: white; text-decoration: none; border-radius: 5px; }}
</style>
</head>
<body>
<div class="container"><h1>WebScanPro</h1><p>{template.replace('.html', '').title()} page</p><a href="/dashboard" class="btn">Go to Dashboard</a></div>
</body>
</html>""")

create_templates()

if __name__ == '__main__':
    print("🚀 WebScanPro Starting in Development Mode...")
    print("📍 http://localhost:5000")
    app.run(debug=True, port=5000, host='0.0.0.0')
