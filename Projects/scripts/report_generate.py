import pandas as pd
from jinja2 import Template
import pdfkit
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.template_dir = "projects/webscanprod/templates/"
        self.html_output_dir = "projects/webscanprod/reports/html/"
        self.pdf_output_dir = "projects/webscanprod/reports/pdf/"
        
    def generate_html_report(self, data, confidence_summary):
        """Generate interactive HTML report with Plotly charts"""
        
        # Prepare data for template
        report_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_findings': len(data),
            'high_confidence_count': len(data[data['confidence_group'] == 'High Confidence']),
            'medium_confidence_count': len(data[data['confidence_group'] == 'Medium Confidence']),
            'low_confidence_count': len(data[data['confidence_group'] == 'Low Confidence']),
            'confidence_summary': confidence_summary.to_dict(),
            'findings_table': data.to_dict('records')
        }
        
        # Load and render template
        with open(os.path.join(self.template_dir, 'report_template.html'), 'r') as f:
            template_content = f.read()
        
        template = Template(template_content)
        rendered_html = template.render(**report_data)
        
        # Save HTML report
        output_path = os.path.join(self.html_output_dir, 'webscan_ai_report.html')
        with open(output_path, 'w') as f:
            f.write(rendered_html)
        
        print(f"HTML report generated: {output_path}")
        return output_path
    
    def generate_pdf_report(self, data, confidence_summary):
        """Generate PDF report with static charts"""
        filename = f"webscan_ai_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        output_path = os.path.join(self.pdf_output_dir, filename)
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title = Paragraph("AI-Enhanced Vulnerability Scan Report", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))
        
        # Summary section
        summary_text = Paragraph(f"""
        <b>Report Summary:</b><br/>
        Total Findings: {len(data)}<br/>
        High Confidence Predictions: {len(data[data['confidence_group'] == 'High Confidence'])}<br/>
        Medium Confidence Predictions: {len(data[data['confidence_group'] == 'Medium Confidence'])}<br/>
        Low Confidence Predictions: {len(data[data['confidence_group'] == 'Low Confidence'])}<br/>
        Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        """, styles['Normal'])
        story.append(summary_text)
        story.append(Spacer(1, 12))
        
        # Confidence summary table
        confidence_data = [['Confidence Group', 'Count', 'Mean Confidence', 'Std Dev']]
        for group in ['High Confidence', 'Medium Confidence', 'Low Confidence']:
            group_data = data[data['confidence_group'] == group]
            if len(group_data) > 0:
                row = [
                    group,
                    str(len(group_data)),
                    f"{group_data['ml_confidence'].mean():.3f}",
                    f"{group_data['ml_confidence'].std():.3f}"
                ]
                confidence_data.append(row)
        
        confidence_table = Table(confidence_data)
        confidence_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(confidence_table)
        story.append(Spacer(1, 12))
        
        # Add visualization images if they exist
        viz_paths = [
            'reports/pdf/ml_confidence_dist.png',
            'reports/pdf/confidence_heatmap.png'
        ]
        
        for viz_path in viz_paths:
            if os.path.exists(viz_path):
                img = Image(viz_path, width=400, height=300)
                story.append(img)
                story.append(Spacer(1, 12))
        
        doc.build(story)
        print(f"PDF report generated: {output_path}")
        return output_path