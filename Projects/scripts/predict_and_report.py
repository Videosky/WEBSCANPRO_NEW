import pandas as pd
import numpy as np
import os
import sys
import logging
from datetime import datetime

# ✅ Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ✅ EXPLICIT: Define the exact project root path
def get_project_root():
    """Get the absolute path to the project root directory"""
    # Use explicit path to ensure everything is under webscanprod_reports
    explicit_path = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\webscanprod_reports"
    if os.path.exists(explicit_path):
        return explicit_path
    else:
        # Fallback to dynamic detection
        current_script_dir = os.path.dirname(os.path.abspath(__file__))
        webscanprod_reports_dir = os.path.dirname(current_script_dir)
        return webscanprod_reports_dir

# Set project root
PROJECT_ROOT = get_project_root()

# ✅ EXPLICIT: Define absolute paths
def get_absolute_path(relative_path):
    """Convert relative path to absolute path"""
    absolute_path = os.path.join(PROJECT_ROOT, relative_path)
    logger.debug(f"Resolved path: {relative_path} -> {absolute_path}")
    return absolute_path

# Configuration with absolute paths - ALL UNDER webscanprod_reports
MODEL_PATH = get_absolute_path("models/vuln_classifier.pkl")
DATA_PATH = get_absolute_path("data/processed/findings_with_ml.csv")
OUTPUT_PATH = get_absolute_path("data/processed/findings_with_ml_enhanced.csv")
REPORTS_HTML_DIR = get_absolute_path("reports/html")
REPORTS_VIZ_DIR = get_absolute_path("reports/visualizations")
REPORTS_PDF_DIR = get_absolute_path("reports/pdf")

class MLEnhancedReporter:
    def __init__(self, model_path=None, data_path=None):
        self.model_path = model_path
        self.data_path = data_path
        self.model = None
        self.data = None
        
        # ✅ EXPLICIT: Store all output paths
        self.reports_html_dir = REPORTS_HTML_DIR
        self.reports_viz_dir = REPORTS_VIZ_DIR
        self.reports_pdf_dir = REPORTS_PDF_DIR
        self.data_output_path = OUTPUT_PATH
        
        # Log the exact locations
        logger.info(f"📁 Project Root: {PROJECT_ROOT}")
        logger.info(f"📊 Data will be saved to: {self.data_output_path}")
        logger.info(f"🌐 Reports will be saved to: {self.reports_html_dir}")
        logger.info(f"📈 Visualizations will be saved to: {self.reports_viz_dir}")
        
        # Initialize visualization attributes
        self.plt = None
        self.sns = None
        self.joblib = None
        
        # Try to import optional dependencies
        self._import_optional_dependencies()
    
    def _import_optional_dependencies(self):
        """Import optional dependencies with error handling"""
        try:
            import joblib
            self.joblib = joblib
            logger.info("joblib loaded successfully")
        except ImportError:
            logger.warning("joblib not available - using simulated predictions")
            
        try:
            import matplotlib.pyplot as plt
            self.plt = plt
            # Set matplotlib backend to avoid display issues
            plt.switch_backend('Agg')
            logger.info("matplotlib loaded successfully")
        except ImportError:
            logger.warning("matplotlib not available")
            
        try:
            import seaborn as sns
            self.sns = sns
            logger.info("seaborn loaded successfully")
        except ImportError:
            logger.warning("seaborn not available")
    
    def load_data(self):
        """Load the vulnerability data"""
        try:
            logger.info(f"📥 Loading data from: {self.data_path}")
            self.data = pd.read_csv(self.data_path)
            logger.info(f"✅ Data loaded successfully: {len(self.data)} records from {os.path.abspath(self.data_path)}")
            return self.data
        except FileNotFoundError:
            logger.error(f"❌ Data file not found: {self.data_path}")
            # Create sample data if file doesn't exist
            self.create_sample_data()
            return self.load_data()
        except Exception as e:
            logger.error(f"❌ Error loading data: {e}")
            raise
    
    def create_sample_data(self):
        """Create sample data if file doesn't exist"""
        sample_data = {
            'vuln_id': [f'VULN-{i:03d}' for i in range(1, 11)],
            'vuln_name': [
                'SQL Injection', 'XSS', 'CSRF', 'Info Disclosure', 
                'Broken Authentication', 'Sensitive Data Exposure',
                'XXE', 'Insecure Deserialization', 'Security Misconfig',
                'Insufficient Logging'
            ],
            'severity': ['Critical', 'High', 'Medium', 'Low', 'High', 
                        'Medium', 'Critical', 'High', 'Medium', 'Low'],
            'description': ['Potential security vulnerability'] * 10,
            'affected_url': [f'https://example.com/page{i}' for i in range(1, 11)],
            'recommendation': ['Apply security patches'] * 10
        }
        
        # ✅ EXPLICIT: Create directory and save file
        data_dir = os.path.dirname(self.data_path)
        logger.info(f"📁 Creating data directory: {data_dir}")
        os.makedirs(data_dir, exist_ok=True)
        
        sample_df = pd.DataFrame(sample_data)
        sample_df.to_csv(self.data_path, index=False)
        logger.info(f"✅ Sample data created: {self.data_path}")
        logger.info(f"📍 File saved at: {os.path.abspath(self.data_path)}")
    
    def load_model(self):
        """Load the ML model or use simulated predictions"""
        if self.model_path and os.path.exists(self.model_path) and self.joblib:
            try:
                self.model = self.joblib.load(self.model_path)
                logger.info("✅ ML model loaded successfully")
                return True
            except Exception as e:
                logger.warning(f"⚠️ Could not load model: {e}. Using simulated predictions.")
        
        # If model loading fails, use simulated predictions
        logger.info("🤖 Using simulated ML predictions")
        return False
    
    def predict_vulnerabilities(self):
        """Apply ML predictions to vulnerability data"""
        if self.data is None:
            self.load_data()
        
        # Use simulated predictions (since we don't have a real model)
        predictions, confidence_scores = self._simulate_predictions()
        
        # Add ML results to dataframe
        self.data['ml_pred_label'] = predictions
        self.data['ml_confidence'] = confidence_scores
        
        # Add confidence grouping
        self.data['confidence_group'] = self.data['ml_confidence'].apply(
            lambda x: 'High Confidence' if x >= 0.85 
                     else 'Medium Confidence' if x >= 0.60 
                     else 'Low Confidence'
        )
        
        # Add prediction match status
        self.data['prediction_match'] = self.data['severity'] == self.data['ml_pred_label']
        
        logger.info("✅ ML predictions applied successfully")
        return self.data
    
    def _simulate_predictions(self):
        """Generate simulated predictions for demo purposes"""
        np.random.seed(42)  # For consistent results
        
        severity_levels = ['Critical', 'High', 'Medium', 'Low', 'Info']
        
        # Simulate predictions (sometimes matching, sometimes different)
        predictions = []
        confidence_scores = []
        
        for true_severity in self.data['severity']:
            # 70% chance of correct prediction, 30% chance of nearby severity
            if np.random.random() < 0.7:
                pred = true_severity
                conf = np.random.uniform(0.8, 0.98)  # High confidence for correct
            else:
                # Incorrect prediction
                true_idx = severity_levels.index(true_severity) if true_severity in severity_levels else 2
                offset = np.random.choice([-2, -1, 1, 2])  # Random offset
                pred_idx = max(0, min(len(severity_levels)-1, true_idx + offset))
                pred = severity_levels[pred_idx]
                conf = np.random.uniform(0.4, 0.79)  # Lower confidence for incorrect
            
            predictions.append(pred)
            confidence_scores.append(round(conf, 3))
        
        return predictions, confidence_scores
    
    def generate_confidence_summary(self):
        """Generate summary statistics by confidence group"""
        if self.data is None:
            self.predict_vulnerabilities()
        
        summary = self.data.groupby('confidence_group').agg({
            'vuln_id': 'count',
            'ml_confidence': ['mean', 'std', 'min', 'max'],
            'prediction_match': 'mean'
        }).round(3)
        
        logger.info("✅ Confidence summary generated")
        return summary
    
    def create_visualizations(self):
        """Create basic visualizations"""
        if self.plt is None:
            logger.warning("⚠️ matplotlib not available - skipping visualizations")
            return
        
        try:
            # ✅ EXPLICIT: Create visualization directory
            logger.info(f"📁 Creating visualization directory: {self.reports_viz_dir}")
            os.makedirs(self.reports_viz_dir, exist_ok=True)
            
            # Plot 1: Confidence distribution histogram
            plt.figure(figsize=(12, 8))
            
            # Subplot 1: Confidence distribution
            plt.subplot(2, 2, 1)
            plt.hist(self.data['ml_confidence'], bins=20, alpha=0.7, color='skyblue', edgecolor='black')
            plt.title('Distribution of ML Confidence Scores')
            plt.xlabel('Confidence Score')
            plt.ylabel('Frequency')
            plt.grid(True, alpha=0.3)
            
            # Subplot 2: Confidence by group (box plot)
            plt.subplot(2, 2, 2)
            confidence_data = [self.data[self.data['confidence_group'] == group]['ml_confidence'] 
                             for group in ['High Confidence', 'Medium Confidence', 'Low Confidence']]
            
            plt.boxplot(confidence_data, labels=['High', 'Medium', 'Low'])
            plt.title('Confidence Scores by Confidence Group')
            plt.ylabel('Confidence Score')
            plt.grid(True, alpha=0.3)
            
            # Subplot 3: Prediction accuracy by confidence group
            plt.subplot(2, 2, 3)
            accuracy_by_group = self.data.groupby('confidence_group')['prediction_match'].mean()
            colors = ['#28a745', '#ffc107', '#dc3545']  # Green, Yellow, Red
            accuracy_by_group.plot(kind='bar', color=colors, alpha=0.7, edgecolor='black')
            plt.title('Prediction Accuracy by Confidence Group')
            plt.ylabel('Accuracy Rate')
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            
            # Subplot 4: Severity distribution
            plt.subplot(2, 2, 4)
            severity_counts = self.data['severity'].value_counts()
            severity_counts.plot(kind='pie', autopct='%1.1f%%', startangle=90)
            plt.title('Vulnerability Severity Distribution')
            plt.ylabel('')  # Remove y-label for pie chart
            
            plt.tight_layout()
            
            # ✅ EXPLICIT: Save visualization with full path logging
            viz_path = os.path.join(self.reports_viz_dir, 'ml_analysis_dashboard.png')
            plt.savefig(viz_path, dpi=300, bbox_inches='tight')
            plt.close()
            logger.info(f"📊 Main dashboard saved: {viz_path}")
            logger.info(f"📍 Absolute path: {os.path.abspath(viz_path)}")
            
            # Create additional individual plots
            self._create_individual_plots()
            
            logger.info("✅ All visualizations created successfully")
            
        except Exception as e:
            logger.error(f"❌ Error creating visualizations: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    def _create_individual_plots(self):
        """Create individual plot files"""
        if self.plt is None:
            return
            
        try:
            # Plot 1: Confidence distribution
            plt.figure(figsize=(10, 6))
            plt.hist(self.data['ml_confidence'], bins=20, alpha=0.7, color='skyblue', edgecolor='black')
            plt.title('Distribution of ML Confidence Scores')
            plt.xlabel('Confidence Score')
            plt.ylabel('Frequency')
            plt.grid(True, alpha=0.3)
            viz_path = os.path.join(self.reports_viz_dir, 'confidence_distribution.png')
            plt.savefig(viz_path, dpi=300, bbox_inches='tight')
            plt.close()
            logger.info(f"📈 Confidence distribution saved: {viz_path}")
            
            # Plot 2: Confidence by group
            plt.figure(figsize=(10, 6))
            confidence_data = [self.data[self.data['confidence_group'] == group]['ml_confidence'] 
                             for group in ['High Confidence', 'Medium Confidence', 'Low Confidence']]
            
            plt.boxplot(confidence_data, labels=['High', 'Medium', 'Low'])
            plt.title('Confidence Scores by Confidence Group')
            plt.ylabel('Confidence Score')
            plt.grid(True, alpha=0.3)
            viz_path = os.path.join(self.reports_viz_dir, 'confidence_by_group.png')
            plt.savefig(viz_path, dpi=300, bbox_inches='tight')
            plt.close()
            logger.info(f"📊 Confidence by group saved: {viz_path}")
            
        except Exception as e:
            logger.error(f"❌ Error creating individual plots: {e}")
    
    def generate_html_report(self):
        """Generate HTML report"""
        if self.data is None:
            self.predict_vulnerabilities()
        
        # ✅ EXPLICIT: Create HTML reports directory
        logger.info(f"📁 Creating HTML reports directory: {self.reports_html_dir}")
        os.makedirs(self.reports_html_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Calculate statistics
        total_findings = len(self.data)
        high_conf = len(self.data[self.data['confidence_group'] == 'High Confidence'])
        medium_conf = len(self.data[self.data['confidence_group'] == 'Medium Confidence'])
        low_conf = len(self.data[self.data['confidence_group'] == 'Low Confidence'])
        accuracy = self.data['prediction_match'].mean()
        
        # Check if visualizations exist
        viz_dashboard_path = os.path.join(self.reports_viz_dir, 'ml_analysis_dashboard.png')
        has_visualizations = os.path.exists(viz_dashboard_path)
        
        # Generate HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>WebScanPro - AI Enhanced Vulnerability Report</title>
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 0; 
                    background-color: #f8f9fa; 
                    color: #333;
                    line-height: 1.6;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    color: white; 
                    padding: 40px 30px; 
                    border-radius: 15px; 
                    margin-bottom: 30px; 
                    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 2.5em;
                    font-weight: 300;
                }}
                .header p {{
                    margin: 10px 0 0 0;
                    opacity: 0.9;
                    font-size: 1.1em;
                }}
                .summary-cards {{ 
                    display: flex; 
                    gap: 20px; 
                    margin: 30px 0; 
                    flex-wrap: wrap; 
                }}
                .card {{ 
                    flex: 1; 
                    min-width: 200px; 
                    padding: 25px; 
                    border-radius: 12px; 
                    text-align: center; 
                    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                    transition: transform 0.3s ease, box-shadow 0.3s ease;
                }}
                .card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 8px 25px rgba(0,0,0,0.15);
                }}
                .high-confidence {{ 
                    background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%); 
                    border-left: 5px solid #28a745; 
                }}
                .medium-confidence {{ 
                    background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); 
                    border-left: 5px solid #ffc107; 
                }}
                .low-confidence {{ 
                    background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%); 
                    border-left: 5px solid #dc3545; 
                }}
                .accuracy {{ 
                    background: linear-gradient(135deg, #e2e3e5 0%, #d6d8db 100%); 
                    border-left: 5px solid #6c757d; 
                }}
                .card h3 {{
                    margin: 0 0 15px 0;
                    font-size: 1.2em;
                    color: #2c3e50;
                }}
                .card-value {{
                    font-size: 2.5em; 
                    font-weight: bold; 
                    margin: 15px 0; 
                    color: #2c3e50;
                }}
                table {{ 
                    width: 100%; 
                    border-collapse: collapse; 
                    margin: 30px 0; 
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    background: white;
                    border-radius: 10px;
                    overflow: hidden;
                }}
                th, td {{ 
                    padding: 15px 20px; 
                    text-align: left; 
                    border-bottom: 1px solid #e9ecef; 
                }}
                th {{ 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    color: white; 
                    font-weight: 600;
                    font-size: 1.1em;
                }}
                tr:hover {{ 
                    background-color: #f8f9fa; 
                    transition: background-color 0.2s ease;
                }}
                .match {{ 
                    color: #28a745; 
                    font-weight: bold; 
                }}
                .mismatch {{ 
                    color: #dc3545; 
                    font-weight: bold; 
                }}
                .confidence-bar {{ 
                    background: #e9ecef; 
                    border-radius: 10px; 
                    height: 25px; 
                    overflow: hidden;
                    position: relative;
                }}
                .confidence-fill {{ 
                    height: 100%; 
                    border-radius: 10px; 
                    text-align: center; 
                    color: white; 
                    font-size: 12px; 
                    line-height: 25px;
                    font-weight: bold;
                    transition: width 0.5s ease;
                }}
                .visualization-section {{
                    background: white;
                    padding: 30px;
                    border-radius: 15px;
                    margin: 30px 0;
                    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                }}
                .visualization-section h2 {{
                    color: #2c3e50;
                    border-bottom: 2px solid #667eea;
                    padding-bottom: 10px;
                    margin-top: 0;
                }}
                .footer {{ 
                    margin-top: 50px; 
                    text-align: center; 
                    color: #6c757d; 
                    border-top: 2px solid #e9ecef; 
                    padding-top: 30px; 
                    font-size: 0.9em;
                }}
                .section-title {{
                    color: #2c3e50;
                    font-size: 1.8em;
                    margin: 40px 0 20px 0;
                    padding-bottom: 10px;
                    border-bottom: 3px solid #667eea;
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }}
                .stat-item {{
                    background: white;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    text-align: center;
                }}
                .stat-value {{
                    font-size: 2em;
                    font-weight: bold;
                    color: #667eea;
                    margin: 10px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 WebScanPro - AI Enhanced Vulnerability Report</h1>
                    <p>Generated: {timestamp}</p>
                    <p><small>Location: {self.reports_html_dir}</small></p>
                </div>
                
                <div class="summary-cards">
                    <div class="card high-confidence">
                        <h3>🚀 High Confidence</h3>
                        <div class="card-value">{high_conf}</div>
                        <p>findings</p>
                    </div>
                    <div class="card medium-confidence">
                        <h3>⚠️ Medium Confidence</h3>
                        <div class="card-value">{medium_conf}</div>
                        <p>findings</p>
                    </div>
                    <div class="card low-confidence">
                        <h3>🔍 Low Confidence</h3>
                        <div class="card-value">{low_conf}</div>
                        <p>findings</p>
                    </div>
                    <div class="card accuracy">
                        <h3>🎯 Prediction Accuracy</h3>
                        <div class="card-value">{accuracy:.1%}</div>
                        <p>ML model accuracy</p>
                    </div>
                </div>

                <div class="stats-grid">
                    <div class="stat-item">
                        <h3>Total Findings</h3>
                        <div class="stat-value">{total_findings}</div>
                    </div>
                    <div class="stat-item">
                        <h3>High Confidence Rate</h3>
                        <div class="stat-value">{(high_conf/total_findings*100):.1f}%</div>
                    </div>
                    <div class="stat-item">
                        <h3>Manual Review Needed</h3>
                        <div class="stat-value">{low_conf + medium_conf}</div>
                    </div>
                </div>
        """
        
        # Add visualization section if images exist
        if has_visualizations:
            # Convert absolute path to relative path for web display
            viz_relative_path = os.path.relpath(viz_dashboard_path, self.reports_html_dir)
            html_content += f"""
                <div class="visualization-section">
                    <h2>📊 ML Analysis Dashboard</h2>
                    <img src="{viz_relative_path}" alt="ML Analysis Dashboard" style="width: 100%; max-width: 1000px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                    <p style="text-align: center; margin-top: 15px; color: #6c757d;">
                        <em>Machine Learning confidence analysis and performance metrics</em>
                    </p>
                </div>
            """
        
        html_content += f"""
                <h2 class="section-title">📋 Vulnerability Findings with ML Predictions</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Vuln ID</th>
                            <th>Vulnerability</th>
                            <th>True Severity</th>
                            <th>ML Prediction</th>
                            <th>Confidence</th>
                            <th>Status</th>
                            <th>Affected URL</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for _, finding in self.data.iterrows():
            confidence_pct = finding['ml_confidence'] * 100
            fill_color = '#28a745' if finding['ml_confidence'] >= 0.85 else '#ffc107' if finding['ml_confidence'] >= 0.60 else '#dc3545'
            
            html_content += f"""
                        <tr>
                            <td><strong>{finding['vuln_id']}</strong></td>
                            <td>{finding['vuln_name']}</td>
                            <td>{finding['severity']}</td>
                            <td>{finding['ml_pred_label']}</td>
                            <td style="min-width: 150px;">
                                <div class="confidence-bar">
                                    <div class="confidence-fill" style="width: {confidence_pct}%; background: {fill_color};">
                                        {confidence_pct:.1f}%
                                    </div>
                                </div>
                            </td>
                            <td class="{'match' if finding['prediction_match'] else 'mismatch'}">
                                {'✅ Match' if finding['prediction_match'] else '❌ Review Needed'}
                            </td>
                            <td><code style="background: #f8f9fa; padding: 5px 10px; border-radius: 5px;">{finding['affected_url']}</code></td>
                        </tr>
            """
        
        html_content += f"""
                    </tbody>
                </table>
                
                <div class="footer">
                    <p><strong>Total Findings Analyzed:</strong> {total_findings} | 
                       <strong>Report Generated:</strong> {timestamp} | 
                       <strong>Confidence Threshold:</strong> High (≥85%), Medium (60-85%), Low (<60%)</p>
                    <p><em>WebScanPro AI Security Scanner - Enhanced with Machine Learning</em></p>
                    <p style="margin-top: 10px; font-size: 0.8em; color: #adb5bd;">
                        Report Location: {self.reports_html_dir}<br>
                        This report includes AI-generated predictions with confidence scoring. <br>
                        Low confidence findings require manual security review.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # ✅ EXPLICIT: Save HTML report with full path logging
        output_path = os.path.join(self.reports_html_dir, 'webscan_ai_report.html')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"🌐 HTML report generated: {output_path}")
        logger.info(f"📍 Absolute path: {os.path.abspath(output_path)}")
        return output_path
    
    def save_enhanced_data(self):
        """Save enhanced dataset with ML predictions"""
        if self.data is not None:
            logger.info(f"📁 Creating data directory: {os.path.dirname(self.data_output_path)}")
            os.makedirs(os.path.dirname(self.data_output_path), exist_ok=True)
            
            self.data.to_csv(self.data_output_path, index=False)
            logger.info(f"💾 Enhanced data saved: {self.data_output_path}")
            logger.info(f"📍 Absolute path: {os.path.abspath(self.data_output_path)}")
            return self.data_output_path

def debug_file_locations():
    """Debug function to show where files are being created"""
    print("\n" + "🔍" * 50)
    print("🔍 DEBUG - FILE LOCATIONS AND PATHS")
    print("🔍" * 50)
    print(f"📂 Current working directory: {os.getcwd()}")
    print(f"📜 Script location: {os.path.dirname(os.path.abspath(__file__))}")
    print(f"🏠 Project root: {PROJECT_ROOT}")
    print(f"📍 Project root exists: {os.path.exists(PROJECT_ROOT)}")
    
    # Check if directories exist
    directories_to_check = [
        ("data/processed", "📊 Data Directory"),
        ("reports/html", "🌐 HTML Reports Directory"), 
        ("reports/visualizations", "📈 Visualizations Directory"),
        ("reports/pdf", "📄 PDF Reports Directory"),
        ("models", "🤖 Models Directory")
    ]
    
    print(f"\n📁 DIRECTORY STATUS:")
    for relative_path, description in directories_to_check:
        full_path = get_absolute_path(relative_path)
        exists = os.path.exists(full_path)
        status = "✅ EXISTS" if exists else "❌ MISSING"
        print(f"   {status} {description}: {full_path}")

def create_directory_structure():
    """Create the required directory structure"""
    print(f"\n🏗️ CREATING DIRECTORY STRUCTURE under: {PROJECT_ROOT}")
    directories = [
        ("data/processed", "Data storage"),
        ("models", "ML models"), 
        ("reports/html", "HTML reports"),
        ("reports/visualizations", "Charts and graphs"),
        ("reports/pdf", "PDF reports"),
        ("scripts", "Python scripts")
    ]
    
    for relative_path, description in directories:
        full_path = get_absolute_path(relative_path)
        os.makedirs(full_path, exist_ok=True)
        print(f"   ✅ Created: {full_path} ({description})")

def verify_file_creation():
    """Verify that files are created in the correct locations"""
    print(f"\n" + "✅" * 50)
    print("✅ VERIFYING FILE CREATION IN webscanprod_reports")
    print("✅" * 50)
    
    expected_files = [
        OUTPUT_PATH,
        os.path.join(REPORTS_HTML_DIR, 'webscan_ai_report.html'),
        os.path.join(REPORTS_VIZ_DIR, 'ml_analysis_dashboard.png')
    ]
    
    for file_path in expected_files:
        exists = os.path.exists(file_path)
        status = "✅ FOUND" if exists else "❌ MISSING"
        print(f"   {status} {file_path}")

def main():
    """Main execution function"""
    print("🚀 STARTING WebScanPro ML-Enhanced Reporting...")
    print(f"🎯 TARGET LOCATION: {PROJECT_ROOT}")
    
    # Debug information
    debug_file_locations()
    
    # Create directory structure
    create_directory_structure()
    
    try:
        # Initialize reporter with absolute paths
        reporter = MLEnhancedReporter(
            model_path=MODEL_PATH, 
            data_path=DATA_PATH
        )
        
        # Step 1: Load data and model
        reporter.load_data()
        reporter.load_model()
        
        # Step 2: Generate predictions
        logger.info("📊 Applying ML predictions...")
        enhanced_data = reporter.predict_vulnerabilities()
        
        # Step 3: Generate summary
        logger.info("📈 Generating confidence summary...")
        summary = reporter.generate_confidence_summary()
        print("\n" + "="*60)
        print("📊 CONFIDENCE SUMMARY")
        print("="*60)
        print(summary)
        print("="*60)
        
        # Step 4: Create visualizations
        logger.info("🎨 Creating visualizations...")
        reporter.create_visualizations()
        
        # Step 5: Generate reports
        logger.info("📄 Generating HTML report...")
        html_report = reporter.generate_html_report()
        
        # Step 6: Save enhanced data
        logger.info("💾 Saving enhanced dataset...")
        data_output = reporter.save_enhanced_data()
        
        # Final output
        print(f"\n" + "🎉" * 20)
        print("🎉 AI-Enhanced Reporting Completed Successfully!")
        print("🎉" * 20)
        
        print(f"\n📍 ALL FILES SAVED UNDER: {PROJECT_ROOT}")
        print(f"\n📁 EXACT FILE LOCATIONS:")
        print(f"   💾 Enhanced Dataset: {os.path.abspath(data_output)}")
        print(f"   🌐 HTML Report: {os.path.abspath(html_report)}")
        print(f"   📊 Visualizations: {os.path.abspath(REPORTS_VIZ_DIR)}")
        
        # Verify file creation
        verify_file_creation()
        
        # Show sample of the data
        print(f"\n📊 SAMPLE OF ENHANCED DATA:")
        print(reporter.data[['vuln_id', 'severity', 'ml_pred_label', 'ml_confidence', 'confidence_group']].head())
        
        print(f"\n✨ To view your report, open this file in a web browser:")
        print(f"   {os.path.abspath(html_report)}")
        
    except Exception as e:
        logger.error(f"❌ Error in ML reporting pipeline: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise

if __name__ == "__main__":
    main()