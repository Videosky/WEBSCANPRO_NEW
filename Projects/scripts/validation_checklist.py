import os
import pandas as pd
import json
from datetime import datetime
import logging
import numpy as np

logger = logging.getLogger(__name__)

class ValidationChecklist:
    """
    Comprehensive validation checklist for WebScanPro ML reporting
    Validates data quality, ML predictions, and report generation
    """
    
    def __init__(self, project_root):
        self.project_root = project_root
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'total_checks': 0,
            'passed_checks': 0,
            'failed_checks': 0,
            'warnings': 0,
            'details': []
        }
    
    def run_full_validation(self, enhanced_data=None, reports_generated=None):
        """
        Run complete validation suite
        """
        logger.info("🔍 Starting WebScanPro Validation Checklist...")
        
        # Data Quality Checks
        self._validate_data_quality(enhanced_data)
        
        # ML Prediction Checks
        self._validate_ml_predictions(enhanced_data)
        
        # File System Checks
        self._validate_file_system()
        
        # Report Quality Checks
        self._validate_reports(reports_generated)
        
        # Performance Checks
        self._validate_performance(enhanced_data)
        
        return self._generate_validation_report()
    
    def _validate_data_quality(self, data):
        """Validate data quality and integrity"""
        checks = [
            self._check_data_not_empty(data),
            self._check_required_columns(data),
            self._check_no_missing_values(data),
            self._check_severity_values(data),
            self._check_confidence_ranges(data),
            self._check_url_format(data)
        ]
        
        for check in checks:
            self._record_result(check)
    
    def _validate_ml_predictions(self, data):
        """Validate ML prediction quality"""
        if data is None:
            self._record_result({
                'check': 'ML Predictions Available',
                'passed': False,
                'message': 'No data provided for ML prediction validation'
            })
            return
            
        checks = [
            self._check_ml_predictions_present(data),
            self._check_confidence_scores_valid(data),
            self._check_confidence_groups_calculated(data),
            self._check_prediction_accuracy(data),
            self._check_confidence_distribution(data)
        ]
        
        for check in checks:
            self._record_result(check)
    
    def _validate_file_system(self):
        """Validate file system structure and permissions"""
        checks = [
            self._check_project_structure(),
            self._check_data_files_exist(),
            self._check_report_files_exist(),
            self._check_write_permissions()
        ]
        
        for check in checks:
            self._record_result(check)
    
    def _validate_reports(self, reports_generated):
        """Validate generated reports"""
        checks = [
            self._check_html_report_generated(),
            self._check_visualizations_generated(),
            self._check_enhanced_data_saved()
        ]
        
        for check in checks:
            self._record_result(check)
    
    def _validate_performance(self, data):
        """Validate system performance metrics"""
        if data is not None:
            checks = [
                self._check_processing_speed(data),
                self._check_memory_usage(data),
                self._check_prediction_consistency(data)
            ]
            
            for check in checks:
                self._record_result(check)
    
    # Individual validation methods
    def _check_data_not_empty(self, data):
        """Check if data is not empty"""
        if data is None:
            return {
                'check': 'Data Not Empty',
                'passed': False,
                'message': 'No data provided for validation'
            }
        
        passed = len(data) > 0
        return {
            'check': 'Data Not Empty',
            'passed': passed,
            'message': f'Data contains {len(data)} records' if passed else 'Data is empty',
            'value': len(data)
        }
    
    def _check_required_columns(self, data):
        """Check if all required columns are present"""
        required_columns = ['vuln_id', 'vuln_name', 'severity', 'ml_pred_label', 'ml_confidence']
        missing_columns = [col for col in required_columns if col not in data.columns]
        
        passed = len(missing_columns) == 0
        return {
            'check': 'Required Columns Present',
            'passed': passed,
            'message': f'Missing columns: {missing_columns}' if not passed else 'All required columns present',
            'value': list(data.columns)
        }
    
    def _check_no_missing_values(self, data):
        """Check for missing values in critical columns"""
        critical_columns = ['vuln_id', 'severity', 'ml_pred_label', 'ml_confidence']
        missing_counts = data[critical_columns].isnull().sum().to_dict()
        total_missing = sum(missing_counts.values())
        
        passed = total_missing == 0
        return {
            'check': 'No Missing Values',
            'passed': passed,
            'message': f'Missing values found: {missing_counts}' if not passed else 'No missing values in critical columns',
            'value': missing_counts
        }
    
    def _check_severity_values(self, data):
        """Validate severity values are in expected range"""
        valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
        invalid_severities = data[~data['severity'].isin(valid_severities)]['severity'].unique()
        
        passed = len(invalid_severities) == 0
        return {
            'check': 'Valid Severity Values',
            'passed': passed,
            'message': f'Invalid severity values: {list(invalid_severities)}' if not passed else 'All severity values are valid',
            'value': list(data['severity'].unique())
        }
    
    def _check_confidence_ranges(self, data):
        """Validate confidence score ranges and groups"""
        if data is None or 'ml_confidence' not in data.columns:
            return {
                'check': 'Confidence Ranges',
                'passed': False,
                'message': 'No data or confidence column for range validation',
                'value': None
            }
        
        # Check confidence ranges
        confidence_stats = {
            'min': float(data['ml_confidence'].min()),
            'max': float(data['ml_confidence'].max()),
            'mean': float(data['ml_confidence'].mean())
        }
        
        # Check if confidence groups make sense
        if 'confidence_group' in data.columns:
            group_counts = data['confidence_group'].value_counts().to_dict()
        else:
            group_counts = {}
        
        # Validate ranges are reasonable
        ranges_ok = (0 <= confidence_stats['min'] <= 1 and 
                    0 <= confidence_stats['max'] <= 1 and
                    confidence_stats['min'] <= confidence_stats['max'])
        
        return {
            'check': 'Confidence Ranges',
            'passed': ranges_ok,
            'message': f'Confidence range: {confidence_stats["min"]:.3f} - {confidence_stats["max"]:.3f}',
            'value': {
                'stats': confidence_stats,
                'group_counts': group_counts
            }
        }
    
    def _check_confidence_scores_valid(self, data):
        """Validate confidence scores are within 0-1 range"""
        invalid_confidence = data[(data['ml_confidence'] < 0) | (data['ml_confidence'] > 1)]
        
        passed = len(invalid_confidence) == 0
        return {
            'check': 'Valid Confidence Scores',
            'passed': passed,
            'message': f'{len(invalid_confidence)} records with invalid confidence scores' if not passed else 'All confidence scores are valid (0-1)',
            'value': {
                'min_confidence': float(data['ml_confidence'].min()),
                'max_confidence': float(data['ml_confidence'].max())
            }
        }
    
    def _check_confidence_groups_calculated(self, data):
        """Check if confidence groups are properly calculated"""
        required_groups = ['High Confidence', 'Medium Confidence', 'Low Confidence']
        actual_groups = data['confidence_group'].unique() if 'confidence_group' in data.columns else []
        missing_groups = [group for group in required_groups if group not in actual_groups]
        
        passed = len(missing_groups) == 0
        return {
            'check': 'Confidence Groups Calculated',
            'passed': passed,
            'message': f'Missing confidence groups: {missing_groups}' if not passed else 'All confidence groups properly calculated',
            'value': list(actual_groups)
        }
    
    def _check_ml_predictions_present(self, data):
        """Check if ML predictions are present"""
        ml_columns_present = all(col in data.columns for col in ['ml_pred_label', 'ml_confidence'])
        
        passed = ml_columns_present
        return {
            'check': 'ML Predictions Present',
            'passed': passed,
            'message': 'ML prediction columns missing' if not passed else 'ML predictions successfully generated',
            'value': ml_columns_present
        }
    
    def _check_prediction_accuracy(self, data):
        """Calculate and validate prediction accuracy"""
        if 'prediction_match' not in data.columns:
            return {
                'check': 'Prediction Accuracy',
                'passed': False,
                'message': 'Prediction match column not found',
                'value': None
            }
        
        accuracy = float(data['prediction_match'].mean())
        passed = accuracy >= 0.7  # 70% minimum accuracy threshold
        
        return {
            'check': 'Prediction Accuracy',
            'passed': passed,
            'message': f'Accuracy: {accuracy:.1%} - {"Meets" if passed else "Below"} minimum threshold (70%)',
            'value': accuracy
        }
    
    def _check_confidence_distribution(self, data):
        """Validate confidence score distribution"""
        confidence_stats = {
            'mean': float(data['ml_confidence'].mean()),
            'std': float(data['ml_confidence'].std()),
            'high_confidence_rate': float((data['ml_confidence'] >= 0.85).mean())
        }
        
        # Check if we have reasonable confidence distribution
        high_conf_rate_ok = confidence_stats['high_confidence_rate'] >= 0.5  # At least 50% high confidence
        reasonable_std = confidence_stats['std'] > 0.1  # Some variance in confidence
        
        passed = high_conf_rate_ok and reasonable_std
        
        return {
            'check': 'Confidence Distribution',
            'passed': passed,
            'message': f'High confidence rate: {confidence_stats["high_confidence_rate"]:.1%}, Std: {confidence_stats["std"]:.3f}',
            'value': confidence_stats
        }
    
    def _check_project_structure(self):
        """Validate project directory structure"""
        required_dirs = [
            'data/processed',
            'reports/html',
            'reports/visualizations',
            'scripts',
            'models'
        ]
        
        missing_dirs = []
        for dir_path in required_dirs:
            full_path = os.path.join(self.project_root, dir_path)
            if not os.path.exists(full_path):
                missing_dirs.append(dir_path)
        
        passed = len(missing_dirs) == 0
        return {
            'check': 'Project Structure',
            'passed': passed,
            'message': f'Missing directories: {missing_dirs}' if not passed else 'Project structure is correct',
            'value': required_dirs
        }
    
    def _check_data_files_exist(self):
        """Check if required data files exist"""
        required_files = [
            'data/processed/findings_with_ml.csv',
            'data/processed/findings_with_ml_enhanced.csv'
        ]
        
        missing_files = []
        for file_path in required_files:
            full_path = os.path.join(self.project_root, file_path)
            if not os.path.exists(full_path):
                missing_files.append(file_path)
        
        passed = len(missing_files) == 0
        return {
            'check': 'Data Files Exist',
            'passed': passed,
            'message': f'Missing files: {missing_files}' if not passed else 'All data files present',
            'value': required_files
        }
    
    def _check_report_files_exist(self):
        """Check if report files are generated"""
        required_files = [
            'reports/html/webscan_ai_report.html'
        ]
        
        # Check for visualizations (optional)
        visualization_files = [
            'reports/visualizations/ml_analysis_dashboard.png',
            'reports/visualizations/confidence_distribution.png'
        ]
        
        missing_files = []
        for file_path in required_files:
            full_path = os.path.join(self.project_root, file_path)
            if not os.path.exists(full_path):
                missing_files.append(file_path)
        
        # Check visualizations but don't fail if missing
        missing_viz = []
        for viz_file in visualization_files:
            full_path = os.path.join(self.project_root, viz_file)
            if not os.path.exists(full_path):
                missing_viz.append(viz_file)
        
        passed = len(missing_files) == 0
        message = f'Missing report files: {missing_files}' if not passed else 'All report files present'
        if missing_viz:
            message += f' (Missing visualizations: {len(missing_viz)})'
        
        return {
            'check': 'Report Files Generated',
            'passed': passed,
            'message': message,
            'value': {
                'required_files': required_files,
                'missing_visualizations': missing_viz
            }
        }
    
    def _check_html_report_generated(self):
        """Validate HTML report generation"""
        report_path = os.path.join(self.project_root, 'reports/html/webscan_ai_report.html')
        
        if not os.path.exists(report_path):
            return {
                'check': 'HTML Report Generated',
                'passed': False,
                'message': 'HTML report file not found',
                'value': None
            }
        
        # Check if report has reasonable size
        file_size = os.path.getsize(report_path)
        reasonable_size = file_size > 1000  # At least 1KB
        
        return {
            'check': 'HTML Report Generated',
            'passed': reasonable_size,
            'message': f'HTML report generated ({file_size} bytes)',
            'value': file_size
        }
    
    def _check_visualizations_generated(self):
        """Check if visualizations are created"""
        viz_files = [
            'ml_analysis_dashboard.png',
            'confidence_distribution.png',
            'confidence_by_group.png'
        ]
        
        viz_dir = os.path.join(self.project_root, 'reports/visualizations')
        existing_files = []
        
        if os.path.exists(viz_dir):
            for viz_file in viz_files:
                if os.path.exists(os.path.join(viz_dir, viz_file)):
                    existing_files.append(viz_file)
        
        viz_count = len(existing_files)
        passed = viz_count > 0
        
        return {
            'check': 'Visualizations Generated',
            'passed': passed,
            'message': f'{viz_count}/{len(viz_files)} visualizations generated' if passed else 'No visualizations generated',
            'value': existing_files
        }
    
    def _check_enhanced_data_saved(self):
        """Check if enhanced data is saved"""
        enhanced_data_path = os.path.join(self.project_root, 'data/processed/findings_with_ml_enhanced.csv')
        
        if not os.path.exists(enhanced_data_path):
            return {
                'check': 'Enhanced Data Saved',
                'passed': False,
                'message': 'Enhanced data file not found',
                'value': None
            }
        
        # Check file size and content
        file_size = os.path.getsize(enhanced_data_path)
        reasonable_size = file_size > 100  # At least 100 bytes
        
        return {
            'check': 'Enhanced Data Saved',
            'passed': reasonable_size,
            'message': f'Enhanced data saved ({file_size} bytes)',
            'value': file_size
        }
    
    def _check_write_permissions(self):
        """Check if we have write permissions for output directories"""
        test_dirs = [
            'reports/html',
            'reports/visualizations',
            'data/processed'
        ]
        
        permission_issues = []
        for test_dir in test_dirs:
            full_path = os.path.join(self.project_root, test_dir)
            test_file = os.path.join(full_path, '.write_test')
            
            try:
                # Try to create a test file
                with open(test_file, 'w') as f:
                    f.write('test')
                # Clean up
                if os.path.exists(test_file):
                    os.remove(test_file)
            except Exception as e:
                permission_issues.append(f"{test_dir}: {str(e)}")
        
        passed = len(permission_issues) == 0
        return {
            'check': 'Write Permissions',
            'passed': passed,
            'message': f'Permission issues: {permission_issues}' if not passed else 'All directories are writable',
            'value': not permission_issues
        }
    
    def _check_processing_speed(self, data):
        """Validate processing speed (simplified)"""
        # This would normally measure actual processing time
        # For now, we'll just check if processing completed
        passed = data is not None and len(data) > 0
        return {
            'check': 'Processing Completed',
            'passed': passed,
            'message': 'Data processing completed successfully' if passed else 'Data processing failed',
            'value': passed
        }
    
    def _check_memory_usage(self, data):
        """Check memory usage (simplified)"""
        # In a real implementation, you'd measure memory usage
        record_count = len(data) if data is not None else 0
        reasonable_size = record_count <= 10000  # Reasonable for this application
        
        return {
            'check': 'Memory Usage',
            'passed': reasonable_size,
            'message': f'Processed {record_count} records - within reasonable limits' if reasonable_size else f'Large dataset: {record_count} records',
            'value': record_count
        }
    
    def _check_prediction_consistency(self, data):
        """Check prediction consistency"""
        if data is None or 'ml_confidence' not in data.columns:
            return {
                'check': 'Prediction Consistency',
                'passed': False,
                'message': 'No data for consistency check',
                'value': None
            }
        
        # Check if confidence scores are consistent (not all the same)
        confidence_std = float(data['ml_confidence'].std())
        consistent = confidence_std > 0.01  # Some variation expected
        
        return {
            'check': 'Prediction Consistency',
            'passed': consistent,
            'message': f'Confidence std: {confidence_std:.3f} - {"Reasonable variation" if consistent else "Low variation"}',
            'value': confidence_std
        }
    
    def _check_url_format(self, data):
        """Validate URL formats"""
        if 'affected_url' not in data.columns:
            return {
                'check': 'URL Format Validation',
                'passed': False,
                'message': 'affected_url column not found',
                'value': None
            }
        
        # Simple URL format check
        url_patterns = ['http://', 'https://', 'example.com']
        invalid_urls = 0
        
        for url in data['affected_url']:
            if not any(pattern in str(url) for pattern in url_patterns):
                invalid_urls += 1
        
        passed = invalid_urls == 0
        return {
            'check': 'URL Format Validation',
            'passed': passed,
            'message': f'{invalid_urls} URLs with unexpected format' if not passed else 'All URLs have expected format',
            'value': invalid_urls
        }
    
    def _record_result(self, check_result):
        """Record individual check result"""
        self.results['total_checks'] += 1
        
        if check_result['passed']:
            self.results['passed_checks'] += 1
        else:
            self.results['failed_checks'] += 1
        
        self.results['details'].append(check_result)
    
    def _generate_validation_report(self):
        """Generate comprehensive validation report"""
        success_rate = (self.results['passed_checks'] / self.results['total_checks']) * 100 if self.results['total_checks'] > 0 else 0
        
        report = {
            'summary': {
                'timestamp': self.results['timestamp'],
                'total_checks': self.results['total_checks'],
                'passed_checks': self.results['passed_checks'],
                'failed_checks': self.results['failed_checks'],
                'success_rate': f'{success_rate:.1f}%',
                'overall_status': 'PASS' if success_rate >= 80 else 'WARNING' if success_rate >= 60 else 'FAIL'
            },
            'details': self.results['details']
        }
        
        # Log summary
        logger.info(f"📋 Validation Complete: {report['summary']['passed_checks']}/{report['summary']['total_checks']} checks passed ({report['summary']['success_rate']})")
        
        return report
    
    def save_validation_report(self, report, output_path=None):
        """Save validation report to file"""
        if output_path is None:
            output_path = os.path.join(self.project_root, 'reports/validation_report.json')
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # ✅ FIX: Convert numpy/pandas types to native Python types for JSON serialization
        def convert_to_serializable(obj):
            """Recursively convert numpy/pandas types to native Python types"""
            if hasattr(obj, 'item'):  # numpy types
                return obj.item()
            elif hasattr(obj, 'isoformat'):  # datetime
                return obj.isoformat()
            elif isinstance(obj, (np.integer, np.floating)):
                return float(obj) if isinstance(obj, np.floating) else int(obj)
            elif isinstance(obj, np.bool_):
                return bool(obj)
            elif isinstance(obj, dict):
                return {key: convert_to_serializable(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_serializable(item) for item in obj]
            elif isinstance(obj, (bool, int, float, str)) or obj is None:
                return obj
            else:
                return str(obj)  # Fallback to string representation
        
        # Convert the entire report to serializable format
        serializable_report = convert_to_serializable(report)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(serializable_report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Validation report saved: {output_path}")
        return output_path
    
    def print_validation_summary(self, report):
        """Print a formatted validation summary"""
        print("\n" + "="*60)
        print("📋 WEBSCANPRO VALIDATION CHECKLIST SUMMARY")
        print("="*60)
        print(f"🕒 Timestamp: {report['summary']['timestamp']}")
        print(f"📊 Total Checks: {report['summary']['total_checks']}")
        print(f"✅ Passed: {report['summary']['passed_checks']}")
        print(f"❌ Failed: {report['summary']['failed_checks']}")
        print(f"🎯 Success Rate: {report['summary']['success_rate']}")
        print(f"📈 Overall Status: {report['summary']['overall_status']}")
        print("="*60)
        
        # Print failed checks
        failed_checks = [check for check in report['details'] if not check['passed']]
        if failed_checks:
            print("\n🚨 FAILED CHECKS:")
            for check in failed_checks:
                print(f"   ❌ {check['check']}: {check['message']}")
        
        # Print passed checks summary
        passed_checks = [check for check in report['details'] if check['passed']]
        if passed_checks:
            print(f"\n✅ PASSED CHECKS: {len(passed_checks)} checks completed successfully")
        
        print("="*60)

# Utility function to run validation
def run_validation(project_root, enhanced_data_path=None):
    """
    Run complete validation suite
    """
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    validator = ValidationChecklist(project_root)
    
    # Load enhanced data if path provided
    enhanced_data = None
    if enhanced_data_path and os.path.exists(enhanced_data_path):
        try:
            enhanced_data = pd.read_csv(enhanced_data_path)
            logger.info(f"📊 Loaded enhanced data: {len(enhanced_data)} records")
        except Exception as e:
            logger.error(f"❌ Failed to load enhanced data: {e}")
    
    # Run validation
    report = validator.run_full_validation(enhanced_data=enhanced_data)
    
    # Print summary
    validator.print_validation_summary(report)
    
    # Save report
    report_path = validator.save_validation_report(report)
    
    return report, report_path

if __name__ == "__main__":
    # Example usage
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    enhanced_data_path = os.path.join(project_root, 'data/processed/findings_with_ml_enhanced.csv')
    
    print("🔍 Starting WebScanPro Validation Checklist...")
    report, report_path = run_validation(project_root, enhanced_data_path)
    print(f"\n📄 Full validation report saved: {report_path}")