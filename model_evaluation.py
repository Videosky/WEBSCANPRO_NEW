"""
Comprehensive model evaluation and reporting
"""

import pandas as pd
import numpy as np
import json
import joblib
import os
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve

class IDORModelEvaluator:
    def __init__(self):
        self.results = {}
        
    def load_model_and_data(self, models_dir, splits_dir):
        """Load trained model and test data"""
        print("📂 Loading model and test data...")
        
        # Load model
        model_path = os.path.join(models_dir, 'idor_model.joblib')
        preprocessor_path = os.path.join(models_dir, 'preprocessor.joblib')
        metadata_path = os.path.join(models_dir, 'training_metadata.json')
        
        self.model = joblib.load(model_path)
        self.feature_columns = joblib.load(preprocessor_path)
        
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)
        
        # Load test data
        test_df = pd.read_csv(os.path.join(splits_dir, 'test.csv'))
        self.X_test = test_df[self.feature_columns]
        self.y_test = test_df['is_unauthorized']
        
        print(f"Model loaded: {type(self.model).__name__}")
        print(f"Test set size: {len(self.X_test)}")
        
    def comprehensive_evaluation(self):
        """Perform comprehensive model evaluation"""
        print("📊 Performing comprehensive evaluation...")
        
        # Predictions
        y_pred = self.model.predict(self.X_test)
        y_pred_proba = self.model.predict_proba(self.X_test)[:, 1]
        
        # Basic metrics
        from sklearn.metrics import precision_recall_fscore_support, accuracy_score
        
        accuracy = accuracy_score(self.y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(self.y_test, y_pred, average='binary')
        roc_auc = roc_auc_score(self.y_test, y_pred_proba)
        
        # Detailed classification report
        class_report = classification_report(self.y_test, y_pred, output_dict=True)
        
        # Confusion matrix
        cm = confusion_matrix(self.y_test, y_pred)
        
        # Precision-Recall curve
        precision_curve, recall_curve, thresholds = precision_recall_curve(self.y_test, y_pred_proba)
        
        # Find optimal threshold (maximizing F1)
        f1_scores = 2 * (precision_curve * recall_curve) / (precision_curve + recall_curve + 1e-8)
        optimal_idx = np.argmax(f1_scores)
        optimal_threshold = thresholds[optimal_idx] if optimal_idx < len(thresholds) else 0.5
        
        self.results = {
            'basic_metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'roc_auc': roc_auc
            },
            'classification_report': class_report,
            'confusion_matrix': cm.tolist(),
            'optimal_threshold': optimal_threshold,
            'precision_recall_curve': {
                'precision': precision_curve.tolist(),
                'recall': recall_curve.tolist(),
                'thresholds': thresholds.tolist()
            }
        }
        
        return self.results
    
    def generate_evaluation_report(self, output_path):
        """Generate comprehensive evaluation report"""
        print("📝 Generating evaluation report...")
        
        # Build report content step by step to avoid f-string issues
        report_lines = []
        
        # Header
        report_lines.append("# IDOR ML Model Evaluation Report")
        report_lines.append("")
        
        # Model Overview
        report_lines.append("## Model Overview")
        report_lines.append(f"- **Model Type**: {self.metadata['model_type']}")
        report_lines.append(f"- **Training Date**: {self.metadata['training_timestamp']}")
        report_lines.append(f"- **Feature Count**: {len(self.feature_columns)}")
        report_lines.append(f"- **Best Validation Score**: {self.metadata['best_validation_score']:.4f}")
        report_lines.append("")
        
        # Test Set Performance
        report_lines.append("## Test Set Performance")
        report_lines.append("")
        report_lines.append("### Basic Metrics")
        report_lines.append(f"- **Accuracy**: {self.results['basic_metrics']['accuracy']:.4f}")
        report_lines.append(f"- **Precision**: {self.results['basic_metrics']['precision']:.4f}")
        report_lines.append(f"- **Recall**: {self.results['basic_metrics']['recall']:.4f}")
        report_lines.append(f"- **F1-Score**: {self.results['basic_metrics']['f1_score']:.4f}")
        report_lines.append(f"- **ROC-AUC**: {self.results['basic_metrics']['roc_auc']:.4f}")
        report_lines.append("")
        
        # Optimal Threshold
        report_lines.append("### Optimal Threshold")
        report_lines.append(f"The optimal classification threshold for maximizing F1-score is **{self.results['optimal_threshold']:.4f}**")
        report_lines.append("")
        
        # Confusion Matrix
        report_lines.append("### Confusion Matrix")
        report_lines.append("```")
        report_lines.append(f"True Negatives: {self.results['confusion_matrix'][0][0]}")
        report_lines.append(f"False Positives: {self.results['confusion_matrix'][0][1]}")
        report_lines.append(f"False Negatives: {self.results['confusion_matrix'][1][0]}")
        report_lines.append(f"True Positives: {self.results['confusion_matrix'][1][1]}")
        report_lines.append("```")
        report_lines.append("")
        
        # Classification Report
        report_lines.append("### Detailed Classification Report")
        report_lines.append("```")
        class_report_str = classification_report(self.y_test, self.model.predict(self.X_test))
        report_lines.append(class_report_str)
        report_lines.append("```")
        report_lines.append("")
        
        # Feature Importance
        report_lines.append("## Feature Importance")
        report_lines.append("")
        report_lines.append(self._get_feature_importance_text())
        report_lines.append("")
        
        # Model Comparison
        report_lines.append("## Model Comparison")
        report_lines.append("")
        report_lines.append(self._get_model_comparison_text())
        report_lines.append("")
        
        # Recommendations
        report_lines.append("## Recommendations")
        report_lines.append("1. **Deployment Threshold**: Use {:.3f} for balanced precision/recall".format(self.results['optimal_threshold']))
        report_lines.append("2. **Monitoring**: Track precision/recall weekly for model drift")
        report_lines.append("3. **Retraining**: Retrain when F1-score drops below 0.7")
        report_lines.append("")
        report_lines.append("---")
        report_lines.append("*Generated automatically by IDOR ML Evaluation System*")
        
        # Combine all lines
        report_content = "\n".join(report_lines)
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(report_content)
        
        print(f"✅ Evaluation report saved: {output_path}")
        return report_content
    
    def _get_feature_importance_text(self):
        """Get feature importance text for report"""
        try:
            # Try to get feature importances from different model types
            model = self.model
            if hasattr(model, 'named_steps'):
                # Pipeline model - get the actual estimator
                for step_name, step_model in model.named_steps.items():
                    if hasattr(step_model, 'feature_importances_'):
                        model = step_model
                        break
            
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
            else:
                return "Feature importance not available for this model type."
            
            # Create feature importance dataframe
            feature_importance_df = pd.DataFrame({
                'feature': self.feature_columns,
                'importance': importances
            }).sort_values('importance', ascending=False)
            
            importance_lines = ["Top 10 Most Important Features:", ""]
            for _, row in feature_importance_df.head(10).iterrows():
                importance_lines.append(f"- {row['feature']}: {row['importance']:.4f}")
            
            return "\n".join(importance_lines)
            
        except Exception as e:
            return f"Could not compute feature importance: {e}"
    
    def _get_model_comparison_text(self):
        """Get model comparison text for report"""
        if 'model_comparison' not in self.metadata:
            return "Model comparison data not available."
        
        comparison_lines = ["Model Performance Comparison:", ""]
        
        for model_name, model_info in self.metadata['model_comparison'].items():
            comparison_lines.append(f"- **{model_name}**: F1 = {model_info['score']:.4f}")
        
        return "\n".join(comparison_lines)

def main():
    """Main evaluation pipeline"""
    models_dir = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\models"
    splits_dir = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\data\splits"
    report_path = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\docs\idor_model_evaluation.md"
    
    evaluator = IDORModelEvaluator()
    
    try:
        # Load model and data
        evaluator.load_model_and_data(models_dir, splits_dir)
        
        # Perform evaluation
        results = evaluator.comprehensive_evaluation()
        
        # Generate report
        evaluator.generate_evaluation_report(report_path)
        
        print("\n🎉 Model evaluation completed successfully!")
        print(f"📊 Final F1-Score: {results['basic_metrics']['f1_score']:.4f}")
        print(f"📁 Report saved: {report_path}")
        
    except Exception as e:
        print(f"❌ Error in model evaluation: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()