"""
Authentication Anomaly Detection Model Trainer - FIXED VERSION
Author: Security Analytics Team
Date: 2025
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    roc_curve, precision_recall_curve
)
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Input, Dense, Dropout
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import pickle
import joblib
import logging
from datetime import datetime
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class AuthAnomalyDetector:
    """
    Authentication Anomaly Detection System
    Trains and evaluates Isolation Forest and Autoencoder models
    """
    
    def __init__(self, data_path=None):
        self.data_path = data_path
        self.df = None
        self.X_train = None
        self.X_val = None
        self.X_test = None
        self.y_train = None
        self.y_val = None
        self.y_test = None
        self.X_train_normal = None
        
        # Models
        self.isolation_forest = None
        self.autoencoder = None
        self.autoencoder_threshold = None
        
        # Scalers
        self.scaler = StandardScaler()
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging with timestamped log file"""
        logs_dir = Path("projects/auth_session/logs")
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_filename = logs_dir / f"model_train_eval_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('auth_anomaly_detector')
        self.logger.info(f"Logging initialized: {log_filename}")
    
    def load_and_prepare_data(self, test_size=0.15, val_size=0.15, random_state=42):
        """Load and prepare data for training - FIXED VERSION"""
        self.logger.info("Loading and preparing data...")
        
        try:
            # Load dataset
            self.df = pd.read_csv(self.data_path)
            self.logger.info(f"Dataset loaded: {len(self.df)} records, {len(self.df.columns)} columns")
            
            # Print column info for debugging
            self.logger.info("Dataset columns and dtypes:")
            for col in self.df.columns:
                self.logger.info(f"  {col}: {self.df[col].dtype}, unique values: {self.df[col].nunique()}")
            
            # Check for missing values
            missing_values = self.df.isnull().sum()
            if missing_values.any():
                self.logger.warning(f"Missing values found: {missing_values[missing_values > 0]}")
                # Fill missing values
                self.df = self.df.fillna(0)
            
            # Separate features and target - EXCLUDE non-numeric and identifier columns
            exclude_columns = [
                'is_anomalous', 'timestamp', 'username', 'ip_address', 'session_id', 
                'user_agent', 'event_id', 'auth_result', 'failure_reason', 'notes',
                'endpoint', 'method', 'geolocation'
            ]
            
            # Only include numeric columns
            numeric_columns = self.df.select_dtypes(include=[np.number]).columns.tolist()
            feature_columns = [col for col in numeric_columns if col not in exclude_columns and col != 'is_anomalous']
            
            # If no numeric columns found, try to convert object columns
            if len(feature_columns) == 0:
                self.logger.warning("No numeric columns found. Attempting to convert object columns...")
                for col in self.df.columns:
                    if col not in exclude_columns and col != 'is_anomalous':
                        try:
                            self.df[col] = pd.to_numeric(self.df[col], errors='coerce')
                            feature_columns.append(col)
                        except:
                            self.logger.warning(f"Could not convert column {col} to numeric")
                
                # Fill any NaN values created during conversion
                self.df[feature_columns] = self.df[feature_columns].fillna(0)
            
            self.logger.info(f"Using {len(feature_columns)} numeric features: {feature_columns}")
            
            # Verify we have features
            if len(feature_columns) == 0:
                self.logger.error("No valid numeric features found for training!")
                return False
            
            X = self.df[feature_columns]
            y = self.df['is_anomalous']
            
            # Verify target variable
            if y.isnull().any():
                self.logger.warning("Missing values in target variable. Filling with 0.")
                y = y.fillna(0)
            
            self.logger.info(f"Target distribution: {y.value_counts().to_dict()}")
            
            # Split data: train/val/test
            X_temp, self.X_test, y_temp, self.y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state, stratify=y
            )
            
            # Adjust validation size
            val_size_adjusted = val_size / (1 - test_size)
            self.X_train, self.X_val, self.y_train, self.y_val = train_test_split(
                X_temp, y_temp, test_size=val_size_adjusted, random_state=random_state, stratify=y_temp
            )
            
            # Scale features
            self.X_train = self.scaler.fit_transform(self.X_train)
            self.X_val = self.scaler.transform(self.X_val)
            self.X_test = self.scaler.transform(self.X_test)
            
            # Get normal samples for unsupervised training
            train_normal_mask = (self.y_train == 0)
            self.X_train_normal = self.X_train[train_normal_mask]
            
            self.logger.info(f"Data splits prepared:")
            self.logger.info(f"  Training: {len(self.X_train)} samples (normal: {len(self.X_train_normal)})")
            self.logger.info(f"  Validation: {len(self.X_val)} samples")
            self.logger.info(f"  Test: {len(self.X_test)} samples")
            self.logger.info(f"  Anomaly rate - Train: {1 - train_normal_mask.mean():.3f}, Test: {self.y_test.mean():.3f}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Data preparation failed: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            return False
    
    def train_isolation_forest(self, n_estimators=100, contamination='auto', max_samples='auto', random_state=42):
        """Train Isolation Forest model"""
        self.logger.info("Training Isolation Forest model...")
        
        try:
            self.isolation_forest = IsolationForest(
                n_estimators=n_estimators,
                contamination=contamination,
                max_samples=max_samples,
                random_state=random_state,
                n_jobs=-1
            )
            
            # Train on normal data
            self.isolation_forest.fit(self.X_train_normal)
            
            self.logger.info("Isolation Forest training completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Isolation Forest training failed: {e}")
            return False
    
    def build_autoencoder(self, input_dim, encoding_dim=32, hidden_dims=[64, 32], dropout_rate=0.2):
        """Build autoencoder architecture"""
        self.logger.info(f"Building Autoencoder with input_dim={input_dim}, encoding_dim={encoding_dim}")
        
        # Input layer
        input_layer = Input(shape=(input_dim,))
        
        # Encoder
        x = input_layer
        for dim in hidden_dims:
            x = Dense(dim, activation='relu')(x)
            x = Dropout(dropout_rate)(x)
        
        # Bottleneck
        encoded = Dense(encoding_dim, activation='relu', name='bottleneck')(x)
        
        # Decoder
        x = encoded
        for dim in reversed(hidden_dims):
            x = Dense(dim, activation='relu')(x)
            x = Dropout(dropout_rate)(x)
        
        # Output layer
        decoded = Dense(input_dim, activation='linear')(x)
        
        # Autoencoder model
        autoencoder = Model(input_layer, decoded)
        
        # Compile
        autoencoder.compile(optimizer=Adam(learning_rate=0.001), loss='mse')
        
        self.autoencoder = autoencoder
        self.logger.info("Autoencoder architecture built successfully")
        return autoencoder
    
    def train_autoencoder(self, epochs=100, batch_size=32, validation_split=0.1):
        """Train Autoencoder model"""
        self.logger.info("Training Autoencoder model...")
        
        try:
            # Callbacks
            callbacks = [
                EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True),
                ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=5, min_lr=1e-7)
            ]
            
            # Train only on normal data
            history = self.autoencoder.fit(
                self.X_train_normal, self.X_train_normal,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=validation_split,
                callbacks=callbacks,
                verbose=1
            )
            
            # Calculate reconstruction error threshold
            reconstructions = self.autoencoder.predict(self.X_train_normal)
            train_mse = np.mean(np.power(self.X_train_normal - reconstructions, 2), axis=1)
            self.autoencoder_threshold = np.mean(train_mse) + 2 * np.std(train_mse)
            
            self.logger.info(f"Autoencoder training completed")
            self.logger.info(f"Reconstruction error threshold: {self.autoencoder_threshold:.6f}")
            
            return history
            
        except Exception as e:
            self.logger.error(f"Autoencoder training failed: {e}")
            return None
    
    def predict_isolation_forest(self, X):
        """Predict using Isolation Forest"""
        if self.isolation_forest is None:
            raise ValueError("Isolation Forest model not trained")
        
        # Get anomaly scores (-1 for anomalies, 1 for normal)
        scores = self.isolation_forest.decision_function(X)
        predictions = self.isolation_forest.predict(X)
        
        # Convert to binary (0 for normal, 1 for anomaly)
        binary_predictions = (predictions == -1).astype(int)
        
        return binary_predictions, scores
    
    def predict_autoencoder(self, X):
        """Predict using Autoencoder"""
        if self.autoencoder is None:
            raise ValueError("Autoencoder model not trained")
        
        # Get reconstructions and calculate MSE
        reconstructions = self.autoencoder.predict(X)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        
        # Classify as anomaly if reconstruction error > threshold
        binary_predictions = (mse > self.autoencoder_threshold).astype(int)
        
        return binary_predictions, mse
    
    def evaluate_model(self, model_name, y_true, y_pred, y_scores=None):
        """Comprehensive model evaluation"""
        self.logger.info(f"Evaluating {model_name}...")
        
        # Basic metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        # Rates
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        # ROC AUC if scores available
        roc_auc = roc_auc_score(y_true, y_scores) if y_scores is not None else None
        
        results = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'false_positive_rate': fpr,
            'false_negative_rate': fnr,
            'true_positives': tp,
            'true_negatives': tn,
            'false_positives': fp,
            'false_negatives': fn,
            'confusion_matrix': cm,
            'roc_auc': roc_auc
        }
        
        self.logger.info(f"{model_name} Results:")
        self.logger.info(f"  Accuracy: {accuracy:.4f}")
        self.logger.info(f"  Precision: {precision:.4f}")
        self.logger.info(f"  Recall: {recall:.4f}")
        self.logger.info(f"  F1-Score: {f1:.4f}")
        self.logger.info(f"  FPR: {fpr:.4f}, FNR: {fnr:.4f}")
        self.logger.info(f"  Confusion Matrix: TP={tp}, TN={tn}, FP={fp}, FN={fn}")
        
        return results
    
    def plot_curves(self, y_true, if_scores, ae_scores, output_path):
        """Plot ROC and Precision-Recall curves"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # ROC Curve
        fpr_if, tpr_if, _ = roc_curve(y_true, if_scores)
        fpr_ae, tpr_ae, _ = roc_curve(y_true, ae_scores)
        
        ax1.plot(fpr_if, tpr_if, label=f'Isolation Forest (AUC = {roc_auc_score(y_true, if_scores):.3f})')
        ax1.plot(fpr_ae, tpr_ae, label=f'Autoencoder (AUC = {roc_auc_score(y_true, ae_scores):.3f})')
        ax1.plot([0, 1], [0, 1], 'k--', label='Random Classifier')
        ax1.set_xlabel('False Positive Rate')
        ax1.set_ylabel('True Positive Rate')
        ax1.set_title('ROC Curves')
        ax1.legend()
        ax1.grid(True)
        
        # Precision-Recall Curve
        precision_if, recall_if, _ = precision_recall_curve(y_true, if_scores)
        precision_ae, recall_ae, _ = precision_recall_curve(y_true, ae_scores)
        
        ax2.plot(recall_if, precision_if, label='Isolation Forest')
        ax2.plot(recall_ae, precision_ae, label='Autoencoder')
        ax2.set_xlabel('Recall')
        ax2.set_ylabel('Precision')
        ax2.set_title('Precision-Recall Curves')
        ax2.legend()
        ax2.grid(True)
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info(f"Evaluation curves saved to: {output_path}")
    
    def save_models(self):
        """Save trained models"""
        ml_dir = Path("projects/auth_session/ml")
        ml_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Save Isolation Forest
            iforest_path = ml_dir / "isolation_forest_model.pkl"
            joblib.dump(self.isolation_forest, iforest_path)
            self.logger.info(f"Isolation Forest saved to: {iforest_path}")
            
            # Save Autoencoder
            autoencoder_path = ml_dir / "autoencoder_model.h5"
            self.autoencoder.save(autoencoder_path)
            self.logger.info(f"Autoencoder saved to: {autoencoder_path}")
            
            # Save scaler and threshold
            artifacts_path = ml_dir / "preprocessing_artifacts.pkl"
            artifacts = {
                'scaler': self.scaler,
                'autoencoder_threshold': self.autoencoder_threshold,
                'feature_names': [f'feature_{i}' for i in range(self.X_train.shape[1])]
            }
            joblib.dump(artifacts, artifacts_path)
            self.logger.info(f"Preprocessing artifacts saved to: {artifacts_path}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save models: {e}")
            return False
    
    def generate_evaluation_report(self, if_results, ae_results, output_path):
        """Generate comprehensive evaluation report"""
        self.logger.info("Generating evaluation report...")
        
        # Build report content step by step to avoid f-string issues
        report_lines = []
        
        report_lines.append("# Authentication Anomaly Detection Model Evaluation Report")
        report_lines.append("")
        report_lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"**Dataset:** {self.data_path}")
        report_lines.append(f"**Test Samples:** {len(self.X_test)} ({self.y_test.mean():.1%} anomalies)")
        report_lines.append("")
        
        report_lines.append("## Dataset Overview")
        report_lines.append(f"- **Total Features:** {self.X_train.shape[1]}")
        report_lines.append(f"- **Training Samples:** {len(self.X_train)} ({len(self.X_train_normal)} normal)")
        report_lines.append(f"- **Validation Samples:** {len(self.X_val)}")
        report_lines.append(f"- **Test Samples:** {len(self.X_test)}")
        report_lines.append("")
        
        report_lines.append("## Model Performance Comparison")
        report_lines.append("")
        report_lines.append("### Isolation Forest")
        report_lines.append("| Metric | Value |")
        report_lines.append("|--------|-------|")
        report_lines.append(f"| Accuracy | {if_results['accuracy']:.4f} |")
        report_lines.append(f"| Precision | {if_results['precision']:.4f} |")
        report_lines.append(f"| Recall | {if_results['recall']:.4f} |")
        report_lines.append(f"| F1-Score | {if_results['f1_score']:.4f} |")
        report_lines.append(f"| False Positive Rate | {if_results['false_positive_rate']:.4f} |")
        report_lines.append(f"| False Negative Rate | {if_results['false_negative_rate']:.4f} |")
        report_lines.append(f"| ROC AUC | {if_results['roc_auc']:.4f if if_results['roc_auc'] else 'N/A'} |")
        report_lines.append("")
        report_lines.append("**Confusion Matrix:**")
        report_lines.append("```")
        report_lines.append(f"True Positives:  {if_results['true_positives']}")
        report_lines.append(f"True Negatives:  {if_results['true_negatives']}")
        report_lines.append(f"False Positives: {if_results['false_positives']}")
        report_lines.append(f"False Negatives: {if_results['false_negatives']}")
        report_lines.append("```")
        report_lines.append("")
        
        report_lines.append("### Autoencoder")
        report_lines.append("| Metric | Value |")
        report_lines.append("|--------|-------|")
        report_lines.append(f"| Accuracy | {ae_results['accuracy']:.4f} |")
        report_lines.append(f"| Precision | {ae_results['precision']:.4f} |")
        report_lines.append(f"| Recall | {ae_results['recall']:.4f} |")
        report_lines.append(f"| F1-Score | {ae_results['f1_score']:.4f} |")
        report_lines.append(f"| False Positive Rate | {ae_results['false_positive_rate']:.4f} |")
        report_lines.append(f"| False Negative Rate | {ae_results['false_negative_rate']:.4f} |")
        report_lines.append(f"| ROC AUC | {ae_results['roc_auc']:.4f if ae_results['roc_auc'] else 'N/A'} |")
        report_lines.append("")
        report_lines.append("**Confusion Matrix:**")
        report_lines.append("```")
        report_lines.append(f"True Positives:  {ae_results['true_positives']}")
        report_lines.append(f"True Negatives:  {ae_results['true_negatives']}")
        report_lines.append(f"False Positives: {ae_results['false_positives']}")
        report_lines.append(f"False Negatives: {ae_results['false_negatives']}")
        report_lines.append("```")
        report_lines.append("")
        
        report_lines.append("## Key Observations")
        report_lines.append("")
        
        # Isolation Forest observations
        if_strengths = "Fast training, handles high-dimensional data well, no feature scaling required" if if_results['accuracy'] > 0.8 else "Reasonable performance but may need parameter tuning"
        if_weaknesses = "May have higher false positive rate with complex patterns" if if_results['false_positive_rate'] > 0.1 else "Balanced performance across metrics"
        
        report_lines.append("### Isolation Forest")
        report_lines.append(f"- **Strengths:** {if_strengths}")
        report_lines.append(f"- **Weaknesses:** {if_weaknesses}")
        report_lines.append("")
        
        # Autoencoder observations
        ae_strengths = "Excellent at capturing complex patterns, good reconstruction capability" if ae_results['accuracy'] > 0.8 else "Learns data distribution effectively"
        ae_weaknesses = "Requires more tuning, sensitive to threshold selection" if ae_results['false_negative_rate'] > 0.1 else "Well-calibrated threshold"
        
        report_lines.append("### Autoencoder")
        report_lines.append(f"- **Strengths:** {ae_strengths}")
        report_lines.append(f"- **Weaknesses:** {ae_weaknesses}")
        report_lines.append("")
        
        report_lines.append("## Recommendations")
        report_lines.append("")
        report_lines.append("### Immediate Actions:")
        
        # Model selection recommendation
        model_selection = "Use Isolation Forest for real-time detection due to faster inference" if if_results['f1_score'] >= ae_results['f1_score'] else "Use Autoencoder for better precision in high-security scenarios"
        report_lines.append(f"1. **Model Selection:** {model_selection}")
        
        # Threshold tuning recommendation
        threshold_tuning = "Adjust contamination parameter in Isolation Forest" if if_results['false_positive_rate'] > 0.15 else "Current thresholds are well-calibrated"
        report_lines.append(f"2. **Threshold Tuning:** {threshold_tuning}")
        
        # Feature engineering recommendation
        feature_eng = "Consider adding temporal features for better pattern recognition" if max(if_results['recall'], ae_results['recall']) < 0.8 else "Feature set is comprehensive"
        report_lines.append(f"3. **Feature Engineering:** {feature_eng}")
        report_lines.append("")
        
        report_lines.append("### Next Iteration:")
        report_lines.append("1. **Ensemble Approach:** Combine both models for improved performance")
        report_lines.append("2. **Incremental Learning:** Implement online learning for adapting to new patterns")
        report_lines.append("3. **Feature Importance:** Analyze which features contribute most to anomaly detection")
        report_lines.append("")
        
        report_lines.append("## Conclusion")
        report_lines.append("")
        
        # Performance assessment
        best_f1 = max(if_results['f1_score'], ae_results['f1_score'])
        if best_f1 > 0.9:
            performance = "excellent"
        elif best_f1 > 0.8:
            performance = "good" 
        else:
            performance = "moderate"
            
        best_model = "Isolation Forest" if if_results['f1_score'] > ae_results['f1_score'] else "Autoencoder"
        recommended_model = "Isolation Forest" if if_results['f1_score'] > ae_results['f1_score'] else "Autoencoder"
        
        report_lines.append(f"Both models show {performance} performance in detecting authentication anomalies.")
        report_lines.append(f"{best_model} performs slightly better overall based on F1-score.")
        report_lines.append("")
        report_lines.append(f"**Recommended for production:** {recommended_model} with continuous monitoring and periodic retraining.")
        
        # Join all lines
        report_content = "\n".join(report_lines)
        
        # Save report
        with open(output_path, 'w') as f:
            f.write(report_content)
        
        self.logger.info(f"Evaluation report saved to: {output_path}")
        return report_content
    
    def run_full_pipeline(self):
        """Run complete training and evaluation pipeline"""
        self.logger.info("Starting full anomaly detection pipeline...")
        
        # 1. Load and prepare data
        if not self.load_and_prepare_data():
            return False
        
        # 2. Train Isolation Forest
        if not self.train_isolation_forest():
            return False
        
        # 3. Build and train Autoencoder
        self.build_autoencoder(input_dim=self.X_train.shape[1])
        self.train_autoencoder(epochs=50)
        
        # 4. Evaluate models
        # Isolation Forest
        if_pred, if_scores = self.predict_isolation_forest(self.X_test)
        if_results = self.evaluate_model("Isolation Forest", self.y_test, if_pred, if_scores)
        
        # Autoencoder  
        ae_pred, ae_scores = self.predict_autoencoder(self.X_test)
        ae_results = self.evaluate_model("Autoencoder", self.y_test, ae_pred, ae_scores)
        
        # 5. Plot curves
        curves_path = Path("projects/auth_session/docs/model_curves.png")
        curves_path.parent.mkdir(parents=True, exist_ok=True)
        self.plot_curves(self.y_test, if_scores, ae_scores, curves_path)
        
        # 6. Save models
        self.save_models()
        
        # 7. Generate report
        report_path = Path("projects/auth_session/docs/model_evaluation_report.md")
        self.generate_evaluation_report(if_results, ae_results, report_path)
        
        self.logger.info("Anomaly detection pipeline completed successfully!")
        return True


def main():
    """Main execution function"""
    detector = AuthAnomalyDetector(
        data_path="projects/auth_session/data/feature_dataset.csv"
    )
    
    try:
        success = detector.run_full_pipeline()
        
        if success:
            print("\n" + "="*70)
            print("🎉 ANOMALY DETECTION PIPELINE COMPLETED SUCCESSFULLY!")
            print("="*70)
            print("📁 Generated Artifacts:")
            print("   projects/auth_session/ml/isolation_forest_model.pkl")
            print("   projects/auth_session/ml/autoencoder_model.h5") 
            print("   projects/auth_session/ml/preprocessing_artifacts.pkl")
            print("   projects/auth_session/docs/model_evaluation_report.md")
            print("   projects/auth_session/docs/model_curves.png")
            print("   projects/auth_session/logs/model_train_eval_<timestamp>.log")
            print("\n📊 Next Steps:")
            print("   1. Review the evaluation report")
            print("   2. Deploy the preferred model")
            print("   3. Monitor performance in production")
            print("   4. Retrain periodically with new data")
        else:
            print("\n❌ Pipeline failed! Check logs for details.")
            
    except Exception as e:
        print(f"❌ Fatal error: {e}")


if __name__ == "__main__":
    main()