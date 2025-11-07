"""
IDOR ML Model Training and Hyperparameter Tuning
"""

import pandas as pd
import numpy as np
import json
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

class IDORModelTrainer:
    def __init__(self):
        self.models = {}
        self.best_model = None
        self.best_score = 0
        self.feature_columns = None
        
    def load_training_data(self, splits_dir):
        """Load training, validation, and test data"""
        print("📂 Loading training data...")
        
        train_df = pd.read_csv(os.path.join(splits_dir, 'train.csv'))
        val_df = pd.read_csv(os.path.join(splits_dir, 'val.csv'))
        test_df = pd.read_csv(os.path.join(splits_dir, 'test.csv'))
        
        # Load split configuration
        with open(os.path.join(splits_dir, 'split_config.json'), 'r') as f:
            config = json.load(f)
        
        self.feature_columns = config['feature_columns']
        
        # Prepare features and labels
        X_train = train_df[self.feature_columns]
        y_train = train_df['is_unauthorized']
        
        X_val = val_df[self.feature_columns]
        y_val = val_df['is_unauthorized']
        
        X_test = test_df[self.feature_columns]
        y_test = test_df['is_unauthorized']
        
        print(f"Training set: {X_train.shape}")
        print(f"Validation set: {X_val.shape}")
        print(f"Test set: {X_test.shape}")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def train_logistic_regression(self, X_train, y_train, X_val, y_val):
        """Train and tune Logistic Regression model"""
        print("🧮 Training Logistic Regression...")
        
        pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('lr', LogisticRegression(random_state=42, max_iter=1000))
        ])
        
        param_grid = {
            'lr__C': [0.1, 1.0, 10.0],
            'lr__penalty': ['l1', 'l2'],
            'lr__solver': ['liblinear']
        }
        
        grid_search = GridSearchCV(
            pipeline, param_grid, cv=3, scoring='f1', n_jobs=-1, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        # Validate on validation set
        val_score = grid_search.score(X_val, y_val)
        
        self.models['logistic_regression'] = {
            'model': grid_search.best_estimator_,
            'score': val_score,
            'params': grid_search.best_params_
        }
        
        print(f"✅ Logistic Regression - Best F1: {val_score:.4f}")
        return grid_search.best_estimator_
    
    def train_random_forest(self, X_train, y_train, X_val, y_val):
        """Train and tune Random Forest model"""
        print("🌲 Training Random Forest...")
        
        pipeline = Pipeline([
            ('rf', RandomForestClassifier(random_state=42))
        ])
        
        param_grid = {
            'rf__n_estimators': [100, 200],
            'rf__max_depth': [10, 20, None],
            'rf__min_samples_split': [2, 5],
            'rf__min_samples_leaf': [1, 2]
        }
        
        grid_search = GridSearchCV(
            pipeline, param_grid, cv=3, scoring='f1', n_jobs=-1, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        # Validate on validation set
        val_score = grid_search.score(X_val, y_val)
        
        self.models['random_forest'] = {
            'model': grid_search.best_estimator_,
            'score': val_score,
            'params': grid_search.best_params_
        }
        
        print(f"✅ Random Forest - Best F1: {val_score:.4f}")
        return grid_search.best_estimator_
    
    def train_xgboost(self, X_train, y_train, X_val, y_val):
        """Train and tune XGBoost model"""
        print("🚀 Training XGBoost...")
        
        try:
            pipeline = Pipeline([
                ('xgb', xgb.XGBClassifier(random_state=42, eval_metric='logloss'))
            ])
            
            param_grid = {
                'xgb__n_estimators': [100, 200],
                'xgb__max_depth': [3, 6, 9],
                'xgb__learning_rate': [0.01, 0.1, 0.2],
                'xgb__subsample': [0.8, 1.0]
            }
            
            grid_search = GridSearchCV(
                pipeline, param_grid, cv=3, scoring='f1', n_jobs=-1, verbose=1
            )
            
            grid_search.fit(X_train, y_train)
            
            # Validate on validation set
            val_score = grid_search.score(X_val, y_val)
            
            self.models['xgboost'] = {
                'model': grid_search.best_estimator_,
                'score': val_score,
                'params': grid_search.best_params_
            }
            
            print(f"✅ XGBoost - Best F1: {val_score:.4f}")
            return grid_search.best_estimator_
            
        except Exception as e:
            print(f"⚠️  XGBoost training failed: {e}")
            return None
    
    def select_best_model(self):
        """Select the best performing model based on validation score"""
        print("\n🏆 Selecting best model...")
        
        best_model_name = None
        best_score = 0
        
        for name, model_info in self.models.items():
            print(f"{name}: {model_info['score']:.4f}")
            if model_info['score'] > best_score:
                best_score = model_info['score']
                best_model_name = name
                self.best_model = model_info['model']
        
        print(f"🎯 Best model: {best_model_name} (F1: {best_score:.4f})")
        self.best_score = best_score
        
        return best_model_name, best_score
    
    def evaluate_model(self, model, X_test, y_test, model_name):
        """Comprehensive model evaluation"""
        print(f"\n📊 Evaluating {model_name} on test set...")
        
        # Predictions
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)[:, 1]
        
        # Metrics
        from sklearn.metrics import precision_recall_fscore_support, accuracy_score
        
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        print(f"📈 Test Results for {model_name}:")
        print(f"  Accuracy:  {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall:    {recall:.4f}")
        print(f"  F1-Score:  {f1:.4f}")
        print(f"  ROC-AUC:   {roc_auc:.4f}")
        print(f"  Confusion Matrix:\n{cm}")
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'roc_auc': roc_auc,
            'confusion_matrix': cm.tolist(),
            'predictions': y_pred.tolist(),
            'probabilities': y_pred_proba.tolist()
        }
    
    def save_model_artifacts(self, model, output_dir, evaluation_results):
        """Save model and related artifacts"""
        print("💾 Saving model artifacts...")
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Save model
        model_path = os.path.join(output_dir, 'idor_model.joblib')
        joblib.dump(model, model_path)
        
        # Save preprocessor (if separate)
        preprocessor_path = os.path.join(output_dir, 'preprocessor.joblib')
        joblib.dump(self.feature_columns, preprocessor_path)
        
        # Save training metadata
        metadata = {
            'feature_columns': self.feature_columns,
            'model_type': type(model).__name__,
            'training_timestamp': pd.Timestamp.now().isoformat(),
            'best_validation_score': self.best_score,
            'test_evaluation': evaluation_results,
            'model_comparison': {
                name: {'score': info['score'], 'params': info['params']}
                for name, info in self.models.items()
            }
        }
        
        metadata_path = os.path.join(output_dir, 'training_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print("✅ Model artifacts saved successfully")
        return model_path, preprocessor_path, metadata_path

def main():
    """Main model training pipeline"""
    splits_dir = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\data\splits"
    models_dir = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\projects\auth_session\models"
    
    trainer = IDORModelTrainer()
    
    try:
        # Load data
        X_train, X_val, X_test, y_train, y_val, y_test = trainer.load_training_data(splits_dir)
        
        # Train models
        trainer.train_logistic_regression(X_train, y_train, X_val, y_val)
        trainer.train_random_forest(X_train, y_train, X_val, y_val)
        trainer.train_xgboost(X_train, y_train, X_val, y_val)
        
        # Select best model
        best_name, best_score = trainer.select_best_model()
        
        if trainer.best_model is None:
            raise ValueError("No model trained successfully")
        
        # Evaluate best model on test set
        test_results = trainer.evaluate_model(trainer.best_model, X_test, y_test, best_name)
        
        # Save artifacts
        model_path, preprocessor_path, metadata_path = trainer.save_model_artifacts(
            trainer.best_model, models_dir, test_results
        )
        
        print("\n🎉 Model training completed successfully!")
        print(f"📁 Model saved to: {model_path}")
        print(f"📊 Test F1-Score: {test_results['f1_score']:.4f}")
        
    except Exception as e:
        print(f"❌ Error in model training: {e}")
        raise

if __name__ == "__main__":
    main()