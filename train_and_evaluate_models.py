# projects/sql_injection/scripts/train_and_evaluate_models.py

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
import pickle
import os
import matplotlib.pyplot as plt
import seaborn as sns


class SQLInjectionModelTrainer:
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.models = {}
        self.metrics = {}

    def load_data(self, file_path):
        """Load the feature dataset"""
        try:
            self.df = pd.read_csv(file_path)
            print(f"✅ Dataset loaded successfully with {len(self.df)} rows and {len(self.df.columns)} columns.")
            return True
        except Exception as e:
            print(f"❌ Error loading dataset: {e}")
            return False

    def prepare_features(self):
        """Prepare features and target variable"""
        feature_columns = ['response_time', 'html_content_length', 'error_message_flag', 'status_group']
        self.X = self.df[feature_columns]
        self.y = self.df['is_malicious']

        print(f"📊 Features shape: {self.X.shape}")
        print(f"🎯 Target distribution:\n{self.y.value_counts()}")

    def split_data(self, test_size=0.2):
        """Split data into training and testing sets"""
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            self.X, self.y,
            test_size=test_size,
            random_state=self.random_state,
            stratify=self.y
        )
        print(f"🔹 Training set: {self.X_train.shape[0]} samples")
        print(f"🔹 Testing set: {self.X_test.shape[0]} samples")

    def train_decision_tree(self):
        """Train Decision Tree Classifier"""
        print("🌲 Training Decision Tree Classifier...")
        dt_model = DecisionTreeClassifier(random_state=self.random_state)
        dt_model.fit(self.X_train, self.y_train)
        self.models['decision_tree'] = dt_model
        return dt_model

    def train_random_forest(self):
        """Train Random Forest Classifier"""
        print("🌳 Training Random Forest Classifier...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            random_state=self.random_state,
            max_depth=10
        )
        rf_model.fit(self.X_train, self.y_train)
        self.models['random_forest'] = rf_model
        return rf_model

    def evaluate_model(self, model, model_name):
        """Evaluate model performance"""
        y_pred = model.predict(self.X_test)

        accuracy = accuracy_score(self.y_test, y_pred)
        precision = precision_score(self.y_test, y_pred)
        recall = recall_score(self.y_test, y_pred)
        f1 = f1_score(self.y_test, y_pred)

        self.metrics[model_name] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'classification_report': classification_report(self.y_test, y_pred),
            'confusion_matrix': confusion_matrix(self.y_test, y_pred)
        }

        print(f"\n📈 {model_name.upper()} Evaluation:")
        print(f"Accuracy:  {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1-Score:  {f1:.4f}")

        return self.metrics[model_name]

    def plot_confusion_matrix(self, model_name, cm):
        """Plot confusion matrix"""
        plt.figure(figsize=(6, 4))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title(f'Confusion Matrix - {model_name}')
        plt.ylabel('Actual')
        plt.xlabel('Predicted')

        plots_dir = 'projects/sql_injection/docs/plots'
        os.makedirs(plots_dir, exist_ok=True)
        plt.savefig(f'{plots_dir}/{model_name}_confusion_matrix.png')
        plt.close()

    def select_best_model(self):
        """Select the best model based on F1-score"""
        best_model_name = None
        best_f1 = 0

        for model_name, metrics in self.metrics.items():
            if metrics['f1_score'] > best_f1:
                best_f1 = metrics['f1_score']
                best_model_name = model_name

        self.best_model_name = best_model_name
        self.best_model = self.models[best_model_name]

        print(f"\n🏆 Best Model: {best_model_name.upper()} (F1-Score: {best_f1:.4f})")
        return best_model_name, best_f1

    def save_models(self):
        """Save all trained models"""
        models_dir = 'projects/sql_injection/models'
        os.makedirs(models_dir, exist_ok=True)

        for model_name, model in self.models.items():
            filename = f'{models_dir}/{model_name}_model.pkl'
            with open(filename, 'wb') as f:
                pickle.dump(model, f)
            print(f"💾 Saved {model_name} model to {filename}")

        best_model_filename = f'{models_dir}/best_model.pkl'
        with open(best_model_filename, 'wb') as f:
            pickle.dump(self.best_model, f)
        print(f"💾 Saved best model ({self.best_model_name}) to {best_model_filename}")

    def generate_evaluation_report(self):
        """Generate model evaluation report in Markdown format"""
        docs_dir = 'projects/sql_injection/docs'
        os.makedirs(docs_dir, exist_ok=True)

        report_content = "# SQL Injection Detection - Model Evaluation Report\n\n"
        report_content += "## Model Performance Comparison\n\n"

        report_content += "| Model | Accuracy | Precision | Recall | F1-Score |\n"
        report_content += "|-------|----------|-----------|--------|----------|\n"

        for model_name, metrics in self.metrics.items():
            report_content += (
                f"| {model_name.replace('_', ' ').title()} | "
                f"{metrics['accuracy']:.4f} | {metrics['precision']:.4f} | "
                f"{metrics['recall']:.4f} | {metrics['f1_score']:.4f} |\n"
            )

        report_content += (
            f"\n## ✅ Best Model: {self.best_model_name.replace('_', ' ').title()} "
            f"(F1-Score: {self.metrics[self.best_model_name]['f1_score']:.4f})\n\n"
        )

        report_content += "## Detailed Classification Reports\n\n"
        for model_name, metrics in self.metrics.items():
            report_content += f"### {model_name.replace('_', ' ').title()}\n\n"
            report_content += "```\n" + metrics['classification_report'] + "\n```\n\n"

        report_filename = f'{docs_dir}/model_evaluation_report.md'
        # ✅ FIX: Use UTF-8 encoding to handle emojis and special characters
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report_content)

        print(f"📄 Evaluation report saved to {report_filename}")
        return report_content


def main():
    """Main execution function"""
    print("🚀 SQL Injection Detection - Model Training & Evaluation")
    print("=" * 60)

    trainer = SQLInjectionModelTrainer(random_state=42)

    # Step 1: Load dataset
    dataset_path = r"C:\Users\vishal\Desktop\WEBSCAN_PRO\data\feature_dataset.csv"
    if not trainer.load_data(dataset_path):
        return

    trainer.prepare_features()
    trainer.split_data(test_size=0.2)

    # Step 2: Train models
    dt_model = trainer.train_decision_tree()
    rf_model = trainer.train_random_forest()

    # Step 3: Evaluate models
    print("\n" + "=" * 60)
    print("MODEL EVALUATION RESULTS")
    print("=" * 60)
    trainer.evaluate_model(dt_model, 'decision_tree')
    trainer.evaluate_model(rf_model, 'random_forest')

    # Step 4: Select best model
    best_model_name, best_f1 = trainer.select_best_model()

    # Step 5: Save models and generate report
    print("\n" + "=" * 60)
    print("SAVING MODELS AND GENERATING REPORTS")
    print("=" * 60)
    trainer.save_models()
    trainer.generate_evaluation_report()

    # Step 6: Plot confusion matrices
    for model_name, metrics in trainer.metrics.items():
        trainer.plot_confusion_matrix(model_name, metrics['confusion_matrix'])

    print("\n✅ Training and evaluation completed successfully!")
    print(f"🎯 Best model: {best_model_name} with F1-Score: {best_f1:.4f}")


if __name__ == "__main__":
    main()
