import torch
import numpy as np
import json
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import os
import sys
import inspect
from datetime import datetime

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Add safe globals for PyTorch 2.6+ security
torch.serialization.add_safe_globals([np.core.multiarray.scalar])

class Evaluator:
    def __init__(self, model, device, class_names=None):
        self.model = model
        self.device = device
        self.class_names = class_names
        
    def evaluate(self, dataloader):
        self.model.eval()
        all_predictions = []
        all_targets = []
        all_probabilities = []
        
        with torch.no_grad():
            for batch_idx, (tokens, features, target) in enumerate(dataloader):
                tokens, features, target = tokens.to(self.device), features.to(self.device), target.to(self.device)
                output = self.model(tokens, features)
                
                # For binary classification with 1 output, use sigmoid
                if output.shape[1] == 1:
                    probabilities = torch.sigmoid(output)
                    pred = (probabilities > 0.5).long()
                else:
                    probabilities = torch.softmax(output, dim=1)
                    pred = output.argmax(dim=1, keepdim=True)
                
                all_predictions.extend(pred.cpu().numpy())
                all_targets.extend(target.cpu().numpy())
                all_probabilities.extend(probabilities.cpu().numpy())
        
        all_predictions = np.array(all_predictions).flatten()
        all_targets = np.array(all_targets).flatten()
        all_probabilities = np.array(all_probabilities)
        
        metrics = self._calculate_metrics(all_targets, all_predictions, all_probabilities)
        return metrics, all_predictions, all_targets, all_probabilities
    
    def _calculate_metrics(self, y_true, y_pred, y_probabilities):
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_true, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_true, y_pred, average='weighted', zero_division=0)
        }
        
        # Add per-class metrics if class names are provided
        if self.class_names:
            metrics['classification_report'] = classification_report(
                y_true, y_pred, target_names=self.class_names, output_dict=True
            )
            
            # Calculate ROC AUC for binary classification
            if len(self.class_names) == 2:
                from sklearn.metrics import roc_auc_score
                try:
                    if y_probabilities.shape[1] == 2:
                        metrics['roc_auc'] = roc_auc_score(y_true, y_probabilities[:, 1])
                    else:
                        metrics['roc_auc'] = roc_auc_score(y_true, y_probabilities.flatten())
                except:
                    metrics['roc_auc'] = 0.0
        
        return metrics
    
    def plot_confusion_matrix(self, y_true, y_pred, save_path=None):
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=self.class_names if self.class_names else ['Class 0', 'Class 1'],
                   yticklabels=self.class_names if self.class_names else ['Class 0', 'Class 1'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, bbox_inches='tight', dpi=300)
        plt.show()
        plt.close()
    
    def save_results(self, metrics, predictions, targets, save_dir):
        os.makedirs(save_dir, exist_ok=True)
        
        # Save metrics as JSON
        with open(os.path.join(save_dir, 'evaluation_metrics.json'), 'w') as f:
            json_metrics = {}
            for key, value in metrics.items():
                if key == 'classification_report':
                    json_metrics[key] = value
                else:
                    json_metrics[key] = float(value) if isinstance(value, (np.float32, np.float64)) else value
            json.dump(json_metrics, f, indent=4)
        
        # Save predictions and targets
        results_df = pd.DataFrame({
            'true_label': targets,
            'predicted_label': predictions
        })
        results_df.to_csv(os.path.join(save_dir, 'predictions.csv'), index=False)
        
        print(f"Results saved to {save_dir}")

def load_exact_model():
    """Load the model with exact parameters from the checkpoint"""
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    model_path = r'C:\Users\vishal\Desktop\WEBSCAN_PRO\xss_detection\models\best_model.pt'
    
    if not os.path.exists(model_path):
        print(f"Model not found: {model_path}")
        return None
    
    try:
        # Load checkpoint
        checkpoint = torch.load(model_path, map_location=device, weights_only=False)
        print("✓ Checkpoint loaded")
        
        # Import models
        from models import LSTMClassifier
        
        # Extract exact parameters from state dict
        state_dict = checkpoint['model_state_dict']
        
        # Get parameters from state dict
        vocab_size = state_dict['embedding.weight'].shape[0]
        embedding_dim = state_dict['embedding.weight'].shape[1]
        
        model = LSTMClassifier(
            vocab_size=vocab_size,
            embedding_dim=embedding_dim,
            hidden_size=256,
            num_layers=2,
            dropout=0.5,
            bidirectional=True,
            num_features=50,
            output_dim=1
        )
        
        # Load state dict
        model.load_state_dict(state_dict)
        model.to(device)
        model.eval()
        
        print("✓ Model loaded successfully with exact parameters!")
        print(f"Model architecture: LSTMClassifier")
        print(f"Parameters: vocab_size={vocab_size}, embedding_dim={embedding_dim}, hidden_size=256, num_layers=2, output_dim=1")
        print(f"Input signature: forward(tokens, features)")
        
        return model
        
    except Exception as e:
        print(f"Error loading model: {e}")
        import traceback
        traceback.print_exc()
        return None

def create_test_data_for_model(num_samples=200):
    """Create test data for the dual-input LSTMClassifier"""
    from torch.utils.data import DataLoader, TensorDataset
    
    # Based on the model architecture and state dict analysis:
    sequence_length = 50
    
    # Create tokens: token indices (integers between 0 and vocab_size-1)
    # vocab_size is 100, so tokens should be in range [0, 99]
    tokens = torch.randint(0, 100, (num_samples, sequence_length))
    
    # Create features: numerical features (based on feature_fc.0.weight shape [512, 50])
    # The model expects features with the same sequence length as tokens
    features = torch.randn(num_samples, sequence_length)
    
    # Create targets: binary labels
    targets = torch.randint(0, 2, (num_samples,))
    
    # Create dataset with three components: tokens, features, targets
    test_dataset = TensorDataset(tokens, features, targets)
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)
    
    print(f"Created test data:")
    print(f"  - tokens shape: ({num_samples}, {sequence_length}) - range [0, 99]")
    print(f"  - features shape: ({num_samples}, {sequence_length}) - normal distribution")
    print(f"  - targets shape: ({num_samples},) - binary [0, 1]")
    return test_loader

def test_model_with_correct_input(model, device):
    """Test the model with the correct input format"""
    print("\nTesting model with correct input format...")
    
    try:
        # Create correct input
        tokens = torch.randint(0, 100, (2, 50))  # batch_size=2, sequence_length=50
        features = torch.randn(2, 50)            # same shape as tokens
        
        tokens, features = tokens.to(device), features.to(device)
        
        with torch.no_grad():
            output = model(tokens, features)
        
        print(f"✓ Model forward pass successful!")
        print(f"  Input tokens shape: {tokens.shape}")
        print(f"  Input features shape: {features.shape}")
        print(f"  Output shape: {output.shape}")
        print(f"  Output range: [{output.min().item():.4f}, {output.max().item():.4f}]")
        
        # Test binary classification output
        probabilities = torch.sigmoid(output)
        predictions = (probabilities > 0.5).long()
        print(f"  Predictions: {predictions.flatten().cpu().numpy()}")
        
        return True
        
    except Exception as e:
        print(f"✗ Model test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    # Load the exact model
    model = load_exact_model()
    if model is None:
        print("Failed to load model")
        return
    
    device = next(model.parameters()).device
    
    # Test the model with correct input format
    if not test_model_with_correct_input(model, device):
        print("Model test failed. Cannot proceed with evaluation.")
        return
    
    # Create appropriate test data
    print("\nCreating test data...")
    test_loader = create_test_data_for_model()
    
    # Evaluate
    class_names = ['Benign', 'XSS']
    evaluator = Evaluator(model, device, class_names)
    
    print("\nStarting evaluation...")
    try:
        metrics, predictions, targets, probabilities = evaluator.evaluate(test_loader)
        
        # Print results
        print("\n" + "="*50)
        print("XSS DETECTION EVALUATION RESULTS")
        print("="*50)
        for metric, value in metrics.items():
            if metric != 'classification_report':
                print(f"{metric.upper()}: {value:.4f}")
        
        # Display detailed results
        if 'classification_report' in metrics:
            print("\nDetailed Classification Report:")
            report = metrics['classification_report']
            for class_name in class_names:
                if class_name in report:
                    print(f"{class_name}: "
                          f"Precision: {report[class_name]['precision']:.4f}, "
                          f"Recall: {report[class_name]['recall']:.4f}, "
                          f"F1-Score: {report[class_name]['f1-score']:.4f}")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_dir = f"experiments/evaluation_{timestamp}"
        evaluator.save_results(metrics, predictions, targets, save_dir)
        
        # Plot confusion matrix
        print("\nPlotting confusion matrix...")
        evaluator.plot_confusion_matrix(targets, predictions, 
                                       os.path.join(save_dir, 'confusion_matrix.png'))
        
        print(f"\nEvaluation completed! Results saved to: {save_dir}")
        
    except Exception as e:
        print(f"Error during evaluation: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()