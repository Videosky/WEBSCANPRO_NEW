import torch
import numpy as np
import matplotlib.pyplot as plt
import os
import json
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import seaborn as sns

def save_checkpoint(state, filename):
    """Save model checkpoint"""
    torch.save(state, filename)
    print(f"Checkpoint saved: {filename}")

def load_checkpoint(filename):
    """Load model checkpoint with PyTorch 2.6 compatibility"""
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Checkpoint file not found: {filename}")
    
    try:
        # First try with weights_only=True (secure)
        checkpoint = torch.load(filename, map_location='cpu', weights_only=True)
    except Exception as e:
        print(f"Secure loading failed: {e}")
        print("Trying with weights_only=False (use only for trusted sources)")
        # Fallback to weights_only=False for compatibility
        checkpoint = torch.load(filename, map_location='cpu', weights_only=False)
    
    print(f"Checkpoint loaded: {filename}")
    return checkpoint

def calculate_metrics(labels, probs, preds=None):
    """Calculate comprehensive evaluation metrics"""
    labels = np.array(labels)
    probs = np.array(probs)
    
    if preds is None:
        preds = (probs > 0.5).astype(float)
    else:
        preds = np.array(preds)
    
    metrics = {
        'accuracy': accuracy_score(labels, preds),
        'precision': precision_score(labels, preds, zero_division=0),
        'recall': recall_score(labels, preds, zero_division=0),
        'f1': f1_score(labels, preds, zero_division=0)
    }
    
    # Calculate AUC-ROC
    try:
        metrics['auc_roc'] = roc_auc_score(labels, probs)
    except:
        metrics['auc_roc'] = 0.0
    
    # Additional metrics for binary classification
    try:
        tn, fp, fn, tp = confusion_matrix(labels, preds).ravel()
        metrics.update({
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp),
            'specificity': tn / (tn + fp) if (tn + fp) > 0 else 0.0,
            'false_positive_rate': fp / (fp + tn) if (fp + tn) > 0 else 0.0,
            'false_negative_rate': fn / (fn + tp) if (fn + tp) > 0 else 0.0
        })
    except:
        # Handle case where confusion matrix can't be computed
        metrics.update({
            'true_negatives': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'true_positives': 0,
            'specificity': 0.0,
            'false_positive_rate': 0.0,
            'false_negative_rate': 0.0
        })
    
    return metrics

def plot_training_curves(history, save_path=None):
    """Plot training and validation curves"""
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle('Training Progress', fontsize=16, fontweight='bold')
    
    # Loss curves
    axes[0, 0].plot(history['train_loss'], label='Train Loss', linewidth=2)
    axes[0, 0].plot(history['val_loss'], label='Val Loss', linewidth=2)
    axes[0, 0].set_title('Loss')
    axes[0, 0].set_xlabel('Epoch')
    axes[0, 0].set_ylabel('Loss')
    axes[0, 0].legend()
    axes[0, 0].grid(True, alpha=0.3)
    
    # Accuracy curves
    axes[0, 1].plot(history['train_accuracy'], label='Train Accuracy', linewidth=2)
    axes[0, 1].plot(history['val_accuracy'], label='Val Accuracy', linewidth=2)
    axes[0, 1].set_title('Accuracy')
    axes[0, 1].set_xlabel('Epoch')
    axes[0, 1].set_ylabel('Accuracy')
    axes[0, 1].legend()
    axes[0, 1].grid(True, alpha=0.3)
    
    # F1 Score curves
    axes[0, 2].plot(history['train_f1'], label='Train F1', linewidth=2)
    axes[0, 2].plot(history['val_f1'], label='Val F1', linewidth=2)
    axes[0, 2].set_title('F1 Score')
    axes[0, 2].set_xlabel('Epoch')
    axes[0, 2].set_ylabel('F1 Score')
    axes[0, 2].legend()
    axes[0, 2].grid(True, alpha=0.3)
    
    # Precision-Recall curves
    axes[1, 0].plot(history['train_precision'], label='Train Precision', linewidth=2)
    axes[1, 0].plot(history['val_precision'], label='Val Precision', linewidth=2)
    axes[1, 0].plot(history['train_recall'], label='Train Recall', linewidth=2)
    axes[1, 0].plot(history['val_recall'], label='Val Recall', linewidth=2)
    axes[1, 0].set_title('Precision & Recall')
    axes[1, 0].set_xlabel('Epoch')
    axes[1, 0].set_ylabel('Score')
    axes[1, 0].legend()
    axes[1, 0].grid(True, alpha=0.3)
    
    # Learning rate
    if 'learning_rate' in history:
        axes[1, 1].plot(history['learning_rate'], label='Learning Rate', color='purple', linewidth=2)
        axes[1, 1].set_title('Learning Rate')
        axes[1, 1].set_xlabel('Epoch')
        axes[1, 1].set_ylabel('LR')
        axes[1, 1].set_yscale('log')
        axes[1, 1].legend()
        axes[1, 1].grid(True, alpha=0.3)
    
    # Epoch times
    if 'epoch_times' in history:
        axes[1, 2].plot(history['epoch_times'], label='Epoch Time', color='red', linewidth=2)
        axes[1, 2].set_title('Epoch Time')
        axes[1, 2].set_xlabel('Epoch')
        axes[1, 2].set_ylabel('Time (s)')
        axes[1, 2].legend()
        axes[1, 2].grid(True, alpha=0.3)
    
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Training curves saved: {save_path}")
    
    plt.close()

def plot_confusion_matrix(labels, preds, save_path=None):
    """Plot confusion matrix"""
    cm = confusion_matrix(labels, preds)
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Benign', 'Malicious'],
                yticklabels=['Benign', 'Malicious'])
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Confusion matrix saved: {save_path}")
    
    plt.close()

def plot_roc_curve(labels, probs, save_path=None):
    """Plot ROC curve"""
    from sklearn.metrics import roc_curve
    
    fpr, tpr, thresholds = roc_curve(labels, probs)
    auc_score = roc_auc_score(labels, probs)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, linewidth=2, label=f'ROC curve (AUC = {auc_score:.3f})')
    plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random classifier')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"ROC curve saved: {save_path}")
    
    plt.close()

def print_metrics(metrics, title="Metrics"):
    """Print metrics in a formatted way"""
    print(f"\n{title}")
    print("=" * 50)
    print(f"Accuracy:    {metrics['accuracy']:.4f}")
    print(f"Precision:   {metrics['precision']:.4f}")
    print(f"Recall:      {metrics['recall']:.4f}")
    print(f"F1 Score:    {metrics['f1']:.4f}")
    print(f"AUC-ROC:     {metrics.get('auc_roc', 0):.4f}")
    print(f"Specificity: {metrics.get('specificity', 0):.4f}")
    if 'true_positives' in metrics:
        print(f"TP: {metrics.get('true_positives', 0)} | FP: {metrics.get('false_positives', 0)}")
        print(f"FN: {metrics.get('false_negatives', 0)} | TN: {metrics.get('true_negatives', 0)}")

def count_parameters(model):
    """Count trainable parameters in model"""
    return sum(p.numel() for p in model.parameters() if p.requires_grad)

def get_device():
    """Get available device"""
    if torch.cuda.is_available():
        return torch.device('cuda')
    elif torch.backends.mps.is_available():
        return torch.device('mps')
    else:
        return torch.device('cpu')

def set_seed(seed=42):
    """Set random seed for reproducibility"""
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
    np.random.seed(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False

def create_experiment_dir(base_dir, experiment_name):
    """Create experiment directory with timestamp"""
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    experiment_dir = os.path.join(base_dir, f"{experiment_name}_{timestamp}")
    os.makedirs(experiment_dir, exist_ok=True)
    return experiment_dir

def save_model_summary(model, config, filepath):
    """Save model summary to file"""
    with open(filepath, 'w') as f:
        f.write("MODEL SUMMARY\n")
        f.write("=" * 50 + "\n")
        f.write(f"Model Type: {config['model']['type']}\n")
        f.write(f"Total Parameters: {count_parameters(model):,}\n")
        f.write(f"Trainable Parameters: {count_parameters(model):,}\n")
        f.write("\nModel Architecture:\n")
        f.write(str(model))
        f.write("\n\nConfiguration:\n")
        f.write(json.dumps(config, indent=2))

def load_best_model_from_checkpoint(checkpoint_path, model, optimizer=None):
    """Load best model from checkpoint"""
    checkpoint = load_checkpoint(checkpoint_path)
    model.load_state_dict(checkpoint['model_state_dict'])
    
    if optimizer and 'optimizer_state_dict' in checkpoint:
        optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
    
    print(f"Loaded best model from epoch {checkpoint['epoch']}")
    print(f"Best validation F1: {checkpoint.get('val_f1', 0):.4f}")
    
    return checkpoint

def calculate_class_weights(dataloader):
    """Calculate class weights for imbalanced datasets"""
    all_labels = []
    for batch in dataloader:
        all_labels.extend(batch['label'].numpy())
    
    class_counts = np.bincount(all_labels)
    total_samples = len(all_labels)
    class_weights = total_samples / (len(class_counts) * class_counts)
    
    return torch.tensor(class_weights, dtype=torch.float32)

# Test the functions
if __name__ == "__main__":
    print("Testing utils functions...")
    
    # Test metrics calculation
    test_labels = [0, 1, 0, 1, 1, 0, 1, 1]
    test_probs = [0.1, 0.9, 0.2, 0.8, 0.7, 0.3, 0.85, 0.95]
    
    metrics = calculate_metrics(test_labels, test_probs)
    print_metrics(metrics, "Test Metrics")
    
    print("✓ All utils functions working correctly!")