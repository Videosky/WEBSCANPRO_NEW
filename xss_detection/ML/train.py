import torch
import torch.nn as nn
import torch.optim as optim
from torch.optim.lr_scheduler import ReduceLROnPlateau, CosineAnnealingLR
import numpy as np
import pandas as pd
import yaml
import os
import json
from datetime import datetime
import warnings
from tqdm import tqdm
import time
import traceback
warnings.filterwarnings('ignore')

from dataset import XSSDataPreprocessor
from models import get_model, get_loss_function
from utils import save_checkpoint, load_checkpoint, calculate_metrics, plot_training_curves

def create_default_config():
    """Create default config file if it doesn't exist"""
    default_config = {
        'model': {
            'type': 'lstm',
            'embedding_dim': 128,
            'hidden_size': 256,
            'num_layers': 2,
            'dropout': 0.3,
            'bidirectional': True,
            'use_attention': True,
            'use_residual': True,
            'num_heads': 8,
            'filter_sizes': [2, 3, 4, 5]
        },
        'training': {
            'epochs': 50,
            'batch_size': 8,  # Reduced for small dataset
            'learning_rate': 0.001,
            'patience': 5,
            'test_split': 0.2,
            'validation_split': 0.1,
            'optimizer': 'adam',
            'scheduler': 'reduce_lr',
            'loss_type': 'bce',
            'focal_alpha': 1.0,
            'focal_gamma': 2.0,
            'weight_decay': 0.0,
            'grad_clip': 1.0,
            'gradient_accumulation_steps': 1
        },
        'data': {
            'max_sequence_length': 500,  # Reduced for small dataset
            'min_sequence_length': 5,    # Reduced for small dataset
            'lowercase': True,
            'clean_special_chars': False
        },
        'features': {
            'use_basic_features': True,
            'use_regex_features': True,
            'use_statistical_features': True,
            'regex_patterns': [
                '<script', 'onerror=', 'onload=', 'javascript:', 
                'alert\\(', 'eval\\(', 'fromCharCode'  # Already escaped
            ]
        },
        'experiment': {
            'random_seed': 42,
            'name': 'xss_detection_v1'
        }
    }
    
    with open('config.yaml', 'w') as f:
        yaml.dump(default_config, f, default_flow_style=False)
    
    print("✓ Created default config.yaml file")
    return default_config

def fix_config_regex_patterns(config):
    """Fix regex patterns by escaping special characters"""
    if 'features' in config and 'regex_patterns' in config['features']:
        fixed_patterns = []
        for pattern in config['features']['regex_patterns']:
            # Escape special regex characters
            fixed_pattern = pattern
            # Escape parentheses
            fixed_pattern = fixed_pattern.replace('(', '\\(').replace(')', '\\)')
            # Escape other regex special characters that might be in XSS patterns
            fixed_pattern = fixed_pattern.replace('[', '\\[').replace(']', '\\]')
            fixed_pattern = fixed_pattern.replace('{', '\\{').replace('}', '\\}')
            fixed_pattern = fixed_pattern.replace('+', '\\+').replace('*', '\\*')
            fixed_pattern = fixed_pattern.replace('?', '\\?').replace('|', '\\|')
            fixed_pattern = fixed_pattern.replace('^', '\\^').replace('$', '\\$')
            fixed_patterns.append(fixed_pattern)
        
        config['features']['regex_patterns'] = fixed_patterns
        print("✓ Fixed regex patterns by escaping special characters")
    
    return config

def generate_test_data():
    """Generate test data if it doesn't exist"""
    print("Generating test dataset...")
    
    # Sample XSS payloads (malicious)
    malicious_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert('XSS')",
        "';alert(1)//",
        "\"><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input onfocus=alert(1) autofocus>"
    ]
    
    # Benign payloads
    benign_payloads = [
        "hello world",
        "test123",
        "search query",
        "user input",
        "normal text",
        "sample data",
        "testing payload",
        "regular input",
        "safe content"
    ]
    
    data = []
    
    # Add malicious samples
    for i, payload in enumerate(malicious_payloads):
        data.append({
            'payload_id': f"M{i+1}",
            'url': f"http://localhost:8080/test.php?q={payload[:20]}",
            'method': 'GET',
            'injection_point': 'query_param:q',
            'payload': payload,
            'response_time': np.random.uniform(0.01, 0.1),
            'status_group': 'success',
            'html_content_length': np.random.randint(1000, 5000),
            'reflected_payload_present': True,
            'is_malicious': True,
            'notes': 'XSS pattern detected'
        })
    
    # Add benign samples
    for i, payload in enumerate(benign_payloads):
        data.append({
            'payload_id': f"B{i+1}",
            'url': f"http://localhost:8080/test.php?q={payload}",
            'method': 'GET',
            'injection_point': 'query_param:q',
            'payload': payload,
            'response_time': np.random.uniform(0.01, 0.05),
            'status_group': 'success',
            'html_content_length': np.random.randint(800, 3000),
            'reflected_payload_present': False,
            'is_malicious': False,
            'notes': 'No XSS indicators found'
        })
    
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    df = pd.DataFrame(data)
    df.to_csv('data/xss_response_dataset.csv', index=False)
    print(f"✓ Generated test dataset with {len(df)} samples")
    print(f"  - Malicious: {df['is_malicious'].sum()}")
    print(f"  - Benign: {len(df) - df['is_malicious'].sum()}")
    return df

class AdvancedXSSTrainer:
    def __init__(self, config, experiment_dir):
        self.config = config
        self.experiment_dir = experiment_dir
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        print(f"Using device: {self.device}")
        if torch.cuda.is_available():
            print(f"GPU: {torch.cuda.get_device_name()}")
            print(f"CUDA version: {torch.version.cuda}")
        
        # Set random seeds for reproducibility
        seed = config['experiment']['random_seed']
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed(seed)
            torch.cuda.manual_seed_all(seed)
        np.random.seed(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
        
        # Initialize components
        self.preprocessor = XSSDataPreprocessor(config)
        self.model = None
        self.optimizer = None
        self.scheduler = None
        
        # Enhanced loss function with class balancing
        self.criterion = get_loss_function(
            config['training'].get('loss_type', 'bce'),
            alpha=config['training'].get('focal_alpha', 1.0),
            gamma=config['training'].get('focal_gamma', 2.0)
        )
        
        # Enhanced training history
        self.history = {
            'train_loss': [], 'val_loss': [],
            'train_f1': [], 'val_f1': [],
            'train_accuracy': [], 'val_accuracy': [],
            'train_precision': [], 'val_precision': [],
            'train_recall': [], 'val_recall': [],
            'learning_rate': [],
            'epoch_times': []
        }
        
        # Gradient accumulation
        self.gradient_accumulation_steps = config['training'].get('gradient_accumulation_steps', 1)
    
    def prepare_data(self, data_path):
        """Prepare data loaders with enhanced validation"""
        print("Preparing data...")
        
        try:
            # Load and preprocess data
            texts, features, labels, df = self.preprocessor.load_and_clean_data(data_path)
            
            # Prepare splits
            splits = self.preprocessor.prepare_splits(
                texts, features, labels,
                test_size=self.config['training']['test_split'],
                val_size=self.config['training']['validation_split'],
                random_state=self.config['experiment']['random_seed']
            )
            
            X_train, X_val, X_test, feat_train, feat_val, feat_test, y_train, y_val, y_test = splits
            
            # Create data loaders with optimized settings
            batch_size = self.config['training']['batch_size']
            train_loader, val_loader, test_loader = self.preprocessor.create_data_loaders(
                X_train, X_val, X_test, feat_train, feat_val, feat_test, 
                y_train, y_val, y_test, batch_size
            )
            
            print(f"✓ Data prepared successfully:")
            print(f"  - Train: {len(X_train)} samples")
            print(f"  - Validation: {len(X_val)} samples") 
            print(f"  - Test: {len(X_test)} samples")
            print(f"  - Features: {feat_train.shape[1]} dimensions")
            print(f"  - Vocabulary size: {self.preprocessor.tokenizer.vocab_size}")
            print(f"  - Label distribution: {np.sum(y_train)} malicious, {len(y_train) - np.sum(y_train)} benign")
            
            return train_loader, val_loader, test_loader, self.preprocessor.tokenizer.vocab_size, feat_train.shape[1]
            
        except Exception as e:
            print(f"❌ Error preparing data: {e}")
            raise
    
    def setup_model(self, vocab_size, num_features):
        """Setup model, optimizer, and scheduler with enhanced options"""
        print("Setting up model...")
        
        self.model = get_model(
            self.config['model']['type'],
            vocab_size,
            num_features,
            self.config
        ).to(self.device)
        
        # Use DataParallel for multi-GPU training
        if torch.cuda.device_count() > 1:
            print(f"Using {torch.cuda.device_count()} GPUs!")
            self.model = nn.DataParallel(self.model)
        
        # Enhanced optimizer with different options
        optimizer_type = self.config['training'].get('optimizer', 'adam').lower()
        lr = self.config['training']['learning_rate']
        weight_decay = self.config['training'].get('weight_decay', 1e-5)
        
        if optimizer_type == 'adamw':
            self.optimizer = optim.AdamW(
                self.model.parameters(),
                lr=lr,
                weight_decay=weight_decay,
                betas=(0.9, 0.999)
            )
        elif optimizer_type == 'adam':
            self.optimizer = optim.Adam(
                self.model.parameters(),
                lr=lr,
                weight_decay=weight_decay
            )
        elif optimizer_type == 'sgd':
            self.optimizer = optim.SGD(
                self.model.parameters(),
                lr=lr,
                momentum=0.9,
                weight_decay=weight_decay,
                nesterov=True
            )
        else:
            raise ValueError(f"Unsupported optimizer: {optimizer_type}")
        
        # Enhanced learning rate scheduler
        scheduler_type = self.config['training'].get('scheduler', 'reduce_lr').lower()
        
        if scheduler_type == 'cosine':
            self.scheduler = CosineAnnealingLR(
                self.optimizer,
                T_max=self.config['training']['epochs'],
                eta_min=lr * 0.01
            )
        elif scheduler_type == 'reduce_lr':
            self.scheduler = ReduceLROnPlateau(
                self.optimizer,
                mode='max',
                factor=0.5,
                patience=3,
                min_lr=1e-7
            )
        elif scheduler_type == 'onecycle':
            self.scheduler = optim.lr_scheduler.OneCycleLR(
                self.optimizer,
                max_lr=lr,
                epochs=self.config['training']['epochs'],
                steps_per_epoch=1,  # Will be updated in training
                pct_start=0.1
            )
        
        # Gradient clipping
        self.grad_clip = self.config['training'].get('grad_clip', 1.0)
        
        print(f"✓ Model setup completed:")
        print(f"  - Model: {self.config['model']['type']}")
        print(f"  - Optimizer: {optimizer_type}")
        print(f"  - Scheduler: {scheduler_type}")
        print(f"  - Parameters: {sum(p.numel() for p in self.model.parameters()):,}")
        print(f"  - Trainable parameters: {sum(p.numel() for p in self.model.parameters() if p.requires_grad):,}")
    
    def train_epoch(self, train_loader, epoch):
        """Enhanced training with gradient accumulation"""
        self.model.train()
        total_loss = 0
        all_preds = []
        all_labels = []
        all_probs = []
        
        # Progress bar
        batch_iterator = tqdm(train_loader, desc=f'Epoch {epoch+1} Training', leave=False)
        
        self.optimizer.zero_grad()
        
        for i, batch in enumerate(batch_iterator):
            tokens = batch['tokens'].to(self.device)
            features = batch['features'].to(self.device)
            labels = batch['label'].to(self.device)
            
            # Forward pass
            outputs = self.model(tokens, features)
            loss = self.criterion(outputs.squeeze(), labels)
            
            # Scale loss for gradient accumulation
            loss = loss / self.gradient_accumulation_steps
            loss.backward()
            
            # Store predictions
            probs = outputs.squeeze().detach()
            preds = (probs > 0.5).float()
            
            all_probs.extend(probs.cpu().numpy())
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            
            # Gradient accumulation
            if (i + 1) % self.gradient_accumulation_steps == 0:
                # Gradient clipping
                if self.grad_clip > 0:
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.grad_clip)
                
                self.optimizer.step()
                self.optimizer.zero_grad()
                
                # Update OneCycleLR scheduler if used
                if isinstance(self.scheduler, optim.lr_scheduler.OneCycleLR):
                    self.scheduler.step()
            
            total_loss += loss.item() * self.gradient_accumulation_steps
            
            # Update progress bar
            current_lr = self.optimizer.param_groups[0]['lr']
            batch_iterator.set_postfix({
                'loss': f'{loss.item() * self.gradient_accumulation_steps:.4f}',
                'lr': f'{current_lr:.2e}'
            })
        
        # Handle remaining gradients
        if len(train_loader) % self.gradient_accumulation_steps != 0:
            if self.grad_clip > 0:
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.grad_clip)
            self.optimizer.step()
            self.optimizer.zero_grad()
        
        avg_loss = total_loss / len(train_loader)
        metrics = calculate_metrics(all_labels, all_probs, all_preds)
        
        return avg_loss, metrics
    
    def validate(self, val_loader, epoch):
        """Enhanced validation with detailed metrics"""
        self.model.eval()
        total_loss = 0
        all_preds = []
        all_labels = []
        all_probs = []
        
        with torch.no_grad():
            batch_iterator = tqdm(val_loader, desc=f'Epoch {epoch+1} Validation', leave=False)
            
            for batch in batch_iterator:
                tokens = batch['tokens'].to(self.device)
                features = batch['features'].to(self.device)
                labels = batch['label'].to(self.device)
                
                outputs = self.model(tokens, features)
                loss = self.criterion(outputs.squeeze(), labels)
                
                total_loss += loss.item()
                
                probs = outputs.squeeze().cpu().numpy()
                preds = (probs > 0.5).astype(float)
                
                all_probs.extend(probs)
                all_preds.extend(preds)
                all_labels.extend(labels.cpu().numpy())
                
                batch_iterator.set_postfix({'loss': f'{loss.item():.4f}'})
        
        avg_loss = total_loss / len(val_loader)
        metrics = calculate_metrics(all_labels, all_probs, all_preds)
        
        return avg_loss, metrics
    
    def train(self, train_loader, val_loader, epochs, patience=5):
        """Enhanced training loop with comprehensive logging"""
        print("Starting training...")
        
        best_val_f1 = 0
        patience_counter = 0
        best_model_path = os.path.join(self.experiment_dir, 'best_model.pt')
        best_metrics = {}
        
        # Training loop with timing
        start_time = time.time()
        
        for epoch in range(epochs):
            epoch_start = time.time()
            
            # Train
            train_loss, train_metrics = self.train_epoch(train_loader, epoch)
            
            # Validate
            val_loss, val_metrics = self.validate(val_loader, epoch)
            
            # Update schedulers
            current_lr = self.optimizer.param_groups[0]['lr']
            
            if isinstance(self.scheduler, ReduceLROnPlateau):
                old_lr = current_lr
                self.scheduler.step(val_metrics['f1'])
                new_lr = self.optimizer.param_groups[0]['lr']
                if new_lr != old_lr:
                    print(f"  → Learning rate reduced from {old_lr:.2e} to {new_lr:.2e}")
            elif isinstance(self.scheduler, CosineAnnealingLR):
                self.scheduler.step()
            
            # Calculate epoch time
            epoch_time = time.time() - epoch_start
            
            # Update history
            self.history['train_loss'].append(train_loss)
            self.history['val_loss'].append(val_loss)
            self.history['train_f1'].append(train_metrics['f1'])
            self.history['val_f1'].append(val_metrics['f1'])
            self.history['train_accuracy'].append(train_metrics['accuracy'])
            self.history['val_accuracy'].append(val_metrics['accuracy'])
            self.history['train_precision'].append(train_metrics['precision'])
            self.history['val_precision'].append(val_metrics['precision'])
            self.history['train_recall'].append(train_metrics['recall'])
            self.history['val_recall'].append(val_metrics['recall'])
            self.history['learning_rate'].append(current_lr)
            self.history['epoch_times'].append(epoch_time)
            
            # Print detailed progress
            print(f"\nEpoch {epoch+1}/{epochs} ({epoch_time:.1f}s):")
            print(f"  LR: {current_lr:.2e} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f}")
            print(f"  Train - F1: {train_metrics['f1']:.4f} | Acc: {train_metrics['accuracy']:.4f} | "
                  f"Prec: {train_metrics['precision']:.4f} | Rec: {train_metrics['recall']:.4f}")
            print(f"  Val   - F1: {val_metrics['f1']:.4f} | Acc: {val_metrics['accuracy']:.4f} | "
                  f"Prec: {val_metrics['precision']:.4f} | Rec: {val_metrics['recall']:.4f}")
            
            # Save best model
            if val_metrics['f1'] > best_val_f1:
                best_val_f1 = val_metrics['f1']
                best_metrics = val_metrics.copy()
                
                checkpoint = {
                    'epoch': epoch,
                    'model_state_dict': self.model.state_dict(),
                    'optimizer_state_dict': self.optimizer.state_dict(),
                    'scheduler_state_dict': self.scheduler.state_dict() if self.scheduler else None,
                    'val_f1': best_val_f1,
                    'val_metrics': val_metrics,
                    'history': self.history,
                    'config': self.config
                }
                
                save_checkpoint(checkpoint, best_model_path)
                patience_counter = 0
                print(f"  → New best model saved with Val F1: {best_val_f1:.4f}")
            else:
                patience_counter += 1
                print(f"  → No improvement ({patience_counter}/{patience})")
            
            # Early stopping
            if patience_counter >= patience:
                print(f"Early stopping triggered at epoch {epoch+1}")
                break
            
            # Save periodic checkpoint
            if (epoch + 1) % 10 == 0:
                periodic_path = os.path.join(self.experiment_dir, f'checkpoint_epoch_{epoch+1}.pt')
                save_checkpoint({
                    'epoch': epoch,
                    'model_state_dict': self.model.state_dict(),
                    'optimizer_state_dict': self.optimizer.state_dict(),
                    'val_f1': val_metrics['f1'],
                    'history': self.history,
                    'config': self.config
                }, periodic_path)
        
        total_time = time.time() - start_time
        print(f"\nTraining completed in {total_time:.1f}s ({total_time/60:.1f}min)")
        print(f"Best Val F1: {best_val_f1:.4f}")
        
        # Load best model for final evaluation
       # Don't reload the model - we already have the best weights in memory
        print("✓ Using best model from training (no reload needed)")
        
        return best_val_f1, best_metrics
    
    def evaluate(self, test_loader):
        """Comprehensive evaluation on test set"""
        print("\nEvaluating on test set...")
        
        test_loss, test_metrics = self.validate(test_loader, 0)  # epoch=0 for evaluation
        
        # Calculate additional metrics
        print("\n" + "="*50)
        print("TEST SET RESULTS")
        print("="*50)
        for metric, value in test_metrics.items():
            if metric not in ['true_positives', 'false_positives', 'false_negatives', 'true_negatives']:
                print(f"{metric.upper():<12}: {value:.4f}")
        
        # Performance analysis
        print(f"\nPerformance Analysis:")
        if test_metrics['precision'] > 0.8 and test_metrics['recall'] > 0.8:
            print("✓ Excellent performance - Well balanced")
        elif test_metrics['precision'] > 0.9:
            print("○ High precision - Few false positives")
        elif test_metrics['recall'] > 0.9:
            print("○ High recall - Few false negatives")
        else:
            print("△ Needs improvement - Consider tuning")
        
        return test_metrics
    
    def save_experiment(self, test_metrics):
        """Save comprehensive experiment results"""
        print(f"\nSaving experiment to: {self.experiment_dir}")
        
        # Enhanced metrics with training summary
        experiment_data = {
            'test_metrics': test_metrics,
            'training_history': self.history,
            'best_val_f1': max(self.history['val_f1']) if self.history['val_f1'] else 0,
            'final_val_f1': self.history['val_f1'][-1] if self.history['val_f1'] else 0,
            'training_time': sum(self.history['epoch_times']),
            'num_epochs': len(self.history['train_loss']),
            'timestamp': datetime.now().isoformat(),
            'device': str(self.device)
        }
        
        # Save metrics
        metrics_path = os.path.join(self.experiment_dir, 'metrics.json')
        with open(metrics_path, 'w') as f:
            json.dump(experiment_data, f, indent=2)
        
        # Save config
        config_path = os.path.join(self.experiment_dir, 'config_used.yaml')
        with open(config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
        
        # Save preprocessor
        preprocessor_path = os.path.join(self.experiment_dir, 'preprocessor.pkl')
        self.preprocessor.save_preprocessor(preprocessor_path)
        
        # Save training curves
        plot_path = os.path.join(self.experiment_dir, 'training_curves.png')
        plot_training_curves(self.history, plot_path)
        
        # Save model summary
        summary_path = os.path.join(self.experiment_dir, 'model_summary.txt')
        with open(summary_path, 'w') as f:
            f.write(f"Model Type: {self.config['model']['type']}\n")
            f.write(f"Parameters: {sum(p.numel() for p in self.model.parameters()):,}\n")
            f.write(f"Best Val F1: {experiment_data['best_val_f1']:.4f}\n")
            f.write(f"Test F1: {test_metrics['f1']:.4f}\n")
        
        print("✓ Experiment artifacts saved successfully")

def main():
    """Enhanced main function with better error handling and validation"""
    try:
        # Create necessary directories
        os.makedirs('experiments', exist_ok=True)
        os.makedirs('data', exist_ok=True)
        os.makedirs('models', exist_ok=True)
        
        # Load configuration
        config_path = 'config.yaml'
        if not os.path.exists(config_path):
            print("Config file not found. Creating default config...")
            config = create_default_config()
        else:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            print("✓ Config file loaded successfully")
        
        # Validate and fix config
        required_sections = ['model', 'training', 'data', 'experiment']
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Missing required config section: {section}")
        
        # Fix regex patterns in config
        config = fix_config_regex_patterns(config)
        
        # Create experiment directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        experiment_dir = os.path.join('experiments', f"run_{timestamp}")
        os.makedirs(experiment_dir, exist_ok=True)
        
        print("="*60)
        print("XSS DETECTION MODEL TRAINING")
        print("="*60)
        print(f"Experiment: {experiment_dir}")
        print(f"Model: {config['model']['type']}")
        print(f"Epochs: {config['training']['epochs']}")
        print(f"Batch size: {config['training']['batch_size']}")
        print(f"Learning rate: {config['training']['learning_rate']}")
        print("="*60)
        
        # Initialize trainer
        trainer = AdvancedXSSTrainer(config, experiment_dir)
        
        # Prepare data
        data_path = 'data/xss_response_dataset.csv'
        if not os.path.exists(data_path):
            print(f"Data file not found: {data_path}")
            print("Generating test dataset...")
            generate_test_data()
        
        train_loader, val_loader, test_loader, vocab_size, num_features = trainer.prepare_data(data_path)
        
        # Setup model
        trainer.setup_model(vocab_size, num_features)
        
        # Train model
        best_val_f1, best_metrics = trainer.train(
            train_loader, 
            val_loader, 
            epochs=config['training']['epochs'],
            patience=config['training']['patience']
        )
        
        # Evaluate on test set
        test_metrics = trainer.evaluate(test_loader)
        
        # Save experiment
        trainer.save_experiment(test_metrics)
        
        # Final summary
        print("\n" + "="*60)
        print("TRAINING COMPLETED SUCCESSFULLY!")
        print("="*60)
        print(f"Results saved to: {experiment_dir}")
        print(f"Best Validation F1: {best_val_f1:.4f}")
        print(f"Test F1: {test_metrics['f1']:.4f}")
        print(f"Test Accuracy: {test_metrics['accuracy']:.4f}")
        print(f"Test Precision: {test_metrics['precision']:.4f}")
        print(f"Test Recall: {test_metrics['recall']:.4f}")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ Training failed with error: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()