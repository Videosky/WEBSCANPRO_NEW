import torch
import torch.nn as nn
import optuna
from sklearn.model_selection import train_test_split
import json
import os
from datetime import datetime
import yaml

class HyperparameterTuner:
    def __init__(self, model_class, dataset, device):
        self.model_class = model_class
        self.dataset = dataset
        self.device = device
        
    def objective(self, trial):
        # Define hyperparameter search space
        lr = trial.suggest_float('lr', 1e-5, 1e-2, log=True)
        batch_size = trial.suggest_categorical('batch_size', [16, 32, 64])
        hidden_size = trial.suggest_categorical('hidden_size', [64, 128, 256, 512])
        num_layers = trial.suggest_int('num_layers', 1, 4)
        dropout = trial.suggest_float('dropout', 0.1, 0.5)
        
        # Split dataset
        train_size = 0.8
        train_dataset, val_dataset = train_test_split(
            self.dataset, train_size=train_size, random_state=42
        )
        
        train_loader = torch.utils.data.DataLoader(
            train_dataset, batch_size=batch_size, shuffle=True
        )
        val_loader = torch.utils.data.DataLoader(
            val_dataset, batch_size=batch_size, shuffle=False
        )
        
        # Create model
        model = self.model_class(
            vocab_size=100,  # Adjust based on your dataset
            embedding_dim=128,
            hidden_size=hidden_size,
            num_layers=num_layers,
            dropout=dropout,
            bidirectional=True,
            num_features=50,
            output_dim=1
        ).to(self.device)
        
        # Training setup
        criterion = nn.BCEWithLogitsLoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        
        # Train for a few epochs
        best_val_loss = float('inf')
        patience = 3
        patience_counter = 0
        
        for epoch in range(10):  # Quick training for tuning
            # Training
            model.train()
            train_loss = 0
            for batch in train_loader:
                if len(batch) == 3:
                    tokens, features, targets = batch
                    tokens, features, targets = tokens.to(self.device), features.to(self.device), targets.to(self.device)
                    optimizer.zero_grad()
                    outputs = model(tokens, features)
                    loss = criterion(outputs.squeeze(), targets.float())
                else:
                    # Handle single input case
                    data, targets = batch
                    data, targets = data.to(self.device), targets.to(self.device)
                    optimizer.zero_grad()
                    outputs = model(data)
                    loss = criterion(outputs.squeeze(), targets.float())
                
                loss.backward()
                optimizer.step()
                train_loss += loss.item()
            
            # Validation
            model.eval()
            val_loss = 0
            with torch.no_grad():
                for batch in val_loader:
                    if len(batch) == 3:
                        tokens, features, targets = batch
                        tokens, features, targets = tokens.to(self.device), features.to(self.device), targets.to(self.device)
                        outputs = model(tokens, features)
                        loss = criterion(outputs.squeeze(), targets.float())
                    else:
                        data, targets = batch
                        data, targets = data.to(self.device), targets.to(self.device)
                        outputs = model(data)
                        loss = criterion(outputs.squeeze(), targets.float())
                    val_loss += loss.item()
            
            val_loss /= len(val_loader)
            
            # Early stopping for tuning
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
            else:
                patience_counter += 1
                
            if patience_counter >= patience:
                break
        
        return best_val_loss

def run_hyperparameter_tuning(config):
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    # Load your dataset
    # You'll need to implement this based on your dataset structure
    try:
        from dataset import load_dataset
        dataset = load_dataset()
    except:
        print("Warning: Using dummy dataset for demonstration")
        # Create dummy dataset
        from torch.utils.data import TensorDataset
        tokens = torch.randint(0, 100, (1000, 50))
        features = torch.randn(1000, 50)
        targets = torch.randint(0, 2, (1000,))
        dataset = TensorDataset(tokens, features, targets)
    
    # Import your model
    from models import LSTMClassifier
    
    tuner = HyperparameterTuner(LSTMClassifier, dataset, device)
    
    study = optuna.create_study(
        direction='minimize',
        pruner=optuna.pruners.HyperbandPruner()
    )
    
    study.optimize(
        tuner.objective,
        n_trials=config.get('n_trials', 50),
        timeout=config.get('timeout', 3600)  # 1 hour default
    )
    
    return study

def save_tuning_results(study, config, save_dir):
    os.makedirs(save_dir, exist_ok=True)
    
    # Save best parameters
    best_params = study.best_params
    with open(os.path.join(save_dir, 'best_parameters.json'), 'w') as f:
        json.dump(best_params, f, indent=4)
    
    # Save study
    with open(os.path.join(save_dir, 'study.pkl'), 'wb') as f:
        import pickle
        pickle.dump(study, f)
    
    # Save config
    with open(os.path.join(save_dir, 'tuning_config.yaml'), 'w') as f:
        yaml.dump(config, f)
    
    # Create visualization
    try:
        import optuna.visualization as vis
        
        # Optimization history
        fig = vis.plot_optimization_history(study)
        fig.write_html(os.path.join(save_dir, 'optimization_history.html'))
        
        # Parameter importance
        fig = vis.plot_param_importances(study)
        fig.write_html(os.path.join(save_dir, 'param_importances.html'))
        
    except ImportError:
        print("Plotly not installed, skipping visualizations")
    
    print(f"Tuning results saved to: {save_dir}")

def main():
    config = {
        'n_trials': 20,
        'timeout': 1800,  # 30 minutes
        'model': 'LSTMClassifier'
    }
    
    print("Starting hyperparameter tuning...")
    print(f"Configuration: {config}")
    
    study = run_hyperparameter_tuning(config)
    
    print("\nBest trial:")
    trial = study.best_trial
    print(f"  Value (loss): {trial.value:.4f}")
    print("  Params: ")
    for key, value in trial.params.items():
        print(f"    {key}: {value}")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_dir = f"experiments/tuning_{timestamp}"
    save_tuning_results(study, config, save_dir)
    
    print(f"\nTuning completed! Results saved to: {save_dir}")

if __name__ == "__main__":
    main()