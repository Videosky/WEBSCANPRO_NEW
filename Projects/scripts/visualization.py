import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
import shap

class VisualizationEngine:
    def __init__(self):
        self.set_styling()
    
    def set_styling(self):
        """Set consistent styling for all visualizations"""
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def create_confidence_distribution(self, data, save_path=None):
        """Create distribution of confidence scores"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Histogram
        sns.histplot(data=data, x='ml_confidence', bins=20, ax=ax1)
        ax1.set_title('Distribution of ML Confidence Scores')
        ax1.set_xlabel('Confidence Score')
        ax1.set_ylabel('Frequency')
        
        # Violin plot by confidence group
        sns.violinplot(data=data, x='confidence_group', y='ml_confidence', ax=ax2)
        ax2.set_title('Confidence Distribution by Group')
        ax2.set_xlabel('Confidence Group')
        ax2.set_ylabel('Confidence Score')
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.show()
    
    def create_severity_comparison(self, data, save_path=None):
        """Create confusion matrix and comparison plots"""
        # Create comparison column
        data['prediction_match'] = data['severity'] == data['ml_pred_label']
        
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Confidence vs Severity', 'Prediction Accuracy by Group',
                          'Severity Comparison', 'Confidence Distribution by Severity'),
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"secondary_y": False}]]
        )
        
        # Scatter plot: Confidence vs Severity
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        data['severity_num'] = data['severity'].apply(
            lambda x: severity_order.index(x) if x in severity_order else -1
        )
        
        fig.add_trace(
            go.Scatter(x=data['severity_num'], y=data['ml_confidence'],
                      mode='markers', name='Confidence by Severity'),
            row=1, col=1
        )
        
        # Bar chart: Accuracy by confidence group
        accuracy_by_group = data.groupby('confidence_group')['prediction_match'].mean().reset_index()
        fig.add_trace(
            go.Bar(x=accuracy_by_group['confidence_group'], 
                   y=accuracy_by_group['prediction_match'],
                   name='Prediction Accuracy'),
            row=1, col=2
        )
        
        # Update layout
        fig.update_layout(height=800, showlegend=True, title_text="ML Model Performance Analysis")
        
        if save_path:
            fig.write_html(save_path)
        
        return fig
    
    def create_confidence_heatmap(self, data, save_path=None):
        """Create heatmap of confidence vs severity"""
        pivot_table = data.pivot_table(
            values='ml_confidence',
            index='severity',
            columns='ml_pred_label',
            aggfunc='mean'
        ).fillna(0)
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(pivot_table, annot=True, cmap='YlOrRd', fmt='.3f')
        plt.title('Average Confidence: True Severity vs Predicted Label')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close()
        else:
            plt.show()