"""
ML Model Training Module
Train classification models on extracted WAF features.
"""

import pandas as pd
import numpy as np
import pickle
import json
import logging
from pathlib import Path
from typing import Dict, Tuple, Any
from datetime import datetime

try:
    from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                                f1_score, roc_auc_score, confusion_matrix,
                                roc_curve, auc, classification_report)
    from sklearn.utils import class_weight
    import matplotlib.pyplot as plt
    import seaborn as sns
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("scikit-learn required: pip install scikit-learn")

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WAFModelTrainer:
    """Train ML models for WAF attack detection."""
    
    def __init__(self, output_dir: str = "models"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.models = {}
        self.scaler = None
        self.feature_names = None
        self.training_results = {}
    
    def load_features(self, csv_file: str) -> Tuple[np.ndarray, np.ndarray, list]:
        """
        Load features from CSV.
        
        Args:
            csv_file: Path to features CSV
            
        Returns:
            (X, y, feature_names) tuple
        """
        logger.info(f"Loading features from {csv_file}")
        
        df = pd.read_csv(csv_file)
        logger.info(f"Loaded {len(df)} samples with {len(df.columns)} columns")
        
        # Separate features and labels
        if 'label_numeric' in df.columns:
            y = df['label_numeric'].values
            X = df.drop(columns=['label_numeric', 'original_label', 'label'], errors='ignore').values
            feature_names = df.drop(columns=['label_numeric', 'original_label', 'label'], 
                                   errors='ignore').columns.tolist()
        else:
            y = df.iloc[:, -1].values
            X = df.iloc[:, :-1].values
            feature_names = df.columns[:-1].tolist()
        
        logger.info(f"Features shape: {X.shape}")
        logger.info(f"Labels distribution: {np.bincount(y.astype(int))}")
        
        self.feature_names = feature_names
        return X, y, feature_names
    
    def prepare_data(self, X: np.ndarray, y: np.ndarray, 
                    test_size: float = 0.2,
                    random_state: int = 42) -> Tuple[Any, Any, Any, Any]:
        """
        Prepare data for training: handle missing values, scale features, split.
        
        Returns:
            (X_train, X_test, y_train, y_test)
        """
        logger.info("Preparing data...")
        
        # Handle missing values
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        logger.info(f"Handled missing values: {np.isnan(X).sum()} NaNs")
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=test_size,
            random_state=random_state,
            stratify=y
        )
        
        logger.info(f"Train set: {X_train.shape}, Test set: {X_test.shape}")
        logger.info(f"Train labels: {np.bincount(y_train.astype(int))}")
        logger.info(f"Test labels: {np.bincount(y_test.astype(int))}")
        
        # Feature scaling
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        logger.info("Features scaled")
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def train_random_forest(self, X_train: np.ndarray, y_train: np.ndarray,
                           X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Train Random Forest classifier."""
        logger.info("Training Random Forest...")
        
        # Calculate class weights
        cw = class_weight.compute_class_weight('balanced', 
                                               classes=np.unique(y_train),
                                               y=y_train)
        cw_dict = {i: w for i, w in enumerate(cw)}
        
        # Train model
        rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            class_weight=cw_dict,
            verbose=1
        )
        
        rf.fit(X_train, y_train)
        self.models['rf'] = rf
        
        # Evaluate
        y_pred = rf.predict(X_test)
        y_pred_proba = rf.predict_proba(X_test)[:, 1]
        
        results = self._evaluate_model(y_test, y_pred, y_pred_proba, "Random Forest")
        self.training_results['RandomForest'] = results
        
        return results
    
    def train_gradient_boosting(self, X_train: np.ndarray, y_train: np.ndarray,
                               X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Train Gradient Boosting classifier."""
        logger.info("Training Gradient Boosting...")
        
        # Calculate scale_pos_weight for imbalanced data
        neg_count = (y_train == 0).sum()
        pos_count = (y_train == 1).sum()
        scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1
        
        gb = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.05,
            max_depth=5,
            min_samples_split=10,
            min_samples_leaf=5,
            subsample=0.8,
            random_state=42,
            verbose=1
        )
        
        gb.fit(X_train, y_train)
        self.models['gb'] = gb
        
        # Evaluate
        y_pred = gb.predict(X_test)
        y_pred_proba = gb.predict_proba(X_test)[:, 1]
        
        results = self._evaluate_model(y_test, y_pred, y_pred_proba, "Gradient Boosting")
        self.training_results['GradientBoosting'] = results
        
        return results
    
    def train_xgboost(self, X_train: np.ndarray, y_train: np.ndarray,
                      X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Train XGBoost classifier."""
        if not XGBOOST_AVAILABLE:
            logger.warning("XGBoost not available")
            return {}
        
        logger.info("Training XGBoost...")
        
        # Calculate scale_pos_weight
        neg_count = (y_train == 0).sum()
        pos_count = (y_train == 1).sum()
        scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1
        
        xgb_model = xgb.XGBClassifier(
            n_estimators=200,
            learning_rate=0.05,
            max_depth=5,
            min_child_weight=1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos_weight,
            random_state=42,
            use_label_encoder=False,
            eval_metric='logloss',
            verbosity=1
        )
        
        xgb_model.fit(X_train, y_train)
        self.models['xgb'] = xgb_model
        
        # Evaluate
        y_pred = xgb_model.predict(X_test)
        y_pred_proba = xgb_model.predict_proba(X_test)[:, 1]
        
        results = self._evaluate_model(y_test, y_pred, y_pred_proba, "XGBoost")
        self.training_results['XGBoost'] = results
        
        return results
    
    def _evaluate_model(self, y_test: np.ndarray, y_pred: np.ndarray,
                       y_pred_proba: np.ndarray, model_name: str) -> Dict[str, Any]:
        """Evaluate model performance."""
        logger.info(f"\nEvaluating {model_name}...")
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        
        # Confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        results = {
            'model_name': model_name,
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'roc_auc': float(roc_auc),
            'false_positive_rate': float(fpr),
            'false_negative_rate': float(fnr),
            'confusion_matrix': {
                'tn': int(tn),
                'fp': int(fp),
                'fn': int(fn),
                'tp': int(tp)
            },
            'classification_report': classification_report(y_test, y_pred, 
                                                          output_dict=True)
        }
        
        # Log results
        logger.info(f"  Accuracy: {accuracy:.4f}")
        logger.info(f"  Precision: {precision:.4f}")
        logger.info(f"  Recall: {recall:.4f}")
        logger.info(f"  F1-Score: {f1:.4f}")
        logger.info(f"  ROC-AUC: {roc_auc:.4f}")
        logger.info(f"  False Positive Rate: {fpr:.4f}")
        logger.info(f"  False Negative Rate: {fnr:.4f}")
        logger.info(f"  Confusion Matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
        
        return results
    
    def cross_validate(self, X: np.ndarray, y: np.ndarray, cv: int = 5) -> Dict[str, Any]:
        """Perform cross-validation."""
        logger.info(f"Performing {cv}-fold cross-validation...")
        
        cv_results = {}
        
        if 'rf' in self.models:
            logger.info("  Random Forest...")
            scores = cross_val_score(self.models['rf'], X, y, cv=cv, 
                                    scoring='f1', n_jobs=-1)
            cv_results['RandomForest'] = {
                'scores': scores.tolist(),
                'mean': float(scores.mean()),
                'std': float(scores.std())
            }
            logger.info(f"    F1-Score: {scores.mean():.4f} (+/- {scores.std():.4f})")
        
        if 'gb' in self.models:
            logger.info("  Gradient Boosting...")
            scores = cross_val_score(self.models['gb'], X, y, cv=cv,
                                    scoring='f1', n_jobs=-1)
            cv_results['GradientBoosting'] = {
                'scores': scores.tolist(),
                'mean': float(scores.mean()),
                'std': float(scores.std())
            }
            logger.info(f"    F1-Score: {scores.mean():.4f} (+/- {scores.std():.4f})")
        
        if 'xgb' in self.models:
            logger.info("  XGBoost...")
            scores = cross_val_score(self.models['xgb'], X, y, cv=cv,
                                    scoring='f1', n_jobs=-1)
            cv_results['XGBoost'] = {
                'scores': scores.tolist(),
                'mean': float(scores.mean()),
                'std': float(scores.std())
            }
            logger.info(f"    F1-Score: {scores.mean():.4f} (+/- {scores.std():.4f})")
        
        return cv_results
    
    def save_models(self, timestamp: str = None) -> None:
        """Save trained models to disk."""
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        logger.info(f"Saving models (timestamp: {timestamp})...")
        
        # Save models
        for name, model in self.models.items():
            model_path = self.output_dir / f"{name}_model_{timestamp}.pkl"
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            logger.info(f"  Saved {name} to {model_path}")
        
        # Save scaler
        if self.scaler:
            scaler_path = self.output_dir / f"scaler_{timestamp}.pkl"
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            logger.info(f"  Saved scaler to {scaler_path}")
        
        # Save feature names
        if self.feature_names:
            features_path = self.output_dir / f"feature_names_{timestamp}.json"
            with open(features_path, 'w') as f:
                json.dump(self.feature_names, f)
            logger.info(f"  Saved feature names to {features_path}")
        
        # Save training results
        results_path = self.output_dir / f"training_results_{timestamp}.json"
        with open(results_path, 'w') as f:
            json.dump(self.training_results, f, indent=2)
        logger.info(f"  Saved results to {results_path}")
    
    def create_summary_report(self, output_file: str = None) -> str:
        """Create comprehensive training summary report."""
        if output_file is None:
            output_file = self.output_dir / f"training_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        report = []
        report.append("="*80)
        report.append("WAF ML MODEL TRAINING REPORT")
        report.append("="*80)
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        report.append(f"\n\nFEATURES: {len(self.feature_names)} features")
        report.append(f"Feature Names: {', '.join(self.feature_names[:10])}...")
        
        report.append(f"\n\nMODELS TRAINED: {len(self.models)}")
        for model_name in self.models.keys():
            report.append(f"  - {model_name}")
        
        report.append(f"\n\nPERFORMANCE RESULTS")
        report.append("-"*80)
        
        for model_name, results in self.training_results.items():
            report.append(f"\n{model_name}:")
            report.append(f"  Accuracy:  {results['accuracy']:.4f}")
            report.append(f"  Precision: {results['precision']:.4f}")
            report.append(f"  Recall:    {results['recall']:.4f}")
            report.append(f"  F1-Score:  {results['f1_score']:.4f}")
            report.append(f"  ROC-AUC:   {results['roc_auc']:.4f}")
            report.append(f"  FPR:       {results['false_positive_rate']:.4f}")
            report.append(f"  FNR:       {results['false_negative_rate']:.4f}")
            
            cm = results['confusion_matrix']
            report.append(f"  Confusion Matrix:")
            report.append(f"    TP={cm['tp']}, FP={cm['fp']}, FN={cm['fn']}, TN={cm['tn']}")
        
        report_text = "\n".join(report)
        
        # Save to file
        with open(output_file, 'w') as f:
            f.write(report_text)
        
        logger.info(f"Saved report to {output_file}")
        return report_text


def main():
    """Main training pipeline."""
    logger.info("Starting WAF Model Training Pipeline")
    
    # Check dependencies
    if not SKLEARN_AVAILABLE:
        logger.error("scikit-learn required. Install with: pip install scikit-learn")
        return
    
    # Initialize trainer
    trainer = WAFModelTrainer(output_dir="models")
    
    # Process datasets
    print("\n" + "="*80)
    print("STEP 1: FEATURE EXTRACTION")
    print("="*80)
    
    # Assuming features are already extracted
    feature_file = "csic_features.csv"
    
    if not Path(feature_file).exists():
        logger.error(f"Feature file not found: {feature_file}")
        logger.info("Run feature extraction first: python 02_feature_extraction.py")
        return
    
    # Load features
    print("\n" + "="*80)
    print("STEP 2: DATA LOADING & PREPARATION")
    print("="*80)
    
    X, y, feature_names = trainer.load_features(feature_file)
    X_train, X_test, y_train, y_test = trainer.prepare_data(X, y)
    
    # Train models
    print("\n" + "="*80)
    print("STEP 3: MODEL TRAINING")
    print("="*80)
    
    trainer.train_random_forest(X_train, y_train, X_test, y_test)
    trainer.train_gradient_boosting(X_train, y_train, X_test, y_test)
    
    if XGBOOST_AVAILABLE:
        trainer.train_xgboost(X_train, y_train, X_test, y_test)
    
    # Cross-validation
    print("\n" + "="*80)
    print("STEP 4: CROSS-VALIDATION")
    print("="*80)
    
    cv_results = trainer.cross_validate(X, y, cv=5)
    
    # Save models
    print("\n" + "="*80)
    print("STEP 5: MODEL PERSISTENCE")
    print("="*80)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    trainer.save_models(timestamp)
    
    # Generate report
    print("\n" + "="*80)
    print("STEP 6: REPORT GENERATION")
    print("="*80)
    
    report = trainer.create_summary_report()
    print(report)
    
    logger.info("\nTraining pipeline completed successfully!")


if __name__ == "__main__":
    main()