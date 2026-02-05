"""
Supervised Machine Learning Classifier Module
Trains and applies ML models for attack classification.
"""

import numpy as np
import pickle
import logging
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass
from pathlib import Path

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available - ML classifier will be disabled")

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class MLPrediction:
    """ML classifier prediction result."""
    predicted_class: str  # "attack" or "benign"
    attack_probability: float  # 0-1 probability of attack
    confidence: float  # 0-1 confidence in prediction
    feature_importance: Dict[str, float]
    top_contributing_features: List[Tuple[str, float]]
    model_version: str


class MLClassifier:
    """
    Supervised ML classifier for attack detection.
    Supports multiple models with ensemble voting.
    """
    
    # Feature names (must match training)
    FEATURE_NAMES = [
        'request_body_length',
        'decoded_body_length',
        'path_length',
        'total_params',
        'param_avg_length',
        'param_max_length',
        'param_min_length',
        'special_char_ratio',
        'digit_ratio',
        'uppercase_ratio',
        'entropy',
        'sql_keyword_count',
        'cmd_keyword_count',
        'percent_signs',
        'null_bytes',
        'quotes_count',
        'xss_tag_count',
        'comment_count',
        'encoding_count'
    ]
    
    def __init__(self, model_dir: Optional[str] = None, model_version: str = "1.0.0"):
        """
        Initialize ML classifier.
        
        Args:
            model_dir: Directory to load/save models
            model_version: Version identifier for models
        """
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn is required for ML classifier")
        
        self.model_dir = Path(model_dir) if model_dir else Path(__file__).parent.parent / 'models'
        self.model_dir.mkdir(exist_ok=True)
        
        self.model_version = model_version
        
        # Initialize models
        self.rf_model: Optional[RandomForestClassifier] = None
        self.gb_model: Optional[GradientBoostingClassifier] = None
        self.xgb_model: Optional[xgb.XGBClassifier] = None if XGBOOST_AVAILABLE else None
        
        # Scaler for feature normalization
        self.scaler: Optional[StandardScaler] = None
        
        # Try to load pre-trained models
        self._load_models()
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_test: Optional[np.ndarray] = None,
              y_test: Optional[np.ndarray] = None,
              validation_split: float = 0.2) -> Dict[str, Any]:
        """
        Train ML models.
        
        Args:
            X_train: Training features (n_samples, n_features)
            y_train: Training labels (0=benign, 1=attack)
            X_test: Test features (optional)
            y_test: Test labels (optional)
            validation_split: Fraction for validation if test not provided
            
        Returns:
            Dictionary with training results and metrics
        """
        if len(X_train) == 0:
            raise ValueError("Training data is empty")
        
        # Initialize scaler and normalize features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Create test set if not provided
        if X_test is None:
            X_train_scaled, X_test, y_train, y_test = train_test_split(
                X_train_scaled, y_train, 
                test_size=validation_split,
                random_state=42,
                stratify=y_train
            )
        else:
            X_test = self.scaler.transform(X_test)
        
        results = {
            'models_trained': [],
            'metrics': {}
        }
        
        # Train Random Forest
        logger.info("Training Random Forest classifier...")
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.rf_model.fit(X_train_scaled, y_train)
        
        # Evaluate RF
        rf_pred = self.rf_model.predict(X_test)
        rf_pred_proba = self.rf_model.predict_proba(X_test)[:, 1]
        
        results['models_trained'].append('RandomForest')
        results['metrics']['RandomForest'] = {
            'accuracy': accuracy_score(y_test, rf_pred),
            'precision': precision_score(y_test, rf_pred, zero_division=0),
            'recall': recall_score(y_test, rf_pred, zero_division=0),
            'f1_score': f1_score(y_test, rf_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, rf_pred_proba)
        }
        
        logger.info(f"Random Forest - Accuracy: {results['metrics']['RandomForest']['accuracy']:.4f}")
        
        # Train Gradient Boosting
        logger.info("Training Gradient Boosting classifier...")
        self.gb_model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            subsample=0.8
        )
        self.gb_model.fit(X_train_scaled, y_train)
        
        # Evaluate GB
        gb_pred = self.gb_model.predict(X_test)
        gb_pred_proba = self.gb_model.predict_proba(X_test)[:, 1]
        
        results['models_trained'].append('GradientBoosting')
        results['metrics']['GradientBoosting'] = {
            'accuracy': accuracy_score(y_test, gb_pred),
            'precision': precision_score(y_test, gb_pred, zero_division=0),
            'recall': recall_score(y_test, gb_pred, zero_division=0),
            'f1_score': f1_score(y_test, gb_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, gb_pred_proba)
        }
        
        logger.info(f"Gradient Boosting - Accuracy: {results['metrics']['GradientBoosting']['accuracy']:.4f}")
        
        # Train XGBoost if available
        if XGBOOST_AVAILABLE:
            logger.info("Training XGBoost classifier...")
            self.xgb_model = xgb.XGBClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                min_child_weight=1,
                random_state=42,
                use_label_encoder=False,
                eval_metric='logloss'
            )
            self.xgb_model.fit(X_train_scaled, y_train)
            
            # Evaluate XGBoost
            xgb_pred = self.xgb_model.predict(X_test)
            xgb_pred_proba = self.xgb_model.predict_proba(X_test)[:, 1]
            
            results['models_trained'].append('XGBoost')
            results['metrics']['XGBoost'] = {
                'accuracy': accuracy_score(y_test, xgb_pred),
                'precision': precision_score(y_test, xgb_pred, zero_division=0),
                'recall': recall_score(y_test, xgb_pred, zero_division=0),
                'f1_score': f1_score(y_test, xgb_pred, zero_division=0),
                'roc_auc': roc_auc_score(y_test, xgb_pred_proba)
            }
            
            logger.info(f"XGBoost - Accuracy: {results['metrics']['XGBoost']['accuracy']:.4f}")
        
        # Ensemble metrics (voting)
        ensemble_pred = self._ensemble_vote([rf_pred, gb_pred])
        ensemble_pred_proba = (rf_pred_proba + gb_pred_proba) / 2
        if self.xgb_model is not None:
            xgb_pred_proba = self.xgb_model.predict_proba(X_test)[:, 1]
            ensemble_pred_proba = (ensemble_pred_proba * 2 + xgb_pred_proba) / 3
            ensemble_pred = self._ensemble_vote([rf_pred, gb_pred, xgb_pred])
        
        results['metrics']['Ensemble'] = {
            'accuracy': accuracy_score(y_test, ensemble_pred),
            'precision': precision_score(y_test, ensemble_pred, zero_division=0),
            'recall': recall_score(y_test, ensemble_pred, zero_division=0),
            'f1_score': f1_score(y_test, ensemble_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, ensemble_pred_proba)
        }
        
        logger.info(f"Ensemble - Accuracy: {results['metrics']['Ensemble']['accuracy']:.4f}")
        
        # Save models
        self._save_models()
        
        return results
    
    def predict(self, features: Dict[str, float]) -> MLPrediction:
        """
        Predict if request is attack or benign.
        
        Args:
            features: Dictionary of extracted features
            
        Returns:
            MLPrediction with probability and confidence
        """
        if self.rf_model is None:
            # Return neutral prediction if models not trained
            return MLPrediction(
                predicted_class="unknown",
                attack_probability=0.5,
                confidence=0.0,
                feature_importance={},
                top_contributing_features=[],
                model_version=self.model_version
            )
        
        # Convert features dict to array
        try:
            X = self._features_dict_to_array(features)
        except Exception as e:
            logger.error(f"Feature conversion error: {e}")
            return MLPrediction(
                predicted_class="error",
                attack_probability=0.5,
                confidence=0.0,
                feature_importance={},
                top_contributing_features=[],
                model_version=self.model_version
            )
        
        # Scale features
        if self.scaler is None:
            logger.warning("Scaler not initialized")
            return MLPrediction(
                predicted_class="unknown",
                attack_probability=0.5,
                confidence=0.0,
                feature_importance={},
                top_contributing_features=[],
                model_version=self.model_version
            )
        
        X_scaled = self.scaler.transform([X])
        
        # Get predictions from all models
        rf_pred = self.rf_model.predict(X_scaled)[0]
        rf_proba = self.rf_model.predict_proba(X_scaled)[0]
        
        gb_pred = self.gb_model.predict(X_scaled)[0] if self.gb_model else rf_pred
        gb_proba = self.gb_model.predict_proba(X_scaled)[0] if self.gb_model else rf_proba
        
        xgb_pred = self.xgb_model.predict(X_scaled)[0] if self.xgb_model else rf_pred
        xgb_proba = self.xgb_model.predict_proba(X_scaled)[0] if self.xgb_model else rf_proba
        
        # Ensemble voting
        predictions = [rf_pred, gb_pred, xgb_pred]
        votes = sum(predictions)
        ensemble_pred = 1 if votes >= 2 else 0
        
        # Ensemble probability (average)
        ensemble_proba = (rf_proba[1] + gb_proba[1] + xgb_proba[1]) / 3
        
        # Calculate confidence
        confidence = max(ensemble_proba, 1 - ensemble_proba)
        
        # Get feature importance
        feature_importance = self._get_feature_importance(X_scaled[0])
        top_features = sorted(feature_importance.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
        
        return MLPrediction(
            predicted_class="attack" if ensemble_pred == 1 else "benign",
            attack_probability=float(ensemble_proba),
            confidence=float(confidence),
            feature_importance=feature_importance,
            top_contributing_features=top_features,
            model_version=self.model_version
        )
    
    def _features_dict_to_array(self, features: Dict[str, float]) -> np.ndarray:
        """Convert feature dictionary to array matching feature names."""
        X = []
        for feature_name in self.FEATURE_NAMES:
            value = features.get(feature_name, 0.0)
            # Handle missing values
            if value is None:
                value = 0.0
            X.append(float(value))
        return np.array(X)
    
    def _get_feature_importance(self, X: np.ndarray) -> Dict[str, float]:
        """Get feature importance scores."""
        importance = {}
        
        if self.rf_model is not None:
            for name, importance_val in zip(self.FEATURE_NAMES, self.rf_model.feature_importances_):
                importance[name] = float(importance_val)
        
        return importance
    
    def _ensemble_vote(self, predictions: List[np.ndarray]) -> np.ndarray:
        """Ensemble voting on predictions."""
        ensemble = np.sum(predictions, axis=0)
        return (ensemble >= len(predictions) / 2).astype(int)
    
    def _save_models(self) -> None:
        """Save trained models to disk."""
        try:
            if self.rf_model:
                with open(self.model_dir / f'rf_model_v{self.model_version}.pkl', 'wb') as f:
                    pickle.dump(self.rf_model, f)
            
            if self.gb_model:
                with open(self.model_dir / f'gb_model_v{self.model_version}.pkl', 'wb') as f:
                    pickle.dump(self.gb_model, f)
            
            if self.xgb_model:
                with open(self.model_dir / f'xgb_model_v{self.model_version}.pkl', 'wb') as f:
                    pickle.dump(self.xgb_model, f)
            
            # Save scaler
            if self.scaler:
                with open(self.model_dir / f'scaler_v{self.model_version}.pkl', 'wb') as f:
                    pickle.dump(self.scaler, f)
            
            logger.info(f"Models saved to {self.model_dir}")
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def _load_models(self) -> None:
        """Load pre-trained models from disk."""
        try:
            # Load latest versions
            rf_path = list(self.model_dir.glob('rf_model_*.pkl'))
            if rf_path:
                with open(rf_path[-1], 'rb') as f:
                    self.rf_model = pickle.load(f)
                logger.info(f"Loaded Random Forest model from {rf_path[-1]}")
            
            gb_path = list(self.model_dir.glob('gb_model_*.pkl'))
            if gb_path:
                with open(gb_path[-1], 'rb') as f:
                    self.gb_model = pickle.load(f)
                logger.info(f"Loaded Gradient Boosting model from {gb_path[-1]}")
            
            xgb_path = list(self.model_dir.glob('xgb_model_*.pkl'))
            if xgb_path and XGBOOST_AVAILABLE:
                with open(xgb_path[-1], 'rb') as f:
                    self.xgb_model = pickle.load(f)
                logger.info(f"Loaded XGBoost model from {xgb_path[-1]}")
            
            scaler_path = list(self.model_dir.glob('scaler_*.pkl'))
            if scaler_path:
                with open(scaler_path[-1], 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info(f"Loaded scaler from {scaler_path[-1]}")
        
        except Exception as e:
            logger.warning(f"Could not load pre-trained models: {e}")


if __name__ == "__main__":
    # Example usage
    classifier = MLClassifier()
    
    # Example features
    example_features = {
        'request_body_length': 100,
        'decoded_body_length': 95,
        'path_length': 25,
        'total_params': 5,
        'param_avg_length': 20,
        'param_max_length': 50,
        'param_min_length': 5,
        'special_char_ratio': 0.1,
        'digit_ratio': 0.2,
        'uppercase_ratio': 0.15,
        'entropy': 4.5,
        'sql_keyword_count': 0,
        'cmd_keyword_count': 0,
        'percent_signs': 0,
        'null_bytes': 0,
        'quotes_count': 2,
        'xss_tag_count': 0,
        'comment_count': 0,
        'encoding_count': 0
    }
    
    prediction = classifier.predict(example_features)
    print(f"Prediction: {prediction.predicted_class}")
    print(f"Attack Probability: {prediction.attack_probability:.4f}")
    print(f"Confidence: {prediction.confidence:.4f}")