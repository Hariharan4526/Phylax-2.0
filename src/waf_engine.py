"""
WAF Engine - Main Orchestrator
Coordinates HTTP parsing, signature detection, ML classification, anomaly detection, and risk aggregation
"""

import json
import logging
import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
import pickle
from pathlib import Path

import numpy as np
from sklearn.preprocessing import StandardScaler


@dataclass
class WAFDecision:
    """Final WAF decision output"""
    request_id: str
    timestamp: str
    decision: str  # "ALLOW", "CHALLENGE", "BLOCK"
    risk_score: float  # 0-100
    confidence: float  # 0-1
    reason: str
    
    # Detailed breakdowns
    signature_matches: List[Dict]
    ml_prediction: Dict
    anomaly_score: float
    
    # Evidence
    contributing_factors: List[str]
    model_confidence: Dict
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


class WAFEngine:
    """
    Main WAF Engine
    
    Coordinates:
    1. HTTP Parsing & Normalization
    2. Signature Detection (Regex rules)
    3. ML Classification (RF, GB, XGBoost)
    4. Anomaly Detection (IF, GMM, LOF)
    5. Risk Aggregation (Weighted scoring)
    6. Final Decision Making
    """
    
    def __init__(
        self,
        model_path: str = "models/gb_model_20260203_144133.pkl",
        scaler_path: str = "models/scaler_20260203_144133.pkl",
        feature_names_path: str = "models/feature_names_20260203_144133.json",
        config_path: Optional[str] = None
    ):
        """
        Initialize WAF Engine
        
        Args:
            model_path: Path to trained ML model
            scaler_path: Path to feature scaler
            feature_names_path: Path to feature names JSON
            config_path: Path to configuration file
        """
        self.logger = self._setup_logger()
        self.logger.info("Initializing WAF Engine...")
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Load models and scalers
        self.ml_model = self._load_model(model_path)
        self.scaler = self._load_scaler(scaler_path)
        self.feature_names = self._load_feature_names(feature_names_path)
        
        # Initialize detection modules (to be imported from user's implementations)
        self.http_parser = None
        self.regex_engine = None
        self.anomaly_detector = None
        self.risk_aggregator = None

        self._initialize_default_modules()
        
        self.logger.info("WAF Engine initialized successfully!")
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("WAFEngine")
        logger.setLevel(logging.INFO)

        if logger.handlers:
            return logger
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger

    def _initialize_default_modules(self):
        """Initialize built-in modules when available."""
        try:
            from src.http_parser import HTTPParser
            self.http_parser = HTTPParser()
        except Exception as e:
            self.logger.warning(f"HTTP parser unavailable: {e}")

        try:
            from src.regex_engine import RegexSignatureEngine
            self.regex_engine = RegexSignatureEngine()
        except Exception as e:
            self.logger.warning(f"Regex engine unavailable: {e}")

        try:
            from src.anamoly_detector import AnomalyDetector
            self.anomaly_detector = AnomalyDetector()
        except Exception as e:
            self.logger.warning(f"Anomaly detector unavailable: {e}")

        try:
            from src.risk_aggregator import RiskAggregator
            self.risk_aggregator = RiskAggregator()
        except Exception as e:
            self.logger.warning(f"Risk aggregator unavailable: {e}")
    
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration"""
        default_config = {
            "risk_thresholds": {
                "allow": 33,
                "challenge": 66,
                "block": 100
            },
            "weights": {
                "signature": 0.35,
                "ml": 0.35,
                "anomaly": 0.20,
                "context": 0.10
            },
            "ml_threshold": 0.5,
            "anomaly_threshold": 0.7,
            "enable_logging": True,
            "cache_decisions": False,
            "max_payload_size": 10 * 1024 * 1024,  # 10 MB
            "fail_open": os.getenv('WAF_FAIL_OPEN', 'false').lower() == 'true',
            "admin_api_key": os.getenv('ADMIN_API_KEY', ''),
            "require_admin_api_key": os.getenv('REQUIRE_ADMIN_API_KEY', 'false').lower() == 'true',
            "request_limit_per_minute": int(os.getenv('RATE_LIMIT_REQUESTS_PER_MINUTE', '120')),
            "rate_limit_window_seconds": int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', '60'))
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path) as f:
                    user_config = json.load(f)
                default_config.update(user_config)
                self.logger.info(f"Loaded custom config from {config_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}. Using defaults.")
        
        return default_config
    
    def _load_model(self, model_path: str):
        """Load ML model"""
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            self.logger.info(f"Loaded ML model from {model_path}")
            return model
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            raise
    
    def _load_scaler(self, scaler_path: str) -> StandardScaler:
        """Load feature scaler"""
        try:
            with open(scaler_path, 'rb') as f:
                scaler = pickle.load(f)
            self.logger.info(f"Loaded scaler from {scaler_path}")
            return scaler
        except Exception as e:
            self.logger.error(f"Failed to load scaler: {e}")
            raise
    
    def _load_feature_names(self, feature_names_path: str) -> List[str]:
        """Load feature names"""
        try:
            with open(feature_names_path) as f:
                feature_names = json.load(f)
            self.logger.info(f"Loaded {len(feature_names)} feature names")
            return feature_names
        except Exception as e:
            self.logger.error(f"Failed to load feature names: {e}")
            raise
    
    def set_detection_modules(
        self,
        http_parser=None,
        regex_engine=None,
        anomaly_detector=None,
        risk_aggregator=None
    ):
        """
        Set detection modules
        
        Args:
            http_parser: HTTPParser instance
            regex_engine: RegexSignatureEngine instance
            anomaly_detector: AnomalyDetector instance
            risk_aggregator: RiskAggregator instance
        """
        self.http_parser = http_parser
        self.regex_engine = regex_engine
        self.anomaly_detector = anomaly_detector
        self.risk_aggregator = risk_aggregator
        self.logger.info("Detection modules set")
    
    def process_request(self, raw_http: str, request_id: str = None) -> WAFDecision:
        """
        Process HTTP request and make WAF decision
        
        Args:
            raw_http: Raw HTTP request string
            request_id: Optional request ID for tracking
            
        Returns:
            WAFDecision object
        """
        if request_id is None:
            request_id = self._generate_request_id()
        
        self.logger.info(f"Processing request {request_id}")
        
        try:
            # Step 1: Parse and normalize request
            parsed_request = self._parse_request(raw_http)
            if parsed_request is None:
                return self._create_block_decision(request_id, "Invalid HTTP request")
            
            # Step 2: Signature detection
            signature_matches = self._detect_signatures(parsed_request)
            signature_score = self._score_signatures(signature_matches)
            
            # Step 3: ML Classification
            ml_prediction = self._classify_ml(parsed_request)
            ml_score = ml_prediction.get('attack_probability', 0) * 100
            
            # Step 4: Anomaly Detection
            anomaly_result = self._detect_anomalies(parsed_request)
            anomaly_score = anomaly_result.get('anomaly_score', 0) * 100
            
            # Step 5: Risk Aggregation
            final_decision = self._aggregate_risk(
                request_id,
                signature_score,
                ml_score,
                anomaly_score,
                signature_matches,
                ml_prediction,
                anomaly_result
            )
            
            # Log decision
            self._log_decision(final_decision)
            
            return final_decision
            
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return self._create_error_decision(request_id, str(e))
    
    def _parse_request(self, raw_http: str) -> Optional[Dict]:
        """Parse HTTP request"""
        if self.http_parser is None:
            self.logger.warning("HTTP parser not set, using mock parser")
            return self._mock_parse(raw_http)
        
        try:
            return self.http_parser.parse_raw_request(raw_http)
        except Exception as e:
            self.logger.error(f"Error parsing request: {e}")
            return None
    
    def _mock_parse(self, raw_http: str) -> Dict:
        """Mock HTTP parser (when real parser not available)"""
        lines = raw_http.split('\n')
        request_line = lines[0].split()
        
        return {
            'method': request_line[0] if len(request_line) > 0 else 'GET',
            'path': request_line[1] if len(request_line) > 1 else '/',
            'body': '\n'.join(lines[1:]),
            'headers': {},
            'query_params': {}
        }
    
    def _detect_signatures(self, request: Dict) -> List[Dict]:
        """Detect signature matches"""
        if self.regex_engine is None:
            self.logger.debug("Regex engine not set, skipping signature detection")
            return []
        
        try:
            matches = self.regex_engine.detect_in_request(request)
            flattened = []

            if isinstance(matches, dict):
                for location, match_list in matches.items():
                    for match in match_list:
                        if hasattr(match, '__dict__'):
                            match_dict = dict(match.__dict__)
                        elif isinstance(match, dict):
                            match_dict = dict(match)
                        else:
                            continue
                        match_dict['location'] = match_dict.get('location', location)
                        flattened.append(match_dict)
            elif isinstance(matches, list):
                for match in matches:
                    if hasattr(match, '__dict__'):
                        flattened.append(dict(match.__dict__))
                    elif isinstance(match, dict):
                        flattened.append(dict(match))

            self.logger.debug(f"Found {len(flattened)} signature matches")
            return flattened
        except Exception as e:
            self.logger.error(f"Error in signature detection: {e}")
            return []
    
    def _score_signatures(self, matches: List[Dict]) -> float:
        """Score signature matches (0-100)"""
        if not matches:
            return 0.0
        
        # Get highest risk score from matches
        max_score = max([m.get('risk_score', 0) for m in matches], default=0)
        return float(max_score)
    
    def _classify_ml(self, request: Dict) -> Dict:
        """ML classification"""
        try:
            # Extract features from request
            features = self._extract_features(request)
            
            # Scale features
            features_scaled = self.scaler.transform([features])[0]
            
            # Predict
            probability = self.ml_model.predict_proba([features_scaled])[0][1]
            
            return {
                'attack_probability': float(probability),
                'confidence': float(max(probability, 1 - probability)),
                'model_type': 'gradient_boosting',
                'prediction': 'attack' if probability > self.config.get('ml_threshold', 0.5) else 'benign'
            }
        except Exception as e:
            self.logger.error(f"Error in ML classification: {e}")
            return {
                'attack_probability': 0.5,
                'confidence': 0.5,
                'error': str(e)
            }
    
    def _extract_features(self, request: Dict) -> List[float]:
        """Extract features from request for ML"""
        feature_map = {}

        if self.http_parser is not None and hasattr(self.http_parser, 'extract_features_for_ml'):
            try:
                feature_map = self.http_parser.extract_features_for_ml(request)
            except Exception as e:
                self.logger.warning(f"Feature extraction from parser failed: {e}")

        if not feature_map:
            if isinstance(request, dict):
                payload = f"{request.get('body', '')} {request.get('path', '')}"
            else:
                payload = f"{getattr(request, 'body', '')} {getattr(request, 'path', '')}"
            feature_map = {
                'request_body_length': float(len(payload)),
                'decoded_body_length': float(len(payload)),
                'path_length': float(len(getattr(request, 'path', ''))),
            }

        features = []
        for feature_name in self.feature_names:
            features.append(float(feature_map.get(feature_name, 0.0)))

        return features
    
    def _detect_anomalies(self, request: Dict) -> Dict:
        """Anomaly detection"""
        if self.anomaly_detector is None:
            self.logger.debug("Anomaly detector not set, skipping anomaly detection")
            return {'anomaly_score': 0.0}
        
        try:
            result = self.anomaly_detector.detect(request)
            return result
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            return {'anomaly_score': 0.0}
    
    def _aggregate_risk(
        self,
        request_id: str,
        signature_score: float,
        ml_score: float,
        anomaly_score: float,
        signature_matches: List[Dict],
        ml_prediction: Dict,
        anomaly_result: Dict
    ) -> WAFDecision:
        """Aggregate all signals into final risk score"""
        
        # Get weights from config
        weights = self.config['weights']
        
        # Normalize scores to 0-100 range
        sig_score = min(100, signature_score)
        ml_score = min(100, ml_score)
        anom_score = min(100, anomaly_score)
        context_score = 0  # Placeholder for context/IP reputation
        
        # Weighted average
        if self.risk_aggregator is not None and hasattr(self.risk_aggregator, 'aggregate'):
            risk_score = self.risk_aggregator.aggregate(
                signature_score=sig_score,
                ml_score=ml_score,
                anomaly_score=anom_score,
                context_score=context_score
            )
        else:
            risk_score = (
                weights['signature'] * sig_score +
                weights['ml'] * ml_score +
                weights['anomaly'] * anom_score +
                weights['context'] * context_score
            )
        
        # Make decision based on thresholds
        thresholds = self.config['risk_thresholds']
        if risk_score <= thresholds['allow']:
            decision = 'ALLOW'
            reason = 'Low risk score'
        elif risk_score <= thresholds['challenge']:
            decision = 'CHALLENGE'
            reason = 'Medium risk score - human verification required'
        else:
            decision = 'BLOCK'
            reason = 'High risk score - potential attack detected'
        
        # Build contributing factors
        contributing_factors = []
        if sig_score > 0:
            contributing_factors.append(f"Signature match: {sig_score:.1f}/100")
        if ml_score > 50:
            contributing_factors.append(f"ML classification: {ml_score:.1f}/100 (attack)")
        if anom_score > 70:
            contributing_factors.append(f"Anomaly detected: {anom_score:.1f}/100")
        
        if not contributing_factors:
            contributing_factors.append("Clean request - no issues detected")
        
        # Create WAF decision
        waf_decision = WAFDecision(
            request_id=request_id,
            timestamp=datetime.utcnow().isoformat(),
            decision=decision,
            risk_score=float(risk_score),
            confidence=float(ml_prediction.get('confidence', 0.5)),
            reason=reason,
            signature_matches=signature_matches,
            ml_prediction=ml_prediction,
            anomaly_score=float(anom_score),
            contributing_factors=contributing_factors,
            model_confidence={
                'signature': float(sig_score),
                'ml': float(ml_score),
                'anomaly': float(anom_score)
            }
        )
        
        return waf_decision
    
    def _create_block_decision(self, request_id: str, reason: str) -> WAFDecision:
        """Create BLOCK decision"""
        return WAFDecision(
            request_id=request_id,
            timestamp=datetime.utcnow().isoformat(),
            decision='BLOCK',
            risk_score=100.0,
            confidence=1.0,
            reason=reason,
            signature_matches=[],
            ml_prediction={},
            anomaly_score=0.0,
            contributing_factors=[reason],
            model_confidence={}
        )
    
    def _create_error_decision(self, request_id: str, error: str) -> WAFDecision:
        """Create decision on processing error based on fail-open policy."""
        fail_open = bool(self.config.get('fail_open', False))
        decision = 'ALLOW' if fail_open else 'BLOCK'
        risk_score = 0.0 if fail_open else 100.0
        reason = f"Error during processing ({'fail-open' if fail_open else 'fail-closed'}): {error}"

        return WAFDecision(
            request_id=request_id,
            timestamp=datetime.utcnow().isoformat(),
            decision=decision,
            risk_score=risk_score,
            confidence=0.0,
            reason=reason,
            signature_matches=[],
            ml_prediction={},
            anomaly_score=0.0,
            contributing_factors=[error],
            model_confidence={}
        )
    
    def _log_decision(self, decision: WAFDecision):
        """Log WAF decision"""
        if self.config.get('enable_logging', True):
            self.logger.info(
                f"Decision for {decision.request_id}: {decision.decision} "
                f"(risk={decision.risk_score:.1f}, confidence={decision.confidence:.2f})"
            )
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        import time
        import random
        return f"req_{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
    
    def get_statistics(self) -> Dict:
        """Get WAF engine statistics"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'ml_model': 'gradient_boosting',
            'feature_count': len(self.feature_names),
            'config': self.config,
            'modules_loaded': {
                'http_parser': self.http_parser is not None,
                'regex_engine': self.regex_engine is not None,
                'anomaly_detector': self.anomaly_detector is not None,
                'risk_aggregator': self.risk_aggregator is not None
            }
        }


if __name__ == "__main__":
    # Example usage
    engine = WAFEngine()
    
    # Example request
    sample_request = """GET /api/users?id=1' OR '1'='1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Content-Length: 0

"""
    
    decision = engine.process_request(sample_request)
    print(decision.to_json())