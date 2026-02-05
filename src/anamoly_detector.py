class AnomalyDetector:
    def detect(self, request: Dict) -> Dict:
        """
        Detect anomalies in request
        
        Args:
            request: Parsed HTTP request
            
        Returns:
            Dict with keys:
                - anomaly_score: float (0-1)
                - method: str (which method detected it)
                - confidence: float (0-1)
        """
        return {
            'anomaly_score': 0.5,
            'method': 'isolation_forest',
            'confidence': 0.8
        }