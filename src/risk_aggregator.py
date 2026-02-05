class RiskAggregator:
    def aggregate(
        self,
        signature_score: float,
        ml_score: float,
        anomaly_score: float,
        context_score: float = 0
    ) -> float:
        """
        Aggregate multiple risk signals
        
        Args:
            signature_score: Score from signatures (0-100)
            ml_score: Score from ML model (0-100)
            anomaly_score: Score from anomaly detection (0-100)
            context_score: Score from context/IP reputation (0-100)
            
        Returns:
            Final risk score (0-100)
        """
        # Your implementation
        weights = {
            'signature': 0.35,
            'ml': 0.35,
            'anomaly': 0.20,
            'context': 0.10
        }
        
        return (
            weights['signature'] * signature_score +
            weights['ml'] * ml_score +
            weights['anomaly'] * anomaly_score +
            weights['context'] * context_score
        )