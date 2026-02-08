# waf_integration_bridge.py
# Bridge between Dashboard (5001) and WAF Engine (5000)
# Handles requests, logging, and integration

import requests
import json
import logging
import sqlite3
from datetime import datetime
from typing import Dict, Optional
from functools import wraps
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WAFIntegrationBridge:
    """
    Bridge between Dashboard and WAF Engine
    
    - Routes requests from dashboard to WAF engine
    - Logs all requests to database
    - Handles errors and retries
    - Caches responses
    """
    
    def __init__(self, waf_url: str = "http://localhost:5000", db_path: str = "dashboard.db"):
        """Initialize bridge"""
        self.waf_url = waf_url
        self.db_path = db_path
        self.session = requests.Session()
        self.session.timeout = 10
        
        # Retry settings
        self.max_retries = 3
        self.retry_delay = 0.5
        
        logger.info(f"WAF Integration Bridge initialized - WAF URL: {waf_url}")
    
    def check_waf_health(self) -> bool:
        """Check if WAF engine is running"""
        try:
            response = self.session.get(
                f"{self.waf_url}/waf/health",
                timeout=5
            )
            is_healthy = response.status_code == 200
            logger.info(f"WAF health check: {'✅ HEALTHY' if is_healthy else '❌ UNHEALTHY'}")
            return is_healthy
        except requests.exceptions.ConnectionError:
            logger.error(f"❌ Cannot connect to WAF engine at {self.waf_url}")
            logger.error("   Make sure WAF engine is running on port 5000")
            return False
        except Exception as e:
            logger.error(f"❌ WAF health check failed: {e}")
            return False
    
    def send_check_request(
        self,
        raw_http: str,
        request_id: str = None,
        verbose: bool = False
    ) -> Optional[Dict]:
        """
        Send request to WAF engine for analysis
        
        Args:
            raw_http: Raw HTTP request string
            request_id: Optional request ID
            verbose: Include detailed analysis
            
        Returns:
            WAF decision dictionary or None if failed
        """
        if not self.check_waf_health():
            logger.warning("WAF engine not available, using mock response")
            return self._get_mock_response(raw_http, request_id)
        
        payload = {
            "raw_http": raw_http,
            "request_id": request_id
        }
        
        # Retry logic
        for attempt in range(self.max_retries):
            try:
                response = self.session.post(
                    f"{self.waf_url}/waf/check",
                    json=payload,
                    params={"verbose": "true" if verbose else "false"}
                )
                
                if response.status_code in [200, 403]:
                    decision = response.json()
                    logger.info(f"Decision: {decision.get('decision')} (risk={decision.get('risk_score'):.1f})")
                    return decision
                else:
                    logger.warning(f"Unexpected status code: {response.status_code}")
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Attempt {attempt + 1}: Request timeout")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error: {e}")
                logger.error("Make sure WAF engine is running:")
                logger.error("  python main.py")
                return None
                
            except json.JSONDecodeError:
                logger.error("Invalid JSON response from WAF engine")
                return None
                
            except Exception as e:
                logger.error(f"Error sending check request: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
        
        logger.error(f"Failed after {self.max_retries} attempts")
        return None
    
    def get_waf_stats(self) -> Optional[Dict]:
        """Get WAF engine statistics"""
        try:
            response = self.session.get(f"{self.waf_url}/waf/stats", timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"Error getting WAF stats: {e}")
        return None
    
    def log_request_to_db(
        self,
        request_id: str,
        method: str,
        path: str,
        ip_address: str,
        decision: str,
        risk_score: float,
        response_time_ms: float = 0,
        user_agent: str = None,
        request_body: str = None
    ):
        """Log request to dashboard database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO dashboard_logs 
                (timestamp, request_id, method, path, ip_address, decision, 
                 risk_score, response_time_ms, user_agent, request_body)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                request_id,
                method,
                path,
                ip_address,
                decision,
                risk_score,
                response_time_ms,
                user_agent,
                request_body
            ))
            
            conn.commit()
            conn.close()
            logger.debug(f"Logged request {request_id} to database")
        except Exception as e:
            logger.error(f"Error logging request: {e}")
    
    def _get_mock_response(self, raw_http: str, request_id: str = None) -> Dict:
        """Generate mock response when WAF is unavailable"""
        return {
            "request_id": request_id or "mock_request",
            "timestamp": datetime.now().isoformat(),
            "decision": "ALLOW",
            "risk_score": 5.0,
            "confidence": 0.9,
            "reason": "Mock response (WAF engine unavailable)",
            "contributing_factors": ["WAF engine offline - defaulting to allow"],
            "signature_matches": [],
            "ml_prediction": {"attack_probability": 0.05},
            "anomaly_score": 0.0,
            "model_confidence": {"signature": 0, "ml": 5, "anomaly": 0}
        }


class Dashboard_WAFConnector:
    """
    Integrate with Flask dashboard
    Provides helper functions for dashboard routes
    """
    
    def __init__(self, dashboard_app, waf_url: str = "http://localhost:5000"):
        """Initialize connector"""
        self.app = dashboard_app
        self.bridge = WAFIntegrationBridge(waf_url)
        self.logger = logger
        
        # Register additional routes
        self._register_waf_routes()
    
    def _register_waf_routes(self):
        """Register WAF-specific routes on dashboard"""
        
        @self.app.route('/api/waf/health', methods=['GET'])
        def waf_health():
            """Check WAF engine health"""
            is_healthy = self.bridge.check_waf_health()
            return {
                'waf_healthy': is_healthy,
                'waf_url': self.bridge.waf_url,
                'status': '✅ ONLINE' if is_healthy else '❌ OFFLINE'
            }
        
        @self.app.route('/api/waf/test', methods=['POST'])
        def waf_test_request():
            """Test a request against WAF"""
            from flask import request
            
            data = request.get_json()
            raw_http = data.get('raw_http')
            
            if not raw_http:
                return {'error': 'Missing raw_http'}, 400
            
            # Send to WAF
            decision = self.bridge.send_check_request(raw_http, verbose=True)
            
            if decision:
                return {'success': True, 'decision': decision}
            else:
                return {'success': False, 'error': 'WAF engine unavailable'}, 503
        
        @self.app.route('/api/waf/stats', methods=['GET'])
        def waf_stats():
            """Get WAF engine stats"""
            stats = self.bridge.get_waf_stats()
            
            if stats:
                return {'success': True, 'data': stats}
            else:
                return {'success': False, 'error': 'Could not get WAF stats'}, 503
    
    def process_and_log_request(
        self,
        raw_http: str,
        ip_address: str,
        user_agent: str = None
    ) -> Optional[Dict]:
        """
        Process request through WAF and log to database
        
        Returns WAF decision
        """
        start_time = time.time()
        
        try:
            # Send to WAF
            decision = self.bridge.send_check_request(raw_http)
            
            if not decision:
                self.logger.error("No decision from WAF")
                return None
            
            # Extract request details
            lines = raw_http.split('\n')
            request_line = lines[0].split()
            method = request_line[0] if len(request_line) > 0 else 'UNKNOWN'
            path = request_line[1] if len(request_line) > 1 else '/'
            
            response_time_ms = (time.time() - start_time) * 1000
            
            # Log to database
            self.bridge.log_request_to_db(
                request_id=decision.get('request_id'),
                method=method,
                path=path,
                ip_address=ip_address,
                decision=decision.get('decision'),
                risk_score=decision.get('risk_score', 0),
                response_time_ms=response_time_ms,
                user_agent=user_agent,
                request_body=raw_http
            )
            
            return decision
            
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            return None


# Convenient helper function for integration
def create_bridge(waf_url: str = "http://localhost:5000") -> WAFIntegrationBridge:
    """Create and return a WAF integration bridge"""
    return WAFIntegrationBridge(waf_url)


# Example usage
if __name__ == "__main__":
    # Create bridge
    bridge = create_bridge()
    
    # Check WAF health
    print("\n" + "="*60)
    print("CHECKING WAF ENGINE HEALTH")
    print("="*60)
    
    if bridge.check_waf_health():
        print("✅ WAF engine is ONLINE and responding\n")
        
        # Test a request
        print("="*60)
        print("SENDING TEST REQUEST TO WAF")
        print("="*60)
        
        test_request = """GET /api/users?id=1' OR '1'='1 HTTP/1.1\r
Host: example.com\r
User-Agent: Mozilla/5.0\r
Content-Length: 0\r
\r
"""
        
        decision = bridge.send_check_request(test_request, verbose=True)
        
        if decision:
            print("\n" + json.dumps(decision, indent=2))
        else:
            print("❌ Failed to get decision from WAF")
    else:
        print("""
❌ WAF ENGINE NOT RESPONDING

SOLUTIONS:
===========

1. START WAF ENGINE:
   $ python main.py
   
2. CHECK IF RUNNING:
   $ curl http://localhost:5000/waf/health
   
3. VERIFY PORT 5000 IS FREE:
   $ lsof -i :5000
   
4. MANUAL WAF START:
   # Terminal 1 (WAF Engine)
   $ python -c "from src.waf_engine import WAFEngine; from src.http_handler import WAFHTTPHandler; engine = WAFEngine('models/gb_model_20260203_144133.pkl', 'models/scaler_20260203_144133.pkl', 'models/feature_names_20260203_144133.json'); handler = WAFHTTPHandler(engine); handler.run()"
   
   # Terminal 2 (Dashboard)
   $ python dashboard.py

5. CHECK LOGS:
   Look for error messages about missing model files
""")