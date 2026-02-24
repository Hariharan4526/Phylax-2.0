"""
HTTP Handler - Flask Integration for Phylax WAF
Receives HTTP requests, processes them through WAF engine, and returns decisions
"""

import logging
import hmac
import time
from typing import Dict, Tuple
from datetime import datetime
import json
from functools import wraps

from flask import Flask, request, jsonify, Response
from werkzeug.exceptions import BadRequest


class WAFHTTPHandler:
    """
    Flask HTTP Handler for Phylax WAF
    
    Integrates with:
    - WAF Engine
    - Security Logging
    - Performance Monitoring
    - Statistics Tracking
    """
    
    def __init__(self, waf_engine, app: Flask = None):
        """
        Initialize HTTP Handler
        
        Args:
            waf_engine: WAFEngine instance
            app: Flask app instance (creates new if None)
        """
        self.waf_engine = waf_engine
        self.app = app or Flask(__name__)
        self.logger = self._setup_logger()
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'challenged_requests': 0,
            'allowed_requests': 0,
            'errors': 0
        }

        self._rate_limit_cache = {}
        
        self._setup_routes()
        self.logger.info("WAF HTTP Handler initialized")
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("WAFHTTPHandler")
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.before_request
        def log_request():
            """Log incoming request"""
            self.logger.debug(
                f"Incoming {request.method} {request.path} "
                f"from {request.remote_addr}"
            )
        
        @self.app.route('/waf/check', methods=['POST'])
        def check_request():
            """Check if request is malicious"""
            return self._handle_check_request()
        
        @self.app.route('/waf/stats', methods=['GET'])
        def get_stats():
            """Get WAF statistics"""
            if not self._is_admin_authorized():
                return jsonify({'error': 'Unauthorized'}), 401
            return self._handle_stats_request()
        
        @self.app.route('/waf/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'engine_stats': self.waf_engine.get_statistics()
            })
        
        @self.app.route('/waf/config', methods=['GET'])
        def get_config():
            """Get WAF configuration"""
            if not self._is_admin_authorized():
                return jsonify({'error': 'Unauthorized'}), 401
            return jsonify(self.waf_engine.config)
        
        @self.app.errorhandler(400)
        def bad_request(error):
            """Handle bad requests"""
            return jsonify({
                'error': 'Bad Request',
                'message': str(error)
            }), 400
        
        @self.app.errorhandler(500)
        def internal_error(error):
            """Handle internal errors"""
            self.logger.error(f"Internal error: {error}")
            self.stats['errors'] += 1
            return jsonify({
                'error': 'Internal Server Error',
                'message': 'An error occurred processing the request'
            }), 500
    
    def _handle_check_request(self) -> Tuple[Dict, int]:
        """
        Handle WAF check request
        
        Expected JSON:
        {
            "raw_http": "GET /path HTTP/1.1\nHost: example.com\n...",
            "request_id": "optional-id"
        }
        """
        try:
            rate_limit_error = self._enforce_rate_limit()
            if rate_limit_error is not None:
                return rate_limit_error

            # Get JSON from request
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            # Extract raw HTTP
            raw_http = data.get('raw_http')
            if not raw_http:
                return jsonify({'error': 'Missing raw_http field'}), 400
            
            # Optional request ID
            request_id = data.get('request_id')
            
            # Check payload size
            if len(raw_http) > self.waf_engine.config.get('max_payload_size', 10*1024*1024):
                self.logger.warning(f"Request exceeds max payload size")
                return jsonify({
                    'error': 'Payload too large',
                    'decision': 'BLOCK'
                }), 413
            
            # Process request through WAF
            waf_decision = self.waf_engine.process_request(raw_http, request_id)
            
            # Update statistics
            self._update_stats(waf_decision.decision)
            
            # Return decision
            response = {
                'request_id': waf_decision.request_id,
                'timestamp': waf_decision.timestamp,
                'decision': waf_decision.decision,
                'risk_score': waf_decision.risk_score,
                'confidence': waf_decision.confidence,
                'reason': waf_decision.reason,
                'contributing_factors': waf_decision.contributing_factors,
                'model_confidence': waf_decision.model_confidence
            }
            
            # Add detailed info for debugging (can be disabled in production)
            if request.args.get('verbose') == 'true':
                response['signature_matches'] = waf_decision.signature_matches
                response['ml_prediction'] = waf_decision.ml_prediction
                response['anomaly_score'] = waf_decision.anomaly_score
            
            # Return appropriate HTTP status
            status_code = 200 if waf_decision.decision == 'ALLOW' else 403
            
            return jsonify(response), status_code
            
        except BadRequest as e:
            self.logger.error(f"Bad request: {e}")
            self.stats['errors'] += 1
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
            self.stats['errors'] += 1
            return jsonify({'error': 'Internal server error'}), 500

    def _is_admin_authorized(self) -> bool:
        """Authorize access to admin endpoints using API key."""
        if not self.waf_engine.config.get('require_admin_api_key', False):
            return True

        configured_key = self.waf_engine.config.get('admin_api_key', '')
        if not configured_key:
            self.logger.error("Admin API key required but not configured")
            return False

        request_key = request.headers.get('X-API-Key', '')
        if not request_key:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.lower().startswith('bearer '):
                request_key = auth_header.split(' ', 1)[1].strip()

        return hmac.compare_digest(request_key, configured_key)

    def _enforce_rate_limit(self):
        """Apply basic in-memory IP rate limiting to request inspection endpoint."""
        max_requests = int(self.waf_engine.config.get('request_limit_per_minute', 120))
        window_seconds = int(self.waf_engine.config.get('rate_limit_window_seconds', 60))

        now = time.time()
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()
        bucket = self._rate_limit_cache.get(client_ip)

        if bucket is None or now - bucket['window_start'] >= window_seconds:
            self._rate_limit_cache[client_ip] = {
                'window_start': now,
                'count': 1
            }
            return None

        bucket['count'] += 1
        if bucket['count'] > max_requests:
            return jsonify({'error': 'Rate limit exceeded'}), 429

        return None
    
    def _handle_stats_request(self) -> Dict:
        """Handle statistics request"""
        return jsonify({
            'timestamp': datetime.utcnow().isoformat(),
            'statistics': self.stats,
            'block_rate': (
                self.stats['blocked_requests'] / self.stats['total_requests']
                if self.stats['total_requests'] > 0
                else 0
            ),
            'engine_stats': self.waf_engine.get_statistics()
        })
    
    def _update_stats(self, decision: str):
        """Update statistics based on decision"""
        self.stats['total_requests'] += 1
        
        if decision == 'BLOCK':
            self.stats['blocked_requests'] += 1
        elif decision == 'CHALLENGE':
            self.stats['challenged_requests'] += 1
        elif decision == 'ALLOW':
            self.stats['allowed_requests'] += 1
    
    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
        """Run Flask server"""
        self.logger.info(f"Starting WAF HTTP Handler on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug, threaded=True)


class WAFMiddleware:
    """
    ASGI/WSGI Middleware for WAF
    Can be used with Django, FastAPI, etc.
    """
    
    def __init__(self, app, waf_engine):
        """
        Initialize middleware
        
        Args:
            app: ASGI/WSGI application
            waf_engine: WAFEngine instance
        """
        self.app = app
        self.waf_engine = waf_engine
        self.logger = logging.getLogger("WAFMiddleware")
    
    def __call__(self, environ, start_response):
        """
        WSGI middleware call
        
        Args:
            environ: WSGI environ
            start_response: Response callback
        """
        # Reconstruct raw HTTP
        raw_http = self._reconstruct_http(environ)
        
        # Process through WAF
        waf_decision = self.waf_engine.process_request(raw_http)
        
        # Handle decision
        if waf_decision.decision == 'BLOCK':
            # Return 403 Forbidden
            response_body = json.dumps({
                'error': 'Forbidden',
                'message': waf_decision.reason
            }).encode('utf-8')
            
            start_response('403 Forbidden', [
                ('Content-Type', 'application/json'),
                ('Content-Length', str(len(response_body)))
            ])
            return [response_body]
        
        elif waf_decision.decision == 'CHALLENGE':
            # Add challenge header
            environ['HTTP_WAF_CHALLENGE'] = waf_decision.request_id
        
        # Allow request to proceed
        return self.app(environ, start_response)
    
    def _reconstruct_http(self, environ: Dict) -> str:
        """Reconstruct raw HTTP from WSGI environ"""
        method = environ.get('REQUEST_METHOD', 'GET')
        path = environ.get('PATH_INFO', '/')
        query_string = environ.get('QUERY_STRING', '')
        
        if query_string:
            path += f"?{query_string}"
        
        # Build request line
        http_version = environ.get('SERVER_PROTOCOL', 'HTTP/1.1')
        request_line = f"{method} {path} {http_version}\n"
        
        # Build headers
        headers = []
        for key, value in environ.items():
            if key.startswith('HTTP_'):
                header_name = key[5:].replace('_', '-').title()
                headers.append(f"{header_name}: {value}\n")
        
        # Build body
        body = ""
        try:
            content_length = int(environ.get('CONTENT_LENGTH', 0))
            if content_length > 0:
                body = environ['wsgi.input'].read(content_length).decode('utf-8')
        except:
            pass
        
        return request_line + ''.join(headers) + '\n' + body


# Example usage
if __name__ == "__main__":
    from waf_engine import WAFEngine
    
    # Initialize WAF Engine
    engine = WAFEngine()
    
    # Initialize HTTP Handler
    handler = WAFHTTPHandler(engine)
    
    # Run server
    handler.run(host='0.0.0.0', port=5000, debug=True)