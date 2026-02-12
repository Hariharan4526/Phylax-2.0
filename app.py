# app.py - Fixed Production-Ready Flask Application
# Single unified app for Website + Dashboard + WAF Integration on port 5001

from flask import Flask, render_template, jsonify, request, Response
from flask_cors import CORS
import sqlite3
import json
import logging
from datetime import datetime, timedelta
import requests
import time
from functools import wraps

# Import configuration
from config import config, logger

# ============== CONFIGURATION ==============

app = Flask(__name__)
app.config.update(config.__dict__)
CORS(app)

# ============== SIMPLE WAF BRIDGE ==============

class WAFBridge:
    """Simple, production-grade WAF Integration Bridge"""
    
    def __init__(self, waf_url, db_path, timeout=10, retries=3, retry_delay=0.5):
        self.waf_url = waf_url
        self.db_path = db_path
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"WAF Bridge initialized - URL: {waf_url}")
    
    def is_healthy(self):
        """Check if WAF engine is online"""
        try:
            resp = self.session.get(f"{self.waf_url}/waf/health", timeout=5)
            return resp.status_code == 200
        except Exception as e:
            self.logger.warning(f"WAF health check failed: {e}")
            return False
    
    def send_request(self, raw_http):
        """Send request to WAF for analysis"""
        if not self.is_healthy():
            self.logger.warning("WAF offline, returning mock response")
            return self._mock_response()
        
        try:
            resp = self.session.post(
                f"{self.waf_url}/waf/check",
                json={"raw_http": raw_http},
                timeout=self.timeout
            )
            if resp.status_code in [200, 403]:
                return resp.json()
        except requests.exceptions.Timeout:
            self.logger.error("WAF request timeout")
        except Exception as e:
            self.logger.error(f"WAF request error: {e}")
        
        return self._mock_response()
    
    def log_request(self, request_id, method, path, ip_addr, decision, risk_score, user_agent=None):
        """Log request to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO dashboard_logs 
                (timestamp, request_id, method, path, ip_address, decision, risk_score, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(), request_id, method, path, 
                ip_addr, decision, risk_score, user_agent
            ))
            conn.commit()
            conn.close()
            self.logger.debug(f"Logged request {request_id}")
        except Exception as e:
            self.logger.error(f"Database logging error: {e}")
    
    def _mock_response(self):
        """Mock response when WAF offline"""
        return {
            "request_id": "mock_req",
            "timestamp": datetime.now().isoformat(),
            "decision": "ALLOW",
            "risk_score": 5.0,
            "confidence": 0.9,
            "reason": "WAF offline - mock response",
            "contributing_factors": ["WAF unavailable"],
            "signature_matches": [],
            "ml_prediction": {"attack_probability": 0.05},
            "anomaly_score": 0.0,
            "model_confidence": {"signature": 0, "ml": 5, "anomaly": 0}
        }

# ============== DATABASE INITIALIZATION ==============

def init_db():
    """Initialize SQLite database"""
    try:
        conn = sqlite3.connect("dashboard.db")
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dashboard_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                request_id TEXT,
                method TEXT,
                path TEXT,
                ip_address TEXT,
                decision TEXT,
                risk_score REAL,
                user_agent TEXT
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON dashboard_logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_decision ON dashboard_logs(decision)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip ON dashboard_logs(ip_address)')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

init_db()

# Initialize WAF Bridge
waf = WAFBridge(config.WAF_URL, "dashboard.db", config.REQUEST_TIMEOUT, config.RETRIES, config.RETRY_DELAY)

# ============== ERROR HANDLERS ==============

def handle_error(status_code, message):
    """Generic error handler"""
    logger.error(f"Error {status_code}: {message}")
    return jsonify({
        'success': False,
        'error': message,
        'timestamp': datetime.now().isoformat()
    }), status_code

@app.errorhandler(404)
def not_found(error):
    """404 handler"""
    return handle_error(404, 'Endpoint not found')

@app.errorhandler(500)
def server_error(error):
    """500 handler"""
    return handle_error(500, 'Internal server error')

# ============== UTILITY FUNCTIONS ==============

def get_db():
    """Get database connection"""
    conn = sqlite3.connect('dashboard.db')
    conn.row_factory = sqlite3.Row
    return conn

def extract_http_details(raw_http):
    """Extract method and path from raw HTTP"""
    try:
        lines = raw_http.split('\n')
        if lines:
            parts = lines[0].split()
            method = parts[0] if len(parts) > 0 else 'GET'
            path = parts[1] if len(parts) > 1 else '/'
            return method, path
    except:
        pass
    return 'GET', '/'

# ============== WEB ROUTES ==============

@app.route('/')
def index():
    """Main page - serves the dashboard"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard route (alias)"""
    return render_template('index.html')

# ============== API: HEALTH & STATUS ==============

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'status': 'healthy',
        'service': 'Phylax Dashboard',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/waf/health', methods=['GET'])
def waf_health():
    """Check WAF engine status"""
    is_healthy = waf.is_healthy()
    logger.info(f"WAF health check: {'ONLINE' if is_healthy else 'OFFLINE'}")
    return jsonify({
        'success': True,
        'waf_healthy': is_healthy,
        'waf_url': waf.waf_url,
        'status': 'ONLINE' if is_healthy else 'OFFLINE',
        'timestamp': datetime.now().isoformat()
    })

# ============== API: WAF TESTING ==============

@app.route('/api/waf/test', methods=['POST'])
def waf_test():
    """Test a request against WAF"""
    try:
        data = request.get_json()
        if not data:
            return handle_error(400, 'No JSON data provided')
        
        raw_http = data.get('raw_http', '')
        ip_address = data.get('ip_address', request.remote_addr)
        user_agent = data.get('user_agent', request.headers.get('User-Agent', ''))
        
        if not raw_http:
            return handle_error(400, 'Missing raw_http field')
        
        # Send to WAF
        start_time = time.time()
        decision = waf.send_request(raw_http)
        response_time = (time.time() - start_time) * 1000
        
        # Extract request details
        method, path = extract_http_details(raw_http)
        
        # Log to database
        if decision:
            waf.log_request(
                decision.get('request_id', 'unknown'),
                method, path, ip_address,
                decision.get('decision', 'UNKNOWN'),
                decision.get('risk_score', 0),
                user_agent
            )
        
        logger.info(f"WAF test: {method} {path} -> {decision.get('decision')} (risk={decision.get('risk_score')})")
        
        return jsonify({
            'success': True,
            'decision': decision,
            'response_time_ms': round(response_time, 2)
        })
    except Exception as e:
        logger.error(f"WAF test error: {e}")
        return handle_error(500, str(e))

@app.route('/api/waf/stats', methods=['GET'])
def waf_stats():
    """Get WAF engine statistics"""
    try:
        if not waf.is_healthy():
            return handle_error(503, 'WAF engine offline')
        
        resp = waf.session.get(f"{waf.waf_url}/waf/stats", timeout=5)
        if resp.status_code == 200:
            return jsonify({'success': True, 'data': resp.json()})
        else:
            return handle_error(500, 'Could not get WAF statistics')
    except Exception as e:
        logger.error(f"WAF stats error: {e}")
        return handle_error(500, str(e))

# ============== API: DASHBOARD STATISTICS ==============

@app.route('/api/stats/overview', methods=['GET'])
def get_overview():
    """Get overview statistics"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        hours = request.args.get('hours', 24, type=int)
        cutoff = datetime.now() - timedelta(hours=hours)
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total_requests,
                SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END) as allowed,
                SUM(CASE WHEN decision='BLOCK' THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN decision='CHALLENGE' THEN 1 ELSE 0 END) as challenged,
                AVG(risk_score) as avg_risk,
                MAX(risk_score) as max_risk
            FROM dashboard_logs
            WHERE timestamp > ?
        ''', (cutoff.isoformat(),))
        
        result = cursor.fetchone()
        conn.close()
        
        total = result['total_requests'] or 0
        blocked = result['blocked'] or 0
        
        return jsonify({
            'success': True,
            'data': {
                'total_requests': total,
                'allowed_requests': result['allowed'] or 0,
                'blocked_requests': blocked,
                'challenged_requests': result['challenged'] or 0,
                'block_rate': (blocked / total * 100) if total > 0 else 0,
                'avg_risk_score': round(result['avg_risk'] or 0, 2),
                'max_risk_score': result['max_risk'] or 0
            }
        })
    except Exception as e:
        logger.error(f"Overview error: {e}")
        return handle_error(500, str(e))

@app.route('/api/stats/hourly', methods=['GET'])
def get_hourly():
    """Get hourly statistics"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        hours = request.args.get('hours', 24, type=int)
        cutoff = datetime.now() - timedelta(hours=hours)
        
        cursor.execute('''
            SELECT 
                strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                COUNT(*) as total,
                SUM(CASE WHEN decision='BLOCK' THEN 1 ELSE 0 END) as blocked,
                AVG(risk_score) as avg_risk
            FROM dashboard_logs
            WHERE timestamp > ?
            GROUP BY strftime('%Y-%m-%d %H:00:00', timestamp)
            ORDER BY hour DESC
            LIMIT ?
        ''', (cutoff.isoformat(), hours))
        
        results = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'data': [dict(row) for row in results]
        })
    except Exception as e:
        logger.error(f"Hourly error: {e}")
        return handle_error(500, str(e))

@app.route('/api/stats/top-ips', methods=['GET'])
def get_top_ips():
    """Get top attacking IPs"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        limit = request.args.get('limit', 10, type=int)
        days = request.args.get('days', 7, type=int)
        cutoff = datetime.now() - timedelta(days=days)
        
        cursor.execute('''
            SELECT 
                ip_address,
                COUNT(*) as total,
                SUM(CASE WHEN decision='BLOCK' THEN 1 ELSE 0 END) as blocked,
                AVG(risk_score) as avg_risk,
                MAX(risk_score) as max_risk
            FROM dashboard_logs
            WHERE timestamp > ? AND ip_address IS NOT NULL
            GROUP BY ip_address
            ORDER BY total DESC
            LIMIT ?
        ''', (cutoff.isoformat(), limit))
        
        results = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'data': [dict(row) for row in results]
        })
    except Exception as e:
        logger.error(f"Top IPs error: {e}")
        return handle_error(500, str(e))

@app.route('/api/stats/recent-requests', methods=['GET'])
def get_recent():
    """Get recent requests"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        limit = request.args.get('limit', 50, type=int)
        decision_filter = request.args.get('decision')
        
        if decision_filter:
            cursor.execute('''
                SELECT * FROM dashboard_logs
                WHERE decision = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (decision_filter, limit))
        else:
            cursor.execute('''
                SELECT * FROM dashboard_logs
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'data': [dict(row) for row in results]
        })
    except Exception as e:
        logger.error(f"Recent requests error: {e}")
        return handle_error(500, str(e))

@app.route('/api/stats/decision-distribution', methods=['GET'])
def get_distribution():
    """Get decision distribution"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        days = request.args.get('days', 7, type=int)
        cutoff = datetime.now() - timedelta(days=days)
        
        cursor.execute('''
            SELECT 
                decision,
                COUNT(*) as count,
                AVG(risk_score) as avg_risk
            FROM dashboard_logs
            WHERE timestamp > ?
            GROUP BY decision
        ''', (cutoff.isoformat(),))
        
        results = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'data': [dict(row) for row in results]
        })
    except Exception as e:
        logger.error(f"Distribution error: {e}")
        return handle_error(500, str(e))

# ============== REQUEST LOGGING MIDDLEWARE ==============

@app.before_request
def log_request():
    """Log incoming requests"""
    logger.debug(f"{request.method} {request.path} from {request.remote_addr}")

@app.after_request
def log_response(response):
    """Log response"""
    logger.debug(f"Response: {response.status_code} for {request.path}")
    return response

# ============== MAIN ==============

if __name__ == '__main__':
    logger.info("="*80)
    logger.info("🚀 STARTING PHYLAX-2.0 UNIFIED APPLICATION")
    logger.info("="*80)
    logger.info(f"✅ Database: dashboard.db")
    logger.info(f"✅ WAF Bridge: {config.WAF_URL}")
    logger.info(f"✅ Dashboard: http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")
    logger.info(f"✅ Debug Mode: {config.DEBUG}")
    logger.info("="*80)
    logger.info(f"\n🌐 Access at: http://localhost:{config.DASHBOARD_PORT}")
    logger.info("💡 Press Ctrl+C to stop\n")
    
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=config.DEBUG,
        use_reloader=False
    )