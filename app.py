# app.py - Single unified Flask application for Phylax-2.0
# Combines: Website + Dashboard + WAF Integration
# Single Port: 5001

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import sqlite3
import json
import os
import logging
from datetime import datetime, timedelta
import requests
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WAFBridge:
    """Simple WAF Integration Bridge"""
    
    def __init__(self, waf_url="http://localhost:5000", db_path="dashboard.db"):
        self.waf_url = waf_url
        self.db_path = db_path
        self.session = requests.Session()
        self.session.timeout = 10
        logger.info(f"WAF Bridge initialized - WAF URL: {waf_url}")
    
    def is_healthy(self):
        """Check if WAF is online"""
        try:
            resp = self.session.get(f"{self.waf_url}/waf/health", timeout=5)
            return resp.status_code == 200
        except:
            return False
    
    def send_request(self, raw_http):
        """Send request to WAF for analysis"""
        if not self.is_healthy():
            return self._mock_response()
        
        try:
            resp = self.session.post(
                f"{self.waf_url}/waf/check",
                json={"raw_http": raw_http},
                timeout=10
            )
            if resp.status_code in [200, 403]:
                return resp.json()
        except Exception as e:
            logger.warning(f"WAF request failed: {e}")
        
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
            ''', (datetime.now().isoformat(), request_id, method, path, ip_addr, decision, risk_score, user_agent))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database error: {e}")
    
    def _mock_response(self):
        """Mock response when WAF offline"""
        return {
            "request_id": "mock_req",
            "timestamp": datetime.now().isoformat(),
            "decision": "ALLOW",
            "risk_score": 5.0,
            "confidence": 0.9,
            "reason": "Mock - WAF offline",
            "contributing_factors": ["WAF unavailable"],
            "signature_matches": [],
            "ml_prediction": {"attack_probability": 0.05},
            "anomaly_score": 0.0,
            "model_confidence": {"signature": 0, "ml": 5, "anomaly": 0}
        }

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'phylax-2026-secret-key'
CORS(app)

# Initialize WAF Bridge
waf = WAFBridge("http://localhost:5000", "dashboard.db")

# Initialize Database
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
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Database init error: {e}")

init_db()

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
        'status': 'healthy',
        'service': 'Phylax Dashboard',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/waf/health', methods=['GET'])
def waf_health():
    """Check WAF engine status"""
    is_healthy = waf.is_healthy()
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
        raw_http = data.get('raw_http', '')
        ip_address = data.get('ip_address', request.remote_addr)
        user_agent = data.get('user_agent', '')
        
        if not raw_http:
            return jsonify({'success': False, 'error': 'Missing raw_http'}), 400
        
        # Send to WAF
        decision = waf.send_request(raw_http)
        
        # Extract request details
        lines = raw_http.split('\n')
        request_line = lines[0].split() if lines else []
        method = request_line[0] if len(request_line) > 0 else 'GET'
        path = request_line[1] if len(request_line) > 1 else '/'
        
        # Log to database
        if decision:
            waf.log_request(
                decision.get('request_id', 'unknown'),
                method, path, ip_address,
                decision.get('decision', 'UNKNOWN'),
                decision.get('risk_score', 0),
                user_agent
            )
        
        return jsonify({
            'success': True,
            'decision': decision
        })
    except Exception as e:
        logger.error(f"WAF test error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/waf/stats', methods=['GET'])
def waf_stats():
    """Get WAF engine statistics"""
    try:
        if not waf.is_healthy():
            return jsonify({'success': False, 'error': 'WAF offline'}), 503
        
        resp = waf.session.get(f"{waf.waf_url}/waf/stats", timeout=5)
        if resp.status_code == 200:
            return jsonify({'success': True, 'data': resp.json()})
        else:
            return jsonify({'success': False, 'error': 'Could not get stats'}), 500
    except Exception as e:
        logger.error(f"WAF stats error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============== API: DASHBOARD STATISTICS ==============

def get_db():
    """Get database connection"""
    conn = sqlite3.connect('dashboard.db')
    conn.row_factory = sqlite3.Row
    return conn

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
        return jsonify({'success': False, 'error': str(e)}), 500

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
        return jsonify({'success': False, 'error': str(e)}), 500

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
        return jsonify({'success': False, 'error': str(e)}), 500

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
        return jsonify({'success': False, 'error': str(e)}), 500

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
        return jsonify({'success': False, 'error': str(e)}), 500

# ============== ERROR HANDLERS ==============

@app.errorhandler(404)
def not_found(error):
    """404 handler"""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(error):
    """500 handler"""
    logger.error(f"Server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# ============== MAIN ==============

if __name__ == '__main__':
    print("\n" + "="*80)
    print("🚀 STARTING PHYLAX-2.0 UNIFIED APPLICATION")
    print("="*80)
    print("\n✅ Database: dashboard.db")
    print("✅ WAF Bridge: http://localhost:5000")
    print("✅ Dashboard: http://localhost:5001")
    print("\n📊 Routes:")
    print("   GET  http://localhost:5001/                   → Dashboard")
    print("   GET  http://localhost:5001/api/health         → Health check")
    print("   GET  http://localhost:5001/api/waf/health     → WAF status")
    print("   POST http://localhost:5001/api/waf/test       → Test request")
    print("   GET  http://localhost:5001/api/stats/*        → Statistics")
    print("\n" + "="*80)
    print("\n🌐 Open: http://localhost:5001")
    print("💡 Press Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=5001, debug=False, use_reloader=False)