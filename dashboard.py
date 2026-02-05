"""
Phylax WAF Dashboard Backend
Provides API endpoints for the web dashboard
Runs on separate port (5001) from WAF engine (5000)
"""

import json
import logging
from typing import Dict, List
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import sqlite3
from pathlib import Path
import threading

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import requests


@dataclass
class RequestLog:
    """Log entry for a request"""
    timestamp: str
    request_id: str
    decision: str
    risk_score: float
    method: str
    path: str
    host: str
    payload: str
    contributing_factors: List[str]
    
    def to_dict(self):
        return asdict(self)


class DashboardDB:
    """SQLite database for dashboard"""
    
    def __init__(self, db_path: str = "dashboard.db"):
        """Initialize database"""
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Create tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Request logs table
        c.execute('''
            CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                request_id TEXT UNIQUE,
                decision TEXT,
                risk_score REAL,
                method TEXT,
                path TEXT,
                host TEXT,
                payload TEXT,
                factors TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Statistics table
        c.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                total_requests INTEGER,
                blocked_requests INTEGER,
                challenged_requests INTEGER,
                allowed_requests INTEGER,
                avg_risk_score REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Alerts table
        c.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                severity TEXT,
                message TEXT,
                request_id TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_log(self, log: RequestLog):
        """Add request log"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                INSERT INTO request_logs 
                (timestamp, request_id, decision, risk_score, method, path, host, payload, factors)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log.timestamp,
                log.request_id,
                log.decision,
                log.risk_score,
                log.method,
                log.path,
                log.host,
                log.payload[:500],  # Limit payload size
                json.dumps(log.contributing_factors)
            ))
            
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            # Request already logged
            pass
        except Exception as e:
            logging.error(f"Error adding log: {e}")
    
    def get_logs(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get recent logs"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            SELECT timestamp, request_id, decision, risk_score, method, path, host, payload, factors
            FROM request_logs
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        logs = []
        for row in c.fetchall():
            logs.append({
                'timestamp': row[0],
                'request_id': row[1],
                'decision': row[2],
                'risk_score': row[3],
                'method': row[4],
                'path': row[5],
                'host': row[6],
                'payload': row[7],
                'factors': json.loads(row[8]) if row[8] else []
            })
        
        conn.close()
        return logs
    
    def get_statistics(self) -> Dict:
        """Get current statistics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Get counts
        c.execute('SELECT COUNT(*) FROM request_logs')
        total = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM request_logs WHERE decision = ?', ('BLOCK',))
        blocked = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM request_logs WHERE decision = ?', ('CHALLENGE',))
        challenged = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM request_logs WHERE decision = ?', ('ALLOW',))
        allowed = c.fetchone()[0]
        
        c.execute('SELECT AVG(risk_score) FROM request_logs')
        avg_risk = c.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_requests': total,
            'blocked_requests': blocked,
            'challenged_requests': challenged,
            'allowed_requests': allowed,
            'avg_risk_score': avg_risk,
            'block_rate': (blocked / total * 100) if total > 0 else 0
        }
    
    def get_hourly_stats(self, hours: int = 24) -> List[Dict]:
        """Get statistics by hour"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        stats = []
        for i in range(hours):
            hour_ago = (datetime.utcnow() - timedelta(hours=i)).strftime('%Y-%m-%d %H:00')
            hour_after = (datetime.utcnow() - timedelta(hours=i-1)).strftime('%Y-%m-%d %H:00')
            
            c.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN decision = 'CHALLENGE' THEN 1 ELSE 0 END) as challenged,
                    SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed
                FROM request_logs
                WHERE timestamp BETWEEN ? AND ?
            ''', (hour_ago, hour_after))
            
            row = c.fetchone()
            stats.append({
                'hour': hour_ago,
                'total': row[0] or 0,
                'blocked': row[1] or 0,
                'challenged': row[2] or 0,
                'allowed': row[3] or 0
            })
        
        conn.close()
        return list(reversed(stats))


class DashboardApp:
    """Dashboard Flask application"""
    
    def __init__(self, waf_url: str = "http://localhost:5000", port: int = 5001):
        """Initialize dashboard"""
        self.waf_url = waf_url
        self.port = port
        self.app = Flask(__name__)
        CORS(self.app)
        
        # Database
        self.db = DashboardDB()
        
        # Logger
        self.logger = self._setup_logger()
        
        # Setup routes
        self._setup_routes()
        
        self.logger.info(f"Dashboard initialized on port {port}")
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("Dashboard")
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
        
        # ============================================================
        # WEB PAGES
        # ============================================================
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return self._render_dashboard()
        
        @self.app.route('/dashboard')
        def dashboard():
            """Dashboard page"""
            return self._render_dashboard()
        
        @self.app.route('/test')
        def test_page():
            """Request testing page"""
            return self._render_test_page()
        
        @self.app.route('/logs')
        def logs_page():
            """Request logs page"""
            return self._render_logs_page()
        
        # ============================================================
        # API ENDPOINTS
        # ============================================================
        
        @self.app.route('/api/stats')
        def get_stats():
            """Get statistics"""
            stats = self.db.get_statistics()
            
            # Try to get live stats from WAF
            try:
                response = requests.get(f"{self.waf_url}/waf/stats", timeout=2)
                live_stats = response.json().get('statistics', {})
                stats.update(live_stats)
            except:
                pass
            
            return jsonify(stats)
        
        @self.app.route('/api/logs')
        def get_logs():
            """Get request logs"""
            limit = request.args.get('limit', 100, type=int)
            offset = request.args.get('offset', 0, type=int)
            
            logs = self.db.get_logs(limit, offset)
            return jsonify({'logs': logs, 'total': self.db.get_statistics()['total_requests']})
        
        @self.app.route('/api/hourly-stats')
        def get_hourly():
            """Get hourly statistics"""
            hours = request.args.get('hours', 24, type=int)
            stats = self.db.get_hourly_stats(hours)
            return jsonify({'stats': stats})
        
        @self.app.route('/api/test', methods=['POST'])
        def test_request():
            """Test a request through WAF"""
            data = request.get_json()
            raw_http = data.get('raw_http', '')
            
            try:
                # Send to WAF
                response = requests.post(
                    f"{self.waf_url}/waf/check",
                    json={'raw_http': raw_http},
                    timeout=5
                )
                
                result = response.json()
                
                # Log the request
                log = RequestLog(
                    timestamp=datetime.utcnow().isoformat(),
                    request_id=result.get('request_id', 'unknown'),
                    decision=result.get('decision', 'UNKNOWN'),
                    risk_score=result.get('risk_score', 0),
                    method=self._extract_method(raw_http),
                    path=self._extract_path(raw_http),
                    host=self._extract_host(raw_http),
                    payload=raw_http[:500],
                    contributing_factors=result.get('contributing_factors', [])
                )
                
                self.db.add_log(log)
                
                return jsonify(result)
            
            except Exception as e:
                self.logger.error(f"Error testing request: {e}")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/health')
        def health():
            """Health check"""
            try:
                response = requests.get(f"{self.waf_url}/waf/health", timeout=2)
                return jsonify({
                    'status': 'healthy' if response.status_code == 200 else 'unhealthy',
                    'waf_url': self.waf_url
                })
            except:
                return jsonify({'status': 'unhealthy', 'waf_url': self.waf_url})
        
        @self.app.route('/api/config')
        def get_config():
            """Get WAF configuration"""
            try:
                response = requests.get(f"{self.waf_url}/waf/config", timeout=2)
                return jsonify(response.json())
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    
    def _extract_method(self, raw_http: str) -> str:
        """Extract HTTP method"""
        try:
            return raw_http.split()[0]
        except:
            return "UNKNOWN"
    
    def _extract_path(self, raw_http: str) -> str:
        """Extract path"""
        try:
            return raw_http.split()[1]
        except:
            return "/"
    
    def _extract_host(self, raw_http: str) -> str:
        """Extract host"""
        try:
            for line in raw_http.split('\n'):
                if 'Host:' in line:
                    return line.split('Host:')[1].strip()
        except:
            pass
        return "unknown"
    
    def _render_dashboard(self) -> str:
        """Render main dashboard page"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phylax WAF Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        h1 {
            color: #667eea;
            font-size: 28px;
        }
        
        .status {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        
        .status-badge {
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 14px;
        }
        
        .status-healthy {
            background: #d4edda;
            color: #155724;
        }
        
        .status-unhealthy {
            background: #f8d7da;
            color: #721c24;
        }
        
        nav {
            display: flex;
            gap: 10px;
        }
        
        nav a {
            padding: 8px 16px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        
        nav a:hover {
            background: #764ba2;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .card-title {
            font-size: 14px;
            color: #666;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .card-value {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }
        
        .card-subtext {
            font-size: 12px;
            color: #999;
            margin-top: 5px;
        }
        
        .card.danger .card-value {
            color: #e74c3c;
        }
        
        .card.warning .card-value {
            color: #f39c12;
        }
        
        .card.success .card-value {
            color: #27ae60;
        }
        
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            position: relative;
            height: 400px;
        }
        
        .chart-title {
            font-size: 18px;
            font-weight: bold;
            color: #333;
            margin-bottom: 15px;
        }
        
        button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: background 0.3s;
        }
        
        button:hover {
            background: #764ba2;
        }
        
        .refresh-btn {
            padding: 8px 16px;
            font-size: 12px;
        }
        
        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
            
            h1 {
                font-size: 20px;
            }
            
            nav {
                flex-wrap: wrap;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Phylax WAF Dashboard</h1>
            <div class="status">
                <span class="status-badge status-healthy" id="status">● Healthy</span>
                <button class="refresh-btn" onclick="location.reload()">Refresh</button>
            </div>
        </header>
        
        <nav>
            <a href="/">Dashboard</a>
            <a href="/test">Test Request</a>
            <a href="/logs">Request Logs</a>
        </nav>
        
        <div class="grid">
            <div class="card">
                <div class="card-title">Total Requests</div>
                <div class="card-value" id="total-requests">0</div>
                <div class="card-subtext">Since start</div>
            </div>
            
            <div class="card danger">
                <div class="card-title">Blocked</div>
                <div class="card-value" id="blocked-requests">0</div>
                <div class="card-subtext">Attack prevented</div>
            </div>
            
            <div class="card warning">
                <div class="card-title">Challenged</div>
                <div class="card-value" id="challenged-requests">0</div>
                <div class="card-subtext">Requires verification</div>
            </div>
            
            <div class="card success">
                <div class="card-title">Allowed</div>
                <div class="card-value" id="allowed-requests">0</div>
                <div class="card-subtext">Safe requests</div>
            </div>
        </div>
        
        <div class="chart-container">
            <div class="chart-title">Requests Over Time</div>
            <canvas id="statsChart"></canvas>
        </div>
    </div>
    
    <script>
        let statsChart = null;
        
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                document.getElementById('total-requests').textContent = data.total_requests || 0;
                document.getElementById('blocked-requests').textContent = data.blocked_requests || 0;
                document.getElementById('challenged-requests').textContent = data.challenged_requests || 0;
                document.getElementById('allowed-requests').textContent = data.allowed_requests || 0;
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }
        
        async function loadChart() {
            try {
                const response = await fetch('/api/hourly-stats?hours=24');
                const data = await response.json();
                const stats = data.stats;
                
                const labels = stats.map(s => new Date(s.hour).toLocaleTimeString());
                const allowedData = stats.map(s => s.allowed);
                const challengedData = stats.map(s => s.challenged);
                const blockedData = stats.map(s => s.blocked);
                
                const ctx = document.getElementById('statsChart').getContext('2d');
                
                if (statsChart) {
                    statsChart.destroy();
                }
                
                statsChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [
                            {
                                label: 'Allowed',
                                data: allowedData,
                                borderColor: '#27ae60',
                                backgroundColor: 'rgba(39, 174, 96, 0.1)',
                                tension: 0.3
                            },
                            {
                                label: 'Challenged',
                                data: challengedData,
                                borderColor: '#f39c12',
                                backgroundColor: 'rgba(243, 156, 18, 0.1)',
                                tension: 0.3
                            },
                            {
                                label: 'Blocked',
                                data: blockedData,
                                borderColor: '#e74c3c',
                                backgroundColor: 'rgba(231, 76, 60, 0.1)',
                                tension: 0.3
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'top'
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Error loading chart:', error);
            }
        }
        
        async function checkHealth() {
            try {
                const response = await fetch('/api/health');
                const data = await response.json();
                const badge = document.getElementById('status');
                
                if (data.status === 'healthy') {
                    badge.textContent = '● Healthy';
                    badge.className = 'status-badge status-healthy';
                } else {
                    badge.textContent = '● Unhealthy';
                    badge.className = 'status-badge status-unhealthy';
                }
            } catch (error) {
                console.error('Error checking health:', error);
            }
        }
        
        // Load data on page load
        window.addEventListener('load', () => {
            loadStats();
            loadChart();
            checkHealth();
            
            // Refresh every 30 seconds
            setInterval(() => {
                loadStats();
                loadChart();
                checkHealth();
            }, 30000);
        });
    </script>
</body>
</html>
        '''
    
    def _render_test_page(self) -> str:
        """Render request testing page"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Request - Phylax WAF</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        
        header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #667eea;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        nav {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
        
        nav a {
            padding: 8px 16px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        
        nav a:hover {
            background: #764ba2;
        }
        
        .main {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            font-weight: bold;
            color: #333;
            margin-bottom: 8px;
        }
        
        textarea {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            resize: vertical;
            min-height: 200px;
        }
        
        button {
            padding: 12px 30px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.3s;
        }
        
        button:hover {
            background: #764ba2;
        }
        
        .result {
            margin-top: 30px;
            padding: 20px;
            border-radius: 5px;
            display: none;
        }
        
        .result.show {
            display: block;
        }
        
        .result.allow {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        
        .result.challenge {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
        }
        
        .result.block {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        
        .result h3 {
            margin-bottom: 10px;
        }
        
        .result-details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-top: 15px;
            font-size: 14px;
        }
        
        .detail-item {
            display: flex;
            justify-content: space-between;
        }
        
        .detail-label {
            font-weight: bold;
            color: #333;
        }
        
        .detail-value {
            text-align: right;
        }
        
        .loading {
            display: none;
            text-align: center;
            color: #667eea;
            margin-top: 20px;
        }
        
        .spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .templates {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .templates h3 {
            font-size: 14px;
            margin-bottom: 10px;
            color: #333;
        }
        
        .template-btn {
            padding: 6px 12px;
            margin-right: 5px;
            margin-bottom: 5px;
            background: white;
            color: #667eea;
            border: 1px solid #667eea;
            font-size: 12px;
            cursor: pointer;
            border-radius: 3px;
            transition: all 0.3s;
        }
        
        .template-btn:hover {
            background: #667eea;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🧪 Test Request</h1>
            <nav>
                <a href="/">Dashboard</a>
                <a href="/test">Test Request</a>
                <a href="/logs">Request Logs</a>
            </nav>
        </header>
        
        <div class="main">
            <div class="form-group">
                <label>Request Templates:</label>
                <div class="templates">
                    <button class="template-btn" onclick="loadTemplate('clean')">Clean Request</button>
                    <button class="template-btn" onclick="loadTemplate('sqli')">SQL Injection</button>
                    <button class="template-btn" onclick="loadTemplate('xss')">XSS Attack</button>
                    <button class="template-btn" onclick="loadTemplate('cmd')">Command Injection</button>
                </div>
            </div>
            
            <form onsubmit="testRequest(event)">
                <div class="form-group">
                    <label>Raw HTTP Request:</label>
                    <textarea id="request-input" placeholder="Enter raw HTTP request here..."></textarea>
                </div>
                
                <button type="submit">Test Request</button>
            </form>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Processing request...</p>
            </div>
            
            <div class="result" id="result"></div>
        </div>
    </div>
    
    <script>
        const templates = {
            clean: 'GET /index.html HTTP/1.1\\r\\nHost: example.com\\r\\nUser-Agent: Mozilla/5.0\\r\\n\\r\\n',
            sqli: 'GET /api/users?id=1\\' OR \\'1\\'=\\'1 HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n',
            xss: 'GET /search?q=<script>alert(\\'XSS\\')</script> HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n',
            cmd: 'POST /cmd HTTP/1.1\\r\\nHost: example.com\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nContent-Length: 20\\r\\n\\r\\ninput=test;whoami'
        };
        
        function loadTemplate(name) {
            const textarea = document.getElementById('request-input');
            const template = templates[name];
            if (template) {
                textarea.value = template;
            }
        }
        
        async function testRequest(event) {
            event.preventDefault();
            
            const rawHttp = document.getElementById('request-input').value;
            if (!rawHttp.trim()) {
                alert('Please enter a request');
                return;
            }
            
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            
            loading.style.display = 'block';
            result.classList.remove('show');
            
            try {
                const response = await fetch('/api/test', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ raw_http: rawHttp })
                });
                
                const data = await response.json();
                
                loading.style.display = 'none';
                
                // Display result
                const decision = data.decision.toLowerCase();
                result.className = `result show ${decision}`;
                
                result.innerHTML = `
                    <h3>Decision: ${data.decision}</h3>
                    <p>${data.reason}</p>
                    <div class="result-details">
                        <div class="detail-item">
                            <span class="detail-label">Risk Score:</span>
                            <span class="detail-value">${data.risk_score?.toFixed(1) || 'N/A'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Confidence:</span>
                            <span class="detail-value">${(data.confidence * 100)?.toFixed(1) || 'N/A'}%</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Request ID:</span>
                            <span class="detail-value">${data.request_id || 'N/A'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Timestamp:</span>
                            <span class="detail-value">${data.timestamp || new Date().toISOString()}</span>
                        </div>
                    </div>
                    ${data.contributing_factors && data.contributing_factors.length > 0 ? `
                        <div style="margin-top: 15px;">
                            <strong>Contributing Factors:</strong>
                            <ul style="margin-top: 8px; margin-left: 20px;">
                                ${data.contributing_factors.map(f => `<li>${f}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                `;
            } catch (error) {
                loading.style.display = 'none';
                result.className = 'result show block';
                result.innerHTML = `<h3>Error</h3><p>${error.message}</p>`;
            }
        }
    </script>
</body>
</html>
        '''
    
    def _render_logs_page(self) -> str:
        """Render request logs page"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Logs - Phylax WAF</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #667eea;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        nav {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
        
        nav a {
            padding: 8px 16px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        
        nav a:hover {
            background: #764ba2;
        }
        
        .main {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        thead {
            background: #f5f5f5;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            font-weight: bold;
            color: #333;
        }
        
        tr:hover {
            background: #f9f9f9;
        }
        
        .badge {
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .badge-allow {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-challenge {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge-block {
            background: #f8d7da;
            color: #721c24;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #667eea;
        }
        
        .pagination {
            display: flex;
            gap: 5px;
            margin-top: 20px;
            justify-content: center;
        }
        
        .pagination button {
            padding: 8px 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        
        .pagination button:hover {
            background: #764ba2;
        }
        
        .pagination button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        
        .no-data {
            text-align: center;
            padding: 40px;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📋 Request Logs</h1>
            <nav>
                <a href="/">Dashboard</a>
                <a href="/test">Test Request</a>
                <a href="/logs">Request Logs</a>
            </nav>
        </header>
        
        <div class="main">
            <h2 style="color: #333; margin-bottom: 10px;">Recent Requests</h2>
            <p style="color: #666; font-size: 14px;">Showing last 100 requests</p>
            
            <div id="loading" class="loading">
                <div style="display: inline-block; width: 20px; height: 20px; border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                <p>Loading logs...</p>
            </div>
            
            <div id="table-container" style="display: none;">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Method</th>
                            <th>Path</th>
                            <th>Host</th>
                            <th>Decision</th>
                            <th>Risk Score</th>
                            <th>Request ID</th>
                        </tr>
                    </thead>
                    <tbody id="logs-table">
                    </tbody>
                </table>
                
                <div class="pagination">
                    <button onclick="previousPage()" id="prev-btn">← Previous</button>
                    <span id="page-info" style="padding: 8px 12px; color: #333;"></span>
                    <button onclick="nextPage()" id="next-btn">Next →</button>
                </div>
            </div>
            
            <div id="no-data" class="no-data" style="display: none;">
                No request logs yet.
            </div>
        </div>
    </div>
    
    <script>
        let currentPage = 0;
        const pageSize = 100;
        let totalLogs = 0;
        
        async function loadLogs() {
            try {
                const offset = currentPage * pageSize;
                const response = await fetch(`/api/logs?limit=${pageSize}&offset=${offset}`);
                const data = await response.json();
                
                totalLogs = data.total;
                const logs = data.logs;
                
                const loading = document.getElementById('loading');
                const tableContainer = document.getElementById('table-container');
                const noData = document.getElementById('no-data');
                const table = document.getElementById('logs-table');
                
                if (logs.length === 0) {
                    loading.style.display = 'none';
                    noData.style.display = 'block';
                    tableContainer.style.display = 'none';
                } else {
                    loading.style.display = 'none';
                    noData.style.display = 'none';
                    tableContainer.style.display = 'block';
                    
                    table.innerHTML = logs.map(log => `
                        <tr>
                            <td>${new Date(log.timestamp).toLocaleString()}</td>
                            <td>${log.method || '-'}</td>
                            <td>${log.path || '-'}</td>
                            <td>${log.host || '-'}</td>
                            <td>
                                <span class="badge badge-${log.decision.toLowerCase()}">
                                    ${log.decision}
                                </span>
                            </td>
                            <td>${log.risk_score.toFixed(1)}</td>
                            <td style="font-size: 12px; font-family: monospace;">${log.request_id}</td>
                        </tr>
                    `).join('');
                    
                    // Update pagination
                    const totalPages = Math.ceil(totalLogs / pageSize);
                    document.getElementById('page-info').textContent = `Page ${currentPage + 1} of ${totalPages}`;
                    document.getElementById('prev-btn').disabled = currentPage === 0;
                    document.getElementById('next-btn').disabled = currentPage >= totalPages - 1;
                }
            } catch (error) {
                console.error('Error loading logs:', error);
                document.getElementById('loading').textContent = 'Error loading logs';
            }
        }
        
        function previousPage() {
            if (currentPage > 0) {
                currentPage--;
                loadLogs();
            }
        }
        
        function nextPage() {
            const totalPages = Math.ceil(totalLogs / pageSize);
            if (currentPage < totalPages - 1) {
                currentPage++;
                loadLogs();
            }
        }
        
        window.addEventListener('load', loadLogs);
    </script>
    
    <style>
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</body>
</html>
        '''
    
    def run(self, host: str = '0.0.0.0', port: int = None, debug: bool = False):
        """Run dashboard"""
        if port is None:
            port = self.port
        
        self.logger.info(f"🚀 Starting Phylax Dashboard on http://0.0.0.0:{port}")
        self.app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    app = DashboardApp(waf_url="http://localhost:5000", port=5001)
    app.run(port=5001, debug=True)