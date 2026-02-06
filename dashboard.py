"""
Phylax WAF - Enhanced Dashboard with Complete Features
Runs on port 5001
Provides:
- Real-time request monitoring
- Statistics & charts
- Request history with details
- Configuration management
- Attack detection logs
"""

import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import sqlite3
from pathlib import Path
import threading
import secrets
from functools import wraps

from flask import Flask, render_template_string, request, jsonify, session
from flask_cors import CORS
import requests


# ============================================================================
# DATA MODELS
# ============================================================================

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
    status_code: int = 200
    response_time_ms: float = 0.0


@dataclass
class AlertLog:
    """Alert entry for suspicious activity"""
    timestamp: str
    alert_type: str  # ATTACK, ANOMALY, PATTERN, THRESHOLD
    severity: str    # LOW, MEDIUM, HIGH, CRITICAL
    message: str
    request_id: str
    request_count: Optional[int] = None


# ============================================================================
# DATABASE LAYER
# ============================================================================

class DashboardDB:
    """SQLite database with enhanced schema"""
    
    def __init__(self, db_path: str = "dashboard.db"):
        """Initialize database"""
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_db()
    
    def init_db(self):
        """Create tables if they don't exist"""
        with self.lock:
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
                    status_code INTEGER DEFAULT 200,
                    response_time_ms REAL DEFAULT 0.0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_decision (decision),
                    INDEX idx_risk_score (risk_score)
                )
            ''')
            
            # Statistics table (hourly aggregates)
            c.execute('''
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT UNIQUE,
                    total_requests INTEGER,
                    blocked_requests INTEGER,
                    challenged_requests INTEGER,
                    allowed_requests INTEGER,
                    avg_risk_score REAL,
                    max_risk_score REAL,
                    attack_count INTEGER,
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
                    request_count INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_severity (severity),
                    INDEX idx_timestamp (timestamp)
                )
            ''')
            
            # Configuration table
            c.execute('''
                CREATE TABLE IF NOT EXISTS configuration (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE,
                    value TEXT,
                    data_type TEXT,
                    description TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Real-time metrics table (for websocket/streaming)
            c.execute('''
                CREATE TABLE IF NOT EXISTS realtime_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    requests_per_second REAL,
                    blocked_per_second REAL,
                    avg_risk_score REAL,
                    unique_hosts INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
    
    # ========================================================================
    # REQUEST LOGS
    # ========================================================================
    
    def add_log(self, log: RequestLog):
        """Add request log"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                
                c.execute('''
                    INSERT INTO request_logs 
                    (timestamp, request_id, decision, risk_score, method, path, host, payload, factors, status_code, response_time_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    log.timestamp,
                    log.request_id,
                    log.decision,
                    log.risk_score,
                    log.method,
                    log.path,
                    log.host,
                    log.payload[:1000],  # Limit payload size
                    json.dumps(log.contributing_factors),
                    log.status_code,
                    log.response_time_ms
                ))
                
                conn.commit()
                conn.close()
        except sqlite3.IntegrityError:
            pass  # Request already logged
        except Exception as e:
            logging.error(f"Error adding log: {e}")
    
    def get_logs(self, limit: int = 100, offset: int = 0, decision_filter: str = None) -> List[Dict]:
        """Get request logs with optional filtering"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            query = '''
                SELECT timestamp, request_id, decision, risk_score, method, path, host, payload, factors, status_code, response_time_ms
                FROM request_logs
            '''
            params = []
            
            if decision_filter and decision_filter in ['ALLOW', 'CHALLENGE', 'BLOCK']:
                query += ' WHERE decision = ?'
                params.append(decision_filter)
            
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            c.execute(query, params)
            
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
                    'factors': json.loads(row[8]) if row[8] else [],
                    'status_code': row[9],
                    'response_time_ms': row[10]
                })
            
            conn.close()
            return logs
    
    def get_log_detail(self, request_id: str) -> Optional[Dict]:
        """Get detailed information for a specific request"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                SELECT timestamp, request_id, decision, risk_score, method, path, host, payload, factors, status_code, response_time_ms
                FROM request_logs
                WHERE request_id = ?
            ''', (request_id,))
            
            row = c.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return {
                'timestamp': row[0],
                'request_id': row[1],
                'decision': row[2],
                'risk_score': row[3],
                'method': row[4],
                'path': row[5],
                'host': row[6],
                'payload': row[7],
                'factors': json.loads(row[8]) if row[8] else [],
                'status_code': row[9],
                'response_time_ms': row[10]
            }
    
    def get_total_logs_count(self, decision_filter: str = None) -> int:
        """Get total count of logs"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            if decision_filter and decision_filter in ['ALLOW', 'CHALLENGE', 'BLOCK']:
                c.execute('SELECT COUNT(*) FROM request_logs WHERE decision = ?', (decision_filter,))
            else:
                c.execute('SELECT COUNT(*) FROM request_logs')
            
            count = c.fetchone()[0]
            conn.close()
            return count
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def get_statistics(self) -> Dict:
        """Get current statistics"""
        with self.lock:
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
            
            c.execute('SELECT AVG(risk_score), MAX(risk_score), MIN(risk_score) FROM request_logs')
            avg_risk, max_risk, min_risk = c.fetchone()
            avg_risk = avg_risk or 0
            max_risk = max_risk or 0
            min_risk = min_risk or 0
            
            # Count unique hosts
            c.execute('SELECT COUNT(DISTINCT host) FROM request_logs')
            unique_hosts = c.fetchone()[0]
            
            conn.close()
            
            return {
                'total_requests': total,
                'blocked_requests': blocked,
                'challenged_requests': challenged,
                'allowed_requests': allowed,
                'avg_risk_score': float(avg_risk),
                'max_risk_score': float(max_risk),
                'min_risk_score': float(min_risk),
                'block_rate': (blocked / total * 100) if total > 0 else 0,
                'challenge_rate': (challenged / total * 100) if total > 0 else 0,
                'allow_rate': (allowed / total * 100) if total > 0 else 0,
                'unique_hosts': unique_hosts
            }
    
    def get_hourly_stats(self, hours: int = 24) -> List[Dict]:
        """Get statistics by hour"""
        with self.lock:
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
                        SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END) as allowed,
                        AVG(risk_score) as avg_risk
                    FROM request_logs
                    WHERE timestamp BETWEEN ? AND ?
                ''', (hour_ago, hour_after))
                
                row = c.fetchone()
                stats.append({
                    'hour': hour_ago,
                    'total': row[0] or 0,
                    'blocked': row[1] or 0,
                    'challenged': row[2] or 0,
                    'allowed': row[3] or 0,
                    'avg_risk_score': float(row[4]) if row[4] else 0
                })
            
            conn.close()
            return list(reversed(stats))
    
    def get_top_attacked_paths(self, limit: int = 10) -> List[Dict]:
        """Get most targeted paths"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                SELECT path, COUNT(*) as count, 
                       SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                       AVG(risk_score) as avg_risk
                FROM request_logs
                WHERE decision IN ('BLOCK', 'CHALLENGE')
                GROUP BY path
                ORDER BY count DESC
                LIMIT ?
            ''', (limit,))
            
            paths = []
            for row in c.fetchall():
                paths.append({
                    'path': row[0],
                    'count': row[1],
                    'blocked': row[2],
                    'avg_risk_score': float(row[3]) if row[3] else 0
                })
            
            conn.close()
            return paths
    
    def get_top_sources(self, limit: int = 10) -> List[Dict]:
        """Get top source hosts/IPs"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                SELECT host, COUNT(*) as count, 
                       SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                       AVG(risk_score) as avg_risk
                FROM request_logs
                GROUP BY host
                ORDER BY count DESC
                LIMIT ?
            ''', (limit,))
            
            hosts = []
            for row in c.fetchall():
                hosts.append({
                    'host': row[0],
                    'count': row[1],
                    'blocked': row[2],
                    'avg_risk_score': float(row[3]) if row[3] else 0
                })
            
            conn.close()
            return hosts
    
    # ========================================================================
    # ALERTS
    # ========================================================================
    
    def add_alert(self, alert: AlertLog):
        """Add alert"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                
                c.execute('''
                    INSERT INTO alerts (timestamp, alert_type, severity, message, request_id, request_count)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    alert.timestamp,
                    alert.alert_type,
                    alert.severity,
                    alert.message,
                    alert.request_id,
                    alert.request_count
                ))
                
                conn.commit()
                conn.close()
        except Exception as e:
            logging.error(f"Error adding alert: {e}")
    
    def get_alerts(self, limit: int = 50, offset: int = 0, severity: str = None) -> List[Dict]:
        """Get alerts with optional severity filter"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            query = 'SELECT timestamp, alert_type, severity, message, request_id, request_count FROM alerts'
            params = []
            
            if severity:
                query += ' WHERE severity = ?'
                params.append(severity)
            
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            c.execute(query, params)
            
            alerts = []
            for row in c.fetchall():
                alerts.append({
                    'timestamp': row[0],
                    'alert_type': row[1],
                    'severity': row[2],
                    'message': row[3],
                    'request_id': row[4],
                    'request_count': row[5]
                })
            
            conn.close()
            return alerts
    
    def get_critical_alerts(self, limit: int = 10) -> List[Dict]:
        """Get critical and high severity alerts"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            c.execute('''
                SELECT timestamp, alert_type, severity, message, request_id, request_count
                FROM alerts
                WHERE severity IN ('CRITICAL', 'HIGH')
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            alerts = []
            for row in c.fetchall():
                alerts.append({
                    'timestamp': row[0],
                    'alert_type': row[1],
                    'severity': row[2],
                    'message': row[3],
                    'request_id': row[4],
                    'request_count': row[5]
                })
            
            conn.close()
            return alerts
    
    # ========================================================================
    # CONFIGURATION
    # ========================================================================
    
    def save_config(self, key: str, value: str, data_type: str = 'string', description: str = ''):
        """Save configuration value"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                
                c.execute('''
                    INSERT OR REPLACE INTO configuration (key, value, data_type, description)
                    VALUES (?, ?, ?, ?)
                ''', (key, value, data_type, description))
                
                conn.commit()
                conn.close()
        except Exception as e:
            logging.error(f"Error saving config: {e}")
    
    def get_config(self, key: str = None) -> Dict:
        """Get configuration"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            if key:
                c.execute('SELECT value, data_type FROM configuration WHERE key = ?', (key,))
                row = c.fetchone()
                conn.close()
                if row:
                    return {'value': row[0], 'type': row[1]}
                return {}
            else:
                c.execute('SELECT key, value, data_type, description FROM configuration')
                config = {}
                for row in c.fetchall():
                    config[row[0]] = {
                        'value': row[1],
                        'type': row[2],
                        'description': row[3]
                    }
                conn.close()
                return config


# ============================================================================
# DASHBOARD APPLICATION
# ============================================================================

class EnhancedDashboardApp:
    """Enhanced dashboard with all requested features"""
    
    def __init__(self, waf_url: str = "http://localhost:5000", port: int = 5001):
        """Initialize dashboard"""
        self.waf_url = waf_url
        self.port = port
        self.app = Flask(__name__)
        self.app.secret_key = secrets.token_hex(16)
        CORS(self.app)
        
        # Database
        self.db = DashboardDB()
        
        # Logger
        self.logger = self._setup_logger()
        
        # In-memory cache for real-time metrics
        self.realtime_metrics = {
            'current_requests': [],
            'last_update': datetime.utcnow()
        }
        
        # Setup routes
        self._setup_routes()
        
        self.logger.info(f"Enhanced Dashboard initialized on port {port}")
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("EnhancedDashboard")
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
        
        # ====================================================================
        # WEB PAGES
        # ====================================================================
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return self._render_dashboard()
        
        @self.app.route('/dashboard')
        def dashboard():
            """Dashboard page"""
            return self._render_dashboard()
        
        @self.app.route('/real-time')
        def real_time():
            """Real-time monitoring page"""
            return self._render_realtime_page()
        
        @self.app.route('/requests')
        def requests_page():
            """Request history page"""
            return self._render_requests_page()
        
        @self.app.route('/request/<request_id>')
        def request_detail(request_id):
            """Request detail page"""
            return self._render_request_detail(request_id)
        
        @self.app.route('/attacks')
        def attacks_page():
            """Attack detection logs page"""
            return self._render_attacks_page()
        
        @self.app.route('/config')
        def config_page():
            """Configuration management page"""
            return self._render_config_page()
        
        @self.app.route('/test')
        def test_page():
            """Request testing page"""
            return self._render_test_page()
        
        # ====================================================================
        # REAL-TIME MONITORING APIs
        # ====================================================================
        
        @self.app.route('/api/realtime/stats')
        def realtime_stats():
            """Get real-time statistics"""
            stats = self.db.get_statistics()
            recent_logs = self.db.get_logs(limit=10)
            
            return jsonify({
                'stats': stats,
                'recent_requests': recent_logs,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        @self.app.route('/api/realtime/events')
        def realtime_events():
            """Get real-time events (for streaming/websocket)"""
            limit = request.args.get('limit', 5, type=int)
            recent = self.db.get_logs(limit=limit)
            return jsonify({'events': recent})
        
        # ====================================================================
        # STATISTICS APIs
        # ====================================================================
        
        @self.app.route('/api/stats')
        def get_stats():
            """Get overall statistics"""
            stats = self.db.get_statistics()
            return jsonify(stats)
        
        @self.app.route('/api/stats/hourly')
        def get_hourly_stats():
            """Get hourly statistics"""
            hours = request.args.get('hours', 24, type=int)
            stats = self.db.get_hourly_stats(hours)
            return jsonify({'stats': stats})
        
        @self.app.route('/api/stats/top-paths')
        def get_top_paths():
            """Get most targeted paths"""
            limit = request.args.get('limit', 10, type=int)
            paths = self.db.get_top_attacked_paths(limit)
            return jsonify({'paths': paths})
        
        @self.app.route('/api/stats/top-sources')
        def get_top_sources():
            """Get top source hosts"""
            limit = request.args.get('limit', 10, type=int)
            sources = self.db.get_top_sources(limit)
            return jsonify({'sources': sources})
        
        # ====================================================================
        # REQUEST HISTORY APIs
        # ====================================================================
        
        @self.app.route('/api/requests')
        def get_requests():
            """Get request logs"""
            limit = request.args.get('limit', 100, type=int)
            offset = request.args.get('offset', 0, type=int)
            decision_filter = request.args.get('decision', None)
            
            logs = self.db.get_logs(limit, offset, decision_filter)
            total = self.db.get_total_logs_count(decision_filter)
            
            return jsonify({
                'logs': logs,
                'total': total,
                'page': offset // limit if limit > 0 else 0,
                'per_page': limit
            })
        
        @self.app.route('/api/request/<request_id>')
        def get_request_detail(request_id):
            """Get request detail"""
            log = self.db.get_log_detail(request_id)
            if not log:
                return jsonify({'error': 'Request not found'}), 404
            return jsonify(log)
        
        # ====================================================================
        # ATTACK LOGS APIs
        # ====================================================================
        
        @self.app.route('/api/alerts')
        def get_alerts():
            """Get alerts/attack logs"""
            limit = request.args.get('limit', 50, type=int)
            offset = request.args.get('offset', 0, type=int)
            severity = request.args.get('severity', None)
            
            alerts = self.db.get_alerts(limit, offset, severity)
            
            return jsonify({
                'alerts': alerts,
                'total': len(alerts),
                'timestamp': datetime.utcnow().isoformat()
            })
        
        @self.app.route('/api/alerts/critical')
        def get_critical_alerts():
            """Get critical alerts"""
            alerts = self.db.get_critical_alerts(limit=20)
            return jsonify({'alerts': alerts})
        
        @self.app.route('/api/alert', methods=['POST'])
        def create_alert():
            """Create a new alert"""
            data = request.get_json()
            alert = AlertLog(
                timestamp=datetime.utcnow().isoformat(),
                alert_type=data.get('type', 'ATTACK'),
                severity=data.get('severity', 'MEDIUM'),
                message=data.get('message', ''),
                request_id=data.get('request_id', ''),
                request_count=data.get('request_count')
            )
            self.db.add_alert(alert)
            return jsonify({'status': 'created'}), 201
        
        # ====================================================================
        # CONFIGURATION APIs
        # ====================================================================
        
        @self.app.route('/api/config')
        def get_config():
            """Get all configuration"""
            config = self.db.get_config()
            return jsonify(config)
        
        @self.app.route('/api/config/<key>')
        def get_config_value(key):
            """Get specific config value"""
            value = self.db.get_config(key)
            if not value:
                return jsonify({'error': 'Config key not found'}), 404
            return jsonify(value)
        
        @self.app.route('/api/config', methods=['POST'])
        def save_config_value():
            """Save configuration"""
            data = request.get_json()
            self.db.save_config(
                key=data.get('key'),
                value=data.get('value'),
                data_type=data.get('type', 'string'),
                description=data.get('description', '')
            )
            return jsonify({'status': 'saved'}), 201
        
        # ====================================================================
        # TEST & UTILITY APIs
        # ====================================================================
        
        @self.app.route('/api/test', methods=['POST'])
        def test_request_endpoint():
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
                    payload=raw_http[:1000],
                    contributing_factors=result.get('contributing_factors', []),
                    status_code=200,
                    response_time_ms=response.elapsed.total_seconds() * 1000
                )
                
                self.db.add_log(log)
                
                # Check for alerts
                if result.get('decision') == 'BLOCK':
                    self._generate_alert_if_needed(result)
                
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
                    'dashboard': 'running',
                    'timestamp': datetime.utcnow().isoformat()
                })
            except:
                return jsonify({'status': 'unhealthy', 'dashboard': 'running'})
        
        @self.app.route('/api/export')
        def export_data():
            """Export data as JSON"""
            stats = self.db.get_statistics()
            hourly = self.db.get_hourly_stats(24)
            top_paths = self.db.get_top_attacked_paths(10)
            top_sources = self.db.get_top_sources(10)
            alerts = self.db.get_alerts(limit=100)
            
            return jsonify({
                'timestamp': datetime.utcnow().isoformat(),
                'statistics': stats,
                'hourly_stats': hourly,
                'top_paths': top_paths,
                'top_sources': top_sources,
                'recent_alerts': alerts
            })
    
    def _generate_alert_if_needed(self, waf_result: Dict):
        """Generate alert based on WAF decision"""
        if waf_result.get('risk_score', 0) > 80:
            alert = AlertLog(
                timestamp=datetime.utcnow().isoformat(),
                alert_type='ATTACK',
                severity='CRITICAL',
                message=f"High-risk attack detected: {waf_result.get('reason', 'Unknown')}",
                request_id=waf_result.get('request_id', ''),
                request_count=None
            )
            self.db.add_alert(alert)
    
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
    
    # ========================================================================
    # HTML TEMPLATES
    # ========================================================================
    
    def _render_dashboard(self) -> str:
        """Render main dashboard page"""
        return render_template_string(DASHBOARD_TEMPLATE)
    
    def _render_realtime_page(self) -> str:
        """Render real-time monitoring page"""
        return render_template_string(REALTIME_TEMPLATE)
    
    def _render_requests_page(self) -> str:
        """Render request history page"""
        return render_template_string(REQUESTS_TEMPLATE)
    
    def _render_request_detail(self, request_id: str) -> str:
        """Render request detail page"""
        template = REQUEST_DETAIL_TEMPLATE
        return render_template_string(template, request_id=request_id)
    
    def _render_attacks_page(self) -> str:
        """Render attack detection logs page"""
        return render_template_string(ATTACKS_TEMPLATE)
    
    def _render_config_page(self) -> str:
        """Render configuration management page"""
        return render_template_string(CONFIG_TEMPLATE)
    
    def _render_test_page(self) -> str:
        """Render request testing page"""
        return render_template_string(TEST_TEMPLATE)
    
    def run(self, host: str = '0.0.0.0', port: int = None, debug: bool = False):
        """Run dashboard"""
        if port is None:
            port = self.port
        
        self.logger.info(f"🚀 Starting Enhanced Dashboard on http://0.0.0.0:{port}")
        self.app.run(host=host, port=port, debug=debug, threaded=True)


# ============================================================================
# HTML TEMPLATES
# ============================================================================

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phylax WAF - Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
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
            max-width: 1600px;
            margin: 0 auto;
        }
        
        header {
            background: white;
            padding: 25px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        h1 {
            color: #667eea;
            font-size: 32px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .header-actions {
            display: flex;
            gap: 15px;
            align-items: center;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: #f0f0f0;
            border-radius: 20px;
            font-weight: bold;
        }
        
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        .status-healthy {
            background: #27ae60;
        }
        
        .status-unhealthy {
            background: #e74c3c;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        nav {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        nav a, nav button {
            padding: 10px 18px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 14px;
            font-weight: 500;
        }
        
        nav a:hover, nav button:hover {
            background: #764ba2;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.15);
        }
        
        .card-title {
            font-size: 13px;
            color: #999;
            margin-bottom: 10px;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        
        .card-value {
            font-size: 36px;
            font-weight: bold;
            color: #667eea;
            margin: 15px 0;
        }
        
        .card-subtext {
            font-size: 12px;
            color: #999;
            margin-top: 8px;
        }
        
        .card-progress {
            width: 100%;
            height: 8px;
            background: #f0f0f0;
            border-radius: 4px;
            margin-top: 10px;
            overflow: hidden;
        }
        
        .card-progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            width: 0%;
            transition: width 0.3s;
        }
        
        .card.danger {
            border-left: 4px solid #e74c3c;
        }
        
        .card.danger .card-value {
            color: #e74c3c;
        }
        
        .card.warning {
            border-left: 4px solid #f39c12;
        }
        
        .card.warning .card-value {
            color: #f39c12;
        }
        
        .card.success {
            border-left: 4px solid #27ae60;
        }
        
        .card.success .card-value {
            color: #27ae60;
        }
        
        .chart-container {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .chart-container h3 {
            font-size: 18px;
            color: #333;
            margin-bottom: 20px;
        }
        
        .chart-wrapper {
            position: relative;
            height: 400px;
            margin-bottom: 20px;
        }
        
        .chart-wrapper canvas {
            max-height: 400px;
        }
        
        .alert-box {
            background: #fff3cd;
            border-left: 4px solid #f39c12;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .alert-box.danger {
            background: #f8d7da;
            border-left-color: #e74c3c;
        }
        
        .alert-box.success {
            background: #d4edda;
            border-left-color: #27ae60;
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
        
        .refresh-indicator {
            font-size: 12px;
            color: #999;
        }
        
        .loading-spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid #f3f3f3;
            border-top: 2px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 8px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
            
            h1 {
                font-size: 24px;
            }
            
            header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .header-actions {
                width: 100%;
            }
            
            nav {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>
                <i class="fas fa-shield-alt"></i> Phylax WAF Dashboard
            </h1>
            <div class="header-actions">
                <div class="status-indicator">
                    <div class="status-dot status-healthy" id="status"></div>
                    <span id="status-text">Healthy</span>
                </div>
                <button onclick="location.reload()"><i class="fas fa-sync"></i> Refresh</button>
            </div>
        </header>
        
        <nav>
            <a href="/"><i class="fas fa-home"></i> Dashboard</a>
            <a href="/real-time"><i class="fas fa-tachometer-alt"></i> Real-Time</a>
            <a href="/requests"><i class="fas fa-history"></i> Requests</a>
            <a href="/attacks"><i class="fas fa-exclamation-circle"></i> Attacks</a>
            <a href="/config"><i class="fas fa-cog"></i> Config</a>
            <a href="/test"><i class="fas fa-flask"></i> Test</a>
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
                <div class="card-subtext"><span id="block-rate">0</span>% of all requests</div>
                <div class="card-progress">
                    <div class="card-progress-bar" id="block-progress"></div>
                </div>
            </div>
            
            <div class="card warning">
                <div class="card-title">Challenged</div>
                <div class="card-value" id="challenged-requests">0</div>
                <div class="card-subtext"><span id="challenge-rate">0</span>% of all requests</div>
                <div class="card-progress">
                    <div class="card-progress-bar" id="challenge-progress"></div>
                </div>
            </div>
            
            <div class="card success">
                <div class="card-title">Allowed</div>
                <div class="card-value" id="allowed-requests">0</div>
                <div class="card-subtext"><span id="allow-rate">0</span>% of all requests</div>
                <div class="card-progress">
                    <div class="card-progress-bar" id="allow-progress"></div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-title">Avg Risk Score</div>
                <div class="card-value" id="avg-risk-score">0</div>
                <div class="card-subtext">0-100 scale</div>
            </div>
            
            <div class="card">
                <div class="card-title">Unique Sources</div>
                <div class="card-value" id="unique-hosts">0</div>
                <div class="card-subtext">Unique hosts</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3><i class="fas fa-chart-line"></i> Requests Over Time (24h)</h3>
            <div class="chart-wrapper">
                <canvas id="statsChart"></canvas>
            </div>
        </div>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px;">
            <div class="chart-container">
                <h3><i class="fas fa-bullseye"></i> Most Targeted Paths</h3>
                <div id="top-paths" style="font-size: 14px;"></div>
            </div>
            
            <div class="chart-container">
                <h3><i class="fas fa-network-wired"></i> Top Source Hosts</h3>
                <div id="top-sources" style="font-size: 14px;"></div>
            </div>
        </div>
        
        <p class="refresh-indicator">
            <i class="fas fa-clock"></i> Last updated: <span id="last-update">--:--:--</span> 
            (Auto-refresh every 30 seconds)
        </p>
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
                document.getElementById('avg-risk-score').textContent = (data.avg_risk_score || 0).toFixed(1);
                document.getElementById('unique-hosts').textContent = data.unique_hosts || 0;
                
                document.getElementById('block-rate').textContent = data.block_rate.toFixed(1);
                document.getElementById('challenge-rate').textContent = data.challenge_rate.toFixed(1);
                document.getElementById('allow-rate').textContent = data.allow_rate.toFixed(1);
                
                document.getElementById('block-progress').style.width = data.block_rate + '%';
                document.getElementById('challenge-progress').style.width = data.challenge_rate + '%';
                document.getElementById('allow-progress').style.width = data.allow_rate + '%';
                
                updateLastUpdate();
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }
        
        async function loadChart() {
            try {
                const response = await fetch('/api/stats/hourly?hours=24');
                const data = await response.json();
                const stats = data.stats;
                
                const labels = stats.map(s => {
                    const dt = new Date(s.hour);
                    return dt.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
                });
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
                                tension: 0.3,
                                fill: true
                            },
                            {
                                label: 'Challenged',
                                data: challengedData,
                                borderColor: '#f39c12',
                                backgroundColor: 'rgba(243, 156, 18, 0.1)',
                                tension: 0.3,
                                fill: true
                            },
                            {
                                label: 'Blocked',
                                data: blockedData,
                                borderColor: '#e74c3c',
                                backgroundColor: 'rgba(231, 76, 60, 0.1)',
                                tension: 0.3,
                                fill: true
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'top',
                                labels: { font: { size: 12 } }
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: { stepSize: 1 }
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Error loading chart:', error);
            }
        }
        
        async function loadTopPaths() {
            try {
                const response = await fetch('/api/stats/top-paths?limit=8');
                const data = await response.json();
                const paths = data.paths;
                
                let html = '<ul style="list-style: none; padding: 0;">';
                paths.forEach((path, idx) => {
                    html += `
                        <li style="padding: 8px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between;">
                            <span>${idx+1}. <strong>${path.path || '/'}</strong></span>
                            <span style="color: #e74c3c;">${path.blocked || 0} blocks</span>
                        </li>
                    `;
                });
                html += '</ul>';
                document.getElementById('top-paths').innerHTML = html;
            } catch (error) {
                console.error('Error loading top paths:', error);
            }
        }
        
        async function loadTopSources() {
            try {
                const response = await fetch('/api/stats/top-sources?limit=8');
                const data = await response.json();
                const sources = data.sources;
                
                let html = '<ul style="list-style: none; padding: 0;">';
                sources.forEach((source, idx) => {
                    html += `
                        <li style="padding: 8px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between;">
                            <span>${idx+1}. <strong>${source.host}</strong></span>
                            <span style="color: #667eea;">${source.count} reqs</span>
                        </li>
                    `;
                });
                html += '</ul>';
                document.getElementById('top-sources').innerHTML = html;
            } catch (error) {
                console.error('Error loading top sources:', error);
            }
        }
        
        async function checkHealth() {
            try {
                const response = await fetch('/api/health');
                const data = await response.json();
                const indicator = document.getElementById('status');
                const text = document.getElementById('status-text');
                
                if (data.status === 'healthy') {
                    indicator.className = 'status-dot status-healthy';
                    text.textContent = 'Healthy';
                } else {
                    indicator.className = 'status-dot status-unhealthy';
                    text.textContent = 'Unhealthy';
                }
            } catch (error) {
                console.error('Error checking health:', error);
            }
        }
        
        function updateLastUpdate() {
            const now = new Date();
            document.getElementById('last-update').textContent = 
                now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
        
        // Load data on page load
        window.addEventListener('load', () => {
            loadStats();
            loadChart();
            loadTopPaths();
            loadTopSources();
            checkHealth();
            updateLastUpdate();
            
            // Refresh every 30 seconds
            setInterval(() => {
                loadStats();
                loadChart();
                loadTopPaths();
                loadTopSources();
                checkHealth();
            }, 30000);
        });
    </script>
</body>
</html>
'''

# Placeholder templates (full implementations in extended version)
REALTIME_TEMPLATE = '<h2>Real-Time Monitoring (Coming Soon)</h2>'
REQUESTS_TEMPLATE = '<h2>Request History (Coming Soon)</h2>'
REQUEST_DETAIL_TEMPLATE = '<h2>Request Detail (Coming Soon)</h2>'
ATTACKS_TEMPLATE = '<h2>Attack Logs (Coming Soon)</h2>'
CONFIG_TEMPLATE = '<h2>Configuration Management (Coming Soon)</h2>'
TEST_TEMPLATE = '<h2>Request Testing (Coming Soon)</h2>'


if __name__ == "__main__":
    app = EnhancedDashboardApp(waf_url="http://localhost:5000", port=5001)
    app.run(port=5001, debug=True)