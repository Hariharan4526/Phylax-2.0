# dashboard.py - Professional Web Dashboard for Phylax WAF
# Production-Grade Flask Application with Modern UI

from flask import Flask, render_template, jsonify, request, session
from flask_cors import CORS
from datetime import datetime, timedelta
import sqlite3
import json
import os
from functools import wraps
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DashboardApp:
    """Professional Dashboard Application for Phylax WAF"""
    
    def __init__(self, waf_url="http://localhost:5000", db_path="dashboard.db", port=5001):
        """Initialize dashboard application"""
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'phylax-dashboard-secret-key-2026')
        self.waf_url = waf_url
        self.db_path = db_path
        self.port = port
        
        # Enable CORS
        CORS(self.app)
        
        # Initialize database
        self.init_db()
        
        # Register routes
        self.register_routes()
        
        logger.info("Dashboard initialized successfully")
    
    def init_db(self):
        """Initialize SQLite database for dashboard"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
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
                    status_code INTEGER,
                    response_time_ms REAL,
                    user_agent TEXT,
                    request_body TEXT
                )
            ''')
            
            # Create index for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp ON dashboard_logs(timestamp)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_decision ON dashboard_logs(decision)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_ip ON dashboard_logs(ip_address)
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
    
    def get_db(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def register_routes(self):
        """Register all dashboard routes"""
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return render_template('index.html')
        
        @self.app.route('/api/stats/overview', methods=['GET'])
        def get_overview_stats():
            """Get dashboard overview statistics"""
            try:
                conn = self.get_db()
                cursor = conn.cursor()
                
                # Get time range
                hours = request.args.get('hours', 24, type=int)
                cutoff = datetime.now() - timedelta(hours=hours)
                
                # Get statistics
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_requests,
                        SUM(CASE WHEN decision='ALLOW' THEN 1 ELSE 0 END) as allowed,
                        SUM(CASE WHEN decision='BLOCK' THEN 1 ELSE 0 END) as blocked,
                        SUM(CASE WHEN decision='CHALLENGE' THEN 1 ELSE 0 END) as challenged,
                        AVG(risk_score) as avg_risk,
                        MAX(risk_score) as max_risk,
                        AVG(response_time_ms) as avg_response_time
                    FROM dashboard_logs
                    WHERE timestamp > ?
                ''', (cutoff.isoformat(),))
                
                result = cursor.fetchone()
                conn.close()
                
                return jsonify({
                    'success': True,
                    'data': {
                        'total_requests': result['total_requests'] or 0,
                        'allowed_requests': result['allowed'] or 0,
                        'blocked_requests': result['blocked'] or 0,
                        'challenged_requests': result['challenged'] or 0,
                        'block_rate': (result['blocked'] / result['total_requests'] * 100) if result['total_requests'] else 0,
                        'avg_risk_score': round(result['avg_risk'] or 0, 2),
                        'max_risk_score': result['max_risk'] or 0,
                        'avg_response_time': round(result['avg_response_time'] or 0, 2)
                    }
                })
            except Exception as e:
                logger.error(f"Error getting overview stats: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/stats/hourly', methods=['GET'])
        def get_hourly_stats():
            """Get hourly statistics"""
            try:
                conn = self.get_db()
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
                logger.error(f"Error getting hourly stats: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/stats/top-ips', methods=['GET'])
        def get_top_ips():
            """Get top attacking IPs"""
            try:
                conn = self.get_db()
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
                logger.error(f"Error getting top IPs: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/stats/recent-requests', methods=['GET'])
        def get_recent_requests():
            """Get recent requests"""
            try:
                conn = self.get_db()
                cursor = conn.cursor()
                
                limit = request.args.get('limit', 50, type=int)
                decision_filter = request.args.get('decision', None)
                
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
                logger.error(f"Error getting recent requests: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/stats/decision-distribution', methods=['GET'])
        def get_decision_distribution():
            """Get decision distribution"""
            try:
                conn = self.get_db()
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
                logger.error(f"Error getting decision distribution: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                'status': 'healthy',
                'service': 'Phylax Dashboard',
                'timestamp': datetime.now().isoformat()
            })
    
    def run(self, host='0.0.0.0', port=None, debug=False):
        """Run the dashboard"""
        port = port or self.port
        logger.info(f"Starting Phylax Dashboard on http://{host}:{port}")
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)


# Create app instance
if __name__ == '__main__':
    app = DashboardApp(port=5001)
    app.run(debug=True)