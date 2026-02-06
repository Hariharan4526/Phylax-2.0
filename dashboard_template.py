"""
Enhanced Dashboard - Complete HTML Templates for all pages
This file contains all the template implementations
"""

# ============================================================================
# REALTIME MONITORING TEMPLATE
# ============================================================================

REALTIME_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Real-Time Monitoring - Phylax WAF</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        header {
            background: white;
            padding: 25px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        h1 { color: #667eea; font-size: 32px; }
        nav {
            display: flex;
            gap: 10px;
            background: white;
            padding: 15px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            flex-wrap: wrap;
        }
        nav a {
            padding: 10px 18px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-size: 14px;
        }
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .live-feed {
            max-height: 600px;
            overflow-y: auto;
            border: 1px solid #eee;
            border-radius: 8px;
        }
        .request-item {
            padding: 15px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
            animation: slideIn 0.3s ease-out;
        }
        .request-item:hover {
            background: #f9f9f9;
        }
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        .request-info {
            flex: 1;
        }
        .request-method {
            font-weight: bold;
            color: #667eea;
            margin-right: 10px;
        }
        .request-path {
            color: #333;
            font-family: monospace;
            font-size: 12px;
        }
        .request-decision {
            padding: 5px 12px;
            border-radius: 15px;
            font-weight: bold;
            font-size: 12px;
            margin: 0 10px;
        }
        .decision-allow {
            background: #d4edda;
            color: #155724;
        }
        .decision-challenge {
            background: #fff3cd;
            color: #856404;
        }
        .decision-block {
            background: #f8d7da;
            color: #721c24;
        }
        .request-timestamp {
            color: #999;
            font-size: 12px;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }
        .metric-label {
            color: #999;
            font-size: 12px;
            text-transform: uppercase;
        }
        .live-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            background: #27ae60;
            border-radius: 50%;
            animation: pulse 1s infinite;
            margin-right: 8px;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><i class="fas fa-tachometer-alt"></i> Real-Time Monitoring</h1>
            <button onclick="location.reload()" style="padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 5px;">
                <i class="fas fa-sync"></i> Refresh
            </button>
        </header>
        
        <nav>
            <a href="/"><i class="fas fa-home"></i> Dashboard</a>
            <a href="/real-time"><i class="fas fa-tachometer-alt"></i> Real-Time</a>
            <a href="/requests"><i class="fas fa-history"></i> Requests</a>
            <a href="/attacks"><i class="fas fa-exclamation-circle"></i> Attacks</a>
            <a href="/config"><i class="fas fa-cog"></i> Config</a>
            <a href="/test"><i class="fas fa-flask"></i> Test</a>
        </nav>
        
        <div class="metrics-grid" id="metrics-container"></div>
        
        <div class="card">
            <h2><i class="fas fa-stream"></i> <span class="live-indicator"></span>Live Request Stream</h2>
            <div class="live-feed" id="live-feed"></div>
        </div>
    </div>
    
    <script>
        async function loadRealtimeStats() {
            try {
                const response = await fetch('/api/realtime/stats');
                const data = await response.json();
                
                const html = `
                    <div class="metric">
                        <div class="metric-label">Requests/sec</div>
                        <div class="metric-value">${(data.stats.total_requests / 3600).toFixed(2)}</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Blocks/sec</div>
                        <div class="metric-value" style="color: #e74c3c;">${(data.stats.blocked_requests / 3600).toFixed(2)}</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Avg Risk</div>
                        <div class="metric-value">${data.stats.avg_risk_score.toFixed(1)}</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Unique Sources</div>
                        <div class="metric-value">${data.stats.unique_hosts}</div>
                    </div>
                `;
                
                document.getElementById('metrics-container').innerHTML = html;
            } catch (error) {
                console.error('Error loading realtime stats:', error);
            }
        }
        
        async function loadLiveEvents() {
            try {
                const response = await fetch('/api/realtime/events?limit=10');
                const data = await response.json();
                
                let html = '';
                data.events.forEach(event => {
                    const decisionClass = 'decision-' + event.decision.toLowerCase();
                    html += `
                        <div class="request-item">
                            <div class="request-info">
                                <span class="request-method">${event.method}</span>
                                <span class="request-path">${event.path}</span>
                            </div>
                            <span class="request-decision ${decisionClass}">${event.decision}</span>
                            <span style="width: 60px; text-align: right;">
                                <strong>${event.risk_score.toFixed(1)}</strong>
                            </span>
                            <span class="request-timestamp">${new Date(event.timestamp).toLocaleTimeString()}</span>
                        </div>
                    `;
                });
                
                document.getElementById('live-feed').innerHTML = html;
            } catch (error) {
                console.error('Error loading live events:', error);
            }
        }
        
        // Initial load
        window.addEventListener('load', () => {
            loadRealtimeStats();
            loadLiveEvents();
            
            // Refresh every 2 seconds for real-time effect
            setInterval(() => {
                loadRealtimeStats();
                loadLiveEvents();
            }, 2000);
        });
    </script>
</body>
</html>
'''

# ============================================================================
# REQUEST HISTORY TEMPLATE
# ============================================================================

REQUESTS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request History - Phylax WAF</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            background: white;
            padding: 25px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }
        h1 { color: #667eea; font-size: 32px; }
        nav {
            display: flex;
            gap: 10px;
            background: white;
            padding: 15px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            flex-wrap: wrap;
        }
        nav a {
            padding: 10px 18px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-size: 14px;
        }
        .filters {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        .filters select, .filters input {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
        }
        .filters button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        table {
            width: 100%;
            background: white;
            border-collapse: collapse;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        thead {
            background: #f5f5f5;
        }
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            font-weight: bold;
            color: #333;
        }
        tr:hover {
            background: #f9f9f9;
        }
        .badge {
            padding: 5px 12px;
            border-radius: 15px;
            font-weight: bold;
            font-size: 12px;
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
        .pagination button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .risk-score {
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 3px;
        }
        .risk-low { background: #d4edda; color: #155724; }
        .risk-medium { background: #fff3cd; color: #856404; }
        .risk-high { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><i class="fas fa-history"></i> Request History</h1>
        </header>
        
        <nav>
            <a href="/"><i class="fas fa-home"></i> Dashboard</a>
            <a href="/real-time"><i class="fas fa-tachometer-alt"></i> Real-Time</a>
            <a href="/requests"><i class="fas fa-history"></i> Requests</a>
            <a href="/attacks"><i class="fas fa-exclamation-circle"></i> Attacks</a>
            <a href="/config"><i class="fas fa-cog"></i> Config</a>
            <a href="/test"><i class="fas fa-flask"></i> Test</a>
        </nav>
        
        <div class="filters">
            <label>
                Filter by:
                <select id="decision-filter" onchange="currentPage = 0; loadRequests()">
                    <option value="">All Requests</option>
                    <option value="ALLOW">Allowed</option>
                    <option value="CHALLENGE">Challenged</option>
                    <option value="BLOCK">Blocked</option>
                </select>
            </label>
            <button onclick="loadRequests()"><i class="fas fa-sync"></i> Refresh</button>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Host</th>
                    <th>Decision</th>
                    <th>Risk Score</th>
                    <th>Time (ms)</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="requests-table"></tbody>
        </table>
        
        <div class="pagination">
            <button onclick="previousPage()">← Previous</button>
            <span id="page-info" style="padding: 8px 12px;"></span>
            <button onclick="nextPage()">Next →</button>
        </div>
    </div>
    
    <script>
        let currentPage = 0;
        const pageSize = 50;
        let totalRequests = 0;
        
        async function loadRequests() {
            try {
                const offset = currentPage * pageSize;
                const decision = document.getElementById('decision-filter').value;
                const url = `/api/requests?limit=${pageSize}&offset=${offset}${decision ? '&decision=' + decision : ''}`;
                
                const response = await fetch(url);
                const data = await response.json();
                
                totalRequests = data.total;
                const requests = data.logs;
                
                const table = document.getElementById('requests-table');
                table.innerHTML = '';
                
                requests.forEach(req => {
                    const decisionClass = 'badge-' + req.decision.toLowerCase();
                    let riskClass = 'risk-low';
                    if (req.risk_score > 66) riskClass = 'risk-high';
                    else if (req.risk_score > 33) riskClass = 'risk-medium';
                    
                    table.innerHTML += `
                        <tr>
                            <td><small>${new Date(req.timestamp).toLocaleString()}</small></td>
                            <td><strong>${req.method}</strong></td>
                            <td><code style="font-size: 12px;">${req.path}</code></td>
                            <td>${req.host}</td>
                            <td><span class="badge ${decisionClass}">${req.decision}</span></td>
                            <td><span class="risk-score ${riskClass}">${req.risk_score.toFixed(1)}</span></td>
                            <td>${req.response_time_ms.toFixed(1)}</td>
                            <td><a href="/request/${req.request_id}" style="color: #667eea; cursor: pointer;">View</a></td>
                        </tr>
                    `;
                });
                
                const totalPages = Math.ceil(totalRequests / pageSize);
                document.getElementById('page-info').textContent = `Page ${currentPage + 1} of ${totalPages || 1}`;
                document.querySelector('.pagination button:nth-of-type(1)').disabled = currentPage === 0;
                document.querySelector('.pagination button:nth-of-type(3)').disabled = currentPage >= totalPages - 1;
            } catch (error) {
                console.error('Error loading requests:', error);
            }
        }
        
        function previousPage() {
            if (currentPage > 0) {
                currentPage--;
                loadRequests();
            }
        }
        
        function nextPage() {
            const totalPages = Math.ceil(totalRequests / pageSize);
            if (currentPage < totalPages - 1) {
                currentPage++;
                loadRequests();
            }
        }
        
        window.addEventListener('load', loadRequests);
    </script>
</body>
</html>
'''

# ============================================================================
# REQUEST DETAIL TEMPLATE
# ============================================================================

REQUEST_DETAIL_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Detail - Phylax WAF</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        header {
            background: white;
            padding: 25px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }
        h1 { color: #667eea; }
        .back-link {
            color: #667eea;
            text-decoration: none;
            margin-bottom: 20px;
            display: inline-block;
        }
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .detail-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .detail-item {
            padding: 10px 0;
            border-bottom: 1px solid #eee;
        }
        .detail-label {
            font-weight: bold;
            color: #667eea;
            font-size: 12px;
            text-transform: uppercase;
        }
        .detail-value {
            margin-top: 5px;
            font-family: monospace;
            word-break: break-all;
        }
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 15px;
            font-weight: bold;
            margin-top: 5px;
        }
        .badge-allow { background: #d4edda; color: #155724; }
        .badge-challenge { background: #fff3cd; color: #856404; }
        .badge-block { background: #f8d7da; color: #721c24; }
        .code-block {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: monospace;
            font-size: 12px;
            line-height: 1.5;
        }
        ul { margin-left: 20px; }
        li { margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <a href="/requests" class="back-link"><i class="fas fa-arrow-left"></i> Back to Requests</a>
            <h1><i class="fas fa-magnifying-glass"></i> Request Details</h1>
        </header>
        
        <div class="card" id="detail-container">
            <p>Loading request details...</p>
        </div>
    </div>
    
    <script>
        const requestId = "{{ request_id }}";
        
        async function loadDetail() {
            try {
                const response = await fetch(`/api/request/${requestId}`);
                if (!response.ok) {
                    document.getElementById('detail-container').innerHTML = '<p>Request not found</p>';
                    return;
                }
                
                const req = await response.json();
                const decisionClass = 'badge-' + req.decision.toLowerCase();
                
                const html = `
                    <div class="detail-grid">
                        <div>
                            <div class="detail-item">
                                <div class="detail-label">Request ID</div>
                                <div class="detail-value">${req.request_id}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Timestamp</div>
                                <div class="detail-value">${new Date(req.timestamp).toLocaleString()}</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Decision</div>
                                <div><span class="badge ${decisionClass}">${req.decision}</span></div>
                            </div>
                        </div>
                        <div>
                            <div class="detail-item">
                                <div class="detail-label">Risk Score</div>
                                <div class="detail-value"><strong>${req.risk_score.toFixed(1)}</strong>/100</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Response Time</div>
                                <div class="detail-value">${req.response_time_ms.toFixed(1)} ms</div>
                            </div>
                            <div class="detail-item">
                                <div class="detail-label">Status Code</div>
                                <div class="detail-value">${req.status_code}</div>
                            </div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 30px; border-top: 2px solid #eee; padding-top: 20px;">
                        <h3>HTTP Request Details</h3>
                        <div class="detail-grid">
                            <div>
                                <div class="detail-item">
                                    <div class="detail-label">Method</div>
                                    <div class="detail-value">${req.method}</div>
                                </div>
                                <div class="detail-item">
                                    <div class="detail-label">Path</div>
                                    <div class="detail-value">${req.path}</div>
                                </div>
                            </div>
                            <div>
                                <div class="detail-item">
                                    <div class="detail-label">Host</div>
                                    <div class="detail-value">${req.host}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 20px;">
                        <h3>Payload</h3>
                        <div class="code-block">${escapeHtml(req.payload)}</div>
                    </div>
                    
                    <div style="margin-top: 20px;">
                        <h3>Contributing Factors</h3>
                        <ul>
                            ${req.factors.map(f => `<li>${escapeHtml(f)}</li>`).join('')}
                        </ul>
                    </div>
                `;
                
                document.getElementById('detail-container').innerHTML = html;
            } catch (error) {
                console.error('Error loading detail:', error);
                document.getElementById('detail-container').innerHTML = '<p>Error loading request details</p>';
            }
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        window.addEventListener('load', loadDetail);
    </script>
</body>
</html>
'''

# ============================================================================
# ATTACK DETECTION LOGS TEMPLATE
# ============================================================================

ATTACKS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Logs - Phylax WAF</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            background: white;
            padding: 25px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }
        h1 { color: #667eea; font-size: 32px; }
        nav {
            display: flex;
            gap: 10px;
            background: white;
            padding: 15px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            flex-wrap: wrap;
        }
        nav a {
            padding: 10px 18px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-size: 14px;
        }
        .filters {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .filters select {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .alert-list {
            list-style: none;
        }
        .alert-item {
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #999;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        .alert-item.critical {
            border-left-color: #e74c3c;
            background: #fff5f5;
        }
        .alert-item.high {
            border-left-color: #f39c12;
            background: #fffbf0;
        }
        .alert-item.medium {
            border-left-color: #f1c40f;
            background: #fffef0;
        }
        .alert-item.low {
            border-left-color: #27ae60;
            background: #f5fff5;
        }
        .alert-content {
            flex: 1;
        }
        .alert-title {
            font-weight: bold;
            font-size: 16px;
            margin-bottom: 5px;
        }
        .alert-message {
            color: #666;
            margin-bottom: 10px;
        }
        .alert-meta {
            display: flex;
            gap: 20px;
            font-size: 12px;
            color: #999;
        }
        .severity-badge {
            padding: 5px 12px;
            border-radius: 15px;
            font-weight: bold;
            font-size: 12px;
        }
        .severity-critical {
            background: #f8d7da;
            color: #721c24;
        }
        .severity-high {
            background: #fff3cd;
            color: #856404;
        }
        .severity-medium {
            background: #d1ecf1;
            color: #0c5460;
        }
        .severity-low {
            background: #d4edda;
            color: #155724;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><i class="fas fa-exclamation-circle"></i> Attack Detection Logs</h1>
        </header>
        
        <nav>
            <a href="/"><i class="fas fa-home"></i> Dashboard</a>
            <a href="/real-time"><i class="fas fa-tachometer-alt"></i> Real-Time</a>
            <a href="/requests"><i class="fas fa-history"></i> Requests</a>
            <a href="/attacks"><i class="fas fa-exclamation-circle"></i> Attacks</a>
            <a href="/config"><i class="fas fa-cog"></i> Config</a>
            <a href="/test"><i class="fas fa-flask"></i> Test</a>
        </nav>
        
        <div class="filters">
            <label>
                Filter by severity:
                <select id="severity-filter" onchange="loadAlerts()">
                    <option value="">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                </select>
            </label>
            <button onclick="loadAlerts()" style="padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer;">
                <i class="fas fa-sync"></i> Refresh
            </button>
        </div>
        
        <ul class="alert-list" id="alerts-list"></ul>
    </div>
    
    <script>
        async function loadAlerts() {
            try {
                const severity = document.getElementById('severity-filter').value;
                const url = `/api/alerts${severity ? '?severity=' + severity : ''}`;
                
                const response = await fetch(url);
                const data = await response.json();
                
                const list = document.getElementById('alerts-list');
                list.innerHTML = '';
                
                if (data.alerts.length === 0) {
                    list.innerHTML = '<li style="background: white; padding: 20px; border-radius: 10px; text-align: center; color: #999;">No alerts found</li>';
                    return;
                }
                
                data.alerts.forEach(alert => {
                    const severityClass = alert.severity.toLowerCase();
                    const badgeClass = 'severity-' + severityClass;
                    
                    list.innerHTML += `
                        <li class="alert-item ${severityClass}">
                            <div class="alert-content">
                                <div class="alert-title">
                                    <i class="fas fa-bomb"></i> ${alert.alert_type}
                                </div>
                                <div class="alert-message">${alert.message}</div>
                                <div class="alert-meta">
                                    <span><strong>Time:</strong> ${new Date(alert.timestamp).toLocaleString()}</span>
                                    <span><strong>Request:</strong> <code>${alert.request_id || 'N/A'}</code></span>
                                    ${alert.request_count ? `<span><strong>Count:</strong> ${alert.request_count}</span>` : ''}
                                </div>
                            </div>
                            <span class="severity-badge ${badgeClass}">${alert.severity}</span>
                        </li>
                    `;
                });
            } catch (error) {
                console.error('Error loading alerts:', error);
            }
        }
        
        window.addEventListener('load', loadAlerts);
        
        // Auto-refresh every 10 seconds
        setInterval(loadAlerts, 10000);
    </script>
</body>
</html>
'''

# ============================================================================
# CONFIGURATION MANAGEMENT TEMPLATE
# ============================================================================

CONFIG_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configuration - Phylax WAF</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        header {
            background: white;
            padding: 25px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }
        h1 { color: #667eea; font-size: 32px; }
        nav {
            display: flex;
            gap: 10px;
            background: white;
            padding: 15px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            flex-wrap: wrap;
        }
        nav a {
            padding: 10px 18px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-size: 14px;
        }
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }
        input, select, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            font-family: monospace;
        }
        textarea {
            min-height: 100px;
            resize: vertical;
        }
        button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
        }
        button:hover {
            background: #764ba2;
        }
        .config-item {
            padding: 15px;
            border: 1px solid #eee;
            border-radius: 5px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .config-key {
            font-weight: bold;
            color: #667eea;
            font-family: monospace;
        }
        .config-value {
            color: #666;
            flex: 1;
            margin: 0 20px;
        }
        .success {
            background: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><i class="fas fa-cog"></i> Configuration Management</h1>
        </header>
        
        <nav>
            <a href="/"><i class="fas fa-home"></i> Dashboard</a>
            <a href="/real-time"><i class="fas fa-tachometer-alt"></i> Real-Time</a>
            <a href="/requests"><i class="fas fa-history"></i> Requests</a>
            <a href="/attacks"><i class="fas fa-exclamation-circle"></i> Attacks</a>
            <a href="/config"><i class="fas fa-cog"></i> Config</a>
            <a href="/test"><i class="fas fa-flask"></i> Test</a>
        </nav>
        
        <div id="success-message" class="success" style="display: none;"></div>
        
        <div class="card">
            <h2>WAF Configuration Settings</h2>
            <p style="color: #666; margin-bottom: 20px;">Manage WAF engine settings and thresholds</p>
            
            <form onsubmit="saveConfig(event)">
                <div class="form-group">
                    <label for="risk-allow">Risk Threshold - Allow (0-100):</label>
                    <input type="number" id="risk-allow" value="33" min="0" max="100" required>
                </div>
                
                <div class="form-group">
                    <label for="risk-challenge">Risk Threshold - Challenge (0-100):</label>
                    <input type="number" id="risk-challenge" value="66" min="0" max="100" required>
                </div>
                
                <div class="form-group">
                    <label for="signature-weight">Signature Detection Weight (0-1):</label>
                    <input type="number" id="signature-weight" value="0.35" min="0" max="1" step="0.01" required>
                </div>
                
                <div class="form-group">
                    <label for="ml-weight">ML Classification Weight (0-1):</label>
                    <input type="number" id="ml-weight" value="0.35" min="0" max="1" step="0.01" required>
                </div>
                
                <div class="form-group">
                    <label for="anomaly-weight">Anomaly Detection Weight (0-1):</label>
                    <input type="number" id="anomaly-weight" value="0.20" min="0" max="1" step="0.01" required>
                </div>
                
                <div class="form-group">
                    <label for="context-weight">Context Weight (0-1):</label>
                    <input type="number" id="context-weight" value="0.10" min="0" max="1" step="0.01" required>
                </div>
                
                <button type="submit"><i class="fas fa-save"></i> Save Configuration</button>
            </form>
        </div>
        
        <div class="card">
            <h2>Current Configuration</h2>
            <div id="config-list"></div>
        </div>
    </div>
    
    <script>
        async function loadConfig() {
            try {
                const response = await fetch('/api/config');
                const config = await response.json();
                
                let html = '';
                for (const [key, item] of Object.entries(config)) {
                    html += `
                        <div class="config-item">
                            <span class="config-key">${key}</span>
                            <span class="config-value">${item.value}</span>
                            <small style="color: #999;">${item.type}</small>
                        </div>
                    `;
                }
                
                document.getElementById('config-list').innerHTML = html || '<p>No configuration found</p>';
            } catch (error) {
                console.error('Error loading config:', error);
            }
        }
        
        async function saveConfig(event) {
            event.preventDefault();
            
            try {
                const config = {
                    'risk_threshold_allow': document.getElementById('risk-allow').value,
                    'risk_threshold_challenge': document.getElementById('risk-challenge').value,
                    'signature_weight': document.getElementById('signature-weight').value,
                    'ml_weight': document.getElementById('ml-weight').value,
                    'anomaly_weight': document.getElementById('anomaly-weight').value,
                    'context_weight': document.getElementById('context-weight').value
                };
                
                for (const [key, value] of Object.entries(config)) {
                    await fetch('/api/config', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ key, value, type: 'number' })
                    });
                }
                
                document.getElementById('success-message').textContent = '✓ Configuration saved successfully!';
                document.getElementById('success-message').style.display = 'block';
                
                loadConfig();
                
                setTimeout(() => {
                    document.getElementById('success-message').style.display = 'none';
                }, 3000);
            } catch (error) {
                console.error('Error saving config:', error);
            }
        }
        
        window.addEventListener('load', loadConfig);
    </script>
</body>
</html>
'''

# ============================================================================
# TEST TEMPLATE
# ============================================================================

TEST_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Request Testing - Phylax WAF</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            background: white;
            padding: 25px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }
        h1 { color: #667eea; font-size: 32px; }
        nav {
            display: flex;
            gap: 10px;
            background: white;
            padding: 15px 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            flex-wrap: wrap;
        }
        nav a {
            padding: 10px 18px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-size: 14px;
        }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }
        textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-family: monospace;
            font-size: 12px;
            min-height: 250px;
            resize: vertical;
        }
        button {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        .template-buttons {
            display: flex;
            gap: 10px;
            margin: 15px 0;
            flex-wrap: wrap;
        }
        .template-btn {
            padding: 8px 15px;
            background: white;
            color: #667eea;
            border: 2px solid #667eea;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
        }
        .template-btn:hover {
            background: #667eea;
            color: white;
        }
        .result {
            padding: 20px;
            border-radius: 5px;
            display: none;
            margin-top: 20px;
        }
        .result.show { display: block; }
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
        .loading {
            display: none;
            text-align: center;
            color: #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><i class="fas fa-flask"></i> Request Testing</h1>
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
                <h2><i class="fas fa-edit"></i> Test Request</h2>
                
                <div class="form-group">
                    <label>Quick Templates:</label>
                    <div class="template-buttons">
                        <button class="template-btn" onclick="loadTemplate('clean')">Clean</button>
                        <button class="template-btn" onclick="loadTemplate('sqli')">SQL Injection</button>
                        <button class="template-btn" onclick="loadTemplate('xss')">XSS</button>
                        <button class="template-btn" onclick="loadTemplate('cmd')">Command</button>
                    </div>
                </div>
                
                <form onsubmit="testRequest(event)">
                    <div class="form-group">
                        <label>Raw HTTP Request:</label>
                        <textarea id="request-input" placeholder="Enter raw HTTP request..."></textarea>
                    </div>
                    <button type="submit"><i class="fas fa-paper-plane"></i> Send Request</button>
                </form>
            </div>
            
            <div class="card">
                <h2><i class="fas fa-chart-bar"></i> Result</h2>
                
                <div class="loading" id="loading">
                    <div style="display: inline-block; width: 30px; height: 30px; border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; animation: spin 1s linear infinite;"></div>
                    <p>Processing request...</p>
                </div>
                
                <div class="result" id="result"></div>
                <p style="color: #999; font-size: 12px; margin-top: 20px;">Results will appear here</p>
            </div>
        </div>
    </div>
    
    <script>
        const templates = {
            clean: 'GET /index.html HTTP/1.1\\r\\nHost: example.com\\r\\nUser-Agent: Mozilla/5.0\\r\\nConnection: close\\r\\n\\r\\n',
            sqli: 'GET /api/users?id=1\\' OR \\'1\\'=\\'1 HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n',
            xss: 'GET /search?q=<script>alert(\\'XSS\\')</script> HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n',
            cmd: 'POST /cmd HTTP/1.1\\r\\nHost: example.com\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nContent-Length: 20\\r\\n\\r\\ninput=test;whoami'
        };
        
        function loadTemplate(name) {
            const textarea = document.getElementById('request-input');
            textarea.value = templates[name];
        }
        
        async function testRequest(event) {
            event.preventDefault();
            
            const rawHttp = document.getElementById('request-input').value;
            if (!rawHttp.trim()) {
                alert('Please enter a request');
                return;
            }
            
            document.getElementById('loading').style.display = 'block';
            document.getElementById('result').classList.remove('show');
            
            try {
                const response = await fetch('/api/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ raw_http: rawHttp })
                });
                
                const data = await response.json();
                document.getElementById('loading').style.display = 'none';
                
                const decision = data.decision.toLowerCase();
                const result = document.getElementById('result');
                result.className = `result show ${decision}`;
                
                result.innerHTML = `
                    <h3 style="margin-bottom: 15px;">Decision: <strong>${data.decision}</strong></h3>
                    <p style="margin-bottom: 15px;">${data.reason}</p>
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                        <div>
                            <strong>Risk Score:</strong> ${data.risk_score?.toFixed(1) || 'N/A'}/100
                        </div>
                        <div>
                            <strong>Confidence:</strong> ${(data.confidence * 100)?.toFixed(1) || 'N/A'}%
                        </div>
                        <div>
                            <strong>Request ID:</strong><br><code style="font-size: 11px;">${data.request_id}</code>
                        </div>
                        <div>
                            <strong>Response Time:</strong> ${response.elapsed || 'N/A'}ms
                        </div>
                    </div>
                    
                    ${data.contributing_factors && data.contributing_factors.length > 0 ? `
                        <div style="margin-top: 15px; border-top: 1px solid rgba(0,0,0,0.1); padding-top: 15px;">
                            <strong>Contributing Factors:</strong>
                            <ul style="margin-top: 10px; margin-left: 20px;">
                                ${data.contributing_factors.map(f => `<li>${f}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                `;
            } catch (error) {
                document.getElementById('loading').style.display = 'none';
                const result = document.getElementById('result');
                result.className = 'result show block';
                result.innerHTML = `<h3>Error</h3><p>${error.message}</p>`;
            }
        }
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