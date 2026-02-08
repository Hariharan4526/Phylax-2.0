"""
Phylax WAF - Complete Startup Script
Runs both WAF Engine (port 5000) and Dashboard (port 5001)
"""

import subprocess
import sys
import time
import os
import signal
from dashboard import DashboardApp

def main():
    """Main entry point"""
    
    print("=" * 80)
    print("🚀 PHYLAX WAF - COMPLETE SYSTEM STARTUP")
    print("=" * 80)
    print()
    
    # WAF Engine process
    waf_process = None
    dashboard_process = None
    
    try:
        # Start WAF Engine
        print("📡 Starting WAF Engine on port 5000...")
        waf_process = subprocess.Popen(
            [sys.executable, "-c", """
import sys
sys.path.insert(0, '.')
from src.waf_engine import WAFEngine
from src.http_handler import WAFHTTPHandler

engine = WAFEngine(
    model_path="models/gb_model_20260203_144133.pkl",
    scaler_path="models/scaler_20260203_144133.pkl",
    feature_names_path="models/feature_names_20260203_144133.json",
    config_path="config.json"
)

handler = WAFHTTPHandler(engine)
handler.run(host='0.0.0.0', port=5000, debug=False)
            """]
        )
        
        print("✅ WAF Engine started!")
        print()
        
        # Wait for WAF to start
        time.sleep(2)
        
        # Start Dashboard
        print("🎨 Starting Dashboard on port 5001...")
        dashboard_process = subprocess.Popen(
            [sys.executable, "-c", """
import sys
sys.path.insert(0, '.')
from dashboard import DashboardApp

app = DashboardApp(waf_url="http://localhost:5000", port=5001)
app.run(host='0.0.0.0', port=5001, debug=False)
            """]
        )
        
        print("✅ Dashboard started!")
        print()
        
        # Display startup information
        print("=" * 80)
        print("✨ PHYLAX WAF IS RUNNING!")
        print("=" * 80)
        print()
        print("📊 DASHBOARD (Web Interface)")
        print("   🌐 http://localhost:5001")
        print("   ✨ Features:")
        print("      • Real-time statistics")
        print("      • Request testing interface")
        print("      • Request history and logs")
        print("      • Live charts and metrics")
        print()
        print("⚔️  WAF ENGINE (API)")
        print("   📡 http://localhost:5000")
        print("   ✨ Endpoints:")
        print("      • POST /waf/check - Check HTTP request")
        print("      • GET  /waf/stats - Get statistics")
        print("      • GET  /waf/health - Health check")
        print("      • GET  /waf/config - Get configuration")
        print()
        print("=" * 80)
        print()
        print("💡 QUICK START:")
        print("   1. Open browser: http://localhost:5001")
        print("   2. Use Test Request tab to test payloads")
        print("   3. View logs and statistics in real-time")
        print()
        print("⏹️  Press Ctrl+C to stop the system")
        print()
        print("=" * 80)
        
        # Wait for both processes
        waf_process.wait()
        dashboard_process.wait()
        
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down Phylax WAF...")
        
        if waf_process:
            waf_process.terminate()
            try:
                waf_process.wait(timeout=5)
            except:
                waf_process.kill()
        
        if dashboard_process:
            dashboard_process.terminate()
            try:
                dashboard_process.wait(timeout=5)
            except:
                dashboard_process.kill()
        
        print("✅ All systems shut down gracefully")
        print()
    
    except Exception as e:
        print(f"❌ Error: {e}")
        
        # Cleanup
        if waf_process:
            waf_process.kill()
        if dashboard_process:
            dashboard_process.kill()
        
        sys.exit(1)


if __name__ == "__main__":
    # Start dashboard
    app = DashboardApp(waf_url="http://localhost:5000", port=5001)
    app.run(host='0.0.0.0', port=5001, debug=False)