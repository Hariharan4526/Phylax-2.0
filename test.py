#!/usr/bin/env python3
"""
Quick WAF Testing Script
Copy-paste ready examples to test your WAF
"""

import requests
import json
import sys

WAF_URL = "http://localhost:5000"

def test_health():
    """Test health endpoint"""
    print("🏥 Testing Health Endpoint...")
    try:
        r = requests.get(f"{WAF_URL}/waf/health")
        print(f"✅ Status: {r.status_code}")
        print(json.dumps(r.json(), indent=2))
    except Exception as e:
        print(f"❌ Error: {e}")


def test_clean():
    """Test clean request"""
    print("\n📄 Testing Clean Request...")
    
    raw_http = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    payload = {
        "raw_http": raw_http,
        "request_id": "test_clean_001"
    }
    
    try:
        r = requests.post(
            f"{WAF_URL}/waf/check",
            json=payload
        )
        print(f"✅ Status: {r.status_code}")
        data = r.json()
        print(f"   Decision: {data.get('decision')}")
        print(f"   Risk Score: {data.get('risk_score'):.1f}")
    except Exception as e:
        print(f"❌ Error: {e}")


def test_sqli():
    """Test SQL injection"""
    print("\n🔓 Testing SQL Injection Detection...")
    
    # Classic SQLi payload
    raw_http = "GET /api/users?id=1' OR '1'='1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    payload = {
        "raw_http": raw_http,
        "request_id": "test_sqli_001"
    }
    
    try:
        r = requests.post(
            f"{WAF_URL}/waf/check",
            json=payload
        )
        print(f"✅ Status: {r.status_code}")
        data = r.json()
        print(f"   Decision: {data.get('decision')}")
        print(f"   Risk Score: {data.get('risk_score'):.1f}")
        factors = data.get('contributing_factors', [])
        if factors:
            print(f"   Factors: {factors}")
    except Exception as e:
        print(f"❌ Error: {e}")


def test_xss():
    """Test XSS"""
    print("\n🔥 Testing XSS Detection...")
    
    raw_http = "GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\nHost: example.com\r\n\r\n"
    payload = {
        "raw_http": raw_http,
        "request_id": "test_xss_001"
    }
    
    try:
        r = requests.post(
            f"{WAF_URL}/waf/check",
            json=payload
        )
        print(f"✅ Status: {r.status_code}")
        data = r.json()
        print(f"   Decision: {data.get('decision')}")
        print(f"   Risk Score: {data.get('risk_score'):.1f}")
    except Exception as e:
        print(f"❌ Error: {e}")


def test_stats():
    """Get statistics"""
    print("\n📊 Testing Statistics Endpoint...")
    try:
        r = requests.get(f"{WAF_URL}/waf/stats")
        print(f"✅ Status: {r.status_code}")
        data = r.json()
        stats = data.get('statistics', {})
        print(f"   Total: {stats.get('total_requests')}")
        print(f"   Blocked: {stats.get('blocked_requests')}")
        print(f"   Challenged: {stats.get('challenged_requests')}")
        print(f"   Allowed: {stats.get('allowed_requests')}")
    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    print("=" * 80)
    print("🚀 PHYLAX WAF - QUICK TEST")
    print("=" * 80)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "health":
            test_health()
        elif sys.argv[1] == "clean":
            test_clean()
        elif sys.argv[1] == "sqli":
            test_sqli()
        elif sys.argv[1] == "xss":
            test_xss()
        elif sys.argv[1] == "stats":
            test_stats()
        elif sys.argv[1] == "all":
            test_health()
            test_clean()
            test_sqli()
            test_xss()
            test_stats()
        else:
            print("Usage: python quick_test.py [health|clean|sqli|xss|stats|all]")
    else:
        # Run all
        test_health()
        test_clean()
        test_sqli()
        test_xss()
        test_stats()
    
    print("\n" + "=" * 80)
    print("✅ TESTS COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()