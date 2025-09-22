#!/usr/bin/env python3
"""
Test script for Candidate Filtration System API
"""

import requests
import json
import time

def test_api_endpoints():
    """Test all API endpoints"""
    base_url = "http://localhost:5000"
    
    print("🔍 Testing Candidate Filtration System API...")
    print(f"Base URL: {base_url}")
    print("-" * 50)
    
    # Test health check
    try:
        print("1. Testing health check...")
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health check passed")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Health check error: {e}")
    
    print()
    
    # Test version endpoint
    try:
        print("2. Testing version endpoint...")
        response = requests.get(f"{base_url}/api/version", timeout=5)
        if response.status_code == 200:
            print("✅ Version endpoint passed")
            data = response.json()
            print(f"   API Version: {data.get('version')}")
            print(f"   Available endpoints: {list(data.get('endpoints', {}).keys())}")
        else:
            print(f"❌ Version endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Version endpoint error: {e}")
    
    print()
    
    # Test candidates endpoint
    try:
        print("3. Testing candidates endpoint...")
        response = requests.get(f"{base_url}/api/candidates", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Candidates endpoint passed")
            print(f"   Total candidates: {data.get('count', 0)}")
        else:
            print(f"❌ Candidates endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Candidates endpoint error: {e}")
    
    print()
    
    # Test jobs endpoint
    try:
        print("4. Testing jobs endpoint...")
        response = requests.get(f"{base_url}/api/jobs", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Jobs endpoint passed")
            print(f"   Total jobs: {data.get('count', 0)}")
        else:
            print(f"❌ Jobs endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Jobs endpoint error: {e}")
    
    print()
    
    # Test statistics endpoint
    try:
        print("5. Testing statistics endpoint...")
        response = requests.get(f"{base_url}/api/stats", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Statistics endpoint passed")
            stats = data.get('statistics', {})
            print(f"   Candidates: {stats.get('candidates', {})}")
            print(f"   Jobs: {stats.get('jobs', {})}")
            print(f"   Users: {stats.get('users', {})}")
        else:
            print(f"❌ Statistics endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Statistics endpoint error: {e}")
    
    print("\n" + "=" * 50)
    print("API Test Complete!")
    print("If all tests pass, your API is ready for deployment! 🚀")

if __name__ == "__main__":
    print("Starting API tests...")
    print("Make sure your API server is running on http://localhost:5000")
    print("Run: py index.py")
    print()
    
    # Wait a moment for user to start server
    input("Press Enter to continue when your server is running...")
    
    test_api_endpoints()
