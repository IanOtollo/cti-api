#!/usr/bin/env python3
"""
Test script for CTI API
Tests all endpoints to ensure they're working correctly
"""

import requests
import sys

# Configuration
BASE_URL = "http://localhost:8000"  # Change this to your deployed URL
API_KEY = "demo-key-CHANGE_ME"
HEADERS = {"Authorization": f"Bearer {API_KEY}"}

def test_endpoint(name, url, method="GET", headers=None, expected_status=200):
    """Test a single endpoint"""
    print(f"\n{'='*60}")
    print(f"Testing: {name}")
    print(f"URL: {url}")
    print(f"{'='*60}")
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        else:
            print(f"Method {method} not implemented in test")
            return False
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == expected_status:
            print("✓ Status code matches expected")
            print(f"Response: {response.json()}")
            return True
        else:
            print(f"✗ Expected {expected_status}, got {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("CTI API Test Suite")
    print("=" * 60)
    print(f"Base URL: {BASE_URL}")
    print(f"API Key: {API_KEY}")
    
    results = []
    
    # Test public endpoints
    results.append(test_endpoint(
        "Root Endpoint",
        f"{BASE_URL}/",
        expected_status=200
    ))
    
    results.append(test_endpoint(
        "Health Check",
        f"{BASE_URL}/health",
        expected_status=200
    ))
    
    # Test protected endpoints without authentication (should fail)
    results.append(test_endpoint(
        "Sources without auth (should fail)",
        f"{BASE_URL}/sources",
        expected_status=401
    ))
    
    # Test protected endpoints with authentication
    results.append(test_endpoint(
        "All Sources",
        f"{BASE_URL}/sources",
        headers=HEADERS,
        expected_status=200
    ))
    
    results.append(test_endpoint(
        "Specific Source",
        f"{BASE_URL}/sources/src_001",
        headers=HEADERS,
        expected_status=200
    ))
    
    results.append(test_endpoint(
        "All Indicators",
        f"{BASE_URL}/indicators",
        headers=HEADERS,
        expected_status=200
    ))
    
    results.append(test_endpoint(
        "Filter Indicators by Type",
        f"{BASE_URL}/indicators?type=ip",
        headers=HEADERS,
        expected_status=200
    ))
    
    results.append(test_endpoint(
        "Filter Indicators by Threat Level",
        f"{BASE_URL}/indicators?threat_level=high",
        headers=HEADERS,
        expected_status=200
    ))
    
    results.append(test_endpoint(
        "Specific Indicator",
        f"{BASE_URL}/indicators/ioc_001",
        headers=HEADERS,
        expected_status=200
    ))
    
    results.append(test_endpoint(
        "All Threats",
        f"{BASE_URL}/threats",
        headers=HEADERS,
        expected_status=200
    ))
    
    results.append(test_endpoint(
        "Filter Threats by Severity",
        f"{BASE_URL}/threats?severity=critical",
        headers=HEADERS,
        expected_status=200
    ))
    
    results.append(test_endpoint(
        "Specific Threat",
        f"{BASE_URL}/threats/rpt_001",
        headers=HEADERS,
        expected_status=200
    ))
    
    # Test 404 errors
    results.append(test_endpoint(
        "Non-existent Source (should return 404)",
        f"{BASE_URL}/sources/invalid_id",
        headers=HEADERS,
        expected_status=404
    ))
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
