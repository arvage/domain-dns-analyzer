#!/usr/bin/env python
"""
Test script for the Domain DNS Analyzer API
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import requests
import json

def test_api():
    """Test the API endpoint"""
    
    # Test domains
    test_domains = [
        "google.com",
        "microsoft.com", 
        "github.com"
    ]
    
    # API endpoint
    url = "http://localhost:8080/api/analyze"
    
    # Request data
    data = {
        "domains": test_domains
    }
    
    try:
        print("Testing Domain DNS Analyzer API...")
        print(f"URL: {url}")
        print(f"Domains: {test_domains}")
        print()
        
        # Send request
        response = requests.post(url, json=data, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            print("✅ API Test Successful!")
            print(f"📊 Summary:")
            print(f"  - Total domains: {result['summary']['total_analyzed']}")
            print(f"  - With DMARC: {result['summary']['domains_with_dmarc_policy']}")
            print(f"  - With websites: {result['summary']['domains_with_websites']}")
            print()
            
            print("📋 Results:")
            for domain_result in result['results']:
                domain = domain_result['domain']
                dmarc = "✅" if domain_result['has_dmarc_policy'] else "❌"
                website = "✅" if domain_result['has_website'] else "❌"
                print(f"  {domain}: DMARC {dmarc}, Website {website}")
                
        else:
            print(f"❌ API Test Failed!")
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection Error: Is the server running on http://localhost:8080?")
    except Exception as e:
        print(f"❌ Test Error: {e}")

def test_health():
    """Test the health endpoint"""
    try:
        response = requests.get("http://localhost:8080/health", timeout=10)
        if response.status_code == 200:
            print("✅ Health Check: Server is running")
        else:
            print(f"❌ Health Check Failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Health Check Error: {e}")

if __name__ == "__main__":
    print("=" * 50)
    print("Domain DNS Analyzer - API Test")
    print("=" * 50)
    print()
    
    # Test health first
    test_health()
    print()
    
    # Test main API
    test_api()