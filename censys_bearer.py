#!/usr/bin/env python3
"""
Censys API with Bearer token (new PAT format)
"""
import os
import requests
from typing import Dict, Any, List

CENSYS_API_KEY = os.environ.get('CENSYS_API_KEY', '')
BASE_URL = "https://search.censys.io/api"

def get_headers():
    return {
        "Authorization": f"Bearer {CENSYS_API_KEY}",
        "Accept": "application/json"
    }

def censys_host_lookup(ip: str) -> Dict[str, Any]:
    """Look up host via Censys API"""
    if not CENSYS_API_KEY:
        return {"error": "No CENSYS_API_KEY configured"}
    
    try:
        # Try the v2 API
        response = requests.get(
            f"{BASE_URL}/v2/hosts/{ip}",
            headers=get_headers(),
            timeout=30
        )
        
        if response.status_code == 401:
            # Bearer might not work for search API yet
            return {"error": "Censys Search API requires legacy API ID/Secret (not PAT)", 
                    "note": "PAT works for data.censys.io only"}
        
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def censys_data_api(endpoint: str) -> Dict[str, Any]:
    """Query Censys Data API (works with PAT)"""
    if not CENSYS_API_KEY:
        return {"error": "No CENSYS_API_KEY configured"}
    
    try:
        response = requests.get(
            f"https://data.censys.io/api/v1/{endpoint}",
            headers=get_headers(),
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import sys
    os.environ['CENSYS_API_KEY'] = 'censys_N23VLEdH_4nhCLpn683R91J9TJDLFBHMy'
    
    if len(sys.argv) > 1:
        ip = sys.argv[1]
        print(f"Looking up {ip}...")
        result = censys_host_lookup(ip)
        print(result)
    else:
        print("Testing Data API...")
        result = censys_data_api("datasets")
        print(result)
