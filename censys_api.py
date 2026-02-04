#!/usr/bin/env python3
"""
Censys Platform API v3 Integration
Uses Bearer token (PAT) authentication
"""
import os
import requests
from typing import Dict, Any, List

CENSYS_TOKEN = os.environ.get('CENSYS_API_KEY', '')
CENSYS_ORG_ID = os.environ.get('CENSYS_ORG_ID', 'a33e6dee-618d-4694-bdd2-dc9fa59d98c5')
BASE_URL = "https://api.platform.censys.io/v3"

def get_headers():
    return {
        "Authorization": f"Bearer {CENSYS_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

def censys_host_lookup(ip: str) -> Dict[str, Any]:
    """Look up host via Censys Platform API v3"""
    if not CENSYS_TOKEN:
        return {"error": "No CENSYS_API_KEY configured"}
    
    try:
        response = requests.get(
            f"{BASE_URL}/global/asset/host/{ip}",
            params={"organization_id": CENSYS_ORG_ID},
            headers=get_headers(),
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        return {"error": str(e)}

def censys_search(query: str, page_size: int = 10) -> Dict[str, Any]:
    """Search Censys Platform API"""
    if not CENSYS_TOKEN:
        return {"error": "No CENSYS_API_KEY configured"}
    
    try:
        response = requests.post(
            f"{BASE_URL}/global/search/query",
            params={"organization_id": CENSYS_ORG_ID},
            headers=get_headers(),
            json={"query": query, "page_size": page_size},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except Exception as e:
        return {"error": str(e)}

def censys_host_summary(ip: str) -> Dict[str, Any]:
    """Get a summary of host info"""
    result = censys_host_lookup(ip)
    if "error" in result:
        return result
    
    resource = result.get("result", {}).get("resource", {})
    return {
        "ip": resource.get("ip"),
        "location": {
            "country": resource.get("location", {}).get("country"),
            "city": resource.get("location", {}).get("city"),
        },
        "asn": resource.get("autonomous_system", {}).get("asn"),
        "org": resource.get("autonomous_system", {}).get("name"),
        "whois_org": resource.get("whois", {}).get("organization", {}).get("name"),
    }

if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) > 1:
        ip = sys.argv[1]
        print(f"Looking up {ip}...")
        result = censys_host_summary(ip)
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python3 censys_api.py <ip>")
        print("\nTesting with 8.8.8.8...")
        result = censys_host_summary("8.8.8.8")
        print(json.dumps(result, indent=2))
