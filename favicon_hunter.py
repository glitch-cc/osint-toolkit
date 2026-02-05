#!/usr/bin/env python3
"""
Favicon Hunter - OSINT tool for infrastructure discovery via favicon hashes

Fetches a website's favicon, calculates its MMH3 hash, and searches
Censys/Shodan for related infrastructure sharing the same favicon.

Use cases:
- Find origin IPs behind CDNs
- Discover staging/dev servers
- Identify related subdomains
- Detect phishing sites using copied favicons
"""

import argparse
import codecs
import hashlib
import json
import os
import re
import subprocess
import sys
from urllib.parse import urljoin, urlparse

import mmh3
import requests

# Disable SSL warnings for sketchy targets
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_favicon(url: str, timeout: int = 10) -> bytes | None:
    """Fetch favicon from a URL, trying multiple common locations."""
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    # Try to find favicon link in HTML first
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
        if resp.status_code == 200:
            # Look for favicon in HTML
            patterns = [
                r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']',
                r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut )?icon["\']',
            ]
            for pattern in patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match:
                    favicon_url = urljoin(url, match.group(1))
                    favicon_resp = requests.get(favicon_url, headers=headers, 
                                               timeout=timeout, verify=False)
                    if favicon_resp.status_code == 200 and len(favicon_resp.content) > 0:
                        return favicon_resp.content
    except Exception as e:
        print(f"[!] Error fetching HTML: {e}", file=sys.stderr)
    
    # Try common favicon locations
    favicon_paths = [
        '/favicon.ico',
        '/favicon.png',
        '/apple-touch-icon.png',
        '/apple-touch-icon-precomposed.png',
    ]
    
    for path in favicon_paths:
        try:
            favicon_url = base_url + path
            resp = requests.get(favicon_url, headers=headers, timeout=timeout, verify=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                # Basic validation - check for image magic bytes
                content = resp.content
                if (content[:4] == b'\x00\x00\x01\x00' or  # ICO
                    content[:8] == b'\x89PNG\r\n\x1a\n' or  # PNG
                    content[:2] == b'\xff\xd8' or  # JPEG
                    content[:6] in (b'GIF87a', b'GIF89a')):  # GIF
                    return content
                # Also accept if content-type indicates image
                if 'image' in resp.headers.get('content-type', ''):
                    return content
        except Exception:
            continue
    
    return None


def calculate_favicon_hash(favicon_data: bytes) -> dict:
    """Calculate multiple hashes of favicon for different search engines."""
    # MMH3 hash (Shodan) - base64 encode then hash
    favicon_b64 = codecs.encode(favicon_data, "base64")
    mmh3_hash = mmh3.hash(favicon_b64)
    
    # MD5 hash (Censys)
    md5_hash = hashlib.md5(favicon_data).hexdigest()
    
    # SHA256 hash (some tools)
    sha256_hash = hashlib.sha256(favicon_data).hexdigest()
    
    return {
        'mmh3': mmh3_hash,
        'md5': md5_hash,
        'sha256': sha256_hash
    }


def search_censys(sha256_hash: str, limit: int = 25) -> list:
    """Search Censys for hosts with matching favicon SHA256 hash using cencli."""
    
    # Censys uses SHA256 for favicon hashes
    query = f'host.services.endpoints.http.favicons.hash_sha256:{sha256_hash}'
    
    try:
        result = subprocess.run(
            ['cencli', 'search', query, '-n', str(limit), '-O', 'json'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            # Parse JSON output - skip the status line at the beginning
            output = result.stdout.strip()
            
            # Find the start of the JSON array
            json_start = output.find('[')
            if json_start == -1:
                return []
            
            json_str = output[json_start:]
            
            try:
                data = json.loads(json_str)
                hosts = []
                for item in data:
                    if 'host' in item:
                        hosts.append(item['host'])
                    elif 'ip' in item:
                        hosts.append(item)
                return hosts
            except json.JSONDecodeError:
                # Try line-by-line parsing as fallback
                hosts = []
                for line in output.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('200'):
                        continue
                    try:
                        data = json.loads(line)
                        if 'ip' in data:
                            hosts.append(data)
                        elif 'host' in data:
                            hosts.append(data['host'])
                    except json.JSONDecodeError:
                        continue
                return hosts
        else:
            err = result.stderr or result.stdout
            if err and 'not found' not in err.lower() and '200' not in err:
                print(f"[!] Censys search note: {err[:200]}", file=sys.stderr)
            return []
    except FileNotFoundError:
        print("[!] cencli not found. Install from: https://github.com/censys/cencli", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print("[!] Censys search timed out", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[!] Censys search failed: {e}", file=sys.stderr)
        return []


def search_shodan(favicon_hash: int, api_key: str = None, limit: int = 25) -> list:
    """Search Shodan for hosts with matching favicon hash."""
    
    if not api_key:
        api_key = os.environ.get('SHODAN_API_KEY')
    
    if not api_key:
        print("[!] No Shodan API key found. Set SHODAN_API_KEY env var.", file=sys.stderr)
        print(f"[*] Manual search: https://www.shodan.io/search?query=http.favicon.hash%3A{favicon_hash}", 
              file=sys.stderr)
        return []
    
    try:
        url = "https://api.shodan.io/shodan/host/search"
        params = {
            'key': api_key,
            'query': f'http.favicon.hash:{favicon_hash}',
            'limit': limit
        }
        resp = requests.get(url, params=params, timeout=30)
        
        if resp.status_code == 200:
            data = resp.json()
            return data.get('matches', [])
        else:
            print(f"[!] Shodan API error: {resp.status_code}", file=sys.stderr)
            return []
    except Exception as e:
        print(f"[!] Shodan search failed: {e}", file=sys.stderr)
        return []


def search_fofa(favicon_hash: int) -> str:
    """Generate FOFA search query (manual - API requires membership)."""
    return f'icon_hash="{favicon_hash}"'


def format_results(results: list, source: str) -> None:
    """Format and print search results."""
    
    if not results:
        print(f"\n[{source}] No results found")
        return
    
    print(f"\n[{source}] Found {len(results)} hosts:\n")
    print("-" * 80)
    
    for r in results:
        if source == "Shodan":
            ip = r.get('ip_str', 'N/A')
            port = r.get('port', 'N/A')
            org = r.get('org', 'N/A')
            hostnames = ', '.join(r.get('hostnames', [])) or 'N/A'
            country = r.get('location', {}).get('country_name', 'N/A')
            
            print(f"  IP: {ip}:{port}")
            print(f"  Org: {org}")
            print(f"  Hostnames: {hostnames}")
            print(f"  Country: {country}")
            print("-" * 40)


def main():
    parser = argparse.ArgumentParser(
        description='Favicon Hunter - Find related infrastructure via favicon hashes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://target.com
  %(prog)s https://target.com --shodan
  %(prog)s --hash 1848946384 --shodan
  %(prog)s https://target.com -o results.json
        """
    )
    
    parser.add_argument('url', nargs='?', help='Target URL to fetch favicon from')
    parser.add_argument('--hash', '-H', type=int, help='Use pre-calculated MMH3 hash')
    parser.add_argument('--shodan', '-s', action='store_true', help='Search Shodan')
    parser.add_argument('--censys', '-c', action='store_true', help='Search Censys')
    parser.add_argument('--all', '-a', action='store_true', help='Search all engines')
    parser.add_argument('--limit', '-l', type=int, default=25, help='Max results (default: 25)')
    parser.add_argument('--output', '-o', help='Save results to JSON file')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Request timeout')
    parser.add_argument('--hash-only', action='store_true', help='Only calculate and print hash')
    
    args = parser.parse_args()
    
    if not args.url and not args.hash:
        parser.error("Either URL or --hash is required")
    
    hashes = {'mmh3': args.hash} if args.hash else None
    favicon_data = None
    
    # Fetch and hash favicon if URL provided
    if args.url:
        print(f"[*] Fetching favicon from: {args.url}")
        favicon_data = fetch_favicon(args.url, args.timeout)
        
        if not favicon_data:
            print("[!] Could not fetch favicon", file=sys.stderr)
            sys.exit(1)
        
        print(f"[+] Favicon fetched: {len(favicon_data)} bytes")
        hashes = calculate_favicon_hash(favicon_data)
    
    print(f"\n[+] Favicon Hashes:")
    print(f"    MMH3:   {hashes['mmh3']}")
    if 'md5' in hashes:
        print(f"    MD5:    {hashes['md5']}")
    if 'sha256' in hashes:
        print(f"    SHA256: {hashes['sha256']}")
    
    print(f"\n[+] Search Queries:")
    print(f"    Shodan: http.favicon.hash:{hashes['mmh3']}")
    if 'sha256' in hashes:
        print(f"    Censys: host.services.endpoints.http.favicons.hash_sha256:{hashes['sha256']}")
    print(f"    FOFA:   {search_fofa(hashes['mmh3'])}")
    print(f"\n[+] Shodan URL: https://www.shodan.io/search?query=http.favicon.hash%3A{hashes['mmh3']}")
    
    if args.hash_only:
        sys.exit(0)
    
    results = {
        'hashes': hashes,
        'source_url': args.url,
        'shodan': [],
        'censys': [],
    }
    
    # Enable all searches if --all flag
    search_shodan_flag = args.shodan or args.all
    search_censys_flag = args.censys or args.all
    
    # Search Shodan
    if search_shodan_flag:
        print("\n[*] Searching Shodan...")
        shodan_results = search_shodan(hashes['mmh3'], limit=args.limit)
        results['shodan'] = shodan_results
        format_results(shodan_results, "Shodan")
    
    # Search Censys
    if search_censys_flag and 'sha256' in hashes:
        print("\n[*] Searching Censys...")
        censys_results = search_censys(hashes['sha256'], limit=args.limit)
        results['censys'] = censys_results
        if censys_results:
            print(f"\n[Censys] Found {len(censys_results)} hosts:\n")
            print("-" * 80)
            for host in censys_results:
                ip = host.get('ip', 'N/A')
                asn = host.get('autonomous_system', {})
                print(f"  IP: {ip}")
                print(f"  ASN: {asn.get('asn', 'N/A')} ({asn.get('name', 'N/A')})")
                print(f"  Location: {host.get('location', {}).get('country', 'N/A')}")
                print("-" * 40)
        else:
            print("\n[Censys] No results found")
    
    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Results saved to: {args.output}")
    
    return results


if __name__ == '__main__':
    main()
