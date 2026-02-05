# OSINT MCP Toolkit

Collection of OSINT tools for the OpenClaw workspace.

## Tools

### favicon_hunter.py
**Favicon Hash OSINT** - Find related infrastructure via favicon fingerprinting.

Fetches a website's favicon, calculates multiple hashes (MMH3, MD5, SHA256), and searches Censys/Shodan for hosts using the same favicon.

**Use Cases:**
- Find origin IPs behind CDNs
- Discover staging/dev servers and shadow IT
- Identify related subdomains and infrastructure
- Detect phishing sites using copied favicons

**Usage:**
```bash
# Activate venv first
source venv/bin/activate

# Hash only (no search)
python favicon_hunter.py https://target.com --hash-only

# Search Censys
python favicon_hunter.py https://target.com --censys

# Search Shodan (requires SHODAN_API_KEY env)
python favicon_hunter.py https://target.com --shodan

# Search both
python favicon_hunter.py https://target.com --all

# Save results
python favicon_hunter.py https://target.com --censys -o results.json

# Use pre-calculated hash
python favicon_hunter.py --hash 1848946384 --shodan
```

**Requirements:**
- Python 3.10+
- mmh3, requests (in venv)
- cencli (for Censys search)
- SHODAN_API_KEY env var (for Shodan search)

---

### osint_tools.py
LinkedIn scraper, people search, company lookup tools.

See `python osint_tools.py --help` for usage.

---

## Setup

```bash
cd /root/.openclaw/workspace/projects/osint-mcp
python3 -m venv venv
source venv/bin/activate
pip install mmh3 requests
```

## API Keys

Store in `/root/.openclaw/.secure/keys.env`:
- `SHODAN_API_KEY`
- `RAPIDAPI_KEY` (for LinkedIn)
- `HUNTER_API_KEY`
- etc.
