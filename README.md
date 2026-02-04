# OSINT Toolkit

Automated Open Source Intelligence gathering from 200+ public data sources.

## 🎯 Features

- **Person Briefs** - Comprehensive dossiers on individuals
- **Company Briefs** - Full company intelligence
- **Infrastructure Scanning** - Domain, IP, and network reconnaissance
- **Social Media** - Username and profile discovery
- **Email OSINT** - Email verification and account discovery

## 🛠️ Tools Included

### Docker Services
- **SpiderFoot** - Web UI for automated OSINT (localhost:5001)
- **theHarvester** - Email/subdomain/IP discovery

### CLI Tools
- **Sherlock** - Username search across 400+ sites
- **Holehe** - Email account discovery

### API Integrations
- Hunter.io - Email finder
- Shodan - Infrastructure scanning
- Apollo - Company/person enrichment
- LinkedIn (RapidAPI) - Profile lookup
- Perplexity - AI web intelligence

## 📦 Installation

```bash
# Clone
git clone git@github.com:glitch-cc/osint-toolkit.git
cd osint-toolkit

# Set up API keys
cp .env.example .env
# Edit .env with your API keys

# Install Python dependencies
pip install -r requirements.txt
```

## 🚀 Usage

```bash
# Person investigation
python osint_tools.py person-brief "John Doe" --company "Acme Corp"

# Company investigation
python osint_tools.py company-brief "Acme Corp" --domain acme.com

# Quick auto-detect
python osint_tools.py quick-brief "target"

# theHarvester
theharvester -d example.com -b all -l 100
```

## 📋 Project Tracking

See our [Notion page](https://www.notion.so/OSINT-Toolkit-Project-2fdf8941c8ba8187a690e0d48280a082) for implementation status.

## 👤 Owner

**Glitch** (glitch@datahp.ai) - Digital gremlin at Cyrenity

---
Built with ⚡ by Glitch

## 🆕 New Tools (Phase 2)

### Maigret
Enhanced username search across 500+ sites (better than Sherlock):
```bash
maigret <username>           # Quick search (top 500 sites)
maigret -a <username>        # Full search (all sites)
maigret --json <username>    # JSON output
```

### Phoneinfoga
Phone number OSINT:
```bash
phoneinfoga scan -n "+15551234567"
phoneinfoga serve            # Web UI on port 5000
```

### AMASS (OWASP)
Attack surface mapping and subdomain discovery:
```bash
amass enum -d example.com           # Basic enum
amass enum -d example.com -passive  # Passive only
amass enum -d example.com -active   # Active enum
amass intel -d example.com          # Intel gathering
```

### Recon-ng
Modular web reconnaissance framework:
```bash
recon-ng                           # Start shell
# marketplace search              # Find modules
# marketplace install all         # Install all
```

### Censys (API Required)
Internet-wide scanning and host intelligence:
```bash
# Set credentials first
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"

# Then use via osint_tools.py
python3 osint_tools.py censys-host 8.8.8.8
python3 osint_tools.py censys-search "services.service_name: SSH"
```
Get free API keys at: https://search.censys.io/account/api

## 📊 Reporting

Generate formatted reports from OSINT data:

```bash
# Generate Markdown report
python3 report_generator.py "target" -f md -o report.md

# Generate JSON report
python3 report_generator.py "target" -i data.json -f json -o report.json

# Generate HTML report
python3 report_generator.py "target" -i data.json -f html -o report.html
```

### Censys Platform API v3
Host lookup and search (requires PAT + Org ID):
```bash
export CENSYS_API_KEY="censys_xxx"
export CENSYS_ORG_ID="your-org-id"

python3 censys_api.py 8.8.8.8
```
