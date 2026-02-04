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
