#!/usr/bin/env python3
"""
OSINT MCP Tools - Core Module
Provides unified interface for various OSINT data sources
"""

import os
import json
import subprocess
import requests
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from datetime import datetime

# Load API keys
def load_env():
    env_file = "/root/.openclaw/.secure/keys.env"
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value

load_env()

PERPLEXITY_API_KEY = os.environ.get('PERPLEXITY_API_KEY')
HUNTER_API_KEY = os.environ.get('HUNTER_API_KEY')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')
RAPIDAPI_KEY = os.environ.get('RAPIDAPI_KEY')
APOLLO_API_KEY = os.environ.get('APOLLO_API_KEY')

@dataclass
class PersonBrief:
    name: str
    company: Optional[str] = None
    role: Optional[str] = None
    background: Optional[str] = None
    social_profiles: List[str] = None
    email_services: List[str] = None
    sources: List[str] = None
    
@dataclass
class CompanyBrief:
    name: str
    description: Optional[str] = None
    headquarters: Optional[str] = None
    employees: Optional[str] = None
    leadership: List[str] = None
    recent_news: List[str] = None
    domain_info: Dict[str, Any] = None
    sec_data: Dict[str, Any] = None
    sources: List[str] = None

def perplexity_query(prompt: str) -> Dict[str, Any]:
    """Query Perplexity API for real-time intelligence"""
    if not PERPLEXITY_API_KEY:
        return {"error": "No Perplexity API key configured"}
    
    response = requests.post(
        "https://api.perplexity.ai/chat/completions",
        headers={
            "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "model": "sonar",
            "messages": [{"role": "user", "content": prompt}]
        },
        timeout=30
    )
    
    if response.status_code == 200:
        data = response.json()
        return {
            "content": data['choices'][0]['message']['content'],
            "citations": data.get('citations', []),
            "cost": data.get('usage', {}).get('cost', {}).get('total_cost', 0)
        }
    else:
        return {"error": f"API error: {response.status_code}"}

def hunter_domain_search(domain: str, limit: int = 10) -> Dict[str, Any]:
    """Search for emails at a domain using Hunter.io"""
    if not HUNTER_API_KEY:
        return {"error": "No Hunter API key configured"}
    
    response = requests.get(
        f"https://api.hunter.io/v2/domain-search",
        params={"domain": domain, "api_key": HUNTER_API_KEY, "limit": limit},
        timeout=30
    )
    
    if response.status_code == 200:
        data = response.json()
        return {
            "domain": data['data'].get('domain'),
            "organization": data['data'].get('organization'),
            "total_emails": data['meta'].get('results', 0),
            "pattern": data['data'].get('pattern'),
            "emails": [
                {
                    "email": e.get('value'),
                    "name": f"{e.get('first_name', '')} {e.get('last_name', '')}".strip(),
                    "position": e.get('position'),
                    "department": e.get('department'),
                    "confidence": e.get('confidence')
                }
                for e in data['data'].get('emails', [])[:limit]
            ]
        }
    else:
        return {"error": f"Hunter API error: {response.status_code}"}

def hunter_email_finder(domain: str, first_name: str, last_name: str) -> Dict[str, Any]:
    """Find specific person's email at a company"""
    if not HUNTER_API_KEY:
        return {"error": "No Hunter API key configured"}
    
    response = requests.get(
        f"https://api.hunter.io/v2/email-finder",
        params={
            "domain": domain,
            "first_name": first_name,
            "last_name": last_name,
            "api_key": HUNTER_API_KEY
        },
        timeout=30
    )
    
    if response.status_code == 200:
        data = response.json()['data']
        return {
            "email": data.get('email'),
            "confidence": data.get('score'),
            "position": data.get('position'),
            "sources": len(data.get('sources', []))
        }
    else:
        return {"error": f"Hunter API error: {response.status_code}"}

def shodan_host_lookup(ip: str) -> Dict[str, Any]:
    """Look up an IP address in Shodan"""
    if not SHODAN_API_KEY:
        return {"error": "No Shodan API key configured"}
    
    response = requests.get(
        f"https://api.shodan.io/shodan/host/{ip}",
        params={"key": SHODAN_API_KEY},
        timeout=30
    )
    
    if response.status_code == 200:
        data = response.json()
        return {
            "ip": data.get('ip_str'),
            "organization": data.get('org'),
            "asn": data.get('asn'),
            "isp": data.get('isp'),
            "hostnames": data.get('hostnames', []),
            "ports": data.get('ports', []),
            "country": data.get('country_name'),
            "city": data.get('city'),
            "vulns": data.get('vulns', []),
            "last_update": data.get('last_update')
        }
    elif response.status_code == 404:
        return {"error": "IP not found in Shodan"}
    else:
        return {"error": f"Shodan API error: {response.status_code}"}

def apollo_company_enrich(domain: str) -> Dict[str, Any]:
    """Enrich company data from Apollo.io"""
    if not APOLLO_API_KEY:
        return {"error": "No Apollo API key configured"}
    
    try:
        response = requests.post(
            "https://api.apollo.io/api/v1/organizations/enrich",
            headers={
                "Content-Type": "application/json",
                "X-Api-Key": APOLLO_API_KEY
            },
            json={"domain": domain},
            timeout=30
        )
        
        if response.status_code == 200:
            org = response.json().get('organization', {})
            return {
                "name": org.get('name'),
                "website": org.get('website_url'),
                "linkedin": org.get('linkedin_url'),
                "twitter": org.get('twitter_url'),
                "employees": org.get('estimated_num_employees'),
                "industry": org.get('industry'),
                "founded": org.get('founded_year'),
                "description": org.get('short_description'),
                "city": org.get('city'),
                "state": org.get('state'),
                "country": org.get('country'),
                "phone": org.get('phone'),
                "annual_revenue": org.get('annual_revenue_printed'),
                "technologies": org.get('technologies', [])[:15] if org.get('technologies') else None,
                "keywords": org.get('keywords', [])[:10] if org.get('keywords') else None
            }
        else:
            return {"error": f"Apollo API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def apollo_person_match(first_name: str, last_name: str, organization: str = None, domain: str = None) -> Dict[str, Any]:
    """Match a person in Apollo.io database"""
    if not APOLLO_API_KEY:
        return {"error": "No Apollo API key configured"}
    
    payload = {
        "first_name": first_name,
        "last_name": last_name
    }
    if organization:
        payload["organization_name"] = organization
    if domain:
        payload["domain"] = domain
    
    try:
        response = requests.post(
            "https://api.apollo.io/api/v1/people/match",
            headers={
                "Content-Type": "application/json",
                "X-Api-Key": APOLLO_API_KEY
            },
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            person = response.json().get('person', {})
            org = person.get('organization', {})
            return {
                "name": person.get('name'),
                "title": person.get('title'),
                "email": person.get('email'),
                "linkedin": person.get('linkedin_url'),
                "city": person.get('city'),
                "state": person.get('state'),
                "country": person.get('country'),
                "company": org.get('name'),
                "company_size": org.get('estimated_num_employees'),
                "company_industry": org.get('industry')
            }
        else:
            return {"error": f"Apollo API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def shodan_domain_lookup(domain: str) -> Dict[str, Any]:
    """Look up a domain in Shodan DNS"""
    if not SHODAN_API_KEY:
        return {"error": "No Shodan API key configured"}
    
    response = requests.get(
        f"https://api.shodan.io/dns/domain/{domain}",
        params={"key": SHODAN_API_KEY},
        timeout=30
    )
    
    if response.status_code == 200:
        data = response.json()
        return {
            "domain": data.get('domain'),
            "subdomains": data.get('subdomains', [])[:20],
            "records": data.get('data', [])[:10]
        }
    else:
        return {"error": f"Shodan API error: {response.status_code}"}

def reddit_user_lookup(username: str) -> Dict[str, Any]:
    """Look up a Reddit user's profile and recent activity"""
    headers = {"User-Agent": "OSINT-MCP/1.0"}
    
    try:
        # Get user profile
        profile_resp = requests.get(
            f"https://www.reddit.com/user/{username}/about.json",
            headers=headers, timeout=15
        )
        
        if profile_resp.status_code != 200:
            return {"error": f"User not found or API error: {profile_resp.status_code}"}
        
        profile = profile_resp.json()['data']
        
        # Get recent posts
        posts_resp = requests.get(
            f"https://www.reddit.com/user/{username}/submitted.json?limit=5",
            headers=headers, timeout=15
        )
        posts = []
        if posts_resp.status_code == 200:
            posts = [
                {
                    "title": p['data']['title'],
                    "subreddit": p['data']['subreddit'],
                    "score": p['data']['score']
                }
                for p in posts_resp.json()['data']['children'][:5]
            ]
        
        # Get recent comments
        comments_resp = requests.get(
            f"https://www.reddit.com/user/{username}/comments.json?limit=5",
            headers=headers, timeout=15
        )
        active_subreddits = []
        if comments_resp.status_code == 200:
            subs = [c['data']['subreddit'] for c in comments_resp.json()['data']['children']]
            active_subreddits = list(set(subs))[:10]
        
        return {
            "username": profile.get('name'),
            "created_utc": profile.get('created_utc'),
            "total_karma": profile.get('total_karma'),
            "comment_karma": profile.get('comment_karma'),
            "link_karma": profile.get('link_karma'),
            "is_mod": profile.get('is_mod'),
            "recent_posts": posts,
            "active_subreddits": active_subreddits
        }
    except Exception as e:
        return {"error": str(e)}

def twitter_user_lookup(username: str) -> Dict[str, Any]:
    """Look up Twitter/X user via RapidAPI (twitter-v24)"""
    if not RAPIDAPI_KEY:
        return {"error": "No RapidAPI key configured"}
    
    # Remove @ if present
    username = username.lstrip('@')
    
    try:
        response = requests.get(
            f"https://twitter-v24.p.rapidapi.com/user/details",
            params={"username": username},
            headers={
                "x-rapidapi-key": RAPIDAPI_KEY,
                "x-rapidapi-host": "twitter-v24.p.rapidapi.com"
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            user = data.get('data', {}).get('user', {}).get('result', {})
            legacy = user.get('legacy', {})
            
            return {
                "id": user.get('rest_id'),
                "name": legacy.get('name'),
                "username": legacy.get('screen_name'),
                "followers": legacy.get('followers_count'),
                "following": legacy.get('friends_count'),
                "tweets": legacy.get('statuses_count'),
                "bio": legacy.get('description'),
                "location": legacy.get('location'),
                "verified": user.get('is_blue_verified'),
                "created": legacy.get('created_at'),
                "profile_image": legacy.get('profile_image_url_https')
            }
        else:
            return {"error": f"Twitter API error: {response.status_code}", "body": response.text[:200]}
    except Exception as e:
        return {"error": str(e)}

def twitter_search(query: str, count: int = 10) -> List[Dict[str, Any]]:
    """Search Twitter/X via RapidAPI (twitter-v24)"""
    if not RAPIDAPI_KEY:
        return [{"error": "No RapidAPI key configured"}]
    
    try:
        response = requests.get(
            f"https://twitter-v24.p.rapidapi.com/search/search",
            params={"query": query, "count": str(count), "type": "Latest"},
            headers={
                "x-rapidapi-key": RAPIDAPI_KEY,
                "x-rapidapi-host": "twitter-v24.p.rapidapi.com"
            },
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            # Parse tweets from response
            tweets = []
            for entry in data.get('data', {}).get('search_by_raw_query', {}).get('search_timeline', {}).get('timeline', {}).get('instructions', []):
                if entry.get('type') == 'TimelineAddEntries':
                    for item in entry.get('entries', []):
                        content = item.get('content', {})
                        if content.get('entryType') == 'TimelineTimelineItem':
                            tweet_result = content.get('itemContent', {}).get('tweet_results', {}).get('result', {})
                            legacy = tweet_result.get('legacy', {})
                            user = tweet_result.get('core', {}).get('user_results', {}).get('result', {}).get('legacy', {})
                            if legacy:
                                tweets.append({
                                    "text": legacy.get('full_text'),
                                    "author": user.get('screen_name'),
                                    "likes": legacy.get('favorite_count'),
                                    "retweets": legacy.get('retweet_count'),
                                    "created": legacy.get('created_at')
                                })
            return tweets[:count]
        else:
            return [{"error": f"Twitter API error: {response.status_code}"}]
    except Exception as e:
        return [{"error": str(e)}]

def linkedin_lookup(name: str, company: Optional[str] = None) -> Dict[str, Any]:
    """Look up LinkedIn profile info via Perplexity (safe, no scraping)"""
    query = f"LinkedIn profile for {name}"
    if company:
        query += f" at {company}"
    query += ": current role, career history, education, skills. Be factual and concise."
    
    result = perplexity_query(query)
    return {
        "name": name,
        "company": company,
        "profile_summary": result.get('content'),
        "sources": result.get('citations', []),
        "note": "Data from public sources via Perplexity, not direct LinkedIn scraping"
    }

def linkedin_find(name: str, company: str = None) -> Dict[str, Any]:
    """Find LinkedIn profile URL from name (+ optional company) via Google search"""
    if not RAPIDAPI_KEY:
        return {"error": "No RapidAPI key configured"}
    
    try:
        payload = {"name": name}
        if company:
            payload["company"] = company
        
        response = requests.post(
            "https://fresh-linkedin-profile-data.p.rapidapi.com/google-profiles",
            headers={
                "x-rapidapi-key": RAPIDAPI_KEY,
                "x-rapidapi-host": "fresh-linkedin-profile-data.p.rapidapi.com",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            urls = data.get('data', [])
            return {
                "name": name,
                "company": company,
                "linkedin_urls": urls,
                "top_result": urls[0] if urls else None
            }
        else:
            return {"error": f"LinkedIn API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def linkedin_profile(linkedin_url: str) -> Dict[str, Any]:
    """Look up LinkedIn person profile via RapidAPI (Fresh LinkedIn Profile Data)"""
    if not RAPIDAPI_KEY:
        return {"error": "No RapidAPI key configured"}
    
    try:
        import urllib.parse
        encoded_url = urllib.parse.quote(linkedin_url, safe='')
        
        response = requests.get(
            f"https://fresh-linkedin-profile-data.p.rapidapi.com/enrich-lead?linkedin_url={encoded_url}&include_skills=true",
            headers={
                "x-rapidapi-key": RAPIDAPI_KEY,
                "x-rapidapi-host": "fresh-linkedin-profile-data.p.rapidapi.com"
            },
            timeout=45
        )
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                "name": data.get('full_name') or f"{data.get('first_name', '')} {data.get('last_name', '')}".strip(),
                "headline": data.get('headline'),
                "about": data.get('about'),
                "location": f"{data.get('city', '')}, {data.get('country', '')}".strip(', '),
                "connections": data.get('connection_count'),
                "current_company": data.get('company'),
                "current_title": data.get('experiences', [{}])[0].get('title') if data.get('experiences') else None,
                "company_size": data.get('company_employee_count'),
                "company_industry": data.get('company_industry'),
                "experience": [
                    {
                        "title": exp.get('title'),
                        "company": exp.get('company'),
                        "duration": exp.get('duration'),
                        "current": exp.get('is_current')
                    }
                    for exp in data.get('experiences', [])[:5]
                ],
                "education": [
                    {
                        "school": edu.get('school'),
                        "degree": edu.get('degree'),
                        "field": edu.get('field_of_study')
                    }
                    for edu in data.get('educations', [])[:3]
                ],
                "skills": data.get('skills', [])[:10] if data.get('skills') else None,
                "linkedin_url": linkedin_url
            }
        else:
            return {"error": f"LinkedIn API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def linkedin_company(linkedin_url: str = None, domain: str = None) -> Dict[str, Any]:
    """Look up LinkedIn company data via RapidAPI (Fresh LinkedIn Profile Data)"""
    if not RAPIDAPI_KEY:
        return {"error": "No RapidAPI key configured"}
    
    try:
        if linkedin_url:
            endpoint = f"https://fresh-linkedin-profile-data.p.rapidapi.com/get-company-by-linkedinurl?linkedin_url={linkedin_url}"
        elif domain:
            endpoint = f"https://fresh-linkedin-profile-data.p.rapidapi.com/get-company-by-domain?domain={domain}"
        else:
            return {"error": "Provide linkedin_url or domain"}
        
        response = requests.get(
            endpoint,
            headers={
                "x-rapidapi-key": RAPIDAPI_KEY,
                "x-rapidapi-host": "fresh-linkedin-profile-data.p.rapidapi.com"
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                "company_name": data.get('company_name'),
                "description": data.get('description'),
                "website": data.get('website'),
                "domain": data.get('domain'),
                "employee_count": data.get('employee_count'),
                "employee_range": data.get('employee_range'),
                "follower_count": data.get('follower_count'),
                "founded": data.get('year_founded'),
                "industry": data.get('industries', [None])[0] if data.get('industries') else None,
                "specialties": data.get('specialties'),
                "hq_location": data.get('hq_full_address'),
                "linkedin_url": data.get('linkedin_url'),
                "logo_url": data.get('logo_url')
            }
        else:
            return {"error": f"LinkedIn API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def sec_edgar_lookup(company_name: str) -> Dict[str, Any]:
    """Look up company in SEC EDGAR (US public companies)"""
    # This is a simplified lookup - would need CIK mapping for full implementation
    # For now, return placeholder
    return {
        "note": "SEC EDGAR lookup requires CIK number",
        "tip": "Use https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany to find CIK"
    }

def dns_lookup(domain: str) -> Dict[str, Any]:
    """Get DNS records for a domain"""
    records = {}
    
    record_types = ['A', 'MX', 'NS', 'TXT']
    for rtype in record_types:
        try:
            result = subprocess.run(
                ['dig', '+short', domain, rtype],
                capture_output=True, text=True, timeout=10
            )
            records[rtype] = result.stdout.strip().split('\n') if result.stdout.strip() else []
        except Exception as e:
            records[rtype] = [f"Error: {e}"]
    
    return records

def whois_lookup(domain: str) -> Dict[str, Any]:
    """Get WHOIS info for a domain"""
    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True, text=True, timeout=15
        )
        # Parse key fields
        whois_data = result.stdout
        parsed = {
            "raw": whois_data[:2000],  # Truncate for brevity
            "registrar": None,
            "creation_date": None,
            "expiry_date": None
        }
        
        for line in whois_data.split('\n'):
            line_lower = line.lower()
            if 'registrar:' in line_lower:
                parsed['registrar'] = line.split(':', 1)[1].strip()
            elif 'creation date:' in line_lower:
                parsed['creation_date'] = line.split(':', 1)[1].strip()
            elif 'expiry date:' in line_lower or 'expiration date:' in line_lower:
                parsed['expiry_date'] = line.split(':', 1)[1].strip()
        
        return parsed
    except Exception as e:
        return {"error": str(e)}

def sherlock_lookup(username: str, timeout: int = 30) -> List[str]:
    """Search for username across social networks"""
    try:
        result = subprocess.run(
            ['/root/.local/bin/sherlock', username, '--timeout', '5', '--print-found'],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, 'PATH': os.environ.get('PATH', '') + ':/root/.local/bin'}
        )
        
        # Parse found profiles
        profiles = []
        for line in result.stdout.split('\n'):
            if line.startswith('[+]'):
                profiles.append(line.replace('[+] ', ''))
        
        return profiles[:20]  # Limit to top 20
    except subprocess.TimeoutExpired:
        return ["Timeout - search took too long"]
    except Exception as e:
        return [f"Error: {e}"]

def holehe_lookup(email: str) -> List[str]:
    """Check which services an email is registered with"""
    try:
        result = subprocess.run(
            ['/root/.local/bin/holehe', email],
            capture_output=True, text=True, timeout=60,
            env={**os.environ, 'PATH': os.environ.get('PATH', '') + ':/root/.local/bin'}
        )
        
        # Parse found services
        services = []
        for line in result.stdout.split('\n'):
            if line.startswith('[+]'):
                services.append(line.replace('[+] ', '').strip())
        
        return services
    except Exception as e:
        return [f"Error: {e}"]

def company_brief(company: str, domain: Optional[str] = None) -> CompanyBrief:
    """Generate comprehensive company brief"""
    
    # Perplexity for general intel
    pplx = perplexity_query(f"""Brief on {company}:
- What they do (1-2 sentences)
- Headquarters location
- Approximate employee count
- Key leadership (CEO, founders)
- Any recent news or funding
Be factual and concise.""")
    
    brief = CompanyBrief(
        name=company,
        description=pplx.get('content'),
        sources=pplx.get('citations', [])
    )
    
    # Add domain intel if provided
    if domain:
        brief.domain_info = {
            "dns": dns_lookup(domain),
            "whois": whois_lookup(domain)
        }
    
    return brief

def person_brief(name: str, company: Optional[str] = None, 
                 email: Optional[str] = None, 
                 username: Optional[str] = None) -> PersonBrief:
    """Generate comprehensive person brief"""
    
    # Build query
    query_parts = [f"Brief on {name}"]
    if company:
        query_parts.append(f"at {company}")
    query_parts.append(": their role, background, recent activity. Be concise.")
    
    pplx = perplexity_query(' '.join(query_parts))
    
    brief = PersonBrief(
        name=name,
        company=company,
        background=pplx.get('content'),
        sources=pplx.get('citations', [])
    )
    
    # Add social profiles if username provided
    if username:
        brief.social_profiles = sherlock_lookup(username)
    
    # Add email services if email provided
    if email:
        brief.email_services = holehe_lookup(email)
    
    return brief

def quick_brief(target: str, context: Optional[str] = None) -> str:
    """Quick 30-second brief for live calls"""
    
    prompt = f"""30-second networking brief on {target}"""
    if context:
        prompt += f" ({context})"
    prompt += """:
- Who they are / their role
- Key facts (company, background)
- 2 conversation starters
Maximum 100 words. Be direct."""

    result = perplexity_query(prompt)
    return result.get('content', 'Unable to generate brief')


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python osint_tools.py <command> [args]")
        print("Commands: company, person, quick, dns, whois, sherlock, holehe")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == "company" and len(sys.argv) >= 3:
        company = sys.argv[2]
        domain = sys.argv[3] if len(sys.argv) > 3 else None
        result = company_brief(company, domain)
        print(json.dumps(asdict(result), indent=2, default=str))
    
    elif cmd == "person" and len(sys.argv) >= 3:
        name = sys.argv[2]
        company = sys.argv[3] if len(sys.argv) > 3 else None
        result = person_brief(name, company)
        print(json.dumps(asdict(result), indent=2, default=str))
    
    elif cmd == "quick" and len(sys.argv) >= 3:
        target = ' '.join(sys.argv[2:])
        print(quick_brief(target))
    
    elif cmd == "dns" and len(sys.argv) >= 3:
        print(json.dumps(dns_lookup(sys.argv[2]), indent=2))
    
    elif cmd == "whois" and len(sys.argv) >= 3:
        print(json.dumps(whois_lookup(sys.argv[2]), indent=2))
    
    elif cmd == "sherlock" and len(sys.argv) >= 3:
        print(json.dumps(sherlock_lookup(sys.argv[2]), indent=2))
    
    elif cmd == "holehe" and len(sys.argv) >= 3:
        print(json.dumps(holehe_lookup(sys.argv[2]), indent=2))
    
    elif cmd == "hunter" and len(sys.argv) >= 3:
        print(json.dumps(hunter_domain_search(sys.argv[2]), indent=2))
    
    elif cmd == "hunter-find" and len(sys.argv) >= 5:
        # hunter-find domain first_name last_name
        print(json.dumps(hunter_email_finder(sys.argv[2], sys.argv[3], sys.argv[4]), indent=2))
    
    elif cmd == "shodan" and len(sys.argv) >= 3:
        print(json.dumps(shodan_host_lookup(sys.argv[2]), indent=2))
    
    elif cmd == "shodan-domain" and len(sys.argv) >= 3:
        print(json.dumps(shodan_domain_lookup(sys.argv[2]), indent=2))
    
    elif cmd == "reddit" and len(sys.argv) >= 3:
        print(json.dumps(reddit_user_lookup(sys.argv[2]), indent=2))
    
    elif cmd == "twitter" and len(sys.argv) >= 3:
        print(json.dumps(twitter_user_lookup(sys.argv[2]), indent=2))
    
    elif cmd == "twitter-search" and len(sys.argv) >= 3:
        query = ' '.join(sys.argv[2:])
        print(json.dumps(twitter_search(query), indent=2))
    
    elif cmd == "linkedin" and len(sys.argv) >= 3:
        name = sys.argv[2]
        company = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(linkedin_lookup(name, company), indent=2))
    
    elif cmd == "linkedin-find" and len(sys.argv) >= 3:
        name = sys.argv[2]
        company = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(linkedin_find(name, company), indent=2))
    
    elif cmd == "linkedin-profile" and len(sys.argv) >= 3:
        print(json.dumps(linkedin_profile(sys.argv[2]), indent=2))
    
    elif cmd == "linkedin-company" and len(sys.argv) >= 3:
        arg = sys.argv[2]
        if arg.startswith("http"):
            print(json.dumps(linkedin_company(linkedin_url=arg), indent=2))
        else:
            print(json.dumps(linkedin_company(domain=arg), indent=2))
    
    elif cmd == "apollo-company" and len(sys.argv) >= 3:
        print(json.dumps(apollo_company_enrich(sys.argv[2]), indent=2))
    
    elif cmd == "apollo-person" and len(sys.argv) >= 4:
        # apollo-person FirstName LastName [Company]
        first = sys.argv[2]
        last = sys.argv[3]
        company = sys.argv[4] if len(sys.argv) > 4 else None
        print(json.dumps(apollo_person_match(first, last, organization=company), indent=2))
    
    else:
        print(f"Unknown command or missing args: {cmd}")
        print("Commands: company, person, quick, dns, whois, sherlock, holehe,")
        print("          hunter, hunter-find, shodan, shodan-domain,")
        print("          reddit, twitter, twitter-search, linkedin,")
        print("          linkedin-find, linkedin-profile, linkedin-company,")
        print("          apollo-company, apollo-person")
        sys.exit(1)


# --- Censys Integration ---
CENSYS_API_ID = os.environ.get('CENSYS_API_ID')
CENSYS_API_SECRET = os.environ.get('CENSYS_API_SECRET')

def censys_host_lookup(ip: str) -> Dict[str, Any]:
    """Look up host information via Censys"""
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return {"error": "No Censys API credentials configured"}
    try:
        from censys.search import CensysHosts
        h = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
        return h.view(ip)
    except Exception as e:
        return {"error": str(e)}

def censys_search(query: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Search Censys for hosts matching query"""
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return [{"error": "No Censys API credentials configured"}]
    try:
        from censys.search import CensysHosts
        h = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
        results = []
        for page in h.search(query, per_page=limit, pages=1):
            results.extend(page)
        return results[:limit]
    except Exception as e:
        return [{"error": str(e)}]
