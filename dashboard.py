#!/usr/bin/env python3
"""
OSINT Dashboard - Unified web interface for all OSINT tools
"""

from flask import Flask, render_template_string, request, jsonify
import subprocess
import json
import os

app = Flask(__name__)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>⚡ Glitch OSINT Dashboard</title>
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0f; color: #f4f4f5; margin: 0; padding: 20px;
        }
        .header { text-align: center; padding: 20px; border-bottom: 1px solid #333; margin-bottom: 20px; }
        .header h1 { color: #6B5CE7; margin: 0; }
        .header p { color: #888; }
        .container { max-width: 1200px; margin: 0 auto; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }
        .card { background: #111116; border: 1px solid #333; border-radius: 8px; padding: 20px; }
        .card h3 { color: #6B5CE7; margin-top: 0; border-bottom: 1px solid #333; padding-bottom: 10px; }
        input, select { 
            width: 100%; padding: 10px; margin: 5px 0 15px 0;
            background: #1a1a1f; border: 1px solid #333; border-radius: 4px;
            color: #fff; font-size: 14px;
        }
        button { 
            background: #6B5CE7; color: white; border: none; padding: 12px 20px;
            border-radius: 4px; cursor: pointer; font-size: 14px; width: 100%;
        }
        button:hover { background: #5a4bd6; }
        .result { 
            background: #0a0a0f; border: 1px solid #333; border-radius: 4px;
            padding: 15px; margin-top: 15px; max-height: 300px; overflow-y: auto;
            font-family: monospace; font-size: 12px; white-space: pre-wrap;
        }
        .tools-status { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; }
        .tool-badge { 
            background: #1a1a1f; padding: 5px 10px; border-radius: 4px;
            font-size: 12px; border: 1px solid #333;
        }
        .tool-badge.active { border-color: #4ade80; color: #4ade80; }
        .loading { opacity: 0.5; pointer-events: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ Glitch OSINT Dashboard</h1>
            <p>Unified interface for all OSINT tools</p>
            <div class="tools-status">
                <span class="tool-badge active">SpiderFoot</span>
                <span class="tool-badge active">theHarvester</span>
                <span class="tool-badge active">Maigret</span>
                <span class="tool-badge active">Phoneinfoga</span>
                <span class="tool-badge active">AMASS</span>
                <span class="tool-badge active">Recon-ng</span>
                <span class="tool-badge active">Sherlock</span>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>🔍 Domain Recon</h3>
                <input type="text" id="domain" placeholder="example.com">
                <select id="domain-tool">
                    <option value="harvester">theHarvester</option>
                    <option value="amass">AMASS</option>
                    <option value="dns">DNS Lookup</option>
                    <option value="whois">WHOIS</option>
                </select>
                <button onclick="runDomainScan()">Scan Domain</button>
                <div class="result" id="domain-result"></div>
            </div>
            
            <div class="card">
                <h3>👤 Username Search</h3>
                <input type="text" id="username" placeholder="johndoe">
                <select id="username-tool">
                    <option value="maigret">Maigret (500+ sites)</option>
                    <option value="sherlock">Sherlock (400+ sites)</option>
                </select>
                <button onclick="runUsernameScan()">Search Username</button>
                <div class="result" id="username-result"></div>
            </div>
            
            <div class="card">
                <h3>📧 Email OSINT</h3>
                <input type="text" id="email" placeholder="user@example.com">
                <select id="email-tool">
                    <option value="holehe">Holehe (Account Check)</option>
                    <option value="hunter">Hunter.io (Verify)</option>
                </select>
                <button onclick="runEmailScan()">Check Email</button>
                <div class="result" id="email-result"></div>
            </div>
            
            <div class="card">
                <h3>📱 Phone OSINT</h3>
                <input type="text" id="phone" placeholder="+15551234567">
                <button onclick="runPhoneScan()">Scan Phone</button>
                <div class="result" id="phone-result"></div>
            </div>
            
            <div class="card">
                <h3>🌐 IP/Host Lookup</h3>
                <input type="text" id="ip" placeholder="8.8.8.8">
                <select id="ip-tool">
                    <option value="shodan">Shodan</option>
                    <option value="censys">Censys</option>
                </select>
                <button onclick="runIPScan()">Lookup</button>
                <div class="result" id="ip-result"></div>
            </div>
            
            <div class="card">
                <h3>🕷️ SpiderFoot</h3>
                <p style="color: #888; font-size: 12px;">Full automated scan with 200+ modules</p>
                <a href="http://localhost:5001" target="_blank">
                    <button>Open SpiderFoot UI →</button>
                </a>
            </div>
        </div>
    </div>
    
    <script>
        async function runScan(endpoint, params, resultId) {
            const resultDiv = document.getElementById(resultId);
            resultDiv.innerHTML = 'Scanning...';
            resultDiv.classList.add('loading');
            
            try {
                const response = await fetch(endpoint + '?' + new URLSearchParams(params));
                const data = await response.json();
                resultDiv.innerHTML = JSON.stringify(data, null, 2);
            } catch (e) {
                resultDiv.innerHTML = 'Error: ' + e.message;
            }
            resultDiv.classList.remove('loading');
        }
        
        function runDomainScan() {
            const domain = document.getElementById('domain').value;
            const tool = document.getElementById('domain-tool').value;
            runScan('/api/domain', {domain, tool}, 'domain-result');
        }
        
        function runUsernameScan() {
            const username = document.getElementById('username').value;
            const tool = document.getElementById('username-tool').value;
            runScan('/api/username', {username, tool}, 'username-result');
        }
        
        function runEmailScan() {
            const email = document.getElementById('email').value;
            const tool = document.getElementById('email-tool').value;
            runScan('/api/email', {email, tool}, 'email-result');
        }
        
        function runPhoneScan() {
            const phone = document.getElementById('phone').value;
            runScan('/api/phone', {phone}, 'phone-result');
        }
        
        function runIPScan() {
            const ip = document.getElementById('ip').value;
            const tool = document.getElementById('ip-tool').value;
            runScan('/api/ip', {ip, tool}, 'ip-result');
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/domain')
def api_domain():
    domain = request.args.get('domain', '')
    tool = request.args.get('tool', 'dns')
    
    if not domain:
        return jsonify({"error": "No domain provided"})
    
    try:
        if tool == 'harvester':
            result = subprocess.run(
                ['theharvester', '-d', domain, '-b', 'duckduckgo', '-l', '50'],
                capture_output=True, text=True, timeout=60
            )
            return jsonify({"tool": "theHarvester", "output": result.stdout[-2000:]})
        elif tool == 'amass':
            result = subprocess.run(
                ['amass', 'enum', '-passive', '-d', domain, '-timeout', '2'],
                capture_output=True, text=True, timeout=120
            )
            return jsonify({"tool": "AMASS", "output": result.stdout[-2000:]})
        elif tool == 'dns':
            result = subprocess.run(['dig', '+short', domain, 'ANY'], capture_output=True, text=True, timeout=10)
            return jsonify({"tool": "DNS", "records": result.stdout.strip().split('\n')})
        elif tool == 'whois':
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=15)
            return jsonify({"tool": "WHOIS", "output": result.stdout[:3000]})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/username')
def api_username():
    username = request.args.get('username', '')
    tool = request.args.get('tool', 'maigret')
    
    if not username:
        return jsonify({"error": "No username provided"})
    
    try:
        if tool == 'maigret':
            result = subprocess.run(
                [os.path.expanduser('~/.local/bin/maigret'), '--timeout', '10', '-n', '-J', 'simple', username],
                capture_output=True, text=True, timeout=60
            )
            return jsonify({"tool": "Maigret", "output": result.stdout[-3000:]})
        elif tool == 'sherlock':
            result = subprocess.run(
                [os.path.expanduser('~/.local/bin/sherlock'), '--timeout', '10', username],
                capture_output=True, text=True, timeout=60
            )
            return jsonify({"tool": "Sherlock", "output": result.stdout[-3000:]})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/email')
def api_email():
    email = request.args.get('email', '')
    tool = request.args.get('tool', 'holehe')
    
    if not email:
        return jsonify({"error": "No email provided"})
    
    try:
        if tool == 'holehe':
            result = subprocess.run(
                [os.path.expanduser('~/.local/bin/holehe'), email],
                capture_output=True, text=True, timeout=60
            )
            return jsonify({"tool": "Holehe", "output": result.stdout[-3000:]})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/phone')
def api_phone():
    phone = request.args.get('phone', '')
    
    if not phone:
        return jsonify({"error": "No phone provided"})
    
    try:
        result = subprocess.run(
            ['phoneinfoga', 'scan', '-n', phone],
            capture_output=True, text=True, timeout=30
        )
        return jsonify({"tool": "Phoneinfoga", "output": result.stdout})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/ip')
def api_ip():
    ip = request.args.get('ip', '')
    tool = request.args.get('tool', 'shodan')
    
    if not ip:
        return jsonify({"error": "No IP provided"})
    
    return jsonify({"tool": tool, "note": f"Use osint_tools.py shodan-host {ip}"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
