from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from typing import Optional, List
from datetime import datetime
import uvicorn

app = FastAPI(
    title="Cyber Threat Intelligence API",
    description="API for accessing cyber threat intelligence data",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple API key authentication
VALID_API_KEYS = {
    "demo-key-CHANGE_ME": "demo_user",
    "test-key-123": "test_user"
}

async def verify_api_key(authorization: Optional[str] = Header(None)):
    """Verify the API key from Authorization header"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format. Use 'Bearer <api_key>'")
    
    api_key = authorization.replace("Bearer ", "")
    
    if api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    return VALID_API_KEYS[api_key]

# Mock data for demonstration
THREAT_SOURCES = [
    {
        "id": "src_001",
        "name": "CISA Advisories",
        "type": "government",
        "url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "description": "US Cybersecurity and Infrastructure Security Agency threat advisories",
        "last_updated": "2025-12-03T10:00:00Z",
        "active": True
    },
    {
        "id": "src_002",
        "name": "AlienVault OTX",
        "type": "community",
        "url": "https://otx.alienvault.com",
        "description": "Open Threat Exchange - Community-driven threat intelligence",
        "last_updated": "2025-12-03T09:30:00Z",
        "active": True
    },
    {
        "id": "src_003",
        "name": "MITRE ATT&CK",
        "type": "framework",
        "url": "https://attack.mitre.org",
        "description": "Adversarial Tactics, Techniques, and Common Knowledge",
        "last_updated": "2025-12-01T00:00:00Z",
        "active": True
    },
    {
        "id": "src_004",
        "name": "Abuse.ch",
        "type": "community",
        "url": "https://abuse.ch",
        "description": "Malware and botnet tracking",
        "last_updated": "2025-12-03T11:00:00Z",
        "active": True
    }
]

THREAT_INDICATORS = [
    {
        "id": "ioc_001",
        "type": "ip",
        "value": "192.168.1.100",
        "threat_level": "high",
        "first_seen": "2025-11-28T14:30:00Z",
        "last_seen": "2025-12-02T08:15:00Z",
        "source": "src_002",
        "description": "Known C2 server IP",
        "tags": ["malware", "c2", "apt"]
    },
    {
        "id": "ioc_002",
        "type": "domain",
        "value": "malicious-example.com",
        "threat_level": "critical",
        "first_seen": "2025-12-01T10:00:00Z",
        "last_seen": "2025-12-03T12:00:00Z",
        "source": "src_001",
        "description": "Phishing domain targeting financial institutions",
        "tags": ["phishing", "financial", "credential-theft"]
    },
    {
        "id": "ioc_003",
        "type": "hash",
        "value": "d41d8cd98f00b204e9800998ecf8427e",
        "threat_level": "medium",
        "first_seen": "2025-11-25T16:45:00Z",
        "last_seen": "2025-11-30T09:20:00Z",
        "source": "src_004",
        "description": "Ransomware payload MD5 hash",
        "tags": ["ransomware", "malware"]
    }
]

THREAT_REPORTS = [
    {
        "id": "rpt_001",
        "title": "Critical Vulnerability in Log4j",
        "severity": "critical",
        "published_date": "2025-11-15T00:00:00Z",
        "threat_actors": ["APT28", "Lazarus Group"],
        "affected_systems": ["Java applications", "Apache Log4j"],
        "summary": "Critical remote code execution vulnerability affecting Log4j library",
        "source": "src_001",
        "cve": ["CVE-2021-44228"]
    },
    {
        "id": "rpt_002",
        "title": "Ransomware Campaign Targeting Healthcare",
        "severity": "high",
        "published_date": "2025-12-01T00:00:00Z",
        "threat_actors": ["RansomCorp"],
        "affected_systems": ["Healthcare", "Medical devices"],
        "summary": "Coordinated ransomware attacks on healthcare infrastructure",
        "source": "src_002",
        "cve": []
    }
]

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint - Interactive Web UI"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CTI API - Cyber Threat Intelligence</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 {
                color: #667eea;
                margin-bottom: 10px;
                font-size: 2.5em;
                text-align: center;
            }
            .subtitle {
                text-align: center;
                color: #666;
                margin-bottom: 30px;
                font-size: 1.1em;
            }
            .api-key-section {
                background: #f8f9fa;
                padding: 25px;
                border-radius: 10px;
                margin-bottom: 30px;
                border-left: 4px solid #667eea;
            }
            .input-group {
                display: flex;
                gap: 10px;
                margin-bottom: 10px;
            }
            input[type="text"] {
                flex: 1;
                padding: 12px 20px;
                border: 2px solid #ddd;
                border-radius: 8px;
                font-size: 16px;
                transition: border-color 0.3s;
            }
            input[type="text"]:focus {
                outline: none;
                border-color: #667eea;
            }
            .btn {
                padding: 12px 30px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                cursor: pointer;
                transition: all 0.3s;
                font-weight: 600;
            }
            .btn-primary {
                background: #667eea;
                color: white;
            }
            .btn-primary:hover {
                background: #5568d3;
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
            }
            .btn-secondary {
                background: #6c757d;
                color: white;
            }
            .btn-secondary:hover {
                background: #5a6268;
            }
            .endpoint-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .endpoint-card {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                border: 2px solid #e9ecef;
                transition: all 0.3s;
            }
            .endpoint-card:hover {
                border-color: #667eea;
                transform: translateY(-5px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }
            .endpoint-card h3 {
                color: #667eea;
                margin-bottom: 10px;
                font-size: 1.2em;
            }
            .endpoint-card p {
                color: #666;
                margin-bottom: 15px;
                font-size: 0.9em;
            }
            .endpoint-card .btn {
                width: 100%;
            }
            .results-section {
                background: #1e1e1e;
                color: #d4d4d4;
                padding: 20px;
                border-radius: 10px;
                margin-top: 20px;
                display: none;
            }
            .results-section.show {
                display: block;
            }
            .results-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 2px solid #667eea;
            }
            .results-header h3 {
                color: #667eea;
            }
            pre {
                background: #2d2d2d;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            .status {
                display: inline-block;
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 0.9em;
                font-weight: 600;
            }
            .status-success {
                background: #28a745;
                color: white;
            }
            .status-error {
                background: #dc3545;
                color: white;
            }
            .hint {
                color: #6c757d;
                font-size: 0.9em;
                margin-top: 5px;
            }
            .loading {
                display: none;
                text-align: center;
                padding: 20px;
                color: #667eea;
                font-weight: 600;
            }
            .loading.show {
                display: block;
            }
            .docs-link {
                text-align: center;
                margin-top: 20px;
                padding-top: 20px;
                border-top: 2px solid #e9ecef;
            }
            .docs-link a {
                color: #667eea;
                text-decoration: none;
                font-weight: 600;
                font-size: 1.1em;
            }
            .docs-link a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Cyber Threat Intelligence API</h1>
            <p class="subtitle">Access real-time threat intelligence data</p>
            
            <div class="api-key-section">
                <h3>API Authentication</h3>
                <div class="input-group">
                    <input type="text" id="apiKey" placeholder="Enter your API key here..." value="demo-key-CHANGE_ME">
                    <button class="btn btn-secondary" onclick="clearResults()">Clear</button>
                </div>
                <p class="hint">Default key: <strong>demo-key-CHANGE_ME</strong> or <strong>test-key-123</strong></p>
            </div>

            <h2 style="margin-bottom: 20px;">Available Endpoints</h2>
            
            <div class="endpoint-grid">
                <div class="endpoint-card">
                    <h3>Threat Sources</h3>
                    <p>Get all threat intelligence sources (CISA, MITRE, AlienVault, etc.)</p>
                    <button class="btn btn-primary" onclick="fetchEndpoint('/sources', 'sources')">Get Sources</button>
                </div>

                <div class="endpoint-card">
                    <h3>Threat Indicators</h3>
                    <p>Get indicators of compromise (IPs, domains, hashes)</p>
                    <button class="btn btn-primary" onclick="fetchEndpoint('/indicators', 'indicators')">Get All Indicators</button>
                </div>

                <div class="endpoint-card">
                    <h3>IP Addresses Only</h3>
                    <p>Filter indicators to show only malicious IP addresses</p>
                    <button class="btn btn-primary" onclick="fetchEndpoint('/indicators?type=ip', 'ip-indicators')">Get IPs</button>
                </div>

                <div class="endpoint-card">
                    <h3>Domains Only</h3>
                    <p>Filter indicators to show only malicious domains</p>
                    <button class="btn btn-primary" onclick="fetchEndpoint('/indicators?type=domain', 'domain-indicators')">Get Domains</button>
                </div>

                <div class="endpoint-card">
                    <h3>Threat Reports</h3>
                    <p>Get detailed threat reports and vulnerabilities</p>
                    <button class="btn btn-primary" onclick="fetchEndpoint('/threats', 'threats')">Get Threats</button>
                </div>

                <div class="endpoint-card">
                    <h3>Critical Threats</h3>
                    <p>Filter threats to show only critical severity</p>
                    <button class="btn btn-primary" onclick="fetchEndpoint('/threats?severity=critical', 'critical-threats')">Get Critical</button>
                </div>
            </div>

            <div class="loading" id="loading">Loading...</div>

            <div class="results-section" id="results">
                <div class="results-header">
                    <h3>Results</h3>
                    <span class="status" id="status"></span>
                </div>
                <pre id="resultsContent"></pre>
            </div>

            <div class="docs-link">
                <p>Need more details? Check out the <a href="/docs" target="_blank">Interactive API Documentation</a></p>
            </div>
        </div>

        <script>
            async function fetchEndpoint(endpoint, name) {
                const apiKey = document.getElementById('apiKey').value.trim();
                const resultsDiv = document.getElementById('results');
                const resultsContent = document.getElementById('resultsContent');
                const statusSpan = document.getElementById('status');
                const loadingDiv = document.getElementById('loading');

                if (!apiKey) {
                    alert('Please enter your API key!');
                    return;
                }

                // Show loading
                loadingDiv.classList.add('show');
                resultsDiv.classList.remove('show');

                try {
                    const response = await fetch(endpoint, {
                        method: 'GET',
                        headers: {
                            'Authorization': `Bearer ${apiKey}`,
                            'Accept': 'application/json'
                        }
                    });

                    const data = await response.json();

                    // Hide loading
                    loadingDiv.classList.remove('show');
                    resultsDiv.classList.add('show');

                    if (response.ok) {
                        statusSpan.textContent = `${response.status} Success`;
                        statusSpan.className = 'status status-success';
                        resultsContent.textContent = JSON.stringify(data, null, 2);
                    } else {
                        statusSpan.textContent = `${response.status} Error`;
                        statusSpan.className = 'status status-error';
                        resultsContent.textContent = JSON.stringify(data, null, 2);
                    }
                } catch (error) {
                    loadingDiv.classList.remove('show');
                    resultsDiv.classList.add('show');
                    statusSpan.textContent = 'Network Error';
                    statusSpan.className = 'status status-error';
                    resultsContent.textContent = `Error: ${error.message}`;
                }
            }

            function clearResults() {
                document.getElementById('results').classList.remove('show');
                document.getElementById('apiKey').value = '';
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "CTI API"
    }

@app.get("/sources")
async def get_sources(user: str = Depends(verify_api_key)):
    """Get all threat intelligence sources"""
    return {
        "status": "success",
        "count": len(THREAT_SOURCES),
        "data": THREAT_SOURCES
    }

@app.get("/sources/{source_id}")
async def get_source(source_id: str, user: str = Depends(verify_api_key)):
    """Get a specific threat intelligence source"""
    source = next((s for s in THREAT_SOURCES if s["id"] == source_id), None)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    return {
        "status": "success",
        "data": source
    }

@app.get("/indicators")
async def get_indicators(
    user: str = Depends(verify_api_key),
    type: Optional[str] = None,
    threat_level: Optional[str] = None
):
    """Get threat indicators with optional filtering"""
    indicators = THREAT_INDICATORS
    
    if type:
        indicators = [i for i in indicators if i["type"] == type]
    
    if threat_level:
        indicators = [i for i in indicators if i["threat_level"] == threat_level]
    
    return {
        "status": "success",
        "count": len(indicators),
        "filters": {
            "type": type,
            "threat_level": threat_level
        },
        "data": indicators
    }

@app.get("/indicators/{indicator_id}")
async def get_indicator(indicator_id: str, user: str = Depends(verify_api_key)):
    """Get a specific threat indicator"""
    indicator = next((i for i in THREAT_INDICATORS if i["id"] == indicator_id), None)
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {
        "status": "success",
        "data": indicator
    }

@app.get("/threats")
async def get_threats(
    user: str = Depends(verify_api_key),
    severity: Optional[str] = None
):
    """Get threat reports with optional filtering"""
    threats = THREAT_REPORTS
    
    if severity:
        threats = [t for t in threats if t["severity"] == severity]
    
    return {
        "status": "success",
        "count": len(threats),
        "filters": {
            "severity": severity
        },
        "data": threats
    }

@app.get("/threats/{threat_id}")
async def get_threat(threat_id: str, user: str = Depends(verify_api_key)):
    """Get a specific threat report"""
    threat = next((t for t in THREAT_REPORTS if t["id"] == threat_id), None)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat report not found")
    return {
        "status": "success",
        "data": threat
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)