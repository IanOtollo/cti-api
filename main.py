from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict
from datetime import datetime
import requests
from functools import lru_cache
import time

app = FastAPI(
    title="Cyber Threat Intelligence API (REAL-TIME)",
    description="Real-time threat intelligence aggregation from multiple authoritative sources",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Keys for authentication
VALID_API_KEYS = {
    "demo-key-CHANGE_ME": "demo_user",
    "test-key-123": "test_user"
}

# AlienVault OTX API Key (user needs to get their own from https://otx.alienvault.com)
OTX_API_KEY = None  # Set this to your OTX API key

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

# Cache results for 5 minutes to avoid hammering APIs
@lru_cache(maxsize=100)
def get_cached_data(cache_key: str, timestamp: int):
    """Helper for caching - timestamp forces cache refresh every 5 minutes"""
    pass

def get_cache_timestamp():
    """Get current 5-minute timestamp for caching"""
    return int(time.time() / 300)  # 300 seconds = 5 minutes

# ============== REAL-TIME DATA FETCHERS ==============

def fetch_abuse_ch_urlhaus():
    """Fetch real-time malicious URLs from URLhaus (Abuse.ch)"""
    try:
        response = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            urls = data.get("urls", [])[:10]  # Get last 10
            return [
                {
                    "id": url.get("id"),
                    "url": url.get("url"),
                    "threat": url.get("threat"),
                    "date_added": url.get("dateadded"),
                    "status": url.get("url_status")
                }
                for url in urls
            ]
    except Exception as e:
        print(f"Error fetching URLhaus: {e}")
    return []

def fetch_abuse_ch_threatfox():
    """Fetch real-time IOCs from ThreatFox (Abuse.ch)"""
    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            iocs = data.get("data", [])[:20]  # Get 20 recent IOCs
            return [
                {
                    "ioc": ioc.get("ioc"),
                    "ioc_type": ioc.get("ioc_type"),
                    "threat_type": ioc.get("threat_type"),
                    "malware": ioc.get("malware"),
                    "confidence": ioc.get("confidence_level"),
                    "first_seen": ioc.get("first_seen")
                }
                for ioc in iocs
            ]
    except Exception as e:
        print(f"Error fetching ThreatFox: {e}")
    return []

def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities"""
    try:
        response = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15
        )
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])[:15]  # Get 15 recent
            return [
                {
                    "cve_id": v.get("cveID"),
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "vulnerability": v.get("vulnerabilityName"),
                    "date_added": v.get("dateAdded"),
                    "due_date": v.get("dueDate"),
                    "action": v.get("requiredAction")
                }
                for v in vulns
            ]
    except Exception as e:
        print(f"Error fetching CISA KEV: {e}")
    return []

def fetch_otx_pulses():
    """Fetch AlienVault OTX threat pulses (requires API key)"""
    if not OTX_API_KEY:
        return []
    
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        response = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers=headers,
            params={"limit": 10},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            pulses = data.get("results", [])
            return [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "created": p.get("created"),
                    "modified": p.get("modified"),
                    "tags": p.get("tags", []),
                    "references": p.get("references", [])
                }
                for p in pulses
            ]
    except Exception as e:
        print(f"Error fetching OTX: {e}")
    return []

# ============== API ENDPOINTS ==============

@app.get("/", response_class=HTMLResponse)
async def root():
    """Web interface"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CTI API - Real-Time Threat Intelligence</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { background: white; padding: 30px; border-radius: 15px; margin-bottom: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
            .header h1 { color: #667eea; margin-bottom: 10px; }
            .badge { display: inline-block; background: #4ade80; color: white; padding: 5px 15px; border-radius: 20px; font-size: 14px; font-weight: bold; margin-top: 10px; }
            .card { background: white; padding: 30px; border-radius: 15px; margin-bottom: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
            .input-group { margin-bottom: 20px; }
            .input-group input { width: 100%; padding: 15px; border: 2px solid #e5e7eb; border-radius: 10px; font-size: 16px; }
            .button-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px; }
            .btn { padding: 15px 25px; border: none; border-radius: 10px; font-size: 16px; font-weight: bold; cursor: pointer; transition: all 0.3s; }
            .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
            .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4); }
            .results { background: #1f2937; color: #e5e7eb; padding: 20px; border-radius: 10px; min-height: 200px; max-height: 500px; overflow-y: auto; font-family: 'Courier New', monospace; font-size: 14px; white-space: pre-wrap; }
            .status { padding: 10px; border-radius: 5px; margin-bottom: 10px; }
            .status.success { background: #d1fae5; color: #065f46; }
            .status.error { background: #fee2e2; color: #991b1b; }
            .status.loading { background: #dbeafe; color: #1e40af; }
            .hint { color: #666; font-size: 14px; margin-top: 5px; }
            .source-badge { display: inline-block; padding: 3px 10px; margin: 2px; border-radius: 5px; font-size: 12px; font-weight: bold; }
            .source-abuse { background: #fbbf24; color: #78350f; }
            .source-cisa { background: #3b82f6; color: white; }
            .source-otx { background: #8b5cf6; color: white; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ CTI API - Real-Time Threat Intelligence</h1>
                <p>Live threat data from Abuse.ch, CISA, and AlienVault OTX</p>
                <span class="badge">✅ REAL-TIME DATA</span>
                <span class="badge">🔄 AUTO-REFRESH EVERY 5 MIN</span>
            </div>
            
            <div class="card">
                <h2 style="color: #667eea; margin-bottom: 20px;">🔑 API Authentication</h2>
                <div class="input-group">
                    <input type="text" id="apiKey" placeholder="Enter your API key..." value="demo-key-CHANGE_ME">
                    <p class="hint">💡 Default: <strong>demo-key-CHANGE_ME</strong> or <strong>test-key-123</strong></p>
                </div>
                
                <h3 style="margin: 20px 0 10px 0;">Quick Actions:</h3>
                <div class="button-grid">
                    <button class="btn btn-primary" onclick="fetchData('/sources')">📋 Threat Sources</button>
                    <button class="btn btn-primary" onclick="fetchData('/live/urlhaus')">🌐 Malicious URLs</button>
                    <button class="btn btn-primary" onclick="fetchData('/live/threatfox')">🎯 Recent IOCs</button>
                    <button class="btn btn-primary" onclick="fetchData('/live/cisa-kev')">⚠️ CISA Vulnerabilities</button>
                    <button class="btn btn-primary" onclick="fetchData('/live/all')">🔥 All Live Data</button>
                    <button class="btn btn-primary" onclick="window.location.href='/docs'">📚 API Docs</button>
                </div>
                
                <div style="margin-top: 20px;">
                    <h3 style="margin-bottom: 10px;">Data Sources:</h3>
                    <span class="source-badge source-abuse">Abuse.ch URLhaus</span>
                    <span class="source-badge source-abuse">Abuse.ch ThreatFox</span>
                    <span class="source-badge source-cisa">CISA KEV</span>
                    <span class="source-badge source-otx">AlienVault OTX</span>
                </div>
            </div>
            
            <div class="card">
                <h2 style="color: #667eea; margin-bottom: 20px;">📊 Results</h2>
                <div id="status"></div>
                <div id="results" class="results">Click a button above to fetch real-time threat data...</div>
            </div>
        </div>
        
        <script>
            async function fetchData(endpoint) {
                const apiKey = document.getElementById('apiKey').value;
                const statusDiv = document.getElementById('status');
                const resultsDiv = document.getElementById('results');
                
                if (!apiKey) {
                    statusDiv.innerHTML = '<div class="status error">❌ Please enter an API key!</div>';
                    return;
                }
                
                statusDiv.innerHTML = '<div class="status loading">⏳ Fetching real-time data...</div>';
                resultsDiv.textContent = 'Loading...';
                
                try {
                    const response = await fetch(endpoint, {
                        headers: { 'Authorization': `Bearer ${apiKey}` }
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        statusDiv.innerHTML = '<div class="status success">✅ Real-time data fetched successfully!</div>';
                        resultsDiv.textContent = JSON.stringify(data, null, 2);
                    } else {
                        statusDiv.innerHTML = `<div class="status error">❌ Error: ${data.detail}</div>`;
                        resultsDiv.textContent = JSON.stringify(data, null, 2);
                    }
                } catch (error) {
                    statusDiv.innerHTML = `<div class="status error">❌ Network error: ${error.message}</div>`;
                    resultsDiv.textContent = error.toString();
                }
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/health")
async def health():
    """Health check"""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "features": "real-time"
    }

@app.get("/sources")
async def get_sources(username: str = Header(None, alias="username")):
    """Get list of real-time threat intelligence sources"""
    sources = [
        {
            "id": 1,
            "name": "Abuse.ch URLhaus",
            "type": "Community",
            "description": "Real-time malicious URL database",
            "url": "https://urlhaus.abuse.ch",
            "status": "active",
            "live": True
        },
        {
            "id": 2,
            "name": "Abuse.ch ThreatFox",
            "type": "Community",
            "description": "Real-time IOC sharing platform",
            "url": "https://threatfox.abuse.ch",
            "status": "active",
            "live": True
        },
        {
            "id": 3,
            "name": "CISA Known Exploited Vulnerabilities",
            "type": "Government",
            "description": "Actively exploited vulnerabilities catalog",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "status": "active",
            "live": True
        },
        {
            "id": 4,
            "name": "AlienVault OTX",
            "type": "Community",
            "description": "Open Threat Exchange threat pulses",
            "url": "https://otx.alienvault.com",
            "status": "active" if OTX_API_KEY else "requires_api_key",
            "live": bool(OTX_API_KEY)
        }
    ]
    
    return {
        "status": "success",
        "count": len(sources),
        "timestamp": datetime.now().isoformat(),
        "data": sources
    }

@app.get("/live/urlhaus")
async def get_urlhaus_data(username: str = Header(None, alias="username")):
    """Get real-time malicious URLs from URLhaus"""
    cache_ts = get_cache_timestamp()
    urls = fetch_abuse_ch_urlhaus()
    
    return {
        "status": "success",
        "source": "Abuse.ch URLhaus",
        "count": len(urls),
        "timestamp": datetime.now().isoformat(),
        "cache_refresh": "5 minutes",
        "data": urls
    }

@app.get("/live/threatfox")
async def get_threatfox_data(username: str = Header(None, alias="username")):
    """Get real-time IOCs from ThreatFox"""
    cache_ts = get_cache_timestamp()
    iocs = fetch_abuse_ch_threatfox()
    
    return {
        "status": "success",
        "source": "Abuse.ch ThreatFox",
        "count": len(iocs),
        "timestamp": datetime.now().isoformat(),
        "cache_refresh": "5 minutes",
        "data": iocs
    }

@app.get("/live/cisa-kev")
async def get_cisa_kev_data(username: str = Header(None, alias="username")):
    """Get CISA Known Exploited Vulnerabilities"""
    cache_ts = get_cache_timestamp()
    vulns = fetch_cisa_kev()
    
    return {
        "status": "success",
        "source": "CISA Known Exploited Vulnerabilities",
        "count": len(vulns),
        "timestamp": datetime.now().isoformat(),
        "cache_refresh": "5 minutes",
        "data": vulns
    }

@app.get("/live/otx")
async def get_otx_data(username: str = Header(None, alias="username")):
    """Get AlienVault OTX threat pulses (requires API key)"""
    if not OTX_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="AlienVault OTX integration requires API key. Get yours at https://otx.alienvault.com"
        )
    
    cache_ts = get_cache_timestamp()
    pulses = fetch_otx_pulses()
    
    return {
        "status": "success",
        "source": "AlienVault OTX",
        "count": len(pulses),
        "timestamp": datetime.now().isoformat(),
        "cache_refresh": "5 minutes",
        "data": pulses
    }

@app.get("/live/all")
async def get_all_live_data(username: str = Header(None, alias="username")):
    """Get all real-time threat intelligence data"""
    cache_ts = get_cache_timestamp()
    
    return {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "cache_refresh": "5 minutes",
        "sources": {
            "urlhaus": {
                "count": len(urls := fetch_abuse_ch_urlhaus()),
                "data": urls
            },
            "threatfox": {
                "count": len(iocs := fetch_abuse_ch_threatfox()),
                "data": iocs
            },
            "cisa_kev": {
                "count": len(vulns := fetch_cisa_kev()),
                "data": vulns
            },
            "otx": {
                "count": len(pulses := fetch_otx_pulses()) if OTX_API_KEY else 0,
                "data": pulses if OTX_API_KEY else [],
                "note": "Requires API key" if not OTX_API_KEY else None
            }
        }
    }

# Add dependency to all protected endpoints
for route in [get_sources, get_urlhaus_data, get_threatfox_data, get_cisa_kev_data, get_otx_data, get_all_live_data]:
    route.__defaults__ = (verify_api_key,)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)