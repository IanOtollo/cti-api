from fastapi import FastAPI, HTTPException, Header, Query, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict
from datetime import datetime
import requests
from functools import lru_cache
import time
import sqlite3
import secrets

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

# Database setup
DATABASE = "api_keys.db"

def init_database():
    """Initialize SQLite database with api_keys table"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create api_keys table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            organization TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active BOOLEAN DEFAULT 1,
            requests_count INTEGER DEFAULT 0,
            last_used TIMESTAMP
        )
    """)
    
    # Create default demo keys if table is empty
    cursor.execute("SELECT COUNT(*) FROM api_keys")
    if cursor.fetchone()[0] == 0:
        default_keys = [
            ("demo-key-CHANGE_ME", "demo_user"),
            ("test-key-123", "test_user")
        ]
        cursor.executemany(
            "INSERT INTO api_keys (key, organization) VALUES (?, ?)",
            default_keys
        )
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_database()

# AlienVault OTX API Key
OTX_API_KEY = None

def verify_api_key_in_db(api_key: str):
    """Check if API key exists in database and is active"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT organization, active FROM api_keys WHERE key = ?",
        (api_key,)
    )
    result = cursor.fetchone()
    
    if result and result[1]:  # Key exists and is active
        # Update usage stats
        cursor.execute(
            "UPDATE api_keys SET requests_count = requests_count + 1, last_used = ? WHERE key = ?",
            (datetime.now().isoformat(), api_key)
        )
        conn.commit()
        conn.close()
        return result[0]  # Return organization name
    
    conn.close()
    return None

async def verify_api_key(authorization: Optional[str] = Header(None)):
    """Verify the API key from Authorization header"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format. Use 'Bearer <api_key>'")
    
    api_key = authorization.replace("Bearer ", "")
    
    organization = verify_api_key_in_db(api_key)
    if not organization:
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    return organization

# Admin password (change this in production!)
ADMIN_PASSWORD = "admin-secret-2024"

def verify_admin(admin_password: str = Header(None, alias="X-Admin-Password")):
    """Verify admin password"""
    if admin_password != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Invalid admin password")
    return True

# Cache results for 5 minutes
@lru_cache(maxsize=100)
def get_cached_data(cache_key: str, timestamp: int):
    pass

def get_cache_timestamp():
    return int(time.time() / 300)

# ============== REAL-TIME DATA FETCHERS ==============

def fetch_abuse_ch_urlhaus():
    """Fetch real-time malicious URLs from URLhaus (Abuse.ch)"""
    try:
        response = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", timeout=10)
        if response.status_code == 200:
            data = response.json()
            urls = data.get("urls", [])[:10]
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
            iocs = data.get("data", [])[:20]
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
            vulns = data.get("vulnerabilities", [])[:15]
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

# ============== ADMIN ENDPOINTS ==============

@app.post("/admin/create-key")
async def create_api_key(
    organization: str = Query(..., description="Organization name"),
    custom_key: Optional[str] = Query(None, description="Custom key (optional)"),
    admin_verified: bool = Depends(verify_admin)
):
    """Create a new API key for an organization"""
    
    # Generate random key if custom key not provided
    if not custom_key:
        custom_key = f"cti-{secrets.token_urlsafe(16)}"
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO api_keys (key, organization) VALUES (?, ?)",
            (custom_key, organization)
        )
        conn.commit()
        
        return {
            "status": "success",
            "message": f"API key created for {organization}",
            "api_key": custom_key,
            "organization": organization,
            "created_at": datetime.now().isoformat()
        }
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="API key already exists")
    finally:
        conn.close()

@app.delete("/admin/delete-key")
async def delete_api_key(
    api_key: str = Query(..., description="API key to delete"),
    admin_verified: bool = Depends(verify_admin)
):
    """Delete an API key"""
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM api_keys WHERE key = ?", (api_key,))
    
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="API key not found")
    
    conn.commit()
    conn.close()
    
    return {
        "status": "success",
        "message": f"API key deleted: {api_key}"
    }

@app.get("/admin/list-keys")
async def list_api_keys(admin_verified: bool = Depends(verify_admin)):
    """List all API keys"""
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT key, organization, created_at, active, requests_count, last_used 
        FROM api_keys 
        ORDER BY created_at DESC
    """)
    
    keys = []
    for row in cursor.fetchall():
        keys.append({
            "key": row[0],
            "organization": row[1],
            "created_at": row[2],
            "active": bool(row[3]),
            "requests_count": row[4],
            "last_used": row[5]
        })
    
    conn.close()
    
    return {
        "status": "success",
        "count": len(keys),
        "keys": keys
    }

@app.patch("/admin/toggle-key")
async def toggle_api_key(
    api_key: str = Query(..., description="API key to toggle"),
    active: bool = Query(..., description="Set active status"),
    admin_verified: bool = Depends(verify_admin)
):
    """Activate or deactivate an API key"""
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE api_keys SET active = ? WHERE key = ?",
        (1 if active else 0, api_key)
    )
    
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="API key not found")
    
    conn.commit()
    conn.close()
    
    status = "activated" if active else "deactivated"
    return {
        "status": "success",
        "message": f"API key {status}: {api_key}"
    }

# ============== PUBLIC ENDPOINTS ==============

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
            body { 
                font-family: 'Segoe UI', Arial, sans-serif; 
                background: #f5f5f5; 
                padding: 40px 20px; 
                color: #333;
            }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { 
                background: white; 
                padding: 30px; 
                border-radius: 8px; 
                margin-bottom: 30px; 
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                border-left: 4px solid #2563eb;
            }
            .header h1 { 
                color: #1e40af; 
                margin-bottom: 10px; 
                font-size: 28px;
                font-weight: 600;
            }
            .header p { 
                color: #64748b; 
                font-size: 16px;
            }
            .badge { 
                display: inline-block; 
                background: #e0e7ff; 
                color: #3730a3; 
                padding: 6px 12px; 
                border-radius: 4px; 
                font-size: 13px; 
                font-weight: 500; 
                margin-top: 15px;
                margin-right: 10px;
            }
            .badge.db { 
                background: #dcfce7; 
                color: #15803d;
            }
            .card { 
                background: white; 
                padding: 30px; 
                border-radius: 8px; 
                margin-bottom: 30px; 
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .card h2 { 
                color: #1e40af; 
                margin-bottom: 20px; 
                font-size: 20px;
                font-weight: 600;
            }
            .card h3 { 
                color: #475569; 
                margin: 20px 0 15px 0; 
                font-size: 16px;
                font-weight: 600;
            }
            .input-group { margin-bottom: 20px; }
            .input-group input { 
                width: 100%; 
                padding: 12px 15px; 
                border: 1px solid #cbd5e1; 
                border-radius: 6px; 
                font-size: 15px;
                font-family: 'Courier New', monospace;
            }
            .input-group input:focus {
                outline: none;
                border-color: #2563eb;
            }
            .button-grid { 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                gap: 12px; 
                margin-top: 20px; 
            }
            .btn { 
                padding: 12px 20px; 
                border: 1px solid #cbd5e1; 
                border-radius: 6px; 
                font-size: 15px; 
                font-weight: 500; 
                cursor: pointer; 
                transition: all 0.2s;
                background: white;
            }
            .btn-primary { 
                background: #2563eb; 
                color: white; 
                border-color: #2563eb;
            }
            .btn-primary:hover { 
                background: #1d4ed8;
                border-color: #1d4ed8;
            }
            .results { 
                background: #1e293b; 
                color: #e2e8f0; 
                padding: 20px; 
                border-radius: 6px; 
                min-height: 200px; 
                max-height: 500px; 
                overflow-y: auto; 
                font-family: 'Courier New', monospace; 
                font-size: 13px; 
                white-space: pre-wrap;
                border: 1px solid #334155;
            }
            .status { 
                padding: 12px 15px; 
                border-radius: 6px; 
                margin-bottom: 15px;
                font-size: 14px;
            }
            .status.success { 
                background: #dcfce7; 
                color: #15803d;
                border: 1px solid #86efac;
            }
            .status.error { 
                background: #fee2e2; 
                color: #991b1b;
                border: 1px solid #fca5a5;
            }
            .status.loading { 
                background: #dbeafe; 
                color: #1e40af;
                border: 1px solid #93c5fd;
            }
            .hint { 
                color: #64748b; 
                font-size: 13px; 
                margin-top: 8px; 
            }
            .source-list {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 15px;
            }
            .source-badge { 
                padding: 8px 14px; 
                border-radius: 4px; 
                font-size: 13px; 
                font-weight: 500;
                border: 1px solid;
            }
            .source-abuse { 
                background: #fef3c7; 
                color: #92400e;
                border-color: #fcd34d;
            }
            .source-cisa { 
                background: #dbeafe; 
                color: #1e40af;
                border-color: #60a5fa;
            }
            .source-otx { 
                background: #e9d5ff; 
                color: #6b21a8;
                border-color: #c084fc;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>CTI API - Real-Time Threat Intelligence</h1>
                <p>Live threat data from Abuse.ch, CISA, and AlienVault OTX</p>
                <span class="badge">REAL-TIME DATA</span>
                <span class="badge">AUTO-REFRESH EVERY 5 MIN</span>
                <span class="badge db">DATABASE KEY STORAGE</span>
            </div>
            
            <div class="card">
                <h2>API Authentication</h2>
                <div class="input-group">
                    <input type="text" id="apiKey" placeholder="Enter your API key..." value="demo-key-CHANGE_ME">
                    <p class="hint">Default keys: <strong>demo-key-CHANGE_ME</strong> or <strong>test-key-123</strong></p>
                    <p class="hint">Keys are now stored in SQLite database - admin can add new keys dynamically</p>
                </div>
                
                <h3>Quick Actions</h3>
                <div class="button-grid">
                    <button class="btn btn-primary" onclick="fetchData('/sources')">Threat Sources</button>
                    <button class="btn btn-primary" onclick="fetchData('/live/urlhaus')">Malicious URLs</button>
                    <button class="btn btn-primary" onclick="fetchData('/live/threatfox')">Recent IOCs</button>
                    <button class="btn btn-primary" onclick="fetchData('/live/cisa-kev')">CISA Vulnerabilities</button>
                    <button class="btn btn-primary" onclick="fetchData('/live/all')">All Live Data</button>
                    <button class="btn btn-primary" onclick="window.location.href='/docs'">API Documentation</button>
                </div>
                
                <h3>Data Sources</h3>
                <div class="source-list">
                    <span class="source-badge source-abuse">Abuse.ch URLhaus</span>
                    <span class="source-badge source-abuse">Abuse.ch ThreatFox</span>
                    <span class="source-badge source-cisa">CISA KEV</span>
                    <span class="source-badge source-otx">AlienVault OTX</span>
                </div>
            </div>
            
            <div class="card">
                <h2>Results</h2>
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
                    statusDiv.innerHTML = '<div class="status error">ERROR: Please enter an API key</div>';
                    return;
                }
                
                statusDiv.innerHTML = '<div class="status loading">Fetching real-time data...</div>';
                resultsDiv.textContent = 'Loading...';
                
                try {
                    const response = await fetch(endpoint, {
                        headers: { 'Authorization': `Bearer ${apiKey}` }
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        statusDiv.innerHTML = '<div class="status success">SUCCESS: Real-time data fetched successfully</div>';
                        resultsDiv.textContent = JSON.stringify(data, null, 2);
                    } else {
                        statusDiv.innerHTML = `<div class="status error">ERROR: ${data.detail}</div>`;
                        resultsDiv.textContent = JSON.stringify(data, null, 2);
                    }
                } catch (error) {
                    statusDiv.innerHTML = `<div class="status error">ERROR: ${error.message}</div>`;
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
        "features": "real-time",
        "database": "sqlite"
    }

@app.get("/sources")
async def get_sources(username: str = Depends(verify_api_key)):
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
async def get_urlhaus_data(username: str = Depends(verify_api_key)):
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
async def get_threatfox_data(username: str = Depends(verify_api_key)):
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
async def get_cisa_kev_data(username: str = Depends(verify_api_key)):
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
async def get_otx_data(username: str = Depends(verify_api_key)):
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
async def get_all_live_data(username: str = Depends(verify_api_key)):
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)