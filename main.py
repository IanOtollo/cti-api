from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
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

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CTI API is running",
        "version": "1.0.0",
        "endpoints": {
            "sources": "/sources",
            "indicators": "/indicators",
            "threats": "/threats",
            "health": "/health"
        }
    }

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
