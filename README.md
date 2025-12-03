# Cyber Threat Intelligence API

A FastAPI-based REST API for accessing cyber threat intelligence data including threat sources, indicators of compromise (IOCs), and threat reports.

## Features

- 🔐 **API Key Authentication** - Secure access with Bearer token authentication
- 📊 **Multiple Data Sources** - Government, community, and framework threat intelligence sources
- 🎯 **IOC Tracking** - Track IPs, domains, and file hashes
- 📝 **Threat Reports** - Detailed vulnerability and threat campaign information
- 🔍 **Filtering** - Query parameters for refined searches
- ⚡ **Fast & Lightweight** - Built with FastAPI for high performance

## API Endpoints

### Public Endpoints
- `GET /` - API information
- `GET /health` - Health check

### Protected Endpoints (Require Authentication)
- `GET /sources` - List all threat intelligence sources
- `GET /sources/{source_id}` - Get specific source details
- `GET /indicators` - List all indicators (supports filtering)
- `GET /indicators/{indicator_id}` - Get specific indicator
- `GET /threats` - List all threat reports (supports filtering)
- `GET /threats/{threat_id}` - Get specific threat report

## Authentication

All protected endpoints require an API key passed in the Authorization header:

```bash
Authorization: Bearer YOUR_API_KEY
```

### Default API Keys (Change in production!)
- `demo-key-CHANGE_ME`
- `test-key-123`

## Quick Start

### Local Development

1. **Clone the repository**
```bash
git clone <your-repo-url>
cd cti-api
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the server**
```bash
python main.py
```

Or with uvicorn directly:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

4. **Access the API**
- API: http://localhost:8000
- Interactive docs: http://localhost:8000/docs
- Alternative docs: http://localhost:8000/redoc

### Deploy to Render

1. **Push code to GitHub**
```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin <your-github-repo-url>
git push -u origin main
```

2. **Deploy on Render**
   - Go to [render.com](https://render.com)
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Render will auto-detect the `render.yaml` configuration
   - Click "Create Web Service"

3. **Alternative Manual Setup**
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

## Usage Examples

### 1. Test the API is running
```bash
curl https://cti-api-project-1.onrender.com/
```

### 2. Check health status
```bash
curl https://cti-api-project-1.onrender.com/health
```

### 3. Get all threat sources
```bash
curl -H "Authorization: Bearer demo-key-CHANGE_ME" \
  https://cti-api-project-1.onrender.com/sources
```

### 4. Get specific source
```bash
curl -H "Authorization: Bearer demo-key-CHANGE_ME" \
  https://cti-api-project-1.onrender.com/sources/src_001
```

### 5. Get all indicators
```bash
curl -H "Authorization: Bearer demo-key-CHANGE_ME" \
  https://cti-api-project-1.onrender.com/indicators
```

### 6. Filter indicators by type
```bash
curl -H "Authorization: Bearer demo-key-CHANGE_ME" \
  "https://cti-api-project-1.onrender.com/indicators?type=ip"
```

### 7. Filter indicators by threat level
```bash
curl -H "Authorization: Bearer demo-key-CHANGE_ME" \
  "https://cti-api-project-1.onrender.com/indicators?threat_level=critical"
```

### 8. Get all threat reports
```bash
curl -H "Authorization: Bearer demo-key-CHANGE_ME" \
  https://cti-api-project-1.onrender.com/threats
```

### 9. Filter threats by severity
```bash
curl -H "Authorization: Bearer demo-key-CHANGE_ME" \
  "https://cti-api-project-1.onrender.com/threats?severity=critical"
```

### PowerShell Examples (Windows)

```powershell
# Get sources
Invoke-RestMethod -Uri "https://cti-api-project-1.onrender.com/sources" `
  -Headers @{Authorization="Bearer demo-key-CHANGE_ME"}

# Get indicators
Invoke-RestMethod -Uri "https://cti-api-project-1.onrender.com/indicators" `
  -Headers @{Authorization="Bearer demo-key-CHANGE_ME"}
```

## Response Format

All successful responses follow this format:

```json
{
  "status": "success",
  "count": 4,
  "data": [...]
}
```

Error responses:

```json
{
  "detail": "Error message"
}
```

## Data Models

### Threat Source
```json
{
  "id": "src_001",
  "name": "CISA Advisories",
  "type": "government",
  "url": "https://www.cisa.gov/...",
  "description": "...",
  "last_updated": "2025-12-03T10:00:00Z",
  "active": true
}
```

### Indicator (IOC)
```json
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
}
```

### Threat Report
```json
{
  "id": "rpt_001",
  "title": "Critical Vulnerability in Log4j",
  "severity": "critical",
  "published_date": "2025-11-15T00:00:00Z",
  "threat_actors": ["APT28"],
  "affected_systems": ["Java applications"],
  "summary": "...",
  "source": "src_001",
  "cve": ["CVE-2021-44228"]
}
```

## Security Notes

⚠️ **IMPORTANT**: Before deploying to production:

1. **Change the default API keys** in `main.py`
2. Use environment variables for sensitive data
3. Implement rate limiting
4. Add logging and monitoring
5. Use HTTPS only
6. Consider adding user management and database integration

## Environment Variables (Optional)

You can add environment variables in Render dashboard:

- `API_KEYS` - Comma-separated list of valid API keys
- `LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)

## Troubleshooting

### "Internal Server Error"
- Check Render logs for detailed error messages
- Ensure all dependencies are in requirements.txt
- Verify the start command is correct

### "Authorization header missing"
- Make sure you're including the Authorization header
- Format: `Authorization: Bearer YOUR_API_KEY`
- No quotes around the API key in the header

### "Invalid API key"
- Verify you're using a valid API key from the VALID_API_KEYS dict
- Default keys: `demo-key-CHANGE_ME` or `test-key-123`

## Development

### Adding New Endpoints

Add new routes to `main.py`:

```python
@app.get("/your-endpoint")
async def your_function(user: str = Depends(verify_api_key)):
    return {"status": "success", "data": []}
```

### Adding Real Data Sources

Replace the mock data with database queries or external API calls:

```python
# Example: Connect to database
from sqlalchemy import create_engine
# Add your database integration here
```

## License

MIT License - Feel free to use and modify for your needs.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues and questions:
- Check the Render logs
- Review the FastAPI documentation
- Open an issue in the repository
