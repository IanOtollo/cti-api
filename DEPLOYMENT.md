# Deployment Guide - Updating Your CTI API on Render

## Option 1: Update Existing Render Service (Recommended)

### Step 1: Prepare Your Local Repository

1. **Navigate to your local project directory**
```bash
cd /path/to/your/cti-api-project
```

2. **Replace the old files with new ones**
   - Copy `main.py`, `requirements.txt`, `render.yaml` to your project folder
   - Or clone this updated version

3. **Test locally first** (optional but recommended)
```bash
pip install -r requirements.txt
python main.py
```

Open http://localhost:8000 to verify it works

### Step 2: Push to GitHub

1. **Stage your changes**
```bash
git add .
```

2. **Commit your changes**
```bash
git commit -m "Fix: Complete CTI API implementation with all endpoints"
```

3. **Push to your repository**
```bash
git push origin main
```

### Step 3: Deploy on Render

**Render will automatically detect the changes and redeploy!**

Just wait 2-5 minutes for the deployment to complete. You can watch the progress in your Render dashboard.

### Step 4: Verify the Deployment

Once deployment is complete, test your API:

```bash
# Test the root endpoint
curl https://cti-api-project-1.onrender.com/

# Test the sources endpoint with authentication
curl -H "Authorization: Bearer demo-key-CHANGE_ME" \
  https://cti-api-project-1.onrender.com/sources
```

You should see JSON responses instead of errors!

---

## Option 2: Create New Render Service from Scratch

If you don't have the GitHub repo connected, follow these steps:

### Step 1: Create GitHub Repository

1. Go to https://github.com/new
2. Create a new repository (e.g., "cti-api")
3. Don't initialize with README (we already have files)

### Step 2: Push Your Code

```bash
# Initialize git (if not already done)
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit: CTI API"

# Add your GitHub remote
git remote add origin https://github.com/YOUR_USERNAME/cti-api.git

# Push to GitHub
git branch -M main
git push -u origin main
```

### Step 3: Deploy on Render

1. Go to https://render.com/dashboard
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub account (if not already connected)
4. Select your `cti-api` repository
5. Render will auto-detect the configuration from `render.yaml`
6. Click **"Create Web Service"**

**If auto-detection doesn't work, use these settings:**
- **Name**: cti-api (or any name you prefer)
- **Environment**: Python 3
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- **Plan**: Free

7. Click **"Create Web Service"**

---

## Option 3: Manual Deployment (Without Git)

### Using Render Dashboard

1. Go to your existing service at https://render.com/dashboard
2. Click on your service name
3. Go to **"Settings"** tab
4. Scroll to **"Build & Deploy"**
5. Update these fields:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
6. Go to **"Manual Deploy"** section
7. Click **"Clear build cache & deploy"**

---

## Troubleshooting

### Issue: Still getting Internal Server Error

**Solution:**
1. Check Render logs:
   - Go to your service dashboard
   - Click "Logs" tab
   - Look for Python errors

2. Common issues:
   - Missing dependencies → Check requirements.txt
   - Wrong start command → Use: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - Python version → Render uses Python 3.7+ by default

### Issue: "Authorization header missing"

**Solution:**
Make sure you're including the header:
```bash
curl -H "Authorization: Bearer demo-key-CHANGE_ME" YOUR_URL/sources
```

### Issue: Git push rejected

**Solution:**
```bash
git pull origin main --rebase
git push origin main
```

---

## Testing Your Deployment

### Quick Test Script (Git Bash / Linux / Mac)

```bash
#!/bin/bash
API_URL="https://cti-api-project-1.onrender.com"
API_KEY="demo-key-CHANGE_ME"

echo "Testing CTI API..."
echo ""

echo "1. Root endpoint:"
curl -s "$API_URL/" | python -m json.tool
echo ""

echo "2. Health check:"
curl -s "$API_URL/health" | python -m json.tool
echo ""

echo "3. Sources (with auth):"
curl -s -H "Authorization: Bearer $API_KEY" "$API_URL/sources" | python -m json.tool
echo ""

echo "4. Indicators:"
curl -s -H "Authorization: Bearer $API_KEY" "$API_URL/indicators" | python -m json.tool
echo ""

echo "All tests completed!"
```

### PowerShell Test Script (Windows)

```powershell
$ApiUrl = "https://cti-api-project-1.onrender.com"
$Headers = @{Authorization="Bearer demo-key-CHANGE_ME"}

Write-Host "Testing CTI API..." -ForegroundColor Green

Write-Host "`n1. Root endpoint:" -ForegroundColor Yellow
Invoke-RestMethod -Uri "$ApiUrl/" | ConvertTo-Json

Write-Host "`n2. Health check:" -ForegroundColor Yellow
Invoke-RestMethod -Uri "$ApiUrl/health" | ConvertTo-Json

Write-Host "`n3. Sources:" -ForegroundColor Yellow
Invoke-RestMethod -Uri "$ApiUrl/sources" -Headers $Headers | ConvertTo-Json

Write-Host "`n4. Indicators:" -ForegroundColor Yellow
Invoke-RestMethod -Uri "$ApiUrl/indicators" -Headers $Headers | ConvertTo-Json

Write-Host "`nAll tests completed!" -ForegroundColor Green
```

---

## Next Steps After Successful Deployment

1. **Change the default API keys** in `main.py`:
```python
VALID_API_KEYS = {
    "your-secure-key-here": "user1",
    "another-secure-key": "user2"
}
```

2. **Add environment variables** in Render dashboard for sensitive data

3. **Set up monitoring** to track API usage

4. **Add a database** for persistent storage (optional)

5. **Implement rate limiting** for production use

---

## Support

If you encounter issues:
1. Check Render logs for detailed error messages
2. Verify all files are committed to Git
3. Ensure requirements.txt is up to date
4. Review the README.md for usage examples

**Render Dashboard**: https://render.com/dashboard
**FastAPI Docs**: https://fastapi.tiangolo.com
