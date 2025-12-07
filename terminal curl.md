1. VIEW ALL KEYS
bashcurl "https://cti-api-9l6b.onrender.com/admin/list-keys" \
  -H "X-Admin-Password: admin-secret-2024"

2. CREATE NEW KEY
Custom key:
bashcurl -X POST "https://cti-api-9l6b.onrender.com/admin/create-key?organization=AcmeCorp&custom_key=acme-2024" \
  -H "X-Admin-Password: admin-secret-2024"
Auto-generated key:
bashcurl -X POST "https://cti-api-9l6b.onrender.com/admin/create-key?organization=TechCorp" \
  -H "X-Admin-Password: admin-secret-2024"

3. DELETE KEY
bashcurl -X DELETE "https://cti-api-9l6b.onrender.com/admin/delete-key?api_key=acme-2024" \
  -H "X-Admin-Password: admin-secret-2024"

4. DEACTIVATE KEY
bashcurl -X PATCH "https://cti-api-9l6b.onrender.com/admin/toggle-key?api_key=acme-2024&active=false" \
  -H "X-Admin-Password: admin-secret-2024"

5. REACTIVATE KEY
bashcurl -X PATCH "https://cti-api-9l6b.onrender.com/admin/toggle-key?api_key=acme-2024&active=true" \
  -H "X-Admin-Password: admin-secret-2024"