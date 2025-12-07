#!/bin/bash
API_URL="https://cti-api-9l6b.onrender.com"
API_KEY="demo-key-CHANGE_ME"

echo "Testing CTI API..."
echo ""

echo "1️⃣ Health Check:"
curl -s "$API_URL/health" | python -m json.tool
echo -e "\n"

echo "2️⃣ Threat Sources:"
curl -s -H "Authorization: Bearer $API_KEY" "$API_URL/sources" | python -m json.tool
echo -e "\n"

echo "3️⃣ Threat Indicators:"
curl -s -H "Authorization: Bearer $API_KEY" "$API_URL/indicators" | python -m json.tool
echo -e "\n"

echo "4️⃣ Threat Reports:"
curl -s -H "Authorization: Bearer $API_KEY" "$API_URL/threats" | python -m json.tool
echo -e "\n"

echo "All tests completed!"