#!/bin/bash

REALM="hw8"
KEYCLOAK_URL="http://localhost:8080"
CLIENT_ID="flask-api-client"
CLIENT_SECRET="1ZCvlNCp96BMBtPhL4MwBSgSMUUkUnfm"
USERNAME="testuser"
PASSWORD="testpassword"
FLASK_API_URL="http://localhost:5000/api/user/info"
ADMIN_API_URL="http://localhost:5000/api/admin/tasks"

echo "[*] Fetching access token..."
TOKEN_RESPONSE=$(curl -X POST http://localhost:8080/realms/hw8/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=flask-api-client" \
  -d "client_secret=1ZCvlNCp96BMBtPhL4MwBSgSMUUkUnfm" \
  -d "username=testuser" \
  -d "password=testpassword" \
  -d "scope=openid")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)

if [[ "$ACCESS_TOKEN" == "null" || -z "$ACCESS_TOKEN" ]]; then
  echo "[!] Failed to retrieve token:"
  echo "$TOKEN_RESPONSE"
  exit 1
fi

echo "[✔] Got access token"

#echo "$ACCESS_TOKEN" | cut -d '.' -f2 | base64 -d 2>/dev/null | jq .

echo
echo "[1] Request WITH valid token:"
curl -s -w "\n[HTTP %{http_code}]\n" -H "Authorization: Bearer $ACCESS_TOKEN" "$FLASK_API_URL"

echo
echo "[2] Request WITHOUT token:"
curl -s -w "\n[HTTP %{http_code}]\n" "$FLASK_API_URL"

echo
echo "[3] Request WITH INVALID token:"
curl -s -w "\n[HTTP %{http_code}]\n" -H "Authorization: Bearer invalid.token.value" "$FLASK_API_URL"

echo
echo "[4] Request WITH VALID token and INCORRECT role:"
curl -s -w "\n[HTTP %{http_code}]\n" -H "Authorization: Bearer $ACCESS_TOKEN" "$ADMIN_API_URL"