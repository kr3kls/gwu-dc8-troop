#!/bin/bash
set -e

REALM="hw8"
KEYCLOAK_URL="http://localhost:8080"
CLIENT_ID="flask-api-client"
CLIENT_SECRET="1ZCvlNCp96BMBtPhL4MwBSgSMUUkUnfm"
USERNAME="testuser"
PASSWORD="testpassword"
FLASK_API_URL="http://localhost:5000/api/user/info"
ADMIN_API_URL="http://localhost:5000/api/admin/tasks"

echo "[*] Starting Keycloak and the Flask app..."
docker compose up -d --build

echo "[*] Waiting for Keycloak to be ready..."
until curl -s "$KEYCLOAK_URL/realms/master" > /dev/null; do
    echo "Waiting for Keycloak to start..."
    sleep 5
done

echo "[*] Configuring Keycloak via REST API..."

# Get admin token
export ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r .access_token)

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" == "null" ]; then
  echo "[❌] Failed to get admin token. Is Keycloak up and admin credentials correct?"
  exit 1
fi

# Check and create realm
REALM_EXISTS=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$KEYCLOAK_URL/admin/realms" | jq -r ".[] | select(.realm==\"$REALM\") | .realm")
if [ "$REALM_EXISTS" == "$REALM" ]; then
  echo "[!] Realm '$REALM' already exists. Skipping creation."
else
  if [ ! -f hw8-realm.json ]; then
    echo "[❌] Realm config file 'hw8-realm.json' not found."
    exit 1
  fi
  curl -s -X POST "$KEYCLOAK_URL/admin/realms" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d @hw8-realm.json
  echo "[✔] Realm '$REALM' created."
fi

# ========================
#       API TESTING
# ========================

echo
echo "[*] Fetching access token..."
TOKEN_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "username=$USERNAME" \
  -d "password=$PASSWORD" \
  -d "scope=openid")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
  echo "[❌] Failed to retrieve access token:"
  echo "$TOKEN_RESPONSE"
  exit 1
fi

echo "[✔] Got access token"

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

echo
echo "[✔] Setup and test complete. Flask is running at http://localhost:5000"