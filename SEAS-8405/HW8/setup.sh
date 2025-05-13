
#!/bin/bash
set -e

echo "[*] Starting Keycloak and the Flask app..."
docker compose up -d --build

echo "[*] Waiting for Keycloak to be ready..."
until curl -s http://localhost:8080/realms/master > /dev/null; do
    echo "Waiting for Keycloak to start..."
    sleep 5
done

echo "[*] Configuring Keycloak via REST API..."

# Get admin token
export ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r .access_token)

# Check and create realm
REALM_EXISTS=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost:8080/admin/realms | jq -r '.[] | select(.realm=="hw8") | .realm')
if [ "$REALM_EXISTS" == "hw8" ]; then
  echo "[!] Realm 'hw8' already exists. Skipping creation."
else
  curl -s -X POST "http://localhost:8080/admin/realms" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d @hw8-realm.json
  echo "[✔] Realm 'hw8' created."
fi

echo "[*] Testing access token retrieval..."
RESPONSE=$(curl -s -X POST "http://localhost:8080/realms/hw8/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=flask-api-client" \
  -d "client_secret=1ZCvlNCp96BMBtPhL4MwBSgSMUUkUnfm" \
  -d "username=testuser" \
  -d "password=testpassword")

echo "$RESPONSE" | jq

echo "[✔] Setup complete. Access the Flask app at: http://localhost:5000"
echo "[ℹ️ ] To test manually:"
echo "curl -H \"Authorization: Bearer <access_token>\" http://localhost:5000"
