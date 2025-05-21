# app.py
import os
from flask import Flask
from authlib.integrations.flask_client import OAuth

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get('APP_SECRET_KEY', '95691db44bed07c1d83b8bbfc8309e3b3b784466f6c625fd1b4a9d4140e8d689')

    required_env = [
        'KEYCLOAK_CLIENT_ID',
        'KEYCLOAK_CLIENT_SECRET',
        'KEYCLOAK_SERVER_URL',
        "KEYCLOAK_INTERNAL_URL",
        'KEYCLOAK_REALM_NAME',
    ]

    for var in required_env:
        if not os.environ.get(var):
            raise RuntimeError(f"Missing required environment variable: {var}")
        app.config[var] = os.environ.get(var)

    oauth = OAuth(app)

    # URLs for Keycloak
    public_base_url = app.config['KEYCLOAK_SERVER_URL'].rstrip('/')
    public_realm_url = f"{public_base_url}/realms/{app.config['KEYCLOAK_REALM_NAME']}"
    public_authorize_url = f"{public_realm_url}/protocol/openid-connect/auth"
    public_issuer_url = public_realm_url
    internal_base_url = app.config['KEYCLOAK_INTERNAL_URL'].rstrip('/')
    internal_realm_url = f"{internal_base_url}/realms/{app.config['KEYCLOAK_REALM_NAME']}"
    internal_token_url = f"{internal_realm_url}/protocol/openid-connect/token"
    internal_userinfo_url = f"{internal_realm_url}/protocol/openid-connect/userinfo"
    internal_jwks_uri = f"{internal_realm_url}/protocol/openid-connect/certs"

    oauth.register(
        name='keycloak',
        client_id=app.config['KEYCLOAK_CLIENT_ID'],
        client_secret=app.config['KEYCLOAK_CLIENT_SECRET'],

        # Manual Endpoint Configuration
        authorize_url=public_authorize_url,
        access_token_url=internal_token_url,
        userinfo_endpoint=internal_userinfo_url,
        jwks_uri=internal_jwks_uri,
        client_kwargs={
            'scope': 'openid email profile',
            'code_challenge_method': 'S256',
            'token_endpoint_auth_method': 'client_secret_post'
        },
        server_metadata={
            'issuer': public_issuer_url,
            'authorization_endpoint': public_authorize_url,
            'token_endpoint': internal_token_url,
            'userinfo_endpoint': internal_userinfo_url,
            'jwks_uri': internal_jwks_uri,
            'end_session_endpoint': f"{public_realm_url}/protocol/openid-connect/logout"
        }
    )
    app.oauth = oauth

    from routes import main_bp
    app.register_blueprint(main_bp)

    return app

app = create_app()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5050, debug=True)