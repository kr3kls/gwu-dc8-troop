import os
from flask import Flask, redirect, url_for, session, request, jsonify, g, current_app
from authlib.integrations.flask_client import OAuth
from functools import wraps
import jwt 
import json

def create_app():
    app = Flask(__name__)

    # Secret key
    app.secret_key = os.environ.get('APP_SECRET_KEY', 'fallback-secret')

    # Required Keycloak config
    required_env = [
        'KEYCLOAK_CLIENT_ID',
        'KEYCLOAK_CLIENT_SECRET',
        'KEYCLOAK_SERVER_URL',
        'KEYCLOAK_REALM_NAME',
    ]

    for var in required_env:
        if not os.environ.get(var):
            raise RuntimeError(f"Missing required environment variable: {var}")
        app.config[var] = os.environ.get(var)
    
    # Authlib OIDC Client Configuration
    metadata_url = f"{app.config['KEYCLOAK_SERVER_URL'].rstrip('/')}/realms/{app.config['KEYCLOAK_REALM_NAME']}/.well-known/openid-configuration"

    oauth = OAuth(app)

    oauth.register(
        name='keycloak',
        client_id=app.config['KEYCLOAK_CLIENT_ID'],
        client_secret=app.config['KEYCLOAK_CLIENT_SECRET'],
        server_metadata_url=metadata_url,
        client_kwargs={
            'scope': 'openid email profile',
            'code_challenge_method': 'S256'
        }
    )

    app.oauth = oauth

    # Import and register your routes
    from routes import main_bp
    app.register_blueprint(main_bp)

    return app

app = create_app()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5050, debug=False)