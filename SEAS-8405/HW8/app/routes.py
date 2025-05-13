from flask import Blueprint, redirect, url_for, session, request, jsonify, g, current_app
from authlib.oauth2.rfc6749.errors import OAuth2Error
from functools import wraps
import requests
import jwt
from jwt import PyJWKClient
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError

main_bp = Blueprint('main', __name__)

KEYCLOAK_BASE = lambda: current_app.config['KEYCLOAK_SERVER_URL'].rstrip('/')
REALM_NAME = lambda: current_app.config['KEYCLOAK_REALM_NAME']
CLIENT_ID = lambda: current_app.config['KEYCLOAK_CLIENT_ID']
ISSUER = lambda: f"{KEYCLOAK_BASE()}/realms/{REALM_NAME()}"
JWKS_URL = lambda: f"{KEYCLOAK_BASE()}/realms/{REALM_NAME()}/protocol/openid-connect/certs"

def fetch_userinfo(access_token):
    keycloak_base = current_app.config['KEYCLOAK_SERVER_URL'].rstrip('/')
    realm = current_app.config['KEYCLOAK_REALM_NAME']
    userinfo_url = f"{keycloak_base}/realms/{realm}/protocol/openid-connect/userinfo"
    
    resp = requests.get(
        userinfo_url,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=5
    )
    resp.raise_for_status()
    return resp.json()

def get_jwks():
    realm = current_app.config['KEYCLOAK_REALM_NAME']
    url = f"{current_app.config['KEYCLOAK_SERVER_URL'].rstrip('/')}/realms/{realm}/protocol/openid-connect/certs"
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    return response.json()

def decode_token(token):
    realm = current_app.config['KEYCLOAK_REALM_NAME']
    issuer = f"http://localhost:8080/realms/{realm}"
    internal_keycloak_url = "http://keycloak:8080"
    jwks_url = f"{internal_keycloak_url}/realms/{realm}/protocol/openid-connect/certs"

    # Load signing key from JWKS
    jwk_client = PyJWKClient(jwks_url)
    signing_key = jwk_client.get_signing_key_from_jwt(token)

    # Decode and validate token
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=["flask-api-client", "account"],
        issuer=issuer
    )

# Authentication Decorators
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"message": "Authorization token is missing!"}), 401
        
        token = auth.split()[1]
        if token.count('.') != 2:
            return jsonify({"message": "Malformed token"}), 400

        try:
            g.user = decode_token(token)
            g.access_token = token
        except (ExpiredSignatureError, InvalidTokenError, DecodeError) as e:
            return jsonify({"message": "Invalid token!"}), 401
        except Exception as e:
            current_app.logger.error(f"Token validation failed: {e}")
            return jsonify({"message": "Token validation failed!"}), 401

        return f(*args, **kwargs)
    return decorated

def roles_required(required_roles):
    if isinstance(required_roles, str):
        required_roles = [required_roles]

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not getattr(g, 'user', None):
                return jsonify({"message": "Authentication required for role check."}), 401

            roles = set()
            realm_roles = g.user.get('realm_access', {}).get('roles', [])
            roles.update(realm_roles)

            resource_roles = g.user.get('resource_access', {}).get(CLIENT_ID(), {}).get('roles', [])
            roles.update(resource_roles)

            current_app.logger.debug(f"User roles: {roles}, Required roles: {required_roles}")
            if not any(role in roles for role in required_roles):
                return jsonify({"message": "Insufficient permissions."}), 403

            return f(*args, **kwargs)
        return decorated
    return decorator

# Routes
@main_bp.route('/')
def index():
    user = session.get('user')
    if user:
        return jsonify(user=user, message="Welcome! You are logged in.")
    return jsonify(message="Welcome! Please log in.", login_url=url_for('main.login', _external=True))

@main_bp.route('/login')
def login():
    # Redirect to Keycloak for authentication
    redirect_uri = url_for('main.authorize', _external=True)
    return current_app.oauth.keycloak.authorize_redirect(redirect_uri)

@main_bp.route('/authorize')
def authorize():
    try:
        # Exchange authorization code for tokens
        token = current_app.oauth.keycloak.authorize_access_token()

        userinfo = token.get('userinfo')
        if not userinfo:
            userinfo = current_app.oauth.keycloak.userinfo(token=token)

        session['user'] = userinfo
        session['user_token'] = token
        current_app.logger.info(f"User {userinfo.get('preferred_username')} logged in successfully.")
        
        # Redirect to a protected area or home page
        return redirect(url_for('main.profile'))
    except OAuth2Error as error:
        current_app.logger.error(f"OAuth2Error during token exchange: {error.description}")
        return jsonify(error="Authentication failed", description=error.description), 400
    except Exception as e:
        current_app.logger.error(f"Exception during authorization: {e}")
        return jsonify(error="Authentication failed", description=str(e)), 500


@main_bp.route('/profile')
def profile():
    user = session.get('user')
    if user:
        return jsonify(user_info=user, message="This is your profile page.")
    return redirect(url_for('main.login'))

@main_bp.route('/logout')
def logout():
    # Clear the local session
    id_token_hint = session.get('user_token', {}).get('id_token')
    session.pop('user', None)
    session.pop('user_token', None)
    
    # Redirect to Keycloak's end session endpoint for Single Sign-Out (SSO logout)
    keycloak_metadata = current_app.oauth.keycloak.load_server_metadata()
    end_session_endpoint = keycloak_metadata.get('end_session_endpoint')
    
    if end_session_endpoint:
        post_logout_redirect_uri = url_for('main.index', _external=True) 
        logout_url = f"{end_session_endpoint}?id_token_hint={id_token_hint}&post_logout_redirect_uri={post_logout_redirect_uri}"
        return redirect(logout_url)
    
    return redirect(url_for('main.index'))

# Protected API Routes
@main_bp.route('/api/public')
def public_resource():
    return jsonify(message="This is a public resource, accessible by anyone.")

@main_bp.route('/api/user/info')
@token_required
def user_info_api():
    # g.user is populated by @token_required
    return jsonify(user=g.user, access_token_subject=g.user.get('sub'))

@main_bp.route('/api/data/viewer')
@token_required
@roles_required(['app_user', 'task_reader'])
def viewer_data_api():
    return jsonify(message=f"Hello {g.user.get('preferred_username')}, you have viewer access!", data="Sensitive viewer data here.")

@main_bp.route('/api/data/editor')
@token_required
@roles_required(['app_admin', 'task_writer'])
def editor_data_api():
    return jsonify(message=f"Hello {g.user.get('preferred_username')}, you have editor access!", data="Highly sensitive editor data here. You can perform write operations.")

@main_bp.route('/api/admin/tasks')
@token_required
@roles_required(['app_admin'])
def admin_tasks_api():
    # Logic for admin tasks
    return jsonify(message=f"Welcome Admin {g.user.get('preferred_username')}! Manage all tasks here.")
