#!/usr/bin/env python3
"""
IoT VPS Gateway - Proxy to IoT devices through WireGuard
Simplified version without database logging functionality
"""

import os
import sys
import time
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, make_response
import logging
from datetime import datetime
import secrets
from flask_limiter import Limiter
from flask_wtf.csrf import CSRFProtect, CSRFError
from config import Config
from utils.security import secure_compare, get_real_ip
from database import get_db_connection, init_database_path, init_database
from device_config import DEVICE_NETWORK_CONFIG, get_device_config, get_device_network_config
from auth import (
    cleanup_expired_sessions,
    get_failed_attempts_info,
    record_failed_attempt,
    reset_failed_attempts,
    create_session,
    validate_session,
    destroy_session,
    require_admin_auth,
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    get_registered_credentials,
    delete_credential,
    has_registered_credentials,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path)
        print(f"Loaded environment variables from {env_path}")
except ImportError:
    print("python-dotenv not installed, using system environment variables only")

# Verify configuration on startup
if not Config.verify_required_vars():
    sys.exit(1)

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY or secrets.token_hex(32)
app.permanent_session_lifetime = Config.SESSION_PERMANENT_LIFETIME

# Initialize CSRF protection
# The automatic before_request check is disabled: it would reject requests before
# the view's rate limit and lockout logic run, leaving CSRF-less POST floods
# unthrottled. Form views call csrf.protect() explicitly instead (see login_submit).
app.config['WTF_CSRF_CHECK_DEFAULT'] = False
csrf = CSRFProtect(app)

# API routes keep @csrf.exempt as documentation; they use session auth, not forms

app.config.update(
    TEMPLATES_AUTO_RELOAD=Config.TEMPLATES_AUTO_RELOAD,
    SESSION_COOKIE_HTTPONLY=Config.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=Config.SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_NAME=Config.SESSION_COOKIE_NAME,
    SESSION_COOKIE_SECURE=Config.SESSION_COOKIE_SECURE,
)

app.jinja_env.auto_reload = True

# ============================================
# RATE LIMITING CONFIGURATION
# ============================================

def get_real_ip_for_limiter():
    """Get real client IP for rate limiting (Nginx-aware)."""
    return get_real_ip()

limiter = Limiter(
    app=app,
    key_func=get_real_ip_for_limiter,
    default_limits=["5000 per day", "500 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
    headers_enabled=True,
)

logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_PATH),
        logging.StreamHandler()
    ]
)
logging.getLogger('werkzeug').setLevel(logging.WARNING)

Config.log_startup_info(logging)
init_database_path(Config.DATABASE_PATH)


# ============================================
# SECURITY HEADERS
# ============================================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'"
    # Prevent caching of login/auth pages to avoid stale CSRF tokens in bfcache
    if request.path in ('/login', '/logout'):
        response.headers['Cache-Control'] = 'no-store'
    return response


# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.route('/login')
@limiter.limit("30 per 15 minutes")
def login_page():
    """Login page (GET) - higher rate limit"""
    if validate_session():
        return redirect(url_for('device_dashboard'))
    passkeys_available = has_registered_credentials()
    response = make_response(render_template('login.html', passkeys_available=passkeys_available))
    response.headers['Cache-Control'] = 'no-store'
    return response


def _login_response(status_code, passkeys_available=None):
    """Render login page with cache-busting headers to prevent bfcache CSRF issues."""
    if passkeys_available is None:
        passkeys_available = has_registered_credentials()
    response = make_response(render_template('login.html', passkeys_available=passkeys_available), status_code)
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/login', methods=['POST'])
@limiter.limit("10 per 15 minutes")
def login_submit():
    """Handle login with centralized error handling."""
    client_ip = get_real_ip()

    try:
        # Check if account is locked
        attempt_info = get_failed_attempts_info(client_ip)

        if attempt_info.get('is_locked'):
            time_left_seconds = attempt_info.get('time_until_unlock', 0)
            time_left_minutes = max(1, time_left_seconds // 60)

            flash(
                f'Account temporarily locked due to too many failed attempts. '
                f'Try again in {time_left_minutes} minutes.',
                'error'
            )
            logging.warning(
                f"Blocked login attempt from locked IP: {client_ip} "
                f"(unlocks in {time_left_minutes} minutes)"
            )
            return _login_response(429)

        # CSRF check after rate limit and lockout, so failures count as attempts
        try:
            csrf.protect()
        except CSRFError as e:
            result = record_failed_attempt(client_ip)
            logging.warning(
                f"CSRF validation failed on login from IP: {client_ip} ({e.description}) "
                f"(attempt {result['attempt_count']}/{Config.MAX_FAILED_ATTEMPTS})"
            )
            flash('Session expired. Please try again.', 'error')
            return _login_response(400)

        # Validate password
        password = request.form.get('password', '')

        if not password:
            flash('Password is required.', 'error')
            return _login_response(400)

        if secure_compare(password, Config.ADMIN_PASSWORD):
            # Successful login
            reset_failed_attempts(client_ip)
            create_session(client_ip)
            logging.info(f"Successful admin login from IP: {client_ip}")
            return redirect(url_for('device_dashboard'))

        # Failed login - record attempt
        result = record_failed_attempt(client_ip)

        if result.get('is_locked'):
            flash(
                f'Too many failed attempts. Account locked for '
                f'{result["lockout_duration_hours"]} hour(s).',
                'error'
            )
            logging.warning(
                f"Failed admin login from IP: {client_ip} "
                f"(attempt {result['attempt_count']}/{Config.MAX_FAILED_ATTEMPTS}) - ACCOUNT LOCKED"
            )
            return _login_response(429)
        else:
            remaining = result.get('remaining_attempts', 0)
            flash(f'Invalid password. {remaining} attempts remaining.', 'error')
            logging.warning(
                f"Failed admin login from IP: {client_ip} "
                f"(attempt {result['attempt_count']}/{Config.MAX_FAILED_ATTEMPTS}, {remaining} remaining)"
            )
            return _login_response(401)

    except Exception as e:
        logging.error(f"Login error for IP {client_ip}: {e}", exc_info=True)
        flash(
            'An error occurred during login. Please try again or contact administrator.',
            'error'
        )
        return _login_response(500)


@app.route('/logout', methods=['GET', 'POST'])
@csrf.exempt
def logout():
    """User logout"""
    if not validate_session():
        # No active session - nothing to log out, keep the audit log clean
        return redirect(url_for('login_page'))
    client_ip = get_real_ip()
    destroy_session()
    logging.info(f"Admin logout from IP: {client_ip}")
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login_page'))


# ============================================
# DASHBOARD ROUTES
# ============================================

@app.route('/')
@app.route('/admin')
@require_admin_auth
def admin_dashboard():
    """Redirect to dashboard"""
    return redirect(url_for('device_dashboard'))


@app.route('/dashboard')
@require_admin_auth
def device_dashboard():
    """Multi-device dashboard"""
    client_ip = get_real_ip()

    try:
        # Build device list from network config (devices with dashboards)
        discovered_types = []
        for device_type, network_config in DEVICE_NETWORK_CONFIG.items():
            if network_config.get('has_local_dashboard'):
                config = get_device_config(device_type)
                discovered_types.append({
                    'type': device_type,
                    'name': config.get('name', device_type.title()),
                    'icon': config.get('icon', ''),
                    'color': config.get('color', '#95a5a6'),
                    'description': config.get('description', ''),
                    'proxy_path': network_config.get('proxy_path', ''),
                    'has_local_dashboard': True
                })

        logging.info(f"Dashboard accessed from {client_ip} - {len(discovered_types)} devices")

        return render_template('dashboard.html',
                             device_types=discovered_types,
                             recent_activity=[])

    except Exception as e:
        logging.error(f"Dashboard error: {e}")
        return jsonify({'error': 'Dashboard error'}), 500


# ============================================
# API ROUTES
# ============================================

@app.route('/api/auth-check')
@limiter.exempt
def auth_check():
    """
    Internal endpoint for Nginx auth_request.
    Returns 200 if session valid, 401 if not.
    Used to protect /device/* proxy routes.
    """
    if validate_session():
        return '', 200
    return '', 401


@app.route('/api/session-info')
@require_admin_auth
def session_info():
    """Session information for frontend"""
    session_data = {
        'authenticated': True,
        'login_time': session.get('login_time'),
        'timeout_minutes': Config.SESSION_TIMEOUT_MINUTES,
        'client_ip': get_real_ip()
    }
    return jsonify(session_data)


@app.route('/api/device-health/<device_type>')
@require_admin_auth
def device_health_check(device_type):
    """Check if IoT device is reachable through WireGuard"""
    from utils.health_check import check_device_health

    if device_type not in DEVICE_NETWORK_CONFIG:
        return jsonify({'error': f'Unknown device type: {device_type}'}), 404

    health = check_device_health(device_type)

    return jsonify({
        'success': True,
        'device_type': device_type,
        'online': health['online'],
        'latency_ms': health.get('latency_ms'),
        'cached': health.get('cached', False)
    }), 200


@app.route('/health', methods=['GET'])
@limiter.limit("30 per minute")
def health_check():
    """Application health check endpoint"""
    cleanup_expired_sessions()

    db_ok = False
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            db_ok = True
    except Exception as e:
        logging.error(f"Health check DB error: {e}")

    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': 'ok' if db_ok else 'error',
        'nginx_mode': Config.ENABLE_NGINX_MODE
    }), 200


# ============================================
# WEBAUTHN / PASSKEY ROUTES
# ============================================

@app.route('/api/webauthn/register/begin', methods=['POST'])
@require_admin_auth
@csrf.exempt
@limiter.limit("10 per hour")
def webauthn_register_begin():
    """Begin WebAuthn credential registration (must be logged in)."""
    try:
        result = generate_registration_options()
        session['webauthn_reg_challenge'] = bytes_to_base64url(result['challenge'])
        return jsonify({'options': result['options_json']}), 200
    except Exception as e:
        logging.error(f"WebAuthn register begin error: {e}")
        return jsonify({'error': 'Failed to generate registration options'}), 500


@app.route('/api/webauthn/register/complete', methods=['POST'])
@require_admin_auth
@csrf.exempt
@limiter.limit("10 per hour")
def webauthn_register_complete():
    """Complete WebAuthn credential registration."""
    challenge_b64 = session.pop('webauthn_reg_challenge', None)
    if not challenge_b64:
        return jsonify({'error': 'No registration challenge found. Start over.'}), 400

    try:
        challenge_bytes = base64url_to_bytes(challenge_b64)
        credential_json = request.get_data(as_text=True)

        result = verify_registration_response(credential_json, challenge_bytes)

        if result.get('success'):
            logging.info(f"WebAuthn credential registered: {result['credential_id'][:16]}...")
            return jsonify({'success': True, 'credential_id': result['credential_id']}), 200
        else:
            return jsonify({'error': result.get('error', 'Registration failed')}), 400
    except Exception as e:
        logging.error(f"WebAuthn register complete error: {e}")
        return jsonify({'error': 'Registration verification failed'}), 500


@app.route('/api/webauthn/auth/begin', methods=['POST'])
@csrf.exempt
@limiter.limit("20 per 15 minutes")
def webauthn_auth_begin():
    """Begin WebAuthn authentication (login page, no session required)."""
    client_ip = get_real_ip()

    attempt_info = get_failed_attempts_info(client_ip)
    if attempt_info.get('is_locked'):
        return jsonify({'error': 'Account temporarily locked'}), 429

    try:
        result = generate_authentication_options()
        if result is None:
            return jsonify({'error': 'No passkeys registered'}), 404

        session['webauthn_auth_challenge'] = bytes_to_base64url(result['challenge'])
        return jsonify({'options': result['options_json']}), 200
    except Exception as e:
        logging.error(f"WebAuthn auth begin error: {e}")
        return jsonify({'error': 'Failed to generate authentication options'}), 500


@app.route('/api/webauthn/auth/complete', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per 15 minutes")
def webauthn_auth_complete():
    """Complete WebAuthn authentication and create session."""
    client_ip = get_real_ip()

    challenge_b64 = session.pop('webauthn_auth_challenge', None)
    if not challenge_b64:
        return jsonify({'error': 'No authentication challenge found. Start over.'}), 400

    try:
        challenge_bytes = base64url_to_bytes(challenge_b64)
        credential_json = request.get_data(as_text=True)

        result = verify_authentication_response(credential_json, challenge_bytes)

        if result.get('success'):
            reset_failed_attempts(client_ip)
            create_session(client_ip)
            logging.info(f"WebAuthn login successful from IP: {client_ip}")
            return jsonify({'success': True, 'redirect': url_for('device_dashboard')}), 200
        else:
            record_failed_attempt(client_ip)
            logging.warning(f"WebAuthn auth failed from IP: {client_ip}: {result.get('error')}")
            return jsonify({'error': 'Authentication failed'}), 401
    except Exception as e:
        logging.error(f"WebAuthn auth complete error: {e}")
        record_failed_attempt(client_ip)
        return jsonify({'error': 'Authentication verification failed'}), 500


@app.route('/api/webauthn/credentials', methods=['GET'])
@require_admin_auth
def webauthn_list_credentials():
    """List all registered WebAuthn credentials."""
    credentials = get_registered_credentials()
    return jsonify({'credentials': credentials}), 200


@app.route('/api/webauthn/credentials/<credential_id>', methods=['DELETE'])
@require_admin_auth
@csrf.exempt
def webauthn_delete_credential(credential_id):
    """Delete a WebAuthn credential."""
    if delete_credential(credential_id):
        logging.info(f"WebAuthn credential deleted: {credential_id[:16]}...")
        return jsonify({'success': True}), 200
    return jsonify({'error': 'Credential not found'}), 404


# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(CSRFError)
def csrf_error(error):
    # Fallback for csrf.protect() calls outside login_submit
    logging.warning(f"CSRF validation failed from IP: {get_real_ip()} on {request.path} ({error.description})")
    return jsonify({'error': 'CSRF validation failed'}), 400


# ============================================
# SERVER STARTUP
# ============================================

def run_admin_server():
    """Run HTTP server for Admin Panel (Nginx handles SSL)"""
    logging.info(f"Starting Admin server on port {Config.ADMIN_PORT} (HTTP - Nginx handles SSL)")
    app.run(host='0.0.0.0', port=Config.ADMIN_PORT, debug=False, threaded=True)


if __name__ == '__main__':
    # Initialize database on startup - MUST succeed before starting server
    if not init_database():
        logging.critical("FATAL: Cannot start server without working database")
        logging.critical(f"Check path and permissions: {Config.DATABASE_PATH}")
        sys.exit(1)

    logging.info("IoT VPS Gateway started (Nginx Mode)")
    logging.info(f"Database: {Config.DATABASE_PATH}")
    logging.info(f"Session timeout: {Config.SESSION_TIMEOUT_MINUTES} minutes")
    logging.info(f"Account lockout: {Config.MAX_FAILED_ATTEMPTS} attempts, {Config.LOCKOUT_DURATION_HOURS}h ban")
    logging.info(f"Nginx reverse proxy mode: {Config.ENABLE_NGINX_MODE}")

    logging.info(f"Starting server on http://0.0.0.0:{Config.ADMIN_PORT}")

    run_admin_server()
