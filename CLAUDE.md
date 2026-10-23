# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IoT VPS Gateway - a Flask-based authentication proxy for IoT devices accessible through WireGuard VPN. The application runs behind Nginx (which handles SSL termination and device proxying) and provides session-based authentication to protect access to IoT device dashboards.

## Commands

```bash
# Run the application (development)
python app.py

# Run with gunicorn (production)
gunicorn -w 4 -b 0.0.0.0:5001 app:app

# Restart the systemd service (production)
sudo systemctl restart home-iot
```

## Architecture

### Request Flow
1. Client -> Nginx (SSL termination) -> Flask app (authentication)
2. Nginx uses `/api/auth-check` endpoint to validate sessions before proxying to IoT devices
3. Device proxy paths (e.g., `/device/top_off_water`) are handled by Nginx, not Flask

### Key Modules

**`app.py`** - Main Flask application with routes:
- Authentication: `/login`, `/logout`
- Dashboard: `/dashboard` (protected, shows device cards)
- API: `/api/auth-check` (Nginx auth_request), `/api/device-health/<device_type>`
- WebAuthn: `/api/webauthn/register/begin|complete`, `/api/webauthn/auth/begin|complete`, `/api/webauthn/credentials`

**`auth/`** - Session management module:
- `session.py` - Database-backed sessions with IP tracking, failed login tracking, account lockout
- `decorators.py` - `@require_admin_auth` decorator for protected routes
- `webauthn.py` - FIDO2/WebAuthn passkey registration and authentication ceremonies

**`database/`** - SQLite layer (WAL mode enabled):
- `connection.py` - Context manager `get_db_connection()` with auto-commit
- `init.py` - Schema for `admin_sessions`, `failed_login_attempts`, and `webauthn_credentials` tables

**`device_config.py`** - Device definitions:
- `DEVICE_TYPES` - Display info (name, icon, color)
- `DEVICE_NETWORK_CONFIG` - Network info (WireGuard IPs, ports, proxy paths)

**`utils/`**:
- `security.py` - `secure_compare()` (timing-safe), `get_real_ip()` (Nginx-aware)
- `health_check.py` - TCP connectivity check to devices with 30s caching

### Configuration

Environment variables (prefix `WATER_SYSTEM_`):
- `ADMIN_PASSWORD` (required) - Single admin password
- `SECRET_KEY` - Flask session key (auto-generated if empty)
- `ADMIN_PORT` - Default 5001
- `NGINX_MODE` - Default true (affects IP detection)
- `SESSION_TIMEOUT` - Minutes, default 30
- `MAX_FAILED_ATTEMPTS` / `LOCKOUT_DURATION` - Brute-force protection
- `WEBAUTHN_RP_ID` - Domain name for WebAuthn (e.g., `app.krzysztoforlinski.pl`)
- `WEBAUTHN_RP_NAME` - Display name (default: `IoT Gateway`)
- `WEBAUTHN_ORIGIN` - Full origin URL (e.g., `https://app.krzysztoforlinski.pl`)

### Database

SQLite at `data/database/sessions.db` with three tables:
- `admin_sessions` - Session tokens, IP, timestamps
- `failed_login_attempts` - IP-based lockout tracking
- `webauthn_credentials` - FIDO2 passkey credentials (credential_id, public_key, sign_count)

No event logging or data storage - this is purely an auth gateway.

### WebAuthn / FIDO2 Passkey Authentication

**Library:** `webauthn==2.7.0` (py_webauthn by Duo Labs)

**Flow:**
1. Admin logs in with password, registers passkey from Dashboard -> bottom drawer (`^`) -> Passkeys
2. On next login, "Sign in with Passkey" button appears alongside password form
3. Conditional UI (passkey autofill): the login page starts a `mediation: 'conditional'` request on load,
   so passkeys are offered in the password field's autofill list (`autocomplete="current-password webauthn"`).
   It calls `/api/webauthn/auth/begin` with `{"conditional": true}`, which leaves `allowCredentials` empty
   (discoverable credentials only). The button aborts the pending conditional request and runs the modal
   flow with the full `allowCredentials` list (needed for non-discoverable security keys).
4. Passkey auth creates the same session as password login (uses `create_session()`)
5. Failed WebAuthn attempts feed into existing IP-based lockout system

**Registration:** Requires active session (password login first). No `authenticator_attachment` restriction - accepts platform (fingerprint), cross-device (QR code), and security keys (NFC/USB).

**Nginx:** `/api/webauthn/` routes require explicit proxy rule to port 5001 in Nginx config. Without it, the generic `/api/` rule routes to port 5000 (ESP32).

**Security:** Challenges stored in Flask session (server-side, signed). Consumed once via `session.pop()`. User verification required. Sign count validated on each auth.

### Known Issues - GrapheneOS

**Google Password Manager passkeys do NOT work on GrapheneOS** (tested Jan 2026):
- Sandboxed Google Play Services lack full access to the lockout/biometrics API
- PIN verification loops endlessly ("unlock device again" prompt repeats)
- Happens even with all permissions granted to Play Services
- Affects both Vanadium and Chrome browsers
- **Standard Android works correctly** - fingerprint registration and login confirmed

**Working setup on GrapheneOS** (confirmed Oct 2026): a third-party passkey provider through
Android Credential Manager, without Google Password Manager:
- Install Bitwarden (Proton Pass should work the same way)
- Settings -> Passwords, passkeys & accounts: set Bitwarden as the preferred service, disable Google
- Register the passkey in Vanadium; login works with Bitwarden's fingerprint/unlock prompt
- Bitwarden passkeys are synced through its cloud (not device-bound)

**Other options:**
- Hardware security key (YubiKey 5C NFC, Google Titan) via NFC or USB-C - usually needs sandboxed Play
- Cross-device flow: scan QR code with a standard Android phone
- Fall back to password login (always available)
