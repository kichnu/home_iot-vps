"""
WebAuthn/FIDO2 passkey authentication for IoT Gateway.
Handles registration and authentication ceremonies for the single admin user.
"""

import json
import time
import logging
from typing import Optional

from webauthn import (
    generate_registration_options as wa_generate_registration_options,
    verify_registration_response as wa_verify_registration_response,
    generate_authentication_options as wa_generate_authentication_options,
    verify_authentication_response as wa_verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    AuthenticatorTransport,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from config import Config
from database import get_db_connection


def generate_registration_options() -> dict:
    """
    Generate WebAuthn registration options (challenge) for the admin user.

    Returns:
        dict with 'options_json' (serialized for frontend) and
        'challenge' (bytes to store in session for verification)
    """
    exclude_credentials = []
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT credential_id, transports FROM webauthn_credentials')
            rows = cursor.fetchall()
            for row in rows:
                transports = []
                if row['transports']:
                    try:
                        transport_list = json.loads(row['transports'])
                        transports = [AuthenticatorTransport(t) for t in transport_list]
                    except (json.JSONDecodeError, ValueError):
                        pass
                exclude_credentials.append(
                    PublicKeyCredentialDescriptor(
                        id=base64url_to_bytes(row['credential_id']),
                        transports=transports,
                    )
                )
    except Exception as e:
        logging.error(f"Error loading existing credentials for exclusion: {e}")

    options = wa_generate_registration_options(
        rp_id=Config.WEBAUTHN_RP_ID,
        rp_name=Config.WEBAUTHN_RP_NAME,
        user_id=b"admin",
        user_name="admin",
        user_display_name="IoT Gateway Admin",
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=exclude_credentials,
        timeout=60000,
    )

    return {
        'options_json': options_to_json(options),
        'challenge': options.challenge,
    }


def verify_registration_response(credential_json: str, expected_challenge: bytes) -> dict:
    """
    Verify a WebAuthn registration response and store the credential.

    Args:
        credential_json: JSON string from navigator.credentials.create()
        expected_challenge: The challenge bytes stored in session

    Returns:
        dict with 'success' and 'credential_id' or 'error'
    """
    try:
        verification = wa_verify_registration_response(
            credential=credential_json,
            expected_challenge=expected_challenge,
            expected_origin=Config.WEBAUTHN_ORIGIN,
            expected_rp_id=Config.WEBAUTHN_RP_ID,
            require_user_verification=True,
        )
    except Exception as e:
        logging.error(f"WebAuthn registration verification failed: {e}")
        return {'success': False, 'error': str(e)}

    credential_id = bytes_to_base64url(verification.credential_id)
    public_key = verification.credential_public_key
    sign_count = verification.sign_count

    # Extract transports from the credential JSON if available
    transports_json = None
    try:
        cred_data = json.loads(credential_json)
        transports = cred_data.get('response', {}).get('transports')
        if transports:
            transports_json = json.dumps(transports)
    except (json.JSONDecodeError, AttributeError):
        pass

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO webauthn_credentials
                   (credential_id, public_key, sign_count, transports, created_at)
                   VALUES (?, ?, ?, ?, ?)''',
                (credential_id, public_key, sign_count, transports_json, int(time.time()))
            )
    except Exception as e:
        logging.error(f"Failed to store WebAuthn credential: {e}")
        return {'success': False, 'error': 'Failed to store credential'}

    return {'success': True, 'credential_id': credential_id}


def generate_authentication_options(conditional: bool = False) -> Optional[dict]:
    """
    Generate WebAuthn authentication options (challenge).

    Args:
        conditional: True for conditional UI (passkey autofill) - allowCredentials is left
            empty, so only discoverable credentials are offered by the browser

    Returns:
        dict with 'options_json' and 'challenge', or None if no credentials registered
    """
    allow_credentials = []
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT credential_id, transports FROM webauthn_credentials')
            rows = cursor.fetchall()
    except Exception as e:
        logging.error(f"Error loading credentials for authentication: {e}")
        return None

    if not rows:
        return None

    for row in rows:
        transports = []
        if row['transports']:
            try:
                transport_list = json.loads(row['transports'])
                transports = [AuthenticatorTransport(t) for t in transport_list]
            except (json.JSONDecodeError, ValueError):
                pass
        allow_credentials.append(
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(row['credential_id']),
                transports=transports,
            )
        )

    options = wa_generate_authentication_options(
        rp_id=Config.WEBAUTHN_RP_ID,
        allow_credentials=[] if conditional else allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )

    return {
        'options_json': options_to_json(options),
        'challenge': options.challenge,
    }


def verify_authentication_response(credential_json: str, expected_challenge: bytes) -> dict:
    """
    Verify a WebAuthn authentication response.

    Args:
        credential_json: JSON string from navigator.credentials.get()
        expected_challenge: Challenge bytes from session

    Returns:
        dict with 'success': True or 'success': False with 'error'
    """
    try:
        cred_data = json.loads(credential_json)
    except json.JSONDecodeError:
        return {'success': False, 'error': 'Invalid credential JSON'}

    credential_id_b64 = cred_data.get('id') or cred_data.get('rawId')
    if not credential_id_b64:
        return {'success': False, 'error': 'Missing credential ID'}

    # Look up stored credential
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE credential_id = ?',
                (credential_id_b64,)
            )
            row = cursor.fetchone()
    except Exception as e:
        logging.error(f"Error looking up credential: {e}")
        return {'success': False, 'error': 'Database error'}

    if not row:
        return {'success': False, 'error': 'Unknown credential'}

    try:
        verification = wa_verify_authentication_response(
            credential=credential_json,
            expected_challenge=expected_challenge,
            expected_origin=Config.WEBAUTHN_ORIGIN,
            expected_rp_id=Config.WEBAUTHN_RP_ID,
            credential_public_key=row['public_key'],
            credential_current_sign_count=row['sign_count'],
            require_user_verification=True,
        )
    except Exception as e:
        logging.error(f"WebAuthn authentication verification failed: {e}")
        return {'success': False, 'error': str(e)}

    # Update sign count and last used timestamp
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE credential_id = ?',
                (verification.new_sign_count, int(time.time()), credential_id_b64)
            )
    except Exception as e:
        logging.error(f"Failed to update sign count: {e}")

    return {'success': True}


def get_registered_credentials() -> list:
    """Get all registered WebAuthn credentials (metadata only, no public keys)."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT credential_id, friendly_name, created_at, last_used_at FROM webauthn_credentials ORDER BY created_at DESC'
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logging.error(f"Error listing credentials: {e}")
        return []


def delete_credential(credential_id: str) -> bool:
    """Delete a WebAuthn credential by ID."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM webauthn_credentials WHERE credential_id = ?', (credential_id,))
            return cursor.rowcount > 0
    except Exception as e:
        logging.error(f"Error deleting credential: {e}")
        return False


def has_registered_credentials() -> bool:
    """Check if any WebAuthn credentials are registered."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as cnt FROM webauthn_credentials')
            row = cursor.fetchone()
            return row['cnt'] > 0
    except Exception as e:
        logging.error(f"Error checking credentials: {e}")
        return False
