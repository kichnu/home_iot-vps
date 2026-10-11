"""
Device health check utilities
Checks if IoT devices are reachable through WireGuard
Uses HTTP GET /api/health per device contract (not TCP connect)
"""

import time
import logging
import urllib.request
import urllib.error
import json
from typing import Dict
from device_config import get_device_network_config

# Cache health results for 30 seconds
_health_cache: Dict[str, dict] = {}
_cache_timeout = 30  # seconds


def check_device_health(device_type: str) -> dict:
    """
    Check if device is reachable via HTTP GET /api/health.
    Results are cached for 30 seconds to avoid spamming ESP32.

    Returns:
        dict with keys: online, latency_ms, last_check, cached, device_name
    """
    current_time = time.time()

    # Check cache
    if device_type in _health_cache:
        cached = _health_cache[device_type]
        if current_time - cached['timestamp'] < _cache_timeout:
            return {
                'online': cached['online'],
                'latency_ms': cached['latency_ms'],
                'last_check': cached['last_check'],
                'device_name': cached.get('device_name'),
                'cached': True
            }

    # Get device network config
    config = get_device_network_config(device_type)
    if not config:
        return {
            'online': False,
            'latency_ms': None,
            'last_check': current_time,
            'error': 'Unknown device type'
        }

    lan_ip = config.get('lan_ip')
    lan_port = config.get('lan_port', 80)
    timeout = config.get('timeout_seconds', 5)
    health_endpoint = config.get('health_endpoint', '/api/health')
    health_check_mode = config.get('health_check_mode', 'strict')

    url = f"http://{lan_ip}:{lan_port}{health_endpoint}"

    # HTTP health check per contract: GET /api/health -> {"status":"ok",...}
    online = False
    latency_ms = None
    device_name = None
    start_time = time.time()

    try:
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.time() - start_time) * 1000)
            if resp.status == 200:
                body = json.loads(resp.read().decode('utf-8'))
                if health_check_mode == 'reachable':
                    # No {"status":"ok"} contract available - any valid JSON
                    # response on this endpoint means the device is up.
                    online = True
                    device_name = body.get('device_name')
                    logging.debug(
                        f"Device {device_type} health check: online ({latency_ms}ms, reachable mode)"
                    )
                elif body.get('status') == 'ok':
                    online = True
                    device_name = body.get('device_name')
                    logging.debug(
                        f"Device {device_type} health check: online ({latency_ms}ms)"
                    )
                else:
                    logging.warning(
                        f"Device {device_type} health check: status={body.get('status')}"
                    )
            else:
                logging.warning(
                    f"Device {device_type} health check: HTTP {resp.status}"
                )

    except (urllib.error.URLError, OSError) as e:
        logging.warning(f"Device {device_type} health check: unreachable ({e})")

    except json.JSONDecodeError:
        latency_ms = int((time.time() - start_time) * 1000)
        logging.warning(f"Device {device_type} health check: invalid JSON response")

    except Exception as e:
        logging.error(f"Device {device_type} health check error: {e}")

    # Update cache
    _health_cache[device_type] = {
        'online': online,
        'latency_ms': latency_ms,
        'last_check': current_time,
        'device_name': device_name,
        'timestamp': current_time
    }

    return {
        'online': online,
        'latency_ms': latency_ms,
        'last_check': current_time,
        'device_name': device_name,
        'cached': False
    }


def get_all_devices_health() -> Dict[str, dict]:
    """Check health of all devices with dashboards"""
    from device_config import DEVICE_NETWORK_CONFIG

    results = {}
    for device_type in DEVICE_NETWORK_CONFIG.keys():
        results[device_type] = check_device_health(device_type)

    return results
