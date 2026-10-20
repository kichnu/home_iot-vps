"""
Device Configuration for IoT Gateway
Network configuration for device proxy through WireGuard
"""

# ============================================
# DEVICE TYPES - Basic info for dashboard
# ============================================

DEVICE_TYPES = {
    'water_system': {
        'name': 'Top Off Water',
        'description': 'Water Top-Off System',
        'icon': '',
        'color': '#38bdf8'
    },
    'doser_system': {
        'name': 'Doser',
        'description': 'Aquarium Dosing System',
        'icon': '',
        'color': '#27ae60'
    },
    'switch_system': {
        'name': 'Switch Timer',
        'description': 'Switch Timer',
        'icon': '',
        'color': '#e67e22'
    },
    'thermo_control': {
        'name': 'Thermo Control',
        'description': 'Aquarium Temperature Controller',
        'icon': '',
        'color': '#f87171'
    },
    'lamp_1': {
        'name': 'Lamp 1',
        'description': 'Aquarium LED Lamp',
        'icon': '',
        'color': '#facc15'
    },
    'lamp_2': {
        'name': 'Lamp 2',
        'description': 'Aquarium LED Lamp',
        'icon': '',
        'color': '#facc15'
    }
}


def get_device_config(device_type):
    """Get configuration for device type"""
    return DEVICE_TYPES.get(device_type, {})


# ============================================
# NETWORK CONFIGURATION FOR DEVICE PROXY
# Used by health check and dashboard
# ============================================

DEVICE_NETWORK_CONFIG = {
    'water_system': {
        'lan_ip': '192.168.10.2',
        'lan_port': 80,
        'proxy_path': '/device/top_off_water',
        'health_endpoint': '/api/health',
        'has_local_dashboard': True,
        'timeout_seconds': 5
    },
    'doser_system': {
        'lan_ip': '192.168.10.3',
        'lan_port': 80,
        'proxy_path': '/device/doser',
        'health_endpoint': '/api/health',
        'has_local_dashboard': True,
        'timeout_seconds': 5
    },
    'switch_system': {
        'lan_ip': '192.168.10.10',
        'lan_port': 80,
        'proxy_path': '/device/switch',
        'health_endpoint': '/api/health',
        'has_local_dashboard': True,
        'timeout_seconds': 5
    },
    'thermo_control': {
        'lan_ip': '192.168.10.4',
        'lan_port': 80,
        'proxy_path': '/device/thermo',
        'health_endpoint': '/api/health',
        'has_local_dashboard': True,
        'timeout_seconds': 5
    },
    'lamp_1': {
        'lan_ip': '192.168.10.5',
        'lan_port': 80,
        'proxy_path': '/device/lamp1',
        'health_endpoint': '/api/health',
        'has_local_dashboard': True,
        'timeout_seconds': 5
    },
    'lamp_2': {
        'lan_ip': '192.168.10.6',
        'lan_port': 80,
        'proxy_path': '/device/lamp2',
        'health_endpoint': '/api/health',
        'has_local_dashboard': True,
        'timeout_seconds': 5
    },
}


def get_device_network_config(device_type: str) -> dict:
    """Get network configuration for device type"""
    return DEVICE_NETWORK_CONFIG.get(device_type, {})


def get_all_devices_with_dashboard() -> list:
    """Get all devices that have local dashboards"""
    devices = []
    for device_type, network_config in DEVICE_NETWORK_CONFIG.items():
        if network_config.get('has_local_dashboard'):
            device_config = get_device_config(device_type)
            devices.append({
                'type': device_type,
                'name': device_config.get('name', device_type),
                'icon': device_config.get('icon', ''),
                'color': device_config.get('color', '#95a5a6'),
                'description': device_config.get('description', ''),
                'proxy_path': network_config.get('proxy_path', ''),
                'has_local_dashboard': True
            })
    return devices
