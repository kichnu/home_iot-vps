# IoT Gateway

Flask-based authentication proxy for IoT devices accessible through WireGuard VPN.

## Requirements

- Python 3.10+
- Nginx (SSL termination, device proxy)
- WireGuard (VPN tunnel to IoT devices)

## Installation

```bash
# Clone repository
git clone <repo-url> /opt/home-iot
cd /opt/home-iot

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create data directories
mkdir -p data/database data/logs
```

## Configuration

Create `.env` file:

```bash
cp .env.example .env
nano .env
```

Required variables:
```
WATER_SYSTEM_ADMIN_PASSWORD=<secure_password>
WATER_SYSTEM_SECRET_KEY=<random_64_char_hex>
```

Optional:
```
WATER_SYSTEM_SESSION_TIMEOUT=30
WATER_SYSTEM_MAX_FAILED_ATTEMPTS=8
WATER_SYSTEM_LOCKOUT_DURATION=1
```

Generate secret key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## Systemd Service

Create `/etc/systemd/system/home-iot.service`:

```ini
[Unit]
Description=IoT Gateway
After=network.target

[Service]
Type=simple
User=<user>
WorkingDirectory=/opt/home-iot
Environment=PATH=/opt/home-iot/.venv/bin
ExecStart=/opt/home-iot/.venv/bin/gunicorn -w 4 -b 127.0.0.1:5001 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable home-iot
sudo systemctl start home-iot
sudo systemctl restart home-iot
```

## Nginx Configuration

Key locations in `/etc/nginx/sites-available/home-iot`:

```nginx
# Admin Panel API (port 5001)
location /api/session-info {
    proxy_pass http://127.0.0.1:5001;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Cookie $http_cookie;
}

location /api/device-health/ {
    proxy_pass http://127.0.0.1:5001;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Cookie $http_cookie;
}

# Auth check for device proxy
location = /api/auth-check {
    internal;
    proxy_pass http://127.0.0.1:5001/api/auth-check;
    proxy_set_header Cookie $http_cookie;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}

# Device proxy (WireGuard)
location /device/top_off_water/ {
    auth_request /api/auth-check;
    error_page 401 = @login_redirect;
    proxy_pass http://192.168.10.2/;
}

# Main app
location / {
    proxy_pass http://127.0.0.1:5001;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
}
```
sudo nginx -t && sudo systemctl reload nginx


## Adding Devices

Edit `device_config.py`:

```python
DEVICE_TYPES = {
    'my_device': {
        'name': 'My Device',
        'description': 'Device description',
        'icon': '',
        'color': '#3498db'
    }
}

DEVICE_NETWORK_CONFIG = {
    'my_device': {
        'lan_ip': '192.168.10.X',
        'lan_port': 80,
        'proxy_path': '/device/my_device',
        'has_local_dashboard': True
    }
}
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/login` | Login page |
| `/dashboard` | Device dashboard |
| `/logout` | End session |
| `/health` | Health check |
| `/api/auth-check` | Nginx auth_request |
| `/api/session-info` | Session details |
| `/api/device-health/<type>` | Device connectivity |
