# IoT + VPS — Wzorce bezpieczenstwa i implementacji

Referencja dla wszystkich urzadzen ESP32 IoT oraz aplikacji VPS (IoT Gateway).
Kazde nowe urzadzenie MUSI implementowac wzorce opisane w tym dokumencie.

**Architektura ogolna:**
```
Przegladarka --> HTTPS --> VPS (nginx + Flask) --> WireGuard --> Router domowy --> ESP32
                  |              |                                                  ^
            TLS termination   auth_request                                   HTTP LAN
                             + proxy
```

VPS pelni dwie role:
1. **Brama autentykacji** — wlasna sesja (haslo + WebAuthn passkeys), chroni dostep do dashboardu VPS
2. **Transparent proxy** — po uwierzytelnieniu w bramie, nginx przepuszcza ruch do ESP32 (ktore maja wlasna autentykacje)

---

# CZESC I — Strona IoT (ESP32)

## 1. Architektura bezpieczenstwa

Kazde urzadzenie ESP32 implementuje warstwowy model dostepu:

```
Dostep LAN (bezposredni):
  Source IP -> Whitelist? -> RateLimit? -> Sesja? -> Dostep
                 403          429          401       200

Dostep zdalny (przez VPS proxy):
  Source IP == TRUSTED_PROXY_IP?
    → Auto-auth: checkAuthentication() zwraca true natychmiast
    → VPS juz uwierzytelnił uzytkownika przez auth_request + sesje VPS
    → ESP32 nie wymaga wlasnej sesji dla requestow z proxy
```

### Warstwy ochrony

| Warstwa | Dostep LAN | Dostep zdalny (VPS) |
|---|---|---|
| Transport | WiFi (brak TLS) | WireGuard tunel (szyfrowany) |
| IP whitelist | `ALLOWED_IPS[]` — odrzucenie 403 | Pominieta — auto-auth dla TRUSTED_PROXY_IP |
| Rate limiting | Per source IP | Pominiete — VPS ma wlasny rate limiter |
| Autentykacja ESP32 | Haslo admin → sesja cookie | Pominieta — VPS auth_request jest granica zaufania |
| Autentykacja VPS | n/a | Haslo/WebAuthn → sesja VPS → auth_request → nginx proxy |

## 2. Trusted Proxy — rozpoznawanie i X-Forwarded-For

| Element | Implementacja |
|---|---|
| `TRUSTED_PROXY_IP` | Oddzielny `const IPAddress` w `config.h`, NIE w tablicy `ALLOWED_IPS[]` |
| Rozpoznanie proxy | `isTrustedProxy()` — `request->client()->remoteIP() == TRUSTED_PROXY_IP` |
| Auto-auth | `checkAuthentication()` zwraca `true` natychmiast dla trusted proxy |
| X-Forwarded-For | Parsowanie WYLACZNIE gdy source IP == `TRUSTED_PROXY_IP` |
| Real IP extraction | `resolveClientIP()` — pierwszy IP z XFF (leftmost = oryginalny klient) |
| Zastosowanie real IP | Logowanie (LOG_INFO) — auth i rate limit pominiete |
| Fallback | Brak XFF → fallback na source IP (proxy IP) |

### resolveClientIP() — referencja implementacji

```cpp
// auth_manager.cpp
IPAddress resolveClientIP(AsyncWebServerRequest* request) {
    IPAddress sourceIP = request->client()->remoteIP();
    if (isTrustedProxy(sourceIP) && request->hasHeader("X-Forwarded-For")) {
        String xff = request->getHeader("X-Forwarded-For")->value();
        int comma = xff.indexOf(',');
        String clientStr = (comma > 0) ? xff.substring(0, comma) : xff;
        clientStr.trim();
        IPAddress realIP;
        if (realIP.fromString(clientStr)) return realIP;
        LOG_WARNING("Failed to parse X-Forwarded-For: %s", xff.c_str());
    }
    return sourceIP;
}
```

### Bezpieczenstwo X-Forwarded-For

| Zasada | Opis |
|---|---|
| Trust boundary | XFF zaufany WYLACZNIE gdy source IP == `TRUSTED_PROXY_IP` |
| Header spoofing | Kazde inne zrodlo XFF ignorowane — klienci moga go sfalszyc |
| Auto-auth model | ESP32 ufa proxy calkowicie — VPS odpowiada za autentykacje i rate limiting |
| Defense in depth | Wielowarstwowa ochrona na VPS: auth_request + sesja + rate limiter + lockout |

## 3. Wspolne API — endpointy kazdego urzadzenia

Kazde urzadzenie ESP32 MUSI implementowac ponizsze endpointy.
Specyficzne endpointy urzadzenia (np. `/api/relay/*`) sa poza ta lista.

### Endpointy wymagane

| Method | Path | Auth | Opis |
|---|---|---|---|
| GET | `/` | Session | Dashboard HTML urzadzenia |
| GET | `/login` | Whitelist/Proxy | Strona logowania |
| POST | `/api/login` | Whitelist/Proxy | Tworzenie sesji (haslo → cookie) |
| POST | `/api/logout` | Session | Zamkniecie sesji |
| GET | `/api/status` | Session | Stan urzadzenia + dane systemowe |
| GET | `/api/health` | Whitelist + Proxy IP | Health check (bez sesji) |

### /api/health — kontrakt

Lekki endpoint do monitoringu. Bez sesji, bez rate limitingu.

```json
{
    "status": "ok",
    "device_name": "smart-switch",
    "uptime": 123456
}
```

Warunek dostepu: `isIPAllowed(sourceIP) || isTrustedProxy(sourceIP)` → else 403.

VPS odpytuje ten endpoint przez HTTP GET (nie TCP connect) i waliduje odpowiedz JSON: `status == "ok"` + HTTP 200 = urzadzenie zyje. Timeout, nie-200, lub brak `"ok"` = urzadzenie niedostepne.

### /api/status — kontrakt

Pelny status urzadzenia. Wymaga sesji.

Pola wspolne (kazde urzadzenie):
```json
{
    "uptime": 123456,
    "free_heap": 280000,
    "wifi_connected": true,
    "wifi_status": "Connected (192.168.2.100)"
}
```

Pola specyficzne — zaleza od urzadzenia (np. `relay_state`, `remaining_seconds` dla switch-timer).

### /api/login — kontrakt

Request: `POST`, body `application/x-www-form-urlencoded`, pole `password`.
Response sukces: `{"success":true}` + `Set-Cookie: session_token=<token>; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800`.
Response blad: `{"success":false, "error":"..."}`.

## 4. Autentykacja haslem (SHA-256)

| Element | Implementacja |
|---|---|
| Hashing | `hashPassword()` — mbedtls SHA-256, lowercase hex (64 znaki) |
| Weryfikacja | `verifyPassword()` — porownanie hash input z hashem z NVS |
| Przechowywanie | Hash w NVS (Preferences library), nigdy plaintext |
| Blokada bez NVS | `areCredentialsLoaded()` = false → 503 |

## 5. Sesje (token + IP binding)

| Element | Implementacja |
|---|---|
| Token | 32 znaki hex, `session_manager.cpp` |
| Powiazanie z IP | `session.ip == ip` — real IP (po resolveClientIP) |
| Cookie | `session_token=<val>; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800` |
| Timeout | 30 min nieaktywnosci |
| Limity | Max 10 sesji globalnie, max 3 per IP |
| Czyszczenie | `updateSessionManager()` w loop |

## 6. Rate limiting

| Element | Implementacja |
|---|---|
| Limit zapytan | 5 req/s per IP w oknie 1s |
| Blokada | 10 nieudanych prob → blokada na 60s |
| IP przez proxy | Rate limit per real IP z XFF |
| Cleanup | Co 5 min usuwanie starych wpisow |

## 7. Przechowywanie credentiali (NVS)

| NVS Key | Wartosc | Wymagane |
|---|---|---|
| `"configured"` | bool — flaga konfiguracji | tak |
| `"device_name"` | Identyfikator urzadzenia (3-32 zn., `[a-zA-Z0-9_-]`) | tak |
| `"wifi_ssid"` | SSID sieci WiFi | tak |
| `"wifi_pass"` | Haslo WiFi (plaintext, wymagane przez WiFi.begin) | tak |
| `"admin_hash"` | SHA-256 hex hasla admin (64 znaki) | tak |

Namespace NVS: `"creds"`. Jesli brakuje wymaganych pol → `loaded = false` → 503 na /api/login.

## 8. Provisioning (Captive Portal)

| Element | Implementacja |
|---|---|
| Wejscie | Dedykowany GPIO przytrzymany 5s podczas boot |
| Tryb | WiFi AP + DNS + web server z formularzem |
| Pola | device_name, wifi_ssid, wifi_password, admin_password |
| Walidacja | Server-side + client-side (regex, min/max length) |
| Zapis | NVS (haslo admin jako SHA-256 hash) |
| Po zapisie | Wymaga fizycznego power cycle (brak auto-restart) |

## 9. Auto-recovery

| Mechanizm | Parametry |
|---|---|
| 24h auto-restart | `millis() > 86400000` → safe stop → `ESP.restart()` |
| WiFi reconnect | Co 30s jesli rozlaczony |
| Session cleanup | W loop, usuwa wygasle (>30min) |
| Rate limit cleanup | Co 5 min |
| Safe output stop | Przed restart — wymuszone wylaczenie wyjscia |

## 10. Ochrona pamieci (ESP32 heap)

| Element | Implementacja |
|---|---|
| Sesje | `vector.reserve(10)`, hard limit 10 globalnie |
| Rate limit timestamps | Hard limit 20 per IP |
| IP cache | Max 10 wpisow, FIFO |

---

# CZESC II — Strona VPS (nginx + Flask)

## 11. Architektura sieciowa

```
Przegladarka --> HTTPS --> VPS (nginx) --> WireGuard tunel --> Router domowy --> ESP32
                  |              |                                                ^
            TLS termination   auth_request                              Dostep LAN (HTTP)
                             + proxy
```

Kazde urzadzenie ma swoj adres IP w sieci WireGuard i jest dostepne na porcie 80.

### Wzorzec auth_request

Nginx uzywa `auth_request` do walidacji sesji VPS przed przepuszczeniem ruchu do ESP32:

```nginx
# Wewnetrzny endpoint — Flask waliduje sesje
location = /api/auth-check {
    internal;
    proxy_pass http://127.0.0.1:5001/api/auth-check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
}

# Kazdy device location uzywa auth_request
location /device/<device_name>/ {
    auth_request /api/auth-check;
    # ... proxy_pass do ESP32
}
```

Flask endpoint `/api/auth-check`:
- Zwraca `200` jesli sesja VPS wazna → nginx przepuszcza request do ESP32
- Zwraca `401` jesli brak sesji → nginx zwraca blad (redirect do /login)

**Model auto-auth:** Uzytkownik loguje sie TYLKO do VPS (brama). ESP32 automatycznie ufa requestom z TRUSTED_PROXY_IP (auto-auth) — nie wymaga osobnego logowania przez proxy. Przy dostepie LAN (bezposrednim) ESP32 wymaga wlasnej sesji. VPS NIE przechowuje hasel urzadzen ani ich tokenow sesji.

## 12. nginx — konfiguracja proxy dla urzadzen IoT

### Obowiazkowe naglowki

```nginx
location /device/<device_name>/ {
    auth_request /api/auth-check;
    proxy_pass http://<WG_IP_DEVICE>:80/;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Host $host;
    proxy_http_version 1.1;
}
```

| Wymaganie | Opis |
|---|---|
| `auth_request` | MUSI byc obecne — walidacja sesji VPS przed proxy |
| `X-Forwarded-For $remote_addr` | MUSI byc `$remote_addr`, NIE `$proxy_add_x_forwarded_for` |
| Path stripping | `proxy_pass` z `/` na koncu automatycznie usuwa prefix |
| TLS termination | nginx odpowiada za HTTPS do przegladarki |
| WireGuard | Szyfruje tunel VPS <-> router domowy (zastepuje TLS do ESP32) |

> **Dlaczego `$remote_addr`?** `$proxy_add_x_forwarded_for` dopisuje do istniejacego naglowka XFF — klient moze wstrzyknac falszywy IP. `$remote_addr` nadpisuje calkowicie.

### Health check — monitoring urzadzen

VPS odpytuje `/api/health` kazdego urzadzenia:

```nginx
location = /device/<device_name>/health {
    proxy_pass http://<WG_IP_DEVICE>:80/api/health;
    # Bez auth_request — VPS odpytuje bezposrednio jako TRUSTED_PROXY_IP
}
```

## 13. Kontrakt API: VPS <-> IoT

VPS traktuje kazde urzadzenie jako identyczny serwis HTTP z ustalonym API:

| Operacja VPS | Endpoint IoT | Auth ESP32 | Cel |
|---|---|---|---|
| Monitoring zdrowia | `GET /api/health` | IP only (proxy/whitelist) | Sprawdzenie czy urzadzenie zyje |
| Proxy dashboardu | `GET /` | Auto-auth (proxy) | Dostep uzytkownika do dashboardu |
| Proxy logowania | `POST /api/login` | Auto-auth (proxy) | Niepotrzebne przez proxy — auto-auth |
| Proxy statusu | `GET /api/status` | Auto-auth (proxy) | Polling stanu urzadzenia |
| Proxy akcji | `POST /api/relay/*` | Auto-auth (proxy) | Sterowanie urzadzeniem |

Przez proxy (VPS) ESP32 nie wymaga wlasnej sesji — auto-auth na podstawie TRUSTED_PROXY_IP. Przy dostepie LAN kazde urzadzenie zarzadza wlasna autentykacja (haslo + sesja cookie).

## 14. Bezpieczenstwo VPS — Flask

### 14.1 Trusted Proxy — weryfikacja zrodla headerow

Wzorzec analogiczny do ESP32 `isTrustedProxy()`:

```python
# utils/security.py
TRUSTED_PROXY_IPS = ['127.0.0.1', '::1']  # nginx na tym samym serwerze

def get_real_ip() -> str:
    if Config.ENABLE_NGINX_MODE and request.remote_addr in TRUSTED_PROXY_IPS:
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
    return request.remote_addr
```

| Zasada | Opis |
|---|---|
| Trust boundary | Headery XFF/X-Real-IP zaufane WYLACZNIE gdy `remote_addr` to nginx (localhost) |
| Ochrona portu | Port 5001 zablokowany z zewnatrz (iptables/firewall) — dodatkowa warstwa |
| Spoofing | Bezposredni request na 5001 z falszywym XFF → `remote_addr` nie jest w trusted list → uzyty `remote_addr` |

### 14.2 Sesje (database-backed)

| Element | Implementacja |
|---|---|
| Token | `secrets.token_urlsafe(32)` (43 znaki, 256 bitow entropii) |
| Przechowywanie | SQLite (`admin_sessions`) + Flask signed cookie |
| Powiazanie z IP | Sesja walidowana z real IP (po `get_real_ip()`) — **MUSI byc wlaczone** |
| Cookie | `iot_session`; `HttpOnly=True`; `SameSite=Strict`; `Secure=True` |
| Timeout | 30 min nieaktywnosci (konfigurowalne) |
| Limity sesji | Max sesji per IP — zapobiega DoS przez flood logowan |
| Czyszczenie | `cleanup_expired_sessions()` przy walidacji |

### 14.3 Rate limiting (flask-limiter)

| Element | Implementacja |
|---|---|
| Biblioteka | `flask-limiter` z memory backend |
| Key function | `get_real_ip()` — per real IP klienta |
| Login POST | 10 req / 15 min |
| Login GET | 30 req / 15 min |
| WebAuthn auth begin | 20 req / 15 min |
| WebAuthn auth complete | 10 req / 15 min |
| WebAuthn register | 10 req / godzine |
| Health check | 30 req / min |
| Domyslne | 5000/dzien, 500/godz |

### 14.4 Failed login tracking + lockout

| Element | Implementacja |
|---|---|
| Tracking | Per IP w SQLite (`failed_login_attempts`) |
| Prog blokady | 8 nieudanych prob (konfigurowalne) |
| Czas blokady | 1 godzina (konfigurowalne) |
| Zakres | Obie metody — haslo i WebAuthn — liczone razem |
| Fail-open | Blad DB → pozwol na probe (ochrona przed DoS przez awarie DB) |

### 14.5 CSRF

| Element | Implementacja |
|---|---|
| Biblioteka | `Flask-WTF` CSRFProtect |
| Formularze | Token CSRF w kazdy formularzu HTML |
| API JSON | Endpointy API zwolnione z CSRF (`@csrf.exempt`) — uzywaja sesji, nie formularzy |
| Cookie | `SameSite=Strict` — dodatkowa ochrona |

### 14.6 Security headers

```python
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'"
    )
    return response
```

Kazdy response z Flask zawiera powyzsze headery. ESP32 nie ustawia tych headerow (ograniczenia pamieci).

### 14.7 WebAuthn / FIDO2 Passkeys (tylko VPS)

Passkeys to dodatkowa metoda logowania do bramy VPS (obok hasla). ESP32 NIE implementuja WebAuthn.

**Biblioteka:** `webauthn==2.7.0` (py_webauthn by Duo Labs)

**Flow rejestracji:**
1. Admin loguje sie haslem do VPS
2. Dashboard → Security → rejestracja passkey
3. Przegladarka wywoluje `navigator.credentials.create()`
4. Credential (public key) zapisany w SQLite (`webauthn_credentials`)

**Flow logowania:**
1. Strona logowania VPS → "Sign in with Passkey" albo passkey wybrany z listy autouzupelniania pola hasla
   (conditional UI, `mediation: 'conditional'`, `allowCredentials` puste — tylko klucze odkrywalne)
2. Przegladarka wywoluje `navigator.credentials.get()`
3. VPS weryfikuje podpis, tworzy sesje (`create_session()`)
4. Nieudane proby WebAuthn liczone w tym samym systemie lockout co haslo

**Endpointy:**

| Method | Path | Auth | Opis |
|---|---|---|---|
| POST | `/api/webauthn/register/begin` | Session | Generuj opcje rejestracji (challenge) |
| POST | `/api/webauthn/register/complete` | Session | Zweryfikuj i zapisz credential |
| POST | `/api/webauthn/auth/begin` | None | Generuj opcje autentykacji (challenge) |
| POST | `/api/webauthn/auth/complete` | None | Zweryfikuj i utworz sesje |
| GET | `/api/webauthn/credentials` | Session | Lista zarejestrowanych passkeys |
| DELETE | `/api/webauthn/credentials/<id>` | Session | Usun passkey |

**Bezpieczenstwo:**

| Zasada | Implementacja |
|---|---|
| Challenge | Losowy, przechowywany w Flask session (server-side, signed) |
| Zuzycie | `session.pop()` — jednorazowy, zapobiega replay |
| User verification | `require_user_verification=True` (biometria/PIN wymagany) |
| Sign count | Walidowany przy kazdym logowaniu (wykrywa klonowanie klucza) |
| Origin | Weryfikowany z `WEBAUTHN_ORIGIN` (np. `https://app.example.com`) |
| RP ID | Weryfikowany z `WEBAUTHN_RP_ID` (domena) |

**nginx:** Routy `/api/webauthn/` wymagaja dedykowanej reguly proxy do portu 5001. Bez niej, generyczna regula `/api/` kieruje na port 5000 (ESP32).

```nginx
location /api/webauthn/ {
    proxy_pass http://127.0.0.1:5001/api/webauthn/;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header Host $host;
}
```

**Znane ograniczenie — GrapheneOS:**
Passkey platform authenticator nie dziala na GrapheneOS (sandboxed Play Services). Obejscia: hardware security key (NFC/USB), cross-device QR code, fallback na haslo.

## 15. Baza danych VPS (SQLite)

Sciezka: `data/database/sessions.db`. WAL mode wlaczony.

### Schemat

```sql
-- Sesje admina
CREATE TABLE admin_sessions (
    session_id TEXT PRIMARY KEY,
    client_ip TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_activity INTEGER NOT NULL,
    user_agent TEXT
);
CREATE INDEX idx_session_activity ON admin_sessions(last_activity);
CREATE INDEX idx_session_ip ON admin_sessions(client_ip);

-- Tracking nieudanych logowan
CREATE TABLE failed_login_attempts (
    client_ip TEXT PRIMARY KEY,
    attempt_count INTEGER DEFAULT 0,
    last_attempt INTEGER NOT NULL,
    locked_until INTEGER DEFAULT NULL
);
CREATE INDEX idx_locked_until ON failed_login_attempts(locked_until);

-- Passkeys (WebAuthn)
CREATE TABLE webauthn_credentials (
    credential_id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    created_at INTEGER NOT NULL,
    friendly_name TEXT DEFAULT 'Passkey',
    last_used_at INTEGER
);
CREATE INDEX idx_webauthn_created ON webauthn_credentials(created_at);
```

Brak event loggingu ani przechowywania danych IoT — czysto auth gateway.

## 16. Konfiguracja VPS — zmienne srodowiskowe

| Zmienna | Wymagana | Domyslna | Opis |
|---|---|---|---|
| `WATER_SYSTEM_ADMIN_PASSWORD` | tak | — | Haslo admina (plaintext, porownanie constant-time) |
| `WATER_SYSTEM_SECRET_KEY` | nie | auto-gen | Klucz podpisu Flask session cookie |
| `WATER_SYSTEM_ADMIN_PORT` | nie | `5001` | Port Flask |
| `WATER_SYSTEM_NGINX_MODE` | nie | `true` | Tryb reverse proxy (wplywa na IP detection) |
| `WATER_SYSTEM_SESSION_TIMEOUT` | nie | `30` | Timeout sesji (minuty) |
| `WATER_SYSTEM_MAX_FAILED_ATTEMPTS` | nie | `8` | Prog blokady per IP |
| `WATER_SYSTEM_LOCKOUT_DURATION` | nie | `1` | Czas blokady (godziny) |
| `WATER_SYSTEM_WEBAUTHN_RP_ID` | nie | `localhost` | Domena dla WebAuthn |
| `WATER_SYSTEM_WEBAUTHN_RP_NAME` | nie | `IoT Gateway` | Nazwa wyswietlana w przegladarce |
| `WATER_SYSTEM_WEBAUTHN_ORIGIN` | nie | `https://localhost` | Pelny origin URL |
| `WATER_SYSTEM_DATABASE_PATH` | nie | `data/database/sessions.db` | Sciezka SQLite |
| `WATER_SYSTEM_LOG_PATH` | nie | `data/logs/app.log` | Sciezka logu |
| `WATER_SYSTEM_LOG_LEVEL` | nie | `INFO` | Poziom logowania |

---

# CZESC III — Procedury

## 17. Dodawanie nowego urzadzenia IoT

### Krok 1: Firmware ESP32

1. Skopiowac szkielet projektu (security/, web/, config/, provisioning/)
2. Ustawic `TRUSTED_PROXY_IP` w `config.h` na IP VPS w WireGuard
3. Ustawic `ALLOWED_IPS[]` na adresy LAN
4. Zaimplementowac endpointy wspolne (sekcja 3):
   - `GET /` — dashboard HTML
   - `GET /login` — strona logowania
   - `POST /api/login` — tworzenie sesji
   - `POST /api/logout` — zamkniecie sesji
   - `GET /api/status` — pola wspolne + specyficzne
   - `GET /api/health` — `{"status":"ok","device_name":"...","uptime":...}`
5. Zaimplementowac endpointy specyficzne (np. `/api/relay/*`, `/api/dose/*`)
6. Provisioning: device_name, wifi, admin password
7. `pio run` — kompilacja, upload, test

### Krok 2: Siec WireGuard

1. Przydzielic IP WireGuard dla nowego urzadzenia (nastepny z puli `192.168.10.x`)
2. Dodac peer WireGuard na routerze domowym
3. Dodac peer WireGuard na VPS
4. Sprawdzic polaczenie: `ping <WG_IP>` z VPS

### Krok 3: VPS — device_config.py

Dodac wpisy w dwoch slownikach:

```python
# device_config.py

DEVICE_TYPES = {
    # ...istniejace...
    '<device_type>': {
        'name': '<Nazwa wyswietlana>',
        'description': '<Opis urzadzenia>',
        'icon': '<emoji>',
        'color': '#<hex>'
    }
}

DEVICE_NETWORK_CONFIG = {
    # ...istniejace...
    '<device_type>': {
        'lan_ip': '192.168.10.<X>',
        'lan_port': 80,
        'proxy_path': '/device/<device_name>',
        'health_endpoint': '/api/health',
        'has_local_dashboard': True,
        'timeout_seconds': 5
    }
}
```

Po dodaniu wpisow dashboard VPS automatycznie pokaze nowe urzadzenie (karty generowane dynamicznie z `DEVICE_NETWORK_CONFIG`).

### Krok 4: VPS — nginx

Dodac trzy bloki location:

```nginx
# 1. Proxy do dashboardu urzadzenia (wymaga sesji VPS)
location /device/<device_name>/ {
    auth_request /api/auth-check;
    proxy_pass http://<WG_IP>:80/;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Host $host;
    proxy_http_version 1.1;
}

# 2. Health check (bez sesji — VPS odpytuje jako trusted proxy)
location = /device/<device_name>/health {
    proxy_pass http://<WG_IP>:80/api/health;
}

# 3. WebSocket jesli urzadzenie uzywa (opcjonalnie)
location /device/<device_name>/ws {
    auth_request /api/auth-check;
    proxy_pass http://<WG_IP>:80/ws;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

Weryfikacja: `sudo nginx -t && sudo systemctl reload nginx`

### Krok 5: Weryfikacja

1. Sprawdz health check: `curl https://<domain>/device/<device_name>/health`
   - Oczekiwane: `{"status":"ok","device_name":"...","uptime":...}`
2. Sprawdz dashboard VPS: nowa karta urzadzenia z prawidlowym statusem online/offline
3. Sprawdz proxy: klik w karte → przekierowanie do dashboardu ESP32 → logowanie na ESP32
4. Sprawdz logi: `journalctl -u home-iot -f` — brak bledow

## 18. Rejestr urzadzen

| Urzadzenie | device_type | device_name (ESP32) | WireGuard IP | Proxy path | Port |
|---|---|---|---|---|---|
| Dolewka (water top-off) | `water_system` | `dolewka` | 192.168.10.2 | `/device/top_off_water/` | 80 |
| Doser | `doser_system` | `doser` | 192.168.10.3 | `/device/doser/` | 80 |
| Switch Timer | `switch_system` | `switch-timer` | 192.168.10.X | `/device/switch/` | 80 |

---

# CZESC IV — Znane ograniczenia i mitygacje

## Ograniczenia ESP32

| Ograniczenie | Opis | Mitygacja |
|---|---|---|
| Brak TLS na ESP32 | HTTP w LAN nieszyfrowany | WireGuard chroni tunel do VPS |
| Slaby PRNG tokenow | `random()` — niska entropia | Sesje krotkotrwale (30 min), IP-bound |
| Brak CSRF | POST bez weryfikacji origin | SameSite=Strict cookie |
| Timing attack na haslo | `String ==` nie jest constant-time | Rate limiting + blokada IP |
| Hardcoded whitelist | Zmiana wymaga rekompilacji | Dostep zdalny przez VPS (nie wymaga whitelist) |
| Hardcoded AP password | Kazdy z fizycznym dostepem moze wejsc w provisioning | Wymaga fizycznego przycisku 5s |
| Brak persystencji logow | Audit trail tylko w RAM | VPS loguje persystentnie do pliku |
| Brak security headers | Ograniczenia pamieci ESP32 | VPS dodaje headery (CSP, X-Frame-Options, etc.) |

## Ograniczenia VPS

| Ograniczenie | Opis | Mitygacja |
|---|---|---|
| Haslo admin plaintext w env | `.env` zawiera haslo w plaintext | Plik z uprawnieniami 600, poza repo |
| SQLite single-writer | Jeden proces piszacy w danym momencie | WAL mode, gunicorn z workerami (kazdy ma polaczenie) |
| Memory-based rate limiter | Reset przy restarcie procesu | Akceptowalne — krotkotrwale okna |
| Brak 2FA na hasle | Haslo jest jedynym wymaganym czynnikiem | WebAuthn passkeys jako silna alternatywa |
| GrapheneOS passkeys | Platform authenticator nie dziala | Hardware key (NFC/USB), cross-device QR, fallback na haslo |
