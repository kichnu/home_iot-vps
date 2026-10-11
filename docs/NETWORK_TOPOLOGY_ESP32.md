# Topologia sieci: VPS ↔ WireGuard ↔ ESP32 (LAN domowe)

Ustalone 2026-07-12 przez bezpośrednią inspekcję VPS. Sekcje 1 i 4 potwierdzone bezpośrednim
odczytem `wg0.conf` i `iptables -t nat` (dostarczone przez użytkownika z uprawnieniami roota);
reszta z tablicy routingu i configów nginx (odczyt bez roota).

**Uwaga bezpieczeństwa:** klucze prywatne/publiczne WireGuard z `wg0.conf` celowo nie są tu
cytowane — tylko nazwy peerów i ich `AllowedIPs`.

## 1. WireGuard — POTWIERDZONE (odczyt `wg0.conf`, 2026-07-12)

- Interfejs `wg0` na VPS: adres `10.99.0.1/24`, `ListenPort = 51820`.
- **Peer "MikroTik"** (domowy router): `AllowedIPs = 10.99.0.2/32, 192.168.0.0/16`,
  `PersistentKeepalive = 25`. To ten peer generuje wpis w tablicy routingu
  `192.168.0.0/16 dev wg0` — VPS ma site-to-site tunel do domowego routera MikroTik, który
  dalej routuje do faktycznej sieci LAN (`192.168.10.0/24`, gdzie żyją ESP32). To **nie** jest
  point-to-point do pojedynczego hosta ESP32, tylko hub-and-spoke przez router brzegowy domu.
- **Peer "Pixel8 Phone"**: `AllowedIPs = 10.99.0.3/32` — **bez** dostępu do `192.168.0.0/16` w
  swoim wpisie. Telefon jako peer nie ma więc jawnie przypisanej trasy do LAN-u domowego.
  Teoretycznie WireGuard może i tak przekazać ruch telefon → MikroTik przez VPS jako hub (VPS
  dopasowuje adres docelowy do `AllowedIPs` peera MikroTik niezależnie od tego, kto jest
  nadawcą), o ile na VPS włączony jest `net.ipv4.ip_forward` i łańcuch `FORWARD` (tabela
  `filter`, nieskontrolowana w tej sesji) na to pozwala. Nieustalone ostatecznie, ale AllowedIPs
  telefonu samo w sobie nie blokuje tego scenariusza.
- Tylko dwa peery skonfigurowane — brak osobnego wpisu WireGuard dla ESP32 (`tmp_fan_control`
  ani żadnego innego urządzenia). Urządzenia IoT nie są peerami WG, siedzą za MikroTikiem w LAN.

## 2. Reverse proxy (nginx) na VPS

Plik: `/etc/nginx/sites-available/home-iot`, domena `app.krzysztoforlinski.pl` (TLS przez
certbot/Let's Encrypt).

Produkcyjne urządzenia mają dedykowane `location /device/...`, każdy z `auth_request` do Flaska
(`/api/auth-check`) i `proxy_pass` do LAN-owego IP:

| Urządzenie      | LAN IP          | Nginx path              |
|-----------------|-----------------|--------------------------|
| top_off_water   | 192.168.10.2    | `/device/top_off_water/` |
| doser           | 192.168.10.3    | `/device/doser/`         |
| thermo          | 192.168.10.4    | `/device/thermo/`        |
| switch          | 192.168.10.10   | `/device/switch/`        |

Wszystkie te bloki ustawiają `proxy_set_header X-Forwarded-For $remote_addr;` — czyli realny IP
klienta widziany przez nginx (nadpisuje ewentualny łańcuch, nie używa `$proxy_add_x_forwarded_for`
w tych lokalizacjach).

**Brak jakiegokolwiek `location` dla `fan_control` / `tmp_fan_control`.** Ten testowy szkic nie
był i nie jest przepuszczany przez nginx.

## 3. Jak realnie działał test `tmp_fan_control`

Skoro nie ma dla niego location w nginx, dostęp podczas testu szedł **bezpośrednim routingiem po
wg0**, z pominięciem nginx. Z listy peerów (sekcja 1) wynikają dwa realne scenariusze:

- (a) curl/przeglądarka uruchomiona z shella na samym VPS → ESP32 widzi źródłowy IP `10.99.0.1`.
- (b) telefon "Pixel8 Phone" jako peer WG (`AllowedIPs = 10.99.0.3/32`, bez jawnej trasy do
  `192.168.0.0/16`) → jeśli forwarding na VPS jest włączony, ruch mógł zostać przekierowany do
  peera MikroTik i dalej do ESP32; ESP32 widziałby wtedy źródłowy IP `10.99.0.3` (tunelowy IP
  telefonu), a nie `10.99.0.1`. Wymaga to `ip_forward` + odpowiedniej reguły `FORWARD` na VPS,
  co nie zostało tu bezpośrednio zweryfikowane.

W obu przypadkach **żaden nagłówek `X-Forwarded-For` nie jest ustawiany** — nic po drodze go nie
dokleja, w przeciwieństwie do ruchu produkcyjnego idącego przez nginx.

## 4. DNAT / port forwarding — POTWIERDZONE (odczyt `iptables -t nat -L -n -v`, 2026-07-12)

Brak jakiegokolwiek DNAT/port-forwardingu związanego z WireGuard lub ESP32. Jedyna reguła DNAT w
tabeli `nat` to standardowy łańcuch `DOCKER`, mapujący `127.0.0.1:8080 → 172.18.0.2:8080`
(niezwiązane z IoT/WireGuard — kontener na tym samym VPS). `PREROUTING`/`INPUT`/`OUTPUT` poza
tym bez reguł dotyczących ruchu z internetu do ESP32. Potwierdza to, że cały dostęp do urządzeń
idzie przez `proxy_pass` w nginx (produkcja) albo przez routing w warstwie WireGuard (test), nie
przez DNAT na styku z publicznym internetem.

## 5. Domena / TLS

Jedna domena `app.krzysztoforlinski.pl` obsługuje wszystkie urządzenia przez `/device/*`,
certyfikat Let's Encrypt (auto-renew, pliki w
`/etc/letsencrypt/live/app.krzysztoforlinski.pl/`). Brak osobnej subdomeny dla ESP32 testowego.
Jeśli `tmp_fan_control` trafi do produkcji, analogicznie dostanie `location /device/fan_control/`
pod tą samą domeną/TLS.

## Wniosek dla auth na ESP32 (`TRUSTED_PROXY_IP` / `auth_manager.cpp`)

Kod ESP32 (w innym repo, nieobecny na tym VPS w chwili sprawdzania) hardkoduje
`TRUSTED_PROXY_IP = 10.99.0.1` w `src/config/config.cpp`.

- Dla ruchu produkcyjnego przez nginx to poprawne założenie: nginx zawsze łączy się z ESP32 z
  adresu `10.99.0.1` po wg0 i zawsze dokleja `X-Forwarded-For`.
- Trzeba jednak poprawnie obsłużyć przypadek, gdy źródłowy IP == `10.99.0.1`, ale nagłówek
  `X-Forwarded-For` jest **nieobecny** (bezpośredni dostęp z shella VPS, jak w teście
  `tmp_fan_control`) — inaczej powstaje niespójność między trybem testowym a produkcyjnym.
  Brak XFF przy source IP == trusted proxy nie powinien być traktowany jako próba spoofingu, tylko
  jako fallback na surowy peer IP.
- Jeśli dostęp idzie od innego peera WG (np. telefon bezpośrednio w LAN), source IP nie będzie
  `10.99.0.1`, więc logika "ufaj tylko 10.99.0.1" zadziała bezpiecznie — żaden XFF nie zostanie
  zaufany, a IP użyte do np. rate limitingu to i tak surowy IP tunelowy peera.

# Dopisek do dokumentacji VPS: Topologia sieci VPS ↔ WireGuard ↔ ESP32

Ten plik to uzupełnienie dokumentu topologii sieciowej trzymanego na VPS
(`# Topologia sieci: VPS ↔ WireGuard ↔ ESP32 (LAN domowe)`, ustalony 2026-07-12).
Treść poniżej należy dopisać na końcu tamtego dokumentu jako sekcja 6 + uzupełnienie
wniosku z sekcji "Wniosek dla auth na ESP32". Zapisane tutaj lokalnie (2026-07-13),
bo kopiowanie polskich znaków przez terminal na VPS sprawiało problemy.

---

## 6. Firmware-side pułapki przy integracji nowych urządzeń (ustalone 2026-07-13, thermo_control)

Podczas wdrażania `thermo_control` pod `/device/thermo/` trafiliśmy na dwa problemy
niewidoczne z samej strony nginx/WireGuard — dotyczą kodu ESP32, ale są bezpośrednią
konsekwencją tej topologii, więc dotkną każdego kolejnego urządzenia podpinanego pod
`/device/<nazwa>/`.

### 6.1. Ścieżki bezwzględne w HTML psują się pod prefiksem

Dashboard/login serwowane przez ESP32 używały bezwzględnych ścieżek
(`fetch('/api/status')`, `window.location.href = '/login'`). Lokalnie
(`http://192.168.10.x/`) działa to poprawnie, ale pod `/device/<nazwa>/` przeglądarka
wysyła taki `fetch` do `https://app.krzysztoforlinski.pl/api/status` — czyli do bloku
`location /api/ { proxy_pass http://127.0.0.1:5000; }` (Flask), **nie** do
urządzenia. Efekt: strona się ładuje (pierwszy GET trafia poprawnie przez
`location /device/<nazwa>/`), ale cały JS przestaje działać — wygląda jak "brak
połączenia", choć routing sieciowy jest w 100% sprawny.

Fix zastosowany w thermo_control: wszystkie `fetch()`/`location.href` w
`src/web/html_pages.cpp` zmienione na ścieżki **względne** (bez wiodącego `/`) —
działają identycznie spod `/` (LAN) i spod `/device/thermo/` (VPS), bo przeglądarka
rozwiązuje je względem katalogu bieżącej strony.

**Wymaga to końcowego `/` w URL-u** (`/device/thermo/`, nie `/device/thermo`) — bez
niego `location /device/thermo/ {...}` w ogóle nie dopasuje żądania (prefix match
wymaga literalnego `/` na końcu), więc względne ścieżki i tak nie pomogą.

**Reguła dla przyszłych integracji:** każdy dashboard ESP32 mający trafić pod
`/device/<nazwa>/` musi używać wyłącznie względnych ścieżek do własnego API/stron —
zero `fetch('/api/...')`, zero `location.href = '/...'`. Sam katalog głównego
`server.on("/", ...)` może zostać bez zmian, problem dotyczy tylko treści HTML/JS.

### 6.2. `checkAuthentication()` na ESP32 pomija sesję dla ruchu z trusted proxy

`src/web/web_server.cpp:52` (repo thermo_control) — funkcja użyta przez wszystkie
endpointy owinięte w `requireAuth()`:

```cpp
bool checkAuthentication(AsyncWebServerRequest* request) {
    IPAddress clientIP = request->client()->remoteIP();
    if (isTrustedProxy(clientIP)) {
        return true;   // <-- bez sprawdzenia cookie sesji!
    }
    ...
}
```

Ponieważ nginx łączy się z ESP32 zawsze z `10.99.0.1` (nowe połączenie TCP przez
`proxy_pass`, niezależnie od oryginalnego klienta), **każde** żądanie przychodzące
przez VPS ma `remoteIP() == 10.99.0.1` i przechodzi ten check natychmiast — bez
walidacji `session_token`. Innymi słowy: dla ruchu z internetu jedyną realną bramką
autoryzacji jest `auth_request /api/auth-check` po stronie nginx/Flask; własny
system logowania ESP32 (`/api/login`, ciasteczko sesji) **realnie chroni tylko
dostęp bezpośredni w LAN** (gdy `remoteIP()` ≠ trusted proxy).

To jest spójne z komentarzem w kodzie ("WireGuard cryptographically authenticates
the VPS — IP check is sufficient") i nie jest błędem — ale warto to mieć jawnie
zapisane, bo:

- Jeśli kiedyś `auth_request` na nginx zostanie źle skonfigurowany/wyłączony dla
  jakiegoś urządzenia, ESP32 nie ma żadnej drugiej linii obrony — natychmiast wpuści
  ruch z `10.99.0.1` bez pytania o hasło.
- Endpoint `POST /api/login` **nie** jest owinięty w `requireAuth()` (to punkt
  wejścia), więc dla niego rate-limiting liczy się poprawnie po realnym IP klienta
  (`resolveClientIP()` w `auth_manager.cpp` — czyta `X-Forwarded-For` gdy source ==
  trusted proxy). To jedyne miejsce, gdzie realny IP klienta z internetu w ogóle
  dociera do logiki ESP32; wszystkie pozostałe `/api/*` po zalogowaniu nie znają już
  realnego IP i nie próbują go znać — świadomie polegają na warstwie nginx.

**Reguła dla przyszłych integracji:** przy dodawaniu nowego urządzenia z takim samym
wzorcem `TRUSTED_PROXY_IP` w `config.cpp`, świadomie decydujemy że nginx `auth_request`
jest jedyną faktyczną bramką dla ruchu produkcyjnego — nie zakładać, że sesja/hasło
ESP32 cokolwiek chronią, gdy urządzenie jest dostępne przez `/device/*`.

### 6.3. Drobne, warte odnotowania przy okazji

- Blok `/device/thermo/health` (i analogiczne dla innych urządzeń) **nie** ma
  `auth_request` — health-check jest celowo publiczny, tylko `proxy_pass` do
  `/api/health` urządzenia.
- Wzorzec `proxy_intercept_errors on; error_page 502 503 504 = @esp32_offline;` (blok
  `/device/thermo/`) to gotowy szablon do skopiowania dla kolejnych urządzeń — daje
  ładny fallback zamiast gołego 502 z nginx, gdy ESP32 jest offline/resetuje się.

### 6.4. Workaround w `device_config.py` trzeba ręcznie cofnąć, gdy firmware dojrzeje (ustalone 2026-07-13)

Dopóki `thermo_control` nie miał kontraktu `/api/health`, Flask (`device_config.py`)
był skonfigurowany na tymczasowy tryb:

```python
'health_endpoint': '/api/state',
'health_check_mode': 'reachable',  # brak {"status":"ok"} - liczy się sama odpowiedź JSON
```

Gdy firmware ESP32 doszedł do właściwego `/api/health` (`{"status":"ok"}`), ten wpis
**nie cofnął się sam** — zostawiony workaround zaczął strzelać w drugą stronę:
`/api/state` przestał istnieć w nowym firmware (404), więc health-check w
`utils/health_check.py` zgłaszał urządzenie jako offline, mimo że WireGuard/routing
były w 100% sprawne, a `curl http://192.168.10.4/api/health` z VPS zwracał poprawne
`200 {"status":"ok"}`. Objaw ("offline" na dashboardzie, urządzenie działa lokalnie)
wygląda identycznie jak realny problem sieciowy z sekcji 1-4, ale przyczyna jest
czysto konfiguracyjna po stronie Flask.

**Reguła dla przyszłych integracji:** jeśli nowe urządzenie startuje z tymczasowym
`health_check_mode: 'reachable'` (bo firmware jeszcze nie ma `/api/health`), to
zmiana ta jest z definicji tymczasowa i **musi zostać ręcznie cofnięta** w
`device_config.py` (`health_endpoint` -> `/api/health`, usunięcie
`health_check_mode`) w tym samym PR/commitcie, który dodaje właściwy endpoint po
stronie firmware. Traktować komentarz "Temporary firmware..." przy takim wpisie jako
TODO do zamknięcia, nie trwały element konfiguracji.

## Aktualizacja wniosku z sekcji "Wniosek dla auth na ESP32"

Punkt o obsłudze braku XFF przy source IP == trusted proxy jest już zaimplementowany
poprawnie — ale **tylko** w `resolveClientIP()` (`auth_manager.cpp`, używane przez
`/api/login`), nie w `checkAuthentication()` (używane przez resztę `/api/*`, patrz
6.2 wyżej — tam kwestia XFF jest w ogóle nieistotna, bo trusted proxy dostaje pełne
zaufanie bez sprawdzania czegokolwiek poza samym source IP).

```cpp
// auth_manager.cpp — poprawny fallback, dotyczy tylko /api/login
IPAddress resolveClientIP(AsyncWebServerRequest* request) {
    IPAddress sourceIP = request->client()->remoteIP();
    if (isTrustedProxy(sourceIP) && request->hasHeader("X-Forwarded-For")) {
        // ... parsuje XFF ...
        return realIP;
    }
    return sourceIP;  // fallback gdy brak XFF, np. bezpośredni dostęp z shella VPS
}
```

Potwierdza to więc oba scenariusze z sekcji 3 (curl z shella VPS bez XFF, ruch
produkcyjny z XFF) są obsłużone bezpiecznie i bez niespójności w kodzie ESP32 — przy
zastrzeżeniu z 6.2, że dotyczy to wyłącznie logiki `/api/login`, reszta endpointów
w ogóle nie patrzy na IP klienta gdy przychodzi z trusted proxy.
