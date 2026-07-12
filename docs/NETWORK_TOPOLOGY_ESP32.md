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
