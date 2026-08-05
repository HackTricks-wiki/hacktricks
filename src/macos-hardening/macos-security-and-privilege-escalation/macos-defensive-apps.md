# Applications défensives macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html) : Il surveille chaque connexion établie par chaque processus. Selon le mode (autorisation silencieuse des connexions, refus silencieux des connexions et alertes), il **vous affichera une alerte** chaque fois qu'une nouvelle connexion est établie. Il dispose également d'une très bonne interface graphique pour consulter toutes ces informations.
- [**LuLu**](https://objective-see.org/products/lulu.html) : Firewall d'Objective-See. Il s'agit d'un firewall basique qui vous alertera en cas de connexions suspectes (il possède une interface graphique, mais elle est moins sophistiquée que celle de Little Snitch).

## Détection de la persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html) : Application d'Objective-See qui recherche dans plusieurs emplacements où des **malwares pourraient persister** (c'est un outil ponctuel, pas un service de monitoring).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html) : Similaire à KnockKnock, en surveillant les processus qui créent de la persistence.

## Détection des keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html) : Application d'Objective-See permettant de détecter les **keyloggers** qui installent des « event taps » de clavier.

## Télémétrie Endpoint / contrôle de l'exécution

- [**Santa**](https://santa.dev/) : Système d'autorisation et de monitoring des binaires pour macOS. Il utilise un client **Endpoint Security** pour autoriser les événements **`exec`** avant l'exécution du code ; il est donc courant dans les flottes d'entreprise qui privilégient l'**allowlisting/denylisting** plutôt que la détection post-exécution.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor) : Outil d'analyse dynamique macOS similaire à Procmon. Il ingère la **télémétrie Endpoint Security** (événements liés aux processus, fichiers, communications interprocessus, connexions et à XProtect) et est utile pour comprendre ce qu'un sensor mature basé sur ES peut réellement observer.<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html) : Outils légers d'Objective-See pour la télémétrie des **processus**, des **fichiers** et du **DNS**. Sur les versions modernes de macOS, ils nécessitent des prérequis supplémentaires tels que les privilèges **root**, l'accès complet au disque pour **Terminal**, ou l'approbation d'une **System/Network Extension**. Pour plus d'idées d'instrumentation, consultez [cette autre page consacrée à l'inspection, au debugging et au fuzzing des applications macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Triage rapide des outils défensifs

La plupart des produits de sécurité macOS modernes s'exécutent sous une combinaison de **System Extensions / clients Endpoint Security**, d'**agents/daemons launchd** et d'applications disposant de l'**accès complet au disque**. Checklist rapide pour l'opérateur :
```bash
# System / network extensions (EDRs, DNS filters, firewalls, VPNs)
systemextensionsctl list

# Legacy kernel agents on older boxes / upgraded fleets
kmutil showloaded 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'
# Older releases:
kextstat 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'

# Userland agents / helpers
launchctl print system | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'
launchctl print gui/$UID | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'

# Inspect code-signing and entitlements of a defensive app
codesign -dvv --entitlements :- /Applications/SomeAgent.app

# Check common TCC grants used by sensors / telemetry tools
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
[ -f "$db" ] || continue
echo "== $db =="
sqlite3 "$db" 'SELECT service,client,auth_value,last_modified FROM access WHERE service IN ("kTCCServiceSystemPolicyAllFiles","kTCCServiceEndpointSecurityClient") ORDER BY last_modified DESC;'
done
```
Si `systemextensionsctl list` affiche un capteur avec l’état **`[activated enabled]`**, c’est généralement l’indicateur le plus rapide que l’extension est réellement active. Sur **macOS 15 Sequoia et les versions ultérieures**, MDM peut également marquer certaines extensions de sécurité comme **non supprimables depuis l’interface utilisateur**. Il n’est donc plus prudent de supposer qu’il suffit de « la désactiver depuis Réglages Système ». Pour les détails internes, consultez [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Télémétrie native récente exploitable par les défenseurs

Les versions récentes de macOS ont rendu certains contournements déclenchés par l’utilisateur, auparavant difficiles à détecter, beaucoup plus bruyants pour les équipes blue team :

- **macOS 15+** : les clients Endpoint Security peuvent recevoir les événements **`gatekeeper_user_override`**, ce qui permet de journaliser les contournements manuels de Gatekeeper de manière centralisée.
- Les outils Endpoint Security actuels pour macOS peuvent également ingérer les événements de détection de malware de **XProtect**, ce qui facilite la confirmation de ce qu’Apple a déjà détecté sur l’endpoint.
- **macOS 15.4+** : Endpoint Security ajoute **`tcc_modify`**, ce qui fournit enfin aux défenseurs un moyen pris en charge de surveiller les **octrois/révocations TCC**, au lieu d’extraire les journaux de débogage TCC.<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Ceci est utile à la fois pour les défenseurs et les red teamers qui réalisent une auto-évaluation : si la cible dispose d’une stack basée sur ES mature, les **chaînes de bypass de Gatekeeper / TCC approuvées par l’utilisateur peuvent être bien plus visibles qu’auparavant**. Pour obtenir des informations générales sur ces protections, consultez [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) et [TCC](macos-security-protections/macos-tcc/README.md).

## Références

- [1] [Objective-See - Croire, c’est TCCer ! Apple ajoute enfin les événements TCC à Endpoint Security !](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Présentation de : Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
