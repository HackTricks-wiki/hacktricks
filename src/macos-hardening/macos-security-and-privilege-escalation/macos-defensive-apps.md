# Applications défensives macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html) : Il surveille chaque connexion établie par chaque processus. Selon le mode (autoriser silencieusement les connexions, refuser silencieusement les connexions et alerter), il vous **affichera une alerte** chaque fois qu'une nouvelle connexion est établie. Il possède également une très bonne GUI pour consulter toutes ces informations.
- [**LuLu**](https://objective-see.org/products/lulu.html) : Firewall d'Objective-See. Il s'agit d'un firewall basique qui vous alertera en cas de connexions suspectes (il possède une GUI, mais elle est moins sophistiquée que celle de Little Snitch).

## Détection de la persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html) : Application Objective-See qui recherche dans plusieurs emplacements où des **malwares pourraient persister** (c'est un outil ponctuel, pas un service de monitoring).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html) : Similaire à KnockKnock, en surveillant les processus qui créent de la persistence.

## Détection des keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html) : Application Objective-See permettant de trouver les **keyloggers** qui installent des « event taps » de clavier.

## Télémétrie des endpoints / contrôle de l'exécution

- [**Santa**](https://santa.dev/) : Système d'autorisation et de monitoring des binaires pour macOS. Il utilise un client **Endpoint Security** pour autoriser les événements **`exec`** avant l'exécution du code ; il est donc courant dans les flottes d'entreprise qui privilégient l'**allowlisting/denylisting** plutôt que la seule détection post-exécution.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor) : Outil d'analyse dynamique de macOS similaire à Procmon. Il ingère la **télémétrie Endpoint Security** (événements liés aux processus, fichiers, communications interprocessus, connexions et à XProtect) et permet de comprendre ce qu'un sensor mature basé sur ES peut réellement observer.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html) : Outils Objective-See légers pour la télémétrie des **processus**, **fichiers** et **DNS**. Sur les versions modernes de macOS, ils nécessitent des prérequis supplémentaires tels que les privilèges **root**, l'autorisation **Terminal Full Disk Access** ou l'approbation d'une **System/Network Extension**. Pour découvrir d'autres idées d'instrumentation, consultez [cette autre page consacrée à l'inspection, au debugging et au fuzzing des applications macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Triage rapide des outils défensifs

La plupart des produits de sécurité macOS modernes s'exécutent sous une combinaison de **System Extensions / clients Endpoint Security**, d'**agents/daemons launchd** et d'applications disposant de **Full Disk Access**. Voici une checklist rapide pour l'opérateur :
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
Si `systemextensionsctl list` affiche un capteur comme **`[activated enabled]`**, c'est généralement l'indicateur le plus rapide que l'extension est réellement active. Sur **macOS 15 Sequoia et les versions ultérieures**, le MDM peut également marquer certaines extensions de sécurité comme **non supprimables depuis l'interface**, donc « la désactiver depuis les Réglages Système » n'est plus une hypothèse sûre. Pour les détails internes, consultez [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Télémétrie native récente exploitable par les défenseurs

Les versions récentes de macOS ont rendu certains contournements initiés par l'utilisateur, auparavant difficiles à détecter, beaucoup plus visibles pour les équipes blue team :

- **macOS 15+** : les clients Endpoint Security peuvent recevoir des événements **`gatekeeper_user_override`**, ce qui permet de journaliser de manière centralisée les contournements manuels de Gatekeeper.
- Les outils Endpoint Security actuels pour macOS peuvent également ingérer les événements de détection de malware de **XProtect**, ce qui facilite la confirmation de ce qu'Apple a déjà détecté sur l'endpoint.
- **macOS 15.4+** : Endpoint Security ajoute **`tcc_modify`**, ce qui fournit enfin aux défenseurs une méthode prise en charge pour surveiller les **octrois/révocations TCC** au lieu d'extraire les journaux de débogage TCC.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Ceci est utile aussi bien pour les défenseurs que pour les red teamers effectuant une auto-évaluation : si la cible dispose d'une stack basée sur ES mature, les **chaînes de bypass de Gatekeeper / TCC approuvées par l'utilisateur peuvent être bien plus visibles qu'auparavant**. Pour en savoir plus sur ces protections, consultez [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) et [TCC](macos-security-protections/macos-tcc/README.md).

## Références


- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
