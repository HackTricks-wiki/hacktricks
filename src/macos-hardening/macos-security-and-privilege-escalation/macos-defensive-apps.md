# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Il surveillera chaque connexion effectuée par chaque processus. Selon le mode (autoriser les connexions en silence, refuser les connexions en silence et alerter), il **vous affichera une alerte** à chaque fois qu'une nouvelle connexion est établie. Il dispose aussi d'une très belle interface graphique pour voir toutes ces informations.
- [**LuLu**](https://objective-see.org/products/lulu.html): firewall d'Objective-See. C'est un firewall de base qui vous avertira des connexions suspectes (il a une interface graphique, mais elle n'est pas aussi élégante que celle de Little Snitch).

## Détection de persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): application Objective-See qui recherchera à plusieurs emplacements où **des malware pourraient persister** (c'est un outil à usage unique, pas un service de monitoring).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Comme KnockKnock, en surveillant les processus qui génèrent de la persistence.

## Détection de keyloggers

- [**ReiKey**](https://objective-see.org/products/reikey.html): application Objective-See pour trouver des **keyloggers** qui installent des "event taps" de clavier

## Télémétrie endpoint / contrôle d'exécution

- [**Santa**](https://santa.dev/): Système d'autorisation binaire et de monitoring pour macOS. Il utilise un client **Endpoint Security** pour autoriser les événements **`exec`** avant l'exécution du code, il est donc courant dans les flottes d'entreprise axées sur l'**allowlisting/denylisting** plutôt que sur la seule détection post-exécution.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): outil d'analyse dynamique macOS de type Procmon. Il ingère la **télémétrie Endpoint Security** (événements de processus, fichiers, interprocess, login et liés à XProtect) et est utile pour comprendre ce qu'un capteur mature basé sur ES peut réellement observer.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): outils légers d'Objective-See pour la télémétrie des **processus**, des **fichiers** et du **DNS**. Sur les versions modernes de macOS, ils ont des prérequis supplémentaires comme **root**, **Terminal Full Disk Access**, ou l'approbation de **System/Network Extension**. Pour plus d'idées d'instrumentation, consultez [cette autre page sur l'inspection, le débogage et le fuzzing d'apps macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Tri rapide des outils défensifs

La plupart des produits de sécurité modernes pour macOS s'exécutent comme une combinaison de **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, et d'applications avec **Full Disk Access**. Une checklist rapide pour l'opérateur :
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
Si `systemextensionsctl list` affiche un sensor comme **`[activated enabled]`**, c’est généralement l’indicateur le plus rapide que l’extension est réellement active. Sur **macOS 15 Sequoia et versions ultérieures**, MDM peut aussi marquer certaines extensions de sécurité comme **non supprimables depuis l’interface**, donc « le désactiver depuis System Settings » n’est plus une hypothèse sûre. Pour les détails internes, voir [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## La télémétrie native récente que les defenders peuvent exploiter

Les versions récentes de macOS ont rendu certains bypass déclenchés par l’utilisateur, auparavant pénibles à détecter, beaucoup plus bruyants pour les blue teams :

- **macOS 15+** : les clients Endpoint Security peuvent recevoir des événements **`gatekeeper_user_override`**, donc les contournements manuels de Gatekeeper peuvent être journalisés de manière centralisée.
- **Les outils Endpoint Security actuels sur macOS** peuvent aussi ingérer des événements de détection de malware **XProtect**, ce qui facilite la confirmation de ce qu’Apple a déjà détecté sur l’endpoint.
- **macOS 15.4+** : Endpoint Security ajoute **`tcc_modify`**, ce qui donne enfin aux defenders une méthode prise en charge pour surveiller les **`TCC grants/revokes`** au lieu d’extraire les logs de debug TCC.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Ceci est utile à la fois pour les defenders et pour les red teamers qui font de l’auto-évaluation : si la cible dispose d’une stack mature basée sur ES, les chaînes de bypass **Gatekeeper / TCC approuvées par l’utilisateur peuvent être beaucoup plus visibles qu’avant**. Pour le contexte sur ces protections, voir [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) et [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
