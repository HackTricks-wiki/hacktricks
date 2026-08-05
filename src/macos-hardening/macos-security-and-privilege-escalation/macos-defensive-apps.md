# App difensive per macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewall

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitora ogni connessione effettuata da ciascun processo. A seconda della modalità (consenti connessioni silenziosamente, nega connessioni silenziosamente e avvisa), **mostrerà un avviso** ogni volta che viene stabilita una nuova connessione. Dispone inoltre di una GUI molto intuitiva per visualizzare tutte queste informazioni.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall di Objective-See. Si tratta di un firewall di base che avvisa in caso di connessioni sospette (dispone di una GUI, ma non è sofisticata quanto quella di Little Snitch).

## Rilevamento della persistenza

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Applicazione di Objective-See che cerca in diverse posizioni in cui **potrebbe persistere del malware** (è uno strumento one-shot, non un servizio di monitoraggio).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Simile a KnockKnock, monitorando i processi che generano persistenza.

## Rilevamento dei keylogger

- [**ReiKey**](https://objective-see.org/products/reikey.html): Applicazione di Objective-See per trovare **keylogger** che installano "event tap" della tastiera.

## Telemetria degli endpoint / controllo dell'esecuzione

- [**Santa**](https://santa.dev/): Sistema di autorizzazione e monitoraggio dei binari per macOS. Utilizza un client **Endpoint Security** per autorizzare gli eventi **`exec`** prima dell'esecuzione del codice, quindi è comune negli ambienti enterprise focalizzati su **allowlisting/denylisting** anziché sul solo rilevamento post-esecuzione.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Strumento di analisi dinamica per macOS simile a Procmon. Acquisisce la **telemetria di Endpoint Security** (eventi relativi a processi, file, interprocessi, login e XProtect) ed è utile per comprendere cosa possa effettivamente osservare un sensor maturo basato su ES.<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Strumenti leggeri di Objective-See per la telemetria di **processi**, **file** e **DNS**. Sulle versioni moderne di macOS richiedono prerequisiti aggiuntivi come **root**, **Terminal Full Disk Access** o l'approvazione di una **System/Network Extension**. Per altre idee di instrumentation, consulta [questa pagina sulla verifica, il debugging e il fuzzing delle app macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Triage rapido degli strumenti difensivi

La maggior parte dei moderni prodotti di sicurezza per macOS viene eseguita come combinazione di **System Extensions / client Endpoint Security**, **agent/daemon launchd** e applicazioni con **Full Disk Access**. Una checklist rapida per l'operatore:
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
Se `systemextensionsctl list` mostra un sensore come **`[activated enabled]`**, di solito è l'indicatore più rapido che l'estensione sia effettivamente attiva. Su **macOS 15 Sequoia e versioni successive**, MDM può anche contrassegnare specifiche estensioni di sicurezza come **non rimovibili dall'interfaccia**, quindi "disabilitarla da Impostazioni di Sistema" non è più un'ipotesi sicura. Per i dettagli interni, consulta [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Telemetria nativa recente che i difensori possono utilizzare

Le versioni recenti di macOS hanno reso molto più rumorosi per i blue teams alcuni bypass avviati dagli utenti che in precedenza erano difficili da rilevare:

- **macOS 15+**: i client Endpoint Security possono ricevere eventi **`gatekeeper_user_override`**, quindi i bypass manuali di Gatekeeper possono essere registrati centralmente.
- Gli strumenti Endpoint Security attuali per macOS possono anche acquisire gli eventi di rilevamento malware di **XProtect**, rendendo più semplice confermare ciò che Apple ha già rilevato sull'endpoint.
- **macOS 15.4+**: Endpoint Security aggiunge **`tcc_modify`**, offrendo finalmente ai difensori un modo supportato per monitorare le **concessioni/revoche TCC** invece di analizzare i log di debug di TCC.<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Questo è utile sia per i defender sia per i red teamer che eseguono self-assessment: se il target dispone di uno stack basato su ES maturo, **le chain di bypass di Gatekeeper / TCC approvate dall'utente potrebbero essere molto più visibili di prima**. Per informazioni di base su queste protezioni, consulta [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) e [TCC](macos-security-protections/macos-tcc/README.md).

## Riferimenti

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
