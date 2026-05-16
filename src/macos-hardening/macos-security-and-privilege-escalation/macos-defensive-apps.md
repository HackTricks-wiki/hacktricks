# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitorerà ogni connessione fatta da ogni processo. A seconda della modalità (silent allow connections, silent deny connection and alert) **ti mostrerà un alert** ogni volta che una nuova connessione viene stabilita. Ha anche una GUI molto bella per vedere tutte queste informazioni.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall di Objective-See. Questo è un firewall base che ti avviserà di connessioni sospette (ha una GUI ma non è elegante come quella di Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Applicazione di Objective-See che cercherà in diverse location dove **malware could be persisting** (è uno strumento one-shot, non un servizio di monitoraggio).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Come KnockKnock, ma monitora i processi che generano persistence.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Applicazione di Objective-See per trovare **keyloggers** che installano "event taps" della tastiera

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): Sistema di autorizzazione binaria e monitoraggio per macOS. Usa un client **Endpoint Security** per autorizzare gli eventi **`exec`** prima che il codice venga eseguito, quindi è comune in ambienti enterprise orientati a **allowlisting/denylisting** invece che solo al rilevamento post-esecuzione.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Strumento di analisi dinamica per macOS simile a Procmon. Ingerisce **Endpoint Security telemetry** (eventi di processo, file, interprocess, login e relativi a XProtect) ed è utile per capire cosa può osservare davvero un sensore maturo basato su ES.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Strumenti leggeri di Objective-See per la telemetria di **process**, **file** e **DNS**. Su macOS moderno hanno prerequisiti aggiuntivi come **root**, **Terminal Full Disk Access** o approvazione **System/Network Extension**. Per altre idee di strumentazione vedi [this other page about macOS app inspection/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Quick triage of defensive tooling

La maggior parte dei moderni prodotti di sicurezza per macOS gira come una combinazione di **System Extensions / Endpoint Security clients**, **launchd agents/daemons** e applicazioni con **Full Disk Access**. Una rapida checklist per l'operatore:
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
Se `systemextensionsctl list` mostra un sensor come **`[activated enabled]`**, di solito è l’indicatore più rapido che l’estensione è davvero attiva. Su **macOS 15 Sequoia e successivi**, MDM può anche contrassegnare specifiche estensioni di sicurezza come **non rimovibili dall’UI**, quindi "disabilitalo da Impostazioni di Sistema" non è più un’ipotesi sicura. Per i dettagli interni, vedi [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry defenders can consume

Le recenti release di macOS hanno reso alcuni bypass avviati dall’utente, prima fastidiosi da rilevare, molto più rumorosi per i blue team:

- **macOS 15+**: i client Endpoint Security possono ricevere eventi **`gatekeeper_user_override`**, quindi i bypass manuali di Gatekeeper possono essere registrati centralmente.
- **Current macOS Endpoint Security tooling** può anche acquisire eventi di **XProtect malware detection**, rendendo più facile confermare ciò che Apple ha già rilevato sull’endpoint.
- **macOS 15.4+**: Endpoint Security aggiunge **`tcc_modify`**, che finalmente offre ai defender un modo supportato per monitorare **TCC grants/revokes** invece di analizzare i debug log di TCC.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Questo è utile sia per i defender sia per i red teamer che fanno self-assessment: se il target ha uno stack basato su ES maturo, **le catene di bypass di Gatekeeper / TCC approvate dall'utente possono essere molto più visibili di quanto non lo fossero prima**. Per un contesto su queste protezioni, vedi [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) e [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finalmente aggiunge eventi TCC a Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
