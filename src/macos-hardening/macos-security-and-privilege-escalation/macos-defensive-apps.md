# macOS Odbrambene aplikacije

{{#include ../../banners/hacktricks-training.md}}

## Firewall-ovi

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Pratiće svaku konekciju koju napravi svaki proces. U zavisnosti od moda (silent allow connections, silent deny connection and alert) **prikazaće vam upozorenje** svaki put kada se uspostavi nova konekcija. Takođe ima veoma dobar GUI za pregled svih ovih informacija.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall. Ovo je osnovni firewall koji će vas upozoriti na sumnjive konekcije (ima GUI, ali nije toliko lep kao Little Snitch).

## Detekcija persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See aplikacija koja će pretražiti više lokacija gde bi **malware could be persisting** (to je alat za jednokratno pokretanje, ne monitoring servis).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Kao KnockKnock, ali prati procese koji generišu persistence.

## Detekcija keyloggera

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See aplikacija za pronalaženje **keyloggera** koji instaliraju tastature "event taps"

## Endpoint telemetry / kontrola izvršavanja

- [**Santa**](https://santa.dev/): Sistem za autorizaciju binarnih fajlova i monitoring za macOS. Koristi **Endpoint Security** klijenta da autorizuje **`exec`** događaje pre nego što se kod izvrši, pa je čest u enterprise flotama fokusiranim na **allowlisting/denylisting** umesto samo na detekciju nakon izvršavanja.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon-like macOS alat za dinamičku analizu. Uvlači **Endpoint Security telemetry** (process, file, interprocess, login, and XProtect-related events) i koristan je da se razume šta jedan zreo ES-based senzor zapravo može da posmatra.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Lagani Objective-See alati za **process**, **file**, i **DNS** telemetry. Na modernom macOS-u imaju dodatne preduslove kao što su **root**, **Terminal Full Disk Access**, ili **System/Network Extension approval**. Za još ideja za instrumentaciju pogledajte [this other page about macOS app inspection/debugging](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Brzi triage odbrambenih alata

Većina modernih macOS security proizvoda radi kao neka kombinacija **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, i aplikacija sa **Full Disk Access**. Brza operatorova checklist:
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
If `systemextensionsctl list` pokaže sensor kao **`[activated enabled]`**, to je obično najbrži indikator da je ekstenzija zapravo aktivna. Na **macOS 15 Sequoia i novijim**, MDM takođe može označiti određene security extensions kao **non-removable from the UI**, tako da "disable it from System Settings" više nije sigurna pretpostavka. Za internals, vidi [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry defenders can consume

Novija macOS izdanja su učinila neke ranije naporne za detekciju user-driven bypasses mnogo bučnijim za blue teams:

- **macOS 15+**: Endpoint Security clients mogu da primaju **`gatekeeper_user_override`** događaje, pa se manual Gatekeeper bypasses mogu centralno logovati.
- **Current macOS Endpoint Security tooling** takođe može da ingestuje **XProtect malware detection** događaje, što olakšava potvrdu onoga što je Apple već detektovao na endpoint-u.
- **macOS 15.4+**: Endpoint Security dodaje **`tcc_modify`**, što konačno daje defenderima podržan način da prate **TCC grants/revokes** umesto da parsiraju TCC debug logs.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Ovo je korisno i za defanzivce i za red teamere koji rade self-assessment: ako cilj ima zreo ES-based stack, **user-approved Gatekeeper / TCC bypass chains mogu biti mnogo vidljiviji nego ranije**. Za pozadinu o ovim zaštitama, pogledajte [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) i [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
