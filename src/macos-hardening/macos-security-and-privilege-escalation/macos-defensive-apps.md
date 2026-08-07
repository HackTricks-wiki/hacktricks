# Defenzivne aplikacije za macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewall-i

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Nadgleda svaku konekciju koju uspostavi svaki proces. U zavisnosti od režima (tiho dozvoljavanje konekcija, tiho odbijanje konekcija i upozoravanje), **prikazaće vam upozorenje** svaki put kada se uspostavi nova konekcija. Takođe ima veoma dobar GUI za pregled svih ovih informacija.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall kompanije Objective-See. Ovo je osnovni firewall koji će vas upozoriti na sumnjive konekcije (ima GUI, ali nije toliko napredan kao onaj u aplikaciji Little Snitch).

## Detekcija persistence-a

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplikacija kompanije Objective-See koja pretražuje nekoliko lokacija na kojima **malware može imati persistence** (alat za jednokratno pokretanje, a ne servis za monitoring).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Slično alatu KnockKnock, ali nadgleda procese koji generišu persistence.

## Detekcija keylogger-a

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplikacija kompanije Objective-See za pronalaženje **keylogger-a** koji instaliraju "event taps" za tastaturu.

## Endpoint telemetrija / kontrola izvršavanja

- [**Santa**](https://santa.dev/): Sistem za binarnu autorizaciju i monitoring za macOS. Koristi **Endpoint Security** klijent za autorizaciju **`exec`** događaja pre pokretanja koda, pa je čest u enterprise okruženjima koja se fokusiraju na **allowlisting/denylisting**, umesto samo na detekciju nakon izvršavanja.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): macOS alat za dinamičku analizu, sličan alatu Procmon. Prikuplja **Endpoint Security telemetriju** (događaje povezane sa procesima, fajlovima, interprocesnom komunikacijom, prijavljivanjem i XProtect-om) i koristan je za razumevanje onoga što zreo senzor zasnovan na ES-u zaista može da posmatra.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Lagani Objective-See alati za **procesnu**, **fajl** i **DNS** telemetriju. Na modernom macOS-u zahtevaju dodatne preduslove, kao što su **root**, **Terminal Full Disk Access** ili odobrenje za **System/Network Extension**. Za više ideja o instrumentation-u pogledajte [ovu drugu stranicu o inspekciji/debugging-u macOS aplikacija](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Brzi triage defenzivnih alata

Većina modernih macOS security proizvoda radi kao neka kombinacija **System Extensions / Endpoint Security klijenata**, **launchd agenata/daemon-a** i aplikacija sa **Full Disk Access** privilegijama. Brza operatorska checklista:
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
Ako `systemextensionsctl list` prikazuje senzor kao **`[activated enabled]`**, to je obično najbrži pokazatelj da je ekstenzija zaista aktivna. Na **macOS 15 Sequoia i novijim verzijama**, MDM takođe može označiti određene security ekstenzije kao **non-removable from the UI**, pa pretpostavka „onemogućite je iz System Settings“ više nije bezbedna. Za interne detalje pogledajte [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Nedavna native telemetry koju defenders mogu da koriste

Nedavna macOS izdanja učinila su neke ranije teško uočljive user-driven bypasses mnogo uočljivijim za blue teams:

- **macOS 15+**: Endpoint Security klijenti mogu primati **`gatekeeper_user_override`** događaje, pa se ručni Gatekeeper bypasses mogu centralno evidentirati.
- **Current macOS Endpoint Security tooling** takođe može unositi **XProtect malware detection** događaje, što olakšava potvrdu onoga što je Apple već detektovao na endpointu.
- **macOS 15.4+**: Endpoint Security dodaje **`tcc_modify`**, što defenderima konačno pruža podržan način za praćenje **TCC grants/revokes**, umesto parsiranja TCC debug logova.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Ovo je korisno i za defendere i za red teamere koji vrše samoprocenu: ako cilj ima zreo stack zasnovan na ES-u, **user-approved Gatekeeper / TCC bypass lanci mogu biti mnogo vidljiviji nego ranije**. Za kontekst o ovim zaštitama pogledajte [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) i [TCC](macos-security-protections/macos-tcc/README.md).

## Reference


- [1] [Objective-See - TCCing is Believing! Apple konačno dodaje TCC događaje u Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Predstavljamo: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
