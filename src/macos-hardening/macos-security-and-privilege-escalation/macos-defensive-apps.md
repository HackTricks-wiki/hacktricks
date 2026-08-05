# Defensive Apps za macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewall-i

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Prati svaku konekciju koju napravi svaki proces. U zavisnosti od režima (tiho dozvoljavanje konekcija, tiho odbijanje konekcija i upozoravanje), **prikazaće vam upozorenje** svaki put kada se uspostavi nova konekcija. Takođe ima veoma dobar GUI za pregled svih ovih informacija.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall kompanije Objective-See. Ovo je osnovni firewall koji će vas upozoriti na sumnjive konekcije (ima GUI, ali nije tako napredan kao Little Snitch).

## Detekcija persistence-a

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplikacija kompanije Objective-See koja pretražuje nekoliko lokacija na kojima **malware može da uspostavi persistence** (alatka se pokreće jednokratno, nije monitoring servis).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Slično kao KnockKnock, ali prati procese koji generišu persistence.

## Detekcija keylogger-a

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplikacija kompanije Objective-See za pronalaženje **keylogger-a** koji instaliraju keyboard "event taps"

## Endpoint telemetrija / kontrola izvršavanja

- [**Santa**](https://santa.dev/): Sistem za autorizaciju i monitoring binary fajlova za macOS. Koristi **Endpoint Security** klijent za autorizaciju **`exec`** događaja pre pokretanja koda, pa je čest u enterprise fleet-ovima koji se fokusiraju na **allowlisting/denylisting**, umesto samo na detekciju nakon izvršavanja.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): macOS alatka za dinamičku analizu, slična Procmon-u. Prikuplja **Endpoint Security telemetriju** (događaje u vezi sa procesima, fajlovima, interprocesnom komunikacijom, prijavljivanjem i XProtect-om) i korisna je za razumevanje onoga što zreo senzor zasnovan na ES-u zaista može da posmatra.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Lagane Objective-See alatke za telemetriju **procesa**, **fajlova** i **DNS-a**. Na modernom macOS-u zahtevaju dodatne preduslove kao što su **root**, **Terminal Full Disk Access** ili odobrenje za **System/Network Extension**. Za više ideja za instrumentaciju pogledajte [ovu drugu stranicu o inspekciji/debugging-u i fuzzing-u macOS aplikacija](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Brza trijaža defensive tooling-a

Većina modernih macOS security proizvoda radi kao kombinacija **System Extensions / Endpoint Security klijenata**, **launchd agenata/daemon-a** i aplikacija sa **Full Disk Access** dozvolom. Kratka operatorska checklista:
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
Ako `systemextensionsctl list` prikaže senzor kao **`[activated enabled]`**, to je obično najbrži pokazatelj da je ekstenzija zaista aktivna. Na **macOS 15 Sequoia i novijim verzijama**, MDM takođe može označiti određene security ekstenzije kao **neuklonjive iz UI-ja**, pa pretpostavka „onemogućite je u System Settings“ više nije bezbedna. Za interne detalje pogledajte [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Najnovija native telemetrija koju defenders mogu da koriste

Novija macOS izdanja učinila su neke ranije teško uočljive bypass-e koje pokreću korisnici mnogo uočljivijim za blue teams:

- **macOS 15+**: Endpoint Security klijenti mogu primati **`gatekeeper_user_override`** događaje, tako da se ručni Gatekeeper bypass-i mogu centralno evidentirati.
- **Trenutni macOS Endpoint Security alati** takođe mogu ingestovati **XProtect malware detection** događaje, što olakšava potvrdu onoga što je Apple već detektovao na endpointu.
- **macOS 15.4+**: Endpoint Security dodaje **`tcc_modify`**, što defenderima konačno pruža podržan način za nadzor **TCC grant/revoke** radnji umesto parsiranja TCC debug logova.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Ovo je korisno i za defendere i za red teamers koji rade self-assessment: ako target ima zreo ES-based stack, **bypass chain-ovi za Gatekeeper / TCC koje je odobrio user mogu biti mnogo vidljiviji nego ranije**. Za osnovne informacije o ovim zaštitama pogledajte [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) i [TCC](macos-security-protections/macos-tcc/README.md).

## Reference

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
