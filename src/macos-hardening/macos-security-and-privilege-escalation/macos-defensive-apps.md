# Defensive Apps za macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewall-i

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Prati svaku konekciju koju uspostavi svaki proces. U zavisnosti od režima (tiho dozvoljavanje konekcija, tiho odbijanje konekcija i upozoravanje), prikazaće vam **upozorenje** svaki put kada se uspostavi nova konekcija. Takođe ima veoma dobar GUI za pregled svih ovih informacija.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall kompanije Objective-See. Ovo je osnovni firewall koji će vas upozoriti na sumnjive konekcije (ima GUI, ali nije toliko napredan kao Little Snitch).

## Detekcija persistence-a

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplikacija kompanije Objective-See koja pretražuje nekoliko lokacija na kojima bi **malware mogao imati persistence** (to je one-shot alat, a ne monitoring servis).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Slično alatu KnockKnock, ali prati procese koji generišu persistence.

## Detekcija keylogger-a

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplikacija kompanije Objective-See za pronalaženje **keylogger-a** koji instaliraju keyboard "event taps"

## Endpoint telemetry / kontrola izvršavanja

- [**Santa**](https://santa.dev/): Sistem za autorizaciju i monitoring binarnih fajlova za macOS. Koristi **Endpoint Security** klijenta za autorizaciju **`exec`** događaja pre pokretanja koda, pa je čest u enterprise flotama usmerenim na **allowlisting/denylisting**, umesto samo na detekciju nakon izvršavanja.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): macOS alat za dinamičku analizu, sličan Procmon-u. Prikuplja **Endpoint Security telemetry** (događaje povezane sa procesima, fajlovima, interprocess komunikacijom, prijavljivanjem i XProtect-om) i koristan je za razumevanje onoga što zreo senzor zasnovan na ES-u zaista može da posmatra.<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Lagani Objective-See alati za **process**, **file** i **DNS** telemetry. Na modernom macOS-u zahtevaju dodatne preduslove, kao što su **root**, **Terminal Full Disk Access** ili odobrenje za **System/Network Extension**. Za više ideja o instrumentaciji pogledajte [ovu drugu stranicu o inspekciji/debugging-u i fuzzing-u macOS aplikacija](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Brza trijaža defensive alata

Većina modernih macOS security proizvoda radi kao kombinacija **System Extensions / Endpoint Security clients**, **launchd agents/daemons** i aplikacija sa **Full Disk Access** dozvolom. Brza operatorska kontrolna lista:
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
Ako `systemextensionsctl list` prikazuje senzor kao **`[activated enabled]`**, to je obično najbrži pokazatelj da je ekstenzija zaista aktivna. Na **macOS 15 Sequoia i novijim verzijama**, MDM takođe može označiti određene security ekstenzije kao **neuklonjive iz UI-ja**, pa pretpostavka da je dovoljno „onemogućiti je iz System Settings“ više nije bezbedna. Za interne detalje pogledajte [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Nedavna nativna telemetrija koju defenders mogu koristiti

Novija izdanja macOS-a učinila su neke ranije teško uočljive bypass-e koje pokreće korisnik mnogo uočljivijim za blue teams:

- **macOS 15+**: Endpoint Security klijenti mogu primati **`gatekeeper_user_override`** događaje, pa se ručni Gatekeeper bypass-i mogu centralno evidentirati.
- **Trenutni macOS Endpoint Security alati** takođe mogu ingestovati **XProtect malware detection** događaje, što olakšava potvrdu onoga što je Apple već detektovao na endpointu.
- **macOS 15.4+**: Endpoint Security dodaje **`tcc_modify`**, što defenderima konačno pruža podržan način za nadgledanje **TCC odobrenja/opoziva**, umesto preuzimanja TCC debug logova.<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Ovo je korisno i za defendere i za red teamere koji rade self-assessment: ako cilj ima zreo ES-based stack, **user-approved Gatekeeper / TCC bypass chains mogu biti mnogo vidljiviji nego ranije**. Za više informacija o ovim zaštitama pogledajte [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) i [TCC](macos-security-protections/macos-tcc/README.md).

## Reference

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
