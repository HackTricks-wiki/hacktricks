# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basiese inligting

Vanaf **macOS Big Sur (11.0)** word die stelselvolume kriptografies verseël met ’n **APFS snapshot hash tree**. Dit word die **Sealed System Volume (SSV)** genoem. Die stelselpartisie word **read-only** gemonteer, en enige wysiging verbreek die seël, wat tydens selflaai geverifieer word.<sup>[[11]](#references)</sup>

Die SSV bied:
- **Opsporing van peutery** — enige wysiging aan stelselbinaries/-raamwerke verander die Merkle-tree-wortel en maak die Apple-ondertekende seël ongeldig
- **Verifikasie tydens selflaai** — die selflaaiketting verifieer die gekose stelselsnapshot voordat dit die root-lêerstelsel word
- **Weerstand teen rootkits** — selfs root kan nie lêers in die geverifieerde stelselsnapshot permanent vervang sonder om authenticated root te deaktiveer of ’n gemagtigde opdateringspad te kompromitteer nie

SSV beskerm die **System**-volume, nie die skryfbare **Data**-volume wat daarmee gepaardgaan nie. Firmlinks voeg albei volumes saam in die naamruimte wat by `/` sigbaar is, dus bewys ’n pad wat skryfbaar lyk nie dat die onderliggende objek aan die verseëlde snapshot behoort nie. FileVault en Data Protection dek die vertroulikheid van data wat nie aan die gang is nie; hulle staan los van SSV-integriteit.<sup>[[11]](#references)</sup>

### SSV-status nagaan

```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / " 

# Show the volume group and the current Sealed field
diskutil apfs listVolumeGroups
diskutil apfs list | grep -B 8 -A 8 'Sealed:'
```

### Doeltreffende stelselbeeld: SSV + Cryptex-grafts

In onlangse macOS-vrystellings kom nie elke uitvoerbare lêer wat onder `/System` sigbaar is noodwendig van die opgestarte SSV-snapshot af nie. **Cryptexes** is afsonderlik geverifieerde APFS-skyfbeelde waarvan die inhoud oor uitgesoekte gidse gemonteer word; Rapid Security Responses kan dus sekuriteitsensitiewe komponente vervang sonder om die basis-SSV te herbou. Wanneer jy volharding ondersoek of stelselkode vergelyk, inventariseer die aktiewe mounts en die Preboot Cryptex-store, eerder as om net die basissnapshot se hashes te bereken:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Die besonderhede oor die bootketting en Rapid Security Response word behandel in [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); hierdie afdeling fokus op die SSV-grens self.

### SSV-skrywerregte

Sekere Apple-stelselbinaries het regte wat hulle toelaat om die verseëlde stelselvolume te wysig of te bestuur:

| Reg | Doel |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Stel die stelselvolume terug na ’n vorige momentopname |
| `com.apple.private.apfs.create-sealed-snapshot` | Skep ’n nuwe verseëlde momentopname ná stelselopdaterings |
| `com.apple.rootless.install.heritable` | Skryf na SIP-beskermde paaie (geërf deur kinderprosesse) |
| `com.apple.rootless.install` | Skryf na SIP-beskermde paaie |

### Vind van SSV-skrywers

```bash
# Search for binaries with SSV-related entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "apfs.revert-to-snapshot\|apfs.create-sealed-snapshot\|rootless.install" && echo "{}"
' \; 2>/dev/null

# Using the scanner database
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'ssv_writer';"
```

### Aanvalscenario's

#### Aanval via terugrol van momentopname

As 'n aanvaller 'n binêre lêer met `com.apple.private.apfs.revert-to-snapshot` kompromitteer, kan hulle **die stelselvolume terugrol na 'n toestand voor 'n opdatering** en bekende kwesbaarhede herstel:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Terugrol van 'n snapshot **maak sekuriteitsopdaterings effektief ongedaan** en herstel voorheen reggestelde kwesbaarhede in die kernel en stelsel. Dit is een van die gevaarlikste bewerkings wat op moderne macOS moontlik is.

#### Vervanging van stelselbinaries

Met 'n SIP-omseiling + SSV-skryfvermoë kan 'n aanvaller:

1. Die stelselvolume lees-skryf monteer
2. 'n Stelseldemon of raamwerkbiblioteek met 'n getrojaniseerde weergawe vervang
3. Die snapshot weer seël (of die gebreekte seël aanvaar as SIP reeds verswak is)
4. Die rootkit bly ná herlaai voortbestaan en is onsigbaar vir userland-opsporingsnutsmiddels

### CVE's in die werklike wêreld

| CVE | Beskrywing |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP-omseiling wat `system_installd` se `com.apple.rootless.install.heritable`-entitlement misbruik om arbitrêre na-installasieskripte uit te voer ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP-omseiling: `system_installd` het die na-installasieskrip in 'n SIP-beskermde vouer onder `/tmp` geberg, maar `/tmp` self is nie SIP-beskerm nie, dus kon die vouer vervang word deur 'n image daaroor te monteer ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — 'n copy-on-write race in XNU wat skrywe na leesalleen-lêers wat deur root besit word, moontlik maak ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basiese inligting

**DataVault** is 'n lêerstelselbeskerming vir sensitiewe lêers en gidse wat deur 'n entitlement beheer word. Die BSD-vlag `UF_DATAVAULT` (`0x00000080`) merk 'n objek as een wat 'n entitlement vir lees én skryf vereis; anders as met normale DAC, voldoen dit nie aan dié kontrole om bloot **root** te word of Full Disk Access te kry terwyl die beskerming afgedwing word nie.<sup>[[4]](#references)[[13]](#references)</sup>

Moenie “DataVault” as 'n sinoniem vir elke beskermde databasis gebruik nie. Die TCC-databasisse word deur TCC/FDA en SIP-spesifieke beleid beheer (sien [macOS TCC](macos-tcc/README.md)), terwyl toegang tot sleutelhoueritems ook van Keychain-ACL's en kriptografiese beskerming afhang (sien [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Werklike DataVault-voorbeelde verskyn dikwels as diensbesitte bergings onder `/private/var/folders/.../0/`, soos die Screen Time-berging; die vlag verskyn as `datavault` in BSD-lêervlae wanneer die ouergids met `stat` ondersoek kan word.

### Entitlements vir DataVault-beheerders

| Entitlement | Grens |
|---|---|
| `com.apple.rootless.datavault.controller` | Kry toegang tot/beheer `UF_DATAVAULT`-objekte<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Bestuur TCC-besluite; dit is 'n verwante, maar afsonderlike privaatheidsgrens |
| `com.apple.private.tcc.allow` | Omseil uitgesoekte TCC-dienste wat in die entitlement-waarde benoem word |
| `com.apple.rootless.storage.TCC` | Skryf na die SIP-beskermde TCC-berging |

'n Proses wat 'n DataVault-beheerder-entitlement met FDA-, rugsteun-, indekserings- of IPC-funksionaliteit kombineer, is besonder interessant: soek na 'n confused-deputy-primitief wat 'n beskermde objek na 'n gewone pad kopieer, eerder as om die vault direk te probeer oopmaak.<sup>[[14]](#references)</sup>

### DataVault-beheerders vind

```bash
# BSD flags: a protected object is printed with the `datavault` keyword
ls -ldeO@ /private/var/folders/*/*/0/com.apple.ScreenTimeAgent 2>/dev/null
sudo find /private/var/folders -flags +datavault -print 2>/dev/null

# Find Apple binaries carrying DataVault/TCC controller entitlements
find /System /usr -type f -perm +111 -exec sh -c '
  ents=$(codesign -d --entitlements - "{}" 2>&1)
  echo "$ents" | grep -q "datavault.controller\|private.tcc\|rootless.storage.TCC" && echo "{}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, c.name
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'datavault_controller';"
```

### Aanvalscenario's

#### Direkte wysiging van die TCC-databasis (afsonderlike TCC-grens)

As 'n aanvaller 'n TCC-bestuurderproses kompromitteer (bv. deur code injection in een met `com.apple.private.tcc.manager`), kan hulle die **TCC-databasis direk wysig** om enige toepassing enige TCC-toestemming toe te ken:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> TCC-databasemodifikasie is die **uiteindelike privaatheidsomseiling** — dit verleen enige toestemming stilweg, sonder enige gebruikersaanporring of sigbare aanduiding. Histories het verskeie macOS-voorregte-eskalasiekettings geëindig met TCC-databas skryfbewerkings as die finale loonvrag.

#### Toegang tot die Keychain-databasis

Rou toegang tot ’n keychain se onderliggende databasis is nie dieselfde as toegang tot geheime in gewone teks nie. As ’n ander voorreggrens ’n aanvaller toelaat om die databasis te kopieer, moet die sleutelmateriaal en item-ACL’s steeds aangeval word; sien eerder die toegewyde [macOS Keychain](../../macos-red-teaming/macos-keychain.md)-bladsy as om aan te neem dat ’n DataVault-beheerderreg voldoende is.

#### Grens van rugsteunkopieë: Time Machine

’n Ontleding van 2026 het ’n nuttige algemene patroon gedemonstreer: `backupd` beskik oor beide `com.apple.rootless.datavault.controller` en Volle skyftoegang sodat dit beskermde datastores kan kopieer. In die getoetste opstelling was `/private/var/folders` by Time Machine ingesluit, en die gemonteerde rugsteunkopie het nie die aktiewe DataVault-grens afgedwing nie. Die navorser het dit gebruik om die Screen Time SQLite-datastore op te spoor en die PIN vir gewone teksbeperkings te lees sonder om die aktiewe kluis oop te maak. Beskou dit as ’n **aanval op die kopiegrens**: lys rugsteun-, uitvoer-, migrasie-, indekserings- en diagnostiese hulpdienste wat kluisdata onder ’n swakker monteringspunt of pad kan materialiseer.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Hierdie gedrag hang af van die weergawe en rugsteunuitleg. Valideer dit op die teikenbou, en onthou dat ’n geënkripteerde Time Machine-bestemming die kopie net beskerm terwyl dit gesluit is; sodra dit gemonteer is, word sy toegangsbeheer deel van die aanvaloppervlak.

### CVE’s uit die werklike wêreld waarby DataVault/TCC-omseiling betrokke is

| CVE | Beskrywing |
|---|---|
| CVE-2024-44131 | FileProvider-symlink-race wat ’n geprivilegieerde helper toegang tot TCC-beskermde data gee ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | As root, **skep ’n nuwe gebruiker wie se `NFSHomeDirectory` na ’n aanvallerbeheerde `TCC.db` wys**; wanneer die gebruiker aanmeld, lees `tccd` dit in en die toestemmings word toegepas, wat toegang tot ander gebruikers se data gee ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": verander die gebruiker se tuisgids om ’n aanvallerbeheerde TCC.db te plaas ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | ’n Bundle-conclusion-fout waardeur ’n app **die TCC-toestemmings van ’n skenkerbundle kon erf** sonder ’n versoek; is in die natuur deur **XCSSET** uitgebuit om ’n skermskoot van die lessenaar te neem ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` het die DB-pad vanaf `$HOME` saamgestel, dus het `launchctl setenv HOME` dit na ’n aanvallerbeheerde `TCC.db` herlei ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` het `com.apple.private.tcc.manager` gehad **en** biblioteekvalidering gedeaktiveer, dus kon ’n HAL-inprop wat in `/Library/Audio/Plug-Ins/HAL` geplaas is, arbitrêre TCC-regte toestaan ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft ontdek nuwe macOS-kwesbaarheid, Shrootless, wat System Integrity Protection kan omseil](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Tegniese ontleding: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Dit is beter om iets swak te doen as glad niks nie](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Databeskerming](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC-omseiling steel data uit iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Ontmaskering van macOS-wanware: Omseiling van TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Nuwe macOS-kwesbaarheid, "powerdir," kan tot ongemagtigde toegang tot gebruikersdata lei](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-day TCC-omseiling ontdek in XCSSET-wanware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Omseiling van die macOS Transparency, Consent, and Control (TCC)-raamwerk](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Speel musiek en omseil TCC, oftewel CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Die nagmerrie van Apple OTA-opdaterings (APFS-kiekies)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC-uitbuiting](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Hoe om jou eie Screen Time-wagkode te omseil — bronkode en Time Machine/DataVault-ontleding](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
