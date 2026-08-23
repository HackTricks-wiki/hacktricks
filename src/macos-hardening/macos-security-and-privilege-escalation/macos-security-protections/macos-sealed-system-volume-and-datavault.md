# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basiese inligting

Vanaf **macOS Big Sur (11.0)** word die stelselvolume kriptografies verseël deur ’n **APFS snapshot hash tree** te gebruik. Dit word die **Sealed System Volume (SSV)** genoem. Die stelselpartisie word **leesalleen** gemonteer, en enige wysiging verbreek die seël, wat tydens selflaai geverifieer word.<sup>[[11]](#references)</sup>

Die SSV bied:
- **Tamper detection** — enige wysiging aan stelselbinaries/-frameworks verander die Merkle-tree-wortel en maak die Apple-ondertekende seël ongeldig
- **Boot-time authentication** — die selflaaiketting verifieer die geselekteerde stelselsnapshot voordat dit die wortellêerstelsel word
- **Rootkit resistance** — selfs root kan nie lêers in die geverifieerde stelselsnapshot permanent vervang sonder om authenticated root te deaktiveer of ’n gemagtigde opdateringspad te kompromitteer nie

SSV beskerm die **System**-volume, nie die skryfbare **Data**-volume wat daarmee gepaar is nie. Firmlinks voeg albei volumes saam in die naamruimte wat by `/` sigbaar is, dus bewys ’n pad wat skryfbaar lyk nie dat die onderliggende objek aan die verseëlde snapshot behoort nie. FileVault en Data Protection dek die vertroulikheid van data in rus; hulle is apart van SSV-integriteit.<sup>[[11]](#references)</sup>

### Kontroleer SSV-status
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
### Doeltreffende stelselaansig: SSV + Cryptex-grafts

In onlangse macOS-vrystellings kom nie elke uitvoerbare lêer wat onder `/System` sigbaar is noodwendig uit die selflaaide SSV-s momentopname nie. **Cryptexes** is afsonderlik geverifieerde APFS-skyfbeelde waarvan die inhoud oor geselekteerde gidse ingeënt word; Rapid Security Responses kan dus sekuriteitsensitiewe komponente vervang sonder om die basis-SSV te herbou. Wanneer jy persistence triage of stelselkode diff, inventariseer die aktiewe mounts en die Preboot Cryptex-store eerder as om slegs die basissnapshot te hash:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
Die boot-chain- en Rapid Security Response-besonderhede word gedek in [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses); hierdie afdeling fokus op die SSV-grens self.

### SSV Writer Entitlements

Sekere Apple-stelselbinaries het entitlements wat hulle toelaat om die sealed system volume te wysig of te bestuur:

| Entitlement | Doel |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Herstel die stelselvolume na ’n vorige snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Skep ’n nuwe sealed snapshot ná stelselopdaterings |
| `com.apple.rootless.install.heritable` | Skryf na SIP-beskermde paaie (geërf deur child processes) |
| `com.apple.rootless.install` | Skryf na SIP-beskermde paaie |

### Finding SSV Writers
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
### Aanval met terugrol van snapshot

As ’n aanvaller ’n binêre lêer met `com.apple.private.apfs.revert-to-snapshot` kompromitteer, kan hulle **die stelselvolume terugrol na ’n toestand voor die opdatering**, wat bekende kwesbaarhede herstel:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback **maak sekuriteitsopdaterings effektief ongedaan**, en herstel voorheen gelapte kern- en stelselkwesbaarhede. Dit is een van die gevaarlikste bewerkings wat op moderne macOS moontlik is.

#### Vervanging van stelselbinaries

Met SIP-bypass + SSV-skryfvermoë kan 'n aanvaller:

1. Die stelselvolume lees-skryf monteer
2. 'n Stelseldaemon of raamwer biblioteek met 'n trojanweergawe vervang
3. Die snapshot weer seël (of die gebroke seël aanvaar indien SIP reeds gedegradeer is)
4. Die rootkit oor herlaaie heen volhard en onsigbaar wees vir userland-opsporingsnutsgoed

### Werklike CVEs

| CVE | Beskrywing |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP-bypass wat `system_installd` se `com.apple.rootless.install.heritable`-entitlement misbruik om arbitrêre post-install-skripte uit te voer ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP-bypass: `system_installd` het die post-install-skrip in 'n SIP-beskermde vouer onder `/tmp` geplaas, maar `/tmp` self is nie SIP-beskerm nie, sodat die vouer vervang kon word deur 'n image daaroor te monteer ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write-race in XNU wat skryfwerk na leesalleen-root-owned-lêers moontlik maak ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basiese inligting

**DataVault** is 'n entitlement-beheerde lêerstelselbeskerming vir sensitiewe lêers en gidse. Die BSD-vlag `UF_DATAVAULT` (`0x00000080`) merk 'n objek as een wat 'n entitlement vir beide lees en skryf vereis; anders as normale DAC voldoen dit nie aan daardie kontrole om bloot **root** te word of Full Disk Access te ontvang terwyl die beskerming afgedwing word nie.<sup>[[4]](#references)[[13]](#references)</sup>

Moenie “DataVault” as 'n sinoniem vir elke beskermde databasis gebruik nie. Die TCC-databasisse word deur TCC/FDA- en SIP-spesifieke beleid beheer (sien [macOS TCC](macos-tcc/README.md)), terwyl toegang tot keychain-items ook van Keychain-ACL's en kriptografiese beskerming afhang (sien [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Werklike DataVault-voorbeelde verskyn gewoonlik as diensbesitte stoorplekke onder `/private/var/folders/.../0/`, soos die Screen Time-stoorplek; die vlag is as `datavault` in BSD-lêervlae sigbaar wanneer die ouer met `stat` ondersoek kan word.

### DataVault-controller-entitlements

| Entitlement | Grens |
|---|---|
| `com.apple.rootless.datavault.controller` | Kry toegang tot/beheer `UF_DATAVAULT`-objekte<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | Beheer TCC-besluite; dit is 'n verwante maar afsonderlike privaatheidsgrens |
| `com.apple.private.tcc.allow` | Omseil geselekteerde TCC-dienste wat in die entitlement-waarde genoem word |
| `com.apple.rootless.storage.TCC` | Skryf na die SIP-beskermde TCC-stoorplek |

'n Proses wat 'n DataVault-controller-entitlement met FDA-, rugsteun-, indekserings- of IPC-funksionaliteit kombineer, is besonder interessant: soek 'n confused-deputy-primitief wat 'n beskermde objek na 'n gewone pad kopieer eerder as om die vault direk te probeer oopmaak.<sup>[[14]](#references)</sup>

### Vind van DataVault-controllers
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

#### Direkte wysiging van TCC-databasis (afsonderlike TCC-grens)

As 'n aanvaller 'n TCC-managerproses kompromitteer (byvoorbeeld deur code injection in een wat `com.apple.private.tcc.manager` bevat), kan hulle **die TCC-databasis direk wysig** om enige toepassing enige TCC-toestemming te gee:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC-databasemodifikasie is die **uiteindelike privaatheidsomseiling** — dit verleen enige toestemming stilweg, sonder enige gebruiker-aanvraag of sigbare aanduiding. Histories het verskeie macOS privilege escalation-kettings geëindig met TCC-databasis-skrifte as die finale payload.

#### Toegang tot Keychain-databasis

Rou toegang tot ’n keychain se ondersteunende databasis is nie gelykstaande aan toegang tot geheime in plaintext nie. Indien ’n ander privilege-grens ’n aanvaller toelaat om die databasis te kopieer, moet die sleutelmateriaal en item-ACL’s steeds aangeval word; sien eerder die toegewyde [macOS Keychain](../../macos-red-teaming/macos-keychain.md)-bladsy as om aan te neem dat ’n DataVault-controller-entitlement voldoende is.

#### Grens van rugsteunkopieë: Time Machine

’n Ontleding uit 2026 het ’n nuttige algemene patroon gedemonstreer: `backupd` dra beide `com.apple.rootless.datavault.controller` en Full Disk Access, sodat dit beskermde stores kan kopieer. In die getoetste konfigurasie was `/private/var/folders` by Time Machine ingesluit, en die gemonteerde rugsteunkopie het nie die aktiewe DataVault-grens afgedwing nie. Die navorser het dit gebruik om die Screen Time SQLite-store op te spoor en sy plaintext-beperkings-PIN te lees sonder om die aktiewe vault oop te maak. Behandel dit as ’n **aanval op die kopiegrens**: enumereer rugsteun-, uitvoer-, migrasie-, indekserings- en diagnostiese deputies wat vault-data onder ’n swakker mount of pad kan materialiseer.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
Hierdie gedrag is weergawe- en rugsteunuitleg-afhanklik. Valideer dit op die teikenbuild, en onthou dat 'n geënkripteerde Time Machine-bestemming slegs die kopie beskerm terwyl dit gesluit is; sodra dit gemount is, word sy toegangskontroles deel van die attack surface.

### CVE's uit die werklike wêreld wat DataVault/TCC Bypass behels

| CVE | Beskrywing |
|---|---|
| CVE-2024-44131 | FileProvider-simboliese-skakel-wedloop wat 'n bevoorregte helper toegang tot TCC-beskermde data gee ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | As root, **skep 'n nuwe gebruiker wie se `NFSHomeDirectory` na 'n aanvaller-beheerde `TCC.db` wys**; wanneer daar aangemeld word, verbruik `tccd` dit en die toestemmings word toegepas, wat toegang tot ander gebruikers se data gee ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": verander die gebruiker se tuisgids om 'n aanvaller-beheerde TCC.db te plaas ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Fout in bundelgevolgtrekking wat 'n app toelaat om **die TCC-toestemmings van 'n skenkerbundel te erf** sonder 'n prompt; dit is in die wild deur **XCSSET** uitgebuit om 'n skermskoot van die desktop te neem ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` het die DB-pad uit `$HOME` saamgestel, dus het `launchctl setenv HOME` dit na 'n aanvaller-beheerde `TCC.db` herlei ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` het `com.apple.private.tcc.manager` **gehou** en biblioteekvalidasie **gedeaktiveer**, dus kon 'n HAL-inprop wat in `/Library/Audio/Plug-Ins/HAL` geplaas is, arbitrêre TCC-regte toestaan ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft vind nuwe macOS-kwesbaarheid, Shrootless, wat System Integrity Protection kan omseil](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Tegniese ontleding: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC bypass steel data uit iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Ontbloot macOS-malware: Bypassing TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Nuwe macOS-kwesbaarheid, "powerdir," kan tot ongemagtigde gebruikerdata-toegang lei](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC bypass in XCSSET-malware ontdek](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Omseiling van die macOS Transparency, Consent, and Control (TCC) Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Speel die musiek en omseil TCC, oftewel CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Die nagmerrie van Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [Hoe om jou eie Screen Time-wagkode te omseil — bron- en Time Machine/DataVault-ontleding](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
