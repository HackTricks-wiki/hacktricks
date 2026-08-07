# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basiese Inligting

Vanaf **macOS Big Sur (11.0)** word die system volume kriptografies verseël deur ’n **APFS snapshot hash tree** te gebruik. Dit word die **Sealed System Volume (SSV)** genoem. Die system partition word **read-only** gemount, en enige wysiging verbreek die verseëling, wat tydens boot geverifieer word.<sup>[[11]](#references)</sup>

Die SSV bied:
- **Tamper detection** — enige wysiging aan system binaries/frameworks kan opgespoor word deur die gebreekte kriptografiese verseëling
- **Rollback protection** — die boot-proses verifieer die integriteit van die system snapshot
- **Rootkit prevention** — selfs root kan nie lêers op die system volume permanent wysig nie (sonder om die verseëling te verbreek)

### Checking SSV Status
```bash
# Check if authenticated root is enabled (SSV seal verification)
csrutil authenticated-root status

# List APFS snapshots (the sealed snapshot is the boot volume)
diskutil apfs listSnapshots disk3s1

# Check mount status (should show read-only)
mount | grep " / "

# Verify the system volume seal
diskutil apfs listVolumeGroups
```
### SSV Writer-Entitlements

Sekere Apple-stelselbinaries het entitlements wat hulle toelaat om die verseelde stelselvolume te wysig of te bestuur:

| Entitlement | Doel |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Stel die stelselvolume na ’n vorige snapshot terug |
| `com.apple.private.apfs.create-sealed-snapshot` | Skep ’n nuwe verseelde snapshot ná stelselopdaterings |
| `com.apple.rootless.install.heritable` | Skryf na SIP-beskermde paths (geërf deur child processes) |
| `com.apple.rootless.install` | Skryf na SIP-beskermde paths |

### Vind SSV Writers
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

#### Snapshot Rollback Attack

As 'n aanvaller 'n binary met `com.apple.private.apfs.revert-to-snapshot` kompromitteer, kan hulle **die stelselvolume na 'n toestand voor die opdatering terugrol**, wat bekende kwesbaarhede herstel:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback maak sekuriteitsopdaterings effektief **ongedaan** en herstel voorheen-gelapte kernel- en stelselkwesbaarhede. Dit is een van die gevaarlikste bewerkings wat op moderne macOS moontlik is.

#### Vervanging van stelselbinêre

Met SIP-bypass + SSV-skryfvermoë kan 'n aanvaller:

1. Die stelselvolume lees-skryf monteer
2. 'n Stelseldeemon of framework-biblioteek met 'n trojaned weergawe vervang
3. Die snapshot weer seël (of die gebreekte seël aanvaar indien SIP reeds gedegradeer is)
4. Die rootkit bly oor herselflaaie heen voortbestaan en is onsigbaar vir userland-opsporingsnutsgoed

### Werklike CVEs

| CVE | Beskrywing |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP-bypass wat `system_installd` se `com.apple.rootless.install.heritable`-entitlement misbruik om arbitrêre post-install-skripte uit te voer ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP-bypass: `system_installd` het die post-install-skrip in 'n SIP-beskermde vouer onder `/tmp` gestoor, maar `/tmp` self is nie SIP-beskerm nie, dus kon die vouer vervang word deur 'n image daaroor te mount ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write-race in XNU wat skryfbewerkings na leesalleen-root-owned-lêers moontlik maak ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Basiese inligting

**DataVault** is Apple se beskermingslaag vir sensitiewe stelseldatabasisse. Selfs **root kan nie toegang tot DataVault-beskermde lêers verkry nie** — slegs prosesse met spesifieke entitlements kan dit lees of wysig.<sup>[[4]](#references)</sup> Beskermde stores sluit in:

| Beskermde databasis | Pad | Inhoud |
|---|---|---|
| TCC (stelsel) | `/Library/Application Support/com.apple.TCC/TCC.db` | Stelselwye TCC-privaatheidsbesluite |
| TCC (gebruiker) | `~/Library/Application Support/com.apple.TCC/TCC.db` | TCC-privaatheidsbesluite per gebruiker |
| Keychain (stelsel) | `/Library/Keychains/System.keychain` | Stelsel-keychain |
| Keychain (gebruiker) | `~/Library/Keychains/login.keychain-db` | Gebruiker-keychain |

DataVault-beskerming word op **lêerstelselvlak** afgedwing deur uitgebreide attribute en volumebeskermingsvlae te gebruik, wat deur die kernel geverifieer word.

### DataVault Controller-entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Vind DataVault Controllers
```bash
# Check DataVault protection on the TCC database
ls -le@ "/Library/Application Support/com.apple.TCC/TCC.db"

# Find binaries with TCC management entitlements
find /System /usr -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "private.tcc\|datavault\|rootless.storage.TCC" && echo "{}"
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

#### Direkte TCC-databasiswysiging

As 'n aanvaller 'n DataVault-beheerder-binêre lêer kompromitteer (byvoorbeeld deur kode-inspuiting in 'n proses met `com.apple.private.tcc.manager`), kan hulle die **TCC-databasis direk wysig** om aan enige toepassing enige TCC-permissie toe te ken:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC-databasiswysiging is die **uiteindelike privaatheidsomseiling** — dit verleen enige toestemming stilweg, sonder enige gebruikersprompt of sigbare aanduiding. Histories het verskeie macOS privilege escalation-kettings geëindig met TCC-databasiswrites as die finale payload.

#### Toegang tot Keychain-databasis

DataVault beskerm ook die keychain se ondersteunende lêers. ’n Gekompromitteerde DataVault-controller kan:

1. Die rou keychain-databasislêers lees
2. Geënkripteerde keychain-items onttrek
3. Offline-dekripsie probeer deur die gebruiker se password of herwonne sleutels te gebruik

### CVEs uit die werklike wêreld wat DataVault/TCC-bypass behels

| CVE | Beskrywing |
|---|---|
| CVE-2024-44131 | FileProvider symlink race wat ’n bevoorregte helper toegang tot TCC-beskermde data gee ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | As root, **skep ’n nuwe gebruiker wie se `NFSHomeDirectory` na ’n aanvaller-beheerde `TCC.db` wys**; met login verwerk `tccd` dit en die grants word toegepas, wat toegang tot ander gebruikers se data gee ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": verander die gebruiker se home dir om ’n aanvaller-beheerde TCC.db te plaas ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Bundle-conclusion-fout wat ’n app toelaat om **die TCC-grants van ’n donor bundle te erf** sonder ’n prompt; in die wild uitgebuit deur **XCSSET** om ’n screenshot van die desktop te neem ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` het die DB-path vanaf `$HOME` gebou, dus het `launchctl setenv HOME` dit na ’n aanvaller-beheerde `TCC.db` herlei ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` het `com.apple.private.tcc.manager` gehad **en library validation gedeaktiveer**, dus kon ’n HAL plug-in wat in `/Library/Audio/Plug-Ins/HAL` geplaas is arbitrêre TCC-regte verleen ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## Verwysings

- [1] [Microsoft vind nuwe macOS-kwesbaarheid, Shrootless, wat System Integrity Protection kan omseil](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Tegniese analise: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Dit is die moeite werd om dit sleg te doen](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC-bypass steel data uit iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Ontbloting van macOS-malware: Omseiling van TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Nuwe macOS-kwesbaarheid, "powerdir", kan tot ongemagtigde gebruikerdata-toegang lei](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day TCC-bypass ontdek in XCSSET-malware](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Omseiling van die macOS Transparency, Consent, and Control (TCC)-Framework](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Speel die musiek en omseil TCC, oftewel CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Die nagmerrie van Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
