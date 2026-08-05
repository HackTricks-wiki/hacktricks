# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Basiese inligting

Vanaf **macOS Big Sur (11.0)** word die stelselvolume kriptografies verseël met behulp van 'n **APFS snapshot hash tree**. Dit word die **Sealed System Volume (SSV)** genoem. Die stelselpartisie word **leesalleen** gemonteer, en enige wysiging verbreek die seël, wat tydens opstart geverifieer word.

Die SSV bied:
- **Opsporing van peutery** — enige wysiging aan stelselbinaries/frameworks kan opgespoor word deur die verbreekte kriptografiese seël
- **Beskerming teen terugrol** — die opstartproses verifieer die integriteit van die stelselsnapshot
- **Voorkoming van rootkits** — selfs root kan nie lêers op die stelselvolume permanent wysig nie (sonder om die seël te verbreek)

### Kontrole van SSV-status
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
### SSV-skrywer-entitlements

Sekere Apple-stelselbinaries het entitlements waarmee hulle die sealed system volume kan wysig of bestuur:

| Entitlement | Doel |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Stel die stelselvolume terug na ’n vorige snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Skep ’n nuwe sealed snapshot ná stelselopdaterings |
| `com.apple.rootless.install.heritable` | Skryf na SIP-beskermde paaie (geërf deur child processes) |
| `com.apple.rootless.install` | Skryf na SIP-beskermde paaie |

### Vind SSV-skrywers
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

As 'n aanvaller 'n binêre lêer met `com.apple.private.apfs.revert-to-snapshot` kompromitteer, kan hulle die stelselvolume **na 'n toestand voor 'n opdatering terugrol**, waardeur bekende kwesbaarhede herstel word:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot rollback **maak sekuriteitsopdaterings effektief ongedaan** deur voorheen-gelapte kernel- en stelselkwesbaarhede te herstel. Dit is een van die gevaarlikste bewerkings wat op moderne macOS moontlik is.

#### System Binary Replacement

Met SIP bypass + SSV write capability kan 'n aanvaller:

1. Die system volume read-write mount
2. 'n System daemon of framework library met 'n trojaned weergawe vervang
3. Die snapshot weer seël (of die gebreekte seël aanvaar indien SIP reeds gedegradeer is)
4. Die rootkit bly voortbestaan ná herlaaie en is onsigbaar vir userland detection tools

### Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass wat `system_installd` se `com.apple.rootless.install.heritable` entitlement misbruik om arbitrêre post-install scripts uit te voer ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd` het die post-install script in 'n SIP-protected folder onder `/tmp` gestoor, maar `/tmp` self is nie SIP-protected nie, dus kon die folder vervang word deur 'n image daaroor te mount ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — copy-on-write race in XNU wat writes na read-only root-owned files moontlik maak ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Basic Information

**DataVault** is Apple se protection layer vir sensitiewe system databases. Selfs **root kan nie toegang tot DataVault-protected files kry nie** — slegs prosesse met spesifieke entitlements kan dit lees of wysig.<sup>[1]</sup> Protected stores sluit in:

| Protected Database | Path | Content |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Stelselwye TCC-privaatheidsbesluite |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | TCC-privaatheidsbesluite per gebruiker |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

DataVault protection word op die **filesystem-vlak** afgedwing deur extended attributes en volume protection flags te gebruik, wat deur die kernel geverifieer word.

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### Vind DataVault-beheerders
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

#### Direkte TCC-databasismodifikasie

As 'n aanvaller 'n DataVault-beheerderbinêr kompromitteer (byvoorbeeld deur code injection in 'n proses met `com.apple.private.tcc.manager`), kan hulle **die TCC-databasis direk wysig** om enige TCC-permissie aan enige toepassing toe te ken:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> TCC-databasiswysiging is die **uiteindelike privaatheid-omseiling** — dit verleen enige toestemming stilweg, sonder enige gebruikersaanpor of sigbare aanduiding. Histories het verskeie macOS privilege escalation-kettings geëindig met TCC-databasisskrywings as die finale payload.

#### Toegang tot Keychain-databasis

DataVault beskerm ook die ondersteunende keychain-lêers. ’n Gekompromitteerde DataVault-beheerder kan:

1. Die rou keychain-databasislêers lees
2. Geënkripteerde keychain-items onttrek
3. Aflyn-dekripsie probeer met die gebruiker se wagwoord of herwonne sleutels

### Werklike CVE's Waarby DataVault/TCC-omseiling Betrokke Is

| CVE | Beskrywing |
|---|---|
| CVE-2024-44131 | FileProvider-simboliese-skakel-race wat ’n bevoorregte helper toelaat om toegang tot TCC-beskermde data te verkry ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | As root, **skep ’n nuwe gebruiker wie se `NFSHomeDirectory` na ’n aanvaller-beheerde `TCC.db` wys**; wanneer daar aangemeld word, verwerk `tccd` dit en die grants word toegepas, wat toegang tot ander gebruikers se data gee ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": verander die gebruiker se tuisgids om ’n aanvaller-beheerde TCC.db te plaas ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Fout in bundelafleiding wat ’n toepassing toelaat om **die TCC-grants van ’n donor-bundel te erf** sonder ’n aanpor; in die wild uitgebuit deur **XCSSET** om die lessenaar af te neem ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` het die databasispad vanaf `$HOME` saamgestel, sodat `launchctl setenv HOME` dit na ’n aanvaller-beheerde `TCC.db` herlei het ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` het `com.apple.private.tcc.manager` gehad **en** biblioteekvalidering gedeaktiveer, sodat ’n HAL-inprop wat in `/Library/Audio/Plug-Ins/HAL` geplaas is, arbitrêre TCC-regte kon verleen ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Verwysings

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
