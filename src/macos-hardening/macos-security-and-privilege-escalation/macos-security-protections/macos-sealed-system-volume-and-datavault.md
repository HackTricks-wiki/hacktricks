# macOS Verseëlde Stelselvolume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Verseëlde Stelselvolume (SSV)

### Basiese inligting

Vanaf **macOS Big Sur (11.0)** word die stelselvolume kriptografies verseël deur gebruik te maak van 'n **APFS snapshot hash tree**. Dit staan bekend as die **Sealed System Volume (SSV)**. Die stelselpartisie word as **read-only** aangemount en enige wysiging breek die seël, wat tydens opstart geverifieer word.

Die SSV bied:
- **Manipulasie-opsporing** — enige wysiging aan stelsel-binaries/frameworks is opspoorbaar deur die gebroke kriptografiese seël
- **Rollback-beskerming** — die opstartproses verifieer die integriteit van die stelsel-snapshot
- **Rootkit-voorkoming** — selfs root kan nie volhoubaar lêers op die stelselvolume wysig nie (sonder om die seël te breek)

### SSV-status nagaan
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
### Entitlements van SSV-skrywers

Sekere Apple-stelselbinaire het entitlements wat hulle toelaat om die verseëlde stelselvolume te wysig of te bestuur:

| Entitlement | Doel |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Herstel die stelselvolume na 'n vorige snapshot |
| `com.apple.private.apfs.create-sealed-snapshot` | Skep 'n nuwe verseëlde snapshot na stelselopdaterings |
| `com.apple.rootless.install.heritable` | Skryf na SIP-beskermde paaie (geërf deur kinderprosesse) |
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

As 'n aanvaller 'n binêre kompromitteer met `com.apple.private.apfs.revert-to-snapshot`, kan hulle die stelselvolume **terugrol na 'n toestand voor die opdatering**, en sodoende bekende kwesbaarhede herstel:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Die terugrol van 'n snapshot maak prakties **veiligheidsopdaterings ongeldig**, en herstel kern- en stelsel kwesbaarhede wat voorheen gepatch is. Dit is een van die gevaarlikste operasies moontlik op moderne macOS.

#### Vervanging van stelselbinasies

Met SIP bypass + SSV-skryfvermoë kan 'n aanvaller:

1. Koppel die stelselvolume as lees-skryf
2. Vervang 'n stelseldaemon of raamwerkbiblioteek met 'n trojaned weergawe
3. Herseël die snapshot (of aanvaar die gebreekte seël as SIP reeds gedegradeer is)
4. Die rootkit bly oor na herlaaibeurte en is onsigbaar vir userland-deteksie-instrumente

### Werklike CVEs

| CVE | Description |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP-bypas wat SSV-wysiging via `system_installd` toelaat |
| CVE-2022-22583 | SSV-bypas deur PackageKit se snapshot-hantering |
| CVE-2022-46689 | Wedrenstoestand wat skrywings na SIP-beskermde lêers toelaat |

---

## DataVault

### Basiese Inligting

**DataVault** is Apple se beskermingslaag vir sensitiewe stelseldatabasisse. Selfs **root kan nie toegang tot DataVault-beskermde lêers kry nie** — slegs prosesse met spesifieke entitlements kan dit lees of wysig. Beskermde stoorplekke sluit in:

| Beskermde Databasis | Pad | Inhoud |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Stelselwyd TCC-privaatheidsbesluite |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-gebruiker TCC-privaatheidsbesluite |
| Keychain (system) | `/Library/Keychains/System.keychain` | Stelsel keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Gebruiker keychain |

DataVault-beskerming word op die **lêerstelselvlak** afgedwing deur gebruik van uitgebreide attributte en volume-beskermingsvlagte, geverifieer deur die kernel.

### DataVault-beheerder entitlements
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

#### Direkte wysiging van die TCC-databasis

Indien 'n aanvaller 'n DataVault controller binary kompromitteer (bv. via code injection into a process with `com.apple.private.tcc.manager`), kan hulle **direk die TCC-databasis wysig** om enige toepassing enige TCC permission te gee:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Die wysiging van die TCC-databasis is die **uiteindelike privacy bypass** — dit verleen enige toestemming stilweg, sonder enige gebruikersprompt of sigbare aanduiding. Histories het verskeie macOS privilege escalation chains geëindig met TCC-databasis-skrywings as die finale payload.

#### Toegang tot Keychain-databasis

DataVault beskerm ook die keychain backing files. ’n Gekompromitteerde DataVault controller kan:

1. Lees die rou keychain database-lêers
2. Extract versleutelde keychain-items
3. Attempt offline decryption using die gebruiker se wagwoord of recovered keys

### Werklike CVE's wat DataVault/TCC Bypass betrek

| CVE | Description |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink to DataVault-protected file |
| CVE-2023-32364 | Sandbox bypass leading to TCC database modification |
| CVE-2021-30713 | TCC bypass via XCSSET malware modifying TCC.db |
| CVE-2020-9934 | TCC bypass via environment variable manipulation |
| CVE-2020-29621 | Music app TCC bypass reaching DataVault |

## References

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
