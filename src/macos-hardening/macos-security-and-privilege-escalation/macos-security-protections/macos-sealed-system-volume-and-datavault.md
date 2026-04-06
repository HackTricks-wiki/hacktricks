# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Grundinformationen

Seit **macOS Big Sur (11.0)** ist das Systemvolume kryptographisch versiegelt mittels eines **APFS snapshot hash tree**. Dies wird als **Sealed System Volume (SSV)** bezeichnet. Die Systempartition wird **read-only** gemountet, und jede Modifikation bricht die Versiegelung, die beim Boot überprüft wird.

Das SSV bietet:
- **Manipulationserkennung** — jede Änderung an Systembinaries/-frameworks ist über die gebrochene kryptographische Versiegelung erkennbar
- **Rollback-Schutz** — der Bootprozess überprüft die Integrität des System-Snapshots
- **Rootkit-Schutz** — selbst root kann Dateien auf dem Systemvolume nicht dauerhaft ändern (ohne die Versiegelung zu brechen)

### SSV-Status überprüfen
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
### SSV-Writer-Berechtigungen

Bestimmte Apple-Systembinaries haben Entitlements, die es ihnen erlauben, das sealed system volume zu ändern oder zu verwalten:

| Entitlement | Zweck |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Setzt das Systemvolume auf einen früheren Snapshot zurück |
| `com.apple.private.apfs.create-sealed-snapshot` | Erstellt nach Systemupdates einen neuen versiegelten Snapshot |
| `com.apple.rootless.install.heritable` | Schreibt in SIP-geschützte Pfade (wird an Kindprozesse vererbt) |
| `com.apple.rootless.install` | Schreibt in SIP-geschützte Pfade |

### SSV-Writer finden
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
### Angriffsszenarien

#### Snapshot Rollback Attack

Wenn ein Angreifer ein binary mit `com.apple.private.apfs.revert-to-snapshot` kompromittiert, kann er **das Systemvolume in einen Zustand vor dem Update zurücksetzen**, wodurch bekannte Schwachstellen wiederhergestellt werden:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Snapshot-Rollback macht effektiv **Sicherheitsupdates rückgängig** und stellt zuvor gepatchte Kernel- und System-Schwachstellen wieder her. Dies ist eine der gefährlichsten Operationen auf modernen macOS-Systemen.

#### System Binary Replacement

Mit SIP bypass + SSV write capability kann ein Angreifer:

1. Mount the system volume read-write
2. Replace a system daemon or framework library with a trojaned version
3. Re-seal the snapshot (or accept the broken seal if SIP is already degraded)
4. The rootkit persists across reboots and is invisible to userland detection tools

### Real-World CVEs

| CVE | Beschreibung |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass, der SSV-Änderungen via `system_installd` ermöglicht |
| CVE-2022-22583 | SSV bypass through PackageKit's snapshot handling |
| CVE-2022-46689 | Race condition allowing writes to SIP-protected files |

---

## DataVault

### Grundlegende Informationen

**DataVault** ist Apples Schutzschicht für sensitive Systemdatenbanken. Selbst **root kann nicht auf DataVault-geschützte Dateien zugreifen** — nur Prozesse mit spezifischen entitlements können sie lesen oder ändern. Geschützte Stores umfassen:

| Geschützte Datenbank | Pfad | Inhalt |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | System-wide TCC privacy decisions |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user TCC privacy decisions |
| Keychain (system) | `/Library/Keychains/System.keychain` | System keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | User keychain |

Der DataVault-Schutz wird auf Ebene des **Dateisystems** durch erweiterte Attribute und Volume protection flags durchgesetzt und vom Kernel überprüft.

### DataVault Controller Entitlements
```
com.apple.private.tcc.manager         — Full TCC database read/write
com.apple.private.tcc.manager.check-by-audit-token — TCC checks via audit token
com.apple.private.tcc.allow           — Access specific TCC-protected resources
com.apple.rootless.storage.TCC        — Write to TCC database (SIP-related)
```
### DataVault-Controller finden
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
### Angriffsszenarien

#### Direkte Modifikation der TCC-Datenbank

Wenn ein Angreifer ein DataVault controller binary kompromittiert (z. B. durch code injection in einen Prozess mit `com.apple.private.tcc.manager`), kann er die TCC-Datenbank **direkt modifizieren**, um jeder Anwendung beliebige TCC-Berechtigungen zu gewähren:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Die Modifikation der TCC-Datenbank ist der **ultimative privacy bypass** — sie gewährt beliebige Berechtigungen lautlos, ohne eine Benutzerabfrage oder sichtbaren Hinweis. Historisch endeten mehrere macOS privilege escalation chains mit TCC-Datenbank-Schreibvorgängen als finaler payload.

#### Zugriff auf die Keychain-Datenbank

DataVault schützt ebenfalls die Keychain-Backing-Dateien. Ein kompromittierter DataVault-Controller kann:

1. die rohen Keychain-Datenbankdateien auslesen
2. verschlüsselte Keychain-Items extrahieren
3. eine Offline-Entschlüsselung versuchen, mithilfe des Benutzerpassworts oder wiedergewonnener Schlüssel

### Real-World CVEs Involving DataVault/TCC Bypass

| CVE | Beschreibung |
|---|---|
| CVE-2023-40424 | TCC bypass via symlink zu einer von DataVault geschützten Datei |
| CVE-2023-32364 | Sandbox bypass, der zur Modifikation der TCC-Datenbank führte |
| CVE-2021-30713 | TCC bypass via XCSSET malware, die TCC.db modifiziert |
| CVE-2020-9934 | TCC bypass via Manipulation von Umgebungsvariablen |
| CVE-2020-29621 | Music-App TCC bypass, der DataVault erreicht |

## Quellen

* [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
* [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
* [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
