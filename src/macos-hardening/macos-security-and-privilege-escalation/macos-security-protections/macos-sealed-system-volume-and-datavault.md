# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Grundlegende Informationen

Ab **macOS Big Sur (11.0)** wird das Systemvolume mithilfe eines kryptografisch versiegelten **APFS-Snapshot-Hash-Trees** geschützt. Dies wird als **Sealed System Volume (SSV)** bezeichnet. Die Systempartition wird **read-only** eingehängt, und jede Änderung bricht die Versiegelung, was während des boot überprüft wird.

Das SSV bietet:
- **Manipulationserkennung** — Jede Änderung an System-Binaries oder Frameworks kann anhand der beschädigten kryptografischen Versiegelung erkannt werden
- **Rollback-Schutz** — Der boot-Prozess überprüft die Integrität des System-Snapshots
- **Rootkit-Prävention** — Selbst root kann Dateien auf dem Systemvolume nicht dauerhaft ändern, ohne die Versiegelung zu brechen

### Überprüfen des SSV-Status
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

Bestimmte Apple-Systembinärdateien verfügen über Berechtigungen, die es ihnen ermöglichen, das versiegelte Systemvolume zu ändern oder zu verwalten:

| Berechtigung | Zweck |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Das Systemvolume auf einen vorherigen Snapshot zurücksetzen |
| `com.apple.private.apfs.create-sealed-snapshot` | Nach Systemupdates einen neuen versiegelten Snapshot erstellen |
| `com.apple.rootless.install.heritable` | In SIP-geschützte Pfade schreiben (wird von untergeordneten Prozessen geerbt) |
| `com.apple.rootless.install` | In SIP-geschützte Pfade schreiben |

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

Wenn ein Angreifer eine Binärdatei mit `com.apple.private.apfs.revert-to-snapshot` kompromittiert, kann er **das Systemvolume auf einen Zustand vor dem Update zurücksetzen** und dadurch bekannte Schwachstellen wiederherstellen:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Ein Snapshot rollback macht Sicherheitsupdates effektiv **rückgängig** und stellt zuvor gepatchte Kernel- und Systemschwachstellen wieder her. Dies ist eine der gefährlichsten möglichen Operationen auf modernem macOS.

#### System Binary Replacement

Mit SIP bypass + SSV write capability kann ein Angreifer:

1. Das Systemvolume read-write mounten
2. Einen System-Daemon oder eine Framework library durch eine trojanisierte Version ersetzen
3. Den Snapshot erneut versiegeln (oder das beschädigte Siegel akzeptieren, wenn SIP bereits beeinträchtigt ist)
4. Das Rootkit bleibt über Reboots hinweg bestehen und ist für Userland detection tools unsichtbar

### Real-World CVEs

| CVE | Beschreibung |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass durch Ausnutzung des Entitlements `com.apple.rootless.install.heritable` von `system_installd`, um beliebige post-install scripts auszuführen ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd` legte das post-install script in einem SIP-geschützten Ordner unter `/tmp` ab, aber `/tmp` selbst ist nicht SIP-geschützt, sodass der Ordner durch das Mounten eines Images darüber ersetzt werden konnte ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — Copy-on-write race in XNU, die Schreibvorgänge in schreibgeschützte, root-eigene Dateien ermöglicht ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Grundlegende Informationen

**DataVault** ist Apples protection layer für sensible Systemdatenbanken. Selbst **root kann nicht auf durch DataVault geschützte Dateien zugreifen** — nur Prozesse mit bestimmten Entitlements können sie lesen oder ändern.<sup>[[1]](#references)</sup> Zu den geschützten Stores gehören:

| Geschützte Datenbank | Pfad | Inhalt |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Systemweite TCC-Datenschutzentscheidungen |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | Benutzerbezogene TCC-Datenschutzentscheidungen |
| Keychain (system) | `/Library/Keychains/System.keychain` | System-Keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Benutzer-Keychain |

Der DataVault-Schutz wird auf **filesystem level** mithilfe von Extended Attributes und Volume-Protection-Flags durchgesetzt und vom Kernel verifiziert.

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

#### Direkte Änderung der TCC-Datenbank

Wenn ein Angreifer ein DataVault controller binary kompromittiert (z. B. durch code injection in einen Prozess mit `com.apple.private.tcc.manager`), kann er die **TCC-Datenbank direkt ändern**, um jeder Anwendung eine beliebige TCC-Berechtigung zu gewähren:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Die Änderung der TCC-Datenbank ist der **ultimative Privacy Bypass** — sie gewährt jede Berechtigung stillschweigend, ohne Benutzerabfrage oder sichtbaren Hinweis. Historisch endeten mehrere macOS-Privilege-Escalation-Ketten mit Schreibzugriffen auf die TCC-Datenbank als finalem Payload.

#### Zugriff auf die Keychain-Datenbank

DataVault schützt auch die zugrunde liegenden Keychain-Dateien. Ein kompromittierter DataVault-Controller kann:

1. Die rohen Keychain-Datenbankdateien lesen
2. Verschlüsselte Keychain-Einträge extrahieren
3. Eine Offline-Entschlüsselung mit dem Passwort des Benutzers oder wiederhergestellten Schlüsseln versuchen

### Reale CVEs im Zusammenhang mit DataVault/TCC Bypass

| CVE | Beschreibung |
|---|---|
| CVE-2024-44131 | FileProvider symlink race, durch die ein privilegierter Helper auf durch TCC geschützte Daten zugreifen kann ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Als root einen **neuen Benutzer erstellen, dessen `NFSHomeDirectory` auf eine vom Angreifer kontrollierte `TCC.db` zeigt**; beim Login verwendet `tccd` diese Datei, und die Berechtigungen werden angewendet, wodurch der Zugriff auf die Daten anderer Benutzer möglich wird ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": Das Home-Verzeichnis des Benutzers ändern, um eine vom Angreifer kontrollierte TCC.db zu platzieren ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Bundle-conclusion-Fehler, durch den eine App **die TCC-Berechtigungen eines Spender-Bundles erben kann**, ohne dass eine Abfrage erscheint; in freier Wildbahn von **XCSSET** ausgenutzt, um den Desktop per Screenshot aufzunehmen ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` erstellte den DB-Pfad aus `$HOME`, sodass `launchctl setenv HOME` ihn auf eine vom Angreifer kontrollierte `TCC.db` umleiten konnte ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` verfügte über `com.apple.private.tcc.manager` **und** deaktivierte die Library-Validierung, sodass ein in `/Library/Audio/Plug-Ins/HAL` abgelegtes HAL-Plug-in beliebige TCC-Berechtigungen gewähren konnte ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Referenzen

- [1] [Apple Platform Security — Datenschutz](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [Der Albtraum der Apple-OTA-Updates (APFS-Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
