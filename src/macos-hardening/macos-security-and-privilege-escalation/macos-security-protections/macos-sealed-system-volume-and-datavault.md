# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Grundlegende Informationen

Ab **macOS Big Sur (11.0)** wird das Systemvolume mithilfe eines **APFS-Snapshot-Hashbaums** kryptografisch versiegelt. Dies wird als **Sealed System Volume (SSV)** bezeichnet. Die Systempartition wird **schreibgeschützt** eingebunden, und jede Änderung hebt die Versiegelung auf, was während des Bootvorgangs überprüft wird.

Das SSV bietet:
- **Manipulationserkennung** — jede Änderung an System-Binaries oder Frameworks kann anhand der beschädigten kryptografischen Versiegelung erkannt werden
- **Rollback-Schutz** — der Bootvorgang überprüft die Integrität des System-Snapshots
- **Rootkit-Prävention** — selbst root kann Dateien auf dem Systemvolume nicht dauerhaft ändern, ohne die Versiegelung aufzuheben

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

Bestimmte Apple-System-Binaries verfügen über Entitlements, die es ihnen erlauben, das sealed system volume zu ändern oder zu verwalten:

| Entitlement | Zweck |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Das System volume auf einen vorherigen Snapshot zurücksetzen |
| `com.apple.private.apfs.create-sealed-snapshot` | Nach Systemupdates einen neuen sealed Snapshot erstellen |
| `com.apple.rootless.install.heritable` | In SIP-geschützte Pfade schreiben (wird von Child-Prozessen geerbt) |
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

#### Snapshot-Rollback-Angriff

Wenn ein Angreifer ein Binary mit `com.apple.private.apfs.revert-to-snapshot` kompromittiert, kann er **das Systemvolume auf einen Zustand vor einem Update zurücksetzen** und dadurch bekannte Schwachstellen wiederherstellen:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Das Zurücksetzen eines Snapshots macht Sicherheitsupdates effektiv **rückgängig** und stellt zuvor gepatchte Kernel- und System-Schwachstellen wieder her. Dies ist eine der gefährlichsten möglichen Operationen unter modernen macOS-Versionen.

#### Ersetzen von System-Binaries

Mit einem SIP bypass + SSV write capability kann ein Angreifer:

1. Das System-Volume read-write mounten
2. Einen System-Daemon oder eine Framework-Bibliothek durch eine trojanisierte Version ersetzen
3. Den Snapshot erneut versiegeln (oder das beschädigte Siegel akzeptieren, wenn SIP bereits beeinträchtigt ist)
4. Das Rootkit bleibt über Neustarts hinweg bestehen und ist für Userland-Erkennungstools unsichtbar

### CVEs aus der Praxis

| CVE | Beschreibung |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass durch Missbrauch des Entitlements `com.apple.rootless.install.heritable` von `system_installd`, um beliebige post-install scripts auszuführen ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)) |
| CVE-2022-22583 | SIP bypass: `system_installd` legte das post-install script in einem SIP-geschützten Ordner unter `/tmp` ab, aber `/tmp` selbst ist nicht SIP-geschützt, sodass der Ordner durch das Mounten eines Images darüber ausgetauscht werden konnte ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)) |
| CVE-2022-46689 | **MacDirtyCow** — Copy-on-Write-Race in XNU, die Schreibzugriffe auf schreibgeschützte Dateien im Besitz von root ermöglicht ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)) |

---

## DataVault

### Grundlegende Informationen

**DataVault** ist Apples Schutzschicht für vertrauliche Systemdatenbanken. Selbst **root kann nicht auf durch DataVault geschützte Dateien zugreifen** — nur Prozesse mit spezifischen Entitlements können sie lesen oder ändern.<sup>[1]</sup> Zu den geschützten Speichern gehören:

| Geschützte Datenbank | Pfad | Inhalt |
|---|---|---|
| TCC (System) | `/Library/Application Support/com.apple.TCC/TCC.db` | Systemweite TCC-Datenschutzentscheidungen |
| TCC (Benutzer) | `~/Library/Application Support/com.apple.TCC/TCC.db` | TCC-Datenschutzentscheidungen pro Benutzer |
| Keychain (System) | `/Library/Keychains/System.keychain` | System-Keychain |
| Keychain (Benutzer) | `~/Library/Keychains/login.keychain-db` | Benutzer-Keychain |

Der DataVault-Schutz wird auf **Dateisystemebene** mithilfe erweiterter Attribute und Volume-Schutz-Flags durchgesetzt und vom Kernel überprüft.

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

Wenn ein Angreifer eine DataVault-Controller-Binärdatei kompromittiert (z. B. durch code injection in einen Prozess mit `com.apple.private.tcc.manager`), kann er die **TCC-Datenbank direkt ändern**, um jeder Anwendung beliebige TCC-Berechtigungen zu gewähren:
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Die Änderung der TCC-Datenbank ist der **ultimative Datenschutz-Bypass** — sie gewährt jede Berechtigung stillschweigend, ohne Benutzerabfrage oder sichtbaren Hinweis. In der Vergangenheit endeten mehrere macOS-Privilege-Escalation-Ketten mit Schreibzugriffen auf die TCC-Datenbank als finalem Payload.

#### Zugriff auf die Keychain-Datenbank

DataVault schützt auch die zugrunde liegenden Keychain-Dateien. Ein kompromittierter DataVault-Controller kann:

1. Die Rohdateien der Keychain-Datenbank lesen
2. Verschlüsselte Keychain-Einträge extrahieren
3. Eine Offline-Entschlüsselung mit dem Passwort des Benutzers oder wiederhergestellten Schlüsseln versuchen

### CVEs aus der Praxis im Zusammenhang mit DataVault/TCC-Bypass

| CVE | Beschreibung |
|---|---|
| CVE-2024-44131 | FileProvider-Symlink-Race, durch die ein privilegierter Helper auf TCC-geschützte Daten zugreifen kann ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)) |
| CVE-2023-40424 | Als root **einen neuen Benutzer erstellen, dessen `NFSHomeDirectory` auf eine vom Angreifer kontrollierte `TCC.db` zeigt**; beim Login verwendet `tccd` diese Datei, und die Berechtigungen werden angewendet, wodurch der Zugriff auf die Daten anderer Benutzer möglich wird ([Kandji](https://blog.kandji.io/malware-bypass-tcc)) |
| CVE-2021-30970 | "powerdir": Das Home-Verzeichnis des Benutzers ändern, um eine vom Angreifer kontrollierte TCC.db zu platzieren ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)) |
| CVE-2021-30713 | Fehler bei der Bundle-Auswertung, durch den eine App **die TCC-Berechtigungen eines Spender-Bundles erben kann**, ohne eine Abfrage; in freier Wildbahn von **XCSSET** ausgenutzt, um den Desktop per Screenshot aufzunehmen ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)) |
| CVE-2020-9934 | `tccd` erstellte den Datenbankpfad aus `$HOME`, sodass `launchctl setenv HOME` ihn auf eine vom Angreifer kontrollierte `TCC.db` umleiten konnte ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)) |
| CVE-2020-29621 | `coreaudiod` verfügte über `com.apple.private.tcc.manager` **und** deaktivierte die Library-Validierung, sodass ein in `/Library/Audio/Plug-Ins/HAL` abgelegtes HAL-Plug-in beliebige TCC-Berechtigungen gewähren konnte ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)) |

## Referenzen

- [1] [Apple Platform Security — Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [2] [The Nightmare of Apple OTA Updates (APFS Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [3] [Objective-See — TCC Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
