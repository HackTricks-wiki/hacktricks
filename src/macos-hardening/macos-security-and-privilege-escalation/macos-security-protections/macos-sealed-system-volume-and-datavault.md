# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Grundlegende Informationen

Ab **macOS Big Sur (11.0)** wird das Systemvolume mithilfe eines kryptografisch versiegelten **APFS snapshot hash tree** geschützt. Dies wird als **Sealed System Volume (SSV)** bezeichnet. Die Systempartition wird **read-only** eingebunden, und jede Änderung bricht die Versiegelung, was während des Bootvorgangs überprüft wird.<sup>[[11]](#references)</sup>

Das SSV bietet:
- **Manipulationserkennung** — jede Änderung an System-Binaries oder Frameworks kann anhand der beschädigten kryptografischen Versiegelung erkannt werden
- **Rollback-Schutz** — der Bootvorgang überprüft die Integrität des System-Snapshots
- **Rootkit-Prävention** — selbst root kann Dateien auf dem Systemvolume nicht dauerhaft ändern, ohne die Versiegelung zu brechen

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
### SSV-Schreibberechtigungen

Bestimmte Apple-System-Binaries verfügen über Berechtigungen, mit denen sie das versiegelte Systemvolume ändern oder verwalten können:

| Berechtigung | Zweck |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Das Systemvolume auf einen vorherigen Snapshot zurücksetzen |
| `com.apple.private.apfs.create-sealed-snapshot` | Nach Systemupdates einen neuen versiegelten Snapshot erstellen |
| `com.apple.rootless.install.heritable` | In SIP-geschützte Pfade schreiben (wird von untergeordneten Prozessen geerbt) |
| `com.apple.rootless.install` | In SIP-geschützte Pfade schreiben |

### SSV-Schreibprozesse finden
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

Wenn ein Angreifer eine Binary mit `com.apple.private.apfs.revert-to-snapshot` kompromittiert, kann er **das Systemvolume auf einen Zustand vor dem Update zurücksetzen** und dadurch bekannte Schwachstellen wiederherstellen:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Ein Snapshot-Rollback macht Sicherheitsupdates effektiv **rückgängig** und stellt zuvor geschlossene Kernel- und System-Schwachstellen wieder her. Dies ist eine der gefährlichsten möglichen Operationen auf modernen macOS-Systemen.

#### Ersetzen von System-Binärdateien

Mit einem SIP bypass + SSV write capability kann ein Angreifer:

1. Das Systemvolume read-write mounten
2. Einen System-Daemon oder eine Framework-Bibliothek durch eine trojanisierte Version ersetzen
3. Den Snapshot erneut versiegeln (oder das beschädigte Siegel akzeptieren, wenn SIP bereits beeinträchtigt ist)
4. Das Rootkit bleibt über Neustarts hinweg bestehen und ist für Userland-Detection-Tools unsichtbar

### CVEs aus der Praxis

| CVE | Beschreibung |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP bypass durch Missbrauch des Entitlements `com.apple.rootless.install.heritable` von `system_installd`, um beliebige post-install scripts auszuführen ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP bypass: `system_installd` legte das post-install script in einem SIP-geschützten Ordner unter `/tmp` ab. `/tmp` selbst ist jedoch nicht SIP-geschützt, sodass der Ordner durch das Mounten eines Images darüber ausgetauscht werden konnte ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — Copy-on-Write-Race in XNU, die Schreibzugriffe auf schreibgeschützte Dateien im Besitz von root ermöglicht ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Grundlegende Informationen

**DataVault** ist Apples Schutzschicht für sensible Systemdatenbanken. Selbst **root kann nicht auf durch DataVault geschützte Dateien zugreifen** — nur Prozesse mit spezifischen Entitlements können sie lesen oder ändern.<sup>[[4]](#references)</sup> Zu den geschützten Stores gehören:

| Geschützte Datenbank | Pfad | Inhalt |
|---|---|---|
| TCC (system) | `/Library/Application Support/com.apple.TCC/TCC.db` | Systemweite TCC-Datenschutzentscheidungen |
| TCC (user) | `~/Library/Application Support/com.apple.TCC/TCC.db` | TCC-Datenschutzentscheidungen pro Benutzer |
| Keychain (system) | `/Library/Keychains/System.keychain` | System-Keychain |
| Keychain (user) | `~/Library/Keychains/login.keychain-db` | Benutzer-Keychain |

Der DataVault-Schutz wird auf **Dateisystemebene** mithilfe erweiterter Attribute und Volume-Schutz-Flags durchgesetzt und vom Kernel überprüft.

### DataVault-Controller-Entitlements
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

Wenn ein Angreifer eine DataVault-Controller-Binärdatei kompromittiert (z. B. durch code injection in einen Prozess mit `com.apple.private.tcc.manager`), kann er die **TCC-Datenbank direkt ändern**, um jeder Anwendung beliebige TCC-Berechtigungen zu erteilen:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Die Änderung der TCC-Datenbank ist der **ultimative Privacy-Bypass** – sie gewährt jede Berechtigung stillschweigend, ohne Benutzerabfrage oder sichtbaren Hinweis. In der Vergangenheit endeten mehrere macOS-Privilege-Escalation-Ketten mit Schreibzugriffen auf die TCC-Datenbank als abschließendem Payload.

#### Zugriff auf die Keychain-Datenbank

DataVault schützt auch die Backing-Dateien der Keychain. Ein kompromittierter DataVault-Controller kann:

1. Die rohen Keychain-Datenbankdateien lesen
2. Verschlüsselte Keychain-Elemente extrahieren
3. Eine Offline-Entschlüsselung mit dem Passwort des Benutzers oder wiederhergestellten Schlüsseln versuchen

### CVEs aus der Praxis im Zusammenhang mit DataVault-/TCC-Bypass

| CVE | Beschreibung |
|---|---|
| CVE-2024-44131 | FileProvider-Symlink-Race, durch die ein privilegierter Helper auf TCC-geschützte Daten zugreifen konnte ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Als root **einen neuen Benutzer erstellen, dessen `NFSHomeDirectory` auf eine vom Angreifer kontrollierte `TCC.db` verweist**; beim Login verarbeitet `tccd` diese Datei und die Grants werden angewendet, wodurch auf die Daten anderer Benutzer zugegriffen werden kann ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | „powerdir“: Ändern des Home-Verzeichnisses des Benutzers, um eine vom Angreifer kontrollierte TCC.db zu platzieren ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Fehler bei der Bundle-Konklusion, durch den eine App **die TCC-Grants eines Donor-Bundles ohne Abfrage erben konnte**; in freier Wildbahn von **XCSSET** ausgenutzt, um den Desktop zu screenen ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` erstellte den DB-Pfad aus `$HOME`, sodass `launchctl setenv HOME` ihn auf eine vom Angreifer kontrollierte `TCC.db` umleiten konnte ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` besaß `com.apple.private.tcc.manager` **und** hatte die Library-Validation deaktiviert, sodass ein in `/Library/Audio/Plug-Ins/HAL` abgelegtes HAL-Plug-in beliebige TCC-Rechte gewähren konnte ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |

## Referenzen

- [1] [Microsoft findet eine neue macOS-Schwachstelle namens Shrootless, die den System Integrity Protection umgehen könnte](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technische Analyse: CVE-2022-22583 – Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow – Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security – Data Protection](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs – CVE-2024-44131: TCC-Bypass stiehlt Daten aus iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji – Aufdeckung von macOS-Malware: TCC-Bypass](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Neue macOS-Schwachstelle „powerdir“ könnte zu unbefugtem Zugriff auf Benutzerdaten führen](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day-TCC-Bypass in XCSSET-Malware entdeckt](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Umgehung des macOS-Frameworks für Transparenz, Zustimmung und Kontrolle (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Musik abspielen und TCC umgehen, auch bekannt als CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Der Albtraum der Apple-OTA-Updates (APFS-Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See – TCC-Exploitation](https://objective-see.org/blog/blog_0x4C.html)

{{#include ../../../banners/hacktricks-training.md}}
