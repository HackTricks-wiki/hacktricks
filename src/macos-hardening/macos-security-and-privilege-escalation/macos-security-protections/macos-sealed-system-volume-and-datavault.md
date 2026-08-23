# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Grundlegende Informationen

Seit **macOS Big Sur (11.0)** wird das Systemvolume mithilfe eines kryptografisch versiegelten **APFS-Snapshot-Hashbaums** geschützt. Dies wird als **Sealed System Volume (SSV)** bezeichnet. Die Systempartition wird **schreibgeschützt** eingehängt, und jede Änderung bricht die Versiegelung, was während des Bootvorgangs überprüft wird.<sup>[[11]](#references)</sup>

Das SSV bietet:
- **Manipulationserkennung** — jede Änderung an System-Binaries oder Frameworks verändert die Wurzel des Merkle-Baums und macht die von Apple signierte Versiegelung ungültig
- **Authentifizierung während des Bootvorgangs** — die Boot-Kette überprüft den ausgewählten System-Snapshot, bevor dieser zum Root-Dateisystem wird
- **Rootkit-Resistenz** — selbst root kann Dateien im authentifizierten System-Snapshot nicht dauerhaft ersetzen, ohne authenticated root zu deaktivieren oder einen autorisierten Update-Pfad zu kompromittieren

Das SSV schützt das **System**-Volume, nicht das beschreibbare **Data**-Volume, das ihm zugeordnet ist. Firmlinks führen beide Volumes in dem unter `/` sichtbaren Namespace zusammen. Daher beweist ein scheinbar beschreibbarer Pfad nicht, dass das zugrunde liegende Objekt zum versiegelten Snapshot gehört. FileVault und Data Protection schützen die Vertraulichkeit ruhender Daten; sie sind vom SSV-Integritätsschutz getrennt.<sup>[[11]](#references)</sup>

### SSV-Status überprüfen
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
### Effektive Systemansicht: SSV + Cryptex-Grafts

Bei aktuellen macOS-Versionen stammt nicht jede unterhalb von `/System` sichtbare ausführbare Datei zwangsläufig aus dem gebooteten SSV-Snapshot. **Cryptexes** sind separat authentifizierte APFS-Disk-Images, deren Inhalt über ausgewählte Verzeichnisse gelegt wird. **Rapid Security Responses** können daher sicherheitsrelevante Komponenten ersetzen, ohne den Basis-SSV neu zu erstellen. Beim Triage von Persistence oder beim Diffing von Systemcode sollten daher die aktiven Mounts und der Preboot-Cryptex-Store inventarisiert werden, anstatt nur den Basis-Snapshot zu hashen:
```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```
Die Details zur Boot-Kette und zu Rapid Security Response werden unter [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses) behandelt; dieser Abschnitt konzentriert sich auf die SSV-Grenze selbst.

### SSV Writer-Entitlements

Bestimmte Apple-System-Binaries verfügen über Entitlements, die es ihnen ermöglichen, das Sealed System Volume zu ändern oder zu verwalten:

| Entitlement | Zweck |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Das System-Volume auf einen vorherigen Snapshot zurücksetzen |
| `com.apple.private.apfs.create-sealed-snapshot` | Nach Systemupdates einen neuen sealed Snapshot erstellen |
| `com.apple.rootless.install.heritable` | In SIP-geschützte Pfade schreiben (wird von untergeordneten Prozessen geerbt) |
| `com.apple.rootless.install` | In SIP-geschützte Pfade schreiben |

### SSV Writer finden
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

Wenn ein Angreifer ein Binary mit `com.apple.private.apfs.revert-to-snapshot` kompromittiert, kann er **das Systemvolume auf einen Zustand vor dem Update zurücksetzen** und bekannte Schwachstellen wiederherstellen:
```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```
> [!WARNING]
> Ein Snapshot-Rollback macht Sicherheitsupdates effektiv rückgängig und stellt zuvor gepatchte Kernel- und System-Schwachstellen wieder her. Dies ist einer der gefährlichsten möglichen Vorgänge auf modernen macOS-Systemen.

#### Ersetzen von System-Binaries

Mit einem SIP-Bypass und der Möglichkeit, auf dem SSV zu schreiben, kann ein Angreifer:

1. Das System-Volume mit Lese- und Schreibzugriff mounten
2. Einen System-Daemon oder eine Framework-Bibliothek durch eine trojanisierte Version ersetzen
3. Den Snapshot erneut versiegeln (oder das beschädigte Siegel akzeptieren, wenn SIP bereits beeinträchtigt ist)
4. Das Rootkit bleibt über Neustarts hinweg bestehen und ist für Userland-Erkennungstools unsichtbar

### Reale CVEs

| CVE | Beschreibung |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP-Bypass, der `system_installd`'s-Entitlement `com.apple.rootless.install.heritable` missbraucht, um beliebige Post-Install-Skripte auszuführen ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP-Bypass: `system_installd` legte das Post-Install-Skript in einem SIP-geschützten Ordner unter `/tmp` ab, aber `/tmp` selbst ist nicht SIP-geschützt, sodass der Ordner durch das Mounten eines Images darüber ausgetauscht werden konnte ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — Copy-on-Write-Race in XNU, die Schreibzugriffe auf schreibgeschützte, root-eigene Dateien ermöglicht ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Grundlegende Informationen

**DataVault** ist ein entitlement-gesteuerter Dateisystemschutz für vertrauliche Dateien und Verzeichnisse. Das BSD-Flag `UF_DATAVAULT` (`0x00000080`) kennzeichnet ein Objekt als zugriffsentitlementpflichtig für Lese- und Schreibzugriffe; anders als bei normalem DAC reicht es nicht aus, lediglich **root** zu werden oder Full Disk Access zu erhalten, solange der Schutz aktiv ist.<sup>[[4]](#references)[[13]](#references)</sup>

Verwende „DataVault“ nicht als Synonym für jede geschützte Datenbank. Die TCC-Datenbanken werden durch TCC/FDA und SIP-spezifische Richtlinien geregelt (siehe [macOS TCC](macos-tcc/README.md)), während der Zugriff auf Keychain-Elemente auch von Keychain-ACLs und kryptografischem Schutz abhängt (siehe [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Tatsächliche DataVault-Beispiele finden sich häufig in dienstbesitzenden Stores unter `/private/var/folders/.../0/`, etwa im Screen-Time-Store; das Flag ist in den BSD-Datei-Flags als `datavault` sichtbar, wenn der übergeordnete Ordner mit `stat` abgefragt werden kann.

### DataVault-Controller-Entitlements

| Entitlement | Grenze |
|---|---|
| `com.apple.rootless.datavault.controller` | Zugriff auf und Verwaltung von `UF_DATAVAULT`-Objekten<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | TCC-Entscheidungen verwalten; dies ist eine verwandte, aber separate Privacy-Grenze |
| `com.apple.private.tcc.allow` | Ausgewählte, im Entitlement-Wert angegebene TCC-Dienste umgehen |
| `com.apple.rootless.storage.TCC` | In den SIP-geschützten TCC-Store schreiben |

Ein Prozess, der ein DataVault-Controller-Entitlement mit FDA-, Backup-, Indexierungs- oder IPC-Funktionen kombiniert, ist besonders interessant: Suche nach einem Confused-Deputy-Primitive, das ein geschütztes Objekt in einen gewöhnlichen Pfad kopiert, anstatt zu versuchen, den Vault direkt zu öffnen.<sup>[[14]](#references)</sup>

### DataVault-Controller finden
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
### Angriffsszenarien

#### Direkte Änderung der TCC-Datenbank (separate TCC-Grenze)

Wenn ein Angreifer einen TCC-Manager-Prozess kompromittiert (z. B. durch Code injection in einen Prozess, der `com.apple.private.tcc.manager` enthält), kann er **die TCC-Datenbank direkt ändern**, um jeder Anwendung beliebige TCC-Berechtigungen zu erteilen:<sup>[[12]](#references)</sup>
```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```
> [!CAUTION]
> Die Änderung der TCC-Datenbank ist der **ultimative Privacy-Bypass** – sie gewährt jede Berechtigung stillschweigend, ohne Benutzerabfrage oder sichtbaren Hinweis. In der Vergangenheit endeten mehrere macOS-Privilege-Escalation-Ketten damit, dass das Schreiben in die TCC-Datenbank als abschließendes Payload ausgeführt wurde.

#### Zugriff auf die Keychain-Datenbank

Der direkte Zugriff auf eine zugrunde liegende Keychain-Datenbank ist nicht gleichbedeutend mit dem Zugriff auf Geheimnisse im Klartext. Wenn eine andere Privilege Boundary es einem Angreifer ermöglicht, die Datenbank zu kopieren, müssen Schlüsselmaterial und Item-ACLs weiterhin angegriffen werden. Siehe stattdessen die spezielle Seite zu [macOS Keychain](../../macos-red-teaming/macos-keychain.md), anstatt davon auszugehen, dass ein DataVault-Controller-Entitlement ausreicht.

#### Grenze von Backup-Kopien: Time Machine

Eine Analyse aus dem Jahr 2026 demonstrierte ein nützliches allgemeines Muster: `backupd` verfügt sowohl über `com.apple.rootless.datavault.controller` als auch über Full Disk Access, damit es geschützte Stores kopieren kann. In der getesteten Konfiguration war `/private/var/folders` in Time Machine enthalten, und die eingebundene Backup-Kopie setzte die aktive DataVault-Grenze nicht durch. Der Forscher nutzte dies, um den SQLite-Store von Screen Time zu lokalisieren und dessen PIN für Einschränkungen im Klartext zu lesen, ohne den aktiven Vault zu öffnen. Betrachte dies als **Copy-Boundary-Angriff**: Enumeriere Backup-, Export-, Migrations-, Indexierungs- und Diagnose-Stellvertreter, die Vault-Daten unter einem schwächeren Mount oder Pfad materialisieren können.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```
Dieses Verhalten hängt von der Version und dem Layout des Backups ab. Überprüfe es auf dem Ziel-Build und beachte, dass ein verschlüsseltes Time Machine-Ziel die Kopie nur schützt, solange es gesperrt ist; sobald es eingehängt wird, werden dessen Zugriffskontrollen Teil der Angriffsfläche.

### Reale CVEs im Zusammenhang mit DataVault/TCC-Umgehungen

| CVE | Beschreibung |
|---|---|
| CVE-2024-44131 | FileProvider-Symlink-Race, durch die ein privilegierter Helper auf durch TCC geschützte Daten zugreifen konnte ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Als root **einen neuen Benutzer erstellen, dessen `NFSHomeDirectory` auf eine vom Angreifer kontrollierte `TCC.db` zeigt**; bei der Anmeldung verwendet `tccd` diese Datei, und die Berechtigungen werden übernommen, wodurch auf die Daten anderer Benutzer zugegriffen werden kann ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | "powerdir": Das Home-Verzeichnis des Benutzers ändern, um eine vom Angreifer kontrollierte TCC.db zu platzieren ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Fehler bei der Bundle-Schlussfolgerung, durch den eine App **die TCC-Berechtigungen eines Spender-Bundles erben** konnte, ohne eine Abfrage auszulösen; wurde in freier Wildbahn von **XCSSET** ausgenutzt, um den Desktop per Screenshot aufzunehmen ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` erstellte den DB-Pfad aus `$HOME`, sodass `launchctl setenv HOME` ihn auf eine vom Angreifer kontrollierte `TCC.db` umleiten konnte ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` verfügte über `com.apple.private.tcc.manager` **und** hatte die Bibliotheksvalidierung deaktiviert, sodass ein in `/Library/Audio/Plug-Ins/HAL` abgelegtes HAL-Plug-in beliebige TCC-Berechtigungen erteilen konnte ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft entdeckt eine neue macOS-Schwachstelle namens Shrootless, die den System Integrity Protection umgehen könnte](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technische Analyse: CVE-2022-22583 - Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow - Es schlecht zu machen, ist besser als gar nichts zu tun](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Datenschutz](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs - CVE-2024-44131: TCC-Umgehung stiehlt Daten aus iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji - Aufdeckung von macOS-Malware: Umgehung von TCC](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Neue macOS-Schwachstelle "powerdir" könnte zu unbefugtem Zugriff auf Benutzerdaten führen](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day-TCC-Umgehung in XCSSET-Malware entdeckt](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Umgehung des macOS-Frameworks für Transparenz, Zustimmung und Kontrolle (TCC)](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Spiele die Musik ab und umgehe TCC, auch bekannt als CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Der Albtraum der Apple-OTA-Updates (APFS-Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC-Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [So umgehst du deinen eigenen Screen-Time-Code — Analyse von Quellcode und Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
