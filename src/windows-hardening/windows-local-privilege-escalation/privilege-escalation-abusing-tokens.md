# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Wenn du **nicht weißt, was Windows Access Tokens sind**, lies diese Seite, bevor du fortfährst:


{{#ref}}
access-tokens.md
{{#endref}}

**Vielleicht kannst du Privilegien eskalieren, indem du die tokens missbrauchst, die du bereits hast**

### SeImpersonatePrivilege

Dieses Privileg, das von jedem Prozess gehalten werden kann, erlaubt die impersonation (aber nicht die Erstellung) eines beliebigen Tokens, sofern ein Handle darauf erlangt werden kann. Ein privilegiertes Token kann von einem Windows-Dienst (DCOM) erlangt werden, indem man ihn dazu bringt, eine NTLM-Authentifizierung gegen einen Exploit durchzuführen, wodurch anschließend die Ausführung eines Prozesses mit SYSTEM-Rechten ermöglicht wird. Diese Schwachstelle kann mit verschiedenen Tools ausgenutzt werden, wie z. B. [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (benötigt, dass winrm deaktiviert ist), [SweetPotato](https://github.com/CCob/SweetPotato) und [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Es ist sehr ähnlich zu **SeImpersonatePrivilege** und verwendet die **gleiche Methode**, um ein privilegiertes Token zu erhalten. Dieses Privileg erlaubt dann, ein primäres Token einem neuen/angehaltenen Prozess zuzuweisen. Mit dem privilegierten impersonation token kann man ein primäres Token ableiten (DuplicateTokenEx). Mit dem Token kann man einen **neuen Prozess** mit 'CreateProcessAsUser' erstellen oder einen Prozess angehalten starten und das Token **setzen** (im Allgemeinen kann man das primäre Token eines laufenden Prozesses nicht ändern).

### SeTcbPrivilege

Wenn du dieses Privileg aktiviert hast, kannst du **KERB_S4U_LOGON** nutzen, um ein **impersonation token** für jeden anderen Benutzer zu erhalten, ohne Anmeldeinformationen zu kennen, eine **beliebige Gruppe** (admins) zum Token hinzuzufügen, das **integrity level** des Tokens auf "**medium**" zu setzen und dieses Token dem **current thread** (SetThreadToken) zuzuweisen.

### SeBackupPrivilege

Dieses Privileg bewirkt, dass dem System vollständiger **Lesezugriff** auf jede Datei gewährt wird (auf Leseoperationen beschränkt). Es wird verwendet, um **die Passwort-Hashes von Local Administrator** Accounts aus der Registry zu lesen, wonach Tools wie "**psexec**" oder "**wmiexec**" mit dem Hash (Pass-the-Hash technique) verwendet werden können. Diese Technik schlägt jedoch in zwei Fällen fehl: wenn das Local Administrator account deaktiviert ist, oder wenn eine Richtlinie vorhanden ist, die administrative Rechte von Local Administrators bei Remote-Verbindungen entfernt.\
Du kannst **dieses Privileg missbrauchen** mit:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Dieses Privileg gewährt **Schreibzugriff** auf beliebige Systemdateien, unabhängig von der Access Control List (ACL) der Datei. Es eröffnet zahlreiche Eskalationsmöglichkeiten, einschließlich der Möglichkeit, **Dienste zu modifizieren**, DLL Hijacking durchzuführen und **Debugger** über Image File Execution Options zu setzen, neben verschiedenen anderen Techniken.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ist eine mächtige Berechtigung, besonders nützlich, wenn ein Benutzer die Fähigkeit besitzt, tokens zu impersonieren, aber auch ohne SeImpersonatePrivilege. Diese Fähigkeit beruht darauf, ein Token zu impersonieren, das denselben Benutzer repräsentiert und dessen integrity level den des aktuellen Prozesses nicht überschreitet.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Es ist möglich, SeCreateTokenPrivilege für EoP auszunutzen, indem tokens unter bestimmten Bedingungen impersoniert werden.
- **Conditions for Token Impersonation:** Erfolgreiche Impersonation erfordert, dass das Zieltoken zum selben Benutzer gehört und ein integrity level hat, das kleiner oder gleich dem integrity level des Prozesses ist, der die Impersonation versucht.
- **Creation and Modification of Impersonation Tokens:** Benutzer können ein impersonation token erstellen und es erweitern, indem sie die SID (Security Identifier) einer privilegierten Gruppe hinzufügen.

### SeLoadDriverPrivilege

Dieses Privileg erlaubt das **Laden und Entladen von Gerätetreibern**, indem ein Registry-Eintrag mit spezifischen Werten für `ImagePath` und `Type` erstellt wird. Da direkter Schreibzugriff auf `HKLM` (HKEY_LOCAL_MACHINE) eingeschränkt ist, muss stattdessen `HKCU` (HKEY_CURRENT_USER) verwendet werden. Um jedoch `HKCU` für den Kernel zur Driver-Konfiguration erkennbar zu machen, muss ein spezifischer Pfad befolgt werden.

Dieser Pfad ist `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, wobei `<RID>` die Relative Identifier des aktuellen Benutzers ist. Innerhalb von `HKCU` muss dieser komplette Pfad erstellt werden und zwei Werte gesetzt werden:

- `ImagePath`, der Pfad zur auszuführenden Binary
- `Type`, mit dem Wert `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Schritte zum Befolgen:**

1. Greife auf `HKCU` statt `HKLM` zu, aufgrund der eingeschränkten Schreibrechte.
2. Erstelle den Pfad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` innerhalb von `HKCU`, wobei `<RID>` die Relative Identifier des aktuellen Benutzers repräsentiert.
3. Setze `ImagePath` auf den Ausführungspfad der Binary.
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
Weitere Möglichkeiten, dieses Privileg zu missbrauchen in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dies ist ähnlich wie **SeRestorePrivilege**. Seine Hauptfunktion erlaubt es einem Prozess, **den Besitz eines Objekts zu übernehmen**, wodurch die Notwendigkeit einer expliziten diskretionären Zugriffsberechtigung umgangen wird, indem WRITE_OWNER-Zugriffsrechte vergeben werden. Der Vorgang besteht darin, zunächst den Besitz des vorgesehenen Registry-Schlüssels für Schreibzwecke zu übernehmen und anschließend die DACL zu ändern, um Schreiboperationen zu ermöglichen.
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

Dieses Privileg erlaubt das **debug other processes**, einschließlich Lese- und Schreibzugriff auf den Speicher. Mit diesem Privileg können verschiedene Strategien zur memory injection eingesetzt werden, die die meisten Antivirus- und Host-Intrusion-Prevention-Lösungen umgehen können.

#### Dump memory

Sie können [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aus der [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) verwenden, um **capture the memory of a process**. Konkret kann dies auf den Prozess **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** angewendet werden, der dafür verantwortlich ist, Benutzeranmeldeinformationen zu speichern, sobald sich ein Benutzer erfolgreich an einem System angemeldet hat.

Sie können diesen dump dann in mimikatz laden, um Passwörter zu erhalten:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Wenn du eine `NT SYSTEM` Shell erhalten möchtest, kannst du Folgendes verwenden:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Dieses Recht (Perform volume maintenance tasks) erlaubt das Öffnen von raw volume device handles (z. B. \\.\C:) für direkten Disk-I/O, der NTFS ACLs umgeht. Damit lassen sich die Bytes beliebiger Dateien auf dem Volume kopieren, indem die zugrunde liegenden Blöcke gelesen werden — wodurch arbitrary file read sensibler Informationen möglich wird (z. B. machine private keys in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Auf CA servers ist das besonders schwerwiegend, denn das exfiltrating des CA private key ermöglicht das Forging eines Golden Certificate, um any principal zu impersonate.

Siehe detaillierte Techniken und Gegenmaßnahmen:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Privilegien prüfen
```
whoami /priv
```
Die **tokens, die als Disabled angezeigt werden**, können aktiviert werden; du kannst tatsächlich _Enabled_ und _Disabled_ tokens ausnutzen.

### Alle Tokens aktivieren

Wenn du Tokens deaktiviert hast, kannst du das Skript [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) verwenden, um alle Tokens zu aktivieren:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oder das **script**, eingebettet in diesen [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabelle

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), die folgende Zusammenfassung listet nur direkte Wege auf, um das Privileg auszunutzen, um eine Admin-Sitzung zu erhalten oder sensitive Dateien zu lesen.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Es würde einem Benutzer erlauben, Tokens zu impersonieren und privesc zum nt system durchzuführen, unter Verwendung von Tools wie potato.exe, rottenpotato.exe und juicypotato.exe."_                                                                                                                                                              | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Bedrohung**  | _**Built-in commands**_ | Mit `robocopy /b` sensible Dateien lesen                                                                                                                                                                                                                                                                                                          | <p>- Könnte interessanter sein, wenn Sie %WINDIR%\MEMORY.DMP lesen können<br><br>- <code>SeBackupPrivilege</code> (und robocopy) ist nicht hilfreich bei offenen Dateien.<br><br>- Robocopy erfordert sowohl SeBackup als auch SeRestore, um mit dem /b-Parameter zu funktionieren.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Beliebigen Token erstellen, inklusive lokaler Admin-Rechte, mit `NtCreateToken`.                                                                                                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Das Token von `lsass.exe` duplizieren.                                                                                                                                                                                                                                                                                                            | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Lade einen fehlerhaften Kernel-Treiber wie <code>szkg64.sys</code><br>2. Exploitiere die Treiber-Schwachstelle<br><br>Alternativ kann das Privileg verwendet werden, um sicherheitsrelevante Treiber mit dem eingebauten Befehl <code>ftlMC</code> zu entladen. z.B.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Die <code>szkg64</code>-Schwachstelle ist gelistet als <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Der <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> wurde erstellt von <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Starte PowerShell/ISE mit vorhandenem SeRestore-Privileg.<br>2. Aktiviere das Privileg mit <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Benenne utilman.exe in utilman.old um<br>4. Benenne cmd.exe in utilman.exe um<br>5. Sperre die Konsole und drücke Win+U</p> | <p>Angriff kann von einigen AV-Programmen erkannt werden.</p><p>Alternative Methode basiert auf dem Ersetzen von Service-Binaries, die in "Program Files" gespeichert sind, unter Verwendung desselben Privilegs</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Benenne cmd.exe in utilman.exe um<br>4. Sperre die Konsole und drücke Win+U</p>                                                                                                                                       | <p>Angriff kann von einigen AV-Programmen erkannt werden.</p><p>Alternative Methode basiert auf dem Ersetzen von Service-Binaries, die in "Program Files" gespeichert sind, unter Verwendung desselben Privilegs.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Token manipulieren, um lokale Admin-Rechte einzuschließen. Kann SeImpersonate erfordern.</p><p>Noch zu verifizieren.</p>                                                                                                                                                                                                                       |                                                                                                                                                                                                                                                                                                                                |

## Referenz

- Siehe diese Tabelle, die Windows-Tokens definiert: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Siehe [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) über privesc mit tokens.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
