# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Vielleicht kannst du Privilegien eskalieren, indem du die Tokens, die du bereits hast, missbrauchst**

### SeImpersonatePrivilege

This is privilege that is held by any process allows the impersonation (but not creation) of any token, given that a handle to it can be obtained. A privileged token can be acquired from a Windows service (DCOM) by inducing it to perform NTLM authentication against an exploit, subsequently enabling the execution of a process with SYSTEM privileges. This vulnerability can be exploited using various tools, such as [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (which requires winrm to be disabled), [SweetPotato](https://github.com/CCob/SweetPotato), and [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

It is very similar to **SeImpersonatePrivilege**, it will use the **same method** to get a privileged token.\
Then, this privilege allows **to assign a primary token** to a new/suspended process. With the privileged impersonation token you can derivate a primary token (DuplicateTokenEx).\
With the token, you can create a **new process** with 'CreateProcessAsUser' or create a process suspended and **set the token** (in general, you cannot modify the primary token of a running process).

### SeTcbPrivilege

If you have enabled this token you can use **KERB_S4U_LOGON** to get an **impersonation token** for any other user without knowing the credentials, **add an arbitrary group** (admins) to the token, set the **integrity level** of the token to "**medium**", and assign this token to the **current thread** (SetThreadToken).

### SeBackupPrivilege

Dieses Privileg veranlasst das System, vollen Lesezugriff auf jede Datei zu gewähren (beschränkt auf Leseoperationen). Es wird genutzt, um die Passwort-Hashes lokaler Administrator-Konten aus der Registry zu lesen, wonach Tools wie "psexec" oder "wmiexec" mit dem Hash verwendet werden können (Pass-the-Hash-Technik). Diese Methode schlägt jedoch in zwei Fällen fehl: wenn das Local Administrator-Konto deaktiviert ist oder wenn eine Richtlinie vorhanden ist, die Administratorrechte von Local Administrators bei Remote-Verbindungen entfernt.\
Du kannst dieses Privileg ausnutzen mit:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Dieses Privileg gewährt Schreibzugriff auf jede Systemdatei, unabhängig von der Access Control List (ACL) der Datei. Es eröffnet viele Eskalationsmöglichkeiten, darunter Dienste zu ändern, DLL Hijacking durchzuführen und Debugger über Image File Execution Options zu setzen, sowie verschiedene andere Techniken.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ist ein mächtiges Recht, besonders nützlich, wenn ein Benutzer die Fähigkeit besitzt, Tokens zu impersonieren, aber auch ohne SeImpersonatePrivilege. Diese Fähigkeit hängt davon ab, ein Token zu impersonieren, das denselben Benutzer repräsentiert und dessen integrity level das des aktuellen Prozesses nicht übersteigt.

**Wichtige Punkte:**

- **Impersonation ohne SeImpersonatePrivilege:** Es ist möglich, SeCreateTokenPrivilege für EoP zu nutzen, indem man Tokens unter bestimmten Bedingungen impersoniert.
- **Bedingungen für Token-Impersonation:** Erfolgreiche Impersonation erfordert, dass das Zieltoken zum selben Benutzer gehört und ein integrity level hat, das kleiner oder gleich dem integrity level des Prozesses ist, der die Impersonation versucht.
- **Erstellung und Modifikation von Impersonation-Tokens:** Benutzer können ein impersonation token erstellen und es erweitern, indem sie die SID (Security Identifier) einer privilegierten Gruppe hinzufügen.

### SeLoadDriverPrivilege

This privilege allows to **load and unload device drivers** with the creation of a registry entry with specific values for `ImagePath` and `Type`. Since direct write access to `HKLM` (HKEY_LOCAL_MACHINE) is restricted, `HKCU` (HKEY_CURRENT_USER) must be utilized instead. However, to make `HKCU` recognizable to the kernel for driver configuration, a specific path must be followed.

This path is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, where `<RID>` is the Relative Identifier of the current user. Inside `HKCU`, this entire path must be created, and two values need to be set:

- `ImagePath`, which is the path to the binary to be executed
- `Type`, with a value of `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Access `HKCU` instead of `HKLM` due to restricted write access.
2. Create the path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` within `HKCU`, where `<RID>` represents the current user's Relative Identifier.
3. Set the `ImagePath` to the binary's execution path.
4. Assign the `Type` as `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
More ways to abuse this privilege in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Das ist ähnlich wie **SeRestorePrivilege**. Seine Hauptfunktion erlaubt es einem Prozess, die Eigentümerschaft eines Objekts zu übernehmen und damit die Notwendigkeit expliziter diskretionärer Zugriffsrechte zu umgehen, indem WRITE_OWNER-Zugriffsrechte vergeben werden. Der Vorgang besteht darin, zunächst die Eigentümerschaft des vorgesehenen registry key für Schreibzwecke zu erlangen und anschließend die DACL zu ändern, um Schreibzugriffe zu ermöglichen.
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

Dieses Privileg erlaubt das **debug other processes**, einschließlich des Lesens und Schreibens im Speicher. Verschiedene Strategien für memory injection, die die meisten antivirus- und host intrusion prevention solutions umgehen können, lassen sich mit diesem Privileg einsetzen.

#### Speicher auslesen

Sie können [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aus der [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) verwenden, um **den Speicher eines Prozesses zu erfassen**. Dies kann sich speziell auf den Prozess **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** beziehen, der dafür verantwortlich ist, Benutzeranmeldeinformationen zu speichern, nachdem sich ein Benutzer erfolgreich an einem System angemeldet hat.

Sie können diesen Dump dann in mimikatz laden, um Passwörter zu erhalten:
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

Dieses Recht (Perform volume maintenance tasks) erlaubt das Öffnen von rohen Volume-Geräte-Handles (z. B. \\.\C:) für direkten Festplatten-I/O, der NTFS ACLs umgeht. Damit können Sie die Bytes beliebiger Dateien auf dem Volume kopieren, indem Sie die zugrunde liegenden Blöcke lesen, was das beliebige Lesen von Dateien mit sensiblen Inhalten ermöglicht (z. B. private Maschinenschlüssel in %ProgramData%\Microsoft\Crypto\, Registry-Hives, SAM/NTDS via VSS). Dies ist besonders gravierend auf CA-Servern, wo das Exfiltrieren des CA-Private-Keys das Fälschen eines Golden Certificate ermöglicht, um sich als jeden Principal auszugeben.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Privilegien prüfen
```
whoami /priv
```
Die **tokens, die als Disabled angezeigt werden**, können aktiviert werden; tatsächlich kann man sowohl _Enabled_- als auch _Disabled_-tokens ausnutzen.

### Alle tokens aktivieren

Wenn du deaktivierte tokens hast, kannst du das script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) verwenden, um alle tokens zu aktivieren:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oder das in diesem [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) eingebettete **script**.

## Tabelle

Vollständiges Cheatsheet für Token-Privilegien unter [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), die folgende Zusammenfassung listet nur direkte Wege auf, das Privileg auszunutzen, um eine Admin-Sitzung zu erhalten oder sensible Dateien zu lesen.

| Privileg                   | Auswirkung  | Tool                    | Ausführungspfad                                                                                                                                                                                                                                                                                                                                     | Bemerkungen                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Tool eines Drittanbieters | _"Es würde einem Benutzer erlauben, Tokens zu impersonifizieren und privesc zum nt system durchzuführen, indem Tools wie potato.exe, rottenpotato.exe und juicypotato.exe verwendet werden"_                                                                                                                                              | Danke an [Aurélien Chalot](https://twitter.com/Defte_) für das Update. Ich werde versuchen, es bald etwas rezeptartig umzuformulieren.                                                                                                                                                                                         |
| **`SeBackup`**             | **Bedrohung**  | _**Built-in commands**_ | Sensible Dateien mit `robocopy /b` lesen.                                                                                                                                                                                                                                                                                                         | <p>- Kann interessanter sein, wenn Sie %WINDIR%\MEMORY.DMP lesen können<br><br>- <code>SeBackupPrivilege</code> (und robocopy) ist nicht hilfreich bei geöffneten Dateien.<br><br>- Robocopy benötigt sowohl SeBackup als auch SeRestore, um mit dem /b-Parameter zu funktionieren.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Tool eines Drittanbieters | Einen beliebigen Token erstellen, einschließlich lokaler Admin-Rechte, mit `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Den Token von `lsass.exe` duplizieren.                                                                                                                                                                                                                                                                                                                   | Script ist zu finden bei [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Tool eines Drittanbieters          | <p>1. Lade einen fehlerhaften Kernel-Treiber wie <code>szkg64.sys</code><br>2. Exploitiere die Treiberschwachstelle<br><br>Alternativ kann das Privileg verwendet werden, sicherheitsrelevante Treiber mit dem eingebauten Befehl <code>ftlMC</code> zu entladen. z. B.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Die <code>szkg64</code>-Schwachstelle ist als <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> gelistet<br>2. Der <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">Exploit-Code</a> wurde von <a href="https://twitter.com/parvezghh">Parvez Anwar</a> erstellt</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Starte PowerShell/ISE mit vorhandenem SeRestore-Privileg.<br>2. Aktiviere das Privileg mit <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> ).<br>3. Benenne utilman.exe in utilman.old um<br>4. Benenne cmd.exe in utilman.exe um<br>5. Sperre die Konsole und drücke Win+U</p> | <p>Angriff kann von einigen AV-Programmen erkannt werden.</p><p>Eine alternative Methode beruht darauf, Service-Binärdateien im Ordner "Program Files" mit demselben Privileg zu ersetzen</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Benenne cmd.exe in utilman.exe um<br>4. Sperre die Konsole und drücke Win+U</p>                                                                                                                                       | <p>Angriff kann von einigen AV-Programmen erkannt werden.</p><p>Alternative Methode beruht darauf, Service-Binärdateien im Ordner "Program Files" mit demselben Privileg zu ersetzen.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Tool eines Drittanbieters          | <p>Tokens manipulieren, um lokale Admin-Rechte einzuschließen. Kann SeImpersonate erfordern.</p><p>Zu verifizieren.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Referenz

- Siehe diese Tabelle, die Windows-Tokens definiert: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Siehe [**dieses Paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) über privesc mit tokens.
- Microsoft – Durchführung von Volume-Wartungsaufgaben (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Zertifikat (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
