# Missbrauch von Tokens

{{#include ../../../banners/hacktricks-training.md}}

## Tokens

Wenn Sie **nicht wissen, was Windows Access Tokens sind**, lesen Sie diese Seite, bevor Sie fortfahren:

{{#ref}}
../access-tokens.md
{{#endref}}

**Vielleicht könnten Sie in der Lage sein, Privilegien durch den Missbrauch der Tokens, die Sie bereits haben, zu eskalieren.**

### SeImpersonatePrivilege

Dies ist ein Privileg, das von jedem Prozess gehalten wird und die Impersonation (aber nicht die Erstellung) eines Tokens ermöglicht, vorausgesetzt, ein Handle dafür kann erlangt werden. Ein privilegiertes Token kann von einem Windows-Dienst (DCOM) erworben werden, indem man ihn dazu bringt, eine NTLM-Authentifizierung gegen einen Exploit durchzuführen, was anschließend die Ausführung eines Prozesses mit SYSTEM-Privilegien ermöglicht. Diese Schwachstelle kann mit verschiedenen Tools ausgenutzt werden, wie [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (was erfordert, dass winrm deaktiviert ist), [SweetPotato](https://github.com/CCob/SweetPotato), [EfsPotato](https://github.com/zcgonvh/EfsPotato), [DCOMPotato](https://github.com/zcgonvh/DCOMPotato) und [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{{#ref}}
../roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
../juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Es ist sehr ähnlich zu **SeImpersonatePrivilege**, es wird die **gleiche Methode** verwendet, um ein privilegiertes Token zu erhalten.\
Dann ermöglicht dieses Privileg **das Zuweisen eines primären Tokens** zu einem neuen/ausgesetzten Prozess. Mit dem privilegierten Impersonation-Token können Sie ein primäres Token ableiten (DuplicateTokenEx).\
Mit dem Token können Sie einen **neuen Prozess** mit 'CreateProcessAsUser' erstellen oder einen Prozess aussetzen und **das Token setzen** (im Allgemeinen können Sie das primäre Token eines laufenden Prozesses nicht ändern).

### SeTcbPrivilege

Wenn Sie dieses Token aktiviert haben, können Sie **KERB_S4U_LOGON** verwenden, um ein **Impersonation-Token** für jeden anderen Benutzer zu erhalten, ohne die Anmeldeinformationen zu kennen, **eine beliebige Gruppe** (Admins) zum Token hinzuzufügen, das **Integritätslevel** des Tokens auf "**medium**" zu setzen und dieses Token dem **aktuellen Thread** zuzuweisen (SetThreadToken).

### SeBackupPrivilege

Das System wird durch dieses Privileg dazu veranlasst, **alle Lesezugriffs**kontrollen auf jede Datei (beschränkt auf Leseoperationen) zu gewähren. Es wird verwendet, um **die Passwort-Hashes von lokalen Administrator**konten aus der Registrierung zu lesen, wonach Tools wie "**psexec**" oder "**wmiexec**" mit dem Hash (Pass-the-Hash-Technik) verwendet werden können. Diese Technik schlägt jedoch unter zwei Bedingungen fehl: wenn das lokale Administratorkonto deaktiviert ist oder wenn eine Richtlinie besteht, die den lokalen Administratoren, die sich remote verbinden, die administrativen Rechte entzieht.\
Sie können **dieses Privileg missbrauchen** mit:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- folge **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Oder wie im Abschnitt **Privilegieneskalation mit Backup-Operatoren** erklärt:

{{#ref}}
../../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Dieses Privileg gewährt die Erlaubnis für **Schreibzugriff** auf jede Systemdatei, unabhängig von der Access Control List (ACL) der Datei. Es eröffnet zahlreiche Möglichkeiten zur Eskalation, einschließlich der Fähigkeit, **Dienste zu modifizieren**, DLL Hijacking durchzuführen und **Debugger** über die Image File Execution Options einzustellen, unter verschiedenen anderen Techniken.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege ist eine mächtige Berechtigung, die besonders nützlich ist, wenn ein Benutzer die Fähigkeit hat, Tokens zu impersonieren, aber auch in Abwesenheit von SeImpersonatePrivilege. Diese Fähigkeit hängt von der Möglichkeit ab, ein Token zu impersonieren, das denselben Benutzer repräsentiert und dessen Integritätslevel nicht höher ist als der des aktuellen Prozesses.

**Wichtige Punkte:**

- **Impersonation ohne SeImpersonatePrivilege:** Es ist möglich, SeCreateTokenPrivilege für EoP zu nutzen, indem Tokens unter bestimmten Bedingungen impersoniert werden.
- **Bedingungen für die Token-Impersonation:** Erfolgreiche Impersonation erfordert, dass das Ziel-Token demselben Benutzer gehört und ein Integritätslevel hat, das kleiner oder gleich dem Integritätslevel des Prozesses ist, der die Impersonation versucht.
- **Erstellung und Modifikation von Impersonation-Tokens:** Benutzer können ein Impersonation-Token erstellen und es verbessern, indem sie eine SID (Security Identifier) einer privilegierten Gruppe hinzufügen.

### SeLoadDriverPrivilege

Dieses Privileg erlaubt es, **Gerätetreiber zu laden und zu entladen**, indem ein Registrierungseintrag mit spezifischen Werten für `ImagePath` und `Type` erstellt wird. Da der direkte Schreibzugriff auf `HKLM` (HKEY_LOCAL_MACHINE) eingeschränkt ist, muss stattdessen `HKCU` (HKEY_CURRENT_USER) verwendet werden. Um `HKCU` für die Kernel-Konfiguration von Treibern erkennbar zu machen, muss ein spezifischer Pfad eingehalten werden.

Dieser Pfad ist `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, wobei `<RID>` der Relative Identifier des aktuellen Benutzers ist. Innerhalb von `HKCU` muss dieser gesamte Pfad erstellt werden, und zwei Werte müssen gesetzt werden:

- `ImagePath`, das der Pfad zur auszuführenden Binärdatei ist
- `Type`, mit einem Wert von `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Schritte, die zu befolgen sind:**

1. Greifen Sie auf `HKCU` anstelle von `HKLM` zu, aufgrund des eingeschränkten Schreibzugriffs.
2. Erstellen Sie den Pfad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` innerhalb von `HKCU`, wobei `<RID>` den relativen Identifikator des aktuellen Benutzers darstellt.
3. Setzen Sie den `ImagePath` auf den Ausführungspfad der Binärdatei.
4. Weisen Sie den `Type` als `SERVICE_KERNEL_DRIVER` (`0x00000001`) zu.
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
Mehr Möglichkeiten, dieses Privileg auszunutzen in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dies ist ähnlich wie **SeRestorePrivilege**. Seine Hauptfunktion ermöglicht es einem Prozess, **das Eigentum an einem Objekt zu übernehmen**, wodurch die Anforderung für expliziten diskretionären Zugriff durch die Bereitstellung von WRITE_OWNER-Zugriffsrechten umgangen wird. Der Prozess umfasst zunächst die Sicherstellung des Eigentums an dem beabsichtigten Registrierungsschlüssel zu Schreibzwecken, gefolgt von der Änderung der DACL, um Schreibvorgänge zu ermöglichen.
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

Dieses Privileg erlaubt es, **andere Prozesse zu debuggen**, einschließlich das Lesen und Schreiben im Speicher. Verschiedene Strategien zur Speicherinjektion, die in der Lage sind, die meisten Antiviren- und Hostintrusionsschutzlösungen zu umgehen, können mit diesem Privileg eingesetzt werden.

#### Speicher dumpen

Sie können [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aus der [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) verwenden, um **den Speicher eines Prozesses zu erfassen**. Dies kann insbesondere für den Prozess **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))** gelten, der dafür verantwortlich ist, Benutzeranmeldeinformationen zu speichern, sobald ein Benutzer erfolgreich in ein System eingeloggt ist.

Sie können diesen Dump dann in mimikatz laden, um Passwörter zu erhalten:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Wenn Sie eine `NT SYSTEM`-Shell erhalten möchten, können Sie Folgendes verwenden:

- \***\*[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)\*\***
- \***\*[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)\*\***
- \***\*[**psgetsys.ps1 (Powershell-Skript)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)\*\***
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Das `SeManageVolumePrivilege` ist ein Windows-Benutzerrecht, das es Benutzern ermöglicht, Festplattenspeicher zu verwalten, einschließlich der Erstellung und Löschung von Volumes. Obwohl es für Administratoren gedacht ist, kann es, wenn es nicht-administrativen Benutzern gewährt wird, für eine Privilegieneskalation ausgenutzt werden.

Es ist möglich, dieses Privileg zu nutzen, um Volumes zu manipulieren, was zu vollem Zugriff auf das Volume führt. Der [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) kann verwendet werden, um allen Benutzern vollen Zugriff auf C:\ zu gewähren.

Darüber hinaus beschreibt der Prozess in [diesem Medium-Artikel](https://medium.com/@raphaeltzy13/exploiting-semanagevolumeprivilege-with-dll-hijacking-windows-privilege-escalation-1a4f28372d37) die Verwendung von DLL-Hijacking in Verbindung mit `SeManageVolumePrivilege`, um Privilegien zu eskalieren. Durch das Platzieren einer Payload-DLL `C:\Windows\System32\wbem\tzres.dll` und das Aufrufen von `systeminfo` wird die DLL ausgeführt.

## Überprüfen der Berechtigungen
```
whoami /priv
```
Die **Tokens, die als Deaktiviert erscheinen**, können aktiviert werden, Sie können tatsächlich _Aktivierte_ und _Deaktivierte_ Tokens ausnutzen.

### Alle Tokens aktivieren

Wenn Sie Tokens deaktiviert haben, können Sie das Skript [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) verwenden, um alle Tokens zu aktivieren:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Oder das **Skript** eingebettet in diesem [**Beitrag**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabelle

Vollständiges Token-Privilegien-Cheatsheet unter [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), die Zusammenfassung unten listet nur direkte Möglichkeiten auf, das Privileg auszunutzen, um eine Admin-Sitzung zu erhalten oder sensible Dateien zu lesen.

| Privileg                  | Auswirkung   | Tool                    | Ausführungspfad                                                                                                                                                                                                                                                                                                                                     | Bemerkungen                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ------------ | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Es würde einem Benutzer erlauben, Tokens zu impersonieren und Privilegien auf das NT-System mit Tools wie potato.exe, rottenpotato.exe und juicypotato.exe zu erhöhen"_                                                                                                                                                                      | Danke an [Aurélien Chalot](https://twitter.com/Defte_) für das Update. Ich werde versuchen, es bald in etwas Rezeptartiges umzuformulieren.                                                                                                                                                                                      |
| **`SeBackup`**             | **Bedrohung** | _**Eingebaute Befehle**_ | Sensible Dateien mit `robocopy /b` lesen                                                                                                                                                                                                                                                                                                             | <p>- Könnte interessanter sein, wenn Sie %WINDIR%\MEMORY.DMP lesen können<br><br>- <code>SeBackupPrivilege</code> (und robocopy) sind nicht hilfreich, wenn es um geöffnete Dateien geht.<br><br>- Robocopy benötigt sowohl SeBackup als auch SeRestore, um mit dem /b-Parameter zu arbeiten.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Erstellen Sie ein beliebiges Token, einschließlich lokaler Administratorrechte mit `NtCreateToken`.                                                                                                                                                                                                                                              |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplizieren Sie das Token von `lsass.exe`.                                                                                                                                                                                                                                                                                                           | Skript zu finden unter [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Laden Sie einen fehlerhaften Kernel-Treiber wie <code>szkg64.sys</code><br>2. Nutzen Sie die Treibersicherheitsanfälligkeit aus<br><br>Alternativ kann das Privileg verwendet werden, um sicherheitsrelevante Treiber mit dem <code>ftlMC</code> eingebauten Befehl zu entladen. d.h.: <code>fltMC sysmondrv</code></p> | <p>1. Die <code>szkg64</code> Sicherheitsanfälligkeit ist als <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> aufgeführt.<br>2. Der <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">Exploit-Code</a> wurde von <a href="https://twitter.com/parvezghh">Parvez Anwar</a> erstellt.</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Starten Sie PowerShell/ISE mit dem vorhandenen SeRestore-Privileg.<br>2. Aktivieren Sie das Privileg mit <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Benennen Sie utilman.exe in utilman.old um<br>4. Benennen Sie cmd.exe in utilman.exe um<br>5. Sperren Sie die Konsole und drücken Sie Win+U</p> | <p>Der Angriff kann von einiger AV-Software erkannt werden.</p><p>Die alternative Methode beruht auf dem Ersetzen von Dienstbinaries, die in "Program Files" gespeichert sind, unter Verwendung desselben Privilegs.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Eingebaute Befehle**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Benennen Sie cmd.exe in utilman.exe um<br>4. Sperren Sie die Konsole und drücken Sie Win+U</p>                                                                                                                                       | <p>Der Angriff kann von einiger AV-Software erkannt werden.</p><p>Die alternative Methode beruht auf dem Ersetzen von Dienstbinaries, die in "Program Files" gespeichert sind, unter Verwendung desselben Privilegs.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulieren Sie Tokens, um lokale Administratorrechte einzuschließen. Möglicherweise ist SeImpersonate erforderlich.</p><p>Zu überprüfen.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Referenz

- Werfen Sie einen Blick auf diese Tabelle, die Windows-Token definiert: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Werfen Sie einen Blick auf [**dieses Papier**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) über Privilegienerweiterung mit Tokens.

{{#include ../../../banners/hacktricks-training.md}}
