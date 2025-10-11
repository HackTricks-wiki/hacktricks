# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Możesz być w stanie eskalować uprawnienia, nadużywając tokenów, które już posiadasz**

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

To uprawnienie powoduje nadanie pełnych praw odczytu do dowolnego pliku (ograniczone do operacji odczytu). Wykorzystuje się je do odczytu hashy haseł kont lokalnych Administratorów z rejestru, po czym można użyć narzędzi takich jak **psexec** czy **wmiexec** z hashem (technika **Pass-the-Hash**). Jednak ta metoda zawodzi w dwóch przypadkach: gdy konto Local Administrator jest wyłączone albo gdy obowiązuje polityka usuwająca prawa administracyjne z Local Administrators łączących się zdalnie.\
Możesz **nadużyć tego uprawnienia** za pomocą:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

To uprawnienie daje prawo zapisu do dowolnego pliku systemowego, niezależnie od Access Control List (ACL). Otwiera to wiele możliwości eskalacji, w tym modyfikację usług, przeprowadzenie **DLL Hijacking** oraz ustawienie debuggerów za pomocą **Image File Execution Options**, jak również inne techniki.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege to potężne uprawnienie, szczególnie przydatne, gdy użytkownik ma możliwość impersonacji tokenów, ale także gdy brakuje SeImpersonatePrivilege. Ta możliwość opiera się na zdolności do impersonowania tokenu, który reprezentuje tego samego użytkownika i którego integrity level nie przekracza integrity level bieżącego procesu.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** Można wykorzystać SeCreateTokenPrivilege do EoP przez impersonację tokenów w określonych warunkach.
- **Conditions for Token Impersonation:** Udana impersonacja wymaga, by docelowy token należał do tego samego użytkownika i miał integrity level mniejszy bądź równy integrity level procesu próbującego impersonacji.
- **Creation and Modification of Impersonation Tokens:** Użytkownicy mogą stworzyć impersonation token i rozszerzyć go, dodając SID uprzywilejowanej grupy (Security Identifier).

### SeLoadDriverPrivilege

To uprawnienie pozwala na ładowanie i odładowywanie sterowników urządzeń poprzez utworzenie wpisu w rejestrze z konkretnymi wartościami dla `ImagePath` i `Type`. Ponieważ bezpośredni zapis do `HKLM` (HKEY_LOCAL_MACHINE) jest ograniczony, należy użyć `HKCU` (HKEY_CURRENT_USER). Jednak aby kernel rozpoznał `HKCU` przy konfiguracji sterownika, trzeba zastosować konkretną ścieżkę.

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
Więcej sposobów nadużycia tego uprawnienia w [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Jest to podobne do **SeRestorePrivilege**. Jego główną funkcją jest umożliwienie procesowi **przejęcia własności obiektu**, omijając wymóg jawnego dostępu dyskrecjonalnego poprzez przyznanie praw dostępu WRITE_OWNER. Proces polega najpierw na zabezpieczeniu własności docelowego klucza rejestru w celu zapisu, a następnie na zmianie DACL, aby umożliwić operacje zapisu.
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

To uprawnienie pozwala na **debug other processes**, w tym na odczyt i zapis w pamięci. Za jego pomocą można zastosować różne strategie wstrzykiwania do pamięci, które potrafią ominąć większość programów antywirusowych oraz rozwiązań Host Intrusion Prevention.

#### Zrzut pamięci

Możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) aby **przechwycić pamięć procesu**. Konkretne zastosowanie dotyczy procesu **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, który odpowiada za przechowywanie poświadczeń użytkownika po pomyślnym zalogowaniu do systemu.

Następnie możesz załadować ten zrzut do mimikatz, aby uzyskać hasła:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Jeśli chcesz uzyskać `NT SYSTEM` shell, możesz użyć:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

To prawo (Perform volume maintenance tasks) umożliwia otwarcie surowych uchwytów urządzeń woluminów (np. \\.\C:) do bezpośrednich operacji I/O dysku, które omijają NTFS ACLs. Dzięki temu można skopiować bajty dowolnego pliku na woluminie poprzez odczyt bloków znajdujących się pod nim, umożliwiając odczyt plików zawierających wrażliwe dane (np. klucze prywatne maszyny w %ProgramData%\Microsoft\Crypto\, hive'y rejestru, SAM/NTDS poprzez VSS). Jest to szczególnie istotne na CA servers, gdzie wykradzenie prywatnego klucza CA umożliwia sfałszowanie Golden Certificate i podszycie się pod dowolny principal.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Sprawdź uprawnienia
```
whoami /priv
```
Te **tokens, które pojawiają się jako Wyłączone**, mogą zostać włączone — można nadużywać zarówno _Włączonych_, jak i _Wyłączonych_ tokens.

### Włącz wszystkie tokens

Jeśli jakieś tokens są wyłączone, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) aby włączyć wszystkie tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Lub **skrypt** osadzony w tym [**poście**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Pełny cheatsheet uprawnień tokenów na [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), poniższe podsumowanie wymienia tylko bezpośrednie sposoby wykorzystania uprawnienia do uzyskania sesji administratora lub odczytu wrażliwych plików.

| Privilege                  | Wpływ       | Narzędzie               | Ścieżka wykonania                                                                                                                                                                                                                                                                                                                                 | Uwagi                                                                                                                                                                                                                                                                                                                           |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Administrator**_ | narzędzie zewnętrzne    | _"Pozwoliłoby użytkownikowi na impersonację tokenów i privesc do nt system przy użyciu narzędzi takich jak potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                           | Dziękuję [Aurélien Chalot](https://twitter.com/Defte_) za aktualizację. Postaram się wkrótce sformułować to w bardziej receptowym stylu.                                                                                                                                                                                         |
| **`SeBackup`**             | **Zagrożenie**  | _**wbudowane polecenia**_ | Odczytuj wrażliwe pliki za pomocą `robocopy /b`                                                                                                                                                                                                                                                                                                    | <p>- Może być ciekawsze, jeśli możesz odczytać %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (i robocopy) nie pomaga w przypadku plików otwartych.<br><br>- Robocopy wymaga obu uprawnień SeBackup i SeRestore, aby działać z parametrem /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Administrator**_ | narzędzie zewnętrzne    | Utwórz dowolny token, w tym prawa lokalnego administratora, za pomocą `NtCreateToken`.                                                                                                                                                                                                                                                              |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Administrator**_ | **PowerShell**          | Zduplikuj token `lsass.exe`.                                                                                                                                                                                                                                                                                                                       | Skrypt można znaleźć na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Administrator**_ | narzędzie zewnętrzne    | <p>1. Załaduj wadliwy sterownik jądra taki jak <code>szkg64.sys</code><br>2. Wykorzystaj lukę w sterowniku<br><br>Alternatywnie uprawnienie może być użyte do odładowania sterowników związanych z bezpieczeństwem za pomocą wbudowanego polecenia <code>ftlMC</code>. i.e.: <code>fltMC sysmondrv</code></p> | <p>1. Luka <code>szkg64</code> jest wymieniona jako <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Kod exploita dla <code>szkg64</code> został stworzony przez <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Administrator**_ | **PowerShell**          | <p>1. Uruchom PowerShell/ISE z obecnym uprawnieniem SeRestore.<br>2. Włącz uprawnienie za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Zmień nazwę utilman.exe na utilman.old<br>4. Zmień nazwę cmd.exe na utilman.exe<br>5. Zablokuj konsolę i naciśnij Win+U</p> | <p>Atak może zostać wykryty przez niektóre programy AV.</p><p>Alternatywna metoda polega na zastąpieniu plików binarnych usług przechowywanych w "Program Files" przy użyciu tego samego uprawnienia</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Administrator**_ | _**wbudowane polecenia**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmień nazwę cmd.exe na utilman.exe<br>4. Zablokuj konsolę i naciśnij Win+U</p>                                                                                                                                       | <p>Atak może zostać wykryty przez niektóre programy AV.</p><p>Alternatywna metoda polega na zastąpieniu plików binarnych usług przechowywanych w "Program Files" przy użyciu tego samego uprawnienia.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Administrator**_ | narzędzie zewnętrzne    | <p>Manipuluj tokenami, aby zawierały prawa lokalnego administratora. Może wymagać SeImpersonate.</p><p>Do potwierdzenia.</p>                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                |

## Odniesienia

- Zobacz tę tabelę definiującą tokeny Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Zobacz [**ten artykuł**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) o privesc z użyciem tokenów.
- Microsoft – Wykonywanie zadań konserwacji woluminów (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
