# Nadużywanie tokenów

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Być może uda Ci się eskalować uprawnienia, nadużywając tokenów, które już posiadasz**

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

The system is caused to **grant all read access** control to any file (limited to read operations) by this privilege. It is utilized for **reading the password hashes of local Administrator** accounts from the registry, following which, tools like "**psexec**" or "**wmiexec**" can be used with the hash (Pass-the-Hash technique). However, this technique fails under two conditions: when the Local Administrator account is disabled, or when a policy is in place that removes administrative rights from Local Administrators connecting remotely.\
You can **abuse this privilege** with:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Permission for **write access** to any system file, irrespective of the file's Access Control List (ACL), is provided by this privilege. It opens up numerous possibilities for escalation, including the ability to **modify services**, perform DLL Hijacking, and set **debuggers** via Image File Execution Options among various other techniques.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is a powerful permission, especially useful when a user possesses the ability to impersonate tokens, but also in the absence of SeImpersonatePrivilege. This capability hinges on the ability to impersonate a token that represents the same user and whose integrity level does not exceed that of the current process.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** It's possible to leverage SeCreateTokenPrivilege for EoP by impersonating tokens under specific conditions.
- **Conditions for Token Impersonation:** Successful impersonation requires the target token to belong to the same user and have an integrity level that is less or equal to the integrity level of the process attempting impersonation.
- **Creation and Modification of Impersonation Tokens:** Users can create an impersonation token and enhance it by adding a privileged group's SID (Security Identifier).

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
Więcej sposobów nadużycia tego uprawnienia w [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Jest to podobne do **SeRestorePrivilege**. Jego główną funkcją jest umożliwienie procesowi **przejęcia własności obiektu**, omijając wymóg jawnego dostępu dyskrecjonalnego poprzez nadanie praw dostępu WRITE_OWNER. Proces polega najpierw na uzyskaniu własności docelowego klucza rejestru w celu zapisu, a następnie na zmianie DACL, aby umożliwić operacje zapisu.
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

Ten przywilej pozwala na **debug other processes**, w tym na odczyt i zapis w pamięci. Z tym przywilejem można zastosować różne strategie memory injection, zdolne do omijania większości rozwiązań antywirusowych i host intrusion prevention.

#### Zrzut pamięci

Możesz użyć [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) z [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), aby **przechwycić pamięć procesu**. Szczególnie może to dotyczyć procesu **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, który odpowiada za przechowywanie poświadczeń użytkownika po pomyślnym zalogowaniu do systemu.

Następnie możesz załadować ten zrzut do mimikatz, aby uzyskać hasła:
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

To prawo (Perform volume maintenance tasks) pozwala na otwieranie surowych uchwytów urządzeń woluminów (np. \\.\C:) w celu bezpośrednich operacji I/O na dysku, które omijają NTFS ACLs. Dzięki temu można skopiować bajty dowolnego pliku na woluminie poprzez odczytanie bloków fizycznych, co umożliwia dowolny odczyt plików zawierających wrażliwe dane (np. klucze prywatne maszyny w %ProgramData%\Microsoft\Crypto\, hivery rejestru, SAM/NTDS przez VSS). Ma to szczególne znaczenie na serwerach CA, gdzie wykradzenie klucza prywatnego CA pozwala na sfałszowanie Golden Certificate i podszycie się pod dowolny podmiot.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Sprawdź uprawnienia
```
whoami /priv
```
Te tokens, które pojawiają się jako **Disabled**, można włączyć — w praktyce można nadużyć zarówno _Enabled_, jak i _Disabled_ tokens.

### Włącz wszystkie tokens

Jeśli masz tokens Disabled, możesz użyć skryptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1), aby włączyć wszystkie tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Lub **skrypt** osadzony w tym [**poście**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Pełna ściąga uprawnień tokenów na https://github.com/gtworek/Priv2Admin, poniższe podsumowanie wymienia jedynie bezpośrednie sposoby wykorzystania uprawnienia do uzyskania admin session lub odczytania poufnych plików.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Administrator**_ | Narzędzie osób trzecich          | _"Pozwoliłoby użytkownikowi podszywać się pod tokeny i privesc do systemu NT używając narzędzi takich jak potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                      | Dziękuję [Aurélien Chalot](https://twitter.com/Defte_) za aktualizację. Postaram się wkrótce sformułować to w bardziej przepisowym stylu.                                                                                                                                                                                    |
| **`SeBackup`**             | **Zagrożenie**  | _**Wbudowane polecenia**_ | Odczytuj poufne pliki przy użyciu `robocopy /b`                                                                                                                                                                                                                                                                                                   | <p>- Może być bardziej interesujące, jeśli możesz odczytać %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (i robocopy) nie pomaga w przypadku otwartych plików.<br><br>- Robocopy wymaga zarówno SeBackup, jak i SeRestore, aby działać z parametrem /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Administrator**_ | Narzędzie osób trzecich          | Utwórz dowolny token, w tym z prawami lokalnego administratora, przy użyciu `NtCreateToken`.                                                                                                                                                                                                                                                      |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Administrator**_ | **PowerShell**          | Zduplikuj token procesu `lsass.exe`.                                                                                                                                                                                                                                                                                                               | Skrypt dostępny na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Administrator**_ | Narzędzie osób trzecich          | <p>1. Załaduj wadliwy sterownik jądra, taki jak <code>szkg64.sys</code><br>2. Wykorzystaj lukę w sterowniku<br><br>Alternatywnie uprawnienie może być użyte do odładowania sterowników związanych z bezpieczeństwem za pomocą wbudowanego polecenia <code>fltMC</code>, np.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Luka <code>szkg64</code> jest zarejestrowana jako <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Kod exploita <code>szkg64</code> został stworzony przez <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Administrator**_ | **PowerShell**          | <p>1. Uruchom PowerShell/ISE z obecnym uprawnieniem SeRestore.<br>2. Włącz uprawnienie za pomocą <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Zmień nazwę utilman.exe na utilman.old<br>4. Zmień nazwę cmd.exe na utilman.exe<br>5. Zablokuj konsolę i naciśnij Win+U</p> | <p>Atak może zostać wykryty przez niektóre oprogramowanie AV.</p><p>Alternatywna metoda polega na zastąpieniu binarek usług przechowywanych w "Program Files" używając tego samego uprawnienia</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Administrator**_ | _**Wbudowane polecenia**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Zmień nazwę cmd.exe na utilman.exe<br>4. Zablokuj konsolę i naciśnij Win+U</p>                                                                                                                                       | <p>Atak może zostać wykryty przez niektóre oprogramowanie AV.</p><p>Alternatywna metoda polega na zastąpieniu binarek usług przechowywanych w "Program Files" używając tego samego uprawnienia.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Administrator**_ | Narzędzie osób trzecich          | <p>Manipuluj tokenami, aby zawierały prawa lokalnego administratora. Może wymagać SeImpersonate.</p><p>Wymaga weryfikacji.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Referencje

- Sprawdź tę tabelę definiującą tokeny Windows: https://github.com/gtworek/Priv2Admin
- Zajrzyj do [**tego artykułu**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) o privesc z tokenami.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
