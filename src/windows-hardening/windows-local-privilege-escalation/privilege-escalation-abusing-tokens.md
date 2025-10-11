# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**이미 보유한 토큰을 악용해 권한을 상승시킬 수 있을지도 모릅니다**

### SeImpersonatePrivilege

이 권한은 프로세스가 토큰의 핸들을 얻을 수 있을 때 그 토큰을 impersonate(대리)할 수 있게 해줍니다(단, 생성은 불가). 윈도우 서비스(DCOM)를 이용해 서비스로 하여금 NTLM 인증을 공격지점으로 수행하게 하면, 권한 있는 토큰을 획득해 SYSTEM 권한으로 프로세스를 실행할 수 있습니다. 이 취약점은 [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm 비활성화 필요), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 등 여러 도구로 악용할 수 있습니다.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

**SeImpersonatePrivilege**와 매우 유사하며, 같은 방식으로 권한 있는 토큰을 획득합니다.\
그 다음 이 권한은 **새로운/정지된 프로세스에 primary token을 할당**할 수 있게 해줍니다. 권한 있는 impersonation 토큰으로부터 primary token을 파생(DuplicateTokenEx)할 수 있습니다.\
해당 토큰으로 'CreateProcessAsUser'로 **새 프로세스**를 생성하거나 프로세스를 suspended 상태로 만들고 **토큰을 설정**할 수 있습니다(일반적으로 실행 중인 프로세스의 primary token은 수정 불가).

### SeTcbPrivilege

이 권한이 활성화되어 있으면 **KERB_S4U_LOGON**을 사용해 자격 증명 없이 다른 사용자에 대한 **impersonation token**을 얻고, 토큰에 임의의 그룹(예: admins)을 **추가**하며, 토큰의 **integrity level**을 "**medium**"으로 설정하고 해당 토큰을 **현재 스레드**에 할당(SetThreadToken)할 수 있습니다.

### SeBackupPrivilege

이 권한은 시스템이 모든 파일에 대해 읽기 접근을 허용하도록 합니다(읽기 작업으로 제한). 레지스트리에서 로컬 Administrator 계정의 **비밀번호 해시를 읽는 데** 사용되며, 이후 해시를 이용해 "**psexec**"이나 "**wmiexec**" 같은 도구를 사용하는 Pass-the-Hash technique이 가능합니다. 다만 이 방법은 로컬 Administrator 계정이 비활성화되어 있거나 원격으로 접속하는 로컬 관리자에게 관리 권한을 제거하는 정책이 적용된 경우 실패합니다.\
이 권한은 다음으로 **악용**할 수 있습니다:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- IppSec의 다음 영상 참조: [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- 또는 다음 문서의 **escalating privileges with Backup Operators** 섹션 참고:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

이 권한은 파일의 ACL과 무관하게 모든 시스템 파일에 대한 **쓰기 접근** 권한을 제공합니다. 이를 통해 서비스 수정, DLL Hijacking 수행, Image File Execution Options를 통한 **debugger** 설정 등 다양한 권한 상승 방법이 가능합니다.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege는 강력한 권한으로, 사용자가 토큰을 impersonate할 수 있는 경우 특히 유용하며 SeImpersonatePrivilege가 없는 상황에서도 유용합니다. 이 기능은 동일한 사용자에 속하고 현재 프로세스의 integrity level을 초과하지 않는 토큰을 impersonate할 수 있는지에 달려 있습니다.

**핵심 포인트:**

- **SeImpersonatePrivilege 없이의 impersonation:** 특정 조건에서 SeCreateTokenPrivilege를 이용해 EoP를 수행할 수 있습니다.
- **토큰 impersonation의 조건:** 성공적인 impersonation은 대상 토큰이 동일한 사용자에 속하고 대상 토큰의 integrity level이 impersonation을 시도하는 프로세스의 integrity level보다 작거나 같아야 합니다.
- **Impersonation 토큰의 생성 및 수정:** 사용자는 impersonation 토큰을 생성하고 여기에 권한 있는 그룹의 SID(Security Identifier)를 추가해 권한을 향상시킬 수 있습니다.

### SeLoadDriverPrivilege

이 권한은 특정 `ImagePath`와 `Type` 값을 가진 레지스트리 항목을 생성하여 **디바이스 드라이버를 로드/언로드**할 수 있게 합니다. `HKLM`(HKEY_LOCAL_MACHINE)에 직접 쓰기 권한이 제한되어 있으므로 `HKCU`(HKEY_CURRENT_USER)를 사용해야 합니다. 다만 커널이 드라이버 설정을 인식하도록 `HKCU`에 특정 경로를 만들어야 합니다.

이 경로는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`이며, 여기서 `<RID>`는 현재 사용자의 Relative Identifier입니다. `HKCU` 내부에 이 전체 경로를 생성하고 다음 두 값을 설정해야 합니다:

- `ImagePath` — 실행할 바이너리의 경로
- `Type` — `SERVICE_KERNEL_DRIVER`(`0x00000001`) 값

**실행 단계:**

1. 쓰기 권한 제한 때문에 `HKLM` 대신 `HKCU`에 접근합니다.
2. `HKCU` 내에 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` 경로를 생성합니다(여기서 `<RID>`는 현재 사용자의 Relative Identifier).
3. `ImagePath`를 실행할 바이너리 경로로 설정합니다.
4. `Type`을 `SERVICE_KERNEL_DRIVER`(`0x00000001`)로 지정합니다.
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
이 권한을 남용하는 더 많은 방법은 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

이는 **SeRestorePrivilege**와 유사합니다. 주된 기능은 프로세스가 **객체의 소유권을 획득**할 수 있게 하여 WRITE_OWNER 접근 권한을 부여함으로써 명시적인 재량적 접근 요구를 우회하는 것입니다. 이 과정은 먼저 쓰기 용도로 대상 레지스트리 키의 소유권을 확보한 다음, 쓰기 작업을 가능하게 하기 위해 DACL을 변경하는 것으로 이루어집니다.
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

이 권한은 **debug other processes**를 허용하며, 프로세스의 메모리를 읽고 쓸 수 있게 합니다. 이 권한을 사용하면 대부분의 안티바이러스 및 호스트 침입 방지 솔루션을 회피할 수 있는 다양한 메모리 인젝션 기법을 적용할 수 있습니다.

#### 메모리 덤프

You could use [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) to **프로세스의 메모리를 캡처**할 수 있습니다. 특히, 이는 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 프로세스에 적용될 수 있으며, 이 프로세스는 사용자가 시스템에 성공적으로 로그인한 후 사용자 자격증명을 저장하는 역할을 합니다.

You can then load this dump in mimikatz to obtain passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` 셸을 얻고 싶다면 다음을 사용할 수 있습니다:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

이 권한(Perform volume maintenance tasks)은 NTFS ACLs를 우회하는 직접 디스크 I/O를 위해 원시 볼륨 디바이스 핸들(예: \\.\C:)을 열 수 있게 해줍니다. 이를 통해 기본 블록을 읽어 볼륨에 있는 어떤 파일의 바이트든 복사할 수 있어, 민감한 자료(예: machine private keys in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS)를 임의로 읽을 수 있습니다. 특히 CA 서버에서 영향이 크며, CA private key를 유출하면 어떤 주체든 가장할 수 있는 Golden Certificate를 위조할 수 있습니다.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 권한 확인
```
whoami /priv
```
Disabled로 표시된 **tokens**는 활성화할 수 있으며, 실제로 _Enabled_ 및 _Disabled_ tokens를 악용할 수 있습니다.

### 모든 tokens 활성화

tokens가 비활성화되어 있다면, 스크립트 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)를 사용하여 모든 tokens를 활성화할 수 있습니다:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
또는 이 [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)에 포함된 **script**.

## 테이블

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| 권한                       | 영향        | 도구                    | 실행 경로                                                                                                                                                                                                                                                                                                                                       | 비고                                                                                                                                                                                                                                                                                                                           |
| -------------------------- | ----------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                    | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                        |
| **`SeBackup`**             | **Threat**  | _**내장 명령**_         | `robocopy /b`로 민감한 파일을 읽음                                                                                                                                                                                                                                                                                                              | <p>- %WINDIR%\MEMORY.DMP를 읽을 수 있다면 더 흥미로울 수 있음<br><br>- <code>SeBackupPrivilege</code> (및 robocopy)은 열린 파일(open files)에 대해서는 도움이 되지 않음.<br><br>- Robocopy가 /b 파라미터로 작동하려면 SeBackup과 SeRestore가 모두 필요함.</p>                                         |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken`으로 로컬 admin 권한을 포함한 임의의 토큰 생성.                                                                                                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                               |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | `lsass.exe` 토큰을 복제.                                                                                                                                                                                                                                                                                                                        | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                          |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. <code>szkg64.sys</code> 같은 취약한 커널 드라이버를 로드<br>2. 드라이버 취약점을 익스플로잇<br><br>대안으로, 이 권한을 사용해 보안 관련 드라이버를 언로드할 수 있음(내장 명령 <code>ftlMC</code> 사용). 예: <code>fltMC sysmondrv</code></p>                                                                                       | <p>1. <code>szkg64</code> 취약점은 <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a>로 등록됨.<br>2. <code>szkg64</code>의 <a href="https://www.greyhathacker.net/?p=1025">exploit code</a>는 <a href="https://twitter.com/parvezghh">Parvez Anwar</a>가 작성함.</p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore 권한이 있는 상태로 PowerShell/ISE 실행.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>로 권한 활성화.<br>3. utilman.exe를 utilman.old로 이름 변경<br>4. cmd.exe를 utilman.exe로 이름 변경<br>5. 콘솔 잠금 후 Win+U 누름</p> | <p>일부 AV 소프트웨어에서 이 공격을 탐지할 수 있음.</p><p>대안 방법으로 동일 권한을 사용해 "Program Files"에 저장된 서비스 바이너리를 교체하는 방법이 있음</p>                                                                                                                                                |
| **`SeTakeOwnership`**      | _**Admin**_ | _**내장 명령**_         | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe를 utilman.exe로 이름 변경<br>4. 콘솔 잠금 후 Win+U 누름</p>                                                                                                                                         | <p>일부 AV 소프트웨어에서 이 공격을 탐지할 수 있음.</p><p>대안 방법으로 동일 권한을 사용해 "Program Files"에 저장된 서비스 바이너리를 교체하는 방법이 있음.</p>                                                                                                                                                          |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>토큰을 조작하여 로컬 admin 권한을 포함하도록 함. SeImpersonate가 필요할 수 있음.</p><p>검증 필요.</p>                                                                                                                                                                                                                                      |                                                                                                                                                                                                                                                                                                                               |

## 참고

- Windows 토큰을 정의한 이 표를 참조: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- 토큰을 이용한 privesc에 관한 문서 참조: [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
