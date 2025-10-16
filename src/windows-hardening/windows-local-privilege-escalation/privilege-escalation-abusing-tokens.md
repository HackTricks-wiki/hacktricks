# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

만약 **Windows Access Tokens가 무엇인지 모른다면** 계속하기 전에 이 페이지를 읽으세요:


{{#ref}}
access-tokens.md
{{#endref}}

**이미 가지고 있는 tokens을 악용하여 권한 상승을 할 수 있을지도 모릅니다**

### SeImpersonatePrivilege

이 권한은 어떤 프로세스가 토큰을 생성하는 것은 아니지만, 해당 토큰에 대한 핸들을 얻을 수 있다면 그 토큰을 impersonation(대리)하는 것을 허용합니다. 권한이 있는 토큰은 Windows 서비스(DCOM)에서 NTLM 인증을 exploit 쪽으로 유도하여 얻을 수 있으며, 이를 통해 SYSTEM 권한으로 프로세스를 실행할 수 있습니다. 이 취약점은 [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm이 비활성화되어 있어야 함), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 같은 다양한 도구로 악용할 수 있습니다.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

이는 **SeImpersonatePrivilege**와 매우 유사하며, 권한 있는 토큰을 얻기 위해 **같은 방법**을 사용합니다.\
그 다음 이 권한은 새로 생성되거나 일시중단된 프로세스에 **primary token을 할당할 수 있게** 해줍니다. 권한 있는 impersonation 토큰으로부터 primary token을 파생(DuplicateTokenEx)할 수 있습니다.\
그 토큰으로 'CreateProcessAsUser'를 사용해 **새 프로세스**를 생성하거나 프로세스를 일시중단 상태로 만든 뒤 **토큰을 설정**할 수 있습니다(일반적으로 실행 중인 프로세스의 primary token은 수정할 수 없습니다).

### SeTcbPrivilege

이 권한이 활성화되어 있으면 **KERB_S4U_LOGON**을 사용해 자격 증명을 모르는 상태에서도 다른 사용자에 대한 **impersonation token**을 얻을 수 있고, 토큰에 임의의 그룹(예: admins)을 **추가**할 수 있으며, 토큰의 **integrity level**을 "**medium**"으로 설정하고 이 토큰을 **현재 스레드**에 할당(SetThreadToken)할 수 있습니다.

### SeBackupPrivilege

이 권한은 시스템이 모든 파일에 대해 **모든 읽기 접근권한**을 부여하도록 하며(읽기 작업으로 제한), 로컬 Administrator 계정의 패스워드 해시를 레지스트리에서 읽어오는 데 사용됩니다. 그런 다음 "psexec"나 "wmiexec" 같은 도구로 해시를 사용(Pass-the-Hash 기법)할 수 있습니다. 다만 Local Administrator 계정이 비활성화되어 있거나 원격 연결 시 로컬 관리자 권한을 제거하는 정책이 있으면 이 기법은 실패합니다.\
이 권한은 다음으로 **악용**할 수 있습니다:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- IppSec가 설명한 내용: [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- 또는 다음 문서의 "escalating privileges with Backup Operators" 섹션에 설명된 방법:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

이 권한은 파일의 Access Control List(ACL)에 관계없이 모든 시스템 파일에 대한 **쓰기 접근**을 허용합니다. 이로 인해 서비스 수정, DLL Hijacking 수행, Image File Execution Options를 통한 **디버거 설정** 등 여러 가지 권한 상승 가능성이 열립니다.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege는 강력한 권한으로, 특히 사용자가 토큰을 impersonate할 수 있을 때 유용하지만 SeImpersonatePrivilege가 없어도 유용합니다. 이 기능은 동일한 사용자를 나타내고 현재 프로세스의 integrity level을 초과하지 않는 토큰을 impersonate할 수 있는 능력에 기반합니다.

**핵심 포인트:**

- **Impersonation without SeImpersonatePrivilege:** 특정 조건에서 SeCreateTokenPrivilege를 이용해 EoP를 시도할 수 있습니다.
- **Conditions for Token Impersonation:** 성공적인 impersonation을 위해서는 대상 토큰이 동일한 사용자에 속하며, 그 토큰의 integrity level이 impersonation을 시도하는 프로세스의 integrity level보다 작거나 같아야 합니다.
- **Creation and Modification of Impersonation Tokens:** 사용자는 impersonation 토큰을 생성하고 여기에 권한이 있는 그룹의 SID(Security Identifier)를 추가하여 토큰을 강화할 수 있습니다.

### SeLoadDriverPrivilege

이 권한은 레지스트리에 특정 값들을 가진 엔트리를 생성해 **device drivers를 load/unload**할 수 있게 합니다. `HKLM`에 대한 직접 쓰기 접근이 제한되어 있으므로 `HKCU`를 사용해야 합니다. 다만 kernel이 드라이버 구성을 인식하게 하려면 특정 경로를 따라야 합니다.

이 경로는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`이며, 여기서 `<RID>`는 현재 사용자의 Relative Identifier입니다. `HKCU` 안에 이 전체 경로를 생성하고 두 가지 값을 설정해야 합니다:

- `ImagePath`는 실행될 바이너리의 경로입니다.
- `Type`은 `SERVICE_KERNEL_DRIVER` (`0x00000001`) 값으로 설정합니다.

**따를 단계:**

1. 쓰기 접근이 제한되어 있으므로 `HKCU`를 사용합니다.
2. `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` 경로를 `HKCU` 내에 생성합니다. 여기서 `<RID>`는 현재 사용자의 Relative Identifier입니다.
3. `ImagePath`를 바이너리 실행 경로로 설정합니다.
4. `Type`을 `SERVICE_KERNEL_DRIVER` (`0x00000001`)로 설정합니다.
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
더 많은 권한 남용 방법은 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege) 참조

### SeTakeOwnershipPrivilege

이것은 **SeRestorePrivilege**와 유사합니다. 주요 기능은 프로세스가 **객체의 소유권을 취득**할 수 있게 하여 WRITE_OWNER 접근 권한을 통해 명시적 재량 접근 요구를 우회하는 것입니다. 이 과정은 먼저 쓰기 목적의 대상 레지스트리 키에 대한 소유권을 확보한 다음, 쓰기 작업을 가능하게 하도록 DACL을 변경하는 것으로 구성됩니다.
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

이 권한은 **debug other processes**를 허용하며, 메모리를 읽고 쓰는 작업을 포함합니다. 이 권한으로 대부분의 안티바이러스 및 호스트 침입 방지 솔루션을 회피할 수 있는 다양한 메모리 인젝션 전략을 사용할 수 있습니다.

#### Dump memory

다음과 같이 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 를 [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) 에서 사용하여 **capture the memory of a process** 할 수 있습니다. 구체적으로, 이는 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 프로세스에 적용될 수 있으며, 이 프로세스는 사용자가 시스템에 성공적으로 로그인한 후 사용자 자격 증명을 저장하는 역할을 합니다.

그런 다음 이 덤프를 mimikatz에 로드하여 암호를 얻을 수 있습니다:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

만약 `NT SYSTEM` shell을 얻고 싶다면 다음을 사용할 수 있습니다:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

이 권한 (Perform volume maintenance tasks)은 NTFS ACL을 우회하는 직접 디스크 I/O를 위해 원시 볼륨 디바이스 핸들(예: \\.\C:)을 열 수 있게 합니다. 이를 통해 기본 블록을 읽어 볼륨에 있는 어떤 파일의 바이트도 복사할 수 있어 민감한 자료(예: machine private keys in %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS)를 임의로 읽을 수 있습니다. CA servers에서 특히 큰 영향을 미치며, CA private key를 유출하면 Golden Certificate를 위조해 어떤 주체로든 가장할 수 있습니다.

자세한 기법과 완화 방법은 다음을 참조하세요:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 권한 확인
```
whoami /priv
```
**Disabled**로 표시되는 토큰은 활성화할 수 있으며, 실제로는 _Enabled_ 및 _Disabled_ 토큰을 모두 악용할 수 있습니다.

### 모든 토큰 활성화

토큰이 비활성화되어 있다면, [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) 스크립트를 사용하여 모든 토큰을 활성화할 수 있습니다:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
또는 이 [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)에 포함된 **script**.

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), 아래 요약은 관리자 세션을 획득하거나 민감한 파일을 읽기 위해 해당 권한을 직접 악용하는 방법만 나열합니다.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**관리자**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | 감사합니다 [Aurélien Chalot](https://twitter.com/Defte_) 업데이트해 주셔서. 곧 더 레시피 형식으로 다시 표현해 보겠습니다.                                                                                                                                                                                                         |
| **`SeBackup`**             | **위협**    | _**Built-in commands**_ | `robocopy /b`로 민감한 파일 읽기                                                                                                                                                                                                                                                                                                                 | <p>- %WINDIR%\\MEMORY.DMP를 읽을 수 있다면 더 흥미로울 수 있음<br><br>- <code>SeBackupPrivilege</code> (및 robocopy)은 열린 파일에는 도움이 되지 않음.<br><br>- Robocopy는 /b 파라미터로 동작하려면 <code>SeBackup</code>과 <code>SeRestore</code> 둘 다 필요.</p>                                                                      |
| **`SeCreateToken`**        | _**관리자**_ | 3rd party tool          | `NtCreateToken`으로 로컬 관리자 권한을 포함한 임의 토큰 생성.                                                                                                                                                                                                                                                                                    |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**관리자**_ | **PowerShell**          | `lsass.exe` 토큰 복제.                                                                                                                                                                                                                                                                                                                            | 스크립트는 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)에서 확인할 수 있음.                                                                                                                                                                                                     |
| **`SeLoadDriver`**         | _**관리자**_ | 3rd party tool          | <p>1. <code>szkg64.sys</code> 같은 취약한 커널 드라이버 로드<br>2. 드라이버 취약점 악용<br><br>또는, 이 권한을 사용해 보안 관련 드라이버를 언로드할 수 있음(내장 명령 <code>ftlMC</code> 사용 예: <code>fltMC sysmondrv</code>).</p>                                                                           | <p>1. <code>szkg64</code> 취약점은 <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a>로 등재됨<br>2. <code>szkg64</code>의 <a href="https://www.greyhathacker.net/?p=1025">exploit code</a>는 <a href="https://twitter.com/parvezghh">Parvez Anwar</a>가 작성함</p> |
| **`SeRestore`**            | _**관리자**_ | **PowerShell**          | <p>1. SeRestore 권한이 있는 상태로 PowerShell/ISE 실행.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>로 권한 활성화.<br>3. utilman.exe를 utilman.old로 이름 변경<br>4. cmd.exe를 utilman.exe로 이름 변경<br>5. 콘솔 잠금 후 Win+U 누름</p> | <p>일부 AV 소프트웨어에서 탐지될 수 있음.</p><p>대안 방법으로 동일 권한으로 "Program Files"에 저장된 서비스 바이너리를 교체하는 방법이 있음</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**관리자**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe를 utilman.exe로 이름 변경<br>4. 콘솔 잠금 후 Win+U 누름</p>                                                                                                                                       | <p>일부 AV 소프트웨어에서 탐지될 수 있음.</p><p>대안 방법으로 동일 권한으로 "Program Files"에 저장된 서비스 바이너리를 교체하는 방법이 있음.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**관리자**_ | 3rd party tool          | <p>토큰을 조작하여 로컬 관리자 권한을 포함하도록 만듦. SeImpersonate가 필요할 수 있음.</p><p>확인 필요.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Reference

- Windows 토큰을 정의한 이 표를 참고: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- 토큰을 이용한 privesc에 관한 [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)를 참고하세요.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
