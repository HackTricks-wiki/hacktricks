# 토큰 악용

{{#include ../../banners/hacktricks-training.md}}

## 토큰

Windows Access Tokens가 무엇인지 **모른다면** 계속하기 전에 이 페이지를 읽으세요:

{{#ref}}
access-tokens.md
{{#endref}}

**이미 가지고 있는 토큰을 악용하여 권한을 상승시킬 수 있을지도 모릅니다.**

### SeImpersonatePrivilege

이 권한은 어떤 프로세스가 토큰을 생성하지 않고도 임시로 사용할 수 있도록 허용합니다. 핸들을 얻을 수 있는 경우, Windows 서비스(DCOM)에서 특권 토큰을 획득하여 NTLM 인증을 유도함으로써 SYSTEM 권한으로 프로세스를 실행할 수 있습니다. 이 취약점은 [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm이 비활성화되어 있어야 함), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)와 같은 다양한 도구를 사용하여 악용할 수 있습니다.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

**SeImpersonatePrivilege**와 매우 유사하며, 특권 토큰을 얻기 위해 **같은 방법**을 사용합니다.\
그 후, 이 권한은 **새로운/중단된 프로세스에 기본 토큰을 할당**할 수 있게 해줍니다. 특권 임시 토큰을 사용하여 기본 토큰을 파생할 수 있습니다(DuplicateTokenEx).\
이 토큰을 사용하여 'CreateProcessAsUser'로 **새 프로세스**를 생성하거나 중단된 프로세스를 생성하고 **토큰을 설정**할 수 있습니다(일반적으로 실행 중인 프로세스의 기본 토큰을 수정할 수는 없습니다).

### SeTcbPrivilege

이 토큰이 활성화되어 있으면 **KERB_S4U_LOGON**을 사용하여 자격 증명을 알지 못한 채 다른 사용자에 대한 **임시 토큰**을 얻을 수 있으며, **임의의 그룹**(관리자)을 토큰에 추가하고, 토큰의 **무결성 수준**을 "**중간**"으로 설정하고, 이 토큰을 **현재 스레드**에 할당할 수 있습니다(SetThreadToken).

### SeBackupPrivilege

이 권한에 의해 시스템은 모든 파일에 대한 **읽기 접근** 제어를 부여받습니다(읽기 작업에 한정됨). 이는 레지스트리에서 로컬 관리자 계정의 비밀번호 해시를 **읽는 데** 사용되며, 이후 "**psexec**" 또는 "**wmiexec**"와 같은 도구를 해시와 함께 사용할 수 있습니다(패스-더-해시 기법). 그러나 이 기법은 두 가지 조건에서 실패합니다: 로컬 관리자 계정이 비활성화되어 있거나, 원격으로 연결하는 로컬 관리자에게 관리 권한을 제거하는 정책이 시행될 때입니다.\
이 권한을 **악용할 수 있습니다**:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)에서 **IppSec**를 따르기
- 또는 다음의 **백업 운영자를 통한 권한 상승** 섹션에서 설명된 대로:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

이 권한은 파일의 접근 제어 목록(ACL)에 관계없이 모든 시스템 파일에 대한 **쓰기 접근**을 제공합니다. 이는 서비스 **수정**, DLL 하이재킹 수행, 이미지 파일 실행 옵션을 통한 **디버거** 설정 등 다양한 상승 가능성을 열어줍니다.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege는 강력한 권한으로, 사용자가 토큰을 임시로 사용할 수 있는 능력을 가질 때 특히 유용하지만, SeImpersonatePrivilege가 없는 경우에도 유용합니다. 이 기능은 동일한 사용자를 나타내는 토큰을 임시로 사용할 수 있는 능력에 의존하며, 이 토큰의 무결성 수준이 현재 프로세스의 무결성 수준을 초과하지 않아야 합니다.

**핵심 사항:**

- **SeImpersonatePrivilege 없이 임시 사용:** 특정 조건에서 토큰을 임시로 사용하여 EoP를 위해 SeCreateTokenPrivilege를 활용할 수 있습니다.
- **토큰 임시 사용 조건:** 성공적인 임시 사용은 대상 토큰이 동일한 사용자에 속하고, 임시 사용을 시도하는 프로세스의 무결성 수준보다 낮거나 같은 무결성 수준을 가져야 합니다.
- **임시 토큰의 생성 및 수정:** 사용자는 임시 토큰을 생성하고 특권 그룹의 SID(보안 식별자)를 추가하여 이를 향상시킬 수 있습니다.

### SeLoadDriverPrivilege

이 권한은 특정 값으로 `ImagePath` 및 `Type`을 가진 레지스트리 항목을 생성하여 **장치 드라이버를 로드하고 언로드**할 수 있게 해줍니다. `HKLM` (HKEY_LOCAL_MACHINE)에 대한 직접 쓰기 접근이 제한되므로 대신 `HKCU` (HKEY_CURRENT_USER)를 사용해야 합니다. 그러나 드라이버 구성을 위해 `HKCU`를 커널이 인식할 수 있도록 하려면 특정 경로를 따라야 합니다.

이 경로는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`이며, 여기서 `<RID>`는 현재 사용자의 상대 식별자입니다. `HKCU` 내에서 이 전체 경로를 생성하고 두 값을 설정해야 합니다:

- `ImagePath`, 실행할 이진 파일의 경로
- `Type`, 값은 `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**따라야 할 단계:**

1. 제한된 쓰기 접근으로 인해 `HKLM` 대신 `HKCU`에 접근합니다.
2. `HKCU` 내에 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` 경로를 생성합니다. 여기서 `<RID>`는 현재 사용자의 상대 식별자를 나타냅니다.
3. `ImagePath`를 이진 파일의 실행 경로로 설정합니다.
4. `Type`을 `SERVICE_KERNEL_DRIVER` (`0x00000001`)로 할당합니다.
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
더 많은 방법은 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)에서 확인할 수 있습니다.

### SeTakeOwnershipPrivilege

이는 **SeRestorePrivilege**와 유사합니다. 이 특권의 주요 기능은 프로세스가 **객체의 소유권을 가정**할 수 있도록 하여 WRITE_OWNER 접근 권한을 제공함으로써 명시적인 재량적 접근 요구 사항을 우회하는 것입니다. 이 과정은 먼저 쓰기 목적으로 의도된 레지스트리 키의 소유권을 확보한 다음, 쓰기 작업을 가능하게 하기 위해 DACL을 변경하는 것을 포함합니다.
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

이 권한은 **다른 프로세스를 디버그**할 수 있게 하며, 메모리에서 읽고 쓸 수 있습니다. 대부분의 안티바이러스 및 호스트 침입 방지 솔루션을 회피할 수 있는 다양한 메모리 주입 전략을 이 권한으로 사용할 수 있습니다.

#### 메모리 덤프

[ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)를 [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)에서 사용하여 **프로세스의 메모리를 캡처**할 수 있습니다. 특히, 이는 사용자가 시스템에 성공적으로 로그인한 후 사용자 자격 증명을 저장하는 **로컬 보안 권한 하위 시스템 서비스 (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 프로세스에 적용될 수 있습니다.

그런 다음 이 덤프를 mimikatz에 로드하여 비밀번호를 얻을 수 있습니다:
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
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## 권한 확인
```
whoami /priv
```
**비활성화된 것으로 나타나는 토큰**은 활성화할 수 있으며, 실제로 _활성화된_ 및 _비활성화된_ 토큰을 악용할 수 있습니다.

### 모든 토큰 활성화

토큰이 비활성화된 경우, 스크립트 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)를 사용하여 모든 토큰을 활성화할 수 있습니다:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
또는 이 [**게시물**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)에 포함된 **스크립트**.

## 표

전체 토큰 권한 요약은 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)에서 확인할 수 있으며, 아래 요약은 관리자 세션을 얻거나 민감한 파일을 읽기 위해 권한을 악용하는 직접적인 방법만 나열합니다.

| 권한                       | 영향        | 도구                    | 실행 경로                                                                                                                                                                                                                                                                                                                                     | 비고                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**관리자**_ | 3rd party tool          | _"사용자가 토큰을 가장하고 potato.exe, rottenpotato.exe 및 juicypotato.exe와 같은 도구를 사용하여 nt 시스템으로 권한 상승을 허용합니다."_                                                                                                                                                                                                      | 업데이트에 대해 [Aurélien Chalot](https://twitter.com/Defte_)에게 감사드립니다. 더 요리법 같은 것으로 다시 표현해 보겠습니다.                                                                                                                                                                                         |
| **`SeBackup`**             | **위협**    | _**내장 명령**_        | `robocopy /b`로 민감한 파일 읽기                                                                                                                                                                                                                                                                                                             | <p>- %WINDIR%\MEMORY.DMP를 읽을 수 있다면 더 흥미로울 수 있습니다.<br><br>- <code>SeBackupPrivilege</code> (및 robocopy)는 열린 파일에 대해서는 도움이 되지 않습니다.<br><br>- Robocopy는 /b 매개변수로 작동하려면 SeBackup과 SeRestore가 모두 필요합니다.</p>                                                                      |
| **`SeCreateToken`**        | _**관리자**_ | 3rd party tool          | `NtCreateToken`으로 임의의 토큰 생성, 로컬 관리자 권한 포함.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**관리자**_ | **PowerShell**          | `lsass.exe` 토큰 복제.                                                                                                                                                                                                                                                                                                                   | [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)에서 스크립트를 찾을 수 있습니다.                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**관리자**_ | 3rd party tool          | <p>1. <code>szkg64.sys</code>와 같은 결함이 있는 커널 드라이버 로드<br>2. 드라이버 취약점 악용<br><br>또는 이 권한을 사용하여 <code>ftlMC</code> 내장 명령으로 보안 관련 드라이버를 언로드할 수 있습니다. 예: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code> 취약점은 <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a>로 나열되어 있습니다.<br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">악용 코드</a>는 <a href="https://twitter.com/parvezghh">Parvez Anwar</a>에 의해 작성되었습니다.</p> |
| **`SeRestore`**            | _**관리자**_ | **PowerShell**          | <p>1. SeRestore 권한이 있는 상태에서 PowerShell/ISE 실행.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>로 권한 활성화.<br>3. utilman.exe를 utilman.old로 이름 변경<br>4. cmd.exe를 utilman.exe로 이름 변경<br>5. 콘솔 잠그고 Win+U 누르기</p> | <p>일부 AV 소프트웨어에서 공격이 감지될 수 있습니다.</p><p>대체 방법은 동일한 권한을 사용하여 "Program Files"에 저장된 서비스 바이너리를 교체하는 것입니다.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**관리자**_ | _**내장 명령**_        | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe를 utilman.exe로 이름 변경<br>4. 콘솔 잠그고 Win+U 누르기</p>                                                                                                                                       | <p>일부 AV 소프트웨어에서 공격이 감지될 수 있습니다.</p><p>대체 방법은 동일한 권한을 사용하여 "Program Files"에 저장된 서비스 바이너리를 교체하는 것입니다.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**관리자**_ | 3rd party tool          | <p>토큰을 조작하여 로컬 관리자 권한을 포함하도록 합니다. SeImpersonate가 필요할 수 있습니다.</p><p>확인 필요.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## 참고

- Windows 토큰을 정의하는 이 표를 확인하세요: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- 토큰을 사용한 권한 상승에 대한 [**이 문서**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)를 확인하세요.

{{#include ../../banners/hacktricks-training.md}}
