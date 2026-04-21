# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic**는 **startup** 시 프로그램을 실행하는 데 사용할 수 있습니다. 어떤 binary가 startup에서 실행되도록 설정되어 있는지 확인하려면:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## 예약된 작업

**Tasks**는 **특정 빈도**로 실행되도록 예약될 수 있습니다. 실행되도록 예약된 바이너리를 확인하려면:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## 폴더

**Startup folders**에 있는 모든 바이너리는 시작 시 실행됩니다. 일반적인 startup folders는 아래에 나열되어 있지만, startup folder는 registry에 표시됩니다. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **deposit payloads directly inside these Startup folders during decompression**, resulting in code execution on the next user logon.  For a deep-dive into this technique see:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): The **Wow6432Node** registry entry indicates that you are running a 64-bit Windows version. The operating system uses this key to display a separate view of HKEY_LOCAL_MACHINE\SOFTWARE for 32-bit applications that run on 64-bit Windows versions.

### Runs

**Commonly known** AutoRun registry:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Registry keys known as **Run** and **RunOnce** are designed to automatically execute programs every time a user logs into the system. The command line assigned as a key's data value is limited to 260 characters or less.

**Service runs** (can control automatic startup of services during boot):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

On Windows Vista and later versions, the **Run** and **RunOnce** registry keys are not automatically generated. Entries in these keys can either directly start programs or specify them as dependencies. For instance, to load a DLL file at logon, one could use the **RunOnceEx** registry key along with a "Depend" key. This is demonstrated by adding a registry entry to execute "C:\temp\evil.dll" during the system start-up:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: 만약 **HKLM** 안의 언급된 registry 중 어느 하나에라도 write할 수 있다면, 다른 user가 log in할 때 privileges를 escalate할 수 있습니다.

> [!TIP]
> **Exploit 2**: 만약 **HKLM** 안의 registry 중 어느 하나에 표시된 binaries를 overwrite할 수 있다면, 다른 user가 log in할 때 그 binary를 backdoor가 포함된 버전으로 modify하고 privileges를 escalate할 수 있습니다.
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Startup** 폴더에 배치된 바로가기는 사용자 logon 또는 system reboot 동안 서비스나 애플리케이션을 자동으로 실행합니다. **Startup** 폴더의 위치는 **Local Machine**과 **Current User** 범위 모두에 대해 registry에서 정의됩니다. 즉, 이 지정된 **Startup** 위치에 추가된 모든 바로가기는 연결된 service나 program이 logon 또는 reboot 과정 이후 시작되도록 보장하므로, program을 자동 실행하도록 예약하는 매우 간단한 방법입니다.

> [!TIP]
> **HKLM** 아래의 아무 \[User] Shell Folder나 overwrite할 수 있다면, 이를 자신이 제어하는 folder로 지정하고 backdoor를 넣어두어 사용자가 system에 log in할 때마다 실행되게 할 수 있으며, 이로써 privileges를 escalte할 수 있습니다.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

이 per-user registry value는 해당 사용자가 로그온할 때 실행되는 script 또는 command를 가리킬 수 있습니다. 이것은 주로 **persistence** primitive인데, 영향을 받는 사용자의 context에서만 실행되기 때문입니다. 하지만 post-exploitation 및 autoruns review 중에는 여전히 확인할 가치가 있습니다.

> [!TIP]
> 현재 user에 대해 이 value를 쓸 수 있다면, admin rights 없이도 다음 interactive logon 때 실행을 다시 trigger할 수 있습니다. 다른 user hive에 쓸 수 있다면, 그 사용자가 로그온할 때 code execution을 얻을 수 있습니다.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notes:

- 대상 사용자가 이미 읽을 수 있는 `.bat`, `.cmd`, `.ps1`, 또는 다른 launcher 파일의 전체 경로를 선호하세요.
- 이 값이 제거될 때까지 logoff/reboot 후에도 유지됩니다.
- `HKLM\...\Run`과 달리, 이것은 그 자체로 elevation을 부여하지 않으며, user-scope persistence입니다.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

일반적으로 **Userinit** 키는 **userinit.exe**로 설정됩니다. 하지만 이 키가 수정되면, 지정된 executable도 사용자 logon 시 **Winlogon**에 의해 함께 실행됩니다. 마찬가지로 **Shell** 키는 **explorer.exe**를 가리키도록 되어 있으며, 이는 Windows의 기본 shell입니다.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> 레지스트리 값 또는 binary를 덮어쓸 수 있다면 privileges를 상승시킬 수 있습니다.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** key를 확인하세요.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Safe Mode Command Prompt 변경

Windows Registry의 `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` 아래에는 기본값으로 `cmd.exe`로 설정된 **`AlternateShell`** 값이 있다. 이는 시작 중 "Safe Mode with Command Prompt"를 선택하면(F8 키를 눌러) `cmd.exe`가 사용된다는 뜻이다. 하지만 F8을 누르지 않고 수동 선택도 없이, 컴퓨터가 이 모드로 자동 시작되도록 설정할 수도 있다.

"Safe Mode with Command Prompt"로 자동 시작하는 boot option을 만드는 단계:

1. `boot.ini` 파일의 속성을 변경해 read-only, system, hidden 플래그를 제거한다: `attrib c:\boot.ini -r -s -h`
2. 편집을 위해 `boot.ini`를 연다.
3. 다음과 같은 줄을 추가한다: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini`에 변경 사항을 저장한다.
5. 원래 파일 속성을 다시 적용한다: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key를 변경하면 custom command shell 설정이 가능하며, 이는 unauthorized access로 이어질 수 있다.
- **Exploit 2 (PATH Write Permissions):** system **PATH** variable의 어떤 부분이든, 특히 `C:\Windows\system32`보다 앞쪽에 write permissions가 있으면 custom `cmd.exe`를 실행할 수 있으며, 시스템이 Safe Mode로 시작될 때 backdoor가 될 수 있다.
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini`에 대한 write access가 있으면 자동 Safe Mode 시작이 가능해져, 다음 재부팅 때 unauthorized access를 쉽게 할 수 있다.

현재 **AlternateShell** 설정을 확인하려면 다음 명령을 사용한다:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup은 Windows의 기능으로, **desktop environment가 완전히 로드되기 전에 시작**됩니다. 이는 특정 command의 실행을 우선 처리하며, user logon이 진행되기 전에 반드시 완료되어야 합니다. 이 과정은 Run 또는 RunOnce registry 섹션의 startup entry들이 트리거되기 전에도 발생합니다.

Active Setup은 다음 registry keys를 통해 관리됩니다:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

이 keys 안에는 여러 subkey가 있으며, 각각 특정 component에 해당합니다. 특히 관심 있는 key values는 다음과 같습니다:

- **IsInstalled:**
- `0`은 component의 command가 실행되지 않음을 의미합니다.
- `1`은 command가 각 user마다 한 번 실행됨을 의미하며, 이는 `IsInstalled` value가 없을 때의 default behavior입니다.
- **StubPath:** Active Setup이 실행할 command를 정의합니다. `notepad`를 실행하는 것처럼 유효한 command line이면 무엇이든 될 수 있습니다.

**Security Insights:**

- **`IsInstalled`**가 `"1"`로 설정된 key에 특정 **`StubPath`**와 함께 modify하거나 write하면 unauthorized command execution으로 이어질 수 있으며, potential for privilege escalation이 있습니다.
- **`StubPath`** value에서 참조되는 binary file을 변경하는 것도 충분한 permissions이 있다면 privilege escalation을 달성할 수 있습니다.

**`StubPath`** configurations across Active Setup components를 확인하려면 다음 commands를 사용할 수 있습니다:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHOs) 개요

Browser Helper Objects (BHOs)는 Microsoft Internet Explorer에 추가 기능을 더하는 DLL 모듈입니다. 이들은 Internet Explorer와 Windows Explorer가 시작될 때마다 로드됩니다. 다만 **NoExplorer** 키를 1로 설정하면 실행이 차단되어 Windows Explorer 인스턴스와 함께 로드되지 않게 할 수 있습니다.

BHOs는 Internet Explorer 11을 통해 Windows 10과 호환되지만, 최신 버전의 Windows에서 기본 브라우저인 Microsoft Edge에서는 지원되지 않습니다.

시스템에 등록된 BHOs를 확인하려면 다음 registry key를 검사할 수 있습니다:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

각 BHO는 registry에서 **CLSID**로 표현되며, 이는 고유 식별자 역할을 합니다. 각 CLSID에 대한 자세한 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` 아래에서 찾을 수 있습니다.

registry에서 BHOs를 조회하려면 다음 명령을 사용할 수 있습니다:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

registry는 각 dll마다 1개의 새로운 registry를 포함하며, 이는 **CLSID**로 표시됩니다. CLSID 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`에서 찾을 수 있습니다.

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Command

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

autoruns를 찾을 수 있는 모든 위치는 [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)에 의해 **이미 검색됩니다**. 하지만 **더 포괄적인 자동 실행** 파일 목록이 필요하다면 sysinternals의 [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)를 사용할 수 있습니다:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## More

**[**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)**에서 Autoruns 같은 registries를 더 찾아보세요

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
