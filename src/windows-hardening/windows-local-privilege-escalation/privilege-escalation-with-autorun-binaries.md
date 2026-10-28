# Autoruns를 통한 권한 상승

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic**를 사용하면 **시작 시** 프로그램을 실행할 수 있습니다. 시작 시 실행되도록 설정된 바이너리를 확인하려면 다음을 실행하세요:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## 예약된 작업

**작업**은 **특정 주기로** 실행되도록 예약할 수 있습니다. 다음 명령을 사용하여 실행이 예약된 바이너리를 확인하세요:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

`/sc ONLOGON /rl HIGHEST`로 생성된 작업은 **등록된 보안 주체가 사용할 수 있는** 가장 높은 실행 수준을 요청합니다. 이 스위치만으로는 해당 보안 주체가 바뀌거나 UAC를 우회하지 않습니다. 낮은 권한의 프로세스는 최고 실행 수준의 작업을 등록하거나 SYSTEM을 작업 ID로 선택할 수 없습니다. 위의 예시는 이미 권한이 상승된 호출자가 실행하는 작업으로 봐야 하며, 일반 사용자가 SYSTEM 권한을 얻는 경로로 보면 안 됩니다.<sup>[[8]](#references)</sup>

작업 정의와 작업 파일이 보호되어 있더라도, SYSTEM으로 실행되는 활성화된 작업은 검토할 필요가 있습니다. [작업 스케줄러에서 작업을 요청 시 실행하려면 해당 작업에 대한 실행 권한이 필요합니다](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). 낮은 권한의 사용자에게 이 권한이 있다면 정확한 작업을 확인하세요. 특히 Active Directory ACL을 수정하거나 계정 보호 설정을 초기화하는 PowerShell 스크립트를 살펴보세요. 작업의 `AllowDemandStart` 설정을 확인하고 스크립트의 입력값과 영향을 검증하세요. 고정된 작업을 시작할 권한만으로 임의 코드 실행이 가능한 것은 아닙니다.

## 폴더

**시작 폴더에 있는 모든 바이너리는 시작 시 실행됩니다**. 일반적인 시작 폴더는 아래에 나열되어 있지만, 시작 폴더는 레지스트리에 지정되어 있습니다. [위치를 확인하려면 여기를 읽어보세요.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

더 높은 권한을 가진 사용자의 Startup 항목이 보호된 스크립트를 실행하고, 해당 스크립트가 다른 사용자가 쓸 수 있는 디렉터리에서 파일을 반복해서 연다면, 그 디렉터리를 권한 상승 경로로 간주하기 전에 항목의 **실제 로그온 계정**, 스크립트의 입력 디렉터리와 ACL, 그리고 정확한 동작을 검토하세요. 특히 [`hh.exe`는 컴파일된 HTML Help (`.chm`) 파일을 엽니다](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program). 호출자가 제공한 파일을 여기에 전달하는 스크립트는 파일 이름이나 첫 바이트를 검사하더라도 콘텐츠 신뢰 경계를 넘습니다. [HTML Help 정책은 실행 가능한 바로 가기를 제한할 수 있으므로](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), 설치된 정책과 접근 가능한 콘텐츠의 동작을 확인하세요. `.chm` 확장자나 매직 바이트만으로는 더 높은 권한의 코드 실행이 입증되지 않습니다. 열거하는 동안 신뢰할 수 없는 파일을 열지 말고 autorun, 프로세스 명령줄, 경로 권한을 검사하세요.

다른 사용자가 바꿀 수 있는 문서 폴더의 `.chm` 파일을 더 높은 권한을 가진 사람이 **수동으로 여는 경우에도** 동일한 콘텐츠 경계가 존재합니다. 정확한 파일과 상위 디렉터리에 대한 쓰기 권한, 실제 뷰어 계정과 파일을 여는 동작, 유효한 HTML Help 정책을 확인하세요. 폴더에 쓰기 권한이 있거나 문서 검토 요청이 있었다는 사실만으로는 더 높은 권한의 계정이 공격자가 제어하는 콘텐츠를 열었다고 볼 수 없습니다.

> **참고**: Archive extraction *path traversal* 취약점(예: WinRAR 7.13 이전 버전에서 악용된 CVE-2025-8088)을 이용하면 압축 해제 중에 **Startup 폴더에 payload를 직접 배치**하여 다음 사용자 로그온 시 코드 실행을 유발할 수 있습니다. 이 기법에 대한 자세한 설명은 다음을 참조하세요:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [여기서 발췌한 참고 사항](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** 레지스트리 항목은 64비트 Windows 버전을 실행 중임을 나타냅니다. 운영 체제는 이 키를 사용하여 64비트 Windows 버전에서 실행되는 32비트 애플리케이션에 HKEY_LOCAL_MACHINE\SOFTWARE의 별도 보기를 표시합니다.

### Runs

**잘 알려진** AutoRun 레지스트리:

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

**Run** 및 **RunOnce**로 알려진 레지스트리 키는 사용자가 시스템에 로그온할 때마다 프로그램을 자동으로 실행하도록 설계되었습니다. 키의 데이터 값으로 지정하는 명령줄은 260자 이하여야 합니다.<sup>[[2]](#references)</sup>

**서비스 Run** (부팅 중 서비스의 자동 시작을 제어할 수 있음):

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

Windows Vista 및 이후 버전에서는 **Run** 및 **RunOnce** 레지스트리 키가 자동으로 생성되지 않습니다. 이 키의 항목은 프로그램을 직접 시작하거나 종속 항목으로 지정할 수 있습니다. 예를 들어 로그온 시 DLL 파일을 로드하려면 **RunOnceEx** 레지스트리 키와 "Depend" 키를 함께 사용할 수 있습니다. 다음은 시스템 시작 중에 "C:\temp\evil.dll"을 실행하는 레지스트리 항목을 추가하는 예입니다.<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: **HKLM** 내에 언급된 레지스트리 항목 중 어느 곳이든 쓸 수 있다면, 다른 사용자가 로그인할 때 권한을 상승시킬 수 있습니다.

> [!TIP]
> **Exploit 2**: **HKLM** 내 레지스트리 항목에 지정된 바이너리 중 어느 것이든 덮어쓸 수 있다면, 다른 사용자가 로그인할 때 해당 바이너리에 백도어를 삽입해 권한을 상승시킬 수 있습니다.

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

### 시작 경로

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Startup** 폴더에 바로 가기를 넣으면 사용자가 로그온하거나 시스템을 재부팅할 때 서비스나 애플리케이션이 자동으로 실행됩니다. **Startup** 폴더의 위치는 레지스트리에서 **Local Machine** 및 **Current User** 범위에 대해 정의됩니다. 따라서 지정된 **Startup** 위치에 바로 가기를 추가하면 로그온 또는 재부팅 후 연결된 서비스나 프로그램이 시작되므로, 프로그램을 자동으로 실행하도록 예약하는 간단한 방법입니다.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> **HKLM** 아래의 \[User] Shell Folder를 덮어쓸 수 있다면, 해당 폴더가 사용자가 제어하는 폴더를 가리키도록 설정하고 backdoor를 넣을 수 있습니다. 그러면 사용자가 시스템에 로그인할 때마다 backdoor가 실행되어 권한이 상승합니다.

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

이 사용자별 레지스트리 값은 해당 사용자가 로그온할 때 실행되는 스크립트나 명령을 가리킬 수 있습니다. 영향을 받는 사용자 컨텍스트에서만 실행되므로 주로 **persistence** 용도로 사용되지만, post-exploitation 및 autoruns 검토 시 확인할 가치가 있습니다.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> 현재 사용자의 이 값을 쓸 수 있다면 관리자 권한 없이 다음 대화형 로그온 때 실행을 다시 트리거할 수 있습니다. 다른 사용자의 hive에 쓸 수 있다면 해당 사용자가 로그온할 때 코드 실행을 얻을 수 있습니다.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

참고:

- 대상 사용자가 이미 읽을 수 있는 `.bat`, `.cmd`, `.ps1` 또는 기타 런처 파일의 전체 경로를 사용하는 것이 좋습니다.
- 값을 제거할 때까지 로그오프/재부팅 후에도 유지됩니다.
- `HKLM\...\Run`과 달리, 이것만으로 권한 상승이 이루어지지는 않습니다. 사용자 범위의 지속성입니다.

### Winlogon 키

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

일반적으로 **Userinit** 키는 **userinit.exe**로 설정됩니다. 하지만 이 키가 수정되면 지정된 실행 파일도 사용자가 로그온할 때 **Winlogon**에 의해 실행됩니다. 마찬가지로 **Shell** 키는 Windows의 기본 셸인 **explorer.exe**를 가리키도록 설정됩니다.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> registry value 또는 binary를 덮어쓸 수 있다면 권한을 상승시킬 수 있습니다.

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

### Safe Mode 명령 프롬프트 변경

`HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` 아래의 Windows Registry에는 기본적으로 `cmd.exe`로 설정된 **`AlternateShell`** 값이 있습니다. 즉, 시작 중에 F8 키를 눌러 "Safe Mode with Command Prompt"를 선택하면 `cmd.exe`가 사용됩니다. 하지만 F8 키를 눌러 직접 선택하지 않아도 컴퓨터가 자동으로 이 모드로 시작하도록 설정할 수 있습니다.

"Safe Mode with Command Prompt"로 자동 시작하는 부팅 옵션을 만드는 단계:<sup>[[5]](#references)</sup>

1. `boot.ini` 파일의 속성을 변경해 읽기 전용, 시스템, 숨김 플래그를 제거합니다: `attrib c:\boot.ini -r -s -h`
2. `boot.ini`를 열어 편집합니다.
3. 다음과 같은 줄을 삽입합니다: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini`의 변경 사항을 저장합니다.
5. 파일의 원래 속성을 다시 적용합니다: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** registry key를 변경하면 사용자 지정 command shell을 설정할 수 있어, 무단 접근에 악용될 가능성이 있습니다.
- **Exploit 2 (PATH Write Permissions):** 시스템 **PATH** 변수의 일부에라도 쓰기 권한이 있으면, 특히 `C:\Windows\system32`보다 앞에 있는 경우 사용자 지정 `cmd.exe`를 실행할 수 있습니다. 시스템이 Safe Mode로 시작될 때 이는 backdoor로 악용될 수 있습니다.
- **Exploit 3 (PATH and boot.ini Write Permissions):** `boot.ini`에 쓰기 권한이 있으면 Safe Mode로 자동 시작하도록 설정해 다음 재부팅 때 무단 접근을 가능하게 할 수 있습니다.

현재 **AlternateShell** 설정을 확인하려면 다음 명령을 사용합니다:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### 설치된 구성 요소

Active Setup은 **데스크톱 환경이 완전히 로드되기 전에 시작되는** Windows 기능입니다. 사용자 로그온이 진행되기 전에 완료되어야 하는 특정 명령의 실행을 우선시합니다. 이 프로세스는 Run 또는 RunOnce 레지스트리 섹션에 있는 항목과 같은 다른 시작 항목이 트리거되기 전에도 실행됩니다.

Active Setup은 다음 레지스트리 키를 통해 관리됩니다.

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

이러한 키에는 여러 하위 키가 있으며, 각각 특정 구성 요소에 해당합니다. 특히 주목할 만한 키 값은 다음과 같습니다.

- **IsInstalled:**
  - `0`은 해당 구성 요소의 명령이 실행되지 않음을 나타냅니다.
  - `1`은 기본 동작으로, `IsInstalled` 값이 없을 때도 적용되며 각 사용자에 대해 명령이 한 번 실행됨을 의미합니다.
- **StubPath:** Active Setup에서 실행할 명령을 정의합니다. `notepad` 실행과 같이 유효한 명령줄이면 무엇이든 지정할 수 있습니다.

**보안 관련 정보:**

- **`IsInstalled`**가 `"1"`로 설정되어 있고 특정 **`StubPath`**가 지정된 키를 수정하거나 해당 키에 값을 쓰면, 권한 상승으로 이어질 수 있는 무단 명령 실행이 발생할 수 있습니다.
- 충분한 권한이 있다면 **`StubPath`** 값에 참조된 바이너리 파일을 변경하는 방법으로도 권한을 상승시킬 수 있습니다.

Active Setup 구성 요소 전체의 **`StubPath`** 설정을 확인하려면 다음 명령을 사용할 수 있습니다.

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### 브라우저 도우미 개체

### 브라우저 도우미 개체(BHOs) 개요

브라우저 도우미 개체(BHOs)는 Microsoft Internet Explorer에 추가 기능을 제공하는 DLL 모듈입니다. 이 모듈은 Internet Explorer와 Windows Explorer가 시작될 때마다 로드됩니다. 하지만 **NoExplorer** 키를 1로 설정하면 실행을 차단하여 Windows Explorer 인스턴스와 함께 로드되지 않게 할 수 있습니다.<sup>[[1]](#references)</sup>

BHO는 Internet Explorer 11을 통해 Windows 10과 호환되지만, 최신 버전의 Windows에서 기본 브라우저로 제공되는 Microsoft Edge에서는 지원되지 않습니다.

시스템에 등록된 BHO를 확인하려면 다음 레지스트리 키를 살펴볼 수 있습니다.

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

각 BHO는 레지스트리에서 고유 식별자 역할을 하는 **CLSID**로 표시됩니다. 각 CLSID에 대한 자세한 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`에서 확인할 수 있습니다.

레지스트리에서 BHO를 조회할 때는 다음 명령을 사용할 수 있습니다:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer 확장

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

레지스트리에는 각 dll마다 새 레지스트리 항목이 하나씩 추가되며, 해당 항목은 **CLSID**로 표시됩니다. CLSID 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`에서 확인할 수 있습니다.

### 글꼴 드라이버

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

### 컨텍스트 메뉴 COM 핸들러

Explorer 컨텍스트 메뉴 핸들러는 `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` 및 `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`와 같은 키 아래에 등록된 shell extension입니다. 핸들러의 기본값 또는 경우에 따라 키 이름은 CLSID입니다. 해당 CLSID를 따라 `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`로 이동합니다. 이 키의 기본값은 핸들러가 호출될 때 로드되는 DLL의 이름입니다.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

32비트와 64비트 레지스트리 뷰를 모두 확인하세요. `HKCR`은 사용자별 및 시스템 전체 클래스 등록 정보를 병합하므로, 프로세스가 실제로 어떤 기본 키를 참조하는지 확인하세요. 낮은 권한의 계정이 시스템 전체 `InprocServer32` 값을 변경할 수 있으면 더 높은 권한의 프로세스가 다른 DLL을 로드하도록 유도할 수 있지만, 권한 상승을 위해서는 해당 프로세스가 핸들러를 호출해야 합니다. 레지스트리 값 자체가 보호되어 있어도 쓰기 가능한 DLL 경로로 인해 비슷한 위험이 발생할 수 있습니다.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

autoruns를 찾을 수 있는 모든 위치는 이미 [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)에서 검색한다는 점에 유의하세요. 하지만 자동 실행되는 파일을 더 포괄적으로 확인하려면 systinternals의 [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)를 사용할 수 있습니다:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## 더 보기

**[https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)에서 레지스트리와 같은 Autoruns를 더 찾아보세요.**<sup>[[4]](#references)</sup>

## References

- [1] [일반적인 malware 지속성 메커니즘](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart 범주 (Windows Sysinternals Tools를 사용한 문제 해결, 제2판)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [대체 셸을 시작하는 부팅 옵션을 추가하려면 어떻게 해야 하나요?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit 주간 정리 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – 작업의 보안 컨텍스트](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
