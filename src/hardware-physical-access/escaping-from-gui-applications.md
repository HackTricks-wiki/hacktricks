# KIOSKs에서 탈출하기

{{#include ../banners/hacktricks-training.md}}

---

## 물리적 장치 확인

| 구성 요소       | 동작                                                             |
| -------------- | ------------------------------------------------------------------ |
| 전원 버튼       | 장치를 껐다가 다시 켜면 시작 화면이 표시될 수 있음                  |
| 전원 케이블     | 전원을 잠시 차단했을 때 장치가 재부팅되는지 확인                    |
| USB 포트       | 더 많은 단축키를 사용할 수 있도록 물리적 키보드 연결                |
| Ethernet       | 네트워크 스캔 또는 sniffing을 통해 추가적인 exploitation이 가능할 수 있음 |

## GUI 애플리케이션 내부에서 가능한 동작 확인

**일반적인 Dialog**는 **파일 저장**, **파일 열기**, 글꼴 및 색상 선택 등에 사용되는 옵션입니다. 대부분의 경우 **전체 Explorer 기능을 제공**합니다. 즉, 다음 옵션에 접근할 수 있다면 Explorer 기능에 접근할 수 있습니다:

- 닫기/다른 이름으로 닫기
- 열기/다음으로 열기
- 인쇄
- Export/Import
- 검색
- 스캔

다음 작업이 가능한지 확인해야 합니다:

- 파일 수정 또는 새 파일 생성
- symbolic link 생성
- 제한된 영역에 접근
- 다른 앱 실행

### Command Execution

어쩌면 **`Open with` 옵션을 사용하여** 어떤 종류의 shell을 열거나 실행할 수 있습니다.

#### Windows

예를 들어 _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._와 같이 명령을 실행하고 예상하지 못한 동작을 수행하는 데 사용할 수 있는 더 많은 바이너리는 여기에서 확인할 수 있습니다: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ 더 많은 항목은 여기에서 확인할 수 있습니다: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### 경로 제한 우회

- **Environment variables**: 특정 경로를 가리키는 environment variable이 많이 존재함
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (새 세션 열기), CTRL+R (Commands 실행), CTRL+SHIFT+ESC (Task Manager), Windows+E (Explorer 열기), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- 숨겨진 Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: shared folder에 연결하기 위한 경로입니다. 로컬 머신의 C$에 연결을 시도해야 합니다 ("\\\127.0.0.1\c$\Windows\System32")
- **More UNC paths:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Restricted Desktop Breakouts (Citrix/RDS/VDI)

- **Dialog-box pivoting**: *Open/Save/Print-to-file* Dialog를 간소화된 Explorer로 사용합니다. 파일 이름 필드에 `*.*` / `*.exe`를 입력하고, 폴더를 마우스 오른쪽 버튼으로 클릭하여 **Open in new window**를 선택하거나, **Properties → Open file location**을 사용해 탐색 범위를 확장합니다.<sup>[[1]](#references)</sup>
- **Create execution paths from dialogs**: 새 파일을 생성한 후 `.CMD` 또는 `.BAT`로 이름을 변경하거나, `%WINDIR%\System32`(또는 `%WINDIR%\System32\cmd.exe`와 같은 특정 바이너리)를 가리키는 shortcut을 생성합니다.
- **Shell launch pivots**: `cmd.exe`로 이동할 수 있다면, 임의의 파일을 해당 파일 위로 **drag-and-drop**하여 prompt를 실행해 봅니다. Task Manager에 접근할 수 있다면(`CTRL+SHIFT+ESC`), **Run new task**를 사용합니다.
- **Task Scheduler bypass**: interactive shell이 차단되어 있지만 scheduling이 허용되는 경우, `cmd.exe`를 실행하는 task를 생성합니다(GUI `taskschd.msc` 또는 `schtasks.exe`).
- **Weak allowlists**: **filename/extension**으로 실행이 허용되는 경우 payload의 이름을 허용된 이름으로 변경합니다. **directory** 기준으로 허용되는 경우 payload를 허용된 program folder로 복사한 후 그 위치에서 실행합니다.
- **Find writable staging paths**: `%TEMP%`에서 시작하고 Sysinternals AccessChk를 사용하여 writeable folder를 열거합니다.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **다음 단계**: shell을 획득했다면 Windows LPE 체크리스트로 전환하세요:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Binaries 다운로드

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### 브라우저에서 filesystem에 접근하기

| PATH                | PATH              | PATH               | PATH               |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### 단축키

- Sticky Keys – SHIFT 5회 누르기
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – NUMLOCK을 5초 동안 누르기
- Filter Keys – 오른쪽 SHIFT를 12초 동안 누르기
- WINDOWS+F1 – Windows 검색
- WINDOWS+D – Desktop 표시
- WINDOWS+E – Windows Explorer 실행
- WINDOWS+R – Run
- WINDOWS+U – 접근성 센터
- WINDOWS+F – 검색
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – 최신 Windows 버전에서 Splash screen 표시
- F1 – 도움말 F3 – 검색
- F6 – Address Bar
- F11 – Internet Explorer 내에서 전체 화면 전환
- CTRL+H – Internet Explorer 기록
- CTRL+T – Internet Explorer – 새 탭
- CTRL+N – Internet Explorer – 새 페이지
- CTRL+O – 파일 열기
- CTRL+S – 저장 CTRL+N – 새 RDP / Citrix

### 스와이프

- 왼쪽에서 오른쪽으로 스와이프하여 열려 있는 모든 Windows를 확인하고 KIOSK 앱을 최소화한 뒤 전체 OS에 직접 접근합니다.
- 오른쪽에서 왼쪽으로 스와이프하여 Action Center를 열고 KIOSK 앱을 최소화한 뒤 전체 OS에 직접 접근합니다.
- 위쪽 가장자리에서 안쪽으로 스와이프하여 전체 화면 모드로 열린 앱의 title bar를 표시합니다.
- 아래쪽에서 위로 스와이프하여 전체 화면 앱에서 taskbar를 표시합니다.

### Internet Explorer Tricks

#### 'Image Toolbar'

이미지를 클릭하면 이미지의 왼쪽 상단에 표시되는 toolbar입니다. 이를 통해 Explorer에서 Save, Print, Mailto, "My Pictures" 열기를 수행할 수 있습니다. Kiosk는 Internet Explorer를 사용하고 있어야 합니다.

#### Shell Protocol

다음 URLs를 입력하여 Explorer view를 확인합니다.

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### 파일 확장자 표시

자세한 정보는 다음 페이지를 확인하세요: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## 브라우저 Tricks

iKat versions 백업:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScript를 사용하여 common dialog를 생성하고 file explorer에 접근합니다: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### 제스처와 버튼

- 네 손가락(또는 다섯 손가락)으로 위로 스와이프 / Home 버튼 두 번 탭: multitask view를 확인하고 App 변경
- 네 손가락 또는 다섯 손가락으로 한쪽 방향으로 스와이프: 다음/이전 App으로 변경
- 다섯 손가락으로 화면 오므리기 / Home 버튼 누르기 / 화면 아래쪽에서 한 손가락으로 빠르게 위로 스와이프: Home에 접근
- 화면 아래쪽에서 한 손가락으로 1~2인치만 천천히 위로 스와이프: dock 표시
- 화면 상단에서 한 손가락으로 아래로 스와이프: notifications 확인
- 화면 오른쪽 상단 모서리에서 한 손가락으로 아래로 스와이프: iPad Pro의 control centre 확인
- 화면 왼쪽에서 한 손가락으로 1~2인치 스와이프: Today view 확인
- 화면 중앙에서 오른쪽 또는 왼쪽으로 한 손가락을 빠르게 스와이프: 다음/이전 App으로 변경
- **iPad +**의 오른쪽 상단 모서리에 있는 On/**Off**/Sleep 버튼을 길게 누름 + Slide to **power off** slider를 오른쪽 끝까지 이동: 전원 끄기
- **iPad의 On/**Off**/Sleep 버튼과 Home 버튼을 몇 초 동안 누름**: 강제 hard power off
- **iPad의 On/**Off**/Sleep 버튼과 Home 버튼을 빠르게 누름**: 화면 왼쪽 아래에 표시되는 screenshot 촬영. 두 버튼을 몇 초 동안 누르는 대신 매우 짧게 동시에 눌러야 하며, 몇 초 동안 누르면 hard power off가 실행됩니다.<sup>[[3]](#references)</sup>

### 단축키

iPad keyboard 또는 USB keyboard adaptor가 있어야 합니다. 여기에는 애플리케이션에서 벗어나는 데 도움이 될 수 있는 단축키만 표시합니다.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### 시스템 단축키

이 단축키는 iPad 사용 방식에 따라 visual settings 및 sound settings에 사용됩니다.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 화면 어둡게                                                                    |
| F2       | 화면 밝게                                                                      |
| F7       | 이전 곡                                                                      |
| F8       | 재생/일시 정지                                                                     |
| F9       | 곡 건너뛰기                                                                      |
| F10      | 음소거                                                                           |
| F11      | 볼륨 낮추기                                                                |
| F12      | 볼륨 높이기                                                                |
| ⌘ Space  | 사용 가능한 언어 목록 표시; 언어를 선택하려면 space bar를 다시 탭합니다. |

#### iPad navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Home으로 이동                                              |
| ⌘⇧H (Command-Shift-H)                              | Home으로 이동                                              |
| ⌘ (Space)                                          | Spotlight 열기                                          |
| ⌘⇥ (Command-Tab)                                   | 최근 사용한 앱 10개 목록 표시                                 |
| ⌘\~                                                | 마지막 App으로 이동                                       |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (저장하거나 작업할 수 있도록 왼쪽 아래에 표시) |
| ⌘⇧4                                                | Screenshot을 촬영하고 editor에서 열기                    |
| Press and hold ⌘                                   | App에서 사용 가능한 단축키 목록                 |
| ⌘⌥D (Command-Option/Alt-D)                         | dock 표시                                      |
| ^⌥H (Control-Option-H)                             | Home 버튼                                             |
| ^⌥H H (Control-Option-H-H)                         | multitask bar 표시                                      |
| ^⌥I (Control-Option-i)                             | Item chooser                                            |
| Escape                                             | Back 버튼                                             |
| → (Right arrow)                                    | 다음 항목                                               |
| ← (Left arrow)                                     | 이전 항목                                           |
| ↑↓ (Up arrow, Down arrow)                          | 선택한 항목을 동시에 탭                        |
| ⌥ ↓ (Option-Down arrow)                            | 아래로 스크롤                                             |
| ⌥↑ (Option-Up arrow)                               | 위로 스크롤                                               |
| ⌥← 또는 ⌥→ (Option-Left arrow 또는 Option-Right arrow) | 왼쪽 또는 오른쪽으로 스크롤                                    |
| ^⌥S (Control-Option-S)                             | VoiceOver speech 켜기 또는 끄기                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 이전 앱으로 전환                              |
| ⌘⇥ (Command-Tab)                                   | 원래 앱으로 다시 전환                         |
| ←+→, then Option + ← 또는 Option+→                   | Dock 탐색                                   |

#### Safari 단축키

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Location 열기                                    |
| ⌘T                      | 새 탭 열기                                   |
| ⌘W                      | 현재 탭 닫기                            |
| ⌘R                      | 현재 탭 새로 고침                          |
| ⌘.                      | 현재 탭 로딩 중지                     |
| ^⇥                      | 다음 탭으로 전환                           |
| ^⇧⇥ (Control-Shift-Tab) | 이전 탭으로 이동                         |
| ⌘L                      | 수정할 text input/URL field 선택     |
| ⌘⇧T (Command-Shift-T)   | 마지막으로 닫은 탭 열기 (여러 번 사용 가능) |
| ⌘\[                     | browsing history에서 한 페이지 뒤로 이동      |
| ⌘]                      | browsing history에서 한 페이지 앞으로 이동   |
| ⌘⇧R                     | Reader Mode 활성화                             |

#### Mail 단축키

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Location 열기                |
| ⌘T                         | 새 탭 열기               |
| ⌘W                         | 현재 탭 닫기               |
| ⌘R                         | 현재 탭 새로 고침               |
| ⌘.                         | 현재 탭 로딩 중지 |
| ⌘⌥F (Command-Option/Alt-F) | mailbox에서 검색       |

## References

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
