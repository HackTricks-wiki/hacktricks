# KIOSK에서 탈출

{{#include ../banners/hacktricks-training.md}}

---

## 물리적 장치 확인

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | 기기를 껐다가 다시 켜면 시작 화면이 노출될 수 있음                 |
| Power cable  | 전원을 잠깐 끊었을 때 장치가 재부팅되는지 확인하세요               |
| USB ports    | 추가 단축키 사용을 위해 물리적 키보드를 연결해 보세요             |
| Ethernet     | 네트워크 스캔 또는 패킷 스니핑으로 추가적인 공격 벡터를 찾을 수 있음 |

## GUI 애플리케이션 내부에서 가능한 동작 확인

**Common Dialogs**는 **파일 저장**, **파일 열기**, 글꼴 선택, 색상 선택 등의 옵션입니다. 대부분의 다이얼로그는 **full Explorer functionality**를 제공합니다. 즉 이러한 옵션에 접근할 수 있다면 Explorer 기능에 접근할 수 있다는 뜻입니다:

- 닫기/다른 이름으로 닫기
- 열기/다음으로 열기
- 인쇄
- 내보내기/가져오기
- 검색
- 스캔

다음 항목들을 확인하세요:

- 파일 수정 또는 새 파일 생성 가능 여부
- 심볼릭 링크 생성 가능 여부
- 제한된 영역에 접근 가능 여부
- 다른 앱 실행 가능 여부

### 명령 실행

Maybe **using a `Open with`** option** you can open/execute some kind of shell.

#### Windows

예: _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ 명령 실행(및 예상치 못한 동작 수행)에 사용할 수 있는 더 많은 바이너리는 여기에서 확인하세요: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ 자세한 내용: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### 경로 제한 우회

- **Environment variables**: 많은 환경 변수들이 특정 경로를 가리키고 있습니다
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**: 심볼릭 링크를 활용
- **Shortcuts**: CTRL+N (새 세션 열기), CTRL+R (명령 실행), CTRL+SHIFT+ESC (작업 관리자), Windows+E (Explorer 열기), CTRL-B, CTRL-I (즐겨찾기), CTRL-H (히스토리), CTRL-L, CTRL-O (파일/열기 대화상자), CTRL-P (인쇄 대화상자), CTRL-S (다른 이름으로 저장)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: 공유 폴더에 연결하는 경로입니다. 로컬 머신의 C$에 연결을 시도해 보세요 ("\\\127.0.0.1\c$\Windows\System32")
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

### 제한된 데스크탑 탈출 (Citrix/RDS/VDI)

- **Dialog-box pivoting**: *Open/Save/Print-to-file* 다이얼로그를 Explorer-lite로 사용하세요. 파일 이름 필드에 `*.*` / `*.exe`를 시도하고, 폴더를 우클릭하여 **Open in new window**를 선택하거나 **Properties → Open file location**을 사용해 탐색 범위를 넓히세요.
- **Create execution paths from dialogs**: 새 파일을 생성한 뒤 `.CMD` 또는 `.BAT`로 이름을 바꾸거나 `%WINDIR%\System32`(또는 `%WINDIR%\System32\cmd.exe` 같은 특정 바이너리)를 가리키는 바로가기를 만드세요.
- **Shell launch pivots**: `cmd.exe`로 탐색할 수 있다면 아무 파일을 끌어다 놓아 프롬프트를 실행해 보세요. 작업 관리자(`CTRL+SHIFT+ESC`)에 접근 가능하면 **Run new task**를 사용하세요.
- **Task Scheduler bypass**: 인터랙티브 셸이 차단되었지만 스케줄링이 허용된다면, `cmd.exe`를 실행하도록 작업을 생성하세요(GUI `taskschd.msc` 또는 `schtasks.exe`).
- **Weak allowlists**: 실행이 **파일명/확장자**로 허용된다면 페이로드 이름을 허용된 이름으로 변경하세요. **디렉터리**로 허용된다면 페이로드를 허용된 프로그램 폴더로 복사하고 거기서 실행하세요.
- **Find writable staging paths**: `%TEMP%`부터 시작하여 쓰기 가능한 폴더를 Sysinternals AccessChk로 열거하세요.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Next step**: 쉘을 얻으면 Windows LPE 체크리스트로 전환하세요:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### 바이너리 다운로드

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### 브라우저에서 파일시스템 접근

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### 단축키

- Sticky Keys – SHIFT 키를 5번 누르기
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – NUMLOCK 키를 5초간 누르기
- Filter Keys – 오른쪽 SHIFT 키를 12초간 누르기
- WINDOWS+F1 – Windows 검색
- WINDOWS+D – 바탕화면 표시
- WINDOWS+E – Windows Explorer 실행
- WINDOWS+R – 실행
- WINDOWS+U – 접근성 센터
- WINDOWS+F – 검색
- SHIFT+F10 – 컨텍스트 메뉴
- CTRL+SHIFT+ESC – 작업 관리자
- CTRL+ALT+DEL – 최신 Windows 버전의 스플래시 화면
- F1 – 도움말 F3 – 검색
- F6 – 주소 표시줄
- F11 – Internet Explorer 내 전체 화면 전환
- CTRL+H – Internet Explorer 기록
- CTRL+T – Internet Explorer – 새 탭
- CTRL+N – Internet Explorer – 새 창
- CTRL+O – 파일 열기
- CTRL+S – 저장 CTRL+N – 새 RDP / Citrix

### 스와이프 동작

- 왼쪽에서 오른쪽으로 스와이프하면 모든 열린 창이 표시되어 KIOSK 앱이 최소화되고 OS 전체에 직접 접근할 수 있습니다;
- 오른쪽에서 왼쪽으로 스와이프하면 Action Center가 열려 KIOSK 앱이 최소화되고 OS 전체에 직접 접근할 수 있습니다;
- 상단 가장자리에서 안쪽으로 스와이프하면 전체 화면 모드로 열린 앱의 제목 표시줄이 보입니다;
- 하단에서 위로 스와이프하면 전체 화면 앱에서 작업 표시줄이 표시됩니다.

### Internet Explorer 팁

#### 'Image Toolbar'

이미지를 클릭하면 왼쪽 상단에 나타나는 툴바입니다. 저장(Save), 인쇄(Print), Mailto, Explorer에서 "My Pictures" 열기 등을 할 수 있습니다. Kiosk는 Internet Explorer를 사용해야 합니다.

#### Shell 프로토콜

다음 URL들을 입력하면 Explorer 뷰를 얻을 수 있습니다:

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> 제어판
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> 내 PC
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> 네트워크 위치
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### 파일 확장자 표시

자세한 정보는 이 페이지를 확인하세요: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## 브라우저 팁

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScript로 공통 대화상자를 생성하고 파일 탐색기에 접근: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### 제스처 및 버튼

- 네 손가락(또는 다섯 손가락)으로 위로 스와이프 / 홈 버튼 더블탭: 멀티태스킹 보기로 전환하여 앱 변경
- 네 손가락 또는 다섯 손가락으로 좌우로 스와이프: 다음/이전 앱으로 전환
- 다섯 손가락으로 화면을 집는 동작 / 홈 버튼 누르기 / 화면 하단에서 한 손가락으로 빠르게 위로 스와이프: 홈으로 이동
- 화면 하단에서 한 손가락을 1-2인치만 천천히 스와이프: Dock이 나타남
- 화면 상단에서 한 손가락으로 아래로 스와이프: 알림 보기
- 화면 우측 상단에서 한 손가락으로 아래로 스와이프: iPad Pro의 제어 센터 보기
- 화면 왼쪽에서 한 손가락으로 1-2인치 스와이프: Today 보기를 보기
- 화면 중앙에서 오른쪽 또는 왼쪽으로 빠르게 한 손가락으로 스와이프: 다음/이전 앱으로 전환
- 상단 우측의 전원(On/Off/Sleep) 버튼을 누르고 길게 누른 후 Slide to power off 슬라이더를 오른쪽으로 끝까지 이동: 전원 끄기
- 상단 우측의 전원 버튼과 홈 버튼을 몇 초간 함께 누르기: 강제 하드 파워오프
- 상단 우측의 전원 버튼과 홈 버튼을 빠르게 누르기: 왼쪽 하단에 미리보기로 나타나는 스크린샷 캡처. 버튼을 아주 짧게 동시에 누르면 스크린샷이 되고, 몇 초간 누르면 하드 파워오프가 수행됩니다.

### 단축키

iPad용 키보드나 USB 키보드 어댑터를 사용하는 것이 좋습니다. 여기에서는 애플리케이션에서 벗어나는 데 도움이 될 수 있는 단축키만 표시합니다.

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

이 단축키들은 시각 설정 및 사운드 설정과 관련되며 iPad 사용 방식에 따라 다릅니다.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 화면 밝기 감소                                                                  |
| F2       | 화면 밝기 증가                                                                  |
| F7       | 이전 곡                                                                         |
| F8       | 재생/일시정지                                                                   |
| F9       | 다음 곡                                                                         |
| F10      | 음소거                                                                          |
| F11      | 볼륨 감소                                                                        |
| F12      | 볼륨 증가                                                                        |
| ⌘ Space  | 사용 가능한 언어 목록을 표시합니다; 선택하려면 스페이스 바를 한 번 더 누르세요. |

#### iPad 내비게이션

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | 홈으로 이동                                             |
| ⌘⇧H (Command-Shift-H)                              | 홈으로 이동                                             |
| ⌘ (Space)                                          | Spotlight 열기                                          |
| ⌘⇥ (Command-Tab)                                   | 최근 사용한 앱 10개 목록                                |
| ⌘\~                                                | 마지막 앱으로 이동                                      |
| ⌘⇧3 (Command-Shift-3)                              | 스크린샷 (화면 왼쪽 하단에 나타나 저장 또는 작업 가능)    |
| ⌘⇧4                                                | 스크린샷을 찍고 편집기로 열기                            |
| Press and hold ⌘                                   | 앱에서 사용 가능한 단축키 목록 보기                      |
| ⌘⌥D (Command-Option/Alt-D)                         | Dock 표시                                               |
| ^⌥H (Control-Option-H)                             | 홈 버튼                                                 |
| ^⌥H H (Control-Option-H-H)                         | 멀티태스크 바 표시                                       |
| ^⌥I (Control-Option-i)                             | 항목 선택기                                             |
| Escape                                             | 뒤로                                                    |
| → (Right arrow)                                    | 다음 항목                                               |
| ← (Left arrow)                                     | 이전 항목                                               |
| ↑↓ (Up arrow, Down arrow)                          | 선택된 항목를 동시에 탭                                  |
| ⌥ ↓ (Option-Down arrow)                            | 아래로 스크롤                                           |
| ⌥↑ (Option-Up arrow)                               | 위로 스크롤                                             |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | 왼쪽 또는 오른쪽으로 스크롤                              |
| ^⌥S (Control-Option-S)                             | VoiceOver 음성 켜기/끄기                                 |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 이전 앱으로 전환                                        |
| ⌘⇥ (Command-Tab)                                   | 원래 앱으로 되돌아가기                                  |
| ←+→, then Option + ← or Option+→                   | Dock을 통해 탐색                                        |

#### Safari 단축키

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | 위치 열기                                        |
| ⌘T                      | 새 탭 열기                                       |
| ⌘W                      | 현재 탭 닫기                                     |
| ⌘R                      | 현재 탭 새로고침                                  |
| ⌘.                      | 현재 탭 로딩 중지                                 |
| ^⇥                      | 다음 탭으로 전환                                  |
| ^⇧⇥ (Control-Shift-Tab) | 이전 탭으로 이동                                  |
| ⌘L                      | 텍스트 입력/URL 필드 선택하여 수정               |
| ⌘⇧T (Command-Shift-T)   | 마지막에 닫은 탭 열기 (여러 번 사용 가능)         |
| ⌘\[                     | 브라우징 히스토리에서 한 페이지 뒤로              |
| ⌘]                      | 브라우징 히스토리에서 한 페이지 앞으로            |
| ⌘⇧R                     | Reader 모드 활성화                                |

#### Mail 단축키

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | 위치 열기                    |
| ⌘T                         | 새 탭 열기                   |
| ⌘W                         | 현재 탭 닫기                 |
| ⌘R                         | 현재 탭 새로고침              |
| ⌘.                         | 현재 탭 로딩 중지             |
| ⌘⌥F (Command-Option/Alt-F) | 메일박스에서 검색             |

## 참고자료

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
