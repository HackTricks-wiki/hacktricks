# KIOSK에서 탈출

{{#include ../banners/hacktricks-training.md}}

---

## 물리적 장치 확인

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | 장치를 껐다가 다시 켜면 시작 화면이 표시될 수 있습니다             |
| Power cable  | 전원을 잠깐 차단했을 때 장치가 재부팅되는지 확인하세요             |
| USB ports    | 더 많은 단축키를 가진 물리적 키보드를 연결해 보세요               |
| Ethernet     | 네트워크 스캔이나 스니핑으로 추가적인 공격 가능성이 생길 수 있습니다 |

## GUI 애플리케이션 내에서 가능한 동작 확인

**Common Dialogs**는 파일 저장, 파일 열기, 글꼴 선택, 색상 선택 등과 같은 옵션들입니다. 대부분의 경우 이러한 옵션들은 **full Explorer functionality**를 제공합니다. 즉, 이러한 옵션들에 접근할 수 있다면 Explorer 기능에 접근할 수 있습니다.

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

다음 사항들을 확인해야 합니다:

- 파일을 수정하거나 새로 생성할 수 있는지
- 심볼릭 링크를 생성할 수 있는지
- 제한된 영역에 접근할 수 있는지
- 다른 앱을 실행할 수 있는지

### 명령 실행

아마도 **`Open with`** 옵션을 사용하면 어떤 종류의 쉘을 열거나 실행할 수 있습니다.

#### Windows

예: _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ 같은 바이너리들이 명령을 실행(및 예기치 않은 동작 수행)하는 데 사용될 수 있습니다. 더 많은 바이너리는 여기에서 확인하세요: [https://lolbas-project.github.io/](https://lolbas-project.github.io/)

#### \*NIX \_\_

_bash, sh, zsh..._ 자세한 내용은: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### 경로 제한 우회

- **Environment variables**: 여러 환경 변수가 특정 경로를 가리키고 있습니다
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (새 세션 열기), CTRL+R (명령 실행), CTRL+SHIFT+ESC (작업 관리자), Windows+E (Explorer 열기), CTRL-B, CTRL-I (즐겨찾기), CTRL-H (히스토리), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: 공유 폴더에 연결하기 위한 경로입니다. 로컬 머신의 C$에 연결해 보세요 ("\\\127.0.0.1\c$\Windows\System32")
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

### 제한된 데스크톱 탈출 (Citrix/RDS/VDI)

- **Dialog-box pivoting**: `Open/Save/Print-to-file` 대화상자를 Explorer-lite로 사용하세요. 파일명 필드에 `*.*` / `*.exe`를 입력하고, 폴더를 우클릭하여 **Open in new window**를 시도하며 **Properties → Open file location**을 사용해 탐색을 확장하세요.
- **Create execution paths from dialogs**: 새 파일을 만들고 파일명을 `.CMD` 또는 `.BAT`로 바꾸거나 `%WINDIR%\System32`(또는 `%WINDIR%\System32\cmd.exe` 같은 특정 바이너리)를 가리키는 바로가기를 만드세요.
- **Shell launch pivots**: `cmd.exe`로 이동할 수 있다면, 어떤 파일이든 드래그 앤 드롭해 프롬프트를 실행해 보세요. Task Manager(`CTRL+SHIFT+ESC`)에 접근할 수 있으면 **Run new task**를 사용하세요.
- **Task Scheduler bypass**: 인터랙티브 쉘이 차단되어 있지만 스케줄링이 허용된다면, `cmd.exe`를 실행하도록 작업을 만드세요 (GUI `taskschd.msc` 또는 `schtasks.exe`).
- **Weak allowlists**: 실행이 파일명/확장자로 허용된다면, 페이로드의 이름을 허용되는 이름으로 바꾸세요. 디렉터리 기준으로 허용된다면 페이로드를 허용된 프로그램 폴더로 복사해 그곳에서 실행하세요.
- **Find writable staging paths**: `%TEMP%`부터 시작하여 쓰기 가능한 폴더를 열거하고 Sysinternals AccessChk로 확인하세요.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Next step**: If you gain a shell, pivot to the Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Download Your Binaries

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Accessing filesystem from the browser

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### ShortCuts

- Sticky Keys – Press SHIFT 5 times
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Hold NUMLOCK for 5 seconds
- Filter Keys – Hold right SHIFT for 12 seconds
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Show Desktop
- WINDOWS+E – Launch Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen on newer Windows versions
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Toggle full screen within Internet Explorer
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Swipes

- Swipe from the left side to the right to see all open Windows, minimizing the KIOSK app and accessing the whole OS directly;
- Swipe from the right side to the left to open Action Center, minimizing the KIOSK app and accessing the whole OS directly;
- Swipe in from the top edge to make the title bar visible for an app opened in full screen mode;
- Swipe up from the bottom to show the taskbar in a full screen app.

### Internet Explorer Tricks

#### 'Image Toolbar'

It's a toolbar that appears on the top-left of image when it's clicked. You will be able to Save, Print, Mailto, Open "My Pictures" in Explorer. The Kiosk needs to be using Internet Explorer.

#### Shell Protocol

Type this URLs to obtain an Explorer view:

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

### Show File Extensions

Check this page for more information: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Browsers tricks

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Create a common dialog using JavaScript and access file explorer: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestures and bottoms

- Swipe up with four (or five) fingers / Double-tap Home button: To view the multitask view and change App
- Swipe one way or another with four or five fingers: In order to change to the next/last App
- Pinch the screen with five fingers / Touch Home button / Swipe up with 1 finger from the bottom of the screen in a quick motion to the up: To access Home
- Swipe one finger from the bottom of the screen just 1-2 inches (slow): The dock will appear
- Swipe down from the top of the display with 1 finger: To view your notifications
- Swipe down with 1 finger the top-right corner of the screen: To see iPad Pro's control centre
- Swipe 1 finger from the left of the screen 1-2 inches: To see Today view
- Swipe fast 1 finger from the centre of the screen to the right or left: To change to next/last App
- Press and hold the On/**Off**/Sleep button at the upper-right corner of the **iPad +** Move the Slide to **power off** slider all the way to the right: To power off
- Press the On/**Off**/Sleep button at the upper-right corner of the **iPad and the Home button for a few second**: To force a hard power off
- Press the On/**Off**/Sleep button at the upper-right corner of the **iPad and the Home button quickly**: To take a screenshot that will pop up in the lower left of the display. Press both buttons at the same time very briefly as if you hold them a few seconds a hard power off will be performed.

### Shortcuts

You should have an iPad keyboard or a USB keyboard adaptor. Only shortcuts that could help escaping from the application will be shown here.

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

#### System shortcuts

These shortcuts are for the visual settings and sound settings, depending on the use of the iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Dim Sscreen                                                                    |
| F2       | Brighten screen                                                                |
| F7       | Back one song                                                                  |
| F8       | Play/pause                                                                     |
| F9       | Skip song                                                                      |
| F10      | Mute                                                                           |
| F11      | Decrease volume                                                                |
| F12      | Increase volume                                                                |
| ⌘ Space  | Display a list of available languages; to choose one, tap the space bar again. |

#### iPad navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Go to Home                                              |
| ⌘⇧H (Command-Shift-H)                              | Go to Home                                              |
| ⌘ (Space)                                          | Open Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | List last ten used apps                                 |
| ⌘\~                                                | Go t the last App                                       |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (hovers in bottom left to save or act on it) |
| ⌘⇧4                                                | Screenshot and open it in the editor                    |
| Press and hold ⌘                                   | List of shortcuts available for the App                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Brings up the dock                                      |
| ^⌥H (Control-Option-H)                             | Home button                                             |
| ^⌥H H (Control-Option-H-H)                         | Show multitask bar                                      |
| ^⌥I (Control-Option-i)                             | Item chooser                                            |
| Escape                                             | Back button                                             |
| → (Right arrow)                                    | Next item                                               |
| ← (Left arrow)                                     | Previous item                                           |
| ↑↓ (Up arrow, Down arrow)                          | Simultaneously tap selected item                        |
| ⌥ ↓ (Option-Down arrow)                            | Scroll down                                             |
| ⌥↑ (Option-Up arrow)                               | Scroll up                                               |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Scroll left or right                                    |
| ^⌥S (Control-Option-S)                             | Turn VoiceOver speech on or off                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Switch to the previous app                              |
| ⌘⇥ (Command-Tab)                                   | Switch back to the original app                         |
| ←+→, then Option + ← or Option+→                   | Navigate through Dock                                   |

#### Safari shortcuts

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Open Location                                    |
| ⌘T                      | Open a new tab                                   |
| ⌘W                      | Close the current tab                            |
| ⌘R                      | Refresh the current tab                          |
| ⌘.                      | Stop loading the current tab                     |
| ^⇥                      | Switch to the next tab                           |
| ^⇧⇥ (Control-Shift-Tab) | Move to the previous tab                         |
| ⌘L                      | Select the text input/URL field to modify it     |
| ⌘⇧T (Command-Shift-T)   | Open last closed tab (can be used several times) |
| ⌘\[                     | Goes back one page in your browsing history      |
| ⌘]                      | Goes forward one page in your browsing history   |
| ⌘⇧R                     | Activate Reader Mode                             |

#### Mail shortcuts

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Open Location                |
| ⌘T                         | Open a new tab               |
| ⌘W                         | Close the current tab        |
| ⌘R                         | Refresh the current tab      |
| ⌘.                         | Stop loading the current tab |
| ⌘⌥F (Command-Option/Alt-F) | Search in your mailbox       |

## References

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
