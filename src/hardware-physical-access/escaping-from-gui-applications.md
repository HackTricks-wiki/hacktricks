# KIOSKsからの脱出

{{#include ../banners/hacktricks-training.md}}

---

## 物理デバイスを確認する

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| 電源ボタン | デバイスの電源を一度オフにしてからオンにすると、スタート画面が表示される場合がある    |
| 電源ケーブル  | 電源を短時間切断したときにデバイスが再起動するか確認する |
| USBポート    | より多くのショートカットを使用できる物理キーボードを接続する                      |
| Ethernet     | Network scanまたはsniffingにより、さらなるexploitが可能になる場合がある           |

## GUIアプリケーション内で可能な操作を確認する

**Common Dialogs**とは、**ファイルの保存**、**ファイルを開く**、フォントや色の選択などのオプションのことです。これらの多くは**完全なExplorer機能**を提供します。つまり、以下のオプションにアクセスできれば、Explorerの機能にアクセスできます。

- 閉じる／別名で閉じる
- 開く／アプリケーションを指定して開く
- 印刷
- Export/Import
- Search
- Scan

以下が可能か確認してください。

- ファイルを変更または新規作成する
- symbolic linksを作成する
- 制限された領域にアクセスする
- 他のアプリを実行する

### Command Execution

**`Open with`オプションを使用して**、何らかのshellを開く／実行できる場合があります。

#### Windows

たとえば、_cmd.exe、command.com、Powershell/Powershell ISE、mmc.exe、at.exe、taskschd.msc..._ などです。commandsを実行できる（および想定外の操作を実行できる）その他のbinariesについては、こちらを参照してください: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash、sh、zsh..._ 詳細はこちら: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### path restrictionsのBypassing

- **Environment variables**: いくつものenvironment variablesが、特定のpathを指している
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N（新しいsessionを開く）、CTRL+R（Execute Commands）、CTRL+SHIFT+ESC（Task Manager）、Windows+E（explorerを開く）、CTRL-B、CTRL-I（Favourites）、CTRL-H（History）、CTRL-L、CTRL-O（File/Open Dialog）、CTRL-P（Print Dialog）、CTRL-S（Save As）
- Hidden Administrative menu: CTRL-ALT-F8、CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: shared foldersに接続するためのpaths。ローカルmachineのC$（"\\\127.0.0.1\c$\Windows\System32"）への接続を試してください
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

- **Dialog-box pivoting**: *Open/Save/Print-to-file*ダイアログをExplorer-liteとして使用します。filename fieldで`*.*` / `*.exe`を試し、folderを右クリックして**Open in new window**を選択し、**Properties → Open file location**を使用してnavigationを拡張します。<sup>[[1]](#references)</sup>
- **Create execution paths from dialogs**: 新しいfileを作成して`.CMD`または`.BAT`にrenameするか、`%WINDIR%\System32`（または`%WINDIR%\System32\cmd.exe`のような特定のbinary）を指すshortcutを作成します。
- **Shell launch pivots**: `cmd.exe`までbrowseできる場合は、任意のfileをそこへ**drag-and-drop**してpromptを起動します。Task Managerにアクセスできる場合（`CTRL+SHIFT+ESC`）は、**Run new task**を使用します。
- **Task Scheduler bypass**: interactive shellsがblockedされていてもschedulingが許可されている場合は、`cmd.exe`を実行するtaskを作成します（GUIの`taskschd.msc`または`schtasks.exe`）。
- **Weak allowlists**: **filename/extension**によってexecutionが許可されている場合は、payloadを許可されたnameにrenameします。**directory**によって許可されている場合は、payloadを許可されたprogram folderにcopyして、そこで実行します。
- **Find writable staging paths**: `%TEMP%`から開始し、Sysinternals AccessChkでwriteableなfolderをenumerateします。
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **次のステップ**: shellを取得した場合は、Windows LPE checklistに移動します:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### バイナリをダウンロード

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### ブラウザからfilesystemにアクセス

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### ショートカット

- Sticky Keys – SHIFTを5回押す
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – NUMLOCKを5秒間押し続ける
- Filter Keys – 右SHIFTを12秒間押し続ける
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Desktopを表示
- WINDOWS+E – Windows Explorerを起動
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – 新しいWindowsバージョンではSplash screen
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Internet Explorer内でfull screenを切り替え
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### スワイプ

- 左側から右側へスワイプすると、開いているすべてのWindowsが表示され、KIOSK appが最小化されてOS全体に直接アクセスできます。
- 右側から左側へスワイプすると、Action Centerが開き、KIOSK appが最小化されてOS全体に直接アクセスできます。
- 上端から内側へスワイプすると、full screen modeで開かれているappのtitle barが表示されます。
- 下端から上へスワイプすると、full screen appでtaskbarが表示されます。

### Internet Explorer Tricks

#### 'Image Toolbar'

画像をクリックすると、画像の左上に表示されるtoolbarです。Save、Print、Mailto、Explorerで"My Pictures"を開く操作が可能になります。KioskはInternet Explorerを使用している必要があります。

#### Shell Protocol

以下のURLを入力してExplorer viewを取得します:

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

### File Extensionsを表示

詳細については、こちらのページを確認してください: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Browsers tricks

iKat versionsのBackup:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScriptを使用してcommon dialogを作成し、file explorerにアクセスします: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### ジェスチャーとボタン

- 4本（または5本）の指で上へスワイプ / Home buttonをダブルタップ: multitask viewを表示してAppを変更
- 4本または5本の指でいずれかの方向へスワイプ: next/last Appへ変更
- 5本の指で画面をピンチ / Home buttonをタッチ / 画面下部から1本の指ですばやく上へスワイプ: Homeにアクセス
- 画面下部から1本の指で1～2インチだけゆっくり上へスワイプ: dockが表示されます
- 1本の指でdisplay上端から下へスワイプ: notificationsを表示
- 画面右上隅を1本の指で下へスワイプ: iPad Proのcontrol centreを表示
- 画面左端から1本の指で1～2インチスワイプ: Today viewを表示
- 画面中央から右または左へ1本の指ですばやくスワイプ: next/last Appへ変更
- iPad右上隅のOn/**Off**/Sleep buttonを長押しし、Slide to **power off** sliderを右端まで移動: power off
- iPad右上隅のOn/**Off**/Sleep buttonとHome buttonを数秒間押す: hard power offを強制実行
- iPad右上隅のOn/**Off**/Sleep buttonとHome buttonをすばやく押す: display左下に表示されるscreenshotを撮影します。両方のbuttonを数秒間押し続けず、非常に短く同時に押してください。数秒間押し続けるとhard power offが実行されます。<sup>[[3]](#references)</sup>

### ショートカット

iPad keyboardまたはUSB keyboard adaptorが必要です。ここでは、applicationから抜け出すのに役立つshortcutのみを示します。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

これらのshortcutは、iPadの用途に応じたvisual settingsおよびsound settings用です。

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Sscreenを暗くする                                                             |
| F2       | screenを明るくする                                                            |
| F7       | 1曲戻る                                                                       |
| F8       | 再生/一時停止                                                                  |
| F9       | 曲をスキップ                                                                   |
| F10      | ミュート                                                                      |
| F11      | volumeを下げる                                                                |
| F12      | volumeを上げる                                                                |
| ⌘ Space  | 使用可能なlanguageのlistを表示。選択するには、もう一度space barをタップします。 |

#### iPad navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Homeへ移動                                              |
| ⌘⇧H (Command-Shift-H)                              | Homeへ移動                                              |
| ⌘ (Space)                                          | Spotlightを開く                                          |
| ⌘⇥ (Command-Tab)                                   | 最後に使用した10個のappを一覧表示                       |
| ⌘\~                                                | 最後のAppへ移動                                         |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot（保存または操作するため、左下にhoverします） |
| ⌘⇧4                                                | Screenshotを撮影し、editorで開く                        |
| Press and hold ⌘                                   | Appで使用可能なshortcutのlist                           |
| ⌘⌥D (Command-Option/Alt-D)                         | dockを表示                                              |
| ^⌥H (Control-Option-H)                             | Home button                                             |
| ^⌥H H (Control-Option-H-H)                         | multitask barを表示                                     |
| ^⌥I (Control-Option-i)                             | Item chooser                                            |
| Escape                                             | Back button                                             |
| → (Right arrow)                                    | 次のitem                                                |
| ← (Left arrow)                                     | 前のitem                                                |
| ↑↓ (Up arrow, Down arrow)                          | 選択したitemを同時にタップ                             |
| ⌥ ↓ (Option-Down arrow)                            | 下へscroll                                              |
| ⌥↑ (Option-Up arrow)                               | 上へscroll                                              |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | 左または右へscroll                                      |
| ^⌥S (Control-Option-S)                             | VoiceOver speechをオンまたはオフ                        |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 前のappに切り替え                                       |
| ⌘⇥ (Command-Tab)                                   | 元のappに戻す                                           |
| ←+→, then Option + ← or Option+→                   | Dock内を移動                                            |

#### Safari shortcuts

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Locationを開く                                   |
| ⌘T                      | 新しいtabを開く                                  |
| ⌘W                      | 現在のtabを閉じる                                |
| ⌘R                      | 現在のtabをRefresh                                |
| ⌘.                      | 現在のtabのloadingを停止                         |
| ^⇥                      | 次のtabに切り替え                                |
| ^⇧⇥ (Control-Shift-Tab) | 前のtabへ移動                                    |
| ⌘L                      | text input/URL fieldを選択して変更               |
| ⌘⇧T (Command-Shift-T)   | 最後に閉じたtabを開く（複数回使用可能）         |
| ⌘\[                     | browsing historyで1ページ戻る                    |
| ⌘]                      | browsing historyで1ページ進む                    |
| ⌘⇧R                     | Reader Modeを有効化                              |

#### Mail shortcuts

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Locationを開く                |
| ⌘T                         | 新しいtabを開く               |
| ⌘W                         | 現在のtabを閉じる             |
| ⌘R                         | 現在のtabをRefresh             |
| ⌘.                         | 現在のtabのloadingを停止       |
| ⌘⌥F (Command-Option/Alt-F) | mailbox内を検索               |

## References

- [1] [Citrixおよびその他のRestricted Desktop Environmentsから抜け出す](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [browserを与えてくれれば、shellを与える](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [知っておくべきiPad専用ジェスチャー6選](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Windows ExplorerでFile Extensionsを表示](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
