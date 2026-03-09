# KIOSKからの脱出

{{#include ../banners/hacktricks-training.md}}

---

## 物理デバイスの確認

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | デバイスの電源を一度切って再度入れるとスタート画面が表示される場合がある |
| Power cable  | 電源を短時間切ったときにデバイスが再起動するか確認する             |
| USB ports    | ショートカットが多い物理キーボードを接続する                       |
| Ethernet     | ネットワークスキャンやスニッフィングで追加の攻撃が可能になる場合がある |

## GUIアプリケーション内で可能な操作の確認

**Common Dialogs** は **ファイルの保存**、**ファイルの開く**、フォントや色の選択などのオプションです。多くは **フルの Explorer 機能** を提供します。つまり、これらのオプションにアクセスできれば Explorer の機能にアクセスできることを意味します:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

以下を確認してください:

- ファイルを修正または新規作成できるか
- シンボリックリンクを作成できるか
- 制限された領域にアクセスできるか
- 他のアプリを実行できるか

### コマンド実行

場合によっては **using a `Open with`** option\*\* 何らかのシェルを開いたり実行したりできるかもしれません。

#### Windows

例えば _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._。コマンドを実行するために使える他のバイナリ（予期しない動作を引き起こす可能性もある）はここで確認してください: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._。詳細はこちら: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### パス制限の回避

- **Environment variables**: 多くの環境変数が特定のパスを指しています
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N（新しいセッションを開く）, CTRL+R（Execute Commands）, CTRL+SHIFT+ESC（Task Manager）, Windows+E（explorer を開く）, CTRL-B, CTRL-I（Favourites）, CTRL-H（History）, CTRL-L, CTRL-O（File/Open Dialog）, CTRL-P（Print Dialog）, CTRL-S（Save As）
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: 共有フォルダに接続するためのパス。ローカルマシンの C$ ("\\\127.0.0.1\c$\Windows\System32") に接続できるか試すべきです
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

- **Dialog-box pivoting**: *Open/Save/Print-to-file* ダイアログを Explorer-lite として使用します。ファイル名フィールドに `*.*` / `*.exe` を試し、フォルダを右クリックして **Open in new window** を選び、**Properties → Open file location** を使ってナビゲーションを拡張します。
- **Create execution paths from dialogs**: 新しいファイルを作成して `.CMD` や `.BAT` にリネームする、または `%WINDIR%\System32`（または `%WINDIR%\System32\cmd.exe` のような特定のバイナリ）を指すショートカットを作成します。
- **Shell launch pivots**: もし `cmd.exe` に移動できるなら、任意のファイルをそこへ **drag-and-drop** してプロンプトを起動してみてください。Task Manager にアクセスできる場合（`CTRL+SHIFT+ESC`）、**Run new task** を使用します。
- **Task Scheduler bypass**: インタラクティブシェルが遮断されているがスケジューリングが許可されている場合、`cmd.exe` を実行するタスクを作成します（GUI `taskschd.msc` または `schtasks.exe`）。
- **Weak allowlists**: 実行が **filename/extension** によって許可されている場合、ペイロードの名前を許可された名前に変更します。**directory** によって許可されている場合、ペイロードを許可されたプログラムフォルダにコピーしてそこで実行します。
- **Find writable staging paths**: まず `%TEMP%` から始め、Sysinternals AccessChk で書き込み可能なフォルダを列挙します。
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

- Sticky Keys – SHIFTを5回押す
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – NUMLOCKを5秒間押し続ける
- Filter Keys – 右SHIFTを12秒間押し続ける
- WINDOWS+F1 – Windows Search
- WINDOWS+D – デスクトップを表示
- WINDOWS+E – Windows Explorerを起動
- WINDOWS+R – 実行
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – 検索
- SHIFT+F10 – コンテキストメニュー
- CTRL+SHIFT+ESC – タスクマネージャ
- CTRL+ALT+DEL – 新しいWindowsバージョンのスプラッシュ画面
- F1 – ヘルプ F3 – 検索
- F6 – アドレスバー
- F11 – Internet Explorer内で全画面を切替
- CTRL+H – Internet Explorerの履歴
- CTRL+T – Internet Explorer – 新しいタブ
- CTRL+N – Internet Explorer – 新しいページ
- CTRL+O – ファイルを開く
- CTRL+S – 保存 CTRL+N – 新しいRDP / Citrix

### Swipes

- 左端から右へスワイプすると、開いているすべてのウィンドウが表示され、KIOSKアプリが最小化されてOS全体に直接アクセスできます；
- 右端から左へスワイプすると、アクションセンターが開き、KIOSKアプリが最小化されてOS全体に直接アクセスできます；
- 上端からスワイプインすると、フルスクリーンモードで開かれているアプリのタイトルバーを表示します；
- 下から上にスワイプすると、フルスクリーンアプリでタスクバーを表示します。

### Internet Explorer Tricks

#### 'Image Toolbar'

画像をクリックすると左上に表示されるツールバーです。Save、Print、Mailto、「My Pictures」をExplorerで開くことができます。KioskはInternet Explorerを使用している必要があります。

#### Shell Protocol

以下のURLを入力するとExplorerビューを開けます:

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> コントロールパネル
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> マイコンピュータ
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> マイ ネットワークプレース
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Show File Extensions

詳細はこのページを確認してください: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Browsers tricks

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScriptを使って共通のダイアログを作成し、ファイルエクスプローラにアクセスする: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestures and bottoms

- 4本（または5本）指で上にスワイプ / Homeボタンをダブルタップ: マルチタスクビューを表示してアプリを切り替える
- 4本または5本指で左右にスワイプ: 次/前のアプリに切り替える
- 5本指でピンチ / Homeボタンに触れる / 下から1本指で素早く上にスワイプ: ホームに戻る
- 下縁から1本指で1〜2インチ（ゆっくり）スワイプ: Dockが表示される
- 画面上部から1本指で下にスワイプ: 通知を表示
- 画面右上から1本指で下にスワイプ: iPad Proのコントロールセンターを表示
- 画面左から1本指で1〜2インチスワイプ: Todayビューを表示
- 画面中央から右または左へ1本指で素早くスワイプ: 次/前のアプリに切り替える
- iPadの右上にあるOn/Off/Sleepボタンを長押しし、スライダーを右端まで移動: 電源オフ
- iPadの右上にあるOn/Off/SleepボタンとHomeボタンを数秒間押し続ける: 強制シャットダウン
- iPadの右上にあるOn/Off/SleepボタンとHomeボタンを素早く押す: 画面キャプチャ（画面左下にポップアップ表示）。両方のボタンを同時に数秒間押し続けると強制シャットダウンになります。

### Shortcuts

iPad用キーボードかUSBキーボードアダプタを用意してください。ここではアプリからの脱出に役立つショートカットのみを示します。

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

これらのショートカットはiPadの画面表示や音に関する設定用です。

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 画面を暗くする                                                                  |
| F2       | 画面を明るくする                                                                |
| F7       | 1曲戻る                                                                         |
| F8       | 再生/一時停止                                                                   |
| F9       | 曲をスキップ                                                                    |
| F10      | ミュート                                                                         |
| F11      | 音量を下げる                                                                    |
| F12      | 音量を上げる                                                                    |
| ⌘ Space  | 利用可能な言語の一覧を表示; 選択するにはもう一度Spaceキーをタップしてください。 |

#### iPad navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | ホームへ移動                                            |
| ⌘⇧H (Command-Shift-H)                              | ホームへ移動                                            |
| ⌘ (Space)                                          | Spotlightを開く                                        |
| ⌘⇥ (Command-Tab)                                   | 最近使ったアプリ上位10件を一覧表示                      |
| ⌘\~                                                | 最後に使っていたアプリへ移動                            |
| ⌘⇧3 (Command-Shift-3)                              | スクリーンショット（左下に表示され、保存や操作が可能）  |
| ⌘⇧4                                                | スクリーンショットを撮り、エディタで開く               |
| Press and hold ⌘                                   | アプリで利用可能なショートカットの一覧を表示            |
| ⌘⌥D (Command-Option/Alt-D)                         | Dockを表示                                             |
| ^⌥H (Control-Option-H)                             | Homeボタン                                             |
| ^⌥H H (Control-Option-H-H)                         | マルチタスクバーを表示                                 |
| ^⌥I (Control-Option-i)                             | アイテム選択                                            |
| Escape                                             | 戻るボタン                                              |
| → (Right arrow)                                    | 次のアイテム                                            |
| ← (Left arrow)                                     | 前のアイテム                                            |
| ↑↓ (Up arrow, Down arrow)                          | 選択中のアイテムを同時にタップ                          |
| ⌥ ↓ (Option-Down arrow)                            | 下にスクロール                                          |
| ⌥↑ (Option-Up arrow)                               | 上にスクロール                                          |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | 左右にスクロール                                        |
| ^⌥S (Control-Option-S)                             | VoiceOverの読み上げをオン/オフ                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 前のアプリに切り替え                                    |
| ⌘⇥ (Command-Tab)                                   | 元のアプリに戻る                                        |
| ←+→, then Option + ← or Option+→                   | Dock内をナビゲート                                      |

#### Safari shortcuts

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | ロケーションを開く                               |
| ⌘T                      | 新しいタブを開く                                 |
| ⌘W                      | 現在のタブを閉じる                               |
| ⌘R                      | 現在のタブをリロード                             |
| ⌘.                      | 現在のタブの読み込みを停止                       |
| ^⇥                      | 次のタブに切り替え                               |
| ^⇧⇥ (Control-Shift-Tab) | 前のタブに移動                                   |
| ⌘L                      | テキスト入力/URLフィールドを選択して編集         |
| ⌘⇧T (Command-Shift-T)   | 最後に閉じたタブを開く（何度でも可能）           |
| ⌘\[                     | 閲覧履歴で1ページ戻る                            |
| ⌘]                      | 閲覧履歴で1ページ進む                            |
| ⌘⇧R                     | リーダーモードを有効にする                      |

#### Mail shortcuts

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | ロケーションを開く          |
| ⌘T                         | 新しいタブを開く            |
| ⌘W                         | 現在のタブを閉じる          |
| ⌘R                         | 現在のタブをリフレッシュ    |
| ⌘.                         | 現在のタブの読み込みを停止  |
| ⌘⌥F (Command-Option/Alt-F) | メールボックス内を検索      |

## References

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
