# KIOSKからの脱出

{{#include ../banners/hacktricks-training.md}}

---

## 物理デバイスの確認

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | デバイスの電源を一度切って再度入れるとスタート画面が表示される場合がある |
| Power cable  | 電源を一時的に切ったときにデバイスが再起動するか確認する                   |
| USB ports    | 追加のショートカットが使える物理キーボードを接続する                     |
| Ethernet     | ネットワークスキャンやスニッフィングでさらなる攻撃が可能になる場合がある   |

## GUIアプリケーション内で可能な操作の確認

**Common Dialogs** は **saving a file**, **opening a file**, フォント選択や色選択などのオプションです。ほとんどは **full Explorer functionality** を提供します。これは、これらのオプションにアクセスできれば Explorer の機能にアクセスできることを意味します:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

次を確認してください:

- ファイルを修正または新規作成できるか
- シンボリックリンクを作成できるか
- 制限された領域にアクセスできるか
- 他のアプリを実行できるか

### コマンド実行

おそらく **using a `Open with`** オプション\*\* を使って何らかのシェルを開いたり実行したりできるかもしれません。

#### Windows

例えば _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._。コマンドを実行する（および予期しない動作を引き起こす）ために利用できるバイナリの一覧はここで確認してください: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ 詳細はこちら: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### パス制限の回避

- **Environment variables**: 多くの環境変数が特定のパスを指しています
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **シンボリックリンク**
- **Shortcuts**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- 隠し管理メニュー: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: 共有フォルダに接続するためのパス。ローカルマシンの C$ に接続してみてください ("\\\127.0.0.1\c$\Windows\System32")
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

### 制限されたデスクトップからの脱出 (Citrix/RDS/VDI)

- **Dialog-box pivoting**: *Open/Save/Print-to-file* ダイアログを Explorer ライトとして利用します。ファイル名欄に `*.*` / `*.exe` を試し、フォルダを右クリックして **Open in new window** を選び、**Properties → Open file location** を使ってナビゲーションを拡張します。
- **Create execution paths from dialogs**: 新しいファイルを作成して `.CMD` や `.BAT` にリネームする、または `%WINDIR%\System32`（または `%WINDIR%\System32\cmd.exe` のような特定のバイナリ）を指すショートカットを作成します。
- **Shell launch pivots**: `cmd.exe` まで参照可能であれば、任意のファイルをそれに **drag-and-drop** してプロンプトを起動してみてください。Task Manager にアクセス可能（`CTRL+SHIFT+ESC`）なら **Run new task** を使います。
- **Task Scheduler bypass**: 対話型シェルがブロックされていてもスケジューリングが許可されている場合は、`cmd.exe` を実行するタスクを作成します（GUI `taskschd.msc` または `schtasks.exe`）。
- **Weak allowlists**: 実行が **filename/extension** で許可されている場合は、ペイロードの名前を許可された名前に変更します。**directory** で許可されている場合は、許可されたプログラムフォルダにペイロードをコピーしてそこで実行します。
- **Find writable staging paths**: まずは `%TEMP%` から始め、Sysinternals AccessChk で書き込み可能なフォルダを列挙します。
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Next step**: シェルを取得できたら、Windows LPE チェックリストに移行してください：
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

- Sticky Keys – SHIFT を 5 回押す
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – NUMLOCK を 5 秒間押し続ける
- Filter Keys – 右 SHIFT を 12 秒間押し続ける
- WINDOWS+F1 – Windows 検索
- WINDOWS+D – デスクトップを表示
- WINDOWS+E – Windows Explorer を起動
- WINDOWS+R – 実行
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – 検索
- SHIFT+F10 – コンテキストメニュー
- CTRL+SHIFT+ESC – タスクマネージャー
- CTRL+ALT+DEL – 新しい Windows バージョンのスプラッシュ画面
- F1 – ヘルプ F3 – 検索
- F6 – アドレスバー
- F11 – Internet Explorer 内で全画面切替
- CTRL+H – Internet Explorer 履歴
- CTRL+T – Internet Explorer – 新しいタブ
- CTRL+N – Internet Explorer – 新しいページ
- CTRL+O – ファイルを開く
- CTRL+S – 保存 CTRL+N – 新しい RDP / Citrix

### Swipes

- 左端から右へスワイプすると、すべての開いているウィンドウが表示され、KIOSK アプリが最小化されて OS 全体に直接アクセスできます；
- 右端から左へスワイプすると、アクションセンターが開き、KIOSK アプリが最小化されて OS 全体に直接アクセスできます；
- 上端から内側へスワイプすると、全画面表示のアプリのタイトルバーが表示されます；
- 下から上へスワイプすると、全画面アプリでタスクバーが表示されます。

### Internet Explorer Tricks

#### 'Image Toolbar'

画像をクリックすると左上に表示されるツールバーです。Save、Print、Mailto、Explorer で "My Pictures" を開くことができます。Kiosk は Internet Explorer を使用している必要があります。

#### Shell Protocol

Explorer ビューを取得するために次の URL を入力します:

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

詳細はこのページを参照してください: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Browsers tricks

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

JavaScript を使って共通のダイアログを作成し、ファイルエクスプローラーにアクセスする: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestures and bottoms

- 4 本（または 5 本）の指で上にスワイプ / Home ボタンをダブルタップ: マルチタスクビューを表示して App を切り替える
- 4 本または 5 本の指で左右にスワイプ: 次/前の App に切り替える
- 5 本の指で画面をピンチ / Home ボタンをタッチ / 下から 1 本の指で素早く上にスワイプ: Home にアクセスする
- 画面下端から 1 本の指でゆっくり 1–2 インチだけスワイプ: ドックが表示される
- 画面上端から 1 本の指で下にスワイプ: 通知を表示する
- 画面右上の角を 1 本の指で下にスワイプ: iPad Pro のコントロールセンターを表示する
- 画面左から 1 本の指で 1–2 インチスワイプ: Today ビューを表示する
- 画面中央から右または左へ素早く 1 本の指でスワイプ: 次/前の App に切り替える
- 上部右角の On/**Off**/Sleep ボタンを押し続ける + **iPad +** のスライドで **power off** を右端まで動かす: 電源オフ
- 上部右角の On/**Off**/Sleep ボタンと Home ボタンを数秒間同時に押す: 強制シャットダウン
- 上部右角の On/**Off**/Sleep ボタンと Home ボタンを素早く同時に押す: スクリーンショットを撮影（左下にプレビューが出現）。両方のボタンを数秒間長押しすると強制シャットダウンになります。

### Shortcuts

iPad 用キーボードまたは USB キーボードアダプタが必要です。ここでは、アプリから脱出するのに役立つショートカットのみを示します。

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

これらのショートカットは視覚設定やサウンド設定に関するもので、iPad の使用方法に応じて機能します。

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 画面を暗くする                                                                 |
| F2       | 画面を明るくする                                                               |
| F7       | 前の曲に戻る                                                                   |
| F8       | 再生/一時停止                                                                  |
| F9       | 次の曲へスキップ                                                               |
| F10      | ミュート                                                                       |
| F11      | 音量を下げる                                                                   |
| F12      | 音量を上げる                                                                   |
| ⌘ Space  | 利用可能な言語の一覧を表示；選択するにはもう一度スペースバーを押します。        |

#### iPad navigation

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Home に移動                                             |
| ⌘⇧H (Command-Shift-H)                              | Home に移動                                             |
| ⌘ (Space)                                          | Spotlight を開く                                        |
| ⌘⇥ (Command-Tab)                                   | 最後に使用した 10 個のアプリを一覧表示                 |
| ⌘\~                                                | 最後に使ったアプリに戻る                                |
| ⌘⇧3 (Command-Shift-3)                              | スクリーンショット（左下に表示され、保存や操作が可能）  |
| ⌘⇧4                                                | スクリーンショットを撮ってエディタで開く               |
| Press and hold ⌘                                   | アプリで利用可能なショートカット一覧を表示             |
| ⌘⌥D (Command-Option/Alt-D)                         | ドックを表示                                           |
| ^⌥H (Control-Option-H)                             | Home ボタン                                            |
| ^⌥H H (Control-Option-H-H)                         | マルチタスクバーを表示                                 |
| ^⌥I (Control-Option-i)                             | アイテムチューザー                                     |
| Escape                                             | 戻るボタン                                              |
| → (Right arrow)                                    | 次のアイテム                                            |
| ← (Left arrow)                                     | 前のアイテム                                            |
| ↑↓ (Up arrow, Down arrow)                          | 選択中のアイテムを同時にタップ                          |
| ⌥ ↓ (Option-Down arrow)                            | 下にスクロール                                         |
| ⌥↑ (Option-Up arrow)                               | 上にスクロール                                         |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | 左右にスクロール                                       |
| ^⌥S (Control-Option-S)                             | VoiceOver の音声をオン/オフ                            |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 前のアプリに切り替え                                   |
| ⌘⇥ (Command-Tab)                                   | 元のアプリに戻る                                       |
| ←+→, then Option + ← or Option+→                   | Dock をナビゲート                                      |

#### Safari shortcuts

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | ロケーションを開く                               |
| ⌘T                      | 新しいタブを開く                                 |
| ⌘W                      | 現在のタブを閉じる                               |
| ⌘R                      | 現在のタブを更新                                 |
| ⌘.                      | 現在のタブの読み込みを停止                       |
| ^⇥                      | 次のタブに切り替え                               |
| ^⇧⇥ (Control-Shift-Tab) | 前のタブに移動                                   |
| ⌘L                      | テキスト入力/URL フィールドを選択して編集可能にする |
| ⌘⇧T (Command-Shift-T)   | 最後に閉じたタブを開く（複数回使用可能）         |
| ⌘\[                     | ブラウジング履歴で 1 ページ戻る                  |
| ⌘]                      | ブラウジング履歴で 1 ページ進む                  |
| ⌘⇧R                     | リーダーモードを有効にする                       |

#### Mail shortcuts

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | ロケーションを開く           |
| ⌘T                         | 新しいタブを開く             |
| ⌘W                         | 現在のタブを閉じる           |
| ⌘R                         | 現在のタブを更新             |
| ⌘.                         | 現在のタブの読み込みを停止   |
| ⌘⌥F (Command-Option/Alt-F) | メールボックス内を検索       |

## References

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
