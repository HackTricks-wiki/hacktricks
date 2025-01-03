{{#include ../../banners/hacktricks-training.md}}

# GUIアプリケーション内の可能なアクションを確認する

**一般的なダイアログ**は、**ファイルの保存**、**ファイルのオープン**、フォントや色の選択などのオプションです。これらのほとんどは**完全なエクスプローラー機能**を提供します。つまり、これらのオプションにアクセスできれば、エクスプローラーの機能にアクセスできるということです：

- 閉じる/名前を付けて閉じる
- 開く/他のアプリで開く
- 印刷
- エクスポート/インポート
- 検索
- スキャン

次のことができるか確認してください：

- 新しいファイルを修正または作成する
- シンボリックリンクを作成する
- 制限された領域にアクセスする
- 他のアプリを実行する

## コマンド実行

おそらく**`Open with`**オプションを使用することで、何らかのシェルを開く/実行することができます。

### Windows

例えば、_cmd.exe、command.com、Powershell/Powershell ISE、mmc.exe、at.exe、taskschd.msc..._ ここでコマンドを実行するために使用できるバイナリをさらに見つけてください：[https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX \_\_

_bash、sh、zsh..._ さらにこちらを参照してください：[https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## パス制限の回避

- **環境変数**：いくつかのパスを指している環境変数がたくさんあります
- **他のプロトコル**：_about:、data:、ftp:、file:、mailto:、news:、res:、telnet:、view-source:_
- **シンボリックリンク**
- **ショートカット**：CTRL+N（新しいセッションを開く）、CTRL+R（コマンドを実行）、CTRL+SHIFT+ESC（タスクマネージャー）、Windows+E（エクスプローラーを開く）、CTRL-B、CTRL-I（お気に入り）、CTRL-H（履歴）、CTRL-L、CTRL-O（ファイル/オープンダイアログ）、CTRL-P（印刷ダイアログ）、CTRL-S（名前を付けて保存）
- 隠し管理メニュー：CTRL-ALT-F8、CTRL-ESC-F9
- **シェルURI**：_shell:Administrative Tools、shell:DocumentsLibrary、shell:Librariesshell:UserProfiles、shell:Personal、shell:SearchHomeFolder、shell:Systemshell:NetworkPlacesFolder、shell:SendTo、shell:UsersProfiles、shell:Common Administrative Tools、shell:MyComputerFolder、shell:InternetFolder_
- **UNCパス**：共有フォルダーに接続するためのパス。ローカルマシンのC$に接続を試みるべきです（"\\\127.0.0.1\c$\Windows\System32"）
- **その他のUNCパス：**

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

## バイナリをダウンロードする

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
レジストリエディタ: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## ブラウザからファイルシステムにアクセスする

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## ショートカット

- スティッキーキー – SHIFTを5回押す
- マウスキー – SHIFT+ALT+NUMLOCK
- ハイコントラスト – SHIFT+ALT+PRINTSCN
- トグルキー – NUMLOCKを5秒間保持する
- フィルターキー – 右SHIFTを12秒間保持する
- WINDOWS+F1 – Windows検索
- WINDOWS+D – デスクトップを表示
- WINDOWS+E – Windowsエクスプローラーを起動
- WINDOWS+R – 実行
- WINDOWS+U – アクセシビリティセンター
- WINDOWS+F – 検索
- SHIFT+F10 – コンテキストメニュー
- CTRL+SHIFT+ESC – タスクマネージャー
- CTRL+ALT+DEL – 新しいWindowsバージョンでのスプラッシュスクリーン
- F1 – ヘルプ F3 – 検索
- F6 – アドレスバー
- F11 – Internet Explorer内で全画面表示を切り替え
- CTRL+H – Internet Explorerの履歴
- CTRL+T – Internet Explorer – 新しいタブ
- CTRL+N – Internet Explorer – 新しいページ
- CTRL+O – ファイルを開く
- CTRL+S – 保存 CTRL+N – 新しいRDP / Citrix

## スワイプ

- 左側から右にスワイプしてすべてのオープンウィンドウを表示し、KIOSKアプリを最小化してOS全体に直接アクセスする；
- 右側から左にスワイプしてアクションセンターを開き、KIOSKアプリを最小化してOS全体に直接アクセスする；
- 上端からスワイプしてフルスクリーンモードで開いているアプリのタイトルバーを表示する；
- 下からスワイプしてフルスクリーンアプリでタスクバーを表示する。

## Internet Explorerのトリック

### '画像ツールバー'

画像をクリックすると左上に表示されるツールバーです。保存、印刷、メール送信、エクスプローラーで「マイピクチャ」を開くことができます。KioskはInternet Explorerを使用している必要があります。

### シェルプロトコル

エクスプローラー表示を取得するためにこのURLを入力します：

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
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> マイネットワークプレイス
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## ファイル拡張子を表示する

詳細についてはこのページを確認してください：[https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# ブラウザのトリック

バックアップiKatバージョン：

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScriptを使用して一般的なダイアログを作成し、ファイルエクスプローラーにアクセスします：`document.write('<input/type=file>')`
出典：https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## ジェスチャーとボタン

- 四本（または五本）の指で上にスワイプ / ホームボタンをダブルタップ：マルチタスクビューを表示し、アプリを変更する

- 四本または五本の指で一方の方向にスワイプ：次の/前のアプリに切り替える

- 五本の指で画面をピンチ / ホームボタンをタッチ / 画面の下から1本の指で素早く上にスワイプ：ホームにアクセスする

- 画面の下から1本の指で1-2インチスワイプ（遅く）：ドックが表示される

- 画面の上部から1本の指でスワイプダウン：通知を表示する

- 画面の右上隅から1本の指でスワイプダウン：iPad Proのコントロールセンターを表示する

- 画面の左から1本の指で1-2インチスワイプ：今日のビューを表示する

- 画面の中央から右または左に1本の指で素早くスワイプ：次の/前のアプリに切り替える

- 上部右隅の**iPad +**の電源ボタンを押し続け、**電源オフ**スライダーを右にスライドさせる：電源を切る

- 上部右隅の**iPad**の電源ボタンとホームボタンを数秒間押す：強制的にハード電源オフする

- 上部右隅の**iPad**の電源ボタンとホームボタンを素早く押す：スクリーンショットを撮影し、表示の左下にポップアップします。両方のボタンを同時に非常に短時間押すと、数秒間保持するとハード電源オフが実行されます。

## ショートカット

iPadキーボードまたはUSBキーボードアダプタが必要です。アプリケーションからの脱出に役立つショートカットのみがここに表示されます。

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

### システムショートカット

これらのショートカットは、iPadの使用に応じた視覚設定と音声設定のためのものです。

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 画面を暗くする                                                                |
| F2       | 画面を明るくする                                                              |
| F7       | 1曲戻る                                                                      |
| F8       | 再生/一時停止                                                                 |
| F9       | 曲をスキップ                                                                  |
| F10      | ミュート                                                                       |
| F11      | 音量を下げる                                                                  |
| F12      | 音量を上げる                                                                  |
| ⌘ Space  | 利用可能な言語のリストを表示；1つを選択するには、スペースバーを再度タップします。 |

### iPadナビゲーション

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | ホームに移動                                            |
| ⌘⇧H (Command-Shift-H)                              | ホームに移動                                            |
| ⌘ (Space)                                          | Spotlightを開く                                        |
| ⌘⇥ (Command-Tab)                                   | 最後に使用したアプリのリストを表示                     |
| ⌘\~                                                | 最後のアプリに移動                                     |
| ⌘⇧3 (Command-Shift-3)                              | スクリーンショット（保存またはアクションを実行するために左下にホバー） |
| ⌘⇧4                                                | スクリーンショットを撮影し、エディタで開く              |
| ⌘を押し続ける                                      | アプリのための利用可能なショートカットのリストを表示     |
| ⌘⌥D (Command-Option/Alt-D)                         | ドックを表示                                            |
| ^⌥H (Control-Option-H)                             | ホームボタン                                            |
| ^⌥H H (Control-Option-H-H)                         | マルチタスクバーを表示                                  |
| ^⌥I (Control-Option-i)                             | アイテム選択                                            |
| Escape                                             | 戻るボタン                                              |
| → (右矢印)                                        | 次のアイテム                                            |
| ← (左矢印)                                        | 前のアイテム                                            |
| ↑↓ (上矢印、下矢印)                               | 選択したアイテムを同時にタップ                          |
| ⌥ ↓ (Option-Down矢印)                            | 下にスクロール                                          |
| ⌥↑ (Option-Up矢印)                               | 上にスクロール                                          |
| ⌥←または⌥→ (Option-Left矢印またはOption-Right矢印) | 左または右にスクロール                                   |
| ^⌥S (Control-Option-S)                             | VoiceOverの音声をオンまたはオフにする                   |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 前のアプリに切り替える                                  |
| ⌘⇥ (Command-Tab)                                   | 元のアプリに戻る                                       |
| ←+→、次にOption + ←またはOption+→                   | ドックをナビゲート                                      |

### Safariショートカット

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | ロケーションを開く                               |
| ⌘T                      | 新しいタブを開く                                 |
| ⌘W                      | 現在のタブを閉じる                               |
| ⌘R                      | 現在のタブを更新する                             |
| ⌘.                      | 現在のタブの読み込みを停止する                   |
| ^⇥                      | 次のタブに切り替える                             |
| ^⇧⇥ (Control-Shift-Tab) | 前のタブに移動                                   |
| ⌘L                      | テキスト入力/URLフィールドを選択して修正する     |
| ⌘⇧T (Command-Shift-T)   | 最後に閉じたタブを開く（何度でも使用可能）      |
| ⌘\[                     | ブラウジング履歴で1ページ戻る                    |
| ⌘]                      | ブラウジング履歴で1ページ進む                    |
| ⌘⇧R                     | リーダーモードを有効にする                       |

### メールショートカット

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | ロケーションを開く          |
| ⌘T                         | 新しいタブを開く            |
| ⌘W                         | 現在のタブを閉じる          |
| ⌘R                         | 現在のタブを更新する        |
| ⌘.                         | 現在のタブの読み込みを停止する |
| ⌘⌥F (Command-Option/Alt-F) | メールボックス内を検索する  |

# 参考文献

- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../../banners/hacktricks-training.md}}
