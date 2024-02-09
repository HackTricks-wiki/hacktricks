<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を使って、ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)を入手する
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**@carlospolopm**をフォローする。

* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>


# GUIアプリケーション内の可能なアクションをチェック

**Common Dialogs**は、**ファイルの保存**、**ファイルの開く**、フォントの選択、色の選択などのオプションです。ほとんどの場合、これらのオプションにアクセスできる場合、**完全なエクスプローラ機能が提供**されます。

* 閉じる/閉じるとして
* 開く/開くとして
* 印刷
* エクスポート/インポート
* 検索
* スキャン

次のことをチェックする必要があります：

* ファイルを変更または新規作成できるかどうか
* シンボリックリンクを作成できるか
* 制限された領域にアクセスできるか
* 他のアプリを実行できるか

## コマンド実行

おそらく**`Open with`**オプションを使用して、いくつかの種類のシェルを開いたり実行したりできるかもしれません。

### Windows

たとえば、_cmd.exe、command.com、Powershell/Powershell ISE、mmc.exe、at.exe、taskschd.msc..._ ここでコマンドを実行するために使用できる他のバイナリを見つける：[https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash、sh、zsh..._ ここで詳細を確認：[https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## パス制限のバイパス

* **環境変数**：いくつかのパスを指す環境変数がたくさんあります
* **その他のプロトコル**：_about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **シンボリックリンク**
* **ショートカット**：CTRL+N（新しいセッションを開く）、CTRL+R（コマンドを実行）、CTRL+SHIFT+ESC（タスクマネージャー）、Windows+E（エクスプローラを開く）、CTRL-B、CTRL-I（お気に入り）、CTRL-H（履歴）、CTRL-L、CTRL-O（ファイル/開くダイアログ）、CTRL-P（印刷ダイアログ）、CTRL-S（名前を付けて保存）
* 隠し管理メニュー：CTRL-ALT-F8、CTRL-ESC-F9
* **シェルURI**：_shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNCパス**：共有フォルダに接続するパス。ローカルマシンのC$に接続してみるべきです（"\\\127.0.0.1\c$\Windows\System32"）
* **その他のUNCパス:**

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

## バイナリのダウンロード

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## ブラウザからファイルシステムにアクセス

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

* Sticky Keys – SHIFTを5回押す
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – NUMLOCKを5秒間押し続ける
* Filter Keys – 右SHIFTを12秒間押し続ける
* WINDOWS+F1 – Windows検索
* WINDOWS+D – デスクトップを表示
* WINDOWS+E – Windowsエクスプローラを起動
* WINDOWS+R – 実行
* WINDOWS+U – 利便性センター
* WINDOWS+F – 検索
* SHIFT+F10 – コンテキストメニュー
* CTRL+SHIFT+ESC – タスクマネージャ
* CTRL+ALT+DEL – 新しいWindowsバージョンのスプラッシュスクリーン
* F1 – ヘルプ F3 – 検索
* F6 – アドレスバー
* F11 – Internet Explorer内でのフルスクリーンの切り替え
* CTRL+H – Internet Explorerの履歴
* CTRL+T – Internet Explorer – 新しいタブ
* CTRL+N – Internet Explorer – 新しいページ
* CTRL+O – ファイルを開く
* CTRL+S – 保存 CTRL+N – 新しいRDP / Citrix

## スワイプ

* 左端から右にスワイプしてすべての開いているウィンドウを表示し、KIOSKアプリを最小化してOS全体に直接アクセスする
* 右端から左にスワイプしてアクションセンターを開き、KIOSKアプリを最小化してOS全体に直接アクセスする
* 上端からスワイプして、フルスクリーンモードで開いているアプリのタイトルバーを表示する
* 下端から上にスワイプして、フルスクリーンアプリでタスクバーを表示する

## Internet Explorerのトリック

### 'Image Toolbar'

画像をクリックすると画像の左上に表示されるツールバー。保存、印刷、メール送信、エクスプローラで「マイピクチャー」を開くなどができます。KioskはInternet Explorerを使用している必要があります。

### シェルプロトコル

これらのURLを入力してエクスプローラビューを取得します：

* `shell:Administrative Tools`
* `shell:DocumentsLibrary`
* `shell:Libraries`
* `shell:UserProfiles`
* `shell:Personal`
* `shell:SearchHomeFolder`
* `shell:NetworkPlacesFolder`
* `shell:SendTo`
* `shell:UserProfiles`
* `shell:Common Administrative Tools`
* `shell:MyComputerFolder`
* `shell:InternetFolder`
* `Shell:Profile`
* `Shell:ProgramFiles`
* `Shell:System`
* `Shell:ControlPanelFolder`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> コントロールパネル
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> マイコンピュータ
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> マイネットワークプレイス
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## ファイル拡張子の表示

詳細はこちら：[https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# ブラウザのトリック

iKatのバックアップバージョン：

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScriptを使用して共通のダイアログを作成し、ファイルエクスプローラにアクセスする：`document.write('<input/type=file>')`
出典：https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## ジェスチャーとボタン

* 4本（または5本）の指で上にスワイプ/ホームボタンを2回タップ：マルチタスクビューを表示してアプリを切り替える

* 4本または5本の指で片方向にスワイプ：次の/前のアプリに切り替える

* 5本の指で画面をつまむ/ホームボタンをタッチ/画面下部から上に素早く1本の指でスワイプ：ホームにアクセス

* 画面下部から1本の指でゆっくり1〜2インチ上にスワイプ：ドックが表示されます

* 画面上部から1本の指で下にスワイプ：通知を表示

* 画面の右上隅から1本の指で下にスワイプ：iPad Proのコントロールセンターを表示

* 画面の左端から1本の指で1〜2インチスワイプ：今日のビューを表示

* 画面の中央から右または左に素早く1本の指でスワイプ：次の/前のアプリに切り替える

* iPadの右上隅にあるOn/**Off**/Sleepボタンを押し続ける + スライドを右まで移動する：電源を切る

* iPadの右上隅にあるOn/**Off**/Sleepボタンを数秒押し続ける + ホームボタン：強制的に電源を切る

* iPadの右上隅にあるOn/**Off**/Sleepボタンとホームボタンを素早く押す：画面左下にポップアップするスクリーンショットを撮る。両方のボタンを同時に非常に短く押すと、数秒間押し続けるかのように、強制的に電源が切れます。

## ショートカット

iPadキーボードまたはUSBキーボードアダプターを持っている必要があります。アプリケーションから脱出するのに役立つショートカットのみがここに表示されます。

| キー | 名前         |
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

これらのショートカットは、iPadの視覚設定や音声設定に依存します。

| ショートカット | アクション                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 画面を暗くする                                                                    |
| F2       | 画面を明るくする                                                                |
| F7       | 前の曲に戻る                                                                  |
| F8       | 再生/一時停止                                                                     |
| F9       | 次の曲にスキップ                                                                      |
| F10      | ミュート                                                                           |
| F11      | 音量を下げる                                                                |
| F12      | 音量を上げる                                                                |
| ⌘ Space  | 利用可能な言語のリストを表示します。選択するには、再度スペースバーをタップします。 |

### iPadナビゲーション

| ショートカット                                           | アクション                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | ホームに移動                                              |
| ⌘⇧H (Command-Shift-H)                              | ホームに移動                                              |
| ⌘ (Space)                                          | Spotlightを開く                                          |
| ⌘⇥ (Command-Tab)                                   | 最後に使用した10個のアプリをリスト表示する                                 |
| ⌘\~                                                | 最後のアプリに移動                                       |
| ⌘⇧3 (Command-Shift-3)                              | スクリーンショット（左下にホバーして保存または操作） |
| ⌘
