<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください**。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


# GUIアプリケーション内の可能なアクションをチェックする

**共通のダイアログ**は、**ファイルの保存**、**ファイルの開く**、フォントの選択、色の選択などのオプションです。ほとんどの場合、これらのオプションにアクセスできる場合、**完全なエクスプローラの機能**を提供します。

これは、次のオプションにアクセスできる場合、エクスプローラの機能にアクセスできることを意味します。

* 閉じる/閉じる
* 開く/開く
* 印刷
* エクスポート/インポート
* 検索
* スキャン

次のことをチェックする必要があります：

* ファイルの変更または作成
* シンボリックリンクの作成
* 制限された領域へのアクセス
* 他のアプリの実行

## コマンドの実行

おそらく、**_**開く**_**オプションを使用して、シェルの種類を開いたり実行したりできるかもしれません。

### Windows

たとえば、_cmd.exe、command.com、Powershell/Powershell ISE、mmc.exe、at.exe、taskschd.msc..._ ここでコマンドを実行するために使用できる他のバイナリを見つけることができます：[https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash、sh、zsh..._ ここでコマンドを実行するために使用できる他のバイナリを見つけることができます：[https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## パス制限のバイパス

* **環境変数**：いくつかのパスを指す環境変数があります
* **その他のプロトコル**：_about:、data:、ftp:、file:、mailto:、news:、res:、telnet:、view-source:_
* **シンボリックリンク**
* **ショートカット**：CTRL+N（新しいセッションを開く）、CTRL+R（コマンドの実行）、CTRL+SHIFT+ESC（タスクマネージャー）、Windows+E（エクスプローラを開く）、CTRL-B、CTRL-I（お気に入り）、CTRL-H（履歴）、CTRL-L、CTRL-O（ファイル/開くダイアログ）、CTRL-P（印刷ダイアログ）、CTRL-S（名前を付けて保存）
* 隠し管理メニュー：CTRL-ALT-F8、CTRL-ESC-F9
* **シェルURI**：_shell:Administrative Tools、shell:DocumentsLibrary、shell:Librariesshell:UserProfiles、shell:Personal、shell:SearchHomeFolder、shell:Systemshell:NetworkPlacesFolder、shell:SendTo、shell:UsersProfiles、shell:Common Administrative Tools、shell:MyComputerFolder、shell:InternetFolder_
* **UNCパス**：共有フォルダに接続するためのパス。ローカルマシンのC$に接続してみてください（"\\\127.0.0.1\c$\Windows\System32"）
* **その他のUNCパス**：

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

コンソール：[https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
エクスプローラ：[https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
レジストリエディタ：[https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

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

* Sticky Keys – SHIFTキーを5回押す
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – NUMLOCKキーを5秒間押し続ける
* Filter Keys – 右SHIFTキーを12秒間押し続ける
* WINDOWS+F1 – Windows検索
* WINDOWS+D – デスクトップを表示
* WINDOWS+E – Windows Explorerを起動
* WINDOWS+R – 実行
* WINDOWS+U – アクセシビリティセンター
* WINDOWS+F – 検索
* SHIFT+F10 – コンテキストメニュー
* CTRL+SHIFT+ESC – タスクマネージャー
* CTRL+ALT+DEL – 新しいWindowsバージョンのスプラッシュスクリーン
* F1 – ヘルプ
* F3 – 検索
* F6 – アドレスバー
* F11 – Internet Explorer内のフルスクリーンの切り替え
* CTRL+H – Internet Explorerの履歴
* CTRL+T – Internet Explorer – 新しいタブ
* CTRL+N – Internet Explorer – 新しいページ
* CTRL+O – ファイルを開く
* CTRL+S – 保存
* CTRL+N – 新しいRDP / Citrix

## スワイプ

* 左側から右にスワイプして、すべての開いているウィンドウを表示し、KIOSKアプリを最小化してOS全体にアクセスします。
* 右側から左にスワイプして、アクションセンターを開き、KIOSKアプリを最小化してOS全体にアクセスします。
* 上端からスワイプして、フルスクリーンモードで開いているアプリのタイトルバーを表示します。
* 下から上にスワイプして、フルスクリーンアプリでタスクバーを表示します。

## Internet Explorerのトリック

### 'Image Toolbar'

画像をクリックすると、画像の左上に表示されるツールバーです。保存、印刷、メール送信、エクスプローラーで「マイピクチャ」を開くことができます。KioskはInternet Explorerを使用する必要があります。

### シェルプロトコル

次のURLを入力してエクスプローラービューを取得します。

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
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> マイネットワークプレース
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

# ブラウザのトリック

iKatのバックアップバージョン：

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScriptを使用して共通のダイアログを作成し、ファイルエクスプローラーにアクセスします：`document.write('<input/type=file>')`
ソース：https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## ジェスチャーとボタン

### 4本（または5本）の指で上にスワイプ/ホームボタンを2回タップ

マルチタスクビューを表示してアプリを切り替える

### 4本または5本の指で片方向にスワイプ

次の/前のアプリに切り替えるため

### 5本の指で画面をつまむ/ホームボタンをタッチ/画面の下から1本の指で上に素早くスワイプ

ホームにアクセスするため

### 画面の下から1本の指で1〜2インチスワイプ（ゆっくり）

ドックが表示されます

### 画面の上から1本の指で下にスワイプ

通知を表示するため

### 画面の右上隅から1本の指で下にスワイプ

iPad Proのコントロールセンターを表示するため

### 画面の左から1本の指で1〜2インチスワイプ

今日のビューを表示するため

### 画面の中央から右または左に素早く1本の指でスワイプ

次の/前のアプリに切り替えるため

### 上部右隅から1本の指で画面を押し続ける/スライドを右に全体に移動する

電源を切るため

### 上部右隅のOn/**Off**/Sleepボタンを押し続ける/スライドを右に全体に移動する

強制的に電源を切るため

### 上部右隅のOn/**Off**/Sleepボタンとホームボタンを素早く押す

スクリーンショットを撮影し、ディスプレイの左下に表示されます。両方のボタンを同時に非常に短く押すと、数秒間押し続けるように見えますが、強制的に電源が切られます。

## ショートカット

iPadのキーボードまたはUSBキーボードアダプターが必要です。アプリケーションからの脱出に役立つショートカットのみがここに表示されます。

| キー | 名前         |
| --- | ------------ |
| ⌘   | コマンド      |
| ⌥   | オプション（Alt） |
| ⇧   | シフト        |
| ↩   | リターン       |
| ⇥   | タブ          |
| ^   | コントロール      |
| ←   | 左矢印   |
| →   | 右矢印  |
| ↑   | 上矢印     |
| ↓   | 下矢印   |

### システムショートカット

これらのショートカットは、iPadの使用方法に応じて、ビジュアル設定とサウンド設定に使用されます。

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
| ⌘ Space  | 使用可能な言語のリストを表示します。選択するには、再度スペースバーをタップします。 |

### iPadのナビゲーション

| ショートカット                                           | アクション                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | ホームに移動                                              |
| ⌘⇧H (Command-Shift-H)                              | ホームに移動                                              |
| ⌘ (Space)                                          | Spotlightを開く                                          |
| ⌘⇥
| ⌘⇧⇥ (Command-Shift-Tab)                            | 前のアプリに切り替える                              |
| ⌘⇥ (Command-Tab)                                   | 元のアプリに戻る                                     |
| ←+→, その後 Option + ← または Option+→                   | ドックを通じてナビゲートする                                   |

### Safari ショートカット

| ショートカット                | アクション                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | ロケーションを開く                                    |
| ⌘T                      | 新しいタブを開く                                     |
| ⌘W                      | 現在のタブを閉じる                                   |
| ⌘R                      | 現在のタブをリフレッシュする                             |
| ⌘.                      | 現在のタブの読み込みを停止する                           |
| ^⇥                      | 次のタブに切り替える                                   |
| ^⇧⇥ (Control-Shift-Tab) | 前のタブに移動する                                     |
| ⌘L                      | テキスト入力/URLフィールドを選択して変更する                 |
| ⌘⇧T (Command-Shift-T)   | 最後に閉じたタブを開く（複数回使用できる）                     |
| ⌘\[                     | ブラウジング履歴で1ページ戻る                             |
| ⌘]                      | ブラウジング履歴で1ページ進む                             |
| ⌘⇧R                     | リーダーモードをアクティブにする                             |

### メール ショートカット

| ショートカット                   | アクション                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | ロケーションを開く                |
| ⌘T                         | 新しいタブを開く                 |
| ⌘W                         | 現在のタブを閉じる               |
| ⌘R                         | 現在のタブをリフレッシュする         |
| ⌘.                         | 現在のタブの読み込みを停止する       |
| ⌘⌥F (Command-Option/Alt-F) | メールボックス内を検索する           |

## 参考文献

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricks**で**会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、**[telegramグループ](https://t.me/peass)**に参加するか、**Twitter**で**フォロー**する[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
