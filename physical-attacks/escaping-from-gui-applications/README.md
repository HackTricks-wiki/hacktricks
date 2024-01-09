```markdown
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>


# GUIアプリケーション内で可能なアクションをチェックする

**Common Dialogs**は、**ファイルの保存**、**ファイルの開く**、フォントの選択、色の選択などのオプションです。ほとんどの場合、**完全なExplorer機能を提供します**。これは、これらのオプションにアクセスできる場合、Explorerの機能にアクセスできることを意味します:

* 閉じる/名前を付けて閉じる
* 開く/開いて実行する
* 印刷する
* エクスポート/インポート
* 検索
* スキャン

以下のことができるかどうかを確認する必要があります:

* ファイルの変更または新規作成
* シンボリックリンクの作成
* 制限されたエリアへのアクセス
* 他のアプリの実行

## コマンド実行

**_**Open with**_** オプション**を使用して、何らかのシェルを開いたり実行したりすることができるかもしれません。

### Windows

例えば _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ ここでコマンドを実行するために使用できるバイナリをもっと見つけることができます: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ もっとここで: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## パス制限のバイパス

* **環境変数**: パスを指している多くの環境変数があります
* **他のプロトコル**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **シンボリックリンク**
* **ショートカット**: CTRL+N (新しいセッションを開く), CTRL+R (コマンドを実行する), CTRL+SHIFT+ESC (タスクマネージャー),  Windows+E (エクスプローラーを開く), CTRL-B, CTRL-I (お気に入り), CTRL-H (履歴), CTRL-L, CTRL-O (ファイル/開くダイアログ), CTRL-P (印刷ダイアログ), CTRL-S (名前を付けて保存)
* 隠された管理メニュー: CTRL-ALT-F8, CTRL-ESC-F9
* **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNCパス**: 共有フォルダに接続するためのパス。ローカルマシンのC$に接続しようとする必要があります ("\\\127.0.0.1\c$\Windows\System32")
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

コンソール: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
エクスプローラー: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
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

* Sticky Keys – SHIFTを5回押す
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – NUMLOCKを5秒間押し続ける
* Filter Keys – 右SHIFTを12秒間押し続ける
* WINDOWS+F1 – Windows検索
* WINDOWS+D – デスクトップを表示
* WINDOWS+E – Windowsエクスプローラーを起動
* WINDOWS+R – 実行
* WINDOWS+U – アクセスの容易さセンター
* WINDOWS+F – 検索
* SHIFT+F10 – コンテキストメニュー
* CTRL+SHIFT+ESC – タスクマネージャー
* CTRL+ALT+DEL – 新しいWindowsバージョンではスプラッシュスクリーン
* F1 – ヘルプ F3 – 検索
* F6 – アドレスバー
* F11 – Internet Explorer内で全画面表示を切り替える
* CTRL+H – Internet Explorer履歴
* CTRL+T – Internet Explorer – 新しいタブ
* CTRL+N – Internet Explorer – 新しいページ
* CTRL+O – ファイルを開く
* CTRL+S – 保存 CTRL+N – 新しいRDP / Citrix

## スワイプ

* 左側から右にスワイプして、全ての開いているWindowsを表示し、KIOSKアプリを最小化してOS全体に直接アクセスする；
* 右側から左にスワイプしてアクションセンターを開き、KIOSKアプリを最小化してOS全体に直接アクセスする；
* フルスクリーンモードでアプリを開いているときに、上端からスワイプしてタイトルバーを表示する；
* フルスクリーンアプリで下からスワイプしてタスクバーを表示する。

## Internet Explorerのコツ

### 'Image Toolbar'

画像がクリックされたときに画像の左上に表示されるツールバーです。Save、Print、Mailto、Explorerで"My Pictures"を開くことができます。KioskはInternet Explorerを使用している必要があります。

### Shell Protocol

Explorerビューを取得するためにこのURLを入力します:

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

# ブラウザのコツ

iKatのバックアップバージョン:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScriptを使用して一般的なダイアログを作成し、ファイルエクスプローラにアクセスする: `document.write('<input/type=file>')`
出典: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## ジェスチャーとボトムズ

### 四本（または五本）の指で上にスワイプ / ホームボタンをダブルタップ

マルチタスクビューを表示し、アプリを変更する

### 四本または五本の指で片方にスワイプ

次/前のアプリに変更する

### 五本の指で画面をピンチ / ホームボタンに触れる / 画面の下から一本の指で素早く上にスワイプ

ホームにアクセスする

### 画面の下からゆっくりと1-2インチ（約2.5-5cm）一本の指でスワイプ

ドックが表示される

### 画面の上から一本の指でスワイプ

通知を表示する

### 画面の右上隅から一本の指でスワイプ

iPad Proのコントロールセンターを表示する

### 画面の左から一本の指で1-2インチ（約2.5-5cm）スワイプ

Todayビューを表示する

### 画面の中央から一本の指で素早く右または左にスワイプ

次/前のアプリに変更する

### iPadの右上隅にあるOn/**Off**/Sleepボタンを押し続ける + **電源を切る**スライダーを右に全て動かす,

電源を切る

### iPadの右上隅にあるOn/**Off**/Sleepボタンとホームボタンを数秒間押し続ける

強制的に電源を切る

### iPadの右上隅にあるOn/**Off**/Sleepボタンとホームボタンを素早く押す

スクリーンショットを撮り、表示の左下にポップアップします。ボタンを数秒間押し続けると、強制的に電源が切れます。

## ショートカット

iPadのキーボードまたはUSBキーボードアダプタが必要です。ここでは、アプリケーションからの脱出に役立つ可能性のあるショートカットのみを示します。

| キー | 名前         |
| --- | ------------ |
| ⌘   | コマンド      |
| ⌥   | オプション (Alt) |
| ⇧   | シフト        |
| ↩   | リターン       |
| ⇥   | タブ          |
| ^   | コントロール      |
| ←   | 左矢印   |
| →   | 右矢印  |
| ↑   | 上矢印     |
| ↓   | 下矢印   |

### システムショートカット

これらのショートカットは、iPadの使用に応じて視覚設定と音設定のためのものです。

| ショートカット | アクション                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 画面を暗くする                                                                    |
| F2       | 画面を明るくする                                                                |
| F7       | 一曲戻る                                                                  |
| F8       | 再生/一時停止                                                                     |
| F9       | 曲をスキップ                                                                      |
| F10      | ミュート                                                                           |
| F11      | 音量を下げる                                                                |
| F12      | 音量を上げる                                                                |
| ⌘ Space  | 使用可能な言語のリストを表示する; 選択するには、もう一度スペースバーをタップします。 |

### iPadナビゲーション

| ショートカット                                           | アクション                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | ホームに行く                                              |
| ⌘⇧H (Command-Shift-H)                              | ホームに行く                                              |
| ⌘ (Space)                                          | Spotlightを開く                                          |
| ⌘⇥ (Command-Tab)                                   | 最後に使用した10個のアプリをリストする                                 |
| ⌘\~                                                | 最後のアプリに行く                                       |
| ⌘⇧3 (Command-Shift-3)                              | スクリーンショット (保存またはアクションを行
