<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、<a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@carlospolopm**をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックする**無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

---

# GUIアプリケーション内の可能なアクションをチェック

**一般的なダイアログ**は、**ファイルの保存**、**ファイルの開く**、フォントの選択、色の選択などのオプションです。ほとんどの場合、これらのオプションにアクセスできる場合、**完全なエクスプローラ機能**が提供されます。

これは、次のオプションにアクセスできる場合、エクスプローラ機能にアクセスできることを意味します：

- 閉じる/閉じる
- 開く/開くと
- 印刷
- エクスポート/インポート
- 検索
- スキャン

次のことをチェックすべきです：

- ファイルの変更または新規作成
- シンボリックリンクの作成
- 制限された領域へのアクセス
- 他のアプリケーションの実行

## コマンドの実行

おそらく**`開くと`**オプションを使用して、いくつかの種類のシェルを開いたり実行したりできるかもしれません。

### Windows

たとえば、_cmd.exe、command.com、Powershell/Powershell ISE、mmc.exe、at.exe、taskschd.msc..._ ここでコマンドを実行するために使用できる他のバイナリを見つける：[https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash、sh、zsh..._ ここで詳細を確認：[https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## パス制限のバイパス

- **環境変数**：いくつかのパスを指す環境変数がたくさんあります
- **その他のプロトコル**：_about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **シンボリックリンク**
- **ショートカット**：CTRL+N（新しいセッションを開く）、CTRL+R（コマンドを実行する）、CTRL+SHIFT+ESC（タスクマネージャー）、Windows+E（エクスプローラを開く）、CTRL-B、CTRL-I（お気に入り）、CTRL-H（履歴）、CTRL-L、CTRL-O（ファイル/開くダイアログ）、CTRL-P（印刷ダイアログ）、CTRL-S（名前を付けて保存）
- 隠し管理メニュー：CTRL-ALT-F8、CTRL-ESC-F9
- **シェルURI**：_shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNCパス**：共有フォルダに接続するパス。ローカルマシンのC$に接続してみるべきです（"\\\127.0.0.1\c$\Windows\System32"）
- **その他のUNCパス:**

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
レジストリエディター: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

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

- Sticky Keys – SHIFTを5回押す
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – NUMLOCKを5秒間押し続ける
- Filter Keys – 右SHIFTを12秒間押し続ける
- WINDOWS+F1 – Windows検索
- WINDOWS+D – デスクトップを表示
- WINDOWS+E – Windows Explorerを起動
- WINDOWS+R – 実行
- WINDOWS+U – 利便性センター
- WINDOWS+F – 検索
- SHIFT+F10 – コンテキストメニュー
- CTRL+SHIFT+ESC – タスクマネージャー
- CTRL+ALT+DEL – 新しいWindowsバージョンのスプラッシュスクリーン
- F1 – ヘルプ F3 – 検索
- F6 – アドレスバー
- F11 – Internet Explorer内でのフルスクリーンの切り替え
- CTRL+H – Internet Explorerの履歴
- CTRL+T – Internet Explorer – 新しいタブ
- CTRL+N – Internet Explorer – 新しいページ
- CTRL+O – ファイルを開く
- CTRL+S – 保存 CTRL+N – 新しいRDP / Citrix
## スワイプ

* 左側から右側にスワイプして、すべての開いているウィンドウを表示し、KIOSKアプリを最小化してOS全体に直接アクセスします。
* 右側から左側にスワイプして、アクションセンターを開き、KIOSKアプリを最小化してOS全体に直接アクセスします。
* 上端からスワイプして、フルスクリーンモードで開かれたアプリのタイトルバーを表示します。
* 下から上にスワイプして、フルスクリーンアプリでタスクバーを表示します。

## Internet Explorerのトリック

### 'Image Toolbar'

画像をクリックすると画像の左上に表示されるツールバーです。保存、印刷、メール送信、エクスプローラーで「マイピクチャー」を開くことができます。KioskはInternet Explorerを使用する必要があります。

### シェルプロトコル

これらのURLを入力してエクスプローラービューを取得します：

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

詳細は次のページを参照してください：[https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# ブラウザのトリック

iKatのバージョンをバックアップします：

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

JavaScriptを使用して共通のダイアログを作成し、ファイルエクスプローラーにアクセスします：`document.write('<input/type=file>')`
出典：https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## ジェスチャーとボタン

* 4本（または5本）の指で上にスワイプ/ホームボタンを2回タップ：マルチタスクビューを表示してアプリを切り替えます

* 4本または5本の指で片方向にスワイプ：次の/前のアプリに切り替えるため

* 5本の指で画面をつまむ/ホームボタンをタッチ/画面下部から上に1本の指で素早くスワイプ：ホームにアクセスするため

* 画面下部から1-2インチ上に1本の指でゆっくりスワイプ：ドックが表示されます

* 画面上部から1本の指で下にスワイプ：通知を表示します

* 画面の右上隅から1本の指で下にスワイプ：iPad Proのコントロールセンターを表示します

* 画面の左端から1-2インチの1本の指でスワイプ：今日のビューを表示します

* 画面の中央から右または左に素早く1本の指でスワイプ：次の/前のアプリに切り替えます

* iPadの右上隅にあるOn/**Off**/Sleepボタンを押し続ける + スライドを右まで移動する：電源を切ります

* iPadの右上隅にあるOn/**Off**/Sleepボタンを押し続ける + ホームボタンを数秒間押す：強制的に電源を切ります

* iPadの右上隅にあるOn/**Off**/Sleepボタンを押し続ける + ホームボタンを素早く押す：画面左下にポップアップするスクリーンショットを撮影します。両方のボタンを同時に非常に短く押すと、数秒間押し続けるかのようにハードパワーオフが実行されます。

## ショートカット

iPadキーボードまたはUSBキーボードアダプターを持っている必要があります。アプリケーションからの脱出に役立つショートカットのみをここに表示します。

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

これらのショートカットは、iPadの視覚設定および音声設定に関連しています。

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
| ⌘⇥ (Command-Tab)                                   | 最後に使用した10個のアプリをリスト表示                                 |
| ⌘\~                                                | 最後のアプリに移動                                       |
| ⌘⇧3 (Command-Shift-3)                              | スクリーンショット（左下にホバーして保存または操作） |
| ⌘⇧4                                                | スクリーンショットを撮影してエディタで開く                    |
| ⌘を押し続ける                                   | アプリ用の利用可能なショートカットのリスト                 |
| ⌘⌥D (Command-Option/Alt-D)                         | ドックを表示                                      |
| ^⌥H (Control-Option-H)                             | ホームボタン                                             |
| ^⌥H H (Control-Option-H-H)                         | マルチタスクバーを表示                                      |
| ^⌥I (Control-Option-i)                             | アイテム選択                                             |
| Escape                                             | 戻るボタン                                             |
| → (右矢印)                                    | 次のアイテム                                               |
| ← (左矢印)                                     | 前のアイテム                                           |
| ↑↓ (上矢印、下矢印)                          | 選択したアイテムを同時にタップ                        |
| ⌥ ↓ (Option-下矢印)                            | 下にスクロール                                             |
| ⌥↑ (Option-上矢印)                               | 上にスクロール                                               |
| ⌥←または⌥→ (Option-左矢印またはOption-右矢印) | 左または右にスクロール                                    |
| ^⌥S (Control-Option-S)                             | VoiceOverスピーチをオンまたはオフにする                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 前のアプリに切り替える                              |
| ⌘⇥ (Command-Tab)                                   | 元のアプリに戻る                         |
| ←+→、次にOption + ←またはOption+→                   | ドックを通じてナビゲートする                                   |
### Safariのショートカット

| ショートカット           | アクション                           |
| ----------------------- | ----------------------------------- |
| ⌘L (Command-L)         | ロケーションを開く                   |
| ⌘T                     | 新しいタブを開く                     |
| ⌘W                     | 現在のタブを閉じる                   |
| ⌘R                     | 現在のタブを更新する                 |
| ⌘.                     | 現在のタブの読み込みを停止する       |
| ^⇥                     | 次のタブに切り替える                 |
| ^⇧⇥ (Control-Shift-Tab) | 前のタブに移動する                   |
| ⌘L                     | テキスト入力/URLフィールドを選択して修正する |
| ⌘⇧T (Command-Shift-T)  | 最後に閉じたタブを開く（複数回使用可能） |
| ⌘\[                    | ブラウジング履歴で1ページ戻る         |
| ⌘]                     | ブラウジング履歴で1ページ進む         |
| ⌘⇧R                    | リーダーモードをアクティブにする       |

### メールのショートカット

| ショートカット           | アクション                   |
| ----------------------- | -------------------------- |
| ⌘L                     | ロケーションを開く           |
| ⌘T                     | 新しいタブを開く             |
| ⌘W                     | 現在のタブを閉じる           |
| ⌘R                     | 現在のタブを更新する         |
| ⌘.                     | 現在のタブの読み込みを停止する |
| ⌘⌥F (Command-Option/Alt-F) | メールボックス内を検索する   |

# 参考文献

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンであり、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックするための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックし、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricksをサポートする他の方法：

* **HackTricksをPDFでダウンロード**したり、**HackTricksで企業を宣伝**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有する

</details>
