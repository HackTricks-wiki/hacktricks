# KIOSK からの脱出

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> で **ゼロからヒーローまでのAWSハッキングを学ぶ** <a href="https://training.hacktricks.xyz/courses/arte"><strong>こちら</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricksをPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェック！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見る
* **Discordグループ** に参加する 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) または [**telegram group**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローする。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks) のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) は、**ダークウェブ** を活用した検索エンジンで、企業やその顧客が **盗聴マルウェア** によって **侵害** を受けていないかをチェックする **無料** 機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックし、**無料** でエンジンを試すことができます:

{% embed url="https://whiteintel.io" %}

---

## 物理デバイスのチェック

|   コンポーネント   | アクション                                                               |
| ------------- | -------------------------------------------------------------------- |
| 電源ボタン  | デバイスの電源を切って再度入れると、スタート画面が表示される可能性があります      |
| 電源ケーブル   | 電源が一時的に切断されたときにデバイスが再起動するかどうかを確認します   |
| USB ポート     | より多くのショートカットを持つ物理キーボードを接続します                        |
| イーサネット      | ネットワークスキャンやスニッフィングにより、さらなる攻撃が可能になるかもしれません             |


## GUI アプリケーション内での可能なアクションのチェック

**共通のダイアログ** は、**ファイルの保存**、**ファイルの開く**、フォントの選択、色の選択などのオプションです。ほとんどの場合、これらのオプションを使用すると **完全なエクスプローラ機能** が提供されます。これは、次のオプションにアクセスできる場合、エクスプローラ機能にアクセスできることを意味します:

* 閉じる/閉じる
* 開く/開くと
* 印刷
* エクスポート/インポート
* 検索
* スキャン

次のことをチェックすべきです:

* ファイルの変更または新規作成
* シンボリックリンクの作成
* 制限された領域へのアクセス
* 他のアプリの実行

### コマンドの実行

おそらく **`開くと`** オプションを使用して、ある種のシェルを開いたり実行したりできるかもしれません。

#### Windows

例えば _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ ここでコマンドを実行するために使用できる他のバイナリを見つける: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ ここで詳細を確認: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### パス制限のバイパス

* **環境変数**: 特定のパスを指す多くの環境変数があります
* **その他のプロトコル**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **シンボリックリンク**
* **ショートカット**: CTRL+N (新しいセッションを開く), CTRL+R (コマンドを実行), CTRL+SHIFT+ESC (タスクマネージャ), Windows+E (エクスプローラを開く), CTRL-B, CTRL-I (お気に入り), CTRL-H (履歴), CTRL-L, CTRL-O (ファイル/開くダイアログ), CTRL-P (印刷ダイアログ), CTRL-S (名前を付けて保存)
* 隠し管理メニュー: CTRL-ALT-F8, CTRL-ESC-F9
* **シェル URI**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
* **UNC パス**: 共有フォルダに接続するパス。ローカルマシンの C$ に接続してみるべきです ("\\\127.0.0.1\c$\Windows\System32")
* **その他の UNC パス:**

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
### ショートカット

* スティッキーキー – SHIFTを5回押す
* マウスキー – SHIFT+ALT+NUMLOCK
* ハイコントラスト – SHIFT+ALT+PRINTSCN
* トグルキー – NUMLOCKを5秒間押し続ける
* フィルターキー – 右SHIFTを12秒間押し続ける
* WINDOWS+F1 – Windows検索
* WINDOWS+D – デスクトップを表示
* WINDOWS+E – Windowsエクスプローラーを起動
* WINDOWS+R – 実行
* WINDOWS+U – 利便性センター
* WINDOWS+F – 検索
* SHIFT+F10 – コンテキストメニュー
* CTRL+SHIFT+ESC – タスクマネージャー
* CTRL+ALT+DEL – 新しいWindowsバージョンのスプラッシュスクリーン
* F1 – ヘルプ F3 – 検索
* F6 – アドレスバー
* F11 – Internet Explorer内でのフルスクリーン切り替え
* CTRL+H – Internet Explorer履歴
* CTRL+T – Internet Explorer – 新しいタブ
* CTRL+N – Internet Explorer – 新しいページ
* CTRL+O – ファイルを開く
* CTRL+S – 保存 CTRL+N – 新しいRDP / Citrix

### スワイプ

* 左側から右側にスワイプしてすべての開いているウィンドウを表示し、KIOSKアプリを最小化してOS全体にアクセスする
* 右側から左側にスワイプしてアクションセンターを開き、KIOSKアプリを最小化してOS全体にアクセスする
* 上端からスワイプしてフルスクリーンモードで開いているアプリのタイトルバーを表示する
* 下端から上にスワイプしてフルスクリーンアプリでタスクバーを表示する

### Internet Explorerのトリック

#### 'Image Toolbar'

画像をクリックすると画像の左上に表示されるツールバーです。保存、印刷、メール送信、エクスプローラーで「マイピクチャー」を開くことができます。KioskはInternet Explorerを使用する必要があります。

#### シェルプロトコル

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
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> マイコンピューター
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> マイネットワークプレイス
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### ファイル拡張子の表示

詳細は次のページを参照してください：[https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## ブラウザのトリック

iKatのバージョンをバックアップします：

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

JavaScriptを使用して共通のダイアログを作成し、ファイルエクスプローラーにアクセスします： `document.write('<input/type=file>')`\
ソース：https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### ジェスチャーとボタン

* 4本（または5本）の指で上にスワイプ/ホームボタンを2回タップ：マルチタスクビューを表示してアプリを切り替える
* 4本または5本の指で片方向にスワイプ：次の/前のアプリに切り替える
* 5本の指で画面をつまむ/ホームボタンをタッチ/画面下部から上に素早く1本の指でスワイプ：ホームにアクセス
* 画面下部から1-2インチ上に1本の指でスワイプ（ゆっくり）：ドックが表示されます
* 画面上部から1本の指で下にスワイプ：通知を表示する
* 画面の右上隅から1本の指で下にスワイプ：iPad Proのコントロールセンターを表示する
* 画面の左端から1-2インチの1本の指でスワイプ：今日のビューを表示する
* 画面の中央から右または左に1本の指で素早くスワイプ：次の/前のアプリに切り替える
* iPadの右上隅にあるOn/**Off**/Sleepボタンを押し続ける + スライドを右まで移動する：電源を切る
* iPadの右上隅にあるOn/**Off**/Sleepボタンとホームボタンを数秒間押し続ける：強制的に電源を切る
* iPadの右上隅にあるOn/**Off**/Sleepボタンとホームボタンを素早く押す：画面左下にポップアップするスクリーンショットを撮る。両方のボタンを同時に非常に短く押すと、数秒間押し続けるかのようにハードパワーオフが実行されます。

### ショートカット

iPadキーボードまたはUSBキーボードアダプターを持っている必要があります。アプリケーションからの脱出に役立つショートカットのみがここに表示されます。

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

#### システムショートカット

これらのショートカットは、iPadの視覚設定と音声設定に依存します。

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

#### iPadナビゲーション

| ショートカット                                           | アクション                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | ホームに移動                                              |
| ⌘⇧H (Command-Shift-H)                              | ホームに移動                                              |
| ⌘ (Space)                                          | Spotlightを開く                                          |
| ⌘⇥ (Command-Tab)                                   | 最後に使用した10個のアプリをリスト表示する                                 |
| ⌘\~                                                | 最後のアプリに移動                                       |
| ⌘⇧3 (Command-Shift-3)                              | スクリーンショット（左下にホバーして保存または操作） |
| ⌘⇧4                                                | スクリーンショットを撮影してエディターで開く                    |
| ⌘を押して押し続ける                                   | アプリ用の利用可能なショートカットのリスト                 |
| ⌘⌥D (Command-Option/Alt-D)                         | ドックを表示する                                      |
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
#### Safariのショートカット

| ショートカット           | アクション                           |
| ----------------------- | ---------------------------------- |
| ⌘L (Command-L)          | ロケーションを開く                    |
| ⌘T                      | 新しいタブを開く                     |
| ⌘W                      | 現在のタブを閉じる                   |
| ⌘R                      | 現在のタブを更新                     |
| ⌘.                      | 現在のタブの読み込みを停止            |
| ^⇥                      | 次のタブに切り替え                   |
| ^⇧⇥ (Control-Shift-Tab) | 前のタブに移動                       |
| ⌘L                      | テキスト入力/URLフィールドを選択して変更 |
| ⌘⇧T (Command-Shift-T)   | 最後に閉じたタブを開く（複数回使用可能） |
| ⌘\[                     | 閲覧履歴で1ページ戻る                 |
| ⌘]                      | 閲覧履歴で1ページ進む                 |
| ⌘⇧R                     | リーダーモードをアクティブにする         |

#### メールのショートカット

| ショートカット           | アクション                   |
| -------------------------- | ---------------------------- |
| ⌘L                         | ロケーションを開く            |
| ⌘T                         | 新しいタブを開く             |
| ⌘W                         | 現在のタブを閉じる           |
| ⌘R                         | 現在のタブを更新             |
| ⌘.                         | 現在のタブの読み込みを停止    |
| ⌘⌥F (Command-Option/Alt-F) | メールボックス内を検索        |

## 参考文献

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、企業やその顧客が**stealer malwares**によって**compromised**されていないかをチェックするための**無料**機能を提供する**dark-web**を活用した検索エンジンです。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、**ハッキングトリックを共有**してください。

</details>
