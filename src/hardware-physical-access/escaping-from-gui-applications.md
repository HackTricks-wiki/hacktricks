# KIOSKからの脱出

{{#include ../banners/hacktricks-training.md}}

---

## 物理デバイスの確認

| コンポーネント    | アクション                                                             |
| ------------ | ------------------------------------------------------------------ |
| 電源ボタン | デバイスをオフにして再度オンにすると、スタート画面が表示される場合があります    |
| 電源ケーブル  | 電源が一時的に切れたときにデバイスが再起動するか確認します |
| USBポート    | 物理キーボードを接続してショートカットを増やします                      |
| Ethernet     | ネットワークスキャンやスニッフィングにより、さらなる悪用が可能になる場合があります           |

## GUIアプリケーション内での可能なアクションの確認

**一般的なダイアログ**は、**ファイルの保存**、**ファイルのオープン**、フォントや色の選択などのオプションです。これらの多くは**完全なエクスプローラー機能**を提供します。つまり、これらのオプションにアクセスできれば、エクスプローラーの機能にアクセスできるということです：

- 閉じる/名前を付けて閉じる
- 開く/別のアプリで開く
- 印刷
- エクスポート/インポート
- 検索
- スキャン

以下のことができるか確認してください：

- 新しいファイルを修正または作成する
- シンボリックリンクを作成する
- 制限された領域にアクセスする
- 他のアプリを実行する

### コマンド実行

おそらく**`Open with`**オプションを使用することで、何らかのシェルを開く/実行することができます。

#### Windows

例えば _cmd.exe、command.com、Powershell/Powershell ISE、mmc.exe、at.exe、taskschd.msc..._ コマンドを実行するために使用できるバイナリをさらに見つけるには、こちらを参照してください: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash、sh、zsh..._ さらに詳しくは: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### パス制限の回避

- **環境変数**: いくつかのパスを指している環境変数がたくさんあります
- **他のプロトコル**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **シンボリックリンク**
- **ショートカット**: CTRL+N (新しいセッションを開く)、CTRL+R (コマンドを実行)、CTRL+SHIFT+ESC (タスクマネージャ)、Windows+E (エクスプローラーを開く)、CTRL-B、CTRL-I (お気に入り)、CTRL-H (履歴)、CTRL-L、CTRL-O (ファイル/オープンダイアログ)、CTRL-P (印刷ダイアログ)、CTRL-S (名前を付けて保存)
- 隠し管理メニュー: CTRL-ALT-F8、CTRL-ESC-F9
- **シェルURI**: _shell:Administrative Tools、shell:DocumentsLibrary、shell:Librariesshell:UserProfiles、shell:Personal、shell:SearchHomeFolder、shell:Systemshell:NetworkPlacesFolder、shell:SendTo、shell:UsersProfiles、shell:Common Administrative Tools、shell:MyComputerFolder、shell:InternetFolder_
- **UNCパス**: 共有フォルダに接続するためのパス。ローカルマシンのC$に接続を試みるべきです ("\\\127.0.0.1\c$\Windows\System32")
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

### バイナリをダウンロードする

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
レジストリエディタ: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### ブラウザからファイルシステムにアクセスする

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
- CTRL+SHIFT+ESC – タスクマネージャ
- CTRL+ALT+DEL – 新しいWindowsバージョンでのスプラッシュ画面
- F1 – ヘルプ F3 – 検索
- F6 – アドレスバー
- F11 – Internet Explorer内で全画面表示を切り替え
- CTRL+H – Internet Explorerの履歴
- CTRL+T – Internet Explorer – 新しいタブ
- CTRL+N – Internet Explorer – 新しいページ
- CTRL+O – ファイルを開く
- CTRL+S – 保存 CTRL+N – 新しいRDP / Citrix

### スワイプ

- 左側から右にスワイプしてすべてのオープンウィンドウを表示し、KIOSKアプリを最小化してOS全体に直接アクセスします；
- 右側から左にスワイプしてアクションセンターを開き、KIOSKアプリを最小化してOS全体に直接アクセスします；
- 上端からスワイプしてフルスクリーンモードで開いているアプリのタイトルバーを表示します；
- 下からスワイプしてフルスクリーンアプリでタスクバーを表示します。

### Internet Explorerのトリック

#### '画像ツールバー'

画像をクリックすると左上に表示されるツールバーです。保存、印刷、メール送信、エクスプローラーで「マイピクチャ」を開くことができます。KioskはInternet Explorerを使用している必要があります。

#### シェルプロトコル

エクスプローラー表示を取得するには、次のURLを入力します：

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

### ファイル拡張子の表示

詳細についてはこのページを確認してください: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## ブラウザのトリック

iKatのバックアップバージョン:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\\

JavaScriptを使用して一般的なダイアログを作成し、ファイルエクスプローラーにアクセスします: `document.write('<input/type=file>')`\
ソース: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### ジェスチャーとボタン

- 四本（または五本）の指で上にスワイプ / ホームボタンをダブルタップ: マルチタスクビューを表示し、アプリを変更します
- 四本または五本の指で一方向にスワイプ: 次の/前のアプリに切り替えます
- 五本の指で画面をピンチ / ホームボタンをタッチ / 画面の下から1本の指で素早く上にスワイプ: ホームにアクセスします
- 画面の下から1本の指で1-2インチスワイプ（遅く）: ドックが表示されます
- 画面の上部から1本の指でスワイプダウン: 通知を表示します
- 画面の右上隅から1本の指でスワイプダウン: iPad Proのコントロールセンターを表示します
- 画面の左から1本の指で1-2インチスワイプ: 今日のビューを表示します
- 画面の中央から右または左に素早く1本の指でスワイプ: 次の/前のアプリに切り替えます
- 右上隅の**iPad +**の電源ボタン/**オフ**/スリープボタンを押し続け、**電源オフ**スライダーを右にスライドします: 電源を切ります
- 右上隅の**iPad**の電源ボタン/**オフ**/スリープボタンとホームボタンを数秒間押し続けます: ハード電源オフを強制します
- 右上隅の**iPad**の電源ボタン/**オフ**/スリープボタンとホームボタンを素早く押します: スクリーンショットが表示の左下にポップアップします。両方のボタンを同時に非常に短時間押すと、数秒間保持するとハード電源オフが実行されます。

### ショートカット

iPadキーボードまたはUSBキーボードアダプタを持っている必要があります。アプリケーションからの脱出に役立つショートカットのみがここに表示されます。

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
| ↓   | 下矢印     |

#### システムショートカット

これらのショートカットは、iPadの使用に応じた視覚設定と音設定のためのものです。

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
| ⌘ Space  | 利用可能な言語のリストを表示; 一つを選択するには、スペースバーを再度タップします。 |

#### iPadナビゲーション

| ショートカット                                           | アクション                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | ホームに移動                                              |
| ⌘⇧H (Command-Shift-H)                              | ホームに移動                                              |
| ⌘ (Space)                                          | スポットライトを開く                                          |
| ⌘⇥ (Command-Tab)                                   | 最後に使用したアプリのリスト                                 |
| ⌘\~                                                | 最後のアプリに移動                                       |
| ⌘⇧3 (Command-Shift-3)                              | スクリーンショット (保存またはアクションを実行するために左下にホバー) |
| ⌘⇧4                                                | スクリーンショットを撮影し、エディタで開く                    |
| ⌘を押し続ける                                   | アプリのための利用可能なショートカットのリスト                 |
| ⌘⌥D (Command-Option/Alt-D)                         | ドックを表示                                      |
| ^⌥H (Control-Option-H)                             | ホームボタン                                             |
| ^⌥H H (Control-Option-H-H)                         | マルチタスクバーを表示                                      |
| ^⌥I (Control-Option-i)                             | アイテム選択                                            |
| Escape                                             | 戻るボタン                                             |
| → (右矢印)                                    | 次のアイテム                                               |
| ← (左矢印)                                     | 前のアイテム                                           |
| ↑↓ (上矢印、下矢印)                          | 選択したアイテムを同時にタップ                        |
| ⌥ ↓ (Option-Down arrow)                            | 下にスクロール                                             |
| ⌥↑ (Option-Up arrow)                               | 上にスクロール                                               |
| ⌥← または ⌥→ (Option-Left arrow または Option-Right arrow) | 左または右にスクロール                                    |
| ^⌥S (Control-Option-S)                             | VoiceOverの音声をオンまたはオフにする                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 前のアプリに切り替える                              |
| ⌘⇥ (Command-Tab)                                   | 元のアプリに戻る                         |
| ←+→、次に Option + ← または Option+→                   | ドックをナビゲート                                   |

#### Safariショートカット

| ショートカット                | アクション                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | ロケーションを開く                                    |
| ⌘T                      | 新しいタブを開く                                   |
| ⌘W                      | 現在のタブを閉じる                            |
| ⌘R                      | 現在のタブを更新                          |
| ⌘.                      | 現在のタブの読み込みを停止                     |
| ^⇥                      | 次のタブに切り替える                           |
| ^⇧⇥ (Control-Shift-Tab) | 前のタブに移動                         |
| ⌘L                      | テキスト入力/URLフィールドを選択して修正する     |
| ⌘⇧T (Command-Shift-T)   | 最後に閉じたタブを開く (何度でも使用可能) |
| ⌘\[                     | ブラウジング履歴で1ページ戻る      |
| ⌘]                      | ブラウジング履歴で1ページ進む   |
| ⌘⇧R                     | リーダーモードを有効にする                             |

#### メールショートカット

| ショートカット                   | アクション                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | ロケーションを開く                |
| ⌘T                         | 新しいタブを開く               |
| ⌘W                         | 現在のタブを閉じる        |
| ⌘R                         | 現在のタブを更新      |
| ⌘.                         | 現在のタブの読み込みを停止 |
| ⌘⌥F (Command-Option/Alt-F) | メールボックス内を検索       |

## 参考文献

- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
