# ブラウザのアーティファクト

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や、**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローしてください。
- **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ブラウザのアーティファクト <a href="#id-3def" id="id-3def"></a>

ブラウザのアーティファクトとは、ナビゲーション履歴、ブックマーク、ダウンロードしたファイルのリスト、キャッシュデータなどを指します。

これらのアーティファクトは、オペレーティングシステム内の特定のフォルダに保存されているファイルです。

各ブラウザは他のブラウザとは異なる場所にファイルを保存し、異なる名前を持っていますが、ほとんどの場合、同じタイプのデータ（アーティファクト）を保存しています。

最も一般的なブラウザによって保存されるアーティファクトを見てみましょう。

- **ナビゲーション履歴:** ユーザーのナビゲーション履歴に関するデータが含まれています。たとえば、ユーザーが悪意のあるサイトを訪れたかどうかを追跡するために使用できます。
- **オートコンプリートデータ:** これは、ブラウザが最も検索される内容に基づいて提案するデータです。ナビゲーション履歴と組み合わせて、さらなる洞察を得ることができます。
- **ブックマーク:** 自己説明的。
- **拡張機能とアドオン:** 自己説明的。
- **キャッシュ:** ウェブサイトをナビゲートする際、ブラウザはさまざまな理由でキャッシュデータ（画像、JavaScriptファイルなど）を作成します。たとえば、ウェブサイトの読み込み時間を短縮するためです。これらのキャッシュファイルは、法的調査中にデータの貴重な情報源となり得ます。
- **ログイン情報:** 自己説明的。
- **ファビコン:** タブ、URL、ブックマークなどに見つかる小さなアイコンです。ユーザーが訪れたウェブサイトや場所に関するさらなる情報を取得するための別の情報源として使用できます。
- **ブラウザセッション:** 自己説明的。
- **ダウンロード:** 自己説明的。
- **フォームデータ:** フォームに入力された内容は、ブラウザによって頻繁に保存されるため、次回ユーザーがフォームに入力する際に、ブラウザが以前に入力されたデータを提案できます。
- **サムネイル:** 自己説明的。
- **カスタム辞書.txt:** ユーザーが辞書に追加した単語。

## Firefox

Firefoxは、\~/_**.mozilla/firefox/**_（Linux）、**/Users/$USER/Library/Application Support/Firefox/Profiles/**（MacOS）、_**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_（Windows）にプロファイルフォルダを作成します。\
このフォルダ内に、_**profiles.ini**_ という名前のファイルがユーザープロファイルの名前で表示されるはずです。\
各プロファイルには、そのデータが保存されるフォルダの名前を示す "**Path**" 変数があります。フォルダは、_profiles.ini_ が存在するディレクトリ内に存在するはずです。存在しない場合は、おそらく削除された可能性があります。

各プロファイルのフォルダ（_\~/.mozilla/firefox/\<ProfileName>/_）内には、次の興味深いファイルが見つかるはずです：

- _**places.sqlite**_ : 履歴（moz\_\_places）、ブックマーク（moz\_bookmarks）、ダウンロード（moz\_\_annos）に関するデータ。Windowsでは、_**places.sqlite**_ 内の履歴を読むために [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) ツールを使用できます。
- 履歴をダンプするクエリ: `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
- リンクタイプは、以下のように示される番号であり、
  - 1: ユーザーがリンクをクリック
  - 2: ユーザーがURLを入力
  - 3: ユーザーがお気に入りを使用
  - 4: iframeから読み込まれた
  - 5: HTTPリダイレクト301経由でアクセス
  - 6: HTTPリダイレクト302経由でアクセス
  - 7: ファイルをダウンロード
  - 8: iframe内のリンクをクリック
- ダウンロードをダンプするクエリ: `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
- _**bookmarkbackups/**_ : ブックマークのバックアップ
- _**formhistory.sqlite**_ : **Webフォームデータ**（電子メールなど）
- _**handlers.json**_ : プロトコルハンドラ（たとえば、_mailto://_ プロトコルをどのアプリが処理するか）
- _**persdict.dat**_ : ユーザーが辞書に追加した単語
- _**addons.json**_ および _**extensions.sqlite**_ : インストールされたアドオンと拡張機能
- _**cookies.sqlite**_ : **クッキー**を含む。Windowsでは、このファイルを調査するために [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) を使用できます。
- _**cache2/entries**_ または _**startupCache**_ : キャッシュデータ（約350MB）。**データカービング**などのトリックを使用して、キャッシュに保存されたファイルを取得することもできます。 [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html) を使用して、**キャッシュに保存されたファイル**を表示できます。

取得できる情報：

- URL、取得回数、ファイル名、コンテンツタイプ、ファイルサイズ、最終変更時刻、最終取得時刻、サーバー最終変更、サーバー応答
- _**favicons.sqlite**_ : ファビコン
- _**prefs.js**_ : 設定と環境設定
- _**downloads.sqlite**_ : 旧ダウンロードデータベース（現在はplaces.sqlite内にあります）
- _**thumbnails/**_ : サムネイル
- _**logins.json**_ : 暗号化されたユーザー名とパスワード
- **ブラウザの組み込みフィッシング対策:** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
  - セーフサーチ設定が無効になっている場合、"safebrowsing.malware.enabled" および "phishing.enabled" が false を返します
- _**key4.db**_ または _**key3.db**_ : マスターキー？

マスターパスワードを復号化しようとする場合、[https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt) を使用できます。\
次のスクリプトと呼び出しを使用して、ブルートフォースでパスワードファイルを指定できます：

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chromeは、ユーザーのホーム内にプロファイルを作成します。Linuxでは_**\~/.config/google-chrome/**_、Windowsでは_**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_、MacOSでは_**/Users/$USER/Library/Application Support/Google/Chrome/**_内に保存されます。\
情報のほとんどは、前述のパス内の_Default/_または_ChromeDefaultData/_フォルダに保存されます。以下の興味深いファイルが見つかります:

* _**History**_: URL、ダウンロード、検索キーワードなど。Windowsでは、[ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html)ツールを使用して履歴を読むことができます。"Transition Type"列の意味は次のとおりです:
* Link: ユーザーがリンクをクリックした
* Typed: URLが入力された
* Auto Bookmark
* Auto Subframe: 追加
* Start page: ホームページ
* Form Submit: フォームが記入され送信された
* Reloaded
* _**Cookies**_: クッキー。[ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html)を使用してクッキーを調査できます。
* _**Cache**_: キャッシュ。Windowsでは、[ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html)ツールを使用してキャッシュを調査できます。
* _**Bookmarks**_: ブックマーク
* _**Web Data**_: フォーム履歴
* _**Favicons**_: ファビコン
* _**Login Data**_: ログイン情報（ユーザー名、パスワードなど）
* _**Current Session**_ および _**Current Tabs**_: 現在のセッションデータと現在のタブ
* _**Last Session**_ および _**Last Tabs**_: Chromeが最後に閉じられたときにアクティブだったサイトが保存されています。
* _**Extensions**_: 拡張機能とアドオンのフォルダ
* **Thumbnails** : サムネイル
* **Preferences**: このファイルには、プラグイン、拡張機能、ジオロケーションを使用するサイト、ポップアップ、通知、DNSプリフェッチング、証明書例外など、多くの情報が含まれています。特定のChrome設定が有効になっているかどうかを調査しようとしている場合、おそらくこの設定をここで見つけることができます。
* **ブラウザの組み込みのフィッシング対策:** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
* 単純に「**safebrowsing**」をgrepして、結果に`{"enabled: true,"}`があるかどうかを確認して、フィッシング対策とマルウェア保護が有効になっていることを示します。

## **SQLite DBデータの回復**

前のセクションで見られるように、ChromeとFirefoxはデータを保存するために**SQLite**データベースを使用しています。ツール[**sqlparse**](https://github.com/padfoot999/sqlparse)または[**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases)を使用して、削除されたエントリを回復することが可能です。

## **Internet Explorer 11**

Internet Explorerは、**データ**と**メタデータ**を異なる場所に保存します。メタデータを使用してデータを見つけることができます。

**メタデータ**は、フォルダ`%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`にあり、VXはV01、V16、またはV24のいずれかです。\
前述のフォルダ内には、ファイルV01.logも含まれています。このファイルの**変更時刻**とWebcacheVX.dataファイルの**異なる場合**、`esentutl /r V01 /d`コマンドを実行して、可能な**非互換性を修正**する必要があります。

このアーティファクトを回復した後（これはESEデータベースであり、photorecを使用してExchange DatabaseまたはEDBのオプションで回復できます）、プログラム[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)を使用して開きます。開いたら、**Containers**という名前のテーブルに移動します。

![](<../../../.gitbook/assets/image (446).png>)

このテーブル内で、保存されている情報の各部分がどの他のテーブルまたはコンテナに保存されているかを見つけることができます。その後、ブラウザによって保存された**データの場所**と内部にある**メタデータ**を見つけることができます。

**このテーブルは、他のMicrosoftツール（例: Skype）のキャッシュのメタデータも示していることに注意してください**

### キャッシュ

ツール[IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html)を使用してキャッシュを調査できます。キャッシュデータを抽出したフォルダを指定する必要があります。

#### メタデータ

* ディスク内のファイル名
* SecureDIrectory: キャッシュディレクトリ内のファイルの場所
* AccessCount: キャッシュに保存された回数
* URL: URLの元
* CreationTime: キャッシュされた最初の時間
* AccessedTime: キャッシュが使用された時間
* ModifiedTime: 最後のウェブページバージョン
* ExpiryTime: キャッシュの有効期限

#### ファイル

キャッシュ情報は_**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_および_**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_にあります

これらのフォルダ内の情報は、ユーザーが見ていた内容のスナップショットです。キャッシュは**250 MB**のサイズで、タイムスタンプはページが訪れられた時点（初回、NTFSの作成日、最終アクセス時刻、NTFSの変更時刻）を示しています。

### クッキー

ツール[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)を使用してクッキーを調査できます。クッキーを抽出したフォルダを指定する必要があります。

#### メタデータ

保存されているクッキーに関するメタデータ情報:

* ファイルシステム内のクッキー名
* URL
* AccessCount: サーバーに送信されたクッキーの回数
* CreationTime: クッキーが作成された最初の時間
* ModifiedTime: クッキーが最後に変更された時間
* AccessedTime: クッキーが最後にアクセスされた時間
* ExpiryTime: クッキーの有効期限

#### ファイル

クッキーデータは_**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_および_**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_にあります

セッションクッキーはメモリに、永続クッキーはディスクに保存されます。

### ダウンロード

#### メタデータ

ツール[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)をチェックすると、ダウンロードのメタデータを含むコンテナが見つかります:

![](<../../../.gitbook/assets/image (445).png>)

"ResponseHeaders"列の情報を取得すると、16進数からURL、ファイルタイプ、ダウンロードファイルの場所を取得できます。

#### ファイル

パス_**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_を確認してください

### **履歴**

ツール[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html)を使用して履歴を読むことができます。ただし、最初にブラウザと抽出した履歴ファイルの場所を指定する必要があります。

#### **メタデータ**

* ModifiedTime: URLが見つかった最初の時間
* AccessedTime: 最後の時間
* AccessCount: アクセス回数

#### **ファイル**

_**userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_および_**userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_を検索してください

### **入力済みURL**

この情報は、レジストリNTDUSER.DAT内のパスにあります:

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
* ユーザーが入力した最後の50のURLを保存します
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
* URLが入力された最後の時間

## Microsoft Edge

Microsoft Edgeのアーティファクトを分析するためには、**前のセクション（IE 11）のキャッシュと場所に関するすべての説明が有効**ですが、この場合のベースロケーションは_**%userprofile%\Appdata\Local\Packages**_です（以下のパスで確認できます）:

* プロファイルパス: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_
* 履歴、クッキー、ダウンロード: _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* 設定、ブックマーク、リーディングリスト: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* キャッシュ: _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* 最後のアクティブセッション: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

データベースは`/Users/$User/Library/Safari`にあります

* **History.db**: `history_visits` _および_ `history_items`テーブルには、履歴とタイムスタンプに関する情報が含まれています。
* `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist**: ダウンロードしたファイルに関する情報が含まれています。
* **Book-marks.plist**: ブックマークされたURL。
* **TopSites.plist**: ユーザーが最も訪れたウェブサイトのリスト。
* **Extensions.plist**: 古いスタイルのSafariブラウザ拡張機能のリストを取得するために使用します。
* `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
* `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist**: 通知をプッシュすることが許可されているドメイン。
* `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist**: ユーザーがSafariを終了したときに開かれていたタブ。
* `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **ブラウザの組み込みのフィッシング対策:** `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
* 設定が有効であることを示すためには、返答は1である必要があります

## Opera

データベースは`/Users/$USER/Library/Application Support/com.operasoftware.Opera`にあります

Operaは、Google Chromeとまったく同じ形式でブラウザの履歴とダウンロードデータを保存します。これはファイル名だけでなく、テーブル名にも適用されます。

* **ブラウザの組み込みのフィッシング対策:** `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
* **fraud\_protection\_enabled** は **true** である必要があります

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**できます。\
今すぐアクセス:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝**したり、**HackTricksをPDFでダウンロード**したりするには、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのスウォッグ**](https://peass.creator-spring.com)を入手してください
* 独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)を含む、[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参
