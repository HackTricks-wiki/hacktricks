# ブラウザのアーティファクト

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も進んだコミュニティツールによって動力を供給される**ワークフローを簡単に構築し自動化**します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ブラウザのアーティファクト <a href="#3def" id="3def"></a>

ブラウザのアーティファクトについて話すとき、私たちはナビゲーション履歴、ブックマーク、ダウンロードされたファイルのリスト、キャッシュデータなどについて話します。

これらのアーティファクトは、オペレーティングシステム内の特定のフォルダに保存されたファイルです。

各ブラウザは、他のブラウザとは異なる場所にファイルを保存し、それぞれ異なる名前を持っていますが、ほとんどの場合、同じタイプのデータ（アーティファクト）を保存します。

ブラウザによって保存される最も一般的なアーティファクトを見てみましょう。

* **ナビゲーション履歴：** ユーザーのナビゲーション履歴に関するデータを含みます。例えば、ユーザーが悪意のあるサイトを訪れたかどうかを追跡するために使用できます。
* **オートコンプリートデータ：** ブラウザが最も検索されるものに基づいて提案するデータです。ナビゲーション履歴と併用してより多くの洞察を得るために使用できます。
* **ブックマーク：** 自己説明的です。
* **拡張機能とアドオン：** 自己説明的です。
* **キャッシュ：** ウェブサイトをナビゲートする際、ブラウザはさまざまな理由でキャッシュデータ（画像、JavaScriptファイルなど）を作成します。例えば、ウェブサイトの読み込み時間を速めるためです。これらのキャッシュファイルは、フォレンジック調査中に素晴らしいデータソースになることがあります。
* **ログイン：** 自己説明的です。
* **ファビコン：** タブ、URL、ブックマークなどに見られる小さなアイコンです。訪れたウェブサイトや場所についての情報を得るための別のソースとして使用できます。
* **ブラウザセッション：** 自己説明的です。
* **ダウンロード：** 自己説明的です。
* **フォームデータ：** フォーム内に入力されたものは、ブラウザによってしばしば保存されるため、次回ユーザーがフォーム内に何かを入力するときに、以前に入力されたデータを提案できます。
* **サムネイル：** 自己説明的です。
* **カスタム辞書.txt：** ユーザーによって辞書に追加された単語。

## Firefox

Firefoxはプロファイルフォルダを\~/_**.mozilla/firefox/**_ (Linux)、**/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS)、_**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_に作成します。\
このフォルダ内には、ユーザープロファイルの名前が記載された_**profiles.ini**_ファイルが表示されるはずです。\
各プロファイルには、そのデータが保存されるフォルダの名前を示す"**Path**"変数があります。そのフォルダは、_profiles.ini_が存在する**同じディレクトリに** **存在するはずです**。存在しない場合は、おそらく削除されたと考えられます。

各プロファイルのフォルダ（_\~/.mozilla/firefox/\<ProfileName>/_）内には、次の興味深いファイルが見つかるはずです：

* _**places.sqlite**_ : 履歴（moz_places）、ブックマーク（moz_bookmarks）、ダウンロード（moz_annos）。Windowsでは、_**places.sqlite**_内の履歴を読むために[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)ツールを使用できます。
* 履歴をダンプするクエリ：`select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
* リンクタイプは、次のような数字で示されることに注意してください：
* 1: リンクをたどったユーザー
* 2: URLを入力したユーザー
* 3: お気に入りを使用したユーザー
* 4: Iframeから読み込まれた
* 5: HTTPリダイレクト301を介してアクセス
* 6: HTTPリダイレクト302を介してアクセス
* 7: ファイルをダウンロードした
* 8: Iframe内のリンクをたどったユーザー
* ダウンロードをダンプするクエリ：`SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
*
* _**bookmarkbackups/**_ : ブックマークのバックアップ
* _**formhistory.sqlite**_ : **ウェブフォームデータ**（メールアドレスなど）
* _**handlers.json**_ : プロトコルハンドラー（_mailto://_プロトコルを処理するアプリなど）
* _**persdict.dat**_ : 辞書に追加された単語
* _**addons.json**_ と _**extensions.sqlite**_ : インストールされたアドオンと拡張機能
* _**cookies.sqlite**_ : **クッキー**を含みます。Windowsでは、このファイルを調査するために[**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html)を使用できます。
*   _**cache2/entries**_ または _**startupCache**_ : キャッシュデータ（約350MB）。キャッシュに保存されたファイルを取得するために、**データカービング**のようなテクニックも使用できます。[MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html)を使用して、**キャッシュに保存されたファイル**を見ることができます。

取得できる情報：

* URL、フェッチ回数、ファイル名、コンテンツタイプ、ファイルサイズ、最終変更時間、最後にフェッチされた時間、サーバーの最終変更、サーバーの応答
* _**favicons.sqlite**_ : ファビコン
* _**prefs.js**_ : 設定と好み
* _**downloads.sqlite**_ : 旧ダウンロードデータベース（現在はplaces.sqlite内にあります）
* _**thumbnails/**_ : サムネイル
* _**logins.json**_ : 暗号化されたユーザー名とパスワード
* **ブラウザの組み込みフィッシング対策：** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
* セーフサーチ設定が無効にされている場合は、"safebrowsing.malware.enabled"と"phishing.enabled"がfalseとして返されます
* _**key4.db**_ または _**key3.db**_ : マスターキー？

マスターパスワードを解読しようとする場合、[https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)を使用できます。\
以下のスクリプトと呼び出しを使用して、ブルートフォースにパスワードファイルを指定できます：

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
```markdown
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

Google Chromeはユーザーのホームディレクトリ内にプロファイルを作成します。_**\~/.config/google-chrome/**_ (Linux)、_**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows)、または _**/Users/$USER/Library/Application Support/Google/Chrome/**_ (MacOS)にあります。
ほとんどの情報は、前述のパス内の_**Default/**_ または _**ChromeDefaultData/**_ フォルダ内に保存されます。ここでは以下の興味深いファイルを見つけることができます：

* _**History**_: URL、ダウンロード、検索キーワードまで。Windowsでは、[ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html)を使用して履歴を読むことができます。"Transition Type"列の意味は以下の通りです：
  * Link: リンクをクリックした
  * Typed: URLを入力した
  * Auto Bookmark
  * Auto Subframe: 追加
  * Start page: ホームページ
  * Form Submit: フォームを記入して送信した
  * Reloaded
* _**Cookies**_: クッキー。[ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html)を使用してクッキーを調査できます。
* _**Cache**_: キャッシュ。Windowsでは、[ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)を使用してキャッシュを調査できます。
* _**Bookmarks**_: ブックマーク
* _**Web Data**_: フォーム履歴
* _**Favicons**_: ファビコン
* _**Login Data**_: ログイン情報（ユーザー名、パスワードなど）
* _**Current Session**_ と _**Current Tabs**_: 現在のセッションデータと現在のタブ
* _**Last Session**_ と _**Last Tabs**_: Chromeが最後に閉じられたときにアクティブだったサイトが保存されています。
* _**Extensions**_: 拡張機能とアドオンフォルダ
* **Thumbnails** : サムネイル
* **Preferences**: プラグイン、拡張機能、ジオロケーションを使用するサイト、ポップアップ、通知、DNSプリフェッチング、証明書の例外など、多くの有益な情報が含まれています。特定のChrome設定が有効だったかどうかを調査しようとしている場合、ここでその設定を見つけることができるでしょう。
* **ブラウザの組み込みフィッシング対策:** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
* 単に“**safebrowsing**”をgrepして、結果に`{"enabled: true,"}`があることで、フィッシングとマルウェア保護がオンであることを示します。

## **SQLite DB Data Recovery**

前のセクションで見たように、ChromeとFirefoxはどちらも**SQLite**データベースを使用してデータを保存しています。[**sqlparse**](https://github.com/padfoot999/sqlparse) **または** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases)というツールを使用して、削除されたエントリを**回復する**ことが可能です。

## **Internet Explorer 11**

Internet Explorerは**データ**と**メタデータ**を異なる場所に保存します。メタデータを使用すると、データを見つけることができます。

**メタデータ**は `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` フォルダ内にあります。VXはV01、V16、またはV24になります。
前述のフォルダ内には、V01.logファイルも見つかります。このファイルとWebcacheVX.dataファイルの**変更時間**が**異なる**場合は、`esentutl /r V01 /d` コマンドを実行して、可能な**非互換性**を**修正**する必要があります。

このアーティファクトを**回復**したら（ESEデータベースで、photorecを使用してExchange DatabaseまたはEDBオプションで回復できます）、[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)プログラムを使用して開きます。**開いた**ら、"**Containers**"という名前のテーブルに移動します。

![](<../../../.gitbook/assets/image (446).png>)

このテーブル内で、保存された情報の各部分がどの他のテーブルまたはコンテナに保存されているかを見つけることができます。それに従って、ブラウザによって保存された**データの場所**と内部にある**メタデータ**を見つけることができます。

**このテーブルには、他のMicrosoftツール（例：skype）のキャッシュのメタデータも示されていることに注意してください**

### Cache

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html)ツールを使用してキャッシュを調査できます。キャッシュデータを抽出したフォルダを指定する必要があります。

#### Metadata

キャッシュに関するメタデータ情報は以下を保存します：

* ディスク上のファイル名
* SecureDIrectory: キャッシュディレクトリ内のファイルの場所
* AccessCount: キャッシュに保存された回数
* URL: 元のURL
* CreationTime: 最初にキャッシュされた時間
* AccessedTime: キャッシュが使用された時間
* ModifiedTime: 最後のウェブページバージョン
* ExpiryTime: キャッシュが期限切れになる時間

#### Files

キャッシュ情報は _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_ と _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_ にあります。

これらのフォルダ内の情報は、ユーザーが見ていたものの**スナップショット**です。キャッシュのサイズは**250 MB**で、タイムスタンプはページが訪れた時間を示します（最初の時間、NTFSの作成日、最後の時間、NTFSの変更時間）。

### Cookies

[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)ツールを使用してクッキーを調査できます。クッキーを抽出したフォルダを指定する必要があります。

#### **Metadata**

保存されたクッキーに関するメタデータ情報は以下を保存します：

* ファイルシステム内のクッキー名
* URL
* AccessCount: サーバーに送信された回数
* CreationTime: クッキーが作成された最初の時間
* ModifiedTime: クッキーが変更された最後の時間
* AccessedTime: クッキーがアクセスされた最後の時間
* ExpiryTime: クッキーの有効期限

#### Files

クッキーデータは _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_ と _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_ にあります。

セッションクッキーはメモリ内に、永続クッキーはディスクに存在します。

### Downloads

#### **Metadata**

[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)ツールをチェックすると、ダウンロードのメタデータが含まれるコンテナを見つけることができます：

![](<../../../.gitbook/assets/image (445).png>)

"ResponseHeaders"列の情報を取得して、その情報を16進数から変換すると、ダウンロードされたファイルのURL、ファイルタイプ、および場所を得ることができます。

#### Files

パス _**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_ を探します。

### **History**

[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)ツールを使用して履歴を読むことができます。しかし、まず、詳細オプションでブラウザを指定し、抽出した履歴ファイルの場所を指定する必要があります。

#### **Metadata**

* ModifiedTime: URLが最初に見つかった時間
* AccessedTime: 最後の時間
* AccessCount: アクセスされた回数

#### **Files**

_**userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_ と _**userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_ を検索します。

### **Typed URLs**

この情報はレジストリNTDUSER.DAT内の以下のパスにあります：

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
* ユーザーが入力した最後の50のURLを保存
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
* URLが入力された最後の時間

## Microsoft Edge

Microsoft Edgeのアーティファクトを分析する場合、前のセクション（IE 11）で説明されたキャッシュと場所に関するすべての説明が有効ですが、この場合の基本的な場所は _**%userprofile%\Appdata\Local\Packages**_ です（以下のパスで確認できます）：

* プロファイルパス: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_
* 履歴、クッキー、ダウンロード: _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* 設定、ブックマーク、リーディングリスト: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* キャッシュ: _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* 最後のアクティブセッション: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

データベースは `/Users/$User/Library/Safari` にあります

* **History.db**: テーブル `history_visits` _と_ `history_items` には履歴とタイムスタンプに関する情報が含まれています。
* `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist**: ダウンロードされたファイルに関する情報が含まれています。
* **Book-marks.plist**: ブックマークされたURL。
* **TopSites.plist**: ユーザーが閲覧する最も訪問されたウェブサイトのリスト。
* **Extensions.plist**: Safariブラウザの拡張機能の古いスタイルのリストを取得する。
* `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
* `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist**: 通知をプッシュすることが許可されているドメイン。
* `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist**: Safariを終了した最後の時に開かれていたタブ。
* `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **ブラウザの組み込みフィッシング対策:** `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
* 設定がアクティブであることを示すためには、返答は1であるべきです

## Opera

データベースは `/Users/$USER/Library/Application Support/com.operasoftware.Opera` にあります

Operaは**ブラウザの履歴とダウンロードデータをGoogle Chromeと全く同じ形式で保存します**。これはファイル名だけでなく、テーブル名にも適用されます。

* **ブラウザの組み込みフィッシング対策:** `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
* **fraud_protection_enabled** は **true** であるべきです

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で**最も先進的な**コミュニティツールによって動力を得た**ワークフローを簡単に構築し自動化**します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksに広告を掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**して
