# ブラウザのアーティファクト

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出**してください。

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによるワークフローを簡単に構築し、自動化します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ブラウザのアーティファクト <a href="#3def" id="3def"></a>

ブラウザのアーティファクトとは、ナビゲーション履歴、ブックマーク、ダウンロードしたファイルのリスト、キャッシュデータなどを指します。

これらのアーティファクトは、オペレーティングシステム内の特定のフォルダに格納されています。

各ブラウザは、他のブラウザとは異なる場所にファイルを保存し、異なる名前を持っていますが、ほとんどの場合、同じタイプのデータ（アーティファクト）を保存しています。

最も一般的なブラウザによって保存されるアーティファクトを見てみましょう。

* **ナビゲーション履歴：** ユーザーのナビゲーション履歴に関するデータが含まれています。たとえば、ユーザーが悪意のあるサイトを訪れたかどうかを追跡するために使用できます。
* **オートコンプリートデータ：** ブラウザが最も検索される内容に基づいて提案するデータです。ナビゲーション履歴と組み合わせて、さらなる洞察を得ることができます。
* **ブックマーク：** 自己説明的です。
* **拡張機能とアドオン：** 自己説明的です。
* **キャッシュ：** ウェブサイトを閲覧する際、ブラウザはさまざまな理由でキャッシュデータ（画像、JavaScriptファイルなど）を作成します。たとえば、ウェブサイトの読み込み時間を高速化するためです。これらのキャッシュファイルは、法的調査中にデータの貴重な情報源となる場合があります。
* **ログイン情報：** 自己説明的です。
* **ファビコン：** タブ、URL、ブックマークなどで見つかる小さなアイコンです。ユーザーが訪れたウェブサイトや場所に関する追加情報を取得するための別の情報源として使用できます。
* **ブラウザセッション：** 自己説明的です。
* **ダウンロード：** 自己説明的です。
* **フォームデータ：** フォーム内に入力された内容は、ブラウザによって保存されることがあります。したがって、次回ユーザーがフォームに入力する際に、ブラウザは以前に入力されたデータを提案することができます。
* **サムネイル：** 自己説明的です。
* **カスタム辞書.txt：** ユーザーによって辞書に追加された単語。

## Firefox

Firefoxは、\~/_**.mozilla/firefox/**_（Linux）、**/Users/$USER/Library/Application Support/Firefox/Profiles/**（MacOS）、_**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_（Windows）にプロファイルフォルダを作成します。\
このフォルダ内には、ユーザープロファイルの名前が記載された _**profiles.ini**_ ファイルが表示されるはずです。\
各プロファイルには、そのデータが保存されるフォルダの名前を示す "**Path**" 変数があります。このフォルダは、_profiles.ini_ と同じディレクトリに存在するはずです。存在しない場合は、おそらく削除されたものです。

各プロファイルのフォルダ（_\~/.mozilla/firefox/\<ProfileName>/_）内には、次の興味深いファイルがあるはずです。

* _**places.sqlite**_：履歴（moz\_\_places）、ブックマーク（moz\_bookmarks）、およびダウンロード（moz\_\_annos）に関するデータ。Windowsでは、ツール[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html)を使用して、_**places.sqlite**_ 内の履歴を読み取ることができます。
* 履歴をダンプするクエリ：`select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
* リンクタイプは、以下のように示される番号です：
* 1：ユーザーがリンクをクリックしました
* 2：ユーザーがURLを入力しました
* 3：ユーザーがお気に入りを使用しました
* 4：Iframeから読み込まれました
* 5：HTTPリダイレクト301経由でアクセスされ
* _**logins.json**_ : 暗号化されたユーザー名とパスワード
* **ブラウザの組み込みのフィッシング対策:** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
* セーフサーチ設定が無効にされている場合、"safebrowsing.malware.enabled"と"phishing.enabled"がfalseとして返されます
* _**key4.db**_または_**key3.db**_ : マスターキー？

マスターパスワードを復号化するために、[https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)を使用することができます。\
以下のスクリプトと呼び出しを使用して、パスワードファイルをブルートフォースで指定できます：

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

Google Chromeは、ユーザーのホームディレクトリ内の_**\~/.config/google-chrome/**_（Linux）、_**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_（Windows）、または_**/Users/$USER/Library/Application Support/Google/Chrome/**_（MacOS）にプロファイルを作成します。ほとんどの情報は、前述のパス内の_Default/_または_ChromeDefaultData/_フォルダに保存されます。ここで、次の興味深いファイルを見つけることができます：

* _**History**_：URL、ダウンロード、さらには検索キーワードまで。Windowsでは、ツール[ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html)を使用して履歴を読み取ることができます。"Transition Type"列の意味は次のとおりです：
* Link：ユーザーがリンクをクリックしました
* Typed：URLが入力されました
* Auto Bookmark
* Auto Subframe：追加
* Start page：ホームページ
* Form Submit：フォームが入力されて送信されました
* Reloaded
* _**Cookies**_：クッキー。[ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html)を使用してクッキーを検査することができます。
* _**Cache**_：キャッシュ。Windowsでは、ツール[ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html)を使用してキャッシュを検査することができます。
* _**Bookmarks**_：ブックマーク
* _**Web Data**_：フォームの履歴
* _**Favicons**_：Favicons
* _**Login Data**_：ログイン情報（ユーザー名、パスワードなど）
* _**Current Session**_および_**Current Tabs**_：現在のセッションデータと現在のタブ
* _**Last Session**_および_**Last Tabs**_：これらのファイルには、Chromeが最後に閉じられたときにブラウザでアクティブだったサイトが保存されています。
* _**Extensions**_：拡張機能とアドオンのフォルダ
* **Thumbnails**：サムネイル
* **Preferences**：このファイルには、プラグイン、拡張機能、ジオロケーションを使用するサイト、ポップアップ、通知、DNSプリフェッチング、証明書の例外など、多くの有用な情報が含まれています。特定のChromeの設定が有効になっているかどうかを調査しようとしている場合、おそらくこの設定をここで見つけることができるでしょう。
* **ブラウザの組み込みのフィッシング対策**：`grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`を使用します
* 単純に「**safebrowsing**」をgrepして、結果に`{"enabled: true,"}`があるかどうかを確認すると、フィッシング対策とマルウェア保護が有効になっていることがわかります。

## **SQLite DBデータの回復**

前のセクションで観察できるように、ChromeとFirefoxの両方がデータを保存するために**SQLite**データベースを使用しています。ツール[**sqlparse**](https://github.com/padfoot999/sqlparse)または[**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases)を使用して、削除されたエントリを回復することが可能です。

## **Internet Explorer 11**

Internet Explorerは、データとメタデータを異なる場所に保存します。メタデータを使用してデータを見つけることができます。

メタデータは、フォルダ`%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`にあります（VXはV01、V16、またはV24になります）。\
前のフォルダには、ファイルV01.logも含まれています。このファイルの**変更時刻**とWebcacheVX.dataファイルの**異なる場合**、コマンド`esentutl /r V01 /d`を実行して、可能な**非互換性**を修正する必要があります。

このアーティファクトを**回復**した後（これはESEデータベースであり、photorecを使用してExchange DatabaseまたはEDBのオプションで回復できます）、プログラム[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)を使用して開くことができます。開いたら、"**Containers**"という名前のテーブルに移動します。

![](<../../../.gitbook/assets/image (446).png>)

このテーブルの中には、保存された情報の各部分がどの他のテーブルまたはコンテナに保存されているかが記載されています。それに続いて、ブラウザによって保存されたデータの場所とメタデータが示されています。

**このテーブルは、他のMicrosoftツール（例：skype）のキャッシュのメタデータも示しています**

### キャッシュ

ツール[IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html)を使用してキャッシュを検査することができます。キャッシュデータが抽出されたフォルダを指定する必要があります。

#### メタデータ

キャッシュに関するメタデータ情報は次のとおりです：

* ディスク上のファイル名
* SecureDIrectory：キャッシュディレクトリ内のファイルの場所
* AccessCount：キャッシュに保存された回数
* URL：元のURL
* CreationTime：キャッシュされた最初の時間
* AccessedTime：キャッシュが使用された時間
* ModifiedTime：最後のウェブページのバージョン
* ExpiryTime：キャッシュの有効期限

#### ファイル

キャッシュ情報は、_**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_および_**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_にあります。

これらのフォルダ内の情報は、ユーザーが表示していた内容のスナップショットです。キャッシュのサイズは**250 MB**であり、タイムスタンプはページが訪問された時点（初回、NTFSの作成日、最後の時間、NTFSの変更日時）を示しています。

### クッキー

ツール[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)を使用してクッキーを検査することができます。クッキーが抽出されたフォルダを指定する必要があります。

#### **メタデータ**

クッキーに関するメタデータ情報は次のとおりです：

* ファイルシステム内のクッキー名
* URL
* AccessCount：クッキーがサーバーに送信された回数
* CreationTime：クッキーが作成された最初の時間
* ModifiedTime：クッキーが最後に変更された時間
* AccessedTime：クッキーが最後にアクセスされた時間
* ExpiryTime：クッキーの有効期限

#### ファイル

クッキーデータは、_**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_および_**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_にあります。

セッションクッキーはメモリに、永続的なクッキーはディスクに保存されます。
### ダウンロード

#### **メタデータ**

ツール[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)をチェックすると、ダウンロードのメタデータが含まれるコンテナを見つけることができます。

![](<../../../.gitbook/assets/image (445).png>)

「ResponseHeaders」列の情報を取得し、その情報を16進数から変換することで、URL、ファイルの種類、ダウンロードされたファイルの場所を取得できます。

#### ファイル

パス「_**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_」を確認してください。

### **履歴**

ツール[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html)を使用して履歴を読み取ることができます。ただし、最初にブラウザと抽出された履歴ファイルの場所を指定する必要があります。

#### **メタデータ**

* ModifiedTime：URLが最初に見つかった時刻
* AccessedTime：最後の時刻
* AccessCount：アクセス回数

#### **ファイル**

「_**userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_」および「_**userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_」を検索します。

### **入力済みのURL**

この情報は、レジストリNTDUSER.DATのパス「_**Software\Microsoft\InternetExplorer\TypedURLs**_」にあります。

* ユーザーが入力した最後の50個のURLを保存します。
* 「_**Software\Microsoft\InternetExplorer\TypedURLsTime**_」には、URLが最後に入力された時刻が保存されます。

## Microsoft Edge

Microsoft Edgeのアーティファクトを分析するために、前のセクション（IE 11）のキャッシュと場所に関する説明はすべて有効ですが、基本的な場所は「_**%userprofile%\Appdata\Local\Packages**_」です（次のパスで確認できます）。

* プロファイルパス：「_**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_」
* 履歴、クッキー、ダウンロード：「_**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_」
* 設定、ブックマーク、読み取りリスト：「_**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_」
* キャッシュ：「_**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC#!XXX\MicrosoftEdge\Cache**_」
* 最後のアクティブなセッション：「_**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_」

## **Safari**

データベースは`/Users/$User/Library/Safari`にあります。

* **History.db**：`history_visits`と`history_items`テーブルには、履歴とタイムスタンプに関する情報が含まれています。
* `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist**：ダウンロードされたファイルに関する情報が含まれています。
* **Book-marks.plist**：ブックマークされたURL。
* **TopSites.plist**：ユーザーが最も頻繁に閲覧するウェブサイトのリスト。
* **Extensions.plist**：古いスタイルのSafariブラウザ拡張機能のリストを取得するために使用します。
* `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
* `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist**：通知をプッシュすることが許可されているドメイン。
* `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist**：ユーザーがSafariを終了したときに開かれていたタブ。
* `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **ブラウザの組み込みのフィッシング対策**：`defaults read com.apple.Safari WarnAboutFraudulentWebsites`
* 設定が有効であることを示すために、返答は1である必要があります

## Opera

データベースは`/Users/$USER/Library/Application Support/com.operasoftware.Opera`にあります。

Operaは、Google Chromeとまったく同じ形式でブラウザの履歴とダウンロードデータを保存します。これは、ファイル名だけでなく、テーブル名にも適用されます。

* **ブラウザの組み込みのフィッシング対策**：`grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
* **fraud\_protection\_enabled**は**true**である必要があります

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化されたワークフローを簡単に構築し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[NFT](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
