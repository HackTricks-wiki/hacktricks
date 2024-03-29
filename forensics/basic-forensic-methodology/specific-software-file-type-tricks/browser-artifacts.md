# ブラウザのアーティファクト

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、ゼロからヒーローまでAWSハッキングを学ぶ</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)を**フォロー**する
- ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによってパワードされた**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ブラウザのアーティファクト <a href="#id-3def" id="id-3def"></a>

ブラウザのアーティファクトには、ナビゲーション履歴、ブックマーク、キャッシュデータなど、Webブラウザによって保存されるさまざまな種類のデータが含まれます。これらのアーティファクトは、一般的に類似したデータ型を保存しつつも、ブラウザごとに異なる場所と名前でオペレーティングシステム内の特定のフォルダに保持されます。

以下は、最も一般的なブラウザのアーティファクトの要約です：

- **ナビゲーション履歴**：ユーザーがWebサイトを訪れた履歴で、悪意のあるサイトへの訪問を特定するのに役立ちます。
- **オートコンプリートデータ**：頻繁な検索に基づいた提案で、ナビゲーション履歴と組み合わせると洞察を提供します。
- **ブックマーク**：ユーザーが保存したサイトで、迅速なアクセスのためです。
- **拡張機能とアドオン**：ユーザーがインストールしたブラウザの拡張機能やアドオン。
- **キャッシュ**：Webコンテンツ（画像、JavaScriptファイルなど）を保存してWebサイトの読み込み時間を短縮するための貴重なデータ。
- **ログイン情報**：保存されたログイン資格情報。
- **Favicons**：タブやブックマークに表示されるWebサイトに関連付けられたアイコンで、ユーザーの訪問に関する追加情報に役立ちます。
- **ブラウザセッション**：オープンされたブラウザセッションに関連するデータ。
- **ダウンロード**：ブラウザを介してダウンロードされたファイルの記録。
- **フォームデータ**：Webフォームに入力された情報で、将来の自動入力提案のために保存されます。
- **サムネイル**：Webサイトのプレビュー画像。
- **Custom Dictionary.txt**：ユーザーがブラウザの辞書に追加した単語。

## Firefox

Firefoxは、プロファイル内のユーザーデータをオペレーティングシステムに基づいて特定の場所に保存します：

- **Linux**：`~/.mozilla/firefox/`
- **MacOS**：`/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**：`%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

これらのディレクトリ内にある`profiles.ini`ファイルには、ユーザープロファイルがリストされています。各プロファイルのデータは、`profiles.ini`と同じディレクトリにある`profiles.ini`内の`Path`変数で名前が付けられたフォルダに保存されます。プロファイルのフォルダが見つからない場合は、削除されている可能性があります。

各プロファイルフォルダ内には、いくつかの重要なファイルがあります：

- **places.sqlite**：履歴、ブックマーク、ダウンロードを保存します。Windows上の[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html)などのツールを使用して履歴データにアクセスできます。
- 履歴とダウンロード情報を抽出するために特定のSQLクエリを使用します。
- **bookmarkbackups**：ブックマークのバックアップが含まれています。
- **formhistory.sqlite**：Webフォームデータを保存します。
- **handlers.json**：プロトコルハンドラを管理します。
- **persdict.dat**：カスタム辞書の単語。
- **addons.json**および**extensions.sqlite**：インストールされたアドオンと拡張機能に関する情報。
- **cookies.sqlite**：Cookieの保存先で、Windows上で[MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)を使用して検査できます。
- **cache2/entries**または**startupCache**：キャッシュデータで、[MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html)などのツールを介してアクセスできます。
- **favicons.sqlite**：Faviconsを保存します。
- **prefs.js**：ユーザー設定と環境設定。
- **downloads.sqlite**：古いダウンロードデータベースで、現在はplaces.sqliteに統合されています。
- **thumbnails**：Webサイトのサムネイル。
- **logins.json**：暗号化されたログイン情報。
- **key4.db**または**key3.db**：機密情報を保護するための暗号化キーを保存します。

さらに、ブラウザのフィッシング対策設定を確認するには、`prefs.js`内で`browser.safebrowsing`エントリを検索して、セーフブラウジング機能が有効か無効かを確認できます。

マスターパスワードを復号化しようとする場合は、[https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)を使用できます。\
次のスクリプトと呼び出しを使用して、ブルートフォースするパスワードファイルを指定できます：

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

Google Chromeは、オペレーティングシステムに基づいて特定の場所にユーザープロファイルを保存します：

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

これらのディレクトリ内で、ほとんどのユーザーデータは **Default/** または **ChromeDefaultData/** フォルダにあります。重要なデータを保持する以下のファイルがあります：

- **History**: URL、ダウンロード、検索キーワードを含む。Windowsでは、[ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) を使用して履歴を読むことができます。"Transition Type" 列には、リンクのクリック、入力されたURL、フォームの送信、ページの再読み込みなど、さまざまな意味があります。
- **Cookies**: Cookieを保存。検査には、[ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) が利用できます。
- **Cache**: キャッシュされたデータを保持。検査するために、Windowsユーザーは[ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) を利用できます。
- **Bookmarks**: ユーザーのブックマーク。
- **Web Data**: フォーム履歴を含む。
- **Favicons**: ウェブサイトのファビコンを保存。
- **Login Data**: ユーザー名やパスワードなどのログイン資格情報を含む。
- **Current Session**/**Current Tabs**: 現在のブラウジングセッションとオープンされているタブに関するデータ。
- **Last Session**/**Last Tabs**: Chromeが閉じられる前の最後のセッション中にアクティブだったサイトに関する情報。
- **Extensions**: ブラウザの拡張機能やアドオンのためのディレクトリ。
- **Thumbnails**: ウェブサイトのサムネイルを保存。
- **Preferences**: プラグイン、拡張機能、ポップアップ、通知などの設定を含む情報が豊富なファイル。
- **ブラウザの組み込みのフィッシング対策**: フィッシング対策やマルウェア保護が有効になっているかどうかを確認するには、`grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` を実行します。出力で `{"enabled: true,"}` を探します。

## **SQLite DBデータの回復**

前のセクションで確認できるように、ChromeとFirefoxはデータを保存するために **SQLite** データベースを使用しています。ツール [**sqlparse**](https://github.com/padfoot999/sqlparse) または [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) を使用して、削除されたエントリを回復することが可能です。

## **Internet Explorer 11**

Internet Explorer 11 は、格納された情報とそれに対応する詳細を簡単にアクセスおよび管理するために、さまざまな場所にデータとメタデータを管理しています。

### メタデータの保存

Internet Explorerのメタデータは `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`（VX は V01、V16、または V24）に保存されます。これに加えて、`V01.log` ファイルは `WebcacheVX.data` との修正時間の不一致を示す場合があり、`esentutl /r V01 /d` を使用して修復が必要となります。このメタデータは ESEデータベースに格納されており、photorec や [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) などのツールを使用して回復および検査が可能です。**Containers** テーブル内では、各データセグメントが格納されている特定のテーブルやコンテナが識別でき、Skypeなどの他のMicrosoftツールのキャッシュの詳細も含まれます。

### キャッシュの検査

[IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) ツールを使用すると、キャッシュデータの抽出フォルダの場所が必要となり、キャッシュに関するメタデータにはファイル名、ディレクトリ、アクセス回数、URLの起源、キャッシュの作成、アクセス、修正、有効期限の時間が示されます。

### Cookieの管理

Cookieは[IECookiesView](https://www.nirsoft.net/utils/iecookies.html) を使用して調査でき、メタデータには名前、URL、アクセス回数、さまざまな時間に関する詳細が含まれます。永続的なCookieは `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` に保存され、セッションCookieはメモリに保存されます。

### ダウンロードの詳細

ダウンロードのメタデータは [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) を使用してアクセスでき、特定のコンテナにはURL、ファイルタイプ、ダウンロード場所などのデータが格納されます。物理ファイルは `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` にあります。

### 閲覧履歴

閲覧履歴を確認するには、[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) を使用し、抽出された履歴ファイルの場所とInternet Explorerの構成が必要です。ここでのメタデータには、修正時間、アクセス回数などが含まれます。履歴ファイルは `%userprofile%\Appdata\Local\Microsoft\Windows\History` にあります。

### 入力されたURL

入力されたURLとその使用時刻は、`NTUSER.DAT` 内の `Software\Microsoft\InternetExplorer\TypedURLs` および `Software\Microsoft\InternetExplorer\TypedURLsTime` に格納されており、ユーザーが入力した最後の50のURLとその最終入力時刻を追跡しています。

## Microsoft Edge

Microsoft Edgeは、ユーザーデータを `%userprofile%\Appdata\Local\Packages` に保存します。さまざまなデータタイプのパスは次のとおりです：

- **プロファイルパス**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **履歴、Cookie、ダウンロード**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **設定、ブックマーク、読書リスト**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **キャッシュ**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **最後のアクティブセッション**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safariのデータは `/Users/$User/Library/Safari` に保存されます。主要なファイルは次のとおりです：

- **History.db**: URLと訪問時刻を含む `history_visits` および `history_items` テーブルが含まれています。クエリを実行するには `sqlite3` を使用します。
- **Downloads.plist**: ダウンロードしたファイルに関する情報。
- **Bookmarks.plist**: ブックマークされたURLを保存します。
- **TopSites.plist**: 最も頻繁に訪れるサイト。
- **Extensions.plist**: Safariブラウザの拡張機能のリスト。取得するには `plutil` または `pluginkit` を使用します。
- **UserNotificationPermissions.plist**: 通知をプッシュすることが許可されたドメイン。解析するには `plutil` を使用します。
- **LastSession.plist**: 最後のセッションからのタブ。解析するには `plutil` を使用します。
- **ブラウザの組み込みのフィッシング対策**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` を使用して確認します。応答が1の場合、機能が有効になっています。

## Opera

Operaのデータは `/Users/$USER/Library/Application Support/com.operasoftware.Opera` に保存され、履歴とダウンロードに関してはChromeと同じ形式を共有しています。

- **ブラウザの組み込みのフィッシング対策**: `fraud_protection_enabled` が `true` に設定されているかどうかを確認するには、`grep` を使用して `Preferences` ファイル内で確認します。

これらのパスとコマンドは、異なるWebブラウザによって保存されるブラウジングデータにアクセスして理解するために重要です。

## 参考文献

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
- **書籍: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) を使用して、世界で最も高度なコミュニティツールによって強化された **ワークフローを簡単に構築** および **自動化** できます。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)** で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</strong></summary>

HackTricks をサポートする他の方法:
* もし**HackTricks**であなたの**企業が宣伝されるのを見たい**か、**PDF形式のHackTricksをダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加**するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**してください 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングテクニックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**
