# ブラウザアーティファクト

{{#include ../../../banners/hacktricks-training.md}}

## ブラウザアーティファクト <a href="#id-3def" id="id-3def"></a>

ブラウザアーティファクトには、閲覧履歴、ブックマーク、キャッシュデータなど、Webブラウザに保存されるさまざまな種類のデータが含まれます。これらのアーティファクトは、オペレーティングシステム内の特定のフォルダに保存されます。場所や名前はブラウザによって異なりますが、一般的には同様の種類のデータが保存されています。

以下は、最も一般的なブラウザアーティファクトの概要です。

- **閲覧履歴**: ユーザーがWebサイトを訪問した記録。悪意のあるサイトへのアクセスを特定するのに役立ちます。
- **オートコンプリートデータ**: 頻繁な検索に基づく候補。閲覧履歴と組み合わせることで有用な情報が得られます。
- **ブックマーク**: ユーザーがすばやくアクセスできるよう保存したサイト。
- **拡張機能とアドオン**: ユーザーがインストールしたブラウザ拡張機能またはアドオン。
- **キャッシュ**: Webサイトの読み込み時間を短縮するためにWebコンテンツ（画像やJavaScriptファイルなど）を保存するもので、フォレンジック分析に役立ちます。
- **ログイン情報**: 保存されたログイン認証情報。
- **ファビコン**: Webサイトに関連付けられたアイコン。タブやブックマークに表示され、ユーザーの訪問に関する追加情報として役立ちます。
- **ブラウザセッション**: 開いているブラウザセッションに関連するデータ。
- **ダウンロード**: ブラウザ経由でダウンロードしたファイルの記録。
- **フォームデータ**: Webフォームに入力された情報。後で自動入力候補として使用するために保存されます。
- **サムネイル**: Webサイトのプレビュー画像。
- **Custom Dictionary.txt**: ユーザーがブラウザの辞書に追加した単語。

## Firefox

Firefoxはユーザーデータをプロファイル内に整理しており、オペレーティングシステムに応じた特定の場所に保存します。<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

これらのディレクトリ内にある`profiles.ini`ファイルには、ユーザープロファイルの一覧が記載されています。各プロファイルのデータは、`profiles.ini`内の`Path`変数で指定された名前のフォルダに保存されます。このフォルダは`profiles.ini`自体と同じディレクトリにあります。プロファイルのフォルダが存在しない場合は、削除された可能性があります。

各プロファイルフォルダ内には、いくつかの重要なファイルがあります。<sup>[[1]](#references)</sup>

- **places.sqlite**: 履歴、ブックマーク、ダウンロードを保存します。Windowsでは、[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)などのツールで履歴データにアクセスできます。
- 履歴とダウンロードの情報を抽出するには、特定のSQLクエリを使用します。
- **bookmarkbackups**: ブックマークのバックアップが含まれます。
- **formhistory.sqlite**: Webフォームデータを保存します。
- **handlers.json**: プロトコルハンドラーを管理します。
- **persdict.dat**: カスタム辞書の単語。
- **addons.json**および**extensions.sqlite**: インストールされたアドオンと拡張機能に関する情報。
- **cookies.sqlite**: Cookieを保存します。Windowsでは、[MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)で確認できます。
- **cache2/entries**または**startupCache**: キャッシュデータ。[MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html)などのツールでアクセスできます。
- **favicons.sqlite**: ファビコンを保存します。
- **prefs.js**: ユーザー設定と環境設定。
- **downloads.sqlite**: 以前のダウンロードデータベース。現在はplaces.sqliteに統合されています。
- **thumbnails**: Webサイトのサムネイル。
- **logins.json**: 暗号化されたログイン情報。
- **key4.db**または**key3.db**: 機密情報を保護するための暗号化キーを保存します。

さらに、`prefs.js`内で`browser.safebrowsing`のエントリを検索すると、ブラウザのフィッシング対策設定を確認できます。これにより、安全なブラウジング機能が有効か無効かを判断できます。<sup>[[2]](#references)</sup>

マスターパスワードの復号を試みるには、[https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)を使用できます。\
以下のスクリプトと呼び出しを使用すると、ブルートフォース用のパスワードファイルを指定できます。
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Browsers Artifacts - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chromeは、オペレーティングシステムに応じた特定の場所にユーザープロファイルを保存します:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

これらのディレクトリ内では、ほとんどのユーザーデータが **Default/** または **ChromeDefaultData/** フォルダにあります。以下のファイルには重要なデータが含まれています:<sup>[[1]](#references)</sup>

- **History**: URL、downloads、検索キーワードが含まれます。Windowsでは、履歴の読み取りに [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html)を使用できます。「Transition Type」列には、ユーザーによるリンクのクリック、入力されたURL、フォーム送信、ページの再読み込みなど、さまざまな意味があります。
- **Cookies**: cookiesを保存します。確認には [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html)を利用できます。
- **Cache**: cacheされたデータを保持します。確認するには、Windowsユーザーは [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)を使用できます。

Electronベースのdesktop app（Discordなど）もChromium Simple Cacheを使用し、ディスク上に豊富なartifactを残します。以下を参照してください:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: ユーザーのbookmark。
- **Web Data**: form historyが含まれます。
- **Favicons**: Webサイトのfaviconを保存します。
- **Login Data**: usernameやpasswordなどのlogin credentialsが含まれます。
- **Current Session**/**Current Tabs**: 現在のbrowsing sessionと開いているtabに関するデータ。
- **Last Session**/**Last Tabs**: Chromeが閉じられる前の、直前のsessionでactiveだったsiteに関する情報。
- **Extensions**: browser extensionとaddonのディレクトリ。
- **Thumbnails**: Webサイトのthumbnailを保存します。
- **Preferences**: plugin、extension、popup、notificationなどの設定を含む、情報量の多いファイルです。
- **Browser’s built-in anti-phishing**: anti-phishingとmalware protectionが有効か確認するには、`grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`を実行します。出力内に`{"enabled: true,"}`があるか確認します。<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

前のセクションで確認したように、ChromeとFirefoxはどちらもデータの保存に **SQLite** databaseを使用します。[**sqlparse**](https://github.com/padfoot999/sqlparse) **または** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases)というtoolを使用して、**削除されたentryをrecover**できます。

## **Internet Explorer 11**

Internet Explorer 11は、さまざまな場所でデータとmetadataを管理しており、保存された情報と対応する詳細を分離することで、容易なaccessと管理を実現しています。

### Metadata Storage

Internet Explorerのmetadataは`%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`に保存されます（VXはV01、V16、またはV24）。これに関連して、`V01.log`ファイルのmodification timeが`WebcacheVX.data`と一致しない場合があり、その場合は`esentutl /r V01 /d`を使用したrepairが必要であることを示しています。このmetadataはESE databaseに格納されており、それぞれphotorecや[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)などのtoolを使用してrecoverおよびinspectできます。**Containers** tableでは、各データsegmentが保存されているspecific tableまたはcontainerを確認できます。これには、Skypeなど他のMicrosoft toolのcache detailsも含まれます。

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) toolを使用するとcacheをinspectできます。その際、cache dataをextractしたfolderの場所が必要です。cacheのmetadataには、filename、directory、access count、URL origin、およびcacheの作成、access、modification、expiry timeを示すtimestampが含まれます。

### Cookies Management

cookiesは[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)を使用して調査できます。metadataには、name、URL、access count、その他のさまざまなtime-related detailsが含まれます。persistent cookieは`%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`に保存され、session cookieはmemory上にあります。

### Download Details

downloadsのmetadataには[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)からaccessできます。specific containerには、URL、file type、download locationなどのデータが格納されています。physical fileは`%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`にあります。

### Browsing History

browsing historyを確認するには、[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)を使用できます。extractしたhistory fileの場所とInternet Explorerの設定が必要です。ここでのmetadataには、modification time、access time、access countが含まれます。history fileは`%userprofile%\Appdata\Local\Microsoft\Windows\History`にあります。

### Typed URLs

入力されたURLとその使用時刻は、`NTUSER.DAT`内のregistryにある`Software\Microsoft\InternetExplorer\TypedURLs`および`Software\Microsoft\InternetExplorer\TypedURLsTime`に保存されます。これらは、ユーザーが入力した直近50件のURLと、それらを最後に入力した時刻を追跡します。

## Microsoft Edge

Microsoft Edgeはユーザーデータを`%userprofile%\Appdata\Local\Packages`に保存します。各種データのpathは次のとおりです:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safariのデータは`/Users/$User/Library/Safari`に保存されます。主なfileは次のとおりです:<sup>[[3]](#references)</sup>

- **History.db**: `history_visits`および`history_items` tableに、URLとvisit timestampが含まれます。queryには`sqlite3`を使用します。
- **Downloads.plist**: downloadしたfileの情報。
- **Bookmarks.plist**: bookmarkしたURLを保存します。
- **TopSites.plist**: 最も頻繁にvisitしたsite。
- **Extensions.plist**: Safari browser extensionのlist。取得には`plutil`または`pluginkit`を使用します。
- **UserNotificationPermissions.plist**: push notificationを許可されたdomain。parseには`plutil`を使用します。
- **LastSession.plist**: 前回のsessionのtab。parseには`plutil`を使用します。
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`を使用して確認します。応答が1の場合、このfeatureはactiveです。<sup>[[2]](#references)</sup>

## Opera

Operaのデータは`/Users/$USER/Library/Application Support/com.operasoftware.Opera`にあり、historyとdownloadsにはChromeと同じformatを使用します。

- **Browser’s built-in anti-phishing**: `grep`を使用してPreferences file内の`fraud_protection_enabled`が`true`に設定されているか確認します。<sup>[[2]](#references)</sup>

これらのpathとcommandは、さまざまなWeb browserが保存するbrowsing dataへのaccessと、その内容の理解に重要です。

## References

- [1] [Web Browsers Forensics: A Guide On Doing Web Browsers Forensic Analysis](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting and Analysis by Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)

{{#include ../../../banners/hacktricks-training.md}}
