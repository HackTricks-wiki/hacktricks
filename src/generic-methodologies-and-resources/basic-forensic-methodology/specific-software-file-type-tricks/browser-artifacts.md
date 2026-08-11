# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Browsers Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifactsには、navigation history、bookmarks、cache dataなど、web browsersによって保存されるさまざまな種類のデータが含まれます。これらのartifactsは、operating system内の特定のfolderに保存されます。browserごとに場所や名前は異なりますが、一般的には同様の種類のデータが保存されています。

最も一般的なbrowser artifactsの概要は次のとおりです。

- **Navigation History**: ユーザーがwebsitesを訪問した記録です。malicious sitesへのアクセスを特定するのに役立ちます。
- **Autocomplete Data**: 頻繁な検索に基づく候補です。navigation historyと組み合わせることで、より詳しい情報が得られます。
- **Bookmarks**: ユーザーがすばやくアクセスできるよう保存したsitesです。
- **Extensions and Add-ons**: ユーザーがインストールしたbrowser extensionsまたはadd-onsです。
- **Cache**: websiteの読み込み時間を短縮するため、web content（画像やJavaScript filesなど）を保存します。forensic analysisに役立ちます。
- **Logins**: 保存されたlogin credentialsです。
- **Favicons**: websitesに関連付けられたiconsで、tabsやbookmarksに表示されます。ユーザーのvisitsに関する追加情報として役立ちます。
- **Browser Sessions**: 開いているbrowser sessionsに関連するデータです。
- **Downloads**: browser経由でdownloadされたfilesの記録です。
- **Form Data**: web formsに入力された情報で、将来のautofill候補として保存されます。
- **Thumbnails**: websitesのpreview imagesです。
- **Custom Dictionary.txt**: ユーザーがbrowserのdictionaryに追加したwordsです。

## Firefox

Firefoxは、operating systemに応じた特定の場所に保存されたprofiles内でユーザーデータを管理します:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

これらのdirectories内にある`profiles.ini` fileには、user profilesの一覧が記載されています。各profileのdataは、`profiles.ini`内の`Path` variableで指定された名前のfolderに保存されます。このfolderは、`profiles.ini`自体と同じdirectory内にあります。profileのfolderが存在しない場合、削除された可能性があります。

各profile folder内には、いくつかの重要なfilesがあります:<sup>[[1]](#references)</sup>

- **places.sqlite**: history、bookmarks、downloadsを保存します。Windowsの[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)などのtoolsでhistory dataにアクセスできます。
- historyとdownloadsの情報を抽出するには、特定のSQL queriesを使用します。
- **bookmarkbackups**: bookmarksのbackupsが含まれます。
- **formhistory.sqlite**: web form dataを保存します。
- **handlers.json**: protocol handlersを管理します。
- **persdict.dat**: custom dictionaryのwordsです。
- **addons.json**および**extensions.sqlite**: インストールされているadd-onsとextensionsに関する情報です。
- **cookies.sqlite**: cookie storageです。Windowsでは[MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)を使用して確認できます。
- **cache2/entries**または**startupCache**: cache dataです。[MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html)などのtoolsでアクセスできます。
- **favicons.sqlite**: faviconsを保存します。
- **prefs.js**: ユーザーのsettingsとpreferencesです。
- **downloads.sqlite**: 以前のdownloads databaseです。現在はplaces.sqliteに統合されています。
- **thumbnails**: website thumbnailsです。
- **logins.json**: 暗号化されたlogin informationです。
- **key4.db**または**key3.db**: 機密情報を保護するためのencryption keysを保存します。

さらに、`prefs.js`内で`browser.safebrowsing` entriesを検索すると、browserのanti-phishing settingsを確認できます。これにより、safe browsing featuresが有効か無効かを確認できます。<sup>[[2]](#references)</sup>

master passwordのdecryptを試すには、[https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)を使用できます。\
次のscriptとcallを使用すると、brute force用のpassword fileを指定できます:
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

Google Chromeは、OSに基づいた特定の場所にユーザープロファイルを保存します:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

これらのディレクトリ内では、ほとんどのユーザーデータが **Default/** または **ChromeDefaultData/** フォルダにあります。以下のファイルには重要なデータが含まれています:<sup>[[1]](#references)</sup>

- **History**: URL、downloads、検索キーワードが含まれます。Windowsでは、履歴の読み取りに [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) を使用できます。「Transition Type」列には、リンクへのユーザークリック、入力されたURL、form submissions、ページのreloadなど、さまざまな意味があります。
- **Cookies**: cookiesを保存します。確認には [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) を使用できます。
- **Cache**: cached dataを保持します。Windowsユーザーは、確認に [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) を利用できます。

Electronベースのdesktop apps（例: Discord）もChromium Simple Cacheを使用し、ディスク上に豊富なartifactsを残します。以下を参照してください:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: ユーザーのbookmarks。
- **Web Data**: form historyが含まれます。
- **Favicons**: website faviconsを保存します。
- **Login Data**: usernamesやpasswordsなどのlogin credentialsが含まれます。
- **Current Session**/**Current Tabs**: 現在のbrowsing sessionとopen tabsに関するデータ。
- **Last Session**/**Last Tabs**: Chromeが閉じられる前の、前回のsessionでactiveだったsitesに関する情報。
- **Extensions**: browser extensionsとaddonsのディレクトリ。
- **Thumbnails**: website thumbnailsを保存します。
- **Preferences**: plugins、extensions、pop-ups、notificationsなどの設定を含む、情報量の多いファイルです。
- **Browser’s built-in anti-phishing**: anti-phishingとmalware protectionが有効か確認するには、`grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`を実行します。出力に`{"enabled: true,"}`が含まれているか確認します。<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

前のセクションで確認できるように、ChromeとFirefoxはどちらもデータの保存に **SQLite** databasesを使用します。[**sqlparse**](https://github.com/padfoot999/sqlparse) **または** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **toolを使用して、削除されたentriesを** **recover**することが可能です。

## **Internet Explorer 11**

Internet Explorer 11は、さまざまな場所にデータとmetadataを管理して保存します。これにより、保存された情報と対応するdetailsを分離し、簡単にaccessおよびmanagementできるようにしています。

### Metadata Storage

Internet Explorerのmetadataは、`%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`（VXはV01、V16、またはV24）に保存されます。これに関連して、`V01.log`ファイルには`WebcacheVX.data`とのmodification timeの不一致が示される場合があり、その場合は`esentutl /r V01 /d`を使用したrepairが必要です。このmetadataはESE databaseに格納されており、photorecなどのtoolsでrecoverし、[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)でinspectできます。**Containers** tableでは、各data segmentが保存されているspecific tablesまたはcontainersを特定できます。これには、Skypeなど他のMicrosoft toolsのcache detailsも含まれます。

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) toolを使用するとcacheをinspectできますが、cache dataをextractするfolderのlocationが必要です。cacheのmetadataには、filename、directory、access count、URL origin、およびcacheのcreation、access、modification、expiry timesを示すtimestampsが含まれます。

### Cookies Management

cookiesは[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)を使用して確認できます。metadataには、names、URLs、access counts、およびさまざまなtime-related detailsが含まれます。persistent cookiesは`%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`に保存され、session cookiesはmemory上に存在します。

### Download Details

downloadsのmetadataには[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)からaccessできます。specific containersには、URL、file type、download locationなどのdataが保存されています。physical filesは`%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`にあります。

### Browsing History

browsing historyを確認するには、[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)を使用できます。extractされたhistory filesのlocationと、Internet Explorerのconfigurationが必要です。ここでのmetadataにはmodification times、access times、access countsが含まれます。history filesは`%userprofile%\Appdata\Local\Microsoft\Windows\History`にあります。

### Typed URLs

typed URLsとそのusage timingsは、`NTUSER.DAT`内のregistryにある`Software\Microsoft\InternetExplorer\TypedURLs`および`Software\Microsoft\InternetExplorer\TypedURLsTime`に保存されます。これらは、ユーザーが入力した最後の50個のURLsと、それらのlast input timesを追跡します。

## Microsoft Edge

Microsoft Edgeはユーザーデータを`%userprofile%\Appdata\Local\Packages`に保存します。各種data typesのpathsは次のとおりです:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari dataは`/Users/$User/Library/Safari`に保存されます。主なfilesは次のとおりです:<sup>[[3]](#references)</sup>

- **History.db**: `history_visits`および`history_items` tablesが含まれ、URLsとvisit timestampsを保持します。queryには`sqlite3`を使用します。
- **Downloads.plist**: downloaded filesに関する情報。
- **Bookmarks.plist**: bookmarked URLsを保存します。
- **TopSites.plist**: 最も頻繁に訪問されたsites。
- **Extensions.plist**: Safari browser extensionsのlist。取得には`plutil`または`pluginkit`を使用します。
- **UserNotificationPermissions.plist**: push notificationsを許可されたdomains。parseには`plutil`を使用します。
- **LastSession.plist**: 前回のsessionのtabs。parseには`plutil`を使用します。
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`を使用して確認します。応答が1の場合、このfeatureはactiveです。<sup>[[2]](#references)</sup>

## Opera

Operaのdataは`/Users/$USER/Library/Application Support/com.operasoftware.Opera`にあり、historyとdownloadsにはChromeと同じformatを使用します。

- **Browser’s built-in anti-phishing**: Preferences fileの`fraud_protection_enabled`が`true`に設定されているかを`grep`で確認します。<sup>[[2]](#references)</sup>

これらのpathsとcommandsは、各種web browsersによって保存されたbrowsing dataへのaccessと理解に不可欠です。

## References

- [1] [Web Browsers Forensics: Web Browsers Forensic Analysisの実施ガイド](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Jaron Bradley著 OS X Incident Response: Scripting and Analysis](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
