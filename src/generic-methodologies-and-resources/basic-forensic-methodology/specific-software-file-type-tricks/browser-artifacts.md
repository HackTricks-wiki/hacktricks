# Browser Artifacts

## Browser Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifacts には、ナビゲーション履歴、ブックマーク、キャッシュデータなど、Web browsers によって保存されるさまざまな種類のデータが含まれます。これらの artifacts は operating system 内の特定のフォルダに保存され、browser によって場所や名前は異なりますが、一般的には類似した種類のデータが保存されています。

以下は、最も一般的な browser artifacts の概要です。

- **Navigation History**: ユーザーが Web サイトを訪問した記録で、悪意のあるサイトへのアクセスを特定する際に役立ちます。
- **Autocomplete Data**: 頻繁な検索に基づく候補で、ナビゲーション履歴と組み合わせることで有用な情報が得られます。
- **Bookmarks**: ユーザーがすばやくアクセスできるよう保存したサイトです。
- **Extensions and Add-ons**: ユーザーがインストールした browser extensions または add-ons です。
- **Cache**: Web サイトの読み込み時間を短縮するために Web コンテンツ（画像や JavaScript ファイルなど）を保存したもので、forensic analysis に役立ちます。
- **Logins**: 保存されたログイン credentials です。
- **Favicons**: Web サイトに関連付けられたアイコンで、tabs や bookmarks に表示され、ユーザーの訪問に関する追加情報として役立ちます。
- **Browser Sessions**: 開いている browser sessions に関連するデータです。
- **Downloads**: browser を通じてダウンロードされたファイルの記録です。
- **Form Data**: Web forms に入力された情報で、後の autofill 候補のために保存されます。
- **Thumbnails**: Web サイトの preview images です。
- **Custom Dictionary.txt**: ユーザーが browser の dictionary に追加した単語です。

## Firefox

Firefox は user data を profiles 内で管理し、operating system に応じた特定の場所に保存します:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

これらのディレクトリ内にある `profiles.ini` ファイルには、user profiles の一覧が記載されています。各 profile の data は、`profiles.ini` 内の `Path` variable で指定された folder に保存されます。この folder は `profiles.ini` 自体と同じ directory にあります。profile の folder が存在しない場合、削除された可能性があります。

各 profile folder 内には、重要なファイルがいくつかあります:<sup>[[1]](#references)</sup>

- **places.sqlite**: history、bookmarks、downloads を保存します。Windows の [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) などの tools で history data にアクセスできます。
- history と downloads の情報を抽出するには、特定の SQL queries を使用します。
- **bookmarkbackups**: bookmarks の backups が含まれています。
- **formhistory.sqlite**: Web form data を保存します。
- **handlers.json**: protocol handlers を管理します。
- **persdict.dat**: custom dictionary の単語です。
- **addons.json** および **extensions.sqlite**: インストールされている add-ons と extensions の情報です。
- **cookies.sqlite**: cookie storage で、Windows では [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) を使用して確認できます。
- **cache2/entries** または **startupCache**: cache data で、[MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) などの tools からアクセスできます。
- **favicons.sqlite**: favicons を保存します。
- **prefs.js**: user settings と preferences です。
- **downloads.sqlite**: 以前の downloads database で、現在は places.sqlite に統合されています。
- **thumbnails**: Web サイトの thumbnails です。
- **logins.json**: 暗号化された login information です。
- **key4.db** または **key3.db**: 機密情報を保護するための encryption keys を保存します。

さらに、browser の anti-phishing settings は、`prefs.js` 内で `browser.safebrowsing` entries を検索することで確認できます。これにより、safe browsing features が enabled か disabled かを判断できます。<sup>[[2]](#references)</sup>

master password の decrypt を試みるには、[https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) を使用できます\
以下の script と call を使用すると、brute force 用の password file を指定できます:
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

Google Chromeは、OSに応じて特定の場所にユーザープロファイルを保存します:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

これらのディレクトリ内では、ほとんどのユーザーデータが**Default/**または**ChromeDefaultData/**フォルダにあります。以下のファイルには重要なデータが含まれています:<sup>[[1]](#references)</sup>

- **History**: URL、downloads、検索キーワードが含まれます。Windowsでは、履歴の読み取りに[ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html)を使用できます。「Transition Type」列には、ユーザーによるリンクのクリック、入力されたURL、form submissions、ページのreloadなど、さまざまな意味があります。
- **Cookies**: cookiesを保存します。確認には[ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html)を使用できます。
- **Cache**: cacheされたデータを保持します。Windowsユーザーは、確認に[ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)を使用できます。

Electronベースのdesktop apps（Discordなど）もChromium Simple Cacheを使用し、ディスク上に豊富なartifactsを残します。以下を参照してください:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: ユーザーのbookmarks。
- **Web Data**: form historyが含まれます。
- **Favicons**: Webサイトのfaviconsを保存します。
- **Login Data**: usernameやpasswordなどのlogin credentialsが含まれます。
- **Current Session**/**Current Tabs**: 現在のbrowsing sessionと開いているtabsに関するデータ。
- **Last Session**/**Last Tabs**: Chromeが閉じられる前の、最後のsessionでactiveだったサイトに関する情報。
- **Extensions**: browser extensionsとaddonsのディレクトリ。
- **Thumbnails**: Webサイトのthumbnailsを保存します。
- **Preferences**: plugins、extensions、pop-ups、notificationsなどの設定を含む、情報量の多いファイルです。
- **Browser’s built-in anti-phishing**: anti-phishingとmalware protectionが有効か確認するには、`grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`を実行します。出力内で`{"enabled: true,"}`を探します。<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

前のセクションで確認できるように、ChromeとFirefoxはいずれもデータの保存に**SQLite** databasesを使用します。[**sqlparse**](https://github.com/padfoot999/sqlparse) **または** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **toolを使用して、削除されたentriesをrecoverすることが可能です**。

## **Internet Explorer 11**

Internet Explorer 11は、さまざまな場所にデータとmetadataを保存します。これにより、保存された情報と対応するdetailsを分離し、容易にアクセスおよび管理できます。

### Metadata Storage

Internet Explorerのmetadataは、`%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`（VXはV01、V16、またはV24）に保存されます。これに伴い、`V01.log`ファイルと`WebcacheVX.data`の間にmodification timeの不一致が表示される場合があり、その場合は`esentutl /r V01 /d`を使用したrepairが必要です。このmetadataはESE databaseに格納されており、photorecなどのtoolsでrecoverし、[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)でinspectできます。**Containers** tableでは、Skypeなど他のMicrosoft toolsのcache detailsを含め、各data segmentが保存されている特定のtablesまたはcontainersを確認できます。

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) toolを使用するとcacheをinspectできますが、cache dataをextractしたfolderの場所が必要です。cacheのmetadataには、filename、directory、access count、URL origin、cacheのcreation、access、modification、expiry timesを示すtimestampsが含まれます。

### Cookies Management

cookiesは[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)を使用して確認できます。metadataには、names、URLs、access counts、その他のさまざまなtime-related detailsが含まれます。persistent cookiesは`%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`に保存され、session cookiesはmemory内に存在します。

### Download Details

downloadsのmetadataは[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)からaccessできます。specific containersには、URL、file type、download locationなどのデータが保存されています。physical filesは`%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`にあります。

### Browsing History

browsing historyを確認するには、[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)を使用できます。extractしたhistory filesの場所とInternet Explorerのconfigurationが必要です。ここでのmetadataには、modification times、access times、access countsが含まれます。history filesは`%userprofile%\Appdata\Local\Microsoft\Windows\History`にあります。

### Typed URLs

typed URLsとその使用timingsは、`NTUSER.DAT`内のregistryにある`Software\Microsoft\InternetExplorer\TypedURLs`および`Software\Microsoft\InternetExplorer\TypedURLsTime`に保存されます。これらは、ユーザーが入力した最後の50個のURLsと、それぞれの最後の入力時刻を記録します。

## Microsoft Edge

Microsoft Edgeはユーザーデータを`%userprofile%\Appdata\Local\Packages`に保存します。各種データのpathsは次のとおりです:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safariのデータは`/Users/$User/Library/Safari`に保存されます。主なfilesは次のとおりです:<sup>[[3]](#references)</sup>

- **History.db**: `history_visits`と`history_items` tablesに、URLsとvisit timestampsが含まれます。queryには`sqlite3`を使用します。
- **Downloads.plist**: downloaded filesに関する情報。
- **Bookmarks.plist**: bookmarked URLsを保存します。
- **TopSites.plist**: 最も頻繁に訪問されたsites。
- **Extensions.plist**: Safari browser extensionsのlist。取得には`plutil`または`pluginkit`を使用します。
- **UserNotificationPermissions.plist**: push notificationsを許可されたdomains。parseには`plutil`を使用します。
- **LastSession.plist**: 最後のsessionのtabs。parseには`plutil`を使用します。
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`を使用して確認します。応答が1の場合、このfeatureはactiveです。<sup>[[2]](#references)</sup>

## Opera

Operaのデータは`/Users/$USER/Library/Application Support/com.operasoftware.Opera`にあり、historyとdownloadsにはChromeと同じformatを使用します。

- **Browser’s built-in anti-phishing**: `grep`を使用してPreferences file内の`fraud_protection_enabled`が`true`に設定されているか確認します。<sup>[[2]](#references)</sup>

これらのpathsとcommandsは、各種web browsersが保存するbrowsing dataへのaccessと、その理解に不可欠です。

## References

- [1] [Web Browsers Forensics: Web Browsers Forensic Analysisの実施ガイド](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Jaron BradleyによるScripting and Analysis](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
