# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## ブラウザーのアーティファクト <a href="#id-3def" id="id-3def"></a>

ブラウザーのアーティファクトには、閲覧履歴、ブックマーク、キャッシュデータなど、Webブラウザーに保存されるさまざまな種類のデータが含まれます。これらのアーティファクトはOS内の特定のフォルダーに保存されます。場所や名前はブラウザーによって異なりますが、一般的に類似した種類のデータが保存されています。

よく見られるブラウザーのアーティファクトを以下にまとめます。

- **閲覧履歴**: ユーザーのWebサイトへのアクセスを記録します。悪意のあるサイトへのアクセスを特定するのに役立ちます。
- **オートコンプリートデータ**: 頻繁な検索に基づいて候補を表示します。閲覧履歴と組み合わせることで、さらなる知見が得られます。
- **ブックマーク**: ユーザーがすぐにアクセスできるよう保存したサイトです。
- **拡張機能とアドオン**: ユーザーがインストールしたブラウザーの拡張機能やアドオンです。
- **キャッシュ**: Webサイトの読み込み時間を短縮するため、Webコンテンツ（画像やJavaScriptファイルなど）を保存します。フォレンジック分析にも役立ちます。
- **ログイン情報**: 保存されたログイン認証情報です。
- **ファビコン**: Webサイトに関連付けられたアイコンで、タブやブックマークに表示されます。ユーザーのアクセスに関する追加情報を得るのに役立ちます。
- **ブラウザーセッション**: 開いているブラウザーセッションに関するデータです。
- **ダウンロード**: ブラウザーからダウンロードされたファイルの記録です。
- **フォームデータ**: Webフォームに入力された情報で、今後の自動入力候補として保存されます。
- **サムネイル**: Webサイトのプレビュー画像です。
- **Custom Dictionary.txt**: ユーザーがブラウザーの辞書に追加した単語です。

## Firefox

Firefoxはユーザーデータをプロファイル内に整理して保存します。保存場所はOSによって異なります。<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

これらのディレクトリ内にある`profiles.ini`ファイルには、ユーザープロファイルの一覧が記載されています。各プロファイルのデータは、`profiles.ini`内の`Path`変数で指定された名前のフォルダーに保存されています。このフォルダーは、`profiles.ini`と同じディレクトリにあります。プロファイルのフォルダーが見つからない場合は、削除されている可能性があります。

各プロファイルフォルダーには、重要なファイルがいくつかあります。<sup>[[1]](#references)</sup>

- **places.sqlite**: 履歴、ブックマーク、ダウンロードを保存します。Windowsでは、[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)などのツールで履歴データにアクセスできます。
  - 履歴とダウンロードの情報を抽出するには、特定のSQLクエリを使用します。
- **bookmarkbackups**: ブックマークのバックアップが含まれます。
- **formhistory.sqlite**: Webフォームのデータを保存します。
- **handlers.json**: プロトコルハンドラーを管理します。
- **persdict.dat**: カスタム辞書の単語です。
- **addons.json**および**extensions.sqlite**: インストールされているアドオンと拡張機能に関する情報です。
- **cookies.sqlite**: Cookieを保存します。Windowsでは[MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)で確認できます。
- **cache2/entries**または**startupCache**: キャッシュデータです。[MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html)などのツールでアクセスできます。
- **favicons.sqlite**: ファビコンを保存します。
- **prefs.js**: ユーザー設定と環境設定です。
- **downloads.sqlite**: 古いダウンロードデータベースです。現在はplaces.sqliteに統合されています。
- **thumbnails**: Webサイトのサムネイルです。
- **logins.json**: 暗号化されたログイン情報です。
- **key4.db**または**key3.db**: 機密情報を保護するための暗号化キーを保存します。

また、`prefs.js`内で`browser.safebrowsing`のエントリを検索すると、ブラウザーのフィッシング対策設定を確認できます。これらのエントリから、セーフブラウジング機能が有効か無効かを判断できます。<sup>[[2]](#references)</sup>

アクセス可能なプロファイルから保存済みのログイン情報を復号するには、設定されている場合、[Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins)を入力するか、別途回復する必要があります。プロファイルからこのパスワードを確認することはできません。回復したログイン情報がWebアカウントの認証に使用できることを確認してください。Unixのrootアクセスには、その認証情報がrootに対するUnix認証でも受け入れられることを別途証明する必要があります。[firefox_decrypt](https://github.com/unode/firefox_decrypt)で保存済みログイン情報を確認できます。以下の例では、パスワードファイルから候補となるPrimary Passwordをテストします。

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![ブラウザーのアーティファクト - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chromeは、オペレーティングシステムに応じた特定の場所にユーザープロファイルを保存します:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

これらのディレクトリ内では、ほとんどのユーザーデータが **Default/** または **ChromeDefaultData/** フォルダーにあります。次のファイルには重要なデータが含まれています:<sup>[[1]](#references)</sup>

- **History**: URL、ダウンロード、検索キーワードが含まれます。Windowsでは、[ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html)を使って履歴を確認できます。「Transition Type」列には、リンクのクリック、URLの入力、フォームの送信、ページの再読み込みなど、さまざまな意味があります。
- **Cookies**: Cookieが保存されています。確認には[ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html)を利用できます。
- **Cache**: キャッシュデータが保存されています。確認するには、Windowsユーザーは[ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)を利用できます。

  Electronベースのデスクトップアプリ（例: Discord）もChromium Simple Cacheを使用し、ディスク上に豊富なアーティファクトを残します。次を参照してください:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: ユーザーのブックマーク。
- **Web Data**: フォーム履歴が含まれます。
- **Favicons**: Webサイトのfaviconが保存されています。
- **Login Data**: ユーザー名やパスワードなどのログイン認証情報が含まれます。
- **Current Session**/**Current Tabs**: 現在の閲覧セッションと開いているタブのデータ。
- **Last Session**/**Last Tabs**: Chromeを閉じる前の前回のセッションでアクティブだったサイトの情報。
- **Extensions**: ブラウザー拡張機能とアドオンのディレクトリ。
- **Thumbnails**: Webサイトのサムネイルが保存されています。
- **Preferences**: プラグイン、拡張機能、ポップアップ、通知などの設定を含む、情報量の多いファイル。
- **ブラウザー内蔵のフィッシング対策**: フィッシング対策とマルウェア保護が有効か確認するには、`grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`を実行します。出力に`{"enabled: true,"}`があるか確認してください。<sup>[[2]](#references)</sup>

Chromiumプロファイルの`Local Extension Settings/<extension-id>/`ディレクトリには、パスワードマネージャーの鍵マテリアルなど、拡張機能固有の状態が保存されている場合があります。たとえば、[Passboltによると、暗号化された秘密鍵はブラウザー拡張機能のローカルストレージに保存されます](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/)。また、その[Chrome拡張機能ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf)から、該当するディレクトリを特定できます。ディレクトリが存在するだけでは、鍵が保存されている証拠にも、vaultのロックを解除できる根拠にもなりません。ユーザーがプロファイルデータにアクセスでき、使用可能な秘密鍵とパスフレーズを持ち、サーバーへの認可済みの復旧・認証手段を利用できる必要があります。vault内のアイテムにオペレーティングシステムのアカウントパスワードが含まれる場合は、アカウントの使い回しを別途検証する必要があります。通常の列挙では、LevelDBファイルや秘密値をダンプせず、ストレージパスのみを報告してください。

## **SQLite DB Data Recovery**

前のセクションで確認したように、ChromeとFirefoxはどちらもデータの保存に **SQLite** データベースを使用します。[**sqlparse**](https://github.com/padfoot999/sqlparse) **または** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **ツールを使って、削除されたエントリを復元できます**。

## **Internet Explorer 11**

Internet Explorer 11は、データとメタデータをさまざまな場所に分けて管理します。これにより、保存された情報とそれに対応する詳細が分離され、容易にアクセスおよび管理できます。

### メタデータの保存場所

Internet Explorerのメタデータは`%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`（VXはV01、V16、またはV24）に保存されます。これに関連する`V01.log`ファイルと`WebcacheVX.data`の更新時刻に食い違いがある場合、`esentutl /r V01 /d`を使った修復が必要であることを示している可能性があります。ESEデータベースに格納されたこのメタデータは、photorecなどのツールで復元し、[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)などで調査できます。**Containers**テーブルでは、各データセグメントの保存先となるテーブルやコンテナを特定できます。これには、Skypeなど他のMicrosoftツールのキャッシュ情報も含まれます。

### キャッシュの調査

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html)ツールを使ってキャッシュを調査できます。その際、抽出したキャッシュデータのフォルダーの場所を指定する必要があります。キャッシュのメタデータには、ファイル名、ディレクトリ、アクセス回数、URLの接続元、キャッシュの作成時刻、アクセス時刻、変更時刻、有効期限を示すタイムスタンプが含まれます。

### Cookieの管理

[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)を使ってCookieを調査できます。メタデータには、名前、URL、アクセス回数、各種時刻情報が含まれます。永続Cookieは`%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`に保存され、セッションCookieはメモリに保存されます。

### ダウンロードの詳細

ダウンロードのメタデータは[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)で確認できます。特定のコンテナには、URL、ファイルの種類、ダウンロード先などのデータが含まれます。実ファイルは`%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`にあります。

### 閲覧履歴

閲覧履歴を確認するには、[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)を利用できます。抽出した履歴ファイルの場所を指定し、Internet Explorer向けに設定する必要があります。ここに含まれるメタデータには、変更時刻とアクセス時刻、およびアクセス回数があります。履歴ファイルは`%userprofile%\Appdata\Local\Microsoft\Windows\History`にあります。

### 入力したURL

入力したURLとその入力時刻は、レジストリの`NTUSER.DAT`内にある`Software\Microsoft\InternetExplorer\TypedURLs`および`Software\Microsoft\InternetExplorer\TypedURLsTime`に保存されます。ここには、ユーザーが入力した直近50件のURLと、それぞれの最終入力時刻が記録されています。

## Microsoft Edge

Microsoft Edgeはユーザーデータを`%userprofile%\Appdata\Local\Packages`に保存します。データの種類ごとのパスは次のとおりです:<sup>[[1]](#references)</sup>

- **プロファイルパス**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **履歴、Cookie、ダウンロード**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **設定、ブックマーク、リーディングリスト**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **キャッシュ**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **最後にアクティブだったセッション**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safariのデータは`/Users/$User/Library/Safari`に保存されます。主なファイルは次のとおりです:<sup>[[3]](#references)</sup>

- **History.db**: URLと訪問時刻を含む`history_visits`テーブルと`history_items`テーブルがあります。クエリには`sqlite3`を使用します。
- **Downloads.plist**: ダウンロードしたファイルに関する情報。
- **Bookmarks.plist**: ブックマークしたURLが保存されています。
- **TopSites.plist**: 最も頻繁に訪問したサイト。
- **Extensions.plist**: Safariブラウザー拡張機能の一覧。取得には`plutil`または`pluginkit`を使用します。
- **UserNotificationPermissions.plist**: プッシュ通知を許可されたドメイン。解析には`plutil`を使用します。
- **LastSession.plist**: 前回のセッションのタブ。解析には`plutil`を使用します。
- **ブラウザー内蔵のフィッシング対策**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`を使って確認します。応答が1なら、この機能は有効です。<sup>[[2]](#references)</sup>

## Opera

Operaのデータは`/Users/$USER/Library/Application Support/com.operasoftware.Opera`にあり、履歴とダウンロードにはChromeと同じ形式を使用します。

- **ブラウザー内蔵のフィッシング対策**: `grep`を使ってPreferencesファイル内の`fraud_protection_enabled`が`true`に設定されているか確認します。<sup>[[2]](#references)</sup>

これらのパスとコマンドは、各種Webブラウザーに保存された閲覧データにアクセスし、内容を把握するうえで重要です。

## References

- [1] [Webブラウザーのフォレンジック: Webブラウザーのフォレンジック分析ガイド](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOSインシデント対応 | Part 3: システム操作](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS Xインシデント対応: Jaron Bradleyによるスクリプト作成と分析](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
