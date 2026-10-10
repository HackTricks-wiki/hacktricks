# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## ブラウザーのアーティファクト <a href="#id-3def" id="id-3def"></a>

ブラウザーのアーティファクトには、閲覧履歴、ブックマーク、キャッシュデータなど、Webブラウザーに保存されるさまざまな種類のデータが含まれます。これらのアーティファクトはオペレーティングシステム内の特定のフォルダーに保存されます。保存場所やフォルダー名はブラウザーごとに異なりますが、一般的には同様の種類のデータが保存されています。

一般的なブラウザーのアーティファクトを以下にまとめます。

- **閲覧履歴**: ユーザーのWebサイト訪問を記録し、悪意のあるサイトへのアクセスを特定するのに役立ちます。
- **オートコンプリートデータ**: 頻繁な検索に基づく候補です。閲覧履歴と組み合わせると、ユーザーに関する情報が得られます。
- **ブックマーク**: ユーザーがすばやくアクセスできるように保存したサイトです。
- **拡張機能とアドオン**: ユーザーがインストールしたブラウザー拡張機能やアドオンです。
- **キャッシュ**: Webコンテンツ（画像やJavaScriptファイルなど）を保存してWebサイトの読み込み時間を短縮します。フォレンジック分析にも役立ちます。
- **ログイン情報**: 保存されたログイン認証情報です。
- **ファビコン**: Webサイトに関連付けられたアイコンで、タブやブックマークに表示されます。ユーザーの訪問に関する追加情報を得るのに役立ちます。
- **ブラウザーセッション**: 開いているブラウザーセッションに関連するデータです。
- **ダウンロード**: ブラウザーからダウンロードされたファイルの記録です。
- **フォームデータ**: Webフォームに入力された情報で、今後の自動入力候補として保存されます。
- **サムネイル**: Webサイトのプレビュー画像です。
- **Custom Dictionary.txt**: ユーザーがブラウザーの辞書に追加した単語です。

## Firefox

Firefoxはユーザーデータをプロファイル内に整理して保存します。保存場所はオペレーティングシステムによって異なります。<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

これらのディレクトリ内にある`profiles.ini`ファイルには、ユーザープロファイルの一覧が記載されています。各プロファイルのデータは、`profiles.ini`内の`Path`変数で指定された名前のフォルダーに保存されます。このフォルダーは`profiles.ini`と同じディレクトリにあります。プロファイルのフォルダーが見つからない場合は、削除された可能性があります。

各プロファイルフォルダーには、重要なファイルがいくつかあります。<sup>[[1]](#references)</sup>

- **places.sqlite**: 履歴、ブックマーク、ダウンロードを保存します。Windowsでは、[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)などのツールで履歴データにアクセスできます。
  - 特定のSQLクエリを使用して、履歴とダウンロードの情報を抽出します。
- **bookmarkbackups**: ブックマークのバックアップが含まれます。
- **formhistory.sqlite**: Webフォームのデータを保存します。
- **handlers.json**: プロトコルハンドラーを管理します。
- **persdict.dat**: カスタム辞書の単語を保存します。
- **addons.json**および**extensions.sqlite**: インストール済みのアドオンと拡張機能に関する情報です。
- **cookies.sqlite**: Cookieを保存します。Windowsでは[MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)で調査できます。
- **cache2/entries**または**startupCache**: キャッシュデータです。[MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html)などのツールでアクセスできます。
- **favicons.sqlite**: ファビコンを保存します。
- **prefs.js**: ユーザー設定と環境設定です。
- **downloads.sqlite**: 以前のダウンロードデータベースです。現在はplaces.sqliteに統合されています。
- **thumbnails**: Webサイトのサムネイルです。
- **logins.json**: 暗号化されたログイン情報です。
- **key4.db**または**key3.db**: 機密情報を保護するための暗号化キーを保存します。

また、`prefs.js`内で`browser.safebrowsing`のエントリーを検索すると、フィッシング対策設定を確認できます。これらのエントリーは、セーフブラウジング機能が有効か無効かを示します。<sup>[[2]](#references)</sup>

アクセス可能なプロファイルから保存済みログイン情報を復号するには、設定されている場合、[Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins)を入力するか、別途入手する必要があります。プロファイルからこのパスワードを確認することはできません。復元したログイン情報がWebアカウントへの認証に使えることを確認してください。Unixのrootアクセスについては、その認証情報がUnixのroot認証でも受け入れられることを別途証明する必要があります。[firefox_decrypt](https://github.com/unode/firefox_decrypt)を使って保存済みログイン情報を確認できます。以下の例では、パスワードファイル内の候補を使ってPrimary Passwordを試します。

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

Google Chromeは、OSに応じた特定の場所にユーザープロファイルを保存します:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

これらのディレクトリ内では、ユーザーデータの大半は**Default/**または**ChromeDefaultData/**フォルダーにあります。重要なデータを含むファイルは次のとおりです:<sup>[[1]](#references)</sup>

- **History**: URL、ダウンロード、検索キーワードが含まれます。Windowsでは、履歴の読み取りに[ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html)を使用できます。「Transition Type」列には、リンクのクリック、入力されたURL、フォーム送信、ページの再読み込みなど、さまざまな意味があります。
- **Cookies**: Cookieを保存します。確認には[ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html)を利用できます。
- **Cache**: キャッシュデータを保持します。確認には、Windowsユーザーは[ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)を利用できます。

  Electronベースのデスクトップアプリ（例: Discord）もChromium Simple Cacheを使用し、豊富なディスク上の痕跡を残します。次を参照してください:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: ユーザーのブックマークです。
- **Web Data**: フォーム履歴が含まれます。
- **Favicons**: Webサイトのファビコンを保存します。
- **Login Data**: ユーザー名やパスワードなどのログイン認証情報が含まれます。
- **Current Session**/**Current Tabs**: 現在の閲覧セッションと開いているタブに関するデータです。
- **Last Session**/**Last Tabs**: Chromeを閉じる直前のセッションでアクティブだったサイトに関する情報です。
- **Extensions**: ブラウザー拡張機能とアドオンのディレクトリです。
- **Thumbnails**: Webサイトのサムネイルを保存します。
- **Preferences**: プラグイン、拡張機能、ポップアップ、通知などの設定を含む、情報量の多いファイルです。
- **ブラウザー組み込みのanti-phishing機能**: anti-phishingとマルウェア保護が有効か確認するには、`grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`を実行します。出力に`{"enabled: true,"}`が含まれているか確認してください。<sup>[[2]](#references)</sup>

Chromiumプロファイルの`Local Extension Settings/<extension-id>/`ディレクトリには、パスワードマネージャーの鍵素材など、拡張機能固有の状態が保存されている場合があります。たとえば、[Passboltによると、暗号化された秘密鍵はブラウザー拡張機能のローカルストレージに保存されています](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/)。また、[Chrome拡張機能のID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf)から、該当するディレクトリを特定できます。ディレクトリが存在するだけでは、鍵の存在は証明されず、vaultのロックも解除されません。ユーザーがプロファイルデータ、使用可能な秘密鍵とパスフレーズ、およびサーバーへの認可された復旧／認証経路にアクセスできる必要があります。vault内のアイテムにOSアカウントのパスワードが含まれる場合は、別途アカウントの再利用を検証する必要があります。通常の列挙では、LevelDBファイルや秘密の値をダンプせず、保存先のパスのみを報告してください。

## **SQLite DBデータの復旧**

前のセクションで確認したように、ChromeとFirefoxはどちらも**SQLite**データベースを使用してデータを保存します。[**sqlparse**](https://github.com/padfoot999/sqlparse)または[**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases)ツールを使って、削除されたエントリを**復旧**できます。

## **Internet Explorer 11**

Internet Explorer 11は、データとメタデータをさまざまな場所に分けて管理し、保存情報とそれに対応する詳細情報を分離することで、簡単にアクセス・管理できるようにしています。

### メタデータの保存先

Internet Explorerのメタデータは`%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`に保存されます（VXはV01、V16、またはV24）。関連する`V01.log`ファイルの更新時刻が`WebcacheVX.data`と一致しない場合があり、その場合は`esentutl /r V01 /d`を使用した修復が必要であることを示している可能性があります。このメタデータはESEデータベースに保存されており、photorecなどのツールで復旧し、[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)で調査できます。**Containers**テーブルでは、各データセグメントが保存されているテーブルまたはコンテナを確認できます。これには、Skypeなど他のMicrosoftツールのキャッシュ情報も含まれます。

### キャッシュの調査

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html)ツールを使ってキャッシュを調査できます。その際、キャッシュデータを抽出したフォルダーの場所が必要です。キャッシュのメタデータには、ファイル名、ディレクトリ、アクセス回数、URLの取得元、キャッシュの作成・アクセス・変更・有効期限のタイムスタンプが含まれます。

### Cookieの管理

[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)を使ってCookieを調査できます。メタデータには、名前、URL、アクセス回数、各種時刻情報が含まれます。永続Cookieは`%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`に保存され、セッションCookieはメモリ内に保存されます。

### ダウンロードの詳細

ダウンロードのメタデータは[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)で確認できます。特定のコンテナには、URL、ファイル形式、ダウンロード先などのデータが含まれます。物理ファイルは`%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`にあります。

### 閲覧履歴

閲覧履歴の確認には[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)を使用できます。抽出した履歴ファイルの場所を指定し、Internet Explorer用に設定する必要があります。このメタデータには、変更時刻とアクセス時刻、およびアクセス回数が含まれます。履歴ファイルは`%userprofile%\Appdata\Local\Microsoft\Windows\History`にあります。

### 入力されたURL

入力されたURLとその使用時刻は、`NTUSER.DAT`内のレジストリキー`Software\Microsoft\InternetExplorer\TypedURLs`および`Software\Microsoft\InternetExplorer\TypedURLsTime`に保存されます。ここには、ユーザーが入力した直近50件のURLと、それぞれの最終入力時刻が記録されています。

## Microsoft Edge

Microsoft Edgeはユーザーデータを`%userprofile%\Appdata\Local\Packages`に保存します。データの種類ごとのパスは次のとおりです:<sup>[[1]](#references)</sup>

- **プロファイルパス**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **履歴、Cookie、ダウンロード**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **設定、ブックマーク、リーディングリスト**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **キャッシュ**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **直近のアクティブセッション**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safariのデータは`/Users/$User/Library/Safari`に保存されます。主なファイルは次のとおりです:<sup>[[3]](#references)</sup>

- **History.db**: URLと訪問時刻を含む`history_visits`テーブルと`history_items`テーブルが含まれます。クエリには`sqlite3`を使用します。
- **Downloads.plist**: ダウンロードしたファイルに関する情報です。
- **Bookmarks.plist**: ブックマークしたURLを保存します。
- **TopSites.plist**: 最も頻繁に訪問したサイトです。
- **Extensions.plist**: Safariブラウザー拡張機能の一覧です。取得には`plutil`または`pluginkit`を使用します。
- **UserNotificationPermissions.plist**: プッシュ通知を許可されたドメインです。解析には`plutil`を使用します。
- **LastSession.plist**: 前回のセッションのタブです。解析には`plutil`を使用します。
- **ブラウザー組み込みのanti-phishing機能**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`で確認します。応答が1なら、この機能は有効です。<sup>[[2]](#references)</sup>

## Opera

Operaのデータは`/Users/$USER/Library/Application Support/com.operasoftware.Opera`にあり、履歴とダウンロードにはChromeと同じ形式が使われます。

- **ブラウザー組み込みのanti-phishing機能**: `grep`を使用してPreferencesファイル内の`fraud_protection_enabled`が`true`に設定されているか確認します。<sup>[[2]](#references)</sup>

これらのパスとコマンドは、さまざまなWebブラウザーに保存された閲覧データにアクセスし、その内容を理解するうえで重要です。

## References

- [1] [Webブラウザーのフォレンジック: Webブラウザーのフォレンジック分析ガイド](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOSインシデントレスポンス | パート3: システム操作](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS Xインシデントレスポンス: Jaron Bradleyによるスクリプト作成と分析](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
