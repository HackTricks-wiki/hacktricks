# ブラウザアーティファクト

{{#include ../../../banners/hacktricks-training.md}}

## Browsers Artifacts <a href="#id-3def" id="id-3def"></a>

ブラウザアーティファクトは、ナビゲーション履歴、ブックマーク、キャッシュデータなど、Webブラウザによって保存されるさまざまな種類のデータを含みます。これらのアーティファクトはOS内の特定フォルダに保持され、ブラウザごとに場所や名前は異なりますが、一般的に類似したデータを格納します。

ここでは、最も一般的なブラウザアーティファクトの概要を示します:

- **Navigation History**: ユーザーのウェブサイト訪問を追跡し、悪意のあるサイトへの訪問特定に役立ちます。
- **Autocomplete Data**: 頻繁な検索に基づく候補で、Navigation Historyと組み合わせると洞察が得られます。
- **Bookmarks**: ユーザーが素早くアクセスするために保存したサイト。
- **Extensions and Add-ons**: ユーザーがインストールしたブラウザ拡張やアドオン。
- **Cache**: 画像やJavaScriptファイルなどのWebコンテンツを保存し、サイト読み込みを高速化する。フォレンジックで価値があることがあります。
- **Logins**: 保存されたログイン資格情報。
- **Favicons**: タブやブックマークに表示されるサイトのアイコンで、ユーザーの訪問に関する追加情報に有用です。
- **Browser Sessions**: 開いているブラウザセッションに関連するデータ。
- **Downloads**: ブラウザ経由でダウンロードしたファイルの記録。
- **Form Data**: Webフォームに入力された情報で、将来のオートフィル候補として保存されます。
- **Thumbnails**: サイトのプレビュー画像。
- **Custom Dictionary.txt**: ユーザーがブラウザの辞書に追加した単語。

## Firefox

Firefoxはユーザーデータをプロファイル内で整理し、OSに応じて特定の場所に保存します:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

これらのディレクトリ内にある `profiles.ini` ファイルはユーザープロファイルを一覧表示します。各プロファイルのデータは `profiles.ini` 内の `Path` 変数で指定された名前のフォルダに保存され、`profiles.ini` と同じディレクトリにあります。プロファイルのフォルダが存在しない場合は削除されている可能性があります。

各プロファイルフォルダ内には、いくつかの重要なファイルがあります:

- **places.sqlite**: 履歴、ブックマーク、ダウンロードを保存します。Windowsでは [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) のようなツールで履歴データにアクセスできます。
- 特定のSQLクエリを使用して履歴やダウンロード情報を抽出します。
- **bookmarkbackups**: ブックマークのバックアップを含みます。
- **formhistory.sqlite**: Webフォームデータを保存します。
- **handlers.json**: プロトコルハンドラを管理します。
- **persdict.dat**: カスタム辞書の単語。
- **addons.json** と **extensions.sqlite**: インストールされたアドオンと拡張機能の情報。
- **cookies.sqlite**: Cookieの保存。Windowsでは [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) を使って確認できます。
- **cache2/entries** または **startupCache**: キャッシュデータ。 [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) のようなツールでアクセスできます。
- **favicons.sqlite**: ファビコンを保存します。
- **prefs.js**: ユーザー設定とプリファレンス。
- **downloads.sqlite**: 旧ダウンロードデータベース（現在は places.sqlite に統合）。
- **thumbnails**: ウェブサイトのサムネイル。
- **logins.json**: 暗号化されたログイン情報。
- **key4.db** または **key3.db**: 機密情報を保護するための暗号化キーを保存します。

さらに、ブラウザのアンチフィッシング設定は `prefs.js` 内の `browser.safebrowsing` エントリを検索することで、セーフブラウジング機能が有効か無効かを確認できます。

To try to decrypt the master password, you can use [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
With the following script and call you can specify a password file to brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (692).png>)

## Google Chrome

Google Chrome はオペレーティングシステムに応じてユーザープロファイルを以下の場所に保存します:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

これらのディレクトリ内では、ほとんどのユーザーデータが **Default/** または **ChromeDefaultData/** フォルダにあります。以下のファイルは重要なデータを保持しています:

- **History**: URL、ダウンロード、検索キーワードを含みます。Windows では [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) を使って履歴を参照できます。"Transition Type" 列はリンクのクリック、直接入力されたURL、フォーム送信、ページのリロードなど、さまざまな意味を持ちます。
- **Cookies**: クッキーを保存します。調査には [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) が利用できます。
- **Cache**: キャッシュデータを保持します。検査するには Windows ユーザーは [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) を使用できます。

Electron ベースのデスクトップアプリ（例: Discord）も Chromium Simple Cache を使用し、オンディスク上に豊富なアーティファクトを残します。参照:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: ユーザーのブックマーク。
- **Web Data**: フォーム履歴を含む。
- **Favicons**: サイトのファビコンを保存。
- **Login Data**: ユーザー名やパスワードなどのログイン情報を含む。
- **Current Session**/**Current Tabs**: 現在のセッションと開いているタブのデータ。
- **Last Session**/**Last Tabs**: Chrome を閉じる前の最後のセッションでアクティブだったサイトに関する情報。
- **Extensions**: ブラウザ拡張やアドオンのディレクトリ。
- **Thumbnails**: サイトのサムネイルを保存。
- **Preferences**: プラグイン、拡張、ポップアップ、通知などの設定を含む情報豊富なファイル。
- **Browser’s built-in anti-phishing**: anti-phishing とマルウェア保護が有効か確認するには `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` を実行してください。出力に `{"enabled: true,"}` があれば機能は有効です。

## **SQLite DB Data Recovery**

前節で見たように、Chrome と Firefox はデータを保存するために **SQLite** データベースを使用しています。削除されたエントリは [**sqlparse**](https://github.com/padfoot999/sqlparse) または [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) を使って復元できる可能性があります。

## **Internet Explorer 11**

Internet Explorer 11 はデータとメタデータを複数の場所に分散して管理しており、保存情報とその詳細を分離して簡単にアクセス・管理できるようにしています。

### Metadata Storage

メタデータは `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`（VX は V01, V16, または V24）に保存されます。これに伴う `V01.log` ファイルは `WebcacheVX.data` と修正時刻が一致しないことがあり、その場合は `esentutl /r V01 /d` を使って修復が必要になることがあります。このメタデータは ESE データベースに格納されており、photorec や [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) のようなツールで復元・検査できます。**Containers** テーブル内では、各データセグメントが格納されている具体的なテーブルやコンテナ（Skype など他の Microsoft ツールのキャッシュの詳細を含む）を識別できます。

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) はキャッシュ検査を可能にするツールで、キャッシュデータを抽出したフォルダの場所を指定する必要があります。キャッシュのメタデータにはファイル名、ディレクトリ、アクセス回数、URL の起点、キャッシュ作成・アクセス・変更・有効期限のタイムスタンプが含まれます。

### Cookies Management

クッキーは [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) で調査でき、メタデータには名前、URL、アクセス回数、各種時間情報が含まれます。永続的なクッキーは `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` に保存され、セッションクッキーはメモリ上に存在します。

### Download Details

ダウンロードのメタデータは [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) でアクセス可能で、特定のコンテナには URL、ファイルタイプ、ダウンロード先などのデータが含まれます。実際のファイルは `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` にあります。

### Browsing History

閲覧履歴を確認するには [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) を使い、抽出した履歴ファイルの場所と Internet Explorer の設定を指定します。ここでのメタデータには修正時刻やアクセス時刻、アクセス回数が含まれます。履歴ファイルは `%userprofile%\Appdata\Local\Microsoft\Windows\History` にあります。

### Typed URLs

Typed URLs とその使用時刻はレジストリ内の `NTUSER.DAT` の `Software\Microsoft\InternetExplorer\TypedURLs` および `Software\Microsoft\InternetExplorer\TypedURLsTime` に保存され、ユーザーが入力した最後の50件の URL とその最終入力時刻を追跡します。

## Microsoft Edge

Microsoft Edge はユーザーデータを `%userprofile%\Appdata\Local\Packages` に保存します。各種データのパスは以下の通りです:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari のデータは `/Users/$User/Library/Safari` に保存されます。主なファイルは次の通りです:

- **History.db**: `history_visits` と `history_items` テーブルに URL と訪問タイムスタンプが含まれます。`sqlite3` を使ってクエリを実行してください。
- **Downloads.plist**: ダウンロードしたファイルの情報。
- **Bookmarks.plist**: ブックマークされた URL を保存。
- **TopSites.plist**: よく訪問するサイト。
- **Extensions.plist**: Safari の拡張一覧。`plutil` や `pluginkit` で取得可能。
- **UserNotificationPermissions.plist**: プッシュ通知を許可したドメイン。`plutil` で解析。
- **LastSession.plist**: 最後のセッションのタブ。`plutil` で解析。
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` を使って確認します。返り値が 1 なら機能は有効です。

## Opera

Opera のデータは `/Users/$USER/Library/Application Support/com.operasoftware.Opera` にあり、履歴やダウンロードは Chrome と同じフォーマットを共有します。

- **Browser’s built-in anti-phishing**: Preferences ファイル内の `fraud_protection_enabled` が `true` に設定されているかを `grep` で確認してください。

これらのパスとコマンドは、各種ウェブブラウザが保存する閲覧データへアクセスし、それらを理解するために重要です。

## 参考

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**


{{#include ../../../banners/hacktricks-training.md}}
