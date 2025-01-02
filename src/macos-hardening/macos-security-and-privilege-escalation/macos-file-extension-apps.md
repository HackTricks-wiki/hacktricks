# macOS ファイル拡張子 & URL スキームアプリハンドラー

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices データベース

これは、macOS にインストールされているすべてのアプリケーションのデータベースで、サポートされている URL スキームや MIME タイプなど、各インストールされたアプリケーションに関する情報を取得するためにクエリできます。

このデータベースをダンプすることが可能です:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Or using the tool [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** はデータベースの中枢です。これは、`.lsd.installation`、`.lsd.open`、`.lsd.openurl` などの **いくつかの XPC サービス** を提供します。しかし、これらの公開された XPC 機能を使用するためには、アプリケーションにいくつかの権限が必要です。例えば、mime タイプや URL スキームのデフォルトアプリを変更するための `.launchservices.changedefaulthandler` や `.launchservices.changeurlschemehandler` などです。

**`/System/Library/CoreServices/launchservicesd`** はサービス `com.apple.coreservices.launchservicesd` を主張し、実行中のアプリケーションに関する情報を取得するためにクエリできます。これは、システムツール /**`usr/bin/lsappinfo`** または [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) を使用してクエリできます。

## ファイル拡張子と URL スキームアプリハンドラー

次の行は、拡張子に応じてファイルを開くことができるアプリケーションを見つけるのに役立ちます:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
または、[**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps)のようなものを使用します：
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
アプリケーションがサポートしている拡張子を確認するには、次のようにします:
```
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
{{#include ../../banners/hacktricks-training.md}}
