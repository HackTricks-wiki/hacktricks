# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

これは macOS にインストールされているすべてのアプリケーションのデータベースであり、各インストール済みアプリケーションがサポートする **URL schemes**、**document types**、**UTIs**、およびデフォルトのハンドラーなどの情報を取得するためにクエリできます。

このデータベースは、次のコマンドで dump できます:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
または、[**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) ツールを使用します。

**`/usr/libexec/lsd`** はデータベースの中核です。`.lsd.installation`、`.lsd.open`、`.lsd.openurl` など、**複数の XPC services** を提供します。ただし、公開されている XPC 機能をアプリケーションから使用できるようにするには、いくつかの **entitlements** も必要です。たとえば、MIME types や URL schemes のデフォルトアプリを変更するための `.launchservices.changedefaulthandler` や `.launchservices.changeurlschemehandler` などです。

**`/System/Library/CoreServices/launchservicesd`** は `com.apple.coreservices.launchservicesd` service を claim し、実行中のアプリケーションに関する情報を取得するために query できます。system tool **`/usr/bin/lsappinfo`** または [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) を使用して query できます。

operator の観点では、通常、次の **2 つの有用な view** があることに注意してください。

- LaunchServices / `lsd` が管理する **registration database**（`.csstore` files によって backing される）。
- `LSHandlers` array 内の `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` に保存されている、**per-user effective defaults**。

この distinction は重要です。アプリケーションが type や scheme を handle できるものとして **registered** されていても、**current default** は別の bundle ID のままである可能性があります。

## File Extension & URL scheme app handlers

次の line は、extension に応じて files を open できるアプリケーションを見つけるのに役立ちます。
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
または、[**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps) のようなものを使用します：
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
また、次の操作を行うことで、アプリケーションがサポートしている拡張子を確認することもできます。
```bash
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
## 有効なハンドラの列挙

**現在のユーザーのデフォルト設定**を確認する際に、通常もっとも役立つファイルは次のとおりです。
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
そこから **URL scheme** ハンドラーをダンプするには:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
**content-type / UTI** handlersをダンプするには:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
サンプルファイルの UTI ツリーを解決するには:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
より使いやすい CLI でデフォルトを確認または変更する場合:
```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```
## 興味深い Info.plist キー

アプリケーションバンドルをトリアージする際、特に重要なのは次のキーです。

- **`CFBundleDocumentTypes`**: バンドルが開けると主張するドキュメントグループ。
- **`LSItemContentTypes`**: ドキュメントタイプを UTI に関連付けるための**最新かつ推奨される**方法。
- **`LSHandlerRank`**: LaunchServices が使用する優先順位（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: アプリが実装するカスタム URI schemes。
- **`UTExportedTypeDeclarations`**: アプリが**所有する** UTI。
- **`UTImportedTypeDeclarations`**: アプリは所有していないものの、システムに認識させたい UTI。

簡単なトリアージには、次のコマンドが便利です。
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
微妙ですが重要な点として、**`LSItemContentTypes`** が存在する場合、**`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`**、**`CFBundleTypeOSTypes`** などの古いキーは、実質的にレガシー互換性データです。実際の handler resolution では、まず UTI path に注目してください。

## Offensive notes

Applications は実行されなくても興味深い対象になります。書き込まれた、または clone された `.app` bundle は、**ディスクに書き込まれるとすぐに `lsd` によって自動的に parse される**可能性があり、ユーザーが bundle を一度も起動しなくても、宣言された document types / URL schemes が登録される場合があります。

これは **persistence / hijacking research** と **initial-access chains** の両方に有用です。

- malicious app は **rare extension** や **custom UTI** を claim し、victim が lure file を開くのを待つことができます。
- malicious app は、browser、Electron app、office document、chat client、または別の helper app から到達可能な **custom URL scheme** を登録できます。<sup>[[1]](#references)</sup>
- build 後に app bundle を edit した場合、次のコマンドで LaunchServices に強制的に再 parse させることができます：
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
不審な bundle をテストする際は、以下に特に注意してください。

- **`LSHandlerRank=Owner`** が一般的でないタイプに設定されている。
- 多数の拡張子を対象としている **`CFBundleDocumentTypes`** 配列。
- 唯一興味深い動作が document または URI handler の背後に隠れている **Helper / wrapper apps**。
- 最終的に LaunchServices へ dispatch される **shortcut-like files**（`.webloc`、`.inetloc`、`.fileloc`）。`.fileloc` スタイルの tricks や関連する Gatekeeper の観点については、[this other page](macos-security-protections/macos-fs-tricks/README.md) を確認してください。<sup>[[2]](#references)</sup>

フォルダを閲覧したりファイルを選択したりするだけで passive code-execution が発生するかを調べる場合は、専用の [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) ページも確認してください。これは異なるものの、密接に関連した file-handler surface です。

## References

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
