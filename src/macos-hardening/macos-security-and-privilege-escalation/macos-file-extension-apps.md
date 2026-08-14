# macOSファイル拡張子およびURL schemeのapp handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServicesデータベース

これはmacOSにインストールされているすべてのapplicationに関するデータベースで、各インストール済みapplicationのサポート対象である**URL schemes**、**document types**、**UTIs**、およびデフォルトのhandlersなどの情報を取得するために照会できます。

次の方法でこのデータベースをdumpできます：
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
または、[**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) ツールを使用します。

**`/usr/libexec/lsd`** はデータベースの中核です。`.lsd.installation`、`.lsd.open`、`.lsd.openurl` などの **複数の XPC services** を提供します。ただし、公開されている XPC 機能をアプリケーションから使用できるようにするには、いくつかの **entitlements** も必要です。たとえば、MIME types または URL schemes のデフォルトアプリを変更するための `.launchservices.changedefaulthandler` や `.launchservices.changeurlschemehandler` などがあります。

**`/System/Library/CoreServices/launchservicesd`** は `com.apple.coreservices.launchservicesd` service を要求し、実行中のアプリケーションに関する情報を取得するために query できます。system tool の **`/usr/bin/lsappinfo`** または [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) を使用して query できます。

operator の観点では、通常、次の **2 つの有用な views** があることを覚えておいてください。

- LaunchServices / `lsd` が管理する **registration database**（`.csstore` files によって backing されています）。
- `LSHandlers` array 内の `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` に保存される、**per-user effective defaults**。

この区別は重要です。アプリケーションが type または scheme を処理できるものとして **registered** されていても、**current default** は別の bundle ID のままになっている可能性があります。

最近の macOS releases では、registration discovery は `/Applications` に限定されません。その他の Spotlight-visible で accessible な folders や mounted/shared volumes にあるアプリも registry に登録される可能性があります。そのため、triage 中は `lsregister -dump` の `path` と volume information を保持し、bundle が引き続き discoverable な状態である限り、アプリの unregister が永続的だと想定しないでください。<sup>[[4]](#references)</sup>

## File Extension と URL scheme の app handlers

次の command line は、extension に応じて files を open できる applications を見つけるのに役立ちます。
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
アプリケーションがサポートしている拡張子は、次の方法でも確認できます:
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
## 有効なハンドラーの列挙

**現在のユーザーのデフォルト設定**に関して、通常もっとも役立つファイルは次のとおりです：
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
そこから **URL scheme** ハンドラーをダンプするには：
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
**content-type / UTI** ハンドラーをダンプするには：
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
サンプルファイルの UTI ツリーを解決するには：
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
より使いやすい CLI でデフォルト値を照会または変更する場合:
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
### ファイルごとの `Open With` オーバーライド

Handler の解決には、**ファイル固有**のレイヤーもあります。ファイルの UTI とユーザーのグローバルなデフォルトにフォールバックする前に、LaunchServices は `com.apple.LaunchServices.OpenWith` extended attribute を確認します。Finder は、1つのファイルに対して **Always Open With** が選択されたときにこれを作成します。その値は、application path、bundle identifier、version selector を含む binary property list です。<sup>[[3]](#references)</sup>

filename extension を信頼せずに検査・デコードします：
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
これは、`duti`、`dutix`、または `LSHandlers` で無害なグローバルデフォルトが報告されているにもかかわらず、単一の lure を開くと予期しないアプリケーションが起動する場合に役立ちます。管理された lab では、Finder で設定したファイルから正確な不透明値をコピーできます。これを削除すると、通常のタイプベースの解決に戻ります。
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## 興味深い Info.plist keys

アプリケーション bundle をトリアージする際、以下の keys が最も重要です。

- **`CFBundleDocumentTypes`**: bundle が開けると主張する document groups。
- **`LSItemContentTypes`**: document types を UTI に紐付ける**modern / preferred**な方法。
- **`LSHandlerRank`**: LaunchServices が使用する ranking（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: app が実装する custom URI schemes。
- **`UTExportedTypeDeclarations`**: app が**所有する**UTIs。
- **`UTImportedTypeDeclarations`**: app は所有していないが、system に認識させたい UTIs。

簡単なトリアージに便利な command は次のとおりです。
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
微妙ですが重要な点として、**`LSItemContentTypes`** が存在する場合、**`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`**、**`CFBundleTypeOSTypes`** などの古いキーは、実質的にレガシーな互換性データです。実際の handler 解決では、まず UTI パスに注目してください。

## Offensive notes

アプリケーションは、興味深い対象になるために実行される必要はありません。書き込まれた、または clone された `.app` bundle は、**ディスクに書き込まれた直後に `lsd` によって自動的に parse される**可能性があり、ユーザーが bundle を起動していなくても、宣言された document types / URL schemes が登録されることがあります。

これは、**persistence / hijacking research** と **initial-access chains** の両方に役立ちます。

- Malicious app は、**rare extension** や **custom UTI** を claim して、victim が lure file を開くのを待つことができます。
- Malicious app は、browser、Electron app、office document、chat client、または別の helper app から到達可能な **custom URL scheme** を登録できます。<sup>[[1]](#references)</sup>
- 通常の default resolution と、特定の candidate handler の testing を分離するには、`open 'targetscheme://host/path?value=test'` で LaunchServices 経由で scheme を invoke し、続けて `open -b com.vendor.Target 'targetscheme://host/path?value=test'` で特定の registered bundle を target にします。これは、受信側 app が attacker-controlled な URL components をどのように validate および decode するかを audit する際に役立ちます。<sup>[[1]](#references)</sup>
- Build 後に app bundle を edit した場合は、次のコマンドで LaunchServices に強制的に再 parse させることができます：
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
疑わしい bundles をテストする際は、特に以下に注意してください。

- **`LSHandlerRank=Owner`** が一般的でないタイプに設定されている。
- 多数の拡張子を対象としている **`CFBundleDocumentTypes`** 配列。
- 唯一興味深い動作が document または URI handler の背後にある **Helper / wrapper apps**。
- **Shortcut-like files**（`.webloc`、`.inetloc`、`.fileloc`）が最終的に LaunchServices へ dispatch されるケース。.fileloc スタイルの tricks と関連する Gatekeeper の観点については、[こちらのページ](macos-security-protections/macos-fs-tricks/README.md)を確認してください。<sup>[[2]](#references)</sup>

フォルダーを閲覧したりファイルを選択したりするだけで passive code-execution が発生することを目的とする場合は、専用の [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) ページも確認してください。これは、関連性は高いものの異なる file-handler surface です。



## References

- [1] [Objective-See - Custom URL Schemes を介した Remote Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate の bypass：macOS における Gatekeeper flaws の詳細](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS が正しい app でファイルを開く仕組み](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia における LaunchServices の制御](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
