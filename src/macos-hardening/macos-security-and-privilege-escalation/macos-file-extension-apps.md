# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

これは、macOS にインストールされているすべてのアプリケーションのデータベースで、各インストール済みアプリケーションについて、サポートされている **URL schemes**、**document types**、**UTIs**、およびデフォルトのハンドラなどの情報を取得するために問い合わせできます。

このデータベースは次の方法でダンプできます:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
または、ツール [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) を使用します。

**`/usr/libexec/lsd`** はデータベースの中核です。これは **いくつかの XPC services**、例えば `.lsd.installation`、`.lsd.open`、`.lsd.openurl` などを提供します。ただし、`.launchservices.changedefaulthandler` や `.launchservices.changeurlschemehandler` のような、MIME types や URL schemes のデフォルト app を変更するための公開された XPC functionalities を使えるように、applications に対して **いくつかの entitlements** も必要とします。

**`/System/Library/CoreServices/launchservicesd`** は `com.apple.coreservices.launchservicesd` サービスを提供し、実行中の applications に関する情報を取得するために問い合わせできます。system tool **`/usr/bin/lsappinfo`** または [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) で問い合わせできます。

operator の観点では、通常 **2 つの有用な view** があることを覚えておいてください:

- LaunchServices / `lsd` によって管理される **registration database**（`.csstore` files によってバックアップされる）。
- `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` の `LSHandlers` array 内に保存される、ユーザーごとの effective defaults。

この区別は重要です。application は type や scheme を処理できるものとして **registered** されていても、**current default** は別の bundle ID のままかもしれません。

## File Extension & URL scheme app handlers

以下の行は、extension に基づいて files を開ける applications を見つけるのに役立ちます:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
または [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps) のようなものを使う:
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
アプリケーションがサポートする拡張子は、次のように確認できます:
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
## 効果的なハンドラの列挙

**current user's defaults** に最も役立つファイルは通常、次のとおりです:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
そこから **URL scheme** ハンドラを dump するには:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
**content-type / UTI** ハンドラをダンプするには:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
サンプルファイルのUTIツリーを解決するには:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
defaults を query したり変更したりする、より使いやすい CLI が欲しい場合:
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
## Interesting Info.plist keys

アプリケーションバンドルをトリアージする際、最も重要なのは次のキーです:

- **`CFBundleDocumentTypes`**: バンドルが開けると主張する document groups。
- **`LSItemContentTypes`**: document types を UTIs に関連付けるための **modern / preferred** な方法。
- **`LSHandlerRank`**: LaunchServices で使われるランク (`Owner`, `Default`, `Alternate`, `None`)。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: アプリが実装する custom URI schemes。
- **`UTExportedTypeDeclarations`**: アプリが **owns** する UTIs。
- **`UTImportedTypeDeclarations`**: アプリは所有しないが、システムに認識させたい UTIs。

有用な quick triage コマンドは次のとおりです:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
微妙ですが重要な点として、**`LSItemContentTypes`** が存在する場合、**`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`**、**`CFBundleTypeOSTypes`** のような古いキーは、実質的にレガシーな互換性データです。実際の handler resolution では、まず UTI の経路に注目してください。

## Offensive notes

Applications は実行されなくても interesting になり得ます。配置された、または cloned された `.app` bundle は、**ディスクに書き込まれた時点ですぐに `lsd` によって自動的に parse され**、その宣言された document types / URL schemes は、ユーザーが bundle を一度も起動しなくても登録されることがあります。

これは **persistence / hijacking research** と **initial-access chains** の両方で有用です。

- malicious app は **rare extension** や **custom UTI** を claim し、victim が lure file を開くのを待てます。
- malicious app は、browser、Electron app、office document、chat client、または別の helper app から到達可能な **custom URL scheme** を register できます。
- app bundle をビルド後に編集すると、次の方法で LaunchServices に再度 parse させることができます:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
疑わしいバンドルをテストする際は、以下に特に注意してください:

- **`LSHandlerRank=Owner`** が珍しいタイプに対して設定されている。
- 多くの拡張子を名乗る **広範な `CFBundleDocumentTypes`** 配列。
- ドキュメントハンドラや URI ハンドラの背後にしか興味深い動作がない **Helper / wrapper apps**。
- LaunchServices に最終的にディスパッチされる **ショートカット風ファイル**（`.webloc`, `.inetloc`, `.fileloc`）。`.fileloc` 風のトリックや関連する Gatekeeper の観点については、[this other page](macos-security-protections/macos-fs-tricks/README.md) を確認してください。

目的が、フォルダをブラウズしたりファイルを選択しただけで発生する受動的な code-execution である場合は、[Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) の専用ページも確認してください。これは別ですが、密接に関連する file-handler surface です。

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
