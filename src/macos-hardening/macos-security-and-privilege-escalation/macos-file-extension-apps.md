# macOSのファイル拡張子とURLスキームのアプリハンドラー

{{#include ../../banners/hacktricks-training.md}}

## LaunchServicesデータベース

macOSにインストールされているすべてのアプリケーションの情報を照会できるデータベースです。各アプリケーションが対応する**URLスキーム**、**ドキュメントタイプ**、**UTI**、デフォルトのハンドラーなどを確認できます。

このデータベースは次のコマンドでダンプできます。

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

または、[**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) ツールを使用します。

**`/usr/libexec/lsd`** はデータベースの中核です。`.lsd.installation`、`.lsd.open`、`.lsd.openurl` など、**複数の XPC サービス**を提供します。ただし、公開されている XPC 機能を利用するには、アプリケーションに特定の entitlement が必要です。たとえば、MIME タイプや URL scheme のデフォルトアプリを変更するには、`.launchservices.changedefaulthandler` や `.launchservices.changeurlschemehandler` などが必要です。

**`/System/Library/CoreServices/launchservicesd`** は `com.apple.coreservices.launchservicesd` サービスを提供し、実行中のアプリケーションに関する情報を取得できます。システムツール **`/usr/bin/lsappinfo`** または [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) を使って問い合わせることができます。

運用者の視点では、通常、次の**2つの有用な見方**があることを覚えておいてください。

- LaunchServices / `lsd` が管理する**登録データベース**（`.csstore` ファイルに保存されます）。
- `LSHandlers` 配列内の `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` に保存される、**ユーザーごとの有効なデフォルト設定**。

この違いは重要です。アプリケーションがあるタイプや scheme を処理できるものとして**登録**されていても、**現在のデフォルト**は別の bundle ID である場合があります。

最近の macOS では、登録対象の検出範囲は `/Applications` に限られません。Spotlight から認識でき、アクセス可能な他のフォルダやマウント済み／共有ボリューム上のアプリも登録対象になり得ます。そのため、トリアージ中は `lsregister -dump` の `path` とボリューム情報を保持し、アプリの bundle が引き続き検出可能な状態であれば、登録解除が永続するとは想定しないでください。<sup>[[4]](#references)</sup>

## ファイル拡張子と URL scheme のアプリハンドラー

次のコマンドは、拡張子に応じてファイルを開くことができるアプリケーションを探すのに役立ちます。

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

または、[**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps)のようなものを使います。

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

アプリケーションがサポートする拡張機能は、次の方法でも確認できます:

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

**content-type / UTI** ハンドラーをダンプするには:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

サンプルファイルのUTIツリーを解決するには:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

デフォルト設定を照会または変更するための、より使いやすいCLIが必要なら:

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

ハンドラーの解決には、**ファイル固有**のレイヤーもあります。ファイルの UTI とユーザーのグローバルなデフォルトにフォールバックする前に、LaunchServices は `com.apple.LaunchServices.OpenWith` 拡張属性を確認します。Finder では、1つのファイルに **Always Open With** を選択するとこの属性が作成されます。その値は、アプリケーションのパス、バンドル識別子、バージョンセレクターを含むバイナリ property list です。<sup>[[3]](#references)</sup>

ファイル名の拡張子を信用せずに、これを調査してデコードします。

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

これは、`duti`、`dutix`、または `LSHandlers` では無害なグローバルデフォルトが報告されているにもかかわらず、単一の lure を開くと予期しないアプリケーションが起動する場合に役立ちます。管理されたラボ環境では、Finder で設定したファイルから不透明な値をそのままコピーできます。これを削除すると、通常のタイプベースの解決に戻ります。

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Interesting Info.plist keys

アプリケーションバンドルをトリアージする際、特に重要なキーは次のとおりです。

- **`CFBundleDocumentTypes`**: バンドルが開けるとするドキュメントの種類。
- **`LSItemContentTypes`**: ドキュメントの種類をUTIに関連付ける**最新の推奨方式**。
- **`LSHandlerRank`**: LaunchServicesが使用する優先順位（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: アプリが実装するカスタムURIスキーム。
- **`UTExportedTypeDeclarations`**: アプリが**所有する**UTI。
- **`UTImportedTypeDeclarations`**: アプリは所有していないが、システムに認識させたいUTI。

手早くトリアージするには、次のコマンドが便利です。

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

重要ですが見落としやすい点として、**`LSItemContentTypes`** が存在する場合、**`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`**、**`CFBundleTypeOSTypes`** などの古いキーは、実質的にレガシー互換データです。実際のハンドラー解決では、まずUTI経由の経路に注目してください。

## 攻撃に関するメモ

アプリケーションは、興味深い対象となるために実行される必要はありません。配置またはクローンされた `.app` バンドルは、ディスクに書き込まれるとすぐに **`lsd` によって自動的に解析される**ことがあり、ユーザーがバンドルを起動しなくても、宣言されたドキュメントタイプやURLスキームが登録される場合があります。

これは、**persistence / hijackingの調査**と**initial-accessチェーン**の両方に役立ちます。

- 悪意のあるアプリは、**あまり使われない拡張子**や**カスタムUTI**を登録し、被害者が誘導用ファイルを開くのを待つことができます。
- 悪意のあるアプリは、ブラウザー、Electronアプリ、Officeドキュメント、チャットクライアント、または別のヘルパーアプリからアクセスできる**カスタムURLスキーム**を登録できます。<sup>[[1]](#references)</sup>
- 通常のデフォルト解決と、特定の候補ハンドラーのテストを切り分けるには、`open 'targetscheme://host/path?value=test'` でLaunchServices経由でスキームを呼び出し、続けて `open -b com.vendor.Target 'targetscheme://host/path?value=test'` で登録済みの特定のバンドルを指定します。これは、受信側アプリが攻撃者の制御するURLコンポーネントをどのように検証・デコードするかを監査する際に役立ちます。<sup>[[1]](#references)</sup>
- アプリバンドルのビルド後に編集した場合は、次のコマンドでLaunchServicesに再解析させることができます：

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

不審な bundle をテストする際は、特に次の点に注意してください。

- **一般的でないタイプに対する `LSHandlerRank=Owner`**。
- **多数の拡張子を指定する、範囲の広い `CFBundleDocumentTypes` 配列**。
- **唯一注目すべき動作が、ドキュメントまたは URI handler の背後に隠れている helper / wrapper アプリ**。
- **LaunchServices に処理を渡すことになる、ショートカットのようなファイル**（`.webloc`、`.inetloc`、`.fileloc`）。`.fileloc` のような手法や関連する Gatekeeper の観点については、[こちらのページ](macos-security-protections/macos-fs-tricks/README.md)を確認してください。<sup>[[2]](#references)</sup>

フォルダーを閲覧したりファイルを選択したりするだけで受動的にコード実行させることが目的なら、専用ページの [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) も確認してください。これは密接に関連していますが、別のファイルハンドラーの攻撃対象領域です。



## References

- [1] [Objective-See - カスタム URL Scheme による Mac のリモート悪用](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate の回避：macOS における Gatekeeper の欠陥を詳しく見る](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS がファイルを適切なアプリで開く仕組み](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia での LaunchServices の制御](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
