# macOS ファイル拡張子と URL scheme のアプリハンドラー

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices データベース

macOSにインストールされているすべてのアプリケーションのデータベースです。各アプリケーションがサポートする **URL schemes**、**document types**、**UTIs**、デフォルトのハンドラーなどの情報を取得できます。

このデータベースは次のコマンドでダンプできます：

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

または、ツール [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) を使用します。

**`/usr/libexec/lsd`** はデータベースの中核です。.lsd.installation、.lsd.open、.lsd.openurl など、**複数の XPC サービス**を提供します。ただし、公開されている XPC 機能をアプリケーションから利用するには、いくつかの **entitlements** も必要です。たとえば、MIME タイプや URL スキームなどのデフォルトアプリを変更するには、`.launchservices.changedefaulthandler` や `.launchservices.changeurlschemehandler` が必要です。

**`/System/Library/CoreServices/launchservicesd`** はサービス `com.apple.coreservices.launchservicesd` を提供し、実行中のアプリケーションに関する情報を取得できます。システムツール **`/usr/bin/lsappinfo`** または [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) を使って問い合わせることができます。

オペレーターの視点では、通常、次の **2つの有用な見方**があることを覚えておいてください。

- LaunchServices / `lsd` が管理する **登録データベース**（`.csstore` ファイルに保存）。
- `LSHandlers` 配列内の `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` に保存される **ユーザーごとの有効なデフォルト設定**。

この違いは重要です。アプリケーションがあるタイプやスキームを処理できるものとして **登録**されていても、**現在のデフォルト**は別の bundle ID のアプリケーションである場合があります。

最近の macOS リリースでは、登録対象の検出は `/Applications` に限定されません。Spotlight から検出可能でアクセスできる他のフォルダーや、マウント済みまたは共有されているボリューム上のアプリもレジストリに登録されることがあります。したがって、トリアージ中は `lsregister -dump` の `path` とボリューム情報を保持し、バンドルが検出可能なままではアプリの登録解除が永続するとは限らないことに注意してください。<sup>[[4]](#references)</sup>

## ファイル拡張子と URL スキームのアプリハンドラー

次のコマンドは、拡張子に応じてファイルを開けるアプリケーションを見つけるのに役立ちます。

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

または [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

また、次の方法でアプリケーションがサポートする拡張子を確認できます:

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

**現在のユーザーのデフォルト設定**を確認するうえで、通常もっとも役立つファイルは次のとおりです。

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

**URL scheme** ハンドラーをダンプするには：

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

**content-type / UTI** handlersをdumpするには:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

サンプルファイルのUTIツリーを解決するには：

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

デフォルト設定の照会や変更に、より使いやすいCLIを使いたい場合は:

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

ハンドラーの解決には、**ファイル固有**のレイヤーもあります。ファイルのUTIとユーザーのグローバルなデフォルトにフォールバックする前に、LaunchServicesは`com.apple.LaunchServices.OpenWith`拡張属性を確認します。Finderでは、1つのファイルに**常にこのアプリケーションで開く**を選択すると、この属性が作成されます。値は、アプリケーションのパス、バンドル識別子、バージョンセレクターを含むバイナリプロパティリストです。<sup>[[3]](#references)</sup>

ファイル名の拡張子を信用せずに、これを調べてデコードします:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

これは、`duti`、`dutix`、または`LSHandlers`で無害なグローバルデフォルトが報告されているにもかかわらず、単一のlureが予期しないアプリケーションで開く場合に役立ちます。管理されたラボでは、Finderで設定したファイルから不透明な値をそのままコピーできます。これを削除すると、通常のタイプベースの解決に戻ります。

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## 興味深い Info.plist キー

アプリケーションバンドルをトリアージする際、特に重要なキーは次のとおりです。

- **`CFBundleDocumentTypes`**: バンドルが開けると主張するドキュメントグループ。
- **`LSItemContentTypes`**: ドキュメントタイプを UTI に関連付ける**最新の推奨方法**。
- **`LSHandlerRank`**: LaunchServices が使用する優先順位（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: アプリが実装するカスタム URI スキーム。
- **`UTExportedTypeDeclarations`**: アプリが**所有する** UTI。
- **`UTImportedTypeDeclarations`**: アプリが所有してはいないが、システムに認識させたい UTI。

手早くトリアージするには、次のコマンドが便利です。

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

微妙ですが重要な点として、**`LSItemContentTypes`** が存在する場合、**`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`**、**`CFBundleTypeOSTypes`** などの古いキーは、実質的にレガシー互換性データです。実際のハンドラー解決では、まず UTI の経路に注目してください。

## 攻撃に関するメモ

アプリが起動する前でも、そのハンドラー登録は注目に値します。ただし、**`.app` バンドルを書き込むだけでは、すぐに登録されるとは限りません**。Finder はアプリを検出したときに登録できます。ユーザーがそのフォルダーを閲覧した場合も同様です。また、起動時やログイン時、明示的な登録呼び出しによって登録されることもあります。登録をテストする前に `lsregister -dump` を確認してください。登録されただけではアプリは起動せず、有効なデフォルトにもなりません。<sup>[[5]](#references)</sup> 永続化の前提条件については、[URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices) を参照してください。

これは、**永続化 / ハイジャックの調査**にも**初期アクセスチェーン**にも役立ちます。

- 悪意のあるアプリは、**使用頻度の低い拡張子**や**カスタム UTI**を登録し、被害者が誘導用ファイルを開くのを待つことができます。
- 悪意のあるアプリは、ブラウザー、Electron アプリ、Office ドキュメント、チャットクライアント、その他のヘルパーアプリから呼び出せる**カスタム URL スキーム**を登録できます。<sup>[[1]](#references)</sup>
- 通常のデフォルト解決と特定の候補ハンドラーのテストを切り分けるには、`open 'targetscheme://host/path?value=test'` で LaunchServices 経由でスキームを呼び出し、`open -b com.vendor.Target 'targetscheme://host/path?value=test'` で登録済みの特定のバンドルを指定します。これは、受信側アプリが攻撃者制御の URL コンポーネントをどのように検証・デコードするかを監査するのに役立ちます。<sup>[[1]](#references)</sup>
- アプリバンドルのビルド後に編集した場合は、次のコマンドで LaunchServices に再解析させることができます：

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

不審なバンドルをテストする際は、特に次の点に注意してください。

- **一般的でない型に対する `LSHandlerRank=Owner`**。
- 多数の拡張子を対象とする **広範な `CFBundleDocumentTypes`** 配列。
- ドキュメントまたは URI handler を介した動作だけが注目に値する **helper / wrapper app**。
- LaunchServices への dispatch に至る **ショートカットに似たファイル**（`.webloc`、`.inetloc`、`.fileloc`）。`.fileloc` 系の手法や関連する Gatekeeper の観点については、[こちらのページ](macos-security-protections/macos-fs-tricks/README.md)を確認してください。<sup>[[2]](#references)</sup>

### 下流オプションに渡される URL パラメーター

ブラウザーの外部プロトコル確認は handler を開くことを許可するだけであり、URL パラメーターの信頼性を保証するものではありません。受信側 app の URL parser から、library、media engine、helper process、またはファイル書き込みオプションへと追跡してください。URL フィールドを下流オプション名に変換する query-key prefix を探してください。使い捨てアカウントで無害な marker を使い、リテラルおよび percent-encoded の区切り文字をどちらもテストしてください。<sup>[[6]](#references)</sup>

app による初期 parsing だけでなく、**下流コンポーネントが最終的に受け付けるオプション**を確認してください。ある handler では、prefix 付きの query key が mpv の input command に到達していました。そのオプションをブロックしても、ファイル書き込みの経路は残っていました。既知の危険なキーを1つ試すだけでなく、到達可能なオプションクラスをテストしてください。<sup>[[7]](#references)</sup>

### 組み込みの `applescript://` handler

`applescript://com.apple.scripteditor` URL handler は、`action=new` と URL-encoded の `script` パラメーターを受け付けます。そのため、ブラウザーのリンクから Script Editor を開き、攻撃者が制御する AppleScript をエディターに表示できます。これにより、Terminal に貼り付ける手順を省けます。**自動実行ではありません**。ブラウザーが Script Editor を開くか確認する場合があり、ユーザーがスクリプトを実行する必要があります。<sup>[[8]](#references)</sup>

最近の macOS バージョンではスクリプト書類の警告が表示される場合があり、XProtect は実行時に AppleScript をスキャンします。<sup>[[8]](#references)[[9]](#references)</sup>

評価対象の macOS リリースで handler と確認プロンプトを検証するには、無害なローカル probe を使用してください。**Run** をクリックするまでは、エディターに内容を表示するだけであることを確認してください。<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

フォルダを閲覧したりファイルを選択したりするだけで、受動的に code-execution を実現することが目的であれば、[Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) の専用ページも確認してください。これは異なるものの、密接に関連する file-handler の攻撃対象領域です。



## References

- [1] [Objective-See - カスタム URL scheme を介した Mac のリモート Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate を回避する：macOS の Gatekeeper の欠陥を詳しく見る](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS がファイルを適切な app で開く仕組み](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia で LaunchServices を制御する](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Launch Services の概念](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - IINA URL scheme の command execution に関する調査](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - URL scheme における mpv options の安全でない処理](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - ClickFix technique は Terminal の代わりに Script Editor を使用する](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Terminal と script の保護](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
