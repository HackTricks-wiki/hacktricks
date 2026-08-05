# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOSのBundlesは、アプリケーション、library、その他の必要なファイルなど、さまざまなリソースをコンテナとしてまとめます。これにより、Finderでは一般的な`*.app`ファイルのように、単一のオブジェクトとして表示されます。最もよく遭遇するBundleは`.app` Bundleですが、`.framework`、`.systemextension`、`.kext`などの種類も広く使用されています。

### Bundleの主要コンポーネント

Bundle内、特に`<application>.app/Contents/`ディレクトリには、さまざまな重要なリソースが格納されています。

- **\_CodeSignature**: このディレクトリには、アプリケーションの整合性の検証に不可欠なcode-signing情報が保存されています。次のようなcommandを使用してcode-signing情報を確認できます。
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: ユーザー操作時に実行されるアプリケーションの実行可能バイナリが含まれます。
- **Resources**: 画像、ドキュメント、インターフェースの説明（nib/xibファイル）など、アプリケーションのユーザーインターフェースコンポーネントを格納します。
- **Info.plist**: アプリケーションのメイン設定ファイルとして機能し、システムがアプリケーションを適切に認識し、操作するために重要です。

#### Info.plist の重要なキー

`Info.plist` ファイルはアプリケーション設定の中核であり、次のようなキーが含まれます。

- **CFBundleExecutable**: `Contents/MacOS` ディレクトリにあるメイン実行ファイルの名前を指定します。
- **CFBundleIdentifier**: アプリケーションのグローバル識別子を提供します。macOS がアプリケーションを管理する際に広く使用されます。
- **LSMinimumSystemVersion**: アプリケーションの実行に必要な macOS の最低バージョンを示します。

### Bundles の探索

`Safari.app` などの Bundle の内容を探索するには、次のコマンドを使用できます。`bash ls -lR /Applications/Safari.app/Contents`

この探索により、`_CodeSignature`、`MacOS`、`Resources` などのディレクトリや、`Info.plist` などのファイルが表示されます。これらは、アプリケーションの保護からユーザーインターフェースや動作パラメータの定義まで、それぞれ固有の役割を果たします。

#### 追加の Bundle ディレクトリ

一般的なディレクトリ以外にも、Bundle には次のものが含まれる場合があります。

- **Frameworks**: アプリケーションが使用する同梱 Frameworks が含まれます。Frameworks は追加のリソースを持つ dylib のようなものです。
- **PlugIns**: アプリケーションの機能を拡張する plug-ins や extensions 用のディレクトリです。
- **XPCServices**: アプリケーションがプロセス外通信に使用する XPC services が格納されます。

この構造により、必要なすべてのコンポーネントが Bundle 内にカプセル化され、モジュール化された安全なアプリケーション環境が実現します。

`Info.plist` のキーとその意味について詳しく知りたい場合は、Apple developer documentation に詳細なリソースがあります。[Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: quarantine された Bundle が初めて実行されると、macOS は署名の詳細な検証を行い、ランダム化された translocated path から実行する場合があります。一度受け入れられると、後続の起動では浅いチェックのみが行われます。歴史的には、`Resources/`、`PlugIns/`、nib などのリソースファイルはチェックされていませんでした。macOS 13 Ventura 以降では、初回実行時に詳細なチェックが強制され、新しい *App Management* TCC permission により、ユーザーの同意なしに third-party processes が他の Bundle を変更することが制限されます。ただし、古いシステムは依然として脆弱です。
- **Bundle Identifier collisions**: 同じ `CFBundleIdentifier` を再利用する複数の embedded targets（PlugIns、helper tools など）が存在すると、署名検証が失敗したり、URL-scheme hijacking/confusion が発生したりする場合があります。必ず sub-bundles を列挙し、ID が一意であることを確認してください。

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura より前では、署名済みアプリの UI resources を置き換えることで、浅い code signing を bypass し、アプリの entitlements を用いた code execution を実現できました。現在の research（2024年）では、これは pre-Ventura および un-quarantined builds でも依然として機能します。<sup>[[1]](#references)[[2]](#references)</sup>

1. target app を writable location（例: `/tmp/Victim.app`）にコピーします。
2. `Contents/Resources/MainMenu.nib`（または `NSMainNibFile` で宣言された任意の nib）を、`NSAppleScript`、`NSTask` などを instantiate する malicious なものに置き換えます。
3. app を起動します。malicious な nib は victim の bundle ID と entitlements（TCC grants、microphone/camera など）で実行されます。
4. Ventura+ では、初回起動時に Bundle を deep-verify し、その後の変更には *App Management* permission を要求することで緩和されます。そのため persistence は困難になりますが、古い macOS における initial-launch attacks は依然として適用されます。<sup>[[1]](#references)</sup>

Minimal malicious nib payload example（xib を `ibtool` で nib に compile）：
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundles 内の Framework / PlugIn / dylib Hijacking

`@rpath` の検索では bundled Frameworks/PlugIns が優先されるため、`Contents/Frameworks/` または `Contents/PlugIns/` 内に悪意のある library を配置すると、main binary が library validation なし、または弱い `LC_RPATH` の順序で署名されている場合に、ロード順を変更できます。

unsigned/ad-hoc bundle を悪用する一般的な手順:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
- `com.apple.security.cs.disable-library-validation` が存在しない Hardened runtime では、third-party dylibs がブロックされます。最初に entitlements を確認してください。
- `Contents/XPCServices/` 配下の XPC services は、同階層の frameworks を load することが多いため、persistence または privilege escalation の経路として、同様にそれらのバイナリを patch します。

## Quick Inspection Cheatsheet
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## References

- [1] [プロセスインジェクションを視野に入れる：nib files を使用した macOS apps の exploit (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB と bundle resource tampering の write-up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
