# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOSのバンドルは、アプリケーション、ライブラリ、その他の必要なファイルを含むさまざまなリソースのコンテナとして機能し、Finderでは`*.app`ファイルのような単一のオブジェクトとして表示されます。最も一般的に遭遇するバンドルは`.app`バンドルですが、`.framework`、`.systemextension`、および`.kext`のような他のタイプも広く存在します。

### バンドルの重要なコンポーネント

バンドル内、特に`<application>.app/Contents/`ディレクトリ内には、さまざまな重要なリソースが格納されています：

- **\_CodeSignature**: このディレクトリは、アプリケーションの整合性を確認するために重要なコード署名の詳細を保存します。次のコマンドを使用してコード署名情報を確認できます： %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
- **MacOS**: ユーザーの操作に応じて実行されるアプリケーションの実行可能バイナリを含みます。
- **Resources**: 画像、文書、インターフェースの説明（nib/xibファイル）など、アプリケーションのユーザーインターフェースコンポーネントのリポジトリです。
- **Info.plist**: アプリケーションの主要な設定ファイルとして機能し、システムがアプリケーションを適切に認識し、相互作用するために重要です。

#### Info.plistの重要なキー

`Info.plist`ファイルはアプリケーション設定の基盤であり、次のようなキーを含んでいます：

- **CFBundleExecutable**: `Contents/MacOS`ディレクトリにある主要な実行可能ファイルの名前を指定します。
- **CFBundleIdentifier**: アプリケーションのグローバル識別子を提供し、macOSによるアプリケーション管理で広く使用されます。
- **LSMinimumSystemVersion**: アプリケーションが実行されるために必要なmacOSの最小バージョンを示します。

### バンドルの探索

`Safari.app`のようなバンドルの内容を探索するには、次のコマンドを使用できます： `bash ls -lR /Applications/Safari.app/Contents`

この探索により、`_CodeSignature`、`MacOS`、`Resources`のようなディレクトリや、`Info.plist`のようなファイルが明らかになり、それぞれがアプリケーションのセキュリティからユーザーインターフェースおよび操作パラメータの定義まで、独自の目的を果たします。

#### 追加のバンドルディレクトリ

一般的なディレクトリに加えて、バンドルには次のようなものも含まれる場合があります：

- **Frameworks**: アプリケーションによって使用されるバンドルフレームワークを含みます。フレームワークは、追加のリソースを持つdylibのようなものです。
- **PlugIns**: アプリケーションの機能を強化するプラグインや拡張のためのディレクトリです。
- **XPCServices**: アプリケーションがプロセス外通信のために使用するXPCサービスを保持します。

この構造により、すべての必要なコンポーネントがバンドル内にカプセル化され、モジュール式で安全なアプリケーション環境が促進されます。

`Info.plist`キーとその意味に関する詳細情報については、Appleの開発者ドキュメントが豊富なリソースを提供しています： [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)。

{{#include ../../../banners/hacktricks-training.md}}
