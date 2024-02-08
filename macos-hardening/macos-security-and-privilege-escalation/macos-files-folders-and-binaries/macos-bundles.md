# macOS バンドル

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェック！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 で **@carlospolopm** をフォローする**.**
* **ハッキングトリックを共有するには** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>

## 基本情報

macOS のバンドルは、アプリケーション、ライブラリ、およびその他の必要なファイルを含むさまざまなリソースのコンテナとして機能し、おなじみの `*.app` ファイルなど、Finder で単一のオブジェクトとして表示されます。最も一般的に遭遇するバンドルは `.app` バンドルですが、`.framework`、`.systemextension`、`.kext` などの他のタイプも一般的です。

### バンドルの必須コンポーネント

バンドル内、特に `<application>.app/Contents/` ディレクトリ内には、さまざまな重要なリソースが格納されています:

- **_CodeSignature**: このディレクトリには、アプリケーションの整合性を検証するために重要なコード署名の詳細が保存されています。次のようなコマンドを使用してコード署名情報を調べることができます:
%%%bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
%%%
- **MacOS**: ユーザーの操作に応じて実行されるアプリケーションの実行可能バイナリが含まれています。
- **Resources**: 画像、ドキュメント、およびインターフェースの説明（nib/xib ファイル）など、アプリケーションのユーザーインターフェースコンポーネントのリポジトリです。
- **Info.plist**: システムがアプリケーションを認識し、適切に対話するために重要なアプリケーションのメイン構成ファイルとして機能します。

#### Info.plist の重要なキー

`Info.plist` ファイルは、アプリケーションの構成にとって基本的なものであり、次のようなキーが含まれています:

- **CFBundleExecutable**: `Contents/MacOS` ディレクトリにあるメイン実行ファイルの名前を指定します。
- **CFBundleIdentifier**: アプリケーションのためのグローバル識別子を提供し、macOS がアプリケーション管理に広く使用します。
- **LSMinimumSystemVersion**: アプリケーションの実行に必要な macOS の最小バージョンを示します。

### バンドルの探索

`Safari.app` などのバンンドルの内容を探索するには、次のコマンドを使用できます:
%%%bash
ls -lR /Applications/Safari.app/Contents
%%%

この探索により、`_CodeSignature`、`MacOS`、`Resources` などのディレクトリや `Info.plist` のようなファイルが表示され、それぞれがアプリケーションのセキュリティを確保し、ユーザーインターフェースと操作パラメータを定義するための独自の目的を果たしています。

#### 追加のバンドルディレクトリ

一般的なディレクトリ以外に、バンドルには次のようなものが含まれる場合があります:

- **Frameworks**: アプリケーションで使用されるバンドル化されたフレームワークが含まれています。
- **PlugIns**: アプリケーションの機能を拡張するプラグインや拡張機能のためのディレクトリです。
- **XPCServices**: アプリケーションがプロセス外通信に使用する XPC サービスを保持します。

この構造により、すべての必要なコンポーネントがバンドル内にカプセル化され、モジュラーで安全なアプリケーション環境が実現されます。

`Info.plist` キーとその意味に関する詳細情報については、Apple 開発者ドキュメントが広範なリソースを提供しています: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェック！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 で **@carlospolopm** をフォローする**.**
* **ハッキングトリックを共有するには** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>
