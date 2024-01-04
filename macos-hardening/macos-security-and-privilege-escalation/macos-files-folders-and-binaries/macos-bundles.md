# macOS Bundles

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでのAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 基本情報

基本的に、バンドルはファイルシステム内の**ディレクトリ構造**です。興味深いことに、デフォルトではこのディレクトリはFinderで**単一のオブジェクトのように見えます**。&#x20;

私たちが遭遇する**一般的な**バンドルは**`.app`バンドル**ですが、**`.framework`**や**`.systemextension`**、**`.kext`**など、他の多くの実行可能ファイルもバンドルとしてパッケージされています。

バンドル内に含まれるリソースの種類には、アプリケーション、ライブラリ、画像、ドキュメント、ヘッダーファイルなどがあります。これらのファイルはすべて`<application>.app/Contents/`内にあります。
```bash
ls -lR /Applications/Safari.app/Contents
```
* `Contents/_CodeSignature` -> アプリケーションの**コード署名情報**を含む（ハッシュなど）。
* `openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64`
* `Contents/MacOS` -> **アプリケーションのバイナリ**を含む（UIでアプリケーションアイコンをダブルクリックすると実行される）。
* `Contents/Resources` -> 画像、ドキュメント、nib/xibファイル（様々なユーザーインターフェースを記述する）など、**アプリケーションのUI要素**を含む。
* `Contents/Info.plist` -> アプリケーションの主な「**設定ファイル**」。Appleは「システムはこのファイルの存在に依存して、\[その]アプリケーションと関連ファイルに関する情報を識別する」と述べている。
* **Plistファイル**は設定情報を含む。plistキーの意味についての情報は[https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)で見つけることができる。
*   アプリケーションを分析する際に興味があるかもしれないペアには以下が含まれる：

* **CFBundleExecutable**

**アプリケーションのバイナリの名前**を含む（Contents/MacOSにある）。

* **CFBundleIdentifier**

アプリケーションのバンドル識別子を含む（システムによってアプリケーションを**グローバルに識別**するためによく使用される）。

* **LSMinimumSystemVersion**

アプリケーションが互換性を持つ**macOSの最古のバージョン**を含む。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
