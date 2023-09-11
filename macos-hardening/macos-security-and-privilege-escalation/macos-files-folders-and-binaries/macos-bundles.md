# macOS バンドル

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するために、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

基本的に、バンドルはファイルシステム内の**ディレクトリ構造**です。興味深いことに、このディレクトリはデフォルトでは**Finderで単一のオブジェクトのように見えます**。&#x20;

**一般的な**バンドルは、**`.app`バンドル**ですが、他にも**`.framework`**や**`.systemextension`**、**`.kext`**などの実行可能ファイルもバンドルとしてパッケージ化されています。

バンドル内に含まれるリソースの種類には、アプリケーション、ライブラリ、画像、ドキュメント、ヘッダーファイルなどがあります。これらのファイルは`<application>.app/Contents/`内にあります。
```bash
ls -lR /Applications/Safari.app/Contents
```
* `Contents/_CodeSignature` -> アプリケーションの**コード署名情報**を含んでいます（ハッシュなど）。
* `openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64`
* `Contents/MacOS` -> ユーザーがUIのアプリケーションアイコンをダブルクリックしたときに実行される**アプリケーションのバイナリ**が含まれています。
* `Contents/Resources` -> 画像、ドキュメント、およびnib/xibファイル（さまざまなユーザーインターフェースを記述する）など、アプリケーションの**UI要素**が含まれています。
* `Contents/Info.plist` -> アプリケーションの主要な「**設定ファイル**」です。Appleは、「システムはこのファイルの存在に依存して、\[アプリケーション]と関連ファイルに関する関連情報を識別する」と述べています。
* **Plist** **ファイル**には設定情報が含まれています。[https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)でplistキーの意味に関する情報を見つけることができます。
*   アプリケーションの解析時に興味がある可能性のあるペアには以下があります:\\

* **CFBundleExecutable**

アプリケーションのバイナリの**名前**が含まれています（Contents/MacOSに見つかります）。

* **CFBundleIdentifier**

アプリケーションのバンドル識別子が含まれています（システムがアプリケーションを**グローバルに識別**するためによく使用されます）。

* **LSMinimumSystemVersion**

アプリケーションが互換性のある**最も古いmacOSのバージョン**が含まれています。
