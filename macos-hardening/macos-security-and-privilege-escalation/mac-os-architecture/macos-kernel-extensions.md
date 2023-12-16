# macOSカーネル拡張機能

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの企業を宣伝したいですか？ または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をご覧ください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をチェックしてください。これは、私たちの独占的な[**NFTコレクション**](https://opensea.io/collection/the-peass-family)です。
* [**PEASSとHackTricksの公式スワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) **Discordグループ**または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローしてください。
* [**hacktricks repo**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを送信して、ハッキングのヒントを共有してください。

</details>

## 基本情報

カーネル拡張機能（Kexts）は、**`.kext`**拡張子を持つ**パッケージ**であり、メインのオペレーティングシステムに追加の機能を提供するために、macOSカーネルスペースに直接ロードされます。

### 要件

明らかに、これは非常に強力なため、カーネル拡張機能をロードするのは**複雑**です。カーネル拡張機能をロードするために満たす必要がある**要件**は次のとおりです：

* **リカバリモードに入る**とき、カーネル**拡張機能のロードが許可される**必要があります：

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* カーネル拡張機能は、**カーネルコード署名証明書**で**署名**されている必要があります。この証明書は**Apple**によってのみ**付与**されます。Appleは、会社とその必要性を詳細に審査します。
* カーネル拡張機能はまた、**ノータリゼーション**を受ける必要があります。Appleはマルウェアをチェックすることができます。
* その後、**root**ユーザーがカーネル拡張機能を**ロード**でき、パッケージ内のファイルは**root**に所属する必要があります。
* アップロードプロセス中、パッケージは**保護された非ルートの場所**に準備される必要があります：`/Library/StagedExtensions`（`com.apple.rootless.storage.KernelExtensionManagement`の許可が必要です）。
* 最後に、ロードしようとすると、ユーザーは[**確認リクエストを受け取ります**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html)。承認された場合、コンピュータを**再起動**してロードする必要があります。

### ロードプロセス

Catalinaでは、次のようになります：**検証**プロセスは**ユーザーランド**で行われることに注意すると興味深いです。ただし、**`com.apple.private.security.kext-management`**の許可を持つアプリケーションのみがカーネルに拡張機能のロードを要求できます：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** CLIは、拡張機能のロードのための**検証**プロセスを**開始**します。
* **Machサービス**を使用して**`kextd`**と通信します。
2. **`kextd`**は、**署名**などのさまざまなチェックを行います。
* **`syspolicyd`**と通信して、拡張機能を**ロード**できるかどうかを**確認**します。
3. **`syspolicyd`**は、拡張機能が以前にロードされていない場合、**ユーザーにプロンプト**を表示します。
* **`syspolicyd`**は結果を**`kextd`**に報告します。
4. **`kextd`**は最終的にカーネルに拡張機能を**ロードするように指示**できます。

**`kextd`**が利用できない場合、**`kextutil`**は同じチェックを実行できます。

## 参考文献

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの企業を宣伝したいですか？ または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をご覧ください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をチェックしてください。これは、私たちの独占的な[**NFTコレクション**](https://opensea.io/collection/the-peass-family)です。
* [**PEASSとHackTricksの公式スワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) **Discordグループ**または[**Telegramグ
