# macOSカーネル拡張

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの企業を宣伝したいですか？ または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をご覧ください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をチェックしてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションです。
* [**PEASSとHackTricksの公式スワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) **Discordグループ**または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローしてください。
* [**hacktricks repo**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを送信して、ハッキングのヒントを共有してください。

</details>

## 基本情報

カーネル拡張（Kexts）は、macOSのカーネルスペースに**直接ロードされる**拡張子**`.kext`**の**パッケージ**であり、主要なオペレーティングシステムに追加の機能を提供します。

### 要件

明らかに、カーネル拡張をロードするのは非常に強力な機能です。カーネル拡張をロードするためには、次の要件を満たす必要があります。

* **リカバリーモード**に入ると、カーネル拡張のロードが**許可される**必要があります。

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* カーネル拡張は、**カーネルコード署名証明書**で**署名されている必要があります**。この証明書は**Apple**によってのみ発行されます。Appleは、**企業**と**必要性**を詳細に検証します。
* カーネル拡張はまた、Appleがマルウェアを検出するために**検証**される必要があります。
* その後、カーネル拡張をロードできるのは**ルートユーザ**であり、パッケージ内のファイルはルートに所属する必要があります。
* ロードプロセス中、パッケージは保護されたルート以外の場所に準備される必要があります：`/Library/StagedExtensions`（`com.apple.rootless.storage.KernelExtensionManagement`権限が必要です）。
* 最後に、ロードを試みると、[**ユーザに確認の要求が表示されます**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html)。承認されると、コンピュータを**再起動**してロードします。

### ロードプロセス

Catalinaでは、次のようになります：興味深いことに、**検証プロセス**は**ユーザランド**で行われます。ただし、**`com.apple.private.security.kext-management`**権限を持つアプリケーションのみがカーネルに**カーネル拡張のロードを要求**できます：kextcache、kextload、kextutil、kextd、syspolicyd

1. **`kextutil`** CLIは、カーネル拡張をロードするための検証プロセスを**開始**します。

* **`kextd`**との間でMachサービスを使用して通信します。

2. **`kextd`**は、署名などのさまざまなチェックを行います。

* **`syspolicyd`**との通信を行い、カーネル拡張をロードできるかどうかを確認します。

3. **`syspolicyd`**は、カーネル拡張が以前にロードされていないかどうかを**ユーザに尋ねます**。

* **`syspolicyd`**は結果を**`kextd`**に伝えます。

4. **`kextd`**は最終的にカーネルにカーネル拡張をロードするよう指示できます。

kextdが利用できない場合、kextutilも同じチェックを実行できます。

## 参考文献

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの企業を宣伝したいですか？ または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をご覧ください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をチェックしてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションです。
* [**PEASSとHackTricksの公式スワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) **Discordグループ**または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローしてください。
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)** **と** [**hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)** にPRを送ることで、あなたのハッキングのテクニックを共有してください。

</details>
