# macOSカーネル拡張機能

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

カーネル拡張機能（Kexts）は、macOSのカーネルスペースに直接ロードされる**`.kext`拡張子**を使用する**バンドル**であり、コアオペレーティングシステムに追加の機能を提供します。

### 必要条件

明らかに、これは非常に強力なものであるため、カーネル拡張機能をロードするのは複雑です。カーネル拡張機能がロードされるための要件は次のとおりです。

* **リカバリモード**に入ると、Kextsは**ロードを許可される必要があります**：

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Kextは**カーネルコード署名証明書**で**署名されている必要があります**。これは**Apple**によってのみ付与されることができます。Appleは、これが必要な**会社**と**理由**を詳細に**審査**します。
* Kextはまた、マルウェアをチェックするためにAppleによって**検証**される必要があります。
* その後、**ルートユーザ**がKextをロードでき、バンドル内のファイルはルートに所属する必要があります。
* ロードプロセス中、バンドルはルートレス保護された場所でステージングされる必要があります：`/Library/StagedExtensions`（エンタイトルメント`com.apple.rootless.storage.KernelExtensionManagement`が必要です）
* 最後に、ロードしようとすると、[**ユーザに確認が求められます**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html)。承認された場合、コンピュータを**再起動**してロードする必要があります。

### ロードプロセス

Catalinaでは、次のようになります：興味深いことに、**検証**プロセスは**ユーザランド**で行われます。ただし、**`com.apple.private.security.kext-management`**のエンタイトルメントを持つアプリケーションのみがカーネルに**拡張機能のロードを要求**できます：kextcache、kextload、kextutil、kextd、syspolicyd

1. **`kextutil`** CLIは、拡張機能をロードするための検証プロセスを**開始**します。
* Machサービスを使用して**`kextd`**に送信します。
2. **`kextd`**は、署名などのいくつかのチェックを行います。
* 拡張機能がロードできるかどうかを確認するために**`syspolicyd`**に話しかけます。
3. **`syspolicyd`**は、拡張機能が以前にロードされていない場合、**ユーザに尋ねます**。
* **`syspolicyd`**は結果を**`kextd`**に示します。
4. **`kextd`**は最終的にカーネルに拡張機能をロードするよう指示できます。

kextdが利用できない場合、kextutilは同じチェックを実行できます。

## 参考文献

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop
