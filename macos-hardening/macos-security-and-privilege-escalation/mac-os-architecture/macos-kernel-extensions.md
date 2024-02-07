# macOSカーネル拡張機能

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？ または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をご覧ください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をチェックして、[**NFTs**](https://opensea.io/collection/the-peass-family)の独占コレクションを発見しましょう。
* [**PEASSとHackTricksの公式スウォッグ**](https://peass.creator-spring.com)を入手しましょう。
* **[💬 Discord](https://emojipedia.org/speech-balloon/)**グループに参加するか、[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** **🐦**で **[@carlospolopm](https://twitter.com/hacktricks\_live)** をフォローしてください。
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)**と**[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**に **PRを送信**して、ハッキングのヒントを共有してください。

</details>

## 基本情報

カーネル拡張機能（Kexts）は、**`.kext`** 拡張子を持つ **パッケージ**であり、**macOSカーネルスペースに直接ロード**され、メインオペレーティングシステムに追加機能を提供します。

### 要件

明らかに、これは非常に強力なため、カーネル拡張機能をロードするのは **複雑** です。カーネル拡張機能をロードするために満たす必要がある **要件** は次のとおりです：

* **リカバリモードに入る**とき、カーネル **拡張機能をロードできるように許可**する必要があります：

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* カーネル拡張機能は **カーネルコード署名証明書で署名されている** 必要があり、これは **Apple** によってのみ **付与** されます。会社とその必要性を詳細に審査します。
* カーネル拡張機能は **ノータライズ** されている必要があり、Appleはマルウェアをチェックできます。
* その後、 **root** ユーザーがカーネル拡張機能を **ロード** でき、パッケージ内のファイルは **rootに属している** 必要があります。
* アップロードプロセス中、パッケージは **保護された非rootの場所** に準備する必要があります：`/Library/StagedExtensions`（`com.apple.rootless.storage.KernelExtensionManagement`権限が必要）。
* 最後に、ユーザーはそれをロードしようとすると、[**確認リクエストを受け取ります**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) 、承認された場合、コンピュータを **再起動** してそれをロードする必要があります。

### ロードプロセス

Catalinaでは、次のようになりました： **検証** プロセスが **ユーザーランド** で発生することに注目することが興味深いです。ただし、 **`com.apple.private.security.kext-management`** 権限を持つアプリケーションのみがカーネルに拡張機能のロードを要求できます：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli は、拡張機能のロードの **検証** プロセスを **開始** します
* **`kextd`** は **Machサービス** を使用して送信して **`kextd`** と通信します。
2. **`kextd`** は、 **署名** など、いくつかのことをチェックします
* **`syspolicyd`** に拡張機能を **ロード** できるかどうかを **確認** するように話します。
3. **`syspolicyd`** は、拡張機能が以前にロードされていない場合、 **ユーザーにプロンプト** を表示します。
* **`syspolicyd`** は結果を **`kextd`** に報告します
4. **`kextd`** は最終的にカーネルに拡張機能を **ロードするよう指示** できます

**`kextd`** が利用できない場合、**`kextutil`** は同じチェックを実行できます。

## 参考

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？ または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をご覧ください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をチェックして、[**NFTs**](https://opensea.io/collection/the-peass-family)の独占コレクションを発見しましょう。
* [**PEASSとHackTricksの公式スウォッグ**](https://peass.creator-spring.com)を入手しましょう。
* **[💬 Discord](https://emojipedia.org/speech-balloon/)**グループに参加するか、[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** **🐦**で **[@carlospolopm](https://twitter.com/hacktricks\_live)** をフォローしてください。
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)**と**[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**に **PRを送信**して、ハッキングのヒントを共有してください。

</details>
