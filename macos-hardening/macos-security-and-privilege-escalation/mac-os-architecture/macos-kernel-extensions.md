# macOSカーネル拡張機能

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>！</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？ または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をご覧ください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をチェックして、独占的な[NFTコレクション](https://opensea.io/collection/the-peass-family)を発見してください
* [**PEASSとHackTricksの公式スウォッグ**](https://peass.creator-spring.com)を入手してください
* **Discord**の[**💬**](https://emojipedia.org/speech-balloon/) **グループに参加**するか、[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私に[**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローしてください。
* **ハッキングのヒントを共有する**には、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを送信してください。

</details>

## 基本情報

カーネル拡張機能（Kexts）は、**`.kext`**拡張子を持つ**パッケージ**であり、**macOSカーネルスペースに直接ロード**され、メインオペレーティングシステムに追加機能を提供します。

### 要件

明らかに、これは非常に強力なため、カーネル拡張機能をロードするのは**複雑**です。カーネル拡張機能をロードするために満たす必要がある**要件**は次のとおりです：

* **リカバリモードに入る**とき、カーネル**拡張機能をロードすることが許可**されている必要があります：

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* カーネル拡張機能は、**Appleによってのみ付与されるカーネルコード署名証明書**で**署名されている**必要があります。Appleは、会社やその必要性を詳細に検討します。
* カーネル拡張機能はまた、**ノータライズ**されている必要があり、Appleはマルウェアをチェックできます。
* その後、**root**ユーザーがカーネル拡張機能を**ロードできる**ユーザーであり、パッケージ内のファイルは**rootに属している**必要があります。
* アップロードプロセス中、パッケージは**保護された非rootの場所**に準備されなければなりません：`/Library/StagedExtensions`（`com.apple.rootless.storage.KernelExtensionManagement`権限が必要）。
* 最後に、ユーザーはそれをロードしようとすると、[**確認リクエストを受け取ります**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) そして、承認された場合、コンピュータを**再起動**してそれをロードする必要があります。

### ロードプロセス

Catalinaでは、次のようになりました：**検証**プロセスが**ユーザーランド**で発生することに注目することが興味深いです。ただし、**`com.apple.private.security.kext-management`**権限を持つアプリケーションのみが**カーネルに拡張機能のロードを要求**できます：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cliは、拡張機能のロードの**検証**プロセスを**開始**します
* **Machサービス**を使用して**`kextd`**に送信して話します。
2. **`kextd`**は、**署名**など、いくつかのことをチェックします
* 拡張機能を**ロード**できるかどうかを**チェック**するために**`syspolicyd`**に話します。
3. **`syspolicyd`**は、拡張機能が以前にロードされていない場合、**ユーザーにプロンプト**を表示します。
* **`syspolicyd`**は結果を**`kextd`**に報告します
4. **`kextd`**は最終的にカーネルに拡張機能を**ロードするよう指示**できます

**`kextd`**が利用できない場合、**`kextutil`**は同じチェックを実行できます。

## 参考文献

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>！</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**したいですか？ または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をご覧ください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をチェックして、独占的な[NFTコレクション](https://opensea.io/collection/the-peass-family)を発見してください
* [**PEASSとHackTricksの公式スウォッグ**](https://peass.creator-spring.com)を入手してください
* **Discord**の[**💬**](https://emojipedia.org/speech-balloon/) **グループに参加**するか、[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私に[**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローしてください。
* **ハッキングのヒントを共有する**には、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを送信してください。

</details>
