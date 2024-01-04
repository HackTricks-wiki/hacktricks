# macOS システム拡張

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## システム拡張 / エンドポイントセキュリティフレームワーク

カーネル拡張とは異なり、**システム拡張はユーザースペースで実行されます**。これにより、拡張の不具合によるシステムクラッシュのリスクが低減されます。

<figure><img src="../../../.gitbook/assets/image (1) (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

システム拡張には3種類あります：**DriverKit** 拡張、**ネットワーク** 拡張、および **エンドポイントセキュリティ** 拡張。

### **DriverKit 拡張**

DriverKitは、**ハードウェアサポートを提供する**カーネル拡張の代替品です。これにより、デバイスドライバー（USB、シリアル、NIC、HIDドライバーなど）がカーネルスペースではなくユーザースペースで実行できます。DriverKitフレームワークには、特定のI/O Kitクラスの**ユーザースペースバージョン**が含まれており、カーネルは通常のI/O Kitイベントをユーザースペースに転送し、これらのドライバーがより安全な環境で実行されるようにします。

### **ネットワーク拡張**

ネットワーク拡張は、ネットワークの動作をカスタマイズする機能を提供します。ネットワーク拡張にはいくつかのタイプがあります：

* **アプリプロキシ**: これは、フロー指向のカスタムVPNプロトコルを実装するVPNクライアントを作成するために使用されます。つまり、個々のパケットではなく接続（またはフロー）に基づいてネットワークトラフィックを処理します。
* **パケットトンネル**: これは、パケット指向のカスタムVPNプロトコルを実装するVPNクライアントを作成するために使用されます。つまり、個々のパケットに基づいてネットワークトラフィックを処理します。
* **フィルタデータ**: これは、ネットワーク「フロー」をフィルタリングするために使用されます。フローレベルでネットワークデータを監視または変更することができます。
* **フィルタパケット**: これは、個々のネットワークパケットをフィルタリングするために使用されます。パケットレベルでネットワークデータを監視または変更することができます。
* **DNSプロキシ**: これは、カスタムDNSプロバイダーを作成するために使用されます。DNSリクエストとレスポンスを監視または変更するために使用できます。

## エンドポイントセキュリティフレームワーク

エンドポイントセキュリティは、macOSでAppleが提供するフレームワークであり、システムセキュリティのためのAPIセットを提供します。これは、**セキュリティベンダーや開発者がシステム活動を監視および制御し、悪意のある活動を特定して防御する製品を構築するために使用されることを意図しています**。

このフレームワークは、プロセスの実行、ファイルシステムイベント、ネットワークおよびカーネルイベントなどの**システム活動を監視および制御するAPIのコレクションを提供します**。

このフレームワークのコアはカーネルに実装されており、**`/System/Library/Extensions/EndpointSecurity.kext`** にあるカーネル拡張（KEXT）です。このKEXTはいくつかの重要なコンポーネントで構成されています：

* **EndpointSecurityDriver**: これはカーネル拡張の「エントリポイント」として機能します。OSとエンドポイントセキュリティフレームワークとの間の主要な相互作用ポイントです。
* **EndpointSecurityEventManager**: このコンポーネントはカーネルフックの実装を担当します。カーネルフックにより、フレームワークはシステムコールを傍受することでシステムイベントを監視できます。
* **EndpointSecurityClientManager**: これはユーザースペースクライアントとの通信を管理し、イベント通知を受け取る必要がある接続されているクライアントを追跡します。
* **EndpointSecurityMessageManager**: これはメッセージとイベント通知をユーザースペースクライアントに送信します。

エンドポイントセキュリティフレームワークが監視できるイベントは以下のカテゴリに分類されます：

* ファイルイベント
* プロセスイベント
* ソケットイベント
* カーネルイベント（カーネル拡張のロード/アンロードやI/O Kitデバイスのオープンなど）

### エンドポイントセキュリティフレームワークアーキテクチャ

<figure><img src="../../../.gitbook/assets/image (3) (8).png" alt=""><figcaption></figcaption></figure>

エンドポイントセキュリティフレームワークとの**ユーザースペース通信**はIOUserClientクラスを通じて行われます。呼び出し元のタイプに応じて、2つの異なるサブクラスが使用されます：

* **EndpointSecurityDriverClient**: これには`com.apple.private.endpoint-security.manager`権限が必要で、これはシステムプロセス`endpointsecurityd`のみが保持しています。
* **EndpointSecurityExternalClient**: これには`com.apple.developer.endpoint-security.client`権限が必要です。これは通常、エンドポイントセキュリティフレームワークと対話する必要があるサードパーティのセキュリティソフトウェアによって使用されます。

エンドポイントセキュリティ拡張：**`libEndpointSecurity.dylib`** は、システム拡張がカーネルと通信するために使用するCライブラリです。このライブラリはI/O Kit（`IOKit`）を使用してエンドポイントセキュリティKEXTと通信します。

**`endpointsecurityd`** は、特にブートプロセスの初期段階でエンドポイントセキュリティシステム拡張の管理と起動に関与する重要なシステムデーモンです。**システム拡張**のみが、その`Info.plist`ファイルに**`NSEndpointSecurityEarlyBoot`** とマークされている場合、この初期ブート処理を受けます。

別のシステムデーモンである**`sysextd`**は、システム拡張を検証し、適切なシステムロケーションに移動します。その後、関連するデーモンに拡張機能のロードを依頼します。**`SystemExtensions.framework`** は、システム拡張のアクティベーションと非アクティベーションを担当します。

## ESFをバイパスする

ESFは、レッドチームを検出しようとするセキュリティツールによって使用されます。したがって、これを回避する方法に関する情報は興味深いものです。

### CVE-2021-30965

セキュリティアプリケーションは**フルディスクアクセス権限**を持っている必要があります。したがって、攻撃者がそれを削除できれば、ソフトウェアの実行を防ぐことができます。
```bash
tccutil reset All
```
このバイパスと関連する情報については、[#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)のトークをご覧ください。

最終的には、新しい権限**`kTCCServiceEndpointSecurityClient`**をセキュリティアプリに与え、**`tccd`**によって管理されることで、`tccutil`がその権限をクリアして実行を防ぐことがないように修正されました。

## 参考文献

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><strong>AWSのハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
