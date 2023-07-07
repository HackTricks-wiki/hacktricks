# macOSシステム拡張

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksであなたの会社を宣伝したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## システム拡張/エンドポイントセキュリティフレームワーク

カーネル拡張とは異なり、**システム拡張はカーネルスペースではなくユーザースペースで実行**されるため、拡張機能の不具合によるシステムクラッシュのリスクが低減されます。

<figure><img src="../../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

システム拡張には、**DriverKit**拡張、**Network**拡張、および**Endpoint Security**拡張の3つのタイプがあります。

### **DriverKit拡張**

DriverKitは、**ハードウェアサポートを提供する**カーネル拡張の代替です。これにより、デバイスドライバ（USB、シリアル、NIC、HIDドライバなど）がカーネルスペースではなくユーザースペースで実行されるようになります。DriverKitフレームワークには、特定のI/O Kitクラスのユーザースペースバージョンが含まれており、カーネルは通常のI/O Kitイベントをユーザースペースに転送することで、これらのドライバが実行される安全な環境を提供します。

### **Network拡張**

Network拡張は、ネットワークの動作をカスタマイズする機能を提供します。いくつかのタイプのNetwork拡張があります。

* **App Proxy**: これは、接続（またはフロー）単位ではなく個々のパケットに基づいてネットワークトラフィックを処理する、フロー指向のカスタムVPNプロトコルを実装するVPNクライアントの作成に使用されます。
* **Packet Tunnel**: これは、個々のパケットに基づいてネットワークトラフィックを処理するパケット指向のカスタムVPNプロトコルを実装するVPNクライアントの作成に使用されます。
* **Filter Data**: これは、ネットワークデータをフローレベルで監視または変更するために使用されます。
* **Filter Packet**: これは、個々のネットワークパケットをフィルタリングするために使用されます。ネットワークデータをパケットレベルで監視または変更することができます。
* **DNS Proxy**: これは、カスタムDNSプロバイダを作成するために使用されます。DNSリクエストとレスポンスを監視または変更するために使用できます。

## エンドポイントセキュリティフレームワーク

エンドポイントセキュリティは、AppleがmacOSで提供するフレームワークで、システムセキュリティのための一連のAPIを提供します。これは、悪意のある活動を特定し、保護するために、**セキュリティベンダーや開発者がシステムの活動を監視および制御するための製品を構築するために使用されます**。

このフレームワークは、プロセスの実行、ファイルシステムイベント、ネットワークおよびカーネルイベントなど、**システムの活動を監視および制御するためのAPIのコレクション**を提供します。

このフレームワークのコアは、カーネル内に実装されたカーネル拡張（KEXT）である**`/System/Library/Extensions/EndpointSecurity.kext`**によって実現されています。このKEXTは、いくつかの主要なコンポーネントで構成されています。

* **EndpointSecurityDriver**: これはカーネル拡張の「エントリーポイント」として機能します。これはOSとEndpoint Securityフレームワークの間の主な相互作用ポイントです。
* **EndpointSecurityEventManager**: このコンポーネントはカーネルフックの実装を担当します。カーネルフックにより、フレームワークはシステムコールを傍受することでシステムイベントを監視できます。
* **EndpointSecurityClientManager**: これはユーザースペースクライアントとの通信を管理し、接続してイベント通知を受け取る必要があるクライアントを追跡します。
* **EndpointSecurityMessageManager**: これはユーザースペースクライアントにメッセージとイベント通知を送信します。

Endpoint Securityフレームワークが監視できるイベントは、次のカテゴリに分類されます。

* ファイルイベント
* プロセスイベント
* ソケットイベント
* カーネルイベント（カーネル拡張の読み込み/アンロードやI/O Kitデバイスのオープンなど）

### エンドポイントセキュリティフレームワークのアーキテクチャ

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

エンドポイントセキュリティフレームワークとの**ユーザースペース間の通信**は、IOUserClientクラスを介して行われます。呼び出し元のタイプに応じて、2つの異なるサブクラスが使用されます。

* **EndpointSecurityDriverClient**: これには`com.apple.private.endpoint-security.manager`の権限が必要で、これはシステムプロセス`endpointsecurityd`のみが保持しています。
* **EndpointSecurityExternalClient**: これには`com.apple.developer.endpoint-security.client`の権限が必要です。これは通常、Endpoint Securityフレームワークと対話する必要があるサードパーティのセキュリティソフトウェアによって使用されます。

エンドポイントセキュリティ拡張機能で使用される**`libEndpointSecurity.dylib`**は、システム拡張機能がカーネルと通信するために使用するCライブラリです。このラ
## ESFのバイパス

ESFは、レッドチームを検出しようとするセキュリティツールによって使用されるため、これを回避する方法に関する情報は興味深いです。

### CVE-2021-30965

問題は、セキュリティアプリケーションが**フルディスクアクセス権限**を持っている必要があることです。したがって、攻撃者がそれを削除できれば、ソフトウェアの実行を防ぐことができます。
```bash
tccutil reset All
```
**詳細情報**については、トーク[#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)を参照してください。

最終的には、新しい権限**`kTCCServiceEndpointSecurityClient`**を**`tccd`**が管理するセキュリティアプリに与えることで、`tccutil`がアクセス許可をクリアしないようにし、実行を防止することで修正されました。

## 参考文献

* [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
* [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
